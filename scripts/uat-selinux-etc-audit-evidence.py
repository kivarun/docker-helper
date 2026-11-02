#!/usr/bin/env python3
"""Read-only raw Linux audit serial-correlation for the host-integrity UAT."""
import os
import re
import sys
from collections import defaultdict
serial_re = re.compile(r"msg=audit\([0-9.]+:(\d+)\)")
kv_re = re.compile(r'\b([a-z_]+)=("[^"]*"|\S+)')
syscalls = {"188","189","190","setxattr","lsetxattr","fsetxattr"}

def fields(s):
    return {k: v.strip('"') for k,v in kv_re.findall(s)}
def serial(s):
    m=serial_re.search(s)
    return m.group(1) if m else None
def collect(raw):
    ev=defaultdict(list)
    with open(raw,encoding="utf-8",errors="replace") as f:
        for line in f:
            sn=serial(line)
            if sn: ev[sn].append(line.strip())
    return ev
def relevant(lines):
    calls=[fields(l) for l in lines if l.startswith("type=SYSCALL ")]
    paths=[fields(l) for l in lines if l.startswith("type=PATH ")]
    calls=[c for c in calls if c.get("success")=="yes" and c.get("syscall") in syscalls]
    return calls,paths
def ident(path):
    st=os.stat(path)
    return (str(st.st_ino),os.major(st.st_dev),os.minor(st.st_dev))
def match(p,ident):
    if p.get("nametype")=="PARENT" or p.get("inode")!=ident[0]: return False
    try: major,minor=[int(v,16) for v in p.get("dev","").split(":")]
    except ValueError: return False
    return (major,minor)==ident[1:]
def capture(key,out):
    with open("/var/log/audit/audit.log",encoding="utf-8",errors="replace") as f: lines=list(f)
    serials={serial(l) for l in lines if l.startswith("type=SYSCALL ") and ('key="'+key+'"') in l}
    with open(out,"w",encoding="utf-8") as f: f.writelines(l for l in lines if serial(l) in serials)
    return 0
def control(raw,pid,file,directory):
    ids={"file":ident(file),"directory":ident(directory)}
    seen={x:set() for x in ids}
    for sn,lines in collect(raw).items():
        calls,paths=relevant(lines)
        if not any(c.get("pid")==pid and c.get("comm")=="python3" and c.get("exe","").startswith("/usr/bin/python3") for c in calls): continue
        for kind,target in ids.items():
            if any(match(p,target) for p in paths):seen[kind].add(sn)
    if len(seen["file"])>=2 and seen["directory"]:
        print("AUDIT_CONTROL_PASS pid=%s file=%s dir=%s"%(pid,",".join(sorted(seen["file"])),",".join(sorted(seen["directory"]))))
        return 0
    return 2
def protected(raw,targets):
    targets={p:ident(p) for p in targets}
    violations=[]
    for sn,lines in collect(raw).items():
        calls,paths=relevant(lines)
        for path,target in targets.items():
            if calls and any(match(p,target) for p in paths):
                violations.append((path,sn,calls,paths))
    for path,sn,calls,paths in violations[:25]:
        for c in calls:
            print("AUDIT_PROTECTED_XATTR path=%s serial=%s pid=%s comm=%s exe=%s syscall=%s"%(path,sn,c.get("pid"),c.get("comm"),c.get("exe"),c.get("syscall")))
        for p in paths: print("  PATH name=%s dev=%s inode=%s"%(p.get("name"),p.get("dev"),p.get("inode")))
    return 1 if violations else 0
def explain(raw,targets):
    ids=[ident(p) for p in targets]
    hits=[]; others=[]
    for sn,lines in collect(raw).items():
        calls,paths=relevant(lines)
        if not calls: continue
        (hits if any(match(p,i) for p in paths for i in ids) else others).append((sn,lines))
    print("AUDIT_EVENTS_PROTECTED=%d AUDIT_EVENTS_OTHER=%d"%(len(hits),len(others)))
    for sn,lines in (hits+others)[-100:]:
        for l in lines:
            if l.startswith(("type=SYSCALL ","type=PATH ","type=PROCTITLE ")):
                print(l[:1100])
    return 0
def main(args):
    if len(args)==3 and args[0]=="capture": return capture(args[1],args[2])
    if len(args)==5 and args[0]=="control": return control(*args[1:])
    if len(args)>=3 and args[0]=="protected":return protected(args[1],args[2:])
    if len(args)>=3 and args[0]=="explain":return explain(args[1],args[2:])
    return 2
if __name__=="__main__":
    try: sys.exit(main(sys.argv[1:]))
    except (OSError,RuntimeError) as e:
        print("AUDIT_READER_ERROR: %s"%e,file=sys.stderr)
        sys.exit(2)
