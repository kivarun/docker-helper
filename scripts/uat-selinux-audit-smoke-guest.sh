#!/usr/bin/env bash
# Standalone Linux audit positive-control smoke, disposable enforcing VM only.
# Neither docker-helper nor its RPM is needed. Never relabel /etc.
set -euo pipefail
[ "${UAT_DISPOSABLE_VM:-}" = YES ] || { echo 'BLOCKED: not a declared disposable VM'; exit 2; }
systemd-detect-virt --vm >/dev/null 2>&1 || { echo 'BLOCKED: not a VM'; exit 2; }
[ "$(id -u)" -eq 0 ] && [ "$(getenforce)" = Enforcing ] || { echo 'BLOCKED: requires root+SELinux Enforcing'; exit 2; }
for prog in auditctl ausearch python3 stat; do
  command -v "$prog" >/dev/null || { echo "BLOCKED: missing $prog"; exit 2; }
done
systemctl enable --now auditd >/dev/null 2>&1 || { echo 'BLOCKED: auditd unavailable'; exit 2; }
auditctl -e 1 >/dev/null || { echo 'BLOCKED: cannot enable audit'; exit 2; }
auditctl -s
[ "$(auditctl -s | awk '$1 == "enabled" { print $2 }')" = 1 ] || { echo 'BLOCKED: audit disabled'; exit 2; }

WORK="$(mktemp -d /opt/uat-audit-smoke.XXXXXXXX)"
KEY="dhas_$(date +%s)_$$"
LOST_BEFORE="$(auditctl -s | awk '$1 == "lost" { print $2}')"
[ -n "$LOST_BEFORE" ] || { echo "BLOCKED: auditctl lost counter missing"; exit 2; }
echo 'AUDIT_RULES_BEFORE_BEGIN'
auditctl -l
echo 'AUDIT_RULES_BEFORE_END'
if auditctl -l | grep -Eq '^-a never,task([[:space:]]|$)'; then
  echo 'AUDIT_NEVER_TASK_FOUND: removing *inside disposable VM only*'
  auditctl -d never,task || { echo 'BLOCKED: cannot remove never,task in guest'; exit 2; }
  if auditctl -l | grep -Eq '^-a never,task([[:space:]]|$)'; then
    echo 'BLOCKED: never,task still loaded'; exit 2
  fi
  echo 'AUDIT_NEVER_TASK_REMOVED'
else
  echo 'AUDIT_NEVER_TASK_ABSENT'
fi
RULE=0
cleanup() {
  [ "$RULE" = 0 ] || auditctl -d always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -k "$KEY" >/dev/null 2>&1 || true
  rm -rf -- "$WORK"
}
trap cleanup EXIT
[ "$(stat -c %d "$WORK")" = "$(stat -c %d /etc)" ] || { echo 'BLOCKED: controls not on /etc filesystem'; exit 2; }
mkdir "$WORK/directory"
printf 'audit-control\n' > "$WORK/file"
ln "$WORK/file" "$WORK/alias"
FILE_INO="$(stat -c %i "$WORK/file")"
DIR_INO="$(stat -c %i "$WORK/directory")"
auditctl -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -k "$KEY" || { echo 'BLOCKED: audit syscall rule failed'; exit 2; }
RULE=1
auditctl -l | grep -F -- "$KEY" || { echo 'BLOCKED: installed audit rule not found'; exit 2; }

python3 - "$WORK" <<'PY'
import os, sys
work = sys.argv[1]
with open(work + '/control.pid', 'w', encoding='ascii') as f:
    f.write(str(os.getpid()))
os.setxattr(work + '/file', 'user.dhas_file', b'1')
os.setxattr(work + '/directory', 'user.dhas_directory', b'1')
os.setxattr(work + '/alias', 'user.dhas_hardlink_alias', b'1')
PY
PID="$(cat "$WORK/control.pid")"
# On this guest the event stream is present in /var/log/audit/audit.log,
# while ausearch -k --raw returned empty despite a valid keyed rule. Use the
# raw source directly, selecting complete audit-serial groups by SYSCALL key.
[ -r /var/log/audit/audit.log ] || { echo 'BLOCKED: raw audit log inaccessible'; exit 2; }
for i in $(seq 1 40); do
  python3 - "$KEY" "$WORK/audit.raw" <<'PY'
import re, sys
key, destination = sys.argv[1:]
with open('/var/log/audit/audit.log', encoding='utf-8', errors='replace') as f:
    lines = list(f)
def serial(line):
    m = re.search(r'msg=audit\([0-9.]+:(\d+)\)', line)
    return m.group(1) if m else None
serials = {serial(line) for line in lines
           if line.startswith('type=SYSCALL ') and ('key="' + key + '"') in line}
with open(destination, 'w', encoding='utf-8') as f:
    f.writelines(line for line in lines if serial(line) in serials)
PY
  if [ "$(grep -c '^type=SYSCALL' "$WORK/audit.raw" || true)" -ge 3 ]; then break; fi
  sleep 0.2
done
printf 'ausearch-key-syscall-count=%s (non-authoritative)\n' \
  "$(ausearch -k "$KEY" --raw 2>/dev/null | grep -c '^type=SYSCALL' || true)"
if [ ! -s "$WORK/audit.raw" ]; then
  echo 'AUDIT_ZERO_EVENTS_DIAGNOSTICS'
  auditctl -l
  auditctl -s
  ls -l /var/log/audit/audit.log 2>&1 || true
  tail -25 /var/log/audit/audit.log 2>/dev/null | grep -E 'type=(SYSCALL|PATH)|key=' | tail -15 || true
  journalctl -k --no-pager 2>/dev/null | grep -F "$KEY" | tail -15 || true
fi
# Join SYSCALL and PATH by audit serial; require PID, success, and exact inode.
python3 - "$PID" "$FILE_INO" "$DIR_INO" "$WORK/audit.raw" <<'PY'
import re, sys
pid, file_ino, dir_ino, filename = sys.argv[1:]
events = {}
with open(filename, encoding='utf-8', errors='replace') as inp:
    for line in inp:
        m = re.search(r'msg=audit\([0-9.]+:(\d+)\)', line)
        if m:
            events.setdefault(m.group(1), []).append(line.strip())
verified = []
for serial, records in events.items():
    calls = [r for r in records if r.startswith('type=SYSCALL ')]
    paths = [r for r in records if r.startswith('type=PATH ')]
    if not calls or not paths:
        continue
    if not any(re.search(r'\bpid=' + re.escape(pid) + r'\b', r)
               and 'success=yes' in r
               and re.search(r'\bsyscall=(188|189|190|setxattr|lsetxattr|fsetxattr)\b', r)
               and 'comm=' in r and 'exe=' in r for r in calls):
        continue
    for kind, ino in (('file', file_ino), ('directory', dir_ino)):
        if any(re.search(r'\binode=' + re.escape(ino) + r'\b', p) for p in paths):
            verified.append((kind, serial))
            print('AUDIT_PROVEN kind=%s serial=%s pid=%s inode=%s' % (kind, serial, pid, ino))
            for r in calls + paths:
                print('  ' + r[:650])
file_serials = set(serial for kind, serial in verified if kind == 'file')
dir_serials = set(serial for kind, serial in verified if kind == 'directory')
if len(file_serials) < 2 or not dir_serials:
    print('AUDIT_BLOCKED: expected two file/hardlink syscalls and one directory syscall, '
          'same PID + success + inode + audit serial; saw files=%s dirs=%s; '
          'raw-lines=%d' % (len(file_serials), len(dir_serials), sum(map(len, events.values()))),
          file=sys.stderr)
    for serial, records in list(events.items())[-5:]:
        for r in records:
            if r.startswith(('type=SYSCALL ', 'type=PATH ')):
                print('  ' + r[:500], file=sys.stderr)
    sys.exit(2)
print('AUDIT_SMOKE_PASS syscall=188/189/190 pid=%s controls=file,directory,hardlink' % pid)
PY
AFTER_LOST="$(auditctl -s | awk '$1 == "lost" { print $2}')"
printf 'audit-lost-after=%s\n' "$AFTER_LOST"
[ "$AFTER_LOST" = "$LOST_BEFORE" ] || { echo "BLOCKED: audit loss during probe ($LOST_BEFORE -> $AFTER_LOST)"; exit 2; }
