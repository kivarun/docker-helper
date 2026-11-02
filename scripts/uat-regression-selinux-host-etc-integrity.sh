#!/usr/bin/env bash
# SECURITY UAT: disposable SELinux VM ONLY. Never execute against a real host.
# Replays the v2.3.0 handoff's absolute symlink build and probes /etc/passwd.
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/uat-regression-lib.sh"
reg_init "incident: external host /etc label integrity"
[ "${UAT_DISPOSABLE_VM:-}" = YES ] || reg_blocked "UAT_DISPOSABLE_VM=YES required"
reg_require_cmd systemd-detect-virt "VM proof"
systemd-detect-virt --vm >/dev/null 2>&1 || reg_blocked "not inside a VM"
reg_require_root
reg_require_service
reg_require_docker
for cmd in stat auditctl ausearch timeout getenforce python3; do reg_require_cmd "$cmd" "host integrity observation"; done
[ "$(getenforce)" = Enforcing ] || reg_blocked "not enforcing SELinux"
ctx() { stat -c '%C' -- "$1" 2>/dev/null; }
ino() { stat -c '%d:%i' -- "$1" 2>/dev/null; }
ETC="$(ctx /etc)"; PASSWD="$(ctx /etc/passwd)"
EI="$(ino /etc)"; PI="$(ino /etc/passwd)"
case "$ETC" in *:etc_t:*) ;; *) reg_blocked "/etc baseline incorrect: $ETC";; esac
case "$PASSWD" in *:passwd_file_t:*) ;; *) reg_blocked "passwd baseline incorrect: $PASSWD";; esac
[ -n "$EI" ] && [ -n "$PI" ] || reg_blocked "cannot read inode baseline"
getent passwd sshd >/dev/null && getent passwd opc >/dev/null || reg_blocked "baseline NSS unavailable"
reg_info "before: /etc=$ETC inode=$EI; passwd=$PASSWD inode=$PI"

# Capture setxattr family on all paths; inode watches detect aliases.
# Unique keys avoid broken ausearch --start recent/today parsing.
KEY="dhec_$(date +%s)_$$"; WK="dhew_$(date +%s)_$$"
ADDED=0; WE=0; WP=0; INCIDENT=0
WS=""; SID=""; CRED=""; OBS_DIR=""; WATCH_PID=""; FAN_LOG=""
cleanup() {
  if [ -n "$WATCH_PID" ]; then
    kill "$WATCH_PID" >/dev/null 2>&1 || true
    wait "$WATCH_PID" 2>/dev/null || true
  fi
  if [ "$INCIDENT" = 1 ]; then
    echo "SECURITY_INCIDENT=1; guest forensic state deliberately preserved" >&2
  elif [ -n "$SID" ] && [ -n "$CRED" ]; then
    dh session delete --token-file "$CRED" "$SID" >/dev/null 2>&1 || true
    [ -z "$WS" ] || rm -rf -- "$WS"
  elif [ -n "$WS" ]; then rm -rf -- "$WS"; fi
  [ "$ADDED" = 1 ] && auditctl -d always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -k "$KEY" >/dev/null 2>&1 || true
  [ "$WE" = 1 ] && auditctl -W /etc -p a -k "$WK" >/dev/null 2>&1 || true
  [ "$WP" = 1 ] && auditctl -W /etc/passwd -p a -k "$WK" >/dev/null 2>&1 || true
  if [ "$INCIDENT" != 1 ]; then
    [ -z "$CRED" ] || rm -f -- "$CRED"
    [ -z "$OBS_DIR" ] || rm -rf -- "$OBS_DIR"
  fi
}
trap cleanup EXIT
auditctl -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -k "$KEY" >/dev/null 2>&1 || reg_blocked "audit syscall rule failed"
ADDED=1
auditctl -w /etc -p a -k "$WK" >/dev/null 2>&1 || reg_blocked "audit /etc watch failed"
WE=1
auditctl -w /etc/passwd -p a -k "$WK" >/dev/null 2>&1 || reg_blocked "audit passwd watch failed"
WP=1
audit_dump() {
  echo "--- auditctl status ---"
  auditctl -s 2>&1 | tail -12 || true
  echo "--- audit key $KEY / inode-watch $WK records ---"
  { ausearch -k "$KEY" --raw 2>/dev/null; ausearch -k "$WK" --raw 2>/dev/null; } |
    grep -E '^type=(SYSCALL|PATH|AVC|PROCTITLE)' | sort -u | redact | tail -90 || true
  echo "--- raw audit-log tail (filtered to xattr or protected inode) ---"
  if [ -r /var/log/audit/audit.log ]; then
    grep -E "(key=\"($KEY|$WK)\"|key=($KEY|$WK)|syscall=(188|189|190)( |$))" /var/log/audit/audit.log 2>/dev/null |
      tail -60 | redact || true
  fi
}
forensic_dump() {
  # Allow the independent observer to drain its event queue after build exit.
  sleep 0.5
  echo "--- FAN_ATTRIB exact-inode attribution ---"
  if [ -n "$FAN_LOG" ] && [ -f "$FAN_LOG" ]; then
    cat "$FAN_LOG" | redact
  else
    echo "(fanotify observer not started)"
  fi
  audit_dump
}
# Fail even on transient xattr writes subsequently undone: exact inode match.
# A parent PATH in an unrelated /etc child operation is not an inode write.
check_audit() {
  local hit
  hit="$(ausearch -k "$WK" --raw 2>/dev/null | awk -v e="${EI##*:}" -v p="${PI##*:}" '
    function sn(s,t) { t=s; sub(/^.*audit\([^:]+:/,"",t); sub(/\).*$/,"",t); return t }
    /^type=SYSCALL / && /success=yes/ && /syscall=(188|189|190)( |$)/ { sc[sn($0)]=$0 }
    /^type=PATH / && !/nametype=PARENT/ && ($0 ~ "inode=" e "( |$)" || $0 ~ "inode=" p "( |$)") { paths[sn($0)]=$0 }
    END { for (x in paths) if (x in sc) { print sc[x]; print paths[x] } }
  ' | head -20)"
  if [ -n "$hit" ]; then
    INCIDENT=1
    printf 'SECURITY_FAIL: successful xattr mutation on protected inode\n%s\n' "$hit" | redact >&2
    forensic_dump
    reg_fail "host /etc or passwd inode xattr changed"
    reg_result
  fi
}
check_host() {
  local phase="$1" ec pc ei pi
  ec="$(ctx /etc)"; pc="$(ctx /etc/passwd)"; ei="$(ino /etc)"; pi="$(ino /etc/passwd)"
  if [ "$ec" != "$ETC" ] || [ "$pc" != "$PASSWD" ] || [ "$ei" != "$EI" ] || [ "$pi" != "$PI" ] ||
     ! getent passwd sshd >/dev/null 2>&1 || ! getent passwd opc >/dev/null 2>&1; then
    INCIDENT=1
    printf 'SECURITY_FAIL at %s: /etc %s->%s; passwd %s->%s; inode %s->%s and %s->%s\n' \
      "$phase" "$ETC" "$ec" "$PASSWD" "$pc" "$EI" "$ei" "$PI" "$pi" >&2
    forensic_dump
    reg_fail "host label/inode/NSS integrity changed at $phase"
    reg_result
  fi
  check_audit
  reg_ok "$phase: /etc and passwd contexts, inodes and NSS unchanged"
}

# Public session and build API; never invoke synthetic chcon or restorecon.
U=dhecprobe
HOME_DIR="$(reg_setup_principal "$U")" || reg_blocked "principal setup failed"
WS="$HOME_DIR/ws-etc-pentest"
[ ! -e "$WS" ] || reg_blocked "existing workspace $WS"
mkdir -p "$WS"; chown "$U:$U" "$WS"
CRED="/tmp/dh-etc-$(date +%s)-$$.token"
reg_principal_credential "$U" "$CRED" || reg_blocked "credential setup failed"
# Creating the *test principal* legitimately replaces /etc/passwd via useradd.
# The initial label contract must survive; only the inode identity baseline is
# re-established after this known test fixture preparation, before any Session
# or untrusted build is admitted. No relabel is tolerated in either phase.
if [ "$(ctx /etc)" != "$ETC" ] || [ "$(ctx /etc/passwd)" != "$PASSWD" ]; then
  INCIDENT=1
  reg_fail "SELinux host label changed during principal setup"
  audit_dump
  reg_result
fi
EI="$(ino /etc)"; PI="$(ino /etc/passwd)"
[ -n "$EI" ] && [ -n "$PI" ] || reg_blocked "post-principal inode inventory missing"
check_host "principal setup"

# Independent kernel FAN_ATTRIB evidence. Global filesystem mark covers
# aliases without relying on the path the mutating process used.
# Positive control is a USER xattr on a disposable scratch inode.
OBS_DIR="$(mktemp -d /opt/uat/dhec-observer.XXXXXXXX)" ||
  reg_blocked "cannot allocate root-filesystem observer scratch"
PROBE="$OBS_DIR/positive-control"
: > "$PROBE"
[ "$(stat -c %d "$PROBE")" = "$(stat -c %d /etc)" ] ||
  reg_blocked "observer positive control is not on /etc filesystem"
FAN_LOG="$OBS_DIR/fanotify.log"
python3 -u "$SCRIPT_DIR/uat-selinux-etc-fanotify.py" \
  --ready "$OBS_DIR/ready" --probe "$PROBE" > "$FAN_LOG" 2>&1 &
WATCH_PID=$!
for _ in $(seq 1 30); do
  [ -f "$OBS_DIR/ready" ] && break
  kill -0 "$WATCH_PID" 2>/dev/null || break
  sleep 0.1
done
if [ ! -f "$OBS_DIR/ready" ]; then
  cat "$FAN_LOG" >&2 || true
  reg_blocked "fanotify could not establish filesystem observation"
fi
python3 - "$PROBE" <<'PY'
import os, sys
os.setxattr(sys.argv[1], "user.dhec_positivectrl", b"1")
PY
for _ in $(seq 1 30); do
  grep -Fq "FANOTIFY_TARGET path=$PROBE " "$FAN_LOG" && break
  sleep 0.1
done
if grep -Fq "FANOTIFY_TARGET path=$PROBE " "$FAN_LOG"; then
  reg_ok "FAN_ATTRIB positive control observed on root filesystem"
else
  forensic_dump
  reg_blocked "FAN_ATTRIB positive control not observed"
fi
if ausearch -k "$KEY" --raw 2>/dev/null | grep -q 'type=SYSCALL'; then
  reg_ok "syscall audit positive control observed"
else
  reg_info "syscall audit source lacks positive control; FAN_ATTRIB remains authoritative"
fi
reg_session "$CRED" "$WS" || reg_blocked "session creation failed"
SID="$REG_SESSION_ID"; export DOCKER_HELPER_SESSION_TOKEN="$REG_SESSION_TOKEN"
check_host "session create"
build_case() {
  local name="$1" target="$2" dockerfile="$3" image="$4" ctx out rc=0
  ctx="$WS/$name"
  mkdir -p "$ctx"
  ln -s "$target" "$ctx/hostetc"
  printf '%s\n' "$dockerfile" > "$ctx/Dockerfile"
  chown -R "$U:$U" "$ctx"
  check_host "before $name"
  out="$(timeout 180 /usr/bin/docker-helper build "$name" --dockerfile Dockerfile --image "$image" 2>&1)" || rc=$?
  if [ "$rc" -eq 124 ]; then
    reg_fail "$name: BuildKit timeout (not a valid observed denial)"
  elif [ "$rc" -eq 0 ]; then
    reg_fail "$name: unexpected symlink COPY success"
  elif printf '%s\n' "$out" | grep -Fq docker_build_failed; then
    reg_ok "$name: BuildKit rejected dangling absolute symlink (rc=$rc)"
  else
    reg_fail "$name: unexpected failure stage (rc=$rc): $(printf '%s\n' "$out" | redact | tail -4)"
  fi
  check_host "after $name"
  forensic_dump
}
# Exact malicious fixture from second incident (minus output-only filtering).
build_case _btest3 /etc $'FROM alpine:3.20\nCOPY hostetc/passwd /from-symlink\nRUN echo "== copy symlink target =="; head -1 /from-symlink || echo FAILCOPY\nRUN echo "== bind mount hostetc =="; ls /mnt 2>/dev/null | head -3 || true' dh-ptest:sym
# Earlier passwd incident: probe direct file symlink, not claimed exact history.
build_case _btest_passwd /etc/passwd $'FROM alpine:3.20\nCOPY hostetc /from-symlink' dh-ptest:passwd
mkdir -p "$WS/_control"
printf 'FROM alpine:3.20\nRUN true\n' > "$WS/_control/Dockerfile"
chown -R "$U:$U" "$WS/_control"
rc=0
out="$(timeout 180 /usr/bin/docker-helper build _control --dockerfile Dockerfile --image dh-ptest:control 2>&1)" || rc=$?
[ "$rc" -eq 0 ] && reg_ok "symlink-free control succeeds" ||
  reg_fail "control failed (rc=$rc): $(printf '%s\n' "$out" | redact | tail -3)"
check_host "symlink-free control"
dh session delete --token-file "$CRED" "$SID" >/dev/null 2>&1 || reg_fail "session delete failed"
SID=""
check_host "session delete"
forensic_dump
reg_result
