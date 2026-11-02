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

# Linux audit syscall receiver proven in independent VM run 41446427180.
# Audit raw source is /var/log/audit/audit.log, never ausearch-key.
KEY="dhec_$(date +%s)_$$"; RULE=0; INCIDENT=0
WS=""; SID=""; CRED=""; OBS_DIR=""; LOST_BEFORE=""
AUDIT_PARSER="$SCRIPT_DIR/uat-selinux-etc-audit-evidence.py"
[ -r "$AUDIT_PARSER" ] || reg_blocked "raw audit reader missing"
cleanup() {
  if [ "$INCIDENT" = 1 ]; then
    echo "SECURITY_INCIDENT=1; operation stopped for review" >&2
  elif [ -n "$SID" ] && [ -n "$CRED" ]; then
    dh session delete --token-file "$CRED" "$SID" >/dev/null 2>&1 || true
    [ -z "$WS" ] || rm -rf -- "$WS"
  elif [ -n "$WS" ]; then
    rm -rf -- "$WS"
  fi
  [ "$RULE" = 0 ] || auditctl -d always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -k "$KEY" >/dev/null 2>&1 || true
  if [ "$INCIDENT" != 1 ]; then
    [ -z "$CRED" ] || rm -f -- "$CRED"
    [ -z "$OBS_DIR" ] || rm -rf -- "$OBS_DIR"
  fi
}
trap cleanup EXIT
snapshot() { [ "$RULE" = 1 ] && python3 "$AUDIT_PARSER" capture "$KEY" "$OBS_DIR/audit.raw"; }
audit_health() {
  [ "$RULE" = 1 ] || return 0
  local lost
  lost="$(auditctl -s | awk '$1=="lost" {print $2}')"
  [ -n "$lost" ] && [ "$lost" = "$LOST_BEFORE" ] ||
    reg_blocked "audit event loss or unreadable counter (was=$LOST_BEFORE now=$lost)"
}
forensic_dump() {
  sleep 0.3
  snapshot || true
  echo "--- raw audit xattr events, complete serials ---"
  if [ -s "$OBS_DIR/audit.raw" ]; then
    python3 "$AUDIT_PARSER" explain "$OBS_DIR/audit.raw" /etc /etc/passwd | redact
  else
    echo "NO_KEYED_RECORDS (verify positive control and audit health)"
  fi
  auditctl -s || true
  audit_health
}
check_audit() {
  [ "$RULE" = 1 ] || return 0
  snapshot || reg_blocked "raw audit snapshot failed"
  audit_health
  if python3 "$AUDIT_PARSER" protected "$OBS_DIR/audit.raw" /etc /etc/passwd; then return 0; fi
  INCIDENT=1
  forensic_dump
  reg_fail "protected host inode had successful xattr write"
  reg_result
}
check_host() {
  local phase="$1" ec pc ei pi
  ec="$(ctx /etc)"; pc="$(ctx /etc/passwd)"; ei="$(ino /etc)"; pi="$(ino /etc/passwd)"
  if [ "$ec" != "$ETC" ] || [ "$pc" != "$PASSWD" ] ||
     [ "$ei" != "$EI" ] || [ "$pi" != "$PI" ] ||
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

# Arm the proven audit observer after useradd replaced /etc/passwd
# legitimately. This rule monitors host xattr writes through ANY pathname.
systemctl enable --now auditd >/dev/null 2>&1 ||
  reg_blocked "auditd service unavailable"
auditctl -e 1 >/dev/null 2>&1 || reg_blocked "cannot enable audit"
[ "$(auditctl -s | awk '$1=="enabled" {print $2}')" = 1 ] ||
  reg_blocked "audit is disabled"
echo "AUDIT_RULES_BEFORE"; auditctl -l
if auditctl -l | grep -Eq '^-a never,task([[:space:]]|$)'; then
  auditctl -d never,task >/dev/null 2>&1 ||
    reg_blocked "cannot remove never,task in disposable VM"
  if auditctl -l | grep -Eq '^-a never,task([[:space:]]|$)'; then
    reg_blocked "never,task remained active"
  fi
  reg_ok "audit never,task filter disabled in guest"
fi
[ -r /var/log/audit/audit.log ] || reg_blocked "raw audit log not readable"
LOST_BEFORE="$(auditctl -s | awk '$1=="lost" {print $2}')"
[ -n "$LOST_BEFORE" ] || reg_blocked "audit loss counter missing"
OBS_DIR="$(mktemp -d /opt/uat/dhec-audit.XXXXXXXX)" ||
  reg_blocked "cannot allocate scratch on /etc filesystem"
[ "$(stat -c %d "$OBS_DIR")" = "$(stat -c %d /etc)" ] ||
  reg_blocked "audit positive controls must be on /etc device"
mkdir "$OBS_DIR/directory"
printf 'control\n' > "$OBS_DIR/file"
ln "$OBS_DIR/file" "$OBS_DIR/alias"
auditctl -a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -k "$KEY" >/dev/null ||
  reg_blocked "cannot install xattr syscall audit rule"
RULE=1
auditctl -l | grep -F -- "$KEY" || reg_blocked "xattr audit rule missing"
python3 - "$OBS_DIR" <<'PY'
import os, sys
w=sys.argv[1]
with open(w+"/control.pid","w") as f: f.write(str(os.getpid()))
for p,n in (("file","user.dhec_file"),("directory","user.dhec_dir"),("alias","user.dhec_alias")):
    os.setxattr(w+"/"+p,n,b"1")
PY
PROVEN=0
for _ in $(seq 1 30); do
  snapshot || reg_blocked "cannot read raw audit evidence"
  if python3 "$AUDIT_PARSER" control "$OBS_DIR/audit.raw" \
     "$(cat "$OBS_DIR/control.pid")" "$OBS_DIR/file" "$OBS_DIR/directory"; then
    PROVEN=1; break
  fi
  sleep 0.1
done
[ "$PROVEN" = 1 ] || reg_blocked "audit positive control missing: file, dir, alias"
audit_health
reg_ok "raw audit receiver proved on file, directory, hardlink"

# PROOF SEAM: never,task was loaded when dockerd/docker-helper were spawned.
# Removing that rule may not re-enable audit for EXISTING task contexts or
# their descendants. Recreate both service process trees only in disposable VM
# AFTER removing never,task and arming the syscall rule. Compare the PIDs.
OLD_DOCKER="$(systemctl show -p MainPID --value docker.service)"
OLD_HELPER="$(systemctl show -p MainPID --value docker-helper.service)"
systemctl restart docker.service || reg_blocked "cannot restart Docker after audit admission"
systemctl restart docker-helper.service || reg_blocked "cannot restart docker-helper after audit admission"
NEW_DOCKER="$(systemctl show -p MainPID --value docker.service)"
NEW_HELPER="$(systemctl show -p MainPID --value docker-helper.service)"
reg_info "audit-seam: dockerd PID $OLD_DOCKER -> $NEW_DOCKER; docker-helper PID $OLD_HELPER -> $NEW_HELPER"
[ -n "$NEW_DOCKER" ] && [ -n "$NEW_HELPER" ] &&
[ "$NEW_DOCKER" != 0 ] && [ "$NEW_HELPER" != 0 ] &&
[ "$NEW_DOCKER" != "$OLD_DOCKER" ] && [ "$NEW_HELPER" != "$OLD_HELPER" ] ||
  reg_blocked "post-audit service process-tree replacement not proven"
systemctl is-active --quiet docker-helper.service ||
  reg_blocked "docker-helper service not active after audit-seam restart"
DOCKER_READY=0
for _ in $(seq 1 20); do
  if docker info >/dev/null 2>&1; then DOCKER_READY=1; break; fi
  sleep 0.25
done
[ "$DOCKER_READY" = 1 ] || reg_blocked "Docker not healthy after audit-seam restart"
check_host "after audit-seam service restarts"
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
