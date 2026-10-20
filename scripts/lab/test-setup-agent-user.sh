#!/usr/bin/env bash
#
# test-setup-agent-user.sh — focused tests for scripts/lab/setup-agent-user.sh
# with stubbed root tooling (no root, no VM, no docker-helper daemon).
#
# The lab-VM guard itself is covered by scripts/lab/test-lab-vm-guard.sh
# (direct cases + unmodified-script refusals), so these tests run a COPY of
# the lab scripts whose guard stub only requires an existing marker file.
#
# What this protects (one invariant per test):
#   1. a fresh run creates a DEDICATED-uid account (useradd -u, never -o) and
#      grants the docker group;
#   2. a fresh run picks the next UNIQUE uid through NSS when the preferred
#      one is taken (no -o, no silent collision); two taken uids -> next free;
#   3. an existing account with an ALLOCATED uid differing from the preferred
#      one is accepted when its identity is coherent (unique in NSS, distinct
#      from opc, principal and ownership consistent) -- interrupted
#      provisioning resumes without changing the identity;
#   4. an account sharing the admin account's (opc) uid FAILS CLOSED: no
#      usermod, no useradd, no /etc/passwd edit, no other mutation;
#   5. a principal record disagreeing with the OS account FAILS CLOSED before
#      any helper mutation (no allowed-root add, no credential ops);
#   6. a good run creates the principal + credential and installs the aliases;
#   7. a second run is idempotent (no duplicate principal/credential);
#   8. an existing principal with a valid installed credential is reused
#      (no create, no rotate);
#   9. a credential of a DIFFERENT principal is not accepted (fail-closed);
#  10. a missing local credential does NOT rotate implicitly -- it fails closed;
#  11. --recover-credential performs the explicit rotate and reinstall;
#  12. the one-time token never leaks to stdout/stderr;
#  13. root / agent SSH config is not touched (no .ssh handling);
#  14. the agent is the trusted launcher (docker group), never the model;
#  15. post-provisioning verification runs (unique uid + ownership proof).
#
# Usage: scripts/lab/test-setup-agent-user.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LAB_DIR="$SRC_DIR/lab"
[ -f "$LAB_DIR/setup-agent-user.sh" ] || { echo "missing $LAB_DIR/setup-agent-user.sh" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Run the tested script from a COPY of the lab directory whose guard stub
# requires an existing marker (the real guard cases live in their own suite).
LAB_COPY="$WORK/lab"
mkdir -p "$LAB_COPY"
cp "$LAB_DIR"/*.sh "$LAB_COPY"/
cat > "$LAB_COPY/lab-vm-guard.sh" <<'SH'
# Test stub: the real guard's cases are covered by test-lab-vm-guard.sh.
require_lab_vm() {
  [ -r "${LAB_VM_TEST_MARKER:?}" ] || { printf 'guard stub: no marker\n' >&2; exit 1; }
}
SH

SETUP="$LAB_COPY/setup-agent-user.sh"
ALIASES="$LAB_COPY/agent-aliases.sh"

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2' got '$3')"; fi; }
contains() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2' in '$3')" ;; esac; }
not_contains() { case "$3" in *"$2"*) bad "$1 (unexpected '$2' in '$3')" ;; *) ok "$1" ;; esac; }
count() { grep -cF "$1" "$2" 2>/dev/null || true; }

# --- stubs -----------------------------------------------------------------
SHIM="$WORK/shim"; mkdir -p "$SHIM"
REC="$WORK/rec"
AGENT_HOME="$WORK/home"

cat > "$SHIM/id" <<'SH'
#!/bin/sh
case "${1:-}" in
  -u)
    case "${2:-}" in
      opc) echo 1000 ;;
      "") echo 0 ;;
      *) cat "$UIDMARK" 2>/dev/null || echo 1001 ;;
    esac ;;
  -g) cat "$UIDMARK" 2>/dev/null || echo 1001 ;;
  -nG) if [ -f "$GROUPMARK" ]; then echo "agent docker"; else echo "agent"; fi ;;
  "") echo "uid=0(root)" ;;
  *) [ -f "$USERMARK" ] ;;
esac
SH
cat > "$SHIM/useradd" <<'SH'
#!/bin/sh
echo "useradd $*" >> "$REC"
uid=""
prev=""
for a in "$@"; do
  [ "$prev" = "-u" ] && uid="$a"
  prev="$a"
done
[ -n "$uid" ] || { echo "useradd without -u" >&2; exit 2; }
: > "$USERMARK"
printf '%s\n' "$uid" > "$UIDMARK"
SH
cat > "$SHIM/usermod" <<'SH'
#!/bin/sh
echo "usermod $*" >> "$REC"
case "${1:-}" in
  -u) [ -n "${USERMOD_FAIL:-}" ] && exit 8; echo "$2" > "$UIDMARK" ;;
  *) : > "$GROUPMARK" ;;
esac
SH
cat > "$SHIM/getent" <<'SH'
#!/bin/sh
# passwd/group NSS lookups driven by the stub state:
#   USERMARK set            -> the agent account exists at $UIDMARK
#   TAKEN_UIDS              -> foreign USERS occupy those uids
#   TAKEN_GID               -> a foreign GROUP occupies that gid
#   DUP_UID                 -> the passwd dump contains a duplicate uid
uid="$UIDMARK"
[ -f "$USERMARK" ] || uid=""
case "${1:-}" in
  passwd)
    if [ "${2:-}" = docker ]; then exit 1; fi
    if [ -n "$uid" ] && { [ "${2:-}" = agent ] || [ "${2:-}" = "$(cat "$UIDMARK")" ]; }; then
      printf 'agent:x:%s:\n' "$(cat "$UIDMARK")"; exit 0
    fi
    if [ -n "${TAKEN_UIDS:-}" ]; then
      for t in $TAKEN_UIDS; do
        if [ "${2:-}" = "$t" ]; then printf 'other:x:%s:\n' "$t"; exit 0; fi
      done
    fi
    if [ -z "${2:-}" ]; then
      [ -n "$uid" ] && printf 'agent:x:%s:\n' "$(cat "$UIDMARK")"
      [ -n "${DUP_UID:-}" ] && [ -n "$uid" ] && printf 'dup:x:%s:\n' "$(cat "$UIDMARK")"
      exit 0
    fi
    exit 1 ;;
  group)
    if [ "${2:-}" = docker ]; then exit 0; fi
    if [ -n "${TAKEN_GID:-}" ] && [ "${2:-}" = "$TAKEN_GID" ]; then
      printf 'otherg:x:%s:\n' "$TAKEN_GID"; exit 0
    fi
    if [ -n "$uid" ] && [ "${2:-}" = "$(cat "$UIDMARK")" ]; then
      printf 'agent:x:%s:\n' "$(cat "$UIDMARK")"; exit 0
    fi
    exit 1 ;;
esac
exit 2
SH
cat > "$SHIM/chown" <<'SH'
#!/bin/sh
echo "chown $*" >> "$REC"
exit 0
SH
cat > "$SHIM/sed" <<'SH'
#!/bin/sh
echo "sed $*" >> "$REC"
exit 0
SH
cat > "$SHIM/install" <<'SH'
#!/bin/sh
echo "install $*" >> "$REC"
d=0; mode=""
while [ $# -gt 0 ]; do
  case "$1" in
    -d) d=1; shift ;;
    -m) shift; mode="$1"; shift ;;
    -o|-g) shift 2 ;;
    *) break ;;
  esac
done
if [ "$d" = 1 ]; then
  for p in "$@"; do mkdir -p "$p"; [ -n "$mode" ] && chmod "$mode" "$p"; done
elif [ "$#" = 2 ]; then
  cp "$1" "$2"; [ -n "$mode" ] && chmod "$mode" "$2"
fi
SH
cat > "$SHIM/stat" <<'SH'
#!/bin/sh
# The post-provisioning ownership check must see the agent user.
while [ $# -gt 0 ]; do
  case "$1" in
    -c) shift; [ "$1" = '%U' ] && { echo "${STATUSER:-agent}"; exit 0; }; shift ;;
    *) shift ;;
  esac
done
exit 1
SH
cat > "$SHIM/su" <<'SH'
#!/bin/sh
cmd=""
while [ $# -gt 0 ]; do
  case "$1" in
    -s) shift 2 ;;
    -c) shift; cmd="$1"; shift ;;
    *) shift ;;
  esac
done
exec bash -c "$cmd"
SH
cat > "$SHIM/docker-helper" <<'SH'
#!/bin/sh
echo "dh $*" >> "$REC"
case "$1 $2" in
  "config allowed-root")
    case "$3" in
      list) [ -f "$ALLOWED" ] && cat "$ALLOWED" ;;
      add) shift 3; echo "$1" > "$ALLOWED" ;;
    esac ;;
  "principal show")
    [ -f "$PRINCIPAL" ] || exit 1
    if [ -n "${PRINCIPAL_STALE_UID:-}" ]; then
      printf '{"uid":%s,"gid":%s}\n' "$PRINCIPAL_STALE_UID" "$PRINCIPAL_STALE_UID"
    else
      printf '{"uid":%s,"gid":%s}\n' "$(cat "$UIDMARK")" "$(cat "$UIDMARK")"
    fi ;;
  "principal create") : > "$PRINCIPAL"; printf '{"token":"dhc_NEWTOKEN"}\n' ;;
  "principal credential") printf '{"token":"dhc_ROTTOKEN"}\n' ;;
  "credential install")
    tok="$(cat)"
    mkdir -p "$AGENT_HOME/.config/docker-helper"
    printf '%s\n' "$tok" > "$AGENT_HOME/.config/docker-helper/credential.token" ;;
  "self --json")
    [ -f "$SELFOK" ] || exit 1
    if [ -n "${WRONG_SELF:-}" ]; then
      printf '{"ok":true,"type":"principal","resource":{"username":"someoneelse"}}\n'
    else
      printf '{"ok":true,"type":"principal","resource":{"username":"agent"}}\n'
    fi ;;
esac
SH
chmod +x "$SHIM"/*
# The `self` probe is matched on "$1 $2"; a bare `self` is not used by setup.

export PATH="$SHIM:$PATH"
export REC AGENT_HOME ALLOWED="$WORK/allowed" PRINCIPAL="$WORK/principal"
export USERMARK="$WORK/usermark" UIDMARK="$WORK/uidmark" GROUPMARK="$WORK/groupmark" SELFOK="$WORK/selfok"
MARKER="$WORK/marker"
export LAB_VM_TEST_MARKER="$MARKER"
CRED="$AGENT_HOME/.config/docker-helper/credential.token"

run_setup() { # [setup-args...] -> stdout+stderr
  bash "$SETUP" "$@" 2>&1
}
reset_state() {
  : > "$REC"
  rm -f "$USERMARK" "$UIDMARK" "$PRINCIPAL" "$SELFOK" "$ALLOWED"
  rm -rf "$AGENT_HOME"; mkdir -p "$AGENT_HOME"
  unset TAKEN_UIDS TAKEN_GID DUP_UID PRINCIPAL_STALE_UID WRONG_SELF USERMOD_FAIL 2>/dev/null || true
}

# --- 1. fresh run: dedicated uid, no -o -------------------------------------
reset_state
printf 'docker-helper-lab-vm 1 x\n' > "$MARKER"
: > "$SELFOK"
out="$(run_setup)" && ok "fresh run succeeds" || bad "fresh run failed: $out"
rec="$(cat "$REC")"
contains "fresh run uses useradd -u 1001" "useradd -u 1001 " "$rec"
not_contains "fresh run does NOT use useradd -o" "useradd -o" "$rec"
contains "fresh run re-owns the home tree" "chown -R agent:agent $AGENT_HOME" "$rec"
contains "agent added to docker group" "usermod -aG docker agent" "$rec"
contains "principal created" "dh principal create agent" "$rec"
contains "credential installed" "dh credential install --force" "$rec"
contains "global allowed root added" "dh config allowed-root add $AGENT_HOME" "$rec"
[ -f "$AGENT_HOME/.bash_aliases" ] && ok "aliases installed" || bad "aliases not installed"
cmp -s "$ALIASES" "$AGENT_HOME/.bash_aliases" && ok "installed aliases match the source" || bad "installed aliases differ"
grep -qF '.bash_aliases' "$AGENT_HOME/.bashrc" && ok "bashrc sources the aliases" || bad "bashrc does not source the aliases"
not_contains "no uid migration tooling ran" "usermod -u" "$rec"
not_contains "no passwd edit ran" "sed " "$rec"
contains "post-provisioning verification ran" "verified: unique uid" "$out"

# --- 11. token never leaks to stdout/stderr --------------------------------
not_contains "new token does not leak to output" "dhc_NEWTOKEN" "$out"

# no SSH-key management
[ -e "$AGENT_HOME/.ssh" ] && bad "agent .ssh was created" || ok "agent .ssh untouched"
not_contains "install never touches /root" "/root" "$rec"
not_contains "install never touches .ssh" ".ssh" "$rec"

# --- 2. unique uid through NSS when the preferred one is taken --------------
reset_state
export TAKEN_UIDS="1001"
: > "$SELFOK"
out="$(run_setup)" && ok "run with taken preferred uid succeeds" || bad "run with taken uid failed: $out"
rec="$(cat "$REC")"
contains "next unique uid is picked (1002)" "useradd -u 1002 " "$rec"
not_contains "collision is never forced with -o" "useradd -o" "$rec"

# --- 2a. two taken uids -> the next free uid is picked (1003) ---------------
reset_state
export TAKEN_UIDS="1001 1002"
: > "$SELFOK"
out="$(run_setup)" && ok "run with two taken uids succeeds" || bad "run with two taken uids failed: $out"
contains "the next free uid is picked (1003)" "useradd -u 1003 " "$(cat "$REC")"

# --- 2b. uid taken by a GROUP also counts as taken ---------------------------
reset_state
export TAKEN_GID=1001
: > "$SELFOK"
out="$(run_setup)" && ok "run with taken gid succeeds" || bad "run with taken gid failed: $out"
contains "uid colliding with a group is skipped" "useradd -u 1002 " "$(cat "$REC")"

# --- 2c. an existing account with an ALLOCATED uid != preferred is accepted --
# The account was created with uid 1002 (1001 was taken at the time); a
# re-run must accept the coherent allocated identity, not demand 1001.
reset_state
: > "$USERMARK"; echo 1002 > "$UIDMARK"; : > "$PRINCIPAL"; : > "$SELFOK"
mkdir -p "$AGENT_HOME/.config/docker-helper"; printf 'dhc_OLD\n' > "$CRED"
: > "$REC"
out="$(run_setup)" && ok "allocated uid 1002 is accepted on re-run" || bad "allocated-uid re-run failed: $out"
rec="$(cat "$REC")"
not_contains "allocated-uid re-run does not useradd" "useradd" "$rec"
not_contains "allocated-uid re-run does not usermod -u" "usermod -u" "$rec"
check "allocated-uid re-run does not rotate" "0" "$(count 'principal credential rotate' "$REC")"
contains "allocated-uid re-run logs the allocated identity" "allocated uid 1002" "$out"
contains "allocated-uid re-run verifies the result" "verified: unique uid" "$out"

# --- 3. an account sharing the admin account's uid: fail-closed -------------
reset_state
: > "$USERMARK"; echo 1000 > "$UIDMARK"
: > "$REC"
if out="$(run_setup)"; then bad "opc uid collision was accepted"; else ok "opc uid collision fails closed"; fi
rec="$(cat "$REC")"
not_contains "collision fail-closed does not usermod the account" "usermod -u" "$rec"
not_contains "collision fail-closed does not useradd" "useradd" "$rec"
not_contains "collision fail-closed does not edit /etc/passwd" "sed " "$rec"
not_contains "collision fail-closed does not touch the helper" "dh " "$rec"
contains "collision fail-closed names the admin account" "shares uid 1000 with the admin account opc" "$out"

# --- 3b. interrupted first provisioning resumes predictably -----------------
# The account was created with uid 1002 (1001 was taken) but the principal
# was never created. The re-run must accept the allocated identity and finish
# provisioning WITHOUT changing the uid.
reset_state
: > "$USERMARK"; echo 1002 > "$UIDMARK"
export TAKEN_UIDS="1001"
: > "$SELFOK"
: > "$REC"
out="$(run_setup)" && ok "interrupted provisioning resumes" || bad "resume failed: $out"
unset TAKEN_UIDS
rec="$(cat "$REC")"
not_contains "resume does not recreate the account" "useradd" "$rec"
not_contains "resume does not change the identity" "usermod -u" "$rec"
contains "resume creates the principal" "dh principal create agent" "$rec"
contains "resume installs the credential" "dh credential install --force" "$rec"
contains "resume verifies the result" "verified: unique uid" "$out"

# --- 4. stale principal record (uid/gid disagree with the OS): fail-closed --
reset_state
: > "$USERMARK"; echo 1001 > "$UIDMARK"; : > "$PRINCIPAL"
export PRINCIPAL_STALE_UID=1000
mkdir -p "$AGENT_HOME/.config/docker-helper"; : > "$CRED"
: > "$REC"
if out="$(run_setup)"; then bad "stale principal record was accepted"; else ok "stale principal record fails closed"; fi
unset PRINCIPAL_STALE_UID
rec="$(cat "$REC")"
not_contains "stale record does not touch allowed roots" "config allowed-root add" "$rec"
not_contains "stale record does not rotate" "principal credential rotate" "$rec"
not_contains "stale record does not install credentials" "credential install" "$rec"
not_contains "stale record does not create" "principal create" "$rec"
contains "stale record names the supported recovery" "supported" "$out"

# --- 5. idempotent re-run (valid credential reused) --------------------------
reset_state
: > "$USERMARK"; echo 1001 > "$UIDMARK"; : > "$PRINCIPAL"; : > "$SELFOK"
mkdir -p "$AGENT_HOME/.config/docker-helper"; printf 'dhc_OLD\n' > "$CRED"
: > "$REC"
out="$(run_setup)" && ok "re-run with valid credential succeeds" || bad "re-run failed: $out"
rec="$(cat "$REC")"
check "re-run does not rotate" "0" "$(count 'principal credential rotate' "$REC")"
check "re-run does not create principal" "0" "$(count 'principal create' "$REC")"
check "re-run does not reinstall credential" "0" "$(count 'credential install' "$REC")"
not_contains "re-run does not useradd" "useradd" "$rec"

# --- 9. missing local credential: fail closed, no implicit rotate -----------
reset_state
: > "$USERMARK"; echo 1001 > "$UIDMARK"; : > "$PRINCIPAL"; : > "$SELFOK"
# no credential file
: > "$REC"
if run_setup >/dev/null 2>&1; then bad "missing credential accepted"; else ok "missing credential fails closed"; fi
check "missing credential does not rotate" "0" "$(count 'principal credential rotate' "$REC")"
check "missing credential does not create" "0" "$(count 'principal create' "$REC")"

# --- 10. explicit recovery rotates and reinstalls ----------------------------
reset_state
: > "$USERMARK"; echo 1001 > "$UIDMARK"; : > "$PRINCIPAL"; : > "$SELFOK"
: > "$REC"
out="$(run_setup --recover-credential)" && ok "recovery run succeeds" || bad "recovery run failed: $out"
rec="$(cat "$REC")"
contains "recovery rotates the credential" "dh principal credential rotate agent" "$rec"
contains "recovery reinstalls the credential" "dh credential install --force" "$rec"
not_contains "recovery token does not leak" "dhc_ROTTOKEN" "$out"

# --- 8. another principal's credential is not accepted ----------------------
reset_state
: > "$USERMARK"; echo 1001 > "$UIDMARK"; : > "$PRINCIPAL"; : > "$SELFOK"
export WRONG_SELF=1
mkdir -p "$AGENT_HOME/.config/docker-helper"; printf 'dhc_FOREIGN\n' > "$CRED"
: > "$REC"
if run_setup >/dev/null 2>&1; then bad "another principal's credential was accepted"; else ok "another principal's credential fails closed"; fi
unset WRONG_SELF
check "foreign credential does not rotate" "0" "$(count 'principal credential rotate' "$REC")"
check "foreign credential does not create" "0" "$(count 'principal create' "$REC")"

# --- 6. present-but-invalid credential fails closed (no rotate) -------------
reset_state
: > "$USERMARK"; echo 1001 > "$UIDMARK"; : > "$PRINCIPAL"
mkdir -p "$AGENT_HOME/.config/docker-helper"; printf 'dhc_STALE\n' > "$CRED"
# SELFOK absent -> self fails
: > "$REC"
if run_setup >/dev/null 2>&1; then bad "invalid credential accepted"; else ok "invalid credential fails closed"; fi
check "invalid credential does not rotate" "0" "$(count 'principal credential rotate' "$REC")"

# --- 14. duplicate uid after provisioning: post-verification fails closed ---
reset_state
: > "$USERMARK"; echo 1001 > "$UIDMARK"; : > "$SELFOK"
export DUP_UID=1
if run_setup >/dev/null 2>&1; then bad "duplicate uid accepted by the post-verification"; else ok "duplicate uid fails the post-verification"; fi

echo
printf 'setup-agent-user tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
