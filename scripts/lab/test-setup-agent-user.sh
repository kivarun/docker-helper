#!/usr/bin/env bash
#
# test-setup-agent-user.sh — focused tests for scripts/lab/setup-agent-user.sh
# with stubbed root tooling (no root, no VM, no docker-helper daemon).
#
# What this protects (one invariant per test):
#   1. the lab-VM guard fails closed (missing marker, wrong tag, wrong
#      machine-id) and passes for a correct marker;
#   2. a fresh run creates a DEDICATED-uid account (useradd -u, never -o) and
#      grants the docker group;
#   3. an existing account with the wrong uid is migrated with usermod -u and
#      the home is re-owned (no silent ownership breakage);
#   4. a good run creates the principal + credential and installs the aliases;
#   5. a second run is idempotent (no duplicate principal/credential);
#   6. an existing principal with a valid installed credential is reused
#      (no create, no rotate);
#   7. a missing local credential does NOT rotate implicitly -- it fails closed;
#   8. --recover-credential performs the explicit rotate and reinstall;
#   9. the one-time token never leaks to stdout/stderr;
#  10. root / agent SSH config is not touched (no .ssh handling);
#  11. the agent is the trusted launcher (docker group), never the model.
#
# Usage: scripts/lab/test-setup-agent-user.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SETUP="$SRC_DIR/lab/setup-agent-user.sh"
ALIASES="$SRC_DIR/lab/agent-aliases.sh"
[ -f "$SETUP" ] || { echo "missing $SETUP" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

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
  -u) if [ -n "${2:-}" ]; then cat "$UIDMARK" 2>/dev/null || echo 1001; else echo 0; fi ;;
  -nG) if [ -f "$GROUPMARK" ]; then echo "agent docker"; else echo "agent"; fi ;;
  "") echo "uid=0(root)" ;;
  *) [ -f "$USERMARK" ] ;;
esac
SH
cat > "$SHIM/useradd" <<'SH'
#!/bin/sh
echo "useradd $*" >> "$REC"
: > "$USERMARK"
echo 1001 > "$UIDMARK"
SH
cat > "$SHIM/usermod" <<'SH'
#!/bin/sh
echo "usermod $*" >> "$REC"
if [ "${1:-}" = "-u" ]; then echo "$2" > "$UIDMARK"; else : > "$GROUPMARK"; fi
SH
cat > "$SHIM/getent" <<'SH'
#!/bin/sh
[ "$1" = group ] && [ "$2" = docker ] && exit 0
exit 0
SH
cat > "$SHIM/chown" <<'SH'
#!/bin/sh
echo "chown $*" >> "$REC"
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
  "principal show") [ -f "$PRINCIPAL" ] ;;
  "principal create") : > "$PRINCIPAL"; printf '{"token":"dhc_NEWTOKEN"}\n' ;;
  "principal credential") printf '{"token":"dhc_ROTTOKEN"}\n' ;;
  "credential install")
    tok="$(cat)"
    mkdir -p "$AGENT_HOME/.config/docker-helper"
    printf '%s\n' "$tok" > "$AGENT_HOME/.config/docker-helper/credential.token" ;;
  "self --json") [ -f "$SELFOK" ] && printf '{"ok":true,"type":"principal"}\n' ;;
esac
SH
chmod +x "$SHIM"/*
# The `self` probe is matched on "$1 $2"; a bare `self` is not used by setup.

export PATH="$SHIM:$PATH"
export REC AGENT_HOME ALLOWED="$WORK/allowed" PRINCIPAL="$WORK/principal"
export USERMARK="$WORK/usermark" UIDMARK="$WORK/uidmark" GROUPMARK="$WORK/groupmark" SELFOK="$WORK/selfok"
MID="$(cat /etc/machine-id)"
MARKER="$WORK/marker"
CRED="$AGENT_HOME/.config/docker-helper/credential.token"

run_setup() { # <marker-path> [setup-args...]
  local marker="$1"; shift
  LAB_VM_MARKER="$marker" AGENT_HOME="$AGENT_HOME" bash "$SETUP" "$@"
}
reset_state() {
  : > "$REC"
  rm -f "$USERMARK" "$UIDMARK" "$PRINCIPAL" "$SELFOK" "$ALLOWED"
  rm -rf "$AGENT_HOME"; mkdir -p "$AGENT_HOME"
}

# --- 1. guard --------------------------------------------------------------
: > "$REC"
if run_setup "$WORK/absent" >/dev/null 2>&1; then bad "guard: missing marker accepted"; else ok "guard: missing marker refused"; fi
check "guard: nothing done when refused" "0" "$(count 'dh ' "$REC")"

printf 'wrongtag 1 %s\n' "$MID" > "$MARKER"
if run_setup "$MARKER" >/dev/null 2>&1; then bad "guard: wrong tag accepted"; else ok "guard: wrong tag refused"; fi

printf 'docker-helper-lab-vm 1 deadbeef\n' > "$MARKER"
if run_setup "$MARKER" >/dev/null 2>&1; then bad "guard: wrong machine-id accepted"; else ok "guard: wrong machine-id refused"; fi

# --- 2. fresh run: dedicated uid, no -o ------------------------------------
reset_state
printf 'docker-helper-lab-vm 1 %s\n' "$MID" > "$MARKER"
: > "$SELFOK"
out="$(run_setup "$MARKER" 2>&1)" && ok "fresh run succeeds" || bad "fresh run failed: $out"
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

# --- 9. token never leaks to stdout/stderr ---------------------------------
not_contains "new token does not leak to output" "dhc_NEWTOKEN" "$out"

# no SSH-key management
[ -e "$AGENT_HOME/.ssh" ] && bad "agent .ssh was created" || ok "agent .ssh untouched"
not_contains "install never touches /root" "/root" "$rec"
not_contains "install never touches .ssh" ".ssh" "$rec"

# --- 3. uid migration ------------------------------------------------------
reset_state
printf 'docker-helper-lab-vm 1 %s\n' "$MID" > "$MARKER"
: > "$SELFOK"
: > "$USERMARK"; echo 1000 > "$UIDMARK"; : > "$PRINCIPAL"
mkdir -p "$AGENT_HOME/.config/docker-helper"; : > "$CRED"
out="$(run_setup "$MARKER" 2>&1)" && ok "migration run succeeds" || bad "migration run failed: $out"
rec="$(cat "$REC")"
contains "migration uses usermod -u 1001" "usermod -u 1001 agent" "$rec"
not_contains "migration does not useradd" "useradd" "$rec"
contains "migration re-owns the home tree" "chown -R agent:agent $AGENT_HOME" "$rec"

# --- 5. idempotent re-run (valid credential reused) ------------------------
reset_state
printf 'docker-helper-lab-vm 1 %s\n' "$MID" > "$MARKER"
: > "$USERMARK"; echo 1001 > "$UIDMARK"; : > "$PRINCIPAL"; : > "$SELFOK"
mkdir -p "$AGENT_HOME/.config/docker-helper"; printf 'dhc_OLD\n' > "$CRED"
: > "$REC"
if run_setup "$MARKER" >/dev/null 2>&1; then ok "re-run with valid credential succeeds"; else bad "re-run failed"; fi
rec="$(cat "$REC")"
check "re-run does not rotate" "0" "$(count 'principal credential rotate' "$REC")"
check "re-run does not create principal" "0" "$(count 'principal create' "$REC")"
check "re-run does not reinstall credential" "0" "$(count 'credential install' "$REC")"
not_contains "re-run does not useradd" "useradd" "$rec"

# --- 7. missing local credential: fail closed, no implicit rotate ----------
reset_state
printf 'docker-helper-lab-vm 1 %s\n' "$MID" > "$MARKER"
: > "$USERMARK"; echo 1001 > "$UIDMARK"; : > "$PRINCIPAL"; : > "$SELFOK"
# no credential file
: > "$REC"
if run_setup "$MARKER" >/dev/null 2>&1; then bad "missing credential accepted"; else ok "missing credential fails closed"; fi
check "missing credential does not rotate" "0" "$(count 'principal credential rotate' "$REC")"
check "missing credential does not create" "0" "$(count 'principal create' "$REC")"

# --- 8. explicit recovery rotates and reinstalls ---------------------------
reset_state
printf 'docker-helper-lab-vm 1 %s\n' "$MID" > "$MARKER"
: > "$USERMARK"; echo 1001 > "$UIDMARK"; : > "$PRINCIPAL"; : > "$SELFOK"
: > "$REC"
out="$(run_setup "$MARKER" --recover-credential 2>&1)" && ok "recovery run succeeds" || bad "recovery run failed: $out"
rec="$(cat "$REC")"
contains "recovery rotates the credential" "dh principal credential rotate agent" "$rec"
contains "recovery reinstalls the credential" "dh credential install --force" "$rec"
not_contains "recovery token does not leak" "dhc_ROTTOKEN" "$out"

# --- 6. present-but-invalid credential fails closed (no rotate) ------------
reset_state
printf 'docker-helper-lab-vm 1 %s\n' "$MID" > "$MARKER"
: > "$USERMARK"; echo 1001 > "$UIDMARK"; : > "$PRINCIPAL"
mkdir -p "$AGENT_HOME/.config/docker-helper"; printf 'dhc_STALE\n' > "$CRED"
# SELFOK absent -> self fails
: > "$REC"
if run_setup "$MARKER" >/dev/null 2>&1; then bad "invalid credential accepted"; else ok "invalid credential fails closed"; fi
check "invalid credential does not rotate" "0" "$(count 'principal credential rotate' "$REC")"

echo
printf 'setup-agent-user tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
