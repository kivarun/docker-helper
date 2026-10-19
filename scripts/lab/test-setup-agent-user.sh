#!/usr/bin/env bash
#
# test-setup-agent-user.sh — focused tests for scripts/lab/setup-agent-user.sh
# with stubbed root tooling (no root, no VM, no docker-helper daemon).
#
# What this protects (one invariant per test):
#   1. the lab-VM guard fails closed (missing marker, wrong tag, wrong
#      machine-id) and passes for a correct marker;
#   2. a good run creates the account, grants the docker group, creates the
#      principal + credential, and installs the launcher aliases;
#   3. root / agent SSH config is not touched (no .ssh handling);
#   4. a second run is idempotent (no duplicate principal/credential);
#   5. the agent is the trusted launcher (docker group), never the model.
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
REC="$WORK/rec"; : > "$REC"

cat > "$SHIM/id" <<'SH'
#!/bin/sh
case "${1:-}" in
  -u) echo 0 ;;
  -nG) if [ -f "$GROUPMARK" ]; then echo "agent docker"; else echo "agent"; fi ;;
  "") echo "uid=0(root)" ;;
  *) [ -f "$USERMARK" ] ;;
esac
SH
cat > "$SHIM/useradd" <<'SH'
#!/bin/sh
echo "useradd $*" >> "$REC"
: > "$USERMARK"
SH
cat > "$SHIM/usermod" <<'SH'
#!/bin/sh
echo "usermod $*" >> "$REC"
: > "$GROUPMARK"
SH
cat > "$SHIM/getent" <<'SH'
#!/bin/sh
[ "$1" = group ] && [ "$2" = docker ] && exit 0
exit 0
SH
cat > "$SHIM/chown" <<'SH'
#!/bin/sh
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
  "principal create") : > "$PRINCIPAL"; printf '{"token":"dhc_TESTTOKEN"}\n' ;;
  "principal credential") printf '{"token":"dhc_TESTTOKEN"}\n' ;;
  "credential install")
    cat >/dev/null
    mkdir -p "$AGENT_HOME/.config/docker-helper"
    printf 'dhc_TESTTOKEN\n' > "$AGENT_HOME/.config/docker-helper/credential.token" ;;
esac
SH
chmod +x "$SHIM"/*

export PATH="$SHIM:$PATH"
export REC AGENT_HOME="$WORK/home" ALLOWED="$WORK/allowed" PRINCIPAL="$WORK/principal"
export USERMARK="$WORK/usermark" GROUPMARK="$WORK/groupmark"
MID="$(cat /etc/machine-id)"
MARKER="$WORK/marker"

run_setup() { # <marker-path>
  LAB_VM_MARKER="$1" AGENT_HOME="$AGENT_HOME" bash "$SETUP"
}

# --- 1. guard --------------------------------------------------------------
: > "$REC"
if run_setup "$WORK/absent" >/dev/null 2>&1; then bad "guard: missing marker accepted"; else ok "guard: missing marker refused"; fi
check "guard: nothing done when refused" "0" "$(count 'dh ' "$REC")"

printf 'wrongtag 1 %s\n' "$MID" > "$MARKER"
if run_setup "$MARKER" >/dev/null 2>&1; then bad "guard: wrong tag accepted"; else ok "guard: wrong tag refused"; fi

printf 'docker-helper-lab-vm 1 deadbeef\n' > "$MARKER"
if run_setup "$MARKER" >/dev/null 2>&1; then bad "guard: wrong machine-id accepted"; else ok "guard: wrong machine-id refused"; fi

# --- 2/5. good run ---------------------------------------------------------
printf 'docker-helper-lab-vm 1 %s\n' "$MID" > "$MARKER"
: > "$REC"
if run_setup "$MARKER" >/dev/null 2>&1; then ok "good run succeeds"; else bad "good run failed"; fi

rec="$(cat "$REC")"
contains "account created" "useradd" "$rec"
contains "agent added to docker group" "usermod -aG docker agent" "$rec"
contains "principal created" "dh principal create agent" "$rec"
contains "credential installed" "dh credential install --force" "$rec"
contains "global allowed root added" "dh config allowed-root add $AGENT_HOME" "$rec"
[ -f "$AGENT_HOME/.bash_aliases" ] && ok "aliases installed" || bad "aliases not installed"
cmp -s "$ALIASES" "$AGENT_HOME/.bash_aliases" && ok "installed aliases match the source" || bad "installed aliases differ"
grep -qF '.bash_aliases' "$AGENT_HOME/.bashrc" && ok "bashrc sources the aliases" || bad "bashrc does not source the aliases"

# no SSH-key management
[ -e "$AGENT_HOME/.ssh" ] && bad "agent .ssh was created" || ok "agent .ssh untouched"
not_contains "install never touches /root" "/root" "$rec"
not_contains "install never touches .ssh" ".ssh" "$rec"

# --- 3. idempotent re-run --------------------------------------------------
: > "$REC"
if run_setup "$MARKER" >/dev/null 2>&1; then ok "second run succeeds"; else bad "second run failed"; fi
rec="$(cat "$REC")"
check "no duplicate principal create" "0" "$(count 'dh principal create' "$REC")"
check "no duplicate credential create/install" "0" "$(count 'dh credential install' "$REC")"
not_contains "no duplicate useradd" "useradd" "$rec"

echo
printf 'setup-agent-user tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
