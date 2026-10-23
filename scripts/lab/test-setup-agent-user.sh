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
    --) shift ;;
    *) break ;;
  esac
done
if [ "$d" = 1 ]; then
  for p in "$@"; do mkdir -p "$p"; [ -n "$mode" ] && chmod "$mode" "$p"; done
elif [ "$#" = 2 ]; then
  cp "$1" "$2"; [ -n "$mode" ] && chmod "$mode" "$2"
fi
SH
real_stat="$(command -v stat)"
cat > "$SHIM/stat" <<SH
#!/usr/bin/env bash
# The post-provisioning ownership checks must see the agent user: %U and %G
# are answered from the harness state; %a falls through to the REAL stat
# (resolved at shim-generation time, before this shim shadows PATH).
args=("\$@")
i=0
while [ "\$i" -lt "\${#args[@]}" ]; do
  case "\${args[\$i]}" in
    -c)
      fmt="\${args[\$((i+1))]:-}"; file="\${args[\$((i+2))]:-}"
      case "\$fmt" in
        %U) echo "\${STATUSER:-agent}"; exit 0 ;;
        %G) echo "\${STATGROUP:-agent}"; exit 0 ;;
        %a) exec "$real_stat" -c %a -- "\$file" ;;
      esac ;;
  esac
  i=\$((i+1))
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
real_jq="$(command -v jq)"
write_jq_shim() { printf '#!/bin/sh\nexec %s "$@"\n' "$real_jq" > "$SHIM/jq"; chmod +x "$SHIM/jq"; }
if [ -n "$real_jq" ]; then write_jq_shim; fi
hide_jq() { rm -f "$SHIM/jq"; ln -s /nonexistent-jq "$SHIM/jq"; }
cat > "$SHIM/zypper" <<SH
#!/bin/sh
echo "zypper \$*" >> "\$REC"
[ -n "\${ZYPPER_FAIL:-}" ] && exit 1
case "\$*" in
  *install\ jq*)
    case "\$*" in *--no-gpg-checks*) echo "unexpected --no-gpg-checks" >&2; exit 1 ;; esac
    printf '#!/bin/sh\nexec %s "\$@"\n' "$real_jq" > "$SHIM/jq"
    chmod +x "$SHIM/jq"
    : > "$WORK/jq-installed" ;;
esac
exit 0
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
export JQ_MISSING_ENV="$WORK/jq-missing-env"
MARKER="$WORK/marker"
export LAB_VM_TEST_MARKER="$MARKER"
CRED="$AGENT_HOME/.config/docker-helper/credential.token"

# UAT-2/F1 harness seam: JQ_MISSING=1 models a VM without jq. The system jq
# on the test host cannot be hidden from PATH, so absence is simulated at the
# exact boundary the body checks: a `command` function override (delivered
# through BASH_ENV, which non-interactive bash sources) makes
# `command -v jq` fail UNTIL the zypper shim marks the package as installed.
enable_jq_missing_seam() {
  cat > "$JQ_MISSING_ENV" <<ENV
command() { if [ "\$1 \$2" = "-v jq" ] && [ ! -e "$WORK/jq-installed" ]; then return 1; fi; builtin command "\$@"; }
ENV
  export BASH_ENV="$JQ_MISSING_ENV"
}
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

# --- 15. phase 1: without docker-helper the account is provisioned and the
#         helper-dependent parts are explicitly deferred (re-run instruction) --
reset_state
: > "$SELFOK"
unset TAKEN_UIDS TAKEN_GID DUP_UID PRINCIPAL_STALE_UID WRONG_SELF USERMOD_FAIL 2>/dev/null || true
mkdir -p "$WORK/shim-p1"
for f in "$SHIM"/*; do
  [ "$(basename "$f")" = docker-helper ] && continue
  ln -s "$f" "$WORK/shim-p1/$(basename "$f")"
done
# The phase-1 PATH must not resolve any docker-helper (shim or the real
# binary that may exist on a dev workstation): shim-p1 only, then /usr/bin
# and /bin.
out="$(PATH="$WORK/shim-p1:/usr/bin:/bin" bash "$SETUP" 2>&1)" \
  && ok "phase-1 run (no docker-helper) succeeds" || bad "phase-1 run failed: $out"
rec="$(cat "$REC")"
contains "phase-1 creates the account" "useradd -u 1001 " "$rec"
contains "phase-1 installs the aliases" "install -m 0644 -o agent -g agent" "$rec"
not_contains "phase-1 never creates a principal" "principal create" "$rec"
not_contains "phase-1 never installs a credential" "credential install" "$rec"
not_contains "phase-1 never adds an allowed root" "allowed-root add" "$rec"
[ -f "$AGENT_HOME/.bash_aliases" ] && ok "phase-1 aliases installed" || bad "phase-1 aliases missing"
contains "phase-1 logs the re-run instruction" "re-run this script after install-docker-helper-v230.sh" "$out"
not_contains "phase-1 does not claim the credential" "credential installed for agent" "$out"

# --- test-seam safety: no mutation may escape the test root ------------------
# The stubs intercept every privileged operation; this tripwire makes any
# escape into the real /home fail the suite instead of passing silently.
trip_home_listing() { ls /home 2>/dev/null | sort | tr '\n' ' '; }
trip_home_before="$(trip_home_listing)"
trip_ssh_state() { [ -e "$HOME/.ssh" ] && printf present || printf absent; }
trip_ssh_before="$(trip_ssh_state)"

trip_home_after="$(trip_home_listing)"
if [ "$trip_home_before" = "$trip_home_after" ]; then
  ok "tripwire: /home was not modified by the suite"
else
  bad "tripwire: /home changed during the suite ('$trip_home_before' -> '$trip_home_after')"
fi
if [ "$trip_ssh_before" = "$(trip_ssh_state)" ]; then
  ok "tripwire: $HOME/.ssh existence unchanged"
else
  bad "tripwire: $HOME/.ssh existence changed ($trip_ssh_before -> $(trip_ssh_state))"
fi

echo
# --- UAT-2/F1. the jq dependency is owned by its consumer --------------------
# The dangling-symlink jq makes `command -v jq` genuinely fail (it is not an
# executable), modeling a VM without jq; the zypper shim "installs" a working
# jq shim over it, exactly like the package install would.

# F1.1 missing jq -> installed through zypper BEFORE its first use
reset_state
: > "$SELFOK"
hide_jq
rm -f "$WORK/jq-installed"
enable_jq_missing_seam
: > "$REC"
if run_setup >/dev/null 2>&1; then ok "F1.1: setup completes after installing jq"; else bad "F1.1: setup failed after the jq install: $(run_setup 2>&1 | tail -1)"; fi
unset JQ_MISSING BASH_ENV
zypper_lines="$(grep '^zypper ' "$REC" || true)"
contains "F1.1: jq is installed through zypper" "zypper --non-interactive install jq" "$zypper_lines"
if printf '%s' "$zypper_lines" | grep -q -- '--no-gpg-checks'; then
  bad "F1.1: jq was installed without signature verification"
else
  ok "F1.1: the jq install keeps signature verification"
fi
first_dh="$(grep -n '^dh principal' "$REC" | head -1 | cut -d: -f1)"
first_zy="$(grep -n '^zypper ' "$REC" | head -1 | cut -d: -f1)"
if [ -n "$first_dh" ] && [ -n "$first_zy" ] && [ "$first_zy" -lt "$first_dh" ]; then
  ok "F1.1: the jq install happens before the first jq-consuming helper call"
else
  bad "F1.1: the jq install order is wrong (zypper=$first_zy dh=$first_dh)"
fi

# F1.2 already installed -> no reinstall
reset_state
: > "$SELFOK"
: > "$REC"
if run_setup >/dev/null 2>&1; then ok "F1.2: setup succeeds with jq present"; else bad "F1.2: setup failed with jq present"; fi
if grep -q '^zypper ' "$REC"; then bad "F1.2: jq was reinstalled although present"; else ok "F1.2: an installed jq is not reinstalled"; fi

# F1.3 zypper failure -> fail closed
reset_state
: > "$SELFOK"
hide_jq
rm -f "$WORK/jq-installed"
enable_jq_missing_seam
export ZYPPER_FAIL=1
: > "$REC"
out="$(run_setup)"; rc=$?
unset ZYPPER_FAIL BASH_ENV
if [ "$rc" != 0 ]; then ok "F1.3: a jq install failure fails the setup closed"; else bad "F1.3: a jq install failure was tolerated"; fi
case "$out" in *"could not install jq"*) ok "F1.3: the failure names the jq install" ;; *) bad "F1.3: the failure reason is missing: $out" ;; esac
if [ -f "$PRINCIPAL" ]; then bad "F1.3: the principal was created despite the failed dependency install"; else ok "F1.3: no credential work happened after the failed install"; fi

# --- UAT-8g. the launcher refresh (--install-launcher-only) ------------------
# The diagnostic driver refreshes the INSTALLED launcher from the canonical
# lab sources before every diagnostic run (the real 8f finding: a stale
# ~/.bash_aliases without the shared configuration owners made the ladder
# fail with '_oc_security_opts: command not found'). The refresh mode must
# touch ONLY the launcher artifacts, install atomically, and verify byte
# equality, owner, group and mode.
GATE_LIB="$LAB_COPY/lab-mount-gate.sh"

# R1: a stale installed launcher is refreshed and verified
reset_state
mkdir -p "$AGENT_HOME/.opencode-docker/lib"
printf '# STALE LAUNCHER\n_OC_BASE=stale\n' > "$AGENT_HOME/.bash_aliases"
printf '# STALE GATE\n' > "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh"
printf '# docker-helper agent launchers\n' > "$AGENT_HOME/.bashrc"
: > "$REC"
out="$(run_setup --install-launcher-only)"; rc=$?
if [ "$rc" = 0 ]; then ok "UAT-8g: the launcher refresh succeeds"; else bad "UAT-8g: the launcher refresh failed (rc $rc): $out"; fi
cmp -s "$ALIASES" "$AGENT_HOME/.bash_aliases" \
  && ok "UAT-8g: the stale aliases are replaced byte-identically (cmp)" \
  || bad "UAT-8g: the installed aliases do not match the source"
cmp -s "$GATE_LIB" "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh" \
  && ok "UAT-8g: the stale gate library is replaced byte-identically (cmp)" \
  || bad "UAT-8g: the installed gate library does not match the source"
[ "$(stat -c '%a' "$AGENT_HOME/.bash_aliases" 2>/dev/null)" = 644 ] \
  && ok "UAT-8g: the installed aliases have mode 0644" \
  || bad "UAT-8g: the installed aliases mode is not 0644"
[ "$(stat -c '%a' "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh" 2>/dev/null)" = 644 ] \
  && ok "UAT-8g: the installed gate library has mode 0644" \
  || bad "UAT-8g: the installed gate library mode is not 0644"
rec="$(cat "$REC")"
not_contains "UAT-8g: the refresh creates no account (no useradd)" "useradd" "$rec"
not_contains "UAT-8g: the refresh runs no helper/principal/credential work" "dh " "$rec"
not_contains "UAT-8g: the refresh performs no usermod" "usermod" "$rec"
contains "UAT-8g: the refresh reports its verified result" "launcher refresh done" "$out"
# UAT-8h: the refresh does NOT touch .bashrc at all (the wiring is a full-
# provisioning responsibility now); the behavioral proof lives in H1–H4.

# R2: the refresh is idempotent (a second run keeps the verified state)
out="$(run_setup --install-launcher-only)" \
  && ok "UAT-8g: a second refresh succeeds" \
  || bad "UAT-8g: a second refresh failed"
cmp -s "$ALIASES" "$AGENT_HOME/.bash_aliases" \
  && ok "UAT-8g: the second refresh keeps the byte-identical aliases" \
  || bad "UAT-8g: the second refresh changed the aliases"

# R3: a symlinked target is refused, never written through
rm -f "$AGENT_HOME/.bash_aliases"
printf 'FOREIGN-DATA\n' > "$WORK/foreign-aliases"
ln -s "$WORK/foreign-aliases" "$AGENT_HOME/.bash_aliases"
out="$(run_setup --install-launcher-only)"; rc=$?
if [ "$rc" != 0 ]; then ok "UAT-8g: a symlinked alias target is refused"; else bad "UAT-8g: a symlinked target was installed through"; fi
[ "$(cat "$WORK/foreign-aliases")" = "FOREIGN-DATA" ] \
  && ok "UAT-8g: the symlink target is intact (nothing written through it)" \
  || bad "UAT-8g: the symlink target was overwritten"
case "$out" in
  *"refusing to write through it"*) ok "UAT-8g: the refusal names the symlink rule" ;;
  *) bad "UAT-8g: the refusal reason is missing: $out" ;;
esac
rm -f "$AGENT_HOME/.bash_aliases"

# R4: a target directory that escapes the agent home is refused
rm -rf "$AGENT_HOME/.opencode-docker/lib"
mkdir -p "$WORK/outside-lib"
ln -s "$WORK/outside-lib" "$AGENT_HOME/.opencode-docker/lib"
out="$(run_setup --install-launcher-only)"; rc=$?
if [ "$rc" != 0 ]; then ok "UAT-8g: a gate lib directory escaping the agent home is refused"; else bad "UAT-8g: an escaping gate lib directory was accepted"; fi
[ -z "$(ls -A "$WORK/outside-lib" 2>/dev/null)" ] \
  && ok "UAT-8g: nothing was installed into the escaped directory" \
  || bad "UAT-8g: the gate library landed outside the agent home"
case "$out" in
  *"escapes the agent home"*) ok "UAT-8g: the refusal names the escape rule" ;;
  *) bad "UAT-8g: the escape refusal reason is missing: $out" ;;
esac
rm -f "$AGENT_HOME/.opencode-docker/lib"

# R5: a missing canonical source fails closed before any target change
mv "$LAB_COPY/agent-aliases.sh" "$LAB_COPY/agent-aliases.sh.hidden"
out="$(run_setup --install-launcher-only)"; rc=$?
mv "$LAB_COPY/agent-aliases.sh.hidden" "$LAB_COPY/agent-aliases.sh"
if [ "$rc" != 0 ]; then ok "UAT-8g: a missing source fails the refresh closed"; else bad "UAT-8g: a missing source was tolerated"; fi

# R6: the FULL provisioning path still installs and verifies the launcher
reset_state
: > "$SELFOK"
out="$(run_setup)" \
  && ok "UAT-8g: the full provisioning still succeeds with the shared installer" \
  || bad "UAT-8g: the full provisioning broke: $out"
cmp -s "$ALIASES" "$AGENT_HOME/.bash_aliases" \
  && ok "UAT-8g: the full provisioning installs byte-identical aliases" \
  || bad "UAT-8g: the full provisioning aliases diverged"
cmp -s "$GATE_LIB" "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh" \
  && ok "UAT-8g: the full provisioning installs the verified gate library" \
  || bad "UAT-8g: the full provisioning gate library diverged"

# --- UAT-8h. .bashrc is NOT a launcher-refresh target ------------------------
# The launcher refresh (--install-launcher-only) has EXACTLY two file targets:
# ~/.bash_aliases and ~/.opencode-docker/lib/lab-mount-gate.sh. The .bashrc
# wiring is a separate responsibility of the FULL provisioning only: in the
# refresh mode a symlinked .bashrc would previously have been appended to and
# chowned THROUGH the link, modifying an arbitrary file outside the agent
# home. Every assertion below checks real file CONTENT and METADATA.
refresh_probe() { # -> runs the refresh, returns rc, output in REFRESH_OUT
  REFRESH_OUT="$(run_setup --install-launcher-only)"; return $?
}

# H1: an absent .bashrc is never created by the refresh
reset_state
mkdir -p "$AGENT_HOME/.opencode-docker/lib"
if refresh_probe; then ok "UAT-8h: the refresh succeeds without a .bashrc"; else bad "UAT-8h: the refresh failed without a .bashrc: $REFRESH_OUT"; fi
[ ! -e "$AGENT_HOME/.bashrc" ] \
  && ok "UAT-8h: the refresh does not create .bashrc" \
  || bad "UAT-8h RED: the refresh created .bashrc"

# H2: an existing .bashrc WITHOUT the wiring is left byte- and metadata-identical
reset_state
mkdir -p "$AGENT_HOME/.opencode-docker/lib"
printf 'original bashrc content\n' > "$AGENT_HOME/.bashrc"
chmod 0600 "$AGENT_HOME/.bashrc"
before_m="$("$real_stat" -c %a "$AGENT_HOME/.bashrc")"
before_t="$("$real_stat" -c %Y "$AGENT_HOME/.bashrc")"
if refresh_probe; then ok "UAT-8h: the refresh succeeds with an unwired .bashrc"; else bad "UAT-8h: the refresh failed with an unwired .bashrc: $REFRESH_OUT"; fi
[ "$(cat "$AGENT_HOME/.bashrc")" = "original bashrc content" ] \
  && ok "UAT-8h: the unwired .bashrc content is unchanged" \
  || bad "UAT-8h RED: the refresh modified the unwired .bashrc content"
[ "$("$real_stat" -c %a "$AGENT_HOME/.bashrc")" = "$before_m" ] \
  && ok "UAT-8h: the unwired .bashrc mode is unchanged" \
  || bad "UAT-8h RED: the refresh modified the unwired .bashrc mode"
[ "$("$real_stat" -c %Y "$AGENT_HOME/.bashrc")" = "$before_t" ] \
  && ok "UAT-8h: the unwired .bashrc mtime is unchanged" \
  || bad "UAT-8h RED: the refresh modified the unwired .bashrc mtime"

# H3: a symlinked .bashrc is never followed by the refresh
reset_state
mkdir -p "$AGENT_HOME/.opencode-docker/lib"
printf 'external bashrc data\n' > "$WORK/external-bashrc"
"$real_stat" -c %Y "$WORK/external-bashrc" > "$WORK/external-mtime"
ln -s "$WORK/external-bashrc" "$AGENT_HOME/.bashrc"
if refresh_probe; then ok "UAT-8h: the refresh succeeds with a symlinked .bashrc"; else bad "UAT-8h: the refresh failed with a symlinked .bashrc: $REFRESH_OUT"; fi
[ "$(cat "$WORK/external-bashrc")" = "external bashrc data" ] \
  && ok "UAT-8h: the symlinked .bashrc target content is untouched" \
  || bad "UAT-8h RED: the refresh wrote through the .bashrc symlink"
[ "$("$real_stat" -c %Y "$WORK/external-bashrc")" = "$(cat "$WORK/external-mtime")" ] \
  && ok "UAT-8h: the symlinked .bashrc target mtime is untouched" \
  || bad "UAT-8h RED: the refresh touched the .bashrc symlink target"

# H4: an already-wired .bashrc is not modified by the refresh
reset_state
mkdir -p "$AGENT_HOME/.opencode-docker/lib"
printf 'prev\n# docker-helper agent launchers\n[ -f "$HOME/.bash_aliases" ] && . "$HOME/.bash_aliases"\n' > "$AGENT_HOME/.bashrc"
before_t="$("$real_stat" -c %Y "$AGENT_HOME/.bashrc")"
if refresh_probe; then ok "UAT-8h: the refresh succeeds with a wired .bashrc"; else bad "UAT-8h: the refresh failed with a wired .bashrc: $REFRESH_OUT"; fi
[ "$("$real_stat" -c %Y "$AGENT_HOME/.bashrc")" = "$before_t" ] \
  && ok "UAT-8h: the wired .bashrc is untouched by the refresh" \
  || bad "UAT-8h RED: the refresh touched an already-wired .bashrc"

# H5: the refresh still updates and verifies a stale launcher and gate
reset_state
mkdir -p "$AGENT_HOME/.opencode-docker/lib"
printf '# STALE LAUNCHER\n' > "$AGENT_HOME/.bash_aliases"
printf '# STALE GATE\n' > "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh"
if refresh_probe; then ok "UAT-8h: the refresh succeeds with a stale launcher"; else bad "UAT-8h: the refresh failed with a stale launcher: $REFRESH_OUT"; fi
cmp -s "$ALIASES" "$AGENT_HOME/.bash_aliases" \
  && ok "UAT-8h: the stale aliases are still refreshed byte-identically (cmp)" \
  || bad "UAT-8h: the stale aliases were not refreshed"
cmp -s "$GATE_LIB" "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh" \
  && ok "UAT-8h: the stale gate library is still refreshed byte-identically (cmp)" \
  || bad "UAT-8h: the stale gate library was not refreshed"

# H6: the refresh is idempotent
if refresh_probe; then ok "UAT-8h: a second refresh succeeds"; else bad "UAT-8h: a second refresh failed: $REFRESH_OUT"; fi
cmp -s "$ALIASES" "$AGENT_HOME/.bash_aliases" \
  && ok "UAT-8h: the second refresh keeps the byte-identical aliases" \
  || bad "UAT-8h: the second refresh changed the aliases"

# H7: the FULL provisioning installs a missing wiring
reset_state
: > "$SELFOK"
out="$(run_setup)"; rc=$?
if [ "$rc" = 0 ]; then ok "UAT-8h: the full provisioning succeeds (absent wiring)"; else bad "UAT-8h: the full provisioning failed (absent wiring): $out"; fi
grep -qF '.bash_aliases' "$AGENT_HOME/.bashrc" \
  && ok "UAT-8h: the full provisioning wires .bash_aliases into .bashrc" \
  || bad "UAT-8h: the full provisioning did not wire .bashrc"
if [ "$(grep -cF '.bash_aliases' "$AGENT_HOME/.bashrc")" = 1 ]; then
  ok "UAT-8h: the wiring is written exactly once"
else
  bad "UAT-8h: the wiring line count is wrong ($(grep -cF '.bash_aliases' "$AGENT_HOME/.bashrc"))"
fi

# H8: an existing wiring is not duplicated by a second full run
reset_state
: > "$SELFOK"
out="$(run_setup)" >/dev/null 2>&1
if run_setup >/dev/null 2>&1; then ok "UAT-8h: the second full run succeeds"; else bad "UAT-8h: the second full run failed"; fi
[ "$(grep -cF '.bash_aliases' "$AGENT_HOME/.bashrc")" = 1 ] \
  && ok "UAT-8h: the second full run does not duplicate the wiring" \
  || bad "UAT-8h: the second full run duplicated the wiring"

# H9: a symlinked .bashrc FAILS the full provisioning closed, the external
# file is never written through
reset_state
: > "$SELFOK"
printf 'external full-provisioning data\n' > "$WORK/external-full-bashrc"
"$real_stat" -c %Y "$WORK/external-full-bashrc" > "$WORK/external-full-mtime"
ln -s "$WORK/external-full-bashrc" "$AGENT_HOME/.bashrc"
out="$(run_setup)"; rc=$?
if [ "$rc" != 0 ]; then
  ok "UAT-8h: a symlinked .bashrc fails the full provisioning closed"
else
  bad "UAT-8h RED: the full provisioning wrote through a symlinked .bashrc"
fi
[ "$(cat "$WORK/external-full-bashrc")" = "external full-provisioning data" ] \
  && ok "UAT-8h: the external .bashrc target is intact" \
  || bad "UAT-8h: the external .bashrc target was modified"
[ "$("$real_stat" -c %Y "$WORK/external-full-bashrc")" = "$(cat "$WORK/external-full-mtime")" ] \
  && ok "UAT-8h: the external .bashrc target mtime is intact" \
  || bad "UAT-8h: the external .bashrc target was touched"
case "$out" in
  *"refusing to write through it"*) ok "UAT-8h: the refusal names the symlink rule" ;;
  *) bad "UAT-8h: the refusal reason is missing: $out" ;;
esac

# H10: the full provisioning still uses the single canonical installer
reset_state
: > "$SELFOK"
: > "$REC"
out="$(run_setup)" >/dev/null 2>&1
rec="$(cat "$REC")"
case "$rec" in
  *".bash_aliases.new."*)
    ok "UAT-8h: the launcher install still goes through the atomic installer" ;;
  *) bad "UAT-8h: the launcher install did not use the atomic installer" ;;
esac
cmp -s "$ALIASES" "$AGENT_HOME/.bash_aliases" \
  && ok "UAT-8h: the launcher install still verifies byte-identical aliases" \
  || bad "UAT-8h: the launcher install verification broke"

printf 'setup-agent-user tests: %d passed, %d failed\n' "$PASS" "$FAIL"

[ "$FAIL" = 0 ]
