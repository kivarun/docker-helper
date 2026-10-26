#!/usr/bin/env bash
#
# test-cmp-dependency.sh — the narrow UAT-8i/UAT-8j tests: the cmp dependency
# handling of scripts/lab/setup-agent-user.sh (require in the launcher-only
# refresh, zypper repair in the full provisioning), the three-outcome cmp
# classification, and the guest dependency preflight of stage_uat_diagnose in
# scripts/lab/provision-lab-vm.sh — all with stubbed root tooling, a
# controlled zypper and a stubbed VM driver (no real VM, no docker, no full
# suites).
#
# Cases:
#   1. launcher-only, cmp present  -> success, zero zypper
#   2. launcher-only, cmp absent   -> dependency FAIL, zero zypper, the two
#                                     launcher files untouched
#   3. full provisioning, cmp absent -> zypper installs diffutils, then success
#   4. full provisioning, install failure / lying install -> fail closed
#   5. diagnostic stage, cmp present -> no install, diagnostics run
#   6. diagnostic stage, cmp absent  -> diffutils installed in the guest
#                                       BEFORE the diagnostics
#   7. preflight failure / hang      -> no diagnostics, the network window is
#                                       closed, the VM is stopped
#   8. cmp rc 0/1/2/127 classification (unchanged from 8i)
#
# Usage: scripts/lab/test-cmp-dependency.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LAB_SRC="$SRC_DIR/lab"

PASS=0
FAIL=0
ok() { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
contains() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2')" ;; esac; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# the scripts under test run from a copy whose guard stub only needs a marker
LABCOPY="$WORK/lab"; mkdir -p "$LABCOPY"
for f in setup-agent-user.sh agent-aliases.sh lab-mount-gate.sh provision-lab-vm.sh; do
  cp "$LAB_SRC/$f" "$LABCOPY/" || { echo "missing $f" >&2; exit 1; }
done
cat > "$LABCOPY/lab-vm-guard.sh" <<'SH'
require_lab_vm() { [ -r "${LAB_VM_TEST_MARKER:?}" ] || exit 1; }
SH
MARKER="$WORK/marker"; : > "$MARKER"

REAL_CMP="$(command -v cmp)"
REAL_STAT="$(command -v stat)"
SHIM="$WORK/shim"; mkdir -p "$SHIM"
REC="$WORK/rec"
AGENT_HOME="$WORK/home"

# the cmp shim: a wrapper around the real cmp whose exit status can be
# forced through CMP_RC (unset -> real behavior)
cat > "$WORK/cmp-wrapper" <<SH
#!/bin/sh
if [ -n "\${CMP_RC:-}" ]; then exit "\$CMP_RC"; fi
exec $REAL_CMP "\$@"
SH
chmod 0755 "$WORK/cmp-wrapper"
cmp_wrapper() { cp "$WORK/cmp-wrapper" "$SHIM/cmp"; chmod 0755 "$SHIM/cmp"; }

cat > "$SHIM/zypper" <<'SH'
#!/bin/sh
echo "zypper $*" >> "@REC@"
case "$*" in
  *"install diffutils"*)
    [ -n "${ZYPPER_FAIL:-}" ] && exit 1
    [ -n "${ZYPPER_LIE:-}" ] && exit 0
    cp "@CMPSRC@" "@SHIM@/cmp"
    chmod 0755 "@SHIM@/cmp"
    exit 0 ;;
esac
exit 0
SH
sed -i "s|@REC@|$REC|g; s|@SHIM@|$SHIM|g; s|@CMPSRC@|$WORK/cmp-wrapper|g" "$SHIM/zypper"

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
cat > "$SHIM/getent" <<'SH'
#!/bin/sh
uid="$UIDMARK"
[ -f "$USERMARK" ] || uid=""
case "${1:-}" in
  passwd)
    if [ "${2:-}" = docker ]; then exit 1; fi
    if [ -n "$uid" ] && { [ "${2:-}" = agent ] || [ "${2:-}" = "$(cat "$UIDMARK")" ]; }; then
      printf 'agent:x:%s:\n' "$(cat "$UIDMARK")"; exit 0
    fi
    if [ -z "${2:-}" ]; then
      [ -n "$uid" ] && printf 'agent:x:%s:\n' "$(cat "$UIDMARK")"
      exit 0
    fi
    exit 1 ;;
  group)
    if [ "${2:-}" = docker ]; then exit 0; fi
    if [ -n "$uid" ] && [ "${2:-}" = "$(cat "$UIDMARK")" ]; then
      printf 'agent:x:%s:\n' "$(cat "$UIDMARK")"; exit 0
    fi
    exit 1 ;;
esac
exit 2
SH
cat > "$SHIM/chown" <<'SH'
#!/bin/sh
exit 0
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
case "$1 $2" in
  "config allowed-root")
    case "$3" in
      list) cat "$ALLOWED" 2>/dev/null ;;
    esac ;;
  "principal show")
    printf '{"uid":%s,"gid":%s}\n' "$(cat "$UIDMARK")" "$(cat "$UIDMARK")" ;;
  "self --json")
    [ -f "$SELFOK" ] || exit 1
    printf '{"ok":true,"type":"principal","resource":{"username":"agent"}}\n' ;;
  *) exit 0 ;;
esac
SH
cat > "$SHIM/install" <<'SH'
#!/bin/sh
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
cat > "$SHIM/stat" <<SH
#!/bin/sh
case "\$1 \$2" in
  "-c %U") echo agent; exit 0 ;;
  "-c %G") echo agent; exit 0 ;;
  "-c %a") exec $REAL_STAT -c %a -- "\$3" ;;
esac
exit 1
SH
chmod 0755 "$SHIM"/*
export REC SHIM USERMARK="$WORK/usermark" UIDMARK="$WORK/uidmark" \
  GROUPMARK="$WORK/groupmark" SELFOK="$WORK/selfok" ALLOWED="$WORK/allowed"

# a controlled PATH for the scripts under test: the shim plus a realbin of
# SYMLINKS to the non-shimmed tools — deliberately WITHOUT cmp, so "cmp
# absent" is modeled by removing the shim wrapper only
REALBIN="$WORK/realbin"; mkdir -p "$REALBIN"
for t in bash mv rm mkdir dirname basename readlink grep cat cp chmod awk cut tr wc jq sleep timeout; do
  ln -s "$(command -v "$t")" "$REALBIN/$t" 2>/dev/null \
    || { echo "missing tool $t" >&2; exit 1; }
done

refresh() { # -> rc (output in OUT); the launcher-only mode under stubs
  OUT="$(PATH="$SHIM:$REALBIN" AGENT_HOME="$AGENT_HOME" \
    LAB_VM_TEST_MARKER="$MARKER" \
    bash "$LABCOPY/setup-agent-user.sh" --install-launcher-only 2>&1)"
  return $?
}
full_run() { # -> rc (output in OUT); the FULL provisioning under stubs
  local dbg=""; [ -n "${FULLRUN_DEBUG:-}" ] && dbg="-x"
  OUT="$(PATH="$SHIM:$REALBIN" AGENT_HOME="$AGENT_HOME" \
    LAB_VM_TEST_MARKER="$MARKER" \
    bash $dbg "$LABCOPY/setup-agent-user.sh" 2>&1)"
  return $?
}
full_state() { # an existing coherent account + a drifted installed launcher
  rm -rf "$AGENT_HOME"; mkdir -p "$AGENT_HOME/.config/docker-helper" \
    "$AGENT_HOME/.opencode-docker/lib"
  printf '# STALE LAUNCHER\n' > "$AGENT_HOME/.bash_aliases"
  printf '# STALE GATE\n' > "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh"
  printf 'token\n' > "$AGENT_HOME/.config/docker-helper/credential.token"
  : > "$USERMARK"; echo 1001 > "$UIDMARK"; : > "$GROUPMARK"; : > "$SELFOK"
  printf '%s\n' "$AGENT_HOME" > "$ALLOWED"
  : > "$REC"
}
refresh_state() { # a drifted installed launcher awaiting the refresh
  rm -rf "$AGENT_HOME"; mkdir -p "$AGENT_HOME/.opencode-docker/lib"
  printf '# STALE LAUNCHER\n' > "$AGENT_HOME/.bash_aliases"
  printf '# STALE GATE\n' > "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh"
  : > "$REC"
}
launcher_untouched() { # the refresh failed before any launcher write
  [ "$(cat "$AGENT_HOME/.bash_aliases")" = "# STALE LAUNCHER" ] \
    && [ "$(cat "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh")" = "# STALE GATE" ]
}
no_zypper() { ! grep -q '^zypper ' "$REC"; }

# --- 1. launcher-only, cmp present -> success, zero zypper -------------------
refresh_state; cmp_wrapper
if refresh; then ok "1: launcher-only, cmp present -> the refresh succeeds"; else bad "1: launcher-only, cmp present -> the refresh failed: $OUT"; fi
no_zypper && ok "1: launcher-only, cmp present -> no package operations" \
  || bad "1: launcher-only, cmp present -> zypper was called"

# --- 2. launcher-only, cmp absent -> dependency FAIL, zero zypper ------------
refresh_state; rm -f "$SHIM/cmp"
refresh; rc2=$?
[ "$rc2" != 0 ] \
  && ok "2: launcher-only, cmp absent -> dependency FAIL" \
  || bad "2: launcher-only, cmp absent -> the refresh was tolerated: $OUT"
no_zypper && ok "2: launcher-only, cmp absent -> zero zypper calls" \
  || bad "2 RED: launcher-only ran zypper: $(cat "$REC")"
contains "2: the refusal names the dependency" "cmp is missing" "$OUT"
launcher_untouched \
  && ok "2: both launcher files are untouched" \
  || bad "2: the launcher was written despite the dependency failure"

# --- 3. full provisioning, cmp absent -> zypper installs diffutils -----------
full_state; rm -f "$SHIM/cmp"
if full_run; then ok "3: full provisioning, cmp absent -> success after the install"; else bad "3: full provisioning, cmp absent -> failed: $OUT"; fi
grep -qF 'install diffutils' "$REC" \
  && ok "3: zypper installed diffutils in the full provisioning" \
  || bad "3: zypper was not called: $(cat "$REC")"
[ -x "$SHIM/cmp" ] && ok "3: cmp is usable after the install" || bad "3: cmp still missing"
cmp -s "$LABCOPY/agent-aliases.sh" "$AGENT_HOME/.bash_aliases" \
  && ok "3: the launcher was refreshed after the dependency install" \
  || bad "3: the launcher was not refreshed"

# --- 4. full provisioning: install failure / lying install -> fail closed ----
full_state; rm -f "$SHIM/cmp"; export ZYPPER_FAIL=1
full_run; rc4=$?; unset ZYPPER_FAIL
[ "$rc4" != 0 ] && ok "4: a failed diffutils install fails closed" || bad "4: a failed install was tolerated: $OUT"
contains "4: the failure names the dependency" "could not install diffutils" "$OUT"
launcher_untouched && ok "4: no launcher write on the failed install" \
  || bad "4: the launcher was written despite the failed install"
full_state; rm -f "$SHIM/cmp"; export ZYPPER_LIE=1
full_run; rc4b=$?; unset ZYPPER_LIE
[ "$rc4b" != 0 ] && ok "4b: a lying install fails closed" || bad "4b: a lying install was tolerated: $OUT"
contains "4b: the failure names the unusable cmp" "cmp is not usable after the diffutils install" "$OUT"
launcher_untouched && ok "4b: no launcher write after a lying install" \
  || bad "4b: the launcher was written despite the lying install"

# --- the diagnostic stage: a stubbed VM driver -------------------------------
STAGE="$WORK/stage"; STAGE_STATE="$STAGE/state"; STAGE_REC="$STAGE/rec"
STAGE_VM="$STAGE/vm"; mkdir -p "$STAGE/repo/scripts/lab" "$STAGE_VM"
cp "$LABCOPY/provision-lab-vm.sh" "$STAGE/repo/scripts/lab/"
: > "$STAGE_STATE"; echo stopped > "$STAGE_STATE"
cat > "$STAGE/repo/scripts/dev-vm-local.sh" <<SH
#!/usr/bin/env bash
STATE="$STAGE_STATE"; REC="$STAGE_REC"
case "\${1:-}" in
  status) printf 'state:    %s\n' "\$(cat "\$STATE" 2>/dev/null || echo unknown)" ;;
  stop) echo stop >> "\$REC"; echo stopped > "\$STATE" ;;
  start) echo "start isolated=\${DEV_VM_NET_ISOLATED:-unset}" >> "\$REC"; echo running > "\$STATE" ;;
  ssh)
    shift; echo "ssh \$1" >> "\$REC"
    cat > /dev/null 2>/dev/null || true
    case "\$1" in
      *mkdir\ -p\ /opt/lab*|*chmod\ 0644*) exit 0 ;;
      *tee\ /opt/lab/*) exit 0 ;;
      *install\ diffutils*)
        # model the guest: cmp present -> the else branch never runs
        if [ "\${GUEST_CMP:-1}" = 1 ]; then exit 0; fi
        [ -n "\${DEP_FAIL:-}" ] && { echo "zypper: signature check failed" >&2; exit 1; }
        if [ -n "\${DEP_HANG:-}" ]; then trap '' TERM; while :; do sleep 1 & wait \$!; done; fi
        echo "GUEST-CMP-INSTALL" >> "\$REC"
        exit 0 ;;
      *bash\ /opt/lab/diagnose-launch.sh*)
        echo "D0 PASS rc=0 elapsed=1"; exit 0 ;;
      *) exit 0 ;;
    esac ;;
  *) echo "stub: unknown op \$1" >&2; exit 2 ;;
esac
SH
chmod 0755 "$STAGE/repo/scripts/dev-vm-local.sh"
run_stage() { # -> rc (output in OUT)
  OUT="$(PATH="$SHIM:$REALBIN" bash "$STAGE/repo/scripts/lab/provision-lab-vm.sh" uat-diagnose 2>&1)"
  return $?
}
stage_reset() { : > "$STAGE_REC"; echo stopped > "$STAGE_STATE"; }
stage_line() { # PATTERN -> the first line number in the stage record
  grep -n "$1" "$STAGE_REC" 2>/dev/null | head -1 | cut -d: -f1
}

# --- 5. stage, cmp present -> no install, diagnostics run --------------------
stage_reset; GUEST_CMP=1 run_stage; rc5=$?
[ "$rc5" = 0 ] && ok "5: stage with cmp present succeeds" || bad "5: stage with cmp present failed (rc $rc5): $OUT"
grep -q "GUEST-CMP-INSTALL" "$STAGE_REC" \
  && bad "5 RED: the guest installed diffutils although cmp was present" \
  || ok "5: no guest package operation when cmp is present"
dep5="$(stage_line 'install diffutils')"; diag5="$(stage_line 'sudo bash /opt/lab/diagnose-launch.sh')"
if [ -n "$dep5" ] && [ -n "$diag5" ] && [ "$dep5" -lt "$diag5" ]; then
  ok "5: the preflight runs before the diagnostics"
else
  bad "5 RED: the guest dependency preflight is missing or runs late (dep=$dep5 diag=$diag5)"
fi

# --- 6. stage, cmp absent -> diffutils installed BEFORE the diagnostics ------
stage_reset; GUEST_CMP=0 run_stage; rc6=$?
[ "$rc6" = 0 ] && ok "6: stage with cmp absent succeeds after the install" || bad "6: stage with cmp absent failed (rc $rc6): $OUT"
grep -q "GUEST-CMP-INSTALL" "$STAGE_REC" \
  && ok "6: the guest installed diffutils" \
  || bad "6: the guest did not install diffutils"
dep6="$(stage_line 'install diffutils')"; diag6="$(stage_line 'sudo bash /opt/lab/diagnose-launch.sh')"
if [ -n "$dep6" ] && [ -n "$diag6" ] && [ "$dep6" -lt "$diag6" ]; then
  ok "6: the diffutils install happens before the diagnostics"
else
  bad "6 RED: the install is missing or runs after the diagnostics (dep=$dep6 diag=$diag6)"
fi

# --- 7. preflight failure / hang -> no diagnostics, window closed, VM stopped -
stage_reset; GUEST_CMP=0 DEP_FAIL=1 run_stage; rc7=$?
[ "$rc7" != 0 ] && ok "7: a failed preflight fails the stage" || bad "7: a failed preflight was tolerated: $OUT"
if [ -n "$(stage_line 'sudo bash /opt/lab/diagnose-launch.sh')" ]; then
  bad "7: the diagnostics ran despite the failed preflight: $(grep 'diagnose-launch' "$STAGE_REC")"
else
  ok "7: no diagnostics after the failed preflight"
fi
stop7="$(stage_line '^stop$')"; start7="$(stage_line '^start isolated=0$')"
if [ -n "$stop7" ] && [ -n "$start7" ] && [ "$stop7" -gt "$start7" ]; then
  ok "7: the network window is closed after the failed preflight"
else
  bad "7: the network window stayed open"
fi
[ "$(cat "$STAGE_STATE")" = stopped ] \
  && ok "7: the VM is confirmed stopped" \
  || bad "7: the VM state is not stopped"
contains "7: the failure names the preflight" "dependency preflight failed" "$OUT"
stage_reset; GUEST_CMP=0 DEP_HANG=1 DIAG_DEP_TIMEOUT=2 DIAG_DEADLINE_KILL=2 run_stage; rc7b=$?
[ "$rc7b" != 0 ] \
  && ok "7b: a hung preflight is bounded and fails the stage" \
  || bad "7b: a hung preflight was tolerated: $OUT"
if [ -n "$(stage_line 'sudo bash /opt/lab/diagnose-launch.sh')" ]; then
  bad "7b: the diagnostics ran despite the hung preflight: $(grep 'diagnose-launch' "$STAGE_REC")"
else
  ok "7b: no diagnostics after the hung preflight"
fi
[ "$(cat "$STAGE_STATE")" = stopped ] \
  && ok "7b: the VM is confirmed stopped after the bounded kill" \
  || bad "7b: the VM state is not stopped"
contains "7b: the hang failure names the preflight" "dependency preflight failed" "$OUT"

# --- 8. the cmp classification (unchanged from 8i) ---------------------------
cmp_wrapper; refresh_state
CMP_RC=0 refresh && ok "8a: cmp rc=0 -> the comparison succeeds" \
  || bad "8a: cmp rc=0 -> the refresh failed: $OUT"
cmp_wrapper; refresh_state
CMP_RC=1 refresh; rc8b=$?
[ "$rc8b" != 0 ] && ok "8b: cmp rc=1 -> a real mismatch fails closed" || bad "8b: cmp rc=1 was tolerated"
contains "8b: the mismatch is reported as a drift" "does not match" "$OUT"
case "$OUT" in *"comparison error"*) bad "8b: a real mismatch was misreported as a comparison error" ;; *) ok "8b: a real mismatch is not a comparison error" ;; esac
cmp_wrapper; refresh_state
CMP_RC=2 refresh; rc8c=$?
[ "$rc8c" != 0 ] && ok "8c: cmp rc=2 -> the comparison error fails closed" || bad "8c: cmp rc=2 was tolerated"
contains "8c: the comparison error is reported explicitly" "comparison error" "$OUT"
case "$OUT" in *"does not match"*) bad "8c RED: a comparison error was misreported as a file mismatch" ;; *) ok "8c: a comparison error is not a false mismatch" ;; esac
cmp_wrapper; refresh_state
CMP_RC=127 refresh; rc8d=$?
[ "$rc8d" != 0 ] && ok "8d: cmp rc=127 (missing cmp at verify) fails closed" || bad "8d: rc 127 was tolerated"
case "$OUT" in *"does not match"*) bad "8d RED: a missing cmp was misreported as a file mismatch" ;; *) ok "8d: a missing cmp is not a false mismatch" ;; esac

printf 'cmp-dependency tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
