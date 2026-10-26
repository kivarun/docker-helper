#!/usr/bin/env bash
#
# test-cmp-dependency.sh — the narrow UAT-8i tests: the cmp dependency
# preflight of scripts/lab/setup-agent-user.sh and the three-outcome cmp
# classification in verify_launcher_aliases, with stubbed root tooling and a
# controlled zypper (no VM, no docker, no full suites).
#
# Cases:
#   1. cmp present            -> refresh succeeds, zypper is never called
#   2. cmp absent             -> zypper install diffutils, then success
#   3. diffutils install fails-> FAIL, no launcher write
#   4. install lies (rc 0, no cmp) -> FAIL, no launcher write
#   5. cmp rc=0               -> the comparison succeeds
#   6. cmp rc=1               -> a real mismatch (drift), fail closed
#   7. cmp rc=2 / rc=127      -> comparison error, NOT a false mismatch
#   8. cmp absent, no zypper  -> dependency FAIL before any launcher write
#   9. (covered by the existing test-provision-lab-vm.sh: a nonzero
#      diagnose-driver exit closes the network window and stops the VM —
#      the dependency failure surfaces through that same exit path)
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

# the script under test runs from a copy whose guard stub only needs a marker
LABCOPY="$WORK/lab"; mkdir -p "$LABCOPY"
for f in setup-agent-user.sh agent-aliases.sh lab-mount-gate.sh; do
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
[ "${1:-}" = "-u" ] && { echo 0; exit 0; }
exit 0
SH
cat > "$SHIM/chown" <<'SH'
#!/bin/sh
exit 0
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
export REC SHIM

# a controlled PATH for the script under test: the shim plus a realbin of
# SYMLINKS to the non-shimmed tools — deliberately WITHOUT cmp, so "cmp
# absent" is modeled by removing the shim wrapper only
REALBIN="$WORK/realbin"; mkdir -p "$REALBIN"
for t in bash mv rm mkdir dirname readlink grep cat cp chmod; do
  ln -s "$(command -v "$t")" "$REALBIN/$t" || { echo "missing tool $t" >&2; exit 1; }
done

refresh() { # -> rc (output in OUT); the launcher-only mode under stubs
  OUT="$(PATH="$SHIM:$REALBIN" AGENT_HOME="$AGENT_HOME" \
    LAB_VM_TEST_MARKER="$MARKER" \
    bash "$LABCOPY/setup-agent-user.sh" --install-launcher-only 2>&1)"
  return $?
}
fresh_state() { # a drifted installed launcher awaiting the refresh
  rm -rf "$AGENT_HOME"; mkdir -p "$AGENT_HOME/.opencode-docker/lib"
  printf '# STALE LAUNCHER\n' > "$AGENT_HOME/.bash_aliases"
  printf '# STALE GATE\n' > "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh"
  : > "$REC"
}
launcher_untouched() { # the refresh failed before any launcher write
  [ "$(cat "$AGENT_HOME/.bash_aliases")" = "# STALE LAUNCHER" ] \
    && [ "$(cat "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh")" = "# STALE GATE" ]
}

# 1. cmp present -> success, no package operations
fresh_state; cmp_wrapper
if refresh; then ok "1: cmp present -> the refresh succeeds"; else bad "1: cmp present -> the refresh failed: $OUT"; fi
if grep -q '^zypper ' "$REC"; then bad "1: cmp present -> zypper was called"; else ok "1: cmp present -> no package operations"; fi

# 2. cmp absent -> zypper install diffutils, then the refresh completes
fresh_state; rm -f "$SHIM/cmp"
if refresh; then ok "2: cmp absent -> the refresh succeeds after the install"; else bad "2: cmp absent -> the refresh failed: $OUT"; fi
grep -qF 'install diffutils' "$REC" \
  && ok "2: zypper installed diffutils" \
  || bad "2: zypper was not called for diffutils: $(cat "$REC")"
[ -x "$SHIM/cmp" ] && ok "2: cmp is usable after the install" || bad "2: cmp still missing"
cmp -s "$LABCOPY/agent-aliases.sh" "$AGENT_HOME/.bash_aliases" \
  && ok "2: the launcher was refreshed after the dependency install" \
  || bad "2: the launcher was not refreshed"

# 3. the diffutils install fails -> FAIL before any launcher write
fresh_state; rm -f "$SHIM/cmp"; export ZYPPER_FAIL=1
refresh; rc3=$?; unset ZYPPER_FAIL
[ "$rc3" != 0 ] && ok "3: a failed diffutils install fails closed" || bad "3: a failed install was tolerated: $OUT"
contains "3: the failure names the dependency" "could not install diffutils" "$OUT"
launcher_untouched && ok "3: no launcher write before the dependency failure" \
  || bad "3: the launcher was written despite the failed dependency"

# 4. the install lies (rc 0, cmp still missing) -> FAIL
fresh_state; rm -f "$SHIM/cmp"; export ZYPPER_LIE=1
refresh; rc4=$?; unset ZYPPER_LIE
[ "$rc4" != 0 ] && ok "4: a lying install fails closed" || bad "4: a lying install was tolerated: $OUT"
contains "4: the failure names the unusable cmp" "cmp is not usable after the diffutils install" "$OUT"
launcher_untouched && ok "4: no launcher write after a lying install" \
  || bad "4: the launcher was written despite the lying install"

# 8. cmp absent and no zypper -> dependency FAIL before any launcher write
fresh_state; rm -f "$SHIM/cmp"
mv "$SHIM/zypper" "$WORK/zypper.saved"
refresh; rc8=$?
mv "$WORK/zypper.saved" "$SHIM/zypper"
[ "$rc8" != 0 ] && ok "8: a missing cmp without zypper fails closed" || bad "8: the missing dependency was tolerated: $OUT"
contains "8: the failure names the unavailable zypper" "zypper is unavailable" "$OUT"
launcher_untouched && ok "8: no launcher write on the dependency failure" \
  || bad "8: the launcher was written despite the missing dependency"

# 5/6/7. the three-outcome cmp classification
cmp_wrapper; fresh_state
CMP_RC=0 refresh && ok "5: cmp rc=0 -> the comparison succeeds" \
  || bad "5: cmp rc=0 -> the refresh failed: $OUT"
cmp_wrapper; fresh_state
CMP_RC=1 refresh; rc6=$?
[ "$rc6" != 0 ] && ok "6: cmp rc=1 -> a real mismatch fails closed" || bad "6: cmp rc=1 was tolerated"
contains "6: the mismatch is reported as a drift" "does not match" "$OUT"
case "$OUT" in *"comparison error"*) bad "6: a real mismatch was misreported as a comparison error" ;; *) ok "6: a real mismatch is not a comparison error" ;; esac
cmp_wrapper; fresh_state
CMP_RC=2 refresh; rc7=$?
[ "$rc7" != 0 ] && ok "7: cmp rc=2 -> the comparison error fails closed" || bad "7: cmp rc=2 was tolerated"
contains "7: the comparison error is reported explicitly" "comparison error" "$OUT"
case "$OUT" in *"does not match"*) bad "7 RED: a comparison error was misreported as a file mismatch" ;; *) ok "7: a comparison error is not a false mismatch" ;; esac
cmp_wrapper; fresh_state
CMP_RC=127 refresh; rcX=$?
[ "$rcX" != 0 ] && ok "7b: cmp rc=127 (missing cmp at verify) fails closed" || bad "7b: rc 127 was tolerated"
case "$OUT" in *"does not match"*) bad "7b RED: a missing cmp was misreported as a file mismatch" ;; *) ok "7b: a missing cmp is not a false mismatch" ;; esac

printf 'cmp-dependency tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
