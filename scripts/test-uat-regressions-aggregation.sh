#!/usr/bin/env bash
#
# test-uat-regressions-aggregation.sh — deterministic tests for the Release-2
# mandatory-UAT BLOCKED contract:
#
#   all PASS                -> exit 0
#   one or more BLOCKED,
#     no FAIL               -> exit 2
#   one or more FAIL        -> exit 1
#
# covered at two levels:
#   1. the extracted aggregation helpers in scripts/uat-regression-lib.sh
#      (reg_classify_rc / reg_aggregate_exit) and the SELinux VM stage
#      acceptance helper selinux_stage_accept in
#      scripts/uat-vm-opensuse-selinux-lib.sh;
#   2. the REAL collect-all runners (scripts/uat-regressions-runner-ubuntu.sh
#      and -selinux.sh) executed end-to-end with the privileged/external
#      commands (systemctl, dpkg, journalctl, ...) stubbed on PATH, and each
#      regression group's rc injected through the `timeout` seam. This proves
#      the runner really prints BLOCKED in its summary and really exits with
#      the fail-closed code — without a root VM.
#
# The BLOCKED semantic: a mandatory regression group that reports BLOCKED
# (exit 2) means the required scenario was NOT successfully exercised, which
# is not acceptable for Release-2, so the runner must fail (exit 2) even when
# no group reported FAIL. Only a plain `PASS` (exit 0) for every group passes.
#
# Usage: scripts/test-uat-regressions-aggregation.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$SRC_DIR/scripts/uat-regression-lib.sh"
RUNNER_UBUNTU="$SRC_DIR/scripts/uat-regressions-runner-ubuntu.sh"
RUNNER_SELINUX="$SRC_DIR/scripts/uat-regressions-runner-selinux.sh"
[ -f "$LIB" ] || { echo "missing $LIB" >&2; exit 1; }
[ -f "$RUNNER_UBUNTU" ] || { echo "missing $RUNNER_UBUNTU" >&2; exit 1; }
[ -f "$RUNNER_SELINUX" ] || { echo "missing $RUNNER_SELINUX" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1" >&2; }

# --- Part 1: the extracted helpers --------------------------------------------
# shellcheck source=scripts/uat-regression-lib.sh
source "$LIB"

# reg_classify_rc
[ "$(reg_classify_rc 0)" = "PASS" ]    && ok "classify rc=0 -> PASS"    || bad "classify rc=0 -> PASS"
[ "$(reg_classify_rc 2)" = "BLOCKED" ] && ok "classify rc=2 -> BLOCKED" || bad "classify rc=2 -> BLOCKED"
[ "$(reg_classify_rc 1)" = "FAIL" ]    && ok "classify rc=1 -> FAIL"    || bad "classify rc=1 -> FAIL"
[ "$(reg_classify_rc 99)" = "FAIL" ]   && ok "classify rc=99 -> FAIL"   || bad "classify rc=99 -> FAIL"
[ "$(reg_classify_rc 124)" = "FAIL" ]  && ok "classify rc=124 (timeout) -> FAIL" || bad "classify rc=124 -> FAIL"

# reg_aggregate_exit (fail-closed BLOCKED contract)
[ "$(reg_aggregate_exit 0 0)" = "0" ] && ok "all PASS -> exit 0" || bad "all PASS -> exit 0"
[ "$(reg_aggregate_exit 0 1)" = "2" ] && ok "BLOCKED, no FAIL -> exit 2" || bad "BLOCKED, no FAIL -> exit 2"
[ "$(reg_aggregate_exit 1 0)" = "1" ] && ok "FAIL -> exit 1" || bad "FAIL -> exit 1"
[ "$(reg_aggregate_exit 1 1)" = "1" ] && ok "BLOCKED + FAIL -> exit 1 (FAIL dominates)" || bad "BLOCKED + FAIL -> exit 1"

# selinux_stage_accept (extracted from the SELinux VM lib; sourced in a
# subshell so the lib's `set -euo pipefail`/harness source cannot disturb
# this test process). The production contract is
# selinux_stage_accept BB SELREG MP LIFECYCLE: every mandatory SELinux stage
# must be PASS (fail-closed) for the job to be eligible for success.
stage_accept() {
  ( SCRIPT_DIR="$SRC_DIR/scripts" \
      source "$SRC_DIR/scripts/uat-vm-opensuse-selinux-lib.sh" \
      && selinux_stage_accept "$1" "$2" "$3" "$4" )
}
stage_accept PASS PASS PASS PASS && ok "VM: all four stages PASS -> eligible for success" \
  || bad "VM: all four stages PASS -> eligible for success"
if stage_accept PASS PASS PASS BLOCKED; then
  bad "VM: LIFECYCLE_RESULT=BLOCKED must be a failure"
else
  ok "VM: LIFECYCLE_RESULT=BLOCKED -> failure"
fi
if stage_accept PASS PASS PASS FAIL; then
  bad "VM: LIFECYCLE_RESULT=FAIL must be a failure"
else
  ok "VM: LIFECYCLE_RESULT=FAIL -> failure"
fi
if stage_accept PASS PASS BLOCKED PASS; then
  bad "VM: MP_RESULT=BLOCKED must be a failure"
else
  ok "VM: MP_RESULT=BLOCKED -> failure"
fi
if stage_accept PASS PASS FAIL PASS; then
  bad "VM: MP_RESULT=FAIL must be a failure"
else
  ok "VM: MP_RESULT=FAIL -> failure"
fi
if stage_accept PASS FAIL PASS PASS; then
  bad "VM: SELREG_RESULT=FAIL must be a failure"
else
  ok "VM: SELREG_RESULT=FAIL -> failure"
fi
if stage_accept FAIL PASS PASS PASS; then
  bad "VM: BB_RESULT=FAIL must be a failure"
else
  ok "VM: BB_RESULT=FAIL -> failure"
fi

# --- Part 2: the real runners end-to-end with stubbed external commands ------
# A stub PATH makes the privileged/external commands harmless so the runner's
# OWN aggregation loop, summary and exit are exercised. Each regression group's
# rc is injected through the `timeout` seam: stub timeout reads the target
# script's basename and returns the rc recorded in $WORK/rc/<basename>.
SHIM="$WORK/shim"
mkdir -p "$SHIM"

cat > "$SHIM/id" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "-u" ]; then echo 0; exit 0; fi
exit 0
EOF

cat > "$SHIM/systemctl" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *"is-active --quiet"*) exit 0 ;;
  *"show -p MainPID --value"*) echo 4242; exit 0 ;;
  *) exit 0 ;;
esac
EOF

cat > "$SHIM/timeout" <<'EOF'
#!/usr/bin/env bash
# timeout 900 bash /abs/scripts/uat-regression-<group>.sh
target="${@: -1}"
name="$(basename "$target")"
rcfile="$WORK/rc/$name"
if [ -f "$rcfile" ]; then
  exit "$(cat "$rcfile")"
fi
exit 0
EOF

for t in journalctl dpkg docker-helper apparmor_parser semodule sesearch ausearch getenforce rm; do
  printf '#!/usr/bin/env bash\nexit 0\n' > "$SHIM/$t"
done
# getenforce must print Enforcing (SELinux runner preflight).
cat > "$SHIM/getenforce" <<'EOF'
#!/usr/bin/env bash
printf 'Enforcing\n'
exit 0
EOF
# rm must be a real-ish no-op in the runner's clean-slate (it removes
# /etc/docker-helper etc.); never touch the host here.
cat > "$SHIM/rm" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$SHIM"/*

export PATH="$SHIM:$PATH"
export WORK

# Fake candidate DEB the ubuntu runner consumes (sha-verified then dpkg -i is
# stubbed). Provides UAT_ARTIFACT_PATH so the runner never invokes
# build-packages.sh.
DEB="$WORK/fake.deb"
printf 'fake-deb-bytes\n' > "$DEB"
DEB_SHA="$(sha256sum "$DEB" | awk '{print $1}')"

# run_runner RUNNER rcfile-template: run a runner once with every group set to
# the same injected rc; print the runner's output; return the runner's exit.
run_runner_all() { # runner rc
  local runner="$1" rc="$2"
  rm -rf "$WORK/rc"
  mkdir -p "$WORK/rc"
  for g in auth-lifecycle cross-principal-isolation workspace-escape \
           mount-pin-replacement concurrent-mount-pins secret-containment \
           daemon-stale-runtime selinux-workspace-lifecycle \
           selinux-operator-boundary selinux-fs-boundary selinux-mount-guard \
           selinux-relabel-avc; do
    printf '%s\n' "$rc" > "$WORK/rc/uat-regression-$g.sh"
  done
  local out
  out="$(UAT_ARTIFACT_PATH="$DEB" UAT_ARTIFACT_SHA256="$DEB_SHA" bash "$runner" 2>&1)"
  local ec=$?
  printf '%s\n' "$out"
  return "$ec"
}

# --- Ubuntu runner -------------------------------------------------------------
out="$(run_runner_all "$RUNNER_UBUNTU" 0)"; ec=$?
[ "$ec" = 0 ] && ok "ubuntu runner: all PASS -> exit 0" \
  || bad "ubuntu runner: all PASS -> exit 0 (got $ec)"
printf '%s' "$out" | grep -q "PASS" && ok "ubuntu runner: all PASS summary shows PASS" \
  || bad "ubuntu runner: all PASS summary shows PASS"

out="$(run_runner_all "$RUNNER_UBUNTU" 2)"; ec=$?
[ "$ec" = 2 ] && ok "ubuntu runner: BLOCKED -> exit 2" \
  || bad "ubuntu runner: BLOCKED -> exit 2 (got $ec)"
printf '%s' "$out" | grep -q "BLOCKED" && ok "ubuntu runner: BLOCKED summary says BLOCKED" \
  || bad "ubuntu runner: BLOCKED summary says BLOCKED"

out="$(run_runner_all "$RUNNER_UBUNTU" 1)"; ec=$?
[ "$ec" = 1 ] && ok "ubuntu runner: FAIL -> exit 1" \
  || bad "ubuntu runner: FAIL -> exit 1 (got $ec)"
printf '%s' "$out" | grep -q "FAILED" && ok "ubuntu runner: FAIL summary says FAILED" \
  || bad "ubuntu runner: FAIL summary says FAILED"

# --- SELinux runner -------------------------------------------------------------
out="$(run_runner_all "$RUNNER_SELINUX" 0)"; ec=$?
[ "$ec" = 0 ] && ok "selinux runner: all PASS -> exit 0" \
  || bad "selinux runner: all PASS -> exit 0 (got $ec)"
printf '%s' "$out" | grep -q "PASS" && ok "selinux runner: all PASS summary shows PASS" \
  || bad "selinux runner: all PASS summary shows PASS"

out="$(run_runner_all "$RUNNER_SELINUX" 2)"; ec=$?
[ "$ec" = 2 ] && ok "selinux runner: BLOCKED -> exit 2" \
  || bad "selinux runner: BLOCKED -> exit 2 (got $ec)"
printf '%s' "$out" | grep -q "BLOCKED" && ok "selinux runner: BLOCKED summary says BLOCKED" \
  || bad "selinux runner: BLOCKED summary says BLOCKED"

out="$(run_runner_all "$RUNNER_SELINUX" 1)"; ec=$?
[ "$ec" = 1 ] && ok "selinux runner: FAIL -> exit 1" \
  || bad "selinux runner: FAIL -> exit 1 (got $ec)"
printf '%s' "$out" | grep -q "FAILED" && ok "selinux runner: FAIL summary says FAILED" \
  || bad "selinux runner: FAIL summary says FAILED"

# --- Summary -------------------------------------------------------------------
echo
echo "================= test-uat-regressions-aggregation summary ================="
echo "passed: $PASS  failed: $FAIL"
echo "======================================================================"
[ "$FAIL" -eq 0 ]
