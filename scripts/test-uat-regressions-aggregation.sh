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
VM_RUNNER="$SRC_DIR/scripts/uat-vm-opensuse-selinux.sh"
[ -f "$VM_RUNNER" ] || { echo "missing $VM_RUNNER" >&2; exit 1; }

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
# subshell so its set -euo pipefail and harness dependencies stay isolated).
# The production contract is TEN mandatory stages:
# BB SELREG MP LIFECYCLE SELCHECK RUNDIR UTABDIAG WLMAC MIG211 MIG22.
# Any non-PASS result, unknown value, or wrong argument count fails closed.
stage_accept() {
  ( SCRIPT_DIR="$SRC_DIR/scripts" \
      source "$SRC_DIR/scripts/uat-vm-opensuse-selinux-lib.sh" \
      && selinux_stage_accept "$@" )
}
pass_stages=(PASS PASS PASS PASS PASS PASS PASS PASS PASS PASS)
stage_accept "${pass_stages[@]}" && ok "VM: all ten stages PASS -> eligible for success" \
  || bad "VM: all ten stages PASS -> eligible for success"

# Every stage must independently control acceptance. In particular, MIG22 was
# previously recorded in the summary but silently omitted from the gate.
for i in "${!pass_stages[@]}"; do
  for rejected in FAIL BLOCKED "" UNKNOWN; do
    candidate=("${pass_stages[@]}")
    candidate[i]="$rejected"
    case "$rejected" in
      "") description="empty" ;;
      *) description="$rejected" ;;
    esac
    if stage_accept "${candidate[@]}"; then
      bad "VM: stage $((i+1))/10=$description unexpectedly accepted"
    else
      ok "VM: stage $((i+1))/10=$description -> rejected"
    fi
  done
done

# Wrong arity is never accepted, even if every supplied value is PASS.
if stage_accept "${pass_stages[@]:0:9}"; then
  bad "VM: missing MIG22 (nine PASS values) unexpectedly accepted"
else
  ok "VM: missing MIG22 (nine PASS values) -> rejected"
fi
if stage_accept "${pass_stages[@]}" PASS; then
  bad "VM: extra eleventh PASS unexpectedly accepted"
else
  ok "VM: extra eleventh PASS -> rejected"
fi
if stage_accept; then
  bad "VM: empty stage vector unexpectedly accepted"
else
  ok "VM: empty stage vector -> rejected"
fi

# Function tests alone are not sufficient: pin the REAL production call site
# so MIG22_RESULT cannot silently disappear from the passed argument vector.
expected_call='if selinux_stage_accept "$BB_RESULT" "$SELREG_RESULT" "$MP_RESULT" "$LIFECYCLE_RESULT" "$SELCHECK_RESULT" "$RUNDIR_RESULT" "$UTABDIAG_RESULT" "$WLMAC_RESULT" "$MIG211_RESULT" "$MIG22_RESULT"; then'
actual_calls="$(grep -F 'if selinux_stage_accept ' "$VM_RUNNER" || true)"
if [ "$actual_calls" = "$expected_call" ]; then
  ok "VM: real orchestrator call gates all ten stage results, including MIG22_RESULT"
else
  bad "VM: real orchestrator call does not gate exact ten-stage vector (MIG22_RESULT required): $actual_calls"
fi

# Regression for newline loss in record_stage: command substitution strips
# trailing newlines, so distinct stage rows used to collapse together.
stage_rows_have_newlines() {
  ( SCRIPT_DIR="$SRC_DIR/scripts" \
      source "$SRC_DIR/scripts/uat-vm-opensuse-selinux-lib.sh" \
      && record_stage "first stage" PASS \
      && record_stage "second stage" FAIL \
      && printf -v expected_rows '%-28s %s\\n%-28s %s\\n' "first stage" PASS "second stage" FAIL \
      && [ "$SELINUX_STAGES" = "$expected_rows" ] )
}
if stage_rows_have_newlines; then
  ok "VM: collect-all summary retains a newline after every stage"
else
  bad "VM: collect-all stage summary lost or altered row delimiters"
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

# runner_group_scripts prints the uat-regression-*.sh basename of every
# REGRESSIONS entry declared by the runner itself. The runner's own
# REGRESSIONS array is the one registry of regression semantics; this test
# consumes it instead of keeping a second, drift-prone group list.
runner_group_scripts() { # runner-file
  awk '/^REGRESSIONS=\(/{flag=1;next} /^\)/{flag=0} flag' "$1" \
    | grep -oE 'uat-regression-[a-z0-9-]+\.sh'
}

run_runner_all() { # runner rc
  local runner="$1" rc="$2"
  rm -rf "$WORK/rc"
  mkdir -p "$WORK/rc"
  local g count=0
  while IFS= read -r g; do
    printf '%s\n' "$rc" > "$WORK/rc/$g"
    count=$((count+1))
  done < <(runner_group_scripts "$runner")
  [ "$count" -gt 0 ] || { bad "runner group extraction found no groups: $runner"; return 1; }
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
