#!/usr/bin/env bash
#
# release-2.4-r7-diag-ubuntu.sh — R7 full-gate corrective diagnosis on the
# hosted Ubuntu runner (tarball candidate). Proves the R7-C Ubuntu builder
# START refusal AND its R7-B dependency differential on the exact candidate
# bytes:
#
#   Phase RED   — install the candidate tarball with R7_RUNTIME_DEPS=skip
#                 (the gate's unprovisioned runner): the build must fail and
#                 the evidence must show the builder START refusal and the
#                 missing launch-vehicle prerequisites.
#   Phase GREEN — uninstall, install the packaged runtime dependency contract
#                 (rootlesskit slirp4netns uidmap, the R7-B alignment), install
#                 the SAME candidate bytes again: the build must proceed past
#                 builder_start.
#
# No release artifact ownership changes: the candidate set is consumed exactly
# as the failed full gate produced it.
#
# Env inputs:
#   UAT_TARBALL           host path to the exact candidate tarball
#   UAT_TARBALL_SHA256    expected SHA-256 of that tarball
#   R7_DIAG_EVIDENCE_DIR  host evidence directory (default under /tmp)

set -Eeuo pipefail

PREFIX='[release-2.4-r7-diag-ubuntu]'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_DIR="${R7_DIAG_EVIDENCE_DIR:-/tmp/release-2.4-r7-diag-ubuntu-evidence}"

log()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

: "${UAT_TARBALL:?UAT_TARBALL required}"
: "${UAT_TARBALL_SHA256:?UAT_TARBALL_SHA256 required}"

mkdir -p "$EVIDENCE_DIR"

run_phase() { # <name> <deps> <expect> <logfile>
  local name="$1" deps="$2" expect="$3" logfile="$4"
  log "phase $name: R7_RUNTIME_DEPS=$deps R7_EXPECT=$expect"
  set +e
  sudo -E env "PATH=$PATH" \
    R7_BACKEND=apparmor R7_INSTALL=tarball \
    R7_ARTIFACT="$UAT_TARBALL" R7_ARTIFACT_SHA256="$UAT_TARBALL_SHA256" \
    R7_EXPECT="$expect" R7_RUNTIME_DEPS="$deps" \
    R7_EVIDENCE_DIR="$EVIDENCE_DIR/$name" \
    bash "$SCRIPT_DIR/release-2.4-r7-diag-guest.sh" 2>&1 | tee "$logfile"
  local rc=${PIPESTATUS[0]}
  set -e
  cat "$logfile"
  return "$rc"
}

# --- Phase RED: reproduce the gate's unprovisioned-runner refusal ----------
if ! run_phase red skip fail "$EVIDENCE_DIR/red.log"; then
  fail "phase RED did not reproduce the defect (see $EVIDENCE_DIR/red.log)"
fi
grep -q "R7-DIAG-RESULT=REPRODUCED" "$EVIDENCE_DIR/red.log" \
  || fail "phase RED did not report REPRODUCED"
log "phase RED: defect reproduced on the unprovisioned runner"

# --- Phase GREEN: the R7-B dependency differential on the SAME bytes --------
BUNDLE="$(find /tmp -maxdepth 2 -type d -name 'r7-bundle.*' | head -1)"
[ -n "$BUNDLE" ] || fail "phase GREEN: bundle extract directory not found"
sudo "$BUNDLE"/docker-helper-*/uninstall-system.sh --yes >/dev/null 2>&1 \
  || log "WARN: uninstall-system.sh exited non-zero (continuing)"

if ! run_phase green install ok "$EVIDENCE_DIR/green.log"; then
  fail "phase GREEN did not pass with the dependency contract applied (see $EVIDENCE_DIR/green.log)"
fi
grep -q "R7-DIAG-RESULT=BUILD-OK" "$EVIDENCE_DIR/green.log" \
  || fail "phase GREEN did not report BUILD-OK"
log "phase GREEN: build passed with the R7-B dependency contract applied"

log 'R7 Ubuntu diagnosis PASSED (red + green differential captured)'
