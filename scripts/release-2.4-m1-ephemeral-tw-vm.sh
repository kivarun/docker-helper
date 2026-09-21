#!/usr/bin/env bash
#
# Host-side Release 2.4 M1 openSUSE/Tumbleweed ephemeral-proof orchestrator.
#
# Reuses the canonical Tumbleweed VM harness (scripts/uat-vm-tumbleweed.sh)
# to boot the official openSUSE Tumbleweed Cloud qcow2 on a GitHub-hosted
# runner, installs the M1 composition prerequisites inside the guest, and
# runs the same ephemeral-instance probe as the hosted-runner proof.
#
# M1 probe only: no docker-helper product behavior, no RPM/policy install.

set -Eeuo pipefail

PREFIX='[release-2.4-m1-tw-vm]'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
EVIDENCE_DIR="${M1_EVIDENCE_DIR:-/tmp/release-2.4-m1-tw-evidence}"
GUEST_EVIDENCE_DIR='/tmp/release-2.4-m1-tw-evidence'

log()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

# shellcheck source=scripts/uat-vm-tumbleweed.sh
source "$SCRIPT_DIR/uat-vm-tumbleweed.sh"

on_err() {
  vm_serial_tail || true
}
trap on_err ERR

log 'boot Tumbleweed VM'
vm_init

log 'transfer the M1 probe scripts into the guest'
vm_scp "$SCRIPT_DIR/release-2.4-m1-ephemeral-proof.sh" opc@127.0.0.1:/tmp/release-2.4-m1-ephemeral-proof.sh
vm_scp "$SCRIPT_DIR/release-2.4-m1-ephemeral-tw.sh" opc@127.0.0.1:/tmp/release-2.4-m1-ephemeral-tw.sh

log 'install guest prerequisites and run the M1 probe'
set +e
vm_ssh 'sudo bash -s' >"$RUNNER_TEMP/m1-tw-guest.log" 2>&1 <<'RMT'
set -euo pipefail
bash /tmp/release-2.4-m1-ephemeral-tw.sh
RMT
GUEST_RC=$?
cat "$RUNNER_TEMP/m1-tw-guest.log"
set -e

log 'collect guest evidence (before the PASS gate: evidence survives failure)'
mkdir -p "$EVIDENCE_DIR"
if vm_ssh "test -d '$GUEST_EVIDENCE_DIR'" 2>/dev/null; then
  vm_ssh "tar -C '$GUEST_EVIDENCE_DIR' -czf - ." > "$EVIDENCE_DIR/guest-evidence.tar.gz" || true
  mkdir -p "$EVIDENCE_DIR/guest"
  tar -xzf "$EVIDENCE_DIR/guest-evidence.tar.gz" -C "$EVIDENCE_DIR/guest" 2>/dev/null || true
fi

[ "$GUEST_RC" = 0 ] || fail "guest probe failed (exit $GUEST_RC)"
grep -q "M1-EPHEMERAL-PROOF-RESULT=PASS" "$RUNNER_TEMP/m1-tw-guest.log" || fail "guest probe did not report PASS"

log 'openSUSE Tumbleweed M1 ephemeral composition proof PASSED'
