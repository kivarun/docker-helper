#!/usr/bin/env bash
#
# Host-side Release 2.4 P4-A1 openSUSE/Tumbleweed orchestrator.
#
# Reuses the canonical Tumbleweed VM harness (scripts/uat-vm-tumbleweed.sh)
# to boot the official openSUSE Tumbleweed Cloud qcow2, transfers the REAL
# production composition (docker-helper binary built from the proof commit,
# the proposed builder unit, the real provisioning script, and the
# distro-agnostic proof script) into the guest, and runs the guest-side
# P4-A1 proof inside the VM. Real-process and build proofs only; no
# packaging matrix (documented as remaining P4 work).

set -Eeuo pipefail

PREFIX='[release-2.4-p4a1-tw-vm]'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
EVIDENCE_DIR="${P4A1_EVIDENCE_DIR:-/tmp/release-2.4-p4a1-tw-evidence}"
GUEST_EVIDENCE_DIR='/tmp/release-2.4-p4a1-tw-evidence'
HELPER_BIN="${P4A1_HELPER_BIN:-$UAT_REPO_DIR/docker-helper}"

log()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

# shellcheck source=scripts/uat-vm-tumbleweed.sh
source "$SCRIPT_DIR/uat-vm-tumbleweed.sh"

on_err() {
  vm_serial_tail || true
}
trap on_err ERR

[ -x "$HELPER_BIN" ] || fail "docker-helper binary not built at $HELPER_BIN (build it before this orchestrator)"

log 'boot Tumbleweed VM'
vm_init

log 'transfer the P4-A1 production composition into the guest'
vm_ssh 'rm -rf /tmp/p4a1 && mkdir -p /tmp/p4a1'
vm_scp "$HELPER_BIN" opc@127.0.0.1:/tmp/p4a1/docker-helper
vm_scp "$UAT_REPO_DIR/packaging/systemd/system/docker-helper-builder.service" \
  opc@127.0.0.1:/tmp/p4a1/docker-helper-builder.service
vm_scp "$UAT_REPO_DIR/packaging/scripts/lib/provision-builder.sh" \
  opc@127.0.0.1:/tmp/p4a1/provision-builder.sh
vm_scp "$SCRIPT_DIR/release-2.4-p4a1-proof.sh" opc@127.0.0.1:/tmp/p4a1/release-2.4-p4a1-proof.sh
vm_scp "$SCRIPT_DIR/release-2.4-p4a1-tw.sh" opc@127.0.0.1:/tmp/p4a1/release-2.4-p4a1-tw.sh

log 'install guest prerequisites and run the P4-A1 proof'
set +e
vm_ssh 'sudo bash /tmp/p4a1/release-2.4-p4a1-tw.sh' >"$RUNNER_TEMP/p4a1-tw-guest.log" 2>&1
GUEST_RC=$?
cat "$RUNNER_TEMP/p4a1-tw-guest.log"
set -e

log 'collect guest evidence (before the PASS gate: evidence survives failure)'
mkdir -p "$EVIDENCE_DIR"
if vm_ssh "test -d '$GUEST_EVIDENCE_DIR'" 2>/dev/null; then
  vm_ssh "tar -C '$GUEST_EVIDENCE_DIR' -czf - ." > "$EVIDENCE_DIR/guest-evidence.tar.gz" || true
  mkdir -p "$EVIDENCE_DIR/guest"
  tar -xzf "$EVIDENCE_DIR/guest-evidence.tar.gz" -C "$EVIDENCE_DIR/guest" 2>/dev/null || true
fi

[ "$GUEST_RC" = 0 ] || fail "guest proof failed (exit $GUEST_RC)"
grep -q "P4A1-PROOF-RESULT=PASS" "$RUNNER_TEMP/p4a1-tw-guest.log" || fail "guest proof did not report PASS"

log 'openSUSE Tumbleweed P4-A1 production unit-boundary proof PASSED'
