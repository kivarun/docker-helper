#!/usr/bin/env bash
#
# Host-side Release 2.4 P5-S2 Phase 4B orchestrator.
#
# Reuses the canonical Tumbleweed VM harness (scripts/uat-vm-tumbleweed.sh)
# to boot the official openSUSE Tumbleweed Cloud qcow2, transfers the REAL
# production composition (the docker-helper binary built from the tested
# proof commit, the shipped SELinux module 1.2 sources, the REAL builder
# unit and provisioning script) into the guest, and runs the guest-side
# Phase 4B launcher/provisioning proof inside the VM. The guest downloads
# and verifies the pinned BuildKit payload itself (the P4-A1 pattern).
# Every terminal outcome is a valid measured result; the report assigns
# the verdict.
#
# The composition is built from the TESTED PROOF COMMIT
# (PHASE4B_PROOF_REF) so the tested binary/policy identity is exact; the
# proof scripts themselves live on the script commit. A composition
# manifest (both SHAs + the input hashes) is transferred with the
# artifacts and recorded in the guest evidence.
#
set -Eeuo pipefail

PREFIX='[release-2.4-p5s2-phase4b-launcher-tw-vm]'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
EVIDENCE_DIR="${PHASE4B_EVIDENCE_DIR:-/tmp/release-2.4-p5s2-phase4b-launcher-evidence}"
GUEST_EVIDENCE_DIR='/tmp/release-2.4-p5s2-phase4b-launcher-evidence'
HELPER_BIN="${PHASE4B_HELPER_BIN:-$UAT_REPO_DIR/docker-helper}"
PROOF_SRC="${PHASE4B_PROOF_SRC:-$UAT_REPO_DIR/proof-src}"
PROOF_REF="$(cat "$PROOF_SRC/.phase4b-proof-ref" 2>/dev/null || true)"

log()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

# shellcheck source=scripts/uat-vm-tumbleweed.sh
source "$SCRIPT_DIR/uat-vm-tumbleweed.sh"

on_err() {
  vm_serial_tail || true
}
trap on_err ERR

[ -x "$HELPER_BIN" ] || fail "docker-helper binary not built at $HELPER_BIN (build it before this orchestrator)"
[ -f "$PROOF_SRC/packaging/selinux/docker-helper.te" ] || fail "proof-commit checkout missing at $PROOF_SRC (check out the tested proof commit)"
[ -n "$PROOF_REF" ] || fail "the proof-commit checkout does not record its own ref (write .phase4b-proof-ref)"
PROOF_REF="$(cat "$PROOF_SRC/.phase4b-proof-ref")"
SCRIPT_COMMIT="$(git -C "$UAT_REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"

log "boot Tumbleweed VM (composition from $PROOF_REF, scripts from $SCRIPT_COMMIT)"
vm_init

log 'transfer the Phase 4B production composition into the guest'
vm_ssh 'rm -rf /tmp/p5s2-phase4b-launcher && mkdir -p /tmp/p5s2-phase4b-launcher'
vm_scp "$HELPER_BIN" opc@127.0.0.1:/tmp/p5s2-phase4b-launcher/docker-helper
vm_scp "$PROOF_SRC/packaging/selinux/docker-helper.te" \
  opc@127.0.0.1:/tmp/p5s2-phase4b-launcher/docker-helper.te
vm_scp "$PROOF_SRC/packaging/selinux/docker-helper.fc" \
  opc@127.0.0.1:/tmp/p5s2-phase4b-launcher/docker-helper.fc
vm_scp "$PROOF_SRC/packaging/systemd/system/docker-helper-builder.service" \
  opc@127.0.0.1:/tmp/p5s2-phase4b-launcher/docker-helper-builder.service
vm_scp "$PROOF_SRC/packaging/scripts/lib/provision-builder.sh" \
  opc@127.0.0.1:/tmp/p5s2-phase4b-launcher/provision-builder.sh
vm_scp "$PROOF_SRC/packaging/modules-load.d/docker-helper-builder.conf" \
  opc@127.0.0.1:/tmp/p5s2-phase4b-launcher/modules-load.conf
vm_scp "$SCRIPT_DIR/release-2.4-p5s2-phase4b-launcher-tw.sh" \
  opc@127.0.0.1:/tmp/p5s2-phase4b-launcher/release-2.4-p5s2-phase4b-launcher-tw.sh
{
  echo "proof_commit=$PROOF_REF"
  echo "script_commit=$SCRIPT_COMMIT"
  echo "binary_sha256=$(sha256sum "$HELPER_BIN" | awk '{print $1}')"
  echo "te_sha256=$(sha256sum "$PROOF_SRC/packaging/selinux/docker-helper.te" | awk '{print $1}')"
  echo "fc_sha256=$(sha256sum "$PROOF_SRC/packaging/selinux/docker-helper.fc" | awk '{print $1}')"
  echo "unit_sha256=$(sha256sum "$PROOF_SRC/packaging/systemd/system/docker-helper-builder.service" | awk '{print $1}')"
  echo "provision_sha256=$(sha256sum "$PROOF_SRC/packaging/scripts/lib/provision-builder.sh" | awk '{print $1}')"
  echo "modules_load_sha256=$(sha256sum "$PROOF_SRC/packaging/modules-load.d/docker-helper-builder.conf" | awk '{print $1}')"
} > /tmp/p4b-vm-manifest
vm_scp /tmp/p4b-vm-manifest opc@127.0.0.1:/tmp/p5s2-phase4b-launcher/manifest.txt

log 'run the Phase 4B launcher/provisioning proof in the guest'
set +e
vm_ssh 'sudo bash /tmp/p5s2-phase4b-launcher/release-2.4-p5s2-phase4b-launcher-tw.sh' \
  > "$RUNNER_TEMP/p5s2-phase4b-guest.log" 2>&1
GUEST_RC=$?
cat "$RUNNER_TEMP/p5s2-phase4b-guest.log"
set -e

log 'collect guest evidence (before the marker gate: evidence survives failure)'
mkdir -p "$EVIDENCE_DIR"
if vm_ssh "test -d '$GUEST_EVIDENCE_DIR'" 2>/dev/null; then
  vm_ssh "tar -C '$GUEST_EVIDENCE_DIR' -czf - ." > "$EVIDENCE_DIR/guest-evidence.tar.gz" || true
  mkdir -p "$EVIDENCE_DIR/guest"
  tar -xzf "$EVIDENCE_DIR/guest-evidence.tar.gz" -C "$EVIDENCE_DIR/guest" 2>/dev/null || true
fi
if [ -s "$RUNNER_TEMP/p5s2-phase4b-guest.log" ]; then
  cp "$RUNNER_TEMP/p5s2-phase4b-guest.log" "$EVIDENCE_DIR/guest.log"
fi
sha256sum "$EVIDENCE_DIR"/guest.log "$EVIDENCE_DIR"/guest-evidence.tar.gz \
  > "$EVIDENCE_DIR/artifact-hashes.txt" 2>/dev/null || true

[ "$GUEST_RC" = 0 ] || fail "guest proof failed (exit $GUEST_RC)"
grep -q 'P5S2-P4B-RESULT=' "$RUNNER_TEMP/p5s2-phase4b-guest.log" \
  || fail "guest proof did not report a terminal measured outcome"

log 'openSUSE Tumbleweed Phase 4B launcher/provisioning proof reached a terminal measured outcome'
