#!/usr/bin/env bash
#
# Host-side Release 2.4 P5-S2 Phase 4B orchestrator.
#
# Reuses the canonical Tumbleweed VM harness (scripts/uat-vm-tumbleweed.sh)
# to boot the official openSUSE Tumbleweed Cloud qcow2 and runs the
# guest-side Phase 4B launcher/provisioning proof inside the VM. The guest
# downloads and verifies the pinned BuildKit payload itself (the P4-A1
# pattern).
#
# Two modes (external reviews F3/F4):
#
#   Release gate mode (PHASE4B_RELEASE_GATE=1, default): the composition
#   is the EXACT release candidate — the orchestrator's own checkout,
#   pinned to the candidate SHA passed in PHASE4B_CANDIDATE_SHA. The
#   binary, the shipped SELinux module sources, the builder unit, and the
#   provisioning script all come from that one checkout; the manifest
#   records the candidate SHA and the input hashes, and the guest evidence
#   records the same manifest (the guest's hash chain verifies every
#   transferred input against it). The verdict gate requires exactly one
#   terminal verdict and that verdict must be PASS.
#
#   Historical experiment mode (PHASE4B_RELEASE_GATE=0): the composition
#   is built from the TESTED PROOF COMMIT (PHASE4B_PROOF_REF) so the
#   tested binary/policy identity is exact for the pinned investigation;
#   the proof scripts themselves live on the script commit. Every terminal
#   outcome is a valid measured result; the report assigns the verdict.
#
set -Eeuo pipefail

PREFIX='[release-2.4-p5s2-phase4b-launcher-tw-vm]'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
EVIDENCE_DIR="${PHASE4B_EVIDENCE_DIR:-/tmp/release-2.4-p5s2-phase4b-launcher-evidence}"
GUEST_EVIDENCE_DIR='/tmp/release-2.4-p5s2-phase4b-launcher-evidence'
HELPER_BIN="${PHASE4B_HELPER_BIN:-$UAT_REPO_DIR/docker-helper}"
TUN_PROBE_BIN="${PHASE4B_TUN_PROBE_BIN:-$UAT_REPO_DIR/tun-command-probe}"
CROSS_VEHICLE_BIN="${PHASE4B_CROSS_VEHICLE_BIN:-$UAT_REPO_DIR/tun-cross-op-vehicle}"
RELEASE_GATE="${PHASE4B_RELEASE_GATE:-1}"

log()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

if [ "$RELEASE_GATE" = "1" ]; then
  # Release gate: the composition IS the candidate checkout. No pinned
  # proof ref exists on this path.
  PROOF_SRC="$UAT_REPO_DIR"
  CANDIDATE_SHA="${PHASE4B_CANDIDATE_SHA:-}"
  [ -n "$CANDIDATE_SHA" ] || fail "release gate mode requires PHASE4B_CANDIDATE_SHA"
  CHECKOUT_SHA="$(git -C "$UAT_REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
  [ "$CHECKOUT_SHA" = "$CANDIDATE_SHA" ] \
    || fail "the composition checkout ($CHECKOUT_SHA) is not the release candidate ($CANDIDATE_SHA)"
else
  PROOF_SRC="${PHASE4B_PROOF_SRC:-$UAT_REPO_DIR/proof-src}"
fi

# shellcheck source=scripts/uat-vm-tumbleweed.sh
source "$SCRIPT_DIR/uat-vm-tumbleweed.sh"

on_err() {
  vm_serial_tail || true
}
trap on_err ERR

[ -x "$HELPER_BIN" ] || fail "docker-helper binary not built at $HELPER_BIN (build it before this orchestrator)"
[ -x "$TUN_PROBE_BIN" ] || fail "tun-command-probe binary not built at $TUN_PROBE_BIN (build it before this orchestrator)"
[ -x "$CROSS_VEHICLE_BIN" ] || fail "tun-cross-op-vehicle binary not built at $CROSS_VEHICLE_BIN (build it before this orchestrator)"
[ -f "$PROOF_SRC/packaging/selinux/docker-helper.te" ] || fail "composition checkout missing at $PROOF_SRC (check out the composition)"
if [ "$RELEASE_GATE" = "1" ]; then
  :
else
  PROOF_REF="$(cat "$PROOF_SRC/.phase4b-proof-ref" 2>/dev/null || true)"
  [ -n "$PROOF_REF" ] || fail "the proof-commit checkout does not record its own ref (write .phase4b-proof-ref)"
  PROOF_REF="$(cat "$PROOF_SRC/.phase4b-proof-ref")"
fi
SCRIPT_COMMIT="$(git -C "$UAT_REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"

if [ "$RELEASE_GATE" = "1" ]; then
  log "boot Tumbleweed VM (release gate: candidate $CANDIDATE_SHA, scripts from $SCRIPT_COMMIT)"
else
  log "boot Tumbleweed VM (historical experiment: composition from $PROOF_REF, scripts from $SCRIPT_COMMIT)"
fi
vm_init

log 'transfer the Phase 4B production composition into the guest'
vm_ssh 'rm -rf /tmp/p5s2-phase4b-launcher && mkdir -p /tmp/p5s2-phase4b-launcher'
vm_scp "$HELPER_BIN" opc@127.0.0.1:/tmp/p5s2-phase4b-launcher/docker-helper
vm_scp "$TUN_PROBE_BIN" opc@127.0.0.1:/tmp/p5s2-phase4b-launcher/tun-command-probe
vm_scp "$CROSS_VEHICLE_BIN" opc@127.0.0.1:/tmp/p5s2-phase4b-launcher/tun-cross-op-vehicle
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
  if [ "$RELEASE_GATE" = "1" ]; then
    echo "candidate_sha=$CANDIDATE_SHA"
  else
    echo "proof_commit=$PROOF_REF"
  fi
  echo "script_commit=$SCRIPT_COMMIT"
  echo "binary_sha256=$(sha256sum "$HELPER_BIN" | awk '{print $1}')"
  echo "tun_probe_sha256=$(sha256sum "$TUN_PROBE_BIN" | awk '{print $1}')"
  echo "cross_vehicle_sha256=$(sha256sum "$CROSS_VEHICLE_BIN" | awk '{print $1}')"
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

log 'collect guest evidence (before the verdict gate: evidence survives failure)'
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
cp /tmp/p4b-vm-manifest "$EVIDENCE_DIR/composition-manifest.txt"

log 'run the verdict gate (external review F4: exactly one terminal verdict; PASS only in release gate mode)'
"$SCRIPT_DIR/release-2.4-p5s2-verdict-gate.sh" \
  "$RUNNER_TEMP/p5s2-phase4b-guest.log" "$GUEST_RC" /tmp/p4b-vm-manifest

if [ "$RELEASE_GATE" = "1" ]; then
  log "openSUSE Tumbleweed Phase 4B release gate: candidate $CANDIDATE_SHA proved PASS on the exact candidate composition"
else
  log 'openSUSE Tumbleweed Phase 4B launcher/provisioning proof reached a terminal measured outcome'
fi
