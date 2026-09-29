#!/usr/bin/env bash
#
# Host-side Release 2.4 P5-S2g31 openSUSE/Tumbleweed orchestrator.
#
# Reuses the canonical Tumbleweed VM harness (scripts/uat-vm-tumbleweed.sh)
# to boot the official openSUSE Tumbleweed Cloud qcow2, transfers the REAL
# production composition (the docker-helper binary built from the proof
# commit, the REAL builder unit, the REAL provisioning script, and the
# shipped SELinux candidate sources) into the guest, and runs the
# guest-side P5-S2g31 production category allocation + launch lifecycle
# measurement inside the VM. The guest downloads and verifies the pinned
# BuildKit payload itself (the P4-A1 pattern). Findings are recorded in
# the guest evidence; every planned terminal outcome (POISONED-OUTPUT,
# FAIL-CLOSED, IGNORED, INCOMPLETE-with-findings) is a valid measured
# result and the report assigns the verdict.

set -Eeuo pipefail

PREFIX='[release-2.4-p5s2-state-mcs-tw-vm]'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
EVIDENCE_DIR="${CAT_LAUNCH_EVIDENCE_DIR:-/tmp/release-2.4-p5s2-cat-launch-evidence}"
GUEST_EVIDENCE_DIR='/tmp/release-2.4-p5s2-cat-launch-evidence'
HELPER_BIN="${CAT_LAUNCH_HELPER_BIN:-$UAT_REPO_DIR/docker-helper}"

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

log 'transfer the P5-S2g31 production composition into the guest'
# The transferred docker-helper binary is the PRODUCTION binary built
# from the proof commit with the GUEST-ONLY experimental patch applied
# (scripts/release-2.4-p5s2-cat-launch.patch): the CI build step applies
# the patch before compiling and restores the sources afterwards, so the
# repo tree itself stays clean. The patch adds the per-instance category
# allocation stand-in, the state-tree labeling at provisioning, and the
# runcon launch wrap. It is never committed to production sources.
vm_ssh 'rm -rf /tmp/p5s2-cat-launch && mkdir -p /tmp/p5s2-cat-launch'
vm_scp "$HELPER_BIN" opc@127.0.0.1:/tmp/p5s2-cat-launch/docker-helper
vm_scp "$UAT_REPO_DIR/packaging/selinux/docker-helper.te" \
  opc@127.0.0.1:/tmp/p5s2-cat-launch/docker-helper.te
vm_scp "$UAT_REPO_DIR/packaging/selinux/docker-helper.fc" \
  opc@127.0.0.1:/tmp/p5s2-cat-launch/docker-helper.fc
vm_scp "$UAT_REPO_DIR/packaging/systemd/system/docker-helper-builder.service" \
  opc@127.0.0.1:/tmp/p5s2-cat-launch/docker-helper-builder.service
vm_scp "$UAT_REPO_DIR/packaging/scripts/lib/provision-builder.sh" \
  opc@127.0.0.1:/tmp/p5s2-cat-launch/provision-builder.sh
vm_scp "$SCRIPT_DIR/release-2.4-p5s2-cat-launch-tw.sh" \
  opc@127.0.0.1:/tmp/p5s2-cat-launch/release-2.4-p5s2-cat-launch-tw.sh

log 'install guest prerequisites and run the P5-S2g31 proof'
set +e
vm_ssh 'sudo bash /tmp/p5s2-cat-launch/release-2.4-p5s2-cat-launch-tw.sh' >"$RUNNER_TEMP/p5s2-cat-launch-guest.log" 2>&1
GUEST_RC=$?
cat "$RUNNER_TEMP/p5s2-cat-launch-guest.log"
set -e

log 'collect guest evidence (before the PASS gate: evidence survives failure)'
mkdir -p "$EVIDENCE_DIR"
if vm_ssh "test -d '$GUEST_EVIDENCE_DIR'" 2>/dev/null; then
  vm_ssh "tar -C '$GUEST_EVIDENCE_DIR' -czf - ." > "$EVIDENCE_DIR/guest-evidence.tar.gz" || true
  mkdir -p "$EVIDENCE_DIR/guest"
  tar -xzf "$EVIDENCE_DIR/guest-evidence.tar.gz" -C "$EVIDENCE_DIR/guest" 2>/dev/null || true
fi
if [ -s "$RUNNER_TEMP/p5s2-cat-launch-guest.log" ]; then
  cp "$RUNNER_TEMP/p5s2-cat-launch-guest.log" "$EVIDENCE_DIR/guest.log"
fi

[ "$GUEST_RC" = 0 ] || fail "guest proof failed (exit $GUEST_RC)"
grep -q "P5S2-CAT-LAUNCH-RESULT=" "$RUNNER_TEMP/p5s2-cat-launch-guest.log" || fail "guest proof did not report a terminal measured outcome"

log 'openSUSE Tumbleweed P5-S2g31 category launch lifecycle proof reached a terminal measured outcome'
