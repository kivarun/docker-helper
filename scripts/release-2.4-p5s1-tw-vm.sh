#!/usr/bin/env bash
#
# Host-side Release 2.4 P5-S1 orchestrator for openSUSE/Tumbleweed — SELinux
# builder bootstrap proof.
#
# Reuses the canonical Tumbleweed VM harness (scripts/uat-vm-tumbleweed.sh)
# to boot the official openSUSE Tumbleweed Cloud qcow2, transfers the
# GENERATED release-candidate RPM + tarball (the canonical producer output,
# never loose files from the checkout) into the guest together with the
# guest-side P5-S1 proof, and runs the proof inside the VM (enforcing
# SELinux throughout).

set -Eeuo pipefail

PREFIX='[release-2.4-p5s1-tw-vm]'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
EVIDENCE_DIR="${P5S1_EVIDENCE_DIR:-/tmp/release-2.4-p5s1-tw-evidence}"
GUEST_EVIDENCE_DIR='/tmp/release-2.4-p5s1-tw-evidence'
CANDIDATE_DIR="${P5S1_CANDIDATE_DIR:-$UAT_REPO_DIR/dist/candidate}"
VERSION="${P5S1_VERSION:-2.4.0}"

log()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

# shellcheck source=scripts/uat-vm-tumbleweed.sh
source "$SCRIPT_DIR/uat-vm-tumbleweed.sh"

on_err() {
  vm_serial_tail || true
}
trap on_err ERR

[ -f "$CANDIDATE_DIR/docker-helper-${VERSION}-1.x86_64.rpm" ] \
  || fail "candidate RPM missing in $CANDIDATE_DIR (run scripts/release-candidate.sh first)"
[ -f "$CANDIDATE_DIR/docker-helper-${VERSION}-linux-amd64.tar.gz" ] \
  || fail "candidate tarball missing in $CANDIDATE_DIR"
[ -f "$CANDIDATE_DIR/SHA256SUMS" ] || fail "candidate SHA256SUMS missing"

log 'boot Tumbleweed VM'
vm_init

log 'transfer the generated release-candidate artifacts into the guest'
vm_ssh 'rm -rf /tmp/p5s1 && mkdir -p /tmp/p5s1/candidate'
vm_scp "$CANDIDATE_DIR"/* opc@127.0.0.1:/tmp/p5s1/candidate/
vm_scp "$SCRIPT_DIR/release-2.4-p5s1-tw.sh" opc@127.0.0.1:/tmp/p5s1/release-2.4-p5s1-tw.sh

log 'run the P5-S1 builder-MAC proof inside the guest'
set +e
vm_ssh 'sudo bash /tmp/p5s1/release-2.4-p5s1-tw.sh' >"$RUNNER_TEMP/p5s1-tw-guest.log" 2>&1
GUEST_RC=$?
cat "$RUNNER_TEMP/p5s1-tw-guest.log"
set -e

log 'collect guest evidence (before the PASS gate: evidence survives failure)'
mkdir -p "$EVIDENCE_DIR"
# The guest's own stdout/stderr log is part of the evidence: failures in the
# guest are only visible here.
cp "$RUNNER_TEMP/p5s1-tw-guest.log" "$EVIDENCE_DIR/guest.log"
if vm_ssh "test -d '$GUEST_EVIDENCE_DIR'" 2>/dev/null; then
  vm_ssh "tar -C '$GUEST_EVIDENCE_DIR' -czf - ." > "$EVIDENCE_DIR/guest-evidence.tar.gz" || true
  mkdir -p "$EVIDENCE_DIR/guest"
  tar -xzf "$EVIDENCE_DIR/guest-evidence.tar.gz" -C "$EVIDENCE_DIR/guest" 2>/dev/null || true
fi

[ "$GUEST_RC" = 0 ] || fail "guest proof failed (exit $GUEST_RC)"
grep -q "P5-S1-TW-BUILDER-MAC-RESULT=PASS" "$RUNNER_TEMP/p5s1-tw-guest.log" \
  || fail "guest proof did not report PASS"

log 'openSUSE Tumbleweed P5-S1 SELinux builder bootstrap proof PASSED'
