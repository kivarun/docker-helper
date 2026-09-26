#!/usr/bin/env bash
#
# Host-side P5-S2 uid_map write-grant scope assessment orchestrator for
# openSUSE/Tumbleweed. Reuses the canonical Tumbleweed VM harness
# (scripts/uat-vm-tumbleweed.sh) — same image, same boot machinery, no
# second harness. Transfers the CANDIDATE policy sources (the repo's
# docker-helper.te/.fc) plus the guest diagnostic script; the guest compiles
# and loads the candidate module on the disposable VM and runs the
# assessment. No production changes, no candidate package build.
set -Eeuo pipefail

PREFIX='[release-2.4-p5s2-uidmap-scope-diag-tw-vm]'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
EVIDENCE_DIR="${P5S2_UIDMAP_SCOPE_DIAG_EVIDENCE_DIR:-/tmp/release-2.4-p5s2-uidmap-scope-diag-evidence}"
GUEST_EVIDENCE_DIR='/tmp/release-2.4-p5s2-uidmap-scope-diag-evidence'

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

log 'transfer the diagnostic script and the candidate policy sources into the guest'
vm_ssh 'rm -rf /tmp/p5s2-uidmap-diag && mkdir -p /tmp/p5s2-uidmap-diag'
vm_scp "$SCRIPT_DIR/release-2.4-p5s2-uidmap-scope-diag-tw.sh" opc@127.0.0.1:/tmp/p5s2-uidmap-diag/
vm_scp "$UAT_REPO_DIR/packaging/selinux/docker-helper.te" opc@127.0.0.1:/tmp/p5s2-uidmap-diag/
vm_scp "$UAT_REPO_DIR/packaging/selinux/docker-helper.fc" opc@127.0.0.1:/tmp/p5s2-uidmap-diag/

log 'run the uid_map grant scope assessment inside the guest'
set +e
vm_ssh 'sudo bash /tmp/p5s2-uidmap-diag/release-2.4-p5s2-uidmap-scope-diag-tw.sh' \
  >"$RUNNER_TEMP/p5s2-uidmap-scope-diag-guest.log" 2>&1
GUEST_RC=$?
cat "$RUNNER_TEMP/p5s2-uidmap-scope-diag-guest.log"
set -e

log 'collect guest evidence (before the PASS gate: evidence survives failure)'
mkdir -p "$EVIDENCE_DIR"
cp "$RUNNER_TEMP/p5s2-uidmap-scope-diag-guest.log" "$EVIDENCE_DIR/guest.log"
if vm_ssh "test -d '$GUEST_EVIDENCE_DIR'" 2>/dev/null; then
  vm_ssh "tar -C '$GUEST_EVIDENCE_DIR' -czf - ." > "$EVIDENCE_DIR/guest-evidence.tar.gz" || true
  mkdir -p "$EVIDENCE_DIR/guest"
  tar -xzf "$EVIDENCE_DIR/guest-evidence.tar.gz" -C "$EVIDENCE_DIR/guest" 2>/dev/null || true
fi

[ "$GUEST_RC" = 0 ] || fail "guest assessment failed (exit $GUEST_RC)"
grep -q "P5S2-UIDMAP-SCOPE-DIAG-RESULT=PASS" "$RUNNER_TEMP/p5s2-uidmap-scope-diag-guest.log" \
  || fail "guest assessment did not report PASS"

log 'openSUSE Tumbleweed uid_map grant scope assessment PASSED'
