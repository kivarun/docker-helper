#!/usr/bin/env bash
#
# release-2.4-r7-diag-tw-selinux-vm.sh — R7 full-gate corrective diagnosis on
# a disposable ENFORCING openSUSE Tumbleweed VM (RPM candidate). Proves the
# R7-A buildctl execution defect and the builder-chain AVC staircase on the
# exact candidate bytes (R7-C/R7-D evidence), without touching any release
# artifact ownership: the candidate set is consumed exactly as the failed
# full gate produced it.
#
# Reuses the canonical VM machinery (scripts/uat-vm-tumbleweed.sh) and the
# shared SELinux host construction (scripts/uat-vm-opensuse-selinux-lib.sh) —
# no second harness, no second SELinux bootstrap.
#
# Env inputs (host side):
#   UAT_REPO_DIR        host checkout (default: repo root)
#   UAT_RPM             host path to the exact candidate RPM
#   UAT_RPM_SHA256      expected SHA-256 of that RPM
#   R7_DIAG_EVIDENCE_DIR  host evidence directory (default under /tmp)

set -Eeuo pipefail

PREFIX='[release-2.4-r7-diag-tw-selinux-vm]'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
EVIDENCE_DIR="${R7_DIAG_EVIDENCE_DIR:-/tmp/release-2.4-r7-diag-selinux-evidence}"
GUEST_EVIDENCE_DIR='/tmp/r7-diag-evidence'

log()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

: "${UAT_RPM:?UAT_RPM required}"
: "${UAT_RPM_SHA256:?UAT_RPM_SHA256 required}"

# shellcheck source=scripts/uat-vm-tumbleweed.sh
source "$SCRIPT_DIR/uat-vm-tumbleweed.sh"
# shellcheck source=scripts/uat-vm-opensuse-selinux-lib.sh
source "$SCRIPT_DIR/uat-vm-opensuse-selinux-lib.sh"

on_err() { vm_serial_tail || true; }
trap on_err ERR

log '== 1-5. SELinux host construction (canonical bootstrap, enforcing proof)'
vm_selinux_bootstrap

log '== 6. transfer repo + exact candidate RPM into the guest'
vm_selinux_transfer_repo
vm_selinux_transfer_artifact "docker-helper.rpm" "$UAT_RPM"

log '== 6b-7a. two-stage Docker preparation + health gate'
vm_selinux_two_stage_docker

log '== 7. transfer and run the R7 guest diagnostic'
vm_ssh 'rm -rf /tmp/r7-diag && mkdir -p /tmp/r7-diag'
vm_scp "$SCRIPT_DIR/release-2.4-r7-diag-guest.sh" opc@127.0.0.1:/tmp/r7-diag/release-2.4-r7-diag-guest.sh

set +e
vm_ssh 'sudo bash -s' <<RMT >"$RUNNER_TEMP/r7-diag-guest.log" 2>&1
export R7_BACKEND=selinux R7_INSTALL=rpm
export R7_ARTIFACT=/opt/uat-import/docker-helper.rpm
export R7_ARTIFACT_SHA256="$UAT_RPM_SHA256"
export R7_EXPECT=fail
export R7_RUNTIME_DEPS=install
export R7_EVIDENCE_DIR='$GUEST_EVIDENCE_DIR'
bash /tmp/r7-diag/release-2.4-r7-diag-guest.sh
RMT
GUEST_RC=$?
cat "$RUNNER_TEMP/r7-diag-guest.log"
set -e

log 'collect guest evidence (survives the verdict)'
mkdir -p "$EVIDENCE_DIR"
cp "$RUNNER_TEMP/r7-diag-guest.log" "$EVIDENCE_DIR/guest.log"
if vm_ssh "test -d '$GUEST_EVIDENCE_DIR'" 2>/dev/null; then
  vm_ssh "tar -C '$GUEST_EVIDENCE_DIR' -czf - ." > "$EVIDENCE_DIR/guest-evidence.tar.gz" || true
  mkdir -p "$EVIDENCE_DIR/guest"
  tar -xzf "$EVIDENCE_DIR/guest-evidence.tar.gz" -C "$EVIDENCE_DIR/guest" 2>/dev/null || true
fi

grep -q "R7-DIAG-RESULT=REPRODUCED" "$RUNNER_TEMP/r7-diag-guest.log" \
  || fail "the R7 SELinux diagnosis did not reproduce the defect (guest exit $GUEST_RC)"
log 'R7 SELinux diagnosis REPRODUCED (red-before evidence captured)'
