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
# The diag VM reboots mid-diagnosis (observed ~55s after boot; runs
# 39006788899+). The guest script is phased with state markers under
# /tmp/r7-diag-state and the evidence lives in a tmpfs dir, so each
# invocation's evidence is collected immediately and the invocation is
# repeated over fresh SSH sessions until the verdict appears.
VERDICT=""
for attempt in 1 2 3; do
  if [ "$attempt" -gt 1 ]; then
    log "re-entry: waiting for SSH after the observed mid-diagnosis reboot"
    vm_wait_ssh
  fi
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

  # Per-attempt evidence files: each attempt's console log and evidence
  # tarball is preserved under its own suffix (a later attempt never
  # overwrites an earlier attempt's captured evidence).
  log "collect guest evidence (survives the verdict; attempt $attempt)"
  mkdir -p "$EVIDENCE_DIR"
  cp "$RUNNER_TEMP/r7-diag-guest.log" "$EVIDENCE_DIR/guest-attempt$attempt.log"
  if vm_ssh "test -d '$GUEST_EVIDENCE_DIR'" 2>/dev/null; then
    vm_ssh "tar -C '$GUEST_EVIDENCE_DIR' -czf - ." > "$EVIDENCE_DIR/guest-evidence-attempt$attempt.tar.gz" || true
    mkdir -p "$EVIDENCE_DIR/guest-attempt$attempt"
    tar -xzf "$EVIDENCE_DIR/guest-evidence-attempt$attempt.tar.gz" -C "$EVIDENCE_DIR/guest-attempt$attempt" 2>/dev/null || true
  fi

  VERDICT="$(grep -aoE 'R7-DIAG-RESULT=[A-Z-]+' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
  case "$VERDICT" in
    "R7-DIAG-RESULT=REPRODUCED")
      log 'R7 SELinux diagnosis REPRODUCED (the defect is still live on this branch; red evidence captured)'
      break
      ;;
    "R7-DIAG-RESULT=BUILD-OK")
      log 'R7 SELinux diagnosis BUILD-OK (the corrective holds on this branch; green evidence captured)'
      break
      ;;
    *)
      if [ "$attempt" -eq 3 ]; then
        fail "the R7 SELinux diagnosis produced no verdict (guest exit $GUEST_RC)"
      fi
      log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
      ;;
  esac
done
set -e
