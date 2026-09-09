#!/usr/bin/env bash
#
# Host-side Release 2.2 M0-S orchestrator. It reuses the canonical openSUSE
# Tumbleweed SELinux VM construction, installs the authoritative production
# docker_helper policy from this checkout, and runs the bounded guest proof.

set -Eeuo pipefail

PREFIX='[release-2.2-m0-selinux-vm]'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
EVIDENCE_DIR="${M0_EVIDENCE_DIR:-/tmp/docker-helper-release-2.2-m0-selinux-evidence}"
GUEST_EVIDENCE_DIR='/tmp/docker-helper-release-2.2-m0-selinux-evidence'
PROOF_RESULT='FAIL'

log() {
  printf '%s %s\n' "$PREFIX" "$*"
}

fail() {
  printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2
  exit 1
}

[ -f "$UAT_REPO_DIR/scripts/release-2.2-m0-selinux-proof.sh" ] \
  || fail "proof script not found in checkout: $UAT_REPO_DIR"
mkdir -p "$EVIDENCE_DIR"

# shellcheck source=/dev/null
source "$SCRIPT_DIR/uat-vm-opensuse-selinux-lib.sh"

on_err() {
  vm_serial_tail || true
  if vm_ssh true 2>/dev/null; then
    guest_evidence || true
  fi
}
trap on_err ERR

collect_guest_evidence() {
  local archive="$EVIDENCE_DIR/guest-evidence.tar.gz"
  if vm_ssh "sudo test -d '$GUEST_EVIDENCE_DIR'" 2>/dev/null; then
    vm_ssh "sudo tar -C '$GUEST_EVIDENCE_DIR' -czf - ." >"$archive" || return 1
    tar -xzf "$archive" -C "$EVIDENCE_DIR"
    return 0
  fi
  return 1
}

log 'bootstrap canonical enforcing Tumbleweed SELinux guest'
vm_selinux_bootstrap
vm_selinux_transfer_repo
vm_selinux_two_stage_docker

log 'install proof-only bindfs and SELinux module build dependencies'
DEPENDENCY_RESULT="$(vm_ssh 'sudo bash -s' <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# shellcheck source=/dev/null
source /opt/uat-repo-policy.sh
opensuse_zypp_tune_timeouts
opensuse_zypper_refresh
opensuse_zypper install -y bindfs checkpolicy policycoreutils-devel setools-console audit
for command_name in bindfs checkmodule semodule_package; do
  command -v "$command_name" >/dev/null 2>&1 \
    || { echo "missing command after dependency install: $command_name" >&2; exit 1; }
done
echo "BINDFS_VERSION=$(bindfs --version | head -1)"
echo 'DEPENDENCIES-DONE'
RMT
)"
printf '%s\n' "$DEPENDENCY_RESULT"
printf '%s\n' "$DEPENDENCY_RESULT" | grep -q 'DEPENDENCIES-DONE' \
  || fail 'guest proof dependency installation did not complete'

log 'compile and load the authoritative production docker_helper policy'
POLICY_RESULT="$(vm_ssh 'sudo bash -s' <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
rm -rf /tmp/docker-helper-m0-production-policy
mkdir -p /tmp/docker-helper-m0-production-policy
/opt/uat/build-selinux-policy.sh /tmp/docker-helper-m0-production-policy
semodule -i /tmp/docker-helper-m0-production-policy/docker_helper.pp
semodule -l | awk '$1 == "docker_helper" { found=1 } END { exit !found }'
seinfo -t docker_helper_container_t | grep -q docker_helper_container_t
seinfo -t docker_helper_workspace_t | grep -q docker_helper_workspace_t
echo 'PRODUCTION-POLICY-DONE'
RMT
)"
printf '%s\n' "$POLICY_RESULT"
printf '%s\n' "$POLICY_RESULT" | grep -q 'PRODUCTION-POLICY-DONE' \
  || fail 'production docker_helper policy preparation did not complete'

log 'run bounded M0-S guest proof'
if vm_ssh "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin M0_EVIDENCE_DIR='$GUEST_EVIDENCE_DIR' scripts/release-2.2-m0-selinux-proof.sh"; then
  PROOF_RESULT='PASS'
else
  PROOF_RC=$?
  log "guest proof failed with exit $PROOF_RC"
fi

if ! collect_guest_evidence; then
  log 'warning: guest evidence directory was unavailable'
fi

{
  printf 'HOST_RESULT=%s\n' "$PROOF_RESULT"
  printf 'VM_IMAGE_SHA256=%s\n' "$VM_IMG_SHA256"
  printf 'VM_ACCEL=%s\n' "$VM_ACCEL"
  printf 'VM_BOOT_TIME=%s\n' "$VM_BOOT_TIME"
  printf 'VM_REBOOT_TIME=%s\n' "$VM_LAST_REBOOT_SECS"
  printf 'TESTED_SOURCE=%s\n' "$(git -C "$UAT_REPO_DIR" rev-parse HEAD)"
} >"$EVIDENCE_DIR/host-summary.txt"

[ "$PROOF_RESULT" = 'PASS' ] || fail 'M0-S guest proof did not close'
grep -Fxq 'M0_S_RESULT=CLOSED' "$EVIDENCE_DIR/summary.txt" \
  || fail 'guest summary does not close M0-S'
log 'M0-S CLOSED in canonical enforcing Tumbleweed guest'
