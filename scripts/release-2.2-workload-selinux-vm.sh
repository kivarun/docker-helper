#!/usr/bin/env bash
#
# Host-side Release 2.2 Phase 2.2.6 live SELinux workload-MAC orchestrator.
# It reuses the canonical openSUSE Tumbleweed SELinux VM construction,
# installs the authoritative production docker_helper policy from this
# checkout, transfers the exact host-built production proof binary, and runs
# the bounded live workload MAC proof (production Go backend + real bindfs
# + enforcing SELinux + real Docker) inside the guest.

set -Eeuo pipefail

PREFIX='[release-2.2-workload-selinux-vm]'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
EVIDENCE_DIR="${WORKLOAD_EVIDENCE_DIR:-/tmp/docker-helper-release-2.2-workload-selinux-evidence}"
GUEST_EVIDENCE_DIR='/tmp/docker-helper-release-2.2-workload-selinux-evidence'
PROOF_RESULT='FAIL'

log() {
  printf '%s %s\n' "$PREFIX" "$*"
}

fail() {
  printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2
  exit 1
}

[ -f "$UAT_REPO_DIR/workload_live_proof_test.go" ] \
  || fail "production live proof test not found in checkout: $UAT_REPO_DIR"
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

log 'install live-proof dependencies (bindfs + policy toolchain + docker)'
DEPENDENCY_RESULT="$(vm_ssh 'sudo bash -s' <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# shellcheck source=/dev/null
source /opt/uat-repo-policy.sh
opensuse_zypp_tune_timeouts
opensuse_zypper_refresh
opensuse_zypper install -y bindfs checkpolicy policycoreutils-devel setools-console audit
command -v bindfs >/dev/null 2>&1 || { echo 'missing bindfs' >&2; exit 1; }
command -v checkmodule >/dev/null 2>&1 || { echo 'missing checkmodule' >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo 'missing docker' >&2; exit 1; }
echo "BINDFS_VERSION=$(bindfs --version | head -1)"
echo 'DEPENDENCIES-DONE'
RMT
)"
printf '%s\n' "$DEPENDENCY_RESULT"
printf '%s\n' "$DEPENDENCY_RESULT" | grep -q 'DEPENDENCIES-DONE' \
  || fail 'guest live-proof dependency installation did not complete'

log 'compile and load the authoritative production docker_helper policy'
POLICY_RESULT="$(vm_ssh 'sudo bash -s' <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
rm -rf /tmp/docker-helper-workload-production-policy
mkdir -p /tmp/docker-helper-workload-production-policy
/opt/uat/build-selinux-policy.sh /tmp/docker-helper-workload-production-policy
semodule -i /tmp/docker-helper-workload-production-policy/docker_helper.pp
semodule -l | awk '$1 == "docker_helper" { found=1 } END { exit !found }'
seinfo -t docker_helper_ro_projection_t | grep -q docker_helper_ro_projection_t \
  || { echo 'production policy lacks docker_helper_ro_projection_t' >&2; exit 1; }
seinfo -t docker_helper_bindfs_exec_t | grep -q docker_helper_bindfs_exec_t \
  || { echo 'production policy lacks docker_helper_bindfs_exec_t' >&2; exit 1; }
echo 'PRODUCTION-POLICY-DONE'
RMT
)"
printf '%s\n' "$POLICY_RESULT"
printf '%s\n' "$POLICY_RESULT" | grep -q 'PRODUCTION-POLICY-DONE' \
  || fail 'production docker_helper policy preparation did not complete'

log 'label bindfs for the production projection mechanism'
vm_ssh 'sudo bash -s' <<'RMT'
set -euo pipefail
if command -v restorecon >/dev/null 2>&1; then
  restorecon /usr/bin/bindfs || true
fi
exit 0
RMT

log 'build the exact host proof binary and transfer it'
PROOF_BINARY="$UAT_REPO_DIR/workload-live-proof.test"
( cd "$UAT_REPO_DIR" && go test -c -o "$PROOF_BINARY" -run 'TestLiveWorkload' . ) \
  || fail 'cannot build the production live proof binary'
[ -x "$PROOF_BINARY" ] || fail 'proof binary is not executable'
vm_selinux_transfer_artifact 'workload-live-proof.test' "$PROOF_BINARY" \
  || fail 'cannot transfer the proof binary'

log 'run bounded live workload SELinux proof in the guest'
if vm_ssh "sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    DOCKER_HELPER_LIVE_WORKLOAD_PROOF=1 \
    WORKLOAD_EVIDENCE_DIR='$GUEST_EVIDENCE_DIR' \
    '/opt/uat-import/workload-live-proof.test' -test.run 'TestLiveWorkloadSELinux|TestLiveWorkloadMCSConcurrentRWRO' -test.v"; then
  PROOF_RESULT='PASS'
else
  PROOF_RC=$?
  log "guest live proof failed with exit $PROOF_RC"
fi

if ! collect_guest_evidence; then
  log 'warning: guest evidence directory was unavailable'
fi

{
  printf 'HOST_RESULT=%s\n' "$PROOF_RESULT"
  printf 'VM_IMAGE_SHA256=%s\n' "$VM_IMG_SHA256"
  printf 'VM_ACCEL=%s\n' "$VM_ACCEL"
  printf 'VM_BOOT_TIME=%s\n' "$VM_BOOT_TIME"
  printf 'TESTED_SOURCE=%s\n' "$(git -C "$UAT_REPO_DIR" rev-parse HEAD)"
} >"$EVIDENCE_DIR/host-summary.txt"

[ "$PROOF_RESULT" = 'PASS' ] || fail 'live workload SELinux proof did not close'
log 'live workload SELinux proof CLOSED in canonical enforcing Tumbleweed guest'
