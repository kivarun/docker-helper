#!/usr/bin/env bash
#
# Host-side Release 2.4 M0 openSUSE/Tumbleweed probe orchestrator.
#
# Reuses the canonical Tumbleweed VM harness (scripts/uat-vm-tumbleweed.sh)
# to boot the official openSUSE Tumbleweed Cloud qcow2 on a GitHub-hosted
# runner, installs the composition-A prerequisites inside the guest
# (distro rootlesskit / slirp4netns / buildkit / uidmap packages from the
# openSUSE Tumbleweed repos, docker from the standard repos), creates the
# dedicated builder identity, and runs the same guest-side probe as the
# Ubuntu runner proof.
#
# M0 probe only: no docker-helper product behavior, no RPM/policy install.

set -Eeuo pipefail

PREFIX='[release-2.4-m0-tw-vm]'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
EVIDENCE_DIR="${M0_EVIDENCE_DIR:-/tmp/release-2.4-m0-tw-evidence}"
GUEST_EVIDENCE_DIR='/tmp/release-2.4-m0-tw-evidence'

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

log 'transfer the probe script into the guest'
vm_scp "$SCRIPT_DIR/release-2.4-m0-buildkit-tw.sh" opc@127.0.0.1:/tmp/release-2.4-m0-buildkit-tw.sh

log 'install guest prerequisites (distro packages + docker) and run the probe'
PROBE_OUT="$(vm_ssh 'sudo bash -s' <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive

log(){ echo "[guest] $*"; }

tune_zypper() {
  zypper --non-interactive --gpg-auto-import-keys refresh 2>/dev/null || true
}

# docker is NOT present in the Minimal-VM cloud image; install it (this is
# also what the UAT platform adapter does: `zypper install -y docker`).
log "install docker + M0 probe prerequisites"
zypper --non-interactive --gpg-auto-import-keys refresh >/dev/null 2>&1 || true
zypper --non-interactive install -y docker rootlesskit slirp4netns buildkit fuse-overlayfs
systemctl enable --now docker >/dev/null 2>&1 || systemctl start docker || true
# shadow provides newuidmap/newgidmap; containerd/runc come with the docker
# stack. Verify every required binary:
for b in rootlesskit slirp4netns buildkitd buildctl newuidmap newgidmap docker; do
  command -v "$b" >/dev/null 2>&1 || { echo "missing after install: $b" >&2; exit 1; }
done

log "create dedicated builder identity"
useradd -m -s /usr/sbin/nologin dhm0builder 2>/dev/null || true
grep -q '^dhm0builder:' /etc/subuid || echo 'dhm0builder:231072:65536' >> /etc/subuid
grep -q '^dhm0builder:' /etc/subgid || echo 'dhm0builder:231072:65536' >> /etc/subgid

chmod +x /tmp/release-2.4-m0-buildkit-tw.sh
log "run the guest probe"
bash /tmp/release-2.4-m0-buildkit-tw.sh
RMT
)"
printf '%s\n' "$PROBE_OUT"

printf '%s\n' "$PROBE_OUT" | grep -q "M0-TW-PROOF-RESULT=PASS" || fail "guest probe did not report PASS"

log 'collect guest evidence'
mkdir -p "$EVIDENCE_DIR"
if vm_ssh "test -d '$GUEST_EVIDENCE_DIR'" 2>/dev/null; then
  vm_ssh "tar -C '$GUEST_EVIDENCE_DIR' -czf - ." > "$EVIDENCE_DIR/guest-evidence.tar.gz" || true
  mkdir -p "$EVIDENCE_DIR/guest"
  tar -xzf "$EVIDENCE_DIR/guest-evidence.tar.gz" -C "$EVIDENCE_DIR/guest" 2>/dev/null || true
fi

log 'openSUSE Tumbleweed composition-A proof PASSED'
