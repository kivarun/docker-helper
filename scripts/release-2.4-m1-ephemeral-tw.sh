#!/usr/bin/env bash
#
# Release 2.4 M1 guest-side bootstrap for openSUSE Tumbleweed.
#
# Installs the composition prerequisites from the Tumbleweed repos and runs
# the same M1 ephemeral-instance probe inside the guest. Runs as root.
#
# M1 probe only.

set -Eeuo pipefail

PREFIX='[release-2.4-m1-tw]'
say() { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

log(){ echo "[guest] $*"; }

log "install docker + M1 probe prerequisites"
zypper --non-interactive --gpg-auto-import-keys refresh >/dev/null 2>&1 || true
zypper --non-interactive install -y docker rootlesskit slirp4netns buildkit fuse-overlayfs
systemctl enable --now docker >/dev/null 2>&1 || systemctl start docker || true
for b in rootlesskit slirp4netns buildkitd buildctl newuidmap newgidmap docker python3 openssl; do
  command -v "$b" >/dev/null 2>&1 || { echo "missing after install: $b" >&2; exit 1; }
done

log "create dedicated builder identity"
useradd -m -s /usr/sbin/nologin dhm0builder 2>/dev/null || true
grep -q '^dhm0builder:' /etc/subuid || echo 'dhm0builder:231072:65536' >> /etc/subuid
grep -q '^dhm0builder:' /etc/subgid || echo 'dhm0builder:231072:65536' >> /etc/subgid

chmod +x /tmp/release-2.4-m1-ephemeral-proof.sh
log "run the M1 ephemeral probe"
M1_EVIDENCE_DIR=/tmp/release-2.4-m1-tw-evidence bash /tmp/release-2.4-m1-ephemeral-proof.sh
