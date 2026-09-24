#!/usr/bin/env bash
#
# Release 2.4 P4-A1 guest-side bootstrap for openSUSE Tumbleweed.
#
# Installs the PRODUCTION composition prerequisites inside the guest and
# runs the distro-agnostic P4-A1 unit-boundary proof:
#   - distro rootlesskit + slirp4netns (zypper; NOT a product copy),
#   - the PINNED upstream BuildKit v0.33.0 payload (SHA-256 verified
#     against the repo pin) at the product paths
#     /usr/libexec/docker-helper/buildkit/{buildkitd,buildctl,buildkit-runc}
#     — the distro buildkit RPM is deliberately NOT used (plan §7),
#   - the real docker-helper binary (built from the proof commit on the
#     host) installed to /usr/bin/docker-helper,
#   - identity + subuid/subgid through the REAL provision-builder.sh,
#   - the proposed docker-helper-builder.service unit, then the proof.
#
# Runs as root inside the guest. Files transferred by the host-side
# orchestrator (scripts/release-2.4-p4a1-tw-vm.sh) into /tmp/p4a1/.

set -Eeuo pipefail

PREFIX='[release-2.4-p4a1-tw]'
say() { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

log() { echo "[guest] $*"; }

GUEST_FILES=/tmp/p4a1
EVIDENCE_DIR=/tmp/release-2.4-p4a1-tw-evidence
BUILDKIT_VERSION=v0.33.0
# Pinned digest: verified against the official release SBOM subject
# (buildkit-v0.33.0.linux-amd64.sbom.json -> digest.sha256); no plain
# .sha256 sidecar exists upstream. The same pin the packaging pipeline
# will carry (plan §7).
BUILDKIT_SHA256=b6242896d343100808dcbe37565caf381e0a444a6a83d7255926bb1519248ead

for f in "$GUEST_FILES/docker-helper" "$GUEST_FILES/docker-helper-builder.service" \
  "$GUEST_FILES/provision-builder.sh" "$GUEST_FILES/release-2.4-p4a1-proof.sh"; do
  [ -f "$f" ] || fail "missing transferred file: $f"
done

log "install distro rootlesskit + slirp4netns (zypper)"
zypper --non-interactive --gpg-auto-import-keys refresh >/dev/null 2>&1 || true
zypper --non-interactive install -y rootlesskit slirp4netns shadow >/dev/null
for b in rootlesskit slirp4netns newuidmap newgidmap useradd usermod python3 curl tar; do
  command -v "$b" >/dev/null 2>&1 || { echo "missing after install: $b" >&2; exit 1; }
done
rootlesskit --version
slirp4netns --version

log "install the pinned BuildKit payload at the product paths"
curl -fsSL -o /tmp/p4a1/buildkit.tgz \
  "https://github.com/moby/buildkit/releases/download/${BUILDKIT_VERSION}/buildkit-${BUILDKIT_VERSION}.linux-amd64.tar.gz"
ACTUAL_SHA256="$(sha256sum /tmp/p4a1/buildkit.tgz | awk '{print $1}')"
if [ "$ACTUAL_SHA256" != "$BUILDKIT_SHA256" ]; then
  echo "BuildKit tarball SHA256 mismatch: expected $BUILDKIT_SHA256, got $ACTUAL_SHA256" >&2
  exit 1
fi
echo "BuildKit tarball SHA256 verified: $ACTUAL_SHA256"
install -d -m 0755 /usr/libexec/docker-helper/buildkit
install -d -m 0755 /tmp/p4a1/buildkit-extract
tar -xzf /tmp/p4a1/buildkit.tgz -C /tmp/p4a1/buildkit-extract
install -m 0755 /tmp/p4a1/buildkit-extract/bin/buildkitd /usr/libexec/docker-helper/buildkit/buildkitd
install -m 0755 /tmp/p4a1/buildkit-extract/bin/buildctl /usr/libexec/docker-helper/buildkit/buildctl
install -m 0755 /tmp/p4a1/buildkit-extract/bin/buildkit-runc /usr/libexec/docker-helper/buildkit/buildkit-runc
/usr/libexec/docker-helper/buildkit/buildkitd --version
/usr/libexec/docker-helper/buildkit/buildctl --version

log "install the real docker-helper binary (built from the proof commit)"
install -m 0755 "$GUEST_FILES/docker-helper" /usr/bin/docker-helper
/usr/bin/docker-helper version || true

log "run the P4-A1 production unit-boundary proof"
P4A1_EVIDENCE_DIR="$EVIDENCE_DIR" \
P4A1_PROVISION_SCRIPT="$GUEST_FILES/provision-builder.sh" \
P4A1_UNIT_FILE="$GUEST_FILES/docker-helper-builder.service" \
  bash "$GUEST_FILES/release-2.4-p4a1-proof.sh"
