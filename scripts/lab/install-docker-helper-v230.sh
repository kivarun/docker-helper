#!/usr/bin/env bash
#
# install-docker-helper-v230.sh — reproducibly install Docker Helper v2.3.0
# (commit dcb886f0) INSIDE the lab VM, from the pinned release artifact, and
# leave it running as the systemd service.
#
# Why the release tarball and not a local build: the tarball is the published,
# checksum-verifiable artifact whose binary and SELinux policy are byte-fixed.
# Pinning its sha256 makes "which build is installed" auditable, so a later
# `main` build cannot silently substitute for the target version.
#
# Run as root in the guest. Needs network for the initial download (and for
# `bindfs` if it is missing); the isolated posture is restored afterwards by
# the caller.
#
# It uses the tarball's OWN install-system.sh (the canonical installer), never
# a re-implementation: that installer selects the MAC backend, loads the
# bundled policy, relabels narrowly, installs the systemd unit and starts the
# service.
#
# Env overrides: DH_V230_URL, DH_V230_SHA256, DH_V230_VERSION, DH_V230_COMMIT.
set -euo pipefail

DH_V230_VERSION="${DH_V230_VERSION:-2.3.0}"
DH_V230_COMMIT="${DH_V230_COMMIT:-dcb886f09ad5c09b18a4083f82331e2205cc3177}"
DH_V230_SHA256="${DH_V230_SHA256:-e2a24a7d01025a9d1269b8edbea7a2d94607efec08a06f5a93935b20d141a0f1}"
DH_V230_URL="${DH_V230_URL:-https://github.com/kivarun/docker-helper/releases/download/v${DH_V230_VERSION}/docker-helper-${DH_V230_VERSION}-linux-amd64.tar.gz}"

log() { printf '[install-dh-v%s] %s\n' "$DH_V230_VERSION" "$*"; }
die() { printf '[install-dh-v%s] ERROR: %s\n' "$DH_V230_VERSION" "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root in the guest"
command -v systemctl >/dev/null 2>&1 || die "systemctl not found"
[ "$(cat /sys/fs/selinux/enforce 2>/dev/null || echo 0)" = 1 ] || die "SELinux is not enforcing"

# bindfs is a hard dependency of the installer's SELinux path (read-only
# workload projection). Install it if missing; that needs the network.
if ! command -v bindfs >/dev/null 2>&1; then
  log "installing missing dependency: bindfs"
  zypper --non-interactive --no-gpg-checks install bindfs || die "could not install bindfs (network open?)"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

log "downloading $DH_V230_URL"
curl -fsSL --retry 3 -o "$work/bundle.tgz" "$DH_V230_URL"
echo "${DH_V230_SHA256}  ${work}/bundle.tgz" | sha256sum -c - >/dev/null \
  || die "release artifact sha256 mismatch"
log "artifact sha256 verified: $DH_V230_SHA256"

tar -xzf "$work/bundle.tgz" -C "$work"
root="$work/docker-helper-${DH_V230_VERSION}-linux-amd64"
[ -x "$root/install-system.sh" ] || die "release tarball missing install-system.sh"

# Stop the ad-hoc daemon if a previous integration started one, and remove the
# /usr/local/bin copy so the canonical /usr/bin/docker-helper (and the unit's
# ExecStart=/usr/bin/docker-helper) is the only installed binary.
pkill -x docker-helper 2>/dev/null || true
systemctl stop docker-helper 2>/dev/null || true
sleep 1
rm -f /usr/local/bin/docker-helper

log "running the tarball's canonical install-system.sh --yes"
( cd "$root" && ./install-system.sh --yes )

# The unit's StateDirectory=docker-helper makes systemd chmod/chown
# /var/lib/docker-helper to StateDirectoryMode (0700) on start. When the dir
# already exists at another mode (e.g. left by an earlier ad-hoc daemon at
# 0755), systemd's setattr under SELinux fails: the shipped policy grants
# init_t create/write/remove on docker_helper_state_t but not setattr, so the
# unit exits 238/STATE_DIRECTORY. Normalize the mode first, then restart.
install -d -m 0700 -o root -g root /var/lib/docker-helper
systemctl reset-failed docker-helper 2>/dev/null || true
systemctl restart docker-helper

# Evidence: the installed binary must be exactly the pinned version.
installed_sha="$(sha256sum /usr/bin/docker-helper | awk '{print $1}')"
installed_ver="$(/usr/bin/docker-helper version)"
[ "$installed_ver" = "$DH_V230_VERSION" ] || die "installed version '$installed_ver' != $DH_V230_VERSION"
[ -x /usr/bin/docker-helper ] || die "binary not installed at /usr/bin/docker-helper"
[ ! -e /usr/local/bin/docker-helper ] || die "/usr/local/bin/docker-helper still shadows /usr/bin"

systemctl is-active --quiet docker-helper || die "docker-helper service is not active"

log "installed version: $installed_ver (source commit $DH_V230_COMMIT)"
log "installed binary sha256: $installed_sha"
log "installed SELinux module: $(semodule -l | awk '/^docker_helper/ {print $1, $2}')"
log "daemon SELinux context: $(ps -o label= -C docker-helper | head -1)"
log "binary SELinux type: $(ls -Z /usr/bin/docker-helper | awk '{print $1}')"
log "done"
