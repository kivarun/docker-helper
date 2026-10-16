#!/usr/bin/env bash
#
# uat-platform-ubuntu.sh — Ubuntu platform adapter for the docker-helper
# black-box UAT. Sourced by scripts/uat-blackbox.sh (the scenario core) when
# UAT_PLATFORM=ubuntu.
#
# This adapter owns the narrow set of things that actually differ between
# Ubuntu and other UAT platforms (currently openSUSE Tumbleweed):
#   * distro identity preflight;
#   * native dependency installation (apt) for the build/test toolchain;
#   * platform defaults for the runner principal and allowed root.
#
# It does NOT own artifact production, installation, the common scenario, or
# MAC confinement/audit (those are separate adapters).
#
# The scenario core defines: fail_uat. It runs this adapter as root.

# platform_name prints the platform label used in UAT output.
platform_name() {
  printf 'Ubuntu'
}

# platform_preflight fails unless the host matches this platform.
platform_preflight() {
  local id
  id="$(grep -E '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || true)"
  [ "$id" = "ubuntu" ] || fail_uat "not Ubuntu (os-release ID='$id')"
}

# platform_install_deps installs the build/test toolchain via the native
# package manager AND the packaged runtime dependency contract of the builder
# backend. Used by the workflow's install-deps provisioning step.
#
# The builder backend runtime trio (rootlesskit, slirp4netns, uidmap) mirrors
# the candidate's declared runtime dependencies (packaging/nfpm.yaml deb
# depends: the distro-owned rootless build backend the bundled BuildKit
# payload drives — the P5AA AppArmor parity UAT installs the same trio; see
# scripts/test-uat-platform-dependency-parity.sh, which fails when the
# packaged contract and this provisioning drift apart). Without them the DEB
# consumers cannot dpkg-install the candidate and the tarball consumers cannot
# start the builder at all.
platform_install_deps() {
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    musl-tools checkpolicy semodule-utils apparmor-utils openssl \
    tar gzip file curl \
    rootlesskit slirp4netns uidmap
}

# platform_default_principal returns the OS user mapped to the docker-helper
# principal when UAT_PRINCIPAL is not set. On the hosted Ubuntu runner this is
# the `runner` user.
platform_default_principal() {
  printf 'runner'
}

# platform_default_allowed_root returns the global allowed root when
# UAT_ALLOWED_ROOT is not set.
platform_default_allowed_root() {
  printf '/home/runner'
}
