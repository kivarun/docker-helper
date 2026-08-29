#!/usr/bin/env bash
#
# uat-platform-opensuse.sh — openSUSE Tumbleweed platform adapter for the
# docker-helper black-box UAT. Sourced by scripts/uat-blackbox.sh (the
# scenario core) when UAT_PLATFORM=opensuse.
#
# This adapter owns the narrow set of things that actually differ between
# openSUSE and Ubuntu (currently):
#   * distro identity preflight;
#   * native dependency installation (zypper) for the build/test/runtime
#     toolchain, including ensuring the Docker daemon runs;
#   * platform defaults for the runner principal and allowed root (derived
#     from the invoking (sudo) user inside the VM guest).
#
# It does NOT own artifact production, installation, the common scenario, or
# MAC confinement/audit (those are separate adapters). MAC confinement is
# deliberately NOT here — it belongs to the MAC adapter.
#
# This adapter describes an already-working openSUSE Tumbleweed system; making
# the guest one (booting the Tumbleweed Cloud VM and activating the selected
# MAC backend) is owned by the MAC-specific VM orchestration
# (scripts/uat-vm-opensuse-apparmor.sh / scripts/uat-vm-opensuse-selinux.sh).
#
# The scenario core defines: fail_uat. It runs this adapter as root.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-opensuse-repo.sh
source "$SCRIPT_DIR/uat-opensuse-repo.sh"  # canonical openSUSE zypper/repo policy owner

# platform_name prints the platform label used in UAT output.
platform_name() {
  printf 'openSUSE Tumbleweed'
}

# platform_preflight fails unless the host is openSUSE Tumbleweed.
platform_preflight() {
  local id
  id="$(grep -E '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || true)"
  [ "$id" = "opensuse-tumbleweed" ] || fail_uat "not openSUSE Tumbleweed (os-release ID='$id')"
}

# platform_install_deps provisions ONLY the runtime/test/install dependencies
# needed by the openSUSE UAT: Docker/runtime, RPM install, MAC backend tooling
# and the common black-box scenario. Build-only dependencies (musl-gcc,
# checkpolicy, SELinux policy build tools) are deliberately NOT installed here:
# the openSUSE profile consumes a prebuilt RPM produced on the hosted Ubuntu
# build job, so no build toolchain is required on this host.
# apparmor-abstractions provides the #include <tunables/global> and
# <abstractions/base> sources referenced by the shipped docker-helper-system
# profile on openSUSE (apparmor-parser/apparmor-utils alone are insufficient).
# policycoreutils / policycoreutils-python-utils are installed because the RPM
# declares them as runtime Requires for the SELinux backend (see
# packaging/nfpm.yaml); neither is build tooling. Required provisioning steps
# (zypper refresh/install) explicitly propagate failure; the Docker
# enable/start is deliberately best-effort because the common UAT preflight
# will later prove whether Docker actually works.
#
# zypper timeout/retry behavior is owned by uat-opensuse-repo.sh (the single
# canonical owner): connect timeout, attempt count/delay and the rule that a
# failed refresh is a repository/network failure that must not be followed by
# an install against stale/incomplete metadata.
platform_install_deps() {
  opensuse_zypp_tune_timeouts
  opensuse_zypper_refresh || return $?

  opensuse_zypper install -y \
    apparmor-parser apparmor-utils openssl \
    apparmor-abstractions \
    policycoreutils policycoreutils-python-utils \
    tar gzip file curl docker \
    || return $?

  # Best-effort: start Docker if not running. The common UAT preflight will
  # later prove whether Docker is actually reachable.
  systemctl enable --now docker >/dev/null 2>&1 || true

  return 0
}

# platform_default_principal returns the OS user mapped to the docker-helper
# principal when UAT_PRINCIPAL is not set. On a self-hosted runner the invoking
# (sudo) user is the runner user. This function fails if the result would be
# root, since the principal UAT must run as a non-root OS identity.
platform_default_principal() {
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    printf '%s' "$SUDO_USER"
  else
    local current
    current="$(id -un)"
    if [ "$current" = "root" ]; then
      echo "error: cannot derive non-root principal (SUDO_USER unavailable and running as root)" >&2
      return 1
    fi
    printf '%s' "$current"
  fi
}

# platform_default_allowed_root returns the global allowed root when
# UAT_ALLOWED_ROOT is not set: the principal's home directory. This function
# fails if the home directory does not exist, preventing silent manufacture of
# a non-existent path.
platform_default_allowed_root() {
  local p="${1:-}"
  if [ -n "$p" ]; then
    local home
    home="$(getent passwd "$p" 2>/dev/null | cut -d: -f6)"
    if [ -n "$home" ] && [ -d "$home" ]; then
      printf '%s' "$home"
      return
    fi
  fi
  echo "error: cannot determine allowed root for principal '$p' (home directory not found)" >&2
  return 1
}
