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
#     from the invoking runner user on a self-hosted VM).
#
# It does NOT own artifact production, installation, the common scenario, or
# MAC confinement/audit (those are separate adapters). AppArmor confinement is
# deliberately NOT here — it belongs to the MAC adapter.
#
# NOTE: This profile requires a real openSUSE Tumbleweed VM/kernel with
# AppArmor active. It is NOT validated yet — the repository has no such
# self-hosted runner registered. Package names below are the expected openSUSE
# equivalents and must be confirmed on a real runner.
#
# The scenario core defines: fail_uat. It runs this adapter as root.

# platform_name prints the platform label used in UAT output.
platform_name() {
  printf 'openSUSE Tumbleweed'
}

# platform_preflight fails unless the host matches this platform and AppArmor
# is the active/expected configuration (AppArmor readiness itself is the MAC
# adapter's job; here we only pin the distribution identity).
platform_preflight() {
  local id
  id="$(grep -E '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || true)"
  case "$id" in
    opensuse-tumbleweed|opensuse)
      ;;
    *)
      fail_uat "not openSUSE (os-release ID='$id')"
      ;;
  esac
}

# platform_install_deps installs the build/test/runtime toolchain via the
# native package manager (zypper) and ensures the Docker daemon is running.
platform_install_deps() {
  zypper --non-interactive refresh || true
  zypper --non-interactive install -y \
    musl-gcc checkpolicy policycoreutils \
    apparmor-parser apparmor-utils openssl \
    tar gzip file curl docker
  systemctl enable --now docker >/dev/null 2>&1 || true
}

# platform_default_principal returns the OS user mapped to the docker-helper
# principal when UAT_PRINCIPAL is not set. On a self-hosted runner the invoking
# (sudo) user is the runner user.
platform_default_principal() {
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    printf '%s' "$SUDO_USER"
  else
    printf '%s' "$(id -un)"
  fi
}

# platform_default_allowed_root returns the global allowed root when
# UAT_ALLOWED_ROOT is not set: the principal's home directory.
platform_default_allowed_root() {
  local p="${1:-}"
  if [ -n "$p" ]; then
    local home
    home="$(getent passwd "$p" 2>/dev/null | cut -d: -f6)"
    if [ -n "$home" ]; then
      printf '%s' "$home"
      return
    fi
  fi
  printf '/home/%s' "${p:-runner}"
}
