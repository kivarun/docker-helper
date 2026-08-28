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

# platform_preflight fails unless the host is openSUSE Tumbleweed.
platform_preflight() {
  local id
  id="$(grep -E '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || true)"
  [ "$id" = "opensuse-tumbleweed" ] || fail_uat "not openSUSE Tumbleweed (os-release ID='$id')"
}

# platform_install_deps installs the build/test/runtime toolchain via the
# native package manager (zypper) and ensures the Docker daemon is running.
# Required provisioning steps (zypper refresh/install) explicitly propagate
# failure; the Docker enable/start is deliberately best-effort because the
# common UAT preflight will later prove whether Docker actually works.
platform_install_deps() {
  zypper --non-interactive refresh || return $?

  zypper --non-interactive install -y \
    musl-gcc checkpolicy policycoreutils \
    apparmor-parser apparmor-utils openssl \
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
