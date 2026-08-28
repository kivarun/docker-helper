#!/usr/bin/env bash
#
# uat-install-deb.sh — Debian-package install backend for the docker-helper
# black-box UAT. Sourced by scripts/uat-blackbox.sh (the install-agnostic
# core) when UAT_INSTALL=deb.
#
# This layer owns everything that is specific to producing and installing the
# Debian package artifact and proving the installed files came from it:
#   * install_preflight       — build tooling present (nfpm, SELinux module tools);
#   * install_build           — one upstream build step producing dist/*.deb;
#   * install_install         — dpkg -i, then init, daemon-reload, enable+start;
#   * install_verify_artifacts— dpkg ownership of binary, systemd unit, AppArmor
#                               profile (proves the package install path);
#   * install_verify_version  — installed /usr/bin/docker-helper version matches.
#
# It does NOT own the generic functional scenario (that is the core) nor the
# MAC confinement/audit checks (that is the MAC backend layer).
#
# The core defines: VERSION, ALLOWED_ROOT, REPO_ROOT, say, info, fail_uat.

# install_name prints the install backend label used in UAT output.
install_name() {
  printf 'Debian package (.deb)'
}

# install_preflight fails unless the build/install tooling for this backend is
# present.
install_preflight() {
  if ! command -v nfpm >/dev/null 2>&1; then
    fail_uat "nfpm not found on PATH (the workflow must install the pinned nfpm)"
  fi
  # build-packages.sh also builds the SELinux policy module (checkmodule +
  # semodule_package), so those tools are required on the build host.
  if ! command -v checkmodule >/dev/null 2>&1; then
    fail_uat "checkmodule not found (build-packages.sh builds the SELinux module)"
  fi
  if ! command -v semodule_package >/dev/null 2>&1; then
    fail_uat "semodule_package not found (build-packages.sh builds the SELinux module)"
  fi
}

# install_build produces the Debian package via the repository packaging path
# (one upstream build step; the artifact is not rebuilt downstream).
install_build() {
  rm -rf dist
  ./build-packages.sh "$VERSION" || fail_uat "./build-packages.sh $VERSION failed"
  DEB="$(ls dist/*.deb 2>/dev/null | head -1)"
  [ -n "$DEB" ] || fail_uat "no .deb produced under dist/"
  info "built $DEB"
}

# install_install performs the actual system-mode installation from the
# artifact, including the init step that is part of this install path.
install_install() {
  local deb
  deb="$(ls dist/*.deb 2>/dev/null | head -1)"
  [ -n "$deb" ] || fail_uat "no .deb produced under dist/"

  info "installing $deb"
  dpkg -i "$deb" || fail_uat "dpkg -i failed"

  # System init writes config + admin token (root reads admin.token later).
  say "phase 2: initialize and start the confined system service"
  [ -d "$ALLOWED_ROOT" ] || fail_uat "allowed root does not exist: $ALLOWED_ROOT"
  INIT_OUT="$(docker-helper init --allowed-root "$ALLOWED_ROOT" 2>&1)" || {
    printf '%s\n' "$INIT_OUT" | grep -v -E '^Admin token:|^dht_' >&2
    fail_uat "docker-helper init failed"
  }

  systemctl daemon-reload || fail_uat "systemctl daemon-reload failed"
  systemctl enable --now docker-helper.service || fail_uat "systemctl enable --now docker-helper failed"
}

# install_verify_artifacts proves the installed binary/unit/profile came from
# the Debian package install path (dpkg ownership).
install_verify_artifacts() {
  dpkg -S /usr/bin/docker-helper >/dev/null 2>&1 \
    || fail_uat "/usr/bin/docker-helper is not owned by the docker-helper package"
  dpkg -S /usr/lib/systemd/system/docker-helper.service >/dev/null 2>&1 \
    || fail_uat "systemd unit is not owned by the docker-helper package"
  dpkg -S /etc/apparmor.d/docker-helper-system >/dev/null 2>&1 \
    || fail_uat "AppArmor profile is not owned by the docker-helper package"
}

# install_verify_version fails unless the installed binary reports the exact
# artifact version.
install_verify_version() {
  [ "$(/usr/bin/docker-helper version)" = "$VERSION" ] \
    || fail_uat "installed binary version mismatch (expected $VERSION)"
}
