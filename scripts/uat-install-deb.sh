#!/usr/bin/env bash
#
# uat-install-deb.sh — Debian-package install adapter for the docker-helper
# black-box UAT. Sourced by scripts/uat-blackbox.sh (the scenario core) when
# UAT_INSTALL=deb.
#
# This adapter owns INSTALLATION of an already-produced .deb artifact and
# proving the installed files came from it. It never builds the artifact
# (that is the artifact adapter's job: uat-artifact-deb.sh).
#
#   * install_preflight       — install-time tooling present (dpkg);
#   * install_apply           — verify the recorded artifact hash, dpkg -i, then
#                               init, daemon-reload, enable+start;
#   * install_verify_artifacts— dpkg ownership of binary, systemd unit, AppArmor
#                               profile (proves the package install path);
#   * install_verify_version  — installed /usr/bin/docker-helper version matches.
#
# It consumes the exact artifact recorded by the artifact adapter
# (ARTIFACT_PATH / ARTIFACT_SHA256) and never rebuilds it.
#
# It does NOT own the generic functional scenario (that is the core) nor the
# MAC confinement/audit checks (that is the MAC adapter).
#
# The core defines: VERSION, ALLOWED_ROOT, REPO_ROOT, say, info, fail_uat,
# fail_uat_status, redact_tokens.

# install_name prints the install adapter label used in UAT output.
install_name() {
  printf 'Debian package (.deb)'
}

# install_preflight fails unless the install-time tooling is present. Build
# tooling is owned by the artifact adapter.
install_preflight() {
  if ! command -v dpkg >/dev/null 2>&1; then
    fail_uat "dpkg not found"
  fi
}

# install_apply installs the exact recorded .deb and initializes/starts the
# confined system service. The admin token emitted by init is captured and
# redacted so it never reaches the CI log; on failure the init exit status is
# preserved.
install_apply() {
  [ -n "$ARTIFACT_PATH" ] || fail_uat "no .deb artifact recorded (artifact_build must run first)"
  [ -f "$ARTIFACT_PATH" ] || fail_uat "recorded .deb missing: $ARTIFACT_PATH"

  # Re-assert the exact-byte identity recorded at production time.
  local now_sha
  now_sha="$(sha256sum "$ARTIFACT_PATH" | awk '{print $1}')"
  [ "$now_sha" = "$ARTIFACT_SHA256" ] \
    || fail_uat ".deb changed since build (expected $ARTIFACT_SHA256, got $now_sha)"

  info "installing $ARTIFACT_PATH"
  dpkg -i "$ARTIFACT_PATH" || fail_uat "dpkg -i failed"

  # System init writes config + admin token (root reads admin.token later).
  say "phase 2: initialize and start the confined system service"
  [ -d "$ALLOWED_ROOT" ] || fail_uat "allowed root does not exist: $ALLOWED_ROOT"
  INIT_OUT="$(docker-helper init --allowed-root "$ALLOWED_ROOT" 2>&1)"
  INIT_EC=$?
  if [ "$INIT_EC" -ne 0 ]; then
    printf '%s\n' "$INIT_OUT" | redact_tokens >&2
    fail_uat_status "docker-helper init failed" "$INIT_EC"
  fi

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
