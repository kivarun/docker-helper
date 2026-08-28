#!/usr/bin/env bash
#
# uat-install-tarball.sh — release-tar.gz install adapter for the docker-helper
# black-box UAT. Sourced by scripts/uat-blackbox.sh (the scenario core) when
# UAT_INSTALL=tarball.
#
# This adapter owns INSTALLATION of an already-produced release tar.gz via the
# shipped install-system.sh path, and proving the installed files came from
# that exact artifact. It never builds the artifact (that is the artifact
# adapter's job: uat-artifact-tarball.sh).
#
#   * install_preflight       — install-time tooling present (tar, gzip);
#   * install_apply           — verify the recorded artifact hash, extract the
#                               EXACT artifact, verify it, then run
#                               ./install-system.sh --yes --allowed-root <root>
#                               non-interactively (init is part of that path);
#   * install_verify_artifacts— installed /usr/bin/docker-helper, systemd unit and
#                               AppArmor profile byte-match the extracted bundle,
#                               and no package manager owns them;
#   * install_verify_version  — installed /usr/bin/docker-helper version matches.
#
# It consumes the exact artifact recorded by the artifact adapter
# (ARTIFACT_PATH / ARTIFACT_SHA256) and never rebuilds it.
#
# The core runs as root (id -u == 0), so install-system.sh is invoked directly
# — the equivalent of the documented `sudo ./install-system.sh`.
#
# The core defines: VERSION, ALLOWED_ROOT, REPO_ROOT, say, info, fail_uat,
# fail_uat_status, redact_tokens.

# Module-level state shared between the install steps.
BUNDLE_DIR=""

# install_name prints the install adapter label used in UAT output.
install_name() {
  printf 'release tarball (tar.gz)'
}

# install_preflight fails unless the install-time tooling is present. Build
# tooling is owned by the artifact adapter.
install_preflight() {
  if ! command -v tar >/dev/null 2>&1; then
    fail_uat "tar not found"
  fi
  if ! command -v gzip >/dev/null 2>&1; then
    fail_uat "gzip not found"
  fi
}

# install_apply extracts the exact recorded artifact, runs the tarball-specific
# pre-install checks, then installs system mode non-interactively. installer
# output is captured and redacted so the admin token (printed by init inside
# install-system.sh --yes) never reaches the CI log; on failure the installer's
# exact exit status is preserved while masked diagnostics are printed.
install_apply() {
  [ -n "$ARTIFACT_PATH" ] || fail_uat "no tarball artifact recorded (artifact_build must run first)"
  [ -f "$ARTIFACT_PATH" ] || fail_uat "release tarball missing: $ARTIFACT_PATH"

  # Re-assert the exact-byte identity recorded at production time.
  local now_sha
  now_sha="$(sha256sum "$ARTIFACT_PATH" | awk '{print $1}')"
  [ "$now_sha" = "$ARTIFACT_SHA256" ] \
    || fail_uat "tarball changed since build (expected $ARTIFACT_SHA256, got $now_sha)"

  local extract_root
  extract_root="$(mktemp -d /tmp/uat-bundle.XXXXXX)" \
    || fail_uat "could not create bundle extract directory"
  BUNDLE_DIR="$extract_root/docker-helper-${VERSION}-linux-amd64"

  # 1. The archive must extract successfully.
  tar xzf "$ARTIFACT_PATH" -C "$extract_root" \
    || fail_uat "tar extraction of $ARTIFACT_PATH failed"

  # 2. The expected top-level directory must exist.
  [ -d "$BUNDLE_DIR" ] \
    || fail_uat "expected top-level bundle directory missing: $BUNDLE_DIR"

  # 3. install-system.sh must be executable in the bundle.
  [ -x "$BUNDLE_DIR/install-system.sh" ] \
    || fail_uat "install-system.sh is not executable in the bundle"

  # 4. The bundled binary must report the expected version BEFORE installation.
  local bundle_ver
  bundle_ver="$("$BUNDLE_DIR/docker-helper" version 2>/dev/null || true)"
  [ "$bundle_ver" = "$VERSION" ] \
    || fail_uat "bundle binary version mismatch: got '$bundle_ver', expected '$VERSION'"

  # 5. Non-interactive system-mode install from the extracted bundle. init is
  #    performed inside install-system.sh --yes (the real user path).
  say "phase 2: install-system.sh --yes (system mode) from extracted bundle"
  [ -d "$ALLOWED_ROOT" ] || fail_uat "allowed root does not exist: $ALLOWED_ROOT"
  INSTALL_OUT="$( (cd "$BUNDLE_DIR" && ./install-system.sh --yes --allowed-root "$ALLOWED_ROOT") 2>&1 )"
  INSTALL_EC=$?
  if [ "$INSTALL_EC" -ne 0 ]; then
    printf '%s\n' "$INSTALL_OUT" | redact_tokens >&2
    fail_uat_status "install-system.sh failed" "$INSTALL_EC"
  fi
  # On success, show the installer progress with bearer tokens redacted.
  printf '%s\n' "$INSTALL_OUT" | redact_tokens
}

# install_verify_artifacts proves the installed binary/unit/profile came from
# the extracted bundle and that no package-manager install was involved.
install_verify_artifacts() {
  [ -n "$BUNDLE_DIR" ] && [ -d "$BUNDLE_DIR" ] \
    || fail_uat "bundle directory not recorded for artifact verification"

  cmp -s /usr/bin/docker-helper "$BUNDLE_DIR/docker-helper" \
    || fail_uat "installed /usr/bin/docker-helper does not match the bundle binary"
  cmp -s /etc/systemd/system/docker-helper.service "$BUNDLE_DIR/systemd/system/docker-helper.service" \
    || fail_uat "installed systemd unit does not match the bundle unit"
  cmp -s /etc/apparmor.d/docker-helper-system "$BUNDLE_DIR/apparmor/docker-helper-system" \
    || fail_uat "installed AppArmor profile does not match the bundle profile"

  # No package-manager install may be used for this case: if any package owns
  # the installed paths, the tarball path was not the actual install source.
  if dpkg -S /usr/bin/docker-helper >/dev/null 2>&1; then
    fail_uat "/usr/bin/docker-helper is owned by a package — tarball case must not use a package manager"
  fi
  if dpkg -S /etc/systemd/system/docker-helper.service >/dev/null 2>&1; then
    fail_uat "installed unit is owned by a package — tarball case must not use a package manager"
  fi
  if dpkg -S /etc/apparmor.d/docker-helper-system >/dev/null 2>&1; then
    fail_uat "installed AppArmor profile is owned by a package — tarball case must not use a package manager"
  fi
  info "installed binary/unit/profile match the extracted bundle (no package manager)"
}

# install_verify_version fails unless the installed binary reports the exact
# artifact version.
install_verify_version() {
  [ "$(/usr/bin/docker-helper version)" = "$VERSION" ] \
    || fail_uat "installed binary version mismatch (expected $VERSION)"
}
