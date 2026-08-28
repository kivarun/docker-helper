#!/usr/bin/env bash
#
# uat-install-tarball.sh — release-tar.gz system-mode install backend for the
# docker-helper black-box UAT. Sourced by scripts/uat-blackbox.sh (the
# install-agnostic core) when UAT_INSTALL=tarball-system.
#
# This layer owns everything that is specific to producing and installing the
# release tarball artifact via the shipped install-system.sh path, and proving
# the installed files came from that exact artifact:
#   * install_preflight       — tooling present (tar, gzip, file for static check);
#   * install_build           — one upstream build step (build-bundle.sh VERSION)
#                               producing dist/docker-helper-<ver>-linux-amd64.tar.gz;
#   * install_install         — extract the EXACT artifact, verify it, then run
#                               ./install-system.sh --yes --allowed-root <root>
#                               non-interactively (init is part of that path);
#   * install_verify_artifacts— installed /usr/bin/docker-helper, systemd unit and
#                               AppArmor profile byte-match the extracted bundle,
#                               and no package manager owns them;
#   * install_verify_version  — installed /usr/bin/docker-helper version matches.
#
# Release-artifact discipline: build-bundle.sh is the single upstream build
# step; the tarball is built once here and the EXACT file (same path, same
# SHA-256) is what install-system.sh consumes. It is never rebuilt downstream.
# Within this single job there is no cross-step transfer, so the hash recorded
# at build time is re-asserted against the file that is installed.
#
# The core defines: VERSION, ALLOWED_ROOT, REPO_ROOT, say, info, fail_uat.
# The core also runs as root (id -u == 0), so install-system.sh is invoked
# directly — the equivalent of the documented `sudo ./install-system.sh`.

# Module-level state shared between the install steps.
TARBALL=""
TARBALL_SHA256=""
BUNDLE_DIR=""

# install_name prints the install backend label used in UAT output.
install_name() {
  printf 'release tarball (tar.gz) system install'
}

# install_preflight fails unless the tooling for this backend is present.
install_preflight() {
  if ! command -v tar >/dev/null 2>&1; then
    fail_uat "tar not found"
  fi
  if ! command -v gzip >/dev/null 2>&1; then
    fail_uat "gzip not found"
  fi
  # build-bundle.sh requires `file` to confirm static linking.
  if ! command -v file >/dev/null 2>&1; then
    fail_uat "file not found (build-bundle.sh confirms static linking)"
  fi
  if ! command -v sha256sum >/dev/null 2>&1; then
    fail_uat "sha256sum not found"
  fi
}

# install_build produces the release tarball via the single upstream build step
# and records its SHA-256 for exact-byte accountability.
install_build() {
  rm -rf dist
  ./build-bundle.sh "$VERSION" || fail_uat "./build-bundle.sh $VERSION failed"

  TARBALL="dist/docker-helper-${VERSION}-linux-amd64.tar.gz"
  [ -f "$TARBALL" ] || fail_uat "release tarball not produced: $TARBALL"
  TARBALL_SHA256="$(sha256sum "$TARBALL" | awk '{print $1}')"
  [ -n "$TARBALL_SHA256" ] || fail_uat "could not compute tarball SHA-256"
  info "tarball: $TARBALL"
  info "sha256:  $TARBALL_SHA256"
}

# install_install extracts the exact artifact, runs the tarball-specific
# pre-install checks, then installs system mode non-interactively. Any installer
# failure aborts the UAT immediately via fail_uat (which preserves the failure
# status while dumping diagnostics).
install_install() {
  [ -f "$TARBALL" ] || fail_uat "tarball missing before install: $TARBALL"
  local now_sha
  now_sha="$(sha256sum "$TARBALL" | awk '{print $1}')"
  [ "$now_sha" = "$TARBALL_SHA256" ] \
    || fail_uat "tarball changed since build (expected $TARBALL_SHA256, got $now_sha)"

  local extract_root
  extract_root="$(mktemp -d /tmp/uat-bundle.XXXXXX)" \
    || fail_uat "could not create bundle extract directory"
  BUNDLE_DIR="$extract_root/docker-helper-${VERSION}-linux-amd64"

  # 1. The archive must extract successfully.
  tar xzf "$TARBALL" -C "$extract_root" \
    || fail_uat "tar extraction of $TARBALL failed"

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
  ( cd "$BUNDLE_DIR" && ./install-system.sh --yes --allowed-root "$ALLOWED_ROOT" ) \
    || fail_uat "install-system.sh failed (installer returned nonzero; see diagnostics)"
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
