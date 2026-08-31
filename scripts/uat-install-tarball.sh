#!/usr/bin/env bash
#
# uat-install-tarball.sh — release-tar.gz install adapter for the docker-helper
# black-box UAT. Sourced by scripts/uat-blackbox.sh (the scenario core) when
# UAT_INSTALL=tarball.
#
# "Tarball" here means: install the exact release tar.gz via the real shipped
# install-system.sh path (./install-system.sh --yes --allowed-root ...), not
# "AppArmor tarball". The adapter is MAC-neutral: which MAC artifacts the
# install must have produced and verified depends on the selected UAT_MAC.
#
#   * install_preflight       — install-time tooling present (tar, gzip);
#   * install_apply           — verify the recorded artifact hash, extract the
#                               EXACT artifact, verify it, then run
#                               ./install-system.sh --yes --allowed-root <root>
#                               non-interactively (init is part of that path);
#   * install_verify_artifacts— proves the installed binary/unit and the MAC
#                               artifacts of the selected backend came from the
#                               extracted bundle, and that no package manager
#                               owns the installed files (dpkg on Ubuntu, rpm
#                               on openSUSE):
#                               AppArmor: binary, unit, AppArmor profile;
#                               SELinux:  binary, unit, SELinux policy artifact
#                                         at the stable path, plus the
#                                         docker_helper policy module loaded;
#                               daemon confinement itself (profile enforce /
#                               docker_helper_t) is verified by the MAC adapter;
#   * install_verify_version  — installed /usr/bin/docker-helper version matches.
#
# It consumes the exact artifact recorded by the artifact adapter
# (ARTIFACT_PATH / ARTIFACT_SHA256) and never rebuilds it.
#
# The core runs as root (id -u == 0), so install-system.sh is invoked directly
# — the equivalent of the documented `sudo ./install-system.sh`.
#
# The core defines: VERSION, ALLOWED_ROOT, REPO_ROOT, say, info, fail_uat,
# fail_uat_status, redact_tokens, and the selected MAC/PLATFORM.

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

# package_owns returns 0 when the platform package manager owns the path.
# Platform-owned: Ubuntu -> dpkg, openSUSE -> rpm. dpkg is NOT a tarball
# invariant; the openSUSE tarball case must use rpm ownership.
package_owns() {
  local path="$1"
  case "$PLATFORM" in
    ubuntu) dpkg -S "$path" >/dev/null 2>&1 ;;
    opensuse) rpm -qf "$path" >/dev/null 2>&1 ;;
    *) fail_uat "no package-ownership check for platform '$PLATFORM'" ;;
  esac
}

# assert_no_package_owner fails the UAT if a package manager owns the path: the
# tarball case must be installed by the tarball, never by a package manager.
assert_no_package_owner() {
  local path="$1" label="$2"
  if package_owns "$path"; then
    fail_uat "$label is owned by a package — tarball case must not use a package manager ($PLATFORM)"
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

  # 0. Independent canonical-ownership check: every archive entry (files AND
  #    directories) must carry numeric ownership 0:0. The producer records this
  #    contract, but the UAT re-verifies it independently so a regression to
  #    runner UID/GID leaks fails here, not in production.
  local own_bad ent_count
  own_bad="$(tar tzvf "$ARTIFACT_PATH" 2>&1 | awk '!($2 == "0/0") { print $2 "\t" $6 }')" \
    || fail_uat "could not inspect tarball ownership of $ARTIFACT_PATH"
  ent_count="$(tar tzvf "$ARTIFACT_PATH" 2>&1 | wc -l)"
  [ "$ent_count" -gt 0 ] \
    || fail_uat "tarball has no parseable entries — ownership cannot be verified: $ARTIFACT_PATH"
  [ -z "$own_bad" ] || fail_uat "tarball entries not owned 0:0:"$'\n'"$own_bad"
  info "tarball canonical ownership 0:0 verified for all $ent_count entries"

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

# files_identical compares two files byte-for-byte WITHOUT depending on `cmp`
# (absent from the minimal openSUSE Tumbleweed cloud image — the RPM path only
# gets it via RPM dependencies). sha256sum is guaranteed (coreutils) and is
# already the UAT's canonical integrity primitive.
files_identical() {
  local a="$1" b="$2"
  [ "$(sha256sum "$a" | awk '{print $1}')" = "$(sha256sum "$b" | awk '{print $1}')" ]
}

# install_verify_artifacts proves the installed binary/unit and the MAC
# artifacts of the selected backend came from the extracted bundle and that no
# package-manager install was involved. Daemon confinement itself (AppArmor
# enforce / docker_helper_t) is verified by the MAC adapter in the core.
install_verify_artifacts() {
  [ -n "$BUNDLE_DIR" ] && [ -d "$BUNDLE_DIR" ] \
    || fail_uat "bundle directory not recorded for artifact verification"

  files_identical /usr/bin/docker-helper "$BUNDLE_DIR/docker-helper" \
    || fail_uat "installed /usr/bin/docker-helper does not match the bundle binary"
  assert_no_package_owner /usr/bin/docker-helper "installed binary"
  files_identical /etc/systemd/system/docker-helper.service "$BUNDLE_DIR/systemd/system/docker-helper.service" \
    || fail_uat "installed systemd unit does not match the bundle unit"
  assert_no_package_owner /etc/systemd/system/docker-helper.service "installed unit"

  if [ "$MAC" = "apparmor" ]; then
    files_identical /etc/apparmor.d/docker-helper-system "$BUNDLE_DIR/apparmor/docker-helper-system" \
      || fail_uat "installed AppArmor profile does not match the bundle profile"
    assert_no_package_owner /etc/apparmor.d/docker-helper-system "installed AppArmor profile"
    info "installed binary/unit/AppArmor profile match the extracted bundle (no package manager)"
  elif [ "$MAC" = "selinux" ]; then
    # The SELinux policy artifact at the stable path must originate from the
    # bundle (install-system.sh copies selinux/docker_helper.pp there).
    files_identical /usr/share/selinux/docker_helper.pp "$BUNDLE_DIR/selinux/docker_helper.pp" \
      || fail_uat "installed SELinux policy artifact does not match the bundle selinux/docker_helper.pp"
    assert_no_package_owner /usr/share/selinux/docker_helper.pp "installed SELinux policy artifact"
    # The docker_helper policy module must actually be loaded (semodule -i ran).
    if ! command -v semodule >/dev/null 2>&1; then
      fail_uat "semodule not found — cannot verify docker_helper policy module is loaded"
    fi
    if ! semodule -l 2>/dev/null | grep -qw docker_helper; then
      fail_uat "docker_helper policy module is not loaded (semodule -l)"
    fi
    info "installed binary/unit/SELinux policy artifact match the extracted bundle; docker_helper module loaded (no package manager)"
  else
    fail_uat "install_verify_artifacts: unsupported UAT_MAC '$MAC'"
  fi
}

# install_verify_version fails unless the installed binary reports the exact
# artifact version.
install_verify_version() {
  [ "$(/usr/bin/docker-helper version)" = "$VERSION" ] \
    || fail_uat "installed binary version mismatch (expected $VERSION)"
}
