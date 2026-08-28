#!/usr/bin/env bash
#
# uat-install-rpm.sh — RPM install adapter for the docker-helper black-box
# UAT. Sourced by scripts/uat-blackbox.sh (the scenario core) when
# UAT_INSTALL=rpm.
#
# This adapter owns INSTALLATION of an already-produced RPM artifact and
# proving the installed files came from it. It never builds the artifact
# (that is the artifact adapter's job: uat-artifact-rpm.sh).
#
#   * install_preflight       — install-time tooling present (rpm);
#   * install_apply           — verify the recorded artifact hash, rpm -i, then
#                               init, daemon-reload, enable+start;
#   * install_verify_artifacts— rpm ownership of binary, systemd unit, and
#                               shipped MAC artifacts (AppArmor profile and
#                               SELinux policy module);
#   * install_verify_version  — installed /usr/bin/docker-helper version matches.
#
# It consumes the exact artifact recorded by the artifact adapter
# (ARTIFACT_PATH / ARTIFACT_SHA256) and never rebuilds it.
#
# Package installation and MAC verification stay separate: the RPM %post script
# may load a MAC policy, but confirming the daemon is actually confined is the
# MAC adapter's job (mac_verify_confinement in the core).
#
# NOTE: the nfpm-built RPM carries Requires on systemd, apparmor-parser,
# policycoreutils, policycoreutils-python-utils. On openSUSE the latter two
# names may differ; if `rpm -i` fails on unmet dependencies on a real runner,
# that is evidence for an RPM-metadata fix (nfpm.yaml), not for changing this
# adapter's install path. This is pending real openSUSE validation.
#
# The core defines: VERSION, ALLOWED_ROOT, REPO_ROOT, say, info, fail_uat,
# fail_uat_status, redact_tokens.

# install_name prints the install adapter label used in UAT output.
install_name() {
  printf 'RPM package (.rpm)'
}

# install_preflight fails unless the install-time tooling is present. Build
# tooling is owned by the artifact adapter.
install_preflight() {
  if ! command -v rpm >/dev/null 2>&1; then
    fail_uat "rpm not found"
  fi
}

# install_apply installs the exact recorded RPM and initializes/starts the
# confined system service. On a persistent self-hosted VM a prior install is
# removed first for idempotency. The admin token emitted by init is captured
# and redacted so it never reaches the CI log; on failure the init exit status
# is preserved.
install_apply() {
  [ -n "$ARTIFACT_PATH" ] || fail_uat "no RPM artifact recorded (artifact_build must run first)"
  [ -f "$ARTIFACT_PATH" ] || fail_uat "recorded RPM missing: $ARTIFACT_PATH"

  # Re-assert the exact-byte identity recorded at production time.
  local now_sha
  now_sha="$(sha256sum "$ARTIFACT_PATH" | awk '{print $1}')"
  [ "$now_sha" = "$ARTIFACT_SHA256" ] \
    || fail_uat "RPM changed since build (expected $ARTIFACT_SHA256, got $now_sha)"

  # Idempotency for re-runs on a persistent self-hosted VM: remove any prior
  # docker-helper package before installing the exact recorded one.
  if rpm -q docker-helper >/dev/null 2>&1; then
    info "removing prior docker-helper package for clean install"
    rpm -e docker-helper >/dev/null 2>&1 || true
  fi

  info "installing $ARTIFACT_PATH"
  rpm -i "$ARTIFACT_PATH" || fail_uat "rpm -i failed"

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

# install_verify_artifacts proves the installed binary/unit and shipped MAC
# artifacts came from the docker-helper RPM package (rpm ownership).
install_verify_artifacts() {
  if ! rpm -qf --queryformat '%{NAME}\n' /usr/bin/docker-helper 2>/dev/null | grep -qx 'docker-helper'; then
    fail_uat "/usr/bin/docker-helper is not owned by the docker-helper package"
  fi
  if ! rpm -qf --queryformat '%{NAME}\n' /usr/lib/systemd/system/docker-helper.service 2>/dev/null | grep -qx 'docker-helper'; then
    fail_uat "systemd unit is not owned by the docker-helper package"
  fi
  # Verify shipped MAC artifacts (both AppArmor and SELinux) are owned by package.
  if ! rpm -qf --queryformat '%{NAME}\n' /etc/apparmor.d/docker-helper-system 2>/dev/null | grep -qx 'docker-helper'; then
    fail_uat "AppArmor profile is not owned by the docker-helper package"
  fi
  if ! rpm -qf --queryformat '%{NAME}\n' /usr/share/selinux/docker_helper.pp 2>/dev/null | grep -qx 'docker-helper'; then
    fail_uat "SELinux policy module is not owned by the docker-helper package"
  fi
}

# install_verify_version fails unless the installed binary reports the exact
# artifact version.
install_verify_version() {
  [ "$(/usr/bin/docker-helper version)" = "$VERSION" ] \
    || fail_uat "installed binary version mismatch (expected $VERSION)"
}
