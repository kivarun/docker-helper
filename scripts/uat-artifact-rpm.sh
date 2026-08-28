#!/usr/bin/env bash
#
# uat-artifact-rpm.sh — RPM artifact producer for the docker-helper black-box
# UAT. Sourced by scripts/uat-blackbox.sh (the scenario core) when
# UAT_INSTALL=rpm.
#
# This adapter owns artifact PRODUCTION only: the repository's canonical RPM
# build path (build-packages.sh) yielding an exact, immutable .rpm whose path
# and SHA-256 are recorded (ARTIFACT_PATH / ARTIFACT_SHA256) for the install
# adapter to consume. It never installs anything and never runs after install.
#
# The install adapter (uat-install-rpm.sh) consumes the recorded artifact and
# never rebuilds it: build once -> immutable artifact -> install/test exact
# artifact. This mirrors the release pipeline's build/install/publish split.
#
# The scenario core defines: VERSION, REPO_ROOT, info, fail_uat.

# artifact_name prints the artifact label used in UAT output.
artifact_name() {
  printf 'RPM package (.rpm)'
}

# artifact_preflight fails unless the build tooling for this artifact is
# present.
artifact_preflight() {
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

# artifact_build produces the exact RPM via the single upstream build step and
# records its path + SHA-256. build-packages.sh emits both a .deb and a .rpm;
# we select the single intended .rpm at production time (no broad rediscovery
# later).
artifact_build() {
  rm -rf dist
  ./build-packages.sh "$VERSION" || fail_uat "./build-packages.sh $VERSION failed"

  local count
  count="$(ls dist/*.rpm 2>/dev/null | wc -l)"
  ARTIFACT_PATH="$(ls dist/*.rpm 2>/dev/null | head -1)"
  [ "$count" = "1" ] && [ -n "$ARTIFACT_PATH" ] \
    || fail_uat "expected exactly one .rpm under dist/ (found $count)"

  ARTIFACT_SHA256="$(sha256sum "$ARTIFACT_PATH" | awk '{print $1}')"
  [ -n "$ARTIFACT_SHA256" ] || fail_uat "could not compute RPM SHA-256"
  info "artifact: $ARTIFACT_PATH"
  info "sha256:   $ARTIFACT_SHA256"
}
