#!/usr/bin/env bash
#
# uat-artifact-tarball.sh — release-tar.gz artifact producer for the
# docker-helper black-box UAT. Sourced by scripts/uat-blackbox.sh (the
# scenario core) when UAT_INSTALL=tarball.
#
# This adapter owns artifact PRODUCTION only: one upstream build step
# (build-bundle.sh VERSION) yielding an exact, immutable tar.gz whose path and
# SHA-256 are recorded (ARTIFACT_PATH / ARTIFACT_SHA256) for the install
# adapter to consume. It never installs anything and never runs after install.
#
# The install adapter (uat-install-tarball.sh) consumes the recorded artifact
# and never rebuilds it: build once -> immutable artifact -> install/test
# exact artifact. This mirrors the release pipeline's build/install/publish
# split and keeps the later multi-job (build-artifacts / UAT / release) split
# straightforward.
#
# The scenario core defines: VERSION, REPO_ROOT, info, fail_uat.

# artifact_name prints the artifact label used in UAT output.
artifact_name() {
  printf 'release tarball (tar.gz)'
}

# artifact_preflight fails unless the tooling for this artifact is present.
artifact_preflight() {
  # build-bundle.sh requires `file` to confirm static linking.
  if ! command -v file >/dev/null 2>&1; then
    fail_uat "file not found (build-bundle.sh confirms static linking)"
  fi
  if ! command -v sha256sum >/dev/null 2>&1; then
    fail_uat "sha256sum not found"
  fi
}

# artifact_build produces the exact release tarball via the single upstream
# build step and records its path + SHA-256. This runs as a distinct phase
# BEFORE the install adapter is asked to install anything.
artifact_build() {
  rm -rf dist
  ./build-bundle.sh "$VERSION" || fail_uat "./build-bundle.sh $VERSION failed"

  ARTIFACT_PATH="dist/docker-helper-${VERSION}-linux-amd64.tar.gz"
  [ -f "$ARTIFACT_PATH" ] || fail_uat "release tarball not produced: $ARTIFACT_PATH"

  ARTIFACT_SHA256="$(sha256sum "$ARTIFACT_PATH" | awk '{print $1}')"
  [ -n "$ARTIFACT_SHA256" ] || fail_uat "could not compute tarball SHA-256"
  info "artifact: $ARTIFACT_PATH"
  info "sha256:   $ARTIFACT_SHA256"
}
