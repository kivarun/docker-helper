#!/usr/bin/env bash
# build-packages.sh — build DEB and RPM packages via nFPM.
#
# Usage:
#   ./build-packages.sh VERSION
#
# Requirements:
#   - nfpm (https://github.com/goreleaser/nfpm)
#   - build-static.sh prerequisites (Go, musl-gcc)
#
# Output:
#   dist/docker-helper_<VERSION>_<arch>.deb
#   dist/docker-helper-<VERSION>-<release>.<arch>.rpm

set -euo pipefail

if [[ $# -lt 1 ]]; then
	echo "usage: build-packages.sh VERSION" >&2
	exit 1
fi

VERSION="$1"

if ! command -v nfpm >/dev/null 2>&1; then
	echo "error: nfpm not found" >&2
	echo "  Install: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest" >&2
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Build static binary — build-static.sh is the authoritative builder.
"${SCRIPT_DIR}/build-static.sh" "$VERSION"

# Verify the binary was produced.
if [[ ! -x "${SCRIPT_DIR}/dist/docker-helper" ]]; then
	echo "error: dist/docker-helper not found or not executable" >&2
	exit 1
fi

# Build man pages.
"${SCRIPT_DIR}/build-manpages.sh"

# Build SELinux policy module (if tools available).
if command -v checkmodule >/dev/null 2>&1 && command -v semodule_package >/dev/null 2>&1; then
  echo "Building SELinux policy module..."
  checkmodule -M -m -o "${SCRIPT_DIR}/packaging/selinux/docker-helper.mod" \
    "${SCRIPT_DIR}/packaging/selinux/docker-helper.te"
  semodule_package -o "${SCRIPT_DIR}/packaging/selinux/docker-helper.pp" \
    -m "${SCRIPT_DIR}/packaging/selinux/docker-helper.mod" \
    -f "${SCRIPT_DIR}/packaging/selinux/docker-helper.fc"
  rm -f "${SCRIPT_DIR}/packaging/selinux/docker-helper.mod"
else
  echo "warning: checkmodule/semodule_package not found; SELinux policy module will not be built" >&2
fi

# Build from repo root so src paths in the config resolve correctly.
# nFPM expands ${VERSION} from the environment.
cd "${SCRIPT_DIR}"

VERSION="$VERSION" nfpm package \
	--config packaging/nfpm.yaml \
	--packager deb \
	--target dist

VERSION="$VERSION" nfpm package \
	--config packaging/nfpm.yaml \
	--packager rpm \
	--target dist

echo "Packages built in ${SCRIPT_DIR}/dist/"
ls -1 dist/*.deb dist/*.rpm
