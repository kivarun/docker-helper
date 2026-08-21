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

# Generate Bash completion script from the freshly built binary.
rm -f "${SCRIPT_DIR}/dist/completions/docker-helper"
mkdir -p "${SCRIPT_DIR}/dist/completions"
echo "Generating Bash completion..."
"${SCRIPT_DIR}/dist/docker-helper" completion bash > "${SCRIPT_DIR}/dist/completions/docker-helper"
if [[ ! -s "${SCRIPT_DIR}/dist/completions/docker-helper" ]]; then
  echo "error: completion generation produced empty output" >&2
  exit 1
fi

# Build SELinux policy module (required).
if ! command -v checkmodule >/dev/null 2>&1; then
  echo "error: checkmodule not found (install checkpolicy or policycoreutils-devel)" >&2
  exit 1
fi
if ! command -v semodule_package >/dev/null 2>&1; then
  echo "error: semodule_package not found (install semodule-utils or policycoreutils)" >&2
  exit 1
fi
# Remove any previous generated output to prevent stale artifacts.
rm -f "${SCRIPT_DIR}/dist/docker-helper.pp"
echo "Building SELinux policy module..."
checkmodule -M -m -o "${SCRIPT_DIR}/dist/docker_helper.mod" \
  "${SCRIPT_DIR}/packaging/selinux/docker-helper.te"
semodule_package -o "${SCRIPT_DIR}/dist/docker-helper.pp" \
  -m "${SCRIPT_DIR}/dist/docker_helper.mod" \
  -f "${SCRIPT_DIR}/packaging/selinux/docker-helper.fc"
rm -f "${SCRIPT_DIR}/dist/docker_helper.mod"

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
