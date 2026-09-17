#!/usr/bin/env bash
# build-packages.sh — assemble DEB and RPM packages via nFPM.
#
# Usage:
#   ./build-packages.sh VERSION [--payload DIR]
#
# Payload modes:
#
#   --payload DIR   assemble the packages from an ALREADY-BUILT shared release
#                   payload (docker-helper, docker_helper.pp, man pages, Bash
#                   completion) without rebuilding anything. The canonical
#                   producer (scripts/release-candidate.sh) builds the payload
#                   exactly once through the canonical builders and passes it
#                   to every artifact builder, so tar/DEB/RPM all pack the
#                   same bytes.
#
#   (default)       developer path: build the payload first through the
#                   canonical builders (build-static.sh, build-selinux-policy.sh,
#                   build-manpages.sh) and generate the Bash completion from
#                   the built binary.
#
# Requirements:
#   - nfpm (https://github.com/goreleaser/nfpm); see scripts/install-nfpm.sh
#   - build-static.sh prerequisites (Go, musl-gcc) in the default payload mode
#
# Output:
#   dist/docker-helper_<VERSION>_<arch>.deb
#   dist/docker-helper-<VERSION>-<release>.<arch>.rpm

set -euo pipefail

if [[ $# -lt 1 ]]; then
	echo "usage: build-packages.sh VERSION [--payload DIR]" >&2
	exit 1
fi

VERSION="$1"

PAYLOAD_DIR=""
if [[ "${2:-}" == "--payload" ]]; then
	PAYLOAD_DIR="${3:-}"
	if [[ -z "$PAYLOAD_DIR" ]]; then
		echo "error: --payload requires a payload directory" >&2
		exit 1
	fi
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if ! command -v nfpm >/dev/null 2>&1; then
	echo "error: nfpm not found" >&2
	echo "  Install (pinned, single owner): scripts/install-nfpm.sh" >&2
	exit 1
fi

# Verify the installed nfpm through the single pinned owner (version/hash live
# only in scripts/install-nfpm.sh); an unpinned or wrong version fails closed.
"${SCRIPT_DIR}/scripts/install-nfpm.sh" --check "$(command -v nfpm)"

if [[ -n "$PAYLOAD_DIR" ]]; then
	# Assemble only: stage the shared payload members into the canonical dist
	# locations the nFPM config consumes (nfpm.yaml src paths are unchanged).
	# The canonical builders (build-static.sh, build-selinux-policy.sh,
	# build-manpages.sh) remain the single owners of compilation.
	echo "=== Assembling from shared release payload: $PAYLOAD_DIR ==="
	for member in docker-helper docker_helper.pp \
		man/docker-helper.1.gz man/docker-helper-config.5.gz \
		completions/docker-helper; do
		if [[ ! -s "$PAYLOAD_DIR/$member" ]]; then
			echo "error: shared release payload member missing or empty: $PAYLOAD_DIR/$member" >&2
			exit 1
		fi
	done
	mkdir -p "${SCRIPT_DIR}/dist" "${SCRIPT_DIR}/dist/man" "${SCRIPT_DIR}/dist/completions"
	cp "$PAYLOAD_DIR/docker-helper" "${SCRIPT_DIR}/dist/docker-helper"
	chmod 755 "${SCRIPT_DIR}/dist/docker-helper"
	cp "$PAYLOAD_DIR/man/docker-helper.1.gz" "${SCRIPT_DIR}/dist/man/docker-helper.1.gz"
	cp "$PAYLOAD_DIR/man/docker-helper-config.5.gz" "${SCRIPT_DIR}/dist/man/docker-helper-config.5.gz"
	cp "$PAYLOAD_DIR/docker_helper.pp" "${SCRIPT_DIR}/dist/docker_helper.pp"
	cp "$PAYLOAD_DIR/completions/docker-helper" "${SCRIPT_DIR}/dist/completions/docker-helper"
else
	# Build static binary — build-static.sh is the authoritative builder.
	"${SCRIPT_DIR}/build-static.sh" "$VERSION"

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

	# Build SELinux policy module through the canonical owner
	# (build-selinux-policy.sh), so the RPM/DEB and the release tarball always
	# carry the byte-identical docker_helper.pp. It fails closed when the SELinux
	# policy build tools are missing and removes stale .pp/.mod output first.
	"${SCRIPT_DIR}/build-selinux-policy.sh" "${SCRIPT_DIR}/dist"
fi

# Verify the payload binary was staged.
if [[ ! -x "${SCRIPT_DIR}/dist/docker-helper" ]]; then
	echo "error: dist/docker-helper not found or not executable" >&2
	exit 1
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
