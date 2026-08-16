#!/usr/bin/env bash
# build-manpages.sh — build compressed man pages from source.
#
# Usage:
#   ./build-manpages.sh
#
# Input:
#   docs/man/docker-helper.1
#   docs/man/docker-helper-config.5
#
# Output:
#   dist/man/docker-helper.1.gz
#   dist/man/docker-helper-config.5.gz
#
# Requirements:
#   - gzip

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="${SCRIPT_DIR}/docs/man"
OUT_DIR="${SCRIPT_DIR}/dist/man"

# Verify source files exist.
for src in docker-helper.1 docker-helper-config.5; do
	if [[ ! -f "${SRC_DIR}/${src}" ]]; then
		echo "error: source man page not found: ${SRC_DIR}/${src}" >&2
		exit 1
	fi
done

# Create output directory.
mkdir -p "${OUT_DIR}"

# Build compressed man pages with deterministic gzip.
for src in docker-helper.1 docker-helper-config.5; do
	gzip -9n -c "${SRC_DIR}/${src}" > "${OUT_DIR}/${src}.gz"
done

# Verify outputs.
for out in "${OUT_DIR}/docker-helper.1.gz" "${OUT_DIR}/docker-helper-config.5.gz"; do
	if ! gzip -t "$out"; then
		echo "error: gzip verification failed: $out" >&2
		exit 1
	fi
done

echo "Man pages built in ${OUT_DIR}/"
ls -1 "${OUT_DIR}/"
