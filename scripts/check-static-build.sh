#!/usr/bin/env bash
# check-static-build.sh — build a static binary once from a non-repo cwd,
# then verify it is executable, has the correct version, and is statically
# linked.
#
# Usage:
#   scripts/check-static-build.sh
#
# Exits 0 on success, non-zero on failure.
# Requires: go, musl-gcc (or Alpine gcc), file
#
# Single invocation proves:
#   - build-static.sh works from a cwd outside the repository
#   - the produced binary is executable
#   - the produced binary reports the requested version
#   - the produced binary is statically linked

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

# Verify required tools are available.
for cmd in go file; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: ${cmd} not found" >&2
        exit 1
    fi
done

# Determine C compiler — must match build-static.sh logic.
if command -v musl-gcc >/dev/null 2>&1; then
    : # musl-gcc available
elif [[ -f "/etc/alpine-release" ]]; then
    if ! command -v gcc >/dev/null 2>&1; then
        echo "ERROR: gcc not found on Alpine" >&2
        exit 1
    fi
else
    echo "ERROR: musl-gcc not found (install musl-tools on Debian/Ubuntu)" >&2
    exit 1
fi

# Verify build script exists.
build_script="${repo_root}/build-static.sh"
if [ ! -f "$build_script" ]; then
    echo "ERROR: ${build_script} not found" >&2
    exit 1
fi

test_version="check-static-build"

# Run build-static.sh from a temporary directory outside the repo.
# This single run proves cwd independence.
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

echo "Building static binary from non-repo cwd..."
(
    cd "$tmp_dir"
    bash "$build_script" "$test_version"
)

bin_path="${repo_root}/dist/docker-helper"

# Check binary exists.
if [ ! -f "$bin_path" ]; then
    echo "ERROR: binary not found at ${bin_path}" >&2
    exit 1
fi

# Check executable bit.
if [ ! -x "$bin_path" ]; then
    echo "ERROR: binary is not executable: ${bin_path}" >&2
    exit 1
fi

# Check version.
actual_version="$("$bin_path" version)"
if [ "$actual_version" != "$test_version" ]; then
    echo "ERROR: version mismatch: expected '${test_version}', got '${actual_version}'" >&2
    exit 1
fi

# Check static linking.
file_output="$(file "$bin_path")"
if ! echo "$file_output" | grep -q "statically linked"; then
    echo "ERROR: binary is not statically linked: ${file_output}" >&2
    exit 1
fi

echo "Static build check passed: version=${actual_version}, statically linked."
