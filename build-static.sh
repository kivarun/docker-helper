#!/usr/bin/env bash
# build-static.sh — produce a static Linux amd64 binary using musl.
#
# Usage:
#   ./build-static.sh [VERSION]
#
# If VERSION is not provided, defaults to "dev".
#
# Requirements:
#   - Go 1.23.0 with the go1.26.7 toolchain pinned in go.mod (the go command
#     honors the toolchain directive automatically)
#   - musl-gcc (e.g., musl-tools on Debian/Ubuntu)
#     OR gcc on Alpine (which uses musl natively)
#   - CGO is required (go-sqlite3)
#
# On a glibc host without musl-gcc this script fails rather than
# silently producing a glibc-linked binary.
#
# Output:
#   <repo>/dist/docker-helper  (static Linux amd64 binary)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
OUT_DIR="$REPO_ROOT/dist"
OUT_BIN="$OUT_DIR/docker-helper"

VERSION="${1:-dev}"

mkdir -p "$OUT_DIR"

# --- Determine the C compiler ---
# Canonical: musl-gcc.
# Fallback: gcc only on Alpine (where the system libc IS musl).
# On a glibc host without musl-gcc: fail.

if command -v musl-gcc >/dev/null 2>&1; then
  CC="musl-gcc"
elif [[ -f "/etc/alpine-release" ]]; then
  # Alpine: gcc already uses musl, so it's safe.
  if command -v gcc >/dev/null 2>&1; then
    CC="gcc"
  else
    echo "error: gcc not found on Alpine" >&2
    exit 1
  fi
else
  echo "error: musl-gcc not found" >&2
  echo "  On Debian/Ubuntu:  sudo apt-get install musl-tools" >&2
  echo "  On Alpine:         apk add musl-dev gcc" >&2
  echo "  On other distros:  install musl and musl-gcc" >&2
  exit 1
fi

# --- Build ---
# -linkmode external: force the linker to use the external (CC) linker
#   so that -extldflags '-static' reaches the system linker.
# -extldflags '-static': tell the system linker to produce a fully
#   static binary (required for go-sqlite3 with musl).

(
  cd "$REPO_ROOT"
  CGO_ENABLED=1 \
  CC="$CC" \
  GOOS=linux \
  GOARCH=amd64 \
  go build \
    -ldflags "-linkmode external -extldflags '-static' -X main.version=${VERSION}" \
    -o "$OUT_BIN" \
    .
)

chmod 755 "$OUT_BIN"

echo "Built: $OUT_BIN (version=$VERSION, CC=$CC)"
