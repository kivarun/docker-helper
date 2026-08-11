#!/usr/bin/env bash
# build-static.sh — produce a static Linux amd64 binary using musl.
#
# Usage:
#   ./build-static.sh [VERSION]
#
# If VERSION is not provided, defaults to the value of the 'version'
# variable in main.go (typically "dev").
#
# Requirements:
#   - Go 1.23+
#   - musl-gcc (e.g., musl-tools on Debian/Ubuntu, musl-dev on Alpine)
#     or gcc on Alpine (which already uses musl)
#   - CGO is required (go-sqlite3)
#
# Output:
#   dist/docker-helper  (static Linux amd64 binary)

set -euo pipefail

VERSION="${1:-}"

if [[ -z "$VERSION" ]]; then
  VERSION="dev"
fi

OUT_DIR="dist"
OUT_BIN="$OUT_DIR/docker-helper"

mkdir -p "$OUT_DIR"

# Determine the C compiler: prefer musl-gcc, fall back to gcc (Alpine).
if command -v musl-gcc >/dev/null 2>&1; then
  CC="musl-gcc"
else
  CC="gcc"
fi

LDFLAGS="-extldflags '-static' -X main.version=${VERSION}"

CGO_ENABLED=1 \
  CC="$CC" \
  GOOS=linux \
  GOARCH=amd64 \
  go build \
    -ldflags "$LDFLAGS" \
    -o "$OUT_BIN" \
    .

chmod 755 "$OUT_BIN"

echo "Built: $OUT_BIN (version=$VERSION, CC=$CC)"