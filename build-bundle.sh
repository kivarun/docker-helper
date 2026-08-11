#!/usr/bin/env bash
# build-bundle.sh — build a static binary and pack a release tarball.
#
# Usage:
#   ./build-bundle.sh VERSION
#
# Example:
#   ./build-bundle.sh 1.0.0
#
# Output:
#   dist/docker-helper-<version>-linux-amd64.tar.gz
#
# The tarball contains:
#   docker-helper-<version>-linux-amd64/
#     README.md
#     docker-helper
#     install.sh
#     uninstall.sh
#     systemd/
#       user/
#         docker-helper.service
#     apparmor/
#       docker-helper
#     skills/
#       docker-helper/
#         SKILL.md
#
# If static linking cannot be confirmed, the build FAILS.
# A release tarball must never contain an unconfirmed binary.

set -euo pipefail

VERSION="${1:-}"

if [[ -z "$VERSION" ]]; then
  echo "error: VERSION is required" >&2
  echo "Usage: $0 VERSION" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$SCRIPT_DIR/dist"
BUNDLE_DIR="$OUT_DIR/docker-helper-${VERSION}-linux-amd64"
TARBALL="$OUT_DIR/docker-helper-${VERSION}-linux-amd64.tar.gz"

# --- Step 1: Build static binary ---

echo "=== Building static binary ==="
bash "$SCRIPT_DIR/build-static.sh" "$VERSION"

# --- Step 2: Assemble bundle directory ---

echo "=== Assembling bundle ==="

rm -rf "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR"

# Binary
cp "$OUT_DIR/docker-helper" "$BUNDLE_DIR/docker-helper"
chmod 755 "$BUNDLE_DIR/docker-helper"

# Release-specific README
cp "$SCRIPT_DIR/packaging/README.release.md" "$BUNDLE_DIR/README.md"

# Install/uninstall scripts
cp "$SCRIPT_DIR/packaging/install.sh" "$BUNDLE_DIR/install.sh"
cp "$SCRIPT_DIR/packaging/uninstall.sh" "$BUNDLE_DIR/uninstall.sh"
chmod 755 "$BUNDLE_DIR/install.sh"
chmod 755 "$BUNDLE_DIR/uninstall.sh"

# Systemd unit
mkdir -p "$BUNDLE_DIR/systemd/user"
cp "$SCRIPT_DIR/packaging/systemd/user/docker-helper.service" \
   "$BUNDLE_DIR/systemd/user/docker-helper.service"

# AppArmor profile
mkdir -p "$BUNDLE_DIR/apparmor"
cp "$SCRIPT_DIR/packaging/apparmor/docker-helper" \
   "$BUNDLE_DIR/apparmor/docker-helper"

# Agent skill
mkdir -p "$BUNDLE_DIR/skills/docker-helper"
cp "$SCRIPT_DIR/.claude/skills/docker-helper/SKILL.md" \
   "$BUNDLE_DIR/skills/docker-helper/SKILL.md"

# --- Step 3: Create tarball ---

echo "=== Creating tarball ==="

tar czf "$TARBALL" \
  -C "$OUT_DIR" \
  "docker-helper-${VERSION}-linux-amd64"

echo "Bundle: $TARBALL"

# --- Step 4: Verify ---

echo "=== Verification ==="

# Check binary exists and is executable
if [[ ! -x "$BUNDLE_DIR/docker-helper" ]]; then
  echo "FAIL: docker-helper not executable" >&2
  exit 1
fi
echo "OK: docker-helper is executable"

# Check version
VER_OUTPUT=$("$BUNDLE_DIR/docker-helper" version)
if [[ "$VER_OUTPUT" != "$VERSION" ]]; then
  echo "FAIL: version mismatch: expected '$VERSION', got '$VER_OUTPUT'" >&2
  exit 1
fi
echo "OK: version is $VERSION"

# Check static linking — MUST be confirmed, not just warned.
STATIC_CONFIRMED=false
FILE_OUTPUT=$(file "$BUNDLE_DIR/docker-helper" 2>/dev/null || true)
if echo "$FILE_OUTPUT" | grep -qi "statically linked"; then
  STATIC_CONFIRMED=true
else
  LDD_OUTPUT=$(ldd "$BUNDLE_DIR/docker-helper" 2>&1 || true)
  if echo "$LDD_OUTPUT" | grep -qi "not a dynamic"; then
    STATIC_CONFIRMED=true
  fi
fi

if [[ "$STATIC_CONFIRMED" != "true" ]]; then
  echo "FAIL: cannot confirm static linking" >&2
  echo "  file output: $FILE_OUTPUT" >&2
  exit 1
fi
echo "OK: binary is statically linked"

# Check tarball contains the exact mandatory set of paths.
EXPECTED_PATHS=(
  "docker-helper-${VERSION}-linux-amd64/docker-helper"
  "docker-helper-${VERSION}-linux-amd64/README.md"
  "docker-helper-${VERSION}-linux-amd64/install.sh"
  "docker-helper-${VERSION}-linux-amd64/uninstall.sh"
  "docker-helper-${VERSION}-linux-amd64/systemd/user/docker-helper.service"
  "docker-helper-${VERSION}-linux-amd64/apparmor/docker-helper"
   "docker-helper-${VERSION}-linux-amd64/skills/docker-helper/SKILL.md"
)

TARBALL_CONTENTS=$(tar tzf "$TARBALL")

for expected in "${EXPECTED_PATHS[@]}"; do
  if ! echo "$TARBALL_CONTENTS" | grep -qxF "$expected"; then
    echo "FAIL: tarball missing required path: $expected" >&2
    exit 1
  fi
done
echo "OK: tarball contains all required paths"

# Check executable bits for files that must be executable.
for f in docker-helper install.sh uninstall.sh; do
  PERMS=$(tar tzvf "$TARBALL" | grep "docker-helper-${VERSION}-linux-amd64/${f}$" | awk '{print $1}')
  if [[ "$PERMS" =~ ^-rwx ]]; then
    echo "OK: $f has executable bit"
  else
    echo "FAIL: $f missing executable bit (got $PERMS)" >&2
    exit 1
  fi
done

echo ""
echo "=== Done ==="
echo "Artifact: $TARBALL"
echo "Size: $(du -h "$TARBALL" | cut -f1)"