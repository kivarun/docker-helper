#!/usr/bin/env bash
# build-bundle.sh — assemble the release tarball.
#
# Usage:
#   ./build-bundle.sh VERSION [--payload DIR]
#
# Example:
#   ./build-bundle.sh 1.0.0
#
# Output:
#   dist/docker-helper-<version>-linux-amd64.tar.gz
#
# Payload modes:
#
#   --payload DIR   assemble the tarball from an ALREADY-BUILT shared release
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
# The tarball contains:
#   docker-helper-<version>-linux-amd64/
#     README.md
#     docker-helper
#     install-system.sh
#     uninstall-system.sh
#     systemd/
#       system/
#         docker-helper.service
#         docker-helper-builder.service
#   apparmor/
#       docker-helper
#       docker-helper-system
#       local/
#         curl
#   selinux/
#       docker_helper.pp
#   buildkit/
#     buildkitd
#     buildctl
#     buildkit-runc
#     LICENSE
#     MANIFEST
#   scripts/
#     provision-builder.sh
#   skills/
#       docker-helper/
#         SKILL.md
#     man/
#       docker-helper.1.gz
#       docker-helper-config.5.gz
#
# If static linking cannot be confirmed, the build FAILS.
# A release tarball must never contain an unconfirmed binary.

set -euo pipefail

VERSION="${1:-}"

if [[ -z "$VERSION" ]]; then
  echo "error: VERSION is required" >&2
  echo "Usage: $0 VERSION [--payload DIR]" >&2
  exit 1
fi

PAYLOAD_DIR=""
if [[ "${2:-}" == "--payload" ]]; then
  PAYLOAD_DIR="${3:-}"
  if [[ -z "$PAYLOAD_DIR" ]]; then
    echo "error: --payload requires a payload directory" >&2
    exit 1
  fi
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$SCRIPT_DIR/dist"
BUNDLE_DIR="$OUT_DIR/docker-helper-${VERSION}-linux-amd64"
TARBALL="$OUT_DIR/docker-helper-${VERSION}-linux-amd64.tar.gz"

# --- Step 1: Obtain the shared release payload members ------------------------
# The canonical builders (build-static.sh, build-selinux-policy.sh,
# build-manpages.sh) remain the single owners of binary/policy/man
# compilation; this script only assembles. With --payload the members were
# built exactly once by the canonical producer and are consumed as-is.

if [[ -n "$PAYLOAD_DIR" ]]; then
  echo "=== Assembling from shared release payload: $PAYLOAD_DIR ==="
  for member in docker-helper docker_helper.pp \
    man/docker-helper.1.gz man/docker-helper-config.5.gz \
    completions/docker-helper \
    buildkit/usr/libexec/docker-helper/buildkit/buildkitd \
    buildkit/usr/libexec/docker-helper/buildkit/buildctl \
    buildkit/usr/libexec/docker-helper/buildkit/buildkit-runc \
    buildkit/usr/share/doc/docker-helper/buildkit/LICENSE \
    buildkit/usr/share/doc/docker-helper/buildkit/MANIFEST; do
    if [[ ! -s "$PAYLOAD_DIR/$member" ]]; then
      echo "error: shared release payload member missing or empty: $PAYLOAD_DIR/$member" >&2
      exit 1
    fi
  done
else
  echo "=== Building static binary ==="
  bash "$SCRIPT_DIR/build-static.sh" "$VERSION"

  # The canonical SELinux policy builder (same owner as build-packages.sh): the
  # tarball carries selinux/docker_helper.pp built from the authoritative
  # packaging/selinux/docker-helper.{te,fc}. A missing policy build tool or a
  # failed compilation FAILS the bundle build (fail-closed).
  echo "=== Building SELinux policy module ==="
  bash "$SCRIPT_DIR/build-selinux-policy.sh" "$OUT_DIR"

  # Stage the pinned BuildKit payload through its single owner (the same
  # owner and pin build-packages.sh consumes: one pinned payload).
  bash "$SCRIPT_DIR/build-buildkit-payload.sh" "$OUT_DIR/buildkit"
fi

# --- Step 2: Assemble bundle directory ---

echo "=== Assembling bundle ==="

rm -rf "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR"

# Binary
if [[ -n "$PAYLOAD_DIR" ]]; then
  cp "$PAYLOAD_DIR/docker-helper" "$BUNDLE_DIR/docker-helper"
else
  cp "$OUT_DIR/docker-helper" "$BUNDLE_DIR/docker-helper"
fi
chmod 755 "$BUNDLE_DIR/docker-helper"

# License
cp "$SCRIPT_DIR/LICENSE" "$BUNDLE_DIR/LICENSE"

# Release-specific README
cp "$SCRIPT_DIR/packaging/README.release.md" "$BUNDLE_DIR/README.md"

# Install/uninstall scripts
cp "$SCRIPT_DIR/packaging/install-system.sh" "$BUNDLE_DIR/install-system.sh"
cp "$SCRIPT_DIR/packaging/uninstall-system.sh" "$BUNDLE_DIR/uninstall-system.sh"
chmod 755 "$BUNDLE_DIR/install-system.sh"
chmod 755 "$BUNDLE_DIR/uninstall-system.sh"

# Systemd units (main daemon + builder backend)
mkdir -p "$BUNDLE_DIR/systemd/system"
cp "$SCRIPT_DIR/packaging/systemd/system/docker-helper.service" \
   "$BUNDLE_DIR/systemd/system/docker-helper.service"
cp "$SCRIPT_DIR/packaging/systemd/system/docker-helper-builder.service" \
   "$BUNDLE_DIR/systemd/system/docker-helper-builder.service"

# Pinned BuildKit payload (flat bundle layout; install-system.sh maps each
# file to its product path). Source: the staged payload in --payload mode,
# the dist staging in developer mode — both produced by the single pinned
# payload owner.
if [[ -n "$PAYLOAD_DIR" ]]; then
  rm -rf "$BUNDLE_DIR/buildkit"
  mkdir -p "$BUNDLE_DIR/buildkit"
  cp -r "$PAYLOAD_DIR/buildkit/usr/libexec/docker-helper/buildkit/." \
        "$BUNDLE_DIR/buildkit/"
  cp -r "$PAYLOAD_DIR/buildkit/usr/share/doc/docker-helper/buildkit/." \
        "$BUNDLE_DIR/buildkit/"
else
  rm -rf "$BUNDLE_DIR/buildkit"
  mkdir -p "$BUNDLE_DIR/buildkit"
  cp "$OUT_DIR/buildkit/usr/libexec/docker-helper/buildkit/buildkitd" \
     "$OUT_DIR/buildkit/usr/libexec/docker-helper/buildkit/buildctl" \
     "$OUT_DIR/buildkit/usr/libexec/docker-helper/buildkit/buildkit-runc" \
     "$BUNDLE_DIR/buildkit/"
  cp "$OUT_DIR/buildkit/usr/share/doc/docker-helper/buildkit/LICENSE" \
     "$OUT_DIR/buildkit/usr/share/doc/docker-helper/buildkit/MANIFEST" \
     "$BUNDLE_DIR/buildkit/"
fi
chmod 755 "$BUNDLE_DIR/buildkit/buildkitd" \
          "$BUNDLE_DIR/buildkit/buildctl" \
          "$BUNDLE_DIR/buildkit/buildkit-runc"
chmod 644 "$BUNDLE_DIR/buildkit/LICENSE" "$BUNDLE_DIR/buildkit/MANIFEST"

# Builder identity provisioning script (the ONE provisioning owner; the
# tarball installer executes it, never re-implements it)
mkdir -p "$BUNDLE_DIR/scripts"
cp "$SCRIPT_DIR/packaging/scripts/lib/provision-builder.sh" \
   "$BUNDLE_DIR/scripts/provision-builder.sh"
chmod 755 "$BUNDLE_DIR/scripts/provision-builder.sh"

# AppArmor profiles
mkdir -p "$BUNDLE_DIR/apparmor/local"
cp "$SCRIPT_DIR/packaging/apparmor/docker-helper-system" \
   "$BUNDLE_DIR/apparmor/docker-helper-system"
cp "$SCRIPT_DIR/packaging/apparmor/local/curl" \
   "$BUNDLE_DIR/apparmor/local/curl"

# SELinux policy module (both MAC backends ship in the bundle; the installer
# selects the active one)
if [[ -n "$PAYLOAD_DIR" ]]; then
  mkdir -p "$BUNDLE_DIR/selinux"
  cp "$PAYLOAD_DIR/docker_helper.pp" "$BUNDLE_DIR/selinux/docker_helper.pp"
else
  mkdir -p "$BUNDLE_DIR/selinux"
  cp "$OUT_DIR/docker_helper.pp" "$BUNDLE_DIR/selinux/docker_helper.pp"
fi

# Agent skill
mkdir -p "$BUNDLE_DIR/skills/docker-helper"
cp "$SCRIPT_DIR/.claude/skills/docker-helper/SKILL.md" \
   "$BUNDLE_DIR/skills/docker-helper/SKILL.md"

# Man pages
if [[ -n "$PAYLOAD_DIR" ]]; then
  mkdir -p "$BUNDLE_DIR/man"
  cp "$PAYLOAD_DIR/man/docker-helper.1.gz" "$BUNDLE_DIR/man/docker-helper.1.gz"
  cp "$PAYLOAD_DIR/man/docker-helper-config.5.gz" "$BUNDLE_DIR/man/docker-helper-config.5.gz"
else
  "$SCRIPT_DIR/build-manpages.sh"
  mkdir -p "$BUNDLE_DIR/man"
  cp "$OUT_DIR/man/docker-helper.1.gz" "$BUNDLE_DIR/man/docker-helper.1.gz"
  cp "$OUT_DIR/man/docker-helper-config.5.gz" "$BUNDLE_DIR/man/docker-helper-config.5.gz"
fi

# Bash completion
if [[ -n "$PAYLOAD_DIR" ]]; then
  mkdir -p "$BUNDLE_DIR/completions"
  cp "$PAYLOAD_DIR/completions/docker-helper" "$BUNDLE_DIR/completions/docker-helper"
else
  rm -f "$OUT_DIR/completions/docker-helper"
  mkdir -p "$OUT_DIR/completions"
  "$BUNDLE_DIR/docker-helper" completion bash > "$OUT_DIR/completions/docker-helper"
  if [[ ! -s "$OUT_DIR/completions/docker-helper" ]]; then
    echo "error: completion generation produced empty output" >&2
    exit 1
  fi
  mkdir -p "$BUNDLE_DIR/completions"
  cp "$OUT_DIR/completions/docker-helper" "$BUNDLE_DIR/completions/docker-helper"
fi

# --- Step 3: Create tarball ---

echo "=== Creating tarball ==="

# Canonical numeric ownership 0:0: the release tarball must carry the same
# UID/GID regardless of the build environment (a root-less runner or a local
# developer machine must not leak its UID/GID into the shipped artifact).
tar czf "$TARBALL" \
  --owner=0 --group=0 --numeric-owner \
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

# The SELinux policy artifact must be present and non-empty in the bundle.
if [[ ! -s "$BUNDLE_DIR/selinux/docker_helper.pp" ]]; then
  echo "FAIL: SELinux policy artifact missing or empty in bundle: selinux/docker_helper.pp" >&2
  exit 1
fi
echo "OK: SELinux policy artifact present: selinux/docker_helper.pp"

# The pinned BuildKit payload must be present and non-empty in the bundle;
# its staged bytes must also match the MANIFEST the payload owner generated.
if [[ ! -s "$BUNDLE_DIR/buildkit/buildkitd" ]] || [[ ! -s "$BUNDLE_DIR/buildkit/buildctl" ]] \
   || [[ ! -s "$BUNDLE_DIR/buildkit/buildkit-runc" ]] || [[ ! -s "$BUNDLE_DIR/buildkit/LICENSE" ]] \
   || [[ ! -s "$BUNDLE_DIR/buildkit/MANIFEST" ]]; then
  echo "FAIL: pinned BuildKit payload missing or empty in bundle: buildkit/" >&2
  exit 1
fi
echo "OK: pinned BuildKit payload present: buildkit/"
while IFS='=' read -r key value; do
  case "$key" in
    buildkitd-sha256|buildctl-sha256|buildkit-runc-sha256)
      actual="$(sha256sum "$BUNDLE_DIR/buildkit/${key%%-sha256}" | awk '{print $1}')"
      if [[ "$actual" != "$value" ]]; then
        echo "FAIL: BuildKit payload digest mismatch for $key: manifest $value != staged $actual" >&2
        exit 1
      fi
      ;;
  esac
done < "$BUNDLE_DIR/buildkit/MANIFEST"
echo "OK: BuildKit payload binaries match their MANIFEST digests"

# Check tarball contains the exact mandatory set of paths.
EXPECTED_PATHS=(
  "docker-helper-${VERSION}-linux-amd64/docker-helper"
  "docker-helper-${VERSION}-linux-amd64/LICENSE"
  "docker-helper-${VERSION}-linux-amd64/README.md"
  "docker-helper-${VERSION}-linux-amd64/install-system.sh"
  "docker-helper-${VERSION}-linux-amd64/uninstall-system.sh"
  "docker-helper-${VERSION}-linux-amd64/systemd/system/docker-helper.service"
  "docker-helper-${VERSION}-linux-amd64/systemd/system/docker-helper-builder.service"
  "docker-helper-${VERSION}-linux-amd64/apparmor/docker-helper-system"
  "docker-helper-${VERSION}-linux-amd64/apparmor/local/curl"
  "docker-helper-${VERSION}-linux-amd64/selinux/docker_helper.pp"
  "docker-helper-${VERSION}-linux-amd64/buildkit/buildkitd"
  "docker-helper-${VERSION}-linux-amd64/buildkit/buildctl"
  "docker-helper-${VERSION}-linux-amd64/buildkit/buildkit-runc"
  "docker-helper-${VERSION}-linux-amd64/buildkit/LICENSE"
  "docker-helper-${VERSION}-linux-amd64/buildkit/MANIFEST"
  "docker-helper-${VERSION}-linux-amd64/scripts/provision-builder.sh"
  "docker-helper-${VERSION}-linux-amd64/skills/docker-helper/SKILL.md"
  "docker-helper-${VERSION}-linux-amd64/man/docker-helper.1.gz"
  "docker-helper-${VERSION}-linux-amd64/man/docker-helper-config.5.gz"
  "docker-helper-${VERSION}-linux-amd64/completions/docker-helper"
)

TARBALL_CONTENTS=$(tar tzf "$TARBALL")

for expected in "${EXPECTED_PATHS[@]}"; do
  if ! echo "$TARBALL_CONTENTS" | grep -qxF "$expected"; then
    echo "FAIL: tarball missing required path: $expected" >&2
    exit 1
  fi
done
echo "OK: tarball contains all required paths"

# Check canonical numeric ownership: every archive entry — files AND
# directories — must be owned 0:0, independent of the build environment.
# GNU tar with --numeric-owner lists the owner as <uid>/<gid> (0/0).
NON_ROOT_OWN=$(tar tzvf "$TARBALL" | awk '!($2 == "0/0") { print $2 "\t" $6 }')
if [[ -n "$NON_ROOT_OWN" ]]; then
  echo "FAIL: tarball entries are not owned 0:0:" >&2
  echo "$NON_ROOT_OWN" >&2
  exit 1
fi
echo "OK: all tarball entries (files and directories) owned 0:0"

# Check executable bits for files that must be executable.
for f in docker-helper install-system.sh uninstall-system.sh \
         buildkit/buildkitd buildkit/buildctl buildkit/buildkit-runc \
         scripts/provision-builder.sh; do
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
