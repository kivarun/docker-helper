#!/usr/bin/env bash
# build-selinux-policy.sh — compile and package the docker-helper SELinux
# policy module into a .pp.
#
# Usage:
#   ./build-selinux-policy.sh [OUTDIR]
#
# OUTDIR (default: dist) receives docker_helper.pp. This is the SINGLE
# canonical owner of SELinux policy compilation for the release artifacts: it
# is called by build-packages.sh (RPM/DEB) and build-bundle.sh (release
# tarball), so every artifact always carries the byte-identical docker_helper.pp
# compiled from the authoritative packaging/selinux/docker-helper.{te,fc}.
# There is deliberately no second policy-compilation path anywhere.
#
# - Fails (non-zero) when checkmodule or semodule_package is missing.
# - Removes stale docker_helper.mod/.pp and the legacy docker-helper.pp from
#   OUTDIR before building, so a stale artifact from an older checkout or
#   build can never satisfy this build.
# - Fails if the produced docker_helper.pp is missing or empty.
#
# Output: OUTDIR/docker_helper.pp

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${1:-$SCRIPT_DIR/dist}"

for cmd in checkmodule semodule_package; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: $cmd not found (install checkpolicy / policycoreutils-devel / semodule-utils)" >&2
    exit 1
  fi
done

TE_FILE="$SCRIPT_DIR/packaging/selinux/docker-helper.te"
FC_FILE="$SCRIPT_DIR/packaging/selinux/docker-helper.fc"
for f in "$TE_FILE" "$FC_FILE"; do
  if [ ! -f "$f" ]; then
    echo "error: $f not found" >&2
    exit 1
  fi
done

mkdir -p "$OUT_DIR"

# Remove any previous generated output so a stale .pp/.mod from an older
# checkout/build cannot satisfy this build. Clean both the current
# docker_helper.pp and the legacy docker-helper.pp.
rm -f "$OUT_DIR/docker_helper.mod" "$OUT_DIR/docker_helper.pp" "$OUT_DIR/docker-helper.pp"

MOD="$OUT_DIR/docker_helper.mod"
PP="$OUT_DIR/docker_helper.pp"

echo "Building SELinux policy module (docker_helper.pp)..."
checkmodule -M -m -o "$MOD" "$TE_FILE"
semodule_package -o "$PP" -m "$MOD" -f "$FC_FILE"
rm -f "$MOD"

if [ ! -s "$PP" ]; then
  echo "error: SELinux policy artifact not produced or empty: $PP" >&2
  exit 1
fi
echo "SELinux policy module: $PP"
