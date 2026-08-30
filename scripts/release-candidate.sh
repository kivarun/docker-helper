#!/usr/bin/env bash
#
# release-candidate.sh — canonical release-candidate producer for docker-helper.
#
# Builds the complete releasable set EXACTLY ONCE and stages it as an
# immutable candidate set:
#
#   docker-helper-<version>-linux-amd64.tar.gz
#   docker-helper_<version>_amd64.deb
#   docker-helper-<version>-<release>.x86_64.rpm
#   SHA256SUMS            (producer-owned; generated exactly once)
#   candidate.manifest    (binds SOURCE_SHA + VERSION + checksums)
#
# Usage:
#   scripts/release-candidate.sh VERSION SOURCE_SHA
#
#   VERSION     semver without a leading 'v' (e.g. 2.0.0 or 2.0.0-uat).
#   SOURCE_SHA  full 40-hex commit SHA the candidate is built from.
#
# This is the SINGLE producer of the release artifacts. It builds only through
# the authoritative underlying builders and never reimplements package
# building:
#
#   build-bundle.sh    -> release tarball (+ static binary + SELinux module)
#   build-packages.sh  -> DEB + RPM (+ static binary + SELinux module)
#
# After building it validates exactly-one tarball/DEB/RPM, verifies binary
# version and package identity, generates SHA256SUMS once, verifies it, and
# stages the immutable candidate set. No other job/step may construct these
# artifacts or regenerate SHA256SUMS; consumers and promotion only download the
# staged bytes and verify against this SHA256SUMS.
#
# Env:
#   RELEASE_CANDIDATE_DIR  staging directory (default: <repo>/dist/candidate)
#
# Exit status: 0 on success; non-zero fails closed on any validation error.

set -euo pipefail

VERSION="${1:-}"
SOURCE_SHA="${2:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$REPO_ROOT/dist"
CANDIDATE_DIR="${RELEASE_CANDIDATE_DIR:-$DIST_DIR/candidate}"

fail() { echo "error: $*" >&2; exit 1; }

# --- Validate inputs ---------------------------------------------------------

if [ -z "$VERSION" ]; then
  fail "VERSION is required: $0 VERSION SOURCE_SHA"
fi
if ! printf '%s' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$'; then
  fail "invalid VERSION '$VERSION' (expected MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-PRERELEASE)"
fi
if [ -z "$SOURCE_SHA" ]; then
  fail "SOURCE_SHA is required: $0 VERSION SOURCE_SHA"
fi
if ! printf '%s' "$SOURCE_SHA" | grep -qE '^[0-9a-f]{40}$'; then
  fail "invalid SOURCE_SHA '$SOURCE_SHA' (expected 40 hex chars)"
fi

# Required tooling for identity verification below (the builders bring their
# own build tooling). rpm is required even though the producer runs on Ubuntu:
# build-packages.sh emits an RPM and the producer verifies its identity.
for cmd in sha256sum file tar dpkg-deb rpm; do
  command -v "$cmd" >/dev/null 2>&1 || fail "$cmd not found (required for release-candidate verification)"
done

# --- Clean dist --------------------------------------------------------------

rm -rf "$DIST_DIR"

# --- Build each release artifact only here -----------------------------------

echo "=== Building release tarball (build-bundle.sh) ==="
"$REPO_ROOT/build-bundle.sh" "$VERSION" || fail "build-bundle.sh $VERSION failed"

echo "=== Building DEB + RPM (build-packages.sh) ==="
"$REPO_ROOT/build-packages.sh" "$VERSION" || fail "build-packages.sh $VERSION failed"

# --- Validate exactly one artifact of each type ------------------------------

shopt -s nullglob
tars=( "$DIST_DIR"/*.tar.gz )
debs=( "$DIST_DIR"/*.deb )
rpms=( "$DIST_DIR"/*.rpm )
[ "${#tars[@]}" -eq 1 ] || fail "expected exactly one *.tar.gz in dist/ (found ${#tars[@]})"
[ "${#debs[@]}" -eq 1 ] || fail "expected exactly one *.deb in dist/ (found ${#debs[@]})"
[ "${#rpms[@]}" -eq 1 ] || fail "expected exactly one *.rpm in dist/ (found ${#rpms[@]})"

TARBALL="${tars[0]}"
DEB="${debs[0]}"
RPM="${rpms[0]}"

# --- Verify binary version ----------------------------------------------------

[ -x "$DIST_DIR/docker-helper" ] || fail "dist/docker-helper not found or not executable"
BIN_VERSION="$("$DIST_DIR/docker-helper" version)"
[ "$BIN_VERSION" = "$VERSION" ] \
  || fail "binary version mismatch: expected '$VERSION', got '$BIN_VERSION'"

# --- Verify tarball (light re-check; build-bundle.sh already verifies fully) --

tar tzf "$TARBALL" >/dev/null 2>&1 || fail "tarball is corrupt or unreadable: $TARBALL"

# --- Verify DEB identity -------------------------------------------------------

# NOTE: grep is used WITHOUT -q here. With set -o pipefail, `grep -q` closes the
# pipe as soon as it matches, giving the upstream writer (dpkg-deb's tar
# subprocess) a SIGPIPE/write error that fails the whole pipeline. Reading the
# full listing keeps the pipeline exit status on grep's result.
dpkg-deb --info "$DEB" | grep -F "Package: docker-helper" >/dev/null \
  || fail "DEB is not the docker-helper package: $DEB"
dpkg-deb --info "$DEB" | grep -F "Architecture: amd64" >/dev/null \
  || fail "DEB is not amd64: $DEB"
for path in /usr/bin/docker-helper /usr/lib/systemd/system/docker-helper.service \
  /etc/apparmor.d/docker-helper-system /usr/share/man/man1/docker-helper.1.gz \
  /usr/share/man/man5/docker-helper-config.5.gz /usr/share/doc/docker-helper/LICENSE; do
  dpkg-deb --contents "$DEB" | grep -F "$path" >/dev/null || fail "DEB missing $path"
done

# --- Verify RPM identity -------------------------------------------------------

[ "$(rpm -qp --queryformat '%{NAME}' "$RPM")" = "docker-helper" ] \
  || fail "RPM name is not docker-helper: $RPM"
[ "$(rpm -qp --queryformat '%{ARCH}' "$RPM")" = "x86_64" ] \
  || fail "RPM arch is not x86_64: $RPM"
[ "$(rpm -qp --queryformat '%{LICENSE}' "$RPM")" = "GPL-3.0-only" ] \
  || fail "RPM license is not GPL-3.0-only: $RPM"
for path in /usr/bin/docker-helper /usr/lib/systemd/system/docker-helper.service \
  /etc/apparmor.d/docker-helper-system /usr/share/man/man1/docker-helper.1.gz \
  /usr/share/man/man5/docker-helper-config.5.gz /usr/share/doc/docker-helper/LICENSE; do
  rpm -qpl "$RPM" | grep -F "$path" >/dev/null || fail "RPM missing $path"
done

# --- Stage the immutable candidate set ----------------------------------------

rm -rf "$CANDIDATE_DIR"
mkdir -p "$CANDIDATE_DIR"
cp "$TARBALL" "$CANDIDATE_DIR/"
cp "$DEB" "$CANDIDATE_DIR/"
cp "$RPM" "$CANDIDATE_DIR/"

TARBALL_NAME="$(basename "$TARBALL")"
DEB_NAME="$(basename "$DEB")"
RPM_NAME="$(basename "$RPM")"

# --- Generate SHA256SUMS EXACTLY ONCE over the staged artifacts ----------------

( cd "$CANDIDATE_DIR" && sha256sum "$TARBALL_NAME" "$DEB_NAME" "$RPM_NAME" > SHA256SUMS )

# --- Verify SHA256SUMS ---------------------------------------------------------

( cd "$CANDIDATE_DIR" && sha256sum --check SHA256SUMS ) || fail "SHA256SUMS verification failed"

# --- Candidate metadata (binds SOURCE_SHA + VERSION + checksums) ---------------

tar_sha="$(awk -v f="$TARBALL_NAME" '$2==f {print $1}' "$CANDIDATE_DIR/SHA256SUMS")"
deb_sha="$(awk -v f="$DEB_NAME" '$2==f {print $1}' "$CANDIDATE_DIR/SHA256SUMS")"
rpm_sha="$(awk -v f="$RPM_NAME" '$2==f {print $1}' "$CANDIDATE_DIR/SHA256SUMS")"
[ -n "$tar_sha" ] && [ -n "$deb_sha" ] && [ -n "$rpm_sha" ] \
  || fail "could not read checksums from SHA256SUMS"

{
  printf 'source_sha=%s\n' "$SOURCE_SHA"
  printf 'version=%s\n' "$VERSION"
  printf 'tarball=%s %s\n' "$TARBALL_NAME" "$tar_sha"
  printf 'deb=%s %s\n' "$DEB_NAME" "$deb_sha"
  printf 'rpm=%s %s\n' "$RPM_NAME" "$rpm_sha"
} > "$CANDIDATE_DIR/candidate.manifest"

# --- Final check: candidate set contains exactly one of each artifact ----------

cnt_tar="$(ls "$CANDIDATE_DIR"/*.tar.gz 2>/dev/null | wc -l)"
cnt_deb="$(ls "$CANDIDATE_DIR"/*.deb 2>/dev/null | wc -l)"
cnt_rpm="$(ls "$CANDIDATE_DIR"/*.rpm 2>/dev/null | wc -l)"
[ "$cnt_tar" = "1" ] || fail "candidate set must contain exactly one tarball (found $cnt_tar)"
[ "$cnt_deb" = "1" ] || fail "candidate set must contain exactly one DEB (found $cnt_deb)"
[ "$cnt_rpm" = "1" ] || fail "candidate set must contain exactly one RPM (found $cnt_rpm)"

echo "=== Candidate set staged at $CANDIDATE_DIR ==="
echo "source_sha: $SOURCE_SHA"
echo "version:    $VERSION"
echo "--- SHA256SUMS ---"
cat "$CANDIDATE_DIR/SHA256SUMS"
echo "--- candidate.manifest ---"
cat "$CANDIDATE_DIR/candidate.manifest"
echo "=== Candidate ready ==="
