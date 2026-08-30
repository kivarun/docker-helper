#!/usr/bin/env bash
#
# release-promote-verify.sh — promotion-time verification of a staged candidate
# set. PROMOTION ONLY: it never builds, never invokes any authoritative build
# machinery, never regenerates generated artifacts, and never regenerates
# SHA256SUMS. It verifies the EXACT candidate bytes produced before UAT and lets
# the caller publish those same bytes.
#
# Usage:
#   scripts/release-promote-verify.sh CANDIDATE_DIR VERSION SOURCE_SHA [TAG]
#
#   CANDIDATE_DIR  staged immutable candidate set (download before calling)
#   VERSION        expected product version
#   SOURCE_SHA     expected source commit SHA (GITHUB_SHA)
#   TAG            optional release tag (e.g. v2.0.0); when given, the tag's
#                  version must equal VERSION.
#
# Verifies:
#   * exactly one tarball / DEB / RPM in the candidate set;
#   * SHA256SUMS exists and every entry checks (producer-owned, not
#     regenerated);
#   * SHA256SUMS covers exactly the three artifacts and nothing else;
#   * candidate.manifest.source_sha == SOURCE_SHA (mismatch is fatal);
#   * candidate.manifest.version == VERSION (mismatch is fatal);
#   * TAG version == VERSION (mismatch is fatal);
#   * manifest checksums match the SHA256SUMS entries.
#
# Exit status: 0 => candidate verified, safe to publish; non-zero => never
# publish these bytes.

set -euo pipefail

CANDIDATE_DIR="${1:-}"
VERSION="${2:-}"
SOURCE_SHA="${3:-}"
TAG="${4:-}"

fail() { echo "error: $*" >&2; exit 1; }

[ -n "$CANDIDATE_DIR" ] && [ -d "$CANDIDATE_DIR" ] || fail "CANDIDATE_DIR is required and must exist"
[ -n "$VERSION" ] || fail "VERSION is required"
[ -n "$SOURCE_SHA" ] || fail "SOURCE_SHA is required"

[ -f "$CANDIDATE_DIR/SHA256SUMS" ] || fail "SHA256SUMS missing in candidate set"
[ -f "$CANDIDATE_DIR/candidate.manifest" ] || fail "candidate.manifest missing in candidate set"

# Exactly one artifact of each type.
shopt -s nullglob
tars=( "$CANDIDATE_DIR"/*.tar.gz )
debs=( "$CANDIDATE_DIR"/*.deb )
rpms=( "$CANDIDATE_DIR"/*.rpm )
[ "${#tars[@]}" -eq 1 ] || fail "candidate set must contain exactly one tarball (found ${#tars[@]})"
[ "${#debs[@]}" -eq 1 ] || fail "candidate set must contain exactly one DEB (found ${#debs[@]})"
[ "${#rpms[@]}" -eq 1 ] || fail "candidate set must contain exactly one RPM (found ${#rpms[@]})"

# Verify the producer-owned SHA256SUMS (read-only; never regenerate it).
( cd "$CANDIDATE_DIR" && sha256sum --check SHA256SUMS ) || fail "SHA256SUMS verification failed"

# SHA256SUMS must cover exactly the three artifacts.
entry_count="$(grep -vc '^[[:space:]]*$' "$CANDIDATE_DIR/SHA256SUMS" || true)"
[ "$entry_count" = "3" ] \
  || fail "SHA256SUMS must contain exactly 3 entries (found $entry_count)"

# Candidate metadata binding.
source_sha="$(sed -n 's/^source_sha=//p' "$CANDIDATE_DIR/candidate.manifest")"
manifest_version="$(sed -n 's/^version=//p' "$CANDIDATE_DIR/candidate.manifest")"
[ -n "$source_sha" ] || fail "candidate.manifest is missing source_sha"
[ -n "$manifest_version" ] || fail "candidate.manifest is missing version"

[ "$source_sha" = "$SOURCE_SHA" ] \
  || fail "candidate source SHA mismatch: manifest '$source_sha' != expected '$SOURCE_SHA'"
[ "$manifest_version" = "$VERSION" ] \
  || fail "candidate version mismatch: manifest '$manifest_version' != expected '$VERSION'"

if [ -n "$TAG" ]; then
  tag_version="${TAG#v}"
  [ "$tag_version" = "$VERSION" ] \
    || fail "tag version mismatch: tag '$TAG' -> '$tag_version' != version '$VERSION'"
fi

# Manifest checksums must match the SHA256SUMS entries.
while IFS= read -r line; do
  case "$line" in
    tarball=*) name="${line#tarball=}"; name="${name%% *}"; sha="${line##* }" ;;
    deb=*)     name="${line#deb=}";     name="${name%% *}"; sha="${line##* }" ;;
    rpm=*)     name="${line#rpm=}";     name="${name%% *}"; sha="${line##* }" ;;
    *)         continue ;;
  esac
  [ -n "$name" ] && [ -n "$sha" ] || fail "malformed candidate.manifest line: $line"
  recorded="$(awk -v f="$name" '$2==f {print $1}' "$CANDIDATE_DIR/SHA256SUMS")"
  [ "$recorded" = "$sha" ] \
    || fail "candidate.manifest checksum for $name does not match SHA256SUMS"
done < "$CANDIDATE_DIR/candidate.manifest"

echo "=== candidate verification OK ==="
echo "source_sha: $source_sha"
echo "version:    $manifest_version"
echo "tarball:    ${tars[0]##*/} $(awk -v f="${tars[0]##*/}" '$2==f{print $1}' "$CANDIDATE_DIR/SHA256SUMS")"
echo "deb:        ${debs[0]##*/} $(awk -v f="${debs[0]##*/}" '$2==f{print $1}' "$CANDIDATE_DIR/SHA256SUMS")"
echo "rpm:        ${rpms[0]##*/} $(awk -v f="${rpms[0]##*/}" '$2==f{print $1}' "$CANDIDATE_DIR/SHA256SUMS")"
[ -z "$TAG" ] || echo "tag:        $TAG (version matches)"
echo "=== safe to publish these exact bytes (no rebuild; SHA256SUMS not regenerated) ==="
