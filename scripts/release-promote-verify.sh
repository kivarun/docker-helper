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
# Verifies the exact candidate set identity:
#   actual artifacts == SHA256SUMS filenames == candidate.manifest artifact
#   filenames, for exactly one tarball / one DEB / one RPM, with no duplicates,
#   no missing artifact and no extra artifact or checksum entry.
#
# SHA256SUMS (producer-owned, never regenerated):
#   * exactly 3 entries;
#   * every entry carries a valid SHA-256 digest;
#   * filenames are exactly the three actual artifact basenames, each occurring
#     exactly once, with no other filename present;
#   * no absolute, directory-qualified or path-traversal filenames;
#   * sha256sum --check still verifies the actual bytes.
#
# candidate.manifest (producer-owned, never rewritten):
#   * exactly one source_sha=, version=, tarball=, deb= and rpm= entry;
#   * duplicate, missing or unrecognized keys are fatal;
#   * source_sha == SOURCE_SHA (mismatch is fatal);
#   * version == VERSION (mismatch is fatal);
#   * TAG version == VERSION (mismatch is fatal);
#   * each artifact entry's filename equals the actual artifact basename and its
#     checksum equals the corresponding SHA256SUMS entry.
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

tar_name="${tars[0]##*/}"
deb_name="${debs[0]##*/}"
rpm_name="${rpms[0]##*/}"

# --- SHA256SUMS exact contract -------------------------------------------------
# Parse the producer-owned SHA256SUMS and prove the set identity:
#   SHA256SUMS filenames == exactly {tar_name, deb_name, rpm_name}, each once.
declare -A sha_entry_count
declare -A sha_entry_digest
sha_entry_total=0
while IFS= read -r line || [ -n "$line" ]; do
  [ -n "${line//[[:space:]]/}" ] || continue
  sha_entry_total=$((sha_entry_total + 1))
  digest="${line%%[[:space:]]*}"
  filename="${line#*[[:space:]]}"
  filename="${filename#"${filename%%[![:space:]]*}"}"
  if ! printf '%s' "$digest" | grep -qE '^[0-9a-f]{64}$'; then
    fail "SHA256SUMS contains an invalid SHA-256 digest: '$line'"
  fi
  case "$filename" in
    */*|""|.|..) fail "SHA256SUMS contains an invalid artifact path: '$line'" ;;
  esac
  if [ -n "${sha_entry_count[$filename]+x}" ]; then
    sha_entry_count[$filename]=$(( sha_entry_count[$filename] + 1 ))
  else
    sha_entry_count[$filename]=1
  fi
  sha_entry_digest[$filename]="$digest"
done < "$CANDIDATE_DIR/SHA256SUMS"

[ "$sha_entry_total" -eq 3 ] \
  || fail "SHA256SUMS must contain exactly 3 entries (found $sha_entry_total)"
for name in "$tar_name" "$deb_name" "$rpm_name"; do
  [ -n "${sha_entry_count[$name]+x}" ] \
    || fail "SHA256SUMS has no checksum entry for $name"
  [ "${sha_entry_count[$name]}" -eq 1 ] \
    || fail "SHA256SUMS contains duplicate checksum entries for $name"
done
[ "${#sha_entry_count[@]}" -eq 3 ] \
  || fail "SHA256SUMS references artifacts outside the candidate set"

tar_sha="${sha_entry_digest[$tar_name]}"
deb_sha="${sha_entry_digest[$deb_name]}"
rpm_sha="${sha_entry_digest[$rpm_name]}"

# Verify the actual bytes against the producer-owned checksums (read-only;
# SHA256SUMS is never regenerated).
( cd "$CANDIDATE_DIR" && sha256sum --check SHA256SUMS ) || fail "SHA256SUMS verification failed"

# --- candidate.manifest exact contract ----------------------------------------
# Require exactly one source_sha=, version=, tarball=, deb= and rpm= entry:
# missing, duplicate or unrecognized entries are fatal. The verifier must not
# merely iterate over whatever artifact keys happen to be present.
declare -A manifest_seen
manifest_source_sha=""
manifest_version=""
manifest_tar=""
manifest_deb=""
manifest_rpm=""
while IFS= read -r line || [ -n "$line" ]; do
  [ -n "${line//[[:space:]]/}" ] || continue
  case "$line" in
    source_sha=*) key="source_sha"; value="${line#source_sha=}" ;;
    version=*)    key="version";    value="${line#version=}" ;;
    tarball=*)    key="tarball";    value="${line#tarball=}" ;;
    deb=*)        key="deb";        value="${line#deb=}" ;;
    rpm=*)        key="rpm";        value="${line#rpm=}" ;;
    *) fail "candidate.manifest contains an unrecognized entry: '$line'" ;;
  esac
  if [ -n "${manifest_seen[$key]+x}" ]; then
    fail "candidate.manifest contains duplicate $key entries"
  fi
  manifest_seen[$key]=1
  case "$key" in
    source_sha) manifest_source_sha="$value" ;;
    version)    manifest_version="$value" ;;
    tarball)    manifest_tar="$value" ;;
    deb)        manifest_deb="$value" ;;
    rpm)        manifest_rpm="$value" ;;
  esac
done < "$CANDIDATE_DIR/candidate.manifest"

for key in source_sha version tarball deb rpm; do
  [ -n "${manifest_seen[$key]+x}" ] || fail "candidate.manifest is missing $key"
done

[ -n "$manifest_source_sha" ] || fail "candidate.manifest is missing source_sha value"
[ -n "$manifest_version" ] || fail "candidate.manifest is missing version value"

[ "$manifest_source_sha" = "$SOURCE_SHA" ] \
  || fail "candidate source SHA mismatch: manifest '$manifest_source_sha' != expected '$SOURCE_SHA'"
[ "$manifest_version" = "$VERSION" ] \
  || fail "candidate version mismatch: manifest '$manifest_version' != expected '$VERSION'"

if [ -n "$TAG" ]; then
  tag_version="${TAG#v}"
  [ "$tag_version" = "$VERSION" ] \
    || fail "tag version mismatch: tag '$TAG' -> '$tag_version' != version '$VERSION'"
fi

# Artifact entries must name the actual artifacts and carry the SHA256SUMS
# checksums (mismatch is fatal).
check_artifact_entry() {
  local key="$1" entry="$2" actual="$3" recorded_sha="$4"
  local name sha rest
  [ -n "$entry" ] || fail "candidate.manifest $key entry is empty"
  read -r name sha rest <<< "$entry"
  [ -n "$name" ] && [ -n "$sha" ] && [ -z "$rest" ] \
    || fail "malformed candidate.manifest $key entry: '$entry'"
  [ "$name" = "$actual" ] \
    || fail "candidate.manifest $key filename '$name' != actual artifact '$actual'"
  [ "$sha" = "$recorded_sha" ] \
    || fail "candidate.manifest $key checksum '$sha' != SHA256SUMS '$recorded_sha'"
}

check_artifact_entry tarball "$manifest_tar" "$tar_name" "$tar_sha"
check_artifact_entry deb     "$manifest_deb" "$deb_name" "$deb_sha"
check_artifact_entry rpm     "$manifest_rpm" "$rpm_name" "$rpm_sha"

echo "=== candidate verification OK ==="
echo "source_sha: $manifest_source_sha"
echo "version:    $manifest_version"
echo "tarball:    $tar_name $tar_sha"
echo "deb:        $deb_name $deb_sha"
echo "rpm:        $rpm_name $rpm_sha"
[ -z "$TAG" ] || echo "tag:        $TAG (version matches)"
echo "=== safe to publish these exact bytes (no rebuild; SHA256SUMS not regenerated) ==="
