#!/usr/bin/env bash
#
# release-candidate-artifact.sh — resolve ONE artifact of a given type from a
# staged candidate set and report its producer-recorded SHA-256.
#
# Usage:
#   scripts/release-candidate-artifact.sh CANDIDATE_DIR deb|rpm|tar
#
# Prints: "<absolute-path-to-artifact> <sha256-from-SHA256SUMS>"
#
# The expected SHA-256 is read from the producer-owned SHA256SUMS (never
# recomputed-and-trusted), and the on-disk file is also re-hashed and must
# match, so a consumer fails fast before install if the transport altered the
# bytes. Consumers of every artifact type (DEB, RPM, tarball) use this single
# resolver, guaranteeing they consume the exact candidate bytes.
#
# Exit status: 0 on success; non-zero fails closed.

set -euo pipefail

CANDIDATE_DIR="${1:-}"
TYPE="${2:-}"

[ -n "$CANDIDATE_DIR" ] || { echo "error: CANDIDATE_DIR is required" >&2; exit 1; }
[ -d "$CANDIDATE_DIR" ] || { echo "error: candidate dir does not exist: $CANDIDATE_DIR" >&2; exit 1; }

case "$TYPE" in
  deb) pattern='*.deb' ;;
  rpm) pattern='*.rpm' ;;
  tar) pattern='*.tar.gz' ;;
  *)   echo "error: unknown artifact type '$TYPE' (expected deb|rpm|tar)" >&2; exit 1 ;;
esac

[ -f "$CANDIDATE_DIR/SHA256SUMS" ] || { echo "error: SHA256SUMS missing in candidate set: $CANDIDATE_DIR" >&2; exit 1; }

shopt -s nullglob
files=( "$CANDIDATE_DIR"/$pattern )
[ "${#files[@]}" -eq 1 ] \
  || { echo "error: expected exactly one $pattern in $CANDIDATE_DIR (found ${#files[@]})" >&2; exit 1; }

file="${files[0]}"
name="$(basename "$file")"

sha="$(awk -v f="$name" '$2==f {print $1}' "$CANDIDATE_DIR/SHA256SUMS")"
[ -n "$sha" ] || { echo "error: no SHA256SUMS entry for $name" >&2; exit 1; }

now="$(sha256sum "$file" | awk '{print $1}')"
[ "$now" = "$sha" ] || { echo "error: $name hash mismatch (expected $sha, got $now)" >&2; exit 1; }

printf '%s %s\n' "$file" "$sha"
