#!/usr/bin/env bash
#
# release-candidate.sh — canonical release-candidate producer for docker-helper.
#
# Single owner of the shared release payload. It builds the payload EXACTLY
# ONCE through the canonical builders, stages it as an immutable payload
# directory, and every artifact builder then only ASSEMBLES its format from
# those same bytes — the tarball, the DEB and the RPM all carry one shared
# payload:
#
#   docker-helper-<version>-linux-amd64.tar.gz
#   docker-helper_<version>_amd64.deb
#   docker-helper-<version>-<release>.x86_64.rpm
#   SHA256SUMS            (producer-owned; generated exactly once)
#   candidate.manifest    (binds SOURCE_SHA + VERSION + checksums)
#
# Shared payload build (once, through the authoritative single owners):
#
#   build-static.sh          -> dist/docker-helper        (static binary)
#   build-selinux-policy.sh  -> dist/docker_helper.pp    (SELinux module)
#   build-manpages.sh        -> dist/man/*.gz            (man pages)
#   <built binary> completion bash -> Bash completion
#
# staged into dist/payload/ and handed to the assemblers:
#
#   build-bundle.sh   VERSION --payload dist/payload   (tarball)
#   build-packages.sh VERSION --payload dist/payload   (DEB + RPM)
#
# This is the SINGLE producer of the release artifacts. It builds only through
# the authoritative underlying builders and never reimplements package
# building. After building it validates exactly-one tarball/DEB/RPM, verifies
# binary version and package identity, extracts the shared payload members
# from every format and compares SHA-256 (byte-identical payload across
# tar/DEB/RPM, fail closed on any mismatch), generates SHA256SUMS once,
# verifies it, and stages the immutable candidate set. No other job/step may
# construct these artifacts or regenerate SHA256SUMS; consumers and promotion
# only download the staged bytes and verify against this SHA256SUMS.
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
# rpm2cpio + cpio extract the RPM payload for the shared-payload identity check.
for cmd in sha256sum file tar dpkg-deb rpm rpm2cpio cpio; do
  command -v "$cmd" >/dev/null 2>&1 || fail "$cmd not found (required for release-candidate verification)"
done
# The RPM payload extraction needs the GNU --no-absolute-filenames option;
# a busybox cpio cannot extract the absolute-entry-name payload and must not
# satisfy this producer.
cpio --version >/dev/null 2>&1 \
  || fail "GNU cpio required for RPM payload extraction (busybox cpio lacks --no-absolute-filenames)"

# --- Clean dist --------------------------------------------------------------

rm -rf "$DIST_DIR"

# --- Build the shared release payload exactly once ----------------------------
# Single owner: the payload members are built through the canonical builders
# and staged into an immutable payload directory; every artifact builder only
# assembles its format from these same bytes.

PAYLOAD_DIR="$DIST_DIR/payload"
rm -rf "$PAYLOAD_DIR"
mkdir -p "$PAYLOAD_DIR/man" "$PAYLOAD_DIR/completions"

echo "=== Building shared release payload (single build) ==="
echo "--- static binary (build-static.sh) ---"
"$REPO_ROOT/build-static.sh" "$VERSION" || fail "build-static.sh $VERSION failed"
echo "--- SELinux policy (build-selinux-policy.sh) ---"
"$REPO_ROOT/build-selinux-policy.sh" "$DIST_DIR" || fail "build-selinux-policy.sh failed"
echo "--- man pages (build-manpages.sh) ---"
"$REPO_ROOT/build-manpages.sh" || fail "build-manpages.sh failed"
echo "--- Bash completion (from the built binary) ---"
mkdir -p "$DIST_DIR/completions"
"$DIST_DIR/docker-helper" completion bash > "$DIST_DIR/completions/docker-helper" \
  || fail "completion generation failed"
[ -s "$DIST_DIR/completions/docker-helper" ] \
  || fail "completion generation produced empty output"

# Stage the immutable shared payload; fail closed on any missing member.
cp "$DIST_DIR/docker-helper" "$PAYLOAD_DIR/docker-helper"
cp "$DIST_DIR/docker_helper.pp" "$PAYLOAD_DIR/docker_helper.pp"
cp "$DIST_DIR/man/docker-helper.1.gz" "$PAYLOAD_DIR/man/docker-helper.1.gz"
cp "$DIST_DIR/man/docker-helper-config.5.gz" "$PAYLOAD_DIR/man/docker-helper-config.5.gz"
cp "$DIST_DIR/completions/docker-helper" "$PAYLOAD_DIR/completions/docker-helper"
for member in docker-helper docker_helper.pp man/docker-helper.1.gz \
  man/docker-helper-config.5.gz completions/docker-helper; do
  [ -s "$PAYLOAD_DIR/$member" ] || fail "shared payload member missing or empty: $member"
done
chmod -R a-w "$PAYLOAD_DIR"
# The payload is immutable while the producer runs; the EXIT trap restores
# write permission so a later run can clean dist/ again.
trap 'chmod -R u+w "$PAYLOAD_DIR" 2>/dev/null || true' EXIT
echo "OK: shared release payload staged at $PAYLOAD_DIR (built exactly once)"

# --- Assemble each release artifact from the shared payload -------------------

echo "=== Assembling release tarball (build-bundle.sh) ==="
"$REPO_ROOT/build-bundle.sh" "$VERSION" --payload "$PAYLOAD_DIR" \
  || fail "build-bundle.sh $VERSION failed"

echo "=== Assembling DEB + RPM (build-packages.sh) ==="
"$REPO_ROOT/build-packages.sh" "$VERSION" --payload "$PAYLOAD_DIR" \
  || fail "build-packages.sh $VERSION failed"

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

# --- Verify tarball canonical numeric ownership --------------------------------
# Every archive entry (files AND directories) must carry canonical numeric
# ownership 0:0 so the release tarball is byte-identical in ownership regardless
# of the build environment. Fail closed on any non-root entry.
NON_ROOT_OWN="$(tar tzvf "$TARBALL" | awk '!($2 == "0/0") { print $2 "\t" $6 }')"
[ -z "$NON_ROOT_OWN" ] || fail "tarball entries not owned 0:0:"$'\n'"$NON_ROOT_OWN"
echo "OK: tarball entries (files and directories) owned 0:0"

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

# --- Verify shared payload identity across formats -----------------------------
# The shared payload was built exactly once; every format must carry
# byte-identical copies of each payload member it ships. Extract from the
# final artifacts and compare SHA-256 member by member. A member intentionally
# absent from a format (for example the DEB does not ship the SELinux policy
# module) is not a mismatch — only the common surface is compared. Any
# mismatch fails closed: mixed-payload artifacts must never be staged.

PAYLOAD_VERIFY_DIR="$(mktemp -d)"
mkdir -p "$PAYLOAD_VERIFY_DIR/tar" "$PAYLOAD_VERIFY_DIR/deb" "$PAYLOAD_VERIFY_DIR/rpm"

tar xzf "$TARBALL" -C "$PAYLOAD_VERIFY_DIR/tar" \
  || fail "cannot extract tarball for payload identity verification"
dpkg-deb -x "$DEB" "$PAYLOAD_VERIFY_DIR/deb" \
  || fail "cannot extract DEB for payload identity verification"
# nFPM's RPM payload carries ABSOLUTE cpio entry names; --no-absolute-filenames
# extracts them under the verification directory instead of the real system
# paths (a non-root producer must never write to /).
#
# rpm2cpio's exit status is deliberately NOT trusted: on the producer platform
# (Ubuntu noble, rpm 4.18.2) rpm2cpio writes the complete payload and exits 1
# on SUCCESS (upstream rpm2cpio exit-status bug; proven by the diagnostic run
# — full valid payload, exit 1, GNU cpio 2.15 extracts it cleanly). The
# authoritative fail-closed gate is cpio itself: an empty, truncated, or
# garbage payload always makes cpio exit non-zero, and the member-existence
# checks below catch any missing file.
rpm2cpio "$RPM" > "$PAYLOAD_VERIFY_DIR/payload.cpio" 2>"$PAYLOAD_VERIFY_DIR/rpm2cpio.err" \
  || true
if [ ! -s "$PAYLOAD_VERIFY_DIR/payload.cpio" ]; then
  fail "rpm2cpio produced no RPM payload for payload identity verification: $(head -c 400 "$PAYLOAD_VERIFY_DIR/rpm2cpio.err" 2>/dev/null)"
fi
if ! ( cd "$PAYLOAD_VERIFY_DIR/rpm" \
       && cpio -idmu --no-absolute-filenames --quiet < "$PAYLOAD_VERIFY_DIR/payload.cpio" ) \
       2>"$PAYLOAD_VERIFY_DIR/cpio.err"; then
  fail "cannot extract RPM payload for payload identity verification: $(head -c 400 "$PAYLOAD_VERIFY_DIR/cpio.err" 2>/dev/null)"
fi

TAR_MEMBER_ROOT="$PAYLOAD_VERIFY_DIR/tar/docker-helper-${VERSION}-linux-amd64"

# <member> <tarball-path-under-bundle-root|-> <deb-path|-> <rpm-path|->
PAYLOAD_MEMBERS=(
  "binary docker-helper usr/bin/docker-helper usr/bin/docker-helper"
  "man1 man/docker-helper.1.gz usr/share/man/man1/docker-helper.1.gz usr/share/man/man1/docker-helper.1.gz"
  "man5 man/docker-helper-config.5.gz usr/share/man/man5/docker-helper-config.5.gz usr/share/man/man5/docker-helper-config.5.gz"
  "completion completions/docker-helper usr/share/bash-completion/completions/docker-helper usr/share/bash-completion/completions/docker-helper"
  "selinux-policy selinux/docker_helper.pp - usr/share/selinux/docker_helper.pp"
)

for entry in "${PAYLOAD_MEMBERS[@]}"; do
  read -r member tar_rel deb_rel rpm_rel <<< "$entry"
  observed=""
  if [ "$tar_rel" != "-" ]; then
    tar_member="$TAR_MEMBER_ROOT/$tar_rel"
    [ -s "$tar_member" ] || fail "payload identity check: tarball missing member '$member'"
    sha="$(sha256sum "$tar_member" | awk '{print $1}')"
    observed="$observed tar=$sha"
  fi
  if [ "$deb_rel" != "-" ]; then
    deb_member="$PAYLOAD_VERIFY_DIR/deb/$deb_rel"
    [ -s "$deb_member" ] || fail "payload identity check: DEB missing member '$member' at $deb_rel"
    sha="$(sha256sum "$deb_member" | awk '{print $1}')"
    observed="$observed deb=$sha"
  fi
  if [ "$rpm_rel" != "-" ]; then
    rpm_member="$PAYLOAD_VERIFY_DIR/rpm/$rpm_rel"
    [ -s "$rpm_member" ] || fail "payload identity check: RPM missing member '$member' at $rpm_rel"
    sha="$(sha256sum "$rpm_member" | awk '{print $1}')"
    observed="$observed rpm=$sha"
  fi
  distinct="$(printf '%s\n' "$observed" | tr -s ' ' '\n' | sed 's/^tar=//;s/^deb=//;s/^rpm=//' | sort -u)"
  [ "$(printf '%s\n' "$distinct" | grep -c .)" -eq 1 ] \
    || fail "shared payload identity mismatch for member '$member' ($observed)"
  echo "OK: shared payload member '$member' byte-identical across formats"
done

rm -rf "$PAYLOAD_VERIFY_DIR"

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
