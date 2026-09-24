#!/usr/bin/env bash
# build-buildkit-payload.sh — SINGLE OWNER of the pinned BuildKit payload
# staging for the Release 2.4 build sandbox (implementation plan §7).
#
# Every package format (tarball, DEB, RPM) stages its BuildKit payload through
# this script and this script only, so all formats ship byte-identical payload
# files. It downloads the pinned upstream release tarball, verifies its SHA-256
# BEFORE any staging, extracts exactly the proven executable set (the M0/M1 and
# P4-A1 evidence: buildkitd, buildctl, and the buildkit-runc OCI worker helper
# resolved by buildkitd's defaultCommandCandidates; the CNI and QEMU helpers
# are unused by the slirp4netns composition and are NOT shipped), and stages
# them together with the pinned upstream LICENSE into a /usr-rooted staging
# tree the artifact assemblers consume.
#
# Usage:
#   ./build-buildkit-payload.sh DEST_DIR
#
# Staged layout (DEST_DIR):
#   usr/libexec/docker-helper/buildkit/buildkitd      (0755)
#   usr/libexec/docker-helper/buildkit/buildctl       (0755)
#   usr/libexec/docker-helper/buildkit/buildkit-runc  (0755)
#   usr/share/doc/docker-helper/buildkit/LICENSE      (0644)
#   usr/share/doc/docker-helper/buildkit/MANIFEST     (0644)
#
# MANIFEST records the pinned version + verified digests so the shipped
# payload metadata states its own provenance (plan §7: version + digest
# recorded in package metadata; no runtime download, no third-party
# repository).
#
# Upstream NOTICE: the pinned v0.33.0 tag tree contains NO top-level NOTICE
# file (verified against the tag tree); Apache-2.0 §4(d) only requires
# distributing a NOTICE file when upstream includes one. Only LICENSE is
# shipped; if a future pin adds one, extend the staged set deliberately.
#
# Pinned identity (NOT overridable by environment variables — only the
# artifact source location may be overridden for availability):

set -euo pipefail

BUILDKIT_VERSION="v0.33.0"
BUILDKIT_TARBALL="buildkit-${BUILDKIT_VERSION}.linux-amd64.tar.gz"
BUILDKIT_TARBALL_URL="https://github.com/moby/buildkit/releases/download/${BUILDKIT_VERSION}/${BUILDKIT_TARBALL}"
# Pinned digest: verified against the official release SBOM subject
# (buildkit-v0.33.0.linux-amd64.sbom.json -> digest.sha256) and by
# independent download comparison (P4-A1 proof runs; plan §7).
BUILDKIT_TARBALL_SHA256="b6242896d343100808dcbe37565caf381e0a444a6a83d7255926bb1519248ead"
BUILDKIT_LICENSE_URL="https://raw.githubusercontent.com/moby/buildkit/${BUILDKIT_VERSION}/LICENSE"
# Computed from the pinned v0.33.0 tag raw fetch (and re-verified on every
# staging run against this constant).
BUILDKIT_LICENSE_SHA256="c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
# Executable digests inside the pinned tarball (identical to the P4-A1
# proof-recorded payload SHAs; the verify-first re-staging path checks them
# so a second assembler pass reuses the first one's verified staging).
BUILDKITD_SHA256="157da954fa081d9ec4f063d62029fbbf12437c1d47ab63080594eae5a85b36f2"
BUILDCTL_SHA256="0b45ae3696f836bf711dbd78138e403924d7733f0b2328ba29a7fcf9ad5f1dfd"
BUILDKIT_RUNC_SHA256="0acdd302ddc5540b2e445b683661bfada9935c702f9008ffb0481abcda16c9b4"
# The generated MANIFEST is deterministic given the pinned payload bytes; its
# digest is pinned so the verify-first re-staging path covers every member.
BUILDKIT_MANIFEST_SHA256="5d65fac136087c2d865f7d69bc21771055eadb8edc05cbe1ff66db78a4a3a0fd"

fail() { echo "error: $*" >&2; exit 1; }

if [ $# -ne 1 ] || [ -z "${1:-}" ]; then
	fail "usage: $0 DEST_DIR"
fi

DEST_DIR="$1"
mkdir -p "$DEST_DIR" || fail "cannot create staging dir $DEST_DIR"

if ! command -v curl >/dev/null 2>&1; then
	fail "curl not found"
fi
if ! command -v tar >/dev/null 2>&1; then
	fail "tar not found"
fi
if ! command -v sha256sum >/dev/null 2>&1; then
	fail "sha256sum not found"
fi

# Verify-first idempotency: when the staging directory already carries every
# payload member and each file's digest matches the pinned identity, reuse it
# without downloading (both artifact assemblers stage through this owner; the
# second assembler must not re-download what the first already verified).
verify_staged() {
	local dir="$1" member sha expected
	[ -d "$dir" ] || return 1
	for member in \
		usr/libexec/docker-helper/buildkit/buildkitd \
		usr/libexec/docker-helper/buildkit/buildctl \
		usr/libexec/docker-helper/buildkit/buildkit-runc \
		usr/share/doc/docker-helper/buildkit/LICENSE \
		usr/share/doc/docker-helper/buildkit/MANIFEST; do
		[ -s "$dir/$member" ] || return 1
		sha="$(sha256sum "$dir/$member" | awk '{print $1}')"
		case "$member" in
			*/buildkitd) expected="$BUILDKITD_SHA256" ;;
			*/buildctl) expected="$BUILDCTL_SHA256" ;;
			*/buildkit-runc) expected="$BUILDKIT_RUNC_SHA256" ;;
			*/LICENSE) expected="$BUILDKIT_LICENSE_SHA256" ;;
			*/MANIFEST) expected="$BUILDKIT_MANIFEST_SHA256" ;;
			*) return 1 ;;
		esac
		[ "$sha" = "$expected" ] || return 1
	done
	return 0
}

if verify_staged "$DEST_DIR"; then
	echo "OK: pinned BuildKit payload already staged and digest-verified in $DEST_DIR"
	exit 0
fi
rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR"

# The upstream release tarball source may be overridden for availability
# (UAT mirrors); the pinned digest is ALWAYS the authority. A tarball that
# does not match the pinned digest is never staged.
TARBALL_SRC="${BUILDKIT_PAYLOAD_TARBALL_PATH:-}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -n "$TARBALL_SRC" ]; then
	if [ ! -s "$TARBALL_SRC" ]; then
		fail "BUILDKIT_PAYLOAD_TARBALL_PATH is set but missing or empty: $TARBALL_SRC"
	fi
	cp "$TARBALL_SRC" "$WORK/$BUILDKIT_TARBALL"
else
	curl -fsSL -o "$WORK/$BUILDKIT_TARBALL" "$BUILDKIT_TARBALL_URL" \
		|| fail "cannot download $BUILDKIT_TARBALL_URL"
fi

ACTUAL_SHA256="$(sha256sum "$WORK/$BUILDKIT_TARBALL" | awk '{print $1}')"
if [ "$ACTUAL_SHA256" != "$BUILDKIT_TARBALL_SHA256" ]; then
	fail "BuildKit tarball SHA-256 mismatch: expected $BUILDKIT_TARBALL_SHA256, got $ACTUAL_SHA256"
fi
echo "OK: BuildKit tarball SHA-256 verified: $ACTUAL_SHA256"

curl -fsSL -o "$WORK/LICENSE" "$BUILDKIT_LICENSE_URL" \
	|| fail "cannot download the pinned upstream LICENSE from $BUILDKIT_LICENSE_URL"
LICENSE_SHA="$(sha256sum "$WORK/LICENSE" | awk '{print $1}')"
if [ "$LICENSE_SHA" != "$BUILDKIT_LICENSE_SHA256" ]; then
	fail "BuildKit LICENSE SHA-256 mismatch: expected $BUILDKIT_LICENSE_SHA256, got $LICENSE_SHA"
fi
echo "OK: BuildKit LICENSE SHA-256 verified: $LICENSE_SHA"

# Extract exactly the proven executable set. The archive layout is flat
# (bin/<binary>); extracting by exact member name fails closed when the
# upstream archive shape changes.
if ! tar -xzf "$WORK/$BUILDKIT_TARBALL" -C "$WORK" \
	bin/buildkitd bin/buildctl bin/buildkit-runc; then
	fail "the pinned upstream archive does not carry the expected bin/ members (buildkitd, buildctl, buildkit-runc)"
fi

BIN_DIR="$DEST_DIR/usr/libexec/docker-helper/buildkit"
DOC_DIR="$DEST_DIR/usr/share/doc/docker-helper/buildkit"
install -d -m 0755 "$BIN_DIR" "$DOC_DIR"
install -m 0755 "$WORK/bin/buildkitd" "$BIN_DIR/buildkitd"
install -m 0755 "$WORK/bin/buildctl" "$BIN_DIR/buildctl"
install -m 0755 "$WORK/bin/buildkit-runc" "$BIN_DIR/buildkit-runc"
install -m 0644 "$WORK/LICENSE" "$DOC_DIR/LICENSE"

# MANIFEST: the payload's own recorded provenance (pinned version, verified
# digests, shipped file digests).
{
	printf 'buildkit-version=%s\n' "$BUILDKIT_VERSION"
	printf 'buildkit-tarball=%s\n' "$BUILDKIT_TARBALL"
	printf 'buildkit-tarball-sha256=%s\n' "$BUILDKIT_TARBALL_SHA256"
	printf 'buildkit-license-sha256=%s\n' "$BUILDKIT_LICENSE_SHA256"
	printf 'buildkitd-sha256=%s\n' "$(sha256sum "$BIN_DIR/buildkitd" | awk '{print $1}')"
	printf 'buildctl-sha256=%s\n' "$(sha256sum "$BIN_DIR/buildctl" | awk '{print $1}')"
	printf 'buildkit-runc-sha256=%s\n' "$(sha256sum "$BIN_DIR/buildkit-runc" | awk '{print $1}')"
	printf 'upstream-notice=absent (no NOTICE file in the %s tag tree; Apache-2.0 requires carrying one only when upstream includes it)\n' "$BUILDKIT_VERSION"
} > "$DOC_DIR/MANIFEST"
chmod 0644 "$DOC_DIR/MANIFEST"

echo "Staged pinned BuildKit payload ($BUILDKIT_VERSION) in $DEST_DIR:"
while IFS= read -r f; do
	printf '  %s\n' "${f#"$DEST_DIR"/}"
done < <(find "$BIN_DIR" "$DOC_DIR" -type f | sort)
