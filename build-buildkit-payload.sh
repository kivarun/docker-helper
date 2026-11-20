#!/usr/bin/env bash
# build-buildkit-payload.sh — SINGLE OWNER of the pinned BuildKit payload
# staging for the Release 2.4 build sandbox (implementation plan §7).
#
# Every package format (tarball, DEB, RPM) stages its BuildKit payload through
# this script and this script only, so all formats ship byte-identical payload
# files. It downloads the pinned upstream release tarball, verifies its SHA-256
# BEFORE any staging, extracts exactly the proven executable set (the M0/M1 and
# P4-A1 evidence: buildkitd and buildctl; the CNI and QEMU helpers
# are unused by the slirp4netns composition and are NOT shipped), verifies the
# archive's own buildkit-runc member against its recorded upstream digest, and
# builds the DEPLOYED runtime member — the pinned-payload runc loader — from
# the pinned runc sources patched by the committed in-repo runc-loader patch.
# The loader build then stages together with the pinned upstream LICENSE into
# a /usr-rooted staging tree the artifact assemblers consume.
#
# Usage:
#   ./build-buildkit-payload.sh DEST_DIR
#
# Staged layout (DEST_DIR):
#   usr/libexec/docker-helper/buildkit/buildkitd              (0755)
#   usr/libexec/docker-helper/buildkit/buildctl               (0755)
#   usr/libexec/docker-helper/buildkit/runtime/buildkit-runc  (0755)
#   usr/share/doc/docker-helper/buildkit/LICENSE              (0644)
#   usr/share/doc/docker-helper/buildkit/MANIFEST             (0644)
#
# The upstream buildkit-runc binary is NOT shipped: the deployed runtime
# member is the pinned-payload runc loader (pinned runc sources + committed
# patch, built in-script), staged at the dedicated runtime/ subpath (the
# accepted R4-P3-P0 D-2 placement): the top-level payload name buildkit-runc
# is the installed wrapper role (a copy of the product binary, staged by the
# artifact assemblers from dist/docker-helper), and the wrapper hands off to
# this relocated loader binary at its fixed absolute path. The relocation
# changes ONLY the staged pathname — the MANIFEST (whose keys record binary
# identity, not paths) records the deployed loader digest plus its source
# and patch provenance.
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
# Executable digests inside the pinned upstream tarball (identical to the
# P4-A1 proof-recorded payload SHAs; the verify-first re-staging path checks
# them so a second assembler pass reuses the first one's verified staging).
BUILDKITD_SHA256="157da954fa081d9ec4f063d62029fbbf12437c1d47ab63080594eae5a85b36f2"
BUILDCTL_SHA256="0b45ae3696f836bf711dbd78138e403924d7733f0b2328ba29a7fcf9ad5f1dfd"
# The deployed runtime member (runtime/buildkit-runc) is NOT the upstream
# archive binary: it is the pinned-payload runc loader — the pinned upstream
# runc v1.4.3 sources patched by the committed runc-loader patch and built
# here through the deterministic recipe below. The upstream archive member
# bin/buildkit-runc keeps its upstream digest (upstream identity/
# provenance guards), but the shipped runtime bytes are the loader build.
# BUILDKIT_RUNC_SHA256 pins those DEPLOYED bytes: the canonical producer
# (the release-candidate producer job, its canonical toolchain set) is the
# authority for this digest. When a build produces a different digest the
# staging FAILS CLOSED: the recipe (pinned source patch + pinned loader
# toolchain + fixed flags) or the builder environment changed, and the
# re-pin procedure (recompute on the canonical producer, land the pin,
# then re-run) replays explicitly — a silently drifting runtime is never
# staged.
# CI-REPIN-PENDING: the value below is still the upstream archive member
# digest and is WRONG for the loader build by construction; the staging of
# the loader FAILS CLOSED against it (printing the actual build digest)
# until the canonical producer's digest is landed here.
BUILDKIT_RUNC_SHA256="0acdd302ddc5540b2e445b683661bfada9935c702f9008ffb0481abcda16c9b4"
# RUNC-LOADER pinning: the loader sources and their digest, the committed
# patch and its digest, and the pinned loader toolchain version (the
# GOTOOLCHAIN value; also stamped into the binary's `go:` version line).
# The patch path is fixed in-repo (packaging/runc-loader/runc-loader.patch);
# its digest guard keeps the recipe subtraction committed exactly as
# recorded here.
RUNC_LOADER_TAG="v1.4.3"
RUNC_LOADER_SOURCE_URL="https://github.com/opencontainers/runc/archive/refs/tags/v1.4.3.tar.gz"
RUNC_LOADER_SOURCE_SHA256="e0a89f9e883ce93e740d14bb105b25c665f7d7beade4cfd0714fcafb38855d35"
RUNC_LOADER_PATCH_SHA256="014d50caa7fa5ffaece36f73b5d915aa1211a42e9e743c530af35783973882ef"
RUNC_LOADER_TOOLCHAIN="go1.26.10"
# The upstream archive's OWN runc member (provenance guard; its bytes are
# never shipped — the deployed runtime member is the loader build above).
BUILDKIT_RUNC_UPSTREAM_SHA256="0acdd302ddc5540b2e445b683661bfada9935c702f9008ffb0481abcda16c9b4"
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
if ! command -v patch >/dev/null 2>&1; then
	fail "patch not found (required to apply the committed runc-loader patch)"
fi
if ! command -v go >/dev/null 2>&1; then
	fail "go not found (required to build the pinned-payload runc loader)"
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
		usr/libexec/docker-helper/buildkit/runtime/buildkit-runc \
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

# Upstream provenance guard for the archive's own runc member: the upstream
# bin/buildkit-runc extraction must still match its recorded upstream digest
# (the archive identity is checked again at member granularity), even though
# its bytes are NOT the shipped runtime anymore.
UPSTREAM_RUNC_SHA="$(sha256sum "$WORK/bin/buildkit-runc" | awk '{print $1}')"
if [ "$UPSTREAM_RUNC_SHA" != "$BUILDKIT_RUNC_UPSTREAM_SHA256" ]; then
	fail "upstream archive buildkit-runc SHA-256 mismatch: expected $BUILDKIT_RUNC_UPSTREAM_SHA256, got $UPSTREAM_RUNC_SHA"
fi
echo "OK: upstream archive buildkit-runc SHA-256 verified: $UPSTREAM_RUNC_SHA"

# ---------------------------------------------------------------------------
# The pinned-payload runc loader: verify the pinned sources and the committed
# patch, apply the patch, and build the deployed runtime through the fixed
# recipe. The built bytes are then evaluated against BUILDKIT_RUNC_SHA256
# below (fail closed; the canonical producer is the re-pin authority).
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNC_LOADER_PATCH_PATH="$SCRIPT_DIR/packaging/runc-loader/runc-loader.patch"
if [ ! -s "$RUNC_LOADER_PATCH_PATH" ]; then
	fail "the committed runc-loader patch is missing: $RUNC_LOADER_PATCH_PATH"
fi
PATCH_SHA="$(sha256sum "$RUNC_LOADER_PATCH_PATH" | awk '{print $1}')"
if [ "$PATCH_SHA" != "$RUNC_LOADER_PATCH_SHA256" ]; then
	fail "runc-loader patch SHA-256 mismatch: expected $RUNC_LOADER_PATCH_SHA256, got $PATCH_SHA"
fi
echo "OK: runc-loader patch SHA-256 verified: $PATCH_SHA"

RUNC_LOADER_TARBALL="runc-${RUNC_LOADER_TAG}.tar.gz"
RUNC_LOADER_TARBALL_URL="https://github.com/opencontainers/runc/archive/refs/tags/${RUNC_LOADER_TAG}.tar.gz"
RUNC_LOADER_SRC="${RUNC_LOADER_SOURCE_PATH:-}"
if [ -n "$RUNC_LOADER_SRC" ]; then
	if [ ! -s "$RUNC_LOADER_SRC" ]; then
		fail "RUNC_LOADER_SOURCE_PATH is set but missing or empty: $RUNC_LOADER_SRC"
	fi
	cp "$RUNC_LOADER_SRC" "$WORK/$RUNC_LOADER_TARBALL"
else
	curl -fsSL -o "$WORK/$RUNC_LOADER_TARBALL" "$RUNC_LOADER_SOURCE_URL" \
		|| fail "cannot download $RUNC_LOADER_SOURCE_URL"
fi
RUNC_SRC_SHA="$(sha256sum "$WORK/$RUNC_LOADER_TARBALL" | awk '{print $1}')"
if [ "$RUNC_SRC_SHA" != "$RUNC_LOADER_SOURCE_SHA256" ]; then
	fail "runc loader source SHA-256 mismatch: expected $RUNC_LOADER_SOURCE_SHA256, got $RUNC_SRC_SHA"
fi
echo "OK: runc loader source SHA-256 verified: $RUNC_SRC_SHA"

tar -xzf "$WORK/$RUNC_LOADER_TARBALL" -C "$WORK" \
	|| fail "cannot extract the runc loader source tree"
RUNC_SRC_DIR="$WORK/runc-${RUNC_LOADER_TAG#v}"
[ -d "$RUNC_SRC_DIR" ] || fail "the loader source archive does not carry the expected top-level tree"
(cd "$RUNC_SRC_DIR" && patch -p1 < "$RUNC_LOADER_PATCH_PATH") \
	|| fail "the committed runc-loader patch does not apply to the pinned sources"

# Fixed build recipe: pinned toolchain (GOTOOLCHAIN — identical `go:` stamp),
# cgo on (runc requires it), trimpath (no filesystem-path residue). No
# version flags: the tag tree carries its own version constant.
( cd "$RUNC_SRC_DIR" && CGO_ENABLED=1 GOTOOLCHAIN="$RUNC_LOADER_TOOLCHAIN" \
	go build -trimpath -o "$WORK/bin/buildkit-runc" . ) \
	|| fail "cannot build the pinned-payload runc loader"
LOADER_SHA="$(sha256sum "$WORK/bin/buildkit-runc" | awk '{print $1}')"
if [ "$LOADER_SHA" != "$BUILDKIT_RUNC_SHA256" ]; then
	fail "the built runc loader digest $LOADER_SHA does not match the pinned deployed runtime digest $BUILDKIT_RUNC_SHA256 (re-pin procedure: recompute the digest on the canonical producer, land BUILDKIT_RUNC_SHA256 and BUILDKIT_MANIFEST_SHA256, then re-run)"
fi
echo "OK: built runc loader digest verified: $LOADER_SHA"

BIN_DIR="$DEST_DIR/usr/libexec/docker-helper/buildkit"
DOC_DIR="$DEST_DIR/usr/share/doc/docker-helper/buildkit"
install -d -m 0755 "$BIN_DIR" "$BIN_DIR/runtime" "$DOC_DIR"
install -m 0755 "$WORK/bin/buildkitd" "$BIN_DIR/buildkitd"
install -m 0755 "$WORK/bin/buildctl" "$BIN_DIR/buildctl"
# The relocated OCI worker runtime (the wrapper's fixed handoff target;
# the top-level buildkit-runc name belongs to the wrapper role).
install -m 0755 "$WORK/bin/buildkit-runc" "$BIN_DIR/runtime/buildkit-runc"
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
	printf 'buildkit-runc-sha256=%s\n' "$(sha256sum "$BIN_DIR/runtime/buildkit-runc" | awk '{print $1}')"
	printf 'runc-loader-base=%s\n' "$RUNC_LOADER_TAG"
	printf 'runc-loader-source-sha256=%s\n' "$RUNC_LOADER_SOURCE_SHA256"
	printf 'runc-loader-patch-sha256=%s\n' "$RUNC_LOADER_PATCH_SHA256"
	printf 'runc-loader-toolchain=%s\n' "$RUNC_LOADER_TOOLCHAIN"
	printf 'upstream-notice=absent (no NOTICE file in the %s tag tree; Apache-2.0 requires carrying one only when upstream includes it)\n' "$BUILDKIT_VERSION"
} > "$DOC_DIR/MANIFEST"
chmod 0644 "$DOC_DIR/MANIFEST"

echo "Staged pinned BuildKit payload ($BUILDKIT_VERSION) in $DEST_DIR:"
while IFS= read -r f; do
	printf '  %s\n' "${f#"$DEST_DIR"/}"
done < <(find "$BIN_DIR" "$DOC_DIR" -type f | sort)
