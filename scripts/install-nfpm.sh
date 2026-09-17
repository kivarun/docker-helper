#!/usr/bin/env bash
#
# install-nfpm.sh — SINGLE OWNER of the pinned nFPM binary installation used by
# the release artifact gate (artifact-gate.yml producer) and the
# packaging-integration CI job (ci.yml).
#
# Owns:
#   * the pinned nFPM version (NFPM_VERSION);
#   * the pinned download archive SHA-256 (NFPM_SHA256);
#   * verified installation of exactly that nFPM binary.
#
# Fails closed on any download/hash/version mismatch. Uses HTTPS only, never
# `latest`, and never silently falls back to an unpinned version.
#
# Usage:
#   scripts/install-nfpm.sh [BIN_DIR]
#   scripts/install-nfpm.sh --check [NFPM]
#
#   BIN_DIR   destination directory for the nfpm binary. Defaults to
#             /usr/local/bin (installed via sudo, matching the CI runner
#             user). A custom BIN_DIR lets an unprivileged local/CI run
#             install into a writable directory (for example
#             "$(go env GOPATH)/bin") without sudo.
#
#   --check   verify an ALREADY-INSTALLED nfpm binary without installing:
#             the binary must be the pinned version. `NFPM` defaults to the
#             first `nfpm` on PATH. A different version (or an unusable
#             binary) fails closed with a message that points back to this
#             script as the single pinned owner. Release tooling callers
#             (build-packages.sh) verify their toolchain through this mode so
#             the pinned version/hash exist in exactly one place.

set -euo pipefail

NFPM_VERSION="2.47.0"
NFPM_SHA256="0660ca602b2d2d2ae4781a06c692b3eeb9d437ffea05b831d76e41f4a3188783"
NFPM_TARBALL="nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz"
NFPM_URL="https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/${NFPM_TARBALL}"

if [ "${1:-}" = "--check" ]; then
  NFPM_BIN="${2:-nfpm}"
  if [ "$NFPM_BIN" = "nfpm" ]; then
    if ! command -v nfpm >/dev/null 2>&1; then
      echo "error: nfpm not found" >&2
      echo "  Install (pinned, single owner): scripts/install-nfpm.sh" >&2
      exit 1
    fi
  fi
  installed="$("$NFPM_BIN" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)"
  if [ "$installed" != "$NFPM_VERSION" ]; then
    echo "error: nfpm version check failed: expected the pinned ${NFPM_VERSION}, found '${installed:-unknown}'" >&2
    echo "  Install the pinned version through the single owner: scripts/install-nfpm.sh" >&2
    exit 1
  fi
  echo "install-nfpm: verified nFPM ${NFPM_VERSION} at $("$NFPM_BIN" --version 2>/dev/null | head -n 1)"
  exit 0
fi

BIN_DIR="${1:-/usr/local/bin}"
if [ -z "$BIN_DIR" ]; then
  echo "error: install-nfpm: BIN_DIR must not be empty" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "install-nfpm: downloading nFPM ${NFPM_VERSION} from ${NFPM_URL}"
curl -fsSL -o "$work/$NFPM_TARBALL" "$NFPM_URL"

echo "install-nfpm: verifying SHA-256 of ${NFPM_TARBALL}"
echo "${NFPM_SHA256}  $work/$NFPM_TARBALL" | sha256sum --check -

tar xzf "$work/$NFPM_TARBALL" -C "$work" nfpm

if [ "$BIN_DIR" = "/usr/local/bin" ]; then
  sudo mkdir -p "$BIN_DIR"
  sudo install -m 0755 "$work/nfpm" "$BIN_DIR/nfpm"
else
  mkdir -p "$BIN_DIR"
  install -m 0755 "$work/nfpm" "$BIN_DIR/nfpm"
fi

"$BIN_DIR/nfpm" --version | grep -qF "$NFPM_VERSION"

echo "install-nfpm: verified nFPM ${NFPM_VERSION} installed at ${BIN_DIR}/nfpm"
