#!/usr/bin/env bash
#
# uat-upgrade-baseline-fixture.sh — immutable "upgrade baseline" package fixture
# for the Release-2.1+ package-lifecycle acceptance. This file is the SINGLE
# OWNER of:
#
#   - baseline version;
#   - baseline DEB URL;
#   - baseline DEB SHA-256;
#   - baseline RPM URL;
#   - baseline RPM SHA-256;
#   - the download/copy + exact-byte verification boundary.
#
# Concept: an "upgrade baseline fixture" is a TEST INPUT, not a runtime/product
# resource and not an owner in the Principal/Launcher/Session model. It
# represents the released stable that a candidate must be a real forward
# upgrade from. The natural baseline for testing 2.1 development candidates is
# the released stable v2.0.0.
#
# The pinned VERSION and SHA-256 values are IDENTITY and are NEVER overridable
# by environment variables. Only the artifact SOURCE may be overridden, for
# availability/recovery.
#
# The hashes were independently verified against the published v2.0.0 release
# SHA256SUMS (and the downloaded bytes re-hashed) BEFORE being pinned here.
# Consumers of the fixture NEVER trust mutable release metadata at runtime;
# they verify the pinned bytes before installation. No private "previous
# release" is ever built in a consumer job, and the baseline package is never
# rebuilt.
#
# Recovery / availability contract (integrity and availability are separate):
#   - the pinned VERSION and SHA-256s are the authority and always come from
#     this file;
#   - the artifact SOURCE may be overridden via explicit local PATH or URL
#     environment variables, with deterministic precedence.
#
# DEB source precedence:
#   1. UAT_UPGRADE_BASELINE_DEB_PATH   explicit local file
#        require regular file; verify pinned SHA; use/copy only after exact
#        verification. A caller-owned source file is NEVER deleted.
#   2. UAT_UPGRADE_BASELINE_DEB_URL    explicit URL override
#        download; verify pinned SHA.
#   3. (default) canonical v2.0.0 GitHub Release URL; download; verify.
#
# RPM source precedence:
#   1. UAT_UPGRADE_BASELINE_RPM_PATH
#   2. UAT_UPGRADE_BASELINE_RPM_URL
#   3. (default) canonical v2.0.0 GitHub Release URL; download; verify.
#
# An explicit bad/unavailable override FAILS CLOSED: it never silently falls
# back to another source after an explicit override fails. The pinned SHA is
# always the authority. We never rebuild the baseline package, never accept a
# caller-supplied SHA, never derive trust from mutable release metadata, never
# repin automatically, and never install bytes before hash verification.
#
# When downloading we write to a temporary file, verify, then atomically rename
# to DEST (no partial download left behind). A caller-owned local source file
# is not deleted on validation failure.
#
# Functions:
#   upgrade_baseline_fetch_deb DEST — resolve + verify the DEB per the
#     precedence above; prints DEST on success, nonzero on any failure.
#   upgrade_baseline_fetch_rpm DEST — same for the RPM.

UPGRADE_BASELINE_VERSION="2.0.0"

UPGRADE_BASELINE_DEB_SHA256="81a95a312f2cabec0d2ca26a71944f0dfbc78bcef22345c1608fb17091d7b4ed"
UPGRADE_BASELINE_DEB_URL="https://github.com/kivarun/docker-helper/releases/download/v2.0.0/docker-helper_2.0.0_amd64.deb"

UPGRADE_BASELINE_RPM_SHA256="b48983d3c4d9cc373246807b195141c77a00b1ac4de107e0e88eeea1828b5dbc"
UPGRADE_BASELINE_RPM_URL="https://github.com/kivarun/docker-helper/releases/download/v2.0.0/docker-helper-2.0.0-1.x86_64.rpm"

# upgrade_baseline_verify FILE SHA — strict exact-byte check; 0 iff the file is
# a regular file whose SHA-256 equals the pinned value.
upgrade_baseline_verify() {
  local file="$1" sha="$2" actual
  [ -f "$file" ] || return 1
  actual="$(sha256sum "$file" 2>/dev/null | awk '{print $1}')"
  [ -n "$actual" ] && [ "$actual" = "$sha" ]
}

# upgrade_baseline_fetch_url URL SHA DEST — download to a temporary file,
# strictly verify the pinned SHA, then atomically rename to DEST (no partial
# download left behind).
upgrade_baseline_fetch_url() {
  local url="$1" sha="$2" dest="$3" tmp
  tmp="$(mktemp "${dest}.XXXXXX" 2>/dev/null)" || return 1
  if ! curl -fsSL -o "$tmp" "$url" 2>/dev/null; then
    rm -f "$tmp"
    return 1
  fi
  if ! upgrade_baseline_verify "$tmp" "$sha"; then
    rm -f "$tmp"
    return 1
  fi
  mv "$tmp" "$dest"
  printf '%s' "$dest"
}

# upgrade_baseline_source_from SRC SHA DEST — use/copy a caller-owned local
# source into DEST only after exact verification.
#   - the caller-owned SRC is NEVER deleted or modified;
#   - SRC is copied to a temporary file adjacent to DEST;
#   - the TEMP file (the exact bytes that become DEST) is verified against the
#     pinned SHA;
#   - only after successful verification is TEMP atomically renamed to DEST;
#   - TEMP is removed on every failure;
#   - if SRC and DEST are already the same file, SRC is verified in place and
#     returned without being removed or copied.
upgrade_baseline_source_from() {
  local src="$1" sha="$2" dest="$3" tmp
  if [ -e "$dest" ] && [ "$src" -ef "$dest" ]; then
    # SRC == DEST: verify in place and return; never remove/copy the file.
    upgrade_baseline_verify "$src" "$sha" || return 1
    printf '%s' "$dest"
    return 0
  fi
  tmp="$(mktemp "${dest}.XXXXXX" 2>/dev/null)" || return 1
  if ! cp "$src" "$tmp" 2>/dev/null; then
    rm -f "$tmp"
    return 1
  fi
  if ! upgrade_baseline_verify "$tmp" "$sha"; then
    rm -f "$tmp"
    return 1
  fi
  if ! mv "$tmp" "$dest" 2>/dev/null; then
    rm -f "$tmp"
    return 1
  fi
  printf '%s' "$dest"
}

# upgrade_baseline_fetch_deb DEST — resolve + verify the DEB (PATH -> URL ->
# canonical). Prints DEST on success, nonzero on any failure.
upgrade_baseline_fetch_deb() {
  local dest="$1"
  local path="${UAT_UPGRADE_BASELINE_DEB_PATH:-}"
  local url="${UAT_UPGRADE_BASELINE_DEB_URL:-}"
  if [ -n "$path" ]; then
    upgrade_baseline_source_from "$path" "$UPGRADE_BASELINE_DEB_SHA256" "$dest"
    return $?
  fi
  if [ -n "$url" ]; then
    upgrade_baseline_fetch_url "$url" "$UPGRADE_BASELINE_DEB_SHA256" "$dest"
    return $?
  fi
  upgrade_baseline_fetch_url "$UPGRADE_BASELINE_DEB_URL" "$UPGRADE_BASELINE_DEB_SHA256" "$dest"
}

# upgrade_baseline_fetch_rpm DEST — resolve + verify the RPM (PATH -> URL ->
# canonical). Prints DEST on success, nonzero on any failure.
upgrade_baseline_fetch_rpm() {
  local dest="$1"
  local path="${UAT_UPGRADE_BASELINE_RPM_PATH:-}"
  local url="${UAT_UPGRADE_BASELINE_RPM_URL:-}"
  if [ -n "$path" ]; then
    upgrade_baseline_source_from "$path" "$UPGRADE_BASELINE_RPM_SHA256" "$dest"
    return $?
  fi
  if [ -n "$url" ]; then
    upgrade_baseline_fetch_url "$url" "$UPGRADE_BASELINE_RPM_SHA256" "$dest"
    return $?
  fi
  upgrade_baseline_fetch_url "$UPGRADE_BASELINE_RPM_URL" "$UPGRADE_BASELINE_RPM_SHA256" "$dest"
}
