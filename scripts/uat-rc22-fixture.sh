#!/usr/bin/env bash
#
# uat-rc22-fixture.sh — immutable v2.0.0-rc.22 package fixture for the
# Release-2 native lifecycle acceptance. This is the single owner of the
# rc.22 DEB/RPM pinned SHA-256s and the download+verify boundary.
#
# The hashes were independently verified against the published rc.22 release
# SHA256SUMS (and the downloaded bytes re-hashed) BEFORE being pinned here.
# Consumers of the fixture NEVER trust mutable release metadata at runtime;
# they verify the pinned bytes before installation. No private "previous
# release" is ever built in a consumer job.
#
# rc22_fetch URL SHA DEST — download (if absent) and strictly verify the pinned
#   SHA-256; on success prints DEST, on any failure returns nonzero and removes
#   the partial file.
# rc22_fetch_deb DEST / rc22_fetch_rpm DEST — convenience wrappers for the
#   DEB and RPM respectively.

RC22_VERSION="2.0.0-rc.22"
RC22_DEB_SHA256="2001c6d6dd6fd3acb58d0f1f55b78ca4033d8ba2e0193ea70a0dad01e1e4fcc6"
RC22_DEB_URL="https://github.com/kivarun/docker-helper/releases/download/v2.0.0-rc.22/docker-helper_2.0.0.rc.22_amd64.deb"
RC22_RPM_SHA256="7589f064a61ddf80f8cdc281393efc7d6edf70c315467c8d1bab9f1a7bd44fe8"
RC22_RPM_URL="https://github.com/kivarun/docker-helper/releases/download/v2.0.0-rc.22/docker-helper-2.0.0.rc.22-1.x86_64.rpm"

rc22_fetch() { # url sha dest
  local url="$1" sha="$2" dest="$3" actual
  if [ ! -f "$dest" ]; then
    curl -fsSL -o "$dest" "$url" 2>/dev/null || { rm -f "$dest"; return 1; }
  fi
  actual="$(sha256sum "$dest" 2>/dev/null | awk '{print $1}')"
  [ -n "$actual" ] && [ "$actual" = "$sha" ] || { rm -f "$dest"; return 1; }
  printf '%s' "$dest"
}

rc22_fetch_deb() { rc22_fetch "$RC22_DEB_URL" "$RC22_DEB_SHA256" "$1"; }
rc22_fetch_rpm() { rc22_fetch "$RC22_RPM_URL" "$RC22_RPM_SHA256" "$1"; }
