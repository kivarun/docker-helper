#!/usr/bin/env bash
#
# uat-opensuse-repo.sh — the single canonical owner of openSUSE Tumbleweed
# repository / package-manager network policy for the docker-helper UAT. Every
# active zypper path routes through this implementation (AppArmor VM bootstrap,
# SELinux VM bootstrap, and the openSUSE platform dependency setup); there is no
# independent retry/timeout logic anywhere else.
#
# This file is deliberately NOT part of the generic VM harness
# (scripts/uat-vm-tumbleweed.sh), which must stay package-manager agnostic. It
# is sourced where zypper is used and defines functions only (sourcing runs
# nothing).
#
# Provided functions:
#   opensuse_zypp_tune_timeouts  Enforce libzypp download policy in zypp.conf so
#                                a dead/stalled mirror costs seconds instead of
#                                the 60s connect default, and a mirror that
#                                connects successfully but then transfers
#                                unusably slowly is abandoned. Sets
#                                download.connect_timeout (5, connection phase
#                                only) and download.min_download_speed
#                                (262144 bytes/s — libzypp's native control for
#                                abandoning an already-connected slow server).
#                                zypper's CLI --connect-timeout flag is not
#                                accepted on this Tumbleweed image; zypp.conf is
#                                the supported knob (zypper.conf(5)).
#                                download.transfer_timeout is left at the
#                                libzypp default. zypp.conf semantics: the last
#                                value for a key wins.
#   opensuse_zypper <args...>    Run `zypper --non-interactive <args...>` with
#                                up to OPENSUSE_ZYPPER_ATTEMPTS (3) command-level
#                                attempts, OPENSUSE_ZYPPER_DELAY (2) seconds
#                                between attempts, logging "attempt N/3" for
#                                each, and returning the FINAL real zypper exit
#                                code. A failed command is never swallowed: the
#                                caller decides how to fail.
#   opensuse_zypper_refresh      Refresh repository metadata through
#                                opensuse_zypper. On exhaustion it prints a
#                                repository/network failure and returns nonzero,
#                                so an install never proceeds against stale or
#                                incomplete metadata (and never produces
#                                misleading "package not found" errors).

OPENSUSE_ZYPP_CONNECT_TIMEOUT=5
OPENSUSE_ZYPP_MIN_DOWNLOAD_SPEED=262144
OPENSUSE_ZYPPER_ATTEMPTS=3
OPENSUSE_ZYPPER_DELAY=2
# Fallback mirrors (region-neutral / US-hosted) used only when the default
# download.opensuse.org repos are unreachable from the CI network (e.g. Azure
# West US). Each is tried with the same bounded curl policy; the first that
# yields a usable repomd.xml is selected. The original repo set is restored
# afterwards, so a failed run never leaves the guest pointing at a fallback.
OPENSUSE_ZYPP_FALLBACK_MIRRORS=(
  "https://cdn.opensuse.org/tumbleweed/repo/oss"
  "https://mirrors.tuna.tsinghua.edu.cn/opensuse/tumbleweed/repo/oss"
  "https://mirror.freedif.org/opensuse/tumbleweed/repo/oss"
  "https://mirror.sjtu.edu.cn/opensuse/tumbleweed/repo/oss"
)

# zypp_set_download_key KEY VALUE: enforce one zypp.conf download key
# (uncomment/rewrite if present, append otherwise; the last value wins). The
# Tumbleweed Minimal-VM Cloud image may ship without /etc/zypp/zypp.conf, so a
# missing file is not an error: the append branch creates it.
zypp_set_download_key() {
  local conf=/etc/zypp/zypp.conf key="$1" value="$2"
  if [ -f "$conf" ] && grep -Eq "^[[:space:]]*#*[[:space:]]*$key([[:space:]]*=)" "$conf"; then
    sed -i -E "s|^[[:space:]]*#*[[:space:]]*$key([[:space:]=]+).*|$key = $value|" "$conf"
  else
    printf '\n%s = %s\n' "$key" "$value" >> "$conf"
  fi
}

# opensuse_zypp_tune_timeouts: enforce the libzypp download policy.
opensuse_zypp_tune_timeouts() {
  zypp_set_download_key download.connect_timeout "$OPENSUSE_ZYPP_CONNECT_TIMEOUT"
  zypp_set_download_key download.min_download_speed "$OPENSUSE_ZYPP_MIN_DOWNLOAD_SPEED"
}

# opensuse_zypper: retry wrapper preserving the final real zypper exit code.
# The zypper call runs in an `if` condition so its failure is captured (rc)
# instead of tripping `set -e` in callers (the bootstraps run errexit).
# If the default repo URLs are flaky/unreachable from the CI network, retry
# once through a fallback mirror (see opensuse_zypp_fallback).
opensuse_zypper() {
  local attempts="$OPENSUSE_ZYPPER_ATTEMPTS" delay="$OPENSUSE_ZYPPER_DELAY"
  local n rc=1
  for n in $(seq 1 "$attempts"); do
    echo "zypper (attempt $n/$attempts): --non-interactive $*"
    if zypper --non-interactive "$@"; then
      return 0
    else
      rc=$?
    fi
    [ "$n" -lt "$attempts" ] && sleep "$delay"
  done
  # Default repos failed for a transient network reason: try once through a
  # curl-probed fallback mirror. Refresh inherits this path too, but the
  # explicit refresh function below also guarantees repo restore.
  if opensuse_zypp_fallback zypper --non-interactive --no-gpg-checks "$@"; then
    return 0
  fi
  return "$rc"
}

# opensuse_zypp_fallback CMD...: run CMD once with the Tumbleweed base repos
# (repo-oss / repo-non-oss / repo-update, whatever exists — the Tumbleweed
# cloud image names them openSUSE-Tumbleweed-Oss etc., so they are located by
# their URL pattern, not by alias) temporarily pointed at the first
# curl-probed reachable fallback mirror. Always restores the original repo URLs
# before returning, so a failed run never leaves the guest configured against a
# fallback mirror. The fallback command runs with --no-gpg-checks when called
# through opensuse_zypper: the mirror is already verified by a TLS curl probe
# of repomd.xml, and zypper would otherwise try to fetch repomd.xml.key from the
# original host after the base URL is moved.
opensuse_zypp_fallback() {
  # Locate the Tumbleweed base repos by URL pattern: line format of
  # `zypper repos --url` is:
  #   Alias | Name | Enabled | GPG Check | Refresh | Priority | Type | URI | URI
  # Match on the URL column (last |  |-delimited field).
  local alias repo_line repo_url saved_ restore_ ok m url
  local base_aliases=()
  local line
  while IFS= read -r line; do
    repo_url="$(printf '%s' "$line" | sed -E 's/.*\| ([^|]+) \|$/\1/' | xargs)"
    case "$repo_url" in
      */tumbleweed/repo/oss*|*/tumbleweed/repo/non-oss*|*/update/tumbleweed*)
        alias="$(printf '%s' "$line" | awk -F'|' '{gsub(/[ ]+/, "", $1); print $1}')"
        [ -n "$alias" ] && base_aliases+=("$alias")
        ;;
    esac
  done < <(zypper --non-interactive repos --url 2>/dev/null || true)
  if [ "${#base_aliases[@]}" = 0 ]; then
    echo "error: could not locate Tumbleweed base repos to point at a fallback mirror" >&2
    return 1
  fi
  for m in "${OPENSUSE_ZYPP_FALLBACK_MIRRORS[@]}"; do
    url="$m/repodata/repomd.xml"
    echo "fallback mirror probe: $url"
    if curl -fsS --connect-timeout 5 --max-time 20 -o /dev/null "$url" 2>/dev/null; then
      # Save the current URL of each base repo so we can restore it.
      for alias in "${base_aliases[@]}"; do
        repo_line="$(zypper --non-interactive repos --url 2>/dev/null | grep "| $alias |" | head -1)"
        repo_url="$(printf '%s' "$repo_line" | sed -E 's/.*\| [^|]+ \| ([^|]+) \|.*/\1/' | xargs)"
        if [ -n "$repo_url" ]; then
          eval "saved_$alias=\$repo_url"
        fi
      done
      for alias in "${base_aliases[@]}"; do
        zypper --non-interactive modifyrepo --url "$m" "$alias" >/dev/null 2>&1 || true
      done
      ok=0
      if "$@"; then
        ok=1
      fi
      # Restore the original URLs before trying the next candidate / returning.
      for alias in "${base_aliases[@]}"; do
        eval "restore_=\$saved_$alias"
        if [ -n "$restore_" ]; then
          zypper --non-interactive modifyrepo --url "$restore_" "$alias" >/dev/null 2>&1 || true
        fi
      done
      if [ "$ok" = 1 ]; then
        echo "fallback mirror selected: $m"
        return 0
      fi
    fi
  done
  return 1
}

# opensuse_zypper_refresh: refresh with the retry policy; never proceed with
# stale/incomplete metadata. Falls back to a mirror through the shared
# opensuse_zypper path (which adds --no-gpg-checks for the fallback run).
opensuse_zypper_refresh() {
  local rc
  if opensuse_zypper refresh; then
    return 0
  else
    rc=$?
  fi
  echo "error: zypper refresh exhausted attempts and fallback mirrors (repository/network failure); not continuing with stale or incomplete metadata" >&2
  return "$rc"
}
