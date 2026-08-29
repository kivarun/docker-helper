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

# zypp_set_download_key KEY VALUE: enforce one zypp.conf download key
# (uncomment/rewrite if present, append otherwise; the last value wins).
zypp_set_download_key() {
  local conf=/etc/zypp/zypp.conf key="$1" value="$2"
  [ -f "$conf" ] || { echo "error: $conf not found" >&2; return 1; }
  if grep -Eq "^[[:space:]]*#*[[:space:]]*$key([[:space:]]*=)" "$conf"; then
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
  return "$rc"
}

# opensuse_zypper_refresh: refresh with the retry policy; never proceed with
# stale/incomplete metadata.
opensuse_zypper_refresh() {
  local rc
  if opensuse_zypper refresh; then
    return 0
  else
    rc=$?
  fi
  echo "error: zypper refresh exhausted $OPENSUSE_ZYPPER_ATTEMPTS attempts (repository/network failure); not continuing with stale or incomplete metadata" >&2
  return "$rc"
}
