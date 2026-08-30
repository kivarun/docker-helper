#!/usr/bin/env bash
#
# uat-regressions-runner-ubuntu.sh — collect-all runner for the Release-2
# targeted UAT regression groups on the Ubuntu / DEB / AppArmor profile
# (groups 3-9).
#
# The runner installs a docker-helper .deb and starts the system service, then
# runs every regression group, capturing rc and recording PASS / FAIL / BLOCKED
# for each. It does NOT depend on the common black-box UAT reaching its final
# phase, and a failure in one group never stops the remaining groups
# (collect-all).
#
# Two DEB sources are supported, with ONE installation truth (the same
# dpkg install -> init -> daemon-reload -> enable+start sequence):
#
#   * External candidate DEB (UAT_ARTIFACT_PATH + UAT_ARTIFACT_SHA256): the
#     runner consumes the EXACT candidate DEB produced once by the release
#     pipeline. The expected SHA-256 is verified strictly BEFORE install and
#     build-packages.sh is NEVER invoked; installed-file provenance is proven
#     via dpkg ownership.
#   * Self-contained (no UAT_ARTIFACT_PATH): the runner builds its own .deb via
#     build-packages.sh (same exact build path as the common black-box UAT).
#     This remains for local/developer use and for UAT paths that are not yet
#     consuming the candidate set.
#
# Exit codes of the individual regression scripts (contract, see
# uat-regression-lib.sh):
#   0 = PASS, 1 = FAIL, 2 = BLOCKED.
#
# Exit status of this runner (fail-closed, see uat-regression-lib.sh):
#   0 = all groups PASS; 2 = one or more BLOCKED and none FAIL; 1 = any FAIL.
# A BLOCKED group means the required scenario was NOT exercised, so it fails
# the runner too.
#
# Env inputs:
#   UAT_VERSION            version string (default 2.0.0-uat)
#   UAT_ALLOWED_ROOT       global allowed root for init (default /home)
#   UAT_ARTIFACT_PATH      exact prebuilt candidate .deb (consumed, never built)
#   UAT_ARTIFACT_SHA256    expected SHA-256 of the candidate .deb (required when
#                          UAT_ARTIFACT_PATH is set)
#
# The workflow must install the runtime/test/install dependencies. When an
# external candidate DEB is supplied the runner needs no build toolchain (no
# nfpm, no go); only the self-contained path requires build tooling.

set -uo pipefail

PREFIX="[regressions-ubuntu]"
say()  { printf '\n%s %s\n' "$PREFIX" "$*"; }
info() { printf '%s %s\n' "$PREFIX" "$*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"
VERSION="${UAT_VERSION:-2.0.0-uat}"
ALLOWED_ROOT="${UAT_ALLOWED_ROOT:-/home}"
UAT_ARTIFACT_PATH_IN="${UAT_ARTIFACT_PATH:-}"
UAT_ARTIFACT_SHA256_IN="${UAT_ARTIFACT_SHA256:-}"

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
cd "$REPO_ROOT" || exit 1

# Clean slate for idempotent re-runs (same reset as the black-box UAT).
systemctl stop docker-helper.service >/dev/null 2>&1 || true
systemctl disable docker-helper.service >/dev/null 2>&1 || true
apparmor_parser -R /etc/apparmor.d/docker-helper-system 2>/dev/null || true
rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper

# install_deb installs an already-produced .deb and starts the confined system
# service. This is the SINGLE installation truth shared by the external-
# candidate and self-contained paths: dpkg install -> init -> daemon-reload ->
# enable+start -> active wait. Installed-file provenance is proven via dpkg
# ownership.
install_deb() {
  local deb="$1" origin="$2"
  [ -f "$deb" ] || { echo "error: $origin .deb not found: $deb" >&2; exit 1; }

  dpkg -i "$deb" >/tmp/reg-install.log 2>&1 || {
    echo "error: dpkg -i failed for $origin DEB (see /tmp/reg-install.log)" >&2
    exit 1
  }

  # Provenance: the installed binary must be owned by the docker-helper package
  # (proves the installed bytes came from this .deb's install path).
  dpkg -S /usr/bin/docker-helper >/dev/null 2>&1 || {
    echo "error: /usr/bin/docker-helper is not owned by the docker-helper package" >&2
    exit 1
  }

  docker-helper init --allowed-root "$ALLOWED_ROOT" >/tmp/reg-init.log 2>&1 || {
    echo "error: docker-helper init failed (see /tmp/reg-init.log)" >&2
    exit 1
  }
  systemctl daemon-reload
  systemctl enable --now docker-helper.service >/dev/null 2>&1 || { echo "error: cannot enable+start service" >&2; exit 1; }
  for _ in $(seq 1 30); do
    systemctl is-active --quiet docker-helper.service && break
    sleep 1
  done
  systemctl is-active --quiet docker-helper.service || { echo "error: service not active" >&2; exit 1; }
  DH_PID="$(systemctl show -p MainPID --value docker-helper.service)"
  info "service active: pid=$DH_PID"
  info "confinement: $(cat "/proc/$DH_PID/attr/current" 2>/dev/null || true)"
}

if [ -n "$UAT_ARTIFACT_PATH_IN" ]; then
  say "setup: consume EXACT candidate DEB (never rebuild)"

  # External candidate DEB: verify the producer-recorded SHA-256 strictly, then
  # install the exact bytes. build-packages.sh is never invoked.
  [ -n "$UAT_ARTIFACT_SHA256_IN" ] || { echo "error: UAT_ARTIFACT_SHA256 is required when UAT_ARTIFACT_PATH is set" >&2; exit 1; }
  [ -f "$UAT_ARTIFACT_PATH_IN" ] || { echo "error: UAT_ARTIFACT_PATH is not a regular file: $UAT_ARTIFACT_PATH_IN" >&2; exit 1; }
  DEB_SHA="$(sha256sum "$UAT_ARTIFACT_PATH_IN" | awk '{print $1}')"
  [ "$DEB_SHA" = "$UAT_ARTIFACT_SHA256_IN" ] || {
    echo "error: candidate DEB SHA-256 mismatch (expected $UAT_ARTIFACT_SHA256_IN, got $DEB_SHA)" >&2
    exit 1
  }
  info "candidate DEB: $UAT_ARTIFACT_PATH_IN"
  info "sha256 (verified): $DEB_SHA"
  install_deb "$UAT_ARTIFACT_PATH_IN" "candidate"
else
  say "self-contained setup: build + install docker-helper .deb + start service"

  # Build the exact .deb locally (self-contained/developer path only).
  rm -rf dist
  ./build-packages.sh "$VERSION" >/tmp/reg-build.log 2>&1 || {
    echo "error: build-packages.sh failed (see /tmp/reg-build.log)" >&2
    exit 1
  }
  DEB="$(ls dist/*.deb 2>/dev/null | head -1)"
  [ -n "$DEB" ] && [ -f "$DEB" ] || { echo "error: no .deb produced" >&2; exit 1; }
  info "artifact: $DEB ($(sha256sum "$DEB" | awk '{print $1}'))"
  install_deb "$DEB" "self-contained"
fi

# 3. Run every regression group (collect-all).
#    name:label -> script file
REGRESSIONS=(
  "3:Authorization lifecycle:uat-regression-auth-lifecycle.sh"
  "4:Cross-principal isolation:uat-regression-cross-principal-isolation.sh"
  "5:Workspace escape pack:uat-regression-workspace-escape.sh"
  "6:Mount-pin pathname replacement:uat-regression-mount-pin-replacement.sh"
  "7:Concurrent mount pins:uat-regression-concurrent-mount-pins.sh"
  "8:Secret containment:uat-regression-secret-containment.sh"
  "9:Daemon stale-runtime recovery:uat-regression-daemon-stale-runtime.sh"
)

declare -A RESULT
declare -A RC_OF
FAIL_COUNT=0
BLOCKED_COUNT=0
for entry in "${REGRESSIONS[@]}"; do
  num="${entry%%:*}"
  rest="${entry#*:}"
  label="${rest%%:*}"
  script="${rest#*:}"
  say "== group $num: $label =="
  # Re-ensure the service so a prior group's cleanup cannot BLOCK later groups
  # (a previous regression failure is never a valid BLOCKED reason).
  if ! systemctl is-active --quiet docker-helper.service 2>/dev/null; then
    systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do
      systemctl is-active --quiet docker-helper.service && break
      sleep 1
    done
  fi
  timeout 900 bash "$SCRIPT_DIR/$script"
  rc=$?
  RC_OF[$num]=$rc
  RESULT[$num]="$(reg_classify_rc "$rc")"
  case "${RESULT[$num]}" in
    BLOCKED) BLOCKED_COUNT=$((BLOCKED_COUNT+1));;
    FAIL)
      FAIL_COUNT=$((FAIL_COUNT+1))
      [ "$rc" = 124 ] && echo "  (group $num timed out after 900s)" >&2
      ;;
  esac
  if [ "${RESULT[$num]}" = "FAIL" ]; then
    echo "--- bounded evidence for group $num ($label) ---" >&2
    journalctl -u docker-helper.service -n 40 --no-pager 2>/dev/null | tail -40 >&2 || true
  fi
  printf 'REGRESSION_MAP: %s=%s:%s\n' "$num" "$label" "${RESULT[$num]}"
done

# 4. Summary.
echo
say "================= REGRESSION SUMMARY (Ubuntu/DEB/AppArmor) ================="
for entry in "${REGRESSIONS[@]}"; do
  num="${entry%%:*}"
  label="$(printf '%s' "${entry#*:}" | cut -d: -f1)"
  printf '  %s. %-34s %s (rc=%s)\n' "$num" "$label" "${RESULT[$num]}" "${RC_OF[$num]}"
done
echo "======================================================================"

# 5. Fail-closed exit: any FAIL -> 1; else any BLOCKED -> 2; else 0.
FINAL_RC="$(reg_aggregate_exit "$FAIL_COUNT" "$BLOCKED_COUNT")"
if [ "$FINAL_RC" = 1 ]; then
  echo "RESULT: at least one mandatory regression FAILED" >&2
elif [ "$FINAL_RC" = 2 ]; then
  echo "RESULT: at least one mandatory regression BLOCKED (required scenario not exercised)" >&2
fi
exit "$FINAL_RC"
