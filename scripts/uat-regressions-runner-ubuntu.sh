#!/usr/bin/env bash
#
# uat-regressions-runner-ubuntu.sh — collect-all runner for the Release-2
# targeted UAT regression groups on the Ubuntu / DEB / AppArmor profile
# (groups 3-9).
#
# This runner is SELF-CONTAINED: it builds and installs the docker-helper .deb
# (same exact build + install path as the common black-box UAT) and starts the
# system service, then runs every regression group, capturing rc and recording
# PASS / FAIL / BLOCKED for each. It does NOT depend on the common black-box
# UAT reaching its final phase, and a failure in one group never stops the
# remaining groups (collect-all).
#
# Exit codes of the individual regression scripts (contract, see
# uat-regression-lib.sh):
#   0 = PASS, 1 = FAIL, 2 = BLOCKED.
#
# Exit status of this runner: 0 when no regression failed, nonzero otherwise.
#
# Env inputs:
#   UAT_VERSION        version string (default 2.0.0-uat)
#   UAT_ALLOWED_ROOT   global allowed root for init (default /home)
#
# The workflow pre-installs the build toolchain (install-deps) and the pinned
# nfpm before invoking this script (same as the black-box UAT).

set -uo pipefail

PREFIX="[regressions-ubuntu]"
say()  { printf '\n%s %s\n' "$PREFIX" "$*"; }
info() { printf '%s %s\n' "$PREFIX" "$*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="${UAT_VERSION:-2.0.0-uat}"
ALLOWED_ROOT="${UAT_ALLOWED_ROOT:-/home}"

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
cd "$REPO_ROOT" || exit 1

say "self-contained setup: build + install docker-helper .deb + start service"

# Clean slate for idempotent re-runs (same reset as the black-box UAT).
systemctl stop docker-helper.service >/dev/null 2>&1 || true
systemctl disable docker-helper.service >/dev/null 2>&1 || true
apparmor_parser -R /etc/apparmor.d/docker-helper-system 2>/dev/null || true
rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper

# 1. Build the exact .deb.
rm -rf dist
./build-packages.sh "$VERSION" >/tmp/reg-build.log 2>&1 || {
  echo "error: build-packages.sh failed (see /tmp/reg-build.log)" >&2
  exit 1
}
DEB="$(ls dist/*.deb 2>/dev/null | head -1)"
[ -n "$DEB" ] && [ -f "$DEB" ] || { echo "error: no .deb produced" >&2; exit 1; }
info "artifact: $DEB ($(sha256sum "$DEB" | awk '{print $1}'))"

# 2. Install + init + start the confined system service.
dpkg -i "$DEB" >/tmp/reg-install.log 2>&1 || {
  echo "error: dpkg -i failed (see /tmp/reg-install.log)" >&2
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
FAILED=0
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
  case "$rc" in
    0) RESULT[$num]="PASS";;
    2) RESULT[$num]="BLOCKED";;
    124) RESULT[$num]="FAIL"; echo "  (group $num timed out after 900s)" >&2;;
    *) RESULT[$num]="FAIL";;
  esac
  if [ "${RESULT[$num]}" = "FAIL" ]; then
    FAILED=1
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

[ "$FAILED" = 0 ] || echo "RESULT: at least one regression FAILED" >&2
exit "$FAILED"
