#!/usr/bin/env bash
#
# uat-regressions-runner-selinux.sh — collect-all runner for the Release-2
# targeted UAT regression groups on the Tumbleweed / RPM / SELinux profile
# (groups 1-4). Runs INSIDE the SELinux guest, as root.
#
# It re-ensures the docker-helper system service (the common black-box UAT may
# have stopped it during cleanup) and runs every SELinux regression group,
# capturing rc and recording PASS / FAIL / BLOCKED for each. A failure in one
# group never stops the others (collect-all). It does NOT depend on the common
# black-box UAT reaching its final phase.
#
# Exit codes of the individual regression scripts (contract):
#   0 = PASS, 1 = FAIL, 2 = BLOCKED.
# Exit status of this runner: 0 when no regression failed, nonzero otherwise.

set -uo pipefail

PREFIX="[regressions-selinux]"
say()  { printf '\n%s %s\n' "$PREFIX" "$*"; }
info() { printf '%s %s\n' "$PREFIX" "$*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
[ "$(getenforce 2>/dev/null || true)" = "Enforcing" ] || { echo "error: SELinux not enforcing" >&2; exit 1; }

say "ensure docker-helper service (common black-box may have stopped it)"
systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
for _ in $(seq 1 60); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
if ! systemctl is-active --quiet docker-helper.service; then
  echo "error: docker-helper.service not active; SELinux regressions cannot run" >&2
  exit 1
fi
DH_PID="$(systemctl show -p MainPID --value docker-helper.service)"
info "service active: pid=$DH_PID type=$(cut -d: -f3 "/proc/$DH_PID/attr/current" 2>/dev/null || true)"

REGRESSIONS=(
  "1:SELinux non-home workspace lifecycle:uat-regression-selinux-workspace-lifecycle.sh"
  "2:SELinux operator-owned boundary:uat-regression-selinux-operator-boundary.sh"
  "3:SELinux restorecon filesystem-boundary:uat-regression-selinux-fs-boundary.sh"
  "4:SELinux mount-boundary guard:uat-regression-selinux-mount-guard.sh"
)

# Fresh AVC/USER_AVC evidence (best-effort; requires auditd started by the
# scope=selinux bootstrap). Dumps a bounded, docker-helper-relevant window of
# denial records since AVC_START.
AVC_START="$(date '+%m/%d/%Y %H:%M:%S')"
info "fresh AVC/USER_AVC evidence window starts $AVC_START"
avc_evidence() { # label
  local label="$1"
  echo "--- AVC evidence: $label ---" >&2
  if command -v ausearch >/dev/null 2>&1; then
    ausearch -m AVC,USER_AVC -ts "$AVC_START" 2>/dev/null \
      | grep -E 'avc:  denied|USER_AVC|scontext=|tcontext=' \
      | grep -Ei 'docker_helper|restorecon|setfiles|filesystem|getattr|denied' \
      | tail -30 || true
  fi
  tail -150 /var/log/audit/audit.log 2>/dev/null \
    | grep -E 'avc:  denied|USER_AVC' \
    | grep -Ei 'docker_helper|restorecon|setfiles|filesystem|getattr|denied' \
    | tail -30 || true
}

declare -A RESULT
declare -A RC_OF
FAILED=0
for entry in "${REGRESSIONS[@]}"; do
  num="${entry%%:*}"
  rest="${entry#*:}"
  label="${rest%%:*}"
  script="${rest#*:}"
  say "== group $num: $label =="
  if ! systemctl is-active --quiet docker-helper.service 2>/dev/null; then
    systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do
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
    avc_evidence "group $num ($label)"
  fi
  printf 'REGRESSION_MAP: %s=%s:%s\n' "$num" "$label" "${RESULT[$num]}"
done
avc_evidence "full regression run"

echo
say "================= REGRESSION SUMMARY (Tumbleweed/RPM/SELinux) ==============="
for entry in "${REGRESSIONS[@]}"; do
  num="${entry%%:*}"
  label="$(printf '%s' "${entry#*:}" | cut -d: -f1)"
  printf '  %s. %-34s %s (rc=%s)\n' "$num" "$label" "${RESULT[$num]}" "${RC_OF[$num]}"
done
echo "======================================================================"

[ "$FAILED" = 0 ] || echo "RESULT: at least one regression FAILED" >&2
exit "$FAILED"
