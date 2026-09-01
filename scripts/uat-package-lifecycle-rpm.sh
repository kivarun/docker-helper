#!/usr/bin/env bash
#
# uat-package-lifecycle-rpm.sh — native RPM lifecycle acceptance for
# docker-helper inside a Tumbleweed guest VM, for BOTH MAC backends:
#
#   Tumbleweed RPM / AppArmor   (driven by uat-vm-opensuse-apparmor.sh)
#   Tumbleweed RPM / SELinux    (driven by uat-vm-opensuse-selinux.sh)
#
# Lifecycle:
#   install (v2.0.0 upgrade baseline) -> upgrade (candidate) ->
#   reinstall (candidate) -> final erase
#
# The v2.0.0 package is an immutable TEST FIXTURE for the real upgrade
# baseline: only the RPM is transferred into the guest, its pinned SHA-256 is
# verified strictly before installation, and mutable release metadata is never
# trusted at runtime. No private "previous release" is built in the consumer.
#
# This exercises actual rpm scriptlet semantics, not just package-manager
# return codes:
#   * upgrade/reinstall: candidate version installed; daemon healthy when it
#     was active before; config survives; principal/credential/session state
#     persists; package-owned MAC artifact remains correct (confinement check);
#     exact candidate artifact used (byte identity verified on entry).
#   * final erase: service stopped+disabled; package-owned executable/unit/
#     profile removed; no stale managed AppArmor profile / SELinux module;
#     operator config/state preserved per the documented package contract.
#   * backend idempotence: absent MAC artifacts are normal success (no bogus
#     cross-MAC warning); a really-removed backend artifact is really gone.
#
# Env inputs:
#   UAT_RPM                            exact candidate RPM path inside the guest (required)
#   UAT_RPM_SHA256                     expected candidate RPM SHA-256 (required)
#   UAT_VERSION                        candidate version string (e.g. 2.1.0-uat)
#   UAT_UPGRADE_BASELINE_RPM           v2.0.0 upgrade-baseline RPM path inside the guest (required;
#                                      the only baseline value supplied by the VM driver)
#   UAT_ALLOWED_ROOT    global allowed root (default: principal home)
#   UAT_PRINCIPAL       OS user mapped to the principal (default: opc)
#
# The v2.0.0 baseline VERSION and RPM SHA-256 are source-owned identity defined
# ONLY by scripts/uat-upgrade-baseline-fixture.sh (the single fixture owner),
# which this script sources below. They are never accepted as caller-controlled
# environment inputs.
#
# Requires: root, systemd, Docker, rpm. Exit 0 = PASS, 1 = FAIL, 2 = BLOCKED.

set -uo pipefail

VERSION="${UAT_VERSION:-2.1.0-uat}"
CANDIDATE_RPM="${UAT_RPM:-}"
CANDIDATE_SHA256="${UAT_RPM_SHA256:-}"
BASELINE_RPM="${UAT_UPGRADE_BASELINE_RPM:-}"
PRINCIPAL="${UAT_PRINCIPAL:-opc}"

PREFIX="[rpm-lifecycle]"
say()  { printf '\n%s %s\n' "$PREFIX" "$*"; }
info() { printf '%s %s\n' "$PREFIX" "$*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-upgrade-baseline-fixture.sh
source "$SCRIPT_DIR/uat-upgrade-baseline-fixture.sh"
BASELINE_VERSION="$UPGRADE_BASELINE_VERSION"
BASELINE_SHA256="$UPGRADE_BASELINE_RPM_SHA256"

redact() {
  sed -E \
    -e 's/dht_[A-Za-z0-9_-]+/<redacted-token>/g' \
    -e 's/dhc_[A-Za-z0-9_-]+/<redacted-token>/g'
}

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
[ -n "$CANDIDATE_RPM" ] || { echo "error: UAT_RPM is required" >&2; exit 1; }
[ -f "$CANDIDATE_RPM" ] || { echo "error: UAT_RPM not a regular file: $CANDIDATE_RPM" >&2; exit 1; }
[ -n "$CANDIDATE_SHA256" ] || { echo "error: UAT_RPM_SHA256 is required" >&2; exit 1; }
[ -n "$BASELINE_RPM" ] || { echo "error: UAT_UPGRADE_BASELINE_RPM is required" >&2; exit 1; }
[ -f "$BASELINE_RPM" ] || { echo "error: UAT_UPGRADE_BASELINE_RPM not a regular file: $BASELINE_RPM" >&2; exit 1; }

# Verify both exact-byte identities once, up front.
CANDIDATE_ACTUAL="$(sha256sum "$CANDIDATE_RPM" | awk '{print $1}')"
[ "$CANDIDATE_ACTUAL" = "$CANDIDATE_SHA256" ] || {
  echo "error: candidate RPM SHA-256 mismatch (expected $CANDIDATE_SHA256, got $CANDIDATE_ACTUAL)" >&2
  exit 1
}
BASELINE_ACTUAL="$(sha256sum "$BASELINE_RPM" | awk '{print $1}')"
[ "$BASELINE_ACTUAL" = "$BASELINE_SHA256" ] || {
  echo "error: v2.0.0 baseline RPM SHA-256 mismatch (expected $BASELINE_SHA256, got $BASELINE_ACTUAL)" >&2
  exit 1
}

FAIL_COUNT=0
BLOCKED_COUNT=0
acc_ok() { printf '  ok:   %s\n' "$*"; }
acc_fail() { printf '  FAIL: %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
acc_blocked() { printf '  BLOCKED: %s\n' "$*" >&2; BLOCKED_COUNT=$((BLOCKED_COUNT + 1)); }
scenario() { say "$1"; }

ALLOWED_ROOT="${UAT_ALLOWED_ROOT:-$(getent passwd "$PRINCIPAL" | cut -d: -f6)}"
if [ -z "$ALLOWED_ROOT" ] || [ ! -d "$ALLOWED_ROOT" ]; then
  echo "error: cannot determine allowed root for principal '$PRINCIPAL'" >&2
  exit 1
fi

dh() { /usr/bin/docker-helper "$@"; }
SOCK="/run/docker-helper/docker-helper.sock"

wait_health() {
  local _i=0
  for _i in $(seq 1 100); do
    curl --silent --fail --max-time 1 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1 && return 0
    if ! systemctl is-active --quiet docker-helper.service 2>/dev/null; then
      return 1
    fi
    sleep 0.2
  done
  return 1
}

# verify_confined proves the running daemon is under the package-owned MAC
# artifact (AppArmor profile or SELinux context, whichever this host uses).
verify_confined() {
  local pid
  pid="$(systemctl show -p MainPID --value docker-helper.service)"
  [ -n "$pid" ] && [ "$pid" != "0" ] || return 1
  local attr
  attr="$(cat "/proc/$pid/attr/current" 2>/dev/null || true)"
  case "$attr" in
    *docker-helper-system*) return 0 ;;
    *docker_helper_t*) return 0 ;;
    *) return 1 ;;
  esac
}

cleanup() {
  systemctl stop docker-helper.service >/dev/null 2>&1 || true
  systemctl disable docker-helper.service >/dev/null 2>&1 || true
  rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# reset: clean slate from the preceding black-box UAT in the same guest
# ---------------------------------------------------------------------------
say "reset: erase any prior docker-helper install + clean state"
systemctl stop docker-helper.service >/dev/null 2>&1 || true
systemctl disable docker-helper.service >/dev/null 2>&1 || true
rpm -e docker-helper >/dev/null 2>&1 || true
rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper

# ---------------------------------------------------------------------------
# 1. install (v2.0.0 upgrade baseline)
# ---------------------------------------------------------------------------
scenario "1. install v2.0.0 baseline RPM"
if rpm -i "$BASELINE_RPM" >/tmp/rpm-life-install.log 2>&1; then
  acc_ok "v2.0.0 RPM installed"
else
  acc_fail "v2.0.0 RPM install failed (see /tmp/rpm-life-install.log)"
fi
if [ "$(docker-helper version)" = "$BASELINE_VERSION" ]; then
  acc_ok "v2.0.0 binary version installed ($BASELINE_VERSION)"
else
  acc_fail "installed binary version is not $BASELINE_VERSION: $(docker-helper version)"
fi
if rpm -q docker-helper >/dev/null 2>&1; then
  acc_ok "rpm records the docker-helper package"
else
  acc_fail "rpm does not record the docker-helper package"
fi

INIT_OUT="$(docker-helper init --allowed-root "$ALLOWED_ROOT" 2>&1)"; INIT_EC=$?
if [ "$INIT_EC" -eq 0 ]; then
  acc_ok "system init on v2.0.0 baseline"
else
  printf '%s\n' "$INIT_OUT" | redact >&2
  acc_fail "system init failed on v2.0.0 baseline"
fi
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
for _i in $(seq 1 30); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
if systemctl is-active --quiet docker-helper.service && wait_health; then
  acc_ok "v2.0.0 daemon healthy"
else
  acc_fail "v2.0.0 daemon not healthy"
fi
verify_confined && acc_ok "v2.0.0 daemon confined by package-owned MAC artifact" || acc_fail "v2.0.0 daemon not confined"

# Seed operator/principal state BEFORE the upgrade to prove persistence.
F_USER="$PRINCIPAL"
F_CRED="/tmp/rpm-life.cred"
if dh principal create --system "$F_USER" >/dev/null 2>&1; then
  dh principal set --system "$F_USER" enabled true >/dev/null 2>&1 || true
  dh principal allowed-root add --system "$F_USER" "$ALLOWED_ROOT" >/dev/null 2>&1 || true
  CRED_OUT="$(dh credential create --system --name rpmlife "$F_USER" 2>/dev/null)"
  F_CRED_ID="$(printf '%s\n' "$CRED_OUT" | sed -n 's/^  ID:    //p' | tr -d '[:space:]')"
  F_CRED_TOKEN="$(printf '%s\n' "$CRED_OUT" | sed -n 's/^  Token: //p' | tr -d '[:space:]')"
  printf '%s\n' "$F_CRED_TOKEN" > "$F_CRED"; chmod 600 "$F_CRED"
  F_WS="$ALLOWED_ROOT/rpm-life-ws"; mkdir -p "$F_WS"; chown -R "$PRINCIPAL:$PRINCIPAL" "$F_WS"
  F_SESS_JSON="$(dh session create --system --token-file "$F_CRED" --workspace "$F_WS" --json 2>/dev/null)"
  F_SESSION_ID="$(printf '%s' "$F_SESS_JSON" | grep -oP '"id": "\K[^"]+' | head -1)"
  [ -n "$F_CRED_ID" ] && [ -n "$F_SESSION_ID" ] \
    && acc_ok "seeded principal/credential/session state on v2.0.0" \
    || acc_fail "could not seed principal/credential/session state on v2.0.0"
else
  acc_fail "principal create failed on v2.0.0 baseline"
fi

# ---------------------------------------------------------------------------
# 2. upgrade (v2.0.0 -> candidate)
# ---------------------------------------------------------------------------
scenario "2. upgrade v2.0.0 -> candidate ($VERSION)"
WAS_ACTIVE=0
systemctl is-active --quiet docker-helper.service && WAS_ACTIVE=1
UPG_LOG="/tmp/rpm-life-upgrade.log"
if rpm -Uvh "$CANDIDATE_RPM" >"$UPG_LOG" 2>&1; then
  acc_ok "upgrade to candidate RPM completed"
else
  acc_fail "upgrade to candidate RPM failed (see $UPG_LOG)"
fi
if [ "$(docker-helper version)" = "$VERSION" ]; then
  acc_ok "candidate version installed after upgrade ($VERSION)"
else
  acc_fail "candidate version not installed after upgrade: $(docker-helper version)"
fi
if [ "$WAS_ACTIVE" = 1 ]; then
  # daemon remains/re-becomes healthy when it was active before upgrade
  for _i in $(seq 1 30); do
    systemctl is-active --quiet docker-helper.service && break
    sleep 1
  done
  if systemctl is-active --quiet docker-helper.service && wait_health; then
    acc_ok "daemon healthy after upgrade (was active before)"
  else
    acc_fail "daemon not healthy after upgrade (was active before)"
  fi
  verify_confined && acc_ok "package-owned MAC artifact correct after upgrade" || acc_fail "confinement wrong after upgrade"
else
  acc_blocked "service was not active before upgrade; upgrade health not exercised"
fi
[ -f /etc/docker-helper/config.json ] && acc_ok "system config survived the upgrade" || acc_fail "system config lost during upgrade"
if dh principal show --system --token-file /etc/docker-helper/admin.token "$F_USER" >/dev/null 2>&1; then
  acc_ok "principal persisted across upgrade"
else
  acc_fail "principal did not persist across upgrade"
fi
if dh credential list --system --token-file /etc/docker-helper/admin.token "$F_USER" 2>/dev/null | grep -q "$F_CRED_ID"; then
  acc_ok "credential persisted across upgrade"
else
  acc_fail "credential did not persist across upgrade"
fi
if dh session list --system --token-file /etc/docker-helper/admin.token 2>/dev/null | grep -q "$F_SESSION_ID"; then
  acc_ok "session persisted across upgrade"
else
  acc_fail "session did not persist across upgrade"
fi
if rpm -q --filesbypkg docker-helper 2>/dev/null | grep -q '/usr/bin/docker-helper'; then
  acc_ok "installed binary is package-owned (candidate artifact provenance)"
else
  acc_fail "installed binary not package-owned after upgrade"
fi

# ---------------------------------------------------------------------------
# 3. reinstall (candidate)
# ---------------------------------------------------------------------------
scenario "3. reinstall candidate RPM ($VERSION)"
if rpm --reinstall "$CANDIDATE_RPM" >/tmp/rpm-life-reinstall.log 2>&1; then
  acc_ok "candidate RPM reinstall completed"
else
  acc_fail "candidate RPM reinstall failed (see /tmp/rpm-life-reinstall.log)"
fi
if [ "$(docker-helper version)" = "$VERSION" ]; then
  acc_ok "candidate version remains installed after reinstall"
else
  acc_fail "version changed after reinstall: $(docker-helper version)"
fi
systemctl start docker-helper.service >/dev/null 2>&1 || true
for _i in $(seq 1 30); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
if systemctl is-active --quiet docker-helper.service && wait_health; then
  acc_ok "daemon healthy after reinstall"
else
  acc_fail "daemon not healthy after reinstall"
fi
verify_confined && acc_ok "package-owned MAC artifact correct after reinstall" || acc_fail "confinement wrong after reinstall"

# ---------------------------------------------------------------------------
# 4. final erase
# ---------------------------------------------------------------------------
scenario "4. final erase"
ERASE_LOG="/tmp/rpm-life-erase.log"
if rpm -e docker-helper >"$ERASE_LOG" 2>&1; then
  acc_ok "rpm -e (final erase) completed"
else
  acc_fail "rpm -e failed (see $ERASE_LOG)"
fi
if grep -qi 'warning: failed to remove SELinux module' "$ERASE_LOG"; then
  acc_fail "erase emitted a bogus cross-MAC SELinux warning: $(cat "$ERASE_LOG")"
else
  acc_ok "erase emitted no bogus cross-MAC SELinux warning"
fi
if grep -qi 'warning: failed to unload AppArmor profile' "$ERASE_LOG"; then
  acc_fail "erase emitted a bogus AppArmor unload warning: $(cat "$ERASE_LOG")"
else
  acc_ok "erase emitted no bogus AppArmor unload warning"
fi
if systemctl is-active --quiet docker-helper.service 2>/dev/null; then
  acc_fail "service still active after erase"
else
  acc_ok "service stopped after erase"
fi
if systemctl is-enabled --quiet docker-helper.service 2>/dev/null; then
  acc_fail "service still enabled after erase"
else
  acc_ok "service disabled after erase"
fi
for p in /usr/bin/docker-helper /usr/lib/systemd/system/docker-helper.service; do
  if [ -e "$p" ]; then
    acc_fail "package-owned path still present after erase: $p"
  fi
done
acc_ok "package-owned executable/unit removed"
# No stale managed AppArmor profile belonging to the package.
if grep -q 'docker-helper-system' /sys/kernel/security/apparmor/profiles 2>/dev/null; then
  acc_fail "stale AppArmor profile still loaded after erase"
else
  acc_ok "no stale AppArmor profile remains after erase"
fi
# No stale SELinux module belonging to the package.
if command -v semodule >/dev/null 2>&1 && semodule -l 2>/dev/null | grep -qw docker_helper; then
  acc_fail "stale SELinux module docker_helper still installed after erase"
else
  acc_ok "no stale SELinux module remains after erase"
fi
# Operator config/state preserved on erase (documented package contract).
if [ -d /etc/docker-helper ] && [ -d /var/lib/docker-helper ]; then
  acc_ok "operator config/state preserved on erase (documented contract)"
else
  acc_fail "operator config/state removed on erase (contract violation)"
fi
if rpm -q docker-helper >/dev/null 2>&1; then
  acc_fail "package still recorded after erase"
else
  acc_ok "package fully erased"
fi

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------
echo
echo "================= RPM LIFECYCLE SUMMARY ================="
printf '  FAILS:    %d\n' "$FAIL_COUNT"
printf '  BLOCKED:  %d\n' "$BLOCKED_COUNT"
echo "=========================================================="
if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "RESULT: RPM lifecycle FAILED" >&2
  exit 1
fi
if [ "$BLOCKED_COUNT" -gt 0 ]; then
  echo "RESULT: RPM lifecycle BLOCKED (required scenario not exercised)" >&2
  exit 2
fi
echo "RESULT: RPM lifecycle PASSED"
exit 0
