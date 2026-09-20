#!/usr/bin/env bash
#
# uat-migration-rpm-22.sh — Release 2.3 migration gate 2.2.0 -> candidate on
# the RPM path, running INSIDE the openSUSE Tumbleweed guests of the artifact
# gate (invoked by scripts/uat-vm-opensuse-apparmor.sh and
# scripts/uat-vm-opensuse-selinux.sh, which own the VM construction, the
# guest transfer of the exact candidate RPM and the pinned v2.2.0 baseline
# RPM, and the baseline SHA binding).
#
# The DEB consumer job owns the same migration contract on the DEB path
# (scripts/uat-migration-deb-22.sh). This script owns the RPM-path system-
# mode-only upgrade acceptance over real published-v2.2.0 state, upgraded
# through the package manager with the service running (the natural
# production path):
#
#   R1  the pinned v2.2.0 baseline RPM verifies and installs (version 2.2.0),
#       and the baseline reality is proven: the 2.2 package payload still
#       ships the user systemd unit
#   R2  real pre-upgrade state through the 2.2 CLI: a system-mode Principal
#       with a Principal credential and a live Session whose trivial workload
#       runs, plus a REAL historical user-mode tree on a separate OS account
#       (2.2 non-root init creates the XDG daemon config, admin token, and
#       the per-user systemd unit copy)
#   R3  zypper-free real rpm -U upgrade to the exact candidate RPM with the
#       service running (packaged restart path); version identity verified
#   R4  the shipped user systemd unit is REMOVED by the upgrade
#   R5  the mode-selection grammar is gone post-upgrade: --system is an
#       undefined flag and the `mode` config projection no longer exists
#   R6  identity preservation across the upgrade: the pre-upgrade Principal,
#       credential authority, and Session ID survive and the pre-upgrade
#       Session still runs its trivial workload
#   R7  no adoption: the historical user-mode tree is byte-identical after
#       the upgrade and real post-upgrade traffic, its daemon-owner Principal
#       was never imported, and its admin token is not an authority
#   R8  the upgraded service remains confined (mandatory MAC unchanged) and
#       restart-idempotent
#
# Fail-closed contract: PASS -> continue; FAIL -> gate red; BLOCKED -> a
# required prerequisite is unavailable -> gate red.
# Exit status: 0 = all PASS, 1 = any FAIL, 2 = any BLOCKED (and none FAIL).
#
# Env inputs (guest paths):
#   UAT_VERSION             candidate version string (required)
#   UAT_RPM                 guest path of the exact candidate RPM (required)
#   UAT_RPM_SHA256          expected SHA-256 of the candidate RPM (required)
#   UAT_BASELINE22_RPM      guest path of the pinned v2.2.0 baseline RPM (required)
#   UAT_BASELINE22_SHA256   expected SHA-256 of the baseline RPM (required)
#   UAT_ALLOWED_ROOT        global allowed root (default /home/opc/uat-mig22-roots)
#
# Requires: root, systemd, Docker, rpm, sudo. Exits as above.

set -uo pipefail

VERSION="${UAT_VERSION:?UAT_VERSION is required}"
ALLOWED_ROOT="${UAT_ALLOWED_ROOT:-/home/opc/uat-mig22-roots}"
RPM_PATH_IN="${UAT_RPM:?UAT_RPM is required}"
RPM_SHA256_IN="${UAT_RPM_SHA256:?UAT_RPM_SHA256 is required}"
BASELINE_RPM_IN="${UAT_BASELINE22_RPM:?UAT_BASELINE22_RPM is required}"
BASELINE_SHA_IN="${UAT_BASELINE22_SHA256:?UAT_BASELINE22_SHA256 is required}"

PREFIX="[uat-migration-rpm-22]"
say()  { printf '\n%s %s\n' "$PREFIX" "$*"; }
info() { printf '%s %s\n' "$PREFIX" "$*"; }

redact() {
  sed -E \
    -e 's/dht_[A-Za-z0-9_-]+/<redacted-token>/g' \
    -e 's/dhc_[A-Za-z0-9_-]+/<redacted-token>/g'
}

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
[ -f "$RPM_PATH_IN" ] || { echo "error: UAT_RPM must be an existing file: $RPM_PATH_IN" >&2; exit 1; }
CAND_ACTUAL_SHA="$(sha256sum "$RPM_PATH_IN" | awk '{print $1}')"
[ "$CAND_ACTUAL_SHA" = "$RPM_SHA256_IN" ] || {
  echo "error: candidate RPM SHA-256 mismatch (expected $RPM_SHA256_IN, got $CAND_ACTUAL_SHA)" >&2
  exit 1
}
[ -f "$BASELINE_RPM_IN" ] || { echo "error: UAT_BASELINE22_RPM must be an existing file: $BASELINE_RPM_IN" >&2; exit 1; }
BASE_ACTUAL_SHA="$(sha256sum "$BASELINE_RPM_IN" | awk '{print $1}')"
[ "$BASE_ACTUAL_SHA" = "$BASELINE_SHA_IN" ] || {
  echo "error: v2.2.0 baseline RPM SHA-256 mismatch (expected $BASELINE_SHA_IN, got $BASE_ACTUAL_SHA)" >&2
  exit 1
}
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 \
  || { echo "error: Docker is not reachable (the migration gate runs real workloads)" >&2; exit 1; }
command -v sudo >/dev/null 2>&1 \
  || { echo "error: sudo not found (the historical user-mode seeding runs as a non-root account)" >&2; exit 1; }

FAIL_COUNT=0
acc_ok() { printf '  ok:   %s\n' "$*"; }
acc_fail() { printf '  FAIL: %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
scenario() { say "scenario $1"; }

dh() { /usr/bin/docker-helper "$@"; }
SOCK="/run/docker-helper/docker-helper.sock"

json_field() { grep -oP "\"$1\": \"\K[^\"]+" | head -1; }

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

wait_service_active() {
  local _n="${1:-30}" _i
  for _i in $(seq 1 "$_n"); do
    systemctl is-active --quiet docker-helper.service && return 0
    sleep 1
  done
  return 1
}

cleanup() {
  systemctl stop docker-helper.service >/dev/null 2>&1 || true
  systemctl disable docker-helper.service >/dev/null 2>&1 || true
  rpm -e docker-helper >/dev/null 2>&1 || true
  rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper
  userdel -r mig22u >/dev/null 2>&1 || true
  userdel -r mig22legacy >/dev/null 2>&1 || true
  rm -f /tmp/uat-mig22-cred.tok /tmp/uat-mig22-sess.tok
}
trap cleanup EXIT

# ==============================================================================
# R1: install the pinned v2.2.0 baseline RPM; prove baseline reality
# ==============================================================================
scenario "R1: pinned v2.2.0 baseline RPM"
systemctl stop docker-helper.service >/dev/null 2>&1 || true
systemctl disable docker-helper.service >/dev/null 2>&1 || true
rpm -e docker-helper >/dev/null 2>&1 || true
rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper
if rpm -i "$BASELINE_RPM_IN" >/tmp/uat-mig22-install.log 2>&1 \
    && [ "$(docker-helper version)" = "2.2.0" ]; then
  acc_ok "v2.2.0 baseline RPM installed (sha256 verified: $BASE_ACTUAL_SHA)"
else
  acc_fail "v2.2.0 baseline RPM install/version failed (see /tmp/uat-mig22-install.log)"
fi

if rpm -ql docker-helper 2>/dev/null | grep -qF '/usr/lib/systemd/user/docker-helper.service' \
    && [ -e /usr/lib/systemd/user/docker-helper.service ]; then
  acc_ok "baseline reality proven: the 2.2.0 payload still ships the user systemd unit"
else
  acc_fail "the v2.2.0 baseline payload does not ship the user systemd unit (upgrade-baseline reality broken)"
fi

mkdir -p "$ALLOWED_ROOT" || acc_fail "cannot create the global allowed root $ALLOWED_ROOT"
if docker-helper init --allowed-root "$ALLOWED_ROOT" >/tmp/uat-mig22-init.log 2>&1; then
  acc_ok "system init on v2.2.0 baseline"
else
  acc_fail "system init failed on v2.2.0 baseline (see /tmp/uat-mig22-init.log)"
fi
systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
wait_service_active || acc_fail "v2.2.0 daemon not active (migration gate)"
wait_health || acc_fail "v2.2.0 daemon not healthy (migration gate)"

# ==============================================================================
# R2: real pre-upgrade state through the 2.2 CLI
# ==============================================================================
scenario "R2: v2.2.0 pre-upgrade state"
M_USER="mig22u"
if ! getent passwd "$M_USER" >/dev/null 2>&1; then
  mkdir -p "$ALLOWED_ROOT/mig22-home"
  useradd -m -d "$ALLOWED_ROOT/mig22-home" "$M_USER" >/dev/null 2>&1 \
    || acc_fail "cannot create OS user $M_USER"
fi
M_HOME="$(getent passwd "$M_USER" | cut -d: -f6)"
M_WS="$M_HOME/uat-mig22-ws"
mkdir -p "$M_WS"
chown -R "$M_USER:$M_USER" "$M_WS" 2>/dev/null || true

dh principal create --no-credential "$M_USER" >/dev/null 2>&1 || true
dh principal set "$M_USER" enabled true >/dev/null 2>&1 || true
dh credential create --name mig22 "$M_USER" >/tmp/uat-mig22-cred.out 2>&1 || true
M_CRED_TOKEN="$(sed -n 's/^  Token: //p' /tmp/uat-mig22-cred.out | tr -d '[:space:]')"
if [ -n "$M_CRED_TOKEN" ]; then
  printf '%s\n' "$M_CRED_TOKEN" > /tmp/uat-mig22-cred.tok; chmod 600 /tmp/uat-mig22-cred.tok
  acc_ok "pre-upgrade principal credential issued"
else
  acc_fail "pre-upgrade principal credential issuance failed (see /tmp/uat-mig22-cred.out)"
fi

M_S_JSON="$(dh session create --token-file /tmp/uat-mig22-cred.tok "$M_WS" --json 2>/dev/null || true)"
M_S_ID="$(printf '%s' "$M_S_JSON" | json_field id)"
M_S_TOKEN="$(printf '%s' "$M_S_JSON" | json_field token)"
if [ -n "$M_S_ID" ] && [ -n "$M_S_TOKEN" ]; then
  printf '%s\n' "$M_S_TOKEN" > /tmp/uat-mig22-sess.tok; chmod 600 /tmp/uat-mig22-sess.tok
  acc_ok "pre-upgrade live Session seeded ($M_S_ID)"
else
  acc_fail "pre-upgrade session seeding failed"
fi

M_UID="$(id -u "$M_USER")"
if [ -n "$M_S_TOKEN" ]; then
  M_PRE_RUN="$(DOCKER_HELPER_SESSION_TOKEN="$M_S_TOKEN" \
    dh run --workdir /tmp alpine:3.24 -- sh -ec "test \"\$(id -u)\" = \"$M_UID\" && echo MIG22-PRE-OK")" \
    || acc_fail "pre-upgrade workload failed"
  printf '%s\n' "$M_PRE_RUN" | grep -q 'MIG22-PRE-OK' \
    && acc_ok "pre-upgrade Session workload identity proven"
fi

# Real historical user-mode tree: a separate OS account bootstraps the exact
# 2.2 non-root daemon world (XDG config + admin token + per-user unit copy).
# The 2.2 non-root init delegates to credential install while the system
# service is running; the standalone user-init branch that creates the
# historical tree requires no system daemon and Docker access, so the
# baseline service is stopped for the seeding and restarted afterwards.
if ! id mig22legacy >/dev/null 2>&1; then
  mkdir -p "$ALLOWED_ROOT/mig22legacy-home"
  useradd -m -d "$ALLOWED_ROOT/mig22legacy-home" -s /bin/bash mig22legacy >/dev/null 2>&1 \
    || acc_fail "cannot create the legacy-state account mig22legacy"
fi
LEGACY_HOME="$(getent passwd mig22legacy | cut -d: -f6)"
usermod -aG docker mig22legacy >/dev/null 2>&1 || true
# The legacy account must be able to traverse its home chain for the 2.2
# non-root init probe (the provisioned roots tree is root-owned).
chmod a+x "$ALLOWED_ROOT" 2>/dev/null || true
chmod a+x "$(dirname "$ALLOWED_ROOT")" 2>/dev/null || true
systemctl stop docker-helper.service >/dev/null 2>&1 \
  || acc_fail "cannot stop the baseline service for legacy-state seeding"
sudo -u mig22legacy env -u XDG_CONFIG_HOME HOME="$LEGACY_HOME" \
  docker-helper init --allowed-root "$LEGACY_HOME" >/tmp/uat-mig22-legacy-init.log 2>&1 \
  || acc_fail "the 2.2 baseline non-root init failed (legacy-state seeding broken): $(tail -3 /tmp/uat-mig22-legacy-init.log 2>/dev/null | redact | tr '\n' ' ')"
systemctl start docker-helper.service >/dev/null 2>&1 \
  || acc_fail "cannot restart the baseline service after legacy-state seeding"
wait_service_active || acc_fail "the baseline service did not come back active after legacy-state seeding"
wait_health || acc_fail "the baseline service did not come back healthy after legacy-state seeding"
for legacy_path in \
  "$LEGACY_HOME/.config/docker-helper/config.json" \
  "$LEGACY_HOME/.config/docker-helper/admin.token" \
  "$LEGACY_HOME/.config/systemd/user/docker-helper.service"; do
  [ -e "$legacy_path" ] \
    && acc_ok "historical user-mode state present: $legacy_path" \
    || acc_fail "the 2.2 baseline did not create the legacy user-mode state at $legacy_path"
done
LEGACY_HASHES_BEFORE="$(sha256sum \
  "$LEGACY_HOME/.config/docker-helper/config.json" \
  "$LEGACY_HOME/.config/docker-helper/admin.token" \
  "$LEGACY_HOME/.config/systemd/user/docker-helper.service" 2>/dev/null | awk '{print $1}')"
[ -n "$LEGACY_HASHES_BEFORE" ] || acc_fail "cannot hash the seeded legacy user-mode state"

# ==============================================================================
# R3: real rpm -U upgrade to the exact candidate with the service running
# ==============================================================================
scenario "R3: rpm -U upgrade to the candidate (packaged restart path)"
if rpm -Uvh "$RPM_PATH_IN" >/tmp/uat-mig22-upgrade.log 2>&1 \
    && [ "$(docker-helper version)" = "$VERSION" ]; then
  acc_ok "upgraded to candidate RPM ($VERSION) with the service running"
else
  acc_fail "candidate upgrade failed (see /tmp/uat-mig22-upgrade.log: $(redact </tmp/uat-mig22-upgrade.log | tail -3))"
fi
wait_service_active || acc_fail "the upgraded daemon is not active"
wait_health || acc_fail "the upgraded daemon is not healthy"

# ==============================================================================
# R4: the shipped user systemd unit is removed by the upgrade
# ==============================================================================
scenario "R4: user systemd unit removed by the upgrade"
rpm -ql docker-helper 2>/dev/null | grep -qF '/usr/lib/systemd/user/docker-helper.service' \
  && acc_fail "the candidate payload still ships the user systemd unit" \
  || acc_ok "the candidate payload no longer ships the user systemd unit"
[ ! -e /usr/lib/systemd/user/docker-helper.service ] \
  && acc_ok "the user systemd unit was removed on disk by the upgrade" \
  || acc_fail "the user systemd unit survived the upgrade on disk"

# ==============================================================================
# R5: the mode-selection grammar is gone post-upgrade
# ==============================================================================
scenario "R5: mode-selection grammar removed"
SYS_OUT="$(dh session list --system 2>&1)"
SYS_RC=$?
if [ "$SYS_RC" -eq 2 ] && printf '%s\n' "$SYS_OUT" | grep -q "flag provided but not defined: -system"; then
  acc_ok "--system is no longer an operator flag"
else
  acc_fail "--system must be an undefined flag after the upgrade (rc=$SYS_RC): $(printf '%s\n' "$SYS_OUT" | redact | head -3)"
fi
MODE_OUT="$(dh config show mode 2>&1)"
MODE_RC=$?
[ "$MODE_RC" -ne 0 ] \
  && acc_ok "the mode config projection no longer exists" \
  || acc_fail "config show mode still resolves after the upgrade: $MODE_OUT"

# ==============================================================================
# R6: identity preservation across the upgrade
# ==============================================================================
scenario "R6: pre-upgrade identity preservation"
dh principal show "$M_USER" >/tmp/uat-mig22-princ.out 2>&1 \
  && acc_ok "pre-upgrade Principal survived" \
  || acc_fail "the pre-upgrade Principal did not survive the upgrade (see /tmp/uat-mig22-princ.out: $(redact </tmp/uat-mig22-princ.out | tail -2))"

dh session list --token-file /tmp/uat-mig22-cred.tok >/tmp/uat-mig22-list.out 2>&1 \
  && acc_ok "pre-upgrade credential authority survived" \
  || acc_fail "the pre-upgrade credential authority did not survive the upgrade (see /tmp/uat-mig22-list.out)"
if [ -n "$M_S_ID" ]; then
  grep -qF "$M_S_ID" /tmp/uat-mig22-list.out \
    && acc_ok "pre-upgrade Session identity survived" \
    || acc_fail "the pre-upgrade Session identity did not survive the upgrade"
fi

if [ -n "$M_S_TOKEN" ]; then
  M_POST_RUN="$(DOCKER_HELPER_SESSION_TOKEN="$M_S_TOKEN" \
    dh run --workdir /tmp alpine:3.24 -- sh -ec "test \"\$(id -u)\" = \"$M_UID\" && echo MIG22-POST-OK")" \
    || acc_fail "the preserved Session's post-upgrade workload failed"
  printf '%s\n' "$M_POST_RUN" | grep -q 'MIG22-POST-OK' \
    && acc_ok "the preserved Session still runs its workload with the Principal identity"
fi

# ==============================================================================
# R7: no adoption of the historical user-mode tree
# ==============================================================================
scenario "R7: no historical user-state adoption"
if dh principal show mig22legacy >/dev/null 2>&1; then
  acc_fail "the historical legacy-state account was imported as a system Principal"
else
  acc_ok "the historical user-mode state was never imported as system state"
fi

LEGACY_AUTH_OUT="$(dh session list --token-file "$LEGACY_HOME/.config/docker-helper/admin.token" 2>&1)"
LEGACY_AUTH_RC=$?
if [ "$LEGACY_AUTH_RC" -ne 0 ] && printf '%s\n' "$LEGACY_AUTH_OUT" | grep -q "unauthorized"; then
  acc_ok "the historical per-user admin token is not an authority"
else
  acc_fail "presenting the historical admin token must be unauthorized (rc=$LEGACY_AUTH_RC): $(printf '%s\n' "$LEGACY_AUTH_OUT" | redact | head -3)"
fi

LEGACY_HASHES_AFTER="$(sha256sum \
  "$LEGACY_HOME/.config/docker-helper/config.json" \
  "$LEGACY_HOME/.config/docker-helper/admin.token" \
  "$LEGACY_HOME/.config/systemd/user/docker-helper.service" 2>/dev/null | awk '{print $1}')"
if [ "$LEGACY_HASHES_AFTER" = "$LEGACY_HASHES_BEFORE" ] && [ -n "$LEGACY_HASHES_AFTER" ]; then
  acc_ok "the historical user-mode tree survived byte-identical (operator cleanup matter, never touched)"
else
  acc_fail "the historical user-mode tree was modified by the upgrade or by post-upgrade traffic"
fi

# ==============================================================================
# R8: the upgraded service remains confined and restart-idempotent
# ==============================================================================
scenario "R8: confinement and restart idempotency"
DH_PID="$(systemctl show -p MainPID --value docker-helper.service)"
[ -n "$DH_PID" ] && [ "$DH_PID" != "0" ] || acc_fail "daemon MainPID is empty/zero after the upgrade"
ATTR_CURRENT="$(cat "/proc/$DH_PID/attr/current" 2>/dev/null || true)"
if printf '%s\n' "$ATTR_CURRENT" | grep -Eq "docker-helper|docker_helper"; then
  acc_ok "the upgraded daemon remains confined ($ATTR_CURRENT)"
else
  acc_fail "the upgraded daemon is not confined (attr/current: '$ATTR_CURRENT')"
fi

MIG_SESSIONS_BEFORE="$(dh session list --token-file /tmp/uat-mig22-cred.tok 2>/dev/null | grep -cF "$M_S_ID" || true)"
systemctl restart docker-helper.service >/dev/null 2>&1 || true
# A cold QEMU-guest restart under the gate's load (AppArmor profile
# replacement, SQLite WAL recovery, session MAC reconciliation) can exceed
# the default 30s service window; wait on the state, with bounded patience
# and failure evidence, not on an estimate.
wait_service_active 120 \
  || acc_fail "the daemon did not come back after restart (is-active: $(systemctl is-active docker-helper.service 2>&1); journal: $(journalctl -u docker-helper.service -n 8 --no-pager 2>/dev/null | tail -8 | redact | tr '\n' ' '))"
wait_health \
  || acc_fail "the daemon is not healthy after restart (is-active: $(systemctl is-active docker-helper.service 2>&1); journal: $(journalctl -u docker-helper.service -n 8 --no-pager 2>/dev/null | tail -8 | redact | tr '\n' ' '))"
MIG_SESSIONS_AFTER="$(dh session list --token-file /tmp/uat-mig22-cred.tok 2>/dev/null | grep -cF "$M_S_ID" || true)"
if [ "$MIG_SESSIONS_BEFORE" = "1" ] && [ "$MIG_SESSIONS_AFTER" = "1" ]; then
  acc_ok "restart idempotency: the preserved Session survives a daemon restart"
else
  acc_fail "restart idempotency broken (before=$MIG_SESSIONS_BEFORE after=$MIG_SESSIONS_AFTER)"
fi

echo
if [ "$FAIL_COUNT" -gt 0 ]; then
  say "RESULT: FAIL ($FAIL_COUNT failed scenario assertions)"
  exit 1
fi
say "RESULT: PASS"
exit 0
