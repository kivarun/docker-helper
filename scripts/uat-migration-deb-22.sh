#!/usr/bin/env bash
#
# uat-migration-deb-22.sh — Release 2.3 migration gate 2.2.0 -> candidate on
# the DEB path (Ubuntu / AppArmor).
#
# This script owns the DEB-path system-mode-only upgrade acceptance over the
# real published v2.2.0 state, upgraded through the package manager with the
# service running (the natural production path). It is the 2.3 counterpart
# of the 2.1.1 -> candidate migration gate:
#
#   M1  the pinned v2.2.0 baseline DEB verifies and installs (version 2.2.0),
#       and the baseline reality is proven: the 2.2 package payload still
#       ships the user systemd unit
#   M2  real pre-upgrade state through the 2.2 CLI: a system-mode Principal
#       with a Principal credential and a live Session whose trivial workload
#       runs, plus a REAL historical user-mode tree on a separate OS account
#       (2.2 non-root init creates the XDG daemon config, admin token, and
#       the per-user systemd unit copy)
#   M3  real dpkg -i upgrade to the exact candidate DEB with the service
#       running; candidate version identity verified
#   M4  the shipped user systemd unit is REMOVED by the upgrade: absent from
#       the candidate payload, absent from dpkg ownership, absent on disk
#   M5  the mode-selection grammar is gone post-upgrade: --system is an
#       undefined flag and the `mode` config projection no longer exists
#   M6  identity preservation across the upgrade: the pre-upgrade Principal,
#       credential authority, and Session ID survive and the pre-upgrade
#       Session still runs its trivial workload
#   M7  no adoption: the historical user-mode tree is byte-identical after
#       the upgrade and real post-upgrade traffic, its daemon-owner Principal
#       was never imported, and its admin token is not an authority
#   M8  the upgraded service remains confined (mandatory MAC unchanged)
#   M9  cleanup of the created system-mode state
#
# Fail-closed contract: PASS -> continue; FAIL -> gate red; BLOCKED -> a
# required prerequisite is unavailable -> gate red.
# Exit status: 0 = all PASS, 1 = any FAIL, 2 = any BLOCKED (and none FAIL).
#
# Env inputs:
#   UAT_VERSION             candidate version string (required)
#   UAT_ARTIFACT_PATH       host path of the exact candidate DEB (required)
#   UAT_ARTIFACT_SHA256     expected SHA-256 of the candidate DEB (required)
#   UAT_BASELINE22_DEB      host path of the pinned v2.2.0 baseline DEB
#                           (optional: resolved through
#                           scripts/uat-upgrade-baseline-fixture.sh when
#                           unset)
#   UAT_ALLOWED_ROOT        global allowed root for init (default /home)
#
# Requires: root, systemd, Docker (the pre-upgrade and preserved Session
# workloads), dpkg. Exits as above.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Baseline fixture: the single owner of the pinned v2.2.0 baseline identity.
# shellcheck source=scripts/uat-upgrade-baseline-fixture.sh
source "$SCRIPT_DIR/uat-upgrade-baseline-fixture.sh"

VERSION="${UAT_VERSION:?UAT_VERSION is required}"
ALLOWED_ROOT="${UAT_ALLOWED_ROOT:-/home}"
CANDIDATE_DEB="${UAT_ARTIFACT_PATH:?UAT_ARTIFACT_PATH is required}"
CANDIDATE_SHA="${UAT_ARTIFACT_SHA256:?UAT_ARTIFACT_SHA256 is required}"
BASELINE_DEB="${UAT_BASELINE22_DEB:-}"

fail_mig() {
  printf '\n[migration-deb-22] FAILED: %s\n' "$1" >&2
  exit 1
}

blocked_mig() {
  printf '\n[migration-deb-22] BLOCKED: %s\n' "$1" >&2
  exit 2
}

ok_mig() { printf '[migration-deb-22] ok: %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || blocked_mig "must run as root"
[ -f "$CANDIDATE_DEB" ] || blocked_mig "candidate DEB not found: $CANDIDATE_DEB"
NOW_SHA="$(sha256sum "$CANDIDATE_DEB" | awk '{print $1}')"
[ "$NOW_SHA" = "$CANDIDATE_SHA" ] || fail_mig "candidate DEB SHA-256 mismatch (expected $CANDIDATE_SHA, got $NOW_SHA)"
command -v dpkg >/dev/null 2>&1 || blocked_mig "dpkg not found"
command -v docker >/dev/null 2>&1 || blocked_mig "docker not found (the migration gate runs real workloads)"
docker info >/dev/null 2>&1 || blocked_mig "Docker daemon is not reachable"
[ -d /run/systemd/system ] || blocked_mig "systemd is not running"
[ -d "$ALLOWED_ROOT" ] || fail_mig "allowed root does not exist: $ALLOWED_ROOT"

SERVICE=docker-helper.service
SOCK=/run/docker-helper/docker-helper.sock

wait_health() {
  for _ in $(seq 1 60); do
    if systemctl is-active --quiet "$SERVICE" 2>/dev/null \
        && curl --silent --fail --max-time 1 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# ---------------------------------------------------------------------------
# M1. pinned v2.2.0 baseline: verify, install, prove baseline reality.
# ---------------------------------------------------------------------------
if [ -n "$BASELINE_DEB" ]; then
  UAT_UPGRADE22_DEB_PATH="$BASELINE_DEB"
fi
BASELINE_RESOLVED="$(upgrade22_fetch_deb /tmp/uat-mig22-baseline.deb)" \
  || blocked_mig "cannot resolve + verify the pinned v2.2.0 baseline DEB (source override must carry the exact pinned bytes)"
ok_mig "v2.2.0 baseline DEB verified ($UPGRADE22_DEB_SHA256)"

# Clean slate for idempotent re-runs (same reset as the regression runner).
systemctl stop "$SERVICE" >/dev/null 2>&1 || true
systemctl disable "$SERVICE" >/dev/null 2>&1 || true
apparmor_parser -R /etc/apparmor.d/docker-helper-system 2>/dev/null || true
rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper

dpkg -i "$BASELINE_RESOLVED" >/tmp/uat-mig22-baseline-install.log 2>&1 \
  || fail_mig "dpkg -i failed for the v2.2.0 baseline (see /tmp/uat-mig22-baseline-install.log)"
dpkg -s docker-helper 2>/dev/null | grep -q '^Version: 2.2.0$' \
  || fail_mig "the installed baseline is not docker-helper 2.2.0"
ok_mig "v2.2.0 baseline installed"

dpkg -L docker-helper 2>/dev/null | grep -qF '/usr/lib/systemd/user/docker-helper.service' \
  || fail_mig "the v2.2.0 baseline payload does not ship the user systemd unit (upgrade-baseline reality broken)"
[ -e /usr/lib/systemd/user/docker-helper.service ] \
  || fail_mig "the v2.2.0 baseline user systemd unit is missing on disk after install"
ok_mig "baseline reality proven: the 2.2.0 payload still ships the user systemd unit"

docker-helper init --allowed-root "$ALLOWED_ROOT" >/tmp/uat-mig22-init.log 2>&1 \
  || fail_mig "docker-helper init failed for the baseline (see /tmp/uat-mig22-init.log)"
systemctl daemon-reload
systemctl enable --now "$SERVICE" >/dev/null 2>&1 \
  || fail_mig "cannot enable+start the baseline service"
wait_health || fail_mig "the baseline service did not become healthy"
ok_mig "v2.2.0 baseline service active and healthy"

# ---------------------------------------------------------------------------
# M2. real pre-upgrade state through the 2.2 CLI.
# ---------------------------------------------------------------------------
docker-helper principal create --no-credential mig22u >/dev/null 2>&1 \
  || fail_mig "principal create failed on the baseline"
MIG_CRED_OUT="$(docker-helper credential create --name mig22 mig22u 2>/dev/null)" \
  || fail_mig "credential create failed on the baseline"
MIG_CRED_ID="$(printf '%s\n' "$MIG_CRED_OUT" | sed -n 's/^  ID:    //p' | tr -d '[:space:]')"
MIG_CRED_TOKEN="$(printf '%s\n' "$MIG_CRED_OUT" | sed -n 's/^  Token: //p' | tr -d '[:space:]')"
[ -n "$MIG_CRED_ID" ] && [ -n "$MIG_CRED_TOKEN" ] || fail_mig "could not parse the baseline credential"
MIG_CRED_FILE="/tmp/uat-mig22-credential.token"
printf '%s\n' "$MIG_CRED_TOKEN" > "$MIG_CRED_FILE"
chmod 600 "$MIG_CRED_FILE"

MIG_WS="/home/mig22u-ws"
mkdir -p "$MIG_WS"
MIG_SESSION_JSON="$(docker-helper session create --token-file "$MIG_CRED_FILE" "$MIG_WS" --json 2>/dev/null)" \
  || fail_mig "session create failed on the baseline"
MIG_SESSION_ID="$(printf '%s\n' "$MIG_SESSION_JSON" | grep -oP '"id": "\K[^"]+' | head -1)"
MIG_SESSION_TOKEN="$(printf '%s\n' "$MIG_SESSION_JSON" | grep -oP '"token": "\K[^"]+' | head -1)"
[ -n "$MIG_SESSION_ID" ] && [ -n "$MIG_SESSION_TOKEN" ] || fail_mig "could not parse the baseline session"
ok_mig "pre-upgrade state: principal mig22u, credential $MIG_CRED_ID, session $MIG_SESSION_ID"

MIG_UID="$(id -u mig22u 2>/dev/null)" || MIG_UID=""
if [ -z "$MIG_UID" ]; then
  useradd -m -d /home/mig22u -s /bin/bash mig22u >/dev/null 2>&1 || true
  MIG_UID="$(id -u mig22u)"
fi
MIG_RUN_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$MIG_SESSION_TOKEN" \
  docker-helper run --workdir /tmp alpine:3.24 -- sh -ec "test \"\$(id -u)\" = \"$MIG_UID\" && echo MIG22-PRE-OK")" \
  || fail_mig "pre-upgrade workload failed"
printf '%s\n' "$MIG_RUN_OUT" | grep -q 'MIG22-PRE-OK' \
  || fail_mig "pre-upgrade workload did not reach MIG22-PRE-OK: $MIG_RUN_OUT"
ok_mig "pre-upgrade Session workload identity proven"

# Real historical user-mode tree: a separate OS account bootstraps the exact
# 2.2 non-root daemon world (XDG config + admin token + per-user unit copy).
if ! id mig22legacy >/dev/null 2>&1; then
  useradd -m -d /home/mig22legacy -s /bin/bash mig22legacy >/dev/null 2>&1 \
    || fail_mig "cannot create the legacy-state account mig22legacy"
fi
sudo -u mig22legacy env HOME=/home/mig22legacy \
  docker-helper init --allowed-root /home >/tmp/uat-mig22-legacy-init.log 2>&1 \
  || fail_mig "the 2.2 baseline non-root init failed (legacy-state seeding broken): see /tmp/uat-mig22-legacy-init.log"
for legacy_path in \
  /home/mig22legacy/.config/docker-helper/config.json \
  /home/mig22legacy/.config/docker-helper/admin.token \
  /home/mig22legacy/.config/systemd/user/docker-helper.service; do
  [ -e "$legacy_path" ] || fail_mig "the 2.2 baseline did not create the legacy user-mode state at $legacy_path"
done
LEGACY_HASHES_BEFORE="$(sha256sum \
  /home/mig22legacy/.config/docker-helper/config.json \
  /home/mig22legacy/.config/docker-helper/admin.token \
  /home/mig22legacy/.config/systemd/user/docker-helper.service 2>/dev/null | awk '{print $1}')"
[ -n "$LEGACY_HASHES_BEFORE" ] || fail_mig "cannot hash the seeded legacy user-mode state"
ok_mig "historical user-mode tree seeded on mig22legacy (2.2 non-root init)"

# ---------------------------------------------------------------------------
# M3. real package upgrade with the service running.
# ---------------------------------------------------------------------------
dpkg -i "$CANDIDATE_DEB" >/tmp/uat-mig22-upgrade.log 2>&1 \
  || fail_mig "dpkg -i upgrade to the candidate failed (see /tmp/uat-mig22-upgrade.log)"
dpkg -s docker-helper 2>/dev/null | grep -q "^Version: $VERSION\$" \
  || fail_mig "the upgraded package is not version $VERSION"
wait_health || fail_mig "the upgraded service did not become healthy"
ok_mig "upgraded to $VERSION with the service running; service healthy"

# ---------------------------------------------------------------------------
# M4. the shipped user systemd unit is removed by the upgrade.
# ---------------------------------------------------------------------------
dpkg -L docker-helper 2>/dev/null | grep -qF '/usr/lib/systemd/user/docker-helper.service' \
  && fail_mig "the candidate payload still ships the user systemd unit"
[ ! -e /usr/lib/systemd/user/docker-helper.service ] \
  || fail_mig "the user systemd unit survived the upgrade on disk"
ok_mig "the shipped user systemd unit was removed by the upgrade"

# ---------------------------------------------------------------------------
# M5. the mode-selection grammar is gone post-upgrade.
# ---------------------------------------------------------------------------
SYS_OUT="$(docker-helper session list --system 2>&1)"
SYS_RC=$?
[ "$SYS_RC" -eq 2 ] && printf '%s\n' "$SYS_OUT" | grep -q "flag provided but not defined: -system" \
  || fail_mig "--system must be an undefined flag after the upgrade (rc=$SYS_RC): $(printf '%s\n' "$SYS_OUT" | redact | head -3)"
ok_mig "--system is no longer an operator flag"
MODE_OUT="$(docker-helper config show mode 2>&1)"
MODE_RC=$?
[ "$MODE_RC" -ne 0 ] || fail_mig "config show mode still resolves after the upgrade: $MODE_OUT"
ok_mig "the mode config projection no longer exists"

# ---------------------------------------------------------------------------
# M6. identity preservation across the upgrade.
# ---------------------------------------------------------------------------
PRINC_OUT="$(docker-helper principal show mig22u 2>&1)"
PRINC_RC=$?
[ "$PRINC_RC" -eq 0 ] \
  || fail_mig "the pre-upgrade Principal did not survive the upgrade (rc=$PRINC_RC): $(printf '%s\n' "$PRINC_OUT" | redact | head -3)"
ok_mig "pre-upgrade Principal survived"

LIST_OUT="$(docker-helper session list --token-file "$MIG_CRED_FILE" 2>&1)"
LIST_RC=$?
[ "$LIST_RC" -eq 0 ] \
  || fail_mig "the pre-upgrade credential authority did not survive the upgrade (rc=$LIST_RC): $(printf '%s\n' "$LIST_OUT" | redact | head -3)"
printf '%s\n' "$LIST_OUT" | grep -qF "$MIG_SESSION_ID" \
  || fail_mig "the pre-upgrade Session identity did not survive the upgrade"
ok_mig "pre-upgrade credential authority and Session identity survived"

SHOW_OUT="$(docker-helper session show --token-file "$MIG_CRED_FILE" "$MIG_SESSION_ID" 2>&1)"
SHOW_RC=$?
[ "$SHOW_RC" -eq 0 ] || fail_mig "session show failed for the preserved Session (rc=$SHOW_RC)"

MIG_RUN_AFTER_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$MIG_SESSION_TOKEN" \
  docker-helper run --workdir /tmp alpine:3.24 -- sh -ec "test \"\$(id -u)\" = \"$MIG_UID\" && echo MIG22-POST-OK")" \
  || fail_mig "the preserved Session's post-upgrade workload failed"
printf '%s\n' "$MIG_RUN_AFTER_OUT" | grep -q 'MIG22-POST-OK' \
  || fail_mig "the preserved Session's post-upgrade workload did not reach MIG22-POST-OK: $MIG_RUN_AFTER_OUT"
ok_mig "the preserved Session still runs its workload with the Principal identity"

# ---------------------------------------------------------------------------
# M7. no adoption of the historical user-mode tree.
# ---------------------------------------------------------------------------
LEGACY_PRINC_OUT="$(docker-helper principal show mig22legacy 2>&1)"
LEGACY_PRINC_RC=$?
[ "$LEGACY_PRINC_RC" -ne 0 ] \
  || fail_mig "the historical legacy-state account was imported as a system Principal"
ok_mig "the historical user-mode state was never imported as system state"

LEGACY_AUTH_OUT="$(docker-helper session list --token-file /home/mig22legacy/.config/docker-helper/admin.token 2>&1)"
LEGACY_AUTH_RC=$?
[ "$LEGACY_AUTH_RC" -ne 0 ] && printf '%s\n' "$LEGACY_AUTH_OUT" | grep -q "unauthorized" \
  || fail_mig "the historical per-user admin token must not be an authority (rc=$LEGACY_AUTH_RC): $(printf '%s\n' "$LEGACY_AUTH_OUT" | redact | head -3)"
ok_mig "the historical per-user admin token is not an authority"

LEGACY_HASHES_AFTER="$(sha256sum \
  /home/mig22legacy/.config/docker-helper/config.json \
  /home/mig22legacy/.config/docker-helper/admin.token \
  /home/mig22legacy/.config/systemd/user/docker-helper.service 2>/dev/null | awk '{print $1}')"
[ "$LEGACY_HASHES_AFTER" = "$LEGACY_HASHES_BEFORE" ] \
  || fail_mig "the historical user-mode tree was modified by the upgrade or by post-upgrade traffic"
ok_mig "the historical user-mode tree survived byte-identical (operator cleanup matter, never touched)"

# ---------------------------------------------------------------------------
# M8. the upgraded service remains confined.
# ---------------------------------------------------------------------------
DH_PID="$(systemctl show -p MainPID --value "$SERVICE")"
[ -n "$DH_PID" ] && [ "$DH_PID" != "0" ] || fail_mig "daemon MainPID is empty/zero after the upgrade"
ATTR_CURRENT="$(cat "/proc/$DH_PID/attr/current" 2>/dev/null || true)"
printf '%s\n' "$ATTR_CURRENT" | grep -q "docker-helper" \
  || fail_mig "the upgraded daemon is not confined (attr/current: '$ATTR_CURRENT')"
ok_mig "the upgraded daemon remains confined ($ATTR_CURRENT)"

# ---------------------------------------------------------------------------
# M9. cleanup of the created system-mode state.
# ---------------------------------------------------------------------------
docker-helper session delete --token-file "$MIG_CRED_FILE" "$MIG_SESSION_ID" >/dev/null 2>&1 || true
docker-helper principal delete mig22u >/dev/null 2>&1 || true
rm -f "$MIG_CRED_FILE"
rm -rf "$MIG_WS"
userdel -r mig22legacy >/dev/null 2>&1 || true
userdel -r mig22u >/dev/null 2>&1 || true
ok_mig "created system-mode state cleaned up"

printf '\n[migration-deb-22] RESULT: PASS\n'
exit 0
