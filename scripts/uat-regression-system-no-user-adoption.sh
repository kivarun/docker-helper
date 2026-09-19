#!/usr/bin/env bash
#
# uat-regression-system-no-user-adoption.sh — Release-2.3 targeted regression
# group: no legacy user-state adoption (Ubuntu / DEB / AppArmor).
#
# Black-box acceptance for the Release-2.3 migration boundary: the system
# daemon never discovers, imports, adopts, consumes, or cleans up historical
# user-mode daemon state. Old per-user state may remain on disk as an
# operator cleanup matter; the system deployment works independently of it.
#
# The group builds a REAL-looking historical user-mode tree for a probe
# account — the exact 2.2 user-mode layout (XDG config.json + admin.token +
# SQLite daemon state with a marked daemon-owner Principal and a marked
# Session, plus a stale user socket) — and then proves, while the system
# service is running and serving real traffic:
#
#   A. the system daemon's canonical paths are untouched by it: config and
#      admin token stay /etc/docker-helper; the marker Principal and marker
#      Session of the fake state are absent from the system daemon's
#      inventory (no silent adoption);
#   B. the historical per-user admin token is not an authority on the system
#      daemon: presenting it as a bearer token is the stable unauthorized
#      authentication result;
#   C. the historical state is untouched by system-daemon activity: every
#      fake-state file survives byte-identical across a real
#      session-create/delete cycle (the system deployment neither imports
#      nor cleans operator home directories).
#
# This group is a regression guard for the cutover itself: the no-adoption
# invariant already holds on the 2.2 system daemon (adoption never existed
# there); the RED producers for the removed user-mode contracts live in the
# system-only daemon and endpoint-resolution groups.
#
# Docker is NOT required. Requires: root, the installed candidate system
# service (active), python3 (fake SQLite state), sha256sum.
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "18. System-only no user-state adoption"

reg_require_root
reg_require_service
reg_require_cmd python3 "the fake historical SQLite state is built with python3"

LEGACY_USER="uat23legacy"
LEGACY_HOME="/home/$LEGACY_USER"
LEGACY_CONFIG_DIR="$LEGACY_HOME/.config/docker-helper"
LEGACY_STATE_DIR="$LEGACY_HOME/.local/share/docker-helper"
LEGACY_RUN_DIR="$LEGACY_HOME/.local/state/xdg-run/docker-helper"
LEGACY_DB="$LEGACY_STATE_DIR/docker-helper.db"
LEGACY_ADMIN_TOKEN="$LEGACY_CONFIG_DIR/admin.token"
LEGACY_SOCKET="$LEGACY_RUN_DIR/docker-helper.sock"

if ! id "$LEGACY_USER" >/dev/null 2>&1; then
  useradd -m -d "$LEGACY_HOME" -s /bin/bash "$LEGACY_USER" \
    || reg_blocked "cannot create the legacy-state probe account $LEGACY_USER"
fi
chown -R "$LEGACY_USER:$LEGACY_USER" "$LEGACY_HOME" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Build the historical user-mode tree (the exact 2.2 per-user layout).
# ---------------------------------------------------------------------------
rm -rf "$LEGACY_CONFIG_DIR" "$LEGACY_STATE_DIR" "$LEGACY_RUN_DIR"
mkdir -p "$LEGACY_CONFIG_DIR" "$LEGACY_STATE_DIR" "$LEGACY_RUN_DIR"

# config.json: a valid-looking 2.2 user-mode daemon configuration with a
# marker allowed root that the system daemon must never project.
LEGACY_CONFIG="$LEGACY_CONFIG_DIR/config.json"
printf '%s\n' '{
  "allowed_roots": [
    {"path": "/home/uat23legacy-legacy-marker", "access": "read_write"}
  ],
  "session_ttl": "12h",
  "log_level": "info",
  "shutdown_timeout": "30s"
}' > "$LEGACY_CONFIG"

# admin.token: a fake dht_ token. If the system daemon ever authenticated
# with it, the unauthorized assertion below fails.
LEGACY_TOKEN="dht_$(printf '%s' "$LEGACY_USER-legacy-marker" | sha256sum | cut -c1-64)"
printf '%s\n' "$LEGACY_TOKEN" > "$LEGACY_ADMIN_TOKEN"

# SQLite daemon state with a marked daemon-owner Principal and Session. If
# the system daemon adopted this database, both markers would appear in its
# canonical inventory and the marker assertions below would fail.
python3 - "$LEGACY_DB" <<'PY' || reg_blocked "cannot build the fake historical SQLite state"
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
c = con.cursor()
c.execute(
    "CREATE TABLE principals ("
    " id INTEGER PRIMARY KEY,"
    " username TEXT NOT NULL UNIQUE,"
    " uid INTEGER NOT NULL,"
    " gid INTEGER NOT NULL,"
    " home TEXT NOT NULL,"
    " enabled INTEGER NOT NULL DEFAULT 1)"
)
c.execute(
    "CREATE TABLE sessions ("
    " id TEXT PRIMARY KEY,"
    " token_hash TEXT NOT NULL UNIQUE,"
    " workspace TEXT NOT NULL,"
    " created_at INTEGER NOT NULL,"
    " expires_at INTEGER NOT NULL,"
    " principal_id INTEGER)"
)
c.execute(
    "INSERT INTO principals (username, uid, gid, home, enabled)"
    " VALUES ('uat23legacy', 4711, 4711, '/home/uat23legacy', 1)"
)
c.execute(
    "INSERT INTO sessions VALUES"
    " ('dhs_legacy_marker_session', 'deadbeeflegacy',"
    "  '/home/uat23legacy/marker-ws', 1, 2, 1)"
)
con.commit()
con.close()
PY

# Stale user socket file (the 2.2 user-mode endpoint location).
: > "$LEGACY_SOCKET"

chown -R "$LEGACY_USER:$LEGACY_USER" "$LEGACY_HOME" 2>/dev/null || true
chmod 600 "$LEGACY_ADMIN_TOKEN"

state_hashes() {
  sha256sum "$LEGACY_CONFIG" "$LEGACY_ADMIN_TOKEN" "$LEGACY_DB" "$LEGACY_SOCKET" 2>/dev/null | awk '{print $1}'
}

# The admin token used for every canonical inventory probe: the REAL system
# admin token, resolved explicitly (grammar-neutral across the cutover).
ADMIN_FILE="/tmp/uat23legacy-admin.token"
cp /etc/docker-helper/admin.token "$ADMIN_FILE"
chmod 600 "$ADMIN_FILE"

cleanup() {
  rm -f "$ADMIN_FILE"
}
trap cleanup EXIT

HASHES_BEFORE="$(state_hashes)" || reg_blocked "cannot hash the fake historical state"

# ---------------------------------------------------------------------------
# A. no silent adoption of the historical state.
# ---------------------------------------------------------------------------
CONFIG_PATH_OUT="$(docker-helper config show config_path 2>/dev/null)"
if [ "$CONFIG_PATH_OUT" = "/etc/docker-helper/config.json" ]; then
  reg_ok "the system daemon's config path is the canonical /etc/docker-helper/config.json"
else
  reg_fail "the system daemon's config path is '$CONFIG_PATH_OUT'; the historical XDG config must never be consulted"
fi

SHOW_OUT="$(docker-helper principal show --token-file "$ADMIN_FILE" "$LEGACY_USER" 2>&1)"
SHOW_RC=$?
if [ "$SHOW_RC" -ne 0 ] && printf '%s\n' "$SHOW_OUT" | grep -q "principal_not_found"; then
  reg_ok "the historical daemon-owner Principal was not adopted (principal_not_found)"
else
  reg_fail "the historical daemon-owner Principal must not appear on the system daemon (rc=$SHOW_RC, output below)
$(printf '%s\n' "$SHOW_OUT" | redact_tokens | head -5)"
fi

SESSIONS_JSON="$(docker-helper session list --token-file "$ADMIN_FILE" --json 2>/dev/null)"
if printf '%s\n' "$SESSIONS_JSON" | grep -q "dhs_legacy_marker_session"; then
  reg_fail "the historical marker Session was adopted by the system daemon"
else
  reg_ok "the historical marker Session is absent from the system daemon's inventory"
fi

ROOTS_OUT="$(docker-helper config allowed-root list --token-file "$ADMIN_FILE" --json 2>/dev/null)"
if printf '%s\n' "$ROOTS_OUT" | grep -q "uat23legacy-legacy-marker"; then
  reg_fail "the historical marker allowed root was adopted into the system policy"
else
  reg_ok "the historical marker allowed root is absent from the system policy"
fi

# ---------------------------------------------------------------------------
# B. the historical admin token is not an authority.
# ---------------------------------------------------------------------------
LEGACY_AUTH_OUT="$(docker-helper session list --token-file "$LEGACY_ADMIN_TOKEN" 2>&1)"
LEGACY_AUTH_RC=$?
if [ "$LEGACY_AUTH_RC" -ne 0 ] && printf '%s\n' "$LEGACY_AUTH_OUT" | grep -q "unauthorized"; then
  reg_ok "the historical per-user admin token is not an authority (unauthorized)"
else
  reg_fail "presenting the historical admin token must be an unauthorized authentication result (rc=$LEGACY_AUTH_RC, output below)
$(printf '%s\n' "$LEGACY_AUTH_OUT" | redact_tokens | head -5)"
fi

# ---------------------------------------------------------------------------
# Real system-daemon activity while the fake state exists.
# ---------------------------------------------------------------------------
ACT_USER="uat23legacy-act"
ACT_HOME="$(reg_setup_principal "$ACT_USER")" \
  || reg_blocked "cannot set up the activity principal $ACT_USER"
ACT_WS="$ACT_HOME/uat-legacy-act-ws"
mkdir -p "$ACT_WS"
chown -R "$ACT_USER:$ACT_USER" "$ACT_HOME"
reg_principal_credential "$ACT_USER" "$ACT_HOME/activity.token" \
  || reg_blocked "cannot create the activity principal credential"
ACT_CRED_FILE="$ACT_HOME/activity.token"
ACT_SESSION_JSON="$(docker-helper session create --token-file "$ACT_CRED_FILE" "$ACT_WS" --json 2>/dev/null)"
ACT_SESSION_ID="$(printf '%s\n' "$ACT_SESSION_JSON" | json_field id)"
[ -n "$ACT_SESSION_ID" ] || reg_blocked "cannot create the activity session (no adoption proof target)"
docker-helper session delete --token-file "$ADMIN_FILE" "$ACT_SESSION_ID" >/dev/null 2>&1 \
  || reg_blocked "cannot delete the activity session"

# ---------------------------------------------------------------------------
# C. the historical state is untouched (neither imported nor cleaned).
# ---------------------------------------------------------------------------
HASHES_AFTER="$(state_hashes)" || reg_blocked "cannot re-hash the fake historical state"
if [ "$HASHES_BEFORE" = "$HASHES_AFTER" ] && [ -n "$HASHES_AFTER" ]; then
  reg_ok "every historical state file survived byte-identical across real system-daemon activity"
else
  reg_fail "historical user state was modified while the system daemon served real traffic"
fi

for state_path in "$LEGACY_CONFIG" "$LEGACY_ADMIN_TOKEN" "$LEGACY_DB" "$LEGACY_SOCKET"; do
  if [ -e "$state_path" ]; then
    reg_ok "historical state remains on disk as operator cleanup matter: $state_path"
  else
    reg_fail "the system deployment removed historical operator state: $state_path"
  fi
done

reg_result
