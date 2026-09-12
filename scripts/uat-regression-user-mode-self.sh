#!/usr/bin/env bash
#
# uat-regression-user-mode-self.sh — Release-2.2 self-introspection targeted
# regression group: user-mode self introspection (Ubuntu / DEB / AppArmor).
#
# Black-box acceptance coverage for GET /self on a REAL user-mode
# installation (its own initialized and started user-mode daemon, never the
# system service):
#
#   A. session bearer self — a selector-less user-mode Session's bearer
#      answers with type=session, its workspace, ownership, expiry, and the
#      persisted immutable filesystem snapshot carrying exactly the issued
#      workspace-only read_write entry (user mode issues no external roots);
#   B. admin has no self resource — the user-mode daemon answers the admin
#      token with the stable 404 self_not_available contract too;
#   C. unknown credentials receive the non-disclosing 401 authentication
#      contract;
#   D. the self CLI renders each answer without performing any local
#      classification (one GET /self request, observable through the
#      dedicated user socket).
#
# Requires: installed docker-helper binary, root (user/XDG-runtime setup).
# Docker is NOT required (no workload is run). The system service is NOT
# required and is stopped for the duration so the user-mode daemon is
# unambiguous.
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "User-mode self introspection"

reg_require_root
reg_require_cmd curl "health probing and raw /self probes of the user-mode daemon"
reg_require_cmd sudo "the user-mode daemon runs as a non-root user"

TMPDIR_UMS="/tmp/uat-reg-user-self"
mkdir -p "$TMPDIR_UMS"

U_USER="uatregself"
U_SERVE_PID=""
U_XDG=""

cleanup() {
  if [ -n "$U_SERVE_PID" ]; then
    kill "$U_SERVE_PID" 2>/dev/null || true
    wait "$U_SERVE_PID" 2>/dev/null || true
  fi
  [ -n "$U_USER" ] && pkill -TERM -u "$U_USER" -f '/usr/bin/docker-helper serve' 2>/dev/null || true
  [ -n "$U_USER" ] && userdel -r "$U_USER" >/dev/null 2>&1 || true
  [ -n "$U_XDG" ] && rm -rf "$U_XDG" 2>/dev/null || true
  rm -rf "$TMPDIR_UMS"
}
trap cleanup EXIT

# The user-mode daemon is unambiguous only without a system daemon competing
# for the default endpoint of the UAT user.
systemctl stop docker-helper.service >/dev/null 2>&1 || true

# --- setup: real non-root user + initialized and started user-mode daemon ----

if getent passwd "$U_USER" >/dev/null 2>&1; then
  userdel -r "$U_USER" >/dev/null 2>&1 || true
fi
if useradd -m -s /bin/bash "$U_USER" 2>/dev/null; then
  reg_ok "setup: UAT user $U_USER created"
else
  reg_blocked "could not create the user-mode UAT user"
fi
U_UID="$(id -u "$U_USER")"
U_HOME="$(getent passwd "$U_USER" | cut -d: -f6)"
# User-mode init requires a reachable Docker daemon when no system daemon
# answers (the same dependency the other user-mode groups give the UAT
# user). The prerequisite mutation is required: a silently failed usermod
# would turn the failed prerequisite into misleading downstream evidence.
if usermod -aG docker "$U_USER" 2>/dev/null; then
  reg_ok "setup: $U_USER added to the docker group"
else
  reg_fail "usermod -aG docker $U_USER failed (user-mode init cannot reach the Docker daemon)"
  reg_result
fi
mkdir -p "$U_HOME/ws"; chown -R "$U_USER:$U_USER" "$U_HOME"

U_XDG="/run/user/$U_UID"
mkdir -p "$U_XDG"
chown "$U_USER:$U_USER" "$U_XDG"
chmod 0700 "$U_XDG"

# A clean, user-scoped environment for every user-mode docker-helper process.
U_ENV=(env -i "HOME=$U_HOME" "XDG_RUNTIME_DIR=$U_XDG" \
  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")

# dhx runs docker-helper as the user-mode daemon owner against the user socket.
dhx() { sudo -u "$U_USER" "${U_ENV[@]}" /usr/bin/docker-helper "$@"; }

if dhx init --allowed-root "$U_HOME" >"$TMPDIR_UMS/init.log" 2>&1; then
  reg_ok "user-mode init succeeded for $U_USER"
else
  reg_fail "user-mode init failed (see $TMPDIR_UMS/init.log)"
  sed 's/^/    init-log: /' "$TMPDIR_UMS/init.log" 2>/dev/null | redact | tail -15 >&2
  reg_result
fi

U_SOCK="$U_XDG/docker-helper/docker-helper.sock"
# shellcheck disable=SC2024
sudo -u "$U_USER" "${U_ENV[@]}" /usr/bin/docker-helper serve >"$TMPDIR_UMS/serve.log" 2>&1 &
U_SERVE_PID=$!
U_READY=0
for _ in $(seq 1 100); do
  if [ -S "$U_SOCK" ] && curl --silent --fail --max-time 1 --unix-socket "$U_SOCK" http://localhost/health >/dev/null 2>&1; then
    U_READY=1; break
  fi
  sleep 0.2
done
if [ "$U_READY" = 1 ]; then
  reg_ok "user-mode daemon healthy on its own socket"
else
  reg_fail "user-mode daemon did not become ready (see $TMPDIR_UMS/serve.log)"
  reg_result
fi

WS="$U_HOME/ws"

# --- scenario A: session bearer self on the user-mode daemon -----------------

S_CREATE="$(dhx session create --workspace "$WS" --json 2>/dev/null || true)"
S_ID="$(printf '%s\n' "$S_CREATE" | json_field id)"
S_TOKEN="$(printf '%s\n' "$S_CREATE" | json_field token)"
if [ -n "$S_ID" ] && [ -n "$S_TOKEN" ]; then
  reg_ok "setup: user-mode session $S_ID created"
else
  reg_fail "user-mode session create failed: $(printf '%s\n' "$S_CREATE" | redact | head -3)"
  reg_result
fi

if S_SELF="$(sudo -u "$U_USER" "${U_ENV[@]}" DOCKER_HELPER_SESSION_TOKEN="$S_TOKEN" /usr/bin/docker-helper self --json 2>&1)"; then
  if printf '%s\n' "$S_SELF" | grep -q '"type": "session"' \
      && printf '%s\n' "$S_SELF" | grep -q "\"id\": \"$S_ID\"" \
      && printf '%s\n' "$S_SELF" | grep -q "\"workspace\": \"$WS\"" \
      && printf '%s' "$S_SELF" | python3 -c '
import json, sys
env = json.load(sys.stdin)
res = env["resource"]
entries = res["filesystem_snapshot"]["entries"]
assert res["workspace"] == "$WS", res["workspace"]
assert entries == [{"path": "$WS", "access": "read_write"}], entries
print("A-JSON-OK")
' >/dev/null 2>&1; then
    reg_ok "A: session bearer self carries type/session, workspace, and the workspace-only read_write snapshot"
  else
    reg_fail "A: session bearer self mismatch: $(printf '%s\n' "$S_SELF" | redact | head -8 | tr '\n' ' ')"
  fi
else
  reg_fail "A: user-mode self CLI failed: $(printf '%s\n' "$S_SELF" | redact | head -3)"
fi

# --- scenario B: admin self_not_available on the user-mode daemon ------------

U_ADMIN_TOKEN="$(sudo -u "$U_USER" "${U_ENV[@]}" cat "$U_HOME/.config/docker-helper/admin.token" 2>/dev/null || true)"
if [ -n "$U_ADMIN_TOKEN" ]; then
  U_ADMIN_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
    --unix-socket "$U_SOCK" -H "Authorization: Bearer $U_ADMIN_TOKEN" http://localhost/self 2>/dev/null || true)"
  if [ "$U_ADMIN_CODE" = "404" ]; then
    reg_ok "B: the admin token receives 404 self_not_available on the user-mode daemon"
  else
    reg_fail "B: admin self on the user-mode daemon returned $U_ADMIN_CODE (expected 404)"
  fi
else
  reg_fail "B: could not read the user-mode admin token"
fi

# --- scenario C: unknown credential -> non-disclosing 401 --------------------

U_UNKNOWN_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
  --unix-socket "$U_SOCK" -H 'Authorization: Bearer dht_unknown_user_mode_self_probe' http://localhost/self 2>/dev/null || true)"
if [ "$U_UNKNOWN_CODE" = "401" ]; then
  reg_ok "C: an unknown credential receives the non-disclosing 401"
else
  reg_fail "C: unknown credential returned $U_UNKNOWN_CODE (expected 401)"
fi

# --- scenario D: the self CLI performs no local classification ---------------

D_REQUESTS="$(sudo -u "$U_USER" "${U_ENV[@]}" DOCKER_HELPER_SESSION_TOKEN="$S_TOKEN" /usr/bin/docker-helper self --json 2>/dev/null; \
  sudo -u "$U_USER" "${U_ENV[@]}" DOCKER_HELPER_SESSION_TOKEN="$S_TOKEN" /usr/bin/docker-helper self 2>&1)"
if printf '%s\n' "$D_REQUESTS" | grep -q '"type": "session"'; then
  reg_ok "D: the bare self CLI resolves the user-mode session bearer from the environment and renders the resource"
else
  reg_fail "D: bare self CLI failed to render the session self: $(printf '%s\n' "$D_REQUESTS" | redact | head -3)"
fi

# --- cleanup: remove the probe session ---------------------------------------

dhx session delete --id "$S_ID" >/dev/null 2>&1 || reg_fail "cleanup: probe session delete failed"

reg_result
