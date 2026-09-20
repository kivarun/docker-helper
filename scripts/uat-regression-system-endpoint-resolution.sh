#!/usr/bin/env bash
#
# uat-regression-system-endpoint-resolution.sh — Release-2.3 targeted
# regression group: system-only endpoint/token resolution (Ubuntu / DEB /
# AppArmor).
#
# Black-box acceptance for the Release-2.3 endpoint cutover: after the
# cutover there is no mode selector and no user-socket probing. The default
# (no flags) endpoint is ALWAYS the system socket:
#
#   * non-root -> /run/docker-helper/docker-helper.sock + the installed
#     Principal credential (~/.config/docker-helper/credential.token);
#   * root     -> /run/docker-helper/docker-helper.sock + the system admin
#     token (/etc/docker-helper/admin.token).
#
# Proven here:
#
#   A. negative probe: a fake per-user daemon socket at
#      $XDG_RUNTIME_DIR/docker-helper/docker-helper.sock is NEVER selected.
#      With the fake socket in place a default non-root `session list` still
#      succeeds against the system socket (RED on the 2.2 baseline, whose
#      default resolution prefers the user socket when it exists).
#   B. root default resolution: `session list` with no flags and no
#      --token-file reaches the system daemon with the admin token.
#   C. explicit supported overrides remain: --endpoint (unix:// path and
#      http://127.0.0.1:PORT) with --token-file work and are not mode
#      selectors.
#   D. the full non-root chain stays first-class THROUGH THE DEFAULT
#      ENDPOINT, with the fake user socket still in place: credential
#      install -> default session create -> real workload identity
#      (Principal -> default Launcher -> Session -> run).
#   E. the mode-selection grammar is gone for non-root clients too:
#      `--system` is rejected as an undefined flag.
#
# The fake user socket is a real, bound, listening unix socket owned by the
# probe account, and the group proves the 2.3 client never even connected to
# it (zero accepted connections), so absence of probing is proven
# positively, not inferred from success alone.
#
# Requires: root, the installed candidate system service (active), Docker
# (subcase D runs a real trivial workload), sudo, python3, curl.
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "12. System-only endpoint resolution"

reg_require_root
reg_require_service
reg_require_docker
reg_require_cmd sudo "non-root client probes run as the probe account"
reg_require_cmd python3 "the fake user-socket listener is a python3 probe"
reg_require_cmd curl "health probing of the system service"

EP_USER="uat23ep"
EP_HOME="$(reg_setup_principal "$EP_USER")" \
  || reg_blocked "cannot set up the probe principal $EP_USER"
EP_WS="$EP_HOME/uat-ep-ws"
mkdir -p "$EP_WS"
chown -R "$EP_USER:$EP_USER" "$EP_HOME"

CRED_FILE="/tmp/uat23ep-credential.token"
reg_principal_credential "$EP_USER" "$CRED_FILE" \
  || reg_blocked "cannot create the probe principal credential"

# Install the Principal credential into the probe account's client state
# (the canonical non-root client-side store; this is NOT user-mode daemon
# state and remains first-class after the cutover).
EP_TOKEN_FILE="/tmp/uat23ep-stdin.token"
printf '%s\n' "$REG_CRED_TOKEN" > "$EP_TOKEN_FILE"
chmod 600 "$EP_TOKEN_FILE"
EP_INSTALL_OUT="$(sudo -u "$EP_USER" env -u XDG_CONFIG_HOME HOME="$EP_HOME" docker-helper credential install \
  < "$EP_TOKEN_FILE" 2>&1)"
EP_INSTALL_RC=$?
if [ "$EP_INSTALL_RC" -ne 0 ]; then
  reg_blocked "credential install as the probe account failed (rc=$EP_INSTALL_RC): $(printf '%s\n' "$EP_INSTALL_OUT" | redact | head -5)"
fi
rm -f "$EP_TOKEN_FILE"

if [ ! -f "$EP_HOME/.config/docker-helper/credential.token" ]; then
  reg_blocked "the probe account has no installed credential.token after credential install"
fi
reg_ok "probe account holds the installed credential (client-side store)"

# A real listening fake user socket, owned by the probe account. The listener
# counts every accepted connection into a file the group reads afterwards.
EP_RUN="$EP_HOME/xdg-run"
FAKE_SOCK_DIR="$EP_RUN/docker-helper"
FAKE_SOCK="$FAKE_SOCK_DIR/docker-helper.sock"
FAKE_COUNT_FILE="$EP_HOME/xdg-run/fake-socket-connections"
rm -rf "$EP_RUN"
mkdir -p "$FAKE_SOCK_DIR"
chown -R "$EP_USER:$EP_USER" "$EP_RUN"
FAKE_LISTENER_LOG="$EP_HOME/xdg-run/fake-socket-log"
sudo -u "$EP_USER" env HOME="$EP_HOME" XDG_RUNTIME_DIR="$EP_RUN" \
  python3 -c '
import socket, sys, threading
path, count_path = sys.argv[1], sys.argv[2]
try:
    import os
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(16)
    count = [0]
    stop = threading.Event()
    def accept_loop():
        srv.settimeout(1.0)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
                count[0] += 1
            except socket.timeout:
                continue
            except OSError:
                break
    t = threading.Thread(target=accept_loop)
    t.start()
    open(count_path, "w").write("")
    import signal
    signal.pause()
except Exception as e:
    sys.stderr.write("fake listener failed: %s\n" % e)
    sys.exit(1)
' "$FAKE_SOCK" "$FAKE_COUNT_FILE" >/dev/null 2>&1 &
FAKE_PID=$!
for _ in $(seq 1 20); do
  [ -S "$FAKE_SOCK" ] && break
  sleep 0.1
done
[ -S "$FAKE_SOCK" ] || { kill "$FAKE_PID" 2>/dev/null || true; reg_blocked "the fake user socket listener did not start"; }
reg_ok "fake per-user daemon socket is listening at $FAKE_SOCK"

fake_connections() {
  python3 -c '
import sys
try:
    with open(sys.argv[1]) as fh:
        data = fh.read().strip()
    print(int(data) if data else 0)
except Exception:
    sys.exit(1)
' "$FAKE_COUNT_FILE" 2>/dev/null
}

# ep_cli CMD... — run a docker-helper CLI command as the probe account with
# the fake user socket in place.
ep_cli() { # cmd...
  sudo -u "$EP_USER" \
    env -u XDG_CONFIG_HOME HOME="$EP_HOME" XDG_RUNTIME_DIR="$EP_RUN" \
    "$@"
}

cleanup_fake_listener() {
  kill "$FAKE_PID" 2>/dev/null || true
  wait "$FAKE_PID" 2>/dev/null || true
  rm -rf "$EP_RUN"
}
trap cleanup_fake_listener EXIT

# ---------------------------------------------------------------------------
# A. negative probe: the fake user socket is never selected.
# ---------------------------------------------------------------------------
DEF_OUT="$(ep_cli docker-helper session list 2>&1)"
DEF_RC=$?
if [ "$DEF_RC" -eq 0 ]; then
  reg_ok "default non-root session list succeeds with a fake user socket present"
else
  reg_fail "default (no flags) non-root session list must reach the system socket, not the fake user socket (rc=$DEF_RC, output below)
$(printf '%s\n' "$DEF_OUT" | redact | head -5)"
fi

CONN_COUNT="$(fake_connections)" || CONN_COUNT=""
if [ "$CONN_COUNT" = "0" ]; then
  reg_ok "the fake user socket accepted zero connections (no client probing)"
else
  reg_fail "the fake user socket accepted $CONN_COUNT connection(s); the client must never probe it"
fi

# ---------------------------------------------------------------------------
# B. root default resolution: system socket + admin token, no flags.
# ---------------------------------------------------------------------------
ROOT_OUT="$(docker-helper session list 2>&1)"
ROOT_RC=$?
if [ "$ROOT_RC" -eq 0 ]; then
  reg_ok "root default session list reaches the system daemon with the admin token"
else
  reg_fail "root default session list must succeed without any flag (rc=$ROOT_RC, output below)
$(printf '%s\n' "$ROOT_OUT" | redact | head -5)"
fi

# ---------------------------------------------------------------------------
# C. explicit overrides remain supported and are not mode selectors.
# ---------------------------------------------------------------------------
UNIX_OUT="$(docker-helper session list --endpoint unix:///run/docker-helper/docker-helper.sock --token-file "$CRED_FILE" 2>&1)"
UNIX_RC=$?
if [ "$UNIX_RC" -eq 0 ]; then
  reg_ok "explicit unix:// endpoint override works with an explicit token file"
else
  reg_fail "explicit unix:// endpoint override must keep working (rc=$UNIX_RC, output below)
$(printf '%s\n' "$UNIX_OUT" | redact | head -5)"
fi

HTTP_ADMIN_FILE="/tmp/uat23ep-admin.token"
cp /etc/docker-helper/admin.token "$HTTP_ADMIN_FILE"
chmod 600 "$HTTP_ADMIN_FILE"
HTTP_OUT="$(docker-helper session list --endpoint http://127.0.0.1:52375 --token-file "$HTTP_ADMIN_FILE" 2>&1)"
HTTP_RC=$?
rm -f "$HTTP_ADMIN_FILE"
if [ "$HTTP_RC" -eq 0 ]; then
  reg_ok "explicit http://127.0.0.1 endpoint override works with an explicit token file"
else
  reg_fail "explicit http endpoint override must keep working (rc=$HTTP_RC, output below)
$(printf '%s\n' "$HTTP_OUT" | redact | head -5)"
fi

# ---------------------------------------------------------------------------
# D. full non-root chain through the DEFAULT endpoint (fake socket still in
#    place): session create + real workload identity.
# ---------------------------------------------------------------------------
EP_SESSION_JSON="$(ep_cli docker-helper session create "$EP_WS" --json 2>&1)"
EP_SESSION_RC=$?
EP_SESSION_ID="$(printf '%s\n' "$EP_SESSION_JSON" | json_field id)"
EP_SESSION_TOKEN="$(printf '%s\n' "$EP_SESSION_JSON" | json_field token)"
if [ "$EP_SESSION_RC" -eq 0 ] && [ -n "$EP_SESSION_ID" ] && [ -n "$EP_SESSION_TOKEN" ]; then
  reg_ok "default-endpoint session create for the probe principal (id $EP_SESSION_ID)"
else
  reg_fail "default-endpoint session create must work with a fake user socket present (rc=$EP_SESSION_RC, output below)
$(printf '%s\n' "$EP_SESSION_JSON" | redact | head -5)"
fi

if [ -n "$EP_SESSION_TOKEN" ]; then
  EP_UID="$(id -u "$EP_USER")"
  EP_TOKEN_RUNTIME_FILE="/tmp/uat23ep-session.token"
  printf '%s\n' "$EP_SESSION_TOKEN" > "$EP_TOKEN_RUNTIME_FILE"
  chmod 600 "$EP_TOKEN_RUNTIME_FILE"
  RUN_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$EP_SESSION_TOKEN" \
    docker-helper run --workdir /tmp alpine:3.24 -- sh -ec "test \"\$(id -u)\" = \"$EP_UID\" && echo EP-CHAIN-OK")"
  RUN_RC=$?
  rm -f "$EP_TOKEN_RUNTIME_FILE"
  if [ "$RUN_RC" -eq 0 ] && printf '%s\n' "$RUN_OUT" | grep -q 'EP-CHAIN-OK'; then
    reg_ok "default-endpoint chain ran the real workload with the Principal OS identity"
  else
    reg_fail "default-endpoint session run failed (rc=$RUN_RC, output below)
$(printf '%s\n' "$RUN_OUT" | redact | head -5)"
  fi
  ep_cli docker-helper session delete "$EP_SESSION_ID" >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# E. the mode-selection grammar is gone for non-root clients too.
# ---------------------------------------------------------------------------
SYS_OUT="$(ep_cli docker-helper session list --system 2>&1)"
SYS_RC=$?
if [ "$SYS_RC" -eq 2 ] && printf '%s\n' "$SYS_OUT" | grep -q "flag provided but not defined: -system"; then
  reg_ok "non-root --system is rejected as an undefined flag"
else
  reg_fail "non-root --system must be an undefined flag (rc=$SYS_RC, output below)
$(printf '%s\n' "$SYS_OUT" | redact | head -5)"
fi

reg_result
