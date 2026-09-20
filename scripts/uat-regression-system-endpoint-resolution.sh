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
# positively, not inferred from success alone. The connection counter is
# observable state: the listener durably records every accepted connection
# in a counter file, and a NEGATIVE SELF-TEST runs first — a deliberate
# control connection must move the counter 0 -> 1 before the real probes,
# otherwise the harness is broken and the group is BLOCKED, never PASS.
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

# fake_connections — read the listener's durable connection counter. A
# missing, empty, or non-numeric counter file is an ERROR (non-zero rc), not
# a silent zero: the counter must be real observable state, and masking a
# broken counter as "zero connections" would fake the whole proof.
# Defined before the listener starts: the readiness loop reads it.
fake_connections() {
  python3 -c '
import sys
try:
    with open(sys.argv[1]) as fh:
        data = fh.read().strip()
    n = int(data)
    assert n >= 0
except Exception:
    sys.exit(1)
print(n)
' "$FAKE_COUNT_FILE" 2>/dev/null
}

# A real listening fake user socket, owned by the probe account. The
# listener durably records every accepted connection into the counter file
# (atomic replace on each accept), so the count is observable state on
# disk, not listener-internal memory.
EP_RUN="$EP_HOME/xdg-run"
FAKE_SOCK_DIR="$EP_RUN/docker-helper"
FAKE_SOCK="$FAKE_SOCK_DIR/docker-helper.sock"
FAKE_COUNT_FILE="$EP_HOME/xdg-run/fake-socket-connections"
rm -rf "$EP_RUN"
mkdir -p "$FAKE_SOCK_DIR"
chown -R "$EP_USER:$EP_USER" "$EP_RUN"
sudo -u "$EP_USER" env HOME="$EP_HOME" XDG_RUNTIME_DIR="$EP_RUN" \
  python3 -c '
import os, socket, sys, threading, signal
path, count_path = sys.argv[1], sys.argv[2]

def write_count(n):
    tmp = count_path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(str(n))
        fh.flush()
    os.replace(tmp, count_path)

try:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(16)
    accepted = [0]
    lock = threading.Lock()
    def accept_loop():
        srv.settimeout(0.5)
        while True:
            try:
                conn, _ = srv.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                return
            with lock:
                accepted[0] += 1
                write_count(accepted[0])
    t = threading.Thread(target=accept_loop)
    write_count(accepted[0])
    t.start()
    signal.pause()
except Exception as e:
    sys.stderr.write("fake listener failed: %s\n" % e)
    sys.exit(1)
' "$FAKE_SOCK" "$FAKE_COUNT_FILE" >/dev/null 2>&1 &
FAKE_PID=$!
for _ in $(seq 1 20); do
  [ -S "$FAKE_SOCK" ] && [ "$(fake_connections 2>/dev/null)" = "0" ] && break
  sleep 0.1
done
[ -S "$FAKE_SOCK" ] || { kill "$FAKE_PID" 2>/dev/null || true; reg_blocked "the fake user socket listener did not start"; }
[ "$(fake_connections 2>/dev/null)" = "0" ] \
  || { kill "$FAKE_PID" 2>/dev/null || true; reg_blocked "the fake user socket counter file did not reach its initial zero state"; }
reg_ok "fake per-user daemon socket is listening at $FAKE_SOCK (counter observable at 0)"

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
# A0. NEGATIVE SELF-TEST: the connection counter must actually observe
#     connections. A deliberate control client connects to the fake socket
#     and the counter must move 0 -> 1; only then is the counter reset to
#     zero for the real probes. If the self-test cannot observe the
#     artificial connection, the harness cannot prove absence of probing
#     and the group is BLOCKED, never PASS.
# ---------------------------------------------------------------------------
ep_cli python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.close()
' "$FAKE_SOCK" \
  || reg_blocked "the control client could not connect to the fake user socket"

SELF_CONN_OK=""
for _ in $(seq 1 50); do
  if [ "$(fake_connections 2>/dev/null)" = "1" ]; then
    SELF_CONN_OK=1
    break
  fi
  sleep 0.1
done
if [ "$SELF_CONN_OK" != "1" ]; then
  reg_blocked "counter self-test failed: the deliberate control connection was not reflected in the observable counter; the zero-probe proof is not trustworthy (last count: '$(fake_connections 2>/dev/null)')"
fi
reg_ok "counter self-test: the deliberate connection moved the counter 0 -> 1"

# Reset the observable counter to zero for the real probes. The listener's
# in-memory count keeps incrementing, so any post-reset accepted connection
# moves the counter file away from exactly 0 and fails the proof.
printf '0' > "$FAKE_COUNT_FILE"
if [ "$(fake_connections 2>/dev/null)" != "0" ]; then
  reg_blocked "counter reset did not reach a readable zero state"
fi
reg_ok "counter reset to zero for the real probes"

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

CONN_COUNT="$(fake_connections 2>/dev/null)" || CONN_COUNT=""
if [ "$CONN_COUNT" = "0" ]; then
  reg_ok "the fake user socket accepted zero connections after the self-test (no client probing)"
else
  reg_fail "the fake user socket accepted connections (observed count '$CONN_COUNT'); the client must never probe it"
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
