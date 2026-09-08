#!/usr/bin/env bash
#
# uat-regression-helper-socket.sh — 2.1.1 targeted regression group 16:
# helper_socket runtime projection (Ubuntu / DEB / AppArmor).
#
# Black-box acceptance of the --helper-socket server-owned capability in
# system mode:
#   * a workload without --helper-socket does not see the helper runtime
#     or socket;
#   * a workload with --helper-socket sees /run/docker-helper/
#     docker-helper.sock and can reach the daemon through it;
#   * ordinary absolute --mount sources remain rejected (the helper runtime
#     path is not obtainable through the ordinary mount contract);
#   * workspace escape remains rejected;
#   * the socket provides transport only: an operation without a bearer
#     credential is refused at the API boundary;
#   * the injected bind is read-only and top-level runtime entries cannot
#     be created or removed by the workload;
#   * helper-private runtime state (builds/, mounts/, sessions/, the socket
#     lock) stays unreadable for the Principal-UID workload;
#   * a REAL service restart terminates the running workload (the 2.1.0
#     run lifecycle intentionally leaves no orphan containers), preserves
#     the /run/docker-helper directory inode, and recreates the socket
#     inside it; a fresh --helper-socket workload sees the new socket;
#   * the pre-existing directory projection of a surviving orphaned
#     workload sees the recreated socket after a daemon crash-restart and
#     performs an authorized launcher operation through it.
#
# The script never prints a real credential token.
#
# Requires: installed docker-helper system service (active), Docker
# reachable, root, systemd. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "16. helper_socket runtime projection"

reg_require_root
reg_require_service
reg_require_docker
reg_require_cmd systemctl "restart semantics drive the real service lifecycle"

IMAGE="alpine:3.24"
USER="uatreg16"

home="$(reg_setup_principal "$USER")" || { reg_fail "setup principal failed"; reg_result; }
ws="$home/ws"; mkdir -p "$ws"
chown -R "$USER:$USER" "$ws"

cred="/tmp/uat-reg16.token"
reg_principal_credential "$USER" "$cred" || { reg_fail "credential create failed"; reg_result; }
LAUNCHER_CRED_TOKEN="$REG_CRED_TOKEN"
reg_session "$cred" "$ws" || { reg_fail "session create failed"; reg_result; }
SESSION_TOKEN="$REG_SESSION_TOKEN"

# The workload uses the packaged docker-helper CLI itself through the
# injected socket; the binary must be inside the container, so the host
# binary is placed into the workspace (the workspace bind carries it in).
cp /usr/bin/docker-helper "$ws/docker-helper"
chmod 755 "$ws/docker-helper"
chown "$USER:$USER" "$ws/docker-helper"

# --- basic isolation: no socket without the capability -----------------------
if DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
   dh run --image "$IMAGE" -- sh -ec 'test ! -e /run/docker-helper/docker-helper.sock' >/dev/null 2>&1; then
  reg_ok "workload without --helper-socket does not receive the helper runtime"
else
  reg_fail "workload without --helper-socket saw the helper runtime/socket"
fi

# --- with the capability the socket is present -------------------------------
if DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
   dh run --image "$IMAGE" --helper-socket -- sh -ec 'test -S /run/docker-helper/docker-helper.sock' >/dev/null 2>&1; then
  reg_ok "workload with --helper-socket sees /run/docker-helper/docker-helper.sock"
else
  reg_fail "workload with --helper-socket did NOT see /run/docker-helper/docker-helper.sock"
fi

# --- ordinary absolute mount of the helper runtime remains rejected ----------
DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
  dh run --image "$IMAGE" --mount "/run/docker-helper:/run/docker-helper" -- true \
  >/tmp/uat-reg16-absmount.out 2>/tmp/uat-reg16-absmount.err
ABS_RC=$?
if [ "$ABS_RC" != 0 ] && grep -q "relative" /tmp/uat-reg16-absmount.err 2>/dev/null; then
  reg_ok "ordinary absolute --mount of the helper runtime path remains rejected"
else
  reg_fail "absolute --mount handling unexpected (rc=$ABS_RC, stderr: $(cat /tmp/uat-reg16-absmount.err 2>/dev/null))"
fi

# --- workspace escape remains rejected ---------------------------------------
DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
  dh run --image "$IMAGE" --mount "../uatreg16-escape:/escape" -- true \
  >/tmp/uat-reg16-escape.out 2>/tmp/uat-reg16-escape.err
ESC_RC=$?
if [ "$ESC_RC" != 0 ]; then
  reg_ok "workspace escape mount remains rejected"
else
  reg_fail "workspace escape mount was NOT rejected"
fi

# --- transport only: no bearer credential means no protected operation -------
DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
  dh run --image "$IMAGE" --helper-socket --mount .:/workspace \
  -- sh -ec '/workspace/docker-helper pull alpine:3.24' \
  >/tmp/uat-reg16-noauth.out 2>/tmp/uat-reg16-noauth.err
NOAUTH_RC=$?
if [ "$NOAUTH_RC" != 0 ] && grep -q "unauthorized" /tmp/uat-reg16-noauth.err 2>/dev/null; then
  reg_ok "socket without a bearer credential performs no protected operation (unauthorized)"
else
  reg_fail "credential-free socket use did not fail closed (rc=$NOAUTH_RC, stderr: $(cat /tmp/uat-reg16-noauth.err 2>/dev/null))"
fi

# --- runtime directory protection: read-only bind ----------------------------
if DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
   dh run --image "$IMAGE" --helper-socket -- sh -ec '
    touch /run/docker-helper/uat16-nope 2>/dev/null && exit 1
    mkdir /run/docker-helper/uat16-dir 2>/dev/null && exit 1
    rm /run/docker-helper/docker-helper.sock 2>/dev/null && exit 1
    true' >/dev/null 2>&1; then
  reg_ok "workload cannot create or remove top-level runtime entries (read-only bind)"
else
  reg_fail "workload mutated top-level runtime entries (bind is not read-only)"
fi

# --- helper-private runtime state stays unreadable ---------------------------
if DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
   dh run --image "$IMAGE" --helper-socket -- sh -ec '
    cat /run/docker-helper/docker-helper.sock.lock >/dev/null 2>&1 && exit 1
    ls /run/docker-helper/builds >/dev/null 2>&1 && exit 1
    ls /run/docker-helper/mounts >/dev/null 2>&1 && exit 1
    ls /run/docker-helper/sessions >/dev/null 2>&1 && exit 1
    true' >/dev/null 2>&1; then
  reg_ok "helper-private runtime directories/state unreadable for the workload"
else
  reg_fail "workload read helper-private runtime state"
fi

# --- restart semantics (real service restart) --------------------------------
RUNTIME_DIR_INODE_BEFORE="$(stat -c %i /run/docker-helper)"
SOCKET_INODE_BEFORE="$(stat -c %i /run/docker-helper/docker-helper.sock)"
rm -f "$ws/reg16-restart-started" 2>/dev/null || true

DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" dh run --image "$IMAGE" \
  --helper-socket --mount .:/workspace \
  -- sh -ec 'echo started > /workspace/reg16-restart-started; sleep 60' \
  >/tmp/uat-reg16-restart.out 2>/tmp/uat-reg16-restart.err &
RESTART_CLI_PID=$!

for _ in $(seq 1 20); do
  [ -f "$ws/reg16-restart-started" ] && break
  sleep 1
done
[ -f "$ws/reg16-restart-started" ] || reg_fail "restart probe workload never started"

systemctl restart docker-helper.service
for _ in $(seq 1 60); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
systemctl is-active --quiet docker-helper.service || { reg_fail "service did not come back after restart"; reg_result; }

# Documented finding: the 2.1.0 run lifecycle terminates running operations
# at shutdown (graceful SIGTERM to the docker CLI, bounded force cleanup by
# cidfile). The workload is therefore killed by the daemon's own lifecycle.
RESTART_ALIVE=0
if kill -0 "$RESTART_CLI_PID" 2>/dev/null; then
  RESTART_ALIVE=1
fi
if [ "$RESTART_ALIVE" = 0 ]; then
  reg_ok "running workload terminated by the real service restart (lifecycle finding)"
else
  kill -9 "$RESTART_CLI_PID" 2>/dev/null || true
  reg_fail "running workload survived the real service restart"
fi

RUNTIME_DIR_INODE_AFTER="$(stat -c %i /run/docker-helper)"
SOCKET_INODE_AFTER="$(stat -c %i /run/docker-helper/docker-helper.sock)"
if [ "$RUNTIME_DIR_INODE_BEFORE" = "$RUNTIME_DIR_INODE_AFTER" ]; then
  reg_ok "runtime directory inode preserved across the real restart (bindable, not socket inode)"
else
  reg_fail "runtime directory inode changed across the real restart ($RUNTIME_DIR_INODE_BEFORE -> $RUNTIME_DIR_INODE_AFTER)"
fi
if [ "$SOCKET_INODE_BEFORE" != "$SOCKET_INODE_AFTER" ] && [ -S /run/docker-helper/docker-helper.sock ]; then
  reg_ok "daemon socket recreated with a new inode inside the same directory"
else
  reg_fail "daemon socket was not recreated as a new inode ($SOCKET_INODE_BEFORE -> $SOCKET_INODE_AFTER)"
fi

if DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
   dh run --image "$IMAGE" --helper-socket -- sh -ec 'test -S /run/docker-helper/docker-helper.sock' >/dev/null 2>&1; then
  reg_ok "fresh --helper-socket workload sees the recreated socket after restart"
else
  reg_fail "fresh --helper-socket workload did NOT see the recreated socket"
fi

# --- pre-existing projection across a daemon crash-restart -------------------
# The graceful restart terminates run workloads by design, so the surviving
# pre-existing-bind scenario is exercised on the crash-restart path: the
# daemon is SIGKILLed (hard crash), the service auto-restarts, and the
# orphaned workload observes the recreated socket through its already
# existing directory bind and performs an authorized launcher operation
# through it.
rm -f "$ws/reg16-orphan-old" "$ws/reg16-orphan-new" "$ws/reg16-orphan-ready" \
      "$ws/reg16-orphan-result" "$ws/reg16-orphan-list.json" "$ws/reg16-orphan-list.err" 2>/dev/null || true

DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" UAT_LAUNCHER_CRED_SOURCE="$LAUNCHER_CRED_TOKEN" \
  dh run --image "$IMAGE" \
  --helper-socket --mount .:/workspace \
  --env-from "UAT_REG16_CRED=UAT_LAUNCHER_CRED_SOURCE" \
  -- sh -ec '
    set -eu
    OLD_I=$(stat -c %i /run/docker-helper/docker-helper.sock)
    printf "%s" "$OLD_I" > /workspace/reg16-orphan-old
    touch /workspace/reg16-orphan-ready
    NEW_I=0
    for i in $(seq 1 90); do
      NEW_I=$(stat -c %i /run/docker-helper/docker-helper.sock 2>/dev/null || echo 0)
      if [ "$NEW_I" != "0" ] && [ "$NEW_I" != "$OLD_I" ]; then break; fi
      sleep 1
    done
    printf "%s" "$NEW_I" > /workspace/reg16-orphan-new
    printf "%s\n" "$UAT_REG16_CRED" > /tmp/launcher-cred
    chmod 600 /tmp/launcher-cred
    if /workspace/docker-helper session list \
        --endpoint /run/docker-helper/docker-helper.sock \
        --token-file /tmp/launcher-cred --json \
        > /workspace/reg16-orphan-list.json 2> /workspace/reg16-orphan-list.err; then
      echo ok > /workspace/reg16-orphan-result
    else
      echo fail > /workspace/reg16-orphan-result
    fi
    rm -f /tmp/launcher-cred
  ' >/tmp/uat-reg16-orphan.out 2>/tmp/uat-reg16-orphan.err &
ORPHAN_CLI_PID=$!

for _ in $(seq 1 20); do
  [ -f "$ws/reg16-orphan-ready" ] && break
  sleep 1
done
if [ ! -f "$ws/reg16-orphan-ready" ]; then
  reg_fail "orphan probe never recorded its pre-restart socket"
  kill -9 "$ORPHAN_CLI_PID" 2>/dev/null || true
  reg_result
fi

# Hard-crash the daemon (no graceful cleanup): only the daemon cgroup dies;
# the container process lives in its own Docker cgroup and survives.
systemctl kill --kill-whom=all --signal=SIGKILL docker-helper.service
for _ in $(seq 1 90); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
systemctl is-active --quiet docker-helper.service || { reg_fail "service did not auto-restart after the crash"; reg_result; }

for _ in $(seq 1 120); do
  [ -f "$ws/reg16-orphan-result" ] && break
  sleep 1
done

ORPHAN_RESULT="$(cat "$ws/reg16-orphan-result" 2>/dev/null || echo missing)"
ORPHAN_OLD_I="$(cat "$ws/reg16-orphan-old" 2>/dev/null || echo 0)"
ORPHAN_NEW_I="$(cat "$ws/reg16-orphan-new" 2>/dev/null || echo 0)"
if [ "$ORPHAN_RESULT" = "ok" ]; then
  reg_ok "surviving pre-existing directory projection performed an authorized operation after daemon recovery"
else
  reg_fail "surviving pre-existing projection failed (result=$ORPHAN_RESULT, stderr: $(cat "$ws/reg16-orphan-list.err" 2>/dev/null))"
fi
if [ "$ORPHAN_NEW_I" != "$ORPHAN_OLD_I" ] && [ "$ORPHAN_NEW_I" != "0" ]; then
  reg_ok "pre-existing projection observed the newly created socket inode"
else
  reg_fail "pre-existing projection did not observe a new socket inode ($ORPHAN_OLD_I -> $ORPHAN_NEW_I)"
fi
if [ -s "$ws/reg16-orphan-list.json" ]; then
  reg_ok "authorized launcher operation returned session data through the injected socket"
else
  reg_fail "authorized launcher operation returned no session data"
fi

# --- cleanup: stop the orphaned probe container ------------------------------
CID_LIST="$(docker ps -q --filter "label=com.dockerhelper.session.id=$REG_SESSION_ID" 2>/dev/null || true)"
if [ -n "$CID_LIST" ]; then
  docker rm -f $CID_LIST >/dev/null 2>&1 || true
fi
rm -f /tmp/uat-reg16.* 2>/dev/null || true
rm -f "$ws"/reg16-* 2>/dev/null || true

reg_result
