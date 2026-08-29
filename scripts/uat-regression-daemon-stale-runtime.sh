#!/usr/bin/env bash
#
# uat-regression-daemon-stale-runtime.sh — Release-2 targeted regression group 9:
# Daemon stale-runtime recovery (Ubuntu / DEB / AppArmor).
#
# Sequence:
#   1. normal system-mode initialization (service active);
#   2. prove Session/run works;
#   3. SIGKILL the daemon;
#   4. no normal cleanup;
#   5. restart the service;
#   6. stale socket/lock/runtime artifacts do not block startup;
#   7. the service is again AppArmor-confined;
#   8. create a fresh Session;
#   9. a fresh run succeeds;
#  10. no harmful stale runtime state remains.
# This is daemon/runtime startup recovery ONLY: no desired-state/container
# recovery semantics are asserted.
#
# Requires: installed docker-helper system service (active, AppArmor system
# mode), Docker reachable, root. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "9. Daemon stale-runtime recovery"

reg_require_root
reg_require_service
reg_require_docker

IMAGE="alpine:3.24"
USER="uatreg9"
SOCK="/run/docker-helper/docker-helper.sock"

home="$(reg_setup_principal "$USER")" || { reg_fail "setup principal failed"; reg_result; }
ws="$home/ws"; mkdir -p "$ws"
chown -R "$USER:$USER" "$ws"

cred="/tmp/uat-reg9.token"
reg_principal_credential "$USER" "$cred" || { reg_fail "credential create failed"; reg_result; }
reg_session "$cred" "$ws" || { reg_fail "session create failed"; reg_result; }
stok="$REG_SESSION_TOKEN"

# --- 2. prove Session/run works (baseline) --------------------------------------
if DOCKER_HELPER_SESSION_TOKEN="$stok" \
    dh run --image "$IMAGE" -- sh -ec 'true' >/dev/null 2>&1; then
  reg_ok "baseline session run works before SIGKILL"
else
  reg_fail "baseline session run failed before SIGKILL"
  reg_result
fi

# --- 3+4. SIGKILL the daemon with no normal cleanup ------------------------------
DAEMON_PID="$(systemctl show -p MainPID --value docker-helper.service)"
if [ -z "$DAEMON_PID" ] || [ "$DAEMON_PID" = "0" ]; then
  reg_fail "cannot determine daemon MainPID for SIGKILL"
  reg_result
fi
kill -9 "$DAEMON_PID" 2>/dev/null || { reg_fail "SIGKILL failed"; reg_result; }
sleep 1
# Cancel any systemd auto-restart and mark the unit as explicitly stopped so the
# next start is a genuine fresh restart against the stale runtime.
systemctl stop docker-helper.service >/dev/null 2>&1 || true
systemctl reset-failed docker-helper.service >/dev/null 2>&1 || true
if systemctl is-active --quiet docker-helper.service; then
  reg_fail "daemon still active after SIGKILL+stop (auto-restart interfered)"
  reg_result
fi
reg_ok "daemon SIGKILLed and left stopped (no normal cleanup)"

if [ -S "$SOCK" ]; then
  reg_ok "stale socket file present after SIGKILL (no cleanup ran)"
else
  reg_info "stale socket not present after SIGKILL (runtime may have been recreated)"
fi

# --- 5+6. restart; stale socket/lock must not block startup -----------------------
if systemctl start docker-helper.service 2>/tmp/reg9-start.err; then
  reg_ok "service restarted despite stale socket/lock runtime"
else
  reg_fail "service did not restart over stale runtime: $(cat /tmp/reg9-start.err | head -3)"
  reg_result
fi
for _ in $(seq 1 30); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
if systemctl is-active --quiet docker-helper.service; then
  reg_ok "service is active after restart"
else
  reg_fail "service not active after restart"
  reg_result
fi

# --- 7. service again AppArmor-confined -------------------------------------------
NEW_PID="$(systemctl show -p MainPID --value docker-helper.service)"
ATTR="$(cat "/proc/$NEW_PID/attr/current" 2>/dev/null || true)"
if [ "$ATTR" = "docker-helper-system (enforce)" ]; then
  reg_ok "service is again AppArmor-confined (docker-helper-system enforce)"
else
  reg_fail "service not AppArmor-confined after restart (attr='$ATTR')"
fi

# --- 8+9. fresh Session + run succeeds --------------------------------------------
reg_session "$cred" "$ws" || { reg_fail "fresh session create failed after restart"; reg_result; }
freshtok="$REG_SESSION_TOKEN"
if DOCKER_HELPER_SESSION_TOKEN="$freshtok" \
    dh run --image "$IMAGE" -- sh -ec 'echo FRESH-OK' | grep -q 'FRESH-OK'; then
  reg_ok "fresh session run succeeds after restart"
else
  reg_fail "fresh session run failed after restart"
fi

# --- 10. no harmful stale runtime state remains ------------------------------------
# A fake leftover session runtime dir must be removed by startup cleanup.
FAKE="/run/docker-helper/sessions/dhs_$(openssl rand -hex 16)/docker"
mkdir -p "$FAKE"
reg_info "planted fake stale session runtime dir: $(dirname "$FAKE")"
# Restart once more so the planted stale dir is observed at startup. The
# subcase oracle is the disappearance of the planted stale session runtime
# dir itself: systemctl is-active becomes active before the daemon's startup
# sweep has run, so it is not a sufficient startup-completion signal. Poll
# the real condition at short bounded intervals (no blind sleep) and require
# the daemon API to be reachable too (GET /health is served on the unix
# socket only after the startup sweep completes). Fail immediately if the
# service exits/fails while we wait.
systemctl restart docker-helper.service >/dev/null 2>&1 || true
STALE="$(dirname "$FAKE")"
READY=0
for _ in $(seq 1 50); do
  if [ ! -e "$STALE" ] && \
     curl --silent --fail --max-time 1 \
       --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1; then
    READY=1
    break
  fi
  if ! systemctl is-active --quiet docker-helper.service 2>/dev/null; then
    reg_fail "docker-helper.service exited/failed while waiting for stale runtime cleanup"
    reg_result
  fi
  sleep 0.2
done
if [ "$READY" = 1 ]; then
  reg_ok "stale session runtime dir removed at startup"
else
  reg_fail "stale session runtime dir was NOT cleaned at startup"
fi

PINS="$(find /run/docker-helper/mounts -mindepth 2 -maxdepth 2 -type d 2>/dev/null | grep -E '/[0-9]+$' || true)"
CIDS="$(find /run/docker-helper -maxdepth 1 -name '*.cid' 2>/dev/null || true)"
if [ -z "$PINS" ] && [ -z "$CIDS" ]; then
  reg_ok "no stale mount pins or cid files remain"
else
  reg_fail "stale runtime remains: pins='$PINS' cids='$CIDS'"
fi

# best-effort cleanup
dh principal delete --system "$USER" >/dev/null 2>&1 || true
userdel -r "$USER" >/dev/null 2>&1 || true
rm -f "$cred" /tmp/reg9-start.err

reg_result
