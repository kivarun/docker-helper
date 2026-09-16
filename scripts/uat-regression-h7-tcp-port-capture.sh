#!/usr/bin/env bash
#
# uat-regression-h7-tcp-port-capture.sh — Release-2 targeted regression
# group 23: H7 optional TCP listener liveness (Ubuntu / DEB / AppArmor).
#
# A local unprivileged user binds and holds docker-helper's configured
# loopback TCP port. The pre-fix startup treated that TCP bind failure as
# fatal: it closed the authoritative Unix listener, removed its socket, and
# failed the daemon — which the shipped Restart=on-failure +
# StartLimitBurst=3 unit turned into a restart storm and start-limit failure.
#
# Post-fix contract proven here against the real packaged system service
# (mandatory MAC active; the finding is not MAC-specific):
#   * the service starts and stays active with the port captured;
#   * the authoritative Unix socket exists and serves the authenticated API;
#   * the hostile process still owns the TCP port; docker-helper did not
#     steal or replace it;
#   * the journal carries exactly the bounded degraded-TCP warning
#     (configured address + bind failure);
#   * no restart storm (NRestarts does not grow; no start-limit failure);
#   * after the hostile listener is released and the service is normally
#     restarted, both Unix and TCP listeners work again.
#
# No privileged process holds the port; no pre-probe is performed by the
# daemon (the bind itself is the authority).
#
# Requires: installed docker-helper system service (active), root, curl, ss,
# python3. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "23. H7 hostile TCP port capture: degraded startup keeps Unix authoritative"

reg_require_root
reg_require_service
reg_require_cmd curl "Unix and loopback /health probes"
reg_require_cmd ss "TCP listener ownership inventory"
reg_require_cmd python3 "unprivileged hostile TCP port holder"
reg_require_cmd journalctl "degraded-startup warning evidence"

SOCK="/run/docker-helper/docker-helper.sock"

# --- baseline: service healthy, configured loopback TCP address -----------------
HTTP_ADDR="$(dh config show http_address 2>/dev/null || true)"
case "$HTTP_ADDR" in
  127.0.0.1:*) : ;;
  *) reg_fail "cannot read the configured loopback TCP address ('$HTTP_ADDR')"; reg_result ;;
esac
PORT="${HTTP_ADDR##*:}"
reg_ok "configured loopback TCP address: $HTTP_ADDR"

reg_fail_early() { reg_fail "$1"; reg_result; }

# --- hostile holder: an ordinary unprivileged local user binds the port ---------
# The capture must happen BEFORE service startup (the finding scenario): the
# runner re-ensures the service before each group, so the daemon may currently
# own the port. Stop it first and prove the port is free.
systemctl stop docker-helper.service >/dev/null 2>&1 || true
systemctl reset-failed docker-helper.service >/dev/null 2>&1 || true
PORT_FREE_BEFORE=1
for _ in $(seq 1 50); do
  if ! ss -ltn "sport = :$PORT" 2>/dev/null | grep -q LISTEN; then PORT_FREE_BEFORE=0; break; fi
  sleep 0.2
done
[ "$PORT_FREE_BEFORE" -eq 0 ] || reg_fail_early "the configured TCP port is not free before the hostile capture"

H7_USER="h7holder"
id -u "$H7_USER" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$H7_USER" 2>/dev/null \
  || reg_fail_early "cannot create the unprivileged hostile user"

HOLDER_UID=""
start_holder() {
  sudo -u "$H7_USER" python3 -c '
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(1)
sys.stderr.write("held\n")
sys.stderr.flush()
while True:
    time.sleep(3600)
' "$PORT" >/tmp/h7-holder.out 2>/tmp/h7-holder.err &
  HOLD_PID=$!
  # The hold is proven, not assumed: wait until the kernel reports the port
  # LISTENING and the listener process belongs to the unprivileged holder
  # (bounded; the holder exits nonzero if the bind failed).
  for _ in $(seq 1 30); do
    if ! kill -0 "$HOLD_PID" 2>/dev/null; then return 1; fi
    if ss -ltn "sport = :$PORT" 2>/dev/null | grep -q LISTEN; then
      local uid user
      uid="$(ss -ltnp "sport = :$PORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"
      user="$(ps -o user= -p "$uid" 2>/dev/null || true)"
      if [ "$user" = "$H7_USER" ]; then
        HOLDER_UID="$uid"
        return 0
      fi
    fi
    sleep 0.2
  done
  return 1
}
stop_holder() {
  if [ -n "$HOLD_PID" ] && kill -0 "$HOLD_PID" 2>/dev/null; then
    kill "$HOLD_PID" 2>/dev/null || true
    wait "$HOLD_PID" 2>/dev/null || true
  fi
}
trap stop_holder EXIT

start_holder || reg_fail_early "the hostile holder could not take the port (holder log: $(tail -2 /tmp/h7-holder.err 2>/dev/null | redact))"
reg_ok "unprivileged hostile holder owns TCP $HTTP_ADDR (pid $HOLDER_UID as $H7_USER)"

# --- restart the real packaged service with the port captured -------------------
JOURNAL_MARK="$(date '+%Y-%m-%d %H:%M:%S')"
if systemctl restart docker-helper.service 2>/tmp/h7-restart.err; then
  reg_ok "service restart command completed with the TCP port captured"
else
  reg_fail_early "service restart failed with the TCP port captured: $(head -3 /tmp/h7-restart.err | redact)"
fi

# The authoritative service must reach and STAY active (no restart storm,
# no start-limit failure).
ACTIVE_OK=1
for _ in $(seq 1 30); do
  if systemctl is-active --quiet docker-helper.service 2>/dev/null; then
    ACTIVE_OK=0; break
  fi
  sleep 1
done
if [ "$ACTIVE_OK" -eq 0 ]; then
  reg_ok "systemd service reaches and stays active with the TCP port captured"
else
  reg_fail_early "service did not stay active with the TCP port captured (is-active: $(systemctl is-active docker-helper.service 2>&1), is-failed: $(systemctl is-failed docker-helper.service 2>&1))"
fi
if [ "$(systemctl is-failed docker-helper.service 2>/dev/null)" != "failed" ]; then
  reg_ok "service is not in start-limit/failed state"
else
  reg_fail_early "service entered start-limit/failed state"
fi
NRESTARTS="$(systemctl show -p NRestarts --value docker-helper.service 2>/dev/null || echo '?')"
case "$NRESTARTS" in
  ''|*[!0-9]*) reg_fail_early "cannot read NRestarts ('$NRESTARTS')" ;;
  *) if [ "$NRESTARTS" -le 1 ]; then
       reg_ok "no restart storm (NRestarts=$NRESTARTS)"
     else
       reg_fail_early "restart storm detected (NRestarts=$NRESTARTS)"
     fi ;;
esac

# --- Unix authority: socket exists, authenticated API + health work -------------
if [ -S "$SOCK" ]; then
  reg_ok "authoritative Unix socket exists"
else
  reg_fail_early "authoritative Unix socket missing with the TCP port captured"
fi
if curl --silent --fail --max-time 2 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1; then
  reg_ok "GET /health over Unix works during degraded startup"
else
  reg_fail_early "GET /health over Unix failed during degraded startup"
fi
if dh config show http_address >/dev/null 2>&1; then
  reg_ok "authenticated API operation over Unix works during degraded startup"
else
  reg_fail_early "authenticated API operation over Unix failed during degraded startup"
fi

# --- the hostile process still owns the port; docker-helper did not take it ----
if ss -ltn "sport = :$PORT" 2>/dev/null | grep -q LISTEN; then
  NOW_UID="$(ss -ltnp "sport = :$PORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"
  NOW_USER="$(ps -o user= -p "$NOW_UID" 2>/dev/null || true)"
  if [ "$NOW_UID" = "$HOLDER_UID" ] && [ "$NOW_USER" = "$H7_USER" ]; then
    reg_ok "hostile process still owns the TCP port; docker-helper did not steal or replace it"
  else
    reg_fail_early "the TCP port owner changed (was pid $HOLDER_UID/$H7_USER, now pid $NOW_UID/$NOW_USER)"
  fi
else
  reg_fail_early "the hostile holder no longer owns the port"
fi

# --- the bounded degraded-TCP warning in the journal ----------------------------
JOURNAL_DEGRADED="$(journalctl -u docker-helper.service --since "$JOURNAL_MARK" --no-pager 2>/dev/null \
  | grep -c 'loopback TCP listener unavailable' || true)"
case "$JOURNAL_DEGRADED" in
  1) reg_ok "journal carries exactly one bounded degraded-TCP warning" ;;
  0) reg_fail_early "journal is missing the degraded-TCP warning (window since $JOURNAL_MARK)" ;;
  *) reg_fail_early "journal carries $JOURNAL_DEGRADED degraded-TCP warnings (expected exactly one)" ;;
esac
if journalctl -u docker-helper.service --since "$JOURNAL_MARK" --no-pager 2>/dev/null | grep 'loopback TCP listener unavailable' | grep -q "$HTTP_ADDR"; then
  reg_ok "the degraded warning contains the configured address"
else
  reg_fail_early "the degraded warning does not contain the configured address $HTTP_ADDR"
fi
if journalctl -u docker-helper.service --since "$JOURNAL_MARK" --no-pager 2>/dev/null | grep 'loopback TCP listener unavailable' | grep -q 'address already in use'; then
  reg_ok "the degraded warning contains the bind failure"
else
  reg_fail_early "the degraded warning does not contain the bind failure"
fi
if journalctl -u docker-helper.service --since "$JOURNAL_MARK" --no-pager 2>/dev/null | grep -q 'daemon startup failed'; then
  reg_fail_early "degraded startup must not be logged as a fatal startup failure"
else
  reg_ok "degradation is not logged as a fatal startup failure"
fi

# --- release the hostile listener; a normal restart restores both transports ---
stop_holder
PORT_FREE=1
for _ in $(seq 1 50); do
  if ! ss -ltn "sport = :$PORT" 2>/dev/null | grep -q LISTEN; then PORT_FREE=0; break; fi
  sleep 0.2
done
if [ "$PORT_FREE" -eq 0 ]; then
  reg_ok "hostile listener released; TCP port is free again"
else
  reg_fail_early "the TCP port is still occupied after releasing the hostile listener"
fi

RECOVERY_CURSOR="$(journalctl -n 0 --show-cursor -q 2>/dev/null | grep -oE 's=[a-f0-9]+' | head -1 || true)"
systemctl restart docker-helper.service 2>/dev/null || reg_fail_early "normal restart after release failed"
for _ in $(seq 1 30); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
systemctl is-active --quiet docker-helper.service || reg_fail_early "service not active after the recovery restart"

if curl --silent --fail --max-time 2 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1; then
  reg_ok "Unix listener works after the recovery restart"
else
  reg_fail_early "Unix listener broken after the recovery restart"
fi
if curl --silent --fail --max-time 2 "http://$HTTP_ADDR/health" >/dev/null 2>&1; then
  reg_ok "TCP listener works again after the recovery restart"
else
  reg_fail_early "TCP listener did not come back after the recovery restart"
fi
# The cursor-based window is exact: a same-second capture-phase warning can
# never bleed into the recovery window (second-granularity --since did).
if [ -n "$RECOVERY_CURSOR" ] && journalctl -u docker-helper.service --after-cursor "$RECOVERY_CURSOR" --no-pager 2>/dev/null | grep -q 'loopback TCP listener unavailable'; then
  reg_fail_early "the recovery restart must not report a degraded TCP listener"
elif [ -z "$RECOVERY_CURSOR" ]; then
  reg_fail_early "cannot obtain the journal cursor for the recovery window (absence is never assumed)"
else
  reg_ok "recovery restart reports no degraded TCP listener"
fi

# --- cleanup ---------------------------------------------------------------------
stop_holder
deluser --remove-home "$H7_USER" >/dev/null 2>&1 || userdel -r "$H7_USER" >/dev/null 2>&1 || true
rm -f /tmp/h7-holder.out /tmp/h7-holder.err /tmp/h7-restart.err 2>/dev/null || true

reg_result
