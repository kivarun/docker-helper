#!/usr/bin/env bash
#
# uat-regression-concurrent-mount-pins.sh — Release-2 targeted regression
# group 7: Concurrent mount pins (Ubuntu / DEB / AppArmor).
#
# Two simultaneous active operations against the same mount source:
#   * both work and both access their pinned source;
#   * ending operation A does not break operation B;
#   * B still accesses its pinned source after A ends;
#   * after both exit, no stale pin/mount runtime remains.
# Asserts observable lifecycle behavior, not an internal refcount.
#
# Requires: installed docker-helper system service (active, system mode),
# Docker reachable, root. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "7. Concurrent mount pins"

reg_require_root
reg_require_service
reg_require_docker

IMAGE="alpine:3.24"
USER="uatreg7"

home="$(reg_setup_principal "$USER")" || { reg_fail "setup principal failed"; reg_result; }
ws="$home/ws"; shared="$ws/shared"; mkdir -p "$shared"
printf 'CONTENT-C\n' > "$shared/file"
chown -R "$USER:$USER" "$ws"

cred="/tmp/uat-reg7.token"
reg_principal_credential "$USER" "$cred" || { reg_fail "credential create failed"; reg_result; }
reg_session "$cred" "$ws" || { reg_fail "session create failed"; reg_result; }
stok="$REG_SESSION_TOKEN"

SA='cat /mnt/shared/file > /mnt/shared/phaseA; echo startedA > /mnt/shared/startedA; while [ ! -f /mnt/shared/releaseA ]; do sleep 1; done; echo OP-A-DONE'
SB='cat /mnt/shared/file > /mnt/shared/phaseB; echo startedB > /mnt/shared/startedB; while [ ! -f /mnt/shared/releaseB ]; do sleep 1; done; cat /mnt/shared/file > /mnt/shared/phaseB2; echo OP-B-DONE'

RUN_A="/tmp/uat-reg7-a.log"; RUN_B="/tmp/uat-reg7-b.log"
DOCKER_HELPER_SESSION_TOKEN="$stok" \
  dh run --image "$IMAGE" --mount shared:/mnt/shared -- sh -ec "$SA" >"$RUN_A" 2>&1 &
PID_A=$!
DOCKER_HELPER_SESSION_TOKEN="$stok" \
  dh run --image "$IMAGE" --mount shared:/mnt/shared -- sh -ec "$SB" >"$RUN_B" 2>&1 &
PID_B=$!

# Wait for both containers to report readiness and their first reads.
both_up=0
for _ in $(seq 1 90); do
  if [ -f "$shared/startedA" ] && [ -f "$shared/startedB" ] && [ -f "$shared/phaseA" ] && [ -f "$shared/phaseB" ]; then
    both_up=1; break
  fi
  if ! kill -0 "$PID_A" 2>/dev/null || ! kill -0 "$PID_B" 2>/dev/null; then
    break
  fi
  sleep 1
done
[ "$both_up" = 1 ] || {
  reg_fail "both concurrent operations did not become ready (A: $(cat "$RUN_A" 2>/dev/null | redact) | B: $(cat "$RUN_B" 2>/dev/null | redact))"
  kill "$PID_A" "$PID_B" 2>/dev/null || true
  reg_result
}

if [ "$(cat "$shared/phaseA")" = "CONTENT-C" ] && [ "$(cat "$shared/phaseB")" = "CONTENT-C" ]; then
  reg_ok "both concurrent operations access their pinned source (content C)"
else
  reg_fail "concurrent operations did not both read content C (A:$(cat "$shared/phaseA") B:$(cat "$shared/phaseB"))"
fi

# Count live pins while both are active (>= 2 pins is the observable).
PINS="$(find /run/docker-helper/mounts -mindepth 2 -maxdepth 2 -type d 2>/dev/null | grep -E '/[0-9]+$' || true)"
PINCOUNT="$(printf '%s\n' "$PINS" | sed '/^[[:space:]]*$/d' | wc -l)"
reg_info "live mount pins while both active: $PINCOUNT ($(printf '%s' "$PINS" | tr '\n' ' '))"

# --- end A; B must be unaffected -------------------------------------------------
touch "$shared/releaseA"
wait "$PID_A" 2>/dev/null; EC_A=$?
if [ "$EC_A" -eq 0 ] && grep -q 'OP-A-DONE' "$RUN_A"; then
  reg_ok "operation A completed normally"
else
  reg_fail "operation A did not complete normally (rc=$EC_A)"
fi
sleep 1
if kill -0 "$PID_B" 2>/dev/null; then
  reg_ok "operation B kept running after A ended"
else
  reg_fail "operation B was broken by ending operation A"
fi

# --- end B; B still accesses its pinned source (re-read after A ended) ---------
touch "$shared/releaseB"
wait "$PID_B" 2>/dev/null; EC_B=$?
if [ "$EC_B" -eq 0 ] && grep -q 'OP-B-DONE' "$RUN_B"; then
  reg_ok "operation B completed normally"
else
  reg_fail "operation B did not complete normally (rc=$EC_B)"
fi
if [ "$(cat "$shared/phaseB2" 2>/dev/null || true)" = "CONTENT-C" ]; then
  reg_ok "operation B still accessed its pinned source after A ended (phaseB2=CONTENT-C)"
else
  reg_fail "operation B could not access its pinned source after A ended"
fi

# --- no stale pin/mount runtime remains ------------------------------------------
REMAINING="$(find /run/docker-helper/mounts -mindepth 2 -maxdepth 2 -type d 2>/dev/null | grep -E '/[0-9]+$' || true)"
if [ -z "$REMAINING" ]; then
  reg_ok "no stale mount-pin runtime state remains after both operations exit"
else
  reg_fail "stale mount pins remain after both operations: $REMAINING"
fi

# best-effort cleanup
dh principal delete --system "$USER" >/dev/null 2>&1 || true
userdel -r "$USER" >/dev/null 2>&1 || true
rm -f "$cred" "$RUN_A" "$RUN_B"

reg_result
