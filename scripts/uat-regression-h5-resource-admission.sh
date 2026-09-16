#!/usr/bin/env bash
#
# uat-regression-h5-resource-admission.sh — Release-2 targeted regression
# group 25: H5 fixed resource admission ceilings (Ubuntu / DEB / AppArmor).
#
# Pre-fix, three Session-token-controlled host-resource channels were
# unbounded: one log request materialized the whole retained log and expanded
# it up to the measured 6x JSON-encoding amplification; one run request could
# create hundreds of open_tree/move_mount pins (the 16 KiB request-body limit
# was the only incidental count bound); and admit() imposed no running-
# operation ceiling, while run pinned its mounts and build staged its whole
# context BEFORE admission was even consulted.
#
# Post-fix contract proven here against the real packaged system service
# (mandatory MAC active), with the REAL production ceilings (4 concurrent
# Operations per Session, 8 globally, 2 concurrent builds, 16 caller mounts,
# 256 KiB raw log response chunk):
#   * Session/global concurrency: 4 long-lived operations occupy the Session
#     ceiling; the next request is refused immediately with the single
#     bounded capacity refusal (HTTP 429 / operation_capacity_unavailable);
#     a second Session still uses free global capacity; the refusal creates
#     no Docker container/process/state; terminating one operation makes the
#     capacity reusable immediately;
#   * refusal-before-expensive-work: the capacity-refused run request carries
#     a valid mount yet adds no mount pin and no workload-MAC state; the
#     capacity-refused build adds no staging tree;
#   * mount ceiling: a run with exactly 16 caller mounts is accepted; 17 are
#     refused before any pin (mountinfo and the canonical pin inventory are
#     unchanged) and the service stays healthy;
#   * bounded log response: a workload emitting ~700 KB of JSON-hostile
#     control bytes is served in bounded chunks (every encoded HTTP response
#     stays under the documented ~1.6 MiB bound); walking next_offset
#     reconstructs the retained stream exactly (sentinels + exact hostile
#     byte count prove no gap and no duplication); the ordinary CLI fully
#     delivers terminal output spanning several chunks;
#   * recovery: after terminating the hostile long-lived operations, no pins,
#     no staging residue, no workload-MAC state and no residual capacity
#     remain, and a subsequent ordinary run and build both succeed.
#
# Requires: installed docker-helper system service (active), Docker reachable,
# root, curl, journalctl, python3. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED
# (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "25. H5 fixed resource admission ceilings"

reg_require_root
reg_require_service
reg_require_docker
reg_require_cmd curl "Unix /health probes and direct logs-endpoint evidence"
reg_require_cmd journalctl "capacity-refusal audit evidence"
reg_require_cmd python3 "request-body generation and chunk reconstruction checks"

# The REAL production ceilings (fixed Release-2.2 security constants;
# documented in docs/architecture.md). The regression uses the real counters,
# never reduced or per-MAC duplicated.
SESSION_CEILING=4        # concurrent Operations per Session
GLOBAL_CEILING=8         # concurrent Operations globally (2 build slots incl.)
MOUNT_CEILING=16         # caller mounts per run request
LOG_CHUNK_BYTES=262144   # raw log bytes per HTTP logs response
LOG_RESPONSE_BOUND=1700000 # documented worst-case encoded response bound

SOCK="/run/docker-helper/docker-helper.sock"
RUNTIME_DIR="/run/docker-helper"

cont_count() { # operation-labeled containers
  docker ps -q --filter "label=com.dockerhelper.operation.id" 2>/dev/null | wc -l | tr -d ' '
}
pin_count() { # canonical pin inventory (live pinned mount destinations)
  find "$RUNTIME_DIR/mounts" -mindepth 2 -maxdepth 2 -type d 2>/dev/null | grep -E '/[0-9]+$' | wc -l | tr -d ' '
}
mac_state_inventory() { # transient + durable workload-MAC roots
  printf '%s\n' "$(( $(inventory_count "$RUNTIME_DIR/workload-mac") + $(inventory_count /var/lib/docker-helper/workload-mac) ))"
}
mountinfo_count() { # kernel mount-table lines visible to init namespace
  wc -l < /proc/self/mountinfo 2>/dev/null | tr -d ' '
}
require_number() { # VALUE
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}
service_healthy() { # LABEL
  if systemctl is-active --quiet docker-helper.service 2>/dev/null; then
    reg_ok "$1: service remains active"
  else
    reg_fail "$1: service is not active"
  fi
  if curl --silent --fail --max-time 2 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1; then
    reg_ok "$1: Unix API remains healthy"
  else
    reg_fail "$1: GET /health over the Unix API failed"
  fi
}

# --- two Principals and two Sessions ------------------------------------------
USER_A="uatreg25a"
USER_B="uatreg25b"
home_a="$(reg_setup_principal "$USER_A")" || { reg_fail "setup principal A failed"; reg_result; }
home_b="$(reg_setup_principal "$USER_B")" || { reg_fail "setup principal B failed"; reg_result; }
WS_A="$home_a/ws"; WS_B="$home_b/ws"
mkdir -p "$WS_A" "$WS_B"
# Mount sources used by the held operations must exist inside each workspace.
for i in 1 2 3 4; do
  mkdir -p "$WS_A/shareda$i" "$WS_B/sharedb$i"
  printf 'content\n' > "$WS_A/shareda$i/file" 2>/dev/null
  printf 'content\n' > "$WS_B/sharedb$i/file" 2>/dev/null
done
chown -R "$USER_A:$USER_A" "$WS_A"
chown -R "$USER_B:$USER_B" "$WS_B"

cred_a="/tmp/uat-h5a.token"; cred_b="/tmp/uat-h5b.token"
reg_principal_credential "$USER_A" "$cred_a" || { reg_fail "credential A create failed"; reg_result; }
reg_session "$cred_a" "$WS_A" || { reg_fail "session A create failed"; reg_result; }
TOKEN_A="$REG_SESSION_TOKEN"
export DOCKER_HELPER_SESSION_TOKEN="$TOKEN_A"
reg_principal_credential "$USER_B" "$cred_b" || { reg_fail "credential B create failed"; reg_result; }
reg_session "$cred_b" "$WS_B" || { reg_fail "session B create failed"; reg_result; }
TOKEN_B="$REG_SESSION_TOKEN"

IMAGE="alpine:3.24"
HOLD='sh -ec "sleep 300"'

# --- baselines ----------------------------------------------------------------
PINS_BEFORE="$(pin_count)"
MAC_BEFORE="$(mac_state_inventory)"
BUILDS_BEFORE="$(inventory_count "$RUNTIME_DIR/builds")"
CONTAINERS_BEFORE="$(cont_count)"
MOUNTINFO_BEFORE="$(mountinfo_count)"
for v in "$PINS_BEFORE" "$MAC_BEFORE" "$BUILDS_BEFORE" "$CONTAINERS_BEFORE" "$MOUNTINFO_BEFORE"; do
  require_number "$v" || { reg_fail "baseline inventory not numeric: $v"; reg_result; }
done
reg_ok "baselines: pins=$PINS_BEFORE mac=$MAC_BEFORE builds=$BUILDS_BEFORE containers=$CONTAINERS_BEFORE mountinfo=$MOUNTINFO_BEFORE"

# --- A: Session ceiling — 4 long-lived operations, 5th refused immediately -----
PIDS_A=()
for i in 1 2 3 4; do
  DOCKER_HELPER_SESSION_TOKEN="$TOKEN_A" \
    dh run --image "$IMAGE" --mount "shareda$i:/mnt/shared$i" -- sh -ec "sleep 300" \
    >"/tmp/h5-run-a$i.log" 2>&1 &
  PIDS_A+=("$!")
done
# Wait until all four operation containers are observable.
up=0
for _ in $(seq 1 60); do
  c="$(cont_count)"
  if require_number "$c" && [ "$c" -ge 4 ]; then up=1; break; fi
  sleep 1
done
if [ "$up" = 1 ]; then
  reg_ok "four long-lived operations occupy the Session ceiling (containers: $(cont_count))"
else
  reg_fail "the four long-lived operations did not all start (containers: $(cont_count))"
  reg_result
fi

# One valid mount on the refused request proves the refusal happens before
# any pin or workload-MAC preparation.
CAPACITY_MARK="$(date '+%Y-%m-%d %H:%M:%S')"
DOCKER_HELPER_SESSION_TOKEN="$TOKEN_A" \
  dh run --image "$IMAGE" --mount "shareda1:/mnt/refused" -- sh -ec "true" \
  >/tmp/h5-run-refused.out 2>/tmp/h5-run-refused.err
RC=$?
if [ "$RC" -ne 0 ] && grep -q 'status 429' /tmp/h5-run-refused.err && grep -q 'code operation_capacity_unavailable' /tmp/h5-run-refused.err; then
  reg_ok "5th request refused immediately with the single bounded capacity refusal (429 / operation_capacity_unavailable)"
else
  reg_fail "5th request: expected immediate 429 / operation_capacity_unavailable refusal (rc=$RC, stderr: $(head -2 /tmp/h5-run-refused.err | redact))"
fi
if grep -q 'too many concurrent operations' /tmp/h5-run-refused.err; then
  reg_ok "capacity refusal message names no capacity topology (session/global hidden)"
else
  reg_fail "capacity refusal message missing: $(head -2 /tmp/h5-run-refused.err | redact)"
fi

# No extra Docker container/process/state exists for the refusal.
CONTAINERS_AFTER_REFUSAL="$(cont_count)"
if [ "$CONTAINERS_AFTER_REFUSAL" = "$CONTAINERS_BEFORE" ]; then
  reg_ok "refusal created no Docker container/process/state (containers unchanged: $CONTAINERS_AFTER_REFUSAL)"
else
  reg_fail "refusal changed the container inventory ($CONTAINERS_BEFORE -> $CONTAINERS_AFTER_REFUSAL)"
fi

# Refusal-before-expensive-work for the run: the valid mount was never probed,
# never pinned, never MAC-prepared.
if [ "$(pin_count)" = "$PINS_BEFORE" ]; then
  reg_ok "capacity-refused run: mount-pin inventory unchanged ($PINS_BEFORE)"
else
  reg_fail "capacity-refused run: pin inventory changed ($(pin_count) != $PINS_BEFORE)"
fi
if [ "$(mac_state_inventory)" = "$MAC_BEFORE" ]; then
  reg_ok "capacity-refused run: workload-MAC inventory unchanged"
else
  reg_fail "capacity-refused run: workload-MAC inventory changed"
fi

# Refusal-before-expensive-work for the build: no staging tree.
DOCKER_HELPER_SESSION_TOKEN="$TOKEN_A" \
  dh build --context . --dockerfile Dockerfile --image uat-h5-refused:2.2 \
  >/tmp/h5-build-refused.out 2>/tmp/h5-build-refused.err
RC=$?
if [ "$RC" -ne 0 ] && grep -q 'status 429' /tmp/h5-build-refused.err && grep -q 'code operation_capacity_unavailable' /tmp/h5-build-refused.err; then
  reg_ok "build at the Session ceiling refused with the same bounded capacity refusal"
else
  reg_fail "build at the Session ceiling: expected 429 / operation_capacity_unavailable (rc=$RC, stderr: $(head -2 /tmp/h5-build-refused.err | redact))"
fi
if [ "$(inventory_count "$RUNTIME_DIR/builds")" = "$BUILDS_BEFORE" ]; then
  reg_ok "capacity-refused build: no staging tree under $RUNTIME_DIR/builds"
else
  reg_fail "capacity-refused build: staging residue appeared ($(inventory_count "$RUNTIME_DIR/builds") != $BUILDS_BEFORE)"
fi
printf 'FROM scratch\n' > "$WS_A/Dockerfile"
journal="$(journalctl -u docker-helper.service --since "$CAPACITY_MARK" --no-pager 2>/dev/null || true)"
if printf '%s\n' "$journal" | grep -q '"result":"operation_capacity_unavailable"'; then
  reg_ok "run/build rejections audited with the capacity refusal code"
else
  reg_fail "no run/build.rejected audit record carries operation_capacity_unavailable in the journal window"
fi

# --- A: second Session uses free global capacity (distinguishes scopes) -------
PIDS_B=()
for i in 1 2 3 4; do
  DOCKER_HELPER_SESSION_TOKEN="$TOKEN_B" \
    dh run --image "$IMAGE" --mount "sharedb$i:/mnt/shared$i" -- sh -ec "sleep 300" \
    >"/tmp/h5-run-b$i.log" 2>&1 &
  PIDS_B+=("$!")
done
up=0
for _ in $(seq 1 60); do
  c="$(cont_count)"
  if require_number "$c" && [ "$c" -ge 8 ]; then up=1; break; fi
  sleep 1
done
if [ "$up" = 1 ]; then
  reg_ok "second Session admits its 4 operations while Session A is saturated (global ceiling reached: $(cont_count))"
else
  reg_fail "second Session could not use free global capacity (containers: $(cont_count))"
  reg_result
fi

DOCKER_HELPER_SESSION_TOKEN="$TOKEN_B" \
  dh run --image "$IMAGE" -- sh -ec "true" >/tmp/h5-run-b5.out 2>/tmp/h5-run-b5.err
if grep -q 'status 429' /tmp/h5-run-b5.err && grep -q 'code operation_capacity_unavailable' /tmp/h5-run-b5.err; then
  reg_ok "9th operation refused at the ceilings (no queue, no wait)"
else
  reg_fail "9th operation: expected immediate 429 refusal (stderr: $(head -2 /tmp/h5-run-b5.err | redact))"
fi

# --- A: terminal release — capacity reusable immediately ----------------------
kill -TERM "${PIDS_A[0]}" 2>/dev/null || true
wait "${PIDS_A[0]}" 2>/dev/null || true
free=0
for _ in $(seq 1 30); do
  c="$(cont_count)"
  if require_number "$c" && [ "$c" -eq 7 ]; then free=1; break; fi
  sleep 1
done
if [ "$free" = 1 ]; then
  reg_ok "terminated operation released its container and capacity immediately"
else
  reg_fail "terminated operation did not release its container (containers: $(cont_count))"
  reg_result
fi
DOCKER_HELPER_SESSION_TOKEN="$TOKEN_A" \
  dh run --image "$IMAGE" -- sh -ec "true" >/tmp/h5-run-reuse.out 2>/tmp/h5-run-reuse.err
if [ "$?" -eq 0 ]; then
  reg_ok "freed capacity is reusable immediately (terminal release, not retention release)"
else
  reg_fail "a new operation was not admitted after the terminal release: $(head -2 /tmp/h5-run-reuse.err | redact)"
fi

# --- C: caller-mount ceiling ---------------------------------------------------
for i in $(seq 0 $((MOUNT_CEILING - 1))); do
  mkdir -p "$WS_A/mdir$i"
  printf 'content\n' > "$WS_A/mdir$i/file"
done
chown -R "$USER_A:$USER_A" "$WS_A"
mount_args=()
for i in $(seq 0 $((MOUNT_CEILING - 1))); do
  mount_args+=(--mount "mdir$i:/m$i")
done

DOCKER_HELPER_SESSION_TOKEN="$TOKEN_A" \
  dh run --image "$IMAGE" "${mount_args[@]}" -- sh -ec "true" \
  >/tmp/h5-mounts-ok.out 2>/tmp/h5-mounts-ok.err
if [ "$?" -eq 0 ]; then
  reg_ok "exactly-at-mount-limit run accepted ($MOUNT_CEILING caller mounts)"
else
  reg_fail "exactly-at-mount-limit run failed: $(head -2 /tmp/h5-mounts-ok.err | redact)"
fi

PINS_MOUNT_BEFORE="$(pin_count)"
MOUNTINFO_MOUNT_BEFORE="$(mountinfo_count)"
over_args=("${mount_args[@]}" --mount "mdir0:/m$MOUNT_CEILING")
DOCKER_HELPER_SESSION_TOKEN="$TOKEN_A" \
  dh run --image "$IMAGE" "${over_args[@]}" -- sh -ec "true" \
  >/tmp/h5-mounts-over.out 2>/tmp/h5-mounts-over.err
RC=$?
if [ "$RC" -ne 0 ] && grep -q 'status 400' /tmp/h5-mounts-over.err && grep -q 'code too_many_mounts' /tmp/h5-mounts-over.err; then
  reg_ok "limit+1 mounts refused before probing/pinning (400 / too_many_mounts)"
else
  reg_fail "limit+1 mounts: expected 400 / too_many_mounts (rc=$RC, stderr: $(head -2 /tmp/h5-mounts-over.err | redact))"
fi
PINS_MOUNT_AFTER="$(pin_count)"
MOUNTINFO_MOUNT_AFTER="$(mountinfo_count)"
if [ "$PINS_MOUNT_AFTER" = "$PINS_MOUNT_BEFORE" ]; then
  reg_ok "over-limit mounts: pin inventory unchanged ($PINS_MOUNT_AFTER)"
else
  reg_fail "over-limit mounts: pin inventory changed ($PINS_MOUNT_BEFORE -> $PINS_MOUNT_AFTER)"
fi
if require_number "$MOUNTINFO_MOUNT_AFTER" && [ "$MOUNTINFO_MOUNT_AFTER" = "$MOUNTINFO_MOUNT_BEFORE" ]; then
  reg_ok "over-limit mounts: /proc/self/mountinfo unchanged ($MOUNTINFO_MOUNT_AFTER lines)"
else
  reg_fail "over-limit mounts: /proc/self/mountinfo changed ($MOUNTINFO_MOUNT_BEFORE -> $MOUNTINFO_MOUNT_AFTER)"
fi
service_healthy "mount ceiling refusal"

# --- D: bounded log response chunks (hostile control bytes) --------------------
python3 - > /tmp/h5-hostile-body.json <<'PY'
import json
cmd = 'printf START; head -c 700000 /dev/zero | tr \'\\0\' \'\\001\'; printf END'
print(json.dumps({
    "image": "alpine:3.24",
    "command": ["sh", "-ec", cmd],
}))
PY
HOSTILE_MARK="$(date '+%Y-%m-%d %H:%M:%S')"
HOSTILE_RESP="$(curl --silent --show-error --max-time 60 --unix-socket "$SOCK" \
  -H "Authorization: Bearer $TOKEN_A" -H "Content-Type: application/json" \
  --data-binary @/tmp/h5-hostile-body.json http://localhost/run 2>/tmp/h5-hostile-curl.err)"
HOSTILE_OP="$(printf '%s' "$HOSTILE_RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("operation_id",""))' 2>/dev/null)"
[ -n "$HOSTILE_OP" ] || { reg_fail "hostile run creation failed: $(head -2 /tmp/h5-hostile-curl.err | redact)"; reg_result; }

# Wait for the hostile operation to reach a terminal state.
hostile_done=0
for _ in $(seq 1 60); do
  st="$(curl --silent --max-time 5 --unix-socket "$SOCK" \
    -H "Authorization: Bearer $TOKEN_A" http://localhost/operations/$HOSTILE_OP 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' 2>/dev/null)"
  if [ "$st" = "succeeded" ] || [ "$st" = "failed" ]; then hostile_done=1; break; fi
  sleep 1
done
if [ "$hostile_done" = 1 ]; then
  reg_ok "hostile-byte operation reached a terminal state"
else
  reg_fail "hostile-byte operation did not reach a terminal state"
  reg_result
fi

python3 - "$HOSTILE_OP" "$TOKEN_A" "$LOG_CHUNK_BYTES" "$LOG_RESPONSE_BOUND" <<'PY' || { reg_fail "chunk walk evidence failed"; reg_result; }
import json, subprocess, sys

op, token, chunk_bytes, bound = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
sock = "/run/docker-helper/docker-helper.sock"

def fetch(offset):
    out = subprocess.run(
        ["curl", "--silent", "--show-error", "--max-time", "10", "--unix-socket", sock,
         "-H", "Authorization: Bearer " + token, "-o", "/dev/stdout",
         "-w", "\n%{size_download}",
         f"http://localhost/operations/{op}/logs?offset={offset}"],
        capture_output=True, text=True, timeout=20)
    body, _, size = out.stdout.rpartition("\n")
    return json.loads(body), int(size)

offset, reassembled, chunks, saw_truncated = 0, b"", 0, False
while True:
    resp, size = fetch(offset)
    if size > bound:
        sys.exit(f"encoded response {size} exceeds the documented bound {bound}")
    data = resp["logs"].encode()
    reassembled += data
    chunks += 1
    saw_truncated = saw_truncated or resp["truncated"]
    if len(resp["logs"]) < chunk_bytes:
        if resp["next_offset"] != offset + len(data):
            sys.exit(f"next_offset {resp['next_offset']} does not follow returned bytes at offset {offset}")
        break
    if resp["next_offset"] <= offset:
        sys.exit(f"next_offset did not advance at offset {offset}")
    offset = resp["next_offset"]
    if chunks > 16:
        sys.exit("chunk walk did not terminate")

if chunks < 2:
    sys.exit(f"expected multiple response chunks, got {chunks}")
if len(reassembled) != 5 + 700000 + 3:
    sys.exit(f"reconstructed stream length {len(reassembled)} != 700008")
if reassembled[:5] != b"START" or reassembled[-3:] != b"END":
    sys.exit("reconstructed stream does not carry the boundary sentinels")
middle = reassembled[5:-3]
if any(b != 0x01 for b in middle):
    sys.exit("reconstructed middle is not exactly the emitted control bytes (gap or duplication)")
print(f"OK chunks={chunks} bytes={len(reassembled)} truncated={saw_truncated}")
PY
if [ "$?" = 0 ]; then
  reg_ok "every encoded logs response stayed under the documented bound and the chunk walk reconstructed the stream exactly (no gap, no duplication)"
else
  reg_fail "chunk walk assertions failed (see evidence above)"
fi

# The ordinary CLI fully delivers terminal output spanning several chunks.
DOCKER_HELPER_SESSION_TOKEN="$TOKEN_A" \
  dh run --image "$IMAGE" -- sh -ec 'printf CLI-HEAD; head -c 700000 /dev/zero | tr "\0" "-"; printf CLI-TAIL' \
  >/tmp/h5-cli-drain.out 2>/tmp/h5-cli-drain.err
RC=$?
if [ "$RC" -eq 0 ]; then
  head_ok=$(grep -c 'CLI-HEAD' /tmp/h5-cli-drain.out || true)
  tail_ok=$(grep -c 'CLI-TAIL' /tmp/h5-cli-drain.out || true)
  middle="$(sed 's/.*CLI-HEAD//; s/CLI-TAIL.*//' /tmp/h5-cli-drain.out | tr -cd '-' | wc -c | tr -d ' ')"
  if [ "$head_ok" -ge 1 ] && [ "$tail_ok" -ge 1 ] && [ "$middle" = "700000" ]; then
    reg_ok "CLI terminal output spanning multiple chunks is fully delivered (sentinels + 700000 bytes between them)"
  else
    reg_fail "CLI drain incomplete (head=$head_ok tail=$tail_ok middle=$middle)"
  fi
else
  reg_fail "CLI drain run failed (rc=$RC): $(head -2 /tmp/h5-cli-drain.err | redact)"
fi

# --- E: recovery — no residue and ordinary operations work again ---------------
for pid in "${PIDS_A[@]:1}" "${PIDS_B[@]}"; do
  kill -TERM "$pid" 2>/dev/null || true
done
for pid in "${PIDS_A[@]:1}" "${PIDS_B[@]}"; do
  wait "$pid" 2>/dev/null || true
done
recovered=0
for _ in $(seq 1 30); do
  c="$(cont_count)"
  if require_number "$c" && [ "$c" -eq 0 ]; then recovered=1; break; fi
  sleep 1
done
if [ "$recovered" = 1 ]; then
  reg_ok "all hostile long-lived operations terminated; no correlated container remains"
else
  reg_fail "containers remain after recovery (count: $(cont_count))"
fi

PINS_AFTER="$(pin_count)"
MAC_AFTER="$(mac_state_inventory)"
BUILDS_AFTER="$(inventory_count "$RUNTIME_DIR/builds")"
if [ "$PINS_AFTER" = "$PINS_BEFORE" ]; then
  reg_ok "recovery: no mount-pin residue"
else
  reg_fail "recovery: pin residue remains ($PINS_AFTER != $PINS_BEFORE)"
fi
if [ "$MAC_AFTER" = "$MAC_BEFORE" ]; then
  reg_ok "recovery: no workload-MAC state remains"
else
  reg_fail "recovery: workload-MAC state remains ($MAC_AFTER != $MAC_BEFORE)"
fi
if [ "$BUILDS_AFTER" = "$BUILDS_BEFORE" ]; then
  reg_ok "recovery: no staging residue"
else
  reg_fail "recovery: staging residue remains ($BUILDS_AFTER != $BUILDS_BEFORE)"
fi

printf 'h5-payload\n' > "$WS_A/payload.txt"
printf 'FROM scratch\nCOPY payload.txt /payload.txt\n' > "$WS_A/Dockerfile"
chown -R "$USER_A:$USER_A" "$WS_A"
DOCKER_HELPER_SESSION_TOKEN="$TOKEN_A" \
  dh run --image "$IMAGE" -- sh -ec "true" >/tmp/h5-final-run.out 2>/tmp/h5-final-run.err
if [ "$?" -eq 0 ]; then
  reg_ok "recovery: a subsequent ordinary run succeeds"
else
  reg_fail "recovery: the ordinary run failed: $(head -2 /tmp/h5-final-run.err | redact)"
fi
DOCKER_HELPER_SESSION_TOKEN="$TOKEN_A" \
  dh build --context . --dockerfile Dockerfile --image uat-h5-final:2.2 \
  >/tmp/h5-final-build.out 2>/tmp/h5-final-build.err
if [ "$?" -eq 0 ]; then
  reg_ok "recovery: a subsequent ordinary build succeeds"
else
  reg_fail "recovery: the ordinary build failed: $(head -2 /tmp/h5-final-build.err | redact)"
fi
service_healthy "recovery"

# --- cleanup -------------------------------------------------------------------
dh principal delete --system "$USER_A" >/dev/null 2>&1 || true
dh principal delete --system "$USER_B" >/dev/null 2>&1 || true
userdel -r "$USER_A" >/dev/null 2>&1 || true
userdel -r "$USER_B" >/dev/null 2>&1 || true
rm -f "$cred_a" "$cred_b" /tmp/h5-*.log /tmp/h5-*.err /tmp/h5-*.out /tmp/h5-hostile-body.json

reg_result
