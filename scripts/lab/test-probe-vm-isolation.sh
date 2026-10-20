#!/usr/bin/env bash
#
# test-probe-vm-isolation.sh — focused tests for the HOST role of
# scripts/lab/probe-vm-isolation.sh (the guest role is exercised only on the
# real lab VM; here it is simulated by a stub dev-vm-local.sh).
#
# What this protects (one invariant per test):
#   1. host self-check + idle guest -> PASS: the preparation connections are
#      drained into an explicit baseline and the counter DELTA is zero;
#   2. a guest that actually connects to a prepared IPv4 endpoint FAILS the
#      probe even when its own probe report claims success (the counter is
#      the evidence, not the guest's honesty);
#   3. same for the IPv6 listener/endpoint;
#   4. a guest probe that fails is reported as FAIL;
#   5. a listener that did not start FAILS the probe (never a PASS);
#   6. no host IPv6 -> the IPv6 check is a SKIP, not a silent PASS.
#
# The IPv6 cases require a working ::1 (any normal Linux host); they are
# skipped explicitly when the environment cannot bind/connect on IPv6.
#
# Usage: scripts/lab/test-probe-vm-isolation.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROBE_SRC="$SRC_DIR/lab/probe-vm-isolation.sh"
GUARD_SRC="$SRC_DIR/lab/lab-vm-guard.sh"
[ -f "$PROBE_SRC" ] || { echo "missing $PROBE_SRC" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
contains() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2')" ;; esac; }
not_contains() { case "$3" in *"$2"*) bad "$1 (unexpected '$2')" ;; *) ok "$1" ;; esac; }

# --- fake repo layout: the probe resolves its sibling guard lib and the
# --- stub dev-vm-local.sh exactly as it would in the real tree.
REPO="$WORK/repo/scripts"
mkdir -p "$REPO/lab"
cp "$PROBE_SRC" "$REPO/lab/probe-vm-isolation.sh"
cp "$GUARD_SRC" "$REPO/lab/lab-vm-guard.sh"

# Stub `ip`: controlled LAN addresses, IPv6 presence driven by FAKE_V6.
# The stubbed LAN addresses are the loopback endpoints (127.0.0.1 / ::1):
# they are real and connectable on any Linux host, so the mechanism under
# test — endpoint preparation, baseline fixation, counter delta — is
# deterministic without depending on the test host's actual interfaces.
SHIM="$WORK/shim"; mkdir -p "$SHIM"
cat > "$SHIM/ip" <<'SH'
#!/bin/sh
case "$1 $2 $3 $4" in
  "-4 route get 1.1.1.1") echo "1.1.1.1 via 10.0.0.1 dev eth0 src 127.0.0.1"; exit 0 ;;
  "-6 route get 2606:4700::1")
    if [ "${FAKE_V6:-1}" = 1 ]; then
      echo "2606:4700::1 via fe80::1 dev eth0 src ::1"; exit 0
    fi
    exit 1 ;;
esac
exit 1
SH
chmod +x "$SHIM/ip"

# Stub dev-vm-local.sh: simulates the guest over `ssh` per FAKE_GUEST.
cat > "$REPO/dev-vm-local.sh" <<'SH'
#!/usr/bin/env bash
case "${1:-}" in
  ssh)
    shift
    cmd="${1:-}"
    guest_args="${cmd##*-- }"
    set -- $guest_args
    [ "${1:-}" = guest ] || { echo "stub: unexpected guest args" >&2; exit 2; }
    gw_host="$2" gw_port="$3" lan4_host="$4" lan4_port="$5"
    lan6_host="${6:-}" lan6_port="${7:-}"
    case "${FAKE_GUEST:-idle}" in
      idle)
        # Boundary diagnostic owned by the stub: what the host role handed to
        # the guest. The guest role itself (link/route/endpoint/DNS checks and
        # its SKIP line) is exercised on the real VM only.
        if [ -n "$lan6_host" ]; then
          echo "STUB guest received the IPv6 endpoint $lan6_host:$lan6_port"
        else
          echo "STUB guest received no IPv6 endpoint"
        fi
        exit 0 ;;
      fail) echo "stub: guest probe failed inside the guest" >&2; exit 1 ;;
      attack)
        timeout 3 bash -c 'exec 3<>/dev/tcp/$1/$2' _ "$lan4_host" "$lan4_port" 2>/dev/null || exit 3
        exit 0 ;;
      attack6)
        [ -n "$lan6_host" ] || { echo "stub: no v6 endpoint" >&2; exit 4; }
        timeout 3 bash -c 'exec 3<>/dev/tcp/$1/$2' _ "$lan6_host" "$lan6_port" 2>/dev/null || exit 5
        exit 0 ;;
      *) echo "stub: unknown FAKE_GUEST" >&2; exit 2 ;;
    esac
    ;;
  *) echo "stub: only ssh is simulated" >&2; exit 2 ;;
esac
SH
chmod +x "$REPO/dev-vm-local.sh"

# IPv6 capability precheck (bounded): a throwaway listener on :: decides
# whether the IPv6 cases can run in this environment.
v6_capable=0
V6PROBE_PORT="$(( (RANDOM % 20000) + 30000 ))"
python3 - "$V6PROBE_PORT" <<'PY' & V6PID=$!
import socket, sys, time
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
s.bind(("::", int(sys.argv[1])))
s.listen(1)
time.sleep(8)
PY
for _ in $(seq 1 20); do
  if timeout 2 bash -c "exec 3<>/dev/tcp/::1/$V6PROBE_PORT" 2>/dev/null; then v6_capable=1; break; fi
  sleep 0.1
done
kill "$V6PID" 2>/dev/null; wait "$V6PID" 2>/dev/null

run_probe() { # <FAKE_GUEST> <FAKE_V6> <port> -> sets OUT and RC
  FAKE_GUEST="$1" FAKE_V6="$2" PATH="$SHIM:$PATH" \
    bash "$REPO/lab/probe-vm-isolation.sh" host "$3" >"$WORK/out" 2>&1
  RC=$?
  OUT="$(cat "$WORK/out")"
}

next_port() { echo "$(( (RANDOM % 20000) + 30000 ))"; }

# --- 1. idle guest -> PASS ---------------------------------------------------
P="$(next_port)"
run_probe idle 1 "$P"
if [ "$RC" = 0 ]; then ok "idle guest: probe passes"; else bad "idle guest: probe failed (rc $RC): $OUT"; fi
contains "idle guest: guest probe reported" "ok   - guest probe passed over host->guest SSH" "$OUT"
contains "idle guest: counter delta is zero" "ok   - no guest connection reached any controlled listener" "$OUT"
contains "idle guest: IPv6 endpoint prepared" "[::1]:$P" "$OUT"
contains "idle guest: the IPv6 endpoint is handed to the guest" "STUB guest received the IPv6 endpoint ::1:$P" "$OUT"
not_contains "idle guest: no skip with IPv6 present" "skip -" "$OUT"

# --- 2. guest connects to the prepared IPv4 endpoint -> FAIL -----------------
P="$(next_port)"
run_probe attack 1 "$P"
if [ "$RC" != 0 ]; then ok "attacking guest (v4): probe fails"; else bad "attacking guest (v4): probe passed"; fi
contains "attacking guest (v4): counter delta proves the connection" \
  "FAIL - a guest connection REACHED a controlled host listener" "$OUT"
contains "attacking guest (v4): the delta names IPv4" "ipv4" "$OUT"

# --- 3. guest connects to the prepared IPv6 endpoint -> FAIL -----------------
if [ "$v6_capable" = 1 ]; then
  P="$(next_port)"
  run_probe attack6 1 "$P"
  if [ "$RC" != 0 ]; then ok "attacking guest (v6): probe fails"; else bad "attacking guest (v6): probe passed"; fi
  contains "attacking guest (v6): counter delta proves the connection" \
    "FAIL - a guest connection REACHED a controlled host listener" "$OUT"
  contains "attacking guest (v6): the delta names IPv6" "ipv6" "$OUT"
else
  ok "attacking guest (v6): SKIPPED (no working ::1 in this environment)"
fi

# --- 4. failing guest probe -> FAIL ------------------------------------------
P="$(next_port)"
run_probe fail 1 "$P"
if [ "$RC" != 0 ]; then ok "failing guest probe: probe fails"; else bad "failing guest probe: probe passed"; fi
contains "failing guest probe: reported" "FAIL - guest probe failed" "$OUT"

# --- 5. listener did not start -> FAIL (a blocker holds the port) ------------
P="$(next_port)"
python3 - "$P" <<'PY' & BLOCKER_PID=$!
import socket, sys, time
s = socket.socket(socket.AF_INET)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen(1)
time.sleep(15)
PY
# The blocker must provably hold the port BEFORE the probe starts, otherwise
# the probe's own listener may win the bind race.
blocker_ready=0
for _ in $(seq 1 20); do
  if timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$P" 2>/dev/null; then blocker_ready=1; break; fi
  sleep 0.1
done
[ "$blocker_ready" = 1 ] || { echo "blocker listener did not start" >&2; exit 1; }
run_probe idle 1 "$P"
kill "$BLOCKER_PID" 2>/dev/null; wait "$BLOCKER_PID" 2>/dev/null
if [ "$RC" != 0 ]; then ok "blocked port: probe fails"; else bad "blocked port: probe passed"; fi
contains "blocked port: names the failure" "ERROR" "$OUT"

# --- 6. no host IPv6 -> SKIP, not a false PASS -------------------------------
P="$(next_port)"
run_probe idle 0 "$P"
if [ "$RC" = 0 ]; then ok "no-IPv6 host: probe passes with the v6 part skipped"; else bad "no-IPv6 host: probe failed (rc $RC): $OUT"; fi
contains "no-IPv6 host: the guest receives no IPv6 endpoint" "STUB guest received no IPv6 endpoint" "$OUT"
not_contains "no-IPv6 host: no v6 endpoint claimed" "[::1]:" "$OUT"

echo
printf 'probe-vm-isolation tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
