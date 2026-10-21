#!/usr/bin/env bash
#
# probe-vm-isolation.sh — prove the lab VM's isolated network posture against
# PREPARED host-side endpoints, and that the local stack still works offline.
#
# Two roles in one file (one owner for the isolation-verification contract):
#
#   probe-vm-isolation.sh host [PORT]     run on the PHYSICAL HOST:
#       1. detect the host's LAN IPv4 (and IPv6, when available);
#       2. start CONTROLLED TCP listeners (IPv4 0.0.0.0:PORT, IPv6 :::PORT)
#          that COUNT accepted connections in counter files. The harness
#          never touches the host firewall: only userspace listeners run.
#       3. PREPARE phase: prove each listener accepts from the physical host
#          (loopback AND the LAN endpoint it will be probed on, IPv6
#          included) — endpoints are proven available BEFORE the guest
#          probes them. A listener that did not start FAILS the probe.
#       4. DRAIN phase: wait (bounded, counter-driven) until every
#          preparation connection has been accounted, then fixate the
#          BASELINE counter values. No log clearing, no races: only the
#          DELTA after the baseline matters.
#       5. stream the guard library plus this script into the guest over the
#          host->guest SSH path (that transport is itself the SSH evidence)
#          and run the guest probe there.
#       6. VERIFY phase: listeners must still be alive and the counter delta
#          must be zero — no guest connection ever reached a real, accepting
#          endpoint. A dead listener makes the verdict INCOMPLETE and fails.
#
#   probe-vm-isolation.sh guest GW_HOST GW_PORT LAN4_HOST LAN4_PORT \
#                                 [LAN6_HOST LAN6_PORT]
#       run as root INSIDE the guest (or streamed in by `host`). Asserts:
#       the lab-VM guard passes; the NIC has an address; there is no IPv4 or
#       IPv6 default route; every prepared endpoint (slirp gateway, LAN IPv4,
#       LAN IPv6) is unreachable; internet egress fails over IPv4 and IPv6;
#       DNS resolution fails; SELinux is enforcing; docker-helper works
#       offline (session create -> bearer self -> delete, no orphan).
#
# Unavailability of a NON-EXISTENT service is not proof of isolation: every
# negative guest probe targets an endpoint the host verified as accepting.
#
# The slirp restrict=on posture leaves the guest without gateway/DNS/outbound
# routing, so prepared endpoints must be unreachable AND DNS must fail.
set -u

SELF="${BASH_SOURCE[0]:-$0}"
SCRIPT_DIR=""
if [ -n "$SELF" ] && [ -f "$SELF" ]; then
  SCRIPT_DIR="$(cd "$(dirname "$SELF")" && pwd)"
fi

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
skip() { SKIP=$((SKIP+1)); printf 'skip - %s\n' "$1"; }
summary() {
  echo
  printf 'isolation probe: %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
  [ "$FAIL" = 0 ]
}

# tcp_reachable HOST PORT — succeeds only when a TCP connection is established.
# Pure connect probe (no protocol assumptions), bounded by timeout.
tcp_reachable() {
  timeout 3 bash -c 'exec 3<>/dev/tcp/$1/$2' _ "$1" "$2" 2>/dev/null
}

expect_unreachable() { # LABEL HOST PORT
  if tcp_reachable "$2" "$3"; then
    bad "$1: TCP connect to $2:$3 SUCCEEDED (not isolated)"
  else
    ok "$1: $2:$3 unreachable"
  fi
}

# --- IPv4-only posture helpers (UAT-4/F3) -------------------------------------
# probe_ipv6_disabled [CMDLINE_FILE] [IF_INET6_FILE] — returns 0 when IPv6 is
# disabled at the GUEST OS LEVEL: the kernel command line carries
# ipv6.disable=1 and the IPv6 procfs interface (/proc/net/if_inet6) is absent.
# Merely unrouted IPv6 is NOT a disabled stack, so both conditions are
# required. The file arguments are the production defaults; the tests pass
# private temp files and execute the same code.
probe_ipv6_disabled() { # [CMDLINE_FILE] [IF_INET6_FILE]
  local cmdline="${1:-/proc/cmdline}" ifinet6="${2:-/proc/net/if_inet6}"
  grep -qw 'ipv6.disable=1' "$cmdline" 2>/dev/null || return 1
  [ ! -e "$ifinet6" ] || return 1
  return 0
}

# ipv6_transport_usable — returns 0 when an AF_INET6 socket can be created and
# bound, i.e. IPv6 transport is actually functioning. A functioning transport
# contradicts an IPv4-only posture regardless of route visibility.
ipv6_transport_usable() {
  command -v python3 >/dev/null 2>&1 || return 2
  python3 - <<'PY' 2>/dev/null
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.bind(("::1", 0))
s.close()
PY
}

# --- guest role --------------------------------------------------------------
probe_guest() { # GW_HOST GW_PORT LAN4_HOST LAN4_PORT [LAN6_HOST LAN6_PORT]
  [ "$#" -ge 4 ] || { echo "usage: $0 guest GW_HOST GW_PORT LAN4_HOST LAN4_PORT [LAN6_HOST LAN6_PORT]" >&2; return 2; }
  local gw_host="$1" gw_port="$2" lan4_host="$3" lan4_port="$4"
  local lan6_host="${5:-}" lan6_port="${6:-}"

  # Lab-VM guard: shared library when streamed in by the host role, sourced
  # from the copied lab directory when run standalone in the guest.
  if ! declare -F require_lab_vm >/dev/null 2>&1; then
    [ -n "$SCRIPT_DIR" ] || { echo "cannot locate lab-vm-guard.sh" >&2; return 2; }
    # shellcheck source=lab-vm-guard.sh
    . "$SCRIPT_DIR/lab-vm-guard.sh"
  fi
  require_lab_vm

  [ "$(id -u)" = 0 ] || { echo "guest probe must run as root" >&2; return 1; }

  # 1. link up
  if ip -4 -o addr show scope global 2>/dev/null | grep -q 'inet '; then
    ok "guest NIC has an address (link alive)"
  else
    bad "guest NIC has no address"
  fi

  # 2. no default route (IPv4 and IPv6)
  if ip -4 route 2>/dev/null | grep -q '^default'; then
    bad "an IPv4 default route is present (not isolated)"
  else
    ok "no IPv4 default route"
  fi
  if ip -6 route 2>/dev/null | grep -q '^default'; then
    bad "an IPv6 default route is present (not isolated)"
  else
    ok "no IPv6 default route"
  fi

  # 2b. UAT-4/F3: the lab VM is IPv4-only — IPv6 must be DISABLED at the
  # guest OS level (ipv6.disable=1 on the kernel command line and no IPv6
  # procfs interface). An unrouted-but-alive stack is not a disabled stack.
  # These checks are critical and never SKIP.
  if probe_ipv6_disabled; then
    ok "IPv6 is disabled at the guest OS level (ipv6.disable=1, no /proc/net/if_inet6)"
  else
    bad "IPv6 is NOT disabled at the guest OS level (cmdline ipv6.disable=1 and /proc/net/if_inet6 required)"
  fi
  if ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'; then
    bad "active IPv6 addresses are present (not an IPv4-only VM)"
  else
    ok "no active IPv6 addresses"
  fi
  case "$(ipv6_transport_usable && echo usable || echo unusable)" in
    unusable) ok "IPv6 transport is not usable (an AF_INET6 socket cannot be created and bound)" ;;
    usable)   bad "IPv6 transport is FUNCTIONING (a working AF_INET6 socket contradicts an IPv4-only VM)" ;;
    *)        bad "cannot verify the IPv6 transport (python3 unavailable)" ;;
  esac

  # 3. prepared endpoints unreachable (each was verified accepting host-side)
  expect_unreachable "slirp gateway" "$gw_host" "$gw_port"
  expect_unreachable "host LAN IPv4" "$lan4_host" "$lan4_port"
  if [ -n "$lan6_host" ]; then
    expect_unreachable "host LAN IPv6" "$lan6_host" "$lan6_port"
  else
    skip "host LAN IPv6 probe (host has no global IPv6)"
  fi

  # 4. no internet egress (IPv4 and IPv6)
  expect_unreachable "internet IPv4" 1.1.1.1 80
  expect_unreachable "internet IPv6" 2606:4700:4700::1111 80

  # 5. DNS fails
  if timeout 10 getent hosts github.com >/dev/null 2>&1; then
    bad "DNS resolution works (github.com)"
  else
    ok "DNS resolution fails"
  fi

  # 6. SELinux
  if [ "$(getenforce)" = "Enforcing" ]; then ok "SELinux enforcing"; else bad "SELinux not enforcing"; fi

  # 7. daemon + offline session round-trip
  local dh=/usr/bin/docker-helper agent_user="${AGENT_USER:-agent}"
  if systemctl is-active --quiet docker-helper; then ok "docker-helper daemon active"; else bad "docker-helper daemon not active"; fi
  local ws="/home/$agent_user/work/probe"
  install -d -m 0755 -o "$agent_user" -g "$agent_user" "$ws"
  local resp sid tok
  resp="$(sudo -u "$agent_user" "$dh" session create "$ws" --json 2>/dev/null)" || resp=""
  sid="$(printf '%s' "$resp" | jq -r '.session.id // empty')"
  tok="$(printf '%s' "$resp" | jq -r '.token // empty')"
  if [ -n "$sid" ] && [ -n "$tok" ]; then
    ok "session create works offline"
    if sudo -u "$agent_user" env DOCKER_HELPER_SESSION_TOKEN="$tok" "$dh" self --json 2>/dev/null | jq -e '.type == "session"' >/dev/null; then
      ok "session bearer introspects offline"
    else
      bad "session bearer self failed"
    fi
    sudo -u "$agent_user" "$dh" session delete "$sid" >/dev/null 2>&1 && ok "session delete works offline" || bad "session delete failed"
  else
    bad "session create failed offline"
  fi
  local n
  n="$(sudo -u "$agent_user" "$dh" session list --json 2>/dev/null | jq '.sessions | length')"
  if [ "$n" = 0 ]; then ok "no orphan session"; else bad "orphan session(s): $n"; fi

  summary
}

# --- host role ---------------------------------------------------------------
probe_host_fail() {
  printf '[probe-vm-isolation] ERROR: %s\n' "$*" >&2
  exit 1
}

# UAT-4/F4: the diagnostic listeners' lifetime is owned by a GLOBAL registry.
# The previous design kept the PIDs in probe_host() locals while installing an
# EXIT trap: after probe_host returned, the trap referenced dead locals
# ('pid4: unbound variable') and the listener processes leaked (the real UAT
# left a Python listener on port 47812). The registry is global, the traps are
# installed before the first listener starts, and cleanup only ever kills the
# PIDs this probe itself recorded — never a foreign process on the port.
LISTENER_PIDS=""
LISTENER_WORK=""

cleanup_listeners() {
  local p
  for p in $LISTENER_PIDS; do
    kill "$p" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [ -n "$LISTENER_WORK" ]; then
    rm -rf "$LISTENER_WORK"
  fi
  LISTENER_PIDS=""
  LISTENER_WORK=""
}
trap cleanup_listeners EXIT
trap 'cleanup_listeners; exit 130' INT
trap 'cleanup_listeners; exit 143' TERM

probe_host() { # [PORT]
  local port="${1:-47812}"

  command -v python3 >/dev/null 2>&1 || probe_host_fail "python3 not found on the physical host"
  command -v ip >/dev/null 2>&1 || probe_host_fail "ip not found on the physical host"
  local devvm="$SCRIPT_DIR/../dev-vm-local.sh"
  [ -f "$devvm" ] || probe_host_fail "cannot find scripts/dev-vm-local.sh next to this probe"

  local lan4 lan6 work cnt4 cnt6 pid4 pid6 stream
  lan4="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1)}' | head -1)"
  [ -n "$lan4" ] || probe_host_fail "cannot determine the host's LAN IPv4 source address"
  lan6="$(ip -6 route get 2606:4700::1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1)}' | head -1)"

  work="$(mktemp -d)" || probe_host_fail "mktemp failed"
  LISTENER_WORK="$work"
  cnt4="$work/accepts4" cnt6="$work/accepts6" stream="$work/probe-stream.sh"
  : > "$cnt4"; : > "$cnt6"

  # Each listener counts accepted connections in its counter file (the only
  # writer is the listener itself; readers poll). No log clearing anywhere:
  # the verdict uses the DELTA after an explicitly fixated baseline.
  python3 - "$port" "$cnt4" <<'PY' & pid4=$!
import socket, sys
port, cnt = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(8)
n = 0
while True:
    try:
        c, _ = s.accept()
    except OSError:
        break
    n += 1
    with open(cnt, "w") as f:
        f.write(str(n))
    c.close()
PY
  LISTENER_PIDS="$LISTENER_PIDS $pid4"
  if [ -n "$lan6" ]; then
    python3 - "$port" "$cnt6" <<'PY' & pid6=$!
import socket, sys
port, cnt = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
s.bind(("::", port))
s.listen(8)
n = 0
while True:
    try:
        c, _ = s.accept()
    except OSError:
        break
    n += 1
    with open(cnt, "w") as f:
        f.write(str(n))
    c.close()
PY
  LISTENER_PIDS="$LISTENER_PIDS $pid6"
  else
    pid6=""
  fi

  count_of() { cat "$1" 2>/dev/null || echo 0; }
  listener_alive() {
    kill -0 "$pid4" 2>/dev/null || return 1
    [ -z "$pid6" ] || kill -0 "$pid6" 2>/dev/null
  }

  # (the listeners are owned by the global registry and the traps installed
  # before the first start; the PREPARE phase additionally requires the
  # recorded PIDs to be alive, so a foreign process occupying the port can
  # never stand in for a listener this probe started)

  # --- PREPARE phase: every listener must accept from the host side, on the
  # exact endpoints the guest will later probe. A listener that did not start
  # is a FAIL, never a PASS.
  local ready=0
  for _ in $(seq 1 20); do
    if kill -0 "$pid4" 2>/dev/null && tcp_reachable 127.0.0.1 "$port"; then ready=1; break; fi
    sleep 0.1
  done
  kill -0 "$pid4" 2>/dev/null \
    || probe_host_fail "IPv4 listener not running on port $port (a foreign process may hold it; it was not touched)"
  [ "$ready" = 1 ] || probe_host_fail "IPv4 listener not accepting on port $port"
  tcp_reachable "$lan4" "$port" || probe_host_fail "LAN IPv4 endpoint not accepting: $lan4:$port"
  if [ -n "$lan6" ]; then
    tcp_reachable ::1 "$port" || probe_host_fail "IPv6 listener not accepting on loopback"
    tcp_reachable "$lan6" "$port" || probe_host_fail "LAN IPv6 endpoint not accepting: [$lan6]:$port"
  fi
  printf 'prepared endpoints: 0.0.0.0:%s, %s:%s%s\n' "$port" "$lan4" "$port" \
    "$( [ -n "$lan6" ] && printf ', [%s]:%s' "$lan6" "$port" )"

  # --- DRAIN phase: wait until every preparation connection has been counted
  # (IPv4 and, when present, IPv6), then fixate the baselines. Counter-driven
  # (no blind clearing, no races).
  local drained=0
  for _ in $(seq 1 50); do
    drained=1
    if [ "$(count_of "$cnt4")" -lt 2 ]; then drained=0; fi
    if [ -n "$lan6" ] && [ "$(count_of "$cnt6")" -lt 2 ]; then drained=0; fi
    [ "$drained" = 1 ] && break
    sleep 0.1
  done
  [ "$drained" = 1 ] || probe_host_fail "listeners did not account the preparation connections"
  local baseline4 baseline6
  baseline4="$(count_of "$cnt4")"
  baseline6="$(count_of "$cnt6")"
  listener_alive || probe_host_fail "a listener died before the guest probes"

  # --- guest probes over the host->guest SSH path (the SSH evidence itself).
  { cat "$SCRIPT_DIR/lab-vm-guard.sh"; printf '\n'; cat "$SELF"; } > "$stream"
  local guest_args="guest 10.0.2.2 $port $lan4 $port"
  [ -n "$lan6" ] && guest_args="$guest_args $lan6 $port"
  echo "running the guest probe over host->guest SSH (this transport is the SSH evidence)"
  if "$devvm" ssh "sudo bash -s -- $guest_args" < "$stream"; then
    ok "guest probe passed over host->guest SSH"
  else
    bad "guest probe failed (see its output above)"
  fi

  # --- VERIFY phase: listeners alive, counter delta zero on BOTH families
  # (stability-checked so a connection accepted in flight cannot be missed).
  if ! listener_alive; then
    bad "a listener died during the guest probes (verdict INCOMPLETE)"
  else
    local final1_4 final2_4 final1_6="" final2_6="" delta=""
    final1_4="$(count_of "$cnt4")"
    [ -n "$lan6" ] && final1_6="$(count_of "$cnt6")"
    sleep 0.3
    final2_4="$(count_of "$cnt4")"
    [ -n "$lan6" ] && final2_6="$(count_of "$cnt6")"
    if [ "$final1_4" != "$baseline4" ] || [ "$final2_4" != "$baseline4" ]; then
      delta="$delta ipv4"
    fi
    if [ -n "$lan6" ] && { [ "$final1_6" != "$baseline6" ] || [ "$final2_6" != "$baseline6" ]; }; then
      delta="$delta ipv6"
    fi
    if [ -n "$delta" ]; then
      bad "a guest connection REACHED a controlled host listener (baseline ${baseline4}/${baseline6:--}, now ${final2_4}/${final2_6:--}):$delta"
    else
      ok "no guest connection reached any controlled listener"
    fi
  fi

  # UAT-4/F4: the minimal listener lifetime ends here — the verification is
  # complete, so the listeners are stopped and the temp state removed
  # immediately (the global trap remains as a safety net and is idempotent).
  cleanup_listeners

  summary
}

usage() {
  cat <<'EOF'
usage:
  probe-vm-isolation.sh host [PORT]
      on the physical host: prepare controlled listeners, run the guest
      probe over SSH, assert no guest connection reached any listener.
  probe-vm-isolation.sh guest GW_HOST GW_PORT LAN4_HOST LAN4_PORT [LAN6_HOST LAN6_PORT]
      inside the guest (normally streamed in by the host role).
EOF
}

case "${1:-}" in
  host)  shift; probe_host "$@" ;;
  guest) shift; probe_guest "$@" ;;
  *) usage; [ "${1:-}" = "" ] || exit 2 ;;
esac
