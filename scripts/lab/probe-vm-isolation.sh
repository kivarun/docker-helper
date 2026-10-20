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
#          and self-verify they accept connections — endpoints are proven
#          available BEFORE the guest probes them. The harness never touches
#          the host firewall: only userspace listeners are started.
#       3. stream the guard library plus this script into the guest over the
#          host->guest SSH path (that transport is itself the SSH evidence)
#          and run the guest probe there;
#       4. assert the listener logs stayed EMPTY — no guest connection ever
#          reached a real, accepting endpoint.
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

probe_host() { # [PORT]
  local port="${1:-47812}"

  command -v python3 >/dev/null 2>&1 || probe_host_fail "python3 not found on the physical host"
  command -v ip >/dev/null 2>&1 || probe_host_fail "ip not found on the physical host"
  local devvm="$SCRIPT_DIR/../dev-vm-local.sh"
  [ -f "$devvm" ] || probe_host_fail "cannot find scripts/dev-vm-local.sh next to this probe"

  local lan4 lan6 work log4 log6 pid4 pid6 stream
  lan4="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1)}' | head -1)"
  [ -n "$lan4" ] || probe_host_fail "cannot determine the host's LAN IPv4 source address"
  lan6="$(ip -6 route get 2606:4700::1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src") print $(i+1)}' | head -1)"

  work="$(mktemp -d)" || probe_host_fail "mktemp failed"
  log4="$work/listener4.log" log6="$work/listener6.log" stream="$work/probe-stream.sh"
  : > "$log4"; : > "$log6"

  python3 - "$port" "$log4" <<'PY' & pid4=$!
import socket, sys
port, log = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(8)
while True:
    try:
        c, _ = s.accept()
    except OSError:
        break
    with open(log, "a") as f:
        f.write("accepted\n")
    c.close()
PY
  if [ -n "$lan6" ]; then
    python3 - "$port" "$log6" <<'PY' & pid6=$!
import socket, sys
port, log = int(sys.argv[1]), sys.argv[2]
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
s.bind(("::", port))
s.listen(8)
while True:
    try:
        c, _ = s.accept()
    except OSError:
        break
    with open(log, "a") as f:
        f.write("accepted\n")
    c.close()
PY
  else
    pid6=""
  fi

  cleanup_listeners() {
    [ -n "$pid4" ] && kill "$pid4" 2>/dev/null
    [ -n "$pid6" ] && kill "$pid6" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$work"
  }
  trap cleanup_listeners EXIT

  # Endpoints must be PROVEN available before the guest probes them: wait for
  # the listeners to accept (bounded polling, no blind sleep).
  local ready=0
  for _ in $(seq 1 20); do
    if tcp_reachable 127.0.0.1 "$port"; then ready=1; break; fi
    sleep 0.1
  done
  [ "$ready" = 1 ] || probe_host_fail "IPv4 listener not accepting on port $port"
  tcp_reachable "$lan4" "$port" || probe_host_fail "LAN IPv4 endpoint not accepting: $lan4:$port"
  if [ -n "$lan6" ]; then
    tcp_reachable ::1 "$port" || probe_host_fail "IPv6 listener not accepting on port $port"
  fi
  printf 'prepared endpoints: 0.0.0.0:%s, %s:%s%s\n' "$port" "$lan4" "$port" \
    "$( [ -n "$lan6" ] && printf ', [%s]:%s' "$lan6" "$port" )"

  # Stream guard library + this script into the guest over SSH; the guest
  # probe running over this transport is the host->guest SSH evidence.
  { cat "$SCRIPT_DIR/lab-vm-guard.sh"; printf '\n'; cat "$SELF"; } > "$stream"
  local guest_args="guest 10.0.2.2 $port $lan4 $port"
  [ -n "$lan6" ] && guest_args="$guest_args $lan6 $port"
  echo "running the guest probe over host->guest SSH (this transport is the SSH evidence)"
  if "$devvm" ssh "sudo bash -s -- $guest_args" < "$stream"; then
    ok "guest probe passed over host->guest SSH"
  else
    bad "guest probe failed (see its output above)"
  fi

  if [ -s "$log4" ] || { [ -n "$pid6" ] && [ -s "$log6" ]; }; then
    bad "a guest connection REACHED a controlled host listener"
  else
    ok "no guest connection reached any controlled listener"
  fi

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
