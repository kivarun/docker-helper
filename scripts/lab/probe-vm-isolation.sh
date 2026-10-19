#!/usr/bin/env bash
#
# probe-vm-isolation.sh — prove the lab VM's isolated network posture from
# INSIDE the guest, and that the local stack still works offline.
#
# Run as root in the guest (the host-side SSH check is implicit: the host runs
# this over `dev-vm-local.sh ssh`). With the slirp `restrict=on` posture the
# guest keeps a link-local address but has no gateway/DNS/outbound routing.
#
# Asserts:
#   1. the slirp NIC is up with an address (link alive);
#   2. there is no default route;
#   3. outbound internet TCP fails;
#   4. DNS resolution fails;
#   5. TCP to the slirp host gateway fails (no physical-host services);
#   6. SELinux is enforcing;
#   7. the docker-helper daemon is active and a real Session round-trips
#      offline (create -> self -> delete, no orphan).
set -u

AGENT_USER="${AGENT_USER:-agent}"
DH=/usr/bin/docker-helper
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }

[ "$(id -u)" = 0 ] || { echo "must run as root in the guest" >&2; exit 1; }

# 1. link up
if ip -4 -o addr show scope global 2>/dev/null | grep -q 'inet '; then
  ok "guest NIC has an address (link alive)"
else
  bad "guest NIC has no address"
fi

# 2. no default route
if ip route 2>/dev/null | grep -q '^default'; then
  bad "a default route is present (not isolated)"
else
  ok "no default route"
fi

# 3. no internet
if curl -s --max-time 5 http://1.1.1.1/ >/dev/null 2>&1; then
  bad "internet reachable (1.1.1.1)"
else
  ok "internet unreachable (1.1.1.1 TCP fails)"
fi

# 4. no DNS
if getent hosts github.com >/dev/null 2>&1; then
  bad "DNS resolution works (github.com)"
else
  ok "DNS resolution fails"
fi

# 5. no host gateway services
if curl -s --max-time 4 http://10.0.2.2/ >/dev/null 2>&1; then
  bad "slirp host gateway TCP reachable (10.0.2.2)"
else
  ok "slirp host gateway TCP unreachable (no host services)"
fi

# 6. SELinux
if [ "$(getenforce)" = "Enforcing" ]; then ok "SELinux enforcing"; else bad "SELinux not enforcing"; fi

# 7. daemon + offline session round-trip
if systemctl is-active --quiet docker-helper; then ok "docker-helper daemon active"; else bad "docker-helper daemon not active"; fi
ws="/home/$AGENT_USER/work/probe"
install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$ws"
resp="$(sudo -u "$AGENT_USER" "$DH" session create "$ws" --json 2>/dev/null)" || resp=""
sid="$(printf '%s' "$resp" | jq -r '.session.id // empty')"
tok="$(printf '%s' "$resp" | jq -r '.token // empty')"
if [ -n "$sid" ] && [ -n "$tok" ]; then
  ok "session create works offline"
  if sudo -u "$AGENT_USER" env DOCKER_HELPER_SESSION_TOKEN="$tok" "$DH" self --json 2>/dev/null | jq -e '.type == "session"' >/dev/null; then
    ok "session bearer introspects offline"
  else
    bad "session bearer self failed"
  fi
  sudo -u "$AGENT_USER" "$DH" session delete "$sid" >/dev/null 2>&1 && ok "session delete works offline" || bad "session delete failed"
else
  bad "session create failed offline"
fi
n="$(sudo -u "$AGENT_USER" "$DH" session list --json 2>/dev/null | jq '.sessions | length')"
if [ "$n" = 0 ]; then ok "no orphan session"; else bad "orphan session(s): $n"; fi

echo
printf 'isolation probe: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
