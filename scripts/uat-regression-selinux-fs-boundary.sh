#!/usr/bin/env bash
#
# uat-regression-selinux-fs-boundary.sh — Release-2 targeted regression
# group 3: restorecon filesystem-boundary (Tumbleweed / RPM / SELinux).
#
# Proves that the canonical recursive workspace restorecon
# (restorecon -R -m -x) does NOT cross into a DIFFERENT filesystem mounted
# beneath the workspace:
#   * a tmpfs is mounted at <workspace>/mnt (a different device than the
#     workspace filesystem);
#   * Session creation (real production MAC path) relabels the workspace to
#     docker_helper_workspace_t;
#   * the tmpfs subtree keeps its own label (NOT docker_helper_workspace_t),
#     proving -x prevented restorecon from crossing the filesystem boundary;
#   * the tmpfs marker content is intact;
#   * session teardown (rollback restorecon, same canonical invocation) also
#     does not cross the boundary.
#
# This is a concrete filesystem-boundary test of the workspace restorecon
# invocation, not of authorization.
#
# Requires: installed docker-helper system service (active), enforcing SELinux,
# root, mount(8). Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see
# uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "3. SELinux restorecon filesystem-boundary"

reg_require_root
reg_require_service
reg_require_cmd stat "coreutils"
reg_require_cmd mount "util-linux mount"
reg_require_cmd umount "util-linux umount"

if [ "$(getenforce 2>/dev/null || true)" != "Enforcing" ]; then
  reg_blocked "SELinux is not enforcing"
fi

# --- ensure /opt is an authorized global root (authorization, not MAC) ----------
dh config allowed-root add /opt >/dev/null 2>&1 || true
if ! dh config allowed-root list 2>/dev/null | grep -qx '/opt'; then
  reg_fail "cannot add /opt to global allowed roots (authorization prerequisite)"
fi
dh reload --system >/dev/null 2>&1 || reg_fail "config reload failed after adding /opt root"

# --- workspace below /opt with a different-filesystem mount beneath it ----------
WS="/opt/uat-ws-fsbound-$RANDOM"
MNT="$WS/mnt"
mkdir -p "$MNT"

cleanup() {
  umount "$MNT" >/dev/null 2>&1 || true
  rm -rf "$WS"
}
trap cleanup EXIT

if ! mount -t tmpfs tmpfs-dh-uat "$MNT"; then
  reg_fail "cannot mount tmpfs at $MNT (different-filesystem regression cannot be set up)"
  reg_result
fi

WS_DEV="$(stat -c '%d' "$WS" 2>/dev/null)"
MNT_DEV="$(stat -c '%d' "$MNT" 2>/dev/null)"
reg_info "workspace dev=$WS_DEV mounted-tmpfs dev=$MNT_DEV (different => -x must not cross)"
if [ "$WS_DEV" = "$MNT_DEV" ]; then
  reg_fail "tmpfs did not yield a different device than the workspace; test setup invalid"
  reg_result
fi

printf 'boundary-marker\n' > "$MNT/marker.txt"
MARKER_TYPE_BEFORE="$(stat -c '%C' "$MNT/marker.txt" 2>/dev/null | cut -d: -f3)"
reg_info "marker on the mounted tmpfs before session: '$MARKER_TYPE_BEFORE'"

# --- session creation (real production MAC path: restorecon -R -m -x) ------------
SESS_JSON="$(dh session create --system --workspace "$WS" --json 2>&1)" || {
  reg_fail "session create failed (MAC preparation must run the canonical restorecon): $(printf '%s' "$SESS_JSON" | redact | head -3)"
  reg_result
}
SID="$(printf '%s' "$SESS_JSON" | json_field id)"
[ -n "$SID" ] || { reg_fail "session create returned no id"; reg_result; }
reg_ok "session created; workspace MAC preparation ran the canonical restorecon"

WS_TYPE="$(stat -c '%C' "$WS" 2>/dev/null | cut -d: -f3)"
if [ "$WS_TYPE" = "docker_helper_workspace_t" ]; then
  reg_ok "workspace relabeled to docker_helper_workspace_t"
else
  reg_fail "workspace type != docker_helper_workspace_t (got '$WS_TYPE')"
fi

MARKER_TYPE_AFTER="$(stat -c '%C' "$MNT/marker.txt" 2>/dev/null | cut -d: -f3)"
if [ "$MARKER_TYPE_AFTER" != "docker_helper_workspace_t" ]; then
  reg_ok "different-filesystem content not relabeled across the boundary ('$MARKER_TYPE_BEFORE' -> '$MARKER_TYPE_AFTER')"
else
  reg_fail "restorecon crossed the filesystem boundary: tmpfs marker relabeled to docker_helper_workspace_t"
fi

MARK="$(cat "$MNT/marker.txt" 2>/dev/null || true)"
if [ "$MARK" = "boundary-marker" ]; then
  reg_ok "different-filesystem content intact"
else
  reg_fail "different-filesystem content changed/missing (marker '$MARK')"
fi

# --- session teardown (rollback restorecon, same canonical invocation) ------------
if dh session delete --system --id "$SID" >/dev/null 2>&1; then
  reg_ok "session deleted (rollback restorecon also -R -m -x)"
else
  reg_fail "session delete failed"
fi

MARKER_TYPE_FINAL="$(stat -c '%C' "$MNT/marker.txt" 2>/dev/null | cut -d: -f3)"
if [ "$MARKER_TYPE_FINAL" != "docker_helper_workspace_t" ]; then
  reg_ok "different-filesystem content still not relabeled after teardown ('$MARKER_TYPE_FINAL')"
else
  reg_fail "rollback restorecon crossed the filesystem boundary"
fi

reg_result
