#!/usr/bin/env bash
#
# uat-regression-selinux-fs-boundary.sh — Release-2 targeted regression
# group 3: restorecon filesystem-boundary (Tumbleweed / RPM / SELinux).
#
# Proves the canonical workspace recursive restorecon invocation
# (restorecon -R -m -x) does NOT cross into a DIFFERENT filesystem mounted
# beneath the workspace:
#   * a tmpfs is mounted at <scratch>/mnt (a different device than the
#     workspace filesystem);
#   * a semanage fcontext rule maps <scratch>(/.*)? to docker_helper_workspace_t;
#   * running the exact canonical command restorecon -R -m -x relabels the
#     scratch tree to docker_helper_workspace_t;
#   * the tmpfs subtree keeps its own label (NOT docker_helper_workspace_t),
#     proving -x prevented restorecon from crossing the filesystem boundary;
#   * the tmpfs marker content is intact.
#
# This is a self-contained proof of the canonical invocation's traversal
# semantics, run unconfined as root so the result is not confounded by the
# confined-domain relabel permissions (a separate, reported blocker). The
# docker-helper Session MAC path exercises this same canonical command
# end-to-end once that blocker is resolved.
#
# Requires: root, semanage + restorecon (SELinux tooling), mount(8), enforcing
# SELinux. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "3. SELinux restorecon filesystem-boundary"

reg_require_root
reg_require_cmd semanage "SELinux fcontext tooling"
reg_require_cmd restorecon "SELinux restorecon"
reg_require_cmd stat "coreutils"
reg_require_cmd mount "util-linux mount"
reg_require_cmd umount "util-linux umount"

if [ "$(getenforce 2>/dev/null || true)" != "Enforcing" ]; then
  reg_blocked "SELinux is not enforcing"
fi

# --- scratch tree below /opt with a different-filesystem mount beneath it --------
SCRATCH="/opt/uat-fsbound-$RANDOM"
MNT="$SCRATCH/mnt"
mkdir -p "$MNT"

cleanup() {
  umount "$MNT" >/dev/null 2>&1 || true
  semanage fcontext -d "$SCRATCH(/.*)?" >/dev/null 2>&1 || true
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

if ! mount -t tmpfs tmpfs-dh-uat "$MNT"; then
  reg_fail "cannot mount tmpfs at $MNT (different-filesystem regression cannot be set up)"
  reg_result
fi

SCRATCH_DEV="$(stat -c '%d' "$SCRATCH" 2>/dev/null)"
MNT_DEV="$(stat -c '%d' "$MNT" 2>/dev/null)"
reg_info "workspace dev=$SCRATCH_DEV mounted-tmpfs dev=$MNT_DEV (different => -x must not cross)"
if [ "$SCRATCH_DEV" = "$MNT_DEV" ]; then
  reg_fail "tmpfs did not yield a different device than the workspace; test setup invalid"
  reg_result
fi

printf 'boundary-marker\n' > "$MNT/marker.txt"
MARKER_TYPE_BEFORE="$(stat -c '%C' "$MNT/marker.txt" 2>/dev/null | cut -d: -f3)"
reg_info "marker on the mounted tmpfs before restorecon: '$MARKER_TYPE_BEFORE'"

# --- persistent fcontext mapping, then the exact canonical workspace restorecon --
if ! semanage fcontext -a -t docker_helper_workspace_t "$SCRATCH(/.*)?" 2>/dev/null; then
  reg_fail "cannot add the fcontext mapping for the scratch tree"
  reg_result
fi

restorecon -R -m -x "$SCRATCH" >/dev/null 2>&1 \
  || { reg_fail "canonical restorecon -R -m -x failed on the scratch tree"; reg_result; }

SCRATCH_TYPE="$(stat -c '%C' "$SCRATCH" 2>/dev/null | cut -d: -f3)"
if [ "$SCRATCH_TYPE" = "docker_helper_workspace_t" ]; then
  reg_ok "workspace tree relabeled to docker_helper_workspace_t"
else
  reg_fail "workspace tree type != docker_helper_workspace_t (got '$SCRATCH_TYPE')"
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

reg_result
