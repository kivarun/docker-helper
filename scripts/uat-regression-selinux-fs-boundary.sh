#!/usr/bin/env bash
#
# uat-regression-selinux-fs-boundary.sh — Release-2 targeted regression
# group 3: restorecon filesystem-boundary (Tumbleweed / RPM / SELinux).
#
# Self-contained proof (run unconfined as root) of the canonical workspace
# recursive restorecon invocation (restorecon -R -m -x) traversal semantics:
#
#   Subcase A — DIFFERENT filesystem mounted beneath the workspace:
#     * a tmpfs is mounted at <scratch>/mnt (a different device than the
#       workspace filesystem);
#     * a semanage fcontext rule maps <scratch>(/.*)? to docker_helper_workspace_t;
#     * running the exact canonical command restorecon -R -m -x relabels the
#       scratch tree to docker_helper_workspace_t;
#     * the tmpfs subtree keeps its own label (NOT docker_helper_workspace_t),
#       proving -x prevented restorecon from crossing the filesystem boundary;
#     * the tmpfs marker content is intact.
#
#   Subcase B — SAME-filesystem bind mount beneath the workspace (the mount
#   alias): /opt/uat-bind-outside is bind-mounted at /opt/uat-bind-workspace/mnt
#   (same st_dev). restorecon -R -m -x on the workspace cannot detect the bind
#   (-x only skips a different st_dev), so the REAL external source inode under
#   /opt/uat-bind-outside is relabeled to docker_helper_workspace_t. This proves
#   and documents the mount-alias safety gap that the production workspace
#   relabel-boundary guard closes by rejecting such a boundary BEFORE running
#   restorecon (see selinux_fcontext.go checkWorkspaceRelabelBoundary).
#
# These are self-contained proofs of the canonical invocation's traversal
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

# --- same-filesystem bind-mount subcase paths (fixed, per proof spec) -------------
BIND_WS="/opt/uat-bind-workspace"
BIND_OUT="/opt/uat-bind-outside"

cleanup() {
  umount "$MNT" >/dev/null 2>&1 || true
  semanage fcontext -d "$SCRATCH(/.*)?" >/dev/null 2>&1 || true
  rm -rf "$SCRATCH"
  umount "$BIND_WS/mnt" >/dev/null 2>&1 || true
  semanage fcontext -d "$BIND_WS(/.*)?" >/dev/null 2>&1 || true
  rm -rf "$BIND_WS" "$BIND_OUT"
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

# =============================================================================
# Subcase B: SAME-filesystem bind mount (the mount alias).
#   Does -x traverse a same-filesystem bind mount and relabel the EXTERNAL
#   source inode according to the workspace pathname?
# =============================================================================
reg_info "--- same-filesystem bind-mount subcase ---"
rm -rf "$BIND_WS" "$BIND_OUT"
mkdir -p "$BIND_WS/mnt" "$BIND_OUT"
printf 'external-marker\n' > "$BIND_OUT/marker.txt"

BIND_WS_DEV="$(stat -c '%d' "$BIND_WS" 2>/dev/null)"
BIND_OUT_DEV="$(stat -c '%d' "$BIND_OUT" 2>/dev/null)"
reg_info "bind workspace dev=$BIND_WS_DEV outside dev=$BIND_OUT_DEV (equal => same filesystem)"
if [ "$BIND_WS_DEV" != "$BIND_OUT_DEV" ]; then
  reg_fail "bind subcase setup invalid: workspace and outside are not on the same filesystem"
  reg_result
fi

EXT_TYPE_BEFORE="$(stat -c '%C' "$BIND_OUT/marker.txt" 2>/dev/null | cut -d: -f3)"
EXT_INODE_BEFORE="$(stat -c '%d:%i' "$BIND_OUT/marker.txt" 2>/dev/null)"
reg_info "external source inode BEFORE: type=$EXT_TYPE_BEFORE inode=$EXT_INODE_BEFORE"

if ! mount --bind "$BIND_OUT" "$BIND_WS/mnt" 2>/dev/null; then
  reg_fail "cannot bind mount $BIND_OUT at $BIND_WS/mnt"
  reg_result
fi

if ! semanage fcontext -a -t docker_helper_workspace_t "$BIND_WS(/.*)?" 2>/dev/null; then
  reg_fail "cannot add fcontext mapping for the bind workspace"
  reg_result
fi

# Exact canonical command.
restorecon -R -m -x "$BIND_WS" >/dev/null 2>&1 \
  || { reg_fail "canonical restorecon -R -m -x failed on the bind workspace"; reg_result; }

# Inspect the REAL source inode under the external dir (not through the mount).
EXT_TYPE_AFTER="$(stat -c '%C' "$BIND_OUT/marker.txt" 2>/dev/null | cut -d: -f3)"
EXT_INODE_AFTER="$(stat -c '%d:%i' "$BIND_OUT/marker.txt" 2>/dev/null)"
EXT_DIR_TYPE_AFTER="$(stat -c '%C' "$BIND_OUT" 2>/dev/null | cut -d: -f3)"
reg_info "external source inode AFTER: type=$EXT_TYPE_AFTER inode=$EXT_INODE_AFTER (dir type=$EXT_DIR_TYPE_AFTER)"

if [ "$EXT_INODE_BEFORE" = "$EXT_INODE_AFTER" ] && [ "$EXT_TYPE_AFTER" = "docker_helper_workspace_t" ]; then
  reg_ok "CONFIRMED: -x traverses the same-filesystem bind mount and relabeled the external source inode to docker_helper_workspace_t (mount-alias safety gap)"
else
  reg_fail "unexpected bind subcase result: external inode $EXT_INODE_BEFORE -> $EXT_INODE_AFTER type $EXT_TYPE_BEFORE -> $EXT_TYPE_AFTER"
fi

reg_result
