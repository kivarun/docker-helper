#!/usr/bin/env bash
#
# Release 2.2 M0-S SELinux feasibility proof. Runs inside the canonical
# enforcing openSUSE Tumbleweed guest after the production docker_helper
# policy module and container-selinux have been loaded.
#
# Candidate mechanism: a helper-owned bindfs passthrough projection gives each
# read-only exposure a separate FUSE superblock. A mount-wide SELinux context
# labels that projection docker_helper_ro_projection_t without changing the
# backing tree. The projection is intentionally VFS-writable; write denial is
# therefore attributable to SELinux rather than to a read-only mount flag.

set -Eeuo pipefail

PREFIX='[release-2.2-m0-selinux]'
IMAGE="${M0_SELINUX_IMAGE:-alpine:3.20}"
EVIDENCE_DIR="${M0_EVIDENCE_DIR:-/tmp/docker-helper-release-2.2-m0-selinux-evidence}"
RUN_KEY_RAW="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$$"
RUN_KEY="$(printf '%s' "$RUN_KEY_RAW" | tr -c 'A-Za-z0-9_' '_')"
WORK_DIR="$(mktemp -d /tmp/docker-helper-m0-selinux.XXXXXXXX)"
STATE_DIR="$WORK_DIR/owned-projections"
SHARED_SOURCE="/opt/docker-helper-m0-selinux.$RUN_KEY"
RO_TYPE='docker_helper_ro_projection_t'
RO_CONTEXT="system_u:object_r:${RO_TYPE}:s0"
MODULE_NAME='docker_helper_m0_ro_projection'
MODULE_TE="$WORK_DIR/$MODULE_NAME.te"
MODULE_MOD="$WORK_DIR/$MODULE_NAME.mod"
MODULE_PP="$WORK_DIR/$MODULE_NAME.pp"
RO_CONTAINER="docker-helper-m0-se-ro-$RUN_KEY"
RW_CONTAINER="docker-helper-m0-se-rw-$RUN_KEY"
COLLISION_CONTAINER="docker-helper-m0-se-failure-$RUN_KEY"
FOREIGN_MOUNT="$WORK_DIR/foreign-mount"
MODULE_LOADED=0
DONTAUDIT_DISABLED=0
LAST_PROJECTION_STATE=''
LAST_PROJECTION_MOUNT=''
FUSERMOUNT=''

say() {
  printf '%s %s\n' "$PREFIX" "$*"
}

fail() {
  printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

ctx_type() {
  printf '%s' "$1" | cut -d: -f3
}

ctx_range() {
  printf '%s' "$1" | cut -d: -f4-
}

projection_is_mounted() {
  mountpoint -q "$1/mount" 2>/dev/null
}

remove_projection() {
  local state="$1" pid=''
  case "$state" in
    "$STATE_DIR"/*) ;;
    *) fail "refusing to remove non-owned projection path: $state" ;;
  esac

  if mountpoint -q "$state/mount" 2>/dev/null; then
    "$FUSERMOUNT" -u "$state/mount" >/dev/null 2>&1 || umount -l "$state/mount"
  fi
  if [ -f "$state/source-bind" ] && mountpoint -q "$state/lower/item" 2>/dev/null; then
    umount "$state/lower/item"
  fi
  if [ -r "$state/bindfs.pid" ]; then
    pid="$(cat "$state/bindfs.pid")"
    if [ -n "$pid" ]; then
      for _ in $(seq 1 20); do
        if ! kill -0 "$pid" 2>/dev/null; then
          break
        fi
        sleep 0.1
      done
      if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
      fi
      wait "$pid" 2>/dev/null || true
    fi
  fi
  rm -rf -- "$state"
}

reconcile_owned_projections() {
  local marker state
  shopt -s nullglob
  for marker in "$STATE_DIR"/*/.docker-helper-m0-owned; do
    state="$(dirname "$marker")"
    remove_projection "$state"
  done
  shopt -u nullglob
}

cleanup() {
  local original_status=$?
  trap - EXIT INT TERM
  set +e
  docker rm -f "$RO_CONTAINER" "$RW_CONTAINER" "$COLLISION_CONTAINER" >/dev/null 2>&1
  reconcile_owned_projections >/dev/null 2>&1
  if mountpoint -q "$FOREIGN_MOUNT" 2>/dev/null; then
    umount "$FOREIGN_MOUNT" >/dev/null 2>&1
  fi
  if [ "$DONTAUDIT_DISABLED" = 1 ]; then
    semodule -B >/dev/null 2>&1
  fi
  if [ "$MODULE_LOADED" = 1 ]; then
    semodule -r "$MODULE_NAME" >/dev/null 2>&1
  fi
  case "$SHARED_SOURCE" in
    /opt/docker-helper-m0-selinux.*) rm -rf -- "$SHARED_SOURCE" ;;
  esac
  case "$WORK_DIR" in
    /tmp/docker-helper-m0-selinux.*) rm -rf -- "$WORK_DIR" ;;
  esac
  exit "$original_status"
}
trap cleanup EXIT INT TERM

write_proof_module() {
  cat >"$MODULE_TE" <<'TE_EOF'
module docker_helper_m0_ro_projection 1.0;

require {
    attribute file_type;
    type docker_helper_container_t;
    type container_runtime_t;
    type fusefs_t;
    class filesystem { associate getattr };
    class file { execute execute_no_trans entrypoint getattr ioctl lock map open read };
    class dir { getattr ioctl lock open read search };
    class lnk_file { getattr read };
    class sock_file { getattr ioctl lock open read };
    class fifo_file { getattr ioctl lock open read };
}

# Static projection type. It deliberately does not carry container_file_type:
# container-selinux's generic writable-volume rules must not apply to it.
type docker_helper_ro_projection_t, file_type;

# Mount-context labels on FUSE must be associable with the FUSE filesystem.
allow docker_helper_ro_projection_t fusefs_t:filesystem associate;

# Preserve read/execute compatibility while intentionally omitting every
# mutation permission (write, append, create, setattr, add_name, remove_name,
# unlink, rename, link and reparent).
allow docker_helper_container_t docker_helper_ro_projection_t:file {
    execute execute_no_trans entrypoint getattr ioctl lock map open read
};
allow docker_helper_container_t docker_helper_ro_projection_t:dir {
    getattr ioctl lock open read search
};
allow docker_helper_container_t docker_helper_ro_projection_t:lnk_file { getattr read };
allow docker_helper_container_t docker_helper_ro_projection_t:sock_file {
    getattr ioctl lock open read
};
allow docker_helper_container_t docker_helper_ro_projection_t:fifo_file {
    getattr ioctl lock open read
};
allow docker_helper_container_t fusefs_t:filesystem getattr;

# Docker/runc may inspect the already-mounted projection while constructing a
# bind in the container mount namespace. These are setup-only read grants;
# workload mutation remains governed by docker_helper_container_t above.
allow container_runtime_t docker_helper_ro_projection_t:dir { getattr open read search };
allow container_runtime_t docker_helper_ro_projection_t:file { getattr open read };
allow container_runtime_t docker_helper_ro_projection_t:lnk_file { getattr read };
allow container_runtime_t fusefs_t:filesystem getattr;
TE_EOF
}

load_proof_module() {
  write_proof_module
  checkmodule -M -m -o "$MODULE_MOD" "$MODULE_TE"
  semodule_package -o "$MODULE_PP" -m "$MODULE_MOD"
  semodule -i "$MODULE_PP"
  MODULE_LOADED=1
  semodule -l | awk '{print $1}' | grep -Fxq "$MODULE_NAME" \
    || fail 'temporary projection policy module was not loaded'
}

create_projection() {
  local id="$1" kind="$2" source="$3"
  local state="$STATE_DIR/$id" backing pid ready=0

  case "$id" in
    *[!A-Za-z0-9_-]*|'') fail "invalid projection id: $id" ;;
  esac
  [ ! -e "$state" ] || fail "projection state already exists: $state"

  mkdir -p "$state/mount"
  chmod 0755 "$state" "$state/mount"
  printf '%s\n' "$RUN_KEY" >"$state/.docker-helper-m0-owned"

  case "$kind" in
    directory)
      [ -d "$source" ] || fail "directory projection source is invalid: $source"
      backing="$source"
      ;;
    file)
      [ -f "$source" ] || fail "file projection source is invalid: $source"
      mkdir -p "$state/lower"
      chmod 0755 "$state/lower"
      : >"$state/lower/item"
      mount --bind "$source" "$state/lower/item"
      printf '%s\n' "$source" >"$state/source-bind"
      backing="$state/lower"
      ;;
    *) fail "unsupported projection kind: $kind" ;;
  esac

  bindfs -f -o allow_other -o "context=$RO_CONTEXT" \
    "$backing" "$state/mount" >"$state/bindfs.log" 2>&1 &
  pid=$!
  printf '%s\n' "$pid" >"$state/bindfs.pid"

  for _ in $(seq 1 100); do
    if mountpoint -q "$state/mount" 2>/dev/null; then
      ready=1
      break
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  if [ "$ready" != 1 ]; then
    sed -n '1,120p' "$state/bindfs.log" >&2 || true
    fail "bindfs projection did not mount: $id"
  fi

  LAST_PROJECTION_STATE="$state"
  LAST_PROJECTION_MOUNT="$state/mount"
}

snapshot_source_contexts() {
  local rel path
  for rel in . protected.txt output output/seed.txt single.txt; do
    path="$SHARED_SOURCE/$rel"
    printf '%s|' "$rel"
    stat -Lc '%d:%i|%C' "$path"
  done
}

collect_audit() {
  local raw
  if command -v ausearch >/dev/null 2>&1 && pgrep -x auditd >/dev/null 2>&1; then
    ausearch -m AVC -m USER_AVC -ts "$AUDIT_START_AUSEARCH" 2>/dev/null || true
    return 0
  fi
  raw="$(dmesg 2>/dev/null || true)"
  if [ -z "$raw" ]; then
    journalctl -k --since "@${AUDIT_START_EPOCH}" --no-pager 2>/dev/null || true
  else
    printf '%s\n' "$raw"
  fi
}

assert_policy_is_read_only() {
  local policy_file="$EVIDENCE_DIR/projection-policy-live.txt"
  sesearch -A -s docker_helper_container_t -t "$RO_TYPE" >"$policy_file"
  grep -F 'allow docker_helper_container_t docker_helper_ro_projection_t' "$policy_file" >/dev/null \
    || fail 'live policy has no workload read grants for projection type'
  if grep -Eq '\b(write|append|create|setattr|add_name|remove_name|unlink|rename|link|reparent)\b' "$policy_file"; then
    fail 'live projection policy contains a mutation permission'
  fi
}

mkdir -p "$EVIDENCE_DIR" "$STATE_DIR" "$SHARED_SOURCE/output" "$FOREIGN_MOUNT"
chmod 0755 "$WORK_DIR" "$STATE_DIR" "$SHARED_SOURCE" "$SHARED_SOURCE/output" "$FOREIGN_MOUNT"
printf 'protected-seed\n' >"$SHARED_SOURCE/protected.txt"
printf 'output-seed\n' >"$SHARED_SOURCE/output/seed.txt"
printf 'single-seed\n' >"$SHARED_SOURCE/single.txt"
chmod 0666 "$SHARED_SOURCE/protected.txt" "$SHARED_SOURCE/output/seed.txt" "$SHARED_SOURCE/single.txt"

for command_name in docker bindfs mount mountpoint findmnt checkmodule semodule_package \
  semodule getenforce sestatus chcon sha256sum sesearch; do
  require_command "$command_name"
done
if command -v fusermount3 >/dev/null 2>&1; then
  FUSERMOUNT="$(command -v fusermount3)"
elif command -v fusermount >/dev/null 2>&1; then
  FUSERMOUNT="$(command -v fusermount)"
else
  fail 'fusermount3/fusermount not found'
fi

[ "$(id -u)" -eq 0 ] || fail 'proof must run as root'
[ "$(getenforce 2>/dev/null || true)" = 'Enforcing' ] || fail 'SELinux is not enforcing'
LSM="$(cat /sys/kernel/security/lsm 2>/dev/null || true)"
printf '%s' "$LSM" | grep -qw selinux || fail "SELinux is not an active LSM: $LSM"
if printf '%s' "$LSM" | grep -qw apparmor; then
  fail "AppArmor is concurrently active: $LSM"
fi
sestatus | grep -qE 'Current mode:[[:space:]]+enforcing' || fail 'sestatus is not enforcing'
docker info >/dev/null 2>&1 || fail 'Docker daemon is not reachable'
docker info --format '{{json .SecurityOptions}}' | grep -q 'selinux' \
  || fail 'Docker does not report SELinux as an active security option'
semodule -l | awk '{print $1}' | grep -Fxq docker_helper \
  || fail 'production docker_helper policy module is not loaded'
[ -e /dev/fuse ] || fail '/dev/fuse is unavailable'

exec > >(tee "$EVIDENCE_DIR/proof.log") 2>&1

say "run key: $RUN_KEY"
say "kernel: $(uname -srvm)"
say "image: $IMAGE"
say "lsm: $LSM"
docker version >"$EVIDENCE_DIR/docker-version.txt"
docker info >"$EVIDENCE_DIR/docker-info.txt"
sestatus >"$EVIDENCE_DIR/sestatus.txt"
bindfs --version >"$EVIDENCE_DIR/bindfs-version.txt"

say 'load bounded read-only projection policy'
load_proof_module
cp "$MODULE_TE" "$EVIDENCE_DIR/generated-projection-policy.te"
assert_policy_is_read_only

# This single label is the existing Session-workspace lifecycle state. Access
# mode never changes it; both concurrent Sessions below use this same tree.
chcon -R -t docker_helper_workspace_t "$SHARED_SOURCE"
SOURCE_CONTEXTS_BEFORE="$(snapshot_source_contexts)"
printf '%s\n' "$SOURCE_CONTEXTS_BEFORE" >"$EVIDENCE_DIR/source-contexts-before.txt"
PROTECTED_HASH_BEFORE="$(sha256sum "$SHARED_SOURCE/protected.txt" | awk '{print $1}')"
SINGLE_HASH_BEFORE="$(sha256sum "$SHARED_SOURCE/single.txt" | awk '{print $1}')"

say 'create directory and regular-file passthrough projections'
create_projection tree directory "$SHARED_SOURCE"
TREE_STATE="$LAST_PROJECTION_STATE"
TREE_MOUNT="$LAST_PROJECTION_MOUNT"
create_projection single file "$SHARED_SOURCE/single.txt"
FILE_STATE="$LAST_PROJECTION_STATE"
FILE_MOUNT="$LAST_PROJECTION_MOUNT"

findmnt -T "$TREE_MOUNT" -o TARGET,SOURCE,FSTYPE,OPTIONS >"$EVIDENCE_DIR/tree-projection-mount.txt"
findmnt -T "$FILE_MOUNT/item" -o TARGET,SOURCE,FSTYPE,OPTIONS >"$EVIDENCE_DIR/file-projection-mount.txt"
TREE_VIEW_CONTEXT="$(stat -Lc '%C' "$TREE_MOUNT/protected.txt")"
FILE_VIEW_CONTEXT="$(stat -Lc '%C' "$FILE_MOUNT/item")"
[ "$(ctx_type "$TREE_VIEW_CONTEXT")" = "$RO_TYPE" ] \
  || fail "tree projection has wrong SELinux type: $TREE_VIEW_CONTEXT"
[ "$(ctx_type "$FILE_VIEW_CONTEXT")" = "$RO_TYPE" ] \
  || fail "file projection has wrong SELinux type: $FILE_VIEW_CONTEXT"

say 'prove the projection and exact projected file are VFS-writable'
printf 'control\n' >"$TREE_MOUNT/vfs-control.txt"
grep -Fx control "$SHARED_SOURCE/vfs-control.txt" >/dev/null \
  || fail 'directory projection did not forward a control write'
rm "$TREE_MOUNT/vfs-control.txt"
printf 'control\n' >>"$FILE_MOUNT/item"
grep -Fx control "$SHARED_SOURCE/single.txt" >/dev/null \
  || fail 'file projection did not forward a control append'
printf 'single-seed\n' >"$SHARED_SOURCE/single.txt"
[ "$(sha256sum "$SHARED_SOURCE/single.txt" | awk '{print $1}')" = "$SINGLE_HASH_BEFORE" ] \
  || fail 'could not restore single-file control fixture'

docker pull "$IMAGE" >/dev/null
semodule -DB
DONTAUDIT_DISABLED=1
if command -v auditctl >/dev/null 2>&1; then
  auditctl -e 1 >/dev/null 2>&1 || true
fi
AUDIT_START_EPOCH="$(date +%s)"
AUDIT_START_AUSEARCH="$(date '+%m/%d/%Y %H:%M:%S')"

say 'start concurrent RO and RW Sessions over one backing tree'
docker run -d --name "$RO_CONTAINER" \
  --security-opt label=type:docker_helper_container_t \
  --mount "type=bind,source=$TREE_MOUNT,target=/m0/tree" \
  --mount "type=bind,source=$SHARED_SOURCE/output,target=/m0/tree/output" \
  --mount "type=bind,source=$FILE_MOUNT/item,target=/m0-single.txt" \
  "$IMAGE" sh -c 'sleep 300' >/dev/null
docker run -d --name "$RW_CONTAINER" \
  --security-opt label=type:docker_helper_container_t \
  --mount "type=bind,source=$SHARED_SOURCE,target=/m0/tree" \
  "$IMAGE" sh -c 'sleep 300' >/dev/null

docker inspect "$RO_CONTAINER" "$RW_CONTAINER" >"$EVIDENCE_DIR/containers-after-start.json"
docker ps -a --filter "name=^/${RO_CONTAINER}$" --filter "name=^/${RW_CONTAINER}$" \
  >"$EVIDENCE_DIR/containers-after-start.txt"
[ "$(docker inspect --format '{{.State.Running}}' "$RO_CONTAINER")" = true ] \
  || fail "RO Session exited after start: $(docker logs "$RO_CONTAINER" 2>&1 || true)"
[ "$(docker inspect --format '{{.State.Running}}' "$RW_CONTAINER")" = true ] \
  || fail "RW Session exited after start: $(docker logs "$RW_CONTAINER" 2>&1 || true)"
docker exec "$RO_CONTAINER" true
docker exec "$RW_CONTAINER" true

RO_PID="$(docker inspect --format '{{.State.Pid}}' "$RO_CONTAINER")"
RW_PID="$(docker inspect --format '{{.State.Pid}}' "$RW_CONTAINER")"
RO_PROCESS_CONTEXT="$(tr -d '\0' <"/proc/$RO_PID/attr/current")"
RW_PROCESS_CONTEXT="$(tr -d '\0' <"/proc/$RW_PID/attr/current")"
[ "$(ctx_type "$RO_PROCESS_CONTEXT")" = docker_helper_container_t ] \
  || fail "RO Session has wrong process type: $RO_PROCESS_CONTEXT"
[ "$(ctx_type "$RW_PROCESS_CONTEXT")" = docker_helper_container_t ] \
  || fail "RW Session has wrong process type: $RW_PROCESS_CONTEXT"
[ "$(ctx_range "$RO_PROCESS_CONTEXT")" != "$(ctx_range "$RW_PROCESS_CONTEXT")" ] \
  || fail 'concurrent Sessions received the same MCS range'

RO_ROOTFS_CONTEXT="$(stat -Lc '%C' "/proc/$RO_PID/root")"
RW_ROOTFS_CONTEXT="$(stat -Lc '%C' "/proc/$RW_PID/root")"
[ "$(ctx_type "$RO_ROOTFS_CONTEXT")" = container_file_t ] \
  || fail "RO Session rootfs has wrong type: $RO_ROOTFS_CONTEXT"
[ "$(ctx_type "$RW_ROOTFS_CONTEXT")" = container_file_t ] \
  || fail "RW Session rootfs has wrong type: $RW_ROOTFS_CONTEXT"
[ "$(ctx_range "$RO_ROOTFS_CONTEXT")" = "$(ctx_range "$RO_PROCESS_CONTEXT")" ] \
  || fail 'RO Session rootfs MCS range does not match its process'
[ "$(ctx_range "$RW_ROOTFS_CONTEXT")" = "$(ctx_range "$RW_PROCESS_CONTEXT")" ] \
  || fail 'RW Session rootfs MCS range does not match its process'

{
  printf 'RO_PROCESS_CONTEXT=%s\n' "$RO_PROCESS_CONTEXT"
  printf 'RW_PROCESS_CONTEXT=%s\n' "$RW_PROCESS_CONTEXT"
  printf 'RO_ROOTFS_CONTEXT=%s\n' "$RO_ROOTFS_CONTEXT"
  printf 'RW_ROOTFS_CONTEXT=%s\n' "$RW_ROOTFS_CONTEXT"
  printf 'TREE_VIEW_CONTEXT=%s\n' "$TREE_VIEW_CONTEXT"
  printf 'FILE_VIEW_CONTEXT=%s\n' "$FILE_VIEW_CONTEXT"
} >"$EVIDENCE_DIR/session-contexts.txt"

say 'prove nested RW survives inside the RO ancestor while RO writes fail'
docker exec "$RO_CONTAINER" sh -euc '
  grep -Fx protected-seed /m0/tree/protected.txt
  grep -Fx single-seed /m0-single.txt
  printf allowed > /m0/tree/output/from-ro-session.txt
  if printf denied >> /m0/tree/protected.txt 2>/dev/null; then exit 41; fi
  if touch /m0/tree/created.txt 2>/dev/null; then exit 42; fi
  if rm /m0/tree/protected.txt 2>/dev/null; then exit 43; fi
  if mv /m0/tree/protected.txt /m0/tree/renamed.txt 2>/dev/null; then exit 44; fi
  if printf denied >> /m0-single.txt 2>/dev/null; then exit 45; fi
  test -f /m0/tree/protected.txt
  test ! -e /m0/tree/created.txt
  test ! -e /m0/tree/renamed.txt
'

say 'prove the concurrent RW Session mutates the same backing tree'
docker exec "$RW_CONTAINER" sh -euc '
  printf session-b > /m0/tree/from-rw-session.txt
  grep -Fx allowed /m0/tree/output/from-ro-session.txt
'
docker exec "$RO_CONTAINER" grep -Fx session-b /m0/tree/from-rw-session.txt >/dev/null \
  || fail 'RO projection did not observe the concurrent RW Session change'
if docker exec "$RO_CONTAINER" rm /m0/tree/from-rw-session.txt 2>/dev/null; then
  fail 'RO Session removed a file created by the concurrent RW Session'
fi

[ -f "$SHARED_SOURCE/output/from-ro-session.txt" ] \
  || fail 'nested RW write did not reach the backing tree'
[ -f "$SHARED_SOURCE/from-rw-session.txt" ] \
  || fail 'concurrent RW Session write did not reach the backing tree'
[ "$(sha256sum "$SHARED_SOURCE/protected.txt" | awk '{print $1}')" = "$PROTECTED_HASH_BEFORE" ] \
  || fail 'protected source content changed'
[ "$(sha256sum "$SHARED_SOURCE/single.txt" | awk '{print $1}')" = "$SINGLE_HASH_BEFORE" ] \
  || fail 'single-file source content changed'
[ "$(ctx_type "$(stat -Lc '%C' "$TREE_MOUNT/from-rw-session.txt")")" = "$RO_TYPE" ] \
  || fail 'live backing-tree change did not retain the projection context'

SOURCE_CONTEXTS_AFTER="$(snapshot_source_contexts)"
printf '%s\n' "$SOURCE_CONTEXTS_AFTER" >"$EVIDENCE_DIR/source-contexts-after.txt"
[ "$SOURCE_CONTEXTS_AFTER" = "$SOURCE_CONTEXTS_BEFORE" ] \
  || fail 'per-Session access mode changed a backing object label or identity'

say 'require attributable SELinux AVC evidence'
collect_audit >"$EVIDENCE_DIR/audit-all.log"
grep -E 'avc:[[:space:]]+denied|type=AVC' "$EVIDENCE_DIR/audit-all.log" \
  | grep -E 'scontext=.*:docker_helper_container_t:' \
  | grep -E 'tcontext=.*:docker_helper_ro_projection_t:' \
  >"$EVIDENCE_DIR/projection-avc.log" || true
[ -s "$EVIDENCE_DIR/projection-avc.log" ] \
  || fail 'no attributable SELinux AVC for the read-only projection'
grep -Eq 'denied[[:space:]]+\{[^}]*(write|append)' "$EVIDENCE_DIR/projection-avc.log" \
  || fail 'no projection file-write AVC was captured'
grep -Eq 'denied[[:space:]]+\{[^}]*(add_name|create)' "$EVIDENCE_DIR/projection-avc.log" \
  || fail 'no projection create/add_name AVC was captured'
grep -Eq 'denied[[:space:]]+\{[^}]*(remove_name|unlink|rename)' "$EVIDENCE_DIR/projection-avc.log" \
  || fail 'no projection delete/rename AVC was captured'

docker rm -f "$RO_CONTAINER" "$RW_CONTAINER" >/dev/null
remove_projection "$FILE_STATE"
remove_projection "$TREE_STATE"
if [ -e "$FILE_STATE" ] || [ -e "$TREE_STATE" ]; then
  fail 'normal projection cleanup left state behind'
fi

say 'prove Docker create-failure cleanup ordering'
docker create --name "$COLLISION_CONTAINER" "$IMAGE" true >/dev/null
create_projection create-failure directory "$SHARED_SOURCE"
FAILURE_STATE="$LAST_PROJECTION_STATE"
FAILURE_MOUNT="$LAST_PROJECTION_MOUNT"
if docker create --name "$COLLISION_CONTAINER" \
  --security-opt label=type:docker_helper_container_t \
  --mount "type=bind,source=$FAILURE_MOUNT,target=/m0/tree" \
  "$IMAGE" true >/dev/null 2>&1; then
  fail 'intentional Docker create failure unexpectedly succeeded'
fi
remove_projection "$FAILURE_STATE"
if projection_is_mounted "$FAILURE_STATE" || [ -e "$FAILURE_STATE" ]; then
  fail 'create-failure projection cleanup left state behind'
fi
docker rm "$COLLISION_CONTAINER" >/dev/null

say 'prove startup reconciliation is ownership bounded'
create_projection stale directory "$SHARED_SOURCE"
STALE_STATE="$LAST_PROJECTION_STATE"
mount -t tmpfs -o size=1m tmpfs "$FOREIGN_MOUNT"
printf 'foreign\n' >"$FOREIGN_MOUNT/sentinel.txt"
reconcile_owned_projections
[ ! -e "$STALE_STATE" ] || fail 'owned stale projection survived reconciliation'
mountpoint -q "$FOREIGN_MOUNT" || fail 'reconciliation removed a foreign mount'
grep -Fx foreign "$FOREIGN_MOUNT/sentinel.txt" >/dev/null \
  || fail 'foreign mount sentinel changed during reconciliation'
umount "$FOREIGN_MOUNT"

semodule -B
DONTAUDIT_DISABLED=0
semodule -r "$MODULE_NAME"
MODULE_LOADED=0
if semodule -l | awk '{print $1}' | grep -Fxq "$MODULE_NAME"; then
  fail 'temporary projection policy module survived removal'
fi
if findmnt -rn | grep -F "$WORK_DIR" >/dev/null; then
  fail 'helper-owned mount residue remains'
fi
if docker ps -aq --filter "name=^/${RO_CONTAINER}$" --filter "name=^/${RW_CONTAINER}$" \
    --filter "name=^/${COLLISION_CONTAINER}$" | grep -q .; then
  fail 'container residue remains'
fi

{
  printf 'M0_S_RESULT=CLOSED\n'
  printf 'RUN_KEY=%s\n' "$RUN_KEY"
  printf 'MECHANISM=bindfs-passthrough-plus-SELinux-mount-context\n'
  printf 'IMAGE=%s\n' "$IMAGE"
  printf 'KERNEL=%s\n' "$(uname -r)"
  printf 'LSM=%s\n' "$LSM"
  printf 'SELINUX_ENFORCING=PASS\n'
  printf 'VFS_WRITABLE_CONTROL=PASS\n'
  printf 'MIXED_NESTED_RW_RO=PASS\n'
  printf 'REGULAR_FILE_RO=PASS\n'
  printf 'SHARED_TREE_CONCURRENCY=PASS\n'
  printf 'DISTINCT_MCS_AND_ROOTFS_MATCH=PASS\n'
  printf 'SOURCE_LABELS_UNCHANGED=PASS\n'
  printf 'MAC_ATTRIBUTABLE_DENIAL=PASS\n'
  printf 'CREATE_FAILURE_CLEANUP=PASS\n'
  printf 'OWNERSHIP_BOUNDED_RECONCILIATION=PASS\n'
  printf 'POLICY_MODULE_RESIDUE=NONE\n'
  printf 'MOUNT_RESIDUE=NONE\n'
  printf 'CONTAINER_RESIDUE=NONE\n'
} >"$EVIDENCE_DIR/summary.txt"

chmod -R a+rX "$EVIDENCE_DIR"
say 'M0-S CLOSED'
