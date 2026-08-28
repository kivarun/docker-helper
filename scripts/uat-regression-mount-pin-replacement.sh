#!/usr/bin/env bash
#
# uat-regression-mount-pin-replacement.sh — Release-2 targeted regression
# group 6: Mount-pin pathname replacement (Ubuntu / DEB / AppArmor).
#
# Sequence:
#   1. source pathname (ws/src/file) contains inode/content A;
#   2. start an active operation/container using it;
#   3. prove the container sees A;
#   4. host renames/replaces the pathname with a new inode/content B;
#   5. the active container continues seeing the old inode/content A (the mount
#      pin aliases the original inode, not the pathname);
#   6. a new helper operation using the same pathname sees B;
#   7. terminate both;
#   8. no stale mount-pin runtime state remains.
# device:inode is recorded where useful.
#
# Requires: installed docker-helper system service (active, system mode),
# Docker reachable, root. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "6. Mount-pin pathname replacement"

reg_require_root
reg_require_service
reg_require_docker

IMAGE="alpine:3.24"
USER="uatreg6"

home="$(reg_setup_principal "$USER")" || { reg_fail "setup principal failed"; reg_result; }
ws="$home/ws"; src="$ws/src"; ctl="$ws/ctl"
mkdir -p "$src" "$ctl"
printf 'CONTENT-A\n' > "$src/file"
chown -R "$USER:$USER" "$ws"

cred="/tmp/uat-reg6.token"
reg_principal_credential "$USER" "$cred" || { reg_fail "credential create failed"; reg_result; }
reg_session "$cred" "$ws" || { reg_fail "session create failed"; reg_result; }
stok="$REG_SESSION_TOKEN"

# device:inode of the original source inode (A).
INODE_A_DIR="$(stat -c '%d:%i' "$src")"
INODE_A_FILE="$(stat -c '%d:%i' "$src/file")"
reg_info "source dir inode A: $INODE_A_DIR  source file inode A: $INODE_A_FILE (content-A)"

# ---------------------------------------------------------------------------
# 1+2. start the active container reading the source through a mount pin
# ---------------------------------------------------------------------------
# Container 1: reports first read, waits for release1, then re-reads the mount
# (must still show A), reports via the control mount.
S1='cat /mnt/src/file > /mnt/ctl/phase1; echo started > /mnt/ctl/started1; while [ ! -f /mnt/ctl/release1 ]; do sleep 1; done; cat /mnt/src/file > /mnt/ctl/phase2; echo OP1-DONE'
RUN1="/tmp/uat-reg6-run1.log"
DOCKER_HELPER_SESSION_TOKEN="$stok" \
  dh run --image "$IMAGE" --mount src:/mnt/src --mount ctl:/mnt/ctl -- sh -ec "$S1" \
  >"$RUN1" 2>&1 &
RUN1_PID=$!

# ---------------------------------------------------------------------------
# 3. prove the container sees A (phase1) and record the pin inode
# ---------------------------------------------------------------------------
started=0
for _ in $(seq 1 90); do
  [ -f "$ctl/started1" ] && { started=1; break; }
  if ! kill -0 "$RUN1_PID" 2>/dev/null; then
    reg_fail "container 1 exited before readiness (log: $(cat "$RUN1" 2>/dev/null | redact))"
    reg_result
  fi
  sleep 1
done
[ "$started" = 1 ] || { reg_fail "container 1 did not report readiness in 90s"; reg_result; }

PHASE1="$(cat "$ctl/phase1" 2>/dev/null || true)"
if [ "$PHASE1" = "CONTENT-A" ]; then
  reg_ok "active container sees original content A (phase1='$PHASE1')"
else
  reg_fail "active container did not see content A (phase1='$PHASE1')"
fi

# Record the live mount-pin alias inode (single src pin among mounts/<op>/<n>).
PIN=""
for p in $(find /run/docker-helper/mounts -mindepth 2 -maxdepth 2 -type d 2>/dev/null | grep -E '/[0-9]+$' || true); do
  if mountpoint -q "$p" 2>/dev/null && [ "$(stat -c '%d:%i' "$p")" = "$INODE_A_DIR" ]; then
    PIN="$p"; break
  fi
done
if [ -n "$PIN" ]; then
  reg_ok "mount pin aliases source dir inode A (pin=$PIN dev:ino=$(stat -c '%d:%i' "$PIN"))"
else
  reg_fail "no mount pin aliasing source dir inode A found while container 1 is active"
fi

# ---------------------------------------------------------------------------
# 4. host replaces the pathname with a new inode/content B
# ---------------------------------------------------------------------------
mv "$src" "$src.old"
mkdir -p "$src"
printf 'CONTENT-B\n' > "$src/file"
chown -R "$USER:$USER" "$src"
INODE_B_DIR="$(stat -c '%d:%i' "$src")"
INODE_B_FILE="$(stat -c '%d:%i' "$src/file")"
reg_info "source dir inode B after replacement: $INODE_B_DIR  file inode B: $INODE_B_FILE (content-B)"
if [ "$INODE_A_DIR" = "$INODE_B_DIR" ]; then
  reg_fail "pathname replacement did not create a new inode (same dir dev:ino $INODE_B_DIR)"
fi

# ---------------------------------------------------------------------------
# 5. active container must still see A (pinned inode), not B
# ---------------------------------------------------------------------------
touch "$ctl/release1"
OP1_EC=0; wait "$RUN1_PID" 2>/dev/null; OP1_EC=$?
PHASE2="$(cat "$ctl/phase2" 2>/dev/null || true)"
if [ "$OP1_EC" -eq 0 ] && grep -q 'OP1-DONE' "$RUN1"; then
  reg_ok "container 1 completed normally"
else
  reg_fail "container 1 did not complete (rc=$OP1_EC, log: $(cat "$RUN1" 2>/dev/null | redact))"
fi
if [ "$PHASE2" = "CONTENT-A" ]; then
  reg_ok "active container continued seeing original inode A after host replacement (phase2='$PHASE2')"
else
  reg_fail "active container saw the replaced content (phase2='$PHASE2') — pin did not preserve the inode"
fi

# ---------------------------------------------------------------------------
# 6. new helper operation using the same pathname sees B
# ---------------------------------------------------------------------------
NEW_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$stok" \
  dh run --image "$IMAGE" --mount src:/mnt/src -- sh -ec 'cat /mnt/src/file' 2>/dev/null)"
if [ "$NEW_OUT" = "CONTENT-B" ]; then
  reg_ok "new helper operation sees replaced content B"
else
  reg_fail "new helper operation did not see B (got '$(printf '%s' "$NEW_OUT" | head -1)')"
fi

# ---------------------------------------------------------------------------
# 7+8. terminate both; no stale mount-pin runtime state remains
# ---------------------------------------------------------------------------
rm -rf "$src.old"
REMAINING="$(find /run/docker-helper/mounts -mindepth 2 -maxdepth 2 -type d 2>/dev/null | grep -E '/[0-9]+$' || true)"
if [ -z "$REMAINING" ]; then
  reg_ok "no stale mount-pin runtime state remains after both operations"
else
  reg_fail "stale mount pins remain: $REMAINING"
fi

# best-effort cleanup
dh principal delete --system "$USER" >/dev/null 2>&1 || true
userdel -r "$USER" >/dev/null 2>&1 || true
rm -f "$cred" "$RUN1"

reg_result
