#!/usr/bin/env bash
#
# uat-regression-workspace-escape.sh — Release-2 targeted regression group 5:
# Workspace escape pack (Ubuntu / DEB / AppArmor).
#
# Exercises public docker-helper behavior:
#   * ../outside (relative workspace escape)            -> reject
#   * absolute outside (mount source / session)        -> reject where applicable
#   * symlink inside -> outside (workspace + mount)    -> reject
#   * symlink inside -> inside (mount)                 -> accept
#   * build-context escapes (../outside, symlink out)  -> reject
# Rejected cases must not leak or mutate the outside path (marker preserved).
#
# Requires: installed docker-helper system service (active), Docker reachable,
# root. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "5. Workspace escape pack"

reg_require_root
reg_require_service
reg_require_docker

IMAGE="alpine:3.24"
USER="uatreg5"
OUTSIDE="/tmp/uatreg5-outside"

home="$(reg_setup_principal "$USER")" || { reg_fail "setup principal failed"; reg_result; }
ws="$home/ws"; mkdir -p "$ws"
chown -R "$USER:$USER" "$home"

cred="/tmp/uat-reg5.token"
reg_principal_credential "$USER" "$cred" || { reg_fail "credential create failed"; reg_result; }
reg_session "$cred" "$ws" || { reg_fail "session create failed"; reg_result; }
stok="$REG_SESSION_TOKEN"

# Outside-path marker proving rejected cases never leak or mutate the target.
mkdir -p "$OUTSIDE"
printf 'outside-marker\n' > "$OUTSIDE/marker.txt"
MARKER_BEFORE="$(cat "$OUTSIDE/marker.txt")"

# expect_reject: returns 0 if the given command exits non-zero, printing the
# command and rc as evidence (bounded).
expect_reject() {
  local desc="$1"; shift
  if "$@" >/tmp/reg5-out.log 2>&1; then
    reg_fail "$desc: expected rejection but command succeeded"
  else
    reg_ok "$desc (rejected, rc=$?)"
  fi
}

# --- ../outside (relative escape) via mount source ---------------------------
expect_reject "mount source ../outside" \
  env DOCKER_HELPER_SESSION_TOKEN="$stok" \
  dh run --image "$IMAGE" --mount ../outside:/mnt/x -- sh -ec 'true'

# --- absolute outside via mount source (rejected at the CLI) -----------------
expect_reject "absolute mount source" \
  env DOCKER_HELPER_SESSION_TOKEN="$stok" \
  dh run --image "$IMAGE" --mount "$OUTSIDE:/mnt/x" -- sh -ec 'true'

# --- absolute outside as session workspace -----------------------------------
expect_reject "session workspace absolute outside allowed root" \
  dh session create --system --token-file "$cred" --workspace "$OUTSIDE/ws" --json

# --- symlink inside -> outside ------------------------------------------------
ln -s "$OUTSIDE" "$ws/escape"
expect_reject "session workspace via symlink to outside" \
  dh session create --system --token-file "$cred" --workspace "$ws/escape" --json
expect_reject "mount source via symlink to outside" \
  env DOCKER_HELPER_SESSION_TOKEN="$stok" \
  dh run --image "$IMAGE" --mount escape:/mnt/x -- sh -ec 'true'

# --- symlink inside -> inside (accept) ----------------------------------------
mkdir -p "$ws/real"
printf 'inside\n' > "$ws/real/f.txt"
chown -R "$USER:$USER" "$ws/real"
ln -s "$ws/real" "$ws/link"
if DOCKER_HELPER_SESSION_TOKEN="$stok" \
    dh run --image "$IMAGE" --mount link:/mnt/link -- sh -ec 'cat /mnt/link/f.txt && echo SYMLINK-INSIDE-OK' \
    | grep -q 'SYMLINK-INSIDE-OK'; then
  reg_ok "mount source via symlink to inside workspace accepted"
else
  reg_fail "mount source via symlink to inside workspace was rejected"
fi

# --- build-context escapes -----------------------------------------------------
expect_reject "build context ../outside" \
  env DOCKER_HELPER_SESSION_TOKEN="$stok" \
  dh build --context ../outside --dockerfile Dockerfile --image reg5-esc:1
expect_reject "build context via symlink to outside" \
  env DOCKER_HELPER_SESSION_TOKEN="$stok" \
  dh build --context escape --dockerfile Dockerfile --image reg5-esc:2
expect_reject "build dockerfile escaping context" \
  env DOCKER_HELPER_SESSION_TOKEN="$stok" \
  dh build --context real --dockerfile ../../outside/Dockerfile --image reg5-esc:3

# --- rejected cases must not leak/mutate the outside path ----------------------
MARKER_AFTER="$(cat "$OUTSIDE/marker.txt" 2>/dev/null || true)"
if [ "$MARKER_AFTER" = "$MARKER_BEFORE" ] && [ -z "$(find "$OUTSIDE" -maxdepth 1 -newer "$OUTSIDE/marker.txt" -name '*.new' 2>/dev/null)" ]; then
  reg_ok "outside path untouched after all rejected escape attempts"
else
  reg_fail "outside path was leaked/mutated by a rejected escape attempt"
fi

# --- best-effort cleanup --------------------------------------------------------
rm -f "$ws/escape" "$ws/link"
dh principal delete --system "$USER" >/dev/null 2>&1 || true
userdel -r "$USER" >/dev/null 2>&1 || true
rm -f "$cred"
rm -rf "$OUTSIDE"

reg_result
