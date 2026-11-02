#!/usr/bin/env bash
# D1 SELinux UAT, corrected for 2026-11-02 host-integrity incident:
# internal relative symlinks are preserved, but escaping symlinks are rejected
# before Docker/BuildKit, with no host relabel or staging residue.
# This is a breaking correction of the previous D1 external-symlink contract.
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "10. D1 staging allows internal symlinks and refuses escapes"

reg_require_root
reg_require_service
reg_require_docker
reg_require_cmd curl "Unix /health probes"
reg_require_cmd journalctl "build.start audit evidence"

if [ "$(getenforce 2>/dev/null || true)" != "Enforcing" ]; then
  reg_blocked "SELinux is not enforcing"
fi

SOCK="/run/docker-helper/docker-helper.sock"
RUNTIME_DIR="/run/docker-helper"
IMAGE_BASE="alpine:3.24"

USER="d1symlink"
home="$(reg_setup_principal "$USER")" || { reg_fail "setup principal failed"; reg_result; }
WS="$home/ws"
rm -rf "$WS"
mkdir -p "$WS"
chown -R "$USER:$USER" "$WS"

cred="/tmp/uat-d1.token"
reg_principal_credential "$USER" "$cred" || { reg_fail "credential create failed"; reg_result; }
reg_session "$cred" "$WS" || { reg_fail "session create failed"; reg_result; }
export DOCKER_HELPER_SESSION_TOKEN="$REG_SESSION_TOKEN"

dh_build() { dh build "$@" 2>/tmp/d1-build.err; }
# --- audit window helpers (same source-selection pattern as uat-mac-selinux.sh:
# ausearch when it yields records, else dmesg, else journalctl -k; the window
# is applied locally from the record's audit(epoch) timestamp, so a shared
# kernel ring buffer is never double-counted) ---------------------------------

audit_ts() { sed -n 's/.*audit(\([0-9][0-9]*\)\.[0-9]*:[0-9]*).*/\1/p' | head -1; }

audit_records_since() { # START_EPOCH
  local epoch="$1" raw ausearch_out line ts
  if command -v ausearch >/dev/null 2>&1; then
    ausearch_out="$(ausearch -m AVC,USER_AVC --start recent </dev/null 2>/dev/null | grep 'avc:' || true)"
    if [ -n "$ausearch_out" ]; then
      printf '%s\n' "$ausearch_out" | while IFS= read -r line; do
        ts="$(printf '%s\n' "$line" | audit_ts)"
        if [ -n "$ts" ] && [ "$ts" -ge "$epoch" ]; then
          printf '%s\n' "$line"
        fi
      done | sort -u
      return 0
    fi
  fi
  raw="$(dmesg 2>/dev/null || true)"
  if [ -z "$raw" ]; then
    raw="$(journalctl -k --since "@$epoch" --no-pager 2>/dev/null || true)"
  fi
  printf '%s\n' "$raw" | grep 'avc:' | while IFS= read -r line; do
    ts="$(printf '%s\n' "$line" | audit_ts)"
    if [ -n "$ts" ] && [ "$ts" -ge "$epoch" ]; then
      printf '%s\n' "$line"
    fi
  done | sort -u
}

# fresh_d1_denials EPOCH prints fresh AVC denials relevant to the D1 staging
# subject in the window starting at EPOCH. The scope is the daemon's own
# domain (scontext type docker_helper_t — the pre-fix denials were exactly
# lnk_file getattr/setattr from comm="docker-helper", and restorecon runs
# WITHIN docker_helper_t via execute_no_trans, so its denials stay covered).
# Denials of OTHER domains merely plumbing data to the daemon
# (setfiles_t/load_policy_t writing the pipe the daemon passed them) are the
# pre-existing MAC-preparation pattern of earlier groups, not D1 staging.
fresh_d1_denials() { # START_EPOCH
  audit_records_since "$1" | grep 'denied' \
    | grep -E 'scontext=[^:]+:[^:]+:docker_helper_t' | grep -F 'docker_helper_'
}

require_healthy_after_build() { # LABEL START_EPOCH MARK
  local label="$1" epoch="$2" mark="$3" denies starts journal
  if systemctl is-active --quiet docker-helper.service 2>/dev/null; then
    reg_ok "$label: service remains active"
  else
    reg_fail "$label: service is not active after the build"
  fi
  if curl --silent --fail --max-time 2 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1; then
    reg_ok "$label: Unix API remains healthy"
  else
    reg_fail "$label: GET /health over the Unix API failed after the build"
  fi
  journal="$(journalctl -u docker-helper.service --since "$mark" --no-pager 2>/dev/null || true)"
  starts="$(printf '%s\n' "$journal" | grep -c '"event":"build.start"' || true)"
  if [ "$starts" -ge 1 ]; then
    reg_ok "$label: build.start audit event present (staging completed, BuildKit started)"
  else
    reg_fail "$label: no build.start audit event; BuildKit never started"
  fi
  denies="$(fresh_d1_denials "$epoch")"
  if [ -z "$denies" ]; then
    reg_ok "$label: no fresh docker_helper_t AVC denial (the D1 getattr/setattr denials are gone)"
  else
    printf '%s\n' "$denies" >&2
    reg_fail "$label: fresh docker_helper_t AVC denial(s) in the case window"
  fi
  if [ "$(inventory_count "$RUNTIME_DIR/builds")" = "0" ]; then
    reg_ok "$label: no staging residue under $RUNTIME_DIR/builds"
  else
    reg_fail "$label: staging residue remains under $RUNTIME_DIR/builds"
  fi
}

run_image_expects() { # IMAGE EXPECT_SUBSTRING LABEL [CONTAINER_PATH]
  local image="$1" expect="$2" label="$3" path="${4:-/payload.txt}" out
  if out="$(dh run "$image" -- cat "$path" 2>/tmp/d1-run.err)"; then
    if printf '%s' "$out" | grep -qF "$expect"; then
      reg_ok "$label: produced image runs and serves the staged payload"
    else
      reg_fail "$label: image output missing expected payload (got: $(printf '%s' "$out" | head -1 | redact))"
    fi
  else
    reg_fail "$label: produced image failed to run: $(head -2 /tmp/d1-run.err | redact)"
  fi
}

# Escaping symlinks must never reach BuildKit: the vulnerable Docker fsutil
# DiskWriter applies source xattrs through setxattr, following the link target.
build_starts() {
  journalctl -u docker-helper.service --no-pager 2>/dev/null |
    grep -c '"event":"build.start"' || true
}
expect_escape_rejected() { # LABEL CTXDIR IMAGE
  local label="$1" ctx="$2" image="$3" before after
  before="$(build_starts)"
  if dh_build "$ctx" --dockerfile Dockerfile --image "$image"; then
    reg_fail "$label: unsafe context unexpectedly built successfully"
  elif grep -q 'invalid_build_context' /tmp/d1-build.err; then
    reg_ok "$label: typed pre-Docker symlink escape refusal"
  else
    reg_fail "$label: unexpected error (expected invalid_build_context): $(head -3 /tmp/d1-build.err | redact)"
  fi
  after="$(build_starts)"
  if [ "$before" = "$after" ]; then
    reg_ok "$label: no build.start (Docker/BuildKit never invoked)"
  else
    reg_fail "$label: build.start observed for a refused context ($before -> $after)"
  fi
  if curl --silent --fail --max-time 2 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1; then
    reg_ok "$label: API remains healthy"
  else
    reg_fail "$label: API unhealthy"
  fi
  if [ "$(inventory_count "$RUNTIME_DIR/builds")" = "0" ]; then
    reg_ok "$label: no staging residue"
  else
    reg_fail "$label: staging residue"
  fi
}

# --- case fixture builder ------------------------------------------------------
# make_case NAME creates $WS/<name>/ctx with a context-local payload and a
# workspace-owned Dockerfile. Symlink-specific content is added by the caller.
make_case() { # NAME
  local name="$1"
  local ctx="$WS/$name/ctx"
  mkdir -p "$ctx"
  printf 'd1-payload\n' > "$ctx/payload.txt"
  printf 'FROM %s\nCOPY payload.txt /payload.txt\n' "$IMAGE_BASE" > "$ctx/Dockerfile"
}

# --- case 1: internal same-directory symlink (link -> target.txt) --------------
make_case case1
printf 'same-dir payload\n' > "$WS/case1/ctx/target.txt"
ln -s target.txt "$WS/case1/ctx/link"
chown -R "$USER:$USER" "$WS/case1"

# The semantic proof: COPY the internal link into the image, then read the
# link's resolved content through the produced image. This proves the staged
# symlink is the context entry BuildKit consumed (preserved link text).
mkdir -p "$WS/case1/ctx-linkcopy"
printf 'same-dir payload\n' > "$WS/case1/ctx-linkcopy/target.txt"
ln -s target.txt "$WS/case1/ctx-linkcopy/link"
printf 'FROM %s\nCOPY link /out.txt\n' "$IMAGE_BASE" \
  > "$WS/case1/ctx-linkcopy/Dockerfile"
chown -R "$USER:$USER" "$WS/case1"

EPOCH="$(date +%s)"
MARK="$(date '+%Y-%m-%d %H:%M:%S')"
if dh_build case1/ctx --dockerfile Dockerfile --image uat-d1-1:2.2; then
  reg_ok "case 1: build accepted and succeeded (internal same-directory symlink)"
else
  reg_fail "case 1: build failed: $(head -3 /tmp/d1-build.err | redact)"
fi
require_healthy_after_build "case 1" "$EPOCH" "$MARK"
run_image_expects uat-d1-1:2.2 "d1-payload" "case 1"

if dh_build case1/ctx-linkcopy --dockerfile Dockerfile --image uat-d1-1-copy:2.2; then
  reg_ok "case 1: link-copy build succeeded"
else
  reg_fail "case 1: link-copy build failed: $(head -3 /tmp/d1-build.err | redact)"
fi
run_image_expects uat-d1-1-copy:2.2 "same-dir payload" "case 1 link-copy" /out.txt

# --- case 2: internal relative symlink across a directory (dir/link -> ../target.txt)
make_case case2
printf 'nested payload\n' > "$WS/case2/ctx/target.txt"
mkdir -p "$WS/case2/ctx/subdir"
ln -s ../target.txt "$WS/case2/ctx/subdir/link"
chown -R "$USER:$USER" "$WS/case2"

EPOCH="$(date +%s)"
MARK="$(date '+%Y-%m-%d %H:%M:%S')"
if dh_build case2/ctx --dockerfile Dockerfile --image uat-d1-2:2.2; then
  reg_ok "case 2: build accepted and succeeded (internal relative symlink across a directory)"
else
  reg_fail "case 2: build failed: $(head -3 /tmp/d1-build.err | redact)"
fi
require_healthy_after_build "case 2" "$EPOCH" "$MARK"
run_image_expects uat-d1-2:2.2 "d1-payload" "case 2"

# --- case 3: absolute external symlink, rejected before Docker ------------
make_case case3
OUTSIDE_ABS="$WS/outside-abs"
mkdir -p "$OUTSIDE_ABS"
printf 'host payload\n' > "$OUTSIDE_ABS/host.txt"
ln -s "$OUTSIDE_ABS" "$WS/case3/ctx/link"
chown -R "$USER:$USER" "$WS/case3" "$OUTSIDE_ABS"
expect_escape_rejected "case 3 absolute external" case3/ctx uat-d1-3:2.3

# --- case 4: relative target escapes the context (within workspace) --------
make_case case4
printf 'workspace payload\n' > "$WS/outside-file"
ln -s ../outside-file "$WS/case4/ctx/link"
chown -R "$USER:$USER" "$WS/case4" "$WS/outside-file"
expect_escape_rejected "case 4 relative external" case4/ctx uat-d1-4:2.3

# --- case 4b: direct host /etc and /etc/passwd targets, label integrity ----
ETC_BEFORE="$(stat -c '%d:%i %C' /etc)"
PASSWD_BEFORE="$(stat -c '%d:%i %C' /etc/passwd)"
make_case case4-etc
ln -s /etc "$WS/case4-etc/ctx/link"
make_case case4-passwd
ln -s /etc/passwd "$WS/case4-passwd/ctx/link"
chown -R "$USER:$USER" "$WS/case4-etc" "$WS/case4-passwd"
expect_escape_rejected "host etc" case4-etc/ctx uat-d1-etc:2.3
expect_escape_rejected "host passwd" case4-passwd/ctx uat-d1-passwd:2.3
if [ "$(stat -c '%d:%i %C' /etc)" = "$ETC_BEFORE" ] &&
   [ "$(stat -c '%d:%i %C' /etc/passwd)" = "$PASSWD_BEFORE" ]; then
  reg_ok "host /etc and passwd inode+SELinux contexts unchanged"
else
  reg_fail "host /etc or passwd inode/SELinux context was mutated"
fi

# --- case 4c: lexical-safe but symlink-chain escape -------------------------
make_case case4-chain
mkdir -p "$WS/case4-chain/ctx/a"
ln -s .. "$WS/case4-chain/ctx/a/up"
ln -s a/up/../../outside "$WS/case4-chain/ctx/chain"
chown -R "$USER:$USER" "$WS/case4-chain"
expect_escape_rejected "case 4c: symlink chain with later dotdot" case4-chain/ctx uat-d1-chain:2.3

# --- case 5: symlink-free control ----------------------------------------------
make_case case5
chown -R "$USER:$USER" "$WS/case5"

EPOCH="$(date +%s)"
MARK="$(date '+%Y-%m-%d %H:%M:%S')"
if dh_build case5/ctx --dockerfile Dockerfile --image uat-d1-5:2.2; then
  reg_ok "case 5: control build accepted and succeeded (symlink-free context)"
else
  reg_fail "case 5: control build failed: $(head -3 /tmp/d1-build.err | redact)"
fi
require_healthy_after_build "case 5" "$EPOCH" "$MARK"
run_image_expects uat-d1-5:2.2 "d1-payload" "case 5"

# --- cleanup --------------------------------------------------------------------
rm -rf "$WS"
rm -f /tmp/d1-build.err /tmp/d1-run.err /tmp/uat-d1.token

reg_result
