#!/usr/bin/env bash
#
# uat-regression-h4-build-staging-bounds.sh — Release-2 targeted regression
# group 24: H4 build-context staging ceilings (Ubuntu / DEB / AppArmor).
#
# Pre-fix, one build request could drive the packaged system service into
# unbounded staging work on the runtime tmpfs: the full build context was
# copied into /run/docker-helper/builds before any ceiling existed — payload
# bytes, destination entries/inodes, directory depth and the daemon memory
# used while enumerating a very large directory were all unbounded, and the
# enumeration itself accumulated the whole []dirEntry before any per-entry
# decision.
#
# Post-fix contract proven here against the real packaged system service
# (mandatory MAC active; the finding is not MAC-specific), with the REAL
# production ceilings (128 MiB staged payload bytes, 50000 entries, depth 64):
#   * a sparse source file just over the byte ceiling is refused quickly
#     without filling /run (filesystem usage evidence before/after);
#   * a zero-file context over the entry ceiling is refused boundedly and
#     leaves no staging residue;
#   * a tree deeper than the depth ceiling is refused boundedly;
#   * for every refusal: the public error classification is the intended
#     limit refusal (HTTP 400 / code build_context_too_large via the real
#     CLI), the service stays active, the Unix API stays healthy, no Docker
#     build was started (audit build.start absent from the journal window),
#     no staging operation tree remains under the runtime builds directory,
#     and no stale MAC ownership/use state was added;
#   * a subsequent small valid build succeeds — and its build.start audit
#     event IS present, proving the absence checks above are meaningful.
#
# The byte case never allocates a ceiling-sized payload: the hostile fixture
# is a sparse file (logical size only), exactly like the daemon's reservation
# semantics it must refuse.
#
# Requires: installed docker-helper system service (active), Docker reachable,
# root, curl, journalctl, truncate, python3. Exits 0 = PASS, 1 = FAIL,
# 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "24. H4 build staging ceilings: bounded refusal, no residue"

reg_require_root
reg_require_service
reg_require_docker
reg_require_cmd curl "Unix /health probes"
reg_require_cmd journalctl "build.start absence / build.rejected evidence"
reg_require_cmd truncate "sparse hostile fixture"
reg_require_cmd python3 "hostile fixture generation"

# The REAL production ceilings (productionBuildStagingCeilings in
# staging_linux.go; documented in docs/architecture.md). A fixture must
# exceed the ceiling by the smallest meaningful amount, never allocate the
# ceiling-sized payload for real.
BYTE_CEILING=134217728      # 128 MiB staged payload bytes
ENTRY_CEILING=50000         # staged entries below the context root
DEPTH_CEILING=64            # context root = depth 0, direct child = depth 1

SOCK="/run/docker-helper/docker-helper.sock"
RUNTIME_DIR="/run/docker-helper"

USER="h4bounds"
home="$(reg_setup_principal "$USER")" || { reg_fail "setup principal failed"; reg_result; }
WS="$home/ws"
rm -rf "$WS"
mkdir -p "$WS"
chown -R "$USER:$USER" "$WS"

cred="/tmp/uat-h4.token"
reg_principal_credential "$USER" "$cred" || { reg_fail "credential create failed"; reg_result; }
reg_session "$cred" "$WS" || { reg_fail "session create failed"; reg_result; }
SESSION_TOKEN="$REG_SESSION_TOKEN"
export DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN"

# agent CLI over the system Unix API.
dh_build() { dh build "$@" 2>/tmp/h4-build.err; }

require_healthy_after_refusal() { # LABEL JOURNAL_MARK
  local label="$1" mark="$2" starts rejected journal
  if systemctl is-active --quiet docker-helper.service 2>/dev/null; then
    reg_ok "$label: service remains active"
  else
    reg_fail "$label: service is not active after the refusal"
  fi
  if curl --silent --fail --max-time 2 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1; then
    reg_ok "$label: Unix API remains healthy"
  else
    reg_fail "$label: GET /health over the Unix API failed after the refusal"
  fi
  journal="$(journalctl -u docker-helper.service --since "$mark" --no-pager 2>/dev/null || true)"
  starts="$(printf '%s\n' "$journal" | grep -c '"event":"build.start"' || true)"
  if [ "$starts" -eq 0 ]; then
    reg_ok "$label: no Docker build was started (no build.start audit event)"
  else
    reg_fail "$label: build.start audit event present ($starts) — a Docker build was started"
  fi
  rejected="$(printf '%s\n' "$journal" | grep -c '"result":"build_context_too_large"' || true)"
  if [ "$rejected" -ge 1 ]; then
    reg_ok "$label: build.rejected audit record carries the limit refusal code"
  else
    reg_fail "$label: no build.rejected record with build_context_too_large in the journal window"
  fi
  if [ "$(inventory_count "$RUNTIME_DIR/builds")" = "0" ]; then
    reg_ok "$label: no staging operation tree remains"
  else
    reg_fail "$label: staging residue remains under $RUNTIME_DIR/builds"
  fi
}

# mac_state_inventory prints the total entry count of the transient and
# durable workload-MAC roots (absent roots count 0). The refused builds must
# add nothing to either inventory; session binding state created before the
# baseline is never attributed to the refusals.
mac_state_inventory() {
  printf '%s\n' "$(( $(inventory_count "$RUNTIME_DIR/workload-mac") + $(inventory_count /var/lib/docker-helper/workload-mac) ))"
}

run_fs() { # df-like usage evidence of the filesystem backing the runtime dir
  df -k --output=used "$RUNTIME_DIR" 2>/dev/null | tail -1 | tr -d ' '
}
run_inodes() {
  df -i --output=iused "$RUNTIME_DIR" 2>/dev/null | tail -1 | tr -d ' '
}

# --- case 1: bytes — sparse payload just over the byte ceiling -----------------
mkdir -p "$WS/ctx-bytes"
printf 'FROM scratch\nCOPY big.bin /big.bin\n' > "$WS/ctx-bytes/Dockerfile"
truncate -s "$((BYTE_CEILING + 1))" "$WS/ctx-bytes/big.bin"
chown -R "$USER:$USER" "$WS/ctx-bytes"
reg_ok "bytes fixture: sparse source with st_size $((BYTE_CEILING + 1)) (never allocated for real)"

FS_USED_BEFORE="$(run_fs)"
INODES_BEFORE="$(run_inodes)"
MAC_BEFORE="$(mac_state_inventory)"
MARK="$(date '+%Y-%m-%d %H:%M:%S')"

if dh_build --context ctx-bytes --dockerfile Dockerfile --image uat-h4-bytes:2.2; then
  reg_fail "bytes case: the over-ceiling sparse payload must be refused"
else
  if grep -q 'status 400' /tmp/h4-build.err && grep -q 'code build_context_too_large' /tmp/h4-build.err; then
    reg_ok "bytes case: refused with the intended limit classification (400 / build_context_too_large)"
  else
    reg_fail "bytes case: unexpected refusal surface: $(head -2 /tmp/h4-build.err | redact)"
  fi
fi
require_healthy_after_refusal "bytes case" "$MARK"

FS_USED_AFTER="$(run_fs)"
FS_DELTA=$(( FS_USED_AFTER - FS_USED_BEFORE ))
if [ "$FS_DELTA" -lt 8192 ]; then
  reg_ok "bytes case: /run usage unchanged (${FS_USED_BEFORE}K -> ${FS_USED_AFTER}K, delta ${FS_DELTA}K) — refusal is preventative"
else
  reg_fail "bytes case: /run usage grew by ${FS_DELTA}K during the refusal"
fi
INODES_AFTER="$(run_inodes)"
INODES_DELTA=$(( INODES_AFTER - INODES_BEFORE ))
if [ "$INODES_DELTA" -lt 16 ]; then
  reg_ok "bytes case: /run inode usage unchanged (${INODES_BEFORE} -> ${INODES_AFTER})"
else
  reg_fail "bytes case: /run inode usage grew by ${INODES_DELTA} during the refusal"
fi
if [ "$(mac_state_inventory)" = "$MAC_BEFORE" ]; then
  reg_ok "bytes case: no MAC ownership/use state added"
else
  reg_fail "bytes case: workload-MAC inventories changed during the refusal"
fi

# --- case 2: entries — zero-file context over the entry ceiling ---------------
mkdir -p "$WS/ctx-entries"
printf 'FROM scratch\nCOPY f000000 /f000000\n' > "$WS/ctx-entries/Dockerfile"
python3 - "$WS/ctx-entries" "$ENTRY_CEILING" <<'PY' || { reg_fail "entries fixture generation failed"; reg_result; }
import os, sys
ctx, count = sys.argv[1], int(sys.argv[2])
for i in range(count):
    with open(os.path.join(ctx, "f%06d" % i), "wb") as f:
        pass
PY
chown -R "$USER:$USER" "$WS/ctx-entries"
reg_ok "entries fixture: Dockerfile + ${ENTRY_CEILING} zero-byte files (one entry over the ceiling)"

MAC_BEFORE="$(mac_state_inventory)"
MARK="$(date '+%Y-%m-%d %H:%M:%S')"

if dh_build --context ctx-entries --dockerfile Dockerfile --image uat-h4-entries:2.2; then
  reg_fail "entries case: the over-ceiling entry count must be refused"
else
  if grep -q 'status 400' /tmp/h4-build.err && grep -q 'code build_context_too_large' /tmp/h4-build.err; then
    reg_ok "entries case: refused with the intended limit classification (400 / build_context_too_large)"
  else
    reg_fail "entries case: unexpected refusal surface: $(head -2 /tmp/h4-build.err | redact)"
  fi
fi
require_healthy_after_refusal "entries case" "$MARK"

if [ "$(mac_state_inventory)" = "$MAC_BEFORE" ]; then
  reg_ok "entries case: no MAC ownership/use state added"
else
  reg_fail "entries case: workload-MAC inventories changed during the refusal"
fi

# --- case 3: depth — tree deeper than the depth ceiling -----------------------
mkdir -p "$WS/ctx-depth"
printf 'FROM scratch\n' > "$WS/ctx-depth/Dockerfile"
DEEP="$WS/ctx-depth"
for _ in $(seq 1 "$((DEPTH_CEILING + 1))"); do
  DEEP="$DEEP/d"
done
mkdir -p "$DEEP"
printf 'deep\n' > "$DEEP/leaf.txt"
chown -R "$USER:$USER" "$WS/ctx-depth"
reg_ok "depth fixture: chain $((DEPTH_CEILING + 1)) levels deep with a leaf file"

MAC_BEFORE="$(mac_state_inventory)"
MARK="$(date '+%Y-%m-%d %H:%M:%S')"

if dh_build --context ctx-depth --dockerfile Dockerfile --image uat-h4-depth:2.2; then
  reg_fail "depth case: the over-ceiling depth must be refused"
else
  if grep -q 'status 400' /tmp/h4-build.err && grep -q 'code build_context_too_large' /tmp/h4-build.err; then
    reg_ok "depth case: refused with the intended limit classification (400 / build_context_too_large)"
  else
    reg_fail "depth case: unexpected refusal surface: $(head -2 /tmp/h4-build.err | redact)"
  fi
fi
require_healthy_after_refusal "depth case" "$MARK"

if [ "$(mac_state_inventory)" = "$MAC_BEFORE" ]; then
  reg_ok "depth case: no MAC ownership/use state added"
else
  reg_fail "depth case: workload-MAC inventories changed during the refusal"
fi

# --- recovery: a subsequent small valid build succeeds ------------------------
mkdir -p "$WS/ctx-valid"
printf 'FROM scratch\nCOPY payload.txt /payload.txt\n' > "$WS/ctx-valid/Dockerfile"
printf 'h4-valid\n' > "$WS/ctx-valid/payload.txt"
chown -R "$USER:$USER" "$WS/ctx-valid"
MARK="$(date '+%Y-%m-%d %H:%M:%S')"

if dh_build --context ctx-valid --dockerfile Dockerfile --image uat-h4-valid:2.2; then
  reg_ok "a subsequent small valid build succeeds"
else
  reg_fail "the subsequent small valid build failed: $(head -3 /tmp/h4-build.err | redact)"
fi
# Positive control for the absence checks: an admitted build DOES emit
# build.start into the same journal channel.
if journalctl -u docker-helper.service --since "$MARK" --no-pager 2>/dev/null | grep -q '"event":"build.start"'; then
  reg_ok "the valid build emitted build.start (the build.start absence checks are meaningful)"
else
  reg_fail "the valid build did not emit build.start; the journal absence checks cannot be trusted"
fi

# --- cleanup: remove the bulky hostile fixtures -------------------------------
rm -rf "$WS/ctx-bytes" "$WS/ctx-entries" "$WS/ctx-depth"
rm -f /tmp/h4-build.err /tmp/uat-h4.token

reg_result
