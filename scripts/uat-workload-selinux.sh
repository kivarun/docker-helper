#!/usr/bin/env bash
#
# uat-workload-selinux.sh — Release 2.2 SELinux workload-MAC acceptance for
# the exact candidate RPM, running INSIDE the enforcing openSUSE Tumbleweed
# guest of the artifact gate (invoked by scripts/uat-vm-opensuse-selinux.sh;
# the host wrapper owns the VM construction, the guest transfer of the exact
# RPM + candidate manifest + host-compiled live harness, and the harness
# source binding).
#
# This is the ONE full SELinux workload-MAC acceptance matrix of the release
# gate (docs/release-2.2-mac-enforcement.md, SELinux acceptance matrix):
#   1  RW exposure is really writable through the prepared workload state;
#   2  RO exposure is readable;
#   3  RO exposure is immutable (the write is denied, host file unchanged);
#   4  mixed RW + RO exposures work independently in ONE workload;
#   5  a writable parent spanning a nested RO region is refused with the
#      stable read_only_root code BEFORE any MAC/container state exists;
#   6  the backend-only forced-writable RO case is denied by SELinux ITSELF
#      (not the VFS): the host-compiled live harness drives the production
#      bindfs/projection backend from the same source SHA the candidate was
#      built from over a deliberately VFS-writable projection, and the
#      matching docker_helper_ro_projection_t AVC is independently verified;
#   7  the workload stays in docker_helper_container_t and Docker-owned MCS
#      confinement is preserved (distinct per-container categories);
#   8  two concurrent Sessions use one host tree with different issued
#      snapshots without interference;
#   9  a regular-file RO exposure works (read ok, write denied);
#  10  the bindfs projection backend is really used on the packaged RPM path
#      (fuse.bindfs projection observed during a live RO exposure, and the
#      run.start audit records workload_mac_backend=selinux);
#  11  the backing source is not broad/recurrently relabeled (contexts
#      unchanged across the whole scenario, no global/Principal/Launcher
#      root relabel);
#  12  generated workload state is cleaned after success AND failure, and
#      restart/reconciliation leaves no stale helper-owned state;
#  13  the bounded audit window carries the attributable
#      docker_helper_ro_projection_t write AVC and no unexpected
#      docker_helper AVC outside the expected negative subcases.
#
# Fail-closed contract: PASS -> continue; FAIL -> gate red; BLOCKED -> a
# required dependency/evidence is unavailable -> gate red. Missing AVC or
# projection evidence is never counted as success.
# Exit status: 0 = all PASS, 1 = any FAIL, 2 = any BLOCKED (and none FAIL).
#
# Env inputs (guest paths):
#   UAT_VERSION        candidate version string (required)
#   UAT_RPM            guest path of the exact candidate RPM (required)
#   UAT_RPM_SHA256     expected SHA-256 of the candidate RPM (required)
#   UAT_PROOF_BIN      guest path of the host-compiled live harness (required)
#   UAT_SOURCE_SHA     the gate source SHA bound into candidate.manifest (required)
#   UAT_MANIFEST       guest path of candidate.manifest (required)
#   UAT_ALLOWED_ROOT   global allowed root (default /opt)
#   UAT_PRINCIPAL      OS user mapped to the principal (default opc)
#   UAT_EVIDENCE_DIR   guest evidence dir for the harness (default /tmp/uat-wls-evidence)
#
# Requires: root, enforcing SELinux, systemd, Docker, bindfs + /dev/fuse,
# policy module docker_helper loaded, ausearch (audit). Exits as above.

set -uo pipefail

VERSION="${UAT_VERSION:-2.2.0-uat}"
ALLOWED_ROOT="${UAT_ALLOWED_ROOT:-/opt}"
PRINCIPAL="${UAT_PRINCIPAL:-opc}"
RPM_PATH_IN="${UAT_RPM:-}"
RPM_SHA256_IN="${UAT_RPM_SHA256:-}"
PROOF_BIN_IN="${UAT_PROOF_BIN:-}"
SOURCE_SHA_IN="${UAT_SOURCE_SHA:-}"
MANIFEST_IN="${UAT_MANIFEST:-}"
EVIDENCE_DIR="${UAT_EVIDENCE_DIR:-/tmp/uat-wls-evidence}"

PREFIX="[uat-workload-selinux]"
say()  { printf '\n%s %s\n' "$PREFIX" "$*"; }
info() { printf '%s %s\n' "$PREFIX" "$*"; }

redact() {
  sed -E \
    -e 's/dht_[A-Za-z0-9_-]+/<redacted-token>/g' \
    -e 's/dhc_[A-Za-z0-9_-]+/<redacted-token>/g'
}

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
[ -n "$RPM_PATH_IN" ] && [ -f "$RPM_PATH_IN" ] || { echo "error: UAT_RPM must be an existing file: $RPM_PATH_IN" >&2; exit 1; }
[ -n "$RPM_SHA256_IN" ] || { echo "error: UAT_RPM_SHA256 is required" >&2; exit 1; }
ACTUAL_SHA="$(sha256sum "$RPM_PATH_IN" | awk '{print $1}')"
[ "$ACTUAL_SHA" = "$RPM_SHA256_IN" ] || {
  echo "error: candidate RPM SHA-256 mismatch (expected $RPM_SHA256_IN, got $ACTUAL_SHA)" >&2
  exit 1
}
[ -n "$PROOF_BIN_IN" ] && [ -x "$PROOF_BIN_IN" ] || { echo "error: UAT_PROOF_BIN must be an executable file: $PROOF_BIN_IN" >&2; exit 1; }
[ -n "$SOURCE_SHA_IN" ] || { echo "error: UAT_SOURCE_SHA is required" >&2; exit 1; }
[ -n "$MANIFEST_IN" ] && [ -f "$MANIFEST_IN" ] || { echo "error: UAT_MANIFEST must be an existing file: $MANIFEST_IN" >&2; exit 1; }
MANIFEST_SOURCE_SHA="$(sed -n 's/^source_sha=//p' "$MANIFEST_IN" | head -1)"
[ "$MANIFEST_SOURCE_SHA" = "$SOURCE_SHA_IN" ] || {
  echo "error: candidate.manifest source_sha mismatch (expected $SOURCE_SHA_IN, got ${MANIFEST_SOURCE_SHA:-absent})" >&2
  exit 1
}

FAIL_COUNT=0
BLOCKED_COUNT=0
acc_ok() { printf '  ok:      %s\n' "$*"; }
acc_fail() { printf '  FAIL:    %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
acc_blocked() { printf '  BLOCKED: %s\n' "$*" >&2; BLOCKED_COUNT=$((BLOCKED_COUNT + 1)); }
scenario() { say "scenario $1"; }

dh() { /usr/bin/docker-helper "$@"; }
SOCK="/run/docker-helper/docker-helper.sock"

json_field() { grep -oP "\"$1\": \"\K[^\"]+" | head -1; }

wait_health() {
  local _i=0
  for _i in $(seq 1 100); do
    curl --silent --fail --max-time 1 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1 && return 0
    if ! systemctl is-active --quiet docker-helper.service 2>/dev/null; then
      return 1
    fi
    sleep 0.2
  done
  return 1
}

helper_container_count() {
  docker ps -a --filter 'label=com.dockerhelper.schema=1' -q | wc -l
}

wait_no_helper_containers() {
  local _i=0
  for _i in $(seq 1 40); do
    [ "$(helper_container_count)" = "0" ] && return 0
    sleep 0.25
  done
  return 1
}

residue_state() {
  printf 'containers=%s pins=%s wlmac=%s\n' \
    "$(helper_container_count)" \
    "$(ls /run/docker-helper/mounts 2>/dev/null | wc -l)" \
    "$(ls /run/docker-helper/workload-mac 2>/dev/null | wc -l)"
}

residue_unchanged() {
  local base="$1" now
  now="$(residue_state)"
  [ "$now" = "$base" ] || { printf '  residue drift: before %s after %s\n' "$base" "$now" >&2; return 1; }
}

workload_residue_clean() {
  [ "$(ls /run/docker-helper/workload-mac 2>/dev/null | wc -l)" = "0" ] \
    && [ "$(ls /var/lib/docker-helper/workload-mac 2>/dev/null | wc -l)" = "0" ]
}

create_session() {
  local cred="$1" ws="$2" out id
  out="$(dh session create --system --token-file "$cred" --workspace "$ws" --json 2>/dev/null || true)"
  id="$(printf '%s' "$out" | json_field id)"
  [ -n "$id" ] || return 1
  printf '%s' "$out" | json_field token > "/tmp/uat-wls-tok-$id"; chmod 600 "/tmp/uat-wls-tok-$id"
  printf '%s' "$id"
}

expect_read_only_root() {
  local token="$1" source="$2" target="$3" snippet="$4" base="$5" out ec
  out="$(DOCKER_HELPER_SESSION_TOKEN="$token" \
    dh run --image alpine:3.24 --mount "$source:$target" -- sh -ec "$snippet" 2>&1)"
  ec=$?
  [ "$ec" -ne 0 ] || { printf '  writable request on %s unexpectedly succeeded\n' "$source" >&2; return 1; }
  printf '%s\n' "$out" | grep -q 'read_only_root' \
    || { printf '  refusal for %s is not read_only_root: %s\n' "$source" "$(printf '%s\n' "$out" | redact)" >&2; return 1; }
  residue_unchanged "$base"
}

# tree_context_snapshot prints the SELinux contexts of the acceptance tree so
# before/after equality is the no-relabel evidence.
tree_context_snapshot() {
  find "$TREE" -exec stat -c '%n %C' {} \; 2>/dev/null | sort
}

# wait_bindfs_projection PID — waits bounded while the background RO run with
# the given PID is in flight, for the packaged bindfs projection mount under
# the workload MAC runtime root. Prints the first observed projection
# evidence line ("<mountpoint> <context>") or nothing.
wait_bindfs_projection() {
  local bgpid="$1" _i=0 mp ctx
  for _i in $(seq 1 120); do
    mp="$(grep 'fuse.bindfs' /proc/mounts 2>/dev/null \
      | grep '/run/docker-helper/workload-mac/' | awk '{print $2}' | head -1 || true)"
    if [ -n "$mp" ] && [ -d "$mp" ]; then
      ctx="$(stat -c '%C' "$mp" 2>/dev/null | cut -d: -f3 || true)"
      printf '%s %s\n' "$mp" "$ctx"
      return 0
    fi
    if ! kill -0 "$bgpid" 2>/dev/null; then
      return 1
    fi
    sleep 0.25
  done
  return 1
}

cleanup() {
  systemctl stop docker-helper.service >/dev/null 2>&1 || true
  systemctl disable docker-helper.service >/dev/null 2>&1 || true
  rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper "$EVIDENCE_DIR"
}
trap cleanup EXIT

# ==============================================================================
# setup: enforcing SELinux, exact candidate RPM, confined system service
# ==============================================================================
say "setup: enforcing SELinux + exact candidate RPM + confined system service"
if [ "$(getenforce 2>/dev/null || true)" != "Enforcing" ]; then
  echo "error: SELinux is not enforcing (got: $(getenforce 2>/dev/null || true))" >&2
  exit 1
fi
acc_ok "SELinux enforcing"

if semodule -l 2>/dev/null | awk '$1 == "docker_helper" { found=1 } END { exit !found }' \
    && seinfo -t docker_helper_container_t 2>/dev/null | grep -q docker_helper_container_t \
    && seinfo -t docker_helper_ro_projection_t 2>/dev/null | grep -q docker_helper_ro_projection_t; then
  acc_ok "packaged docker_helper policy module loaded (container + ro_projection types)"
else
  echo "error: docker_helper policy module/types not loaded" >&2
  exit 1
fi

# Deterministic clean slate: the previous guest stage can leave the service
# active, failed, or in an auto-restart backoff, and a swallowed erase makes
# the candidate install hit "already installed". Stop, reset, erase, and
# prove the erase happened before installing.
systemctl stop docker-helper.service >/dev/null 2>&1 || true
systemctl reset-failed docker-helper.service >/dev/null 2>&1 || true
if rpm -q docker-helper >/dev/null 2>&1; then
  rpm -e docker-helper >/tmp/uat-wls-erase.log 2>&1 || true
  if rpm -q docker-helper >/dev/null 2>&1; then
    echo "error: candidate erase failed, package still installed: $(redact </tmp/uat-wls-erase.log | tail -3)" >&2
    exit 1
  fi
fi
rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper
if rpm -i "$RPM_PATH_IN" >/tmp/uat-wls-install.log 2>&1 \
    && [ "$(docker-helper version)" = "$VERSION" ] \
    && rpm -q docker-helper 2>/dev/null | grep -q "docker-helper-$VERSION"; then
  acc_ok "exact candidate RPM installed (sha256 verified: $ACTUAL_SHA)"
else
  echo "error: candidate RPM install/version check failed: $(redact </tmp/uat-wls-install.log | tail -3)" >&2
  exit 1
fi

if dh init --allowed-root "$ALLOWED_ROOT" >/tmp/uat-wls-init.log 2>&1; then
  acc_ok "system init (global ceiling: $ALLOWED_ROOT)"
else
  printf '  init output: %s\n' "$(redact </tmp/uat-wls-init.log)" >&2
  echo "error: docker-helper init failed" >&2
  exit 1
fi
systemctl daemon-reload || { echo "error: daemon-reload failed" >&2; exit 1; }
systemctl enable --now docker-helper.service >/dev/null 2>&1 \
  || { echo "error: enable --now failed" >&2; exit 1; }
for _ in $(seq 1 30); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
systemctl is-active --quiet docker-helper.service || { echo "error: service not active" >&2; exit 1; }
DH_PID="$(systemctl show -p MainPID --value docker-helper.service)"
DH_LABEL="$(tr -d '\0' < "/proc/$DH_PID/attr/current" 2>/dev/null || true)"
case "$DH_LABEL" in
  docker_helper_t:*) acc_ok "candidate daemon confined (docker_helper_t)" ;;
  *) echo "error: daemon process label is not docker_helper_t: '$DH_LABEL'" >&2; exit 1 ;;
esac
wait_health || { echo "error: API socket not ready" >&2; exit 1; }
ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
[ -n "$ADMIN_TOKEN" ] || { echo "error: could not read the admin token" >&2; exit 1; }

docker pull alpine:3.24 >/dev/null 2>&1 || true
docker pull alpine:3.19 >/dev/null 2>&1 || true

# ---- fixture: policy tree with one RO region ---------------------------------
TREE="$ALLOWED_ROOT/uat-wl-tree"
rm -rf "$TREE"
mkdir -p "$TREE/project" "$TREE/pipeline-inputs"
printf 'project-file\n' > "$TREE/project/keep.txt"
printf 'ro-input\n' > "$TREE/pipeline-inputs/input.txt"
chown -R "$PRINCIPAL:$PRINCIPAL" "$TREE"
chmod -R u+rwX,go+rX "$TREE"
TREE_CTX_BEFORE="$(tree_context_snapshot)"

dh principal create --system --no-credential "$PRINCIPAL" >/dev/null 2>&1 || true
dh principal set --system "$PRINCIPAL" enabled true >/dev/null 2>&1 || true
dh principal allowed-root add --system "$PRINCIPAL" "$TREE" >/dev/null 2>&1 || true
dh principal allowed-root add --system --access read_only "$PRINCIPAL" "$TREE/pipeline-inputs" >/dev/null 2>&1 || true
MAIN_L_JSON="$(dh launcher create --system --principal "$PRINCIPAL" --name main --no-credential 2>/dev/null || true)"
MAIN_L_ID="$(printf '%s' "$MAIN_L_JSON" | json_field id)"
[ -n "$MAIN_L_ID" ] || { echo "error: launcher create failed: $MAIN_L_JSON" >&2; exit 1; }
MAIN_LC_OUT="$(dh launcher credential create --system --principal "$PRINCIPAL" "$MAIN_L_ID" 2>/dev/null || true)"
MAIN_LC_TOKEN="$(printf '%s' "$MAIN_LC_OUT" | json_field token)"
[ -n "$MAIN_LC_TOKEN" ] || { echo "error: launcher credential create failed" >&2; exit 1; }
printf '%s\n' "$MAIN_LC_TOKEN" > /tmp/uat-wls-cred-main; chmod 600 /tmp/uat-wls-cred-main
WSA_ID="$(create_session /tmp/uat-wls-cred-main "$TREE")" \
  || { echo "error: acceptance session creation failed" >&2; exit 1; }
WSA_TOKEN="$(cat "/tmp/uat-wls-tok-$WSA_ID")"
acc_ok "acceptance session $WSA_ID with mixed policy tree"

# The audit window starts now.
AUDIT_START_EPOCH="$(date +%s)"

# ==============================================================================
# scenario S1: RW exposure is really writable
# ==============================================================================
say "S1: RW exposure really writable"
if DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
    dh run --image alpine:3.24 --mount project:/mnt/project -- \
    sh -ec 'echo s1-write > /mnt/project/written.txt && cat /mnt/project/keep.txt' >/tmp/uat-wls-s1.log 2>&1 \
    && [ "$(cat "$TREE/project/written.txt" 2>/dev/null)" = "s1-write" ]; then
  acc_ok "S1 RW exposure mounted writable and the write persisted"
else
  acc_fail "S1 RW exposure write failed: $(redact </tmp/uat-wls-s1.log | tail -3)"
fi

# ==============================================================================
# scenario S2: RO exposure is readable
# ==============================================================================
say "S2: RO exposure readable"
S2_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --image alpine:3.24 --mount pipeline-inputs:/mnt/inputs:ro -- \
  sh -ec 'test "$(cat /mnt/inputs/input.txt)" = "ro-input" && echo S2-RO-READ-OK' 2>&1)"
if printf '%s\n' "$S2_OUT" | grep -q 'S2-RO-READ-OK'; then
  acc_ok "S2 RO exposure readable (bindfs projection path)"
else
  acc_fail "S2 RO read failed: $(printf '%s\n' "$S2_OUT" | redact | tail -3)"
fi

# ==============================================================================
# scenario S3: RO exposure is immutable
# ==============================================================================
say "S3: RO exposure immutable"
DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --image alpine:3.24 --mount pipeline-inputs:/mnt/inputs:ro -- \
  sh -ec 'echo forbidden > /mnt/inputs/forbidden.txt' >/dev/null 2>&1
S3_EC=$?
if [ "$S3_EC" -ne 0 ] && [ ! -e "$TREE/pipeline-inputs/forbidden.txt" ]; then
  acc_ok "S3 RO write denied and the host file was not created"
else
  acc_fail "S3 RO exposure immutability broken (ec=$S3_EC)"
fi

# ==============================================================================
# scenario S4: mixed RW + RO exposures work independently in one workload
# ==============================================================================
say "S4: mixed RW + RO in one workload"
S4_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --image alpine:3.24 --mount project:/mnt/project --mount pipeline-inputs:/mnt/inputs:ro -- \
  sh -ec 'echo s4-write > /mnt/project/written.txt; test "$(cat /mnt/inputs/input.txt)" = "ro-input" || exit 3; if echo x > /mnt/inputs/forbidden.txt 2>/dev/null; then exit 4; fi; echo S4-MIXED-OK' 2>&1)"
S4_EC=$?
if [ "$S4_EC" -eq 0 ] && printf '%s\n' "$S4_OUT" | grep -q 'S4-MIXED-OK' \
    && [ "$(cat "$TREE/project/written.txt" 2>/dev/null)" = "s4-write" ] \
    && [ ! -e "$TREE/pipeline-inputs/forbidden.txt" ]; then
  acc_ok "S4 mixed RW+RO exposures independent in one workload"
else
  acc_fail "S4 mixed workload failed (ec=$S4_EC): $(printf '%s\n' "$S4_OUT" | redact | tail -3)"
fi

# ==============================================================================
# scenario S5: writable parent over nested RO refused before workload creation
# ==============================================================================
say "S5: writable parent over nested RO refused before workload creation"
S5_BASE="$(residue_state)"
if expect_read_only_root "$WSA_TOKEN" . /mnt/tree 'echo x > /mnt/tree/pipeline-inputs/x.txt' "$S5_BASE"; then
  acc_ok "S5 writable parent refused with read_only_root before MAC/container creation"
else
  acc_fail "S5 writable parent refusal wrong (base: $S5_BASE)"
fi

# ==============================================================================
# scenario S7: bindfs projection really used on the packaged RPM path
# ==============================================================================
say "S7: bindfs projection used on the packaged RPM path"
dh run --image alpine:3.24 --mount pipeline-inputs:/mnt/inputs:ro -- \
  sh -ec 'sleep 12; cat /mnt/inputs/input.txt' >/tmp/uat-wls-s7.log 2>&1 &
BG_PID=$!
PROJ_EVIDENCE="$(wait_bindfs_projection "$BG_PID" || true)"
wait "$BG_PID" || true
if [ -n "$PROJ_EVIDENCE" ]; then
  info "S7 projection observed during the live RO exposure: $PROJ_EVIDENCE"
  if printf '%s\n' "$PROJ_EVIDENCE" | grep -q 'docker_helper_ro_projection_t'; then
    acc_ok "S7 live fuse.bindfs projection with docker_helper_ro_projection_t observed"
  else
    acc_fail "S7 projection context wrong: $PROJ_EVIDENCE"
  fi
else
  acc_fail "S7 no bindfs projection observed during the live RO exposure"
fi
if journalctl --utc -u docker-helper.service --since "@${AUDIT_START_EPOCH}" --no-pager 2>/dev/null \
    | grep '"event":"run.start"' | grep -q '"workload_mac_backend":"selinux"'; then
  acc_ok "S7 run.start audit records workload_mac_backend=selinux"
else
  acc_fail "S7 run.start audit does not record the SELinux workload backend"
fi

# ==============================================================================
# scenario S6: workload stays docker_helper_container_t with distinct MCS
# ==============================================================================
say "S6: docker_helper_container_t + Docker-owned MCS"
S6_L1="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --image alpine:3.24 --mount project:/mnt/project -- /bin/cat /proc/self/attr/current 2>/dev/null || true)"
S6_L2="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --image alpine:3.24 --mount pipeline-inputs:/mnt/inputs:ro -- /bin/cat /proc/self/attr/current 2>/dev/null || true)"
case "$S6_L1" in docker_helper_container_t:*) ;; *)
  acc_fail "S6 RW workload process label wrong: '$S6_L1'" ;;
esac
case "$S6_L2" in docker_helper_container_t:*) ;; *)
  acc_fail "S6 RO workload process label wrong: '$S6_L2'" ;;
esac
if [ "$S6_L1" != "$S6_L2" ]; then
  acc_ok "S6 both workloads run as docker_helper_container_t with distinct Docker MCS labels"
else
  acc_fail "S6 Docker-owned MCS categories did not differ: '$S6_L1'"
fi

# ==============================================================================
# scenario S8: two concurrent Sessions share one host tree (different snapshots)
# ==============================================================================
say "S8: two concurrent Sessions on one host tree"
WSB_ID="$(create_session /tmp/uat-wls-cred-main "$TREE/project")" \
  || { echo "error: second acceptance session creation failed" >&2; exit 1; }
WSB_TOKEN="$(cat "/tmp/uat-wls-tok-$WSB_ID")"
rm -f "$TREE/project/a-file" "$TREE/project/b-file"
DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --image alpine:3.24 --mount project:/mnt/p -- \
  sh -ec 'echo session-A > /mnt/p/a-file; sleep 5; cat /mnt/p/a-file' >/tmp/uat-wls-s8a.log 2>&1 &
S8A_PID=$!
DOCKER_HELPER_SESSION_TOKEN="$WSB_TOKEN" \
  dh run --image alpine:3.24 --mount .:/mnt/self -- \
  sh -ec 'echo session-B > /mnt/self/b-file; sleep 5; cat /mnt/self/b-file' >/tmp/uat-wls-s8b.log 2>&1 &
S8B_PID=$!
S8A_OK=0; S8B_OK=0
wait "$S8A_PID" && S8A_OK=1 || true
wait "$S8B_PID" && S8B_OK=1 || true
if [ "$S8A_OK" = 1 ] && [ "$S8B_OK" = 1 ] \
    && [ "$(cat "$TREE/project/a-file" 2>/dev/null)" = "session-A" ] \
    && [ "$(cat "$TREE/project/b-file" 2>/dev/null)" = "session-B" ]; then
  acc_ok "S8 concurrent Sessions with different issued snapshots shared the tree (A=$WSA_ID B=$WSB_ID)"
else
  acc_fail "S8 concurrent session use failed (A=$S8A_OK B=$S8B_OK: $(redact </tmp/uat-wls-s8a.log | tail -2) / $(redact </tmp/uat-wls-s8b.log | tail -2))"
fi

# ==============================================================================
# scenario S9: regular-file RO exposure
# ==============================================================================
say "S9: regular-file RO exposure"
S9_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --image alpine:3.24 --mount pipeline-inputs/input.txt:/mnt/file:ro -- \
  sh -ec 'test "$(cat /mnt/file)" = "ro-input" || exit 3; if echo x > /mnt/file 2>/dev/null; then exit 4; fi; echo S9-FILE-OK' 2>&1)"
S9_EC=$?
if [ "$S9_EC" -eq 0 ] && printf '%s\n' "$S9_OUT" | grep -q 'S9-FILE-OK' \
    && [ "$(cat "$TREE/pipeline-inputs/input.txt" 2>/dev/null)" = "ro-input" ]; then
  acc_ok "S9 regular-file RO exposure read works and the write is denied"
else
  acc_fail "S9 regular-file RO exposure failed (ec=$S9_EC): $(printf '%s\n' "$S9_OUT" | redact | tail -3)"
fi

# ==============================================================================
# scenario S11: no broad/recurrent relabel of the acceptance tree
# ==============================================================================
say "S11: no relabel of the backing source"
if [ "$(tree_context_snapshot)" = "$TREE_CTX_BEFORE" ]; then
  acc_ok "S11 acceptance tree contexts unchanged after all scenarios (no broad relabel)"
else
  acc_fail "S11 acceptance tree contexts changed (relabel detected)"
fi

# ==============================================================================
# scenario S12: cleanup after success/failure + restart/reconciliation
# ==============================================================================
say "S12: cleanup after success and failure, restart/reconciliation"
wait_no_helper_containers || acc_fail "S12 helper containers remain after the scenarios"
if workload_residue_clean; then
  acc_ok "S12 no generated workload state remains after the positive scenarios"
else
  acc_fail "S12 workload residue after the positive scenarios"
fi
DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --image alpine:3.24 --mount project:/mnt/project -- sh -ec 'exit 9' >/dev/null 2>&1
S12_FAIL_EC=$?
[ "$S12_FAIL_EC" -ne 0 ] \
  && acc_ok "S12 failing workload propagates the container failure (ec=$S12_FAIL_EC)" \
  || acc_fail "S12 failing workload unexpectedly succeeded"
wait_no_helper_containers || acc_fail "S12 helper containers remain after the failing run"
if workload_residue_clean; then
  acc_ok "S12 no generated workload state remains after the failing run"
else
  acc_fail "S12 workload residue after the failing run"
fi
systemctl restart docker-helper.service >/dev/null 2>&1 || true
for _ in $(seq 1 30); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
DH_PID2="$(systemctl show -p MainPID --value docker-helper.service)"
DH_LABEL2="$(tr -d '\0' < "/proc/$DH_PID2/attr/current" 2>/dev/null || true)"
if wait_health && case "$DH_LABEL2" in docker_helper_t:*) true ;; *) false ;; esac \
    && workload_residue_clean; then
  acc_ok "S12 restart/reconciliation: daemon confined again, no stale workload state"
else
  acc_fail "S12 restart left confinement or workload residue broken"
fi

# ==============================================================================
# scenario S13: harness proof + bounded audit window evidence
# ==============================================================================
say "S13: forced-writable RO denied by SELinux (harness) + audit evidence"
mkdir -p "$EVIDENCE_DIR"
if DOCKER_HELPER_LIVE_WORKLOAD_PROOF=1 WORKLOAD_EVIDENCE_DIR="$EVIDENCE_DIR" \
    "$PROOF_BIN_IN" -test.run 'TestLiveWorkloadSELinux|TestLiveWorkloadSELinuxRegularFile|TestLiveWorkloadMCSConcurrentRWRO' -test.v \
    >/tmp/uat-wls-harness.log 2>&1; then
  acc_ok "S13 live harness passed: bindfs projection denies the would-be-RO write (VFS view writable), regular-file RO proven, MCS concurrency proven"
else
  acc_fail "S13 live harness failed: $(tail -10 /tmp/uat-wls-harness.log 2>/dev/null | redact)"
fi

# Required independent evidence: a fresh AVC attributable to the projection
# type. ausearch is bounded to the window; fall back to the raw audit log
# when ausearch yields nothing.
AVC_START_DATE="$(date -d "@$AUDIT_START_EPOCH" '+%m/%d/%Y %H:%M:%S' 2>/dev/null || true)"
AVC_WINDOW="$(ausearch -m AVC -ts "$AVC_START_DATE" 2>/dev/null || true)"
if [ -z "$AVC_WINDOW" ] && [ -f /var/log/audit/audit.log ]; then
  AVC_WINDOW="$(awk -v start="$AUDIT_START_EPOCH" '
    match($0, /audit\(([0-9]+)\./, m) { if (m[1] + 0 >= start + 0) print }
  ' /var/log/audit/audit.log 2>/dev/null || true)"
fi
RO_AVC="$(printf '%s\n' "$AVC_WINDOW" | grep 'avc:  denied' \
  | grep 'docker_helper_ro_projection_t' | grep 'tclass=dir' | head -1 || true)"
if [ -n "$RO_AVC" ]; then
  acc_ok "S13 attributable projection-type AVC present: $RO_AVC"
else
  acc_blocked "S13 no attributable docker_helper_ro_projection_t AVC in the window (independent MAC denial evidence impossible)"
fi

# No unexpected AVCs in the docker-helper policy scope: any denied AVC whose
# source context involves docker_helper_* must be the expected projection
# write denials.
UNEXPECTED=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  printf '%s\n' "$line" | grep -q 'scontext.*docker_helper' || continue
  if printf '%s\n' "$line" | grep -q 'docker_helper_ro_projection_t' \
      && printf '%s\n' "$line" | grep -Eq 'tclass=(dir|file)' \
      && printf '%s\n' "$line" | grep -q 'perm=write'; then
    info "expected projection write denial: $line"
  else
    printf '  UNEXPECTED AVC: %s\n' "$line" >&2
    UNEXPECTED=$((UNEXPECTED + 1))
  fi
done <<< "$AVC_WINDOW"
if [ "$UNEXPECTED" -eq 0 ]; then
  acc_ok "S13 no unexpected docker_helper AVC outside the expected negative subcases"
else
  acc_fail "S13 unexpected docker_helper AVCs in the window: $UNEXPECTED"
fi

# ==============================================================================
# summary
# ==============================================================================
echo
echo "========= RELEASE 2.2 SELINUX WORKLOAD-MAC UAT SUMMARY (Tumbleweed/RPM) ========="
printf '  FAILS:    %d\n' "$FAIL_COUNT"
printf '  BLOCKED:  %d\n' "$BLOCKED_COUNT"
echo "================================================================================="

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "RESULT: at least one mandatory SELinux workload-MAC scenario FAILED" >&2
  exit 1
fi
if [ "$BLOCKED_COUNT" -gt 0 ]; then
  echo "RESULT: at least one mandatory workload-MAC scenario BLOCKED (required evidence not exercised)" >&2
  exit 2
fi
echo "RESULT: Release 2.2 SELinux workload-MAC UAT PASSED"
