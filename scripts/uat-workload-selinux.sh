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
#      built from over a deliberately VFS-writable projection — including
#      the external-source chain (real external root → production
#      mount-pin owner → RO projection owner) — and the matching
#      docker_helper_ro_projection_t AVC is independently verified;
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
#   UAT_PRINCIPAL      OS user mapped to the principal (default opc)
#   UAT_EVIDENCE_DIR   guest evidence dir for the harness (default /tmp/uat-wls-evidence)
#
# Requires: root, enforcing SELinux, systemd, Docker, bindfs + /dev/fuse,
# policy module docker_helper loaded, ausearch (audit). Exits as above.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Shared measurement primitives (fail-closed residue inventory) come from the
# canonical lib owner; the script's own helpers below win.
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

VERSION="${UAT_VERSION:-2.2.0-uat}"
# RPM version field uses "~" for the UAT suffix ("-" separates version from
# release), so the rpm record check must match the transformed string. Bash
# tilde-expands a bare "~" replacement in ${var//pat/rep} ($HOME), so the
# transform goes through tr.
RPM_VERSION="$(printf '%s' "$VERSION" | tr '-' '~')"
# The one global ceiling of this guest matrix: the principal's home must sit
# under it (2.2 principal-home contract), so the acceptance tree, the
# workspace, and the SE external-root launcher all carry this root.
ALLOWED_ROOT="/home/opc"
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

# Fail-closed residue inventory: the three-state ABSENT/PRESENT/UNKNOWN
# contract is owned by the shared primitives in uat-regression-lib.sh
# (helper_container_count, wait_no_helper_containers, inventory_count).
# "Cannot inspect" is never "clean".

residue_state() {
  local containers pins wlmac
  containers="$(helper_container_count)" || return 1
  pins="$(inventory_count /run/docker-helper/mounts)" || return 1
  wlmac="$(inventory_count /run/docker-helper/workload-mac)" || return 1
  printf 'containers=%s pins=%s wlmac=%s\n' "$containers" "$pins" "$wlmac"
}

residue_unchanged() {
  local base="$1" now
  now="$(residue_state)" || { printf '  residue inventory unavailable for the drift check\n' >&2; return 1; }
  [ "$now" = "$base" ] || { printf '  residue drift: before %s after %s\n' "$base" "$now" >&2; return 1; }
}

# workload_residue_clean asserts no transient/durable workload-MAC state
# remains. Exit status: 0 = clean, 1 = residue, 2 = inventory unavailable
# (never clean).
workload_residue_clean() {
  local runtime durable
  runtime="$(inventory_count /run/docker-helper/workload-mac)" || return 2
  durable="$(inventory_count /var/lib/docker-helper/workload-mac)" || return 2
  [ "$runtime" = "0" ] && [ "$durable" = "0" ]
}

create_session() {
  local cred="$1" ws="$2" out id
  out="$(dh session create --system --token-file "$cred" --workspace "$ws" --json 2>&1 || true)"
  id="$(printf '%s' "$out" | json_field id)"
  [ -n "$id" ] || { echo "session create failed for $ws: $(printf '%s' "$out" | redact | tail -2)" >&2; return 1; }
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
  # The live workspace region is relabeled to docker_helper_workspace_t while
  # its Sessions exist (the designed workspace label, restored on delete);
  # the no-broad-relabel invariant therefore compares only the region
  # outside the workspace.
  find "$TREE" -path "$TREE/work" -prune -o -exec stat -c '%n %C' {} \; 2>/dev/null | sort
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
# candidate_installed_ok verifies the FULL packaged install state: binary
# version, rpm record, and the loaded policy module. A scriptlet that fails
# late (e.g. a systemd daemon-reload/restart race) leaves a partially valid
# state that this verifier does not silently accept.
candidate_installed_ok() {
  [ "$(docker-helper version)" = "$VERSION" ] \
    && rpm -q docker-helper 2>/dev/null | grep -q "docker-helper-$RPM_VERSION" \
    && semodule -l 2>/dev/null | awk '$1 == "docker_helper" { found=1 } END { exit !found }'
}
# verifier_member_results reports each member's boolean state at the moment
# it is called (runs 7-9 showed the members passing in the evidence dump
# seconds AFTER the verifier had already failed, which cannot distinguish a
# flaky member from a verifier-context defect).
verifier_member_results() {
  local raw qrc prc rpm_out
  raw="$(docker-helper version 2>/dev/null || true)"
  rpm_out="$(rpm -q docker-helper 2>/dev/null || true)"
  rpm -q docker-helper >/dev/null 2>&1
  qrc=$?
  rpm -q docker-helper 2>/dev/null | grep -q "docker-helper-$RPM_VERSION"
  prc=$?
  printf '  verifier members now: version=%s rpm-record=%s(rpmrc=%s) policy-module=%s raw=[%s] piperc=%s\n' \
    "$([ "$raw" = "$VERSION" ] && echo yes || echo NO)" \
    "$(rpm -q docker-helper 2>/dev/null | grep -q "docker-helper-$RPM_VERSION" && echo yes || echo NO)" \
    "$qrc" \
    "$(semodule -l 2>/dev/null | awk '$1 == "docker_helper" { found=1 } END { exit !found }' && echo yes || echo NO)" \
    "$raw" \
    "$prc"
  printf '  verifier rpm detail: RPM_VERSION=[%s] rpm-out=[%s]\n' "$RPM_VERSION" "$rpm_out"
}
# wls_install_evidence dumps the complete bounded failure context for a
# candidate install that did not verify: the FULL non-trivial scriptlet log,
# each candidate_installed_ok member separately, the unit state, leftover
# containers from earlier guest stages, and the systemd journal window. A
# tail fragment of one error line is not enough to separate a scriptlet
# defect from a systemd-state artifact of the preceding guest stage.
wls_install_evidence() {
  echo "  --- install log (full, non-trivial) ---" >&2
  grep -v '^[[:space:]]*$' /tmp/uat-wls-install.log 2>/dev/null | redact | tail -30 >&2 || true
  echo "  --- erase log (tail) ---" >&2
  redact </tmp/uat-wls-erase.log 2>/dev/null | tail -5 >&2 || true
  echo "  --- verifier members: version / rpm -q / semodule ---" >&2
  echo "  version: $(docker-helper version 2>&1 || true)" >&2
  echo "  rpm -q: $(rpm -q docker-helper 2>&1 || true)" >&2
  echo "  semodule: $(semodule -l 2>&1 | grep -w docker_helper || echo '(module not listed)')" >&2
  echo "  --- unit state ---" >&2
  systemctl status docker-helper.service --no-pager 2>&1 | head -15 >&2 || true
  echo "  --- leftover containers ---" >&2
  docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null | tail -5 >&2 || true
  echo "  --- guest journal window (transient/scope/job/docker-helper) ---" >&2
  journalctl --since '-5 min' --no-pager 2>/dev/null \
    | grep -iE 'docker-helper|transient|scope|failed to start|Bad message' \
    | tail -40 | redact >&2 || true
}
if rpm -i "$RPM_PATH_IN" >/tmp/uat-wls-install.log 2>&1 && candidate_installed_ok; then
  acc_ok "exact candidate RPM installed (sha256 verified: $ACTUAL_SHA)"
else
  wls_install_evidence
  echo "  install attempt 1 evidence above" >&2
  # One bounded settle + retry for the known-flaky category: after heavy
  # package churn a systemd job-queue race can surface inside the RPM
  # scriptlet ("Failed to start transient service unit"). A healthy system
  # still installs on the retry; a persistent failure keeps the gate red.
  systemctl daemon-reload >/dev/null 2>&1 || true
  for _ in $(seq 1 15); do
    state="$(systemctl is-system-running 2>/dev/null || true)"
    case "$state" in running|degraded) break ;; esac
    sleep 1
  done
  if ! candidate_installed_ok; then
    verifier_member_results >&2
    rpm -e docker-helper >/dev/null 2>&1 || true
    rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper
    rpm -i "$RPM_PATH_IN" >/tmp/uat-wls-install.log 2>&1 || true
  fi
  # Bounded re-verification: the members' read-only checks (version, rpm
  # record, semodule listing) can transiently fail while the just-finished
  # postinst's policy store commit is still settling; run 7's evidence showed
  # every member passing moments after the verifier reported failure. A
  # stable pass is accepted; a genuinely broken install keeps failing all
  # attempts and the gate stays red.
  candidate_verified=""
  for _ in 1 2 3; do
    if candidate_installed_ok; then
      candidate_verified=yes
      break
    fi
    verifier_member_results >&2
    sleep 2
  done
  if [ -n "$candidate_verified" ]; then
    acc_ok "exact candidate RPM installed (sha256 verified: $ACTUAL_SHA; transient systemd scriptlet hiccup recovered)"
  else
    echo "error: candidate RPM install/version check failed after settle + retry:" >&2
    wls_install_evidence
    echo "error: systemd state: $(systemctl is-system-running 2>&1 || true)" >&2
    exit 1
  fi
fi

# The principal's home must sit under the global allowed root (2.2 contract),
# so this acceptance tree lives under /home/opc. Non-home fcontext lifecycle
# remains owned by the targeted SELinux regression groups.
if dh init --allowed-root "$ALLOWED_ROOT" >/tmp/uat-wls-init.log 2>&1; then
  acc_ok "system init (global ceiling: $ALLOWED_ROOT)"
  dh config allowed-root list 2>/dev/null | sed 's/^/  config-roots: /' >&2 || true
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
  *:docker_helper_t:*) acc_ok "candidate daemon confined (docker_helper_t)" ;;
  docker_helper_t:*) acc_ok "candidate daemon confined (docker_helper_t)" ;;
  *) echo "error: daemon process label is not docker_helper_t: '$DH_LABEL'" >&2; exit 1 ;;
esac
wait_health || { echo "error: API socket not ready" >&2; exit 1; }
ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
[ -n "$ADMIN_TOKEN" ] || { echo "error: could not read the admin token" >&2; exit 1; }

docker pull alpine:3.24 >/dev/null 2>&1 || true
docker pull alpine:3.19 >/dev/null 2>&1 || true

# ---- fixture: policy tree with one RO region ---------------------------------
# One global ceiling (dh init takes a single --allowed-root): it must contain
# the principal's home (2.2 principal-home contract), so the tree lives under
# /home/opc. Non-home fcontext lifecycle stays with the targeted regressions.
TREE="/home/opc/uat-wl-tree"
rm -rf "$TREE"
mkdir -p "$TREE/work" "$TREE/work/project" "$TREE/work/pipeline-inputs"
printf 'project-file\n' > "$TREE/work/project/keep.txt"
printf 'ro-input\n' > "$TREE/work/pipeline-inputs/input.txt"
chown -R "$PRINCIPAL:$PRINCIPAL" "$TREE"
chmod -R u+rwX,go+rX "$TREE"
TREE_CTX_BEFORE="$(tree_context_snapshot)"
# Fail-closed inventory contract: the no-relabel baseline must be a
# positively observed context snapshot; an unavailable context inventory
# (stat/find failure) collapses before and after to equal empties and must
# never read as "unchanged".
if [ -z "$TREE_CTX_BEFORE" ]; then
  echo "error: acceptance-tree context inventory is empty (stat/find failed); S11 no-relabel evidence is unavailable" >&2
  exit 2
fi

dh principal create --system --no-credential "$PRINCIPAL" 2>/tmp/uat-wls-setup.err || {
  echo "error: principal create failed: $(redact </tmp/uat-wls-setup.err | tail -3)" >&2; exit 1; }
dh principal set --system "$PRINCIPAL" enabled true 2>>/tmp/uat-wls-setup.err || true
dh principal allowed-root add --system "$PRINCIPAL" "$TREE" 2>>/tmp/uat-wls-setup.err || {
  echo "error: principal TREE root add failed: $(redact </tmp/uat-wls-setup.err | tail -3)" >&2; exit 1; }
dh principal allowed-root add --system --access read_only "$PRINCIPAL" "$TREE/work/pipeline-inputs" 2>>/tmp/uat-wls-setup.err || {
  echo "error: principal pipeline-inputs root add failed: $(redact </tmp/uat-wls-setup.err | tail -3)" >&2; exit 1; }
MAIN_L_JSON="$(dh launcher create --system --principal "$PRINCIPAL" --name main --no-credential 2>>/tmp/uat-wls-setup.err || true)"
MAIN_L_ID="$(printf '%s' "$MAIN_L_JSON" | json_field id)"
[ -n "$MAIN_L_ID" ] || { echo "error: launcher create failed: $MAIN_L_JSON ($(redact </tmp/uat-wls-setup.err | tail -10))" >&2; exit 1; }
MAIN_LC_OUT="$(dh launcher credential create --system --principal "$PRINCIPAL" "$MAIN_L_ID" 2>/dev/null || true)"
MAIN_LC_TOKEN="$(printf '%s' "$MAIN_LC_OUT" | json_field token)"
[ -n "$MAIN_LC_TOKEN" ] || { echo "error: launcher credential create failed" >&2; exit 1; }
printf '%s\n' "$MAIN_LC_TOKEN" > /tmp/uat-wls-cred-main; chmod 600 /tmp/uat-wls-cred-main
WSA_ID="$(create_session /tmp/uat-wls-cred-main "$TREE/work")" \
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
    && [ "$(cat "$TREE/work/project/written.txt" 2>/dev/null)" = "s1-write" ]; then
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
if [ "$S3_EC" -ne 0 ] && [ ! -e "$TREE/work/pipeline-inputs/forbidden.txt" ]; then
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
    && [ "$(cat "$TREE/work/project/written.txt" 2>/dev/null)" = "s4-write" ] \
    && [ ! -e "$TREE/work/pipeline-inputs/forbidden.txt" ]; then
  acc_ok "S4 mixed RW+RO exposures independent in one workload"
else
  acc_fail "S4 mixed workload failed (ec=$S4_EC): $(printf '%s\n' "$S4_OUT" | redact | tail -3)"
fi

# ==============================================================================
# scenario S5: writable parent over nested RO refused before workload creation
# ==============================================================================
say "S5: writable parent over nested RO refused before workload creation"
if S5_BASE="$(residue_state)"; then
  if expect_read_only_root "$WSA_TOKEN" . /mnt/tree 'echo x > /mnt/tree/pipeline-inputs/x.txt' "$S5_BASE"; then
    acc_ok "S5 writable parent refused with read_only_root before MAC/container creation"
  else
    acc_fail "S5 writable parent refusal wrong (base: $S5_BASE)"
  fi
else
  acc_blocked "S5 residue inventory unavailable for the no-state baseline"
fi

# ==============================================================================
# scenario SE: external Session filesystem roots under the SELinux backend —
# the Session issues an external read-only root and an external read-write
# root through the absolute --filesystem-root grammar and mounts them through
# the same exposure/pin/projection owners as the workspace itself: the
# external RO root gets the read-only projection (writes denied, readable
# through it), the external RW root stays writable, and cleanup leaves no
# projections/pins/state.
# ==============================================================================
say "SE: external Session filesystem roots under the SELinux backend"

SE_OPT="/opt/$PRINCIPAL"
SE_HELPER="$SE_OPT/repos/helper"
SE_CACHE="$SE_OPT/cache"
rm -rf "$SE_OPT"
mkdir -p "$SE_HELPER" "$SE_CACHE"
printf 'se-helper-src\n' > "$SE_HELPER/main.go"
printf 'seed\n' > "$SE_CACHE/seed.txt"
chown -R "$PRINCIPAL:$PRINCIPAL" "$SE_OPT"
chmod -R u+rwX,go+rX "$SE_OPT"
if dh config allowed-root add --access read_write "$SE_OPT" >/dev/null 2>&1 \
    && dh principal allowed-root add --system --access read_write "$PRINCIPAL" "$ALLOWED_ROOT" >/dev/null 2>&1 \
    && dh principal allowed-root add --system --access read_write "$PRINCIPAL" "$SE_OPT" >/dev/null 2>&1; then
  acc_ok "SE setup: second effective root $SE_OPT (global RW + Principal RW)"
else
  acc_fail "SE setup: second effective root setup failed"
fi
SE_L_JSON="$(dh launcher create --system --principal "$PRINCIPAL" --name se-multiroot --no-credential 2>/dev/null || true)"
SE_L_ID="$(printf '%s' "$SE_L_JSON" | json_field id)"
if [ -n "$SE_L_ID" ] \
    && dh launcher allowed-root add --system --principal "$PRINCIPAL" "$SE_L_ID" "$ALLOWED_ROOT" >/dev/null 2>&1 \
    && dh launcher allowed-root add --system --principal "$PRINCIPAL" "$SE_L_ID" "$SE_OPT" >/dev/null 2>&1; then
  acc_ok "SE setup: multiroot launcher carries both effective roots"
else
  acc_fail "SE setup: multiroot launcher setup failed: $SE_L_JSON"
fi
SE_LC_OUT="$(dh launcher credential create --system --principal "$PRINCIPAL" "$SE_L_ID" 2>/dev/null || true)"
SE_LC_TOKEN="$(printf '%s' "$SE_LC_OUT" | json_field token)"
if [ -n "$SE_LC_TOKEN" ]; then
  printf '%s\n' "$SE_LC_TOKEN" > /tmp/uat-wls-cred-multiroot; chmod 600 /tmp/uat-wls-cred-multiroot
else
  echo "error: SE launcher credential create failed" >&2; exit 1
fi
SE_WS="$ALLOWED_ROOT/se-runs/run-123"
rm -rf "$ALLOWED_ROOT/se-runs"
mkdir -p "$SE_WS"
chown -R "$PRINCIPAL:$PRINCIPAL" "$ALLOWED_ROOT/se-runs"
chmod -R u+rwX,go+rX "$ALLOWED_ROOT/se-runs"
SE_OUT="$(dh session create --system --token-file /tmp/uat-wls-cred-multiroot \
  --workspace "$SE_WS" --json \
  --filesystem-root "$SE_HELPER=read_only" \
  --filesystem-root "$SE_CACHE=read_write" 2>&1 || true)"
SE_ID="$(printf '%s' "$SE_OUT" | json_field id)"
if [ -n "$SE_ID" ]; then
  printf '%s' "$SE_OUT" | json_field token > "/tmp/uat-wls-tok-$SE_ID"; chmod 600 "/tmp/uat-wls-tok-$SE_ID"
  SE_TOKEN="$(cat "/tmp/uat-wls-tok-$SE_ID")"
  acc_ok "SE multi-root Session created (external helper RO + cache RW)"
else
  acc_fail "SE multi-root session create failed: $(printf '%s\n' "$SE_OUT" | redact | tail -3)"
fi

# SE-RO: the external RO root is projected read-only (bindfs path): reads
# succeed through the projection and the writable attempt is denied with the
# host file not created. The readonly bind participates in the ordinary run
# (production defense in depth), so the independent backend-only denial of
# the external source — projection VFS writable underneath, the projection
# type itself the refuser — is proven by the S13 external-root live proof.
SE_RO="$(DOCKER_HELPER_SESSION_TOKEN="$SE_TOKEN" \
  dh run --image alpine:3.24 --mount "$SE_HELPER:/helper:ro" -- \
  sh -ec 'test "$(cat /helper/main.go)" = "se-helper-src" && echo SE-RO-READ-OK' 2>&1)"
if printf '%s\n' "$SE_RO" | grep -q 'SE-RO-READ-OK'; then
  acc_ok "SE external RO root readable through its projection"
else
  acc_fail "SE external RO read failed: $(printf '%s\n' "$SE_RO" | redact | tail -3)"
fi
DOCKER_HELPER_SESSION_TOKEN="$SE_TOKEN" \
  dh run --image alpine:3.24 --mount "$SE_HELPER:/helper:ro" -- \
  sh -ec 'echo forbidden > /helper/forbidden.txt' >/dev/null 2>&1
SE_EC=$?
if [ "$SE_EC" -ne 0 ] && [ ! -e "$SE_HELPER/forbidden.txt" ]; then
  acc_ok "SE external RO root write denied and the host file was not created"
else
  acc_fail "SE external RO root immutability broken (ec=$SE_EC)"
fi

# SE-RW: the external RW root stays writable; the write persists to the host.
SE_W="$(DOCKER_HELPER_SESSION_TOKEN="$SE_TOKEN" \
  dh run --image alpine:3.24 --mount "$SE_CACHE:/cache" -- \
  sh -ec 'echo se-write > /cache/written.txt && echo SE-RW-OK' >/tmp/uat-wls-se-w.log 2>&1)"
if [ -f "$SE_CACHE/written.txt" ] && [ "$(cat "$SE_CACHE/written.txt" 2>/dev/null)" = "se-write" ]; then
  acc_ok "SE external RW root writable through the workload owner"
else
  acc_fail "SE external RW write failed: $(redact </tmp/uat-wls-se-w.log | tail -3)"
fi

# SE introspection: session show and self carry the issued external roots.
SE_SHOW="$(dh session show --system --token-file "/tmp/uat-wls-tok-$SE_ID" --id "$SE_ID" --json 2>/dev/null || true)"
if printf '%s' "$SE_SHOW" | grep -q '"'"$SE_CACHE"'"' \
    && printf '%s' "$SE_SHOW" | grep -q '"'"$SE_HELPER"'"'; then
  acc_ok "SE session show carries the issued external roots (RW cache + RO helper)"
else
  acc_fail "SE session show does not expose the issued external roots: $(printf '%s' "$SE_SHOW" | redact | head -2)"
fi
SE_SELF="$(dh self --system --token-file "/tmp/uat-wls-tok-$SE_ID" --json 2>/dev/null || true)"
if printf '%s' "$SE_SELF" | grep -q '"'"$SE_CACHE"'"' \
    && printf '%s' "$SE_SELF" | grep -q 'read_write'; then
  acc_ok "SE self carries the issued external RW root"
else
  acc_fail "SE self does not expose the issued external RW root: $(printf '%s' "$SE_SELF" | redact | head -2)"
fi

# SE fcontext coverage: the external issued RW tree carries the helper-owned
# persistent coverage while the session is live; the ceiling parent never
# gets a rule merely by existing.
se_fcontext_has_rule() {
  local pattern="$1"
  semanage fcontext -l -C 2>/dev/null | grep -F -- "$pattern" >/dev/null
}
if se_fcontext_has_rule "$SE_CACHE(/.*)?"; then
  acc_ok "SE external RW tree carries helper-owned persistent fcontext coverage"
else
  acc_fail "SE external RW tree has no persistent fcontext coverage: $(semanage fcontext -l -C 2>/dev/null | grep docker_helper_workspace_t | head -3)"
fi
if se_fcontext_has_rule "$SE_OPT(/.*)?"; then
  acc_fail "SE the ceiling parent $SE_OPT must not gain coverage merely by being authorized (only issued trees do)"
else
  acc_ok "SE ceiling parent has no MAC state from authorization alone"
fi
SE_LABEL="$(ls -Zd "$SE_CACHE" 2>/dev/null | awk '{print $1}')"
case "$SE_LABEL" in
  *docker_helper_workspace_t*) acc_ok "SE external RW tree actually relabeled to docker_helper_workspace_t" ;;
  *) acc_fail "SE external RW tree label wrong: '$SE_LABEL'" ;;
esac

# SE share: a second Session issuing the same external tree must prevent
# early release of the coverage when the first Session is deleted.
SE2_OUT="$(dh session create --system --token-file /tmp/uat-wls-cred-multiroot \
  --workspace "$SE_WS" --json \
  --filesystem-root "$SE_CACHE=read_write" 2>&1 || true)"
SE2_ID="$(printf '%s' "$SE2_OUT" | json_field id)"
if [ -n "$SE2_ID" ]; then
  printf '%s' "$SE2_OUT" | json_field token > "/tmp/uat-wls-tok-$SE2_ID"; chmod 600 "/tmp/uat-wls-tok-$SE2_ID"
  dh session delete --system --token-file "/tmp/uat-wls-tok-$SE_ID" --id "$SE_ID" >/dev/null 2>&1
  if se_fcontext_has_rule "$SE_CACHE(/.*)?"; then
    acc_ok "SE shared external tree survives the first Session deletion (second Session keeps it)"
  else
    acc_fail "SE external fcontext coverage was released while a second Session still issues the tree"
  fi
  SE2_W="$(DOCKER_HELPER_SESSION_TOKEN="$(cat "/tmp/uat-wls-tok-$SE2_ID")" \
    dh run --image alpine:3.24 --mount "$SE_CACHE:/cache" -- \
    sh -ec 'echo se2-write > /cache/se2.txt' >/tmp/uat-wls-se2.log 2>&1; echo $?)"
  if [ "$SE2_W" -eq 0 ] && [ "$(cat "$SE_CACHE/se2.txt" 2>/dev/null)" = "se2-write" ]; then
    acc_ok "SE second Session still writes the shared external tree"
  else
    acc_fail "SE second Session lost write access to the shared tree (ec=$SE2_W)"
  fi
  dh session delete --system --token-file "/tmp/uat-wls-tok-$SE2_ID" --id "$SE2_ID" >/dev/null 2>&1
  if se_fcontext_has_rule "$SE_CACHE(/.*)?"; then
    acc_fail "SE external fcontext coverage must be relinquished after the last Session released it"
  else
    acc_ok "SE external fcontext coverage relinquished after the last Session deletion"
  fi
  SE_RELBL="$(ls -Zd "$SE_CACHE" 2>/dev/null | awk '{print $1}')"
  case "$SE_RELBL" in
    *docker_helper_workspace_t*) acc_fail "SE external tree label not restored after the last Session deletion: '$SE_RELBL'" ;;
    *) acc_ok "SE external tree labels restored after the last Session deletion" ;;
  esac
  rm -f "$SE_CACHE/se2.txt"
else
  acc_fail "SE share scenario setup failed: $(printf '%s' "$SE2_OUT" | redact | tail -2)"
fi

# SE overlap: issued ancestor/descendant trees survive either deletion order.
SE3_OUT="$(dh session create --system --token-file /tmp/uat-wls-cred-multiroot \
  --workspace "$SE_WS" --json \
  --filesystem-root "$SE_OPT=read_write" \
  --filesystem-root "$SE_CACHE=read_write" 2>&1 || true)"
SE3_ID="$(printf '%s' "$SE3_OUT" | json_field id)"
if [ -n "$SE3_ID" ]; then
  printf '%s' "$SE3_OUT" | json_field token > "/tmp/uat-wls-tok-$SE3_ID"; chmod 600 "/tmp/uat-wls-tok-$SE3_ID"
  # The projection collapses the descendant into the issued ancestor: only
  # the ancestor boundary is prepared.
  if se_fcontext_has_rule "$SE_OPT(/.*)?" && ! se_fcontext_has_rule "$SE_CACHE(/.*)?"; then
    acc_ok "SE nested issued roots collapse to the single ancestor MAC boundary"
  else
    acc_fail "SE nested issued roots did not collapse (rules: $(semanage fcontext -l -C 2>/dev/null | grep docker_helper_workspace_t | head -3))"
  fi
  dh session delete --system --token-file "/tmp/uat-wls-tok-$SE3_ID" --id "$SE3_ID" >/dev/null 2>&1
  if se_fcontext_has_rule "$SE_OPT(/.*)?"; then
    acc_fail "SE ancestor boundary must be removed after the only session released it"
  else
    acc_ok "SE ancestor boundary removed after the only session deletion"
  fi
  rm -f "$SE_CACHE/written.txt" 2>/dev/null || true
else
  acc_fail "SE overlap scenario setup failed: $(printf '%s' "$SE3_OUT" | redact | tail -2)"
fi

# SE reverse overlap: issue the child first, then the parent; deleting the
# child must keep the parent usable, deleting the parent cleans up.
SE4_OUT="$(dh session create --system --token-file /tmp/uat-wls-cred-multiroot \
  --workspace "$SE_WS" --json \
  --filesystem-root "$SE_CACHE=read_write" 2>&1 || true)"
SE4_ID="$(printf '%s' "$SE4_OUT" | json_field id)"
SE5_OUT="$(dh session create --system --token-file /tmp/uat-wls-cred-multiroot \
  --workspace "$SE_WS" --json \
  --filesystem-root "$SE_OPT=read_write" 2>&1 || true)"
SE5_ID="$(printf '%s' "$SE5_OUT" | json_field id)"
if [ -n "$SE4_ID" ] && [ -n "$SE5_ID" ]; then
  printf '%s' "$SE4_OUT" | json_field token > "/tmp/uat-wls-tok-$SE4_ID"; chmod 600 "/tmp/uat-wls-tok-$SE4_ID"
  printf '%s' "$SE5_OUT" | json_field token > "/tmp/uat-wls-tok-$SE5_ID"; chmod 600 "/tmp/uat-wls-tok-$SE5_ID"
  # Both boundaries exist (created in reverse order: child, then parent).
  if se_fcontext_has_rule "$SE_CACHE(/.*)?" && se_fcontext_has_rule "$SE_OPT(/.*)?"; then
    acc_ok "SE reverse-order issuance prepares both disjoint boundaries"
  else
    acc_fail "SE reverse-order issuance boundaries missing (rules: $(semanage fcontext -l -C 2>/dev/null | grep docker_helper_workspace_t | head -4))"
  fi
  # Delete the child session first: the parent boundary stays.
  dh session delete --system --token-file "/tmp/uat-wls-tok-$SE4_ID" --id "$SE4_ID" >/dev/null 2>&1
  if se_fcontext_has_rule "$SE_OPT(/.*)?"; then
    acc_ok "SE child deletion first keeps the parent boundary"
  else
    acc_fail "SE child deletion removed the parent boundary needed by the parent session"
  fi
  # Delete the parent session: everything is released and restored.
  dh session delete --system --token-file "/tmp/uat-wls-tok-$SE5_ID" --id "$SE5_ID" >/dev/null 2>&1
  if se_fcontext_has_rule "$SE_OPT(/.*)?" || se_fcontext_has_rule "$SE_CACHE(/.*)?"; then
    acc_fail "SE final deletion leaves fcontext residue (rules: $(semanage fcontext -l -C 2>/dev/null | grep docker_helper_workspace_t | head -4))"
  else
    acc_ok "SE final deletion relinquishes every external boundary"
  fi
  SE_RELBL2="$(ls -Zd "$SE_OPT" 2>/dev/null | awk '{print $1}')"
  case "$SE_RELBL2" in
    *docker_helper_workspace_t*) acc_fail "SE parent tree label not restored after final deletion: '$SE_RELBL2'" ;;
    *) acc_ok "SE parent tree labels restored after final deletion" ;;
  esac
else
  acc_fail "SE reverse overlap setup failed: $(printf '%s' "$SE4_OUT" "$SE5_OUT" | redact | tail -2)"
fi

# SE regular file: an issued regular-file RW root is writable and its exact
# fcontext coverage is relinquished on deletion.
SE_FILE="$SE_OPT/worker.env"
printf 'se-file-src\n' > "$SE_FILE"
chown "$PRINCIPAL:$PRINCIPAL" "$SE_FILE" 2>/dev/null || true
SE6_OUT="$(dh session create --system --token-file /tmp/uat-wls-cred-multiroot \
  --workspace "$SE_WS" --json \
  --filesystem-root "$SE_FILE=read_write" 2>&1 || true)"
SE6_ID="$(printf '%s' "$SE6_OUT" | json_field id)"
if [ -n "$SE6_ID" ]; then
  printf '%s' "$SE6_OUT" | json_field token > "/tmp/uat-wls-tok-$SE6_ID"; chmod 600 "/tmp/uat-wls-tok-$SE6_ID"
  SE6_W="$(DOCKER_HELPER_SESSION_TOKEN="$(cat "/tmp/uat-wls-tok-$SE6_ID")" \
    dh run --image alpine:3.24 --mount "$SE_FILE:/etc/worker.env" -- \
    sh -ec 'echo file-write > /etc/worker.env' >/tmp/uat-wls-se6.log 2>&1; echo $?)"
  if [ "$SE6_W" -eq 0 ] && [ "$(cat "$SE_FILE" 2>/dev/null)" = "file-write" ]; then
    acc_ok "SE issued regular-file RW root is writable through the backend"
  else
    acc_fail "SE regular-file RW write failed (ec=$SE6_W): $(redact </tmp/uat-wls-se6.log | tail -2)"
  fi
  dh session delete --system --token-file "/tmp/uat-wls-tok-$SE6_ID" --id "$SE6_ID" >/dev/null 2>&1
  if se_fcontext_has_rule "$SE_FILE"; then
    acc_fail "SE regular-file boundary must be relinquished after deletion"
  else
    acc_ok "SE regular-file boundary relinquished after deletion"
  fi
  printf 'se-file-src\n' > "$SE_FILE"
else
  acc_fail "SE regular-file scenario setup failed: $(printf '%s' "$SE6_OUT" | redact | tail -2)"
fi

# SE restart: a live session's external coverage survives restart and the
# reconciled binding keeps the write path working.
SE7_OUT="$(dh session create --system --token-file /tmp/uat-wls-cred-multiroot \
  --workspace "$SE_WS" --json \
  --filesystem-root "$SE_CACHE=read_write" 2>&1 || true)"
SE7_ID="$(printf '%s' "$SE7_OUT" | json_field id)"
if [ -n "$SE7_ID" ]; then
  printf '%s' "$SE7_OUT" | json_field token > "/tmp/uat-wls-tok-$SE7_ID"; chmod 600 "/tmp/uat-wls-tok-$SE7_ID"
  systemctl restart docker-helper.service >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    systemctl is-active --quiet docker-helper.service && break
    sleep 1
  done
  if se_fcontext_has_rule "$SE_CACHE(/.*)?" \
      && DOCKER_HELPER_SESSION_TOKEN="$(cat "/tmp/uat-wls-tok-$SE7_ID")" \
        dh run --image alpine:3.24 --mount "$SE_CACHE:/cache" -- \
        sh -ec 'echo restart-write > /cache/restart.txt' >/tmp/uat-wls-se7.log 2>&1 \
      && [ "$(cat "$SE_CACHE/restart.txt" 2>/dev/null)" = "restart-write" ]; then
    acc_ok "SE restart/reconciliation restores live issued external coverage and write access"
  else
    acc_fail "SE restart lost the external coverage or write access: $(redact </tmp/uat-wls-se7.log | tail -2)"
  fi
  dh session delete --system --token-file "/tmp/uat-wls-tok-$SE7_ID" --id "$SE7_ID" >/dev/null 2>&1
  rm -f "$SE_CACHE/restart.txt"
  if se_fcontext_has_rule "$SE_CACHE(/.*)?"; then
    acc_fail "SE final cleanup leaves external fcontext residue (rules: $(semanage fcontext -l -C 2>/dev/null | grep docker_helper_workspace_t | head -3))"
  else
    acc_ok "SE no external fcontext residue after the final cleanup"
  fi
else
  acc_fail "SE restart scenario setup failed: $(printf '%s' "$SE7_OUT" | redact | tail -2)"
fi
rm -f "/tmp/uat-wls-tok-$SE_ID" "/tmp/uat-wls-tok-$SE2_ID" "/tmp/uat-wls-tok-$SE3_ID" \
  "/tmp/uat-wls-tok-$SE4_ID" "/tmp/uat-wls-tok-$SE5_ID" "/tmp/uat-wls-tok-$SE6_ID" \
  "/tmp/uat-wls-tok-$SE7_ID" 2>/dev/null || true

# ==============================================================================
# scenario S7: bindfs projection really used on the packaged RPM path
# ==============================================================================
say "S7: bindfs projection used on the packaged RPM path"
DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
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
  echo "  S7 detail: run-log=$(cat /tmp/uat-wls-s7.log 2>/dev/null | redact | tail -2)" >&2
  grep 'fuse.bindfs' /proc/mounts 2>/dev/null | sed 's/^/  S7 mounts: /' >&2 || echo "  S7 mounts: none" >&2
fi
# The run.start audit stream carries the backend fact for every system-mode
# run. The bounded window conversion uses the same ISO form as the S13 AVC
# window (journalctl's @epoch since-form is not uniformly accepted across
# systemd builds); the window is retried briefly because journald can lag the
# just-finished run, and a failed read is diagnosed instead of failing silent.
S7_AUDIT_START="$(date -u -d "@${AUDIT_START_EPOCH}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || true)"
S7_AUDIT_OK=""
for _s7i in 1 2 3; do
  if [ -n "$S7_AUDIT_START" ] \
      && journalctl --utc -u docker-helper.service --since "$S7_AUDIT_START" --no-pager 2>/dev/null \
        | grep '"event":"run.start"' | grep -q '"workload_mac_backend":"selinux"'; then
    S7_AUDIT_OK=1
    break
  fi
  sleep 2
done
if [ -n "$S7_AUDIT_OK" ]; then
  acc_ok "S7 run.start audit records workload_mac_backend=selinux"
else
  acc_fail "S7 run.start audit does not record the SELinux workload backend (window start: ${S7_AUDIT_START:-unavailable})"
  journalctl --utc -u docker-helper.service --no-pager 2>/dev/null \
    | grep '"event":"run.start"' | tail -3 | sed 's/^/  S7 audit detail: /' >&2 || true
fi

# ==============================================================================
# scenario S6: workload stays docker_helper_container_t with distinct MCS
# ==============================================================================
say "S6: docker_helper_container_t + Docker-owned MCS"
S6_L1="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --image alpine:3.24 --mount project:/mnt/project -- /bin/cat /proc/self/attr/current 2>/dev/null || true)"
S6_L2="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --image alpine:3.24 --mount pipeline-inputs:/mnt/inputs:ro -- /bin/cat /proc/self/attr/current 2>/dev/null || true)"
case "$S6_L1" in *docker_helper_container_t:*) ;; *)
  acc_fail "S6 RW workload process label wrong: '$S6_L1'" ;;
esac
case "$S6_L2" in *docker_helper_container_t:*) ;; *)
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
WSB_ID="$(create_session /tmp/uat-wls-cred-main "$TREE/work/project")" \
  || { echo "error: second acceptance session creation failed" >&2; exit 1; }
WSB_TOKEN="$(cat "/tmp/uat-wls-tok-$WSB_ID")"
rm -f "$TREE/work/project/a-file" "$TREE/work/project/b-file"
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
    && [ "$(cat "$TREE/work/project/a-file" 2>/dev/null)" = "session-A" ] \
    && [ "$(cat "$TREE/work/project/b-file" 2>/dev/null)" = "session-B" ]; then
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
    && [ "$(cat "$TREE/work/pipeline-inputs/input.txt" 2>/dev/null)" = "ro-input" ]; then
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
wait_no_helper_containers
S12_WAIT_RC=$?
if [ "$S12_WAIT_RC" -eq 2 ]; then
  acc_blocked "S12 helper container inventory unavailable after the scenarios"
elif [ "$S12_WAIT_RC" -ne 0 ]; then
  acc_fail "S12 helper containers remain after the scenarios"
fi
workload_residue_clean
S12_CLEAN_RC=$?
if [ "$S12_CLEAN_RC" -eq 0 ]; then
  acc_ok "S12 no generated workload state remains after the positive scenarios"
elif [ "$S12_CLEAN_RC" -eq 2 ]; then
  acc_blocked "S12 workload residue inventory unavailable after the positive scenarios"
else
  acc_fail "S12 workload residue after the positive scenarios"
fi
DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --image alpine:3.24 --mount project:/mnt/project -- sh -ec 'exit 9' >/dev/null 2>&1
S12_FAIL_EC=$?
[ "$S12_FAIL_EC" -ne 0 ] \
  && acc_ok "S12 failing workload propagates the container failure (ec=$S12_FAIL_EC)" \
  || acc_fail "S12 failing workload unexpectedly succeeded"
wait_no_helper_containers
S12_WAIT2_RC=$?
if [ "$S12_WAIT2_RC" -eq 2 ]; then
  acc_blocked "S12 helper container inventory unavailable after the failing run"
elif [ "$S12_WAIT2_RC" -ne 0 ]; then
  acc_fail "S12 helper containers remain after the failing run"
fi
workload_residue_clean
S12_CLEAN2_RC=$?
if [ "$S12_CLEAN2_RC" -eq 0 ]; then
  acc_ok "S12 no generated workload state remains after the failing run"
elif [ "$S12_CLEAN2_RC" -eq 2 ]; then
  acc_blocked "S12 workload residue inventory unavailable after the failing run"
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
if wait_health \
    && case "$DH_LABEL2" in *docker_helper_t:*) true ;; *) false ;; esac; then
  workload_residue_clean
  S12_CLEAN3_RC=$?
  if [ "$S12_CLEAN3_RC" -eq 0 ]; then
    acc_ok "S12 restart/reconciliation: daemon confined again, no stale workload state"
  elif [ "$S12_CLEAN3_RC" -eq 2 ]; then
    acc_blocked "S12 restart left the daemon confined but the workload residue inventory is unavailable"
  else
    acc_fail "S12 restart left stale workload state"
  fi
else
  workload_residue_clean
  S12_CLEAN4_RC=$?
  echo "  S12 restart detail: health=$(wait_health && echo ok || echo FAIL) label='$DH_LABEL2' residue=$( [ "$S12_CLEAN4_RC" -eq 0 ] && echo clean || { [ "$S12_CLEAN4_RC" -eq 2 ] && echo unavail || echo dirty; })" >&2
  acc_fail "S12 restart left confinement or workload residue broken"
fi

# is_expected_projection_denial LINE — the single canonical predicate deciding
# whether a raw audit AVC record is the expected enforcing write denial by a
# docker_helper_container_t workload against the docker_helper_ro_projection_t
# projection. It is used BOTH to select the mandatory attributable S13 evidence
# and to exclude those same expected records from UNEXPECTED, so the two never
# drift into different definitions of "expected projection AVC". Requires (at
# minimum):
#   avc:  denied
#   scontext contains docker_helper_container_t
#   tcontext contains docker_helper_ro_projection_t
#   tclass=dir OR tclass=file
#   write present in the actual raw AVC permission set (denied { write })
#   permissive=0
# A raw AVC record reports its permission set in braces ("denied { write }"),
# NOT as "perm=write", so the write test is anchored to the brace-delimited
# permission set. An unrelated permission, target type, source domain, class,
# or permissive AVC is never accepted as the required enforcing write denial.
is_expected_projection_denial() {
  local line="$1"
  printf '%s\n' "$line" | grep -q 'avc:  *denied' \
    && printf '%s\n' "$line" | grep -q 'scontext=.*docker_helper_container_t' \
    && printf '%s\n' "$line" | grep -q 'tcontext=.*docker_helper_ro_projection_t' \
    && printf '%s\n' "$line" | grep -Eq 'tclass=(dir|file)\b' \
    && printf '%s\n' "$line" | grep -Eq '\{[^}]*\bwrite\b[^}]*\}' \
    && printf '%s\n' "$line" | grep -Eq 'permissive=0'
}

# count_unexpected_helper_avcs WINDOW — counts, within a window of raw AVC
# records, the denials in the docker_helper scope that are not the expected
# enforcing projection write denial (is_expected_projection_denial). This is
# the single decision point behind the S13 "no unexpected docker_helper AVC"
# gate; it prints the count on stdout and routes its per-record diagnostics to
# stderr so the count stays machine-readable under command substitution. Only
# AVCs whose source context is in the docker_helper* scope are considered;
# every in-scope denial that is not an expected projection write denial is
# unexpected.
count_unexpected_helper_avcs() {
  local window="$1" line count=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    printf '%s\n' "$line" | grep -q 'scontext.*docker_helper' || continue
    if is_expected_projection_denial "$line"; then
      printf '  expected projection write denial: %s\n' "$line" >&2
    else
      printf '  UNEXPECTED AVC: %s\n' "$line" >&2
      count=$((count + 1))
    fi
  done <<< "$window"
  printf '%s' "$count"
}

# ==============================================================================
# scenario S13: harness proof + bounded audit window evidence
# ==============================================================================
say "S13: forced-writable RO denied by SELinux (harness) + audit evidence"
mkdir -p "$EVIDENCE_DIR"
if DOCKER_HELPER_LIVE_WORKLOAD_PROOF=1 WORKLOAD_EVIDENCE_DIR="$EVIDENCE_DIR" \
    "$PROOF_BIN_IN" -test.run 'TestLiveWorkloadSELinux|TestLiveWorkloadSELinuxRegularFile|TestLiveWorkloadSELinuxExternalRoot|TestLiveWorkloadMCSConcurrentRWRO' -test.v \
    >/tmp/uat-wls-harness.log 2>&1; then
  acc_ok "S13 live harness passed: bindfs projection denies the would-be-RO write (VFS view writable), regular-file RO proven, MCS concurrency proven, external-source backend-only proof proven"
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
RO_AVC="$(printf '%s\n' "$AVC_WINDOW" | while IFS= read -r _line; do
  is_expected_projection_denial "$_line" && printf '%s\n' "$_line"
done | head -1 || true)"
if [ -n "$RO_AVC" ]; then
  acc_ok "S13 attributable enforcing projection write-denial AVC present: $RO_AVC"
else
  acc_blocked "S13 no attributable docker_helper_ro_projection_t enforcing write-denial AVC in the window (independent MAC denial evidence impossible)"
fi

# No unexpected AVCs in the docker-helper policy scope: any denied AVC whose
# source context involves docker_helper_* must be the expected projection
# write denials (or the daemon's own policy-tool fifo artifact).
UNEXPECTED="$(count_unexpected_helper_avcs "$AVC_WINDOW")"
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