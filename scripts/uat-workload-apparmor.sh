#!/usr/bin/env bash
#
# uat-workload-apparmor.sh — Release 2.2 AppArmor workload-MAC acceptance on
# the exact candidate DEB produced by the artifact gate (never rebuilt here).
#
# This is the ONE full AppArmor workload-MAC acceptance matrix of the release
# gate (docs/release-2.2-mac-enforcement.md, AppArmor acceptance matrix):
#   1  RW exposure is really writable through the generated workload profile;
#   2  RO exposure is readable;
#   3  RO exposure is immutable (the write is denied, host file unchanged);
#   4  mixed RW + RO exposures work independently in ONE workload;
#   5  a writable parent spanning a nested RO region is refused with the
#      stable read_only_root code BEFORE any MAC/container state exists;
#   6  the backend-only forced-writable RO case is denied by AppArmor ITSELF
#      (not the VFS readonly bit): the compiled live-proof harness drives the
#      production renderer/parser/lifecycle from the same source SHA the
#      candidate was built from, over a deliberately VFS-writable target,
#      and the attributable kernel DENIED record is independently verified;
#   7  generated workload profile/state is cleaned after success AND failure;
#   8  daemon restart/reconciliation leaves no stale helper-owned
#      profile/state;
#   9  the docker-helper-system daemon profile is not widened to workload-RW
#      policy (packaged profile bytes unchanged, separate generated profiles);
#  10  the bounded audit window carries the attributable workload-profile
#      DENIED record and no unexpected docker-helper-system DENIED records.
#
# Candidate binding (fail closed, before any scenario):
#   * the exact candidate DEB SHA-256 matches the gate manifest checksum;
#   * candidate.manifest source_sha equals this checkout SHA (UAT_SOURCE_SHA);
#   * the installed binary reports exactly UAT_VERSION and is owned by the
#     candidate package together with its packaged daemon profile.
# The production API intentionally has no "force writable" bypass, so proof 6
# uses the test-only live harness compiled from the same verified source; it
# is test infrastructure and never part of the product.
#
# Contract for every check: PASS -> continue; FAIL -> gate red;
# BLOCKED -> required prerequisite/evidence unavailable -> gate red.
# Exit status: 0 = all PASS, 1 = any FAIL, 2 = any BLOCKED (and none FAIL).
#
# Env inputs:
#   UAT_VERSION          candidate version string (required)
#   UAT_ARTIFACT_PATH    exact candidate .deb produced by the gate (required)
#   UAT_ARTIFACT_SHA256  expected SHA-256 of the candidate .deb (required)
#   UAT_MANIFEST_PATH    candidate.manifest produced by the gate (required)
#   UAT_SOURCE_SHA       the gate checkout SHA (github.sha; required)
#   UAT_REPO_DIR         the gate checkout of the same SHA (required)
#   UAT_ALLOWED_ROOT     global allowed root (default /home/runner)
#   UAT_PRINCIPAL        OS user mapped to the principal (default runner)
#
# Requires: root, systemd, Docker, AppArmor, Go toolchain (harness compile),
# python3. Exits as above.

set -uo pipefail

VERSION="${UAT_VERSION:-2.2.0-uat}"
ALLOWED_ROOT="${UAT_ALLOWED_ROOT:-/home/runner}"
PRINCIPAL="${UAT_PRINCIPAL:-runner}"
ARTIFACT_PATH_IN="${UAT_ARTIFACT_PATH:-}"
ARTIFACT_SHA256_IN="${UAT_ARTIFACT_SHA256:-}"
MANIFEST_PATH_IN="${UAT_MANIFEST_PATH:-}"
SOURCE_SHA_IN="${UAT_SOURCE_SHA:-}"
REPO_DIR_IN="${UAT_REPO_DIR:-}"

PREFIX="[uat-workload-apparmor]"
say()  { printf '\n%s %s\n' "$PREFIX" "$*"; }
info() { printf '%s %s\n' "$PREFIX" "$*"; }

redact() {
  sed -E \
    -e 's/dht_[A-Za-z0-9_-]+/<redacted-token>/g' \
    -e 's/dhc_[A-Za-z0-9_-]+/<redacted-token>/g'
}

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
[ -n "$ARTIFACT_PATH_IN" ] || { echo "error: UAT_ARTIFACT_PATH is required" >&2; exit 1; }
[ -f "$ARTIFACT_PATH_IN" ] || { echo "error: UAT_ARTIFACT_PATH is not a regular file: $ARTIFACT_PATH_IN" >&2; exit 1; }
[ -n "$ARTIFACT_SHA256_IN" ] || { echo "error: UAT_ARTIFACT_SHA256 is required" >&2; exit 1; }
ACTUAL_SHA="$(sha256sum "$ARTIFACT_PATH_IN" | awk '{print $1}')"
[ "$ACTUAL_SHA" = "$ARTIFACT_SHA256_IN" ] || {
  echo "error: candidate DEB SHA-256 mismatch (expected $ARTIFACT_SHA256_IN, got $ACTUAL_SHA)" >&2
  exit 1
}
[ -n "$MANIFEST_PATH_IN" ] || { echo "error: UAT_MANIFEST_PATH is required" >&2; exit 1; }
[ -f "$MANIFEST_PATH_IN" ] || { echo "error: UAT_MANIFEST_PATH is not a regular file: $MANIFEST_PATH_IN" >&2; exit 1; }
[ -n "$SOURCE_SHA_IN" ] || { echo "error: UAT_SOURCE_SHA is required" >&2; exit 1; }
[ -n "$REPO_DIR_IN" ] || { echo "error: UAT_REPO_DIR is required" >&2; exit 1; }
[ -d "$REPO_DIR_IN/.git" ] || { echo "error: UAT_REPO_DIR is not the gate checkout: $REPO_DIR_IN" >&2; exit 1; }

# Candidate source binding: the checkout that compiles the harness must be
# the exact source the candidate was built from, as asserted by the gate
# manifest. This is the harness-to-candidate link required by the release
# gate; it is checked before any scenario runs.
MANIFEST_SOURCE_SHA="$(sed -n 's/^source_sha=//p' "$MANIFEST_PATH_IN" | head -1)"
[ "$MANIFEST_SOURCE_SHA" = "$SOURCE_SHA_IN" ] || {
  echo "error: candidate.manifest source_sha mismatch (expected $SOURCE_SHA_IN, got ${MANIFEST_SOURCE_SHA:-absent})" >&2
  exit 1
}
REPO_HEAD="$(git -C "$REPO_DIR_IN" rev-parse HEAD 2>/dev/null || true)"
[ "$REPO_HEAD" = "$SOURCE_SHA_IN" ] || {
  echo "error: checkout HEAD ($REPO_HEAD) is not the candidate source SHA ($SOURCE_SHA_IN)" >&2
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

# helper_container_count counts helper-owned containers (including exited).
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

# generated_workload_profiles lists loaded generated workload profiles.
generated_workload_profiles() {
  aa-status 2>/dev/null | grep -oE 'docker-helper-workload-[A-Za-z0-9_-]+' | sort -u
}

# workload_residue_clean asserts no transient/durable workload-MAC state and
# no loaded generated workload profile remains.
workload_residue_clean() {
  [ "$(ls /run/docker-helper/workload-mac 2>/dev/null | wc -l)" = "0" ] \
    && [ "$(ls /var/lib/docker-helper/workload-mac 2>/dev/null | wc -l)" = "0" ] \
    && [ -z "$(generated_workload_profiles)" ]
}

# create_session CREDFILE WORKSPACE — creates a launcher-credential session
# (bearer stored in /tmp/uat-wla-<id>), prints the session ID.
create_session() {
  local cred="$1" ws="$2" out id
  out="$(dh session create --system --token-file "$cred" --workspace "$ws" --json 2>/dev/null || true)"
  id="$(printf '%s' "$out" | json_field id)"
  [ -n "$id" ] || return 1
  printf '%s' "$out" | json_field token > "/tmp/uat-wla-tok-$id"; chmod 600 "/tmp/uat-wla-tok-$id"
  printf '%s' "$id"
}

# expect_read_only_root TOKEN SOURCE TARGET SNIPPET BASE — asserts the stable
# read_only_root refusal and that the refusal created no workload state.
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

cleanup() {
  systemctl stop docker-helper.service >/dev/null 2>&1 || true
  systemctl disable docker-helper.service >/dev/null 2>&1 || true
  apparmor_parser -R /etc/apparmor.d/docker-helper-system 2>/dev/null || true
  rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper /tmp/uat-wla-evidence
}
trap cleanup EXIT

# ==============================================================================
# setup: install the exact candidate DEB and start the confined system service
# ==============================================================================
say "setup: install exact candidate DEB + start confined system service"
systemctl stop docker-helper.service >/dev/null 2>&1 || true
systemctl disable docker-helper.service >/dev/null 2>&1 || true
apparmor_parser -R /etc/apparmor.d/docker-helper-system 2>/dev/null || true
dpkg -P docker-helper >/dev/null 2>&1 || true
rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper

if dpkg -i "$ARTIFACT_PATH_IN" >/tmp/uat-wla-install.log 2>&1; then
  acc_ok "candidate DEB installed (sha256 verified: $ACTUAL_SHA)"
else
  echo "error: dpkg -i failed for candidate DEB (see /tmp/uat-wla-install.log)" >&2
  exit 1
fi
if dpkg -S /usr/bin/docker-helper >/dev/null 2>&1 \
    && dpkg -S /etc/apparmor.d/docker-helper-system >/dev/null 2>&1; then
  acc_ok "candidate binary and packaged daemon profile owned by the candidate package"
else
  echo "error: candidate binary/profile not owned by the candidate package" >&2
  exit 1
fi
DAEMON_PROFILE_SHA="$(sha256sum /etc/apparmor.d/docker-helper-system | awk '{print $1}')"

if dh init --allowed-root "$ALLOWED_ROOT" >/tmp/uat-wla-init.log 2>&1; then
  acc_ok "system init (global ceiling: $ALLOWED_ROOT)"
else
  printf '  init output: %s\n' "$(redact </tmp/uat-wla-init.log)" >&2
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
[ "$(cat "/proc/$DH_PID/attr/current" 2>/dev/null || true)" = "docker-helper-system (enforce)" ] \
  || { echo "error: service not AppArmor-confined after setup install" >&2; exit 1; }
wait_health || { echo "error: API socket not ready" >&2; exit 1; }
[ "$(dh version)" = "$VERSION" ] \
  || { echo "error: installed binary version mismatch (expected $VERSION)" >&2; exit 1; }
acc_ok "candidate daemon confined (docker-helper-system (enforce)), version $VERSION"
ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
[ -n "$ADMIN_TOKEN" ] || { echo "error: could not read the admin token" >&2; exit 1; }

docker pull alpine:3.24 >/dev/null 2>&1 || true
docker pull alpine:3.19 >/dev/null 2>&1 || true

# Compile the test-only live harness from the verified same-SHA checkout.
say "harness: compile the live-proof harness from the candidate source SHA"
if command -v go >/dev/null 2>&1; then
  if (cd "$REPO_DIR_IN" && go test -c -o /tmp/uat-wla-proof.test .) >/tmp/uat-wla-compile.log 2>&1 \
      && [ -x /tmp/uat-wla-proof.test ]; then
    acc_ok "live harness compiled from $REPO_HEAD"
  else
    acc_blocked "harness compilation failed (backend-only MAC proof impossible): $(tail -3 /tmp/uat-wla-compile.log 2>/dev/null)"
  fi
else
  acc_blocked "Go toolchain unavailable (backend-only MAC proof impossible)"
fi

# ---- fixture: policy tree with one RO region ---------------------------------
TREE="$ALLOWED_ROOT/mac-tree"
rm -rf "$TREE"
mkdir -p "$TREE/project" "$TREE/pipeline-inputs"
printf 'project-file\n' > "$TREE/project/keep.txt"
printf 'ro-input\n' > "$TREE/pipeline-inputs/input.txt"
chown -R "$PRINCIPAL:$PRINCIPAL" "$TREE"
chmod -R u+rwX,go+rX "$TREE"

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
printf '%s\n' "$MAIN_LC_TOKEN" > /tmp/uat-wla-cred-main; chmod 600 /tmp/uat-wla-cred-main
WSA_ID="$(create_session /tmp/uat-wla-cred-main "$TREE")" \
  || { echo "error: acceptance session creation failed" >&2; exit 1; }
WSA_TOKEN="$(cat "/tmp/uat-wla-tok-$WSA_ID")"
acc_ok "acceptance session $WSA_ID with mixed policy tree"

# The kernel-audit window starts now: every check below runs inside it.
# Independent AppArmor denial evidence needs a drained kernel audit stream:
# hosted CI runners run without auditd, so the audit fallback (printk/kmsg
# and the netlink backlog) silently drops records under rate limiting and
# the attributable denial is structurally unobservable. Start auditd before
# the window opens when it is available; the raw-evidence collectors below
# then read /var/log/audit/audit.log first.
AA_AUDIT_START_EPOCH="$(date +%s)"
if ! pgrep -x auditd >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1 && ! command -v auditd >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends auditd >/dev/null 2>&1 || true
  fi
  systemctl start auditd 2>/dev/null || service auditd start 2>/dev/null || auditd 2>/dev/null || true
fi
if pgrep -x auditd >/dev/null 2>&1; then
  acc_ok "kernel audit stream drained by auditd for the denial-evidence window"
else
  info "auditd unavailable; denial evidence relies on the kernel printk fallback"
fi

# ==============================================================================
# scenario W1: RW exposure is really writable
# ==============================================================================
say "W1: RW exposure really writable"
if DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
    dh run --image alpine:3.24 --mount project:/mnt/project -- \
    sh -ec 'echo w1-write > /mnt/project/written.txt && cat /mnt/project/keep.txt' >/tmp/uat-wla-w1.log 2>&1 \
    && [ "$(cat "$TREE/project/written.txt" 2>/dev/null)" = "w1-write" ]; then
  acc_ok "W1 RW exposure mounted writable and the write persisted"
else
  acc_fail "W1 RW exposure write failed: $(redact </tmp/uat-wla-w1.log | tail -3)"
fi

# ==============================================================================
# scenario W2: RO exposure is readable
# ==============================================================================
say "W2: RO exposure readable"
W2_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --image alpine:3.24 --mount pipeline-inputs:/mnt/inputs:ro -- \
  sh -ec 'test "$(cat /mnt/inputs/input.txt)" = "ro-input" && echo W2-RO-READ-OK' 2>&1)"
if printf '%s\n' "$W2_OUT" | grep -q 'W2-RO-READ-OK'; then
  acc_ok "W2 RO exposure readable"
else
  acc_fail "W2 RO read failed: $(printf '%s\n' "$W2_OUT" | redact | tail -3)"
fi

# ==============================================================================
# scenario W3: RO exposure is immutable
# ==============================================================================
say "W3: RO exposure immutable"
DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --image alpine:3.24 --mount pipeline-inputs:/mnt/inputs:ro -- \
  sh -ec 'echo forbidden > /mnt/inputs/forbidden.txt' >/dev/null 2>&1
W3_EC=$?
if [ "$W3_EC" -ne 0 ] && [ ! -e "$TREE/pipeline-inputs/forbidden.txt" ]; then
  acc_ok "W3 RO write denied and the host file was not created"
else
  acc_fail "W3 RO exposure immutability broken (ec=$W3_EC)"
fi

# ==============================================================================
# scenario W4: mixed RW + RO exposures work independently in one workload
# ==============================================================================
say "W4: mixed RW + RO in one workload"
W4_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --image alpine:3.24 --mount project:/mnt/project --mount pipeline-inputs:/mnt/inputs:ro -- \
  sh -ec 'echo w4-write > /mnt/project/written.txt; test "$(cat /mnt/inputs/input.txt)" = "ro-input" || exit 3; if echo x > /mnt/inputs/forbidden.txt 2>/dev/null; then exit 4; fi; echo W4-MIXED-OK' 2>&1)"
W4_EC=$?
if [ "$W4_EC" -eq 0 ] && printf '%s\n' "$W4_OUT" | grep -q 'W4-MIXED-OK' \
    && [ "$(cat "$TREE/project/written.txt" 2>/dev/null)" = "w4-write" ] \
    && [ ! -e "$TREE/pipeline-inputs/forbidden.txt" ]; then
  acc_ok "W4 mixed RW+RO exposures independent in one workload"
else
  acc_fail "W4 mixed workload failed (ec=$W4_EC): $(printf '%s\n' "$W4_OUT" | redact | tail -3)"
fi

# ==============================================================================
# scenario W5: writable parent over nested RO refused before workload creation
# ==============================================================================
say "W5: writable parent over nested RO refused before workload creation"
W5_BASE="$(residue_state)"
if expect_read_only_root "$WSA_TOKEN" . /mnt/tree 'echo x > /mnt/tree/pipeline-inputs/x.txt' "$W5_BASE"; then
  acc_ok "W5 writable parent refused with read_only_root before MAC/container creation"
else
  acc_fail "W5 writable parent refusal wrong (base: $W5_BASE)"
fi

# ==============================================================================
# scenario W7a: cleanup after success
# ==============================================================================
say "W7a: cleanup after a successful workload"
wait_no_helper_containers || acc_fail "W7a helper containers remain after a successful run"
if workload_residue_clean; then
  acc_ok "W7a no generated workload profile/state remains after success"
else
  acc_fail "W7a workload residue after success (profiles: $(generated_workload_profiles))"
fi

# ==============================================================================
# scenario W7b: cleanup after failure
# ==============================================================================
say "W7b: cleanup after a failing workload"
DOCKER_HELPER_SESSION_TOKEN="$WSA_TOKEN" \
  dh run --image alpine:3.24 --mount project:/mnt/project -- sh -ec 'exit 7' >/dev/null 2>&1
W7_FAIL_EC=$?
[ "$W7_FAIL_EC" -ne 0 ] \
  && acc_ok "W7b failing workload propagates the container failure (ec=$W7_FAIL_EC)" \
  || acc_fail "W7b failing workload unexpectedly succeeded"
wait_no_helper_containers || acc_fail "W7b helper containers remain after the failing run"
if workload_residue_clean; then
  acc_ok "W7b no generated workload profile/state remains after failure"
else
  acc_fail "W7b workload residue after failure (profiles: $(generated_workload_profiles))"
fi

# ==============================================================================
# scenario W6: backend-only forced-writable RO denied by AppArmor itself
# ==============================================================================
say "W6: backend-only forced-writable RO denied by AppArmor (live harness)"
if [ -x /tmp/uat-wla-proof.test ]; then
  mkdir -p /tmp/uat-wla-evidence
  if DOCKER_HELPER_LIVE_WORKLOAD_PROOF=1 WORKLOAD_EVIDENCE_DIR=/tmp/uat-wla-evidence \
      /tmp/uat-wla-proof.test -test.run 'TestLiveWorkloadAppArmor' -test.v \
      >/tmp/uat-wla-harness.log 2>&1; then
    acc_ok "W6 live harness passed: AppArmor denies the would-be-RO write (VFS view writable)"
  else
    acc_fail "W6 live harness failed: $(tail -8 /tmp/uat-wla-harness.log 2>/dev/null | redact)"
  fi
else
  acc_blocked "W6 live harness unavailable (BLOCKED recorded at compile time)"
fi

# ==============================================================================
# scenario W8: restart/reconciliation leaves no stale helper-owned state
# ==============================================================================
say "W8: restart/reconciliation"
systemctl restart docker-helper.service >/dev/null 2>&1 || true
for _ in $(seq 1 30); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
if wait_health \
    && [ "$(cat "/proc/$(systemctl show -p MainPID --value docker-helper.service)/attr/current" 2>/dev/null || true)" = "docker-helper-system (enforce)" ] \
    && workload_residue_clean; then
  acc_ok "W8 restart/reconciliation: daemon confined again, no stale workload profile/state"
else
  acc_fail "W8 restart left confinement or workload residue broken"
fi

# ==============================================================================
# scenario W9: the daemon profile is not widened to workload-RW policy
# ==============================================================================
say "W9: docker-helper-system profile not widened"
if [ "$(sha256sum /etc/apparmor.d/docker-helper-system | awk '{print $1}')" = "$DAEMON_PROFILE_SHA" ] \
    && aa-status 2>/dev/null | grep -q 'docker-helper-system' \
    && [ -z "$(generated_workload_profiles)" ]; then
  acc_ok "W9 packaged daemon profile unchanged; generated workload profiles are separate and unloaded"
else
  acc_fail "W9 daemon profile was widened or generated profiles linger"
fi

# ==============================================================================
# scenario W10: bounded audit window evidence
# ==============================================================================
say "W10: audit window carries the attributable denial and no unexpected denies"
# Required independent evidence: a fresh kernel DENIED record attributable to
# a generated workload profile (produced by the W6 forced-writable proof).
# The raw audit sources are read once and concatenated: /var/log/audit/audit.log
# first (authoritative while auditd drains the netlink queue), then dmesg, then
# journalctl -k as the last fallback; duplicates are removed so a record that
# reached two sinks is judged once. Every record is filtered to the UAT audit
# window.
AA_RAW_AUDIT="$(cat /var/log/audit/audit.log 2>/dev/null || true)
$(dmesg 2>/dev/null || true)"
if [ -z "$(printf '%s' "$AA_RAW_AUDIT" | tr -d '[:space:]')" ]; then
  AA_RAW_AUDIT="$(journalctl -k --since "@${AA_AUDIT_START_EPOCH}" --no-pager 2>/dev/null || true)"
fi
AA_RAW_AUDIT="$(printf '%s\n' "$AA_RAW_AUDIT" | awk '!seen[$0]++' || true)"
AA_WL_DENIAL_LINE="$(printf '%s\n' "$AA_RAW_AUDIT" \
  | grep 'apparmor="DENIED"' | grep -F 'profile="docker-helper-workload-' \
  | while IFS= read -r line; do
      ts="$(printf '%s\n' "$line" | audit_ts)"
      [ -n "$ts" ] && [ "$ts" -ge "$AA_AUDIT_START_EPOCH" ] && printf '%s\n' "$line"
    done | head -1 || true)"
if [ -n "$AA_WL_DENIAL_LINE" ]; then
  acc_ok "W10 attributable AppArmor DENIED record present: $AA_WL_DENIAL_LINE"
else
  acc_blocked "W10 no attributable workload-profile AppArmor DENIED record in the audit window (independent MAC denial evidence impossible)"
fi

# No unexpected denials under the daemon profile (the shipped adapter's
# allowlist of demonstrated benign probes is reused, never widened).
# shellcheck source=scripts/uat-mac-apparmor.sh
source "$REPO_DIR_IN/scripts/uat-mac-apparmor.sh"
SYSTEM_DENIALS="$(printf '%s\n' "$AA_RAW_AUDIT" \
  | grep 'apparmor="DENIED"' | grep -F 'profile="docker-helper-system"' || true)"
UNEXPECTED=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  ts="$(printf '%s\n' "$line" | audit_ts)"
  [ -n "$ts" ] && [ "$ts" -ge "$AA_AUDIT_START_EPOCH" ] || continue
  if is_allowlisted_deny "$line"; then
    info "allowlisted benign deny: $line"
  else
    printf '  UNEXPECTED deny: %s\n' "$line" >&2
    UNEXPECTED=$((UNEXPECTED + 1))
  fi
done <<< "$SYSTEM_DENIALS"
if [ "$UNEXPECTED" -eq 0 ]; then
  acc_ok "W10 no unexpected docker-helper-system DENIED records in the window"
else
  acc_fail "W10 unexpected docker-helper-system DENIED records: $UNEXPECTED"
fi

# ==============================================================================
# summary
# ==============================================================================
echo
echo "=========== RELEASE 2.2 APPARMOR WORKLOAD-MAC UAT SUMMARY (Ubuntu/DEB) ==========="
printf '  FAILS:    %d\n' "$FAIL_COUNT"
printf '  BLOCKED:  %d\n' "$BLOCKED_COUNT"
echo "=================================================================================="

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "RESULT: at least one mandatory AppArmor workload-MAC scenario FAILED" >&2
  exit 1
fi
if [ "$BLOCKED_COUNT" -gt 0 ]; then
  echo "RESULT: at least one mandatory workload-MAC scenario BLOCKED (required evidence not exercised)" >&2
  exit 2
fi
echo "RESULT: Release 2.2 AppArmor workload-MAC UAT PASSED"
