#!/usr/bin/env bash
#
# uat-access-modes.sh — canonical Release 2.2 functional access-mode UAT for
# the Ubuntu / DEB / AppArmor profile, running on the exact candidate DEB
# produced by the artifact gate (never rebuilt here).
#
# This is the ONE full functional matrix of the Release 2.2 issued
# filesystem-snapshot policy (the issue-#8 orchestrator-shaped tree). The
# common black-box UAT only carries a short access-mode smoke; the complete
# 12-point Phase 2.2.7 matrix runs once here on the exact candidate bytes:
#
#   1  project mounts read_write and a write persists;
#   2  pipeline-inputs mounts read_only and a read succeeds;
#   3  a writable request for pipeline-inputs is refused with the stable
#      read_only_root code BEFORE any workload is created (no container,
#      operation, pin, MAC, or runtime residue from the refusal);
#   4  a writable request on the run-root parent spanning the nested RO
#      region is refused with read_only_root (same fail-before-workload
#      residue proof);
#   5  a direct writable mount of project remains allowed;
#   6  a symlink alias of pipeline-inputs cannot widen the issued access
#      mode (the canonical resolved source keeps read_only);
#   7  a Principal-ceiling read_only region cannot be widened by a Launcher
#      read_write grant (read_only dominance through the meet);
#   8  most-specific read_write -> read_only -> read_write transitions give
#      the deterministic issued result (sub RW below RO parent);
#   9  legacy path-only policy stays read_write (the 2.x path-only scope
#      replacement input maps every path to read_write);
#   10 an existing Session keeps its issued snapshot after parent policy
#      mutations while a new Session gets the new mode (snapshot
#      immutability, both directions);
#   11 audit records carry canonical path/access facts and ownership
#      provenance, and never carry bearer/env/credential secrets;
#   12 no container/mount-pin/workload-MAC/runtime residue remains after the
#      scenarios.
#
# Plus the Release 2.2 build-side read-only policy proof:
#   B1 a Session whose issued snapshot carries the build context read_only
#      builds successfully through `docker-helper build`;
#   B2 the source tree is unchanged after the build (content, modes, mtimes);
#   B3 the build needed no read_write allowed-root authority (snapshot shows
#      only read_only), and the same Session's writable run exposure is
#      refused with read_only_root.
#
# The packaged control-plane surface is proven end-to-end on the candidate
# (one unit-matrix-free pass through the shipped CLI/API):
#   P1 config allowed-root add --access read_only (+ list);
#   P2 config allowed-root set-access (+ list);
#   P3 principal allowed-root add with omitted --access -> read_write;
#   P4 principal allowed-root add --access read_only;
#   P5 principal allowed-root set-access;
#   P6 rich Launcher scope replacement (PUT allowed_root_entries);
#   P7 the 2.x path-only allowed_roots projection is retained beside the
#      authoritative allowed_root_entries projection;
#   P8 session show renders the really-issued filesystem_snapshot entries.
#
# Contract for every scenario: PASS -> continue; FAIL -> gate red;
# BLOCKED -> required prerequisite unavailable -> gate red.
# Exit status: 0 = all PASS, 1 = any FAIL, 2 = any BLOCKED (and none FAIL).
#
# Env inputs:
#   UAT_VERSION          candidate version string (required by the caller)
#   UAT_ARTIFACT_PATH    exact candidate .deb produced by the gate (required)
#   UAT_ARTIFACT_SHA256  expected SHA-256 of the candidate .deb (required)
#   UAT_ALLOWED_ROOT     global allowed root (default /home/runner)
#   UAT_PRINCIPAL        OS user mapped to the principal (default runner)
#
# Requires: root, systemd, Docker, apparmor (package-owned daemon profile),
# python3. Exits as above.

set -uo pipefail

VERSION="${UAT_VERSION:-2.2.0-uat}"
ALLOWED_ROOT="${UAT_ALLOWED_ROOT:-/home/runner}"
PRINCIPAL="${UAT_PRINCIPAL:-runner}"
ARTIFACT_PATH_IN="${UAT_ARTIFACT_PATH:-}"
ARTIFACT_SHA256_IN="${UAT_ARTIFACT_SHA256:-}"

PREFIX="[uat-access-modes]"
say()  { printf '\n%s %s\n' "$PREFIX" "$*"; }

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

FAIL_COUNT=0
BLOCKED_COUNT=0
acc_ok() { printf '  ok:      %s\n' "$*"; }
acc_fail() { printf '  FAIL:    %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
acc_blocked() { printf '  BLOCKED: %s\n' "$*" >&2; BLOCKED_COUNT=$((BLOCKED_COUNT + 1)); }
scenario() { say "scenario $1"; }

dh() { /usr/bin/docker-helper "$@"; }
SOCK="/run/docker-helper/docker-helper.sock"

json_field() { grep -oP "\"$1\": ?\"\K[^\"]+" | head -1; }

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

# helper_container_count counts helper-owned containers (including exited --
# --rm removes them on exit, and a pre-admission refusal never creates one).
helper_container_count() {
  docker ps -a --filter 'label=com.dockerhelper.schema=1' -q | wc -l
}

# wait_no_helper_containers polls until no helper container is visible
# (bounded), so a finished --rm container's brief exit window cannot flake
# the final residue assertions.
wait_no_helper_containers() {
  local _i=0
  for _i in $(seq 1 40); do
    [ "$(helper_container_count)" = "0" ] && return 0
    sleep 0.25
  done
  return 1
}

# residue_state prints the observable workload residue so refusal and cleanup
# assertions compare the same fields.
residue_state() {
  printf 'containers=%s pins=%s wlmac=%s builds=%s\n' \
    "$(helper_container_count)" \
    "$(ls /run/docker-helper/mounts 2>/dev/null | wc -l)" \
    "$(ls /run/docker-helper/workload-mac 2>/dev/null | wc -l)" \
    "$(ls /run/docker-helper/builds 2>/dev/null | wc -l)"
}

# residue_unchanged BASE asserts the current residue equals the recorded base.
residue_unchanged() {
  local base="$1" now
  now="$(residue_state)"
  [ "$now" = "$base" ] || { printf '  residue drift: before %s after %s\n' "$base" "$now" >&2; return 1; }
}

# workload_profile_count counts loaded generated workload profiles.
workload_profile_count() {
  grep -c 'docker-helper-workload-' /sys/kernel/security/apparmor/profiles 2>/dev/null || true
}

# api METHOD PATH [BODY] — raw control-plane API call under the admin token
# (never printed; sent only as an Authorization header). Prints the body.
api() {
  local method="$1" path="$2" body="${3:-}" args=()
  if [ -n "$body" ]; then
    args=(-d "$body")
  fi
  curl --silent --max-time 5 \
    --unix-socket "$SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' -X "$method" "${args[@]}" \
    "http://localhost$path" 2>/dev/null || true
}

# issue_launcher_credential USER LAUNCHER_ID CREDFILE
issue_launcher_credential() {
  local out token
  out="$(dh launcher credential create --system --principal "$1" "$2" 2>/dev/null || true)"
  token="$(printf '%s' "$out" | json_field token)"
  [ -n "$token" ] || return 1
  printf '%s\n' "$token" > "$3"; chmod 600 "$3"
}

# create_session CREDFILE WORKSPACE — creates a launcher-credential session,
# prints the session ID on success (the bearer is stored in /tmp/uat-am-<id>).
create_session() {
  local cred="$1" ws="$2" out id
  out="$(dh session create --system --token-file "$cred" --workspace "$ws" --json 2>/dev/null || true)"
  id="$(printf '%s' "$out" | json_field id)"
  [ -n "$id" ] || return 1
  printf '%s' "$out" | json_field token > "/tmp/uat-am-tok-$id"; chmod 600 "/tmp/uat-am-tok-$id"
  printf '%s' "$id"
}

# show_snapshot SESSION_ID — prints the issued snapshot as PATH/ACCESS lines.
show_snapshot() {
  dh session show --system --id "$1" 2>/dev/null \
    | sed -n '/^FILESYSTEM SNAPSHOT/,$p' | tail -n +2
}

# snapshot_has SESSION_ID PATH ACCESS — true iff the issued snapshot carries
# the exact path/access entry.
snapshot_has() {
  local line
  line="$(printf '%s' "$(show_snapshot "$1")" | grep -F "$2" | head -1)"
  [ -n "$line" ] || return 1
  printf '%s\n' "$line" | grep -Eq "[[:space:]]$3\$"
}

# expect_read_only_root TOKEN SOURCE TARGET SNIPPET [BASE_RESIDUE] — runs a
# writable exposure request and asserts the stable read_only_root refusal,
# then (when a residue base is supplied) asserts no residue was created.
expect_read_only_root() {
  local token="$1" source="$2" target="$3" snippet="$4" base="${5:-}" out ec
  out="$(DOCKER_HELPER_SESSION_TOKEN="$token" \
    dh run --image alpine:3.24 --mount "$source:$target" -- sh -ec "$snippet" 2>&1)"
  ec=$?
  [ "$ec" -ne 0 ] || { printf '  writable request on %s unexpectedly succeeded\n' "$source" >&2; return 1; }
  printf '%s\n' "$out" | grep -q 'read_only_root' \
    || { printf '  refusal for %s is not read_only_root: %s\n' "$source" "$(printf '%s\n' "$out" | redact)" >&2; return 1; }
  if [ -n "$base" ]; then
    residue_unchanged "$base" || return 1
  fi
  return 0
}

cleanup() {
  systemctl stop docker-helper.service >/dev/null 2>&1 || true
  systemctl disable docker-helper.service >/dev/null 2>&1 || true
  apparmor_parser -R /etc/apparmor.d/docker-helper-system 2>/dev/null || true
  rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper /tmp/uat-am-api.out
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

if dpkg -i "$ARTIFACT_PATH_IN" >/tmp/uat-am-install.log 2>&1; then
  acc_ok "candidate DEB installed (sha256 verified: $ACTUAL_SHA)"
else
  echo "error: dpkg -i failed for candidate DEB (see /tmp/uat-am-install.log)" >&2
  exit 1
fi
dpkg -S /usr/bin/docker-helper >/dev/null 2>&1 \
  || { echo "error: binary not owned by the candidate package" >&2; exit 1; }

if dh init --allowed-root "$ALLOWED_ROOT" >/tmp/uat-am-init.log 2>&1; then
  acc_ok "system init (global ceiling: $ALLOWED_ROOT)"
else
  printf '  init output: %s\n' "$(redact </tmp/uat-am-init.log)" >&2
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
ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
[ -n "$ADMIN_TOKEN" ] || { echo "error: could not read the admin token" >&2; exit 1; }
docker pull alpine:3.24 >/dev/null 2>&1 || true

# ---- Release 2.2 orchestrator-shaped fixture tree ----------------------------
TREE="$ALLOWED_ROOT/run-root"
LEGACY="$ALLOWED_ROOT/legacy-rw"
BUILDROOT="$ALLOWED_ROOT/build-root"
rm -rf "$TREE" "$LEGACY" "$BUILDROOT"
mkdir -p "$TREE/project" "$TREE/pipeline-inputs/sub" "$TREE/pipeline-outputs" \
  "$TREE/global-ro" "$LEGACY" "$BUILDROOT"
printf 'project-file\n' > "$TREE/project/keep.txt"
printf 'ro-input\n' > "$TREE/pipeline-inputs/input.txt"
printf 'sub-write\n' > "$TREE/pipeline-inputs/sub/sub.txt"
printf 'build-input\n' > "$BUILDROOT/Dockerfile"
mkdir -p "$BUILDROOT/app"
printf 'app-src\n' > "$BUILDROOT/app/main.c"
chown -R "$PRINCIPAL:$PRINCIPAL" "$TREE" "$LEGACY" "$BUILDROOT"
chmod -R u+rwX,go+rX "$TREE" "$LEGACY" "$BUILDROOT"

# ==============================================================================
# scenario P: packaged control-plane surface (2.2 policy ownership)
# ==============================================================================
scenario "P: packaged control-plane surface"

# P1: config allowed-root add --access read_only (rich config entry).
if dh config allowed-root add --access read_only "$TREE/global-ro" >/dev/null 2>&1 \
    && dh config allowed-root list 2>/dev/null | grep -F "$TREE/global-ro" | grep -q 'read_only'; then
  acc_ok "P1 config allowed-root add --access read_only (list shows read_only)"
else
  acc_fail "P1 config allowed-root add --access read_only failed"
fi
# P2: config allowed-root set-access back to read_write.
if dh config allowed-root set-access "$TREE/global-ro" read_write >/dev/null 2>&1 \
    && dh config allowed-root list 2>/dev/null | grep -F "$TREE/global-ro" | grep -q 'read_write'; then
  acc_ok "P2 config allowed-root set-access (list shows read_write)"
else
  acc_fail "P2 config allowed-root set-access failed"
fi

# Principal with the 2.2 tree policy.
dh principal create --system --no-credential "$PRINCIPAL" >/dev/null 2>&1 || true
dh principal set --system "$PRINCIPAL" enabled true >/dev/null 2>&1 || true

# P3: principal allowed-root add with omitted --access -> read_write.
if dh principal allowed-root add --system "$PRINCIPAL" "$TREE" >/dev/null 2>&1 \
    && dh principal allowed-root list --system "$PRINCIPAL" 2>/dev/null \
      | grep -F "$TREE" | grep -q 'read_write'; then
  acc_ok "P3 principal allowed-root add with omitted --access -> read_write"
else
  acc_fail "P3 principal allowed-root add (omitted --access) failed"
fi

# P4: principal allowed-root add --access read_only for the RO region.
if dh principal allowed-root add --system --access read_only "$PRINCIPAL" "$TREE/pipeline-inputs" >/dev/null 2>&1 \
    && dh principal allowed-root list --system "$PRINCIPAL" 2>/dev/null \
      | grep -F "$TREE/pipeline-inputs" | grep -q 'read_only'; then
  acc_ok "P4 principal allowed-root add --access read_only"
else
  acc_fail "P4 principal allowed-root add --access read_only failed"
fi

# P5: principal allowed-root set-access (flip and flip back, exact contract).
if dh principal allowed-root set-access --system "$PRINCIPAL" "$TREE/pipeline-inputs" read_write >/dev/null 2>&1 \
    && dh principal allowed-root list --system "$PRINCIPAL" 2>/dev/null \
      | grep -F "$TREE/pipeline-inputs" | grep -q 'read_write' \
    && dh principal allowed-root set-access --system "$PRINCIPAL" "$TREE/pipeline-inputs" read_only >/dev/null 2>&1 \
    && dh principal allowed-root list --system "$PRINCIPAL" 2>/dev/null \
      | grep -F "$TREE/pipeline-inputs" | grep -q 'read_only'; then
  acc_ok "P5 principal allowed-root set-access (read_write -> read_only -> read_only)"
else
  acc_fail "P5 principal allowed-root set-access failed"
fi

# P6: rich Launcher scope replacement through PUT allowed_root_entries.
# A restricted launcher requires at least one allowed root at creation
# (restricted scope requires at least one allowed root), so create with the
# path-only single-root form (the create route carries legacy paths; rich
# entries are the allowed-roots PUT route's own form) and let the PUT below
# replace the whole set with the rich three-entry form.
MAIN_L_JSON="$(api POST "/principals/$PRINCIPAL/launchers" \
  '{"name":"main","scope":"restricted","allowed_roots":["'"$TREE"'"]}')"
MAIN_L_ID="$(printf '%s' "$MAIN_L_JSON" | json_field id)"
[ -n "$MAIN_L_ID" ] || { echo "error: launcher 'main' create failed: $MAIN_L_JSON" >&2; exit 1; }
RICH_BODY="$(printf '{"scope":"restricted","allowed_root_entries":[{"path":"%s","access":"read_write"},{"path":"%s","access":"read_only"},{"path":"%s","access":"read_write"}]}' \
  "$TREE" "$TREE/pipeline-inputs" "$TREE/pipeline-outputs")"
MAIN_PUT_HTTP="$(curl --silent --output /tmp/uat-am-put.out --write-out '%{http_code}' --max-time 5 \
  --unix-socket "$SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -X PUT -d "$RICH_BODY" \
  "http://localhost/principals/$PRINCIPAL/launchers/$MAIN_L_ID/allowed-roots" 2>/dev/null || true)"
# P6 asserts the projection via the indented JSON of launcher show: the access
# is on the line following the path, hence grep -A1.
if [ "$MAIN_PUT_HTTP" = 200 ] \
    && dh launcher show --system --principal "$PRINCIPAL" "$MAIN_L_ID" 2>/dev/null \
      | grep -A1 -F "\"path\": \"$TREE/pipeline-inputs\"" | grep -q '"access": "read_only"'; then
  acc_ok "P6 rich launcher scope replacement (PUT allowed_root_entries, access per entry)"
else
  acc_fail "P6 rich launcher scope replacement failed (http=$MAIN_PUT_HTTP: $(redact </tmp/uat-am-put.out 2>/dev/null))"
fi

# P7: the 2.x path-only allowed_roots projection is retained beside the
# authoritative allowed_root_entries projection.
MAIN_SHOW="$(dh launcher show --system --principal "$PRINCIPAL" "$MAIN_L_ID" 2>/dev/null || true)"
if printf '%s\n' "$MAIN_SHOW" | grep -q '"allowed_root_entries"' \
    && printf '%s\n' "$MAIN_SHOW" | grep -q '"allowed_roots"'; then
  acc_ok "P7 launcher projection keeps allowed_roots (2.x path-only) beside allowed_root_entries"
else
  acc_fail "P7 launcher projections wrong: $MAIN_SHOW"
fi

# Legacy path-only Launcher (point 9 policy owner): the 2.x path-only scope
# replacement input maps every path to read_write.
LEGACY_L_JSON="$(api POST "/principals/$PRINCIPAL/launchers" '{"name":"legacy","scope":"inherit"}')"
LEGACY_L_ID="$(printf '%s' "$LEGACY_L_JSON" | json_field id)"
[ -n "$LEGACY_L_ID" ] || { echo "error: launcher 'legacy' create failed: $LEGACY_L_JSON" >&2; exit 1; }
LEGACY_PUT_HTTP="$(curl --silent --output /tmp/uat-am-put2.out --write-out '%{http_code}' --max-time 5 \
  --unix-socket "$SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -X PUT \
  -d "{\"scope\":\"restricted\",\"allowed_roots\":[\"$LEGACY\"]}" \
  "http://localhost/principals/$PRINCIPAL/launchers/$LEGACY_L_ID/allowed-roots" 2>/dev/null || true)"
if [ "$LEGACY_PUT_HTTP" = 200 ] \
    && dh launcher show --system --principal "$PRINCIPAL" "$LEGACY_L_ID" 2>/dev/null \
      | grep -A1 -F "\"path\": \"$LEGACY\"" | grep -q '"access": "read_write"'; then
  acc_ok "P9 legacy path-only scope replacement maps the path to read_write"
else
  acc_fail "P9 legacy path-only scope replacement failed (http=$LEGACY_PUT_HTTP: $(redact </tmp/uat-am-put2.out 2>/dev/null))"
fi

# widen: a Launcher read_write grant on the Principal read_only region
# (point 7 policy owner: stored wider mode is ordinary state; the meet keeps
# the read_only).
WIDEN_L_JSON="$(api POST "/principals/$PRINCIPAL/launchers" '{"name":"widen","scope":"restricted"}')"
WIDEN_L_ID="$(printf '%s' "$WIDEN_L_JSON" | json_field id)"
[ -n "$WIDEN_L_ID" ] || { echo "error: launcher 'widen' create failed: $WIDEN_L_JSON" >&2; exit 1; }
dh launcher allowed-root add --system --principal "$PRINCIPAL" "$WIDEN_L_ID" "$TREE" >/dev/null 2>&1 || true
if dh launcher allowed-root add --system --principal "$PRINCIPAL" --access read_write \
    "$WIDEN_L_ID" "$TREE/pipeline-inputs" >/dev/null 2>&1; then
  acc_ok "P7 setup: launcher stored a read_write grant on the Principal read_only region"
else
  acc_fail "P7 setup: launcher could not store the read_write grant"
fi

# sub: most-specific RW->RO->RW transitions (point 8 policy owner).
SUB_L_JSON="$(api POST "/principals/$PRINCIPAL/launchers" '{"name":"sub","scope":"restricted"}')"
SUB_L_ID="$(printf '%s' "$SUB_L_JSON" | json_field id)"
[ -n "$SUB_L_ID" ] || { echo "error: launcher 'sub' create failed: $SUB_L_JSON" >&2; exit 1; }
dh launcher allowed-root add --system --principal "$PRINCIPAL" "$SUB_L_ID" "$TREE" >/dev/null 2>&1 || true
dh launcher allowed-root add --system --principal "$PRINCIPAL" --access read_only \
  "$SUB_L_ID" "$TREE/pipeline-inputs" >/dev/null 2>&1 || true
dh launcher allowed-root add --system --principal "$PRINCIPAL" --access read_write \
  "$SUB_L_ID" "$TREE/pipeline-inputs/sub" >/dev/null 2>&1 || true
acc_ok "P8 setup: launcher sub carries RW -> RO -> RW transitions"

# buildro: the read-only build policy owner (snapshot with only RO).
BUILD_L_JSON="$(api POST "/principals/$PRINCIPAL/launchers" '{"name":"buildro","scope":"restricted"}')"
BUILD_L_ID="$(printf '%s' "$BUILD_L_JSON" | json_field id)"
[ -n "$BUILD_L_ID" ] || { echo "error: launcher 'buildro' create failed: $BUILD_L_JSON" >&2; exit 1; }
if dh launcher allowed-root add --system --principal "$PRINCIPAL" --access read_only \
    "$BUILD_L_ID" "$BUILDROOT" >/dev/null 2>&1; then
  acc_ok "build-RO setup: launcher buildro carries a single read_only root"
else
  acc_fail "build-RO setup failed"
fi

# Launcher credentials for every test launcher.
issue_launcher_credential "$PRINCIPAL" "$MAIN_L_ID" /tmp/uat-am-cred-main \
  || { echo "error: main launcher credential issuance failed" >&2; exit 1; }
issue_launcher_credential "$PRINCIPAL" "$LEGACY_L_ID" /tmp/uat-am-cred-legacy \
  || { echo "error: legacy launcher credential issuance failed" >&2; exit 1; }
issue_launcher_credential "$PRINCIPAL" "$WIDEN_L_ID" /tmp/uat-am-cred-widen \
  || { echo "error: widen launcher credential issuance failed" >&2; exit 1; }
issue_launcher_credential "$PRINCIPAL" "$SUB_L_ID" /tmp/uat-am-cred-sub \
  || { echo "error: sub launcher credential issuance failed" >&2; exit 1; }
issue_launcher_credential "$PRINCIPAL" "$BUILD_L_ID" /tmp/uat-am-cred-build \
  || { echo "error: buildro launcher credential issuance failed" >&2; exit 1; }

# ==============================================================================
# scenario S: issued snapshots (P8: session show really-issued entries)
# ==============================================================================
scenario "S: issued Session snapshots (session show)"

SA_ID="$(create_session /tmp/uat-am-cred-main "$TREE")" \
  || { echo "error: session SA creation failed" >&2; exit 1; }
SB_ID="$(create_session /tmp/uat-am-cred-widen "$TREE")" \
  || { echo "error: session SB creation failed" >&2; exit 1; }
SC_ID="$(create_session /tmp/uat-am-cred-sub "$TREE")" \
  || { echo "error: session SC creation failed" >&2; exit 1; }
SL_ID="$(create_session /tmp/uat-am-cred-legacy "$LEGACY")" \
  || { echo "error: session SL creation failed" >&2; exit 1; }
SD_ID="$(create_session /tmp/uat-am-cred-build "$BUILDROOT")" \
  || { echo "error: session SD creation failed" >&2; exit 1; }
acc_ok "sessions created: main=$SA_ID widen=$SB_ID sub=$SC_ID legacy=$SL_ID build=$SD_ID"

if snapshot_has "$SA_ID" "$TREE/project" read_write \
    && snapshot_has "$SA_ID" "$TREE/pipeline-inputs" read_only \
    && snapshot_has "$SA_ID" "$TREE/pipeline-outputs" read_write \
    && snapshot_has "$SB_ID" "$TREE/pipeline-inputs" read_only \
    && snapshot_has "$SC_ID" "$TREE/pipeline-inputs" read_only \
    && snapshot_has "$SC_ID" "$TREE/pipeline-inputs/sub" read_write \
    && snapshot_has "$SL_ID" "$LEGACY" read_write \
    && snapshot_has "$SD_ID" "$BUILDROOT" read_only; then
  acc_ok "P8 issued snapshots match the 2.2 hierarchy (session show PATH/ACCESS)"
else
  acc_fail "P8 issued snapshot content wrong (SA: $(show_snapshot "$SA_ID" | tr '\n' '; '))"
fi

# ==============================================================================
# scenario 1-3: RW project, RO pipeline-inputs, read_only_root refusal
# ==============================================================================
scenario "1-3: project RW / pipeline-inputs RO / read_only_root"

SA_TOKEN="$(cat "/tmp/uat-am-tok-$SA_ID")"
RW_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SA_TOKEN" \
  dh run --image alpine:3.24 --mount project:/mnt/project -- \
  sh -ec 'echo rw-write > /mnt/project/written.txt && cat /mnt/project/keep.txt')" \
  || acc_fail "1 project writable mount failed: $RW_OUT"
if [ -f "$TREE/project/written.txt" ] && [ "$(cat "$TREE/project/written.txt")" = "rw-write" ]; then
  acc_ok "1 project mounted read_write and the write persisted"
else
  acc_fail "1 project write did not persist to the host"
fi

RO_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SA_TOKEN" \
  dh run --image alpine:3.24 --mount pipeline-inputs:/mnt/inputs:ro -- \
  sh -ec 'test "$(cat /mnt/inputs/input.txt)" = "ro-input" && echo RO-READ-OK')" \
  || acc_fail "2 pipeline-inputs read-only mount failed: $RO_OUT"
printf '%s\n' "$RO_OUT" | grep -q 'RO-READ-OK' \
  && acc_ok "2 pipeline-inputs mounted read_only and the read succeeded" \
  || acc_fail "2 pipeline-inputs read did not reach RO-READ-OK"

RESIDUE_BASE="$(residue_state)"
if expect_read_only_root "$SA_TOKEN" pipeline-inputs /mnt/inputs 'echo x > /mnt/inputs/forbidden.txt' "$RESIDUE_BASE"; then
  acc_ok "3 writable pipeline-inputs refused with read_only_root before workload creation"
else
  acc_fail "3 writable pipeline-inputs refusal wrong (base: $RESIDUE_BASE)"
fi
[ ! -e "$TREE/pipeline-inputs/forbidden.txt" ] \
  || acc_fail "3 forbidden host-side file was created"

# ==============================================================================
# scenario 4: writable parent over nested RO refused
# ==============================================================================
scenario "4: writable run-root parent over nested RO"
RESIDUE_BASE="$(residue_state)"
if expect_read_only_root "$SA_TOKEN" . /mnt/tree 'echo x > /mnt/tree/pipeline-outputs/x.txt' "$RESIDUE_BASE"; then
  acc_ok "4 writable run-root parent refused with read_only_root before workload creation"
else
  acc_fail "4 writable parent refusal wrong (base: $RESIDUE_BASE)"
fi

# ==============================================================================
# scenario 5: direct RW mount of project remains allowed
# ==============================================================================
scenario "5: direct project RW remains allowed"
P5_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SA_TOKEN" \
  dh run --image alpine:3.24 --mount project:/mnt/project -- sh -ec 'test -w /mnt/project && echo PROJECT-RW-OK')" \
  || acc_fail "5 direct project RW mount failed: $P5_OUT"
printf '%s\n' "$P5_OUT" | grep -q 'PROJECT-RW-OK' \
  && acc_ok "5 direct project RW mount allowed" \
  || acc_fail "5 direct project RW check failed"

# ==============================================================================
# scenario 6: symlink alias cannot widen the issued mode
# ==============================================================================
scenario "6: symlink alias cannot widen access"
ln -sfn pipeline-inputs "$TREE/alias-inputs"
chown -h "$PRINCIPAL:$PRINCIPAL" "$TREE/alias-inputs"
RESIDUE_BASE="$(residue_state)"
if expect_read_only_root "$SA_TOKEN" alias-inputs /mnt/alias 'echo x > /mnt/alias/forbidden.txt' "$RESIDUE_BASE"; then
  acc_ok "6 writable symlink alias refused with read_only_root (canonical source keeps read_only)"
else
  acc_fail "6 symlink alias widening was not refused (base: $RESIDUE_BASE)"
fi
ALIAS_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SA_TOKEN" \
  dh run --image alpine:3.24 --mount alias-inputs:/mnt/alias:ro -- \
  sh -ec 'test "$(cat /mnt/alias/input.txt)" = "ro-input" && echo ALIAS-RO-OK')" \
  || acc_fail "6 read-only symlink alias mount failed: $ALIAS_OUT"
printf '%s\n' "$ALIAS_OUT" | grep -q 'ALIAS-RO-OK' \
  && acc_ok "6 read-only symlink alias mount allowed" \
  || acc_fail "6 read-only alias check failed"

# ==============================================================================
# scenario 7: Principal RO ceiling cannot be widened by a Launcher RW grant
# ==============================================================================
scenario "7: principal read_only cannot be widened by launcher read_write"
SB_TOKEN="$(cat "/tmp/uat-am-tok-$SB_ID")"
RESIDUE_BASE="$(residue_state)"
if expect_read_only_root "$SB_TOKEN" pipeline-inputs /mnt/inputs 'echo x > /mnt/inputs/forbidden2.txt' "$RESIDUE_BASE"; then
  acc_ok "7 launcher RW grant did not widen the Principal read_only region (read_only_root)"
else
  acc_fail "7 launcher RW grant widened the Principal read_only region (base: $RESIDUE_BASE)"
fi

# ==============================================================================
# scenario 8: most-specific RW -> RO -> RW transitions are deterministic
# ==============================================================================
scenario "8: most-specific transitions (sub RW below RO parent)"
SC_TOKEN="$(cat "/tmp/uat-am-tok-$SC_ID")"
SUB_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SC_TOKEN" \
  dh run --image alpine:3.24 --mount pipeline-inputs/sub:/mnt/sub -- \
  sh -ec 'echo sub-write > /mnt/sub/new.txt && cat /mnt/sub/sub.txt')" \
  || acc_fail "8 sub read_write mount failed: $SUB_OUT"
if [ -f "$TREE/pipeline-inputs/sub/new.txt" ] && [ "$(cat "$TREE/pipeline-inputs/sub/new.txt")" = "sub-write" ]; then
  acc_ok "8 most-specific sub read_write honored below the RO parent"
else
  acc_fail "8 sub write did not persist (SC: $(show_snapshot "$SC_ID" | tr '\n' '; '))"
fi
SC_RO_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SC_TOKEN" \
  dh run --image alpine:3.24 --mount pipeline-inputs:/mnt/inputs:ro -- \
  sh -ec 'test "$(cat /mnt/inputs/input.txt)" = "ro-input" && echo SUB-RO-OK')" \
  || acc_fail "8 RO parent read failed under the RW sub: $SC_RO_OUT"
printf '%s\n' "$SC_RO_OUT" | grep -q 'SUB-RO-OK' \
  && acc_ok "8 RO parent honored beside the RW sub" \
  || acc_fail "8 RO parent check failed"
RESIDUE_BASE="$(residue_state)"
if expect_read_only_root "$SC_TOKEN" pipeline-inputs /mnt/inputs 'echo x > /mnt/inputs/forbidden3.txt' "$RESIDUE_BASE"; then
  acc_ok "8 writable parent (RO) still refused while its sub is RW"
else
  acc_fail "8 writable RO parent was not refused (base: $RESIDUE_BASE)"
fi

# ==============================================================================
# scenario 9: legacy path-only policy stays read_write
# ==============================================================================
scenario "9: legacy path-only policy remains read_write"
SL_TOKEN="$(cat "/tmp/uat-am-tok-$SL_ID")"
LEGACY_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SL_TOKEN" \
  dh run --image alpine:3.24 --mount .:/mnt/legacy -- \
  sh -ec 'echo legacy-write > /mnt/legacy/written.txt && echo LEGACY-RW-OK')" \
  || acc_fail "9 legacy path-only writable mount failed: $LEGACY_OUT"
printf '%s\n' "$LEGACY_OUT" | grep -q 'LEGACY-RW-OK' \
  && [ -f "$LEGACY/written.txt" ] \
  && acc_ok "9 legacy path-only root remained read_write" \
  || acc_fail "9 legacy path-only write did not persist"

# ==============================================================================
# scenario 10: snapshot immutability across parent policy mutations
# ==============================================================================
scenario "10: existing Session keeps its snapshot; new Sessions get the new mode"
if dh principal allowed-root set-access --system "$PRINCIPAL" "$TREE/project" read_only >/dev/null 2>&1; then
  acc_ok "10 parent policy mutation: project narrowed to read_only"
else
  acc_fail "10 principal set-access for the immutability pair failed"
fi
SA2_ID="$(create_session /tmp/uat-am-cred-main "$TREE")" \
  || { echo "error: session SA2 creation failed" >&2; exit 1; }
SA2_TOKEN="$(cat "/tmp/uat-am-tok-$SA2_ID")"
IMM_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SA_TOKEN" \
  dh run --image alpine:3.24 --mount project:/mnt/project -- \
  sh -ec 'echo still-writable > /mnt/project/imm.txt && echo OLD-SNAPSHOT-WRITES')" \
  || acc_fail "10 old session lost its issued read_write (immutability broken): $IMM_OUT"
printf '%s\n' "$IMM_OUT" | grep -q 'OLD-SNAPSHOT-WRITES' \
  && acc_ok "10 existing Session kept its issued read_write after the mutation" \
  || acc_fail "10 old-session write did not persist"
RESIDUE_BASE="$(residue_state)"
if expect_read_only_root "$SA2_TOKEN" project /mnt/project 'echo x > /mnt/project/forbidden.txt' "$RESIDUE_BASE"; then
  acc_ok "10 new Session got the new read_only mode (read_only_root)"
else
  acc_fail "10 new Session did not receive the narrowed mode (base: $RESIDUE_BASE)"
fi
if dh principal allowed-root set-access --system "$PRINCIPAL" "$TREE/project" read_write >/dev/null 2>&1; then
  if snapshot_has "$SA2_ID" "$TREE/project" read_only; then
    acc_ok "10 issued snapshot is immutable: SA2 keeps read_only after the parent was restored"
  else
    acc_fail "10 issued snapshot changed after a parent restore (immutability broken)"
  fi
  SA3_ID="$(create_session /tmp/uat-am-cred-main "$TREE")" \
    || { echo "error: session SA3 creation failed" >&2; exit 1; }
  SA3_TOKEN="$(cat "/tmp/uat-am-tok-$SA3_ID")"
  SA3_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SA3_TOKEN" \
    dh run --image alpine:3.24 --mount project:/mnt/project -- sh -ec 'echo NEW-MODE-OK')" \
    || acc_fail "10 restored session failed: $SA3_OUT"
  printf '%s\n' "$SA3_OUT" | grep -q 'NEW-MODE-OK' \
    && acc_ok "10 sessions created after the restore get the restored read_write" \
    || acc_fail "10 restored-mode session check failed"
else
  acc_fail "10 restore of project read_write failed"
fi

# ==============================================================================
# scenario B: build over a read-only-only snapshot
# ==============================================================================
scenario "B: build over a read-only snapshot"
SD_TOKEN="$(cat "/tmp/uat-am-tok-$SD_ID")"
SNAP_BEFORE="$(cd "$BUILDROOT" && find . -printf '%p %m %T@\n' 2>/dev/null | sort)"
BUILD_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SD_TOKEN" \
  dh build --context . --dockerfile Dockerfile --image uat-am-robuild:2.2 2>&1)" \
  || acc_fail "B1 build over the read-only snapshot failed: $(printf '%s\n' "$BUILD_OUT" | redact | tail -3)"
SNAP_AFTER="$(cd "$BUILDROOT" && find . -printf '%p %m %T@\n' 2>/dev/null | sort)"
if [ "$SNAP_BEFORE" = "$SNAP_AFTER" ]; then
  acc_ok "B2 source tree unchanged after the build (content, modes, mtimes)"
else
  acc_fail "B2 source tree changed during the read-only build"
fi
if snapshot_has "$SD_ID" "$BUILDROOT" read_only \
    && ! show_snapshot "$SD_ID" | grep -q read_write; then
  acc_ok "B3 build needed no read_write authority (snapshot carries only read_only)"
else
  acc_fail "B3 build snapshot carries read_write authority"
fi
RESIDUE_BASE="$(residue_state)"
if expect_read_only_root "$SD_TOKEN" . /mnt/buildroot 'echo x > /mnt/buildroot/forbidden.txt' "$RESIDUE_BASE"; then
  acc_ok "B3 writable run exposure of the same Session is refused (read_only_root)"
else
  acc_fail "B3 writable run exposure of the RO build Session was not refused"
fi

# ==============================================================================
# scenario A: audit facts without secrets
# ==============================================================================
scenario "A: audit carries canonical path/access facts and no secrets"
AUDIT_SINCE="$(date -u +'%Y-%m-%d %H:%M:%S')"
# One positive and one negative operation inside a fresh bounded window.
AUD_NEG_BASE="$(residue_state)"
expect_read_only_root "$SA_TOKEN" pipeline-inputs /mnt/inputs 'echo x > /mnt/inputs/forbidden4.txt' "$AUD_NEG_BASE" \
  || acc_fail "A negative audit precondition failed"
AUD_POS_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SA_TOKEN" \
  dh run --image alpine:3.24 --mount project:/mnt/project -- sh -ec 'echo AUDIT-WINDOW-OK')" \
  || acc_fail "A positive audit precondition failed: $AUD_POS_OUT"
sleep 1
AUDIT_JSON="$(journalctl --utc -u docker-helper.service --since "$AUDIT_SINCE" --no-pager 2>/dev/null \
  | grep '"stream":"audit"' || true)"
if [ -z "$AUDIT_JSON" ]; then
  acc_blocked "no audit records in the bounded window (audit proof impossible)"
else
  START_LINE="$(printf '%s\n' "$AUDIT_JSON" | grep '"event":"run.start"' | tail -1 || true)"
  if printf '%s\n' "$START_LINE" | grep -q '"resolved_source"' \
      && printf '%s\n' "$START_LINE" | grep -q '"access":"read_write"' \
      && printf '%s\n' "$START_LINE" | grep -q "\"principal_name\":\"$PRINCIPAL\"" \
      && printf '%s\n' "$START_LINE" | grep -q "\"session_id\":\"$SA_ID\""; then
    acc_ok "A run.start carries canonical source/access facts and ownership provenance"
  else
    acc_fail "A run.start audit facts wrong: $START_LINE"
  fi
  REJECT_LINE="$(printf '%s\n' "$AUDIT_JSON" | grep '"event":"run.rejected"' | grep read_only_root | tail -1 || true)"
  if printf '%s\n' "$REJECT_LINE" | grep -q "\"resolved_source\":\"$TREE/pipeline-inputs\"" \
      && printf '%s\n' "$REJECT_LINE" | grep -q '"access":"read_only"' \
      && printf '%s\n' "$REJECT_LINE" | grep -q '"writable_allowed":false'; then
    acc_ok "A run.rejected carries the offending canonical exposure facts"
  else
    acc_fail "A run.rejected audit facts wrong: $REJECT_LINE"
  fi
  if printf '%s\n' "$AUDIT_JSON" | grep -q 'dhc_'; then
    acc_fail "A audit leaked a credential bearer"
  fi
  if printf '%s\n' "$AUDIT_JSON" | grep -q 'dht_'; then
    acc_fail "A audit leaked a session/admin bearer"
  fi
  acc_ok "A audit contains no bearer material"
fi

# ==============================================================================
# scenario Z: residue and cleanup
# ==============================================================================
scenario "Z: no container/mount-pin/workload-MAC/runtime residue"
for sid in "$SA_ID" "$SB_ID" "$SC_ID" "$SL_ID" "$SD_ID" "${SA2_ID:-}" "${SA3_ID:-}"; do
  [ -n "$sid" ] || continue
  dh session delete --system --id "$sid" >/dev/null 2>&1 || acc_fail "Z session $sid delete failed"
done
if wait_no_helper_containers; then
  acc_ok "Z no helper-owned containers remain"
else
  acc_fail "Z helper-owned containers remain ($(docker ps -a --filter 'label=com.dockerhelper.schema=1' --format '{{.ID}} {{.Status}}' | head -3))"
fi
[ "$(ls /run/docker-helper/mounts 2>/dev/null | wc -l)" = "0" ] \
  && acc_ok "Z no mount pins remain" \
  || acc_fail "Z mount pins remain: $(ls /run/docker-helper/mounts 2>/dev/null | head -3)"
[ "$(ls /run/docker-helper/workload-mac 2>/dev/null | wc -l)" = "0" ] \
  && acc_ok "Z no workload-MAC runtime state remains" \
  || acc_fail "Z workload-MAC runtime state remains"
[ "$(ls /run/docker-helper/builds 2>/dev/null | wc -l)" = "0" ] \
  && acc_ok "Z no build staging remains" \
  || acc_fail "Z build staging remains"
[ "$(ls /run/docker-helper/sessions 2>/dev/null | wc -l)" = "0" ] \
  && acc_ok "Z no session runtime directories remain" \
  || acc_fail "Z session runtime directories remain"
[ "$(ls /var/lib/docker-helper/workload-mac 2>/dev/null | wc -l)" = "0" ] \
  && acc_ok "Z no durable workload-MAC records remain" \
  || acc_fail "Z durable workload-MAC records remain"
[ "$(workload_profile_count)" = "0" ] \
  && acc_ok "Z no generated workload profiles remain loaded" \
  || acc_fail "Z generated workload profiles still loaded"

# ==============================================================================
# summary
# ==============================================================================
echo
echo "================= RELEASE 2.2 ACCESS-MODE UAT SUMMARY (Ubuntu/DEB/AppArmor) ================="
printf '  FAILS:    %d\n' "$FAIL_COUNT"
printf '  BLOCKED:  %d\n' "$BLOCKED_COUNT"
echo "======================================================================"

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "RESULT: at least one mandatory access-mode scenario FAILED" >&2
  exit 1
fi
if [ "$BLOCKED_COUNT" -gt 0 ]; then
  echo "RESULT: at least one mandatory access-mode scenario BLOCKED (required scenario not exercised)" >&2
  exit 2
fi
echo "RESULT: Release 2.2 access-mode UAT PASSED"
exit 0
