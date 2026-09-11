#!/usr/bin/env bash
#
# uat-access-modes.sh — canonical Release 2.2 functional access-mode UAT for
# the Ubuntu / DEB / AppArmor profile, running on the exact candidate DEB
# produced by the artifact gate (never rebuilt here).
#
# This is the ONE full functional matrix of the Release 2.2 issued
# filesystem-snapshot policy (the issue-#8 orchestrator-shaped tree). The
# common black-box UAT only carries a short access-mode smoke; the canonical
# full Release 2.2 functional access-mode matrix runs once here on the exact
# candidate bytes, with the explicit scenario inventory below:
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
#      scenarios, no active Session remains (fail-closed session-list
#      inventory), and the durable database carries no Session or snapshot
#      rows (sessions, session_filesystem_snapshot_entries,
#      session_filesystem_snapshot_meta all structurally empty, fail closed);
#   13 a Launcher credential creates a dynamically named run workspace and
#      narrows the Session at issuance time through --filesystem-entry
#      ('.' read-only, project/pipeline-outputs read-write,
#      pipeline-inputs read-only); the issued snapshot exposes exactly the
#      effective semantics (a redundant read-only entry may be normalized
#      away), the narrowing is enforced at runtime, and a second session on
#      the same run workspace without filesystem_entries keeps the inherited
#      read-write behavior;
#   14 an attempted issuance-time widening (read_write under the parent
#      read_only ceiling) is refused 400 invalid_filesystem_policy before
#      the Session exists, leaving no Session, container, pin, or
#      workload-MAC residue, with the bounded non-disclosing public message,
#      no bearer/Session material in the response, and the matching
#      session.create invalid_filesystem_policy audit record of a bounded
#      window opened before the attempt (no session_id, no bearer);
#   15 a global read_only ceiling cannot be widened downstream by Principal
#      and Launcher read_write grants (global -> Principal -> Launcher
#      composition on a really issued Session: effective read_only snapshot,
#      read-only exposure succeeds, writable exposure refused read_only_root
#      before workload, no residue);
#   16 Admin and Principal credential authorities get the same issuance-time
#      narrowing symmetry the Launcher credential proves in scenario N: a
#      valid narrowing issues the same effective snapshot and a widening
#      request is refused 400 invalid_filesystem_policy with no new Session
#      (no authority's refusal is taken as another authority's proof);
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Shared measurement primitives only (structural rich allowed-root JSON parse,
# fail-closed residue inventory); the script's own helpers below win.
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

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

# Residue inventory: the shared fail-closed primitives from
# uat-regression-lib.sh (helper_container_count, wait_no_helper_containers,
# inventory_count) own the three-state ABSENT/PRESENT/UNKNOWN contract;
# "cannot inspect" is never "clean". residue_state composes this scenario's
# inventories (it additionally tracks build staging) and inherits the
# fail-closed contract: any inventory failure exits 1, never reports clean.
residue_state() {
  local containers pins wlmac builds
  containers="$(helper_container_count)" || return 1
  pins="$(inventory_count /run/docker-helper/mounts)" || return 1
  wlmac="$(inventory_count /run/docker-helper/workload-mac)" || return 1
  builds="$(inventory_count /run/docker-helper/builds)" || return 1
  printf 'containers=%s pins=%s wlmac=%s builds=%s\n' \
    "$containers" "$pins" "$wlmac" "$builds"
}

# residue_unchanged BASE asserts the current residue equals the recorded base.
# Fail-closed: an unavailable inventory is never an unchanged policy.
residue_unchanged() {
  local base="$1" now
  now="$(residue_state)" || { printf '  residue inventory unavailable for the drift check\n' >&2; return 1; }
  [ "$now" = "$base" ] || { printf '  residue drift: before %s after %s\n' "$base" "$now" >&2; return 1; }
}

# workload_profile_count prints the number of loaded generated workload
# profiles. Fail-closed: a profiles inventory read failure is an inventory
# error (exit 1), never a zero count. grep -c reports the authoritative count
# for both exit 0 (matches) and exit 1 (no matches); only a read error (exit
# 2) means the count is unknown.
workload_profile_count() {
  local out rc
  out="$(grep -c 'docker-helper-workload-' /sys/kernel/security/apparmor/profiles 2>/dev/null)"
  rc=$?
  if [ "$rc" -eq 2 ]; then
    printf '  workload profile inventory unavailable (cannot read the loaded profiles)\n' >&2
    return 1
  fi
  printf '%s\n' "$out"
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
  out="$(dh session create --system --token-file "$cred" --workspace "$ws" --json 2>&1 || true)"
  id="$(printf '%s' "$out" | json_field id)"
  if [ -z "$id" ]; then
    printf 'session create failed (workspace %s): %s\n' \
      "$ws" "$(printf '%s\n' "$out" | redact | tail -3)" >&2
    return 1
  fi
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

# snapshot_lacks asserts the entry is absent from the issued snapshot. The
# 2.2 normalization drops entries whose access equals their containing
# region, so redundant read_write children of a read_write region must not
# appear even though they were granted.
snapshot_lacks() {
  ! printf '%s' "$(show_snapshot "$1")" | grep -Fq "$2"
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
# The Session workspace must be a proper subdirectory of an allowed root, not
# the root itself (2.2 create-session contract), so every launcher root below
# hosts a dedicated workspace directory that the scenarios run against.
TREE="$ALLOWED_ROOT/run-root"
WS="$TREE/work"
LEGACY="$ALLOWED_ROOT/legacy-rw"
LEGACY_WS="$LEGACY/work"
BUILDROOT="$ALLOWED_ROOT/build-root"
BUILD_WS="$BUILDROOT/work"
rm -rf "$TREE" "$LEGACY" "$BUILDROOT"
mkdir -p "$WS/project" "$WS/pipeline-inputs/sub" "$WS/pipeline-outputs" \
  "$TREE/global-ro" "$LEGACY_WS" "$BUILD_WS"
printf 'project-file\n' > "$WS/project/keep.txt"
printf 'ro-input\n' > "$WS/pipeline-inputs/input.txt"
printf 'sub-write\n' > "$WS/pipeline-inputs/sub/sub.txt"
printf 'FROM scratch\nCOPY app/main.c /main.c\n' > "$BUILD_WS/Dockerfile"
mkdir -p "$BUILD_WS/app"
printf 'app-src\n' > "$BUILD_WS/app/main.c"
chown -R "$PRINCIPAL:$PRINCIPAL" "$TREE" "$LEGACY" "$BUILDROOT"
chmod -R u+rwX,go+rX "$TREE" "$LEGACY" "$BUILDROOT"

# ==============================================================================
# scenario P: packaged control-plane surface (2.2 policy ownership)
# ==============================================================================
scenario "P: packaged control-plane surface"

# P1: config allowed-root add --access read_only (rich config entry). The
# access is verified through the rich --json projection, parsed structurally.
if dh config allowed-root add --access read_only "$TREE/global-ro" >/dev/null 2>&1 \
    && [ "$(dh config allowed-root list --json 2>/dev/null | allowed_root_json_access "$TREE/global-ro")" = read_only ]; then
  acc_ok "P1 config allowed-root add --access read_only (rich projection shows read_only)"
else
  acc_fail "P1 config allowed-root add --access read_only failed"
fi
# P2: config allowed-root set-access back to read_write.
if dh config allowed-root set-access "$TREE/global-ro" read_write >/dev/null 2>&1 \
    && [ "$(dh config allowed-root list --json 2>/dev/null | allowed_root_json_access "$TREE/global-ro")" = read_write ]; then
  acc_ok "P2 config allowed-root set-access (rich projection shows read_write)"
else
  acc_fail "P2 config allowed-root set-access failed"
fi
# The default human list is separately proven as the 2.1-compatible surface:
# exactly one canonical path per line, no ACCESS column (the access lives in
# the rich --json projection above).
AM_HUMAN_LIST="$(dh config allowed-root list 2>/dev/null || true)"
if printf '%s\n' "$AM_HUMAN_LIST" | grep -qx "$ALLOWED_ROOT" \
    && printf '%s\n' "$AM_HUMAN_LIST" | grep -qx "$TREE/global-ro"; then
  acc_ok "P1/P2 default human list keeps the 2.1 one-path-per-line contract (no ACCESS column)"
else
  acc_fail "P1/P2 default human list lost the 2.1 one-path-per-line contract: $AM_HUMAN_LIST"
fi

# Principal with the 2.2 tree policy.
dh principal create --system --no-credential "$PRINCIPAL" >/dev/null 2>&1 || true
dh principal set --system "$PRINCIPAL" enabled true >/dev/null 2>&1 || true

# P3: principal allowed-root add with omitted --access -> read_write.
if dh principal allowed-root add --system "$PRINCIPAL" "$TREE" >/dev/null 2>&1 \
    && [ "$(dh principal allowed-root list --system --json "$PRINCIPAL" 2>/dev/null | allowed_root_json_access "$TREE")" = read_write ]; then
  acc_ok "P3 principal allowed-root add with omitted --access -> read_write (rich projection)"
else
  acc_fail "P3 principal allowed-root add (omitted --access) failed"
fi

# P4: principal allowed-root add --access read_only for the RO region.
if dh principal allowed-root add --system --access read_only "$PRINCIPAL" "$WS/pipeline-inputs" >/dev/null 2>&1 \
    && [ "$(dh principal allowed-root list --system --json "$PRINCIPAL" 2>/dev/null | allowed_root_json_access "$WS/pipeline-inputs")" = read_only ]; then
  acc_ok "P4 principal allowed-root add --access read_only (rich projection shows read_only)"
else
  acc_fail "P4 principal allowed-root add --access read_only failed"
fi

# P4b: the Principal owns the project path itself (read_write) so scenario 10
# can narrow exactly this root with set-access (set-access requires an
# existing root; it cannot reach into the parent TREE entry).
if dh principal allowed-root add --system --access read_write "$PRINCIPAL" \
    "$WS/project" >/dev/null 2>&1 \
    && [ "$(dh principal allowed-root list --system --json "$PRINCIPAL" 2>/dev/null | allowed_root_json_access "$WS/project")" = read_write ]; then
  acc_ok "P4b principal owns the project root (read_write, rich projection)"
else
  acc_fail "P4b principal project-root add failed"
fi

# P5: principal allowed-root set-access (flip and flip back, exact contract).
# The mutations run unconditionally and each verification is its own
# collect-all step: a failed verification must never skip the flip-back
# mutation and leave the fixture (pipeline-inputs = read_write) corrupted for
# the downstream read_only scenarios.
if dh principal allowed-root set-access --system "$PRINCIPAL" "$WS/pipeline-inputs" read_write >/dev/null 2>&1; then
  acc_ok "P5 set-access to read_write accepted"
else
  acc_fail "P5 set-access to read_write failed"
fi
if [ "$(dh principal allowed-root list --system --json "$PRINCIPAL" 2>/dev/null | allowed_root_json_access "$WS/pipeline-inputs")" = read_write ]; then
  acc_ok "P5 rich projection shows read_write after the flip"
else
  acc_fail "P5 read_write verification failed"
fi
if dh principal allowed-root set-access --system "$PRINCIPAL" "$WS/pipeline-inputs" read_only >/dev/null 2>&1; then
  acc_ok "P5 set-access back to read_only accepted"
else
  acc_fail "P5 set-access back to read_only failed"
fi
if [ "$(dh principal allowed-root list --system --json "$PRINCIPAL" 2>/dev/null | allowed_root_json_access "$WS/pipeline-inputs")" = read_only ]; then
  acc_ok "P5 rich projection shows read_only after the flip back"
else
  acc_fail "P5 read_only verification failed"
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
RICH_BODY="$(printf '{"scope":"restricted","allowed_root_entries":[{"path":"%s","access":"read_write"},{"path":"%s","access":"read_write"},{"path":"%s","access":"read_only"},{"path":"%s","access":"read_write"}]}' \
  "$TREE" "$WS/project" "$WS/pipeline-inputs" "$WS/pipeline-outputs")"
MAIN_PUT_HTTP="$(curl --silent --output /tmp/uat-am-put.out --write-out '%{http_code}' --max-time 5 \
  --unix-socket "$SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -X PUT -d "$RICH_BODY" \
  "http://localhost/principals/$PRINCIPAL/launchers/$MAIN_L_ID/allowed-roots" 2>/dev/null || true)"
# P6 asserts the projection via the indented JSON of launcher show: the access
# is on the line following the path, hence grep -A1.
if [ "$MAIN_PUT_HTTP" = 200 ] \
    && dh launcher show --system --principal "$PRINCIPAL" "$MAIN_L_ID" 2>/dev/null \
      | grep -A1 -F "\"path\": \"$WS/pipeline-inputs\"" | grep -q '"access": "read_only"'; then
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
WIDEN_L_JSON="$(api POST "/principals/$PRINCIPAL/launchers" \
  '{"name":"widen","scope":"restricted","allowed_roots":["'"$TREE"'"]}')"
WIDEN_L_ID="$(printf '%s' "$WIDEN_L_JSON" | json_field id)"
[ -n "$WIDEN_L_ID" ] || { echo "error: launcher 'widen' create failed: $WIDEN_L_JSON" >&2; exit 1; }
if dh launcher allowed-root add --system --principal "$PRINCIPAL" --access read_write \
    "$WIDEN_L_ID" "$WS/pipeline-inputs" >/dev/null 2>&1; then
  acc_ok "P7 setup: launcher stored a read_write grant on the Principal read_only region"
else
  acc_fail "P7 setup: launcher could not store the read_write grant"
fi

# sub: most-specific RW->RO->RW transitions (point 8 policy owner). The
# 2.2 composition meets the launcher mode against the Principal mode at each
# candidate path, so a launcher RW under a Principal read_only ancestor would
# compose to read_only. The Principal therefore carries its own read_write
# entry at the sub path (within its read_write ceiling): the region composes
# to read_write, the parent region stays read_only, and the RO-over-nested-RW
# refusals in the widen scenario remain intact.
SUB_L_JSON="$(api POST "/principals/$PRINCIPAL/launchers" \
  '{"name":"sub","scope":"restricted","allowed_roots":["'"$TREE"'"]}')"
SUB_L_ID="$(printf '%s' "$SUB_L_JSON" | json_field id)"
[ -n "$SUB_L_ID" ] || { echo "error: launcher 'sub' create failed: $SUB_L_JSON" >&2; exit 1; }
dh principal allowed-root add --system --access read_write "$PRINCIPAL" \
  "$WS/pipeline-inputs/sub" >/dev/null 2>&1 || true
dh launcher allowed-root add --system --principal "$PRINCIPAL" --access read_only \
  "$SUB_L_ID" "$WS/pipeline-inputs" >/dev/null 2>&1 || true
dh launcher allowed-root add --system --principal "$PRINCIPAL" --access read_write \
  "$SUB_L_ID" "$WS/pipeline-inputs/sub" >/dev/null 2>&1 || true
acc_ok "P8 setup: launcher sub carries RW -> RO -> RW transitions"

# buildro: the read-only build policy owner (snapshot with only RO). A
# restricted launcher create requires at least one root and the create
# request carries the legacy path-only (read_write) form, so the stored root
# is flipped to read_only through the narrow set-access mutation.
BUILD_L_JSON="$(api POST "/principals/$PRINCIPAL/launchers" \
  '{"name":"buildro","scope":"restricted","allowed_roots":["'"$BUILDROOT"'"]}')"
BUILD_L_ID="$(printf '%s' "$BUILD_L_JSON" | json_field id)"
[ -n "$BUILD_L_ID" ] || { echo "error: launcher 'buildro' create failed: $BUILD_L_JSON" >&2; exit 1; }
if dh launcher allowed-root set-access --system --principal "$PRINCIPAL" \
    "$BUILD_L_ID" "$BUILDROOT" read_only >/dev/null 2>&1; then
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

SA_ID="$(create_session /tmp/uat-am-cred-main "$WS")" \
  || { echo "error: session SA creation failed" >&2; exit 1; }
SB_ID="$(create_session /tmp/uat-am-cred-widen "$WS")" \
  || { echo "error: session SB creation failed" >&2; exit 1; }
SC_ID="$(create_session /tmp/uat-am-cred-sub "$WS")" \
  || { echo "error: session SC creation failed" >&2; exit 1; }
SL_ID="$(create_session /tmp/uat-am-cred-legacy "$LEGACY_WS")" \
  || { echo "error: session SL creation failed" >&2; exit 1; }
SD_ID="$(create_session /tmp/uat-am-cred-build "$BUILD_WS")" \
  || { echo "error: session SD creation failed" >&2; exit 1; }
acc_ok "sessions created: main=$SA_ID widen=$SB_ID sub=$SC_ID legacy=$SL_ID build=$SD_ID"

# Issued snapshots carry the normalized mode-transition representation: a
# read_write child of a read_write region is redundant and dropped
# (normalizeAllowedRootEntries), so SA shows the TREE read_write region and
# the pipeline-inputs transition only; SC additionally shows the RW->RO->RW
# sub transition that both scopes granted.
if snapshot_has "$SA_ID" "$WS" read_write \
    && snapshot_has "$SA_ID" "$WS/pipeline-inputs" read_only \
    && snapshot_lacks "$SA_ID" "$WS/project" \
    && snapshot_lacks "$SA_ID" "$WS/pipeline-outputs" \
    && snapshot_has "$SB_ID" "$WS/pipeline-inputs" read_only \
    && snapshot_has "$SC_ID" "$WS/pipeline-inputs" read_only \
    && snapshot_has "$SC_ID" "$WS/pipeline-inputs/sub" read_write \
    && snapshot_has "$SL_ID" "$LEGACY_WS" read_write \
    && snapshot_has "$SD_ID" "$BUILD_WS" read_only; then
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
if [ -f "$WS/project/written.txt" ] && [ "$(cat "$WS/project/written.txt")" = "rw-write" ]; then
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
[ ! -e "$WS/pipeline-inputs/forbidden.txt" ] \
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
ln -sfn pipeline-inputs "$WS/alias-inputs"
chown -h "$PRINCIPAL:$PRINCIPAL" "$WS/alias-inputs"
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
if [ -f "$WS/pipeline-inputs/sub/new.txt" ] && [ "$(cat "$WS/pipeline-inputs/sub/new.txt")" = "sub-write" ]; then
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
  && [ -f "$LEGACY_WS/written.txt" ] \
  && acc_ok "9 legacy path-only root remained read_write" \
  || acc_fail "9 legacy path-only write did not persist"

# ==============================================================================
# scenario 10: snapshot immutability across parent policy mutations
# ==============================================================================
scenario "10: existing Session keeps its snapshot; new Sessions get the new mode"
if dh principal allowed-root set-access --system "$PRINCIPAL" "$WS/project" read_only >/dev/null 2>&1; then
  acc_ok "10 parent policy mutation: project narrowed to read_only"
else
  acc_fail "10 principal set-access for the immutability pair failed"
fi
SA2_ID="$(create_session /tmp/uat-am-cred-main "$WS")" \
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
if dh principal allowed-root set-access --system "$PRINCIPAL" "$WS/project" read_write >/dev/null 2>&1; then
  if snapshot_has "$SA2_ID" "$WS/project" read_only; then
    acc_ok "10 issued snapshot is immutable: SA2 keeps read_only after the parent was restored"
  else
    acc_fail "10 issued snapshot changed after a parent restore (immutability broken)"
  fi
  SA3_ID="$(create_session /tmp/uat-am-cred-main "$WS")" \
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
# scenario N: issuance-time Session filesystem narrowing (Launcher credential,
# dynamic pipeline run). The Launcher's effective ceiling is broad read_write
# authority over the run tree; the orchestrator creates a dynamically named
# run workspace and narrows the per-run Session at issuance time — the exact
# Release 2.2 capability a dynamic pipeline run needs and durable per-run
# Launcher policy mutations cannot express.
# ==============================================================================
scenario "N: issuance-time Session filesystem narrowing (Launcher credential)"

# N-setup: the orchestrator creates the run directories BEFORE creating the
# Session (the existence requirement makes every entry's canonical identity
# provable). The run name is dynamic: no durable policy change was made for
# it.
RUNDIR="$TREE/run-uat-$(date +%s)-$$"
mkdir -p "$RUNDIR/project" "$RUNDIR/pipeline-inputs" "$RUNDIR/pipeline-outputs"
printf 'run-input\n' > "$RUNDIR/pipeline-inputs/task.md"
chown -R "$PRINCIPAL:$PRINCIPAL" "$RUNDIR"
chmod -R u+rwX,go+rX "$RUNDIR"

# N-create: Launcher credential + per-Session issuance-time narrowing.
NARROW_OUT="$(dh session create --system --token-file /tmp/uat-am-cred-main \
  --workspace "$RUNDIR" --json \
  --filesystem-entry .=read_only \
  --filesystem-entry project=read_write \
  --filesystem-entry pipeline-inputs=read_only \
  --filesystem-entry pipeline-outputs=read_write 2>&1 || true)"
SN_ID="$(printf '%s' "$NARROW_OUT" | json_field id)"
if [ -n "$SN_ID" ]; then
  printf '%s' "$NARROW_OUT" | json_field token > "/tmp/uat-am-tok-$SN_ID"; chmod 600 "/tmp/uat-am-tok-$SN_ID"
  acc_ok "13 Launcher credential created the narrowed Session on the dynamic run workspace"
else
  acc_fail "13 narrowed session create failed: $(printf '%s\n' "$NARROW_OUT" | redact | tail -3)"
fi

# N-show: the issued snapshot exposes exactly the effective semantics. The
# explicit pipeline-inputs read_only entry may be normalized away because the
# root '.' entry is already read_only — UAT verifies effective semantics, not
# redundant storage.
if [ -n "${SN_ID:-}" ] \
    && snapshot_has "$SN_ID" "$RUNDIR" read_only \
    && snapshot_has "$SN_ID" "$RUNDIR/project" read_write \
    && snapshot_has "$SN_ID" "$RUNDIR/pipeline-outputs" read_write \
    && snapshot_lacks "$SN_ID" "$RUNDIR/pipeline-inputs"; then
  acc_ok "13 session show exposes the effective narrowed snapshot (root RO, project/outputs RW, redundant RO normalized away)"
else
  acc_fail "13 issued narrowed snapshot wrong (SN: $(show_snapshot "${SN_ID:-}" 2>/dev/null | tr '\n' '; '))"
fi

# N-runtime: the narrowed snapshot enforces exactly those semantics.
if [ -n "${SN_ID:-}" ]; then
  SN_TOKEN="$(cat "/tmp/uat-am-tok-$SN_ID")"
  NP_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SN_TOKEN" \
    dh run --image alpine:3.24 --mount project:/mnt/project -- \
    sh -ec 'echo run-write > /mnt/project/run.txt && cat /mnt/project/run.txt')" \
    || acc_fail "13 narrowed project RW write failed: $NP_OUT"
  if [ -f "$RUNDIR/project/run.txt" ] && [ "$(cat "$RUNDIR/project/run.txt")" = "run-write" ]; then
    acc_ok "13 narrowed project mounted read_write and the write persisted"
  else
    acc_fail "13 narrowed project write did not persist to the host"
  fi
  NI_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SN_TOKEN" \
    dh run --image alpine:3.24 --mount pipeline-inputs:/mnt/inputs:ro -- \
    sh -ec 'test "$(cat /mnt/inputs/task.md)" = "run-input" && echo RUN-INPUT-RO-OK')" \
    || acc_fail "13 narrowed pipeline-inputs read failed: $NI_OUT"
  printf '%s\n' "$NI_OUT" | grep -q 'RUN-INPUT-RO-OK' \
    && acc_ok "13 narrowed pipeline-inputs read succeeded" \
    || acc_fail "13 narrowed pipeline-inputs read check failed"
  RESIDUE_BASE="$(residue_state)"
  if expect_read_only_root "$SN_TOKEN" pipeline-inputs /mnt/inputs 'echo x > /mnt/inputs/forbidden.txt' "$RESIDUE_BASE"; then
    acc_ok "13 narrowed pipeline-inputs RW exposure refused with read_only_root before workload"
  else
    acc_fail "13 narrowed pipeline-inputs RW exposure was not refused (base: $RESIDUE_BASE)"
  fi
  NO_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SN_TOKEN" \
    dh run --image alpine:3.24 --mount pipeline-outputs:/mnt/outputs -- \
    sh -ec 'echo declared-output > /mnt/outputs/out.txt && cat /mnt/outputs/out.txt')" \
    || acc_fail "13 narrowed pipeline-outputs RW write failed: $NO_OUT"
  if [ -f "$RUNDIR/pipeline-outputs/out.txt" ] && [ "$(cat "$RUNDIR/pipeline-outputs/out.txt")" = "declared-output" ]; then
    acc_ok "13 narrowed pipeline-outputs mounted read_write and the write persisted"
  else
    acc_fail "13 narrowed pipeline-outputs write did not persist to the host"
  fi
  RESIDUE_BASE="$(residue_state)"
  if expect_read_only_root "$SN_TOKEN" . /mnt/run 'echo x > /mnt/run/pipeline-inputs/forbidden2.txt' "$RESIDUE_BASE"; then
    acc_ok "13 writable narrowed workspace parent spanning the RO input refused (read_only_root)"
  else
    acc_fail "13 writable narrowed workspace parent was not refused (base: $RESIDUE_BASE)"
  fi
fi

# N-omitted: the same dynamic run workspace WITHOUT filesystem_entries keeps
# the inherited behavior byte-for-byte: the Session gets the existing derived
# snapshot (workspace read_write) and a workspace-root writable write works.
SN2_ID="$(create_session /tmp/uat-am-cred-main "$RUNDIR")" \
  || { echo "error: inherited (omitted) session creation failed" >&2; exit 1; }
if snapshot_has "$SN2_ID" "$RUNDIR" read_write; then
  SN2_TOKEN="$(cat "/tmp/uat-am-tok-$SN2_ID")"
  SN2_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SN2_TOKEN" \
    dh run --image alpine:3.24 --mount .:/mnt/runroot -- \
    sh -ec 'echo inherited-write > /mnt/runroot/inherited.txt && echo INHERITED-RW-OK')" \
    || acc_fail "13 inherited workspace-root write failed: $SN2_OUT"
  printf '%s\n' "$SN2_OUT" | grep -q 'INHERITED-RW-OK' \
    && acc_ok "13 omitted filesystem_entries keeps the inherited read-write behavior" \
    || acc_fail "13 inherited workspace-root write did not persist"
else
  acc_fail "13 omitted filesystem_entries snapshot is not the inherited read_write root: $(show_snapshot "$SN2_ID" | tr '\n' '; ')"
fi

# N-refusal: an attempted issuance-time widening — read_write under the
# parent read_only ceiling — is refused 400 invalid_filesystem_policy before
# the Session exists: no Session, no bearer, no container, no pin, no
# workload-MAC residue. The residue and Session-count baselines are captured
# BEFORE the single tested attempt, so state created by the attempt itself
# can never end up inside its own baseline, and both inventories are the
# fail-closed owners: an unavailable inventory is a failed proof, never a
# silently-equal count. The public response must be the bounded
# non-disclosing contract (stable code, bounded message, no Session ID, no
# bearer/credential material; credential IDs are not secrets and are not
# asserted), and the bounded audit window opens immediately before the same
# single attempt so the required session.create audit record below is
# provably the record of this refusal — a missing record is a failed proof,
# never an accepted silence.
if N_BASE="$(residue_state)" && N_BEFORE="$(session_list_count)"; then
  N_AUDIT_SINCE="$(date -u +'%Y-%m-%d %H:%M:%S')"
  WIDEN_OUT="$(dh session create --system --token-file /tmp/uat-am-cred-main \
    --workspace "$WS" --json \
    --filesystem-entry .=read_write \
    --filesystem-entry pipeline-inputs=read_write 2>&1 || true)"
  if printf '%s\n' "$WIDEN_OUT" | grep -q 'invalid_filesystem_policy' \
      && printf '%s\n' "$WIDEN_OUT" | grep -q 'invalid session filesystem policy' \
      && ! printf '%s\n' "$WIDEN_OUT" | grep -q '"id"' \
      && ! printf '%s\n' "$WIDEN_OUT" | grep -q 'dhs_' \
      && ! printf '%s\n' "$WIDEN_OUT" | grep -q 'dht_' \
      && ! printf '%s\n' "$WIDEN_OUT" | grep -q 'dhc_'; then
    if N_AFTER="$(session_list_count)" \
        && [ "$N_AFTER" = "$N_BEFORE" ] \
        && residue_unchanged "$N_BASE"; then
      N_AUDIT_JSON="$(journalctl --utc -u docker-helper.service --since "$N_AUDIT_SINCE" --no-pager 2>/dev/null \
        | grep '"stream":"audit"' || true)"
      N_REJECT_LINE="$(printf '%s\n' "$N_AUDIT_JSON" \
        | grep '"event":"session.create"' | grep '"result":"invalid_filesystem_policy"' | tail -1 || true)"
      if [ -n "$N_REJECT_LINE" ] \
          && ! printf '%s\n' "$N_REJECT_LINE" | grep -q '"session_id"' \
          && ! printf '%s\n' "$N_REJECT_LINE" | grep -q 'dht_' \
          && ! printf '%s\n' "$N_REJECT_LINE" | grep -q 'dhc_'; then
        acc_ok "14 issuance-time widening refused with invalid_filesystem_policy: bounded message, no Session/bearer, matching audit record, no container/pin/workload-MAC residue"
      else
        acc_fail "14 refused create lacks the matching session.create invalid_filesystem_policy audit record (or it carries Session/bearer state): $(printf '%s\n' "$N_REJECT_LINE" | redact | head -2)"
      fi
    else
      acc_fail "14 refused create left state (sessions $N_BEFORE -> ${N_AFTER:-inventory-unavailable}, residue drift against the pre-attempt baseline)"
    fi
  else
    acc_fail "14 widening create not refused correctly: $(printf '%s\n' "$WIDEN_OUT" | redact | tail -3)"
  fi
else
  acc_fail "14 baseline capture failed before the widening attempt (fail-closed inventory)"
fi

# ==============================================================================
# scenario G: a global read_only ceiling cannot be widened downstream
# (global -> Principal -> Launcher live proof). Scenario 7 proves the
# Principal-ceiling meet against a Launcher grant; this scenario proves the
# upstream dimension of the same contract on a really issued Session: the
# global ceiling of a dedicated subtree is narrowed to read_only while BOTH
# the Principal and the Launcher carry stored read_write grants on the same
# subtree. Stored wider modes are ordinary state; the meet decides at
# issuance time. A dedicated nested fixture (its own subtree, launcher and
# credential) keeps the other scenarios' fixture state intact.
# ==============================================================================
scenario "G: global read_only cannot be widened downstream (live proof)"

G_WS="$TREE/global-ro/work"
mkdir -p "$G_WS"
printf 'global-ro-input\n' > "$G_WS/input.txt"
chown -R "$PRINCIPAL:$PRINCIPAL" "$TREE/global-ro"
chmod -R u+rwX,go+rX "$TREE/global-ro"

# G-setup: the three policy levels. The global ceiling is narrowed to
# read_only through the packaged config CLI (verified through the rich
# projection); the Principal and the Launcher store read_write on the same
# subtree (each verified through its rich projection).
if dh config allowed-root set-access "$TREE/global-ro" read_only >/dev/null 2>&1 \
    && [ "$(dh config allowed-root list --json 2>/dev/null | allowed_root_json_access "$TREE/global-ro")" = read_only ]; then
  acc_ok "G global ceiling narrowed to read_only (rich projection)"
else
  acc_fail "G global ceiling set-access to read_only failed"
fi
if dh principal allowed-root add --system --access read_write "$PRINCIPAL" "$TREE/global-ro" >/dev/null 2>&1 \
    && [ "$(dh principal allowed-root list --system --json "$PRINCIPAL" 2>/dev/null | allowed_root_json_access "$TREE/global-ro")" = read_write ]; then
  acc_ok "G Principal carries read_write on the global read_only subtree"
else
  acc_fail "G Principal read_write add failed"
fi
G_L_JSON="$(api POST "/principals/$PRINCIPAL/launchers" \
  '{"name":"globalro","scope":"restricted","allowed_roots":["'"$TREE"'/global-ro"]}')"
G_L_ID="$(printf '%s' "$G_L_JSON" | json_field id)"
[ -n "$G_L_ID" ] || { echo "error: launcher 'globalro' create failed: $G_L_JSON" >&2; exit 1; }
if dh launcher show --system --principal "$PRINCIPAL" "$G_L_ID" 2>/dev/null \
    | grep -A1 -F "\"path\": \"$TREE/global-ro\"" | grep -q '"access": "read_write"'; then
  acc_ok "G Launcher carries read_write on the same subtree (rich projection)"
else
  acc_fail "G Launcher read_write grant failed"
fi
issue_launcher_credential "$PRINCIPAL" "$G_L_ID" /tmp/uat-am-cred-globalro \
  || { echo "error: globalro launcher credential issuance failed" >&2; exit 1; }

# G-live: the Session is issued on the standard authority path (Launcher
# credential, inherited policy — no filesystem_entries) and composes the
# three read_write grants down to read_only.
G_ID="$(create_session /tmp/uat-am-cred-globalro "$G_WS")" \
  || { echo "error: session G creation failed" >&2; exit 1; }
if snapshot_has "$G_ID" "$G_WS" read_only; then
  acc_ok "G issued effective snapshot is read_only (global RO dominates the downstream read_write grants)"
else
  acc_fail "G issued snapshot is not read_only: $(show_snapshot "$G_ID" | tr '\n' '; ')"
fi
G_TOKEN="$(cat "/tmp/uat-am-tok-$G_ID")"
G_RO_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$G_TOKEN" \
  dh run --image alpine:3.24 --mount .:/mnt/g:ro -- \
  sh -ec 'test "$(cat /mnt/g/input.txt)" = "global-ro-input" && echo GLOBAL-RO-OK')" \
  || acc_fail "G read-only exposure failed: $G_RO_OUT"
printf '%s\n' "$G_RO_OUT" | grep -q 'GLOBAL-RO-OK' \
  && acc_ok "G read-only exposure succeeded" \
  || acc_fail "G read-only exposure check failed"
G_RESIDUE_BASE="$(residue_state)"
if expect_read_only_root "$G_TOKEN" . /mnt/g 'echo x > /mnt/g/forbidden.txt' "$G_RESIDUE_BASE"; then
  acc_ok "G writable exposure refused with read_only_root before workload creation (no residue)"
else
  acc_fail "G writable exposure was not refused (base: $G_RESIDUE_BASE)"
fi
[ ! -e "$G_WS/forbidden.txt" ] \
  || acc_fail "G forbidden host-side file was created"

# G-restore: the global ceiling returns to the P2 state (read_write) so the
# nested fixture leaves no durable global-policy drift behind.
if dh config allowed-root set-access "$TREE/global-ro" read_write >/dev/null 2>&1; then
  acc_ok "G global ceiling restored to read_write"
else
  acc_fail "G global ceiling restore failed"
fi

# ==============================================================================
# scenario SYM: Admin and Principal credential narrowing symmetry. Scenario N
# proves the Launcher credential authority; the same issuance-time narrowing
# contract binds every authority that may create Sessions, and each authority
# is proven on its own (one authority's refusal is never another's proof).
# Admin selects the main Launcher explicitly through the public CLI with the
# system admin token; the Principal credential resolves its inherit-scope
# default Launcher. Each authority: a valid narrowing request on the main
# workspace, the issued effective semantics through session show, one
# widening attempt against the read_only pipeline-inputs ceiling, the
# stable refusal, and no new Session (fail-closed session-list inventory
# around the attempt); the created Session is deleted afterwards.
# ==============================================================================
scenario "SYM: Admin and Principal credential narrowing symmetry"

# Admin authority: same valid narrowing as scenario N, on the main workspace.
SYM_ADMIN_OUT="$(dh session create --system --token-file /etc/docker-helper/admin.token \
  --launcher "$MAIN_L_ID" --workspace "$WS" --json \
  --filesystem-entry .=read_only \
  --filesystem-entry project=read_write \
  --filesystem-entry pipeline-inputs=read_only \
  --filesystem-entry pipeline-outputs=read_write 2>&1 || true)"
SYM_ADMIN_ID="$(printf '%s' "$SYM_ADMIN_OUT" | json_field id)"
if [ -n "$SYM_ADMIN_ID" ]; then
  printf '%s' "$SYM_ADMIN_OUT" | json_field token > "/tmp/uat-am-tok-$SYM_ADMIN_ID"; chmod 600 "/tmp/uat-am-tok-$SYM_ADMIN_ID"
  acc_ok "16 Admin created the narrowed Session through the public CLI (explicit launcher selector)"
else
  acc_fail "16 Admin narrowed session create failed: $(printf '%s\n' "$SYM_ADMIN_OUT" | redact | tail -3)"
fi
if [ -n "${SYM_ADMIN_ID:-}" ] \
    && snapshot_has "$SYM_ADMIN_ID" "$WS" read_only \
    && snapshot_has "$SYM_ADMIN_ID" "$WS/project" read_write \
    && snapshot_has "$SYM_ADMIN_ID" "$WS/pipeline-outputs" read_write \
    && snapshot_lacks "$SYM_ADMIN_ID" "$WS/pipeline-inputs"; then
  acc_ok "16 Admin issued snapshot matches the Launcher narrowing semantics (effective, redundant RO normalized away)"
else
  acc_fail "16 Admin issued snapshot wrong: $(show_snapshot "${SYM_ADMIN_ID:-}" 2>/dev/null | tr '\n' '; ')"
fi
if SYM_ADMIN_BEFORE="$(session_list_count)"; then
  SYM_ADMIN_WIDEN_OUT="$(dh session create --system --token-file /etc/docker-helper/admin.token \
    --launcher "$MAIN_L_ID" --workspace "$WS" --json \
    --filesystem-entry .=read_only \
    --filesystem-entry pipeline-inputs=read_write 2>&1 || true)"
  if printf '%s\n' "$SYM_ADMIN_WIDEN_OUT" | grep -q 'invalid_filesystem_policy' \
      && ! printf '%s\n' "$SYM_ADMIN_WIDEN_OUT" | grep -q '"id"'; then
    if SYM_ADMIN_AFTER="$(session_list_count)" && [ "$SYM_ADMIN_AFTER" = "$SYM_ADMIN_BEFORE" ]; then
      acc_ok "16 Admin widening request refused with invalid_filesystem_policy: no new Session"
    else
      acc_fail "16 refused Admin create changed the Session inventory ($SYM_ADMIN_BEFORE -> ${SYM_ADMIN_AFTER:-inventory-unavailable})"
    fi
  else
    acc_fail "16 Admin widening create not refused correctly: $(printf '%s\n' "$SYM_ADMIN_WIDEN_OUT" | redact | tail -3)"
  fi
else
  acc_fail "16 Admin widening baseline capture failed (fail-closed session inventory)"
fi
if [ -n "${SYM_ADMIN_ID:-}" ]; then
  dh session delete --system --id "$SYM_ADMIN_ID" >/dev/null 2>&1 \
    || acc_fail "16 Admin narrowed session delete failed"
fi

# Principal credential authority: a real Principal bearer through the
# packaged CLI, no selector (resolves the inherit-scope default Launcher).
if reg_principal_credential "$PRINCIPAL" /tmp/uat-am-cred-principal; then
  acc_ok "16 Principal credential issued through the packaged CLI"
else
  acc_fail "16 Principal credential issuance failed"
fi
SYM_PRIN_OUT="$(dh session create --system --token-file /tmp/uat-am-cred-principal \
  --workspace "$WS" --json \
  --filesystem-entry .=read_only \
  --filesystem-entry project=read_write \
  --filesystem-entry pipeline-inputs=read_only \
  --filesystem-entry pipeline-outputs=read_write 2>&1 || true)"
SYM_PRIN_ID="$(printf '%s' "$SYM_PRIN_OUT" | json_field id)"
if [ -n "$SYM_PRIN_ID" ]; then
  printf '%s' "$SYM_PRIN_OUT" | json_field token > "/tmp/uat-am-tok-$SYM_PRIN_ID"; chmod 600 "/tmp/uat-am-tok-$SYM_PRIN_ID"
  acc_ok "16 Principal credential created the narrowed Session (no selector, default Launcher)"
else
  acc_fail "16 Principal narrowed session create failed: $(printf '%s\n' "$SYM_PRIN_OUT" | redact | tail -3)"
fi
if [ -n "${SYM_PRIN_ID:-}" ] \
    && snapshot_has "$SYM_PRIN_ID" "$WS" read_only \
    && snapshot_has "$SYM_PRIN_ID" "$WS/project" read_write \
    && snapshot_has "$SYM_PRIN_ID" "$WS/pipeline-outputs" read_write \
    && snapshot_lacks "$SYM_PRIN_ID" "$WS/pipeline-inputs"; then
  acc_ok "16 Principal issued snapshot matches the Launcher narrowing semantics (effective, redundant RO normalized away)"
else
  acc_fail "16 Principal issued snapshot wrong: $(show_snapshot "${SYM_PRIN_ID:-}" 2>/dev/null | tr '\n' '; ')"
fi
if SYM_PRIN_BEFORE="$(session_list_count)"; then
  SYM_PRIN_WIDEN_OUT="$(dh session create --system --token-file /tmp/uat-am-cred-principal \
    --workspace "$WS" --json \
    --filesystem-entry .=read_only \
    --filesystem-entry pipeline-inputs=read_write 2>&1 || true)"
  if printf '%s\n' "$SYM_PRIN_WIDEN_OUT" | grep -q 'invalid_filesystem_policy' \
      && ! printf '%s\n' "$SYM_PRIN_WIDEN_OUT" | grep -q '"id"'; then
    if SYM_PRIN_AFTER="$(session_list_count)" && [ "$SYM_PRIN_AFTER" = "$SYM_PRIN_BEFORE" ]; then
      acc_ok "16 Principal widening request refused with invalid_filesystem_policy: no new Session"
    else
      acc_fail "16 refused Principal create changed the Session inventory ($SYM_PRIN_BEFORE -> ${SYM_PRIN_AFTER:-inventory-unavailable})"
    fi
  else
    acc_fail "16 Principal widening create not refused correctly: $(printf '%s\n' "$SYM_PRIN_WIDEN_OUT" | redact | tail -3)"
  fi
else
  acc_fail "16 Principal widening baseline capture failed (fail-closed session inventory)"
fi
if [ -n "${SYM_PRIN_ID:-}" ]; then
  dh session delete --system --id "$SYM_PRIN_ID" >/dev/null 2>&1 \
    || acc_fail "16 Principal narrowed session delete failed"
fi

# ==============================================================================
# scenario B: build over a read-only-only snapshot
# ==============================================================================
scenario "B: build over a read-only snapshot"
SD_TOKEN="$(cat "/tmp/uat-am-tok-$SD_ID")"
SNAP_BEFORE="$(cd "$BUILD_WS" && find . -printf '%p %m %T@\n' 2>/dev/null | sort)"
BUILD_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SD_TOKEN" \
  dh build --context . --dockerfile Dockerfile --image uat-am-robuild:2.2 2>&1)" \
  || acc_fail "B1 build over the read-only snapshot failed: $(printf '%s\n' "$BUILD_OUT" | redact | tail -3)"
SNAP_AFTER="$(cd "$BUILD_WS" && find . -printf '%p %m %T@\n' 2>/dev/null | sort)"
if [ "$SNAP_BEFORE" = "$SNAP_AFTER" ]; then
  acc_ok "B2 source tree unchanged after the build (content, modes, mtimes)"
else
  acc_fail "B2 source tree changed during the read-only build"
fi
if snapshot_has "$SD_ID" "$BUILD_WS" read_only \
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
  if printf '%s\n' "$REJECT_LINE" | grep -q "\"resolved_source\":\"$WS/pipeline-inputs\"" \
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
# scenario Z: residue and cleanup (fail-closed three-state inventory:
# ABSENT / PRESENT / UNKNOWN — "cannot inspect" is never "clean", an
# inventory failure blocks the gate instead of reporting zero residue)
# ==============================================================================
scenario "Z: no container/mount-pin/workload-MAC/runtime residue"
for sid in "$SA_ID" "$SB_ID" "$SC_ID" "$SL_ID" "$SD_ID" "${SA2_ID:-}" "${SA3_ID:-}" "${SN_ID:-}" "${SN2_ID:-}" "${G_ID:-}" "${SYM_ADMIN_ID:-}" "${SYM_PRIN_ID:-}"; do
  [ -n "$sid" ] || continue
  dh session delete --system --id "$sid" >/dev/null 2>&1 || acc_fail "Z session $sid delete failed"
done
wait_no_helper_containers
Z_WAIT_RC=$?
if [ "$Z_WAIT_RC" -eq 2 ]; then
  acc_blocked "Z helper container inventory unavailable after the scenarios"
elif [ "$Z_WAIT_RC" -ne 0 ]; then
  acc_fail "Z helper-owned containers remain ($(docker ps -a --filter 'label=com.dockerhelper.schema=1' --format '{{.ID}} {{.Status}}' | head -3))"
else
  acc_ok "Z no helper-owned containers remain"
fi
Z_PINS="$(inventory_count /run/docker-helper/mounts)"; Z_PINS_RC=$?
if [ "$Z_PINS_RC" -eq 0 ]; then
  [ "$Z_PINS" = "0" ] && acc_ok "Z no mount pins remain" \
    || acc_fail "Z mount pins remain: $(ls /run/docker-helper/mounts 2>/dev/null | head -3)"
else
  acc_blocked "Z mount-pin inventory unavailable"
fi
Z_WLMAC="$(inventory_count /run/docker-helper/workload-mac)"; Z_WLMAC_RC=$?
if [ "$Z_WLMAC_RC" -eq 0 ]; then
  [ "$Z_WLMAC" = "0" ] && acc_ok "Z no workload-MAC runtime state remains" \
    || acc_fail "Z workload-MAC runtime state remains"
else
  acc_blocked "Z workload-MAC runtime inventory unavailable"
fi
Z_BUILDS="$(inventory_count /run/docker-helper/builds)"; Z_BUILDS_RC=$?
if [ "$Z_BUILDS_RC" -eq 0 ]; then
  [ "$Z_BUILDS" = "0" ] && acc_ok "Z no build staging remains" \
    || acc_fail "Z build staging remains"
else
  acc_blocked "Z build staging inventory unavailable"
fi
Z_SESSIONS="$(inventory_count /run/docker-helper/sessions)"; Z_SESSIONS_RC=$?
if [ "$Z_SESSIONS_RC" -eq 0 ]; then
  [ "$Z_SESSIONS" = "0" ] && acc_ok "Z no session runtime directories remain" \
    || acc_fail "Z session runtime directories remain"
else
  acc_blocked "Z session runtime inventory unavailable"
fi
Z_DURABLE="$(inventory_count /var/lib/docker-helper/workload-mac)"; Z_DURABLE_RC=$?
if [ "$Z_DURABLE_RC" -eq 0 ]; then
  [ "$Z_DURABLE" = "0" ] && acc_ok "Z no durable workload-MAC records remain" \
    || acc_fail "Z durable workload-MAC records remain"
else
  acc_blocked "Z durable workload-MAC inventory unavailable"
fi
Z_PROFILES="$(workload_profile_count)"; Z_PROFILES_RC=$?
if [ "$Z_PROFILES_RC" -eq 0 ]; then
  [ "$Z_PROFILES" = "0" ] && acc_ok "Z no generated workload profiles remain loaded" \
    || acc_fail "Z generated workload profiles still loaded"
else
  acc_blocked "Z workload profile inventory unavailable"
fi

# Z-final: Release 2.2 also promises no remaining Session/snapshot state.
# After every known Session is deleted, the active Session inventory must be
# positively empty through the fail-closed canonical session-list helper,
# and the durable database must carry no Session or snapshot rows. The DB
# inventory is the shared fail-closed owner (python3 stdlib sqlite3,
# read-only): a missing/unopenable database, an SQL error, a parse failure,
# or an unexpected schema is an unavailable inventory (blocked gate), never
# a silent zero. The database is inspected in place — it is never deleted
# before this check.
if Z_LIST_COUNT="$(session_list_count)"; then
  [ "$Z_LIST_COUNT" = "0" ] \
    && acc_ok "Z no active Sessions remain (fail-closed session-list inventory)" \
    || acc_fail "Z active Sessions remain after the cleanup: $Z_LIST_COUNT"
else
  acc_blocked "Z session-list inventory unavailable after the cleanup"
fi
Z_DB_COUNTS="$(durable_session_snapshot_counts /var/lib/docker-helper/docker-helper.db)"
Z_DB_RC=$?
if [ "$Z_DB_RC" -eq 0 ]; then
  [ "$Z_DB_COUNTS" = "$(printf '0\t0\t0')" ] \
    && acc_ok "Z durable DB carries no Session/snapshot rows (sessions, snapshot entries, snapshot meta)" \
    || acc_fail "Z durable Session/snapshot rows remain: $Z_DB_COUNTS"
else
  acc_blocked "Z durable DB inventory unavailable (cannot inspect the Session/snapshot tables)"
fi

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
