#!/usr/bin/env bash
#
# uat-release2-acceptance.sh — privileged Release-2 acceptance suite for the
# Ubuntu / DEB / AppArmor profile (runs on the exact candidate DEB produced by
# the artifact gate).
#
# Scenarios (each mandatory; fail-closed):
#   A  two-credential independent revocation (one Principal, two credentials)
#   B  principal_name in real operation audit (structured journal audit)
#   C  registry login end-to-end + session isolation (self-contained registry)
#   D  bounded restart/shutdown with active operations
#   E  user-mode + system-mode deployment coexistence
#   G  v2.0.0 -> candidate upgrade ownership migration (depth proofs: credential
#      identity retention, default-Launcher attribution, non-attributable admin
#      session invalidation, no fabricated Launcher credential, restart
#      idempotency, final schema, migrated-Launcher functionality)
#   M  v2.1.1 -> candidate migration (mandatory Release 2.2 gate): real
#      published-v2.1.1 path-only state (global/Principal/Launcher roots,
#      credentials, live Sessions), fail-closed migration refusal without
#      half-migrated state, read_write authority of migrated roots, workspace
#      compatibility snapshots, identity/Session-ID preservation, writable
#      behavior of the old Session, restart idempotency
#   H  launcher hierarchy, isolation, rotation, and lifecycle on the candidate
#      (separate namespaces, cross-launcher non-disclosure, rotation continuity,
#      restricted scope, stale-root rejection, disable propagation, checked
#      delete, bearer/provenance audit checks)
#   F  DEB native lifecycle: install(upgrade baseline v2.0.0) ->
#      upgrade(candidate) -> reinstall(candidate) -> remove -> purge
#
# Contract for every scenario:
#   PASS    -> gate may continue
#   FAIL    -> gate fails
#   BLOCKED -> a required prerequisite is unavailable -> gate fails
# Exit status: 0 = all PASS, 1 = any FAIL, 2 = any BLOCKED (and none FAIL).
#
# The v2.0.0 package is an immutable TEST FIXTURE for the real upgrade
# baseline: the needed DEB is downloaded from the published release, its pinned
# SHA-256 is verified strictly BEFORE installation, and mutable release
# metadata is never trusted at runtime. No private "previous release" is built.
#
# Env inputs:
#   UAT_VERSION          candidate version string (e.g. 2.2.0-uat)
#   UAT_ARTIFACT_PATH    exact candidate .deb produced by the gate (required)
#   UAT_ARTIFACT_SHA256  expected SHA-256 of the candidate .deb (required)
#   UAT_ALLOWED_ROOT     global allowed root (default /home)
#
# The upgrade-baseline fixture (URL + pinned SHA-256) is owned by
# scripts/uat-upgrade-baseline-fixture.sh.
#
# Requires: root, systemd, Docker, dpkg. Exits as above.

set -uo pipefail

VERSION="${UAT_VERSION:-2.2.0-uat}"
ALLOWED_ROOT="${UAT_ALLOWED_ROOT:-/home}"
ARTIFACT_PATH_IN="${UAT_ARTIFACT_PATH:-}"
ARTIFACT_SHA256_IN="${UAT_ARTIFACT_SHA256:-}"

PREFIX="[r2-acceptance]"
say()  { printf '\n%s %s\n' "$PREFIX" "$*"; }
info() { printf '%s %s\n' "$PREFIX" "$*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-upgrade-baseline-fixture.sh
source "$SCRIPT_DIR/uat-upgrade-baseline-fixture.sh"
# Shared measurement primitives only (structural rich allowed-root JSON parse,
# fail-closed residue inventory); the script's own helpers below win.
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

# redact masks bearer-token values (admin/session dht_, credential dhc_) in a
# captured stream so they never reach the CI log. Session IDs (dhs_) and
# credential IDs (dhcr_) are not bearer secrets and are left intact.
redact() {
  sed -E \
    -e 's/dht_[A-Za-z0-9_-]+/<redacted-token>/g' \
    -e 's/dhc_[A-Za-z0-9_-]+/<redacted-token>/g'
}

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
[ -n "$ARTIFACT_PATH_IN" ] || { echo "error: UAT_ARTIFACT_PATH is required" >&2; exit 1; }
[ -f "$ARTIFACT_PATH_IN" ] || { echo "error: UAT_ARTIFACT_PATH is not a regular file: $ARTIFACT_PATH_IN" >&2; exit 1; }
[ -n "$ARTIFACT_SHA256_IN" ] || { echo "error: UAT_ARTIFACT_SHA256 is required" >&2; exit 1; }

# Verify the exact candidate DEB bytes once, up front (never recompute-and-trust).
ACTUAL_SHA="$(sha256sum "$ARTIFACT_PATH_IN" | awk '{print $1}')"
[ "$ACTUAL_SHA" = "$ARTIFACT_SHA256_IN" ] || {
  echo "error: candidate DEB SHA-256 mismatch (expected $ARTIFACT_SHA256_IN, got $ACTUAL_SHA)" >&2
  exit 1
}

# --- fail-closed accounting --------------------------------------------------

FAIL_COUNT=0
BLOCKED_COUNT=0

acc_ok() { printf '  ok:   %s\n' "$*"; }

acc_fail() {
  printf '  FAIL: %s\n' "$*" >&2
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

acc_blocked() {
  printf '  BLOCKED: %s\n' "$*" >&2
  BLOCKED_COUNT=$((BLOCKED_COUNT + 1))
}

scenario() { # name
  say "scenario $1"
}

# dh is the installed system-mode docker-helper CLI.
dh() { /usr/bin/docker-helper "$@"; }

# wait_health SOCKET_OR_URL: poll GET /health until it succeeds (bounded).
wait_health() {
  local target="$1" _i=0
  for _i in $(seq 1 100); do
    if [ "${target#http}" != "$target" ]; then
      curl --silent --fail --max-time 1 "$target/health" >/dev/null 2>&1 && return 0
    else
      curl --silent --fail --max-time 1 --unix-socket "$target" http://localhost/health >/dev/null 2>&1 && return 0
    fi
    if ! systemctl is-active --quiet docker-helper.service 2>/dev/null; then
      return 1
    fi
    sleep 0.2
  done
  return 1
}

# observe_mf_failclosed: bounded fail-closed observation of the refused
# candidate startup (MF decoy in place). With Type=exec the start job
# completes the moment the binary is exec'd, BEFORE the serve refuses, and
# Restart=on-failure then re-executes the unit, so systemd passes through
# transient active windows while the refusal repeats until the start limit
# stops it. Transient systemd active is therefore never treated as evidence
# here. The fail-closed contract is observed directly:
#   * the expected serve_startup refusal must appear in the journal, and
#   * daemon readiness must NEVER become available at any point of the whole
#     observation window (GET /health over the unix socket) — the refusal
#     must not degenerate into a serving daemon.
# The observation ends when the unit reaches its terminal failed state
# (restarts exhausted: nothing further can start) or the bounded window
# expires. Sets:
#   MF_REFUSAL           the last observed serve_startup refusal journal line
#                        ("" when none appeared)
#   MF_HEALTH_AVAILABLE  1 when daemon readiness became available at ANY point
#                        of the window, else 0
observe_mf_failclosed() {
  MF_REFUSAL=""
  MF_HEALTH_AVAILABLE=0
  local _i=0
  for _i in $(seq 1 40); do
    if [ -S "$SOCK" ] && curl --silent --fail --max-time 1 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1; then
      MF_HEALTH_AVAILABLE=1
      break
    fi
    if [ -z "$MF_REFUSAL" ]; then
      MF_REFUSAL="$(journalctl --utc -u docker-helper.service --since '-3 min' --no-pager 2>/dev/null \
        | grep '"operation":"serve_startup"' \
        | grep 'unsupported session_filesystem_snapshot_entries schema' | tail -1 || true)"
    fi
    systemctl is-failed --quiet docker-helper.service 2>/dev/null && break
    sleep 1
  done
}

# json_field extracts a string field from a JSON document read on stdin.
json_field() { # field
  grep -oP "\"$1\": \"\K[^\"]+" | head -1
}

# classify_registry_failure STREAM — the single classifier for a captured
# docker CLI failure stream in the registry scenarios. Emits one of:
#   network — a network/backend marker is present (checked FIRST). This is
#             NEVER proof of a registry auth/authorization denial, even if an
#             auth marker also appears below.
#   auth    — a registry auth/authorization-denial marker is present and no
#             network marker matched.
#   unknown — neither; NOT proof of a registry auth/authorization denial.
# Markers mirror production classifyDockerError (docker_error_classify.go) and
# are matched case-insensitively. Fail-closed: only "auth" may satisfy an
# auth-denial acceptance assertion.
classify_registry_failure() {
  local stream="$1"

  if grep -qiE \
      'dial tcp|connection refused|no such host|i\/o timeout|tls handshake timeout|connection reset|proxyconnect|net\/http: request canceled' <<<"$stream"; then
    printf 'network\n'
    return 0
  fi

  if grep -qiE \
      'unauthorized|authentication required|401 unauthorized|failed with status: 401|pull access denied|denied: requested access|authorization failed|no basic auth credentials' <<<"$stream"; then
    printf 'auth\n'
    return 0
  fi

  printf 'unknown\n'
  return 0
}

SOCK="/run/docker-helper/docker-helper.sock"
HTTP_ENDPOINT="http://127.0.0.1:52375"
CRED_DIR="/tmp/uat-r2ac"
rm -rf "$CRED_DIR"; mkdir -p "$CRED_DIR"

cleanup() {
  docker rm -f uatr2f-rtdir >/dev/null 2>&1 || true
  systemctl stop docker-helper.service >/dev/null 2>&1 || true
  systemctl disable docker-helper.service >/dev/null 2>&1 || true
  apparmor_parser -R /etc/apparmor.d/docker-helper-system 2>/dev/null || true
  pkill -u uatcoex docker-helper 2>/dev/null || true
  kill "${D_OP_CLI_PID:-}" 2>/dev/null || true
  rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper "$CRED_DIR"
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

if dpkg -i "$ARTIFACT_PATH_IN" >/tmp/r2ac-install.log 2>&1; then
  info "candidate DEB installed (sha256 verified: $ACTUAL_SHA)"
else
  echo "error: dpkg -i failed for candidate DEB (see /tmp/r2ac-install.log)" >&2
  exit 1
fi
dpkg -S /usr/bin/docker-helper >/dev/null 2>&1 || { echo "error: binary not owned by package" >&2; exit 1; }

INIT_OUT="$(docker-helper init --allowed-root "$ALLOWED_ROOT" 2>&1)"; INIT_EC=$?
if [ "$INIT_EC" -ne 0 ]; then
  printf '%s\n' "$INIT_OUT" | redact >&2
  echo "error: docker-helper init failed" >&2
  exit 1
fi
systemctl daemon-reload || { echo "error: daemon-reload failed" >&2; exit 1; }
systemctl enable --now docker-helper.service >/dev/null 2>&1 || { echo "error: enable --now failed" >&2; exit 1; }
for _ in $(seq 1 30); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
systemctl is-active --quiet docker-helper.service || { echo "error: service not active" >&2; exit 1; }
DH_PID="$(systemctl show -p MainPID --value docker-helper.service)"
[ "$(cat "/proc/$DH_PID/attr/current" 2>/dev/null || true)" = "docker-helper-system (enforce)" ] \
  || { echo "error: service not AppArmor-confined after setup install" >&2; exit 1; }
wait_health "$SOCK" || { echo "error: API socket not ready" >&2; exit 1; }
[ "$(docker-helper version)" = "$VERSION" ] \
  || { echo "error: installed binary version mismatch (expected $VERSION)" >&2; exit 1; }

# Ensure the shared fixture image is present (availability only; not an
# operation under test).
docker pull alpine:3.24 >/dev/null 2>&1 || true

# set_up_principal USER CREDFILE creates the OS user, docker-helper principal,
# a credential, and a principal session; sets GLOBAL_USER / GLOBAL_CRED_ID /
# GLOBAL_SESSION_ID / GLOBAL_SESSION_TOKEN.
set_up_principal() {
  local user="$1" credfile="$2" home out json
  GLOBAL_USER="$user"
  if ! getent passwd "$user" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$user" || return 1
  fi
  home="$(getent passwd "$user" | cut -d: -f6)"
  mkdir -p "$home/ws"; chown -R "$user:$user" "$home/ws"
  # The candidate CLI requires --issue-credential/--no-credential on
  # non-interactive stdin; the v2.0.0 upgrade baseline (scenarios F/G) predates
  # the flags. Try the candidate form first, then the baseline form.
  dh principal create --system --no-credential "$user" >/dev/null 2>&1 \
    || dh principal create --system "$user" >/dev/null 2>&1 || true
  dh principal set --system "$user" enabled true >/dev/null 2>&1 || true
  dh principal allowed-root add --system "$user" "$ALLOWED_ROOT" >/dev/null 2>&1 || true
  rm -f "$credfile"
  out="$(dh credential create --system --name r2ac "$user" 2>/dev/null)" || return 1
  GLOBAL_CRED_ID="$(printf '%s\n' "$out" | sed -n 's/^  ID:    //p' | tr -d '[:space:]')"
  GLOBAL_CRED_TOKEN="$(printf '%s\n' "$out" | sed -n 's/^  Token: //p' | tr -d '[:space:]')"
  [ -n "$GLOBAL_CRED_ID" ] && [ -n "$GLOBAL_CRED_TOKEN" ] || return 1
  printf '%s\n' "$GLOBAL_CRED_TOKEN" > "$credfile"; chmod 600 "$credfile"
  # The final ownership model provisions a Principal's enabled inherit-scope
  # 'default' Launcher automatically at Principal creation (and startup
  # migration backfills Principals that predate the rule), and a selector-less
  # principal-credential Session resolves to that Launcher (deriving the
  # Principal through it). Under the v2.0.0 upgrade baseline (scenario F),
  # which predates the Launcher control plane, provisioning does not exist:
  # raw HTTP is used to create the default Launcher over the control-plane API
  # with the system admin token (never printed; sent only as an Authorization
  # header), because under that baseline the route is absent (HTTP 404, a
  # plain text 404 page, no JSON body). Under that baseline a principal Session
  # must still be creatable WITHOUT a Launcher, so a 404 (route not
  # implemented) is tolerated and the Session create below exercises that
  # version's own ownership semantics. Any other status demands a live default
  # Launcher — creation conflict (409) from the candidate's own eager
  # provisioning is also acceptable, since the required state already exists.
  ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
  [ -n "$ADMIN_TOKEN" ] || { echo "error: could not read the admin token from /etc/docker-helper/admin.token" >&2; return 1; }
  LAUNCHER_HTTP="$(curl --silent --output /tmp/r2ac-launcher.json --write-out '%{http_code}' --max-time 5 \
    --unix-socket "$SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"scope":"inherit"}' "http://localhost/principals/$user/launchers" 2>/dev/null || true)"
  if [ "$LAUNCHER_HTTP" != "404" ]; then
    LAUNCHER_JSON="$(cat /tmp/r2ac-launcher.json 2>/dev/null || true)"
    # 200: the baseline/admin path created the Launcher. 409: the candidate
    # already provisioned 'default' eagerly at Principal creation — the
    # required state exists. Anything else is a real failure.
    printf '%s\n' "$LAUNCHER_JSON" | grep -q '"ok":true' \
      || { [ "$LAUNCHER_HTTP" = "409" ] || { echo "error: default launcher create for principal '$user' failed (http=$LAUNCHER_HTTP): $LAUNCHER_JSON" >&2; return 1; }; }
  fi
  json="$(dh session create --system --token-file "$credfile" --workspace "$home/ws" --json 2>/dev/null)" || return 1
  GLOBAL_SESSION_ID="$(printf '%s' "$json" | json_field id)"
  GLOBAL_SESSION_TOKEN="$(printf '%s' "$json" | json_field token)"
  [ -n "$GLOBAL_SESSION_ID" ] && [ -n "$GLOBAL_SESSION_TOKEN" ] || return 1
  return 0
}

# ==============================================================================
# scenario A: two credentials for one Principal, independent revocation
# ==============================================================================
scenario "A: two-credential independent revocation"

A_USER="uatr2ac"
A_CRED_A="$CRED_DIR/a.tok"
A_CRED_B="$CRED_DIR/b.tok"
A_WORKSPACE="$(getent passwd "$A_USER" 2>/dev/null | cut -d: -f6)"
[ -n "$A_WORKSPACE" ] || A_WORKSPACE="/home/$A_USER"
mkdir -p "$A_WORKSPACE/ws"; chown -R "$A_USER:$A_USER" "$A_WORKSPACE/ws" 2>/dev/null || true

set_up_principal "$A_USER" "$A_CRED_A" || acc_fail "principal setup failed"
A_PRINC="$GLOBAL_USER"; A_TOK_A="$GLOBAL_SESSION_TOKEN"

# credential B for the SAME principal.
B_OUT="$(dh credential create --system --name r2ac-b "$A_PRINC" 2>/dev/null)" \
  || { acc_fail "credential B create failed"; :; }
B_TOKEN="$(printf '%s\n' "$B_OUT" | sed -n 's/^  Token: //p' | tr -d '[:space:]')"
printf '%s\n' "$B_TOKEN" > "$A_CRED_B"; chmod 600 "$A_CRED_B"

# B authenticates as the same principal and creates a valid session.
B_SESS_JSON="$(dh session create --system --token-file "$A_CRED_B" --workspace "$A_WORKSPACE/ws" --json 2>/dev/null)"
B_SESS_ID="$(printf '%s' "$B_SESS_JSON" | json_field id)"
if [ -n "$B_SESS_ID" ]; then
  acc_ok "credential B authenticates as principal $A_PRINC and created session $B_SESS_ID"
else
  acc_fail "credential B could not create a session"
fi

# A already-issued session (created through A) must remain valid.
if DOCKER_HELPER_SESSION_TOKEN="$A_TOK_A" \
    dh run --image alpine:3.24 -- sh -ec 'echo A-OK' | grep -q 'A-OK'; then
  acc_ok "pre-revoke session token created through A works"
else
  acc_fail "pre-revoke session token created through A failed"
fi

# Revoke credential A.
dh credential revoke --system "$GLOBAL_CRED_ID" >/dev/null 2>&1 \
  && acc_ok "credential A revoked" || acc_fail "credential A revoke failed"

# A can no longer create a new session.
if dh session create --system --token-file "$A_CRED_A" --workspace "$A_WORKSPACE/ws" --json >/dev/null 2>&1; then
  acc_fail "revoked credential A still created a session"
else
  acc_ok "revoked credential A can no longer create a session"
fi

# B continues to work.
if dh session create --system --token-file "$A_CRED_B" --workspace "$A_WORKSPACE/ws" --json >/dev/null 2>&1; then
  acc_ok "credential B still creates sessions after A revoked"
else
  acc_fail "credential B stopped working after A revoked"
fi

# No credential secret appears in list/show/audit/log output. The list must
# succeed first — a failed list yields no output and would vacuously "leak
# nothing".
LIST_OUT="$(dh credential list --system "$A_PRINC" 2>&1)"; LIST_EC=$?
if [ "$LIST_EC" -ne 0 ]; then
  acc_fail "credential list failed (rc=$LIST_EC); leak check cannot proceed: $(printf '%s\n' "$LIST_OUT" | redact | tail -3)"
elif printf '%s\n' "$LIST_OUT" | grep -q 'dhc_'; then
  acc_fail "credential list leaked a credential secret"
else
  acc_ok "credential list shows no credential secrets"
fi
LIST_AUDIT="$(journalctl --utc -u docker-helper.service --since '-5 min' --no-pager 2>/dev/null)"
if printf '%s\n' "$LIST_AUDIT" | grep -q 'dhc_'; then
  acc_fail "journal audit leaked a credential secret"
else
  acc_ok "journal audit shows no credential secrets"
fi

# ==============================================================================
# scenario B: principal_name in real operation audit
# ==============================================================================
scenario "B: principal_name in real operation audit"

B_USER="uatr2audit"
B_CRED="$CRED_DIR/audit.tok"
set_up_principal "$B_USER" "$B_CRED" || acc_fail "audit principal setup failed"
B_AUDIT_SESSION="$GLOBAL_SESSION_ID"
B_AUDIT_TOKEN="$GLOBAL_SESSION_TOKEN"

BEFORE="$(date -u +'%Y-%m-%d %H:%M:%S')"
sleep 0.1

if DOCKER_HELPER_SESSION_TOKEN="$B_AUDIT_TOKEN" \
    dh run --image alpine:3.24 -- sh -ec 'echo AUDIT-OP-OK' | grep -q 'AUDIT-OP-OK'; then
  acc_ok "principal-owned Docker operation executed"
else
  acc_fail "principal-owned Docker operation failed"
fi

# Structured audit lines from the journal (JSON Lines, stream=audit). Use the
# audit stream field, not unrelated log prose.
AUDIT_JSON="$(journalctl --utc -u docker-helper.service --since "$BEFORE" --no-pager 2>/dev/null \
  | grep '"stream":"audit"' || true)"

PRINC_EVENT="$(printf '%s\n' "$AUDIT_JSON" | grep '"event":"run.start"' | tail -1 || true)"
if printf '%s\n' "$PRINC_EVENT" | grep -q "\"principal_name\":\"$B_USER\""; then
  acc_ok "audit run.start carries principal_name=$B_USER"
else
  acc_fail "audit run.start lacks principal_name=$B_USER: $PRINC_EVENT"
fi
if printf '%s\n' "$PRINC_EVENT" | grep -q "\"session_id\":\"$B_AUDIT_SESSION\""; then
  acc_ok "audit run.start carries session_id=$B_AUDIT_SESSION"
else
  acc_fail "audit run.start lacks session attribution: $PRINC_EVENT"
fi

# No credential secret, no session bearer, no registry/secret leakage in audit.
if printf '%s\n' "$AUDIT_JSON" | grep -q 'dhc_'; then
  acc_fail "audit leaked a credential secret"
else
  acc_ok "audit contains no credential secret"
fi
if printf '%s\n' "$AUDIT_JSON" | grep -q "$B_AUDIT_TOKEN"; then
  acc_fail "audit leaked the session bearer token"
else
  acc_ok "audit contains no session bearer token"
fi

# Stage 1.3 retired the selector-less / global-root admin Session: every Session
# is owned by a Launcher, and the Principal is derived through that Launcher. A
# session run's run.start audit event therefore always carries the owning
# principal_name. The former "legacy admin session audit omits principal_name"
# check asserted the retired model and no longer applies.

# ==============================================================================
# scenario C: registry login end-to-end + session isolation
# ==============================================================================
scenario "C: registry login end-to-end + session isolation"

C_USER="uatr2reg"
C_CRED="$CRED_DIR/reg.tok"
set_up_principal "$C_USER" "$C_CRED" || acc_fail "registry principal setup failed"
C_SESSION_A="$GLOBAL_SESSION_ID"; C_TOKEN_A="$GLOBAL_SESSION_TOKEN"

# Session B: a second principal with its own session (isolation target).
C_USER_B="uatr2regb"
C_CRED_B="$CRED_DIR/regb.tok"
set_up_principal "$C_USER_B" "$C_CRED_B" || acc_fail "registry principal B setup failed"
C_TOKEN_B="$GLOBAL_SESSION_TOKEN"

GATEWAY="$(ip -4 addr show docker0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)"
[ -n "$GATEWAY" ] || GATEWAY="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true)"
[ -n "$GATEWAY" ] || { acc_blocked "cannot determine docker bridge gateway for local registry"; :; }

REG_PORT=5001
REG_ADDR="$GATEWAY:$REG_PORT"
REG_HTUSER="uatreguser"
# A unique random marker is embedded in the registry password so the
# leak-absence checks can grep for something that can never occur in
# unrelated output.
REG_MARKER="$(openssl rand -hex 12)"
REG_HTPASS="uat-secret-$REG_MARKER"
REGISTRY_CID=""
DOCKER_CFG_DIR="/tmp/uat-dockercfg"
DOCKER_DAEMON_JSON="/etc/docker/daemon.json"
DAEMON_JSON_BACKUP="/tmp/uat-daemon.json.bak"

if [ -n "$GATEWAY" ]; then
  # 1. Configure Docker's insecure-registries for the bridge registry address
  #    BEFORE the registry exists, so the daemon restart cannot interfere with
  #    the fixture mid-scenario. UAT-harness-owned setup, restored afterwards.
  #    The guard is deterministic (grep for our exact registry address), never
  #    an inference from /info.
  NEED_INSECURE=0
  if [ -f "$DOCKER_DAEMON_JSON" ] && grep -q "$REG_ADDR" "$DOCKER_DAEMON_JSON" 2>/dev/null; then
    : # already configured for this address
  else
    NEED_INSECURE=1
  fi
  if [ "$NEED_INSECURE" = 1 ]; then
    if [ -f "$DOCKER_DAEMON_JSON" ]; then
      cp "$DOCKER_DAEMON_JSON" "$DAEMON_JSON_BACKUP"
    else
      printf '{}\n' > "$DAEMON_JSON_BACKUP"
    fi
    if command -v jq >/dev/null 2>&1; then
      if [ -f "$DOCKER_DAEMON_JSON" ]; then
        jq ". + {\"insecure-registries\": (.\"insecure-registries\" // [] | . + [\"$REG_ADDR\"] | unique)}" "$DOCKER_DAEMON_JSON" > /tmp/daemon.json.new
      else
        jq -n "{\"insecure-registries\": [\"$REG_ADDR\"]}" > /tmp/daemon.json.new
      fi
      mv /tmp/daemon.json.new "$DOCKER_DAEMON_JSON"
    else
      # No jq: write a minimal daemon.json only if none exists (common case).
      if [ ! -f "$DOCKER_DAEMON_JSON" ]; then
        printf '{"insecure-registries":["%s"]}\n' "$REG_ADDR" > "$DOCKER_DAEMON_JSON"
      else
        acc_fail "cannot merge insecure-registries without jq (existing $DOCKER_DAEMON_JSON)"
        : "${DAEMON_JSON_BACKUP:-}"
      fi
    fi
    systemctl restart docker >/dev/null 2>&1 || acc_fail "docker daemon restart failed after insecure-registries config"
    for _ in $(seq 1 60); do
      docker info >/dev/null 2>&1 && break
      sleep 1
    done
    docker info >/dev/null 2>&1 || acc_fail "docker daemon did not recover after insecure-registries config"
  fi

  # 2. Generate the htpasswd file on the HOST, independent of any tools inside
  #    the registry image (which may not ship htpasswd). The registry binary
  #    only accepts bcrypt hashes, so use Python's crypt (the documented hash
  #    format); anything else (apr1/plaintext) is rejected with 401 by the
  #    current distribution registry. The fixture is a bounded UAT-owned
  #    random secret.
  rm -rf /tmp/uat-registry-auth; mkdir -p /tmp/uat-registry-auth
  if python3 -c 'import crypt,sys; print(crypt.crypt(sys.argv[1], crypt.mksalt(crypt.METHOD_BLOWFISH)))' "$REG_HTPASS" \
      > /tmp/uat-registry-auth/htpasswd.new 2>/dev/null \
      && [ -s /tmp/uat-registry-auth/htpasswd.new ]; then
    printf '%s:%s\n' "$REG_HTUSER" "$(cat /tmp/uat-registry-auth/htpasswd.new)" > /tmp/uat-registry-auth/htpasswd
    acc_ok "registry htpasswd generated (host python bcrypt)"
  else
    acc_blocked "could not generate bcrypt registry htpasswd (python crypt unavailable)"
  fi
  chmod 0644 /tmp/uat-registry-auth/htpasswd

  if [ -s /tmp/uat-registry-auth/htpasswd ]; then
    REGISTRY_CID="$(docker run -d --name uat-registry-r2ac -p "$REG_PORT:5000" \
      -e REGISTRY_AUTH=htpasswd \
      -e REGISTRY_AUTH_HTPASSWD_REALM=UAT-Registry \
      -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
      -v /tmp/uat-registry-auth:/auth:ro registry:2 2>/tmp/uat-registry-run.err || true)"
    if [ -z "$REGISTRY_CID" ]; then
      acc_blocked "could not start local authenticated registry container: $(tail -2 /tmp/uat-registry-run.err | redact)"
    fi
  fi
fi

if [ -n "$REGISTRY_CID" ]; then
  # Wait for the registry to serve (loopback, auth required -> 401).
  REG_READY=0
  for _ in $(seq 1 60); do
    if curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$REG_PORT/v2/" 2>/dev/null | grep -q '401'; then
      REG_READY=1; break
    fi
    sleep 1
  done
  [ "$REG_READY" = 1 ] || acc_blocked "local registry did not become ready"
  # Re-verify the container is actually running (not exited after serving).
  if [ "$REG_READY" = 1 ] && ! docker ps -q --filter "name=uat-registry-r2ac" | grep -q .; then
    acc_blocked "local registry container exited after readiness: $(docker logs --tail 15 uat-registry-r2ac 2>&1 | redact | tr '\n' ' ')"
    REG_READY=0
  fi
  REG_UP=1
elif [ -s /tmp/uat-registry-auth/htpasswd ] && [ -n "$GATEWAY" ]; then
  acc_blocked "registry scenario could not start (no registry container)"
  REG_UP=0
else
  REG_UP=0
fi

if [ "$REG_UP" = 1 ]; then

  # 2. Seed a private image with UAT-owned credentials, using an isolated
  #    docker config so the host ~/.docker/config.json stays clean.
  rm -rf "$DOCKER_CFG_DIR"; mkdir -p "$DOCKER_CFG_DIR"
  if printf '%s\n' "$REG_HTPASS" | docker --config "$DOCKER_CFG_DIR" login --username "$REG_HTUSER" --password-stdin "127.0.0.1:$REG_PORT" >/tmp/r2ac-seed-login.err 2>&1 \
    && docker tag alpine:3.24 "127.0.0.1:$REG_PORT/uat/private:v1" >/dev/null 2>&1 \
    && docker --config "$DOCKER_CFG_DIR" push "127.0.0.1:$REG_PORT/uat/private:v1" >/tmp/r2ac-seed-push.err 2>&1; then
    acc_ok "seeded private image 127.0.0.1:$REG_PORT/uat/private:v1 (UAT-owned credentials)"
  else
    acc_fail "could not seed the private image into the local registry"
    sed 's/^/    seed-login: /' /tmp/r2ac-seed-login.err 2>/dev/null | redact | tail -4 >&2
    sed 's/^/    seed-push: /' /tmp/r2ac-seed-push.err 2>/dev/null | redact | tail -4 >&2
    docker ps -a --filter "name=uat-registry-r2ac" --format 'registry-state: {{.Status}}' 2>/dev/null >&2
    docker logs --tail 15 uat-registry-r2ac 2>&1 | sed 's/^/    registry-log: /' | redact >&2 || true
  fi

  # 3-4. Session A has no registry credentials -> private pull must FAIL with
  #      a registry authentication/authorization denial. Any other failure
  #      (Docker/helper runtime, network) is an unexpected error, NOT proof of
  #      the no-credentials path. The classifier is fail-closed: only its
  #      "auth" result may satisfy this assertion (network/unknown cannot).
  A_NOAUTH_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$C_TOKEN_A" \
    dh run --image "$REG_ADDR/uat/private:v1" -- sh -ec 'true' 2>&1)"
  A_NOAUTH_EC=$?
  A_NOAUTH_KIND="$(classify_registry_failure "$A_NOAUTH_OUT")"
  if [ "$A_NOAUTH_EC" -eq 0 ]; then
    acc_fail "private pull unexpectedly succeeded without registry credentials (session A)"
  elif [ "$A_NOAUTH_KIND" = auth ]; then
    acc_ok "private pull fails for session A without registry credentials (auth denial)"
  elif [ "$A_NOAUTH_KIND" = network ]; then
    acc_fail "private pull failed for session A with a network error, not a registry auth denial (rc=$A_NOAUTH_EC): $(printf '%s\n' "$A_NOAUTH_OUT" | redact | tail -3)"
  else
    acc_fail "private pull failed for session A but not for a registry auth reason (rc=$A_NOAUTH_EC): $(printf '%s\n' "$A_NOAUTH_OUT" | redact | tail -3)"
  fi

  # 5. docker-helper registry login for session A (password via stdin).
  if printf '%s\n' "$REG_HTPASS" | DOCKER_HELPER_SESSION_TOKEN="$C_TOKEN_A" \
      dh registry login --registry "$REG_ADDR" --username "$REG_HTUSER" --password-stdin >/tmp/r2ac-reglogin.out 2>&1; then
    acc_ok "docker-helper registry login succeeded for session A"
  else
    acc_fail "docker-helper registry login failed for session A: $(tail -3 /tmp/r2ac-reglogin.out | redact)"
  fi

  # 6. Private pull now succeeds in session A.
  if DOCKER_HELPER_SESSION_TOKEN="$C_TOKEN_A" \
      dh run --image "$REG_ADDR/uat/private:v1" -- sh -ec 'echo REG-A-OK' | grep -q 'REG-A-OK'; then
    acc_ok "private pull+run succeeds in session A after registry login"
  else
    acc_fail "private pull+run failed in session A after registry login"
  fi

  # 7. Session B still cannot pull it (session isolation). Session A's pull
  #    cached the image in the local Docker daemon, so remove the cached image
  #    first (harness-owned cleanup): otherwise session B would "succeed" by
  #    reusing the local cache without ever contacting the registry, which is
  #    not what the isolation contract proves. The expected failure must be a
  #    registry authentication/authorization denial — any other failure
  #    (Docker/helper runtime, network) is an unexpected error, not proof of
  #    isolation. The classifier is fail-closed: only its "auth" result may
  #    satisfy this assertion (network/unknown cannot).
  docker rmi "$REG_ADDR/uat/private:v1" >/dev/null 2>&1 || true
  B_ISO_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$C_TOKEN_B" \
    dh run --image "$REG_ADDR/uat/private:v1" -- sh -ec 'true' 2>&1)"
  B_ISO_EC=$?
  B_ISO_KIND="$(classify_registry_failure "$B_ISO_OUT")"
  if [ "$B_ISO_EC" -eq 0 ]; then
    acc_fail "session B unexpectedly pulled the private image (isolation broken)"
  elif [ "$B_ISO_KIND" = auth ]; then
    acc_ok "session B cannot pull the private image (isolation holds: auth denial)"
  elif [ "$B_ISO_KIND" = network ]; then
    acc_fail "session B pull failed with a network error, not a registry auth denial (rc=$B_ISO_EC): $(printf '%s\n' "$B_ISO_OUT" | redact | tail -3)"
  else
    acc_fail "session B pull failed but not for a registry auth reason (rc=$B_ISO_EC): $(printf '%s\n' "$B_ISO_OUT" | redact | tail -3)"
  fi

  # 8. Registry password absent from journal/audit, operation output, host config.
  PASS_MARKER="$REG_MARKER"
  JOURNAL="$(journalctl --utc -u docker-helper.service --since '-10 min' --no-pager 2>/dev/null)"
  if printf '%s\n' "$JOURNAL" | grep -q "$PASS_MARKER"; then
    acc_fail "registry password leaked into journal/audit"
  else
    acc_ok "registry password absent from journal/audit"
  fi
  # Session A (which holds the registry credentials) re-pulls the image after
  # the isolation check removed the local cache; its output is the successful
  # authenticated path, i.e. the strongest place a password could leak. The
  # run MUST succeed first — a failed pull cannot leak the password through
  # its output, so the absence-of-leak assertion is only meaningful after the
  # authenticated pull/run actually succeeded.
  OP_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$C_TOKEN_A" \
    dh run --image "$REG_ADDR/uat/private:v1" -- sh -ec 'true' 2>&1)"
  OP_EC=$?
  if [ "$OP_EC" -ne 0 ]; then
    acc_fail "authenticated re-pull (session A) failed (rc=$OP_EC): $(printf '%s\n' "$OP_OUT" | redact | tail -3)"
  elif printf '%s\n' "$OP_OUT" | grep -q "$PASS_MARKER"; then
    acc_fail "registry password leaked into operation output"
  else
    acc_ok "authenticated re-pull succeeded; registry password absent from operation output"
  fi
  HOST_DOCKER_CFG="$HOME/.docker/config.json"
  if [ -f "$HOST_DOCKER_CFG" ] && grep -q "127.0.0.1:$REG_PORT" "$HOST_DOCKER_CFG"; then
    acc_fail "host user ~/.docker/config.json gained the registry auth"
  else
    acc_ok "host user ~/.docker/config.json has no registry auth (session-scoped)"
  fi

  # 9. Session deletion removes the session-scoped Docker auth material.
  C_SESS_DIR="/run/docker-helper/sessions/$C_SESSION_A"
  if [ -f "$C_SESS_DIR/docker/config.json" ]; then
    acc_ok "session-scoped Docker auth material written under the session runtime dir"
    if dh session delete --system --id "$C_SESSION_A" >/dev/null 2>&1; then
      if [ -e "$C_SESS_DIR" ]; then
        acc_fail "session runtime dir (docker auth material) survived session deletion"
      else
        acc_ok "session deletion removed the session-scoped Docker auth material"
      fi
    else
      acc_fail "session delete failed for session A"
    fi
  else
    acc_fail "session-scoped Docker auth material not present under $C_SESS_DIR/docker/config.json"
    dh session delete --system --id "$C_SESSION_A" >/dev/null 2>&1 || true
  fi

  # Restore the Docker daemon configuration (UAT-harness-owned setup).
  if [ -f "$DAEMON_JSON_BACKUP" ]; then
    if [ "$(cat "$DAEMON_JSON_BACKUP")" = "{}" ]; then
      rm -f "$DOCKER_DAEMON_JSON"
    else
      mv "$DAEMON_JSON_BACKUP" "$DOCKER_DAEMON_JSON"
    fi
    systemctl restart docker >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do
      docker info >/dev/null 2>&1 && break
      sleep 1
    done
    docker info >/dev/null 2>&1 || acc_fail "docker daemon did not recover after config restore"
  fi
  docker rm -f uat-registry-r2ac >/dev/null 2>&1 || true
  docker rmi "$REG_ADDR/uat/private:v1" >/dev/null 2>&1 || true
  rm -rf "$DOCKER_CFG_DIR" /tmp/uat-registry-auth
fi

# ==============================================================================
# scenario D: bounded restart/shutdown with active operations
# ==============================================================================
scenario "D: bounded restart/shutdown with active operations"

D_USER="uatr2restart"
D_CRED="$CRED_DIR/restart.tok"
set_up_principal "$D_USER" "$D_CRED" || acc_fail "restart principal setup failed"
D_TOKEN="$GLOBAL_SESSION_TOKEN"

start_long_op() { # sets D_CID from the daemon cidfile
  local before now
  before="$(ls /run/docker-helper/*.cid 2>/dev/null | wc -l)"
  DOCKER_HELPER_SESSION_TOKEN="$D_TOKEN" \
    dh run --image alpine:3.24 -- sh -ec 'while true; do sleep 1; done' \
    >/tmp/r2ac-longop.out 2>&1 &
  D_OP_CLI_PID=$!
  # Wait until the daemon actually created the container (cidfile) and the
  # container is in a running state (not a blind sleep; polls the real state).
  for _ in $(seq 1 100); do
    now="$(ls /run/docker-helper/*.cid 2>/dev/null | wc -l)"
    if [ "$now" -gt "$before" ]; then
      D_CIDFILE="$(ls -t /run/docker-helper/*.cid 2>/dev/null | head -1)"
      D_CID="$(cat "$D_CIDFILE" 2>/dev/null || true)"
      if [ -n "$D_CID" ] && docker inspect -f '{{.State.Running}}' "$D_CID" 2>/dev/null | grep -q true; then
        acc_ok "long-running operation is actually running (container $D_CID)"
        return 0
      fi
    fi
    sleep 0.2
  done
  acc_fail "long-running operation never reached a running container state"
  return 1
}

wait_no_container() { # CID
  local cid="$1" _i=0
  for _i in $(seq 1 150); do
    if ! docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null | grep -q true; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

# --- D1: restart while an operation is active -------------------------------
D_CID=""
start_long_op || true

if [ -n "$D_CID" ]; then
  T0="$(date +%s)"
  systemctl restart docker-helper.service >/tmp/r2ac-restart.log 2>&1
  RC=$?
  T1="$(date +%s)"
  RESTART_SECS=$((T1 - T0))
  if [ "$RC" -eq 0 ] && systemctl is-active --quiet docker-helper.service; then
    acc_ok "docker-helper.service restarted within bounded window (${RESTART_SECS}s)"
  else
    acc_fail "docker-helper.service restart failed (see /tmp/r2ac-restart.log)"
  fi
  if wait_health "$SOCK"; then
    acc_ok "daemon returned healthy after restart"
  else
    acc_fail "daemon did not return healthy after restart"
  fi
  if wait_no_container "$D_CID"; then
    acc_ok "old active operation container terminated by bounded shutdown (no resume)"
  else
    acc_fail "old active operation container survived restart (uncontrolled leak)"
  fi
  # No uncontrolled helper subprocess / mount-pin / runtime leak.
  LEAK="$(find /run/docker-helper/mounts -mindepth 2 -maxdepth 2 -type d 2>/dev/null | grep -E '/[0-9]+$' || true)"
  if [ -z "$LEAK" ]; then
    acc_ok "no stale mount pins after restart"
  else
    acc_fail "stale mount pins after restart: $LEAK"
  fi
  # A fresh operation succeeds afterwards.
  FRESH_JSON="$(dh session create --system --token-file "$D_CRED" --workspace "$(getent passwd "$D_USER" | cut -d: -f6)/ws" --json 2>/dev/null)" \
    && FRESH_TOKEN="$(printf '%s' "$FRESH_JSON" | json_field token)"
  if [ -n "${FRESH_TOKEN:-}" ] && \
      DOCKER_HELPER_SESSION_TOKEN="$FRESH_TOKEN" \
      dh run --image alpine:3.24 -- sh -ec 'echo FRESH-OK' | grep -q 'FRESH-OK'; then
    acc_ok "fresh operation succeeds after restart"
  else
    acc_fail "fresh operation failed after restart"
  fi
else
  acc_fail "restart scenario could not start a long-running operation"
fi

# --- D2: explicit stop while an operation is active --------------------------
D_CID=""
start_long_op || true

if [ -n "$D_CID" ]; then
  T0="$(date +%s)"
  systemctl stop docker-helper.service >/tmp/r2ac-stop.log 2>&1
  RC=$?
  T1="$(date +%s)"
  STOP_SECS=$((T1 - T0))
  if [ "$RC" -eq 0 ] && ! systemctl is-active --quiet docker-helper.service; then
    acc_ok "docker-helper.service stopped while an operation was active (${STOP_SECS}s, bounded)"
  else
    acc_fail "docker-helper.service did not stop cleanly while an operation was active"
  fi
  if wait_no_container "$D_CID"; then
    acc_ok "active operation container terminated on explicit stop (bounded shutdown)"
  else
    acc_fail "active operation container survived explicit stop (uncontrolled leak)"
  fi
else
  acc_fail "shutdown scenario could not start a long-running operation"
fi

# Bring the service back for the remaining scenarios.
kill "${D_OP_CLI_PID:-}" 2>/dev/null || true
systemctl start docker-helper.service >/dev/null 2>&1 || true
for _ in $(seq 1 30); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
wait_health "$SOCK" || acc_fail "daemon not healthy after restart for later scenarios"

# ==============================================================================
# scenario E: user-mode + system-mode coexistence
# ==============================================================================
scenario "E: user-mode + system-mode coexistence"

E_USER="uatcoex"

E_SYSTEM_SESS=""

# 1. package is installed; stop/disable the system daemon so the user-mode
#    daemon is started FIRST (the required ordering).
systemctl stop docker-helper.service >/dev/null 2>&1 || true
systemctl disable docker-helper.service >/dev/null 2>&1 || true

# 2. create a real non-root UAT user.
if getent passwd "$E_USER" >/dev/null 2>&1; then
  userdel -r "$E_USER" >/dev/null 2>&1 || true
fi
useradd -m -s /bin/bash "$E_USER" 2>/dev/null || { acc_blocked "could not create coexistence user"; :; }
E_UID="$(id -u "$E_USER")"
E_HOME="$(getent passwd "$E_USER" | cut -d: -f6)"
usermod -aG docker "$E_USER" 2>/dev/null || true
mkdir -p "$E_HOME/ws"; chown -R "$E_USER:$E_USER" "$E_HOME/ws"

# XDG runtime dir for the user-mode daemon (no logind session on the runner).
E_XDG_RUNTIME="/run/user/$E_UID"
mkdir -p "$E_XDG_RUNTIME"
chown "$E_USER:$E_USER" "$E_XDG_RUNTIME"
chmod 0700 "$E_XDG_RUNTIME"

# A clean, user-scoped environment for every user-mode docker-helper process.
# `env -i` prevents the CI runner's inherited XDG_CONFIG_HOME/XDG_STATE_HOME
# (etc.) from leaking into the user-mode daemon: os.UserConfigDir() on Linux
# prefers $XDG_CONFIG_HOME over $HOME, so a leaked runner value would make the
# user-mode init write into the runner's config tree instead of the UAT user's.
E_ENV="env -i HOME=$E_HOME XDG_RUNTIME_DIR=$E_XDG_RUNTIME PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# 3. BEFORE starting the system daemon, initialize + start the user's user-mode
#    daemon.
{
  echo "=== coexistence pre-init diagnostics ==="
  echo "system socket exists: $(test -S /run/docker-helper/docker-helper.sock && echo yes || echo no)"
  echo "user groups: $(id -nG "$E_USER")"
  if sudo -u "$E_USER" $E_ENV sh -c 'test -S /run/docker.sock && echo "docker.sock visible" || echo "docker.sock NOT visible"'; then
    :
  fi
} > /tmp/r2ac-coex-diag.log 2>&1 || true
if sudo -u "$E_USER" $E_ENV docker-helper init --allowed-root "$E_HOME" >/tmp/r2ac-coex-init.log 2>&1; then
  acc_ok "user-mode init succeeded for $E_USER"
else
  acc_fail "user-mode init failed for $E_USER (see /tmp/r2ac-coex-init.log)"
  sed 's/^/    init-log: /' /tmp/r2ac-coex-init.log 2>/dev/null | redact | tail -15 >&2
  sed 's/^/    diag: /' /tmp/r2ac-coex-diag.log 2>/dev/null | redact | tail -10 >&2
fi

E_USER_SOCK="$E_XDG_RUNTIME/docker-helper/docker-helper.sock"
sudo -u "$E_USER" $E_ENV docker-helper serve >/tmp/r2ac-user-serve.log 2>&1 &
E_USER_SERVE_PID=$!
E_USER_READY=0
for _ in $(seq 1 100); do
  if [ -S "$E_USER_SOCK" ] && curl --silent --fail --max-time 1 --unix-socket "$E_USER_SOCK" http://localhost/health >/dev/null 2>&1; then
    E_USER_READY=1; break
  fi
  sleep 0.2
done
[ "$E_USER_READY" = 1 ] && acc_ok "user-mode daemon healthy on its own socket" || acc_fail "user-mode daemon did not become ready"

# 4. prove user-mode socket/config/state/database work (a user session + run).
E_USER_SESS=""
if [ "$E_USER_READY" = 1 ]; then
  E_USER_SESS_JSON="$(sudo -u "$E_USER" $E_ENV docker-helper session create --workspace "$E_HOME/ws" --json 2>/tmp/r2ac-coex-usr-sess.err)" \
    && E_USER_SESS="$(printf '%s' "$E_USER_SESS_JSON" | json_field id)" \
    && E_USER_TOK="$(printf '%s' "$E_USER_SESS_JSON" | json_field token)"
  if [ -n "$E_USER_SESS" ]; then
    acc_ok "user-mode session created via the user socket ($E_USER_SESS)"
    if [ -f "$E_HOME/.config/docker-helper/docker-helper.db" ] \
        || [ -f "$E_HOME/.local/state/docker-helper/docker-helper.db" ]; then
      acc_ok "user-mode database exists under the user's own state path"
    else
      acc_fail "user-mode database not found under user state path"
    fi
    if sudo -u "$E_USER" env -i DOCKER_HELPER_SESSION_TOKEN="$E_USER_TOK" HOME="$E_HOME" XDG_RUNTIME_DIR="$E_XDG_RUNTIME" PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        docker-helper run --image alpine:3.24 -- sh -ec 'echo USER-MODE-OK' | grep -q 'USER-MODE-OK'; then
      acc_ok "user-mode docker-helper operation works"
    else
      acc_fail "user-mode docker-helper operation failed"
    fi
  else
    acc_fail "user-mode session create failed: $(cat /tmp/r2ac-coex-usr-sess.err | redact)"
  fi
fi

# 5. start system mode. The system daemon was already initialized by the
#    suite setup (config + admin.token + database persist across scenarios);
#    init is not idempotent and must not be re-run. The ordering that matters
#    is that the user-mode daemon started BEFORE the system daemon.
if [ -f /etc/docker-helper/config.json ] && [ -f /etc/docker-helper/admin.token ]; then
  acc_ok "system mode already initialized (setup); starting system daemon"
else
  acc_fail "system mode not initialized when coexistence started"
fi
systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
for _ in $(seq 1 30); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
if wait_health "$SOCK"; then
  acc_ok "system daemon healthy while user-mode daemon runs"
else
  acc_fail "system daemon not healthy while user-mode daemon runs"
fi

# 6. prove BOTH daemons remain healthy simultaneously.
if curl --silent --fail --max-time 1 --unix-socket "$E_USER_SOCK" http://localhost/health >/dev/null 2>&1 \
    && curl --silent --fail --max-time 1 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1 \
    && curl --silent --fail --max-time 1 "$HTTP_ENDPOINT/health" >/dev/null 2>&1; then
  acc_ok "user socket + system socket + system HTTP all healthy simultaneously"
else
  acc_fail "not both daemons healthy simultaneously"
fi

# 7. prove paths/sockets/state are distinct.
if [ "$E_USER_SOCK" = "$SOCK" ]; then
  acc_fail "user and system sockets are not distinct"
else
  acc_ok "user socket ($E_USER_SOCK) distinct from system socket ($SOCK)"
fi
SYS_DB="/var/lib/docker-helper/docker-helper.db"
if [ -f "$SYS_DB" ] && [ "$SYS_DB" != "$E_HOME/.local/state/docker-helper/docker-helper.db" ]; then
  acc_ok "system database at $SYS_DB is distinct from user-mode state"
else
  acc_fail "system/user databases not distinct or system DB missing"
fi

# 8. default endpoint for that user selects the existing user socket.
if [ "$E_USER_READY" = 1 ]; then
  DEFAULT_SESS_JSON="$(sudo -u "$E_USER" $E_ENV docker-helper session create --workspace "$E_HOME/ws" --json 2>/dev/null)" \
    && DEFAULT_SESS="$(printf '%s' "$DEFAULT_SESS_JSON" | json_field id)"
  if [ -n "${DEFAULT_SESS:-}" ]; then
    # The default-endpoint session must live in the USER daemon, not the
    # system daemon. The system session list must succeed first — a failed
    # list would vacuously "not contain" the session.
    SYS_LIST="$(dh session list --system --token-file /etc/docker-helper/admin.token 2>&1)"; SYS_LIST_EC=$?
    if [ "$SYS_LIST_EC" -ne 0 ]; then
      acc_fail "system session list failed (rc=$SYS_LIST_EC); default-endpoint leak check cannot proceed"
    elif printf '%s\n' "$SYS_LIST" | grep -q "$DEFAULT_SESS"; then
      acc_fail "default endpoint session leaked into the system daemon"
    else
      acc_ok "user's default endpoint selected the existing user socket (not the system daemon)"
    fi
  else
    acc_fail "user's default-endpoint session create failed"
  fi
else
  acc_fail "cannot verify default endpoint selection without a user daemon"
fi

# 9. explicit --system selects the system daemon (operator creates a principal
#    + credential for the user; the user installs it, then --system works).
E_OPERATOR_CRED="$CRED_DIR/coex-sys.tok"
if set_up_principal "$E_USER" "$E_OPERATOR_CRED" >/dev/null 2>&1; then
  E_SYSTEM_SESS="$GLOBAL_SESSION_ID"
  if [ -n "$E_SYSTEM_SESS" ]; then
    # A system-mode session for the coexistence user must be visible to the
    # SYSTEM daemon (proves --system/credential path selected the system daemon).
    SYS_LIST2="$(dh session list --system --token-file /etc/docker-helper/admin.token 2>/dev/null)"
    if printf '%s\n' "$SYS_LIST2" | grep -q "$E_SYSTEM_SESS"; then
      acc_ok "explicit system-mode session is owned by the system daemon"
    else
      acc_fail "explicit system-mode session not found in the system daemon"
    fi
    # A system-mode session token must NOT be consumed by the user daemon.
    if sudo -u "$E_USER" env -i DOCKER_HELPER_SESSION_TOKEN="$GLOBAL_SESSION_TOKEN" HOME="$E_HOME" XDG_RUNTIME_DIR="$E_XDG_RUNTIME" PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        docker-helper run --image alpine:3.24 -- sh -ec 'true' >/dev/null 2>&1; then
      acc_fail "system-mode session token was consumed by the user-mode daemon"
    else
      acc_ok "system-mode session token rejected by the user-mode daemon"
    fi
  fi
else
  acc_fail "could not provision a system credential for the coexistence user"
fi

# 10. a user-mode session token must NOT be consumed by the system daemon.
if [ -n "${E_USER_TOK:-}" ]; then
  if DOCKER_HELPER_SESSION_TOKEN="$E_USER_TOK" \
      dh run --image alpine:3.24 -- sh -ec 'true' >/dev/null 2>&1; then
    acc_fail "user-mode session token was consumed by the system daemon"
  else
    acc_ok "user-mode session token rejected by the system daemon"
  fi
fi

# Tear down the user-mode daemon for the lifecycle phase.
kill "$E_USER_SERVE_PID" 2>/dev/null || true
wait "$E_USER_SERVE_PID" 2>/dev/null || true
userdel -r "$E_USER" >/dev/null 2>&1 || true
rm -rf "$E_XDG_RUNTIME"
systemctl stop docker-helper.service >/dev/null 2>&1 || true

# ==============================================================================
# scenario G: v2.0.0 -> candidate upgrade ownership migration (depth proofs)
#
# Seeds real v2.0.0 state (principal + credential + attributable principal
# session + a non-attributable admin session), upgrades to the exact candidate
# DEB, and proves the migration contract end-to-end on real packages:
#   G1  pre-upgrade Principal credential still authenticates with its retained
#       identity (GET /auth authority=principal, principal=<user>)
#   G2  the attributable v2.0 session is re-owned by the principal's 'default'
#       Launcher (session list shows launcher=default, principal=<user>)
#   G3  the pre-upgrade credential still creates sessions (auth semantics kept)
#   G4  exactly one 'default' inherit Launcher exists for the principal
#   G5  the non-attributable admin session was invalidated: absent from the
#       session list; its bearer is first proven to authenticate on the
#       session data plane before the upgrade (GET /operations/{id} with an
#       unknown id -> 404 operation_not_found), then rejected by the same
#       data plane after the upgrade (401 unauthorized); /auth is not used
#       for this invariant (it rejects Session tokens by design); the
#       invalidated session leaves no stale helper-owned session runtime
#       state (its runtime artifact, materialized before the upgrade through
#       a session-scoped Docker operation, is removed by the candidate
#       startup cleanup)
#   G6  no Launcher credential was fabricated for the migrated default
#       Launcher (GET credential -> 404 launcher_credential_not_found)
#   G7  restart idempotency: after a daemon restart the migrated ownership is
#       unchanged and the final sessions schema never re-gains principal_id
#       (schema asserted via the python3 sqlite3 stdlib)
#   G8  the migrated default Launcher is fully functional: credential create,
#       launcher-credential session create, and rotate (old rejected, new
#       works, same credential ID)
# ==============================================================================
scenario "G: upgrade ownership migration"

G_USER="uatr2upg"
G_CRED="$CRED_DIR/upg.tok"

G_BASELINE_DEB=""
if upgrade_baseline_fetch_deb /tmp/r2ac-g-baseline.deb >/dev/null 2>&1; then
  G_BASELINE_DEB="/tmp/r2ac-g-baseline.deb"
  acc_ok "v2.0.0 baseline DEB resolved and SHA-256 verified (migration scenario)"
else
  acc_blocked "could not resolve/verify the v2.0.0 baseline DEB (migration scenario)"
fi

if [ -n "$G_BASELINE_DEB" ]; then
  # clean slate; install the exact baseline and seed v2.0.0 state.
  systemctl stop docker-helper.service >/dev/null 2>&1 || true
  dpkg -P docker-helper >/dev/null 2>&1 || true
  rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper
  if dpkg -i "$G_BASELINE_DEB" >/tmp/r2ac-g-install.log 2>&1 \
      && [ "$(docker-helper version)" = "$UPGRADE_BASELINE_VERSION" ]; then
    acc_ok "v2.0.0 baseline installed for migration seeding"
  else
    acc_fail "v2.0.0 baseline install failed (see /tmp/r2ac-g-install.log)"
  fi
  if docker-helper init --allowed-root "$ALLOWED_ROOT" >/dev/null 2>&1; then
    acc_ok "system init on v2.0.0 baseline (migration scenario)"
  else
    acc_fail "system init failed on v2.0.0 baseline (migration scenario)"
  fi
  systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    systemctl is-active --quiet docker-helper.service && break
    sleep 1
  done
  wait_health "$SOCK" || acc_fail "v2.0.0 daemon not healthy (migration scenario)"

  # Seed attributable principal-owned state through v2.0.0's own semantics.
  if set_up_principal "$G_USER" "$G_CRED"; then
    G_SESSION_ID="$GLOBAL_SESSION_ID"
    G_ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
    acc_ok "v2.0.0 principal + credential + attributable session seeded ($G_SESSION_ID)"
  else
    G_SESSION_ID=""
    acc_fail "v2.0.0 principal seeding failed (migration scenario)"
  fi
  # Seed a non-attributable admin session (v2.0.0 admin sessions carry no
  # owner): the candidate migration must invalidate it.
  G_ADMIN_SESS_ID=""
  G_ADMIN_SESS_TOKEN=""
  G_HOME="$(getent passwd "$G_USER" | cut -d: -f6)"
  mkdir -p "$G_HOME/ws-admin"; chown -R "$G_USER:$G_USER" "$G_HOME/ws-admin"
  if [ -n "${G_ADMIN_TOKEN:-}" ]; then
    G_ADMIN_SESS_JSON="$(dh session create --system --token-file /etc/docker-helper/admin.token --workspace "$G_HOME/ws-admin" --json 2>/dev/null || true)"
    G_ADMIN_SESS_ID="$(printf '%s' "$G_ADMIN_SESS_JSON" | json_field id || true)"
    G_ADMIN_SESS_TOKEN="$(printf '%s' "$G_ADMIN_SESS_JSON" | json_field token || true)"
    if [ -n "$G_ADMIN_SESS_ID" ] && [ -n "$G_ADMIN_SESS_TOKEN" ]; then
      acc_ok "v2.0.0 non-attributable admin session seeded ($G_ADMIN_SESS_ID)"
    else
      acc_fail "v2.0.0 admin session seeding failed (migration scenario)"
    fi
  fi

  # G5 precondition (before upgrade): the admin session bearer authenticates
  # on a session-authenticated data-plane endpoint. GET /operations/{id} with
  # an unknown id reaches the operation lookup only after session
  # authentication, so 404 operation_not_found proves the bearer works;
  # 401 here would mean it does not. /auth is not used for this invariant:
  # it rejects Session tokens by design, valid ones included.
  if [ -n "${G_ADMIN_SESS_TOKEN:-}" ]; then
    G_OP_PRE_HTTP="$(curl --silent --output /tmp/r2ac-g-op-pre.json --write-out '%{http_code}' --max-time 5 \
      --unix-socket "$SOCK" -H "Authorization: Bearer $G_ADMIN_SESS_TOKEN" \
      "http://localhost/operations/uat-r2ac-nonexistent-operation" 2>/dev/null || true)"
    if [ "$G_OP_PRE_HTTP" = 404 ] \
        && grep -q '"code":"operation_not_found"' /tmp/r2ac-g-op-pre.json; then
      acc_ok "pre-upgrade admin session bearer authenticates on the session data plane (404 unknown operation)"
    else
      acc_fail "pre-upgrade admin session data-plane precondition failed (http=$G_OP_PRE_HTTP)"
    fi

    # Materialize the invalidated session's helper-owned session runtime
    # artifact through the canonical production path: a session-scoped
    # Docker operation creates /run/docker-helper/sessions/<id>/docker
    # (ensureSessionDockerDir).
    if DOCKER_HELPER_SESSION_TOKEN="$G_ADMIN_SESS_TOKEN" \
        dh run --image alpine:3.24 -- true >/tmp/r2ac-g-admin-run.log 2>&1; then
      acc_ok "session-scoped Docker operation ran for the admin session before upgrade"
    else
      acc_fail "session-scoped Docker operation failed before upgrade (see /tmp/r2ac-g-admin-run.log)"
    fi
    G_ADMIN_RT_DIR="/run/docker-helper/sessions/$G_ADMIN_SESS_ID"
    if [ -d "$G_ADMIN_RT_DIR/docker" ]; then
      acc_ok "session runtime artifact exists before upgrade ($G_ADMIN_RT_DIR/docker)"
    else
      acc_fail "session runtime artifact missing before upgrade"
    fi
  fi

  # Upgrade to the exact candidate DEB.
  if dpkg -i "$ARTIFACT_PATH_IN" >/tmp/r2ac-g-upgrade.log 2>&1 \
      && [ "$(docker-helper version)" = "$VERSION" ]; then
    acc_ok "upgraded to candidate DEB ($VERSION) for migration proof"
  else
    acc_fail "upgrade to candidate failed (see /tmp/r2ac-g-upgrade.log)"
  fi
  systemctl is-active --quiet docker-helper.service \
    || { systemctl start docker-helper.service >/dev/null 2>&1 || true; }
  for _ in $(seq 1 30); do
    systemctl is-active --quiet docker-helper.service && break
    sleep 1
  done
  wait_health "$SOCK" || acc_fail "daemon not healthy after migration upgrade"

  # The invalidated session must leave no stale helper-owned session runtime
  # state: the candidate startup pass removes session runtime directories
  # that no longer correspond to an active session
  # (cleanupStaleSessionRuntimeDirs).
  if [ -n "${G_ADMIN_SESS_ID:-}" ] && [ -n "${G_ADMIN_RT_DIR:-}" ]; then
    if [ -e "$G_ADMIN_RT_DIR" ]; then
      acc_fail "invalidated admin session left stale session runtime state ($G_ADMIN_RT_DIR)"
    else
      acc_ok "invalidated admin session left no stale session runtime state"
    fi
  fi

  # G1: pre-upgrade credential still authenticates with retained identity.
  G_TOK="$(cat "$G_CRED" 2>/dev/null || true)"
  G_AUTH_HTTP="$(curl --silent --output /tmp/r2ac-g-auth.json --write-out '%{http_code}' --max-time 5 \
    --unix-socket "$SOCK" -H "Authorization: Bearer $G_TOK" http://localhost/auth 2>/dev/null || true)"
  if [ "$G_AUTH_HTTP" = 200 ] \
      && grep -q '"authority":"principal"' /tmp/r2ac-g-auth.json \
      && grep -q "\"principal\":\"$G_USER\"" /tmp/r2ac-g-auth.json; then
    acc_ok "pre-upgrade credential authenticates as principal $G_USER (identity retained)"
  else
    acc_fail "pre-upgrade credential identity check failed (http=$G_AUTH_HTTP)"
  fi

  # G2: attributable session re-owned by the 'default' Launcher.
  if [ -n "${G_SESSION_ID:-}" ]; then
    G_LIST="$(dh session list --system --token-file /etc/docker-helper/admin.token --json 2>/dev/null)"
    if printf '%s\n' "$G_LIST" | grep -q "$G_SESSION_ID" \
        && printf '%s\n' "$G_LIST" | grep -q '"launcher": "default"' \
        && printf '%s\n' "$G_LIST" | grep -q "\"principal\": \"$G_USER\""; then
      acc_ok "migrated session owned by principal's default Launcher"
    else
      acc_fail "migrated session ownership wrong: $(printf '%s\n' "$G_LIST" | redact | tail -3)"
    fi
  fi

  # G3: pre-upgrade credential still creates sessions.
  G_NEW_JSON="$(dh session create --system --token-file "$G_CRED" --workspace "$G_HOME/ws" --json 2>/dev/null || true)"
  G_NEW_ID="$(printf '%s' "$G_NEW_JSON" | json_field id || true)"
  if [ -n "$G_NEW_ID" ]; then
    acc_ok "pre-upgrade credential still creates sessions ($G_NEW_ID)"
  else
    acc_fail "pre-upgrade credential lost session-creation capability"
  fi

  # G4: exactly one 'default' inherit Launcher for the principal.
  G_LAUNCHERS="$(dh launcher list --system --principal "$G_USER" --json 2>/dev/null)"
  G_LCOUNT="$(printf '%s\n' "$G_LAUNCHERS" | grep -c '"id": "dhl_' || true)"
  if [ "$G_LCOUNT" = 1 ] \
      && printf '%s\n' "$G_LAUNCHERS" | grep -q '"name": "default"' \
      && printf '%s\n' "$G_LAUNCHERS" | grep -q '"scope": "inherit"'; then
    acc_ok "exactly one default inherit Launcher exists for $G_USER"
  else
    acc_fail "default Launcher provisioning wrong after migration (count=$G_LCOUNT)"
  fi
  G_DEFAULT_ID="$(printf '%s\n' "$G_LAUNCHERS" | json_field id || true)"

  # G5: non-attributable admin session invalidated, never left ownerless.
  if [ -n "${G_ADMIN_SESS_ID:-}" ]; then
    G_LIST2="$(dh session list --system --token-file /etc/docker-helper/admin.token --json 2>/dev/null)"
    if printf '%s\n' "$G_LIST2" | grep -q "$G_ADMIN_SESS_ID"; then
      acc_fail "non-attributable admin session survived migration (must be invalidated)"
    else
      acc_ok "non-attributable admin session invalidated by migration"
    fi
    # The bearer must be rejected by the session data plane, not by /auth
    # (which rejects Session tokens by design): repeat the pre-upgrade
    # operation-status request; authentication now fails with 401.
    G_OP_HTTP="$(curl --silent --output /tmp/r2ac-g-op-post.json --write-out '%{http_code}' --max-time 5 \
      --unix-socket "$SOCK" -H "Authorization: Bearer $G_ADMIN_SESS_TOKEN" \
      "http://localhost/operations/uat-r2ac-nonexistent-operation" 2>/dev/null || true)"
    if [ "$G_OP_HTTP" = 401 ] && grep -q '"code":"unauthorized"' /tmp/r2ac-g-op-post.json; then
      acc_ok "invalidated admin session bearer rejected by the session data plane (401)"
    else
      acc_fail "invalidated admin session bearer not rejected by the data plane (http=$G_OP_HTTP)"
    fi
  fi

  # G6: no Launcher credential fabricated for the migrated default Launcher.
  G_CRED_HTTP="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
    --unix-socket "$SOCK" -H "Authorization: Bearer $G_ADMIN_TOKEN" \
    "http://localhost/principals/$G_USER/launchers/$G_DEFAULT_ID/credential" 2>/dev/null || true)"
  if [ "$G_CRED_HTTP" = 404 ]; then
    acc_ok "no Launcher credential fabricated for the migrated default Launcher (404)"
  else
    acc_fail "migrated default Launcher credential check failed (http=$G_CRED_HTTP)"
  fi

  # G7: restart idempotency + final schema never re-gains principal_id.
  systemctl restart docker-helper.service >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    systemctl is-active --quiet docker-helper.service && break
    sleep 1
  done
  if wait_health "$SOCK"; then
    G_LIST3="$(dh session list --system --token-file /etc/docker-helper/admin.token --json 2>/dev/null)"
    if printf '%s\n' "$G_LIST3" | grep -q "$G_SESSION_ID" \
        && printf '%s\n' "$G_LIST3" | grep -q '"launcher": "default"'; then
      acc_ok "migrated ownership stable across restart (idempotent migration)"
    else
      acc_fail "migrated ownership changed after restart"
    fi
    G_AUTH_HTTP2="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
      --unix-socket "$SOCK" -H "Authorization: Bearer $G_TOK" http://localhost/auth 2>/dev/null || true)"
    if [ "$G_AUTH_HTTP2" = 200 ]; then
      acc_ok "pre-upgrade credential still authenticates after restart"
    else
      acc_fail "pre-upgrade credential broken after restart (http=$G_AUTH_HTTP2)"
    fi
    if python3 -c '
import sqlite3, sys
db = sqlite3.connect("/var/lib/docker-helper/docker-helper.db")
cols = [r[1] for r in db.execute("PRAGMA table_info(sessions)")]
sys.exit(0 if ("principal_id" not in cols and "launcher_id" in cols) else 1)
' 2>/dev/null; then
      acc_ok "final sessions schema after restart: launcher_id present, principal_id absent"
    else
      acc_fail "final sessions schema wrong after restart (principal_id must never return)"
    fi
  else
    acc_fail "daemon not healthy after migration restart (idempotency not exercised)"
  fi

  # G8: migrated default Launcher is fully functional.
  G_ISSUE_OUT="$(dh launcher credential create --system --principal "$G_USER" "$G_DEFAULT_ID" 2>/dev/null || true)"
  G_LC_TOKEN="$(printf '%s' "$G_ISSUE_OUT" | json_field token || true)"
  G_LC_ID="$(printf '%s' "$G_ISSUE_OUT" | json_field id || true)"
  if [ -n "$G_LC_TOKEN" ] && [ -n "$G_LC_ID" ]; then
    printf '%s\n' "$G_LC_TOKEN" > "$CRED_DIR/upg-lc.tok"; chmod 600 "$CRED_DIR/upg-lc.tok"
    G_LC_JSON="$(dh session create --system --token-file "$CRED_DIR/upg-lc.tok" --workspace "$G_HOME/ws" --json 2>/dev/null || true)"
    if printf '%s' "$G_LC_JSON" | grep -q '"launcher": "default"'; then
      acc_ok "migrated default Launcher issues a working credential"
    else
      acc_fail "launcher credential on migrated default Launcher cannot create sessions"
    fi
    G_ROT_OUT="$(dh launcher credential rotate --system --principal "$G_USER" "$G_DEFAULT_ID" 2>/dev/null || true)"
    G_ROT_TOKEN="$(printf '%s' "$G_ROT_OUT" | json_field token || true)"
    G_ROT_ID="$(printf '%s' "$G_ROT_OUT" | json_field id || true)"
    if [ "$G_ROT_ID" = "$G_LC_ID" ] && [ -n "$G_ROT_TOKEN" ] && [ "$G_ROT_TOKEN" != "$G_LC_TOKEN" ]; then
      acc_ok "rotation keeps the same credential ID with a new bearer"
      printf '%s\n' "$G_ROT_TOKEN" > "$CRED_DIR/upg-lc2.tok"; chmod 600 "$CRED_DIR/upg-lc2.tok"
    else
      acc_fail "rotation on migrated Launcher misbehaved (id=$G_ROT_ID)"
    fi
    if dh session create --system --token-file "$CRED_DIR/upg-lc.tok" --workspace "$G_HOME/ws" --json >/dev/null 2>&1; then
      acc_fail "old launcher bearer still accepted after rotation"
    else
      acc_ok "old launcher bearer rejected after rotation"
    fi
    G_LC_JSON2="$(dh session create --system --token-file "$CRED_DIR/upg-lc2.tok" --workspace "$G_HOME/ws" --json 2>/dev/null || true)"
    if printf '%s' "$G_LC_JSON2" | grep -q '"launcher": "default"'; then
      acc_ok "rotated launcher credential creates sessions"
    else
      acc_fail "rotated launcher credential cannot create sessions"
    fi
  else
    acc_fail "credential issuance on migrated default Launcher failed"
  fi
fi

# ==============================================================================
# scenario M: v2.1.1 -> candidate migration (mandatory Release 2.2 gate)
#
# The v2.0.0 baseline of scenario G predates the 2.1 Launcher control plane,
# so Release 2.2 carries its own migration gate from the published stable
# v2.1.1 (the last path-only release), seeded through the v2.1.1 CLI itself:
#   M0  the pinned v2.1.1 baseline DEB resolves and its SHA-256 verifies
#   M1  real pre-upgrade state: two path-only global roots, two path-only
#       Principal roots, one restricted path-only Launcher root, principal +
#       launcher credentials, and two live Sessions (launcher-owned and
#       principal-owned)
#   MF  fail-closed migration: a pre-existing wrong-shaped
#       session_filesystem_snapshot_entries table makes the candidate refuse
#       startup with daemon readiness never becoming available; the refusal
#       leaves no half-migrated state (config.json bytes
#       unchanged, sessions schema unchanged, decoy table untouched and
#       empty); dropping the decoy recovers into the successful migration on
#       the same database
#   M2  legacy path-only config keeps read_write authority (the --json rich
#       list projection; the default list is the 2.1-compatible one path per
#       line) while config.json itself keeps the legacy path-only string form —
#       equivalent RW authority, never an object-form rewrite requirement
#   M3  Principal roots migrated as read_write
#   M4  Launcher roots migrated as read_write
#   M5  both pre-existing Sessions carry the compatibility
#       workspace/read_write snapshot (session show)
#   M6  identity preservation: principal credential authority, launcher
#       identity (same ID), both Session IDs in the authoritative list
#   M7  a real operation of the pre-existing Session keeps the 2.1 writable
#       behavior
#   M8  restart idempotency: policy and snapshots stable, sessions schema
#       final, snapshot table canonical
# ==============================================================================
scenario "M: v2.1.1 -> candidate migration"

M_USER="uatr2mig"
M_LCRED="$CRED_DIR/mig-lc.tok"

M_BASELINE_DEB=""
if upgrade211_fetch_deb /tmp/r2ac-m-baseline.deb >/dev/null 2>&1; then
  M_BASELINE_DEB="/tmp/r2ac-m-baseline.deb"
  acc_ok "v2.1.1 baseline DEB resolved and SHA-256 verified (migration gate)"
else
  acc_blocked "could not resolve/verify the v2.1.1 baseline DEB (mandatory migration gate)"
fi

if [ -n "$M_BASELINE_DEB" ]; then
  # Clean slate; install the exact v2.1.1 baseline and seed real state.
  systemctl stop docker-helper.service >/dev/null 2>&1 || true
  dpkg -P docker-helper >/dev/null 2>&1 || true
  rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper
  if dpkg -i "$M_BASELINE_DEB" >/tmp/r2ac-m-install.log 2>&1 \
      && [ "$(docker-helper version)" = "$UPGRADE211_VERSION" ]; then
    acc_ok "v2.1.1 baseline installed for migration seeding ($UPGRADE211_VERSION)"
  else
    acc_fail "v2.1.1 baseline install failed (see /tmp/r2ac-m-install.log)"
  fi
  if docker-helper init --allowed-root "$ALLOWED_ROOT" >/dev/null 2>&1; then
    acc_ok "system init on v2.1.1 baseline (path-only global root)"
  else
    acc_fail "system init failed on v2.1.1 baseline"
  fi
  systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    systemctl is-active --quiet docker-helper.service && break
    sleep 1
  done
  wait_health "$SOCK" || acc_fail "v2.1.1 daemon not healthy (migration gate)"

  # Seed real pre-upgrade state through the v2.1.1 CLI (path-only everywhere).
  if ! getent passwd "$M_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$M_USER" || true
  fi
  M_HOME="$(getent passwd "$M_USER" | cut -d: -f6)"
  M_POLICY="$M_HOME/policy"
  mkdir -p "$M_HOME/ws" "$M_POLICY/sub/ws"
  printf 'mig-input\n' > "$M_POLICY/sub/ws/input.txt"
  chown -R "$M_USER:$M_USER" "$M_HOME"
  if dh config allowed-root add "$M_POLICY" >/dev/null 2>&1 \
      && dh config allowed-root list 2>/dev/null | grep -qx "$M_POLICY" \
      && dh config allowed-root list 2>/dev/null | grep -qx "$ALLOWED_ROOT"; then
    acc_ok "M1 two path-only global roots seeded (init root + added root)"
  else
    acc_fail "M1 global allowed-root seeding failed"
  fi

  dh principal create --system --no-credential "$M_USER" >/dev/null 2>&1 || true
  dh principal set --system "$M_USER" enabled true >/dev/null 2>&1 || true
  dh principal allowed-root add --system "$M_USER" "$ALLOWED_ROOT" >/dev/null 2>&1 || true
  dh principal allowed-root add --system "$M_USER" "$M_POLICY" >/dev/null 2>&1 || true
  if dh principal allowed-root list --system "$M_USER" 2>/dev/null | grep -qx "$M_POLICY" \
      && dh principal allowed-root list --system "$M_USER" 2>/dev/null | grep -qx "$ALLOWED_ROOT"; then
    acc_ok "M1 two path-only Principal roots seeded"
  else
    acc_fail "M1 Principal allowed-root seeding failed"
  fi

  M_P_CRED_OUT="$(dh credential create --system --name mig "$M_USER" 2>/dev/null || true)"
  M_P_TOKEN="$(printf '%s\n' "$M_P_CRED_OUT" | sed -n 's/^  Token: //p' | tr -d '[:space:]')"
  M_P_CRED_ID="$(printf '%s\n' "$M_P_CRED_OUT" | sed -n 's/^  ID:    //p' | tr -d '[:space:]')"
  if [ -n "$M_P_TOKEN" ] && [ -n "$M_P_CRED_ID" ]; then
    acc_ok "M1 principal credential issued ($M_P_CRED_ID)"
  else
    acc_fail "M1 principal credential issuance failed"
  fi

  # Restricted Launcher with a path-only root, plus its credential.
  M_L_OUT="$(dh launcher create --system --principal "$M_USER" --name mlaunch \
    --allowed-root "$M_POLICY/sub" --no-credential 2>/dev/null || true)"
  M_L_ID="$(printf '%s\n' "$M_L_OUT" | json_field id)"
  if [ -n "$M_L_ID" ] \
      && dh launcher allowed-root list --system --principal "$M_USER" "$M_L_ID" 2>/dev/null | grep -qx "$M_POLICY/sub"; then
    acc_ok "M1 restricted path-only Launcher root seeded ($M_L_ID)"
  else
    acc_fail "M1 restricted Launcher root seeding failed"
  fi
  M_LC_OUT="$(dh launcher credential create --system --principal "$M_USER" "$M_L_ID" 2>/dev/null || true)"
  M_LC_TOKEN="$(printf '%s\n' "$M_LC_OUT" | json_field token)"
  if [ -n "$M_LC_TOKEN" ]; then
    printf '%s\n' "$M_LC_TOKEN" > "$M_LCRED"; chmod 600 "$M_LCRED"
    acc_ok "M1 launcher credential issued"
  else
    acc_fail "M1 launcher credential issuance failed"
  fi

  # Two live Sessions: launcher-owned and principal-owned.
  M_S1_JSON="$(dh session create --system --token-file "$M_LCRED" --workspace "$M_POLICY/sub/ws" --json 2>/dev/null || true)"
  M_S1_ID="$(printf '%s' "$M_S1_JSON" | json_field id)"
  M_S1_TOKEN="$(printf '%s' "$M_S1_JSON" | json_field token)"
  M_PCREDFILE="$CRED_DIR/mig-pc.tok"
  printf '%s\n' "$M_P_TOKEN" > "$M_PCREDFILE"; chmod 600 "$M_PCREDFILE"
  M_S2_JSON="$(dh session create --system --token-file "$M_PCREDFILE" --workspace "$M_HOME/ws" --json 2>/dev/null || true)"
  M_S2_ID="$(printf '%s' "$M_S2_JSON" | json_field id)"
  if [ -n "$M_S1_ID" ] && [ -n "$M_S2_ID" ]; then
    acc_ok "M1 live Sessions seeded (launcher=$M_S1_ID principal=$M_S2_ID)"
  else
    acc_fail "M1 Session seeding failed (launcher: '$M_S1_ID', principal: '$M_S2_ID')"
  fi

  # Pre-upgrade identity + config bytes recorded for the migration proofs.
  M_CONFIG_SHA="$(sha256sum /etc/docker-helper/config.json | awk '{print $1}')"
  M_AUTH_PRE_HTTP="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
    --unix-socket "$SOCK" -H "Authorization: Bearer $M_P_TOKEN" http://localhost/auth 2>/dev/null || true)"
  [ "$M_AUTH_PRE_HTTP" = 200 ] \
    && acc_ok "pre-upgrade principal credential authenticates on v2.1.1" \
    || acc_fail "pre-upgrade principal credential broken on v2.1.1 (http=$M_AUTH_PRE_HTTP)"

  # --- MF: fail-closed migration ------------------------------------------------
  # A wrong-shaped pre-existing snapshot table is unsupported state: the
  # candidate must refuse startup BEFORE any migration transaction, leaving
  # the database and config untouched.
  systemctl stop docker-helper.service >/dev/null 2>&1 || true
  if python3 -c '
import sqlite3, sys
db = sqlite3.connect("/var/lib/docker-helper/docker-helper.db")
db.execute("CREATE TABLE session_filesystem_snapshot_entries (session_id TEXT, path TEXT)")
db.commit()
' 2>/tmp/r2ac-m-decoy.err; then
    acc_ok "MF decoy wrong-shaped snapshot table prepared on the pre-upgrade database"
  else
    acc_fail "MF decoy table preparation failed: $(cat /tmp/r2ac-m-decoy.err 2>/dev/null | tail -2)"
  fi

  if dpkg -i "$ARTIFACT_PATH_IN" >/tmp/r2ac-m-upgrade.log 2>&1 \
      && [ "$(docker-helper version)" = "$VERSION" ]; then
    acc_ok "upgraded to candidate DEB ($VERSION) with the decoy in place"
  else
    acc_fail "candidate upgrade failed (see /tmp/r2ac-m-upgrade.log)"
  fi

  # Fail-closed observation (bounded, deterministic — see
  # observe_mf_failclosed): the expected serve_startup refusal must appear,
  # daemon readiness must never become available in the window, and transient
  # systemd active windows are never evidence (Type=exec completes the start
  # job at exec, before the serve refuses; Restart=on-failure re-executes the
  # unit until the start limit stops it).
  systemctl reset-failed docker-helper.service >/dev/null 2>&1 || true
  systemctl start docker-helper.service >/dev/null 2>&1 || true
  observe_mf_failclosed

  # Quiesce deterministically before the invariant checks: stop cancels any
  # remaining auto-restart and reset-failed clears the terminal failed state.
  systemctl stop docker-helper.service >/dev/null 2>&1 || true
  systemctl reset-failed docker-helper.service >/dev/null 2>&1 || true

  if [ -n "$MF_REFUSAL" ] && [ "$MF_HEALTH_AVAILABLE" = 0 ]; then
    acc_ok "MF startup refused closed: serve_startup refusal observed and daemon readiness never became available (transient active windows ignored)"
  else
    acc_fail "MF startup not proven fail-closed (refusal: ${MF_REFUSAL:-absent}, health became available: $MF_HEALTH_AVAILABLE)"
  fi

  # No half-migrated state: config bytes unchanged, sessions schema unchanged,
  # decoy table exactly as prepared (wrong shape, zero rows).
  M_CONFIG_SHA_FAIL="$(sha256sum /etc/docker-helper/config.json 2>/dev/null | awk '{print $1}')"
  if [ "$M_CONFIG_SHA_FAIL" = "$M_CONFIG_SHA" ]; then
    acc_ok "MF refusal left config.json bytes unchanged"
  else
    acc_fail "MF refusal rewrote config.json (half-migrated config state)"
  fi
  if python3 -c '
import sqlite3, sys
db = sqlite3.connect("/var/lib/docker-helper/docker-helper.db")
scols = [r[1] for r in db.execute("PRAGMA table_info(sessions)")]
dcols = [r[1] for r in db.execute("PRAGMA table_info(session_filesystem_snapshot_entries)")]
rows = db.execute("SELECT COUNT(*) FROM session_filesystem_snapshot_entries").fetchone()[0]
ok = ("principal_id" not in scols and "launcher_id" in scols
      and dcols == ["session_id", "path"] and rows == 0)
sys.exit(0 if ok else 1)
' 2>/dev/null; then
    acc_ok "MF refusal left the database untouched (sessions schema final, decoy intact and empty)"
  else
    acc_fail "MF refusal mutated the database (half-migrated DB state)"
  fi

  # Recovery: drop the decoy; the same database migrates successfully.
  if python3 -c '
import sqlite3, sys
db = sqlite3.connect("/var/lib/docker-helper/docker-helper.db")
db.execute("DROP TABLE session_filesystem_snapshot_entries")
db.commit()
' 2>/dev/null; then
    acc_ok "MF recovery precondition: decoy dropped"
  else
    acc_fail "MF decoy drop failed (recovery impossible)"
  fi
  systemctl reset-failed docker-helper.service >/dev/null 2>&1 || true
  systemctl start docker-helper.service >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    systemctl is-active --quiet docker-helper.service && break
    sleep 1
  done
  if wait_health "$SOCK"; then
    acc_ok "MF recovery: candidate started and migrated the same database"
  else
    acc_fail "MF recovery failed: daemon not healthy after dropping the decoy"
  fi

  # --- M2: legacy config keeps read_write authority in the legacy form ---------
  # The default list is the 2.1-compatible one path per line; the access
  # authority is proven through the explicit --json rich projection, parsed
  # structurally (path and access are separate lines in the pretty JSON, so
  # the projection is never grepped line-wise).
  M_LIST_JSON="$(dh config allowed-root list --json 2>/dev/null || true)"
  M_RW_ROOT="$(printf '%s' "$M_LIST_JSON" | allowed_root_json_access "$ALLOWED_ROOT")"
  M_RW_POLICY="$(printf '%s' "$M_LIST_JSON" | allowed_root_json_access "$M_POLICY")"
  if [ "$M_RW_ROOT" = read_write ] && [ "$M_RW_POLICY" = read_write ]; then
    acc_ok "M2 migrated path-only global roots carry read_write authority (--json rich projection)"
  else
    acc_fail "M2 global root access semantics wrong (rich projection: $M_LIST_JSON)"
  fi
  M_HUMAN_LIST="$(dh config allowed-root list 2>/dev/null || true)"
  if printf '%s\n' "$M_HUMAN_LIST" | grep -qx "$ALLOWED_ROOT" \
      && printf '%s\n' "$M_HUMAN_LIST" | grep -qx "$M_POLICY"; then
    acc_ok "M2 default human list keeps the 2.1 one-path-per-line contract (no ACCESS column)"
  else
    acc_fail "M2 default human list lost the 2.1 one-path-per-line contract: $M_HUMAN_LIST"
  fi
  if python3 -c '
import json, sys
cfg = json.load(open("/etc/docker-helper/config.json"))
roots = cfg.get("allowed_roots", [])
sys.exit(0 if isinstance(roots, list) and len(roots) == 2 and all(isinstance(r, str) for r in roots) else 1)
' 2>/dev/null; then
    acc_ok "M2 config.json keeps the legacy path-only string form (no object-form rewrite)"
  else
    acc_fail "M2 config.json legacy path-only form not preserved"
  fi

  # --- M3/M4: Principal and Launcher roots migrated read_write -----------------
  M_PLIST_JSON="$(dh principal allowed-root list --system --json "$M_USER" 2>/dev/null || true)"
  M_RW_P_ROOT="$(printf '%s' "$M_PLIST_JSON" | allowed_root_json_access "$ALLOWED_ROOT")"
  M_RW_P_POLICY="$(printf '%s' "$M_PLIST_JSON" | allowed_root_json_access "$M_POLICY")"
  if [ "$M_RW_P_ROOT" = read_write ] && [ "$M_RW_P_POLICY" = read_write ]; then
    acc_ok "M3 Principal roots migrated as read_write (--json rich projection)"
  else
    acc_fail "M3 Principal root migration wrong (rich projection: $M_PLIST_JSON)"
  fi
  M_LLIST_JSON="$(dh launcher allowed-root list --system --principal "$M_USER" --json "$M_L_ID" 2>/dev/null || true)"
  M_RW_L_SUB="$(printf '%s' "$M_LLIST_JSON" | allowed_root_json_access "$M_POLICY/sub")"
  if [ "$M_RW_L_SUB" = read_write ]; then
    acc_ok "M4 Launcher root migrated as read_write (--json rich projection)"
  else
    acc_fail "M4 Launcher root migration wrong (rich projection: $M_LLIST_JSON)"
  fi

  # --- M5: compatibility workspace/read_write snapshots ------------------------
  M_S1_SHOW="$(dh session show --system --id "$M_S1_ID" 2>/dev/null || true)"
  M_S2_SHOW="$(dh session show --system --id "$M_S2_ID" 2>/dev/null || true)"
  if printf '%s\n' "$M_S1_SHOW" | grep -Eq "^$(printf '%s' "$M_POLICY/sub/ws" | sed 's/[.[\*^$]/\\&/g')[[:space:]]+read_write$" \
      && printf '%s\n' "$M_S2_SHOW" | grep -Eq "^$(printf '%s' "$M_HOME/ws" | sed 's/[.[\*^$]/\\&/g')[[:space:]]+read_write$"; then
    acc_ok "M5 pre-existing Sessions carry the compatibility workspace/read_write snapshot"
  else
    acc_fail "M5 compatibility snapshot wrong (S1: $(printf '%s\n' "$M_S1_SHOW" | tail -4 | tr '\n' '; '))"
  fi

  # --- M6: identity preservation ----------------------------------------------
  M_AUTH_HTTP="$(curl --silent --output /tmp/r2ac-m-auth.json --write-out '%{http_code}' --max-time 5 \
    --unix-socket "$SOCK" -H "Authorization: Bearer $M_P_TOKEN" http://localhost/auth 2>/dev/null || true)"
  if [ "$M_AUTH_HTTP" = 200 ] && grep -q '"authority":"principal"' /tmp/r2ac-m-auth.json \
      && grep -q "\"principal\":\"$M_USER\"" /tmp/r2ac-m-auth.json; then
    acc_ok "M6 principal credential keeps its identity after migration"
  else
    acc_fail "M6 principal credential identity check failed (http=$M_AUTH_HTTP)"
  fi
  M_LAUNCHERS="$(dh launcher list --system --principal "$M_USER" --json 2>/dev/null || true)"
  if printf '%s\n' "$M_LAUNCHERS" | grep -q "\"id\": \"$M_L_ID\"" \
      && printf '%s\n' "$M_LAUNCHERS" | grep -q '"name": "mlaunch"'; then
    acc_ok "M6 launcher identity preserved (same ID and name)"
  else
    acc_fail "M6 launcher identity changed after migration"
  fi
  M_SESSIONS="$(dh session list --system --token-file /etc/docker-helper/admin.token --json 2>/dev/null || true)"
  if printf '%s\n' "$M_SESSIONS" | grep -q "$M_S1_ID" \
      && printf '%s\n' "$M_SESSIONS" | grep -q "$M_S2_ID"; then
    acc_ok "M6 both pre-existing Session IDs preserved in the authoritative list"
  else
    acc_fail "M6 pre-existing Session IDs not preserved"
  fi

  # --- M7: the old Session keeps the 2.1 writable behavior ---------------------
  if [ -n "${M_S1_TOKEN:-}" ]; then
    M_RUN_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$M_S1_TOKEN" \
      dh run --image alpine:3.24 --mount .:/mnt/ws -- \
      sh -ec 'echo migrated-write > /mnt/ws/after-migration.txt && cat /mnt/ws/input.txt && echo MIG-RW-OK' 2>&1)"
    if printf '%s\n' "$M_RUN_OUT" | grep -q 'MIG-RW-OK' \
        && [ "$(cat "$M_POLICY/sub/ws/after-migration.txt" 2>/dev/null)" = "migrated-write" ]; then
      acc_ok "M7 old Session still exposes its workspace writable (2.1 behavior preserved)"
    else
      acc_fail "M7 old Session writable behavior changed: $(printf '%s\n' "$M_RUN_OUT" | redact | tail -3)"
    fi
  else
    acc_fail "M7 old Session bearer unavailable (seed failed earlier)"
  fi

  # M8 pre-restart baseline: the canonical, formatting-independent rich
  # projection of the migrated policy (config and Principal roots). The
  # post-restart check compares this projection, never formatted output.
  M8_CONFIG_PROJ_BEFORE="$(dh config allowed-root list --json 2>/dev/null | allowed_root_json_projection)"
  M8_PRINCIPAL_PROJ_BEFORE="$(dh principal allowed-root list --system --json "$M_USER" 2>/dev/null | allowed_root_json_projection)"

  # --- M8: restart idempotency --------------------------------------------------
  systemctl restart docker-helper.service >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    systemctl is-active --quiet docker-helper.service && break
    sleep 1
  done
  if wait_health "$SOCK"; then
    M_S1_SHOW2="$(dh session show --system --id "$M_S1_ID" 2>/dev/null || true)"
    if printf '%s\n' "$M_S1_SHOW2" | grep -Eq "^$(printf '%s' "$M_POLICY/sub/ws" | sed 's/[.[\*^$]/\\&/g')[[:space:]]+read_write$"; then
      acc_ok "M8 snapshot stable across restart (idempotent migration)"
    else
      acc_fail "M8 snapshot changed after restart"
    fi
    M8_CONFIG_JSON="$(dh config allowed-root list --json 2>/dev/null || true)"
    M8_PRINCIPAL_JSON="$(dh principal allowed-root list --system --json "$M_USER" 2>/dev/null || true)"
    M8_CONFIG_RW="$(printf '%s' "$M8_CONFIG_JSON" | allowed_root_json_access "$M_POLICY")"
    M8_PRINCIPAL_RW="$(printf '%s' "$M8_PRINCIPAL_JSON" | allowed_root_json_access "$M_POLICY")"
    if [ "$(printf '%s' "$M8_CONFIG_JSON" | allowed_root_json_projection)" = "$M8_CONFIG_PROJ_BEFORE" ] \
        && [ "$(printf '%s' "$M8_PRINCIPAL_JSON" | allowed_root_json_projection)" = "$M8_PRINCIPAL_PROJ_BEFORE" ] \
        && [ "$M8_CONFIG_RW" = read_write ] && [ "$M8_PRINCIPAL_RW" = read_write ]; then
      acc_ok "M8 migrated policy stable across restart (canonical rich projection identical, read_write kept)"
    else
      acc_fail "M8 migrated policy changed after restart (projection before: config=[$M8_CONFIG_PROJ_BEFORE] principal=[$M8_PRINCIPAL_PROJ_BEFORE])"
    fi
    if python3 -c '
import sqlite3, sys
db = sqlite3.connect("/var/lib/docker-helper/docker-helper.db")
scols = [r[1] for r in db.execute("PRAGMA table_info(sessions)")]
snapcols = [r[1] for r in db.execute("PRAGMA table_info(session_filesystem_snapshot_entries)")]
ok = ("principal_id" not in scols and "launcher_id" in scols
      and snapcols == ["session_id", "position", "path", "access"])
sys.exit(0 if ok else 1)
' 2>/dev/null; then
      acc_ok "M8 final schema after restart: sessions final, snapshot table canonical"
    else
      acc_fail "M8 final schema wrong after restart"
    fi
  else
    acc_fail "M8 daemon not healthy after restart (idempotency not exercised)"
  fi
fi

# ==============================================================================
# scenario H: launcher hierarchy, isolation, rotation, and lifecycle (candidate)
#
# Exercised end-to-end against the installed candidate with two launchers on
# one principal:
#   H1  two launchers hold separate Session namespaces; each launcher
#       credential sees only its own sessions
#   H2  cross-launcher non-disclosure: foreign session delete is the same 404
#       outcome as a missing session
#   H3  credential rotation: old bearer rejected, replacement authorized, same
#       launcher identity, no second credential (409 launcher_credential_exists)
#   H4  restricted scope narrows the principal ceiling for new sessions; a
#       workspace outside the restricted Launcher scope but otherwise valid
#       gets the exact contract: HTTP 400 invalid_workspace
#   H5  an already-stored Launcher root becomes stale fail-closed when the
#       exact narrow Principal root containing it is removed: creation is
#       first proven to succeed inside the narrow ceiling (positive
#       precondition), then fails with 422 launcher_unavailable; the original
#       Principal root state is restored
#   H6  disabling a launcher deletes its sessions and rejects its bearer; an
#       individually disabled launcher stays disabled through a principal
#       disable/enable cycle
#   H7  checked delete: launcher delete fails with 409 launcher_runtime_active
#       while a session operation is running, leaving the launcher disabled
#       and its sessions invalidated; the delete succeeds once the operator
#       removes the runtime and retries
#   H8  no credential bearer leaks into journal/audit; rotation provenance
#       (launcher.credential_rotate with launcher_id) is visible in audit
# ==============================================================================
scenario "H: launcher hierarchy, isolation, rotation, lifecycle"

H_USER="uatr2lnc"
H_CRED="$CRED_DIR/lnc.tok"
if set_up_principal "$H_USER" "$H_CRED"; then
  acc_ok "hierarchy principal + default Launcher provisioned ($H_USER)"
else
  acc_fail "hierarchy principal setup failed"
fi
H_HOME="$(getent passwd "$H_USER" | cut -d: -f6)"
H_WS="$H_HOME/ws"
H_SUB="$H_HOME/sub"
mkdir -p "$H_SUB/ws"; chown -R "$H_USER:$H_USER" "$H_SUB"
H_ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"

# H1: two launchers with separate namespaces.
H_ALPHA_OUT="$(dh launcher create --system --principal "$H_USER" --name alpha --no-credential 2>/dev/null || true)"
H_ALPHA_ID="$(printf '%s' "$H_ALPHA_OUT" | json_field id || true)"
H_BETA_OUT="$(dh launcher create --system --principal "$H_USER" --name beta --allowed-root "$H_SUB" --no-credential 2>/dev/null || true)"
H_BETA_ID="$(printf '%s' "$H_BETA_OUT" | json_field id || true)"
if [ -n "$H_ALPHA_ID" ] && [ -n "$H_BETA_ID" ] && [ "$H_ALPHA_ID" != "$H_BETA_ID" ]; then
  acc_ok "two distinct launchers created (alpha=$H_ALPHA_ID, beta=$H_BETA_ID)"
else
  acc_fail "launcher creation failed (alpha=$H_ALPHA_ID beta=$H_BETA_ID)"
fi

# H1a: Principal-scoped launcher selectors. The omitted selector means the
# Principal's 'default' Launcher (created by the setup), the name and the ID
# of the same Launcher resolve identically, the same 'default' name under two
# Principals resolves independently (the migration scenario's principal still
# exists), and a name that exists only under another Principal is the same
# non-disclosing 404 as a missing selector.
H_SEL_DEF_JSON="$(dh launcher show --system --principal "$H_USER" 2>/dev/null || true)"
H_SEL_DEF_ID="$(printf '%s' "$H_SEL_DEF_JSON" | json_field id || true)"
H_SEL_DEF_NAME_ID="$(dh launcher show --system --principal "$H_USER" default 2>/dev/null | json_field id || true)"
H_SEL_ALPHA_NAME_ID="$(dh launcher show --system --principal "$H_USER" alpha 2>/dev/null | json_field id || true)"
H_SEL_UPG_DEF_ID="$(dh launcher show --system --principal "$M_USER" 2>/dev/null | json_field id || true)"
H_SEL_FOREIGN_HTTP="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
  --unix-socket "$SOCK" -H "Authorization: Bearer $H_ADMIN_TOKEN" \
  "http://localhost/principals/$M_USER/launchers/alpha" 2>/dev/null || true)"
H_SEL_MALFORMED_HTTP="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
  --unix-socket "$SOCK" -H "Authorization: Bearer $H_ADMIN_TOKEN" \
  "http://localhost/principals/$H_USER/launchers/Foo" 2>/dev/null || true)"
if [ -n "$H_SEL_DEF_ID" ] \
    && printf '%s' "$H_SEL_DEF_JSON" | grep -q '"name": "default"' \
    && [ "$H_SEL_DEF_NAME_ID" = "$H_SEL_DEF_ID" ] \
    && [ "$H_SEL_ALPHA_NAME_ID" = "$H_ALPHA_ID" ] \
    && [ -n "$H_SEL_UPG_DEF_ID" ] && [ "$H_SEL_UPG_DEF_ID" != "$H_SEL_DEF_ID" ] \
    && [ "$H_SEL_FOREIGN_HTTP" = 404 ] \
    && [ "$H_SEL_MALFORMED_HTTP" = 404 ]; then
  acc_ok "launcher selectors: omitted means default, name and ID resolve the same launcher, same name under two principals resolves independently ($H_SEL_DEF_ID != $H_SEL_UPG_DEF_ID)"
else
  acc_fail "launcher selector resolution broken (default=$H_SEL_DEF_ID by-name=$H_SEL_DEF_NAME_ID alpha-by-name=$H_SEL_ALPHA_NAME_ID/$H_ALPHA_ID upgrade-default=$H_SEL_UPG_DEF_ID foreign=$H_SEL_FOREIGN_HTTP malformed=$H_SEL_MALFORMED_HTTP)"
fi

H_ALPHA_TOK="$(dh launcher credential create --system --principal "$H_USER" "$H_ALPHA_ID" 2>/dev/null | json_field token || true)"
H_BETA_TOK="$(dh launcher credential create --system --principal "$H_USER" "$H_BETA_ID" 2>/dev/null | json_field token || true)"
[ -n "$H_ALPHA_TOK" ] && [ -n "$H_BETA_TOK" ] \
  && acc_ok "credentials issued for both launchers" \
  || acc_fail "launcher credential issuance failed"
printf '%s\n' "$H_ALPHA_TOK" > "$CRED_DIR/lnc-alpha.tok"; chmod 600 "$CRED_DIR/lnc-alpha.tok"
printf '%s\n' "$H_BETA_TOK" > "$CRED_DIR/lnc-beta.tok"; chmod 600 "$CRED_DIR/lnc-beta.tok"

H_ALPHA_SESS_JSON="$(dh session create --system --token-file "$CRED_DIR/lnc-alpha.tok" --workspace "$H_WS" --json 2>/dev/null || true)"
H_ALPHA_SESS="$(printf '%s' "$H_ALPHA_SESS_JSON" | json_field id || true)"
# The beta workspace must be a proper subdirectory of the Launcher allowed
# root; the root itself ($H_SUB) is rejected with 400 invalid_workspace.
H_BETA_SESS_JSON="$(dh session create --system --token-file "$CRED_DIR/lnc-beta.tok" --workspace "$H_SUB/ws" --json 2>/dev/null || true)"
H_BETA_SESS="$(printf '%s' "$H_BETA_SESS_JSON" | json_field id || true)"
if [ -n "$H_ALPHA_SESS" ] && [ -n "$H_BETA_SESS" ]; then
  acc_ok "each launcher created its own session (alpha=$H_ALPHA_SESS, beta=$H_BETA_SESS)"
else
  acc_fail "launcher-credential session creation failed (alpha=$H_ALPHA_SESS beta=$H_BETA_SESS)"
fi

if [ -n "${H_ALPHA_SESS:-}" ] && [ -n "${H_BETA_SESS:-}" ]; then
  # H1 (namespace separation) and H2 (non-disclosure) need both sessions.
  ALPHA_LIST="$(dh session list --system --token-file "$CRED_DIR/lnc-alpha.tok" --json 2>/dev/null)"
  BETA_LIST="$(dh session list --system --token-file "$CRED_DIR/lnc-beta.tok" --json 2>/dev/null)"
  if printf '%s\n' "$ALPHA_LIST" | grep -q "$H_ALPHA_SESS" \
      && ! printf '%s\n' "$ALPHA_LIST" | grep -q "$H_BETA_SESS" \
      && printf '%s\n' "$BETA_LIST" | grep -q "$H_BETA_SESS" \
      && ! printf '%s\n' "$BETA_LIST" | grep -q "$H_ALPHA_SESS"; then
    acc_ok "each launcher sees only its own session namespace"
  else
    acc_fail "launcher session namespaces are not isolated"
  fi
  H_DEL_HTTP="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
    --unix-socket "$SOCK" -H "Authorization: Bearer $H_BETA_TOK" \
    -X DELETE "http://localhost/sessions/$H_ALPHA_SESS" 2>/dev/null || true)"
  H_DEL_MISS_HTTP="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
    --unix-socket "$SOCK" -H "Authorization: Bearer $H_BETA_TOK" \
    -X DELETE "http://localhost/sessions/dhs_00000000000000000000000000000000" 2>/dev/null || true)"
  if [ "$H_DEL_HTTP" = 404 ] && [ "$H_DEL_HTTP" = "$H_DEL_MISS_HTTP" ]; then
    acc_ok "cross-launcher session delete is the same 404 as a missing session (non-disclosure)"
  else
    acc_fail "cross-launcher non-disclosure broken (foreign=$H_DEL_HTTP missing=$H_DEL_MISS_HTTP)"
  fi

  # H3: rotation continuity.
  H_ROT_OUT="$(dh launcher credential rotate --system --principal "$H_USER" "$H_ALPHA_ID" 2>/dev/null || true)"
  H_ALPHA_TOK2="$(printf '%s' "$H_ROT_OUT" | json_field token || true)"
  if [ -n "$H_ALPHA_TOK2" ] && [ "$H_ALPHA_TOK2" != "$H_ALPHA_TOK" ]; then
    printf '%s\n' "$H_ALPHA_TOK2" > "$CRED_DIR/lnc-alpha2.tok"; chmod 600 "$CRED_DIR/lnc-alpha2.tok"
    H_OLD_HTTP="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
      --unix-socket "$SOCK" -H "Authorization: Bearer $H_ALPHA_TOK" http://localhost/auth 2>/dev/null || true)"
    H_NEW_JSON="$(dh session create --system --token-file "$CRED_DIR/lnc-alpha2.tok" --workspace "$H_WS" --json 2>/dev/null || true)"
    H_NEW_SESS="$(printf '%s' "$H_NEW_JSON" | json_field id || true)"
    H_SHOW="$(dh launcher show --system --principal "$H_USER" "$H_ALPHA_ID" 2>/dev/null || true)"
    if [ "$H_OLD_HTTP" = 401 ] \
        && [ -n "$H_NEW_SESS" ] \
        && printf '%s\n' "$H_SHOW" | grep -q "\"id\": \"$H_ALPHA_ID\"" \
        && printf '%s\n' "$H_SHOW" | grep -q '"name": "alpha"'; then
      acc_ok "rotation: old bearer rejected, replacement works, launcher identity unchanged"
    else
      acc_fail "rotation continuity broken (old=$H_OLD_HTTP new=$H_NEW_SESS)"
    fi
    H_DUP_HTTP="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
      --unix-socket "$SOCK" -H "Authorization: Bearer $H_ADMIN_TOKEN" \
      -X PUT "http://localhost/principals/$H_USER/launchers/$H_ALPHA_ID/credential" 2>/dev/null || true)"
    if [ "$H_DUP_HTTP" = 409 ]; then
      acc_ok "no second launcher credential (issue after rotate -> 409 launcher_credential_exists)"
    else
      acc_fail "duplicate launcher credential not rejected (http=$H_DUP_HTTP)"
    fi
  else
    acc_fail "launcher credential rotate failed"
  fi

  # H4: restricted scope narrows new sessions; the exact current API contract
  # for a workspace outside the restricted Launcher scope but otherwise valid
  # (existing directory, inside the global root and the Principal ceiling) is
  # HTTP 400 with structured code invalid_workspace.
  H_NARROW_HTTP="$(curl --silent --output /tmp/r2ac-h-narrow.json --write-out '%{http_code}' --max-time 5 \
    --unix-socket "$SOCK" -H "Authorization: Bearer $H_BETA_TOK" \
    -H 'Content-Type: application/json' \
    -d "{\"workspace\":\"$H_WS\"}" http://localhost/sessions 2>/dev/null || true)"
  if [ "$H_NARROW_HTTP" = 400 ] \
      && grep -q '"code":"invalid_workspace"' /tmp/r2ac-h-narrow.json; then
    acc_ok "restricted launcher rejects out-of-scope workspace (400 invalid_workspace)"
  else
    acc_fail "restricted launcher out-of-scope workspace contract wrong (http=$H_NARROW_HTTP)"
  fi

  # H5: an already-stored Launcher root becomes stale fail-closed when the
  # exact narrow Principal root containing it is removed. The Principal holds
  # two roots at this point: $ALLOWED_ROOT (added by set_up_principal) and the
  # OS user's home directory (auto-installed as the default allowed root by
  # principal create). Narrowing to exactly {H_SUB} removes both; the Launcher
  # root ($H_SUB) is then the Principal's only root, the effective Principal
  # ceiling is exactly {H_SUB} and the stored Launcher root is demonstrably
  # inside it; a positive precondition proves session creation through the
  # Launcher succeeds. Removing that exact Principal root empties the ceiling,
  # the stored Launcher root becomes stale, and the same creation must fail
  # with HTTP 422 and structured code launcher_unavailable. The original
  # Principal root state is restored afterwards (later H checks reuse this
  # Principal).
  H5_REMOVED=false
  H5_NARROWED=false
  if dh principal allowed-root remove --system "$H_USER" "$ALLOWED_ROOT" >/dev/null 2>&1 \
      && dh principal allowed-root remove --system "$H_USER" "$H_HOME" >/dev/null 2>&1; then
    H5_REMOVED=true
    if dh principal allowed-root add --system "$H_USER" "$H_SUB" >/dev/null 2>&1; then
      H5_NARROWED=true
    else
      acc_fail "could not install the narrow principal ceiling for the stale-root check"
    fi
  else
    acc_fail "could not narrow the principal ceiling for the stale-root check"
  fi
  if [ "$H5_NARROWED" = true ]; then
    mkdir -p "$H_SUB/ws5"; chown -R "$H_USER:$H_USER" "$H_SUB/ws5"
    H_POS_HTTP="$(curl --silent --output /tmp/r2ac-h-pos.json --write-out '%{http_code}' --max-time 5 \
      --unix-socket "$SOCK" -H "Authorization: Bearer $H_BETA_TOK" \
      -H 'Content-Type: application/json' \
      -d "{\"workspace\":\"$H_SUB/ws5\"}" http://localhost/sessions 2>/dev/null || true)"
    if [ "$H_POS_HTTP" = 201 ] && grep -q '"id":"dhs_' /tmp/r2ac-h-pos.json; then
      acc_ok "stale-root precondition: session creation through the Launcher succeeds inside the narrow ceiling"
    else
      acc_fail "stale-root precondition failed: Launcher unusable inside the narrow ceiling (http=$H_POS_HTTP)"
    fi
    if dh principal allowed-root remove --system "$H_USER" "$H_SUB" >/dev/null 2>&1; then
      H_STALE_HTTP="$(curl --silent --output /tmp/r2ac-h-stale.json --write-out '%{http_code}' --max-time 5 \
        --unix-socket "$SOCK" -H "Authorization: Bearer $H_BETA_TOK" \
        -H 'Content-Type: application/json' \
        -d "{\"workspace\":\"$H_SUB/ws5\"}" http://localhost/sessions 2>/dev/null || true)"
      if [ "$H_STALE_HTTP" = 422 ] \
          && grep -q '"code":"launcher_unavailable"' /tmp/r2ac-h-stale.json; then
        acc_ok "stale out-of-ceiling launcher root rejected fail-closed (422 launcher_unavailable)"
      else
        acc_fail "stale launcher root contract wrong (http=$H_STALE_HTTP)"
      fi
    else
      acc_fail "could not remove the narrow principal root for the stale-root check"
    fi
  fi
  if [ "$H5_REMOVED" = true ]; then
    if dh principal allowed-root add --system "$H_USER" "$ALLOWED_ROOT" >/dev/null 2>&1 \
        && dh principal allowed-root add --system "$H_USER" "$H_HOME" >/dev/null 2>&1; then
      acc_ok "principal root state restored after the stale-root check"
    else
      acc_fail "could not restore the principal root after the stale-root check"
    fi
  fi

  # H6: disable propagation + persistence of individual disablement.
  H_BETA_DIS_OUT="$(dh launcher set --system --principal "$H_USER" --enabled false "$H_BETA_ID" 2>/dev/null || true)"
  if printf '%s\n' "$H_BETA_DIS_OUT" | grep -q '"enabled": false'; then
    acc_ok "launcher disabled"
  else
    acc_fail "launcher disable failed"
  fi
  H_DIS_LIST="$(dh session list --system --token-file /etc/docker-helper/admin.token --json 2>/dev/null)"
  H_DIS_HTTP="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
    --unix-socket "$SOCK" -H "Authorization: Bearer $H_BETA_TOK" http://localhost/auth 2>/dev/null || true)"
  if ! printf '%s\n' "$H_DIS_LIST" | grep -q "$H_BETA_SESS" && [ "$H_DIS_HTTP" = 401 ]; then
    acc_ok "disabling the launcher deleted its session and rejected its bearer"
  else
    acc_fail "disable propagation failed (session present or bearer alive)"
  fi
  dh principal set --system "$H_USER" enabled false >/dev/null 2>&1 || true
  dh principal set --system "$H_USER" enabled true >/dev/null 2>&1 || true
  H_BETA_SHOW="$(dh launcher show --system --principal "$H_USER" "$H_BETA_ID" 2>/dev/null || true)"
  H_ALPHA_SHOW="$(dh launcher show --system --principal "$H_USER" "$H_ALPHA_ID" 2>/dev/null || true)"
  if printf '%s\n' "$H_BETA_SHOW" | grep -q '"enabled": false' \
      && printf '%s\n' "$H_ALPHA_SHOW" | grep -q '"enabled": true'; then
    acc_ok "individually disabled launcher stays disabled through a principal enable cycle"
  else
    acc_fail "individual launcher disablement not preserved (beta=$(printf '%s' "$H_BETA_SHOW" | grep -o '"enabled": [a-z]*' | head -1))"
  fi
  dh launcher set --system --principal "$H_USER" --enabled true "$H_BETA_ID" >/dev/null 2>&1 || true

  # H7: checked delete with active runtime.
  H_BEFORE_CID="$(ls /run/docker-helper/*.cid 2>/dev/null | wc -l)"
  H_RT_SESS_JSON="$(dh session create --system --token-file "$CRED_DIR/lnc-alpha2.tok" --workspace "$H_WS" --json 2>/dev/null || true)"
  H_RT_SESS="$(printf '%s' "$H_RT_SESS_JSON" | json_field id || true)"
  H_RT_TOKEN="$(printf '%s' "$H_RT_SESS_JSON" | json_field token || true)"
  H_RT_CID=""
  if [ -n "$H_RT_TOKEN" ]; then
    DOCKER_HELPER_SESSION_TOKEN="$H_RT_TOKEN" \
      dh run --image alpine:3.24 -- sh -ec 'while true; do sleep 1; done' \
      >/tmp/r2ac-h-op.out 2>&1 &
    H_OP_PID=$!
    for _ in $(seq 1 100); do
      H_RT_CIDFILE="$(ls -t /run/docker-helper/*.cid 2>/dev/null | head -1)"
      H_RT_CID="$(cat "$H_RT_CIDFILE" 2>/dev/null || true)"
      if [ -n "$H_RT_CID" ] && [ "$(ls /run/docker-helper/*.cid 2>/dev/null | wc -l)" -gt "$H_BEFORE_CID" ] \
          && docker inspect -f '{{.State.Running}}' "$H_RT_CID" 2>/dev/null | grep -q true; then
        break
      fi
      H_RT_CID=""
      sleep 0.2
    done
  fi
  if [ -n "$H_RT_CID" ] && [ -n "$H_RT_SESS" ]; then
    H_DEL_ACT_HTTP="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
      --unix-socket "$SOCK" -H "Authorization: Bearer $H_ADMIN_TOKEN" \
      -X DELETE "http://localhost/principals/$H_USER/launchers/$H_ALPHA_ID" 2>/dev/null || true)"
    H_ALPHA_SHOW2="$(dh launcher show --system --principal "$H_USER" "$H_ALPHA_ID" 2>/dev/null || true)"
    H_ADMIN_LIST="$(dh session list --system --token-file /etc/docker-helper/admin.token --json 2>/dev/null || true)"
    if [ "$H_DEL_ACT_HTTP" = 409 ] \
        && printf '%s\n' "$H_ALPHA_SHOW2" | grep -q '"enabled": true' \
        && [ -n "$H_ADMIN_LIST" ] \
        && printf '%s\n' "$H_ADMIN_LIST" | grep -q "$H_RT_SESS"; then
      acc_ok "launcher delete refused side-effect-free while runtime is active (409 launcher_runtime_active, launcher stays enabled, sessions intact)"
    else
      acc_fail "checked delete did not enforce the sanctioned side-effect-free 409 semantics (http=$H_DEL_ACT_HTTP)"
    fi
    # The daemon does not terminate running operations, and the refused delete
    # must not invalidate the Launcher's Sessions (side-effect-free refusal);
    # the operator stops the container and retries the delete ("retries after
    # the runtime exits"). The runtime-active refusal is retryable: the run
    # operation finalizes shortly after the container exits (its own completion
    # path also releases the MAC bindings), so poll the delete until the daemon
    # itself reports the runtime inactive instead of inferring finalization
    # from side signals.
    docker stop -t 5 "$H_RT_CID" >/dev/null 2>&1 || true
    if wait_no_container "$H_RT_CID"; then
      H_DELETED=false
      for _ in $(seq 1 25); do
        if dh launcher delete --system --principal "$H_USER" "$H_ALPHA_ID" >/dev/null 2>&1; then
          H_DELETED=true
          break
        fi
        sleep 0.4
      done
      if [ "$H_DELETED" = true ]; then
        acc_ok "launcher delete succeeds after its sessions are cleaned up"
      else
        H_DEL_RETRY_OUT="$(dh launcher delete --system --principal "$H_USER" "$H_ALPHA_ID" 2>&1 || true)"
        acc_fail "launcher delete failed after cleanup (cli: ${H_DEL_RETRY_OUT:-<no output>})"
        # Evidence for diagnosis: the delete/run audit trail and any
        # operational error line. Audit lines carry no bearer material.
        journalctl --utc -u docker-helper.service --since '-3 min' --no-pager 2>/dev/null \
          | grep -E '"stream":"audit"|"level":"ERROR"' \
          | tail -40 >&2 || true
        # Reproduce the daemon's exact runtime-inspection command (schema +
        # launcher-id label filters, {{.ID}} {{.State}} format) to distinguish
        # a template error from a confined-daemon environment failure.
        H_PS_RC=0
        H_PS_OUT="$(docker ps -a \
          --filter 'label=com.dockerhelper.schema=1' \
          --filter "label=com.dockerhelper.launcher.id=$H_ALPHA_ID" \
          --format '{{.ID}} {{.State}}' 2>&1)" || H_PS_RC=$?
        printf 'ps-exact rc=%s out: %s\n' "$H_PS_RC" "${H_PS_OUT:-<empty>}" >&2
      fi
    else
      acc_fail "launcher runtime container did not stop for the checked-delete cleanup"
    fi
  else
    acc_fail "checked-delete precondition failed (no active runtime container)"
  fi
  kill "${H_OP_PID:-}" 2>/dev/null || true

  # H8: no bearer in audit; rotation provenance visible.
  H_JOURNAL="$(journalctl --utc -u docker-helper.service --since '-15 min' --no-pager 2>/dev/null)"
  if printf '%s\n' "$H_JOURNAL" | grep -q 'dhc_'; then
    acc_fail "journal audit leaked a launcher credential bearer"
  else
    acc_ok "journal audit contains no launcher credential bearer"
  fi
  if printf '%s\n' "$H_JOURNAL" | grep -q '"event":"launcher.credential_rotate"' \
      && printf '%s\n' "$H_JOURNAL" | grep -q "\"launcher_id\":\"$H_ALPHA_ID\""; then
    acc_ok "rotation provenance visible in audit (launcher.credential_rotate with launcher_id)"
  else
    acc_fail "rotation provenance missing from audit"
  fi
fi

# ==============================================================================
# scenario F: DEB lifecycle install(upgrade baseline v2.0.0) -> upgrade
#             (candidate) -> reinstall(candidate) -> remove -> purge
# ==============================================================================
scenario "F: DEB lifecycle"

BASELINE_DEB=""
BASELINE_VERSION="$UPGRADE_BASELINE_VERSION"

# Resolve the immutable v2.0.0 upgrade-baseline fixture (only the DEB is
# needed) and verify its pinned SHA-256 strictly before installation.
if upgrade_baseline_fetch_deb /tmp/r2ac-baseline.deb >/dev/null 2>&1; then
  BASELINE_DEB="/tmp/r2ac-baseline.deb"
  acc_ok "v2.0.0 baseline DEB resolved and SHA-256 verified (pinned fixture)"
else
  acc_blocked "could not resolve/verify the v2.0.0 baseline DEB (pinned fixture)"
fi

if [ -z "$BASELINE_DEB" ]; then
  acc_blocked "v2.0.0 baseline DEB unavailable; DEB lifecycle not exercised"
else
  # clean slate: the candidate is currently installed from the earlier phases
  dpkg -P docker-helper >/dev/null 2>&1 || true
  rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper

  # --- install (v2.0.0 baseline) ------------------------------------------
  if dpkg -i "$BASELINE_DEB" >/tmp/r2ac-f-install.log 2>&1; then
    acc_ok "v2.0.0 DEB installed"
  else
    acc_fail "v2.0.0 DEB install failed (see /tmp/r2ac-f-install.log)"
  fi
  if [ "$(docker-helper version)" = "$BASELINE_VERSION" ]; then
    acc_ok "v2.0.0 binary version installed ($BASELINE_VERSION)"
  else
    acc_fail "installed binary version is not $BASELINE_VERSION: $(docker-helper version)"
  fi
  if dpkg -s docker-helper 2>/dev/null | grep -q "Version: $BASELINE_VERSION"; then
    acc_ok "dpkg reports package version $BASELINE_VERSION"
  else
    acc_fail "dpkg package version is not $BASELINE_VERSION"
  fi

  # Seed operator/principal state BEFORE the upgrade to prove persistence.
  docker-helper init --allowed-root "$ALLOWED_ROOT" >/dev/null 2>&1 \
    && acc_ok "system init on v2.0.0 baseline" || acc_fail "system init failed on v2.0.0 baseline"
  systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    systemctl is-active --quiet docker-helper.service && break
    sleep 1
  done
  wait_health "$SOCK" || acc_fail "v2.0.0 daemon not healthy"
  F_USER="uatr2life"
  F_CRED="$CRED_DIR/life.tok"
  set_up_principal "$F_USER" "$F_CRED" || acc_fail "lifecycle principal setup failed (v2.0.0)"
  F_PRINC_ID="$GLOBAL_CRED_ID"
  F_SESSION_ID="$GLOBAL_SESSION_ID"

  # --- RuntimeDirectory identity consumer ----------------------------------
  # A long-lived container bind-mounting /run/docker-helper holds the
  # RuntimeDirectory inode through its mount: same dev:inode only while the
  # directory identity survives the package scriptlets' restart
  # (RuntimeDirectoryPreserve=restart in the shipped unit). The consumer must
  # keep seeing the daemon socket recreated in that SAME directory after the
  # upgrade and the reinstall, with the container never recreated. The
  # consumer is plain Docker deliberately: the scenario subject is the
  # systemd RuntimeDirectory/package interaction, not the Session mount
  # model. (The hosted runner is AppArmor-only, so a plain consumer works;
  # the socket is proven with test -S/stat, and /health is the host check.)
  F_RT_CONSUMER="uatr2f-rtdir"
  F_RT_CONTAINER_ID=""
  F_RT_INODE_BASE=""
  rt_dir_inode() { # WHERE: dev:inode of /run/docker-helper from "host" or the
                   # consumer ("container"); "absent" when unavailable.
    local where="$1" out
    if [ "$where" = container ]; then
      out="$(docker exec "$F_RT_CONSUMER" stat -c '%d:%i' /run/docker-helper 2>/dev/null)" || out="absent"
    else
      out="$(stat -c '%d:%i' /run/docker-helper 2>/dev/null)" || out="absent"
    fi
    printf '%s' "$out"
  }
  rt_dir_consumer_running() {
    [ "$(docker inspect -f '{{.State.Running}}' "$F_RT_CONSUMER" 2>/dev/null)" = "true" ]
  }
  rt_dir_container_id() {
    docker inspect -f '{{.Id}}' "$F_RT_CONSUMER" 2>/dev/null
  }
  rt_dir_verify_phase() { # LABEL: the mandatory invariant set after one
                          # package action, without touching the consumer.
    local label="$1" dir dir_c sock sock_c id
    id="$(rt_dir_container_id)"
    if rt_dir_consumer_running && [ "$id" = "$F_RT_CONTAINER_ID" ]; then
      acc_ok "$label: directory-bind consumer still the same container (no recreate/restart)"
    else
      acc_fail "$label: directory-bind consumer not running or recreated (was ${F_RT_CONTAINER_ID:-unknown}, now ${id:-unknown})"
    fi
    dir="$(rt_dir_inode host)"
    if [ "$dir" != absent ] && [ "$dir" = "$F_RT_INODE_BASE" ]; then
      acc_ok "$label: host RuntimeDirectory dev:inode preserved ($dir)"
    else
      acc_fail "$label: host RuntimeDirectory dev:inode changed: before $F_RT_INODE_BASE, after ${dir:-absent}"
    fi
    dir_c="$(rt_dir_inode container)"
    if [ "$dir_c" = "$F_RT_INODE_BASE" ] && [ "$dir_c" = "$dir" ]; then
      acc_ok "$label: consumer still sees the preserved RuntimeDirectory ($dir_c)"
    else
      acc_fail "$label: consumer RuntimeDirectory view wrong (container ${dir_c:-absent}, host ${dir:-absent}, baseline $F_RT_INODE_BASE)"
    fi
    sock="$(stat -c '%d:%i' "$SOCK" 2>/dev/null)" || sock="absent"
    if [ "$sock" != absent ]; then
      acc_ok "$label: host socket exists after the scriptlet-driven restart ($sock)"
    else
      acc_fail "$label: host socket missing after restart ($SOCK)"
    fi
    if docker exec "$F_RT_CONSUMER" test -S "$SOCK" >/dev/null 2>&1; then
      sock_c="$(docker exec "$F_RT_CONSUMER" stat -c '%d:%i' "$SOCK" 2>/dev/null)" || sock_c="absent"
      if [ "$sock_c" = "$sock" ]; then
        acc_ok "$label: consumer sees the same new socket as the host ($sock_c)"
      else
        acc_fail "$label: consumer socket view wrong (container ${sock_c:-absent}, host $sock)"
      fi
    else
      acc_fail "$label: consumer no longer sees the daemon socket through the bind"
    fi
  }
  docker rm -f "$F_RT_CONSUMER" >/dev/null 2>&1 || true
  if docker run -d --name "$F_RT_CONSUMER" \
      -v /run/docker-helper:/run/docker-helper alpine:3.24 sleep infinity >/dev/null 2>&1; then
    for _ in $(seq 1 15); do
      rt_dir_consumer_running && break
      sleep 1
    done
  fi
  if ! rt_dir_consumer_running; then
    acc_blocked "cannot start the directory-bind consumer (image alpine:3.24 pull/run failed)"
    F_RT_INODE_BASE=""
  else
    F_RT_CONTAINER_ID="$(rt_dir_container_id)"
    F_RT_INODE_BASE="$(rt_dir_inode host)"
    if [ -n "$F_RT_INODE_BASE" ] && [ "$(rt_dir_inode container)" = "$F_RT_INODE_BASE" ]; then
      if docker exec "$F_RT_CONSUMER" test -S "$SOCK" >/dev/null 2>&1; then
        acc_ok "directory-bind consumer running on the v2.0.0 baseline (RuntimeDirectory dev:inode $F_RT_INODE_BASE; socket visible)"
      else
        acc_fail "consumer does not see the daemon socket on the baseline ($SOCK)"
      fi
    else
      acc_fail "consumer RuntimeDirectory differs from host (consumer $(rt_dir_inode container), host $F_RT_INODE_BASE)"
    fi
  fi

  # --- upgrade (v2.0.0 -> candidate) ---------------------------------------
  if dpkg -i "$ARTIFACT_PATH_IN" >/tmp/r2ac-f-upgrade.log 2>&1; then
    acc_ok "upgrade to candidate DEB completed"
  else
    acc_fail "upgrade to candidate DEB failed (see /tmp/r2ac-f-upgrade.log)"
  fi
  if [ "$(docker-helper version)" = "$VERSION" ]; then
    acc_ok "candidate version installed after upgrade ($VERSION)"
  else
    acc_fail "candidate version not installed after upgrade: $(docker-helper version)"
  fi
  if dpkg -s docker-helper 2>/dev/null | grep -q "Version: $(printf '%s' "$VERSION" | tr '-' '~')"; then
    acc_ok "dpkg reports candidate package version after upgrade"
  else
    acc_fail "dpkg package version is not the candidate after upgrade"
  fi
  # daemon remains/re-becomes healthy when it was active before upgrade
  systemctl is-active --quiet docker-helper.service \
    || { systemctl start docker-helper.service >/dev/null 2>&1 || true; }
  for _ in $(seq 1 30); do
    systemctl is-active --quiet docker-helper.service && break
    sleep 1
  done
  if systemctl is-active --quiet docker-helper.service && wait_health "$SOCK"; then
    acc_ok "daemon healthy after upgrade (was active before)"
  else
    acc_fail "daemon not healthy after upgrade"
  fi
  # The package action restarted the active daemon through the scriptlets:
  # the bind-mounted RuntimeDirectory identity must have survived it.
  if [ -n "$F_RT_INODE_BASE" ]; then
    rt_dir_verify_phase "upgrade"
  fi
  DH_PID2="$(systemctl show -p MainPID --value docker-helper.service)"
  if [ "$(cat "/proc/$DH_PID2/attr/current" 2>/dev/null || true)" = "docker-helper-system (enforce)" ]; then
    acc_ok "package-owned AppArmor profile correct after upgrade (enforce)"
  else
    acc_fail "AppArmor confinement wrong after upgrade"
  fi
  # system initialization/config survives
  if [ -f /etc/docker-helper/config.json ]; then
    acc_ok "system config survived the upgrade"
  else
    acc_fail "system config lost during upgrade"
  fi
  # Principal/credential/session state persists
  if dh principal show --system --token-file /etc/docker-helper/admin.token "$F_USER" >/dev/null 2>&1; then
    acc_ok "principal persisted across upgrade"
  else
    acc_fail "principal did not persist across upgrade"
  fi
  if dh credential list --system --token-file /etc/docker-helper/admin.token "$F_USER" 2>/dev/null | grep -q "$F_PRINC_ID"; then
    acc_ok "credential persisted across upgrade"
  else
    acc_fail "credential did not persist across upgrade"
  fi
  if dh session list --system --token-file /etc/docker-helper/admin.token 2>/dev/null | grep -q "$F_SESSION_ID"; then
    acc_ok "session persisted across upgrade"
  else
    acc_fail "session did not persist across upgrade"
  fi
  # exact candidate artifact was used (byte identity asserted at entry; binary
  # provenance via dpkg ownership)
  if dpkg -S /usr/bin/docker-helper >/dev/null 2>&1; then
    acc_ok "installed binary is package-owned (candidate artifact provenance)"
  else
    acc_fail "installed binary not package-owned after upgrade"
  fi

  # --- reinstall (candidate) ------------------------------------------------
  # dpkg has no --force-reinstall force option (unknown force/refuse option
  # 'reinstall'); apt-get --reinstall install <deb> is the canonical way to
  # force a same-version reinstall, running prerm(upgrade)+postinst(configure).
  if apt-get -y --reinstall install "$ARTIFACT_PATH_IN" >/tmp/r2ac-f-reinstall.log 2>&1; then
    acc_ok "candidate DEB reinstall completed"
  else
    acc_fail "candidate DEB reinstall failed (see /tmp/r2ac-f-reinstall.log)"
    sed 's/^/    reinstall-log: /' /tmp/r2ac-f-reinstall.log 2>/dev/null | tail -15 >&2
  fi
  if [ "$(docker-helper version)" = "$VERSION" ]; then
    acc_ok "candidate version remains installed after reinstall"
  else
    acc_fail "version changed after reinstall: $(docker-helper version)"
  fi
  systemctl start docker-helper.service >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    systemctl is-active --quiet docker-helper.service && break
    sleep 1
  done
  if systemctl is-active --quiet docker-helper.service && wait_health "$SOCK"; then
    acc_ok "daemon healthy after reinstall"
  else
    acc_fail "daemon not healthy after reinstall"
  fi
  # The reinstall ran the same scriptlets: the same consumer must still see
  # the same RuntimeDirectory and the recreated socket.
  if [ -n "$F_RT_INODE_BASE" ]; then
    rt_dir_verify_phase "reinstall"
  fi

  # The consumer must not hold the bind across the remove/purge phases: a
  # real service stop destroys the RuntimeDirectory by design
  # (RuntimeDirectoryPreserve=restart preserves restarts, not stops).
  docker rm -f "$F_RT_CONSUMER" >/dev/null 2>&1 || true
  acc_ok "directory-bind consumer removed (candidate left installed)"

  # --- remove (dpkg -r) ------------------------------------------------------
  if dpkg -r docker-helper >/tmp/r2ac-f-remove.log 2>&1; then
    acc_ok "dpkg -r (remove) completed"
  else
    acc_fail "dpkg -r failed (see /tmp/r2ac-f-remove.log)"
  fi
  if systemctl is-active --quiet docker-helper.service 2>/dev/null; then
    acc_fail "service still active after remove"
  else
    acc_ok "service stopped after remove"
  fi
  if systemctl is-enabled --quiet docker-helper.service 2>/dev/null; then
    acc_fail "service still enabled after remove"
  else
    acc_ok "service disabled after remove"
  fi
  for p in /usr/bin/docker-helper /usr/lib/systemd/system/docker-helper.service /etc/apparmor.d/docker-helper-system; do
    if [ -e "$p" ]; then
      acc_fail "package-owned path still present after remove: $p"
    fi
  done
  acc_ok "package-owned executable/unit/profile removed"
  if ! grep -q 'docker-helper-system' /sys/kernel/security/apparmor/profiles 2>/dev/null; then
    acc_ok "no stale AppArmor profile belonging to the package remains"
  else
    acc_fail "stale AppArmor profile still loaded after remove"
  fi
  # operator-owned config/state preserved on remove (documented package
  # contract: only purge removes them).
  if [ -d /etc/docker-helper ] && [ -d /var/lib/docker-helper ]; then
    acc_ok "operator config/state preserved on remove (documented contract)"
  else
    acc_fail "operator config/state removed on plain remove (contract violation)"
  fi

  # --- purge (dpkg -P) -------------------------------------------------------
  if dpkg -P docker-helper >/tmp/r2ac-f-purge.log 2>&1; then
    acc_ok "dpkg -P (purge) completed"
  else
    acc_fail "dpkg -P failed (see /tmp/r2ac-f-purge.log)"
  fi
  for d in /etc/docker-helper /var/lib/docker-helper /run/docker-helper; do
    if [ -e "$d" ]; then
      acc_fail "purge did not remove: $d"
    fi
  done
  acc_ok "purge removed /etc/docker-helper, /var/lib/docker-helper, /run/docker-helper"
  if dpkg -s docker-helper >/dev/null 2>&1; then
    acc_fail "package still recorded after purge"
  else
    acc_ok "package fully purged"
  fi
fi

# ==============================================================================
# summary
# ==============================================================================
echo
echo "================= RELEASE-2 ACCEPTANCE SUMMARY (Ubuntu/DEB/AppArmor) ================="
printf '  FAILS:    %d\n' "$FAIL_COUNT"
printf '  BLOCKED:  %d\n' "$BLOCKED_COUNT"
echo "======================================================================"

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "RESULT: at least one mandatory Release-2 acceptance scenario FAILED" >&2
  exit 1
fi
if [ "$BLOCKED_COUNT" -gt 0 ]; then
  echo "RESULT: at least one mandatory Release-2 acceptance scenario BLOCKED (required scenario not exercised)" >&2
  exit 2
fi
echo "RESULT: Release-2 acceptance suite PASSED"
exit 0
