#!/usr/bin/env bash
#
# uat-self-introspection.sh — canonical Release 2.2 self-introspection UAT
# for the Ubuntu / DEB / AppArmor profile, running on the exact candidate
# DEB produced by the artifact gate (never rebuilt here).
#
# This is the ONE full self-introspection matrix of the Release 2.2
# credential self-introspection surface (GET /self, the R2.1 debt closure).
# The common black-box UAT carries a short cross-surface smoke; the canonical
# full matrix runs once here on the exact candidate bytes, with the explicit
# scenario inventory below:
#
#   S1 principal self: the packaged CLI answers with type=principal and the
#      exact identity fields (username/uid/gid/home/enabled) of the created
#      principal; stored and effective allowed-root entries are carried in
#      the rich canonical form (arrays, never null);
#   S2 principal self is one coherent policy generation: after a principal
#      allowed-root add and a subsequent remove, the next self response
#      reflects the mutated stored and effective scope in full;
#   S3 launcher self: an inherit-scope Launcher carries canonically empty
#      stored roots and the effective three-level composition; a
#      restricted-scope Launcher carries its stored entries and the
#      narrowed effective composition;
#   S4 launcher self reflects a scope replacement (inherit -> restricted
#      and back) in the next self response;
#   S5 session self: the Session bearer answers with type=session and the
#      same body 'session show --id' renders for the same Session
#      (workspace, ownership, expiry, persisted immutable filesystem
#      snapshot in canonical ordering);
#   S6 admin has no self resource: 404 self_not_available, no envelope,
#      and the audit record carries result self_not_available without a
#      self_type;
#   S7 negative authentication matrix: an unknown token, a revoked
#      principal credential, a disabled principal, a disabled launcher, an
#      expired session, and a wrong-scheme header each receive the
#      non-disclosing 401 authentication contract (code=unauthorized, no
#      identity material); the /auth contract is unchanged (a Session
#      bearer still cannot authenticate there);
#   S8 audit contract: successful self introspection records carry
#      event=self.show, result=success, and the matching self_type; no
#      journal line in the bounded window carries any bearer token.
#
# Plus scenario Z: residue and cleanup (fail-closed three-state inventory:
# every created Session is deleted, no container/mount-pin/workload-MAC
# residue remains, no active Session remains, and the durable database
# carries no Session or snapshot rows).
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
# Shared measurement primitives only (fail-closed residue inventory, session
# list count, durable DB counts); the script's own helpers below win.
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"


ALLOWED_ROOT="${UAT_ALLOWED_ROOT:-/home/runner}"
PRINCIPAL="${UAT_PRINCIPAL:-runner}"
ARTIFACT_PATH_IN="${UAT_ARTIFACT_PATH:-}"
ARTIFACT_SHA256_IN="${UAT_ARTIFACT_SHA256:-}"

PREFIX="[uat-self-introspection]"
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

SOCK="/run/docker-helper/docker-helper.sock"

# si_wait_health waits for the system daemon to answer /health again.
si_wait_health() {
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

# Install the exact candidate artifact (never rebuilds it) and start the
# confined system service, exactly like the DEB install adapter in
# scripts/uat-install-deb.sh. The runner has no prior installation.
dpkg -i "$ARTIFACT_PATH_IN" 2>/tmp/uat-self-install.err || {
  printf 'error: candidate DEB install failed\n' >&2
  sed -n '1,5p' /tmp/uat-self-install.err 2>/dev/null | redact >&2
  exit 1
}
[ -d "$ALLOWED_ROOT" ] || { echo "error: allowed root does not exist: $ALLOWED_ROOT" >&2; exit 1; }
INIT_OUT="$(/usr/bin/docker-helper init --allowed-root "$ALLOWED_ROOT" 2>&1)"
INIT_EC=$?
if [ "$INIT_EC" -ne 0 ]; then
  printf 'error: docker-helper init failed\n' >&2
  printf '%s\n' "$INIT_OUT" | redact >&2
  exit 1
fi
systemctl daemon-reload || { echo "error: systemctl daemon-reload failed" >&2; exit 1; }
systemctl enable --now docker-helper.service || { echo "error: systemctl enable --now docker-helper failed" >&2; exit 1; }
si_wait_health || { echo "error: the installed system daemon did not become healthy" >&2; exit 1; }
say "installed candidate artifact verified by SHA-256; system daemon healthy"

FAIL_COUNT=0
BLOCKED_COUNT=0
ok()      { printf '  ok:      %s\n' "$*"; }
fail()    { printf '  FAIL:    %s\n' "$*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }
blocked() { printf '  BLOCKED: %s\n' "$*" >&2; BLOCKED_COUNT=$((BLOCKED_COUNT + 1)); }
scenario() { say "scenario $1"; }

dh() { /usr/bin/docker-helper "$@"; }

json_field() { grep -oP "\"$1\": ?\"\K[^\"]+" | head -1; }

# cli_line_field extracts the value from the human-oriented operator CLI
# output lines ("  Token: dht_...", "  ID:    dhcr_..."); credential create
# prints this form, not JSON.
cli_line_field() { sed -n "s/^  $1:[[:space:]]*//p" | head -1; }

# si_cleanup removes everything the scenarios created, best-effort; the
# fail-closed residue assertions live in scenario Z.
FIXTURE_ROOT="$ALLOWED_ROOT/self-introspection"
SELF_PRINC="selfint"
SELF_SESSION_IDS=""
cleanup() {
  local sid
  if [ -n "$SELF_SESSION_IDS" ]; then
    for sid in $SELF_SESSION_IDS; do
      dh session delete --system --id "$sid" >/dev/null 2>&1 || true
    done
  fi
  dh principal delete --system "$SELF_PRINC" >/dev/null 2>&1 || true
  dh config allowed-root remove "$FIXTURE_ROOT" >/dev/null 2>&1 || true
  dh principal delete --system "$PRINCIPAL" >/dev/null 2>&1 || true
  if id -u selfint-disabled >/dev/null 2>&1; then
    userdel -r selfint-disabled >/dev/null 2>&1 || true
  fi
  rm -rf "$FIXTURE_ROOT"
  rm -f /tmp/uat-self-principal.token /tmp/uat-self-launcher.token \
    /tmp/uat-self-session.token /tmp/uat-self-s5-resource.log \
    /tmp/uat-self-s5-show.log
}
trap cleanup EXIT

# --- fixture: dedicated principal (OS user runner) with an owned subtree ----
# The self matrix mutates principal/launcher policy, so it runs on a
# dedicated fixture Principal that scenario cleanup deletes wholesale.

dh principal delete --system "$PRINCIPAL" >/dev/null 2>&1 || true
if dh principal create --system --no-credential "$PRINCIPAL" >/dev/null 2>&1 \
    && dh principal allowed-root add --system "$PRINCIPAL" "$ALLOWED_ROOT" >/dev/null 2>&1; then
  ok "fixture principal $PRINCIPAL provisioned with allowed root $ALLOWED_ROOT"
else
  blocked "fixture principal provisioning failed (cannot run the self matrix)"
fi

mkdir -p "$FIXTURE_ROOT/ws"
chown -R "$PRINCIPAL:$PRINCIPAL" "$FIXTURE_ROOT" 2>/dev/null || true

# =============================================================================
# scenario S1: principal self identity and stored/effective roots
# =============================================================================
scenario "S1: principal self identity and stored/effective roots"
PUID="$(id -u "$PRINCIPAL")"; PGID="$(id -g "$PRINCIPAL")"
P_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"

S1_CRED_OUT="$(dh credential create --system --name self-uat "$PRINCIPAL" 2>/dev/null || true)"
S1_CRED_TOKEN="$(printf '%s\n' "$S1_CRED_OUT" | cli_line_field Token)"
if [ -n "$S1_CRED_TOKEN" ]; then
  printf '%s\n' "$S1_CRED_TOKEN" > /tmp/uat-self-principal.token
  chmod 600 /tmp/uat-self-principal.token
  ok "principal credential issued"
else
  blocked "principal credential creation failed (principal self unprovable)"
fi

if S1_SELF="$(dh self --system --token-file /tmp/uat-self-principal.token --json 2>&1)"; then
  if printf '%s\n' "$S1_SELF" | grep -q '"type": "principal"' \
      && printf '%s\n' "$S1_SELF" | grep -q "\"username\": \"$PRINCIPAL\"" \
      && printf '%s\n' "$S1_SELF" | grep -q "\"uid\": $PUID" \
      && printf '%s\n' "$S1_SELF" | grep -q "\"gid\": $PGID" \
      && printf '%s\n' "$S1_SELF" | grep -q "\"home\": \"$P_HOME\"" \
      && printf '%s\n' "$S1_SELF" | grep -q '"enabled": true'; then
    ok "S1 principal self carries the exact identity fields"
  else
    fail "S1 principal self identity mismatch: $(printf '%s\n' "$S1_SELF" | redact | head -8 | tr '\n' ' ')"
  fi
  if printf '%s\n' "$S1_SELF" | tr '\n' ' ' | grep -Eq "\"allowed_root_entries\": \[[^]]*$ALLOWED_ROOT" \
      && printf '%s\n' "$S1_SELF" | tr '\n' ' ' | grep -Eq "\"effective_allowed_root_entries\": \[[^]]*$ALLOWED_ROOT"; then
    ok "S1 stored and effective entries carry the rich canonical form with the allowed root"
  else
    fail "S1 stored/effective entries missing the allowed root: $(printf '%s\n' "$S1_SELF" | redact | tr '\n' ' ' | head -c 400)"
  fi
else
  fail "S1 principal self CLI failed: $(printf '%s\n' "$S1_SELF" | redact | head -3 | tr '\n' ' ')"
fi

# =============================================================================
# scenario S2: principal self is one coherent policy generation
# =============================================================================
scenario "S2: principal self reflects one policy generation"
RO_DIR="$FIXTURE_ROOT/ro-region"
mkdir -p "$RO_DIR"
chown "$PRINCIPAL:$PRINCIPAL" "$RO_DIR"
if dh principal allowed-root add --system --access read_only "$PRINCIPAL" "$RO_DIR" >/dev/null 2>&1; then
  if S2_SELF="$(dh self --system --token-file /tmp/uat-self-principal.token --json 2>&1)"; then
    if printf '%s' "$S2_SELF" | EXPECTED_RO="$RO_DIR" python3 -c '
import json, os, sys
env = json.load(sys.stdin)
res = env["resource"]
ro = os.environ["EXPECTED_RO"]
stored = res["allowed_root_entries"]
effective = res["effective_allowed_root_entries"]
assert {"path": ro, "access": "read_only"} in stored, stored
assert {"path": ro, "access": "read_only"} in effective, effective
print("S2-JSON-OK")
' >/dev/null 2>&1; then
      ok "S2 stored and effective entries reflect the added read-only root"
    else
      fail "S2 added read-only root absent from the self projection: $(printf '%s\n' "$S2_SELF" | redact | tr '\n' ' ' | head -c 400)"
    fi
  else
    fail "S2 self CLI failed after the add: $(printf '%s\n' "$S2_SELF" | redact | head -3)"
  fi
else
  fail "S2 principal allowed-root add (read-only) failed"
fi
if dh principal allowed-root remove --system "$PRINCIPAL" "$RO_DIR" >/dev/null 2>&1; then
  if S2_SELF="$(dh self --system --token-file /tmp/uat-self-principal.token --json 2>&1)"; then
    if printf '%s\n' "$S2_SELF" | grep -q "$RO_DIR"; then
      fail "S2 removed root still present in the self projection: $(printf '%s\n' "$S2_SELF" | redact | tr '\n' ' ' | head -c 400)"
    else
      ok "S2 removed root is absent from the self projection (one generation, no stale residue)"
    fi
  else
    fail "S2 self CLI failed after the remove: $(printf '%s\n' "$S2_SELF" | redact | head -3)"
  fi
else
  fail "S2 principal allowed-root remove failed"
fi

# =============================================================================
# scenario S3: launcher self (inherit and restricted scopes)
# =============================================================================
scenario "S3: launcher self (inherit and restricted scopes)"
S3_L_OUT="$(dh launcher create --system --principal "$PRINCIPAL" --name restricted-l --issue-credential 2>/dev/null || true)"
S3_L_TOKEN="$(printf '%s\n' "$S3_L_OUT" | json_field token)"
S3_L_ID="$(printf '%s\n' "$S3_L_OUT" | json_field id)"
if [ -n "$S3_L_TOKEN" ] && [ -n "$S3_L_ID" ]; then
  printf '%s\n' "$S3_L_TOKEN" > /tmp/uat-self-launcher.token
  chmod 600 /tmp/uat-self-launcher.token
  if S3_SELF="$(dh self --system --token-file /tmp/uat-self-launcher.token --json 2>&1)"; then
    if printf '%s\n' "$S3_SELF" | grep -q '"type": "launcher"' \
        && printf '%s\n' "$S3_SELF" | grep -q "\"id\": \"$S3_L_ID\"" \
        && printf '%s\n' "$S3_SELF" | grep -q '"name": "restricted-l"' \
        && printf '%s\n' "$S3_SELF" | grep -q "\"principal\": \"$PRINCIPAL\"" \
        && printf '%s\n' "$S3_SELF" | grep -q '"scope": "inherit"' \
        && printf '%s\n' "$S3_SELF" | tr '\n' ' ' | grep -Eq "\"allowed_root_entries\": \[[[:space:]]*\]"; then
      ok "S3 inherit launcher self carries identity and canonically empty stored roots"
    else
      fail "S3 inherit launcher self mismatch: $(printf '%s\n' "$S3_SELF" | redact | tr '\n' ' ' | head -c 400)"
    fi
    if printf '%s\n' "$S3_SELF" | tr '\n' ' ' | grep -Eq "\"effective_allowed_root_entries\": \[[^]]*$ALLOWED_ROOT"; then
      ok "S3 inherit launcher effective roots carry the principal-scope composition"
    else
      fail "S3 inherit launcher effective roots missing the allowed root"
    fi
  else
    fail "S3 launcher self CLI failed: $(printf '%s\n' "$S3_SELF" | redact | head -3)"
  fi

  # Restricted scope: the restricted root narrows the effective composition.
  S3_RES_DIR="$FIXTURE_ROOT/res-only"
  mkdir -p "$S3_RES_DIR"; chown "$PRINCIPAL:$PRINCIPAL" "$S3_RES_DIR"
  if dh launcher allowed-root add --system --principal "$PRINCIPAL" --access read_only restricted-l "$S3_RES_DIR" >/dev/null 2>&1; then
    if S3_SELF="$(dh self --system --token-file /tmp/uat-self-launcher.token --json 2>&1)"; then
      if printf '%s\n' "$S3_SELF" | grep -q '"scope": "restricted"' \
          && printf '%s' "$S3_SELF" | EXPECTED_RO="$S3_RES_DIR" python3 -c '
import json, os, sys
env = json.load(sys.stdin)
res = env["resource"]
ro = os.environ["EXPECTED_RO"]
assert {"path": ro, "access": "read_only"} in res["allowed_root_entries"], res["allowed_root_entries"]
assert any(e["path"] == ro for e in res["effective_allowed_root_entries"]), res["effective_allowed_root_entries"]
print("S3-JSON-OK")
' >/dev/null 2>&1; then
        ok "S3 restricted launcher self carries stored entries and the narrowed effective composition"
      else
        fail "S3 restricted launcher self mismatch: $(printf '%s\n' "$S3_SELF" | redact | tr '\n' ' ' | head -c 400)"
      fi
      if printf '%s' "$S3_SELF" | EXPECTED_BROAD="$ALLOWED_ROOT" python3 -c '
import json, os, sys
env = json.load(sys.stdin)
broad = os.environ["EXPECTED_BROAD"]
assert not any(e["path"] == broad and e["access"] == "read_write" for e in env["resource"]["effective_allowed_root_entries"]), env["resource"]["effective_allowed_root_entries"]
print("S3-NEG-OK")
' >/dev/null 2>&1; then
        ok "S3 restricted launcher effective scope does not leak the broad read-write root"
      else
        fail "S3 restricted launcher effective scope still carries the broad read-write root: $(printf '%s\n' "$S3_SELF" | redact | head -2 | tr '\n' ' ')"
      fi
    else
      fail "S3 restricted launcher self CLI failed: $(printf '%s\n' "$S3_SELF" | redact | head -3)"
    fi
  else
    fail "S3 launcher scope replacement to restricted failed"
  fi
else
  blocked "launcher credential issuance failed (launcher self unprovable)"
fi

# =============================================================================
# scenario S4: launcher self reflects a scope replacement
# =============================================================================
scenario "S4: launcher self reflects scope replacement"
if [ -n "${S3_L_TOKEN:-}" ]; then
  if dh launcher allowed-root inherit --system --principal "$PRINCIPAL" restricted-l >/dev/null 2>&1; then
    if S4_SELF="$(dh self --system --token-file /tmp/uat-self-launcher.token --json 2>&1)"; then
      if printf '%s\n' "$S4_SELF" | grep -q '"scope": "inherit"' \
          && printf '%s\n' "$S4_SELF" | tr '\n' ' ' | grep -Eq "\"allowed_root_entries\": \[[[:space:]]*\]"; then
        ok "S4 scope replacement back to inherit is reflected in the self projection"
      else
        fail "S4 scope replacement not reflected: $(printf '%s\n' "$S4_SELF" | redact | tr '\n' ' ' | head -c 400)"
      fi
    else
      fail "S4 self CLI failed: $(printf '%s\n' "$S4_SELF" | redact | head -3)"
    fi
  else
    fail "S4 launcher scope replacement to inherit failed"
  fi
else
  blocked "S4 requires the S3 launcher fixture"
fi

# =============================================================================
# scenario S5: session self equals the session show body
# =============================================================================
scenario "S5: session self equals the session show body"
S5_WS="$FIXTURE_ROOT/ws"
S5_CREATE="$(dh session create --system --token-file /tmp/uat-self-principal.token --workspace "$S5_WS" --json 2>/dev/null || true)"
S5_ID="$(printf '%s\n' "$S5_CREATE" | json_field id)"
S5_TOKEN="$(printf '%s\n' "$S5_CREATE" | json_field token)"
if [ -n "$S5_ID" ] && [ -n "$S5_TOKEN" ]; then
  SELF_SESSION_IDS="$S5_ID"
  printf '%s\n' "$S5_TOKEN" > /tmp/uat-self-session.token
  chmod 600 /tmp/uat-self-session.token
  if S5_SELF="$(dh self --system --token-file /tmp/uat-self-session.token --json 2>&1)" \
      && S5_SHOW="$(dh session show --system --id "$S5_ID" --json 2>&1)"; then
    if printf '%s\n' "$S5_SELF" | grep -q '"type": "session"' \
        && printf '%s\n' "$S5_SELF" | grep -q "\"id\": \"$S5_ID\"" \
        && printf '%s\n' "$S5_SELF" | grep -q "\"workspace\": \"$S5_WS\""; then
      ok "S5 session self carries type/session, id, and workspace"
    else
      fail "S5 session self identity mismatch: $(printf '%s\n' "$S5_SELF" | redact | head -8 | tr '\n' ' ')"
    fi
    # The resource body equals the session show body of the same Session.
    S5_SELF_RES="$(printf '%s\n' "$S5_SELF" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["resource"], sort_keys=True))' 2>/dev/null)"
    S5_SHOW_DOC="$(printf '%s\n' "$S5_SHOW" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin), sort_keys=True))' 2>/dev/null)"
    if [ -n "$S5_SELF_RES" ] && [ "$S5_SELF_RES" = "$S5_SHOW_DOC" ]; then
      ok "S5 self resource body equals the canonical session show body"
    else
      fail "S5 self resource differs from the session show body (kept in /tmp/uat-self-s5-*.log)"
      printf '%s\n' "$S5_SELF_RES" | redact > /tmp/uat-self-s5-resource.log 2>/dev/null || true
      printf '%s\n' "$S5_SHOW_DOC" | redact > /tmp/uat-self-s5-show.log 2>/dev/null || true
    fi
    # Snapshot canonical ordering: exactly the issued workspace entry.
    if printf '%s' "$S5_SELF" | EXPECTED_WS="$S5_WS" python3 -c '
import json, os, sys
env = json.load(sys.stdin)
ws = os.environ["EXPECTED_WS"]
assert env["resource"]["filesystem_snapshot"]["entries"] == [{"path": ws, "access": "read_write"}], env["resource"]["filesystem_snapshot"]
print("S5-JSON-OK")
' >/dev/null 2>&1; then
      ok "S5 persisted filesystem snapshot carries the issued workspace read_write entry"
    else
      fail "S5 filesystem snapshot missing the issued workspace entry: $(printf '%s\n' "$S5_SELF" | redact | tr '\n' ' ' | head -c 500)"
    fi
  else
    fail "S5 self or session show CLI failed: $(printf '%s\n' "$S5_SELF" "$S5_SHOW" | redact | head -4 | tr '\n' ' ')"
  fi
else
  blocked "session creation failed (session self unprovable)"
fi

# =============================================================================
# scenario S6: admin has no self resource
# =============================================================================
scenario "S6: admin self_not_available"
ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
[ -n "$ADMIN_TOKEN" ] || blocked "cannot read the admin token"
S6_AUDIT_EPOCH="$(date +%s)"
S6_OUT="$(curl --silent --max-time 5 --unix-socket "$SOCK" \
  -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost/self 2>/dev/null || true)"
S6_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
  --unix-socket "$SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost/self 2>/dev/null || true)"
if [ "$S6_CODE" = "404" ] && printf '%s\n' "$S6_OUT" | grep -q '"self_not_available"' \
    && ! printf '%s\n' "$S6_OUT" | grep -q '"resource"'; then
  ok "S6 admin receives 404 self_not_available with no resource envelope"
else
  fail "S6 admin self outcome unexpected (code=$S6_CODE): $(printf '%s\n' "$S6_OUT" | redact | head -3)"
fi
S6_AUDIT_JSON="$(journalctl --utc -u docker-helper.service --since "@${S6_AUDIT_EPOCH}" --no-pager 2>/dev/null | grep '"event":"self.show"' | grep 'self_not_available' | tail -1 || true)"
if [ -n "$S6_AUDIT_JSON" ]; then
  if printf '%s\n' "$S6_AUDIT_JSON" | grep -q '"self_type"'; then
    fail "S6 self_not_available audit record unexpectedly carries a self_type"
  else
    ok "S6 self_not_available audit record carries result without a self_type"
  fi
else
  fail "S6 self_not_available audit record missing from the bounded journal window"
fi

# =============================================================================
# scenario S7: negative authentication matrix (non-disclosing 401)
# =============================================================================
scenario "S7: negative authentication matrix"

# Revoked principal credential: issue a second credential and revoke it.
S7_REV_OUT="$(dh credential create --system --name self-revoked "$PRINCIPAL" 2>/dev/null || true)"
S7_REV_TOKEN="$(printf '%s\n' "$S7_REV_OUT" | cli_line_field Token)"
S7_REV_ID="$(printf '%s\n' "$S7_REV_OUT" | cli_line_field ID)"
if [ -n "$S7_REV_TOKEN" ] && [ -n "$S7_REV_ID" ]; then
  dh credential revoke --system "$S7_REV_ID" >/dev/null 2>&1 || true
fi

# Disabled launcher (the S3 fixture launcher; the S4 pass re-enabled scope
# only): disable it, probe, then re-enable so scenario Z cleanup stays clean.
S7_LAUNCHER_DISABLING=0
if [ -n "${S3_L_ID:-}" ]; then
  if dh launcher set --system --principal "$PRINCIPAL" --enabled false restricted-l >/dev/null 2>&1; then
    S7_LAUNCHER_DISABLING=1
  fi
fi

S7_probe() {
  local label="$1" token="$2" code
  code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
    --unix-socket "$SOCK" -H "Authorization: Bearer $token" http://localhost/self 2>/dev/null || true)"
  local body
  body="$(curl --silent --max-time 5 --unix-socket "$SOCK" \
    -H "Authorization: Bearer $token" http://localhost/self 2>/dev/null || true)"
  if [ "$code" = "401" ] && printf '%s\n' "$body" | grep -q '"code": *"unauthorized"' \
      && ! printf '%s\n' "$body" | grep -Eq '"(type|resource)"'; then
    ok "S7 $label: non-disclosing 401"
  else
    fail "S7 $label: expected non-disclosing 401, got code=$code body=$(printf '%s\n' "$body" | redact | head -2 | tr '\n' ' ')"
  fi
}

S7_probe "unknown token" "dht_unknown_self_uat_token_3m9k2"
[ -n "$S7_REV_TOKEN" ] && S7_probe "revoked principal credential" "$S7_REV_TOKEN" \
  || fail "S7 revoked-credential fixture could not be issued"
S7_probe "wrong scheme" "Basic c2VsZjppbnRyb3NwZWN0aW9u"

# Disabled principal: disable the fixture Principal's SECOND principal only
# if a disposable one exists; disabling the shared fixture principal would
# break the later scenarios. The disabled-principal probe therefore uses the
# daemon-owner pattern: create a dedicated principal, disable it with its
# credential in hand.
if id -u selfint-disabled >/dev/null 2>&1 || useradd -m selfint-disabled >/dev/null 2>&1; then
  dh principal create --system --no-credential selfint-disabled >/dev/null 2>&1 || true
fi
if dh principal allowed-root add --system selfint-disabled "$FIXTURE_ROOT" >/dev/null 2>&1 \
    && S7_DIS_CRED="$(dh credential create --system --name self-disabled selfint-disabled 2>/dev/null)" \
    && S7_DIS_TOKEN="$(printf '%s\n' "$S7_DIS_CRED" | cli_line_field Token)" \
    && [ -n "$S7_DIS_TOKEN" ]; then
  if dh principal set --system selfint-disabled enabled false >/dev/null 2>&1; then
    S7_probe "disabled principal" "$S7_DIS_TOKEN"
    dh principal delete --system selfint-disabled >/dev/null 2>&1 || true
  else
    fail "S7 disabled-principal fixture disable failed"
    dh principal delete --system selfint-disabled >/dev/null 2>&1 || true
  fi
else
  fail "S7 disabled-principal fixture could not be issued"
  dh principal delete --system selfint-disabled >/dev/null 2>&1 || true
fi

# Disabled launcher probe (S3 fixture launcher, disabled above).
if [ "$S7_LAUNCHER_DISABLING" = 1 ] && [ -n "${S3_L_TOKEN:-}" ]; then
  S7_probe "disabled launcher" "$S3_L_TOKEN"
  dh launcher set --system --principal "$PRINCIPAL" --enabled true restricted-l >/dev/null 2>&1 || fail "S7 launcher re-enable failed"
else
  fail "S7 disabled-launcher probe skipped: fixture unavailable"
fi

# Expired session: shorten the daemon session_ttl, create a session, let it
# expire, probe, restore.
S7_TTL_BEFORE="$(dh config show session_ttl 2>/dev/null | head -1 | tr -d '[:space:]')"
if [ -n "$S7_TTL_BEFORE" ] \
    && dh config set session_ttl 2s >/dev/null 2>&1 \
    && dh reload --system >/dev/null 2>&1 \
    && si_wait_health; then
  S7_EXP_CREATE="$(dh session create --system --token-file /tmp/uat-self-principal.token --workspace "$S5_WS" --json 2>/dev/null || true)"
  S7_EXP_ID="$(printf '%s\n' "$S7_EXP_CREATE" | json_field id)"
  S7_EXP_TOKEN="$(printf '%s\n' "$S7_EXP_CREATE" | json_field token)"
  if [ -n "$S7_EXP_ID" ] && [ -n "$S7_EXP_TOKEN" ]; then
    SELF_SESSION_IDS="$SELF_SESSION_IDS $S7_EXP_ID"
    sleep 3
    S7_probe "expired session" "$S7_EXP_TOKEN"
  else
    fail "S7 expired-session fixture could not be created"
  fi
  dh config set session_ttl "$S7_TTL_BEFORE" >/dev/null 2>&1 || fail "S7 session_ttl restore failed"
  dh reload --system >/dev/null 2>&1 && si_wait_health || fail "S7 reload after session_ttl restore failed"
else
  blocked "S7 session_ttl rotation unavailable (expired-session probe skipped)"
fi

# The /auth contract is unchanged: a Session bearer still cannot authenticate
# there.
S7_AUTH_CODE="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 5 \
  --unix-socket "$SOCK" -H "Authorization: Bearer $S5_TOKEN" http://localhost/auth 2>/dev/null || true)"
if [ "${S7_AUTH_CODE:-}" = "401" ]; then
  ok "S7 /auth unchanged: a Session bearer still receives 401 there"
else
  fail "S7 /auth contract drift: session bearer got $S7_AUTH_CODE (expected 401)"
fi

# =============================================================================
# scenario S8: audit contract (self_type, no bearer material)
# =============================================================================
scenario "S8: audit contract"
S8_AUDIT_JSON="$(journalctl --utc -u docker-helper.service --since "@${S6_AUDIT_EPOCH}" --no-pager 2>/dev/null || true)"
if [ -n "$S8_AUDIT_JSON" ]; then
  for want_type in principal launcher session; do
    if printf '%s\n' "$S8_AUDIT_JSON" | grep -q "\"event\":\"self.show\"" \
        && printf '%s\n' "$S8_AUDIT_JSON" | grep "\"self_type\":\"$want_type\"" | grep -q '"result":"success"'; then
      ok "S8 self.show success records carry self_type=$want_type"
    else
      fail "S8 self.show success record with self_type=$want_type missing"
    fi
  done
  if printf '%s\n' "$S8_AUDIT_JSON" | grep -Eq 'dhc_[A-Za-z0-9_-]+|dht_[A-Za-z0-9_-]+'; then
    fail "S8 journal window carries bearer token material"
  else
    ok "S8 journal window carries no bearer token material"
  fi
else
  blocked "S8 journal window unavailable"
fi

# =============================================================================
# scenario Z: residue and cleanup (fail-closed three-state inventory)
# =============================================================================
scenario "Z: no residue after the self-introspection scenarios"
if [ -n "$SELF_SESSION_IDS" ]; then
  for sid in $SELF_SESSION_IDS; do
    dh session delete --system --id "$sid" >/dev/null 2>&1 || fail "Z session $sid delete failed"
  done
fi
Z_WAIT_RC=0
wait_no_helper_containers || Z_WAIT_RC=$?
if [ "$Z_WAIT_RC" -eq 2 ]; then
  blocked "Z helper container inventory unavailable"
elif [ "$Z_WAIT_RC" -ne 0 ]; then
  fail "Z helper-owned containers remain"
else
  ok "Z no helper-owned containers remain"
fi
Z_PINS="$(inventory_count /run/docker-helper/mounts)"; Z_PINS_RC=$?
if [ "$Z_PINS_RC" -eq 0 ]; then
  [ "$Z_PINS" = "0" ] && ok "Z no mount pins remain" || fail "Z mount pins remain"
else
  blocked "Z mount-pin inventory unavailable"
fi
Z_WLMAC="$(inventory_count /run/docker-helper/workload-mac)"; Z_WLMAC_RC=$?
if [ "$Z_WLMAC_RC" -eq 0 ]; then
  [ "$Z_WLMAC" = "0" ] && ok "Z no workload-MAC runtime state remains" || fail "Z workload-MAC runtime state remains"
else
  blocked "Z workload-MAC runtime inventory unavailable"
fi
Z_SESSIONS_DIR="$(inventory_count /run/docker-helper/sessions)"; Z_SESSIONS_RC=$?
if [ "$Z_SESSIONS_RC" -eq 0 ]; then
  [ "$Z_SESSIONS_DIR" = "0" ] && ok "Z no session runtime directories remain" || fail "Z session runtime directories remain"
else
  blocked "Z session runtime inventory unavailable"
fi
if Z_LIST_COUNT="$(session_list_count)"; then
  [ "$Z_LIST_COUNT" = "0" ] \
    && ok "Z no active Sessions remain (fail-closed session-list inventory)" \
    || fail "Z active Sessions remain after the cleanup: $Z_LIST_COUNT"
else
  blocked "Z session-list inventory unavailable"
fi
Z_DB_COUNTS="$(durable_session_snapshot_counts /var/lib/docker-helper/docker-helper.db)"
Z_DB_RC=$?
if [ "$Z_DB_RC" -eq 0 ]; then
  [ "$Z_DB_COUNTS" = "$(printf '0\t0\t0')" ] \
    && ok "Z durable DB carries no Session/snapshot rows" \
    || fail "Z durable Session/snapshot rows remain: $Z_DB_COUNTS"
else
  blocked "Z durable DB inventory unavailable"
fi

# =============================================================================
# summary
# =============================================================================
echo
echo "============== RELEASE 2.2 SELF-INTROSPECTION UAT SUMMARY (Ubuntu/DEB/AppArmor) =============="
printf '  FAILS:    %d\n' "$FAIL_COUNT"
printf '  BLOCKED:  %d\n' "$BLOCKED_COUNT"
echo "======================================================================"

if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "RESULT: at least one mandatory self-introspection scenario FAILED" >&2
  exit 1
fi
if [ "$BLOCKED_COUNT" -gt 0 ]; then
  echo "RESULT: at least one mandatory self-introspection scenario BLOCKED (required scenario not exercised)" >&2
  exit 2
fi
echo "RESULT: Release 2.2 self-introspection UAT PASSED"
exit 0
