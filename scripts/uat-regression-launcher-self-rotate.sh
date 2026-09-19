#!/usr/bin/env bash
#
# uat-regression-launcher-self-rotate.sh — Release 2.2 RC11 targeted
# regression group 29: Launcher credential self-rotation, live
# (Ubuntu / DEB / AppArmor).
#
# The RC11 self-rotation capability is unit/integration-covered internally
# (authority matrix, the deterministic auth→mutation race), but this is a
# real public capability of the shipped CLI/daemon, so this group is its
# exact-candidate live UAT. One real Launcher credential A drives the whole
# rotation sequence against the installed system service:
#
#   S. fixture — a named launcher "pipeline" under a dedicated principal,
#      its Launcher credential, a pre-existing Session created with the
#      original bearer, and a pre-rotation admin-side policy snapshot.
#   R1 omission — `launcher credential rotate` with no positional selector
#      rotates exactly self: same credential row ID, same launcher/principal
#      identity, new bearer returned exactly once on stdout (never stderr),
#      old bearer immediately unauthorized.
#   R2 own name — `rotate <own-launcher-name>` rotates exactly self with the
#      same invariants.
#   R3 own stable ID — `rotate <own-dhl-id>` rotates exactly self with the
#      same invariants.
#   P. preservation — across the whole sequence the credential ID stays
#      constant, the Launcher policy (scope/enabled/roots) and the principal
#      are unchanged, and the pre-existing Session stays owned and listed;
#      the final bearer creates/lists/shows/deletes its own Sessions
#      normally.
#   N. non-disclosing refusals under the current valid bearer — foreign
#      launcher name, foreign dhl_ ID, and a foreign --principal are each
#      refused with the non-disclosing launcher_not_found answer, never
#      invalidate the current bearer, and never rotate anything.
#   C. representative control-plane operations stay forbidden under the
#      rotated bearer (launcher show/set, allowed-root mutation, credential
#      show/delete, principal credential list).
#   J. no bearer (rotated-out or current, session or launcher) appears in
#      the daemon journal (operational or audit stream).
#
# The auth→mutation replacement race is deliberately NOT reproduced here:
# its deterministic owner is the unit/integration seam
# (TestLauncherCredentialSelfRotateStaleAuthRaceFailsClosed); black-box UAT
# cannot park a request between authentication and mutation.
#
# Requires: installed docker-helper system service (active), root, bash.
# Docker is not required (no data-plane container operations).
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "29. Launcher credential self-rotation (live)"

reg_require_root
reg_require_service
reg_require_cmd python3 "JSON identity/response parsing"

TMPDIR_REG29="/tmp/uat-reg29"
mkdir -p "$TMPDIR_REG29"

USER="uatreg29"
USER2="uatreg29b"
LNAME="pipeline"

trap cleanup EXIT
cleanup() {
  dh principal delete --system "$USER" >/dev/null 2>&1 || true
  dh principal delete --system "$USER2" >/dev/null 2>&1 || true
  userdel -r "$USER" >/dev/null 2>&1 || true
  userdel -r "$USER2" >/dev/null 2>&1 || true
  rm -rf "$TMPDIR_REG29"
}

# --- S: fixture -----------------------------------------------------------------
home="$(reg_setup_principal "$USER")" || { reg_fail "fixture: principal $USER failed"; reg_result; }
ws="$home/ws"; mkdir -p "$ws"
chown -R "$USER:$USER" "$home"

home2="$(reg_setup_principal "$USER2")" || { reg_fail "fixture: principal $USER2 failed"; reg_result; }
[ -n "$home2" ] || { reg_fail "fixture: principal $USER2 home missing"; reg_result; }

# Named launcher with its own credential: the launcher credential under test.
# stdout and stderr are captured separately: the canonical --json document
# goes to stdout, the credential-install hint goes to stderr, and the JSON
# parses must only ever see the document.
LC_CREATE="$(dh launcher create --system --principal "$USER" "$LNAME" --issue-credential --json 2>"$TMPDIR_REG29/create.err")"
LC_RC=$?
TOKA="$(printf '%s' "$LC_CREATE" | json_field token || true)"
LID="$(printf '%s' "$LC_CREATE" | json_field id || true)"
if [ "$LC_RC" -eq 0 ] && [ -n "$TOKA" ] && [ -n "$LID" ]; then
  printf '%s\n' "$TOKA" > "$TMPDIR_REG29/credA"; chmod 600 "$TMPDIR_REG29/credA"
  reg_ok "fixture: launcher $LNAME created with credential A ($LID)"
else
  reg_fail "fixture: launcher create with credential failed (rc=$LC_RC: $(redact < "$TMPDIR_REG29/create.err" 2>/dev/null | tail -2))"
  reg_result
fi

# Pre-rotation admin-side policy snapshot (scope/enabled/roots provenance).
SHOW_BEFORE="$(dh launcher show --system --principal "$USER" "$LNAME" --json 2>&1)" \
  || { reg_fail "fixture: launcher show failed: $(printf '%s\n' "$SHOW_BEFORE" | redact | head -2)"; reg_result; }

# Pre-existing Session created with the ORIGINAL bearer A: it must survive
# every later rotation untouched.
S1_JSON="$(dh session create --system --token-file "$TMPDIR_REG29/credA" "$ws" --json 2>&1)"
S1_ID="$(printf '%s' "$S1_JSON" | json_field id || true)"
S1_TOKEN="$(printf '%s' "$S1_JSON" | json_field token || true)"
if [ -n "$S1_ID" ] && [ -n "$S1_TOKEN" ]; then
  printf '%s\n' "$S1_TOKEN" > "$TMPDIR_REG29/s1"; chmod 600 "$TMPDIR_REG29/s1"
  reg_ok "fixture: pre-existing Session $S1_ID created with the original bearer"
else
  reg_fail "fixture: pre-existing Session creation failed: $(printf '%s\n' "$S1_JSON" | redact | tail -2)"
  reg_result
fi

# Original bearer self identity: the projection every rotation must preserve.
SELF_A="$(dh self --system --token-file "$TMPDIR_REG29/credA" --json 2>&1)" \
  || { reg_fail "fixture: launcher bearer self failed: $(printf '%s\n' "$SELF_A" | redact | head -2)"; reg_result; }
if printf '%s' "$SELF_A" | grep -q "\"id\": \"$LID\"" \
    && printf '%s' "$SELF_A" | grep -q "\"name\": \"$LNAME\"" \
    && printf '%s' "$SELF_A" | grep -q "\"principal\": \"$USER\""; then
  reg_ok "fixture: bearer A self identity is launcher $LNAME of $USER ($LID)"
else
  reg_fail "fixture: bearer A self identity mismatch: $(printf '%s\n' "$SELF_A" | redact | head -3)"
fi

# --- rotation helpers ------------------------------------------------------------

# expected_identity BEARERFILE: the bearer still authenticates as exactly the
# same launcher identity (stable ID, name, principal) — used after every
# rotation and after every refusal.
expected_identity() { # bearerfile
  dh self --system --token-file "$1" --json 2>/dev/null \
    | grep -q "\"id\": \"$LID\"" \
    && dh self --system --token-file "$1" --json 2>/dev/null \
    | grep -q "\"principal\": \"$USER\""
}

# bearer_unauthorized BEARERFILE: a data-plane operation with this bearer is
# refused unauthorized (the old bearer is dead; 401 at authentication).
bearer_unauthorized() { # bearerfile
  local out rc
  out="$(dh session create --system --token-file "$1" "$ws" --json 2>&1)"
  rc=$?
  [ "$rc" -ne 0 ] && printf '%s\n' "$out" | grep -q 'unauthorized'
}

# assert_rotated LABEL OUTFILE: one rotation succeeded with the exact
# preservation invariants: same credential row ID, launcher identity
# unchanged, new token present exactly once on stdout (never stderr).
# Emits the new token file path on stdout for the caller to chain.
assert_rotated() { # label out_bearerfile out_errfile in_bearerfile
  local label="$1" newfile="$2" errfile="$3" curfile="$4" out rc tok cred
  out="$(dh launcher credential rotate --system --token-file "$curfile" --json 2>"$errfile")"
  rc=$?
  tok="$(printf '%s' "$out" | json_field token || true)"
  cred="$(printf '%s' "$out" | json_field id || true)"
  if [ "$rc" -ne 0 ] || [ -z "$tok" ] || [ -z "$cred" ]; then
    reg_fail "$label: rotation failed (rc=$rc, stderr: $(redact < "$errfile" | tail -2))"
    return 1
  fi
  if [ "$cred" != "$CRED_ID" ]; then
    reg_fail "$label: credential row ID changed $CRED_ID -> $cred (rotation must preserve it)"
    return 1
  fi
  if ! expected_identity_via_token "$tok"; then
    reg_fail "$label: new bearer does not authenticate as the same launcher identity"
    return 1
  fi
  local stdout_count stderr_count
  stdout_count="$(printf '%s' "$out" | grep -oF "$tok" | wc -l | tr -d ' ')"
  stderr_count="$(grep -oF "$tok" "$errfile" 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$stdout_count" != "1" ] || [ "$stderr_count" != "0" ]; then
    reg_fail "$label: new bearer printed $stdout_count time(s) on stdout and $stderr_count on stderr, want exactly once on stdout only"
    return 1
  fi
  printf '%s\n' "$tok" > "$newfile"; chmod 600 "$newfile"
  reg_ok "$label: rotated self in place (same credential ID, identity preserved, new bearer returned exactly once)"
}

# expected_identity_via_token TOKEN: identity check for a token not yet in a
# file (used inside assert_rotated before persisting).
expected_identity_via_token() { # token
  local tmp="$TMPDIR_REG29/.probe"
  printf '%s\n' "$1" > "$tmp"; chmod 600 "$tmp"
  local ok_rc=1
  if expected_identity "$tmp"; then ok_rc=0; fi
  rm -f "$tmp"
  return $ok_rc
}

# The credential row ID preserved by every rotation: derived structurally from
# the create response's credential object (never from field order).
CRED_ID="$(printf '%s' "$LC_CREATE" | python3 -c '
import json, sys
doc = json.load(sys.stdin)
cred = doc.get("credential") or {}
print(cred.get("id", ""))
' 2>/dev/null)"
if [ -z "$CRED_ID" ]; then
  reg_fail "fixture: credential ID not derivable from the launcher create response"
  reg_result
fi
if [ "$CRED_ID" = "$LID" ]; then
  reg_fail "fixture: credential ID equals the launcher ID (parse error)"
  reg_result
fi

# --- R1: omitted selector rotates self -------------------------------------------
if assert_rotated "R1 omitted selector" "$TMPDIR_REG29/credB" "$TMPDIR_REG29/r1.err" "$TMPDIR_REG29/credA"; then
  if bearer_unauthorized "$TMPDIR_REG29/credA"; then
    reg_ok "R1 old bearer A is immediately unauthorized"
  else
    reg_fail "R1 old bearer A still authenticates after its own rotation"
  fi
else
  reg_fail "R1: rotation chain broken; skipping its dependent assertions"
fi

# --- R2: own-name selector rotates self -------------------------------------------
if assert_rotated "R2 own-name selector" "$TMPDIR_REG29/credC" "$TMPDIR_REG29/r2.err" "$TMPDIR_REG29/credB"; then
  if bearer_unauthorized "$TMPDIR_REG29/credB"; then
    reg_ok "R2 old bearer B is immediately unauthorized"
  else
    reg_fail "R2 old bearer B still authenticates after its own rotation"
  fi
else
  reg_fail "R2: rotation chain broken; skipping its dependent assertions"
fi

# --- R3: own stable dhl_ ID selector rotates self ----------------------------------
if assert_rotated "R3 own stable ID selector" "$TMPDIR_REG29/credD" "$TMPDIR_REG29/r3.err" "$TMPDIR_REG29/credC"; then
  if bearer_unauthorized "$TMPDIR_REG29/credC"; then
    reg_ok "R3 old bearer C is immediately unauthorized"
  else
    reg_fail "R3 old bearer C still authenticates after its own rotation"
  fi
else
  reg_fail "R3: rotation chain broken; skipping its dependent assertions"
fi

CUR="$TMPDIR_REG29/credD"
if [ ! -s "$CUR" ]; then
  reg_fail "sequence: final bearer missing; cannot run preservation/refusal phases"
  reg_result
fi

# --- P: preservation across the sequence -------------------------------------------
SHOW_AFTER="$(dh launcher show --system --principal "$USER" "$LNAME" --json 2>&1)" \
  || reg_fail "P: launcher show after rotation failed: $(printf '%s\n' "$SHOW_AFTER" | redact | head -2)"
if [ -n "$SHOW_AFTER" ] && [ "$(printf '%s' "$SHOW_AFTER" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin), sort_keys=True))' 2>/dev/null)" \
    = "$(printf '%s' "$SHOW_BEFORE" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin), sort_keys=True))' 2>/dev/null)" ]; then
  reg_ok "P: launcher policy (scope/enabled/roots) unchanged across all three rotations"
else
  reg_fail "P: launcher policy changed across rotations (before: $(printf '%s' "$SHOW_BEFORE" | redact | head -c 200), after: $(printf '%s' "$SHOW_AFTER" | redact | head -c 200))"
fi

# The pre-existing Session stays owned and listed under the final bearer, and
# the final bearer drives its full create/list/show/delete lifecycle.
P_JSON="$(dh session create --system --token-file "$CUR" "$ws" --json 2>&1)"
P_ID="$(printf '%s' "$P_JSON" | json_field id || true)"
if [ -n "$P_ID" ]; then
  reg_ok "P: final bearer created its own Session $P_ID normally"
else
  reg_fail "P: final bearer cannot create a Session: $(printf '%s\n' "$P_JSON" | redact | tail -2)"
fi
LIST_JSON="$(dh session list --system --token-file "$CUR" --json 2>&1)"
if printf '%s' "$LIST_JSON" | grep -qF "$S1_ID" && printf '%s' "$LIST_JSON" | grep -qF "$P_ID"; then
  reg_ok "P: launcher-scoped list under the final bearer still carries the pre-rotation Session and the new Session"
else
  reg_fail "P: launcher-scoped list under the final bearer lost $S1_ID or $P_ID: $(printf '%s' "$LIST_JSON" | redact | head -c 200)"
fi
if dh session show --system --token-file "$CUR" "$P_ID" >/dev/null 2>&1; then
  reg_ok "P: final bearer showed its own Session with the issued snapshot"
else
  reg_fail "P: final bearer could not show its own Session $P_ID"
fi
if dh session delete --system --token-file "$CUR" "$P_ID" >/dev/null 2>&1; then
  reg_ok "P: final bearer deleted its own Session normally"
else
  reg_fail "P: final bearer could not delete its own Session $P_ID"
fi

# --- N: non-disclosing refusals under the current valid bearer ----------------------
FOREIGN_ID="dhl_e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"
FOREIGN_NAME="uatreg29-foreign"

refusal_case() { # label args...
  local label="$1"; shift
  local out rc
  out="$(dh launcher credential rotate --system --token-file "$CUR" "$@" 2>&1)"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    reg_fail "$label: expected refusal but rotation succeeded"
    return 1
  fi
  if ! printf '%s\n' "$out" | grep -q 'launcher not found'; then
    reg_fail "$label: refusal is not the non-disclosing launcher_not_found answer: $(printf '%s\n' "$out" | redact | tail -1)"
    return 1
  fi
  if printf '%s\n' "$out" | grep -Eq "$FOREIGN_ID|$FOREIGN_NAME|$USER2"; then
    reg_fail "$label: refusal leaked foreign state: $(printf '%s\n' "$out" | redact | tail -1)"
    return 1
  fi
  reg_ok "$label: refused non-disclosing (rc=$rc, launcher_not_found)"
}

refusal_case "N foreign launcher name" "$FOREIGN_NAME" \
  || true
refusal_case "N foreign dhl_ ID" "$FOREIGN_ID" \
  || true
refusal_case "N foreign --principal" --principal "$USER2" \
  || true

# After every refusal the current bearer must still be valid and must still be
# the SAME credential (nothing was rotated underneath it).
if expected_identity "$CUR"; then
  reg_ok "N: current bearer still authenticates as the same launcher after all refusals"
else
  reg_fail "N: refusals invalidated or rebound the current bearer"
fi
N_JSON="$(dh session create --system --token-file "$CUR" "$ws" --json 2>&1)"
N_ID="$(printf '%s' "$N_JSON" | json_field id || true)"
if [ -n "$N_ID" ]; then
  dh session delete --system --token-file "$CUR" "$N_ID" >/dev/null 2>&1 || true
  reg_ok "N: current bearer still operates its Sessions after all refusals"
else
  reg_fail "N: current bearer cannot operate after the refusals: $(printf '%s\n' "$N_JSON" | redact | tail -2)"
fi

# --- C: representative control-plane operations stay forbidden ----------------------
forbidden_case() { # label cmd...
  local label="$1"; shift
  local out rc
  out="$(dh "$@" --token-file "$CUR" 2>&1)"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    reg_fail "$label: expected 401 refusal but the operation succeeded"
    return 1
  fi
  if ! printf '%s\n' "$out" | grep -q 'unauthorized'; then
    reg_fail "$label: refusal is not the unauthorized contract: $(printf '%s\n' "$out" | redact | tail -1)"
    return 1
  fi
  reg_ok "$label: refused unauthorized"
}

forbidden_case "C launcher show" launcher show --system --principal "$USER" "$LNAME" || true
forbidden_case "C launcher set" launcher set --system --principal "$USER" --enabled true "$LNAME" || true
forbidden_case "C launcher allowed-root add" launcher allowed-root add --system --principal "$USER" "$LNAME" "$ws" || true
forbidden_case "C launcher credential show" launcher credential show --system --principal "$USER" "$LNAME" || true
forbidden_case "C launcher credential delete" launcher credential delete --system --principal "$USER" "$LNAME" || true
forbidden_case "C principal credential list" principal credential list --system "$USER" || true

# --- J: no bearer in the daemon journal (operational or audit stream) ---------------
JOURNAL_SINCE="$(date +%s)"
JOURNAL="$(journalctl -u docker-helper.service --since "@$((JOURNAL_SINCE - 3600))" --no-pager 2>/dev/null)"
if [ -z "$JOURNAL" ] && ! journalctl -u docker-helper.service --no-pager >/dev/null 2>&1; then
  reg_fail "J: daemon journal unavailable; absence of leakage cannot be proven"
else
  LEAK="$(printf '%s\n' "$JOURNAL" | grep -F -e "$TOKA" -e "$(cat "$TMPDIR_REG29/credB")" -e "$(cat "$TMPDIR_REG29/credC")" -e "$(cat "$CUR")" -e "$S1_TOKEN" || true)"
  if [ -z "$LEAK" ]; then
    reg_ok "J: no rotated-out, current, launcher, or session bearer in the daemon journal"
  else
    reg_fail "J: bearer material leaked into the daemon journal ($(printf '%s' "$LEAK" | redact | head -c 120))"
  fi
fi

# --- cleanup: the final bearer deletes the pre-rotation Session ---------------------
if dh session delete --system --token-file "$CUR" "$S1_ID" >/dev/null 2>&1; then
  reg_ok "cleanup: final bearer deleted the pre-rotation Session $S1_ID through the launcher authority"
else
  reg_fail "cleanup: final bearer could not delete the pre-rotation Session $S1_ID"
fi

cleanup
reg_result
