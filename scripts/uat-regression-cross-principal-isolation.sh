#!/usr/bin/env bash
#
# uat-regression-cross-principal-isolation.sh — Release-2 targeted regression
# group 4: Cross-principal isolation (Ubuntu / DEB / AppArmor).
#
# Two OS users / Principals A and B. Proves:
#   * A cannot inspect/list B resources beyond documented visibility;
#   * scope-first Launcher and Principal-credential lists derive maximum
#     visibility from the bearer, while an explicit Principal filter can only
#     narrow it (admin all/narrow, Principal own/narrow, foreign/unknown
#     non-disclosing 404, Launcher credential unauthorized);
#   * the Release 2 compatibility alias `credential list` preserves the
#     scope-first semantics without a mandatory Principal argument;
#   * A cannot delete B's Session;
#   * A cannot modify B's Principal;
#   * A cannot manage B's credentials;
#   * A cannot use B's authorization scope;
#   * the admin (global scope) can perform the corresponding administrative
#     operations.
# Existing anti-enumeration / not-found semantics are preserved: A's deletion
# of B's session is indistinguishable (404) from a nonexistent session, and a
# foreign list filter is indistinguishable from an unknown Principal filter.
#
# Requires: installed docker-helper system service (active), root.
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "4. Cross-principal isolation"

reg_require_root
reg_require_service

USER_A="uatreg4a"
USER_B="uatreg4b"

homeA="$(reg_setup_principal "$USER_A")" || { reg_fail "setup principal A failed"; reg_result; }
homeB="$(reg_setup_principal "$USER_B")" || { reg_fail "setup principal B failed"; reg_result; }

CRED_A="/tmp/uat-reg4-a.token"
CRED_B="/tmp/uat-reg4-b.token"
LAUNCHER_CRED_A="/tmp/uat-reg4-launcher-a.token"

reg_principal_credential "$USER_A" "$CRED_A" || { reg_fail "credential create for A failed"; reg_result; }
credA="$REG_CRED_ID"
reg_principal_credential "$USER_B" "$CRED_B" || { reg_fail "credential create for B failed"; reg_result; }
credB="$REG_CRED_ID"

wsA="$homeA/ws"; wsB="$homeB/ws"
mkdir -p "$wsA" "$wsB"
chown -R "$USER_A:$USER_A" "$homeA"
chown -R "$USER_B:$USER_B" "$homeB"

reg_session "$CRED_A" "$wsA" || { reg_fail "session create for A failed"; reg_result; }
sidA="$REG_SESSION_ID"
reg_session "$CRED_B" "$wsB" || { reg_fail "session create for B failed"; reg_result; }
sidB="$REG_SESSION_ID"
reg_info "sessions: A=$sidA B=$sidB"

# --- A cannot inspect/list B resources beyond documented visibility ----------
LIST_A="$(dh session list --system --token-file "$CRED_A" 2>&1)"
if printf '%s' "$LIST_A" | grep -q "$sidA"; then
  reg_ok "A lists its own session"
else
  reg_fail "A cannot list its own session"
fi
if printf '%s' "$LIST_A" | grep -q "$sidB"; then
  reg_fail "A can list B's session (cross-principal visibility leak)"
else
  reg_ok "A cannot see B's session in its own list"
fi

# --- scope-first Launcher / Principal-credential list contract ---------------
# The default Launchers created with each Principal are enough to prove global
# vs narrowed visibility. Add a Launcher credential for A only to prove that a
# valid Launcher bearer is rejected by both control-plane list families.
LC_OUT="$(dh launcher credential create --system --principal "$USER_A" 2>/dev/null)"
LC_RC=$?
LC_TOKEN="$(printf '%s' "$LC_OUT" | json_field token || true)"
if [ "$LC_RC" -eq 0 ] && [ -n "$LC_TOKEN" ]; then
  printf '%s\n' "$LC_TOKEN" > "$LAUNCHER_CRED_A"; chmod 600 "$LAUNCHER_CRED_A"
  reg_ok "scope-first precondition: Launcher credential created for A's default Launcher"
else
  reg_fail "scope-first precondition failed: could not create Launcher credential"
fi

# has_principal_row TABLE PRINCIPAL: table-form list output has PRINCIPAL as the
# final column for both resource families.
has_principal_row() {
  local table="$1" principal="$2"
  printf '%s\n' "$table" | awk -v p="$principal" '$NF==p {found=1} END {exit(found ? 0 : 1)}'
}

# only_principal_rows TABLE PRINCIPAL: at least one data row exists and every
# data row belongs to the requested Principal. Header is ignored.
only_principal_rows() {
  local table="$1" principal="$2"
  printf '%s\n' "$table" | awk -v p="$principal" '
    NR==1 {next}
    NF==0 {next}
    {seen=1; if ($NF != p) bad=1}
    END {exit(seen && !bad ? 0 : 1)}'
}

# Launcher list: admin sees both Principals without a filter and may narrow.
L_ADMIN="$(dh launcher list --system 2>&1)"; L_ADMIN_RC=$?
if [ "$L_ADMIN_RC" -eq 0 ] && has_principal_row "$L_ADMIN" "$USER_A" && has_principal_row "$L_ADMIN" "$USER_B"; then
  reg_ok "scope-first launcher list: admin without filter sees A and B"
else
  reg_fail "scope-first launcher list: admin global visibility failed"
fi
L_ADMIN_A="$(dh launcher list --system --principal "$USER_A" 2>&1)"; L_ADMIN_A_RC=$?
if [ "$L_ADMIN_A_RC" -eq 0 ] && only_principal_rows "$L_ADMIN_A" "$USER_A"; then
  reg_ok "scope-first launcher list: admin Principal filter only narrows"
else
  reg_fail "scope-first launcher list: admin filter did not narrow to A"
fi

# Principal A derives its own scope from the bearer; no explicit Principal is
# required. Its own explicit filter is equivalent and cannot expand scope.
L_A="$(dh launcher list --system --token-file "$CRED_A" 2>&1)"; L_A_RC=$?
L_A_OWN="$(dh launcher list --system --token-file "$CRED_A" --principal "$USER_A" 2>&1)"; L_A_OWN_RC=$?
if [ "$L_A_RC" -eq 0 ] && only_principal_rows "$L_A" "$USER_A" \
    && [ "$L_A_OWN_RC" -eq 0 ] && only_principal_rows "$L_A_OWN" "$USER_A"; then
  reg_ok "scope-first launcher list: Principal bearer sees only own scope with or without own filter"
else
  reg_fail "scope-first launcher list: Principal own-scope resolution failed"
fi

# Foreign and nonexistent filters are deliberately indistinguishable.
L_FOREIGN="$(dh launcher list --system --token-file "$CRED_A" --principal "$USER_B" 2>&1)"; L_FOREIGN_RC=$?
L_MISSING="$(dh launcher list --system --token-file "$CRED_A" --principal uatreg4missing 2>&1)"; L_MISSING_RC=$?
if [ "$L_FOREIGN_RC" -ne 0 ] && [ "$L_MISSING_RC" -ne 0 ] \
    && printf '%s' "$L_FOREIGN" | grep -q 'status 404, code principal_not_found' \
    && [ "$L_FOREIGN" = "$L_MISSING" ]; then
  reg_ok "scope-first launcher list: foreign and unknown filters are the same non-disclosing 404"
else
  reg_fail "scope-first launcher list: foreign/unknown filter anti-enumeration contract failed"
fi

if [ -n "$LC_TOKEN" ]; then
  L_LAUNCHER="$(dh launcher list --system --token-file "$LAUNCHER_CRED_A" 2>&1)"; L_LAUNCHER_RC=$?
  if [ "$L_LAUNCHER_RC" -ne 0 ] && printf '%s' "$L_LAUNCHER" | grep -q 'status 401, code unauthorized'; then
    reg_ok "scope-first launcher list: Launcher credential rejected as control-plane authority"
  else
    reg_fail "scope-first launcher list: Launcher credential was not rejected with unauthorized"
  fi
fi

# Principal credential list: same authorization rule, same narrowing behavior.
C_ADMIN="$(dh principal credential list --system 2>&1)"; C_ADMIN_RC=$?
if [ "$C_ADMIN_RC" -eq 0 ] && printf '%s' "$C_ADMIN" | grep -q "$credA" \
    && printf '%s' "$C_ADMIN" | grep -q "$credB" \
    && has_principal_row "$C_ADMIN" "$USER_A" && has_principal_row "$C_ADMIN" "$USER_B"; then
  reg_ok "scope-first credential list: admin without filter sees A and B"
else
  reg_fail "scope-first credential list: admin global visibility failed"
fi
C_ADMIN_A="$(dh principal credential list --system "$USER_A" 2>&1)"; C_ADMIN_A_RC=$?
if [ "$C_ADMIN_A_RC" -eq 0 ] && only_principal_rows "$C_ADMIN_A" "$USER_A" \
    && printf '%s' "$C_ADMIN_A" | grep -q "$credA" \
    && ! printf '%s' "$C_ADMIN_A" | grep -q "$credB"; then
  reg_ok "scope-first credential list: admin Principal filter only narrows"
else
  reg_fail "scope-first credential list: admin filter did not narrow to A"
fi

C_A="$(dh principal credential list --system --token-file "$CRED_A" 2>&1)"; C_A_RC=$?
C_A_OWN="$(dh principal credential list --system --token-file "$CRED_A" "$USER_A" 2>&1)"; C_A_OWN_RC=$?
if [ "$C_A_RC" -eq 0 ] && only_principal_rows "$C_A" "$USER_A" \
    && printf '%s' "$C_A" | grep -q "$credA" && ! printf '%s' "$C_A" | grep -q "$credB" \
    && [ "$C_A_OWN_RC" -eq 0 ] && only_principal_rows "$C_A_OWN" "$USER_A"; then
  reg_ok "scope-first credential list: Principal bearer sees only own scope with or without own filter"
else
  reg_fail "scope-first credential list: Principal own-scope resolution failed"
fi

# Release 2 compatibility alias: `credential list` must behave exactly like
# the canonical command, in particular without a mandatory Principal positional.
C_ALIAS="$(dh credential list --system --token-file "$CRED_A" 2>&1)"; C_ALIAS_RC=$?
if [ "$C_ALIAS_RC" -eq 0 ] && only_principal_rows "$C_ALIAS" "$USER_A" \
    && printf '%s' "$C_ALIAS" | grep -q "$credA" && ! printf '%s' "$C_ALIAS" | grep -q "$credB"; then
  reg_ok "scope-first credential list: Release 2 alias works without a Principal argument and preserves own scope"
else
  reg_fail "scope-first credential list: Release 2 alias failed (mandatory Principal restored or own scope broken)"
fi

C_FOREIGN="$(dh principal credential list --system --token-file "$CRED_A" "$USER_B" 2>&1)"; C_FOREIGN_RC=$?
C_MISSING="$(dh principal credential list --system --token-file "$CRED_A" uatreg4missing 2>&1)"; C_MISSING_RC=$?
if [ "$C_FOREIGN_RC" -ne 0 ] && [ "$C_MISSING_RC" -ne 0 ] \
    && printf '%s' "$C_FOREIGN" | grep -q 'status 404, code principal_not_found' \
    && [ "$C_FOREIGN" = "$C_MISSING" ]; then
  reg_ok "scope-first credential list: foreign and unknown filters are the same non-disclosing 404"
else
  reg_fail "scope-first credential list: foreign/unknown filter anti-enumeration contract failed"
fi

if [ -n "$LC_TOKEN" ]; then
  C_LAUNCHER="$(dh principal credential list --system --token-file "$LAUNCHER_CRED_A" 2>&1)"; C_LAUNCHER_RC=$?
  if [ "$C_LAUNCHER_RC" -ne 0 ] && printf '%s' "$C_LAUNCHER" | grep -q 'status 401, code unauthorized'; then
    reg_ok "scope-first credential list: Launcher credential rejected as control-plane authority"
  else
    reg_fail "scope-first credential list: Launcher credential was not rejected with unauthorized"
  fi
fi

# Both list families are metadata-only: no bearer value or dhc_ token shape may
# appear in successful list output.
TOK_A="$(cat "$CRED_A" 2>/dev/null || true)"
TOK_B="$(cat "$CRED_B" 2>/dev/null || true)"
ALL_LISTS="$L_ADMIN
$L_ADMIN_A
$L_A
$L_A_OWN
$C_ADMIN
$C_ADMIN_A
$C_A
$C_A_OWN
$C_ALIAS"
if { [ -n "$TOK_A" ] && printf '%s' "$ALL_LISTS" | grep -Fq "$TOK_A"; } \
    || { [ -n "$TOK_B" ] && printf '%s' "$ALL_LISTS" | grep -Fq "$TOK_B"; } \
    || { [ -n "$LC_TOKEN" ] && printf '%s' "$ALL_LISTS" | grep -Fq "$LC_TOKEN"; } \
    || printf '%s' "$ALL_LISTS" | grep -qE 'dhc_[A-Za-z0-9_-]+'; then
  reg_fail "scope-first list output leaked a credential bearer"
else
  reg_ok "scope-first list output exposes metadata only (including PRINCIPAL ownership)"
fi

# --- A cannot delete B's Session (anti-enumeration: 404 not found) -----------
DEL_ERR="$(dh session delete --system --token-file "$CRED_A" --id "$sidB" 2>&1)"
if printf '%s' "$DEL_ERR" | grep -q 'session_not_found\|not found'; then
  reg_ok "A deleting B's session is indistinguishable from not-found (anti-enumeration)"
else
  reg_fail "A deleting B's session did not return not-found semantics: $(printf '%s' "$DEL_ERR" | head -1)"
fi

# --- A cannot modify B's Principal --------------------------------------------
if dh principal set --system --token-file "$CRED_A" "$USER_B" enabled false >/dev/null 2>&1; then
  reg_fail "A modified B's principal (admin-only operation allowed)"
else
  reg_ok "A cannot modify B's principal"
fi

# --- A cannot manage B's credentials ------------------------------------------
if dh credential revoke --system --token-file "$CRED_A" "$credB" >/dev/null 2>&1; then
  reg_fail "A revoked B's credential (admin-only operation allowed)"
else
  reg_ok "A cannot manage B's credentials"
fi

# --- A cannot use B's authorization scope -------------------------------------
if dh session create --system --token-file "$CRED_A" --workspace "$wsB" --json >/dev/null 2>&1; then
  reg_fail "A created a session using B's authorization scope"
else
  reg_ok "A cannot create a session inside B's authorization scope"
fi

# --- admin (global scope) can perform the corresponding operations -----------
ADMIN_ALL="$(dh session list --system 2>&1)"
if printf '%s' "$ADMIN_ALL" | grep -q "$sidB"; then
  reg_ok "admin lists B's session"
else
  reg_fail "admin cannot list B's session"
fi

if dh session delete --system --id "$sidB" >/dev/null 2>&1; then
  reg_ok "admin deletes B's session"
else
  reg_fail "admin cannot delete B's session"
fi

if dh principal set --system "$USER_B" enabled false >/dev/null 2>&1; then
  reg_ok "admin modifies B's principal"
  dh principal set --system "$USER_B" enabled true >/dev/null 2>&1 || true
else
  reg_fail "admin cannot modify B's principal"
fi

if dh credential revoke --system "$credB" >/dev/null 2>&1; then
  reg_ok "admin revokes B's credential"
else
  reg_fail "admin cannot manage B's credentials"
fi

# --- best-effort cleanup -------------------------------------------------------
for u in "$USER_A" "$USER_B"; do
  dh principal delete --system "$u" >/dev/null 2>&1 || true
  userdel -r "$u" >/dev/null 2>&1 || true
done
rm -f "$CRED_A" "$CRED_B" "$LAUNCHER_CRED_A"

reg_result
