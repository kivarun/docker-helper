#!/usr/bin/env bash
#
# uat-regression-cross-principal-isolation.sh — Release-2 targeted regression
# group 4: Cross-principal isolation (Ubuntu / DEB / AppArmor).
#
# Two OS users / Principals A and B. Proves:
#   * A cannot inspect/list B resources beyond documented visibility;
#   * A cannot delete B's Session;
#   * A cannot modify B's Principal;
#   * A cannot manage B's credentials;
#   * A cannot use B's authorization scope;
#   * the admin (global scope) can perform the corresponding administrative
#     operations.
# Existing anti-enumeration / not-found semantics are preserved: A's deletion
# of B's session is indistinguishable (404) from a nonexistent session.
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

reg_principal_credential "$USER_A" "$CRED_A" || { reg_fail "credential create for A failed"; reg_result; }
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
rm -f "$CRED_A" "$CRED_B"

reg_result
