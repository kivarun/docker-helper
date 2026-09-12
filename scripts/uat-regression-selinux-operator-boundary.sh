#!/usr/bin/env bash
#
# uat-regression-selinux-operator-boundary.sh — Release-2 targeted regression
# group 2: SELinux operator-owned compatible boundary (Tumbleweed / RPM /
# SELinux).
#
# The operator pre-creates a compatible fcontext boundary (docker_helper_workspace_t)
# before Session creation. Proves:
#   * Session can use the existing compatible coverage;
#   * the helper does not claim ownership of operator-managed state (no
#     duplicate fcontext rule);
#   * Session cleanup does not delete the operator fcontext rule;
#   * the operator rule remains after Session teardown;
#   * the resulting filesystem context remains valid.
#
# Requires: installed docker-helper system service (active), enforcing SELinux,
# root. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "2. SELinux operator-owned compatible boundary"

reg_require_root
reg_require_service
reg_require_cmd semanage "SELinux fcontext tooling"
reg_require_cmd restorecon "SELinux restorecon"

if [ "$(getenforce 2>/dev/null || true)" != "Enforcing" ]; then
  reg_blocked "SELinux is not enforcing"
fi

# --- ensure /opt is an authorized global root -----------------------------------------
dh config allowed-root add /opt >/dev/null 2>&1 || true
dh reload --system >/dev/null 2>&1 || reg_fail "config reload failed after adding /opt root"

# --- operator pre-creates the compatible fcontext boundary -----------------------------
BND="/opt/uat-op-bnd-$RANDOM"
mkdir -p "$BND/ws"
semanage fcontext -a -t docker_helper_workspace_t "$BND(/.*)?" 2>/dev/null \
  || { reg_fail "operator could not create the fcontext boundary"; reg_result; }
restorecon -R "$BND" >/dev/null 2>&1 || { reg_fail "operator restorecon failed"; reg_result; }
reg_expect_se_context is "$BND" docker_helper_workspace_t \
  "operator boundary is docker_helper_workspace_t before session creation"
# Positively inventory the operator rule and the complete set of rules
# mentioning the operator stem (fail-closed tri-state): the helper must never
# add or remove a rule at that stem, and the operator rule must survive the
# session lifecycle byte-for-byte. An inventory failure is never "no
# duplicate rule" and never "rule removed".
SE_RULES_BEFORE="$(selinux_rules_for "$BND")"; SE_RULES_BEFORE_RC=$?
if [ "$SE_RULES_BEFORE_RC" -ne 0 ]; then
  reg_fail "fcontext inventory unavailable before session creation (semanage failed)"
  reg_result
fi
if printf '%s\n' "$SE_RULES_BEFORE" | grep -Fxq -- "$BND(/.*)?"; then
  reg_ok "operator rule inventoried before session creation"
else
  reg_fail "operator boundary rule missing from the inventory before session creation"
fi

# --- Session owner (principal + default Launcher + credential) -----------------------
# A Session owner is always a Launcher; create the principal Session through the
# shared lib (principal + default Launcher + credential) so it uses the existing
# operator boundary under the final ownership model.
SEL_P="selbnd"; SEL_CRED="/tmp/selbnd.tok"
reg_setup_principal "$SEL_P" >/dev/null || { reg_fail "principal setup failed"; reg_result; }
# The session workspace is under /opt (the non-home allowed root this group
# deliberately exercises), so /opt must be in the principal's own allowed roots
# for the inherit-scope Session authorization to permit it.
dh principal allowed-root add --system "$SEL_P" /opt >/dev/null 2>&1 || { reg_fail "principal allowed-root add failed"; reg_result; }
reg_principal_credential "$SEL_P" "$SEL_CRED" || { reg_fail "credential create failed"; reg_result; }

# --- Session uses the existing compatible coverage --------------------------------------
reg_session "$SEL_CRED" "$BND/ws" || {
  reg_fail "session create could not use the operator boundary"
  reg_result
}
SID="$REG_SESSION_ID"
[ -n "$SID" ] || { reg_fail "session create returned no id"; reg_result; }
reg_ok "session created inside the operator-owned boundary"

reg_expect_se_context is "$BND/ws" docker_helper_workspace_t \
  "session workspace carries the operator boundary type"

SE_RULES_CREATE="$(selinux_rules_for "$BND")"; SE_RULES_CREATE_RC=$?
if [ "$SE_RULES_CREATE_RC" -ne 0 ]; then
  reg_fail "fcontext inventory unavailable after session creation (semanage failed)"
else
  if [ "$SE_RULES_CREATE" = "$SE_RULES_BEFORE" ]; then
    reg_ok "helper did not add or remove a rule at the operator stem (operator state not claimed)"
  else
    reg_fail "helper changed the fcontext rule set at the operator stem (before: $(printf '%s' "$SE_RULES_BEFORE" | tr '\n' ' ') after: $(printf '%s' "$SE_RULES_CREATE" | tr '\n' ' '))"
  fi
fi

# --- Session cleanup must not delete the operator rule ----------------------------------
if dh session delete --system --id "$SID" >/dev/null 2>&1; then
  reg_ok "session deleted"
else
  reg_fail "session delete failed"
fi

SE_RULES_DELETE="$(selinux_rules_for "$BND")"; SE_RULES_DELETE_RC=$?
if [ "$SE_RULES_DELETE_RC" -ne 0 ]; then
  reg_fail "fcontext inventory unavailable after session deletion (semanage failed); survival cannot be assumed"
else
  if [ "$SE_RULES_DELETE" = "$SE_RULES_BEFORE" ]; then
    reg_ok "operator fcontext rule set survives session teardown byte-for-byte"
  else
    reg_fail "operator fcontext rules changed across session teardown (before: $(printf '%s' "$SE_RULES_BEFORE" | tr '\n' ' ') after: $(printf '%s' "$SE_RULES_DELETE" | tr '\n' ' '))"
  fi
fi

reg_expect_se_context is "$BND/ws" docker_helper_workspace_t \
  "resulting filesystem context remains valid (docker_helper_workspace_t)"

# --- best-effort cleanup ------------------------------------------------------------------
semanage fcontext -d "$BND(/.*)?" >/dev/null 2>&1 || true
rm -rf "$BND"

reg_result
