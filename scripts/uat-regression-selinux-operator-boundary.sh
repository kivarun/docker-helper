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
BND_TYPE="$(stat -c '%C' "$BND" 2>/dev/null | cut -d: -f3)"
if [ "$BND_TYPE" = "docker_helper_workspace_t" ]; then
  reg_ok "operator boundary is docker_helper_workspace_t before session creation"
else
  reg_fail "operator boundary type != docker_helper_workspace_t (got '$BND_TYPE')"
fi
RULE_COUNT_BEFORE="$(semanage fcontext -l -C 2>/dev/null | grep -Fc "$BND")"
reg_info "operator fcontext rules matching $BND before session: $RULE_COUNT_BEFORE"

# --- Session uses the existing compatible coverage --------------------------------------
SESS_JSON="$(dh session create --system --workspace "$BND/ws" --json 2>&1)" || {
  reg_fail "session create could not use the operator boundary: $(printf '%s' "$SESS_JSON" | redact | head -3)"
  reg_result
}
SID="$(printf '%s' "$SESS_JSON" | json_field id)"
[ -n "$SID" ] || { reg_fail "session create returned no id"; reg_result; }
reg_ok "session created inside the operator-owned boundary"

WS_TYPE="$(stat -c '%C' "$BND/ws" 2>/dev/null | cut -d: -f3)"
if [ "$WS_TYPE" = "docker_helper_workspace_t" ]; then
  reg_ok "session workspace carries the operator boundary type"
else
  reg_fail "session workspace type != docker_helper_workspace_t (got '$WS_TYPE')"
fi

RULE_COUNT_AFTER_CREATE="$(semanage fcontext -l -C 2>/dev/null | grep -Fc "$BND")"
if [ "$RULE_COUNT_AFTER_CREATE" = "$RULE_COUNT_BEFORE" ]; then
  reg_ok "helper did not add a duplicate fcontext rule (operator state not claimed)"
else
  reg_fail "helper added/removed fcontext rules for operator-owned boundary ($RULE_COUNT_BEFORE -> $RULE_COUNT_AFTER_CREATE)"
fi

# --- Session cleanup must not delete the operator rule ----------------------------------
if dh session delete --system --id "$SID" >/dev/null 2>&1; then
  reg_ok "session deleted"
else
  reg_fail "session delete failed"
fi

RULE_COUNT_AFTER_DELETE="$(semanage fcontext -l -C 2>/dev/null | grep -Fc "$BND")"
if [ "$RULE_COUNT_AFTER_DELETE" = "$RULE_COUNT_BEFORE" ] && [ "$RULE_COUNT_AFTER_DELETE" -ge 1 ]; then
  reg_ok "operator fcontext rule remains after session teardown"
else
  reg_fail "operator fcontext rule was deleted by session cleanup ($RULE_COUNT_BEFORE -> $RULE_COUNT_AFTER_DELETE)"
fi

WS_TYPE_AFTER="$(stat -c '%C' "$BND/ws" 2>/dev/null | cut -d: -f3)"
if [ "$WS_TYPE_AFTER" = "docker_helper_workspace_t" ]; then
  reg_ok "resulting filesystem context remains valid (docker_helper_workspace_t)"
else
  reg_fail "filesystem context invalid after teardown (got '$WS_TYPE_AFTER')"
fi

# --- best-effort cleanup ------------------------------------------------------------------
semanage fcontext -d "$BND(/.*)?" >/dev/null 2>&1 || true
rm -rf "$BND"

reg_result
