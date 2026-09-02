#!/usr/bin/env bash
#
# uat-regression-selinux-workspace-lifecycle.sh — Release-2 targeted regression
# group 1: SELinux non-home workspace lifecycle (Tumbleweed / RPM / SELinux).
#
# Uses a concrete workspace below /opt and proves, through the public CLI:
#   * Session creation succeeds when authorization permits it;
#   * persistent fcontext coverage is created (docker_helper_workspace_t);
#   * the actual workspace type becomes docker_helper_workspace_t;
#   * the regex/path boundary does not match a sibling outside the workspace;
#   * container RW works through the workspace;
#   * helper-owned Session MAC state is released according to contract
#     (fcontext rule removed, workspace relabeled back) on session delete;
#   * unrelated /opt paths are untouched.
# This is concrete Session workspace MAC lifecycle, NOT global/Principal
# allowed-root authorization.
#
# Requires: installed docker-helper system service (active), enforcing SELinux,
# root. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "1. SELinux non-home workspace lifecycle"

reg_require_root
reg_require_service
reg_require_cmd semanage "SELinux fcontext tooling"
reg_require_cmd restorecon "SELinux restorecon"
reg_require_cmd matchpathcon "SELinux matchpathcon"

if [ "$(getenforce 2>/dev/null || true)" != "Enforcing" ]; then
  reg_blocked "SELinux is not enforcing"
fi

IMAGE="alpine:3.24"

# --- ensure /opt is an authorized global root (authorization, not MAC) ----------
dh config allowed-root add /opt >/dev/null 2>&1 || true
if ! dh config allowed-root list 2>/dev/null | grep -qx '/opt'; then
  reg_fail "cannot add /opt to global allowed roots (authorization prerequisite)"
fi
dh reload --system >/dev/null 2>&1 || reg_fail "config reload failed after adding /opt root"
reg_ok "/opt is an authorized global root (authorization ceiling)"

# --- unrelated /opt path (must stay untouched) -----------------------------------
UNRELATED="/opt/uat-ws-unrelated-$RANDOM"
mkdir -p "$UNRELATED"
printf 'unrelated-marker\n' > "$UNRELATED/marker.txt"
UNREL_TYPE_BEFORE="$(stat -c '%C' "$UNRELATED" 2>/dev/null | cut -d: -f3)"
UNREL_INODE_BEFORE="$(stat -c '%d:%i' "$UNRELATED")"

# --- workspace below /opt ----------------------------------------------------------
WS="/opt/uat-ws-nonhome-$RANDOM"
mkdir -p "$WS/rw"
chmod 0755 "$WS" "$WS/rw"
reg_info "workspace: $WS"

# --- session owner (principal + default Launcher + credential) ---------------------
# Under the final ownership model a Session owner is always a Launcher and a
# selector-less principal Session resolves to the principal's default Launcher.
# Establish one (via the shared lib) and create the Session with its credential
# so authorization + the /opt workspace MAC lifecycle are actually exercised
# (never a selector-less admin Session, which the model now rejects).
SEL_P="selws"; SEL_CRED="/tmp/selws.tok"
reg_setup_principal "$SEL_P" >/dev/null || { reg_fail "principal setup failed"; reg_result; }
reg_principal_credential "$SEL_P" "$SEL_CRED" || { reg_fail "credential create failed"; reg_result; }

# --- session creation ---------------------------------------------------------------
reg_session "$SEL_CRED" "$WS" || {
  reg_fail "session create failed (authorization permits /opt)"
  reg_result
}
SID="$REG_SESSION_ID"; STOK="$REG_SESSION_TOKEN"
[ -n "$SID" ] && [ -n "$STOK" ] || { reg_fail "session create returned no id/token"; reg_result; }
reg_ok "session created under /opt (authorization + MAC preparation)"

# --- persistent fcontext coverage ----------------------------------------------------
FC="$(semanage fcontext -l -C 2>/dev/null)"
if printf '%s' "$FC" | grep -Fq "$WS"; then
  if printf '%s' "$FC" | grep -F "$WS" | grep -q 'docker_helper_workspace_t'; then
    reg_ok "persistent fcontext rule created for the workspace (docker_helper_workspace_t)"
  else
    reg_fail "fcontext rule for workspace does not use docker_helper_workspace_t"
  fi
else
  reg_fail "no persistent fcontext rule created for the workspace"
fi

# --- actual workspace type ------------------------------------------------------------
WS_TYPE="$(stat -c '%C' "$WS" 2>/dev/null | cut -d: -f3)"
if [ "$WS_TYPE" = "docker_helper_workspace_t" ]; then
  reg_ok "actual workspace type is docker_helper_workspace_t"
else
  reg_fail "workspace type != docker_helper_workspace_t (got '$WS_TYPE')"
fi

# --- regex/path boundary does not match a sibling -------------------------------------
SIBLING="$WS-sibling"
mkdir -p "$SIBLING"
SIB_TYPE="$(stat -c '%C' "$SIBLING" 2>/dev/null | cut -d: -f3)"
if [ "$SIB_TYPE" != "docker_helper_workspace_t" ]; then
  reg_ok "sibling outside the fcontext regex is not relabeled (type '$SIB_TYPE')"
else
  reg_fail "sibling outside the fcontext regex was relabeled to docker_helper_workspace_t"
fi
# ensure no fcontext rule covers the sibling
if printf '%s' "$FC" | grep -Fq "$SIBLING"; then
  reg_fail "a fcontext rule matches the sibling path (regex over-match)"
else
  reg_ok "no fcontext rule matches the sibling path"
fi

# --- container RW works ---------------------------------------------------------------
RW_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$STOK" \
  dh run --image "$IMAGE" --mount rw:/mnt/rw -- sh -ec 'echo rw-ok > /mnt/rw/f; cat /mnt/rw/f' 2>&1)"
RW_EC=$?
if [ "$RW_EC" -eq 0 ] && printf '%s' "$RW_OUT" | grep -q 'rw-ok'; then
  reg_ok "container RW through the workspace works"
elif [ "$RW_EC" -ne 0 ]; then
  reg_fail "container RW run failed (rc=$RW_EC): $(printf '%s' "$RW_OUT" | redact | head -4)"
else
  reg_fail "container RW run did not verify content: $(printf '%s' "$RW_OUT" | redact | head -4)"
fi

# --- helper-owned Session MAC state released per contract ------------------------------
if dh session delete --system --id "$SID" >/dev/null 2>&1; then
  reg_ok "session deleted"
else
  reg_fail "session delete failed"
fi

FC_AFTER="$(semanage fcontext -l -C 2>/dev/null)"
if printf '%s' "$FC_AFTER" | grep -Fq "$WS"; then
  reg_fail "fcontext rule NOT removed after session delete (MAC state not released)"
else
  reg_ok "fcontext rule removed after session delete (MAC state released)"
fi
WS_TYPE_AFTER="$(stat -c '%C' "$WS" 2>/dev/null | cut -d: -f3)"
if [ "$WS_TYPE_AFTER" != "docker_helper_workspace_t" ]; then
  reg_ok "workspace relabeled back off docker_helper_workspace_t after delete (type '$WS_TYPE_AFTER')"
else
  reg_fail "workspace still docker_helper_workspace_t after session delete"
fi

# --- unrelated /opt paths untouched -----------------------------------------------------
UNREL_TYPE_AFTER="$(stat -c '%C' "$UNRELATED" 2>/dev/null | cut -d: -f3)"
UNREL_INODE_AFTER="$(stat -c '%d:%i' "$UNRELATED")"
UNREL_MARK="$(cat "$UNRELATED/marker.txt" 2>/dev/null || true)"
if [ "$UNREL_TYPE_AFTER" = "$UNREL_TYPE_BEFORE" ] \
   && [ "$UNREL_INODE_AFTER" = "$UNREL_INODE_BEFORE" ] \
   && [ "$UNREL_MARK" = "unrelated-marker" ]; then
  reg_ok "unrelated /opt path untouched (type+inode+content unchanged)"
else
  reg_fail "unrelated /opt path changed (type $UNREL_TYPE_BEFORE->$UNREL_TYPE_AFTER, inode $UNREL_INODE_BEFORE->$UNREL_INODE_AFTER)"
fi

# --- best-effort cleanup ------------------------------------------------------------------
rm -rf "$WS" "$SIBLING" "$UNRELATED"

reg_result
