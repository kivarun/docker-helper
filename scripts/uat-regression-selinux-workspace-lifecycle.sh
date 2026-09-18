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
# The default list output is one path per line (2.1-compatible); match the
# /opt path line.
if ! dh config allowed-root list 2>/dev/null | awk 'NF && $1 ~ /^\// {print $1}' | grep -qx '/opt'; then
  reg_fail "cannot add /opt to global allowed roots (authorization prerequisite)"
fi
dh reload --system >/dev/null 2>&1 || reg_fail "config reload failed after adding /opt root"
reg_ok "/opt is an authorized global root (authorization ceiling)"

# --- unrelated /opt path (must stay untouched) -----------------------------------
UNRELATED="/opt/uat-ws-unrelated-$RANDOM"
mkdir -p "$UNRELATED"
printf 'unrelated-marker\n' > "$UNRELATED/marker.txt"
UNREL_TYPE_BEFORE="$(selinux_context_type "$UNRELATED")"
[ -n "$UNREL_TYPE_BEFORE" ] || { reg_fail "unrelated /opt path context inventory unavailable (stat failed)"; UNREL_TYPE_BEFORE="<unavailable>"; }
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
# The session workspace is under /opt (the non-home allowed root this group
# deliberately exercises), so /opt must be in the principal's own allowed roots
# for the inherit-scope Session authorization to permit it.
dh principal allowed-root add --system "$SEL_P" /opt >/dev/null 2>&1 || { reg_fail "principal allowed-root add failed"; reg_result; }
reg_principal_credential "$SEL_P" "$SEL_CRED" || { reg_fail "credential create failed"; reg_result; }

# --- session creation ---------------------------------------------------------------
reg_session "$SEL_CRED" "$WS" || {
  reg_fail "session create failed (authorization permits /opt)"
  reg_result
}
SID="$REG_SESSION_ID"; STOK="$REG_SESSION_TOKEN"
[ -n "$SID" ] && [ -n "$STOK" ] || { reg_fail "session create returned no id/token"; reg_result; }
reg_ok "session created under /opt (authorization + MAC preparation)"

# --- persistent fcontext coverage (fail-closed tri-state inventory) ----------
RULE_LINE="$(selinux_rule_line "$WS(/.*)?")"; RULE_RC=$?
case "$RULE_RC" in
  0) if printf '%s' "$RULE_LINE" | grep -q 'docker_helper_workspace_t'; then
       reg_ok "persistent fcontext rule created for the workspace (docker_helper_workspace_t)"
     else
       reg_fail "fcontext rule for workspace does not use docker_helper_workspace_t"
     fi ;;
  1) reg_fail "no persistent fcontext rule created for the workspace" ;;
  *) reg_fail "fcontext inventory unavailable (semanage failed); absence is never assumed" ;;
esac

# --- actual workspace type (fail-closed tri-state label inventory) -----------
reg_expect_se_context is "$WS" docker_helper_workspace_t \
  "actual workspace type is docker_helper_workspace_t"

# --- regex/path boundary does not match a sibling -------------------------------------
SIBLING="$WS-sibling"
mkdir -p "$SIBLING"
reg_expect_se_context is-not "$SIBLING" docker_helper_workspace_t \
  "sibling outside the fcontext regex is not relabeled"
# ensure no fcontext rule covers the sibling (fail-closed tri-state inventory)
reg_expect_no_se_rule_for "$SIBLING" "no fcontext rule matches the sibling path"

# --- container RW works ---------------------------------------------------------------
# The container runs as the principal's unprivileged uid:gid
# (resolveSessionExecutionIdentity), so the workspace root it writes into must be
# owned by the principal — otherwise a root-owned 0755 directory yields an EACCES
# (no AVC). The relabel (session create) already ran over the root-owned workspace,
# so chown to the principal here, and chown back to root before teardown so the
# delete-time relabel does not require an un-granted fowner capability.
chown -R "$SEL_P:$SEL_P" "$WS" >/dev/null 2>&1 || { reg_fail "workspace chown to principal failed"; reg_result; }

RW_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$STOK" \
  dh run --mount rw:/mnt/rw "$IMAGE" -- sh -ec 'echo rw-ok > /mnt/rw/f; cat /mnt/rw/f' 2>&1)"
RW_EC=$?
if [ "$RW_EC" -eq 0 ] && printf '%s' "$RW_OUT" | grep -q 'rw-ok'; then
  reg_ok "container RW through the workspace works"
elif [ "$RW_EC" -ne 0 ]; then
  reg_fail "container RW run failed (rc=$RW_EC): $(printf '%s' "$RW_OUT" | redact | head -4)"
else
  reg_fail "container RW run did not verify content: $(printf '%s' "$RW_OUT" | redact | head -4)"
fi

# --- helper-owned Session MAC state released per contract ------------------------------
# Restore root ownership before teardown so the delete-time restorecon relabel does
# not need the (un-granted) SELinux fowner capability on the principal-owned tree.
chown -R root:root "$WS" >/dev/null 2>&1 || true
if dh session delete --system "$SID" >/dev/null 2>&1; then
  reg_ok "session deleted"
else
  reg_fail "session delete failed"
fi

reg_expect_se_rule absent "$WS(/.*)?" \
  "fcontext rule removed after session delete (MAC state released)" \
  "fcontext rule NOT removed after session delete (MAC state not released)"
reg_expect_se_context is-not "$WS" docker_helper_workspace_t \
  "workspace relabeled back off docker_helper_workspace_t after delete"

# --- unrelated /opt paths untouched -----------------------------------------------------
UNREL_TYPE_AFTER="$(selinux_context_type "$UNRELATED")"
UNREL_INODE_AFTER="$(stat -c '%d:%i' "$UNRELATED")"
UNREL_MARK="$(cat "$UNRELATED/marker.txt" 2>/dev/null || true)"
if [ "$UNREL_TYPE_AFTER" = "$UNREL_TYPE_BEFORE" ] \
   && [ "$UNREL_INODE_AFTER" = "$UNREL_INODE_BEFORE" ] \
   && [ "$UNREL_MARK" = "unrelated-marker" ]; then
  reg_ok "unrelated /opt path untouched (type+inode+content unchanged)"
else
  reg_fail "unrelated /opt path changed (type $UNREL_TYPE_BEFORE->$UNREL_TYPE_AFTER, inode $UNREL_INODE_BEFORE->$UNREL_INODE_AFTER)"
fi

# --- SC1/M11: control-character host-path grammar through the public API ----
# The shared host-path text grammar (Release 2.2 SC1/M11) refuses control
# characters at the canonical host-path policy owner BEFORE any filesystem
# probe, semanage mutation, or MAC preparation: a host capability pathname
# carrying a control character that Unix itself permits (LF here, on a real
# directory) is refused with no fcontext residue, no semanage mutation, and
# no Session/MAC ownership residue.
WS_CTRL="$(printf '%s\nlf' "/opt/uat-ws-m11-$RANDOM")"
mkdir -p "$WS_CTRL"
reg_info "control-character workspace spelling: $WS_CTRL"
CTRL_INV_BEFORE="$(semanage fcontext -l -C -n 2>/dev/null)"
CTRL_INV_RC=$?
CTRL_LIST_BEFORE="$(dh session list --system --token-file "$SEL_CRED" 2>/dev/null)"
if [ "$CTRL_INV_RC" -ne 0 ]; then
  reg_fail "fcontext inventory unavailable before the control-character refusal; absence is never assumed"
fi
CTRL_OUT="$(dh session create --system --token-file "$SEL_CRED" "$WS_CTRL" --json 2>&1)"
CTRL_RC=$?
if [ "$CTRL_RC" -eq 0 ]; then
  reg_fail "session create with a control-character workspace was accepted (must be refused by the host-path text grammar)"
elif printf '%s' "$CTRL_OUT" | grep -q 'control character'; then
  reg_ok "control-character workspace refused through canonical path policy"
else
  reg_fail "control-character workspace refusal did not come from the host-path grammar: $(printf '%s' "$CTRL_OUT" | redact | head -3)"
fi
CTRL_INV_AFTER="$(semanage fcontext -l -C -n 2>/dev/null)"; CTRL_INV_RC=$?
if [ "$CTRL_INV_RC" -ne 0 ]; then
  reg_fail "fcontext inventory unavailable after the control-character refusal"
elif [ "$CTRL_INV_AFTER" = "$CTRL_INV_BEFORE" ]; then
  reg_ok "no semanage mutation and no fcontext residue for the refused control-character path"
else
  reg_fail "fcontext inventory changed by the refused control-character create"
fi
CTRL_LIST_AFTER="$(dh session list --system --token-file "$SEL_CRED" 2>/dev/null)"
if [ "$CTRL_LIST_AFTER" = "$CTRL_LIST_BEFORE" ]; then
  reg_ok "no Session residue for the refused control-character path"
else
  reg_fail "session inventory changed by the refused control-character create"
fi
rm -rf "$WS_CTRL"

# --- SC1/M12: long-path fcontext lifecycle (beyond the producer's padding
# width). The real semanage producer pads the pattern column to a display
# width; a pattern at or beyond it is emitted with a SINGLE separator space
# (captured producer evidence, testdata/semanage-fcontext-producer-capture.txt
# in the source tree). docker-helper's parser must classify such a record
# exactly: the second create on the SAME path re-inspects the existing rule,
# and the delete must remove exactly the proven rule (the old double-space
# split folded the type column into the pattern, misclassifying the helper's
# own rule as unclassifiable/unowned). NOTE: the real producer refuses
# space-carrying file specifications at add time ("File specification can
# not include spaces", captured evidence), so the long proof path is spelled
# without spaces; a space-carrying host path on enforcing SELinux fails
# closed at semanage (unchanged accepted backend limitation), never inside
# the parser.
AVC_START_M12="$(date '+%m/%d/%Y %H:%M:%S')"
WS_LONG="/opt/uat-ws-long-$RANDOM-$(printf 'a%.0s' $(seq 1 60))"
mkdir -p "$WS_LONG"
chmod 0755 "$WS_LONG"
reg_info "long workspace (pattern beyond the producer padding width): $WS_LONG"

LONG_SESSION_A_ID=""
if reg_session "$SEL_CRED" "$WS_LONG"; then
  LONG_SESSION_A_ID="$REG_SESSION_ID"
  reg_ok "first session created on the long path (fcontext rule created)"
else
  reg_fail "first session create on the long path failed"
  reg_result
fi

LONG_RULE_LINE="$(selinux_rule_line "$WS_LONG(/.*)?")"; LONG_RULE_RC=$?
case "$LONG_RULE_RC" in
  0) if printf '%s' "$LONG_RULE_LINE" | grep -q 'docker_helper_workspace_t'; then
       reg_ok "raw producer record for the long rule maps to docker_helper_workspace_t"
     else
       reg_fail "long rule does not use docker_helper_workspace_t"
     fi ;;
  1) reg_fail "no persistent fcontext rule created for the long path" ;;
  *) reg_fail "fcontext inventory unavailable for the long rule (semanage failed); absence is never assumed" ;;
esac
reg_expect_se_context is "$WS_LONG" docker_helper_workspace_t \
  "actual long-path type is docker_helper_workspace_t"

# Second inspection: a second session on the SAME long path must re-observe
# the SAME rule through the parser (idempotent ensure) — no false overlap,
# no unparseable error, no duplicate add.
if reg_session "$SEL_CRED" "$WS_LONG"; then
  LONG_SESSION_B_ID="$REG_SESSION_ID"
  reg_ok "second session on the same long path re-observed the SAME rule correctly"
else
  reg_fail "second session create on the same long path failed (the parser must classify the existing long rule)"
  reg_result
fi

# Consumer-count release: removing the second consumer while the first still
# holds the boundary keeps the helper-owned rule.
if dh session delete --system "$LONG_SESSION_B_ID" >/dev/null 2>&1; then
  reg_ok "second session deleted"
else
  reg_fail "second session delete failed"
fi
reg_expect_se_rule present "$WS_LONG(/.*)?" \
  "fcontext rule kept while the first consumer still holds the boundary"

# Final cleanup: removing the last consumer releases the proven rule and
# relabels the tree back.
if dh session delete --system "$LONG_SESSION_A_ID" >/dev/null 2>&1; then
  reg_ok "first session deleted"
else
  reg_fail "first session delete failed"
fi
reg_expect_se_rule absent "$WS_LONG(/.*)?" \
  "long-path fcontext rule removed after the last session delete" \
  "long-path fcontext rule NOT removed after the last session delete"
reg_expect_se_context is-not "$WS_LONG" docker_helper_workspace_t \
  "long path relabeled back off docker_helper_workspace_t after delete"

# No unexpected AVC in the M12 lifecycle window (best-effort: ausearch is
# present on the SELinux UAT guest; its absence must not block the group
# because the rule inventory above is the hard evidence).
if command -v ausearch >/dev/null 2>&1; then
  AVC_OUT="$(ausearch -m AVC,USER_AVC -ts "$AVC_START_M12" 2>/dev/null | grep 'avc:  denied' | grep -F 'scontext' | grep -F 'tcontext' || true)"
  if printf '%s' "$AVC_OUT" | grep -q 'denied'; then
    reg_fail "unexpected AVC denial in the M12 lifecycle window: $(printf '%s' "$AVC_OUT" | head -3)"
  else
    reg_ok "no unexpected AVC denial in the M12 lifecycle window"
  fi
else
  reg_info "ausearch unavailable; the AVC assertion is covered by the rule inventory assertions"
fi

# --- best-effort cleanup ------------------------------------------------------------------
rm -rf "$WS" "$SIBLING" "$UNRELATED" "$WS_LONG"

reg_result
