#!/usr/bin/env bash
#
# uat-regression-selinux-mount-guard.sh — Release-2 targeted regression
# group 4: SELinux workspace relabel-boundary guard (Tumbleweed / RPM /
# SELinux).
#
# Proves, through the REAL docker-helper Session lifecycle (public CLI), that
# the production workspace relabel-boundary guard rejects a workspace with a
# same-filesystem bind mount BENEATH it BEFORE any recursive restorecon can
# mutate the external source inode:
#   * /opt/uat-guard-out-* is bind-mounted at /opt/uat-guard-ws-*/mnt (same
#     st_dev => restorecon -x cannot see it);
#   * a Session create for that workspace must FAIL with the guard's own
#     error ("refusing recursive workspace relabel: mount point ... beneath
#     workspace"), NOT with a restorecon error;
#   * the external source inode (real path, outside the mount) keeps its
#     original type and inode — proving restorecon never ran across the alias;
#   * no persistent fcontext rule is left behind for the workspace.
#
# This is the confined production lifecycle path; the raw unconfined traversal
# semantics are proven separately by group 3 (uat-regression-selinux-fs-boundary.sh).
#
# Requires: installed docker-helper system service (active), enforcing SELinux,
# root. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "4. SELinux mount-boundary guard (same-fs bind rejected before restorecon)"

reg_require_root
reg_require_service
reg_require_cmd semanage "SELinux fcontext tooling"
reg_require_cmd restorecon "SELinux restorecon"
reg_require_cmd stat "coreutils"
reg_require_cmd mount "util-linux mount"
reg_require_cmd umount "util-linux umount"

if [ "$(getenforce 2>/dev/null || true)" != "Enforcing" ]; then
  reg_blocked "SELinux is not enforcing"
fi

# --- ensure /opt is an authorized global root (authorization, not MAC) ----------
dh config allowed-root add /opt >/dev/null 2>&1 || true
dh reload --system >/dev/null 2>&1 || true

# --- workspace with a same-filesystem bind mount beneath it ----------------------
WS="/opt/uat-guard-ws-$RANDOM"
OUT="/opt/uat-guard-out-$RANDOM"
mkdir -p "$WS/mnt" "$OUT"
printf 'external-marker\n' > "$OUT/marker.txt"

WS_DEV="$(stat -c '%d' "$WS" 2>/dev/null)"
OUT_DEV="$(stat -c '%d' "$OUT" 2>/dev/null)"
reg_info "workspace dev=$WS_DEV outside dev=$OUT_DEV (equal => same filesystem)"
if [ "$WS_DEV" != "$OUT_DEV" ]; then
  reg_fail "setup invalid: workspace and outside are not on the same filesystem"
  reg_result
fi

EXT_TYPE_BEFORE="$(stat -c '%C' "$OUT/marker.txt" 2>/dev/null | cut -d: -f3)"
EXT_INODE_BEFORE="$(stat -c '%d:%i' "$OUT/marker.txt" 2>/dev/null)"
WS_TYPE_BEFORE="$(stat -c '%C' "$WS" 2>/dev/null | cut -d: -f3)"
reg_info "external source inode BEFORE: type=$EXT_TYPE_BEFORE inode=$EXT_INODE_BEFORE; workspace type=$WS_TYPE_BEFORE"

if ! mount --bind "$OUT" "$WS/mnt" 2>/dev/null; then
  reg_fail "cannot bind mount $OUT at $WS/mnt"
  reg_result
fi

# --- real Session create must be rejected by the guard ----------------------------
SESS_JSON="$(dh session create --system --workspace "$WS" --json 2>&1)"
SESS_EC=$?
if [ "$SESS_EC" -eq 0 ]; then
  reg_fail "session create unexpectedly SUCCEEDED despite a mount beneath the workspace"
else
  reg_ok "session create rejected (rc=$SESS_EC) for a workspace with a mount beneath it"
fi
if printf '%s' "$SESS_JSON" | grep -Eq 'refusing recursive workspace relabel.*beneath workspace'; then
  reg_ok "rejection is the mount-boundary guard error (from CLI)"
else
  # The CLI surfaces only a generic API error (internal details are not leaked
  # into API errors by contract). The authoritative guard error is in the
  # daemon's operational log for this workspace.
  DAEMON_ERR="$(journalctl -u docker-helper.service -n 200 --no-pager 2>/dev/null | grep -F "$WS" | tail -6)"
  if printf '%s' "$DAEMON_ERR" | grep -Eq 'refusing recursive workspace relabel.*beneath workspace'; then
    reg_ok "rejection is the mount-boundary guard error (daemon operational log)"
  else
    reg_fail "rejection is NOT the guard error (CLI: $(printf '%s' "$SESS_JSON" | redact | head -2); daemon: $(printf '%s' "$DAEMON_ERR" | redact | tail -2))"
  fi
fi

# --- the external source inode must be untouched -----------------------------------
EXT_TYPE_AFTER="$(stat -c '%C' "$OUT/marker.txt" 2>/dev/null | cut -d: -f3)"
EXT_INODE_AFTER="$(stat -c '%d:%i' "$OUT/marker.txt" 2>/dev/null)"
WS_TYPE_AFTER="$(stat -c '%C' "$WS" 2>/dev/null | cut -d: -f3)"
MARK="$(cat "$OUT/marker.txt" 2>/dev/null || true)"
if [ "$EXT_TYPE_AFTER" = "$EXT_TYPE_BEFORE" ] \
   && [ "$EXT_INODE_AFTER" = "$EXT_INODE_BEFORE" ] \
   && [ "$MARK" = "external-marker" ]; then
  reg_ok "external source inode unchanged (type $EXT_TYPE_BEFORE, inode $EXT_INODE_BEFORE) - restorecon never mutated it"
else
  reg_fail "external source inode CHANGED: type $EXT_TYPE_BEFORE->$EXT_TYPE_AFTER inode $EXT_INODE_BEFORE->$EXT_INODE_AFTER"
fi
if [ "$WS_TYPE_AFTER" = "$WS_TYPE_BEFORE" ]; then
  reg_ok "workspace itself unchanged (type $WS_TYPE_BEFORE)"
else
  reg_fail "workspace type changed $WS_TYPE_BEFORE -> $WS_TYPE_AFTER"
fi

# --- no persistent fcontext rule may have been created ------------------------------
FC="$(semanage fcontext -l -C 2>/dev/null)"
if printf '%s' "$FC" | grep -Fq "$WS"; then
  reg_fail "a persistent fcontext rule was created for the rejected workspace"
else
  reg_ok "no persistent fcontext rule created for the rejected workspace"
fi

# --- cleanup -------------------------------------------------------------------------
umount "$WS/mnt" >/dev/null 2>&1 || true
semanage fcontext -d "$WS(/.*)?" >/dev/null 2>&1 || true
rm -rf "$WS" "$OUT"

reg_result
