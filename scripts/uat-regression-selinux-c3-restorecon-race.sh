#!/usr/bin/env bash
#
# uat-regression-selinux-c3-restorecon-race.sh — Release-2 targeted regression
# group 7: C3 descriptor-safe recursive restorecon on enforcing Tumbleweed.
#
# Two proofs on the exact candidate, through the public CLI and the real
# confined service:
#
#   1. Prerequisite evidence (Phase A, live on the supported environment):
#      the installed libselinux implementation is the descriptor-safe floor
#      (libselinux1 >= 3.11, the upstream selinux_restorecon TOCTOU rewrite),
#      /usr/sbin/restorecon resolves against that libselinux, and /proc is a
#      real procfs so descriptor-backed /proc/self/fd labeling is actually
#      used. The runtime procfs prerequisite is enforced by the daemon itself
#      (zero-restorecon refusal unit-proven; not manufactured here — the
#      host/UAT runner /proc is never altered).
#
#   2. Hostile workspace race (bounded stress): while the confined daemon
#      runs recursive workspace restorecon (session create), a Principal-
#      owned process aggressively swaps a workspace path component between
#      the real directory and a symlink to a Principal-owned victim tree
#      OUTSIDE the issued workspace. The accepted security-closure contract
#      admits TWO per-round outcomes: the workspace relabel may COMPLETE
#      (successful raced create) or FAIL SAFELY (the daemon refuses
#      fail-closed with the stable mac_preparation_failed class and commits
#      no usable Session or bearer). A hostile Principal may continuously
#      remove a mutable pathname, so the contract promises no raced-create
#      availability; the mandatory positive proof is the normal
#      post-race lifecycle. In BOTH admitted outcomes the victim starts
#      with a known non-workspace SELinux type and must never receive
#      docker_helper_workspace_t; no foreign inode outside the issued tree
#      may be relabeled; the workspace lifecycle must stay healthy and leave
#      no stale helper-owned fcontext state. Any other create failure
#      classification is a regression.
#
# The OLD vulnerability is established by upstream/source evidence (libselinux
# 3.11 release notes and the selinux_restorecon rewrite); this script proves
# the SAFE composition on the exact candidate.
#
# Requires: installed docker-helper system service (active), enforcing
# SELinux, root. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see
# uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "7. SELinux C3 descriptor-safe restorecon: prerequisite evidence + hostile workspace race"

reg_require_root
reg_require_service
reg_require_cmd rpm "rpm package database"
reg_require_cmd ldd "dynamic linker inspection"
reg_require_cmd sudo "the hostile racer runs as the Principal, not root"
reg_require_cmd semanage "SELinux fcontext tooling"
reg_require_cmd restorecon "SELinux restorecon"

if [ "$(getenforce 2>/dev/null || true)" != "Enforcing" ]; then
  reg_blocked "SELinux is not enforcing"
fi

IMAGE="alpine:3.24"

# --- C3 floor comparison (dot-separated numeric, malformed refuses) -----------
c3_version_at_least() { # A B
  local a="$1" b="$2" i ai bi
  local -a A B
  IFS=. read -r -a A <<<"$a"
  IFS=. read -r -a B <<<"$b"
  for i in 0 1 2; do
    ai="${A[i]:-0}"
    bi="${B[i]:-0}"
    case "$ai" in ''|*[!0-9]*) return 2 ;; esac
    case "$bi" in ''|*[!0-9]*) return 2 ;; esac
    if ((10#$ai > 10#$bi)); then return 0; fi
    if ((10#$ai < 10#$bi)); then return 1; fi
  done
  return 0
}

# --- Phase A: the installed implementation is the descriptor-safe floor -------
LIBSELINUX_MIN="3.11"

LIB_PKG_VER="$(rpm -q libselinux1 2>/dev/null)"
if [ -z "$LIB_PKG_VER" ]; then
  reg_fail "libselinux1 package record unavailable (rpm failed)"
else
  LIB_VER="${LIB_PKG_VER#libselinux1-}"
  LIB_VER="${LIB_VER%%-*}"
  c3_version_at_least "$LIB_VER" "$LIBSELINUX_MIN"
  case $? in
    0) reg_ok "installed libselinux1 is the descriptor-safe floor ($LIB_PKG_VER >= $LIBSELINUX_MIN)" ;;
    1) reg_fail "installed libselinux1 ($LIB_PKG_VER) is older than the descriptor-safe floor $LIBSELINUX_MIN" ;;
    *) reg_fail "cannot parse installed libselinux1 version ($LIB_PKG_VER); floor unprovable" ;;
  esac
fi

FRONTEND_VER="$(rpm -q policycoreutils 2>/dev/null)"
[ -n "$FRONTEND_VER" ] \
  && reg_ok "restorecon frontend present ($FRONTEND_VER)" \
  || reg_fail "policycoreutils (restorecon frontend) is not installed"

FRONTEND_OWNER="$(rpm -qf /usr/sbin/restorecon 2>/dev/null)"
if [ "$FRONTEND_OWNER" = "policycoreutils" ] || [[ "$FRONTEND_OWNER" == policycoreutils-* ]]; then
  reg_ok "/usr/sbin/restorecon is owned by policycoreutils ($FRONTEND_OWNER)"
else
  reg_fail "/usr/sbin/restorecon ownership unexpected: '$FRONTEND_OWNER'"
fi

RESTORECON_LDD="$(ldd /usr/sbin/restorecon 2>/dev/null || true)"
if printf '%s\n' "$RESTORECON_LDD" | grep -q 'libselinux.so.1'; then
  reg_ok "restorecon links libselinux.so.1"
else
  reg_fail "restorecon does not link libselinux.so.1 (implementation unprovable)"
fi

LIB_PATH="$(printf '%s\n' "$RESTORECON_LDD" | awk '$1 == "libselinux.so.1" {print $3; exit}')"
LIB_RESOLVED="$(readlink -f "$LIB_PATH" 2>/dev/null || true)"
if [ -n "$LIB_RESOLVED" ] && [ -e "$LIB_RESOLVED" ]; then
  reg_ok "libselinux.so.1 resolved to $LIB_RESOLVED"
else
  reg_fail "cannot resolve the restorecon-linked libselinux.so.1 ('$LIB_PATH')"
fi

LIB_OWNER="$(rpm -qf "$LIB_RESOLVED" 2>/dev/null || true)"
if [[ "$LIB_OWNER" == libselinux1-* ]]; then
  reg_ok "the loaded libselinux implementation is owned by $LIB_OWNER"
else
  reg_fail "the loaded libselinux implementation is not an libselinux1 package record ('$LIB_OWNER')"
fi

reg_info "restorecon --version: $(/usr/sbin/restorecon --version 2>&1 | head -1)"

# --- Phase A: /proc is real procfs (statfs filesystem identity) ----------------
PROC_FSTYPE="$(stat -f -c '%T' /proc 2>/dev/null || true)"
PROC_MAGIC="$(stat -f -c '%t' /proc 2>/dev/null || true)"
if [ "$PROC_FSTYPE" = "proc" ] && [ "$PROC_MAGIC" = "9fa0" ]; then
  reg_ok "/proc is real procfs (fstype=proc, magic=0x$PROC_MAGIC)"
else
  reg_fail "/proc is not provably procfs (fstype='$PROC_FSTYPE', magic=0x$PROC_MAGIC)"
fi
if ls /proc/self/fd >/dev/null 2>&1 && [ -e /proc/self/fd/0 ]; then
  reg_ok "/proc/self/fd is usable in this execution environment"
else
  reg_fail "/proc/self/fd is not usable"
fi
# The recursive relabel executes inside the confined docker_helper_t domain;
# that same /proc is already consumed by the daemon's mount-boundary guard
# (/proc/self/mountinfo) on every session create, which the lifecycle proofs
# below exercise end to end.

# --- hostile race setup ---------------------------------------------------------
dh config allowed-root add /opt >/dev/null 2>&1 || true
if ! dh config allowed-root list 2>/dev/null | awk 'NF && $1 ~ /^\// {print $1}' | grep -qx '/opt'; then
  reg_fail "cannot add /opt to global allowed roots (authorization prerequisite)"
fi
dh reload >/dev/null 2>&1 || reg_fail "config reload failed after adding /opt root"

C3_P="c3race"
C3_CRED="/tmp/c3race.tok"
WS="/opt/uat-c3-ws-$RANDOM"
VICTIM="/opt/uat-c3-victim-$RANDOM"
reg_setup_principal "$C3_P" >/dev/null || { reg_fail "principal setup failed"; reg_result; }
dh principal allowed-root add "$C3_P" /opt >/dev/null 2>&1 || { reg_fail "principal allowed-root add failed"; reg_result; }
reg_principal_credential "$C3_P" "$C3_CRED" || { reg_fail "credential create failed"; reg_result; }

# Victim: a Principal-owned tree OUTSIDE the issued workspace. Its PARENT
# stays root-owned, so the Principal can own and read the victim but can
# never rename or replace the victim pathname itself.
mkdir -p "$VICTIM/inner"
printf 'c3-victim\n' > "$VICTIM/secret.txt"
printf 'c3-victim-inner\n' > "$VICTIM/inner/marker.txt"
chown -R "$C3_P:$C3_P" "$VICTIM"
VICTIM_TYPE_BEFORE="$(selinux_context_type "$VICTIM/secret.txt")"
VICTIM_INNER_TYPE_BEFORE="$(selinux_context_type "$VICTIM/inner/marker.txt")"
VICTIM_INODE_BEFORE="$(stat -c '%d:%i' "$VICTIM/secret.txt")"
if [ -n "$VICTIM_TYPE_BEFORE" ] && [ "$VICTIM_TYPE_BEFORE" != "docker_helper_workspace_t" ]; then
  reg_ok "victim starts outside the workspace type space ($VICTIM_TYPE_BEFORE)"
else
  reg_fail "victim precondition unusable (type '$VICTIM_TYPE_BEFORE')"
fi

# Workspace: root-owned skeleton first (the first relabel must succeed like
# the plain lifecycle), then handed to the Principal for the hostile race.
mkdir -p "$WS/rw/swap/deep"
chown -R "$C3_P:$C3_P" "$WS"
reg_info "workspace: $WS / victim: $VICTIM"

# The bounded hostile racer: swap the workspace path component WS/rw/swap
# between the real directory and a symlink to the external victim, using
# only operations available to the Principal (rename + symlink inside its
# own workspace). Runs as the Principal for a bounded iteration count.
c3_racer() { # iterations ws victim
  sudo -u "$C3_P" bash -c '
    i=0
    while [ "$i" -lt "$1" ]; do
      i=$((i + 1))
      mv "$2/rw/swap" "$2/rw/swap.real" 2>/dev/null || true
      ln -sfn "$3" "$2/rw/swap" 2>/dev/null || true
      rm -f "$2/rw/swap" 2>/dev/null || true
      mv "$2/rw/swap.real" "$2/rw/swap" 2>/dev/null || true
    done
  ' c3racer "$1" "$2" "$3"
}

# c3_read_create_outcome OUTFILE RC classifies one raced session-create
# outcome against the accepted security-closure contract. Prints exactly one
# verdict:
#   created       — rc 0 and the response carries a real Session id (dhs_)
#                   and a real bearer token (dht_)
#   safe_refusal  — the stable mac_preparation_failed class (the documented
#                   fail-closed MAC-preparation refusal; commits no Session)
#   unclassified  — anything else (rc 0 without a real id/token, or any other
#                   failure class) — always a C3 regression
#
# This narrow classifier is owned here, not in the shared regression lib,
# because only this scenario must retain the create's own error output, which
# the shared reg_session helper deliberately discards.
c3_read_create_outcome() { # outfile rc
  local out="$1" rc="$2"
  if [ "$rc" -eq 0 ]; then
    if grep -q '"id": "dhs_' "$out" && grep -q '"token": "dht_' "$out"; then
      printf 'created\n'
    else
      printf 'unclassified\n'
    fi
    return 0
  fi
  if grep -q "mac_preparation_failed" "$out"; then
    printf 'safe_refusal\n'
  else
    printf 'unclassified\n'
  fi
  return 0
}

RACE_ROUNDS=3
RACER_ITERS=4000
RACE_FAILED=0
for round in $(seq 1 "$RACE_ROUNDS"); do
  c3_racer "$RACER_ITERS" "$WS" "$VICTIM" &
  RACER_PID=$!
  # Capture the create's own output so the outcome can be classified against
  # the accepted two-outcome contract instead of failing on any nonzero rc.
  CREATE_OUT="/tmp/uat-c3-create.$round.$$"
  CREATE_RC=0
  dh session create --token-file "$C3_CRED" --json "$WS" >"$CREATE_OUT" 2>&1 || CREATE_RC=$?
  OUTCOME="$(c3_read_create_outcome "$CREATE_OUT" "$CREATE_RC")"
  SID=""
  STOK=""
  case "$OUTCOME" in
    created)
      SID="$(json_field id <"$CREATE_OUT")"
      STOK="$(json_field token <"$CREATE_OUT")"
      reg_ok "round $round: session created under race (relabel completed against the hostile tree)"
      ;;
    safe_refusal)
      reg_ok "round $round: relabel failed safely (mac_preparation_failed; no usable Session or bearer issued)"
      # Safe-refusal proof: no Session/token was issued for this credential
      # and the service stays healthy — the list answers successfully and
      # shows no issued session for this Principal.
      LIST_OUT="$(dh session list --token-file "$C3_CRED" 2>&1)"
      if [ $? -eq 0 ] && ! printf '%s\n' "$LIST_OUT" | grep -q 'dhs_'; then
        reg_ok "round $round: no Session was issued by the safe refusal (credential-owned session list empty, service healthy)"
      else
        reg_fail "round $round: safe-refusal proof failed (session list errored or a session exists after mac_preparation_failed)"
        RACE_FAILED=1
      fi
      # Safe rollback: the refusal must not leave helper-owned fcontext state.
      reg_expect_no_se_rule_for "$WS" "round $round: no helper-owned fcontext rule remains after the safe refusal"
      ;;
    *)
      reg_fail "round $round: session create failed with an unexpected public classification (only a completed relabel or the safe mac_preparation_failed refusal is admitted): $(head -3 "$CREATE_OUT" | redact | tr '\n' ' ')"
      RACE_FAILED=1
      ;;
  esac
  rm -f "$CREATE_OUT"
  # The victim must never have received the workspace type.
  VICTIM_TYPE_NOW="$(selinux_context_type "$VICTIM/secret.txt" || true)"
  if [ "$VICTIM_TYPE_NOW" != "docker_helper_workspace_t" ] && [ "$VICTIM_TYPE_NOW" = "$VICTIM_TYPE_BEFORE" ]; then
    reg_ok "round $round: victim type unchanged ($VICTIM_TYPE_NOW)"
  else
    reg_fail "round $round: victim label changed ('$VICTIM_TYPE_BEFORE' -> '$VICTIM_TYPE_NOW')"
    RACE_FAILED=1
  fi
  VICTIM_INNER_TYPE_NOW="$(selinux_context_type "$VICTIM/inner/marker.txt" || true)"
  if [ "$VICTIM_INNER_TYPE_NOW" = "$VICTIM_INNER_TYPE_BEFORE" ]; then
    reg_ok "round $round: victim inner tree unchanged ($VICTIM_INNER_TYPE_NOW)"
  else
    reg_fail "round $round: victim inner tree relabeled ('$VICTIM_INNER_TYPE_BEFORE' -> '$VICTIM_INNER_TYPE_NOW')"
    RACE_FAILED=1
  fi
  VICTIM_INODE_NOW="$(stat -c '%d:%i' "$VICTIM/secret.txt" 2>/dev/null || true)"
  if [ "$VICTIM_INODE_NOW" = "$VICTIM_INODE_BEFORE" ]; then
    reg_ok "round $round: victim inode identity unchanged ($VICTIM_INODE_NOW)"
  else
    reg_fail "round $round: victim inode replaced ($VICTIM_INODE_BEFORE -> $VICTIM_INODE_NOW)"
    RACE_FAILED=1
  fi
  # Release the round's coverage before the next round (fresh relabel each
  # time). A failed release leaves the rule; the residue check below catches
  # it only after the final round, so release failures surface here too.
  if [ -n "$SID" ]; then
    chown -R root:root "$WS" >/dev/null 2>&1 || true
    if dh session delete "$SID" >/dev/null 2>&1; then
      reg_ok "round $round: session deleted (coverage released)"
    else
      reg_fail "round $round: session delete failed"
      RACE_FAILED=1
    fi
  fi
  wait "$RACER_PID" 2>/dev/null || true
done

if [ "$RACE_FAILED" -eq 0 ]; then
  reg_ok "bounded hostile race completed ($RACE_ROUNDS rounds x $RACER_ITERS swaps): every round completed or failed safely, no foreign inode outside the issued tree was relabeled"
fi

# --- no stale helper-owned fcontext ownership/residue -----------------------------
# After the final release, no helper-owned workspace rule may survive for the
# raced workspace (a failed transition must not leave half-applied state).
reg_expect_no_se_rule_for "$WS" "no stale fcontext rule remains for the raced workspace after release"

# --- service remains healthy ----------------------------------------------------
if dh session list >/dev/null 2>&1; then
  reg_ok "service remains healthy after the race (session list answered)"
else
  reg_fail "service unhealthy after the race (session list failed)"
fi

# --- normal workspace lifecycle still works afterward ----------------------------
POST_SID=""
if reg_session "$C3_CRED" "$WS"; then
  POST_SID="$REG_SESSION_ID"; STOK="$REG_SESSION_TOKEN"
  if [ -n "$POST_SID" ] && [ -n "$STOK" ]; then
    reg_ok "normal session creation works after the race"
  else
    reg_fail "post-race session create returned no id/token"
  fi
else
  reg_fail "normal session creation failed after the race"
fi

if [ -n "$POST_SID" ]; then
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
  reg_expect_se_context is "$WS" docker_helper_workspace_t \
    "actual workspace type is docker_helper_workspace_t"
  chown -R "$C3_P:$C3_P" "$WS" >/dev/null 2>&1 || { reg_fail "workspace chown to principal failed"; }
  RW_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$STOK" \
    dh run --mount rw:/mnt/rw "$IMAGE" -- sh -ec 'echo c3-rw-ok > /mnt/rw/f; cat /mnt/rw/f' 2>&1)"
  if [ $? -eq 0 ] && printf '%s' "$RW_OUT" | grep -q 'c3-rw-ok'; then
    reg_ok "container RW through the workspace works after the race"
  else
    reg_fail "container RW run failed after the race: $(printf '%s' "$RW_OUT" | redact | head -4)"
  fi
  chown -R root:root "$WS" >/dev/null 2>&1 || true
  if dh session delete "$POST_SID" >/dev/null 2>&1; then
    reg_ok "post-race session deleted"
  else
    reg_fail "post-race session delete failed"
  fi
fi

# --- cleanup ----------------------------------------------------------------------
rm -rf "$WS" "$VICTIM" "$C3_CRED" 2>/dev/null || true

reg_result
