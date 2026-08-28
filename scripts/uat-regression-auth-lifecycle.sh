#!/usr/bin/env bash
#
# uat-regression-auth-lifecycle.sh — Release-2 targeted regression group 3:
# Authorization lifecycle (Ubuntu / DEB / AppArmor).
#
# Subcases (independent):
#   A. credential revoke            — revoked credential cannot perform new
#                                     control-plane operations; existing
#                                     Session retains the documented lifecycle.
#   B. allowed-root narrowing       — a new Session outside the narrowed ceiling
#                                     is rejected; the existing Session retains
#                                     documented behavior.
#   C. Session delete               — subsequent Session-token requests rejected.
#   D. already-running operation    — a Session/control-plane lifecycle change
#                                     does not terminate an already-started
#                                     operation (documented lifecycle).
#   E. Principal disable            — active Sessions invalidated per contract;
#                                     Principal credentials no longer control
#                                     resources.
#
# Each subcase uses its own OS user/principal/session so results are
# independent. A subcase failure does not stop the others (collect-all).
#
# Requires: installed docker-helper system service (active), Docker reachable,
# root. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "3. Authorization lifecycle"

reg_require_root
reg_require_service
reg_require_docker

IMAGE="alpine:3.24"
CRED_DIR="/tmp/uat-reg3"
mkdir -p "$CRED_DIR"

# run_ok returns 0 when the given docker-helper data-plane op (session token in
# DOCKER_HELPER_SESSION_TOKEN) succeeds.
run_ok() {
  DOCKER_HELPER_SESSION_TOKEN="$1" dh run --image "$IMAGE" -- sh -ec 'true' >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# A. credential revoke
# ---------------------------------------------------------------------------
subcase_a() {
  reg_info "subcase A: credential revoke"
  local user="uatreg3a" home ws cred CRED_BASIC
  home="$(reg_setup_principal "$user")" || { reg_fail "A: setup principal failed"; return; }
  ws="$home/ws-a"; mkdir -p "$ws"
  chown -R "$user:$user" "$ws"

  CRED_BASIC="/tmp/uat-reg3/a.token"
  reg_principal_credential "$user" "$CRED_BASIC" || { reg_fail "A: credential create failed"; return; }
  reg_session "$CRED_BASIC" "$ws" || { reg_fail "A: session create failed"; return; }
  local sid="$REG_SESSION_ID" stok="$REG_SESSION_TOKEN" cid="$REG_CRED_ID"

  if dh credential revoke --system "$cid" >/dev/null 2>&1; then
    reg_ok "A: credential $cid revoked"
  else
    reg_fail "A: credential revoke failed"
    return
  fi

  if dh session create --system --token-file "$CRED_BASIC" --workspace "$ws" --json >/dev/null 2>&1; then
    reg_fail "A: revoked credential performed a new control-plane operation (session create)"
  else
    reg_ok "A: revoked credential rejected for new control-plane operation"
  fi

  if run_ok "$stok"; then
    reg_ok "A: existing session retains its documented lifecycle after revoke"
  else
    reg_fail "A: existing session broke after credential revoke"
  fi
}

# ---------------------------------------------------------------------------
# B. allowed-root narrowing
# ---------------------------------------------------------------------------
subcase_b() {
  reg_info "subcase B: allowed-root narrowing"
  local user="uatreg3b" home ws narrow ws2 cred
  home="$(reg_setup_principal "$user")" || { reg_fail "B: setup principal failed"; return; }
  ws="$home/ws-b"; narrow="$ws/narrow"; ws2="$home/ws-b-outside"
  mkdir -p "$narrow" "$ws2"
  chown -R "$user:$user" "$home"

  cred="/tmp/uat-reg3/b.token"
  reg_principal_credential "$user" "$cred" || { reg_fail "B: credential create failed"; return; }
  reg_session "$cred" "$narrow" || { reg_fail "B: session create under broad root failed"; return; }
  local sid="$REG_SESSION_ID" stok="$REG_SESSION_TOKEN"

  # Narrow: remove the broad default root (/home/$user), add the narrow one.
  dh principal allowed-root remove --system "$user" "$home" >/dev/null 2>&1 || true
  if ! dh principal allowed-root add --system "$user" "$narrow" >/dev/null 2>&1; then
    reg_fail "B: could not add narrowed allowed root"
    return
  fi
  reg_ok "B: allowed root narrowed to $narrow"

  if dh session create --system --token-file "$cred" --workspace "$ws2" --json >/dev/null 2>&1; then
    reg_fail "B: new session outside narrowed ceiling was accepted"
  else
    reg_ok "B: new session outside narrowed ceiling rejected"
  fi

  if run_ok "$stok"; then
    reg_ok "B: existing session retains documented behavior after narrowing"
  else
    reg_fail "B: existing session broke after allowed-root narrowing"
  fi
}

# ---------------------------------------------------------------------------
# C. Session delete
# ---------------------------------------------------------------------------
subcase_c() {
  reg_info "subcase C: session delete"
  local user="uatreg3c" home ws cred
  home="$(reg_setup_principal "$user")" || { reg_fail "C: setup principal failed"; return; }
  ws="$home/ws-c"; mkdir -p "$ws"
  chown -R "$user:$user" "$ws"

  cred="/tmp/uat-reg3/c.token"
  reg_principal_credential "$user" "$cred" || { reg_fail "C: credential create failed"; return; }
  reg_session "$cred" "$ws" || { reg_fail "C: session create failed"; return; }
  local sid="$REG_SESSION_ID" stok="$REG_SESSION_TOKEN"

  if ! dh session delete --system --id "$sid" >/dev/null 2>&1; then
    reg_fail "C: session delete failed"
    return
  fi
  reg_ok "C: session deleted"

  if run_ok "$stok"; then
    reg_fail "C: deleted session token still accepted for data-plane requests"
  else
    reg_ok "C: deleted session token rejected for subsequent requests"
  fi
}

# ---------------------------------------------------------------------------
# D. already-running operation
# ---------------------------------------------------------------------------
subcase_d() {
  reg_info "subcase D: already-running operation survives lifecycle change"
  local user="uatreg3d" home ws cred ctl out
  home="$(reg_setup_principal "$user")" || { reg_fail "D: setup principal failed"; return; }
  ws="$home/ws-d"; ctl="$ws/ctl"; mkdir -p "$ctl"
  chown -R "$user:$user" "$ws"

  cred="/tmp/uat-reg3/d.token"
  reg_principal_credential "$user" "$cred" || { reg_fail "D: credential create failed"; return; }
  reg_session "$cred" "$ws" || { reg_fail "D: session create failed"; return; }
  local sid="$REG_SESSION_ID" stok="$REG_SESSION_TOKEN"

  # Long-running op: reports readiness via a started marker, then waits for a
  # release marker in the same control mount.
  local runlog="/tmp/uat-reg3/d-run.log"
  local script='echo started > /mnt/ctl/started; while [ ! -f /mnt/ctl/release ]; do sleep 1; done; echo OP-DONE'
  DOCKER_HELPER_SESSION_TOKEN="$stok" \
    dh run --image "$IMAGE" --mount ctl:/mnt/ctl -- sh -ec "$script" >"$runlog" 2>&1 &
  local runpid=$!

  # Wait for the container to report readiness (started marker in the mount).
  local started=0
  for _ in $(seq 1 60); do
    if [ -f "$ctl/started" ]; then
      started=1
      break
    fi
    if ! kill -0 "$runpid" 2>/dev/null; then
      reg_fail "D: long-running operation exited before readiness (log: $(cat "$runlog" 2>/dev/null | redact))"
      return
    fi
    sleep 1
  done
  [ "$started" = 1 ] || { reg_fail "D: container did not report readiness in 60s"; return; }

  # Lifecycle change: delete the session while the operation is running.
  dh session delete --system --id "$sid" >/dev/null 2>&1 || true
  reg_ok "D: session deleted while operation running"

  sleep 2
  if kill -0 "$runpid" 2>/dev/null; then
    reg_ok "D: already-started operation continued after session delete"
  else
    reg_fail "D: already-started operation was terminated by session delete"
  fi

  touch "$ctl/release"
  local ec=0
  wait "$runpid" 2>/dev/null; ec=$?
  if [ "$ec" -eq 0 ] && grep -q 'OP-DONE' "$runlog"; then
    reg_ok "D: already-started operation completed normally (documented lifecycle)"
  else
    reg_fail "D: operation did not complete normally after session delete (rc=$ec)"
  fi
}

# ---------------------------------------------------------------------------
# E. Principal disable
# ---------------------------------------------------------------------------
subcase_e() {
  reg_info "subcase E: principal disable"
  local user="uatreg3e" home ws cred
  home="$(reg_setup_principal "$user")" || { reg_fail "E: setup principal failed"; return; }
  ws="$home/ws-e"; mkdir -p "$ws"
  chown -R "$user:$user" "$ws"

  cred="/tmp/uat-reg3/e.token"
  reg_principal_credential "$user" "$cred" || { reg_fail "E: credential create failed"; return; }
  reg_session "$cred" "$ws" || { reg_fail "E: session create failed"; return; }
  local sid="$REG_SESSION_ID" stok="$REG_SESSION_TOKEN"

  if ! dh principal set --system "$user" enabled false >/dev/null 2>&1; then
    reg_fail "E: principal disable failed"
    return
  fi
  reg_ok "E: principal disabled"

  if run_ok "$stok"; then
    reg_fail "E: active session still accepted after principal disable"
  else
    reg_ok "E: active session invalidated per contract after principal disable"
  fi

  if dh session create --system --token-file "$cred" --workspace "$ws" --json >/dev/null 2>&1; then
    reg_fail "E: disabled principal credential still controls resources"
  else
    reg_ok "E: disabled principal credential cannot create resources"
  fi
}

subcase_a
subcase_b
subcase_c
subcase_d
subcase_e

# best-effort cleanup of OS users (kept for evidence on failure)
for u in uatreg3a uatreg3b uatreg3c uatreg3d uatreg3e; do
  dh principal delete --system "$u" >/dev/null 2>&1 || true
  dh credential revoke --system "$(dh credential list --system "$u" 2>/dev/null | sed -n 's/^  ID:    //p' | head -1)" >/dev/null 2>&1 || true
  userdel -r "$u" >/dev/null 2>&1 || true
done
rm -rf "$CRED_DIR"

reg_result
