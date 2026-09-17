#!/usr/bin/env bash
#
# uat-regression-h2-parked-revocation.sh — Release-2 targeted regression
# group 27 (Ubuntu / DEB / AppArmor) and group 9 (Tumbleweed / RPM /
# SELinux): H2 commit-boundary credential revocation race.
#
# H2 is closed at the Session-issuance linearization owner: a
# credential-authority Session create re-proves its authorizing credential
# row (still existing, still owned, still active) inside the create
# transaction's conditional insert, so a revoke that commits before the
# Session commit prevents that Session and the refusal answers the canonical
# non-disclosing 401 credential contract. The final security ledger requires
# this composition as cross-boundary UAT on the exact candidate: the parked
# ordering — create authenticated, parked, credential revoked, create
# resumed — must lose at the commit boundary. The ordinary sequential
# revoke-then-create regressions (group 3 subcase A) do not prove the parked
# ordering, so this group adds exactly that missing cross-boundary proof.
#
# This group reuses the H8 guest-local hostile mechanism (the backend's own
# MAC frontend binary is temporarily replaced by a test-only shim, moved
# back afterwards, with a fail-closed restore trap; no production seam, no
# debug API, no configurable command pathname, no sleep-based "probably
# revoked by now" race, and no direct database injection). The shim here is
# the bounded PASS-THROUGH parking shape, not the H8 hang shape: it raises
# SIGSTOP on itself, and the harness releases it with SIGCONT AFTER it has
# restored the real backend binary, so the parked daemon command execs the
# real frontend at its canonical, policy-granted path with the original
# argv and the normal production flow continues. If the harness never
# releases, the daemon's own fixed MAC transition budget (60s) kills and
# reaps the stopped child — the parked hold is bounded by production
# constants, never by the harness.
#
# Proven per backend:
#   * the real packaged Session create authenticates and enters the real
#     post-authentication / pre-insert MAC preparation section (the shim
#     process exists and stays parked);
#   * while parked, the authorizing credential is revoked through the
#     normal production control plane (the revoke does not queue behind
#     the held lifecycle coordination);
#   * after the release, the parked create continues through the REAL
#     backend command (the real frontend execs; the create passes MAC
#     preparation and reaches the commit boundary);
#   * the create LOSES at the commit-boundary revalidation: it fails with
#     the canonical non-disclosing 401 credential contract (public output
#     stays `status 401, code unauthorized` and never discloses the
#     revoked-vs-unknown classification; the classification lives only in
#     the audit stream as one auth.failure record with
#     result=credential.revoked and no session.create success record);
#   * no Session exists for the requested workspace;
#   * no stale MAC/helper state: the preparation that succeeded after the
#     release was rolled back through the canonical removal owner
#     (AppArmor managed fragment / SELinux fcontext inventory carry no
#     boundary for the workspace), and no shim/backend child survives;
#   * the Unix API/service stays healthy throughout;
#   * after the hostile condition is removed, a normal Session create with
#     a fresh credential succeeds (recovery proof).
#
# Requires: installed docker-helper system service (active), mandatory MAC
# (AppArmor or enforcing SELinux), root. Exits 0 = PASS, 1 = FAIL,
# 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "27/9. H2 commit-boundary credential revocation race"

reg_require_root
reg_require_service

SOCK="/run/docker-helper/docker-helper.sock"

# ---------------------------------------------------------------------------
# Backend selection (fail closed on anything else)
# ---------------------------------------------------------------------------
BACKEND=""
PARSER_PATH="/usr/sbin/apparmor_parser"
SEMANAGE_PATH="/usr/sbin/semanage"
if [ -d /sys/kernel/security/apparmor ] && [ -f "$PARSER_PATH" ]; then
  BACKEND="apparmor"
elif command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null || true)" = "Enforcing" ] && [ -f "$SEMANAGE_PATH" ]; then
  BACKEND="selinux"
fi
case "$BACKEND" in
  apparmor) reg_info "active backend: AppArmor (Ubuntu)" ;;
  selinux)  reg_info "active backend: SELinux (Tumbleweed)" ;;
  *) reg_blocked "no supported mandatory MAC backend active" ;;
esac

# The whole parked scenario must finish far below the daemon's own MAC
# transition budget: the harness releases the parked command seconds after
# parking it, and the create must reach the commit boundary through the REAL
# backend command rather than being budget-killed (a budget kill would fail
# the create as mac_preparation_failed, not as the commit-boundary 401).
PARK_WAIT_S=15
RELEASE_BUDGET_S=45

# --- fail-closed hostile-mechanism restore -----------------------------------
TARGET_PATH=""
REAL_PATH=""
SHIM_ARMED=0
SHIM_PID=""

restore_hostile() {
  if [ "$SHIM_ARMED" = 1 ] && [ -n "$REAL_PATH" ] && [ -e "$REAL_PATH" ]; then
    mv -f "$REAL_PATH" "$TARGET_PATH"
    SHIM_ARMED=0
    REAL_PATH=""
  fi
}
trap restore_hostile EXIT

backend_command_path() {
  if [ "$BACKEND" = "apparmor" ]; then printf '%s' "$PARSER_PATH"; else printf '%s' "$SEMANAGE_PATH"; fi
}

arm_shim() {
  TARGET_PATH="$(backend_command_path)"
  if [ ! -f "$TARGET_PATH" ]; then
    reg_blocked "backend command $TARGET_PATH not found (unexpected on a supported guest)"
  fi
  REAL_PATH="${TARGET_PATH}.dh2-real-$$"
  SHIM_TYPE=""
  if [ "$BACKEND" = "selinux" ] && command -v ls >/dev/null 2>&1; then
    # SELinux is type-based: copy the ORIGINAL binary's type onto the shim so
    # the confined daemon's execute of that path keeps exactly the original
    # permission; the restore (mv) brings the original file and its type
    # back (same mechanism as the H8 group).
    SHIM_TYPE="$(ls -Z "$TARGET_PATH" 2>/dev/null | awk '{print $1}' | cut -d: -f3)"
    [ -n "$SHIM_TYPE" ] || SHIM_TYPE=""
  fi
  mv "$TARGET_PATH" "$REAL_PATH"
  # Bounded PASS-THROUGH parking shim: park on SIGSTOP immediately, and after
  # a SIGCONT release exec the path this process was invoked as ($0 / the
  # canonical backend command path) with the original argv. The harness
  # restores the real backend binary onto that canonical path BEFORE the
  # release, so the parked daemon command continues through the real
  # frontend under the same policy-granted exec permission that started the
  # shim. If the release never arrives, the daemon's own fixed MAC
  # transition budget kills and reaps the stopped child (fail-closed).
  #
  # The interpreter choice follows the H8 evidence: on Ubuntu /bin/sh
  # executes under the profile at the parser path (proven); on Tumbleweed
  # /bin/sh is bash and docker_helper_t may only execute the semanage
  # interpreter chain (python3, semanage's own shebang interpreter).
  if [ "$BACKEND" = "selinux" ]; then
    printf '#!/usr/bin/python3\nimport os, signal, sys\nos.kill(os.getpid(), signal.SIGSTOP)\nos.execv(sys.argv[0], sys.argv)\n' > "$TARGET_PATH"
  else
    printf '#!/bin/sh\nkill -STOP $$\nexec "$0" "$@"\n' > "$TARGET_PATH"
  fi
  chmod 0755 "$TARGET_PATH"
  if [ -n "$SHIM_TYPE" ] && command -v chcon >/dev/null 2>&1; then
    chcon -t "$SHIM_TYPE" "$TARGET_PATH" 2>/dev/null || true
  fi
  SHIM_ARMED=1
}

shim_marker_present() { # -> 0 when a shim child process exists
  # The shim's argv ends with the backend command path (shebang exec), so the
  # pattern is anchored at the end: the moved real binary path
  # (<path>.dh2-real-$$) must not produce a substring match, and nothing else
  # may match while the shim is armed.
  local cmd
  cmd="$(backend_command_path)"
  pgrep -f -- "${cmd}([[:space:]]|\$)" >/dev/null 2>&1
}

shim_pid() {
  local cmd
  cmd="$(backend_command_path)"
  pgrep -f -- "${cmd}([[:space:]]|\$)" 2>/dev/null | head -1
}

service_healthy() { # LABEL
  if systemctl is-active --quiet docker-helper.service 2>/dev/null; then
    reg_ok "$1: service remains active"
  else
    reg_fail "$1: service is not active"
  fi
  if curl --silent --fail --max-time 2 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1; then
    reg_ok "$1: Unix API remains healthy"
  else
    reg_fail "$1: GET /health over the Unix API failed"
  fi
}

# --- fixture -------------------------------------------------------------------
USER_A="uatreg27a"
home_a="$(reg_setup_principal "$USER_A")" || { reg_fail "setup principal A failed"; reg_result; }
WS_A="$home_a/ws"
mkdir -p "$WS_A"
CREDFILE="/tmp/uat-h2-cred.$$"
reg_principal_credential "$USER_A" "$CREDFILE" || { reg_fail "credential create failed"; reg_result; }

# --- hostile scenario: parked create vs credential revocation -------------------
reg_info "arming the pass-through parking shim on the backend command"
arm_shim

CREATE_OUT="/tmp/uat-h2-create.$$"
REVOKE_OUT="/tmp/uat-h2-revoke.$$"
create_start="$(date +%s)"
(
  dh session create --system --token-file "$CREDFILE" --workspace "$WS_A" >"$CREATE_OUT" 2>&1
) &
CREATE_PID=$!
# The create parks inside the shimmed MAC command: this proves the request
# was authenticated (entry authentication happened) and reached the real
# post-authentication / pre-insert MAC preparation section of the packaged
# daemon.
marker_seen=0
deadline=$(( $(date +%s) + PARK_WAIT_S ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if shim_marker_present; then marker_seen=1; break; fi
  sleep 0.1
done
if [ "$marker_seen" = 1 ]; then
  # Confirm durability: a transient match must not count as the parked state.
  sleep 1
  if shim_marker_present; then
    reg_ok "the real Session create authenticated and parked inside the post-authentication/pre-insert MAC preparation (shim process present and durable)"
  else
    marker_seen=0
    reg_fail "the shim process vanished before the revocation: the parked post-authentication state was not durable"
  fi
else
  reg_fail "the create never reached the parked MAC preparation section (it may have failed before the backend command)"
  cat "$CREATE_OUT" >&2 2>/dev/null || true
fi

if [ "$marker_seen" = 1 ]; then
  SHIM_PID="$(shim_pid)"
  if [ -n "$SHIM_PID" ]; then
    reg_ok "the parked backend command is a real parked process (pid $SHIM_PID)"
  else
    reg_fail "the parked backend command pid could not be captured (release proof impossible)"
  fi

  # Revoke the authorizing credential THROUGH the normal production control
  # plane while the create is parked. The revoke must complete while the
  # parked create still holds the lifecycle coordination: credential
  # revocation does not queue behind that boundary.
  if dh credential revoke --system "$REG_CRED_ID" >"$REVOKE_OUT" 2>&1; then
    reg_ok "the authorizing credential was revoked through the production control plane while the create stayed parked"
  else
    reg_fail "credential revoke failed while the create was parked"
    cat "$REVOKE_OUT" >&2 2>/dev/null || true
  fi
  if shim_marker_present; then
    reg_ok "the create was still parked when the revocation committed"
  else
    reg_fail "the parked create did not stay parked across the revocation"
  fi

  # Release: restore the real backend binary onto its canonical path FIRST
  # (the fail-closed restore primitive), then SIGCONT the parked process so
  # it execs the real frontend at the canonical, policy-granted path and the
  # normal production flow continues.
  restore_hostile
  if [ -f "$(backend_command_path)" ]; then
    reg_ok "the real backend command binary was restored before the release"
  else
    reg_fail "the backend command binary was not restored before the release"
  fi
  kill -CONT "$SHIM_PID" 2>/dev/null || true

  # The released create must finish bounded through the REAL flow: it passes
  # MAC preparation and reaches the commit-boundary credential revalidation,
  # which it loses. Wait with a bounded deadline and diagnostics.
  create_done=0
  create_rc=0
  deadline=$(( $(date +%s) + RELEASE_BUDGET_S ))
  while [ "$create_done" = 0 ]; do
    if ! kill -0 "$CREATE_PID" 2>/dev/null; then
      create_done=1
      wait "$CREATE_PID" 2>/dev/null
      create_rc=$?
      break
    fi
    if [ "$(date +%s)" -gt "$deadline" ]; then
      reg_info "release diagnostics: create state after the release deadline:"
      ps -o pid,ppid,stat,etime,args -e 2>/dev/null | grep -F "$(backend_command_path)" | grep -v grep || true
      journalctl -u docker-helper.service --since "@${create_start}" --no-pager 2>/dev/null | tail -12 || true
      reg_fail "the released create exceeded the bounded wait (${RELEASE_BUDGET_S}s): the parked ordering did not resolve through the production flow"
      kill "$CREATE_PID" 2>/dev/null || true
      break
    fi
    sleep 0.2
  done

  if [ "$create_rc" = 0 ]; then
    reg_fail "a Session create whose authorizing credential was revoked before the commit must not issue a Session (H2 regression)"
  else
    if grep -q "status 401" "$CREATE_OUT" 2>/dev/null && grep -q "code unauthorized" "$CREATE_OUT" 2>/dev/null; then
      reg_ok "the parked create lost at the commit boundary: canonical non-disclosing 401 credential refusal"
    elif grep -q "mac_preparation_failed" "$CREATE_OUT" 2>/dev/null; then
      reg_fail "the create failed as mac_preparation_failed: the parked command did not continue through the real backend flow (pass-through broken)"
    else
      reg_fail "the parked create failed with an unexpected public failure (expected the canonical 401 credential contract): $(head -3 "$CREATE_OUT" 2>/dev/null | redact | tr '\n' ' ')"
    fi
  fi
  if grep -q "credential.revoked\|credential.not_found" "$CREATE_OUT" 2>/dev/null; then
    reg_fail "the public failure disclosed the credential classification (non-disclosing contract broken)"
  else
    reg_ok "the public failure stayed non-disclosing (classification lives only in the audit stream)"
  fi

  # Audit stream: exactly the canonical credential classification for this
  # request, and no session.create success record in the scenario window.
  AUDIT_WINDOW="$(journalctl -u docker-helper.service --since "@${create_start}" --no-pager 2>/dev/null || true)"
  AUDIT_REVOKE="$(printf '%s\n' "$AUDIT_WINDOW" | grep '"event":"auth.failure"' | grep '"path":"/sessions"' | grep '"result":"credential.revoked"' || true)"
  if [ -n "$AUDIT_REVOKE" ]; then
    reg_ok "the audit stream carries one auth.failure record classified credential.revoked (commit-boundary rejection proven on the production path)"
  else
    reg_fail "no auth.failure record with result=credential.revoked in the bounded journal window (the commit-boundary rejection was not proven on the audit path)"
  fi
  if printf '%s\n' "$AUDIT_WINDOW" | grep '"event":"session.create"' | grep -q '"result":"success"'; then
    reg_fail "the audit window carries a session.create success record (a Session was issued behind the revoked authority)"
  else
    reg_ok "the audit window carries no session.create success record (no Session was issued)"
  fi
fi

service_healthy "during/after the parked revocation race"

# Fail-closed convergence: whatever happened above, the backend command
# binary must be restored and no parked shim process may remain (best-effort
# release for any branch that skipped the explicit release).
restore_hostile
if shim_marker_present; then
  LINGER_PID="$(shim_pid)"
  [ -n "$LINGER_PID" ] && kill -CONT "$LINGER_PID" 2>/dev/null || true
fi

# No Session exists for the requested workspace.
if dh session list --system --json 2>/dev/null | grep -qF "$WS_A"; then
  reg_fail "the parked create issued a Session for the revoked credential"
else
  reg_ok "no Session exists for the requested workspace (the losing ordering issued nothing)"
fi

# The released pass-through must have really run the real backend command and
# the create's rollback owner must have removed the prepared coverage: no
# MAC boundary for the workspace may survive, and no backend child may
# remain.
restore_hostile
if [ -f "$(backend_command_path)" ]; then
  reg_ok "the backend command binary is the real frontend after the scenario"
else
  reg_fail "the backend command binary was not restored after the scenario"
fi
shim_gone=1
for _ in $(seq 1 50); do
  if shim_marker_present; then shim_gone=0; sleep 0.1; else shim_gone=1; break; fi
done
if [ "$shim_gone" = 1 ]; then
  reg_ok "no parked backend command process survived the release (the real frontend ran and exited, no child left behind)"
else
  reg_fail "a backend command process survived after the release"
fi

if [ "$BACKEND" = "apparmor" ]; then
  FRAGMENT="/var/lib/docker-helper/apparmor/managed-boundaries"
  if [ -f "$FRAGMENT" ] && grep -qF "$WS_A" "$FRAGMENT"; then
    reg_fail "the managed fragment recorded a boundary although the create was refused at the commit boundary (stale MAC state)"
  else
    reg_ok "the AppArmor managed fragment carries no boundary for the refused create (prepared coverage rolled back)"
  fi
else
  if semanage fcontext -l -C -n 2>/dev/null | grep -qF "$WS_A"; then
    reg_fail "a persistent fcontext rule exists although the create was refused at the commit boundary (stale MAC state)"
  else
    reg_ok "the SELinux fcontext inventory carries no rule for the refused create (prepared coverage rolled back)"
  fi
fi

# --- recovery proof ---------------------------------------------------------------
service_healthy "after the parked revocation race"

# A normal Session create with a FRESH credential succeeds after the hostile
# condition is removed (the original credential stays revoked on purpose).
RECOVERY_CRED="/tmp/uat-h2-recovery.$$"
if reg_principal_credential "$USER_A" "$RECOVERY_CRED"; then
  WS_REC="$home_a/ws-recovery"
  mkdir -p "$WS_REC"
  if reg_session "$RECOVERY_CRED" "$WS_REC"; then
    reg_ok "a subsequent normal Session create succeeds after the hostile condition is removed (recovery)"
    RECOVERY_SESSION_ID="$REG_SESSION_ID"
  else
    reg_fail "normal Session create failed after the hostile condition was removed (recovery broken)"
    RECOVERY_SESSION_ID=""
  fi
else
  reg_fail "recovery credential create failed (recovery proof impossible)"
  RECOVERY_SESSION_ID=""
fi

# --- cleanup -----------------------------------------------------------------------
if [ -n "${RECOVERY_SESSION_ID:-}" ]; then
  dh session delete --system --id "$RECOVERY_SESSION_ID" >/dev/null 2>&1 || true
fi
dh principal delete --system "$USER_A" >/dev/null 2>&1 || true
rm -rf "$WS_A" "${WS_REC:-}" "$CREDFILE" "$RECOVERY_CRED" "$CREATE_OUT" "$REVOKE_OUT" 2>/dev/null || true

reg_result
