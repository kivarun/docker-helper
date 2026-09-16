#!/usr/bin/env bash
#
# uat-regression-h8-mac-liveness.sh — Release-2 targeted regression group 26
# (Ubuntu / DEB / AppArmor) and group 8 (Tumbleweed / RPM / SELinux): H8
# bounded MAC-command liveness.
#
# External MAC one-shot commands once had no execution bound, so a hung
# command could hold the lifecycle coordination (lifecycleMu is held across a
# Session create's whole MAC preparation) indefinitely and delay an
# emergency administrative disable. Post-fix every serialized MAC transition
# runs under one fixed, non-configurable Release-2.2 MAC transition budget
# (60s, documented in docs/architecture.md); individual subprocesses consume
# the remaining budget, a budget-expired command is killed and reaped (and
# carries Pdeathsig=SIGKILL), and a timed-out command is a failure, never
# successful MAC preparation.
#
# This group proves REAL process behavior of the packaged daemon under
# mandatory MAC, on BOTH active backends, with the least invasive
# guest-local hostile mechanism: the backend's own MAC frontend binary is
# temporarily replaced by a self-blocking shim (moved back afterwards, with
# a fail-closed restore trap). No production seam, debug API, environment
# backdoor, or configurable command pathname was added for this: the daemon
# runs its normal production command path against a command that never
# returns.
#
# Proven per backend:
#   * measurement evidence: real ordinary MAC command durations (parser
#     reload / semanage listing / large-workspace restorecon) sit far below
#     the fixed transition budget;
#   * the hostile shim really blocks the MAC one-shot (process present);
#   * the daemon does not wait forever: the parked Session create fails
#     within the bound and commits no Session;
#   * the queue closure: further Session creates issued while the first
#     parked create holds the lifecycle coordination are refused immediately
#     with the stable lifecycle_busy / HTTP 503 class (no queued wait for the
#     boundary, no own late MAC budget), so the emergency disable completes
#     within ONE in-flight transition budget regardless of the concurrent
#     create count, and the refused creates commit no Session and leave no
#     MAC state;
#   * the hung command process is gone after the bound (no MAC child left
#     behind);
#   * the administrative Principal disable completes within the proven
#     bound (its wall-clock is recorded);
#   * the Unix API/service stays healthy throughout (the expected failure
#     mode is the failed create, not a dead service);
#   * MAC ownership/backend state is fail closed (AppArmor fragment /
#     SELinux fcontext inventory unchanged, no false coverage);
#   * after the hostile condition is removed, a subsequent normal MAC
#     transition works;
#   * shutdown: with the shim armed and a create parked, the real packaged
#     service reaches stopped state within the documented shutdown
#     wall-clock bound (TimeoutStopSec=45s) and leaves no external MAC
#     child behind.
#
# Requires: installed docker-helper system service (active), mandatory MAC
# (AppArmor or enforcing SELinux), root. Exits 0 = PASS, 1 = FAIL,
# 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "26/8. H8 bounded MAC-command liveness"

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

# The fixed Release-2.2 MAC transition budget (production security constant;
# documented in docs/architecture.md). The regression waits for the bound,
# never reduced.
MAC_BUDGET_S=60
# Wall-clock bound for the whole hostile lifecycle (create fails, disable
# completes): the transition budget plus generous scheduling/CLI slop.
HOLD_BUDGET_S=100

# --- fail-closed hostile-mechanism restore -----------------------------------
TARGET_PATH=""
REAL_PATH=""
SHIM_ARMED=0

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
  REAL_PATH="${TARGET_PATH}.dh8-real-$$"
  SHIM_TYPE=""
  if [ "$BACKEND" = "selinux" ] && command -v ls >/dev/null 2>&1; then
    # SELinux is type-based: a freshly created file inherits the directory
    # default, not the original binary's type, so the confined daemon could
    # not execute the shim at all. Copy the ORIGINAL's type onto the shim so
    # the daemon's execute of that path keeps exactly the original
    # permission; the restore (mv) brings the original file and its type
    # back.
    SHIM_TYPE="$(ls -Z "$TARGET_PATH" 2>/dev/null | awk '{print $1}' | cut -d: -f3)"
    [ -n "$SHIM_TYPE" ] || SHIM_TYPE=""
  fi
  mv "$TARGET_PATH" "$REAL_PATH"
  # A self-stopping blocker: the shim raises SIGSTOP on itself, so it blocks
  # with no exec, no file access, and no CPU cost under the daemon's own
  # mandatory MAC policy (an exec-based shim would be denied by the shipped
  # policy itself — the hostile state must be reachable from the confined
  # daemon). The bounded runner's budget kill delivers SIGKILL, which
  # terminates a stopped process and is reaped.
  #
  # The shebang must be an interpreter the shipped policy allows the daemon
  # to execute: on Ubuntu /bin/sh executes under the profile (proven), while
  # on Tumbleweed /bin/sh is bash and docker_helper_t may only execute the
  # semanage interpreter chain (python3) — the AVC evidence proved the bash
  # exec denial. python3 is semanage's own shebang interpreter, so its
  # execution is already granted exactly for this frontend.
  if [ "$BACKEND" = "selinux" ]; then
    printf '#!/usr/bin/python3\nimport os, signal\nos.kill(os.getpid(), signal.SIGSTOP)\n' > "$TARGET_PATH"
  else
    printf '#!/bin/sh\nkill -STOP $$\n' > "$TARGET_PATH"
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
  # (<path>.dh8-real-$$) must not produce a substring match, and nothing else
  # may match while the shim is armed.
  local cmd
  cmd="$(backend_command_path)"
  pgrep -f -- "${cmd}([[:space:]]|\$)" >/dev/null 2>&1
}

# Dump the hostile-state evidence when the hold deadline fires: the parked
# process state, the daemon journal since the hold, and any fresh AVC denial
# (a denied budget kill is a policy defect, not a daemon defect).
hold_deadline_diagnostics() { # $1 = reason
  local reason="$1"
  reg_info "deadline diagnostics (${reason}): parked MAC command state:"
  ps -o pid,ppid,stat,etime,args -e 2>/dev/null | grep -F "$(backend_command_path)" | grep -v grep || true
  reg_info "deadline diagnostics: daemon journal since the hold:"
  journalctl -u docker-helper.service --since "@${create_start}" --no-pager 2>/dev/null | tail -12 || true
  if command -v ausearch >/dev/null 2>&1; then
    reg_info "deadline diagnostics: fresh AVC denials since the hold:"
    ausearch -m AVC --start "$(date -d "@${create_start}" +%H:%M:%S 2>/dev/null || echo "${create_start}")" 2>/dev/null | grep -E "avc:  denied" | tail -6 || true
  fi
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

# --- measurement evidence (Phase-B budget justification) ---------------------
BIGTREE="/opt/uat-h8-bigtree-$RANDOM"
mkdir -p "$BIGTREE"
for d in $(seq 1 100); do
  mkdir -p "$BIGTREE/dir$d"
  for f in $(seq 1 500); do : > "$BIGTREE/dir$d/f$f"; done
done
ENTRY_COUNT="$(find "$BIGTREE" | wc -l | tr -d ' ')"
reg_info "measurement workspace: $BIGTREE ($ENTRY_COUNT entries)"

timeit() { # CMD...
  local t0 t1
  t0="$(date +%s%N)"
  "$@" >/dev/null 2>&1
  t1="$(date +%s%N)"
  echo $(( (t1 - t0) / 1000000 ))
}

measured_max_ms=0
list_max_ms=0
bigrestorecon_ms=0
record_ms() { # MS
  if [ "$1" -gt "$measured_max_ms" ]; then measured_max_ms="$1"; fi
}

if [ "$BACKEND" = "apparmor" ]; then
  parser_max_ms=0
  for _ in 1 2 3 4 5; do
    ms="$(timeit apparmor_parser --replace --skip-cache /etc/apparmor.d/docker-helper-system)"
    if [ "$ms" -gt "$parser_max_ms" ]; then parser_max_ms="$ms"; fi
    record_ms "$ms"
  done
  reg_info "apparmor_parser --replace reload (5 runs): max ${parser_max_ms}ms"
else
  for _ in 1 2 3 4 5; do
    ms="$(timeit semanage fcontext -l -C -n)"
    if [ "$ms" -gt "$list_max_ms" ]; then list_max_ms="$ms"; fi
    record_ms "$ms"
  done
  bigrestorecon_ms="$(timeit restorecon -R -m -x "$BIGTREE")"
  record_ms "$bigrestorecon_ms"
  reg_info "semanage fcontext -l -C -n (5 runs): max ${list_max_ms}ms; restorecon -R -m -x over the large workspace: ${bigrestorecon_ms}ms"
fi
if [ "$measured_max_ms" -lt $(( MAC_BUDGET_S * 1000 / 2 )) ]; then
  reg_ok "measured max ordinary MAC command duration ${measured_max_ms}ms sits far below the fixed ${MAC_BUDGET_S}s transition budget"
else
  reg_fail "measured max MAC command duration ${measured_max_ms}ms is not far below the budget — budget selection evidence broken"
fi

# --- hostile-lifecycle fixture ------------------------------------------------
USER_A="uatreg26a"
home_a="$(reg_setup_principal "$USER_A")" || { reg_fail "setup principal A failed"; reg_result; }
WS_A="$home_a/ws"
mkdir -p "$WS_A"
CREDFILE="/tmp/uat-h8-cred.$$"
reg_principal_credential "$USER_A" "$CREDFILE" || { reg_fail "credential create failed"; reg_result; }
# The credential is kept for the whole group: a Principal disable/enable
# cycle does not revoke credentials, so the recovery session create reuses
# the same one-shot token file (a second credential create could hit the
# per-Principal credential ceiling).

# --- hostile scenario: hung MAC command vs emergency disable -------------------
reg_info "arming the hostile shim on the backend command"
arm_shim

CREATE_OUT="/tmp/uat-h8-create.$$"
DISABLE_OUT="/tmp/uat-h8-disable.$$"
create_start="$(date +%s)"
HOLD_DEADLINE_BREACHED=0
(
  dh session create --system --token-file "$CREDFILE" --workspace "$WS_A" >"$CREATE_OUT" 2>&1
) &
CREATE_PID=$!
# The create parks inside the shimmed MAC command.
marker_seen=0
for _ in $(seq 1 50); do
  if shim_marker_present; then marker_seen=1; break; fi
  sleep 0.1
done
if [ "$marker_seen" = 1 ]; then
  # Confirm durability: a transient match must not count as the hostile
  # blocked state.
  sleep 1
  if shim_marker_present; then
    reg_ok "external MAC command really entered the hostile blocked state (shim process present)"
  else
    marker_seen=0
    reg_fail "the shim process vanished before the hold: the hostile state was not durable"
  fi
else
  reg_fail "the hostile shim never blocked a MAC one-shot (create may have failed before the backend command)"
  cat "$CREATE_OUT" >&2 || true
fi

# --- H8 queue closure: concurrent creates while the boundary is held ------------
# While the first create provably holds the lifecycle coordination inside the
# parked MAC command, further Session creates must be refused immediately
# (the stable lifecycle_busy / HTTP 503 class) without queueing on the
# boundary and without obtaining their own late MAC budget, so the emergency
# disable's delay stays bounded by the ONE in-flight transition budget
# regardless of the concurrent create count.
QUEUE_COUNT=4
QUEUE_OUT_PREFIX="/tmp/uat-h8-q.$$"
queue_pids=""
for i in $(seq 1 "$QUEUE_COUNT"); do
  (
    dh session create --system --token-file "$CREDFILE" --workspace "$WS_A" >"${QUEUE_OUT_PREFIX}-$i" 2>&1
  ) &
  queue_pids="$queue_pids $!"
done
queue_deadline=$(( $(date +%s) + 20 ))
queue_all_done=1
for pid in $queue_pids; do
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$(date +%s)" -gt "$queue_deadline" ]; then
      queue_all_done=0
      break 2
    fi
    sleep 0.2
  done
done
if [ "$queue_all_done" = 1 ]; then
  reg_ok "all $QUEUE_COUNT concurrent Session creates were refused while the first MAC command stayed parked (no queued wait for the boundary)"
else
  reg_fail "a concurrent Session create waited for the lifecycle boundary instead of being refused (queued-create liveness gap)"
  kill $queue_pids 2>/dev/null || true
fi
if shim_marker_present; then
  reg_ok "the first MAC command was still parked after every concurrent create was refused"
else
  reg_fail "the hostile parked MAC command vanished during the queue subcase"
fi
queue_class_ok=1
for i in $(seq 1 "$QUEUE_COUNT"); do
  if ! grep -q "lifecycle_busy" "${QUEUE_OUT_PREFIX}-$i" 2>/dev/null || ! grep -q "status 503" "${QUEUE_OUT_PREFIX}-$i" 2>/dev/null; then
    queue_class_ok=0
  fi
done
if [ "$queue_class_ok" = 1 ]; then
  reg_ok "every concurrent create answered the stable lifecycle_busy / HTTP 503 refusal"
else
  reg_fail "a concurrent create did not answer the lifecycle_busy / HTTP 503 refusal (it waited or failed differently)"
  for i in $(seq 1 "$QUEUE_COUNT"); do cat "${QUEUE_OUT_PREFIX}-$i" >&2 2>/dev/null || true; done
fi

# Emergency administrative disable while the create holds lifecycleMu inside
# the parked MAC command.
disable_start="$(date +%s)"
(
  dh principal set --system "$USER_A" enabled false >"$DISABLE_OUT" 2>&1
) &
DISABLE_PID=$!

# Service health during the hold (the expected failure mode is the failed
# create, not a dead service).
service_healthy "during the hostile MAC hold"

# Both must progress within the whole-transition bound.
create_done=0
disable_done=0
create_rc=0
disable_rc=0
deadline=$(( create_start + HOLD_BUDGET_S ))
while [ "$create_done" = 0 ] || [ "$disable_done" = 0 ]; do
  if [ "$create_done" = 0 ] && ! kill -0 "$CREATE_PID" 2>/dev/null; then
    create_done=1
    wait "$CREATE_PID" 2>/dev/null
    create_rc=$?
  fi
  if [ "$disable_done" = 0 ] && ! kill -0 "$DISABLE_PID" 2>/dev/null; then
    disable_done=1
    wait "$DISABLE_PID" 2>/dev/null
    disable_rc=$?
  fi
  if [ "$(date +%s)" -gt "$deadline" ]; then
    hold_deadline_diagnostics "the hostile MAC hold exceeded the whole-transition bound (${HOLD_BUDGET_S}s): the daemon waited without a bound"
    reg_fail "the hostile MAC hold exceeded the whole-transition bound (${HOLD_BUDGET_S}s): the daemon waited without a bound"
    kill "$CREATE_PID" "$DISABLE_PID" 2>/dev/null || true
    HOLD_DEADLINE_BREACHED=1
    break
  fi
  sleep 0.2
done
reg_info "hostile lifecycle wall-clock: $(( $(date +%s) - create_start ))s (bound: ${HOLD_BUDGET_S}s)"
reg_info "disable wall-clock from its launch: $(( $(date +%s) - disable_start ))s — the parked in-flight create's single ${MAC_BUDGET_S}s transition budget plus kill/reap slop, independent of the $QUEUE_COUNT refused concurrent creates"
if [ "$HOLD_DEADLINE_BREACHED" = 1 ]; then
  # Every later subcase would run against a still-held daemon and produce
  # garbage results: abort the group with the deadline evidence on record.
  reg_fail "the hostile hold never cleared: later subcases aborted (see deadline diagnostics above)"
  reg_result
fi

if [ "$create_rc" = 0 ]; then
  reg_fail "a Session create whose MAC command was terminated at the budget must fail, not succeed"
else
  if grep -q "mac_preparation_failed" "$CREATE_OUT" 2>/dev/null; then
    reg_ok "the parked Session create failed bounded with the documented mac_preparation_failed class"
  else
    reg_ok "the parked Session create failed bounded (nonzero exit)"
  fi
fi
if [ "$disable_rc" = 0 ]; then
  reg_ok "administrative disable reached its authoritative transition within the proven bound"
else
  reg_fail "administrative disable failed during the hostile hold (rc=$disable_rc)"
  cat "$DISABLE_OUT" >&2 || true
fi

# The hung command process is gone after the bound (no MAC child behind).
shim_gone=1
for _ in $(seq 1 50); do
  if shim_marker_present; then shim_gone=0; sleep 0.1; else shim_gone=1; break; fi
done
if [ "$shim_gone" = 1 ]; then
  reg_ok "the hung MAC command process is gone after the bound (killed and reaped, no child left behind)"
else
  reg_fail "the hung MAC command process survived the budget: a MAC child was left behind"
fi

# Restore the backend binary BEFORE any post-hold check that would itself
# invoke it: the fail-closed MAC inventory below uses the real frontend
# (restoring the binary does not change any MAC state the failed create
# left behind).
restore_hostile
if [ -f "$(backend_command_path)" ]; then
  reg_ok "the backend command binary was restored"
else
  reg_fail "the backend command binary was not restored"
fi

# No Session was committed by the parked create nor by any refused
# concurrent create (all of them request the same workspace).
if dh session list --system --json 2>/dev/null | grep -qF "$WS_A"; then
  reg_fail "the parked or a refused concurrent Session create committed a Session"
else
  reg_ok "the parked create and every refused concurrent create committed no Session"
fi

# The disable is durable (list JSON: {"ok":...,"principals":[...]}).
if dh principal list --system --json 2>/dev/null | python3 -c "
import json, sys
doc = json.load(sys.stdin)
for p in doc.get('principals', []):
    if p.get('username') == '$USER_A':
        sys.exit(0 if p.get('enabled') is False else 1)
sys.exit(1)
" 2>/dev/null; then
  reg_ok "the disable target is durably disabled"
else
  reg_fail "the disable target is not durably disabled"
fi

# MAC ownership/backend state is fail closed.
if [ "$BACKEND" = "apparmor" ]; then
  FRAGMENT="/var/lib/docker-helper/apparmor/managed-boundaries"
  if [ -f "$FRAGMENT" ] && grep -qF "$WS_A" "$FRAGMENT"; then
    reg_fail "the managed fragment recorded a boundary although the reload never succeeded (false coverage)"
  else
    reg_ok "AppArmor managed fragment carries no false boundary after the failed create and the refused concurrent creates"
  fi
else
  if semanage fcontext -l -C -n 2>/dev/null | grep -qF "$WS_A"; then
    reg_fail "a persistent fcontext rule exists although the transition never succeeded"
  else
    reg_ok "SELinux fcontext inventory carries no false coverage after the failed create and the refused concurrent creates"
  fi
fi

# --- prove recovery -------------------------------------------------------------
service_healthy "after restoring the backend command"

# A subsequent normal MAC transition works after the hostile condition is
# removed (the kept one-shot credential token file is reused; a disable/
# enable cycle does not revoke credentials).
dh principal set --system "$USER_A" enabled true >/dev/null 2>&1 || true
if reg_session "$CREDFILE" "$WS_A"; then
  reg_ok "a subsequent normal MAC transition (session create) succeeds after the hostile condition is removed"
  RECOVERY_SESSION_ID="$REG_SESSION_ID"
else
  reg_fail "normal session create failed after the hostile condition was removed"
  RECOVERY_SESSION_ID=""
fi

# --- shutdown bound -------------------------------------------------------------
reg_info "re-arming the hostile shim for the shutdown proof"
# A FRESH workspace: the recovery create gave its workspace real coverage, so
# that workspace's create is idempotent at the backend and would never reach
# the backend command. Only a NEW boundary reaches the parser/semanage path.
WS_STOP="$home_a/ws-stop-$$"
mkdir -p "$WS_STOP"
arm_shim
(
  dh session create --system --token-file "$CREDFILE" --workspace "$WS_STOP" >/dev/null 2>&1
) &
CREATE_PID2=$!
for _ in $(seq 1 50); do
  if shim_marker_present; then break; fi
  sleep 0.1
done

stop_start="$(date +%s)"
systemctl stop docker-helper.service >/dev/null 2>&1
stop_rc=$?
stop_elapsed=$(( $(date +%s) - stop_start ))
wait "$CREATE_PID2" 2>/dev/null || true
if [ "$stop_rc" = 0 ] && ! systemctl is-active --quiet docker-helper.service 2>/dev/null; then
  if [ "$stop_elapsed" -le 60 ]; then
    reg_ok "the packaged service reached stopped state in ${stop_elapsed}s despite the hostile MAC command (documented shutdown wall-clock bound)"
  else
    reg_fail "service stop took ${stop_elapsed}s, beyond the documented shutdown bound"
  fi
else
  reg_fail "systemctl stop failed (rc=$stop_rc) with a hostile MAC command in flight"
fi
if shim_marker_present; then
  reg_fail "an external MAC child survived the stopped service (not reaped by the shutdown path)"
else
  reg_ok "no external MAC child survived the stopped service"
fi

restore_hostile
if [ -f "$(backend_command_path)" ]; then
  reg_ok "the backend command binary was restored after the shutdown proof"
else
  reg_fail "the backend command binary was not restored after the shutdown proof"
fi
systemctl start docker-helper.service >/dev/null 2>&1
# Type=exec reports active at exec start, before the daemon binds its socket
# and finishes startup reconciliation: readiness is the /health answer, not
# the unit state.
health_ready=0
for _ in $(seq 1 30); do
  if curl --silent --fail --max-time 2 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1; then
    health_ready=1
    break
  fi
  sleep 1
done
if [ "$health_ready" = 1 ]; then
  reg_ok "the service returned healthy after the shutdown proof and restart"
else
  reg_fail "the service did not become healthy within the bounded wait after the restart"
fi
service_healthy "after the shutdown proof and restart"

# --- cleanup ---------------------------------------------------------------------
if [ -n "${RECOVERY_SESSION_ID:-}" ]; then
  dh session delete --system --id "$RECOVERY_SESSION_ID" >/dev/null 2>&1 || true
fi
dh principal delete --system "$USER_A" >/dev/null 2>&1 || true
rm -rf "$BIGTREE" "$WS_A" "$WS_STOP" "$CREATE_OUT" "$DISABLE_OUT" "$CREDFILE" "$QUEUE_OUT_PREFIX"-* 2>/dev/null || true

reg_result
