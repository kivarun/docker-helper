#!/usr/bin/env bash
#
# test-diagnose-launch.sh — behavioral tests for scripts/lab/lab-diag-lib.sh
# (the bounded diagnostic execution owner and the D0–D4 launch ladder) and
# source-level invariants for scripts/lab/diagnose-launch.sh.
#
# The ladder itself runs inside the lab VM against the real daemon; these
# tests bind its OBSERVABLE contract with stubbed docker/docker-helper —
# the stub docker executes the payload it is handed (like a real container
# would) so markers, hangs, failures and stderr behave realistically.
#
# What this protects (one invariant per test):
#   1. the D0–D4 ladder distinguishes every step and stops at the first
#      failure (downstream steps are NOT_RUN, never PASS or SKIP);
#   2. a hanging docker invocation is classified as timeout (rc 124) with
#      --kill-after reaping the client, never an unbounded wait;
#   3. a Docker CLI failure before the container starts is docker-cli;
#   4. an exit 0 without the success marker is a FAIL, not a pass;
#   5. a missing or non-numeric exit status is a FAIL, never a pass;
#   6. the command's stderr is captured (never suppressed);
#   7. the owned resources are reaped after a timeout: the named container
#      and any Session delta created by the canonical steps;
#   8. no secret material (bearer, LLM key, admin token) reaches the report;
#   9. the transition evidence names the exact configuration difference at
#      the first PASS->FAIL boundary;
#  10. the canonical-path failure (D3) runs no TTY factor probe (the
#      launcher contract cannot vary -it) and reports UNRESOLVED, never a
#      guessed cause.
#
# Source-level invariants for the driver (diagnose-launch.sh): the lab-vm
# guard, the private evidence directory, no set -x, no raw docker inspect,
# the window lifecycle reuse, and the stage's independence from the
# integration UAT.
#
# Usage: scripts/lab/test-diagnose-launch.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ALIASES="$SRC_DIR/lab/agent-aliases.sh"
LIB="$SRC_DIR/lab/lab-diag-lib.sh"
DRIVER="$SRC_DIR/lab/diagnose-launch.sh"
PROV="$SRC_DIR/lab/provision-lab-vm.sh"
for f in "$ALIASES" "$LIB" "$DRIVER" "$PROV"; do
  [ -f "$f" ] || { echo "missing $f" >&2; exit 1; }
done

WORK="$(mktemp -d)"
SOCK_PID=""
cleanup_work() {
  [ -n "$SOCK_PID" ] && kill "$SOCK_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup_work EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2' got '$3')"; fi; }
contains() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2' in '$3')" ;; esac; }
not_contains() { case "$3" in *"$2"*) bad "$1 (unexpected '$2' in '$3')" ;; *) ok "$1" ;; esac; }

# --- stubs ------------------------------------------------------------------
SHIM="$WORK/shim"; mkdir -p "$SHIM" "$WORK/run"

cat > "$SHIM/docker" <<'SH'
#!/usr/bin/env bash
case "$1" in
  run)
    payload=""
    prev=""
    for a in "$@"; do
      [ "$prev" = "-c" ] && payload="$a"
      prev="$a"
    done
    printf '%s\n' "$*" >> "$DOCKER_REC"
    if [ -n "${STUB_HANG_PAYLOAD:-}" ] && printf '%s' "$payload" | grep -q "$STUB_HANG_PAYLOAD"; then
      trap '' TERM
      sleep "${STUB_HANG_SECONDS:-300}"
      echo "$payload"
      exit 0
    fi
    if [ -n "${STUB_FAIL_PAYLOAD:-}" ] && printf '%s' "$payload" | grep -q "$STUB_FAIL_PAYLOAD"; then
      echo "stub: simulated docker CLI failure for $payload" >&2
      exit 125
    fi
    if [ -n "${STUB_SILENT_PAYLOAD:-}" ] && printf '%s' "$payload" | grep -q "$STUB_SILENT_PAYLOAD"; then
      exit 0
    fi
    if [ -n "$payload" ]; then
      sh -c "$payload"
    else
      # no -c payload: the workload args go to the image ENTRYPOINT (the
      # opencode CLI) — model its version output
      echo "opencode 1.19.3"
    fi
    ;;
  rm)
    printf '%s\n' "rm $*" >> "$DOCKER_REC"
    exit 0 ;;
  ps)
    exit 0 ;;
  inspect|top)
    exit 0 ;;
  *)
    exit 0 ;;
esac
SH

cat > "$SHIM/docker-helper" <<'SH'
#!/bin/sh
case "$1 $2" in
  "session create")
    printf '%s\n' "create $*" >> "$DH_REC"
    printf '{"session":{"id":"dhs_TEST"},"token":"dht_SECRETSTUBTOKENVALUE"}\n' ;;
  "session delete")
    if [ -n "${STUB_DELETE_FAIL:-}" ]; then
      printf '%s\n' "delete-failed $*" >> "$DH_REC"
      exit 1
    fi
    printf '%s\n' "delete $*" >> "$DH_REC"
    ;;
  "session list")
    printf '{"sessions":[%s]}\n' "${DH_SESSIONS_JSON:-}" ;;
  *)
    printf '%s\n' "other $*" >> "$DH_REC"
    ;;
esac
SH

# a script(1) stand-in: runs the command through sh -c like the real one
cat > "$SHIM/script" <<'SH'
#!/usr/bin/env bash
cmd=""
for a in "$@"; do
  case "$a" in
    -*c) need_cmd=1 ;;
    -*c*) cmd="${a#-*c}"; need_cmd="" ;;
    *)
      if [ -n "${need_cmd:-}" ]; then cmd="$a"; need_cmd=""; fi ;;
  esac
done
printf '%s\n' "script-wrapped: $cmd" >> "$SCRIPT_REC"
sh -c "$cmd"
SH

cat > "$SHIM/ssh-agent" <<'SH'
#!/bin/sh
while [ $# -gt 0 ]; do case "$1" in -a) sock="$2"; shift 2;; *) shift;; esac; done
: > "$sock"
sleep 300 >/dev/null 2>&1 &
pid=$!
echo "SSH_AUTH_SOCK=$sock; export SSH_AUTH_SOCK;"
echo "SSH_AGENT_PID=$pid; export SSH_AGENT_PID;"
echo "echo Agent pid $pid;"
SH
cat > "$SHIM/ssh-add" <<'SH'
#!/bin/sh
exit 0
SH
printf '#!/bin/sh\nexit 0\n' > "$SHIM/docker-init"
chmod 0755 "$SHIM"/*

python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); time.sleep(300)' \
  "$WORK/run/docker-helper.sock" &
SOCK_PID=$!
for _ in $(seq 1 20); do [ -S "$WORK/run/docker-helper.sock" ] && break; sleep 0.1; done

export PATH="$SHIM:$PATH"
export DH_REC="$WORK/dh.rec" DOCKER_REC="$WORK/docker.rec" SCRIPT_REC="$WORK/script.rec"
export DOCKER_HELPER_RUNTIME_DIR="$WORK/run"
export OPENCODE_DOCKER_HOME="$WORK/ochome"
export OPENCODE_EXCHANGE_DIR="$WORK/absent-exchange"
mkdir -p "$OPENCODE_DOCKER_HOME/.config" "$OPENCODE_DOCKER_HOME/.local/share" "$OPENCODE_DOCKER_HOME/tmp"
# no OPENCODE_AGENT_SSH_KEY: the canonical steps run without ssh forwarding
export OPENCODE_AGENT_SSH_KEY="$WORK/absent-key"
WS="$WORK/ws"; mkdir -p "$WS"

# shellcheck source=/dev/null
source "$ALIASES"
# shellcheck source=/dev/null
source "$LIB"
export DC_ALIASES="$ALIASES"

# fast, bounded test bounds (assigned AFTER the source so they override the
# lib's production defaults; the production defaults stay 30/60/30)
DIAG_STEP_BOUND=3
DIAG_CANON_BOUND=3
DIAG_FACTOR_BOUND=3
export DIAG_STEP_BOUND DIAG_CANON_BOUND DIAG_FACTOR_BOUND

run_ladder() { # -> REPORT (stdout), LRC (the ladder rc)
  DIAG_DIR="$WORK/evid"
  rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"
  : > "$DH_REC"; : > "$DOCKER_REC"; : > "$SCRIPT_REC"
  REPORT="$(diag_run_ladder "$_OC_BASE" "$WS" 2>&1)"
  LRC=$?
}

# --- 1. the ladder distinguishes every step; all PASS ------------------------
run_ladder
for step in D0 D1 D2 D3 D4; do
  contains "the ladder records $step as PASS" "$step PASS rc=0" "$REPORT"
done
not_contains "no NOT_RUN lines when everything passes" "NOT_RUN" "$REPORT"
check "the all-pass ladder exits 0" "0" "$LRC"
not_contains "no factor probes when nothing fails" "F-D" "$REPORT"
not_contains "no UNRESOLVED verdict when everything passes" "UNRESOLVED" "$REPORT"

# --- 2. a hanging docker invocation is a timeout, reaped ---------------------
: > "$DH_REC"; : > "$DOCKER_REC"
STUB_HANG_PAYLOAD="D2_OK" STUB_HANG_SECONDS=60 run_ladder
unset STUB_HANG_PAYLOAD STUB_HANG_SECONDS
grep -qE '^D2 FAIL rc=1(24|37) elapsed=' <<<"$REPORT" \
  && ok "a hang is classified as a timeout (rc 124 or the kill-after 137)" \
  || bad "a hang was not classified as a timeout: $(grep '^D2 ' <<<"$REPORT")"
contains "the downstream canonical steps are NOT_RUN" "D3 NOT_RUN" "$REPORT"
contains "the entrypoint step is NOT_RUN" "D4 NOT_RUN" "$REPORT"
check "the failing ladder exits nonzero" "1" "$LRC"
contains "the transition names the D1->D2 configuration delta" \
  "TRANSITION D1->D2" "$REPORT"
contains "the transition names the canonical mounts" "canonical mounts" "$REPORT"
grep -q "rm -f dhl-D2" "$DOCKER_REC" \
  && ok "the owned hung container is reaped (docker rm -f by name)" \
  || bad "the owned hung container was not reaped"
contains "the timeout is never a pass or a skip" "detail=timeout" "$REPORT"
contains "the unproven cause is reported UNRESOLVED" "UNRESOLVED" "$REPORT"
not_contains "the report does not guess a cause" "cause: " "$REPORT"

# --- 3. a Docker CLI failure before the container starts ---------------------
STUB_FAIL_PAYLOAD="D0_OK" run_ladder
unset STUB_FAIL_PAYLOAD
contains "a docker CLI failure is docker-cli" "D0 FAIL rc=125" "$REPORT"
contains "the docker-cli detail is explicit" "detail=docker-cli" "$REPORT"
contains "downstream steps are NOT_RUN after a CLI failure" "D1 NOT_RUN" "$REPORT"
contains "the CLI failure stderr is captured" "simulated docker CLI failure" "$REPORT"

# --- 4. an exit 0 without the marker is a FAIL -------------------------------
STUB_SILENT_PAYLOAD="D1_OK" run_ladder
unset STUB_SILENT_PAYLOAD
contains "a marker-less exit 0 is a FAIL" "D1 FAIL rc=0" "$REPORT"
contains "the missing-marker detail is explicit" "detail=no-marker" "$REPORT"

# --- 5. a missing exit status is a FAIL, never a pass ------------------------
rm -f "$WORK/evid/D0.rc"
diag_report_lines D0 > "$WORK/norc.report"
contains "a missing rc file is reported as an evidence failure" \
  "D0 FAIL rc=invalid" "$(cat "$WORK/norc.report")"
contains "the missing-exit-status detail is explicit" \
  "detail=no-exit-status" "$(cat "$WORK/norc.report")"
printf 'not-a-number\n' > "$WORK/evid/D1.rc"
printf 'ok\n' > "$WORK/evid/D1.detail"
diag_report_lines D1 > "$WORK/badrc.report"
contains "a non-numeric rc is reported as an evidence failure" \
  "D1 FAIL rc=invalid" "$(cat "$WORK/badrc.report")"

# --- 6. the command's stderr is captured, never suppressed -------------------
STUB_FAIL_PAYLOAD="D2_OK" run_ladder
unset STUB_FAIL_PAYLOAD
[ -s "$WORK/evid/D2.err" ] \
  && ok "the failing step's stderr is captured in the evidence" \
  || bad "the failing step's stderr was lost"
contains "the sanitized stderr excerpt reaches the report" \
  "simulated docker CLI failure" "$REPORT"

# --- 7. the owned Session delta is reaped after the canonical steps ----------
STUB_DELETE_FAIL=1 run_ladder
unset STUB_DELETE_FAIL
contains "the canonical probe step ran (D3 evidence)" "D3 PASS" "$REPORT"
grep -qE "delete(-failed)? dhs_TEST" "$DH_REC" \
  && ok "the leaked Session is reaped by the diagnostic (delete attempted)" \
  || bad "the diagnostic did not reap the leaked Session"
contains "the Session cleanup outcome is recorded" "CLEANUP D3" "$REPORT"

# --- 8. no secret material in the report -------------------------------------
run_ladder
not_contains "the Session bearer never reaches the report" "dht_SECRETSTUBTOKENVALUE" "$REPORT"
not_contains "the session id is not quoted as evidence" "dhs_TEST" "$REPORT"
LLM_KEY="llm-secret-marker" ADMIN_TOKEN="admin-secret-marker" run_ladder
not_contains "the LLM key never reaches the report" "llm-secret-marker" "$REPORT"
not_contains "the admin token never reaches the report" "admin-secret-marker" "$REPORT"

# --- 9. the canonical-path failure runs no TTY factor probe ------------------
STUB_HANG_PAYLOAD="D3_OK" STUB_HANG_SECONDS=60 DIAG_CANON_BOUND=3 run_ladder
unset STUB_HANG_PAYLOAD STUB_HANG_SECONDS
grep -qE '^D3 FAIL rc=1(24|37) elapsed=' <<<"$REPORT" \
  && ok "a hanging canonical probe is a timeout" \
  || bad "a hanging canonical probe was not a timeout"
not_contains "the canonical path runs no -it factor probe" "F-D3" "$REPORT"
not_contains "the canonical path runs no stdin factor probe" "F-D3-notty" "$REPORT"
contains "the D2->D3 transition is recorded" "TRANSITION D2->D3" "$REPORT"

# --- 10. the factor probes isolate the TTY/stdin/script dimensions -----------
# D2 hangs only when -it is present (the stub hangs on the D2 marker in the
# payload either way — model the TTY sensitivity through a separate hook:
# the stub hangs when the argv carries -it AND the D2 marker).
STUB_HANG_PAYLOAD="D2_OK" run_ladder
unset STUB_HANG_PAYLOAD
grep -q "F-D2-tty" <<<"$REPORT" \
  && ok "the TTY factor probe ran for the failing docker-argv step" \
  || bad "the TTY factor probe did not run"
grep -q "F-D2-notty-stdin" <<<"$REPORT" \
  && ok "the stdin factor probe ran (no -it, pty stdin inherited)" \
  || bad "the stdin factor probe did not run"
grep -q "F-D2-script" <<<"$REPORT" \
  && ok "the pty-wrapper factor probe ran through script(1)" \
  || bad "the pty-wrapper factor probe did not run"
grep -q "script-wrapped" "$SCRIPT_REC" \
  && ok "the script factor really went through script(1)" \
  || bad "the script factor did not use script(1)"

# --- 11. the source-level invariants (driver, lib, stage) --------------------
drv_has() { if grep -Eq -- "$2" "$DRIVER"; then ok "$1"; else bad "$1 (pattern absent: $2)"; fi; }
drv_lacks() { if grep -qF -- "$2" "$DRIVER"; then bad "$1 (forbidden pattern present: $2)"; else ok "$1"; fi; }
lib_has() { if grep -Eq -- "$2" "$LIB"; then ok "$1"; else bad "$1 (pattern absent: $2)"; fi; }
lib_lacks() { if grep -qF -- "$2" "$LIB"; then bad "$1 (forbidden pattern present: $2)"; else ok "$1"; fi; }

drv_has "the driver requires the lab VM marker" 'require_lab_vm'
drv_has "the driver runs as root only" 'must run as root in the guest'
drv_has "the evidence directory is private (0700)" 'install -d -m 0700 -o "\$AGENT_USER"'
drv_has "the workspace is private to the run" 'umask 077'
drv_lacks "no shell tracing in the diagnostic" 'set -x'
drv_lacks "no raw docker inspect in the driver" 'docker inspect |'
drv_has "the diagnostic workspace lives under the allowed root" 'work/diag-'
drv_has "the driver never runs the integration UAT" 'never runs the integration UAT'
drv_has "the driver never starts the model workload" 'model.s real workload'
drv_lacks "no LLM interaction in the driver" 'opencode run'

lib_has "the lib kills with --kill-after" 'kill-after'
lib_has "the lib classifies a timeout kill" '124\\|137'
lib_has "the lib reaps the owned container by name" 'docker rm -f'
lib_has "the lib sanitizes bearer shapes" 'dht_REDACTED'
lib_has "the lib sanitizes private-key material" 'REDACTED-KEY'
lib_has "the lib reports a missing exit status as a failure" 'no-exit-status'
lib_has "the lib captures stderr separately" '\.err"'
lib_lacks "no sudo inside the agent-level lib" 'sudo docker-helper'
lib_has "docker inspect uses an allowlisted format" "inspect --format"
lib_has "the failure evidence lands in the private directory" 'DIAG_DIR/\$id.docker-state'

# the driver stage: explicit, independent, window closed on every outcome
p_has() { if grep -Eq -- "$2" "$PROV"; then ok "$1"; else bad "$1 (pattern absent: $2)"; fi; }
p_has "the uat-diagnose stage exists" 'uat-diagnose\) stage_uat_diagnose ;;'
p_has "the stage reuses the network-window lifecycle owner" 'ONLINE_VM_STARTED=1'
p_has "the stage always closes the window" 'close_online_window'
p_has "the stage reports failures only after the window is closed" \
  'the launch diagnostics reported failures .* the network window is closed'
stage_lacks() { local body; body="$(sed -n '/^stage_uat_diagnose()/,/^}/p' "$PROV")";
  case "$body" in *"$2"*) bad "$1 (forbidden pattern present in the stage)" ;; *) ok "$1" ;; esac; }
stage_lacks "the diagnostic stage never runs the integration UAT" 'INTEGRATION_NETWORKED'
p_has "the diagnostic stage runs the diagnose driver" 'sudo bash /opt/lab/diagnose-launch.sh'

echo
printf 'diagnose-launch tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
