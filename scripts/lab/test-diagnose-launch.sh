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
#      guessed cause;
#  11. (UAT-8k) the strict D3 factor matrix isolates the docker flags, the
#      nested pty wrapper and the stdin policy under ONE composition owner
#      and ONE payload; a timeout carries the bounded hang-stage observation
#      of the owned container; and only controlled single-variable
#      comparisons may name a cause (the multi-variable notty probe stays
#      preliminary OBSERVED evidence);
#  12. (UAT-8l) a D3 probe's docker result is a usable PASS only when its
#      mandatory cleanup is confirmed (clean/reaped): an unconfirmed cleanup
#      is a separate FAIL that voids the probe as diagnosis evidence and
#      stops all further new matrix probes, and a -t/-i attribution must be
#      consistent with the combined -it probe (a contradiction stays
#      UNRESOLVED);
#  13. (UAT-8m) the no-docker script(1) smoke probe and the direct no-flag
#      probe isolate the wrapper from the docker execution under it (the
#      wrapper hangs / docker hangs under it / docker hangs directly
#      verdicts, contradictions stay UNRESOLVED); the fixed phase markers
#      are secret-free private evidence; and a recorded docker invocation
#      without a cidfile stays unknown, never "no create happened".
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

# Deterministic stdin: the direct (unwrapped) probes inherit THIS shell's
# stdin, and the UAT-8m hang hooks distinguish the script(1) pty (a tty)
# from the direct probes. A terminal-attached invocation must not change
# the outcomes, so the suite always runs with a non-tty stdin.
exec </dev/null

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
# A STRICT docker stand-in that models a real daemon boundary:
#   * it refuses unknown subcommands (a wrong argv cannot hide);
#   * it refuses to remove a container it did not start itself;
#   * `.Image` of a container is the LOCAL IMAGE ID, never the OCI reference;
#   * `docker image inspect` resolves the pinned reference to an image ID;
#   * `--cidfile` records the immutable container ID; a run that fails
#     before creating the container writes no cidfile;
#   * `-it` without an available TTY fails like real docker;
#   * removal is by container ID or name, verified against the registry.
: "${CIDS:?CIDS must be exported by the harness}"
: "${CIDMAP:?CIDMAP must be exported by the harness}"
OWN_IMAGE_ID="${OWN_IMAGE_ID:-sha256:1111111111111111111111111111111111111111111111111111111111111111}"
FOREIGN_IMAGE_ID="sha256:2222222222222222222222222222222222222222222222222222222222222222"
record_cid() { # name id
  printf '%s %s\n' "$1" "$2" >> "$CIDMAP"
}
lookup_cid() { # name -> id
  awk -v n="$1" '$1 == n { print $2; exit }' "$CIDMAP" 2>/dev/null
}
is_known_container() { # id-or-name
  if grep -qxF "$1" "$CIDS" 2>/dev/null; then return 0; fi
  [ -n "$(lookup_cid "$1")" ] && return 0
  awk '{print $2}' "$CIDMAP" 2>/dev/null | grep -qxF "$1"
}
case "$1" in
  run)
    payload=""; cname=""; cidfile_arg=""; image_arg=""; opt_i=""; opt_t=""; prev=""
    for a in "$@"; do
      [ "$prev" = "-c" ] && payload="$a"
      [ "$prev" = "--name" ] && cname="$a"
      [ "$prev" = "--cidfile" ] && cidfile_arg="$a"
      [ "$prev" = "--entrypoint" ] && image_seen=1
      case "$a" in
        -it|--it) opt_i=1; opt_t=1 ;;
        -i) opt_i=1 ;;
        -t) opt_t=1 ;;
      esac
      case "$prev" in
        --entrypoint) : ;;
        *) case "$a" in "$_OC_BASE"|*"@sha256:"*) image_arg="$a" ;; esac ;;
      esac
      prev="$a"
    done
    [ -z "$image_arg" ] && image_arg="$_OC_BASE"
    si=notty; [ -t 0 ] && si=pty
    printf '%s\n' "$* stdin=$si" >> "$DOCKER_REC"
    if [ -n "${STUB_STDERR_SECRET:-}" ]; then
      # an arbitrary value that reached Docker's stderr (a daemon error
      # string is operator-uncontrolled text)
      echo "docker: mock daemon error: $STUB_STDERR_SECRET" >&2
    fi
    # real docker refuses a TTY request without a terminal (-t needs the
    # client's stdin to be a TTY, with or without -i)
    if [ -n "$opt_t" ] && ! [ -t 0 ]; then
      echo "the input device is not a TTY" >&2
      exit 125
    fi
    if [ -n "${STUB_HANG_BEFORE_CREATE:-}" ]; then
      # the CLI hung before it ever created the container: no cidfile, no
      # registry entry — the hang-stage observation must say no-cidfile
      trap '' TERM
      sleep "${STUB_HANG_SECONDS:-300}"
      exit 0
    fi
    if [ -n "$cidfile_arg" ] && [ -n "$cname" ]; then
      # a fixed-length 64-hex container id, unique per run invocation
      cid="deadbeef$(printf '%016x' $((RANDOM * 32768 + RANDOM)))0000000000000000000000000000000000000000"
      printf '%s' "$cid" > "$cidfile_arg" 2>/dev/null
      record_cid "$cname" "$cid"
      printf '%s\n' "$cname" >> "$CIDS"
      printf '%s\n' "$cid" >> "$CIDS"
    fi
    if [ -n "${STUB_HANG_PAYLOAD:-}" ] && printf '%s' "$payload" | grep -q "$STUB_HANG_PAYLOAD"; then
      trap '' TERM
      sleep "${STUB_HANG_SECONDS:-300}"
      echo "$payload"
      exit 0
    fi
    if [ -n "${STUB_HANG_WHEN_TTY:-}" ] && [ -n "$opt_t" ] \
       && printf '%s' "$payload" | grep -q "D3_OK"; then
      trap '' TERM
      sleep "${STUB_HANG_SECONDS:-300}"
      echo "$payload"
      exit 0
    fi
    if [ -n "${STUB_HANG_CANON:-}" ] \
       && printf '%s\n' "$*" | grep -qF -- '--name dhl-D3-'; then
      # hang exactly the CANONICAL D3 launch (its name is dhl-D3-<runid>),
      # never the F-D3-* factor or matrix probes (UAT-8l)
      trap '' TERM
      sleep "${STUB_HANG_SECONDS:-300}"
      echo "$payload"
      exit 0
    fi
    if [ -n "${STUB_HANG_WHEN_PTY_STDIN:-}" ] && [ -t 0 ] \
       && printf '%s' "$payload" | grep -q "D3_OK"; then
      # hang exactly the pty-stdin docker runs — the script(1)-wrapped
      # probes, whose wrapper hands the client a tty (the direct probes in
      # this suite inherit a non-tty stdin): the UAT-8m rule-B driver
      trap '' TERM
      sleep "${STUB_HANG_SECONDS:-300}"
      echo "$payload"
      exit 0
    fi
    if [ -n "${STUB_HANG_NOFLAGS_NOTTY:-}" ] && ! [ -t 0 ] \
       && [ -z "$opt_i" ] && [ -z "$opt_t" ] \
       && printf '%s' "$payload" | grep -q "D3_OK"; then
      # hang exactly the no-flag, non-tty docker runs (the direct-none
      # probe and the legacy notty probe): the UAT-8m rule-C driver
      trap '' TERM
      sleep "${STUB_HANG_SECONDS:-300}"
      echo "$payload"
      exit 0
    fi
    if [ -n "${STUB_HANG_DFLAG:-}" ]; then
      # hang exactly for the docker runs carrying one of THESE flag tokens
      # (a space-separated list): the strict single-variable matrix driver
      # for the UAT-8k tests
      # shellcheck disable=SC2086  # the token list is word-split by design
      matched=""
      for want in $STUB_HANG_DFLAG; do
        for a in "$@"; do
          [ "$a" = "$want" ] && { matched=1; break; }
        done
        [ -n "$matched" ] && break
      done
      if [ -n "$matched" ]; then
        trap '' TERM
        sleep "${STUB_HANG_SECONDS:-300}"
        echo "$payload"
        exit 0
      fi
    fi
    if [ -n "${STUB_HANG_WHEN_AGENT:-}" ] && printf '%s\n' "$*" | grep -q '/ssh-agent' \
       && printf '%s' "$payload" | grep -q "D3_OK"; then
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
    # --rm: the container exited and was auto-removed; the registry forgets
    # it (its cidfile keeps the ID, which real docker also leaves behind).
    # STUB_KEEP_NAME_PREFIX keeps a matching container in the registry, so
    # the diagnostic's own cleanup must remove it (UAT-8l)
    keep=0
    if [ -n "${STUB_KEEP_NAME_PREFIX:-}" ]; then
      case "$cname" in "$STUB_KEEP_NAME_PREFIX"*) keep=1 ;; esac
    fi
    if [ "$keep" = 0 ]; then
      grep -vxF "$cname" "$CIDS" > "$CIDS.next" 2>/dev/null; mv "$CIDS.next" "$CIDS"
      grep -vE "(^| )$cname( |$)" "$CIDMAP" > "$CIDMAP.next" 2>/dev/null; mv "$CIDMAP.next" "$CIDMAP"
      grep -vxF "$cid" "$CIDS" > "$CIDS.next" 2>/dev/null; mv "$CIDS.next" "$CIDS"
      grep -vE "(^| )$cid( |$)" "$CIDMAP" > "$CIDMAP.next" 2>/dev/null; mv "$CIDMAP.next" "$CIDMAP"
    fi
    ;;
  rm)
    shift
    [ "${1:-}" = "-f" ] && shift
    for name in "$@"; do
      if [ -n "${STUB_RM_FAIL:-}" ] && printf '%s' "$name" | grep -q "^dhl-\|^deadbeef"; then
        echo "stub: simulated rm failure for $name" >&2
        exit 1
      fi
      if is_known_container "$name"; then
        printf '%s\n' "rm $name" >> "$DOCKER_REC"
        grep -vxF "$name" "$CIDS" > "$CIDS.next" 2>/dev/null; mv "$CIDS.next" "$CIDS"
        if [ -f "$CIDMAP" ]; then
          grep -vE "(^| )$name( |$)" "$CIDMAP" > "$CIDMAP.next" 2>/dev/null; mv "$CIDMAP.next" "$CIDMAP"
        fi
      else
        echo "stub: refusing to remove a container this daemon did not start: $name" >&2
        exit 1
      fi
    done
    exit 0 ;;
  ps)
    if [ -n "${STUB_HANG_PS:-}" ]; then
      trap '' TERM
      sleep "${STUB_HANG_SECONDS:-300}"
      exit 0
    fi
    printf '%s\n' "ps $*" >> "$DOCKER_REC"
    if printf '%s\n' "$*" | grep -q 'ancestor='; then
      [ -n "${STUB_FOREIGN_CIDS:-}" ] && printf '%s\n' $STUB_FOREIGN_CIDS
      exit 0
    fi
    if printf '%s\n' "$*" | grep -q -- '--filter id='; then
      # the decisive existence check for one exact FULL container ID
      c="$(printf '%s\n' "$*" | sed -n 's/.*--filter id=//p')"
      grep -qxF "$c" "$CIDS" 2>/dev/null && printf '%s\n' "$c"
      exit 0
    fi
    if printf '%s\n' "$*" | grep -q 'name=^/'; then
      # the decisive existence check for one exact name
      n="$(printf '%s\n' "$*" | sed -n "s/.*name=^\/\\([^$]*\\)\\\$.*/\\1/p")"
      [ -n "$(lookup_cid "$n")" ] && printf '%s\n' "$(lookup_cid "$n")"
      # the foreign fixtures also exist under their own names
      if [ -n "$n" ]; then
        case " ${STUB_FOREIGN_CIDS:-} " in
          *" $n "*) printf '%s\n' "$n" ;;
        esac
      fi
      exit 0
    fi
    exit 0 ;;
  image)
    # docker image inspect --format '{{.Id}}' REF: the reference resolves to
    # the LOCAL image ID (the pinned reference -> OWN, anything else ->
    # FOREIGN, which is a different image by definition)
    if printf '%s\n' "$*" | grep -qF "${DIAG_IMAGE:-}"; then
      printf '%s\n' "$OWN_IMAGE_ID"
    else
      printf '%s\n' "$FOREIGN_IMAGE_ID"
    fi
    exit 0 ;;
  inspect)
    if [ -n "${STUB_HANG_INSPECT:-}" ]; then
      trap '' TERM
      sleep "${STUB_HANG_SECONDS:-300}"
      exit 0
    fi
    if [ -n "${STUB_INSPECT_ERROR:-}" ]; then
      # a daemon-side inspect error: the query itself failed, which proves
      # nothing about the container's existence
      echo "stub: simulated docker inspect error" >&2
      exit 1
    fi
    target="${*: -1}"
    # real docker fails the inspect for a container that does not exist
    cid="$(lookup_cid "$target")"
    if [ -z "$cid" ] && ! grep -qxF "$target" "$CIDS" 2>/dev/null; then
      echo "stub: no such container: $target" >&2
      exit 1
    fi
    [ -n "$cid" ] || cid="$target"
    if [ -n "${STUB_NAME_SWAP:-}" ]; then
      # the recorded container ID now inspects as a DIFFERENT container (the
      # name was reused/swapped after the launch): the ID chain must refuse
      printf 'swappedid00000000000000000000000000000000000000000000000000000000|%s|%s\n' \
        "${DIAG_RUNID:-}" "$OWN_IMAGE_ID"
      exit 0
    fi
    if [ -n "${STUB_INSPECT_FOREIGN_LABEL:-}" ]; then
      printf '%s|%s|%s\n' "$cid" "$STUB_INSPECT_FOREIGN_LABEL" "$OWN_IMAGE_ID"
      exit 0
    fi
    if [ -n "${STUB_INSPECT_WRONG_IMAGE:-}" ]; then
      printf '%s|%s|%s\n' "$cid" "${DIAG_RUNID:-}" "$FOREIGN_IMAGE_ID"
      exit 0
    fi
    # the UAT-8k hang-state query: a State.Status-only format (no other
    # fields) is answered with the container's lifecycle state
    if printf '%s\n' "$*" | grep -q 'State.Status' \
       && ! printf '%s\n' "$*" | grep -q 'State.ExitCode'; then
      printf '%s\n' "${STUB_INSPECT_STATUS:-running}"
      exit 0
    fi
    # an owned container: its own ID, this run's runid label, and the LOCAL
    # image ID of the image it was started from
    printf '%s|%s|%s\n' "$cid" "${DIAG_RUNID:-}" "$OWN_IMAGE_ID"
    exit 0 ;;
  top)
    [ -n "${STUB_TOP_FAIL:-}" ] && exit 1
    if [ -n "${STUB_HANG_TOP:-}" ]; then
      trap '' TERM
      sleep "${STUB_HANG_SECONDS:-300}"
      exit 0
    fi
    if [ -n "${STUB_TOP_SECRET:-}" ]; then
      # an arbitrary value in a process argv (what docker top reports)
      printf 'UID   PID  PPID CMD\n1001 101 100 /bin/sh -c --token=%s\n' "$STUB_TOP_SECRET"
    else
      printf 'UID   PID  PPID CMD\n1001 101 100 /bin/sh -c echo OK\n'
    fi
    exit 0 ;;
  version)
    echo "24.0" ;;
  *)
    echo "stub: unsupported docker invocation: $*" >&2
    exit 2 ;;
esac
SH

cat > "$SHIM/docker-helper" <<'SH'
#!/bin/sh
# A strict docker-helper stand-in: sessions it creates are tracked in a
# registry with the harness workspace; a failed delete keeps the session in
# the registry (a real leak), a successful delete removes it. The list is
# therefore STATEFUL, mirroring the daemon.
: "${DH_SESSIONS:?DH_SESSIONS must be exported by the harness}"
: "${WS:?WS must be exported by the harness}"
case "$1 $2" in
  "session create")
    printf '%s\n' "create $*" >> "$DH_REC"
    printf '%s\n' "dhs_TEST $WS" >> "$DH_SESSIONS"
    printf '{"session":{"id":"dhs_TEST"},"token":"dht_SECRETSTUBTOKENVALUE"}\n' ;;
  "session delete")
    if [ -n "${STUB_DELETE_FAIL:-}" ]; then
      printf '%s\n' "delete-failed $*" >> "$DH_REC"
      exit 1
    fi
    printf '%s\n' "delete $*" >> "$DH_REC"
    # grep exits 1 when every line matches (the empty result) — the removal
    # must still land, so the mv runs unconditionally
    grep -vF "dhs_TEST $WS" "$DH_SESSIONS" > "$DH_SESSIONS.next" 2>/dev/null
    mv -f "$DH_SESSIONS.next" "$DH_SESSIONS" 2>/dev/null
    ;;
  "session list")
    if [ -n "${STUB_SESSION_LIST_FAIL:-}" ]; then
      echo "stub: the daemon is unreachable" >&2
      exit 1
    fi
    if [ -n "${STUB_SESSION_LIST_HANG:-}" ]; then
      trap '' TERM
      sleep "${STUB_HANG_SECONDS:-300}"
      printf '{"sessions":[]}\n'
      exit 0
    fi
    n=$(cat "$DH_LIST_COUNT" 2>/dev/null || echo 0)
    echo $((n + 1)) > "$DH_LIST_COUNT"
    parts=""
    if [ -s "$DH_SESSIONS" ]; then
      while IFS= read -r line; do
        sid="${line%% *}"
        sws="${line#* }"
        parts="$parts${parts:+,}{\"id\":\"$sid\",\"workspace\":\"$sws\"}"
      done < "$DH_SESSIONS"
    fi
    [ -n "${DH_SESSIONS_JSON:-}" ] && parts="$parts${parts:+,}$DH_SESSIONS_JSON"
    if [ -n "${STUB_FOREIGN_DURING:-}" ] && [ "$n" -ge 1 ]; then
      parts="$parts${parts:+,}{\"id\":\"dhs_FOREIGN_DURING\",\"workspace\":\"/home/agent/work/real\"}"
    fi
    printf '{"sessions":[%s]}\n' "$parts" ;;
  *)
    printf '%s\n' "other $*" >> "$DH_REC"
    ;;
esac
SH

cat > "$SHIM/script" <<'SH'
#!/usr/bin/env bash
# The script(1) stand-in: it records the invocation and parses the -qec
# contract, then delegates to the REAL script(1) when available so pty
# behavior (test -t 0 under -it launches) is genuine, not emulated.
SCRIPT_REC="${SCRIPT_REC:?SCRIPT_REC must be exported}"
printf '%s\n' "$*" >> "$SCRIPT_REC"
args=("$@")
payload=""
for ((i=0; i<${#args[@]}; i++)); do
  case "${args[$i]}" in
    -q|-qc|-qec) payload="${args[$((i+1))]:-}"; break ;;
    -*) ;;
    *) payload="${args[$i]}"; break ;;
  esac
done
if [ -n "${SMOKE_HANG_SHIM:-}" ] && printf '%s\n' "$*" | grep -qF 'SCRIPT_SMOKE_OK'; then
  # UAT-8m fault injection: hang exactly the no-docker wrapper smoke probe
  # (its inner command carries the fixed marker), before script(1) runs
  # anything at all
  trap '' TERM
  sleep "${STUB_HANG_SECONDS:-300}"
  exit 0
fi
if [ -x /usr/bin/script ]; then
  exec /usr/bin/script "$@"
fi
# no real script(1): emulate without a pty (the legacy behavior)
sh -c "$payload"
SH
chmod +x "$SHIM/script"

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
export DH_LIST_COUNT="$WORK/dh-list.count" CIDS="$WORK/containers.started"
export CIDMAP="$WORK/containers.map" DH_SESSIONS="$WORK/dh.sessions"
: > "$DH_LIST_COUNT"; : > "$CIDS"; : > "$CIDMAP"; : > "$DH_SESSIONS"
export DOCKER_HELPER_RUNTIME_DIR="$WORK/run"
export OPENCODE_DOCKER_HOME="$WORK/ochome"
export OPENCODE_EXCHANGE_DIR="$WORK/absent-exchange"
mkdir -p "$OPENCODE_DOCKER_HOME/.config" "$OPENCODE_DOCKER_HOME/.local/share" "$OPENCODE_DOCKER_HOME/tmp"
# no OPENCODE_AGENT_SSH_KEY by default: the canonical steps run without ssh
# forwarding (the T13 agent test provisions its own key)
export OPENCODE_AGENT_SSH_KEY="$WORK/absent-key"
WS="$WORK/ws"; mkdir -p "$WS"; export WS

# shellcheck source=/dev/null
source "$ALIASES"
# shellcheck source=/dev/null
source "$LIB"
export DC_ALIASES="$ALIASES"

# fast, bounded test bounds (assigned AFTER the source so they override the
# lib's production defaults; the production defaults stay 30/60/30 and the
# kill-after 10 — the hangs below are rc 124 or 137 alike, only faster)
DIAG_STEP_BOUND=3
DIAG_CANON_BOUND=3
DIAG_FACTOR_BOUND=3
DIAG_KILL_AFTER=2
export DIAG_STEP_BOUND DIAG_CANON_BOUND DIAG_FACTOR_BOUND DIAG_KILL_AFTER

DIAGRUN=0
run_ladder() { # -> REPORT (stdout), LRC (the ladder rc)
  DIAGRUN=$((DIAGRUN + 1))
  DIAG_DIR="$WORK/evid"
  rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"
  : > "$DH_REC"; : > "$DOCKER_REC"; : > "$SCRIPT_REC"
  : > "$DH_LIST_COUNT"; : > "$CIDS"; : > "$CIDMAP"; : > "$DH_SESSIONS"
  export DIAG_RUNID="diagrun-$DIAGRUN" DIAG_IMAGE="$_OC_BASE"
  REPORT="$(diag_run_ladder "$_OC_BASE" "$WS" "diagrun-$DIAGRUN" 2>&1)"
  LRC=$?
  printf '%s\n' "=== run $DIAGRUN LRC=$LRC" >> /tmp/opencode/8e-reports.log
  printf '%s\n' "$REPORT" >> /tmp/opencode/8e-reports.log
  if [ "${DIAG_DEBUG_ONCE:-x}" = "$DIAGRUN" ]; then
    cp "$DOCKER_REC" /tmp/opencode/8e-docker.rec
    cp "$DH_REC" /tmp/opencode/8e-dh.rec
    cp -r "$DIAG_DIR" /tmp/opencode/8e-evid
    printf '%s\n' "$REPORT" > /tmp/opencode/8e-report.debug
  fi
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
grep -qE '^D2 FAIL rc=1(24|37) elapsed=.* detail=timeout hang=running' <<<"$REPORT" \
  && ok "UAT-8k: the timeout carries the observed container state (hang=running)" \
  || bad "UAT-8k: the timeout line lost the hang-stage observation: $(grep '^D2 ' <<<"$REPORT")"
contains "the downstream canonical steps are NOT_RUN" "D3 NOT_RUN" "$REPORT"
contains "the entrypoint step is NOT_RUN" "D4 NOT_RUN" "$REPORT"
check "the failing ladder exits nonzero" "1" "$LRC"
contains "the transition names the D1->D2 configuration delta" \
  "TRANSITION D1->D2" "$REPORT"
contains "the transition names the canonical mounts" "canonical mounts" "$REPORT"
grep -qE "rm(- -f)? $(cat "$WORK/evid/D2.cid" 2>/dev/null)" "$DOCKER_REC" \
  && ok "the owned hung container is reaped (docker rm -f by verified container ID)" \
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
not_contains "UAT-8f: raw docker error strings never reach the report" \
  "simulated docker CLI failure" "$REPORT"
[ "$(cat "$WORK/evid/D0.err" 2>/dev/null)" = "stub: simulated docker CLI failure for echo D0_OK" ] \
  && ok "the CLI failure stderr is captured in the private evidence" \
  || bad "the CLI failure stderr was lost or altered"

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

# --- 6. the command's stderr is captured privately, never printed ------------
STUB_FAIL_PAYLOAD="D2_OK" run_ladder
unset STUB_FAIL_PAYLOAD
[ -s "$WORK/evid/D2.err" ] \
  && ok "the failing step's stderr is captured in the private evidence" \
  || bad "the failing step's stderr was lost"
not_contains "UAT-8f: the raw stderr never reaches the report" \
  "simulated docker CLI failure" "$REPORT"
contains "the report names the private-stderr category" \
  "DIAG stderr: captured in the private evidence (not printed)" "$REPORT"

# --- 7. the owned Session delta is reaped after the canonical steps ----------
STUB_DELETE_FAIL=1 run_ladder
unset STUB_DELETE_FAIL
contains "the canonical probe step ran (D3 evidence)" "D3 PASS" "$REPORT"
grep -qE "delete(-failed)? dhs_TEST" "$DH_REC" \
  && ok "the leaked Session is reaped by the diagnostic (delete attempted)" \
  || bad "the diagnostic did not reap the leaked Session"
contains "the Session cleanup outcome is recorded" "CLEANUP D3 session=" "$REPORT"

# --- 8. no secret material in the report -------------------------------------
run_ladder
not_contains "the Session bearer never reaches the report" "dht_SECRETSTUBTOKENVALUE" "$REPORT"
not_contains "the session id is not quoted as evidence" "dhs_TEST" "$REPORT"
LLM_KEY="llm-secret-marker" ADMIN_TOKEN="admin-secret-marker" run_ladder
not_contains "the LLM key never reaches the report" "llm-secret-marker" "$REPORT"
not_contains "the admin token never reaches the report" "admin-secret-marker" "$REPORT"

# --- 9. the canonical-path failure gets its own bounded factor probes --------
# UAT-8d: the canonical D3 baseline changes three factors at once (the
# Session lifecycle, the ssh-agent, the TTY); a hanging D3 now runs the
# notty/nosession/noagent probes, each removing exactly one factor.
STUB_HANG_PAYLOAD="D3_OK" STUB_HANG_SECONDS=60 DIAG_CANON_BOUND=3 run_ladder
unset STUB_HANG_PAYLOAD STUB_HANG_SECONDS
grep -qE '^D3 FAIL rc=1(24|37) elapsed=' <<<"$REPORT" \
  && ok "a hanging canonical probe is a timeout" \
  || bad "a hanging canonical probe was not a timeout"
contains "the D2->D3 transition names all three added factors" \
  "TRANSITION D2->D3: + the Session lifecycle and bearer, + the per-launch ssh-agent (when a key is provisioned), + the -it TTY" "$REPORT"
for probe in F-D3-notty F-D3-nosession F-D3-noagent; do
  contains "the $probe probe ran for the hanging canonical step" "$probe " "$REPORT"
done

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
grep -q "docker run" "$SCRIPT_REC" \
  && ok "the script factor really went through script(1)" \
  || bad "the script factor did not use script(1)"

# --- UAT-8d. provable resource ownership --------------------------------------
# The stub docker is a strict daemon boundary: it refuses to remove a
# container it did not start, and it answers ownership queries faithfully.

# T1/T2: foreign containers on the SAME pinned image (and ones started
# concurrently by another process) are never removed — the old delta-based
# cleanup would have removed them.
STUB_FOREIGN_CIDS="foreign-abc foreign-def" STUB_HANG_PAYLOAD="D2_OK" STUB_HANG_SECONDS=60 run_ladder
unset STUB_FOREIGN_CIDS STUB_HANG_PAYLOAD STUB_HANG_SECONDS
if grep -qE "rm(- -f)? foreign-(abc|def)" "$DOCKER_REC"; then
  bad "UAT-8d RED: a foreign container was removed by image/delta cleanup"
else
  ok "UAT-8d: foreign containers on the same image are never removed"
fi
grep -qE "rm(- -f)? $(cat "$WORK/evid/D2.cid" 2>/dev/null)" "$DOCKER_REC" \
  && ok "UAT-8d: the owned hung container is still reaped by verified identity" \
  || bad "UAT-8d: the owned hung container was not reaped"

# T3: an ownership verification failure refuses the removal and records it
STUB_INSPECT_FOREIGN_LABEL="otherrun-9" STUB_HANG_PAYLOAD="D2_OK" STUB_HANG_SECONDS=60 run_ladder
unset STUB_INSPECT_FOREIGN_LABEL STUB_HANG_PAYLOAD STUB_HANG_SECONDS
check "UAT-8d: an unverified container is never removed (refused)" "refused-unowned" "$(cat "$WORK/evid/D2.reap")"
check "UAT-8k: the unattributed container state is recorded, never guessed" \
  "unattributed" "$(cat "$WORK/evid/D2.hangstate")"
if grep -qE "rm(- -f)? dhl-D2-" "$DOCKER_REC"; then
  bad "UAT-8d RED: a container with a foreign runid label was removed"
else
  ok "UAT-8d: a container whose runid label does not match is never removed"
fi

# T4: a failed session list refuses the cleanup (never proceeds empty)
STUB_SESSION_LIST_FAIL=1 run_ladder
unset STUB_SESSION_LIST_FAIL
contains "UAT-8d: a failed session list refuses the cleanup" \
  "CLEANUP D3 session=refused-list-error" "$REPORT"
# the canonical launches own TWO deletes (D3's and D4's own traps); the
# diagnostic's reaping would add more
if [ "$(grep -c "delete dhs_TEST" "$DH_REC")" -gt 2 ]; then
  bad "UAT-8d RED: the diagnostic deleted sessions despite a failed registration list"
else
  ok "UAT-8d: only the launcher's own cleanup ran; the diagnostic deleted nothing"
fi

# T5: a foreign session that existed before is never touched
DH_SESSIONS_JSON='{"id":"dhs_FOREIGN_BEFORE","workspace":"/home/agent/work/real"}' run_ladder
unset DH_SESSIONS_JSON
if grep -q "delete dhs_FOREIGN_BEFORE" "$DH_REC"; then
  bad "UAT-8d: a pre-existing foreign session was deleted"
else
  ok "UAT-8d: a pre-existing foreign session is never deleted"
fi

# T6: a foreign session created WHILE the diagnostic runs is never deleted
# (the old global before/after delta would have deleted it)
STUB_FOREIGN_DURING=1 run_ladder
unset STUB_FOREIGN_DURING
if grep -q "delete dhs_FOREIGN_DURING" "$DH_REC"; then
  bad "UAT-8d RED: a concurrent foreign session was deleted by the delta cleanup"
else
  ok "UAT-8d: a concurrent foreign session is never deleted"
fi
contains "UAT-8d: the own session cleanup outcome is recorded" \
  "CLEANUP D3 session=clean" "$REPORT"

# T8: a forced removal of an OWN resource that fails is recorded, not hidden
STUB_RM_FAIL=1 STUB_HANG_PAYLOAD="D2_OK" STUB_HANG_SECONDS=60 run_ladder
unset STUB_RM_FAIL STUB_HANG_PAYLOAD STUB_HANG_SECONDS
check "UAT-8d: a failed owned-removal is recorded" "failed" "$(cat "$WORK/evid/D2.reap")"

# T9: the canonical argv carries the LLM provider env flags, with and without
# the values present in the launcher environment; the values never appear in
# the argv
: > "$DOCKER_REC"
( cd "$WS" && oc-probe 'echo T9' ) >/dev/null 2>&1
contains "UAT-8d: LLM_SERVER is in the canonical argv" "-e LLM_SERVER" "$(cat "$DOCKER_REC")"
contains "UAT-8d: LLM_KEY is in the canonical argv" "-e LLM_KEY" "$(cat "$DOCKER_REC")"
not_contains "UAT-8d: no LLM value in the argv when the env is unset" "LLM_SERVER=" "$(cat "$DOCKER_REC")"
: > "$DOCKER_REC"
( cd "$WS" && LLM_SERVER=https://llm.example LLM_KEY=llm-secret-value oc-probe 'echo T9' ) >/dev/null 2>&1
contains "UAT-8d: LLM_SERVER is in the canonical argv when set" "-e LLM_SERVER" "$(cat "$DOCKER_REC")"
not_contains "UAT-8d: the LLM key value never enters the argv" "llm-secret-value" "$(cat "$DOCKER_REC")"

# T10: a mount-gate refusal stops the step BEFORE docker (zero docker runs)
ln -s /tmp "$OPENCODE_DOCKER_HOME/ca"
run_ladder
rm -f "$OPENCODE_DOCKER_HOME/ca"
contains "UAT-8d: an unsafe mount source fails the composition" \
  "D2 FAIL rc=refused elapsed=unknown detail=composition-refused" "$REPORT"
if grep -q " run " "$DOCKER_REC"; then
  bad "UAT-8d RED: docker ran despite a mount-gate refusal"
else
  ok "UAT-8d: a mount-gate refusal means zero docker runs"
fi

# T11a: an init copy verification refusal (the lab init dir escapes the lab
# home) fails D1 BEFORE docker, and D2 with it
mv "$OPENCODE_DOCKER_HOME/init" "$OPENCODE_DOCKER_HOME/init.real" 2>/dev/null
ln -s /tmp "$OPENCODE_DOCKER_HOME/init"
run_ladder
rm -f "$OPENCODE_DOCKER_HOME/init"
mv "$OPENCODE_DOCKER_HOME/init.real" "$OPENCODE_DOCKER_HOME/init" 2>/dev/null
contains "UAT-8d: a broken init copy refuses D1" \
  "D1 FAIL rc=refused elapsed=unknown detail=init-verify-refused" "$REPORT"
if grep -qE "^run .*dhl-D1-" "$DOCKER_REC"; then
  bad "UAT-8d RED: docker ran with an unverifiable init copy"
else
  ok "UAT-8d: an init verification refusal means zero docker runs for D1"
fi
contains "UAT-8d: D2 depends on the verified init (the ladder stops)" \
  "D2 NOT_RUN" "$REPORT"

# T11b: no system docker-init at all — D1 is a FAIL, never a successful
# --init run. The candidate search is replaced wholesale by the documented
# test seam so the case is hermetic regardless of the host's real
# docker-init locations.
mv "$SHIM/docker-init" "$SHIM/docker-init.hidden"
LAB_DOCKER_INIT_CANDIDATES="" run_ladder
mv "$SHIM/docker-init.hidden" "$SHIM/docker-init"
contains "UAT-8d: a missing system docker-init is a FAIL, not a pass" \
  "D1 FAIL rc=refused elapsed=unknown detail=no-init-copy" "$REPORT"
if grep -qE "^run .*dhl-D1-" "$DOCKER_REC"; then
  bad "UAT-8d RED: docker ran without any verified init copy"
else
  ok "UAT-8d: no verified init copy means zero docker runs for D1"
fi

# T12: a D3 hang caused ONLY by the TTY — the strict matrix attributes it to
# the docker -t flag (the multi-variable notty probe may no longer name a
# cause: it changes the flags, the stdin and the payload together)
STUB_HANG_WHEN_TTY=1 STUB_HANG_SECONDS=60 DIAG_CANON_BOUND=3 run_ladder
unset STUB_HANG_WHEN_TTY STUB_HANG_SECONDS
contains "UAT-8d: the TTY-implicated diagnosis is named by the strict matrix" \
  "DIAGNOSIS: the D3 docker -t flag is implicated" "$REPORT"
not_contains "UAT-8d RED: the multi-variable notty probe never names the cause" \
  "the D3-notty factor is implicated" "$REPORT"

# T13: a D3 hang caused ONLY by the ssh-agent — the no-agent probe passes
mkdir -p "$(dirname "$OPENCODE_AGENT_SSH_KEY")"
printf 'PRIVATE-KEY\n' > "$OPENCODE_AGENT_SSH_KEY"
chmod 0600 "$OPENCODE_AGENT_SSH_KEY"
STUB_HANG_WHEN_AGENT=1 STUB_HANG_SECONDS=60 DIAG_CANON_BOUND=3 run_ladder
unset STUB_HANG_WHEN_AGENT STUB_HANG_SECONDS
rm -f "$OPENCODE_AGENT_SSH_KEY"
contains "UAT-8d: the ssh-agent-implicated diagnosis is named" \
  "DIAGNOSIS: the D3-noagent factor is implicated" "$REPORT"

# T14: the report carries no secret material in any scenario
run_ladder
not_contains "UAT-8d: no bearer token in the report" "dht_SECRETSTUBTOKENVALUE" "$REPORT"
not_contains "UAT-8d: no session id quoted as evidence" "dhs_TEST" "$REPORT"

# --- UAT-8e. image-ID ownership, provenance, PTY, cleanup-as-PASS, bounds ----

# T1: the OCI reference and the local image ID are DIFFERENT identifiers; the
# ownership verification compares the container's image ID against the ID
# resolved from the pinned reference (the old code compared an ID with the
# reference and could never match)
STUB_HANG_PAYLOAD="D2_OK" STUB_HANG_SECONDS=60 run_ladder
unset STUB_HANG_PAYLOAD STUB_HANG_SECONDS
if grep -qE "rm(- -f)? $(cat "$WORK/evid/D2.cid" 2>/dev/null)" "$DOCKER_REC"; then
  ok "UAT-8e: a hung container is reaped by the verified immutable container ID"
else
  bad "UAT-8e RED: the image-ID ownership chain failed to reap the owned container"
fi

# T1b: a container built from a DIFFERENT image than the pinned reference is
# never removed (the image ID comparison catches it)
STUB_INSPECT_WRONG_IMAGE=1 STUB_HANG_PAYLOAD="D2_OK" STUB_HANG_SECONDS=60 run_ladder
unset STUB_INSPECT_WRONG_IMAGE STUB_HANG_PAYLOAD STUB_HANG_SECONDS
check "UAT-8e: a container from a different image is refused" \
  "refused-unowned" "$(cat "$WORK/evid/D2.reap")"
if grep -qE "rm(- -f)? $(cat "$WORK/evid/D2.cid" 2>/dev/null)" "$DOCKER_REC"; then
  bad "UAT-8e RED: a container with a foreign image ID was removed"
else
  ok "UAT-8e: a container from a different image is never removed"
fi

# T2: a swapped container name cannot fool the verification: the removal
# decision is anchored on the IMMUTABLE container ID recorded in the cidfile
STUB_NAME_SWAP=1 STUB_HANG_PAYLOAD="D2_OK" STUB_HANG_SECONDS=60 run_ladder
unset STUB_NAME_SWAP STUB_HANG_PAYLOAD STUB_HANG_SECONDS
check "UAT-8e: a name swap after start is refused" \
  "refused-unowned" "$(cat "$WORK/evid/D2.reap")"
if grep -qE "rm(- -f)? $(cat "$WORK/evid/D2.cid" 2>/dev/null)" "$DOCKER_REC"; then
  bad "UAT-8e RED: a container whose ID does not match the cidfile was removed"
else
  ok "UAT-8e: the name-swap defense holds (removal only by the verified ID)"
fi

# T5: D3/D4 containers carry NO com.dockerhelper.* labels (they are plain
# docker run); a hung canonical container is identified by the diagnostic
# provenance the launcher applies when explicitly asked
STUB_HANG_PAYLOAD="D3_OK" STUB_HANG_SECONDS=60 DIAG_CANON_BOUND=3 run_ladder
unset STUB_HANG_PAYLOAD STUB_HANG_SECONDS
contains "UAT-8e: the hung canonical container is reaped by provenance" \
  "CLEANUP D3 session=reaped" "$REPORT"
if grep -qE "rm(- -f)? $(cat "$WORK/evid/D3.cid" 2>/dev/null)" "$DOCKER_REC"; then
  ok "UAT-8e: the D3 container removal used the recorded container ID"
else
  bad "UAT-8e RED: the provenance-based D3 reap did not run"
fi

# T6: a run that died before writing the cidfile grants no removal
# permission by assumption; proven absence is a normal outcome
CID_FILE_MISSING="$WORK/missing.cid"
: > "$CID_FILE_MISSING"
# (a) a missing cidfile with a provably absent container: a normal outcome
( export DIAG_DIR="$WORK/evid" DIAG_RUNID="diagrun-$DIAGRUN" DIAG_IMAGE="$_OC_BASE"
  check "UAT-8e: a missing cidfile with a provably absent container is clean" \
    "clean" "$(diag_reap_owned_container "dhl-absent-$DIAGRUN" "$CID_FILE_MISSING")" )
# (b) a missing cidfile while a container with that name exists: no
# assumption, the removal is refused
( export DIAG_DIR="$WORK/evid" DIAG_RUNID="diagrun-$DIAGRUN" DIAG_IMAGE="$_OC_BASE"
  out="$(STUB_FOREIGN_CIDS="foreign-present" diag_reap_owned_container "foreign-present" "$CID_FILE_MISSING")"
  check "UAT-8e: a missing cidfile with an existing container is refused" \
    "refused-unowned" "$out" )

# T7/T8: the PTY matrix. The canonical -it steps run under a real script(1)
# and the container payload proves the TTY with test -t 0 (D3_OK); the
# no-TTY probe deliberately uses stdin /dev/null without -it; real docker
# refuses -it without a terminal and the stub models that refusal.
STUB_HANG_PAYLOAD="D3_NOTTY" STUB_HANG_SECONDS=60 run_ladder || true
unset STUB_HANG_PAYLOAD STUB_HANG_SECONDS
contains "UAT-8e: the D3 payload proved the in-container TTY (test -t 0)" \
  "D3 PASS rc=0" "$REPORT"
( docker run --rm -it --name tty-refusal-test "$_OC_BASE" -c 'echo X' </dev/null ) >/dev/null 2>&1
[ $? -eq 125 ] \
  && ok "UAT-8e: -it without an available TTY is refused (rc 125)" \
  || bad "UAT-8e RED: the stub accepted -it without a TTY"

# T9: a passing workload with a FAILED mandatory cleanup is a diagnostic
# FAIL: the workload verdict stays PASS, the cleanup verdict names the
# reason, and the ladder exits nonzero
STUB_DELETE_FAIL=1 run_ladder
unset STUB_DELETE_FAIL
contains "UAT-8e: the workload verdict stays PASS with a failed cleanup" \
  "D3 PASS rc=0" "$REPORT"
contains "UAT-8e: the cleanup verdict names the failure" \
  "CLEANUP D3 session=failed" "$REPORT"
contains "UAT-8e: the mandatory cleanup failure fails the diagnostic" \
  "DIAGNOSTIC FAIL reason=cleanup-D3 failed" "$REPORT"
[ "$LRC" != 0 ] \
  && ok "UAT-8e: a failed cleanup makes the ladder exit nonzero" \
  || bad "UAT-8e RED: a failed cleanup still reported success"

# T11: a hung docker inspect during recovery is bounded and refuses without
# blocking the ladder
STUB_HANG_INSPECT=1 STUB_HANG_SECONDS=60 DIAG_RECOVERY_BOUND=2 \
  STUB_HANG_PAYLOAD="D2_OK" run_ladder
unset STUB_HANG_INSPECT STUB_HANG_SECONDS STUB_HANG_PAYLOAD
export DIAG_RECOVERY_BOUND=10
if grep -qE "elapsed=[0-9]+" <<<"$REPORT"; then
  ok "UAT-8e: a hung docker inspect did not block the ladder (bounded recovery)"
else
  bad "UAT-8e: the bounded recovery did not produce elapsed evidence"
fi

# T12: a hung session list is bounded and refuses the cleanup explicitly
STUB_SESSION_LIST_HANG=1 STUB_HANG_SECONDS=60 DIAG_RECOVERY_BOUND=2 run_ladder
unset STUB_SESSION_LIST_HANG STUB_HANG_SECONDS
DIAG_RECOVERY_BOUND=10
contains "UAT-8e: a hung session list refuses the cleanup" \
  "CLEANUP D3 session=refused-list-error" "$REPORT"
contains "UAT-8e: a hung session list fails the diagnostic" \
  "DIAGNOSTIC FAIL reason=cleanup-D3 refused-list-error" "$REPORT"
[ "$LRC" != 0 ] \
  && ok "UAT-8e: the hung-list ladder exits nonzero" \
  || bad "UAT-8e RED: a hung session list was tolerated as success"

# T16: the normal oc entry points never carry the diagnostic provenance
: > "$DOCKER_REC"
( cd "$WS" && oc echo hi )
dargv="$(cat "$DOCKER_REC" 2>/dev/null || true)"
not_contains "UAT-8e: a normal oc launch carries no diagnostic name" "--name dhl-" "$dargv"
not_contains "UAT-8e: a normal oc launch carries no diagnostic label" "lab.diagnostic.runid" "$dargv"
not_contains "UAT-8e: a normal oc launch carries no cidfile" "--cidfile" "$dargv"

# T14/T15: the evidence summary is a real executable path with REAL
# allowlisting: a secret VALUE injected into the evidence never reaches the
# output, only the predefined safe docker-state fields are printed, and raw
# docker top process argv never enters the report at all (UAT-8f: the argv
# may carry arbitrary operator-uncontrolled values). A sanitization failure
# fails closed. (The root driver sources this same library, so the summary
# runs with the single sanitization owner.)
evid_dir="$WORK/summary-evid"
mkdir -p "$evid_dir"
printf 'exited=0\n' > "$evid_dir/D2.docker-state"
printf 'UID   PID  PPID CMD\n1001 101 100 /bin/sh -c --token=SECRET-VALUE-8d9f2c1b\n' > "$evid_dir/D3.procs"
out="$(diag_register_secret_value "SECRET-VALUE-8d9f2c1b"; diag_print_evidence_summary "$evid_dir" 2>&1)"
rc_sum=$?
[ "$rc_sum" = 0 ] \
  && ok "UAT-8e: the evidence summary runs end to end" \
  || bad "UAT-8e RED: the evidence summary failed (rc $rc_sum)"
not_contains "UAT-8e: the injected secret value is redacted from the summary" \
  "SECRET-VALUE-8d9f2c1b" "$out"
contains "UAT-8e: the allowlisted docker-state line is printed" \
  "D2 docker-state:" "$out"
not_contains "UAT-8f RED: raw docker top process argv never reaches the summary" \
  "container processes:" "$out"
case "$out" in
  *"--token="*) bad "UAT-8f RED: process argv text leaked into the summary" ;;
  *) ok "UAT-8f: no process argv content in the summary" ;;
esac
printf 'unavailable\n' > "$evid_dir/D3.docker-state"
out="$(diag_print_evidence_summary "$evid_dir" 2>&1)"
contains "UAT-8e: an observability failure prints UNAVAILABLE explicitly" \
  "D3 docker-state: UNAVAILABLE" "$out"

# --- UAT-8f BLOCKER 1. the cleanup verdict aggregation matrix ----------------
# ANY mandatory failure dominates ANY success: a successful container reap
# must never mask a failed Session deletion and vice versa. The refused
# verdicts never become a PASS, and only clean/reaped without any other
# failure is accepted by diag_cleanup_ok. The matrix drives the REAL
# aggregation owner (diag_canonical_recover) through the stubbed
# docker/docker-helper stateful boundaries.
mx_home="$WORK/mx-home"; mkdir -p "$mx_home/work"
mx_evid="$WORK/mx-evid"; mkdir -p "$mx_evid"
mx_cid="deadbeef$(printf 'a%.0s' {1..56})"
mx_run() { # SESSION_MODE CONTAINER_MODE -> verdict on stdout
  local s="$1" c="$2"
  local cidfile="$WORK/mx-$s-$c.cid"
  : > "$DH_SESSIONS"; rm -f "$cidfile"
  case "$s" in
    reaped|failed) printf '%s\n' "dhs_MX $mx_home/work" >> "$DH_SESSIONS" ;;
  esac
  case "$c" in
    ok|failed|refused-unowned)
      printf '%s' "$mx_cid" > "$cidfile"
      grep -qxF "$mx_cid" "$CIDS" 2>/dev/null || printf '%s\n' "$mx_cid" >> "$CIDS" ;;
  esac
  (
    export DIAG_DIR="$mx_evid" DIAG_RUNID=diagrun-mx DIAG_IMAGE="$_OC_BASE"
    case "$c" in
      failed) export STUB_RM_FAIL=1 ;;
      refused-unowned) export STUB_INSPECT_FOREIGN_LABEL=1 ;;
    esac
    case "$s" in
      failed) export STUB_DELETE_FAIL=1 ;;
      refused-list-error) export STUB_SESSION_LIST_FAIL=1 ;;
    esac
    diag_canonical_recover MX "$mx_home/work" "dhl-MX-diagrun-mx" "$cidfile"
  )
}
mx_matrix_fail=0
for s in clean reaped failed refused-list-error; do
  for c in clean ok failed refused-unowned; do
    case "$s/$c" in
      refused-list-error/*) want=refused-list-error ;;
      */refused-unowned)    want=refused-unowned ;;
      */failed)             want=failed ;;
      failed/*)             want=failed ;;
      */ok)                 want=reaped ;;
      */clean)              want="$s" ;;
      *)                    want=refused-unowned ;;
    esac
    got="$(mx_run "$s" "$c")"
    if [ "$got" = "$want" ]; then
      ok "cleanup matrix: session=$s container=$c -> $want"
    else
      mx_matrix_fail=$((mx_matrix_fail + 1))
      bad "cleanup matrix: session=$s container=$c -> want $want got $got"
    fi
  done
done
for v in clean reaped; do
  diag_cleanup_ok "$v" && ok "diag_cleanup_ok accepts $v" || bad "diag_cleanup_ok rejects $v"
done
for v in failed refused-unowned refused-list-error "n/a" ""; do
  diag_cleanup_ok "$v" && bad "diag_cleanup_ok accepted '$v'" || ok "diag_cleanup_ok rejects '$v'"
done

# --- UAT-8f BLOCKER 5. full-CID absence proof --------------------------------
# A failed inspect by CID proves nothing; an empty name search proves nothing
# about a container that may have been renamed; a 12-hex short ID is not
# immutable identity. Absence is accepted only from a successful, empty
# search on the FULL container ID.
abs_evid="$WORK/abs-evid"; mkdir -p "$abs_evid"
abs_cid="beef0000$(printf 'b%.0s' {1..56})"
abs_run() { # NAME CID_HEX [STUB_VARS...] -> verdict (fresh stub state each call)
  local name="$1" cid="$2"; shift 2
  local cidfile="$WORK/abs-$name.cid"
  printf '%s' "$cid" > "$cidfile"
  (
    export DIAG_DIR="$abs_evid" DIAG_RUNID=diagrun-abs DIAG_IMAGE="$_OC_BASE"
    # shellcheck disable=SC2163  # "$@" is the caller's STUB_VAR=value list
    if [ "$#" -gt 0 ]; then export "$@"; fi
    diag_reap_owned_container "$name" "$cidfile"
  )
}
# (16) a failed inspect + a successful empty FULL-CID search -> proven absent
: > "$CIDS"
out="$(abs_run "dhl-abs16-diagrun-abs" "$abs_cid" STUB_INSPECT_ERROR=1)"
check "UAT-8f: an inspect error with a provably absent full CID is clean" \
  "clean" "$out"
grep -qF -- "--filter id=$abs_cid" "$DOCKER_REC" \
  && ok "UAT-8f: the absence was proven by the FULL container ID search" \
  || bad "UAT-8f RED: absence was decided without a full-CID search"
# (14) a failed inspect while the container exists under a RENAMED identity:
# the empty name search must NOT produce a clean verdict
: > "$CIDS"; printf '%s\n' "$abs_cid" >> "$CIDS"
out="$(abs_run "dhl-abs14-diagrun-abs" "$abs_cid" STUB_INSPECT_ERROR=1)"
check "UAT-8f: a renamed container with a known CID is refused (never clean)" \
  "refused-unowned" "$out"
if grep -qE "rm(- -f)? $abs_cid" "$DOCKER_REC"; then
  bad "UAT-8f RED: a container with an unproven identity was removed"
else
  ok "UAT-8f: no removal happened on an unprovable identity"
fi
# (15) an inspect error while the container exists under its own name: the
# refusal is the same, and the identity is still never removed
: > "$CIDS"; printf '%s\n' "$abs_cid" >> "$CIDS"
printf '%s %s\n' "dhl-abs15-diagrun-abs" "$abs_cid" >> "$CIDMAP"
out="$(abs_run "dhl-abs15-diagrun-abs" "$abs_cid" STUB_INSPECT_ERROR=1)"
check "UAT-8f: an inspect error with a present container is refused" \
  "refused-unowned" "$out"
if grep -qE "rm(- -f)? $abs_cid" "$DOCKER_REC"; then
  bad "UAT-8f: a container was removed although its identity could not be verified"
else
  ok "UAT-8f: the present container is intact after the refused reap"
fi
# a short (12-hex) container ID is never accepted as identity evidence
: > "$CIDS"; : > "$CIDMAP"
short_cid="deadbeefcafe"
printf '%s\n' "$short_cid" >> "$CIDS"
out="$(abs_run "dhl-short-diagrun-abs" "$short_cid")"
check "UAT-8f: a 12-hex short CID is refused as identity evidence" \
  "refused-unowned" "$out"
if grep -qE "rm(- -f)? $short_cid" "$DOCKER_REC"; then
  bad "UAT-8f RED: a removal was authorized by a 12-hex short ID"
else
  ok "UAT-8f: a short CID authorizes nothing (no docker call at all)"
fi
: > "$CIDS"; : > "$CIDMAP"

# (13) hung docker inspect/top during failure evidence: bounded, UNAVAILABLE,
# never blocking the report
hang_evid="$WORK/hang-evid"; mkdir -p "$hang_evid"
(
  export DIAG_DIR="$hang_evid" DIAG_RUNID=diagrun-hang DIAG_IMAGE="$_OC_BASE"
  export STUB_HANG_INSPECT=1 STUB_HANG_TOP=1 STUB_HANG_SECONDS=60
  export DIAG_RECOVERY_BOUND=2 DIAG_KILL_AFTER=1
  timeout --kill-after=3 20 bash -c '
    source "$1"
    diag_collect_failure D0
  ' _ "$LIB"
)
hang_rc=$?
[ "$hang_rc" = 0 ] \
  && ok "UAT-8f: hung docker inspect/top did not block the failure evidence" \
  || bad "UAT-8f RED: the failure-evidence collection blocked (rc $hang_rc)"
check "UAT-8f: hung inspect evidence is recorded UNAVAILABLE" \
  "unavailable" "$(cat "$hang_evid/D0.docker-state" 2>/dev/null)"
check "UAT-8f: hung top evidence is recorded UNAVAILABLE" \
  "unavailable" "$(cat "$hang_evid/D0.procs" 2>/dev/null)"
unset STUB_HANG_INSPECT STUB_HANG_TOP STUB_HANG_SECONDS
export DIAG_RECOVERY_BOUND=10

# --- UAT-8f BLOCKER 2. arbitrary secrets never reach the public output -------
# (5) an arbitrary value inside a Docker error string: the stderr excerpt is
# no longer part of the report, so the value cannot leak even though nothing
# registered it
STUB_STDERR_SECRET="RUNSECRET-7f3a9b2c" STUB_FAIL_PAYLOAD="D1_OK" run_ladder
unset STUB_STDERR_SECRET STUB_FAIL_PAYLOAD
not_contains "UAT-8f RED: an arbitrary Docker-stderr secret never reaches the report" \
  "RUNSECRET-7f3a9b2c" "$REPORT"
grep -q "RUNSECRET-7f3a9b2c" "$WORK/evid/D1.err" 2>/dev/null \
  && ok "UAT-8f: the stderr secret stayed in the private evidence only" \
  || bad "UAT-8f: the stderr fixture did not reach the evidence (test setup broken)"
# (6) a secret value with regex metacharacters and a newline is matched
# LITERALLY: the exact value is redacted, a regex-only near-miss is not
metaval="$(printf 'MV[x].*y&\\z\nsecond-line')"
diag_register_secret_value "$metaval"
san="$(diag_sanitize "prefix MV[x].*y&\\z
second-line suffix")"
check "UAT-8f RED: a metacharacter+newline secret is redacted exactly" \
  "prefix REDACTED suffix" "$san"
san2="$(diag_sanitize "MV[x]QQQQy&\\z
second-line stays")"
check "UAT-8f: a regex-only near-miss is NOT redacted (literal matching)" \
  "MV[x]QQQQy&\\z
second-line stays" "$san2"
# (7) an arbitrary secret in docker top process argv: docker top is internal
# evidence and is never printed — not by the ladder and not by the summary
STUB_TOP_SECRET="TOPARGV-4d8e1f0a" STUB_FAIL_PAYLOAD="D3_OK" run_ladder
unset STUB_TOP_SECRET STUB_FAIL_PAYLOAD
not_contains "UAT-8f RED: a docker top argv secret never reaches the ladder report" \
  "TOPARGV-4d8e1f0a" "$REPORT"
out="$(diag_print_evidence_summary "$WORK/evid" 2>&1)"
not_contains "UAT-8f RED: a docker top argv secret never reaches the summary" \
  "TOPARGV-4d8e1f0a" "$out"
grep -q "TOPARGV-4d8e1f0a" "$WORK/evid/D3.procs" 2>/dev/null \
  && ok "UAT-8f: the argv secret stayed in the private evidence only" \
  || bad "UAT-8f: the argv fixture did not reach the evidence (test setup broken)"
# (8) a secret in child-runner state that the root driver does not know: a
# FRESH process (the root driver's state) prints the summary without any
# registration and still cannot leak the value
fresh_out="$(bash -c 'source "$1"; diag_print_evidence_summary "$2"' _ "$LIB" "$WORK/evid" 2>&1)"
fresh_rc=$?
[ "$fresh_rc" = 0 ] \
  && ok "UAT-8f: the root-driver-side summary runs in a fresh process" \
  || bad "UAT-8f: the fresh-process summary failed (rc $fresh_rc)"
not_contains "UAT-8f RED: an unknown child secret cannot leak from the root driver" \
  "TOPARGV-4d8e1f0a" "$fresh_out"

# --- UAT-8f BLOCKER 4. the unique diagnostic workspace -----------------------
# Allocation is atomic (mktemp -d) under the agent's allowed root: an
# existing directory is never reused, the name is unpredictable, the mode is
# 0700 with the agent as owner, and the canonical path must stay inside the
# canonical home. One cleanup owner removes the registered workspace and
# PROVES the removal.
ws_home="$WORK/ws-home"; mkdir -p "$ws_home/work"
# (11) a pre-existing PID-shaped workspace holding foreign data survives
foreign="$ws_home/work/diag-$$"
mkdir -p "$foreign"; printf 'foreign-data\n' > "$foreign/precious.txt"
ws1="$(diag_alloc_workspace "$ws_home" "$(id -un)")"
[ -n "$ws1" ] \
  && ok "UAT-8f: the workspace is allocated atomically" \
  || bad "UAT-8f RED: the workspace allocation failed"
[ "$ws1" != "$foreign" ] \
  && ok "UAT-8f: a pre-existing PID-named directory is never reused" \
  || bad "UAT-8f RED: the pre-existing PID-named directory was reused"
[ "$(cat "$foreign/precious.txt" 2>/dev/null)" = "foreign-data" ] \
  && ok "UAT-8f RED: the foreign workspace data is untouched" \
  || bad "UAT-8f: the foreign workspace data was damaged"
ws2="$(diag_alloc_workspace "$ws_home" "$(id -un)")"
[ -n "$ws2" ] && [ "$ws1" != "$ws2" ] \
  && ok "UAT-8f: every run gets its own unique workspace" \
  || bad "UAT-8f: workspace allocation is not unique"
[ "$(stat -c %a "$ws1" 2>/dev/null)" = 700 ] \
  && ok "UAT-8f: the workspace is private (0700)" \
  || bad "UAT-8f: the workspace mode is not 0700 ($(stat -c %a "$ws1" 2>/dev/null))"
[ "$(stat -c %U "$ws1" 2>/dev/null)" = "$(id -un)" ] \
  && ok "UAT-8f: the workspace is owned by the agent user" \
  || bad "UAT-8f: the workspace owner is wrong"
# a symlinked workroot that escapes the canonical home is refused
mv "$ws_home/work" "$ws_home/work.real"
ln -s /tmp "$ws_home/work"
if diag_alloc_workspace "$ws_home" "$(id -un)" >/dev/null 2>&1; then
  bad "UAT-8f: a workroot escaping the canonical home was accepted"
else
  ok "UAT-8f: a workroot escaping the canonical home is refused"
fi
rm -f "$ws_home/work"; mv "$ws_home/work.real" "$ws_home/work"
if diag_driver_cleanup "$WORK/ws-absent-root" "$ws1"; then
  ok "UAT-8f: the single cleanup owner removes the registered workspace"
else
  bad "UAT-8f: the cleanup owner failed on an owned workspace"
fi
[ ! -e "$ws1" ] && ok "UAT-8f: the removal is verified (the tree is gone)" \
  || bad "UAT-8f: the workspace survived the cleanup owner"
# (12) a failed removal of the OWN workspace is a failure, never a success
ws3="$(diag_alloc_workspace "$ws_home" "$(id -un)")"
mkdir -p "$ws3/locked"; printf 'keep\n' > "$ws3/locked/f.txt"
chmod 0555 "$ws3/locked"
if diag_driver_cleanup "$WORK/ws-absent-root" "$ws3"; then
  bad "UAT-8f RED: an unremovable own workspace was reported as clean"
else
  ok "UAT-8f: a failed own-workspace removal is reported as a failure"
fi
[ -e "$ws3/locked/f.txt" ] \
  && ok "UAT-8f: the unremovable content is intact (nothing force-removed)" \
  || bad "UAT-8f: the locked content vanished"
chmod 0755 "$ws3/locked"
diag_driver_cleanup "$WORK/ws-absent-root" "$ws3" \
  || bad "UAT-8f: the workspace could not be cleaned after unlocking"
[ -n "$(cat "$foreign/precious.txt" 2>/dev/null)" ] \
  && ok "UAT-8f: the foreign workspace still exists after all runs" \
  || bad "UAT-8f: the foreign workspace was removed by the diagnostic"

# --- UAT-8k. the strict D3 factor matrix and the hang-stage evidence --------
# The legacy F-D3-notty probe changed the docker flags, the stdin and the
# payload TOGETHER, so its pass could never prove a single cause. The matrix
# probes share ONE composition owner and ONE payload; only the explicit
# parameters (docker flags, pty wrapper, stdin policy) vary, and the
# diagnosis names a factor only through a controlled single-variable
# comparison. (Kill-after is shortened for these runs: the hang outcomes
# below are rc 124 or 137 alike, only faster.)

mrec() { grep "dhl-$1-" "$DOCKER_REC" | head -1; }
norm_rec() { # strip the deliberately-varied fields; the rest must be equal
  mrec "$1" \
    | sed -e "s/--name dhl-$1-$DIAG_RUNID//" \
          -e "s/--label lab.diagnostic.step=$1//" \
          -e 's|--cidfile [^ ]*||' \
          -e 's/ -it//' -e 's/ -i//' -e 's/ -t//' \
          -e 's/  */ /g'
}

# Run A: the TTY-allocating probes hang (-t and -it), everything else passes
STUB_HANG_WHEN_TTY=1 STUB_HANG_SECONDS=60 run_ladder
unset STUB_HANG_WHEN_TTY STUB_HANG_SECONDS
for probe in F-D3-flag-none F-D3-direct-none F-D3-flag-i F-D3-flag-t \
             F-D3-flag-it F-D3-pty-direct F-D3-stdin-pty F-D3-stdin-null; do
  contains "UAT-8k: the $probe matrix probe ran for the hanging D3" \
    "$probe " "$REPORT"
done
contains "UAT-8m: the no-docker wrapper smoke probe ran and passed" \
  "F-D3-script-smoke PASS rc=0" "$REPORT"
for probe in F-D3-flag-none F-D3-direct-none F-D3-flag-i F-D3-flag-t \
             F-D3-flag-it; do
  rec="$(mrec "$probe")"
  case "$rec" in
    *"--cap-drop ALL"*) ok "UAT-8k: $probe carries the canonical security posture" ;;
    *) bad "UAT-8k: $probe lost the canonical security posture" ;;
  esac
  case "$rec" in
    *"lab.diagnostic.runid=diagrun-"*) ok "UAT-8k: $probe carries the run-identity label" ;;
    *) bad "UAT-8k: $probe lost the run-identity label" ;;
  esac
  case "$rec" in
    *"-e DOCKER_HELPER_SESSION_TOKEN"*) ok "UAT-8k: $probe carries the canonical Session bearer" ;;
    *) bad "UAT-8k: $probe lost the Session bearer env" ;;
  esac
  case "$rec" in
    *"--init -v"*) ok "UAT-8k: $probe carries the verified init copy" ;;
    *) bad "UAT-8k: $probe lost the verified init copy" ;;
  esac
  case "$rec" in
    *"$WS:/workspace:Z"*) ok "UAT-8k: $probe carries the canonical workspace mount" ;;
    *) bad "UAT-8k: $probe lost the canonical workspace mount" ;;
  esac
  case "$rec" in
    *"-c echo D3_OK"*) ok "UAT-8k: $probe uses the identical safe payload" ;;
    *) bad "UAT-8k: $probe does not use the identical safe payload: $rec" ;;
  esac
  case "$rec" in
    *"test -t 0"*) bad "UAT-8k RED: $probe varied the payload" ;;
    *) ok "UAT-8k: $probe does not vary the payload" ;;
  esac
done
r_none="$(norm_rec F-D3-flag-none)"
r_direct_none="$(norm_rec F-D3-direct-none)"
# the pair differs ONLY in the wrapper; the observed stdin marker (pty under
# the script wrapper, the inherited non-tty stdin when direct) is that
# same wrapper difference, so it is normalized away here
check "UAT-8k: F-D3-direct-none differs from the script no-flag probe ONLY in the wrapper" \
  "$(printf '%s' "$r_none" | sed 's/ stdin=[a-z]*$//')" \
  "$(printf '%s' "$r_direct_none" | sed 's/ stdin=[a-z]*$//')"
for probe in F-D3-flag-i F-D3-flag-t F-D3-flag-it; do
  check "UAT-8k: $probe differs from the no-flag probe ONLY in its flag" \
    "$r_none" "$(norm_rec "$probe")"
done
for probe in F-D3-flag-none F-D3-flag-i F-D3-flag-t F-D3-flag-it; do
  grep -q "dhl-$probe-" "$SCRIPT_REC" \
    && ok "UAT-8k: $probe runs under the canonical script(1) pty wrapper" \
    || bad "UAT-8k: $probe did not run under the pty wrapper"
done
for probe in F-D3-direct-none F-D3-pty-direct F-D3-stdin-pty F-D3-stdin-null; do
  grep -q "dhl-$probe-" "$SCRIPT_REC" \
    && bad "UAT-8k RED: $probe was confounded with the pty wrapper factor" \
    || ok "UAT-8k: $probe runs WITHOUT the pty wrapper (isolated factor)"
  grep -q "dhl-$probe-" "$DOCKER_REC" \
    && ok "UAT-8k: $probe ran docker directly" \
    || bad "UAT-8k: $probe never ran docker"
done
case "$(mrec F-D3-flag-none)" in
  *" stdin=pty"*) ok "UAT-8k: the flag probes share one pty stdin policy" ;;
  *) bad "UAT-8k: the flag probes did not run with a pty stdin" ;;
esac
case "$(mrec F-D3-stdin-null)" in
  *" stdin=notty"*) ok "UAT-8k: the closed-stdin probe used /dev/null stdin" ;;
  *) bad "UAT-8k RED: the closed-stdin probe did not close its stdin" ;;
esac
contains "UAT-8k: the -t diagnosis is named by the controlled comparison" \
  "DIAGNOSIS: the D3 docker -t flag is implicated" "$REPORT"
contains "UAT-8k: the hanging -t probe is a timeout, never a false pass" \
  "F-D3-flag-t FAIL rc=1" "$REPORT"
contains "UAT-8k: the -i probe passes under the identical probe" \
  "F-D3-flag-i PASS rc=0" "$REPORT"
contains "UAT-8k: the no-flag probe passes under the identical probe" \
  "F-D3-flag-none PASS rc=0" "$REPORT"
not_contains "UAT-8k RED: the incomparable notty probe never names the cause" \
  "the D3-notty factor is implicated" "$REPORT"
grep -qE '^D3 FAIL rc=1(24|37) elapsed=.* detail=timeout hang=running' <<<"$REPORT" \
  && ok "UAT-8k: the canonical D3 timeout carries the observed container state" \
  || bad "UAT-8k: the D3 timeout line lost the hang-stage observation"
grep -qE '^F-D3-flag-t FAIL rc=1(24|37) elapsed=.* detail=timeout hang=running' <<<"$REPORT" \
  && ok "UAT-8k: the matrix timeout carries the observed container state" \
  || bad "UAT-8k: the matrix timeout line lost the hang-stage observation"
if grep -E '^F-D3-flag-i PASS' <<<"$REPORT" | grep -q 'hang='; then
  bad "UAT-8k: a passing probe carried hang-state text"
else
  ok "UAT-8k: no hang-state text on a passing probe"
fi
if grep -q "dhs_TEST $WS" "$DH_SESSIONS" 2>/dev/null; then
  bad "UAT-8k RED: a matrix probe leaked its Session"
else
  ok "UAT-8k: every matrix probe recovered its own Session"
fi
# UAT-8l scenarios 2 and 4: the passing probes and the hung -t probe all
# carry a CONFIRMED cleanup verdict, so their results are valid evidence
case "$(cat "$WORK/evid/F-D3-flag-i.session" 2>/dev/null)" in
  clean|reaped)
    ok "UAT-8l: the passing -i probe's cleanup is confirmed (a validated PASS)" ;;
  *)
    bad "UAT-8l: the passing -i probe's cleanup verdict is unconfirmed: $(cat "$WORK/evid/F-D3-flag-i.session" 2>/dev/null || echo missing)" ;;
esac
case "$(cat "$WORK/evid/F-D3-flag-t.session" 2>/dev/null)" in
  clean|reaped)
    ok "UAT-8l: the hung -t probe's cleanup is confirmed (attribution evidence is valid)" ;;
  *)
    bad "UAT-8l: the hung -t probe's cleanup verdict is unconfirmed: $(cat "$WORK/evid/F-D3-flag-t.session" 2>/dev/null || echo missing)" ;;
esac

# Run B: only the -it combination hangs (the old single-pass rule would
# have misattributed this to the multi-variable notty probe)
STUB_HANG_DFLAG='-it' STUB_HANG_SECONDS=60 run_ladder
unset STUB_HANG_DFLAG STUB_HANG_SECONDS
contains "UAT-8k: the -it combination is named when only the combination hangs" \
  "DIAGNOSIS: the D3 docker -it flag combination is implicated" "$REPORT"
not_contains "UAT-8k RED: the old single-pass rule no longer misattributes notty" \
  "the D3-notty factor is implicated" "$REPORT"
contains "UAT-8k: the -i probe passes when only the combination hangs" \
  "F-D3-flag-i PASS rc=0" "$REPORT"
contains "UAT-8k: the -t probe passes when only the combination hangs" \
  "F-D3-flag-t PASS rc=0" "$REPORT"

# Run C: contradictory/inconclusive evidence — the diagnosis stays
# UNRESOLVED and the notty pass is stated as preliminary OBSERVED evidence
STUB_HANG_WHEN_TTY=1 STUB_HANG_DFLAG='-i' STUB_HANG_SECONDS=60 run_ladder
unset STUB_HANG_WHEN_TTY STUB_HANG_DFLAG STUB_HANG_SECONDS
contains "UAT-8k: the preliminary notty evidence is stated as OBSERVED" \
  "DIAG OBSERVED: F-D3-notty passed (preliminary evidence only" "$REPORT"
contains "UAT-8k: inconclusive matrix evidence stays UNRESOLVED" \
  "DIAGNOSIS UNRESOLVED: the failing step is D3" "$REPORT"
not_contains "UAT-8k: nothing is implicated without a controlled comparison" \
  "is implicated" "$REPORT"

# Run D: only the -i flag hangs -> the -i diagnosis
STUB_HANG_DFLAG='-i -it' STUB_HANG_SECONDS=60 run_ladder
unset STUB_HANG_DFLAG STUB_HANG_SECONDS
contains "UAT-8k: the -i diagnosis is named by the controlled comparison" \
  "DIAGNOSIS: the D3 docker -i flag is implicated" "$REPORT"
contains "UAT-8k: the -t probe passes when -i hangs" \
  "F-D3-flag-t PASS rc=0" "$REPORT"

# Run E: everything hangs -> the new direct-none observation upgrades the
# hopeless matrix: docker hangs even WITHOUT the wrapper (UAT-8m rule C),
# so the run no longer reports UNRESOLVED and implicates no flag/wrapper
STUB_HANG_PAYLOAD="D3_OK" STUB_HANG_SECONDS=60 run_ladder
unset STUB_HANG_PAYLOAD STUB_HANG_SECONDS
grep -qE '^F-D3-direct-none FAIL rc=1(24|37) elapsed=.* detail=timeout' <<<"$REPORT" \
  && ok "UAT-8m: the direct no-flag probe really hung in the all-hung run" \
  || bad "UAT-8m: the direct-none probe did not hang"
contains "UAT-8m: docker hanging directly is stated even when every probe hung" \
  "DIAGNOSIS: docker hangs even when invoked directly without the nested script wrapper" "$REPORT"
not_contains "UAT-8m: the direct observation replaces UNRESOLVED" \
  "DIAGNOSIS UNRESOLVED" "$REPORT"
not_contains "UAT-8k: a hopeless matrix implicates no flag or wrapper" \
  "is implicated" "$REPORT"

# Run F: the CLI hung before creating the container -> no-cidfile, and no
# removal is authorized by an unproven identity
STUB_HANG_BEFORE_CREATE=1 STUB_HANG_SECONDS=60 run_ladder
unset STUB_HANG_BEFORE_CREATE STUB_HANG_SECONDS
grep -qE '^D0 FAIL rc=1(24|37) elapsed=.* detail=timeout hang=no-cidfile' <<<"$REPORT" \
  && ok "UAT-8k: a CLI hang before container creation is localized (no-cidfile)" \
  || bad "UAT-8k: the no-cidfile hang stage was not reported: $(grep '^D0 ' <<<"$REPORT")"
check "UAT-8k: nothing needed recovery on a no-cidfile hang" \
  "clean" "$(cat "$WORK/evid/D0.reap")"
if grep -qE '^rm ' "$DOCKER_REC"; then
  bad "UAT-8k RED: a removal happened without any container identity"
else
  ok "UAT-8k: a no-cidfile hang authorizes no removal"
fi

# the bounded hang-state observation, exercised directly on the stubbed
# daemon boundary: every class is produced by a real observation, never a
# guess, and the state answer is accepted only from the fixed allowlist
hs_evid="$WORK/hs-evid"; mkdir -p "$hs_evid"
hs_cid="feed0000$(printf 'f%.0s' {1..56})"
printf '%s\n' "$hs_cid" >> "$CIDS"
( export DIAG_DIR="$hs_evid" DIAG_RUNID=diagrun-hs DIAG_IMAGE="$_OC_BASE"
  printf '%s' "$hs_cid" > "$hs_evid/hs.cid"
  diag_capture_hang_state HS "$hs_evid/hs.cid" )
check "UAT-8k: a live owned container is observed as running" \
  "running" "$(cat "$hs_evid/HS.hangstate")"
( export DIAG_DIR="$hs_evid" DIAG_RUNID=diagrun-hs DIAG_IMAGE="$_OC_BASE" \
    STUB_INSPECT_STATUS=exited
  diag_capture_hang_state HE "$hs_evid/hs.cid" )
check "UAT-8k: an exited container is observed as exited" \
  "exited" "$(cat "$hs_evid/HE.hangstate")"
( export DIAG_DIR="$hs_evid" DIAG_RUNID=diagrun-hs DIAG_IMAGE="$_OC_BASE" \
    STUB_INSPECT_STATUS=definitely-not-a-state
  diag_capture_hang_state HW "$hs_evid/hs.cid" )
check "UAT-8k: a non-allowlisted state is unknown, never echoed" \
  "unknown" "$(cat "$hs_evid/HW.hangstate")"
( export DIAG_DIR="$hs_evid" DIAG_RUNID=diagrun-hs DIAG_IMAGE="$_OC_BASE" \
    STUB_HANG_INSPECT=1 STUB_HANG_SECONDS=60 DIAG_RECOVERY_BOUND=2 DIAG_KILL_AFTER=1
  printf '%s' "$hs_cid" > "$hs_evid/hu.cid"
  diag_capture_hang_state HU "$hs_evid/hu.cid" )
check "UAT-8k: an unattributable container is recorded unattributed" \
  "unattributed" "$(cat "$hs_evid/HU.hangstate")"
( export DIAG_DIR="$hs_evid" DIAG_RUNID=diagrun-hs DIAG_IMAGE="$_OC_BASE"
  printf '%s' "cafe0000$(printf 'a%.0s' {1..56})" > "$hs_evid/ab.cid"
  diag_capture_hang_state AB "$hs_evid/ab.cid" )
check "UAT-8k: a proven-absent container is recorded absent" \
  "absent" "$(cat "$hs_evid/AB.hangstate")"
( export DIAG_DIR="$hs_evid" DIAG_RUNID=diagrun-hs DIAG_IMAGE="$_OC_BASE" \
    STUB_HANG_PS=1 STUB_HANG_SECONDS=60 DIAG_RECOVERY_BOUND=2 DIAG_KILL_AFTER=1
  printf '%s' "$hs_cid" > "$hs_evid/uk.cid"
  diag_capture_hang_state UK "$hs_evid/uk.cid" )
check "UAT-8k: a failed existence observation stays unknown" \
  "unknown" "$(cat "$hs_evid/UK.hangstate")"
( export DIAG_DIR="$hs_evid" DIAG_RUNID=diagrun-hs DIAG_IMAGE="$_OC_BASE"
  : > "$hs_evid/nc.cid"
  diag_capture_hang_state NC "$hs_evid/nc.cid" )
check "UAT-8m: an empty cidfile WITHOUT docker-invocation evidence is no-cidfile" \
  "no-cidfile" "$(cat "$hs_evid/NC.hangstate")"
( export DIAG_DIR="$hs_evid" DIAG_RUNID=diagrun-hs DIAG_IMAGE="$_OC_BASE"
  printf '%s\n' before-docker-exec > "$hs_evid/UD.phases"
  : > "$hs_evid/UD.cid"
  diag_capture_hang_state UD "$hs_evid/UD.cid" )
check "UAT-8m: a recorded docker invocation without a cidfile stays UNKNOWN" \
  "unknown" "$(cat "$hs_evid/UD.hangstate")"
( export DIAG_DIR="$hs_evid" DIAG_RUNID=diagrun-hs DIAG_IMAGE="$_OC_BASE"
  printf '%s\n' wrapper-entered > "$hs_evid/WE.phases"
  : > "$hs_evid/WE.cid"
  diag_capture_hang_state WE "$hs_evid/WE.cid" )
check "UAT-8m: the wrapper entering its command without docker is still no-cidfile" \
  "no-cidfile" "$(cat "$hs_evid/WE.hangstate")"

# source-level invariants for the new owners
lib_has "UAT-8k: the lib owns the hang-stage capture" 'diag_capture_hang_state'
lib_has "UAT-8k: the report distinguishes OBSERVED from IMPLICATED" 'DIAG OBSERVED'
lib_has "UAT-8k: the matrix probes use one composition owner" '_diag_d3_compose_argv'
probe_body="$(sed -n '/^_diag_d3_probe()/,/^}/p' "$LIB")"
case "$probe_body" in
  *"run --rm"*) bad "UAT-8k RED: the legacy probe still assembles its own docker argv" ;;
  *) ok "UAT-8k: the legacy probe assembles nothing outside the composition owner" ;;
esac
case "$probe_body" in
  *"test -t 0"*) ok "UAT-8k: the legacy probes keep their declared payloads" ;;
  *) bad "UAT-8k: the legacy probe lost its payload selection" ;;
esac
matrix_body="$(sed -n '/^_diag_d3_matrix_probe()/,/^}/p' "$LIB")"
case "$matrix_body" in
  *"test -t 0"*) bad "UAT-8k RED: the matrix probe varies the payload" ;;
  *) ok "UAT-8k: the matrix payload is fixed (echo D3_OK)" ;;
esac
case "$matrix_body" in
  *"_diag_d3_compose_argv"*) ok "UAT-8k: the matrix probe composes through the shared owner" ;;
  *) bad "UAT-8k: the matrix probe bypassed the composition owner" ;;
esac
diag_body="$(sed -n '/^diag_exec()/,/^}/p' "$LIB")"
case "$diag_body" in
  *"diag_capture_hang_state"*) ok "UAT-8k: diag_exec captures the hang state on a timeout" ;;
  *) bad "UAT-8k: diag_exec does not capture the hang state" ;;
esac

# --- UAT-8l. cleanup-gated evidence and consistent D3 inference --------------
# A D3 probe's docker result is a usable PASS only when its mandatory
# cleanup is CONFIRMED (clean/reaped); an unconfirmed cleanup is a separate
# diagnostic FAIL that voids the evidence and stops further new matrix
# probes. A -t/-i attribution must additionally be consistent with the
# combined -it probe, otherwise the diagnosis stays UNRESOLVED.

# Scenario 1: a PASSING probe whose cleanup FAILS is not a PASS and is no
# diagnosis basis; the measured timeout evidence of the hung probes stays
# visible, and the unconfirmed cleanup stops all further new matrix probes
STUB_HANG_WHEN_TTY=1 STUB_KEEP_NAME_PREFIX='dhl-F-D3-' STUB_RM_FAIL=1 \
  STUB_HANG_SECONDS=60 run_ladder
unset STUB_HANG_WHEN_TTY STUB_KEEP_NAME_PREFIX STUB_RM_FAIL STUB_HANG_SECONDS
grep -qE '^F-D3-notty FAIL rc=0 elapsed=.* detail=cleanup-failed$' <<<"$REPORT" \
  && ok "UAT-8l: a docker pass with a failed cleanup is a FAIL naming the cleanup" \
  || bad "UAT-8l RED: a cleanup-failed probe stayed a PASS: $(grep '^F-D3-notty ' <<<"$REPORT")"
not_contains "UAT-8l: a cleanup-failed probe is never reported as PASS" \
  "F-D3-notty PASS" "$REPORT"
check "UAT-8l: the cleanup verdict behind the demoted pass is recorded" \
  "failed" "$(cat "$WORK/evid/F-D3-notty.session" 2>/dev/null || echo missing)"
grep -qE '^F-D3-nosession FAIL rc=1(24|37) elapsed=.* detail=timeout' <<<"$REPORT" \
  && ok "UAT-8l: a hung probe keeps its measured timeout detail" \
  || bad "UAT-8l: the hung probe's timeout evidence was hidden: $(grep '^F-D3-nosession ' <<<"$REPORT")"
for probe in F-D3-direct-none F-D3-flag-none F-D3-flag-i F-D3-flag-t \
             F-D3-flag-it F-D3-pty-direct F-D3-stdin-pty F-D3-stdin-null; do
  not_contains "UAT-8l: the unconfirmed cleanup stopped $probe" \
    "$probe " "$REPORT"
done
contains "UAT-8l: the cleanup-gated matrix stays UNRESOLVED" \
  "DIAGNOSIS UNRESOLVED: the failing step is D3" "$REPORT"
not_contains "UAT-8l: cleanup-failed evidence implicates nothing" \
  "is implicated" "$REPORT"
check "UAT-8l: the cleanup-gated ladder exits nonzero" "1" "$LRC"

# Scenario 3: the -t probe hangs while the combined -it probe PASSES — the
# -t hypothesis is contradicted by its own combination, so nothing may be
# implicated (on the pre-8l code the -t rule fired on this contradiction)
STUB_HANG_CANON=1 STUB_HANG_DFLAG='-t' STUB_HANG_SECONDS=60 run_ladder
unset STUB_HANG_CANON STUB_HANG_DFLAG STUB_HANG_SECONDS
grep -qE '^D3 FAIL rc=1(24|37) elapsed=.* detail=timeout hang=running' <<<"$REPORT" \
  && ok "UAT-8l: the canonical D3 hang is observed at its container stage" \
  || bad "UAT-8l: the canonical hang was not localized: $(grep '^D3 ' <<<"$REPORT")"
grep -qE '^F-D3-flag-t FAIL rc=1(24|37) elapsed=.* detail=timeout' <<<"$REPORT" \
  && ok "UAT-8l: the -t probe really hung in the contradiction scenario" \
  || bad "UAT-8l: the -t probe did not hang"
contains "UAT-8l: the combined -it probe passed while -t hung" \
  "F-D3-flag-it PASS rc=0" "$REPORT"
contains "UAT-8l: the contradictory matrix states the notty evidence as OBSERVED" \
  "DIAG OBSERVED: F-D3-notty passed (preliminary evidence only" "$REPORT"
contains "UAT-8l: a contradicted -t hypothesis stays UNRESOLVED" \
  "DIAGNOSIS UNRESOLVED: the failing step is D3" "$REPORT"
not_contains "UAT-8l RED: -t is never implicated against a passing -it" \
  "is implicated" "$REPORT"

# --- UAT-8m. wrapper/docker isolation and phase evidence ---------------------
# The missing D3 cause evidence: does the nested script(1) wrapper itself
# hang, or does docker hang under it (or even without it)? Two minimal
# probes answer this: the no-docker wrapper smoke (a fixed printf inside
# script(1)) and F-D3-direct-none (the IDENTICAL no-flag composition with
# docker invoked directly). Fixed phase markers (wrapper-entered /
# before-docker-exec) are written into the private evidence only, and a
# recorded docker invocation without a cidfile stays unknown, never
# "no create happened".

# Scenario M-B: every script(1)-wrapped docker probe hangs while the
# IDENTICAL direct no-flag probe and the no-docker smoke pass -> docker
# hangs under the wrapper (UAT-8m rule B)
STUB_HANG_WHEN_PTY_STDIN=1 STUB_HANG_DFLAG='-it' STUB_HANG_SECONDS=60 run_ladder
unset STUB_HANG_WHEN_PTY_STDIN STUB_HANG_DFLAG STUB_HANG_SECONDS
grep -qE '^D3 FAIL rc=1(24|37) elapsed=.* detail=timeout' <<<"$REPORT" \
  && ok "UAT-8m: the canonical D3 hang triggered the M-B probes" \
  || bad "UAT-8m: the canonical D3 did not hang in M-B"
contains "UAT-8m: the no-docker smoke passes while the script probes hang" \
  "F-D3-script-smoke PASS rc=0" "$REPORT"
contains "UAT-8m: the identical direct no-flag probe passed where the script probe hung" \
  "F-D3-direct-none PASS rc=0" "$REPORT"
grep -qE '^F-D3-flag-none FAIL rc=1(24|37) elapsed=.* detail=timeout' <<<"$REPORT" \
  && ok "UAT-8m: the script-wrapped no-flag probe really hung in M-B" \
  || bad "UAT-8m: the script no-flag probe did not hang in M-B"
contains "UAT-8m: docker under the wrapper is named by the direct pair" \
  "DIAGNOSIS: docker hangs under the nested script(1) wrapper (F-D3-flag-none hung where the identical F-D3-direct-none passed" \
  "$REPORT"
not_contains "UAT-8m: the M-B pair leaves nothing UNRESOLVED" \
  "DIAGNOSIS UNRESOLVED" "$REPORT"
check "UAT-8m: the phase markers carry exactly the two fixed markers, nothing else" \
  "$(printf 'wrapper-entered\nbefore-docker-exec')" \
  "$(cat "$WORK/evid/F-D3-flag-none.phases" 2>/dev/null || echo missing)"

# Scenario M-C: the same setup, but the DIRECT no-flag probe hangs too ->
# docker hangs even without the wrapper; the wrapper is excluded (rule C)
STUB_HANG_WHEN_PTY_STDIN=1 STUB_HANG_DFLAG='-it' STUB_HANG_NOFLAGS_NOTTY=1 \
  STUB_HANG_SECONDS=60 run_ladder
unset STUB_HANG_WHEN_PTY_STDIN STUB_HANG_DFLAG STUB_HANG_NOFLAGS_NOTTY \
  STUB_HANG_SECONDS
grep -qE '^F-D3-direct-none FAIL rc=1(24|37) elapsed=.* detail=timeout' <<<"$REPORT" \
  && ok "UAT-8m: the direct no-flag probe really hung in M-C" \
  || bad "UAT-8m: the direct-none probe did not hang in M-C"
contains "UAT-8m: docker hanging directly is named and the wrapper excluded" \
  "DIAGNOSIS: docker hangs even when invoked directly without the nested script wrapper" "$REPORT"
not_contains "UAT-8m: the M-C direct observation leaves nothing UNRESOLVED" \
  "DIAGNOSIS UNRESOLVED" "$REPORT"
not_contains "UAT-8m: the M-C wrapper exclusion implicates nothing else" \
  "is implicated" "$REPORT"

# Scenario M-A: the no-docker smoke probe itself times out (the script(1)
# shim hangs exactly the smoke) while every script(1)-wrapped docker probe
# hangs too and the direct probes pass -> the wrapper itself hangs, and the
# script-wrapped docker evidence is void (the -t rule must NOT fire even
# though the -t probe hung)
SMOKE_HANG_SHIM=1 STUB_HANG_WHEN_PTY_STDIN=1 STUB_HANG_WHEN_TTY=1 \
  STUB_HANG_SECONDS=60 run_ladder
unset SMOKE_HANG_SHIM STUB_HANG_WHEN_PTY_STDIN STUB_HANG_WHEN_TTY \
  STUB_HANG_SECONDS
grep -qE '^F-D3-script-smoke FAIL rc=1(24|37) elapsed=.* detail=timeout' <<<"$REPORT" \
  && ok "UAT-8m: the no-docker smoke probe really timed out" \
  || bad "UAT-8m: the smoke probe did not time out"
if [ -e "$WORK/evid/F-D3-script-smoke.phases" ]; then
  bad "UAT-8m RED: phase markers exist although the wrapper never ran its command"
else
  ok "UAT-8m: a wrapper hang before its command leaves no phase evidence"
fi
contains "UAT-8m: a hanging no-docker wrapper is named by the smoke probe" \
  "DIAGNOSIS: the D3 nested script(1) wrapper itself hangs" "$REPORT"
not_contains "UAT-8m RED: a broken wrapper voids the script-wrapped flag evidence" \
  "the D3 docker -t flag is implicated" "$REPORT"
not_contains "UAT-8m: the smoke verdict implicates no docker factor" \
  "is implicated" "$REPORT"
check "UAT-8m: the smoke-hang ladder exits nonzero" "1" "$LRC"

# Scenario M-D (contradiction): the script-wrapped no-flag probe PASSED
# while the direct no-flag probe hung — the observations contradict each
# other, so only UNRESOLVED may be reported
STUB_HANG_CANON=1 STUB_HANG_NOFLAGS_NOTTY=1 STUB_HANG_SECONDS=60 run_ladder
unset STUB_HANG_CANON STUB_HANG_NOFLAGS_NOTTY STUB_HANG_SECONDS
contains "UAT-8m: the contradictory script no-flag PASS is observed" \
  "F-D3-flag-none PASS rc=0" "$REPORT"
grep -qE '^F-D3-direct-none FAIL rc=1(24|37) elapsed=.* detail=timeout' <<<"$REPORT" \
  && ok "UAT-8m: the contradictory direct no-flag FAIL is observed" \
  || bad "UAT-8m: the direct-none probe did not hang in M-D"
contains "UAT-8m: contradictory wrapper observations stay UNRESOLVED" \
  "DIAGNOSIS UNRESOLVED: the failing step is D3" "$REPORT"
not_contains "UAT-8m: a contradiction implicates nothing" \
  "is implicated" "$REPORT"

# --- UAT-8g. the real runner chain (driver -> runner -> library -> launcher) -
# The runner is executed as a REAL child bash with a PRIVATE HOME: the harness
# never pre-loads the launcher into the test shell, so a stale installed
# launcher reproduces the original 8f drift failure end to end
# ('_oc_security_opts: command not found' -> D0 FAIL detail=composition-refused).
# The launcher refresh runs through the SAME canonical command the driver
# runs (setup-agent-user.sh --install-launcher-only), never a copy.
RUNNER_BODY="$WORK/runner-body.sh"
sed -n "/^cat > \"\$RUNNER\" <<'SH'\$/,/^SH\$/p" "$DRIVER" | sed '1d;$d' \
  > "$RUNNER_BODY"
[ -s "$RUNNER_BODY" ] \
  && ok "UAT-8g: the runner body is extracted from the real driver" \
  || bad "UAT-8g: the runner body extraction failed"

# the canonical /opt/lab content the freshly copied lab scripts represent
OPTLAB="$WORK/optlab"; mkdir -p "$OPTLAB"
cp "$SRC_DIR/lab/lab-diag-lib.sh" "$OPTLAB/lab-diag-lib.sh"
cp "$SRC_DIR/lab/agent-aliases.sh" "$OPTLAB/agent-aliases.sh"
cp "$SRC_DIR/lab/lab-mount-gate.sh" "$OPTLAB/lab-mount-gate.sh"

# the launcher refresh, through the canonical installer in launcher-only mode
LABCOPY="$WORK/labcopy"; mkdir -p "$LABCOPY"
for f in "$SRC_DIR"/lab/*.sh; do cp "$f" "$LABCOPY/"; done
cat > "$LABCOPY/lab-vm-guard.sh" <<'SH'
require_lab_vm() { [ -r "${LAB_VM_TEST_MARKER:?}" ] || exit 1; }
SH
: > "$WORK/syncmarker"
SYNCSHIM="$WORK/syncshim"; mkdir -p "$SYNCSHIM"
sync_real_stat="$(command -v stat)"
cat > "$SYNCSHIM/id" <<'SH'
#!/bin/sh
[ "${1:-}" = "-u" ] && { echo 0; exit 0; }
exit 0
SH
cat > "$SYNCSHIM/chown" <<'SH'
#!/bin/sh
exit 0
SH
cat > "$SYNCSHIM/install" <<'SH'
#!/bin/sh
d=0; mode=""
while [ $# -gt 0 ]; do
  case "$1" in
    -d) d=1; shift ;;
    -m) shift; mode="$1"; shift ;;
    -o|-g) shift 2 ;;
    --) shift ;;
    *) break ;;
  esac
done
if [ "$d" = 1 ]; then
  for p in "$@"; do mkdir -p "$p"; [ -n "$mode" ] && chmod "$mode" "$p"; done
elif [ "$#" = 2 ]; then
  cp "$1" "$2"; [ -n "$mode" ] && chmod "$mode" "$2"
fi
SH
cat > "$SYNCSHIM/stat" <<SH
#!/bin/sh
case "\$1 \$2" in
  "-c %U") echo agent; exit 0 ;;
  "-c %G") echo agent; exit 0 ;;
  "-c %a") exec "$sync_real_stat" -c %a -- "\$3" ;;
esac
exit 1
SH
chmod 0755 "$SYNCSHIM"/*
SYNC_OUT=""
sync_launcher() { # AGENT_HOME -> rc; the SAME canonical command the driver runs
  SYNC_OUT="$(
    export PATH="$SYNCSHIM:$PATH" AGENT_HOME="$1"
    export LAB_VM_TEST_MARKER="$WORK/syncmarker"
    bash "$LABCOPY/setup-agent-user.sh" --install-launcher-only 2>&1
  )"
  return $?
}

run_real_runner() { # AGENT_HOME EVID WS -> rc (output in RUNNER_OUT)
  RUNNER_OUT="$(
    export HOME="$1" DIAG_OPTLAB="$OPTLAB"
    export OPENCODE_DOCKER_HOME="$1/.opencode-docker"
    export LAB_DOCKER_INIT_CANDIDATES="$SHIM/docker-init"
    mkdir -p "$OPENCODE_DOCKER_HOME/.config" "$OPENCODE_DOCKER_HOME/.local/share" \
             "$OPENCODE_DOCKER_HOME/.local/state" "$OPENCODE_DOCKER_HOME/.cache" \
             "$OPENCODE_DOCKER_HOME/tmp"
    bash "$RUNNER_BODY" "$2" "$3" 2>&1
  )"
  return "$?"
}
reset_runner_state() {
  mkdir -p "$2" 2>/dev/null
  : > "$DH_REC"; : > "$DOCKER_REC"; : > "$SCRIPT_REC"
  : > "$DH_LIST_COUNT"; : > "$CIDS"; : > "$CIDMAP"; : > "$DH_SESSIONS"
}

# the stale installed launcher: the pinned reference is present, the shared
# configuration owners the current diagnostic library expects are NOT
stale_home="$WORK/stale-home"; mkdir -p "$stale_home"
cat > "$stale_home/.bash_aliases" <<EOF
_OC_BASE='$_OC_BASE'
oc()      { docker run --rm -it "\$_OC_BASE" "\$@"; }
oc-go26() { docker run --rm -it "\$_OC_BASE" "\$@"; }
oc-probe() { docker run --rm "\$_OC_BASE" "\$@"; }
EOF

# (RED 1-3) the PRE-FIX runner semantics (source without status checks, no
# preflight) against the stale launcher reproduce the real 8f failure exactly
stale_evid="$WORK/prefix-evid"; reset_runner_state x "$stale_evid"
prefix_out="$(
  export HOME="$stale_home" DIAG_OPTLAB="$OPTLAB" DIAG_RUNID=diagrun-prefix
  export DIAG_DIR="$stale_evid" OPENCODE_DOCKER_HOME="$stale_home/.opencode-docker"
  export LAB_DOCKER_INIT_CANDIDATES="$SHIM/docker-init"
  cd "$WS" || exit 9
  bash -c 'set -u
    source "$HOME/.bash_aliases"
    source "$DIAG_OPTLAB/lab-diag-lib.sh"
    diag_run_ladder "$_OC_BASE" "$PWD" "$DIAG_RUNID"' 2>&1
)"
prefix_rc=$?
contains "UAT-8g RED: the pre-fix runner reproduces the original '_oc_security_opts: command not found'" \
  "_oc_security_opts: command not found" "$prefix_out"
contains "UAT-8g RED: the drift was masked as composition-refused" \
  "D0 FAIL rc=refused elapsed=unknown detail=composition-refused" "$prefix_out"
contains "UAT-8g RED: the drifted run reported UNRESOLVED" \
  "DIAGNOSIS UNRESOLVED" "$prefix_out"
[ "$prefix_rc" != 0 ] \
  && ok "UAT-8g RED: the drifted runner exits nonzero" \
  || bad "UAT-8g: the drifted runner reported success"

# the CURRENT runner against the SAME stale launcher: fail-closed loader-drift
# with ZERO docker runs, never a masked composition refusal
stale_evid="$WORK/stale-evid"; reset_runner_state x "$stale_evid"
run_real_runner "$stale_home" "$stale_evid" "$WS"; rr_rc=$?
[ "$rr_rc" != 0 ] \
  && ok "UAT-8g: the current runner fails closed on the stale launcher" \
  || bad "UAT-8g RED: the current runner tolerated the stale launcher"
contains "UAT-8g: the drift is named loader-drift (cmp with the canonical source)" \
  "FAIL loader-drift:" "$RUNNER_OUT"
not_contains "UAT-8g: the drift is never masked as composition-refused" \
  "composition-refused" "$RUNNER_OUT"
not_contains "UAT-8g: the drift is never masked as UNRESOLVED" \
  "UNRESOLVED" "$RUNNER_OUT"
if grep -q " run " "$DOCKER_REC" 2>/dev/null; then
  bad "UAT-8g RED: docker ran although the launcher preflight failed"
else
  ok "UAT-8g: zero docker runs on a failed launcher preflight"
fi

# the preflight's function-level check itself: the stale launcher in a shell
# that bypasses the cmp (functions loaded) reports the exact missing owner
fn_out="$(bash -c 'source "$1"; source "$2"; diag_verify_launcher_loaded' \
  _ "$stale_home/.bash_aliases" "$OPTLAB/lab-diag-lib.sh" 2>&1)"
fn_rc=$?
[ "$fn_rc" != 0 ] \
  && ok "UAT-8g: the preflight rejects a shell with the stale launcher" \
  || bad "UAT-8g: the preflight accepted the stale launcher"
contains "UAT-8g: the preflight names the missing shared owner" \
  "FAIL loader-drift: _oc_security_opts is not loaded" "$fn_out"

# (GREEN 4) the canonical launcher refresh installs the CURRENT launcher; the
# runner preflight then passes and the ladder runs to D4
fresh_home="$WORK/fresh-home"; mkdir -p "$fresh_home"
sync_launcher "$fresh_home" \
  && ok "UAT-8g: the canonical launcher refresh succeeds in the runner harness" \
  || bad "UAT-8g: the canonical launcher refresh failed: $SYNC_OUT"
cmp -s "$fresh_home/.bash_aliases" "$OPTLAB/agent-aliases.sh" \
  && ok "UAT-8g: the refreshed aliases are byte-identical to the canonical source" \
  || bad "UAT-8g: the refreshed aliases diverge from the canonical source"
cmp -s "$fresh_home/.opencode-docker/lib/lab-mount-gate.sh" "$SRC_DIR/lab/lab-mount-gate.sh" \
  && ok "UAT-8g: the refreshed gate library is byte-identical to the canonical source" \
  || bad "UAT-8g: the refreshed gate library diverges from the canonical source"
fresh_evid="$WORK/fresh-evid"; reset_runner_state x "$fresh_evid"
run_real_runner "$fresh_home" "$fresh_evid" "$WS"; rr_rc=$?
[ "$rr_rc" = 0 ] \
  && ok "UAT-8g: the runner passes the preflight and the ladder after the refresh" \
  || bad "UAT-8g RED: the refreshed runner failed (rc $rr_rc): $RUNNER_OUT"
contains "UAT-8g: D0 runs after the verified preflight" "D0 PASS rc=0" "$RUNNER_OUT"
contains "UAT-8g: D3 runs on the canonical launcher" "D3 PASS rc=0" "$RUNNER_OUT"
contains "UAT-8g: D4 runs on the canonical launcher" "D4 PASS rc=0" "$RUNNER_OUT"

# (9) ONE launcher version for D0-D2 and D3/D4: the runner pins DC_ALIASES to
# the file it loaded, so even a hijacked DC_ALIASES in the environment cannot
# give the child processes a different launcher; the D3 child proves the
# canonical configuration owners ran (their argv signature)
stale_evid="$WORK/hijack-evid"; reset_runner_state x "$stale_evid"
RUNNER_OUT="$(
  export HOME="$fresh_home" DIAG_OPTLAB="$OPTLAB" DC_ALIASES="$stale_home/.bash_aliases"
  export OPENCODE_DOCKER_HOME="$fresh_home/.opencode-docker"
  export LAB_DOCKER_INIT_CANDIDATES="$SHIM/docker-init"
  bash "$RUNNER_BODY" "$stale_evid" "$WS" 2>&1
)"
hijack_rc=$?
[ "$hijack_rc" = 0 ] \
  && ok "UAT-8g: a hijacked DC_ALIASES cannot drift the child launcher" \
  || bad "UAT-8g: the pinned launcher source did not survive the hijack (rc $hijack_rc): $RUNNER_OUT"
if grep -E "^run .*--cap-drop ALL" "$DOCKER_REC" >/dev/null 2>&1 \
   && grep "dhl-D3-" "$DOCKER_REC" | grep -q -- "--cap-drop ALL"; then
  ok "UAT-8g: the D3 child process ran the canonical launcher owners (--cap-drop ALL)"
else
  bad "UAT-8g: the D3 child did not run the canonical launcher owners"
fi

# (8) a failed mandatory source is a loader-drift failure with zero runs
broken_evid="$WORK/broken-evid"; reset_runner_state x "$broken_evid"
mv "$OPTLAB/lab-diag-lib.sh" "$OPTLAB/lab-diag-lib.sh.hidden"
run_real_runner "$fresh_home" "$broken_evid" "$WS"; rr_rc=$?
mv "$OPTLAB/lab-diag-lib.sh.hidden" "$OPTLAB/lab-diag-lib.sh"
[ "$rr_rc" != 0 ] \
  && ok "UAT-8g: a failed library source fails the runner closed" \
  || bad "UAT-8g: a failed library source was tolerated"
contains "UAT-8g: the failed source is named loader-drift" \
  "FAIL loader-drift: sourcing" "$RUNNER_OUT"
if grep -q " run " "$DOCKER_REC" 2>/dev/null; then
  bad "UAT-8g RED: docker ran although the library source failed"
else
  ok "UAT-8g: zero docker runs after a failed source"
fi

# a launcher that does NOT match the canonical source is refused even when it
# would load (the runner runs without the driver's refresh): only the aliases
# content drifts, the rest of the installed state is intact
drift_home="$WORK/drift-home"; mkdir -p "$drift_home/.opencode-docker/lib"
cp "$fresh_home/.bash_aliases" "$drift_home/.bash_aliases"
printf '# drifted\n' >> "$drift_home/.bash_aliases"
cp "$fresh_home/.opencode-docker/lib/lab-mount-gate.sh" \
   "$drift_home/.opencode-docker/lib/lab-mount-gate.sh"
drift_evid="$WORK/drift-evid"; reset_runner_state x "$drift_evid"
run_real_runner "$drift_home" "$drift_evid" "$WS"; rr_rc=$?
[ "$rr_rc" != 0 ] \
  && ok "UAT-8g: a drifted-but-loadable launcher is refused" \
  || bad "UAT-8g: a drifted launcher was tolerated"
contains "UAT-8g: the drifted launcher refusal names the canonical source" \
  "does not match the canonical" "$RUNNER_OUT"

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
drv_has "the workspace comes from the atomic allocation owner" \
  'diag_alloc_workspace "\$AGENT_HOME" "\$AGENT_USER"'
drv_lacks "no PID-derived predictable workspace name remains" 'diag-\$\$'
drv_lacks "no second rm of the workspace outside the cleanup owner" 'rm -rf -- "\$ws"'
drv_has "the allocated workspace is registered for cleanup" 'DIAG_WS='
drv_has "the cleanup goes through the single owner" 'diag_driver_cleanup "\$DIAG_ROOT" "\$DIAG_WS"'
drv_has "a failed own-resource cleanup fails closed" \
  'could not remove its own workspace or evidence'
drv_has "the driver never runs the integration UAT" 'never runs the integration UAT'
drv_has "the driver never starts the model workload" 'model.s real workload'
drv_lacks "no LLM interaction in the driver" 'opencode run'
drv_has "the driver refreshes the installed launcher through the canonical installer" \
  'setup-agent-user.sh --install-launcher-only'
drv_has "a failed launcher synchronization fails the driver before the ladder" \
  'launcher synchronization failed; refusing to run the diagnostics'
drv_has "the runner checks the status of every mandatory source" \
  'FAIL loader-drift: sourcing'
drv_has "the runner pins the single launcher source for the child processes" \
  'DC_ALIASES="\$HOME/\.bash_aliases"'
drv_has "the runner verifies the launcher source integrity" \
  'is not a standalone regular file'
drv_has "the runner verifies the launcher against the canonical copy" \
  'does not match the canonical'

lib_has "the lib owns the runner preflight" 'diag_verify_launcher_loaded'
lib_has "the preflight checks the shared configuration owners" '_oc_security_opts _oc_compose_mounts_env'

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
lib_has "every failure-evidence collection call is bounded" \
  'diag_bounded "\$id\.inspect" docker inspect'
lib_has "absence is provable by the full container ID" 'diag_cid_absent'
lib_has "only the full 64-hex container ID authorizes a removal decision" \
  '\^\[0-9a-f\]\{64\}\$'
# UAT-8f: the PUBLIC print paths quote allowlisted material only — no raw
# docker top argv and no raw stderr excerpts anywhere in the report.
sum_body="$(sed -n '/^diag_print_evidence_summary()/,/^}/p' "$LIB")"
case "$sum_body" in
  *".procs"*) bad "UAT-8f: the summary still prints docker top output" ;;
  *) ok "UAT-8f: the evidence summary prints no docker top output" ;;
esac
case "$sum_body" in
  *"docker top"*) bad "UAT-8f: the summary references docker top" ;;
  *) ok "UAT-8f: the summary carries no docker top reference" ;;
esac
ladder_body="$(sed -n '/^diag_run_ladder()/,/^}/p' "$LIB")"
case "$ladder_body" in
  *"err.excerpt"*) bad "UAT-8f: the ladder still prints raw stderr excerpts" ;;
  *) ok "UAT-8f: the ladder report carries no raw stderr excerpt" ;;
esac
case "$ladder_body" in
  *'DIAG stderr ('*) bad "UAT-8f: the ladder still prints a stderr excerpt block" ;;
  *) ok "UAT-8f: no stderr excerpt block in the ladder report" ;;
esac
case "$ladder_body" in
  *'DIAG avc (capped tail)'*) bad "UAT-8f: the ladder still prints raw AVC text" ;;
  *) ok "UAT-8f: the ladder report carries only the AVC category" ;;
esac

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
p_has "the external deadline carries a finite kill budget" \
  'timeout --kill-after="\$DIAG_DEADLINE_KILL" "\$DIAG_DEADLINE"'
p_has "the hard-kill deadline path is explicit" \
  'ignored the deadline SIGTERM and was force-killed'

echo
printf 'diagnose-launch tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
