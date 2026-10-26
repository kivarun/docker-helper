#!/usr/bin/env bash
#
# test-d3-pty-fast.sh — fast, instant stubbed checks for the UAT-8m D3
# changes in scripts/lab/lab-diag-lib.sh (the wrapper/docker isolation).
# It never runs the D0–D4 ladder and never waits for a real hang: outcomes
# that would require a timeout (rc 124/137) are MODELED by writing the rc
# file and calling the real diag_classify, and every other check calls the
# tested functions directly against stub docker/docker-helper binaries.
#
# What this protects (one invariant per check):
#   1. (source) the lib owns the phase-marker prefix, the no-docker smoke
#      probe, the direct no-flag matrix probe and the unknown hang class;
#   2. _diag_phase_prefix emits exactly the fixed markers (and quotes the
#      private-evidence path safely);
#   3. a recorded docker invocation without a cidfile stays UNKNOWN, and so
#      does missing/empty phase evidence (the canonical steps record no
#      markers) — only wrapper-entry WITHOUT the docker marker positively
#      proves the CLI was never invoked (no-cidfile);
#   4. the no-docker smoke probe passes through the real script(1) wrapper,
#      writes only its own marker and creates nothing (no leak);
#   5. the diagnosis separates: the wrapper itself hangs (rule A), docker
#      hangs under the wrapper (rule B), docker hangs even when invoked
#      directly (rule C) — and a more specific legacy factor attribution
#      (Session/ssh-agent) always wins over A/B/C, while contradictory or
#      cleanup-unconfirmed evidence stays UNRESOLVED;
#   6. a real script-wrapped and a real direct matrix probe carry the
#      IDENTICAL composition, leave no Session/container leak, and record
#      their own phase markers (the direct one: before-docker-exec only);
#   7. a cleanup failure still fails the probe and stops the matrix while
#      the Session cleanup still runs (the speedup hides no cleanup error).
#
# Usage: scripts/lab/test-d3-pty-fast.sh   (runs in seconds)

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ALIASES="$SRC_DIR/lab/agent-aliases.sh"
LIB="$SRC_DIR/lab/lab-diag-lib.sh"
for f in "$ALIASES" "$LIB"; do
  [ -f "$f" ] || { echo "missing $f" >&2; exit 1; }
done

# deterministic non-tty stdin (the direct probes inherit it)
exec </dev/null

WORK="$(mktemp -d)"
cleanup_work() { rm -rf -- "$WORK"; }
trap cleanup_work EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2' got '$3')"; fi; }
contains() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2' in '$3')" ;; esac; }
not_contains() { case "$3" in *"$2"*) bad "$1 (unexpected '$2' in '$3')" ;; *) ok "$1" ;; esac; }
lib_has() { if grep -Eq -- "$2" "$LIB"; then ok "$1"; else bad "$1 (pattern absent: $2)"; fi; }

# --- stub docker / docker-helper (instant, deterministic) --------------------
SHIM="$WORK/shim"; mkdir -p "$SHIM"
export DOCKER_STATE="$WORK/docker.state" DH_STATE="$WORK/dh.state"
export DOCKER_REC="$WORK/docker.rec"
: > "$DOCKER_STATE"; : > "$DH_STATE"; : > "$DOCKER_REC"
cat > "$SHIM/docker" <<'SH'
#!/usr/bin/env bash
: "${DOCKER_STATE:?DOCKER_STATE must be exported}"
: "${DOCKER_REC:?DOCKER_REC must be exported}"
OWN_IMAGE_ID="sha256:1111111111111111111111111111111111111111111111111111111111111111"
case "$1" in
  image)
    printf '%s\n' "$OWN_IMAGE_ID"; exit 0 ;;
  run)
    shift
    printf '%s\n' "$*" >> "$DOCKER_REC"
    cname=""; cidfile=""; runid=""; payload=""; prev=""
    for a in "$@"; do
      [ "$prev" = "--name" ] && cname="$a"
      [ "$prev" = "--cidfile" ] && cidfile="$a"
      case "$prev" in --label) case "$a" in lab.diagnostic.runid=*) runid="${a#*=}" ;; esac ;; esac
      [ "$prev" = "-c" ] && payload="$a"
      prev="$a"
    done
    cid="deadbeef$(printf '%016x' $((RANDOM * 32768 + RANDOM)))0000000000000000000000000000000000000000"
    printf '%s' "$cid" > "$cidfile" 2>/dev/null
    printf '%s %s %s\n' "$cname" "$cid" "$runid" >> "$DOCKER_STATE"
    sh -c "$payload"
    exit $? ;;
  ps)
    f="$(printf '%s\n' "$*" | sed -n 's/.*--filter id=//p')"
    if [ -n "$f" ]; then awk -v c="$f" '$2 == c { print $2 }' "$DOCKER_STATE"; exit 0; fi
    n="$(printf '%s\n' "$*" | sed -n 's/.*--filter name=^\/\(.*\)\$/\1/p')"
    [ -n "$n" ] && awk -v n="$n" '$1 == n { print $2 }' "$DOCKER_STATE"
    exit 0 ;;
  inspect)
    target="${*: -1}"
    line="$(awk -v t="$target" '$1 == t || $2 == t { print; exit }' "$DOCKER_STATE")"
    [ -n "$line" ] || { echo "no such container" >&2; exit 1; }
    cid="$(printf '%s' "$line" | awk '{print $2}')"
    runid="$(printf '%s' "$line" | awk '{print $3}')"
    printf '%s|%s|%s\n' "$cid" "$runid" "$OWN_IMAGE_ID"
    exit 0 ;;
  rm)
    shift; [ "${1:-}" = "-f" ] && shift
    for t in "$@"; do
      if [ -n "${DOCKER_RM_FAIL:-}" ]; then echo "stub rm failure" >&2; exit 1; fi
      awk -v t="$t" '$2 != t && $1 != t' "$DOCKER_STATE" > "$DOCKER_STATE.next"
      mv "$DOCKER_STATE.next" "$DOCKER_STATE"
    done
    exit 0 ;;
  *) echo "unknown docker subcommand" >&2; exit 1 ;;
esac
SH
cat > "$SHIM/docker-helper" <<'SH'
#!/usr/bin/env bash
: "${DH_STATE:?DH_STATE must be exported}"
case "$1" in
  session)
    case "$2" in
      create)
        if [ "${3:-}" = "--help" ] || [ "${3:-}" = "-h" ]; then
          printf 'usage: docker-helper session create WORKSPACE --json\n'
          exit 0
        fi
        ws="$3"; [ "$3" = "--workspace" ] && ws="$4"
        sid="s-$(( $(wc -l < "$DH_STATE" 2>/dev/null || echo 0) + 1 ))"
        printf '%s %s\n' "$sid" "$ws" >> "$DH_STATE"
        printf '{"session":{"id":"%s"},"token":"tok-%s"}\n' "$sid" "$sid"
        exit 0 ;;
      list)
        printf '{"sessions":['
        first=1
        while read -r sid ws; do
          [ -n "$sid" ] || continue
          [ "$first" = 1 ] || printf ','
          printf '{"id":"%s","workspace":"%s"}' "$sid" "$ws"
          first=0
        done < "$DH_STATE"
        printf ']}\n'
        exit 0 ;;
      delete)
        awk -v s="$3" '$1 != s' "$DH_STATE" > "$DH_STATE.next"
        mv "$DH_STATE.next" "$DH_STATE"
        exit 0 ;;
    esac ;;
esac
echo "unknown docker-helper subcommand" >&2
exit 1
SH
chmod +x "$SHIM"/*
export PATH="$SHIM:$PATH"

export DOCKER_HELPER_RUNTIME_DIR="$WORK/run"
export OPENCODE_DOCKER_HOME="$WORK/ochome"
export OPENCODE_EXCHANGE_DIR="$WORK/absent-exchange"
mkdir -p "$OPENCODE_DOCKER_HOME/.config" "$OPENCODE_DOCKER_HOME/.local/share" \
  "$OPENCODE_DOCKER_HOME/.cache" "$OPENCODE_DOCKER_HOME/tmp"
export OPENCODE_AGENT_SSH_KEY="$WORK/absent-key"
export DC_ALIASES="$ALIASES"
export DIAG_RUNID="diagrun-fast"
export DIAG_STEP_BOUND=2 DIAG_CANON_BOUND=2 DIAG_FACTOR_BOUND=2
export DIAG_RECOVERY_BOUND=2 DIAG_KILL_AFTER=1

# shellcheck source=/dev/null
source "$ALIASES"
# shellcheck source=/dev/null
source "$LIB"
export DIAG_IMAGE="$_OC_BASE"

# --- 1. source-level invariants ---------------------------------------------
lib_has "the lib owns the phase-marker prefix" '_diag_phase_prefix'
lib_has "the lib owns the no-docker smoke probe" '_diag_d3_script_smoke'
lib_has "the matrix runs the direct no-flag probe" 'F-D3-direct-none'
lib_has "the hang state knows the recorded-invocation unknown class" 'before-docker-exec'

# --- 2. _diag_phase_prefix unit ---------------------------------------------
export DIAG_DIR="$WORK/ev-phase"; mkdir -p "$DIAG_DIR"
snip="$(_diag_phase_prefix F-D3-x docker)"
sh -c "$snip"
check "the docker phase prefix writes exactly the two fixed markers" \
  "$(printf 'wrapper-entered\nbefore-docker-exec')" \
  "$(cat "$DIAG_DIR/F-D3-x.phases")"
snip2="$(_diag_phase_prefix F-D3-y)"
sh -c "$snip2"
check "the no-docker phase prefix writes only wrapper-entered" \
  "wrapper-entered" "$(cat "$DIAG_DIR/F-D3-y.phases")"
export DIAG_DIR="$WORK/ev dir with spaces"; mkdir -p "$DIAG_DIR"
snip3="$(_diag_phase_prefix F-D3-z docker)"
sh -c "$snip3" 2>/dev/null \
  && ok "the phase prefix quotes an evidence path with spaces safely" \
  || bad "the phase prefix broke on an evidence path with spaces"
check "the quoted path still recorded the markers" \
  "$(printf 'wrapper-entered\nbefore-docker-exec')" \
  "$(cat "$DIAG_DIR/F-D3-z.phases" 2>/dev/null || echo missing)"

# --- 3. diag_capture_hang_state: the unknown class (no docker needed) -------
export DIAG_DIR="$WORK/ev-hang"; mkdir -p "$DIAG_DIR"
hang_case() { # NAME PHASES_CONTENT(empty=none) -> the recorded class
  if [ -n "${2:-}" ]; then printf '%s\n' "$2" > "$DIAG_DIR/$1.phases"; fi
  : > "$DIAG_DIR/$1.cid"
  diag_capture_hang_state "$1" "$DIAG_DIR/$1.cid"
  cat "$DIAG_DIR/$1.hangstate"
}
check "a recorded docker invocation without a cidfile stays UNKNOWN" \
  "unknown" "$(hang_case UD 'before-docker-exec')"
check "wrapper entry alone (docker never invoked) stays no-cidfile" \
  "no-cidfile" "$(hang_case WE 'wrapper-entered')"
check "no phase evidence at all stays UNKNOWN (absence proves nothing)" \
  "unknown" "$(hang_case NP '')"
check "a canonical-like step (no markers ever) with no cidfile stays UNKNOWN" \
  "unknown" "$(hang_case D3 '')"

# --- 4. the no-docker smoke probe through the REAL script(1) wrapper --------
export DIAG_DIR="$WORK/ev-smoke"; mkdir -p "$DIAG_DIR"
_diag_d3_script_smoke
check "the smoke probe passes through the real wrapper" \
  "ok" "$(cat "$DIAG_DIR/F-D3-script-smoke.detail")"
grep -q 'SCRIPT_SMOKE_OK' "$DIAG_DIR/F-D3-script-smoke.out" \
  && ok "the smoke probe carries its fixed marker on stdout" \
  || bad "the smoke marker never reached stdout"
check "the smoke probe records only its own wrapper marker" \
  "wrapper-entered" "$(cat "$DIAG_DIR/F-D3-script-smoke.phases")"
check "the smoke probe creates no container state" \
  "n/a" "$(cat "$DIAG_DIR/F-D3-script-smoke.reap")"
[ -s "$DOCKER_STATE" ] && bad "RED: the smoke probe touched docker" \
  || ok "the smoke probe never invoked docker"
# a MODELED smoke timeout: the rc is written deterministically and the REAL
# classifier records the outcome (no sleep, no real hang)
printf '124\n' > "$DIAG_DIR/F-D3-script-smoke.rc"
diag_classify F-D3-script-smoke 'SCRIPT_SMOKE_OK'
check "a modeled smoke timeout classifies as timeout" \
  "timeout" "$(cat "$DIAG_DIR/F-D3-script-smoke.detail")"

# --- 5. the diagnosis verdicts (fixture files, instant) ----------------------
export DIAG_DIR="$WORK/ev-diag"
mf() { # ID DETAIL [SESSION]
  printf '%s\n' "$2" > "$DIAG_DIR/$1.detail"
  if [ -n "${3:-}" ]; then printf '%s\n' "$3" > "$DIAG_DIR/$1.session"; fi
  return 0
}
base_fixtures() { # every docker probe hung with confirmed cleanup; smoke ok
  mf D3 timeout
  mf F-D3-script-smoke ok
  mf F-D3-nosession timeout clean
  mf F-D3-noagent timeout clean
  mf F-D3-flag-none timeout clean
  mf F-D3-direct-none timeout clean
  mf F-D3-flag-i timeout clean
  mf F-D3-flag-t timeout clean
  mf F-D3-flag-it timeout clean
  mf F-D3-pty-direct timeout clean
  mf F-D3-stdin-pty timeout clean
  mf F-D3-stdin-null timeout clean
}
diag_case() { # -> the _diag_d3_diagnose output on stdout
  DIAG_D3_MATRIX_RAN=1 _diag_d3_diagnose
}
rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"; base_fixtures
mf F-D3-script-smoke timeout
contains "rule A: a hung no-docker smoke names the wrapper itself" \
  "DIAGNOSIS: the D3 nested script(1) wrapper itself hangs" "$(diag_case)"

rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"; base_fixtures
mf F-D3-direct-none ok clean
contains "rule B: the identical direct no-flag pass names docker-under-wrapper" \
  "DIAGNOSIS: docker hangs under the nested script(1) wrapper" "$(diag_case)"

rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"; base_fixtures
contains "rule C: a hung direct no-flag probe names docker hanging directly" \
  "DIAGNOSIS: docker hangs even when invoked directly without the nested script wrapper" "$(diag_case)"

rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"; base_fixtures
mf F-D3-noagent ok clean
out="$(diag_case)"
contains "a passing legacy factor wins over the wrapper verdicts" \
  "DIAGNOSIS: the D3-noagent factor is implicated" "$out"
not_contains "the legacy attribution is not overwritten by rule C" \
  "docker hangs even when invoked directly" "$out"

rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"; base_fixtures
mf F-D3-flag-none ok clean
out="$(diag_case)"
contains "contradictory wrapper observations stay UNRESOLVED" \
  "DIAGNOSIS UNRESOLVED: the failing step is D3" "$out"
not_contains "a contradiction implicates nothing" "is implicated" "$out"

rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"; base_fixtures
mf F-D3-direct-none ok failed
out="$(diag_case)"
contains "a cleanup-unconfirmed direct probe proves nothing (UNRESOLVED)" \
  "DIAGNOSIS UNRESOLVED: the failing step is D3" "$out"
not_contains "unconfirmed cleanup evidence never drives rule C" \
  "docker hangs even when invoked directly" "$out"

# --- 6. the real probe path on the stubs ------------------------------------
WS="$WORK/ws"; mkdir -p "$WS"; export WS
cd "$WS" || exit 1
export DIAG_DIR="$WORK/ev-probe"; mkdir -p "$DIAG_DIR"
# the ladder owns these resets; the direct probe calls need them too
export DIAG_D3_INIT_COPY=""
DIAG_D3_CLEANUP_FAILED=0

_diag_d3_matrix_probe F-D3-flag-none "$WS" none script inherit
check "the script-wrapped probe passes on the stub" \
  "ok" "$(cat "$DIAG_DIR/F-D3-flag-none.detail")"
check "the script probe records exactly the two phase markers" \
  "$(printf 'wrapper-entered\nbefore-docker-exec')" \
  "$(cat "$DIAG_DIR/F-D3-flag-none.phases")"
case "$(cat "$DIAG_DIR/F-D3-flag-none.session")" in
  clean|reaped) ok "the script probe's cleanup is confirmed" ;;
  *) bad "the script probe's cleanup verdict is unconfirmed: $(cat "$DIAG_DIR/F-D3-flag-none.session")" ;;
esac
[ -s "$DOCKER_STATE" ] && bad "RED: the script probe leaked its container" \
  || ok "the script probe leaves no container behind"
[ -s "$DH_STATE" ] && bad "RED: the script probe leaked its Session" \
  || ok "the script probe leaves no Session behind"

_diag_d3_matrix_probe F-D3-direct-none "$WS" none direct inherit
check "the direct no-flag probe passes on the stub" \
  "ok" "$(cat "$DIAG_DIR/F-D3-direct-none.detail")"
check "the direct probe records only before-docker-exec" \
  "before-docker-exec" "$(cat "$DIAG_DIR/F-D3-direct-none.phases")"
case "$(cat "$DIAG_DIR/F-D3-direct-none.session")" in
  clean|reaped) ok "the direct probe's cleanup is confirmed" ;;
  *) bad "the direct probe's cleanup verdict is unconfirmed: $(cat "$DIAG_DIR/F-D3-direct-none.session")" ;;
esac
[ -s "$DOCKER_STATE" ] && bad "RED: the direct probe leaked its container" \
  || ok "the direct probe leaves no container behind"
[ -s "$DH_STATE" ] && bad "RED: the direct probe leaked its Session" \
  || ok "the direct probe leaves no Session behind"
norm_argv() { # ID -> the recorded docker argv without the probe-unique fields
  grep " --name dhl-$1-" "$DOCKER_REC" | head -1 \
    | sed -e "s/--name dhl-$1-[a-z0-9-]*//" \
          -e "s/--label lab.diagnostic.step=$1//" \
          -e 's|--cidfile [^ ]*||' \
          -e 's/  */ /g'
}
check "the script and direct no-flag probes share one composition" \
  "$(norm_argv F-D3-flag-none)" "$(norm_argv F-D3-direct-none)"

# --- cleanup failure stops the matrix, the Session cleanup still runs -------
rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"
: > "$DOCKER_STATE"; : > "$DH_STATE"; : > "$DOCKER_REC"
DIAG_D3_CLEANUP_FAILED=0
DOCKER_RM_FAIL=1 _diag_d3_matrix "$WS"
check "a failed container cleanup demotes the docker pass (cleanup-failed)" \
  "cleanup-failed" "$(cat "$DIAG_DIR/F-D3-flag-none.detail")"
for probe in F-D3-direct-none F-D3-flag-i F-D3-flag-t F-D3-flag-it \
             F-D3-pty-direct F-D3-stdin-pty F-D3-stdin-null; do
  if [ -f "$DIAG_DIR/$probe.detail" ]; then
    bad "RED: the matrix continued after the unconfirmed cleanup ($probe)"
  else
    ok "the unconfirmed cleanup stopped $probe"
  fi
done
[ -s "$DH_STATE" ] && bad "RED: the Session leaked although its cleanup could run" \
  || ok "the Session cleanup still ran despite the failed container removal"
check "the gate marks the run for the stop" "1" "${DIAG_D3_CLEANUP_FAILED:-0}"

# --- summary ----------------------------------------------------------------
printf 'd3-pty-fast tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
