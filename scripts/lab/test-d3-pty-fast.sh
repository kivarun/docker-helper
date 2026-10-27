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
#      the Session cleanup still runs (the speedup hides no cleanup error);
#   8. (UAT-8o) the canonical step adds NO nested script(1) wrapper: it
#      hands over to the regular child bash, inherits the runner's outer
#      pty, and fails closed with tty-required when no real client TTY
#      exists (the -it is never dropped to make the step pass);
#   9. (UAT-8o) a proven-unusable wrapper starts no further script-wrapped
#      probes (one bounded smoke control only) and is OBSERVED evidence
#      that can never be named as the D3 cause; the direct -it vs no-flag
#      pair names the -it combination hanging without any wrapper;
#  10. (UAT-8o) the direct-only matrix still cleans every Session/container;
#  11. (UAT-8p) the mock docker-helper socket readiness is awaited with a
#      bounded -S poll (an unready socket is an explicit refusal, never a
#      masked launcher failure); a new direct -t probe separates -t from
#      the -it combination (single-variable -t attribution, combination
#      attribution for -it, UNRESOLVED on missing/unconfirmed/contradictory
#      evidence), and the two-flag no-flag/-it difference is never called a
#      single-variable comparison.
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
  mf F-D3-direct-t timeout clean
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
# UAT-8o: the smoke timeout is OBSERVED evidence, never a D3 cause verdict
rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"; base_fixtures
mf F-D3-script-smoke timeout
out="$(diag_case)"
contains "8o: a hanging wrapper smoke is reported as OBSERVED evidence" \
  "DIAG OBSERVED: F-D3-script-smoke timed out" "$out"
not_contains "8o RED: the wrapper smoke can no longer be named as the D3 cause" \
  "DIAGNOSIS: the D3 nested script(1) wrapper itself hangs" "$out"
contains "8o: with every probe hung the wrapper-free rule C still decides" \
  "DIAGNOSIS: docker hangs even when invoked directly" "$out"

# the UAT-8n shape: smoke hung, direct no-flag and direct -i passed, direct
# -it and direct -t hung — the single-variable -t comparison decides, and
# the wrapper is not blamed for D3
rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"; base_fixtures
mf F-D3-script-smoke timeout
mf F-D3-direct-none ok clean
mf F-D3-stdin-pty ok clean
mf F-D3-stdin-null ok clean
out="$(diag_case)"
contains "8p: the direct -t hang is named by the single-variable comparison" \
  "DIAGNOSIS: the D3 docker -t flag is implicated (F-D3-direct-t hung where the direct -i and no-flag probes passed; single-variable comparison)" "$out"
contains "8o: the unusable wrapper stays visible as OBSERVED evidence" \
  "DIAG OBSERVED: F-D3-script-smoke timed out" "$out"
not_contains "8o: no wrapper verdict replaces the measured direct evidence" \
  "DIAGNOSIS: the D3 nested script(1) wrapper" "$out"

# UAT-8p rule D2: direct -t, -i and no-flag all pass while direct -it hangs
# -> the -it COMBINATION is implicated, never called single-variable. The
# script-wrapped no-flag probe passes too, so the wrapper question is
# settled and only the flag dimension is measured
rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"; base_fixtures
mf F-D3-flag-none ok clean
mf F-D3-direct-none ok clean
mf F-D3-direct-t ok clean
mf F-D3-stdin-pty ok clean
out="$(diag_case)"
contains "8p: the direct -it combination is named by the controlled comparison" \
  "DIAGNOSIS: the D3 docker -it flag combination is implicated (F-D3-pty-direct hung where the direct -t, -i and no-flag probes passed; controlled comparison)" "$out"
not_contains "8p RED: the two-flag -it difference is never a single-variable claim" \
  "F-D3-pty-direct hung where F-D3-direct-none passed; single-variable" "$out"

# UAT-8p: MISSING direct -t evidence -> the -it/-t question names nothing
rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"; base_fixtures
mf F-D3-script-smoke ok
mf F-D3-flag-none ok clean
mf F-D3-direct-none ok clean
mf F-D3-stdin-pty ok clean
rm -f "$DIAG_DIR/F-D3-direct-t.detail"
out="$(diag_case)"
contains "8p: a missing direct -t measurement stays UNRESOLVED" \
  "DIAGNOSIS UNRESOLVED: the failing step is D3" "$out"
not_contains "8p: nothing is implicated without the -t evidence" \
  "is implicated" "$out"

# UAT-8p: cleanup-UNCONFIRMED direct -t evidence names nothing
rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"; base_fixtures
mf F-D3-script-smoke ok
mf F-D3-flag-none ok clean
mf F-D3-direct-none ok clean
mf F-D3-stdin-pty ok clean
mf F-D3-direct-t ok failed
out="$(diag_case)"
contains "8p: a cleanup-unconfirmed direct -t probe proves nothing" \
  "DIAGNOSIS UNRESOLVED: the failing step is D3" "$out"
not_contains "8p: unconfirmed -t evidence never drives the attribution" \
  "is implicated" "$out"

# UAT-8p: CONTRADICTORY direct evidence (direct -t hung where direct -it
# passed) names nothing
rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"; base_fixtures
mf F-D3-script-smoke ok
mf F-D3-direct-none ok clean
mf F-D3-direct-t timeout clean
mf F-D3-stdin-pty ok clean
mf F-D3-pty-direct ok clean
mf F-D3-flag-it ok clean
out="$(diag_case)"
contains "8p: contradictory direct -t/-it evidence stays UNRESOLVED" \
  "DIAGNOSIS UNRESOLVED: the failing step is D3" "$out"
not_contains "8p: a contradiction implicates no flag" \
  "is implicated" "$out"

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

# --- 7. UAT-8o: the canonical step without the nested script(1) wrapper -----
lib_canon="$(sed -n '/^_diag_canonical_step()/,/^}/p' "$LIB")"
case "$lib_canon" in
  *'script -qec "bash'*)
    bad "8o RED: the canonical step still nests a script(1) wrapper" ;;
  *) ok "8o: the canonical step adds no nested script(1) wrapper" ;;
esac
case "$lib_canon" in
  *'bash "$childfile"'*)
    ok "8o: the canonical step hands over to the regular child bash" ;;
  *) bad "8o: the canonical step does not run the child bash directly" ;;
esac
case "$lib_canon" in
  *tty-required*) ok "8o: the canonical step carries an explicit no-TTY FAIL" ;;
  *) bad "8o: no explicit no-TTY FAIL in the canonical step" ;;
esac

# fail-closed: no real client TTY -> an explicit tty-required FAIL before
# anything runs (this shell's stdin is /dev/null)
export DIAG_DIR="$WORK/ev-canon-neg"; mkdir -p "$DIAG_DIR"
rec_before="$(wc -l < "$DOCKER_REC")"; dh_before="$(wc -l < "$DH_STATE")"
if _diag_canonical_step D3 2 'test -t 0 && echo D3_OK' exec "$WS"; then
  bad "8o RED: the canonical step passed without a real TTY"
else
  ok "8o: the canonical step fails closed without a real client TTY"
fi
check "8o: the no-TTY refusal is explicit (tty-required)" \
  "tty-required" "$(cat "$DIAG_DIR/D3.detail")"
check "8o: the no-TTY refusal is a refusal record (rc=refused)" \
  "refused" "$(cat "$DIAG_DIR/D3.rc")"
[ "$(wc -l < "$DOCKER_REC")" = "$rec_before" ] \
  && ok "8o: the no-TTY refusal starts no docker run" \
  || bad "8o RED: docker ran without a real TTY"
[ "$(wc -l < "$DH_STATE")" = "$dh_before" ] \
  && ok "8o: the no-TTY refusal leaks no Session" \
  || bad "8o RED: a Session leaked on the no-TTY path"
check "8o: the no-TTY step performs no reap" "n/a" "$(cat "$DIAG_DIR/D3.reap")"

# the positive case runs under a REAL script(1) pty (the harness simulates
# the runner's outer pty): the canonical step inherits it, adds no second
# wrapper, and the in-container `test -t 0` proves the TTY reached docker
mkdir -p "$WORK/run"
python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); time.sleep(30)' \
  "$WORK/run/docker-helper.sock" 2>/dev/null & sock_pid=$!
# bounded readiness wait (UAT-8p): the launcher refuses while the socket
# file is not yet a socket, which would masquerade as a launcher/docker
# failure — the stub Docker would never be reached. Never a blind sleep.
sock_ok=""
for _ in $(seq 1 50); do
  if [ -S "$WORK/run/docker-helper.sock" ]; then sock_ok=1; break; fi
  sleep 0.1
done
if [ -z "$sock_ok" ]; then
  kill "$sock_pid" 2>/dev/null
  bad "8p RED: the mock docker-helper socket never appeared; the launcher would refuse before docker (the stub Docker was never reached)"
else
  ok "8p: the mock docker-helper socket became ready (bounded wait)"
  export DIAG_DIR="$WORK/ev-canon-pos"; mkdir -p "$DIAG_DIR"
  : > "$DOCKER_STATE"; : > "$DH_STATE"; : > "$DOCKER_REC"
  export FAST_ALIASES="$ALIASES" FAST_LIB="$LIB" FAST_WS="$WS"
  cat > "$WORK/canon-driver.sh" <<'DRV'
#!/usr/bin/env bash
set -u
source "$FAST_ALIASES"
source "$FAST_LIB"
cd "$FAST_WS" || exit 1
DIAG_D3_INIT_COPY=""
DIAG_D3_CLEANUP_FAILED=0
_diag_canonical_step D3 5 'test -t 0 && echo D3_OK' exec "$FAST_WS" || true
printf 'detail=%s rc=%s session=%s\n' \
  "$(cat "$DIAG_DIR/D3.detail")" "$(cat "$DIAG_DIR/D3.rc")" \
  "$(cat "$DIAG_DIR/D3.session")"
DRV
  canon_out="$(timeout 20 script -qec "bash $WORK/canon-driver.sh" /dev/null 2>&1 | tr -d '\r')"
  kill "$sock_pid" 2>/dev/null
  canon_line="$(printf '%s\n' "$canon_out" | grep '^detail=' | head -1)"
  printf '%s\n' "$canon_line" | grep -q '^detail=ok rc=0' \
    && ok "8o: the canonical step passes under the real single runner pty" \
    || bad "8o: the canonical step failed under the real pty: $canon_line"
  case "$canon_line" in
    *session=clean*|*session=reaped*)
      ok "8o: the real-pty canonical step's cleanup is confirmed" ;;
    *) bad "8o: the real-pty canonical step's cleanup verdict: $canon_line" ;;
  esac
  grep -q ' -it ' "$DOCKER_REC" \
    && ok "8o: the canonical launch keeps the unchanged -it configuration" \
    || bad "8o: the canonical launch lost -it"
  grep -q -- '--name dhl-D3-' "$DOCKER_REC" \
    && ok "8o: the canonical launch keeps its diagnostic provenance" \
    || bad "8o: the canonical launch lost its provenance"
  [ -s "$DOCKER_STATE" ] && bad "8o RED: a container leaked on the real-pty path" \
    || ok "8o: the real-pty canonical step leaves no container behind"
  [ -s "$DH_STATE" ] && bad "8o RED: a Session leaked on the real-pty path" \
    || ok "8o: the real-pty canonical step leaves no Session behind"
fi

# the wrapper gate: one bounded smoke control, then no script-wrapped probes
rm -rf "$DIAG_DIR"; mkdir -p "$DIAG_DIR"
if _diag_d3_wrapper_unusable; then
  bad "8o RED: a missing smoke evidence reads the wrapper as unusable"
else
  ok "8o: without smoke evidence the wrapper is unproven, not unusable"
fi
printf 'timeout\n' > "$DIAG_DIR/F-D3-script-smoke.detail"
if _diag_d3_wrapper_unusable; then
  ok "8o: a timed-out smoke marks the wrapper unusable"
else
  bad "8o: the timed-out smoke did not mark the wrapper unusable"
fi
: > "$DOCKER_STATE"; : > "$DH_STATE"; : > "$DOCKER_REC"
DIAG_D3_CLEANUP_FAILED=0
_diag_d3_matrix "$WS"
for probe in F-D3-direct-none F-D3-direct-t F-D3-pty-direct F-D3-stdin-pty \
             F-D3-stdin-null; do
  check "8o: the wrapper-free direct probe $probe still ran" \
    "ok" "$(cat "$DIAG_DIR/$probe.detail" 2>/dev/null || echo missing)"
done
check "8p: the direct -t probe differs from the direct no-flag probe ONLY in its flag" \
  "$(norm_argv F-D3-direct-t | sed 's/ -t//')" "$(norm_argv F-D3-direct-none)"
for probe in F-D3-flag-none F-D3-flag-i F-D3-flag-t F-D3-flag-it; do
  if [ -f "$DIAG_DIR/$probe.detail" ]; then
    bad "8o RED: a script-wrapped probe ran although the wrapper was proven unusable ($probe)"
  else
    ok "8o: no script-wrapped $probe ran with a proven-unusable wrapper"
  fi
done
[ -s "$DH_STATE" ] && bad "8o RED: a Session leaked in the direct-only matrix" \
  || ok "8o: the direct-only matrix leaks no Session"
[ -s "$DOCKER_STATE" ] && bad "8o RED: a container leaked in the direct-only matrix" \
  || ok "8o: the direct-only matrix leaks no container"

# --- UAT-8n: streaming progress is safe, deterministic and immediate -------
export DIAG_DIR="$WORK/ev-progress"; mkdir -p "$DIAG_DIR"
export PROGRESS_SECRET="progress-secret-not-for-terminal"
if DIAG_CONTAINER_NAME="" DIAG_CONTAINER_CID="" \
    diag_exec F-D3-progress-ok "$DIAG_FACTOR_BOUND" \
      sh -c 'printf "%s" "$PROGRESS_SECRET"' \
      2>"$WORK/progress-ok.stderr"; then
  ok "progress: an instant successful command exits 0"
else
  bad "progress: the successful command returned nonzero"
fi
grep -qF '[diag] START F-D3-progress-ok limit=2s' "$WORK/progress-ok.stderr" \
  && ok "progress: START is emitted before the result" \
  || bad "progress: START is missing"
grep -qE '^\[diag\] END F-D3-progress-ok rc=0 elapsed=[0-9]+s reap=n/a$' \
  "$WORK/progress-ok.stderr" \
  && ok "progress: END contains bounded safe fields only" \
  || bad "progress: END or result fields are missing"
if grep -qF "$PROGRESS_SECRET" "$WORK/progress-ok.stderr"; then
  bad "progress: secret leaked into the progress stream"
else
  ok "progress: private command output stays out of the progress stream"
fi
check "progress: private stdout stays in its evidence file" \
  "$PROGRESS_SECRET" "$(cat "$DIAG_DIR/F-D3-progress-ok.out")"
if DIAG_CONTAINER_NAME="" DIAG_CONTAINER_CID="" \
    diag_exec F-D3-progress-fail "$DIAG_FACTOR_BOUND" \
      sh -c 'exit 42' 2>"$WORK/progress-fail.stderr"; then
  bad "progress: a failed command was treated as successful"
else
  rc=$?
  check "progress: command exit code preserved" "42" "$rc"
fi
grep -qE '^\[diag\] END F-D3-progress-fail rc=42 elapsed=[0-9]+s reap=n/a$' \
  "$WORK/progress-fail.stderr" \
  && ok "progress: nonzero exit is emitted immediately and faithfully" \
  || bad "progress: nonzero exit progress is missing"
unset PROGRESS_SECRET

# --- summary ----------------------------------------------------------------
printf 'd3-pty-fast tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
