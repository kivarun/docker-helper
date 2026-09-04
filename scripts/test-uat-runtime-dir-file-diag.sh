#!/usr/bin/env bash
#
# test-uat-runtime-dir-file-diag.sh — deterministic tests for the file-bind
# diagnostic contract of
# scripts/uat-regression-runtime-dir-socket-replacement.sh:
#
#   the file-bind consumer is a NON-VERDICT diagnostic. When it cannot be
#   started or is not running, the regression records
#   "file-bind consumer unavailable" and continues; its unavailability never
#   changes PASS/FAIL of the mandatory directory-bind scenario. Only the
#   directory-bind consumer is mandatory.
#
# The REAL regression script is executed end-to-end with the privileged and
# host-bound external commands (docker, zypper, rpm, systemctl, curl, stat,
# id, docker-helper) stubbed on PATH, and the scenario state (installed
# version, socket/dir dev:inode, MainPID, InvocationID, consumer container
# state) held in a state directory the stubs share. The stubs model the real
# bind semantics: the directory-bind consumer's view always equals the host
# view (shared directory inode); the file-bind consumer's view is the socket
# inode recorded at its start (a file bind pins the inode), so it goes stale
# when the daemon replaces the socket across the zypper phases.
#
# Cases:
#   1. file-bind `docker run` fails          -> PASS, "unavailable" recorded,
#                                               no FAIL subcases
#   2. file-bind starts but never runs       -> PASS, "unavailable" recorded,
#                                               no FAIL subcases
#   3. file-bind healthy                     -> PASS, stale observation
#                                               recorded, all MUST greens
#                                               present, no "unavailable"
#   4. control: directory-bind container
#      view broken                           -> FAIL (exit 1); proves this
#                                               harness reaches the real FAIL
#                                               verdict when the mandatory
#                                               scenario actually fails
#
# Usage: scripts/test-uat-runtime-dir-file-diag.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REG="$SRC_DIR/scripts/uat-regression-runtime-dir-socket-replacement.sh"
[ -f "$REG" ] || { echo "missing $REG" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
STUB="$WORK/stub"
mkdir -p "$STUB"

DIR_CONTAINER="dh-runtime-dir-reg"
FILE_CONTAINER="dh-runtime-dir-sockbind-diag"
RUNTIME_DIR="/run/docker-helper"
SOCK="$RUNTIME_DIR/docker-helper.sock"
export WORK DIR_CONTAINER FILE_CONTAINER RUNTIME_DIR SOCK

PASS=0
FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1" >&2; }

# --- fixture RPMs (dummy bytes; identity verified through the real sha256sum) --
BASELINE_RPM="$WORK/docker-helper-baseline.rpm"
CANDIDATE_RPM="$WORK/docker-helper-2.1.0~uat-1.x86_64.rpm"
printf 'baseline-fixture\n' > "$BASELINE_RPM"
printf 'candidate-fixture\n' > "$CANDIDATE_RPM"
BASELINE_SHA="$(sha256sum "$BASELINE_RPM" | awk '{print $1}')"
CANDIDATE_SHA="$(sha256sum "$CANDIDATE_RPM" | awk '{print $1}')"

# --- scenario state the stubs share --------------------------------------------
# state/dirinode  dev:inode of the RuntimeDirectory (never changes: the
#                 RuntimeDirectoryPreserve=restart contract under test)
# state/inode     dev:inode of the current daemon socket (bumped per zypper
#                 install: the restarted daemon recreates the socket file)
# state/pid       daemon MainPID (bumped per zypper install)
# state/inv       systemd InvocationID (bumped per zypper install)
# state/vr        installed package version-release (rpm/zypper/db state)
# state/pinned    socket inode the file-bind consumer pinned at its start
# state/containers/<name>  marker: the container exists and is running
init_state() {
  rm -rf "$WORK/state"
  mkdir -p "$WORK/state/containers"
  printf '29:4000' > "$WORK/state/dirinode"
  printf '29:4001' > "$WORK/state/inode"
  printf '4711' > "$WORK/state/pid"
  printf 'invaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1' > "$WORK/state/inv"
  rm -f "$WORK/state/vr" "$WORK/state/pinned"
}

bump_socket_state() {
  local cur n
  cur="$(cat "$WORK/state/inode")"; n="${cur##*:}"; n=$((n+1))
  printf '29:%s\n' "$n" > "$WORK/state/inode"
  cur="$(cat "$WORK/state/pid")"; n="${cur}"; n=$((n+1))
  printf '%s\n' "$n" > "$WORK/state/pid"
  cur="$(cat "$WORK/state/inv")"
  printf 'inv%s\n' "$(printf '%s' "$cur" | md5sum | cut -c1-32)" > "$WORK/state/inv"
}

# --- stubs ----------------------------------------------------------------------
cat > "$STUB/id" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "-u" ]; then echo 0; exit 0; fi
exit 0
EOF

cat > "$STUB/stat" <<'EOF'
#!/usr/bin/env bash
# stat stub: scripted dev:inode/type for the two regression paths.
fmt="$2"; path="$3"
case "$fmt:$path" in
  '%d:%i:'"$RUNTIME_DIR")        cat "$WORK/state/dirinode"; exit 0 ;;
  '%d:%i:'"$SOCK")               cat "$WORK/state/inode"; exit 0 ;;
  '%F:'"$SOCK")                  printf 'socket\n'; exit 0 ;;
esac
exit 1
EOF

cat > "$STUB/systemctl" <<'EOF'
#!/usr/bin/env bash
case "$1 $2" in
  'show -p')
    case "$3" in
      MainPID)      cat "$WORK/state/pid"; exit 0 ;;
      InvocationID) cat "$WORK/state/inv"; exit 0 ;;
    esac
    exit 1 ;;
  *) exit 0 ;;
esac
EOF

printf '#!/usr/bin/env bash\nexit 0\n' > "$STUB/curl"

cat > "$STUB/docker-helper" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  init) exit 0 ;;
  version)
    case "$(cat "$WORK/state/vr" 2>/dev/null)" in
      '2.0.0-1')     echo 2.0.0; exit 0 ;;
      '2.1.0~uat-1') echo 2.1.0-uat; exit 0 ;;
    esac
    exit 1 ;;
esac
exit 1
EOF

cat > "$STUB/rpm" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  -e)  rm -f "$WORK/state/vr"; exit 0 ;;
  -q)  cat "$WORK/state/vr" 2>/dev/null; exit 0 ;;
  -qp)
    case "${4##*/}" in
      *baseline*) echo '2.0.0-1' ;;
      *)          echo '2.1.0~uat-1' ;;
    esac
    exit 0 ;;
esac
exit 1
EOF

cat > "$STUB/zypper" <<'EOF'
#!/usr/bin/env bash
# zypper stub: `install` performs the package transaction; for a candidate
# install it also models the scriptlet-driven restart (socket recreated,
# MainPID/InvocationID changed). The regression passes the global option
# --non-interactive before the command word; skip it like real zypper does.
case "${1:-}" in
  --non-interactive) shift ;;
esac
case "${1:-}" in
  install)
    for arg in "$@"; do
      case "${arg##*/}" in
        *baseline*) printf '2.0.0-1\n' > "$WORK/state/vr" ;;
        *uat*)      printf '2.1.0~uat-1\n' > "$WORK/state/vr"; bump_socket_state ;;
      esac
    done
    echo 'Installation OK.'
    exit 0 ;;
esac
exit 1
EOF

cat > "$STUB/docker" <<'EOF'
#!/usr/bin/env bash
cmd="$1"
case "$cmd" in
  info) exit 0 ;;
  run)
    name=""
    prev=""
    for arg in "$@"; do
      [ "$prev" = "--name" ] && name="$arg"
      prev="$arg"
    done
    if [ "$name" = "$FILE_CONTAINER" ]; then
      case "${FILEDIAG_MODE:-ok}" in
        run-fail)    exit 1 ;;
        not-running) exit 0 ;;
        *)           : > "$WORK/state/containers/$name"
                     cp "$WORK/state/inode" "$WORK/state/pinned"
                     exit 0 ;;
      esac
    fi
    if [ "$name" = "$DIR_CONTAINER" ]; then
      : > "$WORK/state/containers/$name"
      exit 0
    fi
    exit 1 ;;
  inspect)
    # docker inspect -f '{{.State.Running}}' NAME
    if [ -f "$WORK/state/containers/$4" ]; then echo true; else echo false; fi
    exit 0 ;;
  exec)
    # docker exec NAME stat -c FMT PATH
    name="$2"; fmt="$5"; path="$6"
    if [ "$name" = "$DIR_CONTAINER" ]; then
      [ "${FILEDIAG_MODE:-ok}" = "dir-view-absent" ] && exit 1
      case "$fmt:$path" in
        '%d:%i:'"$SOCK")        cat "$WORK/state/inode"; exit 0 ;;
        '%d:%i:'"$RUNTIME_DIR") cat "$WORK/state/dirinode"; exit 0 ;;
      esac
      exit 1
    fi
    if [ "$name" = "$FILE_CONTAINER" ]; then
      if [ -f "$WORK/state/pinned" ]; then cat "$WORK/state/pinned"; exit 0; fi
      exit 1
    fi
    exit 1 ;;
  rm)
    shift 2  # rm -f
    for name in "$@"; do rm -f "$WORK/state/containers/$name"; done
    exit 0 ;;
esac
exit 1
EOF

# bump_socket_state is used by the zypper stub (exported for child processes).
export -f bump_socket_state

chmod +x "$STUB"/*
export PATH="$STUB:$PATH"

# run_case MODE: reset the scenario state, run the REAL regression script,
# print its output, and return its exit status. The captured output is kept
# in $WORK/case-<mode>.log for failure inspection.
run_case() {
  init_state
  local out ec
  out="$(FILEDIAG_MODE="$1" \
    UAT_RPM="$CANDIDATE_RPM" UAT_RPM_SHA256="$CANDIDATE_SHA" \
    UAT_BASELINE_RPM="$BASELINE_RPM" UAT_BASELINE_SHA256="$BASELINE_SHA" \
    bash "$REG" 2>&1)"
  ec=$?
  printf '%s\n' "$out" > "$WORK/case-$1.log"
  [ "$ec" != 0 ] && printf '%s\n' "$out" >&2
  printf '%s\n' "$out"
  return "$ec"
}

# --- case 1: file-bind container cannot start ------------------------------------
out="$(run_case run-fail)"; ec=$?
[ "$ec" = 0 ] && ok "case 1: file-bind start failure -> regression PASS (exit 0)" \
  || bad "case 1: file-bind start failure -> regression PASS (exit 0) (got $ec)"
printf '%s' "$out" | grep -q 'REGRESSION_RESULT=PASS' \
  && ok "case 1: verdict PASS" || bad "case 1: verdict PASS"
printf '%s' "$out" | grep -q 'diagnostic: file-bind consumer unavailable' \
  && ok "case 1: unavailable diagnostic recorded" || bad "case 1: unavailable diagnostic recorded"
printf '%s' "$out" | grep -q '^  FAIL:' \
  && bad "case 1: no FAIL subcases" || ok "case 1: no FAIL subcases"
printf '%s' "$out" | grep -q 'BLOCKED' \
  && bad "case 1: no BLOCKED" || ok "case 1: no BLOCKED"
printf '%s' "$out" | grep -q 'diagnostic \[upgrade\]: file-bind consumer unavailable' \
  && ok "case 1: phase observations degrade to unavailable" \
  || bad "case 1: phase observations degrade to unavailable"

# --- case 2: file-bind container starts but never reaches running ------------------
out="$(run_case not-running)"; ec=$?
[ "$ec" = 0 ] && ok "case 2: file-bind not running -> regression PASS (exit 0)" \
  || bad "case 2: file-bind not running -> regression PASS (exit 0) (got $ec)"
printf '%s' "$out" | grep -q 'REGRESSION_RESULT=PASS' \
  && ok "case 2: verdict PASS" || bad "case 2: verdict PASS"
printf '%s' "$out" | grep -q 'diagnostic: file-bind consumer unavailable' \
  && ok "case 2: unavailable diagnostic recorded" || bad "case 2: unavailable diagnostic recorded"
printf '%s' "$out" | grep -q '^  FAIL:' \
  && bad "case 2: no FAIL subcases" || ok "case 2: no FAIL subcases"

# --- case 3: file-bind healthy (control for the mandatory scenario) ----------------
out="$(run_case ok)"; ec=$?
[ "$ec" = 0 ] && ok "case 3: healthy file-bind -> regression PASS (exit 0)" \
  || bad "case 3: healthy file-bind -> regression PASS (exit 0) (got $ec)"
printf '%s' "$out" | grep -q 'REGRESSION_RESULT=PASS' \
  && ok "case 3: verdict PASS" || bad "case 3: verdict PASS"
printf '%s' "$out" | grep -q 'diagnostic: file-bind consumer available' \
  && ok "case 3: available diagnostic recorded" || bad "case 3: available diagnostic recorded"
printf '%s' "$out" | grep -q 'went stale' \
  && ok "case 3: stale file-bind observation recorded" || bad "case 3: stale file-bind observation recorded"
printf '%s' "$out" | grep -q 'unavailable' \
  && bad "case 3: no unavailable records when healthy" || ok "case 3: no unavailable records when healthy"
[ "$(printf '%s' "$out" | grep -c 'container sees the same new socket as the host')" = 2 ] \
  && ok "case 3: MUST container-socket equality green for both phases" \
  || bad "case 3: MUST container-socket equality green for both phases"
[ "$(printf '%s' "$out" | grep -c 'RuntimeDirectory dev:inode preserved on host')" = 2 ] \
  && ok "case 3: MUST RuntimeDirectory preservation green for both phases" \
  || bad "case 3: MUST RuntimeDirectory preservation green for both phases"
[ "$(printf '%s' "$out" | grep -c 'host socket exists after the scriptlet-driven restart')" = 2 ] \
  && ok "case 3: MUST host socket replacement green for both phases" \
  || bad "case 3: MUST host socket replacement green for both phases"
printf '%s' "$out" | grep -q 'evidence \[upgrade\]: socket inode changed' \
  && ok "case 3: socket replacement evidence recorded" || bad "case 3: socket replacement evidence recorded"

# --- case 4: control — the mandatory directory-bind scenario CAN fail ---------------
out="$(run_case dir-view-absent)"; ec=$?
[ "$ec" = 1 ] && ok "case 4: control: broken directory-bind view -> FAIL (exit 1)" \
  || bad "case 4: control: broken directory-bind view -> FAIL (exit 1) (got $ec)"
printf '%s' "$out" | grep -q 'REGRESSION_RESULT=FAIL' \
  && ok "case 4: verdict FAIL" || bad "case 4: verdict FAIL"

# --- summary -----------------------------------------------------------------------
echo
echo "================= test-uat-runtime-dir-file-diag summary ================="
echo "passed: $PASS  failed: $FAIL"
echo "======================================================================"
[ "$FAIL" -eq 0 ]
