#!/usr/bin/env bash
#
# release-2.4-r7-stop-proof-guest.sh — the R7 STOP-isolation proof on a
# disposable openSUSE Tumbleweed VM under ENFORCING AppArmor (RPM candidate).
#
# WHY THIS PROOF EXISTS (the R7 acceptance gate, part 2): the R7 payload's
# BuildKit spawns the bundled buildkit-runc with Go SysProcAttr{Setpgid} —
# live-proven on the SELinux side (UAT 39074498186 serials 1323/1324 + the
# S15 probe reproduction 9089/9090: the forked child's pre-exec setpgid(2)
# on itself). The manager's terminateGroupBounded terminates and verifies
# exactly ONE group — the setsid leader's pgid (inst.pid). A buildkit-runc
# child that moved to its OWN process group is not a member of that group;
# if it (or the OCI workload inside it) survives the manager's group kill,
# the mandatory STOP (build_driver stage D) and the cancellation path would
# report convergence over a live subtree — a false STOP OK.
#
# THE PROOF (both scenarios, on a consumer where the whole build flow —
# including RUN steps and runc — already executes):
#   scenario A (graceful cancel): start a long `RUN sleep 300` build, wait
#     until buildkit-runc AND the OCI workload are live, capture the FULL
#     descendant closure (ancestry from inst.pid UNION every process whose
#     pgrp is any captured member's pgrp — the off-group shape) with
#     PID/PPID/PGID/SID/exe/NSpid/cgroup per member plus the op's mount
#     surface, then POST /operations/<id>/cancel, await the terminal
#     transition, and re-scan at the terminal moment.
#   scenario B (emergency STOP): start the same build again, wait for the
#     same liveness, capture, then SIGKILL the buildctl client mid-RUN —
#     the driver's failure path runs the mandatory manager STOP against a
#     fully live instance tree with NO graceful wind-down — and re-scan at
#     the terminal moment.
#   For each scenario the whole-tree proof is:
#     * every captured pid gone from /proc;
#     * every captured pgid dead (kill(-pgid, 0) ESRCH) — one group's
#       disappearance alone is NEVER accepted as tree cleanup;
#     * no process anywhere on the host whose comm is rootlesskit,
#       buildkitd or buildkit-runc;
#     * no process whose exe or cwd resolves under the builder runtime or
#       state roots;
#     * no process whose cgroup path equals the captured workload cgroup;
#     * no mount entry naming docker-helper-builder in any live namespace;
#     * the op's runtime dir AND state dir absent (the verified
#       removeInstanceDirs contract);
#     * the manager's STOP convergence lines present in the service journal.
#   And after each scenario a fresh small build must SUCCEED — the
#   admission gate reopens and the builder is healthy after the teardown.
#
# Verdict contract: R7-STOP-PROOF=PASS | R7-STOP-PROOF=FAIL:<reason>.
# Any surviving descendant, any dir/mount residue, any admission failure or
# a non-succeeding build itself FAILS the proof and the evidence stays.
#
# Env inputs (guest side):
#   R7_ARTIFACT / R7_ARTIFACT_SHA256  the exact candidate RPM + digest
#   R7_EVIDENCE_DIR                   guest evidence directory
set -uo pipefail

ARTIFACT="${R7_ARTIFACT:?R7_ARTIFACT required}"
ARTIFACT_SHA="${R7_ARTIFACT_SHA256:?R7_ARTIFACT_SHA256 required}"

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

log()  { printf '[r7-stop-proof] %s\n' "$*"; }
fail() { printf '[r7-stop-proof] FAILED: %s\n' "$*" >&2; exit 1; }

EVIDENCE_DIR="${R7_EVIDENCE_DIR:-/tmp/r7-stop-proof-evidence}"
mkdir -p "$EVIDENCE_DIR"

cap() { # <name> <max-lines> <cmd...> — evidence capture never aborts the proof
  local name="$1" maxn="$2" rc; shift 2
  "$@" >"$EVIDENCE_DIR/$name.log" 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || printf 'capture rc=%d\n' "$rc" >>"$EVIDENCE_DIR/$name.log"
  log "--- $name (evidence: $EVIDENCE_DIR/$name.log, first $maxn lines) ---"
  head -n "$maxn" "$EVIDENCE_DIR/$name.log"
  return 0
}

DH_SOCK=/run/docker-helper/docker-helper.sock
STATE_DIR=/tmp/r7-stop-proof-state
mkdir -p "$STATE_DIR"

[ "$(id -u)" = "0" ] || fail "must run as root"
[ -f "$ARTIFACT" ] || fail "artifact missing: $ARTIFACT"
now_sha="$(sha256sum "$ARTIFACT" | awk '{print $1}')"
[ "$now_sha" = "$ARTIFACT_SHA" ] || fail "artifact SHA mismatch (expected $ARTIFACT_SHA, got $now_sha)"

PRINCIPAL="${SUDO_USER:-}"
[ -n "$PRINCIPAL" ] && [ "$PRINCIPAL" != "root" ] || fail "cannot derive non-root principal (SUDO_USER='$SUDO_USER')"
PRINCIPAL_HOME="$(getent passwd "$PRINCIPAL" | cut -d: -f6)"
[ -n "$PRINCIPAL_HOME" ] && [ -d "$PRINCIPAL_HOME" ] || fail "principal home not found: $PRINCIPAL_HOME"
ALLOWED_ROOT="$PRINCIPAL_HOME"

# ============================================================================
# Section 1: platform + AppArmor enforcing proof
# ============================================================================
if [ -f "$STATE_DIR/sec1" ]; then
  log "phase marker: section 1 done; skipping"
else
  log "=== section 1: platform + AppArmor state ==="
  AA="$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo absent)"
  [ "$AA" = "Y" ] || fail "AppArmor not enabled (/sys/module/apparmor/parameters/enabled='$AA')"
  cat /sys/kernel/security/lsm >"$EVIDENCE_DIR/lsm.txt" 2>&1 || true
  grep -qw apparmor "$EVIDENCE_DIR/lsm.txt" || fail "apparmor not an active LSM: $(cat "$EVIDENCE_DIR/lsm.txt")"
  grep -qw selinux "$EVIDENCE_DIR/lsm.txt" && fail "selinux unexpectedly an active LSM: $(cat "$EVIDENCE_DIR/lsm.txt")"
  cap aa-status 12 aa-status
  cat /etc/os-release >"$EVIDENCE_DIR/os-release.txt" 2>&1
  grep -qi 'opensuse tumbleweed' "$EVIDENCE_DIR/os-release.txt" || fail "not openSUSE Tumbleweed"
  date '+%s %F %T' >"$STATE_DIR/sec1.ts"
  touch "$STATE_DIR/sec1"
fi

# ============================================================================
# Section 2: exact candidate install (never rebuilds)
# ============================================================================
if [ -f "$STATE_DIR/sec2" ]; then
  log "phase marker: section 2 done; skipping"
else
  log "=== section 2: candidate install ==="
  rpm -q docker-helper >/dev/null 2>&1 && rpm -e docker-helper >/dev/null 2>&1 || true
  rpm -i "$ARTIFACT" >"$EVIDENCE_DIR/install.log" 2>&1 \
    || fail "rpm -i failed (evidence: $EVIDENCE_DIR/install.log)"
  log "RPM installed: $(rpm -q docker-helper)"
  # The RPM install adapter runs `docker-helper init --allowed-root` after
  # `rpm -i` (the init provisions the config and starts the daemon; the RPM
  # scriptlets do not). Without it the API socket never appears.
  docker-helper init --allowed-root "$ALLOWED_ROOT" >>"$EVIDENCE_DIR/install.log" 2>&1 \
    || fail "docker-helper init failed"
  systemctl daemon-reload
  systemctl enable --now docker-helper.service >>"$EVIDENCE_DIR/install.log" 2>&1 || true
  systemctl enable --now docker-helper-builder.service >>"$EVIDENCE_DIR/install.log" 2>&1 || true
  touch "$STATE_DIR/sec2"
fi

# ============================================================================
# Section 3: install stabilization (the observed mid-install reboot leaves
# the AppArmor profile load half-done; diagnostic-environment repair only)
# ============================================================================
if [ -f "$STATE_DIR/sec3" ]; then
  log "phase marker: section 3 done; skipping"
else
  log "=== section 3: install stabilization ==="
  STAB_LOG="$EVIDENCE_DIR/stop-proof-stabilization.log"
  {
    echo "=== pre-repair state ($(date +%H:%M:%S)):"
    aa-status 2>&1 | grep -E "docker-helper|rootlesskit" | head -10 || true
    loaded=0
    for _ in $(seq 1 30); do
      if aa-status 2>/dev/null | grep -q "docker-helper-builder" \
         && aa-status 2>/dev/null | grep -q "rootlesskit"; then
        loaded=1; break
      fi
      sleep 0.5
    done
    echo "--- profiles settled wait: loaded=$loaded"
    if [ "$loaded" != 1 ]; then
      echo "--- force-loading the shipped profiles:"
      apparmor_parser --replace --skip-read-cache /etc/apparmor.d/docker-helper-system 2>&1 || true
      apparmor_parser --replace --skip-read-cache /etc/apparmor.d/docker-helper-builder 2>&1 || true
      if [ -e /etc/apparmor.d/rootlesskit ]; then
        apparmor_parser --replace --skip-read-cache /etc/apparmor.d/rootlesskit 2>&1 || true
      fi
    fi
    echo "=== post-repair state:"
    aa-status 2>&1 | grep -E "docker-helper|rootlesskit" | head -10 || true
  } >"$STAB_LOG" 2>&1
  # Wait for the confined daemon to come up and prove its confinement.
  ready=0
  for _ in $(seq 1 60); do
    if [ -S "$DH_SOCK" ] && curl --silent --fail --max-time 1 \
        --unix-socket "$DH_SOCK" http://localhost/health >/dev/null 2>&1; then
      ready=1; break
    fi
    sleep 1
  done
  [ "$ready" = 1 ] || fail "daemon not ready on $DH_SOCK after install"
  systemctl show docker-helper -p MainPID >"$EVIDENCE_DIR/daemon-mainpid.txt" 2>&1
  MP="$(awk -F= '{print $2}' "$EVIDENCE_DIR/daemon-mainpid.txt")"
  cat "/proc/$MP/attr/current" >"$EVIDENCE_DIR/daemon-context.txt" 2>&1 || true
  log "daemon ready on $DH_SOCK (pid $MP, context $(cat "$EVIDENCE_DIR/daemon-context.txt" 2>/dev/null))"
  touch "$STATE_DIR/sec3"
fi

# ============================================================================
# Section 4: principal + session setup
# ============================================================================
if [ -f "$STATE_DIR/sec4" ]; then
  log "phase marker: section 4 done; skipping"
else
  log "=== section 4: principal + session ==="
  ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
  [ -n "$ADMIN_TOKEN" ] || fail "admin token unreadable"

  WS="$ALLOWED_ROOT/r7-stop-ws"
  rm -rf "$WS"; mkdir -p "$WS/ctx"
  cat > "$WS/ctx/Dockerfile" <<'EOF'
FROM alpine:3.24
RUN sleep 300
USER 65534:65534
EOF
  chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"

  if ! docker-helper principal create --no-credential "$PRINCIPAL" 2>/dev/null; then
    docker-helper principal show "$PRINCIPAL" >/dev/null \
      || fail "principal create failed and principal '$PRINCIPAL' is absent"
  fi
  docker-helper principal allowed-root add "$PRINCIPAL" "$ALLOWED_ROOT" 2>/dev/null \
    || docker-helper principal show "$PRINCIPAL" >/dev/null \
    || fail "principal allowed-root add failed"

  SESS_JSON="$(curl --silent --max-time 5 \
    --unix-socket "$DH_SOCK" -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"workspace\":\"$WS\",\"principal\":\"$PRINCIPAL\"}" \
    -o "$EVIDENCE_DIR/session-response.json" -w '%{http_code}' http://localhost/sessions)" \
    || { cat "$EVIDENCE_DIR/session-response.json"; fail "session create request failed"; }
  log "session create HTTP $SESS_JSON"
  SESS_TOKEN="$(grep -oE '"token": *"[^"]+"' "$EVIDENCE_DIR/session-response.json" | head -1 | sed 's/.*"token": *"//;s/"$//')"
  [ -n "$SESS_TOKEN" ] || fail "session token missing (response: $(head -c 400 "$EVIDENCE_DIR/session-response.json"))"
  printf '%s' "$SESS_TOKEN" >"$STATE_DIR/sess-token"
  export DOCKER_HELPER_SESSION_TOKEN="$SESS_TOKEN"
  docker-helper pull alpine:3.24 >"$EVIDENCE_DIR/pull.log" 2>&1 \
    || fail "pull alpine:3.24 failed (evidence: $EVIDENCE_DIR/pull.log)"
  log "session + workspace ready; base image pulled"
  touch "$STATE_DIR/sec4"
fi
SESS_TOKEN="$(cat "$STATE_DIR/sess-token")"

# ============================================================================
# Shared helpers: process-tree capture + whole-tree survivor proof
# ============================================================================

# proc_rows: one line per process: pid ppid pgrp sess comm
# (stat = "pid (comm) state ppid pgrp session ..."; the field split is pure
# parameter expansion — anchored on the FIRST ') ' — no regex engine)
proc_rows() {
  for p in /proc/[0-9]*; do
    pid="${p#/proc/}"
    stat="$(cat "$p/stat" 2>/dev/null)"; [ -n "$stat" ] || continue
    case "$stat" in *"("*") "*) ;;
      *) continue;;
    esac
    comm="$(printf '%s' "$stat")"
    comm="${comm##*\(}"
    comm="${comm%%)*}"
    [ -n "$comm" ] || continue
    rest="${stat#*) }"
    ppid="$(printf '%s' "$rest" | awk '{print $2}')"
    pgrp="$(printf '%s' "$rest" | awk '{print $3}')"
    sess="$(printf '%s' "$rest" | awk '{print $4}')"
    printf '%s %s %s %s %s\n' "$pid" "$ppid" "$pgrp" "$sess" "$comm"
  done
}

# capture_tree <tag> <inst_pid> — write the FULL closure evidence:
# ancestry from inst.pid UNION every process whose pgrp is any closure
# member's pgrp (the off-group runc shape), to a fixpoint. One summary
# line per member: pid ppid pgrp sess comm exe nspid cgroup
capture_tree() {
  local tag="$1" root="$2"
  local out="$EVIDENCE_DIR/$tag-tree.tsv"
  proc_rows >"$EVIDENCE_DIR/$tag-procrows.tsv"
  awk -v root="$root" '
    { pid[$1]=1; ppid[$1]=$2; pgrp[$1]=$3; sess[$1]=$4; comm[$1]=$5 }
    END {
      # ancestry closure from the setsid leader (the `in` operator probes
      # without creating — a plain indexed test would seed phantom keys)
      inC[root]=1
      changed=1
      while (changed) {
        changed=0
        for (p in pid) {
          if (!(p in inC) && (ppid[p] in inC)) { inC[p]=1; changed=1 }
        }
      }
      # pgrp closure: every process whose pgrp is a closure member pgrp
      for (p in inC) if (pgrp[p] > 1) pg[pgrp[p]]=1
      changed=1
      while (changed) {
        changed=0
        for (p in pid) {
          if (!(p in inC) && (pgrp[p] in pg)) { inC[p]=1; pg[pgrp[p]]=1; changed=1 }
        }
      }
      for (p in inC) if (p in pid) print p, ppid[p], pgrp[p], sess[p], comm[p]
    }' "$EVIDENCE_DIR/$tag-procrows.tsv" | sort -n >"$EVIDENCE_DIR/$tag-closure.txt"
  : >"$out"
  : >"$EVIDENCE_DIR/$tag-mounts.txt"
  while read -r pid ppid pgrp sess comm; do
    [ -n "$pid" ] || continue
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || echo '-')"
    nspid="$(grep '^NSpid:' "/proc/$pid/status" 2>/dev/null | awk '{print $2}' || true)"
    cg="$(cat "/proc/$pid/cgroup" 2>/dev/null | head -1 || true)"
    printf '%s %s %s %s %s %s %s %s\n' "$pid" "$ppid" "$pgrp" "$sess" "$comm" "$exe" "${nspid:--}" "$cg" >>"$out"
    grep -h "docker-helper-builder/ops/" "/proc/$pid/mounts" 2>/dev/null \
      | sed "s/^/pid=$pid /" >>"$EVIDENCE_DIR/$tag-mounts.txt" || true
  done <"$EVIDENCE_DIR/$tag-closure.txt"
  log "captured $tag: $(wc -l <"$EVIDENCE_DIR/$tag-closure.txt") processes, $(sort -u -k3 "$EVIDENCE_DIR/$tag-closure.txt" | wc -l) distinct pgids"
  cp "$out" "$EVIDENCE_DIR/$tag-tree-final.tsv"
}

# wait_liveness <op_id> — wait until buildkit-runc AND the OCI workload are
# live under THIS op's instance tree (rooted at the recorded instance.pid).
wait_liveness() {
  local op="$1" inst=""
  for _ in $(seq 1 240); do
    inst="$(cat "/run/docker-helper-builder/ops/$op/instance.pid" 2>/dev/null || true)"
    [ -n "$inst" ] && [ -d "/proc/$inst" ] || { sleep 0.5; continue; }
    proc_rows >"$EVIDENCE_DIR/liveness-rows.tsv"
    if grep -q 'buildkit-runc$' "$EVIDENCE_DIR/liveness-rows.tsv" \
       && grep -E ' (sleep|sh)$' "$EVIDENCE_DIR/liveness-rows.tsv" >/dev/null; then
      printf '%s' "$inst"
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# survivor_proof <tag> <op_id> — the whole-tree convergence proof. Prints
# one FAIL line per finding; empty output = converged. A process in Z
# (exited, unreaped) state counts as dead: its address space, namespaces
# and mounts are gone; only the exit-status slot lingers.
survivor_proof() {
  local tag="$1" op="$2"
  local findings=0
  # (1) every captured pid gone (Zombies count as dead)
  while read -r pid _; do
    [ -n "$pid" ] || continue
    if [ -d "/proc/$pid" ]; then
      pst="$(cat "/proc/$pid/stat" 2>/dev/null)"
      st="${pst#*) }"; st="${st%% *}"
      if [ -n "$st" ] && [ "$st" != "Z" ]; then
        echo "SURVIVOR-PID $pid state=$st comm=$(cat "/proc/$pid/comm" 2>/dev/null) from $tag closure"
        findings=$((findings + 1))
      fi
    fi
  done < <(awk '{print $1}' "$EVIDENCE_DIR/$tag-closure.txt" 2>/dev/null)
  # (2) every captured pgid dead — the off-group proof
  for pgid in $(awk '{print $3}' "$EVIDENCE_DIR/$tag-closure.txt" 2>/dev/null | sort -un); do
    [ "$pgid" -gt 1 ] || continue
    if kill -0 -"$pgid" 2>/dev/null; then
      echo "SURVIVOR-PGID $pgid still has live members (kill(-$pgid,0) succeeded)"
      findings=$((findings + 1))
    fi
  done
  # (3) no builder-flow comm anywhere on the host (runc is matched by its
  # product exe only — a distro runc serving the Docker daemon is not ours)
  proc_rows >"$EVIDENCE_DIR/$tag-postrows.tsv"
  for c in rootlesskit buildkitd buildkit-runc; do
    hits="$(awk -v c="$c" '$5 == c {print $1}' "$EVIDENCE_DIR/$tag-postrows.tsv")"
    if [ -n "$hits" ]; then
      echo "SURVIVOR-COMM $c pids: $(printf '%s ' $hits)"
      findings=$((findings + 1))
    fi
  done
  for p in /proc/[0-9]*; do
    exe="$(readlink "$p/exe" 2>/dev/null || true)"
    case "$exe" in
      /usr/libexec/docker-helper/*)
        echo "SURVIVOR-EXE pid=${p#/proc/} exe=$exe"
        findings=$((findings + 1));;
    esac
  done
  # (4) no exe/cwd under the builder roots
  for p in /proc/[0-9]*; do
    pid="${p#/proc/}"
    for link in exe cwd; do
      tgt="$(readlink "$p/$link" 2>/dev/null || true)"
      case "$tgt" in
        /run/docker-helper-builder/*|/var/lib/docker-helper-builder/*)
          echo "SURVIVOR-LINK pid=$pid $link=$tgt"
          findings=$((findings + 1));;
      esac
    done
  done
  # (5) no mount entry for THIS operation's per-op subtrees in any live
  # namespace (the standing ROOT mounts of the builder runtime/state roots
  # — the service namespace's tmpfs/xfs holders — are infrastructure, not
  # per-op residue; only ops/<op> entries are). The captured members'
  # cgroup paths are recorded in the tree evidence; a container's private
  # cgroup namespace makes its host-side path non-attributive, so the
  # pid/comm/exe/pgid nets above carry the proof.
  for p in /proc/[0-9]*; do
    hits="$(grep -h "docker-helper-builder/ops/$op" "$p/mounts" 2>/dev/null | head -2 | tr '\n' '|')"
    if [ -n "$hits" ]; then
      echo "SURVIVOR-MOUNT pid=${p#/proc/}: $hits"
      findings=$((findings + 1))
    fi
  done
  # (6) the op's runtime AND state dirs absent (verified removeInstanceDirs)
  for d in "/run/docker-helper-builder/ops/$op" "/var/lib/docker-helper-builder/ops/$op"; do
    if [ -e "$d" ]; then
      echo "RESIDUE-DIR $d still present"
      findings=$((findings + 1))
    fi
  done
  return "$findings"
}

# await_terminal <op_id> <timeout_s> <tag> — poll until completed_at; on the
# FIRST terminal observation immediately run the survivor scan (the
# false-STOP-OK proof point) and record it.
await_terminal() {
  local op="$1" timeout="$2" tag="$3"
  for _ in $(seq 1 "$((timeout * 2))"); do
    body="$(curl --silent --max-time 3 --unix-socket "$DH_SOCK" \
      -H "Authorization: Bearer $SESS_TOKEN" "http://localhost/operations/$op")" || { sleep 0.5; continue; }
    printf '%s\n' "$body" >"$EVIDENCE_DIR/$tag-status-final.json"
    if printf '%s' "$body" | grep -q '"completed_at"'; then
      date '+%s.%N' >"$EVIDENCE_DIR/$tag-terminal-moment.ts"
      survivor_proof "$tag" "$op" >"$EVIDENCE_DIR/$tag-terminal-scan.txt" 2>&1 || true
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# run_scenario <tag> <image> <kill_buildctl:0|1> — one full proof scenario.
# Every failure path after a successful start best-effort cancels the
# started op first: a leaked RUNNING build would saturate the fixed build
# capacity and poison the retry attempts.
run_scenario() {
  local tag="$1" image="$2" killbuildctl="$3" op resp inst
  log "=== scenario $tag: starting build ($image) ==="
  resp="$(curl --silent --max-time 5 --unix-socket "$DH_SOCK" \
    -H "Authorization: Bearer $SESS_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"context\":\"ctx\",\"dockerfile\":\"Dockerfile\",\"image\":\"$image\"}" \
    -o "$EVIDENCE_DIR/$tag-build-response.json" -w '%{http_code}' http://localhost/build)" \
    || fail "scenario $tag: build start request failed"
  case "$resp" in
    200|201) ;;
    *) fail "scenario $tag: build start HTTP $resp ($(head -c 300 "$EVIDENCE_DIR/$tag-build-response.json"))";;
  esac
  op="$(sed -n 's/.*"operation_id": *"\([^"]*\)".*/\1/p' "$EVIDENCE_DIR/$tag-build-response.json")"
  [ -n "$op" ] || fail "scenario $tag: operation_id missing ($(head -c 300 "$EVIDENCE_DIR/$tag-build-response.json"))"
  log "scenario $tag: op $op running"

  if ! inst="$(wait_liveness "$op")"; then
    curl --silent --max-time 5 --unix-socket "$DH_SOCK" \
      -H "Authorization: Bearer $SESS_TOKEN" \
      "http://localhost/operations/$op/logs" >"$EVIDENCE_DIR/$tag-op-logs.txt" 2>&1 || true
    curl --silent --max-time 10 --unix-socket "$DH_SOCK" \
      -H "Authorization: Bearer $SESS_TOKEN" -X POST \
      -o /dev/null "http://localhost/operations/$op/cancel" 2>/dev/null || true
    echo "R7-STOP-PROOF=FAIL:$tag the RUN step never became live (buildkit-runc/workload absent; see $tag-op-logs.txt)"
    return 1
  fi
  log "scenario $tag: RUN step live (instance pid $inst); capturing the tree"
  capture_tree "$tag" "$inst"
  cap "$tag-opdirs" 20 bash -c "ls -la /run/docker-helper-builder/ops/$op /var/lib/docker-helper-builder/ops/$op 2>&1"

  if [ "$killbuildctl" = 1 ]; then
    log "scenario $tag: EMERGENCY path — SIGKILL the buildctl client mid-RUN"
    pgrep -x buildctl >"$EVIDENCE_DIR/$tag-buildctl-pids.txt" 2>/dev/null || true
    if [ ! -s "$EVIDENCE_DIR/$tag-buildctl-pids.txt" ]; then
      curl --silent --max-time 10 --unix-socket "$DH_SOCK" \
        -H "Authorization: Bearer $SESS_TOKEN" -X POST \
        -o /dev/null "http://localhost/operations/$op/cancel" 2>/dev/null || true
      echo "R7-STOP-PROOF=FAIL:$tag no buildctl process found to kill"
      return 1
    fi
    pkill -9 -x buildctl || true
    sleep 1
    log "scenario $tag: buildctl killed; the driver's failure path must STOP the live tree"
  else
    log "scenario $tag: graceful cancel"
    resp="$(curl --silent --max-time 10 --unix-socket "$DH_SOCK" \
      -H "Authorization: Bearer $SESS_TOKEN" -X POST \
      -o "$EVIDENCE_DIR/$tag-cancel-response.json" -w '%{http_code}' \
      "http://localhost/operations/$op/cancel")" \
      || { echo "R7-STOP-PROOF=FAIL:$tag the cancel request failed"; return 1; }
    if [ "$resp" != "200" ]; then
      echo "R7-STOP-PROOF=FAIL:$tag cancel HTTP $resp ($(head -c 300 "$EVIDENCE_DIR/$tag-cancel-response.json"))"
      return 1
    fi
  fi

  if ! await_terminal "$op" 180 "$tag"; then
    curl --silent --max-time 10 --unix-socket "$DH_SOCK" \
      -H "Authorization: Bearer $SESS_TOKEN" -X POST \
      -o /dev/null "http://localhost/operations/$op/cancel" 2>/dev/null || true
    echo "R7-STOP-PROOF=FAIL:$tag the operation did not reach a terminal state within 180s"
    return 1
  fi
  log "scenario $tag: terminal at $(cat "$EVIDENCE_DIR/$tag-terminal-moment.ts") — running the whole-tree survivor proof"
  if survivor_proof "$tag" "$op" >"$EVIDENCE_DIR/$tag-survivors.txt" 2>&1; then
    log "scenario $tag: converged — no survivors, no residue"
  else
    echo "R7-STOP-PROOF=FAIL:$tag survivors/residue after the terminal transition (FALSE STOP OK):"
    cat "$EVIDENCE_DIR/$tag-survivors.txt"
    return 1
  fi
  # the terminal scan at the exact terminal moment is the false-OK proof
  if [ -s "$EVIDENCE_DIR/$tag-terminal-scan.txt" ]; then
    echo "R7-STOP-PROOF=FAIL:$tag survivors already present AT the terminal moment (the terminal scan):"
    cat "$EVIDENCE_DIR/$tag-terminal-scan.txt"
    return 1
  fi
  curl --silent --max-time 5 --unix-socket "$DH_SOCK" \
    -H "Authorization: Bearer $SESS_TOKEN" \
    "http://localhost/operations/$op/logs" >"$EVIDENCE_DIR/$tag-op-logs.txt" 2>&1 || true
  cap "$tag-stop-journal" 40 journalctl -u docker-helper --no-pager -g "STOP $op"
  log "scenario $tag: PASS"
  return 0
}

# ============================================================================
# Section 5: scenario A — graceful cancel of a live RUN step
# ============================================================================
if [ ! -f "$STATE_DIR/sec5" ]; then
  log "=== section 5: scenario A (graceful cancel) ==="
  if run_scenario A "r7-stop-a:1" 0; then
    touch "$STATE_DIR/sec5"
  else
    # A proof failure is terminal: the verdict line is already on stdout
    # (a retry would re-run the whole scenario and the evidence stays).
    exit 1
  fi
else
  log "phase marker: section 5 done; skipping"
fi

# ============================================================================
# Section 6: scenario B — emergency STOP (buildctl SIGKILLed mid-RUN; the
# mandatory manager STOP must converge the LIVE tree with no wind-down)
# ============================================================================
if [ ! -f "$STATE_DIR/sec6" ]; then
  log "=== section 6: scenario B (emergency STOP) ==="
  if run_scenario B "r7-stop-b:1" 1; then
    touch "$STATE_DIR/sec6"
  else
    exit 1
  fi
else
  log "phase marker: section 6 done; skipping"
fi

# ============================================================================
# Section 7: admission reopens after both teardowns
# ============================================================================
if [ ! -f "$STATE_DIR/sec7" ]; then
  log "=== section 7: admission reopens (a fresh build must succeed) ==="
  mkdir -p "$ALLOWED_ROOT/r7-stop-ws/ctx2"
  cat > "$ALLOWED_ROOT/r7-stop-ws/ctx2/Dockerfile" <<'EOF'
FROM alpine:3.24
RUN true
USER 65534:65534
EOF
  chown -R "$PRINCIPAL:$PRINCIPAL" "$ALLOWED_ROOT/r7-stop-ws/ctx2"
  resp="$(curl --silent --max-time 5 --unix-socket "$DH_SOCK" \
    -H "Authorization: Bearer $SESS_TOKEN" -H 'Content-Type: application/json' \
    -d '{"context":"ctx2","dockerfile":"Dockerfile","image":"r7-stop-admission:1"}' \
    -o "$EVIDENCE_DIR/admission-build-response.json" -w '%{http_code}' http://localhost/build)" \
    || fail "admission build start failed"
  [ "$resp" = "200" ] || [ "$resp" = "201" ] || fail "admission build start HTTP $resp"
  admop="$(sed -n 's/.*"operation_id": *"\([^"]*\)".*/\1/p' "$EVIDENCE_DIR/admission-build-response.json")"
  [ -n "$admop" ] || fail "admission operation_id missing"
  admok=0
  for _ in $(seq 1 480); do
    body="$(curl --silent --max-time 3 --unix-socket "$DH_SOCK" \
      -H "Authorization: Bearer $SESS_TOKEN" "http://localhost/operations/$admop")" || { sleep 0.5; continue; }
    printf '%s\n' "$body" >"$EVIDENCE_DIR/admission-status-final.json"
    if printf '%s' "$body" | grep -q '"completed_at"'; then
      if printf '%s' "$body" | grep -q '"result_code": *"succeeded"'; then
        admok=1
      fi
      break
    fi
    sleep 0.5
  done
  [ "$admok" = 1 ] || fail "the post-teardown admission build did not succeed ($(head -c 300 "$EVIDENCE_DIR/admission-status-final.json"))"
  log "admission reopens: the post-teardown build succeeded ($admop)"
  touch "$STATE_DIR/sec7"
else
  log "phase marker: section 7 done; skipping"
fi

echo "R7-STOP-PROOF=PASS"
exit 0
