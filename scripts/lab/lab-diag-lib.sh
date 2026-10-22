#!/usr/bin/env bash
#
# lab-diag-lib.sh — the bounded diagnostic execution owner for the lab VM.
#
# Consumers:
#   * diagnose-launch.sh — the standalone uat-diagnose stage runs
#     diag_run_ladder as the agent account inside a networked VM;
#   * integration-agent-vm.sh — probe_run executes every bounded probe
#     through diag_exec so one implementation owns timeouts, stderr capture,
#     elapsed time and outcome classification.
#
# Every command runs under `timeout --kill-after`: the diagnostic never
# waits unboundedly for a process or a child container. A timeout kill is a
# first-class outcome (never a PASS, a SKIP, or an empty result).
#
# OWNERSHIP MODEL (UAT-8d). Cleanup touches only resources this diagnostic
# run provably owns:
#   * Containers started directly by the ladder (D0–D2 and the factor
#     probes) carry a unique `--name dhl-<step>-<runid>` AND the diagnostic
#     label `lab.diagnostic.runid=<runid>`. Before any forced removal the
#     container is re-inspected: the name must exist, the runid label must
#     match THIS run and the image must match the pinned reference. An
#     unverified container is never removed; the refusal is recorded.
#   * Containers of the canonical steps (D3/D4) are attributed by the
#     daemon's own reserved labels: `com.dockerhelper.session.id` names the
#     owning Session, and a Session is this run's only when its workspace
#     equals this run's unique diagnostic workspace (verified through the
#     daemon's own `session list --json`, which carries no bearer tokens).
#     No global before/after diff is ever used as ownership evidence.
#   * Sessions are cleaned only by registered identity: after each canonical
#     step the (error-checked) session list is scanned for THIS run's
#     diagnostic workspace; only those exact IDs may be deleted. A failed
#     session list refuses the cleanup instead of proceeding with an empty
#     snapshot. The canonical launcher keeps the primary responsibility for
#     deleting its own Session; the diagnostic only recovers provably
#     leaked ones.
#
# Observability contract per invocation:
#   $DIAG_DIR/<name>.out      the command's stdout
#   $DIAG_DIR/<name>.err      the command's stderr (never suppressed)
#   $DIAG_DIR/<name>.rc       the observed exit status
#   $DIAG_DIR/<name>.elapsed  wall-clock seconds
#   $DIAG_DIR/<name>.layer    docker-cli | timeout | container | script
#   $DIAG_DIR/<name>.reap     ok | failed | refused-unowned | n/a
#   $DIAG_DIR/<name>.session  clean | reaped | refused-list-error | n/a
#
# Secrets: the report is an allowlist of compact result lines; environment
# values, bearer tokens, credentials and raw docker inspect output never
# enter any diagnostic output, and every excerpt is sanitized at BOTH the
# file-write and the print boundaries.

set -u

DIAG_KILL_AFTER="${DIAG_KILL_AFTER:-10}"
# the ladder bounds: production defaults 30/60; overridable ONLY for the
# behavioral test harness (fast, still bounded)
DIAG_STEP_BOUND="${DIAG_STEP_BOUND:-30}"
DIAG_CANON_BOUND="${DIAG_CANON_BOUND:-60}"
DIAG_FACTOR_BOUND="${DIAG_FACTOR_BOUND:-30}"
# the aliases source path for the child shells: $HOME/.bash_aliases in the
# VM; a test harness may point it at the repository copy
DC_ALIASES="${DC_ALIASES:-$HOME/.bash_aliases}"
# test-scoped seam for the docker-init candidate search: when SET (even to
# empty), the lab init verification consults EXACTLY this candidate list
# (used to model a host without any docker-init). Production never sets it;
# this library must not assign a default, because the seam's set/empty
# distinction is what models the absence of docker-init.
# LAB_DOCKER_INIT_CANDIDATES is consumed by agent-aliases.sh via ${VAR+x}.
# the daemon's reserved container labels (one code owner: runtime_labels.go);
# used ONLY as read-only ownership evidence for the canonical steps
DIAG_SESSION_LABEL="com.dockerhelper.session.id"
DIAG_SCHEMA_LABEL="com.dockerhelper.schema"
DIAG_SCHEMA_VALUE="1"

# diag_sanitize TEXT — defense in depth for anything the report quotes:
# bearer-token shapes, admin-token shapes, Authorization values and private
# key material are redacted before any evidence text reaches the report.
diag_sanitize() {
  printf '%s' "$1" \
    | sed -E -e 's/dht_[0-9a-zA-Z]{16,}/dht_REDACTED/g' \
             -e 's/(Bearer[[:space:]]+)[^[:space:]]+/\1REDACTED/g' \
             -e 's/-----BEGIN[A-Z ]*PRIVATE KEY-----/REDACTED-KEY/g' \
             -e 's/(ADMIN[A-Za-z0-9_]*[[:space:]]*[:=][[:space:]]*)[^[:space:]]+/\1REDACTED/g'
}

# diag_exec NAME BOUND CMD... -> runs one bounded command, records everything
diag_exec() { # NAME BOUND CMD...
  local name="$1" bound="$2"
  shift 2
  local t0=$SECONDS rc reap="n/a"
  if timeout --kill-after="$DIAG_KILL_AFTER" "$bound" "$@" \
      >"$DIAG_DIR/$name.out" 2>"$DIAG_DIR/$name.err"; then
    rc=0
  else
    rc=$?
  fi
  printf '%s\n' "$((SECONDS - t0))" > "$DIAG_DIR/$name.elapsed"
  printf '%s\n' "$rc" > "$DIAG_DIR/$name.rc"
  case "$rc" in
    124|137) printf '%s\n' timeout > "$DIAG_DIR/$name.layer" ;;
    125|126|127) printf '%s\n' docker-cli > "$DIAG_DIR/$name.layer" ;;
    *) printf '%s\n' container > "$DIAG_DIR/$name.layer" ;;
  esac
  if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
    reap="$(diag_reap_owned_container "${DIAG_CONTAINER_NAME:-}")"
  fi
  printf '%s\n' "$reap" > "$DIAG_DIR/$name.reap"
  return "$rc"
}

# diag_reap_owned_container NAME — remove a diagnostic-owned container ONLY
# after its identity is verified: the name must exist, its
# lab.diagnostic.runid label must equal THIS run's id, and its image must
# equal the pinned reference. Anything else is never removed.
diag_reap_owned_container() { # NAME -> ok | failed | refused-unowned | n/a
  local name="$1"
  [ -n "$name" ] || { printf 'n/a'; return 0; }
  [ -n "${DIAG_RUNID:-}" ] || { printf 'refused-unowned'; return 0; }
  local observed
  observed="$(docker inspect --format \
    '{{index .Config.Labels "lab.diagnostic.runid"}}|{{.Image}}' "$name" 2>/dev/null)" \
    || { printf 'refused-unowned'; return 0; }
  case "$observed" in
    "${DIAG_RUNID}|${DIAG_IMAGE}") ;;
    *) printf 'refused-unowned'; return 0 ;;
  esac
  if docker rm -f "$name" >/dev/null 2>&1; then
    printf 'ok'
  else
    printf 'failed'
  fi
  return 0
}

# diag_register_step_sessions WORKSPACE FILE — error-checked registration of
# the Session IDs provably owned by this diagnostic run: the daemon's own
# list, filtered to THIS run's unique diagnostic workspace. A failed list is
# a refusal, never an empty snapshot. The list carries no bearer tokens.
diag_register_step_sessions() { # WORKSPACE FILE -> 0 ok | 1 list-failed
  local ws="$1" file="$2" raw
  if ! raw="$(docker-helper session list --json 2>/dev/null)"; then
    return 1
  fi
  printf '%s' "$raw" | jq -r --arg ws "$ws" \
    '.sessions[] | select(.workspace == $ws) | .id' > "$file" 2>/dev/null \
    || { : > "$file"; return 1; }
  return 0
}

# diag_clean_registered_sessions FILE — delete exactly the registered Session
# IDs; anything not registered is never touched.
diag_clean_registered_sessions() { # FILE -> clean | reaped | failed | refused
  local file="$1" id outcome="clean"
  [ -s "$file" ] || { printf 'clean'; return 0; }
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if docker-helper session delete "$id" >/dev/null 2>&1; then
      outcome=reaped
    else
      outcome=failed
      break
    fi
  done < "$file"
  printf '%s' "$outcome"
  return 0
}

# diag_reap_registered_containers SESSIONS_FILE — remove the containers the
# daemon itself attributes to the registered (workspace-owned) Sessions, via
# the daemon's reserved labels. The session IDs were verified against this
# run's diagnostic workspace at registration time.
diag_reap_registered_containers() { # SESSIONS_FILE -> n/a | ok | failed | refused-unowned
  local file="$1" sid cid outcome="n/a"
  [ -s "$file" ] || { printf 'n/a'; return 0; }
  local ids=""
  while IFS= read -r sid; do
    [ -n "$sid" ] || continue
    ids="$ids --filter label=$DIAG_SESSION_LABEL=$sid"
  done < "$file"
  [ -n "$ids" ] || { printf 'n/a'; return 0; }
  # shellcheck disable=SC2086
  local found
  found="$(docker ps -aq --filter "label=$DIAG_SCHEMA_LABEL=$DIAG_SCHEMA_VALUE" $ids 2>/dev/null)" \
    || { printf 'refused-unowned'; return 0; }
  while IFS= read -r cid; do
    [ -n "$cid" ] || continue
    # double-check the label set before any forced removal
    local labels
    labels="$(docker inspect --format \
      '{{index .Config.Labels "com.dockerhelper.schema"}}|{{index .Config.Labels "com.dockerhelper.session.id"}}' "$cid" 2>/dev/null)" \
      || { outcome=refused-unowned; continue; }
    local sid_ok=0
    while IFS= read -r sid; do
      [ -n "$sid" ] || continue
      case "$labels" in
        "$DIAG_SCHEMA_VALUE|$sid") sid_ok=1; break ;;
      esac
    done < "$file"
    [ "$sid_ok" = 1 ] || { outcome=refused-unowned; continue; }
    if docker rm -f "$cid" >/dev/null 2>&1; then
      outcome=ok
    else
      outcome=failed
    fi
  done <<<"$found"
  printf '%s' "$outcome"
  return 0
}

# diag_classify ID MARKER -> DC_OK (1|0) and DC_DETAIL; records .detail.
# A missing or non-numeric exit status can never classify as a PASS.
diag_classify() { # ID MARKER
  local id="$1" marker="$2" rc
  rc="$(cat "$DIAG_DIR/$id.rc" 2>/dev/null || echo invalid)"
  case "$rc" in
    ''|*[!0-9]*)
      DC_OK=0; DC_DETAIL=no-exit-status ;;
    0)
      if grep -aqE "$marker" "$DIAG_DIR/$id.out" 2>/dev/null; then
        DC_OK=1; DC_DETAIL=ok
      else
        DC_OK=0; DC_DETAIL=no-marker
      fi ;;
    124|137)    DC_OK=0; DC_DETAIL=timeout ;;
    125|126|127) DC_OK=0; DC_DETAIL=docker-cli ;;
    *)          DC_OK=0; DC_DETAIL=container-exit ;;
  esac
  printf '%s\n' "$DC_DETAIL" > "$DIAG_DIR/$id.detail"
}

# diag_collect_failure ID — the safe failure diagnostics: allowlisted docker
# inspect fields, the container process list (argv only, never env), and a
# capped AVC tail. Observability failures are recorded explicitly. The
# report quotes only sanitized excerpts.
diag_collect_failure() { # ID
  local id="$1"
  local cname="dhl-$id-$DIAG_RUNID"
  {
    docker inspect --format '{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} err={{.State.Error}}' "$cname" 2>/dev/null || true
    docker ps -a --filter "name=$cname" --format '{{.Names}} {{.State}} {{.Status}}' 2>/dev/null || true
  } > "$DIAG_DIR/$id.docker-state" 2>/dev/null
  [ -s "$DIAG_DIR/$id.docker-state" ] || printf 'unavailable\n' > "$DIAG_DIR/$id.docker-state"
  if ! docker top "$cname" 2>/dev/null > "$DIAG_DIR/$id.procs"; then
    printf 'unavailable\n' > "$DIAG_DIR/$id.procs"
  fi
  dmesg 2>/dev/null | grep -i 'avc:' | tail -20 > "$DIAG_DIR/$id.avc" || true
  ausearch -m AVC -ts recent 2>/dev/null | tail -40 >> "$DIAG_DIR/$id.avc" || true
  diag_sanitize "$(tail -c 2000 "$DIAG_DIR/$id.err" 2>/dev/null || true)" > "$DIAG_DIR/$id.err.excerpt"
}

# diag_step_delta FROM TO — the specific configuration difference between two
# adjacent ladder steps (the transition evidence when a PASS turns into FAIL).
diag_step_delta() { # FROM TO
  case "$1->$2" in
    'D0->D1') printf '%s' '--init with the verified lab docker-init copy' ;;
    'D1->D2') printf '%s' '+ canonical mounts (workspace relabel, agent-owned OpenCode state, read-only helper runtime dir, optional CA/git/ssh/exchange), + launcher env flags, + /workspace workdir' ;;
    'D2->D3') printf '%s' '+ the Session lifecycle and bearer, + the per-launch ssh-agent (when a key is provisioned), + the -it TTY' ;;
    'D3->D4') printf '%s' 'the payload switches from a trivial exec to the real OpenCode entrypoint (--version)' ;;
    *) printf '%s' 'unknown step delta' ;;
  esac
}

# _diag_record_canonical_cleanup ID WS — the error-checked, workspace-scoped
# registration and recovery for one canonical step.
_diag_record_canonical_cleanup() { # ID WS
  local id="$1" ws="$2" outcome
  if diag_register_step_sessions "$ws" "$DIAG_DIR/$id.sessions.registered"; then
    outcome="$(diag_clean_registered_sessions "$DIAG_DIR/$id.sessions.registered")"
    local reap
    reap="$(diag_reap_registered_containers "$DIAG_DIR/$id.sessions.registered")"
    printf '%s/%s' "$outcome" "$reap" > "$DIAG_DIR/$id.session"
  else
    printf 'refused-list-error/n-a' > "$DIAG_DIR/$id.session"
  fi
}

# _diag_step_argv_compose ARRAYNAME LEVEL INIT_COPY WS — assemble the ladder's
# docker argv from the SINGLE canonical owners. Fail-closed: any composition
# or mount-gate refusal is propagated and the caller must NOT run docker.
_diag_step_argv_compose() { # ARRAYNAME LEVEL INIT_COPY [CONTAINER_NAME]
  # shellcheck disable=SC2178  # a bash nameref to the caller's array
  local -n args="$1"
  local level="$2" init_copy="$3"
  local cname="${4:-dhl-$level-$DIAG_RUNID}"
  args+=(run --rm --name "$cname")
  args+=(--label "lab.diagnostic.runid=$DIAG_RUNID")
  args+=(--label "lab.diagnostic.step=$level")
  [ "$level" != D0 ] && [ -n "$init_copy" ] && \
    args+=(--init -v "$init_copy:/sbin/docker-init:ro,z")
  _oc_security_opts args || return 1
  if [ "$level" = D2 ]; then
    _oc_compose_mounts_env args || return 1
  else
    args+=(-e HOME=/tmp)
  fi
  return 0
}

# _diag_run_docker_step ID LEVEL INIT_COPY PAYLOAD MARKER — fail-closed:
# composition errors stop BEFORE docker; the partial argv is never executed.
_diag_run_docker_step() { # ID LEVEL INIT_COPY PAYLOAD MARKER
  local id="$1" level="$2" init_copy="$3" payload="$4" marker="$5"
  local -a argv=()
  if ! _diag_step_argv_compose argv "$level" "$init_copy"; then
    printf 'refused\n' > "$DIAG_DIR/$id.rc"
    printf 'unknown\n' > "$DIAG_DIR/$id.elapsed"
    printf 'composition-refused\n' > "$DIAG_DIR/$id.detail"
    printf 'n/a\n' > "$DIAG_DIR/$id.reap"
    printf 'n/a\n' > "$DIAG_DIR/$id.session"
    DC_OK=0; DC_DETAIL=composition-refused
    return 1
  fi
  argv+=(--entrypoint /bin/sh "$DIAG_IMAGE" -c "$payload")
  DIAG_CONTAINER_NAME="dhl-$level-$DIAG_RUNID" \
    diag_exec "$id" "$DIAG_STEP_BOUND" docker "${argv[@]}" </dev/null || true
  diag_classify "$id" "$marker"
  printf 'n/a\n' > "$DIAG_DIR/$id.session"
  [ "$DC_OK" = 1 ] && return 0 || return 1
}

# _diag_canonical_step ID BOUND PAYLOAD MODE WS — run the canonical aliases
# path (oc-probe for exec, oc for the real entrypoint) under diag_exec, then
# register and recover exactly this run's leaked resources.
_diag_canonical_step() { # ID BOUND PAYLOAD MODE WS
  local id="$1" bound="$2" payload="$3" mode="$4" ws="$5"
  if [ "$mode" = exec ]; then
    DC_PAYLOAD="$payload" diag_exec "$id" "$bound" bash -c '
      # shellcheck source=/dev/null
      source "$DC_ALIASES"
      oc-probe "$DC_PAYLOAD"
    ' </dev/null
  else
    diag_exec "$id" "$bound" bash -c '
      # shellcheck source=/dev/null
      source "$DC_ALIASES"
      oc --version
    ' </dev/null
  fi
  local rc
  rc="$(cat "$DIAG_DIR/$id.rc" 2>/dev/null || echo 1)"
  _diag_record_canonical_cleanup "$id" "$ws"
  return "$rc"
}

# diag_report_lines IDS... — the compact per-step result lines. A step
# without recorded detail is NOT_RUN; a recorded step is always PASS or
# FAIL with a reason — never empty, never a skip.
diag_report_lines() {
  local id detail
  for id in "$@"; do
    if [ -f "$DIAG_DIR/$id.detail" ]; then
      detail="$(cat "$DIAG_DIR/$id.detail" 2>/dev/null || echo unknown)"
      local rc_line elapsed_line
      rc_line="$(cat "$DIAG_DIR/$id.rc" 2>/dev/null || echo invalid)"
      elapsed_line="$(cat "$DIAG_DIR/$id.elapsed" 2>/dev/null || echo unknown)"
      case "$rc_line" in
        refused) : ;;
        ''|*[!0-9]*) detail=no-exit-status; rc_line=invalid ;;
      esac
      if [ "$detail" = ok ]; then
        printf '%s PASS rc=%s elapsed=%s\n' "$id" "$rc_line" "$elapsed_line"
      else
        printf '%s FAIL rc=%s elapsed=%s detail=%s\n' "$id" "$rc_line" "$elapsed_line" "$detail"
      fi
    else
      printf '%s NOT_RUN\n' "$id"
    fi
  done
}

# _diag_report_factor ID — one factor-probe result line.
_diag_report_factor() { # ID
  local id="$1" detail
  [ -f "$DIAG_DIR/$id.detail" ] || return 0
  detail="$(cat "$DIAG_DIR/$id.detail")"
  if [ "$detail" = ok ]; then
    printf '%s PASS rc=%s elapsed=%s\n' "$id" \
      "$(cat "$DIAG_DIR/$id.rc" 2>/dev/null || echo invalid)" \
      "$(cat "$DIAG_DIR/$id.elapsed" 2>/dev/null || echo unknown)"
  else
    printf '%s FAIL rc=%s elapsed=%s detail=%s\n' "$id" \
      "$(cat "$DIAG_DIR/$id.rc" 2>/dev/null || echo invalid)" \
      "$(cat "$DIAG_DIR/$id.elapsed" 2>/dev/null || echo unknown)" \
      "$detail"
  fi
}

# diag_run_ladder IMAGE WS RUNID -> the compact report on stdout; rc 0 = all
# PASS. The ladder stops at the first FAIL (downstream steps NOT_RUN), runs
# bounded factor probes on the failing step, and names the implicated factor
# ONLY when exactly one factor probe succeeds where the step failed;
# otherwise the diagnosis is explicitly UNRESOLVED. It never starts the
# model's real workload and never touches an LLM.
diag_run_ladder() { # IMAGE WS RUNID
  DIAG_IMAGE="$1"
  local ws="$2"
  DIAG_RUNID="${3:-diag-$$}"
  cd "$ws" || return 1
  rm -f "$DIAG_DIR"/F-*.detail 2>/dev/null
  local all_pass=1 first_fail=""
  local DC_OK DC_DETAIL init_copy="" init_state=""
  DIAG_D3_INIT_COPY=""
  local -a argv=()

  # --- D0: the minimal runtime + SELinux posture ---------------------------
  # No init, no mounts, no TTY, stdin closed, HOME=/tmp (the operator's real
  # experiment). Isolates: the Docker runtime and the SELinux domain.
  _diag_run_docker_step D0 D0 "" 'echo D0_OK' 'D0_OK' \
    || { all_pass=0; first_fail="D0"; }

  # --- D1: D0 + --init with the verified lab copy ---------------------------
  if [ "$all_pass" = 1 ]; then
    if init_copy="$(_oc_verify_init_copy)"; then
      if [ -n "$init_copy" ]; then
        init_state=verified
        DIAG_D3_INIT_COPY="$init_copy"
        _diag_run_docker_step D1 D1 "$init_copy" 'echo D1_OK' 'D1_OK' \
          || { all_pass=0; first_fail="D1"; }
      else
        init_state=absent
        printf 'refused\n' > "$DIAG_DIR/D1.rc"
        printf 'unknown\n' > "$DIAG_DIR/D1.elapsed"
        printf 'no-init-copy\n' > "$DIAG_DIR/D1.detail"
        printf 'n/a\n' > "$DIAG_DIR/D1.reap"
        printf 'n/a\n' > "$DIAG_DIR/D1.session"
        DC_OK=0; DC_DETAIL=no-init-copy
        all_pass=0; first_fail="D1"
      fi
    else
      # _oc_verify_init_copy refused: a broken, drifted or non-standalone
      # copy is a fail-closed verification error — the init factor cannot be
      # exercised and D1 is a FAIL, never a successful --init run.
      init_state=refused
      printf 'refused\n' > "$DIAG_DIR/D1.rc"
      printf 'unknown\n' > "$DIAG_DIR/D1.elapsed"
      printf 'init-verify-refused\n' > "$DIAG_DIR/D1.detail"
      printf 'n/a\n' > "$DIAG_DIR/D1.reap"
      printf 'n/a\n' > "$DIAG_DIR/D1.session"
      DC_OK=0; DC_DETAIL=init-verify-refused
      all_pass=0; first_fail="D1"
    fi
  fi

  # --- D2: D1 + the canonical mounts/env/workdir ----------------------------
  # Documented diagnostic differences from production: no Session bearer (D3
  # adds the real Session lifecycle through the canonical composition), no
  # TTY, and the diagnostic ownership labels. The composition is
  # fail-closed: a mount-gate refusal stops the step BEFORE docker. An init
  # verification refusal already failed D1, so the ladder never reaches D2
  # in that state.
  if [ "$all_pass" = 1 ]; then
    _diag_run_docker_step D2 D2 "$init_copy" 'echo D2_OK' 'D2_OK' \
      || { all_pass=0; first_fail="D2"; }
  fi

  # --- D3: the canonical oc-probe path (a real Session, the bearer) ---------
  if [ "$all_pass" = 1 ]; then
    _diag_canonical_step D3 "$DIAG_CANON_BOUND" 'echo D3_OK' exec "$ws" || true
    diag_classify D3 'D3_OK'
    [ "$DC_OK" = 1 ] || { all_pass=0; first_fail="D3"; }
  fi

  # --- D4: the canonical OpenCode entrypoint --------------------------------
  if [ "$all_pass" = 1 ]; then
    _diag_canonical_step D4 "$DIAG_CANON_BOUND" '' real "$ws" || true
    diag_classify D4 '[0-9]+\.[0-9]+\.[0-9]+'
    [ "$DC_OK" = 1 ] || { all_pass=0; first_fail="D4"; }
  fi

  # --- the factor probes ----------------------------------------------------
  # They isolate exactly ONE factor of the canonical launch contract each.
  # Every probe is bounded, reuses the SINGLE canonical composition owners,
  # and is declared as diagnostic-only. The canonical path itself is never
  # modified.
  local step_marker=""
  if [ "$first_fail" = D0 ] || [ "$first_fail" = D1 ] || [ "$first_fail" = D2 ]; then
    local level="$first_fail"
    if [ "$init_state" = refused ] && [ "$level" != D0 ]; then
      # the canonical configuration for this step cannot be assembled (the
      # init verification refused); running the probes without the mandatory
      # init would exercise a DIFFERENT configuration, so no probe runs
      for id in "F-$level-tty" "F-$level-notty-stdin" "F-$level-script"; do
        printf 'init-verify-refused\n' > "$DIAG_DIR/$id.detail"
        printf 'refused\n' > "$DIAG_DIR/$id.rc"
        printf 'unknown\n' > "$DIAG_DIR/$id.elapsed"
      done
    else
    step_marker="${level}_OK"
    local payload="echo ${level}_OK"
    # F-tty: the same step WITH -it and the inherited pty stdin
    local -a fargv=()
    if _diag_step_argv_compose fargv "$level" "$init_copy" "dhl-F-$level-tty-$DIAG_RUNID"; then
      local -a tty_argv=("${fargv[0]}" -it "${fargv[@]:1}")
      tty_argv+=(--entrypoint /bin/sh "$DIAG_IMAGE" -c "$payload")
      DIAG_CONTAINER_NAME="dhl-F-$level-tty-$DIAG_RUNID" \
        diag_exec "F-$level-tty" "$DIAG_FACTOR_BOUND" docker "${tty_argv[@]}" || true
      diag_classify "F-$level-tty" "$step_marker"
    else
      printf 'composition-refused\n' > "$DIAG_DIR/F-$level-tty.detail"
      printf 'refused\n' > "$DIAG_DIR/F-$level-tty.rc"
      printf 'unknown\n' > "$DIAG_DIR/F-$level-tty.elapsed"
    fi
    # F-notty-stdin: no -it, but the pty stdin is inherited (no </dev/null)
    local -a sargv=()
    if _diag_step_argv_compose sargv "$level" "$init_copy" "dhl-F-$level-notty-stdin-$DIAG_RUNID"; then
      sargv+=(--entrypoint /bin/sh "$DIAG_IMAGE" -c "$payload")
      DIAG_CONTAINER_NAME="dhl-F-$level-notty-stdin-$DIAG_RUNID" \
        diag_exec "F-$level-notty-stdin" "$DIAG_FACTOR_BOUND" docker "${sargv[@]}" || true
      diag_classify "F-$level-notty-stdin" "$step_marker"
    else
      printf 'composition-refused\n' > "$DIAG_DIR/F-$level-notty-stdin.detail"
      printf 'refused\n' > "$DIAG_DIR/F-$level-notty-stdin.rc"
      printf 'unknown\n' > "$DIAG_DIR/F-$level-notty-stdin.elapsed"
    fi
    # F-script: the same step wrapped in an explicit pty via script(1)
    local -a pargv=()
    if _diag_step_argv_compose pargv "$level" "$init_copy" "dhl-F-$level-script-$DIAG_RUNID"; then
      pargv+=(--entrypoint /bin/sh "$DIAG_IMAGE" -c "$payload")
      DIAG_CONTAINER_NAME="dhl-F-$level-script-$DIAG_RUNID" \
        diag_exec "F-$level-script" "$DIAG_FACTOR_BOUND" \
        script -qec "docker $(printf '%q ' "${pargv[@]}")" /dev/null </dev/null || true
      diag_classify "F-$level-script" "$step_marker"
    else
      printf 'composition-refused\n' > "$DIAG_DIR/F-$level-script.detail"
      printf 'refused\n' > "$DIAG_DIR/F-$level-script.rc"
      printf 'unknown\n' > "$DIAG_DIR/F-$level-script.elapsed"
    fi
    fi
  elif [ "$first_fail" = D3 ]; then
    step_marker='D3_OK'
    # The canonical D3 baseline changes THREE factors at once versus D2:
    # the Session lifecycle+bearer, the per-launch ssh-agent, and the -it
    # TTY. Each probe below removes exactly ONE factor from the canonical
    # configuration, reassembled from the SAME shared owners (never a
    # parallel launcher). Session creation/deletion always goes through the
    # canonical _dh_session_create/_dh_session_delete owners.
    _diag_d3_probe notty    "$ws" 'echo D3_OK' tty
    _diag_d3_probe nosession "$ws" 'echo D3_OK' session
    _diag_d3_probe noagent  "$ws" 'echo D3_OK' agent
  fi

  # --- the failure diagnostics for the first failing step -------------------
  [ -z "$first_fail" ] || diag_collect_failure "$first_fail"

  # --- the compact report ---------------------------------------------------
  diag_report_lines D0 D1 D2 D3 D4
  # the cleanup status of the owned diagnostic resources (always evidence)
  for id in D3 D4; do
    [ -f "$DIAG_DIR/$id.session" ] || continue
    printf 'CLEANUP %s session=%s\n' "$id" "$(cat "$DIAG_DIR/$id.session")"
  done
  local id
  for id in F-D0-tty F-D0-notty-stdin F-D0-script \
            F-D1-tty F-D1-notty-stdin F-D1-script \
            F-D2-tty F-D2-notty-stdin F-D2-script \
            F-D3-notty F-D3-nosession F-D3-noagent; do
    _diag_report_factor "$id"
  done
  # the transition evidence: the exact configuration difference at the
  # first PASS->FAIL boundary
  if [ -n "$first_fail" ]; then
    case "$first_fail" in
      D1) printf 'TRANSITION D0->D1: %s\n' "$(diag_step_delta D0 D1)" ;;
      D2) printf 'TRANSITION D1->D2: %s\n' "$(diag_step_delta D1 D2)" ;;
      D3) printf 'TRANSITION D2->D3: %s\n' "$(diag_step_delta D2 D3)" ;;
      D4) printf 'TRANSITION D3->D4: %s\n' "$(diag_step_delta D3 D4)" ;;
    esac
    if [ -s "$DIAG_DIR/$first_fail.err.excerpt" ] 2>/dev/null; then
      printf 'DIAG stderr (%s, sanitized excerpt):\n' "$first_fail"
      diag_sanitize "$(cat "$DIAG_DIR/$first_fail.err.excerpt")"
      printf '\n'
    fi
    if [ -s "$DIAG_DIR/$first_fail.avc" ] 2>/dev/null; then
      printf 'DIAG avc (capped tail):\n'
      diag_sanitize "$(cat "$DIAG_DIR/$first_fail.avc")"
      printf '\n'
    fi
    # The cause is named ONLY when exactly one factor probe succeeded where
    # the step failed; otherwise the outcome is explicitly UNRESOLVED.
    local passed_factors=0 passed_name=""
    for id in "$DIAG_DIR"/F-*.detail; do
      [ -f "$id" ] || continue
      if [ "$(cat "$id" 2>/dev/null)" = ok ]; then
        passed_factors=$((passed_factors + 1))
        passed_name="$(basename "$id" .detail)"
      fi
    done
    if [ "$passed_factors" -eq 1 ] && [ -n "$passed_name" ]; then
      printf 'DIAGNOSIS: the %s factor is implicated (%s passed where %s failed; all other factors were excluded)\n' \
        "${passed_name#F-}" "$passed_name" "$first_fail"
    else
      printf 'DIAGNOSIS UNRESOLVED: the failing step is %s (detail %s); the factor evidence did not prove a single cause\n' \
        "$first_fail" "$(cat "$DIAG_DIR/$first_fail.detail" 2>/dev/null || echo unknown)"
    fi
  fi
  [ "$all_pass" = 1 ] && return 0 || return 1
}

# _diag_d3_probe NAME WS PAYLOAD EXCLUDED_FACTOR — one bounded D3 factor
# probe: the canonical exec-path configuration reassembled from the shared
# owners with EXACTLY ONE factor removed. The Session lifecycle, when
# present, always runs through the canonical _dh_session_create/_delete
# owners; the ssh-agent, when present, always through the canonical
# _oc_prepare_ssh_agent owner. Declared differences per probe:
#   notty     — the -it flag removed (stdin closed)
#   (notty-stdin handled by the same assembly with the pty stdin inherited)
#   nosession — the Session lifecycle and bearer removed
#   noagent   — the ssh-agent factor removed (the key path hidden)
_diag_d3_probe() { # NAME WS PAYLOAD EXCLUDED_FACTOR
  local name="$1" ws="$2" payload="$3" excluded="$4"
  local id="F-D3-$name"
  local -a argv=(run --rm --name "dhl-$id-$DIAG_RUNID")
  argv+=(--label "lab.diagnostic.runid=$DIAG_RUNID")
  argv+=(--label "lab.diagnostic.step=F-D3-$name")
  # the shared owners, in the canonical order; fail-closed on any refusal
  if ! _oc_security_opts argv; then
    printf 'composition-refused\n' > "$DIAG_DIR/$id.detail"
    printf 'refused\n' > "$DIAG_DIR/$id.rc"
    printf 'unknown\n' > "$DIAG_DIR/$id.elapsed"
    return 0
  fi
  local init_copy="$DIAG_D3_INIT_COPY"
  [ -n "$init_copy" ] && argv+=(--init -v "$init_copy:/sbin/docker-init:ro,z")
  if ! _oc_compose_mounts_env argv; then
    printf 'composition-refused\n' > "$DIAG_DIR/$id.detail"
    printf 'refused\n' > "$DIAG_DIR/$id.rc"
    printf 'unknown\n' > "$DIAG_DIR/$id.elapsed"
    return 0
  fi
  if [ "$excluded" != agent ]; then
    if ! _oc_prepare_ssh_agent argv; then
      printf 'agent-prepare-refused\n' > "$DIAG_DIR/$id.detail"
      printf 'refused\n' > "$DIAG_DIR/$id.rc"
      printf 'unknown\n' > "$DIAG_DIR/$id.elapsed"
      _diag_d3_probe_cleanup "$ws" "$id"
      return 0
    fi
  fi
  if [ "$excluded" != session ]; then
    if ! _dh_session_create; then
      printf 'session-create-refused\n' > "$DIAG_DIR/$id.detail"
      printf 'refused\n' > "$DIAG_DIR/$id.rc"
      printf 'unknown\n' > "$DIAG_DIR/$id.elapsed"
      _diag_d3_probe_cleanup "$ws" "$id"
      return 0
    fi
    argv+=(-e DOCKER_HELPER_SESSION_TOKEN)
  fi
  if [ "$excluded" != tty ]; then
    argv+=(-it)
  fi
  argv+=(--entrypoint /bin/sh "$DIAG_IMAGE" -c "$payload")
  local -a run_argv=(docker "${argv[@]}")
  if [ "$excluded" = tty ]; then
    # no -it: the stdin/PTY variants close or inherit stdin
    if [ "$name" = notty ]; then
      DIAG_CONTAINER_NAME="dhl-$id-$DIAG_RUNID" \
        diag_exec "$id" "$DIAG_FACTOR_BOUND" "${run_argv[@]}" </dev/null || true
    else
      DIAG_CONTAINER_NAME="dhl-$id-$DIAG_RUNID" \
        diag_exec "$id" "$DIAG_FACTOR_BOUND" "${run_argv[@]}" || true
    fi
  else
    DIAG_CONTAINER_NAME="dhl-$id-$DIAG_RUNID" \
      diag_exec "$id" "$DIAG_FACTOR_BOUND" "${run_argv[@]}" </dev/null || true
  fi
  diag_classify "$id" 'D3_OK'
  _diag_d3_probe_cleanup "$ws" "$id"
  unset DOCKER_HELPER_SESSION_ID DOCKER_HELPER_SESSION_TOKEN
  return 0
}

# _diag_d3_probe_cleanup WS ID — register and recover exactly this probe's
# resources (the workspace-owned Session delta and the daemon-attributed
# containers), then stop the probe's own ssh-agent.
_diag_d3_probe_cleanup() { # WS ID
  local ws="$1" id="$2" outcome reap
  if diag_register_step_sessions "$ws" "$DIAG_DIR/$id.sessions.registered"; then
    outcome="$(diag_clean_registered_sessions "$DIAG_DIR/$id.sessions.registered")"
    reap="$(diag_reap_registered_containers "$DIAG_DIR/$id.sessions.registered")"
    printf '%s/%s' "$outcome" "$reap" > "$DIAG_DIR/$id.session"
  else
    printf 'refused-list-error/n-a' > "$DIAG_DIR/$id.session"
  fi
  if [ -n "${_OC_SSH_AGENT_PID:-}" ]; then
    kill "$_OC_SSH_AGENT_PID" 2>/dev/null || true
    [ -z "${_OC_SSH_RUN_DIR:-}" ] || rm -rf -- "$_OC_SSH_RUN_DIR"
    _OC_SSH_AGENT_PID=""; _OC_SSH_RUN_DIR=""
  fi
  return 0
}
