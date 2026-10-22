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
# first-class outcome (never a PASS, a SKIP, or an empty result). When a
# killed invocation may have left a child container behind, the caller's
# DIAG_CONTAINER_NAME (a name this diagnostic owns) is reaped exactly once;
# nothing outside the diagnostic's own resources is ever touched.
#
# Observability contract per invocation:
#   $DIAG_DIR/<name>.out      the command's stdout
#   $DIAG_DIR/<name>.err      the command's stderr (never suppressed)
#   $DIAG_DIR/<name>.rc       the observed exit status
#   $DIAG_DIR/<name>.elapsed  wall-clock seconds
#   $DIAG_DIR/<name>.layer    docker-cli | timeout | container | script
#   $DIAG_DIR/<name>.reap     the owned-container reap outcome (n/a|ok|failed)
#   $DIAG_DIR/<name>.session  the owned-Session cleanup outcome (n/a|clean|reaped|failed)
#
# Secrets: the report is an allowlist of compact result lines; environment
# values, bearer tokens, credentials and raw docker inspect output never
# enter any diagnostic output.

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

diag_exec() { # NAME BOUND CMD... -> runs one bounded command, records everything
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
    if [ -n "${DIAG_CONTAINER_NAME:-}" ]; then
      if docker rm -f "$DIAG_CONTAINER_NAME" >/dev/null 2>&1; then
        reap=ok
      else
        reap=failed
      fi
    fi
  fi
  printf '%s\n' "$reap" > "$DIAG_DIR/$name.reap"
  return "$rc"
}

# diag_clean_owned_sessions BEFORE_IDS_FILE — delete only the Sessions the
# diagnostic created during its own window (the delta against the recorded
# pre-state); never touch a Session that already existed.
diag_clean_owned_sessions() { # BEFORE_IDS_FILE -> records .session outcome
  local before="$1" outcome="clean" now id
  now="$(docker-helper session list --json 2>/dev/null \
    | jq -r '.sessions[].id' 2>/dev/null || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    grep -qxF "$id" "$before" 2>/dev/null && continue
    if docker-helper session delete "$id" >/dev/null 2>&1; then
      outcome=reaped
    else
      outcome=failed
    fi
  done <<<"$now"
  printf '%s\n' "$outcome"
}

# diag_record_owned_sessions — record the pre-existing Session ids.
diag_record_owned_sessions() { # FILE
  docker-helper session list --json 2>/dev/null \
    | jq -r '.sessions[].id' 2>/dev/null >"$1" || true
}

# diag_record_owned_containers IMAGE FILE — record the pre-existing running
# container ids for the pinned image (the delta basis for the canonical-step
# reap; the canonical launcher does not name its containers).
diag_record_owned_containers() { # IMAGE FILE
  docker ps -q --filter "ancestor=$1" 2>/dev/null >"$1" || true
}

# diag_reap_owned_containers IMAGE BEFORE_FILE — stop only the containers
# that appeared for this image during the diagnostic window.
diag_reap_owned_containers() { # IMAGE BEFORE_FILE -> records .reap
  local image="$1" before="$2" now id outcome="n/a"
  now="$(docker ps -q --filter "ancestor=$image" 2>/dev/null || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    grep -qxF "$id" "$before" 2>/dev/null && continue
    if docker rm -f "$id" >/dev/null 2>&1; then
      outcome=reaped
    else
      outcome=failed
    fi
  done <<<"$now"
  printf '%s\n' "$outcome"
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

# diag_collect_failure ID — the safe failure diagnostics: allowlisted docker
# inspect fields, the container process list (argv only, never env), and a
# capped AVC tail. Everything lands in the private evidence directory; the
# report quotes only sanitized excerpts.
diag_collect_failure() { # ID
  local id="$1"
  local cname="dhl-$id-$$"
  {
    docker inspect --format '{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} err={{.State.Error}}' "$cname" 2>/dev/null || true
    docker ps -a --filter "name=$cname" --format '{{.Names}} {{.State}} {{.Status}}' 2>/dev/null || true
  } > "$DIAG_DIR/$id.docker-state" 2>/dev/null
  docker top "$cname" 2>/dev/null > "$DIAG_DIR/$id.procs" || true
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
    'D2->D3') printf '%s' '+ the real Session lifecycle (create/delete) and the Session bearer through the canonical oc-probe composition' ;;
    'D3->D4') printf '%s' 'the payload switches from a trivial exec to the real OpenCode entrypoint (--version)' ;;
    *) printf '%s' 'unknown step delta' ;;
  esac
}

# _diag_canonical_step ID BOUND PAYLOAD MODE — run the canonical aliases path
# (oc-probe for exec, oc for the real entrypoint) under diag_exec, then clean
# exactly the resources this step created (the Session delta and any
# container that appeared for the pinned image during the step).
_diag_canonical_step() { # ID BOUND PAYLOAD MODE
  local id="$1" bound="$2" payload="$3" mode="$4"
  diag_record_owned_sessions "$DIAG_DIR/$id.sessions.before"
  diag_record_owned_containers "$DIAG_IMAGE" "$DIAG_DIR/$id.containers.before"
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
  local rc sessions reap
  rc="$(cat "$DIAG_DIR/$id.rc" 2>/dev/null || echo 1)"
  sessions="$(diag_clean_owned_sessions "$DIAG_DIR/$id.sessions.before")"
  printf '%s\n' "$sessions" > "$DIAG_DIR/$id.session"
  reap="$(diag_reap_owned_containers "$DIAG_IMAGE" "$DIAG_DIR/$id.containers.before")"
  printf '%s\n' "$reap" > "$DIAG_DIR/$id.reap"
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
      case "$rc_line" in ''|*[!0-9]*) detail=no-exit-status; rc_line=invalid ;; esac
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

# diag_run_ladder IMAGE WS -> the compact report on stdout; rc 0 = all PASS.
# The ladder stops at the first FAIL (downstream steps are NOT_RUN) and runs
# bounded factor probes on the failing docker-argv step to isolate the TTY,
# pty-wrapper and stdin factors. It never starts the model and never touches
# an LLM.
diag_run_ladder() { # IMAGE WS
  DIAG_IMAGE="$1"
  local ws="$2"
  cd "$ws" || return 1
  local all_pass=1 first_fail=""
  local DC_OK DC_DETAIL init_copy=""
  local -a argv=()
  diag_record_owned_sessions "$DIAG_DIR/sessions.before"
  diag_record_owned_containers "$DIAG_IMAGE" "$DIAG_DIR/containers.before"

  # --- D0: the minimal runtime + SELinux posture ---------------------------
  # No init, no mounts, no TTY, stdin closed, HOME=/tmp (the operator's real
  # experiment). Isolates: the Docker runtime and the SELinux domain.
  argv=(run --rm --name "dhl-D0-$$")
  _oc_security_opts argv
  argv+=(-e HOME=/tmp --entrypoint /bin/sh "$DIAG_IMAGE" -c 'echo D0_OK')
  DIAG_CONTAINER_NAME="dhl-D0-$$" diag_exec D0 "$DIAG_STEP_BOUND" docker "${argv[@]}" </dev/null || true
  diag_classify D0 D0_OK
  [ "$DC_OK" = 1 ] || { all_pass=0; first_fail="D0"; }

  # --- D1: D0 + --init with the verified lab copy ---------------------------
  if [ "$all_pass" = 1 ]; then
    init_copy="$(_oc_verify_init_copy)"
    if [ -n "$init_copy" ]; then
      argv=(run --rm --name "dhl-D1-$$" --init -v "$init_copy:/sbin/docker-init:ro,z")
      _oc_security_opts argv
      argv+=(-e HOME=/tmp --entrypoint /bin/sh "$DIAG_IMAGE" -c 'echo D1_OK')
      DIAG_CONTAINER_NAME="dhl-D1-$$" diag_exec D1 "$DIAG_STEP_BOUND" docker "${argv[@]}" </dev/null || true
      diag_classify D1 D1_OK
      [ "$DC_OK" = 1 ] || { all_pass=0; first_fail="D1"; }
    else
      printf 'invalid\n' > "$DIAG_DIR/D1.rc"
      printf 'unknown\n' > "$DIAG_DIR/D1.elapsed"
      printf 'no-init-copy\n' > "$DIAG_DIR/D1.detail"
      all_pass=0; first_fail="D1"
    fi
  fi

  # --- D2: D1 + the canonical mounts/env/workdir ----------------------------
  # Documented diagnostic difference from production: no Session bearer (D3
  # adds the real Session lifecycle through the canonical composition).
  if [ "$all_pass" = 1 ]; then
    argv=(run --rm --name "dhl-D2-$$")
    [ -n "$init_copy" ] && argv+=(--init -v "$init_copy:/sbin/docker-init:ro,z")
    _oc_security_opts argv
    _oc_compose_mounts_env argv
    argv+=(--entrypoint /bin/sh "$DIAG_IMAGE" -c 'echo D2_OK')
    DIAG_CONTAINER_NAME="dhl-D2-$$" diag_exec D2 "$DIAG_STEP_BOUND" docker "${argv[@]}" </dev/null || true
    diag_classify D2 D2_OK
    [ "$DC_OK" = 1 ] || { all_pass=0; first_fail="D2"; }
  fi

  # --- D3: the canonical oc-probe path (a real Session, the bearer) ---------
  if [ "$all_pass" = 1 ]; then
    _diag_canonical_step D3 "$DIAG_CANON_BOUND" 'echo D3_OK' exec || true
    diag_classify D3 D3_OK
    [ "$DC_OK" = 1 ] || { all_pass=0; first_fail="D3"; }
  fi

  # --- D4: the canonical OpenCode entrypoint --------------------------------
  if [ "$all_pass" = 1 ]; then
    _diag_canonical_step D4 "$DIAG_CANON_BOUND" '' real || true
    diag_classify D4 '[0-9]+\.[0-9]+\.[0-9]+'
    [ "$DC_OK" = 1 ] || { all_pass=0; first_fail="D4"; }
  fi

  # --- the factor probes: only on the first failing docker-argv step --------
  # They exist to isolate WHICH factor of the launch contract is implicated.
  # The canonical path (D3/D4) cannot vary -it (that is the launcher
  # contract), so the TTY factor applies to the docker-argv steps D0–D2.
  local step_marker=""
  if [ -n "$first_fail" ] && case "$first_fail" in D[012]) true ;; *) false ;; esac; then
    case "$first_fail" in
      D0) argv=(run --rm --name "dhl-F-D0-$$") ;;
      D1) argv=(run --rm --name "dhl-F-D1-$$" --init -v "$init_copy:/sbin/docker-init:ro,z") ;;
      D2) argv=(run --rm --name "dhl-F-D2-$$" --init -v "$init_copy:/sbin/docker-init:ro,z") ;;
    esac
    _oc_security_opts argv
    if [ "$first_fail" = D2 ]; then
      _oc_compose_mounts_env argv
    else
      argv+=(-e HOME=/tmp)
    fi
    argv+=(--entrypoint /bin/sh "$DIAG_IMAGE" -c "echo ${first_fail}_OK")
    step_marker="${first_fail}_OK"
    # F-tty: the same step WITH -it and the inherited pty stdin
    local -a fargv=("${argv[0]}" -it "${argv[@]:1}")
    diag_exec "F-${first_fail}-tty" "$DIAG_FACTOR_BOUND" docker "${fargv[@]}" || true
    diag_classify "F-${first_fail}-tty" "$step_marker"
    # F-notty-stdin: no -it, but the pty stdin is inherited (no </dev/null)
    fargv=("${argv[@]}")
    diag_exec "F-${first_fail}-notty-stdin" "$DIAG_FACTOR_BOUND" docker "${fargv[@]}" || true
    diag_classify "F-${first_fail}-notty-stdin" "$step_marker"
    # F-script: the same step wrapped in an explicit pty via script(1)
    fargv=("${argv[@]}")
    diag_exec "F-${first_fail}-script" "$DIAG_FACTOR_BOUND" script -qec "docker ${fargv[*]@Q} </dev/null" /dev/null || true
    diag_classify "F-${first_fail}-script" "$step_marker"
  fi

  # --- the failure diagnostics for the first failing step -------------------
  [ -z "$first_fail" ] || diag_collect_failure "$first_fail"

  # --- the compact report ---------------------------------------------------
  diag_report_lines D0 D1 D2 D3 D4
  # the cleanup status of the owned diagnostic resources (always evidence)
  local id2
  for id2 in D3 D4; do
    [ -f "$DIAG_DIR/$id2.session" ] || continue
    printf 'CLEANUP %s session=%s container=%s\n' "$id2" \
      "$(cat "$DIAG_DIR/$id2.session")" \
      "$(cat "$DIAG_DIR/$id2.reap" 2>/dev/null || echo n/a)"
  done
  local id detail
  for id in F-D0-tty F-D0-notty-stdin F-D0-script \
            F-D1-tty F-D1-notty-stdin F-D1-script \
            F-D2-tty F-D2-notty-stdin F-D2-script; do
    [ -f "$DIAG_DIR/$id.detail" ] || continue
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
      cat "$DIAG_DIR/$first_fail.err.excerpt"
      printf '\n'
    fi
    if [ -s "$DIAG_DIR/$first_fail.avc" ] 2>/dev/null; then
      printf 'DIAG avc (capped tail):\n'
      diag_sanitize "$(cat "$DIAG_DIR/$first_fail.avc")"
      printf '\n'
    fi
    # The cause is named only when the factor probes or the layer
    # classification actually prove it; otherwise the outcome is explicitly
    # UNRESOLVED — never an unproven attribution.
    printf 'DIAGNOSIS UNRESOLVED: the failing step is %s (detail %s); the factor evidence above did not prove a single cause\n' \
      "$first_fail" "$(cat "$DIAG_DIR/$first_fail.detail" 2>/dev/null || echo unknown)"
  fi
  [ "$all_pass" = 1 ] && return 0 || return 1
}
