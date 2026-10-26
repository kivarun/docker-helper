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
#   $DIAG_DIR/<name>.phases   fixed UAT-8m phase markers (wrapper-entered,
#                             before-docker-exec) written by the probe's own
#                             inner command; private evidence only
#
# Secrets: the PUBLIC report is a strict allowlist of compact result lines
# and predefined safe fields/categories (UAT-8f): raw stdout/stderr, docker
# top argv, docker error strings, environment values, bearer tokens and
# credentials live ONLY in the private evidence directory, which is wiped
# after the run. Every allowlisted line is still sanitized at print time by
# the single sanitization owner as defense in depth; registration of exact
# secret values is process-local and is never relied on across the
# root-driver/runner boundary.

set -u

DIAG_KILL_AFTER="${DIAG_KILL_AFTER:-10}"
# the ladder bounds: production defaults 30/60; overridable ONLY for the
# behavioral test harness (fast, still bounded)
DIAG_STEP_BOUND="${DIAG_STEP_BOUND:-30}"
DIAG_CANON_BOUND="${DIAG_CANON_BOUND:-60}"
DIAG_FACTOR_BOUND="${DIAG_FACTOR_BOUND:-30}"
# the bound for every bounded recovery call (inspect/rm/ps/image inspect/
# session list/delete): one owner, the same timeout mechanism as the steps
DIAG_RECOVERY_BOUND="${DIAG_RECOVERY_BOUND:-10}"
# the aliases source path for the child shells: $HOME/.bash_aliases in the
# VM; a test harness may point it at the repository copy
DC_ALIASES="${DC_ALIASES:-$HOME/.bash_aliases}"
# test-scoped seam for the docker-init candidate search: when SET (even to
# empty), the lab init verification consults EXACTLY this candidate list
# (used to model a host without any docker-init). Production never sets it;
# this library must not assign a default, because the seam's set/empty
# distinction is what models the absence of docker-init.
# LAB_DOCKER_INIT_CANDIDATES is consumed by agent-aliases.sh via ${VAR+x}.

# diag_sanitize TEXT — the single sanitization owner. Defense in depth for
# anything any report path quotes: bearer-token shapes, admin-token shapes,
# Authorization values and private key material are redacted, PLUS every
# exact secret VALUE registered by this run (DIAG_SECRET_VALUES, an array so
# a value may contain newlines): arbitrary values, not only dht_* shaped
# ones. Registered values are matched LITERALLY (bash pattern substitution
# with a quoted pattern), never as a regular expression — a value carrying
# `[ ] . * / \ &` or newlines is redacted exactly, and a near-miss that only
# a regex would match stays intact.
#
# Registration is process-local state: the root driver and the agent runner
# are different processes with different registries. It is defense in depth
# ONLY — the public report paths are strict allowlists (fixed fields and
# categories) that never quote arbitrary Docker output, process argv,
# environment or shell payload, so an unregistered secret value cannot reach
# the report by construction (UAT-8f).
DIAG_SECRET_VALUES=()
diag_sanitize() {
  local text="$1"
  local out
  out="$(printf '%s' "$text" \
    | sed -E -e 's/dht_[0-9a-zA-Z]{16,}/dht_REDACTED/g' \
             -e 's/(Bearer[[:space:]]+)[^[:space:]]+/\1REDACTED/g' \
             -e 's/-----BEGIN[A-Z ]*PRIVATE KEY-----/REDACTED-KEY/g' \
             -e 's/(ADMIN[A-Za-z0-9_]*[[:space:]]*[:=][[:space:]]*)[^[:space:]]+/\1REDACTED/g')" || {
    # a failed sanitization must never degrade into a PASS-shaped passthrough
    printf '%s' "SANITIZE-FAILURE"
    return 1
  }
  local v
  for v in "${DIAG_SECRET_VALUES[@]}"; do
    [ -n "$v" ] || continue
    out="${out//"$v"/REDACTED}"
  done
  printf '%s' "$out"
  return 0
}

# diag_register_secret_value VALUE — record one exact secret value this run
# holds so every report path redacts it literally. Never logs the value.
diag_register_secret_value() { # VALUE
  [ -n "$1" ] || return 0
  local v
  for v in "${DIAG_SECRET_VALUES[@]}"; do
    [ "$v" = "$1" ] && return 0
  done
  DIAG_SECRET_VALUES+=("$1")
  return 0
}

# diag_verify_launcher_loaded — the runner's preflight (UAT-8g): proves that
# the launcher and THIS diagnostic library were FULLY loaded in the current
# shell BEFORE any ladder step runs. The real 8f failure was a stale
# installed launcher (the pinned reference present, the shared configuration
# owners absent) that blew up mid-ladder as
# '_oc_security_opts: command not found' and was masked as
# composition-refused. A missing shared owner or an empty pinned reference
# is a loader-drift failure with ZERO docker runs — never a composition
# refusal, never an UNRESOLVED diagnosis, never a skip.
diag_verify_launcher_loaded() { # -> 0 ok | 1 loader-drift (reason on stderr)
  local fn
  for fn in _oc_security_opts _oc_compose_mounts_env _oc_verify_init_copy \
            _oc_launch oc oc-probe oc_lab_mount_source_ok \
            diag_run_ladder diag_sanitize; do
    declare -F "$fn" >/dev/null 2>&1 || {
      printf 'FAIL loader-drift: %s is not loaded in the diagnostic shell\n' "$fn" >&2
      return 1
    }
  done
  if [ -z "${_OC_BASE:-}" ]; then
    printf 'FAIL loader-drift: _OC_BASE is not set in the diagnostic shell\n' >&2
    return 1
  fi
  return 0
}

# diag_exec NAME BOUND CMD... -> runs one bounded command, records everything
diag_exec() { # NAME BOUND CMD...
  local name="$1" bound="$2"
  shift 2
  local t0=$SECONDS rc reap="n/a" elapsed
  # UAT-8n: streaming, safe progress. IDs are internal fixed labels only:
  # never emit argv, environment, file paths, stderr or a caller-supplied
  # arbitrary name. This is execution progress, NOT a final PASS verdict;
  # marker checks and mandatory Session cleanup happen after diag_exec.
  local progress_id="$name" progress_limit="bounded"
  [[ "$progress_id" =~ ^(D[0-4]|F-D[0-4]-[a-z0-9-]+)$ ]] || progress_id="unknown"
  [[ "$bound" =~ ^[0-9]+$ ]] && progress_limit="${bound}s"
  printf '[diag] START %s limit=%s\n' "$progress_id" "$progress_limit" >&2
  if timeout --kill-after="$DIAG_KILL_AFTER" "$bound" "$@" \
      >"$DIAG_DIR/$name.out" 2>"$DIAG_DIR/$name.err"; then
    rc=0
  else
    rc=$?
  fi
  elapsed="$((SECONDS - t0))"
  printf '%s\n' "$elapsed" > "$DIAG_DIR/$name.elapsed"
  printf '%s\n' "$rc" > "$DIAG_DIR/$name.rc"
  case "$rc" in
    124|137) printf '%s\n' timeout > "$DIAG_DIR/$name.layer" ;;
    125|126|127) printf '%s\n' docker-cli > "$DIAG_DIR/$name.layer" ;;
    *) printf '%s\n' container > "$DIAG_DIR/$name.layer" ;;
  esac
  if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
    printf '[diag] RECOVER %s rc=%s elapsed=%ss\n' \
      "$progress_id" "$rc" "$elapsed" >&2
    # the hang-stage observation (UAT-8k) is recorded BEFORE any cleanup
    # touches the container: it is the bounded evidence that separates the
    # Docker CLI outcome (the timeout) from the observed container state
    diag_capture_hang_state "$name" "${DIAG_CONTAINER_CID:-}"
    reap="$(diag_reap_owned_container "${DIAG_CONTAINER_NAME:-}" "${DIAG_CONTAINER_CID:-}")"
  fi
  printf '%s\n' "$reap" > "$DIAG_DIR/$name.reap"
  # The reap value is a fixed category; sanitize anyway before logging it.
  case "$reap" in n/a|clean|ok|failed|refused-unowned) : ;; *) reap=unknown ;; esac
  printf '[diag] END %s rc=%s elapsed=%ss reap=%s\n' \
    "$progress_id" "$rc" "$elapsed" "$reap" >&2
  return "$rc"
}

# diag_bounded NAME CMD... — the shared bounded-recovery owner. Every
# potentially blocking recovery operation (docker inspect/rm/ps, image
# inspect, docker-helper session list/delete) runs through THIS mechanism —
# the same timeout+kill-after implementation the steps use — never through
# independent timeout wrappers. Evidence (.out/.err/.rc/.elapsed) is
# recorded like any other bounded execution.
diag_bounded() { # NAME CMD... -> the command's stdout; nonzero on failure
  local name="$1"
  shift
  local t0=$SECONDS rc
  if timeout --kill-after="$DIAG_KILL_AFTER" "$DIAG_RECOVERY_BOUND" "$@" \
      >"$DIAG_DIR/$name.out" 2>"$DIAG_DIR/$name.err"; then
    rc=0
  else
    rc=$?
  fi
  printf '%s\n' "$((SECONDS - t0))" > "$DIAG_DIR/$name.elapsed"
  printf '%s\n' "$rc" > "$DIAG_DIR/$name.rc"
  return "$rc"
}

# diag_expected_image_id REF — resolve the pinned OCI reference to the LOCAL
# Docker image ID. The container's `.Image` is an image ID, not a reference;
# the ownership comparison must be ID to ID. A failed resolution is a
# refusal, never a guess.
diag_expected_image_id() { # REF -> the image ID on stdout, or empty
  local ref="$1"
  diag_bounded "image-id" docker image inspect --format '{{.Id}}' "$ref" \
    >/dev/null 2>&1 || { printf ''; return 0; }
  local id
  id="$(cat "$DIAG_DIR/image-id.out" 2>/dev/null)"
  if [[ "$id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    printf '%s' "$id"
  else
    printf ''
  fi
}

# diag_container_identity NAME_OR_ID — one bounded inspect returning
# "id|runid-label|image-id"; empty on any failure.
diag_container_identity() { # NAME_OR_ID -> id|runid|image-id
  diag_bounded "identity" docker inspect --format \
    '{{.Id}}|{{index .Config.Labels "lab.diagnostic.runid"}}|{{.Image}}' "$1" \
    >/dev/null 2>&1 || { printf ''; return 0; }
  cat "$DIAG_DIR/identity.out" 2>/dev/null
}

# diag_container_absent NAME — bounded, decisive existence check: 0 = a
# container with exactly this name does NOT exist (proven absence);
# 1 = it exists or existence cannot be proven.
diag_container_absent() { # NAME -> 0 absent | 1 present-or-unknown
  diag_bounded "absence" docker ps -aq --filter "name=^/$1\$" \
    >/dev/null 2>&1 || return 1
  [ -s "$DIAG_DIR/absence.out" ] && return 1
  return 0
}

# diag_cid_absent CID — the decisive existence check by the FULL immutable
# container ID: 0 = docker itself proved that no container with this ID
# exists (proven absence); 1 = it exists or existence cannot be proven. A
# name-based search can never substitute for this: a container may have been
# renamed, so an empty name search does not prove the absence of a container
# with a known ID.
diag_cid_absent() { # CID -> 0 absent | 1 present-or-unknown
  diag_bounded "cid-absence" docker ps -aq --filter "id=$1" \
    >/dev/null 2>&1 || return 1
  [ -s "$DIAG_DIR/cid-absence.out" ] && return 1
  return 0
}

# diag_reap_verified_container CID — remove a container by its IMMUTABLE
# container ID after identity verification. Never removes by a name, which
# could be reused.
diag_reap_verified_container() { # CID -> ok | failed
  if diag_bounded "rm" docker rm -f "$1" >/dev/null 2>&1; then
    printf 'ok'
  else
    printf 'failed'
  fi
  return 0
}

# diag_reap_owned_container NAME CIDFILE — remove a diagnostic-owned
# container ONLY after its identity is verified end to end:
#   1. the run's cidfile records the immutable container ID (a run that
#      died before docker wrote it grants no removal permission by
#      assumption);
#   2. the container is inspected BY ID (never by the reusable name): its
#      .Id must equal the recorded FULL ID, its lab.diagnostic.runid label
#      must equal THIS run's id, and its .Image must equal the LOCAL image
#      ID resolved from the pinned OCI reference (an image ID, not a
#      reference). A short (12-hex) ID is not accepted: it is not immutable
#      identity evidence;
#   3. the removal targets the verified container ID.
# Proven absence is a normal outcome (clean), but ONLY when docker itself
# proves it: a FAILED inspect by CID does not prove the container is gone,
# and an empty search by the reusable NAME does not prove the absence of a
# container with a known CID that may have been renamed — absence is proven
# only by a successful, empty search on the FULL container ID. Any
# ambiguity is refused-unowned, and no removal is ever attempted on an
# unproven identity.
diag_reap_owned_container() { # NAME CIDFILE -> clean|ok|failed|refused-unowned|n/a
  local name="$1" cidfile="$2" cid
  [ -n "$name" ] || { printf 'n/a'; return 0; }
  [ -n "${DIAG_RUNID:-}" ] || { printf 'refused-unowned'; return 0; }
  if [ ! -s "$cidfile" ]; then
    # no container ID was ever recorded: the name-based check is the only
    # available evidence, and a container under THIS run's unique name is
    # the only thing it can speak about
    if diag_container_absent "$name"; then
      printf 'clean'
    else
      printf 'refused-unowned'
    fi
    return 0
  fi
  cid="$(tr -d '[:space:]' < "$cidfile" 2>/dev/null)"
  if [[ ! "$cid" =~ ^[0-9a-f]{64}$ ]]; then
    # a 12-hex short ID is not immutable-identity evidence; nothing is
    # inspected, searched or removed on its authority
    printf 'refused-unowned'
    return 0
  fi
  local expected identity
  expected="$(diag_expected_image_id "${DIAG_IMAGE:-}")"
  [ -n "$expected" ] || { printf 'refused-unowned'; return 0; }
  identity="$(diag_container_identity "$cid")"
  if [ -z "$identity" ]; then
    # a failed inspect does NOT prove absence: absence is decided by a
    # successful, empty search on the FULL container ID — never by a name
    # search (the container may have been renamed) and never by the inspect
    # failure itself
    if diag_cid_absent "$cid"; then
      printf 'clean'
    else
      printf 'refused-unowned'
    fi
    return 0
  fi
  local iid lrid img
  iid="${identity%%|*}"
  local rest="${identity#*|}"
  lrid="${rest%%|*}"
  img="${rest#*|}"
  case "$iid|$lrid|$img" in
    "$cid|$DIAG_RUNID|$expected") ;;
    *) printf 'refused-unowned'; return 0 ;;
  esac
  diag_reap_verified_container "$cid"
  return 0
}

# _diag_hang_container_status CID — one bounded inspect of the container's
# lifecycle state; the answer is accepted ONLY from the fixed allowlist (a
# real State.Status value). Anything else is unknown, never a guess.
_diag_hang_container_status() { # CID -> status
  diag_bounded "hang-status" docker inspect --format '{{.State.Status}}' "$1" \
    >/dev/null 2>&1 || { printf 'unknown'; return 0; }
  local st
  st="$(cat "$DIAG_DIR/hang-status.out" 2>/dev/null)"
  case "$st" in
    created|running|restarting|paused|exited|dead) printf '%s' "$st" ;;
    *) printf 'unknown' ;;
  esac
  return 0
}

# diag_capture_hang_state NAME CIDFILE — the bounded hang-stage observation
# (UAT-8k), recorded BEFORE any cleanup touches the container. It separates
# the Docker CLI outcome (the timeout) from the observed container state:
#   no-cidfile    no container ID was recorded AND the phase evidence
#                 POSITIVELY proves the Docker CLI was never invoked (the
#                 wrapper entered its command but never reached the docker
#                 call)
#   unknown       no container ID was recorded and the container-creation
#                 state cannot be decided: either the phase evidence shows
#                 the Docker CLI WAS invoked, or there is no phase evidence
#                 at all (the canonical steps record no markers). A missing
#                 cidfile is never proof that no create happened.
#   absent        docker itself proved that no container with this full ID
#                 exists (the decisive full-CID search)
#   unattributed  a container exists but its identity could not be proven to
#                 belong to THIS run; it is never inspected further here and
#                 never removed on this observation's authority
#   <status>      the container's State.Status from the fixed allowlist
#                 (created|running|restarting|paused|exited|dead):
#                 created = created but not started; running = started while
#                 the CLI hung (attach/stdin/TTY); exited = finished but the
#                 CLI did not return
#   unknown       the observation itself could not be made
diag_capture_hang_state() { # NAME CIDFILE
  local name="$1" cidfile="$2" cid out=unknown
  if [ ! -s "$cidfile" ]; then
    # UAT-8m: a missing cidfile is never proof that the Docker create event
    # did not happen. Only POSITIVE phase evidence — the wrapper entered
    # its command and never reached the recorded docker call — proves the
    # CLI was not invoked. Absent or empty markers (the canonical steps
    # record none) and a recorded docker invocation stay unknown.
    out=unknown
    if grep -qF 'wrapper-entered' "$DIAG_DIR/$name.phases" 2>/dev/null \
        && ! grep -qF 'before-docker-exec' "$DIAG_DIR/$name.phases" 2>/dev/null; then
      out=no-cidfile
    fi
  else
    cid="$(tr -d '[:space:]' < "$cidfile" 2>/dev/null)"
    if [[ "$cid" =~ ^[0-9a-f]{64}$ ]]; then
      if diag_cid_absent "$cid"; then
        out=absent
      elif [ -s "$DIAG_DIR/cid-absence.out" ]; then
        # the full-CID search succeeded and matched: the container exists;
        # attribute it before trusting anything else about it
        local identity expected iid lrid img rest
        identity="$(diag_container_identity "$cid")"
        expected="$(diag_expected_image_id "${DIAG_IMAGE:-}")"
        if [ -n "$identity" ] && [ -n "$expected" ]; then
          iid="${identity%%|*}"
          rest="${identity#*|}"
          lrid="${rest%%|*}"
          img="${rest#*|}"
          if [ "$iid|$lrid|$img" = "$cid|$DIAG_RUNID|$expected" ]; then
            out="$(_diag_hang_container_status "$cid")"
          else
            out=unattributed
          fi
        else
          out=unattributed
        fi
      fi
    fi
  fi
  printf '%s\n' "$out" > "$DIAG_DIR/$name.hangstate"
  return 0
}

# _diag_hang_suffix ID — the hang-stage class appended to a timeout FAIL
# line. Only a RECORDED observation is appended; nothing is guessed.
_diag_hang_suffix() { # ID -> " hang=<class>" | empty
  local hs=""
  if [ -f "$DIAG_DIR/$1.hangstate" ]; then
    hs="$(cat "$DIAG_DIR/$1.hangstate" 2>/dev/null || true)"
  fi
  [ -n "$hs" ] || return 0
  printf ' hang=%s' "$hs"
}

# diag_register_step_sessions WORKSPACE FILE — error-checked registration of
# the Session IDs provably owned by this diagnostic run: the daemon's own
# list, filtered to THIS run's unique diagnostic workspace. A failed list is
# a refusal, never an empty snapshot. The list carries no bearer tokens.
diag_register_step_sessions() { # WORKSPACE FILE -> 0 ok | 1 list-failed
  local ws="$1" file="$2" raw
  if ! raw="$(diag_bounded "session-list" docker-helper session list --json)"; then
    return 1
  fi
  raw="$(cat "$DIAG_DIR/session-list.out" 2>/dev/null)"
  printf '%s' "$raw" | jq -r --arg ws "$ws" \
    '.sessions[] | select(.workspace == $ws) | .id' > "$file" 2>/dev/null \
    || { : > "$file"; return 1; }
  return 0
}

# diag_clean_registered_sessions FILE — delete exactly the registered Session
# IDs; anything not registered is never touched.
diag_clean_registered_sessions() { # FILE -> clean | reaped | failed
  local file="$1" id outcome="clean"
  [ -s "$file" ] || { printf 'clean'; return 0; }
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if diag_bounded "session-delete" docker-helper session delete "$id" \
        >/dev/null 2>&1; then
      outcome=reaped
    else
      outcome=failed
      break
    fi
  done < "$file"
  printf '%s' "$outcome"
  return 0
}

# UAT-8e: the daemon's reserved com.dockerhelper.* labels identify
# containers created BY docker-helper. D3/D4 containers are started with a
# plain `docker run` through the canonical launcher, so they carry none of
# them; they are attributed ONLY through the diagnostic provenance (the
# unique name, the run-identity label and the immutable cidfile container
# ID) the launcher applies when explicitly asked to. There is no
# helper-label based cleanup path left in this library.

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

# diag_collect_failure ID — the failure diagnostics. EVERY collection call
# (docker inspect, docker ps, docker top, dmesg, ausearch) runs through the
# shared bounded owner: a hung collector records UNAVAILABLE and never
# blocks the report. The collected material is PRIVATE evidence (wiped after
# the run): the public report never quotes docker top argv, Docker error
# strings, environment or shell payload — only the allowlisted state fields
# and fixed categories (see diag_print_evidence_summary and the ladder
# report). The inspect format carries ONLY predefined safe fields;
# .State.Error is an arbitrary Docker error string and is never collected.
diag_collect_failure() { # ID
  local id="$1"
  local cname="dhl-$id-$DIAG_RUNID"
  local collected=0
  if diag_bounded "$id.inspect" docker inspect --format \
      '{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}' \
      "$cname" >/dev/null 2>&1 && [ -s "$DIAG_DIR/$id.inspect.out" ]; then
    cp "$DIAG_DIR/$id.inspect.out" "$DIAG_DIR/$id.docker-state"
    collected=1
  fi
  if diag_bounded "$id.pslist" docker ps -a --filter "name=$cname" \
      --format '{{.Names}} {{.State}} {{.Status}}' >/dev/null 2>&1 \
      && [ -s "$DIAG_DIR/$id.pslist.out" ]; then
    printf '%s\n' "$(cat "$DIAG_DIR/$id.pslist.out")" >> "$DIAG_DIR/$id.docker-state"
    collected=1
  fi
  [ "$collected" = 1 ] || printf 'unavailable\n' > "$DIAG_DIR/$id.docker-state"
  # docker top stays an INTERNAL diagnostic: its process argv can carry
  # arbitrary values, so it is stored for private review and never printed
  if diag_bounded "$id.top" docker top "$cname" >/dev/null 2>&1 \
      && [ -s "$DIAG_DIR/$id.top.out" ]; then
    cp "$DIAG_DIR/$id.top.out" "$DIAG_DIR/$id.procs"
  else
    printf 'unavailable\n' > "$DIAG_DIR/$id.procs"
  fi
  # the SELinux evidence: collected bounded, reduced to a private capped
  # tail; the public report names only the category
  local avc_ok=0
  if diag_bounded "$id.dmesg" dmesg >/dev/null 2>&1; then
    grep -i 'avc:' "$DIAG_DIR/$id.dmesg.out" 2>/dev/null | tail -20 \
      >> "$DIAG_DIR/$id.avc" || true
    avc_ok=1
  fi
  if diag_bounded "$id.ausearch" ausearch -m AVC -ts recent >/dev/null 2>&1; then
    tail -40 "$DIAG_DIR/$id.ausearch.out" >> "$DIAG_DIR/$id.avc" 2>/dev/null || true
    avc_ok=1
  fi
  [ "$avc_ok" = 1 ] || printf 'unavailable\n' > "$DIAG_DIR/$id.avc"
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

# diag_canonical_recover ID WS NAME CIDFILE — the error-checked, provenance-
# scoped recovery for one canonical step. Verdict:
#   clean              nothing of this run needed recovery, or the container
#                      is provably absent (a normal outcome)
#   reaped             every owned resource was recovered
#   failed             an owned resource could not be removed
#   refused-list-error the session list could not be verified
#   refused-unowned    a container exists but its ownership could not be
#                      proven (no cidfile / identity mismatch)
diag_canonical_recover() { # ID WS NAME CIDFILE -> verdict on stdout
  local id="$1" ws="$2" name="$3" cidfile="$4"
  local session_verdict container_verdict
  if diag_register_step_sessions "$ws" "$DIAG_DIR/$id.sessions.registered"; then
    session_verdict="$(diag_clean_registered_sessions "$DIAG_DIR/$id.sessions.registered")"
  else
    session_verdict="refused-list-error"
  fi
  container_verdict="$(diag_reap_owned_container "$name" "$cidfile")"
  # UAT-8f: ANY mandatory failure dominates ANY success — a successful
  # container removal must never mask a failed Session deletion and vice
  # versa. The refused verdicts can never become a PASS, unknown verdict
  # values fail closed, and only clean/reaped without any other failure is
  # accepted by diag_cleanup_ok.
  case "$session_verdict/$container_verdict" in
    refused-list-error/*) printf 'refused-list-error' ;;
    */refused-unowned)    printf 'refused-unowned' ;;
    */failed)             printf 'failed' ;;
    failed/*)             printf 'failed' ;;
    */ok)                 printf 'reaped' ;;
    */clean)              printf '%s' "$session_verdict" ;;
    *)                    printf 'refused-unowned' ;;
  esac
  return 0
}

# diag_cleanup_ok VERDICT — the cleanup is part of the step's PASS criterion:
# only a successful or confirmed-unnecessary cleanup accepts.
diag_cleanup_ok() { # VERDICT -> 0 ok | 1 mandatory-cleanup-failure
  case "$1" in
    clean|reaped) return 0 ;;
    *) return 1 ;;
  esac
}

# --- root-driver-side workspace ownership (UAT-8f) ---------------------------
# The root driver (diagnose-launch.sh) allocates the diagnostic workspace and
# owns its removal. These helpers are INERT in the agent context — the runner
# never calls them — and exist so the allocation and removal semantics have
# ONE implementation shared by the driver and the behavioral tests.
#
# The workspace is the Session-ownership anchor: the diagnostic deletes only
# Sessions whose workspace equals THIS run's workspace. A unique,
# unpredictably named workspace keeps that scoping exact: no other run (or a
# leftover directory of a dead one) can share the attribution, and no cleanup
# can ever delete a directory this run did not create.

# diag_alloc_workspace HOME USER — allocate the run's diagnostic workspace
# ATOMICALLY under the agent's allowed root:
#   * mktemp -d: an unpredictable name, created exclusively — an existing
#     directory (e.g. a stale PID-named one holding someone else's data) is
#     never reused and never touched;
#   * mode 0700, owned by the agent user (the runner runs as that user);
#   * the CANONICAL path of the workspace must stay strictly inside the
#     canonical agent home — a symlinked workroot cannot smuggle the
#     workspace (and the Session attribution) outside the allowed root;
#   * the created path is printed for the caller to register for cleanup;
#     any ambiguity removes the just-created directory and fails.
diag_alloc_workspace() { # HOME USER -> the workspace path on stdout
  local home="$1" user="$2" home_canon ws ws_canon uid
  home_canon="$(readlink -f -- "$home" 2>/dev/null)" || return 1
  [ -n "$home_canon" ] && [ -d "$home_canon" ] || return 1
  if [ ! -d "$home/work" ]; then
    mkdir -m 0755 -- "$home/work" 2>/dev/null || return 1
    chown -- "$user" "$home/work" 2>/dev/null || return 1
  fi
  ws="$(mktemp -d "$home/work/diag-XXXXXX")" 2>/dev/null || return 1
  if ! chmod 0700 -- "$ws" 2>/dev/null \
      || ! chown -- "$user" "$ws" 2>/dev/null \
      || ! ws_canon="$(readlink -f -- "$ws" 2>/dev/null)" \
      || [ -z "$ws_canon" ]; then
    rm -rf -- "$ws" 2>/dev/null
    return 1
  fi
  case "$ws_canon" in
    "$home_canon"/work/diag-*) : ;;
    *) rm -rf -- "$ws" 2>/dev/null; return 1 ;;
  esac
  uid="$(id -u -- "$user" 2>/dev/null)" || { rm -rf -- "$ws" 2>/dev/null; return 1; }
  [ "$(stat -c %u -- "$ws" 2>/dev/null)" = "$uid" ] \
    || { rm -rf -- "$ws" 2>/dev/null; return 1; }
  printf '%s\n' "$ws"
}

# diag_discard_tree PATH — remove a tree this run provably created and
# VERIFY the removal. A surviving path is a failure, never a silent success.
diag_discard_tree() { # PATH -> 0 removed-or-absent | 1 survived
  [ -n "$1" ] || return 0
  [ -e "$1" ] || return 0
  rm -rf -- "$1" 2>/dev/null || true
  [ -e "$1" ] && return 1
  return 0
}

# diag_driver_cleanup ROOT WS — the SINGLE cleanup owner of the root driver,
# wired to the driver's EXIT/INT/TERM traps: the workspace (the Session
# ownership anchor) first, then the private evidence root. Any survivor is
# reported to the caller, which must fail closed.
diag_driver_cleanup() { # ROOT WS -> 0 clean | 1 something survived
  local rc=0
  diag_discard_tree "$2" || rc=1
  diag_discard_tree "$1" || rc=1
  return "$rc"
}

# _diag_step_argv_compose ARRAYNAME LEVEL INIT_COPY WS — assemble the ladder's
# docker argv from the SINGLE canonical owners. Fail-closed: any composition
# or mount-gate refusal is propagated and the caller must NOT run docker.
_diag_step_argv_compose() { # ARRAYNAME LEVEL INIT_COPY [CONTAINER_NAME [CIDFILE]]
  # shellcheck disable=SC2178  # a bash nameref to the caller's array
  local -n args="$1"
  local level="$2" init_copy="$3"
  local cname="${4:-dhl-$level-$DIAG_RUNID}"
  args+=(run --rm --name "$cname")
  args+=(--label "lab.diagnostic.runid=$DIAG_RUNID")
  args+=(--label "lab.diagnostic.step=$level")
  args+=(--cidfile "${5:-$DIAG_DIR/$level.cid}")
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
# The mandatory container cleanup is part of the step's PASS criterion: a
# hung container that cannot be verified or removed fails the step even
# when the workload itself succeeded.
_diag_run_docker_step() { # ID LEVEL INIT_COPY PAYLOAD MARKER
  local id="$1" level="$2" init_copy="$3" payload="$4" marker="$5"
  local cidfile="$DIAG_DIR/$id.cid"
  local -a argv=()
  if ! _diag_step_argv_compose argv "$level" "$init_copy" \
      "dhl-$level-$DIAG_RUNID" "$cidfile"; then
    printf 'refused\n' > "$DIAG_DIR/$id.rc"
    printf 'unknown\n' > "$DIAG_DIR/$id.elapsed"
    printf 'composition-refused\n' > "$DIAG_DIR/$id.detail"
    printf 'n/a\n' > "$DIAG_DIR/$id.reap"
    printf 'n/a\n' > "$DIAG_DIR/$id.session"
    DC_OK=0; DC_DETAIL=composition-refused
    return 1
  fi
  argv+=(--entrypoint /bin/sh "$DIAG_IMAGE" -c "$payload")
  DIAG_CONTAINER_NAME="dhl-$level-$DIAG_RUNID" DIAG_CONTAINER_CID="$cidfile" \
    diag_exec "$id" "$DIAG_STEP_BOUND" docker "${argv[@]}" </dev/null || true
  diag_classify "$id" "$marker"
  printf 'n/a\n' > "$DIAG_DIR/$id.session"
  if [ "$DC_OK" = 1 ]; then
    # the workload passed: the mandatory cleanup still gates the verdict
    local reap
    reap="$(cat "$DIAG_DIR/$id.reap" 2>/dev/null || echo n/a)"
    if diag_cleanup_ok_reap "$reap"; then
      return 0
    fi
    DC_DETAIL="cleanup-$reap"
    printf '%s\n' "$DC_DETAIL" > "$DIAG_DIR/$id.detail"
    return 1
  fi
  return 1
}

# diag_cleanup_ok_reap REAP — the reap verdicts that accept a workload PASS:
# n/a (no timeout: the --rm run exited by itself) and a verified ok/clean.
diag_cleanup_ok_reap() {
  case "$1" in
    n/a|ok|clean) return 0 ;;
    *) return 1 ;;
  esac
}

# _diag_canonical_step ID BOUND PAYLOAD MODE WS — run the canonical aliases
# path (oc-probe for exec, oc for the real entrypoint) under diag_exec, then
# recover exactly this run's leaked resources by diagnostic provenance.
#
# PTY contract (UAT-8e): the canonical launcher uses `docker run -it`, so
# the child MUST hold a real terminal — every canonical and `-it` probe step
# runs under a real script(1) pty, and the probe payload itself proves the
# in-container TTY with `test -t 0`. The no-TTY probe deliberately uses
# stdin /dev/null without -it. The canonical launcher configuration is never
# altered to satisfy a test.
#
# The diagnostic provenance (name + run-identity label + cidfile) is
# requested through the launcher's explicitly-enabled diagnostic knobs; the
# cleanup verifies name, label, immutable container ID and image ID, and
# removes by the verified container ID only.
_diag_canonical_step() { # ID BOUND PAYLOAD MODE WS -> 0 pass|1 fail
  local id="$1" bound="$2" payload="$3" mode="$4" ws="$5"
  local name="dhl-$id-$DIAG_RUNID"
  local cidfile="$DIAG_DIR/$id.cid"
  rm -f "$cidfile" 2>/dev/null
  # the child runs through script(1) whose -c command is interpreted by
  # sh; the aliases are bash, so the child is an explicit bash script file
  # (private, inside the evidence directory) — no fragile nested quoting.
  local childfile="$DIAG_DIR/$id.child"
  if [ "$mode" = exec ]; then
    printf '%s\n' 'source "$DC_ALIASES"' 'oc-probe "$DC_PAYLOAD"' > "$childfile"
  else
    printf '%s\n' 'source "$DC_ALIASES"' 'oc --version' > "$childfile"
  fi
  chmod 0600 "$childfile"
  DC_PAYLOAD="$payload" \
    OPENCODE_DIAGNOSTIC_RUNID="$DIAG_RUNID" \
    OPENCODE_DIAGNOSTIC_NAME="$name" \
    OPENCODE_DIAGNOSTIC_CIDFILE="$cidfile" \
    DIAG_CONTAINER_NAME="$name" DIAG_CONTAINER_CID="$cidfile" \
    diag_exec "$id" "$bound" script -qec "bash $childfile" /dev/null || true
  local rc
  rc="$(cat "$DIAG_DIR/$id.rc" 2>/dev/null || echo 1)"
  local verdict
  verdict="$(diag_canonical_recover "$id" "$ws" "$name" "$cidfile")"
  printf '%s\n' "$verdict" > "$DIAG_DIR/$id.session"
  # the workload verdict: the exec probe must additionally prove the
  # in-container TTY through its own marker
  if [ "$mode" = exec ]; then
    diag_classify "$id" 'D3_OK'
  else
    diag_classify "$id" '[0-9]+\.[0-9]+\.[0-9]+'
  fi
  [ "$DC_OK" = 1 ] || return 1
  # the workload passed: the mandatory cleanup still gates the verdict
  if diag_cleanup_ok "$verdict"; then
    return 0
  fi
  return 1
}

# diag_print_evidence_summary EVID_DIR — the safe, allowlisted evidence
# summary for the operator report. This is the ONLY evidence print path: it
# runs in the root driver (which sources this library), quotes ONLY the
# predefined safe docker-state fields, sanitizes every quoted line AT PRINT
# TIME through the single sanitization owner, prints UNAVAILABLE explicitly
# when the evidence could not be collected, and never prints raw docker top
# output (process argv), docker error strings, environment or shell payload —
# those stay in the private evidence wiped after the run (UAT-8f). A
# sanitization failure fails the summary (it can never degrade into a
# PASS-shaped output).
diag_print_evidence_summary() { # EVID_DIR
  local evid="$1" id line
  printf '%s\n' "=== lab launch diagnostics (evidence summary) ==="
  for id in D0 D1 D2 D3 D4; do
    [ -s "$evid/$id.docker-state" ] || continue
    line="$(head -2 "$evid/$id.docker-state")"
    if [ "$line" = unavailable ]; then
      printf '%s docker-state: UNAVAILABLE (the docker inspect/ps evidence could not be collected)\n' "$id"
    else
      line="$(diag_sanitize "$line")" || return 1
      printf '%s docker-state: %s\n' "$id" "$line"
    fi
  done
  return 0
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
        local hang=""
        [ "$detail" = timeout ] && hang="$(_diag_hang_suffix "$id")"
        printf '%s FAIL rc=%s elapsed=%s detail=%s%s\n' \
          "$id" "$rc_line" "$elapsed_line" "$detail" "$hang"
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
    local hang=""
    [ "$detail" = timeout ] && hang="$(_diag_hang_suffix "$id")"
    printf '%s FAIL rc=%s elapsed=%s detail=%s%s\n' "$id" \
      "$(cat "$DIAG_DIR/$id.rc" 2>/dev/null || echo invalid)" \
      "$(cat "$DIAG_DIR/$id.elapsed" 2>/dev/null || echo unknown)" \
      "$detail" "$hang"
  fi
}

# _diag_classify_step_failure ID ALLPASS_VAR FIRSTFAIL_VAR CLEANUPFAIL_VAR —
# a nonzero step outcome is either a workload failure (the factor probes
# apply) or a mandatory-cleanup failure on a passing workload (the verdict
# is reported as a diagnostic failure of its own; the probes do not apply).
_diag_classify_step_failure() { # ID ALLPASS_VAR FIRSTFAIL_VAR CLEANUPFAIL_VAR
  local id="$1"
  # namerefs to the caller's ladder locals (write-only assignment targets)
  # shellcheck disable=SC2178,SC2034  # namerefs to the caller's locals
  local -n allpass_ref="$2"
  # shellcheck disable=SC2178,SC2034
  local -n firstfail_ref="$3"
  # shellcheck disable=SC2178
  local -n cleanup_ref="$4"
  local detail
  detail="$(cat "$DIAG_DIR/$id.detail" 2>/dev/null || echo unknown)"
  if [ "$detail" = ok ]; then
    local verdict
    verdict="$(cat "$DIAG_DIR/$id.session" 2>/dev/null || echo failed)"
    # the first mandatory-cleanup failure names the reason; later ones are
    # already visible in their per-step CLEANUP lines
    [ -z "$cleanup_ref" ] && cleanup_ref="$id $verdict"
  else
    # shellcheck disable=SC2034  # write-only nameref targets
    firstfail_ref="$id"
    # shellcheck disable=SC2034
    allpass_ref="0"
  fi
  return 0
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
  local cleanup_fail=""
  local DC_OK DC_DETAIL init_copy="" init_state=""
  DIAG_D3_INIT_COPY=""
  DIAG_D3_MATRIX_RAN=0
  DIAG_D3_CLEANUP_FAILED=0
  local -a argv=()

  # --- D0: the minimal runtime + SELinux posture ---------------------------
  # No init, no mounts, no TTY, stdin closed, HOME=/tmp (the operator's real
  # experiment). Isolates: the Docker runtime and the SELinux domain.
  _diag_run_docker_step D0 D0 "" 'echo D0_OK' 'D0_OK' \
    || _diag_classify_step_failure D0 all_pass first_fail cleanup_fail

  # --- D1: D0 + --init with the verified lab copy ---------------------------
  if [ "$all_pass" = 1 ]; then
    if init_copy="$(_oc_verify_init_copy)"; then
      if [ -n "$init_copy" ]; then
        init_state=verified
        DIAG_D3_INIT_COPY="$init_copy"
        _diag_run_docker_step D1 D1 "$init_copy" 'echo D1_OK' 'D1_OK' \
          || _diag_classify_step_failure D1 all_pass first_fail cleanup_fail
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
      || _diag_classify_step_failure D2 all_pass first_fail cleanup_fail
  fi

  # --- D3: the canonical oc-probe path (a real Session, the bearer) ---------
  # The payload proves the in-container TTY (test -t 0) as part of the
  # diagnostic evidence; the launcher configuration itself is unchanged.
  if [ "$all_pass" = 1 ]; then
    _diag_canonical_step D3 "$DIAG_CANON_BOUND" 'test -t 0 && echo D3_OK' exec "$ws" \
      || _diag_classify_step_failure D3 all_pass first_fail cleanup_fail
  fi

  # --- D4: the canonical OpenCode entrypoint --------------------------------
  if [ "$all_pass" = 1 ]; then
    _diag_canonical_step D4 "$DIAG_CANON_BOUND" '' real "$ws" \
      || _diag_classify_step_failure D4 all_pass first_fail cleanup_fail
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
    if _diag_step_argv_compose fargv "$level" "$init_copy" \
    "dhl-F-$level-tty-$DIAG_RUNID" "$DIAG_DIR/F-$level-tty.cid"; then
      local -a tty_argv=("${fargv[0]}" -it "${fargv[@]:1}")
      tty_argv+=(--entrypoint /bin/sh "$DIAG_IMAGE" -c "$payload")
      DIAG_CONTAINER_NAME="dhl-F-$level-tty-$DIAG_RUNID" \
        DIAG_CONTAINER_CID="$DIAG_DIR/F-$level-tty.cid" \
        diag_exec "F-$level-tty" "$DIAG_FACTOR_BOUND" docker "${tty_argv[@]}" || true
      diag_classify "F-$level-tty" "$step_marker"
    else
      printf 'composition-refused\n' > "$DIAG_DIR/F-$level-tty.detail"
      printf 'refused\n' > "$DIAG_DIR/F-$level-tty.rc"
      printf 'unknown\n' > "$DIAG_DIR/F-$level-tty.elapsed"
    fi
    # F-notty-stdin: no -it, but the pty stdin is inherited (no </dev/null)
    local -a sargv=()
    if _diag_step_argv_compose sargv "$level" "$init_copy" \
    "dhl-F-$level-notty-stdin-$DIAG_RUNID" "$DIAG_DIR/F-$level-notty-stdin.cid"; then
      sargv+=(--entrypoint /bin/sh "$DIAG_IMAGE" -c "$payload")
      DIAG_CONTAINER_NAME="dhl-F-$level-notty-stdin-$DIAG_RUNID" \
        DIAG_CONTAINER_CID="$DIAG_DIR/F-$level-notty-stdin.cid" \
        diag_exec "F-$level-notty-stdin" "$DIAG_FACTOR_BOUND" docker "${sargv[@]}" || true
      diag_classify "F-$level-notty-stdin" "$step_marker"
    else
      printf 'composition-refused\n' > "$DIAG_DIR/F-$level-notty-stdin.detail"
      printf 'refused\n' > "$DIAG_DIR/F-$level-notty-stdin.rc"
      printf 'unknown\n' > "$DIAG_DIR/F-$level-notty-stdin.elapsed"
    fi
    # F-script: the same step wrapped in an explicit pty via script(1)
    local -a pargv=()
    if _diag_step_argv_compose pargv "$level" "$init_copy" \
    "dhl-F-$level-script-$DIAG_RUNID" "$DIAG_DIR/F-$level-script.cid"; then
      pargv+=(--entrypoint /bin/sh "$DIAG_IMAGE" -c "$payload")
      DIAG_CONTAINER_NAME="dhl-F-$level-script-$DIAG_RUNID" \
        DIAG_CONTAINER_CID="$DIAG_DIR/F-$level-script.cid" \
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
    # UAT-8m: the no-docker wrapper smoke runs first — it isolates the
    # nested script(1) wrapper itself from everything Docker does under it
    _diag_d3_script_smoke
    _diag_d3_probe notty    "$ws" 'echo D3_OK' tty
    _diag_d3_probe nosession "$ws" 'echo D3_OK' session
    _diag_d3_probe noagent  "$ws" 'echo D3_OK' agent
    # the strict UAT-8k matrix: single-variable probes under IDENTICAL
    # composition and payload, isolating the docker flags, the nested pty
    # wrapper and the stdin policy (UAT-8m adds the direct no-flag probe)
    _diag_d3_matrix "$ws"
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
            F-D3-script-smoke \
            F-D3-notty F-D3-nosession F-D3-noagent \
            F-D3-flag-none F-D3-direct-none F-D3-flag-i F-D3-flag-t \
            F-D3-flag-it \
            F-D3-pty-direct F-D3-stdin-pty F-D3-stdin-null; do
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
    # the raw stderr and the SELinux denial text stay in the PRIVATE
    # evidence (wiped after the run); the public report carries only fixed
    # categories — never docker error strings, argv, environment or payload
    if [ -s "$DIAG_DIR/$first_fail.err" ] 2>/dev/null; then
      printf 'DIAG stderr: captured in the private evidence (not printed)\n'
    fi
    if [ -f "$DIAG_DIR/$first_fail.avc" ] && \
       [ "$(head -1 "$DIAG_DIR/$first_fail.avc" 2>/dev/null)" != unavailable ]; then
      printf 'DIAG avc: %s denial lines recorded in the private evidence\n' \
        "$(grep -c . "$DIAG_DIR/$first_fail.avc" 2>/dev/null || echo 0)"
    else
      printf 'DIAG avc: UNAVAILABLE (the kernel audit evidence could not be collected)\n'
    fi
    # The cause is named ONLY by a controlled single-variable comparison
    # (UAT-8k); otherwise the outcome is explicitly UNRESOLVED.
    if [ "$first_fail" = D3 ]; then
      _diag_d3_diagnose
    else
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
  fi
  # a mandatory-cleanup failure is a diagnostic failure of its own: the
  # workload verdicts above stay PASS, the cleanup verdict names the reason
  if [ -n "$cleanup_fail" ]; then
    printf 'DIAGNOSTIC FAIL reason=cleanup-%s\n' "$cleanup_fail"
  fi
  if [ "$all_pass" = 1 ] && [ -z "$cleanup_fail" ]; then
    return 0
  fi
  return 1
}

# _diag_d3_compose_argv ARRAYNAME ID EXCL_SESSION EXCL_AGENT — the SINGLE
# canonical composition owner for every D3 probe (the legacy single-factor
# probes and the strict UAT-8k matrix): the exec-path configuration
# reassembled from the shared owners, with the Session lifecycle and the
# ssh-agent included unless explicitly excluded. Session creation always
# runs through the canonical _dh_session_create owner; the ssh-agent always
# through the canonical _oc_prepare_ssh_agent owner. Fail-closed return
# codes:
#   1  a composition/mount-gate refusal (nothing was created; no cleanup due)
#   2  the ssh-agent preparation refused (the caller must run the probe
#      cleanup: the agent is this probe's own resource)
#   3  the Session creation refused (same)
# The caller alone adds the docker flags, the payload and the
# image/entrypoint, so every probe variant differs ONLY in the factor it
# isolates — never in the shared composition or the payload.
_diag_d3_compose_argv() { # ARRAYNAME ID EXCL_SESSION EXCL_AGENT
  # shellcheck disable=SC2178  # a bash nameref to the caller's array
  local -n args="$1"
  local id="$2" excl_session="$3" excl_agent="$4"
  args=(run --rm --name "dhl-$id-$DIAG_RUNID")
  args+=(--label "lab.diagnostic.runid=$DIAG_RUNID")
  args+=(--label "lab.diagnostic.step=$id")
  _oc_security_opts args || return 1
  [ -n "$DIAG_D3_INIT_COPY" ] && \
    args+=(--init -v "$DIAG_D3_INIT_COPY:/sbin/docker-init:ro,z")
  _oc_compose_mounts_env args || return 1
  if [ "$excl_agent" != agent ]; then
    _oc_prepare_ssh_agent args || return 2
  fi
  if [ "$excl_session" != session ]; then
    _dh_session_create || return 3
    args+=(-e DOCKER_HELPER_SESSION_TOKEN)
  fi
  args+=(--cidfile "$DIAG_DIR/$id.cid")
  return 0
}

# _diag_d3_refusal_records ID CRC — the fail-closed refusal records for a D3
# probe whose composition did not complete: the detail names the refused
# owner, and rc 2/3 mean a probe-owned resource (the agent, the Session) was
# already created and must be recovered by the caller's cleanup.
_diag_d3_refusal_records() { # ID CRC
  local id="$1" crc="$2"
  case "$crc" in
    1) printf 'composition-refused\n' > "$DIAG_DIR/$id.detail" ;;
    2) printf 'agent-prepare-refused\n' > "$DIAG_DIR/$id.detail" ;;
    3) printf 'session-create-refused\n' > "$DIAG_DIR/$id.detail" ;;
    *) printf 'composition-refused\n' > "$DIAG_DIR/$id.detail" ;;
  esac
  printf 'refused\n' > "$DIAG_DIR/$id.rc"
  printf 'unknown\n' > "$DIAG_DIR/$id.elapsed"
}

# _diag_phase_prefix ID WITH_DOCKER — the fixed UAT-8m phase-marker prefix
# for the INNER command of a script(1)-wrapped D3 probe. The inner shell
# appends `wrapper-entered` when the wrapper actually executed its command
# and — when WITH_DOCKER is docker — `before-docker-exec` in the moment
# before the Docker CLI is invoked. Fixed strings only: no argv, no
# environment, no secrets; the file lives in the private evidence directory.
_diag_phase_prefix() { # ID WITH_DOCKER -> inner-shell snippet on stdout
  local pf="$DIAG_DIR/$1.phases" out with_docker="${2:-}"
  out="printf '%s\n' wrapper-entered >>$(printf '%q' "$pf"); "
  if [ "$with_docker" = docker ]; then
    out+="printf '%s\n' before-docker-exec >>$(printf '%q' "$pf"); "
  fi
  printf '%s' "$out"
}

# _diag_d3_script_smoke — the UAT-8m no-docker smoke probe: the nested
# script(1) wrapper ALONE, running a safe fixed printf with a fixed marker.
# It isolates the wrapper itself from everything Docker does under it: no
# docker command, no Session, no ssh-agent, no mounts — nothing is created
# and no cleanup is due. A timeout here means the wrapper itself hangs and
# voids the script-wrapped docker evidence.
_diag_d3_script_smoke() {
  local id="F-D3-script-smoke"
  DIAG_CONTAINER_NAME="" DIAG_CONTAINER_CID="" \
    diag_exec "$id" "$DIAG_FACTOR_BOUND" \
    script -qec "$(_diag_phase_prefix "$id")printf '%s\n' 'SCRIPT_SMOKE_OK'" \
    /dev/null || true
  diag_classify "$id" 'SCRIPT_SMOKE_OK'
  return 0
}

# _diag_d3_cleanup_gate ID — the UAT-8l evidence gate for a D3 probe: its
# docker result counts as PASS (and is usable for cause attribution) ONLY
# when the mandatory cleanup is confirmed (clean/reaped). An unconfirmed
# verdict is a separate diagnostic FAIL of its own: a docker pass is demoted
# to a cleanup-<verdict> detail (a failed workload keeps its own detail, so
# the measured timeout evidence is not hidden), the probe proves nothing for
# the diagnosis, and no further new matrix probes may start. The cleanup
# owners and their ownership checks are untouched.
_diag_d3_cleanup_gate() { # ID -> 0 confirmed | 1 unconfirmed
  local id="$1" verdict
  verdict="$(cat "$DIAG_DIR/$id.session" 2>/dev/null || echo missing)"
  diag_cleanup_ok "$verdict" || {
    if [ "$(cat "$DIAG_DIR/$id.detail" 2>/dev/null || echo missing)" = ok ]; then
      printf 'cleanup-%s\n' "$verdict" > "$DIAG_DIR/$id.detail"
    fi
    DIAG_D3_CLEANUP_FAILED=1
    return 1
  }
  return 0
}

# _diag_d3_probe NAME WS PAYLOAD EXCLUDED_FACTOR — one bounded D3 factor
# probe: the canonical exec-path configuration reassembled through the
# shared composition owner with EXACTLY ONE factor removed. Declared
# differences per probe:
#   notty     — the -it flag removed AND the stdin closed AND the payload
#               simplified (the TTY proof would fail without a TTY): a
#               THREE-variable difference, recorded as evidence but never
#               eligible to name a cause by itself (UAT-8k)
#   nosession — the Session lifecycle and bearer removed (single variable)
#   noagent   — the ssh-agent factor removed (single variable)
_diag_d3_probe() { # NAME WS PAYLOAD EXCLUDED_FACTOR
  local name="$1" ws="$2" payload="$3" excluded="$4"
  local id="F-D3-$name"
  local excl_session="" excl_agent=""
  [ "$excluded" = session ] && excl_session=session
  [ "$excluded" = agent ] && excl_agent=agent
  local -a argv=()
  local crc=0
  _diag_d3_compose_argv argv "$id" "$excl_session" "$excl_agent" || crc=$?
  if [ "$crc" != 0 ]; then
    _diag_d3_refusal_records "$id" "$crc"
    if [ "$crc" = 1 ]; then
      return 0
    fi
    _diag_d3_probe_cleanup "$ws" "$id"
    # UAT-8l: a refused probe's due cleanup feeds the same evidence gate
    _diag_d3_cleanup_gate "$id" || true
    return 0
  fi
  if [ "$excluded" = tty ]; then
    payload='echo D3_OK'
  else
    payload='test -t 0 && echo D3_OK'
    argv+=(-it)
  fi
  argv+=(--entrypoint /bin/sh "$DIAG_IMAGE" -c "$payload")
  local -a run_argv=(docker "${argv[@]}")
  case "$excluded" in
    tty)
      # no -it: the stdin is deliberately /dev/null. UAT-8m: the probe
      # records its own before-docker-exec phase marker first
      printf '%s\n' before-docker-exec >> "$DIAG_DIR/$id.phases"
      DIAG_CONTAINER_NAME="dhl-$id-$DIAG_RUNID" \
        DIAG_CONTAINER_CID="$DIAG_DIR/$id.cid" \
        diag_exec "$id" "$DIAG_FACTOR_BOUND" "${run_argv[@]}" </dev/null || true
      ;;
    *)
      # -it probes run under a real script(1) pty: the client must hold a
      # terminal, exactly like the canonical launcher. UAT-8m: the inner
      # command writes the fixed phase markers before docker runs
      DIAG_CONTAINER_NAME="dhl-$id-$DIAG_RUNID" \
        DIAG_CONTAINER_CID="$DIAG_DIR/$id.cid" \
        diag_exec "$id" "$DIAG_FACTOR_BOUND" \
        script -qec "$(_diag_phase_prefix "$id" docker)$(printf '%q ' "${run_argv[@]}")" /dev/null || true
      ;;
  esac
  diag_classify "$id" 'D3_OK'
  _diag_d3_probe_cleanup "$ws" "$id"
  unset DOCKER_HELPER_SESSION_ID DOCKER_HELPER_SESSION_TOKEN
  # UAT-8l: an unconfirmed cleanup voids the probe's PASS and stops any
  # further new matrix probes
  _diag_d3_cleanup_gate "$id" || true
  return 0
}

# _diag_d3_matrix_probe ID WS FLAGS WRAPPER STDIN — one STRICT single-variable
# matrix probe (UAT-8k). Every probe shares IDENTICAL composition (the same
# canonical owners: security options, init, mounts/env, ssh-agent, Session
# lifecycle and bearer) and the IDENTICAL safe payload `echo D3_OK`; the ONLY
# varied dimensions are the explicit parameters:
#   FLAGS   none | -i | -t | -it   (the docker TTY/stdin flags)
#   WRAPPER script  (a real script(1) pty, exactly like the canonical
#                   launcher) | direct (docker called without a pty wrapper)
#   STDIN   inherit (the probe inherits the caller's stdin) | null (stdin
#           is /dev/null)
# A probe whose composition/agent/session creation refuses records the
# refusal and never runs docker; any probe-owned resource is recovered
# through the shared probe cleanup owner. UAT-8l: the probe's result is a
# usable PASS only when its cleanup is confirmed; an unconfirmed cleanup is
# a probe failure of its own (rc 1) that stops the remaining matrix probes.
_diag_d3_matrix_probe() { # ID WS FLAGS WRAPPER STDIN
  local id="$1" ws="$2" flags="$3" wrapper="$4" stdin_mode="$5"
  local -a argv=()
  local crc=0
  _diag_d3_compose_argv argv "$id" "" "" || crc=$?
  if [ "$crc" != 0 ]; then
    _diag_d3_refusal_records "$id" "$crc"
    if [ "$crc" = 1 ]; then
      return 0
    fi
    _diag_d3_probe_cleanup "$ws" "$id"
    _diag_d3_cleanup_gate "$id"
    return $?
  fi
  case "$flags" in
    none) : ;;
    -i|-t|-it) argv+=("$flags") ;;
    *)
      # an unknown flag spec is a programming error, never a probe result
      printf 'bad-flag-spec\n' > "$DIAG_DIR/$id.detail"
      printf 'refused\n' > "$DIAG_DIR/$id.rc"
      printf 'unknown\n' > "$DIAG_DIR/$id.elapsed"
      return 0
      ;;
  esac
  argv+=(--entrypoint /bin/sh "$DIAG_IMAGE" -c 'echo D3_OK')
  case "$wrapper" in
    script)
      # UAT-8m: the inner command writes the fixed phase markers before
      # docker runs
      local phases
      phases="$(_diag_phase_prefix "$id" docker)"
      if [ "$stdin_mode" = null ]; then
        DIAG_CONTAINER_NAME="dhl-$id-$DIAG_RUNID" \
          DIAG_CONTAINER_CID="$DIAG_DIR/$id.cid" \
          diag_exec "$id" "$DIAG_FACTOR_BOUND" \
          script -qec "${phases}$(printf '%q ' docker "${argv[@]}")" /dev/null </dev/null || true
      else
        DIAG_CONTAINER_NAME="dhl-$id-$DIAG_RUNID" \
          DIAG_CONTAINER_CID="$DIAG_DIR/$id.cid" \
          diag_exec "$id" "$DIAG_FACTOR_BOUND" \
          script -qec "${phases}$(printf '%q ' docker "${argv[@]}")" /dev/null || true
      fi
      ;;
    direct)
      # UAT-8m: the probe records its own before-docker-exec phase marker
      printf '%s\n' before-docker-exec >> "$DIAG_DIR/$id.phases"
      if [ "$stdin_mode" = null ]; then
        DIAG_CONTAINER_NAME="dhl-$id-$DIAG_RUNID" \
          DIAG_CONTAINER_CID="$DIAG_DIR/$id.cid" \
          diag_exec "$id" "$DIAG_FACTOR_BOUND" docker "${argv[@]}" </dev/null || true
      else
        DIAG_CONTAINER_NAME="dhl-$id-$DIAG_RUNID" \
          DIAG_CONTAINER_CID="$DIAG_DIR/$id.cid" \
          diag_exec "$id" "$DIAG_FACTOR_BOUND" docker "${argv[@]}" || true
      fi
      ;;
    *)
      printf 'bad-wrapper-spec\n' > "$DIAG_DIR/$id.detail"
      printf 'refused\n' > "$DIAG_DIR/$id.rc"
      printf 'unknown\n' > "$DIAG_DIR/$id.elapsed"
      return 0
      ;;
  esac
  diag_classify "$id" 'D3_OK'
  _diag_d3_probe_cleanup "$ws" "$id"
  unset DOCKER_HELPER_SESSION_ID DOCKER_HELPER_SESSION_TOKEN
  _diag_d3_cleanup_gate "$id"
}

# _diag_d3_matrix WS — the strict UAT-8k D3 factor matrix: the probes that
# isolate, under IDENTICAL composition and payload, the docker TTY/stdin
# flags (none, -i, -t, -it under the same script(1) pty), the nested pty
# wrapper and the stdin policy. UAT-8m adds F-D3-direct-none: the SAME
# no-flag configuration as F-D3-flag-none with docker invoked DIRECTLY, so
# the script(1) wrapper itself can be separated from the docker execution
# under it. Each probe holds its own Session, created and deleted only
# through the canonical owners. UAT-8l: an unconfirmed cleanup anywhere
# (including a legacy factor probe) stops all further new matrix probes;
# none of them ever skips its own cleanup.
_diag_d3_matrix() { # WS
  local ws="$1"
  DIAG_D3_MATRIX_RAN=1
  [ "${DIAG_D3_CLEANUP_FAILED:-0}" = 0 ] || return 0
  _diag_d3_matrix_probe F-D3-flag-none   "$ws" none script   inherit || return 0
  _diag_d3_matrix_probe F-D3-direct-none "$ws" none direct   inherit || return 0
  _diag_d3_matrix_probe F-D3-flag-i      "$ws" -i   script   inherit || return 0
  _diag_d3_matrix_probe F-D3-flag-t      "$ws" -t   script   inherit || return 0
  _diag_d3_matrix_probe F-D3-flag-it     "$ws" -it  script   inherit || return 0
  _diag_d3_matrix_probe F-D3-pty-direct  "$ws" -it  direct   inherit || return 0
  _diag_d3_matrix_probe F-D3-stdin-pty   "$ws" -i   direct   inherit || return 0
  _diag_d3_matrix_probe F-D3-stdin-null  "$ws" -i   direct   null    || return 0
}

# _diag_mstate ID — the verdict state of one matrix probe from its recorded
# detail: passed (ok), hung (timeout) or other (any refusal or different
# failure). UAT-8l: a probe whose mandatory cleanup was not confirmed
# (clean/reaped) proves nothing for the diagnosis and is never passed or
# hung here, whatever its docker outcome was.
_diag_mstate() { # ID -> passed|hung|other
  local detail verdict
  detail="$(cat "$DIAG_DIR/$1.detail" 2>/dev/null || echo missing)"
  verdict="$(cat "$DIAG_DIR/$1.session" 2>/dev/null || echo missing)"
  if ! diag_cleanup_ok "$verdict"; then
    printf 'other'
    return 0
  fi
  case "$detail" in
    ok) printf 'passed' ;;
    timeout) printf 'hung' ;;
    *) printf 'other' ;;
  esac
  return 0
}

# _diag_d3_legacy_pass — the legacy single-variable probes (the Session
# lifecycle, the ssh-agent) that passed where D3 failed, as "<count> <name>".
# Their factor attribution is MORE SPECIFIC than the UAT-8m wrapper/docker
# verdicts: whenever one of them passed, the wrapper/docker question is not
# the explanation of the D3 failure and must not overwrite it.
_diag_d3_legacy_pass() { # -> "<count> <name>"
  local id count=0 name=""
  for id in F-D3-nosession F-D3-noagent; do
    if [ "$(cat "$DIAG_DIR/$id.detail" 2>/dev/null || echo missing)" = ok ]; then
      name="$id"
      count=$((count + 1))
    fi
  done
  printf '%s %s' "$count" "$name"
}

# _diag_d3_matrix_diagnosis — the controlled-comparison verdict over the
# strict matrix. A factor is named ONLY when a single-variable comparison
# supports it; a probe that refused or failed for another reason proves
# nothing and is never treated as a pass:
#   1. the -it probe hung while the direct -it probe passed -> the nested
#      pty wrapper is implicated
#   2. the -i probe hung with the pty stdin while the closed-stdin -i probe
#      passed -> the pty stdin is implicated
#   3. the -t probe hung while the -i and no-flag probes passed AND the
#      combined -it probe hung too (UAT-8l consistency: the -it probe
#      carries -t, so a passing -it contradicts a -t-only cause) -> the
#      docker -t flag is implicated
#   4. the -i probe hung while the -t and no-flag probes passed AND the
#      combined -it probe hung too (the same consistency rule) -> the
#      docker -i flag is implicated
#   5. the -it probe hung while the -i, -t and no-flag probes passed -> the
#      -it flag combination is implicated
# UAT-8m adds the wrapper-isolation evidence and three further verdicts.
# ALL of them are gated on the legacy single-variable probes NOT having
# passed (a more specific factor attribution always wins), and every
# verdict requires consistency: contradictory observations name nothing.
#   A. the no-docker smoke probe timed out AND no script-wrapped probe
#      passed -> the nested script(1) wrapper itself hangs; it fires FIRST
#      because a broken wrapper voids the script-wrapped docker evidence
#   B. the smoke passed, the script-wrapped no-flag probe hung while the
#      IDENTICAL direct no-flag probe passed and no other script-wrapped
#      probe passed -> docker hangs under the wrapper
#   C. the direct no-flag probe hung (and the script-wrapped no-flag probe
#      did not pass) -> docker hangs even without the wrapper; the wrapper
#      is excluded as the cause
# Contradictory observations name nothing: an empty result means the matrix
# did not prove a single cause.
_diag_d3_matrix_diagnosis() { # -> verdict text on stdout; rc 1 = unresolved
  local none i t it pd sp sn dn smoke detail legacy lcount
  none="$(_diag_mstate F-D3-flag-none)"
  i="$(_diag_mstate F-D3-flag-i)"
  t="$(_diag_mstate F-D3-flag-t)"
  it="$(_diag_mstate F-D3-flag-it)"
  pd="$(_diag_mstate F-D3-pty-direct)"
  sp="$(_diag_mstate F-D3-stdin-pty)"
  sn="$(_diag_mstate F-D3-stdin-null)"
  dn="$(_diag_mstate F-D3-direct-none)"
  legacy="$(_diag_d3_legacy_pass)"
  lcount="${legacy%% *}"
  # the smoke probe creates nothing, so it has no cleanup verdict to gate
  # its PASS: its own docker-free outcome is read directly
  detail="$(cat "$DIAG_DIR/F-D3-script-smoke.detail" 2>/dev/null || echo missing)"
  case "$detail" in
    ok) smoke=passed ;;
    timeout) smoke=hung ;;
    *) smoke=other ;;
  esac
  if [ "$smoke" = hung ] && [ "$lcount" = 0 ] \
      && [ "$none" != passed ] && [ "$i" != passed ] \
      && [ "$t" != passed ] && [ "$it" != passed ]; then
    printf 'the D3 nested script(1) wrapper itself hangs (the no-docker smoke probe timed out; the script-wrapped docker evidence is void)'
    return 0
  fi
  if [ "$it" = hung ] && [ "$pd" = passed ]; then
    printf 'the D3 nested pty wrapper is implicated (F-D3-flag-it hung where F-D3-pty-direct passed; single-variable comparison)'
    return 0
  fi
  if [ "$i" = hung ] && [ "$sp" = hung ] && [ "$sn" = passed ]; then
    printf 'the D3 pty stdin is implicated (F-D3-stdin-pty hung where F-D3-stdin-null passed; single-variable comparison)'
    return 0
  fi
  if [ "$t" = hung ] && [ "$i" = passed ] && [ "$none" = passed ] \
      && [ "$it" = hung ]; then
    printf 'the D3 docker -t flag is implicated (F-D3-flag-t hung where F-D3-flag-i and F-D3-flag-none passed; single-variable comparison)'
    return 0
  fi
  if [ "$i" = hung ] && [ "$t" = passed ] && [ "$none" = passed ] \
      && [ "$it" = hung ]; then
    printf 'the D3 docker -i flag is implicated (F-D3-flag-i hung where F-D3-flag-t and F-D3-flag-none passed; single-variable comparison)'
    return 0
  fi
  if [ "$it" = hung ] && [ "$i" = passed ] && [ "$t" = passed ] \
      && [ "$none" = passed ]; then
    printf 'the D3 docker -it flag combination is implicated (F-D3-flag-it hung where the -i, -t and no-flag probes passed; single-variable comparison)'
    return 0
  fi
  # UAT-8m rule B: the wrapper works (the smoke passed) and the IDENTICAL
  # no-flag configuration hangs under it while passing when docker runs
  # directly; a passing script-wrapped sibling or legacy factor would
  # contradict or supersede a wrapper-only cause and names nothing
  if [ "$lcount" = 0 ] && [ "$smoke" = passed ] && [ "$none" = hung ] \
      && [ "$dn" = passed ] && [ "$i" != passed ] && [ "$t" != passed ] \
      && [ "$it" != passed ]; then
    printf 'docker hangs under the nested script(1) wrapper (F-D3-flag-none hung where the identical F-D3-direct-none passed; single-variable comparison)'
    return 0
  fi
  # UAT-8m rule C: docker hangs even without the wrapper; a passing
  # script-wrapped no-flag probe would contradict the direct observation
  # and a passing legacy factor would supersede it
  if [ "$lcount" = 0 ] && [ "$dn" = hung ] && [ "$none" != passed ]; then
    printf 'docker hangs even when invoked directly without the nested script wrapper (F-D3-direct-none hung; the wrapper is excluded as the cause)'
    return 0
  fi
  return 1
}

# _diag_d3_diagnose — the D3 diagnosis output (UAT-8k). A factor is
# IMPLICATED only by a controlled single-variable comparison; everything
# else is UNRESOLVED. The legacy F-D3-notty probe changes the docker flags,
# the stdin and the payload TOGETHER, so its result is preliminary evidence
# and can never name a cause by itself; the single-variable fallback names
# only the probes that remove exactly one canonical factor (the Session
# lifecycle, the ssh-agent).
_diag_d3_diagnose() {
  local verdict="" legacy lname lcount
  if [ "${DIAG_D3_MATRIX_RAN:-0}" = 1 ]; then
    verdict="$(_diag_d3_matrix_diagnosis)" || true
  fi
  if [ -n "$verdict" ]; then
    printf 'DIAGNOSIS: %s\n' "$verdict"
    return 0
  fi
  read -r lcount lname <<< "$(_diag_d3_legacy_pass)"
  if [ "$lcount" = 1 ]; then
    printf 'DIAGNOSIS: the %s factor is implicated (%s passed where D3 failed; single-variable probes only)\n' \
      "${lname#F-}" "$lname"
    return 0
  fi
  if [ "$(cat "$DIAG_DIR/F-D3-notty.detail" 2>/dev/null || echo missing)" = ok ]; then
    printf 'DIAG OBSERVED: F-D3-notty passed (preliminary evidence only: that probe changes the docker flags, the stdin and the payload together)\n'
  fi
  printf 'DIAGNOSIS UNRESOLVED: the failing step is D3 (detail %s); the factor evidence did not prove a single cause\n' \
    "$(cat "$DIAG_DIR/D3.detail" 2>/dev/null || echo unknown)"
  return 0
}

# _diag_d3_probe_cleanup WS ID — register and recover exactly this probe's
# resources (the workspace-owned Session delta and the daemon-attributed
# containers), then stop the probe's own ssh-agent.
_diag_d3_probe_cleanup() { # WS ID
  local ws="$1" id="$2"
  local verdict
  verdict="$(diag_canonical_recover "$id" "$ws" "dhl-$id-$DIAG_RUNID" "$DIAG_DIR/$id.cid")"
  printf '%s\n' "$verdict" > "$DIAG_DIR/$id.session"
  if [ -n "${_OC_SSH_AGENT_PID:-}" ]; then
    kill "$_OC_SSH_AGENT_PID" 2>/dev/null || true
    [ -z "${_OC_SSH_RUN_DIR:-}" ] || rm -rf -- "$_OC_SSH_RUN_DIR"
    _OC_SSH_AGENT_PID=""; _OC_SSH_RUN_DIR=""
  fi
  return 0
}
