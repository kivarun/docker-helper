#!/usr/bin/env bash
#
# uat-selinux-ab-proof.sh — bounded SELinux A/B evidence for the two real
# production blockers on the Tumbleweed / RPM / SELinux profile. Runs INSIDE
# the guest as root, against an already-installed, confined docker-helper
# system service (docker_helper_t) with the Docker daemon running.
#
# Part A — Docker runtime/socket A/B proof:
#   BEFORE  ->  restorecon -v "$(command -v dockerd)" ; systemctl restart docker
#            ->  AFTER  ->  ONE real `docker-helper pull alpine:3.24`.
#   Reports whether the exact dockerd executable relabel changes the dockerd
#   domain, the /run/docker.sock type, and the docker-helper pull result.
#   This is a bounded experiment and deliberately does NOT broaden the shipped
#   policy: no `allow var_run_t`, no `allow unconfined_service_t`, and no
#   recursive relabel of Docker runtime state.
#
# Part B — semanage production-path proof:
#   Documents the semanage executable/interpreter types and whether the
#   installed policy provides the standard semanage execution/domain types
#   (semanage_exec_t / semanage_t). Then, with dontaudit disabled
#   (semodule -DB), triggers ONE non-home Session creation through the real
#   confined docker_helper_t daemon — the production path that invokes
#   `semanage fcontext -l -C -n` — and captures the exact AVC(s). ALWAYS
#   restores dontaudit (semodule -B), even on failure.
#
# Evidence collection, NOT a pass/fail gate: exit 0 whenever the proofs ran to
# completion (the pull may fail — that failure is itself the evidence);
# nonzero only on a harness failure.
#
# Env inputs:
#   (none required; the RPM must already be installed and the service confined)

set -uo pipefail

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
[ "$(getenforce 2>/dev/null || true)" = "Enforcing" ] \
  || { echo "error: SELinux not enforcing" >&2; exit 1; }

# NOTE: no info/say helpers here; the proof prints labeled AB_* evidence via
# echo so the output is directly parseable.

# attr_current reads /proc/<pid>/attr/current with the trailing NUL stripped
# (kernel writes a NUL terminator; shell tools warn about it otherwise).
attr_current() {
  tr -d '\0' < "/proc/$1/attr/current" 2>/dev/null || true
}

# ctx_type prints the SELinux TYPE of a path's label (full context via stat %C,
# fallback to getfilecon for robustness).
ctx_type() {
  local c
  c="$(stat -c '%C' "$1" 2>/dev/null || true)"
  if [ -z "$c" ] || [ "$c" = "?" ]; then
    c="$(getfilecon "$1" 2>/dev/null | sed 's/^[^:]*:[[:space:]]*//' || true)"
  fi
  printf '%s' "$c" | cut -d: -f3
}

# redact masks bearer tokens (dht_/dhc_) in captured output at display time.
redact() {
  sed -E -e 's/dht_[A-Za-z0-9_-]+/<redacted-token>/g' -e 's/dhc_[A-Za-z0-9_-]+/<redacted-token>/g'
}

# ensure_service re-enables the docker-helper system service (the install-only
# UAT cleanup stops it) and waits for it to be active.
ensure_service() {
  systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
  for _ in $(seq 1 60); do
    systemctl is-active --quiet docker-helper.service && return 0
    sleep 1
  done
  echo "error: docker-helper.service not active" >&2
  return 1
}

# ensure_principal_session creates principal opc + allowed root + a home
# session and prints the session token on stdout (home workspace => the
# semanage production path is NOT triggered; used by the Docker A/B pull).
ensure_principal_session() {
  local cred="/tmp/uat-ab-credential.token"
  rm -f "$cred"
  docker-helper principal create --system opc >/dev/null 2>&1 || true
  docker-helper principal allowed-root add --system opc /home/opc >/dev/null 2>&1 || true
  mkdir -p /home/opc/uat-workspace
  local out
  out="$(docker-helper credential create --system --name uat-ab opc 2>/dev/null || true)"
  local tok
  tok="$(printf '%s\n' "$out" | sed -n 's/^  Token: //p' | tr -d '[:space:]')"
  if [ -z "$tok" ]; then
    # Fall back to an admin session (no credential) for the pull token.
    local sess
    sess="$(docker-helper session create --system --workspace /home/opc/uat-workspace --json 2>/dev/null)" || true
    tok="$(printf '%s\n' "$sess" | grep -oP '"token": "\K[^"]+' | head -1)"
  else
    printf '%s\n' "$tok" > "$cred"
    chmod 600 "$cred"
    local sess2
    sess2="$(docker-helper session create --system --token-file "$cred" --workspace /home/opc/uat-workspace --json 2>/dev/null)" || true
    tok="$(printf '%s\n' "$sess2" | grep -oP '"token": "\K[^"]+' | head -1)"
  fi
  [ -n "$tok" ] || { echo "error: could not obtain a session token" >&2; return 1; }
  printf '%s' "$tok"
}

# restore dontaudit behavior on exit (Part B mutates it and MUST restore it).
restore_dontaudit() {
  echo "AB restore dontaudit: semodule -B"
  semodule -B 2>&1 || echo "warning: semodule -B failed (dontaudit may remain disabled)"
}
trap restore_dontaudit EXIT

echo "================ SELINUX A/B PROOFS (Tumbleweed/RPM/SELinux) ================"

# ===========================================================================
# Part A — Docker runtime/socket A/B proof
# ===========================================================================
echo
echo "===== PART A: DOCKER RUNTIME/SOCKET A/B PROOF ====="
DOCKERD="$(command -v dockerd 2>/dev/null || true)"
if [ -z "$DOCKERD" ]; then
  echo "AB_PART_A=SKIP (dockerd not found)"
else
  DOCKERD_REAL="$(readlink -f "$DOCKERD" 2>/dev/null || true)"
  DOCKERD_PID="$(pidof dockerd 2>/dev/null || true)"

  echo "--- BEFORE ---"
  echo "AB_DOCKERD_CMD=$DOCKERD"
  echo "AB_DOCKERD_REALPATH=$DOCKERD_REAL"
  ls -lZ "$DOCKERD" 2>&1 || true
  matchpathcon "$DOCKERD" 2>&1 || true
  if [ -n "$DOCKERD_PID" ]; then
    printf 'AB_DOCKERD_DOMAIN_BEFORE='
    attr_current "$DOCKERD_PID"
    echo
    ps -Z -p "$DOCKERD_PID" 2>&1 || true
  else
    echo "AB_DOCKERD_DOMAIN_BEFORE=(dockerd not running / pidof empty)"
  fi
  ls -lZ /run/docker.sock 2>&1 || true
  echo "AB_SOCKET_REALPATH=$(readlink -f /run/docker.sock 2>/dev/null || true)"
  matchpathcon /run/docker.sock 2>&1 || true

  echo "--- EXPERIMENT: restorecon -v dockerd + systemctl restart docker ---"
  restorecon -v "$DOCKERD" 2>&1 || true
  systemctl restart docker 2>&1 || true
  # bounded wait for docker to come back
  DOCKER_BACK=0
  for _ in $(seq 1 60); do
    if [ -S /run/docker.sock ] && pidof dockerd >/dev/null 2>&1; then
      DOCKER_BACK=1
      break
    fi
    sleep 1
  done

  echo "--- AFTER ---"
  ls -lZ "$DOCKERD" 2>&1 || true
  DOCKERD_PID="$(pidof dockerd 2>/dev/null || true)"
  if [ -n "$DOCKERD_PID" ]; then
    printf 'AB_DOCKERD_DOMAIN_AFTER='
    attr_current "$DOCKERD_PID"
    echo
    ps -Z -p "$DOCKERD_PID" 2>&1 || true
  else
    echo "AB_DOCKERD_DOMAIN_AFTER=(dockerd not running after restart)"
  fi
  ls -lZ /run/docker.sock 2>&1 || true
  matchpathcon /run/docker.sock 2>&1 || true
  echo "AB_DOCKER_BACK=$DOCKER_BACK"

  # ONE real docker-helper pull through the confined daemon.
  if ensure_service; then
    TOKEN="$(ensure_principal_session || true)"
    if [ -n "$TOKEN" ]; then
      echo "--- ONE real docker-helper pull alpine:3.24 (after Docker restart) ---"
      export DOCKER_HELPER_SESSION_TOKEN="$TOKEN"
      PULL_RC=0
      PULL_OUT="$(docker-helper pull alpine:3.24 2>&1)" || PULL_RC=$?
      printf '%s\n' "$PULL_OUT" | redact | tail -15
      echo "AB_PULL_RC=$PULL_RC"
      unset DOCKER_HELPER_SESSION_TOKEN
    else
      echo "AB_PULL_RC=(no session token; pull not attempted)"
    fi
  else
    echo "AB_PULL_RC=(service not active; pull not attempted)"
  fi
fi

# ===========================================================================
# Part B — semanage production-path proof
# ===========================================================================
echo
echo "===== PART B: SEMANAGE PRODUCTION-PATH PROOF ====="
SEMANAGE="$(command -v semanage 2>/dev/null || true)"
if [ -z "$SEMANAGE" ]; then
  echo "AB_PART_B=SKIP (semanage not found)"
else
  SEMANAGE_REAL="$(readlink -f "$SEMANAGE" 2>/dev/null || true)"
  echo "--- semanage executable ---"
  echo "AB_SEMANAGE_CMD=$SEMANAGE"
  echo "AB_SEMANAGE_REALPATH=$SEMANAGE_REAL"
  echo "AB_SEMANAGE_LS: $(ls -lZ "$SEMANAGE" 2>&1 || true)"
  echo "AB_SEMANAGE_ACTUAL_TYPE=$(ctx_type "$SEMANAGE")"
  echo "AB_SEMANAGE_MATCHPATHCON: $(matchpathcon "$SEMANAGE" 2>&1 || true)"
  echo "AB_SEMANAGE_HEAD: $(head -1 "$SEMANAGE" 2>&1 || true)"

  # If semanage is a script, document its interpreter types too.
  FIRST="$(head -1 "$SEMANAGE" 2>/dev/null || true)"
  case "$FIRST" in
    '#!'*)
      INTERP="$(printf '%s' "$FIRST" | sed -n 's/^#![[:space:]]*//p' | awk '{print $1}')"
      if [ -n "$INTERP" ]; then
        INTERP_REAL="$(readlink -f "$INTERP" 2>/dev/null || true)"
        echo "AB_SEMANAGE_INTERP=$INTERP"
        echo "AB_SEMANAGE_INTERP_REALPATH=$INTERP_REAL"
        echo "AB_SEMANAGE_INTERP_LS: $(ls -lZ "$INTERP" 2>&1 || true)"
        echo "AB_SEMANAGE_INTERP_ACTUAL_TYPE=$(ctx_type "$INTERP")"
        echo "AB_SEMANAGE_INTERP_MATCHPATHCON: $(matchpathcon "$INTERP" 2>&1 || true)"
        if [ -n "$INTERP_REAL" ] && [ "$INTERP_REAL" != "$INTERP" ]; then
          echo "AB_SEMANAGE_INTERP_REAL_LS: $(ls -lZ "$INTERP_REAL" 2>&1 || true)"
          echo "AB_SEMANAGE_INTERP_REAL_MATCHPATHCON: $(matchpathcon "$INTERP_REAL" 2>&1 || true)"
        fi
      fi
      ;;
  esac

  # Does the installed policy provide the standard semanage types?
  echo "--- policy type availability (semanage_exec_t / semanage_t) ---"
  if command -v seinfo >/dev/null 2>&1; then
    echo "AB_POLICY_HAS_SEMANAGE_EXEC_T=$(seinfo -t semanage_exec_t 2>/dev/null | grep -c 'semanage_exec_t' || true)"
    echo "AB_POLICY_HAS_SEMANAGE_T=$(seinfo -t semanage_t 2>/dev/null | grep -c 'semanage_t' || true)"
  else
    echo "AB_POLICY_TOOL=seinfo (setools) not installed; using matchpathcon + sesearch when available"
  fi
  if command -v sesearch >/dev/null 2>&1; then
    echo "--- type_transition rules touching docker_helper_t -> semanage_exec_t ---"
    sesearch -T -s docker_helper_t -t semanage_exec_t 2>/dev/null || echo "(none / no rules)"
  else
    echo "AB_POLICY_SESEARCH=not installed (no transition rule inspection possible)"
  fi

  # Disable dontaudit so the production-path denial is logged, then trigger
  # ONE non-home Session creation through the real confined daemon.
  echo "--- disable dontaudit (semodule -DB) ---"
  semodule -DB 2>&1 || { echo "error: semodule -DB failed" >&2; exit 1; }

  if ! ensure_service; then
    echo "AB_PART_B=(service not active; cannot trigger production path)"
    exit 0
  fi
  DH_PID="$(systemctl show -p MainPID --value docker-helper.service 2>/dev/null || true)"
  printf 'AB_DAEMON_DOMAIN='
  attr_current "$DH_PID"
  echo

  # Authorize /opt (authorization ceiling) so a non-home Session is permitted;
  # the Session MAC preparation for a non-home workspace is the production
  # path that invokes `semanage fcontext -l -C -n`.
  docker-helper config allowed-root add /opt >/dev/null 2>&1 || true
  docker-helper reload --system >/dev/null 2>&1 || true

  WS="/opt/uat-ab-semanage-$RANDOM"
  mkdir -p "$WS"
  chmod 0755 "$WS"
  echo "--- ONE non-home Session creation (production path, dontaudit off) ---"
  SESS_JSON="$(docker-helper session create --system --workspace "$WS" --json 2>&1)"
  SESS_RC=$?
  printf '%s\n' "$SESS_JSON" | redact | head -8
  echo "AB_SESSION_RC=$SESS_RC"

  echo "--- exact AVC evidence (ausearch --start recent) ---"
  ausearch -m AVC -m USER_AVC --start recent 2>/dev/null | grep -E 'docker_helper|semanage|denied' \
    || echo "(ausearch found no matching AVC/USER_AVC records, or auditd is not logging them)"
  echo "--- exact AVC evidence (dmesg fallback, operative source when auditd is absent) ---"
  dmesg 2>/dev/null | grep -E 'docker_helper|semanage|avc:.*denied' | tail -20 \
    || true

  rm -rf "$WS"
fi

echo
echo "================ SELINUX A/B PROOFS COMPLETE ================"
exit 0
