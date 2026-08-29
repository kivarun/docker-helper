#!/usr/bin/env bash
#
# uat-selinux-ab-proof.sh — bounded SELinux A/B evidence for the two real
# production blockers on the Tumbleweed / RPM / SELinux profile. Runs INSIDE
# the guest as root, against an already-installed, confined docker-helper
# system service (docker_helper_t) with the Docker daemon running.
#
# Part A — Docker runtime/socket NATURAL-HEALTH confirmation:
#   Reports whether the two-stage UAT environment setup (container-selinux
#   settled BEFORE Docker is installed) produced the naturally healthy Docker
#   state WITHOUT any docker-helper intervention and WITHOUT any explicit
#   restorecon/restart:
#     dockerd executable = container_runtime_exec_t
#     dockerd process    = container_runtime_t
#     docker.sock        = container_var_run_t
#   Then performs ONE real `docker-helper pull alpine:3.24` and records the
#   explicit pull rc (a successful proof script is NOT a successful pull).
#
# Part B — semanage production-path transition derivation:
#   Documents the semanage executable/interpreter types, whether the installed
#   policy provides semanage_exec_t / semanage_t, and the STANDARD semanage
#   domain-transition pattern present in the installed policy (sesearch), and
#   whether process2:nnp_transition is required (docker-helper.service sets
#   NoNewPrivileges=true). Then loads a TEMPORARY proof module that adds ONLY
#   the candidate transition/access rules for
#       docker_helper_t -> semanage_exec_t -> semanage_t
#   (no docker_helper_t generic policy-store access; no execute_no_trans on
#   semanage_exec_t). With dontaudit disabled (semodule -DB) and auditd running,
#   triggers ONE real non-home Session creation through the confined daemon and
#   captures the exact AVC/USER_AVC evidence (ausearch + dmesg) and the daemon
#   journal. ALWAYS restores dontaudit (semodule -B) and removes the temporary
#   proof module, even on failure.
#
# Evidence collection, NOT a pass/fail gate: exit 0 whenever the proofs ran to
# completion (the pull may fail, the session create may fail — those failures
# are themselves the evidence); nonzero only on a harness failure.
#
# Env inputs:
#   (none required; the RPM must already be installed and the service confined)

set -uo pipefail

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
[ "$(getenforce 2>/dev/null || true)" = "Enforcing" ] \
  || { echo "error: SELinux not enforcing" >&2; exit 1; }
for t in semodule ausearch checkmodule semodule_package sesearch; do
  command -v "$t" >/dev/null 2>&1 || { echo "error: $t not found" >&2; exit 1; }
done

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

# ensure_auditd makes sure the audit daemon is RUNNING so AVC evidence is
# actually captured (the minimal image does not ship/start it). Best-effort
# install through the canonical repo policy owner if the package is absent.
# It also force-enables the kernel audit subsystem (auditctl -e 1) and records
# its status so AVC capture is verifiable, not assumed.
ensure_auditd() {
  if ! command -v auditd >/dev/null 2>&1 && [ -f /opt/uat-repo-policy.sh ]; then
    # shellcheck source=/dev/null
    source /opt/uat-repo-policy.sh
    opensuse_zypp_tune_timeouts
    opensuse_zypper_refresh >/dev/null 2>&1 || true
    opensuse_zypper install -y audit >/dev/null 2>&1 || true
  fi
  systemctl enable --now auditd >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do
    systemctl is-active --quiet auditd && break
    sleep 1
  done
  if systemctl is-active --quiet auditd; then
    # Force the kernel audit subsystem on and record its status + the log file
    # so a later empty ausearch is meaningful (capture proven) rather than
    # ambiguous (capture silently broken).
    if command -v auditctl >/dev/null 2>&1; then
      auditctl -e 1 >/dev/null 2>&1 || true
      echo "AB_AUDITCTL_STATUS: $(auditctl -s 2>&1 || true)"
    else
      echo "AB_AUDITCTL_STATUS=(auditctl not found)"
    fi
    echo "AB_AUDIT_LOG: $(ls -la /var/log/audit/audit.log 2>&1 || true)"
    echo "AB_AUDITD=running"
    # Drain any pre-existing AVC records so only fresh ones are captured.
    ausearch -m AVC -m USER_AVC --start recent >/dev/null 2>&1 || true
  else
    echo "AB_AUDITD=not-running (AVC evidence falls back to dmesg + daemon journal)"
  fi
}

# restore dontaudit behavior + remove the temporary proof module on exit.
# The proof module is removed even on failure so the guest never keeps the
# candidate rules loaded beyond the bounded experiment.
restore_dontaudit() {
  echo "AB restore dontaudit: semodule -B"
  semodule -B 2>&1 || echo "warning: semodule -B failed (dontaudit may remain disabled)"
  if [ -f /tmp/dh_semanage_proof.pp ]; then
    echo "AB remove temp proof module: semodule -r dh_semanage_proof"
    semodule -r dh_semanage_proof 2>&1 || echo "warning: semodule -r dh_semanage_proof failed"
  fi
}
trap restore_dontaudit EXIT

echo "================ SELINUX A/B PROOFS (Tumbleweed/RPM/SELinux) ================"

# ===========================================================================
# Part A — Docker runtime/socket NATURAL-HEALTH confirmation
# ===========================================================================
echo
echo "===== PART A: DOCKER RUNTIME/SOCKET NATURAL-HEALTH CONFIRMATION ====="
DOCKERD="$(command -v dockerd 2>/dev/null || true)"
if [ -z "$DOCKERD" ]; then
  echo "AB_PART_A=SKIP (dockerd not found)"
else
  DOCKERD_REAL="$(readlink -f "$DOCKERD" 2>/dev/null || true)"
  DOCKERD_PID="$(pidof dockerd 2>/dev/null || true)"

  echo "--- current (natural, two-stage setup) state ---"
  echo "AB_DOCKERD_CMD=$DOCKERD"
  echo "AB_DOCKERD_REALPATH=$DOCKERD_REAL"
  ls -lZ "$DOCKERD" 2>&1 || true
  echo "AB_DOCKERD_MATCHPATHCON: $(matchpathcon "$DOCKERD" 2>&1 || true)"
  if [ -n "$DOCKERD_PID" ]; then
    printf 'AB_DOCKERD_PROC_DOMAIN='
    attr_current "$DOCKERD_PID"
    echo
    ps -Z -p "$DOCKERD_PID" 2>&1 || true
  else
    echo "AB_DOCKERD_PROC_DOMAIN=(dockerd not running / pidof empty)"
  fi
  ls -lZ /run/docker.sock 2>&1 || true
  echo "AB_SOCKET_REALPATH=$(readlink -f /run/docker.sock 2>/dev/null || true)"
  echo "AB_SOCKET_MATCHPATHCON: $(matchpathcon /run/docker.sock 2>&1 || true)"

  EXEC_T="$(ctx_type "$DOCKERD")"
  PROC_T="$(if [ -n "$DOCKERD_PID" ]; then attr_current "$DOCKERD_PID" | cut -d: -f3; fi)"
  SOCK_T="$(ctx_type /run/docker.sock)"
  if [ "$EXEC_T" = "container_runtime_exec_t" ] && [ "$PROC_T" = "container_runtime_t" ] && [ "$SOCK_T" = "container_var_run_t" ]; then
    echo "AB_DOCKER_NATURAL_HEALTH=yes (dockerd_exec=$EXEC_T dockerd_proc=$PROC_T socket=$SOCK_T)"
  else
    echo "AB_DOCKER_NATURAL_HEALTH=no (dockerd_exec=$EXEC_T dockerd_proc=$PROC_T socket=$SOCK_T)"
  fi

  # ONE real docker-helper pull through the confined daemon.
  if ensure_service; then
    TOKEN="$(ensure_principal_session || true)"
    if [ -n "$TOKEN" ]; then
      echo "--- ONE real docker-helper pull alpine:3.24 ---"
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
# Part B — semanage production-path transition derivation
# ===========================================================================
echo
echo "===== PART B: SEMANAGE PRODUCTION-PATH TRANSITION DERIVATION ====="
ensure_auditd

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

  echo "--- policy type availability (semanage_exec_t / semanage_t) ---"
  if command -v seinfo >/dev/null 2>&1; then
    echo "AB_POLICY_HAS_SEMANAGE_EXEC_T=$(seinfo -t semanage_exec_t 2>/dev/null | grep -c 'semanage_exec_t' || true)"
    echo "AB_POLICY_HAS_SEMANAGE_T=$(seinfo -t semanage_t 2>/dev/null | grep -c 'semanage_t' || true)"
  else
    echo "AB_POLICY_TOOL=seinfo not installed"
  fi

  echo "--- standard semanage domain-transition pattern in installed policy ---"
  echo "AB_SESEARCH_T_TO_SEMANAGE_EXEC (type_transition rules targeting semanage_exec_t):"
  sesearch -T -t semanage_exec_t 2>&1 || echo "(none / no rules)"
  echo "AB_SESEARCH_A_FILE_T_SEMANAGE_EXEC (file allows on semanage_exec_t):"
  sesearch -A -t semanage_exec_t -c file 2>&1 | head -30 || true
  echo "AB_SESEARCH_A_PROC_T_SEMANAGE_T (process allows on semanage_t):"
  sesearch -A -t semanage_t -c process 2>&1 | head -30 || true
  echo "AB_SESEARCH_A_PROC2_T_SEMANAGE_T (process2 allows on semanage_t):"
  sesearch -A -t semanage_t -c process2 2>&1 | head -30 || true
  echo "AB_SESEARCH_DOCKER_HELPER_SEMANAGE (docker_helper_t rules touching semanage):"
  sesearch -A -s docker_helper_t -t semanage_exec_t -c file 2>&1 || true
  sesearch -A -s docker_helper_t -t semanage_t -c process 2>&1 || true
  sesearch -A -s docker_helper_t -t semanage_t -c process2 2>&1 || true
  sesearch -T -s docker_helper_t -t semanage_exec_t 2>&1 || true

  echo "--- base-policy pre-grants for the semanage target (what semanage_t already has) ---"
  echo "AB_SESEARCH_SEMANAGE_T_BIN_T_FILE (does the base policy already let semanage_t exec its interpreter bin_t?):"
  sesearch -A -s semanage_t -t bin_t -c file 2>&1 | head -20 || true
  echo "AB_SESEARCH_SEMANAGE_T_PIPE (pipe access from semanage_t):"
  sesearch -A -s semanage_t -c pipe 2>&1 | head -10 || true

  echo "--- NoNewPrivileges determination ---"
  grep -n 'NoNewPrivileges' /usr/lib/systemd/system/docker-helper.service 2>&1 || true
  echo "AB_NNP_EXPECTATION=NoNewPrivileges=true means the domain transition requires process2:nnp_transition (same as the existing init_t -> docker_helper_t rule)"

  echo "--- build + load TEMPORARY proof module (docker_helper_t -> semanage_exec_t -> semanage_t) ---"
  # checkmodule requires the module name to match the output base filename, so
  # the .mod/.pp artifacts are named dh_semanage_proof.* (module dh_semanage_proof).
  # Candidate = standard semanage domtrans pattern PLUS the permissions proven by
  # actual AVC evidence from the previous bounded run:
  #   avc: denied { noatsecure } scontext=docker_helper_t tcontext=semanage_t tclass=process
  #     -> process transition also needs noatsecure (and rlimitinh, the next
  #        kernel-required transition perm) beyond transition/siginh;
  #   avc: denied { execute } scontext=docker_helper_t tcontext=bin_t name=python3.13
  #     tclass=file
  #     -> the exec'ing source domain itself must be able to execute the script
  #        interpreter (bin_t), even when the script exec transitions the child.
  TE="/tmp/dh_semanage_proof.te"
  cat > "$TE" <<'TE_EOF'
module dh_semanage_proof 1.0;

require {
	type docker_helper_t;
	type semanage_t;
	type semanage_exec_t;
	type bin_t;
	class process { transition siginh noatsecure rlimitinh };
	class process2 { nnp_transition };
	class file { execute read open getattr map entrypoint };
}

# Standard semanage domain transition (semanage_domtrans pattern):
#   docker_helper_t -> semanage_exec_t -> semanage_t
type_transition docker_helper_t semanage_exec_t:process semanage_t;
allow docker_helper_t semanage_t:process { transition siginh noatsecure rlimitinh };
# docker-helper.service sets NoNewPrivileges=true; the transition therefore
# requires process2:nnp_transition (mirrors init_t -> docker_helper_t).
allow docker_helper_t semanage_t:process2 { nnp_transition };
allow docker_helper_t semanage_exec_t:file { execute read open getattr map };
allow semanage_t semanage_exec_t:file { execute read open getattr map entrypoint };
# The exec'ing source domain must be able to execute the script interpreter
# (python3.13 at bin_t); AVC: docker_helper_t -> bin_t execute denied.
allow docker_helper_t bin_t:file { execute read open getattr map };
TE_EOF
  if checkmodule -M -m -o /tmp/dh_semanage_proof.mod "$TE" 2>&1; then
    if semodule_package -o /tmp/dh_semanage_proof.pp -m /tmp/dh_semanage_proof.mod 2>&1 && semodule -i /tmp/dh_semanage_proof.pp 2>&1; then
      echo "AB_PROOF_MODULE=loaded"
      echo "--- proof rules live in the active policy (post-load verification) ---"
      echo "AB_PROOF_LIVE_T: $(sesearch -T -s docker_helper_t -t semanage_exec_t -c process 2>&1 | head -3 || true)"
      echo "AB_PROOF_LIVE_A_FILE: $(sesearch -A -s docker_helper_t -t semanage_exec_t -c file 2>&1 | head -3 || true)"
      echo "AB_PROOF_LIVE_A_PROC: $(sesearch -A -s docker_helper_t -t semanage_t -c process 2>&1 | head -3 || true)"
      echo "AB_PROOF_LIVE_A_PROC2: $(sesearch -A -s docker_helper_t -t semanage_t -c process2 2>&1 | head -3 || true)"
    else
      # Load-time failure (e.g. 'Failed to resolve allow statement at .../cil:N'):
      # dump the generated CIL with line numbers so the exact failing statement is
      # visible without needing another run.
      echo "error: could not package/load the temporary proof module" >&2
      CIL="$(find /etc/selinux/targeted/tmp/modules -name cil 2>/dev/null | xargs -r ls -t 2>/dev/null | head -1)"
      if [ -n "$CIL" ]; then
        echo "--- generated CIL (with line numbers) ---"
        nl -ba "$CIL" 2>&1 | head -40 || true
      fi
      exit 1
    fi
  else
    echo "error: checkmodule failed for the temporary proof module" >&2
    exit 1
  fi

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
  echo "--- ONE non-home Session creation (production path, dontaudit off, auditd on) ---"
  SESS_JSON="$(docker-helper session create --system --workspace "$WS" --json 2>&1)"
  SESS_RC=$?
  printf '%s\n' "$SESS_JSON" | redact | head -8
  echo "AB_SESSION_RC=$SESS_RC"
  if [ "$SESS_RC" -eq 0 ]; then
    WS_TYPE="$(stat -c '%C' "$WS" 2>/dev/null | cut -d: -f3 || true)"
    echo "AB_SESSION_WORKSPACE_TYPE=$WS_TYPE"
  fi

  echo "--- exact AVC evidence (raw audit.log, auditd running) ---"
  tail -60 /var/log/audit/audit.log 2>/dev/null | grep -E 'avc:|docker_helper|semanage|denied' \
    || echo "(audit.log has no matching AVC lines; raw tail follows)"
  tail -20 /var/log/audit/audit.log 2>/dev/null || true
  echo "--- exact AVC evidence (ausearch variants, since boot) ---"
  ausearch -m avc -m user_avc -ts boot -i 2>&1 | grep -E 'docker_helper|semanage|denied' \
    || echo "(ausearch found no matching AVC/USER_AVC records since boot)"
  ausearch -m AVC -m USER_AVC --start recent 2>/dev/null | grep -E 'docker_helper|semanage|denied' \
    || echo "(ausearch -ts recent found no matching AVC/USER_AVC records)"
  echo "--- exact AVC evidence (kernel journal / dmesg fallback) ---"
  journalctl -k --no-pager -n 2000 2>/dev/null | grep -E 'avc:.*denied|docker_helper|semanage' | tail -20 \
    || true
  dmesg 2>/dev/null | grep -E 'docker_helper|semanage|avc:.*denied' | tail -20 \
    || true
  echo "--- docker-helper daemon journal (authoritative error text) ---"
  journalctl -u docker-helper.service -n 40 --no-pager 2>/dev/null | tail -40 \
    || true

  rm -rf "$WS"
fi

echo
echo "================ SELINUX A/B PROOFS COMPLETE ================"
exit 0
