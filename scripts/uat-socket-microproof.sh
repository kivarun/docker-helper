#!/usr/bin/env bash
#
# uat-socket-microproof.sh — Phase A2 bounded diagnostic for the docker socket
# blocker on the Tumbleweed / RPM / SELinux profile. Runs INSIDE the guest as
# root.
#
# After the A1 exec fix the production pull reaches the Docker CLI and fails
# connecting to the Docker API socket:
#   permission denied while trying to connect to the docker API at
#   unix:///var/run/docker.sock
# The shipped policy expects docker_helper_t -> container_var_run_t:sock_file
# and docker_helper_t -> container_runtime_t:unix_stream_socket. This ONE
# bounded experiment observes the ACTUAL system types and any AVC, with
# dontaudit disabled so denials are logged.
#
# It ALWAYS restores dontaudit behavior (semodule -B) even if the pull fails.
#
# Output fields (labeled):
#   MICROPROOF_SOCKET_REALPATH=  MICROPROOF_SOCKET_CONTEXT=
#   MICROPROOF_SOCKET_MATCHPATHCON=  MICROPROOF_DOCKERD_CONTEXT=
#   MICROPROOF_PULL_RC=  MICROPROOF_AVC=  (complete records)
#
# Exit 0 even when the pull fails (this is evidence collection, not a pass/fail
# gate); nonzero only on harness failure.

set -uo pipefail

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }
for t in semodule ausearch; do
  command -v "$t" >/dev/null 2>&1 || { echo "error: $t not found" >&2; exit 1; }
done

restore_dontaudit() {
  echo "MICROPROOF restoring dontaudit: semodule -B"
  semodule -B 2>&1 || echo "warning: semodule -B failed (dontaudit may remain disabled)"
}
trap restore_dontaudit EXIT

echo "===== DOCKER SOCKET MICRO-PROOF ====="

# --- 1. socket + dockerd types ------------------------------------------------
echo "MICROPROOF_SOCKET_REALPATH=$(readlink -f /var/run/docker.sock 2>/dev/null || true)"
ls -lZ /var/run/docker.sock 2>&1 || true
ls -lZ /run/docker.sock 2>/dev/null || true
matchpathcon /run/docker.sock 2>/dev/null || true
matchpathcon /var/run/docker.sock 2>/dev/null || true

DOCKERD_PID="$(pidof dockerd 2>/dev/null || true)"
if [ -n "$DOCKERD_PID" ]; then
  printf 'MICROPROOF_DOCKERD_CONTEXT='
  cat "/proc/$DOCKERD_PID/attr/current" 2>/dev/null || true
  echo
  echo "--- ps -Z -p $DOCKERD_PID ---"
  ps -Z -p "$DOCKERD_PID" 2>&1 || true
else
  echo "MICROPROOF_DOCKERD_CONTEXT=(dockerd not running / pidof empty)"
fi

# --- 2. disable dontaudit so the diagnostic pull logs AVCs ---------------------
echo "MICROPROOF disable dontaudit: semodule -DB"
semodule -DB 2>&1 || { echo "error: semodule -DB failed" >&2; exit 1; }

# --- 3. ensure a valid admin session -------------------------------------------
echo "MICROPROOF ensure service + session"
systemctl enable --now docker-helper.service >/dev/null 2>&1 || true
for _ in $(seq 1 60); do
  systemctl is-active --quiet docker-helper.service && break
  sleep 1
done
systemctl is-active --quiet docker-helper.service || { echo "error: service not active" >&2; exit 1; }

docker-helper principal create --system opc >/dev/null 2>&1 || true
docker-helper principal allowed-root add --system opc /home/opc >/dev/null 2>&1 || true
mkdir -p /home/opc/uat-workspace
SESSION_JSON="$(docker-helper session create --system --workspace /home/opc/uat-workspace --json 2>&1 || true)"
TOKEN="$(printf '%s\n' "$SESSION_JSON" | grep -oP '"token": "\K[^"]+' | head -1)"
if [ -z "$TOKEN" ]; then
  echo "MICROPROOF_SESSION_CREATED=no"
  printf '%s\n' "$SESSION_JSON" | sed -E 's/dht_[A-Za-z0-9_-]+/<redacted>/g'
  exit 0
fi
echo "MICROPROOF_SESSION_CREATED=yes"

# --- 4. one diagnostic pull (dontaudit disabled) --------------------------------
export DOCKER_HELPER_SESSION_TOKEN="$TOKEN"
echo "MICROPROOF pull alpine:3.24 (dontaudit disabled)"
PULL_OUT="$(docker-helper pull alpine:3.24 2>&1 | sed -E 's/dht_[A-Za-z0-9_-]+/<redacted>/g' || true)"
PULL_RC=$?
printf '%s\n' "$PULL_OUT" | tail -20
echo "MICROPROOF_PULL_RC=$PULL_RC"

# --- 5. capture the complete relevant AVC records -------------------------------
echo "MICROPROOF AVC capture (ausearch --start recent):"
ausearch -m AVC -m USER_AVC --start recent 2>/dev/null | grep -E 'docker_helper|container_runtime|container_var_run|docker' || {
  echo "(ausearch found no matching AVC/USER_AVC records, or auditd is not logging them)"
}
echo "MICROPROOF_DONE"

# trap restores dontaudit
exit 0
