#!/usr/bin/env bash
#
# uat-regression-runtime-dir-socket-replacement.sh — RuntimeDirectory socket
# replacement across a real zypper package upgrade and reinstall, observed by a
# long-lived container bind-mounting the runtime directory.
#
# Verifies the shipped systemd contract (RuntimeDirectoryPreserve=restart in
# packaging/systemd/system/docker-helper.service): the /run/docker-helper
# RuntimeDirectory dev:inode survives the package-scriptlet daemon restarts of
# a zypper upgrade and a zypper --force reinstall, the daemon socket file is
# recreated by the new daemon at the same path, and the long-lived container
# holding a bind-mount of /run/docker-helper sees that same new socket.
#
# Mandatory assertions (MUST), per phase (upgrade, reinstall):
#   - candidate package/version installed;
#   - daemon active;
#   - host /health OK (curl over the unix socket, from the host);
#   - RuntimeDirectory dev:inode unchanged on the host;
#   - the container still sees the same RuntimeDirectory dev:inode;
#   - the host socket exists after the scriptlet-driven restart;
#   - the container's socket dev:inode equals the host's (same new socket).
#
# Evidence only (recorded, never required to change):
#   - socket dev:inode before/after;
#   - daemon MainPID before/after;
#   - systemd InvocationID before/after.
# A changed socket inode or MainPID is NOT a pass condition: a same-inode or
# same-PID restart does not violate the RuntimeDirectory contract.
#
# The consumer is NOT required to run curl: for the container the socket is
# only proven with stat (dev:inode equality); /health is a host check.
#
# Diagnostic (non-verdict, never fails the regression): a second container
# bind-mounting the socket FILE itself records what a stale file-bind consumer
# observes across the replacement. Its observations are recorded as evidence.
#
# The probe containers are plain Docker containers deliberately: the scenario
# subject is the systemd RuntimeDirectory/package interaction, and the bind
# /run/docker-helper:/run/docker-helper is not expressible through the
# docker-helper Session mount model (workspace-relative sources only).
#
# Sequence (run as root; the script establishes its own v2.0.0 baseline):
#   0. clean-slate reset; zypper install of the v2.0.0 baseline RPM; init;
#      enable --now; baseline recorded (versions, inodes, MainPID,
#      InvocationID); both consumers started (directory bind + file-bind
#      diagnostic);
#   1. `zypper install <candidate.rpm>`: MUST set above;
#   2. `zypper install --force <candidate.rpm>`: same MUST set.
#
# Env inputs:
#   UAT_RPM                candidate RPM path inside the guest (required)
#   UAT_RPM_SHA256         expected candidate SHA-256 (optional; verified when set)
#   UAT_BASELINE_RPM       v2.0.0 baseline RPM path (default
#                          /opt/uat-import/docker-helper-baseline.rpm)
#   UAT_BASELINE_SHA256    expected baseline SHA-256 (optional; verified when set)
#   UAT_VERSION            candidate version string (default 2.1.0-uat)
#   UAT_BASELINE_VERSION   baseline version string (default 2.0.0)
#   UAT_ALLOWED_ROOT       global allowed root for baseline init (default /home)
#   UAT_IMAGE              consumer image (default alpine:3.24, the image the
#                          black-box UAT already pulls in the guest)
#
# Requires: root, zypper, rpm, docker, systemctl, curl on the host.
# Exit 0 = PASS, 1 = FAIL, 2 = BLOCKED.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "RuntimeDirectory socket replacement across zypper upgrade/reinstall"

reg_require_root
reg_require_cmd zypper
reg_require_cmd rpm
reg_require_cmd docker
reg_require_cmd systemctl
reg_require_cmd curl
reg_require_docker

CANDIDATE_RPM="${UAT_RPM:-}"
CANDIDATE_SHA256="${UAT_RPM_SHA256:-}"
BASELINE_RPM="${UAT_BASELINE_RPM:-/opt/uat-import/docker-helper-baseline.rpm}"
BASELINE_SHA256="${UAT_BASELINE_SHA256:-}"
VERSION="${UAT_VERSION:-2.1.0-uat}"
BASELINE_VERSION="${UAT_BASELINE_VERSION:-2.0.0}"
ALLOWED_ROOT="${UAT_ALLOWED_ROOT:-/home}"
IMAGE="${UAT_IMAGE:-alpine:3.24}"
DIR_CONTAINER="dh-runtime-dir-reg"
FILE_CONTAINER="dh-runtime-dir-sockbind-diag"
RUNTIME_DIR="/run/docker-helper"
SOCK="$RUNTIME_DIR/docker-helper.sock"
SERVICE="docker-helper.service"

# --- artifact preflight -------------------------------------------------------
[ -n "$CANDIDATE_RPM" ] || reg_blocked "UAT_RPM is required (candidate RPM path inside the guest)"
[ -f "$CANDIDATE_RPM" ] || reg_blocked "candidate RPM not found: $CANDIDATE_RPM"
[ -f "$BASELINE_RPM" ] || reg_blocked "baseline RPM not found: $BASELINE_RPM (v2.0.0 baseline fixture required)"
CANDIDATE_RPM="$(readlink -f "$CANDIDATE_RPM")"
BASELINE_RPM="$(readlink -f "$BASELINE_RPM")"
if [ -n "$CANDIDATE_SHA256" ]; then
  ACTUAL="$(sha256sum "$CANDIDATE_RPM" | awk '{print $1}')"
  [ "$ACTUAL" = "$CANDIDATE_SHA256" ] || reg_blocked "candidate RPM SHA-256 mismatch (expected $CANDIDATE_SHA256, got $ACTUAL)"
  reg_ok "candidate RPM byte identity verified"
fi
if [ -n "$BASELINE_SHA256" ]; then
  ACTUAL="$(sha256sum "$BASELINE_RPM" | awk '{print $1}')"
  [ "$ACTUAL" = "$BASELINE_SHA256" ] || reg_blocked "baseline RPM SHA-256 mismatch (expected $BASELINE_SHA256, got $ACTUAL)"
  reg_ok "baseline RPM byte identity verified"
fi
CANDIDATE_VR="$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$CANDIDATE_RPM" 2>/dev/null)" \
  || reg_blocked "cannot read candidate RPM version: $CANDIDATE_RPM"
BASELINE_VR="$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$BASELINE_RPM" 2>/dev/null)" \
  || reg_blocked "cannot read baseline RPM version: $BASELINE_RPM"
reg_info "candidate RPM: $CANDIDATE_RPM (version-release $CANDIDATE_VR)"
reg_info "baseline RPM:  $BASELINE_RPM (version-release $BASELINE_VR)"

ZYPPER_LOG="/tmp/uat-runtime-dir-zypper.log"
ZYPPER() { timeout 600 zypper --non-interactive --allow-unsigned-rpm "$@" >"$ZYPPER_LOG" 2>&1; }
zypper_tail() { head -8 "$ZYPPER_LOG" 2>/dev/null | redact | tr '\n' ' '; }

installed_vr() { rpm -q --qf '%{VERSION}-%{RELEASE}' docker-helper 2>/dev/null; }
binary_version() { /usr/bin/docker-helper version 2>/dev/null; }
main_pid() { systemctl show -p MainPID --value "$SERVICE" 2>/dev/null; }
invocation_id() { systemctl show -p InvocationID --value "$SERVICE" 2>/dev/null; }

# inode_where HOST_OR_CONTAINER PATH: dev:inode of PATH as seen from the host
# or from inside the directory-bind consumer; "absent" when unavailable.
inode_where() {
  local where="$1" path="$2" out
  if [ "$where" = container ]; then
    out="$(docker exec "$DIR_CONTAINER" stat -c '%d:%i' "$path" 2>/dev/null)" || out="absent"
  else
    out="$(stat -c '%d:%i' "$path" 2>/dev/null)" || out="absent"
  fi
  printf '%s' "$out"
}

# wait_service_health: bounded wait for an active daemon + host /health.
wait_service_health() {
  for _ in $(seq 1 60); do
    if systemctl is-active --quiet "$SERVICE" 2>/dev/null \
        && curl --silent --fail --max-time 1 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# record_evidence LABEL: one evidence line for the observable daemon/socket
# state (never a verdict).
record_evidence() {
  local label="$1" sock pid inv
  sock="$(inode_where host "$SOCK")"
  pid="$(main_pid)"
  inv="$(invocation_id)"
  reg_info "evidence [$label]: socket dev:inode=$sock MainPID=${pid:-unknown} InvocationID=${inv:-unknown}"
}

# verify_phase LABEL: the mandatory post-operation assertion set shared by
# both phases (MUST contract above; socket/MainPID/InvocationID changes are
# evidence, not pass conditions).
verify_phase() {
  local label="$1" vr ver dir dir_c sock sock_c

  vr="$(installed_vr)"
  if [ "$vr" = "$CANDIDATE_VR" ]; then
    reg_ok "$label: candidate installed (rpm version-release $vr)"
  else
    reg_fail "$label: installed version-release '$vr' is not the candidate '$CANDIDATE_VR'"
  fi
  ver="$(binary_version)"
  if [ "$ver" = "$VERSION" ]; then
    reg_ok "$label: candidate binary version installed ($ver)"
  else
    reg_fail "$label: installed binary version is not $VERSION: ${ver:-unknown}"
  fi

  if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
    reg_ok "$label: daemon active"
  else
    reg_fail "$label: $SERVICE not active after $label"
  fi
  if curl --silent --fail --max-time 1 --unix-socket "$SOCK" http://localhost/health >/dev/null 2>&1; then
    reg_ok "$label: host /health OK"
  else
    reg_fail "$label: host /health check failed"
  fi

  dir="$(inode_where host "$RUNTIME_DIR")"
  if [ "$dir" = "$DIR_INODE_BASE" ]; then
    reg_ok "$label: RuntimeDirectory dev:inode preserved on host ($dir)"
  else
    reg_fail "$label: RuntimeDirectory dev:inode changed on host: before $DIR_INODE_BASE, after ${dir:-absent}"
  fi
  dir_c="$(inode_where container "$RUNTIME_DIR")"
  if [ "$dir_c" = "$DIR_INODE_BASE" ] && [ "$dir_c" = "$dir" ]; then
    reg_ok "$label: container sees the same preserved RuntimeDirectory ($dir_c)"
  else
    reg_fail "$label: container RuntimeDirectory view wrong (container ${dir_c:-absent}, host ${dir:-absent}, baseline $DIR_INODE_BASE)"
  fi

  sock="$(inode_where host "$SOCK")"
  if [ "$sock" != absent ] && [ -S "$SOCK" ]; then
    reg_ok "$label: host socket exists after the scriptlet-driven restart ($sock)"
  else
    reg_fail "$label: host socket missing after restart ($SOCK)"
  fi
  sock_c="$(inode_where container "$SOCK")"
  if [ "$sock_c" != absent ] && [ "$sock_c" = "$sock" ]; then
    reg_ok "$label: container sees the same new socket as the host ($sock_c)"
  else
    reg_fail "$label: container socket view wrong (container ${sock_c:-absent}, host ${sock:-absent})"
  fi

  # Evidence only: whether the socket inode / MainPID / InvocationID changed.
  if [ "$sock" != absent ] && [ "$sock" != "$SOCK_INODE_PREV" ]; then
    reg_info "evidence [$label]: socket inode changed ($SOCK_INODE_PREV -> $sock)"
  else
    reg_info "evidence [$label]: socket inode unchanged ($sock)"
  fi
  local pid pid_prev inv inv_prev
  pid="$(main_pid)"; inv="$(invocation_id)"
  pid_prev="${PID_PREV:-unknown}"; inv_prev="${INV_PREV:-unknown}"
  if [ -n "$pid" ] && [ "$pid" != "$pid_prev" ]; then
    reg_info "evidence [$label]: MainPID changed ($pid_prev -> $pid)"
  else
    reg_info "evidence [$label]: MainPID unchanged (${pid:-unknown})"
  fi
  if [ -n "$inv" ] && [ "$inv" != "$inv_prev" ]; then
    reg_info "evidence [$label]: InvocationID changed ($inv_prev -> $inv)"
  else
    reg_info "evidence [$label]: InvocationID unchanged (${inv:-unknown})"
  fi
  PID_PREV="$pid"; INV_PREV="$inv"; SOCK_INODE_PREV="$sock"

  # Non-verdict diagnostic: what the stale file-bind consumer observes.
  local diag_sock
  diag_sock="$(docker exec "$FILE_CONTAINER" stat -c '%d:%i' "$SOCK" 2>/dev/null)" || diag_sock="absent"
  if [ "$diag_sock" = "$sock" ]; then
    reg_info "diagnostic [$label]: file-bind consumer sees the NEW socket ($diag_sock)"
  else
    reg_info "diagnostic [$label]: file-bind consumer went stale (observed $diag_sock, live socket $sock) — expected for a file bind"
  fi
}

# --- cleanup -------------------------------------------------------------------
cleanup() {
  docker rm -f "$DIR_CONTAINER" "$FILE_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- 0. reset + zypper baseline install + consumers -----------------------------
systemctl stop "$SERVICE" >/dev/null 2>&1 || true
systemctl disable "$SERVICE" >/dev/null 2>&1 || true
rpm -e docker-helper >/dev/null 2>&1 || true
rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper

echo "--- phase 0: zypper install v2.0.0 baseline ---"
if ! ZYPPER install "$BASELINE_RPM"; then
  reg_fail "zypper baseline install failed: $(zypper_tail)"
  reg_result
fi
if [ "$(installed_vr)" = "$BASELINE_VR" ]; then
  reg_ok "baseline installed via zypper (version-release $BASELINE_VR)"
else
  reg_fail "baseline version-release after install is '$(installed_vr)', expected $BASELINE_VR"
fi
if [ "$(binary_version)" = "$BASELINE_VERSION" ]; then
  reg_ok "baseline binary version installed ($BASELINE_VERSION)"
else
  reg_fail "baseline binary version is not $BASELINE_VERSION: $(binary_version)"
fi

INIT_OUT="$(/usr/bin/docker-helper init --allowed-root "$ALLOWED_ROOT" 2>&1)" || {
  printf '%s\n' "$INIT_OUT" | redact >&2
  reg_fail "docker-helper init on baseline failed"
  reg_result
}
reg_ok "system init on v2.0.0 baseline"
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable --now "$SERVICE" >/dev/null 2>&1 || true
if wait_service_health; then
  reg_ok "baseline daemon active and healthy"
else
  reg_fail "baseline daemon not active/healthy"
  reg_result
fi

docker rm -f "$DIR_CONTAINER" "$FILE_CONTAINER" >/dev/null 2>&1 || true
if ! docker run -d --name "$DIR_CONTAINER" -v "$RUNTIME_DIR:$RUNTIME_DIR" "$IMAGE" \
    sleep infinity >/dev/null 2>&1; then
  reg_blocked "cannot start the directory-bind consumer (image $IMAGE pull/run failed)"
fi
if ! docker run -d --name "$FILE_CONTAINER" -v "$SOCK:$SOCK" "$IMAGE" \
    sleep infinity >/dev/null 2>&1; then
  reg_blocked "cannot start the file-bind diagnostic consumer (image $IMAGE pull/run failed)"
fi
for _ in $(seq 1 15); do
  [ "$(docker inspect -f '{{.State.Running}}' "$DIR_CONTAINER" 2>/dev/null)" = "true" ] \
    && [ "$(docker inspect -f '{{.State.Running}}' "$FILE_CONTAINER" 2>/dev/null)" = "true" ] && break
  sleep 1
done
if [ "$(docker inspect -f '{{.State.Running}}' "$DIR_CONTAINER" 2>/dev/null)" = "true" ] \
    && [ "$(docker inspect -f '{{.State.Running}}' "$FILE_CONTAINER" 2>/dev/null)" = "true" ]; then
  reg_ok "long-lived consumers running (directory bind $RUNTIME_DIR:$RUNTIME_DIR; file-bind diagnostic $SOCK)"
else
  reg_fail "one or more consumers are not running"
  reg_result
fi

# Baseline records (host + container views).
DIR_INODE_BASE="$(inode_where host "$RUNTIME_DIR")"
SOCK_INODE_BASE="$(inode_where host "$SOCK")"
SOCK_INODE_PREV="$SOCK_INODE_BASE"
PID_PREV="$(main_pid)"
INV_PREV="$(invocation_id)"
[ -n "$DIR_INODE_BASE" ] || { reg_fail "cannot stat host RuntimeDirectory"; reg_result; }
[ "$SOCK_INODE_BASE" != absent ] || { reg_fail "daemon socket missing at $SOCK"; reg_result; }
[ -n "$PID_PREV" ] && [ "$PID_PREV" != "0" ] || { reg_fail "cannot determine baseline daemon MainPID"; reg_result; }

DIR_C="$(inode_where container "$RUNTIME_DIR")"
SOCK_C="$(inode_where container "$SOCK")"
if [ "$DIR_C" = "$DIR_INODE_BASE" ]; then
  reg_ok "host and container see one RuntimeDirectory (dev:inode $DIR_INODE_BASE)"
else
  reg_fail "container RuntimeDirectory differs from host (container ${DIR_C:-absent}, host $DIR_INODE_BASE)"
fi
if [ "$SOCK_C" = "$SOCK_INODE_BASE" ]; then
  reg_ok "container sees the host socket through the bind (dev:inode $SOCK_INODE_BASE)"
else
  reg_fail "container socket view differs from host (container ${SOCK_C:-absent}, host $SOCK_INODE_BASE)"
fi
record_evidence "baseline"

# --- 1. zypper install candidate (upgrade) --------------------------------------
echo "--- phase 1: zypper install (baseline -> candidate upgrade) ---"
if ! ZYPPER install "$CANDIDATE_RPM"; then
  reg_fail "zypper candidate install failed: $(zypper_tail)"
  reg_result
fi
if wait_service_health; then
  reg_ok "daemon active and healthy after zypper upgrade"
else
  reg_fail "daemon not active/healthy after zypper upgrade"
fi
verify_phase "upgrade"

# --- 2. zypper install --force (candidate reinstall) -----------------------------
echo "--- phase 2: zypper install --force (candidate reinstall) ---"
if ! ZYPPER install --force "$CANDIDATE_RPM"; then
  reg_fail "zypper --force reinstall failed: $(zypper_tail)"
  reg_result
fi
if wait_service_health; then
  reg_ok "daemon active and healthy after zypper --force reinstall"
else
  reg_fail "daemon not active/healthy after zypper --force reinstall"
fi
verify_phase "reinstall"

cleanup
reg_ok "consumer containers removed (candidate left installed)"

reg_result
