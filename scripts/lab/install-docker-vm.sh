#!/usr/bin/env bash
#
# install-docker-vm.sh — install and verify Docker INSIDE the lab VM through
# the native openSUSE package manager.
#
# Run as root in the guest, during the temporary ONLINE provisioning window
# (the packages must be downloadable). The lab-VM guard refuses to run
# anywhere but the disposable lab VM, and it runs before any state change.
#
# Package signatures stay verified: this script deliberately does NOT pass
# --no-gpg-checks to zypper. The openSUSE repositories configured in the
# guest carry their signing keys out of the box.
#
# UAT Corrective 1: the installation is SELinux-aware and idempotent. The
# installed binary may carry a stale label (bin_t) until a restorecon is run,
# and a daemon started from a mislabeled binary runs in the wrong domain
# (unconfined_service_t). The verified event order is:
#
#   install package
#   → restore the dockerd executable label (restorecon; verify the type)
#   → restart docker (skipped only when nothing needed fixing)
#   → restore the socket label
#   → verify executable / socket / process labels
#   → verify the Docker Engine
#
# Every SELinux verification is fail-closed: a label that stays wrong after
# restorecon, an unusable MainPID, a process outside container_runtime_t, a
# missing socket or an unaccepted socket type all abort the provisioning.
#
# Idempotent: re-running on a correct system verifies and exits 0 without
# reinstalling packages and without restarting the service.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { printf '[install-docker-vm] %s\n' "$*"; }
die() { printf '[install-docker-vm] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root in the guest (sudo bash $0)"

# --- lab-VM guard (fail closed on the physical host; before ANY mutation) ---
# shellcheck source=lab-vm-guard.sh
. "$SCRIPT_DIR/lab-vm-guard.sh"
require_lab_vm

command -v zypper >/dev/null 2>&1 || die "zypper not found"
command -v systemctl >/dev/null 2>&1 || die "systemctl not found"
[ "$(cat /sys/fs/selinux/enforce 2>/dev/null || echo 0)" = 1 ] || die "SELinux is not enforcing"
# The Docker socket path is a documented override (test harness; some setups
# relocate it). The default is the standard rootful daemon path.
DOCKER_SOCK="${DOCKER_SOCK:-/run/docker.sock}"

# The expected SELinux types. container_var_run_t is the type the installed
# policy assigns to the rootful docker socket on openSUSE; docker_var_run_t
# is accepted as the equivalent type shipped by container-selinux variants.
# The unqualified var_run_t is the UNLABELED default and is exactly the
# broken state this installer must repair, so it is never accepted.
DOCKERD_TYPE="container_runtime_exec_t"
SOCKET_TYPES="container_var_run_t|docker_var_run_t"

# F1: the dockerd executable must exist, be executable and carry
# container_runtime_exec_t. A wrong or unknown label is repaired with the
# standard restorecon and re-verified; restorecon is never replaced by chcon
# and the SELinux policy itself is never modified. Sets BIN_REPAIRED=yes when
# a repair was needed (the running daemon then needs a restart to enter the
# correct domain).
BIN_REPAIRED=no
restore_bin_label() { # -> 0 when the dockerd binary label is verified
  local bin
  bin="$(readlink -f "$(command -v dockerd 2>/dev/null || true)" 2>/dev/null || true)"
  [ -n "$bin" ] || die "the dockerd binary was not found after the Docker install"
  [ -f "$bin" ] || die "the dockerd path is not a regular file: $bin"
  [ -x "$bin" ] || die "the dockerd path is not executable: $bin"
  local ctx
  ctx="$(stat -c '%C' "$bin" 2>/dev/null || echo unknown)"
  case "$ctx" in
    *"$DOCKERD_TYPE"*) log "dockerd SELinux context: $ctx (already correct)" ; return 0 ;;
    unknown) die "the dockerd SELinux context could not be read: $bin" ;;
  esac
  command -v restorecon >/dev/null 2>&1 \
    || die "restorecon is not available (policycoreutils required)"
  log "dockerd label is $ctx; restoring with restorecon"
  restorecon -v "$bin" || die "restorecon failed for the dockerd binary: $bin"
  ctx="$(stat -c '%C' "$bin" 2>/dev/null || echo unknown)"
  case "$ctx" in
    *"$DOCKERD_TYPE"*) log "dockerd SELinux context: $ctx" ; BIN_REPAIRED=yes ;;
    *) die "the dockerd label is still wrong after restorecon: $ctx" ;;
  esac
  return 0
}

# F2: the dockerd process must run in container_runtime_t. The PID comes from
# systemctl show (authoritative), must be a positive integer, and the label is
# read through ps. unconfined_service_t is never accepted.
dockerd_process_label() { # -> 0 when the running daemon is in the right domain
  local pid ctx
  pid="$(systemctl show -p MainPID --value docker.service 2>/dev/null || true)"
  case "$pid" in
    ''|0|*[!0-9]*) die "docker.service reports no usable MainPID (got '$pid')" ;;
  esac
  ctx="$(ps -o label= -p "$pid" 2>/dev/null || echo unknown)"
  case "$ctx" in
    *container_runtime_t*) log "dockerd process domain: $ctx (pid $pid)" ;;
    unknown|*) die "dockerd is not running in container_runtime_t (pid $pid: ${ctx:-unknown})" ;;
  esac
  return 0
}

# The service is started or restarted only when it is not already in the
# correct state: a running daemon in the right domain on a correctly labeled
# binary needs no restart (idempotent re-run).
start_service() { # $1 = whether the binary label needed a repair
  local needed_restart="$1" pid ctx
  systemctl enable docker >/dev/null 2>&1 || true
  if [ "$needed_restart" = no ]; then
    pid="$(systemctl show -p MainPID --value docker.service 2>/dev/null || true)"
    if [ -n "$pid" ] && [ "$pid" != 0 ]; then
      ctx="$(ps -o label= -p "$pid" 2>/dev/null || echo unknown)"
      case "$ctx" in
        *container_runtime_t*) log "docker.service already running in container_runtime_t: no restart needed"; return 0 ;;
      esac
    fi
  fi
  systemctl restart docker || die "could not start docker.service"
  systemctl is-active --quiet docker || die "docker.service is not active"
  dockerd_process_label
  return 0
}

# F3: the socket must exist, and its label must be a justified docker socket
# type. DAC ownership and permissions are never modified.
restore_sock_label() { # -> 0 when the socket label is verified
  [ -S "$DOCKER_SOCK" ] || die "docker socket missing at $DOCKER_SOCK"
  local ctx
  ctx="$(stat -c '%C' "$DOCKER_SOCK" 2>/dev/null || echo unknown)"
  case "$ctx" in
    unknown) die "the docker socket SELinux context could not be read: $DOCKER_SOCK" ;;
  esac
  if printf '%s' "$ctx" | grep -Eq "$SOCKET_TYPES"; then
    log "docker socket SELinux context: $ctx (already correct)"
    return 0
  fi
  command -v restorecon >/dev/null 2>&1 \
    || die "restorecon is not available (policycoreutils required)"
  log "docker socket label is $ctx; restoring with restorecon"
  restorecon -v "$DOCKER_SOCK" || die "restorecon failed for the docker socket: $DOCKER_SOCK"
  ctx="$(stat -c '%C' "$DOCKER_SOCK" 2>/dev/null || echo unknown)"
  if printf '%s' "$ctx" | grep -Eq "$SOCKET_TYPES"; then
    log "docker socket SELinux context: $ctx"
  else
    die "the docker socket label is still wrong after restorecon: $ctx"
  fi
  return 0
}

# --- install (signature-checked) --------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  log "installing Docker (package signatures verified by zypper)"
  zypper --non-interactive install docker || die "zypper install docker failed"
else
  log "docker already installed: $(docker --version 2>/dev/null || echo unknown)"
fi

# --- F1: repair and verify the executable label ------------------------------
restore_bin_label

# --- F2: start the service and verify the process domain ----------------------
start_service "$BIN_REPAIRED"

# --- F3: repair and verify the socket label -----------------------------------
restore_sock_label

# --- final verification --------------------------------------------------------
docker_version="$(docker version --format '{{.Server.Version}}' 2>/dev/null)" \
  || die "docker version failed"
log "docker server version: $docker_version"
docker info >/dev/null 2>&1 || die "docker info failed"

systemctl is-enabled --quiet docker || die "docker.service is not enabled"

getent group docker >/dev/null 2>&1 || die "the docker group is missing (package install broken?)"

log "done: docker $docker_version active, socket present, SELinux labels verified"
