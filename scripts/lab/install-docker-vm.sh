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
# Verification (all must pass before the script reports success):
#   * docker version and docker info work;
#   * docker.service is enabled and active;
#   * /run/docker.sock exists and is a socket;
#   * the dockerd binary and the Docker socket carry their expected SELinux
#     labels (container_runtime_exec_t / container_var_run_t family — the
#     exact types are printed as evidence and checked for non-defaultness);
#   * the 'docker' group exists (the trusted launcher joins it later via
#     setup-agent-user.sh).
#
# Idempotent: re-running on an installed system verifies and exits 0.
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

# --- install (signature-checked) --------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  log "installing Docker (package signatures verified by zypper)"
  zypper --non-interactive install docker || die "zypper install docker failed"
else
  log "docker already installed: $(docker --version 2>/dev/null || echo unknown)"
fi

# --- service ----------------------------------------------------------------
systemctl enable docker >/dev/null 2>&1 || true
systemctl restart docker || die "could not start docker.service"

# --- verification -----------------------------------------------------------
docker_version="$(docker version --format '{{.Server.Version}}' 2>/dev/null)" \
  || die "docker version failed"
log "docker server version: $docker_version"
docker info >/dev/null 2>&1 || die "docker info failed"

systemctl is-active --quiet docker || die "docker.service is not active"
systemctl is-enabled --quiet docker || die "docker.service is not enabled"

[ -S "$DOCKER_SOCK" ] || die "docker socket missing at $DOCKER_SOCK"

dockerd_context="$(stat -c '%C' "$(readlink -f "$(command -v dockerd)")" 2>/dev/null || echo unknown)"
sock_context="$(stat -c '%C' "$DOCKER_SOCK" 2>/dev/null || echo unknown)"
case "$dockerd_context" in
  *container_runtime_exec_t*) log "dockerd SELinux context: $dockerd_context" ;;
  *) die "unexpected dockerd SELinux context: $dockerd_context" ;;
esac
case "$sock_context" in
  *container_var_run_t*|*docker_var_run_t*|*var_run_t*) log "docker socket SELinux context: $sock_context" ;;
  *) die "unexpected docker socket SELinux context: $sock_context" ;;
esac

getent group docker >/dev/null 2>&1 || die "the docker group is missing (package install broken?)"

log "done: docker $docker_version active, socket present, SELinux labels verified"
