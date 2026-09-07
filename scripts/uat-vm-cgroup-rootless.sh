#!/usr/bin/env bash
#
# uat-vm-cgroup-rootless.sh — run the Release 3 ROOTLESS/USER-mode
# aggregate-cgroup feasibility gate inside a real Ubuntu 24.04 VM booted on a
# GitHub-hosted ubuntu-24.04 runner (QEMU/KVM).
#
# Responsibility boundary (mirrors scripts/uat-vm-cgroup-system.sh):
#
#   host workflow (release3-phase0-gates.yml)
#       |  (this file: cgroup-gate orchestration ONLY)
#       v
#   Ubuntu VM harness       (scripts/uat-vm-ubuntu.sh, sourced below)
#       |  image + checksum, qcow overlay + resize, KVM/TCG selection,
#       |  cloud-init NoCloud seed, unattended boot, vm_ssh/vm_scp transport,
#       |  wait-for-SSH, serial-log diagnostics
#       v
#   guest bootstrap + feasibility harness
#       (official supported rootless Docker installation per
#        docs.docker.com/engine/security/rootless, then
#        scripts/cgroup-feasibility-rootless.sh inside the guest)
#
# The guest environment is a NORMALLY CONFIGURED SUPPORTED rootless Docker
# deployment: docker-ce-rootless-extras installed from the Docker deb
# repository (which also ships the Ubuntu 24.04 AppArmor rootlesskit userns
# profile through the distro apparmor package — no manual sysctl or policy
# workarounds), the rootful system daemon disabled per the official rootless
# instructions, a dedicated user with subordinate IDs and linger, the daemon
# configured through the documented ~/.config/docker/daemon.json path, and
# `dockerd-rootless-setuptool.sh install` run as that user in a real login
# session. Nothing is repaired, emulated, or replaced at runtime.
#
# This file does not reimplement VM mechanics or cgroup semantics: the VM is
# the existing canonical harness, and the cgroup evidence is owned by
# scripts/cgroup-feasibility-rootless.sh, whose verbatim output is the
# recorded gate evidence.
#
# Env inputs:
#   UAT_REPO_DIR   host checkout of docker-helper (default: repo root)
#   UAT_KEEP       keep the VM/workdir on failure for debugging
#
# Exit 0 = the rootless-mode cgroup feasibility gate passed inside the VM.
# Nonzero = failed; serial tail + guest evidence are printed.

set -euo pipefail

PREFIX="[cgroup-rootless-vm]"
log()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"

[ -f "$UAT_REPO_DIR/scripts/uat-vm-ubuntu.sh" ] \
  || fail "UAT_REPO_DIR has no scripts/uat-vm-ubuntu.sh: $UAT_REPO_DIR"
[ -f "$UAT_REPO_DIR/scripts/cgroup-feasibility-rootless.sh" ] \
  || fail "UAT_REPO_DIR has no scripts/cgroup-feasibility-rootless.sh"

# ---------------------------------------------------------------------------
# canonical Ubuntu VM harness (VM mechanics; no cgroup/docker knowledge)
# ---------------------------------------------------------------------------
# shellcheck source=scripts/uat-vm-ubuntu.sh
source "$SCRIPT_DIR/uat-vm-ubuntu.sh"

T0="$(date +%s)"

ERR_HANDLED=0
on_err() {
  [ "$ERR_HANDLED" = 1 ] && return 0
  ERR_HANDLED=1
  echo
  echo "================ HARNESS FAILURE DIAGNOSTICS ==============="
  vm_serial_tail
  if vm_ssh true 2>/dev/null; then
    vm_ssh 'cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null; ls /sys/fs/cgroup 2>/dev/null | head; systemctl is-active user@$(id -u fea-su) 2>/dev/null; sudo ls -l /run/user/$(id -u fea-su)/docker.sock 2>/dev/null' || true
  else
    echo "(guest not SSH-reachable)"
  fi
  echo "============================================================"
}
trap on_err ERR

# ---------------------------------------------------------------------------
# 1. start the Ubuntu VM through the common harness
# ---------------------------------------------------------------------------
log "== 1. start Ubuntu 24.04 VM through common harness =="
vm_init

# ---------------------------------------------------------------------------
# 2. guest bootstrap: the official supported rootless Docker installation
# ---------------------------------------------------------------------------
log "== 2. guest bootstrap (official rootless Docker installation) =="
BOOTSTRAP="$(vm_ssh 'sudo bash -s' <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive
log(){ echo "[vm] $*"; }

# Official rootless prerequisites (docs.docker.com/engine/security/rootless).
# apparmor is explicit so the distro-shipped /usr/bin/rootlesskit userns
# profile is present (Ubuntu 24.04 restricts unprivileged user namespaces).
log "installing rootless prerequisites (ca-certificates curl gnupg uidmap dbus-user-session apparmor)"
apt-get update -y || apt-get update -y
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg uidmap dbus-user-session apparmor

# Docker deb repository (noble), official keyring steps.
log "adding the official Docker apt repository (noble)"
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -y || apt-get update -y
log "installing docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-ce-rootless-extras"
apt-get install -y --no-install-recommends \
  docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-ce-rootless-extras
dpkg-query -W -f='FACT: pkg-${Package}=${Version}\n' \
  docker-ce docker-ce-cli containerd.io docker-ce-rootless-extras

# Disable the rootful system daemon (official rootless instruction).
log "disabling the rootful system daemon (docker.service docker.socket)"
systemctl disable --now docker.service docker.socket >/dev/null 2>&1 || true
systemctl is-active --quiet docker.service \
  && { echo "rootful docker.service still active"; exit 1; } || true

# Dedicated feasibility user with the documented subordinate IDs + linger.
id fea-su >/dev/null 2>&1 || useradd -m -s /bin/bash fea-su
grep -q '^feasu:' /etc/subuid 2>/dev/null || echo 'feasu:100000:65536' >> /etc/subuid
grep -q '^feasu:' /etc/subgid 2>/dev/null || echo 'feasu:100000:65536' >> /etc/subgid
loginctl enable-linger fea-su
log "feasibility user fea-su created (subuid/subgid 100000:65536, linger enabled)"

# Daemon configuration through the documented per-user path, before the
# first rootless start, so live-restore is active from the first boot.
install -d -o fea-su -g fea-su -m 0700 /home/feasu/.config/docker
printf '{ "live-restore": true }\n' > /tmp/feasu-daemon.json
install -o fea-su -g fea-su -m 0644 /tmp/feasu-daemon.json \
  /home/feasu/.config/docker/daemon.json
rm -f /tmp/feasu-daemon.json

# Official rootless setup tool, as the user, in a real login session
# (pam_systemd starts the user manager and provides XDG_RUNTIME_DIR).
cat > /tmp/feasu-rootless-install.sh <<'USR'
#!/bin/bash
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "[vm] running dockerd-rootless-setuptool.sh install as $(id -un)"
/usr/bin/dockerd-rootless-setuptool.sh install
echo "[vm] user unit:"
cat ~/.config/systemd/user/docker.service
systemctl --user is-active docker.service || { systemctl --user status docker.service --no-pager || true; exit 1; }
ls -l "$XDG_RUNTIME_DIR/docker.sock"
echo ROOTLESS-INSTALL-DONE
USR
chmod 0755 /tmp/feasu-rootless-install.sh
su -l fea-su -c 'bash /tmp/feasu-rootless-install.sh'
rm -f /tmp/feasu-rootless-install.sh

# Verify the rootless daemon as root through the user socket.
mkdir -p /opt/cg-feas
DOCKERSOCK="/run/user/$(id -u fea-su)/docker.sock"
DOCKER_HOST="unix://$DOCKERSOCK" docker info \
  --format 'FACT: rootless-server={{.ServerVersion}} driver={{.Driver}} cgroup-driver={{.CgroupDriver}} cgroup-version={{.CgroupVersion}} live-restore={{.LiveRestoreEnabled}}'
echo "BOOTSTRAP-DONE"
RMT
)" || true
printf '%s\n' "$BOOTSTRAP"
echo "$BOOTSTRAP" | grep -q "BOOTSTRAP-DONE" || fail "guest bootstrap did not complete"

log "copying the feasibility harness into the guest"
if vm_ssh "sudo tee /opt/cg-feas/cgroup-feasibility-rootless.sh >/dev/null" < "$SCRIPT_DIR/cgroup-feasibility-rootless.sh"; then
  :
else
  EC=$?
  fail "could not transfer the feasibility harness (exit $EC)"
fi
vm_ssh "sudo chmod 0755 /opt/cg-feas/cgroup-feasibility-rootless.sh" || fail "could not mark the harness executable"

# ---------------------------------------------------------------------------
# 3. run the rootless-mode feasibility harness inside the guest
# ---------------------------------------------------------------------------
log "== 3. rootless-mode aggregate cgroup feasibility harness =="
if vm_ssh "sudo bash /opt/cg-feas/cgroup-feasibility-rootless.sh"; then
  :
else
  EC=$?
  vm_serial_tail || true
  fail "rootless-mode cgroup feasibility harness failed (exit $EC)"
fi

# ---------------------------------------------------------------------------
# 4. summary
# ---------------------------------------------------------------------------
T1="$(date +%s)"
TOTAL=$((T1 - T0))
echo
echo "=========== ROOTLESS-MODE CGROUP FEASIBILITY GATE SUMMARY =========="
echo "image:        $VM_IMG_NAME"
echo "image sha256: $VM_IMG_SHA256"
echo "first boot:   ${VM_BOOT_TIME}s to SSH"
echo "accel:        $VM_ACCEL"
echo "total:        ${TOTAL}s"
echo "RESULT: rootless-mode aggregate cgroup feasibility PASSED inside Ubuntu 24.04 VM"
echo "==================================================================="
log "DONE"
