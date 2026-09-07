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
    vm_ssh 'cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null; ls /sys/fs/cgroup 2>/dev/null | head; systemctl is-active user@$(id -u feasu) 2>/dev/null; sudo ls -l /run/user/$(id -u feasu)/docker.sock 2>/dev/null' || true
  else
    echo "(guest not SSH-reachable)"
  fi
  echo "============================================================"
}
trap on_err ERR
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; on_err; exit 1; }

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
id feasu >/dev/null 2>&1 || useradd -m -s /bin/bash feasu
grep -q '^feasu:' /etc/subuid 2>/dev/null || echo 'feasu:100000:65536' >> /etc/subuid
grep -q '^feasu:' /etc/subgid 2>/dev/null || echo 'feasu:100000:65536' >> /etc/subgid
loginctl enable-linger feasu
log "feasibility user feasu created (subuid/subgid 100000:65536, linger enabled)"

# Rootless-prerequisite facts: subordinate-ID state, uid-mapping binaries,
# the distro AppArmor rootlesskit profile, and userns sysctls. This is the
# evidence trail for the recorded gate run.
echo "FACT: subuid=$(tr '\n' ';' < /etc/subuid)"
echo "FACT: subgid=$(tr '\n' ';' < /etc/subgid)"
if command -v getsubids >/dev/null 2>&1; then
  echo "FACT: getsubids-u=$(getsubids feasu 2>&1 || true)"
  echo "FACT: getsubids-g=$(getsubids -g feasu 2>&1 || true)"
else
  echo "FACT: getsubids=absent"
fi
ls -l /usr/bin/rootlesskit /usr/bin/newuidmap /usr/bin/newgidmap /usr/bin/slirp4netns 2>&1 | sed 's/^/FACT: bin /' || true
ls -l /etc/apparmor.d/rootlesskit 2>&1 | sed 's/^/FACT: apparmor-profile /' || true
echo "FACT: apparmor-restrict-unprivileged-userns=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo unknown)"
echo "FACT: user-max-namespaces=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo unknown)"
echo "FACT: kernel=$(uname -r) mem-mb=$(free -m | awk '/^Mem:/{print $2}')"

# Daemon configuration through the documented per-user path, before the
# first rootless start, so live-restore is active from the first boot.
# install -d applies its owner/mode only to the final component, so the
# parent chain is created explicitly to keep it owned by feasu.
install -d -o feasu -g feasu -m 0700 /home/feasu/.config
install -d -o feasu -g feasu -m 0700 /home/feasu/.config/docker
printf '{ "live-restore": true }\n' > /tmp/feasu-daemon.json
install -o feasu -g feasu -m 0644 /tmp/feasu-daemon.json \
  /home/feasu/.config/docker/daemon.json
rm -f /tmp/feasu-daemon.json

# Official rootless setup tool. Invoking it via su/sudo leaves the session
# without XDG_RUNTIME_DIR, so the tool cannot see the user manager; its own
# documented remedy is to log in as the user (ssh works). The key pair below
# gives the bootstrap a real login session (pam_systemd starts the user
# manager and provides XDG_RUNTIME_DIR), and linger keeps that manager
# running afterwards for the gate harness.
cat > /tmp/feasu-rootless-install.sh <<'USR'
#!/bin/bash
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "[vm] env: HOME=$HOME USER=$(id -un) UID=$(id -u) XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-unset}"
echo "[vm] running dockerd-rootless-setuptool.sh install as $(id -un)"
STRC=0
bash -x /usr/bin/dockerd-rootless-setuptool.sh install >/tmp/feasu-setuptool.out 2>&1 || STRC=$?
echo "[vm] setuptool-exit=$STRC"
cat /tmp/feasu-setuptool.out
rm -f /tmp/feasu-setuptool.out
[ "$STRC" = 0 ] || exit "$STRC"
echo "[vm] user unit:"
cat ~/.config/systemd/user/docker.service
systemctl --user is-active docker.service || { systemctl --user status docker.service --no-pager || true; exit 1; }
ls -l "$XDG_RUNTIME_DIR/docker.sock"
echo ROOTLESS-INSTALL-DONE
USR
chmod 0755 /tmp/feasu-rootless-install.sh
FEASU_UID=$(id -u feasu)

# Direct RootlessKit smoke test, isolated from the setup tool (the tool runs
# the same test as its first install step). Captured to a file so nothing is
# lost to session teardown; the result is recorded and the setup attempts
# still run so one CI run collects the full evidence trail.
RKRC=0
timeout 60 sudo -u feasu env XDG_RUNTIME_DIR="/run/user/$FEASU_UID" \
  /usr/bin/rootlesskit true >/tmp/feasu-rk-smoke.out 2>&1 || RKRC=$?
echo "FACT: rootlesskit-smoke-rc=$RKRC"
cat /tmp/feasu-rk-smoke.out
rm -f /tmp/feasu-rk-smoke.out

# The setup tool refuses su/sudo invocations because they carry no
# XDG_RUNTIME_DIR and cannot see the user manager. Its own documented
# remedies: (1) enable-linger + export XDG_RUNTIME_DIR, (2) log in as the
# user (ssh works). Both are used below, in that order, and the chosen path
# is recorded as evidence. Nothing here repairs or emulates runtime internals.
MANAGER=""
for i in $(seq 1 30); do
  if systemctl is-active --quiet "user@$FEASU_UID.service"; then
    MANAGER=yes
    break
  fi
  sleep 2
done
INSTALLED=""
if [ "$MANAGER" = "yes" ]; then
  log "user manager active; running the setup tool with the documented XDG_RUNTIME_DIR export"
  if sudo -u feasu env XDG_RUNTIME_DIR="/run/user/$FEASU_UID" bash /tmp/feasu-rootless-install.sh </dev/null; then
    INSTALLED=xdg-linger
  else
    echo "sudo -u setup attempt failed; falling back to a real ssh login session"
  fi
else
  echo "user manager not active after linger; starting it with a real login session (documented remedy)"
fi

if [ -z "$INSTALLED" ]; then
  install -d -o feasu -g feasu -m 0700 /home/feasu/.ssh
  ssh-keygen -t ed25519 -N "" -C feasu-bootstrap -f /home/feasu/.ssh/id_ed25519 >/dev/null
  cat /home/feasu/.ssh/id_ed25519.pub >> /home/feasu/.ssh/authorized_keys
  chown feasu:feasu /home/feasu/.ssh/id_ed25519 /home/feasu/.ssh/id_ed25519.pub /home/feasu/.ssh/authorized_keys
  chmod 0600 /home/feasu/.ssh/id_ed25519 /home/feasu/.ssh/authorized_keys
  SSHOPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes -o IdentitiesOnly=yes"
  READY=0
  for i in 1 2 3 4 5; do
    OUT=$(ssh -n $SSHOPTS -i /home/feasu/.ssh/id_ed25519 feasu@localhost true 2>&1) && { READY=1; break; }
    echo "ssh login-session probe attempt $i failed: $OUT"
    sleep 2
  done
  if [ "$READY" = 1 ]; then
    log "running the rootless setup tool in a real feasu login session"
    if ssh -n $SSHOPTS -i /home/feasu/.ssh/id_ed25519 feasu@localhost bash /tmp/feasu-rootless-install.sh; then
      INSTALLED=ssh-login
    else
      echo "ssh login-session setup attempt failed"
    fi
  else
    echo "ssh diagnostics:"
    journalctl -u ssh -n 30 --no-pager 2>/dev/null | tail -30 || true
    echo "could not open a login session for feasu via ssh (user manager prerequisite)"
  fi
fi
rm -f /tmp/feasu-rootless-install.sh
[ -n "$INSTALLED" ] || {
  echo "could not run the rootless setup tool through a documented login path"
  echo "FACT: rootless user-unit state:"
  ls -la /home/feasu/.config/systemd/user/ 2>&1 | sed 's/^/FACT: /' || true
  echo "FACT: docker.service user-unit journal (tail):"
  journalctl _SYSTEMD_USER_UNIT=docker.service -b --no-pager 2>/dev/null | tail -20 || true
  echo "FACT: kernel apparmor/oom messages (tail):"
  dmesg 2>/dev/null | grep -iE "apparmor|oom|killed process" | tail -20 || true
  exit 1
}
echo "FACT: rootless-install-path=$INSTALLED"

# Verify the rootless daemon as root through the user socket.
mkdir -p /opt/cg-feas
DOCKERSOCK="/run/user/$(id -u feasu)/docker.sock"
DOCKER_HOST="unix://$DOCKERSOCK" docker info \
  --format 'FACT: rootless-server={{.ServerVersion}} driver={{.Driver}} cgroup-driver={{.CgroupDriver}} cgroup-version={{.CgroupVersion}} live-restore={{.LiveRestoreEnabled}}'
echo "FACT: feasu-daemon-config=$(cat /home/feasu/.config/docker/daemon.json)"
echo "FACT: rootless daemon startup journal (tail):"
journalctl _SYSTEMD_USER_UNIT=docker.service -b --no-pager -n 15 2>/dev/null | tail -15 || true
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
