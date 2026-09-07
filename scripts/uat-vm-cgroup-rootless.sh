#!/usr/bin/env bash
#
# uat-vm-cgroup-rootless.sh — run the Release 3 ROOTLESS/USER-mode
# aggregate-cgroup feasibility gate inside a real openSUSE Tumbleweed Cloud
# VM booted on a GitHub-hosted ubuntu-24.04 runner (QEMU/KVM).
#
# Responsibility boundary (mirrors scripts/uat-vm-opensuse-apparmor.sh):
#
#   host workflow (release3-phase0-gates.yml)
#       |  (this file: rootless cgroup-gate orchestration ONLY)
#       v
#   Tumbleweed VM harness    (scripts/uat-vm-tumbleweed.sh, sourced below)
#       |  image + checksum, qcow overlay + resize, KVM/TCG selection,
#       |  cloud-init NoCloud seed, unattended boot, vm_ssh/vm_scp transport,
#       |  wait-for-SSH, canonical reboot, serial-log diagnostics
#       v
#   guest bootstrap (unprivileged user + systemd user delegation + rootless
#   docker packages), then scripts/cgroup-feasibility-rootless.sh inside the
#   guest; the rootless daemon runs as a systemd USER service of the
#   unprivileged user — running it as root or checking only userns
#   availability would NOT be proof.
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

[ -f "$UAT_REPO_DIR/scripts/uat-vm-tumbleweed.sh" ] \
  || fail "UAT_REPO_DIR has no scripts/uat-vm-tumbleweed.sh: $UAT_REPO_DIR"
[ -f "$UAT_REPO_DIR/scripts/cgroup-feasibility-rootless.sh" ] \
  || fail "UAT_REPO_DIR has no scripts/cgroup-feasibility-rootless.sh"

# ---------------------------------------------------------------------------
# canonical Tumbleweed VM harness (VM mechanics; no cgroup/docker knowledge)
# ---------------------------------------------------------------------------
# shellcheck source=scripts/uat-vm-tumbleweed.sh
source "$SCRIPT_DIR/uat-vm-tumbleweed.sh"

T0="$(date +%s)"

ERR_HANDLED=0
on_err() {
  [ "$ERR_HANDLED" = 1 ] && return 0
  ERR_HANDLED=1
  echo
  echo "================ HARNESS FAILURE DIAGNOSTICS ==============="
  vm_serial_tail
  if vm_ssh true 2>/dev/null; then
    vm_ssh 'cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null; ls /sys/fs/cgroup/user.slice 2>/dev/null; systemctl is-active "user@*.service" 2>/dev/null; ls /etc/systemd/system/user@.service.d 2>/dev/null' || true
  else
    echo "(guest not SSH-reachable)"
  fi
  echo "============================================================"
}
trap on_err ERR

# ---------------------------------------------------------------------------
# 1. start the Tumbleweed VM through the common harness
# ---------------------------------------------------------------------------
log "== 1. start Tumbleweed VM through common harness =="
vm_init

# ---------------------------------------------------------------------------
# 2. guest bootstrap: packages, unprivileged user, systemd user delegation
# ---------------------------------------------------------------------------
log "== 2. guest bootstrap =="
if vm_ssh "sudo tee /opt/uat-repo-policy.sh >/dev/null" < "$SCRIPT_DIR/uat-opensuse-repo.sh"; then
  :
else
  EC=$?
  fail "could not transfer repo policy helper (exit $EC)"
fi
BOOTSTRAP="$(vm_ssh 'sudo bash -s' <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
log(){ echo "[vm] $*"; }
# shellcheck source=/dev/null
source /opt/uat-repo-policy.sh
opensuse_zypp_tune_timeouts
if ! opensuse_zypper_refresh; then
  echo "REPO-FAILURE: zypper refresh exhausted attempts; aborting bootstrap" >&2
  exit 1
fi
# containerd resolves its root/state dirs from the shipped config even
# against explicit flags; this probe VM runs no system containerd, so give
# the unprivileged user those directories (the config also gets read by
# the pre-launched user containerd and by the daemon's managed one).
opensuse_zypper install -y --no-recommends docker containerd rootlesskit slirp4netns fuse-overlayfs checkpolicy policycoreutils curl
log "rootless tool providers:"
for b in dockerd-rootless.sh rootlesskit slirp4netns fuse-overlayfs newuidmap; do
  p="$(command -v "$b" 2>/dev/null || true)"
  if [ -n "$p" ]; then
    log "tool $b -> $p"
  else
    log "tool $b -> MISSING"
  fi
done
log "rootless tool providers:"
for b in dockerd-rootless.sh rootlesskit slirp4netns fuse-overlayfs newuidmap; do
  p="$(command -v "$b" 2>/dev/null || true)"
  if [ -n "$p" ]; then
    log "tool $b -> $p"
  else
    log "tool $b -> MISSING"
  fi
done
if [ -f /usr/lib/systemd/user/docker.service ]; then
  log "package ships a systemd user unit for docker"
else
  log "no systemd user unit for docker in the package; the harness provides one"
fi

FEAS_USER=feasu
if ! id "$FEAS_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$FEAS_USER"
fi
grep -q "^$FEAS_USER:" /etc/subuid || echo "$FEAS_USER:100000:65536" >> /etc/subuid
grep -q "^$FEAS_USER:" /etc/subgid || echo "$FEAS_USER:100000:65536" >> /etc/subgid

# systemd user-session cgroup v2 delegation for the unprivileged user
mkdir -p /etc/systemd/system/user.slice.d /etc/systemd/system/user@.service.d
cat > /etc/systemd/system/user.slice.d/delegation.conf <<'EOF'
[Service]
Delegate=yes
EOF
cat > /etc/systemd/system/user@.service.d/delegation.conf <<'EOF'
[Service]
Delegate=yes
KillMode=mixed
Restart=always
EOF
systemctl daemon-reload
loginctl enable-linger "$FEAS_USER"
# containerd resolves its root/state dirs from the shipped config even
# against explicit flags; this probe VM runs no system containerd, so give
# the unprivileged user those directories (the config also gets read by
# the pre-launched user containerd and by the daemon's managed one).
install -d -o feasu -g feasu /run/containerd /var/lib/containerd
UID_VALUE="$(id -u "$FEAS_USER")"
systemctl restart "user@$UID_VALUE.service"
systemctl is-active "user@$UID_VALUE.service" || { echo "USER-MANAGER-INACTIVE" >&2; exit 1; }
echo "BOOTSTRAP-DONE uid=$UID_VALUE"
RMT
)" || true
printf '%s\n' "$BOOTSTRAP"
echo "$BOOTSTRAP" | grep -q "BOOTSTRAP-DONE" || fail "guest bootstrap did not complete"

log "copying the rootless feasibility harness into the guest"
if vm_ssh "sudo mkdir -p /opt/cg-feas && sudo tee /opt/cg-feas/cgroup-feasibility-rootless.sh >/dev/null" < "$SCRIPT_DIR/cgroup-feasibility-rootless.sh"; then
  :
else
  EC=$?
  fail "could not transfer the rootless feasibility harness (exit $EC)"
fi
vm_ssh 'sudo chmod +x /opt/cg-feas/cgroup-feasibility-rootless.sh'

# ---------------------------------------------------------------------------
# 3. run the rootless-mode feasibility harness inside the guest
# ---------------------------------------------------------------------------
log "== 3. rootless aggregate cgroup feasibility harness =="
if vm_ssh "sudo bash /opt/cg-feas/cgroup-feasibility-rootless.sh"; then
  :
else
  EC=$?
  vm_serial_tail || true
  fail "rootless cgroup feasibility harness failed (exit $EC)"
fi

# ---------------------------------------------------------------------------
# 4. summary
# ---------------------------------------------------------------------------
T1="$(date +%s)"
TOTAL=$((T1 - T0))
echo
echo "=========== ROOTLESS-MODE CGROUP FEASIBILITY GATE SUMMARY ========="
echo "image:        $VM_IMG_NAME"
echo "image sha256: $VM_IMG_SHA256"
echo "first boot:   ${VM_BOOT_TIME}s to SSH"
echo "accel:        $VM_ACCEL"
echo "total:        ${TOTAL}s"
echo "RESULT: rootless-mode aggregate cgroup feasibility PASSED inside Tumbleweed VM"
echo "==================================================================="
log "DONE"
