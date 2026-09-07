#!/usr/bin/env bash
#
# uat-vm-cgroup-system.sh — run the Release 3 SYSTEM-mode aggregate-cgroup
# feasibility gate inside a real openSUSE Tumbleweed Cloud VM booted on a
# GitHub-hosted ubuntu-24.04 runner (QEMU/KVM).
#
# Responsibility boundary (mirrors scripts/uat-vm-opensuse-apparmor.sh):
#
#   host workflow (release3-phase0-gates.yml)
#       |  (this file: cgroup-gate orchestration ONLY)
#       v
#   Tumbleweed VM harness    (scripts/uat-vm-tumbleweed.sh, sourced below)
#       |  image + checksum, qcow overlay + resize, KVM/TCG selection,
#       |  cloud-init NoCloud seed, unattended boot, vm_ssh/vm_scp transport,
#       |  wait-for-SSH, canonical reboot, serial-log diagnostics
#       v
#   guest bootstrap + feasibility harness
#       (docker + tools install, then scripts/cgroup-feasibility-system.sh
#        inside the guest as root)
#
# This file does not reimplement VM mechanics or cgroup semantics: the VM is
# the existing canonical harness, and the cgroup evidence is owned by
# scripts/cgroup-feasibility-system.sh, whose verbatim output is the recorded
# gate evidence.
#
# Env inputs:
#   UAT_REPO_DIR   host checkout of docker-helper (default: repo root)
#   UAT_KEEP       keep the VM/workdir on failure for debugging
#
# Exit 0 = the system-mode cgroup feasibility gate passed inside the VM.
# Nonzero = failed; serial tail + guest evidence are printed.

set -euo pipefail

PREFIX="[cgroup-system-vm]"
log()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"

[ -f "$UAT_REPO_DIR/scripts/uat-vm-tumbleweed.sh" ] \
  || fail "UAT_REPO_DIR has no scripts/uat-vm-tumbleweed.sh: $UAT_REPO_DIR"
[ -f "$UAT_REPO_DIR/scripts/cgroup-feasibility-system.sh" ] \
  || fail "UAT_REPO_DIR has no scripts/cgroup-feasibility-system.sh"

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
    vm_ssh 'cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null; ls /sys/fs/cgroup 2>/dev/null | head; systemctl is-active docker 2>/dev/null' || true
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
# 2. guest bootstrap: docker, curl, the shipped unit file, and the harness
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
opensuse_zypper install -y --no-recommends docker curl
systemctl enable --now docker.service >/dev/null 2>&1 || true
docker version --format '{{.Client.Version}} / server {{.Server.Version}}' || true
mkdir -p /opt/cg-feas
chown opc:opc /opt/cg-feas
echo "BOOTSTRAP-DONE"
RMT
)" || true
printf '%s\n' "$BOOTSTRAP"
echo "$BOOTSTRAP" | grep -q "BOOTSTRAP-DONE" || fail "guest bootstrap did not complete"

log "copying shipped systemd unit + harness scripts into the guest"
vm_scp "$UAT_REPO_DIR/packaging/systemd/system/docker-helper.service" "opc@127.0.0.1:/opt/cg-feas/docker-helper.service" \
  || fail "could not copy the shipped systemd unit into the guest"
if vm_ssh "sudo tee /opt/cg-feas/cgroup-feasibility-system.sh >/dev/null" < "$SCRIPT_DIR/cgroup-feasibility-system.sh"; then
  :
else
  EC=$?
  fail "could not transfer the feasibility harness (exit $EC)"
fi

# ---------------------------------------------------------------------------
# 3. run the system-mode feasibility harness inside the guest (as root)
# ---------------------------------------------------------------------------
log "== 3. system-mode aggregate cgroup feasibility harness =="
if vm_ssh "sudo bash /opt/cg-feas/cgroup-feasibility-system.sh"; then
  :
else
  EC=$?
  vm_serial_tail || true
  fail "system-mode cgroup feasibility harness failed (exit $EC)"
fi

# ---------------------------------------------------------------------------
# 4. summary
# ---------------------------------------------------------------------------
T1="$(date +%s)"
TOTAL=$((T1 - T0))
echo
echo "=========== SYSTEM-MODE CGROUP FEASIBILITY GATE SUMMARY ==========="
echo "image:        $VM_IMG_NAME"
echo "image sha256: $VM_IMG_SHA256"
echo "first boot:   ${VM_BOOT_TIME}s to SSH"
echo "accel:        $VM_ACCEL"
echo "total:        ${TOTAL}s"
echo "RESULT: system-mode aggregate cgroup feasibility PASSED inside Tumbleweed VM"
echo "==================================================================="
log "DONE"
