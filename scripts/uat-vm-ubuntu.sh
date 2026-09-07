#!/usr/bin/env bash
#
# uat-vm-ubuntu.sh — canonical Ubuntu 24.04 VM harness for the docker-helper
# infrastructure UATs that need a normally configured supported host
# environment. This file is SOURCED by an environment-specific orchestration
# script (scripts/uat-vm-cgroup-rootless.sh today).
#
# Responsibility boundary:
#
#   host workflow
#       |  (sourcing script: gate-specific orchestration ONLY)
#       v
#   Ubuntu VM harness       <- THIS FILE
#       |  image + SHA256SUMS verification, qcow overlay + resize,
#       |  KVM/TCG selection, /dev/kvm grant, QEMU lifecycle, cloud-init
#       |  NoCloud seed, canonical guest user + SSH key, unattended first
#       |  boot, wait-for-SSH, vm_ssh/vm_scp transport, serial-log
#       |  diagnostics.
#
# This file knows NOTHING about docker-helper, apt packages, rootless Docker,
# cgroup semantics, or any gate scenario. Those stay in the sourcing script.
#
# Bootloader: Ubuntu amd64 server cloud images boot with the default SeaBIOS
# firmware (the documented QEMU launch path on ubuntu.com), so no OVMF/UEFI
# setup is required.
#
# Public interface (after sourcing; only these are stable):
#   vm_init                 boot the VM and leave it SSH-ready (nonzero on failure)
#   vm_ssh <args...>        run a remote command; exit status == remote status
#   vm_scp <args...>        scp into the guest
#   vm_serial_tail          print the last serial-log lines (diagnostics)
#
# Env inputs:
#   UAT_KEEP   keep the VM/workdir on failure for debugging
#
# Exposed state (read-only for callers):
#   VM_WORKDIR        scratch dir (also the working directory after vm_init)
#   VM_IMG_NAME       official cloud image basename
#   VM_IMG_SHA256     verified image SHA-256
#   VM_ACCEL          kvm | tcg
#   VM_BOOT_TIME      seconds until first SSH
#
# The harness owns the EXIT cleanup trap (workdir lifecycle). It does NOT own
# an ERR diagnostics trap: the sourcing script composes its own, using
# vm_serial_tail for the harness-owned serial-log evidence.

set -euo pipefail

VM_USER="opc"
VM_SSH_PORT=2222
VM_IMG_NAME="ubuntu-24.04-server-cloudimg-amd64.img"
VM_IMG_BASE="https://cloud-images.ubuntu.com/releases/24.04/release"
VM_MARKER="/var/log/ubuntu-vm-uat.marker"
VM_KEEP="${UAT_KEEP:-}"

VM_WORKDIR=""
VM_ACCEL="tcg"
VM_CPU_OPTS="-cpu max"
VM_IMG_SHA256=""
VM_BOOT_TIME="n/a"
VM_SSH_OPTS=()

vm_log()  { printf '[ubuntu-vm] %s\n' "$*"; }
vm_fail() { printf '[ubuntu-vm] FAILED: %s\n' "$*" >&2; exit 1; }

# --- transport (preserves remote exit status: vm_ssh returns ssh's status) ---
vm_ssh() { ssh "${VM_SSH_OPTS[@]}" -p "$VM_SSH_PORT" "${VM_USER}@127.0.0.1" "$@"; }
vm_scp() { scp "${VM_SSH_OPTS[@]}" -P "$VM_SSH_PORT" "$@"; }

# --- diagnostics ---
vm_serial_tail() {
  echo
  echo "================ QEMU SERIAL LOG (last 80) ================"
  [ -f "$VM_WORKDIR/serial.log" ] && tail -80 "$VM_WORKDIR/serial.log" || true
  echo "============================================================"
}

vm_cleanup() {
  if [ -n "$VM_KEEP" ]; then
    vm_log "UAT_KEEP set: leaving workdir at $VM_WORKDIR"
    return 0
  fi
  if [ -n "$VM_WORKDIR" ] && [ -f "$VM_WORKDIR/qemu.pid" ]; then
    kill "$(cat "$VM_WORKDIR/qemu.pid")" 2>/dev/null || true
  fi
  if [ -n "$VM_WORKDIR" ]; then
    cd /tmp 2>/dev/null || true
    rm -rf "$VM_WORKDIR"
  fi
}

# --- image download (bounded; every attempt capped) ---
# Aggressive CI-oriented download policy: a short connect timeout plus bounded
# low-speed detection, so a technically connected but unusably slow mirror is
# abandoned rather than consuming the CI job. SHA-256 verification is unchanged
# (vm_prepare_image).
vm_fetch_or_fail() {
  local name="$1"; shift
  local url
  for url in "$@"; do
    vm_log "  trying $url"
    if curl -fL --connect-timeout 5 --max-time 900 --retry 2 --retry-delay 2 \
        --speed-time 15 --speed-limit 262144 \
        -o "$VM_WORKDIR/$name" "$url"; then
      return 0
    fi
  done
  return 1
}

vm_prepare_image() {
  vm_log "== download official Ubuntu 24.04 cloud image + checksum =="
  vm_fetch_or_fail "$VM_IMG_NAME" \
    "$VM_IMG_BASE/$VM_IMG_NAME" \
    "https://cloud-images.ubuntu.com/releases/noble/release/$VM_IMG_NAME" \
    || vm_fail "image download failed from all sources"
  vm_fetch_or_fail "SHA256SUMS" \
    "$VM_IMG_BASE/SHA256SUMS" \
    "https://cloud-images.ubuntu.com/releases/noble/release/SHA256SUMS" \
    || vm_fail "checksum download failed from all sources"

  local expected actual
  expected="$(awk -v img="$VM_IMG_NAME" '$2 == "*" img {print $1}' \
    "$VM_WORKDIR/SHA256SUMS")"
  [ -n "$expected" ] || vm_fail "no SHA256SUMS entry for $VM_IMG_NAME"
  actual="$(sha256sum "$VM_WORKDIR/$VM_IMG_NAME" | awk '{print $1}')"
  [ "$actual" = "$expected" ] || vm_fail "image checksum mismatch (expected $expected, got $actual)"
  VM_IMG_SHA256="$actual"
  vm_log "image SHA-256 verified: $VM_IMG_SHA256"

  # The cloud image ships its root partition sized to be grown; grow the
  # overlay so cloud-init growpart expands root at first boot. The pristine
  # base image is never modified (overlay).
  qemu-img create -f qcow2 -b "$VM_WORKDIR/$VM_IMG_NAME" -F qcow2 \
    "$VM_WORKDIR/disk.qcow2" >/dev/null
  qemu-img resize "$VM_WORKDIR/disk.qcow2" 12G >/dev/null
  vm_log "overlay disk created and resized to 12G (cloud-init growpart expands root)"
}

vm_seed() {
  vm_log "== cloud-init NoCloud seed =="
  ssh-keygen -t ed25519 -N "" -f "$VM_WORKDIR/id_ed25519" >/dev/null
  local pub
  pub="$(cat "$VM_WORKDIR/id_ed25519.pub")"

  cat > "$VM_WORKDIR/user-data" <<EOF
#cloud-config
hostname: ub-vm-uat
ssh_pwauth: false
disable_root: true
users:
  - name: $VM_USER
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $pub
growpart:
  mode: auto
  devices: ["/"]
resize_rootfs: true
runcmd:
  - [ sh, -c, "echo ubuntu-vm-uat-boot-complete > $VM_MARKER" ]
EOF

  cat > "$VM_WORKDIR/meta-data" <<EOF
instance-id: ubuntu-vm-uat-001
local-hostname: ub-vm-uat
EOF

  cloud-localds "$VM_WORKDIR/seed.iso" "$VM_WORKDIR/user-data" "$VM_WORKDIR/meta-data"
}

vm_boot() {
  vm_log "== boot VM (accelerator=$VM_ACCEL, $VM_CPU_OPTS) =="
  qemu-system-x86_64 \
    -machine "accel=$VM_ACCEL" \
    $VM_CPU_OPTS \
    -smp 2 -m 3072 \
    -drive file="$VM_WORKDIR/disk.qcow2",if=virtio,format=qcow2 \
    -drive file="$VM_WORKDIR/seed.iso",if=virtio,format=raw \
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:$VM_SSH_PORT-:22 \
    -device virtio-net-pci,netdev=net0 \
    -display none \
    -serial file:"$VM_WORKDIR/serial.log" \
    -daemonize -pidfile "$VM_WORKDIR/qemu.pid"

  sleep 2
  [ -s "$VM_WORKDIR/qemu.pid" ] || vm_fail "qemu did not start (no pidfile)"
  local pid
  pid="$(cat "$VM_WORKDIR/qemu.pid")"
  kill -0 "$pid" 2>/dev/null || vm_fail "qemu process exited early (pid $pid)"
  vm_log "qemu running: pid=$pid"
}

vm_wait_ssh() {
  vm_log "== STAGE 1: wait for SSH (unattended first boot, max 360s) =="
  local ready=0 i t0 t1
  t0="$(date +%s)"
  for i in $(seq 1 72); do
    if vm_ssh true 2>/dev/null; then
      ready=1
      break
    fi
    sleep 5
  done
  t1="$(date +%s)"
  VM_BOOT_TIME=$((t1 - t0))
  [ "$ready" = 1 ] || vm_fail "VM did not become SSH-ready in ${VM_BOOT_TIME}s (see serial log)"
  vm_log "SSH ready after ${VM_BOOT_TIME}s"

  local marker=0
  for i in $(seq 1 36); do
    if vm_ssh "test -f $VM_MARKER" 2>/dev/null; then
      marker=1
      break
    fi
    sleep 5
  done
  if [ "$marker" = 1 ]; then
    vm_log "cloud-init completed (marker present)"
  else
    vm_log "WARN: cloud-init marker not seen in 180s (continuing anyway)"
  fi
}

# --- main entry: workdir, accelerator, image, seed, boot, wait-for-SSH ---
vm_init() {
  VM_WORKDIR="$(mktemp -d /tmp/ubuntu-vm-uat.XXXXXX)"
  cd "$VM_WORKDIR"
  VM_SSH_OPTS=(-i "$VM_WORKDIR/id_ed25519" -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR)
  trap vm_cleanup EXIT

  vm_log "== 1. virtualization + accelerator =="
  if [ -e /dev/kvm ]; then
    VM_ACCEL="kvm"
  fi
  VM_CPU_OPTS="-cpu max"
  [ "$VM_ACCEL" = "kvm" ] && VM_CPU_OPTS="-cpu host"
  if [ "$VM_ACCEL" = "kvm" ]; then
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
      vm_log "kvm access: direct"
    else
      # On GitHub-hosted runners /dev/kvm is 0660 root:kvm and the runner user
      # is not in the kvm group; the runner has passwordless sudo, so grant
      # access via chmod 666 and run qemu as the runner user. Confined to the
      # ephemeral job VM.
      sudo -n chmod 666 /dev/kvm || vm_fail "could not grant /dev/kvm access via sudo"
      vm_log "kvm access: granted (sudo chmod 666 /dev/kvm)"
    fi
  fi
  vm_log "accelerator=$VM_ACCEL ($VM_CPU_OPTS)"

  vm_prepare_image
  vm_seed
  vm_boot
  vm_wait_ssh
}
