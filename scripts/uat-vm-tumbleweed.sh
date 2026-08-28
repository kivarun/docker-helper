#!/usr/bin/env bash
#
# uat-vm-tumbleweed.sh — canonical Tumbleweed VM harness for the docker-helper
# infrastructure UATs. This file is SOURCED by a MAC-specific orchestration
# script (scripts/uat-vm-opensuse-apparmor.sh today, a future
# scripts/uat-vm-opensuse-selinux.sh) which then calls vm_init and the transport
# primitives below.
#
# Responsibility boundary:
#
#   host workflow
#       |  (sourcing script: MAC-specific orchestration ONLY)
#       v
#   Tumbleweed VM harness   <- THIS FILE
#       |  image + checksum, bounded mirror fallback, qcow overlay + resize,
#       |  KVM/TCG selection, /dev/kvm grant, QEMU lifecycle, cloud-init
#       |  NoCloud seed, canonical guest user + SSH key, unattended first boot,
#       |  wait-for-SSH, vm_ssh/vm_scp transport, canonical reboot,
#       |  serial-log diagnostics, labeled/newline-safe cmdline+LSM evidence,
#       |  bootloader kernel-cmdline mutation for MAC selector tokens.
#
# This file knows NOTHING about docker-helper, RPMs, UAT_PLATFORM /
# UAT_INSTALL / UAT_MAC, AppArmor or SELinux package/policy semantics, the
# principal/session scenario, or docker-helper service expectations. Those stay
# in the sourcing (MAC-specific) script.
#
# Bootloader: Tumbleweed boots from the official openSUSE Tumbleweed
# Minimal-VM Cloud qcow2; the image carries both a BIOS Boot Partition and an
# EFI System Partition, so legacy SeaBIOS boot works out of the box. The kernel
# cmdline is sourced from /etc/kernel/cmdline (GRUB2-BLS / systemd-boot) or
# /etc/default/grub (classic grub2); both are updated and regenerated, and as a
# deterministic fallback every on-disk BLS Type #1 entry under /boot is edited
# directly (GRUB2-BLS accepts direct edits to the entries).
#
# Public interface (after sourcing; only these are stable):
#   vm_init                 boot the VM and leave it SSH-ready (nonzero on failure)
#   vm_ssh <args...>        run a remote command; exit status == remote status
#   vm_scp <args...>        scp into the guest
#   vm_reboot <reason>      canonical reboot (down -> up, timeout, elapsed time)
#   vm_evidence             print labeled CMDLINE_VAL + LSM_VAL (newline-safe)
#   vm_evidence_cmdline     parse the CMDLINE_VAL out of vm_evidence output
#   vm_evidence_lsm         parse the LSM_VAL out of vm_evidence output
#   vm_set_mac_tokens <t>   replace MAC selector tokens in the boot config
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
#   VM_LAST_REBOOT_SECS  seconds from reboot trigger until SSH returned
#
# The harness owns the EXIT cleanup trap (workdir lifecycle). It does NOT own
# an ERR diagnostics trap: the sourcing script composes its own, using
# vm_serial_tail for the harness-owned serial-log evidence.

set -euo pipefail

VM_USER="opc"
VM_SSH_PORT=2222
VM_IMG_NAME="openSUSE-Tumbleweed-Minimal-VM.x86_64-Cloud.qcow2"
VM_IMG_DIR="tumbleweed/appliances/$VM_IMG_NAME"
VM_MARKER="/var/log/tumbleweed-vm-uat.marker"
VM_KEEP="${UAT_KEEP:-}"

VM_WORKDIR=""
VM_ACCEL="tcg"
VM_CPU_OPTS="-cpu max"
VM_IMG_SHA256=""
VM_BOOT_TIME="n/a"
VM_LAST_REBOOT_SECS="n/a"
VM_SSH_OPTS=()

vm_log()  { printf '[tumbleweed-vm] %s\n' "$*"; }
vm_fail() { printf '[tumbleweed-vm] FAILED: %s\n' "$*" >&2; exit 1; }

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

# --- image download (bounded mirror fallback; every attempt capped) ---
vm_fetch_or_fail() {
  local name="$1"; shift
  local url
  for url in "$@"; do
    vm_log "  trying $url"
    if curl -fL --connect-timeout 10 --max-time 600 --retry 2 --retry-delay 2 \
        -o "$VM_WORKDIR/$name" "$url"; then
      return 0
    fi
  done
  return 1
}

vm_prepare_image() {
  vm_log "== download official Tumbleweed Cloud image + checksum =="
  vm_fetch_or_fail "$VM_IMG_NAME" \
    "https://download.opensuse.org/$VM_IMG_DIR" \
    "https://ftp.fau.de/opensuse/$VM_IMG_DIR" \
    "https://mirror.library.ucy.ac.cy/linux/opensuse/$VM_IMG_DIR" \
    || vm_fail "image download failed from all mirrors"
  vm_fetch_or_fail "$VM_IMG_NAME.sha256" \
    "https://download.opensuse.org/$VM_IMG_DIR.sha256" \
    "https://ftp.fau.de/opensuse/$VM_IMG_DIR.sha256" \
    "https://mirror.library.ucy.ac.cy/linux/opensuse/$VM_IMG_DIR.sha256" \
    || vm_fail "checksum download failed from all mirrors"

  local expected actual
  expected="$(awk '{print $1}' "$VM_WORKDIR/$VM_IMG_NAME.sha256")"
  [ -n "$expected" ] || vm_fail "could not parse expected SHA-256 from .sha256"
  actual="$(sha256sum "$VM_WORKDIR/$VM_IMG_NAME" | awk '{print $1}')"
  [ "$actual" = "$expected" ] || vm_fail "image checksum mismatch (expected $expected, got $actual)"
  VM_IMG_SHA256="$actual"
  vm_log "image SHA-256 verified: $VM_IMG_SHA256"

  # The Cloud image ships its root partition sized to be grown; grow the
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
hostname: tw-vm-uat
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
# Defensive: the openSUSE jeos/systemd firstboot wizard self-skips when
# cloud-init manages the system, but mask the services anyway so no interactive
# firstboot can ever prompt on the console. Harmless if the units are absent.
runcmd:
  - [ sh, -c, "systemctl disable --now jeos-firstboot.service 2>/dev/null || true" ]
  - [ sh, -c, "systemctl disable --now systemd-firstboot.service 2>/dev/null || true" ]
  - [ sh, -c, "echo tumbleweed-vm-uat-boot-complete > $VM_MARKER" ]
EOF

  cat > "$VM_WORKDIR/meta-data" <<EOF
instance-id: tumbleweed-vm-uat-001
local-hostname: tw-vm-uat
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
  VM_WORKDIR="$(mktemp -d /tmp/tumbleweed-vm-uat.XXXXXX)"
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

# --- canonical reboot: trigger, prove down, wait up, timeout, elapsed ---
vm_reboot() {
  local reason="${1:-reboot}"
  local down=0 up=0 i t0 t1 dt
  vm_log "reboot ($reason)"
  vm_ssh "sudo systemctl reboot" >/dev/null 2>&1 || true
  for i in $(seq 1 60); do
    if ! vm_ssh true >/dev/null 2>&1; then
      down=1
      break
    fi
    sleep 3
  done
  [ "$down" = 1 ] || vm_fail "VM did not drop SSH after reboot trigger ($reason)"
  t0="$(date +%s)"
  for i in $(seq 1 120); do
    if vm_ssh true >/dev/null 2>&1; then
      up=1
      break
    fi
    sleep 3
  done
  t1="$(date +%s)"
  dt=$((t1 - t0))
  [ "$up" = 1 ] || vm_fail "VM did not return to SSH after reboot ($reason)"
  VM_LAST_REBOOT_SECS="$dt"
  vm_log "reboot done: SSH back in ${dt}s ($reason)"
}

# --- labeled, newline-safe evidence primitives ---
# /sys/kernel/security/lsm (and other sysfs files) may not end with a newline;
# the explicit printf '\n' terminator guarantees every labeled value is
# terminated and the next label starts on a fresh line. Parse by label, never
# by grep -A1 around a human heading.
vm_evidence() {
  vm_ssh 'bash -s' <<'RMT'
set +e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
printf 'CMDLINE_VAL='
cat /proc/cmdline
printf '\n'
printf 'LSM_VAL='
cat /sys/kernel/security/lsm
printf '\n'
RMT
}

vm_evidence_cmdline() { sed -n 's/^CMDLINE_VAL=//p' | tail -1; }
vm_evidence_lsm()     { sed -n 's/^LSM_VAL=//p' | tail -1; }

# --- mechanical Tumbleweed boot-config MAC selector mutation ---
# Replaces the desired MAC selector token set into every kernel cmdline source
# (/etc/kernel/cmdline, GRUB_CMDLINE_LINUX_DEFAULT, on-disk BLS Type #1
# entries), removing any stale selector tokens first. It accepts the caller's
# token set verbatim (e.g. "security=apparmor apparmor=1 selinux=0" or
# "security=selinux selinux=1 apparmor=0 enforcing=1") and knows nothing about
# the semantics of those tokens.
vm_set_mac_tokens() {
  local tokens="$1"
  vm_log "setting MAC selector tokens: $tokens"
  local out
  out="$(vm_ssh "sudo bash -s '$tokens'" <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
log(){ echo "[vm] $*"; }
TOKENS="$1"

# set_cmdline removes any prior MAC selector tokens and appends the target
# token set. Works for /etc/kernel/cmdline, GRUB_CMDLINE_LINUX_DEFAULT and BLS
# options lines alike.
set_cmdline() {
  local old="$1" out=""
  local t
  for t in $old; do
    case "$t" in
      security=*|selinux=*|enforcing=*|apparmor=*) ;;
      *) out="$out $t" ;;
    esac
  done
  printf '%s %s' "$out" "$TOKENS"
}

if [ -f /etc/kernel/cmdline ]; then
  cp /etc/kernel/cmdline /etc/kernel/cmdline.orig || true
  printf '%s' "$(set_cmdline "$(cat /etc/kernel/cmdline)")" > /etc/kernel/cmdline
  log "/etc/kernel/cmdline now: $(cat /etc/kernel/cmdline)"
fi

if [ -f /etc/default/grub ]; then
  cp /etc/default/grub /etc/default/grub.orig || true
  inner="$(sed -n 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"$/\1/p' /etc/default/grub | tail -1)"
  [ -n "$inner" ] || inner="$(sed -n 's/^GRUB_CMDLINE_LINUX_DEFAULT=\(.*\)$/\1/p' /etc/default/grub | tail -1 | tr -d '"')"
  inner="$(set_cmdline "$inner")"
  sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"$inner\"|" /etc/default/grub
  log "GRUB_CMDLINE_LINUX_DEFAULT now: $(sed -n 's/^GRUB_CMDLINE_LINUX_DEFAULT=//p' /etc/default/grub)"
fi

log "regenerating bootloader config:"
if command -v update-bootloader >/dev/null; then
  update-bootloader --config >/tmp/ub.log 2>&1 && log "update-bootloader --config OK" || { log "update-bootloader returned nonzero:"; tail -20 /tmp/ub.log; }
fi
if command -v sdbootutil >/dev/null; then
  sdbootutil update-all-entries >/tmp/sdb.log 2>&1 && log "sdbootutil update-all-entries OK" || { log "sdbootutil returned nonzero:"; tail -20 /tmp/sdb.log; }
fi
if [ -d /boot/grub2 ] && command -v grub2-mkconfig >/dev/null; then
  grub2-mkconfig -o /boot/grub2/grub.cfg >/tmp/gmk.log 2>&1 && log "grub2-mkconfig OK" || { log "grub2-mkconfig returned nonzero:"; tail -20 /tmp/gmk.log; }
fi

# Deterministic fallback: ensure every on-disk BLS entry carries the tokens
# (GRUB2-BLS accepts direct edits to the Type #1 .conf files).
BLS_FILES="$(find /boot -path '*/loader/entries/*.conf' 2>/dev/null || true)"
if [ -z "$BLS_FILES" ]; then
  log "no BLS .conf entries found under /boot (bootloader may be classic grub2)"
else
  for f in $BLS_FILES; do
    opts="$(sed -n 's/^options[[:space:]]*//p' "$f" | head -1)"
    newopts="$(set_cmdline "$opts")"
    sed -i -E "s|^(options[[:space:]]+).*|\1$newopts|" "$f"
    log "BLS entry updated: $f"
  done
fi

echo "=== on-disk boot entries containing '$TOKENS' ==="
grep -Frl "$TOKENS" /boot 2>/dev/null || echo "(none found under /boot)"
echo "=== current /proc/cmdline (pre-reboot, informational) ==="
cat /proc/cmdline
echo "MAC_TOKENS-DONE"
RMT
)" || true
  printf '%s\n' "$out"
  if ! printf '%s\n' "$out" | grep -q "MAC_TOKENS-DONE"; then
    vm_fail "MAC token bootstrap script did not complete"
  fi
}
