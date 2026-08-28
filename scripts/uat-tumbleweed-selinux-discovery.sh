#!/usr/bin/env bash
#
# uat-tumbleweed-selinux-discovery.sh — discovery PoC #2: boot the official
# openSUSE Tumbleweed Minimal-VM Cloud qcow2 fully unattended on a
# GitHub-hosted ubuntu-24.04 public runner using the QEMU/KVM harness proven by
# uat-selinux-discovery.sh, then switch the running system to genuine SELinux
# enforcing (replacing whatever MAC backend the image shipped with), survive a
# reboot and prove the result from inside the VM.
#
# This is DISCOVERY (workflow_dispatch only). It does NOT run the docker-helper
# UAT, does not touch release workflows and does not install docker-helper.
#
# Image: official openSUSE Tumbleweed cloud image
#   openSUSE-Tumbleweed-Minimal-VM.x86_64-Cloud.qcow2
# from https://download.opensuse.org/tumbleweed/appliances/
# (cloud-init profile, designed for unattended bootstrap), verified against the
# official .sha256. No installer, no self-install, no custom image build.
#
# Stages:
#   STAGE 1  unattended first boot via cloud-init (hostname, user, SSH key,
#            passwordless sudo, no password login, grow filesystem) -> SSH
#            without any console/manual interaction.
#   STAGE 2  determine the actual initial MAC state, install the minimal
#            official Tumbleweed SELinux package set (OSS repo only), set
#            SELINUX=<mode> + SELINUXTYPE=targeted, add
#            security=selinux selinux=1 [enforcing=1] apparmor=0 to the kernel
#            cmdline via the image's bootloader, regenerate initramfs/bootloader.
#   STAGE 3  reboot(s) and prove SELinux enforcing as the active LSM with
#            AppArmor NOT concurrently active (lsm/sestatus/getenforce/enforce),
#            plus basic VM suitability (systemd, SSH, bind mount, network).
#
# Relabel strategy (openSUSE's policycoreutils ships no boot-time autorelabel
# service, so relying on /.autorelabel alone is not dependable):
#   - if the image already booted with SELinux as the active LSM (Tumbleweed
#     default since build 20250211) the filesystem is already labeled: no
#     relabel, no permissive phase; one enforcing reboot proves persistence.
#   - otherwise: boot once with SELINUX=permissive (SELinux active, nothing
#     blocked), run the standard full relabel `fixfiles -F restore`, then flip
#     to SELINUX=enforcing + enforcing=1 and boot again.
#   The final acceptance is always enforcing; permissive is only an
#   intermediate relabel phase, never the end state.
#
# Bootloader: Tumbleweed now defaults to GRUB2-BLS / systemd-boot where the
# kernel cmdline is sourced from /etc/kernel/cmdline; classic grub2 still uses
# /etc/default/grub. Both are updated and regenerated, and as a deterministic
# fallback every on-disk BLS Type #1 entry under /boot is edited directly (the
# news article for GRUB2-BLS explicitly allows editing the entries directly).
#
# Exit 0 = full proof, nonzero = discovery failed (job output shows where).

set -euo pipefail

WORKDIR="$(mktemp -d /tmp/tumbleweed-selinux.XXXXXX)"
cd "$WORKDIR"

T0="$(date +%s)"
log()  { printf '[tumbleweed] %s\n' "$*"; }
fail() { printf '[tumbleweed] FAILED: %s\n' "$*" >&2; exit 1; }

USER="opc"
SSH_OPTS="-i id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR"
vm_ssh() { ssh $SSH_OPTS -p 2222 "$USER"@127.0.0.1 "$@"; }

IMG_BASE_URL="https://download.opensuse.org/tumbleweed/appliances"
IMG_NAME="openSUSE-Tumbleweed-Minimal-VM.x86_64-Cloud.qcow2"
IMG_URL="$IMG_BASE_URL/$IMG_NAME"

cleanup() {
  if [ -f qemu.pid ]; then
    kill "$(cat qemu.pid)" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

on_err() {
  echo
  echo "================ SERIAL LOG (last 80) ================"
  [ -f serial.log ] && tail -80 serial.log || true
  echo "======================================================"
}
trap on_err ERR

# ---------------------------------------------------------------------------
# 1. Virtualization diagnostics
# ---------------------------------------------------------------------------
log "== 1. virtualization diagnostics =="
if [ -e /dev/kvm ]; then
  log "/dev/kvm: PRESENT"
  ls -l /dev/kvm 2>/dev/null || true
else
  log "/dev/kvm: ABSENT"
fi
log "id: $(id)"
if id -nG | tr ' ' '\n' | grep -qx kvm; then
  log "kvm group: member"
else
  log "kvm group: NOT a member"
fi
CPUFLAGS="$(grep -m1 '^flags' /proc/cpuinfo | grep -oE '\b(vmx|svm)\b' | sort -u | tr '\n' ' ')"
log "cpu virt flags: ${CPUFLAGS:-<none>}"
lscpu 2>/dev/null | grep -iE '^(Model name|Virtualization|Hypervisor vendor)' || true
log "qemu: $(qemu-system-x86_64 --version | head -1)"

# ---------------------------------------------------------------------------
# 2. Accelerator decision + /dev/kvm access (same proven mechanism)
# ---------------------------------------------------------------------------
ACCEL="tcg"
if [ -e /dev/kvm ]; then
  ACCEL="kvm"
fi
log "== 2. accelerator = $ACCEL =="
log "RESULT accelerator=$ACCEL"

CPU_OPTS="-cpu max"
[ "$ACCEL" = "kvm" ] && CPU_OPTS="-cpu host"

if [ "$ACCEL" = "kvm" ]; then
  if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    log "kvm access: direct (runner user can open /dev/kvm)"
    KVM_ACCESS="direct"
  else
    log "kvm access: restricted (runner user cannot open /dev/kvm)"
    sudo -n chmod 666 /dev/kvm || fail "could not grant /dev/kvm access via sudo"
    log "kvm access: granted (sudo chmod 666 /dev/kvm)"
    KVM_ACCESS="granted"
  fi
  log "RESULT kvm_access=$KVM_ACCESS"
fi

# ---------------------------------------------------------------------------
# 3. Official cloud image + checksum + grow (cloud images expect to be grown)
# ---------------------------------------------------------------------------
log "== 3. download official Tumbleweed Cloud image =="
T_DL_START="$(date +%s)"
curl -fL --retry 3 --retry-delay 2 -o "$IMG_NAME" "$IMG_URL"
T_DL_END="$(date +%s)"
DL_TIME=$((T_DL_END - T_DL_START))
log "downloaded: $IMG_NAME ($(du -h "$IMG_NAME" | cut -f1)) in ${DL_TIME}s"
log "RESULT download_time=${DL_TIME}s"

curl -fsSL -o "$IMG_NAME.sha256" "$IMG_URL.sha256"
EXPECTED="$(awk '{print $1}' "$IMG_NAME.sha256")"
[ -n "$EXPECTED" ] || fail "could not parse expected SHA-256 from .sha256"
ACTUAL="$(sha256sum "$IMG_NAME" | awk '{print $1}')"
[ "$ACTUAL" = "$EXPECTED" ] || fail "image checksum mismatch (expected $EXPECTED, got $ACTUAL)"
log "image SHA-256 verified: $ACTUAL"
log "RESULT image=$IMG_NAME"
log "RESULT image_sha256=$ACTUAL"

# The Cloud image ships its root partition sized to be grown (the partition
# table already extends beyond the published 2 GiB virtual size). Grow the
# overlay so cloud-init growpart can expand root at first boot. The pristine
# base image is never modified (overlay).
qemu-img create -f qcow2 -b "$IMG_NAME" -F qcow2 disk.qcow2 >/dev/null
qemu-img resize disk.qcow2 12G >/dev/null
log "overlay disk created and resized to 12G (cloud-init growpart expands root)"

# ---------------------------------------------------------------------------
# 4. cloud-init seed (fully automatic, no interaction)
# ---------------------------------------------------------------------------
log "== 4. cloud-init seed =="
ssh-keygen -t ed25519 -N "" -f id_ed25519 >/dev/null

cat > user-data <<EOF
#cloud-config
hostname: tw-poc
ssh_pwauth: false
disable_root: true
users:
  - name: $USER
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat id_ed25519.pub)
growpart:
  mode: auto
  devices: ["/"]
resize_rootfs: true
# Defensive: the openSUSE jeos/systemd firstboot wizard self-skips when
# cloud-init manages the system (its own code checks /run/cloud-init), but mask
# the services anyway so no interactive firstboot can ever prompt on the
# console. Harmless if the units are absent.
runcmd:
  - [ sh, -c, "systemctl disable --now jeos-firstboot.service 2>/dev/null || true" ]
  - [ sh, -c, "systemctl disable --now systemd-firstboot.service 2>/dev/null || true" ]
  - [ sh, -c, "echo tumbleweed-poc-boot-complete > /var/log/tumbleweed-poc.marker" ]
EOF

cat > meta-data <<EOF
instance-id: tumbleweed-selinux-poc-001
local-hostname: tw-poc
EOF

cloud-localds seed.iso user-data meta-data
ls -l seed.iso

# ---------------------------------------------------------------------------
# 5. Boot the VM (SeaBIOS; the image carries both a BIOS Boot Partition and an
#    EFI System Partition, so legacy BIOS boot works out of the box)
# ---------------------------------------------------------------------------
log "== 5. boot VM (accelerator=$ACCEL, $CPU_OPTS) =="
qemu-system-x86_64 \
  -machine "accel=$ACCEL" \
  $CPU_OPTS \
  -smp 2 -m 3072 \
  -drive file=disk.qcow2,if=virtio,format=qcow2 \
  -drive file=seed.iso,if=virtio,format=raw \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 \
  -device virtio-net-pci,netdev=net0 \
  -display none \
  -serial file:serial.log \
  -daemonize -pidfile qemu.pid

sleep 2
[ -s qemu.pid ] || fail "qemu did not start (no pidfile)"
QEMU_PID="$(cat qemu.pid)"
kill -0 "$QEMU_PID" 2>/dev/null || fail "qemu process exited early (pid $QEMU_PID)"
log "qemu running: pid=$QEMU_PID accelerator=$ACCEL"

# ---------------------------------------------------------------------------
# 6. STAGE 1: wait for SSH (unattended first boot)
# ---------------------------------------------------------------------------
log "== 6. STAGE 1: wait for SSH (unattended first boot, max 360s) =="
T_BOOT_START="$(date +%s)"
ready=0
for i in $(seq 1 72); do
  if vm_ssh true 2>/dev/null; then
    ready=1
    break
  fi
  sleep 5
done
T_BOOT_END="$(date +%s)"
BOOT_TIME=$((T_BOOT_END - T_BOOT_START))
[ "$ready" = 1 ] || fail "VM did not become SSH-ready in ${BOOT_TIME}s (see serial log)"
log "SSH ready after ${BOOT_TIME}s"
log "RESULT first_boot_to_ssh=${BOOT_TIME}s"

# Wait for cloud-init to fully finish (marker), max 180s.
marker=0
for i in $(seq 1 36); do
  if vm_ssh "test -f /var/log/tumbleweed-poc.marker" 2>/dev/null; then
    marker=1
    break
  fi
  sleep 5
done
if [ "$marker" = 1 ]; then
  log "cloud-init completed (marker present)"
else
  log "WARN: cloud-init marker not seen in 180s (continuing anyway)"
fi

# STAGE 1 acceptance inside the VM.
log "== STAGE 1 acceptance =="
STAGE1="$(vm_ssh 'bash -s' <<'RMT'
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "=== uname -a ==="; uname -a
echo "=== /etc/os-release ==="; cat /etc/os-release
echo "=== systemd ==="
systemctl is-system-running || true
systemctl is-active systemd-journald || { echo "FAIL: systemd-journald not active"; exit 1; }
echo "systemd OK"
echo "=== cloud-init status ==="; cloud-init status || true
echo "=== sshd ==="; systemctl is-active sshd || systemctl is-active ssh || true
echo "=== password login disabled ==="
grep -iE '^PasswordAuthentication|^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || true
echo "=== firstboot units ==="
systemctl list-unit-files 2>/dev/null | grep -Ei 'firstboot|jeos' || echo "(no firstboot units)"
echo "STAGE1-DONE"
RMT
)" || true
printf '%s\n' "$STAGE1"
echo "$STAGE1" | grep -q "STAGE1-DONE" || fail "STAGE 1 acceptance script did not complete"
echo "$STAGE1" | grep -qi 'opensuse-tumbleweed' || fail "os-release does not identify openSUSE Tumbleweed"
echo "$STAGE1" | grep -q "systemd OK" || fail "systemd not OK"
log "STAGE 1 passed: unattended Tumbleweed boot via cloud-init"

# Check the serial log for any JeOS/systemd-firstboot interactive wizard.
log "== serial log: interactive-firstboot check =="
if grep -aiE 'jeos|firstboot|YaST|license|password for|choose your|welcome' serial.log | head -30; then
  log "NOTE: firstboot-related text found in serial log (see above); confirming it did not block SSH"
else
  log "serial log: no firstboot wizard text detected"
fi

# ---------------------------------------------------------------------------
# 7. STAGE 1.5: actual initial MAC state
# ---------------------------------------------------------------------------
log "== 7. STAGE 1.5: initial MAC / SELinux state =="
STATE="$(vm_ssh 'bash -s' <<'RMT'
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "=== /sys/kernel/security/lsm ==="; cat /sys/kernel/security/lsm
echo "=== /proc/cmdline ==="; cat /proc/cmdline
echo "=== aa-status ==="; (command -v aa-status >/dev/null && aa-status) || echo "(aa-status absent)"
echo "=== sestatus ==="; (command -v sestatus >/dev/null && sestatus) || echo "(sestatus absent)"
echo "=== getenforce ==="; (command -v getenforce >/dev/null && getenforce) || echo "(getenforce absent)"
echo "=== selinux/enforce ==="; cat /sys/fs/selinux/enforce 2>/dev/null || echo "(no /sys/fs/selinux)"
echo "=== SELinux/AppArmor packages ==="; rpm -qa | grep -Ei 'selinux|policycoreutils|libselinux|libsepol|libsemanage|apparmor' || echo "(none)"
echo "STATE-DONE"
RMT
)" || true
printf '%s\n' "$STATE"
echo "$STATE" | grep -q "STATE-DONE" || fail "state discovery did not complete"

RAW_LSM="$(printf '%s\n' "$STATE" | grep -A1 '=== /sys/kernel/security/lsm ===' | tail -1)"
SELINUX_ACTIVE="no"
APPARMOR_ACTIVE="no"
echo "$RAW_LSM" | grep -qw selinux  && SELINUX_ACTIVE="yes"
echo "$RAW_LSM" | grep -qw apparmor && APPARMOR_ACTIVE="yes"
log "initial LSM line: $RAW_LSM"
log "RESULT initial_selinux_active=$SELINUX_ACTIVE"
log "RESULT initial_apparmor_active=$APPARMOR_ACTIVE"

# ---------------------------------------------------------------------------
# 8. STAGE 2: SELinux preparation (mode-aware)
#    MODE is "permissive" only as an intermediate relabel phase; the final
#    acceptance is always enforcing.
# ---------------------------------------------------------------------------
if [ "$SELINUX_ACTIVE" = "yes" ]; then
  NEED_RELABEL="no"
  FINAL_MODE="enforcing"
  log "== 8. STAGE 2: SELinux preparation (image already SELinux-active -> no relabel) =="
else
  NEED_RELABEL="yes"
  FINAL_MODE="permissive"
  log "== 8. STAGE 2: SELinux preparation (image NOT SELinux-active -> permissive relabel phase first) =="
fi
log "RESULT need_relabel=$NEED_RELABEL"

STAGE2="$(vm_ssh "sudo bash -s $FINAL_MODE" <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
log(){ echo "[vm] $*"; }
MODE="$1"
log "target SELinux mode for this boot: $MODE"

NEED=0
rpm -q selinux-policy-targeted >/dev/null 2>&1 || NEED=1
rpm -q policycoreutils >/dev/null 2>&1 || NEED=1
if [ "$NEED" = 1 ]; then
  log "installing minimal official SELinux set: selinux-policy-targeted policycoreutils (pulls selinux-tools/libselinux deps, OSS repo only)"
  zypper --non-interactive refresh || true
  zypper --non-interactive install --no-recommends selinux-policy-targeted policycoreutils
  log "installed SELinux/AppArmor-related packages:"
  rpm -qa | grep -Ei 'selinux|policycoreutils|libselinux|libsepol|libsemanage|apparmor' || true
else
  log "SELinux userspace already present (no install needed)"
  rpm -qa | grep -Ei 'selinux|policycoreutils|libselinux|apparmor' || true
fi

log "tool providers:"
for b in sestatus getenforce setenforce restorecon fixfiles setfiles load_policy semodule setsebool; do
  p="$(command -v "$b" 2>/dev/null || true)"
  if [ -n "$p" ]; then
    echo "tool $b -> $p ($(rpm -qf "$p" 2>/dev/null || echo unknown))"
  else
    echo "tool $b -> MISSING"
  fi
done

# /etc/selinux/config
mkdir -p /etc/selinux
[ -f /etc/selinux/config ] && cp /etc/selinux/config /etc/selinux/config.orig || true
cat > /etc/selinux/config <<SELCFG
SELINUX=$MODE
SELINUXTYPE=targeted
SELCFG
log "/etc/selinux/config:"
cat /etc/selinux/config

# --- kernel cmdline: add to every source and guarantee it lands on the
#     boot entries (BLS Type #1 .conf files are the actual boot config). ---
CMDLINE_ADD="security=selinux selinux=1 apparmor=0"
[ "$MODE" = "enforcing" ] && CMDLINE_ADD="$CMDLINE_ADD enforcing=1"
log "kernel cmdline additions: $CMDLINE_ADD"

if [ -f /etc/kernel/cmdline ]; then
  cp /etc/kernel/cmdline /etc/kernel/cmdline.orig
  for opt in $CMDLINE_ADD; do
    grep -qw "$opt" /etc/kernel/cmdline || printf ' %s' "$opt" >> /etc/kernel/cmdline
  done
  log "/etc/kernel/cmdline now: $(cat /etc/kernel/cmdline)"
fi

if [ -f /etc/default/grub ]; then
  cp /etc/default/grub /etc/default/grub.orig
  inner="$(sed -n 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"$/\1/p' /etc/default/grub | tail -1)"
  [ -n "$inner" ] || inner="$(sed -n 's/^GRUB_CMDLINE_LINUX_DEFAULT=\(.*\)$/\1/p' /etc/default/grub | tail -1 | tr -d '"')"
  for opt in $CMDLINE_ADD; do
    grep -qw "$opt" <<<"$inner" || inner="$inner $opt"
  done
  sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"$inner\"|" /etc/default/grub
  log "GRUB_CMDLINE_LINUX_DEFAULT now: $(sed -n 's/^GRUB_CMDLINE_LINUX_DEFAULT=//p' /etc/default/grub)"
fi

log "regenerating bootloader config:"
if command -v update-bootloader >/dev/null; then
  update-bootloader --config >/tmp/ub.log 2>&1 && log "update-bootloader --config OK" || { log "update-bootloader --config returned nonzero:"; tail -20 /tmp/ub.log; }
fi
if command -v sdbootutil >/dev/null; then
  sdbootutil update-all-entries >/tmp/sdb.log 2>&1 && log "sdbootutil update-all-entries OK" || { log "sdbootutil returned nonzero:"; tail -20 /tmp/sdb.log; }
fi
if [ -d /boot/grub2 ] && command -v grub2-mkconfig >/dev/null; then
  grub2-mkconfig -o /boot/grub2/grub.cfg >/tmp/gmk.log 2>&1 && log "grub2-mkconfig OK" || { log "grub2-mkconfig returned nonzero:"; tail -20 /tmp/gmk.log; }
fi

# Deterministic fallback: ensure every on-disk BLS entry actually carries the
# options (GRUB2-BLS accepts direct edits to the Type #1 .conf files).
BLS_FILES="$(find /boot -path '*/loader/entries/*.conf' 2>/dev/null || true)"
if [ -z "$BLS_FILES" ]; then
  log "no BLS .conf entries found under /boot (bootloader may be classic grub2)"
else
  for f in $BLS_FILES; do
    for opt in $CMDLINE_ADD; do
      grep -qw "$opt" "$f" || sed -i -E "s/^(options[[:space:]]+.*)$/\1 $opt/" "$f"
    done
    log "BLS entry ensured: $f"
  done
fi

# initramfs: force the dracut 98selinux module (load_policy in the initramfs)
# and regenerate.
mkdir -p /etc/dracut.conf.d
grep -q 'add_dracutmodules' /etc/dracut.conf.d/99-selinux.conf 2>/dev/null || \
  echo 'add_dracutmodules+=" selinux "' > /etc/dracut.conf.d/99-selinux.conf
if command -v mkinitrd >/dev/null; then
  if mkinitrd >/tmp/mkinitrd.log 2>&1; then
    log "initramfs regenerated with selinux module"
  else
    log "WARN: mkinitrd failed:"; tail -20 /tmp/mkinitrd.log
  fi
fi

# AppArmor: not the active MAC backend any more. Disable the service; the
# apparmor=0 cmdline entry prevents the LSM registering at next boot.
if systemctl list-unit-files 2>/dev/null | grep -q '^apparmor.service'; then
  systemctl disable --now apparmor >/dev/null 2>&1 || true
  log "apparmor service disabled"
fi

# Verify the on-disk boot entries now carry security=selinux.
echo "=== on-disk boot entries containing security=selinux ==="
grep -rl 'security=selinux' /boot 2>/dev/null || echo "(none found under /boot)"
echo "=== current /proc/cmdline (pre-reboot, informational) ==="
cat /proc/cmdline
echo "STAGE2-DONE"
RMT
)" || true
printf '%s\n' "$STAGE2"
echo "$STAGE2" | grep -q "STAGE2-DONE" || fail "STAGE 2 script did not complete"
log "RESULT selinux_packages=$(printf '%s\n' "$STAGE2" | grep -oE 'selinux-policy-targeted-[^ ]+|policycoreutils-[^ ]+|selinux-tools-[^ ]+' | sort -u | tr '\n' ' ')"

# ---------------------------------------------------------------------------
# 9. STAGE 3: reboot(s) and proof
# ---------------------------------------------------------------------------
log "== 9. STAGE 3: reboot and proof =="
REBOOT_N=0
REBOOT_LOG=""
reboot_vm() {
  local reason="$1"
  REBOOT_N=$((REBOOT_N + 1))
  log "reboot #$REBOOT_N ($reason)"
  vm_ssh "sudo systemctl reboot" >/dev/null 2>&1 || true
  local down=0
  for i in $(seq 1 60); do
    if ! vm_ssh true >/dev/null 2>&1; then down=1; break; fi
    sleep 3
  done
  [ "$down" = 1 ] || fail "VM did not drop SSH after reboot trigger (#$REBOOT_N: $reason)"
  local t0
  t0="$(date +%s)"
  local up=0
  for i in $(seq 1 120); do
    if vm_ssh true >/dev/null 2>&1; then up=1; break; fi
    sleep 3
  done
  local t1 dt
  t1="$(date +%s)"
  dt=$((t1 - t0))
  [ "$up" = 1 ] || fail "VM did not return to SSH after reboot (#$REBOOT_N: $reason)"
  log "reboot #$REBOOT_N done: SSH back in ${dt}s ($reason)"
  REBOOT_LOG="$REBOOT_LOG
reboot #$REBOOT_N (${reason}): down+up in ${dt}s"
}

probe_state() {
  vm_ssh 'bash -s' <<'RMT'
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "=== /proc/cmdline ==="; cat /proc/cmdline
echo "=== /sys/kernel/security/lsm ==="; cat /sys/kernel/security/lsm
echo "=== sestatus ==="; (command -v sestatus >/dev/null && sestatus) || echo "(sestatus absent)"
echo "=== getenforce ==="; (command -v getenforce >/dev/null && getenforce) || echo "(getenforce absent)"
echo "=== /sys/fs/selinux/enforce ==="; cat /sys/fs/selinux/enforce 2>/dev/null || echo "(absent)"
echo "=== firstboot units ==="; systemctl list-unit-files 2>/dev/null | grep -Ei 'firstboot|jeos' || echo "(none)"
echo "PROBE-DONE"
RMT
}

if [ "$NEED_RELABEL" = "yes" ]; then
  # Reboot 1: SELinux active, permissive (relabel phase)
  reboot_vm "SELinux active in permissive mode (relabel phase)"
  P1="$(probe_state)" || true
  printf '%s\n' "$P1"
  echo "$P1" | grep -q "PROBE-DONE" || fail "permissive-phase probe did not complete"
  LSM_P1="$(printf '%s\n' "$P1" | grep -A1 '=== /sys/kernel/security/lsm ===' | tail -1)"
  ENF_P1="$(printf '%s\n' "$P1" | grep -A1 '=== /sys/fs/selinux/enforce ===' | tail -1 | tr -d ' ')"
  echo "$LSM_P1" | grep -qw selinux || fail "SELinux did not become an active LSM in permissive phase (lsm='$LSM_P1')"
  log "permissive phase: SELinux active (lsm='$LSM_P1', enforce='$ENF_P1')"
  [ "$ENF_P1" = "0" ] || log "NOTE: enforce='$ENF_P1' (expected 0 during relabel phase)"

  # Full relabel while SELinux is active (standard openSUSE/Fedora method).
  log "running full relabel (fixfiles -F restore) while SELinux is active"
  RELABEL="$(vm_ssh 'sudo bash -s' <<'RMT'
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "=== fixfiles -F restore (full relabel) ==="
fixfiles -F restore 2>&1 | tail -30
echo "=== sample labels ==="
for p in / /etc /var /usr /home; do
  echo "$p -> $(getfilecon "$p" 2>/dev/null || echo '?')"
done
echo "RELABEL-DONE"
RMT
)" || true
  printf '%s\n' "$RELABEL"
  echo "$RELABEL" | grep -q "RELABEL-DONE" || fail "relabel did not complete"
  log "relabel complete"

  # Reboot 2: enforcing (flip config + add enforcing=1 to every boot entry).
  log "flipping to enforcing for the final boot"
  vm_ssh 'sudo bash -s' <<'RMT'
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
if [ -f /etc/kernel/cmdline ]; then
  grep -qw enforcing=1 /etc/kernel/cmdline || printf ' enforcing=1' >> /etc/kernel/cmdline
fi
if command -v update-bootloader >/dev/null; then update-bootloader --config || true; fi
if command -v sdbootutil >/dev/null; then sdbootutil update-all-entries || true; fi
for f in $(find /boot -path '*/loader/entries/*.conf' 2>/dev/null || true); do
  grep -qw enforcing=1 "$f" || sed -i -E "s/^(options[[:space:]]+.*)$/\1 enforcing=1/" "$f"
done
echo "=== /etc/selinux/config ==="; cat /etc/selinux/config
echo "=== /etc/kernel/cmdline ==="; cat /etc/kernel/cmdline
echo "FLIP-DONE"
RMT
  log "SELINUX=enforcing set; rebooting for final enforcing boot"
  reboot_vm "final enforcing boot"
else
  log "no relabel needed (image was already SELinux-active): single enforcing reboot"
  reboot_vm "apply enforcing config + cmdline"
fi

# ---------------------------------------------------------------------------
# 10. Final acceptance
# ---------------------------------------------------------------------------
log "== 10. final acceptance =="
ACCEPT="$(vm_ssh 'bash -s' <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "=== /etc/os-release ==="; cat /etc/os-release
echo "=== /proc/cmdline ==="; cat /proc/cmdline
echo "=== /sys/kernel/security/lsm ==="; cat /sys/kernel/security/lsm
echo "=== sestatus ==="; sestatus
echo "=== getenforce ==="; getenforce
echo "=== /sys/fs/selinux/enforce ==="; cat /sys/fs/selinux/enforce
echo "=== systemd failed units ==="
systemctl --failed --no-legend || true
echo "=== sshd active ==="; systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || echo "unknown"
echo "=== bind mount ==="
sudo mkdir -p /mnt/b1 /mnt/b2
sudo mount -t tmpfs tmpfs /mnt/b1
sudo mount --bind /mnt/b1 /mnt/b2
sudo mountpoint -q /mnt/b2 || { echo "FAIL bind"; exit 1; }
sudo umount /mnt/b2; sudo umount /mnt/b1
echo "bind OK"
echo "=== outbound network ==="
if timeout 10 bash -c "exec 3<>/dev/tcp/8.8.8.8/53" 2>/dev/null; then
  echo "outbound OK"
else
  echo "outbound FAIL"
fi
echo "ACCEPTANCE-DONE"
RMT
)" || true
printf '%s\n' "$ACCEPT"
echo "$ACCEPT" | grep -q "ACCEPTANCE-DONE" || fail "acceptance script did not complete"

echo "$ACCEPT" | grep -qi 'opensuse-tumbleweed' || fail "ACCEPT: not openSUSE Tumbleweed"
echo "$ACCEPT" | grep -q 'security=selinux' || fail "ACCEPT: /proc/cmdline missing security=selinux"
echo "$ACCEPT" | grep -q 'selinux=1' || fail "ACCEPT: /proc/cmdline missing selinux=1"
echo "$ACCEPT" | grep -q 'enforcing=1' || fail "ACCEPT: /proc/cmdline missing enforcing=1"
LSM_FINAL="$(printf '%s\n' "$ACCEPT" | grep -A1 '=== /sys/kernel/security/lsm ===' | tail -1)"
echo "$LSM_FINAL" | grep -qw selinux || fail "ACCEPT: selinux not in active LSM ($LSM_FINAL)"
if echo "$LSM_FINAL" | grep -qw apparmor; then
  fail "ACCEPT: apparmor is a concurrently active LSM ($LSM_FINAL)"
fi
echo "$ACCEPT" | grep -qE "SELinux status:[[:space:]]+enabled" || fail "ACCEPT: sestatus not enabled"
echo "$ACCEPT" | grep -qE "Current mode:[[:space:]]+enforcing" || fail "ACCEPT: sestatus current mode != enforcing"
echo "$ACCEPT" | grep -qE "Mode from config file:[[:space:]]+enforcing" || fail "ACCEPT: sestatus config mode != enforcing"
GETENF="$(printf '%s\n' "$ACCEPT" | grep -A1 '=== getenforce ===' | tail -1 | tr -d ' ')"
[ "$GETENF" = "Enforcing" ] || fail "ACCEPT: getenforce != Enforcing (got '$GETENF')"
ENF="$(printf '%s\n' "$ACCEPT" | grep -A1 '=== /sys/fs/selinux/enforce ===' | tail -1 | tr -d ' ')"
[ "$ENF" = "1" ] || fail "ACCEPT: /sys/fs/selinux/enforce != 1 (got '$ENF')"
echo "$ACCEPT" | grep -q "bind OK" || fail "ACCEPT: bind mount failed"
if printf '%s\n' "$ACCEPT" | grep -q "outbound FAIL"; then
  fail "ACCEPT: outbound network failed"
fi
log "FINAL ACCEPTANCE PASSED (selinux=$ENF getenforce=$GETENF lsm='$LSM_FINAL')"
log "RESULT final_selinux=enforcing-OK"
log "RESULT final_lsm=$LSM_FINAL"
log "RESULT final_cmdline=$(printf '%s\n' "$ACCEPT" | grep -A1 '=== /proc/cmdline ===' | tail -1)"

# ---------------------------------------------------------------------------
# 11. Summary + timing
# ---------------------------------------------------------------------------
T1="$(date +%s)"
TOTAL=$((T1 - T0))
log "RESULT total_time=${TOTAL}s"
log "RESULT reboot_count=$REBOOT_N"
log "RESULT reboots:$REBOOT_LOG"

echo
echo "======== TUMBLEWEED SELINUX DISCOVERY SUMMARY ========"
echo "accelerator:   $ACCEL"
echo "kvm access:    ${KVM_ACCESS:-n/a (TCG)}"
echo "image:         $IMG_NAME"
echo "image sha256:  $ACTUAL"
echo "download:      ${DL_TIME}s"
echo "first boot:    ${BOOT_TIME}s to SSH (unattended, no console interaction)"
echo "initial LSM:   $RAW_LSM (selinux=$SELINUX_ACTIVE apparmor=$APPARMOR_ACTIVE)"
echo "relabel:       $NEED_RELABEL"
echo "reboots:       $REBOOT_N$REBOOT_LOG"
echo "final LSM:     $LSM_FINAL"
echo "final cmdline: $(printf '%s\n' "$ACCEPT" | grep -A1 '=== /proc/cmdline ===' | tail -1)"
echo "selinux:       enforcing-OK (getenforce=$GETENF enforce=$ENF)"
echo "total job:     ${TOTAL}s"
echo "======================================================"
log "DISCOVERY COMPLETE"
