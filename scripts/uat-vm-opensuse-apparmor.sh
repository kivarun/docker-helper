#!/usr/bin/env bash
#
# uat-vm-opensuse-apparmor.sh — run the docker-helper black-box UAT for
# UAT_PLATFORM=opensuse / UAT_INSTALL=rpm / UAT_MAC=apparmor inside a real
# openSUSE Tumbleweed Cloud VM booted on a GitHub-hosted ubuntu-24.04 runner
# (QEMU/KVM).
#
# Responsibility boundary:
#
#   host workflow
#       |  (this script: image + checksum, cloud-init seed, QEMU boot, SSH,
#       |   repo + RPM transfer into the guest)
#       v
#   Tumbleweed VM harness
#       |  (this script: guest MAC bootstrap — switch the guest to AppArmor
#       |   enforcing via the kernel cmdline, SELinux disabled; then
#       |   install-deps through the existing openSUSE platform adapter)
#       v
#   existing black-box UAT        (scripts/uat-blackbox.sh inside the guest)
#
# This script owns VM transport and the guest MAC bootstrap ONLY. It does not
# reimplement platform or MAC semantics: the guest-side UAT is the existing
# scripts/uat-blackbox.sh with its uat-platform-opensuse.sh (platform owner)
# and uat-mac-apparmor.sh (MAC owner) adapters, which remain the owners of
# their concerns. The platform adapter describes an already-working openSUSE
# system; this harness is what turns the guest into one.
#
# The guest is booted from the official openSUSE Tumbleweed Minimal-VM Cloud
# qcow2 (checksum verified, bounded mirror fallback, qcow overlay, cloud-init
# NoCloud, SSH key, serial log, unattended first boot, user-mode networking).
# The image ships SELinux-active by default, so the harness switches the next
# boot to AppArmor (`security=apparmor apparmor=1 selinux=0`) through the
# image's bootloader — the mechanism proven by the Tumbleweed SELinux
# discovery — and proves AppArmor is the active LSM (and SELinux is NOT)
# before running the UAT.
#
# The RPM is never rebuilt here: the exact bytes built by the hosted
# uat-rpm-build job are copied into the guest and the producer SHA-256 is
# verified strictly by the UAT before install (UAT_ARTIFACT_PATH /
# UAT_ARTIFACT_SHA256).
#
# Env inputs:
#   UAT_REPO_DIR     host checkout of docker-helper (default: repo root of this script)
#   UAT_RPM          path to the exact prebuilt RPM artifact
#   UAT_RPM_SHA256   expected SHA-256 produced by the build job
#   UAT_VERSION      version string (default 2.0.0-uat)
#   UAT_KEEP         keep the VM/workdir on failure for debugging
#
# Exit 0 = full openSUSE/AppArmor black-box UAT passed inside the guest.
# Nonzero = failed; serial tail + guest evidence are printed.

set -euo pipefail

PREFIX="[opensuse-uat-vm]"
log()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
UAT_RPM="${UAT_RPM:-}"
UAT_RPM_SHA256="${UAT_RPM_SHA256:-}"
VERSION="${UAT_VERSION:-2.0.0-uat}"
KEEP="${UAT_KEEP:-}"

[ -n "$UAT_RPM" ] || fail "UAT_RPM is required (exact prebuilt RPM artifact)"
[ -f "$UAT_RPM" ] || fail "UAT_RPM is not a file: $UAT_RPM"
[ -n "$UAT_RPM_SHA256" ] || fail "UAT_RPM_SHA256 is required (producer SHA-256)"
[ -f "$UAT_REPO_DIR/scripts/uat-blackbox.sh" ] \
  || fail "UAT_REPO_DIR has no scripts/uat-blackbox.sh: $UAT_REPO_DIR"

WORKDIR="$(mktemp -d /tmp/opensuse-apparmor-uat.XXXXXX)"
cd "$WORKDIR"

IMG_NAME="openSUSE-Tumbleweed-Minimal-VM.x86_64-Cloud.qcow2"
SSH_OPTS=(-i "$WORKDIR/id_ed25519" -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR)
vm_ssh() { ssh "${SSH_OPTS[@]}" -p 2222 opc@127.0.0.1 "$@"; }
vm_scp() { scp "${SSH_OPTS[@]}" -P 2222 "$@"; }

T0="$(date +%s)"
REBOOT_TIME="n/a"

cleanup() {
  if [ -n "$KEEP" ]; then
    log "UAT_KEEP set: leaving workdir at $WORKDIR"
    return 0
  fi
  if [ -f qemu.pid ]; then
    kill "$(cat qemu.pid)" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

serial_tail() {
  echo
  echo "================ QEMU SERIAL LOG (last 80) ================"
  [ -f serial.log ] && tail -80 serial.log || true
  echo "============================================================"
}

guest_evidence() {
  local out
  out="$(vm_ssh 'bash -s' <<'RMT' 2>/dev/null
set +e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "--- guest /proc/cmdline ---"; cat /proc/cmdline
echo "--- guest /sys/kernel/security/lsm ---"; cat /sys/kernel/security/lsm; echo
echo "--- /sys/module/apparmor/parameters/enabled ---"; cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo "(absent)"
echo "--- aa-status ---"; (command -v aa-status >/dev/null 2>&1 && aa-status 2>&1) || echo "(aa-status absent)"
echo "--- docker-helper service ---"; systemctl status docker-helper.service --no-pager 2>&1 | head -30
echo "--- docker-helper journal (last 80) ---"; journalctl -u docker-helper.service -n 80 --no-pager 2>&1
echo "--- systemd ---"; systemctl is-system-running 2>&1
RMT
)" || true
  printf '%s\n' "$out"
}

ERR_HANDLED=0
on_err() {
  [ "$ERR_HANDLED" = 1 ] && return 0
  ERR_HANDLED=1
  echo
  echo "================ HARNESS FAILURE DIAGNOSTICS ==============="
  serial_tail
  if vm_ssh true 2>/dev/null; then
    guest_evidence
  else
    echo "(guest not SSH-reachable)"
  fi
  echo "============================================================"
}
trap on_err ERR

# ---------------------------------------------------------------------------
# 1. virtualization + accelerator
# ---------------------------------------------------------------------------
log "== 1. virtualization + accelerator =="
ACCEL="tcg"
if [ -e /dev/kvm ]; then
  ACCEL="kvm"
fi
CPU_OPTS="-cpu max"
[ "$ACCEL" = "kvm" ] && CPU_OPTS="-cpu host"
if [ "$ACCEL" = "kvm" ]; then
  if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    log "kvm access: direct"
  else
    sudo -n chmod 666 /dev/kvm || fail "could not grant /dev/kvm access via sudo"
    log "kvm access: granted (sudo chmod 666 /dev/kvm)"
  fi
fi
log "accelerator=$ACCEL ($CPU_OPTS)"

# ---------------------------------------------------------------------------
# 2. official cloud image + checksum + grow
# ---------------------------------------------------------------------------
log "== 2. download official Tumbleweed Cloud image + checksum =="
fetch_or_fail() {
  local name="$1"; shift
  local url
  for url in "$@"; do
    log "  trying $url"
    if curl -fL --connect-timeout 10 --max-time 600 --retry 2 --retry-delay 2 -o "$name" "$url"; then
      return 0
    fi
  done
  return 1
}
IMG_DIR="tumbleweed/appliances/$IMG_NAME"
fetch_or_fail "$IMG_NAME" \
  "https://download.opensuse.org/$IMG_DIR" \
  "https://ftp.fau.de/opensuse/$IMG_DIR" \
  "https://mirror.library.ucy.ac.cy/linux/opensuse/$IMG_DIR" \
  || fail "image download failed from all mirrors"
fetch_or_fail "$IMG_NAME.sha256" \
  "https://download.opensuse.org/$IMG_DIR.sha256" \
  "https://ftp.fau.de/opensuse/$IMG_DIR.sha256" \
  "https://mirror.library.ucy.ac.cy/linux/opensuse/$IMG_DIR.sha256" \
  || fail "checksum download failed from all mirrors"
EXPECTED="$(awk '{print $1}' "$IMG_NAME.sha256")"
[ -n "$EXPECTED" ] || fail "could not parse expected SHA-256 from .sha256"
ACTUAL="$(sha256sum "$IMG_NAME" | awk '{print $1}')"
[ "$ACTUAL" = "$EXPECTED" ] || fail "image checksum mismatch (expected $EXPECTED, got $ACTUAL)"
log "image SHA-256 verified: $ACTUAL"

qemu-img create -f qcow2 -b "$IMG_NAME" -F qcow2 disk.qcow2 >/dev/null
qemu-img resize disk.qcow2 12G >/dev/null
log "overlay disk created and resized to 12G (cloud-init growpart expands root)"

# ---------------------------------------------------------------------------
# 3. cloud-init seed + boot
# ---------------------------------------------------------------------------
log "== 3. cloud-init seed =="
ssh-keygen -t ed25519 -N "" -f id_ed25519 >/dev/null

cat > user-data <<EOF
#cloud-config
hostname: tw-uat
ssh_pwauth: false
disable_root: true
users:
  - name: opc
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
# cloud-init manages the system, but mask the services anyway so no interactive
# firstboot can ever prompt on the console. Harmless if the units are absent.
runcmd:
  - [ sh, -c, "systemctl disable --now jeos-firstboot.service 2>/dev/null || true" ]
  - [ sh, -c, "systemctl disable --now systemd-firstboot.service 2>/dev/null || true" ]
  - [ sh, -c, "echo tw-uat-boot-complete > /var/log/tw-uat.marker" ]
EOF

cat > meta-data <<EOF
instance-id: opensuse-apparmor-uat-001
local-hostname: tw-uat
EOF

cloud-localds seed.iso user-data meta-data

log "== 4. boot VM (accelerator=$ACCEL, $CPU_OPTS) =="
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
log "qemu running: pid=$QEMU_PID"

# ---------------------------------------------------------------------------
# 5. STAGE 1: wait for SSH (unattended first boot)
# ---------------------------------------------------------------------------
log "== 5. STAGE 1: wait for SSH (unattended first boot, max 360s) =="
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

marker=0
for i in $(seq 1 36); do
  if vm_ssh "test -f /var/log/tw-uat.marker" 2>/dev/null; then
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

# ---------------------------------------------------------------------------
# 6. STAGE 1.5: actual initial MAC state (the image ships SELinux-active)
# ---------------------------------------------------------------------------
log "== 6. STAGE 1.5: initial MAC state =="
STATE="$(vm_ssh 'bash -s' <<'RMT'
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "=== /sys/kernel/security/lsm ==="; cat /sys/kernel/security/lsm
echo "=== /proc/cmdline ==="; cat /proc/cmdline
echo "=== aa-status ==="; (command -v aa-status >/dev/null 2>&1 && aa-status 2>&1) || echo "(aa-status absent)"
echo "=== sestatus ==="; (command -v sestatus >/dev/null 2>&1 && sestatus 2>&1) || echo "(sestatus absent)"
echo "STATE-DONE"
RMT
)" || true
printf '%s\n' "$STATE"
echo "$STATE" | grep -q "STATE-DONE" || fail "initial state script did not complete"
RAW_LSM="$(printf '%s\n' "$STATE" | grep -A1 '=== /sys/kernel/security/lsm ===' | tail -1)"
SELINUX_ACTIVE="no"
APPARMOR_ACTIVE="no"
echo "$RAW_LSM" | grep -qw selinux  && SELINUX_ACTIVE="yes"
echo "$RAW_LSM" | grep -qw apparmor && APPARMOR_ACTIVE="yes"
log "initial LSM: $RAW_LSM (selinux=$SELINUX_ACTIVE apparmor=$APPARMOR_ACTIVE)"

# ---------------------------------------------------------------------------
# 7. STAGE 2: AppArmor bootstrap (install userspace + switch MAC backend)
# ---------------------------------------------------------------------------
log "== 7. STAGE 2: AppArmor bootstrap =="
BOOTSTRAP="$(vm_ssh 'sudo bash -s' <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
log(){ echo "[vm] $*"; }

NEW_TOKENS="security=apparmor apparmor=1 selinux=0"

# set_cmdline removes any prior MAC/security=* selector tokens and appends the
# target AppArmor token set. Works for /etc/kernel/cmdline,
# GRUB_CMDLINE_LINUX_DEFAULT and BLS options lines alike.
set_cmdline() {
  local old="$1" out=""
  local t
  for t in $old; do
    case "$t" in
      security=*|selinux=*|enforcing=*|apparmor=*) ;;
      *) out="$out $t" ;;
    esac
  done
  printf '%s %s' "$out" "$NEW_TOKENS"
}

log "installing AppArmor userspace: apparmor-parser apparmor-utils apparmor-abstractions"
zypper --non-interactive refresh || true
zypper --non-interactive install -y --no-recommends \
  apparmor-parser apparmor-utils apparmor-abstractions
log "AppArmor packages:"
rpm -qa | grep -Ei 'apparmor|libapparmor' | sort || true

log "tool providers:"
for b in apparmor_parser aa-status aa-enabled; do
  p="$(command -v "$b" 2>/dev/null || true)"
  if [ -n "$p" ]; then
    log "tool $b -> $p ($(rpm -qf "$p" 2>/dev/null || echo unknown))"
  else
    log "tool $b -> MISSING"
  fi
done

# --- kernel cmdline: switch to AppArmor in every source and regenerate. ---
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

# Deterministic fallback: ensure every on-disk BLS entry carries the AppArmor
# tokens (GRUB2-BLS accepts direct edits to the Type #1 .conf files).
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

# --- Enable the AppArmor service (loads /etc/apparmor.d profiles at boot). ---
if systemctl list-unit-files 2>/dev/null | grep -q '^apparmor.service'; then
  systemctl enable apparmor.service >/dev/null 2>&1 \
    && log "apparmor.service enabled" || log "WARN: could not enable apparmor.service"
fi

echo "=== on-disk boot entries containing security=apparmor ==="
grep -rl 'security=apparmor' /boot 2>/dev/null || echo "(none found under /boot)"
echo "=== current /proc/cmdline (pre-reboot, informational) ==="
cat /proc/cmdline
echo "BOOTSTRAP-DONE"
RMT
)" || true
printf '%s\n' "$BOOTSTRAP"
echo "$BOOTSTRAP" | grep -q "BOOTSTRAP-DONE" || fail "AppArmor bootstrap script did not complete"

# ---------------------------------------------------------------------------
# 8. reboot + STAGE 3: prove AppArmor is the active LSM
# ---------------------------------------------------------------------------
reboot_vm() {
  log "reboot ($1)"
  vm_ssh "sudo systemctl reboot" >/dev/null 2>&1 || true
  local down=0 i
  for i in $(seq 1 60); do
    if ! vm_ssh true >/dev/null 2>&1; then down=1; break; fi
    sleep 3
  done
  [ "$down" = 1 ] || fail "VM did not drop SSH after reboot trigger"
  local t0 t1 dt up=0
  t0="$(date +%s)"
  for i in $(seq 1 120); do
    if vm_ssh true >/dev/null 2>&1; then up=1; break; fi
    sleep 3
  done
  t1="$(date +%s)"
  dt=$((t1 - t0))
  [ "$up" = 1 ] || fail "VM did not return to SSH after reboot"
  REBOOT_TIME="$dt"
  log "reboot done: SSH back in ${dt}s"
}

log "== 8. STAGE 3: reboot into AppArmor and prove it =="
reboot_vm "apply AppArmor cmdline (security=apparmor apparmor=1 selinux=0)"

PROOF="$(vm_ssh 'bash -s' <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "CMDLINE_VAL=$(cat /proc/cmdline)"
echo "LSM_VAL=$(cat /sys/kernel/security/lsm)"
echo "AA_ENABLED_VAL=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo absent)"
echo "=== /etc/os-release ==="; cat /etc/os-release
echo "=== systemd ==="; systemctl is-system-running 2>&1 || true
echo "=== sshd ==="; systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || echo "unknown"
echo "=== aa-status ==="; aa-status 2>&1 | head -40
echo "=== apparmor service ==="; systemctl is-active apparmor.service 2>&1 || true
echo "PROOF-DONE"
RMT
)" || true
printf '%s\n' "$PROOF"
echo "$PROOF" | grep -q "PROOF-DONE" || fail "AppArmor proof script did not complete"

CMDLINE_FINAL="$(printf '%s\n' "$PROOF" | sed -n 's/^CMDLINE_VAL=//p' | tail -1)"
LSM_FINAL="$(printf '%s\n' "$PROOF" | sed -n 's/^LSM_VAL=//p' | tail -1)"
AA_ENABLED="$(printf '%s\n' "$PROOF" | sed -n 's/^AA_ENABLED_VAL=//p' | tail -1 | tr -d '[:space:]')"
echo "$PROOF" | grep -qi 'opensuse-tumbleweed' || fail "ACCEPT: not openSUSE Tumbleweed"
echo "$CMDLINE_FINAL" | grep -q 'security=apparmor' || fail "ACCEPT: cmdline missing security=apparmor"
echo "$CMDLINE_FINAL" | grep -q 'apparmor=1' || fail "ACCEPT: cmdline missing apparmor=1"
echo "$CMDLINE_FINAL" | grep -q 'selinux=0' || fail "ACCEPT: cmdline missing selinux=0"
echo "$LSM_FINAL" | grep -qw apparmor || fail "ACCEPT: apparmor not in active LSM ($LSM_FINAL)"
if echo "$LSM_FINAL" | grep -qw selinux; then
  fail "ACCEPT: selinux still an active LSM ($LSM_FINAL)"
fi
[ "$AA_ENABLED" = "Y" ] || fail "ACCEPT: /sys/module/apparmor/parameters/enabled != Y (got '$AA_ENABLED')"
log "AppArmor proof passed: lsm='$LSM_FINAL' aa_enabled=$AA_ENABLED"

# ---------------------------------------------------------------------------
# 9. STAGE 4: transfer repo + RPM into the guest
# ---------------------------------------------------------------------------
log "== 9. STAGE 4: transfer repo + RPM into the guest =="
vm_ssh "mkdir -p /opt/uat /opt/uat-import" || fail "could not create guest import dirs"

log "copying host checkout into guest (/opt/uat)"
tar -C "$UAT_REPO_DIR" -czf repo.tgz \
  --exclude=.git --exclude=dist --exclude=uat-curl --exclude=docker-helper .
vm_ssh "tar xzf - -C /opt/uat" < repo.tgz || fail "repo transfer to guest failed"

log "copying RPM artifact into guest (/opt/uat-import/docker-helper.rpm)"
vm_scp "$UAT_RPM" opc@127.0.0.1:/opt/uat-import/docker-helper.rpm || fail "RPM transfer to guest failed"

# ---------------------------------------------------------------------------
# 10. STAGE 5: run the existing black-box UAT inside the guest
# ---------------------------------------------------------------------------
log "== 10. STAGE 5: black-box UAT inside the guest =="
log "install-deps (UAT_PLATFORM=opensuse scripts/uat-blackbox.sh install-deps)"
if ! vm_ssh "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_PLATFORM=opensuse scripts/uat-blackbox.sh install-deps"; then
  guest_evidence || true
  serial_tail
  fail "guest install-deps failed"
fi

log "black-box UAT (UAT_PLATFORM=opensuse UAT_INSTALL=rpm UAT_MAC=apparmor, prebuilt RPM)"
if ! vm_ssh "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_VERSION=$VERSION UAT_PLATFORM=opensuse UAT_INSTALL=rpm UAT_MAC=apparmor UAT_ARTIFACT_PATH=/opt/uat-import/docker-helper.rpm UAT_ARTIFACT_SHA256=$UAT_RPM_SHA256 scripts/uat-blackbox.sh"; then
  EC=$?
  guest_evidence || true
  serial_tail
  fail "black-box UAT inside the guest failed (exit $EC)"
fi
log "black-box UAT passed inside the guest"

# ---------------------------------------------------------------------------
# 11. Summary
# ---------------------------------------------------------------------------
T1="$(date +%s)"
TOTAL=$((T1 - T0))
echo
echo "======= OPENSSUSE/APPARMOR UAT (TUMBLEWEED VM) SUMMARY ======="
echo "image:            $IMG_NAME"
echo "image sha256:     $ACTUAL"
echo "first boot:       ${BOOT_TIME}s to SSH"
echo "MAC-switch reboot: ${REBOOT_TIME}s back to SSH"
echo "initial LSM:      $RAW_LSM (selinux=$SELINUX_ACTIVE apparmor=$APPARMOR_ACTIVE)"
echo "final LSM:        $LSM_FINAL"
echo "final cmdline:    $CMDLINE_FINAL"
echo "RPM:              $UAT_RPM"
echo "RPM sha256:       $UAT_RPM_SHA256 (producer, verified by UAT)"
echo "UAT version:      $VERSION"
echo "total:            ${TOTAL}s"
echo "RESULT: openSUSE/AppArmor black-box UAT PASSED inside Tumbleweed VM"
echo "=============================================================="
log "DONE"
