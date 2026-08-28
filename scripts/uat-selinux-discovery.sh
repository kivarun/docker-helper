#!/usr/bin/env bash
#
# uat-selinux-discovery.sh — PoC: boot a real SELinux=enforcing Linux VM on a
# GitHub-hosted ubuntu-24.04 public runner using QEMU (KVM if available, else
# TCG), then prove SELinux enforcing and basic VM suitability from inside.
#
# This is a DISCOVERY workflow (workflow_dispatch only). It does NOT run the
# docker-helper UAT, does not touch release workflows, and makes no production
# changes. It only answers: can we get a genuine SELinux-enforcing Linux VM
# (systemd, mounts, network) on a public hosted runner?
#
# The accelerator decision is explicit in the log and never hidden:
#   /dev/kvm present  -> KVM
#   otherwise         -> TCG
#
# The guest image is the official Rocky Linux 9 GenericCloud Base qcow2,
# downloaded from dl.rockylinux.org and verified against the official
# CHECKSUM file. No custom image is built.
#
# Exit codes: 0 = full proof, nonzero = discovery failed (job shows why).

set -euo pipefail

WORKDIR="$(mktemp -d /tmp/selinux-discovery.XXXXXX)"
cd "$WORKDIR"

T0="$(date +%s)"
log()  { printf '[discovery] %s\n' "$*"; }
fail() { printf '[discovery] FAILED: %s\n' "$*" >&2; exit 1; }

SSH_OPTS="-i id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR"

# SUDO is set to "sudo -n" only when KVM must be accessed as root (hosted
# runners: /dev/kvm is 0660 root:kvm and the runner user is not in kvm group).
# Empty otherwise, so commands run as the invoking user.
SUDO=""

IMG_BASE_URL="https://dl.rockylinux.org/pub/rocky/9/images/x86_64"
IMG_NAME="Rocky-9-GenericCloud-Base.latest.x86_64.qcow2"
IMG_URL="$IMG_BASE_URL/$IMG_NAME"

cleanup() {
  if [ -f qemu.pid ]; then
    $SUDO kill "$(cat qemu.pid)" 2>/dev/null || true
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
# 2. Accelerator decision (explicit, never hidden)
# ---------------------------------------------------------------------------
ACCEL="tcg"
if [ -e /dev/kvm ]; then
  ACCEL="kvm"
fi
log "== 2. accelerator = $ACCEL =="
log "RESULT accelerator=$ACCEL"

CPU_OPTS="-cpu max"
[ "$ACCEL" = "kvm" ] && CPU_OPTS="-cpu host"

# On GitHub-hosted runners /dev/kvm is typically 0660 root:kvm and the runner
# user is not in the kvm group. If the user cannot open it directly, run qemu
# under passwordless sudo so KVM is still used (explicit, not hidden).
if [ "$ACCEL" = "kvm" ]; then
  if exec 3< /dev/kvm 2>/dev/null; then
    exec 3<&- 2>/dev/null || true
    log "kvm access: direct (runner user can open /dev/kvm)"
    KVM_ACCESS="direct"
  else
    log "kvm access: restricted (runner user cannot open /dev/kvm)"
    log "will run qemu via passwordless sudo to use KVM"
    SUDO="sudo -n"
    KVM_ACCESS="sudo"
  fi
  log "RESULT kvm_access=$KVM_ACCESS"
fi

# ---------------------------------------------------------------------------
# 3. Official cloud image (no custom image build)
# ---------------------------------------------------------------------------
log "== 3. download official Rocky 9 GenericCloud image =="
T_DL_START="$(date +%s)"
curl -fL --retry 3 --retry-delay 2 -o "$IMG_NAME" "$IMG_URL"
T_DL_END="$(date +%s)"
DL_TIME=$((T_DL_END - T_DL_START))
log "downloaded: $IMG_NAME ($(du -h "$IMG_NAME" | cut -f1)) in ${DL_TIME}s"
log "RESULT download_time=${DL_TIME}s"

# Verify against the official CHECKSUM file (same dir, name + .CHECKSUM).
curl -fsSL -o "$IMG_NAME.CHECKSUM" "$IMG_URL.CHECKSUM"
EXPECTED="$(sed -n 's/.*SHA256 (.*) = //p' "$IMG_NAME.CHECKSUM" | tail -1)"
[ -n "$EXPECTED" ] || fail "could not parse expected SHA-256 from CHECKSUM file"
ACTUAL="$(sha256sum "$IMG_NAME" | awk '{print $1}')"
[ "$ACTUAL" = "$EXPECTED" ] || fail "image checksum mismatch (expected $EXPECTED, got $ACTUAL)"
log "image SHA-256 verified: $ACTUAL"

# Overlay disk so the pristine base image is never modified.
qemu-img create -f qcow2 -b "$IMG_NAME" -F qcow2 disk.qcow2 >/dev/null

# ---------------------------------------------------------------------------
# 4. cloud-init seed (fully automatic, no interaction)
# ---------------------------------------------------------------------------
log "== 4. cloud-init seed =="
ssh-keygen -t ed25519 -N "" -f id_ed25519 >/dev/null

cat > user-data <<EOF
#cloud-config
ssh_pwauth: false
users:
  - name: uat
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat id_ed25519.pub)
growpart:
  mode: auto
  devices: ["/"]
runcmd:
  - [ sh, -c, "echo selinux-discovery-boot-complete > /var/log/selinux-discovery.marker" ]
EOF

cat > meta-data <<EOF
instance-id: selinux-discovery-001
local-hostname: selinux-uat
EOF

cloud-localds seed.iso user-data meta-data
ls -l seed.iso

# ---------------------------------------------------------------------------
# 5. Boot the VM
# ---------------------------------------------------------------------------
log "== 5. boot VM (accelerator=$ACCEL, $CPU_OPTS${SUDO:+ via sudo}) =="
$SUDO qemu-system-x86_64 \
  -machine "accel=$ACCEL" \
  $CPU_OPTS \
  -smp 2 -m 2048 \
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
ps -p "$QEMU_PID" >/dev/null 2>&1 || fail "qemu process exited early (pid $QEMU_PID)"
log "qemu running: pid=$QEMU_PID accelerator=$ACCEL${SUDO:+ (as root via sudo)}"

# ---------------------------------------------------------------------------
# 6. Wait for SSH
# ---------------------------------------------------------------------------
log "== 6. wait for SSH (max 300s) =="
T_BOOT_START="$(date +%s)"
ready=0
for i in $(seq 1 60); do
  if ssh $SSH_OPTS -p 2222 uat@127.0.0.1 true 2>/dev/null; then
    ready=1
    break
  fi
  sleep 5
done
T_BOOT_END="$(date +%s)"
BOOT_TIME=$((T_BOOT_END - T_BOOT_START))
[ "$ready" = 1 ] || fail "VM did not become SSH-ready in ${BOOT_TIME}s"
log "SSH ready after ${BOOT_TIME}s"
log "RESULT boot_to_ssh=${BOOT_TIME}s"

# Best-effort: wait for cloud-init to finish (marker), max 120s.
marker=0
for i in $(seq 1 24); do
  if ssh $SSH_OPTS -p 2222 uat@127.0.0.1 'test -f /var/log/selinux-discovery.marker' 2>/dev/null; then
    marker=1
    break
  fi
  sleep 5
done
if [ "$marker" = 1 ]; then
  log "cloud-init completed (marker present)"
else
  log "WARN: cloud-init marker not seen in 120s (continuing anyway)"
fi

# ---------------------------------------------------------------------------
# 7. SELinux proof (inside VM)
# ---------------------------------------------------------------------------
log "== 7. SELinux proof (inside VM) =="
PROOF_CMD='set -e
echo "=== uname -a ==="; uname -a
echo "=== /etc/os-release ==="; cat /etc/os-release
echo "=== sestatus ==="; sestatus
echo "GETENFORCE_VAL=$(getenforce)"
echo "ENFORCE_VAL=$(cat /sys/fs/selinux/enforce)"'
PROOF="$(ssh $SSH_OPTS -p 2222 uat@127.0.0.1 "$PROOF_CMD")"
printf '%s\n' "$PROOF"

echo "$PROOF" | grep -qE "SELinux status:[[:space:]]+enabled" \
  || fail "SELinux status is not 'enabled'"
echo "$PROOF" | grep -qE "Current mode:[[:space:]]+enforcing" \
  || fail "SELinux current mode is not 'enforcing'"
GETENFORCE="$(printf '%s\n' "$PROOF" | sed -n 's/^GETENFORCE_VAL=//p' | tail -1)"
ENFORCE="$(printf '%s\n' "$PROOF" | sed -n 's/^ENFORCE_VAL=//p' | tail -1)"
[ "$GETENFORCE" = "Enforcing" ] || fail "getenforce != Enforcing (got '$GETENFORCE')"
[ "$ENFORCE" = "1" ] || fail "/sys/fs/selinux/enforce != 1 (got '$ENFORCE')"
log "SELinux enforcing confirmed (getenforce=$GETENFORCE, enforce=$ENFORCE)"
log "RESULT selinux=enforcing-OK"

# ---------------------------------------------------------------------------
# 8. VM suitability (inside VM)
# ---------------------------------------------------------------------------
log "== 8. VM suitability checks =="
SUIT_CMD='set -euo pipefail
echo "=== systemd ==="
systemctl is-system-running || echo "(system not fully running - informational, not a blocker)"
systemctl is-active systemd-journald.service >/dev/null || { echo "FAIL: systemd-journald not active"; exit 1; }
echo "systemd OK"
echo "=== mount/bind ==="
sudo mkdir -p /mnt/t1 /mnt/t2
sudo mount -t tmpfs tmpfs /mnt/t1
sudo mount --bind /mnt/t1 /mnt/t2
sudo mountpoint -q /mnt/t2 || { echo "FAIL: bind mount not visible"; exit 1; }
sudo umount /mnt/t2
sudo umount /mnt/t1
echo "mount/bind OK"
echo "=== loopback ==="
ip link show lo | grep -q LOOPBACK || { echo "FAIL: lo missing"; exit 1; }
echo "loopback OK"
echo "=== network (outbound TCP) ==="
if timeout 8 bash -c "exec 3<>/dev/tcp/8.8.8.8/53" 2>/dev/null; then
  echo "outbound TCP OK (8.8.8.8:53)"
else
  echo "WARN: outbound TCP to 8.8.8.8:53 failed"
fi
echo "=== disk ==="
df -h /
echo "SUITABILITY-DONE"'
if SUIT="$(ssh $SSH_OPTS -p 2222 uat@127.0.0.1 "$SUIT_CMD")"; then
  printf '%s\n' "$SUIT"
else
  printf '%s\n' "$SUIT"
  fail "VM suitability checks failed (see output above)"
fi
echo "$SUIT" | grep -q 'SUITABILITY-DONE' || fail "suitability script did not complete"
echo "$SUIT" | grep -q 'mount/bind OK' || fail "mount/bind check did not report OK"

# ---------------------------------------------------------------------------
# 9. Summary + timing
# ---------------------------------------------------------------------------
T1="$(date +%s)"
TOTAL=$((T1 - T0))
log "RESULT total_time=${TOTAL}s"

echo
echo "======== DISCOVERY SUMMARY ========"
echo "accelerator:   $ACCEL"
echo "kvm access:    ${KVM_ACCESS:-n/a (TCG)}"
echo "image:         $IMG_NAME"
echo "download:      ${DL_TIME}s"
echo "boot -> ssh:   ${BOOT_TIME}s"
echo "total job:     ${TOTAL}s"
echo "selinux:       enforcing-OK"
echo "==================================="
log "DISCOVERY COMPLETE"
