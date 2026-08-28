#!/usr/bin/env bash
#
# uat-vm-opensuse-selinux.sh — run the docker-helper black-box UAT for
# UAT_PLATFORM=opensuse / UAT_INSTALL=rpm / UAT_MAC=selinux inside a real
# openSUSE Tumbleweed Cloud VM booted on a GitHub-hosted ubuntu-24.04 runner
# (QEMU/KVM).
#
# Responsibility boundary (sibling of scripts/uat-vm-opensuse-apparmor.sh):
#
#   host workflow
#       |  (this file: SELinux-specific orchestration ONLY)
#       v
#   Tumbleweed VM harness    (scripts/uat-vm-tumbleweed.sh, sourced below)
#       |  image + checksum, qcow overlay + resize, KVM/TCG selection,
#       |  cloud-init NoCloud seed, unattended boot, vm_ssh/vm_scp transport,
#       |  wait-for-SSH, canonical reboot, serial-log diagnostics, labeled
#       |  cmdline+LSM evidence, boot-config MAC selector mutation.
#       v
#   existing black-box UAT   (scripts/uat-blackbox.sh inside the guest, with
#                             scripts/uat-platform-opensuse.sh platform owner
#                             and scripts/uat-mac-selinux.sh MAC owner)
#
# This file owns the guest MAC bootstrap ONLY — which backend to select and how
# to prove it — plus copying the checkout and the exact prebuilt RPM into the
# guest, running the existing UAT, and then the SELinux mount-pin / RPM
# postinstall regression (scripts/uat-selinux-mount-pin-regression.sh). All VM
# mechanics live in the harness; the guest-side UAT is the existing
# scripts/uat-blackbox.sh with its uat-platform-opensuse.sh (platform owner)
# and uat-mac-selinux.sh (MAC owner) adapters, which remain the owners of their
# concerns.
#
# Flow:
#   create/start Tumbleweed VM through the common harness (vm_init)
#       -> inspect initial MAC state (harness evidence primitives)
#       -> install/verify SELinux userspace + targeted policy
#       -> ensure /etc/selinux/config = enforcing / targeted
#       -> select security=selinux selinux=1 apparmor=0 enforcing=1 through the
#          harness cmdline primitive (vm_set_mac_tokens)
#       -> reboot through the harness (vm_reboot)
#       -> prove real SELinux enforcing / AppArmor absent
#       -> copy checkout + exact RPM into the guest
#       -> install-deps (UAT_PLATFORM=opensuse)
#       -> existing black-box UAT (UAT_PLATFORM=opensuse UAT_INSTALL=rpm
#          UAT_MAC=selinux, prebuilt RPM)
#       -> SELinux mount-pin / RPM postinstall regression
#
# The Tumbleweed cloud image ships SELinux-active by default (the filesystem
# is already labeled for the targeted policy), so the harness keeps SELinux as
# the LSM — the tokens are selected through the image's bootloader, and one
# enforcing reboot proves persistence. No relabel is needed.
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
# Exit 0 = full openSUSE/SELinux black-box UAT + mount-pin regression passed
# inside the guest. Nonzero = failed; serial tail + guest evidence are printed.

set -euo pipefail

PREFIX="[opensuse-selinux-vm]"
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

# ---------------------------------------------------------------------------
# canonical Tumbleweed VM harness (VM mechanics; no MAC/package/UAT knowledge)
# ---------------------------------------------------------------------------
# shellcheck source=scripts/uat-vm-tumbleweed.sh
source "$SCRIPT_DIR/uat-vm-tumbleweed.sh"

T0="$(date +%s)"

# The harness owns the EXIT cleanup trap (workdir lifecycle) but not the ERR
# diagnostics trap: this file composes its own, using the harness serial-log
# primitive plus docker-helper guest evidence (which the harness must not know).
ERR_HANDLED=0
on_err() {
  [ "$ERR_HANDLED" = 1 ] && return 0
  ERR_HANDLED=1
  echo
  echo "================ HARNESS FAILURE DIAGNOSTICS ==============="
  vm_serial_tail
  if vm_ssh true 2>/dev/null; then
    guest_evidence
  else
    echo "(guest not SSH-reachable)"
  fi
  echo "============================================================"
}
trap on_err ERR

guest_evidence() {
  local out
  out="$(vm_ssh 'bash -s' <<'RMT' 2>/dev/null
set +e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "--- guest /proc/cmdline ---"; cat /proc/cmdline
echo "--- guest /sys/kernel/security/lsm ---"; cat /sys/kernel/security/lsm; echo
echo "--- sestatus ---"; (command -v sestatus >/dev/null 2>&1 && sestatus 2>&1) || echo "(sestatus absent)"
echo "--- getenforce ---"; (command -v getenforce >/dev/null 2>&1 && getenforce 2>&1) || echo "(getenforce absent)"
echo "--- loaded docker_helper policy modules ---"; (command -v semodule >/dev/null 2>&1 && semodule -l 2>&1 | grep docker_helper) || echo "(semodule absent)"
echo "--- docker-helper service ---"; systemctl status docker-helper.service --no-pager 2>&1 | head -30
echo "--- docker-helper journal (last 80) ---"; journalctl -u docker-helper.service -n 80 --no-pager 2>&1
echo "--- systemd ---"; systemctl is-system-running 2>&1
RMT
)" || true
  printf '%s\n' "$out"
}

# ---------------------------------------------------------------------------
# 1. create/start the Tumbleweed VM through the common harness
# ---------------------------------------------------------------------------
log "== 1. start Tumbleweed VM through common harness =="
vm_init

# ---------------------------------------------------------------------------
# 2. initial MAC state (harness evidence primitives)
# ---------------------------------------------------------------------------
log "== 2. initial MAC state =="
STATE="$(vm_ssh 'bash -s' <<'RMT'
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "=== sestatus ==="; (command -v sestatus >/dev/null 2>&1 && sestatus 2>&1) || echo "(sestatus absent)"
echo "=== getenforce ==="; (command -v getenforce >/dev/null 2>&1 && getenforce 2>&1) || echo "(getenforce absent)"
echo "=== /etc/selinux/config ==="; cat /etc/selinux/config 2>/dev/null || echo "(no config)"
echo "STATE-DONE"
RMT
)" || true
printf '%s\n' "$STATE"
echo "$STATE" | grep -q "STATE-DONE" || fail "initial state script did not complete"

EVID="$(vm_evidence)" || true
RAW_CMDLINE="$(printf '%s\n' "$EVID" | vm_evidence_cmdline)"
RAW_LSM="$(printf '%s\n' "$EVID" | vm_evidence_lsm)"
SELINUX_ACTIVE="no"
APPARMOR_ACTIVE="no"
echo "$RAW_LSM" | grep -qw selinux  && SELINUX_ACTIVE="yes"
echo "$RAW_LSM" | grep -qw apparmor && APPARMOR_ACTIVE="yes"
log "initial LSM: $RAW_LSM (selinux=$SELINUX_ACTIVE apparmor=$APPARMOR_ACTIVE)"

# ---------------------------------------------------------------------------
# 3. SELinux userspace bootstrap (packages + config only; the cmdline switch is
#    the harness vm_set_mac_tokens primitive below)
# ---------------------------------------------------------------------------
log "== 3. SELinux userspace bootstrap =="
BOOTSTRAP="$(vm_ssh 'sudo bash -s' <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
log(){ echo "[vm] $*"; }

log "installing/verifying SELinux userspace + targeted policy"
NEED=0
for p in selinux-policy-targeted policycoreutils selinux-tools policycoreutils-python-utils; do
  rpm -q "$p" >/dev/null 2>&1 || { NEED=1; log "missing: $p"; }
done
if [ "$NEED" = 1 ]; then
  # Tune libzypp network timeouts (zypper.conf(5)); zypper's CLI
  # --connect-timeout flag is not accepted on this Tumbleweed image. Lower only
  # download.connect_timeout so a dead mirror costs seconds; keep the 180s
  # download.transfer_timeout default so large packages are not aborted.
  if [ -f /etc/zypp/zypp.conf ] && grep -q '^[[:space:]]*#*[[:space:]]*download\.connect_timeout' /etc/zypp/zypp.conf; then
    sed -i -E 's/^[[:space:]]*#*[[:space:]]*download\.connect_timeout([[:space:]=]+).*/download.connect_timeout = 15/' /etc/zypp/zypp.conf
  else
    printf '\ndownload.connect_timeout = 15\n' >> /etc/zypp/zypp.conf
  fi
  zypper --non-interactive refresh || true
  zypper --non-interactive install -y \
    selinux-policy-targeted policycoreutils selinux-tools policycoreutils-python-utils
fi
log "SELinux/AppArmor-related packages:"
rpm -qa | grep -Ei 'selinux|policycoreutils|libselinux|libsepol|libsemanage|apparmor' | sort || true

log "tool providers:"
for b in sestatus getenforce semodule semanage restorecon matchpathcon; do
  p="$(command -v "$b" 2>/dev/null || true)"
  if [ -n "$p" ]; then
    log "tool $b -> $p ($(rpm -qf "$p" 2>/dev/null || echo unknown))"
  else
    log "tool $b -> MISSING"
  fi
done

# Ensure /etc/selinux/config selects enforcing targeted.
mkdir -p /etc/selinux
cp /etc/selinux/config /etc/selinux/config.orig 2>/dev/null || true
cat > /etc/selinux/config <<SELCFG
SELINUX=enforcing
SELINUXTYPE=targeted
SELCFG
log "/etc/selinux/config:"
cat /etc/selinux/config

# AppArmor is not the active backend here: disable the service; the apparmor=0
# cmdline entry prevents the LSM registering at next boot.
if systemctl list-unit-files 2>/dev/null | grep -q '^apparmor.service'; then
  systemctl disable --now apparmor >/dev/null 2>&1 || true
  log "apparmor service disabled (best-effort)"
fi

echo "BOOTSTRAP-DONE"
RMT
)" || true
printf '%s\n' "$BOOTSTRAP"
echo "$BOOTSTRAP" | grep -q "BOOTSTRAP-DONE" || fail "SELinux bootstrap script did not complete"

# ---------------------------------------------------------------------------
# 4. select MAC tokens through the harness cmdline primitive + reboot
# ---------------------------------------------------------------------------
log "== 4. select SELinux MAC tokens + reboot =="
vm_set_mac_tokens "security=selinux selinux=1 apparmor=0 enforcing=1"
vm_reboot "apply SELinux cmdline (security=selinux selinux=1 apparmor=0 enforcing=1)"

# ---------------------------------------------------------------------------
# 5. prove real SELinux enforcing / AppArmor absent (acceptance stays here)
# ---------------------------------------------------------------------------
log "== 5. prove SELinux enforcing / AppArmor absent =="
PROOF="$(vm_ssh 'sudo bash -s' <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "=== /etc/os-release ==="; cat /etc/os-release
echo "=== systemd ==="; systemctl is-system-running 2>&1 || true
echo "=== sshd ==="; systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || echo "unknown"
echo "=== sestatus ==="; sestatus 2>&1
echo "=== getenforce ==="; getenforce 2>&1
echo "=== /sys/fs/selinux/enforce ==="; cat /sys/fs/selinux/enforce 2>/dev/null || echo "(absent)"; echo
echo "PROOF-DONE"
RMT
)" || true
printf '%s\n' "$PROOF"
echo "$PROOF" | grep -q "PROOF-DONE" || fail "SELinux proof script did not complete"

EVID="$(vm_evidence)" || true
CMDLINE_FINAL="$(printf '%s\n' "$EVID" | vm_evidence_cmdline)"
LSM_FINAL="$(printf '%s\n' "$EVID" | vm_evidence_lsm)"
GETENF="$(printf '%s\n' "$PROOF" | grep -A1 '=== getenforce ===' | tail -1 | tr -d '[:space:]')"

echo "$PROOF" | grep -qi 'opensuse-tumbleweed' || fail "ACCEPT: not openSUSE Tumbleweed"
echo "$CMDLINE_FINAL" | grep -q 'security=selinux' || fail "ACCEPT: cmdline missing security=selinux"
echo "$CMDLINE_FINAL" | grep -q 'selinux=1' || fail "ACCEPT: cmdline missing selinux=1"
echo "$CMDLINE_FINAL" | grep -q 'apparmor=0' || fail "ACCEPT: cmdline missing apparmor=0"
echo "$CMDLINE_FINAL" | grep -q 'enforcing=1' || fail "ACCEPT: cmdline missing enforcing=1"
echo "$LSM_FINAL" | grep -qw selinux || fail "ACCEPT: selinux not in active LSM ($LSM_FINAL)"
if echo "$LSM_FINAL" | grep -qw apparmor; then
  fail "ACCEPT: apparmor is a concurrently active LSM ($LSM_FINAL)"
fi
[ "$GETENF" = "Enforcing" ] || fail "ACCEPT: getenforce != Enforcing (got '$GETENF')"
echo "$PROOF" | grep -qE 'SELinux status:[[:space:]]+enabled' || fail "ACCEPT: sestatus not enabled"
echo "$PROOF" | grep -qE 'Current mode:[[:space:]]+enforcing' || fail "ACCEPT: sestatus current mode != enforcing"
echo "$PROOF" | grep -qE '(Policy from config file|Loaded policy name):[[:space:]]+targeted' || fail "ACCEPT: sestatus policy != targeted"
log "SELinux proof passed: lsm='$LSM_FINAL' getenforce=$GETENF"
log "final cmdline: $CMDLINE_FINAL"

# ---------------------------------------------------------------------------
# 6. transfer checkout + exact RPM into the guest
# ---------------------------------------------------------------------------
log "== 6. transfer repo + RPM into the guest =="
if vm_ssh "sudo mkdir -p /opt/uat /opt/uat-import && sudo chown opc:opc /opt/uat /opt/uat-import"; then
  :
else
  EC=$?
  fail "could not create guest import dirs (exit $EC)"
fi

log "copying host checkout into guest (/opt/uat)"
tar -C "$UAT_REPO_DIR" -czf repo.tgz \
  --exclude=.git --exclude=dist --exclude=uat-curl --exclude=docker-helper .
if vm_ssh "tar xzf - -C /opt/uat" < repo.tgz; then
  :
else
  EC=$?
  fail "repo transfer to guest failed (exit $EC)"
fi

log "copying RPM artifact into guest (/opt/uat-import/docker-helper.rpm)"
if vm_scp "$UAT_RPM" opc@127.0.0.1:/opt/uat-import/docker-helper.rpm; then
  :
else
  EC=$?
  fail "RPM transfer to guest failed (exit $EC)"
fi

# ---------------------------------------------------------------------------
# 7. run the existing black-box UAT inside the guest
# ---------------------------------------------------------------------------
# run_guest_uat: remote command via the harness transport; on failure it prints
# docker-helper diagnostics and exits with the REMOTE exit status preserved.
# (Never `if ! vm_ssh ...; then EC=$?`: $? there is the status of `!`.)
run_guest_uat() {
  local desc="$1"; shift
  if vm_ssh "$@"; then
    return 0
  else
    local ec=$?
    guest_evidence || true
    vm_serial_tail
    fail "$desc failed (exit $ec)"
  fi
}

log "== 7. black-box UAT inside the guest =="
log "install-deps (UAT_PLATFORM=opensuse scripts/uat-blackbox.sh install-deps)"
run_guest_uat "guest install-deps" \
  "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_PLATFORM=opensuse scripts/uat-blackbox.sh install-deps"

# The docker_helper.pp policy module requires container-selinux attributes
# (container_domain, mcs_constrained_type, container_net_domain) and types
# (container_runtime_t, container_file_t, ...). install-deps pulls container-
# selinux in as a dependency of docker and its %posttrans loads the module
# (semodule -i reports "Overriding container module at lower priority 200" when
# it is already present — the module lives in the semanage store, though
# neither `semodule -l` nor the active-modules directory reliably expose it on
# this system, so no hard presence gate is possible). As a best effort the
# distro-shipped container-selinux module is loaded (idempotent; a prerequisite
# for the UAT, not a policy widening). The authoritative proof that the
# prerequisite is satisfied is the UAT install itself: the RPM %post runs
# `semodule -i docker_helper.pp`, which fails loudly if the container
# attributes/types are unavailable.
log "ensure container-selinux policy module (docker_helper.pp prerequisite)"
vm_ssh 'sudo bash -s' <<'RMT'
set -uo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PP="$(rpm -ql container-selinux 2>/dev/null | grep -E '\.pp(\.bz2)?$' | head -1 || true)"
if [ -z "$PP" ] || [ ! -f "$PP" ]; then
  echo "warning: container-selinux module file not found; relying on the UAT install to prove the prerequisite"
  exit 0
fi
echo "ensuring container-selinux module: $PP"
semodule -i "$PP" || echo "warning: semodule -i failed for $PP; relying on the UAT install to prove the prerequisite"
RMT
log "container-selinux module ensured (best-effort); UAT install is the authoritative check"

log "black-box UAT (UAT_PLATFORM=opensuse UAT_INSTALL=rpm UAT_MAC=selinux, prebuilt RPM)"
run_guest_uat "black-box UAT inside the guest" \
  "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_VERSION=$VERSION UAT_PLATFORM=opensuse UAT_INSTALL=rpm UAT_MAC=selinux UAT_ARTIFACT_PATH=/opt/uat-import/docker-helper.rpm UAT_ARTIFACT_SHA256=$UAT_RPM_SHA256 scripts/uat-blackbox.sh"
log "black-box UAT passed inside the guest"

# ---------------------------------------------------------------------------
# 8. SELinux mount-pin / RPM postinstall regression
# ---------------------------------------------------------------------------
log "== 8. SELinux mount-pin / RPM postinstall regression =="
run_guest_uat "SELinux mount-pin regression inside the guest" \
  "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_RPM=/opt/uat-import/docker-helper.rpm UAT_RPM_SHA256=$UAT_RPM_SHA256 scripts/uat-selinux-mount-pin-regression.sh"
log "SELinux mount-pin regression passed inside the guest"

# ---------------------------------------------------------------------------
# 9. Summary
# ---------------------------------------------------------------------------
T1="$(date +%s)"
TOTAL=$((T1 - T0))
echo
echo "======= OPENSUSE/SELINUX UAT (TUMBLEWEED VM) SUMMARY ======="
echo "image:            $VM_IMG_NAME"
echo "image sha256:     $VM_IMG_SHA256"
echo "first boot:       ${VM_BOOT_TIME}s to SSH"
echo "MAC-switch reboot: ${VM_LAST_REBOOT_SECS}s back to SSH"
echo "initial LSM:      $RAW_LSM (selinux=$SELINUX_ACTIVE apparmor=$APPARMOR_ACTIVE)"
echo "final LSM:        $LSM_FINAL"
echo "final cmdline:    $CMDLINE_FINAL"
echo "getenforce:       $GETENF"
echo "RPM:              $UAT_RPM"
echo "RPM sha256:       $UAT_RPM_SHA256 (producer, verified by UAT)"
echo "UAT version:      $VERSION"
echo "total:            ${TOTAL}s"
echo "RESULT: openSUSE/SELinux black-box UAT + mount-pin regression PASSED inside Tumbleweed VM"
echo "=============================================================="
log "DONE"
