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
#       |  (this file: AppArmor-specific orchestration ONLY)
#       v
#   Tumbleweed VM harness    (scripts/uat-vm-tumbleweed.sh, sourced below)
#       |  image + checksum, qcow overlay + resize, KVM/TCG selection,
#       |  cloud-init NoCloud seed, unattended boot, vm_ssh/vm_scp transport,
#       |  wait-for-SSH, canonical reboot, serial-log diagnostics, labeled
#       |  cmdline+LSM evidence, boot-config MAC selector mutation.
#       v
#   existing black-box UAT   (scripts/uat-blackbox.sh inside the guest, with
#                             scripts/uat-platform-opensuse.sh platform owner
#                             and scripts/uat-mac-apparmor.sh MAC owner)
#
# This file owns the guest MAC bootstrap ONLY — which backend to select and how
# to prove it — plus copying the checkout and the exact prebuilt RPM into the
# guest and running the existing UAT. All VM mechanics live in the harness. It
# does not reimplement platform or MAC semantics: the guest-side UAT is the
# existing scripts/uat-blackbox.sh with its uat-platform-opensuse.sh (platform
# owner) and uat-mac-apparmor.sh (MAC owner) adapters, which remain the owners
# of their concerns.
#
# Flow:
#   create/start Tumbleweed VM through the common harness (vm_init)
#       -> inspect initial MAC state (harness evidence primitives)
#       -> install AppArmor userspace
#       -> select security=apparmor apparmor=1 selinux=0 through the harness
#          cmdline primitive (vm_set_mac_tokens)
#       -> reboot through the harness (vm_reboot)
#       -> prove AppArmor active / SELinux absent
#       -> copy checkout + exact RPM into the guest
#       -> install-deps (UAT_PLATFORM=opensuse)
#       -> existing black-box UAT (UAT_PLATFORM=opensuse UAT_INSTALL=rpm
#          UAT_MAC=apparmor, prebuilt RPM)
#
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
#   UAT_VERSION      version string (default 2.1.0-uat)
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
VERSION="${UAT_VERSION:-2.1.0-uat}"
KEEP="${UAT_KEEP:-}"

[ -n "$UAT_RPM" ] || fail "UAT_RPM is required (exact prebuilt RPM artifact)"
[ -f "$UAT_RPM" ] || fail "UAT_RPM is not a file: $UAT_RPM"
[ -n "$UAT_RPM_SHA256" ] || fail "UAT_RPM_SHA256 is required (producer SHA-256)"
[ -f "$UAT_REPO_DIR/scripts/uat-blackbox.sh" ] \
  || fail "UAT_REPO_DIR has no scripts/uat-blackbox.sh: $UAT_REPO_DIR"

# The v2.0.0 package is an immutable TEST FIXTURE for the real RPM
# upgrade baseline. This file owns the download+verify boundary only; the
# baseline version, URL and pinned SHA-256 are owned by the single fixture
# owner (scripts/uat-upgrade-baseline-fixture.sh). The guest lifecycle
# re-verifies before install.
# shellcheck source=scripts/uat-upgrade-baseline-fixture.sh
source "$SCRIPT_DIR/uat-upgrade-baseline-fixture.sh"

BASELINE_RPM_PATH=""
if upgrade_baseline_fetch_rpm /tmp/uat-baseline-docker-helper.rpm >/tmp/baseline-rpm.path 2>/dev/null; then
  BASELINE_RPM_PATH="$(cat /tmp/baseline-rpm.path)"
  log "v2.0.0 baseline RPM downloaded and SHA-256 verified (pinned fixture)"
else
  fail "could not download/verify the v2.0.0 baseline RPM (pinned fixture)"
fi

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
echo "--- /sys/module/apparmor/parameters/enabled ---"; cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo "(absent)"
echo "--- aa-status ---"; (command -v aa-status >/dev/null 2>&1 && aa-status 2>&1) || echo "(aa-status absent)"
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
echo "=== aa-status ==="; (command -v aa-status >/dev/null 2>&1 && aa-status 2>&1) || echo "(aa-status absent)"
echo "=== sestatus ==="; (command -v sestatus >/dev/null 2>&1 && sestatus 2>&1) || echo "(sestatus absent)"
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
# 3. AppArmor userspace bootstrap (packages + service only; the cmdline switch
#    is the harness vm_set_mac_tokens primitive below)
# ---------------------------------------------------------------------------
log "== 3. AppArmor userspace bootstrap =="
# Transfer the canonical openSUSE repo/package policy helper into the guest
# (the bootstrap uses the shared zypper timeout/retry owner; the full checkout
# is only copied later, after the MAC proof).
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

log "installing AppArmor userspace: apparmor-parser apparmor-utils apparmor-abstractions"
opensuse_zypp_tune_timeouts
if ! opensuse_zypper_refresh; then
  echo "REPO-FAILURE: zypper refresh exhausted attempts; aborting bootstrap" >&2
  exit 1
fi
opensuse_zypper install -y --no-recommends \
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

# Enable the AppArmor service (loads /etc/apparmor.d profiles at boot).
if systemctl list-unit-files 2>/dev/null | grep -q '^apparmor.service'; then
  systemctl enable apparmor.service >/dev/null 2>&1 \
    && log "apparmor.service enabled" || log "WARN: could not enable apparmor.service"
fi

echo "BOOTSTRAP-DONE"
RMT
)" || true
printf '%s\n' "$BOOTSTRAP"
echo "$BOOTSTRAP" | grep -q "BOOTSTRAP-DONE" || fail "AppArmor bootstrap script did not complete"

# ---------------------------------------------------------------------------
# 4. select MAC tokens through the harness cmdline primitive + reboot
# ---------------------------------------------------------------------------
log "== 4. select AppArmor MAC tokens + reboot =="
vm_set_mac_tokens "security=apparmor apparmor=1 selinux=0"
vm_reboot "apply AppArmor cmdline (security=apparmor apparmor=1 selinux=0)"

# ---------------------------------------------------------------------------
# 5. prove AppArmor active / SELinux absent (acceptance stays here)
# ---------------------------------------------------------------------------
log "== 5. prove AppArmor active / SELinux absent =="
PROOF="$(vm_ssh 'sudo bash -s' <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "AA_ENABLED_VAL=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo absent)"
echo "=== /etc/os-release ==="; cat /etc/os-release
echo "=== systemd ==="; systemctl is-system-running 2>&1 || true
echo "=== sshd ==="; systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || echo "unknown"
echo "=== aa-status ==="; aa-status 2>&1 | head -40 || true
echo "=== apparmor service ==="; systemctl is-active apparmor.service 2>&1 || true
echo "PROOF-DONE"
RMT
)" || true
printf '%s\n' "$PROOF"
echo "$PROOF" | grep -q "PROOF-DONE" || fail "AppArmor proof script did not complete"

EVID="$(vm_evidence)" || true
CMDLINE_FINAL="$(printf '%s\n' "$EVID" | vm_evidence_cmdline)"
LSM_FINAL="$(printf '%s\n' "$EVID" | vm_evidence_lsm)"
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

log "copying v2.0.0 baseline RPM into guest (/opt/uat-import/docker-helper-baseline.rpm)"
if vm_scp "$BASELINE_RPM_PATH" opc@127.0.0.1:/opt/uat-import/docker-helper-baseline.rpm; then
  :
else
  EC=$?
  fail "v2.0.0 baseline RPM transfer to guest failed (exit $EC)"
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

log "black-box UAT (UAT_PLATFORM=opensuse UAT_INSTALL=rpm UAT_MAC=apparmor, prebuilt RPM)"
run_guest_uat "black-box UAT inside the guest" \
  "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_VERSION=$VERSION UAT_PLATFORM=opensuse UAT_INSTALL=rpm UAT_MAC=apparmor UAT_ARTIFACT_PATH=/opt/uat-import/docker-helper.rpm UAT_ARTIFACT_SHA256=$UAT_RPM_SHA256 scripts/uat-blackbox.sh"
log "black-box UAT passed inside the guest"

# ---------------------------------------------------------------------------
# 7b. RPM lifecycle (install v2.0.0 baseline -> upgrade candidate ->
#     reinstall -> erase)
# ---------------------------------------------------------------------------
log "== 7b. RPM/AppArmor lifecycle (v2.0.0 -> candidate, AppArmor host) =="
run_guest_uat "RPM lifecycle inside the guest" \
  "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_VERSION=$VERSION UAT_PLATFORM=opensuse UAT_RPM=/opt/uat-import/docker-helper.rpm UAT_RPM_SHA256=$UAT_RPM_SHA256 UAT_UPGRADE_BASELINE_RPM=/opt/uat-import/docker-helper-baseline.rpm UAT_PRINCIPAL=opc scripts/uat-package-lifecycle-rpm.sh"
log "RPM/AppArmor lifecycle passed inside the guest"

# ---------------------------------------------------------------------------
# 7c. RuntimeDirectory socket replacement regression (real zypper upgrade +
#     candidate --force reinstall, observed by a long-lived container with a
#     bind-mount of /run/docker-helper; the shipped RuntimeDirectoryPreserve
#     contract)
# ---------------------------------------------------------------------------
log "== 7c. RuntimeDirectory socket replacement regression (zypper) =="
run_guest_uat "RuntimeDirectory socket replacement regression inside the guest" \
  "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_VERSION=$VERSION UAT_PLATFORM=opensuse UAT_RPM=/opt/uat-import/docker-helper.rpm UAT_RPM_SHA256=$UAT_RPM_SHA256 UAT_BASELINE_RPM=/opt/uat-import/docker-helper-baseline.rpm scripts/uat-regression-runtime-dir-socket-replacement.sh"
log "RuntimeDirectory socket replacement regression passed inside the guest"

# ---------------------------------------------------------------------------
# 8. Summary
# ---------------------------------------------------------------------------
T1="$(date +%s)"
TOTAL=$((T1 - T0))
echo
echo "======= OPENSSUSE/APPARMOR UAT (TUMBLEWEED VM) SUMMARY ======="
echo "image:            $VM_IMG_NAME"
echo "image sha256:     $VM_IMG_SHA256"
echo "first boot:       ${VM_BOOT_TIME}s to SSH"
echo "MAC-switch reboot: ${VM_LAST_REBOOT_SECS}s back to SSH"
echo "initial LSM:      $RAW_LSM (selinux=$SELINUX_ACTIVE apparmor=$APPARMOR_ACTIVE)"
echo "final LSM:        $LSM_FINAL"
echo "final cmdline:    $CMDLINE_FINAL"
echo "RPM:              $UAT_RPM"
echo "RPM sha256:       $UAT_RPM_SHA256 (producer, verified by UAT)"
echo "v2.0.0 baseline RPM: $BASELINE_RPM_PATH (pinned fixture, verified)"
echo "UAT version:      $VERSION"
echo "total:            ${TOTAL}s"
echo "RESULT: openSUSE/AppArmor black-box UAT + RPM lifecycle PASSED inside Tumbleweed VM"
echo "=============================================================="
log "DONE"
