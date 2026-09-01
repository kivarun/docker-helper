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
#       |  (this file: RPM artifact orchestration ONLY)
#       v
#   shared SELinux host construction
#                    (scripts/uat-vm-opensuse-selinux-lib.sh, sourced below;
#                     also used by scripts/uat-vm-opensuse-tarball-selinux.sh)
#       |  SELinux userspace bootstrap + targeted policy, MAC token selection,
#       |  enforcing reboot proof, checkout + artifact transfer, two-stage
#       |  Docker preparation + Docker SELinux health gate.
#       v
#   Tumbleweed VM harness    (scripts/uat-vm-tumbleweed.sh, sourced by the lib)
#       |  image + checksum, qcow overlay + resize, KVM/TCG selection,
#       |  cloud-init NoCloud seed, unattended boot, vm_ssh/vm_scp transport,
#       |  wait-for-SSH, canonical reboot, serial-log diagnostics, labeled
#       |  cmdline+LSM evidence, boot-config MAC selector mutation.
#       v
#   existing black-box UAT   (scripts/uat-blackbox.sh inside the guest, with
#                             scripts/uat-platform-opensuse.sh platform owner
#                             and scripts/uat-mac-selinux.sh MAC owner)
#
# This file owns the RPM-specific stages ONLY — the exact RPM transfer, and the
# RPM SELinux stage set (black-box UAT, SELinux mount-pin / RPM postinstall
# regression, the Phase-A2 docker socket micro-proof, and the Release-2 SELinux
# targeted regression groups 1-5). All VM mechanics live in the harness; all
# SELinux host construction lives in the shared lib; the guest-side UAT is the
# existing scripts/uat-blackbox.sh with its uat-platform-opensuse.sh (platform
# owner) and uat-mac-selinux.sh (MAC owner) adapters, which remain the owners of
# their concerns.
#
# Collect-all: a failure in the common black-box UAT or the mount-pin
# regression never prevents the remaining stages (socket micro-proof, Release-2
# regressions 1-5) from executing; the final summary records every stage and
# the job exits nonzero only when a gating stage failed.
#
# Flow:
#   create/start Tumbleweed VM through the common harness (shared lib)
#       -> inspect initial MAC state (harness evidence primitives)
#       -> install/verify SELinux userspace + targeted policy
#       -> ensure /etc/selinux/config = enforcing / targeted
#       -> select security=selinux selinux=1 apparmor=0 enforcing=1 through the
#          harness cmdline primitive (vm_set_mac_tokens)
#       -> reboot through the harness (vm_reboot)
#       -> prove real SELinux enforcing / AppArmor absent
#       -> copy checkout + exact RPM into the guest
#       -> two-stage Docker preparation: install/ensure container-selinux in
#          its own transaction and settle its policy module BEFORE Docker is
#          installed (the rpm selinux plugin then labels dockerd naturally as
#          container_runtime_exec_t; no explicit restorecon/restart)
#       -> install-deps (UAT_PLATFORM=opensuse)  [Docker install, stage 2]
#       -> Docker SELinux health gate before the docker-helper RPM install:
#          dockerd exec = container_runtime_exec_t, dockerd process =
#          container_runtime_t, docker.sock = container_var_run_t. If healthy,
#          the previous docker socket blocker is classified as a UAT/environment
#          construction defect, not a docker-helper production defect. If NOT
#          healthy, stop and report (docker-helper must not own Docker daemon
#          repair without another architecture decision).
#       -> existing black-box UAT (UAT_PLATFORM=opensuse UAT_INSTALL=rpm
#          UAT_MAC=selinux, prebuilt RPM)            [result recorded, collect-all]
#       -> SELinux mount-pin / RPM postinstall regression  [result recorded]
#       -> A2 docker socket micro-proof (dontaudit off, bounded evidence)
#       -> Release-2 SELinux targeted regression groups 1-5 (collect-all runner)
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
#   UAT_VERSION      version string (default 2.1.0-uat)
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
# shared SELinux host construction (sources the canonical Tumbleweed VM harness
# and the SELinux bootstrap/proof/transfer/docker-prep); no VM/MAC knowledge
# lives in this file
# ---------------------------------------------------------------------------
# shellcheck source=scripts/uat-vm-opensuse-selinux-lib.sh
source "$SCRIPT_DIR/uat-vm-opensuse-selinux-lib.sh"

T0="$(date +%s)"

# The harness owns the EXIT cleanup trap (workdir lifecycle) but not the ERR
# diagnostics trap: this file composes its own, using the harness serial-log
# primitive plus docker-helper guest evidence (from the shared lib).
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

# ---------------------------------------------------------------------------
# 1-5. SELinux host construction (VM boot, SELinux bootstrap, enforcing proof)
# ---------------------------------------------------------------------------
vm_selinux_bootstrap

# ---------------------------------------------------------------------------
# 6. transfer checkout + exact RPM into the guest
# ---------------------------------------------------------------------------
log "== 6. transfer repo + RPM into the guest =="
vm_selinux_transfer_repo
vm_selinux_transfer_artifact "docker-helper.rpm" "$UAT_RPM"
vm_selinux_transfer_artifact "docker-helper-baseline.rpm" "$BASELINE_RPM_PATH"

# ---------------------------------------------------------------------------
# 6b-7a. two-stage Docker preparation + Docker SELinux health gate
# ---------------------------------------------------------------------------
vm_selinux_two_stage_docker

# ---------------------------------------------------------------------------
# 7. existing black-box UAT
# ---------------------------------------------------------------------------
log "black-box UAT (UAT_PLATFORM=opensuse UAT_INSTALL=rpm UAT_MAC=selinux, prebuilt RPM)"
BB_RESULT=FAIL
if run_guest_capture "black-box UAT inside the guest" \
  "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_VERSION=$VERSION UAT_PLATFORM=opensuse UAT_INSTALL=rpm UAT_MAC=selinux UAT_ARTIFACT_PATH=/opt/uat-import/docker-helper.rpm UAT_ARTIFACT_SHA256=$UAT_RPM_SHA256 scripts/uat-blackbox.sh"; then
  BB_RESULT=PASS
  log "black-box UAT passed inside the guest"
else
  log "black-box UAT FAILED inside the guest (recorded; continuing with regressions)"
fi
record_stage "black-box UAT" "$BB_RESULT"

# ---------------------------------------------------------------------------
# 8. SELinux mount-pin / RPM postinstall regression
# ---------------------------------------------------------------------------
log "== 8. SELinux mount-pin / RPM postinstall regression =="
MP_RESULT=FAIL
if run_guest_capture "SELinux mount-pin regression inside the guest" \
  "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_RPM=/opt/uat-import/docker-helper.rpm UAT_RPM_SHA256=$UAT_RPM_SHA256 scripts/uat-selinux-mount-pin-regression.sh"; then
  MP_RESULT=PASS
  log "SELinux mount-pin regression passed inside the guest"
else
  MP_EC=$?
  if [ "$MP_EC" = 2 ]; then
    MP_RESULT=BLOCKED
    log "SELinux mount-pin regression BLOCKED inside the guest (scenario not exercised; recorded, fails the job)"
  else
    log "SELinux mount-pin regression FAILED inside the guest (recorded; continuing)"
  fi
fi
record_stage "SELinux mount-pin regression" "$MP_RESULT"

# ---------------------------------------------------------------------------
# 8b. A2 bounded socket micro-proof (evidence collection; not a gate)
# ---------------------------------------------------------------------------
log "== 8b. A2 docker socket micro-proof (dontaudit off, bounded) =="
MICRO_RESULT=FAIL
if run_guest_capture "A2 socket micro-proof inside the guest" \
  "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin scripts/uat-socket-microproof.sh"; then
  MICRO_RESULT=PASS
else
  log "A2 socket micro-proof did not complete (recorded; evidence may be partial)"
fi
record_stage "A2 socket micro-proof" "$MICRO_RESULT"

# ---------------------------------------------------------------------------
# 8c. Release-2 SELinux targeted regression groups 1-5 (collect-all)
# ---------------------------------------------------------------------------
log "== 8c. SELinux targeted regression groups 1-5 (collect-all runner) =="
SELREG_RESULT=FAIL
if run_guest_capture "SELinux regression groups 1-5 inside the guest" \
  "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin bash scripts/uat-regressions-runner-selinux.sh"; then
  SELREG_RESULT=PASS
else
  log "SELinux regression groups 1-5 reported a failure (recorded)"
fi
record_stage "SELinux regressions (1-5)" "$SELREG_RESULT"


# ---------------------------------------------------------------------------
# 8d. RPM lifecycle under SELinux (install v2.0.0 baseline -> upgrade candidate
#     -> reinstall -> erase)
# ---------------------------------------------------------------------------
log "== 8d. RPM/SELinux lifecycle (v2.0.0 -> candidate, SELinux host) =="
LIFECYCLE_RESULT=FAIL
if run_guest_capture "RPM/SELinux lifecycle inside the guest" \
  "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_VERSION=$VERSION UAT_RPM=/opt/uat-import/docker-helper.rpm UAT_RPM_SHA256=$UAT_RPM_SHA256 UAT_UPGRADE_BASELINE_RPM=/opt/uat-import/docker-helper-baseline.rpm UAT_UPGRADE_BASELINE_RPM_SHA256=$UPGRADE_BASELINE_RPM_SHA256 UAT_UPGRADE_BASELINE_VERSION=$UPGRADE_BASELINE_VERSION UAT_PRINCIPAL=opc scripts/uat-package-lifecycle-rpm.sh"; then
  LIFECYCLE_RESULT=PASS
  log "RPM/SELinux lifecycle passed inside the guest"
else
  log "RPM/SELinux lifecycle reported a failure (recorded)"
fi
record_stage "RPM/SELinux lifecycle" "$LIFECYCLE_RESULT"


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
echo "v2.0.0 baseline RPM: $BASELINE_RPM_PATH (pinned fixture, verified)"
echo "UAT version:      $VERSION"
echo "Docker SELinux:   ${DOCKER_HEALTHY:-0}=naturally healthy two-stage setup (container-selinux before Docker)"
echo "total:            ${TOTAL}s"
echo "---- SELinux job stages ----"
printf '%s\n' "$SELINUX_STAGES"
echo "============================="
# Fail-closed acceptance: every gating stage must be PASS. A BLOCKED stage
# (exit 2) means the required scenario was NOT successfully exercised, which
# is not acceptable for Release-2 — the historical docker socket blocker that
# once justified treating BLOCKED as success is closed, so it must not remain
# encoded as acceptance semantics.
if selinux_stage_accept "$BB_RESULT" "$SELREG_RESULT" "$MP_RESULT" "$LIFECYCLE_RESULT"; then
  echo "RESULT: openSUSE/SELinux UAT stages PASSED inside Tumbleweed VM"
  echo "=============================================================="
  log "DONE"
  exit 0
fi
echo "RESULT: at least one SELinux job stage FAILED or BLOCKED (see summary above)"
echo "=============================================================="
exit 1
