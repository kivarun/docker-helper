#!/usr/bin/env bash
#
# uat-vm-opensuse-tarball-selinux.sh — run the docker-helper black-box UAT for
# UAT_PLATFORM=opensuse / UAT_INSTALL=tarball / UAT_MAC=selinux inside a real
# openSUSE Tumbleweed Cloud VM booted on a GitHub-hosted ubuntu-24.04 runner
# (QEMU/KVM).
#
# Responsibility boundary (sibling of scripts/uat-vm-opensuse-selinux.sh):
#
#   host workflow
#       |  (this file: release-tarball artifact orchestration ONLY)
#       v
#   shared SELinux host construction
#                    (scripts/uat-vm-opensuse-selinux-lib.sh, sourced below;
#                     also used by scripts/uat-vm-opensuse-selinux.sh)
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
# This file owns the release-tarball artifact orchestration ONLY — the exact
# tarball transfer and the single common black-box UAT with
# UAT_INSTALL=tarball / UAT_MAC=selinux. All VM mechanics live in the harness;
# all SELinux host construction lives in the shared lib; the guest-side UAT is
# the existing scripts/uat-blackbox.sh with its uat-platform-opensuse.sh and
# uat-mac-selinux.sh adapters.
#
# The tarball is never rebuilt here and the guest never builds the tarball or
# the SELinux policy: the exact bytes produced by the hosted uat-tarball-build
# job are copied into the guest and the producer SHA-256 is verified strictly
# by the UAT before install (UAT_ARTIFACT_PATH / UAT_ARTIFACT_SHA256). The
# install uses the real shipped path:
#     ./install-system.sh --yes --allowed-root <root>
# inside the extracted bundle.
#
# The required evidence is: exact tarball SHA verified in the guest; SELinux
# enforcing; the docker_helper module loaded from the tarball; the daemon
# running as docker_helper_t; and the normal pull/run/build/CA black-box path
# succeeding. All of that is owned by the black-box UAT (mac_preflight,
# install_apply via install-system.sh, install_verify_artifacts, and
# mac_verify_confinement). The exotic SELinux regression groups 1-5 are NOT
# duplicated here: they test the production SELinux model already covered by
# the RPM profile.
#
# Flow:
#   create/start Tumbleweed VM through the common harness (shared lib)
#       -> SELinux host construction: bootstrap, enforcing proof
#       -> copy checkout + exact release tarball into the guest
#       -> two-stage Docker preparation + Docker SELinux health gate
#       -> common black-box UAT (UAT_PLATFORM=opensuse UAT_INSTALL=tarball
#          UAT_MAC=selinux, prebuilt tarball)
#
# Env inputs:
#   UAT_REPO_DIR     host checkout of docker-helper (default: repo root of this script)
#   UAT_TARBALL      path to the exact prebuilt release tarball artifact
#   UAT_TARBALL_SHA256 expected SHA-256 produced by the tarball build job
#   UAT_VERSION      version string (default 2.0.0-uat)
#   UAT_KEEP         keep the VM/workdir on failure for debugging
#
# Exit 0 = openSUSE/AppArmor-independent SELinux tarball black-box UAT passed
# inside the guest. Nonzero = failed; serial tail + guest evidence are printed.

set -euo pipefail

PREFIX="[opensuse-tarball-selinux-vm]"
log()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
UAT_TARBALL="${UAT_TARBALL:-}"
UAT_TARBALL_SHA256="${UAT_TARBALL_SHA256:-}"
VERSION="${UAT_VERSION:-2.0.0-uat}"
KEEP="${UAT_KEEP:-}"

[ -n "$UAT_TARBALL" ] || fail "UAT_TARBALL is required (exact prebuilt release tarball artifact)"
[ -f "$UAT_TARBALL" ] || fail "UAT_TARBALL is not a file: $UAT_TARBALL"
[ -n "$UAT_TARBALL_SHA256" ] || fail "UAT_TARBALL_SHA256 is required (producer SHA-256)"
[ -f "$UAT_REPO_DIR/scripts/uat-blackbox.sh" ] \
  || fail "UAT_REPO_DIR has no scripts/uat-blackbox.sh: $UAT_REPO_DIR"

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
# 6. transfer checkout + exact release tarball into the guest
# ---------------------------------------------------------------------------
log "== 6. transfer repo + release tarball into the guest =="
vm_selinux_transfer_repo
vm_selinux_transfer_artifact "docker-helper.tar.gz" "$UAT_TARBALL"

# ---------------------------------------------------------------------------
# 6b-7a. two-stage Docker preparation + Docker SELinux health gate
# ---------------------------------------------------------------------------
vm_selinux_two_stage_docker

# ---------------------------------------------------------------------------
# 7. common black-box UAT (release tarball / SELinux)
# ---------------------------------------------------------------------------
log "black-box UAT (UAT_PLATFORM=opensuse UAT_INSTALL=tarball UAT_MAC=selinux, prebuilt tarball)"
run_guest_capture "black-box UAT inside the guest" \
  "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_VERSION=$VERSION UAT_PLATFORM=opensuse UAT_INSTALL=tarball UAT_MAC=selinux UAT_ARTIFACT_PATH=/opt/uat-import/docker-helper.tar.gz UAT_ARTIFACT_SHA256=$UAT_TARBALL_SHA256 scripts/uat-blackbox.sh"
log "black-box UAT passed inside the guest"

# ---------------------------------------------------------------------------
# 8. Summary
# ---------------------------------------------------------------------------
T1="$(date +%s)"
TOTAL=$((T1 - T0))
echo
echo "======= OPENSUSE/TUMBLEWEED TARBALL + SELINUX UAT SUMMARY ======="
echo "image:            $VM_IMG_NAME"
echo "image sha256:     $VM_IMG_SHA256"
echo "first boot:       ${VM_BOOT_TIME}s to SSH"
echo "MAC-switch reboot: ${VM_LAST_REBOOT_SECS}s back to SSH"
echo "initial LSM:      $RAW_LSM (selinux=$SELINUX_ACTIVE apparmor=$APPARMOR_ACTIVE)"
echo "final LSM:        $LSM_FINAL"
echo "final cmdline:    $CMDLINE_FINAL"
echo "getenforce:       $GETENF"
echo "tarball:          $UAT_TARBALL"
echo "tarball sha256:   $UAT_TARBALL_SHA256 (producer, verified by UAT)"
echo "UAT version:      $VERSION"
echo "Docker SELinux:   ${DOCKER_HEALTHY:-0}=naturally healthy two-stage setup (container-selinux before Docker)"
echo "total:            ${TOTAL}s"
echo "RESULT: openSUSE/Tumbleweed release-tarball + SELinux black-box UAT PASSED inside the VM"
echo "=============================================================="
log "DONE"
