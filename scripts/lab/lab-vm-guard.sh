#!/usr/bin/env bash
#
# lab-vm-guard.sh — shared fail-closed guard for DESTRUCTIVE lab scripts.
#
# Every lab script that stops services, removes binaries, creates accounts,
# rotates credentials, or otherwise mutates system state MUST call
# require_lab_vm before its first state change. The guard proves the script
# runs inside the disposable lab VM by checking the trust marker written by
# the trusted bootstrap (scripts/dev-vm-local.sh):
#
#   * the marker file exists and is readable (/etc/docker-helper-lab-vm);
#   * the first field carries the expected marker tag;
#   * the second field carries the supported marker version;
#   * the third field equals the running system's /etc/machine-id, so a stray
#     copy of the marker on the physical host (different machine-id) fails.
#
# The marker is NOT a cryptographic proof of virtualization. It protects the
# physical host from ACCIDENTAL provisioning runs, not from an already
# privileged attacker.
#
# Guard bypass: there is deliberately NO environment override for the marker
# path, tag, or version. Ordinary environment variables cannot disable the
# guard. The only seam is the optional first ARGUMENT of require_lab_vm,
# which exists for the test harness (scripts/lab/test-lab-vm-guard.sh);
# production scripts call it with no arguments.
#
# Sourcing contract: this file defines functions and constants only and has
# no side effects at source time. Scripts source it from their own
# SCRIPT_DIR (the lab scripts are copied into the guest as one directory).

LAB_VM_GUARD_TAG="docker-helper-lab-vm"
LAB_VM_GUARD_VERSION="1"
LAB_VM_GUARD_MARKER_PATH="/etc/docker-helper-lab-vm"

lab_vm_guard_die() {
  printf '[lab-vm-guard] ERROR: %s\n' "$*" >&2
  exit 1
}

# require_lab_vm [marker_path]
#   Fail closed unless the running system is the lab VM. The optional
#   argument overrides the marker path for the TEST harness only.
require_lab_vm() {
  local marker="${1:-$LAB_VM_GUARD_MARKER_PATH}"
  local tag ver marker_mid system_mid

  [ -r "$marker" ] \
    || lab_vm_guard_die "not the lab VM: missing $marker (created by scripts/dev-vm-local.sh)"

  read -r tag ver marker_mid _ < "$marker" \
    || lab_vm_guard_die "malformed lab VM marker $marker"
  [ "$tag" = "$LAB_VM_GUARD_TAG" ] \
    || lab_vm_guard_die "unexpected lab VM marker tag '$tag' (want '$LAB_VM_GUARD_TAG')"
  [ "$ver" = "$LAB_VM_GUARD_VERSION" ] \
    || lab_vm_guard_die "unsupported lab VM marker version '$ver' (want '$LAB_VM_GUARD_VERSION')"

  [ -r /etc/machine-id ] \
    || lab_vm_guard_die "no /etc/machine-id to verify the lab VM marker"
  system_mid="$(cat /etc/machine-id)"
  [ -n "$system_mid" ] \
    || lab_vm_guard_die "empty /etc/machine-id to verify the lab VM marker"
  [ "$marker_mid" = "$system_mid" ] \
    || lab_vm_guard_die "lab VM marker machine-id mismatch (physical host?)"
}
