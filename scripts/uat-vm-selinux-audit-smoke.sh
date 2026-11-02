#!/usr/bin/env bash
# Audit-only SELinux VM smoke. Intentionally NO Docker Helper RPM, Docker,
# app build, service, or production security policy changes.
set -euo pipefail
unset UAT_KEEP
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX='[selinux-audit-smoke]'
log() { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }
# Canonical VM SELinux bootstrap provides vm_init, vm_selinux_bootstrap, vm_ssh.
# shellcheck source=scripts/uat-vm-opensuse-selinux-lib.sh
source "$SCRIPT_DIR/uat-vm-opensuse-selinux-lib.sh"
trap 'vm_serial_tail' ERR
vm_selinux_bootstrap
log '== transfer standalone audit control to guest =='
vm_ssh 'sudo tee /tmp/uat-selinux-audit-smoke-guest.sh >/dev/null' \
  < "$SCRIPT_DIR/uat-selinux-audit-smoke-guest.sh" || fail 'probe transfer failed'
log '== audit positive control inside SELinux Enforcing QEMU guest =='
vm_ssh 'sudo -E env UAT_DISPOSABLE_VM=YES bash /tmp/uat-selinux-audit-smoke-guest.sh' \
  || fail 'audit positive control failed or BLOCKED'
log 'AUDIT_SMOKE_VM_PASS'
