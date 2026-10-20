#!/usr/bin/env bash
#
# provision-lab-vm.sh — orchestrate the provisioning of the EXISTING lab VM:
# snapshot, a temporary ONLINE window (packages, Docker Helper v2.3.0,
# operator files, pinned OCI images), then back to the ISOLATED posture with
# offline verification.
#
# Stages (explicit, individually runnable, in this order for `all`):
#
#   provision-lab-vm.sh snapshot
#       stop the VM if it is running, take an internal qcow2 snapshot
#       (`qemu-img snapshot -c pre-provisioning`) of the persistent disk and
#       leave the VM stopped. Idempotent: an existing snapshot is kept.
#
#   provision-lab-vm.sh online
#       boot the VM with the network OPEN (DEV_VM_NET_ISOLATED=0 — the
#       supported per-invocation knob of the existing VM driver; no driver
#       modification), copy the lab scripts into /opt/lab, then inside the
#       guest: install Docker (signature-checked zypper), provision the agent
#       account (phase 1 of setup-agent-user.sh), install Docker Helper
#       v2.3.0 with the minimal --allowed-root, complete the agent setup
#       (phase 2), transfer operator files (SSH key / CA / gitconfig /
#       known_hosts — all optional), optionally prove the corporate CA
#       against a live TLS endpoint (LAB_CA_TEST_URL), and pre-pull the
#       pinned OCI images. The stage ends by STOPPING the VM. The untrusted
#       model is never launched during this window.
#
#   provision-lab-vm.sh isolate
#       boot with DEV_VM_NET_ISOLATED=1 and prove the isolated posture with
#       the full host+guest isolation probe.
#
#   provision-lab-vm.sh verify
#       run the offline integration suite inside the VM.
#
#   provision-lab-vm.sh all
#       snapshot -> online -> isolate -> verify.
#
# Invariants:
#   * the physical host is never modified here: no packages, no firewall, no
#     Docker or SSH configuration changes;
#   * every guest-side mutation runs through scripts carrying the lab-VM
#     guard;
#   * the VM always returns to the isolated network posture;
#   * secrets (SSH key, CA, tokens) are passed only via operator environment
#     variables, transferred over SSH, and never printed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEVVM="$SCRIPT_DIR/../dev-vm-local.sh"

log() { printf '[provision-lab-vm] %s\n' "$*"; }
die() { printf '[provision-lab-vm] ERROR: %s\n' "$*" >&2; exit 1; }

[ -f "$DEVVM" ] || die "cannot find scripts/dev-vm-local.sh next to this script"

vm_field() { # FIELD REGEX — read one field from dev-vm-local.sh status
  "$DEVVM" status 2>/dev/null | awk -v f="$1" '$1 == f":" {print $2}'
}

vm_state() { vm_field state; }
vm_workdir() { vm_field workdir; }

stop_vm_if_running() {
  if [ "$(vm_state)" = running ]; then
    log "stopping the VM before the next stage"
    "$DEVVM" stop
  fi
}

# --- online window lifecycle (single owner) ---------------------------------
# F2: after the VM boots with the network open, EVERY exit path must close
# the window: a successful stage stops the VM and verifies the stop; a
# failure (EXIT trap, INT, TERM or a plain command error) attempts the stop
# and preserves the original exit code. A FAILED stop must never look like
# success: it reports CRITICAL with the actual VM state and the recovery
# command instead. The trap is installed only for the online stage and is
# removed on the normal path, so no competing cleanup owners exist.
# SIGKILL cannot be trapped (documented residual risk): the preflight of the
# next online run stops any leftover open VM before opening a new window.
ONLINE_VM_STARTED=0

online_window_stop_failure() { # REASON
  printf 'CRITICAL: %s\n' "$1" >&2
  printf 'CRITICAL: the VM may still be running with the network OPEN.\n' >&2
  printf 'CRITICAL: current VM state: %s\n' "$(vm_state)" >&2
  printf 'CRITICAL: recovery: scripts/dev-vm-local.sh stop   (then re-run provision-lab-vm.sh online)\n' >&2
}

online_cleanup() { # ORIGINAL_RC
  local rc="$1"
  trap - EXIT INT TERM
  if [ "$ONLINE_VM_STARTED" = 1 ]; then
    log "the online window is closing: stopping the VM"
    if ! "$DEVVM" stop; then
      ONLINE_VM_STARTED=0
      online_window_stop_failure "the VM stop command failed"
      exit 1
    fi
    ONLINE_VM_STARTED=0
    if [ "$(vm_state)" = running ]; then
      online_window_stop_failure "the VM is still running after the stop command"
      exit 1
    fi
    log "VM stopped; the online window is closed"
  fi
  exit "$rc"
}

# Normal-path close: stop the VM and PROVE it is stopped before the stage
# may report success. Never claims isolation was restored by itself.
close_online_window() {
  trap - EXIT INT TERM
  ONLINE_VM_STARTED=0
  log "closing the online window: stopping the VM"
  if ! "$DEVVM" stop; then
    online_window_stop_failure "the VM stop command failed"
    exit 1
  fi
  if [ "$(vm_state)" = running ]; then
    online_window_stop_failure "the VM is still running after the stop command"
    exit 1
  fi
}

stage_snapshot() {
  local workdir disk
  stop_vm_if_running
  workdir="$(vm_workdir)"
  [ -n "$workdir" ] || die "cannot determine the VM workdir (dev-vm-local.sh status)"
  disk="$workdir/disk.qcow2"
  [ -f "$disk" ] || die "no VM disk at $disk (create the VM first)"
  if qemu-img snapshot -l "$disk" 2>/dev/null | awk '{print $2}' | grep -qx 'pre-provisioning'; then
    log "snapshot 'pre-provisioning' already exists (kept)"
  else
    log "taking internal snapshot 'pre-provisioning' of $disk"
    qemu-img snapshot -c pre-provisioning "$disk" || die "qemu-img snapshot failed"
  fi
  log "snapshot stage done (VM stopped)"
}

copy_lab_scripts() {
  log "copying the lab scripts into /opt/lab"
  "$DEVVM" ssh 'sudo mkdir -p /opt/lab' < /dev/null || die "cannot create /opt/lab"
  local f
  for f in "$SCRIPT_DIR"/*.sh; do
    [ -f "$f" ] || continue
    "$DEVVM" ssh "sudo tee /opt/lab/$(basename "$f") >/dev/null" < "$f" \
      || die "cannot copy $(basename "$f") into the VM"
  done
  "$DEVVM" ssh 'sudo chmod 0644 /opt/lab/*.sh' < /dev/null || die "cannot fix /opt/lab modes"
}

pull_pinned_images() {
  log "pre-pulling the pinned OCI images as the agent account"
  local refs
  refs="$(
    SCRIPT_DIR="$SCRIPT_DIR" bash -c '
      # shellcheck source=/dev/null
      source "$SCRIPT_DIR/agent-aliases.sh"
      printf "%s\n%s\n" "$_OC_BASE" "$_OC_GO26"
    '
  )" || die "cannot resolve the pinned image digests"
  local ref
  while IFS= read -r ref; do
    [ -n "$ref" ] || continue
    log "pulling $ref"
    "$DEVVM" ssh "sudo -u agent -H docker pull '$ref'" < /dev/null \
      || die "image pull failed: $ref"
  done <<< "$refs"
}

verify_positive_tls() {
  # Optional positive CA evidence during the online window: a REAL corporate
  # TLS endpoint must validate against the provisioned CA copy. Requires
  # LAB_CA_SOURCE (the CA name derives from it) and LAB_CA_TEST_URL.
  [ -n "${LAB_CA_SOURCE:-}" ] || return 0
  [ -n "${LAB_CA_TEST_URL:-}" ] || return 0
  local ca_name
  ca_name="$(basename -- "$LAB_CA_SOURCE")"
  log "positive TLS check against $LAB_CA_TEST_URL with the provisioned CA"
  "$DEVVM" ssh "curl --cacert '/etc/docker-helper/$ca_name.crt' -fsS --max-time 20 '$LAB_CA_TEST_URL' >/dev/null && echo CA_TLS_OK" < /dev/null \
    | grep -q CA_TLS_OK || die "the corporate CA did not validate $LAB_CA_TEST_URL"
  log "positive TLS evidence recorded"
}

stage_online() {
  stop_vm_if_running
  log "preflight: any leftover online VM from a killed previous run is closed before this window opens"
  log "booting with the network OPEN (temporary provisioning window)"
  DEV_VM_NET_ISOLATED=0 "$DEVVM" start || die "VM start (network open) failed"
  ONLINE_VM_STARTED=1
  trap 'online_cleanup "$?"' EXIT
  trap 'online_cleanup 130' INT
  trap 'online_cleanup 143' TERM

  copy_lab_scripts

  log "installing Docker (inside the VM)"
  "$DEVVM" ssh 'sudo bash /opt/lab/install-docker-vm.sh' < /dev/null || die "docker install failed"

  log "provisioning the agent account (phase 1)"
  "$DEVVM" ssh 'sudo bash /opt/lab/setup-agent-user.sh' < /dev/null || die "agent provisioning (phase 1) failed"

  log "installing Docker Helper v2.3.0 (pinned artifact)"
  "$DEVVM" ssh 'sudo bash /opt/lab/install-docker-helper-v230.sh' < /dev/null || die "docker-helper install failed"

  log "completing the agent provisioning (phase 2)"
  "$DEVVM" ssh 'sudo bash /opt/lab/setup-agent-user.sh' < /dev/null || die "agent provisioning (phase 2) failed"

  log "transferring operator files (optional items)"
  bash "$SCRIPT_DIR/provision-operator-files.sh" || die "operator file provisioning failed"

  verify_positive_tls

  pull_pinned_images

  close_online_window
  log "online stage done (VM stopped; the isolated posture is restored on the next boot)"
}

stage_isolate() {
  stop_vm_if_running
  log "booting with DEV_VM_NET_ISOLATED=1 (isolated posture)"
  DEV_VM_NET_ISOLATED=1 "$DEVVM" start || die "VM start (isolated) failed"
  log "proving the isolated network posture"
  bash "$SCRIPT_DIR/probe-vm-isolation.sh" host || die "network isolation verification failed"
  log "isolate stage done"
}

# --- F3: verify proves isolation, it never assumes it ------------------------
# A running VM may have been booted with the network open, so the actual
# QEMU command line of THIS VM's disk is inspected on the host: exactly one
# QEMU process, exactly one user-mode netdev backend carrying restrict=on,
# and the loopback SSH hostfwd as the only host->guest channel. The guest
# egress posture is then re-proved with the full host+guest isolation probe.
# No environment variable of the current shell is consulted. Any ambiguity
# or missing evidence is fail-closed; verify never changes the network mode.
verify_vm_isolation() {
  local workdir disk evidence pid cmdline netdev_arg
  workdir="$(vm_workdir)"
  [ -n "$workdir" ] || die "cannot determine the VM workdir (dev-vm-local.sh status)"
  disk="$workdir/disk.qcow2"
  command -v pgrep >/dev/null 2>&1 \
    || die "cannot inspect the QEMU process (pgrep unavailable); refusing to verify"
  evidence="$(pgrep -af 'qemu-system' 2>/dev/null | grep -F -- "$disk" || true)"
  [ -n "$evidence" ] || die "no QEMU process found for $disk: the VM is not provably running"
  [ "$(printf '%s\n' "$evidence" | wc -l)" = 1 ] \
    || die "ambiguous QEMU state: multiple processes match $disk"
  pid="$(printf '%s' "$evidence" | awk '{print $1}')"
  cmdline="$(printf '%s' "$evidence" | cut -d' ' -f2-)"
  [ "$(printf '%s' "$cmdline" | grep -oE ' (-netdev|-nic) ' | wc -l)" = 1 ] \
    || die "unexpected additional network backends in the QEMU command line"
  netdev_arg="$(printf '%s' "$cmdline" | sed -n 's/.* -netdev \([^ ]*\).*/\1/p')"
  [ -n "$netdev_arg" ] || die "no -netdev backend found in the QEMU command line"
  case "$netdev_arg" in
    *restrict=on*) ;;
    *) die "the VM's netdev is not isolated (restrict=on missing)" ;;
  esac
  case "$netdev_arg" in
    *hostfwd=tcp:127.0.0.1:*) ;;
    *) die "the loopback SSH host->guest channel is missing" ;;
  esac
  log "QEMU pid $pid verified: single slirp backend with restrict=on, loopback SSH hostfwd"
}

stage_verify() {
  if [ "$(vm_state)" != running ]; then
    die "the VM is not running (run the isolate stage first)"
  fi
  verify_vm_isolation
  log "re-proving guest egress isolation with the full host+guest probe"
  bash "$SCRIPT_DIR/probe-vm-isolation.sh" host \
    || die "the network isolation probe failed: refusing to integrate"
  log "running the offline integration suite inside the VM"
  "$DEVVM" ssh 'sudo bash /opt/lab/integration-agent-vm.sh' < /dev/null \
    || die "offline integration failed"
  log "verify stage done"
}

stage="${1:-}"
[ "$#" -gt 0 ] && shift || true
case "$stage" in
  snapshot) stage_snapshot ;;
  online)   stage_online ;;
  isolate)  stage_isolate ;;
  verify)   stage_verify ;;
  all)      stage_snapshot; stage_online; stage_isolate; stage_verify ;;
  ""|-h|--help|help)
    cat <<'EOF'
usage: provision-lab-vm.sh snapshot|online|isolate|verify|all

  snapshot  stop the VM and take the pre-provisioning qcow2 snapshot
  online    temporary network-open window: Docker, Docker Helper v2.3.0,
            agent provisioning, operator files, pinned image pre-pull
  isolate   boot isolated (DEV_VM_NET_ISOLATED=1) and prove the posture
  verify    run the offline integration suite inside the VM
  all       snapshot -> online -> isolate -> verify

Optional operator env: LAB_AGENT_SSH_KEY, LAB_CA_SOURCE,
LAB_GITCONFIG_SOURCE, LAB_KNOWN_HOSTS_SOURCE, LAB_CA_TEST_URL (online).
EOF
    ;;
  *) die "unknown stage '$stage' (snapshot|online|isolate|verify|all)" ;;
esac
