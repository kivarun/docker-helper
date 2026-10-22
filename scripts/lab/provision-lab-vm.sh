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
  local rc="$1" state
  trap - EXIT INT TERM
  if [ "$ONLINE_VM_STARTED" = 1 ]; then
    ONLINE_VM_STARTED=0
    # R2: the window opened with the start ATTEMPT. Whatever the state is
    # now, the only acceptable outcome is a PROVEN stopped VM. 'unknown',
    # an empty status or a failing status query are NOT proof of a stop.
    state="$(vm_state 2>/dev/null || true)"
    if [ "$state" != stopped ]; then
      log "the online window is closing: VM state '${state:-unknown}': stopping the VM"
      if ! "$DEVVM" stop; then
        online_window_stop_failure "the VM stop command failed"
        exit 1
      fi
    fi
    state="$(vm_state 2>/dev/null || true)"
    if [ "$state" != stopped ]; then
      online_window_stop_failure "the VM is not proven stopped (state: ${state:-unknown})"
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
  local state
  state="$(vm_state 2>/dev/null || true)"
  if [ "$state" != stopped ]; then
    online_window_stop_failure "the VM is not proven stopped (state: ${state:-unknown})"
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
  # UAT-7: awk consumes the whole listing and decides alone — no early-exit
  # reader that could SIGPIPE the writer and misread an existing snapshot.
  if qemu-img snapshot -l "$disk" 2>/dev/null | awk '$2 == "pre-provisioning" { found = 1 } END { exit found ? 0 : 1 }'; then
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
    "$DEVVM" ssh "sudo -u agent -H docker pull $(ssh_sq "$ref")" < /dev/null \
      || die "image pull failed: $ref"
  done <<< "$refs"
}

# R6: host-supplied values are validated as WHOLE strings before anything
# crosses the SSH boundary, and every value interpolated into a remote
# command line is single-quote escaped by ssh_sq() (no re-interpretation).
valid_https_url() { # VALUE — scheme, host, optional port, safe path only
  printf '%s' "$1" | grep -qE '^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/:@?=%+!,-]*)?$'
}
ssh_sq() { # VALUE -> a single-quoted remote-shell-safe token
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

base_image_ref() {
  SCRIPT_DIR="$SCRIPT_DIR" bash -c '
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/agent-aliases.sh"
    printf "%s" "$_OC_BASE"
  '
}

# UAT-7: every marker-based diagnostic runs through this helper. The old
# `ssh ... | grep -q MARKER` closed the read pipe as soon as grep matched,
# SIGPIPE-killing the SSH driver mid-stream (rc 141) and turning a real
# PASS into a false FAIL under set -o pipefail. The helper instead consumes
# the WHOLE command output first, checks the exit status separately, and
# only then searches the completed output for the marker. Fail-closed: an
# SSH/Docker/curl failure stays a failure even when the marker text appears
# in its output, and a zero exit without the marker is a failure too. The
# captured output is never printed — only the exit status and the caller's
# message reach the log — so tokens, certificate contents and other secret
# material in diagnostic payloads cannot leak.
ssh_diag_expect() { # MARKER FAILURE_MESSAGE -- cmd...
  local marker="$1" failmsg="$2"
  shift 2
  [ "${1:-}" = "--" ] || die "internal: ssh_diag_expect requires --"
  shift
  local out rc
  if out="$("$@" < /dev/null 2>&1)"; then rc=0; else rc=$?; fi
  if [ "$rc" -ne 0 ]; then
    die "$failmsg (the diagnostic command exited $rc)"
  fi
  case "$out" in
    *"$marker"*) return 0 ;;
    *) die "$failmsg (exit 0, but no $marker in the completed output)" ;;
  esac
}

# F6 runtime evidence, gathered in the online window with REAL controlled
# endpoints (the model is never launched here; these are one-off diagnostic
# containers without any session):
#   1. corporate TLS positive — the guest validates a live corporate endpoint
#      against the provisioned CA copy;
#   2. corporate TLS positive — a one-off container with the lab CA mount
#      validates the same endpoint (requires the combined bundle);
#   3. public TLS positive — the same container setup still trusts a public
#      CA chain, proving the corporate CA did not replace public trust.
verify_online_tls() {
  # R6: URLs are validated as whole strings on the physical host BEFORE any
  # guest command is built; a malicious value never reaches the guest.
  if [ -n "${LAB_CA_TEST_URL:-}" ]; then
    valid_https_url "$LAB_CA_TEST_URL" \
      || die "LAB_CA_TEST_URL must be an https:// URL with a plain host, optional port and a safe path: refusing"
  fi
  if [ -n "${LAB_PUBLIC_TLS_URL:-}" ]; then
    valid_https_url "$LAB_PUBLIC_TLS_URL" \
      || die "LAB_PUBLIC_TLS_URL must be an https:// URL with a plain host, optional port and a safe path: refusing"
  fi
  # R5: every diagnostic docker run is gated by the SAME mount-source library
  # the launcher uses. The gate runs INSIDE the guest (it must inspect the
  # guest filesystem) against /opt/lab/lab-mount-gate.sh, which is a
  # root-owned repository artifact copied by the controlled provisioning
  # stage — never a user-writable file.
  guest_ca_source_ok() { # -> 0 when the guest CA source passes the gate
    # UAT-3/F1 + UAT-3b: the gate runs INSIDE the agent's context, and cd,
    # the trusted library load and the check happen in ONE bash process —
    # `sh -c "... bash lib && func"` would define the function in a child
    # bash that exits and then call a function the parent sh never had.
    # The agent home is 0700 agent-owned, so the run as agent (-H sets the
    # home) from /home/agent is the only context that can traverse the
    # source. The library is loaded from the trusted root-owned /opt/lab
    # copy of the single canonical gate library. Fail-closed semantics are
    # unchanged: any gate failure refuses the diagnostic docker run.
    "$DEVVM" ssh 'sudo -u agent -H bash -c "cd /home/agent && source /opt/lab/lab-mount-gate.sh && oc_lab_mount_source_ok dir /home/agent/.opencode-docker/ca /home/agent/.opencode-docker"' < /dev/null
  }
  # (1) guest-level corporate positive
  if [ -n "${LAB_CA_SOURCE:-}" ] && [ -n "${LAB_CA_TEST_URL:-}" ]; then
    local ca_name
    ca_name="$(basename -- "$LAB_CA_SOURCE")"
    log "positive TLS check (guest) against $LAB_CA_TEST_URL with the provisioned CA"
    ssh_diag_expect CA_TLS_OK "the corporate CA did not validate $LAB_CA_TEST_URL" -- \
      "$DEVVM" ssh "curl --cacert $(ssh_sq "/etc/docker-helper/$ca_name.crt") -fsS --max-time 20 $(ssh_sq "$LAB_CA_TEST_URL") >/dev/null && echo CA_TLS_OK"
    log "positive TLS evidence recorded (guest)"
    # (2)/(3) container-level evidence through a one-off diagnostic container
    local base_image container_env=""
    base_image="$(base_image_ref)" || base_image=""
    if [ -n "$base_image" ]; then
      if ! guest_ca_source_ok; then
        die "the diagnostic CA mount source failed the shared mount gate: refusing to run docker"
      fi
      # F2: the diagnostics follow the launcher's trust contract exactly —
      # NODE_EXTRA_CA_CERTS only when the corporate certificate exists, the
      # replacing variables only when the combined bundle exists. A missing
      # combined bundle never produces a false PASS: the container corporate
      # check is skipped with an explicit note instead.
      if "$DEVVM" ssh "test -f '/home/agent/.opencode-docker/ca/combined-ca-bundle.crt'" < /dev/null; then
        container_env="-e NODE_EXTRA_CA_CERTS=/etc/opencode-ca/$ca_name.crt -e SSL_CERT_FILE=/etc/opencode-ca/combined-ca-bundle.crt -e CURL_CA_BUNDLE=/etc/opencode-ca/combined-ca-bundle.crt -e GIT_SSL_CAINFO=/etc/opencode-ca/combined-ca-bundle.crt"
        log "positive TLS check (container, corporate) against $LAB_CA_TEST_URL"
        # F6: the certificate must be really present and readable inside the
        # diagnostic container before any positive claim is made.
        ssh_diag_expect CONTAINER_CA_CERT_READABLE "the corporate CA certificate is not readable inside the diagnostic container" -- \
          "$DEVVM" ssh "sudo -u agent -H docker run --rm -v $(ssh_sq '/home/agent/.opencode-docker/ca:/etc/opencode-ca:ro,z') $container_env --entrypoint /bin/sh $(ssh_sq "$base_image") -c $(ssh_sq "test -r /etc/opencode-ca/$ca_name.crt && test -r /etc/opencode-ca/combined-ca-bundle.crt && echo CONTAINER_CA_CERT_READABLE")"
        ssh_diag_expect CONTAINER_CA_OK "the container did not validate the corporate endpoint with the combined bundle" -- \
          "$DEVVM" ssh "sudo -u agent -H docker run --rm -v $(ssh_sq '/home/agent/.opencode-docker/ca:/etc/opencode-ca:ro,z') $container_env --entrypoint /bin/sh $(ssh_sq "$base_image") -c $(ssh_sq "curl -fsS --max-time 20 '$LAB_CA_TEST_URL' >/dev/null && echo CONTAINER_CA_OK")"
        log "positive TLS evidence recorded (container, corporate)"
      elif "$DEVVM" ssh "test -f '/home/agent/.opencode-docker/ca/$ca_name.crt'" < /dev/null; then
        # F6: without the combined bundle, curl has no corporate trust, but
        # Node honours NODE_EXTRA_CA_CERTS alone — use it for the corporate
        # chain when Node exists in the pinned image.
        container_env="-e NODE_EXTRA_CA_CERTS=/etc/opencode-ca/$ca_name.crt"
        log "positive TLS check (container, corporate, Node-only) against $LAB_CA_TEST_URL"
        ssh_diag_expect CONTAINER_CA_NODE_OK "the container did not validate the corporate endpoint through Node" -- \
          "$DEVVM" ssh "sudo -u agent -H docker run --rm -v $(ssh_sq '/home/agent/.opencode-docker/ca:/etc/opencode-ca:ro,z') $container_env --entrypoint /bin/sh $(ssh_sq "$base_image") -c $(ssh_sq "test -r /etc/opencode-ca/$ca_name.crt && test -x /usr/bin/node && node -e \"require('https').get('$LAB_CA_TEST_URL', r => { console.log('CONTAINER_CA_NODE_OK'); process.exit(0); }).on('error', () => { console.log('CONTAINER_CA_NODE_FAIL'); process.exit(1); })\"")"
        log "positive TLS evidence recorded (container, corporate, Node-only)"
      else
        log "container corporate TLS evidence skipped: no corporate trust available in the diagnostic container"
      fi
    else
      log "container TLS evidence skipped: the pinned image reference is unavailable"
    fi
  fi
  # (3b) public TLS positive — with or without a provisioned CA
  local public_url="${LAB_PUBLIC_TLS_URL:-https://www.gnu.org/}"
  local base_image container_env=""
  base_image="$(base_image_ref)" || base_image=""
  if [ -n "$base_image" ]; then
    if [ -n "${LAB_CA_SOURCE:-}" ]; then
      if ! guest_ca_source_ok; then
        die "the diagnostic CA mount source failed the shared mount gate: refusing to run docker"
      fi
      # F2: NODE_EXTRA_CA_CERTS only when the corporate copy exists; the
      # replacing variables only when the combined bundle exists.
      if "$DEVVM" ssh "test -f '/home/agent/.opencode-docker/ca/$(basename -- "$LAB_CA_SOURCE").crt'" < /dev/null; then
        container_env="-e NODE_EXTRA_CA_CERTS=/etc/opencode-ca/$(basename -- "$LAB_CA_SOURCE").crt"
      fi
      if "$DEVVM" ssh "test -f '/home/agent/.opencode-docker/ca/combined-ca-bundle.crt'" < /dev/null; then
        container_env="$container_env -e SSL_CERT_FILE=/etc/opencode-ca/combined-ca-bundle.crt -e CURL_CA_BUNDLE=/etc/opencode-ca/combined-ca-bundle.crt -e GIT_SSL_CAINFO=/etc/opencode-ca/combined-ca-bundle.crt"
      fi
    fi
    log "positive TLS check (container, public) against $public_url"
    ssh_diag_expect CONTAINER_PUBLIC_OK "the container lost trust in the public CA chain (TLS trust was replaced, not extended)" -- \
      "$DEVVM" ssh "sudo -u agent -H docker run --rm ${container_env:+-v $(ssh_sq '/home/agent/.opencode-docker/ca:/etc/opencode-ca:ro,z')} $container_env --entrypoint /bin/sh $(ssh_sq "$base_image") -c $(ssh_sq "curl -fsS --max-time 20 '$public_url' >/dev/null && echo CONTAINER_PUBLIC_OK")"
    log "positive TLS evidence recorded (container, public)"
  fi
}

stage_online() {
  stop_vm_if_running
  log "preflight: any leftover online VM from a killed previous run is closed before this window opens"
  # R2: the lifecycle owns the start ATTEMPT. The traps are installed BEFORE
  # the VM boots with the network open, so a failed start with a booted QEMU
  # (readiness or cloud-init timeout) still closes the window. Double cleanup
  # is impossible: the flags and traps are managed only here.
  ONLINE_VM_STARTED=1
  trap 'online_cleanup "$?"' EXIT
  trap 'online_cleanup 130' INT
  trap 'online_cleanup 143' TERM
  log "booting with the network OPEN (temporary provisioning window)"
  DEV_VM_NET_ISOLATED=0 "$DEVVM" start || die "VM start (network open) failed"

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

  verify_online_tls

  pull_pinned_images

  # UAT-4/F2: the lab VM is IPv4-only — ipv6.disable=1 goes into the guest
  # boot config while the VM is up; the reboot into the isolated posture
  # applies it and the probe verifies it. Fail-closed: a boot config that
  # does not verifiably carry the token fails the online stage.
  log "disabling IPv6 at the guest OS level (persistent boot config)"
  "$DEVVM" set-ipv6-disable || die "setting ipv6.disable=1 in the guest boot config failed"

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

# --- UAT-8: the networked integration UAT stage ------------------------------
# An EXPLICIT networked mode for the real integration work. This is a
# different threat model from the isolate stage: the guest network is ON.
#   * the mode is selected only by running this stage — no implicit removal
#     of restrict=on happens anywhere;
#   * this run never claims isolation: the isolation evidence stays with the
#     isolate stage and the standalone network probe, and verify refuses any
#     VM whose QEMU argv does not carry restrict=on;
#   * the network window is closed on EVERY exit path by the same lifecycle
#     owner as the online window (ONLINE_VM_STARTED + traps), and the stop
#     is confirmed before the stage reports success;
#   * nothing in the integration contract is weakened: the same SELinux
#     domain, DAC, mount gate, bearer boundary and Docker security options.
stage_uat_networked() {
  stop_vm_if_running
  log "preflight: any leftover VM from a killed previous run is closed before this window opens"
  ONLINE_VM_STARTED=1
  trap 'online_cleanup "$?"' EXIT
  trap 'online_cleanup 130' INT
  trap 'online_cleanup 143' TERM
  log "booting with the network OPEN (explicit networked UAT window)"
  DEV_VM_NET_ISOLATED=0 "$DEVVM" start || die "VM start (network open) failed"
  copy_lab_scripts
  log "running the networked integration UAT (INTEGRATION_NETWORKED=1)"
  "$DEVVM" ssh 'sudo env INTEGRATION_NETWORKED=1 bash /opt/lab/integration-agent-vm.sh' < /dev/null \
    || die "networked integration UAT failed"
  close_online_window
  log "networked UAT stage done (the network window is closed and the VM is confirmed stopped)"
}

# --- UAT-8c: the standalone launch-path diagnostic stage ---------------------
# An EXPLICIT diagnostic stage for the real UAT's timeout-124 hang. It uses
# the SAME network-window lifecycle owner as the online stage (the
# ONLINE_VM_STARTED flag and its traps — no second lifecycle owner), runs
# the bounded D0–D4 diagnostic ladder inside the networked VM, and ALWAYS
# closes the window and confirms the VM is stopped, on every outcome. It
# never runs the integration UAT and never touches an LLM. The stage's exit
# status reflects the ladder's outcome, but only AFTER the window is
# confirmed closed.
stage_uat_diagnose() {
  stop_vm_if_running
  log "preflight: any leftover VM from a killed previous run is closed before this window opens"
  ONLINE_VM_STARTED=1
  trap 'online_cleanup "$?"' EXIT
  trap 'online_cleanup 130' INT
  trap 'online_cleanup 143' TERM
  log "booting with the network OPEN (explicit diagnostic window)"
  DEV_VM_NET_ISOLATED=0 "$DEVVM" start || die "VM start (network open) failed"
  copy_lab_scripts
  log "running the bounded launch-path diagnostics (no integration UAT, no LLM)"
  DIAG_RC=0
  "$DEVVM" ssh 'sudo bash /opt/lab/diagnose-launch.sh' < /dev/null || DIAG_RC=$?
  close_online_window
  if [ "$DIAG_RC" != 0 ]; then
    die "the launch diagnostics reported failures (rc $DIAG_RC) — the network window is closed"
  fi
  log "uat-diagnose stage done (the network window is closed and the VM is confirmed stopped)"
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
  uat-networked) stage_uat_networked ;;
  uat-diagnose) stage_uat_diagnose ;;
  all)      stage_snapshot; stage_online; stage_isolate; stage_verify ;;
  ""|-h|--help|help)
    cat <<'EOF'
usage: provision-lab-vm.sh snapshot|online|isolate|verify|uat-networked|uat-diagnose|all

  snapshot  stop the VM and take the pre-provisioning qcow2 snapshot
  online    temporary network-open window: Docker, Docker Helper v2.3.0,
            agent provisioning, operator files, pinned image pre-pull
  isolate   boot isolated (DEV_VM_NET_ISOLATED=1) and prove the posture
  verify    run the offline integration suite inside the VM
  uat-networked  EXPLICIT networked UAT window: run the networked
            integration suite (INTEGRATION_NETWORKED=1), then close the
            window and confirm the VM is stopped. Never an isolation claim.
  uat-diagnose   EXPLICIT diagnostic window: run the bounded D0-D4 launch
            diagnostics (no integration UAT, no LLM), then close the
            window and confirm the VM is stopped on every outcome.
  all       snapshot -> online -> isolate -> verify

Optional operator env: LAB_AGENT_SSH_KEY, LAB_CA_SOURCE,
LAB_GITCONFIG_SOURCE, LAB_KNOWN_HOSTS_SOURCE, LAB_CA_TEST_URL, LAB_PUBLIC_TLS_URL (online).
EOF
    ;;
  *) die "unknown stage '$stage' (snapshot|online|isolate|verify|uat-networked|uat-diagnose|all)" ;;
esac
