#!/usr/bin/env bash
#
# dev-vm-local.sh — persistent, isolated local openSUSE Tumbleweed VM for
# docker-helper security work (pentest guest), driven by a NON-privileged user.
#
# Responsibility boundary (reuse, never a parallel harness):
#
#   THIS FILE (local persistent lifecycle ONLY)
#       |  create/start/stop/status/ssh/destroy, single-instance lock,
#       |  stale-pid handling, explicit destroy confirmation, isolation posture
#       v
#   scripts/uat-vm-opensuse-selinux-lib.sh   (shared SELinux host construction)
#       |  vm_selinux_bootstrap(): userspace/targeted-policy bootstrap, MAC
#       |  token selection + enforcing reboot proof
#       v
#   scripts/uat-vm-tumbleweed.sh             (canonical VM harness, sourced by
#       |  the lib): image+checksum, qcow overlay, KVM/TCG selection,
#       |  cloud-init NoCloud seed (cloud-localds or xorriso), QEMU boot,
#       |  vm_ssh/vm_scp transport, wait-for-SSH, serial-log diagnostics,
#       |  labeled cmdline+LSM evidence, boot-config MAC selector mutation.
#
# The harness keeps its CI defaults byte-for-byte; the local posture is applied
# only through the harness's explicit knobs (VM_WORKDIR, VM_PERSIST,
# VM_KVM_LOCAL, VM_ACCEL, VM_NET_ISOLATED, VM_SSH_PORT).
#
# Lifecycle contract:
#   * a persistent workdir + qcow2 overlay live under DEV_VM_DIR;
#   * start reuses the existing disk (never re-downloads/rebuilds it);
#   * the VM is never removed on script exit (VM_PERSIST), only by destroy;
#   * a single QEMU per workdir (pidfile + flock), stale pidfiles are reaped;
#   * destroy asks for explicit confirmation unless -y/--yes;
#   * serial.log stays in the workdir and is printed on any boot failure.
#
# Network posture (isolation): slirp user networking, loopback-only SSH
# hostfwd, and restrict=on so the guest cannot reach the physical host or its
# LAN — it keeps only its slirp-assigned address (no gateway/DNS, no outbound
# routing). No bridge, no host shares, no credential/socket passthrough.
#
# restrict=on also denies outbound routing, so the preparation pass (SELinux
# userspace + targeted policy install) cannot reach the openSUSE mirrors.
# `create` therefore boots the preparation pass with the network open and then
# reboots the SAME disk into the requested isolation posture and self-checks
# it, so the prepared VM is left isolated by default. DEV_VM_NET_ISOLATED
# selects that posture (0/no/off/false opens the network for later preparation
# such as the docker-helper install).
#
# Env inputs:
#   DEV_VM_DIR            persistent workdir (default ~/.local/state/docker-helper-dev-vm)
#   DEV_VM_SSH_PORT       loopback SSH port (default 2222)
#   DEV_VM_ACCEL          force kvm|tcg (default: kvm when /dev/kvm is usable)
#   DEV_VM_NET_ISOLATED   target network posture: 1 (default) restrict=on
#                         isolates the guest from host/LAN; 0/no/off/false
#                         opens the network. create always opens the network
#                         for its preparation pass, then adopts this posture.
#   UAT_REPO_DIR          host checkout (default: repo root) [for the lib]
#
# Exit codes: 0 ok; nonzero on failure (serial tail printed when available).

set -euo pipefail

PREFIX="[dev-vm-local]"
log()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() {
  printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2
  if [ -n "${VM_WORKDIR:-}" ] && [ -f "${VM_WORKDIR}/serial.log" ]; then
    vm_serial_tail
  fi
  exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# In-guest trust marker: the destructive lab scripts run only where this
# exists and its embedded machine-id matches the guest. Written by this
# trusted driver; the marker contract (tag, version, path) is owned by the
# shared guard library the guest scripts enforce it with.
# shellcheck source=lab/lab-vm-guard.sh
. "$SCRIPT_DIR/lab/lab-vm-guard.sh"
LAB_VM_MARKER="$LAB_VM_GUARD_MARKER_PATH"
LAB_VM_MARKER_TAG="$LAB_VM_GUARD_TAG"

# --- persistent state + local posture (exported BEFORE the lib sources the
# --- harness, so the harness reads them at source time) ---
VM_WORKDIR="${DEV_VM_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/docker-helper-dev-vm}"
VM_SSH_PORT="${DEV_VM_SSH_PORT:-2222}"
VM_USER="${VM_USER:-opc}"
export VM_WORKDIR VM_SSH_PORT VM_USER
export VM_PERSIST=1
export VM_KVM_LOCAL=1
export VM_NET_ISOLATED="${DEV_VM_NET_ISOLATED:-1}"
export VM_ACCEL="${DEV_VM_ACCEL:-}"

# shellcheck source=scripts/uat-vm-opensuse-selinux-lib.sh
source "$SCRIPT_DIR/uat-vm-opensuse-selinux-lib.sh"

# ---------------------------------------------------------------------------
# local lifecycle primitives (pidfile/lock/stale-pid) — no boot/seed/ssh here
# ---------------------------------------------------------------------------
PIDFILE() { printf '%s' "$VM_WORKDIR/qemu.pid"; }

vm_running() {
  local pf pid
  pf="$(PIDFILE)"
  [ -f "$pf" ] || return 1
  pid="$(cat "$pf" 2>/dev/null || true)"
  [ -n "$pid" ] || return 1
  kill -0 "$pid" 2>/dev/null
}

reap_stale_pid() {
  local pf pid
  pf="$(PIDFILE)"
  if [ -f "$pf" ] && ! vm_running; then
    pid="$(cat "$pf" 2>/dev/null || true)"
    log "reaping stale pidfile (pid ${pid:-?} not alive)"
    rm -f "$pf"
  fi
}

# Refuse a concurrent mutating operation on this workdir. flock is used when
# present (the fd is released automatically on exit).
acquire_lock() {
  mkdir -p "$VM_WORKDIR"
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$VM_WORKDIR/.lock"
    flock -n 9 || fail "another dev-vm-local operation holds $VM_WORKDIR/.lock"
  fi
}

stop_vm() {
  reap_stale_pid
  if ! vm_running; then
    log "VM is not running"
    return 0
  fi
  local pid
  pid="$(cat "$(PIDFILE)")"
  log "requesting guest poweroff (qemu pid $pid)"
  vm_ssh "sudo systemctl poweroff" >/dev/null 2>&1 || true
  local i
  for i in $(seq 1 60); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 2
  done
  if kill -0 "$pid" 2>/dev/null; then
    log "guest did not power off in time; terminating qemu"
    kill "$pid" 2>/dev/null || true
    for i in $(seq 1 15); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
  fi
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$(PIDFILE)"
  log "VM stopped"
}

# verify_isolation proves the running guest has a live link but no outbound
# path: the slirp NIC must carry an address (link is up) while an outbound TCP
# connection cannot complete. This is the observable effect of restrict=on;
# the thorough host-service/LAN probes stay in the acceptance checks.
verify_isolation() {
  vm_ssh 'bash -s' <<'RMT'
set -u
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ip -4 -o addr show scope global 2>/dev/null | grep -q 'inet ' || { echo "NO_LINK"; exit 1; }
if curl -s --max-time 5 http://1.1.1.1/ >/dev/null 2>&1; then
  echo "OUTBOUND_REACHABLE"; exit 2
fi
echo "ISOLATED_OK"
RMT
}

# Stamp the guest with the trust marker (fixed tag + guest machine-id). The
# in-guest provisioning requires it, so a stray marker on the physical host
# (whose machine-id differs) cannot pass.
write_lab_marker() {
  local mid
  mid="$(vm_ssh 'cat /etc/machine-id')" || return 1
  [ -n "$mid" ] || return 1
  printf '%s 1 %s\n' "$LAB_VM_MARKER_TAG" "$mid" \
    | vm_ssh "sudo tee $LAB_VM_MARKER >/dev/null"
  log "lab VM marker written: $LAB_VM_MARKER"
}

# ---------------------------------------------------------------------------
# operations
# ---------------------------------------------------------------------------
cmd_create() {
  vm_attach
  acquire_lock
  if [ -f "$VM_WORKDIR/disk.qcow2" ]; then
    fail "VM already exists at $VM_WORKDIR (use 'start', or 'destroy' first)"
  fi
  log "creating persistent VM in $VM_WORKDIR"
  log "guest user: $VM_USER  ssh: 127.0.0.1:$VM_SSH_PORT  accel: ${VM_ACCEL:-auto}  isolated: ${VM_NET_ISOLATED:-0}"
  # Preparation (SELinux userspace + targeted policy) needs outbound network,
  # which the isolated NIC denies, so run the preparation pass with the network
  # open and then adopt the requested posture on the same disk.
  local want_isolated="$VM_NET_ISOLATED"
  VM_NET_ISOLATED=""
  # vm_selinux_bootstrap() calls vm_init() (boot) then proves enforcing SELinux.
  vm_selinux_bootstrap
  if [ -n "$want_isolated" ] && [ "$want_isolated" != 0 ]; then
    log "preparation complete; rebooting into isolated network posture"
    stop_vm
    VM_NET_ISOLATED="$want_isolated"
    vm_init
    if ! verify_isolation; then
      fail "network isolation self-check failed on the prepared VM"
    fi
  fi
  write_lab_marker || fail "could not write the lab VM marker"
  log "VM created and running (SELinux enforcing, isolated=${VM_NET_ISOLATED:-0})"
}

cmd_start() {
  vm_attach
  acquire_lock
  [ -f "$VM_WORKDIR/disk.qcow2" ] || fail "no VM at $VM_WORKDIR (run 'create' first)"
  reap_stale_pid
  if vm_running; then
    fail "VM already running (qemu pid $(cat "$(PIDFILE)")); use 'stop' first"
  fi
  log "starting VM from existing disk (ssh 127.0.0.1:$VM_SSH_PORT)"
  vm_init
  write_lab_marker || fail "could not write the lab VM marker"
  log "VM started"
}

cmd_stop() {
  vm_attach
  acquire_lock
  stop_vm
}

cmd_status() {
  vm_attach
  reap_stale_pid
  local state="stopped"
  vm_running && state="running"
  printf 'state:    %s\n' "$state"
  [ "$state" = running ] && printf 'qemu pid: %s\n' "$(cat "$(PIDFILE)")"
  printf 'workdir:  %s\n' "$VM_WORKDIR"
  printf 'ssh:      127.0.0.1:%s (user %s)\n' "$VM_SSH_PORT" "$VM_USER"
  printf 'accel:    %s\n' "${VM_ACCEL:-auto}"
  printf 'isolated: %s\n' "${VM_NET_ISOLATED:-0}"
  if [ -f "$VM_WORKDIR/disk.qcow2" ]; then
    printf 'disk:     %s\n' "$(du -h "$VM_WORKDIR/disk.qcow2" 2>/dev/null | awk '{print $1}')"
  else
    printf 'disk:     (none)\n'
  fi
  [ -f "$VM_WORKDIR/serial.log" ] && printf 'serial:   %s/serial.log\n' "$VM_WORKDIR"
  if [ "$state" = running ]; then
    if vm_ssh true 2>/dev/null; then printf 'ssh:      reachable\n'; else printf 'ssh:      not reachable yet\n'; fi
  fi
}

# UAT-4/F2: the lab VM is IPv4-only at the guest OS level. This operation
# sets ipv6.disable=1 into the guest's boot configuration through the same
# supported sources as the MAC selector bootstrap (see vm_set_ipv6_disable in
# the harness) and fails closed unless an on-disk boot source verifiably
# carries the token. Idempotent; guest-only; safe to re-run on a partially
# provisioned VM.
cmd_set_ipv6_disable() {
  vm_attach
  vm_running || fail "VM is not running (run 'start'; the boot config is set while the guest is up)"
  vm_set_ipv6_disable
}

cmd_ssh() {
  vm_attach
  vm_running || fail "VM is not running (run 'start')"
  if [ "$#" -gt 0 ]; then
    vm_ssh "$@"
  else
    vm_ssh
  fi
}

# _agent_shell_bootstrap — the agent-side bootstrap for `agent-shell`,
# printed on stdout with CHILD_CMD as the interactive child. The host first
# waits for the READY marker and only then streams two plain `NAME=value`
# lines (LLM_SERVER, LLM_KEY) over the encrypted SSH channel. Echo
# protection is structural, not encoded: the pty echo is disabled BEFORE
# READY is emitted and re-enabled only after both lines have been consumed,
# and the host writes the values only after observing READY — so no
# character of either value can ever be echoed. There is no encoded form
# and no race window. The values are never in argv, shell history, logs or
# files inside the VM (they live only in the process environment the
# launcher forwards via its existing `docker run -e`). If stty cannot
# control the pty echo, the bootstrap fails closed instead of risking an
# echo window. Wrong, missing, empty or line-break-carrying values fail
# closed with an explicit message. CHILD_CMD runs as a child (not exec) so
# QUIT is emitted after it exits; its exit status is propagated.
_agent_shell_bootstrap() { # CHILD_CMD -> bootstrap script on stdout
  cat <<'BOOT'
stty -echo 2>/dev/null || { printf 'cannot disable the pty echo\n' >&2; exit 9; }
printf 'READY\n'
IFS= read -r _llm_line1 || { printf 'the forwarded LLM variable stream ended before LLM_SERVER\n' >&2; exit 9; }
IFS= read -r _llm_line2 || { printf 'the forwarded LLM variable stream ended before LLM_KEY\n' >&2; exit 9; }
stty echo 2>/dev/null || { printf 'cannot restore the pty echo\n' >&2; exit 9; }
case "$_llm_line1" in
  LLM_SERVER=*) LLM_SERVER="${_llm_line1#LLM_SERVER=}" ;;
  *) printf 'the first forwarded line was not LLM_SERVER=<value>\n' >&2; exit 9 ;;
esac
case "$_llm_line2" in
  LLM_KEY=*) LLM_KEY="${_llm_line2#LLM_KEY=}" ;;
  *) printf 'the second forwarded line was not LLM_KEY=<value>\n' >&2; exit 9 ;;
esac
case "${LLM_SERVER}${LLM_KEY}" in
  *$'\n'*|*$'\r'*) printf 'LLM_SERVER/LLM_KEY must not contain line breaks\n' >&2; exit 9 ;;
esac
[ -n "$LLM_SERVER" ] && [ -n "$LLM_KEY" ] \
  || { printf 'empty LLM_SERVER/LLM_KEY refused\n' >&2; exit 9; }
unset _llm_line1 _llm_line2
export LLM_SERVER LLM_KEY
BOOT
  cat <<BOOT
$1
_rc=\$?
printf 'QUIT\n'
exit "\$_rc"
BOOT
}

# _restore_agent_tty — restore the local terminal saved before the agent
# shell pipeline put it into raw mode (the same local discipline ssh applies
# when it owns the tty; here ssh's stdin is a pipe, so the pipeline owns it).
_restore_agent_tty() {
  if [ -n "${_AGENT_STTY_SAVE:-}" ]; then
    stty "${_AGENT_STTY_SAVE}" </dev/tty 2>/dev/null || true
    _AGENT_STTY_SAVE=""
  fi
}

# _agent_shell_cleanup — release everything an agent-shell session holds:
# restore the local terminal, stop the signal watcher and the left pipeline
# member if they are still alive, and remove the temporary fifo directory.
# Safe to call twice (the normal path and the EXIT trap both call it); it
# resets its state markers so a later invocation is a no-op.
_agent_shell_cleanup() {
  _restore_agent_tty
  [ -n "${_AGENT_SHELL_DIR:-}" ] || return 0
  [ -n "${_AGENT_WATCH_PID:-}" ] && kill "${_AGENT_WATCH_PID}" 2>/dev/null
  if [ -f "${_AGENT_SHELL_DIR}/left.pid" ]; then
    local _left_pid
    _left_pid="$(cat "${_AGENT_SHELL_DIR}/left.pid" 2>/dev/null)" || _left_pid=""
    [ -n "${_left_pid}" ] && kill "${_left_pid}" 2>/dev/null
  fi
  rm -rf "${_AGENT_SHELL_DIR}"
  _AGENT_SHELL_DIR=""
  _AGENT_WATCH_PID=""
}

# cmd_agent_shell — open a fully interactive terminal as the agent account
# inside the VM (ssh -tt: fd 0/1/2 of the agent login shell are one pty, so
# interactive tools such as `oc` with Docker -it work), with LLM_SERVER and
# LLM_KEY forwarded from the HOST environment before the interactive shell
# starts. Uses the single existing vm_ssh transport; no second VM management
# mechanism, no launcher/helper/lifecycle changes. The delivery is echo-free
# by construction, without any encoding: the agent-side bootstrap disables
# the pty echo before announcing READY, and the host writes the two plain
# `NAME=value` lines only after that READY has travelled back through the
# session — so no value byte can ever be echoed, logged or stored in the
# VM. The values never appear in argv, shell history, logs or files on
# either side. The READY/QUIT markers stay visible on the operator's screen
# (cosmetic). The local terminal is put into raw mode for the duration
# (ssh's stdin is our pipe), so Ctrl-C and the line editing reach the remote
# pty and the typing is echoed once, by the remote pty. A missing or empty
# variable is an explicit host-side error; control characters are refused
# because the pty line discipline would mangle them in transit.
cmd_agent_shell() {
  # Avoid tracing the forwarded key even when called via bash -x.
  { set +x; } 2>/dev/null
  [ -n "${LLM_SERVER:-}" ] \
    || fail "LLM_SERVER is not exported on the host: export it before agent-shell (it is forwarded through the SSH session only and never stored in the VM)"
  [ -n "${LLM_KEY:-}" ] \
    || fail "LLM_KEY is not exported on the host: export it before agent-shell (it is forwarded through the SSH session only and never stored in the VM)"
  if [[ "${LLM_SERVER}${LLM_KEY}" =~ [[:cntrl:]] ]]; then
    fail "LLM_SERVER/LLM_KEY must not contain control characters (the pty line discipline would mangle them in transit)"
  fi
  vm_attach
  vm_running || fail "VM is not running (run 'start')"
  _AGENT_SHELL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-shell.XXXXXX")" \
    || fail "agent-shell: cannot create the temporary synchronization directory"
  _AGENT_WATCH_PID=""
  _AGENT_STTY_SAVE=""
  local _prev_exit_trap
  _prev_exit_trap="$(trap -p EXIT)"
  trap '_agent_shell_cleanup; eval "${_AGENT_PREV_EXIT_TRAP:-}"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  trap 'exit 129' HUP
  _AGENT_PREV_EXIT_TRAP="$_prev_exit_trap"
  mkfifo "${_AGENT_SHELL_DIR}/sig" "${_AGENT_SHELL_DIR}/ready" \
    || fail "agent-shell: cannot create the synchronization fifos"
  if [ -t 0 ]; then
    _AGENT_STTY_SAVE="$(stty -g </dev/tty)" || _AGENT_STTY_SAVE=""
    stty raw -echo </dev/tty
  fi
  local rc=0
  local _saved_opts=("${VM_SSH_OPTS[@]}")
  # Signal watcher: the session output is tee'd into the sig fifo. READY
  # releases the value injection; QUIT — or the session output's EOF, which
  # means the remote side is gone without QUIT — tears the left pipeline
  # member down so the session always terminates.
  (
    exec 5<>"${_AGENT_SHELL_DIR}/ready"
    local _tries=0
    until [ -s "${_AGENT_SHELL_DIR}/left.pid" ] || [ "${_tries}" -ge 100 ]; do
      sleep 0.05
      _tries=$((_tries + 1))
    done
    while IFS= read -r _sig; do
      # SSH PTY emits CRLF; normalize the trailing control character.
      _sig="${_sig%[[:cntrl:]]}"
      case "$_sig" in
        READY) printf 'go\n' >&5 ;;
        QUIT) break ;;
      esac
    done <"${_AGENT_SHELL_DIR}/sig"
    local _left_pid
    _left_pid="$(cat "${_AGENT_SHELL_DIR}/left.pid" 2>/dev/null)" || _left_pid=""
    [ -n "${_left_pid}" ] && kill "${_left_pid}" 2>/dev/null
    exit 0
  ) &
  _AGENT_WATCH_PID=$!
  # -tt must reach ssh as an OPTION (anything after the host is the remote
  # command), so it is appended to VM_SSH_OPTS for this session only.
  VM_SSH_OPTS+=("-tt")
  # pipefail is relaxed for this pipeline only: at QUIT the watcher SIGTERMs
  # the left member (its cat would otherwise never see EOF), and that
  # expected death must not shadow the session's own exit status.
  set +o pipefail
  {
    printf '%s\n' "$BASHPID" >"${_AGENT_SHELL_DIR}/left.pid"
    exec 4<>"${_AGENT_SHELL_DIR}/ready"
    IFS= read -r _agent_go <&4
    printf 'LLM_SERVER=%s\n' "$LLM_SERVER"
    printf 'LLM_KEY=%s\n' "$LLM_KEY"
    exec 4<&-
    cat
  } | vm_ssh "exec sudo -iu agent bash -c $(printf '%q' "$(_agent_shell_bootstrap 'bash -l')")" \
    > >(tee "${_AGENT_SHELL_DIR}/sig") || rc=$?
  set -o pipefail
  VM_SSH_OPTS=("${_saved_opts[@]}")
  _agent_shell_cleanup
  eval "${_AGENT_PREV_EXIT_TRAP:-}" 2>/dev/null || true
  _AGENT_PREV_EXIT_TRAP=""
  _AGENT_STTY_SAVE=""
  return "$rc"
}

cmd_destroy() {
  local assume_yes=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -y|--yes) assume_yes=1; shift ;;
      *) fail "destroy: unknown argument '$1' (use -y/--yes)" ;;
    esac
  done
  vm_attach
  acquire_lock
  if [ ! -f "$VM_WORKDIR/disk.qcow2" ] && [ ! -f "$VM_WORKDIR/qemu.pid" ]; then
    log "no VM at $VM_WORKDIR (nothing to destroy)"
    return 0
  fi
  if [ "$assume_yes" != 1 ]; then
    printf '%s destroy VM at %s (disk, base image, keys)? [y/N] ' "$PREFIX" "$VM_WORKDIR"
    local ans=""
    read -r ans || true
    case "$ans" in y|Y|yes|YES) ;; *) log "aborted"; return 0 ;; esac
  fi
  if vm_running; then
    log "stopping running VM before destroy"
    stop_vm
  fi
  rm -rf "$VM_WORKDIR"
  log "VM destroyed ($VM_WORKDIR removed)"
}

usage() {
  cat <<EOF
$PREFIX <operation>

  create            build a fresh persistent VM, prove enforcing SELinux,
                    then adopt the isolated network posture and self-check it
  start             boot the existing VM disk (no rebuild)
  stop              gracefully power off the guest
  status            report lifecycle state
  ssh [cmd...]      interactive SSH, or run a remote command
  agent-shell       interactive shell as the agent account with LLM_SERVER
                    and LLM_KEY forwarded from the host environment (they
                    travel only through the SSH session; nothing is stored
                    in the VM; both must be exported on the host)
  set-ipv6-disable  set ipv6.disable=1 in the guest boot config (fail-closed)
  destroy [-y]      remove the VM workdir (explicit confirmation)

Env: DEV_VM_DIR, DEV_VM_SSH_PORT, DEV_VM_ACCEL, DEV_VM_NET_ISOLATED
EOF
}

op="${1:-}"
[ "$#" -gt 0 ] && shift || true
case "$op" in
  create)  cmd_create ;;
  start)   cmd_start ;;
  stop)    cmd_stop ;;
  status)  cmd_status ;;
  ssh)     cmd_ssh "$@" ;;
  agent-shell) cmd_agent_shell ;;
  set-ipv6-disable) cmd_set_ipv6_disable ;;
  destroy) cmd_destroy "$@" ;;
  ""|-h|--help|help) usage ;;
  *) fail "unknown operation '$op' (create|start|stop|status|ssh|set-ipv6-disable|destroy)" ;;
esac
