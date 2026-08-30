#!/usr/bin/env bash
#
# uat-vm-opensuse-selinux-lib.sh — shared openSUSE Tumbleweed SELinux host
# construction for the docker-helper VM UATs. Sourced by the SELinux VM
# orchestrators AFTER they source the canonical Tumbleweed VM harness
# (scripts/uat-vm-tumbleweed.sh) and define their own log()/fail() helpers:
#
#   scripts/uat-vm-opensuse-selinux.sh          (RPM artifact)
#   scripts/uat-vm-opensuse-tarball-selinux.sh  (release tarball artifact)
#
# Responsibility boundary (sibling of scripts/uat-vm-opensuse-apparmor.sh):
#
#   host workflow
#       |  (sourcing script: MAC-specific orchestration ONLY)
#       v
#   Tumbleweed VM harness    (scripts/uat-vm-tumbleweed.sh, sourced below)
#       |  image + checksum, qcow overlay + resize, KVM/TCG selection,
#       |  cloud-init NoCloud seed, unattended boot, vm_ssh/vm_scp transport,
#       |  wait-for-SSH, canonical reboot, serial-log diagnostics, labeled
#       |  cmdline+LSM evidence, boot-config MAC selector mutation.
#       v
#   THIS FILE: SELinux host construction (shared by the SELinux orchestrators)
#       |  SELinux userspace + targeted policy bootstrap, MAC token selection
#       |  through the harness primitive + enforcing reboot proof, checkout +
#       |  exact artifact transfer, two-stage Docker preparation (container-
#       |  selinux before Docker) + Docker SELinux health gate.
#       v
#   existing black-box UAT   (scripts/uat-blackbox.sh inside the guest, with
#                             scripts/uat-platform-opensuse.sh platform owner
#                             and scripts/uat-mac-selinux.sh MAC owner)
#
# This file deliberately exists ONCE so the RPM and tarball SELinux profiles
# share the same SELinux host construction instead of forking a second giant
# VM harness. The MAC-specific orchestration for each artifact (which exact
# artifact to copy, which stages to run, the summary) stays in the sourcing
# script.
#
# The Tumbleweed cloud image ships SELinux-active by default (the filesystem
# is already labeled for the targeted policy), so the harness keeps SELinux as
# the LSM — the tokens are selected through the image's bootloader, and one
# enforcing reboot proves persistence. No relabel is needed.
#
# Env inputs (host side):
#   UAT_REPO_DIR     host checkout of docker-helper (default: repo root)
#
# Exposed state (read-only for callers):
#   SELINUX_ACTIVE / APPARMOR_ACTIVE / RAW_LSM   initial LSM state
#   LSM_FINAL / CMDLINE_FINAL / GETENF            post-reboot SELinux proof
#   DOCKER_HEALTHY                                1 after the Docker health gate
#   SELINUX_STAGES                                collect-all stage accounting

set -euo pipefail

# ---------------------------------------------------------------------------
# canonical Tumbleweed VM harness (VM mechanics; no MAC/package/UAT knowledge)
# ---------------------------------------------------------------------------
# shellcheck source=scripts/uat-vm-tumbleweed.sh
source "$SCRIPT_DIR/uat-vm-tumbleweed.sh"

# --- guest-side evidence (docker-helper SELinux evidence; the harness must
# --- not know docker-helper, so it lives here)
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

# --- collect-all helpers (a failure in one stage never prevents the remaining
# --- stages; the final summary records every stage)
# run_guest_capture: remote command via the harness transport. On failure it
# prints docker-helper diagnostics (bounded) and returns the REMOTE exit
# status; it never aborts the orchestration. The caller records the result.
# (Never `if ! vm_ssh ...; then EC=$?`: $? there is the status of `!`.)
run_guest_capture() {
  local desc="$1"; shift
  if vm_ssh "$@"; then
    echo "$PREFIX $desc: PASS (exit 0)"
    return 0
  else
    local ec=$?
    echo "$PREFIX $desc: FAIL (exit $ec)" >&2
    guest_evidence || true
    vm_serial_tail
    return "$ec"
  fi
}

# Combined result accounting for the SELinux job stages (collect-all).
SELINUX_STAGES=""
record_stage() { # name result
  SELINUX_STAGES="${SELINUX_STAGES}$(printf '%-28s %s\n' "$1" "$2")"
}

# ---------------------------------------------------------------------------
# 1-5. SELinux host construction: create/start the VM, bootstrap SELinux
# userspace + targeted policy, select security=selinux enforcing through the
# harness cmdline primitive, reboot, and prove real SELinux enforcing with
# AppArmor absent. All acceptance stays here.
# ---------------------------------------------------------------------------
vm_selinux_bootstrap() {
  log "== 1. start Tumbleweed VM through common harness =="
  vm_init

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

  log "== 3. SELinux userspace bootstrap =="
  # Transfer the canonical openSUSE repo/package policy helper into the guest
  # (the bootstrap uses the shared zypper timeout/retry owner; the full checkout
  # is only copied later, after the MAC proof).
  if vm_ssh "sudo tee /opt/uat-repo-policy.sh >/dev/null" < "$SCRIPT_DIR/uat-opensuse-repo.sh"; then
    :
  else
    EC=$?
    fail "could not transfer repo policy helper (exit $EC)"
  fi
  BOOTSTRAP="$(vm_ssh "sudo bash -s" <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
log(){ echo "[vm] $*"; }
# shellcheck source=/dev/null
source /opt/uat-repo-policy.sh

log "installing/verifying SELinux userspace + targeted policy"
NEED=0
for p in selinux-policy-targeted policycoreutils selinux-tools policycoreutils-python-utils; do
  rpm -q "$p" >/dev/null 2>&1 || { NEED=1; log "missing: $p"; }
done
if [ "$NEED" = 1 ]; then
  opensuse_zypp_tune_timeouts
  if ! opensuse_zypper_refresh; then
    echo "REPO-FAILURE: zypper refresh exhausted attempts; aborting bootstrap" >&2
    exit 1
  fi
  PKGS="selinux-policy-targeted policycoreutils selinux-tools policycoreutils-python-utils"
  # shellcheck disable=SC2086
  opensuse_zypper install -y $PKGS
fi
# sesearch/seinfo (setools-console) are also used by the scope=selinux
# diagnostic to inspect the LIVE kernel policy, so ensure they exist even in
# full mode.
if ! rpm -q setools-console >/dev/null 2>&1; then
  opensuse_zypp_tune_timeouts
  opensuse_zypper_refresh || true
  opensuse_zypper install -y setools-console || true
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

# Best-effort auditd for fresh AVC/USER_AVC evidence in the scope=selinux run.
# Evidence collection, NOT a hard prerequisite: if install or start fails the
# run continues and the regression evidence falls back to journal-level denials.
if ! rpm -q audit >/dev/null 2>&1; then
  opensuse_zypp_tune_timeouts
  opensuse_zypper_refresh || true
  opensuse_zypper install -y audit || true
fi
if command -v ausearch >/dev/null 2>&1; then
  systemctl enable --now auditd >/dev/null 2>&1 || true
  auditctl -e 1 >/dev/null 2>&1 || true
  log "auditd enabled for fresh AVC/USER_AVC evidence (best-effort)"
else
  log "auditd/ausearch unavailable; AVC evidence will be journal-level only"
fi

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

  log "== 4. select SELinux MAC tokens + reboot =="
  vm_set_mac_tokens "security=selinux selinux=1 apparmor=0 enforcing=1"
  vm_reboot "apply SELinux cmdline (security=selinux selinux=1 apparmor=0 enforcing=1)"

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
}

# ---------------------------------------------------------------------------
# 6. transfer checkout + one exact prebuilt artifact into the guest
# ---------------------------------------------------------------------------
vm_selinux_transfer_repo() {
  log "== 6. transfer repo into the guest =="
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
}

# vm_selinux_transfer_artifact <guest-name> <host-path> — scp the exact prebuilt
# artifact into the guest's import dir under the given name.
vm_selinux_transfer_artifact() {
  local guest_name="$1" host_path="$2"
  log "copying artifact into guest (/opt/uat-import/$guest_name)"
  if vm_scp "$host_path" "opc@127.0.0.1:/opt/uat-import/$guest_name"; then
    :
  else
    EC=$?
    fail "artifact transfer to guest failed (exit $EC)"
  fi
}

# ---------------------------------------------------------------------------
# 6b-7a. two-stage Docker preparation: settle the container-selinux policy
# BEFORE Docker is installed so the Docker daemon binary is labeled naturally,
# then install-deps (Docker, stage 2), then the Docker SELinux health gate.
# ---------------------------------------------------------------------------
# Root cause of the previous "docker socket blocker" (var_run_t socket):
# dockerd was installed in the SAME package transaction as container-selinux.
# In a single transaction container-selinux's %posttrans (which loads its
# policy module) runs only after every package is already on disk, so the rpm
# selinux plugin labeled /usr/bin/dockerd while the container-selinux fcontext
# rules were not yet active — dockerd kept the generic bin_t label, ran as
# unconfined_service_t, and created /run/docker.sock as var_run_t.
#
# Two-stage fix (UAT environment construction, NOT docker-helper production
# code and NOT an explicit restorecon/restart):
#   Stage 1: install/ensure container-selinux in its OWN transaction and load
#            its policy module, so the container fcontext rules are active.
#   Stage 2: install Docker (via install-deps). The rpm selinux plugin then
#            labels /usr/bin/dockerd per the active container-selinux
#            fcontext (container_runtime_exec_t) at install time, and the
#            running daemon transitions to container_runtime_t with the socket
#            at container_var_run_t — all without any docker-helper intervention.
vm_selinux_two_stage_docker() {
  log "== 6b. two-stage Docker preparation: container-selinux before Docker =="
  STAGE1="$(vm_ssh 'sudo bash -s' <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# shellcheck source=/dev/null
source /opt/uat-repo-policy.sh
log(){ echo "[vm] $*"; }

log "stage 1: ensure container-selinux in its own transaction"
if ! rpm -q container-selinux >/dev/null 2>&1; then
  opensuse_zypp_tune_timeouts
  opensuse_zypper_refresh || { echo "REPO-FAILURE: zypper refresh failed; aborting stage 1" >&2; exit 1; }
  opensuse_zypper install -y container-selinux
fi
PP="$(rpm -ql container-selinux 2>/dev/null | grep -E '\.pp(\.bz2)?$' | head -1 || true)"
if [ -z "$PP" ] || [ ! -f "$PP" ]; then
  echo "error: container-selinux policy module file not found" >&2
  exit 1
fi
log "settling container-selinux policy module: $PP"
semodule -i "$PP" 2>&1 || { echo "error: semodule -i failed for $PP" >&2; exit 1; }
log "matchpathcon /usr/bin/dockerd: $(matchpathcon /usr/bin/dockerd 2>&1 || true)"
echo "STAGE1-DONE"
RMT
)" || true
  printf '%s\n' "$STAGE1"
  printf '%s\n' "$STAGE1" | grep -q "STAGE1-DONE" || fail "stage 1 (container-selinux before Docker) did not complete"
  log "container-selinux policy settled BEFORE Docker install (two-stage)"

  # install-deps is a hard prerequisite for everything that follows. It installs
  # Docker (stage 2) in its own transaction AFTER the container-selinux policy
  # was settled above.
  log "install-deps (UAT_PLATFORM=opensuse scripts/uat-blackbox.sh install-deps)"
  run_guest_capture "guest install-deps" \
    "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_PLATFORM=opensuse scripts/uat-blackbox.sh install-deps" \
    || fail "guest install-deps failed (hard prerequisite)"

  # Docker SELinux health gate (BEFORE the docker-helper install). The two-stage
  # setup must yield a naturally healthy Docker host with NO docker-helper
  # intervention and NO explicit restorecon/restart:
  #   dockerd executable = container_runtime_exec_t
  #   dockerd process    = container_runtime_t
  #   docker.sock        = container_var_run_t
  # If healthy, the previous socket blocker is classified as a UAT/environment
  # construction defect (container-selinux policy not settled before Docker),
  # NOT a docker-helper production defect. If NOT healthy, stop and report:
  # docker-helper must not be made to own Docker daemon repair without another
  # architecture decision.
  log "== 7a. Docker SELinux state before docker-helper install (health gate) =="
  DOCKER_HEALTH="$(vm_ssh 'sudo bash -s' <<'RMT'
set -uo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "--- Docker SELinux state before docker-helper install (two-stage setup) ---"
echo "dockerd executable:    $(ls -lZ /usr/bin/dockerd 2>&1 || true)"
echo "dockerd matchpathcon:  $(matchpathcon /usr/bin/dockerd 2>&1 || true)"
DPID="$(pidof dockerd 2>/dev/null || true)"
if [ -n "$DPID" ]; then
  printf 'dockerd process:      '; tr -d '\0' < "/proc/$DPID/attr/current" 2>/dev/null || true; echo
else
  echo "dockerd process:      (dockerd not running / pidof empty)"
fi
echo "docker.sock:           $(ls -lZ /run/docker.sock 2>&1 || true)"
echo "docker.sock matchpathcon: $(matchpathcon /run/docker.sock 2>&1 || true)"
EXEC_T="$(stat -c '%C' /usr/bin/dockerd 2>/dev/null | cut -d: -f3 || true)"
PROC_T="$(if [ -n "$DPID" ]; then tr -d '\0' < "/proc/$DPID/attr/current" 2>/dev/null | cut -d: -f3; fi)"
SOCK_T="$(stat -c '%C' /run/docker.sock 2>/dev/null | cut -d: -f3 || true)"
if [ "$EXEC_T" = "container_runtime_exec_t" ] && [ "$PROC_T" = "container_runtime_t" ] && [ "$SOCK_T" = "container_var_run_t" ]; then
  echo "DOCKER_SELINUX_HEALTHY=yes"
else
  echo "DOCKER_SELINUX_HEALTHY=no (dockerd_exec=$EXEC_T dockerd_proc=$PROC_T socket=$SOCK_T)"
fi
RMT
)" || true
  printf '%s\n' "$DOCKER_HEALTH"
  if printf '%s\n' "$DOCKER_HEALTH" | grep -q "DOCKER_SELINUX_HEALTHY=yes"; then
    DOCKER_HEALTHY=1
    log "Docker host is NATURALLY healthy after two-stage setup: the previous docker socket blocker is a UAT/environment construction defect (container-selinux policy was not settled before Docker), NOT a docker-helper production defect"
  else
    fail "Docker host NOT naturally healthy after two-stage setup (see labels above). docker-helper must not be made to own Docker daemon repair without another architecture decision — stopping and reporting"
  fi
}
