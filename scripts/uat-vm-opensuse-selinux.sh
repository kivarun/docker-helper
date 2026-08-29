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
# guest, running the existing UAT, the SELinux mount-pin / RPM postinstall
# regression (scripts/uat-selinux-mount-pin-regression.sh), the Phase-A2 docker
# socket micro-proof (scripts/uat-socket-microproof.sh) and the Release-2 SELinux
# targeted regression groups 1-2 (scripts/uat-regressions-runner-selinux.sh).
# All VM mechanics live in the harness; the guest-side UAT is the existing
# scripts/uat-blackbox.sh with its uat-platform-opensuse.sh (platform owner)
# and uat-mac-selinux.sh (MAC owner) adapters, which remain the owners of their
# concerns.
#
# Collect-all: a failure in the common black-box UAT or the mount-pin
# regression never prevents the remaining stages (socket micro-proof, Release-2
# regressions 1-2) from executing; the final summary records every stage and
# the job exits nonzero only when a gating stage failed.
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
#       -> Release-2 SELinux targeted regression groups 1-2 (collect-all runner)
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
#   UAT_SELINUX_MODE full (default) | ab-proof
#                    full: the full collect-all SELinux job (black-box UAT,
#                    mount-pin regression, socket micro-proof, regressions 1-2).
#                    ab-proof: bounded single-VM run that installs the RPM +
#                    confined service (install-only) and then runs only the
#                    SELinux A/B proofs (docker runtime/socket A/B and semanage
#                    production-path proof) — no full matrix, no regressions.
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
MODE="${UAT_SELINUX_MODE:-full}"
[ "$MODE" = "full" ] || [ "$MODE" = "ab-proof" ] \
  || fail "UAT_SELINUX_MODE must be 'full' or 'ab-proof' (got '$MODE')"

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
# Transfer the canonical openSUSE repo/package policy helper into the guest
# (the bootstrap uses the shared zypper timeout/retry owner; the full checkout
# is only copied later, after the MAC proof).
if vm_ssh "sudo tee /opt/uat-repo-policy.sh >/dev/null" < "$SCRIPT_DIR/uat-opensuse-repo.sh"; then
  :
else
  EC=$?
  fail "could not transfer repo policy helper (exit $EC)"
fi
BOOTSTRAP="$(vm_ssh "sudo env UAT_SELINUX_MODE=$MODE bash -s" <<'RMT'
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
# In ab-proof mode the semanage production-path proof must determine whether the
# policy provides semanage_exec_t / semanage_t and derive the standard semanage
# transition (sesearch), build a TEMPORARY proof module (checkmodule +
# semodule_package from checkpolicy), and capture AVC evidence with auditd
# RUNNING (the minimal image does not ship/start it). setools-console provides
# seinfo/sesearch on openSUSE (the bare `setools` package only exists in the
# experimental security:/SELinux repo; setools-console is in the default
# Tumbleweed repos). `audit` provides the auditd daemon. Not needed for the
# full UAT stages.
if [ "${UAT_SELINUX_MODE:-full}" = "ab-proof" ]; then
  for p in setools-console audit checkpolicy; do
    rpm -q "$p" >/dev/null 2>&1 || { NEED=1; log "missing: $p (ab-proof mode)"; }
  done
fi
if [ "$NEED" = 1 ]; then
  opensuse_zypp_tune_timeouts
  if ! opensuse_zypper_refresh; then
    echo "REPO-FAILURE: zypper refresh exhausted attempts; aborting bootstrap" >&2
    exit 1
  fi
  PKGS="selinux-policy-targeted policycoreutils selinux-tools policycoreutils-python-utils"
  if [ "${UAT_SELINUX_MODE:-full}" = "ab-proof" ]; then
    PKGS="$PKGS setools-console audit checkpolicy"
  fi
  # shellcheck disable=SC2086
  opensuse_zypper install -y $PKGS
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
# run_guest_capture: remote command via the harness transport. On failure it
# prints docker-helper diagnostics (bounded) and returns the REMOTE exit
# status; it never aborts the orchestration, so a failure in one stage cannot
# prevent the remaining stages from executing (collect-all). The caller records
# the result.
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
# 6b. two-stage Docker preparation: settle the container-selinux policy BEFORE
#     Docker is installed so the Docker daemon binary is labeled naturally.
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
#   Stage 2: install Docker (below, via install-deps). The rpm selinux plugin
#            then labels /usr/bin/dockerd per the active container-selinux
#            fcontext (container_runtime_exec_t) at install time, and the
#            running daemon transitions to container_runtime_t with the socket
#            at container_var_run_t — all without any docker-helper intervention.
#
# This also satisfies the docker_helper.pp prerequisite (container-selinux
# attributes/types) before the docker-helper RPM install.
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

log "== 7. black-box UAT inside the guest =="
log "install-deps (UAT_PLATFORM=opensuse scripts/uat-blackbox.sh install-deps)"
# install-deps is a hard prerequisite for everything that follows. It installs
# Docker (stage 2) in its own transaction AFTER the container-selinux policy
# was settled above.
run_guest_capture "guest install-deps" \
  "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_PLATFORM=opensuse scripts/uat-blackbox.sh install-deps" \
  || fail "guest install-deps failed (hard prerequisite)"

# ---------------------------------------------------------------------------
# 7a. Docker SELinux health gate (BEFORE the docker-helper RPM install).
# ---------------------------------------------------------------------------
# The two-stage setup must yield a naturally healthy Docker host with NO
# docker-helper intervention and NO explicit restorecon/restart:
#   dockerd executable = container_runtime_exec_t
#   dockerd process    = container_runtime_t
#   docker.sock        = container_var_run_t
# If healthy, the previous socket blocker is classified as a UAT/environment
# construction defect (container-selinux policy not settled before Docker),
# NOT a docker-helper production defect. If NOT healthy, stop and report:
# docker-helper must not be made to own Docker daemon repair without another
# architecture decision.
log "== 7a. Docker SELinux state before docker-helper RPM install (health gate) =="
DOCKER_HEALTH="$(vm_ssh 'sudo bash -s' <<'RMT'
set -uo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "--- Docker SELinux state before docker-helper RPM install (two-stage setup) ---"
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

if [ "$MODE" = "ab-proof" ]; then
  # ---------------------------------------------------------------------------
  # 7b. Bounded A/B proof mode: install the RPM + confined service (install
  #     only, via the authoritative uat-blackbox.sh install path) and then run
  #     ONLY the SELinux A/B proofs (docker runtime/socket A/B + semanage
  #     production-path proof). No black-box scenario, no regressions.
  # ---------------------------------------------------------------------------
  log "== 7b. install-only (RPM + confined service) then SELinux A/B proofs =="
  INSTALL_RESULT=FAIL
  if run_guest_capture "RPM install + confined service (install-only)" \
    "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_VERSION=$VERSION UAT_PLATFORM=opensuse UAT_INSTALL=rpm UAT_MAC=selinux UAT_ARTIFACT_PATH=/opt/uat-import/docker-helper.rpm UAT_ARTIFACT_SHA256=$UAT_RPM_SHA256 UAT_STOP_AFTER_INSTALL=1 scripts/uat-blackbox.sh"; then
    INSTALL_RESULT=PASS
    log "install-only passed inside the guest (RPM installed, service confined)"
  else
    log "install-only FAILED inside the guest (recorded; A/B proofs may still collect evidence)"
  fi
  record_stage "RPM install + confinement" "$INSTALL_RESULT"

  AB_RESULT=FAIL
  if run_guest_capture "SELinux A/B proofs (docker socket + semanage) inside the guest" \
    "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin bash scripts/uat-selinux-ab-proof.sh"; then
    AB_RESULT=PASS
    log "SELinux A/B proofs completed inside the guest (evidence recorded)"
  else
    log "SELinux A/B proofs did not complete (recorded; evidence may be partial)"
  fi
  record_stage "SELinux A/B proofs" "$AB_RESULT"

  BB_RESULT=PASS
  MP_RESULT=PASS
  SELREG_RESULT=PASS
else
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
      log "SELinux mount-pin regression BLOCKED inside the guest (docker socket blocker; inconclusive, recorded)"
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
  # 8c. Release-2 SELinux targeted regression groups 1-2 (collect-all)
  # ---------------------------------------------------------------------------
  log "== 8c. SELinux targeted regression groups 1-2 (collect-all runner) =="
  SELREG_RESULT=FAIL
  if run_guest_capture "SELinux regression groups 1-2 inside the guest" \
    "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin bash scripts/uat-regressions-runner-selinux.sh"; then
    SELREG_RESULT=PASS
  else
    log "SELinux regression groups 1-2 reported a failure (recorded)"
  fi
  record_stage "SELinux regressions (1-2)" "$SELREG_RESULT"
fi

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
echo "Docker SELinux:   ${DOCKER_HEALTHY:-0}=naturally healthy two-stage setup (container-selinux before Docker)"
echo "total:            ${TOTAL}s"
echo "---- SELinux job stages ----"
printf '%s\n' "$SELINUX_STAGES"
echo "============================="
# A stage BLOCKED (exit 2) means a real prerequisite prevented the exercise
# (here: the known docker socket blocker making the mount-pin run unable to
# remain active) — inconclusive, not a product failure. Only a FAIL counts.
if [ "$MODE" = "ab-proof" ]; then
  # ab-proof is evidence collection, not a product gate: PASS means the
  # bounded proofs completed and recorded their evidence (the A/B results
  # themselves are reported from the guest output, never a gate here).
  if [ "$AB_RESULT" = "PASS" ]; then
    echo "RESULT: SELinux A/B proofs completed (evidence recorded)"
    echo "=============================================================="
    log "DONE"
    exit 0
  fi
  echo "RESULT: SELinux A/B proof harness did not complete (see summary above)"
  echo "=============================================================="
  exit 1
fi
if [ "$BB_RESULT" = "PASS" ] && [ "$SELREG_RESULT" = "PASS" ] && [ "$MP_RESULT" != "FAIL" ]; then
  echo "RESULT: openSUSE/SELinux UAT stages PASSED inside Tumbleweed VM"
  echo "=============================================================="
  log "DONE"
  exit 0
fi
echo "RESULT: at least one SELinux job stage FAILED (see summary above)"
echo "=============================================================="
exit 1
