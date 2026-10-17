#!/usr/bin/env bash
#
# release-2.4-r7-diag-tw-apparmor-vm.sh — R7 full-gate corrective diagnosis on
# a disposable openSUSE Tumbleweed VM under ENFORCING AppArmor (RPM candidate).
# Proves the R7-C builder START refusal on the exact candidate bytes: the
# builder service journal (the manager's diag lines), the AppArmor launch
# vehicle prerequisites (the distro rootlesskit profile the builder profile's
# fail-closed `px` requires, the userns restriction state), and the live
# kernel audit records. No release artifact ownership changes: the candidate
# set is consumed exactly as the failed full gate produced it.
#
# Reuses the canonical VM machinery (scripts/uat-vm-tumbleweed.sh) — no second
# harness. The AppArmor host construction mirrors the canonical AppArmor UAT
# orchestrator (scripts/uat-vm-opensuse-apparmor.sh) and stays in THIS diag
# script because that orchestrator is linear and exposes no reusable
# bootstrap function.
#
# Env inputs (host side):
#   UAT_REPO_DIR          host checkout (default: repo root)
#   UAT_RPM               host path to the exact candidate RPM
#   UAT_RPM_SHA256        expected SHA-256 of that RPM
#   R7_DIAG_EVIDENCE_DIR  host evidence directory (default under /tmp)

set -Eeuo pipefail

PREFIX='[release-2.4-r7-diag-tw-apparmor-vm]'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UAT_REPO_DIR="${UAT_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
EVIDENCE_DIR="${R7_DIAG_EVIDENCE_DIR:-/tmp/release-2.4-r7-diag-apparmor-evidence}"
GUEST_EVIDENCE_DIR='/tmp/r7-diag-evidence'

log()  { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

: "${UAT_RPM:?UAT_RPM required}"
: "${UAT_RPM_SHA256:?UAT_RPM_SHA256 required}"

# shellcheck source=scripts/uat-vm-tumbleweed.sh
source "$SCRIPT_DIR/uat-vm-tumbleweed.sh"

on_err() { vm_serial_tail || true; }
trap on_err ERR

log '== 1. start Tumbleweed VM through common harness'
vm_init

log '== 2. initial MAC state'
STATE="$(vm_ssh 'bash -s' <<'RMT'
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "=== /sys/kernel/security/lsm ==="; cat /sys/kernel/security/lsm; echo
echo "STATE-DONE"
RMT
)" || true
printf '%s\n' "$STATE"
echo "$STATE" | grep -q "STATE-DONE" || fail "initial state script did not complete"

log '== 3. AppArmor userspace bootstrap'
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
opensuse_zypp_tune_timeouts
if ! opensuse_zypper_refresh; then
  echo "REPO-FAILURE: zypper refresh exhausted attempts; aborting bootstrap" >&2
  exit 1
fi
log "installing AppArmor userspace (canonical orchestrator parity)"
opensuse_zypper install -y --no-recommends \
  apparmor-parser apparmor-utils apparmor-abstractions
if systemctl list-unit-files 2>/dev/null | grep -q '^apparmor.service'; then
  systemctl enable apparmor.service >/dev/null 2>&1 \
    && log "apparmor.service enabled" || log "WARN: could not enable apparmor.service"
fi
echo "BOOTSTRAP-DONE"
RMT
)" || true
printf '%s\n' "$BOOTSTRAP"
echo "$BOOTSTRAP" | grep -q "BOOTSTRAP-DONE" || fail "AppArmor bootstrap script did not complete"

log '== 4. select AppArmor MAC tokens + reboot'
vm_set_mac_tokens "security=apparmor apparmor=1 selinux=0"
vm_reboot "apply AppArmor cmdline (security=apparmor apparmor=1 selinux=0)"

log '== 5. prove AppArmor active / SELinux absent'
PROOF="$(vm_ssh 'sudo bash -s' <<'RMT'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "AA_ENABLED_VAL=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null || echo absent)"
echo "=== /etc/os-release ==="; cat /etc/os-release
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
echo "$LSM_FINAL" | grep -qw selinux && fail "ACCEPT: selinux still an active LSM ($LSM_FINAL)"
[ "$AA_ENABLED" = "Y" ] || fail "ACCEPT: /sys/module/apparmor/parameters/enabled != Y (got '$AA_ENABLED')"
log "AppArmor proof passed: lsm='$LSM_FINAL' aa_enabled=$AA_ENABLED"

log '== 6. transfer repo + exact candidate RPM into the guest'
if vm_ssh "sudo mkdir -p /opt/uat /opt/uat-import && sudo chown opc:opc /opt/uat /opt/uat-import"; then
  :
else
  EC=$?
  fail "could not create guest import dirs (exit $EC)"
fi
tar -C "$UAT_REPO_DIR" -czf repo.tgz \
  --exclude=.git --exclude=dist --exclude=uat-curl --exclude=docker-helper .
if vm_ssh "tar xzf - -C /opt/uat" < repo.tgz; then
  :
else
  EC=$?
  fail "repo transfer to guest failed (exit $EC)"
fi
if vm_scp "$UAT_RPM" "opc@127.0.0.1:/opt/uat-import/docker-helper.rpm"; then
  :
else
  EC=$?
  fail "artifact transfer to guest failed (exit $EC)"
fi

log '== 6b. guest install-deps (Docker + runtime backend deps)'
if vm_ssh "cd /opt/uat && sudo -E env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin UAT_PLATFORM=opensuse scripts/uat-blackbox.sh install-deps"; then
  log "guest install-deps: PASS"
else
  EC=$?
  fail "guest install-deps failed (exit $EC)"
fi

log '== 7. transfer and run the R7 guest diagnostic'
vm_ssh 'rm -rf /tmp/r7-diag && mkdir -p /tmp/r7-diag'
vm_scp "$SCRIPT_DIR/release-2.4-r7-diag-guest.sh" opc@127.0.0.1:/tmp/r7-diag/release-2.4-r7-diag-guest.sh

set +e
# The diag VM reboots mid-diagnosis (observed ~55s after boot; runs
# 39006788899+). The guest script is phased with state markers and the
# evidence is collected after every invocation; the invocation repeats
# over fresh SSH sessions until the verdict appears.
VERDICT=""
for attempt in 1 2 3; do
  if [ "$attempt" -gt 1 ]; then
    log "re-entry: waiting for SSH after the observed mid-diagnosis reboot"
    vm_wait_ssh
  fi
  vm_ssh 'sudo bash -s' <<RMT >"$RUNNER_TEMP/r7-diag-guest.log" 2>&1
export R7_BACKEND=apparmor R7_INSTALL=rpm
export R7_ARTIFACT=/opt/uat-import/docker-helper.rpm
export R7_ARTIFACT_SHA256="$UAT_RPM_SHA256"
export R7_EXPECT=fail
export R7_RUNTIME_DEPS=install
export R7_EVIDENCE_DIR='$GUEST_EVIDENCE_DIR'
bash /tmp/r7-diag/release-2.4-r7-diag-guest.sh
RMT
  GUEST_RC=$?
  cat "$RUNNER_TEMP/r7-diag-guest.log"

  # Per-attempt evidence files: each attempt's console log and evidence
  # tarball is preserved under its own suffix (a later attempt never
  # overwrites an earlier attempt's captured evidence).
  log "collect guest evidence (survives the verdict; attempt $attempt)"
  mkdir -p "$EVIDENCE_DIR"
  cp "$RUNNER_TEMP/r7-diag-guest.log" "$EVIDENCE_DIR/guest-attempt$attempt.log"
  if vm_ssh "test -d '$GUEST_EVIDENCE_DIR'" 2>/dev/null; then
    vm_ssh "tar -C '$GUEST_EVIDENCE_DIR' -czf - ." > "$EVIDENCE_DIR/guest-evidence-attempt$attempt.tar.gz" || true
    mkdir -p "$EVIDENCE_DIR/guest-attempt$attempt"
    tar -xzf "$EVIDENCE_DIR/guest-evidence-attempt$attempt.tar.gz" -C "$EVIDENCE_DIR/guest-attempt$attempt" 2>/dev/null || true
  fi

  VERDICT="$(grep -aoE 'R7-DIAG-RESULT=[A-Z-]+' "$RUNNER_TEMP/r7-diag-guest.log" | tail -1 || true)"
  case "$VERDICT" in
    "R7-DIAG-RESULT=REPRODUCED")
      log 'R7 AppArmor diagnosis REPRODUCED (the defect is still live on this branch; red evidence captured)'
      break
      ;;
    "R7-DIAG-RESULT=BUILD-OK")
      log 'R7 AppArmor diagnosis BUILD-OK (the corrective holds on this branch; green evidence captured)'
      break
      ;;
    *)
      if [ "$attempt" -eq 3 ]; then
        fail "the R7 AppArmor diagnosis produced no verdict (guest exit $GUEST_RC)"
      fi
      log "attempt $attempt produced no verdict (guest exit $GUEST_RC); retrying"
      ;;
  esac
done
set -e
