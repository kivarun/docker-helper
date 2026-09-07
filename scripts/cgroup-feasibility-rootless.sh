#!/usr/bin/env bash
#
# cgroup-feasibility-rootless.sh — Release 3 aggregate-cgroup feasibility
# harness for ROOTLESS/USER deployment. It runs INSIDE a real Ubuntu 24.04 VM
# (the Phase-0 workflow boots it through scripts/uat-vm-cgroup-rootless.sh on
# the canonical Ubuntu VM harness scripts/uat-vm-ubuntu.sh).
#
# The proof target is the unprivileged path exactly as deployed: a normal
# user owns a systemd user session with cgroup v2 controller delegation, a
# rootless Docker daemon (installed through the official
# dockerd-rootless-setuptool.sh path and running as a systemd USER service of
# that user) places workloads in the user's delegated cgroup subtree, and
# workloads are aggregate-limited through that subtree — never by writing
# cgroupfs as root outside the delegation. Root reads are used only for
# evidence.
#
# Aggregate slice properties are applied through systemd USER-unit runtime
# drop-ins ($XDG_RUNTIME_DIR/systemd/user/<unit>.d): the user manager refuses
# `systemctl --user set-property` (polkit org.freedesktop.systemd1.
# set-unit-properties defaults to auth_admin_keep, so an unprivileged user
# cannot set unit properties over D-Bus), while unit-file configuration plus
# a user-manager daemon-reload is the standard delegated path. The drop-ins
# are written before the first workload so systemd reads them when it
# materializes the (implicitly created) slices.
#
# Hierarchy mapping (systemd slice grammar encodes the R3 chain):
#
#   Root          -> the user's delegated cgroup subtree
#                    user.slice/user-<uid>.slice/user@<uid>.service
#   hierarchy top -> dhfeas.slice (top-level slice of the user manager)
#   Principal     -> dhfeas-principal1.slice
#   Launcher      -> dhfeas-principal1-launcher1.slice
#   Session       -> dhfeas-principal1-launcher1-session1.slice
#   workload      -> docker-<id>.scope under the Session slice
#
# systemd derives a slice's parent from its name (a-b-c.slice is a child of
# a-b.slice), so the cgroup path of the Session slice is
# <user tree>/dhfeas.slice/<Principal>/<Launcher>/<Session>; the ancestors
# materialize implicitly when the first workload is placed.
#
# Every observable fact is printed as a stable key:value line; every step ends
# with a STEP-<n>-DONE marker; any failed assertion exits nonzero with the
# exact violated contract. Output is recorded verbatim as gate evidence.

set -uo pipefail

log()    { printf '[cg-rootless] %s\n' "$*"; }
fact()   { printf 'FACT: %s\n' "$*"; }
step()   { printf '\n[cg-rootless] == STEP %s ==\n' "$*"; }
die()    { printf 'GATE-FAIL: %s\n' "$*" >&2; exit 1; }

FEAS_USER=feasu
FEAS_UID=$(id -u "$FEAS_USER" 2>/dev/null) || die "feasibility user $FEAS_USER missing (bootstrap step missing)"
RUN_DIR="/run/user/$FEAS_UID"
USER_TREE="/sys/fs/cgroup/user.slice/user-$FEAS_UID.slice/user@$FEAS_UID.service"
TOP_SLICE=dhfeas.slice
P_SLICE=dhfeas-principal1.slice
L_SLICE=dhfeas-principal1-launcher1.slice
SESS_SLICE=dhfeas-principal1-launcher1-session1.slice
SESS2_SLICE=dhfeas-principal1-launcher1-session2.slice
P_DIR="$USER_TREE/$TOP_SLICE/$P_SLICE"
L_DIR="$P_DIR/$L_SLICE"
SESS_DIR="$L_DIR/$SESS_SLICE"
SESS2_DIR="$L_DIR/$SESS2_SLICE"
export DOCKER_HOST="unix://$RUN_DIR/docker.sock"

# Runs a command inside a REAL login session of the unprivileged user
# (su -l): systemctl --user method calls issued from a runuser-executed
# process (no PAM session, wrong SELinux context) are denied by the user
# manager with "Access denied" before the start machinery even runs. The
# command payload is written to a temp script so quoting survives su.
as_user() {
  local tmp rc
  tmp="$(mktemp /tmp/dh-feas-user-script.XXXXXX)"
  chmod 0644 "$tmp"
  {
    printf '#!/bin/bash\nset -u\nexport XDG_RUNTIME_DIR=%q\n' "$RUN_DIR"
    printf '%q ' "$@"
    printf '\n'
  } > "$tmp"
  su -l "$FEAS_USER" -c "bash $tmp"
  rc=$?
  rm -f "$tmp"
  return $rc
}

# Writes a runtime drop-in for a systemd USER unit as the unprivileged user
# and reloads the user manager. This is the one owner of the aggregate-slice
# configuration mechanism: properties land in
# $XDG_RUNTIME_DIR/systemd/user/<unit>.d/50-dh-feas.conf and are applied by
# systemd when the unit materializes.
apply_user_unit_props() {
  local unit="$1" props="" p
  shift
  for p in "$@"; do props+=" $p"; done
  as_user bash -c "set -e
mkdir -p \"\$XDG_RUNTIME_DIR/systemd/user/$unit.d\"
printf '%s\n' '[Slice]'$props > \"\$XDG_RUNTIME_DIR/systemd/user/$unit.d/50-dh-feas.conf\"
systemctl --user daemon-reload"
}

step 1 "cgroup v2 + user delegation facts"
[ -f /sys/fs/cgroup/cgroup.controllers ] || die "no cgroup v2 unified hierarchy (contract requires cgroup v2)"
fact "kernel=$(uname -r)"
fact "systemd=$(systemctl --version | head -1 | awk '{print $2}')"
fact "user-session=$(systemctl is-active "user@$FEAS_UID.service" 2>&1)"
[ -d "$USER_TREE" ] || die "user manager cgroup subtree $USER_TREE absent (delegation gate)"
fact "user-tree-controllers=$(cat "$USER_TREE/cgroup.controllers" 2>/dev/null || echo ABSENT)"
fact "user-tree-subtree-control=$(cat "$USER_TREE/cgroup.subtree_control" 2>/dev/null || echo ABSENT)"
for want in cpu memory pids; do
  grep -qw "$want" "$USER_TREE/cgroup.controllers" \
    || die "user delegation did not grant controller $want to the user manager (rootless contract)"
done
if command -v getenforce >/dev/null 2>&1; then
  fact "selinux-mode=$(getenforce 2>/dev/null || echo unknown)"
fi
if [ -r /sys/kernel/security/lsm ]; then
  fact "active-lsm=$(cat /sys/kernel/security/lsm)"
fi
echo "STEP-1-DONE"

step 2 "rootless daemon as a systemd user service (official install, verify-only)"
# The provisioning wrapper installs the rootless daemon through the official
# dockerd-rootless-setuptool.sh path. This harness only VERIFIES the
# resulting normally configured supported deployment; it never installs,
# repairs, or replaces Docker/containerd runtime internals.
UNIT_DIR="$(getent passwd "$FEAS_USER" | cut -d: -f6)/.config/systemd/user"
PKG_UNIT="$UNIT_DIR/docker.service"
[ -f "$PKG_UNIT" ] || die "official rootless user unit missing at $PKG_UNIT (provisioning must run dockerd-rootless-setuptool.sh install)"
EXEC_BIN="$(sed -n 's/^ExecStart=//p' "$PKG_UNIT" | head -1 | awk '{print $1}')"
fact "rootless-unit-execstart=$EXEC_BIN"
[ "$EXEC_BIN" = "/usr/bin/dockerd-rootless.sh" ] \
  || die "user unit ExecStart is not the official rootless wrapper (got $EXEC_BIN)"
fact "rootless-unit-source=official-setuptool"
if ! docker info >/dev/null 2>&1; then
  echo "DIAG: socket state:"
  ls -l "$RUN_DIR/docker.sock" 2>&1 || true
  echo "DIAG: daemon journal:"
  as_user journalctl --user -u docker.service -n 40 --no-pager 2>&1 | tail -40 || true
  die "rootless daemon unreachable at $DOCKER_HOST"
fi
docker version --format 'FACT: docker-client={{.Client.Version}}' || true
docker info --format 'FACT: rootless-server={{.ServerVersion}} driver={{.Driver}} cgroup-driver={{.CgroupDriver}} cgroup-version={{.CgroupVersion}}' \
  || die "rootless docker info failed"
DRIVER=$(docker info --format '{{.CgroupDriver}}')
[ "$DRIVER" = "systemd" ] || die "rootless daemon is not using the systemd cgroup driver (got $DRIVER); delegated placement contract unprovable"
LR=$(docker info --format '{{.LiveRestoreEnabled}}')
[ "$LR" = "true" ] || die "rootless daemon live-restore is not enabled (daemon-restart contract unprovable)"
docker info --format 'FACT: security-options={{.SecurityOptions}}' || true
if [ -r /sys/kernel/security/lsm ]; then
  fact "active-lsm=$(cat /sys/kernel/security/lsm)"
fi
echo "STEP-2-DONE"

step 3 "workload placement under the delegated Session slice"
docker pull -q alpine:3.24 >/dev/null 2>&1 || die "could not pull alpine:3.24 (rootless pull gate)"
# Aggregate ceilings are configured before the first workload under the
# hierarchy so systemd reads the drop-ins when it materializes the slices.
apply_user_unit_props "$SESS_SLICE" "CPUQuota=50%" "MemoryMax=128M" "TasksMax=24" \
  || die "could not configure the Session slice runtime drop-in (delegation gate)"
apply_user_unit_props "$L_SLICE" "CPUQuota=70%" \
  || die "could not configure the Launcher slice runtime drop-in (delegation gate)"
fact "session-slice-set=CPUQuota=50% MemoryMax=128M TasksMax=24 (runtime drop-in)"
fact "launcher-slice-set=CPUQuota=70% (runtime drop-in)"
docker rm -f cgr1 cgr2 >/dev/null 2>&1 || true
docker run -d --name cgr1 --cgroup-parent="$SESS_SLICE" --cpus 0.8 --memory 96m --pids-limit 200 \
  alpine:3.24 sh -c 'sleep 900' >/dev/null || die "rootless run under $SESS_SLICE failed (placement gate)"
docker run -d --name cgr2 --cgroup-parent="$SESS_SLICE" --cpus 0.8 --memory 96m --pids-limit 200 \
  alpine:3.24 sh -c 'sleep 900' >/dev/null || die "rootless sibling run under $SESS_SLICE failed (placement gate)"
fact "container-cgroup-parent=$(docker inspect --format '{{.HostConfig.CgroupParent}}' cgr1)"
if [ ! -d "$SESS_DIR" ]; then
  echo "DIAG: materialized user subtree (top 40):"
  find "$USER_TREE" -maxdepth 4 2>/dev/null | head -40 || true
  echo "DIAG: docker scopes in cgroupfs:"
  find /sys/fs/cgroup -maxdepth 6 -name 'docker-*.scope' 2>/dev/null | head -20 || true
  die "Session slice cgroup dir $SESS_DIR not created under the user subtree"
fi
CG1ID=$(docker inspect --format '{{.Id}}' cgr1)
CGDIR="$SESS_DIR/docker-$CG1ID.scope"
[ -d "$CGDIR" ] || die "no workload scope at $CGDIR (systemd-driver placement contract)"
fact "container-scope-dir=$CGDIR"
for f in cpu.max memory.max pids.max; do
  fact "container-limit-$f=$(cat "$CGDIR/$f" 2>/dev/null || echo ABSENT)"
done
grep -q "8000" "$CGDIR/cpu.max" 2>/dev/null || die "concrete Docker --cpus limit not visible in the workload scope"
grep -q "100663296" "$CGDIR/memory.max" 2>/dev/null || die "concrete Docker --memory limit not visible in the workload scope"
fact "session-slice-cpu-max=$(cat "$SESS_DIR/cpu.max" 2>/dev/null || echo ABSENT)"
fact "session-slice-memory-max=$(cat "$SESS_DIR/memory.max" 2>/dev/null || echo ABSENT)"
fact "session-slice-pids-max=$(cat "$SESS_DIR/pids.max" 2>/dev/null || echo ABSENT)"
echo "STEP-3-DONE"

step 4 "aggregate CPU ceiling enforced over sibling workloads"
docker rm -f cgc1 cgc2 >/dev/null 2>&1 || true
docker run -d --name cgc1 --cgroup-parent="$SESS_SLICE" --cpus 0.8 \
  alpine:3.24 sh -c 'while :; do :; done' >/dev/null || die "burner 1 failed to start"
docker run -d --name cgc2 --cgroup-parent="$SESS_SLICE" --cpus 0.8 \
  alpine:3.24 sh -c 'while :; do :; done' >/dev/null || die "burner 2 failed to start"
CPUA=$(awk '/usage_usec/ {print $2}' "$SESS_DIR/cpu.stat")
sleep 10
CPUB=$(awk '/usage_usec/ {print $2}' "$SESS_DIR/cpu.stat")
DELTA=$((CPUB - CPUA))
fact "aggregate-cpu-usage-usec-per-10s=$DELTA"
# Two 0.8-CPU burners would consume ~16s per 10s wall without the Session
# slice CPUQuota=50%; the delegated ceiling yields about 5s.
[ "$DELTA" -ge 2000000 ] || die "burners did not exercise the ceiling (observed ${DELTA}us/10s)"
[ "$DELTA" -le 7000000 ] || die "aggregate CPU ceiling not enforced over siblings (observed ${DELTA}us/10s)"
docker rm -f cgc1 cgc2 >/dev/null 2>&1 || true
echo "STEP-4-DONE"

step 5 "aggregate memory ceiling enforced over sibling workloads"
docker rm -f cgm0 cgm1 cgm2 >/dev/null 2>&1 || true
# Same design as the system harness: a single 90M python-bytearray
# allocation completes under the 128M slice ceiling (control), then two
# concurrent ones exceed it and the parent OOM engages; with 160M
# container limits a 137 exit is only reachable from the parent.
docker pull python:3.12-alpine >/dev/null || die "could not pull the python allocator image"
ALLOCATOR='python3 -c "import time; d=bytearray(94371840); print(\"allocated\", len(d), flush=True); time.sleep(120)"'
docker run -d --name cgm0 --cgroup-parent="$SESS_SLICE" --memory 160m \
  python:3.12-alpine sh -c "$ALLOCATOR" >/dev/null || die "control allocator failed to start"
CONTROL_OK=0
for i in $(seq 1 45); do
  if docker logs cgm0 2>&1 | grep -q "allocated 94371840"; then
    CONTROL_OK=1
    break
  fi
  sleep 2
done
fact "single-allocator-under-ceiling=$(docker inspect --format '{{.State.Status}} exit={{.State.ExitCode}}' cgm0)"
[ "$CONTROL_OK" = "1" ] || die "a single 90M allocation did not complete under the 128M slice ceiling; the calibration is broken"
docker rm -f cgm0 >/dev/null 2>&1 || true
docker run -d --name cgm1 --cgroup-parent="$SESS_SLICE" --memory 160m \
  python:3.12-alpine sh -c "$ALLOCATOR" >/dev/null || die "allocator 1 failed to start"
docker run -d --name cgm2 --cgroup-parent="$SESS_SLICE" --memory 160m \
  python:3.12-alpine sh -c "$ALLOCATOR" >/dev/null || die "allocator 2 failed to start"
sleep 16
KILLED=0
for c in cgm1 cgm2; do
  ST=$(docker inspect --format '{{.State.Status}} exit={{.State.ExitCode}}' "$c")
  fact "allocator-$c=$ST"
  fact "allocator-$c-log=$(docker logs "$c" 2>&1 | tail -1)"
  case "$ST" in
    *"exit=137"*|*"exit=255"*) KILLED=$((KILLED+1)) ;;
  esac
done
fact "session-slice-memory-events=$(cat "$SESS_DIR/memory.events" 2>/dev/null || echo ABSENT)"
[ "$KILLED" -ge 1 ] || die "aggregate memory ceiling did not OOM-kill an allocator under the Session slice"
cat "$SESS_DIR/memory.events" 2>/dev/null | grep -E "oom_kill [1-9]" || die "session slice memory.events shows no oom_kill"
docker rm -f cgm1 cgm2 >/dev/null 2>&1 || true
echo "STEP-5-DONE"

step 6 "aggregate PIDs ceiling enforced over sibling workloads"
docker rm -f cgp1 >/dev/null 2>&1 || true
docker run -d --name cgp1 --cgroup-parent="$SESS_SLICE" --pids-limit 500 \
  alpine:3.24 sh -c 'sleep 2; (for i in $(seq 1 100); do sleep 300 & done) 2>/dev/null; sleep 120' >/dev/null || die "pids workload failed to start"
# Read the limit sources before the workload forks so a rejection can be
# attributed to the cgroup pids controller or to inherited rlimits.
sleep 1
CGP1ID=$(docker inspect --format '{{.Id}}' cgp1)
fact "cgp1-scope-pids-max=$(cat "$SESS_DIR/docker-$CGP1ID.scope/pids.max" 2>/dev/null || echo ABSENT)"
fact "cgp1-container-nproc=$(docker exec cgp1 sh -c "grep -i 'Max processes' /proc/1/limits 2>/dev/null" 2>&1 | tail -1 || echo unknown)"
fact "feasu-host-processes=$(ps -u "$FEAS_USER" --no-headers 2>/dev/null | wc -l)"
sleep 8
CUR=$(cat "$SESS_DIR/pids.current")
EVT=$(cat "$SESS_DIR/pids.events")
fact "session-slice-pids-current=$CUR"
fact "session-slice-pids-events=$EVT"
[ "$CUR" -le 24 ] || die "aggregate PIDs ceiling not enforced (pids.current=$CUR > 24)"
# The kernel records the fork rejection on the forking cgroup (the workload
# scope) even when the ancestor slice's aggregate limit is what bound it:
# the scope's own pids.max (500) cannot reject at ~22 processes, so a max
# event here proves the Session slice ceiling engaged.
SCOPE_EVT=$(cat "$SESS_DIR/docker-$CGP1ID.scope/pids.events" 2>/dev/null || echo ABSENT)
fact "workload-scope-pids-events=$SCOPE_EVT"
if ! echo "$SCOPE_EVT" | grep -E "max [1-9]"; then
  echo "DIAG: cgp1: $(docker inspect --format 'state={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}' cgp1 2>&1)"
  echo "DIAG: cgp1 log tail: $(docker logs cgp1 2>&1 | tail -4 | tr '\n' '|')"
  echo "DIAG: scopes under the Session slice:"
  for s in "$SESS_DIR"/docker-*.scope; do
    [ -e "$s" ] || continue
    echo "DIAG:   $(basename "$s") pids.current=$(cat "$s/pids.current" 2>/dev/null) pids.events=$(cat "$s/pids.events" 2>/dev/null | tr '\n' ' ')"
  done
  die "pids ceiling rejection not observed (workload scope events=$SCOPE_EVT)"
fi
docker rm -f cgp1 >/dev/null 2>&1 || true
echo "STEP-6-DONE"

step 7 "Launcher aggregate ceiling over sibling Sessions"
docker rm -f cgc1 cgs2 >/dev/null 2>&1 || true
docker run -d --name cgc1 --cgroup-parent="$SESS_SLICE" --cpus 0.8 \
  alpine:3.24 sh -c 'while :; do :; done' >/dev/null || die "session-1 burner failed to start"
docker run -d --name cgs2 --cgroup-parent="$SESS2_SLICE" --cpus 0.8 \
  alpine:3.24 sh -c 'while :; do :; done' >/dev/null || die "session-2 burner failed to start"
[ -f "$RUN_DIR/systemd/user/$L_SLICE.d/50-dh-feas.conf" ] \
  || die "Launcher slice runtime drop-in missing (applied in step 3)"
LA=$(awk '/usage_usec/ {print $2}' "$L_DIR/cpu.stat")
sleep 10
LB=$(awk '/usage_usec/ {print $2}' "$L_DIR/cpu.stat")
LDELTA=$((LB - LA))
fact "launcher-cpu-usage-usec-per-10s=$LDELTA"
# session-1 remains capped at 0.5 CPU (STEP-3) and the session-2 burner at
# 0.8 CPU; without the Launcher ceiling the pair could reach ~13s per 10s
# wall. The Launcher ceiling of 0.7 CPU yields about 7s.
[ "$LDELTA" -ge 2000000 ] || die "burners did not exercise the launcher ceiling (observed ${LDELTA}us/10s)"
[ "$LDELTA" -le 8500000 ] || die "launcher aggregate ceiling not enforced (observed ${LDELTA}us/10s)"
docker rm -f cgc1 cgs2 >/dev/null 2>&1 || true
echo "STEP-7-DONE"

step 8 "running and stopped workloads + rootless daemon restart"
docker rm -f cgr3 cgr4 >/dev/null 2>&1 || true
docker create --name cgr3 --cgroup-parent="$SESS_SLICE" alpine:3.24 sh -c 'sleep 60' >/dev/null || die "created-state workload failed"
docker run -d --name cgr4 --cgroup-parent="$SESS_SLICE" alpine:3.24 sh -c 'sleep 900' >/dev/null || die "running workload for restart failed"
docker stop cgr1 >/dev/null || die "stop of running workload failed"
docker inspect --format 'FACT: cgr1={{.State.Status}} cgr3={{.State.Status}} cgr4={{.State.Status}}' cgr1 cgr3 cgr4
# The supported restart procedure is a restart of the systemd user unit
# installed by the official setup tool. Bounded so a wedged restart becomes
# evidence rather than a hung job.
as_user timeout 180 systemctl --user restart docker.service \
  || die "rootless daemon restart failed (bounded systemctl --user restart)"
sleep 2
docker info >/dev/null 2>&1 || die "rootless daemon unreachable after restart"
docker inspect --format 'FACT: after-restart cgr1={{.State.Status}} cgr3={{.State.Status}} cgr4={{.State.Status}}' cgr1 cgr3 cgr4
if [ "$(docker inspect --format '{{.State.Running}}' cgr4)" != "true" ]; then
  echo "DIAG: docker.service user-unit journal around the restart:"
  as_user journalctl --user -u docker.service --since "-2 min" --no-pager 2>/dev/null | tail -25 || true
  C4SCOPE="$SESS_DIR/docker-$(docker inspect --format '{{.Id}}' cgr4).scope"
  echo "DIAG: cgr4 scope after restart: dir=$([ -d "$C4SCOPE" ] && echo present || echo absent) pids.current=$(cat "$C4SCOPE/pids.current" 2>/dev/null || echo ABSENT)"
  die "running workload did not survive rootless daemon restart (live-restore contract)"
fi
[ "$(docker inspect --format '{{.State.Running}}' cgr4)" = "true" ] || die "running workload did not survive rootless daemon restart (live-restore contract)"
[ "$(docker inspect --format '{{.State.Status}}' cgr3)" = "created" ] || die "created workload changed state across daemon restart"
[ "$(docker inspect --format '{{.State.Status}}' cgr1)" = "exited" ] || die "stopped workload changed state across daemon restart"
[ -d "$SESS_DIR/docker-$(docker inspect --format '{{.Id}}' cgr4).scope" ] \
  || die "workload scope cgroup lost across rootless daemon restart"
echo "STEP-8-DONE"

step 9 "container restart re-establishes placement"
docker restart cgr4 >/dev/null || die "rootless container restart failed"
sleep 1
[ "$(docker inspect --format '{{.State.Running}}' cgr4)" = "true" ] || die "container not running after restart"
[ -d "$SESS_DIR/docker-$(docker inspect --format '{{.Id}}' cgr4).scope" ] \
  || die "workload scope cgroup not re-established after container restart"
echo "STEP-9-DONE"

step 10 "fail-closed: rootless placement never escapes the delegated subtree"
docker rm -f cgfc >/dev/null 2>&1 || true
docker run -d --name cgfc --cgroup-parent=system.slice alpine:3.24 sh -c 'sleep 60' >/dev/null 2>&1 \
  && FC=started || FC=refused
fact "foreign-parent-name-placement=$FC"
if [ "$FC" = "refused" ]; then
  echo "DETECT: placement with a foreign slice name was refused (fail-closed at the engine)"
else
  CGFCID=$(docker inspect --format '{{.Id}}' cgfc)
  if [ -d "/sys/fs/cgroup/system.slice/docker-$CGFCID.scope" ]; then
    docker rm -f cgfc >/dev/null 2>&1 || true
    die "rootless workload escaped into the root cgroup tree (system.slice); fail-closed contract violated"
  fi
  if [ -d "$USER_TREE/system.slice/docker-$CGFCID.scope" ]; then
    echo "DETECT: foreign slice name is namespaced into the delegated user tree (no escape; fail-closed holds)"
  else
    docker rm -f cgfc >/dev/null 2>&1 || true
    die "workload scope not found under the delegated user tree nor the root tree; placement unprovable"
  fi
fi
docker rm -f cgfc >/dev/null 2>&1 || true
echo "STEP-10-DONE"

step 11 "cleanup without leaked cgroups"
docker rm -f cgr1 cgr2 cgr3 cgr4 >/dev/null 2>&1 || true
sleep 2
for d in "$SESS_DIR" "$SESS2_DIR" "$L_DIR" "$P_DIR"; do
  if [ -d "$d" ] && ! ls -A "$d" | grep -q .; then
    rmdir "$d" 2>/dev/null || fact "slice-dir-not-removable=$d (systemd-owned; recorded, not a leak)"
  fi
  [ ! -d "$d" ] || fact "slice-dir-present-after-cleanup=$d (transient systemd slice; scopes removed)"
  for f in docker-*.scope; do
    [ -e "$d/$f" ] || continue
    die "leaked workload scope $d/$f after cleanup"
  done
done
echo "STEP-11-DONE"

echo
echo "RESULT: rootless-mode aggregate cgroup feasibility PASSED"
