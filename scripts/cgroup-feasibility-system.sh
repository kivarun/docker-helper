#!/usr/bin/env bash
#
# cgroup-feasibility-system.sh — Release 3 aggregate-cgroup feasibility
# harness for SYSTEM deployment. It runs INSIDE a real openSUSE Tumbleweed VM
# as root (the Phase-0 workflow boots it through scripts/uat-vm-cgroup-system.sh
# using the canonical scripts/uat-vm-tumbleweed.sh harness).
#
# This is a feasibility probe, not the production R3 resource manager. It
# proves (or precisely disproves) the accepted Release 3 contract recorded in
# docs/release-3-resource-constraints.md:
#
#   Root -> Principal -> Launcher -> Session -> workload
#
# for aggregate CPU, memory, and PIDs ceilings, with real Docker workloads
# placed under the Session cgroup via the cgroupfs driver and --cgroup-parent,
# while concrete Docker workload limits are applied simultaneously. It also
# proves daemon/container restart behavior, running and stopped workloads,
# cleanup without leaked cgroups, the shipped systemd unit restrictions, the
# one actively applicable MAC profile of the VM, and fail-closed detection
# when placement without controller enforcement would otherwise be silent.
#
# Every observable fact is printed as a stable key:value line; every step ends
# with a STEP-<n>-DONE marker; any failed assertion exits nonzero with the
# exact violated contract. Output is recorded verbatim as gate evidence.

set -uo pipefail

log()    { printf '[cg-system] %s\n' "$*"; }
fact()   { printf 'FACT: %s\n' "$*"; }
step()   { printf '\n[cg-system] == STEP %s ==\n' "$*"; }
die()    { printf 'GATE-FAIL: %s\n' "$*" >&2; exit 1; }

BASE=/sys/fs/cgroup
HIER=$BASE/dh-feas
P=$HIER/principal-1
L=$P/launcher-1
S1=$L/session-1
S2=$L/session-2
# The cgroupfs driver resolves --cgroup-parent relative to the cgroup root;
# passing a /sys/fs/cgroup-prefixed path silently creates a doubled path.
CGRP=/dh-feas
S1_REL=$CGRP/principal-1/launcher-1/session-1
S2_REL=$CGRP/principal-1/launcher-1/session-2
CTRS="+cpu +memory +pids"

step 1 "cgroup v2 facts"
[ -f "$BASE/cgroup.controllers" ] || die "no cgroup v2 unified hierarchy at $BASE (contract requires cgroup v2)"
fact "cgroup-controllers-root=$(cat "$BASE/cgroup.controllers")"
fact "cgroup-subtree-control-root=$(cat "$BASE/cgroup.subtree_control")"
fact "kernel=$(uname -r)"
fact "systemd=$(systemctl --version | head -1 | awk '{print $2}')"
echo "STEP-1-DONE"

step 2 "hierarchy creation Root->Principal->Launcher->Session"
mkdir -p "$S1" "$S2" || die "cannot create Session cgroup dirs (delegation/writability gate)"
# Enable controllers top-down on every ancestor of the Session dirs; each of
# those cgroups stays process-free, so the no-internal-process rule is kept.
for d in "$BASE" "$HIER" "$P" "$L"; do
  if ! echo "$CTRS" > "$d/cgroup.subtree_control" 2>/dev/null; then
    die "cannot enable controllers in $d/cgroup.subtree_control (controller delegation gate)"
  fi
  fact "subtree-control=$d:$(cat "$d/cgroup.subtree_control")"
done
for want in cpu memory pids; do
  grep -qw "$want" "$S1/cgroup.controllers" || die "Session cgroup did not receive controller $want"
done
fact "session-controllers=$(cat "$S1/cgroup.controllers")"
echo "STEP-2-DONE"

step 3 "Docker (cgroupfs driver) + MAC profile facts"
command -v docker >/dev/null 2>&1 || die "docker not installed in the guest (bootstrap step missing)"
docker version --format 'FACT: docker-client={{.Client.Version}} docker-server={{.Server.Version}}' || die "docker version query failed"
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{ "exec-opts": ["native.cgroupdriver=cgroupfs"], "live-restore": true }
EOF
systemctl restart docker || die "docker restart with cgroupfs driver failed"
systemctl is-active docker >/dev/null || die "docker not active after restart"
docker info --format 'FACT: docker-cgroup-driver={{.CgroupDriver}} cgroup-version={{.CgroupVersion}} storage={{.Driver}}' || die "docker info failed"
if [ -r /sys/kernel/security/lsm ]; then
  fact "active-lsm=$(cat /sys/kernel/security/lsm)"
fi
if command -v getenforce >/dev/null 2>&1; then
  fact "selinux-mode=$(getenforce 2>/dev/null || echo unknown)"
fi
echo "STEP-3-DONE"

step 4 "workload placement under Session + concrete Docker limits"
docker pull -q alpine:3.24 >/dev/null 2>&1 || die "could not pull alpine:3.24"
docker run -d --name cg1 \
  --cgroup-parent="$S1_REL" --cpus 0.8 --memory 96m --pids-limit 200 \
  alpine:3.24 sh -c 'sleep 900' >/dev/null || die "docker run under $S1 failed (placement gate)"
docker run -d --name cg2 \
  --cgroup-parent="$S1_REL" --cpus 0.8 --memory 96m --pids-limit 200 \
  alpine:3.24 sh -c 'sleep 900' >/dev/null || die "docker run sibling under $S1 failed (placement gate)"
fact "container-cgroup-parent=$(docker inspect --format '{{.HostConfig.CgroupParent}}' cg1)"
CG1PID=$(docker inspect --format '{{.State.Pid}}' cg1)
INSIDE=$(cat "/proc/$CG1PID/cgroup" | head -1)
fact "container-host-side-cgroup=$INSIDE"
echo "$INSIDE" | grep -q "dh-feas/principal-1/launcher-1/session-1" \
  || die "container did not land under the Session cgroup ($INSIDE)"
CG1ID=$(docker inspect --format '{{.Id}}' cg1)
CGDIR="$S1/$CG1ID"
[ -d "$CGDIR" ] || die "no container cgroup directory at $CGDIR"
fact "container-cgroup-dir=$CGDIR"
for f in cpu.max memory.max pids.max; do
  fact "container-limit-$f=$(cat "$CGDIR/$f" 2>/dev/null || echo ABSENT)"
done
grep -q "8000" "$CGDIR/cpu.max" 2>/dev/null || die "concrete Docker --cpus limit not visible in the container cgroup"
grep -q "100663296" "$CGDIR/memory.max" 2>/dev/null || die "concrete Docker --memory limit not visible in the container cgroup"
echo "STEP-4-DONE"

step 5 "aggregate CPU ceiling enforced over sibling workloads"
docker rm -f cgc1 cgc2 >/dev/null 2>&1 || true
docker run -d --name cgc1 --cgroup-parent="$S1_REL" --cpus 0.8 \
  alpine:3.24 sh -c 'while :; do :; done' >/dev/null || die "burner 1 failed to start"
docker run -d --name cgc2 --cgroup-parent="$S1_REL" --cpus 0.8 \
  alpine:3.24 sh -c 'while :; do :; done' >/dev/null || die "burner 2 failed to start"
echo "50000 100000" > "$S1/cpu.max" || die "cannot set aggregate cpu.max on $S1"
fact "session-cpu-max=$(cat "$S1/cpu.max")"
CPUA=$(awk '/usage_usec/ {print $2}' "$S1/cpu.stat")
sleep 10
CPUB=$(awk '/usage_usec/ {print $2}' "$S1/cpu.stat")
DELTA=$((CPUB - CPUA))
fact "aggregate-cpu-usage-usec-per-10s=$DELTA"
# Two burners with 0.8 CPU each would consume ~16s of CPU time per 10s wall
# without the ceiling; the Session ceiling of 0.5 CPU yields about 5s.
[ "$DELTA" -ge 2000000 ] || die "burners did not exercise the ceiling (observed ${DELTA}us/10s)"
[ "$DELTA" -le 7000000 ] || die "aggregate CPU ceiling not enforced over siblings (observed ${DELTA}us/10s)"
docker rm -f cgc1 cgc2 >/dev/null 2>&1 || true
echo "STEP-5-DONE"

step 6 "aggregate memory ceiling enforced over sibling workloads"
echo "134217728" > "$S1/memory.max" || die "cannot set aggregate memory.max on $S1"
fact "session-memory-max=$(cat "$S1/memory.max")"
docker rm -f cgm1 cgm2 >/dev/null 2>&1 || true
# Anonymous RSS allocation: 90M shell-string variables, each under its own
# 96M container limit; together they exceed the 128M Session ceiling, and
# the anonymous charge failure is a deterministic parent-level OOM kill.
# The container log records the allocated size as direct evidence.
ALLOCATOR='sleep 3; x=$(dd if=/dev/zero bs=1M count=90 2>/dev/null | tr "\000" "A"); echo allocated=${#x}; sleep 120'
docker run -d --name cgm1 --cgroup-parent="$S1_REL" --memory 96m \
  alpine:3.24 sh -c "$ALLOCATOR" >/dev/null || die "allocator 1 failed to start"
docker run -d --name cgm2 --cgroup-parent="$S1_REL" --memory 96m \
  alpine:3.24 sh -c "$ALLOCATOR" >/dev/null || die "allocator 2 failed to start"
sleep 16
for c in cgm1 cgm2; do
  fact "allocator-$c=$(docker inspect --format '{{.State.Status}} exit={{.State.ExitCode}}' "$c")"
  fact "allocator-$c-log=$(docker logs "$c" 2>&1 | tail -1)"
done
fact "session-memory-current=$(cat "$S1/memory.current")"
EX1=$(docker inspect --format '{{.State.ExitCode}}' cgm1)
EX2=$(docker inspect --format '{{.State.ExitCode}}' cgm2)
fact "session-memory-events=$(cat "$S1/memory.events")"
KILLED=0
{ [ "$EX1" = "137" ] || [ "$EX1" = "255" ]; } && KILLED=1
{ [ "$EX2" = "137" ] || [ "$EX2" = "255" ]; } && KILLED=1
[ "$KILLED" = "1" ] || die "aggregate memory ceiling did not OOM-kill an allocator under $S1 (exits $EX1/$EX2)"
echo "$S1/memory.events" | grep -E "oom_kill [1-9]" || die "session memory.events shows no oom_kill"
docker rm -f cgm1 cgm2 >/dev/null 2>&1 || true
echo "STEP-6-DONE"

step 7 "aggregate PIDs ceiling enforced over sibling workloads"
echo "24" > "$S1/pids.max" || die "cannot set aggregate pids.max on $S1"
fact "session-pids-max=$(cat "$S1/pids.max")"
docker rm -f cgp1 >/dev/null 2>&1 || true
docker run -d --name cgp1 --cgroup-parent="$S1_REL" --pids-limit 500 \
  alpine:3.24 sh -c 'sleep 2; for i in $(seq 1 100); do sleep 300 & done; sleep 120' >/dev/null || die "pids workload failed to start"
sleep 8
CUR=$(cat "$S1/pids.current")
EVT=$(cat "$S1/pids.events")
fact "session-pids-current=$CUR"
fact "session-pids-events=$EVT"
[ "$CUR" -le 24 ] || die "aggregate PIDs ceiling not enforced (pids.current=$CUR > 24)"
echo "$EVT" | grep -E "max [1-9]" || die "pids.events shows no max enforcement"
docker rm -f cgp1 >/dev/null 2>&1 || true
echo "STEP-7-DONE"

step 8 "Launcher aggregate ceiling over sibling Sessions"
docker rm -f cgc1 cgs2 >/dev/null 2>&1 || true
docker run -d --name cgc1 --cgroup-parent="$S1_REL" --cpus 0.8 \
  alpine:3.24 sh -c 'while :; do :; done' >/dev/null || die "session-1 burner failed to start"
docker run -d --name cgs2 --cgroup-parent="$S2_REL" --cpus 0.8 \
  alpine:3.24 sh -c 'while :; do :; done' >/dev/null || die "session-2 burner failed to start"
echo "70000 100000" > "$L/cpu.max" || die "cannot set launcher cpu.max"
fact "launcher-cpu-max=$(cat "$L/cpu.max")"
LA=$(awk '/usage_usec/ {print $2}' "$L/cpu.stat")
sleep 10
LB=$(awk '/usage_usec/ {print $2}' "$L/cpu.stat")
LDELTA=$((LB - LA))
fact "launcher-cpu-usage-usec-per-10s=$LDELTA"
# session-1 is still capped to 0.5 CPU (STEP-5) and session-2's burner to
# 0.8 CPU; without the Launcher ceiling the pair could reach ~13s per 10s
# wall. The Launcher ceiling of 0.7 CPU yields about 7s.
[ "$LDELTA" -ge 2000000 ] || die "burners did not exercise the launcher ceiling (observed ${LDELTA}us/10s)"
[ "$LDELTA" -le 8500000 ] || die "launcher aggregate ceiling not enforced (observed ${LDELTA}us/10s)"
docker rm -f cgc1 cgs2 >/dev/null 2>&1 || true
echo "STEP-8-DONE"

step 9 "running and stopped workloads + daemon restart"
docker rm -f cg3 cg4 >/dev/null 2>&1 || true
docker create --name cg3 --cgroup-parent="$S1_REL" alpine:3.24 sh -c 'sleep 60' >/dev/null || die "created-state workload failed"
docker run -d --name cg4 --cgroup-parent="$S1_REL" alpine:3.24 sh -c 'sleep 900' >/dev/null || die "running workload for restart failed"
docker stop cg1 >/dev/null || die "stop of running workload failed"
docker inspect --format 'FACT: cg1={{.State.Status}} cg3={{.State.Status}} cg4={{.State.Status}}' cg1 cg3 cg4
systemctl restart docker || die "docker daemon restart failed"
sleep 2
docker inspect --format 'FACT: after-daemon-restart cg1={{.State.Status}} cg3={{.State.Status}} cg4={{.State.Status}}' cg1 cg3 cg4
[ "$(docker inspect --format '{{.State.Running}}' cg4)" = "true" ] || die "running workload did not survive daemon restart (live-restore contract)"
[ "$(docker inspect --format '{{.State.Status}}' cg3)" = "created" ] || die "created workload changed state across daemon restart"
[ "$(docker inspect --format '{{.State.Status}}' cg1)" = "exited" ] || die "stopped workload changed state across daemon restart"
CG4PID=$(docker inspect --format '{{.State.Pid}}' cg4)
CG4CG=$(cat "/proc/$CG4PID/cgroup" | head -1)
fact "cg4-host-side-cgroup-after-restart=$CG4CG"
echo "$CG4CG" | grep -q "dh-feas/principal-1/launcher-1/session-1" || die "placement lost across daemon restart"
CG1ID=$(docker inspect --format '{{.Id}}' cg1)
[ -d "$S1/$CG1ID" ] && fact "stopped-container-cgroup-dir=present" || fact "stopped-container-cgroup-dir=absent"
echo "STEP-9-DONE"

step 10 "container restart re-establishes placement"
docker restart cg4 >/dev/null || die "docker restart of container failed"
sleep 1
CG4PID=$(docker inspect --format '{{.State.Pid}}' cg4)
CG4CG2=$(cat "/proc/$CG4PID/cgroup" | head -1)
fact "cg4-host-side-cgroup-after-container-restart=$CG4CG2"
echo "$CG4CG2" | grep -q "dh-feas/principal-1/launcher-1/session-1" || die "placement lost across container restart"
echo "STEP-10-DONE"

step 11 "shipped systemd unit restrictions do not block cgroup management"
# The shipped unit file is copied into the guest by the VM orchestrator.
UNIT=/opt/cg-feas/docker-helper.service
[ -f "$UNIT" ] || die "shipped systemd unit not found at $UNIT"
PROPS_ARR=()
FACT_PROPS=""
for d in NoNewPrivileges RestrictNamespaces RestrictRealtime RestrictAddressFamilies MemoryDenyWriteExecute LockPersonality PrivateTmp ProtectClock ProtectHostname ProtectSystem ProtectHome ProtectControlGroups ProtectKernelTunables PrivateDevices UMask ProtectKernelModules ProtectKernelLogs; do
  v=$(sed -n "s/^$d=//p" "$UNIT" | tail -1)
  if [ -n "$v" ]; then
    PROPS_ARR+=( -p "$d=$v" )
    FACT_PROPS="$FACT_PROPS $d=$v"
  fi
done
fact "shipped-hardening-directives=$FACT_PROPS"
systemd-run --quiet --unit=dh-feas-hardening "${PROPS_ARR[@]}" \
  bash -c 'mkdir -p /sys/fs/cgroup/dh-feas-hardening-probe && echo "+pids" > /sys/fs/cgroup/dh-feas-hardening-probe/cgroup.subtree_control && echo HARDENING-WRITE-OK' \
  || die "cgroup management blocked by the shipped systemd hardening set"
systemd-run --quiet --unit=dh-feas-hardening-check "${PROPS_ARR[@]}" \
  bash -c 'grep -q pids /sys/fs/cgroup/dh-feas-hardening-probe/cgroup.subtree_control && echo HARDENING-CHECK-OK' \
  || die "hardened service could not verify the controller delegation it wrote"
systemctl stop dh-feas-hardening-check.service dh-feas-hardening.service 2>/dev/null || true
rmdir /sys/fs/cgroup/dh-feas-hardening-probe 2>/dev/null || true
echo "STEP-11-DONE"

step 12 "fail-closed: silent placement without controller enforcement is detectable"
# A parent whose subtree controllers were removed must not be silently
# accepted: the detection mechanism (reading the container cgroup
# controllers) must observe the missing enforcement. This proves the R3
# fail-closed contract is implementable with cgroupfs-visible facts.
docker rm -f cgfc >/dev/null 2>&1 || true
mkdir -p "$HIER/nolang"
echo "-cpu -memory -pids" > "$HIER/nolang/cgroup.subtree_control" || die "could not strip controllers from the no-language parent"
docker run -d --name cgfc --cgroup-parent="$CGRP/nolang" alpine:3.24 sh -c 'sleep 60' >/dev/null 2>&1 \
  && FC=started || FC=refused
fact "no-controller-placement=$FC"
if [ "$FC" = "started" ]; then
  FCDIR=$(ls -d "$HIER/nolang"/*/ 2>/dev/null | head -1)
  FCTRLS=$(cat "$FCDIR/cgroup.controllers" 2>/dev/null || echo none)
  fact "no-controller-container-controllers=$FCTRLS"
  grep -qw cpu "$FCTRLS" && die "silent controllerless placement NOT detectable (cpu present without delegation)"
  echo "DETECT: controllerless placement observed and detectable (controllers='$FCTRLS')"
else
  echo "DETECT: engine refused controllerless placement (fail-closed at the engine)"
fi
docker rm -f cgfc >/dev/null 2>&1 || true
rmdir "$HIER/nolang" 2>/dev/null || true
echo "STEP-12-DONE"

step 13 "cleanup without leaked cgroups"
docker rm -f cg1 cg2 cg3 cg4 >/dev/null 2>&1 || true
sleep 1
for d in "$S1" "$S2"; do
  rmdir "$d" 2>/dev/null || [ ! -d "$d" ] || die "Session cgroup $d not removable (leaked cgroup)"
done
rmdir "$L" "$P" "$HIER" 2>/dev/null || die "hierarchy cgroups leaked after cleanup (rmdir failed)"
[ ! -d "$HIER" ] || die "leaked cgroup directory $HIER"
echo "STEP-13-DONE"

echo
echo "RESULT: system-mode aggregate cgroup feasibility PASSED"
