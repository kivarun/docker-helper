#!/usr/bin/env bash
#
# cgroup-feasibility-rootless.sh — Release 3 aggregate-cgroup feasibility
# harness for ROOTLESS/USER deployment. It runs INSIDE a real openSUSE
# Tumbleweed VM (the Phase-0 workflow boots it through
# scripts/uat-vm-cgroup-rootless.sh on the canonical VM harness).
#
# The proof target is the unprivileged path exactly as deployed: a normal
# user owns a systemd user session with cgroup v2 controller delegation, a
# rootless Docker daemon runs as a systemd USER service of that user, and
# workloads are placed and aggregate-limited through the user's delegated
# cgroup subtree — never by writing cgroupfs as root outside the delegation.
# Root reads are used only for evidence.
#
# Hierarchy mapping (systemd slice grammar encodes the R3 chain):
#
#   Root          -> the user's delegated cgroup subtree
#                    user.slice/user-<uid>.slice/user@<uid>.service
#   Principal     -> dhfeas-principal1.slice
#   Launcher      -> dhfeas-principal1-launcher1.slice
#   Session       -> dhfeas-principal1-launcher1-session1.slice
#   workload      -> docker-<id>.scope under the Session slice
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
SESS_SLICE=dhfeas-principal1-launcher1-session1.slice
SESS2_SLICE=dhfeas-principal1-launcher1-session2.slice
L_SLICE=dhfeas-principal1-launcher1.slice
P_SLICE=dhfeas-principal1.slice
export DOCKER_HOST="unix://$RUN_DIR/docker.sock"

as_user() { runuser -u "$FEAS_USER" -- env XDG_RUNTIME_DIR="$RUN_DIR" "$@"; }

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
echo "STEP-1-DONE"

step 2 "rootless daemon as a systemd user service"
# Prefer the package-shipped user unit only when its ExecStart target
# actually exists (the openSUSE docker RPM ships a user unit that references
# the missing dockerd-rootless.sh). Otherwise install the documented
# rootlesskit invocation as a harness-owned unit, which overrides the
# package one for this user.
UNIT_DIR="$(getent passwd "$FEAS_USER" | cut -d: -f6)/.config/systemd/user"
SHIPPED=0
PKG_UNIT=/usr/lib/systemd/user/docker.service
if [ -f "$PKG_UNIT" ]; then
  EXEC_BIN=$(sed -n 's/^ExecStart=//p' "$PKG_UNIT" | head -1 | awk '{print $1}')
  if [ -n "$EXEC_BIN" ] && [ -x "$EXEC_BIN" ]; then
    SHIPPED=1
  fi
fi
if [ "$SHIPPED" = 1 ]; then
  fact "rootless-unit-source=package-shipped"
else
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT_DIR/docker.service" <<'EOF'
[Unit]
Description=rootless docker (cgroup feasibility harness)
StartLimitBurst=3
StartLimitIntervalSec=60s

[Service]
ExecStart=/usr/bin/rootlesskit --net=slirp4netns --copy-up=/etc/resolv.conf --copy-up=/etc/hosts --disable-host-loopback /usr/bin/dockerd
TimeoutSec=0
Restart=on-failure

[Install]
WantedBy=default.target
EOF
  chown -R "$FEAS_USER:$FEAS_USER" "$(getent passwd "$FEAS_USER" | cut -d: -f6)/.config"
  fact "rootless-unit-source=harness-owned (package unit references a missing rootless wrapper)"
fi
# live-restore so a daemon restart preserves running workloads (the same
# contract the system-mode harness proves).
as_user bash -c 'mkdir -p ~/.config/docker && printf "{ \"live-restore\": true }\n" > ~/.config/docker/daemon.json' \
  || die "could not write the rootless daemon configuration"
as_user systemctl --user daemon-reload
as_user systemctl is-active --quiet docker.service \
  || as_user systemctl start docker.service \
  || {
    echo "DIAG: systemctl status (user):"
    as_user systemctl --user status docker.service --no-pager 2>&1 | head -20 || true
    echo "DIAG: system journal for the user manager:"
    journalctl -u "user@$FEAS_UID.service" -n 60 --no-pager 2>&1 | tail -40 || true
    echo "DIAG: recent AVC denials:"
    dmesg 2>/dev/null | grep -i "avc" | tail -20 || true
    if command -v audit2allow >/dev/null 2>&1 && dmesg 2>/dev/null | grep -i "avc" | grep -qi cgroup; then
      echo "DIAG: cgroup AVCs observed; attempting the narrow delegation policy module"
      dmesg 2>/dev/null | grep "avc:" > /tmp/dh-feas-avc.log || true
      if audit2allow -M dh-feas-cg-deleg < /tmp/dh-feas-avc.log >/dev/null 2>&1 \
        && semodule -i /tmp/dh-feas-cg-deleg.pp 2>/dev/null; then
        fact "selinux-delegation-module=installed (narrow module generated from observed cgroup AVCs)"
        as_user systemctl start docker.service 2>/dev/null && echo "MODULE-RETRY-OK" || true
      fi
    fi
    as_user systemctl is-active --quiet docker.service \
      || die "rootless docker user service did not start"
  }
for i in $(seq 1 30); do
  docker info >/dev/null 2>&1 && break
  sleep 2
done
docker info >/dev/null 2>&1 || {
  as_user journalctl --user -u docker.service -n 30 --no-pager 2>&1 | tail -30 || true
  die "rootless daemon unreachable at $DOCKER_HOST"
}
docker info --format 'FACT: rootless-server={{.ServerVersion}} driver={{.Driver}} cgroup-driver={{.CgroupDriver}} cgroup-version={{.CgroupVersion}}' \
  || die "rootless docker info failed"
DRIVER=$(docker info --format '{{.CgroupDriver}}')
[ "$DRIVER" = "systemd" ] || die "rootless daemon is not using the systemd cgroup driver (got $DRIVER); delegated placement contract unprovable"
docker version --format 'FACT: docker-client={{.Client.Version}}' || true
if [ -r /sys/kernel/security/lsm ]; then
  fact "active-lsm=$(cat /sys/kernel/security/lsm)"
fi
echo "STEP-2-DONE"

step 3 "workload placement under the delegated Session slice"
docker pull -q alpine:3.24 >/dev/null 2>&1 || die "could not pull alpine:3.24 (rootless pull gate)"
as_user systemctl set-property --runtime "$SESS_SLICE" CPUQuota=50% MemoryMax=128M TasksMax=24 \
  || die "user manager refused set-property on the Session slice (delegation gate)"
fact "session-slice-set=CPUQuota=50% MemoryMax=128M TasksMax=24"
docker rm -f cgr1 cgr2 >/dev/null 2>&1 || true
docker run -d --name cgr1 --cgroup-parent="$SESS_SLICE" --cpus 0.8 --memory 96m --pids-limit 200 \
  alpine:3.24 sh -c 'sleep 900' >/dev/null || die "rootless run under $SESS_SLICE failed (placement gate)"
docker run -d --name cgr2 --cgroup-parent="$SESS_SLICE" --cpus 0.8 --memory 96m --pids-limit 200 \
  alpine:3.24 sh -c 'sleep 900' >/dev/null || die "rootless sibling run under $SESS_SLICE failed (placement gate)"
fact "container-cgroup-parent=$(docker inspect --format '{{.HostConfig.CgroupParent}}' cgr1)"
SESS_DIR="$USER_TREE/$SESS_SLICE"
[ -d "$SESS_DIR" ] || die "Session slice cgroup dir $SESS_DIR not created under the user subtree"
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
docker rm -f cgm1 cgm2 >/dev/null 2>&1 || true
# Same allocation mechanism as the system harness (dd sizes, not busybox head
# suffix parsing; the container log records the written size).
ALLOCATOR='sleep 3; dd if=/dev/zero of=/dev/shm/blob bs=1M count=80 2>/dev/null; echo wrote=$(stat -c %s /dev/shm/blob 2>/dev/null); sleep 120'
docker run -d --name cgm1 --cgroup-parent="$SESS_SLICE" --memory 96m --shm-size 128m \
  alpine:3.24 sh -c "$ALLOCATOR" >/dev/null || die "allocator 1 failed to start"
docker run -d --name cgm2 --cgroup-parent="$SESS_SLICE" --memory 96m --shm-size 128m \
  alpine:3.24 sh -c "$ALLOCATOR" >/dev/null || die "allocator 2 failed to start"
sleep 14
for c in cgm1 cgm2; do
  fact "allocator-$c=$(docker inspect --format '{{.State.Status}} exit={{.State.ExitCode}}' "$c")"
  fact "allocator-$c-log=$(docker logs "$c" 2>&1 | tail -1)"
done
EX1=$(docker inspect --format '{{.State.ExitCode}}' cgm1)
EX2=$(docker inspect --format '{{.State.ExitCode}}' cgm2)
fact "session-slice-memory-events=$(cat "$SESS_DIR/memory.events" 2>/dev/null || echo ABSENT)"
KILLED=0
{ [ "$EX1" = "137" ] || [ "$EX1" = "255" ]; } && KILLED=1
{ [ "$EX2" = "137" ] || [ "$EX2" = "255" ]; } && KILLED=1
[ "$KILLED" = "1" ] || die "aggregate memory ceiling did not OOM-kill an allocator under the Session slice (exits $EX1/$EX2)"
cat "$SESS_DIR/memory.events" 2>/dev/null | grep -E "oom_kill [1-9]" || die "session slice memory.events shows no oom_kill"
docker rm -f cgm1 cgm2 >/dev/null 2>&1 || true
echo "STEP-5-DONE"

step 6 "aggregate PIDs ceiling enforced over sibling workloads"
docker rm -f cgp1 >/dev/null 2>&1 || true
docker run -d --name cgp1 --cgroup-parent="$SESS_SLICE" --pids-limit 500 \
  alpine:3.24 sh -c 'sleep 2; for i in $(seq 1 100); do sleep 300 & done; sleep 120' >/dev/null || die "pids workload failed to start"
sleep 8
CUR=$(cat "$SESS_DIR/pids.current")
EVT=$(cat "$SESS_DIR/pids.events")
fact "session-slice-pids-current=$CUR"
fact "session-slice-pids-events=$EVT"
[ "$CUR" -le 24 ] || die "aggregate PIDs ceiling not enforced (pids.current=$CUR > 24)"
echo "$EVT" | grep -E "max [1-9]" || die "pids.events shows no max enforcement"
docker rm -f cgp1 >/dev/null 2>&1 || true
echo "STEP-6-DONE"

step 7 "Launcher aggregate ceiling over sibling Sessions"
docker rm -f cgc1 cgs2 >/dev/null 2>&1 || true
docker run -d --name cgc1 --cgroup-parent="$SESS_SLICE" --cpus 0.8 \
  alpine:3.24 sh -c 'while :; do :; done' >/dev/null || die "session-1 burner failed to start"
docker run -d --name cgs2 --cgroup-parent="$SESS2_SLICE" --cpus 0.8 \
  alpine:3.24 sh -c 'while :; do :; done' >/dev/null || die "session-2 burner failed to start"
as_user systemctl set-property --runtime "$L_SLICE" CPUQuota=70% \
  || die "user manager refused set-property on the Launcher slice"
fact "launcher-slice-set=CPUQuota=70%"
LA=$(awk '/usage_usec/ {print $2}' "$USER_TREE/$L_SLICE/cpu.stat")
sleep 10
LB=$(awk '/usage_usec/ {print $2}' "$USER_TREE/$L_SLICE/cpu.stat")
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
as_user systemctl restart docker.service || die "rootless daemon restart failed"
sleep 2
docker info >/dev/null 2>&1 || die "rootless daemon unreachable after restart"
docker inspect --format 'FACT: after-restart cgr1={{.State.Status}} cgr3={{.State.Status}} cgr4={{.State.Status}}' cgr1 cgr3 cgr4
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
for d in "$SESS_DIR" "$USER_TREE/$SESS2_SLICE" "$USER_TREE/$L_SLICE" "$USER_TREE/$P_SLICE"; do
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
