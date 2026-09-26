#!/usr/bin/env bash
#
# Guest-side P5-S2 uid_map write-grant scope assessment for openSUSE
# Tumbleweed. INVESTIGATION ONLY — establishes the ACTUAL object surface of
# a hypothetical `docker_helper_newuidmap_t docker_helper_rootlesskit_t:file
# { write }` grant BEFORE it is considered for the production policy. This
# script must never: modify the repository's production policy (the module
# is compiled HERE from the transferred candidate sources and loaded on
# this disposable VM only), grant the file write, grant capabilities, or
# modify any file's content. Every finding lands in the evidence directory;
# the run is PASS when all phases completed (not when a particular answer
# is obtained — a negative IS a finding).
#
#   A  toolchain + module: compile and load the CANDIDATE policy
#      (transferred docker-helper.te/.fc) plus a GUEST-ONLY diag module
#      that allows systemd transient units to bind docker_helper_rootlesskit_t
#      via SELinuxContext= (init_t transition; production binds the domain
#      only through the builder unit + the pointed exec transition). Distro
#      tooling (checkpolicy/container-selinux/policycoreutils-python-utils)
#      and the DISTRO rootlesskit/slirp4netns/audit packages installed by
#      zypper (absent from the fresh cloud image; plain distro packages, no
#      privilege change). Audit-channel sanity probe.
#   B  real-domain observation: with the four builder-family domains
#      PERMISSIVE (so the real rootlesskit flow runs through the mapping
#      step), instance rk1 runs the REAL distro rootlesskit with the REAL
#      distro newuidmap mapping via runcon into docker_helper_rootlesskit_t;
#      a SIGSTOP watcher freezes the child process at first sighting so the
#      helper's uid_map write lands in a frozen process (the item-5
#      reliable-capture mechanism, replacing the 50 ms sampling); the
#      watcher records the full /proc/<pid> file surface of every REAL
#      docker_helper_rootlesskit_t process (uid_map, gid_map, setgroups,
#      mem, oom_score_adj, comm and the complete enumeration) with labels,
#      modes, owners, and contents.
#   C  layer separation: instance rk2 launches the same flow through the
#      transient unit path; safe open-only checks (no content modification)
#      as the builder identity against ALL live rootlesskit_t processes of
#      both instances demonstrate that one SELinux domain spans all
#      concurrent operations (their isolation is invocation discipline, not
#      MAC, not DAC, not kernel CAP).
#
set -Eeuo pipefail

PREFIX='[release-2.4-p5s2-uidmap-scope-diag-tw]'
EVIDENCE_DIR=/tmp/release-2.4-p5s2-uidmap-scope-diag-evidence
DIAG_BASE=/tmp/uidmap-scope-diag
BUILDER_USER=docker-helper-builder
BUILDER_SUBUID_START=231072
BUILDER_SUBUID_COUNT=65536
TRANSFERRED=/tmp/p5s2-uidmap-diag
RK_EXEC_T=system_u:system_r:docker_helper_rootlesskit_t:s0

log()  { printf '%s %s\n' "$PREFIX" "$*"; }
note() { printf '%s NOTE: %s\n' "$PREFIX" "$*"; }

rm -rf "$EVIDENCE_DIR" "$DIAG_BASE"
mkdir -p "$EVIDENCE_DIR" "$DIAG_BASE"

DOMAINS=(docker_helper_builder_t docker_helper_rootlesskit_t docker_helper_slirp4netns_t docker_helper_newuidmap_t)
set_permissive() { semanage permissive -a "$1" >/dev/null 2>&1 || true; }
clear_permissive() { semanage permissive -d "$1" >/dev/null 2>&1 || true; }

cleanup() {
  # SIGSTOPped processes ignore SIGTERM and would stall systemctl stop for
  # TimeoutStopSec: SIGKILL the diagnostic processes first (SIGKILL works
  # on stopped processes), then stop the units.
  pkill -KILL -f 'rootlesskit --net=none' 2>/dev/null || true
  pkill -KILL -f '/bin/sleep 300' 2>/dev/null || true
  for u in uidmap-diag-rk1 uidmap-diag-rk2; do
    systemctl stop "$u" >/dev/null 2>&1 || true
  done
  for d in "${DOMAINS[@]}"; do
    clear_permissive "$d"
  done
  semodule -r docker_helper_uidmap_diag >/dev/null 2>&1 || true
  semodule -r docker_helper >/dev/null 2>&1 || true
}
trap cleanup EXIT

log 'A: toolchain + candidate module load (disposable VM only)'
{
  echo "=== distro ==="
  grep PRETTY_NAME /etc/os-release 2>/dev/null || true
  echo "=== LSM state ==="
  cat /sys/kernel/security/lsm 2>/dev/null || true
  echo "enforce=$(getenforce 2>/dev/null || true)"
} >"$EVIDENCE_DIR/a-toolchain.txt" 2>&1
# The distro rootlesskit/slirp4netns binaries are NOT on the fresh cloud
# image (the docker-helper RPM's conditional dependencies pull them in on
# the UAT VMs); the diagnosis installs the DISTRO packages itself. They are
# installed without any privilege change: plain distro packages, no file
# capabilities, no chkstat involvement beyond the distro's own defaults.
# auditd is installed for the reliable AVC evidence channel (the P5-S1
# proof installs it for the same reason).
zypper --non-interactive install -y checkpolicy container-selinux \
  policycoreutils-python-utils rootlesskit slirp4netns audit \
  >"$EVIDENCE_DIR/zypper-policy-toolchain.log" 2>&1 \
  || note "zypper install of the policy toolchain failed (see zypper-policy-toolchain.log)"
fail_toolchain=0
for t in checkmodule semodule_package semodule semanage restorecon; do
  command -v "$t" >/dev/null 2>&1 || { echo "$t not found" >>"$EVIDENCE_DIR/a-toolchain.txt"; fail_toolchain=1; }
done
if [ "$fail_toolchain" = 1 ]; then
  note "policy toolchain incomplete; the assessment cannot proceed"
  printf '%s P5S2-UIDMAP-SCOPE-DIAG-RESULT=PASS-INCOMPLETE (toolchain unavailable; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi
if command -v auditctl >/dev/null 2>&1; then
  systemctl enable --now auditd >/dev/null 2>&1 || true
  auditctl -e 1 >/dev/null 2>&1 || true
  log "auditd enabled for the AVC evidence channel"
fi

checkmodule -M -m -o /tmp/docker_helper.tmp "$TRANSFERRED/docker-helper.te" 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "checkmodule failed"; cat "$EVIDENCE_DIR/a-toolchain.txt" >&2; exit 1; }
semodule_package -o /tmp/docker_helper.pp -m /tmp/docker_helper.tmp -f "$TRANSFERRED/docker-helper.fc" 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "semodule_package failed"; exit 1; }
semodule -i /tmp/docker_helper.pp 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "semodule -i of the candidate module failed"; exit 1; }

# GUEST-ONLY diag module: lets systemd transient units bind the helper
# domain through SELinuxContext=. TWO grants are needed for the unit's exec,
# mirroring the proven production init_t -> docker_helper_exec_t rule shape:
# the process transition AND the source-domain file execute (the bprm
# checks run in the SOURCE domain — systemd init_t — before the named
# transition). Production binds docker_helper_rootlesskit_t ONLY through
# the builder unit's pointed exec transition; this module exists solely on
# the disposable VM for the isolated diagnostic runs.
cat > /tmp/uidmap-diag.te <<'EOF'
module docker_helper_uidmap_diag 1.0;
require {
	type init_t;
	type docker_helper_rootlesskit_t;
	type docker_helper_rootlesskit_exec_t;
	class process { transition siginh };
	class file { execute read open };
}
allow init_t docker_helper_rootlesskit_t:process { transition siginh };
allow init_t docker_helper_rootlesskit_exec_t:file { execute read open };
EOF
checkmodule -M -m -o /tmp/docker_helper_uidmap_diag.tmp /tmp/uidmap-diag.te 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "diag module checkmodule failed"; exit 1; }
semodule_package -o /tmp/docker_helper_uidmap_diag.pp -m /tmp/docker_helper_uidmap_diag.tmp 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "diag module semodule_package failed"; exit 1; }
semodule -i /tmp/docker_helper_uidmap_diag.pp 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "diag module load failed"; exit 1; }

restorecon /usr/bin/rootlesskit /usr/bin/slirp4netns /usr/bin/newuidmap 2>>"$EVIDENCE_DIR/a-toolchain.txt" || true
{
  echo "=== loaded modules ==="
  semodule -l 2>/dev/null | grep -E 'docker_helper|container' || true
  echo "=== binary labels ==="
  for p in /usr/bin/rootlesskit /usr/bin/slirp4netns /usr/bin/newuidmap; do
    echo "$p -> $(stat -c '%C' "$p" 2>&1)"
  done
  echo "=== file-type question: what carries passwd_file_t vs etc_t ==="
  for p in /etc/passwd /etc/subuid /etc/subgid /etc/group; do
    echo "$p -> $(stat -c '%C %U:%G %a' "$p" 2>&1)"
  done
  echo "=== audit channel sanity probe: a deliberate enforcing denial from the helper domain ==="
  echo "=== (runcon into docker_helper_newuidmap_t, then an unwritable-file touch; NO content change) ==="
  AUDIT_EPOCH="$(date +%s)"
  runcon system_u:system_r:docker_helper_newuidmap_t:s0 touch /etc/shadow >/tmp/uidmap-scope-diag/sanity.out 2>&1 || true
  echo "touch rc recorded; output:"
  cat /tmp/uidmap-scope-diag/sanity.out
  sleep 2
  echo "--- audit.log window (empty output = channel silent for this window) ---"
  grep -a 'type=AVC' /var/log/audit/audit.log 2>/dev/null \
    | awk -v s="$AUDIT_EPOCH" '{ for (i = 1; i <= NF; i++) if ($i ~ /^msg=audit\(/) { ts = substr($i, 11); split(ts, t, "."); if (t[1] + 0 >= s + 0) print; break } }' \
    | tail -10 || true
  echo "--- journalctl -k window (empty output = channel silent for this window) ---"
  journalctl -k --since "@$AUDIT_EPOCH" --no-pager 2>/dev/null | grep -a 'avc:' | tail -10 || true
  echo "(either a process-denial or a transition-denial AVC above proves the audit channel works)"
} >>"$EVIDENCE_DIR/a-toolchain.txt" 2>&1
cat "$EVIDENCE_DIR/a-toolchain.txt" >&2

useradd -m "$BUILDER_USER" 2>/dev/null || true
grep -q "^$BUILDER_USER:" /etc/subuid || echo "$BUILDER_USER:$BUILDER_SUBUID_START:$BUILDER_SUBUID_COUNT" >> /etc/subuid
grep -q "^$BUILDER_USER:" /etc/subgid || echo "$BUILDER_USER:$BUILDER_SUBUID_START:$BUILDER_SUBUID_COUNT" >> /etc/subgid
{
  echo "=== builder identity ==="
  id "$BUILDER_USER"
  echo "=== subids ==="
  grep "^$BUILDER_USER:" /etc/subuid /etc/subgid
} >"$EVIDENCE_DIR/builder-identity.txt" 2>&1
cat "$EVIDENCE_DIR/builder-identity.txt" >&2

log 'B: real-domain observation (four builder-family domains permissive)'
for d in "${DOMAINS[@]}"; do
  set_permissive "$d"
done
mkdir -p "$DIAG_BASE"/{rk1,rk2}
chown "$BUILDER_USER:$BUILDER_USER" "$DIAG_BASE"/{rk1,rk2}
AVC_EPOCH="$(date +%s)"

# The watcher: continuously records every process observed in
# docker_helper_rootlesskit_t — labels, modes, owners, contents, the full
# /proc/<pid> file enumeration, and the status identity lines. Writes one
# block per pid, deduplicated, bounded by the given budget in seconds.
watcher_loop() {
  local budget="$1" out="$2" deadline seen_pids pid f
  deadline=$(( $(date +%s) + budget ))
  : > "$out"
  seen_pids=$(mktemp)
  while [ "$(date +%s)" -lt "$deadline" ]; do
    for pid in $(pgrep -f rootlesskit 2>/dev/null || true); do
      [ -r "/proc/$pid/attr/current" ] || continue
      ctx="$(cat "/proc/$pid/attr/current" 2>/dev/null || true)"
      case "$ctx" in *docker_helper_rootlesskit_t*) ;; *) continue ;; esac
      grep -qx "$pid" "$seen_pids" 2>/dev/null && continue
      echo "$pid" >> "$seen_pids"
      {
        echo "=== rootlesskit_t process pid=$pid (observed $(date -u +%FT%TZ)) ==="
        echo "attr/current: $ctx"
        echo "comm: $(cat "/proc/$pid/comm" 2>/dev/null || true)"
        grep -E '^(PPid|Uid|Gid|NoNewPrivs|CapEff|CapPrm)' "/proc/$pid/status" 2>/dev/null || true
        echo "--- per-file label/mode/owner surface ---"
        for f in uid_map gid_map setgroups mem oom_score_adj comm; do
          echo "$f: $(stat -c '%C mode=%a owner=%U:%G' "/proc/$pid/$f" 2>&1)"
        done
        echo "--- contents of the map files ---"
        for f in uid_map gid_map setgroups; do
          echo "$f content: [$(cat "/proc/$pid/$f" 2>/dev/null || true)]"
        done
        echo "--- FULL regular-file enumeration of /proc/$pid with labels ---"
        find "/proc/$pid" -maxdepth 1 -type f -printf '%f %C\n' 2>/dev/null | sort || true
        echo
      } >> "$out"
    done
    sleep 0.2
  done
  rm -f "$seen_pids"
}

# The SIGSTOP watcher: freezes the FIRST rootlesskit_t CHILD process (its
# parent is itself a rootlesskit_t process) at first sighting, so the
# helper's uid_map write lands in a frozen process and is read at leisure
# (the reliable capture mechanism for the enforcing proof — no dependence
# on the short-lived newuidmap's lifetime). Polls every 5 ms.
(
  local_deadline=$(( $(date +%s) + 60 ))
  while [ "$(date +%s)" -lt "$local_deadline" ]; do
    for pid in $(pgrep -f rootlesskit 2>/dev/null || true); do
      [ -r "/proc/$pid/attr/current" ] || continue
      ctx="$(cat "/proc/$pid/attr/current" 2>/dev/null || true)"
      case "$ctx" in *docker_helper_rootlesskit_t*) ;; *) continue ;; esac
      ppid="$(awk '/^PPid:/{print $2}' "/proc/$pid/status" 2>/dev/null || true)"
      case "$ppid" in
        ''|*[!0-9]*) continue ;;
      esac
      [ -r "/proc/$ppid/attr/current" ] || continue
      pctx="$(cat "/proc/$ppid/attr/current" 2>/dev/null || true)"
      case "$pctx" in *docker_helper_rootlesskit_t*) ;; *) continue ;; esac
      kill -STOP "$pid" 2>/dev/null || true
      echo "stopped child pid=$pid (parent=$ppid) at $(date -u +%FT%TZ)" \
        > "$EVIDENCE_DIR/b-sigstop-demo.txt"
      exit 0
    done
    sleep 0.005
  done
) &
STOPPER_PID=$!

# Instance rk1: the REAL rootlesskit flow, launched directly (runcon path)
# as the builder identity into the REAL rootlesskit_t domain. Target: the
# long-lived /bin/sleep — the bundled buildkitd is NOT installed here (the
# payload is a separate production artifact); the child process, its user
# namespace, its mapping, and its procfs file surface are the REAL
# mechanics under assessment. The watcher + stopper run concurrently.
watcher_loop 60 "$EVIDENCE_DIR/b-real-domain-processes.txt" &
WATCHER_PID=$!
{
  echo "=== launch: runcon path (instance rk1) ==="
  echo "command: runuser -u $BUILDER_USER -- runcon $RK_EXEC_T /usr/bin/rootlesskit --net=none --state-dir=$DIAG_BASE/rk1/rootlesskit-state /bin/sleep 300"
} > "$EVIDENCE_DIR/b-launch-rk1.txt"
runuser -u "$BUILDER_USER" -- \
  runcon "$RK_EXEC_T" /usr/bin/rootlesskit --net=none \
  --state-dir="$DIAG_BASE/rk1/rootlesskit-state" /bin/sleep 300 \
  >>"$EVIDENCE_DIR/b-launch-rk1.txt" 2>&1 &
RK1_PID=$!
wait "$STOPPER_PID" 2>/dev/null || true
sleep 2
cat "$EVIDENCE_DIR/b-launch-rk1.txt" >&2
cat "$EVIDENCE_DIR/b-sigstop-demo.txt" 2>/dev/null >&2 || true

log 'C: second concurrent instance (transient unit path) + layer separation'
{
  echo "=== launch: transient unit path (instance rk2) ==="
  echo "command: systemd-run --unit=uidmap-diag-rk2 --property=SELinuxContext=$RK_EXEC_T --uid=$BUILDER_USER --gid=$BUILDER_USER /usr/bin/rootlesskit --net=none --state-dir=$DIAG_BASE/rk2/rootlesskit-state /bin/sleep 300"
} > "$EVIDENCE_DIR/c-launch-rk2.txt"
systemd-run --unit=uidmap-diag-rk2 \
  --property="SELinuxContext=$RK_EXEC_T" \
  --uid="$BUILDER_USER" --gid="$BUILDER_USER" \
  /usr/bin/rootlesskit --net=none \
  --state-dir="$DIAG_BASE/rk2/rootlesskit-state" /bin/sleep 300 \
  >>"$EVIDENCE_DIR/c-launch-rk2.txt" 2>&1 || true
sleep 3
journalctl -u uidmap-diag-rk2 --no-pager -n 20 >>"$EVIDENCE_DIR/c-launch-rk2.txt" 2>&1 || true
cat "$EVIDENCE_DIR/c-launch-rk2.txt" >&2

# SIGKILL the possibly-stopped rk1 child + its parent before the unit stop
# (a stopped process ignores SIGTERM and would stall the stop).
pkill -KILL -f 'rootlesskit --net=none' 2>/dev/null || true
kill "$RK1_PID" 2>/dev/null || true
wait "$WATCHER_PID" 2>/dev/null || true
cat "$EVIDENCE_DIR/b-real-domain-processes.txt" >&2

# All live rootlesskit_t processes at this point (both instances).
CHILDS=()
for pid in $(pgrep -f rootlesskit 2>/dev/null || true); do
  [ -r "/proc/$pid/attr/current" ] || continue
  ctx="$(cat "/proc/$pid/attr/current" 2>/dev/null || true)"
  case "$ctx" in *docker_helper_rootlesskit_t*) ;; *) continue ;; esac
  CHILDS+=("$pid")
done
log "live rootlesskit_t processes at layer-separation time: ${CHILDS[*]:-none}"
if [ "${#CHILDS[@]}" -ge 1 ]; then
  PIDS="${CHILDS[*]}"
  OPEN_SCRIPT="$DIAG_BASE/open-checks.sh"
  {
    echo "#!/bin/bash"
    echo "for pid in $PIDS; do"
    echo '  for f in uid_map gid_map setgroups mem oom_score_adj comm; do'
    echo '    p="/proc/$pid/$f"'
    echo '    if exec 3<>"$p" 2>/dev/null; then'
    echo '      echo "OPEN-RDWR-OK pid=$pid file=$f"'
    echo '      exec 3>&-'
    echo '    else'
    echo '      echo "OPEN-RDWR-FAILED pid=$pid file=$f rc=$?"'
    echo '    fi'
    echo '  done'
    echo 'done'
  } > "$OPEN_SCRIPT"
  chmod 0755 "$OPEN_SCRIPT"
  {
    echo "=== safe open-only checks as $BUILDER_USER (O_RDWR, no write performed, no content change) ==="
    echo "=== layer meaning: DAC (same uid) + kernel open policy; SELinux is NOT in this path (unconfined runner) ==="
    echo "=== pids checked: $PIDS (all live rootlesskit_t processes: parents and children across BOTH instances) ==="
    su -s /bin/bash "$BUILDER_USER" -c "bash $OPEN_SCRIPT" 2>&1 || true
  } > "$EVIDENCE_DIR/c-open-checks-dac-kernel.txt"
  cat "$EVIDENCE_DIR/c-open-checks-dac-kernel.txt" >&2
else
  note "no live rootlesskit_t processes for the open checks (recorded as a finding)"
  echo "no live rootlesskit_t processes" > "$EVIDENCE_DIR/c-open-checks-dac-kernel.txt"
fi

# The permissive window's AVC harvest: what the real flows ATTEMPTED
# (permissive=1 records) — evidence of the attempted surface, never a grant.
sleep 2
{
  echo "=== kernel AVC records of the diagnostic window (permissive=1 = allowed+logged attempts) ==="
  grep -a 'type=AVC' /var/log/audit/audit.log 2>/dev/null \
    | awk -v s="$AVC_EPOCH" '{ for (i = 1; i <= NF; i++) if ($i ~ /^msg=audit\(/) { ts = substr($i, 11); split(ts, t, "."); if (t[1] + 0 >= s + 0) print; break } }' \
    | tail -100 || true
  echo "=== journalctl -k window ==="
  journalctl -k --since "@$AVC_EPOCH" --no-pager 2>/dev/null | grep -a 'avc:' | tail -100 || true
} > "$EVIDENCE_DIR/e-permissive-avc-harvest.txt" 2>&1
cat "$EVIDENCE_DIR/e-permissive-avc-harvest.txt" >&2

log 'cleanup'
for d in "${DOMAINS[@]}"; do
  clear_permissive "$d"
done

printf '%s P5S2-UIDMAP-SCOPE-DIAG-RESULT=PASS (assessment completed; findings are in the evidence)\n' "$PREFIX" >&2
exit 0
