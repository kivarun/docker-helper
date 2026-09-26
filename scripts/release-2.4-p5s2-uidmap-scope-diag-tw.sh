#!/usr/bin/env bash
#
# Guest-side P5-S2 uid_map write-grant scope assessment for openSUSE
# Tumbleweed. INVESTIGATION ONLY — establishes the ACTUAL object surface of
# a hypothetical `docker_helper_newuidmap_t docker_helper_rootlesskit_t:file
# { write }` grant BEFORE it is considered for the production policy. This
# script must never: modify the repository's production policy (the module
# is compiled HERE from the transferred candidate sources and loaded on
# this disposable VM only), grant the file write, grant capabilities, or
# modify file contents. Every finding lands in the evidence directory; the
# run is PASS when all phases completed (not when a particular answer is
# obtained — a negative IS a finding).
#
#   A  toolchain + module: compile and load the CANDIDATE policy
#      (transferred docker-helper.te/.fc) plus a GUEST-ONLY diag module
#      that allows systemd transient units to bind docker_helper_rootlesskit_t
#      via SELinuxContext= (init_t transition; production binds the domain
#      only through the builder unit + the pointed exec transition). Distros
#      tooling (checkpolicy/container-selinux) installed by zypper.
#   B  real-domain observation: with the four builder-family domains
#      PERMISSIVE (so the real rootlesskit flow runs through the mapping
#      step), a transient unit launches the REAL distro rootlesskit with the
#      REAL distro newuidmap mapping and a long-lived target; the watcher
#      captures the full /proc/<pid> file surface of the REAL
#      docker_helper_rootlesskit_t processes (uid_map, gid_map, setgroups,
#      mem, oom_score_adj, comm and the complete enumeration) with labels,
#      modes, owners, and contents.
#   C  layer separation: safe open-only checks (no content modification) as
#      the builder identity against the live rootlesskit_t processes, plus a
#      SECOND concurrent instance to demonstrate that one SELinux domain
#      spans all concurrent operations (their isolation is invocation
#      discipline, not MAC, not DAC, not kernel CAP).
#   D  item-5 mechanism demo: a short-lived flow whose child is SIGSTOPped
#      by the watcher at first sighting, so the helper's uid_map write lands
#      in a frozen process and is read at leisure — the reliable capture
#      mechanism for the next enforcing run, replacing the 50 ms sampling.
#
set -Eeuo pipefail

PREFIX='[release-2.4-p5s2-uidmap-scope-diag-tw]'
EVIDENCE_DIR=/tmp/release-2.4-p5s2-uidmap-scope-diag-evidence
DIAG_BASE=/tmp/uidmap-scope-diag
BUILDER_USER=docker-helper-builder
BUILDER_SUBUID_START=231072
BUILDER_SUBUID_COUNT=65536
TRANSFERRED=/tmp/p5s2-uidmap-diag

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
  for u in uidmap-diag-rk1 uidmap-diag-rk2 uidmap-diag-rk3; do
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
  echo "=== install policy toolchain ==="
} >"$EVIDENCE_DIR/a-toolchain.txt" 2>&1
zypper --non-interactive install -y checkpolicy container-selinux policycoreutils-python-utils \
  >"$EVIDENCE_DIR/zypper-policy-toolchain.log" 2>&1 \
  || note "zypper install of the policy toolchain failed (see zypper-policy-toolchain.log)"
for t in checkmodule semodule_package semodule semanage restorecon; do
  command -v "$t" >/dev/null 2>&1 || { echo "$t not found" >>"$EVIDENCE_DIR/a-toolchain.txt"; fail_toolchain=1; }
done
if [ "${fail_toolchain:-0}" = 1 ]; then
  note "policy toolchain incomplete; the assessment cannot proceed"
  printf '%s P5S2-UIDMAP-SCOPE-DIAG-RESULT=PASS-INCOMPLETE (toolchain unavailable; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi

checkmodule -M -m -o /tmp/docker_helper.tmp "$TRANSFERRED/docker-helper.te" 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "checkmodule failed"; cat "$EVIDENCE_DIR/a-toolchain.txt" >&2; exit 1; }
semodule_package -o /tmp/docker_helper.pp -m /tmp/docker_helper.tmp -f "$TRANSFERRED/docker-helper.fc" 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "semodule_package failed"; exit 1; }
semodule -i /tmp/docker_helper.pp 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "semodule -i of the candidate module failed"; exit 1; }

# GUEST-ONLY diag module: lets systemd transient units bind the helper
# domains through SELinuxContext=. Production binds docker_helper_rootlesskit_t
# ONLY through the builder unit's pointed exec transition; this module exists
# solely on the disposable VM for the isolated diagnostic runs.
cat > /tmp/uidmap-diag.te <<'EOF'
module docker_helper_uidmap_diag 1.0;
require {
	type init_t;
	type docker_helper_rootlesskit_t;
	class process { transition siginh };
}
allow init_t docker_helper_rootlesskit_t:process { transition siginh };
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

# The watcher: continuously records every process observed in
# docker_helper_rootlesskit_t — labels, modes, owners, contents, the full
# /proc/<pid> file enumeration, and the status identity lines. Writes one
# block per pid, deduplicated, bounded by the given budget in seconds.
WATCHER_STOP=false
watcher_loop() {
  local budget="$1" out="$2" deadline seen_pids pid f
  deadline=$(( $(date +%s) + budget ))
  : > "$out"
  seen_pids=$(mktemp)
  while [ "$WATCHER_STOP" = false ] && [ "$(date +%s)" -lt "$deadline" ]; do
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

log 'B: real-domain observation (four builder-family domains permissive)'
for d in "${DOMAINS[@]}"; do
  set_permissive "$d"
done
mkdir -p "$DIAG_BASE"/{rk1,rk2,rk3}
chown "$BUILDER_USER:$BUILDER_USER" "$DIAG_BASE"/{rk1,rk2,rk3}
AVC_EPOCH="$(date +%s)"

(
  while [ "$(date +%s)" -lt $((AVC_EPOCH + 240)) ]; do
    for pid in $(pgrep -f rootlesskit 2>/dev/null || true); do
      [ -r "/proc/$pid/attr/current" ] || continue
      ctx="$(cat "/proc/$pid/attr/current" 2>/dev/null || true)"
      case "$ctx" in *docker_helper_rootlesskit_t*) ;;
        *) continue ;;
      esac
      ppid="$(awk '/^PPid:/{print $2}' "/proc/$pid/status" 2>/dev/null || true)"
      case "$ppid" in
        ''|*[!0-9]*) continue ;;
      esac
      [ -r "/proc/$ppid/attr/current" ] || continue
      pctx="$(cat "/proc/$ppid/attr/current" 2>/dev/null || true)"
      case "$pctx" in *docker_helper_rootlesskit_t*) ;;
        *) continue ;;
      esac
      # The child: SIGSTOP it at first sighting so the flow's uid_map write
      # lands in a frozen process (item-5 mechanism demo).
      kill -STOP "$pid" 2>/dev/null || true
      echo "stopped child pid=$pid (parent=$ppid) at $(date -u +%FT%TZ)" \
        > "$EVIDENCE_DIR/d-sigstop-demo.txt"
      exit 0
    done
    sleep 0.005
  done
) &
STOPPER_PID=$!

systemd-run --unit=uidmap-diag-rk3 \
  --property=SELinuxContext=system_u:system_r:docker_helper_rootlesskit_t:s0 \
  --uid="$BUILDER_USER" --gid="$BUILDER_USER" \
  /usr/bin/rootlesskit --net=none --state-dir="$DIAG_BASE/rk3/rootlesskit-state" \
  /bin/false >/dev/null 2>&1 || true
wait "$STOPPER_PID" 2>/dev/null || true
sleep 1
{
  echo "=== the stopped child's identity and state ==="
  for pid in $(pgrep -f rootlesskit 2>/dev/null || true); do
    [ -r "/proc/$pid/attr/current" ] || continue
    ctx="$(cat "/proc/$pid/attr/current" 2>/dev/null || true)"
    case "$ctx" in *docker_helper_rootlesskit_t*) ;; *) continue ;; esac
    st="$(awk '/^State:/{print $2, $3}' "/proc/$pid/status" 2>/dev/null || true)"
    echo "pid=$pid state=[$st] ctx=$ctx"
    echo "  uid_map content: [$(cat "/proc/$pid/uid_map" 2>/dev/null || true)]"
    echo "  uid_map label:   $(stat -c '%C mode=%a owner=%U:%G' "/proc/$pid/uid_map" 2>&1)"
  done
} >> "$EVIDENCE_DIR/d-sigstop-demo.txt" 2>&1
# SIGKILL the stopped child + parent first (a stopped process ignores
# SIGTERM and would stall the unit stop for TimeoutStopSec).
pkill -KILL -f 'rootlesskit --net=none' 2>/dev/null || true
systemctl stop uidmap-diag-rk3 >/dev/null 2>&1 || true
cat "$EVIDENCE_DIR/d-sigstop-demo.txt" >&2

log 'C: two concurrent real-domain instances + layer separation'
for u in rk1 rk2; do
  systemd-run --unit="uidmap-diag-$u" \
    --property=SELinuxContext=system_u:system_r:docker_helper_rootlesskit_t:s0 \
    --uid="$BUILDER_USER" --gid="$BUILDER_USER" \
    /usr/bin/rootlesskit --net=none --state-dir="$DIAG_BASE/$u/rootlesskit-state" \
    /bin/sleep 300 >/dev/null 2>&1 || true
done

watcher_loop 90 "$EVIDENCE_DIR/b-real-domain-processes.txt" &
WATCHER_PID=$!
wait "$WATCHER_PID" 2>/dev/null || true
cat "$EVIDENCE_DIR/b-real-domain-processes.txt" >&2

sleep 1
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
    echo "=== pids checked: $PIDS (all live rootlesskit_t processes: parents and children across instances) ==="
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
  journalctl -k --since "@$AVC_EPOCH" --no-pager 2>/dev/null | grep -a 'avc:' | tail -80 || true
} > "$EVIDENCE_DIR/e-permissive-avc-harvest.txt" 2>&1

log 'cleanup'
for u in uidmap-diag-rk1 uidmap-diag-rk2; do
  systemctl stop "$u" >/dev/null 2>&1 || true
done
pkill -f 'rootlesskit --net=none' 2>/dev/null || true
for d in "${DOMAINS[@]}"; do
  clear_permissive "$d"
done

printf '%s P5S2-UIDMAP-SCOPE-DIAG-RESULT=PASS (assessment completed; findings are in the evidence)\n' "$PREFIX" >&2
exit 0
