#!/usr/bin/env bash
#
# Guest-side P5-S2 gid_map/uid_map write-grant scope assessment for
# openSUSE Tumbleweed. INVESTIGATION ONLY — establishes the ACTUAL object
# surface of a hypothetical `docker_helper_newgidmap_t
# docker_helper_rootlesskit_t:file { write }` grant (and re-checks the
# ALREADY-GRANTED `docker_helper_newuidmap_t ...:file { write open }`
# against the same objects) BEFORE it is considered for the production
# policy. This script must never: modify the repository's production
# policy (the module is compiled HERE from the transferred candidate
# sources and loaded on this disposable VM only), grant the file write in
# the PRODUCTION module, grant capabilities, or modify any file's
# content. Every finding lands in the evidence directory; the run is PASS
# when all phases completed (not when a particular answer is obtained — a
# negative IS a finding).
#
#   A  toolchain + module: compile and load the CANDIDATE policy
#      (transferred docker-helper.te/.fc) plus GUEST-ONLY diag modules:
#      (a) the transient-unit bridge that lets systemd bind
#      docker_helper_rootlesskit_t via SELinuxContext=; (b) the probe
#      bridge that lets a STATIC probe binary serve as an entrypoint for
#      the two map-helper domains (runcon) and write the probe's results
#      through an inherited descriptor. The probe binary performs
#      OPEN-ONLY access checks (O_RDWR then close; no write(2) call
#      exists in its source). Distro tooling (checkpolicy, gcc,
#      container-selinux/policycoreutils-python-utils) and the DISTRO
#      rootlesskit/slirp4netns/audit packages installed by zypper (absent
#      from the fresh cloud image; plain distro packages, no privilege
#      change). Audit-channel sanity probe.
#   B  real-domain observation: with the five builder-family domains
#      PERMISSIVE (so the real rootlesskit flow runs through the mapping
#      step), instance rk1 runs the REAL distro rootlesskit with the REAL
#      distro newuidmap/newgidmap mapping via runcon into
#      docker_helper_rootlesskit_t; a SIGSTOP watcher freezes the child
#      process at first sighting so the helpers' map writes land in a
#      frozen process; the watcher records the full /proc/<pid> file
#      surface of every REAL docker_helper_rootlesskit_t process (uid_map,
#      gid_map, setgroups, mem, oom_score_adj, comm and the complete
#      enumeration) with labels, modes, owners, and contents, ATTRIBUTED
#      to its instance via the --state-dir token.
#   C  second concurrent instance (transient unit path) + per-operation
#      fact sheets: instance rk2 runs the same flow; both instances stay
#      simultaneously alive (the children frozen for a stable window);
#      each operation gets its own fact sheet (pids, user namespaces,
#      SELinux contexts, the actual labels of uid_map/gid_map/mem and the
#      map contents) so own and neighbor processes are never confused;
#      safe open-only checks as the builder identity against ALL live
#      rootlesskit_t processes of both instances demonstrate that one
#      SELinux domain spans all concurrent operations (their isolation is
#      invocation discipline, not MAC, not DAC, not kernel CAP).
#   D  hypothesized-grant scope: the probe battery runs as
#      docker_helper_newgidmap_t WITHOUT the file grant (control: every
#      write-open denied), as docker_helper_newuidmap_t (the PRODUCTION
#      file grant's real surface: the same opens ALLOWED, own and
#      neighbor alike), and again as docker_helper_newgidmap_t with a
#      GUEST-ONLY diag module carrying exactly the hypothesized
#      `{ write }` grant (removed afterwards; the production module is
#      never modified). The SELinux verdict, DAC, and the additional
#      kernel checks (ptrace for mem, capabilities for the actual map
#      write) are separated by comparing the same battery under the three
#      identities and the AVC windows.
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
NGID_EXEC_T=system_u:system_r:docker_helper_newgidmap_t:s0
NUID_EXEC_T=system_u:system_r:docker_helper_newuidmap_t:s0

log()  { printf '%s %s\n' "$PREFIX" "$*"; }
note() { printf '%s NOTE: %s\n' "$PREFIX" "$*"; }

rm -rf "$EVIDENCE_DIR" "$DIAG_BASE"
mkdir -p "$EVIDENCE_DIR" "$DIAG_BASE"

DOMAINS=(docker_helper_builder_t docker_helper_rootlesskit_t docker_helper_slirp4netns_t docker_helper_newuidmap_t docker_helper_newgidmap_t)
set_permissive() { semanage permissive -a "$1" >/dev/null 2>&1 || true; }
clear_permissive() { semanage permissive -d "$1" >/dev/null 2>&1 || true; }

# shellcheck disable=SC2329
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
  semodule -r docker_helper_gidmap_write_diag >/dev/null 2>&1 || true
  semodule -r gidmap_write_diag >/dev/null 2>&1 || true
  semodule -r gidmap_probe_diag >/dev/null 2>&1 || true
  semodule -r docker_helper_uidmap_diag >/dev/null 2>&1 || true
  semodule -r docker_helper >/dev/null 2>&1 || true
}
trap cleanup EXIT

log 'A: toolchain + candidate module load (disposable VM only)'
{
  echo "=== distro ==="
  grep PRETTY_NAME /etc/os-release 2>/dev/null || true
  echo "=== zypper repositories reachable (a repo outage is a transient guest finding) ==="
  zypper repos 2>/dev/null | head -5 || true
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
# proof installs it for the same reason). gcc + glibc-static build the
# STATIC probe binary whose access checks must run inside the map-helper
# domains without depending on the base policy's library-read behavior.
zypper --non-interactive install -y checkpolicy container-selinux \
  policycoreutils-python-utils rootlesskit slirp4netns audit gcc glibc-static \
  >"$EVIDENCE_DIR/zypper-policy-toolchain.log" 2>&1 \
  || note "zypper install of the policy toolchain failed (see zypper-policy-toolchain.log)"
fail_toolchain=0
for t in checkmodule semodule_package semodule semanage restorecon gcc; do
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

restorecon /usr/bin/rootlesskit /usr/bin/slirp4netns /usr/bin/newuidmap /usr/bin/newgidmap 2>>"$EVIDENCE_DIR/a-toolchain.txt" || true
{
  echo "=== loaded modules ==="
  semodule -l 2>/dev/null | grep -E 'docker_helper|container' || true
  echo "=== binary labels ==="
  for p in /usr/bin/rootlesskit /usr/bin/slirp4netns /usr/bin/newuidmap /usr/bin/newgidmap; do
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

# The STATIC probe vehicle: performs open-only (O_RDONLY/O_WRONLY + close,
# no write(2) exists in the source) access checks against /proc/<pid>
# files. A static binary is required because a runcon'd interpreter would
# depend on the base policy's library-read behavior for the helper
# domains; the probe needs no runtime at all. It is built on the ROOT
# filesystem (/usr/local/bin): a domain-transition entrypoint on a NOSUID
# filesystem (the /tmp default) is refused by the kernel's
# process2:nosuid_transition check, while the production helpers live on
# / — the probe mirrors that placement. Its DEDICATED label is applied at
# CREATION time via a name-based type transition (see the diag module
# below): relabeling an existing file's security.selinux xattr is refused
# by the VM's integrity layer (observed twice: chcon fails with EACCES
# and NO SELinux AVC — the xattr change never reaches the SELinux
# decision), so the label must exist from the file's birth and the
# harness verifies it after the build.
mkdir -p /usr/local/bin "$DIAG_BASE/probe"
cat > "$DIAG_BASE/probe/map-probe.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
static const char *files[] = {"uid_map", "gid_map", "setgroups", "mem", "oom_score_adj", "comm", 0};
int main(int argc, char **argv) {
  int i, j, fd;
  char path[256];
  for (i = 1; i < argc; i++) {
    for (j = 0; files[j]; j++) {
      snprintf(path, sizeof path, "/proc/%s/%s", argv[i], files[j]);
      errno = 0;
      fd = open(path, O_RDONLY);
      if (fd >= 0) {
        printf("OPEN-RDONLY-OK pid=%s file=%s\n", argv[i], files[j]);
        close(fd);
      } else {
        printf("OPEN-RDONLY-FAILED pid=%s file=%s errno=%d (%s)\n", argv[i], files[j], errno, strerror(errno));
      }
      errno = 0;
      fd = open(path, O_WRONLY);
      if (fd >= 0) {
        printf("OPEN-WRONLY-OK pid=%s file=%s\n", argv[i], files[j]);
        close(fd);
      } else {
        printf("OPEN-WRONLY-FAILED pid=%s file=%s errno=%d (%s)\n", argv[i], files[j], errno, strerror(errno));
      }
      fflush(stdout);
    }
  }
  return 0;
}
EOF
# The probe's dedicated label must exist from the file's birth (relabeling
# an existing file's security.selinux xattr is refused by the VM's
# integrity layer with NO SELinux AVC — observed), so the GUEST-ONLY
# checker module is loaded BEFORE the build: it declares the dedicated
# type and a name-based type transition that labels the created
# 'map-probe' directly. The entry grants mirror the production entry
# shape exactly ({ entrypoint read open execute getattr map }). The
# file-write grant toward docker_helper_rootlesskit_t is deliberately NOT
# here — it is the HYPOTHESIZED grant and loads as a separate module
# below.
RUNNER_CTX="$(cat /proc/self/attr/current 2>/dev/null || true)"
RUNNER_T="$(printf '%s' "$RUNNER_CTX" | cut -d: -f3)"
OUT_LABEL="$(stat -c '%C' "$EVIDENCE_DIR/zypper-policy-toolchain.log" 2>/dev/null || true)"
OUT_T="$(printf '%s' "$OUT_LABEL" | cut -d: -f3)"
BINDIR_T_LABEL="$(stat -c '%C' /usr/local/bin 2>/dev/null || true)"
BINDIR_T="$(printf '%s' "$BINDIR_T_LABEL" | cut -d: -f3)"
case "${RUNNER_T:-x}" in ''|*[!A-Za-z0-9_]*|x) note "the runner domain could not be observed (context: $RUNNER_CTX)"; exit 1 ;; esac
case "${OUT_T:-x}" in ''|*[!A-Za-z0-9_]*|x) note "the evidence-file type could not be observed (label: $OUT_LABEL)"; exit 1 ;; esac
case "${BINDIR_T:-x}" in ''|*[!A-Za-z0-9_]*|x) note "the /usr/local/bin directory type could not be observed (label: $BINDIR_T_LABEL)"; exit 1 ;; esac
{
  echo "=== static probe vehicle ==="
  echo "runner context: $RUNNER_CTX (type $RUNNER_T)"
  echo "evidence-file type: $OUT_T (from: $OUT_LABEL)"
  echo "/usr/local/bin dir: $BINDIR_T_LABEL (type $BINDIR_T; the creation type-transition target)"
  echo "probe source (open-only; no write(2) call):"
  cat "$DIAG_BASE/probe/map-probe.c"
} > "$EVIDENCE_DIR/d-map-probe-vehicle.txt" 2>&1
cat > /tmp/gidmap_probe_diag.te <<EOF
module gidmap_probe_diag 1.0;
require {
	type docker_helper_newgidmap_t;
	type docker_helper_newuidmap_t;
	type $OUT_T;
	type $RUNNER_T;
	type $BINDIR_T;
	attribute file_type;
	class file { entrypoint read open execute getattr map append write create relabelto relabelfrom };
}
type gidmap_probe_exec_t;
typeattribute gidmap_probe_exec_t file_type;
allow docker_helper_newgidmap_t gidmap_probe_exec_t:file { entrypoint read open execute getattr map };
allow docker_helper_newuidmap_t gidmap_probe_exec_t:file { entrypoint read open execute getattr map };
allow docker_helper_newgidmap_t $OUT_T:file { append write };
allow docker_helper_newuidmap_t $OUT_T:file { append write };
allow $RUNNER_T gidmap_probe_exec_t:file { create open write append setattr relabelto };
type_transition $RUNNER_T $BINDIR_T:file gidmap_probe_exec_t map-probe;
EOF
cp /tmp/gidmap_probe_diag.te "$EVIDENCE_DIR/d-diag-modules.te"
checkmodule -M -m -o /tmp/gidmap_probe_diag.tmp /tmp/gidmap_probe_diag.te 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "the checker diag module failed to compile (see d-diag-modules.te)"; exit 1; }
semodule_package -o /tmp/gidmap_probe_diag.pp -m /tmp/gidmap_probe_diag.tmp 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "the checker diag module failed to package"; exit 1; }
semodule -i /tmp/gidmap_probe_diag.pp 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "the checker diag module failed to load"; exit 1; }
log "checker diag module loaded (the dedicated probe type carries the production entry shape in both map-helper domains)"
{
  echo "=== build (after the diag module load: the creation type-transition labels the probe) ==="
  gcc -static -O2 -o /usr/local/bin/map-probe "$DIAG_BASE/probe/map-probe.c" 2>&1 && echo "build OK"
  echo "probe label (post-build): $(stat -c '%C' /usr/local/bin/map-probe 2>&1)"
  echo "probe fs: $(stat -c '%m' /usr/local/bin/map-probe 2>&1)"
} >> "$EVIDENCE_DIR/d-map-probe-vehicle.txt" 2>&1
if [ ! -x /usr/local/bin/map-probe ]; then
  note "the static probe binary could not be built (see d-map-probe-vehicle.txt); the hypothesized-grant stage cannot run"
  printf '%s P5S2-UIDMAP-SCOPE-DIAG-RESULT=PASS-INCOMPLETE (probe vehicle unavailable; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi
PROBE_POST_LABEL="$(stat -c '%C' /usr/local/bin/map-probe 2>/dev/null || true)"
case "$PROBE_POST_LABEL" in
  *gidmap_probe_exec_t*) ;;
  *)
    note "the probe binary does not carry the dedicated diag type (label: $PROBE_POST_LABEL); the probe stage cannot run"
    printf '%s P5S2-UIDMAP-SCOPE-DIAG-RESULT=PASS-INCOMPLETE (probe vehicle mislabeled; recorded as a finding)\n' "$PREFIX" >&2
    exit 0
    ;;
esac

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

# instance_of PID: attribute a rootlesskit_t process to its diagnostic
# instance (rk1/rk2) via the --state-dir token in its OWN cmdline or the
# nearest ancestor's, so own and neighbor processes are never confused.
instance_of() {
  local pid="$1" i up
  for i in 1 2; do
    if tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | grep -q "state-dir=$DIAG_BASE/rk$i/"; then
      echo "rk$i"; return
    fi
  done
  up="$(awk '/^PPid:/{print $2}' "/proc/$pid/status" 2>/dev/null || true)"
  for _ in 1 2 3 4; do
    case "$up" in ''|*[!0-9]*|0) break ;; esac
    for i in 1 2; do
      if tr '\0' '\n' < "/proc/$up/cmdline" 2>/dev/null | grep -q "state-dir=$DIAG_BASE/rk$i/"; then
        echo "rk$i"; return
      fi
    done
    up="$(awk '/^PPid:/{print $2}' "/proc/$up/status" 2>/dev/null || true)"
  done
  echo "unknown"
}

# The watcher: continuously records every process observed in
# docker_helper_rootlesskit_t — labels, modes, owners, contents, the full
# /proc/<pid> file enumeration, the status identity lines, and the
# instance attribution. Writes one block per pid, deduplicated, bounded by
# the given budget in seconds.
watcher_loop() {
  local budget="$1" out="$2" deadline seen_pids pid f inst
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
      inst="$(instance_of "$pid")"
      {
        echo "=== rootlesskit_t process pid=$pid instance=$inst (observed $(date -u +%FT%TZ)) ==="
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

# The SIGSTOP step: freezes the FIRST rootlesskit_t CHILD process (its
# parent is itself a rootlesskit_t process) that is not already frozen
# (state T), so the helpers' map writes land in a frozen process and are
# read at leisure (the reliable capture mechanism — no dependence on the
# short-lived helpers' lifetime). Used both as a 5 ms poller for the first
# instance and synchronously after the second instance's launch.
stop_unstopped_children() {
  local pid ctx ppid pctx st
  for pid in $(pgrep -f rootlesskit 2>/dev/null || true); do
    [ -r "/proc/$pid/attr/current" ] || continue
    ctx="$(cat "/proc/$pid/attr/current" 2>/dev/null || true)"
    case "$ctx" in *docker_helper_rootlesskit_t*) ;; *) continue ;; esac
    st="$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)"
    [ "$st" = "T" ] && continue
    ppid="$(awk '/^PPid:/{print $2}' "/proc/$pid/status" 2>/dev/null || true)"
    case "$ppid" in
      ''|*[!0-9]*) continue ;;
    esac
    [ -r "/proc/$ppid/attr/current" ] || continue
    pctx="$(cat "/proc/$ppid/attr/current" 2>/dev/null || true)"
    case "$pctx" in *docker_helper_rootlesskit_t*) ;; *) continue ;; esac
    kill -STOP "$pid" 2>/dev/null || true
    echo "stopped child pid=$pid (parent=$ppid) at $(date -u +%FT%TZ)" \
      >> "$EVIDENCE_DIR/b-sigstop-demo.txt"
    return 0
  done
  return 1
}

(
  local_deadline=$(( $(date +%s) + 60 ))
  while [ "$(date +%s)" -lt "$local_deadline" ]; do
    if stop_unstopped_children; then exit 0; fi
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

log 'C: second concurrent instance (transient unit path) + per-operation facts'
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
# Freeze the rk2 child too (rk1's is already frozen): a stable observation
# window for the fact sheets and the probe batteries.
stop_unstopped_children >/dev/null 2>&1 || true
sleep 1

# All live rootlesskit_t processes at this point (both instances). The
# collection happens BEFORE any teardown — the earlier harness killed the
# diagnostic processes before this point, so the layer-separation checks
# never saw live processes (the race this version fixes).
CHILDS=()
for pid in $(pgrep -f rootlesskit 2>/dev/null || true); do
  [ -r "/proc/$pid/attr/current" ] || continue
  ctx="$(cat "/proc/$pid/attr/current" 2>/dev/null || true)"
  case "$ctx" in *docker_helper_rootlesskit_t*) ;; *) continue ;; esac
  CHILDS+=("$pid")
done
log "live rootlesskit_t processes at layer-separation time: ${CHILDS[*]:-none}"

# Per-operation fact sheets (item 2): every live rootlesskit_t process
# grouped by its instance, never mixing own and neighbor observations.
{
  echo "=== per-operation fact sheets (each live rootlesskit_t process attributed via the --state-dir token) ==="
  for inst in rk1 rk2; do
    echo "--- instance $inst ---"
    for pid in "${CHILDS[@]}"; do
      [ "$(instance_of "$pid")" = "$inst" ] || continue
      echo "pid=$pid comm=$(cat "/proc/$pid/comm" 2>/dev/null || true) ctx=$(cat "/proc/$pid/attr/current" 2>/dev/null || true)"
      echo "  ns/user: $(readlink "/proc/$pid/ns/user" 2>/dev/null || echo UNAVAILABLE)"
      grep -E '^(Uid|Gid|PPid|CapEff)' "/proc/$pid/status" 2>/dev/null | sed 's/^/  /' || true
      for f in uid_map gid_map setgroups mem; do
        echo "  $f: $(stat -c '%C mode=%a owner=%U:%G' "/proc/$pid/$f" 2>&1)"
      done
      for f in uid_map gid_map setgroups; do
        echo "  $f content: [$(cat "/proc/$pid/$f" 2>/dev/null || true)]"
      done
    done
  done
  echo "--- neighbor-label comparison (the two mapped children) ---"
  for pid in "${CHILDS[@]}"; do
    [ "$(instance_of "$pid")" = unknown ] && continue
    echo "pid=$pid instance=$(instance_of "$pid") gid_map=$(stat -c '%C' "/proc/$pid/gid_map" 2>&1) uid_map=$(stat -c '%C' "/proc/$pid/uid_map" 2>&1) mem=$(stat -c '%C' "/proc/$pid/mem" 2>&1)"
  done
} > "$EVIDENCE_DIR/b-operation-facts.txt" 2>&1
cat "$EVIDENCE_DIR/b-operation-facts.txt" >&2

if [ "${#CHILDS[@]}" -ge 1 ]; then
  PIDS="${CHILDS[*]}"
  {
    echo "=== safe open-only checks as $BUILDER_USER (the same static probe; O_RDONLY and O_WRONLY, no write performed, no content change) ==="
    echo "=== layer meaning: DAC (same uid) + kernel open policy; SELinux is NOT in this path (unconfined runner) ==="
    echo "=== pids checked: $PIDS (all live rootlesskit_t processes: parents and children across BOTH instances) ==="
    su -s /bin/bash "$BUILDER_USER" -c "/usr/local/bin/map-probe $PIDS" 2>&1 || true
  } > "$EVIDENCE_DIR/c-open-checks-dac-kernel.txt"
  cat "$EVIDENCE_DIR/c-open-checks-dac-kernel.txt" >&2
else
  note "no live rootlesskit_t processes for the open checks (recorded as a finding)"
  echo "no live rootlesskit_t processes" > "$EVIDENCE_DIR/c-open-checks-dac-kernel.txt"
fi

# Harvest helper: the AVC records of a window (audit log + kernel journal).
harvest_avcs_since() {
  local since="$1" out="$2"
  {
    echo "=== kernel AVC records since epoch $since ==="
    grep -a 'type=AVC' /var/log/audit/audit.log 2>/dev/null \
      | awk -v s="$since" '{ for (i = 1; i <= NF; i++) if ($i ~ /^msg=audit\(/) { ts = substr($i, 11); split(ts, t, "."); if (t[1] + 0 >= s + 0) print; break } }' \
      | tail -100 || true
    echo "=== journalctl -k window ==="
    journalctl -k --since "@$since" --no-pager 2>/dev/null | grep -a 'avc:' | tail -100 || true
  } > "$out" 2>&1
}

log 'D: hypothesized-grant scope (open-only probes as the map-helper domains)'
if [ "${#CHILDS[@]}" -ge 1 ]; then
  PIDS="${CHILDS[*]}"

  # The probe batteries need the map-helper domains ENFORCING (the real
  # SELinux decisions); they were made permissive for the real-flow phases.
  # Re-enforce both before the batteries; the flows are complete by now
  # (both children frozen) and the cleanup clears the rest.
  clear_permissive docker_helper_newuidmap_t
  clear_permissive docker_helper_newgidmap_t
  log "the map-helper domains re-enforced for the probe batteries"

  # (1) CONTROL: newgidmap_t with its PRODUCTION surface only (enforcing):
  # every open on the rootlesskit_t files must be DENIED (no file grant).
  CTRL_EPOCH="$(date +%s)"
  {
    echo "=== CONTROL battery: docker_helper_newgidmap_t WITHOUT the file grant (enforcing; production surface only) ==="
  } > "$EVIDENCE_DIR/d-scope-control-newgidmap.txt"
  runcon "$NGID_EXEC_T" /usr/local/bin/map-probe "${CHILDS[@]}" \
    >>"$EVIDENCE_DIR/d-scope-control-newgidmap.txt" 2>&1 || true
  sleep 2
  harvest_avcs_since "$CTRL_EPOCH" "$EVIDENCE_DIR/d-scope-control-newgidmap-avcs.txt"
  cat "$EVIDENCE_DIR/d-scope-control-newgidmap.txt" >&2
  if ! grep -aq 'OPEN-' "$EVIDENCE_DIR/d-scope-control-newgidmap.txt"; then
    note "the control battery produced no probe lines (the probe vehicle failed to run; see d-scope-control-newgidmap-avcs.txt)"
  fi

  # (2) EXISTING GRANT: newuidmap_t with its PRODUCTION file grant
  # ({ write open }): the same battery shows the authority that ALREADY
  # exists (own and neighbor alike) — never a new grant.
  NUID_EPOCH="$(date +%s)"
  {
    echo "=== EXISTING-GRANT battery: docker_helper_newuidmap_t with the production rootlesskit_t:file { write open } (enforcing) ==="
  } > "$EVIDENCE_DIR/d-scope-newuidmap.txt"
  runcon "$NUID_EXEC_T" /usr/local/bin/map-probe "${CHILDS[@]}" \
    >>"$EVIDENCE_DIR/d-scope-newuidmap.txt" 2>&1 || true
  sleep 2
  harvest_avcs_since "$NUID_EPOCH" "$EVIDENCE_DIR/d-scope-newuidmap-avcs.txt"
  cat "$EVIDENCE_DIR/d-scope-newuidmap.txt" >&2

  # (3) HYPOTHESIZED: newgidmap_t with a GUEST-ONLY diag module carrying
  # exactly `allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:file { write };`.
  # The production module is never modified; the diag module is removed at
  # cleanup and never shipped.
  cat > /tmp/gidmap_write_diag.te <<'EOF'
module gidmap_write_diag 1.0;
require {
	type docker_helper_newgidmap_t;
	type docker_helper_rootlesskit_t;
	class file write;
}
allow docker_helper_newgidmap_t docker_helper_rootlesskit_t:file { write };
EOF
  cat /tmp/gidmap_write_diag.te >> "$EVIDENCE_DIR/d-diag-modules.te"
  checkmodule -M -m -o /tmp/gidmap_write_diag.tmp /tmp/gidmap_write_diag.te 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
    || { note "the hypothesized-grant diag module failed to compile"; exit 1; }
  semodule_package -o /tmp/gidmap_write_diag.pp -m /tmp/gidmap_write_diag.tmp 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
    || { note "the hypothesized-grant diag module failed to package"; exit 1; }
  semodule -i /tmp/gidmap_write_diag.pp 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
    || { note "the hypothesized-grant diag module failed to load"; exit 1; }
  HYPO_EPOCH="$(date +%s)"
  {
    echo "=== HYPOTHESIZED battery: docker_helper_newgidmap_t WITH the guest-only diag { write } grant (enforcing) ==="
  } > "$EVIDENCE_DIR/d-scope-hypo-newgidmap.txt"
  runcon "$NGID_EXEC_T" /usr/local/bin/map-probe "${CHILDS[@]}" \
    >>"$EVIDENCE_DIR/d-scope-hypo-newgidmap.txt" 2>&1 || true
  sleep 2
  harvest_avcs_since "$HYPO_EPOCH" "$EVIDENCE_DIR/d-scope-hypo-newgidmap-avcs.txt"
  cat "$EVIDENCE_DIR/d-scope-hypo-newgidmap.txt" >&2
else
  note "no live rootlesskit_t processes for the probe batteries (recorded as a finding)"
fi

log 'teardown (after the checks: the earlier harness killed the diagnostic processes first and the checks never saw live processes)'
pkill -KILL -f 'rootlesskit --net=none' 2>/dev/null || true
pkill -KILL -f '/bin/sleep 300' 2>/dev/null || true
kill "$RK1_PID" 2>/dev/null || true
wait "$WATCHER_PID" 2>/dev/null || true
cat "$EVIDENCE_DIR/b-real-domain-processes.txt" >&2

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
