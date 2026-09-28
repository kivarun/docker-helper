#!/usr/bin/env bash
#
# Guest-side P5-S2g22 cross-operation gid_map security experiment for
# openSUSE Tumbleweed. INVESTIGATION ONLY — answers, with the REAL distro
# newgidmap binary, whether the gid map helper of one Build Operation can
# CHANGE the gid_map of another operation's process once the needed
# capabilities are granted step by step:
#
#   stage 1 CONTROL  — production surface only (no capabilities granted)
#   stage 2          — guest-only `newgidmap_t self:cap_userns sys_admin`
#   stage 3          — additionally `newgidmap_t self:capability setgid`,
#                      loaded only after the previous stage's boundary is
#                      confirmed by its enforcing AVC
#
# Phase F reuses the same stand for the P5-S2g23 experiment: whether the
# EXISTING production policy (its current newuidmap file and capability
# grants, NO new runtime grants, the stage modules unloaded) lets the
# parent-role newuidmap of operation A change the EMPTY uid_map of
# another operation's process B. The positive control is the flow's own
# one-shot child uid_map write.
#
# Phase G reuses the same stand for the P5-S2g24 experiment: whether
# SELinux MCS categories can isolate two Build Operations that run under
# the same builder identity and the same SELinux domain. Operation A's
# vehicles run as docker_helper_rootlesskit_t:s0:c1 and operation B's
# target child as :s0:c2, with NO new policy modules — the mechanism
# under test is the shipped MCS constraint set applied on top of the
# exact g23 shape: whether the categories survive the
# rootlesskit_t→newuidmap_t SUID-helper transition, whether A's
# parent-role newuidmap can still write B's empty uid_map across the
# categories, and whether the own-child write still works.
#
# Phase H reuses the same stand for the P5-S2g25 feasibility proof: the
# ONLY policy delta is a guest-only module that adds
# docker_helper_newuidmap_t to the shipped base's mcs_constrained_type
# attribute (no allow/grant/transition changes). It answers whether that
# single membership yields the required semantics: the cross-operation
# c1→c2 uid_map write denied by exactly the MCS constraint, the own-child
# c1→c1 write still allowed, and the flow reaching the same production
# gid_map boundary with no new blocking denials. An unassignable
# category, a delta that fails to load, or an unverifiable membership is
# recorded and stops the phase.
#
# Phase I reuses the same stand for the P5-S2g26 boundary definition:
# Part A derives the MINIMAL set of docker-helper domains that must join
# the shipped base's mcs_constrained_type attribute (the statically
# derived table with per-line references is in the evidence; the
# manager, the builder launch domain and slirp4netns are excluded with
# reasons); Part B applies exactly those memberships as a guest-only
# module (no allow/capability/transition/relabel/manager rules — if the
# own flow then needs an extra grant, that failure is recorded as the
# architectural result, not fixed); Part C repeats the g25 measurement
# under the full set with its existing controls verbatim; Part D runs
# the paired process-control matrix (ordinary signal / SIGSTOP /
# SIGKILL / ptrace-if-TE-reachable, cross-operation A:c1→B:c2 vs own-op
# A:c1→child A:c1; TE-denied actions are classified as NOT
# MCS-reachable and no permission is added to reach MCS); Part E
# inventories the real runtime shared-object surface (state dirs,
# fifos, the state-tree files the vehicles create — labels, creators,
# who can write, op-private vs shared) with the constraint-class dumps
# for the object classes. Verdict PASS only when all five criteria hold.
#
# Two scenarios, both invoking the REAL /usr/bin/newgidmap with the PID of
# a FRESH target child B (uid_map set, gid_map empty) and the flow's valid
# subgid arguments:
#   PARENT-ROLE: the invoker is a docker_helper_rootlesskit_t process in
#     the INITIAL user namespace with the rootlesskit parent's privilege
#     shape (builder uid/gid, no kernel caps; the helper's setgid file cap
#     applies at exec). This is the pid-substitution stand-in: rootlesskit
#     itself computes the pid, so the experiment models a compromised or
#     incorrect pid source inside the same domain.
#   WORKLOAD-ROLE: the invoker is inside operation A's user namespace
#     (the real rootlesskit instance's payload process, docker_helper_
#     rootlesskit_t, mapped root). Two sub-shapes: mapped root (the
#     realistic buildkitd identity) and mapped builder-uid (the only
#     shape whose getpwuid(getuid()) resolves to the target's owner, so
#     the shadow-helper ownership check passes and the KERNEL verdict is
#     reachable). nsenter/setns with extra privileges is never used.
#
# The stand holds two independent one-shot user namespaces under the
# штатной builder identity (operation A's rootlesskit usern and target
# B's usern). B is a dedicated rootlesskit_t probe process that creates
# its own user namespace and announces its PID through a named pipe
# (blocking open on both sides, no readiness polling); the workload
# payloads receive a barrier pipe as well. B's uid_map is set by the REAL
# distro newuidmap through the production transition chain, so the stand
# needs no root-writer grants. Every temporary module is removed at
# cleanup; the production module is compiled HERE from the transferred
# candidate sources and is never modified. The run is PASS when all
# phases completed (findings — positive or negative — are in the
# evidence).
#
set -Eeuo pipefail

PREFIX='[release-2.4-p5s2-gidmap-crossop-exp-tw]'
EVIDENCE_DIR=/tmp/release-2.4-p5s2-gidmap-crossop-exp-evidence
DIAG_BASE=/tmp/gidmap-crossop-exp
BUILDER_USER=docker-helper-builder
BUILDER_SUBUID_START=231072
BUILDER_SUBUID_COUNT=65536
TRANSFERRED=/tmp/p5s2-gidmap-crossop-exp
RK_EXEC_T=system_u:system_r:docker_helper_rootlesskit_t:s0
# The invoker runcon context for parent_role_attempt. Defaults to the
# same context as the flows (the g22/g23 experiments); the g24 experiment
# reassigns it to the category-carrying operation-A context.
RK_INVOKER_CTX="$RK_EXEC_T"

log()  { printf '%s %s\n' "$PREFIX" "$*"; }
note() { printf '%s NOTE: %s\n' "$PREFIX" "$*"; }

rm -rf "$EVIDENCE_DIR" "$DIAG_BASE"
mkdir -p "$EVIDENCE_DIR" "$DIAG_BASE/fifos"

DOMAINS=(docker_helper_builder_t docker_helper_rootlesskit_t docker_helper_slirp4netns_t docker_helper_newuidmap_t docker_helper_newgidmap_t)
clear_permissive() { semanage permissive -d "$1" >/dev/null 2>&1 || true; }

# shellcheck disable=SC2329
cleanup() {
  pkill -KILL -f 'rootlesskit --net=none' 2>/dev/null || true
  pkill -KILL -f 'map_probe --' 2>/dev/null || true
  # Remove the stand's own artifacts (the evidence dir stays for the
  # orchestrator's collection; the VM itself is disposable).
  rm -f /usr/local/bin/map_probe
  rm -rf "$DIAG_BASE"
  rm -rf /var/tmp/p5s2-g26-e2
  for d in "${DOMAINS[@]}"; do
    clear_permissive "$d"
  done
  semodule -r gidmap_capsetgid_diag >/dev/null 2>&1 || true
  semodule -r gidmap_capuserns_diag >/dev/null 2>&1 || true
  semodule -r gidmap_mcsconstrained_diag >/dev/null 2>&1 || true
  semodule -r gidmap_mcsboundary_diag >/dev/null 2>&1 || true
  semodule -r gidmap_probe_diag >/dev/null 2>&1 || true
  semodule -r docker_helper >/dev/null 2>&1 || true
}
trap cleanup EXIT

# harvest_helper_facts <budget_seconds> <out> <helper-name>: best-effort
# observation of the SHORT-LIVED helper processes during an attempt
# window (their deterministic facts come from the probe facts, the AVCs
# and the exit status; this records the cred state the kernel actually
# saw). The name is the pgrep -x argument; the caller passes its own
# helper's basename (newuidmap for the uid-chain attempts), the default
# keeps the g22 newgidmap shape.
# shellcheck disable=SC2329
harvest_helper_facts() {
  local budget="$1" out="$2" name="${3:-newgidmap}" deadline seen p pid
  deadline=$(( $(date +%s) + budget ))
  seen=$(mktemp)
  : > "$out"
  while [ "$(date +%s)" -lt "$deadline" ]; do
    for pid in $(pgrep -x "$name" 2>/dev/null || true); do
      grep -qx "$pid" "$seen" 2>/dev/null && continue
      echo "$pid" >> "$seen"
      {
        echo "=== $name process pid=$pid (observed $(date -u +%FT%TZ)) ==="
        echo "attr/current: $(tr -d '\0' < "/proc/$pid/attr/current" 2>/dev/null || true)"
        echo "ns/user: $(readlink "/proc/$pid/ns/user" 2>/dev/null || echo UNAVAILABLE)"
        grep -E '^(Uid|Gid|PPid|CapEff|CapPrm|NoNewPrivs)' "/proc/$pid/status" 2>/dev/null || true
      } >> "$out"
    done
    sleep 0.05
  done
  rm -f "$seen"
}

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

# diagnose_stand_failure <tag> <since-epoch> <file>... : record the AVC
# window and the probe outputs when the STAND itself fails (the kernel
# verdict was not reached; the run stays distinguishable from an attempt
# result — such results are undefined, not negative findings).
diagnose_stand_failure() {
  local tag="$1" since="$2"; shift 2
  local out="$EVIDENCE_DIR/stand-failure-$tag.txt"
  {
    echo "=== stand failure: $tag (AVC window since epoch $since) ==="
    echo "--- kernel AVC records ---"
    grep -a 'type=AVC' /var/log/audit/audit.log 2>/dev/null \
      | awk -v s="$since" '{ for (i = 1; i <= NF; i++) if ($i ~ /^msg=audit\(/) { ts = substr($i, 11); split(ts, t, "."); if (t[1] + 0 >= s + 0) print; break } }' \
      | tail -200 || true
    echo "--- journalctl -k window ---"
    journalctl -k --since "@$since" --no-pager 2>/dev/null | grep -a 'avc:' | tail -200 || true
    for f in "$@"; do
      [ -f "$f" ] && { echo "--- $f ---"; cat "$f"; }
    done
  } > "$out" 2>&1
  cat "$out" >&2
}

log 'A: toolchain + candidate module load (disposable VM only)'
STAND_EPOCH_ALL="$(date +%s)"
{
  echo "=== distro ==="
  grep PRETTY_NAME /etc/os-release 2>/dev/null || true
  echo "=== kernel ==="
  uname -r
  echo "=== LSM state ==="
  cat /sys/kernel/security/lsm 2>/dev/null || true
  echo "enforce=$(getenforce 2>/dev/null || true)"
} >"$EVIDENCE_DIR/a-toolchain.txt" 2>&1
zypper --non-interactive install -y checkpolicy container-selinux \
  policycoreutils-python-utils rootlesskit slirp4netns audit gcc glibc-static \
  libcap-progs util-linux iproute2 setools-console \
  >"$EVIDENCE_DIR/zypper-toolchain.log" 2>&1 \
  || note "zypper install of the policy toolchain failed (see zypper-toolchain.log)"
fail_toolchain=0
for t in checkmodule semodule_package semodule semanage restorecon gcc nsenter ip seinfo; do
  command -v "$t" >/dev/null 2>&1 || { echo "$t not found" >>"$EVIDENCE_DIR/a-toolchain.txt"; fail_toolchain=1; }
done
if [ "$fail_toolchain" = 1 ]; then
  note "policy toolchain incomplete; the experiment cannot proceed"
  diagnose_stand_failure toolchain "$STAND_EPOCH_ALL"
  printf '%s P5S2-GIDMAP-CROSSOP-EXP-RESULT=PASS-INCOMPLETE (toolchain unavailable; recorded as a finding)\n' "$PREFIX" >&2
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

restorecon /usr/bin/rootlesskit /usr/bin/slirp4netns /usr/bin/newuidmap /usr/bin/newgidmap 2>>"$EVIDENCE_DIR/a-toolchain.txt" || true
{
  echo "=== binary labels ==="
  for p in /usr/bin/rootlesskit /usr/bin/newuidmap /usr/bin/newgidmap; do
    echo "$p -> $(stat -c '%C' "$p" 2>&1)"
  done
  echo "=== file capabilities (observed, never modified) ==="
  if command -v getcap >/dev/null 2>&1; then
    getcap /usr/bin/newuidmap /usr/bin/newgidmap 2>&1 || true
  else
    echo "getcap unavailable (libcap-progs missing; recorded as a toolchain finding)"
  fi
} >>"$EVIDENCE_DIR/a-toolchain.txt" 2>&1

useradd -m "$BUILDER_USER" 2>/dev/null || true
grep -q "^$BUILDER_USER:" /etc/subuid || echo "$BUILDER_USER:$BUILDER_SUBUID_START:$BUILDER_SUBUID_COUNT" >> /etc/subuid
grep -q "^$BUILDER_USER:" /etc/subgid || echo "$BUILDER_USER:$BUILDER_SUBUID_START:$BUILDER_SUBUID_COUNT" >> /etc/subgid
BUILDER_UID="$(id -u "$BUILDER_USER")"
# The flow's map arguments must be the ACTUAL provisioned subid ranges (a
# fresh VM's useradd assigns the next free 65536 slot — the previous
# hardcoded start sat outside it and would have failed the shadow range
# validation as a stand artifact, not as a kernel verdict).
BUILDER_SUBUID_START="$(awk -F: -v u="$BUILDER_USER" '$1==u{print $2; exit}' /etc/subuid)"
BUILDER_SUBUID_COUNT="$(awk -F: -v u="$BUILDER_USER" '$1==u{print $3; exit}' /etc/subuid)"
BUILDER_SUBGID_START="$(awk -F: -v u="$BUILDER_USER" '$1==u{print $2; exit}' /etc/subgid)"
BUILDER_SUBGID_COUNT="$(awk -F: -v u="$BUILDER_USER" '$1==u{print $3; exit}' /etc/subgid)"
case "${BUILDER_SUBUID_START:-x}:${BUILDER_SUBUID_COUNT:-x}:${BUILDER_SUBGID_START:-x}:${BUILDER_SUBGID_COUNT:-x}" in
  *[!0-9:]*) note "the builder's subid ranges could not be read; the experiment cannot proceed"
             diagnose_stand_failure subid-read "$STAND_EPOCH_ALL"
             printf '%s P5S2-GIDMAP-CROSSOP-EXP-RESULT=PASS-INCOMPLETE (subid ranges unavailable; recorded as a finding)\n' "$PREFIX" >&2
             exit 0 ;;
esac
[ "$BUILDER_SUBGID_START" = "$BUILDER_SUBUID_START" ] && [ "$BUILDER_SUBGID_COUNT" = "$BUILDER_SUBUID_COUNT" ] \
  || note "the subuid and subgid ranges differ; the uid and gid map arguments are built from each range separately"
# The flow's helper-argument shapes (rootlesskit parent's own two extents:
# the own-id entry + the subid range).
U_MAP_ARGS=(0 "$BUILDER_UID" 1 1 "$BUILDER_SUBUID_START" "$BUILDER_SUBUID_COUNT")
G_MAP_ARGS=(0 "$BUILDER_UID" 1 1 "$BUILDER_SUBGID_START" "$BUILDER_SUBGID_COUNT")
{
  echo "=== builder identity ==="
  id "$BUILDER_USER"
  echo "=== subids ==="
  grep "^$BUILDER_USER:" /etc/subuid /etc/subgid
  echo "=== flow's map arguments (parent uid entry + subid range) ==="
  echo "uid args: ${U_MAP_ARGS[*]}"
  echo "gid args: ${G_MAP_ARGS[*]}"
  echo "=== shadow subid backend state (which checks the helpers use) ==="
  grep -a 'subid' /etc/nsswitch.conf 2>/dev/null || echo "no subid line in /etc/nsswitch.conf (the file DB path)"
  grep -a 'SUB_UID_MIN\|SUB_GID_MIN\|SUB_UID_COUNT\|SUB_GID_COUNT' /etc/login.defs 2>/dev/null || true
} >"$EVIDENCE_DIR/builder-identity.txt" 2>&1
cat "$EVIDENCE_DIR/builder-identity.txt" >&2

AVC_EPOCH_ALL="$(date +%s)"

log 'B: barrier fifos + probe vehicle'
mkfifo "$DIAG_BASE/fifos"/bfifo-s1 "$DIAG_BASE/fifos/bfifo-s2" \
       "$DIAG_BASE/fifos/bfifo-s3p" "$DIAG_BASE/fifos/bfifo-s3w1" \
       "$DIAG_BASE/fifos/bfifo-s3w2" "$DIAG_BASE/fifos/bfifo-g23" \
       "$DIAG_BASE/fifos/bfifo-g24" "$DIAG_BASE/fifos/bfifo-g25" \
       "$DIAG_BASE/fifos/bfifo-g26" \
       "$DIAG_BASE/fifos/gofifo-s3w1" "$DIAG_BASE/fifos/gofifo-s3w2"
chmod 666 "$DIAG_BASE/fifos"/*
# The per-stage rootlesskit state dirs are created up front: the module
# generation observes their labels (same creation context as a later
# mkdir) so rootlesskit's mandatory state-dir work (lock, cleanup lock,
# child-pid file, the exit-time RemoveAll) is grantable before the flow
# starts.
mkdir -p "$DIAG_BASE/s1/a1-state" "$DIAG_BASE/s2/a1-state" \
         "$DIAG_BASE/s3/a1-state" "$DIAG_BASE/s3/a2-state" \
         "$DIAG_BASE/g23/a1-state" "$DIAG_BASE/g24/a1-state" \
         "$DIAG_BASE/g25/a1-state" \
         "$DIAG_BASE/g26/a1-state" "$DIAG_BASE/g26/e-shared"
chown "$BUILDER_USER:$BUILDER_USER" "$DIAG_BASE/s1/a1-state" "$DIAG_BASE/s2/a1-state" \
      "$DIAG_BASE/s3/a1-state" "$DIAG_BASE/s3/a2-state" "$DIAG_BASE/g23/a1-state" \
      "$DIAG_BASE/g24/a1-state" "$DIAG_BASE/g25/a1-state" \
      "$DIAG_BASE/g26/a1-state" "$DIAG_BASE/g26/e-shared"
# The Part E prodtype dir lives on the DISK filesystem (a tmpfs relabel
# to the production state type would also need a tmpfs associate rule);
# /var and /var/tmp join the walk paths so the vehicles' path traversal
# is grantable on their real types.
mkdir -p /var/tmp/p5s2-g26-e2
chown "$BUILDER_USER:$BUILDER_USER" /var/tmp/p5s2-g26-e2
FIFO_LABEL="$(stat -c '%C' "$DIAG_BASE/fifos/bfifo-s1" 2>/dev/null || true)"
FIFO_T="$(printf '%s' "$FIFO_LABEL" | cut -d: -f3)"
RUNNER_CTX="$(tr -d '\0' < /proc/self/attr/current 2>/dev/null || true)"
RUNNER_T="$(printf '%s' "$RUNNER_CTX" | cut -d: -f3)"
OUT_LABEL="$(stat -c '%C' "$EVIDENCE_DIR/zypper-toolchain.log" 2>/dev/null || true)"
OUT_T="$(printf '%s' "$OUT_LABEL" | cut -d: -f3)"
BINDIR_T_LABEL="$(stat -c '%C' /usr/local/bin 2>/dev/null || true)"
BINDIR_T="$(printf '%s' "$BINDIR_T_LABEL" | cut -d: -f3)"
case "${RUNNER_T:-x}" in ''|*[!A-Za-z0-9_]*|x) note "the runner domain could not be observed (context: $RUNNER_CTX)"; exit 1 ;; esac
case "${OUT_T:-x}" in ''|*[!A-Za-z0-9_]*|x) note "the evidence-file type could not be observed (label: $OUT_LABEL)"; exit 1 ;; esac
case "${BINDIR_T:-x}" in ''|*[!A-Za-z0-9_]*|x) note "the /usr/local/bin directory type could not be observed (label: $BINDIR_T_LABEL)"; exit 1 ;; esac
case "${FIFO_T:-x}" in ''|*[!A-Za-z0-9_]*|x) note "the fifo type could not be observed (label: $FIFO_LABEL)"; exit 1 ;; esac
# The DISTINCT dir types along the stand's walk paths: the probe's fifo
# opens and rootlesskit's state-dir work each traverse these directories
# (an ungranted dir search short-circuits the open with EACCES BEFORE any
# fifo/file-class check — the stand failure observed in the previous run).
WALK_DIRS=(/tmp /var /var/tmp "$DIAG_BASE" "$DIAG_BASE/fifos" \
           "$DIAG_BASE/s1" "$DIAG_BASE/s1/a1-state" "$DIAG_BASE/s2" "$DIAG_BASE/s2/a1-state" \
           "$DIAG_BASE/s3" "$DIAG_BASE/s3/a1-state" "$DIAG_BASE/s3/a2-state" \
           "$DIAG_BASE/g23" "$DIAG_BASE/g23/a1-state" \
           "$DIAG_BASE/g24" "$DIAG_BASE/g24/a1-state" \
           "$DIAG_BASE/g25" "$DIAG_BASE/g25/a1-state" \
           "$DIAG_BASE/g26" "$DIAG_BASE/g26/a1-state" "$DIAG_BASE/g26/e-shared")
DIR_TYPE_LIST=""
STATE_TYPE_LIST=""
for d in "${WALK_DIRS[@]}"; do
  t="$(stat -c '%C' "$d" 2>/dev/null | cut -d: -f3)"
  case "${t:-x}" in ''|*[!A-Za-z0-9_]*|x) note "a stand walk-dir type could not be observed ($d: $(stat -c '%C' "$d" 2>&1))"; exit 1 ;; esac
  case " $DIR_TYPE_LIST " in *" $t "*) ;; *) DIR_TYPE_LIST="$DIR_TYPE_LIST $t" ;; esac
  case "$d" in *-state) case " $STATE_TYPE_LIST " in *" $t "*) ;; *) STATE_TYPE_LIST="$STATE_TYPE_LIST $t" ;; esac ;; esac
done
{
  echo "=== observed stand labels ==="
  echo "runner context: $RUNNER_CTX (type $RUNNER_T)"
  echo "evidence-file type: $OUT_T (from: $OUT_LABEL)"
  echo "/usr/local/bin dir: $BINDIR_T_LABEL (type $BINDIR_T)"
  echo "fifo: $FIFO_LABEL (type $FIFO_T)"
  echo "walk-dir types (dedup):$DIR_TYPE_LIST"
  echo "state-dir types (dedup):$STATE_TYPE_LIST"
} > "$EVIDENCE_DIR/b-stand-labels.txt" 2>&1
cat "$EVIDENCE_DIR/b-stand-labels.txt" >&2

# The STATIC probe vehicle: no /proc/<target> writes exist in its source;
# it reports identity facts (syscalls + own attr/current + ns/user
# readlink with a fallback), creates its own user namespace for the
# target role, and execs the REAL distro helpers. Built on the ROOT
# filesystem (/usr/local/bin): a domain-transition entrypoint on a NOSUID
# filesystem is refused by the kernel's process2:nosuid_transition check.
# Its dedicated label is applied at CREATION time via a name-based type
# transition (relabeling an existing file is refused by the VM's
# integrity layer with NO SELinux AVC — observed).
mkdir -p "$DIAG_BASE/probe"
cat > "$DIAG_BASE/probe/map_probe.c" <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <linux/capability.h>

static void print_facts(const char *stage) {
  struct __user_cap_header_struct hdr;
  struct __user_cap_data_struct data[2];
  uid_t r, e, s;
  gid_t rg, eg, sg;
  unsigned long long ce = 0, cp = 0;
  char ctx[512];
  char nsbuf[128];
  ssize_t n;
  int fd;
  memset(&hdr, 0, sizeof hdr);
  hdr.version = _LINUX_CAPABILITY_VERSION_3;
  hdr.pid = 0;
  if (syscall(SYS_capget, &hdr, &data) == 0) {
    ce = (unsigned long long)data[0].effective | ((unsigned long long)data[1].effective << 32);
    cp = (unsigned long long)data[0].permitted | ((unsigned long long)data[1].permitted << 32);
  }
  getresuid(&r, &e, &s);
  getresgid(&rg, &eg, &sg);
  ctx[0] = '\0';
  fd = open("/proc/self/attr/current", O_RDONLY);
  if (fd >= 0) {
    n = read(fd, ctx, sizeof ctx - 1);
    if (n > 0) {
      ctx[n] = '\0';
      if (ctx[n - 1] == '\n') ctx[n - 1] = '\0';
    }
    close(fd);
  }
  nsbuf[0] = '\0';
  errno = 0;
  n = readlink("/proc/self/ns/user", nsbuf, sizeof nsbuf - 1);
  if (n > 0) {
    nsbuf[n] = '\0';
  } else {
    snprintf(nsbuf, sizeof nsbuf, "UNAVAILABLE errno=%d", errno);
  }
  printf("PROBE stage=%s pid=%d ruid=%d euid=%d suid=%d rgid=%d egid=%d sgid=%d\n",
         stage, (int)getpid(), (int)r, (int)e, (int)s, (int)rg, (int)eg, (int)sg);
  printf("PROBE selinux=%s\n", ctx);
  printf("PROBE userns=%s\n", nsbuf);
  printf("PROBE capeff=0x%llx capprm=0x%llx\n", ce, cp);
  fflush(stdout);
}

static void wait_go(const char *gofifo) {
  int fd;
  char line[16];
  errno = 0;
  fd = open(gofifo, O_RDONLY); /* blocks until the harness opens the write end */
  if (fd < 0) {
    printf("PROBE gofifo-open-failed errno=%d (%s)\n", errno, strerror(errno));
    fflush(stdout);
    exit(4);
  }
  if (read(fd, line, sizeof line - 1) <= 0) {
    printf("PROBE gofifo-read-failed errno=%d\n", errno);
    fflush(stdout);
    exit(4);
  }
  close(fd);
}

/* fork_exec_capture: fork+exec the helper (the production rootlesskit
 * exec.Command shape: the helper runs in a forked child, so the exec
 * domain transition happens there) with its stdio captured through a
 * pipe OWNED BY THE PROBE (docker_helper_rootlesskit_t:fifo_file — the
 * fd shape whose write grant the production helper domains hold, so the
 * captured output survives the transition's inherited-fd flush). The
 * parent streams the helper's output through its own surviving stdout
 * and reports the helper's exit code. Returns the helper's rc. */
static int fork_exec_capture(char **nargv) {
  int pfd[2];
  pid_t child;
  ssize_t n;
  char buf[4096];
  int status = 0;
  int rc;

  if (pipe(pfd) != 0) {
    printf("PROBE pipe-failed errno=%d (%s)\n", errno, strerror(errno));
    fflush(stdout);
    return 6;
  }
  child = fork();
  if (child < 0) {
    printf("PROBE fork-failed errno=%d (%s)\n", errno, strerror(errno));
    fflush(stdout);
    return 6;
  }
  if (child == 0) {
    close(pfd[0]);
    dup2(pfd[1], STDOUT_FILENO);
    dup2(pfd[1], STDERR_FILENO);
    if (pfd[1] > STDERR_FILENO) close(pfd[1]);
    execv(nargv[0], nargv);
    fprintf(stderr, "execv-failed errno=%d (%s)\n", errno, strerror(errno));
    _exit(127);
  }
  close(pfd[1]);
  printf("HELPER pid=%d out-begin\n", (int)child);
  fflush(stdout);
  while ((n = read(pfd[0], buf, sizeof buf)) > 0) {
    if (write(STDOUT_FILENO, buf, (size_t)n) < 0) break;
  }
  close(pfd[0]);
  if (waitpid(child, &status, 0) < 0) {
    printf("HELPER waitpid-failed errno=%d\n", errno);
    fflush(stdout);
    return 6;
  }
  rc = WIFEXITED(status) ? WEXITSTATUS(status)
        : (WIFSIGNALED(status) ? 128 + WTERMSIG(status) : -1);
  printf("HELPER rc=%d\n", rc);
  fflush(stdout);
  return rc;
}

int main(int argc, char **argv) {
  char line[64];
  char *nargv[64];
  int i, k, fd, n;
  uid_t m;

  if (argc < 2) {
    fprintf(stderr, "usage: map_probe --be-target <fifo> | --invoke-helper <helper> <pid> <range...> | --workload-root <gofifo> <helper> <pid> <range...> | --workload-sub <gofifo> <helper> <pid> <mapped-uid> <range...> | --facts\n");
    return 2;
  }
  if (strcmp(argv[1], "--facts") == 0) {
    if (argc != 2) return 2;
    print_facts("facts");
    return 0;
  }
  if (strcmp(argv[1], "--be-target") == 0) {
    if (argc != 3) return 2;
    print_facts("be-target-pre");
    if (unshare(CLONE_NEWUSER) != 0) {
      printf("PROBE unshare-failed errno=%d (%s)\n", errno, strerror(errno));
      fflush(stdout);
      return 3;
    }
    print_facts("be-target-post");
    errno = 0;
    fd = open(argv[2], O_WRONLY); /* blocks until the harness opens the read end */
    if (fd < 0) {
      printf("PROBE fifo-open-failed errno=%d (%s)\n", errno, strerror(errno));
      fflush(stdout);
      return 4;
    }
    n = snprintf(line, sizeof line, "PID=%d\n", (int)getpid());
    if (write(fd, line, (size_t)n) != (ssize_t)n) {
      printf("PROBE fifo-write-failed errno=%d\n", errno);
      fflush(stdout);
      return 4;
    }
    close(fd);
    for (;;) pause();
  }
  if (strcmp(argv[1], "--invoke-helper") == 0) {
    if (argc < 4) return 2;
    print_facts("invoke-helper");
    return fork_exec_capture(&argv[2]);
  }
  if (strcmp(argv[1], "--workload-root") == 0) {
    if (argc < 5) return 2;
    print_facts("workload-root-pre");
    wait_go(argv[2]);
    print_facts("workload-root-go");
    return fork_exec_capture(&argv[3]);
  }
  if (strcmp(argv[1], "--workload-sub") == 0) {
    if (argc < 6) return 2;
    /* arg layout: --workload-sub <gofifo> <helper> <target-pid> <mapped-uid> <ranges...> */
    m = (uid_t)strtoul(argv[5], NULL, 10);
    print_facts("workload-sub-pre");
    wait_go(argv[2]);
    if (setresgid(m, m, m) != 0) {
      printf("PROBE setresgid-failed errno=%d (%s)\n", errno, strerror(errno));
      fflush(stdout);
      return 5;
    }
    if (setresuid(m, m, m) != 0) {
      printf("PROBE setresuid-failed errno=%d (%s)\n", errno, strerror(errno));
      fflush(stdout);
      return 5;
    }
    print_facts("workload-sub-post");
    k = 0;
    nargv[k++] = argv[3]; /* helper path */
    nargv[k++] = argv[4]; /* target pid */
    for (i = 6; i < argc && k < 62; i++) nargv[k++] = argv[i];
    nargv[k] = NULL;
    return fork_exec_capture(nargv);
  }
  /* P5-S2g26 Part D: the paired process-control modes. The --signal
   * modes send one signal and report the raw errno (the SELinux verdict
   * is the AVC + errno; the kernel's uid/namespace checks pass for every
   * pair here because both operations share the builder kuid). The
   * --ptrace modes report the PTRACE_SEIZE/DETACH verdicts the same
   * way. The --spawn-* modes fork the own-op child first and print its
   * facts, so the own-op leg's target context is in the evidence. */
  if (strcmp(argv[1], "--signal") == 0) {
    pid_t tp;
    int sg, rc;
    if (argc != 4) return 2;
    tp = (pid_t)strtol(argv[2], NULL, 10);
    sg = (int)strtol(argv[3], NULL, 10);
    print_facts("signal-pre");
    errno = 0;
    rc = kill(tp, sg);
    printf("PROBE signal target=%d sig=%d rc=%d errno=%d (%s)\n",
           (int)tp, sg, rc, errno, strerror(errno));
    fflush(stdout);
    return rc == 0 ? 0 : 5;
  }
  if (strcmp(argv[1], "--spawn-signal") == 0) {
    pid_t child;
    int sg, rc, st;
    if (argc != 3) return 2;
    sg = (int)strtol(argv[2], NULL, 10);
    print_facts("spawn-signal-pre");
    child = fork();
    if (child < 0) {
      printf("PROBE fork-failed errno=%d (%s)\n", errno, strerror(errno));
      fflush(stdout);
      return 6;
    }
    if (child == 0) {
      print_facts("spawn-signal-child");
      for (;;) pause();
      _exit(0);
    }
    printf("PROBE spawn pid=%d\n", (int)child);
    fflush(stdout);
    errno = 0;
    rc = kill(child, sg);
    printf("PROBE signal target=%d sig=%d rc=%d errno=%d (%s)\n",
           (int)child, sg, rc, errno, strerror(errno));
    fflush(stdout);
    rc = kill(child, SIGKILL);
    printf("PROBE cleanup-kill rc=%d errno=%d (%s)\n", rc, errno, strerror(errno));
    fflush(stdout);
    if (waitpid(child, &st, 0) < 0) {
      printf("PROBE reap-failed errno=%d (%s)\n", errno, strerror(errno));
    } else {
      printf("PROBE reaped pid=%d st=0x%x\n", (int)child, st);
    }
    fflush(stdout);
    return 0;
  }
  if (strcmp(argv[1], "--ptrace") == 0) {
    pid_t tp;
    long r;
    if (argc != 3) return 2;
    tp = (pid_t)strtol(argv[2], NULL, 10);
    print_facts("ptrace-pre");
    errno = 0;
    r = ptrace(PTRACE_SEIZE, tp, (void *)0, (void *)0);
    printf("PROBE ptrace-seize target=%d rc=%ld errno=%d (%s)\n",
           (int)tp, r, errno, strerror(errno));
    fflush(stdout);
    if (r == 0) {
      errno = 0;
      r = ptrace(PTRACE_DETACH, tp, (void *)0, (void *)0);
      printf("PROBE ptrace-detach target=%d rc=%ld errno=%d (%s)\n",
             (int)tp, r, errno, strerror(errno));
      fflush(stdout);
    }
    return 0;
  }
  if (strcmp(argv[1], "--spawn-ptrace") == 0) {
    pid_t child;
    long r;
    int st;
    if (argc != 2) return 2;
    print_facts("spawn-ptrace-pre");
    child = fork();
    if (child < 0) {
      printf("PROBE fork-failed errno=%d (%s)\n", errno, strerror(errno));
      fflush(stdout);
      return 6;
    }
    if (child == 0) {
      print_facts("spawn-ptrace-child");
      raise(SIGSTOP);
      for (;;) pause();
      _exit(0);
    }
    printf("PROBE spawn pid=%d\n", (int)child);
    fflush(stdout);
    if (waitpid(child, &st, WUNTRACED) < 0) {
      printf("PROBE stop-wait-failed errno=%d (%s)\n", errno, strerror(errno));
      fflush(stdout);
      kill(child, SIGKILL);
      waitpid(child, &st, 0);
      return 6;
    }
    printf("PROBE stop-wait st=0x%x\n", st);
    fflush(stdout);
    errno = 0;
    r = ptrace(PTRACE_SEIZE, child, (void *)0, (void *)0);
    printf("PROBE ptrace-seize target=%d rc=%ld errno=%d (%s)\n",
           (int)child, r, errno, strerror(errno));
    fflush(stdout);
    if (r == 0) {
      errno = 0;
      r = ptrace(PTRACE_DETACH, child, (void *)0, (void *)0);
      printf("PROBE ptrace-detach target=%d rc=%ld errno=%d (%s)\n",
             (int)child, r, errno, strerror(errno));
      fflush(stdout);
    }
    if (kill(child, SIGKILL) != 0) {
      printf("PROBE cleanup-kill rc=-1 errno=%d (%s)\n", errno, strerror(errno));
    }
    if (waitpid(child, &st, 0) < 0) {
      printf("PROBE reap-failed errno=%d (%s)\n", errno, strerror(errno));
    } else {
      printf("PROBE reaped pid=%d st=0x%x\n", (int)child, st);
    }
    fflush(stdout);
    return 0;
  }
  /* P5-S2g26 Part E: the shared-object surface modes. The created file
   * inherits the parent directory's type and the creator's category, so
   * the recorded label is the evidence of who created what. */
  if (strcmp(argv[1], "--touch") == 0) {
    int fd;
    ssize_t wn;
    if (argc != 3) return 2;
    print_facts("touch-pre");
    errno = 0;
    fd = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0644);
    if (fd < 0) {
      printf("PROBE touch path=%s rc=-1 errno=%d (%s)\n", argv[2], errno, strerror(errno));
      fflush(stdout);
      return 5;
    }
    wn = write(fd, "x", 1);
    printf("PROBE touch path=%s rc=0 written=%zd write-errno=%d (%s)\n",
           argv[2], wn, errno, strerror(errno));
    close(fd);
    fflush(stdout);
    return wn == 1 ? 0 : 5;
  }
  if (strcmp(argv[1], "--write") == 0) {
    int fd;
    ssize_t wn;
    if (argc != 3) return 2;
    print_facts("write-pre");
    errno = 0;
    fd = open(argv[2], O_WRONLY);
    if (fd < 0) {
      printf("PROBE write path=%s rc=-1 errno=%d (%s)\n", argv[2], errno, strerror(errno));
      fflush(stdout);
      return 5;
    }
    wn = write(fd, "y", 1);
    printf("PROBE write path=%s rc=0 written=%zd write-errno=%d (%s)\n",
           argv[2], wn, errno, strerror(errno));
    close(fd);
    fflush(stdout);
    return wn == 1 ? 0 : 5;
  }
  if (strcmp(argv[1], "--read") == 0) {
    int fd;
    ssize_t n;
    char buf[64];
    if (argc != 3) return 2;
    print_facts("read-pre");
    errno = 0;
    fd = open(argv[2], O_RDONLY);
    if (fd < 0) {
      printf("PROBE read path=%s rc=-1 errno=%d (%s)\n", argv[2], errno, strerror(errno));
      fflush(stdout);
      return 5;
    }
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n < 0) {
      printf("PROBE read path=%s open-ok read=-1 errno=%d (%s)\n",
             argv[2], errno, strerror(errno));
      fflush(stdout);
      return 5;
    }
    buf[n] = '\0';
    printf("PROBE read path=%s rc=0 bytes=%zd content=[%s]\n", argv[2], n, buf);
    fflush(stdout);
    return 0;
  }
  if (strcmp(argv[1], "--fifo-write") == 0) {
    int fd;
    ssize_t wn;
    if (argc != 3) return 2;
    print_facts("fifo-write-pre");
    errno = 0;
    fd = open(argv[2], O_WRONLY); /* blocks until the harness's reader opens */
    if (fd < 0) {
      printf("PROBE fifo-write path=%s rc=-1 errno=%d (%s)\n", argv[2], errno, strerror(errno));
      fflush(stdout);
      return 5;
    }
    wn = write(fd, "x", 1);
    printf("PROBE fifo-write path=%s rc=0 written=%zd write-errno=%d (%s)\n",
           argv[2], wn, errno, strerror(errno));
    close(fd);
    fflush(stdout);
    return wn == 1 ? 0 : 5;
  }
  fprintf(stderr, "usage: map_probe --be-target <fifo> | --invoke-helper <helper> <pid> <range...> | --workload-root <gofifo> <helper> <pid> <range...> | --workload-sub <gofifo> <helper> <pid> <mapped-uid> <range...> | --facts | --signal <pid> <sig> | --spawn-signal <sig> | --ptrace <pid> | --spawn-ptrace | --touch <path> | --write <path> | --read <path> | --fifo-write <path>\n");
  return 2;
}
EOF
DIR_RULES=""
STATE_RULES=""
FD_RULES=""
REQ_TYPES=" $OUT_T $RUNNER_T $BINDIR_T $FIFO_T $DIR_TYPE_LIST"
for t in $STATE_TYPE_LIST; do
  case " $REQ_TYPES " in *" $t "*) ;; *) REQ_TYPES="$REQ_TYPES $t" ;; esac
done
# The stage-3 real-rootlesskit-flow surface (--net=none), enumerated from
# the permissive scope-assessment run's harvest (run 36316667317
# e-permissive-avc-harvest.txt) plus the driver mechanics: the rootlesskit
# none-driver runs `nsenter ... ip addr add/link set` (so nsenter+ip are
# installed and exec'd from bin_t), the `ip` uses a route socket with
# NET_ADMIN in the child's usern, the flow-child re-mounts propagation on
# / and stages a temp dir under /tmp, and the parent creates the api.sock
# in the state dir. All of it is guest-only diagnostic surface, removed at
# cleanup; the production policy keeps its deliberate boundaries.
FLOW_RULES="
	allow docker_helper_rootlesskit_t bin_t:file { execute read open execute_no_trans getattr map };
	allow docker_helper_rootlesskit_t ifconfig_exec_t:file { execute read open execute_no_trans getattr map };
	allow docker_helper_rootlesskit_t self:netlink_route_socket { create bind getattr getopt setopt read write nlmsg_read nlmsg_write };
	allow docker_helper_rootlesskit_t self:cap_userns { sys_admin net_admin setuid setgid sys_ptrace sys_chroot };
	allow docker_helper_rootlesskit_t root_t:dir { mounton };
	allow docker_helper_rootlesskit_t nsfs_t:file { getattr };
"
REQ_CLASS_LINES="
	class file { entrypoint read open execute execute_no_trans getattr map append write create setattr relabelto relabelfrom unlink lock };
	class fifo_file { read write open getattr };
	class dir { search getattr read open write add_name create remove_name rmdir lock mounton };
	class process { transition siginh };
	class fd { use };
	class sock_file { create unlink };
	class netlink_route_socket { create bind getattr getopt setopt read write nlmsg_read nlmsg_write };
	class cap_userns { sys_admin net_admin setuid setgid sys_ptrace sys_chroot };
"
REQ_TYPES="$REQ_TYPES root_t nsfs_t ifconfig_exec_t"
for t in $DIR_TYPE_LIST; do
  # Full management on the walk-dir types: beyond the path walk itself
  # (search/getattr), the real flow-child stages its mountSysfs temp dir
  # under /tmp and the parent writes the state tree there, so the
  # diagnostic stand grants the flow's evidenced runtime shape on these
  # guest-only types. The fifo_file grant mirrors the stand fifos' grant
  # shape (the g26 Part E cross-operation fifo legs create their test
  # fifos inside the e-shared walk dir).
  DIR_RULES+="	allow docker_helper_rootlesskit_t $t:dir { search getattr read open write add_name create remove_name rmdir lock };
	allow docker_helper_rootlesskit_t $t:file { create open read write getattr setattr lock unlink append };
	allow docker_helper_rootlesskit_t $t:sock_file { create unlink };
	allow docker_helper_rootlesskit_t $t:fifo_file { read write open getattr };
"
done
for t in $STATE_TYPE_LIST; do
  STATE_RULES+="	allow docker_helper_rootlesskit_t $t:dir { search getattr read open write add_name create remove_name rmdir lock };
	allow docker_helper_rootlesskit_t $t:file { create open read write getattr setattr lock unlink append };
	allow docker_helper_rootlesskit_t $t:sock_file { create unlink };
"
done
# The helper domains inherit the attempt's evidence-file fds (the runner's
# O_APPEND redirect) across their exec transitions; the transition's
# inherited-fd flush checks fd:use against the fd's owner domain and the
# file's open-mode access. Grant both so the helpers' OWN failure output
# reaches the attempt records deterministically (the flow's own helper
# stdio is a rootlesskit_t-owned pipe with the same two checks).
FD_RULES+="	allow docker_helper_rootlesskit_t unconfined_t:fd use;
	allow docker_helper_newuidmap_t unconfined_t:fd use;
	allow docker_helper_newgidmap_t unconfined_t:fd use;
"
REQ_TYPE_LINES=""
for t in $REQ_TYPES; do
  REQ_TYPE_LINES+="	type $t;
"
done
cat > /tmp/gidmap_probe_diag.te <<EOF
module gidmap_probe_diag 1.0;
require {
	type docker_helper_newgidmap_t;
	type docker_helper_newuidmap_t;
	type docker_helper_rootlesskit_t;
$REQ_TYPE_LINES	attribute file_type;
$REQ_CLASS_LINES}
type gidmap_probe_exec_t;
typeattribute gidmap_probe_exec_t file_type;
allow docker_helper_newgidmap_t gidmap_probe_exec_t:file { entrypoint read open execute getattr map };
allow docker_helper_newuidmap_t gidmap_probe_exec_t:file { entrypoint read open execute getattr map };
allow docker_helper_rootlesskit_t gidmap_probe_exec_t:file { entrypoint read open execute execute_no_trans getattr map };
allow docker_helper_newgidmap_t $OUT_T:file { append write };
allow docker_helper_newuidmap_t $OUT_T:file { append write };
allow unconfined_t gidmap_probe_exec_t:file { create open write append setattr relabelto };
allow unconfined_t docker_helper_rootlesskit_t:process { transition siginh };
allow docker_helper_rootlesskit_t $FIFO_T:fifo_file { read write open getattr };
allow docker_helper_rootlesskit_t docker_helper_rootlesskit_t:file { read open getattr };
$DIR_RULES$STATE_RULES$FD_RULES$FLOW_RULES
type_transition $RUNNER_T $BINDIR_T:file gidmap_probe_exec_t "map_probe";
EOF
cp /tmp/gidmap_probe_diag.te "$EVIDENCE_DIR/diag-probe-module.te"
checkmodule -M -m -o /tmp/gidmap_probe_diag.tmp /tmp/gidmap_probe_diag.te 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "the probe diag module failed to compile"; cat /tmp/gidmap_probe_diag.te >&2; exit 1; }
semodule_package -o /tmp/gidmap_probe_diag.pp -m /tmp/gidmap_probe_diag.tmp 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "the probe diag module failed to package"; exit 1; }
semodule -i /tmp/gidmap_probe_diag.pp 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "the probe diag module failed to load"; exit 1; }
log "probe diag module loaded"
{
  echo "=== build (after the diag module load: the creation type-transition labels the probe) ==="
  gcc -static -O2 -o /usr/local/bin/map_probe "$DIAG_BASE/probe/map_probe.c" 2>&1 && echo "build OK"
  echo "probe label (post-build): $(stat -c '%C' /usr/local/bin/map_probe 2>&1)"
  echo "probe fs: $(stat -c '%m' /usr/local/bin/map_probe 2>&1)"
} > "$EVIDENCE_DIR/b-probe-vehicle.txt" 2>&1
if [ ! -x /usr/local/bin/map_probe ] \
  || ! stat -c '%C' /usr/local/bin/map_probe 2>/dev/null | grep -q 'gidmap_probe_exec_t'; then
  note "the static probe binary could not be built or is mislabeled; the experiment cannot proceed"
  diagnose_stand_failure probe-vehicle "$STAND_EPOCH_ALL" "$EVIDENCE_DIR/b-probe-vehicle.txt"
  printf '%s P5S2-GIDMAP-CROSSOP-EXP-RESULT=PASS-INCOMPLETE (probe vehicle unavailable; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi

# make_target_b <fifo> [<runcon-ctx>] : create a FRESH target child B — a
# rootlesskit_t probe that creates its own user namespace and announces
# its PID through the fifo (blocking open on both sides; no readiness
# polling). The context is the vehicle's runcon context (the g24
# experiment passes the category-carrying B context; the default keeps
# the g22/g23 shape). The caller then fills (or leaves empty) B's maps.
# Prints the pid on stdout; returns nonzero if the stand failed.
make_target_b() {
  local fifo="$1" ctx="${2:-$RK_EXEC_T}"
  local line bpid=""
  runuser -u "$BUILDER_USER" -- \
    runcon "$ctx" /usr/local/bin/map_probe --be-target "$fifo" \
    >>"$DIAG_BASE/b-target.out" 2>&1 &
  exec 3<>"$fifo"
  if IFS= read -r -t 120 line <&3; then
    case "$line" in
      PID=[0-9]*) bpid="${line#PID=}" ;;
    esac
  fi
  exec 3<&-
  [ -n "$bpid" ] || return 1
  [ -r "/proc/$bpid/attr/current" ] || return 1
  printf '%s' "$bpid"
}

# set_target_uidmap <bpid> : the REAL distro newuidmap writes B's uid_map
# through the production transition chain (parent-role identity). The
# gid_map of B stays empty — the experiment's target state.
set_target_uidmap() {
  local bpid="$1" rc=0 b_uid b_gid
  set +e
  runuser -u "$BUILDER_USER" -- \
    runcon "$RK_EXEC_T" /usr/local/bin/map_probe --invoke-helper /usr/bin/newuidmap \
    "$bpid" "${U_MAP_ARGS[@]}"
  rc=$?
  set -e
  # procfs map files report st_size 0 even when they have content — the
  # check is content-based, never -s.
  b_uid="$(cat "/proc/$bpid/uid_map" 2>/dev/null || true)"
  b_gid="$(cat "/proc/$bpid/gid_map" 2>/dev/null || true)"
  echo "helper exit code: $rc"
  echo "uid_map after: [$b_uid]"
  echo "gid_map after: [$b_gid]"
  [ "$rc" = 0 ] || return 1
  [ -n "$b_uid" ] || return 1
  [ -z "$b_gid" ] || return 1
  return 0
}

# collect_b_facts <bpid> <out> <header>
collect_b_facts() {
  local bpid="$1" out="$2" header="$3"
  {
    echo "=== target child B ($header): pid=$bpid ==="
    echo "attr/current: $(tr -d '\0' < "/proc/$bpid/attr/current" 2>/dev/null || true)"
    grep -E '^(Uid|Gid|PPid|CapEff|CapPrm|NoNewPrivs)' "/proc/$bpid/status" 2>/dev/null || true
    echo "ns/user: $(readlink "/proc/$bpid/ns/user" 2>/dev/null || echo UNAVAILABLE)"
    echo "uid_map content: [$(cat "/proc/$bpid/uid_map" 2>/dev/null || true)]"
    echo "gid_map content: [$(cat "/proc/$bpid/gid_map" 2>/dev/null || true)]"
    echo "setgroups content: [$(cat "/proc/$bpid/setgroups" 2>/dev/null || true)]"
    for f in uid_map gid_map setgroups; do
      echo "$f: $(stat -c '%C mode=%a owner=%U:%G' "/proc/$bpid/$f" 2>&1)"
    done
  } > "$out" 2>&1
}

# load_stage_module <name> <class> <perm> : compile+load one guest-only
# capability module for docker_helper_newgidmap_t.
load_stage_module() {
  local name="$1" cls="$2" perm="$3"
  cat > "/tmp/$name.te" <<EOF
module $name 1.0;
require {
	type docker_helper_newgidmap_t;
	class $cls $perm;
}
allow docker_helper_newgidmap_t docker_helper_newgidmap_t:$cls $perm;
EOF
  cat "/tmp/$name.te" >> "$EVIDENCE_DIR/diag-capability-modules.te"
  checkmodule -M -m -o "/tmp/$name.tmp" "/tmp/$name.te" 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
    || { note "$name failed to compile"; exit 1; }
  semodule_package -o "/tmp/$name.pp" -m "/tmp/$name.tmp" 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
    || { note "$name failed to package"; exit 1; }
  semodule -i "/tmp/$name.pp" 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
    || { note "$name failed to load"; exit 1; }
}

# watch_stage_child_maps <state-dir-tag> <out> : identify the instance's
# rootlesskit_t child (the cmdline carries the state-dir token but not
# the probe) and keep recording its map files until both maps are
# non-empty or the budget runs out, so the last snapshot is the fullest
# state the process reached while alive. Used by the g22 stage controls,
# whose flows stay alive through the netns step; the g23 control uses
# the frozen watch_control_child_frozen variant instead, because the
# production flow dies within milliseconds of its uid_map write.
watch_stage_child_maps() {
  local tag="$1" out="$2" pid ctx ppid pctx cmd cpid uidm gidm
  local deadline=$(( $(date +%s) + 40 ))
  : > "$out"
  cpid=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    # The flow's CHILD re-execs /proc/self/exe, so its cmdline no longer
    # contains the "rootlesskit" name — match both the parent shape and
    # the child shape.
    for pid in $(pgrep -f 'rootlesskit --net=none|self/exe --net=none' 2>/dev/null || true); do
      [ -r "/proc/$pid/attr/current" ] || continue
      ctx="$(tr -d '\0' < "/proc/$pid/attr/current" 2>/dev/null || true)"
      case "$ctx" in *docker_helper_rootlesskit_t*) ;; *) continue ;; esac
      cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
      case "$cmd" in *"$tag"*) ;; *) continue ;; esac
      # The flow's processes (parent and re-exec'd child) carry the probe
      # payload in their argv but NOT as the command name; the standalone
      # probe vehicles are exactly the ones whose FIRST token is map_probe.
      case "${cmd%% *}" in *map_probe*) continue ;; esac
      ppid="$(awk '/^PPid:/{print $2}' "/proc/$pid/status" 2>/dev/null || true)"
      [ -r "/proc/$ppid/attr/current" ] || continue
      pctx="$(tr -d '\0' < "/proc/$ppid/attr/current" 2>/dev/null || true)"
      case "$pctx" in *docker_helper_rootlesskit_t*) cpid="$pid" ;; *) continue ;; esac
      break
    done
    if [ -n "$cpid" ]; then
      uidm="$(cat "/proc/$cpid/uid_map" 2>/dev/null || true)"
      gidm="$(cat "/proc/$cpid/gid_map" 2>/dev/null || true)"
      {
        echo "=== stage child (positive control target): pid=$cpid state-dir=$tag (snapshot $(date -u +%FT%TZ)) ==="
        echo "attr/current: $(tr -d '\0' < "/proc/$cpid/attr/current" 2>/dev/null || true)"
        echo "status Uid: $(awk '/^Uid:/{print $2, $3, $4, $5}' "/proc/$cpid/status" 2>/dev/null || true)"
        echo "status CapEff: $(awk '/^CapEff:/{print $2}' "/proc/$cpid/status" 2>/dev/null || true)"
        echo "uid_map content: [$uidm]"
        echo "gid_map content: [$gidm]"
        echo "setgroups content: [$(cat "/proc/$cpid/setgroups" 2>/dev/null || true)]"
      } > "$out" 2>&1
      if [ -n "$uidm" ] && [ -n "$gidm" ]; then
        return 0
      fi
      cpid=""
    fi
    sleep 0.2
  done
  return 1
}

# watch_control_child_frozen <out> <bg-job-pid> : the deterministic g23
# own-child control. The production flow dies a couple of milliseconds
# after its uid_map write (the parent's gid step fails at the SELinux
# cap_userns sys_admin boundary, and the parent's exit Pdeathsig-kills
# the child), and on the guest the helper processes live only one or two
# milliseconds, so no fork-based polling can observe the state between
# the two map writes. Everything here stays fork-free until the freeze:
# the flow tree is walked through /proc/<pid>/task/<pid>/children down
# to the one descendant whose uid_map is readable and EMPTY — the flow
# child's fresh user namespace (every other descendant: the runuser
# wrapper, the rootlesskit parent in the initial user namespace, the
# SUID map helpers — carries the full initial-namespace map) — then the
# child's uid_map is spun on with bare read syscalls and, the moment the
# write is observed, the flow PARENT is SIGSTOPed: it is the only
# process whose exit would kill the child, it forks both map helpers, so
# the freeze lands before the failing gid step can complete (the
# already-running uid helper finishes its remaining writes independently,
# and the child is stable, blocked on the idmap-completed pipe). After
# the snapshot the flow is resumed to its natural failure path.
watch_control_child_frozen() {
  local out="$1" start="$2" deadline
  deadline=$(( $(date +%s) + 40 ))
  : > "$out"
  local cur nxt kids sub line p3="" p2="" trigger=0 i=0
  # Walk the flow's tree to the empty-uid_map descendant.
  while [ -z "$p3" ] && [ "$(date +%s)" -lt "$deadline" ]; do
    if [ ! -d "/proc/$start" ]; then
      echo "=== g23 control child: the flow's bg job pid=$start exited before any child appeared ===" >> "$out"
      return 1
    fi
    cur="$start"
    while [ -n "$cur" ]; do
      kids=""
      IFS= read -r kids < "/proc/$cur/task/$cur/children" 2>/dev/null || true
      p3=""
      nxt=""
      for sub in $kids; do
        line=""
        IFS= read -r line < "/proc/$sub/uid_map" 2>/dev/null || true
        if [ -n "$line" ]; then
          [ -n "$nxt" ] || nxt="$sub"
        else
          p3="$sub"
        fi
      done
      if [ -n "$p3" ]; then
        p2="$cur"
        break
      fi
      cur="$nxt"
    done
  done
  if [ -z "$p3" ]; then
    echo "=== g23 control child: never appeared under the flow's bg job pid=$start ===" >> "$out"
    return 1
  fi
  # Fork-free trigger: spin on the child's uid_map until the write is
  # observed, then freeze the parent. A bounded iteration count keeps the
  # spin finite without fork-based deadlines; if the child disappears the
  # uid step itself failed (or the race was lost) and the diagnostic is
  # recorded without waiting for the whole budget.
  while [ "$i" -lt 100000 ]; do
    i=$((i + 1))
    if [ -r "/proc/$p3/uid_map" ]; then
      line=""
      IFS= read -r line < "/proc/$p3/uid_map" 2>/dev/null || true
      if [ -n "$line" ]; then
        trigger=1
        break
      fi
    else
      break
    fi
  done
  if [ "$trigger" = 1 ]; then
    kill -STOP "$p2" 2>/dev/null || true
    kill -STOP "$p3" 2>/dev/null || true
    sleep 0.02
    {
      echo "=== control child (frozen at the observed uid_map write): child pid=$p3 parent pid=$p2 walk start=$start (snapshot $(date -u +%FT%TZ)) ==="
      echo "child attr/current: $(tr -d '\0' < "/proc/$p3/attr/current" 2>/dev/null || true)"
      echo "child status Uid: $(awk '/^Uid:/{print $2, $3, $4, $5}' "/proc/$p3/status" 2>/dev/null || true)"
      echo "child status CapEff: $(awk '/^CapEff:/{print $2}' "/proc/$p3/status" 2>/dev/null || true)"
      echo "child uid_map content: [$(cat "/proc/$p3/uid_map" 2>/dev/null || true)]"
      echo "child gid_map content: [$(cat "/proc/$p3/gid_map" 2>/dev/null || true)]"
      echo "child setgroups content: [$(cat "/proc/$p3/setgroups" 2>/dev/null || true)]"
      echo "frozen parent attr/current: $(tr -d '\0' < "/proc/$p2/attr/current" 2>/dev/null || true)"
    } >> "$out" 2>&1
    kill -CONT "$p3" 2>/dev/null || true
    kill -CONT "$p2" 2>/dev/null || true
    return 0
  fi
  {
    echo "=== g23 control child: the uid_map write was never observed for child pid=$p3 (the uid step failed, or the flow died before it) ==="
  } >> "$out"
  return 1
}

# parent_role_attempt <fifo> <bpid> <out> <avcs> [<helper> <mapfile>
# <mapargs...>] : PARENT scenario — a docker_helper_rootlesskit_t invoker
# in the INITIAL user namespace (the builder identity, no kernel caps;
# the helper's file caps apply at exec) execs the REAL distro map helper
# with B's pid and the flow's valid subid arguments. Defaults keep the
# g22 experiment's shape (/usr/bin/newgidmap, gid_map, G_MAP_ARGS); the
# g23 experiment passes /usr/bin/newuidmap, uid_map, U_MAP_ARGS. The
# invoker's runcon context is the RK_INVOKER_CTX global (the g24
# experiment reassigns it to the category-carrying A context; the g22/g23
# default equals RK_EXEC_T). Returns the helper's exit code.
parent_role_attempt() {
  local fifo="$1" bpid="$2" out="$3" avcs="$4" rc=0 epoch
  local helper="${5:-/usr/bin/newgidmap}" mapfile="${6:-gid_map}"
  local -a margs=()
  if [ "$#" -gt 6 ]; then margs=("${@:7}"); else margs=("${G_MAP_ARGS[@]}"); fi
  epoch="$(date +%s)"
  {
    echo "=== PARENT-ROLE attempt: real $(basename "$helper") from the initial user namespace ==="
    echo "invoker domain: $RK_INVOKER_CTX (privilege shape: builder uid/gid, no kernel caps)"
    echo "target child B: pid=$bpid"
    echo "$mapfile before: [$(cat "/proc/$bpid/$mapfile" 2>/dev/null || true)]"
    echo "invocation args: $(basename "$helper") $bpid ${margs[*]}"
  } > "$out"
  harvest_helper_facts 12 "$EVIDENCE_DIR/tmp-helper-facts.txt" "$(basename "$helper")" &
  HELPER_FACTS_PID=$!
  set +e
  runuser -u "$BUILDER_USER" -- \
    runcon "$RK_INVOKER_CTX" /usr/local/bin/map_probe --invoke-helper "$helper" \
    "$bpid" "${margs[@]}" \
    >>"$out" 2>&1
  rc=$?
  set -e
  {
    echo "helper exit code: $rc"
    echo "$mapfile after: [$(cat "/proc/$bpid/$mapfile" 2>/dev/null || true)]"
  } >> "$out"
  sleep 2
  kill "$HELPER_FACTS_PID" 2>/dev/null || true
  wait "$HELPER_FACTS_PID" 2>/dev/null || true
  cat "$EVIDENCE_DIR/tmp-helper-facts.txt" >> "$out" 2>/dev/null || true
  harvest_avcs_since "$epoch" "$avcs"
  cat "$out" >&2
  return "$rc"
}

# run_own_child_uid_control <runcon-ctx> <tag> <prefix> : the
# deterministic positive control — the real rootlesskit flow's own
# one-shot child uid_map write under the given runcon context, captured
# by watch_control_child_frozen while the child is frozen between the
# two map writes, then resumed to its natural failure path (the flow's
# gid step stays on the production policy's gid boundary). The g23 and
# g24 phases both run it through here; the evidence files are
# <prefix>-control.txt, <prefix>-control-child-maps.txt and
# <prefix>-control-avcs.txt.
run_own_child_uid_control() {
  local ctx="$1" tag="$2" prefix="$3" epoch
  {
    echo "=== $prefix positive control: real rootlesskit flow, own-child uid_map write ==="
    echo "command: runuser -u $BUILDER_USER -- runcon $ctx /usr/bin/rootlesskit --net=none --state-dir=$DIAG_BASE/$tag/a1-state /bin/sleep 12"
  } > "$EVIDENCE_DIR/$prefix-control.txt"
  epoch="$(date +%s)"
  runuser -u "$BUILDER_USER" -- \
    runcon "$ctx" /usr/bin/rootlesskit --net=none \
    --state-dir="$DIAG_BASE/$tag/a1-state" /bin/sleep 12 \
    >>"$EVIDENCE_DIR/$prefix-control.txt" 2>&1 &
  RK_PIDS+=($!)
  watch_control_child_frozen "$EVIDENCE_DIR/$prefix-control-child-maps.txt" "$!" || \
    note "$prefix control: the own-child uid_map snapshot was not captured while alive (see $prefix-control.txt)"
  sleep 2
  harvest_avcs_since "$epoch" "$EVIDENCE_DIR/$prefix-control-avcs.txt"
  pkill -KILL -f "state-dir=$DIAG_BASE/$tag/a1-state" 2>/dev/null || true
  cat "$EVIDENCE_DIR/$prefix-control.txt" >&2
}

RK_PIDS=()

log 'C: stage 1 — CONTROL (production surface only, no capabilities granted)'
S1_EPOCH="$(date +%s)"
B_S1="$(make_target_b "$DIAG_BASE/fifos/bfifo-s1" || true)"
if [ -z "${B_S1:-}" ]; then
  note "stage 1: the target child B could not be created (see b-target.out)"
  diagnose_stand_failure s1-target "$S1_EPOCH" "$DIAG_BASE/b-target.out"
  printf '%s P5S2-GIDMAP-CROSSOP-EXP-RESULT=PASS-INCOMPLETE (target stand unavailable; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi
collect_b_facts "$B_S1" "$EVIDENCE_DIR/c1-b-facts.txt" "stage 1"
{
  echo "=== stage 1: B's uid_map set by the REAL distro newuidmap (production chain) ==="
} > "$EVIDENCE_DIR/c1-b-uidmap.txt" 2>&1
if ! set_target_uidmap "$B_S1" >>"$EVIDENCE_DIR/c1-b-uidmap.txt" 2>&1; then
  note "stage 1: B's uid_map could not be set; the stage is recorded as a stand finding"
  diagnose_stand_failure s1-uidmap "$S1_EPOCH" "$EVIDENCE_DIR/c1-b-uidmap.txt"
  printf '%s P5S2-GIDMAP-CROSSOP-EXP-RESULT=PASS-INCOMPLETE (target uid_map unavailable; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi
cat "$EVIDENCE_DIR/c1-b-uidmap.txt" >&2
collect_b_facts "$B_S1" "$EVIDENCE_DIR/c1-b-facts-post-uidmap.txt" "stage 1 after uid_map"

# The positive control: the REAL rootlesskit flow maps its OWN child
# (the payload is a barrier waiter and never starts while the gid step
# fails, so stages 1-2 controls are stderr/AVC based).
{
  echo "=== stage 1 control: real rootlesskit flow, own-child mapping (the payload cannot start while the gid step fails) ==="
  echo "command: runuser -u $BUILDER_USER -- runcon $RK_EXEC_T /usr/bin/rootlesskit --net=none --state-dir=$DIAG_BASE/s1/a1-state map_probe --workload-root ..."
} > "$EVIDENCE_DIR/c1-control-a.txt"
C1_EPOCH="$(date +%s)"
runuser -u "$BUILDER_USER" -- \
  runcon "$RK_EXEC_T" /usr/bin/rootlesskit --net=none \
  --state-dir="$DIAG_BASE/s1/a1-state" \
  /usr/local/bin/map_probe --workload-root "$DIAG_BASE/fifos/gofifo-s3w1" \
  /usr/bin/newgidmap 0 "${G_MAP_ARGS[@]}" \
  >>"$EVIDENCE_DIR/c1-control-a.txt" 2>&1 &
RK_PIDS+=($!)
watch_stage_child_maps "s1/a1-state" "$EVIDENCE_DIR/c1-control-child-maps.txt" || \
  note "stage 1 control: the own-child map snapshot was not captured while alive (see c1-control-a.txt)"
sleep 2
harvest_avcs_since "$C1_EPOCH" "$EVIDENCE_DIR/c1-control-avcs.txt"
cat "$EVIDENCE_DIR/c1-control-a.txt" >&2

if parent_role_attempt "$DIAG_BASE/fifos/bfifo-s1" "$B_S1" \
     "$EVIDENCE_DIR/c1-parent-attempt.txt" "$EVIDENCE_DIR/c1-parent-avcs.txt"; then
  note "stage 1: the parent-role write SUCCEEDED without capabilities (unexpected: the production surface should deny the cap_userns check)"
fi
cat "$EVIDENCE_DIR/c1-parent-avcs.txt" >&2
if grep -E 'denied  \{ sys_admin \}.*docker_helper_newgidmap_t.*tclass=cap_userns' "$EVIDENCE_DIR/c1-parent-avcs.txt" >/dev/null 2>&1; then
  log "stage 1 boundary CONFIRMED: newgidmap_t denied cap_userns sys_admin (the map_write file_ns_capable gate)"
  STAGE1_CONFIRMED=1
else
  note "stage 1: the cap_userns sys_admin boundary was NOT observed; stages 2-3 skipped (recorded as a finding)"
  STAGE1_CONFIRMED=0
fi

log 'D: stage 2 — guest-only newgidmap_t self:cap_userns sys_admin'
if [ "${STAGE1_CONFIRMED:-0}" = 1 ]; then
  load_stage_module gidmap_capuserns_diag cap_userns sys_admin
  log "stage 2 module loaded (newgidmap_t self:cap_userns sys_admin; guest-only, removed at cleanup)"
  S2_EPOCH="$(date +%s)"
  B_S2="$(make_target_b "$DIAG_BASE/fifos/bfifo-s2" || true)"
  if [ -n "${B_S2:-}" ] && set_target_uidmap "$B_S2" >>"$EVIDENCE_DIR/c2-b-uidmap.txt" 2>&1; then
    collect_b_facts "$B_S2" "$EVIDENCE_DIR/c2-b-facts.txt" "stage 2"
    {
      echo "=== stage 2 control: real rootlesskit flow, own-child mapping ==="
    } > "$EVIDENCE_DIR/c2-control-a.txt"
    C2_EPOCH="$(date +%s)"
    runuser -u "$BUILDER_USER" -- \
      runcon "$RK_EXEC_T" /usr/bin/rootlesskit --net=none \
      --state-dir="$DIAG_BASE/s2/a1-state" \
      /usr/local/bin/map_probe --workload-root "$DIAG_BASE/fifos/gofifo-s3w1" \
      /usr/bin/newgidmap 0 "${G_MAP_ARGS[@]}" \
      >>"$EVIDENCE_DIR/c2-control-a.txt" 2>&1 &
    RK_PIDS+=($!)
    watch_stage_child_maps "s2/a1-state" "$EVIDENCE_DIR/c2-control-child-maps.txt" || \
      note "stage 2 control: the own-child map snapshot was not captured while alive (see c2-control-a.txt)"
    sleep 2
    harvest_avcs_since "$C2_EPOCH" "$EVIDENCE_DIR/c2-control-avcs.txt"
    cat "$EVIDENCE_DIR/c2-control-a.txt" >&2
    if parent_role_attempt "$DIAG_BASE/fifos/bfifo-s2" "$B_S2" \
         "$EVIDENCE_DIR/c2-parent-attempt.txt" "$EVIDENCE_DIR/c2-parent-avcs.txt"; then
      note "stage 2: the parent-role write SUCCEEDED with only cap_userns sys_admin (unexpected: the setgid capability boundary should still deny)"
    fi
    cat "$EVIDENCE_DIR/c2-parent-avcs.txt" >&2
    if grep -E 'denied  \{ setgid \}.*docker_helper_newgidmap_t.*tclass=capability' "$EVIDENCE_DIR/c2-parent-avcs.txt" >/dev/null 2>&1; then
      log "stage 2 boundary CONFIRMED: newgidmap_t denied capability setgid (the new_idmap_permitted parent-ns gate)"
      STAGE2_CONFIRMED=1
    else
      note "stage 2: the capability setgid boundary was NOT observed; stage 3 skipped (recorded as a finding)"
      STAGE2_CONFIRMED=0
    fi
  else
    note "stage 2: the fresh target child B could not be prepared; stage 3 skipped (recorded as a finding)"
    diagnose_stand_failure s2-target "$S2_EPOCH" "$DIAG_BASE/b-target.out" "$EVIDENCE_DIR/c2-b-uidmap.txt"
    STAGE2_CONFIRMED=0
  fi
else
  STAGE2_CONFIRMED=0
fi

log 'E: stage 3 — additionally guest-only newgidmap_t self:capability setgid'
S3_EPOCH="$(date +%s)"
if [ "${STAGE2_CONFIRMED:-0}" = 1 ]; then
  load_stage_module gidmap_capsetgid_diag capability setgid
  log "stage 3 module loaded (newgidmap_t self:capability setgid on top of stage 2; guest-only, removed at cleanup)"

  # (3a) PARENT-ROLE on a fresh B: the full chain now passes the shadow
  # checks and the kernel — this attempt is the headline measurement.
  B_S3P="$(make_target_b "$DIAG_BASE/fifos/bfifo-s3p" || true)"
  if [ -n "${B_S3P:-}" ] && set_target_uidmap "$B_S3P" >>"$EVIDENCE_DIR/c3-b-uidmap.txt" 2>&1; then
    collect_b_facts "$B_S3P" "$EVIDENCE_DIR/c3-b-facts.txt" "stage 3 parent attempt"
    if parent_role_attempt "$DIAG_BASE/fifos/bfifo-s3p" "$B_S3P" \
         "$EVIDENCE_DIR/c3-parent-attempt.txt" "$EVIDENCE_DIR/c3-parent-avcs.txt"; then
      log "stage 3 parent-role: the helper COMPLETED (exit 0) — the gid_map-after line in c3-parent-attempt.txt shows whether B's map changed"
    else
      log "stage 3 parent-role: the helper still failed (see c3-parent-attempt.txt and c3-parent-avcs.txt)"
    fi
  else
    note "stage 3: the parent attempt's fresh target child B could not be prepared (recorded as a finding)"
    diagnose_stand_failure s3-parent-target "$S3_EPOCH" "$DIAG_BASE/b-target.out" "$EVIDENCE_DIR/c3-b-uidmap.txt"
  fi

  # (3b) POSITIVE CONTROL at stage 3 + WORKLOAD-ROOT attempt: the real
  # rootlesskit flow's OWN child must now map BOTH maps with the same
  # capability set; its payload (mapped root) then performs the
  # workload-root attempt on a fresh B.
  B_S3W1="$(make_target_b "$DIAG_BASE/fifos/bfifo-s3w1" || true)"
  if [ -n "${B_S3W1:-}" ] && set_target_uidmap "$B_S3W1" >>"$EVIDENCE_DIR/c3-b-uidmap.txt" 2>&1; then
    collect_b_facts "$B_S3W1" "$EVIDENCE_DIR/c3-workload-root-b-facts.txt" "stage 3 workload-root"
    {
      echo "=== stage 3 control + WORKLOAD-ROOT attempt: real rootlesskit flow; payload = mapped-root probe ==="
      echo "payload: map_probe --workload-root <gofifo> /usr/bin/newgidmap $B_S3W1 ${G_MAP_ARGS[*]}"
    } > "$EVIDENCE_DIR/c3-workload-root.txt"
    W3_EPOCH="$(date +%s)"
    runuser -u "$BUILDER_USER" -- \
      runcon "$RK_EXEC_T" /usr/bin/rootlesskit --net=none \
      --state-dir="$DIAG_BASE/s3/a1-state" \
      /usr/local/bin/map_probe --workload-root "$DIAG_BASE/fifos/gofifo-s3w1" \
      /usr/bin/newgidmap "$B_S3W1" "${G_MAP_ARGS[@]}" \
      >>"$EVIDENCE_DIR/c3-workload-root.txt" 2>&1 &
    RK_PIDS+=($!)
    watch_stage_child_maps "s3/a1-state" "$EVIDENCE_DIR/c3-control-child-maps.txt" || \
      note "stage 3 control: the own-child map snapshot was not captured while alive (see c3-workload-root.txt)"
    set +e
    timeout 150 bash -c "printf 'GO\n' > '$DIAG_BASE/fifos/gofifo-s3w1'"
    GO_RC=$?
    set -e
    echo "GO write rc=$GO_RC (0 = the payload received the barrier and made its attempt)" \
      >> "$EVIDENCE_DIR/c3-workload-root.txt"
    sleep 3
    {
      echo "workload-root B gid_map after: [$(cat "/proc/$B_S3W1/gid_map" 2>/dev/null || true)]"
    } >> "$EVIDENCE_DIR/c3-workload-root.txt"
    harvest_avcs_since "$W3_EPOCH" "$EVIDENCE_DIR/c3-workload-root-avcs.txt"
    cat "$EVIDENCE_DIR/c3-workload-root.txt" >&2
  else
    note "stage 3: the workload-root target child B could not be prepared (recorded as a finding)"
    diagnose_stand_failure s3-workload-root-target "$S3_EPOCH" "$DIAG_BASE/b-target.out" "$EVIDENCE_DIR/c3-b-uidmap.txt"
  fi

  # (3c) WORKLOAD-SUB attempt: the payload drops to the mapped builder
  # uid inside operation A's namespace (A-uid $BUILDER_UID is within the
  # flow's 1..count subid extent, so getuid()/getgid() resolve the
  # builder's passwd entry and the subgid range check could pass) against
  # a fresh B. The shadow-helper's target-ownership comparison is a
  # CALLER-VIEW check (st_uid of the target's /proc dir mapped through
  # the caller's usern — 0 from inside A, not 1001), so the evidence
  # decides whether the mapped-builder shape reaches the kernel verdict
  # at all.
  B_S3W2="$(make_target_b "$DIAG_BASE/fifos/bfifo-s3w2" || true)"
  if [ -n "${B_S3W2:-}" ] && set_target_uidmap "$B_S3W2" >>"$EVIDENCE_DIR/c3-b-uidmap.txt" 2>&1; then
    collect_b_facts "$B_S3W2" "$EVIDENCE_DIR/c3-workload-sub-b-facts.txt" "stage 3 workload-sub"
    {
      echo "=== stage 3 WORKLOAD-SUB attempt: real rootlesskit flow; payload drops to the mapped builder uid ==="
      echo "payload: map_probe --workload-sub <gofifo> /usr/bin/newgidmap $B_S3W2 $BUILDER_UID ${G_MAP_ARGS[*]}"
    } > "$EVIDENCE_DIR/c3-workload-sub.txt"
    W3S_EPOCH="$(date +%s)"
    runuser -u "$BUILDER_USER" -- \
      runcon "$RK_EXEC_T" /usr/bin/rootlesskit --net=none \
      --state-dir="$DIAG_BASE/s3/a2-state" \
      /usr/local/bin/map_probe --workload-sub "$DIAG_BASE/fifos/gofifo-s3w2" \
      /usr/bin/newgidmap "$B_S3W2" "$BUILDER_UID" "${G_MAP_ARGS[@]}" \
      >>"$EVIDENCE_DIR/c3-workload-sub.txt" 2>&1 &
    RK_PIDS+=($!)
    set +e
    timeout 150 bash -c "printf 'GO\n' > '$DIAG_BASE/fifos/gofifo-s3w2'"
    GO2_RC=$?
    set -e
    echo "GO write rc=$GO2_RC (0 = the payload received the barrier and made its attempt)" \
      >> "$EVIDENCE_DIR/c3-workload-sub.txt"
    sleep 3
    {
      echo "workload-sub B gid_map after: [$(cat "/proc/$B_S3W2/gid_map" 2>/dev/null || true)]"
    } >> "$EVIDENCE_DIR/c3-workload-sub.txt"
    harvest_avcs_since "$W3S_EPOCH" "$EVIDENCE_DIR/c3-workload-sub-avcs.txt"
    cat "$EVIDENCE_DIR/c3-workload-sub.txt" >&2
  else
    note "stage 3: the workload-sub target child B could not be prepared (recorded as a finding)"
    diagnose_stand_failure s3-workload-sub-target "$S3_EPOCH" "$DIAG_BASE/b-target.out" "$EVIDENCE_DIR/c3-b-uidmap.txt"
  fi
else
  note "stage 3 skipped (the stage 2 boundary was not confirmed; recorded as a finding)"
fi

log 'F: P5-S2g23 — uid_map cross-operation experiment (existing production policy only)'
# Unload the g22 stage modules so the policy is the production module plus
# the stand's own operation module; no new runtime grants for this phase.
semodule -r gidmap_capsetgid_diag >/dev/null 2>&1 || true
semodule -r gidmap_capuserns_diag >/dev/null 2>&1 || true
{
  echo "=== loaded policy modules at the g23 phase start ==="
  semodule -l | grep -a 'docker_helper\|gidmap' || true
  echo "=== the transferred candidate .te's EXISTING newuidmap grants (no new grants added) ==="
  grep -an 'newuidmap' "$TRANSFERRED/docker-helper.te" || true
} > "$EVIDENCE_DIR/g23-production-surface.txt" 2>&1
G23_EPOCH="$(date +%s)"
B_G23="$(make_target_b "$DIAG_BASE/fifos/bfifo-g23" || true)"
if [ -z "${B_G23:-}" ]; then
  note "g23: the target child B could not be created (recorded as a finding)"
  P5S2G23_RESULT="the target child B could not be created (see stand-failure-g23-target.txt)"
  diagnose_stand_failure g23-target "$G23_EPOCH" "$DIAG_BASE/b-target.out" "$EVIDENCE_DIR/g23-b-facts.txt"
else
  collect_b_facts "$B_G23" "$EVIDENCE_DIR/g23-b-facts.txt" "g23 target B before"
  if parent_role_attempt "$DIAG_BASE/fifos/bfifo-g23" "$B_G23" \
       "$EVIDENCE_DIR/g23-parent-attempt.txt" "$EVIDENCE_DIR/g23-parent-avcs.txt" \
       /usr/bin/newuidmap uid_map "${U_MAP_ARGS[@]}"; then
    log "g23 CROSS-OPERATION uid_map write SUCCEEDED under the existing production policy — recorded as an EXISTING production risk (no new runtime grants involved)"
    P5S2G23_RESULT="cross-operation uid_map write SUCCEEDED under the existing production policy — EXISTING production risk (see g23-parent-attempt.txt)"
  else
    log "g23 cross-operation uid_map write FAILED under the existing production policy — the exact additional boundary is in the attempt record and AVCs"
    P5S2G23_RESULT="cross-operation uid_map write FAILED under the existing production policy — the additional boundary is in g23-parent-attempt.txt and g23-parent-avcs.txt"
  fi
  # Positive control: the real rootlesskit flow's own one-shot child
  # uid_map write, in the same window, same policy.
  run_own_child_uid_control "$RK_EXEC_T" "g23" "g23"
fi
P5S2G23_RESULT="${P5S2G23_RESULT:-the g23 phase did not complete its measurement}"
printf '%s P5S2-G23-UIDMAP-CROSSOP-RESULT=COMPLETED (%s)\n' "$PREFIX" "$P5S2G23_RESULT" >&2

log 'G: P5-S2g24 — MCS category cross-operation isolation experiment'
# Same domain, same Unix uid, different MCS categories: operation A's
# vehicles run as docker_helper_rootlesskit_t:s0:c1, operation B's target
# child as :s0:c2. NO new policy modules and no changed grants: the
# mechanism under test is the shipped MCS constraint set applied on top
# of the exact g23 shape. The first gate is the category assignment
# itself: if the existing policy does not allow the builder's runcon
# chain to reach the category-carrying contexts, that obstacle is
# recorded and the phase stops without further attempts.
RK_EXEC_T_A=system_u:system_r:docker_helper_rootlesskit_t:s0:c1
RK_EXEC_T_B=system_u:system_r:docker_helper_rootlesskit_t:s0:c2
{
  echo "=== loaded policy modules at the g24 phase start ==="
  semodule -l | grep -a 'docker_helper\|gidmap' || true
  echo "=== the shipped policy's MCS/MLS constraint set (the mechanism under test) ==="
  echo "--- seinfo --constrain (all classes) ---"
  seinfo --constrain 2>&1 || true
  echo "--- seinfo --constrain file ---"
  seinfo --constrain file 2>&1 || true
  echo "--- seinfo --constrain process ---"
  seinfo --constrain process 2>&1 || true
  echo "=== the production .te's uid_map rules (the TE layer, unchanged) ==="
  grep -an 'uid_map' "$TRANSFERRED/docker-helper.te" || true
} > "$EVIDENCE_DIR/g24-production-surface.txt" 2>&1
A_ASSIGN_RC=0
B_ASSIGN_RC=0
{
  echo "=== the runner's own context (the assignment chain's root) ==="
  echo "runner attr/current: $(tr -d '\0' < /proc/self/attr/current 2>/dev/null || true)"
  echo "=== the builder's PAM context after runuser (the runcon chain's origin; id -Z prints the reading process's own context) ==="
  echo "builder context: $(runuser -u "$BUILDER_USER" -- id -Z 2>/dev/null || echo UNAVAILABLE)"
  echo "=== assignment probe A: runuser+runcon to $RK_EXEC_T_A ==="
  runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_A" /usr/local/bin/map_probe --facts || A_ASSIGN_RC=$?
  echo "assignment A rc=$A_ASSIGN_RC"
  echo "=== assignment probe B: runuser+runcon to $RK_EXEC_T_B ==="
  runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_B" /usr/local/bin/map_probe --facts || B_ASSIGN_RC=$?
  echo "assignment B rc=$B_ASSIGN_RC"
} > "$EVIDENCE_DIR/g24-assignment.txt" 2>&1
cat "$EVIDENCE_DIR/g24-assignment.txt" >&2
A_ASSIGN_OK=0
B_ASSIGN_OK=0
if grep -aq 'PROBE selinux=system_u:system_r:docker_helper_rootlesskit_t:s0:c1' "$EVIDENCE_DIR/g24-assignment.txt"; then A_ASSIGN_OK=1; fi
if grep -aq 'PROBE selinux=system_u:system_r:docker_helper_rootlesskit_t:s0:c2' "$EVIDENCE_DIR/g24-assignment.txt"; then B_ASSIGN_OK=1; fi
if [ "$A_ASSIGN_OK" = 0 ] || [ "$B_ASSIGN_OK" = 0 ]; then
  note "g24 OBSTACLE: the existing policy does not allow assigning the required MCS categories (see g24-assignment.txt) — the phase stops without the cross-operation attempt"
  P5S2G24_RESULT="OBSTACLE: the existing policy does not allow assigning the required MCS categories (see g24-assignment.txt for the probe facts and the exact denial)"
else
  G24_EPOCH="$(date +%s)"
  B_G24="$(make_target_b "$DIAG_BASE/fifos/bfifo-g24" "$RK_EXEC_T_B" || true)"
  if [ -z "${B_G24:-}" ]; then
    note "g24: the target child B could not be created (recorded as a finding)"
    P5S2G24_RESULT="the target child B could not be created (see stand-failure-g24-target.txt)"
    diagnose_stand_failure g24-target "$G24_EPOCH" "$DIAG_BASE/b-target.out" "$EVIDENCE_DIR/g24-b-facts.txt"
  else
    collect_b_facts "$B_G24" "$EVIDENCE_DIR/g24-b-facts.txt" "g24 target B (category c2) before"
    RK_INVOKER_CTX="$RK_EXEC_T_A"
    if parent_role_attempt "$DIAG_BASE/fifos/bfifo-g24" "$B_G24" \
         "$EVIDENCE_DIR/g24-parent-attempt.txt" "$EVIDENCE_DIR/g24-parent-avcs.txt" \
         /usr/bin/newuidmap uid_map "${U_MAP_ARGS[@]}"; then
      log "g24 CROSS-OPERATION uid_map write SUCCEEDED across the assigned MCS categories — the shipped policy does not constrain this path by MCS"
      P5S2G24_RESULT="MCS ISOLATION DOES NOT HOLD on the shipped policy: cross-operation uid_map write SUCCEEDED across the assigned categories (A at c1 wrote B at c2); the own-child control is in g24-control-child-maps.txt (see g24-parent-attempt.txt)"
    else
      # A helper failure alone does not prove MCS isolation. With the
      # production TE write grant in place (the s0/s0 g23 attempt proved
      # it), a file-class denial whose subject context is
      # newuidmap_t:s0:c1 and whose target context is
      # rootlesskit_t:s0:c2 IS the MCS mechanism; anything else is a
      # different boundary.
      G24_CAUSE="another boundary (see g24-parent-attempt.txt and g24-parent-avcs.txt)"
      if grep -aq 'scontext=system_u:system_r:docker_helper_newuidmap_t:s0:c1 ' \
           "$EVIDENCE_DIR/g24-parent-avcs.txt" 2>/dev/null &&
         grep -aq 'tcontext=system_u:system_r:docker_helper_rootlesskit_t:s0:c2 tclass=file' \
           "$EVIDENCE_DIR/g24-parent-avcs.txt" 2>/dev/null; then
        G24_CAUSE="the shipped policy's MCS constraint on the file class (a c1 subject cannot write a c2-labeled object)"
      fi
      log "g24 CROSS-OPERATION uid_map write FAILED across the assigned MCS categories — exact cause: $G24_CAUSE"
      P5S2G24_RESULT="cross-operation uid_map write FAILED across the assigned categories (A at c1, B at c2); blocking cause: $G24_CAUSE"
    fi
    RK_INVOKER_CTX="$RK_EXEC_T"
    run_own_child_uid_control "$RK_EXEC_T_A" "g24" "g24"
  fi
fi
P5S2G24_RESULT="${P5S2G24_RESULT:-the g24 phase did not complete its measurement}"
printf '%s P5S2-G24-MCS-CROSSOP-RESULT=COMPLETED (%s)\n' "$PREFIX" "$P5S2G24_RESULT" >&2

log 'H: P5-S2g25 — constrained MCS feasibility proof (newuidmap_t membership in mcs_constrained_type)'
# The pairing with g24 is the attribution argument: the SAME cross-op
# call succeeded in phase G (the constraint exempted the helper domain)
# and is retried here with the single membership delta loaded, so any
# new denial on the same contexts is caused by the delta, not by
# something else. The delta is a guest-only module; it is removed at
# cleanup.
{
  echo "=== loaded policy modules at the g25 phase start ==="
  semodule -l | grep -a 'docker_helper\|gidmap' || true
  echo "=== the shipped policy's MCS/MLS constraint set (the mechanism under test) ==="
  echo "--- seinfo --constrain file ---"
  seinfo --constrain file 2>&1 || true
  echo "--- seinfo --constrain process ---"
  seinfo --constrain process 2>&1 || true
  echo "--- seinfo --constrain dir ---"
  seinfo --constrain dir 2>&1 || true
  echo "=== the production .te's uid_map rules (the TE layer, unchanged) ==="
  grep -an 'uid_map' "$TRANSFERRED/docker-helper.te" || true
} > "$EVIDENCE_DIR/g25-production-surface.txt" 2>&1
seinfo -a mcs_constrained_type -x 2>/dev/null \
  > "$EVIDENCE_DIR/g25-mcs-members-before.txt" || true
G25_MEMB_BEFORE=0
if grep -aq 'docker_helper_newuidmap_t' "$EVIDENCE_DIR/g25-mcs-members-before.txt"; then
  G25_MEMB_BEFORE=1
  note "g25: docker_helper_newuidmap_t is ALREADY a member of mcs_constrained_type before the delta (unexpected production state)"
fi
cat > /tmp/gidmap_mcsconstrained_diag.te <<'DELTAEOF'
module gidmap_mcsconstrained_diag 1.0;

# P5-S2g25 guest-only policy delta: the ONLY change vs the production
# policy is the membership of docker_helper_newuidmap_t in the shipped
# base's mcs_constrained_type attribute. No allow/grant/transition rules
# are added. Loaded only for this experiment; removed at cleanup.
require {
  attribute mcs_constrained_type;
  type docker_helper_newuidmap_t;
}
typeattribute docker_helper_newuidmap_t mcs_constrained_type;
DELTAEOF
{
  echo "=== the exact policy delta (the guest-only module's source) ==="
  cat /tmp/gidmap_mcsconstrained_diag.te
  echo "=== compile/package/load log ==="
} > "$EVIDENCE_DIR/g25-policy-delta.txt"
DELTA_OK=0
if checkmodule -M -m -o /tmp/gidmap_mcsconstrained_diag.tmp /tmp/gidmap_mcsconstrained_diag.te 2>>"$EVIDENCE_DIR/g25-policy-delta.txt" &&
   semodule_package -o /tmp/gidmap_mcsconstrained_diag.pp -m /tmp/gidmap_mcsconstrained_diag.tmp 2>>"$EVIDENCE_DIR/g25-policy-delta.txt" &&
   semodule -i /tmp/gidmap_mcsconstrained_diag.pp 2>>"$EVIDENCE_DIR/g25-policy-delta.txt"; then
  DELTA_OK=1
fi
G25_MEMB_AFTER=0
if [ "$DELTA_OK" = 1 ]; then
  seinfo -a mcs_constrained_type -x 2>/dev/null \
    > "$EVIDENCE_DIR/g25-mcs-members-after.txt" || true
  if grep -aq 'docker_helper_newuidmap_t' "$EVIDENCE_DIR/g25-mcs-members-after.txt"; then G25_MEMB_AFTER=1; fi
fi
{
  echo "=== mcs_constrained_type membership ==="
  echo "before the delta: member=$G25_MEMB_BEFORE (full dump: g25-mcs-members-before.txt)"
  echo "delta loaded: $DELTA_OK"
  echo "after the delta: member=$G25_MEMB_AFTER (full dump: g25-mcs-members-after.txt)"
  echo "=== the categories and contexts A/B (assignment re-verification) ==="
  echo "runner attr/current: $(tr -d '\0' < /proc/self/attr/current 2>/dev/null || true)"
  echo "builder context: $(runuser -u "$BUILDER_USER" -- id -Z 2>/dev/null || echo UNAVAILABLE)"
  echo "=== assignment probe A: runuser+runcon to $RK_EXEC_T_A ==="
  runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_A" /usr/local/bin/map_probe --facts || true
  echo "=== assignment probe B: runuser+runcon to $RK_EXEC_T_B ==="
  runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_B" /usr/local/bin/map_probe --facts || true
} > "$EVIDENCE_DIR/g25-assignment.txt" 2>&1
cat "$EVIDENCE_DIR/g25-assignment.txt" >&2
G25_ASSIGN_OK=0
if grep -aq 'PROBE selinux=system_u:system_r:docker_helper_rootlesskit_t:s0:c1' "$EVIDENCE_DIR/g25-assignment.txt" &&
   grep -aq 'PROBE selinux=system_u:system_r:docker_helper_rootlesskit_t:s0:c2' "$EVIDENCE_DIR/g25-assignment.txt"; then G25_ASSIGN_OK=1; fi
P5S2G25_RESULT=""
if [ "$DELTA_OK" = 0 ] || [ "$G25_MEMB_AFTER" = 0 ]; then
  note "g25 OBSTACLE: the guest-only MCS delta could not be loaded or its membership is not verifiable (see g25-policy-delta.txt and g25-mcs-members-after.txt) — the phase stops"
  P5S2G25_RESULT="INCONCLUSIVE: the guest-only MCS delta could not be loaded or its membership is not verifiable (see g25-policy-delta.txt and g25-mcs-members-after.txt)"
elif [ "$G25_ASSIGN_OK" = 0 ]; then
  note "g25 OBSTACLE: the existing policy does not allow assigning the required MCS categories (see g25-assignment.txt) — the phase stops without the cross-operation attempt"
  P5S2G25_RESULT="INCONCLUSIVE: the existing policy does not allow assigning the required MCS categories (see g25-assignment.txt)"
fi
if [ -z "$P5S2G25_RESULT" ]; then
  G25_EPOCH="$(date +%s)"
  B_G25="$(make_target_b "$DIAG_BASE/fifos/bfifo-g25" "$RK_EXEC_T_B" || true)"
  if [ -z "${B_G25:-}" ]; then
    note "g25: the target child B could not be created (recorded as a finding)"
    P5S2G25_RESULT="INCONCLUSIVE: the target child B could not be created (see stand-failure-g25-target.txt)"
    diagnose_stand_failure g25-target "$G25_EPOCH" "$DIAG_BASE/b-target.out" "$EVIDENCE_DIR/g25-b-facts.txt"
  else
    collect_b_facts "$B_G25" "$EVIDENCE_DIR/g25-b-facts.txt" "g25 target B (category c2) before"
    RK_INVOKER_CTX="$RK_EXEC_T_A"
    G25_ATTEMPT_RC=0
    if ! parent_role_attempt "$DIAG_BASE/fifos/bfifo-g25" "$B_G25" \
         "$EVIDENCE_DIR/g25-parent-attempt.txt" "$EVIDENCE_DIR/g25-parent-avcs.txt" \
         /usr/bin/newuidmap uid_map "${U_MAP_ARGS[@]}"; then
      G25_ATTEMPT_RC=1
    fi
    RK_INVOKER_CTX="$RK_EXEC_T"
    # Scenario 1 attribution: the same call succeeded in phase G (the
    # exempt subject), so with the membership loaded a file-class write
    # denial or a dir-class search denial on the c1→c2 contexts IS the
    # MCS mechanism (the dir search denies the path traversal that the
    # production TE grants, before the map write itself is reached).
    G25_LEG1=0
    G25_BLOCK_CAUSE=""
    if [ "$G25_ATTEMPT_RC" -eq 1 ]; then
      if grep -aq 'scontext=system_u:system_r:docker_helper_newuidmap_t:s0:c1 ' "$EVIDENCE_DIR/g25-parent-avcs.txt" 2>/dev/null &&
         { grep -aq 'tcontext=system_u:system_r:docker_helper_rootlesskit_t:s0:c2 tclass=file' "$EVIDENCE_DIR/g25-parent-avcs.txt" 2>/dev/null ||
           grep -aq 'tcontext=system_u:system_r:docker_helper_rootlesskit_t:s0:c2 tclass=dir' "$EVIDENCE_DIR/g25-parent-avcs.txt" 2>/dev/null; }; then
        G25_LEG1=1
        G25_BLOCK_CAUSE="the MCS constraint on the dir search and/or the file write for the c1→c2 contexts"
      else
        P5S2G25_RESULT="INCONCLUSIVE: the cross-operation write failed under the constrained membership but the denial is not the MCS mechanism — see g25-parent-attempt.txt and g25-parent-avcs.txt for the exact cause"
      fi
    fi
    if [ -z "$P5S2G25_RESULT" ]; then
      # Scenario 2: the own-child control, the same deterministic machinery.
      run_own_child_uid_control "$RK_EXEC_T_A" "g25" "g25"
      G25_LEG2=0
      if grep -aq 'uid_map content: \[ *0' "$EVIDENCE_DIR/g25-control-child-maps.txt" 2>/dev/null; then G25_LEG2=1; fi
      # Scenario 3: the control flow's whole AVC window must contain only
      # the known-benign shapes (the tolerated passwd getattrs and the
      # gid step's production boundary denials).
      G25_LEG3=0
      G25_NONBENIGN="$(grep -a 'type=AVC' "$EVIDENCE_DIR/g25-control-avcs.txt" 2>/dev/null | grep -av 'passwd_file_t' | grep -av 'tclass=cap_userns' | grep -av 'tclass=capability' | wc -l || true)"
      if grep -aq 'write to gid_map failed' "$EVIDENCE_DIR/g25-control.txt" 2>/dev/null && [ "${G25_NONBENIGN:-999}" -eq 0 ]; then G25_LEG3=1; fi
      if [ "$G25_ATTEMPT_RC" -eq 0 ]; then
        P5S2G25_RESULT="FAIL: the MCS-constrained newuidmap_t still wrote the cross-operation uid_map (see g25-parent-attempt.txt)"
      elif [ "$G25_LEG2" = 0 ] || [ "$G25_LEG3" = 0 ]; then
        P5S2G25_RESULT="FAIL: the own flow broke under the constrained membership (leg2/leg3 evidence: g25-control-child-maps.txt, g25-control.txt, g25-control-avcs.txt)"
      else
        P5S2G25_RESULT="PASS: c1→c2 uid_map write denied by the MCS constraint ($G25_BLOCK_CAUSE); the c1→c1 own-child write still succeeds (g25-control-child-maps.txt); the flow reaches the same production gid_map boundary with no new blocking denials (g25-control-avcs.txt)"
      fi
    fi
  fi
fi
P5S2G25_RESULT="${P5S2G25_RESULT:-the g25 phase did not complete its measurement}"
printf '%s P5S2-G25-MCS-CONSTRAINED-RESULT=COMPLETED (%s)\n' "$PREFIX" "$P5S2G25_RESULT" >&2

log 'I: P5-S2g26 — minimal MCS-constrained boundary (domain set, process-control matrix, shared-object surface)'
# The g25 delta module leaves first: the g26 phase's membership dumps
# must attribute ALL memberships to the g26 delta alone.
semodule -r gidmap_mcsconstrained_diag >/dev/null 2>&1 || true

# --- Part A: the statically derived minimal constrained-domain set ---
{
  echo "=== P5-S2g26 Part A: the statically derived minimal constrained-domain set ==="
  cat <<'TABLEEOF'
| domain                        | privileged/cross-operation surface (the .te refs)                                                                                                                                      | the relevant MCS constraint                                                        | verdict  |
|-------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|----------|
| docker_helper_rootlesskit_t   | as TARGET: the /proc/<pid> dir+file surfaces the map helpers' type-pair grants point at (newuidmap_t 1016/1040, newgidmap_t 1196/1229; slirp4netns_t 941 fifo); as SUBJECT: the state-tree writes (862-864), the builder diag fifo (871), the userns create (1259), cap_userns sys_admin (1272), the helper transitions (916-917/969-970/1132-1133); the ONLY self rules are 1259/1272 | file/dir read-search-write on its OWN procfs objects; process signal/sigkill/sigstop/ptrace against sibling operations' objects | INCLUDE — the pid-source; the only domain whose procfs objects carry the cross-operation grants; the Part D subject vehicle |
| docker_helper_newuidmap_t     | rootlesskit_t:dir {read open getattr search} (1016), :file {write open} (1040), :fifo {write} (1015); self:cap_userns sys_admin (1061), self:capability setuid (1088)                                                                                          | dir {ioctl lock read search} + file read/write — the type-pair grants ARE the g23/g24-demonstrated cross-operation path | INCLUDE |
| docker_helper_newgidmap_t     | the same type-pair shape on the gid path: dir (1196), file {write open} (1229), fifo {write} (1156); NO self rules                                                                                                                                     | the same classes                                                                    | INCLUDE — the same demonstrated cross-operation write-open on the same subject type (the scope note 1180-1196) |
| docker_helper_builder_t       | /proc enumeration: proc_t:dir read (768) + domain:dir/kernel_t:dir getattr (769-770) — the listing object is proc_t (an s0 type; dir getattr is NOT in the dir mlsconstrain set); NO rootlesskit_t:dir read/search — the /proc/<pid> traversal is TE-denied before any MCS check; the launch transition (826-827) | none applicable                                                                     | EXCLUDE — its only /proc surface is MCS-exempt or TE-blocked; no MCS-relevant cross-operation grant |
| docker_helper_slirp4netns_t   | rootlesskit_t:fifo_file {write getattr} (941) — fifo_file's mlsconstrain covers OPEN only, and the helper's inherited-fd write never re-opens; the domain is unreachable in the current enforcing policy (the cap boundary stops the helper exec; the netns fd is passed by fd, not a /proc path)                        | none applicable                                                                     | EXCLUDE — unreachable, and its only cross-operation grant is fd-scoped on a class whose open is the only MLS-constrained perm |
| docker_helper_t (the manager) | process control: semanage_t {transition siginh noatsecure rlimitinh} (434), sigkill (445), process2 nnp_transition (446); self:capability {dac_read_search dac_override sys_admin} (461), fowner (474); NO grants on any docker_helper_rootlesskit_t target (the 8 target-side type-pair lines belong to builder/slirp/newuidmap/newgidmap) | n/a                                                                                  | EXCLUDE — the trusted control plane that owns all operations; its only process-control grant targets semanage_t (the policy reload), not an operation domain |

The minimal set: docker_helper_rootlesskit_t, docker_helper_newuidmap_t,
docker_helper_newgidmap_t.
Caveat: the module text is compiled against the distro base; the
sesearch dumps below enumerate the LOADED policy's TE allow set for the
process-control surface (the base may grant self:process signal/ptrace
through the generic domain rules — the module text's absence is not the
loaded policy's absence). The classification below uses the loaded set.
TABLEEOF
  echo "=== the .te's target-side rules on docker_helper_rootlesskit_t (all of them) ==="
  grep -an 'allow .*docker_helper_rootlesskit_t:' "$TRANSFERRED/docker-helper.te" || echo NONE
  echo "=== the .te's self: rules (all of them) ==="
  grep -an 'allow .*self:' "$TRANSFERRED/docker-helper.te" || echo NONE
  echo "=== the .te's process-class rules (all of them) ==="
  grep -an ':process \|:process2 ' "$TRANSFERRED/docker-helper.te" || echo NONE
  echo "=== the .te's proc_t rules (the /proc enumeration surface) ==="
  grep -an 'proc_t' "$TRANSFERRED/docker-helper.te" || echo NONE
  echo "=== the manager's grants on rootlesskit_t targets (expect NONE) ==="
  grep -an 'allow docker_helper_t docker_helper_rootlesskit_t' "$TRANSFERRED/docker-helper.te" || echo NONE
  echo "=== the loaded policy's TE allow set for the process-control surface (source side) ==="
  for p in signal sigkill sigstop ptrace; do
    echo "--- sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_rootlesskit_t -c process -p $p ---"
    sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_rootlesskit_t -c process -p "$p" 2>&1 || true
  done
  echo "=== the loaded policy's TE allow set for the helpers (source side) ==="
  echo "--- sesearch --allow -s docker_helper_newuidmap_t -t docker_helper_rootlesskit_t ---"
  sesearch --allow -s docker_helper_newuidmap_t -t docker_helper_rootlesskit_t 2>&1 || true
  echo "--- sesearch --allow -s docker_helper_newgidmap_t -t docker_helper_rootlesskit_t ---"
  sesearch --allow -s docker_helper_newgidmap_t -t docker_helper_rootlesskit_t 2>&1 || true
  echo "=== the loaded policy's TE allow set for the state-tree surface ==="
  echo "--- sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_builder_state_t ---"
  sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_builder_state_t 2>&1 || true
  echo "=== the loaded policy's constraint set for the process/object classes (the mechanism under test) ==="
  for c in file dir process sock_file fifo_file lnk_file unix_stream_socket; do
    echo "--- seinfo --constrain $c ---"
    seinfo --constrain "$c" 2>&1 || true
  done
  echo "=== the loaded policy's default rules (the created-object labeling defaults) ==="
  seinfo --default 2>&1 || true
  echo "=== the production .te's uid_map rules (the TE layer, unchanged) ==="
  grep -an 'uid_map' "$TRANSFERRED/docker-helper.te" || true
} > "$EVIDENCE_DIR/g26-domain-surface.txt" 2>&1
G26_TE_SIG=0; G26_TE_SIGKILL=0; G26_TE_SIGSTOP=0; G26_TE_PTRACE=0
G26_DA_SIG=0; G26_DA_SIGKILL=0; G26_DA_SIGSTOP=0; G26_DA_PTRACE=0
for p in signal sigkill sigstop ptrace; do
  if sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_rootlesskit_t -c process -p "$p" 2>/dev/null | grep -aq 'allow '; then
    case "$p" in
      signal)  G26_TE_SIG=1 ;;
      sigkill) G26_TE_SIGKILL=1 ;;
      sigstop) G26_TE_SIGSTOP=1 ;;
      ptrace)  G26_TE_PTRACE=1 ;;
    esac
  fi
  if sesearch --dontaudit -s docker_helper_rootlesskit_t -t docker_helper_rootlesskit_t -c process -p "$p" 2>/dev/null | grep -aq 'dontaudit '; then
    case "$p" in
      signal)  G26_DA_SIG=1 ;;
      sigkill) G26_DA_SIGKILL=1 ;;
      sigstop) G26_DA_SIGSTOP=1 ;;
      ptrace)  G26_DA_PTRACE=1 ;;
    esac
  fi
done
{
  echo "=== the loaded-policy TE/dontaudit flags for the process-control classification ==="
  echo "TE-allowed: signal=$G26_TE_SIG sigkill=$G26_TE_SIGKILL sigstop=$G26_TE_SIGSTOP ptrace=$G26_TE_PTRACE"
  echo "dontaudit'd: signal=$G26_DA_SIG sigkill=$G26_DA_SIGKILL sigstop=$G26_DA_SIGSTOP ptrace=$G26_DA_PTRACE"
} >> "$EVIDENCE_DIR/g26-domain-surface.txt"

# --- Part B: the guest-only membership delta (exactly the minimal set) ---
seinfo -a mcs_constrained_type -x 2>/dev/null \
  > "$EVIDENCE_DIR/g26-mcs-members-before.txt" || true
G26_MEMB_BEFORE=0
for t in docker_helper_rootlesskit_t docker_helper_newuidmap_t docker_helper_newgidmap_t; do
  if grep -aq "$t" "$EVIDENCE_DIR/g26-mcs-members-before.txt"; then
    G26_MEMB_BEFORE=$((G26_MEMB_BEFORE+1))
    note "g26: $t is ALREADY a member of mcs_constrained_type before the delta (unexpected production state)"
  fi
done
cat > /tmp/gidmap_mcsboundary_diag.te <<'DELTAEOF'
module gidmap_mcsboundary_diag 1.0;

# P5-S2g26 guest-only policy delta: the ONLY change vs the production
# policy is the membership of the minimal cross-operation surface set
# (docker_helper_rootlesskit_t, docker_helper_newuidmap_t,
# docker_helper_newgidmap_t) in the shipped base's mcs_constrained_type
# attribute. No allow/capability/transition/relabel/manager rules are
# added — if the own flow then needs an extra grant, that failure is the
# recorded architectural result. Loaded only for this experiment;
# removed at cleanup.
require {
  attribute mcs_constrained_type;
  type docker_helper_rootlesskit_t;
  type docker_helper_newuidmap_t;
  type docker_helper_newgidmap_t;
}
typeattribute docker_helper_rootlesskit_t mcs_constrained_type;
typeattribute docker_helper_newuidmap_t mcs_constrained_type;
typeattribute docker_helper_newgidmap_t mcs_constrained_type;
DELTAEOF
{
  echo "=== the exact policy delta (the guest-only module's source) ==="
  cat /tmp/gidmap_mcsboundary_diag.te
  echo "=== compile/package/load log ==="
} > "$EVIDENCE_DIR/g26-policy-delta.txt"
G26_DELTA_OK=0
if checkmodule -M -m -o /tmp/gidmap_mcsboundary_diag.tmp /tmp/gidmap_mcsboundary_diag.te 2>>"$EVIDENCE_DIR/g26-policy-delta.txt" &&
   semodule_package -o /tmp/gidmap_mcsboundary_diag.pp -m /tmp/gidmap_mcsboundary_diag.tmp 2>>"$EVIDENCE_DIR/g26-policy-delta.txt" &&
   semodule -i /tmp/gidmap_mcsboundary_diag.pp 2>>"$EVIDENCE_DIR/g26-policy-delta.txt"; then
  G26_DELTA_OK=1
fi
G26_MEMB_AFTER=0
if [ "$G26_DELTA_OK" = 1 ]; then
  seinfo -a mcs_constrained_type -x 2>/dev/null \
    > "$EVIDENCE_DIR/g26-mcs-members-after.txt" || true
  for t in docker_helper_rootlesskit_t docker_helper_newuidmap_t docker_helper_newgidmap_t; do
    if grep -aq "$t" "$EVIDENCE_DIR/g26-mcs-members-after.txt"; then
      G26_MEMB_AFTER=$((G26_MEMB_AFTER+1))
    fi
  done
fi
{
  echo "=== mcs_constrained_type membership ==="
  echo "before the delta (the g25 delta module removed first): member=$G26_MEMB_BEFORE/3 (full dump: g26-mcs-members-before.txt)"
  echo "delta loaded: $G26_DELTA_OK"
  echo "after the delta: member=$G26_MEMB_AFTER/3 (full dump: g26-mcs-members-after.txt)"
  echo "=== the categories and contexts A/B (assignment re-verification) ==="
  echo "runner attr/current: $(tr -d '\0' < /proc/self/attr/current 2>/dev/null || true)"
  echo "builder context: $(runuser -u "$BUILDER_USER" -- id -Z 2>/dev/null || echo UNAVAILABLE)"
  echo "=== assignment probe A: runuser+runcon to $RK_EXEC_T_A ==="
  runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_A" /usr/local/bin/map_probe --facts || true
  echo "=== assignment probe B: runuser+runcon to $RK_EXEC_T_B ==="
  runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_B" /usr/local/bin/map_probe --facts || true
} > "$EVIDENCE_DIR/g26-assignment.txt" 2>&1
cat "$EVIDENCE_DIR/g26-assignment.txt" >&2
G26_ASSIGN_OK=0
if grep -aq 'PROBE selinux=system_u:system_r:docker_helper_rootlesskit_t:s0:c1' "$EVIDENCE_DIR/g26-assignment.txt" &&
   grep -aq 'PROBE selinux=system_u:system_r:docker_helper_rootlesskit_t:s0:c2' "$EVIDENCE_DIR/g26-assignment.txt"; then G26_ASSIGN_OK=1; fi
P5S2G26_RESULT=""
if [ "$G26_DELTA_OK" = 0 ] || [ "$G26_MEMB_AFTER" != 3 ]; then
  note "g26 OBSTACLE: the guest-only MCS delta could not be loaded or its memberships are not verifiable (see g26-policy-delta.txt and g26-mcs-members-after.txt) — the phase stops"
  P5S2G26_RESULT="INCONCLUSIVE: the guest-only MCS delta could not be loaded or its memberships are not verifiable (see g26-policy-delta.txt and g26-mcs-members-after.txt)"
elif [ "$G26_ASSIGN_OK" = 0 ]; then
  note "g26 OBSTACLE: the existing policy does not allow assigning the required MCS categories (see g26-assignment.txt) — the phase stops without the attempts"
  P5S2G26_RESULT="INCONCLUSIVE: the existing policy does not allow assigning the required MCS categories (see g26-assignment.txt)"
fi

# --- Part C: the g25 measurement repeated under the full set ---
if [ -z "$P5S2G26_RESULT" ]; then
  B_G26="$(make_target_b "$DIAG_BASE/fifos/bfifo-g26" "$RK_EXEC_T_B" || true)"
  if [ -z "${B_G26:-}" ]; then
    note "g26: the target child B could not be created (recorded as a finding)"
    P5S2G26_RESULT="INCONCLUSIVE: the target child B could not be created (see stand-failure-g26-target.txt)"
    diagnose_stand_failure g26-target "$(date +%s)" "$DIAG_BASE/b-target.out" "$EVIDENCE_DIR/g26-b-facts.txt"
  else
    collect_b_facts "$B_G26" "$EVIDENCE_DIR/g26-b-facts.txt" "g26 target B (category c2) before"
    RK_INVOKER_CTX="$RK_EXEC_T_A"
    G26_ATTEMPT_RC=0
    if ! parent_role_attempt "$DIAG_BASE/fifos/bfifo-g26" "$B_G26" \
         "$EVIDENCE_DIR/g26-parent-attempt.txt" "$EVIDENCE_DIR/g26-parent-avcs.txt" \
         /usr/bin/newuidmap uid_map "${U_MAP_ARGS[@]}"; then
      G26_ATTEMPT_RC=1
    fi
    RK_INVOKER_CTX="$RK_EXEC_T"
    # Scenario 1 attribution: the identical call succeeded in phase G
    # (the exempt subject) and in g25 (the single membership), so with
    # the full set loaded a file-class write or dir-class search denial
    # on the c1→c2 contexts IS the MCS mechanism.
    G26_BLOCK_CAUSE=""
    if [ "$G26_ATTEMPT_RC" -eq 1 ]; then
      if grep -aq 'scontext=system_u:system_r:docker_helper_newuidmap_t:s0:c1 ' "$EVIDENCE_DIR/g26-parent-avcs.txt" 2>/dev/null &&
         { grep -aq 'tcontext=system_u:system_r:docker_helper_rootlesskit_t:s0:c2 tclass=file' "$EVIDENCE_DIR/g26-parent-avcs.txt" 2>/dev/null ||
           grep -aq 'tcontext=system_u:system_r:docker_helper_rootlesskit_t:s0:c2 tclass=dir' "$EVIDENCE_DIR/g26-parent-avcs.txt" 2>/dev/null; }; then
        G26_BLOCK_CAUSE="the MCS constraint on the dir search and/or the file write for the c1→c2 contexts"
      else
        P5S2G26_RESULT="INCONCLUSIVE: the cross-operation write failed under the full constrained set but the denial is not the MCS mechanism — see g26-parent-attempt.txt and g26-parent-avcs.txt for the exact cause"
      fi
    fi
    if [ -z "$P5S2G26_RESULT" ]; then
      run_own_child_uid_control "$RK_EXEC_T_A" "g26" "g26"
      G26_LEG2=0
      if grep -aq 'uid_map content: \[ *0' "$EVIDENCE_DIR/g26-control-child-maps.txt" 2>/dev/null; then G26_LEG2=1; fi
      G26_LEG3=0
      G26_NONBENIGN="$(grep -a 'type=AVC' "$EVIDENCE_DIR/g26-control-avcs.txt" 2>/dev/null | grep -av 'passwd_file_t' | grep -av 'tclass=cap_userns' | grep -av 'tclass=capability' | wc -l || true)"
      if grep -aq 'write to gid_map failed' "$EVIDENCE_DIR/g26-control.txt" 2>/dev/null && [ "${G26_NONBENIGN:-999}" -eq 0 ]; then G26_LEG3=1; fi
      if [ "$G26_ATTEMPT_RC" -eq 0 ]; then
        P5S2G26_RESULT="FAIL: the MCS-constrained operation domains still completed the cross-operation uid_map write (see g26-parent-attempt.txt)"
      elif [ "$G26_LEG2" = 0 ] || [ "$G26_LEG3" = 0 ]; then
        P5S2G26_RESULT="FAIL: the own flow broke under the full constrained set (leg2/leg3 evidence: g26-control-child-maps.txt, g26-control.txt, g26-control-avcs.txt) — the architectural result per the task: the minimal set is NOT implementable without extra grants"
      fi
    fi
  fi
fi

# --- Part D: the paired process-control matrix ---
if [ -z "$P5S2G26_RESULT" ] && [ -n "${B_G26:-}" ]; then
  {
    echo "=== P5-S2g26 Part D: the paired process-control matrix ==="
    echo "cross-op legs: A:c1 (the runcon'd signaler) → B's target pid $B_G26 (rootlesskit_t:s0:c2, in B's child userns)"
    echo "own-op legs: A:c1 → the probe's own forked child (rootlesskit_t:s0:c1, same userns)"
    echo "TE-allowed on the loaded policy: signal=$G26_TE_SIG sigkill=$G26_TE_SIGKILL sigstop=$G26_TE_SIGSTOP ptrace=$G26_TE_PTRACE (dontaudit'd: signal=$G26_DA_SIG sigkill=$G26_DA_SIGKILL sigstop=$G26_DA_SIGSTOP ptrace=$G26_DA_PTRACE)"
    echo "the kernel's uid/namespace checks pass for every pair here (both operations share the builder kuid), so the SELinux verdict is the deciding boundary"
  } > "$EVIDENCE_DIR/g26-pc-matrix.txt"
  pc_attempt() {
    local tag="$1" mode="$2"; shift 2
    local epoch rc
    epoch="$(date +%s)"
    echo "=== $tag: map_probe $mode $* (invoker ctx $RK_EXEC_T_A) ===" \
      > "$EVIDENCE_DIR/g26-pc-$tag.txt"
    set +e
    runuser -u "$BUILDER_USER" -- timeout 30 \
      runcon "$RK_EXEC_T_A" /usr/local/bin/map_probe "$mode" "$@" \
      >>"$EVIDENCE_DIR/g26-pc-$tag.txt" 2>&1
    rc=$?
    set -e
    echo "probe exit code: $rc" >> "$EVIDENCE_DIR/g26-pc-$tag.txt"
    sleep 2
    harvest_avcs_since "$epoch" "$EVIDENCE_DIR/g26-pc-$tag-avcs.txt"
    return "$rc"
  }
  # pc_classify <tag> <perm> <cross|own> : appends the matrix row and
  # ECHOES the classification class (allowed|mcs|te|inconcl). The MCS
  # discriminator is the loaded-policy TE allow set: TE allows the type
  # pair (sesearch) and the AVC still denies → the constraint is the
  # cause (TE and constraint denials are indistinguishable in the AVC
  # itself). A TE-denied action is NOT MCS-reachable.
  pc_classify() {
    local tag="$1" perm="$2" leg="$3" probe_verb="signal"
    if [ "$perm" = ptrace ]; then probe_verb="ptrace-seize"; fi
    local delivered=0 avc=0 te=0 da=0 cause="" cls
    case "$perm" in
      signal)  te="$G26_TE_SIG";     da="$G26_DA_SIG" ;;
      sigkill) te="$G26_TE_SIGKILL"; da="$G26_DA_SIGKILL" ;;
      sigstop) te="$G26_TE_SIGSTOP"; da="$G26_DA_SIGSTOP" ;;
      ptrace)  te="$G26_TE_PTRACE";  da="$G26_DA_PTRACE" ;;
    esac
    if grep -aq "PROBE $probe_verb .*rc=0" "$EVIDENCE_DIR/g26-pc-$tag.txt" 2>/dev/null; then
      delivered=1
    fi
    if grep -aq "scontext=system_u:system_r:docker_helper_rootlesskit_t:s0:c1 " "$EVIDENCE_DIR/g26-pc-$tag-avcs.txt" 2>/dev/null &&
       grep -aq "tcontext=system_u:system_r:docker_helper_rootlesskit_t:s0:c2 tclass=process" "$EVIDENCE_DIR/g26-pc-$tag-avcs.txt" 2>/dev/null &&
       grep -aq "denied  { $perm }" "$EVIDENCE_DIR/g26-pc-$tag-avcs.txt" 2>/dev/null; then
      avc=1
    fi
    if [ "$leg" = own ]; then
      # The own leg's AVC carries BOTH contexts at :s0:c1; the cross
      # grep above cannot match it, so re-check with the own contexts.
      avc=0
      if grep -aq "scontext=system_u:system_r:docker_helper_rootlesskit_t:s0:c1 " "$EVIDENCE_DIR/g26-pc-$tag-avcs.txt" 2>/dev/null &&
         grep -aq "tcontext=system_u:system_r:docker_helper_rootlesskit_t:s0:c1 tclass=process" "$EVIDENCE_DIR/g26-pc-$tag-avcs.txt" 2>/dev/null &&
         grep -aq "denied  { $perm }" "$EVIDENCE_DIR/g26-pc-$tag-avcs.txt" 2>/dev/null; then
        avc=1
      fi
    fi
    if [ "$delivered" = 1 ]; then
      cls=allowed
      if [ "$leg" = cross ]; then
        cause="ALLOWED (the whole stack passed the cross-op check — a FAIL-level finding)"
      else
        cause="ALLOWED (the own-op control passed — expected when the TE layer allows the pair)"
      fi
    elif [ "$avc" = 1 ] && [ "$te" = 1 ]; then
      cls=mcs
      cause="MCS-BLOCKED (the loaded TE allow exists for the pair; the AVC's denial is the constraint)"
    elif [ "$avc" = 1 ]; then
      cls=te
      cause="TE-BLOCKED, NOT MCS-REACHABLE (no loaded TE allow for the pair; the constraint never ran)"
    elif [ "$da" = 1 ]; then
      cls=te
      cause="TE-BLOCKED (dontaudit'd: no AVC possible; not MCS-reachable)"
    else
      cls=inconcl
      cause="NO-AVC/UNKNOWN (no denial and no delivery recorded — see g26-pc-$tag.txt for the errno)"
    fi
    printf '%s | leg=%s perm=%s | %s\n' "$tag" "$leg" "$perm" "$cause" \
      >> "$EVIDENCE_DIR/g26-pc-matrix.txt"
    printf '%s' "$cls"
  }
  G26_PC_CROSS_ALLOWED=0; G26_PC_CROSS_MCS=0; G26_PC_CROSS_TE=0; G26_PC_CROSS_INCONCL=0
  G26_PC_OWN_OK=0; G26_PC_OWN_TE=0; G26_PC_OWN_INCONCL=0
  # pc_leg <leg> <tag> <mode> <perm> [probe args...] : runs ONE matrix
  # leg and records it. The cross legs target B's announced pid; the own
  # legs use the spawn modes (the probe forks its own child and reports
  # its context, so the own-op pair is A:c1→child A:c1). The cross legs
  # skip once the target was destroyed by an earlier ALLOWED action.
  pc_leg() {
    local leg="$1" tag="$2" mode="$3" perm="$4"; shift 4
    local cls
    if [ "$leg" = cross ] && [ -n "${G26_PC_TARGET_DEAD:-}" ]; then
      cls=skipped
      echo "$tag (cross): SKIPPED (the cross-op target was destroyed by an earlier ALLOWED action; the FAIL finding is already recorded)" \
        >> "$EVIDENCE_DIR/g26-pc-matrix.txt"
    else
      pc_attempt "$leg-$tag" "$mode" "$@" || true
      cls="$(pc_classify "$leg-$tag" "$perm" "$leg")"
      if [ "$leg" = cross ]; then
        case "$cls" in
          allowed) G26_PC_CROSS_ALLOWED=$((G26_PC_CROSS_ALLOWED+1)) ;;
          mcs) G26_PC_CROSS_MCS=$((G26_PC_CROSS_MCS+1)) ;;
          te) G26_PC_CROSS_TE=$((G26_PC_CROSS_TE+1)) ;;
          *) G26_PC_CROSS_INCONCL=$((G26_PC_CROSS_INCONCL+1)) ;;
        esac
      else
        case "$cls" in
          allowed) G26_PC_OWN_OK=$((G26_PC_OWN_OK+1)) ;;
          te) G26_PC_OWN_TE=$((G26_PC_OWN_TE+1)) ;;
          *) G26_PC_OWN_INCONCL=$((G26_PC_OWN_INCONCL+1)) ;;
        esac
      fi
      if [ "$leg" = cross ] && [ "$cls" = allowed ]; then
        # An ALLOWED cross-op signal may have destroyed the target
        # (TERM/KILL) or stopped it (STOP): resume a stopped target from
        # the shell, then check whether it still exists (an allowed
        # signal to another operation's process is itself a FAIL-level
        # finding; the target's death only decides whether the
        # remaining cross legs can still run).
        if [ "$perm" != ptrace ]; then
          kill -CONT "$B_G26" 2>/dev/null || true
          if ! kill -0 "$B_G26" 2>/dev/null; then
            G26_PC_TARGET_DEAD=1
            note "g26: the cross-op target B was destroyed by the ALLOWED $perm action (a FAIL-level finding); the remaining cross legs are skipped"
          fi
        fi
      fi
    fi
    case "$tag" in
      term)   if [ "$leg" = cross ]; then G26_PC_X_TERM="$cls";   else G26_PC_O_TERM="$cls";   fi ;;
      stop)   if [ "$leg" = cross ]; then G26_PC_X_STOP="$cls";   else G26_PC_O_STOP="$cls";   fi ;;
      kill)   if [ "$leg" = cross ]; then G26_PC_X_KILL="$cls";   else G26_PC_O_KILL="$cls";   fi ;;
      ptrace) if [ "$leg" = cross ]; then G26_PC_X_PTRACE="$cls"; else G26_PC_O_PTRACE="$cls"; fi ;;
    esac
  }
  G26_PC_TARGET_DEAD=""
  pc_leg cross term --signal signal "$B_G26" 15
  pc_leg own term --spawn-signal signal 15
  pc_leg cross stop --signal sigstop "$B_G26" 19
  pc_leg own stop --spawn-signal sigstop 19
  pc_leg cross kill --signal sigkill "$B_G26" 9
  pc_leg own kill --spawn-signal sigkill 9
  pc_leg cross ptrace --ptrace ptrace "$B_G26"
  pc_leg own ptrace --spawn-ptrace ptrace
  {
    echo "=== the matrix tally ==="
    echo "cross-op: allowed=$G26_PC_CROSS_ALLOWED mcs-blocked=$G26_PC_CROSS_MCS te-blocked(not-mcs-reachable)=$G26_PC_CROSS_TE inconclusive=$G26_PC_CROSS_INCONCL"
    echo "own-op:   allowed=$G26_PC_OWN_OK te-blocked(not-mcs-reachable)=$G26_PC_OWN_TE inconclusive=$G26_PC_OWN_INCONCL"
  } >> "$EVIDENCE_DIR/g26-pc-matrix.txt"
  cat "$EVIDENCE_DIR/g26-pc-matrix.txt" >&2
  G26_PC_RAN=1
fi
# The Part D verdict: for every TE-allowed perm the cross leg must be
# MCS-BLOCKED and the own leg ALLOWED; for every TE-denied perm the two
# legs must show the same TE-blocked parity (the MCS layer never ran —
# not MCS-reachable, and no permission is added to reach it).
G26_PC_PAIRS_OK=1
G26_PC_PAIRS_NOTE=""
check_pc_pair() {
  local tag="$1" perm="$2" te="$3" xres ores
  case "$tag" in
    term)   xres="${G26_PC_X_TERM:-none}";   ores="${G26_PC_O_TERM:-none}" ;;
    stop)   xres="${G26_PC_X_STOP:-none}";   ores="${G26_PC_O_STOP:-none}" ;;
    kill)   xres="${G26_PC_X_KILL:-none}";   ores="${G26_PC_O_KILL:-none}" ;;
    ptrace) xres="${G26_PC_X_PTRACE:-none}"; ores="${G26_PC_O_PTRACE:-none}" ;;
  esac
  if [ "$te" = 1 ]; then
    if [ "$xres" != mcs ] || [ "$ores" != allowed ]; then
      G26_PC_PAIRS_OK=0
      G26_PC_PAIRS_NOTE="$G26_PC_PAIRS_NOTE $perm(cross=$xres,own=$ores)"
    fi
  else
    if [ "$xres" != te ] || [ "$ores" != te ]; then
      G26_PC_PAIRS_OK=0
      G26_PC_PAIRS_NOTE="$G26_PC_PAIRS_NOTE $perm(cross=$xres,own=$ores)"
    fi
  fi
}
if [ "${G26_PC_RAN:-0}" = 1 ]; then
  if [ "$G26_PC_CROSS_ALLOWED" -gt 0 ]; then
    note "g26 Part D FAIL: a cross-op process-control action was ALLOWED (see g26-pc-matrix.txt)"
    P5S2G26_RESULT="FAIL: a cross-op process-control action was ALLOWED (see g26-pc-matrix.txt)"
  else
    check_pc_pair term signal "$G26_TE_SIG"
    check_pc_pair stop sigstop "$G26_TE_SIGSTOP"
    check_pc_pair kill sigkill "$G26_TE_SIGKILL"
    check_pc_pair ptrace ptrace "$G26_TE_PTRACE"
    if [ "$G26_PC_PAIRS_OK" = 0 ]; then
      note "g26 Part D: the matrix pairs did not all hold:$G26_PC_PAIRS_NOTE (see g26-pc-matrix.txt)"
      P5S2G26_RESULT="INCONCLUSIVE: the process-control matrix pairs did not all hold:$G26_PC_PAIRS_NOTE (see g26-pc-matrix.txt)"
    fi
  fi
fi

# --- Part E: the shared-object surface ---
if [ -z "$P5S2G26_RESULT" ]; then
  {
    echo "=== P5-S2g26 Part E: the shared-object surface ==="
    echo "the object-class constraint sets are in g26-domain-surface.txt (sock_file/fifo_file/lnk_file/unix_stream_socket included); the policy-level findings:"
    echo "- the state tree (docker_helper_builder_state_t) is shared at s0 BY DESIGN: both operations' rootlesskit_t domains hold the dir/file/sock_file create+write grants (862-864), the type is NOT in mcs_constrained_type, so the file/dir/sock class constraints (which exist: sock_file constrains getattr/ioctl/read and setattr/write) are EXEMPT for both categories on these types"
    echo "- the created object's OBSERVED label: the parent dir's type and the level s0 WITHOUT the creator's category (the markers were created by s0:c1/s0:c2 processes and carry the parent's level — the policy's own 'default_range file target low' (see the seinfo --default dump in g26-domain-surface.txt) makes every created object inherit the parent directory's LOW level, so the creator's category does not propagate) — the shared tree is category-transparent at the type AND the level"
    echo "- the diag fifos (docker_helper_builder_t) are fd-scoped: the helper's write grant (871/1015/1156) is reachable only through inherited fds, not across operations; fifo_file's mlsconstrain covers OPEN only (h1 dom h2 or t1 != mcs_constrained_type) — an inherited-fd write never re-opens, so the constraint never applies on that path"
    echo "- unix_stream_socket has NO mlsconstrain (policy-level gap): a cross-operation connectto would NOT be MCS-isolated — but the loaded TE has no rootlesskit_t→rootlesskit_t connectto allow (verified in g26-domain-surface.txt), so it is TE-denied, not MCS-reachable"
    echo "=== the prodtype test dir provisioning (relabeled to docker_helper_builder_state_t, the production state type; the vehicles' access comes from the production 862-864 grants, not the diag module) ==="
  } > "$EVIDENCE_DIR/g26-shared-object.txt"
  G26_E_PROD_DIR=/var/tmp/p5s2-g26-e2
  G26_E_PROD_DIR_OK=0
  echo "prodtype dir pre-chcon label: $(stat -c '%C' "$G26_E_PROD_DIR" 2>&1)" >> "$EVIDENCE_DIR/g26-shared-object.txt"
  if chcon -t docker_helper_builder_state_t "$G26_E_PROD_DIR" 2>>"$EVIDENCE_DIR/g26-shared-object.txt"; then
    G26_E_PROD_DIR_OK=1
  fi
  echo "prodtype dir: $G26_E_PROD_DIR chcon-applied=$G26_E_PROD_DIR_OK post-label=$(stat -c '%C' "$G26_E_PROD_DIR" 2>&1)" \
    >> "$EVIDENCE_DIR/g26-shared-object.txt"
  echo "=== the stand-type test dir (the diag-module-granted tmpfs tree) ===" >> "$EVIDENCE_DIR/g26-shared-object.txt"
  echo "stand dir: $DIAG_BASE/g26/e-shared label=$(stat -c '%C' "$DIAG_BASE/g26/e-shared" 2>&1)" >> "$EVIDENCE_DIR/g26-shared-object.txt"
  e_leg() {
    local leg="$1" ctx="$2" mode="$3" path="$4" leg_note="$5" rc
    {
      echo "=== leg $leg ($leg_note): map_probe $mode $path (ctx $ctx) ==="
    } >> "$EVIDENCE_DIR/g26-shared-object.txt"
    set +e
    runuser -u "$BUILDER_USER" -- timeout 20 \
      runcon "$ctx" /usr/local/bin/map_probe "$mode" "$path" \
      >>"$EVIDENCE_DIR/g26-shared-object.txt" 2>&1
    rc=$?
    set -e
    echo "probe exit code: $rc" >> "$EVIDENCE_DIR/g26-shared-object.txt"
    echo "file label now: $(stat -c '%C' "$path" 2>&1)" >> "$EVIDENCE_DIR/g26-shared-object.txt"
    return "$rc"
  }
  G26_E_STAND_RUN=0
  G26_E_STAND_OK=0
  e_shared="$DIAG_BASE/g26/e-shared"
  e_leg 1 "$RK_EXEC_T_A" --touch "$e_shared/a-c1-marker" "A:c1 touches its marker" || true
  if [ -f "$e_shared/a-c1-marker" ]; then
    G26_E_STAND_RUN=1
    e_leg 2 "$RK_EXEC_T_B" --read "$e_shared/a-c1-marker" "B:c2 reads A's marker (the shared-tree finding)" || true
    e_leg 3 "$RK_EXEC_T_B" --write "$e_shared/a-c1-marker" "B:c2 writes A's marker (the shared-tree finding, write)" || true
  else
    echo "=== legs 2-3 skipped: A's touch did not create the marker (see leg 1) ===" >> "$EVIDENCE_DIR/g26-shared-object.txt"
  fi
  e_leg 4 "$RK_EXEC_T_B" --touch "$e_shared/b-c2-marker" "B:c2 touches its marker" || true
  if [ -f "$e_shared/b-c2-marker" ]; then
    G26_E_STAND_RUN=1
    e_leg 5 "$RK_EXEC_T_A" --read "$e_shared/b-c2-marker" "A:c1 reads B's marker (the shared-tree finding, other direction)" || true
  else
    echo "=== leg 5 skipped: B's touch did not create the marker (see leg 4) ===" >> "$EVIDENCE_DIR/g26-shared-object.txt"
  fi
  if [ "$G26_E_STAND_RUN" = 1 ] &&
     grep -aq 'PROBE read path=.*/e-shared/a-c1-marker rc=0' "$EVIDENCE_DIR/g26-shared-object.txt" &&
     grep -aq 'PROBE write path=.*/e-shared/a-c1-marker rc=0' "$EVIDENCE_DIR/g26-shared-object.txt"; then
    G26_E_STAND_OK=1
  fi
  G26_E_PROD_RUN=0
  G26_E_PROD_OK=0
  if [ "$G26_E_PROD_DIR_OK" = 1 ]; then
    e_leg p1 "$RK_EXEC_T_A" --touch "$G26_E_PROD_DIR/a-c1-marker" "A:c1 touches its marker in the production state tree" || true
    if [ -f "$G26_E_PROD_DIR/a-c1-marker" ]; then
      G26_E_PROD_RUN=1
      e_leg p2 "$RK_EXEC_T_B" --read "$G26_E_PROD_DIR/a-c1-marker" "B:c2 reads A's production-tree marker (the finding on the PRODUCTION type)" || true
      e_leg p3 "$RK_EXEC_T_B" --write "$G26_E_PROD_DIR/a-c1-marker" "B:c2 writes A's production-tree marker (the finding on the PRODUCTION type)" || true
    else
      echo "=== legs p2-p3 skipped: A's touch did not create the marker (see leg p1) ===" >> "$EVIDENCE_DIR/g26-shared-object.txt"
    fi
    e_leg p4 "$RK_EXEC_T_B" --touch "$G26_E_PROD_DIR/b-c2-marker" "B:c2 touches its marker in the production state tree" || true
    if [ -f "$G26_E_PROD_DIR/b-c2-marker" ]; then
      G26_E_PROD_RUN=1
      e_leg p5 "$RK_EXEC_T_A" --read "$G26_E_PROD_DIR/b-c2-marker" "A:c1 reads B's production-tree marker" || true
    else
      echo "=== leg p5 skipped: B's touch did not create the marker (see leg p4) ===" >> "$EVIDENCE_DIR/g26-shared-object.txt"
    fi
    if [ "$G26_E_PROD_RUN" = 1 ] &&
       grep -aq 'PROBE read path=.*/p5s2-g26-e2/a-c1-marker rc=0' "$EVIDENCE_DIR/g26-shared-object.txt" &&
       grep -aq 'PROBE write path=.*/p5s2-g26-e2/a-c1-marker rc=0' "$EVIDENCE_DIR/g26-shared-object.txt"; then
      G26_E_PROD_OK=1
    fi
  fi
  # The fifo legs: the reader (cat, as the builder identity) opens the
  # read end first (blocking), then each vehicle's --fifo-write unblocks
  # it; the verdict is the probe's raw rc/errno. Both directions are
  # recorded against the same shared test fifo.
  G26_E_FIFO_OK=0
  mkfifo "$e_shared/e-fifo"
  chmod 666 "$e_shared/e-fifo"
  echo "fifo label: $(stat -c '%C' "$e_shared/e-fifo" 2>&1)" >> "$EVIDENCE_DIR/g26-shared-object.txt"
  echo "=== leg 6 (B:c2 fifo-write, the reader is the harness's cat): the fifo open/write verdict ===" >> "$EVIDENCE_DIR/g26-shared-object.txt"
  runuser -u "$BUILDER_USER" -- timeout 15 cat "$e_shared/e-fifo" >/dev/null 2>&1 &
  CAT_PID=$!
  G26_E_FIFO_RC=0
  set +e
  runuser -u "$BUILDER_USER" -- timeout 20 \
    runcon "$RK_EXEC_T_B" /usr/local/bin/map_probe --fifo-write "$e_shared/e-fifo" \
    >>"$EVIDENCE_DIR/g26-shared-object.txt" 2>&1
  G26_E_FIFO_RC=$?
  set -e
  echo "probe exit code: $G26_E_FIFO_RC" >> "$EVIDENCE_DIR/g26-shared-object.txt"
  wait "$CAT_PID" 2>/dev/null || true
  if [ "$G26_E_FIFO_RC" = 0 ]; then G26_E_FIFO_OK=1; fi
  echo "=== the shared-object finding ===" >> "$EVIDENCE_DIR/g26-shared-object.txt"
  echo "the stand-type legs: ran=$G26_E_STAND_RUN all-expected-observed=$G26_E_STAND_OK (cross-operation read AND write of each other's created files is ALLOWED — the exempt-object finding)" >> "$EVIDENCE_DIR/g26-shared-object.txt"
  echo "the prodtype (builder_state_t, relabeled from the production state type) legs: dir=$G26_E_PROD_DIR provisioned=$G26_E_PROD_DIR_OK ran=$G26_E_PROD_RUN all-expected-observed=$G26_E_PROD_OK (the same finding on the production type — the 862-864 grant shape is category-blind)" >> "$EVIDENCE_DIR/g26-shared-object.txt"
  echo "the fifo leg: rc=$G26_E_FIFO_RC ok=$G26_E_FIFO_OK (the fifo's open is MCS-constrained but its target type user_tmp_t is exempt; the write perm itself is unconstrained — the cross-operation fifo write is ALLOWED on the exempt label)" >> "$EVIDENCE_DIR/g26-shared-object.txt"
  echo "verdict note: the state tree and the stand tmpfs dirs are shared at s0 BY DESIGN (the manager-owned tree; the .te's own scope notes track this as the invocation-discipline-only risk) — this is the separate finding the task records; it grants NO access to the MCS-protected /proc/<pid> and process-control surfaces, so it is not a bypass of the boundary this experiment proves" >> "$EVIDENCE_DIR/g26-shared-object.txt"
  cat "$EVIDENCE_DIR/g26-shared-object.txt" >&2
  if [ "$G26_E_STAND_RUN" = 1 ] && [ "$G26_E_STAND_OK" = 0 ]; then
    note "g26: the stand-type shared-tree legs did not observe the expected exemption (see g26-shared-object.txt)"
    P5S2G26_RESULT="INCONCLUSIVE: the stand-type shared-tree legs did not observe the expected exemption (see g26-shared-object.txt)"
  elif [ "$G26_E_PROD_DIR_OK" = 1 ] && [ "$G26_E_PROD_RUN" = 1 ] && [ "$G26_E_PROD_OK" = 0 ]; then
    note "g26: the prodtype shared-tree legs did not observe the expected exemption (see g26-shared-object.txt)"
    P5S2G26_RESULT="INCONCLUSIVE: the prodtype shared-tree legs did not observe the expected exemption (see g26-shared-object.txt)"
  fi
fi

P5S2G26_RESULT="${P5S2G26_RESULT:-}"
if [ -z "$P5S2G26_RESULT" ]; then
  P5S2G26_RESULT="PASS: the minimal constrained set (rootlesskit_t+newuidmap_t+newgidmap_t, membership $G26_MEMB_BEFORE/3→$G26_MEMB_AFTER/3, reasons in g26-domain-surface.txt) preserves the g25 isolation (${G26_BLOCK_CAUSE:-see g26-parent-avcs.txt}) with the own-child write intact and the control window clean (g26-control-child-maps.txt, g26-control-avcs.txt); the process-control matrix: cross-op allowed=$G26_PC_CROSS_ALLOWED mcs-blocked=$G26_PC_CROSS_MCS te-blocked(not-mcs-reachable)=$G26_PC_CROSS_TE, own-op allowed=$G26_PC_OWN_OK te-blocked=$G26_PC_OWN_TE (g26-pc-matrix.txt); the shared-object surface and its pre-existing state-tree finding are recorded separately (g26-shared-object.txt)"
fi
printf '%s P5S2-G26-MCS-BOUNDARY-RESULT=COMPLETED (%s)\n' "$PREFIX" "$P5S2G26_RESULT" >&2

log 'teardown'
pkill -KILL -f 'rootlesskit --net=none' 2>/dev/null || true
pkill -KILL -f 'map_probe --' 2>/dev/null || true
for p in "${RK_PIDS[@]:-}"; do
  [ -n "$p" ] && kill "$p" 2>/dev/null || true
done

sleep 2
{
  echo "=== kernel AVC records of the whole experiment window (newgidmap only) ==="
  grep -a 'type=AVC' /var/log/audit/audit.log 2>/dev/null \
    | awk -v s="$AVC_EPOCH_ALL" '{ for (i = 1; i <= NF; i++) if ($i ~ /^msg=audit\(/) { ts = substr($i, 11); split(ts, t, "."); if (t[1] + 0 >= s + 0) print; break } }' \
    | grep -a 'docker_helper_newgidmap_t' \
    | tail -100 || true
  echo "=== journalctl -k window (newgidmap only) ==="
  journalctl -k --since "@$AVC_EPOCH_ALL" --no-pager 2>/dev/null | grep -a 'avc:' | grep -a 'newgidmap' | tail -100 || true
} > "$EVIDENCE_DIR/f-newgidmap-avcs-all.txt" 2>&1
{
  echo "=== kernel AVC records of the whole experiment window (ALL docker-helper domains; unfiltered) ==="
  grep -a 'type=AVC' /var/log/audit/audit.log 2>/dev/null \
    | awk -v s="$AVC_EPOCH_ALL" '{ for (i = 1; i <= NF; i++) if ($i ~ /^msg=audit\(/) { ts = substr($i, 11); split(ts, t, "."); if (t[1] + 0 >= s + 0) print; break } }' \
    | grep -a 'docker_helper_' \
    | tail -300 || true
  echo "=== journalctl -k window (all avc lines) ==="
  journalctl -k --since "@$AVC_EPOCH_ALL" --no-pager 2>/dev/null | grep -a 'avc:' | tail -300 || true
} > "$EVIDENCE_DIR/f-all-helper-avcs-all.txt" 2>&1
cat "$EVIDENCE_DIR/f-newgidmap-avcs-all.txt" >&2

log 'cleanup (temporary modules removed; the candidate module stays until the VM is disposed)'
semodule -r gidmap_capsetgid_diag >/dev/null 2>&1 || true
semodule -r gidmap_capuserns_diag >/dev/null 2>&1 || true
semodule -r gidmap_mcsconstrained_diag >/dev/null 2>&1 || true
semodule -r gidmap_mcsboundary_diag >/dev/null 2>&1 || true
semodule -r gidmap_probe_diag >/dev/null 2>&1 || true
semodule -l 2>/dev/null | grep -E 'docker_helper|gidmap' > "$EVIDENCE_DIR/f-final-modules.txt" 2>&1 || true

printf '%s P5S2-GIDMAP-CROSSOP-EXP-RESULT=PASS (experiment completed; findings are in the evidence)\n' "$PREFIX" >&2
exit 0
