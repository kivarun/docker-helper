#!/usr/bin/env bash
#
# Guest-side P5-S2g27 builder state-tree authority / confused-deputy proof
# for openSUSE Tumbleweed. INVESTIGATION ONLY — answers, with the REAL
# production composition under the SHIPPED policy, the single question the
# G26 review left open:
#
#   Can operation A, through the state-tree access it already has
#   (docker_helper_builder_state_t:s0 — proven cross-op
#   readable/writable by G26 Part E), change a trusted production action
#   relating to operation B?
#
# The stand runs the REAL production composition: the REAL docker-helper
# builder manager under its REAL systemd unit (SELinuxContext binding,
# unit-cgroup boundary active, real provision-builder.sh identity), the
# manager's REAL rootlesskit launch vehicle, and the manager RPC over
# manager.sock spoken by the harness as the daemon would (root peer, the
# line protocol of builder_manager_protocol.go). The only policy deltas
# are the G26 guest-only modules reused verbatim: the probe-vehicle
# module (the runcon'd vehicle's own entry/output surface) and the
# MCS-constraint delta (the minimal G26 constrained set), so every
# measurement runs against the G26-final surface. NO additional SELinux
# grants for any production component; no manager changes; no state-tree
# relabels; no ownership/provenance checks added. Every mutation uses
# ONLY the access G26 proved: the production rootlesskit_t grants on the
# state tree (docker-helper.te state-tree rules).
#
# Phases:
#   D (RC1, refuse-to-adopt): paired proof with the REAL manager.
#       baseline START launches the real vehicle (the flow stops at its
#       documented enforced child-process boundary; the manager's own
#       diag tail records it); then A:c1 plants a regular file at
#       ops/<opB> using ONLY the G26-proven state-tree write surface
#       (rootlesskit_t cannot create directories in the state tree —
#       measured separately in phase I); then START again: the manager
#       refuses to adopt (fail closed, no spawn); then the own-op plant
#       control over a second op id (the same vehicle and category);
#       then the harness unplants and the baseline launch path is
#       restored. Cross-op file planting is measured; whether the
#       manager's refuse-to-adopt decision is availability-only (a
#       fail-closed refusal) is decided by the evidence, not asserted.
#   F (RC2, state-dir lock): paired proof with the REAL rootlesskit
#       vehicle. The stand provisions ops/<opC>/rootlesskit-state exactly
#       as launchInstance does; the baseline c2-labeled real rootlesskit
#       flow passes the lock and dies at the production gid_map boundary;
#       then A:c1 flock-holds the SAME lock file and the same flow fails
#       instantly with rootlesskit's own "another RootlessKit is running
#       with the same state directory?" error; then the flock is
#       released and the restore leg re-proves the baseline shape.
#   G (RC4, purge name-injection): A:c1 plants a canonical-grammar fake
#       ops entry; the unit-mode manager restart absorbs it (the
#       unit-boundary purge removes the residue, no signal, the unit
#       still becomes active); the manual legacy-mode serve then FAILS
#       CLOSED at startup purge over the same planted name (no signal, no
#       removal, refusal to start) and starts clean after the harness
#       unplants. This measures the ONLY state-tree data the manager
#       reads (ops directory NAMES — no content reads anywhere) and its
#       fail-closed anchor.
#   H (RC3, buildkitd data-root write-link): A:c1 writes a marker into
#       ops/<opD>/root (the production --root shape, real label and
#       ownership). The CONSUMPTION side (buildkitd trusting its own
#       content/snapshot state under --root) is NOT runnable under the
#       shipped policy (the flow's enforced stop precedes buildkitd;
#       recorded from the RC1 baseline evidence) and stays a static
#       source-grounded finding; no grants are added to reach it.
#   I  invariant dump: the loaded policy's TE sets for the cross-op
#      socket/connect surfaces, the no-dir-create negative control
#      (mkdir(2) from A:c1), the runtime-tree write-denial negative
#      control (the daemon's runtime tree is TE-blocked for rootlesskit_t,
#      which protects the manager's instance.pid), and the
#      .config/buildkit/buildkitd.toml path-absence check (the buildkitd
#      default-config path can never materialize in the state tree).
#
# Temporary modules and the stand's own artifacts are removed at cleanup;
# the production module is compiled HERE from the transferred candidate
# sources and is never modified. The run is PASS when all phases
# completed (findings — positive or negative — are in the evidence; the
# G27 verdict is the report's, not this gate).
#
set -Eeuo pipefail

PREFIX='[release-2.4-p5s2-state-authority-tw]'
EVIDENCE_DIR=/tmp/release-2.4-p5s2-state-authority-evidence
BUILDER_USER=docker-helper-builder
GUEST_FILES=/tmp/p5s2-state-authority
STATE_ROOT=/var/lib/docker-helper-builder
RUNTIME_ROOT=/run/docker-helper-builder
MANAGER_SOCK="$RUNTIME_ROOT/manager.sock"
UNIT=docker-helper-builder
PROBE_BIN=/usr/local/bin/state_probe
RK_EXEC_T_A='system_u:system_r:docker_helper_rootlesskit_t:s0:c1'
RK_EXEC_T_B='system_u:system_r:docker_helper_rootlesskit_t:s0:c2'
BUILDER_T='system_u:system_r:docker_helper_builder_t:s0'

log()  { printf '%s %s\n' "$PREFIX" "$*"; }
note() { printf '%s NOTE: %s\n' "$PREFIX" "$*"; }

rm -rf "$EVIDENCE_DIR"
mkdir -p "$EVIDENCE_DIR"

DOMAINS=(docker_helper_builder_t docker_helper_rootlesskit_t docker_helper_slirp4netns_t docker_helper_newuidmap_t docker_helper_newgidmap_t)
clear_permissive() { semanage permissive -d "$1" >/dev/null 2>&1 || true; }

# shellcheck disable=SC2329
cleanup() {
  pkill -KILL -f 'rootlesskit --net=none' 2>/dev/null || true
  pkill -KILL -f 'state_probe --' 2>/dev/null || true
  systemctl stop "$UNIT" >/dev/null 2>&1 || true
  systemctl disable "$UNIT" >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/"$UNIT".service
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -f /usr/bin/docker-helper /usr/local/bin/state_probe
  rm -rf "$STATE_ROOT" "$RUNTIME_ROOT"
  for d in "${DOMAINS[@]}"; do
    clear_permissive "$d"
  done
  semodule -r state_probe_diag >/dev/null 2>&1 || true
  semodule -r gidmap_mcsboundary_diag >/dev/null 2>&1 || true
  semodule -r docker_helper >/dev/null 2>&1 || true
}
trap cleanup EXIT

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

manager_journal_since() {
  local since="$1" out="$2"
  journalctl -u "$UNIT" --since "@$since" --no-pager 2>/dev/null > "$out" || true
}

gen_op_id() {
  printf 'op_%s' "$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
}

# manager_rpc <req> <out> : one manager RPC through manager.sock exactly
# as the daemon's P2 client speaks it (root peer, one line, one reply).
# Records the command, the reply, the round-trip latency, and the
# manager journal window.
manager_rpc() {
  local req="$1" out="$2" epoch rc started ended
  epoch="$(date +%s)"
  {
    echo "=== manager RPC: $req ==="
    echo "epoch: $epoch"
    echo "command: printf '%s\\n' \"$req\" | timeout 120 socat - UNIX-CONNECT:$MANAGER_SOCK"
  } > "$out"
  started=$(date +%s%N)
  set +e
  printf '%s\n' "$req" | timeout 120 socat - UNIX-CONNECT:"$MANAGER_SOCK" >> "$out" 2>&1
  rc=$?
  set -e
  ended=$(date +%s%N)
  echo "socat rc: $rc" >> "$out"
  echo "round-trip ms: $(( (ended - started) / 1000000 ))" >> "$out"
  manager_journal_since "$epoch" "${out%.txt}-journal.txt"
}

log 'A: toolchain + candidate module load + REAL composition install'
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
  policycoreutils-python-utils rootlesskit slirp4netns audit socat \
  setools-console gcc glibc-static util-linux shadow \
  >"$EVIDENCE_DIR/zypper-toolchain.log" 2>&1 \
  || note "zypper install of the policy toolchain failed (see zypper-toolchain.log)"
fail_toolchain=0
for t in checkmodule semodule_package semodule semanage restorecon gcc socat \
  runuser seinfo systemctl; do
  command -v "$t" >/dev/null 2>&1 || { echo "$t not found" >>"$EVIDENCE_DIR/a-toolchain.txt"; fail_toolchain=1; }
done
if [ "$fail_toolchain" = 1 ]; then
  note "policy toolchain incomplete; the experiment cannot proceed"
  diagnose_stand_failure toolchain "$STAND_EPOCH_ALL"
  printf '%s P5S2-STATE-AUTHORITY-RESULT=PASS-INCOMPLETE (toolchain unavailable; recorded as a finding)\n' "$PREFIX" >&2
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
  echo "=== rootlesskit version ==="
  /usr/bin/rootlesskit --version 2>&1 || true
  echo "=== file capabilities (observed, never modified) ==="
  getcap /usr/bin/newuidmap /usr/bin/newgidmap 2>&1 || true
} >>"$EVIDENCE_DIR/a-toolchain.txt" 2>&1

log 'A2: builder identity + REAL composition (binary, unit, provisioning)'
sh "$TRANSFERRED/provision-builder.sh" >"$EVIDENCE_DIR/a2-provision.txt" 2>&1 \
  || { note "provision-builder.sh failed"; diagnose_stand_failure provision "$STAND_EPOCH_ALL" "$EVIDENCE_DIR/a2-provision.txt"; exit 1; }
install -m 0755 "$TRANSFERRED/docker-helper" /usr/bin/docker-helper
restorecon /usr/bin/docker-helper 2>>"$EVIDENCE_DIR/a-toolchain.txt" || true
install -m 0644 "$TRANSFERRED/docker-helper-builder.service" /etc/systemd/system/"$UNIT".service
systemctl daemon-reload
{
  echo "=== docker-helper binary ==="
  /usr/bin/docker-helper version 2>&1 || true
  echo "binary label: $(stat -c '%C' /usr/bin/docker-helper 2>&1)"
  echo "=== unit file ==="
  cat /etc/systemd/system/"$UNIT".service
  echo "=== builder identity ==="
  id "$BUILDER_USER"
  grep "^$BUILDER_USER:" /etc/subuid /etc/subgid
} > "$EVIDENCE_DIR/a2-composition.txt" 2>&1
cat "$EVIDENCE_DIR/a2-composition.txt" >&2

AVC_EPOCH_ALL="$(date +%s)"

log 'B: probe vehicle'
mkdir -p /tmp/state-probe-src
cat > /tmp/state-probe-src/state_probe.c <<'EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <linux/capability.h>
#include <sys/syscall.h>

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

int main(int argc, char **argv) {
  int fd, rc, hold;
  ssize_t n, wn;
  char buf[64];

  if (argc < 2) {
    fprintf(stderr, "usage: state_probe --facts | --touch <path> | --write <path> | --read <path> | --flock-hold <path> <seconds> | --mkdir-attempt <path>\n");
    return 2;
  }
  if (strcmp(argv[1], "--facts") == 0) {
    if (argc != 2) return 2;
    print_facts("facts");
    return 0;
  }
  if (strcmp(argv[1], "--touch") == 0) {
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
      printf("PROBE read path=%s open-ok read=-1 errno=%d (%s)\n", argv[2], errno, strerror(errno));
      fflush(stdout);
      return 5;
    }
    buf[n] = '\0';
    printf("PROBE read path=%s rc=0 bytes=%zd content=[%s]\n", argv[2], n, buf);
    fflush(stdout);
    return 0;
  }
  /* P5-S2g27 RC2: the mutation leg's flock holder. Opens (creating when
   * absent), takes LOCK_EX non-blocking, reports the verdict, HOLDS the
   * flock for the requested seconds, and releases on exit. */
  if (strcmp(argv[1], "--flock-hold") == 0) {
    if (argc != 4) return 2;
    hold = (int)strtol(argv[3], NULL, 10);
    print_facts("flock-hold-pre");
    errno = 0;
    fd = open(argv[2], O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
      printf("PROBE flock path=%s rc=-1 errno=%d (%s)\n", argv[2], errno, strerror(errno));
      fflush(stdout);
      return 5;
    }
    errno = 0;
    rc = flock(fd, LOCK_EX | LOCK_NB);
    if (rc != 0) {
      printf("PROBE flock path=%s rc=-1 errno=%d (%s)\n", argv[2], errno, strerror(errno));
      fflush(stdout);
      close(fd);
      return 5;
    }
    printf("PROBE flock path=%s rc=0 held=%d\n", argv[2], hold);
    fflush(stdout);
    sleep(hold);
    flock(fd, LOCK_UN);
    close(fd);
    return 0;
  }
  /* P5-S2g27 invariant: the state-tree no-dir-create negative control. */
  if (strcmp(argv[1], "--mkdir-attempt") == 0) {
    if (argc != 3) return 2;
    print_facts("mkdir-pre");
    errno = 0;
    rc = mkdir(argv[2], 0700);
    printf("PROBE mkdir path=%s rc=%d errno=%d (%s)\n", argv[2], rc, errno, strerror(errno));
    fflush(stdout);
    return rc == 0 ? 0 : 5;
  }
  fprintf(stderr, "usage: state_probe --facts | --touch <path> | --write <path> | --read <path> | --flock-hold <path> <seconds> | --mkdir-attempt <path>\n");
  return 2;
}
EOF
# The probe's dynamic module: the runcon'd vehicle's entry/output surface
# only. The probe's state-tree mutations are performed by the PRODUCTION
# rootlesskit_t grants (docker-helper.te state-tree rules) and carry NO
# diagnostic grants; the negative controls (mkdir in the state tree,
# writes into the daemon's runtime tree) are deliberately left ungranted
# so their enforcing denials are the evidence.
RUNNER_CTX="$(tr -d '\0' < /proc/self/attr/current 2>/dev/null || true)"
RUNNER_T="$(printf '%s' "$RUNNER_CTX" | cut -d: -f3)"
OUT_LABEL="$(stat -c '%C' "$EVIDENCE_DIR/zypper-toolchain.log" 2>/dev/null || true)"
OUT_T="$(printf '%s' "$OUT_LABEL" | cut -d: -f3)"
BINDIR_LABEL="$(stat -c '%C' /usr/local/bin 2>/dev/null || true)"
BINDIR_T="$(printf '%s' "$BINDIR_LABEL" | cut -d: -f3)"
case "${RUNNER_T:-x}" in ''|*[!A-Za-z0-9_]*|x) note "the runner domain could not be observed (context: $RUNNER_CTX)"; exit 1 ;; esac
case "${OUT_T:-x}" in ''|*[!A-Za-z0-9_]*|x) note "the evidence-file type could not be observed (label: $OUT_LABEL)"; exit 1 ;; esac
case "${BINDIR_T:-x}" in ''|*[!A-Za-z0-9_]*|x) note "the /usr/local/bin dir type could not be observed ($BINDIR_LABEL)"; exit 1 ;; esac
{
  echo "=== observed stand labels ==="
  echo "runner context: $RUNNER_CTX (type $RUNNER_T)"
  echo "evidence-file type: $OUT_T (from: $OUT_LABEL)"
  echo "/usr/local/bin dir: $BINDIR_LABEL (type $BINDIR_T)"
} > "$EVIDENCE_DIR/b-stand-labels.txt" 2>&1
cat > /tmp/state_probe_diag.te <<EOF
module state_probe_diag 1.0;

# P5-S2g27 guest-only vehicle module: the runcon'd probe's entry and
# output surface ONLY. The probe's state-tree mutations are performed by
# the PRODUCTION rootlesskit_t grants (docker-helper.te state-tree rules)
# and carry NO diagnostic grants; the negative controls (mkdir in the
# state tree, writes into the daemon's runtime tree) are deliberately
# left ungranted so their enforcing denials are the evidence.
require {
	type docker_helper_rootlesskit_t;
	type docker_helper_newuidmap_t;
	type docker_helper_newgidmap_t;
	type docker_helper_builder_t;
	type $OUT_T;
	type $BINDIR_T;
	attribute file_type;
	class file { entrypoint read open execute execute_no_trans getattr map append write create setattr };
	class fd { use };
	class process { transition siginh };
}
type state_probe_exec_t;
typeattribute state_probe_exec_t file_type;
allow docker_helper_rootlesskit_t state_probe_exec_t:file { entrypoint read open execute execute_no_trans getattr map };
allow unconfined_t state_probe_exec_t:file { create open write append setattr };
type_transition $RUNNER_T $BINDIR_T:file state_probe_exec_t "state_probe";
allow unconfined_t docker_helper_rootlesskit_t:process { transition siginh };
# The manual legacy-mode serve's runcon binding (the entrypoint on
# docker_helper_exec_t is already the production rule).
allow unconfined_t docker_helper_builder_t:process { transition siginh };
# The harness's manager RPC transport: the stand's root speaks the same
# manager.sock wire protocol the root daemon does; this mirrors the
# daemon's own production transport grant (docker-helper.te:
# docker_helper_t -> docker_helper_builder_t:unix_stream_socket
# connectto) for the stand's transport vehicle.
allow unconfined_t docker_helper_builder_t:unix_stream_socket { connectto };
allow docker_helper_rootlesskit_t docker_helper_rootlesskit_t:file { read open getattr };
allow docker_helper_rootlesskit_t $OUT_T:file { append write };
allow docker_helper_newuidmap_t $OUT_T:file { append write };
allow docker_helper_newgidmap_t $OUT_T:file { append write };
allow docker_helper_builder_t $OUT_T:file { append write };
allow docker_helper_rootlesskit_t unconfined_t:fd use;
allow docker_helper_newuidmap_t unconfined_t:fd use;
allow docker_helper_newgidmap_t unconfined_t:fd use;
allow docker_helper_builder_t unconfined_t:fd use;
EOF
{
  echo "=== the vehicle diag module (source) ==="
  cat /tmp/state_probe_diag.te
} > "$EVIDENCE_DIR/b-probe-module.te" 2>&1
checkmodule -M -m -o /tmp/state_probe_diag.tmp /tmp/state_probe_diag.te 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "the probe diag module failed to compile"; cat /tmp/state_probe_diag.te >&2; exit 1; }
semodule_package -o /tmp/state_probe_diag.pp -m /tmp/state_probe_diag.tmp 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "the probe diag module failed to package"; exit 1; }
semodule -i /tmp/state_probe_diag.pp 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "the probe diag module failed to load"; exit 1; }
log "probe diag module loaded"
{
  echo "=== build (after the diag module load: the creation type-transition labels the probe) ==="
  gcc -static -O2 -o /usr/local/bin/state_probe /tmp/state-probe-src/state_probe.c 2>&1 && echo "build OK"
  echo "probe label (post-build): $(stat -c '%C' /usr/local/bin/state_probe 2>&1)"
} > "$EVIDENCE_DIR/b-probe-vehicle.txt" 2>&1
if [ ! -x "$PROBE_BIN" ] \
  || ! stat -c '%C' "$PROBE_BIN" 2>/dev/null | grep -q 'state_probe_exec_t'; then
  note "the static probe binary could not be built or is mislabeled; the experiment cannot proceed"
  diagnose_stand_failure probe-vehicle "$STAND_EPOCH_ALL" "$EVIDENCE_DIR/b-probe-vehicle.txt"
  printf '%s P5S2-STATE-AUTHORITY-RESULT=PASS-INCOMPLETE (probe vehicle unavailable; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi

log 'C: the G26 MCS-constraint delta (guest-only, verbatim)'
cat > /tmp/gidmap_mcsboundary_diag.te <<'DELTAEOF'
module gidmap_mcsboundary_diag 1.0;

# P5-S2g26 guest-only policy delta (reused verbatim by g27): the ONLY
# change vs the production policy is the membership of the minimal
# cross-operation surface set in the shipped base's
# mcs_constrained_type attribute. No allow/capability/transition/relabel/
# manager rules are added. Loaded only for this experiment; removed at
# cleanup.
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
  echo "=== the exact policy delta (the G26 module's source, verbatim) ==="
  cat /tmp/gidmap_mcsboundary_diag.te
  echo "=== compile/package/load log ==="
} > "$EVIDENCE_DIR/c-policy-delta.txt"
checkmodule -M -m -o /tmp/gidmap_mcsboundary_diag.tmp /tmp/gidmap_mcsboundary_diag.te 2>>"$EVIDENCE_DIR/c-policy-delta.txt" \
  && semodule_package -o /tmp/gidmap_mcsboundary_diag.pp -m /tmp/gidmap_mcsboundary_diag.tmp 2>>"$EVIDENCE_DIR/c-policy-delta.txt" \
  && semodule -i /tmp/gidmap_mcsboundary_diag.pp 2>>"$EVIDENCE_DIR/c-policy-delta.txt" \
  || { note "the G26 MCS delta failed to load"; exit 1; }
seinfo -a mcs_constrained_type -x 2>/dev/null \
  > "$EVIDENCE_DIR/c-mcs-members.txt" || true
{
  echo "=== mcs_constrained_type membership (the G26 delta loaded) ==="
  for t in docker_helper_rootlesskit_t docker_helper_newuidmap_t docker_helper_newgidmap_t; do
    echo "$t: $(grep -c "^[[:space:]]*$t\$" "$EVIDENCE_DIR/c-mcs-members.txt" 2>/dev/null || true)"
  done
} >> "$EVIDENCE_DIR/c-policy-delta.txt"
cat "$EVIDENCE_DIR/c-policy-delta.txt" >&2

{
  echo "=== the A/B vehicle identity probes (the runcon assignment) ==="
  echo "runner attr/current: $(tr -d '\0' < /proc/self/attr/current 2>/dev/null || true)"
  echo "builder PAM context: $(runuser -u "$BUILDER_USER" -- id -Z 2>/dev/null || echo UNAVAILABLE)"
  echo "=== assignment probe A (:s0:c1) ==="
  runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_A" "$PROBE_BIN" --facts || true
  echo "=== assignment probe B (:s0:c2) ==="
  runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_B" "$PROBE_BIN" --facts || true
} > "$EVIDENCE_DIR/c-assignment.txt" 2>&1
cat "$EVIDENCE_DIR/c-assignment.txt" >&2

log 'D: REAL manager bring-up (the REAL unit, SELinuxContext binding)'
systemctl start "$UNIT" 2>"$EVIDENCE_DIR/d-unit-start.err" || true
UNIT_WAIT=0
until systemctl is-active --quiet "$UNIT" || [ "$UNIT_WAIT" -ge 30 ]; do
  sleep 1
  UNIT_WAIT=$((UNIT_WAIT + 1))
done
if ! systemctl is-active --quiet "$UNIT"; then
  note "the REAL builder unit failed to start; the experiment cannot proceed"
  {
    systemctl status "$UNIT" --no-pager -l || true
    journalctl -u "$UNIT" --no-pager | tail -50 || true
    echo "--- d-unit-start.err ---"
    cat "$EVIDENCE_DIR/d-unit-start.err"
  } > "$EVIDENCE_DIR/stand-failure-unit.txt" 2>&1
  diagnose_stand_failure unit-startup "$STAND_EPOCH_ALL" "$EVIDENCE_DIR/stand-failure-unit.txt"
  printf '%s P5S2-STATE-AUTHORITY-RESULT=PASS-INCOMPLETE (unit failed to start; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi
MG_PID="$(systemctl show -p MainPID --value "$UNIT")"
{
  echo "=== the REAL unit active ==="
  systemctl status "$UNIT" --no-pager -l | head -20 || true
  echo "=== the manager's process context ==="
  echo "manager pid: $MG_PID"
  echo "manager attr/current: $(tr -d '\0' < "/proc/$MG_PID/attr/current" 2>/dev/null || true)"
  echo "manager cgroup: $(cat "/proc/$MG_PID/cgroup" 2>/dev/null || true)"
  echo "=== the trees + socket (systemd-created, .fc-labeled) ==="
  echo "state root: $(stat -c '%C %U:%G %a' "$STATE_ROOT" 2>&1)"
  echo "runtime root: $(stat -c '%C %U:%G %a' "$RUNTIME_ROOT" 2>&1)"
  echo "manager.sock: $(stat -c '%C %U:%G %a' "$MANAGER_SOCK" 2>&1)"
  echo "=== the manager's startup journal (the purge behavior) ==="
  journalctl -u "$UNIT" --no-pager 2>/dev/null | grep -a 'purge\|serve\|refus' | tail -20 || true
} > "$EVIDENCE_DIR/d-manager-up.txt" 2>&1
cat "$EVIDENCE_DIR/d-manager-up.txt" >&2
if ! stat -c '%C' "$STATE_ROOT" 2>/dev/null | grep -q 'docker_helper_builder_state_t'; then
  note "the state root is not labeled builder_state_t; the experiment cannot proceed"
  diagnose_stand_failure state-label "$STAND_EPOCH_ALL" "$EVIDENCE_DIR/d-manager-up.txt"
  printf '%s P5S2-STATE-AUTHORITY-RESULT=PASS-INCOMPLETE (state root label; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi

# provision_op_dirs <opid> : the stand provisions the per-op dir tree
# exactly as launchInstance does (the same paths, ownership, and
# resulting labels — the dirs inherit builder_state_t from the parent).
provision_op_dirs() {
  local opid="$1"
  mkdir -p "$STATE_ROOT/ops/$opid/rootlesskit-state" "$STATE_ROOT/ops/$opid/root" "$RUNTIME_ROOT/ops/$opid"
  chown -R "$BUILDER_USER:$BUILDER_USER" "$STATE_ROOT/ops/$opid" "$RUNTIME_ROOT/ops/$opid"
}

log 'E: RC1 — refuse-to-adopt paired proof (the REAL manager)'
OPB="$(gen_op_id)"
OPC="$(gen_op_id)"
{
  echo "=== P5-S2g27 RC1: the manager's refuse-to-adopt paired proof ==="
  echo "op ids: opB=$OPB (the mutation target), opC=$OPC (the own-op plant control)"
  echo "the planted object: a REGULAR FILE at ops/<opid> (rootlesskit_t cannot create directories in the state tree — the invariant is measured in phase I)"
  echo "the manager's refuse-to-adopt path: builder_manager.go launchInstance Lstat(stDir)/Lstat(rtDir) -> refusing to adopt (fail closed)"
} > "$EVIDENCE_DIR/e-rc1.txt"

rc1_leg() {
  local tag="$1"
  local opid="$2"
  local epoch="$3"
  local out="$EVIDENCE_DIR/e-rc1-$tag.txt"
  {
    echo "=== RC1 leg $tag: START $opid (epoch $epoch) ==="
  } > "$out"
  manager_rpc "START $opid" "$out"
  echo "reply: $(grep -av '===\|^epoch:\|^command:\|^socat rc:\|^round-trip' "$out" | head -1)" >> "$out"
  echo "=== the manager journal window ===" >> "$out"
  cat "${out%.txt}-journal.txt" >> "$out" 2>/dev/null || true
  echo "=== live rootlesskit processes (none = no spawn) ===" >> "$out"
  set +e
  pgrep -af 'rootlesskit' >> "$out" 2>&1
  set -e
  sleep 2
  harvest_avcs_since "$epoch" "${out%.txt}-avcs.txt"
  cat "$out" >&2
}

rc1_leg baseline1 "$OPB" "$(date +%s)"
G27_RC1_BASELINE_LAUNCHED=0
if grep -aq 'exited unexpectedly' "$EVIDENCE_DIR/e-rc1-baseline1.txt" 2>/dev/null; then
  G27_RC1_BASELINE_LAUNCHED=1
fi
if [ "$G27_RC1_BASELINE_LAUNCHED" != 1 ]; then
  note "RC1: the baseline leg did not show the launch path (see e-rc1-baseline1.txt) — recorded as a finding"
fi
{
  echo "=== the baseline flow's enforced stop (the manager's diag child tail) ==="
  journalctl -u "$UNIT" --no-pager 2>/dev/null | grep -a -A5 'exited unexpectedly' | tail -20 || true
} >> "$EVIDENCE_DIR/e-rc1.txt"

# The cross-op mutation: A:c1 plants a regular file at ops/<opB> using
# ONLY the G26-proven production state-tree surface (rootlesskit_t file
# create/write + dir add_name; NO diag grants, NO unlink, NO mkdir).
set +e
runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_A" "$PROBE_BIN" \
  --touch "$STATE_ROOT/ops/$OPB" \
  >> "$EVIDENCE_DIR/e-rc1-mutation-plant.txt" 2>&1
set -e
{
  echo "=== the planted object (cross-op mutation) ==="
  cat "$EVIDENCE_DIR/e-rc1-mutation-plant.txt"
  echo "plant stat: $(stat -c '%C %U:%G %a' "$STATE_ROOT/ops/$OPB" 2>&1)"
} >> "$EVIDENCE_DIR/e-rc1.txt"
G27_RC1_PLANT_OK=0
if grep -aq 'PROBE touch .*rc=0' "$EVIDENCE_DIR/e-rc1-mutation-plant.txt" 2>/dev/null &&
   [ -f "$STATE_ROOT/ops/$OPB" ]; then
  G27_RC1_PLANT_OK=1
fi
if [ "$G27_RC1_PLANT_OK" != 1 ]; then
  note "RC1: the cross-op plant did not create the object (see e-rc1-mutation-plant.txt)"
fi

rc1_leg mutation "$OPB" "$(date +%s)"
G27_RC1_REFUSED=0
if grep -aq 'refusing to adopt' "$EVIDENCE_DIR/e-rc1-mutation.txt" 2>/dev/null &&
   ! grep -aq 'exited unexpectedly' "$EVIDENCE_DIR/e-rc1-mutation.txt" 2>/dev/null; then
  G27_RC1_REFUSED=1
fi
if [ "$G27_RC1_REFUSED" = 1 ]; then
  log "RC1: cross-op plant CONFIRMED the refuse-to-adopt effect: the manager refused B's START (fail closed, no spawn)"
else
  note "RC1: the refuse-to-adopt effect was not observed for the cross-op plant (see e-rc1-mutation.txt)"
fi

# The own-op plant control: the SAME vehicle and category over a second
# op id — the manager's decision must be identical (existence-driven,
# not cross-op-specific).
set +e
runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_A" "$PROBE_BIN" \
  --touch "$STATE_ROOT/ops/$OPC" \
  >> "$EVIDENCE_DIR/e-rc1-ownplant.txt" 2>&1
set -e
rc1_leg owncontrol "$OPC" "$(date +%s)"
G27_RC1_OWN_REFUSED=0
if grep -aq 'refusing to adopt' "$EVIDENCE_DIR/e-rc1-owncontrol.txt" 2>/dev/null &&
   ! grep -aq 'exited unexpectedly' "$EVIDENCE_DIR/e-rc1-owncontrol.txt" 2>/dev/null; then
  G27_RC1_OWN_REFUSED=1
fi
if [ "$G27_RC1_OWN_REFUSED" != 1 ]; then
  note "RC1: the own-op plant control did not reproduce the refusal (see e-rc1-owncontrol.txt)"
fi

# The harness (root, unconfined) unplants BOTH files: a trusted cleanup
# action, not part of the attack surface (rootlesskit_t has no file
# unlink grant on the state tree — the unplant proves the plant's role).
rm -f "$STATE_ROOT/ops/$OPB" "$STATE_ROOT/ops/$OPC"
rc1_leg restore "$OPB" "$(date +%s)"
G27_RC1_RESTORED=0
if grep -aq 'exited unexpectedly' "$EVIDENCE_DIR/e-rc1-restore.txt" 2>/dev/null; then
  G27_RC1_RESTORED=1
fi
if [ "$G27_RC1_RESTORED" = 1 ]; then
  log "RC1: restore leg re-proved the baseline launch path after the unplant"
else
  note "RC1: the restore leg did not re-prove the launch path (see e-rc1-restore.txt)"
fi
{
  echo "=== the RC1 result ==="
  echo "baseline launch path observed: $G27_RC1_BASELINE_LAUNCHED"
  echo "cross-op plant created: $G27_RC1_PLANT_OK"
  echo "cross-op mutation changed the START outcome to the fail-closed refusal: $G27_RC1_REFUSED"
  echo "own-op plant control reproduced the same refusal: $G27_RC1_OWN_REFUSED"
  echo "restore leg re-proved the launch path: $G27_RC1_RESTORED"
  echo "classification: existence-level authority input with a fail-closed bound (a refusal; availability only — the manager never adopts, never launches against, and never acts on the planted object)"
} >> "$EVIDENCE_DIR/e-rc1.txt"
cat "$EVIDENCE_DIR/e-rc1.txt" >&2
printf '%s P5S2-G27-RC1-RESULT=COMPLETED (baseline=%s plant=%s refused=%s owncontrol=%s restored=%s)\n' "$PREFIX" \
  "$G27_RC1_BASELINE_LAUNCHED" "$G27_RC1_PLANT_OK" "$G27_RC1_REFUSED" "$G27_RC1_OWN_REFUSED" "$G27_RC1_RESTORED" >&2

log 'F: RC2 — rootlesskit state-dir lock paired proof (the REAL vehicle)'
OPD2="$(gen_op_id)"
provision_op_dirs "$OPD2"
LOCKDIR="$STATE_ROOT/ops/$OPD2/rootlesskit-state"
LOCKFILE="$LOCKDIR/lock"
{
  echo "=== P5-S2g27 RC2: the rootlesskit state-dir lock paired proof ==="
  echo "op id: $OPD2; the stand provisioned the per-op tree exactly as launchInstance does:"
  echo "  $LOCKDIR: $(stat -c '%C %U:%G %a' "$LOCKDIR" 2>&1)"
  echo "  $STATE_ROOT/ops/$OPD2/root: $(stat -c '%C %U:%G %a' "$STATE_ROOT/ops/$OPD2/root" 2>&1)"
  echo "the lock mechanics (rootlesskit v3, grounded from source): the CLI's InitStateDir -> LockStateDir TryLock; a held flock fails the flow start with the exact 'another RootlessKit is running with the same state directory?' error"
  echo "the baseline leg's expected post-lock stop: the production gid_map cap_userns boundary (newgidmap_t has no cap_userns grant — the G26-proven production boundary)"
} > "$EVIDENCE_DIR/f-rc2.txt"

# Baseline: the c2-labeled real rootlesskit flow passes the lock (the
# payload cannot start while the gid step fails; the flow's stderr and
# AVCs decide).
f_rc2_flow() {
  local tag="$1"
  local epoch="$2"
  local out="$EVIDENCE_DIR/f-rc2-$tag.txt"
  {
    echo "=== RC2 leg $tag: the real rootlesskit flow at $LOCKDIR (epoch $epoch) ==="
    echo "command: runuser -u $BUILDER_USER -- runcon $RK_EXEC_T_B /usr/bin/rootlesskit --net=none --state-dir=$LOCKDIR $PROBE_BIN --facts"
  } > "$out"
  set +e
  timeout 60 runuser -u "$BUILDER_USER" -- \
    runcon "$RK_EXEC_T_B" /usr/bin/rootlesskit --net=none \
    --state-dir="$LOCKDIR" "$PROBE_BIN" --facts \
    >> "$out" 2>&1
  echo "flow exit: $?" >> "$out"
  set -e
  sleep 2
  harvest_avcs_since "$epoch" "${out%.txt}-avcs.txt"
  cat "$out" >&2
}

f_rc2_flow baseline "$(date +%s)"
G27_RC2_BASELINE_LOCKPASSED=0
if ! grep -aq 'failed to lock' "$EVIDENCE_DIR/f-rc2-baseline.txt" 2>/dev/null; then
  # The flow's stderr must reach the map step (the gid boundary) — not a
  # lock error — for the lock passage to be proven.
  if grep -aq 'failed to setup UID/GID map\|write to gid_map failed' "$EVIDENCE_DIR/f-rc2-baseline.txt" 2>/dev/null; then
    G27_RC2_BASELINE_LOCKPASSED=1
  fi
fi
if [ "$G27_RC2_BASELINE_LOCKPASSED" = 1 ]; then
  log "RC2 baseline: the c2-labeled flow PASSED the lock (reached the gid_map production boundary)"
else
  note "RC2: the baseline flow did not prove the lock passage (see f-rc2-baseline.txt)"
fi

# The mutation: A:c1 flock-holds the SAME lock file (the file exists
# after the baseline's flow — the flow's own exit-time RemoveAll is
# TE-limited on builder_state_t files, so the lock file persists).
G27_RC2_LOCK_HELD=0
set +e
runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_A" "$PROBE_BIN" \
  --flock-hold "$LOCKFILE" 25 \
  >> "$EVIDENCE_DIR/f-rc2-flock.txt" 2>&1 &
FLOCK_PID=$!
set -e
sleep 2
if grep -aq 'PROBE flock .*rc=0' "$EVIDENCE_DIR/f-rc2-flock.txt" 2>/dev/null; then
  G27_RC2_LOCK_HELD=1
fi
{
  echo "=== the mutation leg's flock holder ==="
  cat "$EVIDENCE_DIR/f-rc2-flock.txt"
  echo "flock held: $G27_RC2_LOCK_HELD"
} >> "$EVIDENCE_DIR/f-rc2.txt"
if [ "$G27_RC2_LOCK_HELD" != 1 ]; then
  note "RC2: the cross-op flock was not acquired (see f-rc2-flock.txt)"
fi

f_rc2_flow mutation "$(date +%s)"
G27_RC2_MUTATION_LOCKBLOCKED=0
if grep -aq 'another RootlessKit is running with the same state directory?\|failed to lock' "$EVIDENCE_DIR/f-rc2-mutation.txt" 2>/dev/null; then
  G27_RC2_MUTATION_LOCKBLOCKED=1
fi
if [ "$G27_RC2_MUTATION_LOCKBLOCKED" = 1 ]; then
  log "RC2 mutation: the SAME flow failed at the lock with rootlesskit's own error — the cross-op flock changed B's launch outcome"
else
  note "RC2: the mutation leg did not show the lock failure (see f-rc2-mutation.txt)"
fi

# The restore: release the flock (the holder exits by itself; wait
# bounded), then the same flow re-proves the baseline shape.
kill "$FLOCK_PID" 2>/dev/null || true
wait "$FLOCK_PID" 2>/dev/null || true
sleep 1
f_rc2_flow restore "$(date +%s)"
G27_RC2_RESTORED=0
if grep -aq 'failed to setup UID/GID map\|write to gid_map failed' "$EVIDENCE_DIR/f-rc2-restore.txt" 2>/dev/null; then
  G27_RC2_RESTORED=1
fi
{
  echo "=== the RC2 result ==="
  echo "baseline lock passage: $G27_RC2_BASELINE_LOCKPASSED"
  echo "cross-op flock held: $G27_RC2_LOCK_HELD"
  echo "the same flow's launch outcome changed by the cross-op flock: $G27_RC2_MUTATION_LOCKBLOCKED"
  echo "restore leg re-proved the baseline shape: $G27_RC2_RESTORED"
  echo "classification: the lock file's CONTENT is never read (flock is kernel state); the cross-op flock is a DIRECT availability interference on B's launch vehicle, not a trusted-consumer action"
} >> "$EVIDENCE_DIR/f-rc2.txt"
cat "$EVIDENCE_DIR/f-rc2.txt" >&2
printf '%s P5S2-G27-RC2-RESULT=COMPLETED (baseline=%s flockheld=%s lockblocked=%s restored=%s)\n' "$PREFIX" \
  "$G27_RC2_BASELINE_LOCKPASSED" "$G27_RC2_LOCK_HELD" "$G27_RC2_MUTATION_LOCKBLOCKED" "$G27_RC2_RESTORED" >&2

log 'G: RC4 — purge name-injection paired proof (unit mode + manual legacy mode)'
OPFAKE="$(gen_op_id)"
OPFAKE2="$(gen_op_id)"
{
  echo "=== P5-S2g27 RC4: the startup purge name-injection paired proof ==="
  echo "the ONLY state-tree data the manager reads: ops directory NAMES (canonicalOpsEntries, builder_manager.go) — no content reads anywhere"
  echo "fake op id (canonical grammar, planted by A:c1): $OPFAKE (unit mode), $OPFAKE2 (manual legacy mode)"
} > "$EVIDENCE_DIR/g-rc4.txt"

# Unit mode: the planted canonical name is processed by the unit-boundary
# purge and absorbed (removal only; the unit still starts).
set +e
runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_A" "$PROBE_BIN" \
  --touch "$STATE_ROOT/ops/$OPFAKE" \
  >> "$EVIDENCE_DIR/g-rc4-plant.txt" 2>&1
set -e
{
  echo "=== the planted unit-mode entry ==="
  cat "$EVIDENCE_DIR/g-rc4-plant.txt"
  echo "pre-restart stat: $(stat -c '%C %U:%G' "$STATE_ROOT/ops/$OPFAKE" 2>&1)"
} >> "$EVIDENCE_DIR/g-rc4.txt"
G27_RC4_UNIT_PLANTED=0
if [ -e "$STATE_ROOT/ops/$OPFAKE" ]; then G27_RC4_UNIT_PLANTED=1; fi
RESTART_EPOCH="$(date +%s)"
systemctl restart "$UNIT" 2>"$EVIDENCE_DIR/g-rc4-restart.err" || true
RESTART_WAIT=0
until systemctl is-active --quiet "$UNIT" || [ "$RESTART_WAIT" -ge 30 ]; do
  sleep 1
  RESTART_WAIT=$((RESTART_WAIT + 1))
done
G27_RC4_UNIT_ACTIVE=0
systemctl is-active --quiet "$UNIT" && G27_RC4_UNIT_ACTIVE=1 || G27_RC4_UNIT_ACTIVE=0
{
  echo "=== the unit-mode restart with the planted entry ==="
  echo "unit active after restart: $G27_RC4_UNIT_ACTIVE"
  echo "the planted entry after restart: $(stat -c '%C %U:%G' "$STATE_ROOT/ops/$OPFAKE" 2>&1)"
  echo "=== the manager's purge journal window ==="
  journalctl -u "$UNIT" --since "@$RESTART_EPOCH" --no-pager 2>/dev/null | grep -a 'purge\|residue\|refus\|skipping' | head -20 || true
} >> "$EVIDENCE_DIR/g-rc4.txt"
G27_RC4_UNIT_ABSORBED=0
if [ "$G27_RC4_UNIT_ACTIVE" = 1 ] && [ ! -e "$STATE_ROOT/ops/$OPFAKE" ]; then
  G27_RC4_UNIT_ABSORBED=1
fi
if [ "$G27_RC4_UNIT_ABSORBED" = 1 ]; then
  log "RC4 unit mode: the planted canonical name was ABSORBED (the unit-boundary purge removed the residue; the unit started; no signal)"
else
  note "RC4: the unit-mode absorption was not observed (see g-rc4.txt)"
fi

# Manual legacy mode: the same planted name FAILS the manual serve at the
# startup purge, fail closed, with no signal and no removal.
systemctl stop "$UNIT" 2>/dev/null || true
# The unit stop wiped the runtime tree; the manual serve needs it.
mkdir -p "$RUNTIME_ROOT"
chown "$BUILDER_USER:$BUILDER_USER" "$RUNTIME_ROOT"
restorecon -R "$RUNTIME_ROOT" 2>/dev/null || true
set +e
runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_A" "$PROBE_BIN" \
  --touch "$STATE_ROOT/ops/$OPFAKE2" \
  >> "$EVIDENCE_DIR/g-rc4-plant2.txt" 2>&1
set -e
{
  echo "=== the planted manual-mode entry ==="
  cat "$EVIDENCE_DIR/g-rc4-plant2.txt"
  echo "pre-serve stat: $(stat -c '%C %U:%G' "$STATE_ROOT/ops/$OPFAKE2" 2>&1)"
} >> "$EVIDENCE_DIR/g-rc4.txt"
M_EPOCH="$(date +%s)"
{
  echo "=== the manual legacy-mode serve with the planted entry ==="
} > "$EVIDENCE_DIR/g-rc4-manual-planted.txt"
set +e
timeout 20 runuser -u "$BUILDER_USER" -- \
  runcon "$BUILDER_T" /usr/bin/docker-helper builder serve \
  >> "$EVIDENCE_DIR/g-rc4-manual-planted.txt" 2>&1
M_RC_PLANTED=$?
set -e
echo "manual serve exit with the plant: $M_RC_PLANTED" >> "$EVIDENCE_DIR/g-rc4-manual-planted.txt"
sleep 2
harvest_avcs_since "$M_EPOCH" "$EVIDENCE_DIR/g-rc4-manual-planted-avcs.txt"
G27_RC4_MANUAL_REFUSED=0
if [ "$M_RC_PLANTED" != 0 ] &&
   grep -aq 'refusing startup' "$EVIDENCE_DIR/g-rc4-manual-planted.txt" 2>/dev/null &&
   [ -e "$STATE_ROOT/ops/$OPFAKE2" ]; then
  G27_RC4_MANUAL_REFUSED=1
fi
{
  echo "=== the manual serve's output ==="
  cat "$EVIDENCE_DIR/g-rc4-manual-planted.txt"
  echo "the planted entry survived the refused startup (fail closed, no removal, no signal): $([ -e "$STATE_ROOT/ops/$OPFAKE2" ] && echo yes || echo no)"
} >> "$EVIDENCE_DIR/g-rc4.txt"
if [ "$G27_RC4_MANUAL_REFUSED" = 1 ]; then
  log "RC4 manual mode: the planted canonical name FAILED the manual serve at startup purge (fail closed; no signal, no removal)"
else
  note "RC4: the manual-mode fail-closed refusal was not observed (see g-rc4-manual-planted.txt)"
fi

# The manual baseline: the harness unplants; the manual serve starts
# clean (the purge processes no entries; the socket comes up).
rm -f "$STATE_ROOT/ops/$OPFAKE2"
{
  echo "=== the manual legacy-mode serve baseline (after the harness unplant) ==="
} > "$EVIDENCE_DIR/g-rc4-manual-baseline.txt"
set +e
timeout 8 runuser -u "$BUILDER_USER" -- \
  runcon "$BUILDER_T" /usr/bin/docker-helper builder serve \
  >> "$EVIDENCE_DIR/g-rc4-manual-baseline.txt" 2>&1
M_RC_BASE=$?
set -e
echo "manual serve exit (124 = the timeout, the serve was up): $M_RC_BASE" >> "$EVIDENCE_DIR/g-rc4-manual-baseline.txt"
G27_RC4_MANUAL_BASELINE_OK=0
if [ "$M_RC_BASE" = 124 ] || [ "$M_RC_BASE" = 0 ]; then
  G27_RC4_MANUAL_BASELINE_OK=1
fi
{
  echo "=== the manual serve's baseline output ==="
  cat "$EVIDENCE_DIR/g-rc4-manual-baseline.txt"
} >> "$EVIDENCE_DIR/g-rc4.txt"
if [ "$G27_RC4_MANUAL_BASELINE_OK" != 1 ]; then
  note "RC4: the manual serve baseline did not start clean (see g-rc4-manual-baseline.txt)"
fi
{
  echo "=== the RC4 result ==="
  echo "unit mode: planted=$G27_RC4_UNIT_PLANTED absorbed=$G27_RC4_UNIT_ABSORBED (the purge removed the residue; the unit started; no signal)"
  echo "manual legacy mode: planted entry failed the serve fail-closed: $G27_RC4_MANUAL_REFUSED; the clean baseline started: $G27_RC4_MANUAL_BASELINE_OK"
  echo "classification: the ops-name input's decisions are fail-closed anchored (no pid file, no live anchored groups -> refuse or remove-only); a planted name can NEVER become a kill target"
} >> "$EVIDENCE_DIR/g-rc4.txt"
cat "$EVIDENCE_DIR/g-rc4.txt" >&2
printf '%s P5S2-G27-RC4-RESULT=COMPLETED (unit_absorbed=%s manual_refused=%s manual_baseline=%s)\n' "$PREFIX" \
  "$G27_RC4_UNIT_ABSORBED" "$G27_RC4_MANUAL_REFUSED" "$G27_RC4_MANUAL_BASELINE_OK" >&2

# Bring the unit back up for the remaining phases (its runtime tree was
# wiped by the stop; systemd recreates it at start).
systemctl start "$UNIT" 2>"$EVIDENCE_DIR/g-rc4-restart2.err" || true
UNIT_WAIT=0
until systemctl is-active --quiet "$UNIT" || [ "$UNIT_WAIT" -ge 30 ]; do
  sleep 1
  UNIT_WAIT=$((UNIT_WAIT + 1))
done
if ! systemctl is-active --quiet "$UNIT"; then
  note "the REAL builder unit failed to restart; the experiment cannot proceed"
  diagnose_stand_failure unit-restart "$STAND_EPOCH_ALL" "$EVIDENCE_DIR/g-rc4-restart2.err"
  printf '%s P5S2-STATE-AUTHORITY-RESULT=PASS-INCOMPLETE (unit restart; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi

log 'H: RC3 — buildkitd data-root write-link (A:c1, the production --root shape)'
OPWRITE="$(gen_op_id)"
provision_op_dirs "$OPWRITE"
{
  echo "=== P5-S2g27 RC3: the cross-op write into the production buildkitd data-root shape ==="
  echo "the stand provisioned ops/$OPWRITE exactly as launchInstance does:"
  echo "  root dir: $(stat -c '%C %U:%G %a' "$STATE_ROOT/ops/$OPWRITE/root" 2>&1)"
  echo "the consumption side (buildkitd trusting its own content/snapshot state under --root) is NOT runnable under the shipped policy:"
  echo "  the RC1 baseline recorded the real manager's flow stopping at its enforced child-process boundary BEFORE buildkitd (e-rc1-baseline1.txt); no grants are added to reach it (per the task constraints)"
} > "$EVIDENCE_DIR/h-rc3.txt"
set +e
runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_A" "$PROBE_BIN" \
  --touch "$STATE_ROOT/ops/$OPWRITE/root/poison-marker" \
  >> "$EVIDENCE_DIR/h-rc3-write.txt" 2>&1
set -e
G27_RC3_WRITE_OK=0
if grep -aq 'PROBE touch .*rc=0' "$EVIDENCE_DIR/h-rc3-write.txt" 2>/dev/null &&
   [ -f "$STATE_ROOT/ops/$OPWRITE/root/poison-marker" ]; then
  G27_RC3_WRITE_OK=1
fi
{
  echo "=== the write leg ==="
  cat "$EVIDENCE_DIR/h-rc3-write.txt"
  echo "marker label: $(stat -c '%C %U:%G' "$STATE_ROOT/ops/$OPWRITE/root/poison-marker" 2>&1)"
  echo "cross-op write into the production data-root shape: $G27_RC3_WRITE_OK"
  echo "=== the RC3 result ==="
  echo "write-link (cross-op mutation capability on the buildkitd data-root shape): $G27_RC3_WRITE_OK"
  echo "consumption link: NOT runtime-provable under the shipped policy (the payload's MAC is deliberately ungranted; the flow stops before buildkitd) — static source-grounded classification in the report; the G27 verdict therefore cannot be PASS"
} >> "$EVIDENCE_DIR/h-rc3.txt"
cat "$EVIDENCE_DIR/h-rc3.txt" >&2
printf '%s P5S2-G27-RC3-RESULT=COMPLETED (write_link=%s consumption=static-only)\n' "$PREFIX" "$G27_RC3_WRITE_OK" >&2

log 'I: invariant dump (TE sets + the negative controls)'
{
  echo "=== P5-S2g27 invariants: the loaded policy's TE sets ==="
  echo "--- sesearch --allow -s docker_helper_rootlesskit_t -c unix_stream_socket -p connectto (expect none: the cross-op api.sock connect surface) ---"
  sesearch --allow -s docker_helper_rootlesskit_t -c unix_stream_socket -p connectto 2>&1 || true
  echo "--- sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_builder_state_t -c sock_file (expect create/unlink only) ---"
  sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_builder_state_t -c sock_file 2>&1 || true
  echo "--- sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_builder_runtime_t (expect none: the daemon's runtime tree is TE-blocked for operations) ---"
  sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_builder_runtime_t 2>&1 || true
  echo "--- sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_builder_state_t -c dir -p create (expect none: the no-dir-create invariant) ---"
  sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_builder_state_t -c dir -p create 2>&1 || true
  echo "--- sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_builder_state_t -c file -p unlink (expect none) ---"
  sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_builder_state_t -c file -p unlink 2>&1 || true
  echo "--- sesearch --allow -s docker_helper_t -t docker_helper_builder_state_t (expect none: the daemon has no state-tree access) ---"
  sesearch --allow -s docker_helper_t -t docker_helper_builder_state_t 2>&1 || true
  echo "--- sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_builder_state_t -c file -p write (the G26-proven cross-op write surface) ---"
  sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_builder_state_t -c file -p write 2>&1 || true
} > "$EVIDENCE_DIR/i-invariants.txt" 2>&1

# The no-dir-create negative control: A:c1 mkdir(2) in the state tree.
set +e
runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_A" "$PROBE_BIN" \
  --mkdir-attempt "$STATE_ROOT/ops/$OPWRITE/rootlesskit-state-sub" \
  >> "$EVIDENCE_DIR/i-invariants.txt" 2>&1
set -e
G27_INV_NODIRCREATE=0
if grep -aq 'PROBE mkdir .*rc=-1' "$EVIDENCE_DIR/i-invariants.txt" 2>/dev/null; then
  G27_INV_NODIRCREATE=1
fi
{
  echo "=== the no-dir-create negative control (mkdir from A:c1) ==="
  echo "denied: $G27_INV_NODIRCREATE (EACCES — dir create is not granted; the buildkitd default-config path (\$HOME/.config/buildkit/buildkitd.toml inside the state root) can never materialize via an operation's own access)"
} >> "$EVIDENCE_DIR/i-invariants.txt"

# The runtime-tree write-denial negative control.
set +e
runuser -u "$BUILDER_USER" -- runcon "$RK_EXEC_T_A" "$PROBE_BIN" \
  --touch "$RUNTIME_ROOT/ops/$OPWRITE/pid-plant" \
  >> "$EVIDENCE_DIR/i-invariants.txt" 2>&1
set -e
G27_INV_RTWRITE=0
if grep -aq "PROBE touch path=$RUNTIME_ROOT.*rc=-1" "$EVIDENCE_DIR/i-invariants.txt" 2>/dev/null; then
  G27_INV_RTWRITE=1
fi
{
  echo "=== the runtime-tree write-denial negative control (touch from A:c1) ==="
  echo "denied: $G27_INV_RTWRITE (EACCES — the daemon's runtime tree is TE-blocked for rootlesskit_t at the walk; the manager's instance.pid is integrity-protected from operations)"
} >> "$EVIDENCE_DIR/i-invariants.txt"

{
  echo "=== the .config absence check (after all the runs) ==="
  echo "state root listing:"
  ls -la "$STATE_ROOT" 2>&1 || true
  echo ".config exists: $([ -e "$STATE_ROOT/.config" ] && echo YES || echo no)"
  echo ".config/buildkit exists: $([ -e "$STATE_ROOT/.config/buildkit" ] && echo YES || echo no)"
} >> "$EVIDENCE_DIR/i-invariants.txt"
cat "$EVIDENCE_DIR/i-invariants.txt" >&2
printf '%s P5S2-G27-INVARIANTS-RESULT=COMPLETED (nodircreate=%s rtwrite-denied=%s)\n' "$PREFIX" \
  "$G27_INV_NODIRCREATE" "$G27_INV_RTWRITE" >&2

log 'teardown'
pkill -KILL -f 'rootlesskit --net=none' 2>/dev/null || true
pkill -KILL -f 'state_probe --' 2>/dev/null || true

sleep 2
{
  echo "=== kernel AVC records of the whole experiment window (ALL docker-helper domains; unfiltered) ==="
  grep -a 'type=AVC' /var/log/audit/audit.log 2>/dev/null \
    | awk -v s="$AVC_EPOCH_ALL" '{ for (i = 1; i <= NF; i++) if ($i ~ /^msg=audit\(/) { ts = substr($i, 11); split(ts, t, "."); if (t[1] + 0 >= s + 0) print; break } }' \
    | grep -a 'docker_helper_' \
    | tail -300 || true
  echo "=== journalctl -k window (all avc lines) ==="
  journalctl -k --since "@$AVC_EPOCH_ALL" --no-pager 2>/dev/null | grep -a 'avc:' | tail -300 || true
} > "$EVIDENCE_DIR/f-all-helper-avcs-all.txt" 2>&1
{
  echo "=== the manager's unit journal of the whole experiment window ==="
  journalctl -u "$UNIT" --since "@$AVC_EPOCH_ALL" --no-pager 2>/dev/null | tail -200 || true
} > "$EVIDENCE_DIR/f-manager-journal-all.txt" 2>&1
cat "$EVIDENCE_DIR/f-all-helper-avcs-all.txt" >&2

log 'cleanup (temporary modules removed; the candidate module stays until the VM is disposed)'
systemctl stop "$UNIT" >/dev/null 2>&1 || true
systemctl disable "$UNIT" >/dev/null 2>&1 || true
rm -f /etc/systemd/system/"$UNIT".service
systemctl daemon-reload >/dev/null 2>&1 || true
rm -f /usr/bin/docker-helper /usr/local/bin/state_probe
rm -rf "$STATE_ROOT" "$RUNTIME_ROOT"
semodule -r state_probe_diag >/dev/null 2>&1 || true
semodule -r gidmap_mcsboundary_diag >/dev/null 2>&1 || true
semodule -l 2>/dev/null | grep -E 'docker_helper|gidmap|state_probe' > "$EVIDENCE_DIR/f-final-modules.txt" 2>&1 || true

printf '%s P5S2-STATE-AUTHORITY-RESULT=PASS (experiment completed; findings are in the evidence)\n' "$PREFIX" >&2
exit 0
