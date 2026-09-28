#!/usr/bin/env bash
#
# Guest-side P5-S2g30 per-operation state-tree MCS isolation feasibility
# proof for openSUSE Tumbleweed. INVESTIGATION ONLY.
#
# The question G30 answers (the consequence recorded by the G29 FAIL
# verdict — complete operation boundary broken through the already-proven
# cross-op write surface):
#   can the state tree of each Build Operation carry the operation's own
#   MCS category (A -> s0:c1, B -> s0:c2) so that A:c1 can no longer
#   read or write B:c2's state, while B:c2 keeps full own-state access,
#   the manager lifecycle keeps working, the G28 payload keeps working,
#   and cleanup/STOP/PURGE converge?
#
# Method: a runtime feasibility measurement on the G28/G29 stand (REAL
# manager under the REAL unit with the SELinuxContext binding and the P4
# unit-cgroup boundary, REAL rootlesskit production argv, pinned BuildKit
# v0.33.0, SELinux Enforcing everywhere, the G26 MCS delta + the
# UNCHANGED candidate payload module v12 loaded, production policy /
# manager / BuildKit sources untouched). NO new policy module: the
# mechanism under test is the loaded policy's own default-range
# TARGET_LOW rule (the kernel mls_compute_sid copies the containing
# directory's low range — level AND categories — for a created object,
# with the containing directory's context as the transition target) plus
# the loaded mcsconstrain rules plus the G26 process-transition range
# copy. The stand provisions the operation trees in the manager's exact
# shape and assigns each tree its category (the allocator stand-in; the
# allocator design is out of scope), then launches each operation
# through the manager's own transition path (builder_t:s0:cX -> exec ->
# type_transition -> rootlesskit_t:s0:cX: a process transition copies the
# caller's full range), so the whole flow runs in the operation's
# category.
#
# Legs:
#   Part A  the labeling model: the provisioned tree's labels + the
#           propagation measurements (a c2 vehicle's creation inside the
#           c2 tree; a manager-domain stand-in's creation inside the c2
#           tree — the no-de-categorization model for Part F) + the
#           policy's default-range statements.
#   Part B  (folded into C) the own-operation proof: op B at s0:c2
#           launches, reaches readiness, builds a minimal real image,
#           and the descendant inventory proves the category holds
#           deeper in the tree (buildkit root, content blob, snapshot
#           directory, snapshot regular file, metadata DBs, rootlesskit
#           state objects).
#   Part D  the paired cross-operation filesystem matrix: read, write/
#           pwrite, create, open, unlink, flock — cross (A:c1 -> B:c2)
#           MCS-BLOCKED, own (B:c2 -> B:c2) ALLOWED, TE-granted
#           throughout; TE-only blocks are classified as such.
#   Part E  the exact G29 poisoning primitive repeated: the same
#           pwrite marker at offset 0 into B's FROM-snapshot
#           /etc/passwd from A:c1 — EACCES/MCS denial expected, the
#           file unchanged, B's build stays baseline; the own-op control
#           reaches the same object; restore + closure.
#   Part F  the manager/control-plane compatibility: the manager's own
#           START/STOP (the created labels measured), the adoption
#           refusal over a planted c2 pair, the PURGE RPC, the
#           abnormal-termination cleanup, and the startup purge over
#           categorized trees (B's real tree + planted c1/c2 fakes), +
#           the op-id reuse after cleanup.
#   Part G  the short G26 process-boundary regression: cross-op
#           newuidmap MCS-blocked, cross-op signals closed, cross-op
#           connect to the op's buildkitd.sock closed, the op cannot
#           reach the manager.sock. The full G26/G28 suite is NOT
#           repeated.
#
# Out-of-scope by the task contract: production policy commits, manager/
# BuildKit source changes, category allocator design, production
# lifecycle allocation, new BuildKit poisoning targets, payload grant
# extensions, the Release GO.
#
set -Eeuo pipefail

PREFIX='[release-2.4-p5s2-state-mcs-tw]'
EVIDENCE_DIR=/tmp/release-2.4-p5s2-state-mcs-evidence
BUILDER_USER=docker-helper-builder
GUEST_FILES=/tmp/p5s2-state-mcs
TRANSFERRED="$GUEST_FILES"
STATE_ROOT=/var/lib/docker-helper-builder
RUNTIME_ROOT=/run/docker-helper-builder
MANAGER_SOCK="$RUNTIME_ROOT/manager.sock"
UNIT=docker-helper-builder
BUILDKITD=/usr/libexec/docker-helper/buildkit/buildkitd
BUILDCTL=/usr/libexec/docker-helper/buildkit/buildctl
WORK=/tmp/p5s2-g30-work

log()  { printf '%s %s\n' "$PREFIX" "$*"; }
note() { printf '%s NOTE: %s\n' "$PREFIX" "$*"; }

rm -rf "$EVIDENCE_DIR" "$WORK"
mkdir -p "$EVIDENCE_DIR" "$WORK"

DOMAINS=(docker_helper_builder_t docker_helper_rootlesskit_t docker_helper_slirp4netns_t docker_helper_newuidmap_t docker_helper_newgidmap_t)
clear_permissive() { semanage permissive -d "$1" >/dev/null 2>&1 || true; }

# shellcheck disable=SC2329
cleanup() {
  pkill -KILL -f 'rootlesskit --net=' 2>/dev/null || true
  pkill -KILL -f 'buildkitd --rootless' 2>/dev/null || true
  pkill -KILL -f 'buildctl --addr' 2>/dev/null || true
  pkill -KILL -f 'slirp4netns' 2>/dev/null || true
  systemctl stop "$UNIT" >/dev/null 2>&1 || true
  systemctl disable "$UNIT" >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/"$UNIT".service
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -f /usr/bin/docker-helper
  rm -rf /usr/libexec/docker-helper "$STATE_ROOT" "$RUNTIME_ROOT" "$WORK"
  rm -f /usr/local/bin/map_probe
  semanage dontaudit on >/dev/null 2>&1 || true
  semodule -r gidmap_probe_diag >/dev/null 2>&1 || true
  for d in "${DOMAINS[@]}"; do
    clear_permissive "$d"
  done
  semodule -r payload_mac_diag >/dev/null 2>&1 || true
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
      | tail -2000 || true
    echo "=== journalctl -k window ==="
    journalctl -k --since "@$since" --no-pager 2>/dev/null | grep -a 'avc:' | tail -2000 || true
  } > "$out" 2>&1
}

dedup_avcs() {
  local in="$1" out="$2"
  python3 - "$in" "$out" <<'PYEOF' 2>/dev/null || true
import re, sys, collections
raw = open(sys.argv[1], errors='replace').read().splitlines()
recs = [l for l in raw if 'avc:' in l and 'denied' in l]
pat = re.compile(r'avc:\s+denied\s+\{ ([^}]+) \}.*?scontext=(\S+) tcontext=(\S+) tclass=(\S+)')
tuples = collections.OrderedDict()
samples = {}
for l in recs:
    m = pat.search(l)
    if not m:
        continue
    perms = ' '.join(sorted(m.group(1).split()))
    key = (m.group(2), m.group(3), m.group(4), perms)
    tuples[key] = tuples.get(key, 0) + 1
    samples.setdefault(key, l.strip())
lines = ['=== deduplicated (scontext, tcontext, tclass, perms) tuples: %d unique ===' % len(tuples)]
for k, c in tuples.items():
    lines.append('COUNT=%d\nS=%s\nT=%s\nCLASS=%s PERMS={%s}\nRAW: %s' % (c, k[0], k[1], k[2], k[3], samples[k]))
open(sys.argv[2], 'w').write('\n'.join(lines) + '\n')
PYEOF
}

manager_journal_since() {
  local since="$1" out="$2"
  journalctl -u "$UNIT" --since "@$since" --no-pager 2>/dev/null > "$out" || true
}

gen_op_id() {
  printf 'op_%s' "$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
}

log 'A: toolchain + modules (production + candidate + G26 delta) + composition install'
# Part D precondition: the composition runs ONLY under Enforcing with NO
# permissive domains, and the loaded module set is exactly the production
# module + the G26 MCS delta + the guest-only candidate payload module.
for d in "${DOMAINS[@]}"; do
  clear_permissive "$d"
done
{
  echo "=== enforcing + permissive-domains precondition ==="
  echo "getenforce: $(getenforce 2>&1)"
  echo "permissive domains after the clear:"
  semanage permissive -l 2>/dev/null || true
} > "$EVIDENCE_DIR/a-preconditions.txt" 2>&1
if [ "$(getenforce 2>/dev/null)" != "Enforcing" ]; then
  note "SELinux is not Enforcing; the experiment cannot proceed"
  printf '%s P5S2-STATE-MCS-RESULT=INCOMPLETE (not enforcing; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi
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
  setools-console python3-setools gcc glibc-static util-linux shadow \
  libcap-progs python3 curl \
  >"$EVIDENCE_DIR/zypper-toolchain.log" 2>&1 \
  || note "zypper install of the policy toolchain failed (see zypper-toolchain.log)"
fail_toolchain=0
for t in checkmodule semodule_package semodule semanage restorecon gcc socat \
  runuser seinfo systemctl curl ip; do
  command -v "$t" >/dev/null 2>&1 || { echo "$t not found" >>"$EVIDENCE_DIR/a-toolchain.txt"; fail_toolchain=1; }
done
if [ "$fail_toolchain" = 1 ]; then
  note "policy toolchain incomplete; the experiment cannot proceed"
  printf '%s P5S2-STATE-MCS-RESULT=INCOMPLETE (toolchain unavailable; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi
if command -v auditctl >/dev/null 2>&1; then
  systemctl enable --now auditd >/dev/null 2>&1 || true
  auditctl -e 1 >/dev/null 2>&1 || true
  log "auditd enabled for the AVC evidence channel"
fi

checkmodule -M -m -o /tmp/docker_helper.tmp "$TRANSFERRED/docker-helper.te" 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "checkmodule failed"; exit 1; }
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

log 'A2: builder identity + REAL composition + pinned payload install'
sh "$TRANSFERRED/provision-builder.sh" >"$EVIDENCE_DIR/a2-provision.txt" 2>&1 \
  || { note "provision-builder.sh failed"; exit 1; }
install -m 0755 "$TRANSFERRED/docker-helper" /usr/bin/docker-helper
restorecon /usr/bin/docker-helper 2>>"$EVIDENCE_DIR/a-toolchain.txt" || true
install -m 0644 "$TRANSFERRED/docker-helper-builder.service" /etc/systemd/system/"$UNIT".service
systemctl daemon-reload

BUILDKIT_VERSION=v0.33.0
BUILDKIT_TARBALL="buildkit-${BUILDKIT_VERSION}.linux-amd64.tar.gz"
BUILDKIT_SHA256=b6242896d343100808dcbe37565caf381e0a444a6a83d7255926bb1519248ead
BUILDKITD_SHA256=157da954fa081d9ec4f063d62029fbbf12437c1d47ab63080594eae5a85b36f2
BUILDCTL_SHA256=0b45ae3696f836bf711dbd78138e403924d7733f0b2328ba29a7fcf9ad5f1dfd
BUILDKIT_RUNC_SHA256=0acdd302ddc5540b2e445b683661bfada9935c702f9008ffb0481abcda16c9b4
curl -fsSL -o "$WORK/buildkit.tgz" \
  "https://github.com/moby/buildkit/releases/download/${BUILDKIT_VERSION}/${BUILDKIT_TARBALL}" \
  2>"$EVIDENCE_DIR/a2-payload-download.log" || true
ACTUAL_SHA256="$(sha256sum "$WORK/buildkit.tgz" 2>/dev/null | awk '{print $1}' || true)"
if [ "$ACTUAL_SHA256" != "$BUILDKIT_SHA256" ]; then
  note "BuildKit tarball SHA256 mismatch or download failed (got: ${ACTUAL_SHA256:-none})"
  printf '%s P5S2-STATE-MCS-RESULT=INCOMPLETE (payload download/verify failed; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi
install -d -m 0755 /tmp/p5s2-g30-payload-extract
tar -xzf "$WORK/buildkit.tgz" -C /tmp/p5s2-g30-payload-extract
install -d -m 0755 /usr/libexec/docker-helper/buildkit
install -m 0755 /tmp/p5s2-g30-payload-extract/bin/buildkitd "$BUILDKITD"
install -m 0755 /tmp/p5s2-g30-payload-extract/bin/buildctl "$BUILDCTL"
install -m 0755 /tmp/p5s2-g30-payload-extract/bin/buildkit-runc \
  /usr/libexec/docker-helper/buildkit/buildkit-runc
{
  echo "=== pinned payload verification (in-guest, the P4A1 pattern) ==="
  for f in buildkitd buildctl buildkit-runc; do
    echo "$f: $(sha256sum "/usr/libexec/docker-helper/buildkit/$f" | awk '{print $1}')"
  done
  echo "expected buildkitd:  $BUILDKITD_SHA256"
  echo "expected buildctl:   $BUILDCTL_SHA256"
  echo "expected b-runc:     $BUILDKIT_RUNC_SHA256"
  "$BUILDKITD" --version 2>&1 || true
  "$BUILDCTL" --version 2>&1 || true
} > "$EVIDENCE_DIR/a2-payload.txt" 2>&1

log 'A3: the candidate payload module (v12, unchanged: the final proof runs the exact iteration-12 grant set)'
cat > /tmp/payload_mac_diag.te <<'MODEOF'
module payload_mac_diag 12.0;

# P5-S2g28 guest-only candidate payload module. RUN 14 (the final proof, the SAME v12 grant set): the enforcing
# iteration carrying the per-AVC-evidenced grants from the run-1/2
# permissive harvest (195 unique (s,t,class,perm) denial tuples over the
# full production path) plus every enforcing-proven delta since: run 2.5
# (kernel module autoload), run 3 (the tap-handoff relabel direction),
# run 4 (the resolver's DNS udp write, the buildkitd socket shutdown
# unlink, the net-driver teardown sigkill), run 5 (the DNS reply recv),
# run 6 (the slirp relay's host-side recv), run 7 (the slirp TLS-relay
# tcp send), run 8 (the TLS client's tcp send + the relay teardown
# shutdown), run 9 (the TLS client's tcp recv), run 10 (the relay's tcp
# recv), run 11 (the cgroup getattr probe, the runc kcore masked-path
# stat and the manager's state-tree symlink cleanup), plus the relabel
# reshape (the snapshot copies relabel to the state tree's own type,
# keeping the tree uniform for the manager's mandatory cleanup). The
# run-4..7 relabelto AVC (buildkitd's xattr-preserving local-context
# copy) is SOLVED by policy evidence, not by a new grant: the loaded
# policy constrains file/dir relabelto with (u1 == u2 or
# t1 == can_change_object_identity) — the TE allow exists, the subject
# is system_u, and the stand's harness-created context files were
# unconfined_u; the composition now labels the context files
# system_u:docker_helper_builder_state_t so the existing relabelto
# allow applies and the tree stays uniform. Every rule below is
# attributable to harvested AVC records of the REAL production flow
# (manager -> rootlesskit -> slirp4netns/net driver -> copy-up ->
# buildkitd boot -> readiness -> buildctl build -> export) or the
# manager's own-flow control surface; no rule was designed ahead of
# evidence, audit2allow was not used, no macro/bulk sets were added.
# This module is guest-only, removed at cleanup, and NEVER committed to
# the production policy.
require {
	class capability { setgid };
	class cap_userns { chown dac_override dac_read_search fsetid net_admin setgid setpcap setuid sys_admin sys_chroot sys_ptrace };
	class chr_file { ioctl open read unlink write };
	class dir { add_name create getattr mounton open read remove_name reparent rename rmdir search setattr write };
	class fifo_file { create ioctl open read setattr unlink write };
	class filesystem { getattr mount remount unmount };
	class file { append create execute execute_no_trans getattr ioctl mounton open read relabelfrom relabelto rename setattr unlink write };
	class key { setattr view };
	class lnk_file { create getattr read setattr unlink };
	class netlink_route_socket { bind create getattr getopt setopt read write nlmsg_read nlmsg_write };
	class process { setcap setpgid setsched signal sigkill signull };
	class sock_file { create getattr setattr unlink };
	class system { module_request };
	class tcp_socket { connect create getattr getopt name_connect read setopt shutdown write };
	class tun_socket { create relabelfrom relabelto };
	class udp_socket { connect create getattr read setopt write };
	attribute file_type;
	type bin_t;
	type cert_t;
	type cgroup_t;
	type device_t;
	type devpts_t;
	type docker_helper_builder_runtime_t;
	type docker_helper_builder_state_t;
	type docker_helper_builder_t;
	type docker_helper_newgidmap_t;
	type docker_helper_newuidmap_t;
	type docker_helper_rootlesskit_t;
	type docker_helper_slirp4netns_t;
	type etc_t;
	type fs_t;
	type http_port_t;
	type ifconfig_exec_t;
	type kernel_t;
	type net_conf_t;
	type nsfs_t;
	type passwd_file_t;
	type proc_kcore_t;
	type proc_psi_t;
	type proc_t;
	type root_t;
	type sysctl_fs_t;
	type sysctl_irq_t;
	type sysctl_t;
	type sysfs_t;
	type tmp_t;
	type tmpfs_t;
	type tun_tap_device_t;
	type user_tmp_t;
}
type payload_buildkit_exec_t;
typeattribute payload_buildkit_exec_t file_type;

# the cgroup worker probe (RUN-12 DELTA: run-11 AVC
# 1790610348.259:399, scontext=...rootlesskit_t:s0 pid 2892
# comm=buildkitd, tclass=file perm=getattr, path=/sys/fs/cgroup/
# cgroup.subtree_control — buildkitd's cgroup-delegation probe at worker
# init; the production .te already grants the read/open on the same
# file, the stat is the missing half) and the runc container init's
# masked-path stat (RUN-12 DELTA: run-11 AVCs 1790610348.273-.275:400-
# 401, scontext=...rootlesskit_t:s0 pid 3020 comm=runc:[2:INIT],
# tclass=file perm=getattr, path=/proc/kcore — runc's masked-paths setup
# stats each masked path in the container's mountns before binding the
# mask over it; the init process carries the rootlesskit domain, the
# container binaries execute_no_trans from the extracted state-tree
# files)
allow docker_helper_rootlesskit_t cgroup_t:file { getattr };
allow docker_helper_rootlesskit_t proc_kcore_t:file { getattr };

# ---- the flow's own namespace/identity steps (harvest: the flow reaches
# ---- buildkitd only after these) ----
# getsubids probe + nsenter/ip for the netns tap (rootlesskit v3
# PrepareTap execs `nsenter ... ip tuntap add`; bin_t/ifconfig_exec_t on
# Tumbleweed).
allow docker_helper_rootlesskit_t bin_t:file { execute execute_no_trans };
allow docker_helper_rootlesskit_t ifconfig_exec_t:file { execute execute_no_trans getattr open read };
# in-namespace capability checks the flow's children make inside their own
# userns (the kernel reports these via cap_userns for non-initial userns)
allow docker_helper_rootlesskit_t self:cap_userns { chown dac_override dac_read_search fsetid net_admin setgid setpcap setuid sys_chroot sys_ptrace };
# the runc container children's cap transitions inside the userns
allow docker_helper_rootlesskit_t self:process { setcap setpgid setsched };
allow docker_helper_rootlesskit_t self:key { setattr view };
# route/netns setup (netlink socket ops during the slirp4netns flow)
allow docker_helper_rootlesskit_t self:netlink_route_socket { bind create getattr getopt setopt read write nlmsg_read nlmsg_write };
# tap device access (the `ip tuntap` step opens /dev/net/tun)
allow docker_helper_rootlesskit_t tun_tap_device_t:chr_file { ioctl open read write };
allow docker_helper_rootlesskit_t self:tun_socket { create };
# the tap handoff (RUN-4 FIX): the run-2 harvest records
# 1790599487.339:430/431 both carry scontext=slirp4netns_t (comm=slirp4netns
# pid 2917) — relabelfrom on the tap socket labeled rootlesskit_t (created
# by `ip` as rootlesskit_t), then relabelto onto self; the v2/v3 ledger had
# the direction transposed and run 3 proved the missing rule blocking
# (slirp4netns died before the ready fd: waiting for ready fd ... tap0:
# slirp4netns failed). The exec-transition hygiene trio (noatsecure/siginh/
# rlimitinh, surfaced by the dontaudit unmasking on all four transitions)
# is NOT granted: non-blocking, secure-default-preserving, base-policy
# masked by design.
allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:tun_socket { relabelfrom };
allow docker_helper_slirp4netns_t self:tun_socket { relabelto };
# the copy-up and container mount steps
allow docker_helper_rootlesskit_t root_t:dir { mounton };
allow docker_helper_rootlesskit_t etc_t:dir { mounton };
allow docker_helper_rootlesskit_t tmp_t:dir { mounton };
allow docker_helper_rootlesskit_t tmpfs_t:dir { mounton };
allow docker_helper_rootlesskit_t sysfs_t:dir { mounton };
allow docker_helper_rootlesskit_t proc_t:dir { mounton };
allow docker_helper_rootlesskit_t sysctl_t:dir { mounton };
allow docker_helper_rootlesskit_t sysctl_irq_t:dir { mounton };
allow docker_helper_rootlesskit_t docker_helper_builder_state_t:dir { mounton };
allow docker_helper_rootlesskit_t docker_helper_builder_runtime_t:dir { mounton };
allow docker_helper_rootlesskit_t tmpfs_t:file { mounton };
allow docker_helper_rootlesskit_t docker_helper_builder_state_t:file { mounton };
allow docker_helper_rootlesskit_t sysctl_t:file { mounton };
allow docker_helper_rootlesskit_t proc_t:file { mounton };
allow docker_helper_rootlesskit_t proc_kcore_t:file { mounton };
allow docker_helper_rootlesskit_t tmpfs_t:filesystem { mount remount getattr };
allow docker_helper_rootlesskit_t sysfs_t:filesystem { mount };
allow docker_helper_rootlesskit_t proc_t:filesystem { mount remount };
allow docker_helper_rootlesskit_t devpts_t:filesystem { mount };
allow docker_helper_rootlesskit_t fs_t:filesystem { getattr mount remount unmount };
allow docker_helper_rootlesskit_t device_t:filesystem { getattr };
allow docker_helper_rootlesskit_t cgroup_t:filesystem { getattr };
# sysfs/procfs reads the flow and children make (mountSysfs, resolv.conf,
# pressure stats, kcore masking)
allow docker_helper_rootlesskit_t sysctl_fs_t:dir { search };
allow docker_helper_rootlesskit_t sysctl_fs_t:file { getattr open read };
allow docker_helper_rootlesskit_t proc_psi_t:dir { getattr search };
allow docker_helper_rootlesskit_t proc_psi_t:file { getattr open read };
allow docker_helper_rootlesskit_t proc_t:file { getattr open read };
allow docker_helper_rootlesskit_t nsfs_t:file { getattr open read };
allow docker_helper_rootlesskit_t net_conf_t:file { getattr open read };
allow docker_helper_rootlesskit_t cert_t:dir { search };
allow docker_helper_rootlesskit_t cert_t:file { getattr open read };
allow docker_helper_rootlesskit_t cert_t:lnk_file { read };
# /tmp staging for the flow's temp dirs and the container execs
allow docker_helper_rootlesskit_t tmp_t:dir { add_name create mounton read remove_name rmdir write };
allow docker_helper_rootlesskit_t tmp_t:file { create execute execute_no_trans open unlink write };
allow docker_helper_rootlesskit_t tmpfs_t:dir { create mounton };
allow docker_helper_rootlesskit_t tmpfs_t:file { create mounton open read write };
allow docker_helper_rootlesskit_t tmpfs_t:lnk_file { create read unlink };
# the diag pipe's inherited fd (fd-use ioctl only; write grant is production)
allow docker_helper_rootlesskit_t docker_helper_builder_t:fifo_file { ioctl };

# ---- the pinned BuildKit payload's exec (the payload's OWN binaries) ----
allow docker_helper_rootlesskit_t payload_buildkit_exec_t:file { execute execute_no_trans getattr open read };

# ---- buildkitd's own boot/runtime under --root in the state tree ----
# content store, snapshotter metadata, runc state inside the state tree
allow docker_helper_rootlesskit_t docker_helper_builder_state_t:dir { create getattr rename reparent rmdir setattr };
# the snapshot-local-context copy's relabel (RUN-9 RESHAPE: the
# xattr-preserving copy relabels each snapshot copy to the SOURCE file's
# label; with the composition's state_t-labeled context files the target
# is the state tree's own type, so the tree stays uniformly state_t and
# the manager's mandatory op cleanup can unlink everything — the run-8
# composition (user_tmp_t source labels) instead pulled foreign-typed
# objects into the tree and the manager's cleanup failed with 'state dir
# still present after removal' (run-8 AVC 1790609087.679:401, builder_t
# unlink user_tmp_t:file), leaving the op entry retained; the
# user_tmp_t:file relabelto grant this ledger carried for the old
# composition is REMOVED as dead authority)
allow docker_helper_rootlesskit_t docker_helper_builder_state_t:file { append execute execute_no_trans getattr ioctl relabelfrom relabelto rename setattr unlink mounton open read write };
allow docker_helper_rootlesskit_t docker_helper_builder_state_t:lnk_file { create getattr read setattr };
allow docker_helper_rootlesskit_t docker_helper_builder_state_t:chr_file { unlink };
# per-op runtime tree: the buildkitd socket, the otel socket, runc state,
# exec.fifo (all created under the manager-owned per-op runtime dir)
allow docker_helper_rootlesskit_t docker_helper_builder_runtime_t:dir { add_name create getattr open read remove_name rmdir search setattr write };
allow docker_helper_rootlesskit_t docker_helper_builder_runtime_t:file { create getattr open read rename setattr unlink write };
allow docker_helper_rootlesskit_t docker_helper_builder_runtime_t:sock_file { create getattr setattr unlink };
allow docker_helper_rootlesskit_t docker_helper_builder_runtime_t:fifo_file { create open read setattr unlink write };
# HTTPS pulls and DNS (the resolver inside the userns)
# RUN-10 DELTA: the TLS client's recv (run-9 AVC 1790609647.017:399,
# scontext=...rootlesskit_t:s0 pid 2911 comm=buildkitd,
# tclass=tcp_socket perm=read, the connected relay socket — the TLS
# response could not be read, so the pull failed 'connection refused')
allow docker_helper_rootlesskit_t self:tcp_socket { connect create getattr getopt read setopt write };
allow docker_helper_rootlesskit_t self:udp_socket { connect create getattr read setopt write };
allow docker_helper_rootlesskit_t http_port_t:tcp_socket { name_connect };
# kernel module autoload (RUN-2.5 DELTA, the run-2 permissive AVC
# 1790599487.322:411: scontext=docker_helper_rootlesskit_t
# tcontext=kernel_t tclass=system perm=module_request kmod="char-major-10-200",
# comm="ip", pid 2913, the same syscall window as the granted tun
# open/ioctl; the run-2.5 enforcing attempt died at the tap open with
# ENODEV and an empty AVC window because only a dontaudit was loaded).
# The flow's ONLY path to the tun driver on a module-based distro kernel
# is the kernel's own autoload triggered by opening /dev/net/tun — the
# standard container-domain grant (docker_t/container_t carry it for
# exactly this mechanism). SELinux has no per-module granularity; the
# breadth is inherent and recorded in the privilege review.
allow docker_helper_rootlesskit_t kernel_t:system module_request;
# the export tar's destination file (the harness's user_tmp_t file;
# write/open/setattr only — the relabelto authority was removed with the
# state_t-labeled context composition)
allow docker_helper_rootlesskit_t user_tmp_t:file { open write setattr };

# ---- the slirp4netns helper's own runtime (the net driver) ----
allow docker_helper_slirp4netns_t self:cap_userns { sys_admin sys_ptrace };
# the TLS relay's outbound send (RUN-8 DELTA: run-7 AVCs
# 1790608297.159-533:401-408, scontext=...slirp4netns_t:s0 pid 2882
# comm=slirp4netns, tclass=tcp_socket perm=write, lport/laddr the relay
# sockets, faddr the resolved registry IPs fport=443 — the relay could
# connect but not send, so the pull failed 'connection refused') plus its
# teardown shutdown (RUN-9 DELTA: run-8 AVC 1790609087.616:400,
# scontext=...slirp4netns_t:s0 pid 2865 comm=slirp4netns,
# tclass=tcp_socket perm=shutdown — the relay's socket teardown on the
# relay path, the same close shape every completed relay performs; the
# relay's recv (RUN-11 DELTA: run-10 AVCs 1790610041.156-733:399-403,
# scontext=...slirp4netns_t:s0 pid 2821 comm=slirp4netns,
# tclass=tcp_socket perm=read x5 — the responses could not be received
# and the pull ended 'EOF')
allow docker_helper_slirp4netns_t self:tcp_socket { connect create read setopt shutdown write };
# the DNS-proxy relay's outbound sendto (RUN-6 DELTA: run-5 AVCs
# 1790607009.754:404-407, scontext=...slirp4netns_t:s0 pid 2822
# comm=slirp4netns, tclass=udp_socket perm=write, the reply relay out of
# the netns after the tap-side query arrived) and its host-side recv
# (RUN-7 DELTA: run-6 AVCs 1790607892.742:4039-4058, scontext=...
# slirp4netns_t:s0 pid 2913 comm=slirp4netns, tclass=udp_socket perm=read,
# the DNS proxy's recv on its own relay sockets — the queries were
# relayed out but the replies could not be received, so the resolver saw
# 'read: connection refused')
allow docker_helper_slirp4netns_t self:udp_socket { create getattr read setopt write };
allow docker_helper_slirp4netns_t http_port_t:tcp_socket { name_connect };
allow docker_helper_slirp4netns_t tun_tap_device_t:chr_file { ioctl open read write };
allow docker_helper_slirp4netns_t net_conf_t:file { getattr open read };
allow docker_helper_slirp4netns_t nsfs_t:file { open read };
allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:dir { search };
allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:file { read };
allow docker_helper_slirp4netns_t docker_helper_rootlesskit_t:lnk_file { read };
# rootlesskit's teardown of its net-driver child (RUN-5 DELTA: run-4 AVC
# 1790605769.929:405, scontext=...rootlesskit_t:s0 pid 2823 comm=rootlesskit,
# tcontext=...slirp4netns_t:s0 tclass=process perm=sigkill, fired when the
# failed flow's launch vehicle tore the net driver down)
allow docker_helper_rootlesskit_t docker_helper_slirp4netns_t:process { sigkill };

# ---- the uid/gid map helpers: the gid step needs the SAME privilege
# ---- shape the uid step already holds (the production .te grants
# ---- newuidmap_t self:cap_userns sys_admin + self:capability setuid;
# ---- the flow's gid step needs the exact mirrors). With the G26 delta
# ---- loaded, the cross-operation gid_map write stays MCS-blocked.
allow docker_helper_newgidmap_t self:cap_userns { sys_admin };
allow docker_helper_newgidmap_t self:capability { setgid };
allow docker_helper_newuidmap_t passwd_file_t:file { getattr };
allow docker_helper_newgidmap_t passwd_file_t:file { getattr };

# the manager's own-tree cleanup of the extracted image objects
# (RUN-12 DELTA: run-11 AVCs 1790610348.358:402-418+, scontext=...
# builder_t:s0 pid 2816 comm=docker-helper, tclass=lnk_file perms
# { unlink read } on docker_helper_builder_state_t — the op cleanup's
# RemoveAll walks the state tree whose runc-overlayfs snapshot now
# contains the extracted image's busybox symlinks; without lnk_file
# unlink/read the mandatory op cleanup cannot converge)
allow docker_helper_builder_t docker_helper_builder_state_t:lnk_file { read unlink };

# ---- the manager's own-flow process control (the live STOP path) ----
# terminateGroupBounded sends SIGTERM/SIGKILL to the flow's process group
# and probes liveness with signull; without these the live group cannot
# be stopped and STOP never converges. The manager is the trusted control
# plane that owns every operation (the G26 boundary analysis excludes it
# from the constrained set).
allow docker_helper_builder_t docker_helper_rootlesskit_t:process { sigkill signal signull };
allow docker_helper_builder_t docker_helper_slirp4netns_t:process { sigkill signal signull };
MODEOF
cat > /tmp/payload_mac_diag.fc <<'FCOF'
/usr/libexec/docker-helper/buildkit(/.*)?    --    system_u:object_r:payload_buildkit_exec_t:s0
FCOF
{
  echo "=== the candidate payload module (source, run 13: the UNCHANGED iteration-12 grant set) ==="
  cat /tmp/payload_mac_diag.te
  echo "=== its file contexts ==="
  cat /tmp/payload_mac_diag.fc
} > "$EVIDENCE_DIR/a3-candidate-module.txt" 2>&1
checkmodule -M -m -o /tmp/payload_mac_diag.tmp /tmp/payload_mac_diag.te 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "the candidate payload module failed to compile"; exit 1; }
semodule_package -o /tmp/payload_mac_diag.pp -m /tmp/payload_mac_diag.tmp -f /tmp/payload_mac_diag.fc 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "the candidate payload module failed to package"; exit 1; }
semodule -i /tmp/payload_mac_diag.pp 2>>"$EVIDENCE_DIR/a-toolchain.txt" \
  || { note "the candidate payload module failed to load"; exit 1; }
restorecon -R /usr/libexec/docker-helper 2>>"$EVIDENCE_DIR/a-toolchain.txt" || true
{
  echo "=== payload labels after the candidate module's restorecon ==="
  stat -c '%C %U:%G %a' "$BUILDKITD" "$BUILDCTL" /usr/libexec/docker-helper/buildkit/buildkit-runc 2>&1
} >> "$EVIDENCE_DIR/a2-payload.txt"
cat "$EVIDENCE_DIR/a2-payload.txt" >&2

log 'C: the G26 MCS-constraint delta (guest-only, verbatim)'
cat > /tmp/gidmap_mcsboundary_diag.te <<'DELTAEOF'
module gidmap_mcsboundary_diag 1.0;

# P5-S2g26 guest-only policy delta (reused verbatim by g27/g28): the ONLY
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
} > "$EVIDENCE_DIR/c-policy-delta.txt"
checkmodule -M -m -o /tmp/gidmap_mcsboundary_diag.tmp /tmp/gidmap_mcsboundary_diag.te 2>>"$EVIDENCE_DIR/c-policy-delta.txt" \
  && semodule_package -o /tmp/gidmap_mcsboundary_diag.pp -m /tmp/gidmap_mcsboundary_diag.tmp 2>>"$EVIDENCE_DIR/c-policy-delta.txt" \
  && semodule -i /tmp/gidmap_mcsboundary_diag.pp 2>>"$EVIDENCE_DIR/c-policy-delta.txt" \
  || { note "the G26 MCS delta failed to load"; exit 1; }
seinfo -a mcs_constrained_type -x 2>/dev/null > "$EVIDENCE_DIR/c-mcs-members.txt" || true
cat "$EVIDENCE_DIR/c-policy-delta.txt" >&2

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
  } > "$EVIDENCE_DIR/stand-failure-unit.txt" 2>&1
  printf '%s P5S2-STATE-MCS-RESULT=INCOMPLETE (unit failed to start; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi
MG_PID="$(systemctl show -p MainPID --value "$UNIT")"
{
  echo "=== the REAL unit active ==="
  echo "manager pid: $MG_PID"
  echo "manager attr/current: $(tr -d '\0' < "/proc/$MG_PID/attr/current" 2>/dev/null || true)"
  echo "manager cgroup: $(cat "/proc/$MG_PID/cgroup" 2>/dev/null || true)"
  echo "state root: $(stat -c '%C %U:%G %a' "$STATE_ROOT" 2>&1)"
  echo "runtime root: $(stat -c '%C %U:%G %a' "$RUNTIME_ROOT" 2>&1)"
  echo "manager.sock: $(stat -c '%C %U:%G %a' "$MANAGER_SOCK" 2>&1)"
} > "$EVIDENCE_DIR/d-manager-up.txt" 2>&1
cat "$EVIDENCE_DIR/d-manager-up.txt" >&2
if ! stat -c '%C' "$STATE_ROOT" 2>/dev/null | grep -q 'docker_helper_builder_state_t'; then
  note "the state root is not labeled builder_state_t; the experiment cannot proceed"
  printf '%s P5S2-STATE-MCS-RESULT=INCOMPLETE (state root label; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi

log 'I: the stand probe vehicle + assignment gate (the mutation instruments)'
mkdir -p "$WORK/probe" "$WORK/tools"
# The probe vehicle and the probe module follow the G28 stand shapes
# (stand fixtures only; the legs use ONLY the candidate policy's already-
# proven rootlesskit_t -> builder_state_t surface; the probe module grants
# NOTHING to the flow/payload domains beyond what the candidate module
# already carries). map_probe gains three modes for G30: --stat PATH
# (the getattr leg), --flock PATH (the state-lock leg), and keeps the
# G29-exact --poison
# MARKER (open O_WRONLY, pwrite at the offset, fsync, read-back).
cat > "$WORK/probe/map_probe.c" <<'PROBEOF'
/* P5-S2g30 stand probe vehicle (guest-only fixture; the G28 vehicle plus
 * the G30 --stat/--flock modes). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static void emit_facts(const char *tag) {
  char buf[256];
  ssize_t n;
  int fd = open("/proc/self/attr/current", O_RDONLY);
  if (fd < 0) { printf("PROBE %s selinux=UNAVAILABLE errno=%d\n", tag, errno); return; }
  n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n < 0) n = 0;
  if (n > 0 && buf[n-1] == '\n') n--;
  buf[n] = '\0';
  printf("PROBE %s selinux=%s uid=%d pid=%d\n", tag, buf, (int)getuid(), (int)getpid());
}

static int do_open_read(const char *path) {
  int fd = open(path, O_RDONLY);
  printf("READ path=%s rc=%d errno=%d\n", path, fd, errno);
  if (fd >= 0) close(fd);
  return fd >= 0 ? 0 : 1;
}

static int do_open_write(const char *path) {
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  printf("WRITE path=%s rc=%d errno=%d\n", path, fd, errno);
  if (fd >= 0) { write(fd, "probe\n", 6); close(fd); }
  return fd >= 0 ? 0 : 1;
}

static int do_stat(const char *path) {
  struct stat st;
  int rc = stat(path, &st);
  printf("STAT path=%s rc=%d errno=%d", path, rc, errno);
  if (rc == 0) printf(" mode=0%o size=%lld", (int)(st.st_mode & 07777), (long long)st.st_size);
  printf("\n");
  return rc == 0 ? 0 : 1;
}

static int do_flock(const char *path) {
  emit_facts("flocker");
  int fd = open(path, O_RDONLY);
  printf("FLOCK-OPEN path=%s rc=%d errno=%d\n", path, fd, errno);
  if (fd < 0) return 1;
  int rc = flock(fd, LOCK_EX | LOCK_NB);
  printf("FLOCK path=%s rc=%d errno=%d\n", path, rc, errno);
  close(fd);
  return rc == 0 ? 0 : 1;
}

static int do_unlink(const char *path) {
  int rc = unlink(path);
  printf("UNLINK path=%s rc=%d errno=%d\n", path, rc, errno);
  return rc == 0 ? 0 : 1;
}

static int do_connect(const char *path) {
  struct sockaddr_un sa;
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) { printf("CONNECT path=%s socket-rc=%d errno=%d\n", path, fd, errno); return 1; }
  memset(&sa, 0, sizeof(sa));
  sa.sun_family = AF_UNIX;
  strncpy(sa.sun_path, path, sizeof(sa.sun_path) - 1);
  int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
  printf("CONNECT path=%s rc=%d errno=%d\n", path, rc, errno);
  close(fd);
  return rc == 0 ? 0 : 1;
}

static int do_signal(int pid, int sig) {
  int rc = kill(pid, sig);
  printf("SIGNAL target=%d sig=%d rc=%d errno=%d\n", pid, sig, rc, errno);
  int alive = kill(pid, 0);
  printf("SIGNAL target=%d alive-check-rc=%d errno=%d\n", pid, alive, errno);
  return rc == 0 ? 0 : 1;
}

static int do_poison(const char *path, long long offset, const char *marker) {
  emit_facts("poisoner");
  /* The content store finalizes blobs as owner-RO (mode 0444). The write
   * surface this measurement exercises is the SAME granted domain
   * authority (rootlesskit_t -> builder_state_t:file setattr + write,
   * both granted by the loaded policy); the mode flip is performed by
   * the vehicle itself (owner chmod, no root), and the original mode is
   * restored after the write. */
  struct stat st;
  int need_mode_flip = 0;
  if (stat(path, &st) != 0) { printf("POISON-STAT path=%s rc=-1 errno=%d\n", path, errno); return 1; }
  printf("POISON-STAT path=%s mode=0%o size=%lld\n", path, (int)(st.st_mode & 07777), (long long)st.st_size);
  if (!(st.st_mode & S_IWUSR)) {
    need_mode_flip = 1;
    int cr = chmod(path, 0600);
    printf("POISON-CHMOD path=%s to=0600 rc=%d errno=%d\n", path, cr, errno);
    if (cr != 0) return 1;
  }
  int fd = open(path, O_WRONLY);
  printf("POISON-OPEN path=%s rc=%d errno=%d\n", path, fd, errno);
  if (fd < 0) { if (need_mode_flip) chmod(path, st.st_mode & 07777); return 1; }
  size_t len = strlen(marker);
  ssize_t n = pwrite(fd, marker, len, (off_t)offset);
  printf("POISON-PWRITE path=%s offset=%lld len=%zu rc=%zd errno=%d\n", path, offset, len, n, errno);
  int fs = fsync(fd);
  printf("POISON-FSYNC rc=%d errno=%d\n", fs, errno);
  close(fd);
  if (need_mode_flip) {
    int cr2 = chmod(path, st.st_mode & 07777);
    printf("POISON-CHMOD-RESTORE path=%s to=0%o rc=%d errno=%d\n", path, (int)(st.st_mode & 07777), cr2, errno);
  }
  if (n < 0) return 1;
  char *buf = calloc(len + 1, 1);
  if (!buf) return 1;
  fd = open(path, O_RDONLY);
  printf("POISON-READBACK-OPEN rc=%d errno=%d\n", fd, errno);
  if (fd < 0) { free(buf); return 1; }
  ssize_t rn = pread(fd, buf, len, (off_t)offset);
  int match = (rn == (ssize_t)len) && (memcmp(buf, marker, len) == 0);
  printf("POISON-READBACK path=%s offset=%lld rc=%zd match=%d data=%.*s\n", path, offset, rn, match, (int)(rn > 0 ? rn : 0), buf);
  close(fd);
  free(buf);
  return match ? 0 : 1;
}

static int spawn_signal(int sig) {
  /* The G26 spawn shape: the measured kill, then the unconditional
   * cleanup-kill and the plain reap. NO wait that can block on a denied
   * stop — the SELinux verdict is the kill's rc/errno, never a wait. */
  pid_t c = fork();
  if (c == 0) { emit_facts("spawned-child"); for (;;) pause(); }
  emit_facts("spawner");
  printf("SPAWN child=%d\n", c);
  int rc = kill(c, sig);
  printf("SPAWN-SIGNAL child=%d sig=%d rc=%d errno=%d\n", c, sig, rc, errno);
  fflush(stdout);
  int rc2 = kill(c, SIGKILL);
  printf("SPAWN-CLEANUP child=%d rc=%d errno=%d\n", c, rc2, errno);
  int st;
  if (waitpid(c, &st, 0) < 0) printf("SPAWN-REAP failed errno=%d\n", errno);
  else printf("SPAWN-REAP pid=%d st=0x%x\n", c, st);
  return rc == 0 ? 0 : 1;
}

static int invoke_helper(char **argv) {
  execv(argv[0], argv);
  printf("INVOKE-HELPER execv-errno=%d\n", errno);
  return 1;
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  if (argc < 2) { fprintf(stderr, "usage: map_probe MODE ...\n"); return 2; }
  if (strcmp(argv[1], "--facts") == 0) { emit_facts("vehicle"); return 0; }
  if (strcmp(argv[1], "--be-target") == 0 && argc == 3) {
    if (unshare(CLONE_NEWUSER) != 0) { printf("BE-TARGET unshare-errno=%d\n", errno); return 1; }
    emit_facts("be-target");
    int fd = open(argv[2], O_WRONLY);
    if (fd < 0) { printf("BE-TARGET open-errno=%d\n", errno); return 1; }
    dprintf(fd, "PID=%d\n", getpid());
    close(fd);
    for (;;) pause();
    return 0;
  }
  if (strcmp(argv[1], "--invoke-helper") == 0 && argc >= 4) return invoke_helper(&argv[2]);
  if (strcmp(argv[1], "--signal") == 0 && argc == 4) return do_signal(atoi(argv[2]), atoi(argv[3]));
  if (strcmp(argv[1], "--spawn-signal") == 0 && argc == 3) return spawn_signal(atoi(argv[2]));
  if (strcmp(argv[1], "--read") == 0 && argc == 3) return do_open_read(argv[2]);
  if (strcmp(argv[1], "--write") == 0 && argc == 3) return do_open_write(argv[2]);
  if (strcmp(argv[1], "--unlink") == 0 && argc == 3) return do_unlink(argv[2]);
  if (strcmp(argv[1], "--connect") == 0 && argc == 3) return do_connect(argv[2]);
  if (strcmp(argv[1], "--poison") == 0 && argc == 5) return do_poison(argv[2], atoll(argv[3]), argv[4]);
  if (strcmp(argv[1], "--stat") == 0 && argc == 3) return do_stat(argv[2]);
  if (strcmp(argv[1], "--flock") == 0 && argc == 3) return do_flock(argv[2]);
  fprintf(stderr, "usage: map_probe MODE ...\n");
  return 2;
}
PROBEOF
cat > /tmp/gidmap_probe_diag.te <<'PROBEEOF'
module gidmap_probe_diag 1.1;
# P5-S2g28 guest-only stand probe module: the PROBE VEHICLE's fixture
# surface only (the runcon chain, the probe binary's exec/entry, the
# stand's /tmp fixture tree, the inherited evidence fds). It grants
# NOTHING to the flow/payload domains beyond what the candidate module
# already carries; the E-legs' DENIED attempts must stay denied (any
# ALLOWED cross-op attempt is the measurement, never masked).
require {
	type docker_helper_newuidmap_t;
	type docker_helper_rootlesskit_t;
	type unconfined_t;
	type bin_t;
	type user_tmp_t;
	attribute file_type;
	class file { entrypoint read open execute execute_no_trans getattr map append write create setattr relabelto unlink };
	class fifo_file { read write open getattr };
	class lnk_file { read };
	class dir { search getattr read open write add_name create remove_name rmdir };
	class process { transition siginh };
	class fd { use };
}
type gidmap_probe_exec_t;
typeattribute gidmap_probe_exec_t file_type;
type_transition unconfined_t bin_t:file gidmap_probe_exec_t "map_probe";
allow unconfined_t gidmap_probe_exec_t:file { create open write append setattr relabelto };
allow unconfined_t docker_helper_rootlesskit_t:process { transition siginh };
allow docker_helper_rootlesskit_t gidmap_probe_exec_t:file { entrypoint read open execute execute_no_trans getattr map };
allow docker_helper_newuidmap_t gidmap_probe_exec_t:file { entrypoint read open execute getattr map };
allow docker_helper_newuidmap_t unconfined_t:fd use;
allow docker_helper_newuidmap_t user_tmp_t:file { append write };
allow docker_helper_rootlesskit_t unconfined_t:fd use;
allow docker_helper_rootlesskit_t user_tmp_t:dir { search getattr read open write add_name create remove_name rmdir };
allow docker_helper_rootlesskit_t user_tmp_t:file { create open read write getattr setattr unlink append };
allow docker_helper_rootlesskit_t user_tmp_t:fifo_file { read write open getattr };
allow docker_helper_rootlesskit_t user_tmp_t:lnk_file { read };
PROBEEOF
{
  echo "=== the probe module source (unchanged from G28) ==="
  cat /tmp/gidmap_probe_diag.te
} > "$EVIDENCE_DIR/i-probe-module.txt" 2>&1
checkmodule -M -m -o /tmp/gidmap_probe_diag.tmp /tmp/gidmap_probe_diag.te 2>>"$EVIDENCE_DIR/i-probe-module.txt" \
  || { note "the probe module failed to compile"; exit 1; }
semodule_package -o /tmp/gidmap_probe_diag.pp -m /tmp/gidmap_probe_diag.tmp 2>>"$EVIDENCE_DIR/i-probe-module.txt" \
  || { note "the probe module failed to package"; exit 1; }
semodule -i /tmp/gidmap_probe_diag.pp 2>>"$EVIDENCE_DIR/i-probe-module.txt" \
  || { note "the probe module failed to load"; exit 1; }
gcc -static -O2 -o /usr/local/bin/map_probe "$WORK/probe/map_probe.c" 2>>"$EVIDENCE_DIR/i-probe-module.txt" \
  || { note "the probe vehicle failed to build"; exit 1; }
PROBE_LABEL="$(stat -c '%C' /usr/local/bin/map_probe 2>&1)"
echo "probe label (post-build, the creation type-transition): $PROBE_LABEL" >> "$EVIDENCE_DIR/i-probe-module.txt"
cat "$EVIDENCE_DIR/i-probe-module.txt" >&2


log 'I2: the assignment gate (the runcon chain, the c1/c2 vehicles)'
RK_CTX="system_u:system_r:docker_helper_rootlesskit_t"
RK_C1="$RK_CTX:s0:c1"
RK_C2="$RK_CTX:s0:c2"
{
  echo "=== the runner's own context (the assignment chain's root) ==="
  echo "runner attr/current: $(tr -d '\0' < /proc/self/attr/current 2>/dev/null || true)"
  echo "=== the builder's PAM context after runuser ==="
  echo "builder context: $(runuser -u "$BUILDER_USER" -- id -Z 2>/dev/null || echo UNAVAILABLE)"
  echo "=== assignment probe A: runuser+runcon to $RK_C1 ==="
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_C1" /usr/local/bin/map_probe --facts 2>&1 || echo "assignment A rc=$?"
  echo "=== assignment probe B: runuser+runcon to $RK_C2 ==="
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_C2" /usr/local/bin/map_probe --facts 2>&1 || echo "assignment B rc=$?"
} > "$EVIDENCE_DIR/i-assignment.txt" 2>&1
cat "$EVIDENCE_DIR/i-assignment.txt" >&2
ASSIGN_OK=0
if grep -aq 'PROBE vehicle selinux=system_u:system_r:docker_helper_rootlesskit_t:s0:c1' "$EVIDENCE_DIR/i-assignment.txt" \
   && grep -aq 'PROBE vehicle selinux=system_u:system_r:docker_helper_rootlesskit_t:s0:c2' "$EVIDENCE_DIR/i-assignment.txt"; then
  ASSIGN_OK=1
fi
if [ "$ASSIGN_OK" = 0 ]; then
  note "OBSTACLE: the required MCS categories are not assignable (see i-assignment.txt); the isolation legs cannot proceed"
  printf '%s P5S2-STATE-MCS-RESULT=INCOMPLETE (assignment failed; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi

# The analysis tools (guest-only stand fixtures).
tar_report() { # tar json [poison] — the export-report tool wrapper
  python3 "$WORK/tools/tar_report.py" "$1" "$2" "$3" \
    > "$EVIDENCE_DIR/$(basename "$2").run" 2>&1 || true
}
cat > "$WORK/tools/tar_report.py" <<'PYEOF'
import tarfile, io, json, hashlib, sys
path, out, poison = sys.argv[1], sys.argv[2], sys.argv[3]
pb = poison.encode() if poison else b''
by_name = {}
order = []
layers = {}
manifest_raw = None
with tarfile.open(path, 'r:*') as tf:
    for m in tf.getmembers():
        if not m.isfile():
            continue
        data = tf.extractfile(m).read()
        rec = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        if pb:
            rec['poison_at'] = data.find(pb)
        if m.name == 'manifest.json':
            manifest_raw = data
        by_name[m.name] = rec
        order.append(m.name)
        layers[m.name] = data
rep = {'members': order, 'by_name': by_name}
if manifest_raw is not None:
    rep['manifest_raw_sha256'] = hashlib.sha256(manifest_raw).hexdigest()
    rep['manifest_raw'] = manifest_raw.decode(errors='replace')
    marker = []
    try:
        mj = json.loads(manifest_raw)
        e0 = mj[0]
        rep['layers'] = e0.get('Layers', [])
        rep['config'] = e0.get('Config', '')
        for name in e0.get('Layers', []):
            data = layers.get(name)
            if data is None:
                marker.append({'layer': name, 'missing': True})
                continue
            try:
                with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as lt:
                    for lm in lt.getmembers():
                        n = lm.name
                        if n.startswith('./'):
                            n = n[2:]
                        if n.startswith('m1/') or n.startswith('m2/'):
                            marker.append({'layer': name, 'name': lm.name,
                                           'content': lt.extractfile(lm).read().decode(errors='replace')})
            except Exception as e:
                marker.append({'layer': name, 'inner_tar_error': repr(e)})
    except Exception as e:
        rep['manifest_err'] = repr(e)
    rep['marker'] = marker
json.dump(rep, open(out, 'w'), indent=1, sort_keys=True)
PYEOF
cat > "$WORK/tools/state_inventory.py" <<'PYEOF'
import os, sys, hashlib, json
root, out = sys.argv[1], sys.argv[2]
files = []
dirs = []
for dirpath, dirnames, filenames in os.walk(root):
    dirs.append(os.path.relpath(dirpath, root))
    for f in sorted(filenames):
        p = os.path.join(dirpath, f)
        st = os.lstat(p)
        rec = {'path': os.path.relpath(p, root), 'size': st.st_size,
               'mode': oct(st.st_mode & 0o7777), 'uid': st.st_uid, 'gid': st.st_gid}
        try:
            rec['scontext'] = os.getxattr(p, 'security.selinux', follow_symlinks=False).decode().rstrip('\x00')
        except OSError as e:
            rec['scontext'] = 'ERR:%d' % e.errno
        if not os.path.islink(p) and st.st_size <= 64 * 1024 * 1024:
            h = hashlib.sha256()
            with open(p, 'rb') as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b''):
                    h.update(chunk)
            rec['sha256'] = h.hexdigest()
        files.append(rec)
files.sort(key=lambda r: r['path'])
json.dump({'root': root, 'dirs': sorted(dirs), 'files': files}, open(out, 'w'), indent=1, sort_keys=True)
PYEOF
{
  echo "=== the analysis tools (guest-only stand fixtures) ==="
  for t in tar_report.py state_inventory.py; do
    echo "--- $t ---"; cat "$WORK/tools/$t"
  done
} > "$EVIDENCE_DIR/e-tools.txt" 2>&1


log 'E: per-operation state-tree MCS isolation (the G30 stand)'
# Harvest completeness: disable every dontaudit rule (ours and the base
# policy's) so NO denial can hide from the leg harvests; re-enabled at
# teardown. Guest-only, evidence-driven harvest hygiene.
semanage dontaudit off >>"$EVIDENCE_DIR/te-dontaudit-off.log" 2>&1 || true
HV_EPOCH="$(date +%s)"
OPB="$(gen_op_id)"
RB="$RUNTIME_ROOT/ops/$OPB"
SB="$STATE_ROOT/ops/$OPB"
# the manager's fixed child PATH (builder_manager.go:48); the payload
# directory is part of it.
CHILD_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/usr/libexec/docker-helper/buildkit"
# the manager's frozen CA resolver shape (builderSystemCABundleCandidates,
# builder_manager.go:946): the first real readable bundle in its resolved
# real-path form (the M0/M1 realpath fix).
CA=""
for cand in /etc/ssl/ca-bundle.pem /var/lib/ca-certificates/ca-bundle.pem \
            /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt; do
  if [ -f "$cand" ]; then
    CA="$(readlink -f "$cand" 2>/dev/null || true)"
    [ -n "$CA" ] && break
  fi
done
[ -n "$CA" ] || { note "no system CA bundle resolved; stand incomplete"; printf '%s P5S2-STATE-MCS-RESULT=INCOMPLETE (no CA bundle)\n' "$PREFIX" >&2; exit 0; }
CONSUME_LEG=0
mkdir -p "$WORK/ctx" "$WORK/export" "$WORK/probe" "$WORK/tools"

# provision_tree opid category — the manager's exact shape
# (launchInstance: the runtime dir + state/rootlesskit-state + state/root,
# 0700, builder-owned) with the operation's category assigned to the
# state-tree directories (the allocator stand-in; the runtime tree keeps
# the production runtime_t:s0 shape — TE-isolated, not MCS-scoped).
provision_tree() {
  local op="$1" cat="$2"
  mkdir -p "$RUNTIME_ROOT/ops" 2>/dev/null || true
  chown "$BUILDER_USER":"$BUILDER_USER" "$RUNTIME_ROOT/ops" 2>/dev/null || true
  chmod 700 "$RUNTIME_ROOT/ops" 2>/dev/null || true
  mkdir -p "$STATE_ROOT/ops" 2>/dev/null || true
  chown "$BUILDER_USER":"$BUILDER_USER" "$STATE_ROOT/ops" 2>/dev/null || true
  chmod 700 "$STATE_ROOT/ops" 2>/dev/null || true
  mkdir -p "$RUNTIME_ROOT/ops/$op" "$STATE_ROOT/ops/$op/rootlesskit-state" "$STATE_ROOT/ops/$op/root"
  chown "$BUILDER_USER":"$BUILDER_USER" "$RUNTIME_ROOT/ops/$op" "$STATE_ROOT/ops/$op" \
        "$STATE_ROOT/ops/$op/rootlesskit-state" "$STATE_ROOT/ops/$op/root"
  chmod 700 "$RUNTIME_ROOT/ops/$op" "$STATE_ROOT/ops/$op" \
            "$STATE_ROOT/ops/$op/rootlesskit-state" "$STATE_ROOT/ops/$op/root"
  chcon -u system_u -t docker_helper_builder_state_t -l "$cat" \
        "$STATE_ROOT/ops/$op" "$STATE_ROOT/ops/$op/rootlesskit-state" "$STATE_ROOT/ops/$op/root"
  chcon -u system_u -t docker_helper_builder_runtime_t "$RUNTIME_ROOT/ops/$op" 2>/dev/null || true
}

log 'F: Part A — the labeling model + the category-propagation mechanism'
# The model: the operation's state tree carries the operation's category
# at the three top-level directories; every descendant inherits the
# containing directory's range through the policy's default-range
# TARGET_LOW rule. G26's measured s0 objects were created inside s0
# directories: the inheritance mechanism was already there; the trees
# were just never categorized.
provision_tree "$OPB" "s0:c2"
{
  echo "=== Part A: the provisioned operation tree labels (the manager's shape + s0:c2) ==="
  echo "op B id: $OPB"
  stat -c '%C %U:%G %a %n' "$RB" "$SB" "$SB/rootlesskit-state" "$SB/root"
} > "$EVIDENCE_DIR/a-provision-labels.txt" 2>&1
cat "$EVIDENCE_DIR/a-provision-labels.txt" >&2

# a1: a c2 vehicle creates a file inside the c2 tree; the created file's
# context must be state_t:s0:c2 (the directory's range inherited).
set +e
timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_C2" /usr/local/bin/map_probe --write "$SB/root/a1-created" \
  > "$EVIDENCE_DIR/a1-propagation-create.txt" 2>&1
set -e
{
  echo "=== Part A a1: the c2 vehicle's creation inside the c2 tree ==="
  grep -E 'vehicle|WRITE|ERROR' "$EVIDENCE_DIR/a1-propagation-create.txt" || true
  echo "created file context: $(stat -c '%C' "$SB/root/a1-created" 2>&1)"
  echo "expected: docker_helper_builder_state_t:s0:c2 (the default-range TARGET_LOW inheritance)"
} > "$EVIDENCE_DIR/a1-propagation.txt" 2>&1
cat "$EVIDENCE_DIR/a1-propagation.txt" >&2

# a2 (structural, no leg): the default-range mechanism is per-class,
# not per-creator — the a1 measurement covers every creator whose MCS
# allows the containing directory (the manager domain is not
# mcs_constrained, so its creations inside a categorized tree would
# inherit the tree's category the same way). The reachable production
# lifecycle never creates inside an existing operation tree (the
# adoption check refuses pre-existing trees); the allocator's future
# integration point is the tree provisioning step itself.

# a3: the loaded policy's default-range statements as the binary policy
# reports them (seinfo --default; the behavioral proof is a1/a2 and the
# descendant inventory regardless).
{
  echo "=== Part A a3: the loaded policy's default-range statements ==="
  seinfo --default 2>&1 || true
} > "$EVIDENCE_DIR/a3-default-range.txt" 2>&1
grep -i 'default' "$EVIDENCE_DIR/a3-default-range.txt" >&2 || true

log 'H: Part C — op B launched at its category (the manager transition path, the production argv)'
# The launch vehicle: runuser to the builder identity, runcon to the
# manager's type at the operation's category, then exec the PRODUCTION
# rootlesskit argv. The policy's existing type_transition
# builder_t -> rootlesskit_t on the rootlesskit entry file fires on the
# exec, and a process transition with no range_transition copies the
# caller's full range (the kernel mls_compute_sid AVTAB_CHANGE fallback
# for the process class), so the flow starts at
# docker_helper_rootlesskit_t:s0:c2 without any new policy mechanism.
# This is the same transition path the manager uses; only the caller's
# category differs.
{
  echo "=== Part C: the launch command (the production argv, the manager transition path) ==="
  echo "launch context: runuser builder -> env <manager env> -> runcon $RK_C2 -> /usr/bin/rootlesskit (the forced exec lands rootlesskit_t:s0:c2: the entry file has the entrypoint grant for this domain)"
  echo "argv: /usr/bin/rootlesskit --net=slirp4netns --copy-up=/etc --disable-host-loopback --state-dir=$SB/rootlesskit-state $BUILDKITD --rootless --root=$SB/root --addr=unix://$RB/buildkitd.sock"
} > "$EVIDENCE_DIR/c-launch-cmd.txt" 2>&1
runuser -u "$BUILDER_USER" -- env HOME="$STATE_ROOT" USER="$BUILDER_USER" \
    XDG_RUNTIME_DIR="$RB" PATH="$CHILD_PATH" SSL_CERT_FILE="$CA" \
    runcon "$RK_C2" /usr/bin/rootlesskit --net=slirp4netns --copy-up=/etc --disable-host-loopback \
    --state-dir="$SB/rootlesskit-state" "$BUILDKITD" --rootless --root="$SB/root" \
    --addr="unix://$RB/buildkitd.sock" </dev/null > "$EVIDENCE_DIR/c-launch-log.txt" 2>&1 &
RB_SOCK="$RB/buildkitd.sock"
RB_READY=0
B_WAIT=0
until [ -S "$RB_SOCK" ] || [ "$B_WAIT" -ge 90 ]; do
  sleep 1
  B_WAIT=$((B_WAIT + 1))
done
[ -S "$RB_SOCK" ] && RB_READY=1
BUILDER_UID="$(id -u "$BUILDER_USER" 2>/dev/null || echo 475)"
BK_PID=""
for bpid in $(pgrep -f "buildkitd --rootless --root=$SB/root" 2>/dev/null || true); do
  if [ "$(ps -o uid= -p "$bpid" 2>/dev/null | tr -d ' ' || true)" = "$BUILDER_UID" ]; then
    BK_PID="$bpid"
    break
  fi
done
{
  echo "=== Part C: op B launch/readiness at s0:c2 ==="
  echo "sock ready: $RB_READY (wait ${B_WAIT}s)"
  echo "buildkitd pid: ${BK_PID:-none}"
  if [ -n "$BK_PID" ]; then
    echo "buildkitd attr/current: $(tr -d '\0' < "/proc/$BK_PID/attr/current" 2>/dev/null || true)"
    echo "buildkitd uid: $(ps -o uid= -p "$BK_PID" 2>/dev/null || true)"
    echo "buildkitd uid_map: $(tr '\n' ' ' < "/proc/$BK_PID/uid_map" 2>/dev/null || true)"
  fi
  echo "sock: $(stat -c '%C %U:%G %a' "$RB_SOCK" 2>&1)"
} > "$EVIDENCE_DIR/c-launch-ready.txt" 2>&1
cat "$EVIDENCE_DIR/c-launch-ready.txt" >&2
if [ "$RB_READY" -ne 1 ]; then
  note "op B failed to reach readiness at s0:c2"
  harvest_avcs_since "$(date +%s)" "$EVIDENCE_DIR/c-launch-avcs.txt"
  head -40 "$EVIDENCE_DIR/c-launch-avcs.txt" >&2 || true
  printf '%s P5S2-STATE-MCS-RESULT=INCOMPLETE (op B launch at c2 failed; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi

# the per-operation build context: the files carry the operation's
# category (state_t:s0:c2) so the snapshotter's xattr-preserving
# local-context copy relabels the context snapshot into the tree's
# category instead of de-categorizing it (the G28 reshape mechanism,
# now at the op's category). The Dockerfile shape is the G29 consume
# shape (alpine FROM; the fresh RUN writes m2/{nonce,id,marker,uid_map}).
CTX="$WORK/ctx"
mkdir -p "$CTX"
write_consume_dockerfile() { # nonce — rewrites the Dockerfile (label persists)
  cat > "$CTX/Dockerfile" <<EOF
FROM alpine:3.20
RUN mkdir -p /m2 && echo p5s2-g29-nonce-$1 > /m2/nonce.txt && id > /m2/id.txt && echo p5s2-g29-marker2 > /m2/marker.txt && cat /proc/self/uid_map > /m2/uid_map.txt
EOF
}
write_consume_dockerfile 0
chcon -u system_u -t docker_helper_builder_state_t -l s0:c2 "$CTX" "$CTX/Dockerfile"
mkdir -p "$WORK/docker-config" "$WORK/export" "$WORK/reports"
echo '{}' > "$WORK/docker-config/config.json"
do_build() { # sock dest logpath ctxdir — caller wraps with set +e/set -e and reads $BUILD_RC
  DOCKER_CONFIG="$WORK/docker-config" timeout 300 "$BUILDCTL" \
    --addr "unix://$1" build \
    --progress=plain --frontend=dockerfile.v0 \
    --local "context=$4" --local "dockerfile=$4" \
    --output "type=docker,name=p5s2g29:poison,dest=$2" \
    > "$3" 2>&1
  BUILD_RC=$?
  echo "buildctl exit: $BUILD_RC; dest: $(stat -c '%C %U:%G %s' "$2" 2>&1)" >> "$3"
}
{
  echo "=== Part C: the minimal real build (nonce-0, the G29 consume shape) ==="
  cat "$CTX/Dockerfile"
} > "$EVIDENCE_DIR/c-build0-cmd.txt" 2>&1
EXPORT0="$WORK/export/out-b1.tar"
set +e
do_build "$RB_SOCK" "$EXPORT0" "$EVIDENCE_DIR/c-build0.log" "$CTX"
BUILD0_RC=$BUILD_RC
set -e
echo "op B build rc: $BUILD0_RC" >&2
tar_report "$EXPORT0" "$WORK/reports/b1.json" "" \
  > "$EVIDENCE_DIR/c-build0-tar.log" 2>&1 || true
MARKER_OK0=$(python3 -c 'import json,sys;r=json.load(open(sys.argv[1]));print(sum(1 for m in r.get("marker",[]) if m.get("name","").endswith("m2/marker.txt") and "p5s2-g29-marker2" in m.get("content","")))' "$WORK/reports/b1.json" 2>/dev/null || echo 0)
ID_OK0=$(python3 -c 'import json,sys;r=json.load(open(sys.argv[1]));print(sum(1 for m in r.get("marker",[]) if m.get("name","").endswith("m2/id.txt") and "uid=0(root)" in m.get("content","")))' "$WORK/reports/b1.json" 2>/dev/null || echo 0)
{
  echo "=== Part C: the build result ==="
  echo "build rc: $BUILD0_RC (exit 0 expected)"
  echo "buildctl log:"; sed -n 1,10p "$EVIDENCE_DIR/c-build0.log"
  echo "marker p5s2-g29-marker2 in export: $MARKER_OK0 (expected 1)"
  echo "id.txt uid=0(root) in export: $ID_OK0 (expected 1)"
} > "$EVIDENCE_DIR/c-build0-result.txt" 2>&1
cat "$EVIDENCE_DIR/c-build0-result.txt" >&2
if [ "$BUILD0_RC" != 0 ] || [ "$MARKER_OK0" != "1" ]; then
  note "op B's own-op build at s0:c2 failed; recorded as a finding"
  printf '%s P5S2-STATE-MCS-RESULT=INCOMPLETE (own-op build failed; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi

# The a1 stand fixture served its purpose; remove it so the descendant
# inventory measures only the operation's own tree.
rm -f "$SB/root/a1-created" 2>/dev/null || true

log 'J2: Part C — the descendant label inventory (the category deeper in the tree)'
{
  echo "=== Part C: the descendant scontexts after the build (the category-preservation inventory) ==="
  echo "top-level tree labels:"
  stat -c '%C %U:%G %a %n' "$SB" "$SB/rootlesskit-state" "$SB/root"
  echo ""
  echo "metadata objects (the top of the buildkitd root):"
  for f in "$SB/root/buildkitd.lock" "$SB/root/cache.db" "$SB/root/history.db"; do
    [ -e "$f" ] && stat -c '%C %U:%G %a %n' "$f" || true
  done
  echo ""
  echo "rootlesskit-state objects:"
  find "$SB/rootlesskit-state" -mindepth 1 -maxdepth 2 -exec stat -c '%C %a %n' {} \; 2>/dev/null | head -10
  echo ""
  echo "content blob (one representative):"
  CB=$(find "$SB/root/runc-overlayfs/content/blobs" -type f 2>/dev/null | head -1)
  [ -n "$CB" ] && stat -c '%C %U:%G %a %n' "$CB" || true
  echo ""
  echo "snapshot directory + regular file (the G29 target selection):"
  PASSWD="$(find "$SB/root/runc-overlayfs/snapshots" -type f -path '*/fs/etc/passwd' 2>/dev/null | head -1 || true)"
  [ -n "$PASSWD" ] && { SD="$(dirname "$(dirname "$(dirname "$PASSWD")")")"; stat -c '%C %U:%G %a %n' "$SD" "$SD/fs" "$PASSWD" || true; }
  echo ""
  echo "every distinct scontext in the operation state tree:"
  find "$SB" -exec stat -c '%C' {} \; 2>/dev/null | sort | uniq -c | sort -rn
  echo ""
  echo "every distinct scontext in the operation runtime tree:"
  find "$RB" -exec stat -c '%C' {} \; 2>/dev/null | sort | uniq -c | sort -rn
} > "$EVIDENCE_DIR/c-descendant-inventory.txt" 2>&1
sed -n 1,40p "$EVIDENCE_DIR/c-descendant-inventory.txt" >&2 || true

log 'J: Part D — the paired cross-operation filesystem matrix (cross: c1 -> B:c2; own: c2 -> B:c2)'
# The matrix legs run against the REAL populated tree with buildkitd B
# live. Cross = the c1 vehicle (the mutating operation's category);
# own = the c2 vehicle (the same as buildkitd B's). The TE surface is
# type-identical (the candidate module), so every asymmetry is the MCS.
# Targets: the G29 snapshot /etc/passwd (the representative snapshot
# file; mode 0644, writable by DAC, the FROM layer's unpack) and the
# buildkitd root lock (held by the live buildkitd). The own unlink
# parity targets the vehicle's own created file (a deleted snapshot
# file would be self-inflicted); the cross unlink targets the
# backed-up-safe passwd (expected DENIED; the backup restores it if a
# boundary break is observed).
PASSWD_SHA0=$(sha256sum "$PASSWD" | awk '{print $1}')
LOCKF="$SB/root/buildkitd.lock"
[ -n "$PASSWD" ] || { note "no snapshot file found for the matrix; stand incomplete"; printf '%s P5S2-STATE-MCS-RESULT=INCOMPLETE (no snapshot file)\n' "$PREFIX" >&2; exit 0; }
cp -a "$PASSWD" "$WORK/passwd.baseline"
leg_out() { echo "--- $* ---" ; }
mleg() { # ctx mode path — one vehicle leg, full output to the leg file
  echo "--- ${2} ${3} ---"
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$1" /usr/local/bin/map_probe "$2" "$3" 2>&1 < /dev/null || true
}

{
  echo "=== Part D: CROSS matrix (A:c1 -> B:c2 tree) ==="
  leg_out "cross read (the snapshot passwd)"
  mleg "$RK_C1" --read "$PASSWD"
  leg_out "cross stat (getattr)"
  mleg "$RK_C1" --stat "$PASSWD"
  leg_out "cross create in the c2 rootlesskit-state dir"
  mleg "$RK_C1" --write "$SB/rootlesskit-state/d-cross"
  leg_out "cross open the snapshot file (the same open path as read)"
  leg_out "cross unlink the snapshot file (dir remove_name + file unlink)"
  mleg "$RK_C1" --unlink "$PASSWD"
  leg_out "cross flock the buildkitd lock (open O_RDONLY + flock LOCK_EX|NB)"
  mleg "$RK_C1" --flock "$LOCKF"
  echo "created-file exists: $([ -e "$SB/rootlesskit-state/d-cross" ] && echo yes || echo no)"
  echo "passwd still exists: $([ -e "$PASSWD" ] && echo yes || echo no)"
  echo "passwd sha unchanged: $([ "$(sha256sum "$PASSWD" | awk '{print $1}')" = "$PASSWD_SHA0" ] && echo yes || echo no)"
} > "$EVIDENCE_DIR/d-cross-matrix.txt" 2>&1
cat "$EVIDENCE_DIR/d-cross-matrix.txt" >&2
rm -f "$SB/rootlesskit-state/d-cross" 2>/dev/null || true

{
  echo "=== Part D: OWN matrix (B:c2 -> B:c2 tree) ==="
  leg_out "own read"
  mleg "$RK_C2" --read "$PASSWD"
  leg_out "own stat (getattr)"
  mleg "$RK_C2" --stat "$PASSWD"
  leg_out "own create in the own rootlesskit-state dir"
  mleg "$RK_C2" --write "$SB/rootlesskit-state/d-own"
  leg_out "own unlink the just-created disposable file"
  mleg "$RK_C2" --unlink "$SB/rootlesskit-state/d-own"
  leg_out "own flock the buildkitd lock (held by the live buildkitd: EWOULDBLOCK expected)"
  mleg "$RK_C2" --flock "$LOCKF"
  echo "created-then-unlinked file gone: $([ -e "$SB/rootlesskit-state/d-own" ] && echo no || echo yes)"
} > "$EVIDENCE_DIR/d-own-matrix.txt" 2>&1
cat "$EVIDENCE_DIR/d-own-matrix.txt" >&2

log 'K: Part D — the cross-op process-boundary legs while B is live (signal matrix)'
# cross-op TERM to buildkitd B (expected DENIED), sig-0 existence probe
# (the constraint family grant allows the existence test), and the own
# parity (the flow's own signal path).
{
  echo "=== Part D: the cross-op signal matrix (buildkitd B alive) ==="
  echo "buildkitd B pid: $BK_PID"
  echo "--- cross TERM (sig 15) ---"
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_C1" /usr/local/bin/map_probe --signal "$BK_PID" 15 2>&1 < /dev/null || true
  echo "buildkitd B still alive: $(kill -0 "$BK_PID" 2>/dev/null && echo yes || echo no)"
  echo "--- cross sig-0 liveness probe (the unconstrained sig-0: rc=0 expected) ---"
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_C1" /usr/local/bin/map_probe --signal "$BK_PID" 0 2>&1 < /dev/null || true
  echo "--- own sig-0 (same category) ---"
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_C2" /usr/local/bin/map_probe --signal "$BK_PID" 0 2>&1 < /dev/null || true
} > "$EVIDENCE_DIR/d-signal-matrix.txt" 2>&1
cat "$EVIDENCE_DIR/d-signal-matrix.txt" >&2

log 'L: Part E — the exact G29 poisoning primitive, repeated against the corrected boundary'
# The exact G29 primitive: a c1 vehicle's pwrite of the marker at offset
# 0 into B's FROM-snapshot /etc/passwd — the same file, the same offset,
# the same marker shape the G29 legs proved consumption-relevant.
# Expected under the corrected boundary: the open O_WRONLY gets EACCES
# (MCS), the file does not change, B's consume build stays baseline;
# the own-op control reaches the file.
CONSUME_LEG=$((CONSUME_LEG + 1))
write_consume_dockerfile "$CONSUME_LEG"
EXPORT_E="$WORK/export/out-e1.tar"
set +e
do_build "$RB_SOCK" "$EXPORT_E" "$EVIDENCE_DIR/e-baseline-build.log" "$CTX"
BASE_RC=$BUILD_RC
set -e
tar_report "$EXPORT_E" "$WORK/reports/e1.json" "" \
  > "$EVIDENCE_DIR/e-baseline-tar.log" 2>&1 || true
python3 -c 'import json,sys;r=json.load(open(sys.argv[1]));print("".join(m.get("content","") for m in r.get("marker",[]) if m.get("name","").endswith("m2/id.txt")), end="")' "$WORK/reports/e1.json" 2>/dev/null > "$WORK/export/id-baseline.txt" || true
set +e
timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_C1" /usr/local/bin/map_probe --poison "$PASSWD" 0 "g29p" \
  > "$EVIDENCE_DIR/e-cross-poison.txt" 2>&1
set -e
AFTER_SHA=$(sha256sum "$PASSWD" | awk '{print $1}')
{
  echo "=== Part E: the exact G29 primitive against the corrected boundary ==="
  echo "target: $PASSWD (the G29 consumption-relevant FROM-snapshot file)"
  echo "baseline build rc: $BASE_RC; baseline id.txt: $(tr '\n' ' ' < "$WORK/export/id-baseline.txt")"
  grep -E 'vehicle|POISON|ERROR' "$EVIDENCE_DIR/e-cross-poison.txt" || true
  echo "file sha after the c1 poison attempt: $AFTER_SHA"
  echo "file unchanged: $([ "$AFTER_SHA" = "$PASSWD_SHA0" ] && echo yes || echo no)"
} > "$EVIDENCE_DIR/e-cross-result.txt" 2>&1
cat "$EVIDENCE_DIR/e-cross-result.txt" >&2

CONSUME_LEG=$((CONSUME_LEG + 1))
write_consume_dockerfile "$CONSUME_LEG"
EXPORT_E2="$WORK/export/out-e2.tar"
set +e
do_build "$RB_SOCK" "$EXPORT_E2" "$EVIDENCE_DIR/e-postattempt-build.log" "$CTX"
POST_RC=$BUILD_RC
set -e
tar_report "$EXPORT_E2" "$WORK/reports/e2.json" "" \
  > "$EVIDENCE_DIR/e-postattempt-tar.log" 2>&1 || true
POST_ID=$(python3 -c 'import json,sys;r=json.load(open(sys.argv[1]));print("".join(m.get("content","") for m in r.get("marker",[]) if m.get("name","").endswith("m2/id.txt")).replace("\n"," "))' "$WORK/reports/e2.json" 2>/dev/null || true)
{
  echo "=== Part E: the post-attempt consume build (B stays baseline) ==="
  echo "build rc: $POST_RC"
  echo "id.txt: $POST_ID"
  echo "uid=0(root) present: $(echo "$POST_ID" | grep -c 'uid=0(root)' || true)"
  echo "g29p contamination: $(echo "$POST_ID" | grep -c 'g29p' || true)"
} > "$EVIDENCE_DIR/e-postattempt-result.txt" 2>&1
cat "$EVIDENCE_DIR/e-postattempt-result.txt" >&2

log 'M: Part E — the own-op mutation control (the same primitive at the own category)'
set +e
timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_C2" /usr/local/bin/map_probe --poison "$PASSWD" 0 "g29p" \
  > "$EVIDENCE_DIR/e-own-control.txt" 2>&1
set -e
OWN_SHA=$(sha256sum "$PASSWD" | awk '{print $1}')
{
  echo "=== Part E: the own-op mutation control (the same file, the op's own category) ==="
  echo "sha before: $AFTER_SHA"
  grep -E 'vehicle|POISON|ERROR' "$EVIDENCE_DIR/e-own-control.txt" || true
  echo "sha after: $OWN_SHA"
  echo "file changed by the own control: $([ "$OWN_SHA" != "$AFTER_SHA" ] && echo yes || echo no)"
  echo "g29p read-back: $(grep -o 'POISON-READBACK.*' "$EVIDENCE_DIR/e-own-control.txt" || true)"
} > "$EVIDENCE_DIR/e-own-result.txt" 2>&1
cat "$EVIDENCE_DIR/e-own-result.txt" >&2

log 'N: Part E — restore + the causal closure'
cp -a "$WORK/passwd.baseline" "$PASSWD"
RESTORED_SHA=$(sha256sum "$PASSWD" | awk '{print $1}')
CONSUME_LEG=$((CONSUME_LEG + 1))
write_consume_dockerfile "$CONSUME_LEG"
EXPORT_C="$WORK/export/out-c.tar"
set +e
do_build "$RB_SOCK" "$EXPORT_C" "$EVIDENCE_DIR/e-closure-build.log" "$CTX"
CLOS_RC=$BUILD_RC
set -e
tar_report "$EXPORT_C" "$WORK/reports/c.json" "" \
  > "$EVIDENCE_DIR/e-closure-tar.log" 2>&1 || true
CLOS_ID=$(python3 -c 'import json,sys;r=json.load(open(sys.argv[1]));print("".join(m.get("content","") for m in r.get("marker",[]) if m.get("name","").endswith("m2/id.txt")).replace("\n"," "))' "$WORK/reports/c.json" 2>/dev/null || true)
{
  echo "=== Part E: restore + closure ==="
  echo "restored sha == baseline: $([ "$RESTORED_SHA" = "$PASSWD_SHA0" ] && echo yes || echo no)"
  echo "closure build rc: $CLOS_RC"
  echo "closure id.txt: $CLOS_ID"
  echo "closure uid=0(root): $(echo "$CLOS_ID" | grep -c 'uid=0(root)' || true)"
} > "$EVIDENCE_DIR/e-closure-result.txt" 2>&1
cat "$EVIDENCE_DIR/e-closure-result.txt" >&2

log 'Q: Part G — the G26 process-boundary regression (the guards)'
GU_EPOCH="$(date +%s)"
# guard 1: cross-op newuidmap c1 -> c2 (the G28 E1 shape)
FIFO_G1="$WORK/probe/fifo-g1"
mkfifo "$FIFO_G1"
chmod 666 "$FIFO_G1"
timeout 120 runuser -u "$BUILDER_USER" -- runcon "$RK_C2" /usr/local/bin/map_probe --be-target "$FIFO_G1" \
  >"$WORK/probe/b-g1.out" 2>&1 < /dev/null &
exec 3<>"$FIFO_G1"
BPID_G1=""
if IFS= read -r -t 60 line <&3; then
  case "$line" in PID=[0-9]*) BPID_G1="${line#PID=}" ;; esac
fi
exec 3<&-
{
  echo "=== guard 1: cross-op newuidmap c1 -> c2 uid_map write (expect MCS-BLOCKED) ==="
  echo "target pid: ${BPID_G1:-NONE}"
  echo "target uid_map before: [$(cat "/proc/$BPID_G1/uid_map" 2>/dev/null || true)]"
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_C1" /usr/local/bin/map_probe \
    --invoke-helper /usr/bin/newuidmap "$BPID_G1" 0 475 1 1 165536 65536 2>&1 < /dev/null || echo "helper attempt rc=$?"
  echo "target uid_map after: [$(cat "/proc/$BPID_G1/uid_map" 2>/dev/null || true)]"
} > "$EVIDENCE_DIR/g-guard1-newuidmap.txt" 2>&1
cat "$EVIDENCE_DIR/g-guard1-newuidmap.txt" >&2
pkill -KILL -f 'map_probe --be-target' 2>/dev/null || true
# guard 2: cross-op signal path (the G28 E2 shape)
FIFO_G2="$WORK/probe/fifo-g2"
mkfifo "$FIFO_G2"
chmod 666 "$FIFO_G2"
timeout 120 runuser -u "$BUILDER_USER" -- runcon "$RK_C2" /usr/local/bin/map_probe --be-target "$FIFO_G2" \
  >"$WORK/probe/b-g2.out" 2>&1 < /dev/null &
exec 3<>"$FIFO_G2"
BPID_G2=""
if IFS= read -r -t 60 line <&3; then
  case "$line" in PID=[0-9]*) BPID_G2="${line#PID=}" ;; esac
fi
exec 3<&-
{
  echo "=== guard 2: cross-op TERM/KILL c1 -> c2 (expect MCS-BLOCKED, target alive) ==="
  echo "target pid: ${BPID_G2:-NONE}"
  for sigspec in 15 9; do
    timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_C1" /usr/local/bin/map_probe --signal "$BPID_G2" "$sigspec" 2>&1 < /dev/null || true
  done
  echo "target alive after the cross-op signals: $(kill -0 "$BPID_G2" 2>/dev/null && echo YES || echo NO) (the runner's unconfined check)"
} > "$EVIDENCE_DIR/g-guard2-signals.txt" 2>&1
cat "$EVIDENCE_DIR/g-guard2-signals.txt" >&2
pkill -KILL -f 'map_probe --be-target' 2>/dev/null || true
# guard 3: cross-op connect to op B's live buildkitd.sock
{
  echo "=== guard 3: cross-op connect to op B's live buildkitd.sock (expect EACCES) ==="
  echo "socket: $(stat -c '%C %U:%G %a' "$RB_SOCK" 2>&1)"
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_C1" /usr/local/bin/map_probe --connect "$RB_SOCK" 2>&1 < /dev/null || true
} > "$EVIDENCE_DIR/g-guard3-sockconnect.txt" 2>&1
cat "$EVIDENCE_DIR/g-guard3-sockconnect.txt" >&2
# guard 4: op A cannot reach the manager's authority
{
  echo "=== guard 4: op A cannot reach the manager's authority (manager.sock connect + signal) ==="
  echo "manager.sock: $(stat -c '%C %U:%G %a' "$MANAGER_SOCK" 2>&1)"
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_C1" /usr/local/bin/map_probe --connect "$MANAGER_SOCK" 2>&1 < /dev/null || true
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_C1" /usr/local/bin/map_probe --signal "$MG_PID" 15 2>&1 < /dev/null || true
  echo "manager alive after A's signal attempt: $(kill -0 "$MG_PID" 2>/dev/null && echo YES || echo NO)"
} > "$EVIDENCE_DIR/g-guard4-manager.txt" 2>&1
cat "$EVIDENCE_DIR/g-guard4-manager.txt" >&2
harvest_avcs_since "$GU_EPOCH" "$EVIDENCE_DIR/g-guard-avcs.txt"
dedup_avcs "$EVIDENCE_DIR/g-guard-avcs.txt" "$EVIDENCE_DIR/g-guard-avcs-dedup.txt"

log 'O: Part F — the manager/control-plane compatibility over categorized trees'
F_EPOCH="$(date +%s)"
# F1: the manager's own START creates its own (production-shape) trees
# and serves the launch; measure the created labels (the manager's own
# creations are the allocator's integration point) and the lifecycle.
OPM="$(gen_op_id)"
start_op() { # opid — one manager RPC, appended to f-start-ops.txt
  set +e
  printf 'START %s\n' "$1" | timeout 120 socat - UNIX-CONNECT:"$MANAGER_SOCK" >> "$EVIDENCE_DIR/f-start-ops.txt" 2>&1
  echo "socat rc: $?" >> "$EVIDENCE_DIR/f-start-ops.txt"
  set -e
}
stop_op() { # opid — one manager RPC
  set +e
  printf 'STOP %s\n' "$1" | timeout 240 socat - UNIX-CONNECT:"$MANAGER_SOCK" >> "$EVIDENCE_DIR/f-stop-ops.txt" 2>&1
  echo "socat rc: $?" >> "$EVIDENCE_DIR/f-stop-ops.txt"
  set -e
}
start_op "$OPM"
RPM_SOCK="$RUNTIME_ROOT/ops/$OPM/buildkitd.sock"
M_WAIT=0
M_READY=0
until [ -S "$RPM_SOCK" ] || [ "$M_WAIT" -ge 120 ]; do
  sleep 1
  M_WAIT=$((M_WAIT + 1))
done
[ -S "$RPM_SOCK" ] && M_READY=1
{
  echo "=== Part F1: the manager's own START over its own (s0) trees ==="
  echo "START response:"; tail -3 "$EVIDENCE_DIR/f-start-ops.txt" || true
  echo "readiness: $M_READY (wait ${M_WAIT}s)"
  echo "the manager-created tree labels (the production shape; the allocator's integration point):"
  stat -c '%C %U:%G %a %n' "$RUNTIME_ROOT/ops/$OPM" "$STATE_ROOT/ops/$OPM" \
    "$STATE_ROOT/ops/$OPM/rootlesskit-state" "$STATE_ROOT/ops/$OPM/root" 2>&1 || true
  echo "sock: $(stat -c '%C %U:%G %a' "$RPM_SOCK" 2>&1 || true)"
  echo "the unit journal window (the manager's own diag):"
  journalctl -u "$UNIT" --since "-3min" --no-pager 2>/dev/null | tail -15
} > "$EVIDENCE_DIR/f1-start-labels.txt" 2>&1
cat "$EVIDENCE_DIR/f1-start-labels.txt" >&2
stop_op "$OPM"
S_WAIT=0
S_OK=0
until [ ! -e "$STATE_ROOT/ops/$OPM" ] || [ "$S_WAIT" -ge 240 ]; do
  sleep 2
  S_WAIT=$((S_WAIT + 2))
done
[ ! -e "$STATE_ROOT/ops/$OPM" ] && S_OK=1
{
  echo "=== Part F1: the manager's own STOP ==="
  echo "STOP response:"; tail -3 "$EVIDENCE_DIR/f-stop-ops.txt" || true
  echo "trees converged (removed): $S_OK"
} > "$EVIDENCE_DIR/f1-stop-result.txt" 2>&1
cat "$EVIDENCE_DIR/f1-stop-result.txt" >&2

# F2: the adoption check: plant a c2-labeled canonical pair; START must
# refuse to adopt (fail closed, no removal, no launch).
OPF="$(gen_op_id)"
mkdir -p "$RUNTIME_ROOT/ops/$OPF" "$STATE_ROOT/ops/$OPF/rootlesskit-state" "$STATE_ROOT/ops/$OPF/root"
chown "$BUILDER_USER":"$BUILDER_USER" "$RUNTIME_ROOT/ops/$OPF" "$STATE_ROOT/ops/$OPF" \
  "$STATE_ROOT/ops/$OPF/rootlesskit-state" "$STATE_ROOT/ops/$OPF/root"
chmod 700 "$RUNTIME_ROOT/ops/$OPF" "$STATE_ROOT/ops/$OPF" \
  "$STATE_ROOT/ops/$OPF/rootlesskit-state" "$STATE_ROOT/ops/$OPF/root"
chcon -u system_u -t docker_helper_builder_state_t -l s0:c2 \
  "$STATE_ROOT/ops/$OPF" "$STATE_ROOT/ops/$OPF/rootlesskit-state" "$STATE_ROOT/ops/$OPF/root"
start_op "$OPF"
sleep 2
{
  echo "=== Part F2: the adoption check over a planted c2 pair ==="
  echo "START response:"; tail -3 "$EVIDENCE_DIR/f-start-ops.txt" || true
  echo "sock appeared: $([ -S "$RUNTIME_ROOT/ops/$OPF/buildkitd.sock" ] && echo yes || echo no)"
  echo "planted dirs survive (the refusal removes nothing): state=$([ -e "$STATE_ROOT/ops/$OPF" ] && echo yes || echo no) runtime=$([ -e "$RUNTIME_ROOT/ops/$OPF" ] && echo yes || echo no)"
  echo "planted label intact: $(stat -c '%C' "$STATE_ROOT/ops/$OPF" 2>&1)"
} > "$EVIDENCE_DIR/f2-refusal.txt" 2>&1
journalctl -u "$UNIT" --since "@$F_EPOCH" --no-pager 2>/dev/null | tail -8 >> "$EVIDENCE_DIR/f2-refusal.txt" || true
cat "$EVIDENCE_DIR/f2-refusal.txt" >&2
rm -rf "$RUNTIME_ROOT/ops/$OPF" "$STATE_ROOT/ops/$OPF" 2>/dev/null || true

# F6: the abnormal-termination cleanup: the manager's own op launched,
# then the flow's leader is killed from outside; the manager's
# unexpected-exit contract converges the residue.
OPA6="$(gen_op_id)"
start_op "$OPA6"
RPA6="$RUNTIME_ROOT/ops/$OPA6/buildkitd.sock"
A_WAIT=0
A_READY=0
until [ -S "$RPA6" ] || [ "$A_WAIT" -ge 120 ]; do
  sleep 1
  A_WAIT=$((A_WAIT + 1))
done
[ -S "$RPA6" ] && A_READY=1
if [ "$A_READY" -eq 1 ]; then
  pkill -KILL -f "ops/$OPA6/root" 2>/dev/null || true
  X_WAIT=0
  X_OK=0
  until [ ! -e "$STATE_ROOT/ops/$OPA6" ] || [ "$X_WAIT" -ge 240 ]; do
    sleep 2
    X_WAIT=$((X_WAIT + 2))
  done
  [ ! -e "$STATE_ROOT/ops/$OPA6" ] && X_OK=1
else
  X_OK=0
fi
{
  echo "=== Part F6: the abnormal-termination cleanup (the manager's own op, the leader killed) ==="
  echo "launch ready: $A_READY"
  echo "trees converged after the abnormal termination: $X_OK"
  echo "runtime tree: $([ -e "$RUNTIME_ROOT/ops/$OPA6" ] && echo survives || echo removed)"
harvest_avcs_since "$F_EPOCH" "$EVIDENCE_DIR/f6-abnormal-cleanup-avcs.txt"
} > "$EVIDENCE_DIR/f6-abnormal-cleanup.txt" 2>&1
journalctl -u "$UNIT" --since "@$F_EPOCH" --no-pager 2>/dev/null | tail -8 >> "$EVIDENCE_DIR/f6-abnormal-cleanup.txt" || true
cat "$EVIDENCE_DIR/f6-abnormal-cleanup.txt" >&2

# F4: the PURGE RPC smoke (the manager's cleanup owner over its own entries).
set +e
printf 'PURGE\n' | timeout 240 socat - UNIX-CONNECT:"$MANAGER_SOCK" >> "$EVIDENCE_DIR/f4-purge.txt" 2>&1
echo "socat rc: $?" >> "$EVIDENCE_DIR/f4-purge.txt"
set -e
{
  echo "=== Part F4: the PURGE RPC (no live instances) ==="
  grep -a 'OK\|ERR' "$EVIDENCE_DIR/f4-purge.txt" || true
} > "$EVIDENCE_DIR/f4-purge-result.txt" 2>&1
cat "$EVIDENCE_DIR/f4-purge-result.txt" >&2

log 'P: Part F — the startup purge over categorized trees (the real tree + planted fakes)'
# Stop the stand's own flow first (the harness lifecycle; SIGKILL, so
# the flow's own socket cleanup does not run). The purge window's AVCs
# are harvested to attribute each removal outcome.
pkill -KILL -f "rootlesskit --net=slirp4netns.*$OPB" 2>/dev/null || true
pkill -KILL -f "buildkitd --rootless --root=$SB/root" 2>/dev/null || true
pkill -KILL -f slirp4netns 2>/dev/null || true
sleep 3
PF_EPOCH="$(date +%s)"
{
  echo "=== Part F3 pre: the residue after the SIGKILLed flow ==="
  find "$SB/rootlesskit-state" -maxdepth 1 -exec stat -c '%C %a %n' {} \; 2>/dev/null || true
  echo "the flow's own cleanup authority (rootlesskit_t state_t:sock_file unlink, the granted shape):"
} > "$EVIDENCE_DIR/f3-residue.txt" 2>&1
timeout 60 runuser -u "$BUILDER_USER" -- runcon "$RK_C2" /usr/local/bin/map_probe \
  --unlink "$SB/rootlesskit-state/api.sock" >> "$EVIDENCE_DIR/f3-residue.txt" 2>&1 < /dev/null || true
harvest_avcs_since "$PF_EPOCH" "$EVIDENCE_DIR/f3-residue-avcs.txt"
cat "$EVIDENCE_DIR/f3-residue.txt" >&2
OPFAKE1="$(gen_op_id)"
OPFAKE2="$(gen_op_id)"
for pair in "$OPFAKE1:s0:c1" "$OPFAKE2:s0:c2"; do
  fid="${pair%%:*}"; fcat="${pair#*:}"
  mkdir -p "$RUNTIME_ROOT/ops/$fid" "$STATE_ROOT/ops/$fid/rootlesskit-state" "$STATE_ROOT/ops/$fid/root"
  printf 'planted residue\n' > "$STATE_ROOT/ops/$fid/root/planted.txt"
  chown "$BUILDER_USER":"$BUILDER_USER" "$RUNTIME_ROOT/ops/$fid" "$STATE_ROOT/ops/$fid" \
    "$STATE_ROOT/ops/$fid/rootlesskit-state" "$STATE_ROOT/ops/$fid/root" \
    "$STATE_ROOT/ops/$fid/root/planted.txt"
  chmod 700 "$RUNTIME_ROOT/ops/$fid" "$STATE_ROOT/ops/$fid" \
    "$STATE_ROOT/ops/$fid/rootlesskit-state" "$STATE_ROOT/ops/$fid/root"
  chcon -u system_u -t docker_helper_builder_state_t -l "$fcat" \
    "$STATE_ROOT/ops/$fid" "$STATE_ROOT/ops/$fid/rootlesskit-state" "$STATE_ROOT/ops/$fid/root" \
    "$STATE_ROOT/ops/$fid/root/planted.txt"
done
{
  echo "=== Part F3: the trees in place before the startup purge ==="
  echo "op B real tree: state=$([ -e "$SB" ] && echo present || echo absent) $(stat -c '%C' "$SB" 2>&1)"
  echo "fake c1: $(stat -c '%C' "$STATE_ROOT/ops/$OPFAKE1" 2>&1)"
  echo "fake c2: $(stat -c '%C' "$STATE_ROOT/ops/$OPFAKE2" 2>&1)"
  echo "fake content: $(stat -c '%C' "$STATE_ROOT/ops/$OPFAKE2/root/planted.txt" 2>&1)"
} > "$EVIDENCE_DIR/f3-before.txt" 2>&1
cat "$EVIDENCE_DIR/f3-before.txt" >&2
RESTART_EPOCH="$(date +%s)"
systemctl restart "$UNIT" 2>"$EVIDENCE_DIR/f3-restart.err" || true
U_WAIT=0
until systemctl is-active --quiet "$UNIT" || [ "$U_WAIT" -ge 60 ]; do
  sleep 1
  U_WAIT=$((U_WAIT + 1))
done
sleep 3
{
  echo "=== Part F3: the startup purge over categorized trees ==="
  echo "unit active: $(systemctl is-active --quiet "$UNIT" && echo yes || echo no)"
  echo "op B real c2 tree removed: $([ -e "$SB" ] && echo no || echo yes)"
  echo "op B runtime removed: $([ -e "$RB" ] && echo no || echo yes)"
  echo "fake c1 removed: $([ -e "$STATE_ROOT/ops/$OPFAKE1" ] && echo no || echo yes)"
  echo "fake c2 removed: $([ -e "$STATE_ROOT/ops/$OPFAKE2" ] && echo no || echo yes)"
  echo "the manager's purge journal:"
  journalctl -u "$UNIT" --since "@$RESTART_EPOCH" --no-pager 2>/dev/null | grep -a 'purge\|residue\|refus\|skipping' | head -20
} > "$EVIDENCE_DIR/f3-purge-result.txt" 2>&1
harvest_avcs_since "$PF_EPOCH" "$EVIDENCE_DIR/f3-purge-avcs.txt"
cat "$EVIDENCE_DIR/f3-purge-result.txt" >&2

# F5: the reuse check: the same fake id re-provisioned with a fresh
# category; the new tree carries the allocator's assignment, not the
# old label.
provision_tree "$OPFAKE2" "s0:c1"
printf 'fresh provision\n' > "$STATE_ROOT/ops/$OPFAKE2/root/fresh.txt"
chown "$BUILDER_USER":"$BUILDER_USER" "$STATE_ROOT/ops/$OPFAKE2/root/fresh.txt"
chcon -u system_u -t docker_helper_builder_state_t -l s0:c1 "$STATE_ROOT/ops/$OPFAKE2/root/fresh.txt"
REUSE_LABEL="$(stat -c '%C' "$STATE_ROOT/ops/$OPFAKE2" 2>&1)"
{
  echo "=== Part F5: the op-id reuse after the purge ==="
  echo "re-provisioned tree label: $REUSE_LABEL"
  echo "fresh file label: $(stat -c '%C' "$STATE_ROOT/ops/$OPFAKE2/root/fresh.txt" 2>&1)"
  echo "fresh label is c1 (the allocator's assignment): $(echo "$REUSE_LABEL" | grep -q 'c1' && echo yes || echo no)"
  echo "stale c2 inheritance: $(echo "$REUSE_LABEL" | grep -q 'c2' && echo yes || echo no)"
} > "$EVIDENCE_DIR/f5-reuse.txt" 2>&1
cat "$EVIDENCE_DIR/f5-reuse.txt" >&2

log 'R: the final harvest + the leg summary'
harvest_avcs_since "$HV_EPOCH" "$EVIDENCE_DIR/h-avcs-all.txt"
harvest_avcs_since "$HV_EPOCH" "$EVIDENCE_DIR/h-denials-all.txt"
{
  echo "=== the residual AVC ledger (every denial in the leg windows, deduped) ==="
  awk '{for(i=1;i<=NF;i++) if($i=="scontext="||$i=="tcontext="||$i=="class="||$i=="perms=") o=o" "$i" "$(i+1); print o}' "$EVIDENCE_DIR/h-denials-all.txt" 2>/dev/null \
    | sed 's/scontext=//;s/tcontext=//;s/class=//;s/perms=//' | sort | uniq -c | sort -rn | head -40
} > "$EVIDENCE_DIR/h-residual-avcs-dedup.txt" 2>&1
cat "$EVIDENCE_DIR/h-residual-avcs-dedup.txt" >&2 || true

# -------- the leg summary (the verdict flags) --------
CROSS_BLOCKED=0
grep -q 'READ .*rc=-1 errno=13' "$EVIDENCE_DIR/d-cross-matrix.txt" && CROSS_BLOCKED=$((CROSS_BLOCKED+1))
grep -q 'WRITE .*rc=-1 errno=13' "$EVIDENCE_DIR/d-cross-matrix.txt" && CROSS_BLOCKED=$((CROSS_BLOCKED+1))
grep -q 'UNLINK .*rc=-1 errno=13' "$EVIDENCE_DIR/d-cross-matrix.txt" && CROSS_BLOCKED=$((CROSS_BLOCKED+1))
grep -q 'FLOCK-OPEN .*rc=-1 errno=13' "$EVIDENCE_DIR/d-cross-matrix.txt" && CROSS_BLOCKED=$((CROSS_BLOCKED+1))
grep -q 'SIGNAL .*rc=-1 errno=1' "$EVIDENCE_DIR/d-signal-matrix.txt" && CROSS_BLOCKED=$((CROSS_BLOCKED+1))
PROP_OK=0
grep -q 'docker_helper_builder_state_t:s0:c2' "$EVIDENCE_DIR/a1-propagation.txt" && PROP_OK=$((PROP_OK+1))
INVENTORY_BLOCK=$(awk '/every distinct scontext in the operation state tree:/{f=1;next} /^$/{f=0} f' "$EVIDENCE_DIR/c-descendant-inventory.txt")
INVENTORY_C2=$(echo "$INVENTORY_BLOCK" | grep -c 'c2' || true)
INVENTORY_NONC2=$(echo "$INVENTORY_BLOCK" | grep -vc 'c2' || true)
OWN_OK=0
grep -q 'READ .*errno=0' "$EVIDENCE_DIR/d-own-matrix.txt" && OWN_OK=$((OWN_OK+1))
grep -q 'WRITE .*errno=0' "$EVIDENCE_DIR/d-own-matrix.txt" && OWN_OK=$((OWN_OK+1))
grep -q 'UNLINK .*rc=0' "$EVIDENCE_DIR/d-own-matrix.txt" && OWN_OK=$((OWN_OK+1))
BUILD_OK=0
[ "$BUILD0_RC" = "0" ] && [ "$MARKER_OK0" = "1" ] && [ "$ID_OK0" = "1" ] && BUILD_OK=1
MCS29_OK=0
[ "$AFTER_SHA" = "$PASSWD_SHA0" ] && [ "$POST_RC" = "0" ] && echo "$POST_ID" | grep -q 'uid=0(root)' \
  && [ "$OWN_SHA" != "$AFTER_SHA" ] && [ "$RESTORED_SHA" = "$PASSWD_SHA0" ] && [ "$CLOS_RC" = "0" ] \
  && echo "$CLOS_ID" | grep -q 'uid=0(root)' && MCS29_OK=1
MANAGER_OK=0
[ "$S_OK" = "1" ] && [ "$X_OK" = "1" ] && MANAGER_OK=$((MANAGER_OK+1))
PURGE_OK=0
grep -q 'unit active: yes' "$EVIDENCE_DIR/f3-purge-result.txt" \
  && [ ! -e "$SB" ] && [ ! -e "$RB" ] \
  && [ ! -e "$STATE_ROOT/ops/$OPFAKE1" ] && [ ! -e "$STATE_ROOT/ops/$OPFAKE2" ] \
  && grep -q 'fake c1 removed: yes' "$EVIDENCE_DIR/f3-purge-result.txt" \
  && grep -q 'fake c2 removed: yes' "$EVIDENCE_DIR/f3-purge-result.txt" && PURGE_OK=1
REUSE_OK=0
grep -q 'fresh label is c1: yes' "$EVIDENCE_DIR/f5-reuse.txt" && REUSE_OK=1
GUARDS_OK=0
if grep -q 'Could not open proc directory for target.*Permission denied' "$EVIDENCE_DIR/g-guard1-newuidmap.txt" \
   && grep -q 'target uid_map after: \[\]' "$EVIDENCE_DIR/g-guard1-newuidmap.txt" \
   && grep -q 'rc=-1 errno=13' "$EVIDENCE_DIR/g-guard3-sockconnect.txt" \
   && grep -q 'rc=-1 errno=13' "$EVIDENCE_DIR/g-guard4-manager.txt" \
   && grep -q "manager alive after A's signal attempt: YES" "$EVIDENCE_DIR/g-guard4-manager.txt" \
   && grep -q 'target alive after the cross-op signals: YES' "$EVIDENCE_DIR/g-guard2-signals.txt"; then GUARDS_OK=1; fi
{
  echo "=== the G30 leg summary ==="
  echo "cross-op MCS blocks (read/write/create-open/unlink/flock-LOCK/signal; >=5 expected): $CROSS_BLOCKED"
  echo "category propagation (a1 created-file label c2): $PROP_OK"
  echo "descendant inventory: c2-labeled lines=$INVENTORY_C2 non-c2 lines=$INVENTORY_NONC2"
  echo "own-op access parity legs (read/write/unlink; 3 expected): $OWN_OK"
  echo "own-op build at c2 (rc 0 + marker + id): $BUILD_OK"
  echo "G29 primitive blocked (cross denied + file unchanged + baseline build + own control lands + restore + closure): $MCS29_OK"
  echo "manager own lifecycle (START/STOP + abnormal-termination cleanup): $MANAGER_OK"
  echo "manager startup purge over categorized trees: $PURGE_OK"
  echo "op-id reuse gets a fresh category: $REUSE_OK"
  echo "G26 guards (newuidmap/sockconnect/manager): $GUARDS_OK"
  echo ""
  echo "verdict rule: PASS requires PROP_OK, BUILD_OK, MCS29_OK, PURGE_OK, REUSE_OK, GUARDS_OK all 1, CROSS_BLOCKED >= 5, OWN_OK = 3, and no state-tree scontext outside s0:c2"
} > "$EVIDENCE_DIR/h-summary.txt" 2>&1
cat "$EVIDENCE_DIR/h-summary.txt" >&2
RESULT="INCOMPLETE"
if [ "$PROP_OK" = "1" ] && [ "$BUILD_OK" = "1" ] && [ "$MCS29_OK" = "1" ] && [ "$PURGE_OK" = "1" ] \
   && [ "$REUSE_OK" = "1" ] && [ "$GUARDS_OK" = "1" ] && [ "$CROSS_BLOCKED" -ge 5 ] && [ "$OWN_OK" = "3" ] \
   && [ "$INVENTORY_NONC2" = "0" ]; then
  RESULT="PASS"
elif [ "$MCS29_OK" != "1" ]; then
  RESULT="FAIL"
fi
printf '%s P5S2-STATE-MCS-RESULT=%s (part A propagation=%d build=%d matrix-cross=%d G29-blocked=%d manager=%d purge=%d reuse=%d guards=%d)\n' \
  "$PREFIX" "$RESULT" "$PROP_OK" "$BUILD_OK" "$CROSS_BLOCKED" "$MCS29_OK" "$MANAGER_OK" "$PURGE_OK" "$REUSE_OK" "$GUARDS_OK" >&2
