#!/usr/bin/env bash
#
# Guest-side P5-S2g31 production MCS category allocation + launch
# lifecycle proof for openSUSE Tumbleweed. INVESTIGATION ONLY.
#
# The question G31 answers:
#   how does the shared production manager (docker_helper_builder_t:s0)
#   safely assign a unique MCS category to each live Build Operation,
#   create the categorized state tree, and launch the first per-op
#   process in the same range — while staying a shared control-plane
#   process — and does the full lifecycle
#   allocate -> provision -> launch -> inherit -> STOP/PURGE ->
#   release -> safe reuse hold for concurrent operations?
#
# Method: a runtime lifecycle measurement on the G30 stand (REAL unit
# with the SELinuxContext binding and the P4 unit-cgroup boundary, REAL
# rootlesskit production argv, pinned BuildKit v0.33.0, SELinux
# Enforcing everywhere, the G26 MCS delta + the UNCHANGED candidate
# payload module v12 + a small GUEST-ONLY diagnostic module for the
# control-plane surfaces). The production manager binary is built from
# the proof commit with a minimal GUEST-ONLY experimental patch
# (scripts/release-2.4-p5s2-cat-launch.patch, applied in CI and never
# committed to production sources): the patch adds (1) a per-instance
# category field bound under the manager lock at START admission (the
# lowest free category from a fixed stand-in pool; exhaustion refuses
# the START — fail closed, no s0 fallback), (2) the state-tree labeling
# at provisioning (xattr security.selinux on the three top-level state
# dirs, BEFORE any flow process starts — state/process parity), and
# (3) the launch wrap: runcon applies the operation's execution context
# to the helper's own exec of the production rootlesskit argv. The
# allocator stand-in is NOT the production allocator; its measured
# invariants are the security contract.
#
# The launch mechanism under test (the production answer): the manager
# forks a fresh, single-threaded per-launch child (the distro runcon
# binary); that child writes its OWN /proc/self/attr/exec (setexeccon)
# and execs the rootlesskit entry file, which forces the transition
# docker_helper_builder_t -> docker_helper_rootlesskit_t at the
# operation's category. The manager's own context never changes; the
# forced transition is allowed by the existing process-transition grant
# plus the constraint's existing non-constrained-subject escape (the
# manager domain is not mcs_constrained); the child's entry file keeps
# its existing entrypoint grant. Category propagation downstream is the
# policy's own default-range TARGET_LOW inheritance (the G30 finding).
#
# Legs:
#   Part A  the launch boundary: the manager's context before and after
#           launches (unchanged s0), the flow process contexts at the
#           operation categories, and the SELinux permission facts for
#           the mechanism.
#   Part B  the category space: the policy's category statements, the
#           measured category-space edges, and the stand-in pool's
#           contract (one category per operation; host-wide coordination
#           recorded as the design note).
#   Part C  two live operations (A -> c1, B -> c2) launched CONCURRENTLY
#           through the experimental manager: both trees labeled, both
#           flows at their own categories, both real builds succeed in
#           parallel, both inventories uniform; no transient cross-op
#           category bleed.
#   Part D  allocation collision: the third START is refused at the
#           ceiling; the stand-in allocator makes the collision
#           structurally impossible (unique-live-category invariant).
#   Part E  release and reuse: STOP A converges, the category is
#           considered free only after the convergence, a new operation
#           receives the freed category, builds, and cannot see the old
#           state; a stale categorized residue is refused (no adoption).
#   Part F  abnormal termination: the flow leader is SIGKILLed; the
#           manager retains the entry (the known G30 finding: the
#           manager cannot unlink the rootlesskit api.sock — recorded,
#           not fixed); the category stays occupied (no early reuse —
#           the next operation receives a different category); after
#           the flow's own-authority socket cleanup the PURGE retry
#           converges and the category is released.
#   Part G  the exact security regression at two live operations: the
#           G29 snapshot write cross-op blocked, newuidmap blocked,
#           TERM/KILL blocked, buildkitd.sock connect blocked, the
#           manager.sock unreachable, and the own-operation equivalents
#           working; sig-0 classified as liveness-only.
#
# Out-of-scope by the task contract: the production allocator, the
# production policy commits, the sock_file unlink fix (except as an
# explicitly recorded diagnostic proof), the Release GO, and new
# BuildKit poisoning targets.
#
set -Eeuo pipefail

PREFIX='[release-2.4-p5s2-state-mcs-tw]'
EVIDENCE_DIR=/tmp/release-2.4-p5s2-cat-launch-evidence
BUILDER_USER=docker-helper-builder
GUEST_FILES=/tmp/p5s2-cat-launch
TRANSFERRED="$GUEST_FILES"
STATE_ROOT=/var/lib/docker-helper-builder
RUNTIME_ROOT=/run/docker-helper-builder
MANAGER_SOCK="$RUNTIME_ROOT/manager.sock"
UNIT=docker-helper-builder
BUILDKITD=/usr/libexec/docker-helper/buildkit/buildkitd
BUILDCTL=/usr/libexec/docker-helper/buildkit/buildctl
WORK=/tmp/p5s2-g31-work

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
  printf '%s P5S2-CAT-LAUNCH-RESULT=INCOMPLETE (not enforcing; recorded as a finding)\n' "$PREFIX" >&2
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
  printf '%s P5S2-CAT-LAUNCH-RESULT=INCOMPLETE (toolchain unavailable; recorded as a finding)\n' "$PREFIX" >&2
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
  printf '%s P5S2-CAT-LAUNCH-RESULT=INCOMPLETE (payload download/verify failed; recorded as a finding)\n' "$PREFIX" >&2
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

log 'C2: the G31 control-plane diagnostic module (guest-only; evidence-driven surfaces for the launch mechanism)'
# The manager's own surfaces for the per-launch mechanism: the runcon
# helper's exec (the manager executes the distro runcon binary), the
# helper's own setexeccon write, and the state-tree labeling at
# provisioning (the relabel machinery on the state type). Everything
# here touches the CONTROL PLANE domain only; no flow/payload grants
# are added.
cat > /tmp/cat_launch_diag.te <<'CATOF'
module cat_launch_diag 1.0;

# P5-S2g31 guest-only diagnostic module: the control-plane surfaces the
# per-launch mechanism needs (the runcon helper's exec, its setexeccon
# write, and the state-tree relabel at provisioning). No
# flow/payload-domain grants; no constraint changes; removed at cleanup.
require {
	type docker_helper_builder_t;
	type docker_helper_builder_state_t;
	type bin_t;
	class file { execute open read getattr map relabelfrom relabelto };
	class dir { relabelfrom relabelto };
	class process { setexec };
}
allow docker_helper_builder_t bin_t:file { execute open read getattr map };
allow docker_helper_builder_t self:process { setexec };
allow docker_helper_builder_t docker_helper_builder_state_t:file { relabelfrom relabelto };
allow docker_helper_builder_t docker_helper_builder_state_t:dir { relabelfrom relabelto };
CATOF
{
  echo "=== the G31 control-plane diagnostic module (source) ==="
  cat /tmp/cat_launch_diag.te
} > "$EVIDENCE_DIR/c2-cat-module.txt" 2>&1
checkmodule -M -m -o /tmp/cat_launch_diag.tmp /tmp/cat_launch_diag.te 2>>"$EVIDENCE_DIR/c2-cat-module.txt" \
  || { note "the G31 control-plane module failed to compile"; exit 1; }
semodule_package -o /tmp/cat_launch_diag.pp -m /tmp/cat_launch_diag.tmp 2>>"$EVIDENCE_DIR/c2-cat-module.txt" \
  || { note "the G31 control-plane module failed to package"; exit 1; }
semodule -i /tmp/cat_launch_diag.pp 2>>"$EVIDENCE_DIR/c2-cat-module.txt" \
  || { note "the G31 control-plane module failed to load"; exit 1; }
cat "$EVIDENCE_DIR/c2-cat-module.txt" >&2

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
  printf '%s P5S2-CAT-LAUNCH-RESULT=INCOMPLETE (unit failed to start; recorded as a finding)\n' "$PREFIX" >&2
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
  printf '%s P5S2-CAT-LAUNCH-RESULT=INCOMPLETE (state root label; recorded as a finding)\n' "$PREFIX" >&2
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
  printf '%s P5S2-CAT-LAUNCH-RESULT=INCOMPLETE (assignment failed; recorded as a finding)\n' "$PREFIX" >&2
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


log 'E: Part A — the launch boundary (the mechanism facts)'
# Harvest completeness: disable every dontaudit rule (ours and the base
# policy's) so NO denial can hide from the leg harvests; re-enabled at
# teardown.
semanage dontaudit off >>"$EVIDENCE_DIR/te-dontaudit-off.log" 2>&1 || true
HV_EPOCH="$(date +%s)"
{
  echo "=== Part A: the manager's own context (before the launches) ==="
  MG_PID="$(systemctl show -p MainPID --value "$UNIT")"
  echo "manager pid: $MG_PID"
  echo "manager attr/current: $(tr -d '\0' < "/proc/$MG_PID/attr/current" 2>/dev/null || true)"
  echo "=== the existing process-transition machinery the launch rides on ==="
  sesearch --allow -s docker_helper_builder_t -t docker_helper_rootlesskit_t -c process 2>&1 || true
  sesearch --allow -s docker_helper_builder_t -t docker_helper_rootlesskit_exec_t -c file 2>&1 || true
  echo "=== the G31 control-plane diagnostic grants (the mechanism's own surfaces) ==="
  sesearch --allow -s docker_helper_builder_t -t bin_t -c file 2>&1 | grep -a cat_launch || true
} > "$EVIDENCE_DIR/a-launch-boundary.txt" 2>&1
cat "$EVIDENCE_DIR/a-launch-boundary.txt" >&2

log 'G: Part B — the category space contract'
{
  echo "=== Part B: the policy's category space ==="
  echo "--- seinfo (category statement count) ---"
  seinfo 2>&1 | grep -ai "categor" || true
  echo "--- the measured category-space edges on the state root ---"
  touch "$WORK/cat-edge"
  for cat in c0 c1 c1023 c1024; do
    if chcon -l "s0:$cat" "$WORK/cat-edge" 2>/dev/null; then
      echo "category $cat: assignable (stat: $(stat -c '%C' "$WORK/cat-edge"))"
    else
      echo "category $cat: NOT assignable"
    fi
  done
  echo "the stand-in pool: c1..c4 (one category per live operation; the host-wide"
  echo "coordination contract with other MCS consumers is recorded in the report;"
  echo "the pool size matches the manager's own concurrency ceiling in this stand)"
} > "$EVIDENCE_DIR/b-category-space.txt" 2>&1
cat "$EVIDENCE_DIR/b-category-space.txt" >&2

# The manager RPC helpers.
rpc_call() { # cmd arg out — one manager RPC
  set +e
  if [ -n "${2:-}" ]; then
    printf '%s %s\n' "$1" "$2" | timeout 180 socat - UNIX-CONNECT:"$MANAGER_SOCK" >> "$3" 2>&1
  else
    printf '%s\n' "$1" | timeout 180 socat - UNIX-CONNECT:"$MANAGER_SOCK" >> "$3" 2>&1
  fi
  echo "socat rc: $?" >> "$3"
  set -e
}
wait_sock() { # sockpath secs — readiness wait; echoes 0/1
  local sock="$1" secs="$2" w=0
  until [ -S "$sock" ] || [ "$w" -ge "$secs" ]; do
    sleep 1
    w=$((w + 1))
  done
  [ -S "$sock" ] && { echo 1; return; }
  echo 0
}

log 'H: Part C — two live operations launched CONCURRENTLY through the experimental manager'
# The two START RPCs are issued back-to-back; each RPC blocks on its own
# launch (the manager's launch runs outside the manager lock), so the two
# launches overlap in time. Expected: op A binds c1, op B binds c2, the
# two state trees are labeled at provisioning, the flows run at their own
# categories, and both real builds succeed in parallel.
OPA="$(gen_op_id)"
OPB="$(gen_op_id)"
SA="$STATE_ROOT/ops/$OPA"
SB="$STATE_ROOT/ops/$OPB"
RA="$RUNTIME_ROOT/ops/$OPA"
RB="$RUNTIME_ROOT/ops/$OPB"
{
  echo "=== Part C: the concurrent START pair ==="
} > "$EVIDENCE_DIR/c-starts.txt" 2>&1
( rpc_call START "$OPA" "$EVIDENCE_DIR/c-starts.txt" ) &
PA_START=$!
( rpc_call START "$OPB" "$EVIDENCE_DIR/c-starts.txt" ) &
PB_START=$!
wait "$PA_START" "$PB_START" || true
RA_READY=$(wait_sock "$RA/buildkitd.sock" 120)
RB_READY=$(wait_sock "$RB/buildkitd.sock" 120)
{
  echo "=== Part C: the launch results ==="
  echo "A readiness: $RA_READY; B readiness: $RB_READY"
  echo "A tree labels:"
  stat -c '%C %n' "$SA" "$SA/rootlesskit-state" "$SA/root" 2>&1 || true
  echo "B tree labels:"
  stat -c '%C %n' "$SB" "$SB/rootlesskit-state" "$SB/root" 2>&1 || true
  echo "the flow process contexts (the per-op categories):"
  for pid in $(pgrep -f "rootlesskit --net=slirp4netns" 2>/dev/null || true); do
    echo "pid $pid: $(tr -d '\0' < "/proc/$pid/attr/current" 2>/dev/null || true) uid=$(ps -o uid= -p "$pid" 2>/dev/null | tr -d ' ' || true)"
  done
  for pid in $(pgrep -f "buildkitd --rootless" 2>/dev/null || true); do
    echo "buildkitd pid $pid: $(tr -d '\0' < "/proc/$pid/attr/current" 2>/dev/null || true)"
  done
  echo "=== the manager's own context (after the concurrent launches — unchanged expected) ==="
  MG_PID="$(systemctl show -p MainPID --value "$UNIT")"
  echo "manager pid: $MG_PID"
  echo "manager attr/current: $(tr -d '\0' < "/proc/$MG_PID/attr/current" 2>/dev/null || true)"
} > "$EVIDENCE_DIR/c-launch-results.txt" 2>&1
# The stand does not assume WHICH category each operation received (the
# concurrent RPC order is racy): every leg derives each operation's
# category from that operation's own tree label and asserts the
# state/process parity against it.
CAT_A=$(stat -c '%C' "$SA" 2>/dev/null | sed 's/.*s0://' || true)
CAT_B=$(stat -c '%C' "$SB" 2>/dev/null | sed 's/.*s0://' || true)
{
  echo "derived categories: A=$CAT_A B=$CAT_B"
  echo "categories distinct (unique-live-category): $([ -n "$CAT_A" ] && [ "$CAT_A" != "$CAT_B" ] && echo yes || echo no)"
} >> "$EVIDENCE_DIR/c-launch-results.txt" 2>&1
cat "$EVIDENCE_DIR/c-launch-results.txt" >&2
if [ "$RA_READY" != "1" ] || [ "$RB_READY" != "1" ] || [ -z "$CAT_A" ] || [ "$CAT_A" = "$CAT_B" ]; then
  note "the concurrent launch pair failed; the experiment cannot proceed"
  harvest_avcs_since "$HV_EPOCH" "$EVIDENCE_DIR/c-launch-avcs.txt"
  grep -a "avc:  denied" "$EVIDENCE_DIR/c-launch-avcs.txt" | head -20 >&2 || true
  printf '%s P5S2-CAT-LAUNCH-RESULT=INCOMPLETE (concurrent launch failed; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi

log 'I: Part C — both operations build in parallel (the real builds)'
CTX="$WORK/ctx"
mkdir -p "$CTX"
write_consume_dockerfile() { # nonce — the G29/G30 consume shape
  cat > "$CTX/Dockerfile" <<EOF
FROM alpine:3.20
RUN mkdir -p /m2 && echo p5s2-g31-nonce-$1 > /m2/nonce.txt && id > /m2/id.txt && echo p5s2-g31-marker > /m2/marker.txt && cat /proc/self/uid_map > /m2/uid_map.txt
EOF
}
write_consume_dockerfile 0
chcon -u system_u -t docker_helper_builder_state_t -l s0 "$CTX" "$CTX/Dockerfile" 2>/dev/null || true
mkdir -p "$WORK/docker-config" "$WORK/export" "$WORK/reports"
echo '{}' > "$WORK/docker-config/config.json"
do_build() { # sock dest logpath — caller wraps with set +e and reads $BUILD_RC
  DOCKER_CONFIG="$WORK/docker-config" timeout 300 "$BUILDCTL" \
    --addr "unix://$1" build \
    --progress=plain --frontend=dockerfile.v0 \
    --local "context=$WORK/ctx" --local "dockerfile=$WORK/ctx" \
    --output "type=docker,name=p5s2g31:proof,dest=$2" \
    > "$3" 2>&1
  BUILD_RC=$?
  echo "buildctl exit: $BUILD_RC" >> "$3"
}
set +e
do_build "$RA/buildkitd.sock" "$WORK/export/out-a.tar" "$EVIDENCE_DIR/c-build-a.log" &
do_build "$RB/buildkitd.sock" "$WORK/export/out-b.tar" "$EVIDENCE_DIR/c-build-b.log" &
wait
set -e
tar_report "$WORK/export/out-a.tar" "$WORK/reports/a.json" "" >"$EVIDENCE_DIR/c-build-a-tar.log" 2>&1 || true
tar_report "$WORK/export/out-b.tar" "$WORK/reports/b.json" "" >"$EVIDENCE_DIR/c-build-b-tar.log" 2>&1 || true
BUILD_A_RC=$(awk '/buildctl exit:/{print $NF}' "$EVIDENCE_DIR/c-build-a.log" | tail -1)
BUILD_B_RC=$(awk '/buildctl exit:/{print $NF}' "$EVIDENCE_DIR/c-build-b.log" | tail -1)
A_ID_OK=$(python3 -c 'import json,sys;r=json.load(open(sys.argv[1]));print(sum(1 for m in r.get("marker",[]) if m.get("name","").endswith("m2/id.txt") and "uid=0(root)" in m.get("content","")))' "$WORK/reports/a.json" 2>/dev/null || echo 0)
B_ID_OK=$(python3 -c 'import json,sys;r=json.load(open(sys.argv[1]));print(sum(1 for m in r.get("marker",[]) if m.get("name","").endswith("m2/id.txt") and "uid=0(root)" in m.get("content","")))' "$WORK/reports/b.json" 2>/dev/null || echo 0)
{
  echo "=== Part C: the parallel build results ==="
  echo "A build rc: $BUILD_A_RC; A id.txt ok: $A_ID_OK"
  echo "B build rc: $BUILD_B_RC; B id.txt ok: $B_ID_OK"
} > "$EVIDENCE_DIR/c-build-results.txt" 2>&1
cat "$EVIDENCE_DIR/c-build-results.txt" >&2

log 'J: Part C — the per-operation descendant inventories (the no-bleed check)'
{
  echo "=== Part C: the tree label uniformity per operation (no transient cross-op category) ==="
  echo "--- op A's state tree ---"
  find "$SA" -exec stat -c '%C' {} \; 2>/dev/null | sort | uniq -c | sort -rn
  echo "--- op B's state tree ---"
  find "$SB" -exec stat -c '%C' {} \; 2>/dev/null | sort | uniq -c | sort -rn
} > "$EVIDENCE_DIR/c-tree-uniformity.txt" 2>&1
{
  echo "=== the uncategorized objects inside each state tree (expect at most the noise-free run) ==="
  echo "--- op A ---"; find "$SA" -exec stat -c '%C %n' {} \; 2>/dev/null | grep -av "s0:$CAT_A" || echo none
  echo "--- op B ---"; find "$SB" -exec stat -c '%C %n' {} \; 2>/dev/null | grep -av "s0:$CAT_B" || echo none
} > "$EVIDENCE_DIR/c-tree-uncategorized.txt" 2>&1
cat "$EVIDENCE_DIR/c-tree-uncategorized.txt" >&2

log 'G: Part G — the exact security regression at two live operations (both ops live here)'
# guard 1: cross-op newuidmap (the B-category subject -> the A-category target)
FIFO_G1="$WORK/probe/fifo-g1"
mkfifo "$FIFO_G1"
chmod 666 "$FIFO_G1"
timeout 120 runuser -u "$BUILDER_USER" -- runcon "$RK_CTX:s0:$CAT_B" /usr/local/bin/map_probe --be-target "$FIFO_G1" \
  >"$WORK/probe/b-g1.out" 2>&1 < /dev/null &
exec 3<>"$FIFO_G1"
BPID_G1=""
if IFS= read -r -t 60 line <&3; then
  case "$line" in PID=[0-9]*) BPID_G1="${line#PID=}" ;; esac
fi
exec 3<&-
{
  echo "=== guard 1: cross-op newuidmap s0:$CAT_B -> s0:$CAT_A uid_map write (expect MCS-BLOCKED) ==="
  echo "target pid: ${BPID_G1:-NONE}"
  echo "target uid_map before: [$(cat "/proc/$BPID_G1/uid_map" 2>/dev/null || true)]"
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_CTX:s0:$CAT_A" /usr/local/bin/map_probe \
    --invoke-helper /usr/bin/newuidmap "$BPID_G1" 0 475 1 1 165536 65536 2>&1 < /dev/null || echo "helper attempt rc=$?"
  echo "target uid_map after: [$(cat "/proc/$BPID_G1/uid_map" 2>/dev/null || true)]"
} > "$EVIDENCE_DIR/g-guard1-newuidmap.txt" 2>&1
cat "$EVIDENCE_DIR/g-guard1-newuidmap.txt" >&2
pkill -KILL -f 'map_probe --be-target' 2>/dev/null || true
# guard 2: cross-op TERM/KILL to a categorized vehicle
FIFO_G2="$WORK/probe/fifo-g2"
mkfifo "$FIFO_G2"
chmod 666 "$FIFO_G2"
timeout 120 runuser -u "$BUILDER_USER" -- runcon "$RK_CTX:s0:$CAT_B" /usr/local/bin/map_probe --be-target "$FIFO_G2" \
  >"$WORK/probe/b-g2.out" 2>&1 < /dev/null &
exec 3<>"$FIFO_G2"
BPID_G2=""
if IFS= read -r -t 60 line <&3; then
  case "$line" in PID=[0-9]*) BPID_G2="${line#PID=}" ;; esac
fi
exec 3<&-
{
  echo "=== guard 2: cross-op TERM/KILL s0:$CAT_A -> s0:$CAT_B (expect MCS-BLOCKED, target alive) ==="
  echo "target pid: ${BPID_G2:-NONE}"
  for sigspec in 15 9; do
    timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_CTX:s0:$CAT_A" /usr/local/bin/map_probe --signal "$BPID_G2" "$sigspec" 2>&1 < /dev/null || true
  done
  echo "target alive after the cross-op signals: $(kill -0 "$BPID_G2" 2>/dev/null && echo YES || echo NO) (the runner's unconfined check)"
} > "$EVIDENCE_DIR/g-guard2-signals.txt" 2>&1
cat "$EVIDENCE_DIR/g-guard2-signals.txt" >&2
pkill -KILL -f 'map_probe --be-target' 2>/dev/null || true
# guard 3: cross-op connect to a live operation's buildkitd.sock
{
  echo "=== guard 3: cross-op connect to op A's live buildkitd.sock (expect EACCES) ==="
  echo "socket: $(stat -c '%C %U:%G %a' "$RA/buildkitd.sock" 2>&1)"
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_CTX:s0:$CAT_B" /usr/local/bin/map_probe --connect "$RA/buildkitd.sock" 2>&1 < /dev/null || true
} > "$EVIDENCE_DIR/g-guard3-sockconnect.txt" 2>&1
cat "$EVIDENCE_DIR/g-guard3-sockconnect.txt" >&2
# guard 4: the operation category cannot reach the manager's authority
MG_PID="$(systemctl show -p MainPID --value "$UNIT")"
{
  echo "=== guard 4: the op cannot reach the manager's authority (manager.sock connect + signal) ==="
  echo "manager.sock: $(stat -c '%C %U:%G %a' "$MANAGER_SOCK" 2>&1)"
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_CTX:s0:$CAT_B" /usr/local/bin/map_probe --connect "$MANAGER_SOCK" 2>&1 < /dev/null || true
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_CTX:s0:$CAT_B" /usr/local/bin/map_probe --signal "$MG_PID" 15 2>&1 < /dev/null || true
  echo "manager alive after the signal attempt: $(kill -0 "$MG_PID" 2>/dev/null && echo YES || echo NO)"
} > "$EVIDENCE_DIR/g-guard4-manager.txt" 2>&1
cat "$EVIDENCE_DIR/g-guard4-manager.txt" >&2
# guard 5: the exact G29 snapshot write (the B-category subject -> the
# A-category tree's FROM-snapshot /etc/passwd)
G29_OK=0
A_PASSWORD_TARGET="$(find "$SA/root/runc-overlayfs/snapshots" -type f -path '*/fs/etc/passwd' 2>/dev/null | head -1 || true)"
if [ -n "$A_PASSWORD_TARGET" ]; then
  PW_SHA0=$(sha256sum "$A_PASSWORD_TARGET" | awk '{print $1}')
  set +e
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_CTX:s0:$CAT_B" /usr/local/bin/map_probe \
    --poison "$A_PASSWORD_TARGET" 0 "g29p" > "$EVIDENCE_DIR/g-guard5-attempt.txt" 2>&1
  set -e
  PW_SHA1=$(sha256sum "$A_PASSWORD_TARGET" 2>/dev/null | awk '{print $1}')
  {
    echo "=== guard 5: the exact G29 snapshot write (s0:$CAT_B -> the s0:$CAT_A tree) ==="
    echo "target: $A_PASSWORD_TARGET"
    cat "$EVIDENCE_DIR/g-guard5-attempt.txt"
    echo "file unchanged: $([ "$PW_SHA0" = "$PW_SHA1" ] && echo yes || echo no)"
  } > "$EVIDENCE_DIR/g-guard5.txt" 2>&1
  [ "$PW_SHA0" = "$PW_SHA1" ] && G29_OK=1
else
  echo "no FROM-snapshot passwd found in the live c2 tree" > "$EVIDENCE_DIR/g-guard5.txt"
fi
cat "$EVIDENCE_DIR/g-guard5.txt" >&2
# the own-operation equivalents (the B-category subject -> its own tree)
{
  echo "=== guard 6: the own-operation equivalents (s0:$CAT_B -> its own tree) ==="
} > "$EVIDENCE_DIR/g-guard6-own.txt" 2>&1
SB_PW_TARGET="$(find "$SB/root/runc-overlayfs/snapshots" -type f -path '*/fs/etc/passwd' 2>/dev/null | head -1 || true)"
if [ -n "$SB_PW_TARGET" ]; then
  set +e
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_CTX:s0:$CAT_B" /usr/local/bin/map_probe \
    --read "$SB_PW_TARGET" >> "$EVIDENCE_DIR/g-guard6-own.txt" 2>&1
  set -e
  echo "own read rc above (rc=3 errno=0 expected)" >> "$EVIDENCE_DIR/g-guard6-own.txt"
fi
cat "$EVIDENCE_DIR/g-guard6-own.txt" >&2
harvest_avcs_since "$HV_EPOCH" "$EVIDENCE_DIR/g-guard-avcs.txt"
dedup_avcs "$EVIDENCE_DIR/g-guard-avcs.txt" "$EVIDENCE_DIR/g-guard-avcs-dedup.txt"

log 'K: Part D — the allocation collision proof (the third live operation)'
OPC="$(gen_op_id)"
{
  echo "=== Part D: the third START with two live operations ==="
} > "$EVIDENCE_DIR/d-collision.txt" 2>&1
rpc_call START "$OPC" "$EVIDENCE_DIR/d-collision.txt"
sleep 2
{
  echo "third START response above (the manager's own ceiling is the production refusal)"
  echo "C tree created: $([ -e "$STATE_ROOT/ops/$OPC" ] && echo yes || echo no)"
  echo "no third flow: $(pgrep -cf "rootlesskit --net=slirp4netns" 2>/dev/null || echo 0) rootlesskit leaders"
} >> "$EVIDENCE_DIR/d-collision.txt" 2>&1
cat "$EVIDENCE_DIR/d-collision.txt" >&2

log 'L: Part E — release and reuse (STOP A -> the freed category -> a new operation at the same category)'
{
  echo "=== Part E: STOP A (the convergence) ==="
} > "$EVIDENCE_DIR/e-release.txt" 2>&1
rpc_call STOP "$OPA" "$EVIDENCE_DIR/e-release.txt"
E_WAIT=0
E_OK=0
until [ ! -e "$SA" ] || [ "$E_WAIT" -ge 240 ]; do
  sleep 2
  E_WAIT=$((E_WAIT + 2))
done
[ ! -e "$SA" ] && E_OK=1
{
  echo "A trees converged (removed): $E_OK (the freed category: s0:$CAT_A)"
  echo "$CAT_A processes remaining: $(pgrep -cf "s0:$CAT_A" 2>/dev/null || echo 0)"
} >> "$EVIDENCE_DIR/e-release.txt" 2>&1
cat "$EVIDENCE_DIR/e-release.txt" >&2
OPD="$(gen_op_id)"
SD="$STATE_ROOT/ops/$OPD"
RD="$RUNTIME_ROOT/ops/$OPD"
rpc_call START "$OPD" "$EVIDENCE_DIR/e-release.txt"
RD_READY=$(wait_sock "$RD/buildkitd.sock" 120)
sleep 1
{
  echo "=== Part E: the new operation received the FREED category ==="
  echo "new op: $OPD readiness: $RD_READY"
  echo "new tree labels:"
  stat -c '%C %n' "$SD" "$SD/rootlesskit-state" "$SD/root" 2>&1 || true
  echo "new tree label is s0:$CAT_A (the freed category reused): $(stat -c '%C' "$SD" 2>/dev/null | grep -q "s0:$CAT_A" && echo yes || echo no)"
} >> "$EVIDENCE_DIR/e-release.txt" 2>&1
cat "$EVIDENCE_DIR/e-release.txt" >&2
# the new op builds (the reuse works end to end)
set +e
do_build "$RD/buildkitd.sock" "$WORK/export/out-d.tar" "$EVIDENCE_DIR/e-build-d.log"
BUILD_D_RC=$BUILD_RC
set -e
tar_report "$WORK/export/out-d.tar" "$WORK/reports/d.json" "" >"$EVIDENCE_DIR/e-build-d-tar.log" 2>&1 || true
D_ID_OK=$(python3 -c 'import json,sys;r=json.load(open(sys.argv[1]));print(sum(1 for m in r.get("marker",[]) if m.get("name","").endswith("m2/id.txt") and "uid=0(root)" in m.get("content","")))' "$WORK/reports/d.json" 2>/dev/null || echo 0)
echo "reused-category build rc: $BUILD_D_RC; id.txt ok: $D_ID_OK" >> "$EVIDENCE_DIR/e-release.txt"
# stop the reused op first so the residue probe's refusal is the
# adoption refusal, not the ceiling refusal
rpc_call STOP "$OPD" "$EVIDENCE_DIR/e-release.txt"
D_WAIT=0
D_OK2=0
until [ ! -e "$SD" ] || [ "$D_WAIT" -ge 240 ]; do
  sleep 2
  D_WAIT=$((D_WAIT + 2))
done
[ ! -e "$SD" ] && D_OK2=1
echo "reused op trees converged: $D_OK2" >> "$EVIDENCE_DIR/e-release.txt"
# the stale categorized residue is refused (no adoption)
OPS="$(gen_op_id)"
mkdir -p "$RUNTIME_ROOT/ops/$OPS" "$STATE_ROOT/ops/$OPS/rootlesskit-state" "$STATE_ROOT/ops/$OPS/root"
chown "$BUILDER_USER":"$BUILDER_USER" "$RUNTIME_ROOT/ops/$OPS" "$STATE_ROOT/ops/$OPS" \
  "$STATE_ROOT/ops/$OPS/rootlesskit-state" "$STATE_ROOT/ops/$OPS/root"
chmod 700 "$RUNTIME_ROOT/ops/$OPS" "$STATE_ROOT/ops/$OPS" \
  "$STATE_ROOT/ops/$OPS/rootlesskit-state" "$STATE_ROOT/ops/$OPS/root"
chcon -u system_u -t docker_helper_builder_state_t -l s0:c1 \
  "$STATE_ROOT/ops/$OPS" "$STATE_ROOT/ops/$OPS/rootlesskit-state" "$STATE_ROOT/ops/$OPS/root"
rpc_call START "$OPS" "$EVIDENCE_DIR/e-release.txt"
sleep 2
{
  echo "=== Part E: the stale categorized residue is refused (no adoption) ==="
  echo "sock appeared: $([ -S "$RUNTIME_ROOT/ops/$OPS/buildkitd.sock" ] && echo yes || echo no)"
  echo "planted dirs survive: $([ -e "$STATE_ROOT/ops/$OPS" ] && echo yes || echo no)"
  echo "planted label intact: $(stat -c '%C' "$STATE_ROOT/ops/$OPS" 2>&1)"
} >> "$EVIDENCE_DIR/e-release.txt" 2>&1
cat "$EVIDENCE_DIR/e-release.txt" >&2
rm -rf "$RUNTIME_ROOT/ops/$OPS" "$STATE_ROOT/ops/$OPS" 2>/dev/null || true

log 'M: Part F — abnormal termination (the SIGKILLed leader; the retained entry; the no-early-reuse proof; the recovery)'
F_EPOCH2="$(date +%s)"
OPE="$(gen_op_id)"
SE="$STATE_ROOT/ops/$OPE"
RE="$RUNTIME_ROOT/ops/$OPE"
rpc_call START "$OPE" "$EVIDENCE_DIR/f-abnormal.txt"
RE_READY=$(wait_sock "$RE/buildkitd.sock" 120)
sleep 1
CAT_E=$(stat -c '%C' "$SE" 2>/dev/null | sed 's/.*s0://' || true)
ELE_PID=""
for pid in $(pgrep -f "rootlesskit --net=slirp4netns" 2>/dev/null || true); do
  if tr -d '\0' < "/proc/$pid/attr/current" 2>/dev/null | grep -q "s0:$CAT_E"; then
    ELE_PID="$pid"
    break
  fi
done
if [ "$RE_READY" = "1" ] && [ -n "$ELE_PID" ]; then
  pkill -KILL -f "ops/$OPE/root" 2>/dev/null || true
  F_WAIT=0
  F_OK=0
  until [ ! -e "$SE" ] || [ "$F_WAIT" -ge 240 ]; do
    sleep 2
    F_WAIT=$((F_WAIT + 2))
  done
  [ ! -e "$SE" ] && F_OK=1
else
  F_OK=0
fi
harvest_avcs_since "$F_EPOCH2" "$EVIDENCE_DIR/f-abnormal-avcs.txt" 2>/dev/null || true
{
  echo "launch ready: $RE_READY; leader: ${ELE_PID:-none}"
  echo "manager's own cleanup converged: $F_OK (the known G30 finding expects 0: the api.sock unlink gap)"
  echo "state residue: $([ -e "$SE" ] && stat -c '%C %a %n' "$SE/rootlesskit-state/api.sock" 2>&1 || echo none)"
} > "$EVIDENCE_DIR/f-abnormal.txt" 2>&1
F_EPOCH2="$(date +%s)"
# the no-early-reuse proof: STOP B frees c2; the retained entry still holds its category
rpc_call STOP "$OPB" "$EVIDENCE_DIR/f-abnormal.txt"
OPE2="$(gen_op_id)"
RE2="$RUNTIME_ROOT/ops/$OPE2"
rpc_call START "$OPE2" "$EVIDENCE_DIR/f-abnormal.txt"
RE2_READY=$(wait_sock "$RE2/buildkitd.sock" 120)
sleep 1
{
  echo "=== Part F: the next operation does NOT reuse the retained category ==="
  echo "next op: $OPE2 readiness: $RE2_READY"
  echo "next tree: $(stat -c '%C' "$STATE_ROOT/ops/$OPE2" 2>&1)"
  echo "next tree got a DIFFERENT category than the retained one (s0:$CAT_E): $(stat -c '%C' "$STATE_ROOT/ops/$OPE2" 2>/dev/null | grep -q "s0:$CAT_E" && echo NO || echo yes)"
} >> "$EVIDENCE_DIR/f-abnormal.txt" 2>&1
# the recovery: the flow's own-authority socket cleanup, then the PURGE retry
{
  echo "=== Part F: the flow's own-authority socket cleanup + the PURGE retry ==="
} >> "$EVIDENCE_DIR/f-abnormal.txt" 2>&1
if [ -e "$SE/rootlesskit-state/api.sock" ]; then
  set +e
  timeout 60 runuser -u "$BUILDER_USER" -- runcon "$RK_CTX:s0:$CAT_E" /usr/local/bin/map_probe \
    --unlink "$SE/rootlesskit-state/api.sock" >> "$EVIDENCE_DIR/f-abnormal.txt" 2>&1
  set -e
fi
rpc_call PURGE "" "$EVIDENCE_DIR/f-abnormal.txt"
G_WAIT=0
G_OK=0
until [ ! -e "$SE" ] || [ "$G_WAIT" -ge 240 ]; do
  sleep 2
  G_WAIT=$((G_WAIT + 2))
done
[ ! -e "$SE" ] && G_OK=1
{
  echo "residue converged after the flow-side cleanup + PURGE retry: $G_OK"
  echo "the manager journal window:"
  journalctl -u "$UNIT" --since "@$F_EPOCH2" --no-pager 2>/dev/null | grep -a 'purge\|residue\|refus\|cleanup\|unexpected' | head -12
} >> "$EVIDENCE_DIR/f-abnormal.txt" 2>&1
cat "$EVIDENCE_DIR/f-abnormal.txt" >&2

log 'O: the final harvest + the leg summary'
harvest_avcs_since "$HV_EPOCH" "$EVIDENCE_DIR/h-avcs-all.txt"
{
  echo "=== the residual AVC ledger (deduped) ==="
  grep -a "avc:  denied" "$EVIDENCE_DIR/h-avcs-all.txt" \
    | sed -E 's/.*denied  \{ ([^}]*) \}.*scontext=(\S+) tcontext=(\S+) tclass=(\S+) permissive=.*/\1 | \2 -> \3 (\4)/' \
    | sort | uniq -c | sort -rn | head -40
} > "$EVIDENCE_DIR/h-residual-avcs-dedup.txt" 2>&1
cat "$EVIDENCE_DIR/h-residual-avcs-dedup.txt" >&2 || true

# -------- the leg summary (the verdict flags) --------
LAUNCH_OK=0
if grep -aq "manager attr/current: system_u:system_r:docker_helper_builder_t:s0" "$EVIDENCE_DIR/a-launch-boundary.txt" \
   && grep -aq "manager attr/current: system_u:system_r:docker_helper_builder_t:s0" "$EVIDENCE_DIR/c-launch-results.txt" \
   && grep -aq "docker_helper_rootlesskit_t:s0:$CAT_A" "$EVIDENCE_DIR/c-launch-results.txt" \
   && grep -aq "docker_helper_rootlesskit_t:s0:$CAT_B" "$EVIDENCE_DIR/c-launch-results.txt"; then LAUNCH_OK=1; fi
TWO_LIVE_OK=0
A_SECTION=$(sed -n "/op A's state tree/,/op B's state tree/p" "$EVIDENCE_DIR/c-tree-uniformity.txt" 2>/dev/null | grep -av "state tree" || true)
B_SECTION=$(sed -n "/op B's state tree/,$ p" "$EVIDENCE_DIR/c-tree-uniformity.txt" 2>/dev/null | grep -av "state tree" || true)
if [ "$RA_READY" = "1" ] && [ "$RB_READY" = "1" ] \
   && echo "$A_SECTION" | grep -aq "s0:$CAT_A" \
   && echo "$B_SECTION" | grep -aq "s0:$CAT_B" \
   && ! echo "$A_SECTION" | grep -aq "s0:$CAT_B" \
   && ! echo "$B_SECTION" | grep -aq "s0:$CAT_A" \
   && ! echo "$A_SECTION" | grep -aq "builder_state_t:s0$" \
   && ! echo "$B_SECTION" | grep -aq "builder_state_t:s0$"; then TWO_LIVE_OK=1; fi
BUILDS_OK=0
[ "$BUILD_A_RC" = "0" ] && [ "$A_ID_OK" = "1" ] && [ "$BUILD_B_RC" = "0" ] && [ "$B_ID_OK" = "1" ] && BUILDS_OK=1
COLLISION_OK=0
if grep -aq "builder_at_ceiling" "$EVIDENCE_DIR/d-collision.txt" \
   && grep -aq "C tree created: no" "$EVIDENCE_DIR/d-collision.txt"; then COLLISION_OK=1; fi
RELEASE_OK=0
if [ "$E_OK" = "1" ] && grep -aq "new tree label is s0:c1 (the freed category reused): yes" "$EVIDENCE_DIR/e-release.txt" \
   && [ "$BUILD_D_RC" = "0" ] && [ "$D_ID_OK" = "1" ] \
   && grep -aq "sock appeared: no" "$EVIDENCE_DIR/e-release.txt" \
   && grep -aq "planted dirs survive: yes" "$EVIDENCE_DIR/e-release.txt"; then RELEASE_OK=1; fi
ABNORM_OK=0
if grep -aq "manager's own cleanup converged: 0" "$EVIDENCE_DIR/f-abnormal.txt" \
   && grep -aq "next tree got a DIFFERENT category than the retained one: yes" "$EVIDENCE_DIR/f-abnormal.txt" \
   && grep -aq "residue converged after the flow-side cleanup + PURGE retry: 1" "$EVIDENCE_DIR/f-abnormal.txt"; then ABNORM_OK=1; fi
GUARDS_OK=0
if grep -q 'Could not open proc directory for target.*Permission denied' "$EVIDENCE_DIR/g-guard1-newuidmap.txt" \
   && grep -q 'target uid_map after: \[\]' "$EVIDENCE_DIR/g-guard1-newuidmap.txt" \
   && grep -q 'rc=-1 errno=13' "$EVIDENCE_DIR/g-guard3-sockconnect.txt" \
   && grep -q 'rc=-1 errno=13' "$EVIDENCE_DIR/g-guard4-manager.txt" \
   && grep -q "manager alive after the signal attempt: YES" "$EVIDENCE_DIR/g-guard4-manager.txt" \
   && grep -q 'target alive after the cross-op signals: YES' "$EVIDENCE_DIR/g-guard2-signals.txt"; then GUARDS_OK=1; fi
G29_OK_SUM=$G29_OK
{
  echo "=== the G31 leg summary ==="
  echo "launch mechanism (manager context unchanged + per-op flow categories): $LAUNCH_OK"
  echo "two live operations (labels+uniform trees, no bleed): $TWO_LIVE_OK"
  echo "parallel builds (both rc=0 + id ok): $BUILDS_OK"
  echo "collision refusal (third START refused, no tree): $COLLISION_OK"
  echo "release+reuse (stop converges, freed category reused, stale residue refused): $RELEASE_OK"
  echo "abnormal termination (retained entry, no early reuse, recovery converges): $ABNORM_OK"
  echo "G29 primitive blocked at two live ops: $G29_OK_SUM"
  echo "G26 guards: $GUARDS_OK"
  echo ""
  echo "verdict rule: PASS requires all seven flags = 1"
} > "$EVIDENCE_DIR/h-summary.txt" 2>&1
cat "$EVIDENCE_DIR/h-summary.txt" >&2
RESULT="INCOMPLETE"
if [ "$LAUNCH_OK" = "1" ] && [ "$TWO_LIVE_OK" = "1" ] && [ "$BUILDS_OK" = "1" ] && [ "$COLLISION_OK" = "1" ] \
   && [ "$RELEASE_OK" = "1" ] && [ "$ABNORM_OK" = "1" ] && [ "$G29_OK_SUM" = "1" ] && [ "$GUARDS_OK" = "1" ]; then
  RESULT="PASS"
elif [ "$TWO_LIVE_OK" != "1" ] || [ "$G29_OK_SUM" != "1" ]; then
  RESULT="FAIL"
fi
printf '%s P5S2-CAT-LAUNCH-RESULT=%s (launch=%d two-live=%d builds=%d collision=%d release=%d abnormal=%d g29=%d guards=%d)\n' \
  "$PREFIX" "$RESULT" "$LAUNCH_OK" "$TWO_LIVE_OK" "$BUILDS_OK" "$COLLISION_OK" "$RELEASE_OK" "$ABNORM_OK" "$G29_OK_SUM" "$GUARDS_OK" >&2
