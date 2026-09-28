#!/usr/bin/env bash
#
# Guest-side P5-S2g29 paired cross-operation BuildKit state/cache
# poisoning proof for openSUSE Tumbleweed. INVESTIGATION ONLY.
#
# The question G29 answers (the last open G27 criterion):
#   can operation A, through the already-proven cross-op write surface
#   (rootlesskit_t -> docker_helper_builder_state_t over the
#   uncategorized per-op state trees), CAUSALLY change operation B's
#   build result?
#
# Method: a paired causal measurement
#   cross-op state mutation by A -> trusted consumption by buildkitd B
#   -> observable change in B
# or the proof that the chosen writable surface gives no such effect.
# Static trust-model claims are not evidence; every leg is a runtime
# measurement on the G28 stand (REAL manager under the REAL unit with
# the SELinuxContext binding and the P4 unit-cgroup boundary, REAL
# rootlesskit production argv, pinned BuildKit v0.33.0, SELinux
# Enforcing everywhere, the G26 MCS delta + the UNCHANGED candidate
# payload module v12 loaded, production policy / manager / BuildKit
# sources untouched).
#
# Legs (the runs so far: run 1 = CI 36465937458 measured the snapshot
# marker mutation landing cross-op with the cache-hit export ignoring it
# (D4) and the blob write DAC-blocked (0444); run 2 = CI 36467005341
# measured the blob candidate through the granted setattr authority —
# the mutation landed and the export DETECTED it, fail-closed D3):
#   Part A  state inventory: ops/<B>/root's real post-build content
#           (path, size, mode, uid, scontext, sha256 per file) and the
#           target selection: the snapshot file the RUN's fresh
#           execution consumes (the FROM snapshot's /etc/passwd — read
#           by the RUN's own `id`, NOT integrity-verified), with the
#           digest-proven content blobs as the measured fallback class.
#   Part B  baseline pair: B builds the nonce-0 Dockerfile twice with no
#           mutation; the exported observables (the m2 file contents,
#           the manifest digests, the layer blob bytes) must be stable,
#           and the identity check (the exported layer member's bytes ==
#           the state-tree blob's bytes) proves WHICH state object B's
#           export consumes before anything is mutated.
#   Part C  cross-op mutation: from op A's category (a rootlesskit_t:s0:c1
#           vehicle — the G28-established instrument for A's flow
#           domain, byte-identical TE authority to buildkitd A's own
#           processes), one pwrite into the ONE chosen object of op B.
#           Only candidate-policy-granted production-like access; no
#           root write for the mutation; no new grants; B is never
#           stopped; the mutation is proven by the vehicle's pwrite rc +
#           read-back + the harness sha256.
#   Part D  consumption proof: B rebuilds with a FRESH leg nonce (the
#           RUN is a cache-missed execution over the live snapshot state;
#           the FROM stays a cache hit over the same snapshot chain) and
#           the export is compared against the pre-mutation consume
#           baseline. Outcomes: POISONED-OUTPUT (D1/D2 — the FAIL
#           boundary), D3 (integrity fail-closed), D4 (ignored),
#           MUTATION-BLOCKED (the write never landed).
#   Part E  paired own-op control: the object is restored to its exact
#           baseline bytes (harness hygiene, recorded, B idle), the
#           post-restore state is re-baselined, then B's OWN category
#           (a rootlesskit_t:s0:c2 vehicle) performs the SAME mutation
#           on the SAME object; the same consumption observation proves
#           the object is consumption-relevant and the cross-op leg
#           reached the same consumer path.
#   Part F  attribution: the seven conditions are assembled into the
#           leg summary.
#   Guards  the short G26 regressions only: cross-op newuidmap
#           MCS-blocked, cross-op signal path closed, cross-op connect
#           to op B's live buildkitd.sock closed, and op A cannot reach
#           the manager's authority (manager.sock connect + signal).
#           The full G26/G28 suite is NOT repeated.
#
# Out-of-scope by the task contract: production policy commits, manager/
# BuildKit source changes, fixing any found poisoning path, category
# allocator design, random fuzzing of the state tree, boltdb corruption
# as a starting target, root-assisted mutation legs.
#
set -Eeuo pipefail

PREFIX='[release-2.4-p5s2-state-poison-tw]'
EVIDENCE_DIR=/tmp/release-2.4-p5s2-state-poison-evidence
BUILDER_USER=docker-helper-builder
GUEST_FILES=/tmp/p5s2-state-poison
TRANSFERRED="$GUEST_FILES"
STATE_ROOT=/var/lib/docker-helper-builder
RUNTIME_ROOT=/run/docker-helper-builder
MANAGER_SOCK="$RUNTIME_ROOT/manager.sock"
UNIT=docker-helper-builder
BUILDKITD=/usr/libexec/docker-helper/buildkit/buildkitd
BUILDCTL=/usr/libexec/docker-helper/buildkit/buildctl
WORK=/tmp/p5s2-g29-work

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
  printf '%s P5S2-STATE-POISON-RESULT=INCOMPLETE (not enforcing; recorded as a finding)\n' "$PREFIX" >&2
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
  printf '%s P5S2-STATE-POISON-RESULT=INCOMPLETE (toolchain unavailable; recorded as a finding)\n' "$PREFIX" >&2
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
  printf '%s P5S2-STATE-POISON-RESULT=INCOMPLETE (payload download/verify failed; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi
install -d -m 0755 /tmp/p5s2-g29-payload-extract
tar -xzf "$WORK/buildkit.tgz" -C /tmp/p5s2-g29-payload-extract
install -d -m 0755 /usr/libexec/docker-helper/buildkit
install -m 0755 /tmp/p5s2-g29-payload-extract/bin/buildkitd "$BUILDKITD"
install -m 0755 /tmp/p5s2-g29-payload-extract/bin/buildctl "$BUILDCTL"
install -m 0755 /tmp/p5s2-g29-payload-extract/bin/buildkit-runc \
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
  printf '%s P5S2-STATE-POISON-RESULT=INCOMPLETE (unit failed to start; recorded as a finding)\n' "$PREFIX" >&2
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
  printf '%s P5S2-STATE-POISON-RESULT=INCOMPLETE (state root label; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi
log 'E: two live operations (the paired cross-op stand)'
# Harvest completeness: disable every dontaudit rule (ours and the base
# policy's) so NO denial can hide from the leg harvests; re-enabled at
# teardown. Guest-only, evidence-driven harvest hygiene.
semanage dontaudit off >>"$EVIDENCE_DIR/te-dontaudit-off.log" 2>&1 || true
OPA="$(gen_op_id)"
OPB="$(gen_op_id)"
RA_SOCK="$RUNTIME_ROOT/ops/$OPA/buildkitd.sock"
RB_SOCK="$RUNTIME_ROOT/ops/$OPB/buildkitd.sock"
SA="$STATE_ROOT/ops/$OPA"
SB="$STATE_ROOT/ops/$OPB"
HV_EPOCH="$(date +%s)"
POISON_RAW="P5S2-G29-POISON-$HV_EPOCH"
POISON_FULL="$(printf '%-48s' "$POISON_RAW" | tr ' ' '-')"
start_op() { # opid — one manager RPC, appended to e-start-ops.txt
  set +e
  printf 'START %s\n' "$1" | timeout 120 socat - UNIX-CONNECT:"$MANAGER_SOCK" >> "$EVIDENCE_DIR/e-start-ops.txt" 2>&1
  echo "socat rc: $?" >> "$EVIDENCE_DIR/e-start-ops.txt"
  set -e
}
{
  echo "=== P5-S2g29: the paired cross-operation state/cache poisoning proof ==="
  echo "op A: $OPA (the mutating side; a REAL manager operation; its flow"
  echo "      domain is docker_helper_rootlesskit_t, uncategorized :s0 like"
  echo "      every live op's flow; the mutation is performed by a"
  echo "      rootlesskit_t:s0:c1 vehicle — the G28-established instrument"
  echo "      for A's flow domain, byte-identical TE authority)"
  echo "op B: $OPB (the consuming side; the deterministic build)"
  echo "dontaudit rules disabled for the experiment window (semanage dontaudit off)"
  echo "the candidate payload module v12 is loaded UNCHANGED; NO new grants;"
  echo "the mutation legs use ONLY the already-proven candidate-policy"
  echo "surface (rootlesskit_t -> docker_helper_builder_state_t, the G27"
  echo "write-link) with production-like access; no root write performs a"
  echo "measured mutation."
  echo "=== manager RPC: START $OPA ==="
} > "$EVIDENCE_DIR/e-start-ops.txt"
start_op "$OPA"
sleep 2
{
  echo "=== manager RPC: START $OPB ==="
} >> "$EVIDENCE_DIR/e-start-ops.txt"
start_op "$OPB"
sleep 4
OPS_WAIT=0
until { [ -S "$RA_SOCK" ] && [ -S "$RB_SOCK" ]; } || [ "$OPS_WAIT" -ge 60 ]; do
  sleep 2
  OPS_WAIT=$((OPS_WAIT + 1))
done
if ! [ -S "$RA_SOCK" ] || ! [ -S "$RB_SOCK" ]; then
  note "the two operations did not reach readiness; the experiment cannot proceed"
  {
    echo "opA socket: $(stat -c '%C %U:%G %a' "$RA_SOCK" 2>&1)"
    echo "opB socket: $(stat -c '%C %U:%G %a' "$RB_SOCK" 2>&1)"
    ls -la "$RUNTIME_ROOT/ops" 2>&1 || true
    ls -la "$STATE_ROOT/ops" 2>&1 || true
    journalctl -u "$UNIT" --since "@$HV_EPOCH" --no-pager 2>/dev/null | tail -80 || true
  } > "$EVIDENCE_DIR/stand-failure-two-ops.txt" 2>&1
  printf '%s P5S2-STATE-POISON-RESULT=INCOMPLETE (two-op readiness failed; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi
{
  echo "=== the process tree of the two live operations ==="
  for pat in 'rootlesskit --net=' 'buildkitd --rootless' 'slirp4netns'; do
    for p in $(pgrep -f "$pat" 2>/dev/null); do
      echo "pid $p ($(cat "/proc/$p/comm" 2>/dev/null)): $(tr -d '\0' < "/proc/$p/attr/current" 2>/dev/null || true)"
      echo "  op (from --root=): $(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -o -- '--root=[^ ]*' || true)"
      echo "  uid_map: $(tr '\n' ';' < "/proc/$p/uid_map" 2>/dev/null || true)"
      echo "  cgroup: $(cat "/proc/$p/cgroup" 2>/dev/null | head -1 || true)"
    done
  done
  echo "=== per-op tree labels ==="
  stat -c '%C %U:%G %a %n' "$SA" "$SA/root" "$SB" "$SB/root" \
    "$RA_SOCK" "$RB_SOCK" 2>&1 || true
} > "$EVIDENCE_DIR/e-processes.txt" 2>&1
cat "$EVIDENCE_DIR/e-processes.txt" >&2

# The deterministic build context (the P4A1 pattern; NO Docker Engine).
# The context files are labeled system_u:docker_helper_builder_state_t
# BEFORE any build (the G28 composition: the loaded policy constrains
# file/dir relabelto with (u1 == u2 or t1 == can_change_object_identity),
# and buildkitd's xattr-preserving local-context copy relabels the
# snapshot copies to the source's label, so the state_t-labeled sources
# keep the snapshot tree uniform and the manager's mandatory op cleanup
# converges).
#
# ONE context dir, ONE Dockerfile, rewritten per leg with a leg nonce:
# the Part B baseline pair uses the SAME nonce-0 Dockerfile twice (the
# repeat cache-hits the RUN and re-exports the cached result — the
# determinism + stability record); the CONSUME builds rewrite the nonce
# (the RUN vertex becomes a cache MISS — a fresh runc execution that
# READS op B's live FROM-snapshot state) while the FROM vertex stays a
# cache HIT over the same live snapshot chain the mutation legs target.
CTX="$WORK/ctx"
mkdir -p "$CTX"
write_consume_dockerfile() { # nonce — rewrites the Dockerfile (label persists)
  cat > "$CTX/Dockerfile" <<EOF
FROM alpine:3.20
RUN mkdir -p /m2 && echo p5s2-g29-nonce-$1 > /m2/nonce.txt && id > /m2/id.txt && echo p5s2-g29-marker2 > /m2/marker.txt && cat /proc/self/uid_map > /m2/uid_map.txt
EOF
}
write_consume_dockerfile 0
chcon -u system_u -t docker_helper_builder_state_t "$CTX" "$CTX/Dockerfile"
{
  echo "=== the context files' labels after the system_u/state_t chcon ==="
  stat -c '%C %U:%G %n' "$CTX" "$CTX/Dockerfile" 2>&1
  echo "=== the build input (leg nonce 0; identical for the Part B pair) ==="
  sha256sum "$CTX/Dockerfile"
  cat "$CTX/Dockerfile"
} > "$EVIDENCE_DIR/e-ctx-labels.txt" 2>&1
cat "$EVIDENCE_DIR/e-ctx-labels.txt" >&2
mkdir -p "$WORK/docker-config" "$WORK/export" "$WORK/reports" "$WORK/backup" "$WORK/tools" "$WORK/probe"
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

# The analysis tools (guest-only stand fixtures).
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
cat > "$WORK/tools/classify_leg.py" <<'PYEOF'
import json, sys
base, rep, kind, poison, out = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
hexd = sys.argv[6] if len(sys.argv) > 6 else ''
b, r = json.load(open(base)), json.load(open(rep))
pb = poison.encode() if poison else b''
changed, poison_in = [], []
for n in sorted(set(r['by_name']) | set(b['by_name'])):
    mb, mr = b['by_name'].get(n), r['by_name'].get(n)
    if mb and mr:
        if mb['sha256'] != mr['sha256']:
            changed.append(n)
        if pb and mr.get('poison_at', -1) >= 0:
            poison_in.append(n)
    else:
        changed.append(n + ' (only-in-one-leg)')
# the marker observable is the CONTENT VALUES only (mtime-immune, and
# immune to an inner-tar parse error on a poisoned layer)
def mcontents(rep):
    return sorted(m['content'] for m in rep.get('marker', []) if 'content' in m)
def idcontents(rep):
    return sorted(m['content'] for m in rep.get('marker', [])
                  if 'content' in m and m['name'].lstrip('./').endswith('id.txt'))
mc_b, mc_r = mcontents(b), mcontents(r)
marker_changed = mc_b != mc_r
id_changed = idcontents(b) != idcontents(r)
if kind == 'snapshot-data':
    # the nonce difference is BY DESIGN (the cache-miss mechanism) and is
    # NOT a signal; the poison observable is the RUN's own id.txt output
    # (uid 0's passwd-derived name) or the poison bytes themselves
    relevant = 'CHANGED' if (id_changed or poison_in) else 'UNCHANGED'
elif kind == 'snapshot-marker':
    relevant = 'CHANGED' if (marker_changed or poison_in) else 'UNCHANGED'
else:
    rn = 'blobs/sha256/' + hexd
    relevant = 'CHANGED' if (rn in changed or rn in poison_in) else 'UNCHANGED'
lines = ['CHANGED_MEMBERS=%s' % changed, 'POISON_FOUND_IN=%s' % poison_in,
         'MARKER_CONTENT_BEFORE=%s' % mc_b, 'MARKER_CONTENT_AFTER=%s' % mc_r,
         'MARKER_CONTENT_CHANGED=%s' % marker_changed,
         'ID_CONTENT_BEFORE=%s' % idcontents(b), 'ID_CONTENT_AFTER=%s' % idcontents(r),
         'ID_CONTENT_CHANGED=%s' % id_changed,
         'RELEVANT=%s' % relevant]
open(out, 'w').write('\n'.join(lines) + '\n')
print('CLASSIFY CHANGED=%d POISON=%d MARKERCHG=%d RELEVANT=%s' % (1 if changed else 0, 1 if poison_in else 0, 1 if marker_changed else 0, relevant))
PYEOF
{
  echo "=== the analysis tools (guest-only stand fixtures) ==="
  for t in tar_report.py state_inventory.py classify_leg.py; do
    echo "--- $t ---"; cat "$WORK/tools/$t"
  done
} > "$EVIDENCE_DIR/e-tools.txt" 2>&1

log 'F: op A builds first (A is a genuine live builder operation)'
write_consume_dockerfile 0
{
  echo "=== op A's baseline build (buildctl -> $RA_SOCK, the consume shape) ==="
} > "$EVIDENCE_DIR/e-build-a.txt"
set +e
do_build "$RA_SOCK" "$WORK/export/out-a.tar" "$EVIDENCE_DIR/e-build-a.txt" "$CTX"
A_BUILD_RC=$BUILD_RC
set -e
echo "op A build rc: $A_BUILD_RC" >&2
python3 "$WORK/tools/tar_report.py" "$WORK/export/out-a.tar" "$WORK/reports/a.json" "" \
  > "$EVIDENCE_DIR/e-build-a-report.txt" 2>&1 || true

log 'G: Part B baseline — op B build 1 (the deterministic marker build)'
{
  echo "=== op B baseline build 1 (buildctl -> $RB_SOCK, nonce 0; COLD: the pull + the fresh RUN) ==="
} > "$EVIDENCE_DIR/b1-build.txt"
set +e
do_build "$RB_SOCK" "$WORK/export/out-b1.tar" "$EVIDENCE_DIR/b1-build.txt" "$CTX"
B1_RC=$BUILD_RC
set -e
echo "op B build 1 rc: $B1_RC" >&2
python3 "$WORK/tools/tar_report.py" "$WORK/export/out-b1.tar" "$WORK/reports/b1.json" "" \
  > "$EVIDENCE_DIR/b1-report-run.txt" 2>&1 || true
if [ "$B1_RC" != 0 ] || [ ! -s "$WORK/export/out-b1.tar" ]; then
  note "op B's baseline build 1 failed; the experiment cannot proceed"
  printf '%s P5S2-STATE-POISON-RESULT=INCOMPLETE (baseline build failed; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi

log 'H: Part A — the state-tree inventory (both live operations) + digest association'
python3 "$WORK/tools/state_inventory.py" "$SB/root" "$WORK/reports/inv-B.json" 2>"$EVIDENCE_DIR/h-inventory.err" || true
python3 "$WORK/tools/state_inventory.py" "$SA/root" "$WORK/reports/inv-A.json" >>"$EVIDENCE_DIR/h-inventory.err" 2>&1 || true
{
  echo "=== op B's state tree AFTER its baseline build (buildkitd B still running) ==="
  echo "--- top-level layout ---"
  ls -la "$SB/root" 2>&1 || true
  echo "--- the digest-bearing content objects found in the tree ---"
  find "$SB/root" -type f -path '*sha256*' 2>/dev/null | while read -r f; do
    echo "$f $(stat -c '%C %U:%G %a %s' "$f" 2>&1) sha=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
  done
  echo "--- every state-tree file label is builder_state_t (tree uniformity) ---"
  python3 -c '
import json, sys
inv = json.load(open(sys.argv[1]))
labels = sorted(set(f["scontext"] for f in inv["files"]))
print("distinct scontexts:", labels)
print("uniform builder_state_t:", all("docker_helper_builder_state_t" in l for l in labels))
' "$WORK/reports/inv-B.json" 2>&1 || true
  echo "=== op A's state tree (informational: A holds its own copy of the same digests) ==="
  find "$SA/root" -type f -path '*sha256*' 2>/dev/null | while read -r f; do
    echo "$f $(stat -c '%C %U:%G %a %s' "$f" 2>&1) sha=$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
  done
} > "$EVIDENCE_DIR/h-inventory.txt" 2>&1
cat "$EVIDENCE_DIR/h-inventory.txt" >&2

# Digest association: B's own export names the layer/config digests; the
# state tree holds the ingested/materialized content objects under those
# digests. The association (manifest digest -> state-tree path) is what
# ties the chosen object to a specific input/result. The snapshot-side
# candidates: the FROM snapshot's /etc/passwd (consumed by the RUN's own
# execution — `id` resolves the uid name from it — and NOT integrity-
# verified: unpacked filesystem files carry no digest checks) and the RUN
# snapshot's own marker file (the run-1 candidate, whose D4 covered only
# the cache-hit export path).
L_CONFIG_HEX="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("config","").split("/")[-1])' "$WORK/reports/b1.json" 2>/dev/null || true)"
L1_HEX="$(python3 -c 'import json,sys;ls=json.load(open(sys.argv[1])).get("layers",[]);print(ls[0].split("/")[-1] if len(ls)>0 else "")' "$WORK/reports/b1.json" 2>/dev/null || true)"
L2_HEX="$(python3 -c 'import json,sys;ls=json.load(open(sys.argv[1])).get("layers",[]);print(ls[1].split("/")[-1] if len(ls)>1 else "")' "$WORK/reports/b1.json" 2>/dev/null || true)"
BLOB_L1="$(find "$SB/root" -type f -name "$L1_HEX" 2>/dev/null | head -1 || true)"
BLOB_L2="$(find "$SB/root" -type f -name "$L2_HEX" 2>/dev/null | head -1 || true)"
SNAPPASSWD="$(find "$SB/root/runc-overlayfs/snapshots" -type f -path '*/fs/etc/passwd' 2>/dev/null | head -1 || true)"
SNAPMARK="$(find "$SB/root" -type f -path '*/m2/marker.txt' 2>/dev/null | head -1 || true)"
{
  echo "=== the digest association (manifest digest -> state-tree object) ==="
  echo "config digest:     sha256:$L_CONFIG_HEX"
  echo "layer 1 (FROM):    sha256:$L1_HEX  -> ${BLOB_L1:-NOT-FOUND-IN-TREE}"
  echo "layer 2 (RUN):     sha256:$L2_HEX  -> ${BLOB_L2:-NOT-FOUND-IN-TREE}"
  echo "FROM-snapshot /etc/passwd (consumed by every fresh RUN execution; unverified): ${SNAPPASSWD:-NOT-FOUND}"
  [ -n "$SNAPPASSWD" ] && echo "  passwd file: $(stat -c '%C %U:%G %a %s' "$SNAPPASSWD" 2>&1) sha=$(sha256sum "$SNAPPASSWD" | awk '{print $1}')"
  [ -n "$SNAPPASSWD" ] && echo "  passwd content:" && cat "$SNAPPASSWD"
  echo "RUN-snapshot marker file (the run-1 candidate): ${SNAPMARK:-NOT-FOUND}"
  [ -n "$BLOB_L1" ] && echo "  blob 1 store invariant (content sha == digest name): $(sha256sum "$BLOB_L1" | awk '{print $1}')"
  [ -n "$BLOB_L2" ] && echo "  blob 2 store invariant (content sha == digest name): $(sha256sum "$BLOB_L2" | awk '{print $1}')"
} > "$EVIDENCE_DIR/h-digest-association.txt" 2>&1
cat "$EVIDENCE_DIR/h-digest-association.txt" >&2

log 'I: the stand probe vehicle + assignment gate (the mutation instruments)'
# The probe vehicle and the probe module follow the G28 stand shapes
# (stand fixtures only; the legs use ONLY the candidate policy's already-
# proven rootlesskit_t -> builder_state_t surface; the probe module grants
# NOTHING to the flow/payload domains beyond what the candidate module
# already carries). map_probe gains one mode for G29: --poison PATH OFFSET
# MARKER (open O_WRONLY, pwrite at the offset, fsync, read-back).
cat > "$WORK/probe/map_probe.c" <<'PROBEOF'
/* P5-S2g29 stand probe vehicle (guest-only fixture; the G28 vehicle plus
 * the --poison mode). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/socket.h>
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

RK_C1='system_u:system_r:docker_helper_rootlesskit_t:s0:c1'
RK_C2='system_u:system_r:docker_helper_rootlesskit_t:s0:c2'
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
  note "OBSTACLE: the required MCS categories are not assignable (see i-assignment.txt); the mutation legs cannot proceed"
  printf '%s P5S2-STATE-POISON-RESULT=INCOMPLETE (assignment failed; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi

log 'J: Part B — op B build 2 (the no-mutation repeat: stability + consumption-path identity)'
{
  echo "=== op B baseline build 2 (IDENTICAL input, NO mutation between builds) ==="
} > "$EVIDENCE_DIR/b2-build.txt"
set +e
do_build "$RB_SOCK" "$WORK/export/out-b2.tar" "$EVIDENCE_DIR/b2-build.txt" "$CTX"
B2_RC=$BUILD_RC
set -e
echo "op B build 2 rc: $B2_RC" >&2
python3 "$WORK/tools/tar_report.py" "$WORK/export/out-b2.tar" "$WORK/reports/b2.json" "" \
  > "$EVIDENCE_DIR/b2-report-run.txt" 2>&1 || true
# The identity check: the exported layer member's BYTES vs the state-tree
# blob's bytes. Equal = B's export consumed that exact object verbatim
# (the poisoning candidate's consumer path, proven without any mutation).
python3 - "$WORK/reports/b2.json" "$BLOB_L1" "$L1_HEX" "$BLOB_L2" "$L2_HEX" \
  > "$EVIDENCE_DIR/h-identity-checks.txt" <<'PYEOF'
import json, hashlib, sys, os
rep = json.load(open(sys.argv[1]))
b1, l1, b2, l2 = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
def member_sha(name):
    m = rep['by_name'].get(name)
    return m['sha256'] if m else None
def file_sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()
n1, n2 = 'blobs/sha256/' + l1, 'blobs/sha256/' + l2
print('EXPORT_MEMBER %s sha=%s' % (n1, member_sha(n1)))
print('EXPORT_MEMBER %s sha=%s' % (n2, member_sha(n2)))
if b1:
    print('TREE_BLOB1 %s sha=%s size-match=%s' % (b1, file_sha(b1),
          rep['by_name'][n1]['size'] == os.lstat(b1).st_size))
    print('IDENTITY1_BLOB_CONSUMED=%s' % (member_sha(n1) == file_sha(b1)))
else:
    print('IDENTITY1_BLOB_CONSUMED=NO-BLOB-IN-TREE')
if b2:
    print('TREE_BLOB2 %s sha=%s size-match=%s' % (b2, file_sha(b2),
          rep['by_name'][n2]['size'] == os.lstat(b2).st_size))
    print('IDENTITY2_BLOB_CONSUMED=%s' % (member_sha(n2) == file_sha(b2)))
else:
    print('IDENTITY2_BLOB_CONSUMED=NO-BLOB-IN-TREE')
PYEOF
cat "$EVIDENCE_DIR/h-identity-checks.txt" >&2
# Baseline stability (build 1 vs build 2, no mutation between them).
# The content observables are mtime-immune: the marker CONTENT values and
# the exported manifest; the per-member sha table is the detailed record
# (a re-diffed layer's tar headers would carry fresh mtimes).
python3 - "$WORK/reports/b1.json" "$WORK/reports/b2.json" > "$EVIDENCE_DIR/b-baseline-compare.txt" <<'PYEOF'
import json, sys
a, b = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
na, nb = a['by_name'], b['by_name']
lines = []
for n in sorted(set(na) | set(nb)):
    if n not in na or n not in nb:
        lines.append('%s MISSING-IN-ONE' % n)
    elif na[n]['sha256'] != nb[n]['sha256']:
        lines.append('%s sha DIFFERS (%s vs %s)' % (n, na[n]['sha256'][:16], nb[n]['sha256'][:16]))
    else:
        lines.append('%s sha equal' % n)
def mcontents(rep):
    return sorted(m['content'] for m in rep.get('marker', []) if 'content' in m)
mc_a, mc_b = mcontents(a), mcontents(b)
marker_equal = mc_a == mc_b
manifest_equal = a.get('manifest_raw_sha256') == b.get('manifest_raw_sha256')
lines.append('manifest_equal=%s' % manifest_equal)
lines.append('marker_contents_equal=%s (content=%s)' % (marker_equal, mc_a))
lines.append('BASELINE_STABLE=%s' % ('YES' if marker_equal and manifest_equal else 'NO'))
print('\n'.join(lines))
PYEOF
BASELINE_STABLE="$(grep -o 'BASELINE_STABLE=[A-Z]*' "$EVIDENCE_DIR/b-baseline-compare.txt" | cut -d= -f2 || true)"
cat "$EVIDENCE_DIR/b-baseline-compare.txt" >&2
echo "baseline stable: $BASELINE_STABLE" >&2

# Target selection for THIS run (the measured state so far: run 1
# measured the cache-hit export path — the export consumes ONLY the
# digest-named content blobs (both identity checks True) and the RUN
# snapshot marker's mutation was invisible to it (D4); run 2 measured
# the blob candidate through the granted setattr authority (the owner
# chmod dance inside the vehicle): the mutation landed and the export
# DETECTED it (fail-closed D3). The remaining justified candidate is
# the OTHER consumption path of the writable snapshot files: the RUN's
# fresh execution reads op B's live FROM-snapshot files inside the
# container — /etc/passwd is consumed by the RUN's own `id` (unpacked
# filesystem files carry NO digest checks). The consume builds use the
# leg-nonce Dockerfile (the RUN is a fresh cache-missed execution; the
# FROM stays a cache hit over the same live snapshot chain).
TARGET_KIND=""
TARGET_PATH=""
TARGET_HEX=""
if [ -n "$SNAPPASSWD" ]; then
  TARGET_KIND="snapshot-data"; TARGET_PATH="$SNAPPASSWD"; TARGET_HEX=""
elif [ -n "$BLOB_L1" ] && grep -q 'IDENTITY1_BLOB_CONSUMED=True' "$EVIDENCE_DIR/h-identity-checks.txt"; then
  TARGET_KIND="blob-l1"; TARGET_PATH="$BLOB_L1"; TARGET_HEX="$L1_HEX"
elif [ -n "$BLOB_L2" ] && grep -q 'IDENTITY2_BLOB_CONSUMED=True' "$EVIDENCE_DIR/h-identity-checks.txt"; then
  TARGET_KIND="blob-l2"; TARGET_PATH="$BLOB_L2"; TARGET_HEX="$L2_HEX"
elif [ -n "$BLOB_L1" ]; then
  TARGET_KIND="blob-l1-unverified"; TARGET_PATH="$BLOB_L1"; TARGET_HEX="$L1_HEX"
elif [ -n "$BLOB_L2" ]; then
  TARGET_KIND="blob-l2-unverified"; TARGET_PATH="$BLOB_L2"; TARGET_HEX="$L2_HEX"
elif [ -n "$SNAPMARK" ]; then
  TARGET_KIND="snapshot-marker"; TARGET_PATH="$SNAPMARK"; TARGET_HEX="$L2_HEX"
else
  note "no justified poisoning candidate exists in the inventory; the experiment cannot proceed"
  printf '%s P5S2-STATE-POISON-RESULT=INCOMPLETE (no candidate; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi
TARGET_SIZE="$(stat -c '%s' "$TARGET_PATH" 2>/dev/null || echo 0)"
case "$TARGET_KIND" in
  snapshot-data)
    POISON_USE="g29p"; OFFSET_USE=0 ;;
  snapshot-marker)
    POISON_USE="$(printf '%s' "$POISON_FULL" | head -c "$TARGET_SIZE")"; OFFSET_USE=0 ;;
  *)
    if [ "$TARGET_SIZE" -gt 2097152 ]; then OFFSET_USE=1048576; else OFFSET_USE=$((TARGET_SIZE / 2)); fi
    POISON_USE="$POISON_FULL" ;;
esac
BASELINE_TARGET_SHA="$(sha256sum "$TARGET_PATH" | awk '{print $1}')"
cp -a "$TARGET_PATH" "$WORK/backup/target.baseline"
BACKUP_SHA="$(sha256sum "$WORK/backup/target.baseline" | awk '{print $1}')"
{
  echo "=== the chosen poisoning target (Part A selection) ==="
  echo "kind: $TARGET_KIND"
  echo "exact path: $TARGET_PATH"
  echo "SELinux label: $(stat -c '%C' "$TARGET_PATH" 2>&1)"
  echo "owner/mode/size: $(stat -c '%U:%G %a %s' "$TARGET_PATH" 2>&1)"
  echo "digest (logical identity): sha256:$TARGET_HEX"
  echo "file content sha256: $BASELINE_TARGET_SHA"
  case "$TARGET_KIND" in
    snapshot-data)
      echo "produced by: the FROM alpine:3.20 layer unpacked into the FROM snapshot (the snapshotter's extracted filesystem)"
      echo "consumed by: every FRESH RUN execution of op B (the RUN's runc container mounts the live FROM snapshot as its rootfs base; the RUN's \`id\` resolves uid 0's name from /etc/passwd; unpacked snapshot files carry NO digest verification — the identity checks above prove the EXPORT path consumes only the content blobs, which leaves the RUN-execution path as the unmeasured consumption surface)"
      echo "poison effect claimed: the RUN's id.txt output would name uid 0 as 'g29p' — A's data inside B's trusted consumption path" ;;
    snapshot-marker)
      echo "produced by: the RUN step (the runc container wrote /m2/marker.txt into its snapshot)"
      echo "consumed by: NOT the cache-hit export (run 1's D4); measured here for the completeness of the snapshot class" ;;
    *)
      echo "produced by: the FROM alpine:3.20 pull ingested this layer blob into the content store (input-tied)"
      echo "consumed by: B's export of every subsequent rebuild (the identity check proves the exported layer member's bytes equal this object's bytes); run 2 measured this class: the export verifies the digest at the consumption point and fails closed (D3)" ;;
  esac
  echo "backup saved: $WORK/backup/target.baseline sha=$BACKUP_SHA (harness read; the restore between legs is the only root write on the target and is recorded)"
  echo "poison payload: $POISON_USE"
  echo "poison offset: $OFFSET_USE"
} > "$EVIDENCE_DIR/h-target-selection.txt" 2>&1
cat "$EVIDENCE_DIR/h-target-selection.txt" >&2

log 'K: the pre-mutation consume baseline (a fresh RUN over the LIVE state)'
CONSUME_LEG=1
write_consume_dockerfile "$CONSUME_LEG"
{
  echo "=== op B consume-baseline build (nonce $CONSUME_LEG; a FRESH RUN execution pre-mutation) ==="
} > "$EVIDENCE_DIR/b3-build.txt"
set +e
do_build "$RB_SOCK" "$WORK/export/out-b3.tar" "$EVIDENCE_DIR/b3-build.txt" "$CTX"
B3_RC=$BUILD_RC
set -e
echo "op B consume-baseline rc: $B3_RC" >&2
python3 "$WORK/tools/tar_report.py" "$WORK/export/out-b3.tar" "$WORK/reports/b3.json" "" \
  > "$EVIDENCE_DIR/b3-report-run.txt" 2>&1 || true
if [ "$B3_RC" != 0 ] || [ ! -s "$WORK/export/out-b3.tar" ]; then
  note "the consume-baseline build failed; the experiment cannot proceed"
  printf '%s P5S2-STATE-POISON-RESULT=INCOMPLETE (consume baseline failed; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi
cp "$WORK/reports/b3.json" "$WORK/reports/baseline-id.json"

# measure_candidate KIND PATH HEX POISON OFFSET LOGPREFIX
# One paired measurement round on ONE object: cross-op mutation (A's c1
# vehicle) -> consumption build -> classification; harness restore; the
# post-restore stability build; the own-op mutation (B's c2 vehicle) ->
# consumption build -> classification; restore. No other object is
# touched; B is never stopped; the classification compares against the
# no-mutation baseline report.
measure_candidate() { # $1=kind $2=path $3=hex $4=poison $5=offset $6=logprefix
  local KIND="$1" TPATH="$2" THEX="$3" PST="$4" OFF="$5" LP="$6"
  {
    echo "=== the cross-op mutation (Part C): A's category -> the ONE chosen object of op B ==="
    echo "writer: runuser $BUILDER_USER -> runcon $RK_C1 -> map_probe --poison (the instrument for A's flow domain)"
    echo "target: $TPATH (kind $KIND)"
    echo "before: $(sha256sum "$TPATH" 2>&1)"
    echo "before label/owner/mode/size: $(stat -c '%C %U:%G %a %s' "$TPATH" 2>&1)"
  } > "$EVIDENCE_DIR/$LP-cross-mutation.txt"
  MUT_EPOCH="$(date +%s)"
  set +e
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_C1" /usr/local/bin/map_probe \
    --poison "$TPATH" "$OFF" "$PST" >> "$EVIDENCE_DIR/$LP-cross-mutation.txt" 2>&1 < /dev/null
  CROSS_WRITE_RC=$?
  set -e
  {
    echo "cross-op pwrite vehicle rc: $CROSS_WRITE_RC"
    echo "after: $(sha256sum "$TPATH" 2>&1)"
    echo "after label/owner/mode/size: $(stat -c '%C %U:%G %a %s' "$TPATH" 2>&1)"
    echo "tcontext (the mutated object of op B): $(stat -c '%C' "$TPATH" 2>&1)"
    echo "baseline-digest-differs: $([ "$(sha256sum "$TPATH" | awk '{print $1}')" != "$BASELINE_TARGET_SHA" ] && echo yes || echo no)"
  } >> "$EVIDENCE_DIR/$LP-cross-mutation.txt"
  harvest_avcs_since "$MUT_EPOCH" "$EVIDENCE_DIR/$LP-cross-mutation-avcs.txt"
  echo "cross-op mutation AVC window (an allowed write shows no denial; dontaudit is off)" >> "$EVIDENCE_DIR/$LP-cross-mutation.txt"
  DENIALS="$(grep -a 'avc:.*denied' "$EVIDENCE_DIR/$LP-cross-mutation-avcs.txt" 2>/dev/null | wc -l || true)"
  echo "denial-record-count in the mutation window: ${DENIALS:-0}" >> "$EVIDENCE_DIR/$LP-cross-mutation.txt"
  cat "$EVIDENCE_DIR/$LP-cross-mutation.txt" >&2
  # Part D: the consumption proof (B rebuilds; the RUN is a fresh
  # cache-missed execution over the LIVE snapshot state; the FROM stays a
  # cache hit over the same snapshot chain).
  CONSUME_LEG=$((CONSUME_LEG + 1))
  write_consume_dockerfile "$CONSUME_LEG"
  echo "consume leg nonce: $CONSUME_LEG (the RUN's fresh cache-missed execution)" >> "$EVIDENCE_DIR/$LP-cross-mutation.txt"
  {
    echo "=== the consumption build (Part D): B rebuilds after the cross-op mutation ==="
  } > "$EVIDENCE_DIR/$LP-build3.txt"
  set +e
  do_build "$RB_SOCK" "$WORK/export/out-$LP-3.tar" "$EVIDENCE_DIR/$LP-build3.txt" "$CTX"
  CROSS_BUILD_RC=$BUILD_RC
  set -e
  echo "cross-op consumption build rc: $CROSS_BUILD_RC" >&2
  python3 "$WORK/tools/tar_report.py" "$WORK/export/out-$LP-3.tar" "$WORK/reports/$LP-3.json" "$PST" \
    > "$EVIDENCE_DIR/$LP-3-report-run.txt" 2>&1 || true
  python3 "$WORK/tools/classify_leg.py" "$WORK/reports/baseline-id.json" "$WORK/reports/$LP-3.json" \
    "$KIND" "$PST" "$EVIDENCE_DIR/$LP-cross-compare.txt" "$THEX" \
    > "$EVIDENCE_DIR/$LP-cross-compare-run.txt" 2>&1 || true
  cat "$EVIDENCE_DIR/$LP-cross-compare.txt" >&2
  CROSS_RELEVANT="$(grep -o 'RELEVANT=[A-Z]*' "$EVIDENCE_DIR/$LP-cross-compare.txt" | cut -d= -f2 || true)"
  CROSS_POISON_ANY="$(grep -o 'POISON=[01]' "$EVIDENCE_DIR/$LP-cross-compare-run.txt" | cut -d= -f2 || true)"
  if [ "$CROSS_WRITE_RC" != 0 ]; then
    # the mutation did NOT land (read-back/digest never proven) — this is
    # not D4; the task's D-outcomes presuppose a confirmed mutation
    ROUND_CROSS_OUTCOME="MUTATION-BLOCKED"
  elif [ "$CROSS_BUILD_RC" = 0 ]; then
    if [ "$CROSS_RELEVANT" = "CHANGED" ] || [ "$CROSS_POISON_ANY" = "1" ]; then
      ROUND_CROSS_OUTCOME="POISONED-OUTPUT"
    else
      ROUND_CROSS_OUTCOME="D4-IGNORED"
    fi
  else
    ROUND_CROSS_OUTCOME="D3-FAILCLOSED"
  fi
  # harness restore + post-restore stability (inter-leg hygiene; B idle)
  {
    echo "=== the harness restore between legs (recorded; B idle; NOT a measured mutation) ==="
    cp -a "$WORK/backup/target.baseline" "$TPATH"
    echo "restored: $(sha256sum "$TPATH" 2>&1)"
    echo "restore digest matches the baseline: $([ "$(sha256sum "$TPATH" | awk '{print $1}')" = "$BASELINE_TARGET_SHA" ] && echo yes || echo no)"
  } > "$EVIDENCE_DIR/$LP-restore.txt"
  cat "$EVIDENCE_DIR/$LP-restore.txt" >&2
  CONSUME_LEG=$((CONSUME_LEG + 1))
  write_consume_dockerfile "$CONSUME_LEG"
  {
    echo "=== the post-restore stability build (the restored state re-baselined; nonce $CONSUME_LEG) ==="
  } > "$EVIDENCE_DIR/$LP-build3b.txt"
  set +e
  do_build "$RB_SOCK" "$WORK/export/out-$LP-3b.tar" "$EVIDENCE_DIR/$LP-build3b.txt" "$CTX"
  RESTORE_BUILD_RC=$BUILD_RC
  set -e
  echo "post-restore build rc: $RESTORE_BUILD_RC" >&2
  python3 "$WORK/tools/tar_report.py" "$WORK/export/out-$LP-3b.tar" "$WORK/reports/$LP-3b.json" "$PST" \
    > "$EVIDENCE_DIR/$LP-3b-report-run.txt" 2>&1 || true
  python3 "$WORK/tools/classify_leg.py" "$WORK/reports/baseline-id.json" "$WORK/reports/$LP-3b.json" \
    "$KIND" "$PST" "$EVIDENCE_DIR/$LP-restore-compare.txt" "$THEX" \
    > "$EVIDENCE_DIR/$LP-restore-compare-run.txt" 2>&1 || true
  # the own-op control (Part E): B's OWN category, the SAME object, the SAME method
  {
    echo "=== the own-op mutation (Part E): B's own category -> the same object, the same method ==="
    echo "writer: runuser $BUILDER_USER -> runcon $RK_C2 -> map_probe --poison"
    echo "before: $(sha256sum "$TPATH" 2>&1)"
  } > "$EVIDENCE_DIR/$LP-own-mutation.txt"
  OWNMUT_EPOCH="$(date +%s)"
  set +e
  timeout 90 runuser -u "$BUILDER_USER" -- runcon "$RK_C2" /usr/local/bin/map_probe \
    --poison "$TPATH" "$OFF" "$PST" >> "$EVIDENCE_DIR/$LP-own-mutation.txt" 2>&1 < /dev/null
  OWN_WRITE_RC=$?
  set -e
  {
    echo "own-op pwrite vehicle rc: $OWN_WRITE_RC"
    echo "after: $(sha256sum "$TPATH" 2>&1)"
  } >> "$EVIDENCE_DIR/$LP-own-mutation.txt"
  harvest_avcs_since "$OWNMUT_EPOCH" "$EVIDENCE_DIR/$LP-own-mutation-avcs.txt"
  cat "$EVIDENCE_DIR/$LP-own-mutation.txt" >&2
  CONSUME_LEG=$((CONSUME_LEG + 1))
  write_consume_dockerfile "$CONSUME_LEG"
  {
    echo "=== the own-op consumption build (nonce $CONSUME_LEG) ==="
  } > "$EVIDENCE_DIR/$LP-build4.txt"
  set +e
  do_build "$RB_SOCK" "$WORK/export/out-$LP-4.tar" "$EVIDENCE_DIR/$LP-build4.txt" "$CTX"
  OWN_BUILD_RC=$BUILD_RC
  set -e
  echo "own-op consumption build rc: $OWN_BUILD_RC" >&2
  python3 "$WORK/tools/tar_report.py" "$WORK/export/out-$LP-4.tar" "$WORK/reports/$LP-4.json" "$PST" \
    > "$EVIDENCE_DIR/$LP-4-report-run.txt" 2>&1 || true
  python3 "$WORK/tools/classify_leg.py" "$WORK/reports/baseline-id.json" "$WORK/reports/$LP-4.json" \
    "$KIND" "$PST" "$EVIDENCE_DIR/$LP-own-compare.txt" "$THEX" \
    > "$EVIDENCE_DIR/$LP-own-compare-run.txt" 2>&1 || true
  cat "$EVIDENCE_DIR/$LP-own-compare.txt" >&2
  OWN_RELEVANT="$(grep -o 'RELEVANT=[A-Z]*' "$EVIDENCE_DIR/$LP-own-compare.txt" | cut -d= -f2 || true)"
  OWN_POISON_ANY="$(grep -o 'POISON=[01]' "$EVIDENCE_DIR/$LP-own-compare-run.txt" | cut -d= -f2 || true)"
  if [ "$OWN_WRITE_RC" != 0 ]; then
    ROUND_OWN_OUTCOME="MUTATION-BLOCKED"
  elif [ "$OWN_BUILD_RC" = 0 ]; then
    if [ "$OWN_RELEVANT" = "CHANGED" ] || [ "$OWN_POISON_ANY" = "1" ]; then
      ROUND_OWN_OUTCOME="POISONED-OUTPUT"
    else
      ROUND_OWN_OUTCOME="D4-IGNORED"
    fi
  else
    ROUND_OWN_OUTCOME="D3-FAILCLOSED"
  fi
  # restore again for a clean next round
  cp -a "$WORK/backup/target.baseline" "$TPATH" 2>/dev/null || true
  ROUND_OUTCOME="cross=$ROUND_CROSS_OUTCOME own=$ROUND_OWN_OUTCOME"
}

# The candidate rounds, in the task's preference order, ONE object at a
# time; the first terminal cross-op finding (D1/D2/D3) stops the rounds.
# Round 1 = the chosen content blob (identity-proven consumed); round 2 =
# the RUN layer blob (the same class, if distinct); round 3 = the RUN
# snapshot's own marker file. A MUTATION-BLOCKED round falls through to
# the next justified candidate (run 1 measured: the finalized content
# blobs are owner-RO mode 0444 — the naive write is DAC-blocked — so the
# vehicle exercises the SAME granted domain authority through the
# candidate policy's setattr grant: owner chmod 0600 -> pwrite -> the
# original mode restored; all inside the vehicle, no root).
FINAL_CROSS_OUTCOME=""
FINAL_OWN_OUTCOME=""
FINAL_ROUND=""
FINAL_LP=""
FINAL_TARGET_KIND=""
FINAL_TARGET_PATH=""
FINAL_TARGET_SHA=""
MEASURED_PATHS=""
for ROUND in 1 2 3; do
  case "$ROUND" in
    1) R_KIND="$TARGET_KIND"; R_PATH="$TARGET_PATH"; R_HEX="$TARGET_HEX" ;;
    2) R_KIND="blob-l1"; R_PATH="$BLOB_L1"; R_HEX="$L1_HEX" ;;
    3) R_KIND="snapshot-marker"; R_PATH="$SNAPMARK"; R_HEX="$L2_HEX" ;;
  esac
  if [ -z "$R_PATH" ]; then
    note "round $ROUND: no such object in the inventory; skipping"
    continue
  fi
  case " $MEASURED_PATHS " in
    *" $R_PATH "*) note "round $ROUND skipped: $R_PATH was already measured"; continue ;;
  esac
  if [ "$ROUND" = 2 ] && [ "$TARGET_KIND" = "snapshot-marker" ]; then
    note "round 2 skipped: the round-1 target already WAS the snapshot marker (no second snapshot-side candidate)"
    break
  fi
  if [ "$ROUND" != 1 ]; then
    TARGET_SIZE="$(stat -c '%s' "$R_PATH" 2>/dev/null || echo 0)"
    POISON_USE="$(printf '%s' "$POISON_FULL" | head -c "$TARGET_SIZE")"
    if [ "$R_KIND" = "snapshot-marker" ]; then
      OFFSET_USE=0
      POISON_USE="$(printf '%s' "$POISON_FULL" | head -c "$TARGET_SIZE")"
    elif [ "$R_KIND" = "snapshot-data" ]; then
      OFFSET_USE=0
      POISON_USE="g29p"
    elif [ "$TARGET_SIZE" -gt 2097152 ]; then OFFSET_USE=1048576; else OFFSET_USE=$((TARGET_SIZE / 2)); fi
    BASELINE_TARGET_SHA="$(sha256sum "$R_PATH" | awk '{print $1}')"
    cp -a "$R_PATH" "$WORK/backup/target.baseline"
    {
      echo "=== the round-$ROUND target (the next justified candidate after the previous outcome) ==="
      echo "previous outcome was: ${ROUND_OUTCOME:-none}"
      echo "kind: $R_KIND; path: $R_PATH; size: $TARGET_SIZE"
    } > "$EVIDENCE_DIR/h-round$ROUND-selection.txt"
    cat "$EVIDENCE_DIR/h-round$ROUND-selection.txt" >&2
  fi
  MEASURED_PATHS="$MEASURED_PATHS $R_PATH"
  FINAL_ROUND="$R_KIND"
  FINAL_LP="r$ROUND"
  FINAL_TARGET_KIND="$R_KIND"
  FINAL_TARGET_PATH="$R_PATH"
  FINAL_TARGET_SHA="$BASELINE_TARGET_SHA"
  measure_candidate "$R_KIND" "$R_PATH" "$R_HEX" "$POISON_USE" "$OFFSET_USE" "r$ROUND"
  FINAL_CROSS_OUTCOME="$ROUND_CROSS_OUTCOME"
  FINAL_OWN_OUTCOME="$ROUND_OWN_OUTCOME"
  FINAL_CROSS_DENIALS="${DENIALS:-0}"
  case "$ROUND_CROSS_OUTCOME" in
    POISONED-OUTPUT|D3-FAILCLOSED) break ;;
  esac
  case "$ROUND_OWN_OUTCOME" in
    POISONED-OUTPUT|D3-FAILCLOSED) break ;;
  esac
done

log 'K: the short regression guards (the G26 shapes; compact)'
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
# the sig-0 policy facts: the guards measured cross-op kill(pid,0)
# succeeding between same-type categorized vehicles while every real
# signal stayed denied — capture the loaded policy's rules and
# constraints for the process class so the classification is
# policy-evidenced
{
  echo "=== sesearch: process-class allows between the two vehicle contexts ==="
  sesearch --allow -s docker_helper_rootlesskit_t -t docker_helper_rootlesskit_t -c process 2>&1 || true
  echo "=== the loaded policy's mlsconstrain rules for the process class ==="
  seinfo --constrain 2>&1 | grep -A4 -i 'process' | head -60 || true
} > "$EVIDENCE_DIR/k-process-policy-facts.txt" 2>&1
# guard verdicts
GUARD1=0
if grep -q 'Could not open proc directory for target.*Permission denied' "$EVIDENCE_DIR/g-guard1-newuidmap.txt" \
   && grep -q 'target uid_map after: \[\]' "$EVIDENCE_DIR/g-guard1-newuidmap.txt"; then GUARD1=1; fi
SIG_COUNT="$(awk '/rc=-1 errno=13$/{n++} END{print n+0}' "$EVIDENCE_DIR/g-guard2-signals.txt")"
GUARD2=0
if [ "$SIG_COUNT" -ge 2 ] \
   && grep -q 'target alive after the cross-op signals: YES' "$EVIDENCE_DIR/g-guard2-signals.txt"; then GUARD2=1; fi
GUARD3=0
if grep -q 'rc=-1 errno=13' "$EVIDENCE_DIR/g-guard3-sockconnect.txt"; then GUARD3=1; fi
SIGM_COUNT="$(awk '/rc=-1 errno=13$/{n++} END{print n+0}' "$EVIDENCE_DIR/g-guard4-manager.txt")"
GUARD4=0
if grep -q 'rc=-1 errno=13' "$EVIDENCE_DIR/g-guard4-manager.txt" \
   && [ "$SIGM_COUNT" -ge 1 ] \
   && grep -q "manager alive after A's signal attempt: YES" "$EVIDENCE_DIR/g-guard4-manager.txt"; then GUARD4=1; fi
echo "guard verdicts: newuidmap=$GUARD1 signals=$GUARD2 sockconnect=$GUARD3 manager=$GUARD4" >&2

log 'L: STOP both operations (the convergence)'
{
  echo "=== manager RPC: STOP $OPA ==="
} > "$EVIDENCE_DIR/l-stop.txt"
set +e
printf 'STOP %s\n' "$OPA" | timeout 120 socat - UNIX-CONNECT:"$MANAGER_SOCK" >> "$EVIDENCE_DIR/l-stop.txt" 2>&1
echo "socat rc: $?" >> "$EVIDENCE_DIR/l-stop.txt"
set -e
sleep 4
{
  echo "=== manager RPC: STOP $OPB ==="
} >> "$EVIDENCE_DIR/l-stop.txt"
set +e
printf 'STOP %s\n' "$OPB" | timeout 120 socat - UNIX-CONNECT:"$MANAGER_SOCK" >> "$EVIDENCE_DIR/l-stop.txt" 2>&1
echo "socat rc: $?" >> "$EVIDENCE_DIR/l-stop.txt"
set -e
sleep 4
manager_journal_since "$HV_EPOCH" "$EVIDENCE_DIR/l-manager-journal.txt"
{
  echo "=== trees after STOP (removed = the own-op convergence) ==="
  ls -la "$STATE_ROOT/ops" 2>&1 || true
  ls -la "$RUNTIME_ROOT/ops" 2>&1 || true
} >> "$EVIDENCE_DIR/l-stop.txt"
cat "$EVIDENCE_DIR/l-stop.txt" >&2

log 'M: the final harvest + the leg summary (Part F attribution)'
sleep 2
harvest_avcs_since "$HV_EPOCH" "$EVIDENCE_DIR/m-residual-avcs.txt"
dedup_avcs "$EVIDENCE_DIR/m-residual-avcs.txt" "$EVIDENCE_DIR/m-residual-avcs-dedup.txt"
{
  echo "=== P5-S2g29 LEG SUMMARY (Part F attribution) ==="
  echo "stand: SELinux Enforcing; candidate module v12 loaded UNCHANGED; G26 MCS delta loaded;"
  echo "       dontaudit off for the whole window; REAL manager + REAL rootlesskit + pinned BuildKit v0.33.0"
  echo "op A: $OPA; op B: $OPB (both REAL manager operations, concurrent, at the ceiling)"
  echo "input: one Dockerfile rewritten per leg with a nonce (the RUN is a fresh cache-missed execution; the FROM stays a cache hit over the live snapshot chain); nonce-0 pair sha: $(sha256sum "$CTX/Dockerfile" | awk '{print $1}')"
  echo "op A baseline build rc: ${A_BUILD_RC:-NA}; op B build 1 rc: ${B1_RC:-NA}; build 2 rc: ${B2_RC:-NA}; consume-baseline rc: ${B3_RC:-NA}"
  echo "baseline stable (build 1 vs build 2, no mutation): $BASELINE_STABLE"
  echo "measured candidate (round kind): $FINAL_ROUND"
  echo "measured target: kind=$FINAL_TARGET_KIND path=$FINAL_TARGET_PATH baseline_sha=$FINAL_TARGET_SHA"
  echo "consumption-path identity (export member bytes == tree blob bytes): $(grep 'IDENTITY.*_BLOB_CONSUMED' "$EVIDENCE_DIR/h-identity-checks.txt" 2>/dev/null | tr '\n' '; ' || true)"
  echo "cross-op mutation: vehicle rc=${CROSS_WRITE_RC:-NA} (POISON-READBACK match in $FINAL_LP-cross-mutation.txt; deny-count in the window: $FINAL_CROSS_DENIALS)"
  echo "cross-op consumption build rc: ${CROSS_BUILD_RC:-NA}; outcome: ${FINAL_CROSS_OUTCOME:-NONE}"
  echo "own-op mutation: vehicle rc=${OWN_WRITE_RC:-NA}; consumption build rc: ${OWN_BUILD_RC:-NA}; outcome: ${FINAL_OWN_OUTCOME:-NONE}"
  echo "round outcome record: ${ROUND_OUTCOME:-NONE}"
  echo "guards: newuidmap=$GUARD1 signals=$GUARD2 sockconnect=$GUARD3 manager=$GUARD4"
  echo "MCS process boundary remains active: op A's vehicles used NO /proc write, NO signal, NO socket connect;"
  echo "the only cross-op action was the granted rootlesskit_t -> builder_state_t file write (the G27 write-link)."
} > "$EVIDENCE_DIR/m-summary.txt" 2>&1
cat "$EVIDENCE_DIR/m-summary.txt" >&2

log 'teardown + cleanup (enforcing everywhere; temporary modules removed)'
mkdir -p "$EVIDENCE_DIR/legs"
cp -a "$WORK/reports/"*.json "$EVIDENCE_DIR/legs/" 2>/dev/null || true
semanage dontaudit on >/dev/null 2>&1 || true
pkill -KILL -f 'map_probe' 2>/dev/null || true
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
semodule -r gidmap_probe_diag >/dev/null 2>&1 || true
semodule -r payload_mac_diag >/dev/null 2>&1 || true
semodule -r gidmap_mcsboundary_diag >/dev/null 2>&1 || true
semodule -l 2>/dev/null | grep -E 'docker_helper|gidmap|payload' > "$EVIDENCE_DIR/m-final-modules.txt" 2>&1 || true

# the terminal measured outcome (the report assigns the verdict)
RESULT_LINE="INCOMPLETE"
if [ "${FINAL_CROSS_OUTCOME:-}" = "POISONED-OUTPUT" ]; then
  RESULT_LINE="POISONED-OUTPUT"
elif [ "${FINAL_CROSS_OUTCOME:-}" = "D3-FAILCLOSED" ]; then
  RESULT_LINE="FAIL-CLOSED"
elif [ "${FINAL_CROSS_OUTCOME:-}" = "D4-IGNORED" ] && [ "${FINAL_OWN_OUTCOME:-}" = "POISONED-OUTPUT" ]; then
  RESULT_LINE="INCONCLUSIVE"
elif [ "${FINAL_CROSS_OUTCOME:-}" = "D4-IGNORED" ]; then
  RESULT_LINE="IGNORED"
fi
printf '%s P5S2-STATE-POISON-RESULT=%s (the paired cross-op poisoning measurement completed; see m-summary.txt)\n' "$PREFIX" "$RESULT_LINE" >&2
exit 0
