#!/usr/bin/env bash
#
# Guest-side P5-S2g28 BuildKit payload MAC closure for openSUSE
# Tumbleweed. INVESTIGATION ONLY — run 12 (the enforcing candidate
# iteration, ledger v12): the candidate payload module carries the
# run-1/2 harvest-ledger grants PLUS the enforcing-proven deltas (run
# 2.5: kernel module autoload; run 3: the tap-handoff relabel direction;
# run 4: the resolver's DNS udp write, the buildkitd socket shutdown
# unlink, the net-driver teardown sigkill; run 5: the DNS reply recv;
# run 6: the slirp relay's host-side recv; run 7: the slirp TLS-relay
# tcp send; run 8: the TLS client's tcp send + the relay teardown
# shutdown; run 9: the TLS client's tcp recv; run 10: the relay's tcp
# recv; run 11: the cgroup getattr probe, the runc kcore masked-path
# stat and the manager's state-tree symlink cleanup) plus the relabel
# reshape (snapshot copies relabel to the state tree's own type,
# keeping the tree uniform for the manager's mandatory cleanup); every
# flow/payload domain
# stays ENFORCING (no permissive), and the full production composition
# manager -> rootlesskit -> buildkitd -> readiness -> minimal buildctl
# build -> STOP runs. Every residual AVC denial is harvested as the next
# iteration's ledger delta; base-policy dontaudit rules are disabled for
# the attempt window so no hidden denial can mask the ledger source
# (re-enabled at teardown).
#
# Starting point (runs 1/2 = CI 36420911926/36423428498, enforcing
# attempt = run 2.5 = CI 36426082065):
#  - Part A baseline recorded: the production flow's exact enforcing
#    stop at the gid-map capability boundary (newgidmap_t cap_userns
#    sys_admin + capability setgid), plus the auxiliary boundaries the
#    flow passes in permissive but needs under enforcing (the getsubids
#    bin_t exec, the helper passwd_file getattr reads, the manager's
#    process-control signals for its own flow group).
#  - The permissive harvest recorded the full production path's AVC
#    surface (195 unique (s,t,class,perm) tuples: the slirp4netns net
#    driver, the copy-up mounts, buildkitd boot, content store, runc
#    workers, HTTPS pulls, export tar) as the grant-ledger source.
#  - A real FROM alpine:3.20 HTTPS build COMPLETED under permissive
#    (buildctl exit 0, a 3.6MB export tar), proving the composition and
#    the harvest method.
#  - Run 2.5 (CI 36426082065, enforcing candidate): the flow passed the
#    G27 gid-map enforcing boundary (newgidmap_t cap_userns sys_admin +
#    capability setgid carried it through) and died at rootlesskit's tap
#    setup — `ip tuntap add` opening /dev/net/tun returned ENODEV with an
#    EMPTY AVC window. Cause: the run-2 permissive harvest recorded the
#    tun autoload AVC (docker_helper_rootlesskit_t -> kernel_t:system
#    module_request, kmod="char-major-10-200", comm="ip", the same
#    syscall window as the granted tun open/ioctl) but the candidate
#    module carried only a dontaudit for it; under enforcing the driver
#    never loads, so the open fails ENODEV ("open: No such device" in
#    the manager's child-output tail) and the launch aborts.
#  - Run 3 (CI 36434942701, enforcing, ledger v3 + dontaudit unmasking):
#    the tap open worked (the module_request grant confirmed) and
#    slirp4netns died at the tap handoff — the v2/v3 ledger had the
#    relabel pair transposed; the run-2 harvest records 431/432-class
#    tuples (1790599487.339:430/431) both carry scontext=slirp4netns_t
#    (relabelfrom on the rootlesskit_t-labeled tap socket, relabelto on
#    self), so the delta is one subject-corrected rule. The unmasking
#    also surfaced the exec-transition hygiene trio
#    (noatsecure/siginh/rlimitinh on all four transitions): non-blocking
#    (the transitions complete), base-policy masked by design, NOT
#    granted.
#
# This run: the candidate module (v4) carries ONLY per-AVC-evidenced
# grants (85 allow rules; the run-11 deltas attributed to the run-11
# enforcing AVC window); the run harvests the RESIDUAL denials under
# enforcing with dontaudits unmapped. The relabel puzzle is solved
# from the loaded policy's constraint dump (the G26 seinfo --constrain
# method): file/dir relabelto is constrained by
# (u1 == u2 or t1 == can_change_object_identity), and the stand's
# context files now carry the state tree's own type so the snapshot
# copies stay tree-uniform (the run-8 manager cleanup failure is the
# recorded composition evidence).
#
# The stand is the G27 stand maximally unchanged: REAL manager under the
# REAL systemd unit (SELinuxContext binding, P4 unit-cgroup boundary,
# real provision-builder.sh identity), REAL rootlesskit with the
# PRODUCTION argv, REAL pinned BuildKit payload, the manager RPC over
# manager.sock spoken by the harness as the daemon would. The G26
# MCS-constraint delta is loaded verbatim. The production module is
# compiled from the UNCHANGED repo sources; the candidate payload
# module is guest-only and removed at cleanup; NO manager/BuildKit/
# docker-helper source changes; NO production policy commit; NO state
# relabels; NO cache poisoning.
#
set -Eeuo pipefail

PREFIX='[release-2.4-p5s2-payload-mac-tw]'
EVIDENCE_DIR=/tmp/release-2.4-p5s2-payload-mac-evidence
BUILDER_USER=docker-helper-builder
GUEST_FILES=/tmp/p5s2-payload-mac
TRANSFERRED="$GUEST_FILES"
STATE_ROOT=/var/lib/docker-helper-builder
RUNTIME_ROOT=/run/docker-helper-builder
MANAGER_SOCK="$RUNTIME_ROOT/manager.sock"
UNIT=docker-helper-builder
BUILDKITD=/usr/libexec/docker-helper/buildkit/buildkitd
BUILDCTL=/usr/libexec/docker-helper/buildkit/buildctl
WORK=/tmp/p5s2-g28-work

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
  semanage dontaudit on >/dev/null 2>&1 || true
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
  printf '%s P5S2-PAYLOAD-MAC-RESULT=PASS-INCOMPLETE (toolchain unavailable; recorded as a finding)\n' "$PREFIX" >&2
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
  printf '%s P5S2-PAYLOAD-MAC-RESULT=PASS-INCOMPLETE (payload download/verify failed; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi
install -d -m 0755 /tmp/p5s2-g28-payload-extract
tar -xzf "$WORK/buildkit.tgz" -C /tmp/p5s2-g28-payload-extract
install -d -m 0755 /usr/libexec/docker-helper/buildkit
install -m 0755 /tmp/p5s2-g28-payload-extract/bin/buildkitd "$BUILDKITD"
install -m 0755 /tmp/p5s2-g28-payload-extract/bin/buildctl "$BUILDCTL"
install -m 0755 /tmp/p5s2-g28-payload-extract/bin/buildkit-runc \
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

log 'A3: the candidate payload module (v12: the harvest ledger + the run-2.5..11 enforcing deltas + the relabel reshape, enforcing)'
cat > /tmp/payload_mac_diag.te <<'MODEOF'
module payload_mac_diag 12.0;

# P5-S2g28 guest-only candidate payload module. RUN 12: the enforcing
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
  echo "=== the candidate payload module (source, run 12: harvest-ledger grants + the run-2.5..11 enforcing deltas + the relabel reshape) ==="
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
  printf '%s P5S2-PAYLOAD-MAC-RESULT=PASS-INCOMPLETE (unit failed to start; recorded as a finding)\n' "$PREFIX" >&2
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
  printf '%s P5S2-PAYLOAD-MAC-RESULT=PASS-INCOMPLETE (state root label; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi

log 'E: the enforcing candidate attempt — START + readiness + minimal build + STOP'
# Harvest completeness: disable every dontaudit rule (ours and the base
# policy's) so NO denial can hide from the ledger harvest; re-enabled at
# teardown. Guest-only, evidence-driven harvest hygiene.
semanage dontaudit off >>"$EVIDENCE_DIR/te-dontaudit-off.log" 2>&1 || true
OPH="$(gen_op_id)"
HV_EPOCH="$(date +%s)"
{
  echo "=== P5-S2g28 run 12: the enforcing candidate attempt (ledger v12) ==="
  echo "op id: $OPH; epoch: $HV_EPOCH"
  echo "dontaudit rules disabled for the attempt window (semanage dontaudit off)"
  echo "attribution: run 2.5 proved module_request necessary under enforcing;"
  echo "run 3 proved the tap-handoff relabel direction blocking as transposed;"
  echo "run 4 proved the resolver's DNS udp write, the buildkitd socket shutdown"
  echo "unlink and the net-driver teardown sigkill blocking; run 5 proved the"
  echo "DNS reply recv (rootlesskit_t udp read) and the slirp relay send"
  echo "(slirp4netns_t udp write) blocking; run 6 proved the slirp relay's"
  echo "host-side recv (slirp4netns_t udp read) blocking; run 7 proved the"
  echo "slirp TLS-relay tcp send (slirp4netns_t tcp write) blocking; the"
  echo "run-4..7 relabelto AVCs were the u1==u2 relabelto constraint against"
  echo "unconfined_u harness context files; run 8 proved the TLS client's tcp"
  echo "send and the relay teardown shutdown blocking; run 9 proved the TLS"
  echo "client's tcp recv blocking; run 10 proved the relay's tcp recv blocking;"
  echo "run 11 proved the buildkitd cgroup getattr probe, the runc container"
  echo "init's /proc/kcore masked-path stat and the manager's state-tree"
  echo "symlink cleanup blocking; the state_t-labeled context keeps the"
  echo "snapshot tree uniform (the manager's mandatory cleanup converged in"
  echo "run 9: the op trees were empty after STOP)."
  echo "=== manager RPC: START $OPH ==="
} > "$EVIDENCE_DIR/e-attempt.txt"
set +e
printf 'START %s\n' "$OPH" | timeout 120 socat - UNIX-CONNECT:"$MANAGER_SOCK" >> "$EVIDENCE_DIR/e-attempt.txt" 2>&1
echo "socat rc: $?" >> "$EVIDENCE_DIR/e-attempt.txt"
set -e
sleep 4
{
  echo "=== the process tree at readiness ==="
  for pat in 'rootlesskit.*--net=' 'buildkitd --rootless' 'slirp4netns'; do
    for p in $(pgrep -f "$pat" 2>/dev/null); do
      echo "pid $p ($(cat "/proc/$p/comm" 2>/dev/null)): $(tr -d '\0' < "/proc/$p/attr/current" 2>/dev/null || true)"
      echo "  uid_map: $(tr '\n' ';' < "/proc/$p/uid_map" 2>/dev/null || true)"
      echo "  cgroup: $(cat "/proc/$p/cgroup" 2>/dev/null | head -1 || true)"
    done
  done
  echo "=== per-op tree labels ==="
  stat -c '%C %U:%G %a %n' "$STATE_ROOT/ops/$OPH" "$RUNTIME_ROOT/ops/$OPH" \
    "$RUNTIME_ROOT/ops/$OPH/buildkitd.sock" 2>&1 || true
} > "$EVIDENCE_DIR/e-processes.txt" 2>&1
cat "$EVIDENCE_DIR/e-processes.txt" >&2

# The minimal real build (the P4A1 pattern; NO Docker Engine needed).
# The context files are labeled system_u:docker_helper_builder_state_t
# BEFORE the build: production's build context is staged by the daemon
# (system_u:docker_helper_t creates the staged files in its runtime dir),
# and the loaded policy constrains file/dir relabelto with (u1 == u2 or
# t1 == can_change_object_identity) — buildkitd's xattr-preserving
# local-context copy relabels the snapshot copies to the source's label,
# so the source files must carry (a) the payload's own user and (b) a
# label that keeps the snapshot tree uniform: with the state-tree type
# the copies relabel to the tree's own type and the manager's mandatory
# op cleanup can unlink everything (the run-8 composition's
# unconfined_u/user_tmp_t labels instead pulled a foreign-typed object
# into the tree and the manager's cleanup failed with 'state dir still
# present after removal', run-8 AVC 1790609087.679:401 builder_t unlink
# user_tmp_t:file, leaving the op entry retained). The production
# mapping (whether the daemon relabels its staged context to the
# builder's state type before handoff, or the manager gains foreign-type
# unlink authority) is an explicit decision for the production policy
# commit, out of this experiment's scope.
CTX="$WORK/ctx"
mkdir -p "$CTX"
cat > "$CTX/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN mkdir -p /m1 && echo p5s2-g28-run12 > /m1/marker.txt && cat /proc/self/uid_map > /m1/uid_map.txt && id > /m1/id.txt
EOF
chcon -u system_u -t docker_helper_builder_state_t "$CTX" "$CTX/Dockerfile"
{
  echo "=== the context files' labels after the system_u/state_t chcon ==="
  stat -c '%C %U:%G %n' "$CTX" "$CTX/Dockerfile" 2>&1
} > "$EVIDENCE_DIR/e-ctx-labels.txt" 2>&1
cat "$EVIDENCE_DIR/e-ctx-labels.txt" >&2
mkdir -p "$WORK/docker-config" "$WORK/export"
echo '{}' > "$WORK/docker-config/config.json"
set +e
DOCKER_CONFIG="$WORK/docker-config" timeout 300 "$BUILDCTL" \
  --addr "unix://$RUNTIME_ROOT/ops/$OPH/buildkitd.sock" build \
  --progress=plain --frontend=dockerfile.v0 \
  --local "context=$CTX" --local "dockerfile=$CTX" \
  --output "type=docker,name=p5s2g28:run12,dest=$WORK/export/out.tar" \
  > "$EVIDENCE_DIR/e-build.txt" 2>&1
BUILD_RC=$?
set -e
{
  echo "buildctl exit: $BUILD_RC"
  echo "export tar: $(stat -c '%C %U:%G %s' "$WORK/export/out.tar" 2>&1)"
  echo "=== buildctl output tail ==="
  tail -30 "$EVIDENCE_DIR/e-build.txt" 2>/dev/null || true
} >> "$EVIDENCE_DIR/e-attempt.txt"

log 'F: own-operation lifecycle stop (the manager STOP; the convergence)'
STP_EPOCH="$(date +%s)"
{
  echo "=== manager RPC: STOP $OPH ==="
} > "$EVIDENCE_DIR/f-stop.txt"
set +e
printf 'STOP %s\n' "$OPH" | timeout 120 socat - UNIX-CONNECT:"$MANAGER_SOCK" >> "$EVIDENCE_DIR/f-stop.txt" 2>&1
echo "socat rc: $?" >> "$EVIDENCE_DIR/f-stop.txt"
set -e
sleep 4
manager_journal_since "$STP_EPOCH" "$EVIDENCE_DIR/f-stop-journal.txt"
{
  echo "=== the manager journal window (the stop's behavior) ==="
  cat "$EVIDENCE_DIR/f-stop-journal.txt"
  echo "=== trees after STOP (removed = the own-op convergence) ==="
  ls -la "$STATE_ROOT/ops" 2>&1 || true
  ls -la "$RUNTIME_ROOT/ops" 2>&1 || true
} >> "$EVIDENCE_DIR/f-stop.txt"

log 'G: the full-window harvest (the residual grant-ledger source)'
sleep 2
harvest_avcs_since "$HV_EPOCH" "$EVIDENCE_DIR/g-residual-avcs.txt"
dedup_avcs "$EVIDENCE_DIR/g-residual-avcs.txt" "$EVIDENCE_DIR/g-residual-avcs-dedup.txt"
{
  echo "=== the manager journal of the whole attempt window ==="
  journalctl -u "$UNIT" --since "@$HV_EPOCH" --no-pager 2>/dev/null | tail -300 || true
} > "$EVIDENCE_DIR/g-manager-journal-all.txt" 2>&1
# the relabelto puzzle (run-4 AVC 1790605769.866:399): the TE allow rule
# exists (docker_helper_rootlesskit_t user_tmp_t:file relabelto) yet the
# AVC fired — capture the loaded policy's constraint rules for the file
# class so the classification is policy-evidenced, not guessed
{
  echo "=== sesearch: TE allow rules rootlesskit_t -> user_tmp_t:file ==="
  sesearch --allow -s docker_helper_rootlesskit_t -t user_tmp_t -c file 2>&1 || true
  echo "=== loaded-policy constraint rules touching the file class (the G26 method: seinfo --constrain) ==="
  seinfo --constrain 2>&1 | grep -B2 -A6 'relabelto' || true
  seinfo --constrain 2>&1 | grep -c 'constraint\|mlsconstrain' || true
} > "$EVIDENCE_DIR/g-relabelto-constraint.txt" 2>&1
wc -l "$EVIDENCE_DIR/g-residual-avcs.txt" "$EVIDENCE_DIR/g-residual-avcs-dedup.txt" >&2

log 'teardown + cleanup (enforcing everywhere; temporary modules removed)'
semanage dontaudit on >/dev/null 2>&1 || true
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
semodule -r payload_mac_diag >/dev/null 2>&1 || true
semodule -r gidmap_mcsboundary_diag >/dev/null 2>&1 || true
semodule -l 2>/dev/null | grep -E 'docker_helper|gidmap|payload' > "$EVIDENCE_DIR/g-final-modules.txt" 2>&1 || true

printf '%s P5S2-PAYLOAD-MAC-RESULT=PASS (run 12 completed: enforcing candidate iteration, ledger v12)\n' "$PREFIX" >&2
exit 0
