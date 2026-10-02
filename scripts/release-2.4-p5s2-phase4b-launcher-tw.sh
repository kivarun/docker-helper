#!/usr/bin/env bash
#
# Guest-side Release 2.4 P5-S2 Phase 4B live launcher/provisioning proof for
# openSUSE Tumbleweed. INVESTIGATION ONLY.
#
# The question Phase 4B answers (G32 r3 §4.2 + §5, live):
#   does the SHIPPED production composition — the real builder unit under
#   the SELinuxContext= binding, the real manager, the Phase 3 categorized
#   provisioning and the Phase 4A launcher self-reexec chain (validated
#   argv, pinned OS thread, /proc/thread-self/attr/exec write, execve
#   replacement) — reach a kernel-verified categorized flow context
#   (docker_helper_rootlesskit_t:s0:cN) from a bare-s0 manager, with zero
#   uncategorized flow and the legacy direct-exec path dead?
#
# This is the live implementation gate the shipped policy's launcher
# section reserves its evidence-dependent additions for. It runs ONLY the
# production composition: the binary, the module 1.2, the unit, the
# provisioning script, rootlesskit and the bundled buildkitd are installed
# exactly as shipped. NO guest allow-module from G26/G28/G30/G31 may exist
# (leftovers are removed first and the clean module list is recorded). No
# policy rule, attribute, Go code, START-protocol, provisioning, ingress,
# payload-ledger, or recovery change is made here.
#
# Composition (the shipped artifacts only):
#   /usr/bin/docker-helper                (built from the tested SHA)
#   /usr/bin/rootlesskit                  (distro)
#   /usr/libexec/docker-helper/buildkit   (pinned payload, SHA-verified)
#   docker-helper-builder.service         (the real unit, SELinuxContext=)
#   provision-builder.sh                  (the real provisioning owner)
#   docker_helper module 1.2              (compiled from the shipped .te/.fc)
#
# Legs:
#   PREREQ     Tumbleweed, selinux-only LSM, Enforcing, toolchain present,
#              clean stand, investigation modules absent (removed first if
#              found), no docker-helper composition residue.
#   PREFLIGHT  loaded-policy static facts (NOT a substitute for the live
#              proof): matchpathcon of the six root/ops/per-op paths (the
#              roots and the shared ops containers stay on the root types,
#              the per-op paths carry the per-op types), the I9 transition
#              negative (zero builder_t -> rootlesskit_t process
#              transition, zero builder_t execute/execute_no_trans on
#              rootlesskit_exec_t), exactly one transition into
#              rootlesskit_t (launcher_t) and one into launcher_t
#              (builder_t), and the setexec split (launcher_t
#              self:setexec; builder_t none).
#   LAUNCH     one real START over the real manager.sock (root peer, the
#              builder_manager_protocol.go line protocol) with a
#              concurrent kernel-label sampler: the four provisioned
#              paths' security.selinux read-backs, the launch leader pid's
#              /proc/<pid>/attr/current sequence (the launcher child
#              BECOMES the rootlesskit leader at the same pid, so the
#              observed context sequence of that pid IS the kernel
#              evidence of both hops), the roots/ops-container labels,
#              and the process table. The manager context is re-read
#              after the attempt: it must still be
#              docker_helper_builder_t:s0.
#   INVENTORY  every AVC of the window attributed to
#              docker_helper_builder_launcher_t, in raw form; the report
#              classifies required-before-rootlesskit /
#              diagnostic-hygiene / missing. NO grants are added here.
#   I9-LIVE    two guest-only transient-unit vehicles (production files
#              unchanged; a transient unit's SELinuxContext= is the same
#              forced-context mechanism the real unit uses):
#              (A) the direct exec of /usr/bin/rootlesskit bound to
#              docker_helper_builder_t:s0 without the launcher — the exec
#              must be denied and rootlesskit_t must never appear;
#              (B) the launch-exec leaf running IN builder_t — the live
#              half of the setexec split: the forced-context write must
#              be denied and the leaf must fail closed before any exec.
#   BOUNDARY   the FIRST downstream AVC of the categorized flow
#              (docker_helper_rootlesskit_t:s0:c*) — recorded as the
#              exact payload-surface boundary of the next step (the G28
#              ledger is deliberately NOT transferred here).
#
# A downstream payload AVC AFTER a proven rootlesskit_t:s0:c1 entry is the
# expected normal failure and is NOT a Phase 4B failure. A launcher-domain
# denial before the rootlesskit_t:s0:c1 entry, a denied provisioning
# relabel, an uncategorized (bare s0) flow context, or a changed manager
# context IS a Phase 4B failure at the exact evidence, and the run STOPs
# without fixing anything.
#
set -Eeuo pipefail

PREFIX='[release-2.4-p5s2-phase4b-launcher-tw]'
EVIDENCE_DIR=/tmp/release-2.4-p5s2-phase4b-launcher-evidence
GUEST_FILES=/tmp/p5s2-phase4b-launcher
TRANSFERRED="$GUEST_FILES"
STATE_ROOT=/var/lib/docker-helper-builder
RUNTIME_ROOT=/run/docker-helper-builder
MANAGER_SOCK="$RUNTIME_ROOT/manager.sock"
UNIT=docker-helper-builder
BUILDKITD=/usr/libexec/docker-helper/buildkit/buildkitd
BUILDER_T='system_u:system_r:docker_helper_builder_t:s0'
LAUNCHER_DOMAIN=docker_helper_builder_launcher_t
RK_DOMAIN=docker_helper_rootlesskit_t
RK_STATE_T=docker_helper_builder_state_t
RK_RUNTIME_T=docker_helper_builder_runtime_t
RK_STATE_ROOT_T=docker_helper_builder_state_root_t
RK_RUNTIME_ROOT_T=docker_helper_builder_runtime_root_t
LEGACY_UNIT_A=p4b-legacy-direct-exec
LEGACY_UNIT_B=p4b-launcher-setexec

log()  { printf '%s %s\n' "$PREFIX" "$*"; }
note() { printf '%s NOTE: %s\n' "$PREFIX" "$*"; }
marker() { printf 'P5S2-P4B-%s\n' "$*"; }
finish() { printf '%s P5S2-P4B-RESULT=%s\n' "$PREFIX" "$1"; }

rm -rf "$EVIDENCE_DIR" /tmp/p4b-work
mkdir -p "$EVIDENCE_DIR" /tmp/p4b-work

# The investigation modules earlier stands installed; the clean composition
# proves none is loaded (leftovers are removed first and recorded).
INVESTIGATION_MODULES=(payload_mac_diag gidmap_mcsboundary_diag cat_launch_diag gidmap_probe_diag)

# gen_op_id: a random canonical-grammar op id (op_ + 32 hex).
gen_op_id() {
  printf 'op_%s' "$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
}

# context_of: the kernel-issued SELinux context of an existing path.
context_of() { stat -c '%C' "$1" 2>/dev/null || true; }

# process_context: /proc/<pid>/attr/current, newline-safe.
process_context() { tr -d '\0' < "/proc/$1/attr/current" 2>/dev/null || true; }

# 4C-27 process/credential snapshot (diagnostic host observation):
# SELinux context, Uid/Gid, the five capability sets, and the user/net
# namespace identities of one pid. The function OWNS its destination
# path (the third argument) — the 4C-27 dispatch passed the path as an
# ignored argument and produced no files.
proc_snapshot() {
  pid="$1"
  ctx="$2"
  out="$3"
  {
    echo "=== pid=$pid ctx=$ctx at $(date +%s.%N) ==="
    grep -a -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NSpid|PPid):' "/proc/$pid/status" 2>/dev/null || true
    echo "ns/user: $(readlink "/proc/$pid/ns/user" 2>/dev/null)"
    echo "ns/net:  $(readlink "/proc/$pid/ns/net" 2>/dev/null)"
  } > "$out"
}

# 4C-28 writer sanity: prove the snapshot writer itself is functional
# (a live long-lived pid must produce a non-empty file with the
# snapshot's header shape) BEFORE the window, so a snapshot absence can
# be classified as an actual race instead of a dead writer.
proc_snapshot 1 "sanity" "$EVIDENCE_DIR/31-writer-sanity.txt"
if [ ! -s "$EVIDENCE_DIR/31-writer-sanity.txt" ]; then
  echo "BLOCKER=the snapshot writer produced an empty sanity file (pid 1)" >&2
  exit 1
fi
if ! grep -aq '^=== pid=1 ctx=sanity at ' "$EVIDENCE_DIR/31-writer-sanity.txt"; then
  echo "BLOCKER=the snapshot writer's sanity file does not carry the snapshot header shape" >&2
  exit 1
fi

# harvest_avcs_since: the audit-log slice + kernel journal slice since an
# epoch (the G31 evidence pattern) plus the kernel ring buffer.
harvest_avcs_since() {
  local since="$1" out="$2"
  {
    echo "=== audit.log AVC records since epoch $since ==="
    grep -a 'type=AVC' /var/log/audit/audit.log 2>/dev/null \
      | awk -v s="$since" '{ for (i = 1; i <= NF; i++) if ($i ~ /^msg=audit\(/) { ts = substr($i, 11); split(ts, t, "."); if (t[1] + 0 >= s + 0) print; break } }' \
      || true
    echo "=== ausearch slice ==="
    ausearch -m AVC,USER_AVC,SELINUX_ERR -ts "$since" --raw 2>/dev/null || true
    echo "=== journalctl -k avc window ==="
    journalctl -k --since "@$since" --no-pager 2>/dev/null | grep -a 'avc:' || true
    echo "=== kernel ring buffer (dmesg) avc tail ==="
    dmesg 2>/dev/null | grep -a 'avc:' | tail -40 || true
  } > "$out" 2>&1
}

# 4C-29 AVC-tracepoint decoder: joins the kernel's avc:selinux_audited
# trace events (raw access-vector masks) against the canonical audit
# slice's symbolic AVC records, calibrating mask->permission pairs from
# co-captured (pid, tclass) evidence. NO hardcoded bit map: only masks
# whose symbolic perm-set is established live by co-capture in the same
# window decode an event; everything else is reported raw.
cat > /tmp/p4b-work/decode.awk <<'AWK'
FNR == NR {
	if ($0 !~ /selinux_audited:/) next
	n = split($1, seg, "-"); pid = seg[n]
	requested = ""; denied = ""; audited = ""; result = ""; sctx = ""; tctx = ""; tc = ""
	for (i = 1; i <= NF; i++) {
		if ($i ~ /^requested=/) { requested = $i; sub(/^requested=/, "", requested) }
		else if ($i ~ /^denied=/) { denied = $i; sub(/^denied=/, "", denied) }
		else if ($i ~ /^audited=/) { audited = $i; sub(/^audited=/, "", audited) }
		else if ($i ~ /^result=/) { result = $i; sub(/^result=/, "", result) }
		else if ($i ~ /^tclass=/) { tc = $i; sub(/^tclass=/, "", tc) }
		else if ($i ~ /^scontext=/) { sctx = $i; sub(/^scontext=/, "", sctx) }
		else if ($i ~ /^tcontext=/) { tctx = $i; sub(/^tcontext=/, "", tctx) }
	}
	if (tc == "" || pid !~ /^[0-9]+$/) next
	key = pid "|" tc
	nevents[key]++
	tmask[key "|" denied]++
	evorder[++evn] = pid "|" tc "|" requested "|" denied "|" audited "|" result "|" sctx "|" tctx
	next
}
{
	if ($0 !~ /type=AVC/) next
	pid = ""; tc = ""
	for (i = 1; i <= NF; i++) {
		if ($i ~ /^pid=/) { pid = $i; sub(/^pid=/, "", pid) }
		else if ($i ~ /^tclass=/) { tc = $i; sub(/^tclass=/, "", tc) }
	}
	perms = ""
	if (match($0, /denied[ \t]+\{[^}]*\}/)) {
		perms = substr($0, RSTART, RLENGTH)
		sub(/denied[ \t]+\{[ \t]*/, "", perms)
		sub(/[ \t]*\}$/, "", perms)
		gsub(/[ \t]+/, " ", perms)
	}
	if (tc == "" || pid !~ /^[0-9]+$/ || perms == "") next
	key = pid "|" tc
	avcpairs[key "|" perms]++
}
END {
	print "--- calibration pairs (co-captured: the same pid+tclass captured by BOTH channels with a unique mask and a unique perm-set) ---"
	for (key in nevents) {
		nm = 0; np = 0; themask = ""; theperms = ""
		for (k in tmask) {
			if (index(k, key "|") == 1) { nm++; themask = substr(k, length(key) + 2) }
		}
		for (k in avcpairs) {
			if (index(k, key "|") == 1) { np++; theperms = substr(k, length(key) + 2) }
		}
		split(key, kp, "|")
		if (nm == 1 && np == 1) {
			printf "CALIBRATED %s: denied-mask %s <-> perms { %s }\n", key, themask, theperms
			if (classpair[kp[2] "|" themask] != "" && classpair[kp[2] "|" themask] != theperms) {
				printf "CONFLICT at class level: mask %s maps to both { %s } and { %s } — dropped from class decode\n", themask, classpair[kp[2] "|" themask], theperms
				delete classpair[kp[2] "|" themask]
			} else {
				classpair[kp[2] "|" themask] = theperms
			}
		} else {
			printf "AMBIGUOUS %s: %d distinct trace mask(s), %d distinct AVC perm-set(s) — not a calibration pair\n", key, nm, np
		}
	}
	print "--- class-level decode table (live-derived in this window; the kernel maps class+bit -> perm name identically for every subject) ---"
	for (k in classpair) {
		split(k, kp, "|")
		printf "tclass=%s denied-mask=%s -> perms { %s }\n", kp[1], kp[2], classpair[k]
	}
	print "--- decoded trace events (docker_helper_* subjects; UNDECODED when no co-captured pair covers the mask) ---"
	for (e = 1; e <= evn; e++) {
		split(evorder[e], ee, "|")
		if (ee[7] !~ /docker_helper_(slirp4netns|rootlesskit|newuidmap|newgidmap)_t/) continue
		decoded = "(uncalibrated in this window)"
		ckey = ee[2] "|" ee[4]
		if (ckey in classpair) decoded = "{ " classpair[ckey] " }"
		if (ee[7] ~ /slirp4netns/) who = "HELPER"; else who = "FLOW"
		printf "%s pid=%s tclass=%s requested=%s denied=%s audited=%s result=%s -> denied-perms %s\n", who, ee[1], ee[2], ee[3], ee[4], ee[5], ee[6], decoded
		printf "    scontext=%s tcontext=%s\n", ee[7], ee[8]
	}
}
AWK

cleanup() {
  log 'cleanup: converge, stop the unit, remove the composition'
  printf 'PURGE\n' | timeout 240 socat - UNIX-CONNECT:"$MANAGER_SOCK" >> "$EVIDENCE_DIR/99-cleanup.txt" 2>&1 || true
  systemctl stop "$UNIT" > /dev/null 2>&1 || true
  systemctl disable "$UNIT" > /dev/null 2>&1 || true
  systemctl daemon-reload > /dev/null 2>&1 || true
  rm -f /etc/systemd/system/"$UNIT".service
  semodule -r docker_helper >> "$EVIDENCE_DIR/99-cleanup.txt" 2>&1 || true
  rm -f /usr/bin/docker-helper
  rm -rf /usr/libexec/docker-helper "$STATE_ROOT" "$RUNTIME_ROOT" "$TRANSFERRED" /tmp/p4b-work /tmp/p4b-buildkit-extract
  echo "cleanup done: $(date)" >> "$EVIDENCE_DIR/99-cleanup.txt"
}
trap cleanup EXIT

# ============================================================
# PREREQ: the stand, the toolchain, the clean composition
# ============================================================
log 'PREREQ: enforcing SELinux, Tumbleweed, clean composition'
{
  echo "=== distro ==="
  grep PRETTY_NAME /etc/os-release 2>/dev/null || true
  echo "=== kernel ==="
  uname -a
  echo "=== LSM state ==="
  cat /sys/kernel/security/lsm 2>/dev/null || true
  echo "enforce=$(getenforce 2>/dev/null || true)"
  echo "=== loaded modules (before any cleanup) ==="
  semodule -l 2>/dev/null | sort || true
  echo "=== permissive domains ==="
  semanage permissive -l 2>/dev/null || true
} > "$EVIDENCE_DIR/00-prereq.txt" 2>&1

if [ "$(grep PRETTY_NAME /etc/os-release 2>/dev/null)" != 'PRETTY_NAME="openSUSE Tumbleweed"' ]; then
  note "the stand does not identify openSUSE Tumbleweed"
  finish INCOMPLETE; exit 0
fi
LSM="$(cat /sys/kernel/security/lsm 2>/dev/null || true)"
printf '%s\n' "$LSM" | grep -aqw selinux || { note "SELinux is not an active LSM ($LSM)"; finish INCOMPLETE; exit 0; }
if printf '%s\n' "$LSM" | grep -aqw apparmor; then
  note "AppArmor is concurrently active ($LSM)"; finish INCOMPLETE; exit 0
fi
if [ "$(getenforce 2>/dev/null)" != "Enforcing" ]; then
  note "SELinux is not Enforcing"; finish INCOMPLETE; exit 0
fi
for d in "$STATE_ROOT" "$RUNTIME_ROOT" /usr/libexec/docker-helper /usr/bin/docker-helper; do
  if [ -e "$d" ]; then
    note "the stand is not clean: $d already exists (a prior composition must be removed first)"
    finish INCOMPLETE; exit 0
  fi
done
if id docker-helper-builder >/dev/null 2>&1; then
  note "the stand is not clean: the docker-helper-builder identity already exists"
  finish INCOMPLETE; exit 0
fi
for m in "${INVESTIGATION_MODULES[@]}"; do
  if semodule -l 2>/dev/null | awk '{print $1}' | grep -aqx "$m"; then
    note "removing leftover investigation module: $m"
    semodule -r "$m" >> "$EVIDENCE_DIR/00-prereq.txt" 2>&1 || true
  fi
done
for m in "${INVESTIGATION_MODULES[@]}"; do
  if semodule -l 2>/dev/null | awk '{print $1}' | grep -aqx "$m"; then
    note "investigation module $m still loaded after removal"
    finish INCOMPLETE; exit 0
  fi
done
marker "PREREQ=PASS"

# ============================================================
# A: toolchain + the SHIPPED module 1.2 + the SHIPPED composition
# ============================================================
log 'A: toolchain + shipped module 1.2 + shipped composition install'
zypper --non-interactive install -y checkpolicy container-selinux \
  policycoreutils-python-utils rootlesskit slirp4netns audit socat \
  setools-console python3 curl \
  > "$EVIDENCE_DIR/a-zypper-toolchain.log" 2>&1 \
  || { note "zypper install of the policy toolchain failed (see a-zypper-toolchain.log)"; finish INCOMPLETE; exit 0; }
fail_toolchain=0
for t in checkmodule semodule_package semodule semanage restorecon getenforce \
  sesearch seinfo matchpathcon ausearch auditctl socat; do
  command -v "$t" >/dev/null 2>&1 || { echo "$t not found" >> "$EVIDENCE_DIR/00-prereq.txt"; fail_toolchain=1; }
done
if [ "$fail_toolchain" = 1 ]; then
  note "policy toolchain incomplete after install"
  finish INCOMPLETE; exit 0
fi

# The shipped module is compiled from the transferred candidate sources and
# loaded UNMODIFIED (the composition's policy identity is the tree's). The
# module VERSION identity is carried by the manifest hash chain: the
# orchestrator hashes the proof-commit checkout's inputs; the transferred
# files must hash identically (the source tree carries
# `module docker_helper 1.2;`). Modern libsemanage's semodule -l has no
# version column, so the loaded-module check is presence + the hash chain.
{
  echo "=== transferred composition manifest ==="
  cat "$TRANSFERRED/manifest.txt" 2>/dev/null || echo "(no manifest recorded)"
  echo "=== input hashes (must match the manifest) ==="
  sha256sum "$TRANSFERRED/docker-helper" "$TRANSFERRED/tun-command-probe" \
    "$TRANSFERRED/tun-cross-op-vehicle" \
    "$TRANSFERRED/docker-helper.te" \
    "$TRANSFERRED/docker-helper.fc" "$TRANSFERRED/docker-helper-builder.service" \
    "$TRANSFERRED/provision-builder.sh" "$TRANSFERRED/modules-load.conf" 2>/dev/null || true
} > "$EVIDENCE_DIR/01-composition-inputs.txt" 2>&1
while IFS='=' read -r key want; do
  case "$key" in
    binary_sha256) file="$TRANSFERRED/docker-helper" ;;
    tun_probe_sha256) file="$TRANSFERRED/tun-command-probe" ;;
    cross_vehicle_sha256) file="$TRANSFERRED/tun-cross-op-vehicle" ;;
    te_sha256) file="$TRANSFERRED/docker-helper.te" ;;
    fc_sha256) file="$TRANSFERRED/docker-helper.fc" ;;
    unit_sha256) file="$TRANSFERRED/docker-helper-builder.service" ;;
    provision_sha256) file="$TRANSFERRED/provision-builder.sh" ;;
    modules_load_sha256) file="$TRANSFERRED/modules-load.conf" ;;
    *) continue ;;
  esac
  got="$(sha256sum "$file" 2>/dev/null | awk '{print $1}')"
  if [ "$got" != "$want" ]; then
    note "composition input $file hashes $got, manifest says $want; the transferred composition is not the proof-commit tree"
    finish INCOMPLETE; exit 0
  fi
done < "$TRANSFERRED/manifest.txt"
grep -q '^module docker_helper 1.2;' "$TRANSFERRED/docker-helper.te" \
  || { note "the shipped module source does not declare module docker_helper 1.2"; finish INCOMPLETE; exit 0; }
checkmodule -M -m -o /tmp/p4b-work/docker_helper.tmp "$TRANSFERRED/docker-helper.te" 2>>"$EVIDENCE_DIR/01-composition-inputs.txt" \
  || { note "checkmodule of the shipped module failed"; finish INCOMPLETE; exit 0; }
semodule_package -o /tmp/p4b-work/docker_helper.pp -m /tmp/p4b-work/docker_helper.tmp -f "$TRANSFERRED/docker-helper.fc" 2>>"$EVIDENCE_DIR/01-composition-inputs.txt" \
  || { note "semodule_package failed"; finish INCOMPLETE; exit 0; }
semodule -i /tmp/p4b-work/docker_helper.pp 2>>"$EVIDENCE_DIR/01-composition-inputs.txt" \
  || { note "semodule -i of the shipped module failed"; finish INCOMPLETE; exit 0; }
if ! semodule -l 2>/dev/null | awk '{print $1}' | grep -aqx docker_helper; then
  note "the docker_helper module is not loaded after install"
  finish INCOMPLETE; exit 0
fi
{
  echo "=== 4C-14 xperm toolchain gate (all four steps must hold before the live run) ==="
  echo "gate 1 checkmodule accepts allowxperm: the shipped .te (carrying the pinned allowxperm rule) compiled with rc=0 — the compile failure path above exits INCOMPLETE before any load"
  echo "gate 2 semodule_package succeeds: rc=0 recorded above"
  echo "gate 3 semodule load succeeds: rc=0 + the module presence check above"
  echo "gate 4 sesearch exposes the xperm rule: proven by the preflight allowxperm inventory (02-preflight.txt)"
  echo "the pinned allowxperm rule in the transferred source:"
  grep -an '^allowxperm docker_helper_rootlesskit_t' "$TRANSFERRED/docker-helper.te" || true
} >> "$EVIDENCE_DIR/01-composition-inputs.txt"
marker "POLICY-IDENTITY=docker_helper-module-1.2-sha"
restorecon /usr/bin/docker-helper /usr/bin/rootlesskit /usr/bin/slirp4netns \
  /usr/bin/newuidmap /usr/bin/newgidmap /usr/bin/nsenter 2>>"$EVIDENCE_DIR/01-composition-inputs.txt" || true
{
  echo "=== binary labels (the dedicated exec types) ==="
  for p in /usr/bin/docker-helper /usr/bin/rootlesskit /usr/bin/slirp4netns \
    /usr/bin/newuidmap /usr/bin/newgidmap /usr/bin/nsenter; do
    echo "$p -> $(context_of "$p")"
  done
  echo "=== loaded modules (after install) ==="
  semodule -l | sort
} >> "$EVIDENCE_DIR/01-composition-inputs.txt" 2>&1
cat "$EVIDENCE_DIR/01-composition-inputs.txt" >&2

# The nsenter packaged-path probe (the 4C-3 .fc authority): the exact real
# executable path, its package, and its label after restorecon. The .fc
# binds exactly this verified path (no wildcard); the preflight below
# fails if the packaged path or its label drifts from the composition.
{
  echo "=== nsenter packaged path probe ==="
  echo "command -v:   $(command -v nsenter)"
  NSENTER_REAL="$(readlink -f "$(command -v nsenter)")"
  echo "readlink -f:  $NSENTER_REAL"
  echo "rpm -qf:      $(rpm -qf "$NSENTER_REAL" 2>&1)"
  ls -lZ "$(command -v nsenter)" "$NSENTER_REAL" 2>&1
  echo "matchpathcon: $(matchpathcon "$NSENTER_REAL" 2>&1)"
} > "$EVIDENCE_DIR/02-nsenter-probe.txt" 2>&1
cat "$EVIDENCE_DIR/02-nsenter-probe.txt" >&2

# The flow's next-executable stand probe (the 4C-4 conditional capture, the
# §8 hypothesis: after the sys_ptrace correction the namespace
# reassociation may succeed and the next boundary may be the ip binary the
# nsenter network setup execs). Evidence-only: this records the packaged
# path, its package owner, and its label — it grants NOTHING and changes
# no policy surface.
{
  echo "=== ip packaged path probe (the next-boundary capture) ==="
  IP_BIN="$(command -v ip 2>/dev/null || true)"
  echo "command -v:   ${IP_BIN:-(not found)}"
  if [ -n "$IP_BIN" ]; then
    IP_REAL="$(readlink -f "$IP_BIN" 2>&1)"
    echo "readlink -f:  $IP_REAL"
    echo "rpm -qf:      $(rpm -qf "$IP_REAL" 2>&1)"
    ls -lZ "$IP_BIN" "$IP_REAL" 2>&1
    echo "matchpathcon: $(matchpathcon "$IP_REAL" 2>&1)"
  fi
} > "$EVIDENCE_DIR/02-ip-probe.txt" 2>&1
cat "$EVIDENCE_DIR/02-ip-probe.txt" >&2

# Evidence-only capture (P5-S2 Phase 4C-17): /dev/net/tun — the TUN
# ioctl boundary. The flow's `ip tuntap add` path reaches
# open("/dev/net/tun", O_RDWR) (the granted 4C-11/4C-12 chain) plus the
# two evidenced ioctls — TUNSETIFF (0x54ca) and TUNSETPERSIST (0x54cb) —
# mediated by the ordinary { ioctl } bit plus the exact
# { 0x54ca 0x54cb } allowxperm of the 4C-17 composition. This is a
# stand-shape capture (actual type, no assumption) + a loaded-policy
# inventory of the flow domain's tun/tap authority (expected: the
# 4C-17 ordinary + two-command xperm contribution, nothing wider).
{
  echo "=== /dev/net/tun evidence-only probe (stand shape + the 4C-14 loaded-policy tun authority inventory) ==="
  echo "--- the device node:"
  if [ -e /dev/net/tun ]; then
    ls -lZ /dev/net/tun
    stat /dev/net/tun
    echo "matchpathcon: $(matchpathcon /dev/net/tun 2>&1)"
  else
    echo "/dev/net/tun absent on the stand (pre-flow state)"
    ls -ldZ /dev/net 2>&1 || true
  fi
  echo "--- the TUN kernel facility truth (pre-provisioning; P5-S2 Phase 4C-13):"
  echo "sysfs endpoint: $(cat /sys/class/misc/tun/dev 2>&1 || true)"
  echo "lsmod tun:"
  lsmod | grep -a "^tun" || echo "(tun not listed in lsmod)"
  echo "modinfo tun:"
  modinfo tun 2>&1 | head -8 || true
  echo "--- loaded-policy inventory: flow domain -> tun/tap authority (expected: the 4C-17 { read write open ioctl } + TUNSETIFF+TUNSETPERSIST xperm contribution, nothing wider)"
  TUN_DEV_TYPE="$(matchpathcon /dev/net/tun 2>/dev/null | awk '{print $2}' | cut -d: -f3 || true)"
  echo "stand type from matchpathcon: ${TUN_DEV_TYPE:-(undetermined)}"
  echo "--- sesearch allow rootlesskit_t -> tun_tap_device_t (expected: the 4C-17 ordinary rule):"
  sesearch --allow -s docker_helper_rootlesskit_t -t tun_tap_device_t /sys/fs/selinux/policy 2>&1 || true
  if [ -n "${TUN_DEV_TYPE:-}" ] && [ "$TUN_DEV_TYPE" != "tun_tap_device_t" ] && [ "$TUN_DEV_TYPE" != "(undetermined)" ]; then
    echo "--- the stand shows a DIFFERENT device type than tun_tap_device_t; inventory for the actual type:"
    sesearch --allow -s docker_helper_rootlesskit_t -t "$TUN_DEV_TYPE" /sys/fs/selinux/policy 2>&1 || true
  fi
} > "$EVIDENCE_DIR/02-tun-probe.txt" 2>&1
cat "$EVIDENCE_DIR/02-tun-probe.txt" >&2

# The REAL builder identity + the REAL unit + the pinned payload (P4-A1 shape).
log 'A2: builder identity + REAL unit + pinned payload install'
# The reboot persistence asset is placed at the PRODUCTION destination
# before provisioning, from the composition's own bytes (P5-S2 Phase
# 4C-13); the current-boot convergence stays owned by the real
# provisioner (no ad-hoc harness modprobe).
install -d -m 0755 /usr/lib/modules-load.d
install -m 0644 "$TRANSFERRED/modules-load.conf" /usr/lib/modules-load.d/docker-helper-builder.conf
{
  echo "=== modules-load.d asset at the production destination ==="
  stat -c '%n %a %U:%G' /usr/lib/modules-load.d/docker-helper-builder.conf
  echo "contents:"
  cat /usr/lib/modules-load.d/docker-helper-builder.conf
} > "$EVIDENCE_DIR/a2-modules-load.txt" 2>&1
sh "$TRANSFERRED/provision-builder.sh" > "$EVIDENCE_DIR/a2-provision.txt" 2>&1 \
  || { note "provision-builder.sh failed"; finish INCOMPLETE; exit 0; }
# The provisioner's third responsibility: the TUN facility must report
# 10:200 after the REAL provisioner ran (P5-S2 Phase 4C-13).
TUN_DEV_AFTER="$(cat /sys/class/misc/tun/dev 2>/dev/null || true)"
if [ "$TUN_DEV_AFTER" != "10:200" ]; then
  note "the TUN facility did not converge through the real provisioner (/sys/class/misc/tun/dev reports '${TUN_DEV_AFTER:-nothing}', want 10:200)"
  finish INCOMPLETE; exit 0
fi
{
  echo "=== post-provisioning TUN facility ==="
  echo "sysfs endpoint: $TUN_DEV_AFTER"
  lsmod | grep -a "^tun" || true
} >> "$EVIDENCE_DIR/a2-modules-load.txt" 2>&1
install -m 0755 "$TRANSFERRED/docker-helper" /usr/bin/docker-helper
restorecon /usr/bin/docker-helper 2>>"$EVIDENCE_DIR/01-composition-inputs.txt" || true
install -m 0644 "$TRANSFERRED/docker-helper-builder.service" /etc/systemd/system/"$UNIT".service

BUILDKIT_VERSION=v0.33.0
BUILDKIT_TARBALL="buildkit-${BUILDKIT_VERSION}.linux-amd64.tar.gz"
BUILDKIT_SHA256=b6242896d343100808dcbe37565caf381e0a444a6a83d7255926bb1519248ead
BUILDKITD_SHA256=157da954fa081d9ec4f063d62029fbbf12437c1d47ab63080594eae5a85b36f2
BUILDCTL_SHA256=0b45ae3696f836bf711dbd78138e403924d7733f0b2328ba29a7fcf9ad5f1dfd
BUILDKIT_RUNC_SHA256=0acdd302ddc5540b2e445b683661bfada9935c702f9008ffb0481abcda16c9b4
curl -fsSL -o /tmp/p4b-work/buildkit.tgz \
  "https://github.com/moby/buildkit/releases/download/${BUILDKIT_VERSION}/${BUILDKIT_TARBALL}" \
  2>"$EVIDENCE_DIR/a2-payload-download.log" || true
ACTUAL_SHA256="$(sha256sum /tmp/p4b-work/buildkit.tgz 2>/dev/null | awk '{print $1}' || true)"
if [ "$ACTUAL_SHA256" != "$BUILDKIT_SHA256" ]; then
  note "BuildKit tarball SHA256 mismatch or download failed (got: ${ACTUAL_SHA256:-none})"
  finish INCOMPLETE; exit 0
fi
mkdir -p /tmp/p4b-buildkit-extract
tar -xzf /tmp/p4b-work/buildkit.tgz -C /tmp/p4b-buildkit-extract
install -d -m 0755 /usr/libexec/docker-helper/buildkit
install -m 0755 /tmp/p4b-buildkit-extract/bin/buildkitd "$BUILDKITD"
install -m 0755 /tmp/p4b-buildkit-extract/bin/buildctl /usr/libexec/docker-helper/buildkit/buildctl
install -m 0755 /tmp/p4b-buildkit-extract/bin/buildkit-runc \
  /usr/libexec/docker-helper/buildkit/buildkit-runc
restorecon -R /usr/libexec/docker-helper 2>>"$EVIDENCE_DIR/01-composition-inputs.txt" || true
{
  echo "=== pinned payload verification ==="
  for f in buildkitd buildctl buildkit-runc; do
    echo "$f: $(sha256sum "/usr/libexec/docker-helper/buildkit/$f" | awk '{print $1}')"
  done
  echo "expected buildkitd:  $BUILDKITD_SHA256"
  echo "expected buildctl:   $BUILDCTL_SHA256"
  echo "expected b-runc:     $BUILDKIT_RUNC_SHA256"
  "$BUILDKITD" --version 2>&1 || true
  /usr/bin/rootlesskit --version 2>&1 || true
} > "$EVIDENCE_DIR/a2-payload.txt" 2>&1

log 'A3: REAL unit bring-up (SELinuxContext binding)'
systemctl daemon-reload
systemctl start "$UNIT" 2>"$EVIDENCE_DIR/a3-unit-start.err" || true
UNIT_WAIT=0
until systemctl is-active --quiet "$UNIT" || [ "$UNIT_WAIT" -ge 30 ]; do
  sleep 1
  UNIT_WAIT=$((UNIT_WAIT + 1))
done
if ! systemctl is-active --quiet "$UNIT"; then
  note "the REAL builder unit failed to start"
  {
    systemctl status "$UNIT" --no-pager -l || true
    journalctl -u "$UNIT" --no-pager | tail -50 || true
  } > "$EVIDENCE_DIR/stand-failure-unit.txt" 2>&1
  finish INCOMPLETE; exit 0
fi
MG_PID="$(systemctl show -p MainPID --value "$UNIT")"
{
  echo "=== the REAL unit active ==="
  echo "manager pid: $MG_PID"
  echo "manager context: $(process_context "$MG_PID")"
  echo "manager cgroup: $(cat "/proc/$MG_PID/cgroup" 2>/dev/null || true)"
  echo "state root: $(stat -c '%C %U:%G %a' "$STATE_ROOT" 2>&1)"
  echo "runtime root: $(stat -c '%C %U:%G %a' "$RUNTIME_ROOT" 2>&1)"
  echo "manager.sock: $(stat -c '%C %U:%G %a' "$MANAGER_SOCK" 2>&1)"
} > "$EVIDENCE_DIR/03-manager-up.txt" 2>&1
cat "$EVIDENCE_DIR/03-manager-up.txt" >&2
if [ "$(process_context "$MG_PID")" != "$BUILDER_T" ]; then
  note "the manager is not docker_helper_builder_t:s0"
  finish INCOMPLETE; exit 0
fi
marker "MANAGER-CONTEXT-BEFORE=$BUILDER_T"

# ============================================================
# B: loaded-policy static preflight (NOT a substitute for live proof)
# ============================================================
log 'B: loaded-policy static preflight'
PREFLIGHT_OK=1
{
  echo "=== matchpathcon: the root/ops/per-op fc expectations ==="
  for entry in \
    "$STATE_ROOT:$RK_STATE_ROOT_T" \
    "$STATE_ROOT/ops:$RK_STATE_ROOT_T" \
    "$STATE_ROOT/ops/op_0123456789abcdef0123456789abcdef:$RK_STATE_T" \
    "$RUNTIME_ROOT:$RK_RUNTIME_ROOT_T" \
    "$RUNTIME_ROOT/ops:$RK_RUNTIME_ROOT_T" \
    "$RUNTIME_ROOT/ops/op_0123456789abcdef0123456789abcdef:$RK_RUNTIME_T"; do
    path="${entry%%:*}"; want="${entry##*:}"
    got="$(matchpathcon "$path" 2>/dev/null | awk '{print $2}')"
    if [ "$got" = "system_u:object_r:${want}:s0" ]; then
      echo "PASS $path -> $got"
    else
      echo "FAIL $path -> got '$got', want system_u:object_r:${want}:s0"
      PREFLIGHT_OK=0
    fi
  done

  echo "=== sesearch tool sanity (the loaded module's own rules must be visible) ==="
  echo "--- launcher_t entry allow (known rule):"
  sesearch --allow -s "$LAUNCHER_DOMAIN" -t docker_helper_exec_t -c file /sys/fs/selinux/policy || true
  if sesearch --allow -s "$LAUNCHER_DOMAIN" -t docker_helper_exec_t -c file /sys/fs/selinux/policy 2>/dev/null | grep -aq entrypoint; then
    echo "PASS: sesearch sees the loaded module's rules"
  else
    echo "FAIL: sesearch cannot query the loaded policy (tool error — every other sesearch result here is vacuous)"
    PREFLIGHT_OK=0
  fi

  echo "=== I9 negative: builder_t -> rootlesskit_t process transition (must be zero) ==="
  echo "--- allow transition rules:"
  sesearch --allow -s docker_helper_builder_t -t "$RK_DOMAIN" -c process -p transition /sys/fs/selinux/policy || true
  echo "--- type_transition rules (default-type dump, source builder_t):"
  sesearch --type_trans -c process /sys/fs/selinux/policy \
    | awk '$1 == "type_transition" && $2 == "docker_helper_builder_t" && $4 == "docker_helper_rootlesskit_t;"' || true
  if sesearch --allow -s docker_helper_builder_t -t "$RK_DOMAIN" -c process -p transition /sys/fs/selinux/policy 2>/dev/null | grep -q . \
    || sesearch --type_trans -c process /sys/fs/selinux/policy 2>/dev/null \
      | awk '$1 == "type_transition" && $2 == "docker_helper_builder_t" && $4 == "docker_helper_rootlesskit_t;"' | grep -q .; then
    echo "FAIL: a builder_t -> rootlesskit_t process transition exists"
    PREFLIGHT_OK=0
  else
    echo "PASS: zero builder_t -> rootlesskit_t process transition"
  fi

  echo "=== I9 negative: builder_t on rootlesskit_exec_t:file execute/execute_no_trans (must be zero) ==="
  echo "--- execute:"
  sesearch --allow -s docker_helper_builder_t -t docker_helper_rootlesskit_exec_t -c file -p execute /sys/fs/selinux/policy || true
  echo "--- execute_no_trans:"
  sesearch --allow -s docker_helper_builder_t -t docker_helper_rootlesskit_exec_t -c file -p execute_no_trans /sys/fs/selinux/policy || true
  echo "--- every builder_t rule on rootlesskit_exec_t (inventory):"
  sesearch --allow -s docker_helper_builder_t -t docker_helper_rootlesskit_exec_t /sys/fs/selinux/policy || true
  if sesearch --allow -s docker_helper_builder_t -t docker_helper_rootlesskit_exec_t -c file -p execute /sys/fs/selinux/policy 2>/dev/null | grep -q . \
    || sesearch --allow -s docker_helper_builder_t -t docker_helper_rootlesskit_exec_t -c file -p execute_no_trans /sys/fs/selinux/policy 2>/dev/null | grep -q .; then
    echo "FAIL: builder_t holds execute authority on rootlesskit_exec_t"
    PREFLIGHT_OK=0
  else
    echo "PASS: zero builder_t execute/execute_no_trans on rootlesskit_exec_t"
  fi

  echo "=== I9 positive: exactly ONE process transition into rootlesskit_t (launcher_t) ==="
  echo "--- every type_transition rule into rootlesskit_t (the default-type dump):"
  sesearch --type_trans -c process /sys/fs/selinux/policy \
    | awk '$1 == "type_transition" && $4 == "docker_helper_rootlesskit_t;"' || true
  echo "--- allow transition rules toward rootlesskit_t (attribute-expanded entries are expected from the base policy; recorded, not asserted):"
  sesearch --allow -t "$RK_DOMAIN" -c process -p transition /sys/fs/selinux/policy || true
  RK_IN="$(sesearch --type_trans -c process /sys/fs/selinux/policy 2>/dev/null \
    | awk '$1 == "type_transition" && $4 == "docker_helper_rootlesskit_t;"' | grep -c . || true)"
  if [ "$RK_IN" = 1 ] \
    && sesearch --type_trans -c process /sys/fs/selinux/policy 2>/dev/null \
      | awk '$1 == "type_transition" && $4 == "docker_helper_rootlesskit_t;"' | grep -aq "docker_helper_builder_launcher_t"; then
    echo "PASS: exactly one transition into rootlesskit_t, source launcher_t"
  else
    echo "FAIL: the rootlesskit_t entry set is not exactly the launcher edge ($RK_IN type_transition rules)"
    PREFLIGHT_OK=0
  fi

  echo "=== I9 hop 1: exactly ONE transition into launcher_t (builder_t) ==="
  LAUNCH_IN="$(sesearch --type_trans -c process /sys/fs/selinux/policy 2>/dev/null \
    | awk '$1 == "type_transition" && $4 == "docker_helper_builder_launcher_t;"')"
  echo "--- every type_transition rule into launcher_t:"
  printf '%s\n' "$LAUNCH_IN"
  if [ "$(printf '%s\n' "$LAUNCH_IN" | grep -c . || true)" = 1 ] \
    && printf '%s\n' "$LAUNCH_IN" | grep -aq "docker_helper_builder_t"; then
    echo "PASS: exactly one transition into launcher_t, source builder_t"
  else
    echo "FAIL: the launcher_t entry set is not exactly the manager edge"
    PREFLIGHT_OK=0
  fi

  echo "=== setexec split: launcher_t has setexec; builder_t has none ==="
  echo "--- launcher_t:"
  LAUNCHER_SETEXEC="$(sesearch --allow -s "$LAUNCHER_DOMAIN" -c process -p setexec /sys/fs/selinux/policy 2>/dev/null || true)"
  printf '%s\n' "${LAUNCHER_SETEXEC:-(none)}"
  echo "--- builder_t:"
  BUILDER_SETEXEC="$(sesearch --allow -s docker_helper_builder_t -c process -p setexec /sys/fs/selinux/policy 2>/dev/null || true)"
  printf '%s\n' "${BUILDER_SETEXEC:-(none)}"
  echo "--- every domain holding setexec (inventory; the base policy's own grants are expected here):"
  sesearch --allow -c process -p setexec /sys/fs/selinux/policy || true
  if [ -n "$LAUNCHER_SETEXEC" ] && [ -z "$BUILDER_SETEXEC" ]; then
    echo "PASS: the setexec split holds"
  else
    echo "FAIL: the setexec split does not hold"
    PREFLIGHT_OK=0
  fi

  echo "=== nsenter exec identity (the 4C-3 composition: the dedicated type, the exact packaged path, same-domain exec) ==="
  echo "--- the stand probe (02-nsenter-probe.txt):"
  cat "$EVIDENCE_DIR/02-nsenter-probe.txt" 2>/dev/null || true
  echo "--- loaded-policy facts:"
  echo "type inventory (docker_helper_nsenter_exec_t must be declared; docker_helper_nsenter_t must NOT exist):"
  seinfo -t /sys/fs/selinux/policy 2>/dev/null | grep -a "docker_helper_nsenter" || true
  echo "allow rules on nsenter_exec_t (expected: the rootlesskit child's same-domain exec only):"
  sesearch --allow -t docker_helper_nsenter_exec_t /sys/fs/selinux/policy || true
  echo "type_transition rules mentioning nsenter_exec_t (must be zero):"
  sesearch --type_trans /sys/fs/selinux/policy 2>/dev/null | awk '$3 ~ /docker_helper_nsenter_exec_t/' || true
  NSENTER_PATH_OK=0; NSENTER_LABEL_OK=0; NSENTER_TRANS_OK=0
  if grep -aq "readlink -f:  /usr/bin/nsenter" "$EVIDENCE_DIR/02-nsenter-probe.txt" 2>/dev/null; then
    NSENTER_PATH_OK=1
  fi
  if matchpathcon /usr/bin/nsenter 2>/dev/null | grep -aq "object_r:docker_helper_nsenter_exec_t:s0"; then
    NSENTER_LABEL_OK=1
  fi
  if ! sesearch --type_trans /sys/fs/selinux/policy 2>/dev/null | grep -aq "docker_helper_nsenter"; then
    NSENTER_TRANS_OK=1
  fi
  if [ "$NSENTER_PATH_OK" = 1 ] && [ "$NSENTER_LABEL_OK" = 1 ] && [ "$NSENTER_TRANS_OK" = 1 ]; then
    echo "PASS: nsenter exec identity (exact packaged path + dedicated label + no transition)"
  else
    echo "FAIL: nsenter exec identity (path=$NSENTER_PATH_OK label=$NSENTER_LABEL_OK transition-absent=$NSENTER_TRANS_OK)"
    PREFLIGHT_OK=0
  fi

  echo "=== ip execution identity (the 4C-6 composition: the distro ifconfig_exec_t identity, same-domain exec, NO ifconfig_t transition) ==="
  echo "--- the stand probe (02-ip-probe.txt):"
  cat "$EVIDENCE_DIR/02-ip-probe.txt" 2>/dev/null || true
  echo "--- loaded-policy facts:"
  echo "allow rules on ifconfig_exec_t (expected: the rootlesskit child's same-domain exec only):"
  sesearch --allow -t ifconfig_exec_t /sys/fs/selinux/policy || true
  echo "type_transition rules from the flow domain on ifconfig_exec_t (must be zero):"
  sesearch --type_trans /sys/fs/selinux/policy 2>/dev/null | awk '$2 == "docker_helper_rootlesskit_t" && $3 ~ /ifconfig_exec_t/' || true
  echo "flow-domain rules toward the distro ifconfig_t domain (raw; the base policy's attribute-generic domain rules are expected here):"
  sesearch --allow -s docker_helper_rootlesskit_t -t ifconfig_t /sys/fs/selinux/policy || true
  echo "--- CONCRETE flow->ifconfig_t rules (must be zero; attribute-generic 'allow domain domain:*' base rules are not ifconfig-specific authority):"
  sesearch --allow -s docker_helper_rootlesskit_t -t ifconfig_t /sys/fs/selinux/policy 2>/dev/null | awk '$2 == "docker_helper_rootlesskit_t"' || true
  echo "--- the distro's shared network-tool type (fcontext inventory of ifconfig_exec_t):"
  semanage fcontext -l 2>/dev/null | grep -a "ifconfig_exec_t" || true
  IP_PATH_OK=0; IP_LABEL_OK=0; IP_TRANS_OK=0; IP_NOTRANS_T_OK=0
  if grep -aq "readlink -f:  /usr/sbin/ip" "$EVIDENCE_DIR/02-ip-probe.txt" 2>/dev/null; then
    IP_PATH_OK=1
  fi
  if matchpathcon /usr/sbin/ip 2>/dev/null | grep -aq "object_r:ifconfig_exec_t:s0"; then
    IP_LABEL_OK=1
  fi
  if ! sesearch --type_trans /sys/fs/selinux/policy 2>/dev/null | awk '$2 == "docker_helper_rootlesskit_t" && $3 ~ /ifconfig_exec_t/' | grep -aq .; then
    IP_TRANS_OK=1
  fi
  if ! sesearch --allow -s docker_helper_rootlesskit_t -t ifconfig_t /sys/fs/selinux/policy 2>/dev/null | awk '$2 == "docker_helper_rootlesskit_t"' | grep -aq .; then
    IP_NOTRANS_T_OK=1
  fi
  if [ "$IP_PATH_OK" = 1 ] && [ "$IP_LABEL_OK" = 1 ] && [ "$IP_TRANS_OK" = 1 ] && [ "$IP_NOTRANS_T_OK" = 1 ]; then
    echo "PASS: ip execution identity (distro ifconfig_exec_t + same-domain exec + no ifconfig_t transition)"
  else
    echo "FAIL: ip execution identity (path=$IP_PATH_OK label=$IP_LABEL_OK transition-absent=$IP_TRANS_OK no-ifconfig_t=$IP_NOTRANS_T_OK)"
    PREFLIGHT_OK=0
  fi

  echo "=== TUN device-node access identity (the 4C-17 composition: the distro tun_tap_device_t identity, exactly { read write open ioctl } ordinary + the exact TUNSETIFF+TUNSETPERSIST xperm { 0x54ca 0x54cb }, no third ioctl command, no capability surface) ==="
  # NOTE (4C-12 harness-mechanics correction, still current): a refpolicy
  # macro's NAME does not exist after policy compilation — sesearch sees
  # only the resulting AV rules — so macro provenance (the
  # corenet_rw_tun_tap_dev ban) is asserted at SOURCE level by the Go
  # policy test, never by sesearch here. This preflight asserts the
  # effective concrete permission surface.
  echo "--- the stand probe (02-tun-probe.txt):"
  cat "$EVIDENCE_DIR/02-tun-probe.txt" 2>/dev/null || true
  echo "--- toolchain encoding gate (allowxperm must survive the real toolchain; compile/package/load failures above exit INCOMPLETE before any load):"
  if grep -aqx 'allowxperm docker_helper_rootlesskit_t tun_tap_device_t:chr_file ioctl { 0x54ca 0x54cb };' "$TRANSFERRED/docker-helper.te"; then
    echo "PASS: the transferred .te carries the exact pinned two-command allowxperm rule; checkmodule 4-24-era semantics accepted it (compile rc=0 recorded in 01-composition-inputs.txt)"
  else
    echo "FAIL: the transferred .te does not carry the exact pinned allowxperm rule"
    PREFLIGHT_OK=0
  fi
  echo "--- STEP 1: ordinary effective surface BEFORE dispatch (rootlesskit -> tun_tap_device_t chr_file; base-policy expansions recorded, not asserted):"
  sesearch --allow -s docker_helper_rootlesskit_t -t tun_tap_device_t -c chr_file /sys/fs/selinux/policy || true
  echo "--- STEP 1 CONCRETE module contribution (source must be docker_helper_rootlesskit_t; must be exactly read+write+open+ioctl):"
  sesearch --allow -s docker_helper_rootlesskit_t -t tun_tap_device_t -c chr_file /sys/fs/selinux/policy 2>/dev/null | awk '$2 == "docker_helper_rootlesskit_t"' || true
  echo "--- STEP 2: allowxperm rules queried SEPARATELY (raw xperm inventory; stderr kept apart for the toolchain gate):"
  XP_TOOL_ERR=/tmp/p4b-work/sesearch-xperm.stderr
  XP_RAW="$(sesearch --allowxperm -s docker_helper_rootlesskit_t -t tun_tap_device_t -c chr_file /sys/fs/selinux/policy 2>"$XP_TOOL_ERR" || true)"
  if [ -s "$XP_TOOL_ERR" ]; then
    echo "sesearch --allowxperm stderr:"
    cat "$XP_TOOL_ERR"
  fi
  if grep -aqE 'invalid option|unrecognized|unknown option|Usage:' "$XP_TOOL_ERR" 2>/dev/null; then
    echo "TOOLCHAIN-GATE: this stand's sesearch cannot query allowxperm rules — the xperm authority cannot be proven on the loaded policy; STOP with no verdict and NO broad ioctl fallback"
    TUN_TOOLCHAIN_BLOCKED=1
    PREFLIGHT_OK=0
  elif [ -n "$XP_RAW" ]; then
    printf '%s\n' "$XP_RAW"
    echo "PASS: sesearch exposes the loaded xperm rule (toolchain query gate)"
  else
    echo "FAIL: sesearch --allowxperm returned ZERO rules — the loaded policy does not carry the module's TUNSETIFF xperm rule"
    PREFLIGHT_OK=0
  fi
  echo "--- STEP 2 effective xperm union (every hex command value across the raw inventory — attribute-derived/base-policy contributions count; the security verdict):"
  XP_UNION="$(printf '%s\n' "$XP_RAW" | grep -aoE '0x[0-9a-fA-F]+' | tr 'A-F' 'a-f' | sort -u | tr '\n' ' ' || true)"
  echo "effective union: ${XP_UNION:-(empty)}"
  XP_EXACT_OK=0
  if [ "$XP_UNION" = "0x54ca 0x54cb " ]; then
    echo "PASS: effective xperm union is EXACTLY { 0x54ca 0x54cb } (TUNSETIFF + TUNSETPERSIST)"
    XP_EXACT_OK=1
  else
    echo "FAIL: effective xperm union is not exactly { 0x54ca 0x54cb } (got: ${XP_UNION:-(empty)})"
    PREFLIGHT_OK=0
  fi
  echo "--- explicit beyond-the-two negatives (no third TUN ioctl command):"
  THIRD_CMD_OK=1
  for tok in $XP_UNION; do
    case "$tok" in
      0x54ca|0x54cb) ;;
      *) THIRD_CMD_OK=0; echo "extra effective command: $tok" ;;
    esac
  done
  if [ "$THIRD_CMD_OK" = 1 ]; then
    echo "PASS: no effective command beyond { 0x54ca, 0x54cb } (TUNSETOWNER/TUNSETGROUP/TUNSETLINK/TUNGETFEATURES/TUNSETOFFLOAD/TUNSETQUEUE and every other command stay denied)"
  else
    echo "FAIL: an effective ioctl command beyond { 0x54ca 0x54cb } is present"
    PREFLIGHT_OK=0
  fi
  echo "--- flow-domain plain capability net_admin/net_raw (must be zero; the in-namespace cap_userns net_admin authority lives ONLY in the child's own cap_userns rule — the 4C-15 grant — never in a TUN rule; asserted positively by the flow cap_userns identity section):"
  sesearch --allow -s docker_helper_rootlesskit_t -c capability -p net_admin /sys/fs/selinux/policy || true
  sesearch --allow -s docker_helper_rootlesskit_t -c capability -p net_raw /sys/fs/selinux/policy || true
  TUN_PAIR_OK=0; TUN_NO_MORE_OK=0; TUN_LABEL_OK=0; TUN_NO_NETADMIN_OK=0
  TUN_TOOLCHAIN_BLOCKED=0
  TUN_CONCRETE="$(sesearch --allow -s docker_helper_rootlesskit_t -t tun_tap_device_t -c chr_file /sys/fs/selinux/policy 2>/dev/null | awk '$2 == "docker_helper_rootlesskit_t"' || true)"
  if printf '%s\n' "$TUN_CONCRETE" | grep -aq "read" && printf '%s\n' "$TUN_CONCRETE" | grep -aq "write" \
    && printf '%s\n' "$TUN_CONCRETE" | grep -aq "open" && printf '%s\n' "$TUN_CONCRETE" | grep -aq "ioctl"; then
    TUN_PAIR_OK=1
  fi
  if ! printf '%s\n' "$TUN_CONCRETE" | grep -aqE "append|lock|create|setattr|getattr|exec"; then
    TUN_NO_MORE_OK=1
  fi
  if [ -e /dev/net/tun ]; then
    if matchpathcon /dev/net/tun 2>/dev/null | grep -aq "object_r:tun_tap_device_t:s0"; then
      TUN_LABEL_OK=1
    else
      echo "the stand's /dev/net/tun exists but is NOT tun_tap_device_t (evidence recorded above)"
    fi
  else
    echo "/dev/net/tun absent on the stand (evidence-only fact; the live AVC tcontext remains the type authority)"
    TUN_LABEL_OK=1
  fi
  if ! { sesearch --allow -s docker_helper_rootlesskit_t -c capability -p net_admin /sys/fs/selinux/policy 2>/dev/null; \
         sesearch --allow -s docker_helper_rootlesskit_t -c capability -p net_raw /sys/fs/selinux/policy 2>/dev/null; } | grep -aq "docker_helper_rootlesskit_t"; then
    TUN_NO_NETADMIN_OK=1
  fi
  if [ "$TUN_PAIR_OK" = 1 ] && [ "$TUN_NO_MORE_OK" = 1 ] && [ "$TUN_LABEL_OK" = 1 ] && [ "$TUN_NO_NETADMIN_OK" = 1 ]; then
    echo "PASS: tun device-node access identity (distro tun_tap_device_t + exactly { read write open ioctl } + effective xperm union exactly { 0x54ca 0x54cb }, no third command, no capability surface)"
  else
    echo "FAIL: tun device-node access identity (pair=$TUN_PAIR_OK no-more=$TUN_NO_MORE_OK label=$TUN_LABEL_OK no-netadmin=$TUN_NO_NETADMIN_OK xperm-union=$XP_EXACT_OK toolchain-blocked=$TUN_TOOLCHAIN_BLOCKED)"
    PREFLIGHT_OK=0
  fi

  echo "=== flow cap_userns identity (the 4C-15 composition: exactly { sys_admin sys_ptrace sys_chroot net_admin }, exactly one rule, in-userns only — the plain capability class stays zero) ==="
  echo "--- raw effective inventory (rootlesskit -> cap_userns; base-policy expansions recorded, not asserted):"
  sesearch --allow -s docker_helper_rootlesskit_t -c cap_userns /sys/fs/selinux/policy || true
  echo "--- CONCRETE module contribution (source must be docker_helper_rootlesskit_t; the perm set must be EXACTLY the four evidenced bits):"
  CAP_CONCRETE="$(sesearch --allow -s docker_helper_rootlesskit_t -c cap_userns /sys/fs/selinux/policy 2>/dev/null | awk '$2 == "docker_helper_rootlesskit_t"' || true)"
  printf '%s\n' "${CAP_CONCRETE:-(none)}"
  CAP_SET_OK=0
  CAP_SET="$(printf '%s\n' "$CAP_CONCRETE" | sed -n 's/.*{ \(.*\) };/\1/p' | tr ' ' '\n' | sort | tr '\n' ' ' || true)"
  echo "extracted perm set: ${CAP_SET:-(none)}"
  if [ "$CAP_SET" = "net_admin sys_admin sys_chroot sys_ptrace " ]; then
    CAP_SET_OK=1
  fi
  echo "--- plain capability negatives (rootlesskit self:capability net_admin/net_raw must be absent — the live AVCs name cap_userns, never capability):"
  sesearch --allow -s docker_helper_rootlesskit_t -c capability -p net_admin /sys/fs/selinux/policy || true
  sesearch --allow -s docker_helper_rootlesskit_t -c capability -p net_raw /sys/fs/selinux/policy || true
  CAP_CAPNEG_OK=0
  if ! { sesearch --allow -s docker_helper_rootlesskit_t -c capability -p net_admin /sys/fs/selinux/policy 2>/dev/null; \
         sesearch --allow -s docker_helper_rootlesskit_t -c capability -p net_raw /sys/fs/selinux/policy 2>/dev/null; } | grep -aq "docker_helper_rootlesskit_t"; then
    CAP_CAPNEG_OK=1
  fi
  if [ "$CAP_SET_OK" = 1 ] && [ "$CAP_CAPNEG_OK" = 1 ]; then
    echo "PASS: flow cap_userns identity (exactly { sys_admin sys_ptrace sys_chroot net_admin }, exactly one rule; plain capability net_admin/net_raw absent)"
  else
    echo "FAIL: flow cap_userns identity (set=$CAP_SET_OK capability-negative=$CAP_CAPNEG_OK)"
    PREFLIGHT_OK=0
  fi

  echo "=== flow tun_socket identity (the 4C-16 composition: the concrete contribution must be exactly { create } — the security_tun_dev_create() boundary of the NEW-device TUNSETIFF path; no attach_queue/relabel*, no inherited socket permission) ==="
  echo "--- raw effective inventory (rootlesskit -> tun_socket; base-policy/attribute expansions recorded, not asserted):"
  sesearch --allow -s docker_helper_rootlesskit_t -c tun_socket /sys/fs/selinux/policy || true
  echo "--- CONCRETE module contribution (source must be docker_helper_rootlesskit_t; must be exactly create):"
  TS_CONCRETE="$(sesearch --allow -s docker_helper_rootlesskit_t -c tun_socket /sys/fs/selinux/policy 2>/dev/null | awk '$2 == "docker_helper_rootlesskit_t"' || true)"
  printf '%s\n' "${TS_CONCRETE:-(none)}"
  TS_EXACT_OK=0
  if [ "$(printf '%s\n' "$TS_CONCRETE" | grep -ac . || true)" = 1 ] \
    && printf '%s\n' "$TS_CONCRETE" | grep -aqE ':tun_socket (\{ )?create( \})?;' \
    && ! printf '%s\n' "$TS_CONCRETE" | grep -aqE 'attach_queue|relabelfrom|relabelto'; then
    TS_EXACT_OK=1
  fi
  echo "--- EFFECTIVE negative check (attach_queue/relabelfrom/relabelto must be absent from the whole effective surface — base-policy/attribute-derived contributions count; an extra one is a STOP):"
  TS_EFFECTIVE_EXTRA="$(sesearch --allow -s docker_helper_rootlesskit_t -c tun_socket /sys/fs/selinux/policy 2>/dev/null | grep -aE 'attach_queue|relabelfrom|relabelto' || true)"
  TS_EFFECTIVE_NEG_OK=0
  if [ -z "$TS_EFFECTIVE_EXTRA" ]; then
    echo "PASS: no effective attach_queue/relabelfrom/relabelto authority"
    TS_EFFECTIVE_NEG_OK=1
  else
    echo "STOP: the effective tun_socket surface contains attach_queue/relabelfrom/relabelto (base-policy/attribute-derived):"
    printf '%s\n' "$TS_EFFECTIVE_EXTRA"
    PREFLIGHT_OK=0
  fi
  if [ "$TS_EXACT_OK" = 1 ] && [ "$TS_EFFECTIVE_NEG_OK" = 1 ]; then
    echo "PASS: flow tun_socket identity (exactly { create }, exactly one rule; no attach_queue/relabel* authority)"
  else
    echo "FAIL: flow tun_socket identity (exact=$TS_EXACT_OK effective-negative=$TS_EFFECTIVE_NEG_OK)"
    PREFLIGHT_OK=0
  fi

  echo "=== netlink-route send+lookup+receive+mutation identity (the 4C-22 composition: exactly { create setopt bind getattr write nlmsg_read read nlmsg_write }, no other socket permission, no capability surface) ==="
  echo "--- allow rules on netlink_route_socket (expected: the rootlesskit child's create+setopt+bind+getattr+write+nlmsg_read only; attribute-generic base-policy rules recorded, not asserted):"
  sesearch --allow -c netlink_route_socket /sys/fs/selinux/policy || true
  echo "--- the flow domain's own netlink_route_socket rules (concrete; must be exactly create+setopt+bind+getattr+write+nlmsg_read+read+nlmsg_write):"
  sesearch --allow -s docker_helper_rootlesskit_t -c netlink_route_socket /sys/fs/selinux/policy || true
  echo "--- flow-domain plain capability net_admin/net_raw (must be zero; the in-namespace cap_userns net_admin authority lives ONLY in the child's own cap_userns rule — the 4C-15 grant — never in a netlink rule):"
  sesearch --allow -s docker_helper_rootlesskit_t -c capability -p net_admin /sys/fs/selinux/policy || true
  sesearch --allow -s docker_helper_rootlesskit_t -c capability -p net_raw /sys/fs/selinux/policy || true
  NL_CREATE_OK=0; NL_SETOPT_OK=0; NL_BIND_OK=0; NL_GETATTR_OK=0; NL_WRITE_OK=0; NL_NLMSG_READ_OK=0; NL_READ_OK=0; NL_NLMSG_WRITE_OK=0; NL_NO_MORE_OK=0; NL_NO_NETADMIN_OK=0
  NL_FLOW_RULES="$(sesearch --allow -s docker_helper_rootlesskit_t -c netlink_route_socket /sys/fs/selinux/policy 2>/dev/null || true)"
  if printf '%s\n' "$NL_FLOW_RULES" | grep -aq "create"; then
    NL_CREATE_OK=1
  fi
  if printf '%s\n' "$NL_FLOW_RULES" | grep -aq "setopt"; then
    NL_SETOPT_OK=1
  fi
  if printf '%s\n' "$NL_FLOW_RULES" | grep -aq "bind"; then
    NL_BIND_OK=1
  fi
  if printf '%s\n' "$NL_FLOW_RULES" | grep -aq "getattr"; then
    NL_GETATTR_OK=1
  fi
  if printf '%s\n' "$NL_FLOW_RULES" | grep -aq " write"; then
    NL_WRITE_OK=1
  fi
  if printf '%s\n' "$NL_FLOW_RULES" | grep -aq "nlmsg_read"; then
    NL_NLMSG_READ_OK=1
  fi
  if printf '%s\n' "$NL_FLOW_RULES" | grep -aqw "read"; then
    NL_READ_OK=1
  fi
  if printf '%s\n' "$NL_FLOW_RULES" | grep -aqw "nlmsg_write"; then
    NL_NLMSG_WRITE_OK=1
  fi
  # The 4C-22 no-more check: connect/getopt/ioctl/shutdown stay closed
  # (read, nlmsg_read, and nlmsg_write are now evidenced).
  if ! printf '%s\n' "$NL_FLOW_RULES" | grep -aqE "getopt|connect|ioctl|shutdown"; then
    NL_NO_MORE_OK=1
  fi
  echo "--- the message-level absence proof (each individually; none may be present):"
  for denied_perm in connect ioctl getopt shutdown; do
    if printf '%s\n' "$NL_FLOW_RULES" | grep -aqw "$denied_perm"; then
      echo "PRESENT (must not be): $denied_perm"
      NL_NO_MORE_OK=0
    else
      echo "absent: $denied_perm"
    fi
  done
  echo "--- flow-domain dontaudit inventory on netlink_route_socket (audit-suppression provenance; captured on the production baseline BEFORE any diagnostic leg):"
  sesearch --dontaudit -s docker_helper_rootlesskit_t -c netlink_route_socket /sys/fs/selinux/policy || true

  echo "=== slirp4netns helper cross-domain inventory (the 4C-24 composition: exactly one dir-search + exactly one lnk_file-read grant toward the rootlesskit namespace target; NO file namespace-path pre-grant; NO capability) ==="
  echo "--- the helper's own allows toward docker_helper_rootlesskit_t (concrete; the target-specific set: the pinned dir+lnk_file rules + the fifo rule + the distro's attribute-generic fd/key expansions):"
  sesearch --allow -s docker_helper_slirp4netns_t -t docker_helper_rootlesskit_t /sys/fs/selinux/policy || true
  echo "--- the helper's allows toward its own entry type:"
  sesearch --allow -s docker_helper_slirp4netns_t -t docker_helper_slirp4netns_exec_t /sys/fs/selinux/policy || true
  echo "--- the helper's whole -c dir sweep (RECORDED ONLY: the distro's domain template grants generic dir access through attribute expansion; the module's own authority is the single rootlesskit-target rule below):"
  sesearch --allow -s docker_helper_slirp4netns_t -c dir /sys/fs/selinux/policy || true
  echo "--- the helper's capability/cap_userns surface (the 4C-30 namespace-join widening: EXACTLY one self:cap_userns { sys_ptrace sys_admin } rule; no other cap bit, no plain capability):"
  sesearch --allow -s docker_helper_slirp4netns_t -c capability /sys/fs/selinux/policy || true
  sesearch --allow -s docker_helper_slirp4netns_t -c cap_userns /sys/fs/selinux/policy || true
  SL_OK=0; SL_DIR_COUNT_OK=0; SL_DIR_SHAPE_OK=0; SL_LNK_COUNT_OK=0; SL_LNK_SHAPE_OK=0; SL_FILE_COUNT_OK=0; SL_FILE_SHAPE_OK=0; SL_NO_EXTRA_OK=0; SL_CAP_COUNT_OK=0; SL_CAP_SHAPE_OK=0; SL_NO_CAP_OK=0
  SL_TGT_RULES="$(sesearch --allow -s docker_helper_slirp4netns_t -t docker_helper_rootlesskit_t /sys/fs/selinux/policy 2>/dev/null || true)"
  SL_DIR_RULES="$(printf '%s\n' "$SL_TGT_RULES" | grep -a ':dir[ ;]' || true)"
  if [ "$(printf '%s\n' "$SL_DIR_RULES" | grep -ac 'rootlesskit_t:dir search;')" = 1 ]; then
    SL_DIR_COUNT_OK=1
    SL_DIR_SHAPE_OK=1
  fi
  SL_LNK_RULES="$(printf '%s\n' "$SL_TGT_RULES" | grep -a ':lnk_file[ ;]' || true)"
  if [ "$(printf '%s\n' "$SL_LNK_RULES" | grep -ac 'rootlesskit_t:lnk_file read;')" = 1 ]; then
    SL_LNK_COUNT_OK=1
    SL_LNK_SHAPE_OK=1
  fi
  SL_FILE_RULES="$(printf '%s\n' "$SL_TGT_RULES" | grep -a ':file[ ;]' || true)"
  if [ "$(printf '%s\n' "$SL_FILE_RULES" | grep -ac 'rootlesskit_t:file read;')" = 1 ]; then
    SL_FILE_COUNT_OK=1
    SL_FILE_SHAPE_OK=1
  fi
  # No extra target-specific file-class authority: the file set must be
  # EXACTLY the single read rule (no open/getattr/write), and the lnk
  # set exactly the single read rule.
  if [ "$SL_FILE_COUNT_OK" = 1 ] && [ "$SL_FILE_SHAPE_OK" = 1 ] && [ "$(printf '%s\n' "$SL_FILE_RULES" | grep -ac .)" = 1 ] \
    && [ "$(printf '%s\n' "$SL_LNK_RULES" | grep -ac .)" = 1 ]; then
    SL_NO_EXTRA_OK=1
  fi
  SL_CAP_RULES="$(sesearch --allow -s docker_helper_slirp4netns_t -c cap_userns /sys/fs/selinux/policy 2>/dev/null | grep -a 'docker_helper_slirp4netns_t:cap_userns' || true)"
  if [ "$(printf '%s\n' "$SL_CAP_RULES" | grep -ac .)" = 1 ]; then
    SL_CAP_COUNT_OK=1
  fi
  # Order-independent shape: the single rule's perm set must fold to
  # exactly { sys_admin sys_ptrace } (setools renders perm sets
  # alphabetically — the 4C-29 run proved the rendering; the 4C-30
  # widening's sys_admin member must be present and nothing else).
  SL_CAP_SET="$(printf '%s\n' "$SL_CAP_RULES" \
    | sed -n 's/.*:cap_userns {\(.*\)};$/\1/p' \
    | sed 's/^[{ ]*//; s/[} ]*$//' \
    | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "helper cap_userns effective perm set: ${SL_CAP_SET:-(none)}"
  if [ "$SL_CAP_SET" = "sys_admin sys_ptrace " ]; then
    SL_CAP_SHAPE_OK=1
  fi
  # The helper's capability surface after 4C-25: no PLAIN capability/
  # capability2 rule, and no cap_userns rule beyond the one
  # self:cap_userns sys_ptrace grant.
  if ! sesearch --allow -s docker_helper_slirp4netns_t -c capability /sys/fs/selinux/policy 2>/dev/null | grep -aq 'docker_helper_slirp4netns_t' \
    && [ "$SL_CAP_COUNT_OK" = 1 ] && [ "$SL_CAP_SHAPE_OK" = 1 ]; then
    SL_NO_CAP_OK=1
  fi
  if [ -n "$SL_TGT_RULES" ] && [ "$SL_DIR_COUNT_OK" = 1 ] && [ "$SL_DIR_SHAPE_OK" = 1 ] && [ "$SL_LNK_COUNT_OK" = 1 ] && [ "$SL_LNK_SHAPE_OK" = 1 ] && [ "$SL_FILE_COUNT_OK" = 1 ] && [ "$SL_FILE_SHAPE_OK" = 1 ] && [ "$SL_NO_EXTRA_OK" = 1 ] && [ "$SL_CAP_COUNT_OK" = 1 ] && [ "$SL_CAP_SHAPE_OK" = 1 ] && [ "$SL_NO_CAP_OK" = 1 ]; then
    echo "PASS: slirp4netns helper cross-domain inventory (exactly one dir-search, one lnk_file-read, and one file-read rule toward the rootlesskit target, exactly one self:cap_userns rule whose perm set is exactly { sys_ptrace sys_admin }, no other capability surface)"
    SL_OK=1
  else
    echo "FAIL: slirp4netns helper cross-domain inventory (dir-count=$SL_DIR_COUNT_OK dir-shape=$SL_DIR_SHAPE_OK lnk-count=$SL_LNK_COUNT_OK lnk-shape=$SL_LNK_SHAPE_OK file-count=$SL_FILE_COUNT_OK file-shape=$SL_FILE_SHAPE_OK no-extra=$SL_NO_EXTRA_OK cap-count=$SL_CAP_COUNT_OK cap-shape=$SL_CAP_SHAPE_OK no-cap=$SL_NO_CAP_OK)"
    PREFLIGHT_OK=0
  fi

  echo "=== slirp4netns helper nsfs namespace-handle inventory (the 4C-29 composition: the EFFECTIVE helper -> nsfs authority must be EXACTLY { read open } — no getattr/ioctl/lock/write/map/execute from ANY source, distro attribute expansion included; an effective extra is a STOP, not a pin violation) ==="
  echo "--- raw effective inventory (slirp4netns -> nsfs; attribute/base-policy expansions recorded, not asserted per-rule):"
  sesearch --allow -s docker_helper_slirp4netns_t -t nsfs_t /sys/fs/selinux/policy || true
  echo "--- CONCRETE module contribution (source must be docker_helper_slirp4netns_t; must be EXACTLY one nsfs_t:file rule whose perm set folds to { open read }; NOTE: setools renders perm sets alphabetically — the 4C-29 run proved { read open } source renders as { open read }):"
  SL_NSFS_RULES="$(sesearch --allow -s docker_helper_slirp4netns_t -t nsfs_t /sys/fs/selinux/policy 2>/dev/null | awk '$2 == "docker_helper_slirp4netns_t"' || true)"
  printf '%s\n' "${SL_NSFS_RULES:-(none)}"
  SL_NSFS_COUNT_OK=0; SL_NSFS_SHAPE_OK=0; SL_NSFS_UNION_OK=0; SL_NSFS_CLASS_OK=0; SL_NSFS_NO_FLOW_GRANT_OK=0
  SL_NSFS_CONCRETE_COUNT="$(printf '%s\n' "$SL_NSFS_RULES" | grep -ac . || true)"
  SL_NSFS_CONCRETE_SET="$(printf '%s\n' "$SL_NSFS_RULES" \
    | sed -n 's/^allow [^ ]* nsfs_t:file {\(.*\)};$/\1/p' \
    | sed 's/^[{ ]*//; s/[} ]*$//' \
    | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "concrete rule's perm token set: ${SL_NSFS_CONCRETE_SET:-(empty)}"
  if [ "$SL_NSFS_CONCRETE_COUNT" = 1 ] && [ "$SL_NSFS_CONCRETE_SET" = "open read " ]; then
    SL_NSFS_COUNT_OK=1
    SL_NSFS_SHAPE_OK=1
  fi
  # The effective perm union across the WHOLE helper -> nsfs surface:
  # single-perm rules render bare, multi-perm rules render in braces;
  # both forms fold into one token set which must be exactly
  # { open read } (sorted) — any other permission (the named negatives
  # getattr/ioctl/lock/write/map/execute included) breaks the equality.
  SL_NSFS_UNION="$(sesearch --allow -s docker_helper_slirp4netns_t -t nsfs_t /sys/fs/selinux/policy 2>/dev/null \
    | grep -a 'nsfs_t:file' \
    | sed -n 's/^allow [^ ]* nsfs_t:file \(.*\);$/\1/p' \
    | sed 's/^[{ ]*//; s/[} ]*$//' \
    | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "effective helper -> nsfs:file perm union: ${SL_NSFS_UNION:-(empty)}"
  if [ "$SL_NSFS_UNION" = "open read " ]; then
    SL_NSFS_UNION_OK=1
  fi
  # Any EFFECTIVE nsfs authority in a NON-file class is an extra too.
  SL_NSFS_OTHER_CLASS="$(sesearch --allow -s docker_helper_slirp4netns_t -t nsfs_t /sys/fs/selinux/policy 2>/dev/null | grep -av 'nsfs_t:file' || true)"
  if [ -z "$SL_NSFS_OTHER_CLASS" ]; then
    SL_NSFS_CLASS_OK=1
  else
    echo "STOP: the effective helper -> nsfs surface contains a non-file class:"
    printf '%s\n' "$SL_NSFS_OTHER_CLASS"
  fi
  echo "--- the helper's dontaudit surface toward nsfs (RECORDED SEPARATELY per the 4C-28 preflight contract; never merged into the allow verdict):"
  SL_NSFS_DONTAUDIT="$(sesearch --dontaudit -s docker_helper_slirp4netns_t -t nsfs_t /sys/fs/selinux/policy 2>/dev/null || true)"
  printf '%s\n' "${SL_NSFS_DONTAUDIT:-(none — no dontaudit rule hides helper -> nsfs denials)}"
  echo "--- the flow domain's effective nsfs surface (the 4C-27-observed docker_helper_rootlesskit_t -> nsfs_t:file getattr denial stays UNGRANTED — a separate candidate boundary, not this phase's grant):"
  sesearch --allow -s docker_helper_rootlesskit_t -t nsfs_t /sys/fs/selinux/policy || true
  RK_NSFS_CONCRETE="$(sesearch --allow -s docker_helper_rootlesskit_t -t nsfs_t /sys/fs/selinux/policy 2>/dev/null | awk '$2 == "docker_helper_rootlesskit_t"' || true)"
  printf '%s\n' "${RK_NSFS_CONCRETE:-(none — the module contributes NO rootlesskit -> nsfs rule)}"
  if [ -z "$RK_NSFS_CONCRETE" ]; then
    SL_NSFS_NO_FLOW_GRANT_OK=1
  fi
  echo "--- the transferred source's macro-exclusion gate (fs_read_nsfs_files must not appear outside comments; macro names do not exist post-compilation, so this is asserted at source level, like the 4C-12 xperm provenance):"
  if grep -av '^[[:space:]]*#' "$TRANSFERRED/docker-helper.te" | grep -aq 'fs_read_nsfs_files'; then
    echo "FAIL: the transferred .te uses the distro fs_read_nsfs_files interface (its read_file_perms expansion is broader than the evidenced read)"
    PREFLIGHT_OK=0
  else
    echo "PASS: no fs_read_nsfs_files interface use outside comments"
  fi
  if [ "$SL_NSFS_COUNT_OK" = 1 ] && [ "$SL_NSFS_SHAPE_OK" = 1 ] && [ "$SL_NSFS_UNION_OK" = 1 ] && [ "$SL_NSFS_CLASS_OK" = 1 ] && [ "$SL_NSFS_NO_FLOW_GRANT_OK" = 1 ]; then
    echo "PASS: slirp4netns helper nsfs namespace-handle inventory (exactly one nsfs_t:file { read open } rule; the effective union is exactly { read open }; no non-file class; no rootlesskit -> nsfs grant)"
  else
    echo "FAIL: slirp4netns helper nsfs namespace-handle inventory (count=$SL_NSFS_COUNT_OK shape=$SL_NSFS_SHAPE_OK union=$SL_NSFS_UNION_OK class=$SL_NSFS_CLASS_OK no-flow-grant=$SL_NSFS_NO_FLOW_GRANT_OK)"
    PREFLIGHT_OK=0
  fi
  echo "=== slirp4netns helper TUN device-node inventory (the 4C-36 composition: the EFFECTIVE helper -> tun_tap_device_t authority must be EXACTLY chr_file { read write open ioctl } ordinary + allowxperm ioctl { 0x54ca } — the single live-proven TUNSETIFF command; no getattr/append/lock/create/setattr, no second/third ioctl command, no helper tun_socket authority beyond the single cross-domain relabelfrom rule plus the single self relabelto rule, from ANY source, distro attribute expansion included; an effective extra is a STOP, not a pin violation) ==="
  echo "--- raw effective inventory (slirp4netns -> tun_tap_device_t; attribute/base-policy expansions recorded, not asserted per-rule):"
  sesearch --allow -s docker_helper_slirp4netns_t -t tun_tap_device_t /sys/fs/selinux/policy || true
  echo "--- CONCRETE module contribution (source must be docker_helper_slirp4netns_t; must be EXACTLY one tun_tap_device_t:chr_file rule whose perm set folds to { read write open ioctl }; NOTE: setools renders perm sets alphabetically — the 4C-29 run proved { read open } source renders as { open read }, so the 4C-33 set renders as { ioctl open read write }):"
  SL_TUN_RULES="$(sesearch --allow -s docker_helper_slirp4netns_t -t tun_tap_device_t /sys/fs/selinux/policy 2>/dev/null | awk '$2 == "docker_helper_slirp4netns_t"' || true)"
  printf '%s\n' "${SL_TUN_RULES:-(none)}"
  SL_TUN_COUNT_OK=0; SL_TUN_SHAPE_OK=0; SL_TUN_UNION_OK=0; SL_TUN_CLASS_OK=0
  SL_TUNSOCK_COUNT_OK=0; SL_TUNSOCK_SHAPE_OK=0; SL_TUNSOCK_UNION_OK=0; SL_TUNSOCK_SELF_UNION_OK=0; SL_TUNSOCK_NOTARGET_OK=0
  SL_TUN_CONCRETE_COUNT="$(printf '%s\n' "$SL_TUN_RULES" | grep -ac . || true)"
  SL_TUN_CONCRETE_SET="$(printf '%s\n' "$SL_TUN_RULES" \
    | sed -n 's/^allow [^ ]* tun_tap_device_t:chr_file {\(.*\)};$/\1/p' \
    | sed 's/^[{ ]*//; s/[} ]*$//' \
    | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "concrete rule's perm token set: ${SL_TUN_CONCRETE_SET:-(empty)}"
  if [ "$SL_TUN_CONCRETE_COUNT" = 1 ] && [ "$SL_TUN_CONCRETE_SET" = "ioctl open read write " ]; then
    SL_TUN_COUNT_OK=1
    SL_TUN_SHAPE_OK=1
  fi
  # The effective perm union across the WHOLE helper -> tun_tap_device_t
  # surface: chr_file single-perm rules render bare, multi-perm rules in
  # braces; both fold into one token set which must be exactly
  # { ioctl open read write } (sorted) — any other permission (the named negatives
  # getattr/append/lock/create/setattr included) breaks the equality.
  SL_TUN_UNION="$(sesearch --allow -s docker_helper_slirp4netns_t -t tun_tap_device_t /sys/fs/selinux/policy 2>/dev/null \
    | grep -a 'tun_tap_device_t:chr_file' \
    | sed -n 's/^allow [^ ]* tun_tap_device_t:chr_file \(.*\);$/\1/p' \
    | sed 's/^[{ ]*//; s/[} ]*$//' \
    | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "effective helper -> tun_tap_device_t:chr_file perm union: ${SL_TUN_UNION:-(empty)}"
  if [ "$SL_TUN_UNION" = "ioctl open read write " ]; then
    SL_TUN_UNION_OK=1
  fi
  # Any EFFECTIVE tun_tap_device_t authority in a NON-chr_file class is
  # an extra too.
  SL_TUN_OTHER_CLASS="$(sesearch --allow -s docker_helper_slirp4netns_t -t tun_tap_device_t /sys/fs/selinux/policy 2>/dev/null | grep -av 'tun_tap_device_t:chr_file' || true)"
  if [ -z "$SL_TUN_OTHER_CLASS" ]; then
    SL_TUN_CLASS_OK=1
  else
    echo "STOP: the effective helper -> tun_tap_device_t surface contains a non-chr_file class:"
    printf '%s\n' "$SL_TUN_OTHER_CLASS"
  fi
  # The 4C-35/4C-36 TUN socket-relabel surface: the helper holds EXACTLY
  # TWO tun_socket rules — the cross-domain relabelfrom toward the
  # rootlesskit target (the 4C-34 canonical run's terminal boundary,
  # record 2339) and the SELF-targeted relabelto (the 4C-35 canonical
  # run's terminal boundary, record 2309; sesearch resolves `self` to the
  # source type). The negatives: attach_queue/create and every other
  # tun_socket permission (the per-pair union equalities), any rule
  # toward a THIRD target, and any SECOND rule per pair
  # (split/parallel/duplicate equivalents).
  echo "--- the helper's tun_socket inventory (raw; the attach-relabel surface, both sides):"
  SL_TUN_TS="$(sesearch --allow -s docker_helper_slirp4netns_t -c tun_socket /sys/fs/selinux/policy 2>/dev/null | grep -a 'docker_helper_slirp4netns_t' || true)"
  printf '%s\n' "${SL_TUN_TS:-(none — the helper holds NO tun_socket rule)}"
  SL_TUNSOCK_CONCRETE_COUNT="$(printf '%s\n' "$SL_TUN_TS" | grep -ac . || true)"
  SL_TUNSOCK_CROSS_BARE="$(printf '%s\n' "$SL_TUN_TS" \
    | sed -n 's/^allow [^ ]* docker_helper_rootlesskit_t:tun_socket \([^{}]*\);$/\1/p' \
    | sed 's/^[{ ]*//; s/[} ]*$//' \
    | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  SL_TUNSOCK_CROSS_BRACED="$(printf '%s\n' "$SL_TUN_TS" \
    | sed -n 's/^allow [^ ]* docker_helper_rootlesskit_t:tun_socket {\(.*\)};$/\1/p' \
    | sed 's/^[{ ]*//; s/[} ]*$//' \
    | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  SL_TUNSOCK_SELF_BARE="$(printf '%s\n' "$SL_TUN_TS" \
    | sed -n 's/^allow [^ ]* docker_helper_slirp4netns_t:tun_socket \([^{}]*\);$/\1/p' \
    | sed 's/^[{ ]*//; s/[} ]*$//' \
    | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  SL_TUNSOCK_SELF_BRACED="$(printf '%s\n' "$SL_TUN_TS" \
    | sed -n 's/^allow [^ ]* docker_helper_slirp4netns_t:tun_socket {\(.*\)};$/\1/p' \
    | sed 's/^[{ ]*//; s/[} ]*$//' \
    | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "cross-side perm set: braced: ${SL_TUNSOCK_CROSS_BRACED:-(none)} / bare: ${SL_TUNSOCK_CROSS_BARE:-(none)}"
  echo "self-side perm set: braced: ${SL_TUNSOCK_SELF_BRACED:-(none)} / bare: ${SL_TUNSOCK_SELF_BARE:-(none)}"
  if [ "$SL_TUNSOCK_CONCRETE_COUNT" = 2 ] && [ "$SL_TUNSOCK_CROSS_BARE" = "relabelfrom " ] && [ -z "$SL_TUNSOCK_CROSS_BRACED" ] && [ "$SL_TUNSOCK_SELF_BARE" = "relabelto " ] && [ -z "$SL_TUNSOCK_SELF_BRACED" ]; then
    SL_TUNSOCK_COUNT_OK=1
    SL_TUNSOCK_SHAPE_OK=1
  fi
  # The EFFECTIVE unions per pair: base-policy/attribute-derived
  # contributions count toward each verdict, and each must fold to
  # EXACTLY its evidenced single permission (any other socket permission
  # — attach_queue/create — breaks the equality).
  SL_TUNSOCK_CROSS_UNION="$(sesearch --allow -s docker_helper_slirp4netns_t -t docker_helper_rootlesskit_t /sys/fs/selinux/policy 2>/dev/null \
    | grep -a 'tun_socket' \
    | sed -n 's/^allow [^ ]* docker_helper_rootlesskit_t:tun_socket \(.*\);$/\1/p' \
    | sed 's/^[{ ]*//; s/[} ]*$//' \
    | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "effective helper -> rootlesskit_t:tun_socket perm union: ${SL_TUNSOCK_CROSS_UNION:-(empty)}"
  if [ "$SL_TUNSOCK_CROSS_UNION" = "relabelfrom " ]; then
    SL_TUNSOCK_UNION_OK=1
  fi
  SL_TUNSOCK_SELF_UNION="$(sesearch --allow -s docker_helper_slirp4netns_t -t docker_helper_slirp4netns_t /sys/fs/selinux/policy 2>/dev/null \
    | grep -a 'tun_socket' \
    | sed -n 's/^allow [^ ]* docker_helper_slirp4netns_t:tun_socket \(.*\);$/\1/p' \
    | sed 's/^[{ ]*//; s/[} ]*$//' \
    | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "effective helper -> self:tun_socket perm union: ${SL_TUNSOCK_SELF_UNION:-(empty)}"
  if [ "$SL_TUNSOCK_SELF_UNION" = "relabelto " ]; then
    SL_TUNSOCK_SELF_UNION_OK=1
  fi
  # Any EFFECTIVE helper tun_socket authority toward a THIRD target is
  # an extra too.
  SL_TUNSOCK_NOTARGET="$(sesearch --allow -s docker_helper_slirp4netns_t -c tun_socket /sys/fs/selinux/policy 2>/dev/null | grep -a 'docker_helper_slirp4netns_t' | grep -avE 'docker_helper_(rootlesskit|slirp4netns)_t:tun_socket' || true)"
  if [ -z "$SL_TUNSOCK_NOTARGET" ]; then
    SL_TUNSOCK_NOTARGET_OK=1
  else
    echo "STOP: the helper's effective tun_socket surface contains a rule toward a third target:"
    printf '%s\n' "$SL_TUNSOCK_NOTARGET"
  fi
  echo "--- explicit beyond-the-two negatives (attach_queue/create must be absent from both effective unions):"
  if [ "$SL_TUNSOCK_UNION_OK" = 1 ] && [ "$SL_TUNSOCK_SELF_UNION_OK" = 1 ]; then
    echo "PASS: the helper's effective tun_socket unions hold no permission beyond { relabelfrom } (cross) and { relabelto } (self) (attach_queue/create and every other socket permission stay denied)"
  else
    echo "FAIL: the helper's effective tun_socket unions are not exactly { relabelfrom } (cross, got: ${SL_TUNSOCK_CROSS_UNION:-(empty)}) and { relabelto } (self, got: ${SL_TUNSOCK_SELF_UNION:-(empty)}); concrete-rules=$SL_TUNSOCK_CONCRETE_COUNT"
    PREFLIGHT_OK=0
  fi
  # The helper's EFFECTIVE allowxperm union (the 4C-34 command filter):
  # every hex command value across ALL allowxperm rules for the helper
  # tuple must fold to EXACTLY { 0x54ca } (TUNSETIFF, the one live-proven
  # command — the 4C-32/4C-33 runs' sys_enter/exit_ioctl records). The
  # RootlessKit staircase's union (exactly { 0x54ca 0x54cb }) stays owned
  # by its own subject-scoped section above. The toolchain gate (the
  # rootlesskit section's allowxperm query) already proved the sesearch
  # build exposes xperm rules, so an empty result here is an absence
  # proof, not a tool limitation.
  echo "--- the helper's allowxperm inventory for the tuple (raw; stderr kept apart):"
  SL_TUN_XP_TOOL_ERR=/tmp/p4b-work/sesearch-sl-tun-xperm.stderr
  SL_TUN_XP_RAW="$(sesearch --allowxperm -s docker_helper_slirp4netns_t -t tun_tap_device_t -c chr_file /sys/fs/selinux/policy 2>"$SL_TUN_XP_TOOL_ERR" || true)"
  if [ -s "$SL_TUN_XP_TOOL_ERR" ]; then
    echo "sesearch --allowxperm stderr:"
    cat "$SL_TUN_XP_TOOL_ERR"
  fi
  printf '%s\n' "${SL_TUN_XP_RAW:-(none)}"
  SL_TUN_XPERM_UNION_OK=0; SL_TUN_THIRD_CMD_OK=0; SL_TUN_XPERM_COUNT_OK=0
  SL_TUN_XPERM_CONCRETE_COUNT="$(printf '%s\n' "$SL_TUN_XP_RAW" | awk '$2 == "docker_helper_slirp4netns_t"' | grep -ac . || true)"
  if [ "$SL_TUN_XPERM_CONCRETE_COUNT" = 1 ]; then
    SL_TUN_XPERM_COUNT_OK=1
  fi
  SL_TUN_XPERM_UNION="$(printf '%s\n' "$SL_TUN_XP_RAW" | grep -aoE '0x[0-9a-fA-F]+' | tr 'A-F' 'a-f' | sort -u | tr '\n' ' ' || true)"
  echo "effective helper -> tun_tap_device_t:chr_file ioctl xperm union: ${SL_TUN_XPERM_UNION:-(empty)}"
  if [ "$SL_TUN_XPERM_UNION" = "0x54ca " ]; then
    SL_TUN_XPERM_UNION_OK=1
  fi
  echo "--- explicit beyond-the-one negatives (the helper's SECOND/THIRD command must be absent):"
  if [ "$SL_TUN_XPERM_UNION_OK" = 1 ]; then
    SL_TUN_THIRD_CMD_OK=1
    echo "PASS: no effective command beyond { 0x54ca } (TUNSETPERSIST 0x54cb — the creator's persistence command — TUNSETOWNER/TUNSETGROUP/TUNSETLINK/TUNGETFEATURES/TUNSETOFFLOAD/TUNSETQUEUE and every other command stay denied)"
  else
    echo "FAIL: the helper's effective xperm union is not exactly { 0x54ca } (got: ${SL_TUN_XPERM_UNION:-(empty)}; concrete-rules=$SL_TUN_XPERM_CONCRETE_COUNT)"
    PREFLIGHT_OK=0
  fi
  # (The helper's cap_userns net_admin and plain capability net_admin
  # negatives are the cross-domain inventory's existing equality checks:
  # the cap set folds to exactly { sys_admin sys_ptrace } and the plain
  # capability class is empty.)
  echo "--- the helper's dontaudit surface toward tun_tap_device_t (RECORDED SEPARATELY per the 4C-28 preflight contract; never merged into the allow verdict):"
  SL_TUN_DONTAUDIT="$(sesearch --dontaudit -s docker_helper_slirp4netns_t -t tun_tap_device_t /sys/fs/selinux/policy 2>/dev/null || true)"
  printf '%s\n' "${SL_TUN_DONTAUDIT:-(none — no dontaudit rule hides helper -> tun_tap_device_t denials)}"
  if [ "$SL_TUN_COUNT_OK" = 1 ] && [ "$SL_TUN_SHAPE_OK" = 1 ] && [ "$SL_TUN_UNION_OK" = 1 ] && [ "$SL_TUN_CLASS_OK" = 1 ] && [ "$SL_TUNSOCK_COUNT_OK" = 1 ] && [ "$SL_TUNSOCK_SHAPE_OK" = 1 ] && [ "$SL_TUNSOCK_UNION_OK" = 1 ] && [ "$SL_TUNSOCK_SELF_UNION_OK" = 1 ] && [ "$SL_TUNSOCK_NOTARGET_OK" = 1 ] && [ "$SL_TUN_XPERM_COUNT_OK" = 1 ] && [ "$SL_TUN_XPERM_UNION_OK" = 1 ] && [ "$SL_TUN_THIRD_CMD_OK" = 1 ]; then
    echo "PASS: slirp4netns helper TUN device-node inventory (exactly one tun_tap_device_t:chr_file { read write open ioctl } rule; the effective ordinary union is exactly { ioctl open read write }; no non-chr_file class; the effective xperm union is exactly { 0x54ca }; exactly one cross-domain tun_socket relabelfrom rule toward the rootlesskit target and exactly one self tun_socket relabelto rule)"
  else
    echo "FAIL: slirp4netns helper TUN device-node inventory (count=$SL_TUN_COUNT_OK shape=$SL_TUN_SHAPE_OK union=$SL_TUN_UNION_OK class=$SL_TUN_CLASS_OK tunsock-count=$SL_TUNSOCK_COUNT_OK tunsock-shape=$SL_TUNSOCK_SHAPE_OK tunsock-union=$SL_TUNSOCK_UNION_OK tunsock-self-union=$SL_TUNSOCK_SELF_UNION_OK tunsock-notarget=$SL_TUNSOCK_NOTARGET_OK xperm-count=$SL_TUN_XPERM_COUNT_OK xperm-union=$SL_TUN_XPERM_UNION_OK third-cmd=$SL_TUN_THIRD_CMD_OK)"
    PREFLIGHT_OK=0
  fi
  echo "--- live Netlink mediation model (recorded; FAIL CLOSED if it unexpectedly changes):"
  NL_XPERM_FACT="unknown"
  if command -v seinfo >/dev/null 2>&1; then
    echo "seinfo --polcap:"
    seinfo --polcap /sys/fs/selinux/policy 2>/dev/null | grep -a -A1 -B1 'netlink' || true
    echo "--- full polcap list:"
    seinfo --polcap /sys/fs/selinux/policy 2>/dev/null || true
    if seinfo --polcap /sys/fs/selinux/policy 2>/dev/null | grep -aq 'netlink_xperm.*[[:space:]]\+on\|netlink_xperm.*true\|netlink_xperm.*enabled'; then
      NL_XPERM_FACT="enabled"
    else
      NL_XPERM_FACT="disabled"
    fi
  else
    echo "(seinfo unavailable — recording the raw polcap probe)"
    grep -a netlink_xperm /sys/fs/selinux/policy 2>/dev/null || echo "(no polcap info)"
  fi
  echo "NETLINK_XPERM = $NL_XPERM_FACT"
  if [ "$NL_XPERM_FACT" != "disabled" ]; then
    echo "FAIL: the live policycap state changed — the composition was designed and validated against NETLINK_XPERM = disabled"
    PREFLIGHT_OK=0
  fi
  if ! { sesearch --allow -s docker_helper_rootlesskit_t -c capability -p net_admin /sys/fs/selinux/policy 2>/dev/null; \
         sesearch --allow -s docker_helper_rootlesskit_t -c capability -p net_raw /sys/fs/selinux/policy 2>/dev/null; } | grep -aq "docker_helper_rootlesskit_t"; then
    NL_NO_NETADMIN_OK=1
  fi
  if [ "$NL_CREATE_OK" = 1 ] && [ "$NL_SETOPT_OK" = 1 ] && [ "$NL_BIND_OK" = 1 ] && [ "$NL_GETATTR_OK" = 1 ] && [ "$NL_WRITE_OK" = 1 ] && [ "$NL_NLMSG_READ_OK" = 1 ] && [ "$NL_READ_OK" = 1 ] && [ "$NL_NLMSG_WRITE_OK" = 1 ] && [ "$NL_NO_MORE_OK" = 1 ] && [ "$NL_NO_NETADMIN_OK" = 1 ]; then
    echo "PASS: netlink-route create+setopt+bind+getattr+write+nlmsg_read+read+nlmsg_write identity (exactly the eight evidenced permissions, no capability surface)"
  else
    echo "FAIL: netlink-route create+setopt+bind+getattr+write+nlmsg_read+read+nlmsg_write identity (create=$NL_CREATE_OK setopt=$NL_SETOPT_OK bind=$NL_BIND_OK getattr=$NL_GETATTR_OK write=$NL_WRITE_OK nlmsg_read=$NL_NLMSG_READ_OK read=$NL_READ_OK nlmsg_write=$NL_NLMSG_WRITE_OK no-more=$NL_NO_MORE_OK no-netadmin=$NL_NO_NETADMIN_OK)"
    PREFLIGHT_OK=0
  fi

  echo "=== builder_t security_t facts (the /sys/fs/selinux read surface; recorded for the live-verdict causal chain) ==="
  echo "--- allow (expected: none):"
  sesearch --allow -s docker_helper_builder_t -t security_t /sys/fs/selinux/policy || true
  echo "--- dontaudit rules on security_t:file (any subject):"
  sesearch --dontaudit -t security_t -c file /sys/fs/selinux/policy || true
  echo "--- the daemon's own security_t grant (the known reference grant):"
  sesearch --allow -s docker_helper_t -t security_t -c file /sys/fs/selinux/policy || true

  echo "=== launcher entry/loader facts (recorded for the AVC inventory) ==="
  sesearch --allow -s "$LAUNCHER_DOMAIN" -t docker_helper_exec_t -c file /sys/fs/selinux/policy || true
  sesearch --allow -s "$LAUNCHER_DOMAIN" -t docker_helper_rootlesskit_exec_t -c file /sys/fs/selinux/policy || true
} > "$EVIDENCE_DIR/02-preflight.txt" 2>&1
cat "$EVIDENCE_DIR/02-preflight.txt" >&2
if [ "${TUN_TOOLCHAIN_BLOCKED:-0}" = 1 ]; then
  # The 4C-14 toolchain gate: if the real Tumbleweed toolchain cannot
  # encode or query the xperm rule safely, STOP — no verdict is issued
  # and there is NO broad ioctl fallback.
  note "the Tumbleweed toolchain cannot prove the TUNSETIFF xperm rule on the loaded policy (see 02-preflight.txt); stopping without a verdict and without any fallback grant"
  marker "PREFLIGHT=INCOMPLETE"
  marker "BLOCKER=sesearch allowxperm tooling unavailable on this stand (see 02-preflight.txt)"
  finish INCOMPLETE; exit 0
fi
if [ "$PREFLIGHT_OK" != 1 ]; then
  note "loaded-policy preflight FAILED; the loaded policy is not the shipped one"
  marker "PREFLIGHT=FAIL"
  marker "BLOCKER=loaded-policy preflight failure (see 02-preflight.txt)"
  finish FAIL; exit 0
fi
marker "PREFLIGHT=PASS"

# ============================================================
# C: audit window
# ============================================================
log 'C: audit window'
systemctl enable --now auditd > /dev/null 2>&1 || true
{
  echo "=== auditd state ==="
  systemctl is-active auditd || true
  systemctl status auditd --no-pager -l 2>/dev/null | head -12 || true
  echo "=== audit subsystem settings (lost counters at window start) ==="
  auditctl -s 2>&1 || true
} > "$EVIDENCE_DIR/audit-channel.txt" 2>&1
if systemctl is-active --quiet auditd 2>/dev/null; then
  log "auditd is consuming the evidence channel"
else
  note "auditd is NOT active; the audit-log slices will be empty unless the kernel printk's the records (the auditctl lost counters decide)"
fi
if command -v auditctl >/dev/null 2>&1; then
  auditctl -e 1 > /dev/null 2>&1 || true
  log "audit rules enforcement on"
fi
# ============================================================
# 4C-19: the CANONICAL window runs PRODUCTION policy — dontaudit
# ENABLED (no semodule -DB here). The dontaudit-disabled companion
# window runs after the canonical gates pass (section CC), so the
# canonical leg's audit behavior stays production-identical and the
# 4C-18 boundary comparison (canonical vs -DB) is reproduced for the
# new composition.
# ============================================================
{
  echo "=== 4C-19 canonical-window baseline (production policy, dontaudit ENABLED) ==="
  echo "getenforce: $(getenforce 2>/dev/null)"
  echo "docker_helper permissive domains (must be none):"
  semanage permissive -l 2>/dev/null | grep -a docker_helper || echo "(none)"
  echo "flow-domain dontaudit inventory on netlink_route_socket (NON-ZERO = the generic write/read suppression is present, as in the canonical 4C-18 comparison):"
  sesearch --dontaudit -s docker_helper_rootlesskit_t -c netlink_route_socket /sys/fs/selinux/policy 2>/dev/null || true
} > "$EVIDENCE_DIR/18-semodule-db-diag.txt"
cat "$EVIDENCE_DIR/18-semodule-db-diag.txt" >&2
# Kernel-side syscall chronology for the live window (audit rules, not
# ptrace — no SELinux ptrace authority is needed or granted): every
# socket/socketpair/sendmsg/sendto/recvmsg/recvfrom/ioctl/close is
# logged with pid, args, and exit code; the report filters by pid.
#
# Run 36769407676 root cause: openSUSE ships `-a never,task` as the
# FIRST rule in the kernel table (loaded at auditd start from
# /etc/audit/rules.d/). A never,task match tags the task "never audit"
# at creation, so NO exit rules ever fire for it — that is why the
# always,exit rules produced zero records while AVCs still appeared
# (denials audit through a different path). Remove the catch-all for
# the window; restore it with the baseline.
auditctl -d never,task >> "$EVIDENCE_DIR/18-auditctl-sysrules.txt" 2>&1 || true
# Raise the kernel's audit backlog for the window: the shipped default
# (backlog_limit 64) dropped the flow's own syscall records under the
# sampler's fork load in the 4C-22 runs (the slice held only the
# harness's own processes). 8192 keeps the whole window's records
# deliverable; restored with the baseline below.
auditctl -b 8192 >> "$EVIDENCE_DIR/18-auditctl-sysrules.txt" 2>&1 || true
auditctl -a always,exit -F arch=b64 \
  -S socket,socketpair,sendmsg,sendto,recvmsg,recvfrom,ioctl,close \
  -k p5s2diag >> "$EVIDENCE_DIR/18-auditctl-sysrules.txt" 2>&1 \
  || { note "auditctl syscall-chronology rules failed"; finish INCOMPLETE; exit 0; }
# The 4C-18 rerun instrumentation: read the kernel's rule table back so
# the evidence proves the rules were ACTUALLY loaded during the window.
{
  echo "=== auditctl -l (the kernel rule table after the add) ==="
  auditctl -l 2>&1 || true
  echo "=== auditctl -s (counters before the window) ==="
  auditctl -s 2>&1 || true
} >> "$EVIDENCE_DIR/18-auditctl-sysrules.txt"
cat "$EVIDENCE_DIR/18-auditctl-sysrules.txt" >&2
T0="$(date +%s)"
echo "$T0" > "$EVIDENCE_DIR/window-start-epoch"
auditctl -s > "$EVIDENCE_DIR/audit-status-window-start.txt" 2>&1 || true

# ============================================================
# 4C-27: kernel-side diagnostic tracepoints (policy delta = ZERO)
# ============================================================
# The audit syscall rules cannot observe the nsenter'd leaf processes
# (established across the 4C-22/4C-26 runs); the tracefs path is
# separate and needs no policy authority. Collected: the capability
# capable-check results (capability:cap_capable — the Linux capability
# verdict including negative commoncap results, distinguishing the
# SELinux cap_userns AVC from the actual capability outcome) and the
# namespace-path syscalls' exits (openat/setns/socket) for the helper.
TRACING=/sys/kernel/tracing
TRACE_ENABLED=0
TRACE_AVC_ENABLED=0
if [ -d "$TRACING/events/capability/cap_capable" ]; then
  echo 0 > "$TRACING/tracing_on" 2>/dev/null || true
  echo > "$TRACING/trace" 2>/dev/null || true
  # 4C-36: a generous ring — the manager's retained-entry poll denials
  # (an alive helper is now the expected shape) run at ~100 events/s and
  # must not eat the window's own syscall/AVC records.
  echo 16384 > "$TRACING/buffer_size_kb" 2>/dev/null || true
  echo 1 > "$TRACING/events/capability/cap_capable/enable" 2>/dev/null || true \
    && TRACE_ENABLED=1
  echo 1 > "$TRACING/events/syscalls/sys_enter_openat/enable" 2>/dev/null || true
  echo 1 > "$TRACING/events/syscalls/sys_exit_openat/enable" 2>/dev/null || true
  echo 1 > "$TRACING/events/syscalls/sys_enter_setns/enable" 2>/dev/null || true
  echo 1 > "$TRACING/events/syscalls/sys_exit_setns/enable" 2>/dev/null || true
  echo 1 > "$TRACING/events/syscalls/sys_enter_socket/enable" 2>/dev/null || true
  # 4C-31/4C-33: the ioctl syscall tracepoints — the helper's
  # existing-TAP attach path issues ioctl(fd, TUNSETIFF) right after
  # the device open completes; the events carry the NUMERIC command
  # (fd/cmd/arg, exit adds ret) so a reached TUNSETIFF is recorded as
  # 0x54ca WITHOUT granting it (the 4C-33 grant is the generic ioctl
  # permission only; the command whitelist stays closed).
  echo 1 > "$TRACING/events/syscalls/sys_enter_ioctl/enable" 2>/dev/null || true
  echo 1 > "$TRACING/events/syscalls/sys_exit_ioctl/enable" 2>/dev/null || true
  # 4C-29: the SELinux decision tracepoint (avc:selinux_audited) —
  # independent of auditd's userspace log harvest (run 36864816648
  # showed launch-period SYSCALL+AVC records absent with lost=0, so
  # userspace audit absence alone is no absence proof). The trace line
  # carries the raw requested/denied/audited MASKS, the result, the
  # contexts, and the kernel-decoded symbolic tclass.
  if [ -d "$TRACING/events/avc/selinux_audited" ]; then
    echo 1 > "$TRACING/events/avc/selinux_audited/enable" 2>/dev/null || true \
      && TRACE_AVC_ENABLED=1
  fi
  echo 1 > "$TRACING/tracing_on" 2>/dev/null || true
  {
    echo "=== 4C-27 tracefs collector armed ==="
    echo "cap_capable enabled: $TRACE_ENABLED"
    echo "avc/selinux_audited available: $TRACE_AVC_ENABLED"
    echo "sys_enter_ioctl/sys_exit_ioctl available: $([ -d "$TRACING/events/syscalls/sys_exit_ioctl" ] && echo yes || echo no) (4C-33: the generic ioctl permission is granted; the TUNSETIFF command whitelist is NOT — any reached command is recorded numerically, fd/cmd/arg/ret)"
    echo "=== 4C-29 selinux_audited tracepoint format (recorded verbatim) ==="
    cat "$TRACING/events/avc/selinux_audited/format" 2>/dev/null || echo "(format file unavailable)"
    echo "=== 4C-31 sys_exit_ioctl tracepoint format (recorded verbatim: fd/cmd/arg/ret) ==="
    cat "$TRACING/events/syscalls/sys_exit_ioctl/format" 2>/dev/null || echo "(format file unavailable)"
    echo "=== 4C-29 live class/permission mapping evidence (RECORDED, not hardcoded — decode validation uses co-captured AVC records) ==="
    echo "--- /sys/fs/selinux/class file-class perms listing (as the kernel presents it):"
    ls /sys/fs/selinux/class/file/perms 2>/dev/null || true
    echo "--- seinfo class expansion attempt (whatever the tooling exposes):"
    seinfo -c -x /sys/fs/selinux/policy 2>&1 | sed -n '1,30p' || true
    echo "--- sedismod class-map attempt (interactive tool, piped; output recorded as evidence only):"
    printf 'q\n' | timeout 5 sedismod /sys/fs/selinux/policy 2>&1 | head -15 || true
    echo "=== cap tracepoint state ==="
    cat "$TRACING/events/capability/cap_capable/enable" 2>/dev/null || true
    cat "$TRACING/events/avc/selinux_audited/enable" 2>/dev/null || true
    echo "tracing_on (must be 1 after arming — a 0 here means the collector never ran):"
    cat "$TRACING/tracing_on" 2>/dev/null || true
  } > "$EVIDENCE_DIR/30-trace-arm.txt" 2>&1
else
  note "tracefs capability tracepoint unavailable"
  : > "$EVIDENCE_DIR/30-trace-arm.txt"
fi

# ============================================================
# D: the live START with a concurrent kernel-label sampler
# ============================================================
OP_ID="$(gen_op_id)"
RT_OP_DIR="$RUNTIME_ROOT/ops/$OP_ID"
ST_OP_DIR="$STATE_ROOT/ops/$OP_ID"
echo "$OP_ID" > "$EVIDENCE_DIR/op-id"

# The sampler records, until the op tree converges away or the ceiling:
#   - every distinct /proc/<leader>/attr/current of the launch leader (the
#     same pid crosses builder_t -> launcher_t -> rootlesskit_t:s0:cN: the
#     context sequence IS the kernel-observed chain);
#   - the kernel-issued labels of the four provisioned paths (first-seen
#     is the pre-relabel source-side state, last-seen is the verdict
#     value, all-observed is the full sequence);
#   - the roots' and the shared ops containers' labels;
#   - process-table samples for the uncategorized-flow gate.
log "D: live START $OP_ID (sampler armed)"
(
  set +e
  seen_pid=""
  TAP_HITS=0
  seen_ctx=""
  end=$(( $(date +%s) + 75 ))
  while [ "$(date +%s)" -lt "$end" ]; do
    if [ -z "$seen_pid" ] && [ -s "$RT_OP_DIR/instance.pid" ]; then
      seen_pid="$(cat "$RT_OP_DIR/instance.pid" 2>/dev/null)"
      [ -n "$seen_pid" ] && printf 'INSTANCE-PID %s first-seen=%s\n' "$seen_pid" "$(date +%s.%N)" >> "$EVIDENCE_DIR/05-flow-context.txt"
    fi
    if [ -n "$seen_pid" ] && [ -d "/proc/$seen_pid" ]; then
      ctx="$(process_context "$seen_pid")"
      if [ -n "$ctx" ] && ! printf '%s\n' "$seen_ctx" | grep -aqx "$ctx"; then
        seen_ctx="$seen_ctx$ctx
"
        printf 'LEADER-CTX %s pid=%s comm=%s ctx=%s\n' "$(date +%s.%N)" "$seen_pid" "$(cat "/proc/$seen_pid/comm" 2>/dev/null)" "$ctx" >> "$EVIDENCE_DIR/05-flow-context.txt"
      fi
      if [ $(( RANDOM % 8 )) -eq 0 ]; then
        ps -eZ 2>/dev/null | awk '$1 ~ /docker_helper_rootlesskit_t/ { print "PS-FLOW " $0 }' >> "$EVIDENCE_DIR/12-uncategorized-ps.txt"
      fi
      # 4C-27 process/credential snapshot: one shot per helper/target
      # pid (diagnostic host observation; no flow authority touched).
      CHILDREN="$(cat "/proc/$seen_pid/task/$seen_pid/children" 2>/dev/null || true)"
      for C in $CHILDREN; do
        snap_shot="$C"
        snap_ctx="$(tr -d '\0' < "/proc/$C/attr/current" 2>/dev/null || true)"
        case "$snap_ctx" in
          docker_helper_slirp4netns_t:*)
            if [ ! -s "$EVIDENCE_DIR/31-slirp-snap-$snap_shot.txt" ]; then
              proc_snapshot "$snap_shot" "$snap_ctx" "$EVIDENCE_DIR/31-slirp-snap-$snap_shot.txt"
            fi
            for C2 in $(cat "/proc/$snap_shot/task/$snap_shot/children" 2>/dev/null || true); do
              snap_ctx2="$(tr -d '\0' < "/proc/$C2/attr/current" 2>/dev/null || true)"
              case "$snap_ctx2" in
                docker_helper_slirp4netns_t:*)
                  if [ ! -s "$EVIDENCE_DIR/31-slirp-snap-$C2.txt" ]; then
                    proc_snapshot "$C2" "$snap_ctx2" "$EVIDENCE_DIR/31-slirp-snap-$C2.txt"
                  fi
                  ;;
              esac
            done
            ;;
          docker_helper_rootlesskit_t:*)
            if [ ! -s "$EVIDENCE_DIR/31-rk-target-snap-$snap_shot.txt" ]; then
              proc_snapshot "$snap_shot" "$snap_ctx" "$EVIDENCE_DIR/31-rk-target-snap-$snap_shot.txt"
            fi
            ;;
        esac
        TAP_LINE="$(grep -a 'tap0' "/proc/$C/net/dev" 2>/dev/null || true)"
        if [ -n "$TAP_LINE" ] && [ "$TAP_HITS" -lt 3 ]; then
          TAP_HITS=$((TAP_HITS + 1))
          printf 'TAP0-OBSERVED %s child=%s ns=%s ctx=%s dev=%s\n' \
            "$(date +%s.%N)" "$C" \
            "$(readlink "/proc/$C/ns/net" 2>/dev/null)" \
            "$(tr -d '\0' < "/proc/$C/attr/current" 2>/dev/null)" \
            "$(printf '%s\n' "$TAP_LINE" | head -1 | awk '{print $1, $2}')" \
            >> "$EVIDENCE_DIR/05-flow-context.txt"
        fi
        if [ -n "$TAP_LINE" ] && [ ! -s "$EVIDENCE_DIR/20-tap0-detail.txt" ]; then
          nsenter -t "$C" -n -- ip link show tap0 2>&1 \
            | head -2 > "$EVIDENCE_DIR/20-tap0-detail.txt" || true
        fi
      done
    fi
    # Batched label sampling: ONE stat call for the four provisioned
    # per-op paths. The sampler's iteration cost is the catch-rate
    # ceiling: the 4C-15 flow window shrank to ~45ms and a per-path stat
    # loop (one fork per path) fit only ONE iteration inside such a
    # window — the parent's stat ran before the tree existed while the
    # children's ran after, so the parent was never observed and the
    # provisioning gate false-failed on a pure observation race
    # (run 36754289051). Batching turns an iteration into a single fork,
    # so every path is sampled repeatedly inside any >=10ms window. The
    # first/last/all observation semantics are unchanged.
    while IFS= read -r line; do
      path="${line%% *}"; ctx="${line#* }"
      case "$path" in
        "$ST_OP_DIR") label=state-op ;;
        "$ST_OP_DIR/root") label=state-root ;;
        "$ST_OP_DIR/rootlesskit-state") label=state-rkstate ;;
        "$RT_OP_DIR") label=runtime-op ;;
        *) continue ;;
      esac
      if [ -n "$ctx" ]; then
        [ -s "$EVIDENCE_DIR/first.$label" ] || printf '%s\n' "$ctx" > "$EVIDENCE_DIR/first.$label"
        printf '%s\n' "$ctx" > "$EVIDENCE_DIR/last.$label"
        grep -aqx "$ctx" "$EVIDENCE_DIR/all.$label" 2>/dev/null || printf '%s\n' "$ctx" >> "$EVIDENCE_DIR/all.$label"
      fi
    done < <(stat -c '%n %C' "$ST_OP_DIR" "$ST_OP_DIR/root" "$ST_OP_DIR/rootlesskit-state" "$RT_OP_DIR" 2>/dev/null || true)
    while IFS= read -r line; do
      path="${line%% *}"; ctx="${line#* }"
      case "$path" in
        "$STATE_ROOT") label=state-root-container ;;
        "$STATE_ROOT/ops") label=state-ops-container ;;
        "$RUNTIME_ROOT") label=runtime-root-container ;;
        "$RUNTIME_ROOT/ops") label=runtime-ops-container ;;
        *) continue ;;
      esac
      [ -n "$ctx" ] && printf '%s\n' "$ctx" > "$EVIDENCE_DIR/container.$label"
    done < <(stat -c '%n %C' "$STATE_ROOT" "$STATE_ROOT/ops" "$RUNTIME_ROOT" "$RUNTIME_ROOT/ops" 2>/dev/null || true)
    if [ -n "$seen_pid" ] && [ ! -d "/proc/$seen_pid" ] && [ ! -d "$RT_OP_DIR" ] && [ ! -d "$ST_OP_DIR" ]; then
      printf 'CONVERGED %s\n' "$(date +%s.%N)" >> "$EVIDENCE_DIR/05-flow-context.txt"
      break
    fi
    sleep 0.002
  done
  touch /tmp/p4b-work/sampler.done
) &
SAMPLER_PID=$!

START_RC=0
START_OUT="$(printf 'START %s\n' "$OP_ID" | timeout 120 socat - UNIX-CONNECT:"$MANAGER_SOCK")" || START_RC=$?
{
  echo "window-start: $T0"
  echo "START: $OP_ID"
  echo "response: $START_OUT (rc=$START_RC)"
  echo "window-end: $(date +%s)"
} > "$EVIDENCE_DIR/04-launch-window.txt"
cat "$EVIDENCE_DIR/04-launch-window.txt" >&2

# ---- 4C-27: read the trace ring IMMEDIATELY after the manager's
# ---- response (the flow has exited by then; the sampler's later fork
# ---- volume would otherwise overwrite the ring).
# ---- 4C-29: the ring now also carries avc/selinux_audited decisions;
# ---- the disable sweep must cover the avc event too.
if [ "$TRACE_ENABLED" = 1 ]; then
  echo 0 > "$TRACING/tracing_on" 2>/dev/null || true
  cat "$TRACING/trace" > "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true
  echo 0 > "$TRACING/events/capability/cap_capable/enable" 2>/dev/null || true
  echo 0 > "$TRACING/events/syscalls/sys_enter_openat/enable" 2>/dev/null || true
  echo 0 > "$TRACING/events/syscalls/sys_exit_openat/enable" 2>/dev/null || true
  echo 0 > "$TRACING/events/syscalls/sys_enter_setns/enable" 2>/dev/null || true
  echo 0 > "$TRACING/events/syscalls/sys_exit_setns/enable" 2>/dev/null || true
  echo 0 > "$TRACING/events/syscalls/sys_enter_socket/enable" 2>/dev/null || true
  echo 0 > "$TRACING/events/syscalls/sys_enter_ioctl/enable" 2>/dev/null || true
  echo 0 > "$TRACING/events/syscalls/sys_exit_ioctl/enable" 2>/dev/null || true
  echo 0 > "$TRACING/events/avc/selinux_audited/enable" 2>/dev/null || true
  grep -a -E 'slirp4netns|rootlesskit| ns/net|ns/user|/dev/net/tun|cap_capable|selinux_audited' "$EVIDENCE_DIR/30-trace-window.txt" \
    > "$EVIDENCE_DIR/30-trace-relevant.txt" 2>/dev/null || true
else
  : > "$EVIDENCE_DIR/30-trace-window.txt"
  : > "$EVIDENCE_DIR/30-trace-relevant.txt"
fi
{
  echo "=== 4C-27 relevant trace lines (helper/namespace/capability events of the window) ==="
  cat "$EVIDENCE_DIR/30-trace-relevant.txt"
} >&2

# ---- manager context AFTER the launch attempt: captured immediately,
# ---- before any gate branching, so an early-stopped leg still carries
# ---- the manager-context evidence (R1/R2 lost it twice this way).
MGR_AFTER="$(process_context "$MG_PID")"
echo "$MGR_AFTER" > "$EVIDENCE_DIR/07-manager-after.txt"

# Give the sampler its grace, then collect.
for i in $(seq 1 100); do
  [ -f /tmp/p4b-work/sampler.done ] && break
  sleep 0.1
done
kill "$SAMPLER_PID" 2>/dev/null || true
wait "$SAMPLER_PID" 2>/dev/null || true

# ---- the window's audit slice (before anything converges further)
harvest_avcs_since "$T0" "$EVIDENCE_DIR/09-avc-window.txt"
auditctl -s > "$EVIDENCE_DIR/audit-status-window-end.txt" 2>&1 || true

# ---- 4C-18: the syscall-chronology slice for the window, then the
# ---- diagnostic restore (baseline dontaudit back, audit rules flushed)
{
  echo "=== audit.log SYSCALL records (key p5s2diag) since epoch $T0 ==="
  grep -a 'type=SYSCALL' /var/log/audit/audit.log 2>/dev/null \
    | grep -a 'p5s2diag' \
    | awk -v s="$T0" '{ for (i = 1; i <= NF; i++) if ($i ~ /^msg=audit\(/) { ts = substr($i, 11); split(ts, t, "."); if (t[1] + 0 >= s + 0) print; break } }' \
    || true
  echo "=== audit.log SYSCALL records (ANY key) since epoch $T0 ==="
  grep -a 'type=SYSCALL' /var/log/audit/audit.log 2>/dev/null \
    | awk -v s="$T0" '{ for (i = 1; i <= NF; i++) if ($i ~ /^msg=audit\(/) { ts = substr($i, 11); split(ts, t, "."); if (t[1] + 0 >= s + 0) print; break } }' \
    || true
  echo "=== ausearch -k p5s2diag --raw (SYSCALL records) ==="
  ausearch -k p5s2diag --raw 2>/dev/null | grep -a 'type=SYSCALL' || true
  echo "=== auditctl -s (counters AT HARVEST: lost/backlog prove kernel->auditd delivery) ==="
  auditctl -s 2>&1 || true
  echo "=== auditctl -l (rule table AT HARVEST, before the flush) ==="
  auditctl -l 2>&1 || true
  echo "=== raw audit.log tail (last 120 lines, unfiltered) ==="
  tail -n 120 /var/log/audit/audit.log 2>/dev/null || true
} > "$EVIDENCE_DIR/18-syscall-chronology.txt" 2>&1
cat "$EVIDENCE_DIR/18-syscall-chronology.txt" >&2

# ---- manager diagnostics of the window (procattr/exec failures surface here)
{
  echo "=== manager journal of the window ==="
  journalctl -u "$UNIT" --since "@$T0" --no-pager 2>/dev/null | tail -120 || true
} > "$EVIDENCE_DIR/07-manager-diag.txt" 2>&1

# ---- provisioning verdict: the LAST kernel-observed label of each
# ---- provisioned path must be the exact per-op context of the record's
# ---- category (the first live op is c1); the first-seen value is the
# ---- recorded pre-relabel source side.
PROVISIONING_OK=1
{
  echo "=== the four provisioned paths: first-seen, last-seen, all observed ==="
  for entry in \
    "state-op:$ST_OP_DIR:$RK_STATE_T:s0:c1" \
    "state-root:$ST_OP_DIR/root:$RK_STATE_T:s0:c1" \
    "state-rkstate:$ST_OP_DIR/rootlesskit-state:$RK_STATE_T:s0:c1" \
    "runtime-op:$RT_OP_DIR:$RK_RUNTIME_T:s0:c1"; do
    label="${entry%%:*}"; rest="${entry#*:}"
    path="${rest%%:*}"; want="system_u:object_r:${rest#*:}"
    echo "--- $label ($path)"
    echo "first-seen:  $(cat "$EVIDENCE_DIR/first.$label" 2>/dev/null || echo NEVER-OBSERVED)"
    echo "last-seen:   $(cat "$EVIDENCE_DIR/last.$label" 2>/dev/null || echo NEVER-OBSERVED)"
    echo "all-observed: $(tr '\n' '|' < "$EVIDENCE_DIR/all.$label" 2>/dev/null)"
    if [ "$(cat "$EVIDENCE_DIR/last.$label" 2>/dev/null)" = "$want" ]; then
      echo "PASS $label == $want"
    else
      echo "FAIL $label: last-seen != $want"
      PROVISIONING_OK=0
    fi
  done
  echo "=== the roots and the shared ops containers stayed bare s0 root types ==="
  for entry in \
    "state-root-container:$STATE_ROOT:$RK_STATE_ROOT_T" \
    "state-ops-container:$STATE_ROOT/ops:$RK_STATE_ROOT_T" \
    "runtime-root-container:$RUNTIME_ROOT:$RK_RUNTIME_ROOT_T" \
    "runtime-ops-container:$RUNTIME_ROOT/ops:$RK_RUNTIME_ROOT_T"; do
    label="${entry%%:*}"; rest="${entry#*:}"
    path="${rest%%:*}"; want="system_u:object_r:${rest#*:}:s0"
    got="$(cat "$EVIDENCE_DIR/container.$label" 2>/dev/null)"
    if [ "$got" = "$want" ]; then
      echo "PASS $label == $want"
    else
      echo "FAIL $label: '$got' != $want"
      PROVISIONING_OK=0
    fi
  done
  echo "=== post-convergence residue (a failed START must leave no tree) ==="
  for path in "$RT_OP_DIR" "$ST_OP_DIR" "$RT_OP_DIR/instance.pid"; do
    if [ -e "$path" ]; then echo "RESIDUE $path"; else echo "GONE $path"; fi
  done
} > "$EVIDENCE_DIR/06-labels.txt" 2>&1
cat "$EVIDENCE_DIR/06-labels.txt" >&2
if [ "$PROVISIONING_OK" = 1 ]; then
  marker "PROVISIONING=PASS"
else
  marker "PROVISIONING=FAIL"
  marker "BLOCKER=categorized provisioning not proven (labels/journal: 06-labels.txt, 07-manager-diag.txt, 09-avc-window.txt)"
  finish FAIL; exit 0
fi

# ---- manager context AFTER the launch attempt (captured above, right
# ---- after START returned; only the gate reads it here)
if [ "$MGR_AFTER" = "$BUILDER_T" ]; then
  marker "MANAGER-CONTEXT-AFTER=$BUILDER_T"
  marker "MANAGER-CONTEXT=PASS"
else
  marker "MANAGER-CONTEXT-AFTER=$MGR_AFTER"
  marker "MANAGER-CONTEXT=FAIL"
  marker "BLOCKER=the manager context changed across the launch attempt"
  finish FAIL; exit 0
fi

# ---- launcher-chain verdict: kernel-observed flow context + no
# ---- procattr failure in the manager diagnostics
CHAIN_OK=1
FLOW_CTX_SEEN="$(grep -a 'LEADER-CTX' "$EVIDENCE_DIR/05-flow-context.txt" 2>/dev/null | grep -a "$RK_DOMAIN:s0:c" | tail -1 || true)"
# The 4C-3 proof-harness correction: a short-lived leader can die before
# the sampler's first /proc/<pid>/attr/current read, which produced a
# false chain FAIL on a run whose kernel audit records still proved the
# categorized entry. A kernel-originated AVC/audit record with a
# categorized rootlesskit_t:s0:c* scontext counts as positive evidence
# that the flow existed in the categorized domain; the two accepted
# forms are (a) the /proc attr/current observation or (b) the kernel
# audit record. The no-bare scan stays a separate mandatory check below:
# an audit context may prove a categorized flow exists, but it never
# replaces the no-bare scan.
CHAIN_AVC_SEEN=0
if grep -a "scontext=system_u:system_r:$RK_DOMAIN:s0:c" "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -aq ':[0-9]\+ '; then
  CHAIN_AVC_SEEN=1
fi
PROCATTR_FAILED="$(grep -a 'cannot set the forced exec context' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null || true)"
CHAIN_FORM=none
if [ -n "$FLOW_CTX_SEEN" ]; then
  CHAIN_FORM=proc-attr
elif [ "$CHAIN_AVC_SEEN" = 1 ]; then
  CHAIN_FORM=kernel-avc
fi
if [ -n "$FLOW_CTX_SEEN" ] || [ "$CHAIN_AVC_SEEN" = 1 ]; then
  echo "$FLOW_CTX_SEEN" > "$EVIDENCE_DIR/flow-context-final.txt"
  grep -a "scontext=system_u:system_r:$RK_DOMAIN:s0:c" "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | head -3 >> "$EVIDENCE_DIR/flow-context-final.txt" || true
else
  echo "(no rootlesskit_t:s0:c* observation)" > "$EVIDENCE_DIR/flow-context-final.txt"
  CHAIN_OK=0
fi
# The separate mandatory no-bare check for the chain window: no
# rootlesskit_t:s0 WITHOUT a category in the window's kernel records or
# process-table samples. A bare context here means the forced-context
# application did not happen even once.
BARE_IN_WINDOW="$(grep -a "scontext=system_u:system_r:$RK_DOMAIN:s0 " "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | wc -l || true)"
PS_BARE_IN_WINDOW="$(awk '/docker_helper_rootlesskit_t:s0( |$)/ { n++ } END { print n+0 }' "$EVIDENCE_DIR/12-uncategorized-ps.txt" 2>/dev/null || echo 0)"
if [ "$BARE_IN_WINDOW" != 0 ] || [ "$PS_BARE_IN_WINDOW" != 0 ]; then
  CHAIN_OK=0
  echo "BARE: bare rootlesskit_t:s0 context in the chain window (avc=$BARE_IN_WINDOW ps=$PS_BARE_IN_WINDOW)" > "$EVIDENCE_DIR/chain-bare.txt"
fi
[ -n "$PROCATTR_FAILED" ] && { CHAIN_OK=0; echo "$PROCATTR_FAILED" > "$EVIDENCE_DIR/procattr-failure.txt"; }
{
  echo "=== kernel observations of the launch leader (the chain's causal record) ==="
  cat "$EVIDENCE_DIR/05-flow-context.txt" 2>/dev/null || echo "(no observation)"
  echo "=== the final flow context ==="
  cat "$EVIDENCE_DIR/flow-context-final.txt"
  echo "=== the proof form ==="
  echo "chain-form: $CHAIN_FORM (proc-attr observation or kernel audit record; no-bare scan ran separately)"
  echo "=== bare-scan (separate mandatory check) ==="
  echo "avc-bare-count=$BARE_IN_WINDOW ps-bare-count=$PS_BARE_IN_WINDOW"
  echo "=== procattr failure? ==="
  cat "$EVIDENCE_DIR/procattr-failure.txt" 2>/dev/null || echo "(none recorded)"
} > "$EVIDENCE_DIR/11-chain-evidence.txt" 2>&1
cat "$EVIDENCE_DIR/11-chain-evidence.txt" >&2
if [ "$CHAIN_OK" = 1 ]; then
  marker "LAUNCHER-CHAIN=PASS"
else
  if [ -f "$EVIDENCE_DIR/chain-bare.txt" ]; then
    marker "BLOCKER=a bare rootlesskit_t:s0 context appeared in the chain window (see chain-bare.txt, 09-avc-window.txt)"
  elif grep -aq "scontext=system_u:system_r:$LAUNCHER_DOMAIN" "$EVIDENCE_DIR/09-avc-window.txt"; then
    marker "BLOCKER=launcher_t denial before the rootlesskit_t:s0:c1 entry (exact AVC: 08-avc-launcher.txt)"
  else
    marker "BLOCKER=the chain did not reach rootlesskit_t:s0:c1 (no launcher_t AVC; see 07-manager-diag.txt, 05-flow-context.txt)"
  fi
  marker "LAUNCHER-CHAIN=FAIL"
  finish FAIL; exit 0
fi

# ---- the first downstream AVC of the categorized flow (the next step's
# ---- exact boundary; the G28 ledger is deliberately NOT transferred)
{
  echo "=== the FIRST flow-domain (rootlesskit_t:s0:c*) AVC of the window ==="
  grep -a "scontext=system_u:system_r:$RK_DOMAIN:s0:" "$EVIDENCE_DIR/09-avc-window.txt" | head -1 \
    || echo "(no flow-domain AVC recorded: the flow exited before its first enforced denial)"
} > "$EVIDENCE_DIR/10-avc-first-downstream.txt"
cat "$EVIDENCE_DIR/10-avc-first-downstream.txt" >&2
RAW_FIRST="$(grep -a "scontext=system_u:system_r:$RK_DOMAIN:s0:" "$EVIDENCE_DIR/09-avc-window.txt" | head -1 || true)"
PERMS_FIRST="$(printf '%s\n' "$RAW_FIRST" | sed -n 's/.*denied  *{ \([^}]*\) }.*/\1/p' || true)"
SUMMARY_FIRST="$(printf '%s\n' "$RAW_FIRST" | sed -n 's/.*scontext=\([^ ]*\) tcontext=\([^ ]*\) tclass=\([a-z_]*\).*/scontext=\1 tcontext=\2 tclass=\3/p' || true)"
marker "DOWNSTREAM-BOUNDARY=${SUMMARY_FIRST:-none} perms=${PERMS_FIRST:-none}"

# ---- the 4C-14 gate (updated for the 4C-17 composition): the TUN ioctl
# ---- boundary is SELinux-mediated by the ordinary { ioctl } bit + the
# ---- exact { 0x54ca 0x54cb } allowxperm. HARD FAILURES: any
# ---- tun_tap_device_t denial of the granted ordinary surface
# ---- (read/write/open — or any never-granted ordinary bit:
# ---- getattr/append/lock/create/setattr), the canonical 4C-13 shape
# ---- (ioctlcmd=0x54ca), and the canonical 4C-16 shape
# ---- (ioctlcmd=0x54cb) — the whole evidenced two-command surface must
# ---- hold. NOT a failure — the gate holding as pinned: an ioctl denial
# ---- with any OTHER ioctlcmd (e.g. TUNSETOWNER if one were attempted) —
# ---- the xperm mediation denied exactly what the composition does not
# ---- grant; it is RECORDED as next-boundary evidence.
TUN_IOCTL_GONE_OK=1
{
  echo "=== tun_tap_device_t AVCs of the window (4C-17 composition: the granted surface must not regress; 0x54ca and 0x54cb denials must be gone; non-whitelisted ioctl commands must be denied and are recorded) ==="
  TUN_AVC_WINDOW="$(grep -a 'tcontext=system_u:object_r:tun_tap_device_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null || true)"
  printf '%s\n' "${TUN_AVC_WINDOW:-(none — no tun_tap_device_t denial in the window)}"
  echo "--- the exact 4C-13 shape (denied ioctl, ioctlcmd=0x54ca = TUNSETIFF; ROOTLESSKIT subject only — the 4C-30 correction carried to the canonical shapes: another domain's TUNSETIFF boundary is its own staircase and fails its own gate, not this one):"
  OLD_TUN_IOCTL="$(printf '%s\n' "$TUN_AVC_WINDOW" | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' | grep -a 'ioctlcmd=0x54ca' || true)"
  printf '%s\n' "${OLD_TUN_IOCTL:-(none — the 4C-13 ioctl(TUNSETIFF) denial is gone)}"
  echo "--- the exact 4C-16 shape (denied ioctl, ioctlcmd=0x54cb = TUNSETPERSIST; ROOTLESSKIT subject only):"
  OLD_PERSIST_IOCTL="$(printf '%s\n' "$TUN_AVC_WINDOW" | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' | grep -a 'ioctlcmd=0x54cb' || true)"
  printf '%s\n' "${OLD_PERSIST_IOCTL:-(none — the 4C-16 ioctl(TUNSETPERSIST) denial is gone)}"
  echo "--- the manager journal's 4C-16 EACCES shape (must be gone — TUNSETPERSIST completes):"
  MGR_SETPERSIST_EACCES="$(grep -a 'ioctl(TUNSETPERSIST): Permission denied' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null || true)"
  printf '%s\n' "${MGR_SETPERSIST_EACCES:-(none — the TUNSETPERSIST SELinux-hook EACCES is gone)}"
  echo "--- granted-surface regressions (the ROOTLESSKIT flow domain's granted ordinary bits — must be zero; the 4C-30 correction: this gate owns the ROOTLESSKIT domain's TUN surface only, another domain's tun_tap_device_t denial is its own staircase and is recorded below, not failed):"
  TUN_REGRESSION="$(printf '%s\n' "$TUN_AVC_WINDOW" | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' | grep -aE 'denied  *\{ (read|write|open|getattr|append|lock|create|setattr)' || true)"
  printf '%s\n' "${TUN_REGRESSION:-(none — the granted ordinary surface held)}"
  echo "--- OTHER domains' tun_tap_device_t denials (their independent TUN staircases — recorded, not failed; the slirp helper's granted surface is the 4C-31/4C-32/4C-33 { read write open ioctl } and its denials are owned by the helper TUN gates below, not by this gate):"
  TUN_OTHER_DOMAIN="$(printf '%s\n' "$TUN_AVC_WINDOW" | grep -av 'scontext=system_u:system_r:docker_helper_rootlesskit_t' || true)"
  printf '%s\n' "${TUN_OTHER_DOMAIN:-(none — no other-domain TUN denial appeared)}"
  echo "--- xperm-mediated denials of non-whitelisted commands (the gate holding; ROOTLESSKIT subject only — another domain's non-whitelisted ioctl is its own staircase's next-boundary evidence):"
  XP_DENIALS="$(printf '%s\n' "$TUN_AVC_WINDOW" | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' | grep -a 'denied  *{ ioctl }' | grep -a 'ioctlcmd=' | grep -av 'ioctlcmd=0x54ca' | grep -av 'ioctlcmd=0x54cb' || true)"
  printf '%s\n' "${XP_DENIALS:-(none — no non-whitelisted ioctl command was attempted)}"
  if [ -n "$TUN_REGRESSION" ]; then
    echo "GATE: a tun_tap_device_t denial hit the granted ordinary surface — the loaded TUN surface did not hold exactly as pinned"
    TUN_IOCTL_GONE_OK=0
  fi
  if [ -n "$OLD_TUN_IOCTL" ]; then
    echo "GATE: the exact 4C-13 ioctl(TUNSETIFF) boundary reappeared"
    TUN_IOCTL_GONE_OK=0
  fi
  if [ -n "$OLD_PERSIST_IOCTL" ]; then
    echo "GATE: the exact 4C-16 ioctl(TUNSETPERSIST) boundary reappeared"
    TUN_IOCTL_GONE_OK=0
  fi
  if [ -n "$MGR_SETPERSIST_EACCES" ]; then
    echo "GATE: the journal still shows the 4C-16 TUNSETPERSIST EACCES shape"
    TUN_IOCTL_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/14-tun-ioctl-gone.txt" 2>&1
cat "$EVIDENCE_DIR/14-tun-ioctl-gone.txt" >&2
if [ "$TUN_IOCTL_GONE_OK" = 1 ]; then
  marker "TUN-IOCTL-BOUNDARY=GONE"
  marker "TUN-DEVICE-ACCESS=CLEAN"
  # The 4C-30 next-boundary record, carried over: a NON-rootlesskit
  # domain's tun_tap_device_t denial, if one appeared. The slirp
  # helper's own TUN denials are owned by the 4C-31/4C-32/4C-33 helper
  # gates below (38-slirp-tun-rw-gone.txt, 39-slirp-tun-open-gone.txt,
  # 40-slirp-tun-ioctl-gone.txt); this raw record is informational only.
  TUN_OTHER_FIRST="$(printf '%s\n' "$TUN_OTHER_DOMAIN" | head -1 || true)"
  TUN_OTHER_PERMS="$(printf '%s\n' "$TUN_OTHER_FIRST" | sed -n 's/.*denied  *{ \([^}]*\) }.*/\1/p' || true)"
  TUN_OTHER_SUMMARY="$(printf '%s\n' "$TUN_OTHER_FIRST" | sed -n 's/.*scontext=\([^ ]*\) tcontext=\([^ ]*\) tclass=\([a-z_]*\).*/scontext=\1 tcontext=\2 tclass=\3/p' || true)"
  marker "HELPER-TUN-NEXT-BOUNDARY=${TUN_OTHER_SUMMARY:-none} perms=${TUN_OTHER_PERMS:-none}"
else
  marker "BLOCKER=the 4C-14 TUN ioctl composition did not hold on the loaded policy (see 14-tun-ioctl-gone.txt)"
  marker "TUN-IOCTL-BOUNDARY=FAIL"
  finish FAIL; exit 0
fi

# ---- the 4C-15 gate: the in-namespace CAP_NET_ADMIN check is now granted
# ---- (cap_userns net_admin), so the canonical 4C-14 boundary — denied
# ---- { net_admin } tclass=cap_userns self->self on the TUNSETIFF path —
# ---- must be GONE, and the kernel capability-check EPERM at that check
# ---- must be gone: the flow passed ns_capable(net->user_ns,
# ---- CAP_NET_ADMIN) and its TUNSETIFF request moved into the driver's
# ---- next LSM hook. The first new terminal boundary stays recorded by
# ---- the generic mechanism (10-avc-first-downstream.txt +
# ---- DOWNSTREAM-BOUNDARY marker); nothing downstream (tun_socket,
# ---- nlmsg, plain capability) is pre-granted here.
CAP_NETADMIN_GONE_OK=1
{
  echo "=== cap_userns AVCs of the window (the 4C-14 net_admin boundary must be absent) ==="
  CAP_AVC_WINDOW="$(grep -a 'tclass=cap_userns' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null || true)"
  printf '%s\n' "${CAP_AVC_WINDOW:-(none — no cap_userns denial in the window)}"
  echo "--- the exact 4C-14 shape (denied { net_admin } comm=ip scontext==tcontext=flow:c1):"
  OLD_CAP_NETADMIN="$(printf '%s\n' "$CAP_AVC_WINDOW" | grep -a 'denied  *{ net_admin }' | grep -a "scontext=system_u:system_r:$RK_DOMAIN:s0:" || true)"
  printf '%s\n' "${OLD_CAP_NETADMIN:-(none — the 4C-14 cap_userns net_admin denial is gone)}"
  echo "--- the manager journal's 4C-14 EPERM shape (must be gone):"
  MGR_IOCTL_EPERM="$(grep -a 'ioctl(TUNSETIFF): Operation not permitted' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null || true)"
  printf '%s\n' "${MGR_IOCTL_EPERM:-(none — the TUNSETIFF capability-check EPERM is gone)}"
  if [ -n "$OLD_CAP_NETADMIN" ]; then
    echo "GATE: the 4C-14 cap_userns net_admin boundary reappeared"
    CAP_NETADMIN_GONE_OK=0
  fi
  if [ -n "$MGR_IOCTL_EPERM" ]; then
    echo "GATE: the flow still dies at the in-namespace CAP_NET_ADMIN check (the journal still shows the 4C-14 EPERM shape)"
    CAP_NETADMIN_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/15-cap-netadmin-gone.txt" 2>&1
cat "$EVIDENCE_DIR/15-cap-netadmin-gone.txt" >&2
if [ "$CAP_NETADMIN_GONE_OK" = 1 ]; then
  marker "CAP-NETADMIN-BOUNDARY=GONE"
else
  marker "BLOCKER=the 4C-15 cap_userns net_admin composition did not hold (see 15-cap-netadmin-gone.txt)"
  marker "CAP-NETADMIN-BOUNDARY=FAIL"
  finish FAIL; exit 0
fi

# ---- the 4C-16 gate: the NEW-device TUNSETIFF creation hook is now
# ---- granted (self:tun_socket create), so the canonical 4C-15
# ---- boundary — denied { create } tclass=tun_socket self->self — must
# ---- be GONE, and the journal must no longer show the TUNSETIFF EACCES
# ---- shape: TUNSETIFF completes past security_tun_dev_create(). The
# ---- gate owns the ROOTLESSKIT subject's granted create shape only
# ---- (the 4C-33 correction, mirroring the 4C-30 TUN-gate correction:
# ---- another domain's tun_socket denial — notably the slirp helper's
# ---- attach-side relabel surface — is its own staircase's evidence,
# ---- recorded below and owned by the helper TUN gates, not failed
# ---- here). The next boundary (per the iproute2 tap_add_ioctl()
# ---- sequence, predicted TUNSETPERSIST 0x54cb) is NOT granted and is
# ---- recorded by the 14-gate's xperm-denial inventory and the generic
# ---- DOWNSTREAM-BOUNDARY mechanism; no route/nlmsg/attach authority is
# ---- pre-granted here.
TS_CREATE_GONE_OK=1
{
  echo "=== tun_socket AVCs of the window (raw; the ROOTLESSKIT create regression must be absent) ==="
  TS_AVC_WINDOW="$(grep -a 'tclass=tun_socket' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null || true)"
  printf '%s\n' "${TS_AVC_WINDOW:-(none — no tun_socket denial in the window)}"
  echo "--- the ROOTLESSKIT subject's tun_socket create denials (the 4C-15/4C-16 boundary shape — must be zero):"
  TS_RK_CREATE="$(printf '%s\n' "$TS_AVC_WINDOW" | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' | grep -a 'denied  *{ create }' || true)"
  printf '%s\n' "${TS_RK_CREATE:-(none — the 4C-16 tun_socket create grant held)}"
  echo "--- the ROOTLESSKIT subject's OTHER tun_socket denials (its staircase's own next-boundary evidence; recorded, not failed):"
  TS_RK_OTHER="$(printf '%s\n' "$TS_AVC_WINDOW" | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' | grep -av 'denied  *{ create }' || true)"
  printf '%s\n' "${TS_RK_OTHER:-(none)}"
  echo "--- OTHER subjects' tun_socket denials (their independent tun_socket staircases — recorded, not failed; the slirp helper's attach-side relabel surface is owned by the helper TUN gates below):"
  TS_OTHER_SUBJECT="$(printf '%s\n' "$TS_AVC_WINDOW" | grep -av 'scontext=system_u:system_r:docker_helper_rootlesskit_t' || true)"
  printf '%s\n' "${TS_OTHER_SUBJECT:-(none — no other-subject tun_socket denial appeared)}"
  echo "--- the manager journal's TUNSETIFF EACCES shape (must be gone — TUNSETIFF completes past security_tun_dev_create()):"
  MGR_TUNSETIFF_EACCES="$(grep -a 'ioctl(TUNSETIFF): Permission denied' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null || true)"
  printf '%s\n' "${MGR_TUNSETIFF_EACCES:-(none — the TUNSETIFF SELinux-hook EACCES is gone)}"
  if [ -n "$TS_RK_CREATE" ]; then
    echo "GATE: the ROOTLESSKIT subject's tun_socket create denial reappeared — the 4C-16 create grant did not take effect"
    TS_CREATE_GONE_OK=0
  fi
  if [ -n "$MGR_TUNSETIFF_EACCES" ]; then
    echo "GATE: the flow still dies inside TUNSETIFF (the journal still shows the SELinux-hook EACCES shape)"
    TS_CREATE_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/16-tunsocket-create-gone.txt" 2>&1
cat "$EVIDENCE_DIR/16-tunsocket-create-gone.txt" >&2
if [ "$TS_CREATE_GONE_OK" = 1 ]; then
  marker "TUN-SOCKET-CREATE-BOUNDARY=GONE"
else
  marker "BLOCKER=the 4C-16 tun_socket create composition did not hold (see 16-tunsocket-create-gone.txt)"
  marker "TUN-SOCKET-CREATE-BOUNDARY=FAIL"
  finish FAIL; exit 0
fi

# ---- evidence-only capture (the 4C-17 first-tuntap-completion proof):
# ---- the manager journal's child-output tail must have moved past the
# ---- tuntap command (no ioctl(TUNSETIFF/TUNSETPERSIST) error in the
# ---- tail — the failing step is now the NEXT command of the setup),
# ---- and a persisted TAP's devtmpfs node (if the kernel created one —
# ---- /dev/tap* is netns-independent) is recorded as direct tap0
# ---- evidence when present.
{
  echo "=== the child output tail (the last failing step of the network setup) ==="
  grep -a -A4 'child output tail' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null | head -8 || true
  echo "=== /dev/tap* nodes (persisted-TAP devtmpfs evidence; netns-independent) ==="
  ls -lZ /dev/tap* 2>/dev/null || echo "(no /dev/tap* node recorded)"
} > "$EVIDENCE_DIR/17-tuntap-completion.txt" 2>&1
cat "$EVIDENCE_DIR/17-tuntap-completion.txt" >&2

# ============================================================
# E: the 4C-21 NETLINK_ROUTE receive-side read gate
# ============================================================
# The 4C-21 grant: the generic receive-side read permission. The gate
# hard-fails if ANY of the three proven boundaries still appears in the
# window: the generic write (4C-19's hidden boundary), the message-class
# nlmsg_read (the 4C-19 canonical terminal denial), or the generic
# receive-side read (the 4C-20 -DB companion's terminal denial). Any
# OTHER netlink_route_socket denial — notably the mutation-class
# nlmsg_write the RTM_NEWLINK send would need — is the EXPECTED next
# boundary and is recorded, not failed: the fallback datagram creates
# remain visible and un-granted by design whenever the lookup still
# fails, and the fd-correlated chronology is reconstructed by the
# report from 18-syscall-chronology.txt and the dontaudit-disabled
# companion window (section CC).
NL_WRITE_GONE_OK=1
{
  echo "=== netlink_route_socket write + nlmsg_read + read + nlmsg_write AVCs of the window (all four proven boundaries must be absent) ==="
  NL_WRITE_AVC="$(grep -a 'tclass=netlink_route_socket' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -aE 'denied  *\{ (write|nlmsg_read|read|nlmsg_write) \}' || true)"
  printf '%s\n' "${NL_WRITE_AVC:-(none — the 4C-19 write, 4C-20 nlmsg_read, 4C-21 read, and 4C-22 nlmsg_write boundaries are all gone)}"
  echo "--- ALL other netlink_route_socket AVCs of the window (the next-boundary evidence; recorded, not failed):"
  NL_OTHER_AVC="$(grep -a 'tclass=netlink_route_socket' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -avE 'denied  *\{ (write|nlmsg_read) \}' || true)"
  printf '%s\n' "${NL_OTHER_AVC:-(none — no other netlink_route_socket denial appeared)}"
  echo "--- the userspace tail check: the lookup's failure shape (informational)"
  grep -a 'Cannot talk to rtnetlink\|Cannot find device' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null | tail -4 || true
  if [ -n "$NL_WRITE_AVC" ]; then
    echo "GATE: a write, nlmsg_read, read, or nlmsg_write netlink denial still appeared — the 4C-19/4C-20/4C-21/4C-22 grants did not take effect"
    NL_WRITE_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/21-netlink-write-gone.txt" 2>&1
cat "$EVIDENCE_DIR/21-netlink-write-gone.txt" >&2
if [ "$NL_WRITE_GONE_OK" = 1 ]; then
  marker "NETLINK-WRITE-BOUNDARY=GONE"
  marker "NETLINK-LOOKUP-CLASS-BOUNDARY=GONE"
  marker "NETLINK-RECEIVE-READ-BOUNDARY=GONE"
  marker "NETLINK-MUTATION-CLASS-BOUNDARY=GONE"
else
  marker "BLOCKER=the 4C-22 netlink_route_socket mutation-class composition did not hold (see 21-netlink-write-gone.txt)"
  marker "NETLINK-WRITE-BOUNDARY=FAIL"
  marker "NETLINK-LOOKUP-CLASS-BOUNDARY=FAIL"
  marker "NETLINK-RECEIVE-READ-BOUNDARY=FAIL"
  marker "NETLINK-MUTATION-CLASS-BOUNDARY=FAIL"
  finish FAIL; exit 0
fi

# ============================================================
# E2: the 4C-23 slirp4netns proc-traversal gate
# ============================================================
# The 4C-23 grant: the helper's dir-search authority over the
# categorized rootlesskit target's proc directories. The gate
# hard-fails if that proven boundary (slirp4netns_t:s0:cN →
# rootlesskit_t:s0:cN :dir search on /proc/<target-pid>/) still appears.
# Any OTHER helper-domain AVC (the namespace-path open — file/lnk_file
# on the ns magic links, an nsfs object, the setns capability checks)
# is the EXPECTED next boundary and is recorded, not failed; the report
# classifies it from the raw inventory below.
SL_SEARCH_GONE_OK=1
{
  echo "=== slirp4netns_t -> rootlesskit_t dir AVCs of the window (the 4C-23 boundary must be absent) ==="
  SL_SEARCH_AVC="$(grep -a 'tclass=dir' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -a 'tcontext=system_u:system_r:docker_helper_rootlesskit_t' || true)"
  printf '%s\n' "${SL_SEARCH_AVC:-(none — the 4C-23 /proc/<target-pid> traversal boundary is gone)}"
  echo "--- ALL other slirp4netns-domain AVCs of the window (the next-boundary evidence; recorded, not failed):"
  SL_OTHER_AVC="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -av 'tclass=dir' || true)"
  printf '%s\n' "${SL_OTHER_AVC:-(none — no other slirp4netns-domain denial appeared)}"
  echo "--- the helper's userspace failure shape (informational; the ready-fd wait is the stage marker)"
  grep -a 'slirp4netns\|waiting for ready fd' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null | tail -4 || true
  if [ -n "$SL_SEARCH_AVC" ]; then
    echo "GATE: the slirp4netns_t -> rootlesskit_t dir denial still appeared — the 4C-23 grant did not take effect"
    SL_SEARCH_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/26-slirp-proc-search-gone.txt" 2>&1
cat "$EVIDENCE_DIR/26-slirp-proc-search-gone.txt" >&2
if [ "$SL_SEARCH_GONE_OK" = 1 ]; then
  marker "SLIRP-PROC-SEARCH-BOUNDARY=GONE"
else
  marker "BLOCKER=the 4C-23 slirp4netns proc-traversal composition did not hold (see 26-slirp-proc-search-gone.txt)"
  marker "SLIRP-PROC-SEARCH-BOUNDARY=FAIL"
  finish FAIL; exit 0
fi

# ============================================================
# E3: the 4C-24 slirp4netns namespace magic-link read gate
# ============================================================
# The 4C-24 grant: the helper's lnk_file-read authority over the
# categorized rootlesskit target's proc magic-links (/proc/<pid>/ns/net
# and /proc/<pid>/ns/user on this kernel/policy pair are labeled as the
# target's lnk_file). The gate hard-fails if that proven boundary still
# appears. Any OTHER helper-domain AVC (the SELinux ptrace READ access
# check against the target SID — security_ptrace_access_check maps a
# PTRACE_MODE_READ check to slirp4netns_t -> rootlesskit_t:file read —
# an nsfs/file object behind the magic link, or a further proc shape)
# is the EXPECTED next boundary and is recorded, not failed.
SL_LNK_GONE_OK=1
{
  echo "=== slirp4netns_t -> rootlesskit_t lnk_file AVCs of the window (the 4C-24 boundary must be absent) ==="
  SL_LNK_AVC="$(grep -a 'tclass=lnk_file' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -a 'tcontext=system_u:system_r:docker_helper_rootlesskit_t' || true)"
  printf '%s\n' "${SL_LNK_AVC:-(none — the 4C-24 /proc/<target-pid>/ns magic-link read boundary is gone)}"
  echo "--- ALL other slirp4netns-domain AVCs of the window (the next-boundary evidence; recorded, not failed):"
  SL_LNK_OTHER_AVC="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -av 'tclass=lnk_file' || true)"
  printf '%s\n' "${SL_LNK_OTHER_AVC:-(none — no other slirp4netns-domain denial appeared)}"
  echo "--- the helper's userspace failure shape (informational)"
  grep -a 'slirp4netns\|waiting for ready fd' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null | tail -4 || true
  if [ -n "$SL_LNK_AVC" ]; then
    echo "GATE: the slirp4netns_t -> rootlesskit_t lnk_file denial still appeared — the 4C-24 grant did not take effect"
    SL_LNK_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/27-slirp-nslink-read-gone.txt" 2>&1
cat "$EVIDENCE_DIR/27-slirp-nslink-read-gone.txt" >&2
if [ "$SL_LNK_GONE_OK" = 1 ]; then
  marker "SLIRP-NSLINK-READ-BOUNDARY=GONE"
else
  marker "BLOCKER=the 4C-24 slirp4netns namespace magic-link read composition did not hold (see 27-slirp-nslink-read-gone.txt)"
  marker "SLIRP-NSLINK-READ-BOUNDARY=FAIL"
  finish FAIL; exit 0
fi

# ============================================================
# E4: the 4C-25 slirp4netns namespace-link ptrace gate
# ============================================================
# The 4C-25 grant: the helper's self:cap_userns sys_ptrace — the
# ptrace-may-access CAPABILITY prerequisite inside
# open("/proc/<target-pid>/ns/net", O_RDONLY) → proc_ns_get_link() →
# ptrace_may_access(target, PTRACE_MODE_READ_FSCREDS). ATTRIBUTION
# (corrected, mandatory): this is the proc namespace-link dereference
# boundary, NOT a setns boundary — a real setns(CLONE_NEWUSER) later
# reaches userns_install() whose privilege check is
# ns_capable(target_user_ns, CAP_SYS_ADMIN), not CAP_SYS_PTRACE. The
# gate hard-fails if the sys_ptrace cap_userns denial still appears.
# The next boundary candidates (recorded, not failed): the SELinux
# ptrace READ access check against the TARGET SID
# (slirp4netns_t -> rootlesskit_t:file read), the userns_install
# cap_userns sys_admin check, or another object behind the magic link.
SL_PTRACE_GONE_OK=1
{
  echo "=== slirp4netns_t self cap_userns sys_ptrace AVCs of the window (the 4C-25 boundary must be absent) ==="
  SL_PTRACE_AVC="$(grep -a 'tclass=cap_userns' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -a 'sys_ptrace' || true)"
  printf '%s\n' "${SL_PTRACE_AVC:-(none — the 4C-25 namespace-link dereference ptrace-may-access boundary is gone)}"
  echo "--- ALL other slirp4netns-domain AVCs of the window (the next-boundary evidence; recorded, not failed):"
  SL_PTRACE_OTHER_AVC="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -av 'tclass=cap_userns' || true)"
  printf '%s\n' "${SL_PTRACE_OTHER_AVC:-(none — no other slirp4netns-domain denial appeared)}"
  echo "--- the helper's userspace failure shape (informational)"
  grep -a 'slirp4netns\|waiting for ready fd' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null | tail -4 || true
  if [ -n "$SL_PTRACE_AVC" ]; then
    echo "GATE: the slirp4netns_t self cap_userns sys_ptrace denial still appeared — the 4C-25 grant did not take effect"
    SL_PTRACE_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/28-slirp-nslink-ptrace-gone.txt" 2>&1
cat "$EVIDENCE_DIR/28-slirp-nslink-ptrace-gone.txt" >&2
if [ "$SL_PTRACE_GONE_OK" = 1 ]; then
  marker "SLIRP-NSLINK-PTRACE-BOUNDARY=GONE"
else
  marker "BLOCKER=the 4C-25 slirp4netns namespace-link ptrace composition did not hold (see 28-slirp-nslink-ptrace-gone.txt)"
  marker "SLIRP-NSLINK-PTRACE-BOUNDARY=FAIL"
  finish FAIL; exit 0
fi

# ============================================================
# E5: the 4C-26 slirp4netns target-SID ptrace file-read gate
# ============================================================
# The 4C-26 grant: the helper's file-read authority toward the
# rootlesskit target — the SELinux PTRACE_MODE_READ target-SID check
# (security_ptrace_access_check). The gate hard-fails if that proven
# boundary still appears. Any OTHER helper-domain AVC (a further
# VFS/SELinux check on the followed namespace object — nsfs/file
# shapes, a getattr/open completion, or the userns_install sys_admin
# check) is the EXPECTED next boundary and is recorded, not failed.
SL_FILE_GONE_OK=1
{
  echo "=== slirp4netns_t -> rootlesskit_t file AVCs of the window (the 4C-26 boundary must be absent) ==="
  SL_FILE_AVC="$(grep -a 'tclass=file' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -a 'tcontext=system_u:system_r:docker_helper_rootlesskit_t' || true)"
  printf '%s\n' "${SL_FILE_AVC:-(none — the 4C-26 ptrace target-SID file-read boundary is gone)}"
  echo "--- ALL other slirp4netns-domain AVCs of the window (the next-boundary evidence; recorded, not failed):"
  SL_FILE_OTHER_AVC="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -av 'tclass=file' || true)"
  printf '%s\n' "${SL_FILE_OTHER_AVC:-(none — no other slirp4netns-domain denial appeared)}"
  echo "--- the helper's userspace failure shape (informational)"
  grep -a 'slirp4netns\|waiting for ready fd' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null | tail -4 || true
  if [ -n "$SL_FILE_AVC" ]; then
    echo "GATE: the slirp4netns_t -> rootlesskit_t file denial still appeared — the 4C-26 grant did not take effect"
    SL_FILE_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/29-slirp-ptrace-file-read-gone.txt" 2>&1
cat "$EVIDENCE_DIR/29-slirp-ptrace-file-read-gone.txt" >&2
if [ "$SL_FILE_GONE_OK" = 1 ]; then
  marker "SLIRP-PTRACE-FILE-READ-BOUNDARY=GONE"
else
  marker "BLOCKER=the 4C-26 slirp4netns target-SID ptrace file-read composition did not hold (see 29-slirp-ptrace-file-read-gone.txt)"
  marker "SLIRP-PTRACE-FILE-READ-BOUNDARY=FAIL"
  finish FAIL; exit 0
fi

# ============================================================
# E6: the 4C-28 slirp4netns nsfs namespace-handle read gate
# ============================================================
# The 4C-28 grant: the helper's nsfs_t:file read — the VFS open of the
# FOLLOWED namespace inode (nsfs_t:s0, globally labelled, NO MCS
# category) after the categorized proc-target chain (dir search, lnk
# read, target-SID file read) passes. The gate hard-fails ONLY when the
# GRANTED { read } surface itself is denied again (the grant did not
# take effect). A FURTHER nsfs permission (the predicted Case A:
# the VFS open's own { open } requirement — or a getattr shape) is the
# EXPECTED next boundary: it is recorded with its exact shape and the
# phase stops there with no further grant. The rootlesskit domain's
# separate nsfs getattr denial (the 4C-27 candidate boundary) was
# deliberately NOT granted; its reappearance is recorded, not failed.
SL_NSFS_GONE_OK=1
{
  echo "=== slirp4netns_t -> nsfs_t:file { read } AVCs of the window (the 4C-28 granted surface must be absent) ==="
  SL_NSFS_READ_AVC="$(grep -a 'tcontext=system_u:object_r:nsfs_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -a 'denied  *{ [^}]*read' || true)"
  printf '%s\n' "${SL_NSFS_READ_AVC:-(none — the 4C-28 namespace-handle read boundary is gone)}"
  echo "--- ALL other slirp4netns_t -> nsfs_t AVCs of the window (the next-boundary evidence — a further nsfs permission owns its own phase; recorded, not failed):"
  SL_NSFS_OTHER_AVC="$(grep -a 'tcontext=system_u:object_r:nsfs_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -av 'denied  *{ [^}]*read' || true)"
  printf '%s\n' "${SL_NSFS_OTHER_AVC:-(none — no further nsfs permission was attempted)}"
  echo "--- ALL other slirp4netns-domain AVCs of the window (recorded, not failed):"
  SL_NSFS_NONNSFS_AVC="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -av 'tcontext=system_u:object_r:nsfs_t' || true)"
  printf '%s\n' "${SL_NSFS_NONNSFS_AVC:-(none — no other slirp4netns-domain denial appeared)}"
  echo "--- the rootlesskit domain's nsfs AVCs of the window (the separate getattr candidate boundary stays UNGRANTED; recorded, not failed):"
  RK_NSFS_AVC="$(grep -a 'tcontext=system_u:object_r:nsfs_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' || true)"
  printf '%s\n' "${RK_NSFS_AVC:-(none — no rootlesskit_t -> nsfs_t denial in the window)}"
  echo "--- the helper's userspace failure shape (informational)"
  grep -a 'slirp4netns\|waiting for ready fd' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null | tail -4 || true
  if [ -n "$SL_NSFS_READ_AVC" ]; then
    echo "GATE: the slirp4netns_t -> nsfs_t:file read denial still appeared — the 4C-28 grant did not take effect"
    SL_NSFS_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/32-slirp-nsfs-read-gone.txt" 2>&1
cat "$EVIDENCE_DIR/32-slirp-nsfs-read-gone.txt" >&2
if [ "$SL_NSFS_GONE_OK" = 1 ]; then
  marker "SLIRP-NSFS-READ-BOUNDARY=GONE"
  # The next nsfs boundary from the recorded evidence (the predicted
  # Case A shape: a further permission on the same nsfs object); the
  # phase STOPS here — the boundary owns the next phase and is granted
  # by nothing in this composition.
  SL_NSFS_NEXT="$(printf '%s\n' "$SL_NSFS_OTHER_AVC" | head -1 || true)"
  SL_NSFS_NEXT_PERMS="$(printf '%s\n' "$SL_NSFS_NEXT" | sed -n 's/.*denied  *{ \([^}]*\) }.*/\1/p' || true)"
  SL_NSFS_NEXT_SUMMARY="$(printf '%s\n' "$SL_NSFS_NEXT" | sed -n 's/.*scontext=\([^ ]*\) tcontext=\([^ ]*\) tclass=\([a-z_]*\).*/scontext=\1 tcontext=\2 tclass=\3/p' || true)"
  marker "SLIRP-NSFS-NEXT-BOUNDARY=${SL_NSFS_NEXT_SUMMARY:-none} perms=${SL_NSFS_NEXT_PERMS:-none}"
else
  marker "BLOCKER=the 4C-28 slirp4netns nsfs namespace-handle read composition did not hold (see 32-slirp-nsfs-read-gone.txt)"
  marker "SLIRP-NSFS-READ-BOUNDARY=FAIL"
  finish FAIL; exit 0
fi

# ============================================================
# E7: the 4C-29 slirp4netns nsfs FILE__OPEN gate
# ============================================================
# The 4C-29 grant: the helper's nsfs_t:file open — the VFS open
# completion's separate FILE__OPEN permission on the followed namespace
# inode (the 4C-28 run's first new terminal boundary). The gate
# hard-fails ONLY when the granted { read open } surface itself is
# denied again (the grant did not take effect). A FURTHER nsfs
# permission (getattr/ioctl/lock shapes) is the EXPECTED next boundary:
# recorded with its exact shape; the phase stops there with no further
# grant. The rootlesskit domain's separate nsfs getattr denial stays
# UNGRANTED; its reappearance is recorded, not failed.
SL_NSFS_OPEN_GONE_OK=1
{
  echo "=== slirp4netns_t -> nsfs_t:file { read open } AVCs of the window (the 4C-29 granted surface must be absent) ==="
  SL_NSFS_GRANTED_AVC="$(grep -a 'tcontext=system_u:object_r:nsfs_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -aE 'denied  *\{ [^}]*\b(read|open)\b' || true)"
  printf '%s\n' "${SL_NSFS_GRANTED_AVC:-(none — the 4C-28 read and 4C-29 open boundaries are both gone)}"
  echo "--- ALL other slirp4netns_t -> nsfs_t AVCs of the window (the next-boundary evidence — a further nsfs permission owns its own phase; recorded, not failed):"
  SL_NSFS_OPEN_OTHER_AVC="$(grep -a 'tcontext=system_u:object_r:nsfs_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -avE 'denied  *\{ [^}]*\b(read|open)\b' || true)"
  printf '%s\n' "${SL_NSFS_OPEN_OTHER_AVC:-(none — no further nsfs permission was attempted)}"
  echo "--- ALL other slirp4netns-domain AVCs of the window (recorded, not failed):"
  SL_NSFS_OPEN_NONNSFS_AVC="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -av 'tcontext=system_u:object_r:nsfs_t' || true)"
  printf '%s\n' "${SL_NSFS_OPEN_NONNSFS_AVC:-(none — no other slirp4netns-domain denial appeared)}"
  echo "--- the rootlesskit domain's nsfs AVCs of the window (the separate getattr candidate boundary stays UNGRANTED; recorded, not failed):"
  RK_NSFS_OPEN_AVC="$(grep -a 'tcontext=system_u:object_r:nsfs_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' || true)"
  printf '%s\n' "${RK_NSFS_OPEN_AVC:-(none — no rootlesskit_t -> nsfs_t denial in the window)}"
  echo "--- the helper's userspace failure shape (informational)"
  grep -a 'slirp4netns\|waiting for ready fd' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null | tail -4 || true
  if [ -n "$SL_NSFS_GRANTED_AVC" ]; then
    echo "GATE: a slirp4netns_t -> nsfs_t:file read/open denial still appeared — the 4C-28/4C-29 grants did not take effect"
    SL_NSFS_OPEN_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/33-slirp-nsfs-open-gone.txt" 2>&1
cat "$EVIDENCE_DIR/33-slirp-nsfs-open-gone.txt" >&2
if [ "$SL_NSFS_OPEN_GONE_OK" = 1 ]; then
  marker "SLIRP-NSFS-OPEN-BOUNDARY=GONE"
  SL_NSFS_OPEN_NEXT="$(printf '%s\n' "$SL_NSFS_OPEN_OTHER_AVC" | head -1 || true)"
  SL_NSFS_OPEN_NEXT_PERMS="$(printf '%s\n' "$SL_NSFS_OPEN_NEXT" | sed -n 's/.*denied  *{ \([^}]*\) }.*/\1/p' || true)"
  SL_NSFS_OPEN_NEXT_SUMMARY="$(printf '%s\n' "$SL_NSFS_OPEN_NEXT" | sed -n 's/.*scontext=\([^ ]*\) tcontext=\([^ ]*\) tclass=\([a-z_]*\).*/scontext=\1 tcontext=\2 tclass=\3/p' || true)"
  marker "SLIRP-NSFS-NEXT-BOUNDARY=${SL_NSFS_OPEN_NEXT_SUMMARY:-none} perms=${SL_NSFS_OPEN_NEXT_PERMS:-none}"
else
  marker "BLOCKER=the 4C-29 slirp4netns nsfs FILE__OPEN composition did not hold (see 33-slirp-nsfs-open-gone.txt)"
  marker "SLIRP-NSFS-OPEN-BOUNDARY=FAIL"
  finish FAIL; exit 0
fi

# ============================================================
# 4C-29: decode the avc:selinux_audited tracepoint against the
# canonical audit slice (the audit-observation gap of run 36864816648
# makes userspace audit absence alone unusable; the kernel tracepoint
# records the SELinux decision independently). The decode CALIBRATES
# the numeric access-vector masks against co-captured symbolic AVC
# records in the same window — NO hardcoded bit map; uncalibrated
# events are reported raw.
# ============================================================
{
  echo "=== 4C-29 avc/selinux_audited availability (30-trace-arm.txt carries the format + the recorded class/perm mapping evidence) ==="
  echo "armed: $TRACE_AVC_ENABLED"
  echo "=== raw selinux_audited events of the canonical window (tracefs; independent of auditd) ==="
  grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || echo "(none — tracepoint unavailable or no audited decisions in the ring)"
  echo "=== calibration + decode (co-captured pid+tclass pairs; unpaired events stay raw) ==="
  awk -f /tmp/p4b-work/decode.awk "$EVIDENCE_DIR/30-trace-window.txt" "$EVIDENCE_DIR/09-avc-window.txt" 2>&1 || true
} > "$EVIDENCE_DIR/34-avc-trace-decode.txt" 2>&1
cat "$EVIDENCE_DIR/34-avc-trace-decode.txt" >&2

# ============================================================
# E8: the 4C-30 slirp4netns namespace-join sys_admin gate
# ============================================================
# The 4C-30 grant: the helper's self:cap_userns sys_admin — the
# namespace-join authority (the 4C-29 fatal netns setns boundary;
# the ignored CLONE_NEWUSER attempt shares the permission and its
# denials are non-terminal effects). The gate hard-fails if ANY
# slirp4netns_t cap_userns denial of a GRANTED permission (sys_admin or
# sys_ptrace) still appears; a DIFFERENT cap_userns permission
# (sys_chroot/net_admin — ungranted) is the EXPECTED next boundary and
# is recorded, not failed. Other helper-domain AVCs are recorded.
SL_NSJOIN_GONE_OK=1
{
  echo "=== slirp4netns_t cap_userns AVCs of granted perms (the 4C-25 sys_ptrace and 4C-30 sys_admin boundaries must be absent) ==="
  SL_NSJOIN_AVC="$(grep -a 'tclass=cap_userns' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -aE 'denied  *\{ [^}]*\b(sys_ptrace|sys_admin)\b' || true)"
  printf '%s\n' "${SL_NSJOIN_AVC:-(none — the namespace-join sys_admin boundary is gone)}"
  echo "--- ALL other slirp4netns_t cap_userns AVCs (ungranted perms — the next-boundary evidence; recorded, not failed):"
  SL_NSJOIN_OTHER_CAP="$(grep -a 'tclass=cap_userns' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -avE 'denied  *\{ [^}]*\b(sys_ptrace|sys_admin)\b' || true)"
  printf '%s\n' "${SL_NSJOIN_OTHER_CAP:-(none — no ungranted cap_userns permission was attempted)}"
  echo "--- ALL other slirp4netns-domain AVCs of the window (recorded, not failed):"
  SL_NSJOIN_NONCAP_AVC="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -av 'tclass=cap_userns' || true)"
  printf '%s\n' "${SL_NSJOIN_NONCAP_AVC:-(none — no other slirp4netns-domain denial appeared)}"
  echo "--- the helper's userspace failure shape (informational)"
  grep -a 'slirp4netns\|waiting for ready fd' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null | tail -4 || true
  if [ -n "$SL_NSJOIN_AVC" ]; then
    echo "GATE: a slirp4netns_t cap_userns sys_ptrace/sys_admin denial still appeared — the 4C-25/4C-30 grants did not take effect"
    SL_NSJOIN_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/37-slirp-nsjoin-sysadmin-gone.txt" 2>&1
cat "$EVIDENCE_DIR/37-slirp-nsjoin-sysadmin-gone.txt" >&2
if [ "$SL_NSJOIN_GONE_OK" = 1 ]; then
  marker "SLIRP-NSJOIN-SYSADMIN-BOUNDARY=GONE"
  SL_NSJOIN_NEXT="$(printf '%s\n' "$SL_NSJOIN_OTHER_CAP" | head -1 || true)"
  SL_NSJOIN_NEXT_PERMS="$(printf '%s\n' "$SL_NSJOIN_NEXT" | sed -n 's/.*denied  *{ \([^}]*\) }.*/\1/p' || true)"
  SL_NSJOIN_NEXT_SUMMARY="$(printf '%s\n' "$SL_NSJOIN_NEXT" | sed -n 's/.*scontext=\([^ ]*\) tcontext=\([^ ]*\) tclass=\([a-z_]*\).*/scontext=\1 tcontext=\2 tclass=\3/p' || true)"
  marker "SLIRP-NSJOIN-NEXT-BOUNDARY=${SL_NSJOIN_NEXT_SUMMARY:-none} perms=${SL_NSJOIN_NEXT_PERMS:-none}"
else
  marker "BLOCKER=the 4C-30 slirp4netns namespace-join sys_admin composition did not hold (see 37-slirp-nsjoin-sysadmin-gone.txt)"
  marker "SLIRP-NSJOIN-SYSADMIN-BOUNDARY=FAIL"
  finish FAIL; exit 0
fi

# ============================================================
# 4C-31: the slirp4netns helper TUN device-node gate (SLIRP-TUN-RW-BOUNDARY)
# ============================================================
# The 4C-31 grant: the helper's tun_tap_device_t:chr_file { read write }
# — the 4C-30 open("/dev/net/tun", O_RDWR) boundary. The gate owns ONLY
# the helper domain's TUN read/write pair (the 4C-14 gate above owns the
# RootlessKit surface): it hard-fails if any slirp4netns_t
# tun_tap_device_t:chr_file denial of a GRANTED permission (read or
# write) still appears. The 4C-32 widening moved the open permission to
# the granted surface; its regression is owned by the
# 39-slirp-tun-open-gone.txt gate below, and the 4C-33 generic ioctl
# permission's regression is owned by the 40-slirp-tun-ioctl-gone.txt
# gate. Any OTHER helper TUN permission (getattr/append/lock/create/
# setattr — ungranted) is the EXPECTED next boundary and is
# recorded, not failed.
SL_TUN_GONE_OK=1
{
  echo "=== slirp4netns_t tun_tap_device_t AVCs of granted perms (the 4C-31 read/write device-node boundary must be absent) ==="
  SL_TUN_AVC="$(grep -a 'tcontext=system_u:object_r:tun_tap_device_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -aE 'denied  *\{ [^}]*\b(read|write)\b' || true)"
  printf '%s\n' "${SL_TUN_AVC:-(none — the 4C-31 TUN read/write boundary is gone)}"
  echo "--- ALL other slirp4netns_t tun_tap_device_t AVCs (ungranted perms — the next-boundary evidence; recorded, not failed):"
  SL_TUN_OTHER_TUN="$(grep -a 'tcontext=system_u:object_r:tun_tap_device_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -avE 'denied  *\{ [^}]*\b(read|write)\b' || true)"
  printf '%s\n' "${SL_TUN_OTHER_TUN:-(none — no ungranted helper TUN permission was attempted)}"
  echo "--- the tracepoint decode's helper TUN decisions (34-avc-trace-decode.txt; informational, uncalibrated events stay raw):"
  grep -a 'HELPER' "$EVIDENCE_DIR/34-avc-trace-decode.txt" 2>/dev/null | grep -a 'tclass=chr_file' || true
  echo "--- the helper's userspace failure shape (informational)"
  grep -a 'slirp4netns\|waiting for ready fd' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null | tail -4 || true
  if [ -n "$SL_TUN_AVC" ]; then
    echo "GATE: a slirp4netns_t tun_tap_device_t read/write denial still appeared — the 4C-31 grant did not take effect"
    SL_TUN_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/38-slirp-tun-rw-gone.txt" 2>&1
cat "$EVIDENCE_DIR/38-slirp-tun-rw-gone.txt" >&2
if [ "$SL_TUN_GONE_OK" = 1 ]; then
  marker "SLIRP-TUN-RW-BOUNDARY=GONE"
  SL_TUN_NEXT_FIRST="$(printf '%s\n' "$SL_TUN_OTHER_TUN" | head -1 || true)"
  SL_TUN_NEXT_PERMS="$(printf '%s\n' "$SL_TUN_NEXT_FIRST" | sed -n 's/.*denied  *{ \([^}]*\) }.*/\1/p' || true)"
  SL_TUN_NEXT_SUMMARY="$(printf '%s\n' "$SL_TUN_NEXT_FIRST" | sed -n 's/.*scontext=\([^ ]*\) tcontext=\([^ ]*\) tclass=\([a-z_]*\).*/scontext=\1 tcontext=\2 tclass=\3/p' || true)"
  SL_TUN_NEXT_IOCTL="$(printf '%s\n' "$SL_TUN_NEXT_FIRST" | sed -n 's/.*ioctlcmd=\([0-9a-fx]*\).*/\1/p' || true)"
  marker "SLIRP-TUN-NEXT-BOUNDARY=${SL_TUN_NEXT_SUMMARY:-none} perms=${SL_TUN_NEXT_PERMS:-none} ioctlcmd=${SL_TUN_NEXT_IOCTL:-none}"
else
  marker "BLOCKER=the 4C-31 slirp4netns TUN read/write composition did not hold (see 38-slirp-tun-rw-gone.txt)"
  marker "SLIRP-TUN-RW-BOUNDARY=FAIL"
  finish FAIL; exit 0
fi

# 4C-32: the slirp4netns helper TUN device-node open gate
# (SLIRP-TUN-OPEN-BOUNDARY)
# ============================================================
# The 4C-32 grant: the helper's tun_tap_device_t:chr_file open — the
# second SELinux hook of the SAME open(O_RDWR) syscall (the 4C-31
# rerun's first new terminal boundary, audit record 2820). The gate
# hard-fails ONLY when the whole granted { read write open } surface is
# denied again (the 4C-31/4C-32 grants did not take effect). A FURTHER
# chr_file permission — ioctl (the 40-slirp-tun-ioctl-gone.txt gate
# below owns the generic-ioctl regression and the command-level
# xperm record) / getattr/append/lock/create/setattr (ungranted) — is
# the EXPECTED next boundary: recorded
# numerically, not failed; the phase stops there with no further grant.
SL_TUN_OPEN_GONE_OK=1
{
  echo "=== slirp4netns_t tun_tap_device_t AVCs of granted perms (the 4C-31 read/write and 4C-32 open device-node boundaries must be absent) ==="
  SL_TUN_OPEN_GRANTED_AVC="$(grep -a 'tcontext=system_u:object_r:tun_tap_device_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -aE 'denied  *\{ [^}]*\b(read|write|open)\b' || true)"
  printf '%s\n' "${SL_TUN_OPEN_GRANTED_AVC:-(none — the 4C-31/4C-32 TUN read/write/open boundaries are gone)}"
  echo "--- ALL other slirp4netns_t tun_tap_device_t AVCs (ungranted perms — the next-boundary evidence; an ioctlcmd= value is the command-level boundary; recorded, not failed):"
  SL_TUN_OPEN_OTHER_TUN="$(grep -a 'tcontext=system_u:object_r:tun_tap_device_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -avE 'denied  *\{ [^}]*\b(read|write|open)\b' || true)"
  printf '%s\n' "${SL_TUN_OPEN_OTHER_TUN:-(none — no ungranted helper TUN permission was attempted)}"
  echo "--- the helper's openat('/dev/net/tun') + reached ioctl trace lines (fd/cmd/arg/ret; the causal open-success + any TUN command, recorded numerically):"
  grep -a 'slirp4netns' "$EVIDENCE_DIR/30-trace-relevant.txt" 2>/dev/null | grep -a '/dev/net/tun\|sys_ioctl' || true
  echo "--- the tracepoint decode's helper TUN decisions (34-avc-trace-decode.txt; informational, uncalibrated events stay raw):"
  grep -a 'HELPER' "$EVIDENCE_DIR/34-avc-trace-decode.txt" 2>/dev/null | grep -a 'tclass=chr_file' || true
  echo "--- the helper's userspace failure shape (informational)"
  grep -a 'slirp4netns\|waiting for ready fd' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null | tail -4 || true
  if [ -n "$SL_TUN_OPEN_GRANTED_AVC" ]; then
    echo "GATE: a slirp4netns_t tun_tap_device_t read/write/open denial still appeared — the 4C-31/4C-32 grants did not take effect"
    SL_TUN_OPEN_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/39-slirp-tun-open-gone.txt" 2>&1
cat "$EVIDENCE_DIR/39-slirp-tun-open-gone.txt" >&2
if [ "$SL_TUN_OPEN_GONE_OK" = 1 ]; then
  marker "SLIRP-TUN-OPEN-BOUNDARY=GONE"
  SL_TUN_OPEN_NEXT_FIRST="$(printf '%s\n' "$SL_TUN_OPEN_OTHER_TUN" | head -1 || true)"
  SL_TUN_OPEN_NEXT_PERMS="$(printf '%s\n' "$SL_TUN_OPEN_NEXT_FIRST" | sed -n 's/.*denied  *{ \([^}]*\) }.*/\1/p' || true)"
  SL_TUN_OPEN_NEXT_SUMMARY="$(printf '%s\n' "$SL_TUN_OPEN_NEXT_FIRST" | sed -n 's/.*scontext=\([^ ]*\) tcontext=\([^ ]*\) tclass=\([a-z_]*\).*/scontext=\1 tcontext=\2 tclass=\3/p' || true)"
  SL_TUN_OPEN_NEXT_IOCTL="$(printf '%s\n' "$SL_TUN_OPEN_NEXT_FIRST" | sed -n 's/.*ioctlcmd=\([0-9a-fx]*\).*/\1/p' || true)"
  marker "SLIRP-TUN-NEXT-BOUNDARY=${SL_TUN_OPEN_NEXT_SUMMARY:-none} perms=${SL_TUN_OPEN_NEXT_PERMS:-none} ioctlcmd=${SL_TUN_OPEN_NEXT_IOCTL:-none}"
else
  marker "BLOCKER=the 4C-32 slirp4netns TUN open composition did not hold (see 39-slirp-tun-open-gone.txt)"
  marker "SLIRP-TUN-OPEN-BOUNDARY=FAIL"
  finish FAIL; exit 0
fi

# 4C-33: the slirp4netns helper TUN device-node ioctl gate
# (SLIRP-TUN-IOCTL-BOUNDARY)
# ============================================================
# The 4C-33 grant: the helper's tun_tap_device_t:chr_file ioctl — the
# GENERIC ioctl permission (the 4C-32 canonical run's first new
# terminal boundary: cmd 0x400454ca = TUNSETIFF recorded numerically).
# The gate hard-fails when the granted read/write/open surface is
# denied again, OR when a helper ioctl denial WITHOUT an ioctlcmd=
# value appears (a generic-ioctl av-stage regression). A helper ioctl
# denial CARRYING ioctlcmd= is the EXPECTED extended-permission
# (xperm) command denial: the preflight proves the loaded union is
# exactly { ioctl open read write } with an EMPTY helper xperm bitmap,
# so the ordinary ioctl permission cannot itself deny — a
# command-carrying denial is the command-level stage for a
# non-whitelisted command (TUNSETIFF 0x54ca is the predicted shape; its
# whitelist is the NEXT staircase owner, granted by NOTHING here). The
# syscall trace lines (fd/cmd/arg/ret) and the avc/selinux_audited
# masks carry the decision causally; helper cap_capable failures and
# tun_socket/cap_userns AVCs are recorded to prove which deeper hooks
# were or were not reached.
SL_TUN_IOCTL_GONE_OK=1
{
  echo "=== slirp4netns_t tun_tap_device_t AVCs of granted perms (the 4C-31/4C-32 read/write/open device-node boundaries must be absent) ==="
  SL_TUN_IOCTL_GRANTED_AVC="$(grep -a 'tcontext=system_u:object_r:tun_tap_device_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -aE 'denied  *\{ [^}]*\b(read|write|open)\b' || true)"
  printf '%s\n' "${SL_TUN_IOCTL_GRANTED_AVC:-(none — the 4C-31/4C-32 TUN read/write/open boundaries are gone)}"
  echo "--- helper ioctl denials WITHOUT ioctlcmd= (the generic ioctl permission's own av-stage regression — hard failure):"
  SL_TUN_IOCTL_GENERIC_REGRESSION="$(grep -a 'tcontext=system_u:object_r:tun_tap_device_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -a 'denied  *{ ioctl }' | grep -av 'ioctlcmd=' || true)"
  printf '%s\n' "${SL_TUN_IOCTL_GENERIC_REGRESSION:-(none — the 4C-33 generic ioctl permission held)}"
  echo "--- helper ioctl denials WITH ioctlcmd= (the EXPECTED xperm-stage command denial for a non-whitelisted command — the next-boundary evidence; recorded, not failed; the whitelist is granted by nothing in this composition):"
  SL_TUN_IOCTL_XPERM_AVC="$(grep -a 'tcontext=system_u:object_r:tun_tap_device_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -a 'denied  *{ ioctl }' | grep -a 'ioctlcmd=' || true)"
  printf '%s\n' "${SL_TUN_IOCTL_XPERM_AVC:-(none — no helper TUN ioctl denial was recorded in the window)}"
  echo "--- ALL other slirp4netns_t tun_tap_device_t AVCs (further ungranted ordinary perms — next-boundary evidence; recorded, not failed):"
  SL_TUN_IOCTL_OTHER_TUN="$(grep -a 'tcontext=system_u:object_r:tun_tap_device_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | grep -avE 'denied  *\{ [^}]*\b(read|write|open)\b' | grep -av 'denied  *{ ioctl }' || true)"
  printf '%s\n' "${SL_TUN_IOCTL_OTHER_TUN:-(none — no further helper TUN permission was attempted)}"
  echo "--- the helper's tun_socket + cap_userns AVCs of the window (the DEEPER TUN-attach surface: since 4C-35 the relabelfrom grant is owned by 43-slirp-tun-relabel-gone.txt below — any relabelto/attach_queue shape is the next-boundary evidence, recorded, not failed; a cap_userns shape is the capability boundary — recorded):"
  SL_TUN_IOCTL_DEEPER_AVC="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -aE 'tclass=(tun_socket|cap_userns)' || true)"
  printf '%s\n' "${SL_TUN_IOCTL_DEEPER_AVC:-(none — no helper tun_socket/cap_userns AVC appeared)}"
  echo "--- the helper's cap_capable FAILED checks in the trace ring (ret<0 — a reached driver-side capability denial; expected none):"
  grep -a '^     slirp4netns-' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | grep -a 'cap_capable:' | grep -av ' ret 0' || true
  echo "(end of failed-cap_capable lines)"
  echo "--- the helper's openat('/dev/net/tun') + ioctl trace lines (fd/cmd/arg/ret; the causal open-success + the reached TUN command's decision):"
  grep -a 'slirp4netns' "$EVIDENCE_DIR/30-trace-relevant.txt" 2>/dev/null | grep -a '/dev/net/tun\|sys_ioctl' || true
  echo "--- the tracepoint decode's helper TUN decisions (34-avc-trace-decode.txt; informational, uncalibrated events stay raw):"
  grep -a 'HELPER' "$EVIDENCE_DIR/34-avc-trace-decode.txt" 2>/dev/null | grep -a 'tclass=chr_file' || true
  echo "--- the helper's userspace failure shape (informational)"
  grep -a 'slirp4netns\|waiting for ready fd' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null | tail -4 || true
  if [ -n "$SL_TUN_IOCTL_GRANTED_AVC" ]; then
    echo "GATE: a slirp4netns_t tun_tap_device_t read/write/open denial still appeared — the 4C-31/4C-32 grants did not take effect"
    SL_TUN_IOCTL_GONE_OK=0
  fi
  if [ -n "$SL_TUN_IOCTL_GENERIC_REGRESSION" ]; then
    echo "GATE: a slirp4netns_t tun_tap_device_t ioctl denial WITHOUT ioctlcmd= appeared — the 4C-33 generic ioctl grant did not take effect"
    SL_TUN_IOCTL_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/40-slirp-tun-ioctl-gone.txt" 2>&1
cat "$EVIDENCE_DIR/40-slirp-tun-ioctl-gone.txt" >&2
if [ "$SL_TUN_IOCTL_GONE_OK" = 1 ]; then
  marker "SLIRP-TUN-IOCTL-BOUNDARY=GONE"
  SL_TUN_IOCTL_NEXT_FIRST="$(printf '%s\n' "$SL_TUN_IOCTL_XPERM_AVC" | head -1 || true)"
  if [ -z "$SL_TUN_IOCTL_NEXT_FIRST" ]; then
    SL_TUN_IOCTL_NEXT_FIRST="$(printf '%s\n' "$SL_TUN_IOCTL_OTHER_TUN" | head -1 || true)"
  fi
  if [ -z "$SL_TUN_IOCTL_NEXT_FIRST" ]; then
    SL_TUN_IOCTL_NEXT_FIRST="$(printf '%s\n' "$SL_TUN_IOCTL_DEEPER_AVC" | head -1 || true)"
  fi
  SL_TUN_IOCTL_NEXT_PERMS="$(printf '%s\n' "$SL_TUN_IOCTL_NEXT_FIRST" | sed -n 's/.*denied  *{ \([^}]*\) }.*/\1/p' || true)"
  SL_TUN_IOCTL_NEXT_SUMMARY="$(printf '%s\n' "$SL_TUN_IOCTL_NEXT_FIRST" | sed -n 's/.*scontext=\([^ ]*\) tcontext=\([^ ]*\) tclass=\([a-z_]*\).*/scontext=\1 tcontext=\2 tclass=\3/p' || true)"
  SL_TUN_IOCTL_NEXT_IOCTL="$(printf '%s\n' "$SL_TUN_IOCTL_NEXT_FIRST" | sed -n 's/.*ioctlcmd=\([0-9a-fx]*\).*/\1/p' || true)"
  marker "SLIRP-TUN-NEXT-BOUNDARY=${SL_TUN_IOCTL_NEXT_SUMMARY:-none} perms=${SL_TUN_IOCTL_NEXT_PERMS:-none} ioctlcmd=${SL_TUN_IOCTL_NEXT_IOCTL:-none}"
else
  marker "BLOCKER=the 4C-33 slirp4netns TUN generic-ioctl composition did not hold (see 40-slirp-tun-ioctl-gone.txt)"
  marker "SLIRP-TUN-IOCTL-BOUNDARY=FAIL"
  finish FAIL; exit 0
fi

# ============================================================
# 4C-37: the cross-operation TUN isolation proof (proof-only)
# ============================================================
# ZERO policy delta. The proof establishes, on the LIVE production paths
# of two simultaneously alive Build Operations with different MCS
# categories, that the helper domain's authority performs the same-
# operation attach (the 4C-36 clean chain) but stops at a REAL causal
# boundary when applied to the other operation's namespace/socket state.
# The vehicle is the composition's own entry path: a static helper
# binary swapped by rename (the 4C-36 mechanism), which runs the control
# leg against its own parent and the attack leg against operation A's
# rootlesskit netns-owner pid, delivered inside the vehicle's own
# binary tail (read via the helper's existing entry-file authority).
# Lifecycle noise (the retained-flow signull/sigkill/signal denials of
# 4C-36) is inventoried separately and never gates this phase.
marker "CROSS-OP: isolation proof window start"
CROSS_T0="$(date +%s)"
# PID capture: the canonical helper's nsjoin opens /proc/<pid>/ns/user;
# that pid is operation A's rootlesskit netns-owner process. The vehicle
# runs as the SECOND slot (the product's concurrency ceiling is 2 and
# retained entries count toward it — proven live in the 4C-37 diagnosis
# runs), so its attack target is operation A only.
CROSS_A_PID="$(grep -aoE '/proc/[0-9]+/ns/user' "$EVIDENCE_DIR/30-trace-relevant.txt" 2>/dev/null | head -1 | grep -aoE '[0-9]+' || true)"
echo "cross-op identities: A(exe-pid)=$CROSS_A_PID"
CROSS_PIDS_OK=1
case "$CROSS_A_PID" in ''|*[!0-9]*) CROSS_PIDS_OK=0;; esac
# A-side binding inventory, taken BEFORE the vehicle window: the attack
# target's live operation identity (pid, namespace inodes, process
# label/category, tap0 presence in its netns). The vehicle re-checks the
# target's liveness inside its own attack leg (an ENOENT stop is
# IDENTITY-FAIL, never a security boundary), and the post-window re-check
# below detects mid-window PID reuse.
{
  echo "=== 4C-37 A-side binding inventory (the attack target, bound before the window) ==="
  echo "A exe-pid: $CROSS_A_PID"
  if [ -d "/proc/$CROSS_A_PID" ]; then
    echo "A alive at binding: YES"
    echo "A comm:         $(cat "/proc/$CROSS_A_PID/comm" 2>/dev/null)"
    echo "A ns/user:      $(readlink "/proc/$CROSS_A_PID/ns/user" 2>/dev/null)"
    echo "A ns/net:       $(readlink "/proc/$CROSS_A_PID/ns/net" 2>/dev/null)"
    echo "A attr/current: $(cat "/proc/$CROSS_A_PID/attr/current" 2>/dev/null)"
    echo "A tap0:         $(grep -a 'tap0' "/proc/$CROSS_A_PID/net/dev" 2>/dev/null | head -1)"
  else
    echo "A alive at binding: NO (stale target binding — the proof must not run against a stale target)"
  fi
} > /tmp/p4b-work/cross-a-inventory.txt
cat /tmp/p4b-work/cross-a-inventory.txt >&2
if [ "$CROSS_PIDS_OK" = 1 ] && [ ! -e "$TRANSFERRED/tun-cross-op-vehicle" ]; then
  note "the transferred cross-op vehicle binary is missing — the isolation proof cannot run"
  CROSS_PIDS_OK=0
fi
if [ "$CROSS_PIDS_OK" != 1 ]; then
  marker "CROSS-OPERATION-ISOLATION=NOT_PROVEN"
  marker "BLOCKER=the cross-op proof could not bind its identities (see 45-cross-op-isolation.txt)"
else
  # Stage the vehicle inside /usr/bin and append the target line, then
  # swap by rename (an alive helper holds the path's inode open). The
  # helper reads the targets from its OWN installed binary via the
  # existing entry-file read authority.
  cp -p /usr/bin/slirp4netns /usr/bin/.cross-op-orig \
    || { note "the cross-op window could not back up the flow binary"; finish INCOMPLETE; exit 0; }
  cp "$TRANSFERRED/tun-cross-op-vehicle" /usr/bin/.cross-op-vehicle \
    || { note "the cross-op window could not stage the vehicle"; finish INCOMPLETE; exit 0; }
  printf 'CROSS-OP-TARGETS %s\n' "$CROSS_A_PID" >> /usr/bin/.cross-op-vehicle
  # The expected sha is the STAGED inode's (with the appended target line
  # — the 4C-37 vehicle reads its targets from its own binary tail).
  CROSS_EXPECTED_SHA="$(sha256sum /usr/bin/.cross-op-vehicle 2>/dev/null | awk '{print $1}')"
  mv /usr/bin/.cross-op-vehicle /usr/bin/slirp4netns \
    || { note "the cross-op window could not rename the vehicle into place"; finish INCOMPLETE; exit 0; }
  restorecon /usr/bin/slirp4netns 2>/dev/null || true
  CROSS_PLACED_SHA="$(sha256sum /usr/bin/slirp4netns 2>/dev/null | awk '{print $1}')"
  CROSS_PLACED_CTX="$(context_of /usr/bin/slirp4netns)"
  CROSS_PLACED_TYPE="$(printf '%s' "$CROSS_PLACED_CTX" | cut -d: -f3)"
  echo "placed vehicle sha256: $CROSS_PLACED_SHA (expected $CROSS_EXPECTED_SHA)"
  echo "placed vehicle label:  $CROSS_PLACED_CTX"
  if [ "$CROSS_PLACED_SHA" != "$CROSS_EXPECTED_SHA" ] || [ "$CROSS_PLACED_TYPE" != "docker_helper_slirp4netns_exec_t" ]; then
    note "the cross-op vehicle placement failed its byte/label check"
    mv /usr/bin/.cross-op-vehicle /usr/bin/slirp4netns 2>/dev/null || true
    restorecon /usr/bin/slirp4netns 2>/dev/null || true
    marker "CROSS-OPERATION-ISOLATION=NOT_PROVEN"
    marker "BLOCKER=the cross-op vehicle placement failed (see 45-cross-op-isolation.txt)"
    finish INCOMPLETE; exit 0
  fi
  # Re-arm a FRESH trace ring for the cross-op window: the syscall
  # tracepoints (openat/setns/ioctl enter/exit with the numeric results)
  # + capability/cap_capable + avc/selinux_audited — the vehicle's every
  # step is causally recorded with its scontext/tcontext.
  CROSS_TRACE_ENABLED=0
  if [ "$TRACE_ENABLED" = 1 ]; then
    echo 0 > "$TRACING/tracing_on" 2>/dev/null || true
    echo > "$TRACING/trace" 2>/dev/null || true
    echo 16384 > "$TRACING/buffer_size_kb" 2>/dev/null || true
    echo 1 > "$TRACING/events/capability/cap_capable/enable" 2>/dev/null || true
    echo 1 > "$TRACING/events/syscalls/sys_enter_openat/enable" 2>/dev/null || true
    echo 1 > "$TRACING/events/syscalls/sys_exit_openat/enable" 2>/dev/null || true
    echo 1 > "$TRACING/events/syscalls/sys_enter_setns/enable" 2>/dev/null || true
    echo 1 > "$TRACING/events/syscalls/sys_exit_setns/enable" 2>/dev/null || true
    echo 1 > "$TRACING/events/syscalls/sys_enter_ioctl/enable" 2>/dev/null || true
    echo 1 > "$TRACING/events/syscalls/sys_exit_ioctl/enable" 2>/dev/null || true
    if [ -d "$TRACING/events/avc/selinux_audited" ]; then
      echo 1 > "$TRACING/events/avc/selinux_audited/enable" 2>/dev/null || true
    fi
    echo 1 > "$TRACING/tracing_on" 2>/dev/null || true \
      && CROSS_TRACE_ENABLED=1
  fi
  # START in the background; the vehicle's window is the first ~1s; the
  # harvest is bounded BEFORE the manager's readiness-loop poll flood.
  CROSS_OP_ID="$(gen_op_id)"
  CROSS_RT_OP_DIR="$RUNTIME_ROOT/ops/$CROSS_OP_ID"
  CROSS_ST_OP_DIR="$STATE_ROOT/ops/$CROSS_OP_ID"
  printf 'START %s\n' "$CROSS_OP_ID" | timeout 120 socat - UNIX-CONNECT:"$MANAGER_SOCK" \
    > /tmp/p4b-work/cross-start-out.txt 2>/dev/null &
  CROSS_START_PID=$!
  sleep 3
  if [ "$CROSS_TRACE_ENABLED" = 1 ]; then
    echo 0 > "$TRACING/tracing_on" 2>/dev/null || true
    cat "$TRACING/trace" > /tmp/p4b-work/cross-trace.txt 2>/dev/null || true
    echo 0 > "$TRACING/events/capability/cap_capable/enable" 2>/dev/null || true
    echo 0 > "$TRACING/events/syscalls/sys_enter_openat/enable" 2>/dev/null || true
    echo 0 > "$TRACING/events/syscalls/sys_exit_openat/enable" 2>/dev/null || true
    echo 0 > "$TRACING/events/syscalls/sys_enter_setns/enable" 2>/dev/null || true
    echo 0 > "$TRACING/events/syscalls/sys_exit_setns/enable" 2>/dev/null || true
    echo 0 > "$TRACING/events/syscalls/sys_enter_ioctl/enable" 2>/dev/null || true
    echo 0 > "$TRACING/events/syscalls/sys_exit_ioctl/enable" 2>/dev/null || true
    echo 0 > "$TRACING/events/avc/selinux_audited/enable" 2>/dev/null || true
  else
    : > /tmp/p4b-work/cross-trace.txt
  fi
  wait "$CROSS_START_PID" 2>/dev/null || true
  CROSS_START_OUT="$(cat /tmp/p4b-work/cross-start-out.txt 2>/dev/null || true)"
  # The bounded convergence wait for the cross op's cleanup (orders the
  # AVC slice after the op tree is gone).
  CROSS_PID=""
  CROSS_END=$(( $(date +%s) + 75 ))
  while [ "$(date +%s)" -lt "$CROSS_END" ]; do
    if [ -z "$CROSS_PID" ] && [ -s "$CROSS_RT_OP_DIR/instance.pid" ]; then
      CROSS_PID="$(cat "$CROSS_RT_OP_DIR/instance.pid" 2>/dev/null)"
    fi
    if [ -n "$CROSS_PID" ] && [ ! -d "/proc/$CROSS_PID" ] && [ ! -d "$CROSS_RT_OP_DIR" ] && [ ! -d "$CROSS_ST_OP_DIR" ]; then
      break
    fi
    sleep 0.05
  done
  harvest_avcs_since "$CROSS_T0" /tmp/p4b-work/cross-avc-slice.txt
  {
    echo "=== 4C-37 cross-operation isolation window (vehicle in the helper domain; ZERO policy delta) ==="
    echo "window-start: $CROSS_T0"
    echo "START: $CROSS_OP_ID (response: $CROSS_START_OUT)"
    echo "window-end: $(date +%s)"
    echo "identity bindings: A(exe-pid)=$CROSS_A_PID vehicle-op=$CROSS_OP_ID instance-pid=${CROSS_PID:-(not observed)}"
    echo "placed vehicle sha256: $CROSS_PLACED_SHA"
    echo "placed vehicle label:  $CROSS_PLACED_CTX"
    echo "=== the vehicle's step/verdict lines that reached the journal (informational: rootlesskit wires the helper's stderr into its logrus debug writer, so at the default log level these lines are dropped — the kernel trace below is the authoritative channel) ==="
    journalctl -u "$UNIT" --since "@$CROSS_T0" --no-pager 2>/dev/null | grep -aE 'VEHICLE-(ID|STEP|VERDICT)' | head -40 || true
    echo "(end of vehicle journal lines)"
    echo "=== A-side binding inventory (bound before the window) ==="
    cat /tmp/p4b-work/cross-a-inventory.txt
    echo "=== A-side post-window re-check (the PID-reuse guard) ==="
    if [ -d "/proc/$CROSS_A_PID" ]; then
      echo "A alive at window end: YES"
      echo "A ns/user now:      $(readlink "/proc/$CROSS_A_PID/ns/user" 2>/dev/null)"
      echo "A ns/net  now:      $(readlink "/proc/$CROSS_A_PID/ns/net" 2>/dev/null)"
      echo "A attr/current now: $(cat "/proc/$CROSS_A_PID/attr/current" 2>/dev/null)"
    else
      echo "A alive at window end: NO"
    fi
    echo "=== B-side (vehicle) identity from the window's kernel trace ==="
    CROSS_V_CONTROL_OPEN="$(grep -a 'slirp4netns' /tmp/p4b-work/cross-trace.txt 2>/dev/null | grep -a 'sys_openat(' | grep -aoE '/proc/[0-9]+/ns/net' | head -1 || true)"
    echo "the vehicle control openat (its own ns-holder): ${CROSS_V_CONTROL_OPEN:-(absent: the vehicle real invocation never ran)}"
    CROSS_B_HOLDER="$(printf '%s' "$CROSS_V_CONTROL_OPEN" | grep -aoE '[0-9]+' || true)"
    if [ -n "$CROSS_B_HOLDER" ] && [ "$CROSS_B_HOLDER" = "$CROSS_A_PID" ]; then
      echo "IDENTITY-DEFECT: the vehicle's control target equals the attack target"
    fi
    if [ -n "$CROSS_B_HOLDER" ] && [ -d "/proc/$CROSS_B_HOLDER" ]; then
      echo "B ns-holder alive at window end: YES pid=$CROSS_B_HOLDER"
      echo "B ns/user:      $(readlink "/proc/$CROSS_B_HOLDER/ns/user" 2>/dev/null)"
      echo "B ns/net:       $(readlink "/proc/$CROSS_B_HOLDER/ns/net" 2>/dev/null)"
      echo "B attr/current: $(cat "/proc/$CROSS_B_HOLDER/attr/current" 2>/dev/null)"
    else
      echo "B ns-holder: not observable at window end (the vehicle op converges and frees the slot by design)"
    fi
    echo "=== the window's journal RAW tail (managerDiagf lines + the rootlesskit parent error; informational — the verdict is trace-based) ==="
    journalctl -u "$UNIT" --since "@$CROSS_T0" --no-pager 2>/dev/null | tail -30 || true
    echo "(end of raw journal tail)"
    echo "=== the vehicle's syscall/audit trace lines (the causal chain; NOT mixed with the cap_capable flood) ==="
    grep -a 'slirp4netns' /tmp/p4b-work/cross-trace.txt 2>/dev/null \
      | grep -aE '/proc/[0-9]+/ns/|setns|/dev/net/tun|sys_ioctl|selinux_audited' | head -60 || true
    echo "(end of cross-op syscall/audit lines)"
    echo "--- the vehicle's FAILED cap_capable lines (recorded; the cap boundary's own evidence):"
    grep -a 'slirp4netns' /tmp/p4b-work/cross-trace.txt 2>/dev/null \
      | grep -a 'cap_capable:' | grep -av ' ret 0' | head -12 || true
    echo "(end of failed-cap_capable lines)"
    echo "=== the cross-op window's AVC slice: helper-domain records of the attack classes (lifecycle signull/process records inventoried SEPARATELY in 46) ==="
    grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' /tmp/p4b-work/cross-avc-slice.txt 2>/dev/null \
      | grep -avE 'tclass=process' | head -20 || true
    echo "(end of cross-op AVC records)"
    echo "=== restore check ==="
    mv /usr/bin/slirp4netns /usr/bin/.cross-op-vehicle-installed \
      || echo "FAIL: the vehicle could not be renamed out of the path"
    mv /usr/bin/.cross-op-orig /usr/bin/slirp4netns \
      || echo "FAIL: the original binary could not be renamed back into the path"
    restorecon /usr/bin/slirp4netns 2>/dev/null || true
    CROSS_RESTORED_SHA="$(sha256sum /usr/bin/slirp4netns 2>/dev/null | awk '{print $1}')"
    echo "original sha256: $PROBE_ORIG_SHA"
    echo "restored sha256: $CROSS_RESTORED_SHA"
    echo "restored ctx:    $(context_of /usr/bin/slirp4netns)"
    if [ "$CROSS_RESTORED_SHA" = "$PROBE_ORIG_SHA" ]; then
      echo "PASS: the shipped flow binary is restored byte-identical"
    else
      echo "FAIL: the shipped flow binary did NOT restore byte-identical — the composition integrity is broken"
    fi
  } > "$EVIDENCE_DIR/45-cross-op-isolation.txt" 2>&1
  cat "$EVIDENCE_DIR/45-cross-op-isolation.txt" >&2
  cp /tmp/p4b-work/cross-trace.txt "$EVIDENCE_DIR/47-cross-op-trace-raw.txt" 2>/dev/null || true
  cp /tmp/p4b-work/cross-avc-slice.txt "$EVIDENCE_DIR/48-cross-op-avc-raw.txt" 2>/dev/null || true
  grep -aq "PASS: the shipped flow binary is restored byte-identical" "$EVIDENCE_DIR/45-cross-op-isolation.txt" \
    || { marker "BLOCKER=the cross-op window failed to restore the shipped flow binary (see 45-cross-op-isolation.txt)"
         finish FAIL; exit 0; }
  # The lifecycle-noise inventory (RECORDED, NOT GATED — the 4C-36 shape:
  # builder_t/rootlesskit_t process denials against the retained alive
  # helpers; their own staircase owns any widening).
  {
    echo "=== lifecycle-noise inventory (the 4C-36 flow-lifecycle denials; NOT cross-operation proof; recorded, not gated) ==="
    grep -a 'tclass=process' /tmp/p4b-work/cross-avc-slice.txt 2>/dev/null | head -20 || true
    echo "(end of lifecycle-noise records)"
  } > "$EVIDENCE_DIR/46-cross-op-lifecycle-noise.txt" 2>&1
  cat "$EVIDENCE_DIR/46-cross-op-lifecycle-noise.txt" >&2
  # ---- the verdict. The authoritative channel is the KERNEL TRACE: the
  # ---- vehicle's stderr is wired to rootlesskit's logrus debug writer
  # ---- and is dropped at the default log level (the canonical argv has
  # ---- no --debug), and the helper's exit code is not propagated
  # ---- (rootlesskit maps every helper failure to its own exit 1). The
  # ---- trace records every openat/setns/ioctl with the vehicle's
  # ---- comm-pid, so PASS requires ALL of: (a) the control leg's
  # ---- TUNSETIFF (0x400454ca) enter+exit pairing with ret 0; (b) the
  # ---- attack leg STARTED (an A-targeted openat exists in the trace);
  # ---- (c) the attack leg did NOT complete (no successful attack
  # ---- TUNSETIFF — else CROSS-OPERATION-ISOLATION=BROKEN, finish FAIL,
  # ---- no compensating changes); (d) the attack's terminal step failed
  # ---- with a REAL errno (an ENOENT stop is IDENTITY-FAIL, never a
  # ---- boundary); (e) the SELinux/cap decisions of the window carry the
  # ---- cross-category contexts.
  CROSS_OK=1
  CROSS_BROKEN=0
  {
    echo "=== 4C-37 verdict (trace-based: the vehicle's stderr is dropped by rootlesskit's logrus at the default level; the kernel trace + the launch-death journal line are the live channels) ==="
    CROSS_DEATH_LINE="$(journalctl -u "$UNIT" --since "@$CROSS_T0" --no-pager 2>/dev/null | grep -a 'exited unexpectedly' | head -1 || true)"
    echo "the window's launch-death line: ${CROSS_DEATH_LINE:-(absent — the launch did not die in the window)}"
    echo "--- the vehicle's step lines that reached the journal (informational; empty is the expected shape at the default log level):"
    journalctl -u "$UNIT" --since "@$CROSS_T0" --no-pager 2>/dev/null | grep -aE 'VEHICLE-(ID|STEP|VERDICT)' | head -20 || true
    echo "(end of vehicle journal lines)"
    echo "--- control leg: the vehicle's TUNSETIFF enter/exit pairing from the kernel trace (must exist with ret 0):"
    CROSS_CONTROL_TSET="$(awk '/slirp4netns-/ && /sys_ioctl\(/ && /cmd: 0x400454ca/ { if (entered == 0) { entered = 1; enter_line = $0; vpid = substr($1, index($1, "-") + 1); next } } entered && substr($1, length($1) - length(vpid) + 1) == vpid && /sys_ioctl ->/ { print enter_line; print $0; done = 1; exit } END { if (entered == 1 && done == 0) { print enter_line; print "(exit line absent — the ring harvested inside the ioctl)" } }' /tmp/p4b-work/cross-trace.txt 2>/dev/null || true)"
    CROSS_CONTROL_RET="$(printf '%s\n' "$CROSS_CONTROL_TSET" | grep -aoE 'sys_ioctl -> 0x[0-9a-f]+' | tail -1 | awk '{print $NF}')"
    printf '%s\n' "${CROSS_CONTROL_TSET:-(absent in the kernel trace — the vehicle legs never ran)}"
    echo "--- attack leg: the vehicle's traced steps against A's ns-holder pid $CROSS_A_PID (the causal chain; the leg stops at its first failing syscall):"
    CROSS_ATTACK_SEQ="$(awk -v a="$CROSS_A_PID" '/slirp4netns-/ { if (index($0, "/proc/" a "/ns/") > 0) attack = 1; if (attack) print }' /tmp/p4b-work/cross-trace.txt 2>/dev/null | head -14 || true)"
    if [ -n "$CROSS_ATTACK_SEQ" ]; then printf '%s\n' "$CROSS_ATTACK_SEQ"; else echo "(ABSENT — the attack leg never issued an A-targeted step in the kernel trace)"; fi
    echo "--- attack leg's terminal step (the first real boundary's syscall, return and errno):"
    CROSS_ATTACK_LAST_ENTER="$(printf '%s\n' "$CROSS_ATTACK_SEQ" | grep -aE 'sys_(openat|setns|ioctl)\(' | tail -1 || true)"
    CROSS_ATTACK_LAST_EXIT="$(printf '%s\n' "$CROSS_ATTACK_SEQ" | grep -aE 'sys_(openat|setns|ioctl) ->' | tail -1 || true)"
    CROSS_ATTACK_BOUNDARY_STEP="$(printf '%s\n' "$CROSS_ATTACK_LAST_ENTER" | sed -n 's/.*sys_\([a-z]*\)(.*/\1/p' || true)"
    CROSS_ATTACK_BOUNDARY_TARGET="$(printf '%s\n' "$CROSS_ATTACK_LAST_ENTER" | grep -aoE '"/proc/[^"]*"' | head -1 || true)"
    CROSS_ATTACK_RET_HEX="$(printf '%s\n' "$CROSS_ATTACK_LAST_EXIT" | awk '{print $NF}')"
    CROSS_ATTACK_ERRNO=""
    case "$CROSS_ATTACK_RET_HEX" in
      0x[0-9a-f]*) CROSS_ATTACK_ERRNO="$(( $CROSS_ATTACK_RET_HEX ))" ;;
    esac
    CROSS_ATTACK_ERRNO_NAME=""
    case "$CROSS_ATTACK_ERRNO" in
      -13) CROSS_ATTACK_ERRNO_NAME="EACCES" ;;
      -1) CROSS_ATTACK_ERRNO_NAME="EPERM" ;;
      -2) CROSS_ATTACK_ERRNO_NAME="ENOENT" ;;
    esac
    echo "terminal enter: ${CROSS_ATTACK_LAST_ENTER:-(none)}"
    echo "terminal exit:  ${CROSS_ATTACK_LAST_EXIT:-(none)}"
    echo "boundary: step=${CROSS_ATTACK_BOUNDARY_STEP:-(none)} target=${CROSS_ATTACK_BOUNDARY_TARGET:-(none)} ret=${CROSS_ATTACK_RET_HEX:-(none)} errno=${CROSS_ATTACK_ERRNO:-(none)}${CROSS_ATTACK_ERRNO_NAME:+ ($CROSS_ATTACK_ERRNO_NAME)}"
    echo "--- the attack window's kernel-side SELinux decisions (scontext/tcontext; the cross-category binding):"
    CROSS_ATTACK_TRACE="$(grep -a 'slirp4netns' /tmp/p4b-work/cross-trace.txt 2>/dev/null | grep -a 'selinux_audited:' | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' | head -8 || true)"
    printf '%s\n' "${CROSS_ATTACK_TRACE:-(none — no helper SELinux decision was audited in the window)}"
    echo "--- the cross-category bindings (the decisions' scontext/tcontext; must show the vehicle's cN against the A/B targets' c1/c2):"
    grep -a 'slirp4netns' /tmp/p4b-work/cross-trace.txt 2>/dev/null | grep -a 'selinux_audited:' | grep -aoE 'scontext=[^ ]* tcontext=[^ ]* tclass=[a-z_]*' | sort -u || true
    echo "--- the attack window's FAILED cap_capable checks (the capability boundary's own evidence; recorded):"
    grep -a 'slirp4netns' /tmp/p4b-work/cross-trace.txt 2>/dev/null | grep -a 'cap_capable:' | grep -av ' ret 0' | head -8 || true
    echo "--- a successful attack TUNSETIFF (must be ABSENT — its presence is CROSS-OPERATION-ISOLATION=BROKEN):"
    CROSS_ATTACK_TUNSETIFF_OK="$(awk -v a="$CROSS_A_PID" '/slirp4netns-/ { if (index($0, "/proc/" a "/ns/") > 0) attack = 1; if (!attack) next; if (/sys_ioctl\(/ && /cmd: 0x400454ca/) { pend = 1; vpid = substr($1, index($1, "-") + 1); next } if (pend && substr($1, length($1) - length(vpid) + 1) == vpid && /sys_ioctl -> 0x0/) { print; exit } }' /tmp/p4b-work/cross-trace.txt 2>/dev/null || true)"
    printf '%s\n' "${CROSS_ATTACK_TUNSETIFF_OK:-(none — no successful attack TUNSETIFF in the kernel trace)}"
    echo "--- identity checks (an ENOENT stop on the attack's first A-targeted step is IDENTITY-FAIL, not a boundary):"
    CROSS_ATTACK_FIRST_EXIT="$(printf '%s\n' "$CROSS_ATTACK_SEQ" | grep -aE 'sys_(openat|setns|ioctl) ->' | head -1 || true)"
    if printf '%s\n' "$CROSS_ATTACK_FIRST_EXIT" | grep -aqE 'sys_(openat|setns|ioctl) -> 0xfffffffffffffffe'; then
      echo "IDENTITY-FAIL: the attack's first A-targeted step returned ENOENT — the target binding was stale"
    else
      echo "(none — the attack did not stop on ENOENT)"
    fi
    if [ -z "$CROSS_CONTROL_TSET" ]; then
      echo "GATE: the vehicle never issued TUNSETIFF in the window — the proof's legs did not run"
      CROSS_OK=0
    elif [ "$CROSS_CONTROL_RET" != "0x0" ]; then
      echo "GATE: the control leg's TUNSETIFF did not return 0 in the kernel trace — the same-operation baseline is broken"
      CROSS_OK=0
    fi
    if [ -z "$CROSS_ATTACK_SEQ" ]; then
      echo "GATE: the attack leg never started (no A-targeted step in the kernel trace) — the cross-operation path was not exercised"
      CROSS_OK=0
    fi
    if [ -n "$CROSS_ATTACK_TUNSETIFF_OK" ]; then
      echo "GATE: the attack leg completed the attach path — CROSS-OPERATION-ISOLATION=BROKEN"
      CROSS_OK=0
      CROSS_BROKEN=1
    fi
    if printf '%s\n' "$CROSS_ATTACK_FIRST_EXIT" | grep -aqE 'sys_(openat|setns|ioctl) -> 0xfffffffffffffffe'; then
      echo "GATE: the attack leg stopped on ENOENT — a stale target binding (IDENTITY-FAIL), not a security boundary"
      CROSS_OK=0
    fi
    if [ -z "$CROSS_ATTACK_SEQ" ] || [ -z "$CROSS_ATTACK_ERRNO" ] || [ "$CROSS_ATTACK_ERRNO" -ge 0 ]; then
      echo "GATE: the attack leg's terminal step did not fail with a real boundary errno — the proof cannot conclude"
      CROSS_OK=0
    fi
  } > "$EVIDENCE_DIR/45-cross-op-verdict.txt" 2>&1
  cat "$EVIDENCE_DIR/45-cross-op-verdict.txt" >&2
  if [ "$CROSS_OK" = 1 ]; then
    marker "CROSS-OP-CONTROL=SUCCESS"
    marker "CROSS-OP-ATTACK-DENIED-AT=${CROSS_ATTACK_BOUNDARY_STEP:-unknown}:${CROSS_ATTACK_ERRNO:-unknown}${CROSS_ATTACK_ERRNO_NAME:+ ($CROSS_ATTACK_ERRNO_NAME)} target=${CROSS_ATTACK_BOUNDARY_TARGET:-unknown}"
    marker "CROSS-OPERATION-ISOLATION=HOLDS"
    marker "CROSS-OPERATION-GATE=CLOSED"
  elif [ "$CROSS_BROKEN" = 1 ]; then
    marker "CROSS-OPERATION-ISOLATION=BROKEN"
    marker "BLOCKER=the cross-operation isolation is broken (see 45-cross-op-isolation.txt, 45-cross-op-verdict.txt)"
    finish FAIL; exit 0
  else
    marker "BLOCKER=the 4C-37 cross-operation isolation proof did not hold (see 45-cross-op-isolation.txt, 45-cross-op-verdict.txt)"
    marker "CROSS-OPERATION-ISOLATION=NOT_PROVEN"
    finish INCOMPLETE; exit 0
  fi
fi

# ============================================================
# 4C-34: the negative command probe — the command whitelist's LIVE
# narrowing proof (SLIRP-TUN-IOCTL-COMMAND-FILTER)
# ============================================================
# The 4C-33 canonical run proved the bitmap-less intermediate
# command-unrestricted (TUNSETIFF passed the SELinux file-ioctl stage
# into the TUN driver). After the 0x54ca allowxperm grant the helper
# tuple MUST be command-mediated: a real non-whitelisted TUN ioctl must
# be xperm-denied with its ioctlcmd= record, while TUNSETIFF keeps
# passing. The probe vehicle (a VM-local bounded diagnostic window, zero
# policy delta): the composition's OWN entry path — the transferred
# static probe ELF temporarily replaces the flow's /usr/bin/slirp4netns
# and restorecon applies the SHIPPED .fc label (docker_helper_
# slirp4netns_exec_t), so the rootlesskit child's exec enters the helper
# domain exactly as the real binary does (the entry rule's own
# execute/entrypoint grants; no synthetic context). A second START runs
# the flow; the probe opens /dev/net/tun (granted) and issues ONE
# ioctl(fd, TUNSETPERSIST, 1) — a real TUN UAPI command, same driver
# byte 0x54, NOT whitelisted for the helper, SELinux-denied inside
# selinux_file_ioctl() before the TUN driver sees it (no device state
# change, no tun_socket/capability hook; the fd is never attached). The
# original binary is restored byte-verified. The probe's evidence lives
# in this gate's own audit/trace slices; the CANONICAL window's
# positive-path assertions run against 09-avc-window.txt unchanged.
SL_TUN_PROBE_OK=1
PROBE_ORIG_SHA="$(sha256sum /usr/bin/slirp4netns 2>/dev/null | awk '{print $1}')"
PROBE_ORIG_CTX="$(context_of /usr/bin/slirp4netns)"
PROBE_ORIG_MODE="$(stat -c '%a %U:%G' /usr/bin/slirp4netns 2>/dev/null)"
PROBE_TRACE_ENABLED=0
if [ ! -e "$TRANSFERRED/tun-command-probe" ]; then
  note "the transferred tun-command-probe binary is missing — the negative probe cannot run"
  : > "$EVIDENCE_DIR/41-slirp-tun-command-filter.txt"
  marker "SLIRP-TUN-COMMAND-FILTER=NOT_PROBED"
else
  # Stage INSIDE /usr/bin and swap by rename: the 4C-36 runs proved the
  # canonical flow's helper can now STAY ALIVE (the attach path is
  # SELinux-clean), and an alive helper holds the /usr/bin/slirp4netns
  # inode open — a plain `cp` onto the file fails with ETXTBSY and the
  # `|| true` then silently left the REAL binary in place, so the probe
  # window ran a real slirp4netns (the 36998362250 diagnosis). rename(2)
  # over an executed file is allowed; the replaced inode keeps running.
  cp -p /usr/bin/slirp4netns /usr/bin/.slirp4netns.orig \
    || { note "the probe window could not back up /usr/bin/slirp4netns"; finish INCOMPLETE; exit 0; }
  cp "$TRANSFERRED/tun-command-probe" /usr/bin/.slirp4netns.probe \
    || { note "the probe window could not stage the probe binary"; finish INCOMPLETE; exit 0; }
  mv /usr/bin/.slirp4netns.probe /usr/bin/slirp4netns \
    || { note "the probe window could not rename the probe binary into place"; finish INCOMPLETE; exit 0; }
  restorecon /usr/bin/slirp4netns 2>/dev/null || true
  PROBE_PLACED_SHA="$(sha256sum /usr/bin/slirp4netns 2>/dev/null | awk '{print $1}')"
  PROBE_PLACED_CTX="$(context_of /usr/bin/slirp4netns)"
  PROBE_EXPECTED_SHA="$(sha256sum "$TRANSFERRED/tun-command-probe" 2>/dev/null | awk '{print $1}')"
  echo "placed probe sha256: $PROBE_PLACED_SHA (expected $PROBE_EXPECTED_SHA)"
  echo "placed probe label:  $PROBE_PLACED_CTX"
  # Type-only label check: the 4C-34/4C-35 windows proved the exec
  # transition fires on the TYPE component (this system's restorecon
  # writes unconfined_u as the user part); the full-context equality
  # would false-fail on it (run 36999297202: INCOMPLETE).
  PROBE_PLACED_TYPE="$(printf '%s' "$PROBE_PLACED_CTX" | cut -d: -f3)"
  if [ "$PROBE_PLACED_SHA" != "$PROBE_EXPECTED_SHA" ] || [ "$PROBE_PLACED_TYPE" != "docker_helper_slirp4netns_exec_t" ]; then
    note "the probe replacement failed its byte/label check — the negative probe cannot run"
    mv /usr/bin/.slirp4netns.orig /usr/bin/slirp4netns 2>/dev/null || true
    restorecon /usr/bin/slirp4netns 2>/dev/null || true
    marker "SLIRP-TUN-COMMAND-FILTER=NOT_PROBED"
    finish INCOMPLETE; exit 0
  fi
  # Re-arm a FRESH tracefs ring for the probe window (the canonical
  # window's ring was harvested and disabled): the syscall tracepoints
  # (openat enter/exit + ioctl enter/exit with fd/cmd/arg/ret) +
  # capability/cap_capable + avc/selinux_audited.
  if [ "$TRACE_ENABLED" = 1 ]; then
    echo 0 > "$TRACING/tracing_on" 2>/dev/null || true
    echo > "$TRACING/trace" 2>/dev/null || true
    echo 16384 > "$TRACING/buffer_size_kb" 2>/dev/null || true
    echo 1 > "$TRACING/events/capability/cap_capable/enable" 2>/dev/null || true
    echo 1 > "$TRACING/events/syscalls/sys_enter_openat/enable" 2>/dev/null || true
    echo 1 > "$TRACING/events/syscalls/sys_exit_openat/enable" 2>/dev/null || true
    echo 1 > "$TRACING/events/syscalls/sys_enter_ioctl/enable" 2>/dev/null || true
    echo 1 > "$TRACING/events/syscalls/sys_exit_ioctl/enable" 2>/dev/null || true
    if [ -d "$TRACING/events/avc/selinux_audited" ]; then
      echo 1 > "$TRACING/events/avc/selinux_audited/enable" 2>/dev/null || true
    fi
    echo 1 > "$TRACING/tracing_on" 2>/dev/null || true \
      && PROBE_TRACE_ENABLED=1
  fi
  PROBE_T0="$(date +%s)"
  PROBE_OP_ID="$(gen_op_id)"
  PROBE_RT_OP_DIR="$RUNTIME_ROOT/ops/$PROBE_OP_ID"
  PROBE_ST_OP_DIR="$STATE_ROOT/ops/$PROBE_OP_ID"
  PROBE_START_RC=0
  PROBE_START_OUT=""
  # Issue the START in the background. The 4C-36 run (36995923466) proved
  # the response can be delayed by the manager's own readiness loop (a
  # failed flow still waits out the full readiness timeout), during which
  # the manager's retained-entry poll denials (signull to alive helper
  # processes) flood the trace ring and eat the probe's own syscall
  # records. The probe's window is the first ~1s after the START; harvest
  # the ring EARLY (a bounded wait), then collect the response.
  printf 'START %s\n' "$PROBE_OP_ID" | timeout 120 socat - UNIX-CONNECT:"$MANAGER_SOCK" \
    > /tmp/p4b-work/probe-start-out.txt 2>/dev/null &
  PROBE_START_PID=$!
  sleep 3
  # Harvest the trace ring EARLY (before the poll flood can overwrite it),
  # then disable the events.
  if [ "$PROBE_TRACE_ENABLED" = 1 ]; then
    echo 0 > "$TRACING/tracing_on" 2>/dev/null || true
    cat "$TRACING/trace" > /tmp/p4b-work/probe-trace.txt 2>/dev/null || true
    echo 0 > "$TRACING/events/capability/cap_capable/enable" 2>/dev/null || true
    echo 0 > "$TRACING/events/syscalls/sys_enter_openat/enable" 2>/dev/null || true
    echo 0 > "$TRACING/events/syscalls/sys_exit_openat/enable" 2>/dev/null || true
    echo 0 > "$TRACING/events/syscalls/sys_enter_ioctl/enable" 2>/dev/null || true
    echo 0 > "$TRACING/events/syscalls/sys_exit_ioctl/enable" 2>/dev/null || true
    echo 0 > "$TRACING/events/avc/selinux_audited/enable" 2>/dev/null || true
  else
    : > /tmp/p4b-work/probe-trace.txt
  fi
  wait "$PROBE_START_PID" 2>/dev/null || true
  PROBE_START_RC=$?
  PROBE_START_OUT="$(cat /tmp/p4b-work/probe-start-out.txt 2>/dev/null || true)"
  # The bounded convergence wait for the probe op's cleanup (the trace
  # ring is already harvested; this wait only orders the AVC slice after
  # the op tree is gone).
  PROBE_PID=""
  PROBE_END=$(( $(date +%s) + 60 ))
  while [ "$(date +%s)" -lt "$PROBE_END" ]; do
    if [ -z "$PROBE_PID" ] && [ -s "$PROBE_RT_OP_DIR/instance.pid" ]; then
      PROBE_PID="$(cat "$PROBE_RT_OP_DIR/instance.pid" 2>/dev/null)"
    fi
    if [ -n "$PROBE_PID" ] && [ ! -d "/proc/$PROBE_PID" ] && [ ! -d "$PROBE_RT_OP_DIR" ] && [ ! -d "$PROBE_ST_OP_DIR" ]; then
      break
    fi
    sleep 0.05
  done
  harvest_avcs_since "$PROBE_T0" /tmp/p4b-work/probe-avc-slice.txt
  {
    echo "=== 4C-34 negative command probe window (TUNSETPERSIST 0x54cb on the helper's own tuple) ==="
    echo "window-start: $PROBE_T0"
    echo "START: $PROBE_OP_ID (rc=$PROBE_START_RC) response: $PROBE_START_OUT"
    echo "window-end: $(date +%s)"
    echo "probe pid: ${PROBE_PID:-(never observed — the flow died before the instance pid file)}"
    echo "=== the probe's AVC slice (audit records since window-start) ==="
    grep -a 'type=AVC' /tmp/p4b-work/probe-avc-slice.txt 2>/dev/null \
      | grep -a 'docker_helper_slirp4netns_t' || true
    echo "=== the probe's helper TUN + tun_socket/cap_userns AVC records ==="
    grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' /tmp/p4b-work/probe-avc-slice.txt 2>/dev/null \
      | grep -aE 'tclass=(chr_file|tun_socket|cap_userns)' || true
    echo "=== the probe's syscall/audit trace lines (fd/cmd/arg/ret + SELinux decisions; NOT mixed with the cap_capable startup flood) ==="
    grep -a 'slirp4netns' /tmp/p4b-work/probe-trace.txt 2>/dev/null \
      | grep -a '/dev/net/tun\|sys_ioctl\|selinux_audited' || true
    echo "(end of probe syscall/audit trace lines)"
    echo "--- the probe's FAILED cap_capable lines (the nsjoin startup shape; informational):"
    grep -a 'slirp4netns' /tmp/p4b-work/probe-trace.txt 2>/dev/null \
      | grep -a 'cap_capable:' | grep -av ' ret 0' | head -8 || true
    echo "(end of probe-window failed-cap_capable lines)"
    echo "=== the probe's own result line (the stderr copy via the flow's child output; the rc/errno fact) ==="
    journalctl -u "$UNIT" --since "@$PROBE_T0" --no-pager 2>/dev/null | grep -a 'tun-command-probe' | head -4 || true
    echo "=== the flow's death shape in the probe window (informational) ==="
    journalctl -u "$UNIT" --since "@$PROBE_T0" --no-pager 2>/dev/null | tail -6 || true
    echo "=== restore check ==="
    # Same rename(2) swap: an alive helper can hold the path's inode open,
    # so the restore must rename, not write onto the file.
    mv /usr/bin/slirp4netns /usr/bin/.slirp4netns.probe-installed \
      || echo "FAIL: the probe binary could not be renamed out of the path"
    mv /usr/bin/.slirp4netns.orig /usr/bin/slirp4netns \
      || echo "FAIL: the original binary could not be renamed back into the path"
    restorecon /usr/bin/slirp4netns 2>/dev/null || true
    PROBE_RESTORED_SHA="$(sha256sum /usr/bin/slirp4netns 2>/dev/null | awk '{print $1}')"
    PROBE_RESTORED_CTX="$(context_of /usr/bin/slirp4netns)"
    echo "original sha256: $PROBE_ORIG_SHA"
    echo "restored sha256: $PROBE_RESTORED_SHA"
    echo "original ctx:    $PROBE_ORIG_CTX"
    echo "restored ctx:    $PROBE_RESTORED_CTX"
    echo "original mode:   $PROBE_ORIG_MODE"
    echo "restored mode:   $(stat -c '%a %U:%G' /usr/bin/slirp4netns 2>/dev/null)"
    # Byte- and TYPE-identical (run 37000093955 proved this system's
    # restorecon writes unconfined_u as the user part of the restored
    # label; the exec transition and the entry rule are type-based).
    PROBE_RESTORED_TYPE="$(printf '%s' "$PROBE_RESTORED_CTX" | cut -d: -f3)"
    PROBE_ORIG_TYPE="$(printf '%s' "$PROBE_ORIG_CTX" | cut -d: -f3)"
    if [ "$PROBE_RESTORED_SHA" = "$PROBE_ORIG_SHA" ] && [ "$PROBE_RESTORED_TYPE" = "$PROBE_ORIG_TYPE" ] && [ "$(stat -c '%a %U:%G' /usr/bin/slirp4netns 2>/dev/null)" = "$PROBE_ORIG_MODE" ]; then
      echo "PASS: the shipped flow binary is restored byte-, type-, and mode-identical (restored user part: $PROBE_RESTORED_TYPE; full restored ctx: $PROBE_RESTORED_CTX)"
    else
      echo "FAIL: the shipped flow binary did NOT restore byte/type/mode-identical — the composition integrity is broken"
    fi
  } > "$EVIDENCE_DIR/41-slirp-tun-command-filter.txt" 2>&1
  cat "$EVIDENCE_DIR/41-slirp-tun-command-filter.txt" >&2
  grep -aq "PASS: the shipped flow binary is restored" "$EVIDENCE_DIR/41-slirp-tun-command-filter.txt" \
    || { marker "BLOCKER=the negative probe window failed to restore the shipped flow binary (see 41-slirp-tun-command-filter.txt)"
         finish FAIL; exit 0; }

  # ---- the gate verdicts over the probe window's evidence. Channel
  # ---- hierarchy (the userspace audit gap is a MEASURED fact: the
  # ---- 4C-29/4C-31/4C-32 canonical windows carried ZERO helper records
  # ---- with lost=0): the kernel-side channels are authoritative and the
  # ---- symbolic AVC record strengthens where auditd delivers it. A
  # ---- positive-path presence may be proven by the symbolic record OR
  # ---- the canonical window's kernel trace decision; the negative
  # ---- command denial by the symbolic ioctlcmd= record OR the probe
  # ---- window's kernel trace sequence (the issued syscall cmd + the
  # ---- chr_file decision + the exit inside the same ioctl window).
  {
    echo "=== the positive path's assertions (the CANONICAL window) ==="
    echo "--- the 4C-34 TUNSETIFF whitelist must hold (channel 1: no helper chr_file ioctl denial with ioctlcmd=0x54ca in the canonical slice):"
    SL_POS_TUNSETIFF_DENIAL="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'tclass=chr_file' | grep -a 'denied  *{ ioctl }' | grep -a 'ioctlcmd=0x54ca' || true)"
    printf '%s\n' "${SL_POS_TUNSETIFF_DENIAL:-(none — the whitelisted TUNSETIFF command is not denied)}"
    echo "--- the whitelisted command must NOT be denied (channel 2: NO helper chr_file selinux_audited decision in the canonical kernel trace — the TUNSETIFF ioctl passed the SELinux file-ioctl stage):"
    SL_POS_TUNSETIFF_TRACE="$(grep -a 'slirp4netns' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | grep -a 'selinux_audited:' | grep -a 'tclass=chr_file' | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' || true)"
    printf '%s\n' "${SL_POS_TUNSETIFF_TRACE:-(none — no helper chr_file kernel decision in the canonical window)}"
    echo "--- the canonical window's helper TUN trace sequence (the fd/cmd/arg/ret record; informational):"
    grep -a 'slirp4netns' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | grep -a '/dev/net/tun\|sys_ioctl' | head -8 || true
    echo "(end of canonical-window helper TUN trace lines)"
    echo "=== the negative probe's assertions (the probe window's slices) ==="
    echo "--- the non-whitelisted command MUST be issued by the probe (the sys_enter_ioctl cmd 0x400454cb record):"
    SL_NEG_CMD="$(grep -a 'slirp4netns' /tmp/p4b-work/probe-trace.txt 2>/dev/null | grep -a 'sys_ioctl(fd:' | grep -a 'cmd: 0x400454cb' || true)"
    printf '%s\n' "${SL_NEG_CMD:-(GATE FAILURE — the probe window never issued the TUNSETPERSIST syscall)}"
    echo "--- the command-level denial MUST exist — channel 1: the symbolic AVC record (ioctlcmd=0x54cb; present when auditd delivers):"
    SL_NEG_XPERM="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' /tmp/p4b-work/probe-avc-slice.txt 2>/dev/null | grep -a 'tclass=chr_file' | grep -a 'denied  *{ ioctl }' | grep -a 'ioctlcmd=0x54cb' || true)"
    printf '%s\n' "${SL_NEG_XPERM:-(absent in the userspace slice)}"
    echo "--- channel 2: the probe window's kernel chr_file decision (tcontext=tun_tap_device_t between the TUNSETPERSIST enter and exit):"
    SL_NEG_TRACE="$(grep -a 'slirp4netns' /tmp/p4b-work/probe-trace.txt 2>/dev/null | grep -a 'selinux_audited:' | grep -a 'tclass=chr_file' | grep -a 'tcontext=system_u:object_r:tun_tap_device_t' || true)"
    printf '%s\n' "${SL_NEG_TRACE:-(absent in the kernel trace)}"
    echo "--- the probe's ioctl exit (ret; the expected -13 EACCES):"
    grep -a 'slirp4netns' /tmp/p4b-work/probe-trace.txt 2>/dev/null | grep -a 'sys_ioctl ->' | head -4 || true
    echo "--- the probe must NOT reach the deeper TUN hooks (channel 1: no helper tun_socket/cap_userns AVC in the probe slice):"
    SL_NEG_DEEPER="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' /tmp/p4b-work/probe-avc-slice.txt 2>/dev/null | grep -aE 'tclass=(tun_socket|cap_userns)' || true)"
    printf '%s\n' "${SL_NEG_DEEPER:-(none — no helper tun_socket/cap_userns AVC in the probe window)}"
    echo "--- channel 2: no helper tun_socket selinux_audited decision in the probe kernel trace:"
    SL_NEG_DEEPER_TRACE="$(grep -a 'slirp4netns' /tmp/p4b-work/probe-trace.txt 2>/dev/null | grep -a 'selinux_audited:' | grep -a 'tclass=tun_socket' | grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' || true)"
    printf '%s\n' "${SL_NEG_DEEPER_TRACE:-(none — no helper tun_socket kernel decision in the probe window)}"
    echo "--- the probe window's FAILED cap_capable checks (informational; the pre-4C-33 startup shape predates this phase):"
    grep -a 'slirp4netns' /tmp/p4b-work/probe-trace.txt 2>/dev/null | grep -a 'cap_capable:' | grep -av ' ret 0' | head -8 || true
    echo "(end of probe-window failed-cap_capable lines)"
    # (The 4C-35 relabelfrom-boundary verdicts moved to
    # 43-slirp-tun-relabel-gone.txt below: the grant removed the old
    # terminal boundary, so gate 42 owns only the command filter.)
    if [ -n "$SL_POS_TUNSETIFF_DENIAL" ] || [ -n "$SL_POS_TUNSETIFF_TRACE" ]; then
      echo "GATE: the whitelisted TUNSETIFF command was denied in the canonical window — the 4C-34 whitelist membership regressed"
      SL_TUN_PROBE_OK=0
    fi
    if [ -z "$SL_NEG_CMD" ] || { [ -z "$SL_NEG_XPERM" ] && [ -z "$SL_NEG_TRACE" ]; }; then
      echo "GATE: the negative probe did not establish the command-level denial (the issued syscall cmd or both denial channels missing) — the command filter is not proven enforcing"
      SL_TUN_PROBE_OK=0
    fi
    if [ -n "$SL_NEG_DEEPER" ] || [ -n "$SL_NEG_DEEPER_TRACE" ]; then
      echo "GATE: the probe window reached a deeper TUN hook (a helper tun_socket denial in either channel) — the command-level denial did not fire first"
      SL_TUN_PROBE_OK=0
    fi
  } > "$EVIDENCE_DIR/42-slirp-tun-command-filter-verdict.txt" 2>&1
  cat "$EVIDENCE_DIR/42-slirp-tun-command-filter-verdict.txt" >&2
  if [ "$SL_TUN_PROBE_OK" = 1 ]; then
    marker "SLIRP-TUN-IOCTL-COMMAND-FILTER=EXACT-{0x54ca}"
    marker "SLIRP-TUN-COMMAND-PROBE=0x54cb-XPERM-DENIED"
  else
    marker "BLOCKER=the 4C-34 TUN command-filter composition did not hold (see 41-slirp-tun-command-filter.txt, 42-slirp-tun-command-filter-verdict.txt)"
    marker "SLIRP-TUN-IOCTL-COMMAND-FILTER=FAIL"
    finish FAIL; exit 0
  fi
fi

# ============================================================
# 4C-35: the slirp4netns helper TUN socket-relabel gate
# (SLIRP-TUN-SOCKET-RELABELFROM)
# ============================================================
# The 4C-35 grant: the helper's cross-domain tun_socket relabelfrom
# toward the rootlesskit target — the 4C-34 canonical run's terminal
# boundary (record 2339: denied { relabelfrom } for
# scontext=slirp4netns_t:s0:c1 tcontext=rootlesskit_t:s0:c1
# tclass=tun_socket INSIDE the same sys_ioctl(TUNSETIFF) window that had
# already passed the { 0x54ca } command whitelist; the kernel trace's
# masks 0x80 were decode-calibrated against the co-captured symbolic
# record). The gate hard-fails when that relabelfrom denial STILL
# appears (the grant did not take effect): channel 1 = the symbolic AVC
# record, channel 2 = the decode's calibrated helper tun_socket
# decision, channel 3 = the kernel trace's raw 0x80 tun_socket masks
# (this platform's tun_socket perm-bit order: relabelfrom = 0x80).
# Since 4C-36 the SELF-TARGETED relabelto regression is owned by
# 44-slirp-tun-relabelto-gone.txt below. Any other helper tun_socket
# decision (attach_queue / create / any other perm) is the EXPECTED next
# boundary — recorded with its full scontext/tcontext, not failed; a
# reached cap_userns/capability boundary is recorded the same way. The
# phase stops there with no further grant.
SL_TUN_RELABEL_GONE_OK=1
{
  echo "=== slirp4netns_t tun_socket AVCs of the granted relabelfrom (the 4C-35 cross-domain boundary must be absent) ==="
  SL_RELABEL_GONE_AVC="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'tclass=tun_socket' | grep -a 'denied  *{ relabelfrom }' || true)"
  printf '%s\n' "${SL_RELABEL_GONE_AVC:-(none — the 4C-35 tun_socket relabelfrom boundary is gone)}"
  echo "--- the decode's calibrated helper tun_socket decisions naming relabelfrom (34-avc-trace-decode.txt; uncalibrated events stay raw):"
  SL_RELABEL_GONE_DECODE="$(grep -a 'HELPER' "$EVIDENCE_DIR/34-avc-trace-decode.txt" 2>/dev/null | grep -a 'tclass=tun_socket' | grep -a 'relabelfrom' || true)"
  printf '%s\n' "${SL_RELABEL_GONE_DECODE:-(none — no calibrated helper tun_socket relabelfrom decision in the window)}"
  echo "--- ALL helper tun_socket kernel decisions of the canonical window (30-trace-window.txt; raw masks — 0x80 is the granted relabelfrom, anything else is the next boundary):"
  SL_RELABEL_KERNEL="$(grep -a 'slirp4netns' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | grep -a 'selinux_audited:' | grep -a 'tclass=tun_socket' || true)"
  printf '%s\n' "${SL_RELABEL_KERNEL:-(none — no helper tun_socket kernel decision in the window)}"
  SL_RELABEL_KERNEL_0x80="$(printf '%s\n' "$SL_RELABEL_KERNEL" | grep -a 'requested=0x80' || true)"
  printf '%s\n' "${SL_RELABEL_KERNEL_0x80:-(none — no raw 0x80 (relabelfrom) kernel decision)}"
  echo "--- ALL other helper tun_socket AVCs (ungranted perms — the next-boundary evidence; recorded with the full scontext/tcontext, not failed):"
  SL_RELABEL_NEXT="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'tclass=tun_socket' | grep -av 'denied  *{ relabelfrom }' || true)"
  printf '%s\n' "${SL_RELABEL_NEXT:-(none — no ungranted helper tun_socket permission was attempted)}"
  echo "--- ALL helper cap_userns/capability AVCs of the window (the attach path's capability boundary — recorded, not failed):"
  SL_RELABEL_CAP="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -aE 'tclass=(cap_userns|capability)' || true)"
  printf '%s\n' "${SL_RELABEL_CAP:-(none — no helper capability AVC appeared)}"
  echo "--- the helper's FAILED cap_capable checks in the trace ring (ret<0 — a reached capability boundary; recorded, not failed):"
  grep -a '^     slirp4netns-' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | grep -a 'cap_capable:' | grep -av ' ret 0' || true
  echo "(end of failed-cap_capable lines)"
  echo "--- the helper's full TUN trace sequence of the window (openat + ioctl fd/cmd/arg/ret; the causal attach chain):"
  grep -a 'slirp4netns' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | grep -a '/dev/net/tun\|sys_ioctl' | head -10 || true
  echo "(end of helper TUN trace lines)"
  echo "--- the helper's userspace failure shape (informational)"
  grep -a 'slirp4netns\|waiting for ready fd' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null | tail -4 || true
  if [ -n "$SL_RELABEL_GONE_AVC" ]; then
    echo "GATE: a slirp4netns_t tun_socket relabelfrom denial still appeared — the 4C-35 grant did not take effect"
    SL_TUN_RELABEL_GONE_OK=0
  fi
  if [ -n "$SL_RELABEL_GONE_DECODE" ]; then
    echo "GATE: the decode shows a calibrated helper tun_socket relabelfrom decision — the 4C-35 grant did not take effect"
    SL_TUN_RELABEL_GONE_OK=0
  fi
  if [ -n "$SL_RELABEL_KERNEL_0x80" ]; then
    echo "GATE: the kernel trace shows a raw 0x80 tun_socket decision for the helper — the 4C-35 grant did not take effect"
    SL_TUN_RELABEL_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/43-slirp-tun-relabel-gone.txt" 2>&1
cat "$EVIDENCE_DIR/43-slirp-tun-relabel-gone.txt" >&2
if [ "$SL_TUN_RELABEL_GONE_OK" = 1 ]; then
  marker "SLIRP-TUN-SOCKET-RELABELFROM=GONE"
  SL_TUN_RELABEL_NEXT_FIRST="$(printf '%s\n' "$SL_RELABEL_NEXT" | head -1 || true)"
  if [ -z "$SL_TUN_RELABEL_NEXT_FIRST" ]; then
    SL_TUN_RELABEL_NEXT_FIRST="$(printf '%s\n' "$SL_RELABEL_KERNEL" | head -1 || true)"
  fi
  if [ -z "$SL_TUN_RELABEL_NEXT_FIRST" ]; then
    SL_TUN_RELABEL_NEXT_FIRST="$(printf '%s\n' "$SL_RELABEL_CAP" | head -1 || true)"
  fi
  SL_TUN_RELABEL_NEXT_PERMS="$(printf '%s\n' "$SL_TUN_RELABEL_NEXT_FIRST" | sed -n 's/.*denied  *{ \([^}]*\) }.*/\1/p' || true)"
  SL_TUN_RELABEL_NEXT_SUMMARY="$(printf '%s\n' "$SL_TUN_RELABEL_NEXT_FIRST" | sed -n 's/.*scontext=\([^ ]*\) tcontext=\([^ ]*\) tclass=\([a-z_]*\).*/scontext=\1 tcontext=\2 tclass=\3/p' || true)"
  SL_TUN_RELABEL_NEXT_IOCTL="$(printf '%s\n' "$SL_TUN_RELABEL_NEXT_FIRST" | sed -n 's/.*ioctlcmd=\([0-9a-fx]*\).*/\1/p' || true)"
  marker "SLIRP-TUN-NEXT-BOUNDARY=${SL_TUN_RELABEL_NEXT_SUMMARY:-none} perms=${SL_TUN_RELABEL_NEXT_PERMS:-none} ioctlcmd=${SL_TUN_RELABEL_NEXT_IOCTL:-none}"
else
  marker "BLOCKER=the 4C-35 slirp4netns TUN socket-relabel composition did not hold (see 43-slirp-tun-relabel-gone.txt)"
  marker "SLIRP-TUN-SOCKET-RELABELFROM=FAIL"
  finish FAIL; exit 0
fi

# ============================================================
# 4C-36: the slirp4netns helper TUN socket SELF-relabelto gate
# (SLIRP-TUN-SOCKET-RELABELTO)
# ============================================================
# The 4C-36 grant: the helper's SELF-TARGETED tun_socket relabelto —
# the 4C-35 canonical run's terminal boundary (record 2309: denied
# { relabelto } for scontext=slirp4netns_t:s0:c1
# tcontext=slirp4netns_t:s0:c1 tclass=tun_socket INSIDE the same
# sys_ioctl(TUNSETIFF) window, masks 0x100 decode-calibrated; the
# recorded shape is self-targeted, NOT a reverse cross-domain grant).
# The gate hard-fails when that relabelto denial STILL appears (the
# grant did not take effect): channel 1 = the symbolic AVC record,
# channel 2 = the decode's calibrated helper tun_socket decision,
# channel 3 = the kernel trace's raw 0x100 tun_socket masks (this
# platform's tun_socket perm-bit order: relabelto = 0x100). Any OTHER
# helper tun_socket decision (attach_queue 0x800 / create 0x8 / any
# other perm) is the EXPECTED next boundary — recorded with its full
# scontext/tcontext, not failed; a reached cap_userns/capability
# boundary is recorded the same way. The phase stops there with no
# further grant.
SL_TUN_RELABELO_GONE_OK=1
{
  echo "=== slirp4netns_t tun_socket AVCs of the granted self relabelto (the 4C-36 boundary must be absent) ==="
  SL_RELABELO_GONE_AVC="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'tclass=tun_socket' | grep -a 'denied  *{ relabelto }' || true)"
  printf '%s\n' "${SL_RELABELO_GONE_AVC:-(none — the 4C-36 tun_socket relabelto boundary is gone)}"
  echo "--- the decode's calibrated helper tun_socket decisions naming relabelto (34-avc-trace-decode.txt; uncalibrated events stay raw):"
  SL_RELABELO_GONE_DECODE="$(grep -a 'HELPER' "$EVIDENCE_DIR/34-avc-trace-decode.txt" 2>/dev/null | grep -a 'tclass=tun_socket' | grep -a 'relabelto' || true)"
  printf '%s\n' "${SL_RELABELO_GONE_DECODE:-(none — no calibrated helper tun_socket relabelto decision in the window)}"
  echo "--- ALL helper tun_socket kernel decisions of the canonical window (30-trace-window.txt; raw masks — 0x100 is the granted relabelto, anything else is the next boundary):"
  SL_RELABELO_KERNEL="$(grep -a 'slirp4netns' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | grep -a 'selinux_audited:' | grep -a 'tclass=tun_socket' || true)"
  printf '%s\n' "${SL_RELABELO_KERNEL:-(none — no helper tun_socket kernel decision in the window)}"
  SL_RELABELO_KERNEL_0x100="$(printf '%s\n' "$SL_RELABELO_KERNEL" | grep -a 'requested=0x100' || true)"
  printf '%s\n' "${SL_RELABELO_KERNEL_0x100:-(none — no raw 0x100 (relabelto) kernel decision)}"
  echo "--- ALL other helper tun_socket AVCs (ungranted perms — the next-boundary evidence; recorded with the full scontext/tcontext, not failed):"
  SL_RELABELO_NEXT="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'tclass=tun_socket' | grep -av 'denied  *{ relabelto }' || true)"
  printf '%s\n' "${SL_RELABELO_NEXT:-(none — no ungranted helper tun_socket permission was attempted)}"
  echo "--- ALL helper cap_userns/capability AVCs of the window (the attach path's capability boundary — recorded, not failed):"
  SL_RELABELO_CAP="$(grep -a 'scontext=system_u:system_r:docker_helper_slirp4netns_t' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -aE 'tclass=(cap_userns|capability)' || true)"
  printf '%s\n' "${SL_RELABELO_CAP:-(none — no helper capability AVC appeared)}"
  echo "--- the helper's FAILED cap_capable checks in the trace ring (ret<0 — a reached capability boundary; recorded, not failed):"
  grep -a '^     slirp4netns-' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | grep -a 'cap_capable:' | grep -av ' ret 0' || true
  echo "(end of failed-cap_capable lines)"
  echo "--- the helper's full TUN trace sequence of the window (openat + ioctl fd/cmd/arg/ret; the causal attach chain):"
  grep -a 'slirp4netns' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | grep -a '/dev/net/tun\|sys_ioctl' | head -10 || true
  echo "(end of helper TUN trace lines)"
  echo "--- the helper's userspace failure shape (informational)"
  grep -a 'slirp4netns\|waiting for ready fd' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null | tail -4 || true
  if [ -n "$SL_RELABELO_GONE_AVC" ]; then
    echo "GATE: a slirp4netns_t tun_socket relabelto denial still appeared — the 4C-36 grant did not take effect"
    SL_TUN_RELABELO_GONE_OK=0
  fi
  if [ -n "$SL_RELABELO_GONE_DECODE" ]; then
    echo "GATE: the decode shows a calibrated helper tun_socket relabelto decision — the 4C-36 grant did not take effect"
    SL_TUN_RELABELO_GONE_OK=0
  fi
  if [ -n "$SL_RELABELO_KERNEL_0x100" ]; then
    echo "GATE: the kernel trace shows a raw 0x100 tun_socket decision for the helper — the 4C-36 grant did not take effect"
    SL_TUN_RELABELO_GONE_OK=0
  fi
} > "$EVIDENCE_DIR/44-slirp-tun-relabelto-gone.txt" 2>&1
cat "$EVIDENCE_DIR/44-slirp-tun-relabelto-gone.txt" >&2
if [ "$SL_TUN_RELABELO_GONE_OK" = 1 ]; then
  marker "SLIRP-TUN-SOCKET-RELABELTO=GONE"
  SL_TUN_RELABELO_NEXT_FIRST="$(printf '%s\n' "$SL_RELABELO_NEXT" | head -1 || true)"
  if [ -z "$SL_TUN_RELABELO_NEXT_FIRST" ]; then
    SL_TUN_RELABELO_NEXT_FIRST="$(printf '%s\n' "$SL_RELABELO_KERNEL" | head -1 || true)"
  fi
  if [ -z "$SL_TUN_RELABELO_NEXT_FIRST" ]; then
    SL_TUN_RELABELO_NEXT_FIRST="$(printf '%s\n' "$SL_RELABELO_CAP" | head -1 || true)"
  fi
  SL_TUN_RELABELO_NEXT_PERMS="$(printf '%s\n' "$SL_TUN_RELABELO_NEXT_FIRST" | sed -n 's/.*denied  *{ \([^}]*\) }.*/\1/p' || true)"
  SL_TUN_RELABELO_NEXT_SUMMARY="$(printf '%s\n' "$SL_TUN_RELABELO_NEXT_FIRST" | sed -n 's/.*scontext=\([^ ]*\) tcontext=\([^ ]*\) tclass=\([a-z_]*\).*/scontext=\1 tcontext=\2 tclass=\3/p' || true)"
  SL_TUN_RELABELO_NEXT_IOCTL="$(printf '%s\n' "$SL_TUN_RELABELO_NEXT_FIRST" | sed -n 's/.*ioctlcmd=\([0-9a-fx]*\).*/\1/p' || true)"
  marker "SLIRP-TUN-NEXT-BOUNDARY=${SL_TUN_RELABELO_NEXT_SUMMARY:-none} perms=${SL_TUN_RELABELO_NEXT_PERMS:-none} ioctlcmd=${SL_TUN_RELABELO_NEXT_IOCTL:-none}"
else
  marker "BLOCKER=the 4C-36 slirp4netns TUN socket self-relabelto composition did not hold (see 44-slirp-tun-relabelto-gone.txt)"
  marker "SLIRP-TUN-SOCKET-RELABELTO=FAIL"
  finish FAIL; exit 0
fi


# ---- launcher-domain AVC inventory (raw; the report classifies)
{
  echo "=== launcher_t AVCs of the window (raw) ==="
  grep -a "scontext=system_u:system_r:$LAUNCHER_DOMAIN" "$EVIDENCE_DIR/09-avc-window.txt" \
    || echo "(no launcher_t AVC recorded)"
  echo "=== design-candidate shapes (informational grep) ==="
  for shape in 'cgroup_t:dir' 'cgroup_t:file' 'sysctl_net_t' 'tclass=fifo_file' \
    'tcontext=system_u:object_r:docker_helper_builder_t' 'tclass=file' 'tclass=process'; do
    echo "--- $shape:"
    grep -a "scontext=system_u:system_r:$LAUNCHER_DOMAIN" "$EVIDENCE_DIR/09-avc-window.txt" \
      | grep -a "$shape" || echo "(none)"
  done
} > "$EVIDENCE_DIR/08-avc-launcher.txt" 2>&1
cat "$EVIDENCE_DIR/08-avc-launcher.txt" >&2

# ============================================================
# F: I9 live — the legacy direct-exec vehicles
# ============================================================
log 'F: I9 live legacy direct-exec vehicles'
I9_OK=1
T_LEGACY_A="$(date +%s)"

# Vehicle A: the direct exec of the rootlesskit binary bound to the
# builder domain, WITHOUT the launcher. A transient unit's SELinuxContext=
# is the same forced-context binding the real unit uses; systemd performs
# the forced-context execve. No production file, no policy rule touched.
systemd-run --collect --wait --unit="$LEGACY_UNIT_A" \
  --property=SELinuxContext="$BUILDER_T" \
  --uid=docker-helper-builder -- \
  /usr/bin/rootlesskit --version \
  > "$EVIDENCE_DIR/f-vehicle-a.txt" 2>&1 \
  || echo "vehicle A systemd-run rc=$? (a forced-context EXEC failure is the expected shape)" \
  >> "$EVIDENCE_DIR/f-vehicle-a.txt"
{
  echo "=== vehicle A: transient unit $LEGACY_UNIT_A (direct rootlesskit exec, bound to builder_t) ==="
  cat "$EVIDENCE_DIR/f-vehicle-a.txt"
  echo "=== its journal ==="
  journalctl -u "$LEGACY_UNIT_A" --no-pager 2>/dev/null | tail -20 || true
  echo "=== its rootlesskit_exec_t AVCs ==="
  ausearch -m AVC,SELINUX_ERR -ts "$T_LEGACY_A" --raw 2>/dev/null | grep -a 'tcontext=system_u:object_r:docker_helper_rootlesskit_exec_t' || echo "(no rootlesskit_exec_t AVC)"
} >> "$EVIDENCE_DIR/13-i9-legacy.txt" 2>&1
# The I9 negative's PASS composition (the 4C-2 harness correction): the
# runtime direct-exec refusal AND the loaded-policy static proof of the
# absent allowed path are BOTH required; a recorded AVC is optional
# supporting evidence (the loaded policy's dontaudit rules legitimately
# silence the builder-domain denial; dontaudit is not disabled and the
# production policy is not changed for audit visibility). A vehicle
# attempt that never ran (no unit start evidence) is INCONCLUSIVE, never
# a PASS from the static check alone.
I9_A_AVC=0
if ausearch -m AVC -ts "$T_LEGACY_A" --raw 2>/dev/null | grep -a 'rootlesskit_exec_t' | grep -aq .; then
  I9_A_AVC=1
fi
I9_A_RUNTIME=0
if grep -aqE "203/EXEC|Permission denied|Unable to locate executable" "$EVIDENCE_DIR/f-vehicle-a.txt" \
  || journalctl -u "$LEGACY_UNIT_A" --no-pager 2>/dev/null | grep -aqE "Failed at step EXEC|Permission denied|203/EXEC"; then
  I9_A_RUNTIME=1
fi
I9_A_STATIC=0
if ! sesearch --allow -s docker_helper_builder_t -t docker_helper_rootlesskit_exec_t -c file 2>/dev/null | grep -aq 'execute'; then
  I9_A_STATIC=1
fi
I9_A_RAN=0
if grep -aq "Running as unit" "$EVIDENCE_DIR/f-vehicle-a.txt" \
  || journalctl -u "$LEGACY_UNIT_A" --no-pager 2>/dev/null | grep -aq "Started \["; then
  I9_A_RAN=1
fi
if [ "$I9_A_RAN" != 1 ]; then
  echo "INCONCLUSIVE: the direct-exec vehicle attempt never ran (no unit start evidence)" >> "$EVIDENCE_DIR/13-i9-legacy.txt"
  I9_OK=2
elif [ "$I9_A_RUNTIME" = 1 ] && [ "$I9_A_STATIC" = 1 ]; then
  echo "PASS: the direct rootlesskit exec path is dead (runtime refusal AND loaded-policy static negative; AVC evidence=$I9_A_AVC)" >> "$EVIDENCE_DIR/13-i9-legacy.txt"
else
  echo "FAIL: the direct rootlesskit exec negative needs BOTH the runtime refusal and the static negative (runtime=$I9_A_RUNTIME, static=$I9_A_STATIC, AVC=$I9_A_AVC)" >> "$EVIDENCE_DIR/13-i9-legacy.txt"
  I9_OK=0
fi

T_LEGACY_B="$(date +%s)"
# Vehicle B: the launch-exec leaf running IN builder_t (the transient unit
# binds the domain; the leaf's grammar validation is pure — no filesystem
# side effect). The live half of the setexec split: the forced-context
# write must be denied and the leaf must fail closed BEFORE any exec.
VB_OP_ID="op_4b4c41554e4348525200000000000000"
VB_ARGV=(--net=slirp4netns --copy-up=/etc --disable-host-loopback
  "--state-dir=$STATE_ROOT/ops/$VB_OP_ID/rootlesskit-state"
  /usr/libexec/docker-helper/buildkit/buildkitd
  --rootless
  "--root=$STATE_ROOT/ops/$VB_OP_ID/root"
  "--addr=unix://$RUNTIME_ROOT/ops/$VB_OP_ID/buildkitd.sock")
systemd-run --collect --wait --unit="$LEGACY_UNIT_B" \
  --property=SELinuxContext="$BUILDER_T" \
  --uid=docker-helper-builder -- \
  /usr/bin/docker-helper builder launch-exec c1 "${VB_ARGV[@]}" \
  > "$EVIDENCE_DIR/f-vehicle-b.txt" 2>&1 \
  || echo "vehicle B systemd-run rc=$?" >> "$EVIDENCE_DIR/f-vehicle-b.txt"
{
  echo "=== vehicle B: transient unit $LEGACY_UNIT_B (the launch-exec leaf in builder_t) ==="
  cat "$EVIDENCE_DIR/f-vehicle-b.txt"
  echo "=== its journal (the leaf's own stderr: the forced-context refusal) ==="
  journalctl -u "$LEGACY_UNIT_B" --no-pager 2>/dev/null | tail -20 || true
  echo "=== its setexec AVCs ==="
  ausearch -m AVC -ts "$T_LEGACY_B" --raw 2>/dev/null \
    | grep -a 'tclass=process' | grep -a 'perm=setexec' || echo "(no setexec AVC)"
} >> "$EVIDENCE_DIR/13-i9-legacy.txt" 2>&1
if ausearch -m AVC -ts "$T_LEGACY_B" --raw 2>/dev/null | grep -a 'perm=setexec' | grep -aq 'tcontext=system_u:system_r:docker_helper_builder_t'; then
  I9_B_AVC=1
else
  I9_B_AVC=0
fi
# The same AND-composition as vehicle A (the 4C-2 harness correction): the
# launcher's runtime refusal (its fail-closed stderr through the unit
# journal or the --wait output) AND the loaded-policy static proof (no
# builder_t self:process setexec grant) are BOTH required; the AVC is
# optional supporting evidence; an attempt that never ran is
# INCONCLUSIVE.
I9_B_RUNTIME=0
if grep -aq "cannot set the forced exec context" "$EVIDENCE_DIR/f-vehicle-b.txt" \
  || journalctl -u "$LEGACY_UNIT_B" --no-pager 2>/dev/null | grep -aq "cannot set the forced exec context"; then
  I9_B_RUNTIME=1
fi
I9_B_STATIC=0
if ! sesearch --allow -s docker_helper_builder_t -t docker_helper_builder_t -c process 2>/dev/null | grep -aq 'setexec'; then
  I9_B_STATIC=1
fi
I9_B_RAN=0
if grep -aq "Running as unit" "$EVIDENCE_DIR/f-vehicle-b.txt" \
  || journalctl -u "$LEGACY_UNIT_B" --no-pager 2>/dev/null | grep -aq "Started \["; then
  I9_B_RAN=1
fi
if [ "$I9_B_RAN" != 1 ]; then
  echo "INCONCLUSIVE: the launch-exec vehicle attempt never ran (no unit start evidence)" >> "$EVIDENCE_DIR/13-i9-legacy.txt"
  I9_OK=2
elif [ "$I9_B_RUNTIME" = 1 ] && [ "$I9_B_STATIC" = 1 ]; then
  echo "PASS: the launch-exec leaf in builder_t cannot reach the forced-context write (runtime refusal AND loaded-policy static negative; AVC evidence=$I9_B_AVC)" >> "$EVIDENCE_DIR/13-i9-legacy.txt"
else
  echo "FAIL: the launch-exec leaf's setexec negative needs BOTH the runtime refusal and the static negative (runtime=$I9_B_RUNTIME, static=$I9_B_STATIC, AVC=$I9_B_AVC)" >> "$EVIDENCE_DIR/13-i9-legacy.txt"
  I9_OK=0
fi
cat "$EVIDENCE_DIR/13-i9-legacy.txt" >&2

# Neither vehicle may ever have produced a flow context.
if ausearch -m AVC -ts "$T_LEGACY_A" --raw 2>/dev/null | grep -aq "scontext=system_u:system_r:$RK_DOMAIN" \
  || ausearch -m AVC -ts "$T_LEGACY_B" --raw 2>/dev/null | grep -aq "scontext=system_u:system_r:$RK_DOMAIN"; then
  marker "BLOCKER=a rootlesskit_t context appeared from a legacy vehicle"
  marker "I9-DIRECT-EXEC=FAIL"
  finish FAIL; exit 0
fi
I9_VERDICT=FAIL
if [ "$I9_OK" = 1 ]; then
  I9_VERDICT=PASS
elif [ "$I9_OK" = 2 ]; then
  I9_VERDICT=INCONCLUSIVE
fi
marker "I9-DIRECT-EXEC=$I9_VERDICT"

# ============================================================
# G: no uncategorized flow in the whole window
# ============================================================
harvest_avcs_since "$T0" /tmp/p4b-work/avc-whole.txt || true
{
  echo "=== every flow-domain context of the whole window (must all carry a category) ==="
  grep -a "scontext=system_u:system_r:$RK_DOMAIN" /tmp/p4b-work/avc-whole.txt \
    | sed -n 's/.*scontext=\([^ ]*\).*/\1/p' | sort -u || true
  echo "=== process-table samples ==="
  cat "$EVIDENCE_DIR/12-uncategorized-ps.txt" 2>/dev/null || echo "(no process-table samples)"
} > "$EVIDENCE_DIR/12-uncategorized-check.txt" 2>&1
BARE_COUNT="$(grep -a "scontext=system_u:system_r:$RK_DOMAIN" /tmp/p4b-work/avc-whole.txt \
  | sed -n 's/.*scontext=\([^ ]*\).*/\1/p' | sort -u | grep -ac ":$RK_DOMAIN:s0\$" || true)"
PS_BARE="$(awk '/docker_helper_rootlesskit_t:s0( |$)/ { n++ } END { print n+0 }' "$EVIDENCE_DIR/12-uncategorized-ps.txt" 2>/dev/null || echo 0)"
if [ "$BARE_COUNT" -eq 0 ] && [ "$PS_BARE" -eq 0 ]; then
  marker "NO-UNCATEGORIZED=PASS"
else
  marker "BLOCKER=an uncategorized rootlesskit_t:s0 context appeared in the window"
  marker "NO-UNCATEGORIZED=FAIL"
  finish FAIL; exit 0
fi

# ============================================================
# CC: the 4C-19 companion diagnostic window (dontaudit disabled)
# ============================================================
# Evidence-only companion for the SAME semantic composition: the 4C-18
# phase proved the distro base policy's generic
# `dontaudit domain domain:netlink_route_socket { read write };`
# catch-all hides NETLINK_ROUTE denials from the canonical window, so
# after the canonical leg this window reloads the policy with dontaudit
# reporting removed, reruns the SAME production flow, and records what
# the message-level mediation now shows. No allow rule is added here;
# the module itself is unchanged. Enforcement decisions are unchanged
# (dontaudit only silences audit). The baseline is restored and
# verified below.
marker "CC: companion diagnostic window (dontaudit disabled)"
T1="$(date +%s)"
# The syscall-chronology rules from the canonical window were already
# flushed into 18-syscall-chronology.txt; re-arm them for the companion
# (the never,task catch-all is still out from the canonical window).
auditctl -a always,exit -F arch=b64 \
  -S socket,socketpair,sendmsg,sendto,recvmsg,recvfrom,ioctl,close \
  -k p5s2diag >> "$EVIDENCE_DIR/18-auditctl-sysrules.txt" 2>&1 || true
# The second diagnostic leg: disable dontaudit reporting AFTER the
# canonical gates (this is the 4C-18 diagnostic replication for the
# current composition). The backlog stays raised across both windows
# (the never,task catch-all and the syscall rules were not flushed
# between them).
semodule -DB >> "$EVIDENCE_DIR/18-semodule-db-diag.txt" 2>&1 \
  || { note "the companion leg's semodule -DB failed (evidence-only; recorded)"; }
{
  echo "=== 4C-19 companion leg: state after semodule -DB (epoch $T1) ==="
  echo "getenforce: $(getenforce 2>/dev/null)"
  echo "docker_helper permissive domains (must be none):"
  semanage permissive -l 2>/dev/null | grep -a docker_helper || echo "(none)"
  echo "flow-domain dontaudit rules on netlink_route_socket AFTER -DB (must be zero — that is the whole point):"
  sesearch --dontaudit -s docker_helper_rootlesskit_t -c netlink_route_socket /sys/fs/selinux/policy 2>/dev/null || true
  echo "NOTE: this leg's audit inventory is diagnostic-only; enforcement decisions are unchanged."
} >> "$EVIDENCE_DIR/18-semodule-db-diag.txt"
cat "$EVIDENCE_DIR/18-semodule-db-diag.txt" >&2

# The companion window reuses the canonical window's mechanics with a
# NEW op id, its own sampler (the leader-context + tap0 observer
# subset), and its own harvests; the label-provisioning proofs belong
# to the canonical window and are not repeated.
COMP_OP_ID="$(gen_op_id)"
COMP_RT_OP_DIR="$RUNTIME_ROOT/ops/$COMP_OP_ID"
COMP_ST_OP_DIR="$STATE_ROOT/ops/$COMP_OP_ID"
echo "$COMP_OP_ID" > "$EVIDENCE_DIR/companion-op-id"
log "CC: companion START $COMP_OP_ID (dontaudit disabled)"
(
  set +e
  c_seen_pid=""
  c_seen_ctx=""
  c_end=$(( $(date +%s) + 75 ))
  while [ "$(date +%s)" -lt "$c_end" ]; do
    if [ -z "$c_seen_pid" ] && [ -s "$COMP_RT_OP_DIR/instance.pid" ]; then
      c_seen_pid="$(cat "$COMP_RT_OP_DIR/instance.pid" 2>/dev/null)"
      [ -n "$c_seen_pid" ] && printf 'INSTANCE-PID %s first-seen=%s\n' "$c_seen_pid" "$(date +%s.%N)" >> "$EVIDENCE_DIR/22-companion-flow-context.txt"
    fi
    if [ -n "$c_seen_pid" ] && [ -d "/proc/$c_seen_pid" ]; then
      ctx="$(process_context "$c_seen_pid")"
      if [ -n "$ctx" ] && ! printf '%s\n' "$c_seen_ctx" | grep -aqx "$ctx"; then
        c_seen_ctx="$c_seen_ctx$ctx
"
        printf 'LEADER-CTX %s pid=%s comm=%s ctx=%s\n' "$(date +%s.%N)" "$c_seen_pid" "$(cat "/proc/$c_seen_pid/comm" 2>/dev/null)" "$ctx" >> "$EVIDENCE_DIR/22-companion-flow-context.txt"
      fi
      CHILDREN="$(cat "/proc/$c_seen_pid/task/$c_seen_pid/children" 2>/dev/null || true)"
      for C in $CHILDREN; do
        TAP_LINE="$(grep -a 'tap0' "/proc/$C/net/dev" 2>/dev/null || true)"
        if [ -n "$TAP_LINE" ]; then
          printf 'TAP0-OBSERVED %s child=%s dev=%s\n' "$(date +%s.%N)" "$C" "$(printf '%s\n' "$TAP_LINE" | head -1 | awk '{print $1, $2}')" >> "$EVIDENCE_DIR/22-companion-flow-context.txt"
        fi
      done
    fi
    if [ -n "$c_seen_pid" ] && [ ! -d "/proc/$c_seen_pid" ] && [ ! -d "$COMP_RT_OP_DIR" ] && [ ! -d "$COMP_ST_OP_DIR" ]; then
      printf 'CONVERGED %s\n' "$(date +%s.%N)" >> "$EVIDENCE_DIR/22-companion-flow-context.txt"
      break
    fi
    sleep 0.002
  done
  touch /tmp/p4b-work/companion.done
) &
COMP_SAMPLER_PID=$!
# 4C-29: re-arm the avc/selinux_audited tracepoint for the companion
# window with a FRESH ring (the canonical content is already saved in
# 30-trace-window.txt) — the tracepoint records the SELinux decisions
# independently of auditd's userspace harvest.
COMP_TRACE_AVC_ENABLED=0
if [ "$TRACE_AVC_ENABLED" = 1 ]; then
  echo 0 > "$TRACING/tracing_on" 2>/dev/null || true
  echo > "$TRACING/trace" 2>/dev/null || true
  echo 16384 > "$TRACING/buffer_size_kb" 2>/dev/null || true
  echo 1 > "$TRACING/events/avc/selinux_audited/enable" 2>/dev/null || true \
    && COMP_TRACE_AVC_ENABLED=1
  # 4C-37: the openat tracepoints carry the companion helper's own
  # nsjoin paths (/proc/<pid>/ns/user) — the source of the B identity
  # the cross-operation proof binds against.
  echo 1 > "$TRACING/events/syscalls/sys_enter_openat/enable" 2>/dev/null || true
  echo 1 > "$TRACING/events/syscalls/sys_exit_openat/enable" 2>/dev/null || true
  echo 1 > "$TRACING/tracing_on" 2>/dev/null || true
fi
COMP_START_RC=0
COMP_START_OUT="$(printf 'START %s\n' "$COMP_OP_ID" | timeout 120 socat - UNIX-CONNECT:"$MANAGER_SOCK")" || COMP_START_RC=$?
{
  echo "window-start: $T1"
  echo "START: $COMP_OP_ID"
  echo "response: $COMP_START_OUT (rc=$COMP_START_RC)"
  echo "window-end: $(date +%s)"
} > "$EVIDENCE_DIR/22-companion-launch-window.txt"
cat "$EVIDENCE_DIR/22-companion-launch-window.txt" >&2
for i in $(seq 1 100); do
  [ -f /tmp/p4b-work/companion.done ] && break
  sleep 0.1
done
kill "$COMP_SAMPLER_PID" 2>/dev/null || true
wait "$COMP_SAMPLER_PID" 2>/dev/null || true
harvest_avcs_since "$T1" "$EVIDENCE_DIR/23-companion-avc-window.txt"
# 4C-29: read + disable the companion trace ring, then decode it
# against the companion's audit slice (same calibration method; the
# dontaudit-disabled leg makes the userspace channel MORE complete, so
# the calibration here validates the masks for the flow's denials).
if [ "$COMP_TRACE_AVC_ENABLED" = 1 ]; then
  echo 0 > "$TRACING/tracing_on" 2>/dev/null || true
  cat "$TRACING/trace" > "$EVIDENCE_DIR/35-companion-avc-trace.txt" 2>/dev/null || true
  echo 0 > "$TRACING/events/avc/selinux_audited/enable" 2>/dev/null || true
  echo 0 > "$TRACING/events/syscalls/sys_enter_openat/enable" 2>/dev/null || true
  echo 0 > "$TRACING/events/syscalls/sys_exit_openat/enable" 2>/dev/null || true
  {
    echo "=== 4C-29 companion (dontaudit disabled): raw selinux_audited events ==="
    grep -a 'selinux_audited:' "$EVIDENCE_DIR/35-companion-avc-trace.txt" 2>/dev/null || echo "(none in the ring)"
    echo "=== calibration + decode against the companion audit slice ==="
    awk -f /tmp/p4b-work/decode.awk "$EVIDENCE_DIR/35-companion-avc-trace.txt" "$EVIDENCE_DIR/23-companion-avc-window.txt" 2>&1 || true
  } > "$EVIDENCE_DIR/36-companion-avc-trace-decode.txt" 2>&1
  cat "$EVIDENCE_DIR/36-companion-avc-trace-decode.txt" >&2
else
  : > "$EVIDENCE_DIR/35-companion-avc-trace.txt"
  : > "$EVIDENCE_DIR/36-companion-avc-trace-decode.txt"
fi
{
  echo "=== companion window's audit.log SYSCALL records (key p5s2diag) since epoch $T1 ==="
  grep -a 'type=SYSCALL' /var/log/audit/audit.log 2>/dev/null \
    | grep -a 'p5s2diag' \
    | awk -v s="$T1" '{ for (i = 1; i <= NF; i++) if ($i ~ /^msg=audit\(/) { ts = substr($i, 11); split(ts, t, "."); if (t[1] + 0 >= s + 0) print; break } }' \
    || true
  echo "=== auditctl -s (companion-window counters AT HARVEST: backlog_limit/lost/backlog decide whether a missing AVC slice is an absence proof or an audit-loss; the 4C-21 contract) ==="
  auditctl -s 2>&1 || true
} > "$EVIDENCE_DIR/23-companion-syscall-chronology.txt" 2>&1
{
  echo "=== the companion window's manager journal (the child tail) ==="
  grep -a -A6 'child output tail' "$EVIDENCE_DIR/24-companion-manager-diag.txt" 2>/dev/null || true
  journalctl -u "$UNIT" --since "@$T1" --no-pager 2>/dev/null | tail -60 || true
} > "$EVIDENCE_DIR/24-companion-manager-diag.txt" 2>&1
# The companion's own boundary read: every netlink_route_socket denial
# of the dontaudit-disabled window (the message-level evidence).
{
  echo "=== companion (dontaudit disabled): netlink_route_socket AVCs of the window ==="
  grep -a 'tclass=netlink_route_socket' "$EVIDENCE_DIR/23-companion-avc-window.txt" 2>/dev/null \
    || echo "(none — no netlink_route_socket denial visible even with dontaudit disabled)"
  echo "=== companion (dontaudit disabled): the datagram fallback creates of the window ==="
  grep -a -E 'tclass=(unix_dgram_socket|udp_socket)' "$EVIDENCE_DIR/23-companion-avc-window.txt" 2>/dev/null \
    || echo "(none — the libc fallback chain did not run)"
} > "$EVIDENCE_DIR/25-companion-boundary.txt" 2>&1
cat "$EVIDENCE_DIR/25-companion-boundary.txt" >&2
# Restore the production baseline and PROVE it.
auditctl -D > /dev/null 2>&1 || true
auditctl -a never,task > /dev/null 2>&1 || true
auditctl -b 64 > /dev/null 2>&1 || true
semodule -B >> "$EVIDENCE_DIR/18-semodule-db-diag.txt" 2>&1 || true
{
  echo "=== 4C-19 companion restore (post-window semodule -B) ==="
  echo "getenforce: $(getenforce 2>/dev/null)"
  echo "flow-domain dontaudit rules on netlink_route_socket AFTER the restore (non-zero = the production baseline is back):"
  sesearch --dontaudit -s docker_helper_rootlesskit_t -c netlink_route_socket /sys/fs/selinux/policy 2>/dev/null || true
} >> "$EVIDENCE_DIR/18-semodule-db-diag.txt"
marker "CC: companion diagnostic window complete (baseline restored)"
# 4C-27 neutral diagnostic marker (NOT a policy-boundary gate — the
# outcome may not be an SELinux boundary at all; the evidence lives in
# the 30-*/31-* files).
marker "SLIRP-STARTUP-DIAG=collected (tracefs + snapshots; see 30-*/31-*)"

# ============================================================
# H: verdict
# ============================================================
cat > "$EVIDENCE_DIR/verdict.txt" <<EOF
prereq: PASS
preflight: PASS
provisioning: PASS
manager-context: PASS
launcher-chain: PASS
i9-legacy-vehicles: $I9_VERDICT
no-uncategorized: PASS
first downstream boundary: $(cat "$EVIDENCE_DIR/10-avc-first-downstream.txt")
EOF
cat "$EVIDENCE_DIR/verdict.txt" >&2
if [ "$I9_OK" = 1 ]; then
  # The downstream payload AVC (if any) is the recorded boundary of the
  # next step, not a Phase 4B failure: the G28 ledger is deliberately not
  # transferred here.
  finish PASS; exit 0
fi
if [ "$I9_OK" = 2 ]; then
  marker "BLOCKER=i9 legacy vehicles inconclusive (the attempt evidence is missing; see 13-i9-legacy.txt)"
  finish INCOMPLETE
  exit 0
fi
marker "BLOCKER=unresolved I9 vehicle failure (see 13-i9-legacy.txt)"
finish FAIL
exit 0
