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
  sha256sum "$TRANSFERRED/docker-helper" "$TRANSFERRED/docker-helper.te" \
    "$TRANSFERRED/docker-helper.fc" "$TRANSFERRED/docker-helper-builder.service" \
    "$TRANSFERRED/provision-builder.sh" "$TRANSFERRED/modules-load.conf" 2>/dev/null || true
} > "$EVIDENCE_DIR/01-composition-inputs.txt" 2>&1
while IFS='=' read -r key want; do
  case "$key" in
    binary_sha256) file="$TRANSFERRED/docker-helper" ;;
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
  echo 1 > "$TRACING/events/capability/cap_capable/enable" 2>/dev/null || true \
    && TRACE_ENABLED=1
  echo 1 > "$TRACING/events/syscalls/sys_enter_openat/enable" 2>/dev/null || true
  echo 1 > "$TRACING/events/syscalls/sys_exit_openat/enable" 2>/dev/null || true
  echo 1 > "$TRACING/events/syscalls/sys_enter_setns/enable" 2>/dev/null || true
  echo 1 > "$TRACING/events/syscalls/sys_exit_setns/enable" 2>/dev/null || true
  echo 1 > "$TRACING/events/syscalls/sys_enter_socket/enable" 2>/dev/null || true
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
    echo "=== 4C-29 selinux_audited tracepoint format (recorded verbatim) ==="
    cat "$TRACING/events/avc/selinux_audited/format" 2>/dev/null || echo "(format file unavailable)"
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
  echo "--- the exact 4C-13 shape (denied ioctl, ioctlcmd=0x54ca = TUNSETIFF):"
  OLD_TUN_IOCTL="$(printf '%s\n' "$TUN_AVC_WINDOW" | grep -a 'ioctlcmd=0x54ca' || true)"
  printf '%s\n' "${OLD_TUN_IOCTL:-(none — the 4C-13 ioctl(TUNSETIFF) denial is gone)}"
  echo "--- the exact 4C-16 shape (denied ioctl, ioctlcmd=0x54cb = TUNSETPERSIST):"
  OLD_PERSIST_IOCTL="$(printf '%s\n' "$TUN_AVC_WINDOW" | grep -a 'ioctlcmd=0x54cb' || true)"
  printf '%s\n' "${OLD_PERSIST_IOCTL:-(none — the 4C-16 ioctl(TUNSETPERSIST) denial is gone)}"
  echo "--- the manager journal's 4C-16 EACCES shape (must be gone — TUNSETPERSIST completes):"
  MGR_SETPERSIST_EACCES="$(grep -a 'ioctl(TUNSETPERSIST): Permission denied' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null || true)"
  printf '%s\n' "${MGR_SETPERSIST_EACCES:-(none — the TUNSETPERSIST SELinux-hook EACCES is gone)}"
  echo "--- granted-surface regressions (the ROOTLESSKIT flow domain's granted ordinary bits — must be zero; the 4C-30 correction: this gate owns the ROOTLESSKIT domain's TUN surface only, another domain's tun_tap_device_t denial is its own staircase and is recorded below, not failed):"
  TUN_REGRESSION="$(printf '%s\n' "$TUN_AVC_WINDOW" | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' | grep -aE 'denied  *{ (read|write|open|getattr|append|lock|create|setattr)' || true)"
  printf '%s\n' "${TUN_REGRESSION:-(none — the granted ordinary surface held)}"
  echo "--- OTHER domains' tun_tap_device_t denials (their independent TUN staircases — recorded, not failed; the slirp helper has ZERO tun authority and its open_tap() denial is the recorded next-boundary evidence):"
  TUN_OTHER_DOMAIN="$(printf '%s\n' "$TUN_AVC_WINDOW" | grep -av 'scontext=system_u:system_r:docker_helper_rootlesskit_t' || true)"
  printf '%s\n' "${TUN_OTHER_DOMAIN:-(none — no other domain's TUN denial appeared)}"
  echo "--- xperm-mediated denials of non-whitelisted commands (the gate holding; the recorded next-boundary evidence):"
  XP_DENIALS="$(printf '%s\n' "$TUN_AVC_WINDOW" | grep -a 'denied  *{ ioctl }' | grep -a 'ioctlcmd=' | grep -av 'ioctlcmd=0x54ca' | grep -av 'ioctlcmd=0x54cb' || true)"
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
  # The 4C-30 next-boundary record: another domain's (the slirp
  # helper's) independent TUN staircase denial, if one appeared.
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
# ---- next boundary (per the iproute2 tap_add_ioctl() sequence,
# ---- predicted TUNSETPERSIST 0x54cb) is NOT granted and is recorded by
# ---- the 14-gate's xperm-denial inventory and the generic
# ---- DOWNSTREAM-BOUNDARY mechanism; no route/nlmsg/attach authority is
# ---- pre-granted here.
TS_CREATE_GONE_OK=1
{
  echo "=== tun_socket AVCs of the window (the 4C-15 create boundary must be absent) ==="
  TS_AVC_WINDOW="$(grep -a 'tclass=tun_socket' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null || true)"
  printf '%s\n' "${TS_AVC_WINDOW:-(none — no tun_socket denial in the window)}"
  echo "--- the manager journal's TUNSETIFF EACCES shape (must be gone — TUNSETIFF completes past security_tun_dev_create()):"
  MGR_TUNSETIFF_EACCES="$(grep -a 'ioctl(TUNSETIFF): Permission denied' "$EVIDENCE_DIR/07-manager-diag.txt" 2>/dev/null || true)"
  printf '%s\n' "${MGR_TUNSETIFF_EACCES:-(none — the TUNSETIFF SELinux-hook EACCES is gone)}"
  if [ -n "$TS_AVC_WINDOW" ]; then
    echo "GATE: a tun_socket denial appeared in the window — the 4C-16 create grant did not take effect"
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
  echo 1 > "$TRACING/events/avc/selinux_audited/enable" 2>/dev/null || true \
    && COMP_TRACE_AVC_ENABLED=1
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
