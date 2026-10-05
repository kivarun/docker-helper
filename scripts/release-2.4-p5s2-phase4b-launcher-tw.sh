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
finish() {
  # The early finish-exit paths run before the sampler's own grace kill,
  # so finish stops the sampler itself: an exited script must not leave
  # a background writer mutating the evidence and work trees while the
  # cleanup and the packaging run (the post-exit race broke the trap's
  # exit code, run 37047211779).
  [ -n "${SAMPLER_PID:-}" ] && {
    kill "$SAMPLER_PID" 2>/dev/null || true
    wait "$SAMPLER_PID" 2>/dev/null || true
    rm -f "$EVIDENCE_DIR"/.write-* 2>/dev/null || true
  }
  printf '%s P5S2-P4B-RESULT=%s\n' "$PREFIX" "$1"
}

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

# 4C-39 numeric SELinux permission map — THE LOADED POLICY'S OWN NUMBERING.
# Every /sys/fs/selinux/class/<class>/perms/<permission> file carries that
# permission's index in the LOADED POLICY's class definition (decimal
# content, one past the policy's zero-based index). This map is the
# recorded interface fact; it is NOT the kernel's AVC-mask decode: the
# kernel's access decisions and the selinux_audited tracepoint use the
# KERNEL'S OWN STATIC class/perm numbering, and the two numberings differ
# on this kernel/policy pair (live proof in the project's own runs: the
# kernel's audit records calibrate dir:search to the AVC mask 0x20000000
# (run 37050894858) and name mounton for the rootlesskit child's
# mount("/") denial while the perms files number search 31 and mounton
# 18). A symbolic AVC decode therefore comes ONLY from the kernel's own
# symbolic statements — the co-captured calibration pairs and the audit
# slice's same-shape records — never from a directory-listing order (the
# 4C-38 relabelto misread) and never from this map.
numeric_perms_map() { # $1 = class; prints "<name>=<index> (0x<mask>)" lines
  local class="$1" permsdir f name idx
  permsdir="/sys/fs/selinux/class/$class/perms"
  [ -d "$permsdir" ] || { echo "(selinuxfs perms dir for $class unavailable)"; return 0; }
  for f in "$permsdir"/*; do
    [ -f "$f" ] || continue
    name="${f##*/}"
    idx="$(tr -d '[:space:]' < "$f" 2>/dev/null)" || continue
    case "$idx" in
      ''|*[!0-9]*) printf '%s: (non-numeric content %q — the interface form is recorded, not decoded)\n' "$name" "$idx"; continue ;;
    esac
    printf '%s=%s (1<<%s)\n' "$name" "$idx" "$idx"
  done
}

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
  rm -rf /usr/libexec/docker-helper "$STATE_ROOT" "$RUNTIME_ROOT" "$TRANSFERRED" /tmp/p4b-work /tmp/p4b-buildkit-extract 2>/dev/null || true
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

  echo "=== flow root mount-propagation identity (the 4C-39 grant: the module's own rootlesskit -> root_t:dir contribution must be exactly the one bare mounton rule; the EFFECTIVE union may carry only that plus the base policy's standing domain-attribute trio { ioctl lock read }; any other dir permission — relabelto, the 4C-38 decoder misread, included — is a STOP) ==="
  echo "--- raw effective inventory (rootlesskit -> root_t:dir; base-policy/attribute expansions recorded, not asserted):"
  RK_ROOTDIR_RAW="$(sesearch --allow -s docker_helper_rootlesskit_t -t root_t -c dir /sys/fs/selinux/policy 2>/dev/null || true)"
  printf '%s\n' "${RK_ROOTDIR_RAW:-(none)}"
  echo "--- CONCRETE module contribution (source must be docker_helper_rootlesskit_t; must be exactly one bare mounton rule):"
  RK_ROOTDIR_CONCRETE="$(printf '%s\n' "$RK_ROOTDIR_RAW" | awk '$2 == "docker_helper_rootlesskit_t"' || true)"
  printf '%s\n' "${RK_ROOTDIR_CONCRETE:-(none)}"
  echo "--- the dir class's numeric permission map (value -> name from the perms files' contents; the LOADED POLICY's own numbering — the recorded interface fact, never the kernel's AVC-mask decode):"
  numeric_perms_map dir || true
  RK_ROOTDIR_UNION="$(printf '%s\n' "$RK_ROOTDIR_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* root_t:dir \(.*\);$/\1/p' | sed 's/[{}]//g' | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "effective dir perm union: ${RK_ROOTDIR_UNION:-(none)}"
  echo "--- the forbidden-new-perms negative (everything beyond the base policy's standing { ioctl lock read } and the granted mounton must be absent from the whole effective surface; relabelto named first — the 4C-38 decoder misread):"
  RK_ROOTDIR_FORBIDDEN="$(printf '%s\n' "$RK_ROOTDIR_UNION" | tr ' ' '\n' | grep -avE '^(ioctl|lock|mounton|read)$' || true)"
  printf '%s\n' "${RK_ROOTDIR_FORBIDDEN:-(none — no extra dir permission)}"
  RK_ROOTDIR_OK=0
  if [ "$(printf '%s\n' "$RK_ROOTDIR_CONCRETE" | grep -ac . || true)" = 1 ] \
    && printf '%s\n' "$RK_ROOTDIR_CONCRETE" | grep -aqx 'allow docker_helper_rootlesskit_t root_t:dir mounton;' \
    && [ -z "$RK_ROOTDIR_FORBIDDEN" ]; then
    RK_ROOTDIR_OK=1
  fi
  if [ "$RK_ROOTDIR_OK" = 1 ]; then
    echo "PASS: flow root mount-propagation identity (module contribution exactly { mounton }; effective union = the base policy's standing { ioctl lock read } + mounton; no relabelto)"
  else
    echo "FAIL: flow root mount-propagation identity (concrete-rules=$(printf '%s\n' "$RK_ROOTDIR_CONCRETE" | grep -ac . || true) union=${RK_ROOTDIR_UNION:-(none)})"
    PREFLIGHT_OK=0
  fi

  echo "=== flow tmp copy-up identity (the 4C-43 grant: the module's own rootlesskit -> tmp_t contribution must be exactly the one { write add_name create mounton } dir rule — the 4C-43 mounton widened the 4C-42 trio IN PLACE; the EFFECTIVE dir union = the base policy's standing tmp surface + the quartet — the standing rules are ATTRIBUTE-derived (the base policy writes base_file_type/tmpfile, not tmp_t literally), and the 4C-39 run's boundary mask 0x20000004 proved the standing surface carries search; the union is NOT required to be exactly the quartet, but every dir permission beyond the standing { getattr open search } and the granted quartet is a STOP; the RemoveAll cleanup surface (remove_name/read/rmdir) must not ride) ==="
  echo "--- raw effective inventory (rootlesskit -> tmp_t, every class; base-policy/attribute expansions recorded, not asserted):"
  RK_TMP_RAW="$(sesearch --allow -s docker_helper_rootlesskit_t -t tmp_t /sys/fs/selinux/policy 2>/dev/null || true)"
  printf '%s\n' "${RK_TMP_RAW:-(none)}"
  echo "--- CONCRETE module contribution (source must be docker_helper_rootlesskit_t; must be exactly one dir rule contributing exactly { add_name create mounton write } — the SET is checked, sesearch normalizes the brace order):"
  RK_TMP_CONCRETE="$(printf '%s\n' "$RK_TMP_RAW" | awk '$2 == "docker_helper_rootlesskit_t"' || true)"
  printf '%s\n' "${RK_TMP_CONCRETE:-(none)}"
  RK_TMP_CONCRETE_NORM="$(printf '%s\n' "$RK_TMP_CONCRETE" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:[^ ]* {\(.*\)};$/\1/p' | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//' || true)"
  echo "--- the base policy's standing tmp surface (the effective inventory minus the granted quartet — the effective_before record; the 4C-39 run 37101080574's boundary mask 0x20000004 names search as a proven member; the standing rules are attribute-derived — the base policy writes base_file_type/tmpfile/file_type, not tmp_t literally):"
  RK_TMP_STANDING="$(printf '%s\n' "$RK_TMP_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:[^ ]* \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | grep -avE '^(write|add_name|create|mounton)$' | sort -u | tr '\n' ' ' || true)"
  printf '%s\n' "${RK_TMP_STANDING:-(none — the standing surface is empty)}"
  RK_TMP_DIR_UNION="$(printf '%s\n' "$RK_TMP_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:dir \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "effective dir perm union: ${RK_TMP_DIR_UNION:-(none)}"
  echo "--- the forbidden-dir-perms negative (everything beyond the base policy's standing { getattr open search } and the granted quartet must be absent from the whole effective dir surface; the standing set is this run's own inventory fact; the RemoveAll cleanup surface must not ride):"
  RK_TMP_FORBIDDEN="$(printf '%s\n' "$RK_TMP_DIR_UNION" | tr ' ' '\n' | grep -avE '^(getattr|open|search|write|add_name|create|mounton)$' || true)"
  printf '%s\n' "${RK_TMP_FORBIDDEN:-(none — no extra dir permission)}"
  RK_TMP_OK=0
  if [ "$(printf '%s\n' "$RK_TMP_CONCRETE" | grep -ac . || true)" = 1 ] \
    && printf '%s\n' "$RK_TMP_CONCRETE" | grep -aq 'allow docker_helper_rootlesskit_t tmp_t:dir' \
    && [ "$RK_TMP_CONCRETE_NORM" = "add_name create mounton write" ] \
    && printf '%s\n' "$RK_TMP_DIR_UNION" | tr ' ' '\n' | grep -aqx 'write' \
    && printf '%s\n' "$RK_TMP_DIR_UNION" | tr ' ' '\n' | grep -aqx 'add_name' \
    && printf '%s\n' "$RK_TMP_DIR_UNION" | tr ' ' '\n' | grep -aqx 'create' \
    && printf '%s\n' "$RK_TMP_DIR_UNION" | tr ' ' '\n' | grep -aqx 'mounton' \
    && printf '%s\n' "$RK_TMP_DIR_UNION" | tr ' ' '\n' | grep -aqx 'search' \
    && [ -z "$RK_TMP_FORBIDDEN" ]; then
    RK_TMP_OK=1
  fi
  if [ "$RK_TMP_OK" = 1 ]; then
    echo "PASS: flow tmp copy-up identity (module contribution exactly { write add_name create mounton }; effective dir union = the base policy's standing { getattr open search } + the quartet — search is the proven standing member; no module-borne permission beyond the quartet)"
  else
    echo "FAIL: flow tmp copy-up identity (concrete-rules=$(printf '%s\n' "$RK_TMP_CONCRETE" | grep -ac . || true) union=${RK_TMP_DIR_UNION:-(none)})"
    PREFLIGHT_OK=0
  fi
  if [ "$RK_TMP_OK" = 1 ]; then
    echo "PASS: flow tmp copy-up identity (module contribution exactly { write add_name }; effective dir union = the base policy's standing { getattr open search } + { write add_name } — search is the proven standing member; no module-borne permission beyond the pair)"
  else
    echo "FAIL: flow tmp copy-up identity (concrete-rules=$(printf '%s\n' "$RK_TMP_CONCRETE" | grep -ac . || true) union=${RK_TMP_DIR_UNION:-(none)})"
    PREFLIGHT_OK=0
  fi

  echo "=== flow etc copy-up identity (the 4C-44 grant: the module's own rootlesskit -> etc_t contribution must be exactly the one bare dir-mounton rule — the copy-up tmpfs mount over /etc's OWN distro label etc_t, a NEW evidenced pair distinct from root_t and tmp_t; the standing etc_t surface is ATTRIBUTE-derived and RECORDED, not asserted; every dir permission beyond the standing { getattr open search } and the granted mounton is a STOP; the .ro/scan surfaces stay ungranted) ==="
  echo "--- raw effective inventory (rootlesskit -> etc_t, every class; base-policy/attribute expansions recorded, not asserted):"
  RK_ETC_RAW="$(sesearch --allow -s docker_helper_rootlesskit_t -t etc_t /sys/fs/selinux/policy 2>/dev/null || true)"
  printf '%s\n' "${RK_ETC_RAW:-(none)}"
  echo "--- CONCRETE module contribution (source must be docker_helper_rootlesskit_t; must be exactly one bare dir mounton rule):"
  RK_ETC_CONCRETE="$(printf '%s\n' "$RK_ETC_RAW" | awk '$2 == "docker_helper_rootlesskit_t"' || true)"
  printf '%s\n' "${RK_ETC_CONCRETE:-(none)}"
  echo "--- the base policy's standing etc_t surface (the effective inventory minus the granted mounton — the effective_before record; attribute-derived, recorded not asserted):"
  RK_ETC_STANDING="$(printf '%s\n' "$RK_ETC_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:[^ ]* \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | grep -av '^mounton$' | sort -u | tr '\n' ' ' || true)"
  printf '%s\n' "${RK_ETC_STANDING:-(none — the standing surface is empty)}"
  RK_ETC_DIR_UNION="$(printf '%s\n' "$RK_ETC_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:dir \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "effective dir perm union: ${RK_ETC_DIR_UNION:-(none)}"
  echo "--- the forbidden-dir-perms negative (everything beyond the base policy's standing { getattr ioctl lock open read search } — the base_file_type trio plus the base_ro_file_type trio, both attribute-derived — and the granted mounton must be absent from the whole effective dir surface; the standing set is the 4C-44 preflight inventory's own fact, run 37144848669; the .ro/scan surfaces must not ride):"
  RK_ETC_FORBIDDEN="$(printf '%s\n' "$RK_ETC_DIR_UNION" | tr ' ' '\n' | grep -avE '^(getattr|ioctl|lock|open|read|search|mounton)$' || true)"
  printf '%s\n' "${RK_ETC_FORBIDDEN:-(none — no extra dir permission)}"
  RK_ETC_OK=0
  if [ "$(printf '%s\n' "$RK_ETC_CONCRETE" | grep -ac . || true)" = 1 ] \
    && printf '%s\n' "$RK_ETC_CONCRETE" | grep -aqx 'allow docker_helper_rootlesskit_t etc_t:dir mounton;' \
    && printf '%s\n' "$RK_ETC_DIR_UNION" | tr ' ' '\n' | grep -aqx 'mounton' \
    && [ -z "$RK_ETC_FORBIDDEN" ]; then
    RK_ETC_OK=1
  fi
  if [ "$RK_ETC_OK" = 1 ]; then
    echo "PASS: flow etc copy-up identity (module contribution exactly { mounton }; effective dir union = the base policy's standing surface + mounton — the standing residual recorded above; no module-borne permission beyond mounton)"
  else
    echo "FAIL: flow etc copy-up identity (concrete-rules=$(printf '%s\n' "$RK_ETC_CONCRETE" | grep -ac . || true) union=${RK_ETC_DIR_UNION:-(none)})"
    PREFLIGHT_OK=0
  fi

  echo "=== flow tmpfs .ro dir identity (the 4C-46/4C-47 grants: the module's own rootlesskit -> tmpfs_t:dir contribution must be exactly the one brace-pair dir rule { create mounton } — the .ro mkdirat's child-SID create (4C-46, the canonical 4C-45 run's denial) and the move-mount's target-dir mounton (4C-47, the canonical 4C-46 run's denial); SAME pair, one rule; the class is the evidence — dir, never the 4C-45 filesystem pair; the parent-side add_name/remove_name/write are STANDING base-policy attribute authority and must NOT be copied into the module; every dir permission beyond the standing surface and the granted pair is a STOP; the rebuild surfaces stay ungranted) ==="
  echo "--- raw effective inventory (rootlesskit -> tmpfs_t, every class; base-policy/attribute expansions recorded, not asserted):"
  RK_TMPFSDIR_RAW="$(sesearch --allow -s docker_helper_rootlesskit_t -t tmpfs_t /sys/fs/selinux/policy 2>/dev/null || true)"
  printf '%s\n' "${RK_TMPFSDIR_RAW:-(none)}"
  echo "--- CONCRETE module contribution (source must be docker_helper_rootlesskit_t AND class dir — tmpfs_t now carries two owned rules across classes, the 4C-46/47 dir pair and the 4C-45 filesystem mount; must be exactly one brace-pair dir rule):"
  RK_TMPFSDIR_CONCRETE="$(printf '%s\n' "$RK_TMPFSDIR_RAW" | awk '$2 == "docker_helper_rootlesskit_t" && $0 ~ /:dir/' || true)"
  printf '%s\n' "${RK_TMPFSDIR_CONCRETE:-(none)}"
  echo "--- the base policy's standing tmpfs_t:dir surface (the effective inventory minus the granted pair — the effective_before record; attribute-derived, recorded not asserted; the 4C-46 run's inventory showed { add_name getattr ioctl lock open read remove_name search write } — do NOT assume, this run's own inventory is the fact):"
  RK_TMPFSDIR_STANDING="$(printf '%s\n' "$RK_TMPFSDIR_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:[^ ]* \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | grep -avE '^(create|mounton)$' | sort -u | tr '\n' ' ' || true)"
  printf '%s\n' "${RK_TMPFSDIR_STANDING:-(none — the standing surface is empty)}"
  RK_TMPFSDIR_DIR_UNION="$(printf '%s\n' "$RK_TMPFSDIR_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:dir \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "effective dir perm union: ${RK_TMPFSDIR_DIR_UNION:-(none)}"
  echo "--- the forbidden-dir-perms negative (everything beyond the base policy's standing surface and the granted pair must be absent from the whole effective dir surface; the standing set is this run's own inventory fact; the RemoveAll/rebuild surfaces must not ride):"
  RK_TMPFSDIR_FORBIDDEN="$(printf '%s\n' "$RK_TMPFSDIR_DIR_UNION" | tr ' ' '\n' | grep -avE "^(create|mounton|$(printf '%s' "$RK_TMPFSDIR_STANDING" | tr ' ' '|'))$" || true)"
  printf '%s\n' "${RK_TMPFSDIR_FORBIDDEN:-(none — no extra dir permission)}"
  RK_TMPFSDIR_NORM="$(printf '%s\n' "$RK_TMPFSDIR_CONCRETE" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:[^ ]* {\(.*\)};$/\1/p' | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//' || true)"
  RK_TMPFSDIR_OK=0
  if [ "$(printf '%s\n' "$RK_TMPFSDIR_CONCRETE" | grep -ac . || true)" = 1 ] \
    && printf '%s\n' "$RK_TMPFSDIR_CONCRETE" | grep -aq 'allow docker_helper_rootlesskit_t tmpfs_t:dir' \
    && [ "$RK_TMPFSDIR_NORM" = "create mounton" ] \
    && printf '%s\n' "$RK_TMPFSDIR_DIR_UNION" | tr ' ' '\n' | grep -aqx 'create' \
    && printf '%s\n' "$RK_TMPFSDIR_DIR_UNION" | tr ' ' '\n' | grep -aqx 'mounton' \
    && [ -z "$RK_TMPFSDIR_FORBIDDEN" ]; then
    RK_TMPFSDIR_OK=1
  fi
  if [ "$RK_TMPFSDIR_OK" = 1 ]; then
    echo "PASS: flow tmpfs .ro dir identity (module contribution exactly { create mounton }; effective dir union = the base policy's standing surface + the pair — the standing residual recorded above; no module-borne permission beyond the pair)"
  else
    echo "FAIL: flow tmpfs .ro dir identity (concrete-rules=$(printf '%s\n' "$RK_TMPFSDIR_CONCRETE" | grep -ac . || true) norm=${RK_TMPFSDIR_NORM:-(none)} union=${RK_TMPFSDIR_DIR_UNION:-(none)})"
    PREFLIGHT_OK=0
  fi

  echo "=== flow tmpfs rebuild-symlink identity (the 4C-48 create + 4C-50 read + 4C-53 unlink triple: the module's own rootlesskit -> tmpfs_t:lnk_file contribution must be exactly the one brace-triple lnk_file rule { create read unlink } — ONE pair, ONE rule, widened IN PLACE per phase, never split into two rules, never folded into the dir pair or the filesystem rule; provenance stays per-perm: create <- the canonical 4C-47 run's live-proven symlinkat window (the symlink object's own creation check), read <- the canonical 4C-49 run's live-proven openat(\"/etc/hosts\") window (the link traversal's own read hook — generateEtcHosts()'s os.ReadFile, the startup's FIRST /etc read), unlink <- the canonical 4C-52 run's terminal boundary (the RemoveAll(\"/etc/resolv.conf\") stage's own unlinkat destination hook — the setupNet resolv-replacement step's production removal); the class is the evidence — the symlink object's own class lnk_file; the RESOLVED target's own open/read is the net_conf_t:file pair owner's separate grant (4C-51/4C-52), not this rule; the standing tmpfs_t:lnk_file surface is RECORDED, not asserted — the 4C-49 canonical run's inventory showed the child's lnk_file-class standing residual map-only (file_type); every lnk_file permission beyond the standing surface and the granted triple is a STOP) ==="
  echo "--- CONCRETE module contribution (source must be docker_helper_rootlesskit_t AND class lnk_file — tmpfs_t now carries three owned rules across classes; must be exactly one brace-triple lnk_file { create read unlink } rule):"
  RK_LNK_CONCRETE="$(printf '%s\n' "$RK_TMPFSDIR_RAW" | awk '$2 == "docker_helper_rootlesskit_t" && $0 ~ /:lnk_file/' || true)"
  printf '%s\n' "${RK_LNK_CONCRETE:-(none)}"
  RK_LNK_NORM="$(printf '%s\n' "$RK_LNK_CONCRETE" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:[^ ]* {\(.*\)};$/\1/p' | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//' || true)"
  echo "--- the base policy's standing tmpfs_t:lnk_file surface for the child (the effective inventory's OTHER-source lnk_file-class rules — attribute-derived, recorded not asserted; the 4C-49 canonical run's own inventory showed the child's lnk_file-class standing residual map-only):"
  RK_LNK_STANDING="$(printf '%s\n' "$RK_TMPFSDIR_RAW" | grep -av '^allow docker_helper_rootlesskit_t ' | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:lnk_file \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  printf '%s\n' "${RK_LNK_STANDING:-(none — the standing surface is empty)}"
  RK_LNK_UNION="$(printf '%s\n' "$RK_TMPFSDIR_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:lnk_file \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "effective lnk_file perm union: ${RK_LNK_UNION:-(none)}"
  echo "--- the forbidden-lnk-perms negative (everything beyond the base policy's standing surface and the granted triple must be absent from the whole effective lnk_file surface; the standing set is this run's own inventory fact; the write/getattr/link/rename hooks must not ride):"
  RK_LNK_FORBIDDEN="$(printf '%s\n' "$RK_LNK_UNION" | tr ' ' '\n' | grep -avE "^(create|read|unlink|$(printf '%s' "$RK_LNK_STANDING" | tr ' ' '|'))$" || true)"
  printf '%s\n' "${RK_LNK_FORBIDDEN:-(none — no extra lnk_file permission)}"
  RK_LNK_OK=0
  if [ "$(printf '%s\n' "$RK_LNK_CONCRETE" | grep -ac . || true)" = 1 ] \
    && printf '%s\n' "$RK_LNK_CONCRETE" | grep -aq 'allow docker_helper_rootlesskit_t tmpfs_t:lnk_file' \
    && [ "$RK_LNK_NORM" = "create read unlink" ] \
    && printf '%s\n' "$RK_LNK_UNION" | tr ' ' '\n' | grep -aqx 'create' \
    && printf '%s\n' "$RK_LNK_UNION" | tr ' ' '\n' | grep -aqx 'read' \
    && printf '%s\n' "$RK_LNK_UNION" | tr ' ' '\n' | grep -aqx 'unlink' \
    && [ -z "$RK_LNK_FORBIDDEN" ]; then
    RK_LNK_OK=1
  fi
  if [ "$RK_LNK_OK" = 1 ]; then
    echo "PASS: flow tmpfs rebuild-symlink identity (module contribution exactly { create read unlink }; effective lnk_file union = the base policy's standing surface + the triple — the standing residual recorded above; no module-borne permission beyond the triple)"
  else
    echo "FAIL: flow tmpfs rebuild-symlink identity (concrete-rules=$(printf '%s\n' "$RK_LNK_CONCRETE" | grep -ac . || true) norm=${RK_LNK_NORM:-(none)} union=${RK_LNK_UNION:-(none)})"
    PREFLIGHT_OK=0
  fi

  echo "=== flow tmpfs superblock identity (the 4C-45 grant: the module's own rootlesskit -> tmpfs_t contribution must be exactly the one bare filesystem-mount rule — the copy-up tmpfs mount over /etc creates a NEW tmpfs superblock whose OWN filesystem-class check gates its creation; the class is the evidence — filesystem, never a dir permission; tmpfs_t:s0 is a GLOBAL label, so this grant is NOT operation-scoped — the nsfs_t scope shape; the standing tmpfs_t:filesystem surface is RECORDED, not asserted; every filesystem permission beyond the standing surface and the granted mount is a STOP; the .ro/MS_MOVE/scan surfaces stay ungranted) ==="
  echo "--- raw effective inventory (rootlesskit -> tmpfs_t, every class; base-policy/attribute expansions recorded, not asserted):"
  RK_TMPFS_RAW="$(sesearch --allow -s docker_helper_rootlesskit_t -t tmpfs_t /sys/fs/selinux/policy 2>/dev/null || true)"
  printf '%s\n' "${RK_TMPFS_RAW:-(none)}"
  echo "--- CONCRETE module contribution (source must be docker_helper_rootlesskit_t AND class filesystem — tmpfs_t now carries two owned rules across classes, the 4C-45 filesystem mount and the 4C-46 dir-create; must be exactly one bare filesystem mount rule):"
  RK_TMPFS_CONCRETE="$(printf '%s\n' "$RK_TMPFS_RAW" | awk '$2 == "docker_helper_rootlesskit_t" && $0 ~ /:filesystem/' || true)"
  printf '%s\n' "${RK_TMPFS_CONCRETE:-(none)}"
  echo "--- the base policy's standing tmpfs_t:filesystem surface (the effective inventory minus the granted mount — the effective_before record; attribute-derived, recorded not asserted):"
  RK_TMPFS_STANDING="$(printf '%s\n' "$RK_TMPFS_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:[^ ]* \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | grep -av '^mount$' | sort -u | tr '\n' ' ' || true)"
  printf '%s\n' "${RK_TMPFS_STANDING:-(none — the standing surface is empty)}"
  RK_TMPFS_FS_UNION="$(printf '%s\n' "$RK_TMPFS_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:filesystem \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "effective filesystem perm union: ${RK_TMPFS_FS_UNION:-(none)}"
  echo "--- the forbidden-fs-perms negative (everything beyond the base policy's standing surface and the granted mount must be absent from the whole effective filesystem surface; the standing set is this run's own inventory fact; the remount/unmount/.ro hook surfaces must not ride):"
  RK_TMPFS_FORBIDDEN="$(printf '%s\n' "$RK_TMPFS_FS_UNION" | tr ' ' '\n' | grep -avE "^(mount|$(printf '%s' "$RK_TMPFS_STANDING" | tr ' ' '|'))$" || true)"
  printf '%s\n' "${RK_TMPFS_FORBIDDEN:-(none — no extra filesystem permission)}"
  RK_TMPFS_OK=0
  if [ "$(printf '%s\n' "$RK_TMPFS_CONCRETE" | grep -ac . || true)" = 1 ] \
    && printf '%s\n' "$RK_TMPFS_CONCRETE" | grep -aqx 'allow docker_helper_rootlesskit_t tmpfs_t:filesystem mount;' \
    && printf '%s\n' "$RK_TMPFS_FS_UNION" | tr ' ' '\n' | grep -aqx 'mount' \
    && [ -z "$RK_TMPFS_FORBIDDEN" ]; then
    RK_TMPFS_OK=1
  fi
  if [ "$RK_TMPFS_OK" = 1 ]; then
    echo "PASS: flow tmpfs superblock identity (module contribution exactly { mount }; effective filesystem union = the base policy's standing surface + mount — the standing residual recorded above; no module-borne permission beyond mount)"
  else
    echo "FAIL: flow tmpfs superblock identity (concrete-rules=$(printf '%s\n' "$RK_TMPFS_CONCRETE" | grep -ac . || true) union=${RK_TMPFS_FS_UNION:-(none)})"
    PREFLIGHT_OK=0
  fi

  echo "=== flow cgroup preservation identity (the 4C-49 grant: the module's own rootlesskit -> cgroup_t:dir contribution = the STANDING search rule widened by exactly the phase's bare mounton rule — the rksys move-mount target /sys/fs/cgroup's OWN global label cgroup_t, the evidenced pair whose confinement is proven by this run's own 4C-49 confinement-gate section (the holder's distinct mount namespace, the recursive-private propagation order, the exact-source/destination binding); cgroup_t:s0 is a GLOBAL label and mounton is path-insensitive TE authority — the grant is NOT operation-scoped and the cross-operation reachability gate stays OPEN; the LOADED-POLICY REPRESENTATION FACT: the kernel's policy avtab COALESCES the module's two same-key rules (the standing { dir search } and the phase's bare dir mounton) into ONE rule carrying the perm UNION — the canonical run 37190799297's own inventory proved the coalesced form; the SOURCE-level separation (two .te rules, two owners) stays the module source's contract, enforced by the committed owner tests, and is invisible in the loaded form; the loaded contract: the dir inventory = exactly ONE coalesced rule { mounton search } with NO other dir permission; the standing surface: the module's OWN earlier cgroup2-root-walk file pair { read open } (recorded, a prior contribution) plus the base policy's attribute-derived residual (the canonical run's inventory showed it EMPTY for dir); the sysfs mount attempts stay UNGRANTED (the tolerated flow behavior)) ==="
  echo "--- raw effective inventory (rootlesskit -> cgroup_t, every class; base-policy/attribute expansions recorded, not asserted):"
  RK_CGROUP_RAW="$(sesearch --allow -s docker_helper_rootlesskit_t -t cgroup_t /sys/fs/selinux/policy 2>/dev/null || true)"
  printf '%s\n' "${RK_CGROUP_RAW:-(none)}"
  echo "--- CONCRETE module contribution (source must be docker_helper_rootlesskit_t AND class dir — the loaded form carries the kernel's coalesced union of the module's standing search rule and the phase's mounton rule; must be exactly one coalesced { mounton search } rule):"
  RK_CGROUP_DIR_CONCRETE="$(printf '%s\n' "$RK_CGROUP_RAW" | awk '$2 == "docker_helper_rootlesskit_t" && $0 ~ /:dir/' || true)"
  printf '%s\n' "${RK_CGROUP_DIR_CONCRETE:-(none)}"
  RK_CGROUP_MOUNTON_RULES="$(printf '%s\n' "$RK_CGROUP_DIR_CONCRETE" | grep -a 'mounton' || true)"
  echo "--- the mounton-carrying rule (the only concrete dir rule naming mounton):"
  printf '%s\n' "${RK_CGROUP_MOUNTON_RULES:-(none)}"
  echo "--- the base policy's standing cgroup_t:dir surface (the effective inventory's NON-concrete rules — source other than docker_helper_rootlesskit_t, the attribute-derived standing; recorded not asserted):"
  RK_CGROUP_STANDING="$(printf '%s\n' "$RK_CGROUP_RAW" | grep -av '^allow docker_helper_rootlesskit_t ' | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:dir \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  printf '%s\n' "${RK_CGROUP_STANDING:-(none — the attribute-derived standing surface is empty)}"
  RK_CGROUP_DIR_UNION="$(printf '%s\n' "$RK_CGROUP_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:dir \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "effective dir perm union: ${RK_CGROUP_DIR_UNION:-(none)}"
  echo "--- the forbidden-dir-perms negative (everything beyond the module's own declared dir pair { search mounton } and the attribute-derived standing must be absent from the whole effective dir surface; the standing set is this run's own inventory fact):"
  RK_CGROUP_FORBIDDEN="$(printf '%s\n' "$RK_CGROUP_DIR_UNION" | tr ' ' '\n' | grep -avE "^(mounton|search|$(printf '%s' "$RK_CGROUP_STANDING" | tr ' ' '|'))$" || true)"
  printf '%s\n' "${RK_CGROUP_FORBIDDEN:-(none — no extra dir permission)}"
  echo "--- the non-dir class surfaces of cgroup_t (the standing file pair { read open } is the module's own prior contribution; the filesystem and any other class carry NO module rule — their surfaces are RECORDED, not asserted; the MOUNTON negative below is the class-confusion gate):"
  RK_CGROUP_FILE_CONCRETE="$(printf '%s\n' "$RK_CGROUP_RAW" | awk '$2 == "docker_helper_rootlesskit_t" && $0 ~ /:file/' || true)"
  printf '%s\n' "${RK_CGROUP_FILE_CONCRETE:-(none)}"
  RK_CGROUP_FILE_UNION="$(printf '%s\n' "$RK_CGROUP_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:file \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  RK_CGROUP_FS_UNION="$(printf '%s\n' "$RK_CGROUP_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:filesystem \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  RK_CGROUP_OTHER_CLASSES="$(printf '%s\n' "$RK_CGROUP_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:\([^ ]*\) .*/\1/p' | grep -avE '^(dir|file|filesystem)$' | sort -u | tr '\n' ' ' || true)"
  echo "effective file perm union: ${RK_CGROUP_FILE_UNION:-(none)}"
  echo "effective filesystem perm union: ${RK_CGROUP_FS_UNION:-(none)}"
  echo "other classes: ${RK_CGROUP_OTHER_CLASSES:-(none)}"
  echo "--- the MOUNTON negative across every class (the cgroup_t authority's mounton shape belongs to the one dir rule — a file/filesystem mounton record is the class confusion the phase forbids):"
  RK_CGROUP_MOUNTON_CLASSES="$(printf '%s\n' "$RK_CGROUP_RAW" | grep -a 'mounton' | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:\([^ ]*\) .*/\1/p' | sort -u | tr '\n' ' ' || true)"
  echo "mounton-naming classes: ${RK_CGROUP_MOUNTON_CLASSES:-(none)}"
  RK_CGROUP_OK=0
  if [ "$(printf '%s\n' "$RK_CGROUP_DIR_CONCRETE" | grep -ac . || true)" = 1 ] \
    && printf '%s\n' "$RK_CGROUP_DIR_CONCRETE" | grep -aqx 'allow docker_helper_rootlesskit_t cgroup_t:dir { mounton search };' \
    && printf '%s\n' "$RK_CGROUP_DIR_UNION" | tr ' ' '\n' | grep -aqx 'mounton' \
    && printf '%s\n' "$RK_CGROUP_DIR_UNION" | tr ' ' '\n' | grep -aqx 'search' \
    && [ -z "$RK_CGROUP_FORBIDDEN" ] \
    && [ "$(printf '%s\n' "$RK_CGROUP_FILE_CONCRETE" | grep -ac . || true)" = 1 ] \
    && printf '%s\n' "$RK_CGROUP_FILE_CONCRETE" | grep -aqx 'allow docker_helper_rootlesskit_t cgroup_t:file { open read };' \
    && [ "$(printf '%s\n' "$RK_CGROUP_MOUNTON_CLASSES" | tr ' ' '\n' | grep -ac . || true)" = 1 ] \
    && printf '%s\n' "$RK_CGROUP_MOUNTON_CLASSES" | tr ' ' '\n' | grep -aqx 'dir'; then
    RK_CGROUP_OK=1
  fi
  if [ "$RK_CGROUP_OK" = 1 ]; then
    echo "PASS: flow cgroup preservation identity (the loaded dir inventory = exactly ONE coalesced { mounton search } rule — the module's standing search + the phase's mounton, the source-level separation owned by the module source; the file pair { open read } unchanged; mounton named by no other class; the attribute standing empty per this run's own inventory; no module-borne permission beyond mounton)"
  else
    echo "FAIL: flow cgroup preservation identity (dir-rules=$(printf '%s\n' "$RK_CGROUP_DIR_CONCRETE" | grep -ac . || true) dir-union=${RK_CGROUP_DIR_UNION:-(none)} mounton-rules=$(printf '%s\n' "$RK_CGROUP_MOUNTON_RULES" | grep -ac . || true) file-rules=$(printf '%s\n' "${RK_CGROUP_FILE_CONCRETE:-(none)}" | grep -ac . || true) mounton-classes=${RK_CGROUP_MOUNTON_CLASSES:-(none)})"
    PREFLIGHT_OK=0
  fi

  echo "=== flow resolved-/etc read-open pair identity (the 4C-52 widening: the module's own rootlesskit -> net_conf_t contribution must be exactly the one brace pair rule { read open } — the 4C-51 read (the RESOLVED /etc/hosts target's own regular-file read: the canonical 4C-50 run's boundary record denied it, requested=0x2 denied=0x2 result=-13 tcontext=system_u:object_r:net_conf_t:s0 tclass=file, trace-ts 279.786326; confirmed in three observations including the companion c2 window) widened IN PLACE by the 4C-52 open hook (the canonical 4C-51 run 37286690263's SAME openat(\"/etc/hosts\", O_RDONLY|O_CLOEXEC) passed the read hook and the VFS open's own completion hook denied it: requested=0x40002 denied=0x40000 audited=0x40000 result=-13, trace-ts 292.328103; confirmed in the companion c2 window); the target type is LIVE-PROVEN — the kernel's own tcontext, not a pathname inference; the class is the evidence — file, never lnk_file/dir; the provenance stays SEPARATE (read <- 4C-50, open <- 4C-51) and NO standard read bundle rides (no getattr or any third hook); net_conf_t:s0 is a GLOBAL distro label, so the grant is NOT operation-scoped — the nsfs/tmpfs scope shape; the standing net_conf_t:file surface is RECORDED, not asserted (do NOT assume a standing surface: the pre-grant live fact is the 4C-50 boundary denial itself — the effective surface carried NO read; the effective_before = this run's own effective inventory minus the granted pair); every file permission beyond the standing surface and the granted pair is a STOP) ==="
  echo "--- raw effective inventory (rootlesskit -> net_conf_t, every class; base-policy/attribute expansions recorded, not asserted):"
  RK_NCONF_RAW="$(sesearch --allow -s docker_helper_rootlesskit_t -t net_conf_t /sys/fs/selinux/policy 2>/dev/null || true)"
  printf '%s\n' "${RK_NCONF_RAW:-(none)}"
  echo "--- CONCRETE module contribution (source must be docker_helper_rootlesskit_t; must be exactly one brace pair rule { read open }):"
  RK_NCONF_FILE_CONCRETE="$(printf '%s\n' "$RK_NCONF_RAW" | awk '$2 == "docker_helper_rootlesskit_t" && $0 ~ /:file[ ;]/' || true)"
  printf '%s\n' "${RK_NCONF_FILE_CONCRETE:-(none)}"
  echo "--- the base policy's standing net_conf_t:file surface (the effective inventory minus the granted pair — the effective_before record; attribute-derived, recorded not asserted):"
  RK_NCONF_STANDING="$(printf '%s\n' "$RK_NCONF_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:[^ ]* \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | grep -avE '^(open|read)$' | sort -u | tr '\n' ' ' || true)"
  printf '%s\n' "${RK_NCONF_STANDING:-(none — the standing surface is empty)}"
  RK_NCONF_FILE_UNION="$(printf '%s\n' "$RK_NCONF_RAW" | sed -n 's/^[[:space:]]*allow [^ ]* [^:]*:file \(.*\);$/\1/p' | sed 's/[{}]//g; s/;.*//' | tr ' ' '\n' | sort -u | tr '\n' ' ' || true)"
  echo "effective file perm union: ${RK_NCONF_FILE_UNION:-(none)}"
  echo "--- the forbidden-file-perms negative (everything beyond the base policy's standing surface and the granted pair must be absent from the whole effective file surface; the standing set is this run's own inventory fact; the getattr/write hooks must not ride):"
  RK_NCONF_FORBIDDEN="$(printf '%s\n' "$RK_NCONF_FILE_UNION" | tr ' ' '\n' | grep -avE "^(open|read|$(printf '%s' "$RK_NCONF_STANDING" | tr ' ' '|'))$" || true)"
  printf '%s\n' "${RK_NCONF_FORBIDDEN:-(none — no extra file permission)}"
  echo "--- the CLASS-CONFUSION negatives (the net_conf_t:lnk_file and net_conf_t:dir surfaces must be ABSENT from the concrete-source surface — the link traversal's own hook is the 4C-50 tmpfs_t pair's owner, a dir surface is the parent walk, and every concrete non-file class rule is a STOP; the attribute-generic standing rules (source 'domain', the '[ ... ]:True' conditionals) are RECORDED above and never module-borne authority):"
  RK_NCONF_NONFILE="$(printf '%s\n' "$RK_NCONF_RAW" | awk '$2 == "docker_helper_rootlesskit_t" && $0 !~ /:file[ ;]/' || true)"
  printf '%s\n' "${RK_NCONF_NONFILE:-(none — no concrete non-file class surface)}"
  echo "--- the dontaudit surface toward net_conf_t (RECORDED SEPARATELY per the 4C-28 preflight contract; never merged into the allow verdict):"
  RK_NCONF_DONTAUDIT="$(sesearch --dontaudit -s docker_helper_rootlesskit_t -t net_conf_t /sys/fs/selinux/policy 2>/dev/null || true)"
  printf '%s\n' "${RK_NCONF_DONTAUDIT:-(none — no dontaudit rule hides rootlesskit -> net_conf_t denials)}"
  RK_NCONF_OK=0
  if [ "$(printf '%s\n' "$RK_NCONF_FILE_CONCRETE" | grep -ac . || true)" = 1 ] \
    && printf '%s\n' "$RK_NCONF_FILE_CONCRETE" | grep -aqx 'allow docker_helper_rootlesskit_t net_conf_t:file { open read };' \
    && printf '%s\n' "$RK_NCONF_FILE_UNION" | tr ' ' '\n' | grep -aqx 'read' \
    && printf '%s\n' "$RK_NCONF_FILE_UNION" | tr ' ' '\n' | grep -aqx 'open' \
    && [ -z "$RK_NCONF_FORBIDDEN" ] \
    && [ -z "$RK_NCONF_NONFILE" ]; then
    RK_NCONF_OK=1
  fi
  if [ "$RK_NCONF_OK" = 1 ]; then
    echo "PASS: flow resolved-/etc read-open pair identity (module contribution exactly { read open }; effective file union = the base policy's standing surface + the pair — the standing residual recorded above; no module-borne permission beyond the pair; no concrete non-file class surface)"
  else
    echo "FAIL: flow resolved-/etc read-open pair identity (concrete-rules=$(printf '%s\n' "$RK_NCONF_FILE_CONCRETE" | grep -ac . || true) union=${RK_NCONF_FILE_UNION:-(none)} forbidden=${RK_NCONF_FORBIDDEN:-(none)} non-file=${RK_NCONF_NONFILE:-(none)})"
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
  # must not eat the window's own syscall/AVC records. 4C-38 widens the
  # ring further (64 MiB): the lifetime/readiness instrumentation adds
  # the fork/exit, signal, wait, poll and read/write/close tracepoints,
  # and the window must retain every event from the arm to the harvest
  # without the flow's own I/O or the harness's fork noise overwriting
  # the attach and first-death records.
  echo 65536 > "$TRACING/buffer_size_kb" 2>/dev/null || true
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
  # 4C-38: the lifetime/readiness instrumentation. Process fork/exit (the
  # first-death records), signal generate/delivery (SIGCHLD included;
  # the killer's own identity comes from the co-timed kill-family
  # syscall records), the wait family (the parent's reap and its
  # result), the poll family (readiness waits) and read/write/close (the
  # ready channel's own records). 4C-39 adds the mount and execve
  # families: the mount propagation on / (the granted dir:mounton
  # operation) and the following mount/execve stages are the startup
  # story between the ready byte and the next startup boundary.
  # 4C-40 adds the mkdir/mkdirat families: the copy-up setup's
  # os.MkdirTemp("/tmp", "rootlesskit-b*") is the next granted stage's
  # own operation — the trace records carry the pathname, which binds
  # the boundary to the MkdirTemp call (not to another /tmp access).
  # 4C-50 adds the READ-RET families (sys_exit_read, the readv pair) and
  # the close exit: the /etc/hosts read milestone needs the read(2)s'
  # OWN results (fd/bytes/EOF), not just the openat's fd; and the
  # readlinkat pair for the symlink-resolution window. 4C-52 adds the
  # fstat pair: the os.ReadFile fd-Stat's own getattr hook — the
  # canonical 4C-52 pre-correction run 37294649118 showed the getattr
  # decision INSIDE the openat-to-read gap with NO owning window (the
  # untraced fstat) falling to the anchor-relative STARTUP-CAUSAL class
  # and displacing the terminal removal-stage boundary; the owning
  # syscall must be traced so the machinery can attribute the decision.
  # No comm filters:
  # the event field
  # shapes vary by kernel and a wrong filter would silently drop the
  # evidence; the volume is bounded by the ring and post-filtered at the
  # harvest. Each enable is best-effort; the arm file records what the
  # kernel actually offered.
  for ev in sched/sched_process_fork sched/sched_process_exit \
            signal/signal_generate signal/signal_deliver \
            syscalls/sys_enter_kill syscalls/sys_exit_kill \
            syscalls/sys_enter_tkill syscalls/sys_exit_tkill \
            syscalls/sys_enter_tgkill syscalls/sys_exit_tgkill \
            syscalls/sys_enter_pidfd_send_signal syscalls/sys_exit_pidfd_send_signal \
            syscalls/sys_enter_wait4 syscalls/sys_exit_wait4 \
            syscalls/sys_enter_waitid syscalls/sys_exit_waitid \
            syscalls/sys_enter_poll syscalls/sys_exit_poll \
            syscalls/sys_enter_ppoll syscalls/sys_exit_ppoll \
            syscalls/sys_enter_select syscalls/sys_exit_select \
            syscalls/sys_enter_pselect6 syscalls/sys_exit_pselect6 \
            syscalls/sys_enter_read syscalls/sys_exit_read \
            syscalls/sys_enter_readv syscalls/sys_exit_readv \
            syscalls/sys_enter_write syscalls/sys_enter_close syscalls/sys_exit_close \
            syscalls/sys_enter_exit syscalls/sys_enter_exit_group \
            syscalls/sys_enter_mount syscalls/sys_exit_mount \
            syscalls/sys_enter_execve syscalls/sys_exit_execve \
            syscalls/sys_enter_mkdir syscalls/sys_exit_mkdir \
            syscalls/sys_enter_mkdirat syscalls/sys_exit_mkdirat \
            syscalls/sys_enter_umount2 syscalls/sys_exit_umount2 \
            syscalls/sys_enter_umount syscalls/sys_exit_umount \
            syscalls/sys_enter_rename syscalls/sys_exit_rename \
            syscalls/sys_enter_getdents64 syscalls/sys_exit_getdents64 \
            syscalls/sys_enter_openat2 syscalls/sys_exit_openat2 \
            syscalls/sys_enter_newfstatat syscalls/sys_exit_newfstatat \
            syscalls/sys_enter_statx syscalls/sys_exit_statx \
            syscalls/sys_enter_fstat syscalls/sys_exit_fstat \
            syscalls/sys_enter_unlink syscalls/sys_exit_unlink \
            syscalls/sys_enter_unlinkat syscalls/sys_exit_unlinkat \
            syscalls/sys_enter_rmdir syscalls/sys_exit_rmdir \
            syscalls/sys_enter_symlink syscalls/sys_exit_symlink \
            syscalls/sys_enter_symlinkat syscalls/sys_exit_symlinkat \
            syscalls/sys_enter_readlink syscalls/sys_exit_readlink \
            syscalls/sys_enter_readlinkat syscalls/sys_exit_readlinkat; do
    [ -d "$TRACING/events/$ev" ] && echo 1 > "$TRACING/events/$ev/enable" 2>/dev/null || true
  done
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
    echo "=== 4C-38 sched_process_exit tracepoint format (recorded verbatim) ==="
    cat "$TRACING/events/sched/sched_process_exit/format" 2>/dev/null || echo "(format file unavailable)"
    echo "=== 4C-38 signal_generate tracepoint format (recorded verbatim) ==="
    cat "$TRACING/events/signal/signal_generate/format" 2>/dev/null || echo "(format file unavailable)"
    echo "=== 4C-38 post-TUN instrumentation availability (recorded verbatim) ==="
    for ev in sched/sched_process_fork sched/sched_process_exit signal/signal_generate signal/signal_deliver \
              syscalls/sys_enter_kill syscalls/sys_enter_tkill syscalls/sys_enter_tgkill syscalls/sys_enter_pidfd_send_signal \
              syscalls/sys_enter_wait4 syscalls/sys_enter_waitid syscalls/sys_enter_poll syscalls/sys_enter_ppoll \
              syscalls/sys_enter_select syscalls/sys_enter_pselect6 syscalls/sys_exit_pselect6 \
              syscalls/sys_enter_read syscalls/sys_exit_read syscalls/sys_enter_readv syscalls/sys_exit_readv \
              syscalls/sys_enter_write syscalls/sys_enter_close syscalls/sys_exit_close \
              syscalls/sys_enter_exit syscalls/sys_enter_exit_group \
              syscalls/sys_enter_mount syscalls/sys_exit_mount syscalls/sys_enter_execve syscalls/sys_exit_execve \
              syscalls/sys_enter_mkdir syscalls/sys_exit_mkdir syscalls/sys_enter_mkdirat syscalls/sys_exit_mkdirat \
              syscalls/sys_enter_umount2 syscalls/sys_exit_umount2 syscalls/sys_enter_umount syscalls/sys_exit_umount \
              syscalls/sys_enter_rename syscalls/sys_exit_rename \
              syscalls/sys_enter_getdents64 syscalls/sys_exit_getdents64 \
              syscalls/sys_enter_openat2 syscalls/sys_exit_openat2 \
              syscalls/sys_enter_newfstatat syscalls/sys_exit_newfstatat \
              syscalls/sys_enter_statx syscalls/sys_exit_statx \
              syscalls/sys_enter_unlink syscalls/sys_exit_unlink \
              syscalls/sys_enter_unlinkat syscalls/sys_exit_unlinkat \
              syscalls/sys_enter_rmdir syscalls/sys_exit_rmdir \
              syscalls/sys_enter_symlink syscalls/sys_exit_symlink \
              syscalls/sys_enter_symlinkat syscalls/sys_exit_symlinkat \
              syscalls/sys_enter_readlink syscalls/sys_exit_readlink \
              syscalls/sys_enter_readlinkat syscalls/sys_exit_readlinkat; do
      echo "$ev: $([ -d "$TRACING/events/$ev" ] && echo yes || echo no)"
    done
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
  # Label sampling, batched: ONE stat call per group per iteration. The
  # sampler's iteration cost is the catch-rate ceiling: the 4C-15 flow
  # window shrank to ~45ms and a per-path stat loop (one fork per path)
  # fit only ONE iteration inside such a window — the parent's stat ran
  # before the tree existed while the children's ran after, so the parent
  # was never observed and the provisioning gate false-failed on a pure
  # observation race (run 36754289051). Batching turns an iteration into
  # a single fork, so every path is sampled repeatedly inside any >=10ms
  # window. The first/last/all observation semantics are unchanged.
  #
  # Each observation is written ATOMICALLY and only when it changes: the
  # parent kills this subshell once the 10s evidence grace expires (a
  # live canonical leg never converges), and a SIGTERM landing between a
  # printf's redirection truncation and its write used to leave a
  # zero-byte observation file behind — the provisioning gate then
  # false-failed on the empty sample while every other observation of
  # the same window was intact (run 37040610571: only
  # container.state-root-container, the first full-overwrite printf of
  # the iteration, was truncated). A killed subshell can now only leave
  # a complete file, and the steady-state iteration cost stays at the
  # batched two stat forks.
  declare -A OBSERVED=()
  observe() { # kind label ctx — atomic write, on change only
    [ "${OBSERVED[$1.$2]:-}" = "$3" ] && return 0
    if printf '%s\n' "$3" > "$EVIDENCE_DIR/.write-$1-$2" \
       && mv -f "$EVIDENCE_DIR/.write-$1-$2" "$EVIDENCE_DIR/$1.$2"; then
      OBSERVED[$1.$2]="$3"
    fi
    return 0
  }
  sample_ops() {
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
        observe last "$label" "$ctx"
        grep -aqx "$ctx" "$EVIDENCE_DIR/all.$label" 2>/dev/null || printf '%s\n' "$ctx" >> "$EVIDENCE_DIR/all.$label"
      fi
    done < <(stat -c '%n %C' "$ST_OP_DIR" "$ST_OP_DIR/root" "$ST_OP_DIR/rootlesskit-state" "$RT_OP_DIR" 2>/dev/null || true)
    return 0
  }
  sample_containers() {
    while IFS= read -r line; do
      path="${line%% *}"; ctx="${line#* }"
      case "$path" in
        "$STATE_ROOT") label=state-root-container ;;
        "$STATE_ROOT/ops") label=state-ops-container ;;
        "$RUNTIME_ROOT") label=runtime-root-container ;;
        "$RUNTIME_ROOT/ops") label=runtime-ops-container ;;
        *) continue ;;
      esac
      [ -n "$ctx" ] && observe container "$label" "$ctx"
    done < <(stat -c '%n %C' "$STATE_ROOT" "$STATE_ROOT/ops" "$RUNTIME_ROOT" "$RUNTIME_ROOT/ops" 2>/dev/null || true)
    return 0
  }
  sample_containers
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
    sample_ops
    sample_containers
    if [ -n "$seen_pid" ] && [ ! -d "/proc/$seen_pid" ] && [ ! -d "$RT_OP_DIR" ] && [ ! -d "$ST_OP_DIR" ]; then
      printf 'CONVERGED %s\n' "$(date +%s.%N)" >> "$EVIDENCE_DIR/05-flow-context.txt"
      break
    fi
    sleep 0.002
  done
  touch /tmp/p4b-work/sampler.done
) &
SAMPLER_PID=$!

# ---- 4C-38: the post-TUN lifetime observer. Armed BEFORE the START so
# the flow's TUN attach and its first death both fall inside the
# observation span; the timeline needs no replay. The scan is FORKLESS
# (reads only): it walks /proc once per tick (~20ms cadence, 12s cap)
# and records every flow-domain member — pid, stat exit state, ppid
# (parentage), SELinux context, user/net namespace inodes, tap0
# presence. Zombie state (Z), vanished entries and ns-(none)
# transitions bound the deaths between ticks; the exact timestamps come
# from the kernel trace (sched_process_exit). Read-only observation:
# the observer must not change the timing it measures. The flow-domain
# comm set is the lifetime subject (the payload's own `ip` setup ran
# before the attach and is not part of it).
(
  set +e
  declare -A FDSEEN=()
  obs_end=$(( $(date +%s) + 12 ))
  # The 4C-49 confinement-gate identities (recorded once, before the
  # START): the manager-side mount-namespace inodes — the holder's ns/mnt
  # must DIFFER from each of them (gate item B): the harness subshell
  # (this observer's own process), the init process, and the manager
  # daemon (the flow's own parent chain root).
  printf '%s MGR-IDENTITY pid=%s ctx=%s ns/mnt=%s ns/user=%s ns/net=%s\n' \
    "$(date +%s.%N)" "$$" "$(tr -d '\0' < /proc/self/attr/current 2>/dev/null || echo none)" \
    "$(readlink /proc/self/ns/mnt 2>/dev/null || echo none)" \
    "$(readlink /proc/self/ns/user 2>/dev/null || echo none)" \
    "$(readlink /proc/self/ns/net 2>/dev/null || echo none)"
  printf '%s MGR-IDENTITY-INIT pid=1 ctx=%s ns/mnt=%s\n' \
    "$(date +%s.%N)" "$(tr -d '\0' < /proc/1/attr/current 2>/dev/null || echo none)" \
    "$(readlink /proc/1/ns/mnt 2>/dev/null || echo none)"
  printf '%s MGR-IDENTITY-DAEMON pid=%s ctx=%s ns/mnt=%s ns/user=%s\n' \
    "$(date +%s.%N)" "${MG_PID:-none}" \
    "$(tr -d '\0' < "/proc/$MG_PID/attr/current" 2>/dev/null || echo none)" \
    "$(readlink "/proc/$MG_PID/ns/mnt" 2>/dev/null || echo none)" \
    "$(readlink "/proc/$MG_PID/ns/user" 2>/dev/null || echo none)"
  while [ "$(date +%s)" -lt "$obs_end" ]; do
    TS="$(date +%s.%N)"
    for P in /proc/[0-9]*; do
      LC=""
      IFS= read -r LC 2>/dev/null < "$P/comm" || true
      case "$LC" in
        rootlesskit|slirp4netns|buildkitd|newuidmap|newgidmap|exe) ;;
        *) continue ;;
      esac
      PID="${P#/proc/}"
      S1=""; S2=""; S3=""; S4=""; SREST=""
      IFS=" " read -r S1 S2 S3 S4 SREST 2>/dev/null < "$P/stat" || true
      LCTX="$(tr -d '\0' < "$P/attr/current" 2>/dev/null || true)"
      LNSU="$(readlink "$P/ns/user" 2>/dev/null || true)"
      LNSN="$(readlink "$P/ns/net" 2>/dev/null || true)"
      LNSM="$(readlink "$P/ns/mnt" 2>/dev/null || true)"
      # The process start time (field 22 of /proc/<pid>/stat — the field
      # AFTER the comm field's closing paren; the awk finds the
      # paren-SUFFIXED comm field and takes its 20th successor) — the
      # holder-identity fact for the 4C-49 confinement gate.
      LSTIME="$(awk '{ for (i = 1; i <= NF; i++) if ($i ~ /\)$/) { print $(i+20); break } }' "$P/stat" 2>/dev/null || true)"
      LTAP=""
      while IFS= read -r DEVLINE; do
        case "$DEVLINE" in *"tap0:"*) LTAP="$DEVLINE"; break ;; esac
      done 2>/dev/null < "$P/net/dev" || true
      if [ -n "$LTAP" ]; then TAPST="present:$LTAP"; else TAPST=absent; fi
      printf '%s pid=%s comm=%s state=%s ppid=%s ctx=%s ns/user=%s ns/net=%s ns/mnt=%s starttime=%s tap0=%s\n' \
        "$TS" "$PID" "$LC" "$S3" "$S4" "$LCTX" "${LNSU:-(none)}" "${LNSN:-(none)}" "${LNSM:-(none)}" "${LSTIME:-(none)}" "$TAPST"
      if [ -z "${FDSEEN[$PID]:-}" ]; then
        FDSEEN[$PID]=1
        for F in "$P"/fd/[0-9]*; do
          FLT="$(readlink "$F" 2>/dev/null || true)"
          [ -n "$FLT" ] && printf '%s FD-SNAPSHOT pid=%s fd=%s -> %s\n' "$TS" "$PID" "${F##*/}" "$FLT"
        done
      fi
    done
    printf '%s TICK-END\n' "$TS"
    sleep 0.02
  done
) > "$EVIDENCE_DIR/50-posttun-timeline.txt" 2>&1 &
POSTTUN_OBSERVER_PID=$!
log "D: 4C-38 post-TUN lifetime observer armed (pid $POSTTUN_OBSERVER_PID)"

# ---- 4C-49: the confinement-gate watcher. The post-TUN observer's
# ---- observed cadence is ~90ms (its per-pid fork volume dominates the
# ---- 20ms sleep) — the canonical 4C-48 run PROVED it can miss the
# ---- mount-dancing holder entirely (the holder exe-3676 lived 47.5ms
# ---- and appears in zero timeline lines). The gate needs the holder's
# ---- mount-namespace inode and its mountinfo DURING the mount dance,
# ---- so this watcher scans /proc FORKLESS at a ~2-4ms cadence (builtin
# ---- reads only; the fifo-clock read -t paces without a fork; the
# ---- expensive ns/mnt and mountinfo probes run only for the few
# ---- flow-domain pids) and records:
# ----   GATE-HOLDER-FIRST  the first-seen identity of every flow-domain
# ----                      pid (pid, comm, ppid, ctx, ns/mnt, ns/user,
# ----                      starttime — the gate's holder identity facts);
# ----   GATE-NSMNT         each DISTINCT ns/mnt value of a tracked pid
# ----                      (the unshare transition — the new mount
# ----                      namespace's creation is live-proven here);
# ----   GATE-MOUNTINFO     each DISTINCT mountinfo content of a tracked
# ----                      rootlesskit_t pid (best-effort: the dance's
# ----                      own mount stack — bind0/tmpfs/rksys — and the
# ----                      propagation state, captured live before the
# ----                      holder dies).
# ---- The watcher self-terminates (12s cap; early break once a
# ---- flow-domain pid has been seen and none remains for 10 ticks).
# ---- Read-only observation: it changes no flow authority.
mkfifo /tmp/p4b-work/.gate-clock 2>/dev/null || true
(
  set +eu
  exec 9<>"/tmp/p4b-work/.gate-clock" 2>/dev/null || exit 1
  declare -A GSEEN=() GNSM=() GMI=() GCOMM=() GSTIME=() GCTX=()
  G_END=$(( EPOCHSECONDS + 12 ))
  G_GONE=0
  G_NSCHECK=0
  G_LASTPID=0
  G_FULLTICK=39
  GIDENTQ=""
  # The per-pid discovery body, shared by both scan tiers. For an
  # unseen pid: one builtin comm read, the flow-comm match (the alive
  # count happens at the match, before the identity pass — the current
  # semantics), then the identity pass and the GATE-HOLDER-FIRST
  # record. A pid whose identity pass skips (a flow-comm pid with a
  # non-flow ctx — e.g. the runner's own buildkitd) stays unseen and
  # unrecorded; it still counts alive at its own discovery ticks.
  #
  # The canonical run 37326112431 reproduced the discovery stall: the
  # identity pass was one awk + a forked readlink per discovered pid
  # (~2 forks, ~30-60ms each under the launch-window fork storm), so a
  # four-pid discovery burst stretched the tick to ~250ms and the whole
  # mount dance (born ~.66, dead ~.83 on the watcher clock) finished
  # inside one stall gap — the dance pid died before the watcher ever
  # probed it alive (gate items A/B = 0, the phase BLOCKED although the
  # dance itself was clean). The discovery is now fork-free (comm/ctx/
  # stat are builtin reads; the ns identities are queued): the record
  # is emitted the instant the pid matches, the queued ns probe drains
  # the whole queue with ONE readlink fork per tick.
  g_flow_pid() {
    GPID="${1#/proc/}"
    if [ -n "${GSEEN[$GPID]:-}" ]; then
      return 0
    fi
    GLC=""
    IFS= read -r GLC 2>/dev/null < "/proc/$GPID/comm" || return 0
    case "$GLC" in
      rootlesskit|exe|slirp4netns|buildkitd|newuidmap|newgidmap) ;;
      *) return 0 ;;
    esac
    G_ALIVE=$(( G_ALIVE + 1 ))
    GCTXV=""
    IFS= read -r GCTXV 2>/dev/null < "/proc/$GPID/attr/current" || true
    case "$GCTXV" in
      *docker_helper_rootlesskit_t:*|*docker_helper_slirp4netns_t:*) ;;
      *) return 0 ;;
    esac
    GST=""
    IFS= read -r GST 2>/dev/null < "/proc/$GPID/stat" || true
    GSTV="(none)"; GPP="(none)"; GSTART="(none)"
    case "$GST" in
      *") "*)
        GBODY="${GST#*) }"
        # After "pid (comm) " the stat fields shift: state=1, ppid=2,
        # starttime=20 (kernel stat fields 3/4/22).
        set -- $GBODY
        GSTV="${1:-"(none)"}"; GPP="${2:-"(none)"}"; GSTART="${20:-"(none)"}"
        ;;
    esac
    GSEEN[$GPID]=1
    GCOMM[$GPID]="$GLC"
    GSTIME[$GPID]="$GSTART"
    GCTX[$GPID]="$GCTXV"
    GNSM[$GPID]=""
    GMI[$GPID]=""
    GIDENTQ="$GIDENTQ$GPID "
    printf '%s GATE-HOLDER-FIRST pid=%s comm=%s state=%s ppid=%s ctx=%s ns/mnt=pending ns/user=pending starttime=%s\n' \
      "$GTS" "$GPID" "$GLC" "$GSTV" "$GPP" "$GCTXV" "${GSTART:-(none)}"
    # The 4C-52 correction: the discovery moment IS a tick observation
    # (the pid was alive and fully identified the instant this record
    # was built). The canonical run 37307909383 showed a mount-dancing
    # pid whose whole lifetime fell between two watcher ticks: the gate
    # never recorded a GATE-TICK for it, so its recorded mount-ns
    # identity (the gate items A/B input) came out empty. Emitting the
    # GATE-TICK here keeps the recorded ns/mnt list honest for exactly
    # such single-sighting pids; the tracked-pids pass continues to
    # emit its own GATE-TICKs for the pids that survive the next tick.
    printf '%s GATE-TICK pid=%s comm=%s ns/mnt=%s starttime=%s\n' \
      "$GTS" "$GPID" "$GLC" "${GNSM[$GPID]:-(none)}" "${GSTART:-(none)}"
  }
  while :; do
    GTS="$EPOCHREALTIME"
    G_ALIVE=0
    G_FULLTICK=$(( G_FULLTICK + 1 ))
    G_DO_FULL=0
    if [ "$G_FULLTICK" -ge 40 ]; then
      G_FULLTICK=0
      G_DO_FULL=1
    fi
    # The 4C-52 correction — the incremental discovery tier. The
    # canonical 4C-52 pre-correction run 37294649118 showed the full
    # /proc glob scan itself taking ~35-90ms per tick — the same
    # magnitude as the mount-dancing pid's whole lifetime (~45ms) — and
    # the dance pid's birth-to-death fell entirely between two glob
    # expansions (the gate never recorded the dance pid: items A/B/C =
    # 0, the phase BLOCKED/CONFINEMENT-NOT-PROVEN although the mount
    # pairs themselves were clean). The corrected discovery: ONE
    # fork-free ns_last_pid read per tick, then the comm reads ONLY for
    # the pids born since the last tick — the flow children are forked
    # fresh (their birth comm is the parent's own flow comm), so the
    # incremental tier catches each dance pid AT THE FORK with the
    # born-fresh namespace identity. The full-scan retry tier (every
    # 40th tick) keeps the launcher re-exec discovery (the comm changes
    # docker-helper -> rootlesskit in place on an already-scanned pid —
    # the retry semantics the full scan existed for) and resets the
    # vacancy counter for any long-lived flow-comm pid the identity
    # pass skips. The tracked-pids pass below keeps every seen pid's
    # tick record and mountinfo capture at the incremental cadence.
    GLASTNEW=""
    IFS= read -r GLASTNEW 2>/dev/null < /proc/sys/kernel/ns_last_pid || true
    case "$GLASTNEW" in
      ''|*[!0-9]*) GLASTNEW="" ;;
    esac
    if [ -n "$GLASTNEW" ] && [ "$GLASTNEW" -ge "$G_LASTPID" ]; then
      if [ "$G_LASTPID" -gt 0 ]; then
        for (( GPID = G_LASTPID + 1; GPID <= GLASTNEW; GPID++ )); do
          g_flow_pid "/proc/$GPID"
        done
      fi
      G_LASTPID="$GLASTNEW"
    else
      G_LASTPID=0
      G_DO_FULL=1
    fi
    if [ "$G_DO_FULL" = 1 ]; then
      for GPC in /proc/[0-9]*; do
        g_flow_pid "$GPC"
      done
    fi
    # The queued ns-identity probe: ONE readlink fork per tick drains
    # the whole discovery queue (mnt+user pairs per live pid). The
    # alignment guard: dead pids are purged before the fork (a builtin
    # comm test), and if the fork's line count still misses the operand
    # count (a pid died inside the fork window), the queue is retried
    # next tick and the purge eventually drops the dead ones.
    if [ -n "${GIDENTQ:-}" ]; then
      GQNEW=""
      for GQ in $GIDENTQ; do
        if [ -r "/proc/$GQ/comm" ]; then
          GQNEW="$GQNEW$GQ "
        fi
      done
      GIDENTQ="${GQNEW% }"
      if [ -n "$GIDENTQ" ]; then
        GQARGS=()
        for GQ in $GIDENTQ; do
          GQARGS+=("/proc/$GQ/ns/mnt" "/proc/$GQ/ns/user")
        done
        GQOUT="$(readlink "${GQARGS[@]}" 2>/dev/null || true)"
        GQEXP=$(( ${#GQARGS[@]} ))
        GQN="$(printf '%s\n' "$GQOUT" | grep -ac . || true)"
        if [ "$GQN" -eq "$GQEXP" ]; then
          # One output line per argument, in argument order (verified
          # locally: GNU readlink prints the targets in operand order and
          # skips failed operands entirely). The pairing into mnt+user
          # comes from the ARGUMENT ORDER, not from pairing the lines.
          GQI=0
          while IFS= read -r GQLINE; do
            GQI=$(( GQI + 1 ))
            GQP="${GQARGS[$(( GQI - 1 ))]}"
            GQP="${GQP#/proc/}"; GQP="${GQP%/ns/mnt}"; GQP="${GQP%/ns/user}"
            if [ $(( GQI % 2 )) -eq 1 ]; then
              GNSM[$GQP]="$GQLINE"
            else
              printf '%s GATE-HOLDER-IDENT pid=%s ns/mnt=%s ns/user=%s\n' \
                "$GTS" "$GQP" "${GNSM[$GQP]:-(none)}" "$GQLINE"
            fi
          done <<< "$GQOUT"
          GIDENTQ=""
        fi
      fi
    fi
    # The tracked-pids pass: the aliveness (the comm file's readability
    # bounds the death between ticks), the tick record, and the
    # mountinfo change capture for the rootlesskit_t pids.
    for GPID in "${!GSEEN[@]}"; do
      if [ -r "/proc/$GPID/comm" ]; then
        G_ALIVE=$(( G_ALIVE + 1 ))
        printf '%s GATE-TICK pid=%s comm=%s ns/mnt=%s starttime=%s\n' \
          "$GTS" "$GPID" "${GCOMM[$GPID]}" "${GNSM[$GPID]}" "${GSTIME[$GPID]}"
        case "${GCTX[$GPID]:-}" in
          *docker_helper_rootlesskit_t:*)
            GMINFO=""
            IFS= read -r -d '' GMINFO < "/proc/$GPID/mountinfo" 2>/dev/null || true
            if [ -n "$GMINFO" ] && [ "$GMINFO" != "${GMI[$GPID]:-}" ]; then
              GMI[$GPID]="$GMINFO"
              printf '%s GATE-MOUNTINFO pid=%s lines=%s\n' "$GTS" "$GPID" \
                "$(printf '%s\n' "$GMINFO" | grep -ac . || true)"
              printf '%s\n' "$GMINFO" | sed 's/^/    GATE-MOUNTINFO-LINE /'
            fi
            ;;
        esac
      fi
    done
    # The defensive ns/mnt re-check (~once per second of ticks): the
    # flow namespaces are born fresh and never transitioned in any
    # recorded run; the re-check keeps the GATE-NSMNT transition record
    # live for the general case without paying its readlink fork every
    # tick. Batched: one readlink fork covers every tracked pid.
    G_NSCHECK=$(( G_NSCHECK + 1 ))
    if [ "$G_NSCHECK" -ge 250 ] && [ "${#GSEEN[@]}" -gt 0 ]; then
      G_NSCHECK=0
      GNARGS=()
      for GPID in "${!GSEEN[@]}"; do
        GNARGS+=("/proc/$GPID/ns/mnt")
      done
      GNOUT="$(readlink "${GNARGS[@]}" 2>/dev/null || true)"
      GNN="$(printf '%s\n' "$GNOUT" | grep -ac . || true)"
      if [ "$GNN" -eq "${#GNARGS[@]}" ]; then
        GNI=0
        while IFS= read -r GNL; do
          GNP="${GNARGS[$GNI]}"; GNP="${GNP#/proc/}"; GNP="${GNP%/ns/mnt}"
          GNI=$(( GNI + 1 ))
          if [ "${GNSM[$GNP]:-}" != "$GNL" ]; then
            printf '%s GATE-NSMNT pid=%s ns/mnt=%s (was %s)\n' \
              "$GTS" "$GNP" "$GNL" "${GNSM[$GNP]:-none}"
            GNSM[$GNP]="$GNL"
          fi
        done <<< "$GNOUT"
      fi
    fi
    if [ "$G_ALIVE" -gt 0 ]; then
      G_GONE=0
    elif [ "${#GSEEN[@]}" -gt 0 ]; then
      G_GONE=$(( G_GONE + 1 ))
      if [ "$G_GONE" -ge 150 ]; then
        printf '%s GATE-WATCHER-END reason=flow-domain-vacant\n' "$EPOCHREALTIME"
        break
      fi
    fi
    read -t 0.0005 -u 9 _ 2>/dev/null || :
    if [ "$EPOCHSECONDS" -ge "$G_END" ]; then
      printf '%s GATE-WATCHER-END reason=time-cap\n' "$EPOCHREALTIME"
      break
    fi
  done
) > "$EVIDENCE_DIR/51-confinement-gate.txt" 2>&1 &
GATE_WATCHER_PID=$!
log "D: 4C-49 confinement-gate watcher armed (pid $GATE_WATCHER_PID)"

# ---- 4C-49 confinement gate: the host-side mount table BEFORE the
# ---- window (the init process and the harness's own namespace; both
# ---- host-side references for the untouched-host-table proof — item G;
# ---- the AFTER copy is taken at harvest).
{
  echo "=== the host-side mount table BEFORE the window (the 4C-49 confinement gate's untouched-host-table reference) ==="
  echo "--- /proc/1/mountinfo"
  cat /proc/1/mountinfo 2>/dev/null || true
  echo "--- /proc/self/mountinfo (the harness's own namespace)"
  cat /proc/self/mountinfo 2>/dev/null || true
} > "$EVIDENCE_DIR/55-host-mountinfo-before.txt" 2>&1

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
  # 4C-38 clock references, read BEFORE the ring dump: the trace's global
  # clock is mapped to wallclock at this instant (the T0 derivation and
  # the denial classification both ride on this mapping; the ring's own
  # newest event validates the drift in the verdict).
  POSTTUN_READ_EPOCH="$(date +%s.%N)"
  POSTTUN_READ_UPTIME="$(cut -d' ' -f1 /proc/uptime 2>/dev/null || true)"
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
  # 4C-38: the lifetime/readiness instrumentation is disabled with the
  # window's own set, so the later windows re-arm from a clean state.
  for ev in sched/sched_process_fork sched/sched_process_exit \
            signal/signal_generate signal/signal_deliver \
            syscalls/sys_enter_kill syscalls/sys_exit_kill \
            syscalls/sys_enter_tkill syscalls/sys_exit_tkill \
            syscalls/sys_enter_tgkill syscalls/sys_exit_tgkill \
            syscalls/sys_enter_pidfd_send_signal syscalls/sys_exit_pidfd_send_signal \
            syscalls/sys_enter_wait4 syscalls/sys_exit_wait4 \
            syscalls/sys_enter_waitid syscalls/sys_exit_waitid \
            syscalls/sys_enter_poll syscalls/sys_exit_poll \
            syscalls/sys_enter_ppoll syscalls/sys_exit_ppoll \
            syscalls/sys_enter_select syscalls/sys_exit_select \
            syscalls/sys_enter_pselect6 syscalls/sys_exit_pselect6 \
            syscalls/sys_enter_read syscalls/sys_exit_read \
            syscalls/sys_enter_readv syscalls/sys_exit_readv \
            syscalls/sys_enter_write syscalls/sys_enter_close syscalls/sys_exit_close \
            syscalls/sys_enter_exit syscalls/sys_enter_exit_group \
            syscalls/sys_enter_mount syscalls/sys_exit_mount \
            syscalls/sys_enter_execve syscalls/sys_exit_execve \
            syscalls/sys_enter_mkdir syscalls/sys_exit_mkdir \
            syscalls/sys_enter_mkdirat syscalls/sys_exit_mkdirat \
            syscalls/sys_enter_umount2 syscalls/sys_exit_umount2 \
            syscalls/sys_enter_umount syscalls/sys_exit_umount \
            syscalls/sys_enter_rename syscalls/sys_exit_rename \
            syscalls/sys_enter_getdents64 syscalls/sys_exit_getdents64 \
            syscalls/sys_enter_openat2 syscalls/sys_exit_openat2 \
            syscalls/sys_enter_newfstatat syscalls/sys_exit_newfstatat \
            syscalls/sys_enter_statx syscalls/sys_exit_statx \
            syscalls/sys_enter_fstat syscalls/sys_exit_fstat \
            syscalls/sys_enter_unlink syscalls/sys_exit_unlink \
            syscalls/sys_enter_unlinkat syscalls/sys_exit_unlinkat \
            syscalls/sys_enter_rmdir syscalls/sys_exit_rmdir \
            syscalls/sys_enter_symlink syscalls/sys_exit_symlink \
            syscalls/sys_enter_symlinkat syscalls/sys_exit_symlinkat \
            syscalls/sys_enter_readlink syscalls/sys_exit_readlink \
            syscalls/sys_enter_readlinkat syscalls/sys_exit_readlinkat; do
    echo 0 > "$TRACING/events/$ev/enable" 2>/dev/null || true
  done
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

# ---- 4C-38: the POST-TUN-T0 anchor, derived from the kernel trace's
# ---- own attach record: the helper's TUNSETIFF (0x400454ca) enter whose
# ---- same-pid ioctl exit returned 0x0, mapped to wallclock through the
# ---- clock references read at the harvest. The helper's `ip` setup also
# ---- issues 0x400454ca (creating the tap), so the pairing is restricted
# ---- to the slirp4netns comm — the attach executor IS the lifetime
# ---- subject. The shape reuses the 4C-37 verdict's same-pid pairing.
POSTTUN_ATTACH_PAIR="$(awk '
  /slirp4netns-/ && /sys_ioctl\(/ && /cmd: 0x400454ca/ {
    if (entered == 0) { entered = 1; enter_line = $0; vpid = substr($1, index($1, "-") + 1); next }
  }
  entered && /slirp4netns-/ && substr($1, length($1) - length(vpid) + 1) == vpid && /sys_ioctl ->/ {
    print enter_line; print $0; exit
  }
' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
POSTTUN_T0_TRACE_TS="$(printf '%s\n' "$POSTTUN_ATTACH_PAIR" | head -1 | awk '{ ts = $4; sub(/:$/, "", ts); print ts }' 2>/dev/null || true)"
POSTTUN_ATTACH_WHO="$(printf '%s\n' "$POSTTUN_ATTACH_PAIR" | head -1 | awk '{print $1}' 2>/dev/null || true)"
POSTTUN_ATTACH_RET="$(printf '%s\n' "$POSTTUN_ATTACH_PAIR" | tail -1 | awk '{print $NF}' 2>/dev/null || true)"
POSTTUN_T0_EPOCH="$(awk -v e="$POSTTUN_READ_EPOCH" -v u="$POSTTUN_READ_UPTIME" -v t="$POSTTUN_T0_TRACE_TS" 'BEGIN { if (e != "" && u != "" && t != "") printf "%.3f", e - (u - t) }' 2>/dev/null || true)"
POSTTUN_RING_LAST_TS="$(grep -a '[^[:space:]]' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | tail -1 | awk '{ ts = $4; sub(/:$/, "", ts); print ts }' 2>/dev/null || true)"
POSTTUN_CLOCK_DRIFT="$(awk -v u="$POSTTUN_READ_UPTIME" -v l="$POSTTUN_RING_LAST_TS" 'BEGIN { if (u != "" && l != "") printf "%.3f", u - l }' 2>/dev/null || true)"
if [ -n "$POSTTUN_T0_EPOCH" ] && [ "$POSTTUN_ATTACH_RET" = "0x0" ]; then
  marker "POST-TUN-T0=$POSTTUN_T0_EPOCH (trace-ts=$POSTTUN_T0_TRACE_TS attach=$POSTTUN_ATTACH_WHO ret=$POSTTUN_ATTACH_RET read-uptime=$POSTTUN_READ_UPTIME ring-last-ts=$POSTTUN_RING_LAST_TS clock-drift=$POSTTUN_CLOCK_DRIFT)"
else
  marker "POST-TUN-T0=NOT_OBSERVED (attach pair ${POSTTUN_ATTACH_PAIR:+present but ret=$POSTTUN_ATTACH_RET}${POSTTUN_ATTACH_PAIR:-(absent — the attach pair never recorded)})"
fi

# ---- manager context AFTER the launch attempt: captured immediately,
# ---- before any gate branching, so an early-stopped leg still carries
# ---- the manager-context evidence (R1/R2 lost it twice this way).
MGR_AFTER="$(process_context "$MG_PID")"
echo "$MGR_AFTER" > "$EVIDENCE_DIR/07-manager-after.txt"


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
# leg against its own holder and the attack leg against operation A's
# attached helper (the live member of A's netns), delivered inside the
# vehicle's own binary tail (read via the helper's existing entry-file
# authority).
# Lifecycle noise (the retained-flow signull/sigkill/signal denials of
# 4C-36) is inventoried separately and never gates this phase.
marker "CROSS-OP: isolation proof window start"
CROSS_T0="$(date +%s)"
# Attack-target binding: a LIVE member of operation A that holds the
# netns and its attached tap0. The composition's flow lifetime is far
# below a minute — the payload's readiness never completes and the whole
# flow tree is gone within seconds of the attach (the holder pid in run
# 37042643830, the attached helper in run 37044797662: both already gone
# at their binding times), so the binding reads the LIVE SYSTEM, not a
# remembered pid: every live member of the canonical op's flow domains
# carrying operation A's own category (c1) is inventoried (pid, comm,
# namespace inodes, label, tap0), and the binding takes the FIRST member
# that holds tap0 in its own netns — the attached-helper shape. The scan
# is forkless (plain bash reads) so it lands inside the flow's own short
# alive window; the trace-derived attached-helper pid is the independent
# cross-check, recorded here and compared in the verdict against the
# already-harvested ring.
CROSS_TRACE_PID="$(awk '
  $1 ~ /^slirp4netns-/ {
    n = split($1, seg, "-"); pid = seg[n]
    if (/sys_ioctl\(/ && /cmd: 0x400454ca/) { pend[pid] = 1; next }
    if (/sys_ioctl ->/ && pend[pid] && $NF == "0x0") { print pid; pend[pid] = 0 }
    else if (/sys_ioctl ->/) { pend[pid] = 0 }
  }
' "$EVIDENCE_DIR/30-trace-relevant.txt" 2>/dev/null | tail -1 || true)"
CROSS_A_PID=""
{
  echo "=== 4C-37 A-side binding inventory (the attack target, bound from the live system) ==="
  echo "A operation:      $OP_ID (the canonical leg launched by the provisioning window just above)"
  echo "A trace helper:   ${CROSS_TRACE_PID:-(absent)} (the attached helper per the provisioning kernel trace)"
  for P in /proc/[0-9]*; do
    PID="${P#/proc/}"
    LCTX=""
    IFS= read -r LCTX 2>/dev/null < "$P/attr/current" || true
    case "$LCTX" in
      *":docker_helper_slirp4netns_t:s0:c1"|*":docker_helper_rootlesskit_t:s0:c1") ;;
      *) continue ;;
    esac
    LCOMM=""
    IFS= read -r LCOMM 2>/dev/null < "$P/comm" || true
    echo "A live member: pid=$PID comm=$LCOMM ctx=$LCTX"
    echo "  ns/user: $(readlink "$P/ns/user" 2>/dev/null || true)"
    echo "  ns/net:  $(readlink "$P/ns/net" 2>/dev/null || true)"
    LTAP=""
    while IFS= read -r DEVLINE; do
      case "$DEVLINE" in *"tap0:"*) LTAP="$DEVLINE"; break;; esac
    done 2>/dev/null < "$P/net/dev" || true
    echo "  tap0:    ${LTAP:-(absent)}"
    if [ -z "$CROSS_A_PID" ] && [ -n "$LTAP" ]; then
      CROSS_A_PID="$PID"
      echo "  binding: SELECTED (the first live c1 member holding tap0)"
    fi
  done
  if [ -n "$CROSS_A_PID" ]; then
    echo "A bound pid:      $CROSS_A_PID (the first live c1 member holding tap0)"
  else
    echo "A bound pid:      NONE (no live c1 member holds the attached tap0)"
  fi
} > /tmp/p4b-work/cross-a-inventory.txt
cat /tmp/p4b-work/cross-a-inventory.txt >&2
CROSS_PIDS_OK=1
case "$CROSS_A_PID" in ''|*[!0-9]*) CROSS_PIDS_OK=0;; esac
if [ "$CROSS_PIDS_OK" = 1 ] && [ ! -e "$TRANSFERRED/tun-cross-op-vehicle" ]; then
  note "the transferred cross-op vehicle binary is missing — the isolation proof cannot run"
  CROSS_PIDS_OK=0
fi
if [ "$CROSS_PIDS_OK" != 1 ]; then
  # The binding evidence travels to the evidence set so the marker's
  # pointer is resolvable; the phase cannot conclude — INCOMPLETE, not
  # PASS (an unstarted proof is an unfinished phase, never a pass).
  cp /tmp/p4b-work/cross-a-inventory.txt "$EVIDENCE_DIR/45-cross-op-isolation.txt" 2>/dev/null || true
  marker "CROSS-OPERATION-ISOLATION=NOT_PROVEN"
  marker "BLOCKER=the cross-op proof could not bind a live operation-A identity (see 45-cross-op-isolation.txt)"
  CROSS_NOT_PROVEN=1
  CROSS_WINDOW_DEAD=1
fi

# ---- the provisioning window's own audit/journal slices, harvested
# ---- BEFORE the cross window: the window's expected cross-category
# ---- denials must not reach the slices the staircase gates scan.
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

# Stage the vehicle inside /usr/bin and append the target line, then
# swap by rename (an alive helper holds the path's inode open). The
# helper reads the targets from its OWN installed binary via the
# existing entry-file read authority. The staging's own failures record
# NOT_PROVEN and skip the window's remainder; the phase's own gates
# below still run.
if [ "${CROSS_WINDOW_DEAD:-0}" = 0 ]; then
# The cross window owns its own restore baseline: the shipped binary's
# sha/type/mode captured BEFORE any staging touches the path. The probe
# windows run AFTER this window, so their PROBE_ORIG_* variables do not
# exist here (the unbound reference used to kill the guest at the
# restore check, run 37042643830). Every restore path below verifies
# against this record.
CROSS_ORIG_SHA="$(sha256sum /usr/bin/slirp4netns 2>/dev/null | awk '{print $1}')"
CROSS_ORIG_CTX="$(context_of /usr/bin/slirp4netns)"
CROSS_ORIG_MODE="$(stat -c '%a %U:%G' /usr/bin/slirp4netns 2>/dev/null)"
cp -p /usr/bin/slirp4netns /usr/bin/.cross-op-orig \
  || { note "the cross-op window could not back up the flow binary"
       marker "CROSS-OPERATION-ISOLATION=NOT_PROVEN"
       marker "BLOCKER=the cross-op window could not back up the flow binary (see 45-cross-op-isolation.txt)"
       CROSS_NOT_PROVEN=1; CROSS_WINDOW_DEAD=1; }
  cp "$TRANSFERRED/tun-cross-op-vehicle" /usr/bin/.cross-op-vehicle \
    || { note "the cross-op window could not stage the vehicle"
         marker "CROSS-OPERATION-ISOLATION=NOT_PROVEN"
         marker "BLOCKER=the cross-op window could not stage the vehicle (see 45-cross-op-isolation.txt)"
         CROSS_NOT_PROVEN=1; CROSS_WINDOW_DEAD=1; }
  printf 'CROSS-OP-TARGETS %s\n' "$CROSS_A_PID" >> /usr/bin/.cross-op-vehicle
  # The expected sha is the STAGED inode's (with the appended target line
  # — the 4C-37 vehicle reads its targets from its own binary tail).
  CROSS_EXPECTED_SHA="$(sha256sum /usr/bin/.cross-op-vehicle 2>/dev/null | awk '{print $1}')"
  mv /usr/bin/.cross-op-vehicle /usr/bin/slirp4netns \
    || { note "the cross-op window could not rename the vehicle into place"
         marker "CROSS-OPERATION-ISOLATION=NOT_PROVEN"
         marker "BLOCKER=the cross-op window could not rename the vehicle into place (see 45-cross-op-isolation.txt)"
         CROSS_NOT_PROVEN=1; CROSS_WINDOW_DEAD=1; }
  restorecon /usr/bin/slirp4netns 2>/dev/null || true
  CROSS_PLACED_SHA="$(sha256sum /usr/bin/slirp4netns 2>/dev/null | awk '{print $1}')"
  CROSS_PLACED_CTX="$(context_of /usr/bin/slirp4netns)"
  CROSS_PLACED_TYPE="$(printf '%s' "$CROSS_PLACED_CTX" | cut -d: -f3)"
  echo "placed vehicle sha256: $CROSS_PLACED_SHA (expected $CROSS_EXPECTED_SHA)"
  echo "placed vehicle label:  $CROSS_PLACED_CTX"
  if [ "$CROSS_PLACED_SHA" != "$CROSS_EXPECTED_SHA" ] || [ "$CROSS_PLACED_TYPE" != "docker_helper_slirp4netns_exec_t" ]; then
    note "the cross-op vehicle placement failed its byte/label check"
    # rename(2) atomically replaces the path's inode (an executed file
    # keeps running); a rm-then-rename would open an ENOENT window for a
    # concurrent exec instead.
    mv /usr/bin/.cross-op-orig /usr/bin/slirp4netns \
      || note "FAIL: the original binary could not be renamed back into the path"
    restorecon /usr/bin/slirp4netns 2>/dev/null || true
    # The failure path's restore is verified against the pre-staging
    # record: byte (sha256), SELinux type, and mode. A restore that did
    # not reproduce the original leaves a non-composition binary in the
    # flow path — that is a FAIL, not a silent NOT_PROVEN.
    CROSS_RESTORED_SHA="$(sha256sum /usr/bin/slirp4netns 2>/dev/null | awk '{print $1}')"
    CROSS_RESTORED_CTX="$(context_of /usr/bin/slirp4netns)"
    CROSS_RESTORED_TYPE="$(printf '%s' "$CROSS_RESTORED_CTX" | cut -d: -f3)"
    CROSS_ORIG_TYPE="$(printf '%s' "$CROSS_ORIG_CTX" | cut -d: -f3)"
    CROSS_RESTORED_MODE="$(stat -c '%a %U:%G' /usr/bin/slirp4netns 2>/dev/null)"
    echo "restored sha256: $CROSS_RESTORED_SHA (expected $CROSS_ORIG_SHA)"
    echo "restored type:   $CROSS_RESTORED_TYPE (expected $CROSS_ORIG_TYPE)"
    echo "restored mode:   $CROSS_RESTORED_MODE (expected $CROSS_ORIG_MODE)"
    marker "CROSS-OPERATION-ISOLATION=NOT_PROVEN"
    marker "BLOCKER=the cross-op vehicle placement failed (see 45-cross-op-isolation.txt)"
    CROSS_NOT_PROVEN=1
    if [ "$CROSS_RESTORED_SHA" = "$CROSS_ORIG_SHA" ] && [ "$CROSS_RESTORED_TYPE" = "$CROSS_ORIG_TYPE" ] && [ "$CROSS_RESTORED_MODE" = "$CROSS_ORIG_MODE" ]; then
      CROSS_WINDOW_DEAD=1
    else
      marker "BLOCKER=the cross-op placement failure left a non-original binary in the flow path (restore sha/type/mode mismatch)"
      finish FAIL; exit 0
    fi
  fi
fi
  if [ "${CROSS_WINDOW_DEAD:-0}" = 0 ]; then
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
  # AVC slice after the op tree is gone). The tree's absence alone is
  # the convergence: the instance.pid may be created and removed inside
  # the vehicle's own ~2s abort cycle, so requiring a read pid here used
  # to burn the full 75s cap (the launch-death path converges in ~2s).
  CROSS_PID=""
  CROSS_END=$(( $(date +%s) + 75 ))
  while [ "$(date +%s)" -lt "$CROSS_END" ]; do
    if [ -z "$CROSS_PID" ] && [ -s "$CROSS_RT_OP_DIR/instance.pid" ]; then
      CROSS_PID="$(cat "$CROSS_RT_OP_DIR/instance.pid" 2>/dev/null)"
    fi
    if [ ! -d "$CROSS_RT_OP_DIR" ] && [ ! -d "$CROSS_ST_OP_DIR" ]; then
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
    echo "identity bindings: A(attached-helper-pid)=$CROSS_A_PID vehicle-op=$CROSS_OP_ID instance-pid=${CROSS_PID:-(not observed)}"
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
    CROSS_RESTORED_CTX="$(context_of /usr/bin/slirp4netns)"
    CROSS_RESTORED_TYPE="$(printf '%s' "$CROSS_RESTORED_CTX" | cut -d: -f3)"
    CROSS_ORIG_TYPE="$(printf '%s' "$CROSS_ORIG_CTX" | cut -d: -f3)"
    echo "original sha256: $CROSS_ORIG_SHA"
    echo "restored sha256: $CROSS_RESTORED_SHA"
    echo "original ctx:    $CROSS_ORIG_CTX"
    echo "restored ctx:    $CROSS_RESTORED_CTX"
    echo "original mode:   $CROSS_ORIG_MODE"
    echo "restored mode:   $(stat -c '%a %U:%G' /usr/bin/slirp4netns 2>/dev/null)"
    # Byte- and TYPE-identical (run 37000093955 proved this system's
    # restorecon writes unconfined_u as the user part of the restored
    # label; the exec transition and the entry rule are type-based).
    if [ "$CROSS_RESTORED_SHA" = "$CROSS_ORIG_SHA" ] && [ "$CROSS_RESTORED_TYPE" = "$CROSS_ORIG_TYPE" ] && [ "$(stat -c '%a %U:%G' /usr/bin/slirp4netns 2>/dev/null)" = "$CROSS_ORIG_MODE" ]; then
      echo "PASS: the shipped flow binary is restored byte-, type-, and mode-identical (restored full ctx: $CROSS_RESTORED_CTX)"
    else
      echo "FAIL: the shipped flow binary did NOT restore byte/type/mode-identical — the composition integrity is broken"
    fi
  } > "$EVIDENCE_DIR/45-cross-op-isolation.txt" 2>&1
  cat "$EVIDENCE_DIR/45-cross-op-isolation.txt" >&2
  cp /tmp/p4b-work/cross-trace.txt "$EVIDENCE_DIR/47-cross-op-trace-raw.txt" 2>/dev/null || true
  cp /tmp/p4b-work/cross-avc-slice.txt "$EVIDENCE_DIR/48-cross-op-avc-raw.txt" 2>/dev/null || true
  grep -aq "PASS: the shipped flow binary is restored byte-, type-, and mode-identical" "$EVIDENCE_DIR/45-cross-op-isolation.txt" \
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
    echo "identity cross-check: trace attached-helper pid=${CROSS_TRACE_PID:-(absent)} / bound pid=${CROSS_A_PID:-(absent)}"
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
    CROSS_NOT_PROVEN=1
  fi
  fi


# ============================================================
# 4C-38..4C-44: the post-TUN lifetime/readiness causal proof
# ============================================================
# The provisioning window's own operation is the subject: its TUN attach
# is already proven (POST-TUN-T0 above; TUNSETIFF 0x54ca -> 0). This
# verdict reconstructs the causal chain between the attach and the
# operation's FIRST death from the kernel trace (fork/exit/signal/wait/
# poll/read-write-close/mount/mkdir/execve), the post-TUN timeline (50),
# the audit slice and the manager journal. The 4C-44 grant
# (rootlesskit_t -> etc_t:dir mounton) must have REMOVED the 4C-43
# boundary AND made the copy-up tmpfs mount (mount("none", "/etc",
# "tmpfs", 0)) succeed — the C milestone requires B ok AND C ok AND no
# etc_t:dir mounton denial (mounton-absence without a successful
# syscall is not a PASS); the 4C-43/4C-42/4C-41/4C-40/4C-39 grants must
# have stayed in effect (the old boundaries stay GONE — a regression is
# a phase failure); the run's own decisions are classified TEMPORALLY
# against the first failing SYSCALL exit (the 4C-42 report's
# correction: the RemoveAll cleanup-path denials of a failed launch sit
# AFTER the failing syscall but BEFORE the terminal exit, so the old
# exit-anchored classification mislabeled them STARTUP-CAUSAL; the
# kill-family syscalls are excluded from the anchor search — every
# observed kill denial is cleanup, never a startup blocker) with
# fallback to the first failing process exit when no failing
# syscall-exit is recorded; only the first STARTUP-CAUSAL denial may own
# the next semantic phase, and the phase STOPs there. A window with no
# nonzero flow-domain exit is the stable-lifetime outcome. The mkdirat
# success is the ROOTLESSKIT-BIND0-CREATE milestone; the successful
# MS_BIND|MS_REC mount("/etc" -> bind0) is the ROOTLESSKIT-BIND0-BIND-
# MOUNT milestone; the successful tmpfs mount over /etc is the
# ROOTLESSKIT-COPYUP-TMPFS-MOUNT milestone. Nothing is granted in this
# phase beyond the 4C-44 etc_t mounton rule itself.
# The flow-domain comm set is the lifetime subject (rootlesskit parent +
# child, slirp4netns parent + child, the uid-map shims, the payload).
POSTTUN_FLOW_COMM_GREP='(rootlesskit|exe|slirp4netns|buildkitd|newuidmap|newgidmap)-[0-9]+ '
# The awk-side comm shape ($1 has no trailing space; the grep-side
# pattern above cannot be reused there).
POSTTUN_FLOW_COMM_AWK='^(rootlesskit|exe|slirp4netns|buildkitd|newuidmap|newgidmap)-[0-9]+$'
# 4C-50 adds the readv/readlink/readlinkat families to the flow-domain
# extract: the /etc/hosts read stage's own records (the read results
# ride the sys_exit_read exits; readlink/readlinkat are the
# symlink-resolution window's own probes).
POSTTUN_TRACE_EVENT_GREP='sched_process_fork:|sched_process_exit:|signal_generate:|signal_deliver:|selinux_audited:|sys_(openat|setns|ioctl|kill|tkill|tgkill|pidfd_send_signal|wait4|waitid|poll|ppoll|select|pselect6|read|readv|write|close|exit|exit_group|mount|mkdir|mkdirat|execve|readlink|readlinkat)'

# The ordered flow-domain extract (the lifetime subject's own records;
# chronology-preserving; capped).
{
  echo "=== 4C-38 the flow-domain's ordered trace records (T0 and the first death are inside; the arm precedes the window) ==="
  grep -aE "$POSTTUN_FLOW_COMM_GREP" "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -aE "$POSTTUN_TRACE_EVENT_GREP" | head -600 || true
  echo "(end of the flow-domain's ordered trace records)"
} > "$EVIDENCE_DIR/51-posttun-trace.txt" 2>&1

# The denial records (both channels; the classification lives in the verdict).
{
  echo "=== 4C-38/4C-39 the window's SELinux decision records (every tclass) ==="
  echo "--- the kernel trace's selinux_audited records (the trace clock; the authoritative channel):"
  grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | head -200 || true
  echo "(end of the trace's SELinux decision records)"
  echo "--- the audit slice's SELinux records (wallclock epochs; may be empty — the measured userspace-audit gap):"
  grep -a 'type=AVC' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a 'denied' | head -60 || true
  echo "(end of the audit slice's records)"
} > "$EVIDENCE_DIR/52-posttun-denials.txt" 2>&1

POSTTUN_T0_OK=0
POSTTUN_RET0_OK=0
POSTTUN_DEATH_PID_OK=0
POSTTUN_DEATH_TS_OK=0
POSTTUN_DEATH_CAUSE=""
POSTTUN_DENIALS_CLASSIFIED=0
POSTTUN_BOUNDARY=""
POSTTUN_ESTABLISHED=0
POSTTUN_NOT_ESTABLISHED=0
POSTTUN_NSTARTUP=0; POSTTUN_NPOST=0; POSTTUN_NPOLL=0; POSTTUN_NUNTIMED=0
POSTTUN_OLD_BOUNDARY_PRESENT=0
POSTTUN_BND_SYMBOLIC=""
{
  echo "=== 4C-38..4C-53 post-TUN lifetime/readiness causal verdict (the 4C-53 run carries exactly the rootlesskit_t -> net_conf_t:file { read open } pair — the 4C-51 read widened in place by the 4C-52 open hook — beside the tmpfs_t:lnk_file { create read unlink } triple (the 4C-48 create + 4C-50 read widened in place by the 4C-53 unlink removal hook) and the cgroup_t:dir mounton grant; the confinement gate's PASS is this run's own re-proven precondition) ==="
  echo "POST-TUN-T0: ${POSTTUN_T0_EPOCH:-(not derived)}"
  echo "  derivation: trace-ts=$POSTTUN_T0_TRACE_TS attach-executor=${POSTTUN_ATTACH_WHO:-(none)} read-epoch=$POSTTUN_READ_EPOCH read-uptime=$POSTTUN_READ_UPTIME ring-last-ts=${POSTTUN_RING_LAST_TS:-(none)} clock-drift=${POSTTUN_CLOCK_DRIFT:-?}s"
  echo "--- the attach pair (the T0 anchor; the attach executor's own TUNSETIFF):"
  printf '%s\n' "${POSTTUN_ATTACH_PAIR:-(absent: the helper TUNSETIFF pair was never recorded)}"
  if [ -n "$POSTTUN_T0_EPOCH" ] && [ "$POSTTUN_ATTACH_RET" = "0x0" ]; then
    echo "GATE POST-TUN-T0 observed: PASS"
    echo "GATE TUNSETIFF ret == 0: PASS (ret=$POSTTUN_ATTACH_RET)"
    POSTTUN_T0_OK=1
    POSTTUN_RET0_OK=1
  else
    echo "GATE POST-TUN-T0 observed: FAIL (the attach pair or its ret 0 is not in the window's trace)"
    echo "GATE TUNSETIFF ret == 0: FAIL (ret=${POSTTUN_ATTACH_RET:-(none)})"
  fi

  # The first death: the first sched_process_exit of a flow-domain member
  # after T0 (the trace clock is monotonic within the ring).
  POSTTUN_FIRST_DEATH_LINE="$(grep -a 'sched_process_exit:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -aE "$POSTTUN_FLOW_COMM_GREP" \
    | awk -v t0="$POSTTUN_T0_TRACE_TS" '{ ts = $4; sub(/:$/, "", ts); if (t0 != "" && ts + 0 > t0 + 0) { print; exit } }' 2>/dev/null || true)"
  POSTTUN_FIRST_DEATH_PID="$(printf '%s\n' "$POSTTUN_FIRST_DEATH_LINE" | awk '{ pid = $1; sub(/ .*/, "", pid); sub(/^[^-]*-/, "", pid); print pid }' 2>/dev/null || true)"
  POSTTUN_FIRST_DEATH_COMM="$(printf '%s\n' "$POSTTUN_FIRST_DEATH_LINE" | awk '{ c = $1; sub(/ .*/, "", c); sub(/-[0-9]+$/, "", c); print c }' 2>/dev/null || true)"
  POSTTUN_FIRST_DEATH_TS="$(printf '%s\n' "$POSTTUN_FIRST_DEATH_LINE" | awk '{ ts = $4; sub(/:$/, "", ts); print ts }' 2>/dev/null || true)"
  POSTTUN_FIRST_DEATH_EPOCH="$(awk -v e="$POSTTUN_READ_EPOCH" -v u="$POSTTUN_READ_UPTIME" -v t="$POSTTUN_FIRST_DEATH_TS" 'BEGIN { if (e != "" && u != "" && t != "") printf "%.3f", e - (u - t) }' 2>/dev/null || true)"
  POSTTUN_T0_TO_DEATH="$(awk -v d="$POSTTUN_FIRST_DEATH_TS" -v t0="$POSTTUN_T0_TRACE_TS" 'BEGIN { if (d != "" && t0 != "") printf "%.3f", d - t0 }' 2>/dev/null || true)"
  echo "--- the first flow-domain death (the first sched_process_exit after T0):"
  printf '%s\n' "${POSTTUN_FIRST_DEATH_LINE:-(absent: no flow-domain member died inside the trace span of the window)}"
  if [ -n "$POSTTUN_FIRST_DEATH_PID" ]; then
    echo "first-death: pid=$POSTTUN_FIRST_DEATH_PID comm=$POSTTUN_FIRST_DEATH_COMM trace-ts=$POSTTUN_FIRST_DEATH_TS epoch=${POSTTUN_FIRST_DEATH_EPOCH:-(unmapped)} at=T0+${POSTTUN_T0_TO_DEATH:-?}s"
    POSTTUN_DEATH_PID_OK=1
    POSTTUN_DEATH_TS_OK=1
  else
    echo "first-death: NOT OBSERVED in the window's trace span"
  fi

  # The FIRST FAILING exit: the first flow-domain member whose exit_group
  # carried a NONZERO exit code after T0. The designed handoff exits
  # (exit_code 0: the slirp4netns sandbox child's tapfd handoff) are not
  # failures; the first nonzero exit IS the startup/readiness failure's
  # terminal boundary and the reference point for the denial classes.
  # Note the trace's syscall-enter records print as sys_exit_group(...) —
  # the event's printed shape is the syscall's own name, not the
  # tracepoint's directory name (sys_enter_exit_group never appears).
  POSTTUN_FIRST_FAIL_LINE="$(grep -a 'sys_exit_group(' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -aE "$POSTTUN_FLOW_COMM_GREP" \
    | grep -av 'error_code: 0)' \
    | awk -v t0="$POSTTUN_T0_TRACE_TS" '{ ts = $4; sub(/:$/, "", ts); if (t0 != "" && ts + 0 > t0 + 0) { print; exit } }' 2>/dev/null || true)"
  POSTTUN_FIRST_FAIL_EXIT_CODE="$(printf '%s\n' "$POSTTUN_FIRST_FAIL_LINE" | grep -aoE 'error_code: [0-9]+' | grep -aoE '[0-9]+' | head -1 || true)"
  POSTTUN_FIRST_FAIL_PID="$(printf '%s\n' "$POSTTUN_FIRST_FAIL_LINE" | awk '{ pid = $1; sub(/ .*/, "", pid); sub(/^[^-]*-/, "", pid); print pid }' 2>/dev/null || true)"
  POSTTUN_FIRST_FAIL_COMM="$(printf '%s\n' "$POSTTUN_FIRST_FAIL_LINE" | awk '{ c = $1; sub(/ .*/, "", c); sub(/-[0-9]+$/, "", c); print c }' 2>/dev/null || true)"
  POSTTUN_FIRST_FAIL_TS="$(printf '%s\n' "$POSTTUN_FIRST_FAIL_LINE" | awk '{ ts = $4; sub(/:$/, "", ts); print ts }' 2>/dev/null || true)"
  POSTTUN_FIRST_FAIL_EPOCH="$(awk -v e="$POSTTUN_READ_EPOCH" -v u="$POSTTUN_READ_UPTIME" -v t="$POSTTUN_FIRST_FAIL_TS" 'BEGIN { if (e != "" && u != "" && t != "") printf "%.3f", e - (u - t) }' 2>/dev/null || true)"
  POSTTUN_FAIL_EXIT_LINE="$(grep -a 'sched_process_exit:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -aE "$POSTTUN_FLOW_COMM_GREP" \
    | awk -v pf="$POSTTUN_FIRST_FAIL_PID" -v tf="$POSTTUN_FIRST_FAIL_TS" '{ ts = $4; sub(/:$/, "", ts); if (pf != "" && tf != "" && $1 ~ ("-" pf "$") && ts + 0 >= tf + 0) { print; exit } }' 2>/dev/null || true)"
  POSTTUN_T0_TO_FAIL="$(awk -v d="$POSTTUN_FIRST_FAIL_TS" -v t0="$POSTTUN_T0_TRACE_TS" 'BEGIN { if (d != "" && t0 != "") printf "%.3f", d - t0 }' 2>/dev/null || true)"
  echo "--- the first FAILING exit (the first nonzero exit_group of a flow-domain member after T0):"
  printf '%s\n' "${POSTTUN_FIRST_FAIL_LINE:-(absent: no flow-domain member exited nonzero inside the trace span of the window)}"
  printf '%s\n' "${POSTTUN_FAIL_EXIT_LINE:-(its sched_process_exit line: absent)}"
  if [ -n "$POSTTUN_FIRST_FAIL_PID" ]; then
    echo "first-failing-exit: pid=$POSTTUN_FIRST_FAIL_PID comm=$POSTTUN_FIRST_FAIL_COMM exit=$POSTTUN_FIRST_FAIL_EXIT_CODE trace-ts=$POSTTUN_FIRST_FAIL_TS at=T0+${POSTTUN_T0_TO_FAIL:-?}s"
  else
    echo "first-failing-exit: NOT OBSERVED in the window's trace span"
  fi

  # The failure's ±0.25s causal window: every relevant event of every
  # comm, centred on the first failing exit (the lifetime failure) when
  # observed, else on the first death (the killer may be the manager, not
  # a flow member).
  POSTTUN_WINDOW_TS="${POSTTUN_FIRST_FAIL_TS:-$POSTTUN_FIRST_DEATH_TS}"

  # 4C-48: the causal-anchor machinery, CORRECTED. The canonical 4C-47
  # run (37153317223) exposed a misclassification: the anchor was the
  # FIRST failing syscall exit after T0, which was the rootlesskit
  # PARENT's benign state-file housekeeping probe (unlinkat -> ENOENT,
  # 2.3ms BEFORE the holder's startup chain began, NO SELinux decision,
  # the parent continued running) — it stole the anchor and pushed the
  # REAL production boundary (the symlink reconstruction's lnk_file
  # create denial, co-timed with the holder's own symlinkat -> EACCES)
  # into POST-FAILURE/CLEANUP, and the verdict mislabeled the lifetime
  # failure SOFTWARE-LIFECYCLE. The corrected causal contract: a failing
  # syscall may own the PRIMARY-BOUNDARY only when the flow shows NO
  # further forward production progress after it (failure + later
  # production operation => the failure was handled/non-terminal).
  # ENOENT is NOT special-cased: the criterion is the OBSERVED forward
  # production progress, not the errno. The machinery:
  #   1. candidates = every non-kill failing syscall exit of a
  #      flow-domain comm after T0;
  #   2. the cleanup zone begins at the first enter of the residue
  #      cleanup shapes (the defer RemoveAll(bind0): unlink/unlinkat/
  #      rmdir/openat/openat2/getdents64/newfstatat/statx naming
  #      /tmp/rootlesskit-b*; the mkdirat/mkdir/mount stages are
  #      production and excluded — they name the residue path as their
  #      own target/source) — everything at/after it is
  #      POST-FAILURE/CLEANUP territory, never forward progress;
  #   3. the production-enter set = the armed startup-stage syscalls
  #      (mount/mkdir/mkdirat/umount2/umount/rename/getdents64/openat/
  #      openat2/newfstatat/statx/unlink/unlinkat/rmdir/symlink/
  #      symlinkat/readlink/execve/socket/open/setns/ioctl) of flow-domain
  #      comms (4C-49 adds setns and ioctl — both armed startup-stage
  #      production operations of the next stages),
  #      minus the cleanup shapes, before the zone;
  #   4. the ANCHOR = the LAST pre-zone candidate with NO later
  #      different-name non-cleanup production enter (the terminal
  #      production failure — no forward progress follows it;
  #      stage-aware standing, the canonical 4C-52 run 37307909383:
  #      the handled proof must come after the owning stage-chain's
  #      last failing window and from a different stage — the
  #      RemoveAll-stage's own retry chain never proves progress — and
  #      a pre-anchor denial with no spanning owning window but later
  #      production progress is tolerated, the untraced fd-Stat
  #      getattr); every OTHER pre-zone candidate is
  #      HANDLED/NON-TERMINAL (its handling proof = the first later
  #      production enter from a different stage after the chain's
  #      last failure); when every candidate has later progress the
  #      anchor falls back to the LAST candidate, flagged fallback (no
  #      terminal production failure was isolated);
  #   5. denial classes: POLLING-ONLY (recurring shape) > zone
  #      (POST-FAILURE/CLEANUP) > a denial whose owning syscall window
  #      belongs to a HANDLED failure (HANDLED/NON-TERMINAL) > d<=0 vs
  #      the anchor (STARTUP-CAUSAL) > POST-FAILURE/CLEANUP > UNTIMED.
  # The negative control (a terminal failing production syscall with no
  # co-timed SELinux decision and no later progress) still yields
  # SOFTWARE-LIFECYCLE — the correction must not bias the classifier
  # toward SELinux. When no failing non-kill syscall-exit is recorded,
  # the anchor falls back to the first failing process exit (the
  # pre-4C-43 behavior).
  # P4B-ANCHOR-MACHINERY-BEGIN (extracted verbatim by the corpus replays)
  POSTTUN_ANCHOR_TMP="$EVIDENCE_DIR/.p4b-anchor-facts"
  awk -v t0="$POSTTUN_T0_TRACE_TS" -v fl="$POSTTUN_FLOW_COMM_AWK" '
    function namof(s) {
      if (match(s, /sys_[a-z0-9_]+/)) return substr(s, RSTART+4, RLENGTH-4)
      return ""
    }
    # The stage key is the basename of the first quoted path argument
    # (pathname/filename/dir_name/oldname; empty when the syscall
    # carries no quoted path). Name + stage basename together identify
    # the producing call-site stage: the canonical 4C-52 run
    # 37307909383 showed the RemoveAll("/etc/resolv.conf") stage own
    # retry windows (openat("/etc"), fd-based unlinkat/readlinkat)
    # acting as the handling proof while the flow died at the stage
    # anchor — the 4C-48 corpus interleaved same-syscall stages (the
    # sysfs mounts vs the cgroup MS_MOVE) must keep their cross-stage
    # proofs, so the proof search is stage-aware, not name-only.
    function baseof(s,   q, n, parts) {
      if (!match(s, /"[^"]*"/)) return ""
      q = substr(s, RSTART + 1, RLENGTH - 2)
      if (q == "") return ""
      n = split(q, parts, "/")
      return parts[n]
    }
    /^ *[a-zA-Z0-9_.-]+-[0-9]+ +\[[0-9]+\]/ {
      if ($0 !~ /sys_[a-z0-9_]+/ && $0 !~ /selinux_audited:/) next
      who = $1
      if (who !~ fl) next
      ts = $4; sub(/:$/, "", ts)
      if (t0 != "" && ts + 0 <= t0 + 0) next
      if ($0 ~ /selinux_audited:/) {
        nd++
        den[nd] = ts "\t" who "\t" $0
        next
      }
      if (!match($0, /sys_[a-z0-9_]+/)) next
      nm = namof($0)
      if (nm ~ /^(kill|tkill|tgkill|pidfd_send_signal)$/) next
      k = who "|" nm
      if ($0 ~ "sys_" nm " -> ") {
        # The paired window close (both success and failure).
        wasclean = 0
        wbase = ""
        if (qtop[k] > 0) {
          pc++
          pwho[pc] = who; pname[pc] = nm; pets[pc] = qent[k, qtop[k]]; pxts[pc] = ts
          wasclean = qcl[k, qtop[k]]
          pclean[pc] = wasclean
          # The closing window own stage key is captured BEFORE the stack
          # pop: after the decrement the candidate would read the
          # enclosing window base (or empty at depth one), collapsing
          # all same-syscall stages into one broken chain (reproduced on
          # the canonical 4C-52 run 37307909383 corpus: every unlinkat
          # candidate read an empty base and the stage cut landed on the
          # anchor).
          wbase = qbase[k, qtop[k]]
          qtop[k]--
        }
        if ($0 ~ / -> 0xf/ && !wasclean) {
          # A failing exit is a TERMINAL CANDIDATE only when its own
          # syscall window is not a cleanup shape: the RemoveAll(bind0)
          # stage (the tolerated mid-startup temp-dir removal AND the
          # post-failure defer) is the failure-response stage — its own
          # failures never own the lifetime (the 4C-48 canonical run
          # new shape: the tolerated mid-startup RemoveAll followed by
          # the rksys/sysfs production stages).
          nc++
          cand[nc] = ts "\t" who "\t" nm "\t" $0 "\t" wbase
        }
        next
      }
      if ($0 ~ "sys_" nm "\\(") {
        qtop[k]++
        qent[k, qtop[k]] = ts
        qcl[k, qtop[k]] = 0
        # The window stage-key is taken from the ENTER record (the exit
        # record carries no quoted path argument — the canonical
        # 4C-52 run showed every candidate collected with an empty
        # stage key when taken from the exit record, collapsing all
        # same-syscall stages into one chain).
        qbase[k, qtop[k]] = baseof($0)
        # The cleanup-shape recognition (enter-level): the flow temp-dir
        # removal stage (the RemoveAll(bind0) defer AND the rksys
        # self-cleanup after a failed sys move-mount — the canonical
        # 4C-48 run showed both) and the /tmp enumeration opens. These
        # are the failure-response stage: NOT progress, and their own
        # failures are not terminal candidates. The mkdirat/mkdir/mount
        # stages name /tmp paths too but are PRODUCTION and excluded.
        if (nm ~ /^(unlink|unlinkat|rmdir)$/ && $0 ~ /"\/tmp\//) {
          if (zone == "" || ts + 0 < zone + 0) zone = ts
          qcl[k, qtop[k]] = 1
          next
        }
        if (nm ~ /^(unlink|unlinkat|rmdir|openat|openat2|getdents64|newfstatat|statx|readlink)$/ && $0 ~ /\/tmp\/rootlesskit-b/) {
          if (zone == "" || ts + 0 < zone + 0) zone = ts
          qcl[k, qtop[k]] = 1
          next
        }
        if (nm ~ /^(openat|openat2)$/ && $0 ~ /"\/tmp",/) {
          if (zone == "" || ts + 0 < zone + 0) zone = ts
          qcl[k, qtop[k]] = 1
          next
        }
        if (nm ~ /^(mount|mkdir|mkdirat|umount2|umount|rename|getdents64|openat|openat2|newfstatat|statx|unlink|unlinkat|rmdir|symlink|symlinkat|readlink|execve|socket|open|setns|ioctl)$/) {
          ne++
          ent[ne] = ts "\t" who "\t" nm "\t" baseof($0)
        }
        next
      }
    }
    END {
      # The candidates, in order (the cleanup-shaped failures are
      # already excluded at collection).
      m = 0
      for (i = 1; i <= nc; i++) {
        pre[++m] = i
      }
      # The reverse scan: the LAST candidate with no later
      # different-name non-cleanup production enter (the terminal
      # production failure — no forward progress follows it).
      a = 0
      for (j = m; j >= 1; j--) {
        i = pre[j]
        split(cand[i], f, "\t")
        cts = f[1]; cnm = f[3]
        later = 0
        for (e = 1; e <= ne; e++) {
          split(ent[e], g, "\t")
          if (g[1] + 0 > cts + 0 && (zone == "" || g[1] + 0 < zone + 0) && g[3] != cnm) { later = 1; break }
        }
        if (!later) { a = i; break }
      }
      fb = 0
      if (a == 0 && m > 0) { a = pre[m]; fb = 1 }
      split(cand[a], f, "\t")
      print "ANCHOR_TS=" f[1]
      print "ANCHOR_WHO=" f[2]
      print "ANCHOR_SYS=" f[3]
      print "ANCHOR_FALLBACK=" fb
      print "ZONE_TS=" (zone == "" ? "-" : zone)
      print "ANCHOR_LINE=" f[4]
      # The handled candidates: every candidate except the anchor,
      # each with its first later production enter as the handling
      # proof (failure + later production operation => the failure was
      # handled/non-terminal).
      h = 0
      for (j = 1; j <= m; j++) {
        i = pre[j]
        if (i == a) continue
        split(cand[i], f, "\t")
        cts = f[1]; cnm = f[3]; cbase = f[5]
        cut = 0
        for (j2 = 1; j2 <= m; j2++) {
          i2 = pre[j2]
          split(cand[i2], f2, "\t")
          if (f[2] == f2[2] && cnm == f2[3] && cbase == f2[5] && f2[1] + 0 > cut) cut = f2[1] + 0
        }
        proof = ""
        for (e = 1; e <= ne; e++) {
          split(ent[e], g, "\t")
          if (g[1] + 0 > cut + 0 && (g[3] != cnm || g[4] != cbase)) {
            proof = g[1] " " g[3]
            break
          }
        }
        h++
        print "HANDLED " h " trace-ts=" f[1] " who=" f[2] " sys=" cnm " by=" (proof == "" ? "(none — fallback)" : proof)
      }
      print "HANDLED_COUNT=" h
      # The denial classification (the 4C-43 vocabulary + HANDLED):
      # POLLING-ONLY (recurring shape) > a denial whose owning syscall
      # window is a cleanup shape: HANDLED/NON-TERMINAL with the
      # continuation proof when the denial sits before the terminal
      # anchor (the 4C-51 corrective contract — the tolerated mid-flow
      # temp-dir stage noise), POST-FAILURE/CLEANUP at/after the anchor
      # > a denial whose owning failure is HANDLED (HANDLED/NON-TERMINAL;
      # the owning stage-chain own retry chain never serves as the
      # proof: the proof is the first later production enter from a
      # different stage after the chain last failure — the canonical
      # 4C-52 contract §12), the same for the untraced-owner branch
      # (no spanning window + later progress) > d<=0 vs the anchor
      # (STARTUP-CAUSAL) > POST-FAILURE/CLEANUP > UNTIMED.
      ns = 0; np = 0; nq = 0; nu = 0; nh = 0
      for (i = 1; i <= nd; i++) {
        split(den[i], f, "\t")
        ts = f[1]; dwho = f[2]; raw = f[3]
        sh = ""
        if (match(raw, /scontext=[^ \t]+/)) sh = substr(raw, RSTART, RLENGTH)
        if (match(raw, /tcontext=[^ \t]+/)) sh = sh "|" substr(raw, RSTART, RLENGTH)
        if (match(raw, /denied=0x[0-9a-fA-F]+/)) sh = sh "|" substr(raw, RSTART, RLENGTH)
        shp[sh]++
        cls = ""
        if (a != 0) {
          owncand = ""; ownwho = ""; best = -1; ownclean = 0
          for (p = 1; p <= pc; p++) {
            if (pwho[p] != dwho) continue
            if (pets[p] + 0 > ts + 0 || pxts[p] + 0 < ts + 0) continue
            if (pets[p] + 0 > best) { best = pets[p] + 0; owncand = pxts[p]; ownwho = pwho[p]; ownclean = pclean[p] }
          }
          if (ownclean) {
            # The 4C-51 corrective contract: POST-FAILURE/CLEANUP means
            # the terminal anchor has already fired. A denial before the
            # anchor whose owning window is the tolerated temp-dir stage
            # (the residue RmdirAll walks, the /tmp enumeration opens)
            # is never post-failure: the flow demonstrably continues
            # past it. The continuation is proven from the machinery
            # own forward-progress data — the first production enter
            # after the owning window (the stage own retry chain is
            # cleanup-shaped and structurally absent from the enter
            # list).
            split(cand[a], g, "\t")
            if (ts + 0 <= g[1] + 0) {
              prf = ""
              for (sp = 1; sp <= ne; sp++) {
                split(ent[sp], h2, "\t")
                if (h2[1] + 0 > owncand + 0) { prf = h2[1] " " h2[3]; break }
              }
              if (prf != "") { cls = "HANDLED/NON-TERMINAL"; dproof = prf }
              else cls = "POST-FAILURE/CLEANUP"
            } else cls = "POST-FAILURE/CLEANUP"
          }
          else if (owncand != "") {
            # The anchor own denial outranks the polling shape: a
            # denial whose owning window IS the terminal anchor own
            # syscall window is the anchor own boundary — never a
            # polling shape, never a handled failure (the canonical
            # 4C-49 run /etc/hosts openat: the recurring tmpfs_t
            # lnk_file mask shape stole the anchor own denial into
            # POLLING-ONLY and hid the boundary behind a
            # SOFTWARE-LIFECYCLE verdict).
            split(cand[a], g, "\t")
            if (owncand == g[1] && ownwho == g[2]) cls = "STARTUP-CAUSAL"
            else {
              ii = 0
              for (j = 1; j <= m; j++) {
                if (pre[j] == a) continue
                split(cand[pre[j]], f2, "\t")
                if (f2[1] == owncand) { ii = pre[j]; break }
              }
              if (ii != 0) {
                split(cand[ii], f2, "\t")
                cut = 0
                for (j2 = 1; j2 <= m; j2++) {
                  i2 = pre[j2]
                  split(cand[i2], f3, "\t")
                  if (f2[2] == f3[2] && f2[3] == f3[3] && f2[5] == f3[5] && f3[1] + 0 > cut) cut = f3[1] + 0
                }
                prf = ""
                for (e2 = 1; e2 <= ne; e2++) {
                  split(ent[e2], h2, "\t")
                  if (h2[1] + 0 > cut + 0 && (h2[3] != f2[3] || h2[4] != f2[5])) { prf = h2[1] " " h2[3]; break }
                }
                if (prf != "") { cls = "HANDLED/NON-TERMINAL"; dproof = prf }
                else {
                  d = ts - g[1]
                  if (d <= 0) cls = "STARTUP-CAUSAL"
                  else cls = "POST-FAILURE/CLEANUP"
                }
              }
            }
          }
          else if (owncand == "") {
            # The untraced-owner branch (the canonical 4C-52 run
            # 37307909383: the ReadFile fd-Stat getattr decision sat
            # in the openat-to-read gap with NO owning syscall window —
            # the runner kernel offers no fstat syscall tracepoint dir —
            # and the flow demonstrably continued past it: the reads,
            # the EOF, the stateDir hosts write and the network child
            # all followed). Anchor-order outranks the owner gap: a
            # pre-anchor unowned decision with later production
            # progress is tolerated, not terminal.
            split(cand[a], g2, "\t")
            if (ts + 0 <= g2[1] + 0) {
              prf = ""
              for (sp = 1; sp <= ne; sp++) {
                split(ent[sp], h2, "\t")
                if (h2[1] + 0 > ts + 0) { prf = h2[1] " " h2[3]; break }
              }
              if (prf != "") { cls = "HANDLED/NON-TERMINAL"; dproof = prf }
            }
          }
        }
        if (cls == "" && shp[sh] >= 2) cls = "POLLING-ONLY"
        else if (cls == "" && a == 0) cls = "UNTIMED"
        else if (cls == "") {
          split(cand[a], g, "\t")
          d = ts - g[1]
          if (d <= 0) cls = "STARTUP-CAUSAL"
          else cls = "POST-FAILURE/CLEANUP"
        }
        if (cls == "STARTUP-CAUSAL") ns++
        else if (cls == "POST-FAILURE/CLEANUP") np++
        else if (cls == "POLLING-ONLY") nq++
        else if (cls == "UNTIMED") nu++
        else if (cls == "HANDLED/NON-TERMINAL") nh++
        printf "class=%s trace-ts=%s shape=%s\n  %s\n", cls, ts, sh, raw
        if (dproof != "") printf "  HANDLED-PROOF by=%s (the machinery continuation proof)\n", dproof
        dproof = ""
      }
      print "COUNTS STARTUP-CAUSAL=" ns " POST-FAILURE/CLEANUP=" np " POLLING-ONLY=" nq " UNTIMED=" nu " HANDLED/NON-TERMINAL=" nh
    }
  ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null > "$POSTTUN_ANCHOR_TMP" || true
  POSTTUN_ANCHOR_TS="$(grep -a '^ANCHOR_TS=' "$POSTTUN_ANCHOR_TMP" 2>/dev/null | cut -d= -f2 | head -1 || true)"
  POSTTUN_ANCHOR_WHO="$(grep -a '^ANCHOR_WHO=' "$POSTTUN_ANCHOR_TMP" 2>/dev/null | cut -d= -f2 | head -1 || true)"
  POSTTUN_ANCHOR_SYS="$(grep -a '^ANCHOR_SYS=' "$POSTTUN_ANCHOR_TMP" 2>/dev/null | cut -d= -f2 | head -1 || true)"
  POSTTUN_ANCHOR_FALLBACK="$(grep -a '^ANCHOR_FALLBACK=' "$POSTTUN_ANCHOR_TMP" 2>/dev/null | cut -d= -f2 | head -1 || true)"
  POSTTUN_ANCHOR_LINE="$(grep -a '^ANCHOR_LINE=' "$POSTTUN_ANCHOR_TMP" 2>/dev/null | cut -d= -f2- | head -1 || true)"
  POSTTUN_ZONE_TS="$(grep -a '^ZONE_TS=' "$POSTTUN_ANCHOR_TMP" 2>/dev/null | sed 's/^ZONE_TS=//' | head -1 || true)"
  POSTTUN_ANCHOR_FB_NOTE=""
  [ "$POSTTUN_ANCHOR_FALLBACK" = "1" ] && POSTTUN_ANCHOR_FB_NOTE="; FALLBACK — the terminal production failure was not isolated, later progress follows every candidate"
  if [ -n "$POSTTUN_ANCHOR_TS" ]; then
    POSTTUN_CLASS_REF_TS="$POSTTUN_ANCHOR_TS"
    POSTTUN_REF_ANCHOR="the terminal failing production syscall exit ($POSTTUN_ANCHOR_WHO sys_$POSTTUN_ANCHOR_SYS at trace-ts=$POSTTUN_ANCHOR_TS; the 4C-48 corrected contract: a failure owns the primary boundary only when no forward production progress follows it$POSTTUN_ANCHOR_FB_NOTE)"
  else
    POSTTUN_CLASS_REF_TS="$POSTTUN_WINDOW_TS"
    POSTTUN_REF_ANCHOR="the first failing process exit (fallback; no failing non-kill syscall-exit recorded)"
  fi
  echo "classification anchor: $POSTTUN_REF_ANCHOR"
  echo "cleanup zone: ${POSTTUN_ZONE_TS:--} (the earliest /tmp temp-dir stage entry; denials owned by that stage before the terminal anchor are the tolerated stage own noise — HANDLED/NON-TERMINAL with the continuation proof; only the post-anchor ones are POST-FAILURE/CLEANUP)"
  echo "--- the HANDLED/NON-TERMINAL failures (each followed by forward production progress; the probes and handled stages, never the owner):"
  grep -a '^HANDLED ' "$POSTTUN_ANCHOR_TMP" 2>/dev/null || echo "(none — no pre-anchor failure showed later forward production progress)"
  # P4B-ANCHOR-MACHINERY-END
  # The NO-PREANCHOR-POST gate (the standing machinery invariant, the
  # 4C-53 phase contract) — computed FROM the machinery's own output,
  # never re-deriving it: NO decision classified POST-FAILURE/CLEANUP
  # may carry a trace-ts BEFORE the terminal anchor. The corrected
  # machinery's own permanent contract:
  #   timestamp < terminal anchor + subsequent production progress
  #   => never POST-FAILURE
  # (pre-anchor denials are STARTUP-CAUSAL — the anchor's own boundary —
  # or HANDLED/NON-TERMINAL with the continuation proof). A violation
  # means the classification machinery itself is broken: the phase
  # HOLDs (the staircase must not continue on an unreliable ladder;
  # the gate is mandatory, checked below in the verdict).
  POSTTUN_PREANCHOR_POST_REPORT="$(awk -v a="$POSTTUN_ANCHOR_TS" '
    /^class=POST-FAILURE\/CLEANUP trace-ts=/ {
      ts = substr($2, 10)
      if (a == "" || ts + 0 < a + 0) { n++; print "  VIOLATION " $0 }
    }
    END { print "PREANCHOR-POST-COUNT=" n + 0 }
  ' "$POSTTUN_ANCHOR_TMP" 2>/dev/null || true)"
  POSTTUN_PREANCHOR_POST_N="$(grep -a '^PREANCHOR-POST-COUNT=' <<<"$POSTTUN_PREANCHOR_POST_REPORT" | cut -d= -f2 | head -1 || true)"
  POSTTUN_PREANCHOR_POST_ROWS="$(grep -a '^  VIOLATION ' <<<"$POSTTUN_PREANCHOR_POST_REPORT" | sed 's/^  VIOLATION //' || true)"
  POSTTUN_NO_PREANCHOR_POST_OK=0
  if [ "${POSTTUN_PREANCHOR_POST_N:-1}" = "0" ]; then
    POSTTUN_NO_PREANCHOR_POST_OK=1
    echo "NO-PREANCHOR-POST: PASS (no decision classified POST-FAILURE/CLEANUP precedes the terminal anchor trace-ts=${POSTTUN_ANCHOR_TS:-(none)})"
  else
    echo "NO-PREANCHOR-POST: FAIL (${POSTTUN_PREANCHOR_POST_N:-?} pre-anchor decision(s) classified POST-FAILURE/CLEANUP — the machinery standing invariant is violated; the phase HOLDs):"
    printf '%s\n' "$POSTTUN_PREANCHOR_POST_ROWS"
  fi
  if [ -n "$POSTTUN_WINDOW_TS" ]; then
    echo "--- the failure's ±0.25s causal window (all comms, the lifetime-relevant events, ordered; anchored AT T0 — the attach's own pre-T0 steps live in the flow-domain extract):"
    awk -v t0="$POSTTUN_T0_TRACE_TS" -v td="$POSTTUN_WINDOW_TS" '
      { ts = $4; sub(/:$/, "", ts)
        if (t0 != "") { if (ts + 0 < t0 + 0) next } else { if (ts + 0 < td - 0.25) next }
        if (ts + 0 > td + 0.25) next
        print }
    ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
      | grep -aE 'sched_process_fork:|sched_process_exit:|signal_generate:|signal_deliver:|selinux_audited:|sys_(kill|tkill|tgkill|pidfd_send_signal|wait4|waitid|exit|exit_group)' | head -150 || true
    echo "(end of the failure-window records)"
  fi

  # The delivered signal to the dying pids (the killer's identity = the
  # kill-family syscall record's own comm-pid; a delivered signal needs
  # the syscall's ret 0). Checked for the first death and for the first
  # failing exit separately: the designed handoff exit has no killer, the
  # failing exit may or may not have one.
  POSTTUN_DELIVERED_KILL=""
  POSTTUN_DELIVERED_KILL_FAIL=""
  if [ -n "$POSTTUN_FIRST_DEATH_PID" ]; then
    POSTTUN_DELIVERED_KILL="$(awk -v dp="$POSTTUN_FIRST_DEATH_PID" '
      /sys_(kill|tkill|tgkill|pidfd_send_signal)\(/ {
        if (index($0, "pid: " dp " ") > 0 || index($0, "pid: " dp ",") > 0 || index($0, "tid: " dp " ") > 0 || index($0, "tid: " dp ",") > 0) {
          pend = 1; pwho = $1; pline = $0; next
        }
        next
      }
      pend && /sys_(kill|tkill|tgkill|pidfd_send_signal) ->/ && $1 == pwho {
        if ($NF == "0x0") { print pline; print $0; exit }
        pend = 0
      }
    ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
  fi
  if [ -n "$POSTTUN_FIRST_FAIL_PID" ] && [ "$POSTTUN_FIRST_FAIL_PID" != "$POSTTUN_FIRST_DEATH_PID" ]; then
    POSTTUN_DELIVERED_KILL_FAIL="$(awk -v dp="$POSTTUN_FIRST_FAIL_PID" '
      /sys_(kill|tkill|tgkill|pidfd_send_signal)\(/ {
        if (index($0, "pid: " dp " ") > 0 || index($0, "pid: " dp ",") > 0 || index($0, "tid: " dp " ") > 0 || index($0, "tid: " dp ",") > 0) {
          pend = 1; pwho = $1; pline = $0; next
        }
        next
      }
      pend && /sys_(kill|tkill|tgkill|pidfd_send_signal) ->/ && $1 == pwho {
        if ($NF == "0x0") { print pline; print $0; exit }
        pend = 0
      }
    ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
  fi
  echo "--- the delivered signal to the dying pid (the killer's syscall + its ret):"
  printf '%s\n' "${POSTTUN_DELIVERED_KILL:-(none — no delivered kill-family syscall to the first-dying pid inside the trace span)}"
  if [ "$POSTTUN_FIRST_FAIL_PID" != "$POSTTUN_FIRST_DEATH_PID" ]; then
    echo "--- the delivered signal to the first FAILING pid (the lifetime failure's own killer, if any):"
    printf '%s\n' "${POSTTUN_DELIVERED_KILL_FAIL:-(none — no delivered kill-family syscall to the first-failing pid inside the trace span)}"
  fi
  if [ -n "$POSTTUN_FIRST_DEATH_PID" ]; then
    if [ -n "$POSTTUN_DELIVERED_KILL" ]; then
      POSTTUN_DEATH_CAUSE="SIG-DELIVERED (a kill-family syscall returned 0 to the dying pid; the killer is the syscall record's own comm-pid)"
    else
      POSTTUN_DEATH_CAUSE="NO-RECORDED-SIGNAL (no delivered kill-family syscall to the dying pid — voluntary exit, parent-failure, or an unrecorded mechanism; the ordered failure-window above is the evidence)"
    fi
  fi
  echo "first-death cause: ${POSTTUN_DEATH_CAUSE:-UNCLASSIFIED (no death observed)}"

  # The story span: to the first failing exit when one exists, else to
  # the ring's own last timestamp (the stable-lifetime case — the story
  # covers the whole observed span).
  POSTTUN_STORY_END_TS="${POSTTUN_WINDOW_TS:-$POSTTUN_RING_LAST_TS}"

  # The ready channel's ordered story (T0..story end): poll/read/
  # write/close + signal/wait records of the flow-domain members.
  if [ -n "$POSTTUN_T0_TRACE_TS" ] && [ -n "$POSTTUN_STORY_END_TS" ]; then
    echo "--- the ready channel's ordered story (T0..${POSTTUN_STORY_END_TS}; flow-domain comms; poll/read/write/close/signal/wait):"
    awk -v t0="$POSTTUN_T0_TRACE_TS" -v td="$POSTTUN_STORY_END_TS" '
      { ts = $4; sub(/:$/, "", ts); if (ts + 0 < t0 + 0 || ts + 0 > td + 0) next; print }
    ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
      | grep -aE "$POSTTUN_FLOW_COMM_GREP" \
      | grep -aE 'signal_generate:|signal_deliver:|sys_(read|write|close|poll|ppoll|select|pselect6|wait4|waitid)\(|sys_(read|write|close|poll|ppoll|select|pselect6|wait4|waitid) ->' \
      | head -120 || true
    echo "(end of the ready channel's story)"
  fi

  # The post-TUN mount/execve/mkdir story (the 4C-39 + 4C-40 stage
  # evidence): the granted mount propagation on "/", its result, and the
  # following mount/execve/mkdir stages between the ready byte and the
  # next startup boundary (or the span's end in the stable case) — the
  # copy-up setup's MkdirTemp records with their pathnames (the 4C-40
  # stage's own operation; the pathname binds the boundary to MkdirTemp).
  if [ -n "$POSTTUN_T0_TRACE_TS" ] && [ -n "$POSTTUN_STORY_END_TS" ]; then
    echo "--- the post-TUN mount/execve/mkdir story (T0..${POSTTUN_STORY_END_TS}; flow-domain comms; sys_mount/sys_execve/sys_mkdir/sys_mkdirat records with their results and pathnames):"
    awk -v t0="$POSTTUN_T0_TRACE_TS" -v td="$POSTTUN_STORY_END_TS" '
      { ts = $4; sub(/:$/, "", ts); if (ts + 0 < t0 + 0 || ts + 0 > td + 0) next; print }
    ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
      | grep -aE "$POSTTUN_FLOW_COMM_GREP" \
      | grep -aE 'sys_mount\(|sys_mount ->|sys_execve\(|sys_execve ->|sys_mkdirat\(|sys_mkdirat ->|sys_mkdir\(|sys_mkdir ->' \
      | head -80 || true
    echo "(end of the mount/execve/mkdir story)"
  fi

  # The process tree (the fork records from T0 through failure+0.5s).
  echo "--- the process tree (sched_process_fork; the manager/launcher/root and the flow-domain, T0..failure+0.5s):"
  grep -a 'sched_process_fork:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -aE '(docker-helper|rootlesskit|exe|slirp4netns|buildkitd|newuidmap|newgidmap|ip)-[0-9]+ ' \
    | awk -v t0="$POSTTUN_T0_TRACE_TS" -v td="$POSTTUN_WINDOW_TS" '
      { ts = $4; sub(/:$/, "", ts)
        if (t0 == "") next
        if (ts + 0 < t0 + 0) next
        lim = (td != "") ? td + 0.5 : t0 + 3
        if (ts + 0 > lim + 0) next
        print }' | head -60 || true
  echo "(end of the process-tree records)"

  # The timeline (50) around the failure, and its per-pid life summary
  # (printed whenever the timeline exists — in the stable-lifetime case
  # it is the aliveness evidence itself).
  POSTTUN_TIMELINE_ANCHOR_EPOCH="${POSTTUN_FIRST_FAIL_EPOCH:-$POSTTUN_FIRST_DEATH_EPOCH}"
  if [ -n "$POSTTUN_TIMELINE_ANCHOR_EPOCH" ] && [ -s "$EVIDENCE_DIR/50-posttun-timeline.txt" ]; then
    echo "--- the post-TUN timeline around the failure (±0.5s; the wallclock clock):"
    awk -v de="$POSTTUN_TIMELINE_ANCHOR_EPOCH" '
      { ts = $1 + 0; if (ts >= de - 0.5 && ts <= de + 0.5) print }
    ' "$EVIDENCE_DIR/50-posttun-timeline.txt" 2>/dev/null | head -80 || true
    echo "(end of the timeline's death window)"
  fi
  if [ -s "$EVIDENCE_DIR/50-posttun-timeline.txt" ]; then
    echo "--- the timeline's per-pid life summary (first/last seen, state, ppid, ns inodes, tap0):"
    awk '
      $2 == "FD-SNAPSHOT" { next }
      {
        ts = $1
        pid = ""; comm = ""; st = ""; pp = ""; nsu = ""; nsn = ""; tp = ""
        for (i = 2; i <= NF; i++) {
          if ($i ~ /^pid=/) pid = substr($i, 5)
          else if ($i ~ /^comm=/) comm = substr($i, 6)
          else if ($i ~ /^state=/) st = substr($i, 7)
          else if ($i ~ /^ppid=/) pp = substr($i, 6)
          else if ($i ~ /^ns\/user=/) nsu = substr($i, 9)
          else if ($i ~ /^ns\/net=/) nsn = substr($i, 8)
          else if ($i ~ /^tap0=/) tp = substr($i, 6)
        }
        if (pid == "") next
        if (!(pid in first)) { first[pid] = ts; fc[pid] = comm; fst[pid] = st; fpp[pid] = pp; fnsu[pid] = nsu; fnsn[pid] = nsn; ftp[pid] = tp }
        last[pid] = ts; lc[pid] = comm; lst[pid] = st; lpp[pid] = pp; lnsu[pid] = nsu; lnsn[pid] = nsn; ltp[pid] = tp
      }
      END {
        for (p in first) printf "pid=%s comm=%s(first=%s,last=%s) state=%s->%s ppid=%s->%s ns/user=%s->%s ns/net=%s->%s tap0=%s->%s\n", p, fc[p], first[p], last[p], fst[p], lst[p], fpp[p], lpp[p], fnsu[p], lnsu[p], fnsn[p], lnsn[p], ftp[p], ltp[p]
      }
    ' "$EVIDENCE_DIR/50-posttun-timeline.txt" 2>/dev/null | sort || true
    echo "(end of the timeline's per-pid summary)"
  fi

  # The manager journal's causal slice (T0..T0+15s, wallclock; covers
  # the whole post-TUN window — the failure case's own slice and the
  # stable case's op-state evidence).
  if [ -n "$POSTTUN_T0_EPOCH" ]; then
    echo "--- the manager journal's causal slice (T0..T0+15s; T0 = $(date -d "@${POSTTUN_T0_EPOCH%.*}" 2>/dev/null || true)):"
    journalctl -u "$UNIT" --since "@${POSTTUN_T0_EPOCH%.*}" --until "@$(( ${POSTTUN_T0_EPOCH%.*} + 15 ))" --no-pager 2>/dev/null | head -60 || true
    echo "(end of the journal's causal slice)"
  fi

  # The SELinux decisions' temporal classification. The kernel trace is
  # the authoritative channel; the audit slice is corroborating. The
  # classes (the 4C-43 vocabulary):
  # STARTUP-CAUSAL = at or before the first failing SYSCALL exit (the
  #   anchor above; fallback: the first failing process exit) — only
  #   the FIRST such blocker owns the next phase (the boundary search
  #   below takes the earliest);
  # POST-FAILURE/CLEANUP = anything after it (teardown/reap/kill noise
  #   and the failed launch's RemoveAll surface);
  # POLLING-ONLY = a recurring (>=2) scontext/tcontext/denied-mask shape
  #   key (the manager's readiness polls);
  # UNTIMED = the window reference is absent (a classification defect).
  # The classification covers EVERY tclass after T0 (the startup story's
  # own dir/file/socket denials included); the pre-T0 records are the
  # launcher-chain window's scope.
  echo "--- the trace-side SELinux decisions, temporally classified (the anchor: $POSTTUN_REF_ANCHOR; the corrected 4C-48 classes: STARTUP-CAUSAL / POST-FAILURE/CLEANUP / POLLING-ONLY / UNTIMED / HANDLED/NON-TERMINAL):"
  sed -n '/^class=/,$p' "$POSTTUN_ANCHOR_TMP" 2>/dev/null | grep -av '^COUNTS ' || echo "(none — no SELinux decision was recorded after T0)"

  if [ -n "$POSTTUN_ANCHOR_TMP" ] && grep -aq '^COUNTS ' "$POSTTUN_ANCHOR_TMP" 2>/dev/null; then
    POSTTUN_COUNTS_LINE="$(grep -a '^COUNTS ' "$POSTTUN_ANCHOR_TMP" | head -1)"
    POSTTUN_NSTARTUP="$(printf '%s\n' "$POSTTUN_COUNTS_LINE" | sed -n 's/.*STARTUP-CAUSAL=\([0-9]*\).*/\1/p')"
    POSTTUN_NPOST="$(printf '%s\n' "$POSTTUN_COUNTS_LINE" | sed -n 's/.*POST-FAILURE\/CLEANUP=\([0-9]*\).*/\1/p')"
    POSTTUN_NPOLL="$(printf '%s\n' "$POSTTUN_COUNTS_LINE" | sed -n 's/.*POLLING-ONLY=\([0-9]*\).*/\1/p')"
    POSTTUN_NUNTIMED="$(printf '%s\n' "$POSTTUN_COUNTS_LINE" | sed -n 's/.*UNTIMED=\([0-9]*\).*/\1/p')"
    POSTTUN_NHANDLED="$(printf '%s\n' "$POSTTUN_COUNTS_LINE" | sed -n 's/.*HANDLED\/NON-TERMINAL=\([0-9]*\).*/\1/p')"
  fi
  POSTTUN_DENIALS_CLASSIFIED=1
  if grep -aq 'class=UNTIMED' "$POSTTUN_ANCHOR_TMP" 2>/dev/null; then
    POSTTUN_DENIALS_CLASSIFIED=0
  fi
  echo "denial classes: STARTUP-CAUSAL=${POSTTUN_NSTARTUP:-0} POST-FAILURE/CLEANUP=${POSTTUN_NPOST:-0} POLLING-ONLY=${POSTTUN_NPOLL:-0} UNTIMED=${POSTTUN_NUNTIMED:-0} HANDLED/NON-TERMINAL=${POSTTUN_NHANDLED:-0}"

  # 4C-39: the OLD primary boundary must be GONE — no selinux_audited
  # record naming the exact triple (docker_helper_rootlesskit_t ->
  # root_t:dir, denied mask 0x10000 = mounton) anywhere in the window's
  # trace span. A record here means the 4C-39 grant did not take effect
  # on the loaded policy: STOP and report the actual behavior (no rule
  # widening). In the 4C-40 phase this check stays as the STANDING
  # regression guard for the 4C-39 grant.
  POSTTUN_OLD_MOUNTON_PRESENT="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
    | grep -a 'tcontext=system_u:object_r:root_t:s0' \
    | grep -a 'tclass=dir' \
    | grep -a 'denied=0x10000' || true)"
  if [ -n "$POSTTUN_OLD_MOUNTON_PRESENT" ]; then
    echo "OLD-BOUNDARY: STILL-PRESENT — the 4C-39 mounton grant did not take effect (STOP; no rule widening):"
    printf '%s\n' "$POSTTUN_OLD_MOUNTON_PRESENT"
    POSTTUN_OLD_BOUNDARY_PRESENT=1
  else
    echo "OLD-BOUNDARY: GONE (no rootlesskit_t -> root_t:dir mounton (0x10000) decision in the window's trace span)"
  fi

  # 4C-40: the SAME contract for the phase's own grant — the OLD primary
  # boundary (docker_helper_rootlesskit_t -> tmp_t:dir, denied mask 0x4 =
  # write; the 4C-39 run's canonical record) must be GONE anywhere in the
  # window's trace span. The masks are matched exactly (0x4 is not
  # 0x40000's substring — open's mask and every other 0x4* prefix are
  # excluded), and the target context is matched to the type boundary
  # (tmp_t is not user_tmp_t's substring — the distro labels /tmp
  # tmp_t). A record here means the 4C-40 grant did not take effect on
  # the loaded policy: STOP and report the actual behavior (no rule
  # widening).
  POSTTUN_OLD_TMPWRITE_PRESENT="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
    | grep -aE 'tcontext=system_u:object_r:tmp_t:s0([ \t]|$)' \
    | grep -a 'tclass=dir' \
    | grep -aE 'denied=0x4([^0-9a-fA-F]|$)' || true)"
  if [ -n "$POSTTUN_OLD_TMPWRITE_PRESENT" ]; then
    echo "OLD-WRITE-BOUNDARY: STILL-PRESENT — the 4C-40 write grant did not take effect (STOP; no rule widening):"
    printf '%s\n' "$POSTTUN_OLD_TMPWRITE_PRESENT"
    POSTTUN_OLD_TMPWRITE_PRESENT=1
  else
    echo "OLD-WRITE-BOUNDARY: GONE (no rootlesskit_t -> tmp_t:dir write (0x4) decision in the window's trace span)"
  fi

  # 4C-41: the SAME contract for the phase's own grant — the OLD primary
  # boundary (docker_helper_rootlesskit_t -> tmp_t:dir, denied mask
  # 0x4000000 = add_name; the canonical 4C-40 run's record inside
  # sys_mkdirat("/tmp/rootlesskit-b...", 0700)) must be GONE anywhere in
  # the window's trace span. The mask is matched exactly (0x4000000 is
  # not 0x40000's substring — open's mask is excluded); a record here
  # means the 4C-41 grant did not take effect on the loaded policy: STOP
  # and report the actual behavior (no rule widening).
  POSTTUN_OLD_ADDNAME_PRESENT="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
    | grep -aE 'tcontext=system_u:object_r:tmp_t:s0([ \t]|$)' \
    | grep -a 'tclass=dir' \
    | grep -aE 'denied=0x4000000([^0-9a-fA-F]|$)' || true)"
  if [ -n "$POSTTUN_OLD_ADDNAME_PRESENT" ]; then
    echo "OLD-ADDNAME-BOUNDARY: STILL-PRESENT — the 4C-41 add_name grant did not take effect (STOP; no rule widening):"
    printf '%s\n' "$POSTTUN_OLD_ADDNAME_PRESENT"
    POSTTUN_OLD_ADDNAME_PRESENT=1
  else
    echo "OLD-ADDNAME-BOUNDARY: GONE (no rootlesskit_t -> tmp_t:dir add_name (0x4000000) decision in the window's trace span)"
  fi

  # 4C-42: the SAME contract for the phase's own grant — the OLD primary
  # boundary (docker_helper_rootlesskit_t -> tmp_t:dir, denied mask 0x8
  # = create; the canonical 4C-41 run's record inside
  # sys_mkdirat("/tmp/rootlesskit-b...", 0700)) must be GONE anywhere in
  # the window's trace span. The mask is matched exactly (0x8 is not
  # 0x80's or 0x8000000's substring — tun_socket relabelfrom and dir
  # remove_name are excluded); the sigkill cleanup denial carries the
  # SAME mask 0x8 but on tclass=process — the class grep excludes it. A
  # record here means the 4C-42 grant did not take effect on the loaded
  # policy: STOP and report the actual behavior (no rule widening).
  POSTTUN_OLD_CREATE_PRESENT="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
    | grep -aE 'tcontext=system_u:object_r:tmp_t:s0([ \t]|$)' \
    | grep -a 'tclass=dir' \
    | grep -aE 'denied=0x8([^0-9a-fA-F]|$)' || true)"
  if [ -n "$POSTTUN_OLD_CREATE_PRESENT" ]; then
    echo "OLD-CREATE-BOUNDARY: STILL-PRESENT — the 4C-42 create grant did not take effect (STOP; no rule widening):"
    printf '%s\n' "$POSTTUN_OLD_CREATE_PRESENT"
    POSTTUN_OLD_CREATE_PRESENT=1
  else
    echo "OLD-CREATE-BOUNDARY: GONE (no rootlesskit_t -> tmp_t:dir create (0x8) decision in the window's trace span)"
  fi

  # 4C-43: the SAME contract for the phase's own grant — the OLD primary
  # boundary (docker_helper_rootlesskit_t -> tmp_t:dir, denied mask
  # 0x10000 = mounton; the canonical 4C-42 run's record inside
  # sys_mount("/etc", "/tmp/rootlesskit-b...", MS_BIND|MS_REC)) must be
  # GONE anywhere in the window's trace span. The mask is matched
  # exactly (0x10000 is not 0x100000's substring — dir:watch is
  # excluded). A record here means the 4C-43 grant did not take effect
  # on the loaded policy: STOP and report the actual behavior (no rule
  # widening).
  POSTTUN_OLD_TMPMOUNTON_PRESENT="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
    | grep -aE 'tcontext=system_u:object_r:tmp_t:s0([ \t]|$)' \
    | grep -a 'tclass=dir' \
    | grep -aE 'denied=0x10000([^0-9a-fA-F]|$)' || true)"
  if [ -n "$POSTTUN_OLD_TMPMOUNTON_PRESENT" ]; then
    echo "OLD-TMPMOUNTON-BOUNDARY: STILL-PRESENT — the 4C-43 mounton grant did not take effect (STOP; no rule widening):"
    printf '%s\n' "$POSTTUN_OLD_TMPMOUNTON_PRESENT"
    POSTTUN_OLD_TMPMOUNTON_PRESENT=1
  else
    echo "OLD-TMPMOUNTON-BOUNDARY: GONE (no rootlesskit_t -> tmp_t:dir mounton (0x10000) decision in the window's trace span)"
  fi

  # 4C-44: the SAME contract for the phase's own grant — the OLD primary
  # boundary (docker_helper_rootlesskit_t -> etc_t:dir, denied mask
  # 0x10000 = mounton; the canonical 4C-43 run's record inside
  # sys_mount("none", "/etc", "tmpfs", 0)) must be GONE anywhere in the
  # window's trace span. A record here means the 4C-44 grant did not
  # take effect on the loaded policy: STOP and report the actual
  # behavior (no rule widening).
  POSTTUN_OLD_ETCMOUNTON_PRESENT="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
    | grep -aE 'tcontext=system_u:object_r:etc_t:s0([ \t]|$)' \
    | grep -a 'tclass=dir' \
    | grep -aE 'denied=0x10000([^0-9a-fA-F]|$)' || true)"
  if [ -n "$POSTTUN_OLD_ETCMOUNTON_PRESENT" ]; then
    echo "OLD-ETCMOUNTON-BOUNDARY: STILL-PRESENT — the 4C-44 etc mounton grant did not take effect (STOP; no rule widening):"
    printf '%s\n' "$POSTTUN_OLD_ETCMOUNTON_PRESENT"
    POSTTUN_OLD_ETCMOUNTON_PRESENT=1
  else
    echo "OLD-ETCMOUNTON-BOUNDARY: GONE (no rootlesskit_t -> etc_t:dir mounton (0x10000) decision in the window's trace span)"
  fi

  # 4C-45: the SAME contract for the phase's own grant — the OLD primary
  # boundary (docker_helper_rootlesskit_t -> tmpfs_t:filesystem, denied
  # mask 0x1 = mount, bit 0 of the filesystem class's common perms; the
  # canonical 4C-44 run's record inside the same
  # sys_mount("none", "/etc", "tmpfs", 0) window) must be GONE anywhere
  # in the window's trace span. The mask anchor is pinned to the literal
  # 0x1 followed by a non-hex/edge (0x10/0x100/0x10000-class masks are
  # different perms); the tclass=filesystem anchor separates this gate
  # from any file-class ioctl mask (0x1 on file/dir is a different
  # class's decision). A record here means the 4C-45 grant did not take
  # effect on the loaded policy: STOP and report the actual behavior
  # (no rule widening).
  POSTTUN_OLD_FSMOUNT_PRESENT="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
    | grep -aE 'tcontext=system_u:object_r:tmpfs_t:s0([ \t]|$)' \
    | grep -a 'tclass=filesystem' \
    | grep -aE 'denied=0x1([^0-9a-fA-F]|$)' || true)"
  if [ -n "$POSTTUN_OLD_FSMOUNT_PRESENT" ]; then
    echo "OLD-FSMOUNT-BOUNDARY: STILL-PRESENT — the 4C-45 tmpfs filesystem mount grant did not take effect (STOP; no rule widening):"
    printf '%s\n' "$POSTTUN_OLD_FSMOUNT_PRESENT"
    POSTTUN_OLD_FSMOUNT_PRESENT=1
  else
    echo "OLD-FSMOUNT-BOUNDARY: GONE (no rootlesskit_t -> tmpfs_t:filesystem mount (0x1) decision in the window's trace span)"
  fi

  # 4C-46: the SAME contract for the phase's own grant — the OLD primary
  # boundary (docker_helper_rootlesskit_t -> tmpfs_t:dir, denied mask
  # 0x8 = create, bit 3 of the kernel's static dir classmap; the
  # canonical 4C-45 run's record inside the .ro mkdirat window) must be
  # GONE anywhere in the window's trace span. The mask anchor is pinned
  # to the literal 0x8 followed by a non-hex/edge (0x80 relabelfrom/
  # 0x800 rmdir/0x8000000-class masks are different perms); the
  # tcontext=tmpfs_t anchor separates this gate from the 4C-42-era
  # tmp_t:dir create standing gate (different target type). A record
  # here means the 4C-46 grant did not take effect on the loaded
  # policy: STOP and report the actual behavior (no rule widening).
  POSTTUN_OLD_TMPDIRCREATE_PRESENT="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
    | grep -aE 'tcontext=system_u:object_r:tmpfs_t:s0([ \t]|$)' \
    | grep -a 'tclass=dir' \
    | grep -aE 'denied=0x8([^0-9a-fA-F]|$)' || true)"
  if [ -n "$POSTTUN_OLD_TMPDIRCREATE_PRESENT" ]; then
    echo "OLD-TMPDIRCREATE-BOUNDARY: STILL-PRESENT — the 4C-46 .ro dir create grant did not take effect (STOP; no rule widening):"
    printf '%s\n' "$POSTTUN_OLD_TMPDIRCREATE_PRESENT"
    POSTTUN_OLD_TMPDIRCREATE_PRESENT=1
  else
    echo "OLD-TMPDIRCREATE-BOUNDARY: GONE (no rootlesskit_t -> tmpfs_t:dir create (0x8) decision in the window's trace span)"
  fi

  # 4C-47: the SAME contract for the phase's own grant — the OLD primary
  # boundary (docker_helper_rootlesskit_t -> tmpfs_t:dir, denied mask
  # 0x10000 = mounton, bit 16 of the kernel's static dir classmap; the
  # canonical 4C-46 run's record inside the move-mount window) must be
  # GONE anywhere in the window's trace span. The tcontext=tmpfs_t
  # anchor separates this gate from the tmp_t/etc_t/root_t dir mounton
  # standing gates (different target types). A record here means the
  # 4C-47 grant did not take effect on the loaded policy: STOP and
  # report the actual behavior (no rule widening).
  POSTTUN_OLD_TMPDIRMOUNTON_PRESENT="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
    | grep -aE 'tcontext=system_u:object_r:tmpfs_t:s0([ \t]|$)' \
    | grep -a 'tclass=dir' \
    | grep -aE 'denied=0x10000([^0-9a-fA-F]|$)' || true)"
  if [ -n "$POSTTUN_OLD_TMPDIRMOUNTON_PRESENT" ]; then
    echo "OLD-TMPDIRMOUNTON-BOUNDARY: STILL-PRESENT — the 4C-47 move-mount target mounton grant did not take effect (STOP; no rule widening):"
    printf '%s\n' "$POSTTUN_OLD_TMPDIRMOUNTON_PRESENT"
    POSTTUN_OLD_TMPDIRMOUNTON_PRESENT=1
  else
    echo "OLD-TMPDIRMOUNTON-BOUNDARY: GONE (no rootlesskit_t -> tmpfs_t:dir mounton (0x10000) decision in the window's trace span)"
  fi

  # 4C-48: the SAME contract for the phase's own grant — the OLD primary
  # boundary (docker_helper_rootlesskit_t -> tmpfs_t:lnk_file, denied
  # mask 0x8 = create, bit 3 of COMMON_FILE_PERMS; the canonical 4C-47
  # run's record inside the rebuild symlinkat window) must be GONE
  # anywhere in the window's trace span. The mask anchor is pinned to
  # the literal 0x8 followed by a non-hex/edge; the tclass=lnk_file
  # anchor separates this gate from the dir-class create gates
  # (tmpfs_t:dir create — the 4C-46 standing gate) and from the
  # file-class ioctl 0x1/0x8-family masks. A record here means the
  # 4C-48 grant did not take effect on the loaded policy: STOP and
  # report the actual behavior (no rule widening).
  POSTTUN_OLD_LNKCREATE_PRESENT="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
    | grep -aE 'tcontext=system_u:object_r:tmpfs_t:s0([ \t]|$)' \
    | grep -a 'tclass=lnk_file' \
    | grep -aE 'denied=0x8([^0-9a-fA-F]|$)' || true)"
  if [ -n "$POSTTUN_OLD_LNKCREATE_PRESENT" ]; then
    echo "OLD-LNKCREATE-BOUNDARY: STILL-PRESENT — the 4C-48 rebuild symlink create grant did not take effect (STOP; no rule widening):"
    printf '%s\n' "$POSTTUN_OLD_LNKCREATE_PRESENT"
    POSTTUN_OLD_LNKCREATE_PRESENT=1
  else
    echo "OLD-LNKCREATE-BOUNDARY: GONE (no rootlesskit_t -> tmpfs_t:lnk_file create (0x8) decision in the window's trace span)"
  fi

  # 4C-50: the SAME contract for the phase's own widening — the OLD
  # primary boundary (docker_helper_rootlesskit_t -> tmpfs_t:lnk_file,
  # denied mask 0x2 = read, bit 1 of the kernel's static classmap's
  # common layout; the canonical 4C-49 run's record inside the
  # openat("/etc/hosts") window — generateEtcHosts()'s own read, the
  # link traversal's own hook) must be GONE anywhere in the window's
  # trace span. The mask anchor is pinned to the literal 0x2 followed
  # by a non-hex/edge (0x2 never matches a 0x2X/0x2XX mask); the
  # tclass=lnk_file anchor separates this gate from the dir-class read
  # gates (tmp_t:dir read — the standing /tmp-enumeration shape) and
  # the tcontext=tmpfs_t:s0 anchor separates it from every other
  # type's lnk_file read (etc_t's standing traversal read). A record
  # here means the 4C-50 widening did not take effect on the loaded
  # policy: STOP and report the actual behavior (no rule widening).
  POSTTUN_OLD_LNKREAD_PRESENT="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
    | grep -aE 'tcontext=system_u:object_r:tmpfs_t:s0([ \t]|$)' \
    | grep -a 'tclass=lnk_file' \
    | grep -aE 'denied=0x2([^0-9a-fA-F]|$)' || true)"
  if [ -n "$POSTTUN_OLD_LNKREAD_PRESENT" ]; then
    echo "OLD-LNKREAD-BOUNDARY: STILL-PRESENT — the 4C-50 read widening did not take effect (STOP; no rule widening):"
    printf '%s\n' "$POSTTUN_OLD_LNKREAD_PRESENT"
    POSTTUN_OLD_LNKREAD_PRESENT=1
  else
    echo "OLD-LNKREAD-BOUNDARY: GONE (no rootlesskit_t -> tmpfs_t:lnk_file read (0x2) decision in the window's trace span)"
  fi

  # 4C-51: the SAME contract for the phase's own grant — the OLD primary
  # boundary (docker_helper_rootlesskit_t -> net_conf_t:file, denied mask
  # 0x2 = read, bit 1 of the kernel's static COMMON_FILE_SOCK_PERMS
  # layout; the canonical 4C-50 run 37264978329's record inside the
  # openat("/etc/hosts") window — generateEtcHosts()'s os.ReadFile, the
  # RESOLVED target's own file read after the 4C-50 link traversal
  # passed; confirmed in three observations including the companion c2
  # window) must be GONE anywhere in the window's trace span. The mask
  # anchor is pinned to the literal 0x2 followed by a non-hex/edge (0x2
  # never matches a 0x2X/0x2XX mask); the tclass=file anchor separates
  # this gate from the lnk_file-class read gates (the 4C-50 tmpfs_t
  # standing gate — different class) and from every dir/filesystem-class
  # shape; the tcontext=net_conf_t:s0 anchor (the global type carries no
  # MCS category) separates it from every other type's file-class read
  # gates. A record here means the 4C-51 grant did not take effect on
  # the loaded policy: STOP and report the actual behavior (no rule
  # widening).
  POSTTUN_OLD_CONFFILEREAD_PRESENT="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
    | grep -aE 'tcontext=system_u:object_r:net_conf_t:s0([ \t]|$)' \
    | grep -a 'tclass=file' \
    | grep -aE 'denied=0x2([^0-9a-fA-F]|$)' || true)"
  if [ -n "$POSTTUN_OLD_CONFFILEREAD_PRESENT" ]; then
    echo "OLD-CONFFILEREAD-BOUNDARY: STILL-PRESENT — the 4C-51 resolved-file read grant did not take effect (STOP; no rule widening):"
    printf '%s\n' "$POSTTUN_OLD_CONFFILEREAD_PRESENT"
    POSTTUN_OLD_CONFFILEREAD_PRESENT=1
  else
    echo "OLD-CONFFILEREAD-BOUNDARY: GONE (no rootlesskit_t -> net_conf_t:file read (0x2) decision in the window's trace span)"
  fi

  # 4C-52: the SAME contract for the phase's own widening — the OLD
  # primary boundary (docker_helper_rootlesskit_t -> net_conf_t:file,
  # denied mask 0x40000 = the VFS open's completion hook, the canonical
  # 4C-51 run 37286690263's record inside the same openat("/etc/hosts")
  # window AFTER the 4C-51 read hook passed (the read bit 0x2 sat inside
  # requested=0x40002 and not inside denied=0x40000); confirmed in the
  # companion c2 window) must be GONE anywhere in the window's trace
  # span. The mask anchor is pinned to the literal 0x40000 followed by a
  # non-hex/edge (0x40000 never matches a 0x40000X mask prefix-shift);
  # the tclass=file anchor separates this gate from the lnk_file/dir
  # classes and from every other type's file-class open shape; the
  # tcontext=net_conf_t:s0 anchor (the global type carries no MCS
  # category) separates it from every other type's file-class gates. A
  # record here means the 4C-52 widening did not take effect on the
  # loaded policy: STOP and report the actual behavior (no rule
  # widening).
  POSTTUN_OLD_CONFOPEN_PRESENT="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
    | grep -aE 'tcontext=system_u:object_r:net_conf_t:s0([ \t]|$)' \
    | grep -a 'tclass=file' \
    | grep -aE 'denied=0x40000([^0-9a-fA-F]|$)' || true)"
  if [ -n "$POSTTUN_OLD_CONFOPEN_PRESENT" ]; then
    echo "OLD-CONFOPEN-BOUNDARY: STILL-PRESENT — the 4C-52 resolved-pair open widening did not take effect (STOP; no rule widening):"
    printf '%s\n' "$POSTTUN_OLD_CONFOPEN_PRESENT"
    POSTTUN_OLD_CONFOPEN_PRESENT=1
  else
    echo "OLD-CONFOPEN-BOUNDARY: GONE (no rootlesskit_t -> net_conf_t:file open (0x40000) decision in the window's trace span)"
  fi

  # 4C-53: the SAME contract for the phase's own widening — the OLD
  # primary boundary (docker_helper_rootlesskit_t -> tmpfs_t:lnk_file,
  # denied mask 0x800 = unlink, bit 11 of the kernel's static classmap's
  # common layout — the classmap fixture's pinned decode; the canonical
  # 4C-52 run's phase-end NEXT-STARTUP-BOUNDARY record INSIDE the
  # RemoveAll("/etc/resolv.conf") stage's own unlinkat window — the
  # rebuilt /etc/resolv.conf symlink's DESTINATION removal hook) must be
  # GONE anywhere in the window's trace span. The mask anchor is pinned
  # to the literal 0x800 followed by a non-hex/edge (0x8 and 0x80
  # never match; 0x800X masks are different perms); the tclass=lnk_file
  # anchor separates this gate from the dir/file classes; the
  # tcontext=tmpfs_t:s0 anchor separates it from every other type's
  # lnk_file gates (the 4C-50 read gate on the same pair is the 0x2
  # mask, not 0x800). A record here means the 4C-53 widening did not
  # take effect on the loaded policy: STOP and report the actual
  # behavior (no rule widening).
  POSTTUN_OLD_LNKUNLINK_PRESENT="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
    | grep -aE 'tcontext=system_u:object_r:tmpfs_t:s0([ \t]|$)' \
    | grep -a 'tclass=lnk_file' \
    | grep -aE 'denied=0x800([^0-9a-fA-F]|$)' || true)"
  if [ -n "$POSTTUN_OLD_LNKUNLINK_PRESENT" ]; then
    echo "OLD-LNKUNLINK-BOUNDARY: STILL-PRESENT — the 4C-53 rebuild-symlink unlink widening did not take effect (STOP; no rule widening):"
    printf '%s\n' "$POSTTUN_OLD_LNKUNLINK_PRESENT"
    POSTTUN_OLD_LNKUNLINK_PRESENT=1
  else
    echo "OLD-LNKUNLINK-BOUNDARY: GONE (no rootlesskit_t -> tmpfs_t:lnk_file unlink (0x800) decision in the window's trace span)"
  fi

  # 4C-49: the SAME contract for the phase's own grant — the OLD primary
  # boundary (docker_helper_rootlesskit_t -> cgroup_t:dir, denied mask
  # 0x10000 = mounton, bit 16 of the kernel's static dir classmap; the
  # canonical 4C-48 run's record inside the cgroup move-mount's own
  # window) must be GONE anywhere in the window's trace span. The mask
  # anchor is pinned to the literal 0x10000 followed by a non-hex/edge;
  # the tclass=dir anchor separates this gate from the tmpfs
  # lnk_file/filesystem shapes; the tcontext=cgroup_t:s0 anchor (the
  # global type carries no MCS category) separates it from the
  # dir-class mounton gates on the tmp_t/etc_t/tmpfs_t/root_t targets. A
  # record here means the 4C-49 grant did not take effect on the loaded
  # policy: STOP and report the actual behavior (no rule widening).
  POSTTUN_OLD_CGROUPMOUNTON_PRESENT="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
    | grep -aE 'tcontext=system_u:object_r:cgroup_t:s0([ \t]|$)' \
    | grep -a 'tclass=dir' \
    | grep -aE 'denied=0x10000([^0-9a-fA-F]|$)' || true)"
  if [ -n "$POSTTUN_OLD_CGROUPMOUNTON_PRESENT" ]; then
    echo "OLD-CGROUPMOUNTON-BOUNDARY: STILL-PRESENT — the 4C-49 cgroup move-mount mounton grant did not take effect (STOP; no rule widening):"
    printf '%s\n' "$POSTTUN_OLD_CGROUPMOUNTON_PRESENT"
    POSTTUN_OLD_CGROUPMOUNTON_PRESENT=1
  else
    echo "OLD-CGROUPMOUNTON-BOUNDARY: GONE (no rootlesskit_t -> cgroup_t:dir mounton (0x10000) decision in the window's trace span)"
  fi

  # The 4C-42 milestone: a flow-domain mkdirat AFTER T0 returning 0x0
  # means the copy-up temp dir was CREATED — the kernel-stated type of
  # the create hook (tmp_t) now carries the object. Recorded as the
  # ROOTLESSKIT-BIND0-CREATE milestone marker, plus the residue probe
  # (the holder's cleanup may already have removed the dir — its absence
  # is then the cleanup fact, not a milestone refutation).
  POSTTUN_MKDIRAT_OK="$(awk -v t0="$POSTTUN_T0_TRACE_TS" '
    /sys_mkdirat -> / && t0 != "" {
      ts = $4; sub(/:$/, "", ts)
      if (ts + 0 > t0 + 0) print
    }' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -aE "$POSTTUN_FLOW_COMM_GREP" \
    | grep -a '0x0' || true)"
  if [ -n "$POSTTUN_MKDIRAT_OK" ]; then
    echo "MILESTONE: ROOTLESSKIT-BIND0-CREATE=OK — a flow-domain mkdirat returned success:"
    printf '%s\n' "$POSTTUN_MKDIRAT_OK"
  else
    echo "MILESTONE: ROOTLESSKIT-BIND0-CREATE=NOT-REACHED (no successful flow-domain mkdirat in the window's trace span)"
  fi
  echo "--- the /tmp/rootlesskit-b* residue probe at harvest (SID/type/mode when the holder's cleanup has not removed it):"
  ls -ldZ /tmp/rootlesskit-b* 2>/dev/null | head -5 || true
  ls -ld /tmp/rootlesskit-b* 2>/dev/null | head -5 || true
  echo "(end of the residue probe)"

  # 4C-43: the window's mount operations classified by shape — the
  # three-evidence mounts must never be confused by a mount(2)-only
  # gate: A = the granted propagation (mount("none", "/", MS_REC|
  # MS_PRIVATE)); B = the copy-up bind mount (mount("/etc",
  # "/tmp/rootlesskit-b*", MS_BIND|MS_REC) — the 4C-43 grant's owner);
  # C = the tmpfs mount over the copy-up source (the NEXT stage, its
  # own live boundary); D = any other shape.
  echo "--- the window's mount operations, shape-classified (A=propagation B=bind0-copy-up C=tmpfs-over-copy-up-source D=other-mount incl. MS_MOVE; enter lines carry source/target/fstype/flags):"
  awk -v t0="$POSTTUN_T0_TRACE_TS" '
    { ts = $4; sub(/:$/, "", ts)
      if (t0 == "" || ts + 0 <= t0 + 0) next
      print }
  ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
    | grep -aE "$POSTTUN_FLOW_COMM_GREP" \
    | grep -aE 'sys_mount\(|sys_mount ->' \
    | awk '{
        if ($0 ~ /sys_mount\(dev_name:/) {
          lab = "D(other-mount)"
          if ($0 ~ /"none"/ && $0 ~ /dir_name: [^,]*"\/"/ && $0 ~ /flags: 0x44000/) lab = "A(propagation)"
          else if ($0 ~ /"\/etc"/ && $0 ~ /"\/tmp\/rootlesskit-b/ && $0 ~ /flags: 0x5000/) lab = "B(bind0-copy-up)"
          else if ($0 ~ /type: [^,]*"tmpfs"/ && $0 ~ /dir_name: [^,]*"\/etc",/) lab = "C(tmpfs-over-/etc)"
          print lab " | " $0
        } else {
          print "    ret | " $0
        }
      }' \
    | head -24 || true
  echo "(end of the shape-classified mount operations)"

  # ============================================================
  # 4C-49: the CONFINEMENT GATE for the cgroup_t:dir mounton boundary —
  # the PRE-GRANT live proof that the mount authority the next grant
  # would widen is exercised INSIDE the holder's own distinct mount
  # namespace on a recursive-private propagation state, never in the
  # manager/host mount table. The gate is EVIDENCE-ONLY: a BLOCKED gate
  # stops the phase before the semantic delta; no compensating SELinux
  # grants are permitted (the phase contract).
  # Items A..G:
  #   A. the holder (the mount-dancing trace pid) was observed live with
  #      a mount-namespace identity;
  #   B. that mount namespace differs from the manager-side ones (the
  #      harness subshell, the init process, the manager daemon, and the
  #      rootlesskit parent — the parent's ns/mnt is the holder's
  #      inherited-at-fork reference);
  #   C. the propagation mount mount("none", "/", MS_REC|MS_PRIVATE)
  #      returned 0x0 and belongs to the SAME trace pid that performs
  #      the cgroup move-mount (one holder flow);
  #   D. the cgroup move-mount is attempted AFTER the propagation
  #      success (trace-clock order);
  #   E. the move's source /tmp/rksys* was bound FROM /sys/fs/cgroup by
  #      the same holder flow earlier (the MS_BIND|MS_REC pair -> 0x0,
  #      trace-clock order);
  #   F. the move's destination is exactly /sys/fs/cgroup;
  #   G. the host-side mount table is untouched across the window (the
  #      before/after mountinfo diff carries no flow mount and no
  #      /sys/fs/cgroup change).
  # The mountinfo captures of the gate watcher are BEST-EFFORT supporting
  # evidence (the dance window is ~4ms; a tick may miss it) — gate PASS
  # never rests on them; the syscall pairs and the namespace identities
  # are the primary proof.
  # ============================================================
  echo "--- the 4C-49 confinement-gate evidence (pre-grant; the gate items A..G):"
  POSTTUN_GATE_MGR_MNT="$(sed -n 's/^[0-9.]* MGR-IDENTITY pid=[0-9]* ctx=[^ ]* ns\/mnt=\([^ ]*\) .*/\1/p' "$EVIDENCE_DIR/50-posttun-timeline.txt" 2>/dev/null | head -1 || true)"
  POSTTUN_GATE_MGRD_MNT="$(sed -n 's/^[0-9.]* MGR-IDENTITY-DAEMON pid=[0-9]* .* ns\/mnt=\([^ ]*\) .*/\1/p' "$EVIDENCE_DIR/50-posttun-timeline.txt" 2>/dev/null | head -1 || true)"
  POSTTUN_GATE_MGRINIT_MNT="$(sed -n 's/^[0-9.]* MGR-IDENTITY-INIT pid=1 .* ns\/mnt=\([^ ]*\)$/\1/p' "$EVIDENCE_DIR/50-posttun-timeline.txt" 2>/dev/null | head -1 || true)"
  POSTTUN_GATE_PARENT_MNT="$(sed -n 's/^.* pid=[0-9]* comm=rootlesskit .* ns\/mnt=\([^ ]*\) .*/\1/p' "$EVIDENCE_DIR/50-posttun-timeline.txt" 2>/dev/null | head -1 || true)"
  echo "manager-side mount-ns identities (the gate item B references):"
  echo "  harness  ns/mnt=${POSTTUN_GATE_MGR_MNT:-(none)}"
  echo "  init     ns/mnt=${POSTTUN_GATE_MGRINIT_MNT:-(none)}"
  echo "  daemon   ns/mnt=${POSTTUN_GATE_MGRD_MNT:-(none)}"
  echo "  rk-parent ns/mnt=${POSTTUN_GATE_PARENT_MNT:-(none)}"
  # The three mount pairs (the same pair-extraction shape as the
  # milestone extractors: the enter line's SHAPE keys the pair, the
  # paired own exit closes it).
  POSTTUN_GATE_PROP_PAIR="$(awk -v t0="$POSTTUN_T0_TRACE_TS" '
    /sys_mount\(dev_name:/ && t0 != "" {
      ts = $4; sub(/:$/, "", ts)
      if (ts + 0 > t0 + 0 && $0 ~ /dev_name: [^,]*"none"/ && $0 ~ /dir_name: [^,]*"\/",/ && $0 ~ /flags: 0x44000/) {
        pend = 1; pwho = $1; pline = $0; next
      }
      next
    }
    pend && /sys_mount -> / && $1 == pwho {
      print pline; print $0; exit
    }
  ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
  POSTTUN_GATE_CGROUPBIND_PAIR="$(awk -v t0="$POSTTUN_T0_TRACE_TS" '
    /sys_mount\(dev_name:/ && t0 != "" {
      ts = $4; sub(/:$/, "", ts)
      if (ts + 0 > t0 + 0 && $0 ~ /dev_name: [^,]*"\/sys\/fs\/cgroup"/ && $0 ~ /dir_name: [^,]*"\/tmp\/rksys[0-9]+"/ && $0 ~ /flags: 0x5000/) {
        pend = 1; pwho = $1; pline = $0; next
      }
      next
    }
    pend && /sys_mount -> / && $1 == pwho {
      print pline; print $0; exit
    }
  ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
  POSTTUN_GATE_CGROUPMOVE_PAIR="$(awk -v t0="$POSTTUN_T0_TRACE_TS" '
    /sys_mount\(dev_name:/ && t0 != "" {
      ts = $4; sub(/:$/, "", ts)
      if (ts + 0 > t0 + 0 && $0 ~ /dev_name: [^,]*"\/tmp\/rksys[0-9]+"/ && $0 ~ /dir_name: [^,]*"\/sys\/fs\/cgroup"/ && $0 ~ /flags: 0x2000/) {
        pend = 1; pwho = $1; pline = $0; next
      }
      next
    }
    pend && /sys_mount -> / && $1 == pwho {
      print pline; print $0; exit
    }
  ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
  POSTTUN_GATE_PROP_TS="$(printf '%s\n' "$POSTTUN_GATE_PROP_PAIR" | head -1 | awk '{ ts = $4; sub(/:$/, "", ts); print ts }' 2>/dev/null || true)"
  POSTTUN_GATE_PROP_RET="$(printf '%s\n' "$POSTTUN_GATE_PROP_PAIR" | tail -1 | awk '{print $NF}' 2>/dev/null || true)"
  POSTTUN_GATE_BIND_TS="$(printf '%s\n' "$POSTTUN_GATE_CGROUPBIND_PAIR" | head -1 | awk '{ ts = $4; sub(/:$/, "", ts); print ts }' 2>/dev/null || true)"
  POSTTUN_GATE_BIND_RET="$(printf '%s\n' "$POSTTUN_GATE_CGROUPBIND_PAIR" | tail -1 | awk '{print $NF}' 2>/dev/null || true)"
  POSTTUN_GATE_MOVE_TS="$(printf '%s\n' "$POSTTUN_GATE_CGROUPMOVE_PAIR" | head -1 | awk '{ ts = $4; sub(/:$/, "", ts); print ts }' 2>/dev/null || true)"
  POSTTUN_GATE_MOVE_RET="$(printf '%s\n' "$POSTTUN_GATE_CGROUPMOVE_PAIR" | tail -1 | awk '{print $NF}' 2>/dev/null || true)"
  POSTTUN_GATE_MOVE_ENTER_TS="$(printf '%s\n' "$POSTTUN_GATE_CGROUPMOVE_PAIR" | head -1 | awk '{ ts = $4; sub(/:$/, "", ts); print ts }' 2>/dev/null || true)"
  POSTTUN_GATE_MOVE_EXIT_TS="$(printf '%s\n' "$POSTTUN_GATE_CGROUPMOVE_PAIR" | tail -1 | awk '{ ts = $4; sub(/:$/, "", ts); print ts }' 2>/dev/null || true)"
  echo "the holder flow's mount pairs (the trace facts; the MS_MOVE ret stays the BOUNDARY fact, not a gate item):"
  printf '%s\n' "${POSTTUN_GATE_PROP_PAIR:-(the propagation pair was never recorded)}"
  printf '%s\n' "${POSTTUN_GATE_CGROUPBIND_PAIR:-(the cgroup bind pair was never recorded)}"
  printf '%s\n' "${POSTTUN_GATE_CGROUPMOVE_PAIR:-(the cgroup move-mount pair was never recorded)}"
  # The same-trace-pid binding: the three pairs must carry ONE who (the
  # mount-dancing holder).
  POSTTUN_GATE_PROP_WHO="$(printf '%s\n' "$POSTTUN_GATE_PROP_PAIR" | head -1 | awk '{print $1}' 2>/dev/null || true)"
  POSTTUN_GATE_BIND_WHO="$(printf '%s\n' "$POSTTUN_GATE_CGROUPBIND_PAIR" | head -1 | awk '{print $1}' 2>/dev/null || true)"
  POSTTUN_GATE_MOVE_WHO="$(printf '%s\n' "$POSTTUN_GATE_CGROUPMOVE_PAIR" | head -1 | awk '{print $1}' 2>/dev/null || true)"
  POSTTUN_GATE_DANCE_PID="$(printf '%s' "$POSTTUN_GATE_MOVE_WHO" | sed 's/^.*-//' 2>/dev/null || true)"
  # The holder's recorded mount-ns identities: every distinct ns/mnt value
  # the gate watcher recorded for the dance pid (the last tick's value is
  # the dance-time namespace). The GATE-HOLDER-IDENT record (the queued
  # probe's result) is the same evidence, taken at the identification
  # moment; either source proves the recorded ns/mnt.
  POSTTUN_GATE_HOLDER_MNTS="$(grep -a "GATE-TICK pid=$POSTTUN_GATE_DANCE_PID " "$EVIDENCE_DIR/51-confinement-gate.txt" 2>/dev/null | sed -n 's/.* ns\/mnt=\([^ ]*\) .*/\1/p' | sort -u || true)"
  POSTTUN_GATE_HOLDER_MNT_LAST="$(printf '%s\n' "$POSTTUN_GATE_HOLDER_MNTS" | tail -1 || true)"
  POSTTUN_GATE_HOLDER_IDENT_LINE="$(grep -a "GATE-HOLDER-IDENT pid=$POSTTUN_GATE_DANCE_PID " "$EVIDENCE_DIR/51-confinement-gate.txt" 2>/dev/null | head -1 || true)"
  POSTTUN_GATE_HOLDER_IDENT_MNT="$(printf '%s\n' "$POSTTUN_GATE_HOLDER_IDENT_LINE" | sed -n 's/.* ns\/mnt=\([^ ]*\) ns\/user=.*/\1/p' || true)"
  if [ -n "$POSTTUN_GATE_HOLDER_IDENT_MNT" ]; then
    POSTTUN_GATE_HOLDER_MNT_EFF="$POSTTUN_GATE_HOLDER_IDENT_MNT"
  else
    POSTTUN_GATE_HOLDER_MNT_EFF="$POSTTUN_GATE_HOLDER_MNT_LAST"
  fi
  POSTTUN_GATE_HOLDER_FIRST_LINE="$(grep -a "GATE-HOLDER-FIRST pid=$POSTTUN_GATE_DANCE_PID " "$EVIDENCE_DIR/51-confinement-gate.txt" 2>/dev/null | head -1 || true)"
  echo "the holder's watcher records (pid=$POSTTUN_GATE_DANCE_PID from the move-mount pair's trace who):"
  printf '%s\n' "${POSTTUN_GATE_HOLDER_FIRST_LINE:-(the gate watcher never recorded the dance pid — identity missing)}"
  printf '%s\n' "${POSTTUN_GATE_HOLDER_IDENT_LINE:-(no GATE-HOLDER-IDENT record for the dance pid — the queued ns probe did not return for it)}"
  echo "  the holder's distinct ns/mnt values: ${POSTTUN_GATE_HOLDER_MNTS:-(none)}"
  echo "  the holder's last-observed ns/mnt:   ${POSTTUN_GATE_HOLDER_MNT_LAST:-(none)}"
  echo "  the holder's effective ns/mnt:       ${POSTTUN_GATE_HOLDER_MNT_EFF:-(none)}"
  # The ns/mnt transition records (the unshare's live trace, when caught):
  POSTTUN_GATE_HOLDER_NSMNT_LINES="$(grep -a "GATE-NSMNT pid=$POSTTUN_GATE_DANCE_PID " "$EVIDENCE_DIR/51-confinement-gate.txt" 2>/dev/null || true)"
  printf '%s\n' "${POSTTUN_GATE_HOLDER_NSMNT_LINES:-(no ns/mnt transition of the dance pid was caught by a watcher tick — the first tick may have seen the post-unshare namespace; the distinct-ns facts above are the proof)}"
  # The watcher's own best-effort mountinfo captures for the holder:
  POSTTUN_GATE_HOLDER_MOUNTINFO_COUNT="$(grep -ac "GATE-MOUNTINFO pid=$POSTTUN_GATE_DANCE_PID " "$EVIDENCE_DIR/51-confinement-gate.txt" 2>/dev/null || true)"
  POSTTUN_GATE_HOLDER_RKSYS_SEEN="$(awk -v pid="$POSTTUN_GATE_DANCE_PID" '
    /^[0-9.]+ GATE-MOUNTINFO pid=/ { on = ($0 ~ ("pid=" pid " ")) ? 1 : 0; next }
    on && /GATE-MOUNTINFO-LINE/ { print }
  ' "$EVIDENCE_DIR/51-confinement-gate.txt" 2>/dev/null | grep -a '/tmp/rksys' | tail -2 || true)"
  echo "  the holder's distinct mountinfo captures: ${POSTTUN_GATE_HOLDER_MOUNTINFO_COUNT:-0} (best-effort)"
  if [ -n "$POSTTUN_GATE_HOLDER_RKSYS_SEEN" ]; then
    echo "  the rksys bind is LIVE in a captured holder mountinfo (the item E provenance, seen live):"
    printf '%s\n' "$POSTTUN_GATE_HOLDER_RKSYS_SEEN" | sed 's/^/    /'
  else
    echo "  the rksys bind: not caught in a captured holder mountinfo (best-effort; the item E trace pair is the proof)"
  fi
  # The gate items, one computed verdict each:
  POSTTUN_GATE_A=0; POSTTUN_GATE_B=0; POSTTUN_GATE_C=0; POSTTUN_GATE_D=0
  POSTTUN_GATE_E=0; POSTTUN_GATE_F=0; POSTTUN_GATE_G=0
  # A: the holder identity exists and carries a recorded ns/mnt (from a
  # GATE-TICK or a GATE-HOLDER-IDENT record; "(none)" and the pre-probe
  # "pending" placeholder are both no-evidence values).
  if [ -n "$POSTTUN_GATE_DANCE_PID" ] && [ -n "$POSTTUN_GATE_HOLDER_FIRST_LINE" ] \
    && printf '%s\n' "$POSTTUN_GATE_HOLDER_FIRST_LINE" | grep -aq 'docker_helper_rootlesskit_t:' \
    && [ -n "$POSTTUN_GATE_HOLDER_MNT_EFF" ] && [ "$POSTTUN_GATE_HOLDER_MNT_EFF" != "(none)" ] \
    && [ "$POSTTUN_GATE_HOLDER_MNT_EFF" != "pending" ]; then
    POSTTUN_GATE_A=1
  fi
  # B: the holder's dance-time ns/mnt differs from EVERY manager-side
  # reference (harness, init, daemon, rk-parent).
  if [ "$POSTTUN_GATE_A" = 1 ] \
    && [ -n "$POSTTUN_GATE_MGR_MNT" ] && [ "$POSTTUN_GATE_HOLDER_MNT_EFF" != "$POSTTUN_GATE_MGR_MNT" ] \
    && [ -n "$POSTTUN_GATE_MGRINIT_MNT" ] && [ "$POSTTUN_GATE_HOLDER_MNT_EFF" != "$POSTTUN_GATE_MGRINIT_MNT" ] \
    && [ -n "$POSTTUN_GATE_MGRD_MNT" ] && [ "$POSTTUN_GATE_HOLDER_MNT_EFF" != "$POSTTUN_GATE_MGRD_MNT" ] \
    && [ -n "$POSTTUN_GATE_PARENT_MNT" ] && [ "$POSTTUN_GATE_HOLDER_MNT_EFF" != "$POSTTUN_GATE_PARENT_MNT" ]; then
    POSTTUN_GATE_B=1
  fi
  # C: the propagation pair exists, returned 0x0, and belongs to the same
  # dance chain as the cgroup move-mount. The dance chain is proven by
  # the same trace who, or by the trace's own fork edge (the reproduced
  # run 37326112431 shape: the dance's mount sequence split across the
  # dance parent and its forked worker child — propagation + /etc bind by
  # exe-3841, tmpfs + .ro move + cgroup pair by its child exe-3872, the
  # shared /tmp/rootlesskit-b staging name binding the two halves; all
  # gate-relevant mount returns were 0x0, so pid equality was the wrong
  # proxy for one confined dance chain).
  POSTTUN_GATE_DANCE_FORK_EDGE=""
  if [ -n "$POSTTUN_GATE_PROP_WHO" ] && [ -n "$POSTTUN_GATE_MOVE_WHO" ] \
    && [ "$POSTTUN_GATE_PROP_WHO" != "$POSTTUN_GATE_MOVE_WHO" ]; then
    POSTTUN_GATE_PROP_PID="$(printf '%s' "$POSTTUN_GATE_PROP_WHO" | sed 's/^.*-//' 2>/dev/null || true)"
    POSTTUN_GATE_MOVE_PID="$(printf '%s' "$POSTTUN_GATE_MOVE_WHO" | sed 's/^.*-//' 2>/dev/null || true)"
    # Either direction: run 37326112431 reproduced the parent->worker
    # edge (exe-3841 forked exe-3872), run 37332939389 reproduced the
    # reverse (the dance parent exe-3856 forked the propagation stage
    # exe-3907). The chain linkage is what the item proves.
    POSTTUN_GATE_DANCE_FORK_EDGE="$(grep -aE "sched_process_fork: .* pid=($POSTTUN_GATE_PROP_PID|$POSTTUN_GATE_MOVE_PID) child_comm=[^ ]+ child_pid=($POSTTUN_GATE_MOVE_PID|$POSTTUN_GATE_PROP_PID)( |\$)" "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | head -1 || true)"
    if [ -n "$POSTTUN_GATE_DANCE_FORK_EDGE" ]; then
      echo "the dance chain's fork edge (the trace's own linkage between the propagation and move-mount stages):"
      printf '%s\n' "$POSTTUN_GATE_DANCE_FORK_EDGE"
    fi
  fi
  if [ "$POSTTUN_GATE_PROP_RET" = "0x0" ] && [ -n "$POSTTUN_GATE_PROP_WHO" ] \
    && { [ "$POSTTUN_GATE_PROP_WHO" = "$POSTTUN_GATE_MOVE_WHO" ] || [ -n "$POSTTUN_GATE_DANCE_FORK_EDGE" ]; }; then
    POSTTUN_GATE_C=1
  fi
  # D: the move attempt is AFTER the propagation success (trace clock).
  if [ -n "$POSTTUN_GATE_PROP_TS" ] && [ -n "$POSTTUN_GATE_MOVE_TS" ] \
    && awk -v a="$POSTTUN_GATE_MOVE_TS" -v b="$POSTTUN_GATE_PROP_TS" 'BEGIN { exit !(a + 0 > b + 0) }' 2>/dev/null; then
    POSTTUN_GATE_D=1
  fi
  # E: the rksys bind pair exists (from /sys/fs/cgroup, MS_BIND|MS_REC),
  # returned 0x0, belongs to the same trace who, and precedes the move.
  if [ "$POSTTUN_GATE_BIND_RET" = "0x0" ] && [ -n "$POSTTUN_GATE_BIND_WHO" ] \
    && [ "$POSTTUN_GATE_BIND_WHO" = "$POSTTUN_GATE_MOVE_WHO" ] \
    && awk -v a="$POSTTUN_GATE_MOVE_TS" -v b="$POSTTUN_GATE_BIND_TS" 'BEGIN { exit !(a + 0 > b + 0) }' 2>/dev/null; then
    POSTTUN_GATE_E=1
  fi
  # F: the move's destination is exactly /sys/fs/cgroup (the pair's own
  # enter line, extracted verbatim above, carries dir_name "/sys/fs/cgroup").
  if printf '%s\n' "$POSTTUN_GATE_CGROUPMOVE_PAIR" | head -1 | grep -aq 'dir_name: [^,]*"/sys/fs/cgroup"'; then
    POSTTUN_GATE_F=1
  fi
  # G: the host-side mount table is untouched across the window.
  {
    echo "=== the host-side mount table AFTER the window (the 4C-49 confinement gate's untouched-host-table proof) ==="
    echo "--- /proc/1/mountinfo"
    cat /proc/1/mountinfo 2>/dev/null || true
    echo "--- /proc/self/mountinfo (the harness's own namespace)"
    cat /proc/self/mountinfo 2>/dev/null || true
  } > "$EVIDENCE_DIR/55-host-mountinfo-after.txt" 2>&1
  POSTTUN_GATE_HOST_DIFF="$(diff "$EVIDENCE_DIR/55-host-mountinfo-before.txt" "$EVIDENCE_DIR/55-host-mountinfo-after.txt" 2>/dev/null \
    | grep -aE '^[<>].*(/tmp/rksys|/tmp/rootlesskit-b|/sys/fs/cgroup)' || true)"
  if [ -n "$POSTTUN_GATE_MGR_MNT" ] && [ -s "$EVIDENCE_DIR/55-host-mountinfo-before.txt" ] \
    && [ -s "$EVIDENCE_DIR/55-host-mountinfo-after.txt" ] && [ -z "$POSTTUN_GATE_HOST_DIFF" ]; then
    POSTTUN_GATE_G=1
    echo "  the host-table diff (before vs after; the flow-mount/cgroup shapes): CLEAN (no diff line)"
  else
    echo "  the host-table diff (before vs after; the flow-mount/cgroup shapes):"
    printf '%s\n' "${POSTTUN_GATE_HOST_DIFF:-(the diff itself is unavailable)}"
  fi
  echo "GATE 4C-49-CONFINEMENT items: A=$POSTTUN_GATE_A B=$POSTTUN_GATE_B C=$POSTTUN_GATE_C D=$POSTTUN_GATE_D E=$POSTTUN_GATE_E F=$POSTTUN_GATE_F G=$POSTTUN_GATE_G"
  if [ "$POSTTUN_GATE_A" = 1 ] && [ "$POSTTUN_GATE_B" = 1 ] && [ "$POSTTUN_GATE_C" = 1 ] \
    && [ "$POSTTUN_GATE_D" = 1 ] && [ "$POSTTUN_GATE_E" = 1 ] && [ "$POSTTUN_GATE_F" = 1 ] \
    && [ "$POSTTUN_GATE_G" = 1 ]; then
    echo "GATE 4C-49-CONFINEMENT: PASS (all seven items proven live; the authority remains type-wide for cgroup_t and the confinement is the holder's own mount namespace + recursive-private propagation state — the scope statement, not a TE property)"
    POSTTUN_GATE_VERDICT=PASS
  else
    echo "GATE 4C-49-CONFINEMENT: BLOCKED/CONFINEMENT-NOT-PROVEN (the failed items are recorded above; NO cgroup_t:dir mounton authority may be granted and no compensating SELinux grant is permitted)"
    POSTTUN_GATE_VERDICT=BLOCKED
  fi

  # The B milestone: the flow-domain mount whose source is /etc, whose
  # target is the copy-up temp dir, with MS_BIND|MS_REC (0x5000),
  # paired with ITS OWN exit — a 0x0 ret makes
  # ROOTLESSKIT-BIND0-BIND-MOUNT=OK. Absence of a denial without a
  # successful syscall is NOT a pass.
  POSTTUN_BINDMOUNT_PAIR="$(awk -v t0="$POSTTUN_T0_TRACE_TS" '
    /sys_mount\(dev_name:/ && t0 != "" {
      ts = $4; sub(/:$/, "", ts)
      if (ts + 0 > t0 + 0 && $0 ~ /dev_name: [^,]*"\/etc"/ && $0 ~ /dir_name: [^,]*"\/tmp\/rootlesskit-b/ && $0 ~ /flags: 0x5000/) {
        pend = 1; pwho = $1; pline = $0; next
      }
      next
    }
    pend && /sys_mount -> / && $1 == pwho {
      print pline; print $0; exit
    }
  ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
  POSTTUN_BINDMOUNT_RET="$(printf '%s\n' "$POSTTUN_BINDMOUNT_PAIR" | tail -1 | awk '{print $NF}' 2>/dev/null || true)"
  if [ "$POSTTUN_BINDMOUNT_RET" = "0x0" ]; then
    echo "MILESTONE: ROOTLESSKIT-BIND0-BIND-MOUNT=OK — the copy-up bind mount returned success:"
    printf '%s\n' "$POSTTUN_BINDMOUNT_PAIR"
    POSTTUN_BINDMOUNT_OK=1
  else
    echo "MILESTONE: ROOTLESSKIT-BIND0-BIND-MOUNT=NOT-REACHED (ret=${POSTTUN_BINDMOUNT_RET:-(the B-shaped mount was never recorded)}):"
    printf '%s\n' "${POSTTUN_BINDMOUNT_PAIR:-(the B-shaped mount pair was never recorded)}"
    POSTTUN_BINDMOUNT_OK=0
  fi

  # The C milestone: the flow-domain tmpfs mount OVER /etc (fstype
  # "tmpfs", flags 0, source "none"), paired with ITS OWN exit — a 0x0
  # ret makes ROOTLESSKIT-COPYUP-TMPFS-MOUNT=OK. The exact syscall
  # SHAPE keys the gate (fstype+target), not the mount-call order; the
  # phase's PASS needs B ok AND C ok AND the tmpfs_t:filesystem mount
  # gate clean (the 4C-45 grant's own boundary must not reappear).
  POSTTUN_TMPFSMOUNT_PAIR="$(awk -v t0="$POSTTUN_T0_TRACE_TS" '
    /sys_mount\(dev_name:/ && t0 != "" {
      ts = $4; sub(/:$/, "", ts)
      if (ts + 0 > t0 + 0 && $0 ~ /type: [^,]*"tmpfs"/ && $0 ~ /dir_name: [^,]*"\/etc",/) {
        pend = 1; pwho = $1; pline = $0; next
      }
      next
    }
    pend && /sys_mount -> / && $1 == pwho {
      print pline; print $0; exit
    }
  ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
  POSTTUN_TMPFSMOUNT_RET="$(printf '%s\n' "$POSTTUN_TMPFSMOUNT_PAIR" | tail -1 | awk '{print $NF}' 2>/dev/null || true)"
  if [ "$POSTTUN_TMPFSMOUNT_RET" = "0x0" ]; then
    echo "MILESTONE: ROOTLESSKIT-COPYUP-TMPFS-MOUNT=OK — the copy-up tmpfs mount returned success:"
    printf '%s\n' "$POSTTUN_TMPFSMOUNT_PAIR"
    POSTTUN_TMPFSMOUNT_OK=1
  else
    echo "MILESTONE: ROOTLESSKIT-COPYUP-TMPFS-MOUNT=NOT-REACHED (ret=${POSTTUN_TMPFSMOUNT_RET:-(the C-shaped mount was never recorded)}):"
    printf '%s\n' "${POSTTUN_TMPFSMOUNT_PAIR:-(the C-shaped mount pair was never recorded)}"
    POSTTUN_TMPFSMOUNT_OK=0
  fi
  echo "--- the mountinfo probe at harvest (any process whose mount table still carries the bind0 mount point or the rksys bind; best-effort — the holder's namespace dies with it):"
  for mp in /proc/[0-9]*/mountinfo; do
    [ -r "$mp" ] || continue
    if grep -aqE '/tmp/rootlesskit-b|/tmp/rksys' "$mp" 2>/dev/null; then
      echo "  (from $mp):"
      grep -aE '/tmp/rootlesskit-b|/tmp/rksys' "$mp" 2>/dev/null | head -3 | sed 's/^/    /'
    fi
  done 2>/dev/null | head -12 || true
  echo "(end of the mountinfo probe)"

  # The 4C-46 milestone: the flow-domain `.ro` mkdirat inside the
  # tmpfs-over-/etc (pathname /etc/.ro<digits>, the canonical 4C-45
  # run's denial owner), paired with ITS OWN exit — a 0x0 ret makes
  # ROOTLESSKIT-COPYUP-RO-DIR-CREATE=OK. The exact syscall SHAPE keys
  # the gate (path shape), not the mkdir-call order; the phase's PASS
  # needs C ok AND this ok AND the tmpfs_t:dir create gate clean.
  POSTTUN_RODIR_PAIR="$(awk -v t0="$POSTTUN_T0_TRACE_TS" '
    /sys_mkdirat\(dfd:/ && t0 != "" {
      ts = $4; sub(/:$/, "", ts)
      if (ts + 0 > t0 + 0 && $0 ~ /pathname: [^,]*"\/etc\/\.ro[0-9]+"/) {
        pend = 1; pwho = $1; pline = $0; next
      }
      next
    }
    pend && /sys_mkdirat -> / && $1 == pwho {
      print pline; print $0; exit
    }
  ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
  POSTTUN_RODIR_RET="$(printf '%s\n' "$POSTTUN_RODIR_PAIR" | tail -1 | awk '{print $NF}' 2>/dev/null || true)"
  if [ "$POSTTUN_RODIR_RET" = "0x0" ]; then
    echo "MILESTONE: ROOTLESSKIT-COPYUP-RO-DIR-CREATE=OK — the copy-up .ro mkdirat returned success:"
    printf '%s\n' "$POSTTUN_RODIR_PAIR"
    POSTTUN_RODIR_OK=1
  else
    echo "MILESTONE: ROOTLESSKIT-COPYUP-RO-DIR-CREATE=NOT-REACHED (ret=${POSTTUN_RODIR_RET:-(the .ro-shaped mkdirat was never recorded)}):"
    printf '%s\n' "${POSTTUN_RODIR_PAIR:-(the .ro-shaped mkdirat pair was never recorded)}"
    POSTTUN_RODIR_OK=0
  fi

  # The 4C-46 MS_MOVE milestone (record-only per the phase contract —
  # not a pass gate): the flow-domain move-mount of bind0 onto the
  # freshly created .ro dir. The SHAPE keys the extractor (source
  # /tmp/rootlesskit-b* -> target /etc/.ro*, dev_name+dir_name), the
  # flags are RECORDED (MS_MOVE expected, numeric patterns not relied
  # on); a paired exit ret 0x0 makes ROOTLESSKIT-COPYUP-MOVE-MOUNT=OK.
  POSTTUN_MOVEMOUNT_PAIR="$(awk -v t0="$POSTTUN_T0_TRACE_TS" '
    /sys_mount\(dev_name:/ && t0 != "" {
      ts = $4; sub(/:$/, "", ts)
      if (ts + 0 > t0 + 0 && $0 ~ /dev_name: [^,]*"\/tmp\/rootlesskit-b/ && $0 ~ /dir_name: [^,]*"\/etc\/\.ro[0-9]+"/) {
        pend = 1; pwho = $1; pline = $0; next
      }
      next
    }
    pend && /sys_mount -> / && $1 == pwho {
      print pline; print $0; exit
    }
  ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
  POSTTUN_MOVEMOUNT_RET="$(printf '%s\n' "$POSTTUN_MOVEMOUNT_PAIR" | tail -1 | awk '{print $NF}' 2>/dev/null || true)"
  if [ -n "$POSTTUN_MOVEMOUNT_PAIR" ]; then
    echo "--- the MS_MOVE D-shape record (source+target+flags recorded; the pair's ret decides the milestone):"
    printf '%s\n' "$POSTTUN_MOVEMOUNT_PAIR"
    if [ "$POSTTUN_MOVEMOUNT_RET" = "0x0" ]; then
      echo "MILESTONE: ROOTLESSKIT-COPYUP-MOVE-MOUNT=OK — the move mount returned success:"
      POSTTUN_MOVEMOUNT_OK=1
    else
      echo "MILESTONE: ROOTLESSKIT-COPYUP-MOVE-MOUNT=NOT-REACHED (ret=$POSTTUN_MOVEMOUNT_RET — the D-shaped mount failed at its own hook; the pair above is the boundary's owner syscall record)"
      POSTTUN_MOVEMOUNT_OK=0
    fi
  else
    echo "MILESTONE: ROOTLESSKIT-COPYUP-MOVE-MOUNT=NOT-REACHED (the D-shaped move-mount pair was never recorded — the flow did not reach the move stage)"
    POSTTUN_MOVEMOUNT_OK=0
  fi

  # The 4C-48 milestone: the rebuild stage's first symlink creation —
  # the flow-domain symlinkat whose oldname targets the .ro mount and
  # whose newname recreates an original /etc entry, paired with ITS OWN
  # exit — a 0x0 ret makes ROOTLESSKIT-COPYUP-SYMLINK-CREATE=OK. The
  # SHAPE keys the gate (source .ro + destination /etc), not the
  # symlink-call order; repeated symlinkat calls on the same granted
  # surface are ONE stage (the 4C-48 contract: the first successful
  # rebuild symlink proves the stage). Absence without a successful
  # syscall is not a pass.
  POSTTUN_SYMLINK_PAIR="$(awk -v t0="$POSTTUN_T0_TRACE_TS" '
    /sys_symlinkat\(oldname:/ && t0 != "" {
      ts = $4; sub(/:$/, "", ts)
      if (ts + 0 > t0 + 0 && $0 ~ /oldname: [^,]*"[^"]*\.ro[0-9]+\// && $0 ~ /newname: [^,]*"\/etc\//) {
        pend = 1; pwho = $1; pline = $0; next
      }
      next
    }
    pend && /sys_symlinkat -> / && $1 == pwho {
      print pline; print $0; exit
    }
  ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
  POSTTUN_SYMLINK_RET="$(printf '%s\n' "$POSTTUN_SYMLINK_PAIR" | tail -1 | awk '{print $NF}' 2>/dev/null || true)"
  if [ "$POSTTUN_SYMLINK_RET" = "0x0" ]; then
    echo "MILESTONE: ROOTLESSKIT-COPYUP-SYMLINK-CREATE=OK — the rebuild symlink creation returned success:"
    printf '%s\n' "$POSTTUN_SYMLINK_PAIR"
    POSTTUN_SYMLINK_OK=1
  else
    echo "MILESTONE: ROOTLESSKIT-COPYUP-SYMLINK-CREATE=NOT-REACHED (ret=${POSTTUN_SYMLINK_RET:-(the rebuild-shaped symlinkat was never recorded)}):"
    printf '%s\n' "${POSTTUN_SYMLINK_PAIR:-(the rebuild-shaped symlinkat pair was never recorded)}"
    POSTTUN_SYMLINK_OK=0
  fi

  # The 4C-49 milestone: the cgroup preservation move-mount — the flow's
  # own rksys bind (the /sys/fs/cgroup -> /tmp/rksys<digits>
  # MS_BIND|MS_REC pair, extracted by the confinement gate above) and the
  # MS_MOVE of that bind onto the exact /sys/fs/cgroup target, paired
  # with ITS OWN exit. ROOTLESSKIT-CGROUP-MOVE-MOUNT=OK requires ALL of:
  #   - the cgroup bind returned 0x0 (the source provenance is live);
  #   - the MS_MOVE returned 0x0 (the move itself succeeded);
  #   - NO cgroup_t:dir mounton denial inside the exact MS_MOVE window
  #     (between the move's enter and its own exit);
  #   - the production flow went further: a later non-cleanup production
  #     enter of the same trace who (the next stage began).
  # A missing denial alone is NOT a pass; a present denial inside the
  # window means the grant did not take effect on the loaded policy.
  echo "--- the 4C-49 cgroup move-mount objective (bind pair + MS_MOVE pair + the exact window's records):"
  POSTTUN_CGROUPMOVE_WINDOW_DENIAL=""
  if [ -n "$POSTTUN_GATE_MOVE_ENTER_TS" ] && [ -n "$POSTTUN_GATE_MOVE_EXIT_TS" ]; then
    POSTTUN_CGROUPMOVE_WINDOW_DENIAL="$(awk -v a="$POSTTUN_GATE_MOVE_ENTER_TS" -v b="$POSTTUN_GATE_MOVE_EXIT_TS" '
      { ts = $4; sub(/:$/, "", ts)
        if (ts + 0 < a + 0 || ts + 0 > b + 0) next
        print }
    ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
      | grep -a 'selinux_audited:' \
      | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' \
      | grep -a 'tcontext=system_u:object_r:cgroup_t:s0' \
      | grep -a 'tclass=dir' \
      | grep -aE 'denied=0x10000([^0-9a-fA-F]|$)' || true)"
  fi
  POSTTUN_CGROUPMOVE_CONTINUATION=""
  if [ -n "$POSTTUN_GATE_MOVE_WHO" ] && [ -n "$POSTTUN_GATE_MOVE_EXIT_TS" ]; then
    POSTTUN_CGROUPMOVE_CONTINUATION="$(awk -v who="$POSTTUN_GATE_MOVE_WHO" -v te="$POSTTUN_GATE_MOVE_EXIT_TS" '
      $1 != who { next }
      { ts = $4; sub(/:$/, "", ts)
        if (ts + 0 <= te + 0) next
        if ($0 !~ /sys_[a-z0-9_]+\(/) next
        nm = $0; sub(/.*sys_/, "", nm); sub(/\(.*/, "", nm)
        if (nm ~ /^(unlink|unlinkat|rmdir)$/ && $0 ~ /"\/tmp\//) next
        if (nm ~ /^(unlink|unlinkat|rmdir|openat|openat2|getdents64|newfstatat|statx|readlink)$/ && $0 ~ /\/tmp\/rootlesskit-b/) next
        if (nm ~ /^(openat|openat2)$/ && $0 ~ /"\/tmp",/) next
        if (nm ~ /^(mount|mkdir|mkdirat|umount2|umount|rename|getdents64|openat|openat2|newfstatat|statx|unlink|unlinkat|rmdir|symlink|symlinkat|readlink|execve|socket|open|setns|ioctl)$/) {
          print; exit
        }
      }' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | head -1 || true)"
  fi
  POSTTUN_CGROUPMOVE_OK=0
  if [ "$POSTTUN_GATE_BIND_RET" = "0x0" ] && [ "$POSTTUN_GATE_MOVE_RET" = "0x0" ] \
    && [ -z "$POSTTUN_CGROUPMOVE_WINDOW_DENIAL" ] && [ -n "$POSTTUN_CGROUPMOVE_CONTINUATION" ]; then
    POSTTUN_CGROUPMOVE_OK=1
  fi
  echo "  the cgroup bind pair:"
  printf '%s\n' "${POSTTUN_GATE_CGROUPBIND_PAIR:-(the cgroup bind pair was never recorded)}"
  echo "  the cgroup MS_MOVE pair:"
  printf '%s\n' "${POSTTUN_GATE_CGROUPMOVE_PAIR:-(the cgroup MS_MOVE pair was never recorded)}"
  if [ -n "$POSTTUN_CGROUPMOVE_WINDOW_DENIAL" ]; then
    echo "  the exact MS_MOVE window carries a cgroup_t:dir mounton denial (the grant did not take effect):"
    printf '%s\n' "$POSTTUN_CGROUPMOVE_WINDOW_DENIAL"
  else
    echo "  the exact MS_MOVE window: NO cgroup_t:dir mounton denial"
  fi
  if [ "$POSTTUN_CGROUPMOVE_OK" = 1 ]; then
    echo "MILESTONE: ROOTLESSKIT-CGROUP-MOVE-MOUNT=OK — the cgroup bind and the MS_MOVE both returned success, the exact window is clean, and the flow continued:"
    echo "  the first post-move production enter (the next stage began):"
    printf '%s\n' "$POSTTUN_CGROUPMOVE_CONTINUATION"
  else
    echo "MILESTONE: ROOTLESSKIT-CGROUP-MOVE-MOUNT=NOT-REACHED (bind-ret=${POSTTUN_GATE_BIND_RET:-(none)} move-ret=${POSTTUN_GATE_MOVE_RET:-(none)} window-denial=$([ -n "$POSTTUN_CGROUPMOVE_WINDOW_DENIAL" ] && echo PRESENT || echo absent) continuation=$([ -n "$POSTTUN_CGROUPMOVE_CONTINUATION" ] && echo present || echo absent))"
  fi

  # The 4C-50 milestone: the startup's first /etc read —
  # generateEtcHosts()'s os.ReadFile("/etc/hosts") — the FULL read
  # path, not just the link hook. The extractor pairs the flow-domain
  # openat whose pathname is exactly "/etc/hosts" with O_RDONLY against
  # ITS OWN exit (an fd on success — the trace's syscall rets are hex;
  # any 0xf-prefixed ret is an error), then follows THAT fd through the
  # read/readv windows: an enter queues its fd (decimal in the enter
  # records), an exit pops the most recent pending enter (the flow's
  # read stage is sequential, so the pairing is exact) and only the
  # hosts fd's rets count. ROOTLESSKIT-ETC-HOSTS-READ=OK requires ALL
  # of:
  #   - the openat pair returned an fd (the 4C-50 link-traversal hook
  #     passed — the widening's own live proof);
  #   - at least one read on that fd returned > 0 bytes (the content
  #     was actually read);
  #   - the fd's read stream reached its end on the traced fd: a 0x0
  #     (EOF) read or the close(2) of that fd;
  #   - NO tmpfs_t:lnk_file read denial anywhere in the window (the
  #     OLD-LNKREAD gone-gate above);
  #   - NO net_conf_t:file read denial anywhere in the window (the
  #     OLD-CONFFILEREAD gone-gate above — the 4C-51 read hook's own
  #     regression guard);
  #   - NO net_conf_t:file open denial anywhere in the window (the
  #     OLD-CONFOPEN gone-gate above — the 4C-52 open hook's own
  #     regression guard);
  #   - the production flow went further: a later non-cleanup
  #     production enter of the same trace who.
  # A missing denial alone is NOT a pass. An openat that fails at a
  # DEEPER hook (the resolved target's own class/type — the next
  # boundary, whatever the live trace proves it to be) keeps this
  # milestone NOT-REACHED with the reached stage recorded; the phase's
  # own semantic delta is then proven by the gone-gates, and the phase
  # STOPs there (the 4C-50 contract: no compensating grant). With the
  # 4C-52 pair in place the openat is expected to return an fd and the
  # milestone to reach OK — a NOT-REACHED with fd=none now means one of
  # the pair's hooks failed live (a regression, not an expected
  # boundary).
  echo "--- the 4C-50 /etc/hosts read objective (the openat pair, then the fd's own read stream, then the continuation):"
  POSTTUN_HOSTSOPEN_PAIR="$(awk -v t0="$POSTTUN_T0_TRACE_TS" '
    /sys_openat\(/ && t0 != "" {
      ts = $4; sub(/:$/, "", ts)
      if (ts + 0 > t0 + 0 && $0 ~ /filename: [^,]*"\/etc\/hosts"/ && $0 ~ /flags: [^,]*O_RDONLY/) {
        pend = 1; pwho = $1; pline = $0; next
      }
      next
    }
    pend && $1 == pwho && /sys_openat -> / {
      print pline; print $0; exit
    }
  ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
  POSTTUN_HOSTSOPEN_ENTER_TS="$(printf '%s\n' "$POSTTUN_HOSTSOPEN_PAIR" | head -1 | awk '{ ts = $4; sub(/:$/, "", ts); print ts }' 2>/dev/null || true)"
  POSTTUN_HOSTSOPEN_WHO="$(printf '%s\n' "$POSTTUN_HOSTSOPEN_PAIR" | head -1 | awk '{print $1}' 2>/dev/null || true)"
  POSTTUN_HOSTSOPEN_RET="$(printf '%s\n' "$POSTTUN_HOSTSOPEN_PAIR" | tail -1 | awk '{print $NF}' 2>/dev/null || true)"
  POSTTUN_HOSTSOPEN_EXIT_TS="$(printf '%s\n' "$POSTTUN_HOSTSOPEN_PAIR" | tail -1 | awk '{ ts = $4; sub(/:$/, "", ts); print ts }' 2>/dev/null || true)"
  echo "the /etc/hosts openat pair (the generateEtcHosts read):"
  printf '%s\n' "${POSTTUN_HOSTSOPEN_PAIR:-(the O_RDONLY /etc/hosts openat pair was never recorded — the flow did not reach generateEtcHosts)}"
  # The symlink-resolution evidence (the 4C-50 objective's own link):
  # the rebuild stage's symlinkat that recreated /etc/hosts carries the
  # symlink's target pathname (oldname ".ro<random>/hosts"); the
  # resolved object is /etc/<oldname>. The resolved object's own
  # SID/type is recorded from decision evidence ONLY: an AVC record
  # inside the exact openat window names the resolved object's
  # tcontext; a silent success is recorded as not-decision-proven and
  # is never assumed from the pathname.
  POSTTUN_HOSTS_SYMLINK_PAIR="$(awk -v t0="$POSTTUN_T0_TRACE_TS" '
    /sys_symlinkat\(oldname:/ && t0 != "" {
      ts = $4; sub(/:$/, "", ts)
      if (ts + 0 > t0 + 0 && $0 ~ /newname: [^,]*"\/etc\/hosts"/) {
        pend = 1; pwho = $1; pline = $0; next
      }
      next
    }
    pend && /sys_symlinkat -> / && $1 == pwho {
      print pline; print $0; exit
    }
  ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
  POSTTUN_HOSTS_SYMLINK_TARGET="$(printf '%s\n' "$POSTTUN_HOSTS_SYMLINK_PAIR" | head -1 | sed -n 's/.*oldname: [^ ]* "\([^"]*\)".*/\1/p' || true)"
  echo "--- the rebuilt /etc/hosts symlink's resolution evidence:"
  printf '%s\n' "${POSTTUN_HOSTS_SYMLINK_PAIR:-(the /etc/hosts-shaped rebuild symlinkat pair was never recorded)}"
  if [ -n "$POSTTUN_HOSTS_SYMLINK_TARGET" ]; then
    echo "  destination: /etc/hosts; symlink target: $POSTTUN_HOSTS_SYMLINK_TARGET; resolved object: /etc/$POSTTUN_HOSTS_SYMLINK_TARGET"
  fi
  POSTTUN_HOSTSOPEN_WINDOW_AVC=""
  if [ -n "$POSTTUN_HOSTSOPEN_ENTER_TS" ] && [ -n "$POSTTUN_HOSTSOPEN_EXIT_TS" ]; then
    POSTTUN_HOSTSOPEN_WINDOW_AVC="$(awk -v a="$POSTTUN_HOSTSOPEN_ENTER_TS" -v b="$POSTTUN_HOSTSOPEN_EXIT_TS" '
      { ts = $4; sub(/:$/, "", ts)
        if (ts + 0 < a + 0 || ts + 0 > b + 0) next
        print }
    ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null \
      | grep -a 'selinux_audited:' \
      | grep -a 'scontext=system_u:system_r:docker_helper_rootlesskit_t' || true)"
  fi
  if [ -n "$POSTTUN_HOSTSOPEN_WINDOW_AVC" ]; then
    echo "  the exact openat window's SELinux decisions (any record here is decision evidence: an AVC naming the resolved object's tcontext IS the target's proven label; a tmpfs_t:lnk_file denied=0x2 record is the 4C-50 boundary's own regression signal, and a net_conf_t:file denied=0x2 or denied=0x40000 record is the 4C-51/4C-52 boundary's own regression signal):"
    printf '%s\n' "$POSTTUN_HOSTSOPEN_WINDOW_AVC"
  else
    echo "  the exact openat window: no SELinux decision (a silent success is not decision-proven for the resolved object's label; with the pair granted no hook decision is expected here — the resolved object's own label provenance is the 4C-50/4C-51 boundary records' tcontext)"
  fi
  # The fd's own read stream (the reads' rets, the EOF read, the close).
  POSTTUN_HOSTS_FD=""
  POSTTUN_HOSTS_FD_OK=0
  case "$POSTTUN_HOSTSOPEN_RET" in
    0xf*|"") POSTTUN_HOSTS_FD_OK=0 ;;
    *) POSTTUN_HOSTS_FD="$(( POSTTUN_HOSTSOPEN_RET ))"; POSTTUN_HOSTS_FD_OK=1 ;;
  esac
  POSTTUN_HOSTS_READ_REPORT=""
  POSTTUN_HOSTS_READ_BYTES_OK=0
  POSTTUN_HOSTS_EOF_OK=0
  POSTTUN_HOSTS_CLOSE_OK=0
  POSTTUN_HOSTS_STAGE_END_TS=""
  if [ "$POSTTUN_HOSTS_FD_OK" = 1 ]; then
    echo "--- the fd=$POSTTUN_HOSTS_FD read stream (the enter queues the fd, the exit carries the ret; sequential stage):"
    POSTTUN_HOSTS_READ_REPORT="$(awk -v who="$POSTTUN_HOSTSOPEN_WHO" -v fd="$POSTTUN_HOSTS_FD" -v ts0="$POSTTUN_HOSTSOPEN_EXIT_TS" '
      $1 != who { next }
      { ts = $4; sub(/:$/, "", ts)
        if (ts0 != "" && ts + 0 <= ts0 + 0) next
        if ($0 ~ /sys_read\(/ || $0 ~ /sys_readv\(/) {
          if (match($0, /fd: [0-9]+/)) {
            f = substr($0, RSTART + 4, RLENGTH - 4) + 0
            if (f == fd + 0) { lasth = ts; lasthline = $0 }
            else { lasto = ts }
          }
          next
        }
        if ($0 ~ /sys_read -> / || $0 ~ /sys_readv -> /) {
          ret = $NF
          own = ""
          if (lasth != "" && (lasto == "" || lasto + 0 < lasth + 0)) { own = lasth; lasth = "" }
          else if (lasto != "") { lasto = "" }
          if (own != "") {
            if (ret ~ /^0xf/) { print "  read-ERROR trace-ts=" own " ret=" ret }
            else if (ret == "0x0") { print "  read-EOF   trace-ts=" own " ret=" ret; eofseen = 1 }
            else { print "  read       trace-ts=" own " ret=" ret " (bytes>0)"; bytesseen = 1 }
            last = ts
          }
          next
        }
        if ($0 ~ /sys_close\(/) {
          if (match($0, /fd: [0-9]+/)) {
            f = substr($0, RSTART + 4, RLENGTH - 4) + 0
            if (f == fd + 0) { print "  close      trace-ts=" ts; closeseen = 1 }
          }
          next
        }
      }
      END {
        if (bytesseen) print "  READ-BYTES>0: yes"
        else print "  READ-BYTES>0: no"
        if (eofseen) print "  EOF-READ: yes"
        else print "  EOF-READ: no"
        if (closeseen) print "  CLOSE: yes"
        else print "  CLOSE: no"
        if (last != "") print "  STAGE-END-TS=" last
      }
    ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
    printf '%s\n' "$POSTTUN_HOSTS_READ_REPORT"
    grep -aq 'READ-BYTES>0: yes' <<<"$POSTTUN_HOSTS_READ_REPORT" && POSTTUN_HOSTS_READ_BYTES_OK=1
    grep -aq 'EOF-READ: yes' <<<"$POSTTUN_HOSTS_READ_REPORT" && POSTTUN_HOSTS_EOF_OK=1
    grep -aq 'CLOSE: yes' <<<"$POSTTUN_HOSTS_READ_REPORT" && POSTTUN_HOSTS_CLOSE_OK=1
    POSTTUN_HOSTS_STAGE_END_TS="$(grep -a '^  STAGE-END-TS=' <<<"$POSTTUN_HOSTS_READ_REPORT" | cut -d= -f2 | head -1 || true)"
  else
    echo "--- the fd's read stream: NOT REACHED (the openat did not return an fd: ret=${POSTTUN_HOSTSOPEN_RET:-(the pair was never recorded)} — the open failed at its own hook; the pair above is the boundary evidence)"
  fi
  # The continuation: the flow went further after the hosts read stage
  # (the same trace who; the first later non-cleanup production enter —
  # the standard machinery enter set; read/close are this stage's own
  # ops and stay excluded here).
  POSTTUN_HOSTSREAD_CONTINUATION=""
  POSTTUN_HOSTSREAD_CONT_TS="${POSTTUN_HOSTS_STAGE_END_TS:-$POSTTUN_HOSTSOPEN_EXIT_TS}"
  if [ -n "$POSTTUN_HOSTSOPEN_WHO" ] && [ -n "$POSTTUN_HOSTSREAD_CONT_TS" ]; then
    POSTTUN_HOSTSREAD_CONTINUATION="$(awk -v who="$POSTTUN_HOSTSOPEN_WHO" -v te="$POSTTUN_HOSTSREAD_CONT_TS" '
      $1 != who { next }
      { ts = $4; sub(/:$/, "", ts)
        if (ts + 0 <= te + 0) next
        if ($0 !~ /sys_[a-z0-9_]+\(/) next
        nm = $0; sub(/.*sys_/, "", nm); sub(/\(.*/, "", nm)
        if (nm ~ /^(unlink|unlinkat|rmdir)$/ && $0 ~ /"\/tmp\//) next
        if (nm ~ /^(unlink|unlinkat|rmdir|openat|openat2|getdents64|newfstatat|statx|readlink)$/ && $0 ~ /\/tmp\/rootlesskit-b/) next
        if (nm ~ /^(openat|openat2)$/ && $0 ~ /"\/tmp",/) next
        if (nm ~ /^(mount|mkdir|mkdirat|umount2|umount|rename|getdents64|openat|openat2|newfstatat|statx|unlink|unlinkat|rmdir|symlink|symlinkat|readlink|execve|socket|open|setns|ioctl)$/) {
          print; exit
        }
      }' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | head -1 || true)"
  fi
  POSTTUN_HOSTSREAD_OK=0
  if [ "$POSTTUN_HOSTS_FD_OK" = 1 ] && [ "$POSTTUN_HOSTS_READ_BYTES_OK" = 1 ] \
    && { [ "$POSTTUN_HOSTS_EOF_OK" = 1 ] || [ "$POSTTUN_HOSTS_CLOSE_OK" = 1 ]; } \
    && [ -z "$POSTTUN_OLD_LNKREAD_PRESENT" ] \
    && [ -z "$POSTTUN_OLD_CONFFILEREAD_PRESENT" ] \
    && [ -z "$POSTTUN_OLD_CONFOPEN_PRESENT" ] \
    && [ -n "$POSTTUN_HOSTSREAD_CONTINUATION" ]; then
    POSTTUN_HOSTSREAD_OK=1
  fi
  if [ "$POSTTUN_HOSTSREAD_OK" = 1 ]; then
    echo "MILESTONE: ROOTLESSKIT-ETC-HOSTS-READ=OK — the openat returned an fd, the content was actually read (bytes>0), the stream ended (EOF read or close), no tmpfs_t:lnk_file read denial exists in the window, no net_conf_t:file read denial exists in the window (the 4C-51 read hook held), no net_conf_t:file open denial exists in the window (the 4C-52 open hook held), and the flow continued:"
    echo "  the first post-stage production enter (the next stage began):"
    printf '%s\n' "$POSTTUN_HOSTSREAD_CONTINUATION"
  else
    echo "MILESTONE: ROOTLESSKIT-ETC-HOSTS-READ=NOT-REACHED (fd=$([ "$POSTTUN_HOSTS_FD_OK" = 1 ] && echo "$POSTTUN_HOSTS_FD" || echo none) bytes>0=$POSTTUN_HOSTS_READ_BYTES_OK eof=$POSTTUN_HOSTS_EOF_OK close=$POSTTUN_HOSTS_CLOSE_OK lnkread-denial=$([ -n "$POSTTUN_OLD_LNKREAD_PRESENT" ] && echo PRESENT || echo absent) conffileread-denial=$([ -n "$POSTTUN_OLD_CONFFILEREAD_PRESENT" ] && echo PRESENT || echo absent) confopen-denial=$([ -n "$POSTTUN_OLD_CONFOPEN_PRESENT" ] && echo PRESENT || echo absent) continuation=$([ -n "$POSTTUN_HOSTSREAD_CONTINUATION" ] && echo present || echo absent))"
  fi

  # The 4C-53 standing-chain tally: the REBUILD stage's own completeness
  # (the canonical 4C-52 run's standing fact — the rebuilt /etc tree's
  # every rebuild-shaped symlinkat returned success). Every flow-domain
  # rebuild-shaped symlinkat pair (oldname on the .ro mount, newname an
  # /etc entry) after T0 is tallied with its own ret; the stage is
  # COMPLETE when every recorded rebuild-shaped symlinkat returned 0x0
  # and at least one was recorded. The count is this run's own live
  # fact (recorded, never hardcoded). This re-proves the standing
  # rebuild-stage completion beside the standing TUNSETIFF/copy-up/
  # cgroup/hosts-read milestones; it grants nothing.
  echo "--- the 4C-53 standing-chain tally (the rebuild stage's own symlinkat results; every rebuild-shaped pair in trace order):"
  POSTTUN_REBUILD_TALLY="$(awk -v t0="$POSTTUN_T0_TRACE_TS" '
    /sys_symlinkat\(oldname:/ && t0 != "" {
      ts = $4; sub(/:$/, "", ts)
      if (ts + 0 > t0 + 0 && $0 ~ /oldname: [^,]*"[^"]*\.ro[0-9]+\// && $0 ~ /newname: [^,]*"\/etc\//) {
        pend = 1; pwho = $1; pline = $0
      }
      next
    }
    pend && /sys_symlinkat -> / && $1 == pwho {
      total++
      if ($NF == "0x0") ok++; else { bad++; print "  rebuild-symlinkat FAILED trace-ts=" $4 " ret=" $NF ": " pline }
      pend = 0
      next
    }
    END {
      print "REBUILD-SYMLINKAT-TOTAL=" total + 0
      print "REBUILD-SYMLINKAT-OK=" ok + 0
      if (total > 0 && ok == total) print "REBUILD-STAGE=COMPLETE"
      else if (total > 0) print "REBUILD-STAGE=INCOMPLETE"
      else print "REBUILD-STAGE=NOT-REACHED"
    }
  ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
  printf '%s\n' "${POSTTUN_REBUILD_TALLY:-REBUILD-SYMLINKAT-TOTAL=0
REBUILD-SYMLINKAT-OK=0
REBUILD-STAGE=NOT-REACHED}"
  POSTTUN_REBUILD_TOTAL="$(grep -a '^REBUILD-SYMLINKAT-TOTAL=' <<<"${POSTTUN_REBUILD_TALLY:-}" | cut -d= -f2 | head -1 || true)"
  POSTTUN_REBUILD_OK_N="$(grep -a '^REBUILD-SYMLINKAT-OK=' <<<"${POSTTUN_REBUILD_TALLY:-}" | cut -d= -f2 | head -1 || true)"
  POSTTUN_REBUILD_COMPLETE="$(grep -a '^REBUILD-STAGE=' <<<"${POSTTUN_REBUILD_TALLY:-}" | cut -d= -f2 | head -1 || true)"
  POSTTUN_REBUILD_COMPLETE_OK=0
  [ "$POSTTUN_REBUILD_COMPLETE" = "COMPLETE" ] && POSTTUN_REBUILD_COMPLETE_OK=1

  # The 4C-53 objective: the production RemoveAll("/etc/resolv.conf") —
  # the setupNet resolv-replacement stage's FIRST step after the granted
  # /etc/hosts read (the 4C-52 canonical run's terminal boundary was
  # EXACTLY this stage's unlinkat destination hook). The rebuilt
  # /etc/resolv.conf destination symlink (tmpfs_t:lnk_file) must be
  # REMOVED by the flow's own unlinkat, and the stage's whole
  # mini-sequence is recorded EXACTLY — the 4C-52 trace showed several
  # syscall probes around ONE semantic operation, and the timeline is
  # recorded verbatim, never one phase per errno:
  #   unlinkat("/etc/resolv.conf", 0)         (the destination symlink's
  #                                            own removal hook — the
  #                                            4C-53 widening's owner)
  #   unlinkat("/etc/resolv.conf", AT_REMOVEDIR)  (Go's os.Remove's
  #                                            directory retry shape)
  #   dirfd-relative unlinkat("resolv.conf")  (the RemoveAll parent-walk
  #                                            retry probes)
  #   openat("/etc", O_DIRECTORY|O_NOFOLLOW)  (the parent-walk's own
  #                                            dirfd open)
  #   readlinkat                              (the symlink-shaped entry
  #                                            probe)
  #   final result                            (the stage's own completion)
  #   next production enter                   (the replacement stage
  #                                            began)
  # ROOTLESSKIT-ETC-RESOLV-SYMLINK-REMOVE=OK requires ALL of:
  #   - the AT_FDCWD unlinkat("/etc/resolv.conf", 0) pair returned 0x0
  #     (the rebuilt destination symlink was actually removed — the
  #     4C-53 unlink widening's own live proof);
  #   - NO tmpfs_t:lnk_file unlink (0x800) denial anywhere in the window
  #     (the OLD-LNKUNLINK gone-gate above — the grant took effect);
  #   - the production flow went further: a later production enter of
  #     the same trace who from a DIFFERENT stage after the stage's
  #     last resolv window (the stage-aware contract — the RemoveAll
  #     stage's own retry chain never proves progress; the resolv
  #     WriteFile / the /etc/hosts RemoveAll are the next stages).
  # A missing denial alone is NOT a pass; an unlinkat that fails at a
  # DEEPER hook keeps this milestone NOT-REACHED with the reached stage
  # recorded (the phase's semantic delta is then proven by the
  # gone-gates and the phase STOPs there — no compensating grant). The
  # /etc/hosts equivalents are deliberately NOT part of this objective
  # (the resolv-vs-hosts distinction): a hosts-shaped failure on the
  # SAME already-granted surface is the same permission at work, not a
  # new phase — the machinery's terminal-boundary classification owns
  # where the next semantic boundary actually is.
  echo "--- the 4C-53 /etc/resolv.conf RemoveAll objective (the exact mini-sequence timeline; the enter lines name their shape keys, the exit lines are the paired own rets):"
  POSTTUN_RESOLV_TIMELINE="$(awk -v t0="$POSTTUN_T0_TRACE_TS" -v fl="$POSTTUN_FLOW_COMM_AWK" '
    function baseof(s,   q, n, parts) {
      if (!match(s, /"[^"]*"/)) return ""
      q = substr(s, RSTART + 1, RLENGTH - 2)
      n = split(q, parts, "/")
      return parts[n]
    }
    /^ *[a-zA-Z0-9_.-]+-[0-9]+ +\[[0-9]+\]/ && $0 ~ /sys_/ {
      who = $1
      if (who !~ fl) next
      ts = $4; sub(/:$/, "", ts)
      if (t0 == "" || ts + 0 <= t0 + 0) next
      if (!match($0, /sys_[a-z0-9_]+/)) next
      nm = substr($0, RSTART + 4, RLENGTH - 4)
      if (nm !~ /^(unlink|unlinkat|rmdir|openat|openat2|readlink|readlinkat)$/) next
      k = who "|" nm
      if ($0 ~ "sys_" nm " -> ") {
        if (qtop[k] > 0) {
          if (qresolv[k, qtop[k]]) {
            print "    exit trace-ts=" ts " ret=" $NF " (closes " qdesc[k, qtop[k]] ")"
            lastresolvxts[k] = ts
            if (nm == "unlinkat" && firstabs[k] != "" && qets[k, qtop[k]] + 0 == firstabs[k] + 0) firstabsxts[k] = ts
          }
          qtop[k]--
        }
        next
      }
      if ($0 ~ "sys_" nm "\\(") {
        qtop[k]++
        qets[k, qtop[k]] = ts
        qdesc[k, qtop[k]] = ""
        isresolv = 0
        if ($0 ~ /pathname: [^,]*"\/etc\/resolv\.conf"/) { isresolv = 1; qdesc[k, qtop[k]] = "pathname=/etc/resolv.conf" }
        else if ($0 ~ /"resolv\.conf"/) { isresolv = 1; qdesc[k, qtop[k]] = "basename=resolv.conf (dirfd-relative)" }
        else if (nm ~ /^(openat|openat2)$/ && $0 ~ /filename: [^,]*"\/etc",/) { isresolv = 1; qdesc[k, qtop[k]] = "the parent-dir /etc openat" }
        qresolv[k, qtop[k]] = isresolv
        if (isresolv) {
          print "    enter trace-ts=" ts " (" qdesc[k, qtop[k]] "): " $0
          if (nm == "unlinkat" && firstabs[k] == "" && $0 ~ /pathname: [^,]*"\/etc\/resolv\.conf"/) {
            firstabs[k] = ts; firstabsline[k] = $0
          }
        }
        next
      }
    }
    END {
      fa = ""
      for (k in firstabs) {
        if (fa == "" || firstabs[k] + 0 < fa + 0) { fa = firstabs[k]; faline = firstabsline[k]; faxts = firstabsxts[k] }
      }
      if (fa != "") {
        print "  FIRST-ABS-UNLINKAT-ENTER-TS=" fa
        print "  FIRST-ABS-UNLINKAT-ENTER=" faline
        print "  FIRST-ABS-UNLINKAT-EXIT-TS=" faxts
      } else print "  FIRST-ABS-UNLINKAT-ENTER-TS="
      mx = ""
      for (k in lastresolvxts) {
        if (mx == "" || lastresolvxts[k] + 0 > mx + 0) mx = lastresolvxts[k]
      }
      print "  RESOLV-STAGE-END-TS=" mx
    }
  ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | head -60 || true)"
  printf '%s\n' "${POSTTUN_RESOLV_TIMELINE:-(no resolv-removal-shaped records in the trace span — the flow did not reach the resolv-replacement stage)}"
  POSTTUN_RESOLV_UNLINK_ENTER_TS="$(printf '%s\n' "$POSTTUN_RESOLV_TIMELINE" | grep -a '^  FIRST-ABS-UNLINKAT-ENTER-TS=' | cut -d= -f2 | head -1 || true)"
  POSTTUN_RESOLV_UNLINK_ENTER="$(printf '%s\n' "$POSTTUN_RESOLV_TIMELINE" | grep -a '^  FIRST-ABS-UNLINKAT-ENTER=' | cut -d= -f2- | head -1 || true)"
  POSTTUN_RESOLV_UNLINK_EXIT_TS="$(printf '%s\n' "$POSTTUN_RESOLV_TIMELINE" | grep -a '^  FIRST-ABS-UNLINKAT-EXIT-TS=' | cut -d= -f2 | head -1 || true)"
  POSTTUN_RESOLV_STAGE_END_TS="$(printf '%s\n' "$POSTTUN_RESOLV_TIMELINE" | grep -a '^  RESOLV-STAGE-END-TS=' | cut -d= -f2 | head -1 || true)"
  echo "--- the first absolute unlinkat(\"/etc/resolv.conf\", 0) pair (the destination symlink's own removal hook — the 4C-53 widening's live proof):"
  if [ -n "$POSTTUN_RESOLV_UNLINK_ENTER" ]; then
    printf '%s\n' "$POSTTUN_RESOLV_UNLINK_ENTER"
    awk -v who="$(printf '%s' "$POSTTUN_RESOLV_UNLINK_ENTER" | awk '{print $1}')" -v ts0="$POSTTUN_RESOLV_UNLINK_ENTER_TS" '
      $1 != who { next }
      { ts = $4; sub(/:$/, "", ts)
        if (ts + 0 <= ts0 + 0) next
        if ($0 ~ /sys_unlinkat -> /) { print; exit }
      }' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true
  else
    echo "(the absolute unlinkat(\"/etc/resolv.conf\") enter was never recorded)"
  fi
  POSTTUN_RESOLV_UNLINK_RET=""
  if [ -n "$POSTTUN_RESOLV_UNLINK_ENTER" ] && [ -n "$POSTTUN_RESOLV_UNLINK_EXIT_TS" ]; then
    POSTTUN_RESOLV_UNLINK_RET="$(awk -v who="$(printf '%s' "$POSTTUN_RESOLV_UNLINK_ENTER" | awk '{print $1}')" -v ts0="$POSTTUN_RESOLV_UNLINK_EXIT_TS" '
      $1 != who { next }
      { ts = $4; sub(/:$/, "", ts)
        if (ts + 0 == ts0 + 0 && $0 ~ /sys_unlinkat -> /) { print $NF; exit }
      }' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | head -1 || true)"
  fi
  echo "  the pair's ret: ${POSTTUN_RESOLV_UNLINK_RET:-(not paired — the enter never closed)}"
  # The stage-aware continuation: the first later production enter of
  # the SAME trace who (the first absolute unlinkat's own pid — the
  # stage's owner), after the stage's LAST resolv window (the stage's
  # own retry chain is never the proof; the next stage — the resolv
  # WriteFile or the /etc/hosts RemoveAll — is).
  POSTTUN_RESOLVREMOVE_CONTINUATION=""
  if [ -n "$POSTTUN_RESOLV_STAGE_END_TS" ] && [ -n "$POSTTUN_RESOLV_UNLINK_ENTER" ]; then
    POSTTUN_RESOLVREMOVE_WHO="$(printf '%s' "$POSTTUN_RESOLV_UNLINK_ENTER" | awk '{print $1}' || true)"
    POSTTUN_RESOLVREMOVE_CONTINUATION="$(awk -v who="$POSTTUN_RESOLVREMOVE_WHO" -v te="$POSTTUN_RESOLV_STAGE_END_TS" '
      $1 != who { next }
      { ts = $4; sub(/:$/, "", ts)
        if (ts + 0 <= te + 0) next
        if ($0 !~ /sys_[a-z0-9_]+\(/) next
        nm = $0; sub(/.*sys_/, "", nm); sub(/\(.*/, "", nm)
        if (nm ~ /^(unlink|unlinkat|rmdir)$/ && $0 ~ /"\/tmp\//) next
        if (nm ~ /^(unlink|unlinkat|rmdir|openat|openat2|getdents64|newfstatat|statx|readlink)$/ && $0 ~ /\/tmp\/rootlesskit-b/) next
        if (nm ~ /^(openat|openat2)$/ && $0 ~ /"\/tmp",/) next
        if (nm ~ /^(mount|mkdir|mkdirat|umount2|umount|rename|getdents64|openat|openat2|newfstatat|statx|unlink|unlinkat|rmdir|symlink|symlinkat|readlink|execve|socket|open|setns|ioctl)$/) {
          print; exit
        }
      }' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | head -1 || true)"
  fi
  POSTTUN_RESOLVREMOVE_OK=0
  if [ "$POSTTUN_RESOLV_UNLINK_RET" = "0x0" ] \
    && [ -z "$POSTTUN_OLD_LNKUNLINK_PRESENT" ] \
    && [ -n "$POSTTUN_RESOLVREMOVE_CONTINUATION" ]; then
    POSTTUN_RESOLVREMOVE_OK=1
  fi
  if [ "$POSTTUN_RESOLVREMOVE_OK" = 1 ]; then
    echo "MILESTONE: ROOTLESSKIT-ETC-RESOLV-SYMLINK-REMOVE=OK — the RemoveAll(\"/etc/resolv.conf\") unlinkat returned success, no tmpfs_t:lnk_file unlink denial exists in the window, and the flow continued:"
    echo "  the first post-stage production enter (the next stage began):"
    printf '%s\n' "$POSTTUN_RESOLVREMOVE_CONTINUATION"
  else
    echo "MILESTONE: ROOTLESSKIT-ETC-RESOLV-SYMLINK-REMOVE=NOT-REACHED (unlink-ret=${POSTTUN_RESOLV_UNLINK_RET:-(the pair was never recorded)} lnkunlink-denial=$([ -n "$POSTTUN_OLD_LNKUNLINK_PRESENT" ] && echo PRESENT || echo absent) continuation=$([ -n "$POSTTUN_RESOLVREMOVE_CONTINUATION" ] && echo present || echo absent))"
  fi

  # The resolv-vs-hosts distinction (the 4C-53 phase contract): the
  # timeline above is keyed to /etc/resolv.conf ONLY. The NEXT
  # production step (the replacement chain: the resolv WriteFile, then
  # the RemoveAll("/etc/hosts") / WriteFile, then the bind mounts) is
  # recorded here for the run's own execution map — RECORD-ONLY, no
  # gate, no assumed class/type: if the hosts stage fails on the SAME
  # already-granted surface (its destination symlink is also a
  # tmpfs_t:lnk_file), that is the same permission at work, not a new
  # phase; the machinery's terminal-boundary classification owns where
  # the next NEW semantic boundary actually is.
  echo "--- the next production step after the resolv removal (record-only; the first /etc/hosts-named unlinkat pair after the resolv stage, then the flow's first later production enter):"
  POSTTUN_HOSTSREMOVE_PAIR="$(awk -v t0="$POSTTUN_T0_TRACE_TS" -v te="${POSTTUN_RESOLV_STAGE_END_TS:-}" '
    /sys_unlinkat\(/ && t0 != "" {
      ts = $4; sub(/:$/, "", ts)
      if (ts + 0 > t0 + 0 && te != "" && ts + 0 > te + 0 && $0 ~ /pathname: [^,]*"\/etc\/hosts"/) {
        pend = 1; pwho = $1; pline = $0; next
      }
      next
    }
    pend && /sys_unlinkat -> / && $1 == pwho {
      print pline; print $0; exit
    }
  ' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null || true)"
  printf '%s\n' "${POSTTUN_HOSTSREMOVE_PAIR:-(none — no /etc/hosts-shaped unlinkat pair followed the resolv stage in this trace span)}"

  # The gates.
  echo "GATES:"
  [ "$POSTTUN_T0_OK" = 1 ] && echo "  POST-TUN-T0 observed: PASS" || echo "  POST-TUN-T0 observed: FAIL"
  [ "$POSTTUN_RET0_OK" = 1 ] && echo "  TUNSETIFF ret == 0: PASS" || echo "  TUNSETIFF ret == 0: FAIL"
  [ "$POSTTUN_DEATH_PID_OK" = 1 ] && echo "  first-death PID identified: PASS" || echo "  first-death PID identified: FAIL"
  [ "$POSTTUN_DEATH_TS_OK" = 1 ] && echo "  first-death timestamp identified: PASS" || echo "  first-death timestamp identified: FAIL"
  if [ -n "$POSTTUN_DEATH_CAUSE" ]; then
    echo "  first-death cause classified: PASS ($POSTTUN_DEATH_CAUSE)"
  else
    echo "  first-death cause classified: FAIL (no death observed in the window's trace span)"
  fi
  [ "$POSTTUN_DENIALS_CLASSIFIED" = 1 ] && echo "  all observed SELinux decisions temporally classified: PASS" || echo "  all observed SELinux decisions temporally classified: FAIL (UNTIMED records remain)"
  [ "$POSTTUN_NO_PREANCHOR_POST_OK" = 1 ] && echo "  NO-PREANCHOR-POST (no POST-FAILURE/CLEANUP decision precedes the terminal anchor): PASS" || echo "  NO-PREANCHOR-POST (no POST-FAILURE/CLEANUP decision precedes the terminal anchor): FAIL (${POSTTUN_PREANCHOR_POST_N:-?} violation(s) — see the machinery section)"
  if [ -n "$POSTTUN_FIRST_FAIL_PID" ]; then
    echo "  first failing exit identified: PASS (pid=$POSTTUN_FIRST_FAIL_PID comm=$POSTTUN_FIRST_FAIL_COMM exit=$POSTTUN_FIRST_FAIL_EXIT_CODE at=T0+${POSTTUN_T0_TO_FAIL:-?}s)"
  elif [ "$POSTTUN_T0_OK" = 1 ] && [ "$POSTTUN_DENIALS_CLASSIFIED" = 1 ]; then
    echo "  first failing exit identified: PASS (none — no flow-domain member exited nonzero in the window's trace span; the lifetime held)"
  else
    echo "  first failing exit identified: FAIL (no nonzero exit_group of a flow-domain member in the window's trace span — the lifetime failure did not reproduce)"
  fi
  if [ -n "$POSTTUN_CLOCK_DRIFT" ]; then
    POSTTUN_DRIFT_ABS="$(awk -v d="$POSTTUN_CLOCK_DRIFT" 'BEGIN { d = d + 0; print (d < 0) ? -d : d }' 2>/dev/null || true)"
    if awk -v d="$POSTTUN_DRIFT_ABS" 'BEGIN { exit !(d <= 1.0) }' 2>/dev/null; then
      echo "  trace-clock drift validation: PASS (|drift|=${POSTTUN_CLOCK_DRIFT}s <= 1.0s)"
    else
      echo "  trace-clock drift validation: FAIL (|drift|=${POSTTUN_CLOCK_DRIFT}s > 1.0s — the wallclock mapping is unreliable)"
      POSTTUN_DENIALS_CLASSIFIED=0
    fi
  else
    echo "  trace-clock drift validation: FAIL (the clock references are absent)"
    POSTTUN_DENIALS_CLASSIFIED=0
  fi

  # The primary boundary: the earliest of (a) the first STARTUP-CAUSAL
  # SELinux decision of ANY tclass relative to the first failing exit,
  # and (b) the first failing exit itself. A denial that precedes or
  # sits exactly at the failing exit is the policy-candidate owner of
  # the next semantic phase; a first failing exit that no SELinux
  # decision precedes is a software/lifecycle finding (no policy
  # widening). The lifecycle kill/signull/sigkill denials, classified
  # POST-FAILURE/CLEANUP or POLLING-ONLY, are cleanup and polling noise
  # and are not owners. Nothing is granted here either way. With no
  # nonzero flow-domain exit in the span, the lifetime held — the 4C-39
  # stable outcome, no new boundary in this window.
  if [ "$POSTTUN_T0_OK" = 1 ] && [ "$POSTTUN_DEATH_PID_OK" = 1 ] && [ "$POSTTUN_DEATH_TS_OK" = 1 ] && [ -n "$POSTTUN_DEATH_CAUSE" ] && [ "$POSTTUN_DENIALS_CLASSIFIED" = 1 ]; then
    if [ -n "$POSTTUN_FIRST_FAIL_PID" ]; then
    POSTTUN_REF_DESC="$POSTTUN_REF_ANCHOR; the terminal exit pid=$POSTTUN_FIRST_FAIL_PID comm=$POSTTUN_FIRST_FAIL_COMM exit=$POSTTUN_FIRST_FAIL_EXIT_CODE at=T0+${POSTTUN_T0_TO_FAIL:-?}s"
    # The boundary's owner denial = the FIRST denial CLASSIFIED
    # STARTUP-CAUSAL by the corrected 4C-48 machinery (the ownership-
    # aware classification — a chronologically-earlier d<=0 denial that
    # the machinery classified HANDLED/NON-TERMINAL or cleanup-shaped
    # POST is NOT the owner; the canonical 4C-48 evB run showed the
    # difference: the RemoveAll(bind0) remove_name denial sits earlier
    # in time but the classified owner is the cgroup move-mount's own
    # mounton denial).
    POSTTUN_FIRST_PRE_AT_TS="$(grep -a '^class=STARTUP-CAUSAL trace-ts=' "$POSTTUN_ANCHOR_TMP" 2>/dev/null \
      | head -1 | sed -n 's/^class=STARTUP-CAUSAL trace-ts=\([0-9.]*\) shape=.*/\1/p' || true)"
    POSTTUN_PRE_AT_RECORD=""
    if [ -n "$POSTTUN_FIRST_PRE_AT_TS" ]; then
      POSTTUN_PRE_AT_RECORD="$(grep -a "^class=STARTUP-CAUSAL trace-ts=$POSTTUN_FIRST_PRE_AT_TS " -A1 "$POSTTUN_ANCHOR_TMP" 2>/dev/null | sed -n '2p' | sed 's/^  //' || true)"
    fi
    if [ -n "$POSTTUN_FIRST_PRE_AT_TS" ]; then
      POSTTUN_PRE_AT_TO_FAIL="$(awk -v a="$POSTTUN_FIRST_PRE_AT_TS" -v b="$POSTTUN_CLASS_REF_TS" 'BEGIN { printf "%.3f", a - b }' 2>/dev/null || true)"
      POSTTUN_PRE_AT_RECORD="$(grep -a 'selinux_audited:' "$EVIDENCE_DIR/30-trace-window.txt" 2>/dev/null | awk -v ts0="$POSTTUN_FIRST_PRE_AT_TS" '{ ts = $4; sub(/:$/, "", ts); if (ts + 0 == ts0 + 0) { print; exit } }' 2>/dev/null | head -1 || true)"
      echo "--- the boundary's own denial record:"
      printf '%s\n' "${POSTTUN_PRE_AT_RECORD:-(record lookup failed)}"
      POSTTUN_BND_TC="$(printf '%s\n' "$POSTTUN_PRE_AT_RECORD" 2>/dev/null | grep -aoE 'tclass=[a-z_0-9]+' | head -1 | cut -d= -f2 || true)"
      POSTTUN_BND_MASK="$(printf '%s\n' "$POSTTUN_PRE_AT_RECORD" 2>/dev/null | grep -aoE 'denied=0x[0-9a-fA-F]+' | head -1 | cut -d= -f2 || true)"
      POSTTUN_BND_SYMBOLIC=""
      if [ -n "$POSTTUN_BND_TC" ] && [ -n "$POSTTUN_BND_MASK" ]; then
        echo "--- the boundary's symbolic decode — the kernel's own symbolic records for the same shape (the audit slice; the AVC's perm names are the kernel's own decode of this mask):"
        POSTTUN_BND_TCTX_FULL="$(printf '%s\n' "$POSTTUN_PRE_AT_RECORD" | grep -aoE 'tcontext=[^ ]+' | head -1 | cut -d= -f2 || true)"
        POSTTUN_BND_SHAPE_AVC="$(grep -a 'type=AVC' "$EVIDENCE_DIR/09-avc-window.txt" 2>/dev/null | grep -a "tclass=$POSTTUN_BND_TC" | grep -aF "tcontext=$POSTTUN_BND_TCTX_FULL" | grep -a 'denied' || true)"
        printf '%s\n' "${POSTTUN_BND_SHAPE_AVC:-(none — the audit slice carries no same-shape record; the boundary stays raw, no symbolic name is claimed from any other source)}"
        POSTTUN_BND_PERMS="$(printf '%s\n' "$POSTTUN_BND_SHAPE_AVC" | grep -aoE 'denied[ \t]+\{[^}]*\}' | sed 's/denied[ \t]*{[ \t]*//; s/[ \t]*}$//' | tr ' ' '\n' | tr '\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//' | sort -u || true)"
        POSTTUN_BND_DECODED_SETS="$(printf '%s\n' "$POSTTUN_BND_SHAPE_AVC" | grep -aoE 'denied[ \t]+\{[^}]*\}' | sort -u | grep -ac . || true)"
        if [ -n "$POSTTUN_BND_PERMS" ] && [ "$POSTTUN_BND_DECODED_SETS" = 1 ]; then
          echo "denied=$POSTTUN_BND_MASK (tclass=$POSTTUN_BND_TC) -> { ${POSTTUN_BND_PERMS} } (the kernel's own name)"
          POSTTUN_BND_SCTX_TYPE="$(printf '%s\n' "$POSTTUN_PRE_AT_RECORD" | grep -aoE 'scontext=[^ ]+' | head -1 | sed -e 's/^scontext=//' -e 's/^[^:]*:[^:]*://' -e 's/:.*$//' || true)"
          POSTTUN_BND_TCTX_TYPE="$(printf '%s\n' "$POSTTUN_BND_TCTX_FULL" | sed -e 's/^[^:]*:[^:]*://' -e 's/:.*$//' || true)"
          if [ -n "$POSTTUN_BND_SCTX_TYPE" ] && [ -n "$POSTTUN_BND_TCTX_TYPE" ]; then
            POSTTUN_BND_SYMBOLIC="$POSTTUN_BND_SCTX_TYPE -> $POSTTUN_BND_TCTX_TYPE:$POSTTUN_BND_TC { ${POSTTUN_BND_PERMS} }"
          fi
        fi
        echo "--- the loaded policy's own numeric permission map (value -> name from the perms files' contents; the POLICY's numbering — the recorded interface fact, never the AVC decode):"
        numeric_perms_map "$POSTTUN_BND_TC" || true
      else
        echo "(the boundary record lacks a tclass/denied-mask pair — the symbolic decode stays raw)"
      fi
      POSTTUN_BOUNDARY="POLICY-DENIAL-CANDIDATE (${POSTTUN_BND_SYMBOLIC:+$POSTTUN_BND_SYMBOLIC; }a SELinux decision at trace-ts=$POSTTUN_FIRST_PRE_AT_TS, ${POSTTUN_PRE_AT_TO_FAIL}s relative to $POSTTUN_REF_DESC — the denial owns the next semantic phase; see 52-posttun-denials.txt)"
    else
      # The 4C-48 contract: the SOFTWARE verdict must PROVE the
      # terminality — the anchor failure is followed by no forward
      # production operation (only the error/exit path: the cleanup
      # zone or the failing comm own exit).
      echo "--- the terminal-failure proof (the 4C-48 contract: absence of later forward production progress):"
      printf '%s\n' "${POSTTUN_ANCHOR_LINE:-(the anchor record: absent)}"
      echo "  the terminal failing syscall: sys_$POSTTUN_ANCHOR_SYS by $POSTTUN_ANCHOR_WHO at trace-ts=$POSTTUN_ANCHOR_TS"
      echo "  NO non-cleanup production enter follows it before ${POSTTUN_ZONE_TS:--} (the forward-production-enter scan found none; handled failures: ${POSTTUN_NHANDLED:-0})"
      echo "  the transition into the error/exit path: the failing comm subsequent records (the failure window above) end in the terminal exit"
      POSTTUN_BOUNDARY="SOFTWARE-LIFECYCLE ($POSTTUN_REF_DESC at=T0+${POSTTUN_T0_TO_FAIL}s precedes every SELinux decision and no forward production progress follows the anchor failure — no SELinux blocker owns the lifetime failure; the next phase owner is the software/lifecycle finding)"
      POSTTUN_BND_SYMBOLIC="SOFTWARE-LIFECYCLE (no SELinux decision precedes the terminal failing production syscall $POSTTUN_ANCHOR_WHO sys_$POSTTUN_ANCHOR_SYS at trace-ts=$POSTTUN_ANCHOR_TS)"
    fi
    echo "PRIMARY-BOUNDARY: $POSTTUN_BOUNDARY"
  else
    POSTTUN_BOUNDARY="POST-TUN-LIFETIME-STABLE (no nonzero exit of any flow-domain member in the window's trace span T0..${POSTTUN_RING_LAST_TS:-(none)}; no new startup boundary in this window)"
    POSTTUN_BND_SYMBOLIC="POST-TUN-LIFETIME-STABLE (no nonzero flow-domain exit in the span)"
    echo "PRIMARY-BOUNDARY: $POSTTUN_BOUNDARY"
    echo "TARGET-LIFETIME-BLOCKER: GONE (the flow's lifetime failure did not reproduce in this window)"
    echo "  the aliveness evidence: the timeline's per-pid life summary above (holder/userns/netns/tap0 first-vs-last-seen), the post-TUN mount/execve story above (the granted propagation on / and the following stages), and the manager journal slice above (the op's entry state across the window)"
  fi
  POSTTUN_ESTABLISHED=1
  else
    echo "PRIMARY-BOUNDARY: NOT_ESTABLISHED (the causal order could not be established from the window's evidence — no guessing)"
  fi
} > "$EVIDENCE_DIR/53-posttun-verdict.txt" 2>&1
cat "$EVIDENCE_DIR/53-posttun-verdict.txt" >&2
if [ "$POSTTUN_ESTABLISHED" = 1 ]; then
  marker "POSTTUN-FIRST-DEATH=pid=${POSTTUN_FIRST_DEATH_PID:-none} comm=${POSTTUN_FIRST_DEATH_COMM:-none} at=T0+${POSTTUN_T0_TO_DEATH:-?}s cause=${POSTTUN_DEATH_CAUSE%% *}"
  marker "POSTTUN-DENIALS=STARTUP-CAUSAL=$POSTTUN_NSTARTUP POST-FAILURE/CLEANUP=$POSTTUN_NPOST POLLING-ONLY=$POSTTUN_NPOLL UNTIMED=$POSTTUN_NUNTIMED HANDLED/NON-TERMINAL=${POSTTUN_NHANDLED:-0}"
  if [ "$POSTTUN_NO_PREANCHOR_POST_OK" = 1 ]; then
    marker "NO-PREANCHOR-POST=PASS"
  else
    marker "NO-PREANCHOR-POST=FAIL"
    marker "4C-53=HOLD/PREANCHOR-POST-VIOLATION"
  fi
  marker "POSTTUN-PRIMARY-BOUNDARY=${POSTTUN_BND_SYMBOLIC:-(undecoded — see 53-posttun-verdict.txt)}"
  if [ "${POSTTUN_GATE_VERDICT:-}" = "PASS" ]; then
    marker "4C-49-CONFINEMENT-GATE=PASS"
  else
    marker "4C-49-CONFINEMENT-GATE=BLOCKED/CONFINEMENT-NOT-PROVEN"
  fi
  if [ "$POSTTUN_OLD_BOUNDARY_PRESENT" = 1 ]; then
    marker "4C-39-OLD-MOUNTON-BOUNDARY=STILL-PRESENT"
    marker "4C-39=INCOMPLETE/GRANT-DID-NOT-TAKE-EFFECT"
  else
    marker "4C-39-OLD-MOUNTON-BOUNDARY=GONE"
    marker "4C-39=PASS/NEXT-BOUNDARY-CONFIRMED"
  fi
  if [ "$POSTTUN_OLD_TMPWRITE_PRESENT" = 1 ]; then
    marker "4C-40-OLD-WRITE-BOUNDARY=STILL-PRESENT"
    marker "4C-40=INCOMPLETE/GRANT-DID-NOT-TAKE-EFFECT"
  else
    marker "4C-40-OLD-WRITE-BOUNDARY=GONE"
    marker "4C-40=PASS/NEXT-BOUNDARY-CONFIRMED"
  fi
  if [ "$POSTTUN_OLD_ADDNAME_PRESENT" = 1 ]; then
    marker "4C-41-OLD-ADDNAME-BOUNDARY=STILL-PRESENT"
    marker "4C-41=INCOMPLETE/GRANT-DID-NOT-TAKE-EFFECT"
  else
    marker "4C-41-OLD-ADDNAME-BOUNDARY=GONE"
    marker "4C-41=PASS/NEXT-BOUNDARY-CONFIRMED"
  fi
  if [ "$POSTTUN_OLD_CREATE_PRESENT" = 1 ]; then
    marker "4C-42-OLD-CREATE-BOUNDARY=STILL-PRESENT"
    marker "4C-42=INCOMPLETE/GRANT-DID-NOT-TAKE-EFFECT"
  else
    marker "4C-42-OLD-CREATE-BOUNDARY=GONE"
    [ -n "$POSTTUN_MKDIRAT_OK" ] && marker "ROOTLESSKIT-BIND0-CREATE=OK"
    marker "4C-42=PASS/NEXT-BOUNDARY-CONFIRMED"
  fi
  if [ "$POSTTUN_OLD_TMPMOUNTON_PRESENT" = 1 ]; then
    marker "4C-43-OLD-TMPMOUNTON-BOUNDARY=STILL-PRESENT"
    marker "4C-43=INCOMPLETE/GRANT-DID-NOT-TAKE-EFFECT"
  else
    marker "4C-43-OLD-TMPMOUNTON-BOUNDARY=GONE"
    [ "$POSTTUN_BINDMOUNT_OK" = 1 ] && marker "ROOTLESSKIT-BIND0-BIND-MOUNT=OK"
    marker "4C-43=PASS/NEXT-BOUNDARY-CONFIRMED"
  fi
  if [ "$POSTTUN_OLD_ETCMOUNTON_PRESENT" = 1 ]; then
    marker "4C-44-OLD-ETCMOUNTON-BOUNDARY=STILL-PRESENT"
    marker "4C-44=INCOMPLETE/GRANT-DID-NOT-TAKE-EFFECT"
  else
    marker "4C-44-OLD-ETCMOUNTON-BOUNDARY=GONE"
    [ "$POSTTUN_TMPFSMOUNT_OK" = 1 ] && marker "ROOTLESSKIT-COPYUP-TMPFS-MOUNT=OK"
    if [ -n "$POSTTUN_FIRST_FAIL_PID" ]; then
      marker "4C-44-OUTCOME=NEXT-STARTUP-BOUNDARY-CONFIRMED"
      marker "4C-44=PASS/NEXT-BOUNDARY-CONFIRMED"
    else
      marker "4C-44-OUTCOME=POST-TUN-LIFETIME-STABLE"
      marker "TARGET-LIFETIME-BLOCKER=GONE"
      marker "4C-44=PASS/POST-TUN-LIFETIME-STABLE"
    fi
  fi
  if [ "$POSTTUN_OLD_FSMOUNT_PRESENT" = 1 ]; then
    marker "4C-45-OLD-FSMOUNT-BOUNDARY=STILL-PRESENT"
    marker "4C-45=INCOMPLETE/GRANT-DID-NOT-TAKE-EFFECT"
  else
    marker "4C-45-OLD-FSMOUNT-BOUNDARY=GONE"
    [ "$POSTTUN_TMPFSMOUNT_OK" = 1 ] && marker "ROOTLESSKIT-COPYUP-TMPFS-MOUNT=OK"
    if [ -n "$POSTTUN_FIRST_FAIL_PID" ]; then
      marker "4C-45-OUTCOME=NEXT-STARTUP-BOUNDARY-CONFIRMED"
      marker "4C-45=PASS/NEXT-BOUNDARY-CONFIRMED"
    else
      marker "4C-45-OUTCOME=POST-TUN-LIFETIME-STABLE"
      marker "TARGET-LIFETIME-BLOCKER=GONE"
      marker "POST-TUN-LIFETIME=STABLE"
      marker "4C-45=PASS/POST-TUN-LIFETIME-STABLE"
    fi
  fi
  if [ "$POSTTUN_OLD_TMPDIRCREATE_PRESENT" = 1 ]; then
    marker "4C-46-OLD-TMPDIRCREATE-BOUNDARY=STILL-PRESENT"
    marker "4C-46=INCOMPLETE/GRANT-DID-NOT-TAKE-EFFECT"
  else
    marker "4C-46-OLD-TMPDIRCREATE-BOUNDARY=GONE"
    [ "$POSTTUN_RODIR_OK" = 1 ] && marker "ROOTLESSKIT-COPYUP-RO-DIR-CREATE=OK"
    [ "$POSTTUN_MOVEMOUNT_OK" = 1 ] && marker "ROOTLESSKIT-COPYUP-MOVE-MOUNT=OK"
    if [ -n "$POSTTUN_FIRST_FAIL_PID" ]; then
      marker "4C-46-OUTCOME=NEXT-STARTUP-BOUNDARY-CONFIRMED"
      marker "4C-46=PASS/NEXT-BOUNDARY-CONFIRMED"
    else
      marker "4C-46-OUTCOME=POST-TUN-LIFETIME-STABLE"
      marker "TARGET-LIFETIME-BLOCKER=GONE"
      marker "POST-TUN-LIFETIME=STABLE"
      marker "4C-46=PASS/POST-TUN-LIFETIME-STABLE"
    fi
  fi
  if [ "$POSTTUN_OLD_TMPDIRMOUNTON_PRESENT" = 1 ]; then
    marker "4C-47-OLD-TMPDIRMOUNTON-BOUNDARY=STILL-PRESENT"
    marker "4C-47=INCOMPLETE/GRANT-DID-NOT-TAKE-EFFECT"
  else
    marker "4C-47-OLD-TMPDIRMOUNTON-BOUNDARY=GONE"
    [ "$POSTTUN_MOVEMOUNT_OK" = 1 ] && marker "ROOTLESSKIT-COPYUP-MOVE-MOUNT=OK"
    if [ -n "$POSTTUN_FIRST_FAIL_PID" ]; then
      marker "4C-47-OUTCOME=NEXT-STARTUP-BOUNDARY-CONFIRMED"
      marker "4C-47=PASS/NEXT-BOUNDARY-CONFIRMED"
    else
      marker "4C-47-OUTCOME=POST-TUN-LIFETIME-STABLE"
      marker "TARGET-LIFETIME-BLOCKER=GONE"
      marker "POST-TUN-LIFETIME=STABLE"
      marker "4C-47=PASS/POST-TUN-LIFETIME-STABLE"
    fi
  fi
  if [ "$POSTTUN_OLD_LNKCREATE_PRESENT" = 1 ]; then
    marker "4C-48-OLD-LNKCREATE-BOUNDARY=STILL-PRESENT"
    marker "4C-48=INCOMPLETE/GRANT-DID-NOT-TAKE-EFFECT"
  else
    marker "4C-48-OLD-LNKCREATE-BOUNDARY=GONE"
    [ "$POSTTUN_SYMLINK_OK" = 1 ] && marker "ROOTLESSKIT-COPYUP-SYMLINK-CREATE=OK"
    if [ -n "$POSTTUN_FIRST_FAIL_PID" ]; then
      marker "4C-48-OUTCOME=NEXT-STARTUP-BOUNDARY-CONFIRMED"
      marker "4C-48=PASS/NEXT-BOUNDARY-CONFIRMED"
    else
      marker "4C-48-OUTCOME=POST-TUN-LIFETIME-STABLE"
      marker "TARGET-LIFETIME-BLOCKER=GONE"
      marker "POST-TUN-LIFETIME=STABLE"
      marker "4C-48=PASS/POST-TUN-LIFETIME-STABLE"
    fi
  fi
  if [ "$POSTTUN_OLD_CGROUPMOUNTON_PRESENT" = 1 ]; then
    marker "4C-49-OLD-CGROUPMOUNTON-BOUNDARY=STILL-PRESENT"
    marker "4C-49=INCOMPLETE/GRANT-DID-NOT-TAKE-EFFECT"
  else
    marker "4C-49-OLD-CGROUPMOUNTON-BOUNDARY=GONE"
    [ "$POSTTUN_CGROUPMOVE_OK" = 1 ] && marker "ROOTLESSKIT-CGROUP-MOVE-MOUNT=OK"
    if [ -n "$POSTTUN_FIRST_FAIL_PID" ]; then
      marker "4C-49-OUTCOME=NEXT-STARTUP-BOUNDARY-CONFIRMED"
      marker "4C-49=PASS/NEXT-BOUNDARY-CONFIRMED"
    else
      marker "4C-49-OUTCOME=POST-TUN-LIFETIME-STABLE"
      marker "TARGET-LIFETIME-BLOCKER=GONE"
      marker "POST-TUN-LIFETIME=STABLE"
      marker "4C-49=PASS/POST-TUN-LIFETIME-STABLE"
    fi
  fi
  if [ "$POSTTUN_OLD_LNKREAD_PRESENT" = 1 ]; then
    marker "4C-50-OLD-LNKREAD-BOUNDARY=STILL-PRESENT"
    marker "4C-50=INCOMPLETE/GRANT-DID-NOT-TAKE-EFFECT"
  else
    marker "4C-50-OLD-LNKREAD-BOUNDARY=GONE"
    [ "$POSTTUN_HOSTSREAD_OK" = 1 ] && marker "ROOTLESSKIT-ETC-HOSTS-READ=OK"
    if [ -n "$POSTTUN_FIRST_FAIL_PID" ]; then
      marker "4C-50-OUTCOME=NEXT-STARTUP-BOUNDARY-CONFIRMED"
      marker "4C-50=PASS/NEXT-BOUNDARY-CONFIRMED"
    else
      marker "4C-50-OUTCOME=POST-TUN-LIFETIME-STABLE"
      marker "TARGET-LIFETIME-BLOCKER=GONE"
      marker "POST-TUN-LIFETIME=STABLE"
      marker "4C-50=PASS/POST-TUN-LIFETIME-STABLE"
    fi
  fi
  if [ "$POSTTUN_OLD_CONFFILEREAD_PRESENT" = 1 ]; then
    marker "4C-51-OLD-CONFFILEREAD-BOUNDARY=STILL-PRESENT"
    marker "4C-51=INCOMPLETE/GRANT-DID-NOT-TAKE-EFFECT"
  else
    marker "4C-51-OLD-CONFFILEREAD-BOUNDARY=GONE"
    [ "$POSTTUN_HOSTSREAD_OK" = 1 ] && marker "ROOTLESSKIT-ETC-HOSTS-READ=OK"
    if [ -n "$POSTTUN_FIRST_FAIL_PID" ]; then
      marker "4C-51-OUTCOME=NEXT-STARTUP-BOUNDARY-CONFIRMED"
      marker "4C-51=PASS/NEXT-BOUNDARY-CONFIRMED"
    else
      marker "4C-51-OUTCOME=POST-TUN-LIFETIME-STABLE"
      marker "TARGET-LIFETIME-BLOCKER=GONE"
      marker "POST-TUN-LIFETIME=STABLE"
      marker "4C-51=PASS/POST-TUN-LIFETIME-STABLE"
    fi
  fi
  if [ "$POSTTUN_OLD_CONFOPEN_PRESENT" = 1 ]; then
    marker "4C-52-OLD-CONFOPEN-BOUNDARY=STILL-PRESENT"
    marker "4C-52=INCOMPLETE/GRANT-DID-NOT-TAKE-EFFECT"
  else
    marker "4C-52-OLD-CONFOPEN-BOUNDARY=GONE"
    [ "$POSTTUN_HOSTSREAD_OK" = 1 ] && marker "ROOTLESSKIT-ETC-HOSTS-READ=OK"
    if [ -n "$POSTTUN_FIRST_FAIL_PID" ]; then
      marker "4C-52-OUTCOME=NEXT-STARTUP-BOUNDARY-CONFIRMED"
      marker "4C-52=PASS/NEXT-BOUNDARY-CONFIRMED"
    else
      marker "4C-52-OUTCOME=POST-TUN-LIFETIME-STABLE"
      marker "TARGET-LIFETIME-BLOCKER=GONE"
      marker "POST-TUN-LIFETIME=STABLE"
      marker "4C-52=PASS/POST-TUN-LIFETIME-STABLE"
    fi
  fi
  if [ "$POSTTUN_OLD_LNKUNLINK_PRESENT" = 1 ]; then
    marker "4C-53-OLD-LNKUNLINK-BOUNDARY=STILL-PRESENT"
    marker "4C-53=INCOMPLETE/GRANT-DID-NOT-TAKE-EFFECT"
  else
    marker "4C-53-OLD-LNKUNLINK-BOUNDARY=GONE"
    [ "$POSTTUN_REBUILD_COMPLETE_OK" = 1 ] && marker "ROOTLESSKIT-REBUILD-STAGE=COMPLETE"
    [ "$POSTTUN_RESOLVREMOVE_OK" = 1 ] && marker "ROOTLESSKIT-ETC-RESOLV-SYMLINK-REMOVE=OK"
    if [ -n "$POSTTUN_FIRST_FAIL_PID" ]; then
      marker "4C-53-OUTCOME=NEXT-STARTUP-BOUNDARY-CONFIRMED"
      marker "4C-53=PASS/NEXT-BOUNDARY-CONFIRMED"
    else
      marker "4C-53-OUTCOME=POST-TUN-LIFETIME-STABLE"
      marker "TARGET-LIFETIME-BLOCKER=GONE"
      marker "POST-TUN-LIFETIME=STABLE"
      marker "4C-53=PASS/POST-TUN-LIFETIME-STABLE"
    fi
  fi
  marker "4C-38=PROVEN/PRIMARY-BOUNDARY-ESTABLISHED"
else
  marker "4C-38=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-39=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-40=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-41=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-42=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-43=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-44=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-45=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-46=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-47=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-48=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-49=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-50=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-51=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-52=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-53=INCOMPLETE/ORDER_NOT_ESTABLISHED"
  marker "4C-49-CONFINEMENT-GATE=${POSTTUN_GATE_VERDICT:-(the gate did not run — see 53-posttun-verdict.txt)}"
  POSTTUN_NOT_ESTABLISHED=1
fi

# Give the sampler its grace, then collect.
for i in $(seq 1 100); do
  [ -f /tmp/p4b-work/sampler.done ] && break
  sleep 0.1
done
kill "$SAMPLER_PID" 2>/dev/null || true
wait "$SAMPLER_PID" 2>/dev/null || true
# A sampler killed between an atomic write's temp and its rename leaves
# the temp behind; nothing consumes it.
rm -f "$EVIDENCE_DIR"/.write-* 2>/dev/null || true

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
    # rename(2) atomically replaces the path's inode (an executed file
    # keeps running); no rm-then-rename gap a concurrent exec could hit
    # with ENOENT.
    mv /usr/bin/.slirp4netns.orig /usr/bin/slirp4netns \
      || note "FAIL: the original binary could not be renamed back into the path"
    restorecon /usr/bin/slirp4netns 2>/dev/null || true
    # The failure path's restore is verified against the pre-staging
    # record: byte (sha256), SELinux type, and mode. A restore that did
    # not reproduce the original leaves a non-composition binary in the
    # flow path — that is a FAIL, not a silent INCOMPLETE.
    PROBE_PLACEMENT_RESTORED_SHA="$(sha256sum /usr/bin/slirp4netns 2>/dev/null | awk '{print $1}')"
    PROBE_PLACEMENT_RESTORED_CTX="$(context_of /usr/bin/slirp4netns)"
    PROBE_PLACEMENT_RESTORED_TYPE="$(printf '%s' "$PROBE_PLACEMENT_RESTORED_CTX" | cut -d: -f3)"
    PROBE_ORIG_TYPE="$(printf '%s' "$PROBE_ORIG_CTX" | cut -d: -f3)"
    PROBE_PLACEMENT_RESTORED_MODE="$(stat -c '%a %U:%G' /usr/bin/slirp4netns 2>/dev/null)"
    echo "restored sha256: $PROBE_PLACEMENT_RESTORED_SHA (expected $PROBE_ORIG_SHA)"
    echo "restored type:   $PROBE_PLACEMENT_RESTORED_TYPE (expected $PROBE_ORIG_TYPE)"
    echo "restored mode:   $PROBE_PLACEMENT_RESTORED_MODE (expected $PROBE_ORIG_MODE)"
    if [ "$PROBE_PLACEMENT_RESTORED_SHA" = "$PROBE_ORIG_SHA" ] && [ "$PROBE_PLACEMENT_RESTORED_TYPE" = "$PROBE_ORIG_TYPE" ] && [ "$PROBE_PLACEMENT_RESTORED_MODE" = "$PROBE_ORIG_MODE" ]; then
      marker "SLIRP-TUN-COMMAND-FILTER=NOT_PROBED"
      finish INCOMPLETE; exit 0
    fi
    marker "BLOCKER=the probe placement failure left a non-original binary in the flow path (restore sha/type/mode mismatch)"
    finish FAIL; exit 0
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
  # The unstarted cross-op proof makes the phase INCOMPLETE even when
  # every gate of the phase itself passed: the phase's own gates and the
  # cross-op proof are both mandatory for a PASS. The 4C-38 lifetime
  # proof rides the same rule: an unestablished causal order keeps the
  # phase INCOMPLETE (no guessing).
  # A still-present old boundary is a hard phase failure (the grant
  # demonstrably did not take effect); it outranks the cross-op
  # INCOMPLETE. All fifteen standing gone-gates apply: the 4C-53
  # rebuild-symlink unlink boundary (the phase's own widening), the
  # 4C-52 resolved-pair open boundary (the phase's own widening), the
  # 4C-51 resolved-file read boundary (the prior phase's own grant),
  # the 4C-50 read widening boundary (the phase's own grant), the 4C-49
  # cgroup move-mount mounton boundary, the 4C-48 rebuild
  # symlink-create boundary, the 4C-47 move-mount target mounton
  # boundary, the 4C-46 .ro dir-create boundary, the 4C-45 tmpfs
  # filesystem-mount boundary, the 4C-44 etc mounton boundary, the
  # 4C-43 tmp mounton, the 4C-42 create, the 4C-41 add_name, the 4C-40
  # write and the 4C-39 mounton boundaries (the standing regression
  # guards). The machinery's own standing invariant gate
  # (NO-PREANCHOR-POST) outranks them all: a pre-anchor POST
  # classification means the ladder itself is unreliable — the phase
  # HOLDs and the staircase does not continue.
  if [ "${POSTTUN_ESTABLISHED:-0}" = 1 ] && [ "${POSTTUN_NO_PREANCHOR_POST_OK:-0}" != 1 ]; then
    marker "BLOCKER=NO-PREANCHOR-POST failed: a POST-FAILURE/CLEANUP classification precedes the terminal anchor — the machinery standing invariant is violated (see 53-posttun-verdict.txt; the phase HOLDs, the staircase does not continue)"
    finish INCOMPLETE
    exit 0
  fi
  if [ "${POSTTUN_GATE_VERDICT:-}" = "BLOCKED" ]; then
    marker "4C-49=BLOCKED/CONFINEMENT-NOT-PROVEN"
    marker "BLOCKER=the 4C-49 confinement gate did not pass (see 53-posttun-verdict.txt; no cgroup_t:dir mounton authority may be granted)"
    finish INCOMPLETE
    exit 0
  fi
  if [ "${POSTTUN_OLD_CONFOPEN_PRESENT:-0}" = 1 ]; then
    marker "BLOCKER=the 4C-52 resolved-pair open widening did not remove the old rootlesskit_t -> net_conf_t:file open boundary (see 53-posttun-verdict.txt)"
    finish FAIL
    exit 0
  fi
  if [ "${POSTTUN_OLD_CONFFILEREAD_PRESENT:-0}" = 1 ]; then
    marker "BLOCKER=the 4C-51 resolved-file read grant did not remove the old rootlesskit_t -> net_conf_t:file read boundary (see 53-posttun-verdict.txt)"
    finish FAIL
    exit 0
  fi
  if [ "${POSTTUN_OLD_LNKREAD_PRESENT:-0}" = 1 ]; then
    marker "BLOCKER=the 4C-50 read widening did not remove the old rootlesskit_t -> tmpfs_t:lnk_file read boundary (see 53-posttun-verdict.txt)"
    finish FAIL
    exit 0
  fi
  if [ "${POSTTUN_OLD_CGROUPMOUNTON_PRESENT:-0}" = 1 ]; then
    marker "BLOCKER=the 4C-49 cgroup move-mount mounton grant did not remove the old rootlesskit_t -> cgroup_t:dir mounton boundary (see 53-posttun-verdict.txt)"
    finish FAIL
    exit 0
  fi
  if [ "${POSTTUN_OLD_LNKCREATE_PRESENT:-0}" = 1 ]; then
    marker "BLOCKER=the 4C-48 rebuild symlink create grant did not remove the old rootlesskit_t -> tmpfs_t:lnk_file create boundary (see 53-posttun-verdict.txt)"
    finish FAIL
    exit 0
  fi
  if [ "${POSTTUN_OLD_TMPDIRMOUNTON_PRESENT:-0}" = 1 ]; then
    marker "BLOCKER=the 4C-47 move-mount mounton grant did not remove the old rootlesskit_t -> tmpfs_t:dir mounton boundary (see 53-posttun-verdict.txt)"
    finish FAIL
    exit 0
  fi
  if [ "${POSTTUN_OLD_TMPDIRCREATE_PRESENT:-0}" = 1 ]; then
    marker "BLOCKER=the 4C-46 .ro dir create grant did not remove the old rootlesskit_t -> tmpfs_t:dir create boundary (see 53-posttun-verdict.txt)"
    finish FAIL
    exit 0
  fi
  if [ "${POSTTUN_OLD_FSMOUNT_PRESENT:-0}" = 1 ]; then
    marker "BLOCKER=the 4C-45 tmpfs filesystem mount grant did not remove the old rootlesskit_t -> tmpfs_t:filesystem mount boundary (see 53-posttun-verdict.txt)"
    finish FAIL
    exit 0
  fi
  if [ "${POSTTUN_OLD_ETCMOUNTON_PRESENT:-0}" = 1 ]; then
    marker "BLOCKER=the 4C-44 etc mounton grant did not remove the old rootlesskit_t -> etc_t:dir mounton boundary (see 53-posttun-verdict.txt)"
    finish FAIL
    exit 0
  fi
  if [ "${POSTTUN_OLD_TMPMOUNTON_PRESENT:-0}" = 1 ]; then
    marker "BLOCKER=the 4C-43 mounton grant did not remove the old rootlesskit_t -> tmp_t:dir mounton boundary (see 53-posttun-verdict.txt)"
    finish FAIL
    exit 0
  fi
  if [ "${POSTTUN_OLD_CREATE_PRESENT:-0}" = 1 ]; then
    marker "BLOCKER=the 4C-42 create grant did not remove the old rootlesskit_t -> tmp_t:dir create boundary (see 53-posttun-verdict.txt)"
    finish FAIL
    exit 0
  fi
  if [ "${POSTTUN_OLD_ADDNAME_PRESENT:-0}" = 1 ]; then
    marker "BLOCKER=the 4C-41 add_name grant did not remove the old rootlesskit_t -> tmp_t:dir add_name boundary (see 53-posttun-verdict.txt)"
    finish FAIL
    exit 0
  fi
  if [ "${POSTTUN_OLD_TMPWRITE_PRESENT:-0}" = 1 ]; then
    marker "BLOCKER=the 4C-40 write grant did not remove the old rootlesskit_t -> tmp_t:dir write boundary (see 53-posttun-verdict.txt)"
    finish FAIL
    exit 0
  fi
  if [ "${POSTTUN_OLD_BOUNDARY_PRESENT:-0}" = 1 ]; then
    marker "BLOCKER=the 4C-39 mounton grant did not remove the old rootlesskit_t -> root_t:dir mounton boundary (see 53-posttun-verdict.txt)"
    finish FAIL
    exit 0
  fi
  if [ "${CROSS_NOT_PROVEN:-0}" = 1 ] || [ "${POSTTUN_NOT_ESTABLISHED:-0}" = 1 ]; then
    finish INCOMPLETE
    exit 0
  fi
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
