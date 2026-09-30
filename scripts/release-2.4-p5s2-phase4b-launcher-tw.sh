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
    "$TRANSFERRED/provision-builder.sh" 2>/dev/null || true
} > "$EVIDENCE_DIR/01-composition-inputs.txt" 2>&1
while IFS='=' read -r key want; do
  case "$key" in
    binary_sha256) file="$TRANSFERRED/docker-helper" ;;
    te_sha256) file="$TRANSFERRED/docker-helper.te" ;;
    fc_sha256) file="$TRANSFERRED/docker-helper.fc" ;;
    unit_sha256) file="$TRANSFERRED/docker-helper-builder.service" ;;
    provision_sha256) file="$TRANSFERRED/provision-builder.sh" ;;
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

# The REAL builder identity + the REAL unit + the pinned payload (P4-A1 shape).
log 'A2: builder identity + REAL unit + pinned payload install'
sh "$TRANSFERRED/provision-builder.sh" > "$EVIDENCE_DIR/a2-provision.txt" 2>&1 \
  || { note "provision-builder.sh failed"; finish INCOMPLETE; exit 0; }
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
T0="$(date +%s)"
echo "$T0" > "$EVIDENCE_DIR/window-start-epoch"
auditctl -s > "$EVIDENCE_DIR/audit-status-window-start.txt" 2>&1 || true

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
    fi
    for entry in \
      "$ST_OP_DIR:state-op" \
      "$ST_OP_DIR/root:state-root" \
      "$ST_OP_DIR/rootlesskit-state:state-rkstate" \
      "$RT_OP_DIR:runtime-op"; do
      path="${entry%%:*}"; label="${entry##*:}"
      ctx="$(context_of "$path")"
      if [ -n "$ctx" ]; then
        [ -s "$EVIDENCE_DIR/first.$label" ] || printf '%s\n' "$ctx" > "$EVIDENCE_DIR/first.$label"
        printf '%s\n' "$ctx" > "$EVIDENCE_DIR/last.$label"
        grep -aqx "$ctx" "$EVIDENCE_DIR/all.$label" 2>/dev/null || printf '%s\n' "$ctx" >> "$EVIDENCE_DIR/all.$label"
      fi
    done
    for entry in \
      "$STATE_ROOT:state-root-container" \
      "$STATE_ROOT/ops:state-ops-container" \
      "$RUNTIME_ROOT:runtime-root-container" \
      "$RUNTIME_ROOT/ops:runtime-ops-container"; do
      path="${entry%%:*}"; label="${entry##*:}"
      ctx="$(context_of "$path")"
      [ -n "$ctx" ] && printf '%s\n' "$ctx" > "$EVIDENCE_DIR/container.$label"
    done
    if [ -n "$seen_pid" ] && [ ! -d "/proc/$seen_pid" ] && [ ! -d "$RT_OP_DIR" ] && [ ! -d "$ST_OP_DIR" ]; then
      printf 'CONVERGED %s\n' "$(date +%s.%N)" >> "$EVIDENCE_DIR/05-flow-context.txt"
      break
    fi
    sleep 0.005
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
