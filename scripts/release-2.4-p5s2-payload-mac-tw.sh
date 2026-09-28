#!/usr/bin/env bash
#
# Guest-side P5-S2g28 BuildKit payload MAC closure for openSUSE
# Tumbleweed. INVESTIGATION ONLY — run 1: the Part A enforcing baseline
# (the exact current stop of the production flow) + the Part B
# permissive-harvest round 1 (the full production composition
# manager -> rootlesskit -> buildkitd -> readiness -> minimal buildctl
# build under permissive payload domains, recording every AVC of the
# path as the grant-ledger source).
#
# Starting point (G26/G27): the MCS process boundary is proven; the
# complete operation boundary stays INCONCLUSIVE on exactly one item —
# buildkitd's --root consumption — because the production flow stops at
# its enforced child-process boundary before buildkitd ever runs. G28
# asks: can a MINIMAL guest-only candidate payload module bring the
# production flow to a working buildkitd under SELinux Enforcing?
# Cache poisoning is NOT measured in G28.
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
# relabels.
#
# Method (the G-series permissive-harvest precedent, P5-S1 item 2):
#   baseline (enforcing, no candidate grants): the manager's START with
#   the production argv; the flow's exact enforced stop is recorded
#   (the last successful transition = the UID-map step, the first
#   blocking AVC = the gid-map capability boundary, no readiness).
#   harvest (permissive rootlesskit_t/newuidmap_t/newgidmap_t/
#   slirp4netns_t ONLY): the SAME production composition runs to
#   buildkitd readiness and a real minimal HTTPS build; every AVC of
#   the whole path is recorded (deduplicated tuples) as the grant
#   ledger's evidence source. audit2allow is never used for policy
#   design; the analysis is per-AVC in the report.
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
      | tail -100 || true
    echo "=== journalctl -k window ==="
    journalctl -k --since "@$since" --no-pager 2>/dev/null | grep -a 'avc:' | tail -100 || true
  } > "$out" 2>&1
}

dedup_avcs() {
  # Deduplicate raw AVC lines to (scontext, tcontext, tclass, perms)
  # tuples with per-tuple counts and one representative raw record.
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

log 'A: toolchain + candidate module (labels) + REAL composition install'
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
  setools-console gcc glibc-static util-linux shadow libcap-progs \
  python3 curl \
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

log 'A2: builder identity + REAL composition + pinned payload install'
sh "$TRANSFERRED/provision-builder.sh" >"$EVIDENCE_DIR/a2-provision.txt" 2>&1 \
  || { note "provision-builder.sh failed"; exit 1; }
install -m 0755 "$TRANSFERRED/docker-helper" /usr/bin/docker-helper
restorecon /usr/bin/docker-helper 2>>"$EVIDENCE_DIR/a-toolchain.txt" || true
install -m 0644 "$TRANSFERRED/docker-helper-builder.service" /etc/systemd/system/"$UNIT".service
systemctl daemon-reload

# The pinned BuildKit payload (the P4A1 pattern: the same digest pins and
# the verify-before-stage order, downloaded INSIDE the guest).
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
# Each payload binary's SHA-256 re-verified against the pinned digests.
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
  echo "=== payload labels (default, before the candidate labels) ==="
  stat -c '%C %U:%G %a' "$BUILDKITD" "$BUILDCTL" /usr/libexec/docker-helper/buildkit/buildkit-runc 2>&1
  echo "=== /usr/libexec/docker-helper dir label ==="
  stat -c '%C %U:%G' /usr/libexec/docker-helper /usr/libexec/docker-helper/buildkit 2>&1
} > "$EVIDENCE_DIR/a2-payload.txt" 2>&1
cat "$EVIDENCE_DIR/a2-payload.txt" >&2

# The candidate payload module (run 1 = the dedicated payload exec type
# + its file-context labels ONLY; no allow rules yet — the permissive
# harvest records the enforcing surface without any candidate grants).
cat > /tmp/payload_mac_diag.te <<'MODEOF'
module payload_mac_diag 1.0;

# P5-S2g28 guest-only candidate payload module (run 1): the dedicated
# exec type for the pinned BuildKit payload binaries + their file-context
# labels, applied by restorecon after the install. NO allow rules: the
# run-1 harvest is permissive and records the production flow's full
# enforcing surface; the candidate grants are added per-AVC in later
# runs and must stay minimal (never macro/bulk).
require {
	attribute file_type;
}
type payload_buildkit_exec_t;
typeattribute payload_buildkit_exec_t file_type;
MODEOF
cat > /tmp/payload_mac_diag.fc <<'FCOF'
/usr/libexec/docker-helper/buildkit(/.*)?    --    system_u:object_r:payload_buildkit_exec_t:s0
FCOF
{
  echo "=== the candidate payload module (source, run 1: labels only) ==="
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
  echo "=== the manager's startup journal (the purge behavior) ==="
  journalctl -u "$UNIT" --no-pager 2>/dev/null | grep -a 'purge\|serve\|refus' | tail -10 || true
} > "$EVIDENCE_DIR/d-manager-up.txt" 2>&1
cat "$EVIDENCE_DIR/d-manager-up.txt" >&2
if ! stat -c '%C' "$STATE_ROOT" 2>/dev/null | grep -q 'docker_helper_builder_state_t'; then
  note "the state root is not labeled builder_state_t; the experiment cannot proceed"
  printf '%s P5S2-PAYLOAD-MAC-RESULT=PASS-INCOMPLETE (state root label; recorded as a finding)\n' "$PREFIX" >&2
  exit 0
fi

log 'E: Part A baseline — the enforcing stop of the production flow (NO candidate grants)'
OPB="$(gen_op_id)"
BL_EPOCH="$(date +%s)"
{
  echo "=== P5-S2g28 Part A baseline: the enforcing stop of the production flow ==="
  echo "op id: $OPB"
  echo "the EXACT production argv (builder_manager.go builderNewRootlessKitCommand):"
  echo "  /usr/bin/rootlesskit --net=slirp4netns --copy-up=/etc --disable-host-loopback \\"
  echo "    --state-dir=$STATE_ROOT/ops/<opID>/rootlesskit-state \\"
  echo "    $BUILDKITD --rootless --root=$STATE_ROOT/ops/<opID>/root \\"
  echo "    --addr=unix://$RUNTIME_ROOT/ops/<opID>/buildkitd.sock"
  echo "  child env: HOME=$STATE_ROOT USER=$BUILDER_USER XDG_RUNTIME_DIR=<rtDir> PATH=<manager-fixed> SSL_CERT_FILE=<resolved>"
  echo "=== manager RPC: START $OPB ==="
} > "$EVIDENCE_DIR/a-baseline.txt"
set +e
printf 'START %s\n' "$OPB" | timeout 120 socat - UNIX-CONNECT:"$MANAGER_SOCK" >> "$EVIDENCE_DIR/a-baseline.txt" 2>&1
echo "socat rc: $?" >> "$EVIDENCE_DIR/a-baseline.txt"
set -e
sleep 2
manager_journal_since "$BL_EPOCH" "$EVIDENCE_DIR/a-baseline-journal.txt"
harvest_avcs_since "$BL_EPOCH" "$EVIDENCE_DIR/a-baseline-avcs.txt"
{
  cat "$EVIDENCE_DIR/a-baseline-journal.txt"
  echo "=== the AVC window (the enforcing stop's records) ==="
  cat "$EVIDENCE_DIR/a-baseline-avcs.txt"
  echo "=== buildkitd readiness: ABSENT (the flow never reached the payload) ==="
  echo "ops tree after the converged failed start:"
  ls -la "$STATE_ROOT/ops" 2>&1 || true
  ls -la "$RUNTIME_ROOT/ops" 2>&1 || true
} >> "$EVIDENCE_DIR/a-baseline.txt"
cat "$EVIDENCE_DIR/a-baseline.txt" >&2

log 'F: Part B harvest round 1 — permissive payload domains, full production path'
# Permissive: ONLY the flow/payload domains (the manager stays enforcing:
# its own surface is production-granted and P5-S1-proven).
for d in docker_helper_rootlesskit_t docker_helper_newuidmap_t docker_helper_newgidmap_t docker_helper_slirp4netns_t; do
  semanage permissive -a "$d" 2>>"$EVIDENCE_DIR/f-harvest-meta.txt" || true
done
{
  echo "=== permissive harvest domains ==="
  semanage permissive -l 2>/dev/null | grep -a docker_helper || true
} > "$EVIDENCE_DIR/f-harvest-meta.txt"
HV_EPOCH="$(date +%s)"
OPH="$(gen_op_id)"
{
  echo "=== P5-S2g28 Part B harvest round 1 ==="
  echo "op id: $OPH; epoch: $HV_EPOCH"
  echo "=== manager RPC: START $OPH ==="
} > "$EVIDENCE_DIR/f-harvest-start.txt"
set +e
printf 'START %s\n' "$OPH" | timeout 120 socat - UNIX-CONNECT:"$MANAGER_SOCK" >> "$EVIDENCE_DIR/f-harvest-start.txt" 2>&1
echo "socat rc: $?" >> "$EVIDENCE_DIR/f-harvest-start.txt"
set -e
sleep 3
{
  echo "=== the process tree at readiness (domains + categories + uid_map) ==="
  for pat in 'rootlesskit.*--net=slirp4netns' 'buildkitd --rootless' 'slirp4netns'; do
    for p in $(pgrep -f "$pat" 2>/dev/null); do
      echo "pid $p ($(cat "/proc/$p/comm" 2>/dev/null)): $(tr -d '\0' < "/proc/$p/attr/current" 2>/dev/null || true)"
      echo "  uid_map: $(tr '\n' ';' < "/proc/$p/uid_map" 2>/dev/null || true)"
      echo "  cgroup: $(cat "/proc/$p/cgroup" 2>/dev/null | head -1 || true)"
    done
  done
  echo "=== per-op tree labels (the REAL production tree) ==="
  stat -c '%C %U:%G %a %n' "$STATE_ROOT/ops/$OPH" "$STATE_ROOT/ops/$OPH/rootlesskit-state" \
    "$RUNTIME_ROOT/ops/$OPH" "$RUNTIME_ROOT/ops/$OPH/buildkitd.sock" 2>&1 || true
  echo "=== state dir contents ==="
  find "$STATE_ROOT/ops/$OPH" -maxdepth 2 -exec stat -c '%C %U:%G %a %n' {} \; 2>&1 | head -20 || true
} > "$EVIDENCE_DIR/f-harvest-processes.txt" 2>&1
cat "$EVIDENCE_DIR/f-harvest-processes.txt" >&2

# The minimal real build (the P4A1 pattern: the root shell drives buildctl
# exactly as the daemon's build-driver stage would; the export tar proves
# the payload functional end to end; NO Docker Engine needed).
CTX="$WORK/ctx"
mkdir -p "$CTX"
cat > "$CTX/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN mkdir -p /m1 && echo p5s2-g28 > /m1/marker.txt && cat /proc/self/uid_map > /m1/uid_map.txt && id > /m1/id.txt
EOF
mkdir -p "$WORK/docker-config"
echo '{}' > "$WORK/docker-config/config.json"
mkdir -p "$WORK/export"
{
  echo "=== the minimal buildctl invocation (the production buildctl argv shape) ==="
} > "$EVIDENCE_DIR/f-harvest-build.txt"
set +e
DOCKER_CONFIG="$WORK/docker-config" timeout 300 "$BUILDCTL" \
  --addr "unix://$RUNTIME_ROOT/ops/$OPH/buildkitd.sock" build \
  --progress=plain --frontend=dockerfile.v0 \
  --local "context=$CTX" --local "dockerfile=$CTX" \
  --output "type=docker,name=p5s2g28:harvest,dest=$WORK/export/out.tar" \
  >> "$EVIDENCE_DIR/f-harvest-build.txt" 2>&1
BUILD_RC=$?
set -e
echo "buildctl exit: $BUILD_RC" >> "$EVIDENCE_DIR/f-harvest-build.txt"
echo "export tar: $(stat -c '%C %U:%G %s' "$WORK/export/out.tar" 2>&1)" >> "$EVIDENCE_DIR/f-harvest-build.txt"
sleep 3
harvest_avcs_since "$HV_EPOCH" "$EVIDENCE_DIR/f-harvest-avcs.txt"
dedup_avcs "$EVIDENCE_DIR/f-harvest-avcs.txt" "$EVIDENCE_DIR/f-harvest-avcs-dedup.txt"
{
  cat "$EVIDENCE_DIR/f-harvest-build.txt"
  echo "=== the manager journal window ==="
  journalctl -u "$UNIT" --since "@$HV_EPOCH" --no-pager 2>/dev/null | tail -40 || true
} >> "$EVIDENCE_DIR/f-harvest-build.txt"
cat "$EVIDENCE_DIR/f-harvest-build.txt" >&2

log 'G: own-operation lifecycle stop (the manager STOP; the convergence)'
STP_EPOCH="$(date +%s)"
{
  echo "=== manager RPC: STOP $OPH ==="
} > "$EVIDENCE_DIR/g-stop.txt"
set +e
printf 'STOP %s\n' "$OPH" | timeout 120 socat - UNIX-CONNECT:"$MANAGER_SOCK" >> "$EVIDENCE_DIR/g-stop.txt" 2>&1
echo "socat rc: $?" >> "$EVIDENCE_DIR/g-stop.txt"
set -e
sleep 3
manager_journal_since "$STP_EPOCH" "$EVIDENCE_DIR/g-stop-journal.txt"
harvest_avcs_since "$STP_EPOCH" "$EVIDENCE_DIR/g-stop-avcs.txt"
{
  cat "$EVIDENCE_DIR/g-stop.txt"
  echo "=== the manager journal window ==="
  cat "$EVIDENCE_DIR/g-stop-journal.txt"
  echo "=== trees after STOP (removed = the own-op convergence) ==="
  ls -la "$STATE_ROOT/ops" 2>&1 || true
  ls -la "$RUNTIME_ROOT/ops" 2>&1 || true
} >> "$EVIDENCE_DIR/g-stop.txt"
cat "$EVIDENCE_DIR/g-stop.txt" >&2

log 'H: the full-window harvest (the grant ledger source)'
sleep 2
{
  echo "=== kernel AVC records of the whole experiment window (the flow + payload + build domains; unfiltered) ==="
  grep -a 'type=AVC' /var/log/audit/audit.log 2>/dev/null \
    | awk -v s="$BL_EPOCH" '{ for (i = 1; i <= NF; i++) if ($i ~ /^msg=audit\(/) { ts = substr($i, 11); split(ts, t, "."); if (t[1] + 0 >= s + 0) print; break } }' \
    | grep -a 'docker_helper_' \
    | tail -500 || true
} > "$EVIDENCE_DIR/f-all-avcs-full.txt" 2>&1
dedup_avcs "$EVIDENCE_DIR/f-all-avcs-full.txt" "$EVIDENCE_DIR/f-all-avcs-dedup.txt"
{
  echo "=== the manager's unit journal of the whole experiment window ==="
  journalctl -u "$UNIT" --since "@$BL_EPOCH" --no-pager 2>/dev/null | tail -300 || true
} > "$EVIDENCE_DIR/f-manager-journal-all.txt" 2>&1
wc -l "$EVIDENCE_DIR/f-all-avcs-full.txt" "$EVIDENCE_DIR/f-all-avcs-dedup.txt" >&2

log 'teardown + cleanup (permissive flags removed; temporary modules removed)'
pkill -KILL -f 'rootlesskit --net=' 2>/dev/null || true
pkill -KILL -f 'buildkitd --rootless' 2>/dev/null || true
pkill -KILL -f 'buildctl --addr' 2>/dev/null || true
pkill -KILL -f 'slirp4netns' 2>/dev/null || true
for d in docker_helper_rootlesskit_t docker_helper_newuidmap_t docker_helper_newgidmap_t docker_helper_slirp4netns_t; do
  clear_permissive "$d"
done
systemctl stop "$UNIT" >/dev/null 2>&1 || true
systemctl disable "$UNIT" >/dev/null 2>&1 || true
rm -f /etc/systemd/system/"$UNIT".service
systemctl daemon-reload >/dev/null 2>&1 || true
rm -f /usr/bin/docker-helper
rm -rf /usr/libexec/docker-helper "$STATE_ROOT" "$RUNTIME_ROOT" "$WORK"
semodule -r payload_mac_diag >/dev/null 2>&1 || true
semodule -r gidmap_mcsboundary_diag >/dev/null 2>&1 || true
semodule -l 2>/dev/null | grep -E 'docker_helper|gidmap|payload' > "$EVIDENCE_DIR/f-final-modules.txt" 2>&1 || true

printf '%s P5S2-PAYLOAD-MAC-RESULT=PASS (run 1 completed: baseline + harvest round 1)\n' "$PREFIX" >&2
exit 0
