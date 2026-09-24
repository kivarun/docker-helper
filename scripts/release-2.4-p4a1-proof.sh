#!/usr/bin/env bash
#
# Release 2.4 P4-A1 proof: the PRODUCTION builder systemd unit boundary.
#
# Composition under test (all real; no M0/M1 mock anywhere):
#
#   systemd unit docker-helper-builder.service
#     (User/Group=docker-helper-builder, RuntimeDirectory/StateDirectory,
#      deliberate NoNewPrivileges exception, CapabilityBoundingSet=
#      CAP_SETUID CAP_SETGID, KillMode default = control-group)
#     ExecStart=/usr/bin/docker-helper builder serve   <- REAL manager role
#       | narrow START/STOP/PURGE protocol over
#       v /run/docker-helper-builder/manager.sock (0600 builder-owned)
#   setsid /usr/bin/rootlesskit --net=slirp4netns --copy-up=/etc
#     --disable-host-loopback  (distro rootlesskit)
#       v
#   /usr/libexec/docker-helper/buildkit/buildkitd --rootless (pinned v0.33.0)
#     op-private runtime/state/socket
#
# The root shell drives the manager protocol and buildctl (the same role
# the root daemon plays; the daemon-integration wiring is P6, the full
# packaging matrix and MAC policy are P5/P7 — deliberately out of scope).
#
# Proofs included:
#   1. provisioning through the REAL packaging/scripts/lib/provision-builder.sh
#      (dedicated identity + subuid/subgid, idempotent re-run no-op);
#   2. the proposed unit installs and starts; the manager process shows the
#      recorded NNP exception (NoNewPrivs: 0) and the minimal capability
#      bounding set (CapBnd = CAP_SETUID|CAP_SETGID exactly);
#   3. during a REAL build: manager, rootlesskit, buildkitd and the
#      unanchored slirp4netns are ALL members of the unit cgroup
#      (0::/system.slice/docker-helper-builder.service); uid_map shows the
#      builder uid mapping to in-ns root plus the provisioned subordinate
#      range; the child environment is exactly the production contract
#      (HOME=state root, per-op XDG_RUNTIME_DIR, fixed PATH,
#      SSL_CERT_FILE=resolved system bundle; NO USER — unlike M0/M1);
#   4. killing the manager during an active build: systemd restarts the
#      unit and settles ALL old children including the unanchored
#      slirp4netns (control-group kill); the new generation's startup
#      purge cleans the residue the wiped runtime tree left behind (the
#      P4 unit-boundary startup invariant); a fresh build works;
#   5. service stop during an active build settles all children within
#      TimeoutStopSec; the persistent state residue is cleaned by the
#      next start's purge (unit membership is NOT per-op ownership);
#   6. the startup invariant end to end: pid-file-less ambiguous residue
#      (the pre-pid-write crash window / the systemd-wiped runtime tree)
#      is cleaned at start, while noncanonical entries are preserved;
#   7. the resolved SSL_CERT_FILE path is readable INSIDE the child's
#      mount namespace through rootlesskit --copy-up=/etc (the openSUSE
#      /etc/ssl/ca-bundle.pem symlink case, rootlesskit#225); a real
#      HTTPS build exercises the bundle.
#
# Prereqs (installed by the caller): root shell; systemd; docker-helper at
# /usr/bin/docker-helper; the pinned BuildKit payload at
# /usr/libexec/docker-helper/buildkit/{buildkitd,buildctl,buildkit-runc};
# distro rootlesskit + slirp4netns + newuidmap/newgidmap; the provisioning
# script and the unit file reachable via P4A1_PROVISION_SCRIPT /
# P4A1_UNIT_FILE; python3. docker is optional (round-trip probes run when
# the Engine is reachable).

set -Eeuo pipefail

PREFIX='[release-2.4-p4a1]'
EVIDENCE_DIR="${P4A1_EVIDENCE_DIR:-/tmp/release-2.4-p4a1-evidence}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${P4A1_REPO_DIR:-$SCRIPT_DIR/..}"
PROVISION_SCRIPT="${P4A1_PROVISION_SCRIPT:-$REPO_DIR/packaging/scripts/lib/provision-builder.sh}"
UNIT_FILE="${P4A1_UNIT_FILE:-$REPO_DIR/packaging/systemd/system/docker-helper-builder.service}"
HELPER_BIN="${P4A1_HELPER_BIN:-/usr/bin/docker-helper}"

BUILDER_USER=docker-helper-builder
MGR_RUNTIME=/run/docker-helper-builder
MGR_STATE=/var/lib/docker-helper-builder
MGR_SOCK="$MGR_RUNTIME/manager.sock"
UNIT=docker-helper-builder.service
UNIT_CGROUP="/system.slice/$UNIT"
KEEP="${P4A1_KEEP:-}"

say() { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

evidence() {
  local name="$1" content="$2"
  mkdir -p "$EVIDENCE_DIR"
  printf '%s\n' "$content" > "$EVIDENCE_DIR/$name"
  say "evidence: $name ($(wc -l < "$EVIDENCE_DIR/$name") lines)"
}

evidence_cmd() {
  local name="$1"; shift
  local out
  out="$("$@" 2>&1 || true)"
  evidence "$name" "$out"
  printf '%s\n' "$out"
}

cleanup() {
  set +e
  systemctl stop "$UNIT" >/dev/null 2>&1 || true
  if [ -z "$KEEP" ]; then
    rm -rf "$P4A1_WORK" 2>/dev/null || true
  else
    say "P4A1_KEEP set: leaving workdir at $P4A1_WORK"
  fi
}
trap cleanup EXIT
P4A1_WORK="$(mktemp -d "${P4A1_WORK_BASE:-/tmp/release-2.4-p4a1-work.XXXXXXXX}")"

new_op_id() {
  printf 'op_%s' "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
}

# Root-side manager client: one request per connection, one response line.
mgr_call() {
  local payload="$1"
  python3 - "$MGR_SOCK" "$payload" <<'PY'
import socket, sys
path, payload = sys.argv[1], sys.argv[2].encode()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(180)
s.connect(path)
s.sendall(payload)
resp = b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
        if b"\n" in resp:
            break
finally:
    s.close()
print(resp.decode(errors="replace").strip())
PY
}

# as_builder runs a command as the dedicated builder identity.
as_builder() {
  setpriv --reuid "$(id -u "$BUILDER_USER")" --regid "$(id -g "$BUILDER_USER")" --clear-groups "$@"
}

proc_field() { # proc_field <pid> <status-field>
  awk -v f="$2" '$1 == f ":" { print $2; found = 1 } END { if (!found) exit 1 }' "/proc/$1/status" 2>/dev/null
}

proc_cgroup() {
  cat "/proc/$1/cgroup" 2>/dev/null || true
}

proc_environ() {
  tr '\0' '\n' < "/proc/$1/environ" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 0. environment identity + preconditions
# ---------------------------------------------------------------------------
say "=== 0. environment identity and preconditions ==="
evidence_cmd environment.txt bash -c 'uname -a
cat /etc/os-release | head -2
systemd --version | head -1
systemctl --version | head -1
cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo no-restrict-sysctl
cat /sys/kernel/security/lsm 2>/dev/null || echo no-lsm-sysfs
sestatus 2>/dev/null | grep -E "^SELinux status" || true'

command -v rootlesskit >/dev/null 2>&1 || fail "rootlesskit not installed"
command -v slirp4netns >/dev/null 2>&1 || fail "slirp4netns not installed"
command -v newuidmap >/dev/null 2>&1 || fail "newuidmap not installed"
command -v newgidmap >/dev/null 2>&1 || fail "newgidmap not installed"
command -v buildctl >/dev/null 2>&1 || fail "buildctl not installed"
command -v setpriv >/dev/null 2>&1 || fail "setpriv not installed"
command -v python3 >/dev/null 2>&1 || fail "python3 not installed"
[ -x "$HELPER_BIN" ] || fail "docker-helper binary missing at $HELPER_BIN"
[ -f "$PROVISION_SCRIPT" ] || fail "provisioning script missing at $PROVISION_SCRIPT"
[ -f "$UNIT_FILE" ] || fail "unit file missing at $UNIT_FILE"
[ -x "/usr/libexec/docker-helper/buildkit/buildkitd" ] || fail "pinned buildkitd missing at the product path"
[ -x "/usr/libexec/docker-helper/buildkit/buildctl" ] || fail "pinned buildctl missing at the product path"
[ -x "/usr/libexec/docker-helper/buildkit/buildkit-runc" ] || fail "pinned buildkit-runc missing at the product path"

evidence_run() {
  local name="$1"; shift
  local out
  out="$("$@" 2>&1 || true)"
  evidence "$name" "$out"
  printf '%s\n' "$out"
}

collect_versions() {
  rootlesskit --version
  slirp4netns --version
  /usr/libexec/docker-helper/buildkit/buildkitd --version
  /usr/libexec/docker-helper/buildkit/buildctl --version
  "$HELPER_BIN" builder serve --help 2>&1 | head -2
}

collect_shas() {
  sha256sum "$HELPER_BIN" "$UNIT_FILE" "$PROVISION_SCRIPT" \
    /usr/libexec/docker-helper/buildkit/buildkitd \
    /usr/libexec/docker-helper/buildkit/buildctl \
    /usr/libexec/docker-helper/buildkit/buildkit-runc
}

evidence_run versions.txt collect_versions
evidence_run shas.txt collect_shas

if docker info >/dev/null 2>&1; then
  DOCKER_AVAILABLE=1
  say "rootful Docker engine reachable: export round-trip probes enabled"
else
  DOCKER_AVAILABLE=0
  say "Docker engine not reachable: export round-trip probes skipped (recorded)"
fi

# ---------------------------------------------------------------------------
# 1. provisioning through the REAL provision-builder.sh
# ---------------------------------------------------------------------------
say "=== 1. builder identity + subordinate IDs (real provision-builder.sh) ==="
BEFORE_ID="$(id "$BUILDER_USER" 2>&1 || true)"
BEFORE_SUBUID="$(grep "^$BUILDER_USER:" /etc/subuid || true)"
BEFORE_SUBGID="$(grep "^$BUILDER_USER:" /etc/subgid || true)"
evidence provisioning-before.txt "identity before: ${BEFORE_ID:-<absent>}
subuid before: ${BEFORE_SUBUID:-<absent>}
subgid before: ${BEFORE_SUBGID:-<absent>}"

PROVISION_OUT="$(sh "$PROVISION_SCRIPT" 2>&1)" || fail "provision-builder.sh failed: $PROVISION_OUT"
evidence provisioning-run1.txt "$PROVISION_OUT"

AFTER_SUBUID="$(grep "^$BUILDER_USER:" /etc/subuid || true)"
AFTER_SUBGID="$(grep "^$BUILDER_USER:" /etc/subgid || true)"
BUILDER_UID="$(id -u "$BUILDER_USER")"
BUILDER_GID="$(id -g "$BUILDER_USER")"
[ -n "$AFTER_SUBUID" ] || fail "subuid entry missing after provisioning"
[ -n "$AFTER_SUBGID" ] || fail "subgid entry missing after provisioning"
SUBUID_START="$(awk -F: '{print $2}' <<<"$AFTER_SUBUID")"
SUBUID_COUNT="$(awk -F: '{print $3}' <<<"$AFTER_SUBUID")"
SUBGID_START="$(awk -F: '{print $2}' <<<"$AFTER_SUBGID")"
SUBGID_COUNT="$(awk -F: '{print $3}' <<<"$AFTER_SUBGID")"
[ "$SUBUID_COUNT" -ge 65536 ] || fail "subuid count $SUBUID_COUNT < 65536"
[ "$SUBGID_COUNT" -ge 65536 ] || fail "subgid count $SUBGID_COUNT < 65536"
[ "$SUBGID_START" = "$SUBUID_START" ] || fail "subgid range $SUBGID_START != subuid range $SUBUID_START (one range must be written to both)"
NOLOGIN_SHELL="$(awk -F: -v u="$BUILDER_USER" '$1 == u {print $7}' /etc/passwd)"
[ "$NOLOGIN_SHELL" = "/usr/sbin/nologin" ] || fail "builder shell is $NOLOGIN_SHELL, want /usr/sbin/nologin"
BUILDER_HOME_FIELD="$(awk -F: -v u="$BUILDER_USER" '$1 == u {print $6}' /etc/passwd)"
[ "$BUILDER_HOME_FIELD" = "$MGR_STATE" ] || fail "builder home is $BUILDER_HOME_FIELD, want $MGR_STATE"
id -nG "$BUILDER_USER" | tr ' ' '\n' | grep -qx "$BUILDER_USER" || fail "builder group missing"
say "identity ok: uid=$BUILDER_UID gid=$BUILDER_GID home=$BUILDER_HOME_FIELD shell=$NOLOGIN_SHELL"

PROVISION_OUT2="$(sh "$PROVISION_SCRIPT" 2>&1)" || fail "idempotent re-run failed: $PROVISION_OUT2"
AFTER2_SUBUID="$(grep "^$BUILDER_USER:" /etc/subuid || true)"
AFTER2_SUBGID="$(grep "^$BUILDER_USER:" /etc/subgid || true)"
[ "$AFTER2_SUBUID" = "$AFTER_SUBUID" ] || fail "re-run changed /etc/subuid (not a no-op)"
[ "$AFTER2_SUBGID" = "$AFTER_SUBGID" ] || fail "re-run changed /etc/subgid (not a no-op)"
evidence provisioning-rerun.txt "$PROVISION_OUT2"
say "provisioning idempotent re-run is a no-op (PASS)"

# ---------------------------------------------------------------------------
# 2. unit install + start; manager identity evidence
# ---------------------------------------------------------------------------
say "=== 2. unit install and start ==="
install -m 0644 "$UNIT_FILE" "/etc/systemd/system/$UNIT"
systemctl daemon-reload
systemctl start "$UNIT"
systemctl is-active "$UNIT" >/dev/null || { systemctl status "$UNIT" --no-pager -l || true; fail "unit failed to start"; }

MGR_PID="$(systemctl show -p MainPID --value "$UNIT")"
if [ -z "$MGR_PID" ] || [ "$MGR_PID" = "0" ]; then
  fail "unit has no MainPID"
fi
for _ in $(seq 1 40); do
  [ -S "$MGR_SOCK" ] && break
  sleep 0.5
done
[ -S "$MGR_SOCK" ] || { systemctl status "$UNIT" --no-pager -l || true; fail "manager socket never appeared"; }
say "manager up: pid=$MGR_PID"

# ownership/mode of the systemd-managed roots
evidence roots.txt "$(ls -ld "$MGR_RUNTIME" "$MGR_STATE"
ls -la "$MGR_SOCK"
stat -c '%U:%G %a %n' "$MGR_RUNTIME" "$MGR_STATE")"
[ "$(stat -c '%U' "$MGR_RUNTIME")" = "$BUILDER_USER" ] || fail "runtime root not owned by $BUILDER_USER"
[ "$(stat -c '%G' "$MGR_RUNTIME")" = "$BUILDER_USER" ] || fail "runtime root not owned by group $BUILDER_USER"
[ "$(stat -c '%a' "$MGR_RUNTIME")" = "750" ] || fail "runtime root mode is $(stat -c '%a' "$MGR_RUNTIME"), want 750"
[ "$(stat -c '%U' "$MGR_STATE")" = "$BUILDER_USER" ] || fail "state root not owned by $BUILDER_USER"
[ "$(stat -c '%a' "$MGR_STATE")" = "750" ] || fail "state root mode is $(stat -c '%a' "$MGR_STATE"), want 750"

# the recorded NNP exception + the minimal capability floor
MGR_NNP="$(proc_field "$MGR_PID" NoNewPrivs)"
[ "$MGR_NNP" = "0" ] || fail "manager NoNewPrivs=$MGR_NNP, want 0 (the recorded NNP exception)"
MGR_CAPBND="$(proc_field "$MGR_PID" CapBnd)"
[ "$MGR_CAPBND" = "00000000000000c0" ] || fail "manager CapBnd=$MGR_CAPBND, want 00000000000000c0 (CAP_SETUID|CAP_SETGID exactly)"
MGR_CAPEFF="$(proc_field "$MGR_PID" CapEff)"
[ "$MGR_CAPEFF" = "0000000000000000" ] || fail "manager CapEff=$MGR_CAPEFF, want 0"
say "manager NoNewPrivs=0 (recorded exception) and CapBnd=CAP_SETUID|CAP_SETGID exactly (PASS)"

# The manager's own environment is systemd-provided (User= services get
# HOME/USER/LOGNAME from the account); recorded against M0/M1, which ran
# the manager from a shell with HOME=/home/<user> and
# XDG_RUNTIME_DIR=/run/user/<uid>. The CHILD environment below is the
# manager's explicit contract, not this one.
MGR_ENVIRON="$(proc_environ "$MGR_PID")"
evidence manager-env.txt "manager pid $MGR_PID environ:
$MGR_ENVIRON
systemd unit properties:
$(systemctl show "$UNIT" -p User,Group,RuntimeDirectory,StateDirectory,ExecMainStartTimestamp,NRestarts,ExecMainPID,ControlGroup --no-pager)"

# ---------------------------------------------------------------------------
# 3. manager protocol smoke + socket isolation
# ---------------------------------------------------------------------------
say "=== 3. manager protocol smoke ==="
RESP_PURGE="$(mgr_call "PURGE")"
evidence manager-smoke.txt "PURGE -> $RESP_PURGE"
[ "$RESP_PURGE" = "OK" ] || fail "root PURGE failed: $RESP_PURGE"

if setpriv --reuid 65534 --regid 65534 --clear-groups \
  python3 -c 'import socket,sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
sys.exit(0)' "$MGR_SOCK" >/dev/null 2>&1; then
  fail "nobody CAN connect to the manager socket"
fi
say "nobody -> manager socket DENIED (PASS)"

# ---------------------------------------------------------------------------
# 4. real build under the real unit: cgroup/uid_map/env evidence
# ---------------------------------------------------------------------------
say "=== 4. real build; per-process cgroup/env/uid_map evidence ==="
OP_MAIN="$(new_op_id)"
RESP_START="$(mgr_call "START $OP_MAIN")"
evidence start-main.txt "START $OP_MAIN -> $RESP_START"
[ "$RESP_START" = "OK" ] || fail "START failed: $RESP_START"

OP_SOCK="$MGR_RUNTIME/ops/$OP_MAIN/buildkitd.sock"
for _ in $(seq 1 20); do
  [ -S "$OP_SOCK" ] && break
  sleep 0.5
done
[ -S "$OP_SOCK" ] || fail "per-op buildkit socket never appeared at the derived path"
SOCK_UID="$(stat -c '%u' "$OP_SOCK")"
SOCK_MODE="$(stat -c '%a' "$OP_SOCK")"
[ "$SOCK_UID" = "$BUILDER_UID" ] || fail "per-op socket uid $SOCK_UID != builder uid $BUILDER_UID"
[ "$SOCK_MODE" = "600" ] || fail "per-op socket mode $SOCK_MODE, want 600"
say "per-op socket present, builder-owned, private (PASS)"

# locate the instance process tree by the op-scoped argv anchors
RK_PID="$(pgrep -f "rootlesskit.*--state-dir=$MGR_STATE/ops/$OP_MAIN/rootlesskit-state" | head -1 || true)"
[ -n "$RK_PID" ] || fail "rootlesskit leader pid not found"
BK_PID="$(pgrep -f "buildkitd --rootless --root=$MGR_STATE/ops/$OP_MAIN/root" | head -1 || true)"
[ -n "$BK_PID" ] || fail "buildkitd pid not found"
SL_PID="$(pgrep -x slirp4netns | head -1 || true)"
[ -n "$SL_PID" ] || fail "slirp4netns pid not found (unanchored descendant)"
say "instance tree: rootlesskit=$RK_PID buildkitd=$BK_PID slirp4netns=$SL_PID (slirp4netns is the unanchored member)"

# negative self-test: every process must EXIST before the membership proof
for pid in "$MGR_PID" "$RK_PID" "$BK_PID" "$SL_PID"; do
  [ -d "/proc/$pid" ] || fail "pre-existence self-test: process $pid missing"
done

CG_ALL="$(
  for pid in "$MGR_PID" "$RK_PID" "$BK_PID" "$SL_PID"; do
    printf 'pid %s: %s\n' "$pid" "$(proc_cgroup "$pid")"
  done
)"
evidence cgroups.txt "$CG_ALL"
for pid in "$MGR_PID" "$RK_PID" "$BK_PID" "$SL_PID"; do
  CG="$(proc_cgroup "$pid")"
  [ "$CG" = "0:$UNIT_CGROUP" ] || fail "process $pid cgroup is '$CG', want 0:$UNIT_CGROUP (unit membership)"
done
say "manager + rootlesskit + buildkitd + slirp4netns all in the unit cgroup (PASS)"

# uid_map: the leader stays outside the userns; the buildkitd child carries
# the mapping (in-ns 0 = builder uid; in-ns 1.. = the provisioned
# subordinate range)
evidence uid-maps.txt "rootlesskit $RK_PID:
$(cat "/proc/$RK_PID/uid_map" 2>/dev/null || true)
buildkitd $BK_PID:
$(cat "/proc/$BK_PID/uid_map" 2>/dev/null || true)
buildkitd gid_map:
$(cat "/proc/$BK_PID/gid_map" 2>/dev/null || true)"
BK_MAP0="$(awk '$1 == 0 {print $2}' "/proc/$BK_PID/uid_map" | head -1)"
BK_SUBUID_START="$(awk '$1 == 1 {print $2}' "/proc/$BK_PID/uid_map" | head -1)"
[ -n "$BK_MAP0" ] || fail "cannot read the buildkitd uid_map"
[ "$BK_MAP0" != "0" ] || fail "in-ns uid 0 maps to host uid 0 (no sandbox-root boundary)"
[ "$BK_MAP0" = "$BUILDER_UID" ] || fail "in-ns uid 0 maps to host uid $BK_MAP0, want the builder uid $BUILDER_UID"
[ "$BK_SUBUID_START" = "$SUBUID_START" ] || fail "subordinate mapping starts at $BK_SUBUID_START, want the provisioned $SUBUID_START"
say "uid_map: in-ns root -> builder uid $BK_MAP0; subordinate range starts at $BK_SUBUID_START (PASS)"

# child environment: the exact production contract (differs from M0/M1,
# which set USER= and a shared XDG_RUNTIME_DIR)
ENV_RK="$(proc_environ "$RK_PID")"
ENV_BK="$(proc_environ "$BK_PID")"
evidence child-env.txt "rootlesskit $RK_PID environ:
$ENV_RK
buildkitd $BK_PID environ:
$ENV_BK"
env_check() {
  local env_data="$1" key="$2" want="$3"
  local got
  got="$(printf '%s\n' "$env_data" | grep -F "$key=" | head -1)"
  [ "$got" = "$key=$want" ] || fail "child env $got, want $key=$want"
}
env_check "$ENV_BK" HOME "$MGR_STATE"
env_check "$ENV_BK" XDG_RUNTIME_DIR "$MGR_RUNTIME/ops/$OP_MAIN"
env_check "$ENV_BK" PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/usr/libexec/docker-helper/buildkit"
if printf '%s\n' "$ENV_BK" | grep -q "^USER="; then
  fail "child env carries USER= (M0/M1 leftover; the production child env is the explicit contract)"
fi
SSL_CERT_FILE_VAL="$(printf '%s\n' "$ENV_BK" | grep -F "SSL_CERT_FILE=" | head -1 | cut -d= -f2- || true)"
[ -n "$SSL_CERT_FILE_VAL" ] || fail "child env has no SSL_CERT_FILE"
say "child env = production contract (HOME=state root, per-op XDG_RUNTIME_DIR, fixed PATH, no USER) (PASS)"

# real build: outbound TLS pull + export tar (the CA bundle is exercised)
CTX="$P4A1_WORK/ctx-main"
mkdir -p "$CTX"
cat > "$CTX/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN mkdir -p /m1 && echo p4a1-main > /m1/marker.txt && cat /proc/self/uid_map > /m1/uid_map.txt && id > /m1/id.txt && ls -la /var/run/docker.sock /run/docker.sock > /m1/socks.txt 2>&1 || true
EOF
SESSION_DOCKER_CONFIG="$P4A1_WORK/docker-config"
mkdir -p "$SESSION_DOCKER_CONFIG"
echo '{}' > "$SESSION_DOCKER_CONFIG/config.json"

BUILD_LOG="$P4A1_WORK/build-main.log"
if ! DOCKER_CONFIG="$SESSION_DOCKER_CONFIG" buildctl --addr "unix://$OP_SOCK" build \
    --progress=plain --frontend=dockerfile.v0 \
    --local "context=$CTX" --local "dockerfile=$CTX" \
    --output "type=docker,name=p4a1-proof:main,dest=$P4A1_WORK/out-main.tar" \
    > "$BUILD_LOG" 2>&1; then
  tail -30 "$BUILD_LOG" || true
  fail "real build under the unit failed"
fi
[ -s "$P4A1_WORK/out-main.tar" ] || fail "build produced no export tar"
say "real HTTPS build through the real manager under the unit: PASS"

# SSL_CERT_FILE must resolve INSIDE the child's mount namespace (the
# openSUSE symlink-under-copy-up case; see the CA section below)
CA_TARGET_PROOF="$(readlink -f "$SSL_CERT_FILE_VAL" 2>/dev/null || echo "$SSL_CERT_FILE_VAL")"
CA_CHILD_SHA="$(sha256sum < "/proc/$BK_PID/root$SSL_CERT_FILE_VAL" 2>/dev/null | awk '{print $1}' || true)"
CA_HOST_SHA="$(sha256sum < "$CA_TARGET_PROOF" 2>/dev/null | awk '{print $1}' || true)"
evidence ca-check.txt "SSL_CERT_FILE (child env):   $SSL_CERT_FILE_VAL
host realpath:              $CA_TARGET_PROOF
sha256 through child ns:    $CA_CHILD_SHA
sha256 host file:           $CA_HOST_SHA
readlink inside child ns:   $(readlink "/proc/$BK_PID/root$SSL_CERT_FILE_VAL" 2>/dev/null || echo '<not a symlink>')"
[ -n "$CA_CHILD_SHA" ] || fail "SSL_CERT_FILE is unreadable INSIDE the child mount namespace (rootlesskit copy-up broke it)"
[ "$CA_CHILD_SHA" = "$CA_HOST_SHA" ] || fail "the CA the child sees differs from the host bundle"
say "resolved SSL_CERT_FILE readable inside the child --copy-up=/etc namespace, content identical (PASS)"

# docker-backed round trip + sandbox negatives (when the Engine is present)
if [ "$DOCKER_AVAILABLE" = 1 ]; then
  docker load -i "$P4A1_WORK/out-main.tar" >/dev/null
  UID_MAP_IN_BUILD="$(docker run --rm p4a1-proof:main cat /m1/uid_map.txt 2>/dev/null | head -1 || true)"
  BUILD_HOST_UID="$(awk '{print $2}' <<<"$UID_MAP_IN_BUILD")"
  SOCKS_OBS="$(docker run --rm p4a1-proof:main cat /m1/socks.txt 2>/dev/null || true)"
  echo "P4A1-HOST-ROOT-MARKER-SECRET" > "$P4A1_WORK/root-marker"
  chmod 600 "$P4A1_WORK/root-marker"
  CTX_MARKER="$P4A1_WORK/ctx-marker"
  mkdir -p "$CTX_MARKER"
  cat > "$CTX_MARKER/Dockerfile" <<EOF
FROM alpine:3.20
RUN mkdir -p /m1
RUN cat $P4A1_WORK/root-marker > /m1/leak.txt 2>&1; echo rc=\$? >> /m1/leak.txt
EOF
  if ! DOCKER_CONFIG="$SESSION_DOCKER_CONFIG" buildctl --addr "unix://$OP_SOCK" build \
      --progress=plain --frontend=dockerfile.v0 \
      --local "context=$CTX_MARKER" --local "dockerfile=$CTX_MARKER" \
      --output "type=docker,name=p4a1-proof:marker,dest=$P4A1_WORK/out-marker.tar" \
      > "$P4A1_WORK/build-marker.log" 2>&1; then
    tail -20 "$P4A1_WORK/build-marker.log" || true
    fail "marker build failed"
  fi
  docker load -i "$P4A1_WORK/out-marker.tar" >/dev/null
  MARKER_OUT="$(docker run --rm p4a1-proof:marker cat /m1/leak.txt 2>/dev/null || true)"
  evidence docker-roundtrip.txt "export tar -> docker load -> docker run: OK
in-build uid_map line 1: $UID_MAP_IN_BUILD
in-build host-side uid:  $BUILD_HOST_UID
docker.sock visibility:  $SOCKS_OBS
host-root marker probe:  $MARKER_OUT"
  if [ -z "$BUILD_HOST_UID" ] || [ "$BUILD_HOST_UID" = "0" ]; then
    fail "in-build uid 0 maps to host uid 0"
  fi
  if printf '%s\n' "$SOCKS_OBS" | grep -v "No such file" | grep -q "docker.sock"; then
    fail "build RUN saw a docker socket"
  fi
  if printf '%s\n' "$MARKER_OUT" | grep -q "P4A1-HOST-ROOT-MARKER-SECRET"; then
    fail "host-root marker LEAKED into build RUN (the NNP exception must not weaken the sandbox)"
  fi
  say "round trip + sandbox negatives (uid_map nonzero, no docker.sock, no host-root leak) (PASS)"
fi

# ---------------------------------------------------------------------------
# 5. STOP teardown with pre-existence proofs
# ---------------------------------------------------------------------------
say "=== 5. per-op STOP ==="
for pid in "$RK_PID" "$BK_PID" "$SL_PID"; do
  [ -d "/proc/$pid" ] || fail "pre-existence self-test before STOP: process $pid missing"
done
[ -d "$MGR_STATE/ops/$OP_MAIN" ] || fail "pre-existence self-test: state dir missing"
RESP_STOP="$(mgr_call "STOP $OP_MAIN")"
evidence stop-main.txt "STOP $OP_MAIN -> $RESP_STOP"
[ "$RESP_STOP" = "OK" ] || fail "STOP failed: $RESP_STOP"
sleep 1
for pid in "$RK_PID" "$BK_PID" "$SL_PID"; do
  [ -d "/proc/$pid" ] && fail "process $pid survived per-op STOP"
done
[ ! -e "$MGR_STATE/ops/$OP_MAIN" ] || fail "state dir survived per-op STOP"
[ ! -e "$MGR_RUNTIME/ops/$OP_MAIN" ] || fail "runtime dir survived per-op STOP"
[ ! -S "$OP_SOCK" ] || fail "per-op socket survived per-op STOP"
if pgrep -f "rootlesskit.*--state-dir=$MGR_STATE/ops/" >/dev/null 2>&1; then
  fail "a rootlesskit process survived the per-op STOP"
fi
if pgrep -x slirp4netns >/dev/null 2>&1; then
  fail "a slirp4netns process survived the per-op STOP"
fi
say "per-op STOP: processes, dirs, socket gone (PASS)"

# ---------------------------------------------------------------------------
# 6. startup invariant: ambiguous pid-file-less residue is cleaned by the
#    next generation; noncanonical entries are preserved
# ---------------------------------------------------------------------------
say "=== 6. startup invariant over ambiguous residue ==="
systemctl stop "$UNIT"
# After the stop, systemd has removed the runtime directory; recreate the
# residue exactly as the MANAGER would own it (as the builder identity):
# state residue without a pid file (the pre-pid-write crash window and the
# systemd-wiped runtime tree state) and one truncated pid file.
AMBIG_OP="op_11111111111111111111111111111111"
TRUNC_OP="op_22222222222222222222222222222222"
# The stop wiped the systemd RuntimeDirectory (the whole /run root);
# recreate the root itself as root (setpriv cannot mkdir under /run), then
# the residue entries as the builder identity exactly as the manager would
# own them.
install -d -o "$BUILDER_UID" -g "$BUILDER_GID" -m 0750 "$MGR_RUNTIME"
setpriv --reuid "$BUILDER_UID" --regid "$BUILDER_GID" --clear-groups \
  sh -c "mkdir -p '$MGR_STATE/ops/$AMBIG_OP/root' '$MGR_STATE/ops/$AMBIG_OP/rootlesskit-state' '$MGR_RUNTIME/ops/$AMBIG_OP' '$MGR_STATE/ops/$TRUNC_OP/root' '$MGR_RUNTIME/ops/$TRUNC_OP' '$MGR_RUNTIME/ops/not-canonical' '$MGR_STATE/ops/not-canonical'"
# truncated = NO trailing newline (crash mid-write); the value is a live
# pid to make the pre-invariant danger concrete: the pre-F5.1 parser would
# have accepted the decimal prefix as that pid.
setpriv --reuid "$BUILDER_UID" --regid "$BUILDER_GID" --clear-groups \
  sh -c "printf '%s' '1' > '$MGR_RUNTIME/ops/$TRUNC_OP/instance.pid'"
evidence residue-before.txt "$(find "$MGR_RUNTIME" "$MGR_STATE" -maxdepth 3 2>/dev/null | sort)"

systemctl start "$UNIT"
systemctl is-active "$UNIT" >/dev/null || { systemctl status "$UNIT" --no-pager -l || true; fail "unit failed to start over ambiguous residue (startup invariant missing?)"; }
for _ in $(seq 1 40); do
  [ -S "$MGR_SOCK" ] && break
  sleep 0.5
done
[ -S "$MGR_SOCK" ] || fail "manager socket never appeared over ambiguous residue"
[ ! -e "$MGR_STATE/ops/$AMBIG_OP" ] || fail "ambiguous state residue survived startup purge"
[ ! -e "$MGR_RUNTIME/ops/$AMBIG_OP" ] || fail "ambiguous runtime residue survived startup purge"
[ ! -e "$MGR_STATE/ops/$TRUNC_OP" ] || fail "truncated-pid residue survived startup purge"
[ ! -e "$MGR_RUNTIME/ops/$TRUNC_OP" ] || fail "truncated-pid runtime residue survived startup purge"
[ -e "$MGR_RUNTIME/ops/not-canonical" ] || fail "noncanonical runtime entry was removed (must be preserved)"
[ -e "$MGR_STATE/ops/not-canonical" ] || fail "noncanonical state entry was removed (must be preserved)"
evidence residue-after.txt "$(find "$MGR_RUNTIME" "$MGR_STATE" -maxdepth 3 2>/dev/null | sort)"
RESP_PURGE2="$(mgr_call "PURGE")"
[ "$RESP_PURGE2" = "OK" ] || fail "PURGE after invariant start failed: $RESP_PURGE2"
say "ambiguous pid-file-less residue cleaned at start; noncanonical entries preserved (PASS)"

# ---------------------------------------------------------------------------
# 7. kill the manager during an active build: systemd restart settles ALL
#    old children (including unanchored descendants)
# ---------------------------------------------------------------------------
say "=== 7. manager kill during an active build ==="
OP_KILL="$(new_op_id)"
RESP_START_K="$(mgr_call "START $OP_KILL")"
[ "$RESP_START_K" = "OK" ] || fail "START (kill test) failed: $RESP_START_K"
KILL_SOCK="$MGR_RUNTIME/ops/$OP_KILL/buildkitd.sock"
for _ in $(seq 1 20); do [ -S "$KILL_SOCK" ] && break; sleep 0.5; done
[ -S "$KILL_SOCK" ] || fail "per-op socket (kill test) missing"

CTX_KILL="$P4A1_WORK/ctx-kill"
mkdir -p "$CTX_KILL"
cat > "$CTX_KILL/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN mkdir -p /m1 && sleep 3 && echo step1 > /m1/s1
RUN sleep 3 && echo step2 > /m1/s2
RUN sleep 3 && echo step3 > /m1/s3
RUN sleep 3 && echo step4 > /m1/s4
EOF
( DOCKER_CONFIG="$SESSION_DOCKER_CONFIG" buildctl --addr "unix://$KILL_SOCK" build \
    --progress=plain --frontend=dockerfile.v0 \
    --local "context=$CTX_KILL" --local "dockerfile=$CTX_KILL" \
    --output "type=docker,name=p4a1-proof:kill,dest=$P4A1_WORK/out-kill.tar" \
    > "$P4A1_WORK/build-kill.log" 2>&1 ) &
BUILDCTL_PID=$!

# pre-existence of the full tree before the kill (negative self-tests)
OLD_MGR="$MGR_PID"
OLD_RK="$(pgrep -f "rootlesskit.*--state-dir=$MGR_STATE/ops/$OP_KILL/rootlesskit-state" | head -1 || true)"
OLD_BK="$(pgrep -f "buildkitd --rootless --root=$MGR_STATE/ops/$OP_KILL/root" | head -1 || true)"
OLD_SL="$(pgrep -x slirp4netns | head -1 || true)"
for pid in "$OLD_MGR" "$OLD_RK" "$OLD_BK" "$OLD_SL"; do
  if [ -z "$pid" ] || [ ! -d "/proc/$pid" ]; then
    fail "kill-test pre-existence: process $pid missing"
  fi
done
evidence kill-before.txt "manager=$OLD_MGR rootlesskit=$OLD_RK buildkitd=$OLD_BK slirp4netns=$OLD_SL
buildctl=$BUILDCTL_PID (active build)
cgroups:
$(for pid in "$OLD_MGR" "$OLD_RK" "$OLD_BK" "$OLD_SL"; do printf 'pid %s: %s\n' "$pid" "$(proc_cgroup "$pid")"; done)"

kill -9 "$OLD_MGR"

# systemd must restart the unit (Restart=on-failure) into a fresh manager
RESTARTED=0
for _ in $(seq 1 120); do
  NEW_MGR="$(systemctl show -p MainPID --value "$UNIT")"
  if [ -n "$NEW_MGR" ] && [ "$NEW_MGR" != "$OLD_MGR" ] && [ -S "$MGR_SOCK" ]; then
    RESTARTED=1
    break
  fi
  sleep 1
done
[ "$RESTARTED" = 1 ] || { systemctl status "$UNIT" --no-pager -l || true; fail "unit did not restart after the manager kill"; }
wait "$BUILDCTL_PID" 2>/dev/null || true
systemctl is-active "$UNIT" >/dev/null || fail "unit not active after restart"

# ALL old children settled — including the unanchored slirp4netns that the
# manager's own cmdline-anchor cleanup could never see. The unit cgroup is
# what settled them.
for name_pid in manager:$OLD_MGR rootlesskit:$OLD_RK buildkitd:$OLD_BK slirp4netns:$OLD_SL; do
  name="${name_pid%%:*}"; pid="${name_pid##*:}"
  [ -d "/proc/$pid" ] && fail "$name process $pid SURVIVED the systemd restart"
done
if pgrep -f "rootlesskit.*--state-dir=$MGR_STATE/ops/" >/dev/null 2>&1; then
  fail "an old rootlesskit process survived the systemd restart"
fi
if pgrep -f "buildkitd --rootless --root=$MGR_STATE/ops/" >/dev/null 2>&1; then
  fail "an old buildkitd process survived the systemd restart"
fi
if pgrep -x slirp4netns >/dev/null 2>&1; then
  fail "an unanchored slirp4netns descendant survived the systemd restart"
fi
LEFTOVER_BUILDER_PIDS="$(pgrep -u "$BUILDER_UID" | grep -vx "$NEW_MGR" || true)"
[ -z "$LEFTOVER_BUILDER_PIDS" ] || fail "builder-uid processes beyond the new manager survived: $LEFTOVER_BUILDER_PIDS"
say "systemd restart settled manager + rootlesskit + buildkitd + unanchored slirp4netns (PASS)"

# the new generation's startup purge cleaned the residue the wiped runtime
# tree left behind (state dir present, pid file gone with the runtime tree)
[ ! -e "$MGR_STATE/ops/$OP_KILL" ] || fail "kill-test state residue survived the restart purge"
[ ! -e "$MGR_RUNTIME/ops/$OP_KILL" ] || fail "kill-test runtime residue survived the restart purge"
# the noncanonical STATE entry must survive every purge (product-foreign)
[ -e "$MGR_STATE/ops/not-canonical" ] || fail "noncanonical state entry removed by the restart purge"
evidence kill-after.txt "restart: old=$OLD_MGR new=$NEW_MGR
NRestarts: $(systemctl show -p NRestarts --value "$UNIT")
kill-test residue removed; noncanonical state entry preserved
post-restart trees:
$(find "$MGR_RUNTIME" "$MGR_STATE" -maxdepth 3 2>/dev/null | sort)"

# a fresh build works on the new generation
OP_FRESH="$(new_op_id)"
RESP_START_F="$(mgr_call "START $OP_FRESH")"
[ "$RESP_START_F" = "OK" ] || fail "post-restart START failed: $RESP_START_F"
FRESH_SOCK="$MGR_RUNTIME/ops/$OP_FRESH/buildkitd.sock"
for _ in $(seq 1 20); do [ -S "$FRESH_SOCK" ] && break; sleep 0.5; done
[ -S "$FRESH_SOCK" ] || fail "post-restart per-op socket missing"
CTX_FRESH="$P4A1_WORK/ctx-fresh"
mkdir -p "$CTX_FRESH"
cat > "$CTX_FRESH/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN mkdir -p /m1 && echo fresh-write > /m1/marker.txt
EOF
if ! DOCKER_CONFIG="$SESSION_DOCKER_CONFIG" buildctl --addr "unix://$FRESH_SOCK" build \
    --progress=plain --frontend=dockerfile.v0 \
    --local "context=$CTX_FRESH" --local "dockerfile=$CTX_FRESH" \
    --output "type=docker,name=p4a1-proof:fresh,dest=$P4A1_WORK/out-fresh.tar" \
    > "$P4A1_WORK/build-fresh.log" 2>&1; then
  tail -20 "$P4A1_WORK/build-fresh.log" || true
  fail "post-restart build failed"
fi
if [ "$DOCKER_AVAILABLE" = 1 ]; then
  docker load -i "$P4A1_WORK/out-fresh.tar" >/dev/null
  F_OBS="$(docker run --rm p4a1-proof:fresh cat /m1/marker.txt 2>/dev/null || true)"
  [ "$F_OBS" = "fresh-write" ] || fail "post-restart build did not round trip: $F_OBS"
fi
say "post-restart fresh build works (PASS)"

# ---------------------------------------------------------------------------
# 8. service stop during an active build
# ---------------------------------------------------------------------------
say "=== 8. service stop during an active build ==="
OP_STOPTEST="$(new_op_id)"
RESP_START_S="$(mgr_call "START $OP_STOPTEST")"
[ "$RESP_START_S" = "OK" ] || fail "START (stop test) failed: $RESP_START_S"
STOP_SOCK="$MGR_RUNTIME/ops/$OP_STOPTEST/buildkitd.sock"
for _ in $(seq 1 20); do [ -S "$STOP_SOCK" ] && break; sleep 0.5; done
[ -S "$STOP_SOCK" ] || fail "per-op socket (stop test) missing"
( DOCKER_CONFIG="$SESSION_DOCKER_CONFIG" buildctl --addr "unix://$STOP_SOCK" build \
    --progress=plain --frontend=dockerfile.v0 \
    --local "context=$CTX_KILL" --local "dockerfile=$CTX_KILL" \
    --output "type=docker,name=p4a1-proof:stoptest,dest=$P4A1_WORK/out-stoptest.tar" \
    > "$P4A1_WORK/build-stoptest.log" 2>&1 ) &
STOPTCTL_PID=$!

S_MGR="$(systemctl show -p MainPID --value "$UNIT")"
S_RK="$(pgrep -f "rootlesskit.*--state-dir=$MGR_STATE/ops/$OP_STOPTEST/rootlesskit-state" | head -1 || true)"
S_BK="$(pgrep -f "buildkitd --rootless --root=$MGR_STATE/ops/$OP_STOPTEST/root" | head -1 || true)"
S_SL="$(pgrep -x slirp4netns | head -1 || true)"
for pid in "$S_MGR" "$S_RK" "$S_BK" "$S_SL"; do
  if [ -z "$pid" ] || [ ! -d "/proc/$pid" ]; then
    fail "stop-test pre-existence: process $pid missing"
  fi
done

STOP_T0="$(date +%s)"
systemctl stop "$UNIT"
STOP_T1="$(date +%s)"
STOP_SECS=$((STOP_T1 - STOP_T0))
wait "$STOPTCTL_PID" 2>/dev/null || true
evidence stop-test.txt "service stop took ${STOP_SECS}s (TimeoutStopSec=30s)
buildctl exit: waited"
[ "$STOP_SECS" -lt 35 ] || fail "service stop took ${STOP_SECS}s (bounded by TimeoutStopSec=30s)"
systemctl is-active "$UNIT" >/dev/null 2>&1 && fail "unit still active after stop"
for name_pid in manager:$S_MGR rootlesskit:$S_RK buildkitd:$S_BK slirp4netns:$S_SL; do
  name="${name_pid%%:*}"; pid="${name_pid##*:}"
  [ -d "/proc/$pid" ] && fail "$name process $pid SURVIVED the service stop"
done
# the runtime tree is wiped by the stop (RuntimeDirectory semantics; the
# pid files with it), while the state tree persists
[ ! -e "$MGR_RUNTIME/ops/$OP_STOPTEST" ] || fail "runtime residue survived the service stop (RuntimeDirectory not wiped?)"
say "service stop settled all children in ${STOP_SECS}s; runtime tree wiped (PASS)"

# state residue survives the stop (StateDirectory persists); the next
# start's purge cleans it
[ -e "$MGR_STATE/ops/$OP_STOPTEST" ] || fail "stop-test state residue missing before start (StateDirectory removed?)"
systemctl start "$UNIT"
for _ in $(seq 1 40); do
  [ -S "$MGR_SOCK" ] && break
  sleep 0.5
done
[ -S "$MGR_SOCK" ] || fail "manager socket missing after stop/start cycle"
[ ! -e "$MGR_STATE/ops/$OP_STOPTEST" ] || fail "stop-test state residue survived the start purge"
RESP_PURGE3="$(mgr_call "PURGE")"
[ "$RESP_PURGE3" = "OK" ] || fail "PURGE after stop/start cycle failed: $RESP_PURGE3"
say "stop -> start cycle purged the persistent residue (unit membership is NOT per-op ownership; the manager owns the per-op lifecycle) (PASS)"

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------
say "=== ALL P4-A1 PRODUCTION UNIT-BOUNDARY PROOFS COMPLETE ==="
echo "P4A1-PROOF-RESULT=PASS" > "$EVIDENCE_DIR/RESULT.txt"
echo "P4A1-PROOF-RESULT=PASS"
