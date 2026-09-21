#!/usr/bin/env bash
#
# Release 2.4 M0 feasibility probe: rootless BuildKit composition A.
#
# Composition under test:
#   dedicated unprivileged builder user
#     -> rootlesskit --net=slirp4netns --copy-up=/etc --disable-host-loopback
#     -> rootless buildkitd (oci worker)
#     -> private Unix socket owned by the builder
#     -> buildctl --local-dir (client/local-source context transport)
#     -> --output type=docker -> docker load into rootful Engine
#     -> docker run on the imported image
#
# M0 probe only: no docker-helper integration, no product code changes.
# Runs as root (the probe owns the dedicated builder identity itself).

set -Eeuo pipefail

PREFIX='[release-2.4-m0-buildkit]'
EVIDENCE_DIR="${M0_EVIDENCE_DIR:-/tmp/release-2.4-m0-buildkit-evidence}"
BUILDER_USER="${M0_BUILDER_USER:-dhm0builder}"
BUILDER_UID=""
BUILDER_HOME="/home/$BUILDER_USER"
BUILDER_STATE="$BUILDER_HOME/.local/share/buildkit"
BUILDER_XDG=""
WORK_DIR="$(mktemp -d /tmp/release-2.4-m0-buildkit.XXXXXXXX)"
SOCKET="$WORK_DIR/buildkitd.sock"
BUILDCTL_ADDR="unix://$SOCKET"
HOST_MARKER_PORT="${M0_HOST_MARKER_PORT:-59997}"
KEEP="${M0_KEEP:-}"

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

su_builder() {
  setpriv --reuid "$BUILDER_UID" --regid "$BUILDER_UID" --clear-groups \
    env XDG_RUNTIME_DIR="$BUILDER_XDG" HOME="$BUILDER_HOME" PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    "$@"
}

as_builder() {
  su_builder "$@"
}

cleanup() {
  set +e
  if [ -n "${BUILDKITD_PID:-}" ]; then kill "$BUILDKITD_PID" 2>/dev/null; fi
  if [ -n "${MARKER_PID:-}" ]; then kill "$MARKER_PID" 2>/dev/null; fi
  if [ -z "$KEEP" ] && [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 0. environment identity
# ---------------------------------------------------------------------------
say "=== 0. environment identity ==="
evidence_cmd kernel.txt bash -c 'uname -a
cat /proc/sys/user/max_user_namespaces
cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo no-restrict-sysctl
cat /sys/kernel/security/lsm 2>/dev/null'
evidence_cmd packages.txt bash -c 'dpkg -l | grep -E "uidmap|slirp4netns|fuse|docker|apparmor"'
evidence_cmd binaries.txt bash -c 'which rootlesskit slirp4netns buildkitd buildctl newuidmap newgidmap docker dockerd
buildkitd --version
rootlesskit --version
slirp4netns --version
docker --version'
evidence_cmd dockerinfo.txt bash -c 'docker info 2>&1 | grep -E "Server Version|Storage Driver|Operating System"'

command -v rootlesskit >/dev/null 2>&1 || fail "rootlesskit not installed"
command -v slirp4netns >/dev/null 2>&1 || fail "slirp4netns not installed"
command -v buildkitd >/dev/null 2>&1 || fail "buildkitd not installed"
command -v buildctl >/dev/null 2>&1 || fail "buildctl not installed"
command -v newuidmap >/dev/null 2>&1 || fail "newuidmap not installed"
command -v docker >/dev/null 2>&1 || fail "docker not installed"
docker info >/dev/null 2>&1 || fail "rootful docker engine not reachable"

# ---------------------------------------------------------------------------
# 1. dedicated builder identity + subordinate ranges
# ---------------------------------------------------------------------------
say "=== 1. dedicated builder identity ==="
id "$BUILDER_USER" >/dev/null 2>&1 || fail "builder user $BUILDER_USER missing"
BUILDER_UID="$(id -u "$BUILDER_USER")"
BUILDER_XDG="/run/user/$BUILDER_UID"
SUBUID_LINE="$(grep "^$BUILDER_USER:" /etc/subuid || true)"
SUBGID_LINE="$(grep "^$BUILDER_USER:" /etc/subgid || true)"
[ -n "$SUBUID_LINE" ] || fail "subuid missing for $BUILDER_USER"
[ -n "$SUBGID_LINE" ] || fail "subgid missing for $BUILDER_USER"
SUBUID_RANGE="$(awk -F: "{print \$3}" <<<"$SUBUID_LINE")"
SUBGID_RANGE="$(awk -F: "{print \$3}" <<<"$SUBGID_LINE")"
[ "$SUBUID_RANGE" -ge 65536 ] || fail "subordinate uid range < 65536"
[ "$SUBGID_RANGE" -ge 65536 ] || fail "subordinate gid range < 65536"
evidence subuid.txt "subuid: $SUBUID_LINE
subgid: $SUBGID_LINE
builder uid: $BUILDER_UID"
say "subuid/subgid ok (>=65536)"

# builder-owned runtime/state dirs
mkdir -p "$BUILDER_STATE" "$BUILDER_XDG"
chown -R "$BUILDER_USER:$BUILDER_USER" "$BUILDER_HOME" "$BUILDER_STATE"
chmod 700 "$BUILDER_XDG" "$BUILDER_STATE"

# ---------------------------------------------------------------------------
# 2. host-only loopback marker service (host-root-side proof helper)
# ---------------------------------------------------------------------------
say "=== 2. host-loopback marker service ==="
cat > "$WORK_DIR/marker-listener.py" <<'PY'
import socket, threading, time, sys
port = int(sys.argv[1])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(5)
def serve():
    while True:
        try:
            c, _ = s.accept()
            try:
                data = c.recv(4096)
                if data:
                    print("GOT:", data.split(b"\r\n")[0].decode(errors="replace"), flush=True)
            except Exception:
                pass
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nM0-SECRET-OK")
            c.close()
        except Exception:
            break
threading.Thread(target=serve, daemon=True).start()
print("listening", flush=True)
time.sleep(3600)
PY
python3 "$WORK_DIR/marker-listener.py" "$HOST_MARKER_PORT" > "$WORK_DIR/marker-listener.log" 2>&1 &
MARKER_PID=$!
sleep 1
curl -s "http://127.0.0.1:$HOST_MARKER_PORT/" | grep -q M0-SECRET-OK || fail "host marker service not reachable from host"
say "host marker service on 127.0.0.1:$HOST_MARKER_PORT; only host-side listeners receive host loopback"

# ---------------------------------------------------------------------------
# 3. rootless buildkitd under rootlesskit
# ---------------------------------------------------------------------------
say "=== 3. rootless buildkitd under rootlesskit ==="
BUILDKITD_CONFIG="$WORK_DIR/buildkitd.toml"
cat > "$BUILDKITD_CONFIG" <<EOF
debug = false
[grpc]
  address = ["unix://$SOCKET"]
EOF
# the socket and rootlesskit state live under WORK_DIR; the builder must be
# able to traverse/bind there
chmod 755 "$WORK_DIR"
mkdir -p "$WORK_DIR/rootlesskit-state"
chown -R "$BUILDER_USER:$BUILDER_USER" "$WORK_DIR"

as_builder nohup rootlesskit \
  --net=slirp4netns \
  --copy-up=/etc \
  --disable-host-loopback \
  --state-dir="$WORK_DIR/rootlesskit-state" \
  buildkitd \
  --root="$BUILDER_STATE" \
  --addr="unix://$SOCKET" \
  --config="$BUILDKITD_CONFIG" \
  > "$WORK_DIR/buildkitd.log" 2>&1 &
BUILDKITD_PID=$!

socket_ready=0
for _ in $(seq 1 90); do
  if ! kill -0 "$BUILDKITD_PID" 2>/dev/null; then
    tail -60 "$WORK_DIR/buildkitd.log" || true
    fail "rootless buildkitd exited before its socket appeared"
  fi
  if [ -S "$SOCKET" ]; then socket_ready=1; break; fi
  sleep 1
done
[ "$socket_ready" = 1 ] || fail "rootless buildkitd socket did not appear"
say "rootless buildkitd is up; socket=$SOCKET"
evidence buildkitd.log "$(tail -50 "$WORK_DIR/buildkitd.log")"

# root (docker-helper stand-in) can drive the control socket
buildctl --addr "$BUILDCTL_ADDR" workers >/dev/null 2>&1 || fail "root cannot drive the rootless buildkitd socket"
say "root -> buildkitd control socket connectivity OK"

evidence_cmd workers.json bash -c "buildctl --addr $BUILDCTL_ADDR workers --inner 2>&1 || true"

# ---------------------------------------------------------------------------
# 4. namespace + host-root authority evidence (inside build RUN)
# ---------------------------------------------------------------------------
say "=== 4. namespace + host-root authority evidence ==="
CTX_PROBE="$WORK_DIR/ctx-probe"
OUT_PROBE="$WORK_DIR/out-probe"
mkdir -p "$CTX_PROBE" "$OUT_PROBE"
cat > "$CTX_PROBE/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN id > /m0/id.txt
RUN cat /proc/self/uid_map > /m0/uid_map.txt
RUN cat /proc/self/gid_map > /m0/gid_map.txt
RUN grep Cap /proc/self/status > /m0/caps.txt
RUN readlink /proc/self/ns/user > /m0/ns_user.txt
RUN readlink /proc/self/ns/mnt > /m0/ns_mnt.txt
RUN readlink /proc/self/ns/pid > /m0/ns_pid.txt
RUN hostname > /m0/hostname.txt
RUN ls /run/buildkit /var/run/docker.sock /run/docker.sock > /m0/socks.txt 2>&1 || true
RUN ls /proc/1/root/ > /m0/proc1root.txt 2>&1 || true
RUN ls /dev > /m0/dev.txt
EOF
buildctl --addr "$BUILDCTL_ADDR" build \
  --frontend dockerfile.v0 \
  --local "context=$CTX_PROBE" \
  --local "dockerfile=$CTX_PROBE" \
  --output "type=oci,tar=false,dest=$OUT_PROBE" >/dev/null 2>&1 || fail "namespace probe build failed"
PROBE_TAR="$(find "$OUT_PROBE" -type f | head -1)"
docker import "$PROBE_TAR" m0-probe:ns >/dev/null || fail "docker import of probe image failed"

probe_run() {
  docker run --rm m0-probe:ns sh -c "$1" 2>&1 || true
}
NS_OUT="$({
  echo "id:        $(probe_run 'cat /m0/id.txt' | head -1)"
  echo "uid_map:   $(probe_run 'cat /m0/uid_map.txt' | tr -s ' \n' ' ')"
  echo "gid_map:   $(probe_run 'cat /m0/gid_map.txt' | tr -s ' \n' ' ')"
  echo "caps:      $(probe_run 'grep CapEff /m0/caps.txt')"
  echo "ns_user:   $(probe_run 'cat /m0/ns_user.txt')"
  echo "ns_mnt:    $(probe_run 'cat /m0/ns_mnt.txt')"
  echo "ns_pid:    $(probe_run 'cat /m0/ns_pid.txt')"
  echo "hostname:  $(probe_run 'cat /m0/hostname.txt')"
  echo "socks:     $(probe_run 'cat /m0/socks.txt' | tr -s ' \n' ' ')"
  echo "proc1root: $(probe_run 'cat /m0/proc1root.txt' | head -3 | tr -s ' \n' ' ')"
  echo "dev:       $(probe_run 'cat /m0/dev.txt' | tr -s ' \n' ' ')"
})"
evidence ns-evidence.txt "$NS_OUT"
printf '%s\n' "$NS_OUT"

BUILD_HOST_UID="$(printf '%s\n' "$NS_OUT" | sed -n 's/^uid_map:.*[[:space:]]0[[:space:]]\+\([0-9]\+\)[[:space:]]\+[0-9]\+$/\1/p' | head -1)"
[ -n "$BUILD_HOST_UID" ] || fail "cannot determine build RUN host-side uid from uid_map"
case "$BUILD_HOST_UID" in
  0) fail "build RUN maps to host uid 0 — no sandbox-root boundary" ;;
  *) say "build RUN host-side uid=$BUILD_HOST_UID (nonzero => sandbox-root is not host-root) (PASS)" ;;
esac

# ---------------------------------------------------------------------------
# 5. host-root marker file negative proof
# ---------------------------------------------------------------------------
say "=== 5. host-root marker negative proof ==="
echo "M0-ROOT-MARKER-SECRET" > "$WORK_DIR/m0-root-marker"
chmod 600 "$WORK_DIR/m0-root-marker"
CTX_MARKER="$WORK_DIR/ctx-marker"
OUT_MARKER="$WORK_DIR/out-marker"
mkdir -p "$CTX_MARKER" "$OUT_MARKER"
cat > "$CTX_MARKER/Dockerfile" <<EOF
FROM alpine:3.20
RUN cat $WORK_DIR/m0-root-marker > /m0/leak.txt 2>&1; echo rc=\$? >> /m0/leak.txt
RUN cat /proc/self/mountinfo > /m0/mountinfo.txt
EOF
buildctl --addr "$BUILDCTL_ADDR" build \
  --frontend dockerfile.v0 \
  --local "context=$CTX_MARKER" \
  --local "dockerfile=$CTX_MARKER" \
  --output "type=oci,tar=false,dest=$OUT_MARKER" >/dev/null 2>&1 || fail "marker probe build failed"
docker import "$(find "$OUT_MARKER" -type f | head -1)" m0-probe:marker >/dev/null
MARKER_OUT="$(docker run --rm m0-probe:marker sh -c 'cat /m0/leak.txt')"
evidence root-marker.txt "$MARKER_OUT"
if printf '%s\n' "$MARKER_OUT" | grep -q "M0-ROOT-MARKER-SECRET"; then
  fail "host root marker LEAKED into build RUN"
fi
say "host-root marker NOT readable from build RUN (PASS)"
MOUNT_OUT="$(docker run --rm m0-probe:marker sh -c 'cat /m0/mountinfo.txt' || true)"
evidence mountinfo.txt "$MOUNT_OUT"

# ---------------------------------------------------------------------------
# 6. host-loopback negative proof
# ---------------------------------------------------------------------------
say "=== 6. host-loopback negative proof ==="
CTX_LOOP="$WORK_DIR/ctx-loop"
OUT_LOOP="$WORK_DIR/out-loop"
mkdir -p "$CTX_LOOP" "$OUT_LOOP"
cat > "$CTX_LOOP/Dockerfile" <<EOF
FROM alpine:3.20
RUN wget -q -T3 -O- http://127.0.0.1:$HOST_MARKER_PORT/ > /m0/net.txt 2>&1; echo rc=\$? >> /m0/net.txt
EOF
buildctl --addr "$BUILDCTL_ADDR" build \
  --frontend dockerfile.v0 \
  --local "context=$CTX_LOOP" \
  --local "dockerfile=$CTX_LOOP" \
  --output "type=oci,tar=false,dest=$OUT_LOOP" >/dev/null 2>&1 || fail "loopback probe build failed"
docker import "$(find "$OUT_LOOP" -type f | head -1)" m0-probe:loop >/dev/null
LOOP_OUT="$(docker run --rm m0-probe:loop sh -c 'cat /m0/net.txt')"
evidence loop-result.txt "$LOOP_OUT"
if printf '%s\n' "$LOOP_OUT" | grep -q "M0-SECRET-OK"; then
  fail "host loopback marker REACHED from build RUN"
fi
say "host loopback NOT reachable from build RUN (PASS)"
if grep -q "GOT:" "$WORK_DIR/marker-listener.log"; then
  fail "host marker listener received traffic from the build (loopback leak)"
fi
say "host marker listener received no build traffic (PASS)"

# ---------------------------------------------------------------------------
# 7. outbound positive proof
# ---------------------------------------------------------------------------
say "=== 7. outbound network positive proof ==="
CTX_OUT="$WORK_DIR/ctx-out"
OUT_OUT="$WORK_DIR/out-out"
mkdir -p "$CTX_OUT" "$OUT_OUT"
cat > "$CTX_OUT/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN apk add --no-cache curl > /m0/apk.txt 2>&1; echo apk_rc=$? >> /m0/net2.txt; curl -s -o /dev/null https://dl-cdn.alpinelinux.org/alpine/; echo curl_rc=$? >> /m0/net2.txt
EOF
buildctl --addr "$BUILDCTL_ADDR" build \
  --frontend dockerfile.v0 \
  --local "context=$CTX_OUT" \
  --local "dockerfile=$CTX_OUT" \
  --output "type=oci,tar=false,dest=$OUT_OUT" >/dev/null 2>&1 || fail "outbound probe build failed"
docker import "$(find "$OUT_OUT" -type f | head -1)" m0-probe:out >/dev/null
OUT_RUN="$(docker run --rm m0-probe:out sh -c 'cat /m0/net2.txt')"
evidence out-result.txt "$OUT_RUN"
printf '%s\n' "$OUT_RUN" | grep -q "curl_rc=0" || fail "outbound build traffic FAILED: $OUT_RUN"
say "outbound package-repo traffic works from build RUN (PASS)"

# ---------------------------------------------------------------------------
# 8. privileged entitlement negatives
# ---------------------------------------------------------------------------
say "=== 8. privileged entitlement negatives ==="
deny_probe() {
  local name="$1" dockerfile="$2"
  local ctx="$WORK_DIR/ctx-$name" out="$WORK_DIR/out-$name" err="$WORK_DIR/ent-$name.err"
  mkdir -p "$ctx" "$out"
  printf '%s\n' "$dockerfile" > "$ctx/Dockerfile"
  if buildctl --addr "$BUILDCTL_ADDR" build \
    --frontend dockerfile.v0 \
    --local "context=$ctx" \
    --local "dockerfile=$ctx" \
    --output "type=oci,tar=false,dest=$out" 2> "$err"; then
    fail "$name entitlement ACCEPTED without server --allow (contract violation)"
  fi
  evidence "entitlement-$name.err" "$(cat "$err")"
  say "$name refused without server entitlement (PASS)"
}
deny_probe host 'FROM alpine:3.20
RUN --network=host true'
deny_probe insecure 'FROM alpine:3.20
RUN --security=insecure true'

# ---------------------------------------------------------------------------
# 9. control-socket isolation
# ---------------------------------------------------------------------------
say "=== 9. control-socket isolation ==="
ls -la "$SOCKET" > "$EVIDENCE_DIR/socket-perms.txt"
if setpriv --reuid 65534 --regid 65534 --clear-groups \
  env BUILDKIT_HOST="$BUILDCTL_ADDR" buildctl --addr "$BUILDCTL_ADDR" workers >/dev/null 2>&1; then
  fail "ordinary user CAN connect to the buildkit control socket (contract violation)"
fi
say "ordinary (nobody) connect DENIED (PASS)"
echo "nobody connect denied" > "$EVIDENCE_DIR/socket-nobody-denied.txt"

# agent-side session user cannot connect either (same DAC mechanism)
AGENT_USER="m0agent"
id "$AGENT_USER" >/dev/null 2>&1 || useradd -m "$AGENT_USER" 2>/dev/null || true
if id "$AGENT_USER" >/dev/null 2>&1; then
  if setpriv --reuid "$(id -u "$AGENT_USER")" --regid "$(id -g "$AGENT_USER")" --clear-groups \
    env buildctl --addr "$BUILDCTL_ADDR" workers >/dev/null 2>&1; then
    fail "agent user CAN connect to the buildkit control socket"
  fi
  say "agent user connect DENIED (PASS)"
  echo "agent connect denied" > "$EVIDENCE_DIR/socket-agent-denied.txt"
fi

# ---------------------------------------------------------------------------
# 10. docker export -> load -> run round trip
# ---------------------------------------------------------------------------
say "=== 10. docker export -> load -> run round trip ==="
CTX_HELLO="$WORK_DIR/ctx-hello"
mkdir -p "$CTX_HELLO"
cat > "$CTX_HELLO/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN echo m0-roundtrip > /m0/marker.txt
EOF
buildctl --addr "$BUILDCTL_ADDR" build \
  --frontend dockerfile.v0 \
  --local "context=$CTX_HELLO" \
  --local "dockerfile=$CTX_HELLO" \
  --output "type=docker,dest=$WORK_DIR/m0-hello.tar" >/dev/null 2>&1 \
  || fail "docker-type export failed"
docker load < "$WORK_DIR/m0-hello.tar" >/dev/null || fail "docker load failed"
MARKER="$(docker run --rm m0-hello:latest cat /m0/marker.txt)"
[ "$MARKER" = "m0-roundtrip" ] || fail "round-trip marker mismatch: $MARKER"
say "docker export -> docker load -> run marker OK (PASS)"
echo "docker type=docker export + load + run: PASS" > "$EVIDENCE_DIR/roundtrip.txt"

# ---------------------------------------------------------------------------
# 11. failed build leaves no usable import artifact
# ---------------------------------------------------------------------------
say "=== 11. failed build negative ==="
CTX_FAIL="$WORK_DIR/ctx-fail"
OUT_FAIL="$WORK_DIR/out-fail"
mkdir -p "$CTX_FAIL" "$OUT_FAIL"
cat > "$CTX_FAIL/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN false
EOF
if buildctl --addr "$BUILDCTL_ADDR" build \
  --frontend dockerfile.v0 \
  --local "context=$CTX_FAIL" \
  --local "dockerfile=$CTX_FAIL" \
  --output "type=docker,dest=$WORK_DIR/m0-fail.tar" >/dev/null 2>&1; then
  fail "failed build produced an export tar"
fi
[ ! -f "$WORK_DIR/m0-fail.tar" ] || fail "failed build left a partial tar"
say "failed build produced no export artifact (PASS)"
echo "no partial tar on failure: PASS" > "$EVIDENCE_DIR/no-partial.txt"

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------
say "=== ALL PROOFS COMPLETE — composition A viable on this runner ==="
echo "M0-PROOF-RESULT=PASS" > "$EVIDENCE_DIR/RESULT.txt"
