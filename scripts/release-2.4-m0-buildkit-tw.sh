#!/usr/bin/env bash
#
# Release 2.4 M0 guest-side probe for openSUSE Tumbleweed.
#
# Runs the same composition-A proof inside the Tumbleweed VM:
#   dedicated unprivileged builder user
#     -> distro rootlesskit --net=slirp4netns --copy-up=/etc --disable-host-loopback
#     -> buildkitd (distro buildkit RPM)
#     -> private Unix socket
#     -> buildctl --local-dir -> --output type=docker -> docker load
#
# M0 probe only. Expects: root, Tumbleweed, docker running.

set -Eeuo pipefail

PREFIX='[release-2.4-m0-tw]'
EVIDENCE_DIR="${M0_EVIDENCE_DIR:-/tmp/release-2.4-m0-tw-evidence}"
BUILDER_USER="${M0_BUILDER_USER:-dhm0builder}"
BUILDER_HOME="/home/$BUILDER_USER"
BUILDER_STATE="$BUILDER_HOME/.local/share/buildkit"
WORK_DIR="$(mktemp -d /tmp/release-2.4-m0-tw.XXXXXXXX)"
SOCKET="$WORK_DIR/buildkitd.sock"
BUILDCTL_ADDR="unix://$SOCKET"
HOST_MARKER_PORT="${M0_HOST_MARKER_PORT:-59997}"

say() { printf '%s %s\n' "$PREFIX" "$*"; }
fail() { printf '%s FAILED: %s\n' "$PREFIX" "$*" >&2; exit 1; }

evidence() {
  local name="$1" content="$2"
  mkdir -p "$EVIDENCE_DIR"
  printf '%s\n' "$content" > "$EVIDENCE_DIR/$name"
  say "evidence: $name"
}

cleanup() {
  set +e
  if [ -n "${BUILDKITD_PID:-}" ]; then kill "$BUILDKITD_PID" 2>/dev/null; fi
  if [ -n "${MARKER_PID:-}" ]; then kill "$MARKER_PID" 2>/dev/null; fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# 0. identity/packages
say "=== 0. identity + packages ==="
evidence kernel.txt "$(uname -a; cat /proc/sys/user/max_user_namespaces; cat /sys/kernel/security/lsm 2>/dev/null)"
evidence packages.txt "$(rpm -qa | grep -Ei 'rootlesskit|slirp4netns|buildkit|uidmap|shadow|fuse-overlayfs|libfuse|apparmor' | sort)"

command -v rootlesskit >/dev/null 2>&1 || fail "rootlesskit not installed"
command -v slirp4netns >/dev/null 2>&1 || fail "slirp4netns not installed"
command -v buildkitd >/dev/null 2>&1 || fail "buildkitd not installed"
command -v buildctl >/dev/null 2>&1 || fail "buildctl not installed"
command -v newuidmap >/dev/null 2>&1 || fail "newuidmap not installed"
command -v docker >/dev/null 2>&1 || fail "docker not installed"
docker info >/dev/null 2>&1 || fail "rootful docker engine not reachable"
evidence versions.txt "$(buildkitd --version; rootlesskit --version; slirp4netns --version; docker --version)"

# 1. builder identity
id "$BUILDER_USER" >/dev/null 2>&1 || fail "builder user missing"
BUILDER_UID="$(id -u "$BUILDER_USER")"
SUBUID_LINE="$(grep "^$BUILDER_USER:" /etc/subuid || true)"
SUBGID_LINE="$(grep "^$BUILDER_USER:" /etc/subgid || true)"
[ -n "$SUBUID_LINE" ] || fail "subuid missing"
[ -n "$SUBGID_LINE" ] || fail "subgid missing"
SUBUID_RANGE="$(echo "$SUBUID_LINE" | cut -d: -f3)"
SUBGID_RANGE="$(echo "$SUBGID_LINE" | cut -d: -f3)"
[ "$SUBUID_RANGE" -ge 65536 ] || fail "subuid range < 65536"
[ "$SUBGID_RANGE" -ge 65536 ] || fail "subgid range < 65536"
evidence subuid.txt "subuid: $SUBUID_LINE
subgid: $SUBGID_LINE
builder uid: $BUILDER_UID"

BUILDER_XDG="/run/user/$BUILDER_UID"
mkdir -p "$BUILDER_STATE" "$BUILDER_XDG"
chown -R "$BUILDER_USER:$BUILDER_USER" "$BUILDER_HOME" "$BUILDER_STATE" "$BUILDER_XDG"
chmod 700 "$BUILDER_XDG" "$BUILDER_STATE"

# 2. host-loopback marker
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
: > "$WORK_DIR/marker-listener.log"
say "host marker service up"

# 3. rootless buildkitd
chmod 755 "$WORK_DIR"
mkdir -p "$WORK_DIR/rootlesskit-state"
chown -R "$BUILDER_USER:$BUILDER_USER" "$WORK_DIR"
BUILDKITD_CONFIG="$WORK_DIR/buildkitd.toml"
cat > "$BUILDKITD_CONFIG" <<EOF
debug = false
[grpc]
  address = ["unix://$SOCKET"]
EOF
su -s /bin/sh "$BUILDER_USER" -c \
  "exec env XDG_RUNTIME_DIR=$BUILDER_XDG HOME=$BUILDER_HOME USER=$BUILDER_USER PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin rootlesskit --net=slirp4netns --copy-up=/etc --disable-host-loopback --state-dir=$WORK_DIR/rootlesskit-state buildkitd --rootless --root=$BUILDER_STATE --addr=unix://$SOCKET --config=$BUILDKITD_CONFIG" \
  > "$WORK_DIR/buildkitd.log" 2>&1 &
BUILDKITD_PID=$!

socket_ready=0
for _ in $(seq 1 90); do
  if ! kill -0 "$BUILDKITD_PID" 2>/dev/null; then
    tail -40 "$WORK_DIR/buildkitd.log" || true
    fail "rootless buildkitd exited before its socket appeared"
  fi
  if [ -S "$SOCKET" ]; then socket_ready=1; break; fi
  sleep 1
done
[ "$socket_ready" = 1 ] || fail "socket did not appear"
say "rootless buildkitd up"
evidence buildkitd.log "$(tail -40 "$WORK_DIR/buildkitd.log")"

buildctl_ok=0
for _ in $(seq 1 15); do
  if buildctl --addr "$BUILDCTL_ADDR" debug workers >/dev/null 2>&1; then
    buildctl_ok=1; break
  fi
  sleep 1
done
[ "$buildctl_ok" = 1 ] || { buildctl --addr "$BUILDCTL_ADDR" debug workers 2>&1 | head -5 || true; fail "root cannot drive buildkitd"; }
say "root -> buildkitd OK"
evidence workers.json "$(buildctl --addr "$BUILDCTL_ADDR" debug workers 2>&1 || true)"

# 4. namespace evidence
CTX_PROBE="$WORK_DIR/ctx-probe"
mkdir -p "$CTX_PROBE"
cat > "$CTX_PROBE/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN mkdir -p /m0
RUN id > /m0/id.txt
RUN cat /proc/self/uid_map > /m0/uid_map.txt
RUN cat /proc/self/gid_map > /m0/gid_map.txt
RUN grep Cap /proc/self/status > /m0/caps.txt
RUN readlink /proc/self/ns/user > /m0/ns_user.txt
RUN readlink /proc/self/ns/pid > /m0/ns_pid.txt
RUN ls /run/buildkit /var/run/docker.sock /run/docker.sock > /m0/socks.txt 2>&1 || true
RUN ls /dev > /m0/dev.txt
EOF
buildctl --addr "$BUILDCTL_ADDR" build \
  --frontend dockerfile.v0 \
  --local "context=$CTX_PROBE" \
  --local "dockerfile=$CTX_PROBE" \
  --output "type=docker,name=m0-probe:ns,dest=$WORK_DIR/m0-ns.tar" > "$WORK_DIR/nsbuild.log" 2>&1 || {
  tail -30 "$WORK_DIR/nsbuild.log"
  fail "namespace probe build failed"
}
docker load < "$WORK_DIR/m0-ns.tar" >/dev/null || fail "docker load failed"

RAW_UID_MAP="$(docker run --rm m0-probe:ns cat /m0/uid_map.txt 2>/dev/null | head -1 || true)"
BUILD_HOST_UID="$(echo "$RAW_UID_MAP" | awk '{print $2}')"
[ -n "$BUILD_HOST_UID" ] || fail "cannot read uid_map"
[ "$BUILD_HOST_UID" != "0" ] || fail "build RUN maps to host uid 0"
evidence ns-evidence.txt "uid_map: $RAW_UID_MAP
id: $(docker run --rm m0-probe:ns cat /m0/id.txt | head -1)
ns_user: $(docker run --rm m0-probe:ns cat /m0/ns_user.txt)
ns_pid: $(docker run --rm m0-probe:ns cat /m0/ns_pid.txt)
socks: $(docker run --rm m0-probe:ns cat /m0/socks.txt | tr '\n' ';')
dev: $(docker run --rm m0-probe:ns cat /m0/dev.txt | tr '\n' ' ')"
say "sandbox-root host-side uid=$BUILD_HOST_UID (PASS)"

# 5. host-root marker negative
echo "M0-ROOT-MARKER-SECRET" > "$WORK_DIR/m0-root-marker"
chmod 600 "$WORK_DIR/m0-root-marker"
CTX_MARKER="$WORK_DIR/ctx-marker"
mkdir -p "$CTX_MARKER"
cat > "$CTX_MARKER/Dockerfile" <<EOF
FROM alpine:3.20
RUN mkdir -p /m0
RUN cat $WORK_DIR/m0-root-marker > /m0/leak.txt 2>&1; echo rc=\$? >> /m0/leak.txt
EOF
buildctl --addr "$BUILDCTL_ADDR" build \
  --frontend dockerfile.v0 \
  --local "context=$CTX_MARKER" \
  --local "dockerfile=$CTX_MARKER" \
  --output "type=docker,name=m0-probe:marker,dest=$WORK_DIR/m0-marker.tar" >/dev/null 2>&1 || fail "marker build failed"
docker load < "$WORK_DIR/m0-marker.tar" >/dev/null
MARKER_OUT="$(docker run --rm m0-probe:marker sh -c 'cat /m0/leak.txt')"
evidence root-marker.txt "$MARKER_OUT"
if printf '%s\n' "$MARKER_OUT" | grep -q "M0-ROOT-MARKER-SECRET"; then
  fail "host-root marker leaked"
fi
say "host-root marker negative (PASS)"

# 6. host-loopback negative
CTX_LOOP="$WORK_DIR/ctx-loop"
mkdir -p "$CTX_LOOP"
cat > "$CTX_LOOP/Dockerfile" <<EOF
FROM alpine:3.20
RUN mkdir -p /m0
RUN wget -q -T3 -O- http://127.0.0.1:$HOST_MARKER_PORT/ > /m0/net.txt 2>&1; echo rc=\$? >> /m0/net.txt
EOF
buildctl --addr "$BUILDCTL_ADDR" build \
  --frontend dockerfile.v0 \
  --local "context=$CTX_LOOP" \
  --local "dockerfile=$CTX_LOOP" \
  --output "type=docker,name=m0-probe:loop,dest=$WORK_DIR/m0-loop.tar" >/dev/null 2>&1 || fail "loopback build failed"
docker load < "$WORK_DIR/m0-loop.tar" >/dev/null
LOOP_OUT="$(docker run --rm m0-probe:loop sh -c 'cat /m0/net.txt')"
evidence loop-result.txt "$LOOP_OUT"
if printf '%s\n' "$LOOP_OUT" | grep -q "M0-SECRET-OK"; then
  fail "host loopback reached"
fi
say "host loopback negative (PASS)"
if grep -q "GOT:" "$WORK_DIR/marker-listener.log"; then
  fail "listener got build traffic"
fi
say "listener received nothing (PASS)"

# 7. outbound positive
CTX_OUT="$WORK_DIR/ctx-out"
mkdir -p "$CTX_OUT"
cat > "$CTX_OUT/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN mkdir -p /m0
RUN apk add --no-cache curl > /m0/apk.txt 2>&1; echo apk_rc=$? >> /m0/net2.txt; curl -s -o /dev/null https://dl-cdn.alpinelinux.org/alpine/; echo curl_rc=$? >> /m0/net2.txt
EOF
buildctl --addr "$BUILDCTL_ADDR" build \
  --frontend dockerfile.v0 \
  --local "context=$CTX_OUT" \
  --local "dockerfile=$CTX_OUT" \
  --output "type=docker,name=m0-probe:out,dest=$WORK_DIR/m0-out.tar" >/dev/null 2>&1 || fail "outbound build failed"
docker load < "$WORK_DIR/m0-out.tar" >/dev/null
OUT_RUN="$(docker run --rm m0-probe:out sh -c 'cat /m0/net2.txt')"
evidence out-result.txt "$OUT_RUN"
printf '%s\n' "$OUT_RUN" | grep -q "curl_rc=0" || fail "outbound traffic failed"
say "outbound positive (PASS)"

# 8. entitlement negatives
deny_probe() {
  local name="$1" dockerfile="$2"
  local ctx="$WORK_DIR/ctx-$name"
  mkdir -p "$ctx"
  printf '%s\n' "$dockerfile" > "$ctx/Dockerfile"
  if buildctl --addr "$BUILDCTL_ADDR" build \
    --frontend dockerfile.v0 \
    --local "context=$ctx" \
    --local "dockerfile=$ctx" \
    --output "type=docker,dest=$WORK_DIR/ent-$name.tar" 2> "$WORK_DIR/ent-$name.err"; then
    fail "$name entitlement accepted"
  fi
  evidence "entitlement-$name.err" "$(cat "$WORK_DIR/ent-$name.err")"
  say "$name refused (PASS)"
}
deny_probe host 'FROM alpine:3.20
RUN --network=host true'
deny_probe insecure 'FROM alpine:3.20
RUN --security=insecure true'

# 9. control-socket isolation
ls -la "$SOCKET" > "$EVIDENCE_DIR/socket-perms.txt"
TEST_UID=65534
if setpriv --reuid "$TEST_UID" --regid "$TEST_UID" --clear-groups \
  buildctl --addr "$BUILDCTL_ADDR" debug workers >/dev/null 2>&1; then
  fail "ordinary user connected to control socket"
fi
say "ordinary connect denied (PASS)"

# 10. round trip
CTX_HELLO="$WORK_DIR/ctx-hello"
mkdir -p "$CTX_HELLO"
cat > "$CTX_HELLO/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN mkdir -p /m0
RUN echo m0-roundtrip > /m0/marker.txt
EOF
buildctl --addr "$BUILDCTL_ADDR" build \
  --frontend dockerfile.v0 \
  --local "context=$CTX_HELLO" \
  --local "dockerfile=$CTX_HELLO" \
  --output "type=docker,name=m0-hello:latest,dest=$WORK_DIR/m0-hello.tar" >/dev/null 2>&1 || fail "roundtrip build failed"
docker load < "$WORK_DIR/m0-hello.tar" >/dev/null || fail "docker load failed"
MARKER="$(docker run --rm m0-hello:latest cat /m0/marker.txt)"
[ "$MARKER" = "m0-roundtrip" ] || fail "roundtrip marker mismatch"
say "round trip (PASS)"
echo "roundtrip: PASS" > "$EVIDENCE_DIR/roundtrip.txt"

# 11. failed-build negative
CTX_FAIL="$WORK_DIR/ctx-fail"
mkdir -p "$CTX_FAIL"
cat > "$CTX_FAIL/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN false
EOF
if buildctl --addr "$BUILDCTL_ADDR" build \
  --frontend dockerfile.v0 \
  --local "context=$CTX_FAIL" \
  --local "dockerfile=$CTX_FAIL" \
  --output "type=docker,name=m0-fail-target:latest,dest=$WORK_DIR/m0-fail.tar" >/dev/null 2>&1; then
  fail "failed build reported success"
fi
if [ -f "$WORK_DIR/m0-fail.tar" ]; then
  if docker load < "$WORK_DIR/m0-fail.tar" >/dev/null 2>&1; then
    fail "failed build left loadable tar"
  fi
  rm -f "$WORK_DIR/m0-fail.tar"
fi
docker image inspect m0-fail-target:latest >/dev/null 2>&1 && fail "partial target image usable"
say "failed-build negative (PASS)"

say "=== ALL PROOFS COMPLETE — Tumbleweed composition A viable ==="
echo "M0-TW-PROOF-RESULT=PASS" > "$EVIDENCE_DIR/RESULT.txt"
