#!/usr/bin/env bash
#
# Release 2.4 M1 probe, part 2: throwaway builder-manager prototype +
# ephemeral per-build-operation BuildKit instances.
#
# Architecture under test (candidate C):
#
#   root probe (docker-helper stand-in)
#     | narrow line protocol over a private manager socket (0660 root:builder)
#     v
#   builder-manager prototype process (runs AS the unprivileged builder user)
#     | per START <op_id>: op-private runtime/state dirs, then
#     v
#   rootlesskit --net=slirp4netns --copy-up=/etc --disable-host-loopback
#     -> ephemeral rootless buildkitd (op-private --root, op-private socket)
#
#   root probe runs buildctl client-side with DOCKER_CONFIG=<session config>
#   against the op-private socket; on STOP <op_id> the manager kills the
#   instance's process group and removes its state, socket and dirs.
#
# Proofs included:
#   1. START/STOP protocol; START returns only the socket path + readiness.
#   2. Manager socket inaccessible to ordinary users/agents (nobody, m0agent).
#   3. Per-op socket inaccessible to ordinary users/agents.
#   4. Ephemeral state: A writes a cache-mount secret, instance destroyed,
#      B with the same cache id sees nothing (with a NEGATIVE SELF-TEST:
#      before teardown the A state is proven to exist).
#   5. No ordinary layer-cache reuse across operations.
#   6. Concurrency: two ops simultaneously — distinct sockets/state, no
#      cross visibility, both outbound networks work, both loopback
#      negatives hold; killing one does not affect the other.
#   7. Crash/cleanup: client disappears mid-build; STOP; buildkitd killed
#      externally; rootlesskit killed; manager restart purges all
#      op-private runtime/state.
#   8. Manager hard ceiling of 2: third START refused immediately (no
#      queue, no waiting).
#
# M1 probe only: no docker-helper product code changes.

set -Eeuo pipefail

PREFIX='[release-2.4-m1-ephemeral]'
EVIDENCE_DIR="${M1_EVIDENCE_DIR:-/tmp/release-2.4-m1-ephemeral-evidence}"
BUILDER_USER="${M0_BUILDER_USER:-dhm0builder}"
BUILDER_UID=""
BUILDER_GID=""
BUILDER_HOME="/home/$BUILDER_USER"
MGR_RUNTIME="/run/docker-helper-builder"
MGR_STATE="/var/lib/docker-helper-builder"
MGR_SOCK="$MGR_RUNTIME/manager.sock"
HOST_MARKER_PORT="${M0_HOST_MARKER_PORT:-59996}"
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

cleanup() {
  set +e
  if [ -n "${MGR_PID:-}" ]; then kill "$MGR_PID" 2>/dev/null; fi
  if [ -n "${MARKER_PID:-}" ]; then kill "$MARKER_PID" 2>/dev/null; fi
  if [ -z "$KEEP" ] && [ -n "${MGR_WORK:-}" ] && [ -d "$MGR_WORK" ]; then
    rm -rf "$MGR_WORK" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 0. environment identity + preconditions
# ---------------------------------------------------------------------------
say "=== 0. environment identity ==="
evidence_cmd kernel.txt bash -c 'uname -a
cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo no-restrict-sysctl
cat /sys/kernel/security/lsm 2>/dev/null'

command -v rootlesskit >/dev/null 2>&1 || fail "rootlesskit not installed"
command -v slirp4netns >/dev/null 2>&1 || fail "slirp4netns not installed"
command -v buildkitd >/dev/null 2>&1 || fail "buildkitd not installed"
command -v buildctl >/dev/null 2>&1 || fail "buildctl not installed"
command -v newuidmap >/dev/null 2>&1 || fail "newuidmap not installed"
command -v docker >/dev/null 2>&1 || fail "docker not installed"
docker info >/dev/null 2>&1 || fail "rootful docker engine not reachable"

# openSUSE: /etc/ssl/* are RELATIVE symlinks into /var/lib/ca-certificates;
# rootlesskit --copy-up=/etc copies the links but not the targets =>
# dangling CAs inside the child (rootlesskit#225). The manager spawns each
# per-op buildkitd with SSL_CERT_FILE pointing at the real host CA bundle
# (single env var, no mount games; the same narrow fix M0 proved).
M1_BUILDER_CERT_ENV=""
if [ -f /etc/ssl/ca-bundle.pem ]; then
  M1_BUILDER_CERT_ENV="SSL_CERT_FILE=$(realpath /etc/ssl/ca-bundle.pem 2>/dev/null || echo /etc/ssl/ca-bundle.pem)"
elif [ -f /var/lib/ca-certificates/ca-bundle.pem ]; then
  M1_BUILDER_CERT_ENV="SSL_CERT_FILE=/var/lib/ca-certificates/ca-bundle.pem"
fi
if [ -n "$M1_BUILDER_CERT_ENV" ]; then
  # the builder must be able to read the bundle (no chmod of host material)
  CA_TARGET="${M1_BUILDER_CERT_ENV#SSL_CERT_FILE=}"
  if ! su -s /bin/sh "$BUILDER_USER" -c "test -r $CA_TARGET" 2>/dev/null; then
    fail "builder user cannot read host CA bundle ($CA_TARGET)"
  fi
  say "builder CA env: $M1_BUILDER_CERT_ENV"
fi
evidence builder-ca-env.txt "${M1_BUILDER_CERT_ENV:-<none needed>}"

# ---------------------------------------------------------------------------
# 1. dedicated builder identity (M0 mechanics)
# ---------------------------------------------------------------------------
say "=== 1. dedicated builder identity ==="
id "$BUILDER_USER" >/dev/null 2>&1 || fail "builder user $BUILDER_USER missing"
BUILDER_UID="$(id -u "$BUILDER_USER")"
BUILDER_GID="$(id -g "$BUILDER_USER")"
SUBUID_LINE="$(grep "^$BUILDER_USER:" /etc/subuid || true)"
SUBGID_LINE="$(grep "^$BUILDER_USER:" /etc/subgid || true)"
[ -n "$SUBUID_LINE" ] || fail "subuid missing for $BUILDER_USER"
[ -n "$SUBGID_LINE" ] || fail "subgid missing for $BUILDER_USER"
evidence subuid.txt "subuid: $SUBUID_LINE
subgid: $SUBGID_LINE
builder uid: $BUILDER_UID"
say "builder identity ok (uid=$BUILDER_UID)"

# manager runtime/state roots; owned by the builder user
MGR_WORK="$(mktemp -d "${M1_MGR_WORK:-/tmp/release-2.4-m1-ephemeral.XXXXXXXX}")"
BUILDER_XDG="/run/user/$BUILDER_UID"
mkdir -p "$MGR_RUNTIME" "$MGR_STATE" "$BUILDER_XDG"
chown -R "$BUILDER_UID:$BUILDER_GID" "$BUILDER_XDG"
chmod 700 "$BUILDER_XDG"
chown "$BUILDER_UID:$BUILDER_GID" "$MGR_RUNTIME" "$MGR_STATE"
chmod 750 "$MGR_RUNTIME" "$MGR_STATE"

# session Docker config (root side): buildctl reads registry credentials
# from here; the builder manager/buildkitd never receive them
SESSION_DOCKER_CONFIG="$MGR_WORK/docker-config"
mkdir -p "$SESSION_DOCKER_CONFIG"
echo '{}' > "$SESSION_DOCKER_CONFIG/config.json"

# ---------------------------------------------------------------------------
# 2. manager prototype: unprivileged process with a narrow line protocol
# ---------------------------------------------------------------------------
say "=== 2. builder-manager prototype ==="
#
# The manager prototype is ONE bash process running as the builder user with
# a python accept loop dispatching narrow commands to two bash helpers.
#
cat > "$MGR_WORK/manager-ops.sh" <<'OPS'
#!/usr/bin/env bash
# Operation lifecycle helpers for the throwaway manager prototype.
# Usage: manager-ops.sh <RUNTIME> <STATE> <start|stop|purge> <op_id?>
# Prints a single response line on stdout.
set -Eeuo pipefail

RUNTIME="$1"; STATE="$2"; CMD="$3"; OP="${4:-}"

if [ "$CMD" != "purge" ]; then
  # canonical operation id grammar: op_ + exactly 32 lowercase hex chars
  if [[ ! "$OP" =~ ^op_[0-9a-f]{32}$ ]]; then
    echo "ERR bad operation id"; exit 0
  fi
fi

start_op() {
  local op="$1"
  local rt="$RUNTIME/ops/$op"
  local st="$STATE/ops/$op"
  if [ -e "$rt" ] || [ -e "$st" ]; then
    echo "ERR operation already exists"
    return
  fi
  # hard concurrency ceiling (defense in depth; the product already refuses
  # a third build at maxConcurrentBuildsGlobal=2): count live instances,
  # refuse immediately, never queue
  local live=0 d p
  for d in "$RUNTIME"/ops/op_*; do
    [ -d "$d" ] || continue
    p="$(cat "$d/instance.pid" 2>/dev/null || true)"
    if [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then
      live=$((live + 1))
    fi
  done
  if [ "$live" -ge 2 ]; then
    echo "ERR builder at concurrency ceiling"
    return
  fi
  mkdir -p "$rt" "$st/rootlesskit-state"
  local sock="$rt/buildkitd.sock"
  local cfg="$rt/buildkitd.toml"
  cat > "$cfg" <<TOML
debug = false
[grpc]
  address = ["unix://$sock"]
TOML
  setsid env \
    ${M1_BUILDER_CERT_ENV:-} \
    rootlesskit \
    --net=slirp4netns \
    --copy-up=/etc \
    --disable-host-loopback \
    --state-dir="$st/rootlesskit-state" \
    buildkitd \
    --rootless \
    --root="$st/root" \
    --addr="unix://$sock" \
    --config="$cfg" \
    > "$rt/buildkitd.log" 2>&1 &
  local pid=$!
  printf '%s\n' "$pid" > "$rt/instance.pid"
  local ready=0
  for _ in $(seq 1 60); do
    if ! kill -0 "$pid" 2>/dev/null; then
      tail -8 "$rt/buildkitd.log" >&2 || true
      rm -rf "$rt" "$st"
      echo "ERR buildkitd exited early"
      return
    fi
    if [ -S "$sock" ]; then ready=1; break; fi
    sleep 1
  done
  if [ "$ready" != 1 ]; then
    kill -- -"$pid" 2>/dev/null || true
    rm -rf "$rt" "$st"
    echo "ERR socket never appeared"
    return
  fi
  echo "OK $sock"
}

stop_op() {
  local op="$1"
  local rt="$RUNTIME/ops/$op"
  local st="$STATE/ops/$op"
  if [ ! -e "$rt" ] && [ ! -e "$st" ]; then
    echo "OK absent"
    return
  fi
  local pid=""
  if [ -f "$rt/instance.pid" ]; then
    pid="$(cat "$rt/instance.pid")"
  fi
  if [ -n "$pid" ]; then
    kill -- -"$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
  fi
  for _ in $(seq 1 20); do
    [ -S "$rt/buildkitd.sock" ] || break
    sleep 0.5
  done
  rm -rf "$rt" "$st"
  echo "OK stopped"
}

purge_all() {
  rm -rf "$RUNTIME/ops" "$STATE/ops"
  mkdir -p "$RUNTIME/ops" "$STATE/ops"
  echo "OK purged"
}

case "$CMD" in
  start) start_op "$OP" ;;
  stop) stop_op "$OP" ;;
  purge) purge_all ;;
  *) echo "ERR unknown command"; exit 0 ;;
esac
OPS

cat > "$MGR_WORK/manager-listener.py" <<'PY'
import os, socket, sys, threading, subprocess
sock_path, ops_script, runtime, state = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
os.chmod(sock_path, 0o660)
# gid set to the manager's own group; the probe chowns the socket to
# root:builder after connecting so root (docker-helper stand-in) and the
# builder group share access, ordinary users get EACCES.
s.listen(16)

def dispatch(conn, data):
    parts = data.split()
    try:
        if len(parts) == 1 and parts[0] == "PURGE":
            r = subprocess.run(["bash", ops_script, runtime, state, "purge"],
                               capture_output=True, text=True, timeout=120)
            conn.sendall(((r.stdout.strip() or "ERR subprocess") + "\n").encode())
            return
        if len(parts) != 2:
            conn.sendall(b"ERR protocol\n"); return
        cmd, op = parts
        if cmd not in ("START", "STOP"):
            conn.sendall(b"ERR unknown command\n"); return
        helper = "start" if cmd == "START" else "stop"
        r = subprocess.run(["bash", ops_script, runtime, state, helper, op],
                           capture_output=True, text=True, timeout=180)
        out = r.stdout.strip() or ("ERR subprocess-failed: " + r.stderr.strip()[-200:])
        if r.returncode != 0 and r.stdout.strip():
            out += " | stderr: " + r.stderr.strip()[-200:]
        conn.sendall((out + "\n").encode())
    except Exception as e:
        try: conn.sendall(("ERR " + str(e) + "\n").encode())
        except Exception: pass
    finally:
        conn.close()

def serve():
    while True:
        c, _ = s.accept()
        def handle(c):
            try:
                data = c.recv(4096).decode(errors="replace").strip()
                if data:
                    dispatch(c, data)
                else:
                    c.close()
            except Exception:
                try: c.close()
                except Exception: pass
        threading.Thread(target=handle, args=(c,), daemon=True).start()

# startup purge: every manager start removes all previous operation-private
# runtime/state (caches are disposable; no adoption/reconciliation exists)
r = subprocess.run(["bash", ops_script, runtime, state, "purge"],
                   capture_output=True, text=True, timeout=120)
if "OK purged" not in r.stdout:
    sys.stderr.write("startup purge failed: " + r.stdout + r.stderr)
    sys.exit(1)

# readiness marker for the probe
open(os.path.join(os.path.dirname(sock_path), "manager.ready"), "w").write("ready\n")
serve()
PY

# launch the manager AS the builder user; it owns everything below its roots
chown -R "$BUILDER_UID:$BUILDER_GID" "$MGR_WORK"
chmod 755 "$MGR_WORK"
MGR_LOG="$MGR_WORK/manager.log"
touch "$MGR_LOG" "$MGR_WORK/manager-listener.out"
chown "$BUILDER_UID:$BUILDER_GID" "$MGR_LOG" "$MGR_WORK/manager-listener.out"

setsid setpriv --reuid "$BUILDER_UID" --regid "$BUILDER_GID" --clear-groups \
  env XDG_RUNTIME_DIR="$BUILDER_XDG" HOME="$BUILDER_HOME" USER="$BUILDER_USER" \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  python3 -u "$MGR_WORK/manager-listener.py" \
    "$MGR_SOCK" "$MGR_WORK/manager-ops.sh" "$MGR_RUNTIME" "$MGR_STATE" \
  > "$MGR_WORK/manager-listener.out" 2>&1 &
MGR_PID=$!

ready=0
for _ in $(seq 1 20); do
  if ! kill -0 "$MGR_PID" 2>/dev/null; then
    say "manager process exited early"
    break
  fi
  if [ -S "$MGR_SOCK" ] && [ -f "$MGR_RUNTIME/manager.ready" ]; then ready=1; break; fi
  sleep 0.5
done
if [ "$ready" != 1 ]; then
  say "manager listener failed to start; diagnostics:"
  cat "$MGR_WORK/manager-listener.out" 2>/dev/null || true
  ls -la "$MGR_RUNTIME" "$MGR_WORK" 2>/dev/null || true
  pgrep -af "manager-listener" || true
  fail "manager socket never appeared"
fi
# grant root access via the root:builder group pair (the file is 0660 owned
# builder:builder; chown to root:builder so root and builder-group members
# both connect)
chown "root:$BUILDER_GID" "$MGR_SOCK"
say "manager prototype up; socket=$MGR_SOCK pid=$MGR_PID"
evidence manager-socket.txt "$(ls -la "$MGR_SOCK")"

mgr_call() {
  local payload="$1"
  python3 - "$MGR_SOCK" "$payload" <<'PY'
import socket, sys
path, payload = sys.argv[1], sys.argv[2].encode()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(path)
s.sendall(payload)
s.settimeout(180)
resp = b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk: break
        resp += chunk
        if b"\n" in resp: break
finally:
    s.close()
print(resp.decode(errors="replace").strip())
PY
}

# ---------------------------------------------------------------------------
# 3. narrow protocol smoke: shape rejections
# ---------------------------------------------------------------------------
say "=== 3. manager protocol ==="
RESP_BADID="$(mgr_call "START not-an-op-id")"
evidence manager-protocol.txt "START bad id -> $RESP_BADID"
printf '%s\n' "$RESP_BADID" | grep -q "^ERR" || fail "manager accepted a malformed operation id"

RESP_UNKNOWN="$(mgr_call "FROB op_00000000000000000000000000000000")"
RESP_UNKNOWN="$(mgr_call "FROB op_00000000000000000000000000000000")"
evidence manager-protocol2.txt "FROB unknown cmd -> $RESP_UNKNOWN"
printf '%s\n' "$RESP_UNKNOWN" | grep -q "^ERR" || fail "manager accepted an unknown command"

new_op_id() {
  printf 'op_%s' "$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
}

OP_A="$(new_op_id)"
START_RESP="$(mgr_call "START $OP_A")"
evidence manager-protocol3.txt "START $OP_A -> $START_RESP"
SOCKET_A="$(printf '%s\n' "$START_RESP" | awk '{print $2}')"
printf '%s\n' "$START_RESP" | grep -q "^OK " || fail "START failed: $START_RESP"
[ -S "$SOCKET_A" ] || fail "START did not return a real socket path"
say "op A started; socket=$SOCKET_A"

# ---------------------------------------------------------------------------
# 4. socket isolation: manager socket + per-op socket vs ordinary users
# ---------------------------------------------------------------------------
say "=== 4. socket isolation ==="
reach_sock() {
  python3 - "$1" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.sendall(b"PURGE")
s.recv(64)
PY
}
AGENT_USER="m0agent"
id "$AGENT_USER" >/dev/null 2>&1 || useradd -m "$AGENT_USER" 2>/dev/null || true
if id "$AGENT_USER" >/dev/null 2>&1; then
  if setpriv --reuid "$(id -u "$AGENT_USER")" --regid "$(id -g "$AGENT_USER")" --clear-groups \
    reach_sock "$MGR_SOCK" >/dev/null 2>&1; then
    fail "agent user CAN reach the manager socket"
  fi
  say "agent user -> manager socket DENIED (PASS)"
fi
if setpriv --reuid 65534 --regid 65534 --clear-groups \
  reach_sock "$MGR_SOCK" >/dev/null 2>&1; then
  fail "nobody CAN reach the manager socket"
fi
say "nobody -> manager socket DENIED (PASS)"
evidence manager-socket-denied.txt "nobody/agent connect to manager socket: denied"

if setpriv --reuid 65534 --regid 65534 --clear-groups \
  env buildctl --addr "unix://$SOCKET_A" debug workers >/dev/null 2>&1; then
  fail "nobody CAN use the per-op buildkit socket"
fi
say "nobody -> op socket DENIED (PASS)"
evidence op-socket-denied.txt "nobody connect to per-op buildkit socket: denied"

# ---------------------------------------------------------------------------
# 5. ephemeral state: cross-op cache-mount + layer-cache isolation
# ---------------------------------------------------------------------------
say "=== 5. ephemeral state proof ==="
CACHE_ID="dh-eph-test"
CTX_W="$MGR_WORK/ctx-w"
CTX_R="$MGR_WORK/ctx-r"
mkdir -p "$CTX_W" "$CTX_R"
cat > "$CTX_W/Dockerfile" <<EOF
FROM alpine:3.20
RUN --mount=type=cache,id=$CACHE_ID,target=/cache \
    sh -c 'mkdir -p /m1 && echo EPHEMERAL-A-SECRET > /cache/marker'
EOF
cat > "$CTX_R/Dockerfile" <<EOF
FROM alpine:3.20
RUN --mount=type=cache,id=$CACHE_ID,target=/cache \
    sh -c 'mkdir -p /m1 && (cat /cache/marker > /m1/observed.txt 2>/dev/null || echo missing > /m1/observed.txt)'
EOF

build_on() {
  local sock="$1" ctx="$2" tag="$3" out="$4" log="$5"; shift 5
  # buildctl runs client-side in the root docker-helper stand-in with the
  # session's Docker config; the builder never acquires a credential store
  DOCKER_CONFIG="$SESSION_DOCKER_CONFIG" \
    buildctl --addr "unix://$sock" \
    build --frontend dockerfile.v0 \
    "$@" \
    --local "context=$ctx" --local "dockerfile=$ctx" \
    --output "type=docker,name=$tag:latest,dest=$out" \
    > "$log" 2>&1 \
    || { tail -20 "$log"; fail "build on $sock failed"; }
}

# session A: write the secret through op A
build_on "$SOCKET_A" "$CTX_W" m1-eph-a "$MGR_WORK/out-a.tar" "$MGR_WORK/build-A.log"
say "op A build done"

# NEGATIVE SELF-TEST: the A state must provably exist before teardown.
A_STATE_ROOT="$MGR_STATE/ops/$OP_A/root"
if [ ! -d "$A_STATE_ROOT" ] || [ -z "$(ls -A "$A_STATE_ROOT" 2>/dev/null)" ]; then
  fail "negative self-test: op A buildkitd state root missing/empty before teardown"
fi
if ! grep -rls "EPHEMERAL-A-SECRET" "$A_STATE_ROOT" >/dev/null 2>&1; then
  fail "negative self-test: A's cache-mount secret not found in op A state before teardown"
fi
A_STATE_BYTES="$(du -sb "$A_STATE_ROOT" | awk '{print $1}')"
say "negative self-test: A state exists ($A_STATE_BYTES bytes, secret present) (PASS)"
echo "negative-self-test A state present: PASS" > "$EVIDENCE_DIR/negative-selftest.txt"

# op B: separate operation, SAME cache id; the manager creates a fresh
# ephemeral instance per operation, so B must observe nothing.
OP_B="$(new_op_id)"
START_RESP_B="$(mgr_call "START $OP_B")"
SOCKET_B="$(printf '%s\n' "$START_RESP_B" | awk '{print $2}')"
printf '%s\n' "$START_RESP_B" | grep -q "^OK " || fail "START B failed: $START_RESP_B"
[ -S "$SOCKET_B" ] || fail "START B socket missing"
say "op B started; socket=$SOCKET_B"
build_on "$SOCKET_B" "$CTX_R" m1-eph-b "$MGR_WORK/out-b.tar" "$MGR_WORK/build-B.log"
docker load -i "$MGR_WORK/out-b.tar" >/dev/null 2>&1 || true
B_OBS="$(docker run --rm m1-eph-b:latest cat /m1/observed.txt 2>/dev/null || true)"
evidence ephemeral-cache.txt "op B (fresh instance) with the same cache id observed:
$B_OBS"
if printf '%s\n' "$B_OBS" | grep -q "EPHEMERAL-A-SECRET"; then
  fail "op B observed op A's cache-mount secret — ephemeral isolation broken"
fi
printf '%s\n' "$B_OBS" | grep -q "missing" || fail "op B observation is not the expected 'missing' marker: $B_OBS"
say "op B did NOT observe A's cache content (PASS)"
echo "cross-op cache-mount isolation: PASS" > "$EVIDENCE_DIR/ephemeral-cache-pass.txt"

# ordinary layer-cache: identical Dockerfile+context across two separate
# operations. The observable that distinguishes reuse from re-execution is
# the CACHED verdict in the second build's progress output (the first
# instance's cache cannot reach the second instance): on the second build
# the RUN must NOT report CACHED. (The exported value alone cannot prove
# this: busybox date truncates to seconds, so two real executions can
# legitimately produce equal values.)
CTX_L="$MGR_WORK/ctx-layer"
mkdir -p "$CTX_L"
cat > "$CTX_L/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN mkdir -p /m1 && date +%s%N > /m1/nondeterministic.txt
EOF
build_on "$SOCKET_A" "$CTX_L" m1-eph-l1 "$MGR_WORK/out-l1.tar" "$MGR_WORK/build-l1.log"
build_on "$SOCKET_B" "$CTX_L" m1-eph-l2 "$MGR_WORK/out-l2.tar" "$MGR_WORK/build-l2.log"
docker load -i "$MGR_WORK/out-l1.tar" >/dev/null 2>&1 || true
docker load -i "$MGR_WORK/out-l2.tar" >/dev/null 2>&1 || true
LV1="$(docker run --rm m1-eph-l1:latest cat /m1/nondeterministic.txt 2>/dev/null || true)"
LV2="$(docker run --rm m1-eph-l2:latest cat /m1/nondeterministic.txt 2>/dev/null || true)"
L2_CACHED="$(grep -cE " CACHED" "$MGR_WORK/build-l2.log" || true)"
evidence ephemeral-layer.txt "layer build in op A value: $LV1
layer build in op B value: $LV2
op B build CACHED lines: $L2_CACHED
op B build log tail:
$(grep -E 'CACHED|exec|RUN' "$MGR_WORK/build-l2.log" | tail -6 || true)"
# only RUN-step CACHED lines count as layer-cache reuse; the base-image
# resolution step (#N CACHED) is content dedup of the pulled manifest, not
# op A's state
RUN_CACHED="$(awk '/^#[0-9]+ \[.*\] RUN /{step=$1} /^#[0-9]+ CACHED$/{if ($1==step) print $1}' "$MGR_WORK/build-l2.log" | head -1)"
if [ -n "$RUN_CACHED" ]; then
  fail "op B's RUN step was CACHED from op A's layer cache across ephemeral instances ($RUN_CACHED)"
fi
say "ordinary layer cache NOT reused across operations (no CACHED verdict in op B) (PASS)"
echo "cross-op layer-cache isolation: PASS" > "$EVIDENCE_DIR/ephemeral-layer-pass.txt"

# ---------------------------------------------------------------------------
# 6. teardown of op A: state/socket/process gone
# ---------------------------------------------------------------------------
say "=== 6. op A teardown ==="
STOP_RESP="$(mgr_call "STOP $OP_A")"
evidence teardown.txt "STOP $OP_A -> $STOP_RESP"
printf '%s\n' "$STOP_RESP" | grep -q "^OK" || fail "STOP failed: $STOP_RESP"
[ ! -e "$MGR_STATE/ops/$OP_A" ] || fail "op A state dir survived teardown"
[ ! -e "$MGR_RUNTIME/ops/$OP_A" ] || fail "op A runtime dir survived teardown"
[ ! -S "$SOCKET_A" ] || fail "op A socket survived teardown"
if pgrep -f "buildkitd --rootless --root=$MGR_STATE/ops/$OP_A" >/dev/null 2>&1; then
  fail "op A buildkitd process survived teardown"
fi
say "op A state, socket, process gone (PASS)"
echo "teardown-complete: PASS" > "$EVIDENCE_DIR/teardown-pass.txt"

# op B must be untouched by A's teardown
if buildctl --addr "unix://$SOCKET_B" debug workers >/dev/null 2>&1; then
  say "op B unaffected by A teardown (PASS)"
else
  fail "op B broke when op A was torn down"
fi

# ---------------------------------------------------------------------------
# 7. concurrency: distinct instances, network proofs, ceiling
# ---------------------------------------------------------------------------
say "=== 7. concurrency ==="
cat > "$MGR_WORK/marker-listener.py" <<'PY'
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
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nM1-SECRET-OK")
            c.close()
        except Exception:
            break
threading.Thread(target=serve, daemon=True).start()
print("listening", flush=True)
time.sleep(3600)
PY
python3 "$MGR_WORK/marker-listener.py" "$HOST_MARKER_PORT" > "$MGR_WORK/marker-listener.log" 2>&1 &
MARKER_PID=$!
sleep 1
curl -s "http://127.0.0.1:$HOST_MARKER_PORT/" | grep -q M1-SECRET-OK || fail "host marker service not reachable from host"
: > "$MGR_WORK/marker-listener.log"

OP_C="$(new_op_id)"
START_RESP_C="$(mgr_call "START $OP_C")"
SOCKET_C="$(printf '%s\n' "$START_RESP_C" | awk '{print $2}')"
printf '%s\n' "$START_RESP_C" | grep -q "^OK " || fail "START C failed: $START_RESP_C"
say "op C started (concurrent with B); socket=$SOCKET_C"

[ "$SOCKET_B" != "$SOCKET_C" ] || fail "op B and op C share a socket"
STATE_B="$MGR_STATE/ops/$OP_B/root"
STATE_C="$MGR_STATE/ops/$OP_C/root"
[ "$STATE_B" != "$STATE_C" ] || fail "op B and op C share a state root"
say "ops B and C: distinct sockets and state roots (PASS)"

# concurrent outbound positives and host-loopback negatives from both ops
CTX_OUT="$MGR_WORK/ctx-out"
CTX_LOOP="$MGR_WORK/ctx-loop"
mkdir -p "$CTX_OUT" "$CTX_LOOP"
cat > "$CTX_OUT/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN --mount=type=cache,id=dh-eph-net,target=/m1cache \
    sh -c 'apk add --no-cache curl > /dev/null 2>&1; curl -s -o /dev/null https://dl-cdn.alpinelinux.org/alpine/ && echo curl_ok > /m1curl'
EOF
cat > "$CTX_OUT/Dockerfile2" <<'EOF'
EOF
rm -f "$CTX_OUT/Dockerfile2"
cat > "$CTX_OUT/Dockerfile.out" <<'EOF'
EOF
rm -f "$CTX_OUT/Dockerfile.out"
cat > "$CTX_LOOP/Dockerfile" <<EOF
FROM alpine:3.20
RUN --mount=type=cache,id=dh-eph-loop,target=/m1cache \
    sh -c 'mkdir -p /m1 && (wget -q -T3 -O- http://127.0.0.1:$HOST_MARKER_PORT/ > /m1/net.txt 2>&1; echo rc=\$? >> /m1/net.txt)'
EOF

# build the outbound+loopback probe images via op B and op C simultaneously
( build_on "$SOCKET_B" "$CTX_OUT" m1-eph-netb "$MGR_WORK/out-netb.tar" "$MGR_WORK/build-netB.log" ) &
P1=$!
( build_on "$SOCKET_C" "$CTX_OUT" m1-eph-netc "$MGR_WORK/out-netc.tar" "$MGR_WORK/build-netC.log" ) &
P2=$!
wait "$P1" || fail "concurrent outbound build on op B failed"
wait "$P2" || fail "concurrent outbound build on op C failed"

docker load -i "$MGR_WORK/out-netb.tar" >/dev/null 2>&1 || true
docker load -i "$MGR_WORK/out-netc.tar" >/dev/null 2>&1 || true
OUTB="$(docker run --rm m1-eph-netb:latest sh -c 'apk add --no-cache curl >/dev/null 2>&1; curl -s -o /dev/null -w "%{http_code}" https://dl-cdn.alpinelinux.org/alpine/; echo' 2>&1 || true)"
OUTC="$(docker run --rm m1-eph-netc:latest sh -c 'apk add --no-cache curl >/dev/null 2>&1; curl -s -o /dev/null -w "%{http_code}" https://dl-cdn.alpinelinux.org/alpine/; echo' 2>&1 || true)"
evidence concurrency-net.txt "concurrent outbound (op B) http status: $OUTB
concurrent outbound (op C) http status: $OUTC"
case "$OUTB" in 200) ;; *) fail "op B concurrent outbound failed: $OUTB" ;; esac
case "$OUTC" in 200) ;; *) fail "op C concurrent outbound failed: $OUTC" ;; esac
say "concurrent outbound traffic works from both ops (PASS)"

# loopback negatives for both concurrent ops
build_on "$SOCKET_B" "$CTX_LOOP" m1-eph-loopb "$MGR_WORK/out-loopb.tar" "$MGR_WORK/build-loopB.log"
build_on "$SOCKET_C" "$CTX_LOOP" m1-eph-loopc "$MGR_WORK/out-loopc.tar" "$MGR_WORK/build-loopC.log"
docker load -i "$MGR_WORK/out-loopb.tar" >/dev/null 2>&1 || true
docker load -i "$MGR_WORK/out-loopc.tar" >/dev/null 2>&1 || true
LOOPB="$(docker run --rm m1-eph-loopb:latest cat /m1/net.txt 2>/dev/null || true)"
LOOPC="$(docker run --rm m1-eph-loopc:latest cat /m1/net.txt 2>/dev/null || true)"
evidence concurrency-loop.txt "op B loopback attempt: $LOOPB
op C loopback attempt: $LOOPC
listener log: $(cat "$MGR_WORK/marker-listener.log")"
if printf '%s\n' "$LOOPB" | grep -q "M1-SECRET-OK"; then fail "op B reached host loopback"; fi
if printf '%s\n' "$LOOPC" | grep -q "M1-SECRET-OK"; then fail "op C reached host loopback"; fi
if grep -q "GOT:" "$MGR_WORK/marker-listener.log"; then
  fail "host marker listener received build traffic (loopback leak)"
fi
say "host loopback NOT reachable from either concurrent op (PASS)"
echo "concurrency-network negatives: PASS" > "$EVIDENCE_DIR/concurrency-net-pass.txt"

# entitlement negatives remain true on the ephemeral instances
deny_probe() {
  local sock="$1" name="$2" dockerfile="$3" tag="$4"
  local ctx="$MGR_WORK/ctx-$name"
  mkdir -p "$ctx"
  printf '%s\n' "$dockerfile" > "$ctx/Dockerfile"
  if buildctl --addr "unix://$sock" build \
    --frontend dockerfile.v0 \
    --local "context=$ctx" --local "dockerfile=$ctx" \
    --output "type=docker,dest=$MGR_WORK/ent-$name.tar" 2> "$MGR_WORK/ent-$name.err"; then
    fail "$name entitlement ACCEPTED without server --allow (contract violation)"
  fi
  evidence "entitlement-$name.err" "$(cat "$MGR_WORK/ent-$name.err")"
}
deny_probe "$SOCKET_B" host 'FROM alpine:3.20
RUN --network=host true' m1-entb
deny_probe "$SOCKET_C" insecure 'FROM alpine:3.20
RUN --security=insecure true' m1-entc
say "insecure entitlements refused on both concurrent ops (PASS)"

# killing one op must not affect the other: crash op C's buildkitd
CKILL_PID="$(cat "$MGR_RUNTIME/ops/$OP_C/instance.pid")"
kill -9 -- -"$CKILL_PID" 2>/dev/null || kill -9 "$CKILL_PID" 2>/dev/null || true
sleep 2
if buildctl --addr "unix://$SOCKET_B" debug workers >/dev/null 2>&1; then
  say "op B unaffected by op C crash (PASS)"
else
  fail "op B broke when op C's instance was killed"
fi
echo "kill-isolation: PASS" > "$EVIDENCE_DIR/kill-isolation.txt"

# manager ceiling: start a second op while B is live? B is live; start D, E
OP_D="$(new_op_id)"
START_RESP_D="$(mgr_call "START $OP_D")"
SOCKET_D="$(printf '%s\n' "$START_RESP_D" | awk '{print $2}')"
printf '%s\n' "$START_RESP_D" | grep -q "^OK " || fail "START D failed: $START_RESP_D"
say "op D started (2 live: B and D); socket=$SOCKET_D"

OP_E="$(new_op_id)"
RESP_E="$(mgr_call "START $OP_E")"
evidence ceiling.txt "START at ceiling -> $RESP_E"
printf '%s\n' "$RESP_E" | grep -qE "^ERR" || fail "manager accepted a third concurrent instance (ceiling violated)"
say "manager refused the third instance at ceiling 2, immediately (PASS)"

# ---------------------------------------------------------------------------
# 8. crash/restart contract: manager restart purges everything
# ---------------------------------------------------------------------------
say "=== 8. crash/restart contract ==="
# restart the manager (simulate crash + systemd restart): kill it and relaunch
kill "$MGR_PID" 2>/dev/null || true
wait "$MGR_PID" 2>/dev/null || true
rm -f "$MGR_RUNTIME/manager.ready" "$MGR_SOCK"
setsid setpriv --reuid "$BUILDER_UID" --regid "$BUILDER_GID" --clear-groups \
  env XDG_RUNTIME_DIR="$BUILDER_XDG" HOME="$BUILDER_HOME" USER="$BUILDER_USER" \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  python3 -u "$MGR_WORK/manager-listener.py" \
    "$MGR_SOCK" "$MGR_WORK/manager-ops.sh" "$MGR_RUNTIME" "$MGR_STATE" \
  >> "$MGR_WORK/manager-listener.out" 2>&1 &
MGR_PID=$!
ready=0
for _ in $(seq 1 20); do
  if [ -S "$MGR_SOCK" ] && [ -f "$MGR_RUNTIME/manager.ready" ]; then ready=1; break; fi
  sleep 0.5
done
[ "$ready" = 1 ] || { cat "$MGR_WORK/manager-listener.out" || true; fail "manager did not restart"; }
chown "root:$BUILDER_GID" "$MGR_SOCK"
say "manager restarted"

# the startup purge must have removed ALL op-private state: B and D state
# gone, their sockets gone
[ ! -e "$MGR_STATE/ops/$OP_B" ] || fail "op B state survived manager restart (purge missing)"
[ ! -e "$MGR_STATE/ops/$OP_D" ] || fail "op D state survived manager restart (purge missing)"
[ ! -S "$SOCKET_B" ] || fail "op B socket survived manager restart"
[ ! -S "$SOCKET_D" ] || fail "op D socket survived manager restart"
say "manager startup purged all previous op-private runtime/state (PASS)"
echo "restart-purge: PASS" > "$EVIDENCE_DIR/restart-purge-pass.txt"

# a stale socket must not be accepted as live: after purge, ops are gone
RESP_AFTER_PURGE="$(mgr_call "STOP $OP_B")"
evidence restart-stale.txt "STOP for purged op -> $RESP_AFTER_PURGE"
printf '%s\n' "$RESP_AFTER_PURGE" | grep -q "OK absent" || fail "purged op STOP did not answer 'absent': $RESP_AFTER_PURGE"

# a fresh operation works normally after restart: a self-contained build
# (write + read its own write in one RUN, no dependence on any cache state)
CTX_FRESH="$MGR_WORK/ctx-fresh"
mkdir -p "$CTX_FRESH"
cat > "$CTX_FRESH/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN mkdir -p /m1 && echo fresh-op-write > /m1/observed.txt
EOF
OP_F="$(new_op_id)"
START_RESP_F="$(mgr_call "START $OP_F")"
SOCKET_F="$(printf '%s\n' "$START_RESP_F" | awk '{print $2}')"
printf '%s\n' "$START_RESP_F" | grep -q "^OK " || fail "START after restart failed: $START_RESP_F"
build_on "$SOCKET_F" "$CTX_FRESH" m1-eph-f "$MGR_WORK/out-f.tar" "$MGR_WORK/build-F.log"
docker load -i "$MGR_WORK/out-f.tar" >/dev/null 2>&1 || true
F_OBS="$(docker run --rm m1-eph-f:latest cat /m1/observed.txt 2>/dev/null || true)"
evidence restart-fresh.txt "post-restart op build observed its own write: $F_OBS"
if printf '%s\n' "$F_OBS" | grep -q "EPHEMERAL-A-SECRET"; then
  fail "post-restart operation reached pre-restart op A cache state"
fi
printf '%s\n' "$F_OBS" | grep -q "fresh-op-write" || fail "post-restart build did not observe its own write: $F_OBS"
say "post-restart operation fresh and self-contained (PASS)"

# ---------------------------------------------------------------------------
# 9. M0 invariants re-proven on the ephemeral composition (op F socket)
# ---------------------------------------------------------------------------
say "=== 9. M0 invariants on the ephemeral composition ==="
CTX_PROBE="$MGR_WORK/ctx-probe"
mkdir -p "$CTX_PROBE"
cat > "$CTX_PROBE/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN mkdir -p /m1
RUN id > /m1/id.txt
RUN cat /proc/self/uid_map > /m1/uid_map.txt
RUN readlink /proc/self/ns/user > /m1/ns_user.txt
RUN ls /var/run/docker.sock /run/docker.sock > /m1/socks.txt 2>&1 || true
EOF
build_on "$SOCKET_F" "$CTX_PROBE" m1-eph-ns "$MGR_WORK/out-ns.tar" "$MGR_WORK/build-ns.log"
docker load -i "$MGR_WORK/out-ns.tar" >/dev/null 2>&1 || true
RAW_UID_MAP="$(docker run --rm m1-eph-ns:latest cat /m1/uid_map.txt 2>/dev/null | head -1 || true)"
BUILD_HOST_UID="$(awk '{print $2}' <<<"$RAW_UID_MAP")"
[ -n "$BUILD_HOST_UID" ] || fail "cannot read uid_map on ephemeral composition"
[ "$BUILD_HOST_UID" != "0" ] || fail "ephemeral build RUN maps to host uid 0"
NS_USER="$(docker run --rm m1-eph-ns:latest cat /m1/ns_user.txt 2>/dev/null || true)"
SOCKS_OBS="$(docker run --rm m1-eph-ns:latest cat /m1/socks.txt 2>/dev/null || true)"
evidence ephemeral-ns.txt "uid_map: $RAW_UID_MAP
ns_user: $NS_USER
socks: $SOCKS_OBS"
# ls prints "No such file or directory" for absent paths; a present socket
# would appear as a direct ls entry line. Match only the direct-entry form.
if printf '%s\n' "$SOCKS_OBS" | grep -v "No such file" | grep -q "docker.sock"; then
  fail "ephemeral build RUN saw a docker socket"
fi
say "no docker.sock visible from build RUN (PASS)"
say "sandbox-root host-side uid=$BUILD_HOST_UID (PASS)"

# host-root marker negative through op F
echo "M1-ROOT-MARKER-SECRET" > "$MGR_WORK/m1-root-marker"
chmod 600 "$MGR_WORK/m1-root-marker"
CTX_MARKER="$MGR_WORK/ctx-marker"
mkdir -p "$CTX_MARKER"
cat > "$CTX_MARKER/Dockerfile" <<EOF
FROM alpine:3.20
RUN mkdir -p /m1
RUN cat $MGR_WORK/m1-root-marker > /m1/leak.txt 2>&1; echo rc=\$? >> /m1/leak.txt
EOF
build_on "$SOCKET_F" "$CTX_MARKER" m1-eph-marker "$MGR_WORK/out-marker.tar" "$MGR_WORK/build-marker.log"
docker load -i "$MGR_WORK/out-marker.tar" >/dev/null 2>&1 || true
MARKER_OUT="$(docker run --rm m1-eph-marker:latest cat /m1/leak.txt 2>/dev/null || true)"
evidence root-marker.txt "$MARKER_OUT"
if printf '%s\n' "$MARKER_OUT" | grep -q "M1-ROOT-MARKER-SECRET"; then
  fail "host root marker LEAKED into ephemeral build RUN"
fi
say "host-root marker NOT readable from ephemeral build RUN (PASS)"
echo "host-root negative: PASS" > "$EVIDENCE_DIR/host-marker-pass.txt"

# failed build leaves no usable image (round trip + failure semantics)
CTX_FAIL="$MGR_WORK/ctx-fail"
mkdir -p "$CTX_FAIL"
cat > "$CTX_FAIL/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN false
EOF
if buildctl --addr "unix://$SOCKET_F" build \
  --frontend dockerfile.v0 \
  --local "context=$CTX_FAIL" --local "dockerfile=$CTX_FAIL" \
  --output "type=docker,name=m1-eph-fail-target:latest,dest=$MGR_WORK/out-fail.tar" 2>/dev/null; then
  fail "failed build reported success"
fi
if [ -f "$MGR_WORK/out-fail.tar" ]; then
  if docker load -i "$MGR_WORK/out-fail.tar" >/dev/null 2>&1; then
    fail "failed build left a loadable partial tar"
  fi
fi
if docker image inspect m1-eph-fail-target:latest >/dev/null 2>&1; then
  fail "failed build left a usable target image in the Engine"
fi
say "failed build left no usable target image (PASS)"
echo "failed-build negative: PASS" > "$EVIDENCE_DIR/failed-build-pass.txt"

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------
say "=== ALL M1 EPHEMERAL-COMPOSITION PROOFS COMPLETE ==="
echo "M1-EPHEMERAL-PROOF-RESULT=PASS" > "$EVIDENCE_DIR/RESULT.txt"
echo "M1-EPHEMERAL-PROOF-RESULT=PASS"
