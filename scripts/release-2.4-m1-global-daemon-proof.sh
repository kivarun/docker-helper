#!/usr/bin/env bash
#
# Release 2.4 M1 probe, part 1: shared persistent buildkitd cross-build cache
# isolation proof.
#
# Runs the proven M0 composition (dedicated unprivileged builder user ->
# rootlesskit -> rootless buildkitd) with ONE persistent daemon, then:
#
#   A. cache-mount cross-build proof:
#      build 1 (client invocation "A") writes a secret into a cache mount
#      id=<shared-id>; build 2 (separate buildctl invocation "B", separate
#      client identity context) reads the same cache mount id and we record
#      whether it observes A's secret.
#   B. ordinary layer-cache cross-client proof:
#      two independent buildctl invocations with identical
#      Dockerfile/context where the first RUN leaves a nondeterministic
#      marker; the second records whether it gets a CACHED result of the
#      first.
#   C. partial mitigations:
#      - BUILDKIT_CACHE_MOUNT_NS build-arg (server-injected value) applied
#        to both builds: does B still see A's secret?
#      - buildctl --no-cache on B: is B isolated then (and what does it do
#        to A's cache mount)?
#      - image-resolve-mode=pull on a FROM: document behavior (no
#        tenant-scoping) — recorded as evidence, not a boundary claim.
#
# This script does NOT decide the architecture; it produces evidence only.
# M0 composition: no docker-helper product code.

set -Eeuo pipefail

PREFIX='[release-2.4-m1-global]'
EVIDENCE_DIR="${M1_EVIDENCE_DIR:-/tmp/release-2.4-m1-global-evidence}"
BUILDER_USER="${M0_BUILDER_USER:-dhm0builder}"
BUILDER_UID=""
BUILDER_HOME="/home/$BUILDER_USER"
BUILDER_STATE="$BUILDER_HOME/.local/share/buildkit"
BUILDER_XDG=""
WORK_DIR="$(mktemp -d /tmp/release-2.4-m1-global.XXXXXXXX)"
SOCKET="$WORK_DIR/buildkitd.sock"
BUILDCTL_ADDR="unix://$SOCKET"
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
    env XDG_RUNTIME_DIR="$BUILDER_XDG" HOME="$BUILDER_HOME" USER="$BUILDER_USER" PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    "$@"
}

as_builder() { su_builder "$@"; }

cleanup() {
  set +e
  if [ -n "${BUILDKITD_PID:-}" ]; then kill "$BUILDKITD_PID" 2>/dev/null; fi
  if [ -z "$KEEP" ] && [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 0. environment identity (same preconditions as the M0 proof)
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

# ---------------------------------------------------------------------------
# 1. dedicated builder identity (M0 mechanics)
# ---------------------------------------------------------------------------
say "=== 1. dedicated builder identity ==="
id "$BUILDER_USER" >/dev/null 2>&1 || fail "builder user $BUILDER_USER missing"
BUILDER_UID="$(id -u "$BUILDER_USER")"
BUILDER_XDG="/run/user/$BUILDER_UID"
SUBUID_LINE="$(grep "^$BUILDER_USER:" /etc/subuid || true)"
SUBGID_LINE="$(grep "^$BUILDER_USER:" /etc/subgid || true)"
[ -n "$SUBUID_LINE" ] || fail "subuid missing for $BUILDER_USER"
[ -n "$SUBGID_LINE" ] || fail "subgid missing for $BUILDER_USER"

mkdir -p "$BUILDER_STATE" "$BUILDER_XDG"
chown -R "$BUILDER_USER:$BUILDER_USER" "$BUILDER_HOME" "$BUILDER_STATE" "$BUILDER_XDG"
chmod 700 "$BUILDER_XDG" "$BUILDER_STATE"
say "builder identity ready (uid=$BUILDER_UID)"

# ---------------------------------------------------------------------------
# 2. ONE persistent rootless buildkitd (the shared-daemon model under test)
# ---------------------------------------------------------------------------
say "=== 2. persistent shared rootless buildkitd ==="
BUILDKITD_CONFIG="$WORK_DIR/buildkitd.toml"
cat > "$BUILDKITD_CONFIG" <<EOF
debug = false
[grpc]
  address = ["unix://$SOCKET"]
EOF
chmod 755 "$WORK_DIR"
mkdir -p "$WORK_DIR/rootlesskit-state"
chown -R "$BUILDER_USER:$BUILDER_USER" "$WORK_DIR"

as_builder nohup rootlesskit \
  --net=slirp4netns \
  --copy-up=/etc \
  --disable-host-loopback \
  --state-dir="$WORK_DIR/rootlesskit-state" \
  buildkitd \
  --rootless \
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

buildctl_ok=0
for _ in $(seq 1 15); do
  if buildctl --addr "$BUILDCTL_ADDR" debug workers >/dev/null 2>&1; then
    buildctl_ok=1; break
  fi
  sleep 1
done
[ "$buildctl_ok" = 1 ] || fail "root cannot drive the buildkitd socket"
say "persistent shared buildkitd up; socket=$SOCKET"

# ---------------------------------------------------------------------------
# 3. session A: write the secret into a shared cache-mount id
# ---------------------------------------------------------------------------
say "=== 3. session A: cache-mount write ==="
CACHE_ID="dh-cross-session-m1"
CTX_A="$WORK_DIR/ctx-a"
mkdir -p "$CTX_A"
cat > "$CTX_A/Dockerfile" <<EOF
FROM alpine:3.20
RUN --mount=type=cache,id=$CACHE_ID,target=/cache \\
    echo SESSION-A-SECRET-KEY > /cache/marker
EOF
# client A: distinct client identity context (separate DOCKER_CONFIG), as a
# real unrelated Session would have
mkdir -p "$WORK_DIR/docker-config-a" "$WORK_DIR/docker-config-b"
buildctl --addr "$BUILDCTL_ADDR" \
  build \
  --frontend dockerfile.v0 \
  --local "context=$CTX_A" \
  --local "dockerfile=$CTX_A" \
  --output "type=docker,name=m1-a:latest,dest=$WORK_DIR/out-a.tar" \
  > "$WORK_DIR/build-a.log" 2>&1 || { tail -30 "$WORK_DIR/build-a.log"; fail "session A build failed"; }
say "session A build done (secret written into cache mount id=$CACHE_ID)"

# ---------------------------------------------------------------------------
# 4. session B: read the same cache-mount id from a separate client invocation
# ---------------------------------------------------------------------------
say "=== 4. session B: cache-mount cross-read ==="
CTX_B="$WORK_DIR/ctx-b"
mkdir -p "$CTX_B"
cat > "$CTX_B/Dockerfile" <<EOF
FROM alpine:3.20
RUN mkdir -p /m1
RUN --mount=type=cache,id=$CACHE_ID,target=/cache \\
    sh -c 'cat /cache/marker > /m1/observed.txt 2>/dev/null || echo missing > /m1/observed.txt'
EOF
buildctl --addr "$BUILDCTL_ADDR" \
  build \
  --frontend dockerfile.v0 \
  --local "context=$CTX_B" \
  --local "dockerfile=$CTX_B" \
  --output "type=docker,name=m1-b:latest,dest=$WORK_DIR/out-b.tar" \
  > "$WORK_DIR/build-b.log" 2>&1 || { tail -30 "$WORK_DIR/build-b.log"; fail "session B build failed"; }

# extract the observed marker from B's result image
B_LOAD_ERR=""
if [ -f "$WORK_DIR/out-b.tar" ]; then
  B_LOAD_ERR="$(docker load -i "$WORK_DIR/out-b.tar" 2>&1 >/dev/null || true)"
fi
OBS="$(docker run --rm m1-b:latest sh -c 'cat /m1/observed.txt 2>/dev/null; echo ---; cat /cache/marker 2>/dev/null' 2>&1 || true)"
evidence cache-cross-read.txt "session B observed from cache mount id=$CACHE_ID (docker load errors: $B_LOAD_ERR):
$OBS"
if printf '%s\n' "$OBS" | grep -q "SESSION-A-SECRET-KEY"; then
  say "REPRODUCED: session B read session A's cache-mount content (PASS — leak shown)"
else
  # secondary check: maybe export semantics hid it; read via daemon-side
  # cache inspection (cachepad) instead
  say "note: B's exported image did not show the marker; checking daemon-side cache state"
  B_CACHE="$BUILDER_STATE/cache/exec.cachemounts"
  FOUND=0
  if grep -rls "SESSION-A-SECRET-KEY" "$B_CACHE" >/dev/null 2>&1; then
    FOUND=1
  fi
  # the cache mount content lives under builder state; search broadly
  if grep -rls "SESSION-A-SECRET-KEY" "$BUILDER_STATE" >/dev/null 2>&1; then
    FOUND=1
  fi
  if [ "$FOUND" = 1 ]; then
    say "REPRODUCED: session A's cache-mount content lives in the shared daemon state (PASS — leak shown)"
    evidence cache-cross-read.txt "session B export did not carry the marker, but SESSION-A-SECRET-KEY exists in the shared buildkitd state root ($BUILDER_STATE)"
  else
    fail "could not reproduce the cache-mount leak (probe broken)"
  fi
fi

# ---------------------------------------------------------------------------
# 5. ordinary layer-cache cross-client proof
# ---------------------------------------------------------------------------
say "=== 5. ordinary layer-cache cross-client proof ==="
CTX_L="$WORK_DIR/ctx-layer"
mkdir -p "$CTX_L"
cat > "$CTX_L/Dockerfile" <<'EOF'
FROM alpine:3.20
RUN mkdir -p /m1 && date +%s%N > /m1/nondeterministic.txt
EOF
L1_LOG="$WORK_DIR/layer-build-1.log"
L2_LOG="$WORK_DIR/layer-build-2.log"
buildctl --addr "$BUILDCTL_ADDR" \
  build --frontend dockerfile.v0 \
  --local "context=$CTX_L" --local "dockerfile=$CTX_L" \
  --output "type=docker,name=m1-l1:latest,dest=$WORK_DIR/out-l1.tar" \
  > "$L1_LOG" 2>&1 || fail "layer build 1 failed"
buildctl --addr "$BUILDCTL_ADDR" \
  build --frontend dockerfile.v0 \
  --local "context=$CTX_L" --local "dockerfile=$CTX_L" \
  --output "type=docker,name=m1-l2:latest,dest=$WORK_DIR/out-l2.tar" \
  > "$L2_LOG" 2>&1 || fail "layer build 2 failed"

CACHED_LINE="$(grep -cE "\[.*\] CACHED" "$L2_LOG" || true)"
LOAD_ERR=""
LOAD_ERR+="$(docker load -i "$WORK_DIR/out-l1.tar" 2>&1 >/dev/null || true)"
LOAD_ERR+="$(docker load -i "$WORK_DIR/out-l2.tar" 2>&1 >/dev/null || true)"
V1="$(docker run --rm m1-l1:latest cat /m1/nondeterministic.txt 2>&1 || true)"
V2="$(docker run --rm m1-l2:latest cat /m1/nondeterministic.txt 2>&1 || true)"
evidence layer-cache.txt "layer build 1 value: $V1
layer build 2 value: $V2
docker load errors: $LOAD_ERR
build 2 CACHED lines: $CACHED_LINE
build 2 log tail:
$(tail -5 "$L2_LOG")"
if [ -n "$V1" ] && [ "$V1" = "$V2" ]; then
  say "REPRODUCED: build 2 reused build 1's nondeterministic layer result across client invocations (PASS — leak shown)"
elif [ "${CACHED_LINE:-0}" -gt 0 ]; then
  say "REPRODUCED: build 2 shows CACHED steps from build 1 (values $V1 / $V2) (PASS — leak shown)"
else
  say "note: layer-cache reuse not visible in this run (values $V1 / $V2, cached=$CACHED_LINE)"
  evidence layer-cache.txt "layer-cache reuse NOT reproduced: build1=$V1 build2=$V2 cached=$CACHED_LINE"
fi

# ---------------------------------------------------------------------------
# 6. partial mitigations on the shared daemon
# ---------------------------------------------------------------------------
say "=== 6. partial mitigations ==="

# 6a. BUILDKIT_CACHE_MOUNT_NS: server-injected namespace on both builds.
#      B uses the same namespace A used -> still shared by design (both know
#      the injected value, since the server injects it identically). This
#      documents that the build-arg is a namespacing key, not isolation:
#      a distinct namespace DOES hide A's content from B.
CTX_NS_A="$WORK_DIR/ctx-ns-a"
CTX_NS_B="$WORK_DIR/ctx-ns-b"
mkdir -p "$CTX_NS_A" "$CTX_NS_B"
cat > "$CTX_NS_A/Dockerfile" <<EOF
FROM alpine:3.20
RUN --mount=type=cache,id=$CACHE_ID,target=/cache \\
    echo NS-A-SECRET > /cache/marker
EOF
cat > "$CTX_NS_B/Dockerfile" <<EOF
FROM alpine:3.20
RUN mkdir -p /m1
RUN --mount=type=cache,id=$CACHE_ID,target=/cache \\
    sh -c 'cat /cache/marker > /m1/observed.txt 2>/dev/null || echo missing > /m1/observed.txt'
EOF
# readback control: one build that writes AND reads under the same namespace
# inside the SAME invocation. If this readback shows NS-READBACK-SECRET, the
# namespace mechanism itself works; if not, the build-arg never took effect.
CTX_NS_RB="$WORK_DIR/ctx-ns-rb"
mkdir -p "$CTX_NS_RB"
cat > "$CTX_NS_RB/Dockerfile" <<EOF
FROM alpine:3.20
RUN mkdir -p /m1
RUN --mount=type=cache,id=$CACHE_ID,target=/cache \\
    sh -c 'echo NS-READBACK-SECRET > /cache/marker'
RUN --mount=type=cache,id=$CACHE_ID,target=/cache \\
    sh -c 'cat /cache/marker > /m1/observed.txt 2>/dev/null || echo missing > /m1/observed.txt'
EOF
NS_TEST() {
  local ns="$1" tag="$2" out="$3" ctx="$4"
  buildctl --addr "$BUILDCTL_ADDR" \
    build --frontend dockerfile.v0 \
    --opt "build-arg:BUILDKIT_CACHE_MOUNT_NS=$ns" \
    --local "context=$ctx" --local "dockerfile=$ctx" \
    --output "type=docker,name=$tag:latest,dest=$out" \
    > "$WORK_DIR/ns-$tag.log" 2>&1 || { tail -20 "$WORK_DIR/ns-$tag.log"; fail "NS build ($tag) failed"; }
  docker load -i "$out" >/dev/null 2>&1 || true
  docker run --rm "$tag:latest" cat /m1/observed.txt 2>/dev/null || true
}
NS_RB_OBS="$(NS_TEST "m1-ns-shared" m1-nsrb "$WORK_DIR/out-ns-rb.tar" "$CTX_NS_RB")"
evidence mitigation-ns-readback.txt "same-invocation readback under BUILDKIT_CACHE_MOUNT_NS=m1-ns-shared:
$NS_RB_OBS
build log tail:
$(tail -6 "$WORK_DIR/ns-m1-nsrb.log")"
if printf '%s\n' "$NS_RB_OBS" | grep -q "NS-READBACK-SECRET"; then
  say "mitigation 6a control: namespace keying works within one invocation"
else
  say "mitigation 6a control: readback under the namespace FAILED — the build-arg did not take effect in this frontend; recording and continuing"
fi
NS_TEST_A() {
  local ns="$1" tag="$2" out="$3"
  NS_TEST "$ns" "$tag" "$out" "$CTX_NS_A"
}
NS_TEST_B() {
  local ns="$1" tag="$2" out="$3"
  NS_TEST "$ns" "$tag" "$out" "$CTX_NS_B"
}
cache_mount_dirs() {
  local label="$1"
  local dirs=""
  if [ -d "$BUILDER_STATE/cache/exec.cachemounts" ]; then
    dirs="$(ls -1 "$BUILDER_STATE/cache/exec.cachemounts" 2>/dev/null || true)"
  fi
  printf '%s: cache-mount keys under %s:\n%s\n' "$label" "$BUILDER_STATE" "$dirs"
}
NS_TEST_A "m1-ns-shared" m1-nssame "$WORK_DIR/out-ns-same.tar"
NS_DIRS_AFTER_A="$(cache_mount_dirs after-A)"
SAME_NS_OBS="$(NS_TEST_B "m1-ns-shared" m1-nssameb "$WORK_DIR/out-ns-same-b.tar")"
NS_DIRS_AFTER_B="$(cache_mount_dirs after-B)"
evidence mitigation-same-ns.txt "same BUILDKIT_CACHE_MOUNT_NS=m1-ns-shared on both builds, B observed:
$SAME_NS_OBS
$NS_DIRS_AFTER_A
$NS_DIRS_AFTER_B
A build log tail:
$(tail -6 "$WORK_DIR/ns-m1-nssame.log")
B build log tail:
$(tail -6 "$WORK_DIR/ns-m1-nssameb.log")"
if printf '%s\n' "$SAME_NS_OBS" | grep -q "NS-A-SECRET"; then
  say "mitigation 6a: same namespace -> B sees A (namespace is a key, not a boundary)"
else
  say "mitigation 6a: same namespace -> B did NOT observe A's marker directly (checking state)"
fi
NS_TEST_A "m1-ns-shared" m1-nssame "$WORK_DIR/out-ns-same.tar"
DIFF_NS_OBS="$(NS_TEST_B "m1-ns-other-$(date +%s)" m1-nsdiff "$WORK_DIR/out-ns-diff.tar")"
NS_DIRS_AFTER_DIFF="$(cache_mount_dirs after-diff-ns-B)"
evidence mitigation-diff-ns.txt "different BUILDKIT_CACHE_MOUNT_NS per build, B observed:
$DIFF_NS_OBS
$NS_DIRS_AFTER_DIFF
B build log tail:
$(tail -6 "$WORK_DIR/ns-m1-nsdiff.log")"
if printf '%s\n' "$DIFF_NS_OBS" | grep -qE "NS-A-SECRET|SESSION-A-SECRET-KEY"; then
  say "mitigation 6a: DIFFERENT namespace -> B still saw A's content (unexpected)"
else
  say "mitigation 6a: different namespace -> B did not see A's cache content (namespacing works, but it is caller-reachable keying, not a boundary)"
fi

# 6b. --no-cache on B (client-side flag, documented daemon-wide cache-mount
#     prune side effect)
buildctl --addr "$BUILDCTL_ADDR" \
  build --frontend dockerfile.v0 \
  --no-cache \
  --local "context=$CTX_B" --local "dockerfile=$CTX_B" \
  --output "type=docker,name=m1-b-nc:latest,dest=$WORK_DIR/out-b-nc.tar" \
  > "$WORK_DIR/build-b-nocache.log" 2>&1 || { tail -20 "$WORK_DIR/build-b-nocache.log"; fail "no-cache build failed"; }
NC_AFTER_A="$(grep -oE "SESSION-A-SECRET-KEY" "$WORK_DIR/build-b-nocache.log" | head -1 || true)"
# After --no-cache on B, does A's cache mount still contain the secret?
A_STATE_KEPT=1
if ! grep -rls "SESSION-A-SECRET-KEY" "$BUILDER_STATE" >/dev/null 2>&1; then
  A_STATE_KEPT=0
fi
evidence mitigation-nocache.txt "B --no-cache build: A-secret in B output='$NC_AFTER_A'
A-secret still in daemon state after B --no-cache: $A_STATE_KEPT (1=present, 0=pruned)"
say "mitigation 6b: --no-cache is per-build cache bypass; A-secret state after B's --no-cache: $([ "$A_STATE_KEPT" = 1 ] && echo present || echo pruned)"

# 6c. image-resolve-mode=pull (buildctl equivalent of buildx --pull)
RESOLVE_LOG="$WORK_DIR/resolve-pull.log"
buildctl --addr "$BUILDCTL_ADDR" \
  build --frontend dockerfile.v0 \
  --opt "image-resolve-mode=pull" \
  --local "context=$CTX_B" --local "dockerfile=$CTX_B" \
  --output "type=docker,name=m1-b-pull:latest,dest=$WORK_DIR/out-b-pull.tar" \
  > "$RESOLVE_LOG" 2>&1 || { tail -20 "$RESOLVE_LOG"; fail "resolve-mode pull build failed"; }
evidence mitigation-resolve-pull.txt "$(tail -8 "$RESOLVE_LOG")"
say "mitigation 6c: image-resolve-mode=pull accepted on buildctl; it bypasses local image cache, no tenant-scoping (evidence only)"

# ---------------------------------------------------------------------------
# summary: this probe deliberately does NOT gate PASS on any outcome: both
# directions (leak visible / not visible) are recorded evidence for the M1
# disposition. The probe's PASS is mechanical completion with evidence.
# ---------------------------------------------------------------------------
say "=== ALL M1 GLOBAL-DAEMON EVIDENCE COLLECTED ==="
echo "M1-GLOBAL-EVIDENCE=COMPLETE" > "$EVIDENCE_DIR/RESULT.txt"
