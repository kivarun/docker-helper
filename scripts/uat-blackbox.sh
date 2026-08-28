#!/usr/bin/env bash
#
# uat-blackbox.sh — backend-agnostic black-box UAT for docker-helper on a
# full Ubuntu VM (e.g. a GitHub-hosted ubuntu-24.04 runner) with a real
# Docker daemon and an active MAC backend (AppArmor by default).
#
# The GitHub workflow runs this script as root:
#     sudo -E env "PATH=$PATH" scripts/uat-blackbox.sh
# It is also runnable manually on any Ubuntu VM with a rootful Docker daemon.
#
# Coverage (generic, backend-independent):
#   1. preflight: Docker, systemd, versions
#   2. package build + system-mode install
#   3. operator surface: principal + credential; admin and principal sessions
#   4. pull + run (uid/gid/workdir + container exit-code propagation)
#   5. workspace mounts: RW write, RO read, RO write rejected, no host leak
#   6. docker build via docker-helper (Buildx path)
#   7. self-contained trusted-CA E2E: ephemeral CA + local HTTPS endpoint
#   8. backend audit check of fresh confinement denies (allowlist)
#
# All docker-helper operations go through the docker-helper CLI. The real
# Docker CLI is used ONLY for the preflight reachability check and to discover
# the Docker bridge gateway for the HTTPS harness — never as a substitute for
# a docker-helper operation under test.
#
# MAC-backend orchestration lives in scripts/uat-backend-<name>.sh (selected
# by UAT_BACKEND, default apparmor). That layer owns backend-specific
# preflight, confinement verification, audit-window tracking, deny inspection
# and diagnostics; this core is backend-agnostic.
#
# Environment overrides:
#   UAT_VERSION       package version string (default 2.0.0-uat)
#   UAT_ALLOWED_ROOT  global allowed root (default /home/runner)
#   UAT_WORKSPACE     session workspace (default $UAT_ALLOWED_ROOT/uat-workspace)
#   UAT_PRINCIPAL     OS user mapped to the docker-helper principal (default runner)
#   UAT_TLS_PORT      port for the local HTTPS endpoint (default 8443)
#   UAT_KEEP          if set, skip best-effort cleanup (debugging)
#   UAT_BACKEND       MAC backend to exercise (default apparmor)

set -uo pipefail

VERSION="${UAT_VERSION:-2.0.0-uat}"
ALLOWED_ROOT="${UAT_ALLOWED_ROOT:-/home/runner}"
WS="${UAT_WORKSPACE:-${ALLOWED_ROOT}/uat-workspace}"
PRINCIPAL="${UAT_PRINCIPAL:-runner}"
TLS_PORT="${UAT_TLS_PORT:-8443}"
KEEP="${UAT_KEEP:-}"
BACKEND="${UAT_BACKEND:-apparmor}"
DEBUG="${UAT_DEBUG:-}"
if [ -n "$DEBUG" ]; then
  # Verbose command tracing. set -v (NOT set -x) is used deliberately: -x
  # echoes expanded command-substitution values and would leak session/admin/
  # credential tokens into the workflow log. -v echoes only the literal input
  # lines, which contain no token values.
  set -v
fi

# Repo root: script lives in scripts/.
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)" || exit 1
cd "$REPO_ROOT" || exit 1

say()  { printf '\n[UAT] %s\n' "$*"; }
info() { printf '[UAT] %s\n' "$*"; }

# Load the MAC backend layer.
BACKEND_FILE="$REPO_ROOT/scripts/uat-backend-$BACKEND.sh"
if [ ! -f "$BACKEND_FILE" ]; then
  echo "error: unknown UAT backend '$BACKEND' (no $BACKEND_FILE)" >&2
  exit 1
fi
# shellcheck source=scripts/uat-backend-apparmor.sh
source "$BACKEND_FILE"

# Every backend must implement the contract below. Verify it now so a
# misbehaving backend fails loudly instead of deep inside a phase.
for fn in backend_name backend_audit_start backend_preflight \
  backend_reset_policy backend_verify_policy_packaged backend_verify_confinement \
  backend_audit_check backend_diagnostics; do
  if ! declare -F "$fn" >/dev/null 2>&1; then
    echo "error: UAT backend '$BACKEND' is missing required function $fn" >&2
    exit 1
  fi
done

# The backend records its audit-window start BEFORE any docker-helper activity
# so that only fresh confinement events from this UAT run are inspected.
backend_audit_start

DIAG_PRINTED=0
SERVER_PID=""
SESSION_ADMIN_ID=""
SESSION_PRINC_ID=""
CRED_FILE="/tmp/uat-credential.token"
unset DOCKER_HELPER_SESSION_TOKEN

# fail_uat prints a labelled failure, dumps diagnostics, exits 1. Diagnostics
# are printed BEFORE the EXIT trap runs cleanup so the original failure is
# never masked and the evidence is still visible.
fail_uat() {
  printf '\n[UAT] FAILED: %s\n' "$1" >&2
  print_diagnostics
  exit 1
}

# ---- Diagnostics ------------------------------------------------------------

print_diagnostics() {
  [ "$DIAG_PRINTED" = 1 ] && return
  DIAG_PRINTED=1
  echo
  echo "================ UAT DIAGNOSTICS ================"
  echo "--- docker-helper version ---"
  /usr/bin/docker-helper version 2>&1 || true
  echo "--- systemctl status docker-helper ---"
  systemctl status docker-helper.service --no-pager 2>&1 || true
  echo "--- journalctl -u docker-helper (last 200) ---"
  journalctl -u docker-helper.service -n 200 --no-pager 2>&1 || true
  echo "--- backend diagnostics ($(backend_name)) ---"
  backend_diagnostics
  echo "================ END DIAGNOSTICS ================"
}

# ---- Cleanup -----------------------------------------------------------------

cleanup() {
  [ -n "$KEEP" ] && return 0
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [ -n "$SESSION_ADMIN_ID" ]; then
    docker-helper session delete --system --id "$SESSION_ADMIN_ID" >/dev/null 2>&1 || true
  fi
  if [ -n "$SESSION_PRINC_ID" ]; then
    docker-helper session delete --system --id "$SESSION_PRINC_ID" >/dev/null 2>&1 || true
  fi
  if [ -n "$PRINCIPAL" ]; then
    docker-helper principal delete --system "$PRINCIPAL" >/dev/null 2>&1 || true
  fi
  rm -f "$CRED_FILE"
  systemctl stop docker-helper.service >/dev/null 2>&1 || true
  systemctl disable docker-helper.service >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ==============================================================================
# Phase 1: environment / preflight
# ==============================================================================

say "phase 1: preflight (Docker, systemd, versions)"
if [ "$(id -u)" -ne 0 ]; then
  echo "error: this UAT must run as root (sudo scripts/uat-blackbox.sh)" >&2
  exit 1
fi
if [ ! -d /run/systemd/system ]; then
  fail_uat "systemd is not running (no /run/systemd/system)"
fi
if ! command -v docker >/dev/null 2>&1; then
  fail_uat "docker CLI not found"
fi
if ! docker info >/dev/null 2>&1; then
  fail_uat "cannot reach the Docker daemon (docker info failed)"
fi
if ! command -v openssl >/dev/null 2>&1; then
  fail_uat "openssl not found"
fi
if ! command -v nfpm >/dev/null 2>&1; then
  fail_uat "nfpm not found on PATH (the workflow must install the pinned nfpm)"
fi

info "docker:       $(docker --version 2>/dev/null || true)"
info "systemd:      $(systemctl --version 2>/dev/null | head -1 || true)"
info "kernel:       $(uname -r)"
info "distro:       $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || true)"

# MAC backend availability (AppArmor LSM enabled, parser present, ...).
backend_preflight

# ==============================================================================
# Phase 2: package build + system-mode installation
# ==============================================================================

say "phase 2: build the Debian package with the repository packaging path"

# Idempotency for re-runs on a persistent VM: stop/disable any prior service,
# unload any previously loaded shipped policy, and remove docker-helper-owned
# state so init has a clean slate.
systemctl stop docker-helper.service >/dev/null 2>&1 || true
systemctl disable docker-helper.service >/dev/null 2>&1 || true
backend_reset_policy
rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper

rm -rf dist
./build-packages.sh "$VERSION" || fail_uat "./build-packages.sh $VERSION failed"

DEB="$(ls dist/*.deb 2>/dev/null | head -1)"
[ -n "$DEB" ] || fail_uat "no .deb produced under dist/"
info "built $DEB"

dpkg -i "$DEB" || fail_uat "dpkg -i failed"

# System init writes config + admin token (root reads admin.token later).
say "phase 2: initialize and start the confined system service"
[ -d "$ALLOWED_ROOT" ] || fail_uat "allowed root does not exist: $ALLOWED_ROOT"
INIT_OUT="$(docker-helper init --allowed-root "$ALLOWED_ROOT" 2>&1)" || {
  printf '%s\n' "$INIT_OUT" | grep -v -E '^Admin token:|^dht_' >&2
  fail_uat "docker-helper init failed"
}

systemctl daemon-reload
systemctl enable --now docker-helper.service || fail_uat "systemctl enable --now docker-helper failed"

# The service must be active AND confined by the backend, using the
# package-installed binary/policy/unit.
systemctl is-active --quiet docker-helper.service || fail_uat "docker-helper service is not active"
DH_PID="$(systemctl show -p MainPID --value docker-helper.service)"
[ -n "$DH_PID" ] && [ "$DH_PID" != "0" ] || fail_uat "daemon MainPID is empty/zero"

EXE="$(readlink -f "/proc/$DH_PID/exe" 2>/dev/null || true)"
[ "$EXE" = "/usr/bin/docker-helper" ] \
  || fail_uat "daemon binary is not the packaged /usr/bin/docker-helper: got '$EXE'"

dpkg -S /usr/bin/docker-helper >/dev/null 2>&1 \
  || fail_uat "/usr/bin/docker-helper is not owned by the docker-helper package"
dpkg -S /usr/lib/systemd/system/docker-helper.service >/dev/null 2>&1 \
  || fail_uat "systemd unit is not owned by the docker-helper package"

# Backend-specific confinement + shipped-policy ownership checks.
backend_verify_policy_packaged
backend_verify_confinement "$DH_PID"

[ "$(/usr/bin/docker-helper version)" = "$VERSION" ] \
  || fail_uat "installed binary version mismatch (expected $VERSION)"

info "service active: pid=$DH_PID binary=$EXE"

# ==============================================================================
# Phase 3: operator surface (principal + credential) and sessions
# ==============================================================================

say "phase 3: principal + credential setup"

# Workspace fixtures. The RW-mount source is owned by the principal so a
# container running as the principal uid can write through the RW mount.
mkdir -p "$WS/rw" "$WS/ro" "$WS/buildctx"
printf 'ro-content\n' > "$WS/ro/readme.txt"
chown -R "$PRINCIPAL:$PRINCIPAL" "$WS/rw"
chmod 0755 "$WS" "$WS/rw" "$WS/ro" "$WS/buildctx"

docker-helper principal create --system "$PRINCIPAL" >/dev/null \
  || fail_uat "principal create failed"
docker-helper principal allowed-root add --system "$PRINCIPAL" "$ALLOWED_ROOT" \
  || fail_uat "principal allowed-root add failed"

CRED_OUT="$(docker-helper credential create --system --name uat-default "$PRINCIPAL")" \
  || fail_uat "credential create failed"
CRED_TOKEN="$(printf '%s\n' "$CRED_OUT" | sed -n 's/^  Token: //p')"
[ -n "$CRED_TOKEN" ] || fail_uat "could not parse credential token"
printf '%s\n' "$CRED_TOKEN" > "$CRED_FILE"
chmod 600 "$CRED_FILE"

# Admin session (operator token -> global scope). Container identity = root.
SESSION_ADMIN_JSON="$(docker-helper session create --system --workspace "$WS" --json)" \
  || fail_uat "admin session create failed"
SESSION_ADMIN_ID="$(printf '%s\n' "$SESSION_ADMIN_JSON" | grep -oP '"id": "\K[^"]+' | head -1)"
SESSION_ADMIN_TOKEN="$(printf '%s\n' "$SESSION_ADMIN_JSON" | grep -oP '"token": "\K[^"]+' | head -1)"
[ -n "$SESSION_ADMIN_ID" ] && [ -n "$SESSION_ADMIN_TOKEN" ] \
  || fail_uat "admin session create returned no id/token"

# Principal session (credential token -> principal scope). Container identity
# = the principal's OS uid/gid. Proves the credential -> session -> run path.
SESSION_PRINC_JSON="$(docker-helper session create --system --token-file "$CRED_FILE" --workspace "$WS" --json)" \
  || fail_uat "principal session create failed"
SESSION_PRINC_ID="$(printf '%s\n' "$SESSION_PRINC_JSON" | grep -oP '"id": "\K[^"]+' | head -1)"
SESSION_PRINC_TOKEN="$(printf '%s\n' "$SESSION_PRINC_JSON" | grep -oP '"token": "\K[^"]+' | head -1)"
[ -n "$SESSION_PRINC_ID" ] && [ -n "$SESSION_PRINC_TOKEN" ] \
  || fail_uat "principal session create returned no id/token"

info "admin session:     $SESSION_ADMIN_ID"
info "principal session: $SESSION_PRINC_ID (principal $PRINCIPAL)"

# ==============================================================================
# Phase 4: basic functionality (pull, run, identity, exit codes)
# ==============================================================================

PUID="$(id -u "$PRINCIPAL")"
PGID="$(id -g "$PRINCIPAL")"

say "phase 4: pull + run via the admin session"
export DOCKER_HELPER_SESSION_TOKEN="$SESSION_ADMIN_TOKEN"
docker-helper pull alpine:3.24 || fail_uat "docker-helper pull alpine:3.24 failed"

# Admin session container runs as root; verify uid/gid/pwd semantics.
BASIC_ADMIN_SCRIPT='test "$(id -u)" = "0" && test "$(id -g)" = "0" && test "$(pwd)" = "/tmp" && echo BASIC-ADMIN-OK'
BASIC_ADMIN_OUT="$(docker-helper run --image alpine:3.24 --workdir /tmp -- sh -ec "$BASIC_ADMIN_SCRIPT")" \
  || fail_uat "admin-session basic run failed"
printf '%s\n' "$BASIC_ADMIN_OUT" | grep -q 'BASIC-ADMIN-OK' \
  || fail_uat "admin-session identity check did not match: $BASIC_ADMIN_OUT"

# Container exit-code propagation (exit 42 must surface as 42).
docker-helper run --image alpine:3.24 -- sh -ec 'exit 42' >/dev/null 2>&1 \
  && fail_uat "expected non-zero container exit code but run succeeded"
EC=0
docker-helper run --image alpine:3.24 -- sh -ec 'exit 42' >/dev/null 2>&1
EC=$?
[ "$EC" = "42" ] || fail_uat "expected container exit code 42, got $EC"

# Principal session container runs as the principal uid/gid.
say "phase 4: run via the principal session (credential path)"
DOCKER_HELPER_SESSION_TOKEN="$SESSION_PRINC_TOKEN" \
  docker-helper run --image alpine:3.24 --workdir /tmp -- sh -ec "test \"\$(id -u)\" = \"$PUID\" && test \"\$(id -g)\" = \"$PGID\" && echo BASIC-PRINC-OK" \
  | grep -q 'BASIC-PRINC-OK' \
  || fail_uat "principal-session identity check failed (expected uid=$PUID gid=$PGID)"

# Switch back to the admin session for the remaining heavy operations.
export DOCKER_HELPER_SESSION_TOKEN="$SESSION_ADMIN_TOKEN"

# ==============================================================================
# Phase 5: workspace mount behavior
# ==============================================================================

say "phase 5: workspace mounts (RW write, RO read, RO write rejected, no host leak)"
MOUNT_SCRIPT='set -e
echo hello > /mnt/rw/written-by-container.txt
test "$(cat /mnt/ro/readme.txt)" = "ro-content"
if echo x > /mnt/ro/forbidden.txt 2>/dev/null; then
  echo "ERROR: RO mount allowed a write" >&2
  exit 1
fi
echo MOUNT-OK'
MOUNT_OUT="$(docker-helper run --image alpine:3.24 --mount rw:/mnt/rw --mount ro:/mnt/ro:ro -- sh -ec "$MOUNT_SCRIPT")" \
  || fail_uat "mount behavior run failed"
printf '%s\n' "$MOUNT_OUT" | grep -q 'MOUNT-OK' \
  || fail_uat "mount behavior did not reach MOUNT-OK: $MOUNT_OUT"

# Host-side assertions: RW write persisted, RO write left no host file.
[ -f "$WS/rw/written-by-container.txt" ] \
  || fail_uat "RW mount did not persist the container write to the host"
[ "$(cat "$WS/rw/written-by-container.txt")" = "hello" ] \
  || fail_uat "RW mount file content mismatch"
[ ! -e "$WS/ro/forbidden.txt" ] \
  || fail_uat "forbidden host-side file was created: $WS/ro/forbidden.txt"
info "mount behavior ok"

# ==============================================================================
# Phase 6: docker build via docker-helper
# ==============================================================================

say "phase 6: docker build via docker-helper (Buildx path)"
cat > "$WS/buildctx/Dockerfile" <<'EOF'
FROM alpine:3.24
RUN apk add --no-cache curl ca-certificates
USER 65534:65534
EOF
chown -R "$PRINCIPAL:$PRINCIPAL" "$WS/buildctx"

docker-helper build --context buildctx --dockerfile Dockerfile --image uat-curl:alpine3.24 \
  || fail_uat "docker-helper build failed"

BUILD_OUT="$(docker-helper run --image uat-curl:alpine3.24 -- sh -ec 'test -x /usr/bin/curl && echo BUILD-IMAGE-OK')" \
  || fail_uat "built image not usable through docker-helper"
printf '%s\n' "$BUILD_OUT" | grep -q 'BUILD-IMAGE-OK' \
  || fail_uat "built image check failed: $BUILD_OUT"

# ==============================================================================
# Phase 7: self-contained trusted-CA E2E
# ==============================================================================

say "phase 7: trusted-CA E2E with ephemeral CA + local HTTPS endpoint"

# Networking arrangement:
#   docker-helper run places the container on the default Docker bridge. A TLS
#   listener bound to 0.0.0.0 on the host is therefore reachable from the
#   container at the bridge gateway IP. We derive the gateway from the host's
#   docker0 address with ip(8) (pure host topology discovery); the docker CLI
#   is not used for any operation under test.
GATEWAY="$(ip -4 addr show docker0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)"
if [ -z "$GATEWAY" ]; then
  GATEWAY="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true)"
fi
[ -n "$GATEWAY" ] || fail_uat "cannot determine the docker bridge gateway"
info "docker bridge gateway: $GATEWAY"

CERT_DIR="/tmp/uat-ca"
rm -rf "$CERT_DIR"
mkdir -p "$CERT_DIR"

# Ephemeral root CA + server cert signed by it, with a SAN matching the
# gateway IP so the container's curl can verify the hostname.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.pem" -days 2 \
  -subj "/CN=UAT-Test-Root-CA" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
  -subj "/CN=uat-test-server" -addext "subjectAltName=IP:$GATEWAY" >/dev/null 2>&1
openssl x509 -req -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/server.pem" -days 2 -copy_extensions copy >/dev/null 2>&1

openssl s_server -accept "$TLS_PORT" \
  -cert "$CERT_DIR/server.pem" -key "$CERT_DIR/server.key" \
  -www -quiet >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1
curl -k -fsS --max-time 5 "https://127.0.0.1:$TLS_PORT/" >/dev/null 2>&1 \
  || fail_uat "local HTTPS endpoint did not become reachable"

# Control: with injection DISABLED (default), the ephemeral CA must be
# rejected. This proves the cert is genuinely untrusted and that the later
# success is caused by docker-helper's injection.
say "phase 7: control run — ephemeral CA must NOT be trusted without injection"
CONTROL_OUT="$(docker-helper run --image uat-curl:alpine3.24 -- sh -ec "curl -fsS https://$GATEWAY:$TLS_PORT/ >/dev/null" 2>&1)"
CONTROL_EC=$?
[ "$CONTROL_EC" -ne 0 ] \
  || fail_uat "control run unexpectedly succeeded (ephemeral CA trusted without injection)"
printf '%s\n' "$CONTROL_OUT" | grep -qi 'certificate' \
  || fail_uat "control failure did not look like a certificate error: $CONTROL_OUT"
info "control ok: TLS to the ephemeral CA failed without injection (exit=$CONTROL_EC)"

# Enable automatic trusted-CA injection via the operator config interface.
say "phase 7: enable trusted CA injection"
docker-helper config set trusted_ca_path "$CERT_DIR/ca.pem" || fail_uat "config set trusted_ca_path failed"
docker-helper config set trusted_ca_injection auto || fail_uat "config set trusted_ca_injection failed"
[ "$(docker-helper config show trusted_ca_injection)" = "auto" ] \
  || fail_uat "trusted_ca_injection is not auto"
[ "$(docker-helper config show trusted_ca_path)" = "$CERT_DIR/ca.pem" ] \
  || fail_uat "trusted_ca_path mismatch"

# Positive: an ordinary TLS request must succeed with zero manual CA flags or
# overrides — success must come only from docker-helper's automatic injection.
say "phase 7: positive run — ordinary TLS request via automatic injection"
TLS_OUT="$(docker-helper run --image uat-curl:alpine3.24 -- sh -ec "curl -fsS https://$GATEWAY:$TLS_PORT/ >/dev/null && echo TLS-OK")" \
  || fail_uat "trusted TLS request failed: $TLS_OUT"
printf '%s\n' "$TLS_OUT" | grep -q 'TLS-OK' \
  || fail_uat "trusted TLS request did not reach TLS-OK: $TLS_OUT"
info "trusted-CA E2E passed (no --cacert/--capath/-k, no manual CA env overrides)"

# ==============================================================================
# Phase 8: backend audit check
# ==============================================================================

backend_audit_check

# ==============================================================================
# Summary
# ==============================================================================

say "UAT PASSED"
info "preflight ......................... ok"
info "package build + install + confine . ok"
info "principal/credential + sessions .. ok"
info "pull/run/identity/exit-code ...... ok"
info "workspace mounts ................. ok"
info "docker build ..................... ok"
info "trusted-CA E2E ................... ok"
info "backend audit ($(backend_name)) .. ok"

exit 0
