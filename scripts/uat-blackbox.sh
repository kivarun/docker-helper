#!/usr/bin/env bash
#
# uat-blackbox.sh — black-box UAT for docker-helper on a full supported Linux
# VM with a real Docker daemon and an active MAC adapter (AppArmor by default).
#
# The GitHub workflow runs this script as root:
#     sudo -E env "PATH=$PATH" scripts/uat-blackbox.sh
# It is also runnable manually on any supported Linux VM with a rootful Docker
# daemon and the selected platform/MAC adapter.
#
# Coverage (generic, independent of platform, artifact type and MAC adapter):
#   1. preflight: Docker, systemd, versions
#   2. artifact production + system-mode install + confinement
#   3. operator surface: principal + credential; admin and principal sessions
#   4. pull + run (uid/gid/workdir + container exit-code propagation)
#   5. workspace mounts: RW write, RO read, RO write rejected, no host leak
#   6. docker build via docker-helper (Buildx path)
#   7. self-contained trusted-CA E2E: ephemeral CA + local HTTPS endpoint
#   8. MAC audit check of fresh confinement denies (allowlist)
#
# All docker-helper operations go through the docker-helper CLI. The real
# Docker CLI is used ONLY for the preflight reachability check and to discover
# the Docker bridge gateway for the HTTPS harness — never as a substitute for
# a docker-helper operation under test.
#
# Four pluggable adapters are loaded below, mirroring the architecture:
#
#   platform adapter -> scripts/uat-platform-<name>.sh  (UAT_PLATFORM, default ubuntu)
#                        owns the narrow set of things that differ between
#                        distros: identity preflight, native dependency
#                        installation, and platform defaults for the runner
#                        principal/allowed root. Choices: ubuntu, opensuse.
#        |
#        v
#   artifact adapter -> scripts/uat-artifact-<name>.sh  (UAT_INSTALL, default deb)
#                        owns artifact PRODUCTION when the artifact is built
#                        locally on the UAT host: one upstream build step
#                        yielding an exact, immutable artifact whose path and
#                        SHA-256 (ARTIFACT_PATH / ARTIFACT_SHA256) are recorded.
#                        Choices: deb (Debian), tarball (release tar.gz),
#                        rpm (RPM package).
#                        When UAT_ARTIFACT_PATH is set, production is skipped:
#                        the caller hands over an externally produced immutable
#                        artifact directly to the install boundary (see below).
#        |
#        v  exact immutable artifact
#   install adapter  -> scripts/uat-install-<name>.sh
#                        consumes the recorded artifact (never rebuilds) and
#                        installs it, then proves the installed binary/unit/
#                        profile came from that artifact.
#        |
#        v
#   common system black-box scenario  (this file, phases 3-7)
#        |
#        v
#   MAC adapter       -> scripts/uat-mac-<name>.sh  (UAT_MAC, default apparmor)
#                        owns confinement verification, audit-window tracking,
#                        deny inspection and diagnostics.
#
# The generic scenario is written once and shared by every platform /
# artifact/install / MAC combination, so the Ubuntu and openSUSE UATs run
# identical functional coverage. Platform and MAC stay separate concepts:
# distribution logic is never merged into the MAC adapter, and package-manager
# specifics never enter the common scenario.
#
# Canonical vocabulary: platform (distro), artifact (production),
# install (consumption), MAC (confinement/audit),
# scenario (runtime/authorization/functionality).
#
# Environment overrides:
#   UAT_PLATFORM      platform adapter to exercise (default ubuntu)
#   UAT_INSTALL       artifact+install adapter pair to exercise (default deb)
#   UAT_MAC           MAC adapter to exercise (default apparmor)
#   UAT_VERSION       version string (default 2.0.0-uat)
#   UAT_ALLOWED_ROOT  global allowed root (default: platform-provided)
#   UAT_WORKSPACE     session workspace (default $UAT_ALLOWED_ROOT/uat-workspace)
#   UAT_PRINCIPAL     OS user mapped to the docker-helper principal (default: platform-provided)
#   UAT_TLS_PORT      port for the local HTTPS endpoint (default 8443)
#   UAT_KEEP          if set, skip best-effort cleanup (debugging)
#   UAT_ARTIFACT_PATH if set, use this prebuilt artifact instead of running the
#                     artifact adapter's production step. The file must exist,
#                     be a regular file, and match UAT_ARTIFACT_SHA256 exactly.
#                     This is the generic artifact-acquisition boundary for
#                     install adapters: an externally produced immutable
#                     artifact is handed directly to the install boundary, so
#                     artifact build prerequisites are NOT checked and
#                     artifact_build is NOT called. ARTIFACT_PATH / ARTIFACT_SHA256
#                     are then set from these inputs and the install adapter
#                     proceeds unchanged.
#   UAT_ARTIFACT_SHA256  required when UAT_ARTIFACT_PATH is set: the expected
#                     SHA-256 of the prebuilt artifact. It is verified strictly
#                     (never recomputed-and-trusted) before install.

set -uo pipefail

VERSION="${UAT_VERSION:-2.0.0-uat}"
TLS_PORT="${UAT_TLS_PORT:-8443}"
KEEP="${UAT_KEEP:-}"
INSTALL="${UAT_INSTALL:-deb}"
MAC="${UAT_MAC:-apparmor}"
PLATFORM="${UAT_PLATFORM:-ubuntu}"
DEBUG="${UAT_DEBUG:-}"
# Prebuilt-artifact mode: when UAT_ARTIFACT_PATH is set, the artifact adapter's
# production step is skipped and an externally produced immutable artifact is
# handed directly to the install boundary. UAT_ARTIFACT_SHA256 is mandatory and
# verified strictly in phase 2 (never recomputed-and-trusted).
UAT_ARTIFACT_PATH_IN="${UAT_ARTIFACT_PATH:-}"
UAT_ARTIFACT_SHA256_IN="${UAT_ARTIFACT_SHA256:-}"
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

# redact_tokens masks bearer-token values (admin/session/credential tokens:
# dht_/dhc_) in a captured stream so they never reach the CI log. Session
# IDs (dhs_) are not bearer secrets and are left intact.
redact_tokens() {
  sed -E \
    -e 's/dht_[A-Za-z0-9_-]+/<redacted-token>/g' \
    -e 's/dhc_[A-Za-z0-9_-]+/<redacted-token>/g'
}

# Load the platform adapter FIRST: it provides distro identity, dependency
# installation, and the platform defaults for principal/allowed-root.
PLATFORM_FILE="$REPO_ROOT/scripts/uat-platform-$PLATFORM.sh"
if [ ! -f "$PLATFORM_FILE" ]; then
  echo "error: unknown UAT platform adapter '$PLATFORM' (no $PLATFORM_FILE)" >&2
  exit 1
fi
# shellcheck source=scripts/uat-platform-ubuntu.sh
source "$PLATFORM_FILE"  # uat-platform-$PLATFORM.sh (ubuntu or opensuse)
for fn in platform_name platform_preflight platform_install_deps \
  platform_default_principal platform_default_allowed_root; do
  if ! declare -F "$fn" >/dev/null 2>&1; then
    echo "error: UAT platform adapter '$PLATFORM' is missing required function $fn" >&2
    exit 1
  fi
done

# install-deps mode: provision the build/test dependencies for this platform
# and exit. Used by the workflow as a distinct provisioning step (run as root).
# Exit status is propagated so dependency failure cannot return success.
if [ "${1:-}" = "install-deps" ]; then
  platform_install_deps
  exit $?
fi

# Platform-aware defaults: an explicit env value wins; otherwise use the
# platform-provided default. Validate that the principal account exists,
# reject root, and validate that the allowed root exists.
if [ -n "${UAT_PRINCIPAL:-}" ]; then
  PRINCIPAL="$UAT_PRINCIPAL"
else
  PRINCIPAL="$(platform_default_principal)"
fi
# Fail-fast: the selected principal must exist as an OS account.
if ! getent passwd "$PRINCIPAL" >/dev/null 2>&1; then
  echo "error: UAT principal '$PRINCIPAL' does not exist" >&2
  exit 1
fi
# Fail-fast: the principal must not be root.
if [ "$PRINCIPAL" = "root" ]; then
  echo "error: UAT_PRINCIPAL resolved to root; this is not allowed" >&2
  exit 1
fi
if [ -n "${UAT_ALLOWED_ROOT:-}" ]; then
  ALLOWED_ROOT="$UAT_ALLOWED_ROOT"
else
  ALLOWED_ROOT="$(platform_default_allowed_root "$PRINCIPAL")"
fi
if [ ! -d "$ALLOWED_ROOT" ]; then
  echo "error: allowed root '$ALLOWED_ROOT' does not exist" >&2
  exit 1
fi
WS="${UAT_WORKSPACE:-${ALLOWED_ROOT}/uat-workspace}"

# Load the MAC adapter.
MAC_FILE="$REPO_ROOT/scripts/uat-mac-$MAC.sh"
if [ ! -f "$MAC_FILE" ]; then
  echo "error: unknown UAT MAC adapter '$MAC' (no $MAC_FILE)" >&2
  exit 1
fi
# shellcheck source=scripts/uat-mac-apparmor.sh
source "$MAC_FILE"

# Every MAC adapter must implement the contract below. Verify it now so a
# misbehaving adapter fails loudly instead of deep inside a phase.
for fn in mac_name mac_audit_start mac_preflight mac_reset_policy \
  mac_verify_confinement mac_audit_check mac_diagnostics; do
  if ! declare -F "$fn" >/dev/null 2>&1; then
    echo "error: UAT MAC adapter '$MAC' is missing required function $fn" >&2
    exit 1
  fi
done

# Load the artifact adapter (production only).
ARTIFACT_FILE="$REPO_ROOT/scripts/uat-artifact-$INSTALL.sh"
if [ ! -f "$ARTIFACT_FILE" ]; then
  echo "error: unknown UAT artifact adapter '$INSTALL' (no $ARTIFACT_FILE)" >&2
  exit 1
fi
# shellcheck source=scripts/uat-artifact-deb.sh
source "$ARTIFACT_FILE"  # uat-artifact-$INSTALL.sh (deb or tarball)
for fn in artifact_name artifact_preflight artifact_build; do
  if ! declare -F "$fn" >/dev/null 2>&1; then
    echo "error: UAT artifact adapter '$INSTALL' is missing required function $fn" >&2
    exit 1
  fi
done

# Load the install adapter (consumption only).
INSTALL_FILE="$REPO_ROOT/scripts/uat-install-$INSTALL.sh"
if [ ! -f "$INSTALL_FILE" ]; then
  echo "error: unknown UAT install adapter '$INSTALL' (no $INSTALL_FILE)" >&2
  exit 1
fi
# shellcheck source=scripts/uat-install-deb.sh
source "$INSTALL_FILE"  # uat-install-$INSTALL.sh (deb or tarball)
for fn in install_name install_preflight install_apply \
  install_verify_artifacts install_verify_version; do
  if ! declare -F "$fn" >/dev/null 2>&1; then
    echo "error: UAT install adapter '$INSTALL' is missing required function $fn" >&2
    exit 1
  fi
done

# The MAC adapter records its audit-window start BEFORE any docker-helper
# activity so that only fresh confinement events from this UAT run are
# inspected.
mac_audit_start

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

# fail_uat_status is like fail_uat but exits with a caller-supplied status so a
# failed sub-command's exit status is preserved (used by install adapters).
fail_uat_status() {
  local msg="$1" status="$2"
  printf '\n[UAT] FAILED: %s (status %s)\n' "$msg" "$status" >&2
  print_diagnostics
  exit "$status"
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
  echo "--- MAC diagnostics ($(mac_name)) ---"
  mac_diagnostics
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

info "docker:       $(docker --version 2>/dev/null || true)"
info "systemd:      $(systemctl --version 2>/dev/null | head -1 || true)"
info "kernel:       $(uname -r)"
info "distro:       $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || true)"
info "platform:     $(platform_name)"
info "install:      $(install_name)"
info "mac:          $(mac_name)"

# Platform adapter identity/distro preflight.
platform_preflight

# MAC adapter availability (AppArmor LSM enabled, parser present, ...).
mac_preflight

# Artifact adapter prerequisites (build tooling for this artifact type). In
# prebuilt-artifact mode these are not needed: the artifact is produced
# externally and handed straight to the install boundary.
if [ -z "$UAT_ARTIFACT_PATH_IN" ]; then
  artifact_preflight
fi

# Install adapter prerequisites (install-time tooling).
install_preflight

# ==============================================================================
# Phase 2: artifact production + system-mode installation + confinement
# ==============================================================================

say "phase 2: produce + install via $(install_name)"

# Idempotency for re-runs on a persistent VM: stop/disable any prior service,
# unload any previously loaded shipped policy, and remove docker-helper-owned
# state so init has a clean slate. This reset is common to every case.
systemctl stop docker-helper.service >/dev/null 2>&1 || true
systemctl disable docker-helper.service >/dev/null 2>&1 || true
mac_reset_policy
rm -rf /etc/docker-helper /var/lib/docker-helper /run/docker-helper

# Artifact production is a DISTINCT phase: build once, record the exact
# immutable artifact (path + SHA-256), then hand it to the install adapter.
# In prebuilt-artifact mode production is skipped entirely: the caller's
# externally produced artifact (path + expected SHA-256) is validated strictly
# and recorded for the install adapter. Both paths land on the same exact
# artifact boundary (ARTIFACT_PATH / ARTIFACT_SHA256) that install consumes.
if [ -n "$UAT_ARTIFACT_PATH_IN" ]; then
  say "phase 2: use prebuilt artifact for $(install_name)"
  [ -n "$UAT_ARTIFACT_SHA256_IN" ] \
    || fail_uat "UAT_ARTIFACT_SHA256 is required when UAT_ARTIFACT_PATH is set"
  [ -f "$UAT_ARTIFACT_PATH_IN" ] \
    || fail_uat "UAT_ARTIFACT_PATH is not a regular file: $UAT_ARTIFACT_PATH_IN"
  now_sha="$(sha256sum "$UAT_ARTIFACT_PATH_IN" | awk '{print $1}')"
  [ "$now_sha" = "$UAT_ARTIFACT_SHA256_IN" ] \
    || fail_uat "prebuilt artifact SHA-256 mismatch (expected $UAT_ARTIFACT_SHA256_IN, got $now_sha)"
  ARTIFACT_PATH="$UAT_ARTIFACT_PATH_IN"
  ARTIFACT_SHA256="$UAT_ARTIFACT_SHA256_IN"
  info "prebuilt artifact: $ARTIFACT_PATH"
  info "sha256 (verified): $ARTIFACT_SHA256"
else
  say "phase 2: artifact production via $(artifact_name)"
  artifact_build
fi

# Installation consumes the exact recorded artifact (never rebuilds it).
install_apply

# The service must be active AND confined by the MAC adapter, using the
# install-adapter-installed binary/policy/unit.
systemctl is-active --quiet docker-helper.service || fail_uat "docker-helper service is not active"
DH_PID="$(systemctl show -p MainPID --value docker-helper.service)"
[ -n "$DH_PID" ] && [ "$DH_PID" != "0" ] || fail_uat "daemon MainPID is empty/zero"

EXE="$(readlink -f "/proc/$DH_PID/exe" 2>/dev/null || true)"
[ "$EXE" = "/usr/bin/docker-helper" ] \
  || fail_uat "daemon binary is not the installed /usr/bin/docker-helper: got '$EXE'"

# Prove the installed binary/unit/profile came from this install path (for
# tarball: the extracted bundle, with no package-manager involvement).
install_verify_artifacts
install_verify_version

# MAC-specific confinement check (same profile name, same enforce mode).
mac_verify_confinement "$DH_PID"

info "service active: pid=$DH_PID binary=$EXE install=$(install_name)"

# The daemon binds its unix API socket after systemd reports the unit active
# (and after the startup sweep); `systemctl is-active` alone is not a readiness
# oracle, so the first API call in phase 3 can race the socket bind. Wait
# (bounded, short interval) for the actual condition under test — the API
# socket serving GET /health — and fail fast if the service exits/fails. This
# is the same readiness pattern as the group-9 stale-runtime regression fix.
DH_SOCK="/run/docker-helper/docker-helper.sock"
DH_READY=0
for _ in $(seq 1 50); do
  if [ -S "$DH_SOCK" ] && curl --silent --fail --max-time 1 \
      --unix-socket "$DH_SOCK" http://localhost/health >/dev/null 2>&1; then
    DH_READY=1
    break
  fi
  if ! systemctl is-active --quiet docker-helper.service 2>/dev/null; then
    fail_uat "docker-helper.service exited/failed while waiting for the API socket"
  fi
  sleep 0.2
done
[ "$DH_READY" = 1 ] || fail_uat "docker-helper API socket not ready after bounded wait ($DH_SOCK)"

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
# Phase 8: MAC audit check
# ==============================================================================

mac_audit_check

# ==============================================================================
# Summary
# ==============================================================================

say "UAT PASSED"
info "preflight ......................... ok"
info "platform ($(platform_name)) .......... ok"
info "artifact ($(artifact_name)) .......... ok"
info "install ($(install_name)) + confine .. ok"
info "principal/credential + sessions .. ok"
info "pull/run/identity/exit-code ...... ok"
info "workspace mounts ................. ok"
info "docker build ..................... ok"
info "trusted-CA E2E ................... ok"
info "MAC audit ($(mac_name)) .......... ok"

exit 0
