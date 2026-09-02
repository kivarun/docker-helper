#!/usr/bin/env bash
#
# uat-selinux-mount-pin-regression.sh — SELinux-specific targeted regression for
# the confirmed Release-2 bug where a recursive `restorecon -R /run/docker-helper`
# in the RPM %post relabelled real workspace inodes through the mount-pin
# aliases under /run/docker-helper/mounts/... to docker_helper_runtime_t.
#
# The production fix is a NON-recursive `restorecon /run/docker-helper`. This
# script proves the fix on a live enforcing SELinux Tumbleweed system: with a
# docker-helper run active (its mount pin present), a real RPM reinstall runs
# the actual %post scriptlet path (semodule -i + restorecon), and the workspace
# inode must keep its device:inode and its user_home_type SELinux label.
#
# It is invoked by scripts/uat-vm-opensuse-selinux.sh INSIDE the guest (as
# root) after the common black-box UAT, which has already stopped the service
# and deleted its sessions/principal but left the installed RPM/system-mode
# state behind. This script uses only the PUBLIC docker-helper CLI to create a
# new principal/session/run — it never invokes Docker directly.
#
# Design notes (behaviour of the shipped RPM %post):
#   * The %post detects an active service and finishes with
#     `systemctl try-restart docker-helper.service`, which restarts the daemon.
#     Daemon shutdown terminates in-flight operations (bounded shutdown
#     lifecycle; see operation.go / container_lifecycle_integration_test.go),
#     so the ORIGINAL long-running operation is expected to be terminated by
#     the reinstall. The CENTRAL regression here is the label integrity: the
#     mount pin is live when %post's `restorecon /run/docker-helper` runs, and
#     the workspace inode (checked through source AND pin) must be unchanged.
#     Real container access after the postinstall is then proven with a fresh
#     docker-helper run against the same workspace (PIN-READ-OK); the fate of
#     the original run is recorded as evidence.
#
# Env inputs:
#   UAT_RPM          path to the exact prebuilt RPM artifact (already in the guest)
#   UAT_RPM_SHA256   expected SHA-256 (producer, verified by the common UAT)
#
# Required output fields (printed verbatim):
#   SOURCE_INODE_BEFORE=  PIN_INODE_BEFORE=  SOURCE_TYPE_BEFORE=  PIN_TYPE_BEFORE=
#   SOURCE_INODE_AFTER=   PIN_INODE_AFTER=   SOURCE_TYPE_AFTER=   PIN_TYPE_AFTER=
#   CONTAINER_CONTEXT=    PIN_READ_OK=       RESULT=

set -uo pipefail

WS="/home/opc/uat-selinux-pin"
PRINCIPAL="opc"
IMAGE="alpine:3.24"
RUN_LOG="/tmp/uat-pin-run.log"

# Minimal shims for the shared MAC adapter (the scenario core is not loaded
# here; the adapter needs only these).
say()  { printf '\n[pin-regression] %s\n' "$*"; }
info() { printf '[pin-regression] %s\n' "$*"; }
fail_uat() {
  printf '\n[pin-regression] FAILED: %s\n' "$1" >&2
  exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-mac-selinux.sh
source "$SCRIPT_DIR/uat-mac-selinux.sh"

UAT_RPM="${UAT_RPM:-}"
UAT_RPM_SHA256="${UAT_RPM_SHA256:-}"
[ -n "$UAT_RPM" ] || { echo "error: UAT_RPM is required" >&2; exit 1; }
[ -f "$UAT_RPM" ] || { echo "error: UAT_RPM is not a file: $UAT_RPM" >&2; exit 1; }
[ -n "$UAT_RPM_SHA256" ] || { echo "error: UAT_RPM_SHA256 is required" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 1; }

# audit window for this regression's docker-helper activity (adapter owner).
mac_audit_start

# selinux_ctx prints the full SELinux context of a path (stat %C, with
# getfilecon fallback for robustness).
selinux_ctx() {
  local c
  c="$(stat -c '%C' "$1" 2>/dev/null || true)"
  if [ -z "$c" ] || [ "$c" = "?" ]; then
    c="$(getfilecon "$1" 2>/dev/null | sed 's/^[^:]*:[[:space:]]*//' || true)"
  fi
  printf '%s' "$c"
}

# classify_run_exit: the background docker-helper run exited before the
# container became provably active (no mount pin appeared, or a pin appeared
# but the container never wrote its active-context proof). If the log shows the
# known Docker-socket blocker (the var_run_t vs container_var_run_t connection
# denial, documented by the A2 micro-proof), the run could never have remained
# active and the mount-pin lifecycle cannot be exercised — classify that case
# BLOCKED/inconclusive (exit 2) rather than FAIL. Any other early exit is a
# genuine regression (exit 1).
classify_run_exit() {
  local logf="$1" when="${2:-before the container became provably active}"
  printf 'error: background run exited %s (log below)\n' "$when" >&2
  cat "$logf" >&2 || true
  if grep -qiE 'permission denied.*docker|docker[^[:space:]]*\.sock|cannot connect to the docker daemon' "$logf" 2>/dev/null; then
    echo "REGRESSION_RESULT=BLOCKED"
    echo "REGRESSION_BLOCKED_REASON=docker socket blocker prevented the docker-helper run from remaining active (known UNRESOLVED; mount-pin lifecycle not exercised)"
    echo "[pin-regression] BLOCKED: docker socket blocker prevented an active operation; mount-pin case is inconclusive" >&2
    exit 2
  fi
  exit 1
}

# attr_current reads /proc/<pid>/attr/current with the trailing NUL byte
# stripped (the kernel writes a NUL terminator, which makes shell tools emit a
# repeated "ignoring null byte in input" warning). Harness-only sanitation; no
# production change.
attr_current() {
  tr -d '\0' < "/proc/$1/attr/current" 2>/dev/null || true
}

say "== SELinux mount-pin / RPM postinstall regression =="
info "workspace: $WS  (intentionally under /home: normal host user_home_type coverage)"
info "RPM:       $UAT_RPM"
info "RPM sha256: $UAT_RPM_SHA256"

# ---------------------------------------------------------------------------
# 1. bring the service back up after the common black-box cleanup
# ---------------------------------------------------------------------------
info "== 1. restart docker-helper service =="
systemctl enable --now docker-helper.service >/dev/null 2>&1 || { echo "error: cannot enable+start docker-helper" >&2; exit 1; }
systemctl is-active --quiet docker-helper.service || { echo "error: docker-helper not active" >&2; exit 1; }
DAEMON_PID="$(systemctl show -p MainPID --value docker-helper.service)"
echo "DAEMON_CONTEXT_BEFORE=$(attr_current "$DAEMON_PID")"

# ---------------------------------------------------------------------------
# 2. fresh workspace + fixture (probe.txt), principal + credential + session
# ---------------------------------------------------------------------------
info "== 2. workspace + principal + session =="
rm -rf "$WS"
mkdir -p "$WS/rw"
printf 'pin-probe-content\n' > "$WS/rw/probe.txt"
chown -R "$PRINCIPAL:$PRINCIPAL" "$WS"
chmod 0755 "$WS" "$WS/rw"

docker-helper principal create --system "$PRINCIPAL" >/dev/null 2>&1 || true
docker-helper principal allowed-root add --system "$PRINCIPAL" /home/opc >/dev/null 2>&1 || true

# Final ownership model: a selector-less principal Session resolves to the
# principal's inherit-scope 'default' Launcher, so that Launcher must exist
# before the Session create below. There is no Launcher CLI command, so the
# admin creates it over the raw control-plane API using the system admin token
# (never printed; sent only as an Authorization header). Idempotent: 409
# launcher_exists is fine (e.g. black-box UAT already established it for opc).
admin_token="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
if [ -z "$admin_token" ]; then
  echo "error: could not read the admin token from /etc/docker-helper/admin.token" >&2
  exit 1
fi
launcher_http="$(curl --silent --output /tmp/uat-pin-launcher.json --write-out '%{http_code}' --max-time 5 \
  --unix-socket /run/docker-helper/docker-helper.sock -H "Authorization: Bearer $admin_token" \
  -H 'Content-Type: application/json' \
  -d '{"scope":"inherit"}' "http://localhost/principals/$PRINCIPAL/launchers" 2>/dev/null || true)"
launcher_json="$(cat /tmp/uat-pin-launcher.json 2>/dev/null || true)"
if ! printf '%s\n' "$launcher_json" | grep -q '"ok":true' \
  && ! printf '%s\n' "$launcher_json" | grep -q '"launcher_exists"'; then
  echo "error: default launcher create for principal '$PRINCIPAL' failed (http=$launcher_http)" >&2
  exit 1
fi

CRED_FILE="/tmp/uat-pin-credential.token"
rm -f "$CRED_FILE"
CRED_OUT="$(docker-helper credential create --system --name uat-selinux-pin "$PRINCIPAL" 2>&1)" \
  || { echo "error: credential create failed: $CRED_OUT" >&2; exit 1; }
CRED_TOKEN="$(printf '%s\n' "$CRED_OUT" | sed -n 's/^  Token: //p')"
[ -n "$CRED_TOKEN" ] || { echo "error: could not parse credential token" >&2; exit 1; }
printf '%s\n' "$CRED_TOKEN" > "$CRED_FILE"
chmod 600 "$CRED_FILE"

SESSION_JSON="$(docker-helper session create --system --token-file "$CRED_FILE" --workspace "$WS" --json)" \
  || { echo "error: session create failed" >&2; exit 1; }
SESSION_TOKEN="$(printf '%s\n' "$SESSION_JSON" | grep -oP '"token": "\K[^"]+' | head -1)"
[ -n "$SESSION_TOKEN" ] || { echo "error: session create returned no token" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 3. long-running docker-helper run (background) with a mount pin
# ---------------------------------------------------------------------------
info "== 3. start long-running docker-helper run (background) =="
CONTAINER_SCRIPT='set -e
cat /proc/self/attr/current > /mnt/rw/container-context.txt
while [ ! -f /mnt/rw/release ]; do sleep 1; done
cat /mnt/rw/probe.txt
echo PIN-READ-OK'
DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
  docker-helper run --image "$IMAGE" --mount rw:/mnt/rw -- sh -ec "$CONTAINER_SCRIPT" \
  > "$RUN_LOG" 2>&1 &
RUN_PID=$!

# ---------------------------------------------------------------------------
# 4. wait for the real mount pin (single active operation -> single pin;
#    ambiguity > 1 is a failure)
# ---------------------------------------------------------------------------
info "== 4. wait for the mount pin =="
PIN=""
for i in $(seq 1 120); do
  CANDIDATES=""
  while IFS= read -r d; do
    if mountpoint -q "$d" 2>/dev/null; then
      CANDIDATES="$CANDIDATES
$d"
    fi
  done < <(find /run/docker-helper/mounts -mindepth 2 -maxdepth 2 -type d 2>/dev/null | grep -E '/[0-9]+$' || true)
  COUNT="$(printf '%s\n' "$CANDIDATES" | sed '/^[[:space:]]*$/d' | wc -l)"
  if [ "$COUNT" -gt 1 ]; then
    printf 'error: ambiguous mount pins (%s)\n' "$CANDIDATES" >&2
    exit 1
  fi
  if [ "$COUNT" = 1 ]; then
    PIN="$(printf '%s\n' "$CANDIDATES" | sed '/^[[:space:]]*$/d' | head -1)"
    break
  fi
  if ! kill -0 "$RUN_PID" 2>/dev/null; then
    classify_run_exit "$RUN_LOG" "before a mount pin appeared"
  fi
  sleep 1
done
[ -n "$PIN" ] || { echo "error: no mount pin appeared within 120s" >&2; exit 1; }
info "mount pin: $PIN"

# Wait for proof that the container is actually active: the container writes
# its own SELinux context into container-context.txt. While waiting, keep
# checking that the operation is still alive AND the pin still exists/is
# mounted; if the operation exits before the active-container proof is
# reached, classify the outcome from the run log (known Docker socket blocker
# => BLOCKED, otherwise FAIL) instead of stat()ing a pin that may already be
# gone.
ACTIVE_PROOF=0
for i in $(seq 1 30); do
  if [ -s "$WS/rw/container-context.txt" ]; then
    ACTIVE_PROOF=1
    break
  fi
  if ! kill -0 "$RUN_PID" 2>/dev/null; then
    classify_run_exit "$RUN_LOG" "after the mount pin appeared but before the container proved active"
  fi
  if ! mountpoint -q "$PIN" 2>/dev/null; then
    # Operation is still running but the pin is gone: cannot prove active.
    classify_run_exit "$RUN_LOG" "after the mount pin appeared but before the container proved active (pin no longer mounted)"
  fi
  sleep 1
done
[ "$ACTIVE_PROOF" = 1 ] || { echo "error: container never proved active within 30s" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 5. BEFORE state: source + pin device:inode / context / type + matchpathcon
# ---------------------------------------------------------------------------
info "== 5. BEFORE state =="
SOURCE="$WS/rw"
SOURCE_INODE_BEFORE="$(stat -c '%d:%i' "$SOURCE")"
PIN_INODE_BEFORE="$(stat -c '%d:%i' "$PIN")"
SOURCE_CTX_BEFORE="$(selinux_ctx "$SOURCE")"
PIN_CTX_BEFORE="$(selinux_ctx "$PIN")"
SOURCE_TYPE_BEFORE="$(printf '%s' "$SOURCE_CTX_BEFORE" | cut -d: -f3)"
PIN_TYPE_BEFORE="$(printf '%s' "$PIN_CTX_BEFORE" | cut -d: -f3)"

echo "SOURCE_INODE_BEFORE=$SOURCE_INODE_BEFORE"
echo "PIN_INODE_BEFORE=$PIN_INODE_BEFORE"
echo "SOURCE_CONTEXT_BEFORE=$SOURCE_CTX_BEFORE"
echo "PIN_CONTEXT_BEFORE=$PIN_CTX_BEFORE"
echo "SOURCE_TYPE_BEFORE=$SOURCE_TYPE_BEFORE"
echo "PIN_TYPE_BEFORE=$PIN_TYPE_BEFORE"
echo "--- matchpathcon evidence ---"
matchpathcon "$SOURCE" 2>&1 || true
matchpathcon "$PIN" 2>&1 || true

[ "$SOURCE_INODE_BEFORE" = "$PIN_INODE_BEFORE" ] \
  || { echo "error: source and pin are NOT the same inode ($SOURCE_INODE_BEFORE vs $PIN_INODE_BEFORE)" >&2; exit 1; }
[ "$SOURCE_TYPE_BEFORE" = "$PIN_TYPE_BEFORE" ] \
  || { echo "error: source and pin types differ ($SOURCE_TYPE_BEFORE vs $PIN_TYPE_BEFORE)" >&2; exit 1; }
[ "$SOURCE_TYPE_BEFORE" != "docker_helper_runtime_t" ] \
  || { echo "error: workspace type is already docker_helper_runtime_t (corrupted before reinstall)" >&2; exit 1; }
case "$SOURCE_TYPE_BEFORE" in
  user_home_t|user_home_dir_t) info "workspace type $SOURCE_TYPE_BEFORE is user_home_type-compatible (expected for /home)" ;;
  *) info "NOTE: workspace type '$SOURCE_TYPE_BEFORE' is not a user_home_type label (reporting, not failing)" ;;
esac
MATCH_PIN="$(matchpathcon "$PIN" 2>/dev/null || true)"
if printf '%s' "$MATCH_PIN" | grep -q 'docker_helper_runtime_t'; then
  info "matchpathcon expects docker_helper_runtime_t at the pin path (dangerous namespace-alias evidence); actual inode type is $PIN_TYPE_BEFORE"
else
  info "matchpathcon at pin path: $MATCH_PIN"
fi

CONTAINER_CONTEXT="$(tr -d '\0' < "$WS/rw/container-context.txt" 2>/dev/null || true)"
echo "CONTAINER_CONTEXT=$CONTAINER_CONTEXT"
CONTAINER_TYPE="$(printf '%s' "$CONTAINER_CONTEXT" | cut -d: -f3)"
[ -n "$CONTAINER_TYPE" ] || { echo "error: container context file empty/missing" >&2; exit 1; }
[ "$CONTAINER_TYPE" = "docker_helper_container_t" ] \
  || { echo "error: container type != docker_helper_container_t (got '$CONTAINER_TYPE', full '$CONTAINER_CONTEXT')" >&2; exit 1; }
echo "CONTAINER_TYPE=$CONTAINER_TYPE"
if [ "$CONTAINER_TYPE" != "unconfined_t" ] && [ "$CONTAINER_TYPE" != "container_t" ]; then
  info "custom container domain confirmed: $CONTAINER_TYPE (not unconfined/container_t)"
fi

# ---------------------------------------------------------------------------
# 6. real RPM reinstall/upgrade scriptlet path WHILE run + pin are active
# ---------------------------------------------------------------------------
info "== 6. real RPM reinstall (scriptlets run) with run + pin active =="
REINSTALL_CMD="rpm -Uvh --replacepkgs $UAT_RPM"
info "exact command: $REINSTALL_CMD"
REINSTALL_OUT="$(rpm -Uvh --replacepkgs "$UAT_RPM" 2>&1)"
REINSTALL_EC=$?
printf '%s\n' "$REINSTALL_OUT"
[ "$REINSTALL_EC" -eq 0 ] || { echo "error: rpm reinstall failed (exit $REINSTALL_EC)" >&2; exit 1; }
echo "RPM_REINSTALL_OK=yes"

# ---------------------------------------------------------------------------
# 7. AFTER state: source + pin (if it survived) — the central assertion
# ---------------------------------------------------------------------------
info "== 7. AFTER state =="
SOURCE_INODE_AFTER="$(stat -c '%d:%i' "$SOURCE")"
SOURCE_CTX_AFTER="$(selinux_ctx "$SOURCE")"
SOURCE_TYPE_AFTER="$(printf '%s' "$SOURCE_CTX_AFTER" | cut -d: -f3)"
echo "SOURCE_INODE_AFTER=$SOURCE_INODE_AFTER"
echo "SOURCE_CONTEXT_AFTER=$SOURCE_CTX_AFTER"
echo "SOURCE_TYPE_AFTER=$SOURCE_TYPE_AFTER"

PIN_INODE_AFTER=""
PIN_CTX_AFTER=""
PIN_TYPE_AFTER=""
if [ -e "$PIN" ] && mountpoint -q "$PIN" 2>/dev/null; then
  PIN_INODE_AFTER="$(stat -c '%d:%i' "$PIN")"
  PIN_CTX_AFTER="$(selinux_ctx "$PIN")"
  PIN_TYPE_AFTER="$(printf '%s' "$PIN_CTX_AFTER" | cut -d: -f3)"
  echo "PIN_INODE_AFTER=$PIN_INODE_AFTER"
  echo "PIN_CONTEXT_AFTER=$PIN_CTX_AFTER"
  echo "PIN_TYPE_AFTER=$PIN_TYPE_AFTER"
else
  echo "PIN_INODE_AFTER=(pin gone after reinstall; %post restarted the daemon, which cleaned the operation)"
  echo "PIN_CONTEXT_AFTER=(n/a)"
  echo "PIN_TYPE_AFTER=(n/a)"
fi

[ "$SOURCE_INODE_AFTER" = "$SOURCE_INODE_BEFORE" ] \
  || { echo "error: source inode CHANGED after reinstall ($SOURCE_INODE_BEFORE -> $SOURCE_INODE_AFTER)" >&2; exit 1; }
[ "$SOURCE_TYPE_AFTER" = "$SOURCE_TYPE_BEFORE" ] \
  || { echo "error: source type CHANGED after reinstall ($SOURCE_TYPE_BEFORE -> $SOURCE_TYPE_AFTER)" >&2; exit 1; }
[ "$SOURCE_TYPE_AFTER" != "docker_helper_runtime_t" ] \
  || { echo "error: workspace type corrupted to docker_helper_runtime_t after reinstall" >&2; exit 1; }
if [ -n "$PIN_INODE_AFTER" ]; then
  [ "$PIN_INODE_AFTER" = "$PIN_INODE_BEFORE" ] \
    || { echo "error: pin inode changed after reinstall ($PIN_INODE_BEFORE -> $PIN_INODE_AFTER)" >&2; exit 1; }
  [ "$PIN_TYPE_AFTER" = "$PIN_TYPE_BEFORE" ] \
    || { echo "error: pin type changed after reinstall ($PIN_TYPE_BEFORE -> $PIN_TYPE_AFTER)" >&2; exit 1; }
  [ "$PIN_TYPE_AFTER" != "docker_helper_runtime_t" ] \
    || { echo "error: pin actual type corrupted to docker_helper_runtime_t" >&2; exit 1; }
fi

# ---------------------------------------------------------------------------
# 8. release the container; prove post-install container access (PIN-READ-OK)
# ---------------------------------------------------------------------------
info "== 8. release + post-install container access =="
touch "$WS/rw/release"

ORIG_EC="n/a"
ORIG_OUT=""
for i in $(seq 1 60); do
  if ! kill -0 "$RUN_PID" 2>/dev/null; then
    wait "$RUN_PID" 2>/dev/null; ORIG_EC=$?
    break
  fi
  sleep 1
done
ORIG_OUT="$(cat "$RUN_LOG" 2>/dev/null || true)"
ORIG_SURVIVED="no"
PIN_READ_OK="no"
if printf '%s\n' "$ORIG_OUT" | grep -q 'PIN-READ-OK'; then
  ORIG_SURVIVED="yes"
  PIN_READ_OK="yes"
  info "original run survived the reinstall and read the workspace (PIN-READ-OK)"
else
  info "original run did not survive the reinstall (exit=$ORIG_EC); %post restarts the daemon, which terminates in-flight operations"
  info "proving post-install container access with a fresh docker-helper run"
  FRESH_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
    docker-helper run --image "$IMAGE" --mount rw:/mnt/rw -- sh -ec 'cat /mnt/rw/probe.txt && echo PIN-READ-OK' 2>&1)"
  FRESH_EC=$?
  printf '%s\n' "$FRESH_OUT"
  if [ "$FRESH_EC" -eq 0 ] && printf '%s\n' "$FRESH_OUT" | grep -q 'PIN-READ-OK' \
     && printf '%s\n' "$FRESH_OUT" | grep -q 'pin-probe-content'; then
    PIN_READ_OK="yes"
    info "fresh run read the workspace after the postinstall: content verified"
  else
    echo "error: post-install container access FAILED (exit $FRESH_EC)" >&2
  fi
fi
echo "PIN_READ_OK=$PIN_READ_OK"
[ "$PIN_READ_OK" = "yes" ] || { echo "error: PIN_READ_OK != yes" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 9. lifecycle + service state + fresh AVCs for this regression window
# ---------------------------------------------------------------------------
info "== 9. lifecycle + service state + AVC audit =="
REMAINING="$(find /run/docker-helper/mounts -mindepth 2 -maxdepth 2 -type d 2>/dev/null | grep -E '/[0-9]+$' || true)"
if [ -z "$REMAINING" ]; then
  info "mount pins cleaned up by the normal lifecycle (none remain)"
else
  echo "warning: mount pins still present after runs: $REMAINING" >&2
fi
systemctl is-active --quiet docker-helper.service \
  || { echo "error: docker-helper service not active after regression" >&2; exit 1; }
NEW_PID="$(systemctl show -p MainPID --value docker-helper.service)"
echo "DAEMON_CONTEXT_AFTER=$(attr_current "$NEW_PID")"
D_CTX="$(attr_current "$NEW_PID")"
D_TYPE="$(printf '%s' "$D_CTX" | cut -d: -f3)"
[ "$D_TYPE" = "docker_helper_t" ] \
  || { echo "error: daemon type != docker_helper_t after regression (got '$D_TYPE')" >&2; exit 1; }

echo
mac_audit_check

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "=========== SELINUX MOUNT-PIN / RPM POSTINSTALL REGRESSION ==========="
echo "SOURCE_INODE_BEFORE=$SOURCE_INODE_BEFORE"
echo "PIN_INODE_BEFORE=$PIN_INODE_BEFORE"
echo "SOURCE_TYPE_BEFORE=$SOURCE_TYPE_BEFORE"
echo "PIN_TYPE_BEFORE=$PIN_TYPE_BEFORE"
echo "SOURCE_INODE_AFTER=$SOURCE_INODE_AFTER"
echo "PIN_INODE_AFTER=$PIN_INODE_AFTER"
echo "SOURCE_TYPE_AFTER=$SOURCE_TYPE_AFTER"
echo "PIN_TYPE_AFTER=$PIN_TYPE_AFTER"
echo "CONTAINER_CONTEXT=$CONTAINER_CONTEXT"
echo "PIN_READ_OK=$PIN_READ_OK"
echo "ORIGINAL_RUN_SURVIVED=$ORIG_SURVIVED"
echo "RESULT=PASS"
echo "======================================================================"

exit 0
