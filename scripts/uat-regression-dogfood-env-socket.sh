#!/usr/bin/env bash
#
# uat-regression-dogfood-env-socket.sh — 2.1.1 targeted regression group 17:
# combined #3 + #4 dogfood (Ubuntu / DEB / AppArmor).
#
# One integration scenario proving the real delegated-orchestrator use case
# end to end:
#
#   Launcher credential (host, never in argv)
#     -> docker-helper run --helper-socket --env-from <credential>
#     -> orchestrator workload (alpine + packaged docker-helper CLI)
#     -> /run/docker-helper/docker-helper.sock (injected transport)
#     -> explicit Launcher credential
#     -> create child Session
#     -> use the child Session for an authorized run operation
#     -> delete the child Session through the launcher authority
#     -> cleanup verified from the host
#
# Proven properties:
#   * helper transport available inside the workload;
#   * the Launcher credential is passed separately through the process
#     environment, never through CLI argv (probed via /proc/<pid>/cmdline);
#   * the credential value never appears in the daemon journal;
#   * the workload performs an authorized launcher operation through the
#     injected socket (child session create + authorized child run);
#   * created test resources are cleaned up (no child session remains).
#
# Requires: installed docker-helper system service (active), Docker
# reachable, root. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "17. env-from + helper-socket dogfood"

reg_require_root
reg_require_service
reg_require_docker

IMAGE="alpine:3.24"
USER="uatreg17"

home="$(reg_setup_principal "$USER")" || { reg_fail "setup principal failed"; reg_result; }
ws="$home/ws"; mkdir -p "$ws"
chown -R "$USER:$USER" "$ws"

# Launcher credential: the delegated identity that will be handed to the
# orchestrator workload. Created through the canonical launcher-credential
# owner; the token is kept in a 0600 file and never echoed.
rm -f /tmp/uat-reg17-cred.token
launcher_cred_json="$(dh launcher credential create --system --principal "$USER" 2>/dev/null)" \
  || { reg_fail "launcher credential create failed"; reg_result; }
CRED_TOKEN="$(printf '%s\n' "$launcher_cred_json" | json_field token)"
CRED_ID="$(printf '%s\n' "$launcher_cred_json" | json_field id)"
[ -n "$CRED_TOKEN" ] && [ -n "$CRED_ID" ] || { reg_fail "launcher credential token/ID missing"; reg_result; }
printf '%s\n' "$CRED_TOKEN" > /tmp/uat-reg17-cred.token
chmod 600 /tmp/uat-reg17-cred.token

# Launcher-scoped Session for the orchestrator workload itself.
reg_session /tmp/uat-reg17-cred.token "$ws" || { reg_fail "launcher session create failed"; reg_result; }
SESSION_TOKEN="$REG_SESSION_TOKEN"
SESSION_ID="$REG_SESSION_ID"

# Child workspace for the delegated child Session (host path; resolved and
# authorized daemon-side, never chosen inside the container).
CHILD_WS="$ws/dogfood-child"
mkdir -p "$CHILD_WS"
chown "$USER:$USER" "$CHILD_WS"

# The workload runs the packaged docker-helper CLI through the injected
# socket; the binary travels through the workspace bind.
cp /usr/bin/docker-helper "$ws/docker-helper"
chmod 755 "$ws/docker-helper"
chown "$USER:$USER" "$ws/docker-helper"

rm -f "$ws"/reg17-* 2>/dev/null || true

MARKER_EPOCH="$(date +%s)"
set +e
DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" UAT_LAUNCHER_CRED_SOURCE="$CRED_TOKEN" \
  dh run --image "$IMAGE" \
  --helper-socket \
  --env "UAT_CHILD_WS=$CHILD_WS" \
  --env-from "UAT_LAUNCHER_CRED=UAT_LAUNCHER_CRED_SOURCE" \
  --mount .:/workspace \
  -- sh -ec '
    set -eu
    test -S /run/docker-helper/docker-helper.sock
    printf "%s\n" "$UAT_LAUNCHER_CRED" > /tmp/launcher-cred
    chmod 600 /tmp/launcher-cred
    DH=/workspace/docker-helper

    # Delegated child Session through the injected socket, authenticated by
    # the explicitly passed Launcher credential.
    CHILD_JSON=$("$DH" session create \
      --endpoint /run/docker-helper/docker-helper.sock \
      --token-file /tmp/launcher-cred \
      --workspace "$UAT_CHILD_WS" --json)
    CHILD_ID=$(printf "%s" "$CHILD_JSON" | sed -n "s/.*\"id\": \"\([^\"]*\)\".*/\1/p")
    CHILD_TOKEN=$(printf "%s" "$CHILD_JSON" | sed -n "s/.*\"token\": \"\([^\"]*\)\".*/\1/p")
    printf "%s" "$CHILD_ID" > /workspace/reg17-child-id

    # Authorized child-Session operation through the injected socket.
    DOCKER_HELPER_SOCKET_PATH=/run/docker-helper/docker-helper.sock \
    DOCKER_HELPER_SESSION_TOKEN="$CHILD_TOKEN" \
      "$DH" run -- true

    # Cleanup through the launcher authority.
    "$DH" session delete \
      --endpoint /run/docker-helper/docker-helper.sock \
      --token-file /tmp/launcher-cred --id "$CHILD_ID"
    echo done > /workspace/reg17-result
    rm -f /tmp/launcher-cred
  ' >/tmp/uat-reg17.out 2>/tmp/uat-reg17.err &
DOGFOOD_CLI_PID=$!

sleep 2
CMDLINE="$(tr '\0' ' ' < "/proc/$DOGFOOD_CLI_PID/cmdline" 2>/dev/null || true)"
if printf '%s' "$CMDLINE" | grep -qF "$CRED_TOKEN"; then
  reg_fail "launcher credential value leaked into the docker-helper run CLI argv"
else
  reg_ok "launcher credential value absent from the docker-helper run CLI argv"
fi

for _ in $(seq 1 120); do
  [ -f "$ws/reg17-result" ] && break
  kill -0 "$DOGFOOD_CLI_PID" 2>/dev/null || break
  sleep 1
done

if kill -0 "$DOGFOOD_CLI_PID" 2>/dev/null; then
  kill -INT "$DOGFOOD_CLI_PID" 2>/dev/null || true
fi
wait "$DOGFOOD_CLI_PID" 2>/dev/null
DOGFOOD_RC=$?

# --- assertions ---------------------------------------------------------------
if [ "$DOGFOOD_RC" = 0 ]; then
  reg_ok "dogfood workload completed successfully through the injected socket"
else
  reg_fail "dogfood workload failed (rc=$DOGFOOD_RC, stderr: $(tail -c 400 /tmp/uat-reg17.err 2>/dev/null))"
fi

CHILD_ID="$(cat "$ws/reg17-child-id" 2>/dev/null || true)"
if [ -n "$CHILD_ID" ]; then
  reg_ok "delegated child Session created through the injected socket ($CHILD_ID)"
else
  reg_fail "delegated child Session was NOT created"
fi

if [ "$(cat "$ws/reg17-result" 2>/dev/null || true)" = "done" ]; then
  reg_ok "child Session deleted through the launcher authority (cleanup done)"
else
  reg_fail "child Session cleanup did not complete"
fi

# No child session remains (launcher-scoped list through the host credential).
LIST_JSON="$(dh session list --system --token-file /tmp/uat-reg17-cred.token --json 2>/dev/null || true)"
if [ -n "$CHILD_ID" ] && printf '%s' "$LIST_JSON" | grep -qF "$CHILD_ID"; then
  reg_fail "child Session still present after in-workload cleanup"
else
  reg_ok "no child Session residue after cleanup"
fi

# The launcher credential value must not appear in the daemon journal
# (operational or audit stream).
JOURNAL="$(journalctl -u docker-helper.service --since "@$MARKER_EPOCH" --no-pager 2>/dev/null || true)"
if printf '%s\n' "$JOURNAL" | grep -qF "$CRED_TOKEN"; then
  reg_fail "launcher credential value leaked into the daemon journal"
else
  reg_ok "launcher credential value absent from the daemon journal"
fi

# --- cleanup ------------------------------------------------------------------
CID_LIST="$(docker ps -q --filter "label=com.dockerhelper.session.id=$SESSION_ID" 2>/dev/null || true)"
if [ -n "$CID_LIST" ]; then
  docker rm -f $CID_LIST >/dev/null 2>&1 || true
fi
dh session delete --system --token-file /tmp/uat-reg17-cred.token --id "$SESSION_ID" >/dev/null 2>&1 || true
rm -f /tmp/uat-reg17-cred.token /tmp/uat-reg17.* 2>/dev/null || true
rm -f "$ws"/reg17-* 2>/dev/null || true

reg_result
