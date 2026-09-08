#!/usr/bin/env bash
#
# uat-regression-env-from.sh — 2.1.1 targeted regression group 15:
# CLI --env-from secret forwarding (Ubuntu / DEB / AppArmor).
#
# Black-box acceptance of the --env-from DEST=SOURCE CLI capability:
#   * the resolved value reaches the workload environment through the
#     existing run environment contract;
#   * the secret value never appears in the docker-helper run CLI argv
#     (probed via /proc/<pid>/cmdline while the CLI is polling);
#   * the secret value never appears in the journal (operational + audit);
#   * an unset SOURCE variable is rejected fail-closed before any run
#     Operation is created (no run.start in the journal after the attempt);
#   * an explicitly empty SOURCE variable is delivered as an empty value;
#   * neighboring CLI process environment variables do not leak;
#   * --env and --env-from compose;
#   * an invalid DEST is rejected exactly like an invalid --env name.
#
# The script never prints a real secret value. Sentinel values are
# synthetic and unique per run.
#
# Requires: installed docker-helper system service (active), Docker
# reachable, root. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "15. env-from secret forwarding"

reg_require_root
reg_require_service
reg_require_docker

IMAGE="alpine:3.24"
USER="uatreg15"

home="$(reg_setup_principal "$USER")" || { reg_fail "setup principal failed"; reg_result; }
ws="$home/ws"; mkdir -p "$ws"
chown -R "$USER:$USER" "$ws"

cred="/tmp/uat-reg15.token"
reg_principal_credential "$USER" "$cred" || { reg_fail "credential create failed"; reg_result; }
reg_session "$cred" "$ws" || { reg_fail "session create failed"; reg_result; }
SESSION_TOKEN="$REG_SESSION_TOKEN"

SENTINEL="uat-env-from-$(date +%s%N)-$RANDOM"
NEIGHBOR="uat-neighbor-$(date +%s%N)-$RANDOM"
MISSING_VAR="UAT_MISSING_SOURCE_$(date +%s%N)"
reg_info "using unique synthetic sentinels (values are not secrets)"

# --- positive control: resolved value reaches the workload -------------------
ENV_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" UAT_SENTINEL_SOURCE="$SENTINEL" \
  dh run --image "$IMAGE" \
    --env "NEIGHBOR_SENTINEL=$NEIGHBOR" \
    --env-from "LLM_KEY=UAT_SENTINEL_SOURCE" \
    -- sh -ec 'env' 2>/dev/null)"

if printf '%s\n' "$ENV_OUT" | grep -qF "LLM_KEY=$SENTINEL"; then
  reg_ok "--env-from resolved value delivered to the workload"
else
  reg_fail "--env-from resolved value was NOT delivered to the workload"
fi

if printf '%s\n' "$ENV_OUT" | grep -qF "NEIGHBOR_SENTINEL=$NEIGHBOR"; then
  reg_ok "--env value delivered alongside --env-from"
else
  reg_fail "--env value was NOT delivered alongside --env-from"
fi

# --- neighboring CLI environment must not leak -------------------------------
NEIGHBOR_ONLY_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
  UAT_NEIGHBOR_ONLY="$NEIGHBOR" UAT_NEIGHBOR_FREE_SOURCE="$SENTINEL" \
  dh run --image "$IMAGE" \
    --env-from "LLM_KEY=UAT_NEIGHBOR_FREE_SOURCE" \
    -- sh -ec 'env' 2>/dev/null)"

if printf '%s\n' "$NEIGHBOR_ONLY_OUT" | grep -qF "UAT_NEIGHBOR_ONLY="; then
  reg_fail "neighboring CLI process environment leaked into the workload"
else
  reg_ok "neighboring CLI process environment absent from the workload"
fi
if printf '%s\n' "$NEIGHBOR_ONLY_OUT" | grep -qF "LLM_KEY=$SENTINEL"; then
  reg_ok "resolved --env-from value still delivered in the isolation check"
else
  reg_fail "resolved --env-from value missing in the isolation check"
fi

# --- secret value absent from the CLI argv -----------------------------------
MARKER_EPOCH="$(date +%s)"
DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" UAT_SENTINEL_SOURCE="$SENTINEL" \
  dh run --image "$IMAGE" \
    --env-from "LLM_KEY=UAT_SENTINEL_SOURCE" \
    -- sh -ec 'sleep 6' >/tmp/uat-reg15-run.out 2>/tmp/uat-reg15-run.err &
CLI_PID=$!
sleep 2
if kill -0 "$CLI_PID" 2>/dev/null; then
  CMDLINE="$(tr '\0' ' ' < "/proc/$CLI_PID/cmdline" 2>/dev/null || true)"
  if printf '%s' "$CMDLINE" | grep -qF "$SENTINEL"; then
    reg_fail "secret value leaked into the docker-helper run CLI argv"
  else
    reg_ok "secret value absent from the docker-helper run CLI argv"
  fi
  # Stop the probe workload through the CLI's own cancellation path.
  kill -INT "$CLI_PID" 2>/dev/null || true
else
  reg_fail "probe workload exited before the argv probe (could not verify argv)"
fi
wait "$CLI_PID" 2>/dev/null || true

# --- secret value absent from the journal ------------------------------------
JOURNAL="$(journalctl -u docker-helper.service --since "@$MARKER_EPOCH" --no-pager 2>/dev/null || true)"
if printf '%s\n' "$JOURNAL" | grep -qF "$SENTINEL"; then
  reg_fail "secret value leaked into the daemon journal (operational or audit)"
else
  reg_ok "secret value absent from the daemon journal"
fi

# --- missing SOURCE variable fails closed before operation creation ----------
MISSING_EPOCH="$(date +%s)"
set +e
DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
  dh run --image "$IMAGE" \
    --env-from "LLM_KEY=$MISSING_VAR" \
    -- sh -ec 'true' >/tmp/uat-reg15-missing.out 2>/tmp/uat-reg15-missing.err
MISSING_RC=$?
if [ "$MISSING_RC" != 0 ]; then
  reg_ok "missing SOURCE variable rejected (exit $MISSING_RC)"
else
  reg_fail "missing SOURCE variable was NOT rejected"
fi
MISSING_JOURNAL="$(journalctl -u docker-helper.service --since "@$MISSING_EPOCH" --no-pager 2>/dev/null || true)"
if printf '%s\n' "$MISSING_JOURNAL" | grep -q '"event":"run.start"'; then
  reg_fail "missing SOURCE rejection created a run Operation (run.start found)"
else
  reg_ok "missing SOURCE rejection left no run Operation"
fi

# --- explicitly empty SOURCE variable delivered as empty ---------------------
EMPTY_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" UAT_EMPTY_SOURCE="" \
  dh run --image "$IMAGE" \
    --env-from "FLAG=UAT_EMPTY_SOURCE" \
    -- sh -ec 'printf "set=%s len=%s" "${FLAG+set}" "${#FLAG}"' 2>/dev/null)"
if printf '%s\n' "$EMPTY_OUT" | grep -qF "set=set len=0"; then
  reg_ok "explicitly empty SOURCE variable delivered as an empty value"
else
  reg_fail "explicitly empty SOURCE variable was NOT delivered as empty (got: $EMPTY_OUT)"
fi

# --- invalid DEST rejected like invalid --env --------------------------------
set +e
DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
  dh run --image "$IMAGE" --env "BAD-NAME=from-env" -- sh -ec 'true' \
  >/tmp/uat-reg15-badenv.out 2>/tmp/uat-reg15-badenv.err
ENV_BAD_RC=$?
DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
  dh run --image "$IMAGE" --env-from "BAD-NAME=UAT_SENTINEL_SOURCE" -- sh -ec 'true' \
  >/tmp/uat-reg15-badfrom.out 2>/tmp/uat-reg15-badfrom.err
FROM_BAD_RC=$?
if [ "$ENV_BAD_RC" = "$FROM_BAD_RC" ] && [ "$FROM_BAD_RC" != 0 ]; then
  reg_ok "invalid DEST rejected identically to invalid --env (exit $FROM_BAD_RC)"
else
  reg_fail "invalid DEST handling diverges from --env (env=$ENV_BAD_RC, env-from=$FROM_BAD_RC)"
fi
if grep -q "invalid environment variable name" /tmp/uat-reg15-badfrom.err 2>/dev/null; then
  reg_ok "invalid DEST carries the daemon invalid_environment diagnostic"
else
  reg_fail "invalid DEST diagnostic missing (stderr: $(cat /tmp/uat-reg15-badfrom.err 2>/dev/null))"
fi

# --- missing separator rejected at the CLI boundary --------------------------
set +e
DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
  dh run --image "$IMAGE" --env-from "NOSEPARATOR" -- sh -ec 'true' \
  >/tmp/uat-reg15-noeq.out 2>/tmp/uat-reg15-noeq.err
NOEQ_RC=$?
if [ "$NOEQ_RC" = 2 ] && grep -q "invalid env-from format" /tmp/uat-reg15-noeq.err 2>/dev/null; then
  reg_ok "missing DEST=SOURCE separator rejected at the CLI boundary"
else
  reg_fail "missing separator handling unexpected (rc=$NOEQ_RC, stderr: $(cat /tmp/uat-reg15-noeq.err 2>/dev/null))"
fi

# --- cleanup ------------------------------------------------------------------
rm -f /tmp/uat-reg15.* 2>/dev/null || true

reg_result
