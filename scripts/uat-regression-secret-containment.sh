#!/usr/bin/env bash
#
# uat-regression-secret-containment.sh — Release-2 targeted regression group 8:
# Secret containment (Ubuntu / DEB / AppArmor).
#
# Uses unique generated sentinel values and the real token values of this run
# to prove:
#   * Session bearer absent from container env;
#   * admin token absent from container env;
#   * Principal credential absent from container env;
#   * bearer secrets absent from the normal journal (operational + audit);
#   * secrets absent from audit output (the journal carries stream:"audit");
#   * sensitive env/audit values follow the masking contract (env keys only,
#     values never; `config show --json` redacts admin_token);
#   * the UAT itself does not dump secrets (all captured output is redacted).
# The script never prints a real secret value.
#
# Requires: installed docker-helper system service (active), Docker reachable,
# root. Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "8. Secret containment"

reg_require_root
reg_require_service
reg_require_docker

IMAGE="alpine:3.24"
USER="uatreg8"

home="$(reg_setup_principal "$USER")" || { reg_fail "setup principal failed"; reg_result; }
ws="$home/ws"; mkdir -p "$ws"
chown -R "$USER:$USER" "$ws"

cred="/tmp/uat-reg8.token"
reg_principal_credential "$USER" "$cred" || { reg_fail "credential create failed"; reg_result; }
CRED_TOKEN="$REG_CRED_TOKEN"
reg_session "$cred" "$ws" || { reg_fail "session create failed"; reg_result; }
SESSION_TOKEN="$REG_SESSION_TOKEN"

ADMIN_TOKEN="$(cat /etc/docker-helper/admin.token 2>/dev/null || true)"
[ -n "$ADMIN_TOKEN" ] || { reg_fail "could not read admin token for the negative check"; reg_result; }

SENTINEL="secret-env-$(date +%s%N)-$RANDOM"
reg_info "using unique env sentinel (value not shown) for masking checks"

# Journal window: everything from just before the docker-helper activity.
START_EPOCH="$(date +%s)"

# --- container env dump via a docker-helper run --------------------------------
ENV_OUT="$(DOCKER_HELPER_SESSION_TOKEN="$SESSION_TOKEN" \
  dh run --image "$IMAGE" --env UAT_SENTINEL_VAR="$SENTINEL" -- sh -ec 'env' 2>/dev/null)"

for label in "session bearer" "admin token" "principal credential"; do
  tok=""
  case "$label" in
    "session bearer") tok="$SESSION_TOKEN" ;;
    "admin token")    tok="$ADMIN_TOKEN" ;;
    *)                tok="$CRED_TOKEN" ;;
  esac
  if printf '%s\n' "$ENV_OUT" | grep -qF "$tok"; then
    reg_fail "$label leaked into container env"
  else
    reg_ok "$label absent from container env"
  fi
done

if printf '%s\n' "$ENV_OUT" | grep -qF "$SENTINEL"; then
  reg_ok "explicit --env value IS present in the container (positive control)"
else
  reg_fail "explicit --env value was NOT present in the container (positive control failed)"
fi

# --- journal (operational + audit JSONL) must not contain the secrets -----------
JOURNAL="$(journalctl -u docker-helper.service --since "@$START_EPOCH" --no-pager 2>/dev/null || true)"
for label in "session bearer" "admin token" "principal credential" "env sentinel value"; do
  needle=""
  case "$label" in
    "session bearer")     needle="$SESSION_TOKEN" ;;
    "admin token")        needle="$ADMIN_TOKEN" ;;
    "principal credential") needle="$CRED_TOKEN" ;;
    *)                    needle="$SENTINEL" ;;
  esac
  if printf '%s' "$JOURNAL" | grep -qF "$needle"; then
    reg_fail "$label leaked into the journal"
  else
    reg_ok "$label absent from the journal (operational + audit)"
  fi
done

# Explicit audit-stream check: records with stream:"audit" must not carry the
# env VALUE (audit records env KEYS only, never values).
if printf '%s' "$JOURNAL" | grep '"stream": "audit"' | grep -qF "$SENTINEL"; then
  reg_fail "env value leaked into an audit record"
else
  reg_ok "audit records carry no env values (keys only)"
fi

# --- config show --json redaction contract --------------------------------------
CONFIG_JSON="$(dh config show --json 2>/dev/null)"
if printf '%s' "$CONFIG_JSON" | grep -q '<redacted>' \
   && ! printf '%s' "$CONFIG_JSON" | grep -qF "$ADMIN_TOKEN"; then
  reg_ok "config show --json redacts the admin token value"
else
  reg_fail "config show --json did not redact the admin token value"
fi

# --- best-effort cleanup ---------------------------------------------------------
dh principal delete --system "$USER" >/dev/null 2>&1 || true
userdel -r "$USER" >/dev/null 2>&1 || true
rm -f "$cred"

reg_result
