#!/usr/bin/env bash
#
# uat-regression-user-mode-effective-roots.sh — Release-2.1 RC6 targeted
# regression group 12: user-mode effective Principal roots (single semantic
# owner) (Ubuntu / DEB / AppArmor).
#
# Black-box acceptance coverage for the RC6 effective-root ownership blocker,
# exercised on a REAL user-mode installation (its own initialized and started
# user-mode daemon, never the system service):
#
#   A. effective-roots introspection — after transparent user-mode
#      initialization, the daemon-owner Principal's effective Principal roots
#      (GET /principals/{username}/effective-allowed-roots through
#      `completion roots principal`) report the global user-mode allowed
#      root, never the empty set the competing global∩stored computation
#      produced.
#   B. restricted Launcher create under the daemon-owner Principal — a second,
#      differently named Launcher created restricted with a root inside the
#      global user-mode allowed root succeeds; `launcher show` reports the
#      restricted scope and stored root. A restricted root OUTSIDE the global
#      ceiling — a real, policy-legal directory in a permitted namespace — is
#      refused specifically with the stable 400 outside_principal_root code.
#   C. restricted-scope conversion — a second inherit-scope Launcher converted
#      to restricted through the atomic scope replacement succeeds.
#   D. Session under the restricted Launcher — a workspace inside the
#      restricted root creates a Session and runs a trivial container; a
#      workspace inside the global root but outside the Launcher restriction
#      is rejected specifically with the stable 400 invalid_workspace code.
#   E. reservation intact — the reserved 'default' Launcher still refuses a
#      restricted scope specifically with the stable
#      409 user_mode_owner_reserved code (group 11 owns the full
#      reservation-code contract).
#
# Requires: installed docker-helper binary, root (user/XDG-runtime setup),
# Docker (trivial container run). The system service is NOT required and is
# stopped for the duration so the user-mode daemon is unambiguous.
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "12. User-mode effective Principal roots"

reg_require_root
reg_require_docker
reg_require_cmd curl "health probing of the user-mode daemon"
reg_require_cmd sudo "the user-mode daemon runs as a non-root user"

TMPDIR_UER="/tmp/uat-reg12"
mkdir -p "$TMPDIR_UER"

U_USER="uatreg12"
U_SERVE_PID=""
U_XDG=""

cleanup() {
  if [ -n "$U_SERVE_PID" ]; then
    kill "$U_SERVE_PID" 2>/dev/null || true
    wait "$U_SERVE_PID" 2>/dev/null || true
  fi
  [ -n "$U_USER" ] && pkill -TERM -u "$U_USER" -f '/usr/bin/docker-helper serve' 2>/dev/null || true
  [ -n "$U_USER" ] && userdel -r "$U_USER" >/dev/null 2>&1 || true
  [ -n "$U_USER" ] && rm -rf "/home/${U_USER}-outside" 2>/dev/null || true
  [ -n "$U_XDG" ] && rm -rf "$U_XDG" 2>/dev/null || true
  rm -rf "$TMPDIR_UER"
}
trap cleanup EXIT

# The user-mode daemon is unambiguous only without a system daemon competing
# for the default endpoint of the UAT user.
systemctl stop docker-helper.service >/dev/null 2>&1 || true

# --- setup: real non-root user + initialized and started user-mode daemon ----

U_UID=""
U_HOME=""
if getent passwd "$U_USER" >/dev/null 2>&1; then
  userdel -r "$U_USER" >/dev/null 2>&1 || true
fi
if useradd -m -s /bin/bash "$U_USER" 2>/dev/null; then
  reg_ok "setup: UAT user $U_USER created"
else
  reg_blocked "could not create the user-mode UAT user"
fi
U_UID="$(id -u "$U_USER")"
U_HOME="$(getent passwd "$U_USER" | cut -d: -f6)"
usermod -aG docker "$U_USER" 2>/dev/null || true
mkdir -p "$U_HOME/ws"; chown -R "$U_USER:$U_USER" "$U_HOME"

U_XDG="/run/user/$U_UID"
mkdir -p "$U_XDG"
chown "$U_USER:$U_USER" "$U_XDG"
chmod 0700 "$U_XDG"

# A clean, user-scoped environment for every user-mode docker-helper process
# (the same `env -i` discipline as the common black-box UAT coexistence
# scenario: no inherited runner XDG state may leak into the UAT user).
U_ENV=(env -i "HOME=$U_HOME" "XDG_RUNTIME_DIR=$U_XDG" \
  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")

# dhx runs docker-helper as the user-mode daemon owner against the user socket.
dhx() { sudo -u "$U_USER" "${U_ENV[@]}" /usr/bin/docker-helper "$@"; }

if dhx init --allowed-root "$U_HOME" >"$TMPDIR_UER/init.log" 2>&1; then
  reg_ok "user-mode init succeeded for $U_USER"
else
  reg_fail "user-mode init failed (see $TMPDIR_UER/init.log)"
  sed 's/^/    init-log: /' "$TMPDIR_UER/init.log" 2>/dev/null | redact | tail -15 >&2
  reg_result
fi

U_SOCK="$U_XDG/docker-helper/docker-helper.sock"
# The redirect lands on sudo's child (the daemon); sudo itself is quiet.
# shellcheck disable=SC2024
sudo -u "$U_USER" "${U_ENV[@]}" /usr/bin/docker-helper serve >"$TMPDIR_UER/serve.log" 2>&1 &
U_SERVE_PID=$!
U_READY=0
for _ in $(seq 1 100); do
  if [ -S "$U_SOCK" ] && curl --silent --fail --max-time 1 --unix-socket "$U_SOCK" http://localhost/health >/dev/null 2>&1; then
    U_READY=1; break
  fi
  sleep 0.2
done
if [ "$U_READY" = 1 ]; then
  reg_ok "user-mode daemon healthy on its own socket"
else
  reg_fail "user-mode daemon did not become ready (see $TMPDIR_UER/serve.log)"
  reg_result
fi

OWNER="$U_USER"
WS="$U_HOME/ws"
WORK="$WS/work"

# uer_field FIELD: parse a control-plane --json document field.
uer_field() { json_field "$1"; }

# --- A. effective-roots introspection reports the global user-mode ceiling ---

if A_OUT="$(dhx completion roots principal --principal "$OWNER" 2>&1)"; then
  if printf '%s' "$A_OUT" | grep -qx "$U_HOME"; then
    reg_ok "A: daemon-owner effective Principal roots report the global user-mode root ($U_HOME)"
  else
    reg_fail "A: daemon-owner effective Principal roots do not report the global root: $(printf '%s' "$A_OUT" | head -2 | tr '\n' ' ' | redact)"
  fi
else
  reg_fail "A: effective-roots introspection failed: $(printf '%s' "$A_OUT" | head -2 | tr '\n' ' ' | redact)"
fi

# --- B. restricted Launcher create under the daemon-owner Principal ----------

mkdir -p "$WORK" || reg_fail "B: cannot create the restricted workspace $WORK"
mkdir -p "$WORK/proj" || reg_fail "B: cannot create the restricted workspace $WORK/proj"
B_OUT="$(dhx launcher create --principal "$OWNER" --name work --allowed-root "$WORK" --no-credential 2>&1)"
WORK_ID="$(printf '%s' "$B_OUT" | uer_field id || true)"
if [ -n "$WORK_ID" ]; then
  if B_SHOW="$(dhx launcher show --principal "$OWNER" work --json 2>&1)" \
      && [ "$(printf '%s' "$B_SHOW" | uer_field scope)" = "restricted" ] \
      && printf '%s' "$B_SHOW" | grep -q "\"allowed_roots\": \[\"$WORK\"\]"; then
    reg_ok "B: restricted Launcher created under the global root; show reports scope=restricted and the stored root"
  else
    reg_fail "B: launcher show does not report the restricted root: $(printf '%s' "$B_SHOW" | head -3 | tr '\n' ' ' | redact)"
  fi
else
  reg_fail "B: restricted Launcher create failed: $(printf '%s' "$B_OUT" | head -2 | tr '\n' ' ' | redact)"
  WORK_ID=""
fi

# A restricted root outside the global user-mode ceiling is still refused.
# The candidate is a REAL, policy-legal directory (a sibling of the global
# root under the permitted /home namespace, owned by the UAT user), so the
# rejection proves the effective-ceiling check rather than a workspace-path
# policy rejection or a nonexistent path.
B_OUTSIDE="/home/${U_USER}-outside"
mkdir -p "$B_OUTSIDE" && chown "$U_USER:$U_USER" "$B_OUTSIDE"
B_OUT="$(dhx launcher create --principal "$OWNER" --name bad --allowed-root "$B_OUTSIDE" --no-credential 2>&1)"
if [ "$?" -ne 0 ] && printf '%s' "$B_OUT" | grep -q 'code outside_principal_root'; then
  reg_ok "B: restricted Launcher create outside the global ceiling is refused with outside_principal_root"
else
  reg_fail "B: restricted Launcher create outside the global ceiling not refused with outside_principal_root: $(printf '%s' "$B_OUT" | head -2 | tr '\n' ' ' | redact)"
fi

# --- C. restricted-scope conversion of an inherit Launcher -------------------

C_OUT="$(dhx launcher create --principal "$OWNER" --name conv --no-credential 2>&1)"
if [ -n "$(printf '%s' "$C_OUT" | uer_field id || true)" ]; then
  # `launcher scope set` always emits the launcher JSON document.
  if C_SHOW="$(dhx launcher scope set --principal "$OWNER" --allowed-root "$WORK" conv 2>&1)" \
      && [ "$(printf '%s' "$C_SHOW" | uer_field scope)" = "restricted" ] \
      && printf '%s' "$C_SHOW" | grep -q "\"allowed_roots\": \[\"$WORK\"\]"; then
    reg_ok "C: inherit -> restricted scope replacement succeeds and returns the committed scope and root"
  else
    reg_fail "C: inherit -> restricted scope replacement failed: $(printf '%s' "$C_SHOW" | head -2 | tr '\n' ' ' | redact)"
  fi
else
  reg_fail "C: inherit Launcher create failed: $(printf '%s' "$C_OUT" | head -2 | tr '\n' ' ' | redact)"
fi

# --- D. Session under the restricted Launcher --------------------------------

uer_session_run() {
  local what="$1" ws json sid tok run_out
  ws="$2"
  if ! json="$(dhx session create --workspace "$ws" --launcher "$WORK_ID" --json 2>"$TMPDIR_UER/sess.err")"; then
    reg_fail "$what: session create under the restricted Launcher failed: $(head -2 "$TMPDIR_UER/sess.err" 2>/dev/null | tr '\n' ' ' | redact)"
    return
  fi
  sid="$(printf '%s' "$json" | uer_field id)"
  tok="$(printf '%s' "$json" | uer_field token)"
  if [ -z "$sid" ] || [ -z "$tok" ]; then
    reg_fail "$what: session create returned no identity"
    return
  fi
  if run_out="$(sudo -u "$U_USER" "${U_ENV[@]}" DOCKER_HELPER_SESSION_TOKEN="$tok" \
      /usr/bin/docker-helper run --image alpine:3.24 -- sh -ec 'echo UER-RUN-OK' 2>&1)" \
      && printf '%s' "$run_out" | grep -q 'UER-RUN-OK'; then
    reg_ok "$what: Session inside the restricted root ran a trivial container ($sid)"
  else
    reg_fail "$what: trivial container run failed: $(printf '%s' "$run_out" | head -2 | tr '\n' ' ' | redact)"
  fi
  dhx session delete --id "$sid" >/dev/null 2>&1 || true
}

if [ -n "$WORK_ID" ]; then
  uer_session_run "D inside restriction" "$WORK/proj"

  # A workspace inside the global root but outside the Launcher restriction
  # is rejected with the stable workspace code.
  D_OUT="$(dhx session create --workspace "$WS" --launcher "$WORK_ID" --json 2>&1)"
  if [ "$?" -ne 0 ] && printf '%s' "$D_OUT" | grep -q 'code invalid_workspace'; then
    reg_ok "D: workspace outside the Launcher restriction (inside the global root) is rejected with invalid_workspace"
  else
    reg_fail "D: workspace outside the Launcher restriction not rejected with invalid_workspace: $(printf '%s' "$D_OUT" | head -2 | tr '\n' ' ' | redact)"
  fi
fi

# --- E. the reserved default Launcher is still not restrictable --------------

E_OUT="$(dhx launcher scope set --principal "$OWNER" --allowed-root "$WORK" default 2>&1)"
if [ "$?" -ne 0 ] && printf '%s' "$E_OUT" | grep -q 'code user_mode_owner_reserved'; then
  reg_ok "E: the reserved default Launcher still refuses a restricted scope (user_mode_owner_reserved)"
else
  reg_fail "E: the reserved default Launcher not refused with user_mode_owner_reserved: $(printf '%s' "$E_OUT" | head -2 | tr '\n' ' ' | redact)"
fi

rm -rf "$TMPDIR_UER"
reg_result
