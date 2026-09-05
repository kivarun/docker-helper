#!/usr/bin/env bash
#
# uat-regression-user-mode-owner-reservation.sh — Release-2.1 RC6 targeted
# regression group 11: user-mode transparent owner reservation
# (Ubuntu / DEB / AppArmor).
#
# Black-box acceptance coverage for the RC6 user-mode ownership blocker,
# exercised on a REAL user-mode installation (its own initialized and started
# user-mode daemon, never the system service):
#
#   A. transparent chain identification — the daemon-owner Principal and its
#      'default' Launcher are identified through the supported control paths
#      (principal show / launcher show) and match the transparent contract:
#      Principal enabled, UID/GID/home = OS identity, zero allowed roots;
#      Launcher enabled, name 'default', inherit scope, zero roots.
#   B. prohibited mutations — public control-plane mutations that would
#      corrupt the transparent ownership chain are rejected with the stable
#      409 user_mode_owner_reserved code and leave the chain unchanged:
#      Principal disable/delete/allowed-root add/allowed-root remove;
#      default Launcher disable/rename/delete/restricted scope.
#   C. harmless no-ops — re-enable of the enabled owner Principal, re-enable
#      of the enabled default Launcher, and re-assert of the inherit scope
#      remain ordinary successes.
#   D. non-reserved mutability — a second, differently named Launcher under
#      the daemon-owner Principal is still created/disabled/deleted normally.
#   E. current-runtime usability — after every rejection a normal
#      selector-less user-mode Session still resolves the cached default
#      chain and runs a trivial container successfully.
#   F. restart invariant — after killing and restarting the user-mode daemon
#      the startup contract still succeeds on the unchanged chain and a
#      normal selector-less Session still runs a trivial container.
#
# Requires: installed docker-helper binary, root (user/XDG-runtime setup),
# Docker (trivial container run). The system service is NOT required and is
# stopped for the duration so the user-mode daemon is unambiguous.
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "11. User-mode owner reservation"

reg_require_root
reg_require_docker
reg_require_cmd curl "health probing of the user-mode daemon"
reg_require_cmd sudo "the user-mode daemon runs as a non-root user"

TMPDIR_UMO="/tmp/uat-reg11"
mkdir -p "$TMPDIR_UMO"

U_USER="uatreg11"
U_SERVE_PID=""
U_XDG=""

cleanup() {
  if [ -n "$U_SERVE_PID" ]; then
    kill "$U_SERVE_PID" 2>/dev/null || true
    wait "$U_SERVE_PID" 2>/dev/null || true
  fi
  [ -n "$U_USER" ] && pkill -TERM -u "$U_USER" -f '/usr/bin/docker-helper serve' 2>/dev/null || true
  [ -n "$U_USER" ] && userdel -r "$U_USER" >/dev/null 2>&1 || true
  [ -n "$U_XDG" ] && rm -rf "$U_XDG" 2>/dev/null || true
  rm -rf "$TMPDIR_UMO"
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

if dhx init --allowed-root "$U_HOME" >"$TMPDIR_UMO/init.log" 2>&1; then
  reg_ok "user-mode init succeeded for $U_USER"
else
  reg_fail "user-mode init failed (see $TMPDIR_UMO/init.log)"
  sed 's/^/    init-log: /' "$TMPDIR_UMO/init.log" 2>/dev/null | redact | tail -15 >&2
  reg_result
fi

U_SOCK="$U_XDG/docker-helper/docker-helper.sock"
# The redirect lands on sudo's child (the daemon); sudo itself is quiet.
# shellcheck disable=SC2024
sudo -u "$U_USER" "${U_ENV[@]}" /usr/bin/docker-helper serve >"$TMPDIR_UMO/serve.log" 2>&1 &
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
  reg_fail "user-mode daemon did not become ready (see $TMPDIR_UMO/serve.log)"
  reg_result
fi

OWNER="$U_USER"
WS="$U_HOME/ws"

# um_field FIELD: parse a control-plane --json document field.
um_field() { json_field "$1"; }

# assert_owner_invariant WHAT: the transparent chain still matches the
# contract, observed through the supported control paths.
assert_owner_invariant() {
  local what="$1" p l
  if p="$(dhx principal show "$OWNER" --json 2>/dev/null)"; then
    if [ "$(printf '%s' "$p" | um_field enabled)" = "true" ] \
        && [ "$(printf '%s' "$p" | um_field uid)" = "$U_UID" ] \
        && [ "$(printf '%s' "$p" | um_field gid)" = "$(id -g "$U_USER")" ] \
        && printf '%s' "$p" | grep -q '"allowed_roots": \[\]'; then
      :
    else
      reg_fail "$what: daemon-owner Principal invariant violated: $(printf '%s' "$p" | head -6 | tr '\n' ' ')"
      return
    fi
  else
    reg_fail "$what: daemon-owner Principal show failed"
    return
  fi
  if l="$(dhx launcher show --principal "$OWNER" default --json 2>/dev/null)"; then
    if [ "$(printf '%s' "$l" | um_field enabled)" = "true" ] \
        && [ "$(printf '%s' "$l" | um_field name)" = "default" ] \
        && [ "$(printf '%s' "$l" | um_field scope)" = "inherit" ] \
        && printf '%s' "$l" | grep -q '"allowed_roots": \[\]'; then
      reg_ok "$what: transparent owner chain intact (Principal enabled/zero-roots, default Launcher enabled/inherit/zero-roots)"
    else
      reg_fail "$what: default Launcher invariant violated: $(printf '%s' "$l" | head -6 | tr '\n' ' ')"
    fi
  else
    reg_fail "$what: default Launcher show failed"
  fi
}

# expect_reserved WHAT CMD...: the mutation must fail with the stable code.
expect_reserved() {
  local what="$1"; shift
  local out rc
  out="$(dhx "$@" 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'code user_mode_owner_reserved'; then
    reg_ok "$what: rejected with the stable user_mode_owner_reserved code"
  else
    reg_fail "$what: not rejected with user_mode_owner_reserved (rc=$rc): $(printf '%s' "$out" | head -2 | tr '\n' ' ' | redact)"
  fi
}

# um_session_run WHAT: a normal selector-less user-mode Session resolves the
# transparent default chain and runs a trivial container.
um_session_run() {
  local what="$1" json sid tok ldefault run_out
  if ! json="$(dhx session create --workspace "$WS" --json 2>"$TMPDIR_UMO/sess.err")"; then
    reg_fail "$what: selector-less session create failed: $(head -2 "$TMPDIR_UMO/sess.err" 2>/dev/null | tr '\n' ' ' | redact)"
    return
  fi
  sid="$(printf '%s' "$json" | um_field id)"
  tok="$(printf '%s' "$json" | um_field token)"
  ldefault="$(printf '%s' "$json" | um_field launcher)"
  if [ -z "$sid" ] || [ -z "$tok" ] || [ "$ldefault" != "default" ]; then
    reg_fail "$what: session is not owned by the transparent default chain: id=$sid launcher=$ldefault"
    return
  fi
  if run_out="$(sudo -u "$U_USER" "${U_ENV[@]}" DOCKER_HELPER_SESSION_TOKEN="$tok" \
      /usr/bin/docker-helper run --image alpine:3.24 -- sh -ec 'echo UMO-RUN-OK' 2>&1)" \
      && printf '%s' "$run_out" | grep -q 'UMO-RUN-OK'; then
    reg_ok "$what: selector-less Session ran a trivial container ($sid)"
  else
    reg_fail "$what: trivial container run failed: $(printf '%s' "$run_out" | head -2 | tr '\n' ' ' | redact)"
  fi
  dhx session delete --id "$sid" >/dev/null 2>&1 || true
}

# --- A. transparent chain identification -------------------------------------

assert_owner_invariant "A identify"

# --- B. prohibited mutations are rejected, state unchanged -------------------

expect_reserved "B principal disable"  principal set "$OWNER" enabled false
expect_reserved "B principal delete"   principal delete "$OWNER"
expect_reserved "B principal allowed-root add"    principal allowed-root add "$OWNER" "$WS"
expect_reserved "B principal allowed-root remove" principal allowed-root remove "$OWNER" "$WS"
expect_reserved "B default launcher disable"      launcher set --principal "$OWNER" --enabled false default
expect_reserved "B default launcher rename"       launcher set --principal "$OWNER" --name moved default
expect_reserved "B default launcher delete"       launcher delete --principal "$OWNER" default
expect_reserved "B default launcher restricted"   launcher scope set --principal "$OWNER" --allowed-root "$WS" default
assert_owner_invariant "B after rejections"

# --- C. harmless no-ops remain coherent --------------------------------------

if dhx principal set "$OWNER" enabled true >/dev/null 2>&1 \
    && dhx launcher set --principal "$OWNER" --enabled true default >/dev/null 2>&1 \
    && dhx launcher scope set --principal "$OWNER" --inherit default >/dev/null 2>&1; then
  reg_ok "C: invariant-preserving no-ops remain ordinary successes"
else
  reg_fail "C: an invariant-preserving no-op was rejected"
fi
assert_owner_invariant "C after no-ops"

# --- D. non-reserved Launcher mutability under the same Principal ------------

second_out="$(dhx launcher create --principal "$OWNER" --name second --no-credential 2>&1)"
second_id="$(printf '%s' "$second_out" | um_field id || true)"
if [ -n "$second_id" ]; then
  if dhx launcher set --principal "$OWNER" --enabled false "$second_id" >/dev/null 2>&1 \
      && dhx launcher delete --principal "$OWNER" "$second_id" >/dev/null 2>&1; then
    reg_ok "D: second Launcher under the daemon-owner Principal is still mutable"
  else
    reg_fail "D: second Launcher mutation failed"
  fi
else
  reg_fail "D: second Launcher create failed: $(printf '%s' "$second_out" | head -2 | tr '\n' ' ' | redact)"
fi

# --- E. current-runtime usability after rejections ---------------------------

um_session_run "E current runtime"

# --- F. restart invariant ----------------------------------------------------

kill "$U_SERVE_PID" 2>/dev/null || true
wait "$U_SERVE_PID" 2>/dev/null || true
U_SERVE_PID=""
pkill -TERM -u "$U_USER" -f '/usr/bin/docker-helper serve' 2>/dev/null || true
U_RESTARTED=0
for _ in $(seq 1 100); do
  if ! curl --silent --fail --max-time 1 --unix-socket "$U_SOCK" http://localhost/health >/dev/null 2>&1; then
    U_RESTARTED=1; break
  fi
  sleep 0.2
done
if [ "$U_RESTARTED" = 1 ]; then
  reg_ok "F: user-mode daemon stopped for restart"
else
  reg_fail "F: user-mode daemon still answering after stop"
fi

# The redirect lands on sudo's child (the daemon); sudo itself is quiet.
# shellcheck disable=SC2024
sudo -u "$U_USER" "${U_ENV[@]}" /usr/bin/docker-helper serve >"$TMPDIR_UMO/serve2.log" 2>&1 &
U_SERVE_PID=$!
U_READY2=0
for _ in $(seq 1 100); do
  if [ -S "$U_SOCK" ] && curl --silent --fail --max-time 1 --unix-socket "$U_SOCK" http://localhost/health >/dev/null 2>&1; then
    U_READY2=1; break
  fi
  sleep 0.2
done
if [ "$U_READY2" = 1 ]; then
  reg_ok "F: restarted user-mode daemon healthy (startup contract still succeeds)"
else
  reg_fail "F: restarted user-mode daemon did not become ready (see $TMPDIR_UMO/serve2.log)"
  sed 's/^/    serve2-log: /' "$TMPDIR_UMO/serve2.log" 2>/dev/null | redact | tail -15 >&2
  reg_result
fi
assert_owner_invariant "F restarted chain"
um_session_run "F restarted daemon"

rm -rf "$TMPDIR_UMO"
reg_result
