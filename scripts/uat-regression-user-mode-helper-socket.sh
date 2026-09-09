#!/usr/bin/env bash
#
# uat-regression-user-mode-helper-socket.sh — 2.1.1 targeted regression
# group 18: helper_socket fail-closed on a REAL user-mode daemon
# (Ubuntu / tarball / AppArmor, but the capability decision is
# installation-independent).
#
# The shipped unit test only proves the handler classification; this group
# proves the contract black-box on a running user-mode daemon (its own
# initialized and started daemon, never the system service):
#
#   A. ordinary user-mode run keeps working: a session creates and a trivial
#      container runs, and the workload does NOT see any helper runtime
#      projection (no /run/docker-helper inside the container);
#   B. the same daemon rejects `docker-helper run --helper-socket ...`
#      fail-closed with the stable public code `invalid_helper_socket`;
#   C. the workload/container does not start: no container exists for the
#      session and the user-mode daemon never logged a run.start for the
#      rejected request (no run Operation is created);
#   D. an ordinary run still succeeds afterwards (the fail-closed check did
#      not disturb the unchanged user-mode run contract).
#
# Requires: installed docker-helper binary, root (user/XDG-runtime setup),
# Docker (trivial container run). The system service is NOT required and is
# stopped for the duration so the user-mode daemon is unambiguous.
# Exits 0 = PASS, 1 = FAIL, 2 = BLOCKED (see uat-regression-lib.sh).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/uat-regression-lib.sh
source "$SCRIPT_DIR/uat-regression-lib.sh"

reg_init "18. User-mode helper_socket fail-closed"

reg_require_root
reg_require_docker
reg_require_cmd curl "health probing of the user-mode daemon"
reg_require_cmd sudo "the user-mode daemon runs as a non-root user"

TMPDIR_UHS="/tmp/uat-reg18"
mkdir -p "$TMPDIR_UHS"

U_USER="uatreg18"
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
  rm -rf "$TMPDIR_UHS"
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
# (the same `env -i` discipline as group 12: no inherited runner state).
U_ENV=(env -i "HOME=$U_HOME" "XDG_RUNTIME_DIR=$U_XDG" \
  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")

# dhx runs docker-helper as the user-mode daemon owner against the user socket.
dhx() { sudo -u "$U_USER" "${U_ENV[@]}" /usr/bin/docker-helper "$@"; }

if dhx init --allowed-root "$U_HOME" >"$TMPDIR_UHS/init.log" 2>&1; then
  reg_ok "user-mode init succeeded for $U_USER"
else
  reg_fail "user-mode init failed (see $TMPDIR_UHS/init.log)"
  sed 's/^/    init-log: /' "$TMPDIR_UHS/init.log" 2>/dev/null | redact | tail -15 >&2
  reg_result
fi

# User-mode audit is disabled by default (it derives from log_level); this
# group's no-Operation proof needs the audit stream, so enable it explicitly.
if dhx config set audit_enabled true >"$TMPDIR_UHS/audit.log" 2>&1; then
  reg_ok "user-mode audit_enabled=true set for the group's audit assertions"
else
  reg_fail "user-mode config set audit_enabled failed (see $TMPDIR_UHS/audit.log)"
  reg_result
fi

U_SOCK="$U_XDG/docker-helper/docker-helper.sock"
# The redirect lands on sudo's child (the daemon); sudo itself is quiet.
# shellcheck disable=SC2024
sudo -u "$U_USER" "${U_ENV[@]}" /usr/bin/docker-helper serve >"$TMPDIR_UHS/serve.log" 2>&1 &
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
  reg_fail "user-mode daemon did not become ready (see $TMPDIR_UHS/serve.log)"
  reg_result
fi

WS="$U_HOME/ws"

# --- A. ordinary user-mode run keeps working, no helper projection ----------
A_JSON="$(dhx session create --workspace "$WS" --json 2>"$TMPDIR_UHS/a-sess.err")" \
  || { reg_fail "A: user-mode session create failed: $(head -2 "$TMPDIR_UHS/a-sess.err" 2>/dev/null | tr '\n' ' ' | redact)"; reg_result; }
A_SID="$(printf '%s' "$A_JSON" | json_field id)"
A_TOK="$(printf '%s' "$A_JSON" | json_field token)"
[ -n "$A_SID" ] && [ -n "$A_TOK" ] || { reg_fail "A: session create returned no identity"; reg_result; }

A_OUT="$(sudo -u "$U_USER" "${U_ENV[@]}" DOCKER_HELPER_SESSION_TOKEN="$A_TOK" \
  /usr/bin/docker-helper run --image alpine:3.24 \
  -- sh -ec 'echo U18-RUN-OK; test ! -e /run/docker-helper && echo U18-NO-PROJECTION' 2>&1)"
if printf '%s' "$A_OUT" | grep -q 'U18-RUN-OK'; then
  reg_ok "A: ordinary user-mode run works without --helper-socket"
else
  reg_fail "A: ordinary user-mode run failed: $(printf '%s' "$A_OUT" | head -3 | tr '\n' ' ' | redact)"
fi
if printf '%s' "$A_OUT" | grep -q 'U18-NO-PROJECTION'; then
  reg_ok "A: workload without the capability sees no helper runtime projection"
else
  reg_fail "A: workload without the capability saw a helper runtime projection"
fi

# --- B. --helper-socket fails closed with invalid_helper_socket ---------------
# The successful A-run emitted one run.start; the rejected request must not
# add another one (no run Operation is created for it).
STARTS_BEFORE="$(grep -c '"event":"run.start"' "$TMPDIR_UHS/serve.log" 2>/dev/null || true)"
B_OUT="$(sudo -u "$U_USER" "${U_ENV[@]}" DOCKER_HELPER_SESSION_TOKEN="$A_TOK" \
  /usr/bin/docker-helper run --image alpine:3.24 --helper-socket -- true 2>&1)"
B_RC=$?
if [ "$B_RC" -ne 0 ] && printf '%s' "$B_OUT" | grep -q 'code invalid_helper_socket'; then
  reg_ok "B: --helper-socket rejected by the user-mode daemon (invalid_helper_socket, rc=$B_RC)"
else
  reg_fail "B: --helper-socket not rejected with invalid_helper_socket (rc=$B_RC, out: $(printf '%s' "$B_OUT" | head -3 | tr '\n' ' ' | redact))"
fi

# --- C. no workload started, no run Operation created -------------------------
C_CONTAINERS="$(docker ps -q --filter "label=com.dockerhelper.session.id=$A_SID" 2>/dev/null || true)"
if [ -z "$C_CONTAINERS" ]; then
  reg_ok "C: no container exists for the session after the rejection"
else
  reg_fail "C: a container started for the rejected helper_socket request"
fi
sleep 2
STARTS_AFTER="$(grep -c '"event":"run.start"' "$TMPDIR_UHS/serve.log" 2>/dev/null || true)"
if [ "$STARTS_AFTER" = "$STARTS_BEFORE" ]; then
  reg_ok "C: the rejected request created no run Operation (run.start count unchanged: $STARTS_AFTER)"
else
  reg_fail "C: the rejected request created a run Operation (run.start $STARTS_BEFORE -> $STARTS_AFTER)"
fi
if grep -q '"result":"invalid_helper_socket"' "$TMPDIR_UHS/serve.log" 2>/dev/null; then
  reg_ok "C: the rejection was classified at daemon policy (run.rejected invalid_helper_socket)"
else
  reg_fail "C: no run.rejected invalid_helper_socket classification in the daemon audit"
fi

# --- D. ordinary run still works after the fail-closed rejection ---------------
D_OUT="$(sudo -u "$U_USER" "${U_ENV[@]}" DOCKER_HELPER_SESSION_TOKEN="$A_TOK" \
  /usr/bin/docker-helper run --image alpine:3.24 -- sh -ec 'echo U18-AFTER-OK' 2>&1)"
if printf '%s' "$D_OUT" | grep -q 'U18-AFTER-OK'; then
  reg_ok "D: ordinary user-mode run still works after the rejection"
else
  reg_fail "D: ordinary user-mode run broke after the rejection: $(printf '%s' "$D_OUT" | head -3 | tr '\n' ' ' | redact)"
fi

dhx session delete --id "$A_SID" >/dev/null 2>&1 || true

reg_result
