#!/usr/bin/env bash
#
# integration-agent-vm.sh — REAL end-to-end checks inside the lab VM
# (SELinux enforcing, real dockerd + docker-helper v2.3.0, real container).
#
# Run as root in the guest, after install-docker-helper-v230.sh and
# setup-agent-user.sh have run. Complements the stubbed unit tests by entering
# through the real production paths.
#
# What it proves (one invariant per check):
#   1. the installed docker-helper is the pinned v2.3.0;
#   2. opc and agent have distinct uids and no duplicate-uid resolution;
#   3. the principal record matches the OS uid;
#   4. SELinux is enforcing, the daemon runs in docker_helper_t, the binary is
#      docker_helper_exec_t;
#   5. an existing valid credential is reused (no rotate);
#   6. a missing credential fails closed without rotating;
#   7. --recover-credential rotates (old bearer dies, new bearer lives);
#   8. the launcher creates one Session, runs the container as the agent uid,
#      and deletes the Session (no orphan);
#   9. the container argv carries the isolation posture and only the bearer;
#  10. the container can write the agent-owned OpenCode mounts.
#
# Env: EXPECT_VERSION (default 2.3.0), AGENT_USER (default agent).
set -u

EXPECT_VERSION="${EXPECT_VERSION:-2.3.0}"
AGENT_USER="${AGENT_USER:-agent}"
AGENT_HOME="/home/$AGENT_USER"
DH=/usr/bin/docker-helper
MARKER=/etc/docker-helper-lab-vm

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2' got '$3')"; fi; }
contains() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2' in '$3')" ;; esac; }
not_contains() { case "$3" in *"$2"*) bad "$1 (unexpected '$2')" ;; *) ok "$1" ;; esac; }

[ "$(id -u)" = 0 ] || { echo "must run as root in the guest" >&2; exit 1; }
[ -r "$MARKER" ] || { echo "missing $MARKER (run dev-vm-local.sh first)" >&2; exit 1; }

# --- 1. pinned version ------------------------------------------------------
check "docker-helper version is v$EXPECT_VERSION" "$EXPECT_VERSION" "$("$DH" version)"

# --- 2. uid uniqueness ------------------------------------------------------
opc_uid="$(id -u opc)"
agent_uid="$(id -u "$AGENT_USER")"
if [ "$opc_uid" != "$agent_uid" ]; then ok "opc and agent uids differ ($opc_uid vs $agent_uid)"; else bad "uid collision: both $opc_uid"; fi
check "getent resolves the agent uid to $AGENT_USER" "$AGENT_USER" "$(getent passwd "$agent_uid" | cut -d: -f1)"
check "getent resolves the opc uid to opc" "opc" "$(getent passwd "$opc_uid" | cut -d: -f1)"

# --- 3. principal record matches the OS uid ---------------------------------
p_uid="$("$DH" principal show "$AGENT_USER" --json | jq -r '.uid')"
check "principal record uid matches the OS uid" "$agent_uid" "$p_uid"

# --- 4. SELinux -------------------------------------------------------------
check "SELinux enforcing" "Enforcing" "$(getenforce)"
contains "daemon runs in docker_helper_t" "docker_helper_t" "$(ps -o label= -C docker-helper | head -1)"
contains "binary carries docker_helper_exec_t" "docker_helper_exec_t" "$(ls -Z "$DH")"
check "docker_helper policy module loaded" "docker_helper" "$(semodule -l | awk '/^docker_helper/ {print $1}')"

# --- 5. valid credential reused --------------------------------------------
: > /tmp/itest-setup.out
bash /opt/lab/setup-agent-user.sh >/tmp/itest-setup.out 2>&1 && ok "idempotent setup succeeds" || bad "idempotent setup failed"
contains "valid credential reused" "reusing the installed credential" "$(cat /tmp/itest-setup.out)"
not_contains "reuse does not rotate" "recovering credential" "$(cat /tmp/itest-setup.out)"

# --- 6/7. fail-closed then explicit recovery --------------------------------
CRED="$AGENT_HOME/.config/docker-helper/credential.token"
old_id="$("$DH" principal credential list "$AGENT_USER" --json | jq -r '.credentials[0].id')"
cp "$CRED" /tmp/itest-cred.bak
rm "$CRED"
if bash /opt/lab/setup-agent-user.sh >/tmp/itest-fc.out 2>&1; then bad "missing credential was accepted"; else ok "missing credential fails closed"; fi
check "fail-closed did not rotate (same credential id)" "$old_id" "$("$DH" principal credential list "$AGENT_USER" --json | jq -r '.credentials[0].id')"
bash /opt/lab/setup-agent-user.sh --recover-credential >/tmp/itest-rec.out 2>&1 && ok "recovery succeeds" || bad "recovery failed"
check "rotate keeps the credential id" "$old_id" "$("$DH" principal credential list "$AGENT_USER" --json | jq -r '.credentials[0].id')"
if "$DH" self --token-file /tmp/itest-cred.bak >/dev/null 2>&1; then bad "old bearer still valid after rotate"; else ok "old bearer invalidated by rotate"; fi
sudo -u "$AGENT_USER" "$DH" self --json >/tmp/itest-self.out 2>&1 && ok "new bearer authenticates" || bad "new bearer rejected"
contains "self reports the agent principal" '"type": "principal"' "$(cat /tmp/itest-self.out)"

# --- 8/9/10. real launcher end-to-end ---------------------------------------
ws="$AGENT_HOME/work/itest"
install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$ws"
SHIM=/tmp/itest-shim; rm -rf "$SHIM"; mkdir -p "$SHIM"
cat > "$SHIM/docker-helper" <<'SH'
#!/bin/sh
printf 'DH %s\n' "$*" >> "$ARGV_REC"
exec /usr/bin/docker-helper "$@"
SH
chmod +x "$SHIM/docker-helper"
RUNNER=/tmp/itest-run.sh
cat > "$RUNNER" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
export PATH="$SHIM_DIR:$PATH"
cd "$1"
docker() { printf '%s\n' "$*" >> "$ARGV_REC"; command docker "$@"; }
# shellcheck source=/dev/null
source "$HOME/.bash_aliases"
oc --version
SH
ARGV=/tmp/itest-argv; : > "$ARGV"; chmod 0666 "$ARGV"
set +e
sudo -u "$AGENT_USER" env ARGV_REC="$ARGV" SHIM_DIR="$SHIM" \
  script -qec "bash $RUNNER $ws" /dev/null >/tmp/itest-oc.out 2>&1
set -e
oc_rc=$?
if [ "$oc_rc" = 0 ]; then ok "launcher exited 0"; else bad "launcher exited $oc_rc"; fi
grep -Eq '[0-9]+\.[0-9]+\.[0-9]+' /tmp/itest-oc.out && ok "container ran opencode (version printed)" || bad "no opencode version in output"

argv="$(cat "$ARGV")"
contains "launcher created a Session" "DH session create" "$argv"
contains "launcher deleted the Session" "DH session delete" "$argv"
contains "container runs as the agent uid" "--user $(id -u "$AGENT_USER"):$(id -g "$AGENT_USER")" "$argv"
contains "container drops caps" "--cap-drop ALL" "$argv"
contains "container sets no-new-privileges" "no-new-privileges=true" "$argv"
contains "container runs in docker_helper_container_t" "label=type:docker_helper_container_t" "$argv"
contains "workspace is a private relabel" ":/workspace:Z" "$argv"
contains "opencode .local is agent-owned" "/.local:/home/opencode/.local:Z" "$argv"
contains "helper runtime dir is read-only" "/run/docker-helper:ro" "$argv"
contains "container gets only the session bearer env" "-e DOCKER_HELPER_SESSION_TOKEN" "$argv"
not_contains "container has no docker.sock" "docker.sock" "$argv"
not_contains "container has no admin token" "ADMIN" "$argv"
not_contains "container has no principal credential" "/.config/docker-helper" "$argv"

n_sessions="$(sudo -u "$AGENT_USER" "$DH" session list --json | jq '.sessions | length')"
check "no orphan Session after launch" "0" "$n_sessions"

# the container wrote the agent-owned state tree (mount writability across uid)
if [ -n "$(find "$AGENT_HOME/.opencode-docker/.local" -mindepth 1 2>/dev/null)" ]; then
  ok "container wrote the agent-owned .local tree"
else
  bad "container did not write the agent-owned .local tree"
fi

echo
printf 'agent VM integration: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
