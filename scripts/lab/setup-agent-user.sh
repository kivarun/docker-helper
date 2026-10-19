#!/usr/bin/env bash
#
# setup-agent-user.sh — provision a dedicated local 'agent' Linux user that can
# run opencode-docker agents through docker-helper.
#
# Run as root on the docker-helper host (openSUSE Tumbleweed):
#
#   sudo bash scripts/lab/setup-agent-user.sh
#
# Idempotent. It:
#   1. creates the 'agent' user and its workspace root, and adds it to the
#      'docker' group (the launcher runs `docker run`);
#   2. installs the given SSH public key for root and for agent;
#   3. ensures a global allowed root covers the agent home;
#   4. creates the docker-helper principal 'agent' (its 'default' Launcher and
#      default allowed root are provisioned atomically with it), issues a
#      principal credential and installs it, as the agent user, into
#      ~agent/.config/docker-helper/credential.token (never printed);
#   5. installs scripts/lab/agent-aliases.sh as ~agent/.bash_aliases and sources
#      it from ~agent/.bashrc.
#
# The agent then launches agents with `oc`, `oc-go26`, `oc-dotnet10` from a
# workspace below ~/work.
#
# Env overrides: AGENT_USER, AGENT_HOME, AGENT_WORKROOT, AGENT_DOCKER_GROUP,
#                AGENT_PUBKEY.
set -euo pipefail

AGENT_USER="${AGENT_USER:-agent}"
AGENT_HOME="${AGENT_HOME:-/home/$AGENT_USER}"
AGENT_WORKROOT="${AGENT_WORKROOT:-$AGENT_HOME/work}"
AGENT_DOCKER_GROUP="${AGENT_DOCKER_GROUP:-docker}"
AGENT_PUBKEY="${AGENT_PUBKEY:-ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICbxCMSaYTbiml8YqWkJcoTOQBmRcyzQBtUZskk5JgML michael@kazakov}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALIASES_SRC="$SCRIPT_DIR/agent-aliases.sh"

log() { printf '[setup-agent-user] %s\n' "$*"; }
die() { printf '[setup-agent-user] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root (sudo bash $0)"

DH="$(command -v docker-helper)" || die "docker-helper not found in PATH"
command -v jq >/dev/null 2>&1 || die "jq not found in PATH"
[ -f "$ALIASES_SRC" ] || die "missing $ALIASES_SRC"

# --- 1. user, workspace root, docker access --------------------------------
if id "$AGENT_USER" >/dev/null 2>&1; then
  log "user $AGENT_USER already exists"
else
  log "creating user $AGENT_USER"
  useradd -m -s /bin/bash -c "docker-helper agent" "$AGENT_USER"
fi

install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_WORKROOT"

if getent group "$AGENT_DOCKER_GROUP" >/dev/null 2>&1; then
  if id -nG "$AGENT_USER" | tr ' ' '\n' | grep -qx "$AGENT_DOCKER_GROUP"; then
    log "$AGENT_USER already in group $AGENT_DOCKER_GROUP"
  else
    log "adding $AGENT_USER to group $AGENT_DOCKER_GROUP"
    usermod -aG "$AGENT_DOCKER_GROUP" "$AGENT_USER"
  fi
else
  log "WARN: group $AGENT_DOCKER_GROUP missing; add it before launching agents"
fi

# --- 2. ssh key for root and agent -----------------------------------------
install_key() { # <home> <owner>
  local home="$1" owner="$2"
  install -d -m 0700 -o "$owner" -g "$owner" "$home/.ssh"
  [ -f "$home/.ssh/authorized_keys" ] || : > "$home/.ssh/authorized_keys"
  chown "$owner:$owner" "$home/.ssh/authorized_keys"
  chmod 0600 "$home/.ssh/authorized_keys"
  if grep -qxF "$AGENT_PUBKEY" "$home/.ssh/authorized_keys"; then
    log "ssh key already present for $owner"
  else
    log "adding ssh key for $owner"
    printf '%s\n' "$AGENT_PUBKEY" >> "$home/.ssh/authorized_keys"
  fi
}
install_key /root root
install_key "$AGENT_HOME" "$AGENT_USER"

# --- 3. global allowed root (authorization ceiling) -------------------------
if "$DH" config allowed-root list 2>/dev/null | grep -qF "$AGENT_HOME"; then
  log "global allowed root already covers $AGENT_HOME"
else
  log "adding global allowed root $AGENT_HOME"
  "$DH" config allowed-root add "$AGENT_HOME" --access read_write
fi

# --- 4. create the principal / issue the credential (token captured once) ---
CRED_FILE="$AGENT_HOME/.config/docker-helper/credential.token"
TOKEN=""
if "$DH" principal show "$AGENT_USER" >/dev/null 2>&1; then
  log "principal $AGENT_USER already exists"
  if [ -f "$CRED_FILE" ]; then
    log "credential already installed at $CRED_FILE"
  else
    log "issuing a credential for the existing principal $AGENT_USER"
    TOKEN="$("$DH" principal credential create "$AGENT_USER" --json | jq -er '.token')"
  fi
else
  log "creating principal $AGENT_USER (default Launcher + default allowed root)"
  TOKEN="$("$DH" principal create "$AGENT_USER" --issue-credential --json | jq -er '.token')"
fi

if [ -n "$TOKEN" ]; then
  install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_HOME/.config"
  printf '%s\n' "$TOKEN" | su -s /bin/bash "$AGENT_USER" -c "$DH credential install --force"
  unset TOKEN
  log "credential installed for $AGENT_USER"
fi

# --- 5. opencode home + launcher aliases -----------------------------------
install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" \
  "$AGENT_HOME/.opencode-docker/.config/opencode" \
  "$AGENT_HOME/.opencode-docker/.local/share/opencode"

install -m 0644 -o "$AGENT_USER" -g "$AGENT_USER" \
  "$ALIASES_SRC" "$AGENT_HOME/.bash_aliases"
if grep -qF '.bash_aliases' "$AGENT_HOME/.bashrc" 2>/dev/null; then
  log "$AGENT_HOME/.bashrc already sources .bash_aliases"
else
  log "wiring $AGENT_HOME/.bash_aliases into $AGENT_HOME/.bashrc"
  printf '\n# docker-helper agent launchers\n[ -f "$HOME/.bash_aliases" ] && . "$HOME/.bash_aliases"\n' \
    >> "$AGENT_HOME/.bashrc"
  chown "$AGENT_USER:$AGENT_USER" "$AGENT_HOME/.bashrc"
fi

log "done: user=$AGENT_USER home=$AGENT_HOME workroot=$AGENT_WORKROOT"
log "next: log in as $AGENT_USER, cd ~/work/<project>, then run: oc | oc-go26 | oc-dotnet10"
