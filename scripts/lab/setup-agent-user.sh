#!/usr/bin/env bash
#
# setup-agent-user.sh — provision the dedicated 'agent' account INSIDE the
# local lab VM.
#
# Run as root in the GUEST (the VM's opc account has passwordless sudo). The
# script refuses to run on the physical host: it requires the lab marker
# written by the trusted VM bootstrap (scripts/dev-vm-local.sh) and verifies
# that the marker's embedded machine-id matches the running system.
#
#   # from the physical host, with the lab scripts copied into the VM:
#   scripts/dev-vm-local.sh ssh 'sudo bash /opt/lab/setup-agent-user.sh'
#
# "host" below means the GUEST VM; the physical host's /etc, /home, SSH config
# and docker-helper config are not touched.
#
# Idempotent. It:
#   1. creates the 'agent' account and its workspace root, and adds it to the
#      'docker' group (the trusted launcher drives `docker run`);
#   2. ensures a global allowed root covers the agent home;
#   3. creates the docker-helper principal 'agent' (its 'default' Launcher and
#      default allowed root are provisioned atomically with it), issues a
#      principal credential and installs it, as the agent account, into
#      ~agent/.config/docker-helper/credential.token (never printed);
#   4. installs scripts/lab/agent-aliases.sh as ~agent/.bash_aliases and sources
#      it from ~agent/.bashrc.
#
# It does NOT manage SSH keys: VM access stays with the dev-vm-local.sh SSH
# identity, and the agent account gets no SSH of its own.
#
# Env overrides: AGENT_USER, AGENT_HOME, AGENT_WORKROOT, AGENT_DOCKER_GROUP,
#                LAB_VM_MARKER, LAB_VM_MARKER_TAG.
set -euo pipefail

AGENT_USER="${AGENT_USER:-agent}"
AGENT_HOME="${AGENT_HOME:-/home/$AGENT_USER}"
AGENT_WORKROOT="${AGENT_WORKROOT:-$AGENT_HOME/work}"
AGENT_DOCKER_GROUP="${AGENT_DOCKER_GROUP:-docker}"
LAB_VM_MARKER="${LAB_VM_MARKER:-/etc/docker-helper-lab-vm}"
LAB_VM_MARKER_TAG="${LAB_VM_MARKER_TAG:-docker-helper-lab-vm}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALIASES_SRC="$SCRIPT_DIR/agent-aliases.sh"

log() { printf '[setup-agent-user] %s\n' "$*"; }
die() { printf '[setup-agent-user] ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "must run as root in the guest (sudo bash $0)"

# --- 0. lab-VM guard (fail closed on the physical host) ---------------------
# The marker is written by the trusted VM bootstrap and carries the guest
# machine-id, so a stray copy on the physical host does not pass. KVM/QEMU
# presence alone is deliberately not trusted.
require_lab_vm() {
  [ -r "$LAB_VM_MARKER" ] \
    || die "not the lab VM: missing $LAB_VM_MARKER (created by scripts/dev-vm-local.sh)"
  local tag ver mid
  read -r tag ver mid _ < "$LAB_VM_MARKER" || die "malformed lab VM marker $LAB_VM_MARKER"
  [ "$tag" = "$LAB_VM_MARKER_TAG" ] || die "unexpected lab VM marker tag '$tag'"
  [ "$ver" = 1 ] || die "unsupported lab VM marker version '$ver'"
  [ -r /etc/machine-id ] || die "no /etc/machine-id to verify the marker"
  [ "$mid" = "$(cat /etc/machine-id)" ] || die "lab VM marker machine-id mismatch (physical host?)"
}
require_lab_vm

DH="$(command -v docker-helper)" || die "docker-helper not found in PATH"
command -v jq >/dev/null 2>&1 || die "jq not found in PATH"
[ -f "$ALIASES_SRC" ] || die "missing $ALIASES_SRC"

# --- 1. account, workspace root, docker access ------------------------------
# The 'agent' account is the trusted launcher, so it may hold docker access.
# The untrusted model is the container process and gets no docker group.
if id "$AGENT_USER" >/dev/null 2>&1; then
  log "account $AGENT_USER already exists"
else
  log "creating account $AGENT_USER"
  useradd -m -s /bin/bash -c "docker-helper agent launcher" "$AGENT_USER"
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

# --- 2. global allowed root (authorization ceiling) -------------------------
if "$DH" config allowed-root list 2>/dev/null | grep -qF "$AGENT_HOME"; then
  log "global allowed root already covers $AGENT_HOME"
else
  log "adding global allowed root $AGENT_HOME"
  "$DH" config allowed-root add "$AGENT_HOME" --access read_write
fi

# --- 3. create the principal / issue the credential (token captured once) ---
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

# --- 4. opencode home + launcher aliases -----------------------------------
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

log "done: account=$AGENT_USER home=$AGENT_HOME workroot=$AGENT_WORKROOT"
log "next: as $AGENT_USER, cd ~/work/<project>, then run: oc | oc-go26 | oc-dotnet10"
