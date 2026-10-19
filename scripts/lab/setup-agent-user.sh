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
# The agent account gets a DEDICATED uid (default 1001), distinct from the
# admin account (uid 1000). The opencode-docker image runs as uid 1000, so the
# launchers pass --user "$(id -u):$(id -g)" and bind-mount the agent-owned
# OpenCode state directories; the container identity then matches the guest
# account and the mounts stay writable without loosening SELinux/DAC.
#
# Credential lifecycle: a fresh principal is created with an issued credential;
# an existing principal reuses its installed credential when that credential
# still authenticates. A missing (or non-authenticating) local credential is
# NOT rotated implicitly -- --recover-credential performs the explicit rotate.
#
# Usage: setup-agent-user.sh [--recover-credential]
#
# Env overrides: AGENT_USER, AGENT_HOME, AGENT_WORKROOT, AGENT_DOCKER_GROUP,
#                AGENT_UID, LAB_VM_MARKER, LAB_VM_MARKER_TAG.
set -euo pipefail

AGENT_USER="${AGENT_USER:-agent}"
AGENT_HOME="${AGENT_HOME:-/home/$AGENT_USER}"
AGENT_WORKROOT="${AGENT_WORKROOT:-$AGENT_HOME/work}"
AGENT_DOCKER_GROUP="${AGENT_DOCKER_GROUP:-docker}"
AGENT_UID="${AGENT_UID:-1001}"
LAB_VM_MARKER="${LAB_VM_MARKER:-/etc/docker-helper-lab-vm}"
LAB_VM_MARKER_TAG="${LAB_VM_MARKER_TAG:-docker-helper-lab-vm}"

RECOVER_CREDENTIAL=0
for arg in "$@"; do
  case "$arg" in
    --recover-credential) RECOVER_CREDENTIAL=1 ;;
    *) die "unknown argument '$arg' (only --recover-credential)" ;;
  esac
done

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
# The untrusted model is the container process and gets no docker group. The
# agent uid is dedicated (never the admin account's), so DAC never conflates
# the two accounts.
if id "$AGENT_USER" >/dev/null 2>&1; then
  current_uid="$(id -u "$AGENT_USER")"
  if [ "$current_uid" != "$AGENT_UID" ]; then
    log "migrating account $AGENT_USER uid $current_uid -> $AGENT_UID"
    # usermod -u also rewrites ownership of the account's home tree; the
    # explicit chown below re-normalizes any leftover ownership. Existing
    # credential content is unaffected (the daemon matches the token hash,
    # not the uid).
    usermod -u "$AGENT_UID" "$AGENT_USER"
  else
    log "account $AGENT_USER already exists (uid $current_uid)"
  fi
else
  log "creating account $AGENT_USER (uid $AGENT_UID, distinct from the admin account)"
  useradd -u "$AGENT_UID" -m -s /bin/bash -c "docker-helper agent launcher" "$AGENT_USER"
fi

# Normalize ownership of the whole home: covers a uid migration and any
# pre-existing parent left at its old owner by `install -d`.
chown -R "$AGENT_USER:$AGENT_USER" "$AGENT_HOME"

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

# --- 3. principal + credential (fail-closed; explicit recovery) -------------
# The daemon stores only the token hash. An existing local credential is reused
# when it still authenticates; a missing or non-authenticating one is NOT
# rotated implicitly (that would silently invalidate any other copy of the
# bearer). --recover-credential performs the explicit rotate.
CRED_FILE="$AGENT_HOME/.config/docker-helper/credential.token"

credential_valid() {
  local out
  out="$(su -s /bin/bash "$AGENT_USER" -c "$DH self --json" 2>/dev/null)" || return 1
  printf '%s' "$out" | jq -e 'select(.ok == true and .type == "principal")' >/dev/null 2>&1
}

install_token() { # token in $1 (never printed)
  install -d -m 0700 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_HOME/.config"
  printf '%s\n' "$1" | su -s /bin/bash "$AGENT_USER" -c "$DH credential install --force"
}

if "$DH" principal show "$AGENT_USER" >/dev/null 2>&1; then
  if [ "$RECOVER_CREDENTIAL" = 1 ]; then
    log "recovering credential: rotating the $AGENT_USER default credential"
    TOKEN="$("$DH" principal credential rotate "$AGENT_USER" --json | jq -er '.token')"
    install_token "$TOKEN"
    unset TOKEN
    credential_valid || die "rotated credential does not authenticate"
    log "credential rotated and installed for $AGENT_USER"
  elif [ -f "$CRED_FILE" ]; then
    if credential_valid; then
      log "reusing the installed credential at $CRED_FILE"
    else
      die "principal $AGENT_USER exists and $CRED_FILE is present but does not authenticate; re-run with --recover-credential (rotates the bearer)"
    fi
  else
    die "principal $AGENT_USER exists but $CRED_FILE is missing; re-run with --recover-credential (rotates the bearer)"
  fi
else
  log "creating principal $AGENT_USER (default Launcher + default allowed root)"
  TOKEN="$("$DH" principal create "$AGENT_USER" --issue-credential --json | jq -er '.token')"
  install_token "$TOKEN"
  unset TOKEN
  credential_valid || die "newly issued credential does not authenticate"
  log "credential installed for $AGENT_USER"
fi

# --- 4. opencode home + launcher aliases -----------------------------------
# The container runs as the agent uid (via --user) and writes these
# bind-mounted paths.
install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" \
  "$AGENT_HOME/.opencode-docker/.config/opencode" \
  "$AGENT_HOME/.opencode-docker/.local/share/opencode" \
  "$AGENT_HOME/.opencode-docker/.local/state" \
  "$AGENT_HOME/.opencode-docker/.cache" \
  "$AGENT_HOME/.opencode-docker/tmp"
# install -d leaves already-existing parents at their old owner, so normalize
# the whole tree.
chown -R "$AGENT_USER:$AGENT_USER" "$AGENT_HOME/.opencode-docker"

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
