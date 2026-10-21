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
# Idempotent, in two phases driven by whether docker-helper is installed:
#   1. creates the 'agent' account with a unique uid and its workspace root,
#      and adds it to the 'docker' group (the trusted launcher drives
#      `docker run`);
#   2. installs the launcher aliases and prepares the OpenCode state tree;
#   3. WITHOUT docker-helper: stops here with an explicit log (the helper
#      install needs the agent home as its minimal --allowed-root); re-run
#      after install-docker-helper-v230.sh;
#   4. WITH docker-helper: refuses to continue when the docker-helper
#      principal record disagrees with the OS account (fail-closed, see the
#      UID policy below), ensures a global allowed root covers the agent
#      home, creates the docker-helper principal 'agent' (its 'default'
#      Launcher and default allowed root are provisioned atomically with it),
#      issues a principal credential and installs it, as the agent account,
#      into ~agent/.config/docker-helper/credential.token (never printed);
#   5. verifies the result: unique uid, agent-owned credential (when present)
#      and OpenCode state.
#
# It does NOT manage SSH keys: VM access stays with the dev-vm-local.sh SSH
# identity, and the agent account gets no SSH of its own.
#
# UID policy (fail-closed; the lab VM is disposable):
#   * PREFERRED uid (AGENT_UID, default 1001) is only the starting point for
#     the FIRST creation: a fresh account gets a UNIQUE uid (NSS-checked
#     against users AND groups; never useradd -o), taking the next free one
#     when the preferred is taken;
#   * ALLOCATED uid is the identity the account actually carries. An existing
#     account is ACCEPTED when its identity is coherent -- the uid resolves
#     uniquely to this account through NSS, differs from the admin account
#     (opc), and agrees with the principal record and the file ownership
#     (verified below) -- even when it differs from the preferred uid. An
#     interrupted first provisioning is therefore resumable;
#   * an incompatible or ambiguous state FAILS CLOSED: no usermod -u and no
#     direct /etc/passwd, /etc/shadow, or /etc/group edit here; recreate the
#     disposable VM or perform an explicitly controlled migration instead;
#   * the opc/admin account's uid is never modified;
#   * the docker-helper principal record stores the uid/gid resolved at
#     creation and the daemon uses it as the workload execution identity;
#     there is no supported CLI to rewrite it, so a principal record that
#     disagrees with the OS account FAILS CLOSED (recreate the lab principal
#     through the supported CLI or re-provision the VM). Lab scripts never
#     write the helper database directly.
#
# Usage: setup-agent-user.sh [--recover-credential]
#
# Env overrides: AGENT_USER, AGENT_HOME, AGENT_WORKROOT, AGENT_DOCKER_GROUP,
#                AGENT_UID.
# The lab-VM guard has no environment overrides (see lab-vm-guard.sh).
set -euo pipefail

AGENT_USER="${AGENT_USER:-agent}"
AGENT_HOME="${AGENT_HOME:-/home/$AGENT_USER}"
AGENT_WORKROOT="${AGENT_WORKROOT:-$AGENT_HOME/work}"
AGENT_DOCKER_GROUP="${AGENT_DOCKER_GROUP:-docker}"
AGENT_UID="${AGENT_UID:-1001}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALIASES_SRC="$SCRIPT_DIR/agent-aliases.sh"

log() { printf '[setup-agent-user] %s\n' "$*"; }
die() { printf '[setup-agent-user] ERROR: %s\n' "$*" >&2; exit 1; }

RECOVER_CREDENTIAL=0
for arg in "$@"; do
  case "$arg" in
    --recover-credential) RECOVER_CREDENTIAL=1 ;;
    *) die "unknown argument '$arg' (only --recover-credential)" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "must run as root in the guest (sudo bash $0)"

# --- 0. lab-VM guard (fail closed on the physical host) ---------------------
# Shared guard (lab-vm-guard.sh): marker tag, marker version, and machine-id
# are all verified before ANY state change. KVM/QEMU presence alone is
# deliberately not trusted.
# shellcheck source=lab-vm-guard.sh
. "$SCRIPT_DIR/lab-vm-guard.sh"
require_lab_vm

[ -f "$ALIASES_SRC" ] || die "missing $ALIASES_SRC"

# --- 1. account, workspace root, docker access ------------------------------
# The 'agent' account is the trusted launcher, so it may hold docker access.
# The untrusted model is the container process and gets no docker group.
#
# UID policy (see header): a fresh account gets a UNIQUE uid found through
# NSS (users AND groups are checked, so useradd never needs -o), starting at
# the preferred AGENT_UID. An existing account is accepted on its ALLOCATED
# uid when the identity is coherent (unique in NSS, distinct from the admin
# account, consistent with the principal record and file ownership); an
# incompatible or ambiguous state fails closed.
find_free_uid() { # $1 = preferred uid; prints the first free uid >= preferred
  local uid="$1" max=60000
  while [ "$uid" -le "$max" ]; do
    if ! getent passwd "$uid" >/dev/null 2>&1 \
       && ! getent group "$uid" >/dev/null 2>&1; then
      printf '%s' "$uid"
      return 0
    fi
    uid=$((uid + 1))
  done
  return 1
}

opc_uid=""
if id opc >/dev/null 2>&1; then
  opc_uid="$(id -u opc)"
fi

if id "$AGENT_USER" >/dev/null 2>&1; then
  current_uid="$(id -u "$AGENT_USER")"
  # Early identity checks for an existing account: the allocated uid must
  # resolve uniquely to THIS account and must never be the admin account's.
  uid_entries="$(getent passwd | awk -F: -v u="$current_uid" '$3 == u' | wc -l)"
  [ "$uid_entries" = 1 ] \
    || die "uid $current_uid of $AGENT_USER is not unique in NSS ($uid_entries passwd entries): fail-closed"
  [ "$(getent passwd "$current_uid" | cut -d: -f1)" = "$AGENT_USER" ] \
    || die "uid $current_uid does not resolve to $AGENT_USER via NSS: fail-closed"
  if [ -n "$opc_uid" ]; then
    [ "$current_uid" != "$opc_uid" ] \
      || die "account $AGENT_USER shares uid $current_uid with the admin account opc: fail-closed (recreate the disposable VM)"
  fi
  log "account $AGENT_USER already exists (allocated uid $current_uid; coherence verified below)"
else
  agent_uid="$(find_free_uid "$AGENT_UID")" \
    || die "no free uid at or above $AGENT_UID (NSS users and groups all taken)"
  log "creating account $AGENT_USER (unique uid $agent_uid, distinct from the admin account)"
  useradd -u "$agent_uid" -m -s /bin/bash -c "docker-helper agent launcher" "$AGENT_USER"
fi

# Normalize ownership of the whole home: covers a pre-existing parent left at
# its old owner by `install -d`.
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

# --- 2. opencode home + launcher aliases -----------------------------------
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
# The mount gate library is part of the launcher's trusted loading path: the
# installed aliases resolve it from this agent-owned lib copy in the VM.
GATE_LIB_SRC="$(dirname -- "$ALIASES_SRC")/lab-mount-gate.sh"
[ -f "$GATE_LIB_SRC" ] || die "missing $GATE_LIB_SRC"
install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_HOME/.opencode-docker/lib"
install -m 0644 -o "$AGENT_USER" -g "$AGENT_USER" \
  "$GATE_LIB_SRC" "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh"
if grep -qF '.bash_aliases' "$AGENT_HOME/.bashrc" 2>/dev/null; then
  log "$AGENT_HOME/.bashrc already sources .bash_aliases"
else
  log "wiring $AGENT_HOME/.bash_aliases into $AGENT_HOME/.bashrc"
  printf '\n# docker-helper agent launchers\n[ -f "$HOME/.bash_aliases" ] && . "$HOME/.bash_aliases"\n' \
    >> "$AGENT_HOME/.bashrc"
  chown "$AGENT_USER:$AGENT_USER" "$AGENT_HOME/.bashrc"
fi

# --- 3. docker-helper phase gate -------------------------------------------
# The account, workspace and launcher aliases are OS-level state and are
# provisioned first, so install-docker-helper-v230.sh can pass the agent home
# as the minimal --allowed-root (the daemon requires an existing directory).
# When docker-helper is not installed yet, this script stops here with an
# explicit log and a success status: re-run it after the helper install to
# provision the principal, allowed root and credential. Nothing helper-related
# is skipped silently.
if ! command -v docker-helper >/dev/null 2>&1; then
  log "docker-helper not found in PATH: account=$AGENT_USER workspace+aliases provisioned; re-run this script after install-docker-helper-v230.sh to provision the principal, allowed root and credential"
  exit 0
fi
DH="$(command -v docker-helper)" || die "docker-helper not found in PATH"
command -v jq >/dev/null 2>&1 || die "jq not found in PATH"
CRED_FILE="$AGENT_HOME/.config/docker-helper/credential.token"

# --- 4. principal record consistency (fail-closed; never DB-edited) ---------
# The principal record stores the uid/gid the daemon resolved from the OS
# account at creation time, and the daemon uses it as the workload execution
# identity. docker-helper v2.3.0 has no supported CLI to rewrite these
# fields ('principal set' only supports 'enabled'), so a record that
# disagrees with the OS account is an inconsistent environment: fail closed
# and point at the supported recovery paths. Lab scripts never write the
# helper database (no sqlite3, no direct UPDATE/DELETE).
check_principal_identity() {
  local p_json p_uid p_gid os_uid os_gid
  p_json="$("$DH" principal show "$AGENT_USER" --json 2>/dev/null)" || return 0
  p_uid="$(printf '%s' "$p_json" | jq -r '.uid // empty')"
  p_gid="$(printf '%s' "$p_json" | jq -r '.gid // empty')"
  [ -n "$p_uid" ] || return 0
  os_uid="$(id -u "$AGENT_USER")"
  os_gid="$(id -g "$AGENT_USER")"
  [ "$p_uid" = "$os_uid" ] && [ "$p_gid" = "$os_gid" ] && return 0
  die "principal $AGENT_USER record uid/gid $p_uid:$p_gid disagrees with the OS account $os_uid:$os_gid: fail-closed (docker-helper has no supported migration); recreate the lab principal with the supported CLI (principal delete + principal create --issue-credential) or re-provision the disposable VM"
}
check_principal_identity

# --- 5. global allowed root (authorization ceiling) -------------------------
if "$DH" config allowed-root list 2>/dev/null | grep -qF "$AGENT_HOME"; then
  log "global allowed root already covers $AGENT_HOME"
else
  log "adding global allowed root $AGENT_HOME"
  "$DH" config allowed-root add "$AGENT_HOME" --access read_write
fi

# --- 6. principal credential (fail-closed; explicit recovery) ---------------
# The daemon stores only the token hash. An existing local credential is reused
# when it still authenticates AND belongs to exactly this principal; a missing
# or non-authenticating one is NOT rotated implicitly (that would silently
# invalidate any other copy of the bearer). --recover-credential performs the
# explicit rotate.

# A credential is valid only when it authenticates, classifies as a principal
# credential, and resolves to the EXPECTED principal -- never accept another
# principal's credential. The expected username crosses jq through --arg, not
# through string interpolation.
credential_valid() {
  local out
  out="$(su -s /bin/bash "$AGENT_USER" -c "$DH self --json" 2>/dev/null)" || return 1
  printf '%s' "$out" | jq -e --arg expected "$AGENT_USER" \
    '.ok == true and .type == "principal" and .resource.username == $expected' >/dev/null 2>&1
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

log "done: account=$AGENT_USER home=$AGENT_HOME workroot=$AGENT_WORKROOT"

# --- 7. post-provisioning verification (uid uniqueness, ownership) ---------
# Prove the invariants the provisioning promised: the agent uid is unique in
# NSS (exactly one passwd entry), and the files the launcher and container
# rely on are owned by the agent account. The credential exists only after
# the docker-helper phase, so its ownership is verified conditionally.
final_uid="$(id -u "$AGENT_USER")"
final_uid_entries="$(getent passwd | awk -F: -v u="$final_uid" '$3 == u' | wc -l)"
[ "$final_uid_entries" = 1 ] \
  || die "uid $final_uid is not uniquely owned by $AGENT_USER ($final_uid_entries passwd entries)"
[ "$(getent passwd "$final_uid" | cut -d: -f1)" = "$AGENT_USER" ] \
  || die "uid $final_uid does not resolve to $AGENT_USER via NSS"
verified_list=("$AGENT_HOME/.opencode-docker" "$AGENT_HOME/.bash_aliases" "$AGENT_WORKROOT")
if [ -f "$CRED_FILE" ]; then
  verified_list=("$CRED_FILE" "${verified_list[@]}")
fi
for verified in "${verified_list[@]}"; do
  [ "$(stat -c '%U' "$verified")" = "$AGENT_USER" ] \
    || die "$verified is not owned by $AGENT_USER"
done
log "verified: unique uid $final_uid; OpenCode state, aliases and workroot owned by $AGENT_USER"

log "next: as $AGENT_USER, cd ~/work/<project>, then run: oc | oc-go26"
