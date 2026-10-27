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
#   2. installs the launcher aliases and prepares the OpenCode state tree,
#      installs the DEFAULT OpenCode configuration
#      (~agent/.opencode-docker/.config/opencode/opencode.json — only when
#      absent: an existing user configuration is never overwritten, a
#      symlinked target is refused; the file carries no secrets: the LLM
#      endpoint and key are resolved from the environment at launch time),
#      and creates the agent exchange directory (~agent/agent-exchange,
#      0700, agent:agent, existing contents preserved);
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
# --install-launcher-only (UAT-8g): refreshes ONLY the installed launcher
# artifacts (~/.bash_aliases and ~/.opencode-docker/lib/lab-mount-gate.sh)
# from the canonical lab sources, atomically, and verifies them (cmp, owner,
# group, mode). It performs NO other change: no .bashrc wiring, no OpenCode
# configuration install, no exchange directory, no account, workspace,
# docker group, helper, principal or credential changes. The diagnostic
# driver runs it before every diagnostic ladder so the installed launcher
# can never drift from the freshly copied /opt/lab scripts.
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
# Usage: setup-agent-user.sh [--recover-credential] [--install-launcher-only]
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
GATE_LIB_SRC="$SCRIPT_DIR/lab-mount-gate.sh"

log() { printf '[setup-agent-user] %s\n' "$*"; }
die() { printf '[setup-agent-user] ERROR: %s\n' "$*" >&2; exit 1; }

RECOVER_CREDENTIAL=0
INSTALL_LAUNCHER_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --recover-credential) RECOVER_CREDENTIAL=1 ;;
    --install-launcher-only) INSTALL_LAUNCHER_ONLY=1 ;;
    *) die "unknown argument '$arg' (--recover-credential, --install-launcher-only)" ;;
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

# --- the launcher installation (the SINGLE canonical installer) --------------
# install_launcher_aliases installs the launcher aliases and the mount-gate
# library copy into the agent home from the canonical lab sources
# ($ALIASES_SRC -> ~/.bash_aliases, $GATE_LIB_SRC ->
# ~/.opencode-docker/lib/lab-mount-gate.sh). UAT-8g invariants:
#   * the SOURCES are standalone regular files (a symlinked source would
#     make the verified copy track something outside the lab tree);
#   * the TARGET paths are not symlinks — installing through a symlink
#     would write through it, possibly outside the agent home — and their
#     canonical directories stay inside the canonical agent home (no
#     escape); an unexpected symlink target is a drifted or poisoned state
#     and is refused, never overwritten;
#   * the installation is ATOMIC (temporary file + rename), so a crashed
#     run never leaves a half-written launcher behind;
#   * verify_launcher_aliases then proves byte equality (cmp), owner, group
#     and mode. Any failure is fatal (fail closed).
install_file_atomically() { # SRC TGT OWNER GROUP MODE -> 0 ok | 1 failure
  local src="$1" tgt="$2" owner="$3" grp="$4" mode="$5" tmp
  tmp="$tgt.new.$$"
  if ! install -m "$mode" -o "$owner" -g "$grp" -- "$src" "$tmp"; then
    rm -f -- "$tmp" 2>/dev/null || true
    return 1
  fi
  if ! mv -f -- "$tmp" "$tgt"; then
    rm -f -- "$tmp" 2>/dev/null || true
    return 1
  fi
  return 0
}

# target_inside_agent_home_ok TGT — the shared containment check for any
# file this script writes INSIDE the agent home: the target must not be a
# symlink (installing or appending through one would modify a file outside
# the home) and its canonical location must stay inside the canonical agent
# home. The check must work for a NOT-YET-EXISTING target: the deepest
# EXISTING ancestor is resolved, and any existing component between it and
# the target that is a symlink is refused. Dies on any refused state.
target_inside_agent_home_ok() { # TGT
  local tgt="$1" home_real dir base comp dir_real
  home_real="$(readlink -f -- "$AGENT_HOME")" \
    || die "cannot resolve the agent home $AGENT_HOME"
  [ -n "$home_real" ] && [ -d "$home_real" ] \
    || die "the agent home $AGENT_HOME is not a directory"
  [ -L "$tgt" ] \
    && die "$tgt is a symlink: refusing to write through it (fail closed)"
  dir="$(dirname -- "$tgt")"
  base="$dir"
  while [ ! -d "$base" ]; do
    base="$(dirname -- "$base")"
    [ "$base" != "/" ] || die "cannot resolve an existing ancestor of $tgt"
  done
  dir_real="$(readlink -f -- "$base")" \
    || die "cannot resolve the target directory of $tgt"
  case "$dir_real" in
    "$home_real"|"$home_real"/*) : ;;
    *) die "$tgt escapes the agent home $AGENT_HOME (canonical $dir_real): refusing" ;;
  esac
  comp="$dir"
  while [ "$comp" != "$base" ]; do
    [ -L "$comp" ] \
      && die "$tgt resolves through the symlink $comp: refusing (fail closed)"
    comp="$(dirname -- "$comp")"
  done
  return 0
}

launcher_targets_ok() { # -> 0 ok; dies on any refused state
  local tgt
  for tgt in "$AGENT_HOME/.bash_aliases" \
             "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh"; do
    target_inside_agent_home_ok "$tgt"
  done
  return 0
}

install_launcher_aliases() {
  [ -f "$ALIASES_SRC" ] && [ ! -L "$ALIASES_SRC" ] \
    || die "$ALIASES_SRC is missing or not a standalone regular file"
  [ -f "$GATE_LIB_SRC" ] && [ ! -L "$GATE_LIB_SRC" ] \
    || die "$GATE_LIB_SRC is missing or not a standalone regular file"
  launcher_targets_ok
  install -d -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" \
    "$AGENT_HOME/.opencode-docker/lib"
  install_file_atomically "$ALIASES_SRC" "$AGENT_HOME/.bash_aliases" \
    "$AGENT_USER" "$AGENT_USER" 0644 \
    || die "cannot atomically install $AGENT_HOME/.bash_aliases"
  install_file_atomically "$GATE_LIB_SRC" \
    "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh" \
    "$AGENT_USER" "$AGENT_USER" 0644 \
    || die "cannot atomically install $AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh"
}

# wire_bashrc — the SINGLE owner of the shell wiring (UAT-8h): connects the
# installed launcher into the agent's .bashrc. It runs ONLY in the FULL
# provisioning — never in the launcher refresh (--install-launcher-only has
# exactly two file targets: ~/.bash_aliases and the mount-gate library copy;
# .bashrc is neither). Before ANY write it refuses a symlinked .bashrc (the
# append and the chown would otherwise modify an arbitrary file outside the
# agent home) and verifies the canonical location stays inside the agent
# home. An existing wiring is never duplicated.
wire_bashrc() {
  local bashrc="$AGENT_HOME/.bashrc"
  target_inside_agent_home_ok "$bashrc"
  if grep -qF '.bash_aliases' "$bashrc" 2>/dev/null; then
    log "$bashrc already sources .bash_aliases"
  else
    log "wiring $AGENT_HOME/.bash_aliases into $bashrc"
    printf '\n# docker-helper agent launchers\n[ -f "$HOME/.bash_aliases" ] && . "$HOME/.bash_aliases"\n' \
      >> "$bashrc"
    chown "$AGENT_USER:$AGENT_USER" "$bashrc"
  fi
}

# install_opencode_config — provision the DEFAULT OpenCode configuration for
# the agent account (full provisioning only; the launcher refresh never
# touches it). The configuration names exactly one provider ('local', the
# lab LiteLLM endpoint) and one model; the endpoint and key are resolved
# from the environment at launch time ({env:LLM_SERVER}, {env:LLM_KEY}) —
# no secret material is ever written into the file. Invariants:
#   * the target path is checked by the shared containment owner (a
#     symlinked target is refused, fail closed);
#   * an EXISTING configuration is never overwritten: re-provisioning keeps
#     the user's file as it is;
#   * a fresh install is staged, validated with jq (well-formed JSON and a
#     fixed content self-check: the default model exists in
#     provider.local.models, exactly one provider/model, no subagent or
#     notifier leftovers) and published atomically (temp file + rename);
#   * owner agent:agent, mode 0644.
install_opencode_config() {
  local tgt="$AGENT_HOME/.opencode-docker/.config/opencode/opencode.json"
  local tmp
  target_inside_agent_home_ok "$tgt"
  if [ -f "$tgt" ]; then
    log "$tgt already exists: keeping the existing configuration (re-provisioning never overwrites the user's config)"
    return 0
  fi
  tmp="$tgt.provision.$$"
  cat > "$tmp" <<'JSON'
{
  "$schema": "https://opencode.ai/config.json",
  "model": "local/ds41-flash-uncensored",
  "lsp": true,
  "permission": {
    "lsp": "allow",
    "external_directory": {
      "*": "deny",
      "/exchange/**": "allow",
      "/tmp/**": "allow",
      "/home/opencode/.ssh/*": "allow",
      "/home/opencode/.cache/**": "allow"
    },
    "websearch": "allow",
    "webfetch": "allow"
  },
  "provider": {
    "local": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Local LiteLLM",
      "options": {
        "baseURL": "{env:LLM_SERVER}/v1",
        "apiKey": "{env:LLM_KEY}"
      },
      "models": {
        "ds41-flash-uncensored": {
          "name": "ds41-flash-heretic"
        }
      }
    }
  }
}
JSON
  if ! jq -e . "$tmp" >/dev/null 2>&1; then
    rm -f -- "$tmp" 2>/dev/null || true
    die "the staged OpenCode configuration is not valid JSON: fail closed"
  fi
  if ! jq -e \
      '.model == "local/ds41-flash-uncensored"
       and .provider.local.models["ds41-flash-uncensored"].name == "ds41-flash-heretic"
       and ((.provider | length) == 1)
       and ((.provider.local.models | length) == 1)
       and .subagents == null and .subagent_depth == null and .plugin == null' \
      "$tmp" >/dev/null 2>&1; then
    rm -f -- "$tmp" 2>/dev/null || true
    die "the staged OpenCode configuration failed its content self-check: fail closed"
  fi
  if ! install_file_atomically "$tmp" "$tgt" "$AGENT_USER" "$AGENT_USER" 0644; then
    rm -f -- "$tmp" 2>/dev/null || true
    die "cannot atomically install $tgt"
  fi
  rm -f -- "$tmp" 2>/dev/null || true
  log "installed $tgt (owner $AGENT_USER:$AGENT_USER, mode 0644; secrets resolve from the environment at launch time)"
}

# ensure_exchange_dir — create the agent exchange directory the launcher
# mounts as /exchange (OPENCODE_EXCHANGE_DIR defaults to $HOME/agent-exchange;
# the launcher logic is not changed here). Full provisioning only.
# Invariants: agent:agent, mode 0700, idempotent (an existing directory is
# reused and normalized, its CONTENTS are never removed), a symlink at the
# path is refused fail closed, an unexpected non-directory fails explicitly.
ensure_exchange_dir() {
  local dir="$AGENT_HOME/agent-exchange"
  target_inside_agent_home_ok "$dir"
  if [ -d "$dir" ]; then
    log "$dir already exists: existing contents are preserved"
  else
    mkdir -p -- "$dir" || die "cannot create the exchange directory $dir"
    log "created the exchange directory $dir"
  fi
  chown "$AGENT_USER:$AGENT_USER" "$dir" \
    || die "cannot set the owner of $dir"
  chmod 0700 "$dir" || die "cannot set the mode of $dir"
}

# require_cmp_dependency — the launcher-refresh dependency check (UAT-8j):
# the refresh installs NO packages (the 8h contract: exactly two file
# targets), so a missing cmp is an explicit dependency FAILURE before the
# first launcher write — never a zypper run and never a false file mismatch.
require_cmp_dependency() {
  command -v cmp >/dev/null 2>&1 && [ -x "$(command -v cmp)" ] && return 0
  die "cmp is missing: dependency failure (the launcher refresh installs no packages; provision the guest with diffutils first)"
}

# ensure_cmp_dependency — the FULL-provisioning dependency repair (UAT-8i):
# the launcher verification compares the installed artifacts with cmp, so a
# guest without a working cmp is repaired BEFORE any launcher change. If cmp
# already runs, NO package operation happens; otherwise the guest package
# diffutils is installed through the standard zypper path with signature
# checks (never --no-gpg-checks). A failed install or an unusable cmp
# afterwards fails closed with an explicit dependency diagnosis.
ensure_cmp_dependency() {
  command -v cmp >/dev/null 2>&1 && [ -x "$(command -v cmp)" ] && return 0
  log "installing missing dependency: diffutils (cmp)"
  command -v zypper >/dev/null 2>&1 \
    || die "cmp is missing and zypper is unavailable (cannot install diffutils): dependency failure"
  zypper --non-interactive install diffutils \
    || die "could not install diffutils (cmp): dependency failure"
  command -v cmp >/dev/null 2>&1 && [ -x "$(command -v cmp)" ] \
    || die "cmp is not usable after the diffutils install: dependency failure"
  log "dependency installed: cmp is available"
}

# ensure_jq_dependency — the SINGLE owner of the guest jq dependency
# (UAT-2/F1). The consumer owns its dependency (the same pattern the helper
# installer applies to bindfs): install it once through the standard zypper
# path with package signature verification; an installed jq is never
# reinstalled, and a failed install or a missing/unusable jq afterwards
# fails closed. Package installation stays inside the guest (the lab-VM
# guard has already refused the physical host). It runs in the FULL
# provisioning BEFORE the OpenCode configuration install (which validates
# the staged JSON with jq) and again before the principal/credential phase.
ensure_jq_dependency() {
  command -v jq >/dev/null 2>&1 && [ -x "$(command -v jq)" ] && return 0
  log "installing missing dependency: jq"
  command -v zypper >/dev/null 2>&1 || die "zypper not found (cannot install jq)"
  zypper --non-interactive install jq || die "could not install jq (network open?)"
  command -v jq >/dev/null 2>&1 && [ -x "$(command -v jq)" ] \
    || die "jq is missing or unusable after the install attempt: dependency failure"
  log "dependency installed: jq is available"
}

# verify_installed_copy SRC TGT — the three-outcome cmp classification
# (UAT-8i): rc 0 = the files match; rc 1 = the files really differ (a
# launcher drift, fail closed); rc >= 2 = the COMPARISON itself failed
# (a missing or unreadable file, a missing cmp): a separate explicit
# failure, never a false mismatch report.
verify_installed_copy() { # SRC TGT
  local src="$1" tgt="$2" rc=0
  cmp -s -- "$src" "$tgt" || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) die "$tgt does not match $src (cmp): the installed launcher drifted" ;;
    *) die "cmp could not compare $tgt with $src (cmp rc $rc): comparison error, fail closed" ;;
  esac
}

verify_launcher_aliases() {
  verify_installed_copy "$ALIASES_SRC" "$AGENT_HOME/.bash_aliases"
  verify_installed_copy "$GATE_LIB_SRC" \
    "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh"
  local tgt
  for tgt in "$AGENT_HOME/.bash_aliases" \
             "$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh"; do
    [ -f "$tgt" ] && [ ! -L "$tgt" ] \
      || die "$tgt is missing or not a standalone regular file"
    [ "$(stat -c '%U' "$tgt")" = "$AGENT_USER" ] \
      || die "$tgt is not owned by $AGENT_USER"
    [ "$(stat -c '%G' "$tgt")" = "$AGENT_USER" ] \
      || die "$tgt is not group-owned by $AGENT_USER"
    [ "$(stat -c '%a' "$tgt")" = 644 ] \
      || die "$tgt does not have mode 0644"
  done
  return 0
}

# --- dependency preflight (UAT-8i/UAT-8j) ------------------------------------
# The launcher verification compares with cmp. The two modes differ by the
# 8h boundary: the launcher refresh never changes system packages (a missing
# cmp is an explicit dependency refusal), while the full provisioning
# repairs the guest dependency through the standard zypper path. In BOTH
# modes the check happens before ANY launcher change, so the absence can
# never surface later as a false file mismatch.
if [ "$INSTALL_LAUNCHER_ONLY" = 1 ]; then
  require_cmp_dependency
fi

# --- launcher refresh mode (UAT-8g) ------------------------------------------
# Refreshes ONLY the installed launcher artifacts from the canonical lab
# sources: no account, uid, workspace, docker group, helper, principal or
# credential changes. The diagnostic driver runs this before every
# diagnostic ladder so the installed launcher can never drift from the
# freshly copied /opt/lab scripts (the real 8f finding). Fail-closed: any
# install or verification failure exits nonzero BEFORE the ladder runs.
if [ "$INSTALL_LAUNCHER_ONLY" = 1 ]; then
  install_launcher_aliases
  verify_launcher_aliases
  log "launcher refresh done: aliases=$AGENT_HOME/.bash_aliases gate=$AGENT_HOME/.opencode-docker/lib/lab-mount-gate.sh (verified: cmp, owner, group, mode)"
  exit 0
fi

# the full provisioning repairs the guest dependency through zypper (UAT-8i)
ensure_cmp_dependency

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

# --- 2a. the default OpenCode configuration + the exchange directory --------
# Full provisioning only (the launcher refresh exited above with exactly its
# two file targets). jq is ensured first: the configuration install validates
# its staged JSON with it, fail closed.
ensure_jq_dependency
install_opencode_config
ensure_exchange_dir

install_launcher_aliases
verify_launcher_aliases
wire_bashrc

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
# jq is also a hard dependency of the principal/credential phase; the single
# dependency owner below has already ensured it in the FULL provisioning.
[ -x "$(command -v jq)" ] || die "jq is not executable at $(command -v jq)"
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
