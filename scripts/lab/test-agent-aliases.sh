#!/usr/bin/env bash
#
# test-agent-aliases.sh — focused tests for scripts/lab/agent-aliases.sh with
# stubbed docker/docker-helper (no real daemon, container, or root needed).
#
# What this protects (one invariant per test):
#   1. each launch creates a Session for $PWD and passes its bearer to the
#      container (never docker.sock);
#   2. the container argv carries the isolation posture (cap-drop ALL,
#      no-new-privileges, --rm --init, read-only helper dir, :Z workspace);
#   3. the Session is deleted on normal exit;
#   4. the Session is deleted when the launcher is interrupted (SIGINT);
#   5. the workspace is passed in the form the installed CLI advertises
#      (--workspace flag vs positional WORKSPACE);
#   6. the model gets only the bearer: no docker.sock, no GH_TOKEN, no admin
#      token, no principal credential;
#   7. the images are pinned by OCI digest (no floating :latest);
#   8. --init uses a lab-owned VERIFIED COPY of docker-init: no :z/:Z relabel
#      ever targets a system executable, the copy stays byte-identical
#      (refreshed on drift), and an unverifiable copy fails the launch closed;
#   9. the copy is a STANDALONE regular file at an independent inode: a
#      symlink or hardlink alias of the system binary is replaced, a parent
#      directory symlink escaping the lab home is refused, and the system
#      binary's inode/mode never change;
#  10. the mounted source set is an allowlist of lab-owned paths: no implicit
#      SSH credentials (or any other unlisted directory) ride along.
#
# Usage: scripts/lab/test-agent-aliases.sh

set -u

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ALIASES="$SRC_DIR/lab/agent-aliases.sh"
[ -f "$ALIASES" ] || { echo "missing $ALIASES" >&2; exit 1; }

WORK="$(mktemp -d)"
SOCK_PID=""
cleanup_work() {
  [ -n "$SOCK_PID" ] && kill "$SOCK_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup_work EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2' got '$3')"; fi; }
contains() { # desc needle haystack
  case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2' in '$3')" ;; esac
}
not_contains() { # desc needle haystack
  case "$3" in *"$2"*) bad "$1 (unexpected '$2' in '$3')" ;; *) ok "$1" ;; esac
}

# --- stubs -----------------------------------------------------------------
SHIM="$WORK/shim"; mkdir -p "$SHIM" "$WORK/run"

# A stand-in system docker-init: deterministic init-copy resolution regardless
# of whether the CI host has Docker installed.
printf '#!/bin/sh\nexit 0\n' > "$SHIM/docker-init"
chmod 0755 "$SHIM/docker-init"

cat > "$SHIM/docker-helper" <<'SH'
#!/bin/sh
# Only the subcommands the launcher uses. DH_HELP_WORKSPACE toggles whether the
# `session create --help` probe advertises --workspace (flag form) or not.
case "$1 $2" in
  "session create")
    for a in "$@"; do
      if [ "$a" = "--help" ]; then
        if [ -n "${DH_HELP_WORKSPACE:-}" ]; then
          echo "Usage: docker-helper session create [--workspace DIR] [--json]"
        else
          echo "Usage: docker-helper session create [--json] WORKSPACE"
        fi
        exit 0
      fi
    done
    printf '%s\n' "create $*" >> "$DH_REC"
    printf '{"session":{"id":"dhs_TEST"},"token":"dht_SECRET"}\n'
    ;;
  "session delete")
    printf '%s\n' "delete $*" >> "$DH_REC"
    ;;
  *)
    printf '%s\n' "other $*" >> "$DH_REC"
    ;;
esac
SH

cat > "$SHIM/docker" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "$DOCKER_REC"
[ -n "${STUB_SLEEP:-}" ] && sleep 30
exit 0
SH

# ssh-agent stub: a real background process stands in for the agent so the
# launcher's cleanup (kill "$SSH_AGENT_PID") is observable.
cat > "$SHIM/ssh-agent" <<'SH'
#!/bin/sh
sock=""
while [ $# -gt 0 ]; do
  case "$1" in
    -a) sock="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ -n "$sock" ] || { echo "usage: ssh-agent -a socket" >&2; exit 2; }
sleep 300 >/dev/null 2>&1 &
pid=$!
echo "$pid" > "$SSH_AGENT_PIDFILE"
echo "SSH_AUTH_SOCK=$sock; export SSH_AUTH_SOCK;"
echo "SSH_AGENT_PID=$pid; export SSH_AGENT_PID;"
echo "Agent pid $pid"
SH
cat > "$SHIM/ssh-add" <<'SH'
#!/bin/sh
printf 'ssh-add %s\n' "$*" >> "$SSH_ADD_REC"
[ -n "${SSH_ADD_FAIL:-}" ] && exit 1
exit 0
SH

chmod +x "$SHIM/docker-helper" "$SHIM/docker" "$SHIM/ssh-agent" "$SHIM/ssh-add"

# A real AF_UNIX socket at the expected path (kept bound by a background pid).
python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); time.sleep(300)' \
  "$WORK/run/docker-helper.sock" &
SOCK_PID=$!
for _ in $(seq 1 20); do [ -S "$WORK/run/docker-helper.sock" ] && break; sleep 0.1; done

export PATH="$SHIM:$PATH"
export DH_REC="$WORK/dh.rec" DOCKER_REC="$WORK/docker.rec"
export SSH_AGENT_PIDFILE="$WORK/ssh-agent.pid" SSH_ADD_REC="$WORK/ssh-add.rec"
export DOCKER_HELPER_RUNTIME_DIR="$WORK/run"
export OPENCODE_DOCKER_HOME="$WORK/ochome"
export OPENCODE_EXCHANGE_DIR="$WORK/absent-exchange"
export OPENCODE_AGENT_SSH_KEY="$WORK/agent-ssh-key/id_ed25519_opencode"
mkdir -p "$OPENCODE_DOCKER_HOME/.config" "$OPENCODE_DOCKER_HOME/.local/share"
WS="$WORK/ws"; mkdir -p "$WS"

# shellcheck source=/dev/null
source "$ALIASES"

# --- 1/2/3. normal launch: session lifecycle + container argv --------------
export DH_HELP_WORKSPACE=1
: > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo hi )

dh="$(cat "$DH_REC" 2>/dev/null || true)"
dargv="$(cat "$DOCKER_REC" 2>/dev/null || true)"

contains "launch creates a session for \$PWD (--workspace CLI)" "create session create --workspace $WS" "$dh"
contains "launch deletes the session (positional SESSION_ID)" "delete session delete dhs_TEST" "$dh"
not_contains "session delete does not use --id" "--id" "$dh"
contains "container gets the session bearer" "-e DOCKER_HELPER_SESSION_TOKEN" "$dargv"
contains "container drops caps" "--cap-drop ALL" "$dargv"
contains "container sets no-new-privileges" "--security-opt no-new-privileges=true" "$dargv"
contains "container runs as the guest launcher uid" "--user $(id -u):$(id -g)" "$dargv"
contains "container runs in the helper workload SELinux domain" "--security-opt label=type:docker_helper_container_t" "$dargv"
DH_INIT_SRC="$(readlink -f "$SHIM/docker-init")"
INIT_COPY="$OPENCODE_DOCKER_HOME/init/docker-init"
INIT_SYS_SNAP="$(stat -c '%d:%i %a' "$DH_INIT_SRC")"
contains "init binary is the lab-owned verified copy" "$INIT_COPY:/sbin/docker-init:ro,z" "$dargv"
not_contains "system docker-init is never a mount source" "$DH_INIT_SRC:" "$dargv"
cmp -s "$DH_INIT_SRC" "$INIT_COPY" && ok "init copy is byte-identical to the system binary" || bad "init copy drifted from the system binary"
contains "container is --rm --init" "--rm -it --init" "$dargv"
contains "helper runtime dir is read-only" "$WORK/run:/run/docker-helper:ro" "$dargv"
contains "workspace is a private relabel" "$WS:/workspace:Z" "$dargv"
contains "opencode .local state is agent-owned" "$OPENCODE_DOCKER_HOME/.local:/home/opencode/.local:Z" "$dargv"
contains "opencode cache is agent-owned" "$OPENCODE_DOCKER_HOME/.cache:/home/opencode/.cache:Z" "$dargv"
contains "opencode tmp is agent-owned" "$OPENCODE_DOCKER_HOME/tmp:/tmp/opencode:Z" "$dargv"

# model gets only the bearer: no docker.sock, no admin token, no principal cred
not_contains "container does not mount docker.sock" "docker.sock" "$dargv"
not_contains "container does not get GH_TOKEN" "-e GH_TOKEN" "$dargv"
not_contains "container does not get an admin token" "ADMIN_TOKEN" "$dargv"
not_contains "container does not mount the principal credential" "/.config/docker-helper" "$dargv"
not_contains "the agent's real .ssh is never a mount source" "-v $HOME/.ssh" "$dargv"

# REGRESSION: no :z/:Z relabel may ever target a SYSTEM executable. Parse the
# mount pairs and forbid system-path sources on any relabeled mount.
zsrc_hits=""
prev=""
for w in $dargv; do
  if [ "$prev" = "-v" ]; then
    src="${w%%:*}"
    opts="${w##*:}"
    case "$opts" in
      *z*|*Z*)
        case "$src" in
          /usr/*|/sbin/*|/bin/*|/lib/*|/lib64/*|/libexec/*|/etc/*|/var/lib/*|/opt/*) \
            zsrc_hits="$zsrc_hits $src" ;;
        esac
        ;;
    esac
  fi
  prev="$w"
done
if [ -z "$zsrc_hits" ]; then
  ok "no relabeled (:z/:Z) mount sources a system executable"
else
  bad "relabeled mount sources system executables:$zsrc_hits"
fi

# The mounted source set is an ALLOWLIST: exactly the agent-owned OpenCode
# state, the workspace, the verified init copy, and the read-only helper
# runtime dir. Any additional implicit mount (SSH credentials, agent config,
# anything else) fails here.
mounted_srcs=""
prev=""
for w in $dargv; do
  [ "$prev" = "-v" ] && mounted_srcs="$mounted_srcs${w%%:*}
"
  prev="$w"
done
check "mounted sources are exactly the lab allowlist" \
  "$INIT_COPY
$WS
$OPENCODE_DOCKER_HOME/.config
$OPENCODE_DOCKER_HOME/.local
$OPENCODE_DOCKER_HOME/.cache
$OPENCODE_DOCKER_HOME/tmp
$WORK/run" \
  "$(printf '%s' "$mounted_srcs" | sed '/^$/d')"

# --- 6b. no implicit SSH credential mount ----------------------------------
mkdir -p "$OPENCODE_DOCKER_HOME/.ssh"
printf 'SSHKEY-MARKER\n' > "$OPENCODE_DOCKER_HOME/.ssh/id_ed25519"
: > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo hi )
dargv="$(cat "$DOCKER_REC" 2>/dev/null || true)"
not_contains "present .ssh dir is NOT mounted" ".ssh" "$dargv"
rm -rf "$OPENCODE_DOCKER_HOME/.ssh"

# --- 7. capability layer: CA, gitconfig, ssh material, ssh-agent -----------
mkdir -p "$OPENCODE_DOCKER_HOME/ca" "$OPENCODE_DOCKER_HOME/git" "$OPENCODE_DOCKER_HOME/ssh"
printf 'CA-CERT\n' > "$OPENCODE_DOCKER_HOME/ca/lab-ca.crt"
printf '[user]\n\tname = agent\n' > "$OPENCODE_DOCKER_HOME/git/gitconfig"
printf 'known hosts\n' > "$OPENCODE_DOCKER_HOME/ssh/known_hosts"
mkdir -p "$(dirname "$OPENCODE_AGENT_SSH_KEY")"
printf 'PRIVATE-KEY\n' > "$OPENCODE_AGENT_SSH_KEY"
chmod 0600 "$OPENCODE_AGENT_SSH_KEY"
: > "$DH_REC"; : > "$DOCKER_REC"; : > "$SSH_ADD_REC"
( cd "$WS" && oc echo hi )
dargv="$(cat "$DOCKER_REC" 2>/dev/null || true)"
contains "lab CA copy is mounted read-only" "$OPENCODE_DOCKER_HOME/ca:/etc/opencode-ca:ro,z" "$dargv"
contains "NODE_EXTRA_CA_CERTS points at the mounted copy" "-e NODE_EXTRA_CA_CERTS=/etc/opencode-ca/lab-ca.crt" "$dargv"
contains "SSL_CERT_FILE points at the mounted copy" "-e SSL_CERT_FILE=/etc/opencode-ca/lab-ca.crt" "$dargv"
contains "CURL_CA_BUNDLE points at the mounted copy" "-e CURL_CA_BUNDLE=/etc/opencode-ca/lab-ca.crt" "$dargv"
contains "GIT_SSL_CAINFO points at the mounted copy" "-e GIT_SSL_CAINFO=/etc/opencode-ca/lab-ca.crt" "$dargv"
contains "gitconfig copy is mounted read-only" "$OPENCODE_DOCKER_HOME/git/gitconfig:/home/opencode/.gitconfig:ro,z" "$dargv"
contains "public ssh material is mounted read-only" "$OPENCODE_DOCKER_HOME/ssh:/home/opencode/.ssh:ro,z" "$dargv"
contains "the ssh-agent socket dir is the only agent mount" "$OPENCODE_DOCKER_HOME/agent-ssh:/ssh-agent:ro" "$dargv"
contains "SSH_AUTH_SOCK points at the forwarded socket" "-e SSH_AUTH_SOCK=/ssh-agent/agent.sock" "$dargv"
contains "ssh-add loaded the provisioned key" "ssh-add -- $OPENCODE_AGENT_SSH_KEY" "$(cat "$SSH_ADD_REC" 2>/dev/null || true)"
not_contains "the private key file is never a mount source" "$OPENCODE_AGENT_SSH_KEY:" "$dargv"
AGENT_PID="$(cat "$SSH_AGENT_PIDFILE" 2>/dev/null || true)"
if [ -n "$AGENT_PID" ] && ! kill -0 "$AGENT_PID" 2>/dev/null; then
  ok "the per-launch ssh-agent is stopped after the launch"
else
  bad "the per-launch ssh-agent survived the launch"
fi
contains "opencode LSP tool flag is passed" "-e OPENCODE_EXPERIMENTAL_LSP_TOOL=true" "$dargv"
contains "opencode exa flag is passed" "-e OPENCODE_ENABLE_EXA=1" "$dargv"

# the full mounted source allowlist with every capability present
mounted_srcs=""
prev=""
for w in $dargv; do
  [ "$prev" = "-v" ] && mounted_srcs="$mounted_srcs${w%%:*}
"
  prev="$w"
done
check "mounted sources with capabilities are exactly the lab allowlist" \
  "$INIT_COPY
$WS
$OPENCODE_DOCKER_HOME/.config
$OPENCODE_DOCKER_HOME/.local
$OPENCODE_DOCKER_HOME/.cache
$OPENCODE_DOCKER_HOME/tmp
$WORK/run
$OPENCODE_DOCKER_HOME/ca
$OPENCODE_DOCKER_HOME/git/gitconfig
$OPENCODE_DOCKER_HOME/ssh
$OPENCODE_DOCKER_HOME/agent-ssh" \
  "$(printf '%s' "$mounted_srcs" | sed '/^$/d')"

# --- 7a. GH_AGENT_TOKEN is opt-in -------------------------------------------
: > "$DOCKER_REC"
( cd "$WS" && oc echo hi )
not_contains "GH_AGENT_TOKEN is not passed by default" "-e GH_AGENT_TOKEN" "$(cat "$DOCKER_REC")"
export GH_AGENT_TOKEN=gh-agent-token-marker
: > "$DOCKER_REC"
( cd "$WS" && oc echo hi )
unset GH_AGENT_TOKEN
contains "GH_AGENT_TOKEN passed only when explicitly exported" "-e GH_AGENT_TOKEN" "$(cat "$DOCKER_REC")"

# --- 7b. ambiguous CA provisioning fails the launch -------------------------
printf 'CA2\n' > "$OPENCODE_DOCKER_HOME/ca/second.crt"
: > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo hi ) >/dev/null 2>&1
amb_rc=$?
if [ "$amb_rc" != 0 ]; then ok "ambiguous CA provisioning fails the launch"; else bad "ambiguous CA provisioning was accepted"; fi
rm -f "$OPENCODE_DOCKER_HOME/ca/second.crt"

# --- 7c. an unloadable ssh key fails the launch and stops the agent ---------
export SSH_ADD_FAIL=1
: > "$SSH_ADD_REC"; : > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo hi ) >/dev/null 2>&1
addfail_rc=$?
unset SSH_ADD_FAIL
if [ "$addfail_rc" != 0 ]; then ok "an unloadable ssh key fails the launch"; else bad "launch proceeded without the ssh key loaded"; fi
grep -q "ssh-add -- $OPENCODE_AGENT_SSH_KEY" "$SSH_ADD_REC" && ok "the failed add attempted the provisioned key" || bad "the failed add did not attempt the key"
AGENT_PID="$(cat "$SSH_AGENT_PIDFILE" 2>/dev/null || true)"
if [ -n "$AGENT_PID" ] && ! kill -0 "$AGENT_PID" 2>/dev/null; then
  ok "the ssh-agent is stopped after a failed add"
else
  bad "the ssh-agent survived a failed add"
fi

# --- 7d. without a provisioned ssh key there is no agent and no ssh mount ---
rm -f "$OPENCODE_AGENT_SSH_KEY"
: > "$SSH_ADD_REC"; : > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo hi )
dargv="$(cat "$DOCKER_REC" 2>/dev/null || true)"
not_contains "no key: no ssh-agent socket mount" "/ssh-agent" "$dargv"
not_contains "no key: no SSH_AUTH_SOCK env" "SSH_AUTH_SOCK" "$dargv"
not_contains "no key: ssh-add never ran" "ssh-add" "$(cat "$SSH_ADD_REC" 2>/dev/null || true)"

# --- 7e. oc-dotnet10 is gone -------------------------------------------------
if type -t oc-dotnet10 >/dev/null 2>&1; then bad "oc-dotnet10 is still defined"; else ok "oc-dotnet10 removed"; fi
if grep -q "dotnet10" "$ALIASES"; then bad "dotnet10 image is still referenced"; else ok "dotnet10 digest removed"; fi

# --- 2b. the init copy is verified and refreshed on drift ------------------
printf 'DRIFT\n' >> "$INIT_COPY"
: > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo hi )
cmp -s "$DH_INIT_SRC" "$INIT_COPY" && ok "drifted init copy is refreshed from the system binary" || bad "drifted init copy was not refreshed"

# --- 2b2. a symlinked copy is replaced by a standalone inode ---------------
# A symlink to the system binary would route the ro,z relabel onto the system
# inode; the launcher must replace it with an independent regular file.
ln -sf "$DH_INIT_SRC" "$INIT_COPY"
: > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo hi )
if [ ! -L "$INIT_COPY" ] && [ -f "$INIT_COPY" ]; then
  ok "symlinked copy is replaced by a standalone regular file"
else
  bad "symlinked copy survived the launch"
fi
if [ "$(stat -c '%d:%i' "$INIT_COPY")" != "$(stat -c '%d:%i' "$DH_INIT_SRC")" ]; then
  ok "replacement copy has an independent inode"
else
  bad "replacement copy still aliases the system inode"
fi
cmp -s "$DH_INIT_SRC" "$INIT_COPY" && ok "replacement copy is byte-identical" || bad "replacement copy content differs"

# --- 2b3. a hardlinked copy is replaced by an independent inode ------------
# A hardlink aliases the system inode even with identical content; device and
# inode must differ after the launch.
rm -f "$INIT_COPY"
ln "$DH_INIT_SRC" "$INIT_COPY"
: > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo hi )
if [ "$(stat -c '%d:%i' "$INIT_COPY")" != "$(stat -c '%d:%i' "$DH_INIT_SRC")" ]; then
  ok "hardlinked copy is replaced by an independent inode"
else
  bad "hardlinked copy survived the launch"
fi
cmp -s "$DH_INIT_SRC" "$INIT_COPY" && ok "hardlink replacement is byte-identical" || bad "hardlink replacement content differs"

# --- 2c. init copy failure is fail-closed (no launch) ----------------------
# Drift the copy AND make the lab init dir unwritable: the staged publication
# must fail the launch before docker runs, and the session must still be
# deleted by the launcher cleanup.
printf 'DRIFT\n' >> "$INIT_COPY"
chmod 0555 "$OPENCODE_DOCKER_HOME/init"
: > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo hi ) >/dev/null 2>&1
launch_rc=$?
chmod 0755 "$OPENCODE_DOCKER_HOME/init"
if [ "$launch_rc" != 0 ]; then ok "unverifiable init copy fails the launch"; else bad "launch proceeded with an unverifiable init copy"; fi
if [ -s "$DOCKER_REC" ]; then bad "failed launch still invoked docker"; else ok "failed launch did not invoke docker"; fi
dh="$(cat "$DH_REC" 2>/dev/null || true)"
contains "failed launch still deletes its session" "delete session delete dhs_TEST" "$dh"

# --- 2b4. a parent directory symlink that escapes the lab home is refused --
# Point the init directory at the shim directory (which contains a
# docker-init): the content would "work", so the refusal must come from the
# path-escape check, not from missing content.
rm -rf "$OPENCODE_DOCKER_HOME/init"
ln -s "$SHIM" "$OPENCODE_DOCKER_HOME/init"
: > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo hi ) >/dev/null 2>&1
esc_rc=$?
if [ "$esc_rc" != 0 ]; then ok "escaped init directory refuses the launch"; else bad "escaped init directory was accepted"; fi
if [ -s "$DOCKER_REC" ]; then bad "escaped init dir still invoked docker"; else ok "escaped init dir did not invoke docker"; fi
dh="$(cat "$DH_REC" 2>/dev/null || true)"
contains "escaped init dir launch still deletes its session" "delete session delete dhs_TEST" "$dh"
rm -f "$OPENCODE_DOCKER_HOME/init"

# images pinned by OCI digest
contains "base image is digest-pinned" \
  "ghcr.io/kivarun/opencode-docker/base@sha256:f6c6dd302f447ec05d93f9f6ffba92dd726dcf1a82c6181733bae10e0012b970" "$dargv"
not_contains "base image is not floating" "base:latest" "$dargv"

# a second launcher carries its own pinned digest
: > "$DOCKER_REC"
( cd "$WS" && oc-go26 echo hi )
contains "go26 image is digest-pinned" \
  "ghcr.io/kivarun/opencode-docker/go26@sha256:076273633dd33218b0a0f0d783cb80539a4066c1e59dee1b069a96db971830b7" \
  "$(cat "$DOCKER_REC" 2>/dev/null || true)"

# positional CLI (release/2.4 line): same launch, no --workspace flag
unset DH_HELP_WORKSPACE
: > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo hi )
dh="$(cat "$DH_REC" 2>/dev/null || true)"
contains "launch creates a session for \$PWD (positional CLI)" "create session create $WS --json" "$dh"

# --- 4. SIGINT still deletes the session -----------------------------------
: > "$DH_REC"; : > "$DOCKER_REC"
export STUB_SLEEP=1
( cd "$WS" && oc echo bye ) &
oc_pid=$!
for _ in $(seq 1 50); do [ -s "$DOCKER_REC" ] && break; sleep 0.1; done
kill -INT "$oc_pid" 2>/dev/null || true
wait "$oc_pid" 2>/dev/null || true
unset STUB_SLEEP
dh="$(cat "$DH_REC" 2>/dev/null || true)"
contains "SIGINT deletes the session" "delete session delete dhs_TEST" "$dh"

# --- 3b. the system docker-init is untouched across every launch -----------
check "system docker-init inode/mode unchanged across all launches" \
  "$INIT_SYS_SNAP" "$(stat -c '%d:%i %a' "$DH_INIT_SRC")"

# --- F4. every lab-managed relabel mount source is safety-gated --------------
# The launcher must refuse to run docker when a relabeled source could touch
# anything outside the agent-owned lab tree. Each case exercises the real
# launcher flow; refusal is observed through the docker record.
OUTSIDE="$WORK/outside-f4"; mkdir -p "$OUTSIDE"
printf 'SYSTEM-INODE-MARKER\n' > "$OUTSIDE/system-like-file"
outside_inode="$(stat -c '%d:%i' "$OUTSIDE/system-like-file")"

f4_reset() {
  rm -rf "$OPENCODE_DOCKER_HOME/ca" "$OPENCODE_DOCKER_HOME/git" "$OPENCODE_DOCKER_HOME/ssh"
  mkdir -p "$OPENCODE_DOCKER_HOME/ca" "$OPENCODE_DOCKER_HOME/git" "$OPENCODE_DOCKER_HOME/ssh"
  printf 'CA-CERT\n' > "$OPENCODE_DOCKER_HOME/ca/lab-ca.crt"
  printf '[user]\n\tname = agent\n' > "$OPENCODE_DOCKER_HOME/git/gitconfig"
  printf 'known hosts\n' > "$OPENCODE_DOCKER_HOME/ssh/known_hosts"
}

f4_expect_refusal() { # CASE
  : > "$DH_REC"; : > "$DOCKER_REC"
  ( cd "$WS" && oc echo hi ) >"$WORK/f4.err" 2>&1
  [ "${F4_DEBUG:-}" = "$1" ] && { echo "DEBUG[$1] $(cat "$WORK/f4.err")"; cat "$DOCKER_REC"; } >&2
  if [ -s "$DOCKER_REC" ]; then
    bad "F4/$1: docker run was reached despite the unsafe mount source"
  else
    ok "F4/$1: the launch is refused before docker runs"
  fi
  if grep -q 'session create' "$DH_REC" && grep -q 'session delete' "$DH_REC"; then
    ok "F4/$1: the session is still cleaned up after the refusal"
  else
    bad "F4/$1: the session lifecycle was broken by the refusal"
  fi
}

# F4.1 a normal lab CA copy still launches
f4_reset
: > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo hi ) >/dev/null 2>&1
[ -s "$DOCKER_REC" ] && ok "F4/normal: a clean lab CA copy launches" || bad "F4/normal: a clean CA copy was refused"

# F4.2 the CA directory itself is a symlink out of the lab tree
f4_reset; rm -rf "$OPENCODE_DOCKER_HOME/ca"; ln -s "$OUTSIDE" "$OPENCODE_DOCKER_HOME/ca"
f4_expect_refusal "ca-dir-symlink"

# F4.3 a symlink INSIDE the CA directory points at a foreign file
f4_reset; ln -s "$OUTSIDE/system-like-file" "$OPENCODE_DOCKER_HOME/ca/evil.crt"
f4_expect_refusal "ca-entry-symlink"
[ "$(stat -c '%d:%i' "$OUTSIDE/system-like-file")" = "$outside_inode" ] \
  && ok "F4/ca-entry-symlink: the foreign inode was not relabeled" \
  || bad "F4/ca-entry-symlink: the foreign inode changed"

# F4.4 a hardlink inside the CA directory aliases a foreign inode
f4_reset; ln "$OUTSIDE/system-like-file" "$OPENCODE_DOCKER_HOME/ca/hardlink.crt"
f4_expect_refusal "ca-entry-hardlink"
[ "$(stat -c '%d:%i' "$OUTSIDE/system-like-file")" = "$outside_inode" ] \
  && ok "F4/ca-entry-hardlink: the foreign inode was not relabeled" \
  || bad "F4/ca-entry-hardlink: the foreign inode changed"

# F4.5 the gitconfig source is a symlink
f4_reset; rm -f "$OPENCODE_DOCKER_HOME/git/gitconfig"; ln -s "$OUTSIDE/system-like-file" "$OPENCODE_DOCKER_HOME/git/gitconfig"
f4_expect_refusal "gitconfig-symlink"

# F4.6 a symlink inside the container-facing ssh directory
f4_reset; ln -sf "$OUTSIDE/system-like-file" "$OPENCODE_DOCKER_HOME/ssh/known_hosts"
f4_expect_refusal "ssh-entry-symlink"

# F4.7 the parent directory of the gitconfig escapes the lab tree
f4_reset; rm -rf "$OPENCODE_DOCKER_HOME/git"; mkdir -p "$OUTSIDE/etc-like"
printf '[user]\n' > "$OUTSIDE/etc-like/gitconfig"
ln -s "$OUTSIDE/etc-like" "$OPENCODE_DOCKER_HOME/git"
f4_expect_refusal "gitconfig-parent-escape"

# F4.8 a refusal never mutates the foreign inode (content + inode stable)
f4_reset; ln -s "$OUTSIDE/system-like-file" "$OPENCODE_DOCKER_HOME/ca/evil.crt"
f4_expect_refusal "final-content-check"
[ "$(cat "$OUTSIDE/system-like-file")" = "SYSTEM-INODE-MARKER" ] \
  && ok "F4: the foreign file content is unchanged after refusals" \
  || bad "F4: the foreign file content changed"

# F4.9 the unit-level gate refuses a symlinked file source directly
ln -sf "$OUTSIDE/system-like-file" "$OPENCODE_DOCKER_HOME/git/gitconfig"
if oc_lab_mount_source_ok file "$OPENCODE_DOCKER_HOME/git/gitconfig" "$OPENCODE_DOCKER_HOME" 2>/dev/null; then
  bad "F4/unit: the gate accepted a symlinked file source"
else
  ok "F4/unit: the gate refuses a symlinked file source"
fi

echo
printf 'agent-aliases tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
