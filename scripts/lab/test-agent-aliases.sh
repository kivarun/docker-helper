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
[ -n "${STUB_SLEEP:-}" ] && sleep "${STUB_SLEEP_SECONDS:-30}"
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
python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])' "$sock" 2>/dev/null || : > "$sock"
sleep 300 >/dev/null 2>&1 &
pid=$!
echo "$pid" > "$SSH_AGENT_PIDFILE"
echo "SSH_AUTH_SOCK=$sock; export SSH_AUTH_SOCK;"
echo "SSH_AGENT_PID=$pid; export SSH_AGENT_PID;"
echo "echo Agent pid $pid;"
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

# --- UAT-8. the ssh-agent's "Agent pid" echo never reaches launch stdout ----
# The real ssh-agent env script ends with `echo Agent pid N;`; eval executes
# it and the message used to land on the launcher's stdout, where diagnostic
# consumers could mistake it for container output. The launcher suppresses
# only that echo; the exported env still takes effect (the launch still
# works and the agent socket is still created).
export DH_HELP_WORKSPACE=1
# the ssh-agent branch must really run for this check: provision the key
# for the duration of the block (the suite creates it later for its own
# ssh sections; the state is restored here)
mkdir -p "$(dirname "$OPENCODE_AGENT_SSH_KEY")"
printf 'PRIVATE-KEY\n' > "$OPENCODE_AGENT_SSH_KEY"
chmod 0600 "$OPENCODE_AGENT_SSH_KEY"
: > "$DH_REC"; : > "$DOCKER_REC"
oc_stdout="$( cd "$WS" && oc echo hi )"
case "$oc_stdout" in
  *"Agent pid"*) bad "UAT-8 RED: the ssh-agent 'Agent pid' echo polluted the launch stdout" ;;
  *) ok "UAT-8: no ssh-agent 'Agent pid' echo on the launch stdout" ;;
esac

# --- UAT-8. oc-probe execs the payload through /bin/sh -c -------------------
# The image ENTRYPOINT is `opencode`, so `oc docker-helper self --json` and
# `oc sh -c ...` hand their words to the OpenCode CLI as ITS arguments and
# never run docker-helper or sh (the UAT-8 real-VM finding). oc-probe is the
# diagnostic access path: the SAME canonical launch composition, with
# --entrypoint /bin/sh and the payload as `-c`.
mkdir -p "$(dirname "$OPENCODE_AGENT_SSH_KEY")"
printf 'PRIVATE-KEY\n' > "$OPENCODE_AGENT_SSH_KEY"
chmod 0600 "$OPENCODE_AGENT_SSH_KEY"
: > "$DH_REC"; : > "$DOCKER_REC"
probe_stdout="$( cd "$WS" && oc-probe 'docker-helper self --json' )"
pargv="$(cat "$DOCKER_REC")"
contains "oc-probe overrides the entrypoint to /bin/sh" "--entrypoint /bin/sh" "$pargv"
not_contains "oc-probe does not hand the payload to the image entrypoint bare" "--entrypoint /bin/sh $WS" "$(printf '%s' "$pargv" | sed 's/-c /-c PLACEHOLDER /')"
contains "oc-probe runs the payload through -c" "-c docker-helper self --json" "$pargv"
contains "oc-probe keeps the canonical session bearer" "-e DOCKER_HELPER_SESSION_TOKEN" "$pargv"
contains "oc-probe keeps the canonical user" "--user $(id -u):$(id -g)" "$pargv"
contains "oc-probe keeps cap-drop ALL" "--cap-drop ALL" "$pargv"
contains "oc-probe keeps no-new-privileges" "no-new-privileges=true" "$pargv"
contains "oc-probe keeps the helper workload SELinux domain" "label=type:docker_helper_container_t" "$pargv"
contains "oc-probe keeps the workspace relabel" "$WS:/workspace:Z" "$pargv"
contains "oc-probe keeps the read-only helper runtime dir" "$WORK/run:/run/docker-helper:ro" "$pargv"
dh="$(cat "$DH_REC")"
contains "oc-probe creates its own Session" "create session create --workspace $WS" "$dh"
contains "oc-probe deletes its Session on exit" "delete session delete dhs_TEST" "$dh"
case "$probe_stdout" in
  *"Agent pid"*) bad "UAT-8: oc-probe stdout carries the ssh-agent echo" ;;
  *) ok "UAT-8: oc-probe stdout carries only the container payload output" ;;
esac

rm -f "$OPENCODE_AGENT_SSH_KEY"

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
not_contains "F6: without a combined bundle the client trust variables are NOT overridden" "SSL_CERT_FILE" "$dargv"
not_contains "F6: without a combined bundle curl trust is NOT overridden" "CURL_CA_BUNDLE" "$dargv"
not_contains "F6: without a combined bundle git trust is NOT overridden" "GIT_SSL_CAINFO" "$dargv"
contains "gitconfig copy is mounted read-only" "$OPENCODE_DOCKER_HOME/git/gitconfig:/home/opencode/.gitconfig:ro,z" "$dargv"
contains "public ssh material is mounted read-only" "$OPENCODE_DOCKER_HOME/ssh:/home/opencode/.ssh:ro,z" "$dargv"
contains "the ssh-agent socket dir is the only agent mount" "/ssh-agent:ro" "$dargv"
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

# F6: with a combined bundle the client trust variables point at it
printf 'PUBLIC-CA-1\n-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----\n' > "$OPENCODE_DOCKER_HOME/ca/combined-ca-bundle.crt"
: > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo hi )
dargv="$(cat "$DOCKER_REC" 2>/dev/null || true)"
contains "F6: NODE_EXTRA_CA_CERTS still adds the corporate CA" "-e NODE_EXTRA_CA_CERTS=/etc/opencode-ca/lab-ca.crt" "$dargv"
contains "F6: SSL_CERT_FILE uses the combined bundle" "-e SSL_CERT_FILE=/etc/opencode-ca/combined-ca-bundle.crt" "$dargv"
contains "F6: CURL_CA_BUNDLE uses the combined bundle" "-e CURL_CA_BUNDLE=/etc/opencode-ca/combined-ca-bundle.crt" "$dargv"
contains "F6: GIT_SSL_CAINFO uses the combined bundle" "-e GIT_SSL_CAINFO=/etc/opencode-ca/combined-ca-bundle.crt" "$dargv"
rm -f "$OPENCODE_DOCKER_HOME/ca/combined-ca-bundle.crt"

# the full mounted source allowlist with every capability present; the
# ssh-agent run directory is unique per launch, so it is taken from the argv
agent_ssh_mount="$(printf '%s' "$dargv" | grep -oE '\-v [^ ]*agent-ssh/run[^ :]*:/ssh-agent:ro' | head -1 | sed 's/^-v //; s|:/ssh-agent:ro$||')"
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
$agent_ssh_mount" \
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

# R5: the gate has exactly ONE canonical implementation in the repository
check "R5: the mount gate is defined exactly once in the lab scripts" "1" \
  "$(grep -rc 'oc_lab_mount_source_ok() {' "$SRC_DIR/lab/" 2>/dev/null | awk -F: '$1 !~ /test-/ && $2 > 0' | wc -l)"
check "R5: the launcher loads the shared gate library" "1" \
  "$(grep -c 'loads the shared gate library' "$ALIASES")"

# F4.9 the unit-level gate refuses a symlinked file source directly
ln -sf "$OUTSIDE/system-like-file" "$OPENCODE_DOCKER_HOME/git/gitconfig"
if oc_lab_mount_source_ok file "$OPENCODE_DOCKER_HOME/git/gitconfig" "$OPENCODE_DOCKER_HOME" 2>/dev/null; then
  bad "F4/unit: the gate accepted a symlinked file source"
else
  ok "F4/unit: the gate refuses a symlinked file source"
fi

# --- R4. an incomplete filesystem walk is never accepted as safe -------------
# A traversal error (previously swallowed by 2>/dev/null into a process
# substitution) must fail the whole gate.
r4_tree="$OPENCODE_DOCKER_HOME/ca"
f4_reset
mkdir -p "$r4_tree/sub/deeper"
printf 'CA\n' > "$r4_tree/sub/deeper/deep.crt"
if oc_lab_mount_source_ok dir "$r4_tree" "$OPENCODE_DOCKER_HOME" 2>/dev/null; then
  ok "R4: a fully accessible safe tree passes"
else
  bad "R4: a fully accessible safe tree was refused"
fi

mkdir -p "$r4_tree/locked"
printf 'X\n' > "$r4_tree/locked/f.crt"
chmod 000 "$r4_tree/locked"
if oc_lab_mount_source_ok dir "$r4_tree" "$OPENCODE_DOCKER_HOME" 2>/dev/null; then
  bad "R4: an unreadable nested directory was accepted as safe"
else
  ok "R4: an unreadable nested directory fails the gate"
fi
chmod 755 "$r4_tree/locked"

ln -sf "$OUTSIDE/system-like-file" "$r4_tree/sub/deeper/evil2.crt"
if oc_lab_mount_source_ok dir "$r4_tree" "$OPENCODE_DOCKER_HOME" 2>/dev/null; then
  bad "R4: a deep symlink entry was accepted"
else
  ok "R4: a deep symlink entry fails the gate"
fi
rm -f "$r4_tree/sub/deeper/evil2.crt"

mkfifo "$r4_tree/sub/pipe"
if oc_lab_mount_source_ok dir "$r4_tree" "$OPENCODE_DOCKER_HOME" 2>/dev/null; then
  bad "R4: an unsupported object type (fifo) was accepted"
else
  ok "R4: an unsupported object type fails the gate"
fi
rm -f "$r4_tree/sub/pipe"

# foreign-filesystem entry: verified through a controlled stat mock (a real
# cross-device bind mount needs privileges; the check itself is the same
# st_dev comparison exercised here)
mkdir -p "$WORK/statshim" "$r4_tree/sub/mnt"
printf 'X\n' > "$r4_tree/sub/mnt/foreign.crt"
real_stat="$(command -v stat)"
cat > "$WORK/statshim/stat" <<SH
#!/bin/sh
case "\$*" in
  *"/sub/mnt/"*) echo "999999" ;;
  *) exec "$real_stat" "\$@" ;;
esac
SH
chmod +x "$WORK/statshim/stat"
if PATH="$WORK/statshim:$PATH" oc_lab_mount_source_ok dir "$r4_tree" "$OPENCODE_DOCKER_HOME" 2>/dev/null; then
  bad "R4: a foreign-filesystem entry was accepted"
else
  ok "R4: a foreign-filesystem entry fails the gate"
fi

# F4: a nested EMPTY mountpoint (no files for the previous file-level check to
# catch) must be refused through the directory's own st_dev. A fresh tree is
# used so the earlier non-empty mountpoint cannot explain the refusal.
rm -rf "$r4_tree"
mkdir -p "$r4_tree/sub/mnt-empty"
real_stat="$(command -v stat)"
cat > "$WORK/statshim/stat" <<SH
#!/bin/sh
case "\$*" in
  *%F*"/sub/mnt"*) echo "directory" ;;
  *%F*) exec "$real_stat" "\$@" ;;
  *"/sub/mnt"*) echo "999999" ;;
  *) exec "$real_stat" "\$@" ;;
esac
SH
chmod +x "$WORK/statshim/stat"
if PATH="$WORK/statshim:$PATH" oc_lab_mount_source_ok dir "$r4_tree" "$OPENCODE_DOCKER_HOME" 2>/dev/null; then
  bad "F4: an empty nested foreign-filesystem mountpoint was accepted"
else
  ok "F4: an empty nested foreign-filesystem mountpoint fails the gate"
fi
rm -rf "$r4_tree/sub/mnt-empty"

# launcher-level: the unreadable directory refuses the launch before docker
f4_reset
mkdir -p "$OPENCODE_DOCKER_HOME/ca/locked"
printf 'X\n' > "$OPENCODE_DOCKER_HOME/ca/locked/f.crt"
chmod 000 "$OPENCODE_DOCKER_HOME/ca/locked"
: > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo hi ) >/dev/null 2>&1
chmod 755 "$OPENCODE_DOCKER_HOME/ca/locked"
if [ -s "$DOCKER_REC" ]; then bad "R4: docker ran despite an incomplete walk"; else ok "R4: docker is not called when the walk is incomplete"; fi

# --- F5. concurrent launches own private ssh-agent sockets -------------------
# The previous design used one shared socket path: the next launch's rm -f
# broke the running launch's agent. Each launch must own a private run dir.
mkdir -p "$(dirname "$OPENCODE_AGENT_SSH_KEY")"
printf 'PRIVATE-KEY\n' > "$OPENCODE_AGENT_SSH_KEY"
f4_reset  # start from a clean capability layout (the F4 cases left traps)

f5_socket_of() { # RECFILE -> the agent-ssh mount source of that record
  printf '%s' "$(cat "$1" 2>/dev/null || true)" \
    | grep -oE "\-v [^ ]*agent-ssh/run[^ :]*:/ssh-agent:ro" \
    | head -1 | sed 's/^-v //; s|:/ssh-agent:ro$||'
}

# F5.1 two overlapping launches get different socket paths; the first is not
# broken by the second
: > "$DH_REC"; : > "$DOCKER_REC"
( export STUB_SLEEP=1 STUB_SLEEP_SECONDS=6; cd "$WS" && oc echo first ) &
a_pid=$!
for _ in $(seq 1 50); do grep -q "agent-ssh/run" "$DOCKER_REC" 2>/dev/null && break; sleep 0.1; done
a_sock="$(f5_socket_of "$DOCKER_REC")"
if [ -n "$a_sock" ]; then ok "F5: the first launch mounts its own run socket"; else bad "F5: no agent-ssh run mount for the first launch"; fi
if [ -S "$a_sock/agent.sock" ]; then ok "F5: the first launch's socket exists while it runs"; else bad "F5: the first launch's socket is missing (a_sock=$a_sock; ls: $(ls -la "$a_sock" 2>&1 | tail -2))"; fi

: > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo second )
b_sock="$(f5_socket_of "$DOCKER_REC")"
if [ -n "$b_sock" ] && [ "$a_sock" != "$b_sock" ]; then
  ok "F5: concurrent launches use different socket paths"
else
  bad "F5: concurrent launches share a socket path ('$a_sock' vs '$b_sock')"
fi
if [ -S "$a_sock/agent.sock" ]; then
  ok "F5: the second launch did not break the first launch's socket"
else
  bad "F5: the second launch destroyed the first launch's socket"
fi
if grep -q 'delete session delete dhs_TEST' "$DH_REC"; then
  ok "F5: the second launch deleted its own session"
else
  bad "F5: the second launch did not delete its session"
fi
wait "$a_pid" 2>/dev/null || true
unset STUB_SLEEP STUB_SLEEP_SECONDS
if [ ! -e "$a_sock" ]; then ok "F5: the first launch cleaned its own run dir"; else bad "F5: the first launch left its run dir"; fi

# F5.2 a failed ssh-add cleans only its own agent; a foreign live run survives
foreign_dir="$OPENCODE_DOCKER_HOME/agent-ssh/run.foreign"
mkdir -p "$foreign_dir"
sleep 20 >/dev/null 2>&1 &
foreign_pid=$!
printf '%s\n' "$foreign_pid" > "$foreign_dir/agent.pid"
export SSH_ADD_FAIL=1
: > "$DH_REC"; : > "$DOCKER_REC"
( cd "$WS" && oc echo hi ) >/dev/null 2>&1
unset SSH_ADD_FAIL
remaining=0
for d in "$OPENCODE_DOCKER_HOME/agent-ssh"/run.*; do
  [ -d "$d" ] || continue
  case "$(basename "$d")" in
    run.foreign) ;;
    *) remaining=$((remaining+1)) ;;
  esac
done
check "F5: a failed ssh-add removed its own run dir" "0" "$remaining"
if kill -0 "$foreign_pid" 2>/dev/null && [ -d "$foreign_dir" ]; then
  ok "F5: a failed launch left the foreign live run untouched"
else
  bad "F5: a failed launch touched the foreign live run"
fi
kill "$foreign_pid" 2>/dev/null || true
rm -rf "$foreign_dir"

# F5.3 the stale-resource sweep removes only dead launches (no pkill)
sleep 20 >/dev/null 2>&1 &
live_pid=$!
mkdir -p "$foreign_dir"
printf '%s\n' "$live_pid" > "$foreign_dir/agent.pid"
printf '%s\n' "$live_pid" > "$foreign_dir/launcher.pid"
dead_dir="$OPENCODE_DOCKER_HOME/agent-ssh/run.dead"
mkdir -p "$dead_dir"
printf '%s\n' "999999" > "$dead_dir/agent.pid"
printf '%s\n' "999999" > "$dead_dir/launcher.pid"
( cd "$WS" && oc echo hi ) >/dev/null 2>&1
if [ ! -e "$dead_dir" ]; then ok "F5: the sweep removed the dead run dir"; else bad "F5: the sweep left the dead run dir"; fi
if [ -d "$foreign_dir" ] && kill -0 "$live_pid" 2>/dev/null; then
  ok "F5: the sweep never touches a live run"
else
  bad "F5: the sweep removed a live run"
fi
kill "$live_pid" 2>/dev/null || true; rm -rf "$foreign_dir"

# --- R3. the stale sweep is race-safe and never guesses ----------------------
# Ownership and completion must both be proven before a run dir is removed;
# a missing launcher.pid is NEVER proof of staleness. The scenarios below are
# deterministic pid-state setups, not sleep races.
r3_base="$OPENCODE_DOCKER_HOME/agent-ssh"
mkdir -p "$r3_base"

# R3.1 a live launcher without agent.pid yet (the allocation race): kept
mkdir -p "$r3_base/run.starting"
printf '%s\n' "$$" > "$r3_base/run.starting/launcher.pid"
_oc_ssh_stale_cleanup
if [ -d "$r3_base/run.starting" ]; then
  ok "R3: a live launcher without agent.pid is not swept"
else
  bad "R3: the sweep destroyed a launching run dir"
fi

# R3.2 a dir with no pidfiles at all is suspicious: never auto-removed
mkdir -p "$r3_base/run.suspicious"
_oc_ssh_stale_cleanup
if [ -d "$r3_base/run.suspicious" ]; then
  ok "R3: a suspicious dir without pidfiles is not auto-removed"
else
  bad "R3: the sweep auto-removed a suspicious dir"
fi

# R3.3 a dead launcher with a live agent: the agent is never killed on a
# pid we cannot prove ownership of; the dir stays for manual review
mkdir -p "$r3_base/run.orphan-agent"
printf '%s\n' "999999" > "$r3_base/run.orphan-agent/launcher.pid"
sleep 20 >/dev/null 2>&1 &
orphan_agent_pid=$!
printf '%s\n' "$orphan_agent_pid" > "$r3_base/run.orphan-agent/agent.pid"
_oc_ssh_stale_cleanup
if [ -d "$r3_base/run.orphan-agent" ] && kill -0 "$orphan_agent_pid" 2>/dev/null; then
  ok "R3: a live agent behind a dead launcher is left for manual review"
else
  bad "R3: the sweep killed or deleted an unproven live agent"
fi
kill "$orphan_agent_pid" 2>/dev/null || true
rm -rf "$r3_base/run.orphan-agent"

# R3.4 a provably dead launch (both pids dead) is swept
mkdir -p "$r3_base/run.expired"
printf '%s\n' "999998" > "$r3_base/run.expired/launcher.pid"
printf '%s\n' "999997" > "$r3_base/run.expired/agent.pid"
_oc_ssh_stale_cleanup
if [ ! -e "$r3_base/run.expired" ]; then
  ok "R3: a provably dead launch is swept"
else
  bad "R3: a provably dead launch survived the sweep"
fi

# R3.5 the launcher pid must be the real subshell pid (BASHPID), not the
# parent's $$: during a live launch launcher.pid differs from this shell
mkdir -p "$(dirname "$OPENCODE_AGENT_SSH_KEY")"
printf 'PRIVATE-KEY\n' > "$OPENCODE_AGENT_SSH_KEY"
f4_reset
: > "$DH_REC"; : > "$DOCKER_REC"
( export STUB_SLEEP=1 STUB_SLEEP_SECONDS=6; cd "$WS" && oc echo first ) &
r3_pid=$!
for _ in $(seq 1 50); do grep -q "agent-ssh/run" "$DOCKER_REC" 2>/dev/null && break; sleep 0.1; done
r3_sock="$(f5_socket_of "$DOCKER_REC")"
r3_launcher_pid="$(cat "$r3_sock/launcher.pid" 2>/dev/null || true)"
if [ -n "$r3_launcher_pid" ] && [ "$r3_launcher_pid" != "$$" ]; then
  ok "R3: launcher.pid records the real launch process (BASHPID)"
else
  bad "R3: launcher.pid is the parent's pid ($$) or missing ('$r3_launcher_pid')"
fi
wait "$r3_pid" 2>/dev/null || true
unset STUB_SLEEP STUB_SLEEP_SECONDS
rm -f "$OPENCODE_AGENT_SSH_KEY"
rm -rf "$r3_base/run.starting" "$r3_base/run.suspicious"

# F5.4 an interrupted launcher cleans its Session, its agent and its dir
mkdir -p "$(dirname "$OPENCODE_AGENT_SSH_KEY")"
printf 'PRIVATE-KEY\n' > "$OPENCODE_AGENT_SSH_KEY"
: > "$DH_REC"; : > "$DOCKER_REC"
( export STUB_SLEEP=1 STUB_SLEEP_SECONDS=30; cd "$WS" && oc echo bye ) &
oc_pid=$!
for _ in $(seq 1 50); do grep -q "agent-ssh/run" "$DOCKER_REC" 2>/dev/null && break; sleep 0.1; done
int_sock="$(f5_socket_of "$DOCKER_REC")"
kill -INT "$oc_pid" 2>/dev/null || true
wait "$oc_pid" 2>/dev/null || true
unset STUB_SLEEP STUB_SLEEP_SECONDS
if grep -q 'delete session delete dhs_TEST' "$DH_REC" && [ -n "$int_sock" ] && [ ! -e "$int_sock" ]; then
  ok "F5: an interrupted launcher cleans its session, agent and run dir"
else
  bad "F5: an interrupted launcher left resources behind (sock=$int_sock)"
fi
rm -f "$OPENCODE_AGENT_SSH_KEY"

echo
printf 'agent-aliases tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
