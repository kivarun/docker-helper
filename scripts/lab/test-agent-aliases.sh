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

chmod +x "$SHIM/docker-helper" "$SHIM/docker"

# A real AF_UNIX socket at the expected path (kept bound by a background pid).
python3 -c 'import socket,sys,time; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); time.sleep(300)' \
  "$WORK/run/docker-helper.sock" &
SOCK_PID=$!
for _ in $(seq 1 20); do [ -S "$WORK/run/docker-helper.sock" ] && break; sleep 0.1; done

export PATH="$SHIM:$PATH"
export DH_REC="$WORK/dh.rec" DOCKER_REC="$WORK/docker.rec"
export DOCKER_HELPER_RUNTIME_DIR="$WORK/run"
export OPENCODE_DOCKER_HOME="$WORK/ochome"
export OPENCODE_EXCHANGE_DIR="$WORK/absent-exchange"
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
dh="$(cat "$DH_REC" 2>/dev/null || true)"
contains "SIGINT deletes the session" "delete session delete dhs_TEST" "$dh"

# --- 3b. the system docker-init is untouched across every launch -----------
check "system docker-init inode/mode unchanged across all launches" \
  "$INIT_SYS_SNAP" "$(stat -c '%d:%i %a' "$DH_INIT_SRC")"

echo
printf 'agent-aliases tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
