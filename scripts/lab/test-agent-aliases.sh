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
#   7. the images are pinned by OCI digest (no floating :latest).
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
ok()  { PASS=$((PASS+1)); printf 'ok   - %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf 'FAIL - %s\n' "$1"; }
contains() { # desc needle haystack
  case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (missing '$2' in '$3')" ;; esac
}
not_contains() { # desc needle haystack
  case "$3" in *"$2"*) bad "$1 (unexpected '$2' in '$3')" ;; *) ok "$1" ;; esac
}

# --- stubs -----------------------------------------------------------------
SHIM="$WORK/shim"; mkdir -p "$SHIM" "$WORK/run"

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
contains "docker-init is relabeled for the container domain" ":/sbin/docker-init:Z" "$dargv"
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

echo
printf 'agent-aliases tests: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
