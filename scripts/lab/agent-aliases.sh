#!/usr/bin/env bash
#
# agent-aliases.sh — opencode-docker launchers for the dedicated 'agent' host
# user. Installed as ~agent/.bash_aliases by scripts/lab/setup-agent-user.sh
# and sourced from ~agent/.bashrc.
#
# Each launcher creates exactly one docker-helper Session for the current
# workspace, runs the agent container under it, and deletes the Session on
# exit — on normal exit, Ctrl-C (SIGINT) and SIGTERM — so a killed launcher
# never leaves an orphan Session. The worker container never receives
# docker.sock: it gets only the Session bearer and a read-only view of the
# helper runtime directory.
#
# Run from a workspace below the agent user's allowed root (e.g. ~/work/...):
#
#   cd ~/work/project && oc
#
# Host requirements: docker, docker-helper, jq.

# --- docker-helper session lifecycle ---------------------------------------
_dh_session_create() {
    local response

    unset DOCKER_HELPER_SESSION_ID DOCKER_HELPER_SESSION_TOKEN

    response="$(
        command docker-helper session create \
            --workspace "$PWD" \
            --json
    )" || return 1

    DOCKER_HELPER_SESSION_ID="$(
        jq -er '.session.id | select(type == "string" and length > 0)' \
            <<<"$response"
    )" || return 1

    DOCKER_HELPER_SESSION_TOKEN="$(
        jq -er '.token | select(type == "string" and length > 0)' \
            <<<"$response"
    )" || {
        command docker-helper session delete \
            --id "$DOCKER_HELPER_SESSION_ID" >/dev/null 2>&1 || true
        unset DOCKER_HELPER_SESSION_ID
        return 1
    }

    export DOCKER_HELPER_SESSION_TOKEN
}

_dh_session_delete() {
    [[ -n "${DOCKER_HELPER_SESSION_ID:-}" ]] || return 0
    command docker-helper session delete \
        --id "$DOCKER_HELPER_SESSION_ID" >/dev/null
}

# --- launcher ---------------------------------------------------------------
# Runs in a subshell so DOCKER_HELPER_SESSION_ID/TOKEN never leak into the
# caller's shell.
_oc_run() (
    local image="$1"
    shift

    local helper_runtime_dir="${DOCKER_HELPER_RUNTIME_DIR:-/run/docker-helper}"
    local opencode_home="${OPENCODE_DOCKER_HOME:-$HOME/.opencode-docker}"
    local exchange_dir="${OPENCODE_EXCHANGE_DIR:-$HOME/agent-exchange}"
    local session_id=""
    local -a extra_mounts=()

    [[ -S "$helper_runtime_dir/docker-helper.sock" ]] || {
        echo "docker-helper socket not found: $helper_runtime_dir/docker-helper.sock" >&2
        return 1
    }

    # Delete the Session on every exit path. trap - first so a signal-driven
    # run does not re-enter cleanup through the EXIT trap.
    cleanup() {
        local rc="$?"
        trap - EXIT INT TERM
        DOCKER_HELPER_SESSION_ID="$session_id" _dh_session_delete || \
            echo "warning: failed to delete docker-helper session $session_id" >&2
        exit "$rc"
    }
    trap cleanup EXIT INT TERM

    _dh_session_create || return 1
    session_id="$DOCKER_HELPER_SESSION_ID"

    # Optional host exchange directory (shared label, so several containers
    # may use it at once).
    if [[ -d "$exchange_dir" ]]; then
        extra_mounts+=(-v "$exchange_dir:/exchange:z")
    fi

    docker run --rm -it \
        --init \
        --cap-drop ALL \
        --security-opt no-new-privileges=true \
        -e LLM_SERVER \
        -e LLM_KEY \
        -e GH_TOKEN \
        -e DOCKER_HELPER_SESSION_TOKEN \
        -v "$PWD:/workspace:Z" \
        -v "$opencode_home/.config:/home/opencode/.config:Z" \
        -v "$opencode_home/.local/share/opencode:/home/opencode/.local/share/opencode:Z" \
        -v "$helper_runtime_dir:/run/docker-helper:ro" \
        "${extra_mounts[@]}" \
        -w /workspace \
        "$image" "$@"
)

# --- images -----------------------------------------------------------------
oc()          { _oc_run ghcr.io/kivarun/opencode-docker/base:latest "$@"; }
oc-go26()     { _oc_run ghcr.io/kivarun/opencode-docker/go26:latest "$@"; }
oc-dotnet10() { _oc_run ghcr.io/kivarun/opencode-docker/dotnet10:latest "$@"; }
