#!/usr/bin/env bash
#
# agent-aliases.sh — opencode-docker launchers for the dedicated 'agent'
# account INSIDE the lab VM. Installed as ~agent/.bash_aliases by
# scripts/lab/setup-agent-user.sh and sourced from ~agent/.bashrc.
#
# Trust boundary (three separate roles):
#   * the 'agent' Linux account is the TRUSTED LAUNCHER: it owns the workspace,
#     talks to the docker-helper socket with its principal credential, creates
#     one Session per launch, and drives `docker run`;
#   * docker-helper principal 'agent' is the session owner;
#   * the UNTRUSTED model is the process inside the container. It never gets
#     docker.sock, the admin token, or the principal credential — only the
#     per-launch Session bearer and a read-only view of the helper runtime dir.
#
# Each launcher creates exactly one Session for the current workspace and
# deletes it on exit — on normal exit, Ctrl-C (SIGINT) and SIGTERM — so a
# killed launcher never leaves an orphan Session.
#
# Run from a workspace below the agent account's allowed root (e.g. ~/work/...):
#
#   cd ~/work/project && oc
#
# Guest requirements: docker, docker-helper, jq.

# --- docker-helper session lifecycle ---------------------------------------
# `session create` takes WORKSPACE positionally on the release/2.4 line and via
# `--workspace` on newer lines; probe the installed CLI once per launch and
# cache the form so the aliases work on either.
_DH_WS_STYLE=""
_dh_workspace_style() {
    if [[ -z "$_DH_WS_STYLE" ]]; then
        if command docker-helper session create --help 2>&1 | grep -q -- '--workspace'; then
            _DH_WS_STYLE=flag
        else
            _DH_WS_STYLE=positional
        fi
    fi
    printf '%s' "$_DH_WS_STYLE"
}

_dh_session_create() {
    local response

    unset DOCKER_HELPER_SESSION_ID DOCKER_HELPER_SESSION_TOKEN

    if [[ "$(_dh_workspace_style)" == flag ]]; then
        response="$(command docker-helper session create --workspace "$PWD" --json)" || return 1
    else
        response="$(command docker-helper session create "$PWD" --json)" || return 1
    fi

    DOCKER_HELPER_SESSION_ID="$(
        jq -er '.session.id | select(type == "string" and length > 0)' \
            <<<"$response"
    )" || return 1

    DOCKER_HELPER_SESSION_TOKEN="$(
        jq -er '.token | select(type == "string" and length > 0)' \
            <<<"$response"
    )" || {
        command docker-helper session delete \
            "$DOCKER_HELPER_SESSION_ID" >/dev/null 2>&1 || true
        unset DOCKER_HELPER_SESSION_ID
        return 1
    }

    export DOCKER_HELPER_SESSION_TOKEN
}

_dh_session_delete() {
    [[ -n "${DOCKER_HELPER_SESSION_ID:-}" ]] || return 0
    # SESSION_ID is positional on both the release/2.4 and newer lines.
    command docker-helper session delete "$DOCKER_HELPER_SESSION_ID" >/dev/null
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

    # Optional guest exchange directory (shared label, so several containers
    # may use it at once).
    if [[ -d "$exchange_dir" ]]; then
        extra_mounts+=(-v "$exchange_dir:/exchange:z")
    fi

    # Only the Session bearer enters the container. LLM_SERVER/LLM_KEY carry
    # the model provider auth; no GH_TOKEN, no admin token, no principal
    # credential. No docker.sock: the helper socket directory is mounted
    # read-only and authority comes solely from the bearer.
    #
    # Under SELinux the container must run in the helper's workload domain
    # (docker_helper_container_t) to reach the helper socket; the shipped
    # policy grants socket access only to that domain. On an AppArmor host the
    # SELinux label is inert (OPENCODE_DOCKER_SELINUX_TYPE may be emptied).
    local selinux_type="${OPENCODE_DOCKER_SELINUX_TYPE-docker_helper_container_t}"
    local -a selinux_opts=()
    [[ -n "$selinux_type" ]] && selinux_opts=(--security-opt "label=type:$selinux_type")

    # The container runs as the guest launcher's own uid/gid. The
    # opencode-docker image's built-in user is uid 1000, which differs from the
    # dedicated agent uid, so an explicit --user keeps the agent-owned bind
    # mounts writable by owner without widening DAC or SELinux.
    local -a user_opt=(--user "$(id -u):$(id -g)")

    # OpenCode writes under $HOME (.config, .local, .cache) and /tmp/opencode;
    # bind each from the agent-owned tree so the non-image uid can write.
    local -a home_mounts=(
        -v "$opencode_home/.config:/home/opencode/.config:Z"
        -v "$opencode_home/.local:/home/opencode/.local:Z"
        -v "$opencode_home/.cache:/home/opencode/.cache:Z"
        -v "$opencode_home/tmp:/tmp/opencode:Z"
    )
    [[ -d "$opencode_home/.ssh" ]] && home_mounts+=(-v "$opencode_home/.ssh:/home/opencode/.ssh:Z")

    # The runtime bind-mounts its --init binary with the host label (bin_t),
    # which the custom container domain cannot execute. Bind the same binary
    # explicitly with a container-domain relabel (:Z); --init then execs the
    # mounted file. Resolution is best-effort (distros place it differently).
    local docker_init="" cand
    for cand in "$(command -v docker-init 2>/dev/null || true)" \
                /usr/bin/docker-init /usr/libexec/docker/docker-init /sbin/docker-init; do
        [[ -n "$cand" && -x "$cand" ]] || continue
        docker_init="$(readlink -f "$cand")"
        break
    done
    local -a init_mount=()
    [[ -n "$docker_init" ]] && init_mount=(-v "$docker_init:/sbin/docker-init:Z")

    docker run --rm -it \
        --init \
        "${user_opt[@]}" \
        --cap-drop ALL \
        --security-opt no-new-privileges=true \
        "${selinux_opts[@]}" \
        "${init_mount[@]}" \
        -e LLM_SERVER \
        -e LLM_KEY \
        -e DOCKER_HELPER_SESSION_TOKEN \
        -v "$PWD:/workspace:Z" \
        "${home_mounts[@]}" \
        -v "$helper_runtime_dir:/run/docker-helper:ro" \
        "${extra_mounts[@]}" \
        -w /workspace \
        "$image" "$@"
)

# --- images (pinned by OCI digest for reproducibility) ----------------------
_OC_BASE='ghcr.io/kivarun/opencode-docker/base@sha256:f6c6dd302f447ec05d93f9f6ffba92dd726dcf1a82c6181733bae10e0012b970'
_OC_GO26='ghcr.io/kivarun/opencode-docker/go26@sha256:076273633dd33218b0a0f0d783cb80539a4066c1e59dee1b069a96db971830b7'
_OC_DOTNET10='ghcr.io/kivarun/opencode-docker/dotnet10@sha256:683beb7dc1e94defabf0bb81b23e99be86530765205e63e52fcb31d53523f3e6'

oc()          { _oc_run "$_OC_BASE" "$@"; }
oc-go26()     { _oc_run "$_OC_GO26" "$@"; }
oc-dotnet10() { _oc_run "$_OC_DOTNET10" "$@"; }
