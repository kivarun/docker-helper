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
# Runs in a subshell so DOCKER_HELPER_SESSION_ID/TOKEN and the ssh-agent
# environment never leak into the caller's shell.
#
# Optional capabilities (provisioned by provision-operator-files.sh; each one
# activates only when its lab-managed artifact exists):
#   * corporate CA: a lab-owned copy under $OPENCODE_DOCKER_HOME/ca is mounted
#     read-only and exposed through NODE_EXTRA_CA_CERTS / SSL_CERT_FILE /
#     CURL_CA_BUNDLE / GIT_SSL_CAINFO (the container is started by plain
#     `docker run`, so Docker Helper's own CA injection does not apply);
#   * gitconfig: a lab-owned copy under $OPENCODE_DOCKER_HOME/git is mounted
#     read-only;
#   * SSH: a dedicated ssh-agent is started as the launcher, the provisioned
#     key is loaded into it, and ONLY the agent socket plus public host keys
#     enter the container. The private key and the agent's ~/.ssh are never
#     mounted. TRUST BOUNDARY: the model holding the ssh-agent socket can
#     authenticate via SSH as the key's owner — that is this lab agent's
#     intended capability, not an accident.
_oc_run() (
    local image="$1"
    shift

    local helper_runtime_dir="${DOCKER_HELPER_RUNTIME_DIR:-/run/docker-helper}"
    local opencode_home="${OPENCODE_DOCKER_HOME:-$HOME/.opencode-docker}"
    local exchange_dir="${OPENCODE_EXCHANGE_DIR:-$HOME/agent-exchange}"
    local agent_ssh_key="${OPENCODE_AGENT_SSH_KEY:-$HOME/.ssh/id_ed25519_opencode}"
    local session_id=""
    local ssh_agent_pid=""
    local -a extra_mounts=()
    local -a docker_env=()

    [[ -S "$helper_runtime_dir/docker-helper.sock" ]] || {
        echo "docker-helper socket not found: $helper_runtime_dir/docker-helper.sock" >&2
        return 1
    }

    # Delete the Session on every exit path, and stop the per-launch ssh-agent
    # this launcher started. trap - first so a signal-driven run does not
    # re-enter cleanup through the EXIT trap.
    cleanup() {
        local rc="$?"
        trap - EXIT INT TERM
        DOCKER_HELPER_SESSION_ID="$session_id" _dh_session_delete || \
            echo "warning: failed to delete docker-helper session $session_id" >&2
        [ -z "$ssh_agent_pid" ] || kill "$ssh_agent_pid" 2>/dev/null || true
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
    # the model provider auth; GH_AGENT_TOKEN is passed ONLY when the
    # operator explicitly exports it for this launch. No docker.sock, no
    # admin token, no principal credential. No private key either: SSH goes
    # through a per-launch ssh-agent socket only.
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
    # No other directory is mounted implicitly: SSH credentials, agent
    # configuration, and host secrets must never ride along with a launch.
    local -a home_mounts=(
        -v "$opencode_home/.config:/home/opencode/.config:Z"
        -v "$opencode_home/.local:/home/opencode/.local:Z"
        -v "$opencode_home/.cache:/home/opencode/.cache:Z"
        -v "$opencode_home/tmp:/tmp/opencode:Z"
    )

    # Model capability flags carried by the operator launcher.
    docker_env+=(-e OPENCODE_EXPERIMENTAL_LSP_TOOL=true -e OPENCODE_ENABLE_EXA=1)
    [[ -n "${GH_AGENT_TOKEN:-}" ]] && docker_env+=(-e GH_AGENT_TOKEN)

    # --- corporate CA (lab-owned copy; never a system CA file) ---------------
    # The container is created by plain `docker run`, so Docker Helper's own
    # CA injection (POST /run only) does not apply. The lab copy is mounted
    # read-only and exported to the usual TLS client variables; the image's
    # own system store cannot be updated inside a non-root pinned image.
    local ca_dir="$opencode_home/ca"
    if [[ -d "$ca_dir" ]]; then
        local -a ca_files=()
        local ca_path
        for ca_path in "$ca_dir"/*.crt; do
            [[ -f "$ca_path" ]] && ca_files+=("$ca_path")
        done
        if (( ${#ca_files[@]} > 1 )); then
            echo "ambiguous CA provisioning: multiple certificates in $ca_dir" >&2
            return 1
        fi
        if [[ -n "${ca_files[0]:-}" ]]; then
            local ca_name
            ca_name="$(basename -- "${ca_files[0]}")"
            extra_mounts+=(-v "$ca_dir:/etc/opencode-ca:ro,z")
            docker_env+=(
                -e "NODE_EXTRA_CA_CERTS=/etc/opencode-ca/$ca_name"
                -e "SSL_CERT_FILE=/etc/opencode-ca/$ca_name"
                -e "CURL_CA_BUNDLE=/etc/opencode-ca/$ca_name"
                -e "GIT_SSL_CAINFO=/etc/opencode-ca/$ca_name"
            )
        fi
    fi

    # --- gitconfig (lab-owned copy, read-only) --------------------------------
    if [[ -f "$opencode_home/git/gitconfig" ]]; then
        extra_mounts+=(-v "$opencode_home/git/gitconfig:/home/opencode/.gitconfig:ro,z")
    fi

    # --- public SSH host keys (lab-owned, read-only) --------------------------
    # Only public material enters the container: known_hosts for verifying
    # trusted servers. The private key and the agent's own ~/.ssh never do.
    if [[ -d "$opencode_home/ssh" ]]; then
        extra_mounts+=(-v "$opencode_home/ssh:/home/opencode/.ssh:ro,z")
    fi

    # --- SSH agent forwarding (dedicated per-launch agent) -------------------
    # The launcher starts a fresh ssh-agent, loads the provisioned key and
    # passes ONLY the socket. A passphrase-protected key cannot be loaded
    # non-interactively: that is a fail-closed launch error, not a silent
    # degradation.
    if [[ -f "$agent_ssh_key" ]]; then
        local agent_dir="$opencode_home/agent-ssh"
        mkdir -p "$agent_dir" 2>/dev/null && chmod 0700 "$agent_dir" \
            || { echo "cannot prepare the ssh-agent directory: $agent_dir" >&2; return 1; }
        rm -f -- "$agent_dir/agent.sock"
        local agent_env
        if ! agent_env="$(ssh-agent -a "$agent_dir/agent.sock")"; then
            echo "cannot start the per-launch ssh-agent" >&2
            return 1
        fi
        eval "$agent_env"
        ssh_agent_pid="$SSH_AGENT_PID"
        if ! SSH_ASKPASS_REQUIRE=never ssh-add -- "$agent_ssh_key" </dev/null; then
            kill "$ssh_agent_pid" 2>/dev/null || true
            ssh_agent_pid=""
            echo "cannot load $agent_ssh_key into the ssh-agent (passphrase-protected keys are not supported by the non-interactive launcher)" >&2
            return 1
        fi
        extra_mounts+=(-v "$agent_dir:/ssh-agent:ro")
        docker_env+=(-e SSH_AUTH_SOCK=/ssh-agent/agent.sock)
    fi

    # --init under the confined container domain. The runtime bind-mounts its
    # own init binary from the host filesystem, whose system label the custom
    # container domain cannot execute (live AVC: exec /sbin/docker-init:
    # permission denied). Relabeling THAT system inode with :Z is forbidden:
    # it would mutate a system executable of the guest. Instead a lab-owned
    # COPY of the same binary is verified and bind-mounted; the relabel then
    # touches only the copy inside the agent-owned lab tree.
    #
    # The published copy must be a STANDALONE regular file at an independent
    # inode: a symlink (or a hardlink) to the system binary would make the
    # ro,z relabel land on the system inode — exactly what must never happen.
    # A SHA-256 match alone does NOT prove independence, so device/inode are
    # compared explicitly, the copy is published atomically (temp file +
    # rename) and re-verified immediately before it is handed to Docker.
    #
    # TOCTOU boundary (documented residual risk): between the final
    # verification and the docker mount the copy could in principle be
    # swapped by another process able to write the lab init directory. That
    # directory is owned by the trusted launcher account; the untrusted model
    # cannot reach it (it is not mounted into any container), and the guest
    # root is the trusted provisioning domain. No policy change is made for
    # this; the trust boundary is the launcher account itself.
    local docker_init="" cand
    for cand in "$(command -v docker-init 2>/dev/null || true)" \
                /usr/bin/docker-init /usr/libexec/docker/docker-init /sbin/docker-init; do
        [[ -n "$cand" && -x "$cand" ]] || continue
        docker_init="$(readlink -f "$cand")"
        break
    done
    local -a init_mount=()
    if [[ -n "$docker_init" ]]; then
        [[ -r "$docker_init" && -f "$docker_init" ]] \
            || { echo "resolved docker-init is not a readable regular file: $docker_init" >&2; return 1; }
        local init_copy_dir="$opencode_home/init"
        local init_copy="$init_copy_dir/docker-init"

        # Every significant path component must stay inside the agent-owned
        # lab root: a symlinked directory that resolves outside
        # $opencode_home is refused (the relabel must never land outside the
        # lab tree).
        local home_real init_dir_real
        home_real="$(readlink -f -- "$opencode_home")" \
            || { echo "cannot resolve the lab home: $opencode_home" >&2; return 1; }
        init_dir_real="$(readlink -f -- "$init_copy_dir")" \
            || { echo "cannot resolve the lab init directory: $init_copy_dir" >&2; return 1; }
        [[ "$init_dir_real" == "$home_real/"* && "$init_dir_real" != "$home_real" ]] \
            || { echo "lab init directory escapes the lab home: $init_copy_dir" >&2; return 1; }

        mkdir -p "$init_copy_dir" 2>/dev/null \
            || { echo "cannot create the lab init directory: $init_copy_dir" >&2; return 1; }

        # Refresh when the existing path is not a standalone, byte-identical
        # regular file: missing, a symlink, a hardlink alias of the system
        # binary, or drifted content. Publication is atomic (temp file +
        # rename), so a relabeled copy from a previous run never needs to be
        # written in place and a partial copy is never visible.
        local src_sum copy_sum needs_refresh=0
        src_sum="$(sha256sum -- "$docker_init" | awk '{print $1}')" \
            || { echo "cannot hash the system docker-init" >&2; return 1; }
        if [[ -L "$init_copy" ]]; then
            needs_refresh=1
        elif [[ ! -f "$init_copy" ]]; then
            needs_refresh=1
        else
            copy_sum="$(sha256sum -- "$init_copy" | awk '{print $1}')" || copy_sum=""
            if [[ "$(stat -c '%d:%i' -- "$init_copy")" == "$(stat -c '%d:%i' -- "$docker_init")" ]] \
               || [[ "$copy_sum" != "$src_sum" ]]; then
                needs_refresh=1
            fi
        fi
        if [[ "$needs_refresh" = 1 ]]; then
            local tmp=""
            tmp="$(mktemp -- "$init_copy_dir/.docker-init.XXXXXX")" \
                || { echo "cannot stage the lab docker-init copy" >&2; return 1; }
            if ! cp -- "$docker_init" "$tmp" || ! chmod 0755 -- "$tmp"; then
                rm -f -- "$tmp"
                echo "cannot copy docker-init into the lab tree" >&2
                return 1
            fi
            if ! mv -f -- "$tmp" "$init_copy"; then
                rm -f -- "$tmp"
                echo "cannot publish the lab docker-init copy" >&2
                return 1
            fi
            tmp=""
        fi

        # FINAL verification of the exact file about to be mounted. Failure is
        # fail-closed: the launch never falls back to the system binary.
        [[ -f "$init_copy" && ! -L "$init_copy" ]] \
            || { echo "lab docker-init copy is not a standalone regular file" >&2; return 1; }
        [[ "$(stat -c '%d:%i' -- "$init_copy")" != "$(stat -c '%d:%i' -- "$docker_init")" ]] \
            || { echo "lab docker-init copy aliases the system binary (hardlink)" >&2; return 1; }
        copy_sum="$(sha256sum -- "$init_copy" | awk '{print $1}')"
        [[ "$copy_sum" = "$src_sum" ]] \
            || { echo "lab docker-init copy does not match the system binary" >&2; return 1; }

        # Read-only shared relabel (ro,z): the container only execs the binary;
        # the shared label stays stable across concurrent launches instead of
        # being re-pinned to each container's single-use :Z categories.
        init_mount=(-v "$init_copy:/sbin/docker-init:ro,z")
    fi

    docker run --rm -it \
        --init \
        "${user_opt[@]}" \
        --cap-drop ALL \
        --security-opt no-new-privileges=true \
        "${selinux_opts[@]}" \
        "${init_mount[@]}" \
        "${docker_env[@]}" \
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

oc()      { _oc_run "$_OC_BASE" "$@"; }
oc-go26() { _oc_run "$_OC_GO26" "$@"; }
