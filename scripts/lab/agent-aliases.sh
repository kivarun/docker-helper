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
        # UAT-7: capture the help output fully before matching — no early-exit
        # reader that could SIGPIPE the probe; a failed probe cannot pass.
        if dh_help="$(command docker-helper session create --help 2>&1)" && printf '%s' "$dh_help" | grep -q -- '--workspace'; then
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

# --- lab-managed mount-source safety gate ------------------------------------
# R5: loads the shared gate library (single canonical implementation).
# The SINGLE canonical implementation lives in scripts/lab/lab-mount-gate.sh;
# this file only loads it. Resolution order: an explicit override, the
# agent-owned lib copy installed by provisioning (the VM), then the
# repository location (development and test environments). Without the gate
# the launcher refuses to work at all — no unguarded relabel mounts.
_lab_gate_lib="${OPENCODE_LAB_GATE_LIB:-}"
if [ -z "$_lab_gate_lib" ]; then
    for _lab_gate_cand in \
        "${HOME:-}/.opencode-docker/lib/lab-mount-gate.sh" \
        "$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)/lab-mount-gate.sh"; do
        [ -n "$_lab_gate_cand" ] && [ -f "$_lab_gate_cand" ] && { _lab_gate_lib="$_lab_gate_cand"; break; }
    done
fi
if [ -n "$_lab_gate_lib" ] && [ -f "$_lab_gate_lib" ]; then
    # shellcheck source=/dev/null
    . "$_lab_gate_lib"
else
    echo "the lab mount gate library is missing: refusing to define launchers" >&2
    return 1 2>/dev/null || exit 1
fi

# --- per-launch ssh-agent lifecycle (F5/R3) ----------------------------------
# Each launch owns a private run directory (mktemp -d, 0700) holding its own
# agent socket, so concurrent launches never share a socket pathname and one
# launch can never destroy another's socket. The sweep below removes ONLY
# resources whose ownership and completion are BOTH proven, and never uses
# pkill-style user-wide kills:
#   * launcher.pid (the real subshell pid, BASHPID) is the ownership anchor:
#     a directory WITHOUT it is suspicious and is never removed
#     automatically;
#   * a live launcher.pid means the launch is running or still initializing
#     (the agent.pid may not exist yet — that is exactly the allocation
#     race): the directory is left alone;
#   * a dead launcher.pid plus an absent agent.pid is provably finished and
#     may be swept;
#   * a dead launcher.pid with a LIVE agent.pid cannot prove that the agent
#     process is ours (a pid may be reused), so neither the agent nor the
#     directory is touched: the directory stays for manual operator review;
#   * each launcher's own cleanup (normal exit, failed ssh-add, INT, TERM)
#     remains independent and removes exactly its own directory.
_oc_ssh_stale_cleanup() {
    local base="${OPENCODE_DOCKER_HOME:-$HOME/.opencode-docker}/agent-ssh"
    [ -d "$base" ] || return 0
    local d launcher_pid agent_pid
    for d in "$base"/run.*; do
        [ -d "$d" ] || continue
        if [ ! -f "$d/launcher.pid" ]; then
            echo "note: suspicious ssh-agent run dir without launcher.pid, left for manual review: $d" >&2
            continue
        fi
        launcher_pid="$(cat "$d/launcher.pid" 2>/dev/null)"
        [ -n "$launcher_pid" ] || { echo "note: unreadable launcher.pid, left for manual review: $d" >&2; continue; }
        kill -0 "$launcher_pid" 2>/dev/null && continue
        if [ -f "$d/agent.pid" ]; then
            agent_pid="$(cat "$d/agent.pid" 2>/dev/null)"
            if [ -n "$agent_pid" ] && kill -0 "$agent_pid" 2>/dev/null; then
                echo "note: live agent behind a dead launcher, left for manual review: $d (agent pid $agent_pid)" >&2
                continue
            fi
        fi
        rm -rf -- "$d"
    done
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
# _oc_launch IMAGE MODE PAYLOAD... — the SINGLE canonical launch composition.
# Every launch (the model's `oc`, and the diagnostic probes) goes through this
# one construction: session lifecycle, mounts, security options, env, init
# copy, workspace — one owner, no parallel implementations.
#
# MODE=opencode — the image's own entrypoint runs the payload (the real model
#   launch; for the pinned image that entrypoint is `opencode`).
# MODE=exec — the payload is exec'd through `--entrypoint /bin/sh -c`, for
#   probes that must reach container binaries directly. The image ENTRYPOINT
#   is `opencode`, so bare payload words would be handed to the OpenCode CLI
#   as ITS arguments (the UAT-8 real-VM finding: `oc docker-helper self` and
#   `oc sh -c ...` never ran docker-helper or sh at all).
# --- UAT-8c: the shared canonical configuration owners -----------------------
# The security posture and the mount/env composition each have ONE owner, so
# the diagnostic ladder can replay the exact production configuration instead
# of re-describing it (a re-described configuration drifts; a shared one
# cannot). _oc_launch consumes both; lab-diag-lib.sh sources this file and
# consumes them for the D0–D2 ladder steps.

# _oc_security_opts ARR — the container security posture: the launcher uid,
# dropped capabilities, no-new-privileges, and the helper workload SELinux
# domain (inert on an AppArmor host).
_oc_security_opts() {
    # shellcheck disable=SC2178  # a bash nameref to the caller's array
    local -n out="$1"
    out+=(--user "$(id -u):$(id -g)")
    out+=(--cap-drop ALL)
    out+=(--security-opt no-new-privileges=true)
    local selinux_type="${OPENCODE_DOCKER_SELINUX_TYPE-docker_helper_container_t}"
    [[ -n "$selinux_type" ]] && out+=(--security-opt "label=type:$selinux_type")
    return 0
}

# _oc_compose_mounts_env ARR — the canonical mounts and environment: the
# workspace relabel, the agent-owned OpenCode state mounts, the model env
# flags, the optional lab-managed CA/git/ssh/exchange artifacts (each behind
# its mount-source gate), the read-only helper runtime dir, and the
# workspace workdir. The Session bearer is NOT included: only a real launch
# adds it, after creating its own Session.
_oc_compose_mounts_env() {
    # shellcheck disable=SC2178  # a bash nameref to the caller's array
    local -n out="$1"
    local helper_runtime_dir="${DOCKER_HELPER_RUNTIME_DIR:-/run/docker-helper}"
    local opencode_home="${OPENCODE_DOCKER_HOME:-$HOME/.opencode-docker}"
    local exchange_dir="${OPENCODE_EXCHANGE_DIR:-$HOME/agent-exchange}"

    # Optional guest exchange directory (shared label, so several containers
    # may use it at once).
    if [[ -d "$exchange_dir" ]]; then
        out+=(-v "$exchange_dir:/exchange:z")
    fi

    # OpenCode writes under $HOME (.config, .local, .cache) and /tmp/opencode;
    # bind each from the agent-owned tree so the non-image uid can write.
    # No other directory is mounted implicitly: SSH credentials, agent
    # configuration, and host secrets must never ride along with a launch.
    out+=(
        -v "$PWD:/workspace:Z"
        -v "$opencode_home/.config:/home/opencode/.config:Z"
        -v "$opencode_home/.local:/home/opencode/.local:Z"
        -v "$opencode_home/.cache:/home/opencode/.cache:Z"
        -v "$opencode_home/tmp:/tmp/opencode:Z"
        -v "$helper_runtime_dir:/run/docker-helper:ro"
    )

    # Model capability flags carried by the operator launcher, and the model
    # provider environment: docker resolves `-e NAME` from the launcher's own
    # environment at run time, so the values never appear in the docker argv,
    # any log, or any report (UAT-8d: these two flags were lost in the UAT-8c
    # refactor and are restored here to the exact eeeceacc contract).
    out+=(-e OPENCODE_EXPERIMENTAL_LSP_TOOL=true -e OPENCODE_ENABLE_EXA=1)
    out+=(-e LLM_SERVER -e LLM_KEY)
    [[ -n "${GH_AGENT_TOKEN:-}" ]] && out+=(-e GH_AGENT_TOKEN)

    # --- corporate CA (lab-owned copy; never a system CA file) ---------------
    # The container is created by plain `docker run`, so Docker Helper's own
    # CA injection (POST /run only) does not apply. The lab copy is mounted
    # read-only and exported to the usual TLS client variables; the image's
    # own system store cannot be updated inside a non-root pinned image.
    # The source directory is gated before any mount decision is made.
    local ca_dir="$opencode_home/ca"
    if [[ -d "$ca_dir" || -L "$ca_dir" ]]; then
        oc_lab_mount_source_ok dir "$ca_dir" "$opencode_home" \
            || { echo "unsafe relabel mount source: $ca_dir" >&2; return 1; }
        local -a ca_files=()
        local ca_path
        for ca_path in "$ca_dir"/*.crt; do
            # the combined bundle is a companion artifact, not a second
            # corporate CA — the ambiguity check applies to root choices
            [[ "$ca_path" == */combined-ca-bundle.crt ]] && continue
            [[ -f "$ca_path" ]] && ca_files+=("$ca_path")
        done
        if (( ${#ca_files[@]} > 1 )); then
            echo "ambiguous CA provisioning: multiple certificates in $ca_dir" >&2
            return 1
        fi
        if [[ -n "${ca_files[0]:-}" ]]; then
            local ca_name
            ca_name="$(basename -- "${ca_files[0]}")"
            out+=(-v "$ca_dir:/etc/opencode-ca:ro,z")
            # NODE_EXTRA_CA_CERTS ADDS the corporate CA to Node's own trust;
            # it never replaces the image's public set (F6).
            out+=(-e "NODE_EXTRA_CA_CERTS=/etc/opencode-ca/$ca_name")
            # SSL_CERT_FILE/CURL_CA_BUNDLE/GIT_SSL_CAINFO REPLACE the client
            # trust source, so they may only point at a combined bundle
            # (image public CAs + the corporate CA) built as a lab-owned
            # file. Without it these variables must not be set at all: a
            # single corporate certificate would disable trust in every
            # public CA for those clients.
            if [[ -f "$ca_dir/combined-ca-bundle.crt" ]]; then
                out+=(
                    -e "SSL_CERT_FILE=/etc/opencode-ca/combined-ca-bundle.crt"
                    -e "CURL_CA_BUNDLE=/etc/opencode-ca/combined-ca-bundle.crt"
                    -e "GIT_SSL_CAINFO=/etc/opencode-ca/combined-ca-bundle.crt"
                )
            fi
        fi
    fi

    # --- gitconfig (lab-owned copy, read-only) --------------------------------
    if [[ -f "$opencode_home/git/gitconfig" || -L "$opencode_home/git/gitconfig" ]]; then
        oc_lab_mount_source_ok file "$opencode_home/git/gitconfig" "$opencode_home" \
            || { echo "unsafe relabel mount source: $opencode_home/git/gitconfig" >&2; return 1; }
        out+=(-v "$opencode_home/git/gitconfig:/home/opencode/.gitconfig:ro,z")
    fi

    # --- public SSH host keys (lab-owned, read-only) --------------------------
    # Only public material enters the container: known_hosts for verifying
    # trusted servers. The private key and the agent's own ~/.ssh never do.
    if [[ -d "$opencode_home/ssh" || -L "$opencode_home/ssh" ]]; then
        oc_lab_mount_source_ok dir "$opencode_home/ssh" "$opencode_home" \
            || { echo "unsafe relabel mount source: $opencode_home/ssh" >&2; return 1; }
        out+=(-v "$opencode_home/ssh:/home/opencode/.ssh:ro,z")
    fi

    out+=(-w /workspace)
    return 0
}

# _oc_verify_init_copy — resolve the system docker-init and publish the
# verified lab copy that the confined container domain can exec; prints the
# copy path (empty when the host has no docker-init), fails closed on any
# unverifiable state. See _oc_launch for the full boundary rationale.
_oc_verify_init_copy() {
    local opencode_home="${OPENCODE_DOCKER_HOME:-$HOME/.opencode-docker}"
    local docker_init="" cand
    local -a candidates=()
    if [[ ${LAB_DOCKER_INIT_CANDIDATES+x} == x ]]; then
        # test-scoped seam (documented in lab-diag-lib.sh): the candidate
        # list is replaced wholesale; production never sets this variable
        read -ra candidates <<< "$LAB_DOCKER_INIT_CANDIDATES"
    else
        candidates=("$(command -v docker-init 2>/dev/null || true)"
            /usr/bin/docker-init /usr/libexec/docker/docker-init /sbin/docker-init)
    fi
    for cand in "${candidates[@]}"; do
        [[ -n "$cand" && -x "$cand" ]] || continue
        docker_init="$(readlink -f "$cand")"
        break
    done
    [[ -n "$docker_init" ]] || return 0
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
    printf '%s\n' "$init_copy"
}

# _oc_prepare_ssh_agent ARRAY — the per-launch ssh-agent owner: a private
# run directory per launch (F5) with its own socket and its own cleanup.
# On success it appends the read-only run-dir mount and SSH_AUTH_SOCK env to
# the caller's docker argv array and sets _OC_SSH_AGENT_PID /
# _OC_SSH_RUN_DIR for the caller's cleanup. A stale sweep first removes run
# dirs whose recorded agent is gone (crash leftovers); live launches are
# never touched. The launcher pid is recorded BEFORE the agent starts so a
# concurrent sweep cannot mistake a starting launch for stale. A
# passphrase-protected key cannot be loaded non-interactively: that is a
# fail-closed launch error, not a silent degradation.
_oc_prepare_ssh_agent() {
    # shellcheck disable=SC2178  # a bash nameref to the caller's array
    local -n out="$1"
    local agent_ssh_key="${OPENCODE_AGENT_SSH_KEY:-$HOME/.ssh/id_ed25519_opencode}"
    local opencode_home="${OPENCODE_DOCKER_HOME:-$HOME/.opencode-docker}"
    _OC_SSH_AGENT_PID=""
    _OC_SSH_RUN_DIR=""
    [[ -f "$agent_ssh_key" ]] || return 0
    _oc_ssh_stale_cleanup
    local run_dir
    mkdir -p "$opencode_home/agent-ssh" 2>/dev/null \
        || { echo "cannot prepare the ssh-agent base directory" >&2; return 1; }
    run_dir="$(mktemp -d "$opencode_home/agent-ssh/run.XXXXXX")" \
        || { echo "cannot allocate the ssh-agent run directory" >&2; return 1; }
    _OC_SSH_RUN_DIR="$run_dir"
    printf '%s\n' "$BASHPID" > "$run_dir/launcher.pid"
    local agent_env
    if ! agent_env="$(ssh-agent -a "$run_dir/agent.sock")"; then
        rm -rf -- "$run_dir"
        _OC_SSH_RUN_DIR=""
        echo "cannot start the per-launch ssh-agent" >&2
        return 1
    fi
    # UAT-8: ssh-agent's env script ends with `echo Agent pid N;` — eval
    # executes that echo and the message lands on the launcher's stdout,
    # where diagnostic consumers could mistake it for container output.
    # The exports still take effect; only the informational echo is
    # silenced.
    eval "$agent_env" >/dev/null
    _OC_SSH_AGENT_PID="$SSH_AGENT_PID"
    printf '%s\n' "$_OC_SSH_AGENT_PID" > "$run_dir/agent.pid"
    if ! SSH_ASKPASS_REQUIRE=never ssh-add -- "$agent_ssh_key" </dev/null; then
        kill "$_OC_SSH_AGENT_PID" 2>/dev/null || true
        _OC_SSH_AGENT_PID=""
        rm -rf -- "$run_dir"
        _OC_SSH_RUN_DIR=""
        echo "cannot load $agent_ssh_key into the ssh-agent (passphrase-protected keys are not supported by the non-interactive launcher)" >&2
        return 1
    fi
    out+=(-v "$run_dir:/ssh-agent:ro")
    out+=(-e SSH_AUTH_SOCK=/ssh-agent/agent.sock)
    return 0
}

_oc_launch() (
    local image="$1"
    local mode="$2"
    shift 2

    local helper_runtime_dir="${DOCKER_HELPER_RUNTIME_DIR:-/run/docker-helper}"
    local agent_ssh_key="${OPENCODE_AGENT_SSH_KEY:-$HOME/.ssh/id_ed25519_opencode}"
    local session_id=""
    local ssh_agent_pid=""
    local ssh_run_dir=""

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
        [ -z "$ssh_run_dir" ] || rm -rf -- "$ssh_run_dir"
        exit "$rc"
    }
    trap cleanup EXIT INT TERM

    _dh_session_create || return 1
    session_id="$DOCKER_HELPER_SESSION_ID"

    # The canonical container configuration comes from its single owners
    # (UAT-8c): the security posture, then the mounts and environment. The
    # per-launch ssh-agent forwarding below is launch-only state (processes),
    # so it stays here and appends its own mount and env.
    local -a run_args=(run --rm -it)
    local init_copy
    init_copy="$(_oc_verify_init_copy)" || return 1
    [[ -n "$init_copy" ]] && run_args+=(--init -v "$init_copy:/sbin/docker-init:ro,z")
    _oc_security_opts run_args || return 1
    _oc_compose_mounts_env run_args || return 1

    # --- SSH agent forwarding (the shared owner) ------------------------------
    if [[ -f "$agent_ssh_key" ]]; then
        _oc_prepare_ssh_agent run_args || return 1
        ssh_agent_pid="$_OC_SSH_AGENT_PID"
        ssh_run_dir="$_OC_SSH_RUN_DIR"
    fi

    # UAT-8e: narrow, explicitly enabled diagnostic provenance. A diagnostic
    # replay of this launcher may require attribution of the container it
    # starts; the knobs exist ONLY for that replay and are never set by the
    # normal oc / oc-go26 / oc-probe entry points. All three must be set
    # together (a partial diagnostic configuration is a diagnostic bug and
    # fails the launch instead of launching an unattributed container).
    if [[ -n "${OPENCODE_DIAGNOSTIC_RUNID:-}${OPENCODE_DIAGNOSTIC_NAME:-}${OPENCODE_DIAGNOSTIC_CIDFILE:-}" ]]; then
        if [[ -z "${OPENCODE_DIAGNOSTIC_RUNID:-}" || -z "${OPENCODE_DIAGNOSTIC_NAME:-}" || -z "${OPENCODE_DIAGNOSTIC_CIDFILE:-}" ]]; then
            echo "incomplete diagnostic provenance configuration (runid, name and cidfile must be set together)" >&2
            return 1
        fi
        run_args+=(--name "$OPENCODE_DIAGNOSTIC_NAME")
        run_args+=(--label "lab.diagnostic.runid=$OPENCODE_DIAGNOSTIC_RUNID")
        run_args+=(--cidfile "$OPENCODE_DIAGNOSTIC_CIDFILE")
    fi

    # Only the Session bearer enters the container. LLM_SERVER/LLM_KEY carry
    # the model provider auth; GH_AGENT_TOKEN is passed ONLY when the
    # operator explicitly exports it for this launch. No docker.sock, no
    # admin token, no principal credential. No private key either: SSH goes
    # through a per-launch ssh-agent socket only.
    run_args+=(-e DOCKER_HELPER_SESSION_TOKEN)

    if [[ "$mode" == exec ]]; then
        run_args+=(--entrypoint /bin/sh "$image" -c "$*")
    else
        run_args+=("$image" "$@")
    fi
    docker "${run_args[@]}"
)

# --- images (pinned by OCI digest for reproducibility) ----------------------
_OC_BASE='ghcr.io/kivarun/opencode-docker/base@sha256:f6c6dd302f447ec05d93f9f6ffba92dd726dcf1a82c6181733bae10e0012b970'
_OC_GO26='ghcr.io/kivarun/opencode-docker/go26@sha256:076273633dd33218b0a0f0d783cb80539a4066c1e59dee1b069a96db971830b7'

oc()      { _oc_launch "$_OC_BASE" opencode "$@"; }
oc-go26() { _oc_launch "$_OC_GO26" opencode "$@"; }

# oc-probe PAYLOAD — the diagnostic access path: the SAME canonical launch
# composition, with the payload exec'd through /bin/sh -c inside the
# container. Used by the VM integration suite to run `docker-helper self`
# and the TLS probe with the real Session bearer and the real launcher
# constraints; never a second model-launch implementation.
oc-probe() { _oc_launch "$_OC_BASE" exec "$@"; }
