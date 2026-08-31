# docker-helper

docker-helper is a policy-enforcing daemon that provides a restricted
interface to Docker.

A coding agent runs on the same machine as the developer and needs to
build images and run containers. Giving the agent direct access to
`docker.sock` means it can read any file on the host, access any network,
and run arbitrary processes. docker-helper sits between the agent and
Docker and enforces policy:

- host paths accepted as build contexts and bind-mount sources are
  restricted to the session workspace;
- build, pull, and run require a session token; session management
  requires an admin token or Principal credential;
- all supported Docker operations are mediated by the daemon;
- the developer controls which workspace each session can access.

docker-helper assumes the agent cannot directly read `admin.token` or
access `docker.sock`. It does not sandbox an otherwise unrestricted agent
process running as the same host user.

Full architecture and detailed API documentation: [docs/architecture.md](docs/architecture.md)

## Table of contents

- [Deployment modes](#deployment-modes)
- [Authentication model](#authentication-model)
- [Prerequisites](#prerequisites)
- [Docker access](#docker-access)
- [Installation](#installation)
  - [Quick start: user mode](#quick-start-user-mode)
  - [Quick start: system mode](#quick-start-system-mode)
  - [Package installation](#package-installation)
- [Getting started](#getting-started)
- [Session management](#session-management)
- [Operator CLI](#operator-cli)
- [Bash completion](#bash-completion)
- [Client interfaces](#client-interfaces)
- [Using the HTTP API](#using-the-http-api)
- [Security](#security)
- [Logging](#logging)
- [Agent instructions](#agent-instructions)
- [Mandatory access control (system mode)](#mandatory-access-control-system-mode)
  - [AppArmor](#apparmor)
  - [SELinux](#selinux)
- [Workspace root policy](#workspace-root-policy)
- [System mode: provisioning a principal](#system-mode-provisioning-a-principal)
- [Documentation](#documentation)
- [Release artifacts](#release-artifacts)
- [License](#license)
- [More information](#more-information)

## Deployment modes

docker-helper supports two deployment modes determined by the effective
UID of the process:

| | User mode | System mode |
|---|---|---|
| **Effective UID** | non-root | root |
| **Config** | `${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper/config.json` | `/etc/docker-helper/config.json` |
| **State** | `${XDG_STATE_HOME:-$HOME/.local/state}/docker-helper` | `/var/lib/docker-helper` |
| **Runtime** | `$XDG_RUNTIME_DIR/docker-helper` | `/run/docker-helper` |
| **Transport** | Unix socket (0600) | Unix socket (0666) + loopback HTTP |
| **Default HTTP** | — | `127.0.0.1:52375` |

In user mode, the daemon runs as the current user and listens on a
private Unix socket.

In system mode, the daemon runs as root, serves multiple principals, and
exposes both a system Unix socket and a loopback HTTP listener. The
loopback HTTP address is configurable (`http_address`); changing it
requires a daemon restart.

System daemon mode is implemented. Release 2 adds system mode, native
DEB/RPM packages, a systemd system service, and mandatory confinement by
exactly one supported MAC backend: AppArmor or enforcing SELinux.

## Authentication model

Three authentication classes provide different levels of access:

1. **Admin token** — full administrative access: manage principals,
   credentials, and all sessions.
2. **Principal credential** — bound to a principal: create sessions for
   that principal, list and delete only that principal's sessions.
   Cannot manage principals or credentials.
3. **Session token** — narrow workspace capability for Docker operations
   (pull, build, run, registry login).

After a session token is issued:
- revoking the Principal credential does not invalidate the session;
- disabling the principal deletes its active sessions and blocks their tokens;
- removing an allowed root does not invalidate the session;
- session expiry or deletion blocks future requests;
- an already-started Docker operation continues its lifecycle.

## Prerequisites

- Linux
- Docker CLI and access to a running Docker daemon

To build from source, you additionally need:
- Go 1.23.0 with the go1.26.7 toolchain pinned in `go.mod` (the `go` command
  honors the `toolchain` directive automatically), CGO enabled, and a C
  compiler

## Docker access

Docker access requirements depend on deployment mode.

### User mode

The user running docker-helper must be able to access the Docker daemon.
docker-helper runs as the current user and does not use sudo (except
optionally for the AppArmor profile). Ensure the current user has Docker
access before installing.

For a standard rootful Docker installation, add the user to the `docker`
group:

```bash
sudo usermod -aG docker "$USER"
```

Log out and back in for the new group membership to apply. Verify access
before starting docker-helper:

```bash
docker info
```

Membership in the `docker` group is effectively root-level access to the
host. For rootless Docker, use the already configured Docker environment
instead of adding the user to the `docker` group.

### System mode

The system daemon runs as root and accesses rootful Docker directly.
Rootful Docker is effectively root-equivalent host capability.

Principals do NOT need direct docker.sock access or membership in the
`docker` group. The daemon mediates all Docker operations on their behalf.

## Installation

Install the package or extract the release tarball. Both DEB and RPM
packages support user mode and system mode. The release tarball supports
both modes via `install.sh` (user) and `install-system.sh` (system).

### Quick start: user mode

Single-user deployment. No root required after package installation.
Uses the current user's home directory as the default allowed root.

```bash
docker-helper init
systemctl --user enable --now docker-helper
mkdir -p ~/myproject
docker-helper session create --workspace ~/myproject
```

Export the `TOKEN` printed by `session create` (starts with `dht_...`):

```bash
export DOCKER_HELPER_SESSION_TOKEN='dht_...'
docker-helper pull alpine:3.24
docker-helper run --image alpine:3.24 -- echo hello-from-docker-helper
```

User mode does not require principals or credentials. The current user
creates sessions directly.

### Quick start: system mode

Multi-user deployment. Requires root for initial setup.

```bash
sudo docker-helper init
sudo systemctl enable --now docker-helper
sudo docker-helper principal create alice
sudo docker-helper credential create alice
```

The `credential create` command uses the name `default` unless `--name` is
provided and prints the token once. On alice's machine (not as root):

```bash
docker-helper credential install
mkdir -p ~/myproject
docker-helper session create --workspace ~/myproject
```

Export the `TOKEN` printed by `session create` (starts with `dht_...`):

```bash
export DOCKER_HELPER_SESSION_TOKEN='dht_...'
docker-helper pull alpine:3.24
docker-helper run --image alpine:3.24 -- echo hello-from-docker-helper
```

`credential install` reads the token from stdin and stores it for
subsequent use. After installation, `docker-helper` commands use the
credential and connect to the correct daemon automatically.

For more on principals, allowed roots, and MAC confinement, see
below.

### Package installation

Install the package for your distribution:

**Ubuntu / DEB:**

```bash
sudo apt install ./docker-helper_*.deb
```

**openSUSE Tumbleweed / RPM:**

```bash
sudo zypper install ./docker-helper-*.rpm
```

Both package formats install the binary, system and user systemd units,
the AppArmor system profile, Bash completion, and man pages. The RPM also
contains the compiled SELinux policy module. Packages do NOT run `init`,
generate configuration, or start the service. Thus one native package supports
both user and system deployment; the selected service determines the mode.

The RPM is validated against openSUSE Tumbleweed. It carries both AppArmor
and SELinux runtime toolchain dependencies because RPM dependency resolution
cannot select packages based on the host's active LSM. Broader RPM
distribution support is planned post-Release-2.

Package installation paths:

| Path | Description |
|------|-------------|
| `/usr/bin/docker-helper` | Binary |
| `/etc/docker-helper/config.json` | Configuration (created by init) |
| `/etc/docker-helper/admin.token` | Admin token (created by init) |
| `/var/lib/docker-helper/docker-helper.db` | State database (created by init) |
| `/run/docker-helper/docker-helper.sock` | Unix socket (created at runtime) |

#### Package removal

**DEB:**

- `apt remove docker-helper` stops/disables the service and removes
  packaged assets; config and state are preserved.
- `apt purge docker-helper` additionally removes config, state, and
  runtime data.

**RPM:**

- Final erase stops/disables the service and removes packaged assets;
  persistent config and state are preserved.
- Modified managed-roots follows native RPM `%config(noreplace)`
  semantics.

### Release tarball

Download the release tarball, extract it, and run the installer:

```bash
tar xzf docker-helper-*.tar.gz
cd docker-helper-*
./install.sh
```

The installer copies the binary to `~/.local/bin/docker-helper`,
installs the systemd user unit, and optionally installs the agent
skill. For non-interactive installation:

```bash
./install.sh --yes
```

For system mode from a tarball:

```bash
sudo ./install-system.sh --yes --allowed-root /srv/workspaces
```

Unlike native packages, extracting or running the normal tarball installer does
not provision system mode. `install-system.sh` is the explicit manual
system-install path.

### Manual installation

Build from source and place the binary in `~/.local/bin` (the `go` command
uses the Go version and `go1.26.7` toolchain pinned in `go.mod`):

```bash
go build -o docker-helper .
mkdir -p ~/.local/bin
cp docker-helper ~/.local/bin/docker-helper
```

Ensure `~/.local/bin` is on your PATH (most distributions add it via
`~/.profile` or `/etc/profile`).

Install the systemd user unit:

```bash
mkdir -p ~/.config/systemd/user
cp packaging/systemd/user/docker-helper.service ~/.config/systemd/user/
systemctl --user daemon-reload
```

### Uninstall

Soft uninstall (preserves config and state):

```bash
./uninstall.sh
```

Hard uninstall (also removes `~/.config/docker-helper` and
`~/.local/state/docker-helper`):

```bash
./uninstall.sh --purge
```

## Getting started

### 1. Initialize

```bash
docker-helper init
```

Creates configuration and state directories, writes `config.json` with
`allowed_roots`, `session_ttl`, `log_level` (default `info`), `shutdown_timeout`
(default `30s`), `operation_retention_ttl` (default `10m`),
`operation_max_completed` (default `200`), and `operation_log_max_bytes`
(default `4194304` = 4 MiB), and generates an admin token. The
token is printed once and stored beside the config file.

If running interactively and `--allowed-root` is not provided, you will
be prompted for the allowed root directory. The user's home directory is
used as the default. For root, `/home` is used as the default.

```bash
docker-helper init --allowed-root /path/to/workspaces
```

In non-interactive environments (CI, scripts), `--allowed-root` is
required.

By default, the config file is at:

```
${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper/config.json
```

and the token at:

```
${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper/admin.token
```

To relocate the config and token, set `DOCKER_HELPER_CONFIG` before
running `init`, `serve`, and `config` commands:

```bash
export DOCKER_HELPER_CONFIG=/some/path/config.json
```

This changes the effective locations to:

```
config_path=/some/path/config.json
config_dir=/some/path
admin_token_path=/some/path/admin.token
```

The same environment variable must be supplied to the daemon and CLI.
`DOCKER_HELPER_CONFIG` does not relocate runtime or state data; those
continue to follow `XDG_RUNTIME_DIR` and `XDG_STATE_HOME`.

### 2. Review and modify configuration

```bash
docker-helper config show
```

Displays all configuration fields as JSON. The `admin_token` is shown as
`"<redacted>"`. To see the real token:

```bash
docker-helper config show admin_token
```

To modify a setting:

```bash
docker-helper config set log_level debug
docker-helper config set audit_enabled true
```

Workspace roots are managed through dedicated commands:

```bash
docker-helper config allowed-root add /path/to/workspaces
docker-helper config allowed-root list
```

Each command prints feedback: `updated` when the value changes, `unchanged`
when it was already set to the same value.

To remove a setting and restore its default:

```bash
docker-helper config unset log_level
docker-helper config unset audit_enabled
docker-helper config unset shutdown_timeout
docker-helper config unset operation_retention_ttl
docker-helper config unset operation_max_completed
docker-helper config unset operation_log_max_bytes
```

Each prints `unset` when the member was removed, or `unchanged ... is already unset`
when it was already absent. `allowed_roots` and `session_ttl` are required and
cannot be unset.

Configuration fields:

**Configurable members** accepted in config.json:

| Field | Type | Description |
|-------|------|-------------|
| `allowed_roots` | array of strings | Canonical root directories for agent workspaces (required) |
| `session_ttl` | duration | Session lifetime, e.g. `12h` (required) |
| `log_level` | string | `debug`, `info`, `warn`, `error` (default: `info`) |
| `audit_enabled` | boolean | Override audit behavior (default: `true` in system mode; in user mode, `true` only when `log_level` is `debug`) |
| `shutdown_timeout` | duration | Graceful shutdown budget for HTTP drain + operation termination (default: `30s`; maximum `30s` so the internal budget always fits inside systemd `TimeoutStopSec=45s`; the last part of the budget is reserved for force cleanup, which must finish by the deadline — the extra 15s outside the internal maximum covers process exit and systemd's SIGKILL fallback, not the internal force-cleanup phase). Release 1 configs with a value above `30s` still load but are bounded to `30s` at startup with a warning; `config show` reports the effective value |
| `operation_retention_ttl` | duration | How long completed operations are kept (default: `10m`) |
| `operation_max_completed` | int | Max completed operations retained in memory (default: `200`) |
| `operation_log_max_bytes` | int | Max bytes retained per operation log and synchronous pull output (bounded buffer, default: `4194304` = 4 MiB) |
| `trusted_ca_path` | string | Absolute path to a single PEM X.509 CA certificate file (optional, required when `trusted_ca_injection` is `auto`). The source may be located anywhere on the host. |
| `trusted_ca_injection` | string | `"disabled"` or `"auto"` (default: `"disabled"`). When `auto`, injects CA into containers via `POST /run`. |
| `http_address` | string | Loopback TCP listen address `127.0.0.1:PORT`, system mode only, restart required (default: `127.0.0.1:52375`) |

`allowed_roots` and `session_ttl` are required and cannot be unset.
Other fields may be unset to restore their defaults, except that
`trusted_ca_path` cannot be unset while `trusted_ca_injection` is `auto`
— set it to `disabled` first.

Runtime reload: after `config set` or `config unset`, the change is written
to disk immediately. If the daemon is running, the new configuration is
applied automatically, except for startup-only fields such as `http_address`
which require a daemon restart. If the daemon is not running, the change
will apply on the next start.

The operation is transactional: if the daemon rejects the new configuration
during reload, the change is automatically rolled back to the previous
config.json contents and the command exits with a non-zero status. If
rollback and reload after rollback succeed, config.json and the daemon are
synchronized. If the reload after rollback fails, they may diverge until the
next manual reload or restart.

You can also trigger a reload explicitly:

```bash
docker-helper reload
```

This asks the running daemon to re-read `config.json` and apply changes
without restarting. If the daemon is not running, the command fails with
a non-zero exit code. The reload validates the new configuration before
applying it; if validation fails, the daemon keeps its current configuration
and the command returns an error.

The following fields are applied at runtime:
- `allowed_roots`
- `session_ttl`
- `log_level`
- `audit_enabled`
- `shutdown_timeout`
- `operation_retention_ttl`
- `operation_max_completed`
- `operation_log_max_bytes`
- `trusted_ca_path`
- `trusted_ca_injection`

Startup-only fields (require daemon restart):
- `http_address`

Runtime paths (socket, database, state) are not changed by reload.

### Trusted CA injection

Inject a company or internal CA certificate into agent containers so they
trust your internal services. The CA file must be a single PEM-encoded
X.509 CA certificate. Injection only affects containers started via
`POST /run`.

#### User mode

User mode accepts any absolute path to a readable CA file.

```bash
docker-helper config set trusted_ca_path /absolute/path/to/company-root-ca.pem
docker-helper config set trusted_ca_injection auto
```

#### System mode

System mode accepts any absolute path to a readable CA file, just like user
mode. The source does not have to live under `/etc/docker-helper`.

```bash
sudo install -m 0644 company-root-ca.crt /etc/docker-helper/company-root-ca.crt
```

On SELinux hosts, restore the correct label:

```bash
sudo restorecon /etc/docker-helper/company-root-ca.crt
```

Then enable injection:

```bash
sudo docker-helper config set trusted_ca_path /etc/docker-helper/company-root-ca.crt
sudo docker-helper config set trusted_ca_injection auto
```

The CA source may also be an arbitrary host path, for example a certificate
managed by the distribution CA bundle:

```bash
sudo docker-helper config set trusted_ca_path /var/lib/ca-certificates/pem/RCA-CA.pem
sudo docker-helper config set trusted_ca_injection auto
```

#### Disable

```bash
docker-helper config set trusted_ca_injection disabled
docker-helper config unset trusted_ca_path
```

Each command triggers a daemon reload automatically when the daemon is
running.

In system mode, the source file must also be readable under the active AppArmor
or SELinux policy. Arbitrary host locations are not a portable confined-system
contract; use a helper-owned operator-controlled location until the Release 2
source lifecycle is finalized.

**Computed/output-only fields** are read-only and must not be added to
config.json. If present, configuration validation and daemon startup fail:

| Field | Description |
|-------|-------------|
| `audit_enabled_source` | `"explicit"`, `"system_default"`, or `"log_level"` |
| `config_path` | Path to `config.json` |
| `config_dir` | Configuration directory |
| `runtime_dir` | Runtime directory under `XDG_RUNTIME_DIR` |
| `socket_path` | Unix socket path |
| `lock_path` | Lock file path |
| `state_dir` | State directory |
| `database_path` | SQLite database path |
| `admin_token_path` | Path to `admin.token` |
| `admin_token` | Admin token (redacted in general show) |
| `mode` | `"user"` or `"system"` |

### 3. Start the daemon

Choose one of the startup modes below. In user mode the daemon listens on
the Unix socket at `$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock`
(permissions 0600). In system mode it listens on both
`/run/docker-helper/docker-helper.sock` (0666) and the configured loopback
HTTP address (default `127.0.0.1:52375`).

On SIGINT or SIGTERM, docker-helper stops accepting new connections and
waits for in-flight HTTP requests to complete, up to the configured
`shutdown_timeout` (default and maximum 30 seconds). The last part of the
30-second budget is reserved by the supervisor for force cleanup, which must
finish by the `shutdown_timeout` deadline — force cleanup does not start
after the deadline. The shipped systemd units use `TimeoutStopSec=45s`; the
extra 15 seconds sit outside the internal daemon budget and cover process
final exit, scheduler/kernel/systemd overhead, and systemd's SIGKILL
fallback if the process still has not exited. They are not intended for the
regular internal force-cleanup phase.

#### Manual foreground run

```bash
docker-helper serve
```

Use this mode for testing and troubleshooting. Audit records are written
to stdout, operational logs to stderr. Stop the daemon with Ctrl+C.

#### systemd user service

The systemd user service runs as the current user. That user must have
Docker access before the service is started.

Enable and start the service:

```bash
systemctl --user daemon-reload
systemctl --user enable --now docker-helper
```

Check status and logs:

```bash
systemctl --user status docker-helper
journalctl --user -u docker-helper
```

Reload configuration without restarting:

```bash
docker-helper reload
# or
systemctl --user reload docker-helper
```

## Session management

### Create a session

```bash
docker-helper session create --workspace /path/to/project
```

Returns the session ID, token (shown once), workspace, creation time,
and expiration time. The workspace must be inside an allowed root.

Assign the printed token to an environment variable for use in later
examples:

```bash
export DOCKER_HELPER_SESSION_TOKEN='dht_...'
```

### List sessions

```bash
docker-helper session list
```

### Delete a session

```bash
docker-helper session delete --id dhs_...
```

Permanently removes the session. Subsequent requests with its token
receive 401 Unauthorized.

### Clean up expired sessions

```bash
docker-helper session cleanup
```

Removes expired session rows from the local state database and cleans up
stale session runtime directories. Session runtime directories may contain
session-scoped Docker registry credentials. Active sessions are untouched.
Expired sessions are already rejected for authentication and excluded from
session lists by their `expires_at` value; this command is useful for
explicitly reclaiming storage during long daemon uptimes. The daemon also
removes expired sessions automatically at startup. No running daemon or
admin token is required.

## Operator CLI

API-backed operator commands (principal, credential, session, reload, admin-token rotate)
support explicit endpoint selection:

```
--system              connect to system daemon (Unix socket)
--endpoint ENDPOINT   explicit endpoint (unix:///path or http://127.0.0.1:port)
--token-file PATH     token file path
```

Default behavior: select the user socket when it exists; otherwise select the
system socket. The token source changes with the selected socket: user-mode
`admin.token` for the user socket, and the installed Principal credential (or
root system `admin.token`) for the system socket.

`--endpoint` requires `--token-file`. `--system` and `--endpoint` are
mutually exclusive. Selection happens before the request; if the selected
endpoint is unavailable, the command fails rather than retrying another daemon.

For the full command syntax, use `docker-helper help <command>`.

## Bash completion

Bash completion is available and installed automatically when using the
DEB or RPM packages. Command names and flags are derived from the command tree;
selected argument values have specialized completion (e.g., directories for
`config allowed-root add`).

Install manually:

    source <(docker-helper completion bash)

Or persistently:

    docker-helper completion bash > ~/.local/share/bash-completion/completions/docker-helper

Package-installed completion is at:

    /usr/share/bash-completion/completions/docker-helper

Restart your shell or source the file to activate.

## Client interfaces

Docker Helper has two supported client interfaces:

- **CLI** — `docker-helper pull/build/run/registry login`
- **HTTP API** — direct protocol access over the Unix socket

Neither is deprecated or fallback. Choice depends on deployment and environment.

### CLI

The `docker-helper` binary includes a client CLI for agent use. The client
commands use `DOCKER_HELPER_SESSION_TOKEN` available in the client environment and communicate with the running daemon.

```bash
docker-helper pull IMAGE
docker-helper build --context . --dockerfile Dockerfile --image NAME
docker-helper run --image NAME -- command args...
docker-helper registry login --registry REG --username USER
```

`build` and `run` appear synchronous: the CLI polls for completion, streams
logs, and returns the final exit status. Operation IDs and log offsets are
handled internally.

Agent-facing commands (`pull`, `build`, `run`, `registry login`) select the
daemon endpoint the same way operator commands do, but authenticate with the
Session token from `DOCKER_HELPER_SESSION_TOKEN` (never a Principal
credential):

```
--system              connect to system daemon (Unix socket)
--endpoint ENDPOINT   explicit endpoint (/path, unix:///path, or http://127.0.0.1:port)
```

Resolution precedence:

1. `--endpoint` (explicit)
2. `--system` (system socket)
3. `DOCKER_HELPER_SOCKET_PATH`
4. the existing user-mode socket `$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock`
5. the system socket `/run/docker-helper/docker-helper.sock`

The presence of `XDG_RUNTIME_DIR` alone does not select a user socket; agent
commands fall back to the system socket when no user-mode daemon is present.
`--system` and `--endpoint` are mutually exclusive.

SIGINT (Ctrl+C) or SIGTERM cancels the current operation:
- SIGINT -> exit 130
- SIGTERM -> exit 143

Use `docker-helper help` and `docker-helper help <command>` for discovery.

Portable agent skill for Claude Code and OpenCode:
[.claude/skills/docker-helper/SKILL.md](.claude/skills/docker-helper/SKILL.md)

## Using the HTTP API

The HTTP API is the direct protocol interface and is fully supported for
agent integrations, custom clients, and environments where the CLI binary
is not installed.

The `curl` examples below demonstrate direct HTTP use.

### Pull

```bash
curl --unix-socket "$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d '{"image":"alpine:3.24"}' \
  http://localhost/pull
```

### Build

`POST /build` starts an asynchronous Docker build and returns immediately
with an `operation_id`. The build runs in the background.

```bash
curl --unix-socket "$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d '{"context":".","dockerfile":"Dockerfile","image":"myapp:v1"}' \
  http://localhost/build
```

Optional `build_args` (map of string keys to string values) passes
build-time variables to Docker:

```bash
curl --unix-socket "$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d '{"context":".","dockerfile":"Dockerfile","image":"myapp:v1","build_args":{"FOO":"bar","VERSION":"1.2.3"}}' \
  http://localhost/build
```

Build-arg names must match `[A-Za-z_][A-Za-z0-9_]*`. Empty values are valid.
Build args are not intended for secrets. Values may become visible in Docker
build output depending on the Dockerfile/build process. Docker Helper audit
records contain only `build_arg_keys`, never build-arg values.

Response (HTTP 201):

```json
{"ok":true,"operation_id":"op_abcdef1234567890","status":"running"}
```

**Poll status** until `status` is `succeeded` or `failed`:

```bash
curl --unix-socket "$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  http://localhost/operations/op_abcdef1234567890
```

**Read incremental logs** using the `offset` parameter:

```bash
curl --unix-socket "$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  'http://localhost/operations/op_abcdef1234567890/logs?offset=0'
```

The logs response includes `next_offset` (use it as the `offset` for the
next request) and `truncated` (true when older log data was evicted by
the bounded retention limit, `operation_log_max_bytes`).

### Run

`POST /run` starts an asynchronous container run and returns immediately
with an `operation_id`. The container runs in the background.

```bash
curl --unix-socket "$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d '{"image":"alpine:3.24","command":["echo","hello"]}' \
  http://localhost/run
```

Optional `shm_size` sets the `/dev/shm` size for the container. Accepts
a plain integer with an optional binary unit (`k`, `m`, `g`; case-insensitive).
Example: `"64m"`, `"1g"`. Maximum is 2 GiB. If omitted, Docker uses its default.

Response (HTTP 201):

```json
{"ok":true,"operation_id":"op_abcdef1234567890","status":"running"}
```

Track progress using the same operation workflow as build:

- **Poll status** until `status` is `succeeded` or `failed`:

  ```bash
  curl --unix-socket "$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock" \
    -H "Authorization: Bearer $SESSION_TOKEN" \
    http://localhost/operations/op_abcdef1234567890
  ```

- **Read incremental logs** using the `offset` parameter:

  ```bash
  curl --unix-socket "$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock" \
    -H "Authorization: Bearer $SESSION_TOKEN" \
    'http://localhost/operations/op_abcdef1234567890/logs?offset=0'
  ```

Run-specific result codes:

- `succeeded` — container exited with status 0;
- `docker_run_failed` — Docker run operation failed;
- `container_exit_nonzero` — container exited with a non-zero status;
- `cancelled` — operation cancelled by client.

### Cancel an operation

Cancel a running build or run operation:

```bash
curl --unix-socket "$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -X POST 'http://localhost/operations/op_abcdef1234567890/cancel'
```

The operation becomes terminal with `status=failed` and `result_code=cancelled`.
Cancelling an already-terminal operation is idempotent (returns current state).

### Private registry authentication

Authenticate with a private registry before pulling images:

```bash
curl --unix-socket "$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "registry": "registry.example.com",
    "username": "myuser",
    "password": "mypassword"
  }' \
  http://localhost/registry/login
```

Or use the CLI:

```bash
docker-helper registry login \
  --registry registry.example.com \
  --username myuser
```

When run interactively, the CLI prompts for the password via the terminal.
Use `--password-stdin` for non-interactive automation.

After successful login, subsequent `POST /pull` requests for images from
that registry use the stored credentials automatically.

### Health check

```bash
curl --unix-socket "$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock" \
  http://localhost/health
```

No authentication required.

### Getting the socket path and admin token

Use `config show` to retrieve paths and tokens for scripting:

```bash
SOCKET=$(docker-helper config show socket_path)
curl --unix-socket "$SOCKET" http://localhost/health

ADMIN_TOKEN=$(docker-helper config show admin_token)
curl --unix-socket "$SOCKET" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost/sessions
```

Note: `docker-helper config show` (without a field) displays
`"admin_token": "<redacted>"` to prevent accidental leakage. Use
`docker-helper config show admin_token` to print the real token.

## Security

- **Host path policy** — build contexts, Dockerfiles, and bind-mount
  sources are validated against the session workspace. Builds use an
  isolated staging copy with FD-relative traversal; system-mode run
  mounts use inode-pinned helper-owned mounts.
- **Bearer authentication** — admin token uses SHA-256 hashing with
  constant-time comparison in memory; Principal credentials and session
  tokens use SHA-256 hashes stored in SQLite and resolved through
  database lookup.
- **Socket permissions** — user mode Unix socket has 0600 permissions;
  system mode Unix socket has 0666 permissions. In system mode, the
  socket is accessible to any local user, but security is enforced
  through bearer authentication and authorization, not socket
  permissions alone.
- **Container policy** — containers run with `--rm` and
  `--user <uid>:<gid>` (principal UID:GID for principal-owned sessions,
  daemon UID:GID for legacy/admin sessions). User mode and AppArmor system mode
  use `--security-opt label=disable`; SELinux system mode uses the confined
  `docker_helper_container_t` type.
- **Mandatory access control** — system mode requires exactly one active
  backend: AppArmor with `docker-helper-system`, or enforcing SELinux with the
  daemon in `docker_helper_t`. Neither, both, and permissive SELinux fail closed.
  The release tarball also includes an optional user-mode AppArmor profile
  template.

**Known limitations:**

- docker-helper does not sandbox a coding tool that already has direct
  access to the host filesystem.
- In user mode, bind-mount sources are restricted to the workspace root.
  Subdirectory and file mounts are not available.
- Builds and containers use Docker's default networking; docker-helper
  does not provide network isolation.
- docker-helper is a highly trusted component because it has access to
  the Docker daemon, so a validation or command-construction bug may
  compromise the host.
- Operation logs for async build/run are bounded by `operation_log_max_bytes`; older output is evicted when the limit is reached.
- Detached containers, custom networks, named volumes, and resource
  controls are not supported.

## Logging

docker-helper writes two separate JSON Lines streams:

- **stdout** — audit records (one JSON object per line).
- **stderr** — operational records (structured slog JSON).

The `audit_enabled` config field controls whether audit records are written
to stdout. The `log_level` config field controls operational log verbosity
on stderr (`debug`, `info`, `warn`, `error`; default `info`).

Full logging and audit documentation — including audit enablement rules,
event schema, request correlation, and sensitive-data handling — is in
[docs/architecture.md](docs/architecture.md) § Audit logging.

## Agent instructions

Agents using docker-helper need explicit operating instructions because the
helper enforces policy that the agent must not bypass. A portable skill is
available at
[.claude/skills/docker-helper/SKILL.md](.claude/skills/docker-helper/SKILL.md).

## Mandatory access control (system mode)

System mode requires exactly one supported enforcing backend. Backend
detection is automatic; the operator cannot select a weaker mode with a flag.

### Common workflow

The normal workflow for managing workspace roots is backend-neutral:

```bash
# Initial setup
sudo docker-helper init --allowed-root /opt/docker-helper-workspaces

# Add workspace roots later
sudo docker-helper config allowed-root add /path/to/workspace
```

`config allowed-root add` updates the global authorization ceiling only.
It does NOT prepare MAC state. MAC preparation occurs at session creation
time for the concrete workspace.

### AppArmor

System mode uses mandatory AppArmor confinement with the
`docker-helper-system` profile. Managed workspace roots are stored in
`/etc/apparmor.d/docker-helper.d/managed-roots`.

MAC preparation occurs at session creation time for the concrete workspace.
`docker-helper init` does NOT prepare MAC state for the bootstrap allowed root.

Advanced backend-specific management:

```bash
docker-helper apparmor root list
docker-helper apparmor root add /path/to/workspace
docker-helper apparmor root remove /path/to/workspace
docker-helper apparmor check
```

User mode does not use AppArmor confinement by default. The release tarball
includes an optional user-mode AppArmor profile template that can be
installed manually.

### SELinux

On an enforcing SELinux system, the systemd service runs in
`docker_helper_t`; containers started by the service use
`docker_helper_container_t` with MCS confinement.

#### Workspace SELinux labeling

- `/home` and descendants retain their normal host `user_home_type` labels.
  docker-helper does not relabel `/home` paths.

- Explicitly managed non-home workspace roots (e.g., `/opt/docker-helper-workspaces`)
  use the dedicated `docker_helper_workspace_t` SELinux type.
  MAC preparation occurs at session creation time for the concrete workspace,
  not when the root is added.

- Previously managed roots may retain the `docker_helper_workspace_t` label
  after an authorization change, because existing sessions can still reference
  them. This label is confinement metadata, not authorization.

- No Docker `:z`/`:Z` mount options or `label=disable` is used for workspace
  labeling. The SELinux labeling is managed natively through `semanage fcontext`
  and `restorecon`.

#### Container workspace permissions

Authorized workspace mounts support normal development-tree operations such
as creating/modifying files, building and executing workspace binaries,
symlinks, Unix-domain socket pathnames, and FIFOs.

Both `user_home_type` and `docker_helper_workspace_t` have equivalent
container-side development workspace semantics.

The RPM contains `/usr/share/selinux/docker_helper.pp` and its lifecycle script
loads the module on an enforcing SELinux host. The DEB does not install the
SELinux module. See [docs/selinux-support-plan.md](docs/selinux-support-plan.md)
for the policy contract and outstanding distribution UAT.

### AppArmor-confined curl

On some distributions (openSUSE, Ubuntu with `apparmor-profiles`),
`/usr/bin/curl` is confined by its own AppArmor profile. This prevents
curl from connecting to docker-helper sockets, even though
docker-helper itself is working correctly.

**Symptom:** curl fails with `Permission denied` when connecting to the
socket, while the `docker-helper` CLI works normally. The denial applies
to the `curl` AppArmor profile, not to the socket permissions.

**Fix:** add the bundled AppArmor compatibility snippet to the curl
profile's local include directory, then reload the curl profile.

For a native package installation, the snippet is at
`/usr/share/docker-helper/apparmor/local/curl`. For a release tarball,
it is at `apparmor/local/curl`.

```bash
# Append the snippet to the curl local profile
sudo sh -c 'cat /usr/share/docker-helper/apparmor/local/curl >> /etc/apparmor.d/local/curl'

# Reload the curl profile
sudo apparmor_parser -r /etc/apparmor.d/curl
```

The snippet covers both user-mode and system-mode sockets:

```
# docker-helper user mode
owner /run/user/*/docker-helper/docker-helper.sock rw,

# docker-helper system mode
/run/docker-helper/docker-helper.sock rw,
```

Allowing socket access does not bypass docker-helper authorization.
API requests still require a valid session token or admin token.

## Workspace root policy

A new workspace root must:

- be a non-empty absolute path;
- exist and be a directory;
- not be `/`;
- not be or descend into a system namespace.

Forbidden namespaces (the root itself and all descendants):

    /bin  /boot  /dev  /etc  /lib  /lib32  /lib64  /libx32
    /proc /root  /run  /sbin /sys  /usr    /var    /tmp

The following namespaces are forbidden at the root but permit descendants:

    /home/alice/work  (allowed)
    /srv/workspaces   (allowed)
    /opt/projects     (allowed)
    /mnt/data         (allowed)
    /media/backup     (allowed)

When running as root (uid 0), `/home` and `/opt` are permitted as workspace
roots. Non-root users cannot use these namespaces directly.

Other non-system absolute paths such as `/data/workspaces` or `/workspace`
are allowed if otherwise valid.

A symlink whose canonical target enters a forbidden namespace is rejected.

New workspace roots are resolved to their canonical path through symlink
resolution before policy evaluation; the canonical path is the effective
and stored root.

## System mode: provisioning a principal

System mode requires the operator to configure both docker-helper policy
and MAC confinement. The common workflow handles both:

```bash
# 1. Create the principal.
#    principal create resolves the OS user; the canonical home directory
#    becomes the initial allowed root.
sudo docker-helper principal create --system alice

# 2. Review the principal's allowed roots.
sudo docker-helper principal show --system alice

# 3. Add a global allowed root.
#    config allowed-root add updates the authorization ceiling only;
#    it does NOT prepare MAC state.
sudo mkdir -p /srv/workspaces
sudo docker-helper config allowed-root add /srv/workspaces

# 4. Narrow the principal's authorization to a subdirectory.
#    principal allowed-root add does NOT prepare MAC; it only defines
#    which paths this principal may select at session creation time.
sudo mkdir -p /srv/workspaces/alice
sudo docker-helper principal allowed-root add \
    --system alice /srv/workspaces/alice

# 5. Create a Principal credential for the principal.
sudo docker-helper credential create \
    --system --name laptop alice
```

The three-level authorization model:

- **Global allowed root** — system-wide ceiling managed by
  `config allowed-root add`; authorization-only, does NOT prepare MAC.
- **Principal allowed root** — per-principal narrowing managed by
  `principal allowed-root add`; does not prepare MAC.
- **Project workspace** — selected only at session creation time via
  `session create --workspace PATH`; must be under both a global and
  a principal allowed root.

Individual projects are not registered persistently. The operator adds
global roots and principal roots, then creates sessions for specific
workspaces under those roots.

Advanced backend-specific management remains available:

```bash
docker-helper apparmor root list
docker-helper apparmor root add /path/to/workspace
docker-helper apparmor root remove /path/to/workspace
```

The separation is intentional:

- `principal create` and `principal allowed-root add` define per-principal
  workspace policy;
- `config allowed-root add` updates the system-wide authorization ceiling only;
- `apparmor root add` is an advanced backend-specific operation;
- `credential create` produces a Principal credential token for session creation.

If the operator does not want the default home root to remain usable,
they may remove it:

```bash
sudo docker-helper principal allowed-root remove \
    --system alice /home/alice
```

To remove a principal and all associated sessions, credentials, and allowed
roots:

```bash
sudo docker-helper principal delete --system alice
```

The delete operation is transactional: sessions are deleted first (not relying
on FK cascade), then the principal record is removed (credentials and allowed
roots are cleaned up via FK cascade). Session runtime directories are cleaned
up best-effort after the transaction commits.

Disabling a principal (`principal set alice enabled false`) has a narrower
effect: it deletes all active sessions and rejects future authentication for
any session token belonging to that principal. The principal record,
credentials, and allowed roots are preserved and can be restored by re-enabling
the principal.

### Principal: install the credential

The principal installs the token on their machine (not as root):

```bash
# Interactive input (token is hidden on terminal):
docker-helper credential install

# Replace an existing credential:
docker-helper credential install --force
```

The token is stored at `${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper/credential.token`
with mode `0600`. The directory is created with mode `0700` if it does not exist.
The write is atomic: a failure will not corrupt an existing credential.

Once installed, operator commands automatically select the system socket and
credential when no user socket exists. `--system`, `--endpoint`, and
`--token-file` remain available for an explicit selection.

## Documentation

Man pages are installed with native packages:

```bash
man docker-helper
man docker-helper-config
```

The release tarball includes compressed man pages in the `man/` directory.

## Release artifacts

Each release publishes:

- `docker-helper-<version>-linux-amd64.tar.gz` — static binary + install scripts
- one `.deb` — native DEB package
- one `.rpm` — native RPM package
- `SHA256SUMS` — SHA-256 checksums for the three artifacts above

Verify downloaded artifacts:

```bash
sha256sum --check SHA256SUMS
```

## License

docker-helper is licensed under GPL-3.0-only. See LICENSE.

## More information

- [docs/architecture.md](docs/architecture.md) — full architecture, HTTP API reference,
  audit logging, filesystem and environment policy, error codes,
  security considerations, and future work.
