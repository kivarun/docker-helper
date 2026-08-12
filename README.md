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
  requires an admin token;
- all supported Docker operations are mediated by the daemon;
- the developer controls which workspace each session can access.

docker-helper assumes the agent cannot directly read `admin.token` or
access `docker.sock`. It does not sandbox an otherwise unrestricted agent
process running as the same host user.

Full architecture and detailed API documentation: [docs/architecture.md](docs/architecture.md)

## Prerequisites

- Linux
- Docker CLI and access to a running Docker daemon

To build from source, you additionally need:
- Go 1.23 with CGO enabled and a C compiler

## Docker access

The user running docker-helper must be able to access the Docker daemon.
docker-helper runs as a **user service** and does not use sudo (except
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

## Installation

### Quick start (release tarball)

Download the release tarball for your platform, extract it, and run the
installer:

```bash
tar xzf docker-helper-*.tar.gz
cd docker-helper-*
./install.sh
```

The installer:

- copies the binary to `~/.local/bin/docker-helper`;
- installs the systemd user unit to `~/.config/systemd/user/`;
- optionally installs an AppArmor profile (requires sudo for this step only);
- prompts to run `docker-helper init` and enable+start the user service.

For a fully non-interactive installation:

```bash
./install.sh --yes
```

### Manual installation

Build from source and place the binary in `~/.local/bin`:

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
`allowed_root`, `session_ttl`, `log_level` (default `info`), `shutdown_timeout`
(default `30s`), `operation_retention_ttl` (default `10m`),
`operation_max_completed` (default `200`), and `operation_log_max_bytes`
(default `4194304` = 4 MiB), and generates an admin token. The
token is printed once and stored beside the config file.

If running interactively and `--allowed-root` is not provided, you will
be prompted for the allowed root directory. The current working directory
is used as the default.

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
docker-helper config set allowed_root /path/to/workspaces
docker-helper config set log_level debug
docker-helper config set audit_enabled true
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
when it was already absent. `allowed_root` and `session_ttl` are required and
cannot be unset.

Configuration fields:

**Configurable members** accepted in config.json:

| Field | Type | Description |
|-------|------|-------------|
| `allowed_root` | string | Root directory for agent workspaces (required) |
| `session_ttl` | duration | Session lifetime, e.g. `12h` (required) |
| `log_level` | string | `debug`, `info`, `warn`, `error` (default: `info`) |
| `audit_enabled` | boolean | Override audit behavior (default: derived from `log_level`) |
| `shutdown_timeout` | duration | Graceful shutdown budget for HTTP drain + operation termination (default: `30s`) |
| `operation_retention_ttl` | duration | How long completed operations are kept (default: `10m`) |
| `operation_max_completed` | int | Max completed operations retained in memory (default: `200`) |
| `operation_log_max_bytes` | int | Max bytes retained per operation log (bounded buffer, default: `4194304` = 4 MiB) |
| `trusted_ca_path` | string | Absolute path to a single PEM X.509 CA certificate file (optional, required when `trusted_ca_injection` is `auto`) |
| `trusted_ca_injection` | string | `"disabled"` or `"auto"` (default: `"disabled"`). When `auto`, injects CA into containers via `POST /run`. Requires host `openssl` binary for hash computation. |

`allowed_root` and `session_ttl` are required and cannot be unset. All other
fields may be unset to restore their defaults.

Runtime reload: after `config set` or `config unset`, the change is written
to disk immediately. If the daemon is running, the new configuration is
applied automatically. If the daemon is not running, the change will apply
on the next start.

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
- `allowed_root`
- `session_ttl`
- `log_level`
- `audit_enabled`
- `shutdown_timeout`
- `operation_retention_ttl`
- `operation_max_completed`
- `operation_log_max_bytes`
- `trusted_ca_path`
- `trusted_ca_injection`

Runtime paths (socket, database, state) are not changed by reload.

**Computed/output-only fields** are read-only and must not be added to
config.json. If present, configuration validation and daemon startup fail:

| Field | Description |
|-------|-------------|
| `audit_enabled_source` | `"explicit"` or `"log_level"` |
| `config_path` | Path to `config.json` |
| `config_dir` | Configuration directory |
| `runtime_dir` | Runtime directory under `XDG_RUNTIME_DIR` |
| `socket_path` | Unix socket path |
| `lock_path` | Lock file path |
| `state_dir` | State directory |
| `database_path` | SQLite database path |
| `admin_token_path` | Path to `admin.token` |
| `admin_token` | Admin token (redacted in general show) |

### 3. Start the daemon

Choose one of the startup modes below. The daemon listens on the Unix
socket at `$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock`
(permissions 0600). On SIGINT or SIGTERM, docker-helper stops accepting
new connections and waits for in-flight HTTP requests to complete, up to
the configured `shutdown_timeout` (default 30 seconds).

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
and expiration time. The workspace must be inside `allowed_root`.

Assign the printed token to an environment variable for use in later
examples:

```bash
export SESSION_TOKEN='dht_...'
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

Removes expired session rows from the local state database. Active
sessions are untouched. Expired sessions are already rejected for
authentication and excluded from session lists by their `expires_at`
value; this command is useful for explicitly reclaiming storage during
long daemon uptimes. The daemon also removes expired sessions
automatically at startup. No running daemon or admin token is required.

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
  sources are validated against the session workspace.
- **Two-token model** — admin token manages sessions; session token
  performs operations within a workspace. SHA-256 hashes,
  constant-time comparison.
- **Socket** — the daemon exposes a separate Unix socket with 0600
  permissions. The coding tool must not be given access to docker.sock.
- **Container policy** — containers run with `--rm`, host UID/GID,
  and `--security-opt label=disable`.
- **AppArmor** — an optional AppArmor profile is included in the release
  tarball and can be installed during `./install.sh` to further restrict
  daemon access.

**Known limitations:**

- docker-helper does not sandbox a coding tool that already has direct
  access to the host filesystem.
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

## More information

- [docs/architecture.md](docs/architecture.md) — full architecture, HTTP API reference,
  audit logging, filesystem and environment policy, error codes,
  security considerations, and future work.
