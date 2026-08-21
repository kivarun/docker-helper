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
  requires an admin or launcher credential;
- all supported Docker operations are mediated by the daemon;
- the developer controls which workspace each session can access.

docker-helper assumes the agent cannot directly read `admin.token` or
access `docker.sock`. It does not sandbox an otherwise unrestricted agent
process running as the same host user.

Full architecture and detailed API documentation: [docs/architecture.md](docs/architecture.md)

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
DEB/RPM packages, systemd system service, and mandatory AppArmor confinement.

## Authentication model

Three credential classes provide different levels of access:

1. **Admin token** — full administrative access: manage principals,
   credentials, and all sessions.
2. **Launcher credential** — bound to a principal: create sessions for
   that principal, list and delete only that principal's sessions.
   Cannot manage principals or credentials.
3. **Session token** — narrow workspace capability for Docker operations
   (pull, build, run, registry login).

After a session token is issued:
- revoking the launcher credential does not invalidate the session;
- disabling the principal does not invalidate the session;
- removing an allowed root does not invalidate the session;
- session expiry or deletion blocks future requests;
- an already-started Docker operation continues its lifecycle.

## Prerequisites

- Linux
- Docker CLI and access to a running Docker daemon

To build from source, you additionally need:
- Go 1.23 with CGO enabled and a C compiler

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

The `credential create` command prints a token. On alice's machine (not
as root):

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

For more on principals, allowed roots, and AppArmor confinement, see
below.

### Package installation

Install the package for your distribution:

**Ubuntu / DEB:**

```bash
sudo apt install ./docker-helper_*.deb
```

**openSUSE / RPM:**

```bash
sudo zypper install ./docker-helper-*.rpm
```

The package installs the binary, systemd units (system and user), the
AppArmor system profile, and man pages. It does NOT run `init`,
generate configuration, or start the service.

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
| `audit_enabled` | boolean | Override audit behavior (default: `true` in system mode; in user mode, `true` only when `log_level` is `debug`) |
| `shutdown_timeout` | duration | Graceful shutdown budget for HTTP drain + operation termination (default: `30s`) |
| `operation_retention_ttl` | duration | How long completed operations are kept (default: `10m`) |
| `operation_max_completed` | int | Max completed operations retained in memory (default: `200`) |
| `operation_log_max_bytes` | int | Max bytes retained per operation log (bounded buffer, default: `4194304` = 4 MiB) |
| `trusted_ca_path` | string | Absolute path to a single PEM X.509 CA certificate file (optional, required when `trusted_ca_injection` is `auto`) |
| `trusted_ca_injection` | string | `"disabled"` or `"auto"` (default: `"disabled"`). When `auto`, injects CA into containers via `POST /run`. |
| `http_address` | string | Loopback TCP listen address `127.0.0.1:PORT`, system mode only, restart required (default: `127.0.0.1:52375`) |

`allowed_root` and `session_ttl` are required and cannot be unset.
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
rollback and re-reload succeed, config.json and the daemon are synchronized.
If re-reload fails, they may diverge until the next manual reload or restart.

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

Startup-only fields (require daemon restart):
- `http_address`

Runtime paths (socket, database, state) are not changed by reload.

### Trusted CA injection

Inject a company or internal CA certificate into agent containers so they
trust your internal services. The CA file must be a single PEM-encoded
X.509 CA certificate. Injection only affects containers started via
`POST /run`.

Enable:

```bash
docker-helper config set trusted_ca_path /absolute/path/to/company-root-ca.pem
docker-helper config set trusted_ca_injection auto
```

Disable:

```bash
docker-helper config set trusted_ca_injection disabled
docker-helper config unset trusted_ca_path
```

Each command triggers a daemon reload automatically when the daemon is
running.

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
`shutdown_timeout` (default 30 seconds).

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

Removes expired session rows from the local state database. Active
sessions are untouched. Expired sessions are already rejected for
authentication and excluded from session lists by their `expires_at`
value; this command is useful for explicitly reclaiming storage during
long daemon uptimes. The daemon also removes expired sessions
automatically at startup. No running daemon or admin token is required.

## Operator CLI

API-backed operator commands (principal, credential, session, reload)
support explicit endpoint selection:

```
--system              connect to system daemon (Unix socket)
--endpoint ENDPOINT   explicit endpoint (unix:///path or http://127.0.0.1:port)
--token-file PATH     token file path
```

Default behavior: check user socket existence, fall back to system
socket.

`--endpoint` requires `--token-file`. `--system` and `--endpoint` are
mutually exclusive. There is no fallback: if the chosen endpoint is
unavailable, the command fails.

For the full command syntax, use `docker-helper help <command>`.

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
  sources are validated against the session workspace. Builds use an
  isolated staging copy with FD-relative traversal; system-mode run
  mounts use inode-pinned helper-owned mounts.
- **Bearer authentication** — admin token uses SHA-256 hashing with
  constant-time comparison in memory; launcher credentials and session
  tokens use SHA-256 hashes stored in SQLite and resolved through
  database lookup.
- **Socket permissions** — user mode Unix socket has 0600 permissions;
  system mode Unix socket has 0666 permissions. In system mode, the
  socket is accessible to any local user, but security is enforced
  through bearer authentication and authorization, not socket
  permissions alone.
- **Container policy** — containers run with `--rm`, `--security-opt label=disable`,
  and `--user <uid>:<gid>` (principal UID:GID for principal-owned sessions,
  daemon UID:GID for legacy/admin sessions).
- **AppArmor** — system mode uses mandatory AppArmor confinement with the
  `docker-helper-system` profile. The release tarball also includes an optional
  user-mode AppArmor profile template.

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

## AppArmor (system mode)

System mode uses mandatory AppArmor confinement with the
`docker-helper-system` profile. Managed workspace roots are stored in
`/etc/apparmor.d/docker-helper.d/managed-roots`.

During system-mode `docker-helper init`, the initial `allowed_root` is
automatically added to managed AppArmor roots. Subsequent changes to
configuration or principal allowed roots do NOT automatically update
AppArmor. Manage them explicitly:

```bash
docker-helper apparmor root list
docker-helper apparmor root add /path/to/workspace
docker-helper apparmor root remove /path/to/workspace
docker-helper apparmor check
```

User mode does not use AppArmor confinement by default. The release tarball
includes an optional user-mode AppArmor profile template that can be
installed manually.

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
API requests still require a valid session token or admin credential.

## Workspace root policy

A new workspace root (config `allowed_root`, principal allowed roots, or
AppArmor managed roots) must:

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

Existing stale AppArmor roots remain removable even if they no longer
satisfy the current policy.

## System mode: provisioning a principal

System mode requires the operator to configure both docker-helper policy
and AppArmor confinement separately. Changing principal or config allowed
roots does NOT automatically update AppArmor.

```bash
# 1. Create the principal.
#    principal create resolves the OS user; the canonical home directory
#    becomes the initial allowed root.
sudo docker-helper principal create --system alice

# 2. Review the principal's allowed roots.
#    The default home root is shown; this is what AppArmor must cover
#    if the operator wants it to remain usable.
sudo docker-helper principal show --system alice

# 3. Add additional allowed roots as needed.
sudo docker-helper principal allowed-root add \
    --system alice /srv/workspaces/alice

# 4. Add matching AppArmor roots for every allowed root.
#    The show command above reveals the actual home/default root.
sudo docker-helper apparmor root add /home/alice
sudo docker-helper apparmor root add /srv/workspaces/alice

# 5. Create a launcher credential for the principal.
sudo docker-helper credential create \
    --system --name laptop alice
```

The separation is intentional:

- `principal create` and `principal allowed-root add` define docker-helper
  workspace policy;
- `apparmor root add` defines daemon filesystem confinement;
- `credential create` produces a launcher token for session creation.

These layers are not synchronized automatically. The operator must add
matching AppArmor roots for every workspace that a principal needs.

If the operator does not want the default home root to remain usable,
they may remove it before provisioning AppArmor:

```bash
sudo docker-helper principal allowed-root remove \
    --system alice /home/alice

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

Once installed, `docker-helper --system` uses the credential automatically.

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
