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
- Go 1.23 with CGO enabled and a C compiler
- Docker CLI and access to a running Docker daemon

## Docker access

The user running docker-helper must be able to access the Docker daemon.
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

## Getting started

### 1. Build and install

```bash
go build -o docker-helper .
sudo install -Dm755 docker-helper /usr/bin/docker-helper
```

### 2. Initialize

```bash
docker-helper init
```

Creates configuration and state directories, writes `config.json` with
`allowed_root` and `session_ttl`, and generates an admin token. The
token is printed once and stored beside the config file.

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

### 3. Review and modify configuration

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
```

Each prints `unset` when the member was removed, or `unchanged ... is already unset`
when it was already absent.

Configuration fields:

**Configurable members** accepted in config.json:

| Field | Type | Description |
|-------|------|-------------|
| `allowed_root` | string | Root directory for agent workspaces (required) |
| `session_ttl` | duration | Session lifetime, e.g. `12h` (required) |
| `log_level` | string | `debug`, `info`, `warn`, `error` (default: `info`) |
| `audit_enabled` | boolean | Override audit behavior (default: derived from `log_level`) |

Only `log_level` and `audit_enabled` may be unset to restore defaults.

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

Changes take effect after restarting the daemon.

### 4. Start the daemon

Choose one of the startup modes below. The daemon listens on the Unix
socket at `$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock`
(permissions 0600). On SIGINT or SIGTERM, docker-helper stops accepting
new connections and waits up to 30 seconds for in-flight HTTP requests
to complete.

#### Manual foreground run

```bash
docker-helper serve
```

Use this mode for testing and troubleshooting. Audit records are written
to stdout, operational logs to stderr. Stop the daemon with Ctrl+C.

#### systemd user service

The systemd user service runs as the current user. That user must have
Docker access before the service is started.

Install the unit and start the service:

```bash
sudo install -Dm644 packaging/systemd/user/docker-helper.service \
  /usr/lib/systemd/user/docker-helper.service
systemctl --user daemon-reload
systemctl --user enable --now docker-helper
```

Check status and logs:

```bash
systemctl --user status docker-helper
journalctl --user -u docker-helper
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

## Using the HTTP API

The `curl` examples below are host-side smoke tests. A containerized
coding tool normally accesses the mounted socket at:

```
/run/docker-helper/docker-helper.sock
```

### Pull

```bash
curl --unix-socket "$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d '{"image":"alpine:3.24"}' \
  http://localhost/pull
```

### Build

```bash
curl --unix-socket "$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d '{"context":".","dockerfile":"Dockerfile","image":"myapp:v1"}' \
  http://localhost/build
```

### Run

```bash
curl --unix-socket "$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d '{"image":"alpine:3.24","command":["echo","hello"]}' \
  http://localhost/run
```

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

**Known limitations:**

- docker-helper does not sandbox a coding tool that already has direct
  access to the host filesystem.
- Builds and containers use Docker's default networking; docker-helper
  does not provide network isolation.
- docker-helper is a highly trusted component because it has access to
  the Docker daemon, so a validation or command-construction bug may
  compromise the host.
- Operations currently have no execution timeout, output-size limit, or
  concurrency limit.
- Detached containers, custom networks, named volumes, and resource
  controls are not supported.

## Logging

docker-helper writes two separate JSON Lines streams:

- **stdout** — audit records (one JSON object per line). Every record
  contains `"stream": "audit"`.
- **stderr** — operational records (structured slog JSON). Level-filtered
  by `log_level` in config.json. Every record contains `"stream": "operational"`.

All timestamps use UTC in RFC 3339 nanosecond format (`time.RFC3339Nano`).

### Log levels

The `log_level` field in `config.json` controls operational log verbosity:

| Value | Operational records emitted |
|-------|----------------------------|
| `debug` | debug, info, warn, error |
| `info` | info, warn, error (default) |
| `warn` | warn, error |
| `error` | error only |

### Audit enablement

Audit output is controlled by the optional `audit_enabled` field in
`config.json`. The effective value is resolved as follows:

1. Explicit `audit_enabled: true` enables audit.
2. Explicit `audit_enabled: false` disables audit, even when `log_level`
   is `debug`.
3. When `audit_enabled` is absent:
   - `log_level=debug` enables audit;
   - every other `log_level` disables audit.

`docker-helper init` omits `audit_enabled` from the generated config.
Since the default `log_level` is `info`, audit is disabled by default.
If the user later changes `log_level` to `debug`, audit becomes enabled
unless explicitly overridden with `audit_enabled: false`.

When audit is disabled, no audit records are written to stdout and no
audit encoding or writer errors are emitted. Operational logging and
request handling are unaffected.

### Debug request logging

When `log_level` is `debug`, an additional operational record is emitted
after every HTTP request:

```json
{"time":"...","level":"DEBUG","msg":"request completed","request_id":"req_...","method":"POST","route":"/run","status":200,"duration_ms":401,"stream":"operational"}
```

This record is suppressed at `info`, `warn`, and `error` levels. The
`route` field uses the registered route pattern (e.g.
`DELETE /sessions/{id}`), never the actual request URI or session ID.
Query parameters, request bodies, headers, and Docker output are never
included.

### Request correlation

Every HTTP request receives a server-generated `X-Request-ID` response
header. The same ID appears in all audit and operational records for
that request, enabling end-to-end tracing.

### Sensitive data

Command arguments, environment values, Docker output, and Authorization
headers are **never** logged. The audit record for `POST /run` includes
`command_arg_count` (number of arguments) but never the arguments
themselves.

### Log collection

Log collection, retention, and rotation are delegated to the process
supervisor (systemd/journald, Docker, or a log shipper). docker-helper
does not write log files or implement internal rotation.

## More information

- [docs/architecture.md](docs/architecture.md) — full architecture, HTTP API reference,
  audit logging, filesystem and environment policy, error codes,
  security considerations, and future work.
