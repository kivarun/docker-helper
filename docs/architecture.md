# Architecture

## Goal

docker-helper is a small policy-enforcing daemon that provides a restricted
interface to Docker.

A coding agent runs on the same machine as the developer and needs to build
images and run containers. Giving the agent direct access to `docker.sock`
means it can read any file on the host, access any network, and run arbitrary
processes. docker-helper sits between the agent and Docker and enforces
policy:

- filesystem access is restricted to an explicit workspace per session;
- every operation requires a session token;
- all Docker commands go through a single process;
- the developer controls which workspace each session can access.

The agent cannot escalate beyond the workspace boundary.

## High-level architecture

```
Developer
    │
Launcher  [planned]
    │
OpenCode
    │
Custom Tool  [planned]
    │
docker-helper (Unix socket)
    │
Docker CLI
    │
Docker Engine
```

Launcher and Custom Tool are planned components. The launcher starts
docker-helper and holds the administrative token. The custom tool is the
OpenCode-side client that communicates with docker-helper.

docker-helper listens on a Unix socket at
`$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock` with `0600` permissions.

## Trust model

### Trusted

- the developer who runs `docker-helper init` and `docker-helper serve`;
- the host filesystem outside `AllowedRoot`;
- the Docker Engine and its configuration;
- the `docker-helper` process itself.

### Partially trusted

- the `AllowedRoot` directory and its contents;
- the workspace selected at session creation time.

### Untrusted

- the coding agent;
- any input from the agent (JSON payloads, paths, image names);
- Dockerfiles inside the workspace;
- container processes.

The agent is untrusted because it may execute arbitrary code, generate
malicious Dockerfiles, or attempt path traversal. docker-helper validates
every agent input before passing it to Docker.

## Session lifecycle

```
docker-helper init
    │
    ├── creates config directory (0700)
    ├── creates state directory (0700)
    ├── writes config.json
    └── generates admin token (dht_<64 hex chars>)
    │
docker-helper serve
    │
    ├── loads config.json
    ├── reads admin token, computes SHA-256 hash
    ├── opens SQLite database
    ├── deletes expired session rows (expires_at <= now)
    └── starts HTTP server on Unix socket
    │
POST /sessions  (admin token)
    │
    ├── validates workspace inside AllowedRoot
    ├── generates session ID (dhs_<32 hex chars>)
    ├── generates session token (dht_<64 hex chars>)
    ├── stores SHA-256 hash of token in database
    ├── stores full token in response (one-time)
    └── returns session + token
    │
POST /build or POST /run  (session token)
    │
    ├── computes SHA-256 of provided token
    ├── looks up session by token hash
    ├── checks not expired, not revoked
    ├── validates request against session workspace
    └── executes docker command
    │
DELETE /sessions/{id}  (admin token)
    │
    └── physically deletes session row
    │
subsequent requests with deleted session token
    │
    └── 401 Unauthorized
```

The administrative token stays with the launcher and the developer. The
coding agent never receives it. The agent only gets a session token, which
grants access to a single workspace and expires after the configured TTL.
This separation ensures the agent cannot create sessions for other
workspaces or manage sessions it does not own.

Expired sessions are rejected immediately by the `expires_at` check in
`findSessionByToken`. Their database rows are physically removed the next
time `docker-helper serve` starts.

## Session CLI

docker-helper provides a CLI for session management.

### docker-helper session create

Create a new session. Requires the admin token.

```
docker-helper session create --workspace PATH [--json]
```

Flags:

| Flag | Description |
|------|-------------|
| `--workspace PATH` | Workspace directory (required) |
| `--json` | Output in JSON format |

Returns the session ID, token, workspace, creation time, and expiration
time. The token is shown only once and cannot be retrieved later.

### docker-helper session list

List active sessions. Requires the admin token.

```
docker-helper session list [--json]
```

Flags:

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format |

Returns a table of active sessions with ID, workspace, creation time,
and expiration time.

### docker-helper session delete

Delete a session. Requires the admin token.

```
docker-helper session delete --id SESSION_ID [--json]
```

Flags:

| Flag | Description |
|------|-------------|
| `--id SESSION_ID` | Session ID to delete (required) |
| `--json` | Output in JSON format |

Permanently removes the session. Subsequent requests with the session's
token will receive 401 Unauthorized.

## CLI reference

### `docker-helper <command>`

Root command. Without arguments, prints help and exits 0.

```
docker-helper <command>
```

Available commands: `serve`, `init`, `config`, `reload`, `session`,
`version`, `help`.

### `docker-helper help`

Prints root help (identical to running without arguments).

### `docker-helper serve`

Starts the HTTP server on the Unix socket.

### `docker-helper init`

Initializes configuration and admin token.

### `docker-helper version`

Prints the current version.

### `docker-helper config <subcommand>`

Inspect and modify configuration. Requires a subcommand.

Subcommands: `show`, `set`, `unset`.

`docker-helper config show [FIELD]` — without FIELD, prints the complete
effective configuration as JSON (admin_token redacted). With FIELD, prints
only that field's scalar value.

`docker-helper config set FIELD VALUE` — sets a writable field
(`allowed_root`, `session_ttl`, `log_level`, `audit_enabled`). Reports
`updated` or `unchanged`. If the daemon is running, the change is applied
immediately.

`docker-helper config unset FIELD` — removes an optional field
(`log_level`, `audit_enabled`) to restore its default. Reports `unset` or
`unchanged`. If the daemon is running, the change is applied immediately.

### `docker-helper reload`

Ask the running daemon to re-read `config.json` and apply changes without
restarting. Only configurable fields are applied at runtime
(`allowed_root`, `session_ttl`, `log_level`, `audit_enabled`). Computed
paths (socket, database, state) are not changed. If the daemon is not
running, the command fails with a non-zero exit code. If the new
configuration is invalid, the daemon keeps its current configuration and
the command returns an error.

### `docker-helper session <subcommand>`

Manages sessions. Requires a subcommand.

Subcommands: `create`, `list`, `delete` (see Session CLI section above).

### Help flag

The `-h` / `--help` flag is available on every command and session
subcommand. It prints usage information and exits 0 without executing
the command action.

### Exit codes

| Code | Meaning | Examples |
|------|---------|----------|
| 0 | Success or help displayed | `docker-helper version`, `docker-helper serve --help` |
| 1 | Runtime error (config load, API call, server failure) | `docker-helper init` with an unwritable configuration directory, `docker-helper session create` with unreachable server |
| 2 | CLI syntax or argument validation error | unknown command, missing/unknown subcommand, missing required flag, unexpected positional argument, unknown flag |

## systemd user service

docker-helper can run as a systemd user service. The unit file is
installed at `/usr/lib/systemd/user/docker-helper.service`.

### Installation

```
docker-helper init
systemctl --user daemon-reload
systemctl --user enable --now docker-helper
```

Configuration and state directories are created by `docker-helper init`
using standard XDG paths. Non-standard `XDG_CONFIG_HOME` and
`XDG_STATE_HOME` are supported when they are present in the systemd user
manager environment.

### Stop and restart

docker-helper installs a signal handler for SIGINT and SIGTERM and calls
`http.Server.Shutdown` with a 30-second timeout. On stop:

- the server stops accepting new connections;
- in-flight HTTP requests are drained until the timeout expires;
- the lock is held during the entire drain so a second instance cannot
  start until the first fully stops;
- if the timeout is exceeded, `server.Close()` is called and the process
  terminates;
- child `docker` CLI processes are not explicitly waited on — they may
  continue running after the helper exits.

After `TimeoutStopSec=30s`, systemd sends SIGKILL if any processes
remain.

### Logout

- **without linger** (`loginctl enable-linger` not set): the user manager
  and all services normally stop after the last user session ends;
- **with linger**: the user manager continues running and the service
  stays active after logout.

### StartLimit

The unit limits restarts to 3 attempts within 60 seconds. If this limit
is reached (e.g. when `docker-helper init` has not been run):

```
systemctl --user reset-failed docker-helper
systemctl --user start docker-helper
```

### Hardening

The unit applies process-level hardening (`NoNewPrivileges`,
`RestrictSUIDSGID`, `RestrictNamespaces`, `RestrictRealtime`).
Filesystem namespace directives (`ProtectSystem`, `ProtectHome`, etc.)
are not used in the initial unit: their compatibility with docker-helper
depends on the runtime environment and requires per-distribution testing.

The unit does not restrict direct access to the host filesystem. The
process-level directives only forbid specific operations. Access to the
Docker socket means the unit does not create a full security boundary.

## Authentication

Two token types exist.

### Administrative token

- generated once by `docker-helper init`;
- stored at `$XDG_CONFIG_HOME/docker-helper/admin.token`;
- SHA-256 hash loaded into memory at server start;
- required for `POST /sessions`, `GET /sessions`, `DELETE /sessions/{id}`;
- sent as `Authorization: Bearer <admin-token>`;
- compared via `crypto/subtle.ConstantTimeCompare`.

### Session token

- generated per session by `POST /sessions`;
- returned once in the creation response;
- SHA-256 hash stored in SQLite;
- required for `POST /build`, `POST /run`, `POST /pull`;
- sent as `Authorization: Bearer <session-token>`;
- looked up by hash, checked for expiration and revocation.

The two tokens serve different purposes. The admin token manages sessions.
The session token performs operations within a session's workspace boundary.
An admin token cannot be used for build or run. A session token cannot
create or delete sessions.

## Workspace isolation

Each session is bound to a single workspace directory.

### Canonical paths

All paths are resolved through `filepath.EvalSymlinks` before comparison.
This prevents symlink-based escape attacks.

### isInside()

The function `isInside(parent, child)` checks whether `child` is inside
`parent` by computing `filepath.Rel(parent, child)` and verifying the
result does not start with `..`.

### Symlink escape prevention

When a session is created, the workspace path is resolved through
`EvalSymlinks`. The canonical workspace is stored in the database.

When a build or run request specifies a path relative to the workspace,
the resolved path is compared against the canonical workspace. If the
resolved path escapes the workspace, the request is rejected.

### Per-session workspace

Each session has its own workspace. An agent with a session for
`/home/user/project-a` cannot access `/home/user/project-b`, even if both
are inside `AllowedRoot`.

## Build pipeline

```
Authentication
    │
Request validation
    │
Canonical path resolution
    │
Boundary validation
    │
Docker invocation
```

Authentication validates the session token and returns the session.
Request validation checks required fields, image name format, and
dockerfile relativity. Canonical path resolution resolves the workspace
and context through `EvalSymlinks`. Boundary validation ensures the
context and dockerfile are inside the workspace and context respectively.
Docker invocation runs `docker build` with fixed flags.

Validation details:

- context may be relative (joined with workspace) or absolute (must be
  inside workspace);
- dockerfile must be relative to context;
- image name must match `^[a-zA-Z0-9._/-]+:[a-zA-Z0-9._-]+$`;
- all paths are resolved through `EvalSymlinks` before `isInside` checks.

## Run pipeline

```
Authentication
    │
Request validation
    │
Workdir validation
    │
Environment validation
    │
Mount resolution
    │
Docker invocation
```

Authentication validates the session token. Request validation checks
the image name. Workdir validation ensures the value is an absolute path
if provided. Environment validation ensures variable names match
`^[A-Za-z_][A-Za-z0-9_]*$`. Mount resolution resolves each source path
against the workspace and checks for duplicate targets. Docker invocation
runs `docker run` with fixed security policy.

Validation details:

- workdir must be an absolute path if provided;
- mount source must be relative to workspace;
- mount target must be absolute;
- source is resolved through `EvalSymlinks` and checked via `isInside`;
- environment values are never logged (only names in `env_keys`);
- environment names are sorted for deterministic output;
- container runs with fixed security policy (details in implementation).

## Pull pipeline

```
Authentication
    │
Request validation
    │
Docker invocation
```

Authentication validates the session token. Request validation checks
that the image name is present and matches
`^[a-zA-Z0-9._/-]+:[a-zA-Z0-9._-]+$`. Docker invocation runs
`docker pull` with the image name.

## Health endpoint

`GET /health` returns a 200 OK response with a JSON body indicating the
server is running. No authentication is required. This endpoint is
intended for liveness probes and does not perform any audit logging.

## Filesystem policy

### Bind mounts

Each mount in a `POST /run` request specifies a `source` (relative to the
session workspace) and a `target` (absolute path inside the container).

Allowed:

- `source` is a relative path inside the session workspace;
- `source` resolves to an existing directory or regular file;
- `source` is `.` (the entire workspace);
- `target` is any absolute path;
- `read_only` is true or false;
- the same `source` can be mounted to multiple `target` paths.

Forbidden:

- `source` is an absolute path;
- `source` is empty;
- `source` resolves outside the session workspace (including via symlinks);
- `source` does not exist;
- `source` is not a directory or regular file;
- `target` is empty;
- `target` is not absolute;
- two mounts use the same `target`.

### Why source must be relative

Requiring a relative source ensures the mount is always scoped to the
session workspace. An absolute source could bypass workspace isolation.

## Environment policy

Environment variable names must match `^[A-Za-z_][A-Za-z0-9_]*$`.

Values can be any string, including empty.

Values are never logged. Only variable names appear in `env_keys`.

Environment variables are sorted by name before being passed to Docker.
This makes the command line deterministic and reproducible.

## Error handling

Current:

- the API returns JSON errors with a stable `code` field;
- clients can distinguish error types programmatically;
- Docker output is included in the response on both success and failure;
- the `duration` field reports wall-clock time.

Current error codes:

| Code | Endpoint | Condition |
|------|----------|-----------|
| `unauthorized` | all protected | missing/invalid token |
| `invalid_build_context` | `POST /build` | context validation failure |
| `invalid_image` | `POST /build`, `POST /run`, `POST /pull` | image name empty or invalid format |
| `invalid_mount` | `POST /run` | mount validation failure |
| `invalid_workdir` | `POST /run` | workdir is not an absolute path |
| `invalid_environment` | `POST /run` | environment variable name invalid |
| `invalid_workspace` | `POST /sessions` | workspace invalid or outside AllowedRoot |
| `invalid_session_id` | `DELETE /sessions/{id}` | session ID is empty |
| `docker_build_failed` | `POST /build` | docker build returned non-zero |
| `docker_pull_failed` | `POST /pull` | docker pull returned non-zero |
| `docker_run_failed` | `POST /run` | docker run failed (exit 125 or other error) |
| `container_exit_nonzero` | `POST /run` | container exited with non-zero status (not 125) |

Planned:

- audit coverage for rejected build/run/pull requests;
- audit events for GET /sessions and GET /health.

## Audit logging

docker-helper writes structured audit records to **stdout**. Operational
logs are written to **stderr**. Both streams use JSON Lines format.
Timestamps in both streams use UTC in RFC 3339 nanosecond format
(`time.RFC3339Nano`).

### Stream separation

| Stream | Destination | Content | Level-filtered |
|--------|-------------|---------|----------------|
| Audit | stdout | Audit records (JSONL) | No (controlled by `audit_enabled`) |
| Operational | stderr | Daemon events (JSONL) | Yes, by `log_level` |

No runtime `fmt.Printf`, `log.Printf`, or other free-form text output
is emitted. Human-oriented CLI output from `init`, `version`, `help`,
and `session` commands remains unchanged.

Every audit record contains `"stream": "audit"`.
Every operational record contains `"stream": "operational"`.

### Audit enablement

Audit output is controlled by the optional `audit_enabled` field in
`config.json`. The effective value is resolved using these rules:

1. Explicit `audit_enabled: true` enables audit.
2. Explicit `audit_enabled: false` disables audit, including when
   `log_level` is `debug`.
3. When `audit_enabled` is absent:
   - `log_level=debug` enables audit;
   - every other `log_level` disables audit.

`docker-helper init` omits `audit_enabled` from the generated config.
Since the default `log_level` is `info`, audit is disabled by default.
If the user later changes `log_level` to `debug`, audit becomes enabled
unless explicitly overridden with `audit_enabled: false`.

When audit is disabled:

- no audit records are written to stdout;
- no audit encoding or writer errors are emitted;
- operational logging and request handling are unaffected.

### Operational log levels

The `log_level` field in `config.json` controls operational log verbosity:

| Value | Records emitted |
|-------|-----------------|
| `debug` | debug, info, warn, error |
| `info` | info, warn, error (default) |
| `warn` | warn, error |
| `error` | error only |

### Debug request logging

When `log_level` is `debug`, an operational record is emitted after
every HTTP request:

```json
{"time":"...","level":"DEBUG","msg":"request completed","request_id":"req_...","method":"POST","route":"/run","status":200,"duration_ms":401,"stream":"operational"}
```

This record is suppressed at `info`, `warn`, and `error` levels. The
`route` field uses the registered route pattern (e.g.
`DELETE /sessions/{id}`), never the actual request URI or session ID.
Query parameters, request bodies, headers, command arguments, session
tokens, and Docker output are never included. `duration_ms` is a JSON
number.

### Request correlation

Every HTTP request receives a server-generated request ID. It is:

- returned in the `X-Request-ID` response header;
- added as `request_id` to every audit record for that request;
- added to every operational record for that request;
- `session_id` is added to operational records when authentication
  has established a session.

The server does not trust or reuse any client-supplied request ID.

### Sensitive data

The following are **never** logged:

- command arguments (only `command_arg_count` appears in audit);
- environment variable values (only names in `env_keys`);
- Docker build output or container stdout/stderr;
- `Authorization` header values;
- raw HTTP request bodies.

### Log collection

Log collection, retention, and rotation are delegated to the process
supervisor (systemd/journald or another log shipper). docker-helper
does not write log files or implement internal rotation.

### Format

JSON Lines: one JSON object per line, UTF-8 encoded. Each line is an
independent record.

Operational records use slog's structured `time`, `level`, and `msg`
fields.

### Common fields

| Field | Type | Description |
|-------|------|-------------|
| `time` | string | UTC timestamp, RFC 3339 with nanoseconds |
| `event` | string | event name |
| `result` | string | outcome code (omitted on `build.start`) |
| `session_id` | string | session identifier (omitted on `auth.failure`) |
| `duration` | string | wall-clock duration, e.g. `"1s"`, `"150ms"` |

Additional fields depend on the event. Fields with empty or zero values
are omitted from the JSON output.

### Events

#### build.start

Emitted before a Docker build begins.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `image` | string | target image name with tag |
| `context` | string | build context path from the request |
| `dockerfile` | string | Dockerfile path from the request |

No `result` or `duration` field.

#### build.finish

Emitted after a Docker build completes (success or failure).

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `image` | string | target image name with tag |
| `context` | string | build context path from the request |
| `dockerfile` | string | Dockerfile path from the request |
| `result` | string | `success` or `build_error` |
| `exit_code` | number | present when an exit code is available |
| `duration` | string | build wall-clock time |

#### session.create

Emitted for every `POST /sessions` request after authentication.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier (present on `success` only) |
| `workspace` | string | workspace path from the request |
| `result` | string | outcome code |
| `duration` | string | request wall-clock time |

Result codes:

| Code | Condition |
|------|-----------|
| `success` | session created |
| `invalid_json` | request body is not valid JSON |
| `invalid_workspace` | workspace is empty, does not exist, is not a directory, or is outside `AllowedRoot` |
| `database_error` | SQLite write failure |
| `system_error` | cannot resolve `AllowedRoot` path |
| `unknown_error` | unexpected error not classified above |

#### session.delete

Emitted for every `DELETE /sessions/{id}` request after authentication.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier from the URL |
| `workspace` | string | workspace of the session (present when the session was found) |
| `result` | string | outcome code |
| `duration` | string | request wall-clock time |

Result codes:

| Code | Condition |
|------|-----------|
| `success` | session deleted |
| `invalid_session_id` | session ID is empty in the URL |
| `not_found` | no session with the given ID |
| `database_error` | SQLite failure during delete |
| `unknown_error` | unexpected error not classified above |

#### run.start

Emitted before a container starts.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `request_id` | string | request correlation ID |
| `image` | string | container image name with tag |
| `command_arg_count` | number | number of command arguments (present when command is set) |
| `mounts` | object[] | bind mounts (present when set) |
| `env_keys` | string[] | environment variable names, sorted (present when set; values are never logged) |

No `result` or `duration` field.

Each entry in `mounts` has:

| Field | Type | Description |
|-------|------|-------------|
| `source` | string | source path relative to the workspace |
| `target` | string | absolute target path inside the container |
| `read_only` | boolean | whether the mount is read-only |

#### run.finish

Emitted after a container run attempt completes.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `request_id` | string | request correlation ID |
| `image` | string | container image name with tag |
| `command_arg_count` | number | number of command arguments (present when command is set) |
| `mounts` | object[] | bind mounts (present when set) |
| `env_keys` | string[] | environment variable names, sorted (present when set) |
| `result` | string | outcome code |
| `exit_code` | number | container exit code (present when available) |
| `duration` | string | container run attempt wall-clock time |

Result codes:

| Code | Condition |
|------|-----------|
| `success` | container exited with status 0 |
| `container_exit_nonzero` | container exited with a non-zero status (not 125) |
| `docker_error` | Docker failed to start the container, or exited with status 125 |

#### auth.failure

Emitted for every failed authorization attempt. No `session_id` is
included because the session is not reliably established.

| Field | Type | Description |
|-------|------|-------------|
| `method` | string | HTTP method of the request |
| `path` | string | request path |
| `result` | string | failure reason |

Result codes:

| Code | Condition |
|------|-----------|
| `admin.parse_failed` | `Authorization` header is missing, uses a non-Bearer scheme, or the token is empty/malformed on an admin endpoint |
| `admin.wrong_token` | Bearer token does not match the configured admin token |
| `session.parse_failed` | `Authorization` header is missing, uses a non-Bearer scheme, or the token is empty/malformed on a session endpoint |
| `session.not_found` | No active session matches the token (unknown, expired, or deleted) |
| `session.database_error` | Database error during session lookup |

#### pull.start

Emitted before a Docker pull begins.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `image` | string | image name with tag |

No `result` or `duration` field.

#### pull.finish

Emitted after a Docker pull completes (success or failure).

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `image` | string | image name with tag |
| `result` | string | `success` or `pull_error` |
| `exit_code` | number | present when an exit code is available |
| `duration` | string | pull wall-clock time |

### What is never logged

The audit log and operational log never contain:

- the raw HTTP request body;
- HTTP request headers;
- `Authorization` header values and the token used for authentication;
- environment variable values (only names appear in `env_keys`);
- Docker build output or container stdout/stderr;
- internal error messages or stack traces;
- command arguments (only `command_arg_count` is recorded).

### Examples

Successful build:

```json
{"time":"2026-01-15T10:30:00Z","event":"build.start","session_id":"dhs_0a1b2c3d4e5f","image":"myapp:v1","context":".","dockerfile":"Dockerfile"}
{"time":"2026-01-15T10:30:05Z","event":"build.finish","session_id":"dhs_0a1b2c3d4e5f","image":"myapp:v1","context":".","dockerfile":"Dockerfile","result":"success","duration":"5s"}
```

Successful session creation:

```json
{"time":"2026-01-15T10:29:55Z","event":"session.create","session_id":"dhs_0a1b2c3d4e5f","workspace":"/home/user/project","result":"success","duration":"1ms"}
```

Authorization failure:

```json
{"time":"2026-01-15T10:31:00Z","event":"auth.failure","method":"POST","path":"/run","result":"session.not_found"}
```

Container run:

```json
{"time":"2026-01-15T10:32:00Z","stream":"audit","event":"run.start","session_id":"dhs_0a1b2c3d4e5f","request_id":"req_abcdef1234567890","image":"alpine:3.19","command_arg_count":3,"mounts":[{"source":".","target":"/workspace","read_only":true}],"env_keys":["APP_MODE"]}
{"time":"2026-01-15T10:32:01Z","stream":"audit","event":"run.finish","session_id":"dhs_0a1b2c3d4e5f","request_id":"req_abcdef1234567890","image":"alpine:3.19","command_arg_count":3,"mounts":[{"source":".","target":"/workspace","read_only":true}],"env_keys":["APP_MODE"],"result":"success","duration":"1s"}
```

## Security considerations

### Path traversal

All paths are resolved through `filepath.Abs` and `filepath.EvalSymlinks`
before comparison. The `isInside` function uses `filepath.Rel`, which
operates on canonical paths.

### Symlink escape

`EvalSymlinks` resolves all symlinks in a path. If a symlink inside the
workspace points outside, the resolved path will fail the `isInside` check.

### Cross-workspace access

Each session is bound to one workspace. Build context and mount sources
are validated against that workspace. An agent cannot access another
session's workspace.

### Session token leakage

Session tokens are returned once during creation. The full token is never
stored in the database — only its SHA-256 hash. Token comparison uses
`ConstantTimeCompare` to prevent timing attacks.

### Direct docker.sock access

docker-helper does not expose `docker.sock`. The agent communicates only
through the HTTP API. The Unix socket has `0600` permissions.

### Secret leakage through logs

Command arguments, environment variable values, and Docker output are
never logged. Admin and session tokens are never logged. The audit
record for `POST /run` includes `command_arg_count` but never the
arguments themselves.

### Container security

docker-helper applies a fixed security policy when running containers:

- `--rm` — remove the container on exit;
- `--security-opt label=disable` — disable SELinux/MacAppLabel confinement;
- `--user <uid>:<gid>` — run as the helper process's own UID and GID.

## Design principles

- small API surface;
- deny by default;
- policy enforcement outside the coding agent;
- session-scoped authorization;
- canonical path validation;
- deterministic Docker command generation;
- Docker CLI instead of exposing docker.sock.

## Non-goals

- container orchestration;
- Kubernetes integration;
- full Docker API compatibility;
- multi-host execution;
- container scheduling;
- image registry management;
- network management;
- volume management beyond bind mounts;
- detached container execution;
- container logs endpoint;
- health checks;
- resource limits (CPU, memory);
- build caching configuration;
- build secrets;
- build arguments.

## Future work

Items discussed but not yet implemented:

- OpenCode custom tool integration (client-side);
- launcher component;
- RPM/DEB packaging;
- token rotation command;