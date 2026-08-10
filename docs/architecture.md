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
    ├── registers operation (tryCreate — atomic with shutdown gate)
    ├── starts async process (cmd.Start under op.mu)
    ├── captures stdout/stderr into bounded LogBuffer
    ├── completion goroutine owns cmd.Wait()
    ├── transitions operation to succeeded/failed
    └── status/logs available via operation endpoints
    │
POST /operations/{id}/cancel  (session token)
    │
    ├── graceful SIGTERM to running process
    ├── bounded force-cleanup fallback if process does not exit
    └── operation becomes terminal (status=failed, result_code=cancelled)
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

### docker-helper session cleanup

Remove expired sessions from the local state database. Does not require
a running daemon or admin token.

```
docker-helper session cleanup
```

Deletes rows whose `expires_at` has passed. Active sessions are
untouched. Reports the number of removed rows.

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
(`allowed_root`, `session_ttl`, `log_level`, `audit_enabled`,
`shutdown_timeout`, `operation_retention_ttl`, `operation_max_completed`,
`operation_log_max_bytes`). Reports `updated` or `unchanged`. If the daemon
is running, the change is applied immediately.

`docker-helper config unset FIELD` — removes an optional field to restore
its default. `allowed_root` and `session_ttl` are required and cannot be
unset. Reports `unset` or `unchanged`. If the daemon is running, the change
is applied immediately.

### `docker-helper reload`

Ask the running daemon to re-read `config.json` and apply changes without
restarting. All configurable fields are applied at runtime:
`allowed_root`, `session_ttl`, `log_level`, `audit_enabled`,
`shutdown_timeout`, `operation_retention_ttl`, `operation_max_completed`,
`operation_log_max_bytes`. Computed paths (socket, database, state) are not
changed. If the daemon is not running, the command fails with a non-zero
exit code. If the new configuration is invalid, the daemon keeps its current
configuration and the command returns an error.

### `docker-helper session <subcommand>`

Manages sessions. Requires a subcommand.

Subcommands: `create`, `list`, `delete`, `cleanup` (see Session CLI section
above).

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

docker-helper installs a signal handler for SIGINT and SIGTERM. On stop:

- the operation admission gate closes immediately (no new operations accepted);
- HTTP drain and operation termination share one `shutdown_timeout` budget;
- in-flight HTTP requests are drained;
- running build/run processes receive graceful SIGTERM;
- for run, helper-owned containers are cleaned up via cidfile before
  force-killing the Docker CLI process;
- after the deadline, still-running processes are force-killed;
- the completion goroutine owns `cmd.Wait()` and reaps each process;
- the lock is held during the entire drain so a second instance cannot
  start until the first fully stops;
- helper-owned build/run processes and containers are never left unmanaged
  after shutdown.

After `TimeoutStopSec=30s`, systemd sends SIGKILL if any processes
remain.

### Operation lifecycle invariants

Key internal guarantees that make cancel and shutdown safe:

- explicit cancel and daemon shutdown share the same underlying
  termination lifecycle;
- first termination reason wins and cannot be overwritten by a concurrent
  caller;
- terminal transition is single-winner: the first `succeed()` or `fail()`
  to set `CompletedAt` wins; subsequent calls are no-ops;
- completion goroutine is the sole `cmd.Wait()` owner; termination paths
  only Signal/Kill processes, coordinate force cleanup through the shared
  force phase, and never call `cmd.Wait()` themselves; the cancel handler
  waits for terminal `op.done` before returning;
- graceful termination phase is bounded (default 5s);
- force cleanup is single-owner: only the first caller to reach the force
  phase performs daemon-side container cleanup and CLI process kill;
- concurrent followers wait on a shared absolute force-cleanup deadline
  rather than creating independent timers;
- `/run` force cleanup uses cidfile + daemon-side `docker kill` to prevent
  orphan containers;
- `<kind>.finish` audit event is emitted exactly once per operation.

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
Operation registration (tryCreate — atomic with shutdown gate)
    │
Async process start (cmd.Start under op.mu)
    │
Incremental bounded log capture (cmd.Stdout/stderr → boundedBuffer)
    │
Completion goroutine (cmd.Wait → status transition)
    │
Retention cleanup
```

Authentication validates the session token. Request validation checks
required fields and dockerfile relativity. Canonical path resolution
resolves the workspace and context through `EvalSymlinks`. Boundary
validation ensures the context and dockerfile are inside the workspace
and context respectively.

Operation registration uses `tryCreate`, which atomically checks the
shutdown gate and registers the operation under the same mutex. If the
daemon is shutting down, registration is rejected with 503.

The build process starts asynchronously. `cmd.Start()` is called under
`op.mu` to synchronize with shutdown termination. stdout and stderr are
captured directly into a thread-safe bounded buffer (`operation_log_max_bytes`).

A completion goroutine owns `cmd.Wait()` and transitions the operation
to `succeeded` or `failed` when the process exits.

Validation details:

- context may be relative (joined with workspace) or absolute (must be
  inside workspace);
- dockerfile must be relative to context;
- all paths are resolved through `EvalSymlinks` before `isInside` checks;
- build-arg names must match `^[A-Za-z_][A-Za-z0-9_]*$`;
- build-arg keys are sorted for deterministic Docker argv;
- build-arg values are never logged or audited (only `build_arg_keys`).

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
Operation registration (tryCreate — atomic with shutdown gate)
    │
Async docker run process start (cmd.Start under op.mu)
    │
Incremental bounded log capture (cmd.Stdout/stderr → boundedBuffer)
    │
Completion goroutine (cmd.Wait → status transition)
    │
Retention cleanup
```

Authentication validates the session token. Request validation checks
that the image field is non-empty. Workdir validation ensures the value
is an absolute path if provided. Environment validation ensures variable
names match `^[A-Za-z_][A-Za-z0-9_]*$`. Mount resolution resolves each
source path against the workspace and checks for duplicate targets.

Operation registration uses `tryCreate`, which atomically checks the
shutdown gate and registers the operation under the same mutex. If the
daemon is shutting down, registration is rejected with 503.

The run process starts asynchronously. `cmd.Start()` is called under
`op.mu` to synchronize with shutdown termination. stdout and stderr are
captured directly into a thread-safe bounded buffer (`operation_log_max_bytes`).

A completion goroutine owns `cmd.Wait()` and transitions the operation
to `succeeded` or `failed` when the process exits.

**Container lifecycle:**

- `--rm` — container is removed on exit;
- helper-owned `--cidfile` — records container ID for lifecycle management;
- graceful shutdown — Docker CLI receives SIGTERM;
- force fallback — daemon-side `docker kill` by CID, then CLI process
  force-kill/reap if needed;
- helper-owned containers are never left orphan after shutdown.

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
that the image field is non-empty. Docker invocation runs
`docker pull` with the image reference.

Image reference syntax is delegated to Docker. The helper does not
reimplement the Docker reference grammar; it only checks that the image
field is non-empty. Docker CLI validates the reference when the command
executes. If Docker rejects the reference, the endpoint returns its
standard Docker failure response.

## Health endpoint

`GET /health` returns a 200 OK response with a JSON body indicating the
server is running. No authentication is required. This endpoint is
intended for liveness probes and does not perform any audit logging.

## Operation endpoints

`POST /build` and `POST /run` return HTTP 201 with an `operation_id`.
The client uses the operation endpoints to track progress.

### GET /operations/{id}

Returns the operation status and metadata. Requires the session token
that created the operation.

Response fields:

| Field | Type | Description |
|-------|------|-------------|
| `ok` | boolean | always true on success |
| `operation_id` | string | operation identifier |
| `status` | string | `running`, `succeeded`, or `failed` |
| `created_at` | string | RFC 3339 timestamp |
| `started_at` | string | RFC 3339 timestamp (present when process started) |
| `completed_at` | string | RFC 3339 timestamp (present when finished) |
| `duration` | string | wall-clock duration (present when finished) |
| `exit_code` | number | process exit code (present on failure) |
| `result_code` | string | `succeeded` or failure code (present when finished) |

### GET /operations/{id}/logs

Returns incremental operation output. Requires the session token.

Query parameters:

| Parameter | Description |
|-----------|-------------|
| `offset` | Byte offset to start reading from (default: 0) |

Response fields:

| Field | Type | Description |
|-------|------|-------------|
| `ok` | boolean | always true on success |
| `operation_id` | string | operation identifier |
| `offset` | number | the requested offset |
| `next_offset` | number | offset for the next request |
| `truncated` | boolean | true if older data was evicted |
| `logs` | string | log data from the requested offset |

Logs are a mixed stdout/stderr byte stream. Retention: each operation
log is stored in a bounded buffer of `operation_log_max_bytes`. When the
limit is exceeded, the oldest data is evicted. `truncated` is true when
the requested offset refers to evicted data.

### POST /operations/{id}/cancel

Cancels a running operation. Requires the session token that created the
operation.

Contract:

- running operation → graceful SIGTERM, then bounded force-cleanup
  fallback if the process does not exit in time;
- operation becomes terminal: `status=failed`, `result_code=cancelled`;
- already-terminal operation → idempotent HTTP 200 with current state;
- unknown or foreign operation → HTTP 404 `operation_not_found`;
- operation logs remain accessible after cancel;
- the response returns after the operation reaches terminal state.

Cancel and daemon shutdown share the same underlying termination
lifecycle. The first termination reason to be set wins and cannot be
overwritten by a concurrent caller.

## Retention

Completed operations are retained in memory. Cleanup is opportunistic and
runs on access:

- `operation_retention_ttl` — operations older than this are removed;
- `operation_max_completed` — when more completed operations exist than
  this limit, the oldest are removed;
- `operation_log_max_bytes` — per-operation log buffer size; older output
  is evicted when exceeded.

Cleanup is invoked during operation creation (`POST /build`, `POST /run`) and operation
status access (`GET /operations/{id}`). There is no background retention
worker or periodic ticker.

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

The API returns JSON errors with a stable `code` field. Clients can
distinguish error types programmatically. The `duration` field reports
wall-clock time.

`POST /build` and `POST /run` return HTTP 201 with an `operation_id` when
accepted. Execution result (success, failure, exit code, logs) appears
through the operation endpoints:

- `GET /operations/{id}` — status, timestamps, exit code, result code;
- `GET /operations/{id}/logs?offset=N` — incremental operation output.

`POST /pull` remains synchronous and returns the execution
result directly in the response.

Current error codes (non-exhaustive):

| Code | Endpoint | Condition |
|------|----------|-----------|
| `unauthorized` | all protected | missing/invalid token |
| `invalid_json` | all JSON endpoints | request body is not valid JSON |
| `invalid_build_context` | `POST /build` | build request validation failure |
| `invalid_build_args` | `POST /build` | build-arg name invalid |
| `invalid_image` | `POST /run`, `POST /pull` | image name is empty |
| `invalid_mount` | `POST /run` | mount validation failure |
| `invalid_workdir` | `POST /run` | workdir is not an absolute path |
| `invalid_environment` | `POST /run` | environment variable name invalid |
| `invalid_workspace` | `POST /sessions` | workspace invalid or outside AllowedRoot |
| `invalid_session_id` | `DELETE /sessions/{id}` | session ID is empty |
| `shutting_down` | `POST /build`, `POST /run` | daemon is shutting down |
| `docker_pull_failed` | `POST /pull` | docker pull returned non-zero |
| `operation_not_found` | `GET /operations/{id}`, `GET /operations/{id}/logs`, `POST /operations/{id}/cancel` | operation not found or foreign session |

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
| `request_id` | string | request correlation ID |
| `session_id` | string | session identifier |
| `operation_id` | string | operation identifier |
| `image` | string | target image reference |
| `context` | string | build context path from the request |
| `dockerfile` | string | Dockerfile path from the request |
| `build_arg_keys` | string[] | build-arg names, sorted (present when set; values are never logged) |

No `result` or `duration` field.

#### build.finish

Emitted after a Docker build completes (success or failure).
Does not include `request_id` because completion is not request-scoped.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `operation_id` | string | operation identifier |
| `image` | string | target image reference |
| `context` | string | build context path from the request |
| `dockerfile` | string | Dockerfile path from the request |
| `build_arg_keys` | string[] | build-arg names, sorted (present when set; values are never logged) |
| `result` | string | `succeeded`, `docker_build_failed`, or `cancelled` |
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
| `request_id` | string | request correlation ID |
| `session_id` | string | session identifier |
| `operation_id` | string | operation identifier |
| `image` | string | container image reference |
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
Does not include `request_id` because completion is not request-scoped.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `operation_id` | string | operation identifier |
| `image` | string | container image reference |
| `command_arg_count` | number | number of command arguments (present when command is set) |
| `mounts` | object[] | bind mounts (present when set) |
| `env_keys` | string[] | environment variable names, sorted (present when set) |
| `result` | string | outcome code |
| `exit_code` | number | container exit code (present when available) |
| `duration` | string | container run attempt wall-clock time |

Result codes:

| Code | Condition |
|------|-----------|
| `succeeded` | container exited with status 0 |
| `docker_run_failed` | Docker failed to start the container |
| `container_exit_nonzero` | container exited with a non-zero status |
| `cancelled` | operation cancelled by client |

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
| `image` | string | image reference |

No `result` or `duration` field.

#### pull.finish

Emitted after a Docker pull completes (success or failure).

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `image` | string | image reference |
| `result` | string | `success` or `pull_error` |
| `exit_code` | number | present when an exit code is available |
| `duration` | string | pull wall-clock time |

### What is never logged

The audit log and operational log never contain:

- the raw HTTP request body;
- HTTP request headers;
- `Authorization` header values and the token used for authentication;
- environment variable values (only names appear in `env_keys`);
- build-arg values (only names appear in `build_arg_keys`);
- Docker build output or container stdout/stderr;
- internal error messages or stack traces;
- command arguments (only `command_arg_count` is recorded).

### Examples

Successful build:

```json
{"time":"2026-01-15T10:30:00Z","event":"build.start","request_id":"req_abcdef1234567890","session_id":"dhs_0a1b2c3d4e5f","operation_id":"op_abcdef1234567890","image":"myapp:v1","context":".","dockerfile":"Dockerfile"}
{"time":"2026-01-15T10:30:05Z","event":"build.finish","session_id":"dhs_0a1b2c3d4e5f","operation_id":"op_abcdef1234567890","image":"myapp:v1","context":".","dockerfile":"Dockerfile","result":"succeeded","duration":"5s"}
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
{"time":"2026-01-15T10:32:00Z","event":"run.start","request_id":"req_abcdef1234567890","session_id":"dhs_0a1b2c3d4e5f","operation_id":"op_abcdef1234567890","image":"alpine:3.19","command_arg_count":3,"mounts":[{"source":".","target":"/workspace","read_only":true}],"env_keys":["APP_MODE"]}
{"time":"2026-01-15T10:32:01Z","event":"run.finish","session_id":"dhs_0a1b2c3d4e5f","operation_id":"op_abcdef1234567890","image":"alpine:3.19","command_arg_count":3,"mounts":[{"source":".","target":"/workspace","read_only":true}],"env_keys":["APP_MODE"],"result":"succeeded","duration":"1s"}
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
- build secrets.

## Future work

Items discussed but not yet implemented:

- OpenCode custom tool integration (client-side);
- launcher component;
- RPM/DEB packaging;
- token rotation command;