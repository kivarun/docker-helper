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
`$XDG_RUNTIME_DIR/docker-helper.sock` with `0600` permissions.

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
- required for `POST /build`, `POST /run`;
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
Environment validation
    │
Mount resolution
    │
Docker invocation
```

Authentication validates the session token. Request validation checks
the image name. Environment validation ensures variable names match
`^[A-Za-z_][A-Za-z0-9_]*$`. Mount resolution resolves each source path
against the workspace and checks for duplicate targets. Docker invocation
runs `docker run` with fixed security policy.

Validation details:

- mount source must be relative to workspace;
- mount target must be absolute;
- source is resolved through `EvalSymlinks` and checked via `isInside`;
- environment values are masked before logging;
- environment names are sorted for deterministic output;
- container runs with fixed security policy (details in implementation).

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

Values are logged in masked form:

```
KEY=s*** (length=32)
FLAG="" (length=0)
```

Full values are never logged. The mask shows the first character and the
length. This prevents secret leakage while retaining diagnostic value.

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
| `invalid_mount` | `POST /run` | mount validation failure |

Planned:

- internal errors (database failures, encoding errors) will be logged
  through the standard Go `log` package;
- when running under systemd, these logs will be available in journald;
- internal error details will not be exposed in API responses.

## Audit logging

docker-helper writes structured audit records to `stderr`. There is no
configuration option to change the output destination; redirect `stderr`
when starting the daemon to persist the log.

### Format

JSON Lines: one JSON object per line, UTF-8 encoded. Each line is an
independent record.

### Common fields

| Field | Type | Description |
|-------|------|-------------|
| `time` | string | UTC timestamp, RFC 3339 |
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

#### run.start

Emitted before a container starts.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `image` | string | container image name with tag |
| `command` | string[] | container command with arguments (present when set) |
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
| `image` | string | container image name with tag |
| `command` | string[] | container command with arguments (present when set) |
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

### What is never logged

The audit log never contains:

- the raw HTTP request body;
- HTTP request headers;
- `Authorization` header values and the token used for authentication;
- environment variable values (only names appear in `env_keys`);
- Docker build output or container stdout/stderr;
- internal error messages or stack traces.

The `command` field in `run.start`/`run.finish` records the full command
with arguments as provided, without masking. Do not pass secrets in
command arguments.

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
{"time":"2026-01-15T10:32:00Z","event":"run.start","session_id":"dhs_0a1b2c3d4e5f","image":"alpine:3.19","command":["sh","-c","echo hello"],"mounts":[{"source":".","target":"/workspace","read_only":true}],"env_keys":["APP_MODE"]}
{"time":"2026-01-15T10:32:01Z","event":"run.finish","session_id":"dhs_0a1b2c3d4e5f","image":"alpine:3.19","command":["sh","-c","echo hello"],"mounts":[{"source":".","target":"/workspace","read_only":true}],"env_keys":["APP_MODE"],"result":"success","duration":"1s"}
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

Environment variable values are masked before logging. Admin and session
tokens are never logged.

### Container security

docker-helper applies a fixed security policy when running containers.
The specific Docker flags used are an implementation detail.

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
- systemd user service;
- structured logging (JSON);
- token rotation command;
- session revocation (soft delete via `revoked_at`).