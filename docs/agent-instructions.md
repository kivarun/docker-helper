# Agent Instructions Template

This is a ready-to-copy `AGENTS.md` fragment for a coding agent that needs to
use docker-helper. The `/exchange` section is environment-specific; the Docker
Helper section describes the agent-facing docker-helper contract.

## Shared exchange directory

A shared directory is available at `/exchange`.

Use it as follows:

* `/exchange/inbox` — files provided by the user.
* `/exchange/outbox` — completed results.
* `/exchange/scratch` — temporary working files.

Rules:

* Do not modify project source files through `/exchange`.
* Store temporary files in `/exchange/scratch`.
* Store finished deliverables in `/exchange/outbox`.
* Publish completed files using an atomic rename (`mv`).

## Docker Helper for agents

Docker is available through the docker-helper daemon. Do not invoke `docker`
directly, access `docker.sock`, or attempt to start or manage the helper.

The launcher has already created a Docker Helper session and provided its
session token.

### API access

Send HTTP requests through the Unix socket:

```
/run/docker-helper/docker-helper.sock
```

Every protected request must include:

```
Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN
Content-Type: application/json
```

Never print, log, echo, or otherwise expose `DOCKER_HELPER_SESSION_TOKEN`.

A typical request:

```bash
curl --silent --show-error \
  --unix-socket /run/docker-helper/docker-helper.sock \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"image":"alpine:3.24"}' \
  http://localhost/pull
```

Do not use Docker directly as a fallback if a helper request fails.

### Pull

```bash
curl --silent --show-error \
  --unix-socket /run/docker-helper/docker-helper.sock \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"image":"alpine:3.24"}' \
  http://localhost/pull
```

### Build

`POST /build` starts an asynchronous Docker build and returns immediately.
The build runs in the background.

```bash
curl --silent --show-error \
  --unix-socket /run/docker-helper/docker-helper.sock \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"context":".","dockerfile":"Dockerfile","image":"myapp:test"}' \
  http://localhost/build
```

* `context` is resolved against the host workspace associated with the current
  helper session. Prefer paths relative to the session workspace.
* `dockerfile` must be relative to `context`.
* Do not pass agent-container paths such as `/workspace/...` as build-context
  paths.

Optional `build_args` (map[string]string) passes build-time variables to
Docker. Names must match `[A-Za-z_][A-Za-z0-9_]*`. Empty values are valid.
Build args are not intended for secrets.

**Build is asynchronous.** The response is HTTP 201 with an `operation_id`:

```json
{"ok":true,"operation_id":"op_abcdef1234567890","status":"running"}
```

HTTP 201 does not mean the build finished. You must poll for completion.

**Poll status** until `status` is `succeeded` or `failed`:

```bash
curl --silent --show-error \
  --unix-socket /run/docker-helper/docker-helper.sock \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  http://localhost/operations/op_abcdef1234567890
```

**Read incremental logs** using the `offset` parameter:

```bash
curl --silent --show-error \
  --unix-socket /run/docker-helper/docker-helper.sock \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  'http://localhost/operations/op_abcdef1234567890/logs?offset=0'
```

The logs response includes `next_offset` — use it as the `offset` for the
next request. When `truncated` is `true`, older log data was evicted by
the bounded retention limit.

Operation logs are the merged stdout/stderr stream from the Docker CLI
process and may include Docker pull/build status output in addition to
container stdout. Do not assume the response contains only container output.

**Do not** start `/run` with the new image until the build status is
`succeeded`. If the status is `failed`, inspect `result_code`, `exit_code`
and the logs to diagnose the problem.

Do not fall back to invoking Docker directly if the build fails.

### Run

`POST /run` starts an asynchronous container run and returns immediately.
The container runs in the background.

```bash
curl --silent --show-error \
  --unix-socket /run/docker-helper/docker-helper.sock \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "image":"myapp:test",
    "command":["echo","hello"],
    "workdir":"/workspace",
    "mounts":[
      {
        "source":".",
        "target":"/workspace",
        "read_only":true
      }
    ]
  }' \
  http://localhost/run
```

Supported fields:

* `image` — image reference.
* `entrypoint` — optional entrypoint string.
* `command` — optional array of command arguments.
* `workdir` — optional absolute path inside the new container.
* `environment` — optional object mapping environment-variable names to string values.
* `mounts` — optional array of bind mounts.
* `shm_size` — optional `/dev/shm` size string (e.g. `"64m"`, `"1g"`; case-insensitive
  unit; max 2 GiB).

Mount rules:

* `source` must be relative to the current session workspace.
* `source` must resolve to an existing regular file or directory inside that workspace.
* `target` must be an absolute path inside the new container.
* `read_only` is optional and defaults to `false`.
* Two mounts must not use the same effective target path.
* Do not use `/workspace/...` from the agent container as a mount source.
  The helper runs on the host, where that path may not exist.

Environment rules:

* `environment` is a JSON object.
* Environment-variable names must use shell-style identifiers such as
  `FOO`, `MY_VAR`, or `VALUE_1`.
* Environment values are strings.

**Run is asynchronous.** The response is HTTP 201 with an `operation_id`:

```json
{"ok":true,"operation_id":"op_abcdef1234567890","status":"running"}
```

HTTP 201 does not mean the container finished. You must poll for completion.

**Poll status** until `status` is `succeeded` or `failed`:

```bash
curl --silent --show-error \
  --unix-socket /run/docker-helper/docker-helper.sock \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  http://localhost/operations/op_abcdef1234567890
```

**Read incremental logs** using the `offset` parameter:

```bash
curl --silent --show-error \
  --unix-socket /run/docker-helper/docker-helper.sock \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  'http://localhost/operations/op_abcdef1234567890/logs?offset=0'
```

The logs response includes `next_offset` — use it as the `offset` for the
next request. When `truncated` is `true`, older log data was evicted by
the bounded retention limit.

Operation logs are the merged stdout/stderr stream from the Docker CLI
process and may include Docker status output. Do not assume the response
contains only container stdout.

Run-specific result codes:

- `succeeded` — container exited with status 0;
- `docker_run_failed` — Docker run operation failed;
- `container_exit_nonzero` — container exited with a non-zero status;
- `cancelled` — operation cancelled by client.

If the status is `failed`, inspect `result_code`, `exit_code`
and the logs to diagnose the problem.

### Cancel an operation

To cancel a running build or run operation:

```bash
curl --unix-socket /run/docker-helper/docker-helper.sock \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  -X POST 'http://localhost/operations/op_abcdef1234567890/cancel'
```

The operation becomes terminal with `status=failed` and `result_code=cancelled`.
Cancelling an already-terminal operation is idempotent (returns HTTP 200
with the current terminal state).

Do not fall back to invoking Docker directly (no `docker kill`, no manual
container removal). Cancel must go through the helper.

### Workspace path model

There are two different filesystem namespaces:

1. The agent container.
2. The host workspace associated with the Docker Helper session.

The current project is typically visible to the agent at `/workspace`, but
Docker Helper does not interpret `/workspace` as the host project path.

For helper requests:

* build contexts and mount sources are resolved against the session workspace
  on the host;
* `workdir` and mount `target` refer to paths inside the newly launched container.

Therefore:

* use `.` or another workspace-relative path for host-side build and mount sources;
* use `/workspace`, `/input`, or similar absolute paths only for paths inside
  a container being launched by `/run`.

### Responses and errors

Inspect both the HTTP status and the JSON response body. If you need the HTTP
status code, obtain it explicitly with `curl --write-out "%{http_code}"` — do
not infer it from the response body or curl's exit code.

**POST /pull (synchronous)**

| HTTP | `ok` | `code` | Meaning |
|------|------|--------|---------|
| 200 | true | — | Success |
| 400 | false | validation error | Request validation failed |
| 401 | false | — | Missing or invalid session token |
| 500 | false | `docker_pull_failed` | Docker operation failed |

**POST /build and POST /run (asynchronous)**

| HTTP | `ok` | `code` | Meaning |
|------|------|--------|---------|
| 201 | true | — | Operation accepted; poll `/operations/{id}` |
| 400 | false | validation error | Request validation failed |
| 401 | false | — | Missing or invalid session token |
| 503 | false | `shutting_down` | Daemon is shutting down |

After 201, poll `GET /operations/{id}`:

| `status` | Meaning |
|----------|---------|
| `running` | Operation in progress; continue polling |
| `succeeded` | Operation complete |
| `failed` | Operation failed; check `result_code`, `exit_code`, logs |

Run-specific `result_code` values on failure:

| `result_code` | Meaning |
|---------------|---------|
| `docker_run_failed` | Docker run operation failed |
| `container_exit_nonzero` | Container exited with non-zero status |

Do not retry failed helper operations by invoking Docker directly. Report the
helper error and its response when it prevents completion of the task.

### Security rules

* Never invoke Docker directly.
* Never access or expose `docker.sock`.
* Never print or expose `DOCKER_HELPER_SESSION_TOKEN`.
* Do not attempt to create, list, or delete helper sessions.
* Do not look for or use the Docker Helper administrative token.
* Do not start, stop, reload, or reconfigure Docker Helper.
* Use only the session and API made available by the launcher.