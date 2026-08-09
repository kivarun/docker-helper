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

### Run

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

Four categories of responses:

**1. Success** — HTTP 200, `ok: true`.

**2. Validation error** — HTTP 400, `ok: false`, `code` describes the invalid
input (for example `invalid_image`, `invalid_build_context`, `invalid_mount`,
`invalid_workdir`). The request was rejected before the Docker operation was
started.

**3. Docker execution error** — HTTP 500, `ok: false`, `code` is
`docker_pull_failed`, `docker_build_failed`, or `docker_run_failed`. The
request passed helper validation, but the Docker operation failed.

**4. Container process failure** — HTTP 200, `ok: false`, `code` is
`container_exit_nonzero`, `exit_code` contains the process exit code. The
container started successfully but the process inside exited with a non-zero
code. This is a container-process failure, not a Docker Helper transport failure.

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