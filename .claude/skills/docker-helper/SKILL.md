---
name: docker-helper
description: Use Docker through Docker Helper to pull images, build images, run containers, and authenticate to container registries without direct access to Docker or docker.sock. Use this skill whenever a task requires Docker operations in an environment where Docker Helper is available.
---

# Docker Helper

Docker access is provided through Docker Helper.

Never:

- invoke `docker` directly;
- access `docker.sock`;
- start, stop, reload, or configure Docker Helper;
- create, list, delete, or otherwise manage Docker Helper sessions;
- look for or use the Docker Helper administrative token;
- print, log, echo, or otherwise expose `DOCKER_HELPER_SESSION_TOKEN`;
- fall back to direct Docker access if a Docker Helper operation fails;
- use operator commands: `serve`, `init`, `reload`, `session`, `config`,
  `principal`, `credential`.

## Client interfaces

Docker Helper provides two supported client interfaces:

1. the `docker-helper` CLI;
2. the HTTP API over the Docker Helper Unix socket.

Both interfaces are first-class. Neither is a legacy or fallback interface.

Use the interface selected by the user or environment.

If no interface was explicitly selected, determine availability of both:

- **CLI available:** `command -v docker-helper >/dev/null 2>&1`
- **HTTP available:** the Docker Helper socket exists and a suitable HTTP
  client is present (for the documented curl examples — `curl`)

Then:

- if only one interface is available, use it;
- if both are available, either may be used, with no preference;
- if neither is available, report that Docker Helper is unavailable.

Use one interface consistently for the current operation when practical.

The CLI is a convenience client for the same daemon capabilities exposed by
the HTTP API. It hides transport details such as asynchronous operation
polling and incremental log offsets.

Protected operations use the session token from:

```text
DOCKER_HELPER_SESSION_TOKEN
```

Never display its value.

The Docker Helper socket is normally:

```text
/run/docker-helper/docker-helper.sock
```

If `DOCKER_HELPER_SOCKET_PATH` is set, use that socket path instead.

## Path model

Both interfaces share the same path semantics. Define once, apply everywhere.

- **Mount sources** and **build contexts** are relative to the Docker Helper
  session workspace, never absolute agent-container paths like `/workspace/...`.
- **Mount targets** are absolute paths inside the launched container.
- **`--workdir`** / **`workdir`** is an absolute path inside the launched
  container.

### Trusted CA injection

When the administrator enables `trusted_ca_injection` to `"auto"`, Docker
Helper automatically injects a trusted CA certificate into containers
started via `POST /run`. The agent does not need to configure this.

Do not attempt to mount host CA files or set `SSL_CERT_DIR` or
`NODE_EXTRA_CA_CERTS` to override the injection, unless the workload
explicitly requires a different value. If the agent mounts a path that
overlaps with `/run/docker-helper/trusted-ca`, the request will be
rejected as `invalid_mount`.

# CLI interface

When the `docker-helper` command is available, its built-in help is the
authoritative CLI reference.

For discovery:

```bash
docker-helper help
docker-helper help pull
docker-helper help build
docker-helper help run
docker-helper help registry
docker-helper help registry login
```

Do not use operator commands: `serve`, `init`, `reload`, `session`, `config`.

## Pull

```bash
docker-helper pull IMAGE
```

## Build

```bash
docker-helper build \
  --context . \
  --dockerfile Dockerfile \
  --image IMAGE
```

Build arguments may be repeated:

```bash
docker-helper build \
  --context . \
  --dockerfile Dockerfile \
  --image IMAGE \
  --build-arg KEY=value \
  --build-arg OTHER=value
```

`build` waits for the daemon operation to finish and streams operation output.
Build arguments are not a mechanism for passing secrets.

## Run

```bash
docker-helper run \
  --image IMAGE \
  -- command arg...
```

Optional environment variables:

```bash
docker-helper run \
  --image IMAGE \
  --env KEY=value \
  -- command arg...
```

Optional workspace mounts:

```bash
docker-helper run \
  --image IMAGE \
  --mount relative/source:/container/path \
  -- command arg...
```

Read-only mount:

```bash
docker-helper run \
  --image IMAGE \
  --mount relative/source:/container/path:ro \
  -- command arg...
```

Other useful options: `--entrypoint`, `--workdir`, `--shm-size`.
Use `docker-helper help run` for exact syntax.

`run` waits for the container operation to finish and streams its output.
If the container exits with a non-zero status, the CLI propagates the
container exit code.

## Cancellation

While CLI `build` or `run` is active:

- SIGINT cancels the daemon operation and exits with code 130;
- SIGTERM cancels the daemon operation and exits with code 143.

Do not attempt manual `docker kill` or container cleanup.

## Registry authentication

Interactive:

```bash
docker-helper registry login \
  --registry REGISTRY \
  --username USER
```

Non-interactive (pipe password via stdin):

```bash
printf '%s\n' "$REGISTRY_PASSWORD" | \
  docker-helper registry login \
    --registry REGISTRY \
    --username USER \
    --password-stdin
```

Do not put registry passwords directly into command arguments.

# HTTP API interface

The HTTP API is a fully supported direct client interface.

Set the socket path without displaying any secret:

```bash
SOCKET="${DOCKER_HELPER_SOCKET_PATH:-/run/docker-helper/docker-helper.sock}"
```

Protected requests require:

```text
Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN
Content-Type: application/json
```

Do not print the Authorization header with the expanded token.

## Pull over HTTP

`POST /pull` is synchronous.

```bash
curl --silent --show-error \
  --unix-socket "$SOCKET" \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"image":"alpine:3.24"}' \
  http://localhost/pull
```

## Build over HTTP

`POST /build` starts an asynchronous operation.

```bash
curl --silent --show-error \
  --unix-socket "$SOCKET" \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"context":".","dockerfile":"Dockerfile","image":"myapp:test"}' \
  http://localhost/build
```

A successful start returns HTTP 201 with an `operation_id`.
HTTP 201 means the operation was accepted, not that the build completed.

Optional build arguments:

```json
{
  "build_args": {
    "KEY": "value"
  }
}
```

## Run over HTTP

`POST /run` also starts an asynchronous operation.

```bash
curl --silent --show-error \
  --unix-socket "$SOCKET" \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "image":"alpine:3.24",
    "command":["echo","hello"]
  }' \
  http://localhost/run
```

Useful request fields: `image`, `entrypoint`, `command`, `workdir`,
`environment`, `mounts`, `shm_size`.

Example mount:

```json
{
  "source": ".",
  "target": "/workspace",
  "read_only": true
}
```

## Async operation lifecycle

For HTTP `build` and `run`, follow this algorithm:

1. **Start** — POST to `/build` or `/run`; retain the returned `operation_id`.
2. **Poll** — GET `/operations/OPERATION_ID` until status is `succeeded` or `failed`.
3. **Fetch logs** — GET `/operations/OPERATION_ID/logs?offset=OFFSET` during
   polling and after completion. Use `next_offset` from each response for the
   next request. When `truncated` is true, older output has been discarded.
4. **Inspect result** — after a terminal status, check `result_code` and
   `exit_code` in the operation status response.

Do not start work that depends on a successful build until the build operation
has reached `succeeded`.

## Cancel over HTTP

```bash
curl --silent --show-error \
  --unix-socket "$SOCKET" \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  -X POST \
  "http://localhost/operations/OPERATION_ID/cancel"
```

Do not use Docker directly to terminate the workload.

## Registry authentication over HTTP

`POST /registry/login` with JSON fields:

```json
{
  "registry": "registry.example.com",
  "username": "user",
  "password": "secret"
}
```

Treat the password as a secret. Construct and send the JSON using a mechanism
that does not print or expose the password in shell command text, logs, or
diagnostic output.

After a successful login, subsequent operations in the same Docker Helper
session use that session's registry credentials.

# Failures

When Docker Helper rejects or fails an operation:

- inspect the returned Docker Helper diagnostic;
- for asynchronous operations, inspect status, `result_code`, `exit_code`,
  and operation logs;
- correct the request when appropriate;
- do not bypass Docker Helper by invoking Docker directly.

If the requested capability cannot be performed through the available
Docker Helper interface, report that limitation to the user.

Do not invent workload-specific URLs, credentials, tokens, passwords, or other
required external configuration. If a launched workload requires real
configuration that is unavailable, report or request it rather than fabricating
placeholder values and continuing.
