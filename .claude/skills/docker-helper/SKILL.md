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
- create, list, or delete Docker Helper sessions when the environment
  provisioned this agent only with a Session token: Session management
  requires a Docker Helper credential (Launcher or Principal — see Delegated
  identity below) and is then allowed only as permitted by that authority;
- look for or use the Docker Helper administrative token;
- print, log, echo, or otherwise expose `DOCKER_HELPER_SESSION_TOKEN` or a
  Docker Helper credential token;
- fall back to direct Docker access if a Docker Helper operation fails;
- use administrative/operator commands: `serve`, `init`, `reload`, `config`,
  `principal`, `launcher`, `credential`.

## Delegated identity

Some environments provision the agent with a Docker Helper credential
instead of a pre-created session token. The credential is a Bearer key
(stored by the environment via `docker-helper credential install`; the
agent never installs or rotates it):

- **Launcher credential** (narrowest): session creation and session
  management are automatically scoped to one launcher. No selector is
  needed; do not pass one.
- **Principal credential** (broader): session creation resolves the
  principal's default launcher automatically. Do not pass a selector
  unless explicitly instructed.

With a credential, create sessions with:

```bash
docker-helper session create --workspace .
```

and use the returned session token for Docker operations exactly as
described below.

When the Launcher's effective policy permits finer per-Session control,
the creating authority may issue additional filesystem roots at
issuance time with a repeatable `--filesystem-root PATH=ACCESS` flag
(PATH is an absolute host path inside the target Launcher's effective
allowed roots; ACCESS `read_write` or `read_only`). The workspace stays
mandatory and receives the maximum permitted ceiling mode; a root at the
canonical workspace path explicitly narrows it:

```bash
docker-helper session create --workspace /home/michael/work/git/BoxProbe \
  --filesystem-root /home/michael/work/git/BoxProbe=read_only \
  --filesystem-root /opt/michael/cache=read_write
```

The request may only narrow the target Launcher's ceiling; a widening
request is refused `invalid_filesystem_policy` before the Session exists.
Omitting the flag keeps the inherited behavior. There is no post-create
Session filesystem mutation.

`GET /auth` (HTTP, with the installed credential as the Bearer token)
reports the authority: the response is `{"authority":"launcher",...}` or
`{"authority":"principal",...}`. The credential is consumed by the existing
client resolution from the canonical installed credential file; do not copy
it into shell variables or command text, and do not display any token value.

If the environment provides only `DOCKER_HELPER_SESSION_TOKEN` and no
credential, skip this section entirely: do not create, list, or delete
sessions.

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

- **Build contexts** are always relative to the session workspace.
- **Mount sources** are never agent-container absolute paths such as
  `/workspace/...`. The accepted source depends on deployment mode:
  - in **user mode**, only the workspace root source `.` is accepted;
  - in **system mode**, a workspace-relative file or subdirectory source
    is accepted;
  - if the deployment mode is not explicitly known, use `.` as the portable
    mount source.
- **Mount targets** are absolute paths inside the launched container.
- **`--workdir`** / **`workdir`** is an absolute path inside the launched
  container.

Do not call operator commands such as `config show mode` to discover the
deployment mode.

### Session filesystem policy

The session's filesystem policy is an immutable snapshot issued when the
session was created (visible through `session show` as a PATH/ACCESS
table; do not run `session show` unless you were provisioned with a
credential that authorizes it). It does not change during the session's
lifetime, and parent allowed-root policy changes do not affect an
already-issued session.

What this means for mounts:

- A requested **writable** mount can be refused with
  **`read_only_root`** when the source resolves to a read-only region of
  the issued snapshot, or when it would cover such a region. This is a
  policy refusal, distinct from `invalid_mount` (which reports a
  structurally invalid mount). Correct responses are to request the
  source read-only or to stop and report the policy limitation — never
  to retry the same writable request, re-spell the source path (for
  example through a symlink), or bypass Docker Helper.
- If a source is only needed for reading, request it read-only
  (`--mount source:target:ro` or `"read_only": true`). A read-only
  request is valid for a source in either access mode.
- If the workload genuinely requires write access that the session
  snapshot forbids, report the policy limitation to the user and request
  a suitable session from the environment owner. Do not attempt to
  bypass Docker Helper or use symlink spellings to widen authority; the
  daemon decides on the canonical resolved source, never on the spelling.

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

Do not use administrative/operator commands: `serve`, `init`, `reload`,
`config`, `principal`, `launcher`, `credential`. The `session` subcommands
(create, list, delete) require a Docker Helper credential (Launcher or
Principal); with only a Session token, do not use them.

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

To pass a secret value (an API key, a credential token) without placing it
in the `docker-helper` command line, export it in your own environment and
use `--env-from DEST=SOURCE`, where SOURCE names your environment variable
and DEST is the name the workload sees. The value is read locally from
your environment; it is not placed in the `docker-helper` argv, is not
printed in diagnostics, is not inherited from the surrounding shell, and
the daemon does not log environment values. Known limitation: `run` starts
the workload through the legacy Docker CLI, which receives the value as
`--env DEST=value`, so the value can appear in that daemon-side child
process's argv; `--env-from` guarantees nothing beyond the `docker-helper`
process boundary. An unset SOURCE variable stops the command before any
container operation is created.

```bash
ORCHESTRATOR_LLM_KEY=secret \
docker-helper run \
  --image IMAGE \
  --env-from LLM_KEY=ORCHESTRATOR_LLM_KEY \
  -- command arg...
```

In system mode, `--helper-socket` makes the Docker Helper socket reachable
inside the container at `/run/docker-helper/docker-helper.sock` (read-only
projection, chosen server-side). While the projection is active, a `--mount`
target overlapping `/run/docker-helper` — the path itself, an ancestor such
as `/run`, or a descendant such as the socket path — is rejected. The socket
provides transport only; the
workload still needs a bearer credential for protected operations, which
can be passed separately with `--env-from`. In user mode the flag is
rejected.

Optional workspace mounts:

```bash
docker-helper run \
  --image IMAGE \
  --mount .:/workspace \
  -- command arg...
```

System-mode-only: mount a workspace-relative file or subdirectory:

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
  --mount .:/workspace:ro \
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
`environment`, `mounts`, `shm_size`, `helper_socket`.

`"helper_socket": true` is the HTTP equivalent of the CLI
`--helper-socket` (see [Run](#run)): system mode only, a server-owned
read-only projection of the daemon's runtime directory at
`/run/docker-helper` that provides transport reachability only — the
workload still needs a bearer credential passed separately, and user mode
rejects the flag.

Example mount (portable — works in both user and system mode):

```json
{
  "source": ".",
  "target": "/workspace",
  "read_only": true
}
```

Example mount (system-mode-only — relative subdirectory):

```json
{
  "source": "src",
  "target": "/workspace/src",
  "read_only": false
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

## Transport failure vs. API rejection

Any HTTP response from Docker Helper proves that the daemon was reached.
Do not describe Docker Helper as unavailable after an HTTP response.

- **HTTP 4xx** with a structured error `code` means the daemon responded and
  rejected the request due to authentication, validation, or policy. This is
  not evidence that the daemon is down.
- **`invalid_mount`** specifically means the mount specification or mount
  policy was rejected. After this error, inspect the source, target, and
  deployment-mode restrictions described in the Path model section, then
  correct the request.
- **`read_only_root`** specifically means the issued session filesystem
  policy refuses a writable exposure of the source. This is a policy
  refusal, not a structural error and not daemon unavailability: request
  the source read-only when reads suffice, or report the policy
  limitation as described in the Session filesystem policy section.
- **Transport/connectivity failure** (e.g., inability to connect to the
  configured Unix socket) is the only condition that indicates Docker Helper
  is unavailable.

Do not switch to direct Docker access after an API rejection.

If the requested capability cannot be performed through the available
Docker Helper interface, report that limitation to the user.

Do not invent workload-specific URLs, credentials, tokens, passwords, or other
required external configuration. If a launched workload requires real
configuration that is unavailable, report or request it rather than fabricating
placeholder values and continuing.
