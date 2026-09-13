---
name: docker-helper
description: Drive Docker through Docker Helper — pull images, build images, run containers, and authenticate to registries without direct access to Docker or docker.sock. Covers delegated Session creation when the environment provisions a Launcher or Principal credential, the Session's issued filesystem scope (workspace plus filesystem roots), and self-introspection of your own authority with docker-helper self / GET /self. Use this skill whenever a task requires Docker operations in an environment where Docker Helper is available.
---

# Docker Helper

Docker access is provided through Docker Helper.

## Quick start

Most environments provision the agent with a Session token — use it and
skip the delegated-identity machinery:

```bash
docker-helper pull IMAGE
docker-helper build --context . --dockerfile Dockerfile --image IMAGE
docker-helper run --image IMAGE --mount .:/workspace -- command arg...
```

Protected operations read the Session token from
`DOCKER_HELPER_SESSION_TOKEN` (set by your environment; never display its
value).

- No `docker-helper` binary → use the HTTP API over the Docker Helper
  Unix socket (HTTP API interface below). Both interfaces are first-class.
- Provisioned with a Docker Helper credential instead of a session
  token → Delegated identity below.
- Want to know exactly what your bearer authorizes → Introspection:
  self below.

## Never

- invoke `docker` directly;
- access `docker.sock`;
- start, stop, reload, or configure Docker Helper;
- use any `session` subcommand with only a Session token: Session
  management requires a Docker Helper credential (Launcher or Principal —
  see Delegated identity below) and is then allowed only as permitted by
  that authority;
- look for or use the Docker Helper administrative token;
- print, log, echo, or otherwise expose `DOCKER_HELPER_SESSION_TOKEN` or a
  Docker Helper credential token;
- fall back to direct Docker access if a Docker Helper operation fails;
- use administrative/operator commands: `serve`, `init`, `reload`, `config`,
  `principal`, `launcher`, `credential`, `admin-token`, `apparmor`,
  `selinux`.

## Introspection: self

`docker-helper self` (HTTP: `GET /self` with the same bearer) is the one
self-introspection surface. The daemon classifies your credential and
answers with exactly your own authority — no more:

- **Session bearer** → your Session: identity, ownership, expiry, and the
  persisted immutable filesystem snapshot (workspace plus any issued
  filesystem roots, each with its access mode);
- **Launcher credential** → your Launcher: id, name, owning principal,
  scope, and stored/effective allowed-root entries;
- **Principal credential** → your Principal: username, uid/gid, home,
  enabled state, and stored/effective allowed-root entries.

The admin token has no self resource (`404 self_not_available`). A self
read is read-only and grants no authority over peers: it never permits
listing or managing other Sessions, Launchers, or Principals.

## Client interfaces

Docker Helper provides two first-class client interfaces — the
`docker-helper` CLI and the HTTP API over the Docker Helper Unix socket.
Neither is a legacy or fallback interface; use the interface selected by
the user or environment.

If none was selected, determine availability of both:

- **CLI available:** `command -v docker-helper >/dev/null 2>&1`
- **HTTP available:** a Docker Helper socket is resolvable (Socket
  discovery below) and `curl` (or an equivalent HTTP client) is present

- only one available → use it;
- both available → either may be used, with no preference;
- neither available → report that Docker Helper is unavailable.

Use one interface consistently for the current operation when practical.
The CLI is a convenience client for the same daemon capabilities the HTTP
API exposes; it hides transport details (operation polling, log offsets).

### Socket discovery

Resolve the Docker Helper Unix socket in this order:

1. `DOCKER_HELPER_SOCKET_PATH`, if set — the authoritative override;
2. the user-mode socket
   `$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock`, when
   `XDG_RUNTIME_DIR` is set and that socket exists;
3. the system socket `/run/docker-helper/docker-helper.sock` — the
   system/sandbox default.

The CLI resolves this order automatically. An HTTP client resolves the
same order itself. Never declare Docker Helper unavailable only because
the system-mode socket is absent while the daemon runs in user mode: check
the user-mode socket first. A transport/connectivity failure on every
resolved socket is the only unavailability evidence.

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

`GET /auth` (HTTP, with the installed credential as the Bearer token)
reports the authority: the response is `{"authority":"launcher",...}` or
`{"authority":"principal",...}`. The CLI consumes the credential from the
canonical installed credential file automatically; do not display any
token value.

If the environment provides only `DOCKER_HELPER_SESSION_TOKEN` and no
credential, skip this section entirely: do not create, list, show, or
delete sessions.

### Creating a Session (Launcher or Principal credential)

CLI:

```bash
docker-helper session create --workspace .
```

The workspace is resolved against your own current directory; it must lie
inside the Launcher's effective allowed roots. The response shows the
session token once — export it as `DOCKER_HELPER_SESSION_TOKEN` and never
display it.

HTTP: the installed credential is the Bearer. Read it into a shell
variable from the canonical installed credential file — the same file
`docker-helper credential install` wrote and the CLI resolves — without
printing it, and never echo the variable:

```bash
CREDENTIAL="$(cat "${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper/credential.token")"

curl --silent --show-error \
  --unix-socket "$SOCKET" \
  -H "Authorization: Bearer $CREDENTIAL" \
  -H "Content-Type: application/json" \
  -d '{"workspace":"/host/path/inside/effective/roots"}' \
  http://localhost/sessions
```

### Session filesystem roots

The Session's filesystem scope is issued at creation time and is immutable
afterwards: parent allowed-root policy changes never affect an
already-issued Session. The workspace is mandatory. What else can be
issued depends on the deployment mode:

- **System mode**: a repeatable `--filesystem-root PATH=ACCESS` flag (CLI)
  or a `filesystem_roots` array of `{path, access}` objects (HTTP) may add
  absolute host filesystem roots — directories or regular files — inside
  the target Launcher's effective ceiling. ACCESS is `read_write` or
  `read_only`, always within the parent authority. Issued roots may be
  used as absolute mount sources (see Path model).
- **User mode**: no disjoint filesystem root can be issued — an explicit
  root is accepted only when its canonical path equals the canonical
  workspace. Such an explicit workspace root may narrow the workspace to
  `read_only` (for example
  `--filesystem-root /host/path/to/workspace=read_only`); any additional,
  disjoint, or child root is refused before the Session exists.

Every request may only narrow the target Launcher's ceiling; a widening
request is refused `invalid_filesystem_policy` before the Session exists.
Omitting the flag keeps the inherited behavior. There is no post-create
Session filesystem mutation.

## Path model

Both interfaces share the same path semantics. Define once, apply everywhere.

- **Build contexts** are workspace-relative by default; an absolute host
  path inside the session workspace is also accepted (containment is
  daemon-validated).
- **Mount sources** are never agent-container absolute paths such as
  `/workspace/...`. Two source forms exist:
  - a **workspace-relative source** (including `.` for the workspace
    root) is scoped to the session workspace by grammar;
  - an **absolute host source** is authorized through the Session's issued
    filesystem snapshot: it is accepted when it lies inside the snapshot
    (the workspace, or an issued filesystem root visible in your `self`
    snapshot); any other absolute path is refused.
- **User-mode mount rule** — the daemon-enforced invariant is that the
  canonical resolved source equals the canonical Session workspace.
  `.` is the recommended portable spelling and is valid in both modes;
  in user mode no subdirectory, file, or disjoint source is accepted
  (rejected as `invalid_mount`).
- **Mount targets** are absolute paths inside the launched container.
- **`--workdir`** / **`workdir`** is an absolute path inside the launched
  container.

Do not call operator commands such as `config show mode` to discover the
deployment mode.

### Session filesystem policy

The session's filesystem policy is the immutable snapshot issued when the
session was created. Introspect your own snapshot with `docker-helper self`
— it renders the exact persisted PATH/ACCESS table for a Session bearer.
`session show SESSION_ID` is the operator/control-plane lookup for a
credential that authorizes it, not a Session-bearer surface. The snapshot
does not change during the session's lifetime, and parent allowed-root
policy changes do not affect an already-issued session.

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

```bash
docker-helper help
docker-helper help pull
docker-helper help build
docker-helper help run
docker-helper help registry
docker-helper help registry login
docker-helper help self
docker-helper help session
```

Do not use the administrative/operator commands from the Never list.
The `session` subcommands (create, list, show, delete) require a Docker
Helper credential (Launcher or Principal); with only a Session token, do
not use them. `self` works with whichever bearer you hold, including a
Session token.

## Pull

```bash
docker-helper pull IMAGE
```

## Build

```bash
docker-helper build \
  --context . \
  --dockerfile Dockerfile \
  --image IMAGE \
  --build-arg KEY=value      # repeatable
```

`build` waits for the daemon operation to finish and streams operation
output. Build arguments are not a mechanism for passing secrets.

## Run

```bash
docker-helper run \
  --image IMAGE \
  -- command arg...
```

Other useful options: `--entrypoint`, `--workdir`, `--shm-size`, `--env
KEY=value`. Use `docker-helper help run` for exact syntax. Mount sources
follow the Path model; `run` waits for the operation to finish, streams
its output, and propagates a non-zero container exit code.

**Passing secrets.** Export the value in your own environment and use
`--env-from DEST=SOURCE` (SOURCE names your environment variable, DEST is
the name the workload sees):

```bash
ORCHESTRATOR_LLM_KEY=secret \
docker-helper run --image IMAGE \
  --env-from LLM_KEY=ORCHESTRATOR_LLM_KEY \
  -- command arg...
```

- the value is read locally; it is not placed in the `docker-helper`
  argv, is not printed in diagnostics, is not inherited from the
  surrounding shell, and the daemon does not log environment values;
- an unset SOURCE stops the command (exit 2) before any container
  operation is created;
- known limitation: `run` starts the workload through the legacy Docker
  CLI, which receives the value as `--env DEST=value`, so the value can
  appear in that daemon-side child process's argv; `--env-from`
  guarantees nothing beyond the `docker-helper` process boundary.

**Helper socket (system mode only).** `--helper-socket` makes the Docker
Helper socket reachable inside the container at
`/run/docker-helper/docker-helper.sock` (read-only projection, chosen
server-side; rejected in user mode). While the projection is active, a
`--mount` target overlapping `/run/docker-helper` — the path itself, an
ancestor such as `/run`, or a descendant such as the socket path — is
rejected. The socket provides transport only; the workload still needs a
bearer credential for protected operations, passed separately with
`--env-from`.

**Mount examples** (rules in Path model):

```bash
--mount .:/workspace                # portable, both modes
--mount relative/source:/path       # system mode: workspace-relative file or subdirectory
--mount /opt/agent/cache:/cache     # system mode: issued absolute filesystem root
--mount .:/workspace:ro             # read-only
```

## Cancellation

While CLI `build` or `run` is active:

- SIGINT cancels the daemon operation and exits with code 130;
- SIGTERM cancels the daemon operation and exits with code 143.

Do not attempt manual `docker kill` or container cleanup.

## Registry authentication

Interactive:

```bash
docker-helper registry login --registry REGISTRY --username USER
```

Non-interactive (pipe password via stdin; never put registry passwords
directly into command arguments):

```bash
printf '%s\n' "$REGISTRY_PASSWORD" | \
  docker-helper registry login \
    --registry REGISTRY \
    --username USER \
    --password-stdin
```

# HTTP API interface

The HTTP API is a fully supported direct client interface — same
capabilities as the CLI, different syntax only. Set the socket path
without displaying any secret (Socket discovery order):

```bash
if [ -n "$DOCKER_HELPER_SOCKET_PATH" ]; then
  SOCKET="$DOCKER_HELPER_SOCKET_PATH"
elif [ -n "$XDG_RUNTIME_DIR" ] && [ -S "$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock" ]; then
  SOCKET="$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock"
else
  SOCKET=/run/docker-helper/docker-helper.sock
fi
```

Protected requests require (never print the Authorization header with the
expanded token):

```text
Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN
Content-Type: application/json
```

## Endpoints

```bash
# Pull — synchronous
curl --silent --show-error --unix-socket "$SOCKET" \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"image":"alpine:3.24"}' \
  http://localhost/pull

# Build — async, 201 + operation_id (acceptance, not completion)
curl --silent --show-error --unix-socket "$SOCKET" \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"context":".","dockerfile":"Dockerfile","image":"myapp:test"}' \
  http://localhost/build

# Run — async, 201 + operation_id
curl --silent --show-error --unix-socket "$SOCKET" \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"image":"alpine:3.24","command":["echo","hello"]}' \
  http://localhost/run

# Cancel
curl --silent --show-error --unix-socket "$SOCKET" \
  -H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN" \
  -X POST \
  "http://localhost/operations/OPERATION_ID/cancel"
```

Run request fields: `image`, `entrypoint`, `command`, `workdir`,
`environment`, `mounts`, `shm_size`, `helper_socket`.
Build request fields: `context`, `dockerfile`, `image`, `build_args`.

`"helper_socket": true` is the HTTP equivalent of the CLI
`--helper-socket` (Run, CLI interface): system mode only, server-owned
read-only projection, user mode rejects the flag.

## Mount examples (rules in Path model)

```json
{"source": ".",                "target": "/workspace",     "read_only": true}
{"source": "src",              "target": "/workspace/src", "read_only": false}
{"source": "/opt/agent/cache", "target": "/cache",         "read_only": false}
```

First is portable (both modes); second is a workspace-relative
subdirectory (system mode); third is an issued absolute filesystem root
(system mode) — the same capability as the CLI `--mount
/opt/agent/cache:/cache` example.

## Async operation lifecycle

For HTTP `build` and `run`:

1. **Start** — POST to `/build` or `/run`; retain the returned
   `operation_id`.
2. **Poll** — GET `/operations/OPERATION_ID` until status is `succeeded`
   or `failed`.
3. **Fetch logs** — GET `/operations/OPERATION_ID/logs?offset=OFFSET`
   during polling and after completion. Use `next_offset` from each
   response for the next request. When `truncated` is true, older output
   has been discarded.
4. **Inspect result** — after a terminal status, check `result_code` and
   `exit_code` in the operation status response.

Do not start work that depends on a successful build until the build
operation has reached `succeeded`. Do not use Docker directly to
terminate the workload — cancel through the endpoint above.

## Registry authentication over HTTP

`POST /registry/login` with JSON fields:

```json
{
  "registry": "registry.example.com",
  "username": "user",
  "password": "secret"
}
```

Treat the password as a secret. Construct and send the JSON using a
mechanism that does not print or expose the password in shell command
text, logs, or diagnostic output. After a successful login, subsequent
operations in the same Docker Helper session use that session's registry
credentials.

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
- **Transport/connectivity failure** (e.g., inability to connect to any
  socket resolved by the Socket discovery order) is the only condition
  that indicates Docker Helper is unavailable.

Do not switch to direct Docker access after an API rejection.

If the requested capability cannot be performed through the available
Docker Helper interface, report that limitation to the user.

Do not invent workload-specific URLs, credentials, tokens, passwords, or other
required external configuration. If a launched workload requires real
configuration that is unavailable, report or request it rather than fabricating
placeholder values and continuing.
