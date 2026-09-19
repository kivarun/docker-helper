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
docker-helper build . --dockerfile Dockerfile --image IMAGE
docker-helper run --mount .:/workspace IMAGE -- command arg...
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

Authentication sources are per command family, and
`DOCKER_HELPER_SESSION_TOKEN` never overrides an operator credential:

- Agent/data-plane commands (`pull`, `build`, `run`, `registry login`)
  authenticate **only** with the Session token from
  `DOCKER_HELPER_SESSION_TOKEN`; they never fall back to an installed
  credential and never become operator-authority requests because one is
  installed.
- Session control commands (`session create/list/show/delete`)
  authenticate **only** through the operator credential source (explicit
  `--token-file`, otherwise the installed operator credential);
  `DOCKER_HELPER_SESSION_TOKEN` does not participate in these commands.
- `self` is the one dual-authority surface: `--token-file` wins, then a
  non-empty `DOCKER_HELPER_SESSION_TOKEN`, then the installed operator
  credential. The daemon classifies the selected bearer; the CLI only
  selects the source.

If your harness must exercise a specific authority, provide only the
intended source or select it explicitly (`--token-file`); never rely on
ambient credentials. Never inspect or print token values.

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

Endpoint selection differs by command family; do not conflate them.

Agent/data-plane commands (`pull`, `build`, `run`, `registry login`,
authenticated with the Session bearer) resolve the Unix socket in this
order:

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

Operator/control-plane commands (`session create/list/show/delete`,
`principal`, `launcher`, `credential`, `reload`, `admin-token rotate`,
completion introspection) authenticate with Principal/Launcher credentials
through explicit endpoint selection: `--endpoint` / `--system` when given,
otherwise the documented operator default (an existing user socket first,
otherwise the system socket). `DOCKER_HELPER_SOCKET_PATH` does **not**
select their endpoint. `session cleanup` is not an API-backed command at
all: it is offline local-state maintenance with no endpoint selection.

`self` follows whichever credential source its documented precedence
selects: with the explicit `--token-file` or with neither source it uses
the operator resolution; with a non-empty `DOCKER_HELPER_SESSION_TOKEN` it
uses the agent/data-plane resolution above.

## Delegated identity

Some environments provision the agent with a Docker Helper credential
instead of a pre-created session token. The credential is a Bearer key
stored by the environment via `docker-helper credential install`; the agent
does not install it itself. A Launcher credential may optionally perform the
narrow self-rotation hardening step described below:

- **Launcher credential** (narrowest): session creation and session
  management are automatically scoped to one launcher. No selector is
  needed; do not pass one. Supplying that Launcher's own `dhl_...` ID is
  accepted as explicit self-selection and does not change the target.
- **Principal credential** (broader): session creation resolves the
  principal's default launcher automatically. Do not pass a selector
  unless explicitly instructed.

`GET /auth` (HTTP, with the installed credential as the Bearer token)
reports the authority: the response is `{"authority":"launcher",...}` or
`{"authority":"principal",...}`. The CLI consumes the credential from the
canonical installed credential file automatically; do not display any
token value.

A Launcher credential may rotate exactly its own credential — the
launcher credential rotate command with no selector (an explicit selector
may be that Launcher's own name or stable `dhl_...` ID; HTTP:
`POST /principals/{principal}/launchers/{launcher}/credential/rotate`
with the installed credential as the Bearer): the
credential ID, ownership, Launcher policy, and Sessions are preserved,
only the bearer secret changes, and the bootstrap bearer becomes invalid
atomically. This is the recommended post-provisioning hardening step when
the environment hands you a bootstrap credential — authenticate, rotate
self, persist the returned replacement securely through the environment's
supported install mechanism, and discard the bootstrap bearer. Rotation
is optional: ordinary Session use works without it. The CLI never rewrites
your credential store, and the new bearer is printed exactly once. A
Launcher credential has no general Launcher/Principal control-plane
authority — self-rotation is its only credential-management capability.

If the environment provides only `DOCKER_HELPER_SESSION_TOKEN` and no
credential, skip this section entirely: do not create, list, show, or
delete sessions.

### Creating a Session (Launcher or Principal credential)

CLI:

```bash
docker-helper session create .
```

The workspace is resolved against your own current directory; it must
resolve to a proper descendant of an effective allowed root — the allowed
root itself is an authority ceiling, not a valid Session workspace. The
response shows the
session token once — export it as `DOCKER_HELPER_SESSION_TOKEN` and never
display it.

HTTP: the installed credential is the Bearer. Keep the credential file as
the only source of the value and feed the Authorization header to curl
through its header-from-stdin form (`-H @-`) — the token must never appear
in any process argument and is never printed. Define the file-backed header
producer once and pipe it into curl:

```bash
docker_helper_header_from_file() {
  printf '%s' 'Authorization: Bearer '
  tr -d '\r\n' < "$1"
  printf '\n'
}

docker_helper_header_from_file \
  "${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper/credential.token" | \
curl --silent --show-error \
  --unix-socket "$SOCKET" \
  -H @- \
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
  absolute host filesystem roots — directories or regular files that must
  already exist — inside
  the target Launcher's effective ceiling. ACCESS is `read_write` or
  `read_only`. The request may only narrow the effective Launcher ceiling,
  never widen it: a `read_write` root at a path where the effective
  Launcher ceiling is `read_only` is refused. Within one request's own
  entries a more-specific `read_write` exception below a broader
  `read_only` Session region is legal when the ceiling authorizes
  `read_write` at that child — a Session may be read-only over a broader
  tree with a more-specific writable child (the pipeline-run shape). Never
  read this as "a Session cannot have a writable child under its own
  read-only parent". Issued roots may be
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

The issued snapshot is the daemon-normalized effective authority, not a
verbatim echo of your request: an explicit root equal to the workspace
replaces the implicit workspace grant, redundant authority already covered
by another entry with the same effective access may collapse during
normalization, and a narrower nested `read_only` region stays represented
because it changes effective authority. Read your issued scope back
through `docker-helper self` (or `session show`) instead of
reconstructing it from the create request.

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
- **Mount containment is on the canonical source, not the spelling.** Both
  source forms are admitted lexically before any probing and then
  canonicalized; the canonical source must stay inside issued Session
  authority, and the enforcement implementation's
  intermediate-path/ancestor containment invariants apply on top (a
  writable exposure additionally requires no `read_only` region below the
  source inside the snapshot, and the enforced system-mode pathname may
  not contain a symlinked intermediate component). A spelling that only
  reaches a compliant final target by violating that containment is not a
  bypass.
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
`docker-helper session show SESSION_ID` is the operator/control-plane
lookup for a credential that authorizes it, not a Session-bearer surface.
The snapshot does not change during the session's lifetime, and parent
allowed-root policy changes do not affect an already-issued session.

Authority for future Sessions can change under you: narrowing a parent
allowed-root ceiling may delete stored Principal or restricted-Launcher
descendant roots that are no longer covered, and a restricted Launcher
whose final stored root is cascaded away remains restricted with zero
roots. This changes authority for future Session creation only — the
operator's concern, never something to manipulate from your side. The
operational consequences for you are: trust your own `self` snapshot as
the authority actually issued to the current Session, and do not assume a
future Session will receive the same authority merely because the current
Session has it.

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

### Machine consumption: request --json explicitly

Finite-result CLI commands default to human-readable output. When
consuming a finite result programmatically, request `--json` explicitly —
for example `docker-helper self --json`, `docker-helper session create
--json ...`, `docker-helper session show --json SESSION_ID` — and parse
the documented JSON fields; never parse the human block. Stream, protocol,
and help commands (`pull`, `build`, `run`, `completion`, `help`) are
deliberate exceptions: consume them according to their streaming, protocol,
or text contract instead (operation output, exit codes, log offsets).

## Pull

```bash
docker-helper pull IMAGE
```

## Build

```bash
docker-helper build . \
  --dockerfile Dockerfile \
  --image IMAGE \
  --build-arg KEY=value      # repeatable
```

`build` waits for the daemon operation to finish and streams operation
output. Build arguments are not a mechanism for passing secrets: a value
reaches the daemon-side Docker CLI child as `--build-arg K=V` argv and is
observable through `/proc/<pid>/cmdline` while that child runs (where host
procfs policy permits), and Docker/BuildKit may retain ARG-related material
in image history/provenance.

## Run

```bash
docker-helper run IMAGE -- command arg...
```

IMAGE is the primary operand: all docker-helper flags (including
`--entrypoint`, `--workdir`, `--shm-size`, `--env KEY=value`, `--mount`)
belong before IMAGE, and everything after IMAGE belongs to the workload
command — the workload's own flags are never interpreted by
docker-helper. A single optional bare `--` separator after IMAGE may be
used for clarity. Use `docker-helper help run` for exact syntax. Mount sources
follow the Path model; `run` waits for the operation to finish, streams
its output, and propagates a non-zero container exit code.

**Passing secrets.** Export the value in your own environment and use
`--env-from DEST=SOURCE` (SOURCE names your environment variable, DEST is
the name the workload sees):

```bash
ORCHESTRATOR_LLM_KEY=secret \
docker-helper run --env-from LLM_KEY=ORCHESTRATOR_LLM_KEY IMAGE -- command arg...
```

- the value is read locally; it is not placed in the `docker-helper`
  argv, is not printed in diagnostics, is not inherited from the
  surrounding shell, and the daemon does not log environment values;
- an unset SOURCE stops the command (exit 2) before any container
  operation is created;
- known limitation (accepted Release 2.2 residual): `run` starts the
  workload through the legacy Docker CLI, which receives the value as
  `--env DEST=value`, so the value can appear in that daemon-side child
  process's argv (observable through `/proc/<pid>/cmdline` while the child
  runs, where host procfs policy permits); `--env-from` guarantees nothing
  beyond the `docker-helper` process boundary. No alternative secret
  transport is introduced in Release 2.2; the argv class closes with the
  future migration away from the legacy Docker CLI.

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
docker-helper registry login --username USER REGISTRY
```

Non-interactive (pipe password via stdin; never put registry passwords
directly into command arguments):

```bash
printf '%s\n' "$REGISTRY_PASSWORD" | \
  docker-helper registry login \
    --username USER \
    --password-stdin \
    REGISTRY
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

Protected requests require two headers (never print the Authorization
header with the real token; the examples below feed the bearer to curl
through its header-from-stdin form, so the value never appears in any
process argument):

```text
Authorization: Bearer <token>
Content-Type: application/json
```

Define the environment-backed header producer once; every example below is
then copy-paste executable:

```bash
docker_helper_session_header() {
  printf '%s' 'Authorization: Bearer '
  printf '%s' "$DOCKER_HELPER_SESSION_TOKEN"
  printf '\n'
}
```

## Endpoints

```bash
# Pull — synchronous
docker_helper_session_header | \
curl --silent --show-error --unix-socket "$SOCKET" \
  -H @- \
  -H "Content-Type: application/json" \
  -d '{"image":"alpine:3.24"}' \
  http://localhost/pull

# Build — async, 201 + operation_id (acceptance, not completion)
docker_helper_session_header | \
curl --silent --show-error --unix-socket "$SOCKET" \
  -H @- \
  -H "Content-Type: application/json" \
  -d '{"context":".","dockerfile":"Dockerfile","image":"myapp:test"}' \
  http://localhost/build

# Run — async, 201 + operation_id
docker_helper_session_header | \
curl --silent --show-error --unix-socket "$SOCKET" \
  -H @- \
  -H "Content-Type: application/json" \
  -d '{"image":"alpine:3.24","command":["echo","hello"]}' \
  http://localhost/run

# Cancel
docker_helper_session_header | \
curl --silent --show-error --unix-socket "$SOCKET" \
  -H @- \
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
