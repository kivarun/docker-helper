# Release 3 API and CLI

## Purpose

This document owns the integrated public HTTP and CLI contract for Release 3.
Capability documents define domain behavior; this document assigns exact
routes, request and response fields, CLI spelling, compatibility changes, and
stable public errors without exposing Docker Engine as the product API.

The contract is frozen incrementally as its remaining public choices are
accepted. An undecided spelling in this document is not permission for an
implementation package to invent one locally.

## HTTP compatibility and versioning

Release 3 keeps the existing unversioned HTTP path space. It does not add a
`/v3` prefix, request version header, response version header, or runtime
version-negotiation mechanism.

The HTTP contract follows docker-helper's major product version. Additive
changes may be made within a major version; incompatible request, response, or
semantic changes require a major release and explicit migration notes. CLI and
daemon are distributed as one product and are upgraded together. The daemon
does not retain parallel legacy routes or response schemas solely to support a
mismatched older CLI.

The interactive exec WebSocket protocol is independently versioned through
the `docker-helper.exec.v1` subprotocol. That version belongs to its
long-lived message framing and does not imply an HTTP `/v1` or `/v3`
namespace.

## Process invocation vocabulary

`command` is the public JSON field for the Docker command vector used by
one-shot `run` and Managed Container create. It replaces the image `CMD` and is
combined with either the image Entrypoint or an explicit `entrypoint` override.

`argv` is the public JSON field for the complete executable-and-arguments
vector used by synchronous non-interactive exec and the initial interactive
exec WebSocket message.

`env` is likewise the only public JSON field for the process-local environment
map. It is used by one-shot `run`, Managed Container create, non-interactive
exec, and the initial interactive exec WebSocket message. The Release 2
`environment` field on `/run` is replaced rather than retained as an alias.

For example, exec uses:

```json
{
  "argv": ["pytest", "-q"],
  "env": {
    "MODE": "test"
  },
  "workdir": "/workspace"
}
```

The first `argv` element names the executable and must be non-empty. Later elements
are passed as individual arguments and may be empty. docker-helper never joins
an `argv` or `command` array into a shell command, interprets shell syntax, or inserts
`/bin/sh -c`.

The Release 2 `command` field on `POST /run` is retained. Only its
`environment` field is renamed to `env`; the server defines no alias or
precedence between those environment spellings. Release 3 changes the `/run`
HTTP response from the asynchronous Operation workflow to a synchronous
process result, while its normal blocking CLI use remains unchanged.
Arguments after `--` become `command` for run and create or `argv` for exec,
without local shell rewriting.

## Exec surface

Non-interactive exec uses one synchronous HTTP Command:

```text
POST /containers/{container}/exec
```

Its JSON body uses the common `argv`, `env`, and `workdir` fields. The terminal
process result uses the flat bounded-output envelope defined by
`release-3-logs-and-exec.md`.

Interactive exec upgrades one HTTP GET request to the versioned WebSocket
protocol defined by `release-3-interactive-streaming.md`:

```text
GET /containers/{container}/exec/interactive
```

Both modes are Session data-plane capabilities and admit only a Session
bearer (see `Session-bound command scope`).

Both modes are exposed through one CLI command:

```text
docker-helper container exec CONTAINER -- COMMAND [ARG...]
docker-helper container exec --interactive CONTAINER -- COMMAND [ARG...]
docker-helper container exec -i CONTAINER -- COMMAND [ARG...]
```

Without `-i` or `--interactive`, the command performs synchronous
non-interactive exec. With either flag, it opens the WebSocket transport and
allocates a TTY. There is no separate `--tty` flag because Release 3 has no
interactive non-TTY mode.

The CLI never selects interactive mode from local terminal detection. It uses
terminal detection only to validate an explicitly requested interactive mode.
There is no `container shell` command: docker-helper requires an explicit
executable and never chooses or inserts a shell.

## Session selection and local-name resolution

One Session-selection algorithm is used wherever an authorized management
Command or Query on Session-owned resources needs a Session context it does
not otherwise name: resolving a Session-local Managed Container name and
`POST /containers`. It is a control-plane rule: credential scope can
authorize Session management, never Session workload execution (the
Session-bound data-plane capabilities below require a Session bearer).

- a Session token selects its own Session;
- a Launcher credential may omit `session_id` only when exactly one active,
  unexpired Session is available within that Launcher;
- a Principal credential may omit `session_id` only when exactly one active,
  unexpired Session is available under that Principal's default Launcher;
- Principal inference never searches Sessions owned by non-default Launchers;
- an administrator must always provide `session_id` explicitly;
- no inferable Session returns `400 missing_session`;
- more than one candidate returns `400 ambiguous_session`;
- an explicit selector may select only a Session inside the credential scope;
  a foreign or nonexistent explicit selector returns the same
  `404 session_not_found` response.

Inference never chooses the newest, oldest, or otherwise ordered candidate.
It succeeds only when token scope and the default-Launcher rule produce one
unambiguous usable Session. An explicit selector remains valid for every
authority but can only narrow its token scope.

Commands and Queries that target a Managed Container by its Session-local
`name` use the algorithm with an optional HTTP `session_id` query parameter
and CLI `--session` flag. This applies to `show`, `start`, `stop`, `restart`,
`remove`, `repair`, and `logs`; both exec modes are Session data-plane
capabilities that resolve their container only inside the Session bearer's
own Session.

A globally unique ManagedContainerID needs no Session selection. If an
explicit Session selector is nevertheless supplied with an ID, it only
narrows resolution: a mismatch returns `404 container_not_found`. A local name
that is absent from the selected Session or outside credential scope returns
the same `404 container_not_found` response.

### Launcher selection

Release 3 keeps the existing Principal-scoped Launcher resource hierarchy:
every Launcher route lives under
`/principals/{username}/launchers/{launcher}`, and Release 3 policy
subresources extend that same hierarchy rather than adding parallel
top-level name-based routes. Within such a route, the `{launcher}` path
value accepts:

- a `dhl_...` Launcher ID resolved under the path Principal; or
- a Launcher name resolved only within the path Principal's scope.

Launcher names are the path-safe, Principal-local identifiers established by
Release 2.1 and cannot match Launcher ID syntax; there is no global Launcher
name lookup and no second ownership model. The `{username}` path segment
identifies the Principal: a Principal credential may target only its own
Principal (a foreign username is the same non-disclosing `404
principal_not_found` as the Release 2.1 control plane), and an administrator
names the Principal explicitly in the path. Foreign, nonexistent, and
mismatched selectors return the same `404 launcher_not_found`.

Targeted Launcher CLI commands accept `NAME_OR_ID`. For the ordinary Principal
workflow the argument may be omitted and means that Principal's `default`
Launcher. Administrator omission requires `--principal USERNAME` and means
that Principal's `default`; omission without a Principal is an error. The CLI
materializes the literal `default` selector and does not list Launchers or
guess from global uniqueness.

For example, both forms are valid when Session inference is unambiguous:

```text
docker-helper container show postgres
docker-helper container exec postgres -- pytest -q
```

The caller can always make local-name resolution explicit:

```text
docker-helper container show --session dhs_... postgres
```

## Session-bound command scope

The existing routes remain:

```text
POST /pull
POST /build
POST /run
POST /registry/login
```

Release 3 freezes the Release 2.1 capability boundary:

```text
admin token            -> administrative/control plane
Principal credential   -> Principal control plane
Launcher credential    -> Launcher control plane
Session token          -> Session data plane
```

Credential scope can authorize control-plane management; the Session token
authorizes Session workload execution. These routes are Session data-plane
capabilities and require a Session bearer; a higher-level credential never
becomes a substitute bearer for workload execution, and no inference path
resolves a Session for a Principal or Launcher credential here. The Session
token already identifies its Session, so an optional JSON `session_id`
request field (CLI `--session` flag) is only a narrowing assertion: a value
that does not match the token's Session is the same non-disclosing
`404 session_not_found` as any foreign selector. A Session bearer may
continue using every command without an added field or flag.

Both exec modes are Session data-plane capabilities under the same rule:
non-interactive exec and interactive exec admit only a Session bearer for
the owning Session. A valid Principal or Launcher credential presented
directly to a Session data-plane endpoint is rejected and is never converted
into Session execution authority by inference.

## Managed Container creation scope

The ordinary CLI path therefore remains:

```text
docker-helper container create --image postgres:17
```

A caller selects the Session explicitly whenever inference is unavailable or
ambiguous:

```text
docker-helper container create --session dhs_... --image postgres:17
```

The resource remains `POST /containers`; Release 3 does not add a second
Session-nested container route.

### Create CLI

The CLI syntax is:

```text
docker-helper container create [flags] -- [COMMAND [ARG...]]
```

The public flags are:

```text
--session SESSION_ID
--name NAME
--image IMAGE
--entrypoint EXECUTABLE
--workdir PATH
--env KEY=VALUE
--mount SOURCE:TARGET[:ro]
--cpus NUMBER
--memory SIZE
--pids-limit NUMBER
--shm-size SIZE
--publish CONTAINER_PORT
--publish HOST_PORT:CONTAINER_PORT
--json
```

`--env`, `--mount`, and `--publish` are repeatable. One port means automatic
host-port allocation; `HOST_PORT:CONTAINER_PORT` requests one explicit allowed
host port. Host address and protocol are not CLI inputs. Arguments after `--`
form the `command` array. Their omission preserves image `CMD`.

Create is synchronous and has no `--detach` flag.

### Create request

The complete JSON shape is:

```json
{
  "session_id": "dhs_...",
  "name": "postgres",
  "image": "postgres:17",
  "entrypoint": "/usr/local/bin/docker-entrypoint.sh",
  "command": ["postgres"],
  "workdir": "/workspace",
  "env": {
    "POSTGRES_DB": "app"
  },
  "mounts": [
    {
      "source": "data",
      "target": "/var/lib/postgresql/data",
      "read_only": false
    }
  ],
  "limits": {
    "cpu": 2.0,
    "memory_bytes": 2147483648,
    "pids": 256,
    "shared_memory_bytes": 268435456
  },
  "publications": [
    {
      "container_port": 5432,
      "host_port": 25432
    },
    {
      "container_port": 9187
    }
  ]
}
```

Only `image` is unconditionally required. `session_id` follows the authority
selection rule above. An omitted `name` follows the immutable image-basename
derivation rule. Omitted `entrypoint` and `command` preserve the image values;
an explicitly empty value is rejected rather than interpreted as a request to
clear an image default.

`env` adds or replaces image environment entries for this container. Mount
sources are relative to the Session workspace and targets are absolute
container paths; `read_only` defaults to false. The established workspace,
canonicalization, and MAC policy remains authoritative.

A publication accepts one required `container_port` and one optional
`host_port`. Omitting `host_port` requests server allocation. Host address and
protocol are not request fields because Release 3 fixes them to `127.0.0.1`
and TCP. The complete publication list is limited to 16 entries under the
rules in `release-3-port-publishing.md`.

The request uses the existing 16 KiB body limit, rejects unknown fields, and
contains no restart policy, named volume, arbitrary host path, network mode,
additional alias, privilege, capability, user override, or mutable-update
surface.

### Container representation

Successful create returns HTTP `201 Created`,
`Location: /containers/{id}`, and the same direct representation used by
`container show`:

```json
{
  "id": "dhmc_...",
  "name": "postgres",
  "session_id": "dhs_...",
  "image": "postgres:17",
  "runtime_state": "stopped",
  "limits": {
    "cpu": 2.0,
    "memory_bytes": 2147483648,
    "pids": 256,
    "shared_memory_bytes": 268435456
  },
  "effective_limits": {
    "cpu": 2.0,
    "memory_bytes": 2147483648,
    "pids": 256
  },
  "swap_enabled": false,
  "publications": [
    {
      "host_address": "127.0.0.1",
      "host_port": 25432,
      "container_port": 5432,
      "protocol": "tcp"
    }
  ],
  "created_at": "2026-09-03T18:20:00Z"
}
```

`limits` are the concrete immutable workload values accepted at creation.
`effective_limits` are the current CPU, memory, and PIDs maxima after applying
any narrower current ancestor ceiling. Shared-memory capacity remains only in
`limits`: a later hierarchy change does not rewrite the container's `/dev/shm`
configuration. `swap_enabled` is always false in Release 3 and makes the
applied helper policy observable without creating a request field that can
enable swap.

Every requested or automatically allocated publication is returned with its
concrete address, host port, container port, and protocol. An automatically
derived `name` is also returned.

`condition` and `active_operation_id` appear only while their corresponding
state exists; they are otherwise omitted rather than set to `null`. The
representation exposes no entrypoint, command, workdir, environment, mount,
backend ID, raw Docker configuration, or image-ID fields.

### Container show and list

Managed Container Queries use:

```text
GET /containers/{container}?session_id=dhs_...
GET /containers?principal=alice&launcher_id=dhl_...&session_id=dhs_...&limit=100&cursor=...
```

Show returns the direct Container representation above. `{container}` and the
optional Session selector use the common local-name resolution rules.

List starts from token scope and accepts optional `principal` username,
`launcher_id`, and `session_id` ownership filters. Multiple filters are ANDed
and must describe one ownership chain. A nonexistent, foreign, or mismatched
filter produces an empty collection and never expands visibility.

Each compact list item contains:

```json
{
  "id": "dhmc_...",
  "name": "postgres",
  "principal": "alice",
  "launcher_id": "dhl_...",
  "session_id": "dhs_...",
  "image": "postgres:17",
  "runtime_state": "running"
}
```

`condition` and `active_operation_id` are added only when present. Limits,
publications, swap policy, and timestamps remain available through show and do
not expand every list item.

HTTP pagination defaults to `100` and accepts `limit` in `1..1000` plus one
opaque `cursor`. Results are ordered by newest `created_at` first, with
ManagedContainerID as the stable tie-breaker. The direct envelope is:

```json
{
  "containers": [],
  "next_cursor": "..."
}
```

`next_cursor` is omitted on the last page. There is no total, page number, or
offset.

The CLI forms are:

```text
docker-helper container show [--session SESSION_ID] [--json] NAME_OR_ID
docker-helper container list [--principal USERNAME] [--launcher LAUNCHER_ID] \
  [--session SESSION_ID] [--limit N] [--cursor CURSOR] [--json]
```

Without `--limit`, list follows pages to exhaustion. With `--limit`, it returns
at most that many total items. JSON output preserves the collection envelope;
tabular output writes any remaining cursor to stderr. CLI help always calls the
pagination value `CURSOR`, never `TOKEN`.

### Entrypoint override

Managed Container create retains the existing one-shot `run` entrypoint
capability. Its optional `entrypoint` field is one non-empty executable string;
omission preserves the image Entrypoint. `command` remains the separate vector
that replaces the image `CMD`. docker-helper neither inserts a
shell nor joins either value into a command string.

```json
{
  "image": "example/app:latest",
  "entrypoint": "/bin/sh",
  "command": ["-c", "sleep infinity"]
}
```

The CLI uses the existing `--entrypoint` flag. The accepted entrypoint is
immutable for the Managed Container lifetime.

### Workload limits

Managed Container create and one-shot `run` use one optional `limits` object:

```json
{
  "limits": {
    "cpu": 2.0,
    "memory_bytes": 2147483648,
    "pids": 256,
    "shared_memory_bytes": 268435456
  }
}
```

The object and each member are optional. Every omitted value is materialized
from the accepted default defined by `release-3-resource-constraints.md`.
`cpu` is a positive JSON number with 0.1 logical-CPU granularity;
`memory_bytes` and `shared_memory_bytes` are positive integer byte counts;
`pids` is a positive integer. String sizes, negative or unlimited sentinels,
and Docker-native resource structures are rejected.

Container inspection uses these same canonical field names and units. The
object describes enforced limits, not sampled resource use, reservations, or
a separate Resource domain object.

The CLI exposes the same four limit inputs for one-shot `run` and Managed
Container create:

```text
--cpus 2.0
--memory 2GiB
--pids-limit 256
--shm-size 256MiB
```

Canonical help and human rendering use IEC `KiB`, `MiB`, `GiB`, and `TiB`
suffixes. An integer without a suffix denotes bytes. The existing
case-insensitive integer `k`, `m`, and `g` spellings remain accepted as binary
multipliers for `--shm-size` compatibility. Fractional byte sizes such as
`1.5GiB` are rejected. CLI values are normalized to the JSON number or integer
fields before the request is sent.

The Release 2 `/run` JSON field `shm_size` is replaced by
`limits.shared_memory_bytes`. It is not retained as an HTTP alias; only the CLI
flag remains source-compatible.

## One-shot run request and CLI

Synchronous one-shot execution retains the route:

```text
POST /run
```

Its complete Release 3 request is:

```json
{
  "session_id": "dhs_...",
  "image": "alpine:3.24",
  "entrypoint": "/bin/sh",
  "command": ["-c", "make test"],
  "workdir": "/workspace",
  "env": {
    "CI": "true"
  },
  "mounts": [
    {
      "source": ".",
      "target": "/workspace",
      "read_only": false
    }
  ],
  "limits": {
    "cpu": 2.0,
    "memory_bytes": 2147483648,
    "pids": 256,
    "shared_memory_bytes": 268435456
  }
}
```

Only `image` is required. The request requires a Session bearer; the
optional `session_id` field only narrows or validates the token's own
Session. Omitted `entrypoint` and `command` preserve the image values;
explicitly empty values are rejected rather than interpreted as clearing
an image default.
`env`, `mounts`, and `limits` use exactly the same normalization, workspace,
policy, and default rules as Managed Container create.

One-shot run has no name, port publication, stdin, detach mode, retained
Managed Container, or Operation. Its transient backend container is always
cleaned up through the existing bounded synchronous execution lifecycle.

The CLI form is:

```text
docker-helper run [--session SESSION_ID] --image IMAGE [flags] -- \
  [COMMAND [ARG...]]
```

The supported request flags are `--entrypoint`, `--workdir`, repeatable
`--env`, repeatable `--mount`, `--cpus`, `--memory`, `--pids-limit`, and
`--shm-size`. Arguments after `--` form `command`. There is no `--detach` or
stdin flag.

## Pull request and CLI

Synchronous image pull retains the route:

```text
POST /pull
```

Its complete Release 3 request is:

```json
{
  "session_id": "dhs_...",
  "image": "alpine:3.24"
}
```

`image` is required. The request requires a Session bearer; the optional
`session_id` field only narrows or validates the token's own Session. No
platform, pull-policy, registry, credential, or arbitrary Engine option is
accepted by this request. Unknown fields are rejected.

A successful pull returns HTTP `200`:

```json
{
  "ok": true,
  "output": "...",
  "truncated": false,
  "duration": "3.217s"
}
```

The success result has no redundant `message` or repeated image field. Pull
uses the same combined `command_output_max_bytes` limit as build and run.

The CLI form is:

```text
docker-helper pull [--session SESSION_ID] IMAGE
```

The command blocks for the direct result and has no detach or Operation
workflow.

Expected pull failures preserve already captured bounded progress output:

| HTTP / code | Meaning |
| --- | --- |
| `404 image_not_found` | The registry authoritatively reports that the requested image is absent. |
| `422 pull_access_denied` | The registry denied access or requires different registry credentials. |
| `502 registry_unavailable` | Docker Engine is reachable, but the registry cannot be reached. |

These three responses add sanitized `message`, `output`, `truncated`, and
`duration` to the flat error envelope. A failure before pull execution begins
uses the ordinary short error envelope. Docker Engine unavailability remains
`503 backend_unavailable`; an unexpected Engine interaction remains
`502 backend_failure`.

`401 unauthorized` and `403 forbidden` are reserved for authentication and
authorization at the docker-helper boundary. A remote registry rejection must
not masquerade as either one.

## Build request and CLI

Synchronous image build retains the route:

```text
POST /build
```

Its complete Release 3 request is:

```json
{
  "session_id": "dhs_...",
  "context": ".",
  "dockerfile": "Dockerfile",
  "image": "myapp:v1",
  "build_args": {
    "VERSION": "1.2.3"
  }
}
```

`context`, `dockerfile`, and `image` are required. The request requires a
Session bearer and the optional `session_id` field only narrows or
validates the token's own Session; `build_args` is optional and remains a
string-to-string map with the existing validated key syntax. Build arguments are not a secrets
transport and their values may appear in workload build output.

Unknown fields are rejected. Release 3 adds no platform, target, no-cache,
secret, SSH forwarding, network selection, or arbitrary Docker build option.

The CLI form is:

```text
docker-helper build [--session SESSION_ID] --context PATH --dockerfile FILE \
  --image NAME [--build-arg KEY=VALUE ...]
```

`--build-arg` is repeatable. The CLI blocks for the direct build result and
has no `--detach` flag, Operation polling, or Operation-log retrieval.

## Registry login request and CLI

Session-scoped registry authentication retains the route:

```text
POST /registry/login
```

Its complete Release 3 request is:

```json
{
  "session_id": "dhs_...",
  "registry": "registry.example.com",
  "username": "myuser",
  "password": "secret"
}
```

`registry`, `username`, and `password` are required non-empty strings. The
request requires a Session bearer; the optional `session_id` field only
narrows or validates the token's own Session. Unknown fields are rejected.
A successful login returns HTTP `200` with only:

```json
{
  "ok": true
}
```

The response does not repeat the registry, include duration, or carry a
decorative success message.

Registry credentials are Session-scoped runtime secrets. They are stored only
in protected Session credential storage, never in SQLite, and are removed with
the Session. Username and password never enter audit, operational logs, public
errors, command arguments, or environment variables. The Engine adapter reads
the stored credentials only when authorizing the matching pull or build.

The CLI form is:

```text
docker-helper registry login [--session SESSION_ID] --registry REGISTRY \
  --username USER [--password-stdin] [--json]
```

Without `--password-stdin`, an interactive terminal is required and the CLI
prompts without echo. With it, the CLI reads exactly one line from stdin. No
password flag is exposed. Human mode prints `Login succeeded for REGISTRY`;
JSON mode prints the exact one-field server response.

Registry login failures use:

| HTTP / code | Meaning |
| --- | --- |
| `400 invalid_registry_login` | A required field is absent or fails public validation. |
| `422 registry_auth_denied` | The registry rejected the supplied username and password. |
| `502 registry_unavailable` | Docker Engine is reachable, but the registry cannot be reached. |
| `503 backend_unavailable` | Docker Engine cannot be reached or observed. |
| `502 backend_failure` | An unexpected Engine interaction prevents a trustworthy result. |

All use the ordinary sanitized error envelope and include no registry command
output, username, password, or duration. `401 unauthorized` remains reserved
for authentication at the docker-helper boundary. The Release 2 generic
`registry_login_failed` code is removed rather than retained as an ambiguous
fallback.

## Synchronous build and run results

`POST /build` and `POST /run` complete within their request lifetimes and
return no Operation identity, status URL, log cursor, or cancellation URL.
Both use the shared combined bounded-output contract.

A successful build returns HTTP `200`:

```json
{
  "ok": true,
  "output": "...",
  "truncated": false,
  "duration": "12.438s"
}
```

A build reached by Docker Engine but rejected by the build mechanism returns
HTTP `422`:

```json
{
  "ok": false,
  "code": "build_failed",
  "message": "image build failed",
  "output": "...",
  "truncated": false,
  "duration": "12.438s"
}
```

The message is sanitized and stable; raw BuildKit, Docker, registry, and
operating-system errors are not copied into it. Captured diagnostic output is
available only in the bounded `output` field.

A one-shot workload that exits zero returns HTTP `200`:

```json
{
  "ok": true,
  "output": "...",
  "truncated": false,
  "duration": "1.243s",
  "exit_code": 0
}
```

A one-shot workload that starts and exits non-zero also returns HTTP `200`:

```json
{
  "ok": false,
  "code": "container_exit_nonzero",
  "output": "...",
  "truncated": false,
  "duration": "1.243s",
  "exit_code": 2
}
```

This workload outcome deliberately has no `message`: `code` and the exact
`exit_code` carry the machine result, while any workload explanation belongs
to `output`. Build results do not repeat the requested image reference, and
run results do not expose a transient BackendContainerID.

## Managed Container lifecycle surface

Lifecycle Commands use the following routes:

```text
POST   /containers/{container}/start
POST   /containers/{container}/stop
POST   /containers/{container}/restart
POST   /containers/{container}/repair
DELETE /containers/{container}
```

`{container}` is either a ManagedContainerID or a Session-local name. A local
name may be narrowed explicitly with `?session_id=dhs_...`; omission uses the
common Session-selection algorithm above. The same query parameter may be
supplied with a ManagedContainerID only as a narrowing assertion.

The four `POST` Commands have empty request bodies. A direct HTTP client may
supply `Idempotency-Key` on them under the durable Operation contract. The CLI
does not generate or expose that header.

Removal also has no request body. Its one optional Command parameter is:

```text
DELETE /containers/{container}?force=true
```

`force=true` is accepted only from an administrator, only with a
ManagedContainerID, and only for the narrow `ownership_mismatch` recovery
defined by `release-3-managed-container-lifecycle.md`. It does not change stop
signal or timeout behavior. `false` is equivalent to omission; duplicate,
empty, or non-boolean `force` values are rejected. `Idempotency-Key` is not
accepted on removal: a completed retry observes absence and returns `204 No
Content`, while an in-progress retry observes the active Operation.

The corresponding CLI Commands are:

```text
docker-helper container start [--session SESSION_ID] [--detach] NAME_OR_ID
docker-helper container stop [--session SESSION_ID] [--detach] NAME_OR_ID
docker-helper container restart [--session SESSION_ID] [--detach] NAME_OR_ID
docker-helper container repair [--session SESSION_ID] [--detach] NAME_OR_ID
docker-helper container remove [--session SESSION_ID] [--detach] [--force] NAME_OR_ID
```

The CLI waits for an accepted Operation by default. `--detach` returns after
admission and prints the Operation identity; it has no effect on a synchronous
no-op response. Callers cannot select a stop signal, stop timeout, immediate
kill mode, or other Docker lifecycle option. `--force` has exactly the same
administrator-only meaning as the HTTP query parameter.

## Container logs surface

One bounded log snapshot uses:

```text
GET /containers/{container}/logs?tail=200&session_id=dhs_...
```

`{container}` and optional `session_id` follow the common target-resolution
rules above. `tail` is optional, defaults to `200`, and accepts one integer in
`1..10000`. Duplicate, empty, non-integer, zero, negative, and out-of-range
values return `400 invalid_tail`.

A successful Query returns the direct result:

```json
{
  "output": "...",
  "truncated": false
}
```

`output` is the combined Docker-delivery-order snapshot and may be empty.
`truncated` reports the server byte limit defined in
`release-3-logs-and-exec.md`. Release 3 exposes no follow, timestamps, stream
selection, cursor, or pagination parameters.

The CLI command is:

```text
docker-helper container logs [--session SESSION_ID] [--tail N] [--json] NAME_OR_ID
```

Human mode writes `output` unchanged to stdout. When `truncated` is true, it
also writes one concise warning to stderr after the payload. It emits no
placeholder for empty output. JSON mode prints the two-field server result and
does not replace it with a raw string.

## Container orphan administration

Container orphans are administrator-only live diagnostic resources, not
Managed Containers. Their routes are therefore separate from `/containers`:

```text
GET    /container-orphans
GET    /container-orphans/{backend_container_id}
DELETE /container-orphans/{backend_container_id}
```

An orphan representation contains only the complete valid helper ownership
metadata and the normalized current runtime observation:

```json
{
  "backend_container_id": "...",
  "managed_container_id": "dhmc_...",
  "session_id": "dhs_...",
  "name": "postgres",
  "runtime_state": "running"
}
```

It exposes no image, command, environment, mounts, raw labels, Docker inspect
payload, or other backend configuration. `backend_container_id` is public only
on this administrator-only surface because no persistent helper identity
exists with which to target the object.

The collection uses the common `limit` and opaque `cursor` parameters,
default `100`, maximum `1000`, and the direct envelope:

```json
{
  "orphans": [],
  "next_cursor": "..."
}
```

`next_cursor` is omitted on the last page. Ordering is by
`backend_container_id`; the Query does not claim snapshot isolation across
pages while Docker objects are changing.

Removal accepts no body, force option, or idempotency key. It verifies the
complete helper ownership labels and absence of a matching SQL record again,
uses the common graceful stop timeout when the orphan is running, removes that
exact backend object, confirms absence, and returns `204 No Content`. An object
that has already disappeared also returns `204`. An object that exists but is
not a verified orphan returns `404 container_orphan_not_found` and is never
modified.

The CLI forms are:

```text
docker-helper container orphan list [--limit N] [--cursor CURSOR] [--json]
docker-helper container orphan show BACKEND_CONTAINER_ID [--json]
docker-helper container orphan remove BACKEND_CONTAINER_ID
```

Without `--limit`, CLI list follows pages to exhaustion. With `--limit`, it
returns at most that many total items. Only an administrator may use these
Commands and Queries; every other valid authority receives `403 forbidden`.

## Session network repair surface

Session lookup uses:

```text
GET /sessions/{session_id}
docker-helper session show --id SESSION_ID [--json]
```

The Query returns one direct Session management projection:

```json
{
  "id": "dhs_...",
  "state": "active",
  "principal": "alice",
  "launcher_id": "dhl_...",
  "launcher": "default",
  "workspace": "/srv/workspaces/project",
  "created_at": "2026-09-03T18:00:00Z",
  "expires_at": "2026-09-03T22:00:00Z"
}
```

Public Session states are `active`, `closing`, `cleanup_failed`, and `closed`.
The following fields appear only when applicable:

- `condition`: `network_missing` or `network_name_conflict`;
- `active_operation_id`: current Session repair or cleanup Operation;
- `last_cleanup_operation_id`: most recent terminal cleanup attempt, including
  the result retained by a `closed` tombstone;
- `cleanup_retry_at`: next automatic cleanup-attempt time while a `closing`
  Session waits after a transient failure.

The Session representation does not duplicate a cleanup Operation's error or
cancellation payload. An authorized caller follows the public Operation ID for
that detail. Resource-ceiling and publishing-grant projections extend this
same object below; they are not separate Session resources.

The Session, Launcher, and Principal show projections use one resource-policy
shape:

```json
{
  "resource_ceiling": {
    "cpu": {
      "mode": "inherit",
      "effective": 4.0
    },
    "memory_bytes": {
      "mode": "explicit",
      "value": 2147483648,
      "effective": 2147483648
    },
    "pids": {
      "mode": "inherit",
      "effective": 512
    }
  }
}
```

Each dimension has `mode: inherit` or `mode: explicit`. `value` appears only
for an explicit stored ceiling; `effective` is always present and reflects the
complete current ancestor constraint. Root values are always explicit because
initialization materializes its defaults. Units and numeric validation match
workload limits. The projection exposes no inherited-from path, current usage,
remaining capacity, reservation, pressure, or OOM history.

Resource-ceiling policy is replaced atomically through one owner-specific
subresource:

```text
PUT /principals/{username}/resource-ceiling
PUT /principals/{username}/launchers/{launcher}/resource-ceiling
PUT /sessions/{session_id}/resource-ceiling
```

The request is a complete replacement:

```json
{
  "cpu": 2.0,
  "memory_bytes": 2147483648,
  "pids": 256
}
```

Every omitted dimension becomes inherited. An empty object resets all three
dimensions to inheritance. Supplied values use the canonical CPU, byte, and
PID units; unknown fields are rejected. A successful HTTP `200` returns the
updated `resource_ceiling` subresource in its configured/effective show shape.

The CLI forms are:

```text
docker-helper principal resource-ceiling set USERNAME [--cpus N] [--memory SIZE] [--pids-limit N]
docker-helper launcher resource-ceiling set [NAME_OR_ID] [--principal USERNAME] [--cpus N] [--memory SIZE] [--pids-limit N]
docker-helper session resource-ceiling set SESSION_ID [--cpus N] [--memory SIZE] [--pids-limit N]
```

The command always sends one complete replacement. Absence of a flag means
inheritance, not preservation of the stored dimension. CLI never performs a
hidden GET, local merge, and PUT.

The same show projections use one publishing-policy shape. Inheritance is:

```json
{
  "publishing_grant": {
    "mode": "inherit",
    "effective": {
      "start": 20000,
      "end": 29999
    }
  }
}
```

An explicitly narrowed range adds its configured value:

```json
{
  "publishing_grant": {
    "mode": "explicit",
    "value": {
      "start": 24000,
      "end": 24999
    },
    "effective": {
      "start": 24000,
      "end": 24999
    }
  }
}
```

Disabled publishing is represented without a fictitious range:

```json
{
  "publishing_grant": {
    "mode": "disabled"
  }
}
```

`mode` is `inherit`, `explicit`, or `disabled`. `value` appears only for an
explicit configured range; `effective` appears whenever publishing is
permitted and is omitted when disabled. Root permits only `explicit` or
`disabled`. The projection never contains free-port, occupied-port, lease, or
remaining-capacity lists.

Publishing grants are replaced atomically through:

```text
PUT /principals/{username}/publishing-grant
PUT /principals/{username}/launchers/{launcher}/publishing-grant
PUT /sessions/{session_id}/publishing-grant
```

The complete request is exactly one of:

```json
{"mode":"inherit"}
```

```json
{"mode":"disabled"}
```

```json
{
  "mode": "explicit",
  "value": {
    "start": 24000,
    "end": 24999
  }
}
```

`value` is required only for `explicit` and forbidden for the other modes.
Unknown fields, reversed ranges, ports outside `1..65535`, and values outside
the effective parent grant are rejected. A successful HTTP `200` returns the
updated configured/effective `publishing_grant` subresource.

The CLI forms are:

```text
docker-helper principal publishing-grant set USERNAME (--inherit | --disable | --range START-END)
docker-helper launcher publishing-grant set [NAME_OR_ID] [--principal USERNAME] (--inherit | --disable | --range START-END)
docker-helper session publishing-grant set SESSION_ID (--inherit | --disable | --range START-END)
```

Exactly one mode flag is required. The optional Launcher target follows the
common `default` rule above. Every command sends one complete replacement and
never performs hidden read-modify-write.

Foreign and nonexistent Sessions return the same
`404 session_not_found`. A Session bearer becomes invalid when cleanup claims
its Session, so a `closing`, `cleanup_failed`, or `closed` Session is observed
through an owning Launcher, owning Principal, or administrator credential.

### Explicit repair

Explicit Session Network recovery uses:

```text
POST /sessions/{session_id}/repair
```

The request body is empty. The target Session is always explicit; this rare
recovery Command does not use Session inference. An authorized Session bearer,
owning Launcher, owning Principal, or administrator may invoke it within token
scope. A direct HTTP client may supply `Idempotency-Key` under the durable
Operation contract.

When the Session Network is already valid, or has not been provisioned and no
Managed Containers exist, repair is a synchronous no-op:

```json
{
  "ok": true
}
```

It returns HTTP `200` and creates no Operation or idempotency record. When the
missing-network invariant requires repair, the Command returns HTTP `202` with
the direct Operation representation and its `Location` header.

The CLI form is:

```text
docker-helper session repair --id SESSION_ID [--detach]
```

`--id` is required. CLI waits for an accepted Operation by default;
`--detach` returns after admission. User-facing network warnings and
troubleshooting include the Session ID so recovery never depends on guessing a
target.

## Operation read surface

Durable Operations have two read-only HTTP routes:

```text
GET /operations
GET /operations/{operation_id}
```

The list route is bounded and applies the authenticating token's ownership
scope before any caller-supplied filter. Status, Operation type, and public
target filters may only narrow that scope. Its common ownership filters and
cursor behavior follow the Release 3 list contract finalized below.

The CLI exposes:

```text
docker-helper operation show OPERATION_ID
docker-helper operation list [filters]
docker-helper operation wait OPERATION_ID [--timeout DURATION]
```

`show` performs one lookup. `list` performs the bounded list Query. `wait`
polls the lookup route until the Operation reaches a terminal status. Its
optional timeout stops only local waiting; it never cancels the Operation.
There is no server-side wait route.

Release 3 exposes no `operation cancel`, `operation logs`, or
`operation remove` command or route. Operations are working state owned and
retained by their Session, not independently managed resources.

### Operation representation

Operation lookup and accepted asynchronous Commands return the Operation
resource directly, without an `ok` flag or an `operation` wrapper:

```json
{
  "id": "op_...",
  "type": "container.start",
  "session_id": "dhs_...",
  "target": {
    "type": "container",
    "id": "dhmc_..."
  },
  "status": "running",
  "created_at": "2026-09-03T18:20:00Z",
  "started_at": "2026-09-03T18:20:01Z"
}
```

The public fields are:

| Field | Presence | Meaning |
| --- | --- | --- |
| `id` | always | Public Operation ID. |
| `type` | always | Stable Operation type. |
| `session_id` | always | Owning Session. |
| `target` | always | Public target `type` and `id`. |
| `status` | always | `pending`, `running`, `succeeded`, `failed`, or `canceled`. |
| `created_at` | always | Durable admission time. |
| `started_at` | after execution starts | First transition to `running`. |
| `completed_at` | terminal only | Transition to the immutable terminal status. |
| `result` | successful types that define one | Type-specific non-secret outcome. |
| `error` | `failed` only | Stable `code`, sanitized `message`, and optional structured details. |
| `cancellation` | `canceled` only | Stable `reason` and optional structured details. |

`result`, `error`, and `cancellation` are mutually exclusive. Missing
state-dependent fields are omitted rather than serialized as `null`.
Initiator identity, origin request correlation, backend IDs, credentials, and
workload output are never part of this representation.

`operation_id` is used only when another public object or error refers to an
Operation, including `active_operation_id`. The Operation resource itself uses
the ordinary `id` field.

An asynchronous Command returns HTTP `202 Accepted`, this same representation,
and `Location: /operations/{id}`. The list response is:

```json
{
  "operations": [],
  "next_cursor": null
}
```

### Operation listing

`GET /operations` accepts ownership filters `principal`, `launcher_id`, and
`session_id`, plus `status`, Operation `type`, and `target_id`. All supplied
filters are combined with AND after applying the authenticating credential's
maximum visibility scope. A foreign, nonexistent, or mismatched ownership
chain produces an empty list rather than a disclosing lookup error.

The Query also accepts `limit` and `cursor`:

- default HTTP `limit` is 100 and the maximum is 1000;
- ordering is descending `created_at`, with Operation `id` as the stable
  tie-breaker;
- `cursor` is opaque and denotes the position after the last returned item;
- `next_cursor` is present only when another page exists;
- no total count, offset, or numeric page is returned.

The corresponding CLI filters are `--principal`, `--launcher`, `--session`,
`--status`, `--type`, and `--target`. The CLI uses `CURSOR`, never `TOKEN`, as
the pagination argument placeholder. Without `--limit`, it follows all pages;
`--limit N` caps the total emitted items rather than one HTTP page.
`--cursor` selects the starting position. JSON mode preserves the
`operations` and `next_cursor` envelope; tabular output reports a remaining
cursor separately on stderr.

There is no separate `target_type` filter. The public target ID identifies its
resource kind, while Operation `type` provides the useful operation-class
filter.

## Public Principal identity

Principal has no public resource ID in Release 2.1 or Release 3. Its public
identity is the OS username in the `principal` field and `--principal`
selector. The SQLite integer `principal_id` remains an internal foreign key and
never appears in public resources, filters, examples, or CLI arguments.

## HTTP error envelope

Ordinary HTTP failures retain the existing flat envelope and may add one
code-defined `details` object:

```json
{
  "ok": false,
  "code": "operation_in_progress",
  "message": "another lifecycle operation is active",
  "details": {
    "operation_id": "op_..."
  }
}
```

`code` is the stable machine-readable contract. `message` is a concise
sanitized human explanation and must not be parsed for control flow. Each
error code defines the complete allowlist and types of its optional `details`
fields; handlers must not copy arbitrary backend data into the object.

Public errors and details never contain bearer material, registry credentials,
environment values, workload output, argv, host paths, BackendContainerID,
Docker exec IDs, or raw Engine, OCI runtime, or operating-system error text.
The request correlation ID remains in the existing `X-Request-ID` response
header and is not duplicated in JSON.

An ordinary request failure uses its corresponding non-success HTTP status.
Two successful read/execution mechanisms deliberately differ:

- a started synchronous process that exits non-zero returns HTTP `200` with
  the process-result envelope, `ok: false`, `code: container_exit_nonzero`,
  combined bounded `output`, and its trustworthy `exit_code`;
- lookup of a terminal failed or canceled Operation returns HTTP `200` with
  the Operation resource and its nested `error` or `cancellation` outcome.

Neither is converted into a generic transport error merely because the
workload or durable Operation outcome was unsuccessful.

### Docker Engine failures

Docker remains the deliberate runtime backend and part of the product's
purpose. Public failures are nevertheless normalized at the docker-helper
boundary so clients never depend on an Engine call sequence or raw backend
error wording:

| HTTP / code | Meaning |
| --- | --- |
| `502 backend_failure` | Docker Engine was reachable, but an unexpected interaction failure prevented a trustworthy result. |
| `503 backend_unavailable` | Docker Engine could not be reached or could not provide the required observation. |

Expected capability outcomes retain their specific codes, including
`build_failed`, `exec_start_failed`, `host_port_unavailable`, and persistent
integrity conditions. Release 3 introduces no public `docker_*` error codes.

This normalization is not a promise of interchangeable container backends.
It prevents transport mechanics and backend message strings from becoming a
second public API.

### Authentication, authority, and existence

| HTTP / code | Meaning |
| --- | --- |
| `401 unauthorized` | The bearer is absent, malformed, unknown, revoked, expired, or no longer valid because its owning authority is disabled. |
| `403 forbidden` | The bearer is valid, but its authority type cannot perform the requested capability. |
| `404 container_not_found` | The requested Managed Container is absent or outside the caller's token scope. |
| `404 operation_not_found` | The requested Operation is absent or outside the caller's token scope. |
| `404 session_not_found` | The requested Session is absent or outside the caller's token scope. |

Absent and out-of-scope resources produce the same status, code, message, and
details. Resource-specific not-found codes do not disclose additional
information because the route already identifies the requested resource kind.
A foreign or nonexistent selector on a list Query returns HTTP `200` with an
empty list rather than a lookup error.

Administrator authority may perform every Release 3 management capability.
Administrator-only capabilities return `403 forbidden` to another otherwise
valid authority; they do not reinterpret a valid Principal credential,
Launcher credential, or Session token as unauthenticated.

Session data-plane capabilities (`pull`, `build`, `run`, `registry login`,
and both exec modes) are the complement: they admit only a Session bearer.
A valid Principal or Launcher credential presented directly to a Session
data-plane endpoint is rejected with the endpoint's non-disclosing
unauthorized response and is never converted into Session execution
authority by inference; the bearer's own validity is never disclosed there.

### Active Operation conflict reference

`409 operation_in_progress` includes only the conflicting public Operation
reference:

```json
{
  "ok": false,
  "code": "operation_in_progress",
  "message": "another lifecycle operation is active",
  "details": {
    "operation_id": "op_..."
  }
}
```

`active_operation_id` remains the field used by a Managed Container
representation. It is not duplicated under that name in an error envelope.
