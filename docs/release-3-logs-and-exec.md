# Release 3 Container Logs and Exec

## Purpose

This document defines the Release 3 contracts for bounded Managed Container
log retrieval and command execution inside a Managed Container.

Container logs are a Query over Docker-owned runtime data. Exec is a Command
that starts a new process inside an existing Managed Container. They share
bounded-output mechanics but remain distinct capabilities with separate
authorization, lifecycle, and failure semantics.

This revision freezes the D4 Container Logs and D5 common Exec contracts as
implementation inputs. Interactive transport remains owned by
`release-3-interactive-streaming.md`.

Exact Go types, SQL DDL, and Moby adapter calls are implementation decisions
for the operational architect. Public JSON fields, routes, and CLI spelling
are canonical in `release-3-api-cli.md` and must preserve the authorization,
output, and failure contracts defined here.

## Container Logs boundary

Release 3 provides one bounded snapshot of logs belonging to one Managed
Container. It does not expose a general Docker logging interface.

The public Query is:

```text
GET /containers/{container}/logs?tail=200
```

It supports only:

- a ManagedContainerID or Session-local name resolved through the common
  container-selector contract;
- one `tail` line-count option;
- combined output in Docker delivery order;
- a bounded JSON response;
- runtime data available through the connected Docker Engine.

It does not support:

- `follow` or another streaming mode;
- `since`, `until`, or timestamp filtering;
- separate stdout and stderr results;
- cursor, offset, or incremental replay;
- a persistent helper-owned log, index, cache, or retention policy;
- direct Docker identifiers or caller-selected Docker logging options.

Interactive exec streaming does not extend this Query. Adding WebSocket
transport for exec is not permission to add container-log following.

## Authorization and target resolution

Log access uses the same token-scope and ownership rules as `container show`.
An administrator may read every Managed Container visible to the daemon. A
Principal, Launcher, or Session bearer may read only a container inside its
existing scope.

Resolution starts from SQLite:

1. authenticate the caller;
2. resolve the ManagedContainerID inside caller scope;
3. resolve the owning Session and require it to remain usable for the Query;
4. resolve the exact recorded BackendContainerID;
5. observe Docker and verify the complete immutable ownership metadata;
6. only then request logs from Docker Engine.

No persistent record, a foreign record, and a syntactically valid identifier
outside caller scope produce the same non-disclosing `404 Not Found`. Docker
objects with matching names or labels are not alternative targets. The orphan
administration surface does not provide log access.

The Query creates no Operation, lease, or durable application record and never
changes Managed Container state.

## Tail contract

`tail` is the maximum number of newest Docker log records requested before the
byte limit is applied.

- omitted `tail` selects `200`;
- accepted values are integers in `1..10000`;
- zero, negative values, non-integers, duplicate query parameters, and values
  above `10000` are rejected as invalid input;
- Release 3 has no value meaning "all logs".

The helper passes the normalized line limit to its Docker Engine adapter. It
does not fetch the complete history and implement line selection locally.
Docker owns record boundaries and the history still available from its logging
backend.

The line limit is not a byte guarantee. One or several unusually large records
may still exceed the response byte limit and be truncated.

## Output contract

The successful direct JSON result contains:

- one combined `output` string;
- one `truncated` boolean.

It must not split the result into stdout and stderr fields or wrap it in an
`ok` result envelope.

For a non-TTY container, the Engine's multiplexed stdout and stderr frames are
decoded by the backend adapter and appended to the same bounded sink in the
order delivered by Docker. For a TTY container, the Engine's combined stream
is consumed directly. Raw Docker multiplexing headers never enter the public
result.

docker-helper does not claim to reconstruct an ordering more precise than the
one supplied by Docker Engine. It does not sort lines by timestamp or infer a
source stream after combination.

Empty logs are a normal successful result with an empty `output` and
`truncated: false`.

## Byte limit and truncation

`container_log_max_bytes` is a reloadable server setting with a default of
1 MiB. It is distinct from `command_output_max_bytes`: retrieving retained
container logs and returning live Command output have different operational
costs and are tuned independently.

The limit applies to decoded combined payload bytes, excluding Docker framing
and the JSON envelope. Data is consumed through a bounded sink; docker-helper
never buffers the complete Engine response before truncating it.

When the selected Docker records exceed the byte limit:

- the newest bytes are retained;
- `truncated` is `true`;
- the Query still succeeds;
- no continuation cursor or hidden server-side remainder is created.

The result may therefore begin in the middle of a log record. This is explicit
bounded-tail behavior, not evidence that older bytes remain available through
docker-helper.

The effective byte limit is captured once at Query admission. A concurrent
configuration reload affects later requests, not a response already being
read.

## Runtime-state behavior

Log retrieval does not require a running process. Once ownership is verified:

| Observed state or Condition | Result |
| --- | --- |
| `created` / never started | `200 OK` with empty output when Docker has no records. |
| `running` | `200 OK` with the current bounded snapshot. |
| `stopped` | `200 OK` with retained Docker logs. |
| `paused` | `200 OK` with the current bounded snapshot; pause is only an observed state. |
| `dead` | Attempt the bounded snapshot; dead workload state alone does not erase readable logs. |
| `policy_mismatch` | Allow the Query when immutable ownership is still proven. |
| `backend_missing` | `409 backend_missing`; no cached output is substituted. |
| `backend_unavailable` | `503 backend_unavailable`; no cached output is substituted. |
| `ownership_mismatch` | Reject ordinary log access; an unverified backend is not an authorized output source. |

A concurrent explicit removal may complete after ownership verification. If
Docker then reports the object absent before log retrieval begins, the Query
returns `409 backend_missing`. If Docker has already returned a bounded
snapshot before removal commits, returning that snapshot is valid: Queries do
not lock a container against an authorized lifecycle mutation.

## Docker logging backend

docker-helper reads logs through Docker Engine and does not select or override
the daemon's logging driver for a Managed Container. Log persistence, rotation,
and history availability remain Docker administrator policy.

If the configured Docker logging backend cannot serve the logs API,
docker-helper returns `409 logs_unavailable`. It does not create a second local
copy, switch logging drivers, or silently redirect workload output to its own
stdout or stderr.

This does not override an administrator's Docker configuration. If the trusted
Docker daemon itself is configured to deliver container logs to journald or
another backend, that is Docker-owned host policy. Release 3 only forbids
docker-helper from copying workload output into its operational or audit logs.

## Failure taxonomy

The stable Container Logs results are:

| HTTP / code | Meaning |
| --- | --- |
| `200` | A bounded snapshot was returned, including a valid empty snapshot. |
| `400 invalid_tail` | The `tail` query is absent from the accepted numeric contract. |
| `404` | No Managed Container is visible under the supplied public identity and caller scope. |
| `409 backend_missing` | The persistent Managed Container exists but its backend object is absent. |
| `409 ownership_mismatch` | The backend object cannot be proven to belong to the persistent Managed Container. |
| `409 logs_unavailable` | The verified backend exists, but its Docker logging backend cannot serve retained logs. |
| `503 backend_unavailable` | Docker Engine cannot provide a trustworthy response. |

Unexpected Engine stream corruption or adapter failure is an internal backend
error. A partial snapshot is not returned as success unless the only loss is
the deliberate byte-limit truncation represented by `truncated: true`.

Error classification must use typed Engine responses where available. It must
not infer `backend_missing`, `logs_unavailable`, or authorization state from
arbitrary human-readable Docker error strings when a stable typed signal
exists.

## Audit and operational logging

Every admitted log Query produces a bounded audit result containing public
ownership identities, initiator, requested `tail`, returned payload byte count,
`truncated`, normalized outcome, and request correlation. Rejections follow the
common non-disclosure rules.

Audit and operational logs never contain:

- the returned workload output;
- Docker stream frames;
- the BackendContainerID;
- environment values, credentials, or request authorization;
- a copied Docker error payload that may contain workload data.

Repeated reads are independent Queries. docker-helper does not retain a read
cursor or a record that a particular byte range was consumed.

## CLI behavior

The exact CLI form is:

```text
docker-helper container logs [--session SESSION_ID] [--tail N] [--json] NAME_OR_ID
```

The CLI requests one snapshot and writes combined `output` to its stdout. An
empty result writes no placeholder text. If `truncated` is true, the CLI emits
one concise warning to stderr after the output; it does not retry with a larger
limit or paginate automatically. JSON mode prints the exact two-field direct
result.

Human and JSON modes use the same server Query. The CLI does not invoke
`docker logs`, resolve BackendContainerID, combine streams, or apply its own
tail and byte limits.

Target inference and explicit `--session` narrowing are owned by
`release-3-api-cli.md`.

## Troubleshooting contract

User-facing documentation, CLI help, and the manual include these paths:

| Observation | Supported action |
| --- | --- |
| Empty output | The container has produced no retained Docker logs; this is not an error. |
| `truncated: true` | Request fewer lines or ask the operator to raise `container_log_max_bytes`; no continuation exists. |
| `backend_missing` | Remove the stale Managed Container record through the supported container lifecycle. |
| `backend_unavailable` | Restore Docker Engine availability or helper access, then retry. |
| `ownership_mismatch` | Administrator inspects the exact recorded backend; ordinary callers cannot read it. |
| `logs_unavailable` | Administrator checks the Docker logging-driver policy; docker-helper does not replace it. |

Troubleshooting may direct an administrator to Docker's own diagnostics. It
must not instruct a caller to use BackendContainerID as docker-helper authority,
edit SQLite, or enable helper-side workload logging.

## Verification requirements

D4 implementation is not complete without tests for:

- authentication and Administrator, Principal, Launcher, and Session scope;
- identical `404` behavior for absent and out-of-scope ManagedContainerIDs;
- default, minimum, maximum, malformed, duplicate, and excessive `tail`;
- no "all" or implicit unbounded form;
- combined non-TTY stdout/stderr in Engine delivery order without Docker frame
  headers;
- TTY log decoding;
- empty, running, stopped, paused, and dead results;
- `policy_mismatch` read access after ownership proof;
- `backend_missing`, `backend_unavailable`, `ownership_mismatch`, and
  `logs_unavailable` classification;
- exact 1 MiB default, newest-tail truncation, and `truncated` behavior;
- bounded streaming without whole-response accumulation;
- configuration reload affecting later but not active Queries;
- remove/read races without stale helper-owned cache behavior;
- CLI stdout and truncation-warning stderr behavior;
- audit fields and unique-marker proof that workload output never enters audit
  or operational logs;
- absence of follow, cursor, timestamp filtering, separate streams, and direct
  Docker identifiers from the public surface;
- help, manual, architecture, and packaged `SKILL.md` consistency.

Real-Docker integration tests must cover readable logs for both TTY and non-TTY
Managed Containers, a supported Docker logging backend, an unreadable logging
backend where the test environment can provide one, lifecycle states, and the
byte boundary. Unit-only stream fixtures cannot establish the Engine framing
and logging-driver contracts.

## Accepted Exec boundary

The following D5 decisions are fixed:

- non-interactive exec is a synchronous Command with combined bounded output,
  exit code, and no Operation;
- interactive exec uses the same authorization and execution core through the
  separate WebSocket transport;
- exec inherits the Managed Container's configured user;
- Release 3 exposes no exec user override, privileged mode, or additional
  Linux capabilities;
- workload output never enters docker-helper operational logs, journald, or
  audit;
- active exec instances are transient daemon state and never block stop,
  restart, remove, or Session cleanup;
- exec has no recovery, reconnect, or output replay contract.

## Exec request boundary

Both exec modes address one Managed Container by ManagedContainerID and start
one process from the public `argv` array defined in
`release-3-api-cli.md`. Its first element names the executable and must be
non-empty; later elements are individual arguments and may be empty.
docker-helper never joins argv into a shell command, interprets shell syntax,
or inserts `/bin/sh -c`.

The common request may additionally contain:

- a map of process-local environment entries;
- an absolute container-local working directory.

Environment names use the same validation and deterministic normalization as
one-shot `run`. Values are supplied only to the new exec process. They do not
mutate the Managed Container specification, persistent state, later execs, or
the container's initial process environment. Environment values never enter
audit, operational logs, or public error details.

The working directory is interpreted inside the container. It must be an
absolute cleaned path, but docker-helper does not resolve it against the host
workspace or expose a host-path fallback. Docker Engine reports a missing or
inaccessible container path when the process is started.

Release 3 exec does not accept:

- stdin for non-interactive exec;
- a shell command string or entrypoint override;
- user, group, privilege, capability, security-option, or namespace override;
- mounts, published ports, resource-limit changes, or other container mutation.

Non-interactive exec starts with stdin closed, so a command reading it receives
EOF instead of waiting indefinitely. Pipe input is a possible post-Release-3
feature and is not assigned to a specific future release. Callers use a
workspace file or interactive exec when input is required.

## Exec lifetime and disconnect

Release 3 exposes no caller-selected or server-default exec timeout. A
non-interactive exec request normally remains open until the process exits and
returns one terminal result. Its lifetime is still bounded by the owning
Managed Container and Session; exec never creates or extends an independent
lease.

Docker Engine provides exec create, start, attach, inspect, and resize, but no
exec-process kill operation. Closing an Engine attachment or canceling its
client context is not proof that the process stopped. docker-helper therefore
does not report successful cancellation merely because the HTTP request or
backend stream ended.

If the caller disconnects before completion:

1. docker-helper closes the client and Engine attachments;
2. the caller receives no terminal result and cannot reconnect or replay
   output;
3. the exec process may continue inside the container;
4. the daemon keeps the transient exec slot while it can still observe that
   process and releases the slot after observed exit;
5. loss of daemon memory does not create a durable exec record or recovery
   scan.

The CLI exits on local interruption and writes one concise stderr warning that
the command may still be running. It does not claim remote cancellation and
does not retry the request.

An accepted container stop, restart, remove, or Session cleanup closes new exec
admission and terminates active exec processes through the container lifecycle.
Exec never delays or vetoes that lifecycle action. Session expiration provides
no separate exec grace period.

Daemon shutdown closes exec admission and active attachments. It does not keep
the daemon alive indefinitely waiting for exec processes and does not write a
terminal result after the client is gone. Any process left in a still-running
container remains bounded by later container or Session teardown.

This limitation is explicit in CLI help and troubleshooting. Release 3 does
not signal a host PID, inject a process supervisor into the container, add an
exec-kill endpoint, or turn exec into a durable Operation to approximate a
stronger guarantee.

## Exec admission and container state

Exec is admitted only while all of the following remain true under the common
per-container admission boundary:

- the caller presents a Session bearer for the owning Session; exec is a
  Session data-plane capability, so a Principal or Launcher credential is
  rejected and is never converted into Session execution authority by
  inference;
- the Session remains `active`;
- the persistent Managed Container is fully `managed`;
- Docker Engine is reachable and the exact backend object's immutable
  ownership and helper-owned policy are verified;
- the observed runtime state is `running`;
- no helper lifecycle Operation is active or being admitted;
- every applicable exec-concurrency slot can be acquired.

docker-helper never starts or resumes a Managed Container implicitly to satisfy
exec.

| Observed state or Condition | Exec result |
| --- | --- |
| `running` | Admit subject to authorization and concurrency ceilings. |
| `created` or `stopped` | `409 container_not_running`. |
| `paused` | `409 container_paused`; `container start` is the explicit resume path. |
| helper lifecycle Operation active | `409 operation_in_progress` with its public Operation ID. |
| backend `transitioning` without a helper Operation | `409 backend_transition_in_progress`. |
| `dead` | `409 container_dead`. |
| `backend_missing` | `409 backend_missing`. |
| `backend_unavailable` | `503 backend_unavailable`. |
| `policy_mismatch` | `409 policy_mismatch`; exec does not run against unverified effective policy. |
| `ownership_mismatch` | `409 ownership_mismatch`; an unverified backend is never an exec target. |

Admission and lifecycle mutation share one ordering boundary:

- if stop, restart, remove, or Session cleanup closes admission first, the new
  exec is rejected and is never queued;
- if exec admission completes first, the lifecycle Command does not return a
  busy conflict or wait for that exec to finish;
- the lifecycle owner closes further admission and stops the active process as
  part of the full container stop or removal path;
- start must complete and clear its lifecycle Operation before exec may be
  admitted.

An exec instance owns only its transient concurrency slots and Engine
attachment. It does not set `active_operation_id`, change management state, or
become a lifecycle conflict visible as a durable Operation.

## Non-interactive exec result

Non-interactive exec is one synchronous HTTP Command. It does not stream a
partial public response and does not return an exec identifier. After the
process starts, the request waits for the Engine to report its terminal state
and returns the existing flat process-result envelope:

```json
{
  "ok": true,
  "output": "...",
  "truncated": false,
  "duration": "1.243s",
  "exit_code": 0
}
```

The result is not nested under a separate `result` object. Combined output is
returned as one string; stdout and stderr fields do not exist.

A process exit is a successfully completed exec mechanism even when the
workload reports failure. Therefore:

- exit code zero returns HTTP `200` with `ok: true`;
- a non-zero exit returns HTTP `200` with `ok: false`,
  `code: container_exit_nonzero`, and the actual `exit_code`;
- the bounded `output`, `truncated`, and `duration` fields are present for both
  outcomes.

A rejected process start is normalized from Engine state, not from error text:

- if Docker created the exec instance and `ExecInspect` provides a trustworthy
  terminal exit code, docker-helper returns the ordinary HTTP `200` process
  result, including Engine-provided exit codes such as `126` or `127`;
- if Docker rejects the start before a trustworthy terminal exec result exists,
  docker-helper returns HTTP `422` with `code: exec_start_failed` and no
  `exit_code`;
- docker-helper never assigns `126` or `127` itself and never matches Docker,
  OCI runtime, or operating-system error strings to infer whether an executable
  or working directory exists.

The public `exec_start_failed` message is sanitized and stable. Backend detail
may be included only through the common non-secret diagnostic field defined by
the API contract; it does not expose BackendContainerID, exec ID, or host
paths.

This distinction lets an HTTP client separate a command's own exit result from
failure to authenticate, authorize, validate, reach Docker, create the exec,
start it, or obtain a trustworthy terminal observation. Those mechanism and
dependency failures retain their normal non-success HTTP statuses and do not
invent a workload exit code.

Unexpected Engine interaction uses `502 backend_failure`;
Engine unavailability uses `503 backend_unavailable`. The integrated public
contract does not collapse either case into `container_exit_nonzero`.

If the process started but its attachment fails before a trustworthy terminal
observation, docker-helper returns a mechanism failure. It may include already
captured bounded output when the response format permits, but never reports
that partial capture as a successful or complete workload result.

## Exec output limit

Non-interactive exec uses the common reloadable
`command_output_max_bytes` setting. Its default is 4 MiB. The value is captured
once at admission and shared with synchronous pull, build, and one-shot `run`;
exec does not introduce a second configuration field.

The Engine's non-TTY stdout and stderr frames are decoded and appended to one
bounded sink in delivery order. When payload exceeds the limit, the newest
bytes are retained and `truncated` is true. The adapter continues consuming the
Engine stream until terminal state; filling the response buffer must not block
or terminate the process.

The output exists only for the active request and response. It is not written
to SQLite, retained after response completion, exposed through an offset or
cursor API, or copied to daemon stdout, stderr, journald, or audit.

## Exec audit boundary

Exec audit records identify the initiator, Principal, Launcher, Session,
ManagedContainerID, interactive or non-interactive mode, command argument
count, sorted environment key names, normalized outcome, exit code when
available, duration, and request or stream correlation.

They never contain command argument values, environment values, workdir
contents, workload output, Engine framing, BackendContainerID, or an exec ID.
Exec IDs are transient backend correlations and never public authority.

Rejected exec requests use the same non-disclosing authorization audit rules
as container lifecycle. A caller cannot use errors or audit-visible metadata to
discover a foreign Managed Container or another subject's concurrency usage.

## Exec concurrency ceilings

Exec concurrency is bounded independently at several ownership scopes. The
Release 3 server defaults are:

| Scope | All active execs | Interactive subset |
| --- | ---: | ---: |
| Managed Container | 16 | 4 |
| Session | 32 | 16 |
| Principal | 32 | 16 |
| Daemon | 64 | 64 |

These values are reloadable server-policy defaults, not hard protocol maxima.
An administrator may raise or lower them. A deployment with greater legitimate
parallelism may therefore raise the Principal and daemon ceilings rather than
being permanently capped at 32 or 64 execs.

Configuration must remain internally coherent for each column:

```text
Managed Container <= Session <= Principal <= Daemon
```

When raising a child-scope ceiling beyond its current parent, the administrator
raises the parent first. Interactive ceilings must additionally be no greater
than the corresponding all-exec ceiling.

Interactive exec consumes one slot from both columns at every applicable
scope. Non-interactive exec consumes only the all-exec column. All required
slots are checked and acquired atomically with exec admission; partial slot
acquisition is never exposed.

When any effective ceiling is reached, admission fails immediately with HTTP
`429` and `exec_capacity_exhausted`. docker-helper does not queue the request or
wait for a slot. The response does not identify which foreign Principal,
Session, container, or exec consumes capacity and does not return
`Retry-After`, because no reliable release time exists.

Increasing a value affects later admission immediately. Decreasing a value
does not terminate active execs; it blocks new admission at that scope until
observed usage falls below the new ceiling. A slot is released only after
process exit is observed or container teardown has terminated the process.

The counters are transient daemon state. Release 3 does not persist exec
instances or reconstruct them after daemon restart merely to recover counters;
the disconnect and teardown limitations above remain explicit.

## Descendant processes

Release 3 provides no explicit detach mode for non-interactive exec. The
started program may nevertheless fork or daemonize a descendant and then exit.
docker-helper treats the tracked exec process as terminal when Docker reports
that process's exit and releases its transient exec-concurrency slots.

It does not scan the container process tree, attribute descendants to a
completed exec, or kill them merely because their parent exited. Remaining
processes stay inside the Managed Container and its Session aggregate cgroups,
including the accepted PIDs ceiling. Full container stop, restart, remove, or
Session cleanup terminates them through the ordinary container lifecycle.

Preventing daemonization would require a separate in-container process policy
or supervisor and is outside Release 3.
