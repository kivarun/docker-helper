# Release 3 D0 Execution Plan

## Status and baseline

This document fixes the D0 semantic contract and records an implementation plan against the inspected baseline for the cross-cutting Operation foundation defined by `release-3-operation-model.md`.

The inspected baseline is `main` at
`694ca5944c87b17303b761c5f38e4afd390a7d89`. Release 2.1 Launcher delegation,
Launcher-owned Session persistence, the canonical Launcher-name grammar, and
the Principal-scoped Launcher locator are implemented at this commit.

The baseline implementation invokes the Docker CLI. Release 3 uses the official `github.com/moby/moby/client` Docker Engine API client, pinned to a reviewed version, behind a docker-helper-owned adapter. The client negotiates the daemon API version, while docker-helper documents and tests a minimum supported Engine API. The CLI-specific inventory remains evidence about code that must be retired. Before production migration begins, the operational architect must freeze the narrow adapter methods needed by build, pull, one-shot run, lifecycle, logs, and exec. No executor should introduce a new long-lived `exec.Cmd` abstraction solely to reproduce the baseline mechanics or expose Moby request types outside the adapter.

The current Docker CLI reads a Session-scoped Docker configuration directory. Engine API calls do not inherit that client configuration automatically. The adapter must read the existing Session credential source just in time, pass only the matching registry authorization to image pull, and pass the Session-scoped registry authorization map required by image build. Container create and one-shot run receive no registry credentials after the image is local. Credentials never enter durable Operation data, container management projections, audit, daemon logs, or public errors.

D0 changes two mechanisms that currently share one in-memory object but have different target semantics:

1. `build` and one-shot `run` become synchronous Commands bound to their HTTP Requests;
2. durable Operation is introduced for managed-container start, stop, restart,
   remove, administrator policy repair, explicit Session network repair, and
   Session cleanup only.

The current in-memory Operation is not migrated or generalized. Its public status/log/cancel contract and record are removed. Existing cancellation, shutdown, and cleanup behavior is retained as an observable requirement, not as a requirement to preserve the Docker CLI process mechanism.

## Fixed contract

The following decisions are already binding:

- `build`, one-shot `run`, and non-interactive exec are synchronous Commands;
- `container.create` is also synchronous, returns `201 Created` with a stopped Managed Container, and creates no Operation;
- interactive exec uses WebSocket and is not an Operation;
- durable Operation types are limited to `container.start`, `container.stop`,
  `container.restart`, `container.remove`, `container.repair`,
  `session.repair`, and `session.cleanup`; container policy repair is
  administrator-only, while Session network repair follows Session credential
  scope; a state-matching start or stop returns `200 OK` as a no-op and creates
  neither an Operation nor an idempotency record;
- synchronous process execution does not survive request loss or daemon restart; after create's provisional database commit, only bounded registration or compensation continues under server ownership and restart recovery;
- the normal CLI remains blocking and returns the workload exit result;
- `pull`, `build`, one-shot `run`, and non-interactive exec return one combined bounded `output` that is not replayable;
- a started `run` or exec returns HTTP `200` with its actual `exit_code`, including a non-zero exit;
- a build that reaches the backend but fails returns HTTP `422` with bounded diagnostic output;
- invalid, denied, absent, and conflicting inputs use HTTP `400`, `403`, `404`, and `409`; backend unavailability and unexpected backend interaction use `503` and `502` respectively;
- `command_output_max_bytes` replaces `operation_log_max_bytes`, retains the 4 MiB default, newest-output tail, `truncated` flag, and reload behavior, and applies to all four synchronous Commands;
- Release 3 accepts `operation_log_max_bytes` as a deprecated alias with a startup warning, rejects configurations containing both names, and exposes only the new name through config CLI operations;
- workload output is never emitted to the daemon logger, journald, or audit stream;
- durable Operations persist no workload output or progress log;
- public build/run Operation status, log, and cancel workflows are removed;
- a daemon shutdown must still cancel live build/run execution within the existing shared shutdown deadline;
- one-shot `run` cleanup must still remove its backend container after request cancellation, client disconnect, or daemon shutdown;
- staged build contexts, pinned mounts, and MAC leases retain their current cleanup ordering and failure semantics; cidfiles are a baseline Docker CLI mechanism and need not survive the Engine API migration;
- daemon shutdown does not convert a durable running Operation into a terminal cancellation; restart recovery decides its result;
- no independent Operation retention configuration or delete API exists;
- no hidden queue defers a conflicting lifecycle Command for later execution.

Direct process results keep the existing flat response envelope. A started one-shot `run` or non-interactive exec returns HTTP `200` with `ok`, combined `output`, `truncated`, `duration`, and actual `exit_code`; a non-zero workload exit uses `ok: false` and `code: container_exit_nonzero`, but no redundant `message`, without changing the HTTP status. A backend-reported build failure returns HTTP `422` with `ok: false`, `code: build_failed`, sanitized `message`, combined `output`, `truncated`, and `duration`. Results are not nested under another object and never split stdout from stderr.

## Current implementation inventory

The current `operation` object owns five unrelated responsibilities:

| Responsibility | Current owner | D0 disposition |
| --- | --- | --- |
| Public build/run status | `operation` fields and `GET /operations/{id}` | Remove for build/run; replace later with the durable representation. |
| Client output replay | `operation.LogBuffer`, offset polling, `/logs` | Remove. Retain only a bounded direct-response buffer. |
| Public cancellation | `/operations/{id}/cancel`, `operationSupervisor.cancel` | Remove. Request/signal loss cancels synchronous work; Session cleanup owns internal durable cancellation. |
| Live execution termination | `operation.cmd`, `terminateForShutdown`, force cleanup | Re-express as request-context cancellation and bounded backend-resource cleanup outside the durable Operation store. |
| Durable execution | None | Add SQLite-backed records, one dispatcher, typed handlers, and restart recovery. |

### Production files

| File | Current responsibility | Required change |
| --- | --- | --- |
| `operation.go` | In-memory record, registry, log buffer, public cancellation, process start, shutdown termination. | Remove the public record and child-process ownership after callers migrate; retain the bounded output primitive only if the Engine API path still needs it; add durable Operation types in separate files. |
| `pull.go` and registry configuration helpers | Invoke Docker CLI with the Session configuration directory and return bounded pull output. | Execute pull through the Engine API and explicitly bridge only the matching Session registry authorization. |
| `build.go` | Validates and stages, registers Operation, starts Docker, returns `201`, completes in a goroutine. | Execute within the request lifetime, return one bounded terminal response, preserve staging/MAC cleanup, and pass Session-scoped registry authorization for private `FROM` resolution. |
| `run.go` | Validates, pins mounts, registers Operation, manages cidfile, returns `201`, completes in a goroutine. | Execute through the Engine API within the request lifetime, return one bounded terminal response, and preserve daemon-side container, pin, and MAC cleanup without retaining cidfile as target architecture. |
| `api_contract.go` | Build/run created, status, logs, and cancel response shapes. | Replace build/run response with direct result shapes. Later add the durable Operation representation and list envelope. |
| `response.go` | `writeOperationCreated` and generic response envelope. | Remove build/run creation response; keep one owner for direct Command responses. |
| `client.go` | Starts Operations, polls status/logs, cancels. | Replace build/run methods with one-request direct methods; later add durable lookup/list/wait methods. |
| `agent_cli.go` | Poll loop, log offsets, signal-triggered public cancel. | Render direct build/run results; use request-context cancellation on signals. Durable lifecycle waiting is added separately and performs no public cancel. |
| `main.go` | Registers legacy Operation routes and terminates `OperationSupervisor` during shutdown. | Remove legacy routes; wire synchronous execution cancellation and backend cleanup separately from the durable dispatcher. Add durable lookup/list routes only with the new model. |
| `app.go` | Stores `OperationSupervisor`; test seams use `operationID` as a runtime key. | Hold separate synchronous-execution and durable Operation owners. Rename runtime-key parameters so they do not imply public Operation identity. |
| `config.go`, `config_cli.go`, `reload.go`, `cli.go` | Operation TTL/count and log-buffer configuration. | Remove TTL/count settings. Move the byte limit to direct Command output under the agreed compatibility rule. |
| `database.go` | Launcher-owned Session/Principal/MAC schema; immediate expired-Session deletion. | Add durable Operation/idempotency schema against the existing non-null Session `launcher_id`; Session cleanup replaces immediate deletion in the later integration step. |
| `audit.go`, `logging.go` | Request-correlated audit and operational records. | Stop emitting Operation IDs for synchronous build/run. Durable events use the new Operation type/initiator/target vocabulary. |

### Shipped contract files

The synchronous migration changes all sources that currently document the async workflow:

- `README.md`;
- `docs/architecture.md`;
- `docs/roadmap.md` historical-versus-current wording;
- relevant files in `docs/man/`;
- `.claude/skills/docker-helper/SKILL.md`;
- CLI help and completion fixtures.

Historical roadmap sections may describe the old Release 1/2 implementation, but the current architecture and examples must not present it as the active Release 3 contract.

## Target ownership split

### 1. Synchronous Command service

The build and run services remain the owners of their domain validation, typed failure classification, audit metadata, and resource cleanup.

The public build capability remains deliberately narrow: `context`,
`dockerfile`, and `image` are required; optional `session_id` uses the common
Session-selection contract; and optional `build_args` preserves the existing
validated string map. D0 does not add platform, target, no-cache, BuildKit
secret, SSH-forwarding, network, or generic Engine request fields while
migrating the transport.

Pull accepts only required `image` and optional Session-selected `session_id`.
Its successful direct result contains `ok`, combined bounded `output`,
`truncated`, and `duration`, with no redundant success message or repeated
image field. The Engine API migration adds no platform, pull-policy, registry,
credential, or generic Engine option to the request.

Pull failure translation uses typed Engine stream results: absent image is
`404 image_not_found`, registry credential rejection is
`422 pull_access_denied`, and registry reachability failure is
`502 registry_unavailable`. These expected execution failures preserve
already captured bounded progress output. Helper authentication and authority
remain the sole meanings of `401 unauthorized` and `403 forbidden`; the old
`docker_pull_failed` code does not survive the adapter migration.

One-shot run reuses the Managed Container create vocabulary for `image`,
`entrypoint`, `command`, `workdir`, `env`, `mounts`, and `limits`, but creates
no persistent resource and accepts no name, publication, stdin, or detach
option. Only `image` is required; optional `session_id` uses the common
selection contract. Omitted entrypoint and command preserve the image values,
while explicit empty values are rejected.

Registry login accepts required `registry`, `username`, and `password` plus
optional Session-selected `session_id`, and returns only `{\"ok\":true}` on
success. Username and password remain protected Session runtime secrets and
never enter SQLite, argv, environment, audit, operational logs, or public
errors. The Engine adapter persists only the credential material needed for
later matching pull and build authorization and removes it with the Session.

Registry authentication denial is `422 registry_auth_denied`, registry
reachability failure is `502 registry_unavailable`, Engine unavailability is
`503 backend_unavailable`, and an unexpected Engine interaction is
`502 backend_failure`. None returns captured backend output. `401` remains
reserved for docker-helper authentication, and the Release 2 generic
`registry_login_failed` code is retired.

They invoke one docker-helper-owned Docker Engine API adapter that:

- executes under the caller's context and the daemon shutdown boundary;
- decodes backend streams without exposing Docker framing publicly;
- reads Session registry credentials only for image operations, sends matching authorization to pull and the required Session-scoped authorization map to build, and never forwards those credentials to container create or run;
- collects combined output under the shared bounded-output contract;
- waits for or observes one terminal backend result;
- returns typed backend failure, workload exit code where applicable, duration, retained output, and truncation;
- does not allocate, expose, or persist an Operation ID.

The adapter does not own build staging, mount pinning, policy validation, audit events, or HTTP status selection.

### 2. Transient execution coordination

Synchronous execution is live daemon state. Its coordinator owns only:

- an admission gate closed when daemon shutdown begins;
- active execution contexts;
- the admission-versus-shutdown race boundary;
- cancellation and bounded cleanup under the existing absolute shutdown deadline;
- command-specific backend-resource cleanup where cancellation alone cannot prove the postcondition.

One-shot run tracks the Engine-returned BackendContainerID internally and removes that container on request cancellation, disconnect, or daemon shutdown. Build cancellation closes the Engine request and stream through its context. Domain services continue to clean staging, pins, and MAC leases after execution reaches its terminal local state.

This coordinator has no public lookup, result state, log buffer, retention, Session authorization, or retry semantics. A private per-request runtime key may identify staging or pin paths, but it is not an Operation ID and is not returned or audited as one.

### 3. Durable Operation store and dispatcher

Durable Operation is a separate control-plane owner:

- SQLite owns records and state transitions;
- one dispatcher owns selection and in-process active tracking;
- a bounded worker set calls registered type handlers;
- each registered type supplies distinct `Execute` and `Recover` behavior;
- resource services own validation and admission preconditions;
- the common store owns insertion, idempotency association, and generic status transitions;
- a type-specific transaction hook applies resource changes that must be atomic with terminal status, including clearing `active_mutation_operation_id`.

The daemon instance lock already prevents two docker-helper processes from using the same state directory. D0 must not add distributed leases or a second database-locking framework. Within one daemon, a single dispatcher plus an in-memory active-ID set prevents duplicate handler invocation; conditional SQL updates protect state transitions.

## Persistent shape on the Release 2.1 baseline

The migration uses the existing non-null `sessions.launcher_id` foreign key and
derives Principal ownership through Launcher. It must not restore a direct
Session-to-Principal authority path.

### `operations`

Required data:

- public Operation ID using the retained `op_` prefix;
- non-null owning Session foreign key with `ON DELETE CASCADE`;
- bounded `type` discriminator;
- type-specific payload version used to recover work admitted by an earlier daemon version;
- `pending`, `running`, `succeeded`, `failed`, or `canceled` status;
- initiator type and the permitted stable initiator identifier;
- public target type and identifier;
- optional origin request ID;
- normalized type-specific input required to execute a pending record;
- bounded type-specific recovery data required to inspect interrupted work;
- exactly one status-compatible terminal result, error, or cancellation payload;
- created, started, cancellation-requested, and completed timestamps where applicable.

Required indexes support:

- lookup and bounded listing by Session and creation order;
- startup scans by status and creation order;
- public lookup by Operation ID through Session authorization.

No column stores output chunks, progress logs, raw Docker IDs as public targets, credentials, bearer material, or generic retryability. Payload versions are internal persistence compatibility data and are not part of the public Operation representation.

### `operation_idempotency`

Required data:

- owning Session foreign key;
- hash of the opaque idempotency key rather than the raw header value;
- fingerprint of the normalized Command;
- resulting Operation foreign key;
- creation timestamp.

The Session and key hash form the logical unique key. The association is inserted in the same transaction as the Operation. Reuse with a different fingerprint returns `idempotency_key_reused`; identical reuse returns the original Operation and performs no second resource mutation. Physical Session deletion removes both tables through cascade.

### State consistency

Application and schema checks must reject impossible combinations:

- `pending` and `running` have no terminal payload;
- `succeeded` has only a result;
- `failed` has only an error;
- `canceled` has only a cancellation;
- terminal rows have `completed_at` and never change status;
- `started_at` appears only after the atomic `pending -> running` claim;
- type-specific input and recovery payload size are bounded before persistence.

## Dispatcher algorithm

### Admission

1. Authenticate, authorize, resolve the public target, and validate before backend access.
2. Normalize the type-specific Command and compute its versioned non-secret fingerprint.
3. Resolve an existing optional Session-scoped idempotency key before current-state observation. Identical reuse returns the original Operation; different reuse returns `idempotency_key_reused`.
4. For a fresh request, obtain the type-specific runtime observation needed for admission.
5. Begin the admission transaction and re-resolve the idempotency key to close concurrent-reuse races.
6. Recheck persistent management state and lifecycle conflicts. A competing active mutation returns `409 Conflict` even if the last runtime observation happened to match the requested postcondition.
7. If the requested start or stop postcondition already holds, commit no new record and return `200 OK` with the current container representation.
8. Otherwise insert the `pending` Operation and idempotency association and apply the resource-specific active mutation reference in the same transaction.
9. Commit, return `202 Accepted` with `Location`, and signal the dispatcher.

The architecture fixes this observable ordering but does not require holding a SQLite transaction across Docker Engine access. The operational architect chooses the exact transaction mechanics while preserving idempotency, conflict, and no-op races.

If admission loses a conflict, it returns `409 operation_in_progress` with the
conflicting Operation ID. No rejected or state-matching no-op Command is
queued, and neither creates an Operation row.

### New execution

1. The dispatcher gives interrupted `running` rows priority over new `pending` rows.
2. For a `pending` row, conditionally update it to `running` and set `started_at` before calling external code.
3. A crash after this commit is safe: startup calls `Recover`, never `Execute`, for that row.
4. Call the handler's `Execute` once in the current daemon process.
5. Commit terminal status, terminal payload, timestamp, and type-specific resource finalization atomically.

### Restart recovery

1. After database initialization and handler registration, enumerate `running` Operations in deterministic order.
2. Call the matching handler's `Recover`; never rewrite the row to `pending`.
3. Unknown Operation types or unsupported persisted payload versions fail daemon startup rather than being guessed or marked failed.
4. After interrupted work has been scheduled, dispatch `pending` work normally.
5. Recovery observes backend postconditions and type-specific evidence; the generic dispatcher never repeats an external action by itself.

### Wake-up and concurrency

Admission sends a coalescing in-memory wake-up after commit. The dispatcher queries SQLite for work; the notification is not the queue and may be dropped when a wake-up is already pending. Startup scanning guarantees recovery after process loss.

Worker concurrency is bounded in code and is not operator configuration in the first implementation. The dispatcher is the sole selector and maintains the active-ID set. Resource-specific active mutation references provide the stronger per-container serialization required by D2.

### Internal cancellation

Only Session teardown may request cancellation through the common D0 boundary:

1. a `pending` user Operation transitions directly to `canceled` with reason `session_closing`;
2. a `running` Operation receives `cancel_requested_at` in SQLite and its active handler context is canceled with a distinguishable Session-closing cause;
3. the handler stops only at a type-specific safe point and returns a typed cancellation decision;
4. terminal success or failure already committed by the handler wins over a competing cancellation request;
5. after restart, `Recover` observes the durable cancellation request and applies the same type-specific safe-point rule.

The generic dispatcher never converts an arbitrary context error into public cancellation. Daemon shutdown, request loss, worker failure, and Session teardown remain distinguishable causes.

### Shutdown

When shutdown begins:

1. close synchronous-execution and durable-Operation admission gates;
2. stop claiming new `pending` Operations;
3. cancel active handler contexts with a daemon-shutdown cause;
4. cancel synchronous Engine API activity and finish required backend cleanup within the existing shared absolute deadline;
5. allow a durable handler that reaches a valid terminal commit to keep that result;
6. leave any other durable row `running` for restart recovery;
7. never write `canceled` solely because the daemon stopped.

Pending Operations remain pending. The next daemon instance resumes dispatch after recovering interrupted running work.

## Ordered implementation tasks

Each task is intended to be a focused commit or a small reviewable commit series. Later tasks must not leave the old and new owners active together.

### D0.1 — Freeze the Docker Engine API boundary

This is an architectural and compatibility gate, not an intermediate production migration.

- define the narrow adapter methods required by image pull, image build, one-shot run, lifecycle, logs, and exec without exposing Moby types to domain services;
- define API-version negotiation and the minimum tested Engine API version from the supported daemon matrix;
- verify `ImageBuild` stream and error handling against the project's BuildKit-enabled and legacy test environments;
- verify translation from the existing Session registry credential source to pull authorization and build authorization maps, including private-registry success and secret non-disclosure;
- define cancellation, shutdown, stream decoding, BackendContainerID handling, and one-shot-container cleanup contracts;
- do not migrate build or run to an Engine-backed copy of the legacy status/log/cancel workflow.

Completion evidence:

- the adapter contract and compatibility evidence are recorded for review;
- private pull and private `FROM` behavior are covered explicitly;
- no production path, public response, or temporary owner reproduces the asynchronous build/run mechanism over Engine API.

### D0.2 — Migrate pull and make build synchronous

- pin and introduce the reviewed official Moby dependency with the first production adapter methods;
- execute image pull through the adapter with only matching Session registry authorization;
- execute Docker build under the request context through the Engine API adapter and transient execution coordinator, with the Session-scoped authorization map required for private `FROM` images;
- return flat bounded terminal responses;
- remove `newBuildOperation`, build polling, build public cancellation, and `waitBuildCompletion`;
- preserve validation, isolated staging, build-arg ordering, Session credential ownership, audit fields, cleanup order, and MAC lease retention on cleanup failure;
- remove build Operation IDs from API responses and audit records.

Completion evidence:

- public and private pull and build paths use the reviewed adapter without exposing credentials;
- the CLI still blocks, prints build output, reports truncation, handles signals, and exits non-zero on build failure;
- request disconnect and daemon shutdown cancel the Engine build and clean staging;
- no build path calls the legacy Operation registry or public Operation routes.

### D0.3 — Make one-shot run synchronous

- execute Docker run under the request context through the Engine API adapter and transient execution coordinator;
- return bounded output, duration, result code, and exit code directly;
- remove `newRunOperation`, run polling, run public cancellation, and `waitRunCompletion`;
- preserve UID/GID selection, MAC backend enforcement, mount validation and pinning, CA injection, image-reference behavior, daemon-side container removal, audit metadata, and exit-code mapping;
- remove run Operation IDs from API responses and audit records.

Completion evidence:

- the CLI still blocks and returns the container exit code for `container_exit_nonzero`;
- CLI signal cancellation and request disconnect cannot leave the one-shot container running;
- pin/container/MAC cleanup ordering preserves the existing observable guarantees;
- no run path calls the legacy Operation registry or public Operation routes.

### D0.4 — Delete the legacy public Operation mechanism

- remove legacy status/log/cancel handlers, routes, client calls, response types, poll loops, and offset parsing;
- remove in-memory Operation retention and public log-buffer ownership;
- remove `operation_retention_ttl` and `operation_max_completed` from runtime config, reload, CLI help, completion, docs, and tests;
- apply the agreed compatibility treatment to the output byte-limit field;
- update architecture, README, man pages, agent skill, and examples in the same change;
- retain only reusable bounded-output and cleanup behavior from the old implementation; do not retain its child-process supervisor as target architecture.

Completion evidence:

- searching production code finds no build/run `operation_id`, `/operations/{id}/logs`, public cancel, polling, pruning, or completed-operation registry;
- tests no longer reimplement the deleted workflow;
- current documentation describes synchronous build/run while historical roadmap text is clearly historical.

### D0.5 — Add durable persistence and typed handler boundary

The Release 2.1 implementation and vocabulary-map rebaseline prerequisites for
this task are satisfied.

- add the Operation and idempotency tables through the repository's existing explicit SQLite migration style;
- add bounded domain types for identity, type, status, initiator, target, terminal payload, and timestamps;
- add transactional admission helpers that participate in a caller-owned transaction;
- add conditional transition and terminal-finalization methods;
- add one handler registry requiring both Execute and Recover behavior;
- make persisted payload-version support explicit at handler registration;
- reject duplicate type registration and unknown persisted types or payload versions.

Completion evidence:

- foreign keys are enforced on every connection and cascades are tested;
- invalid state/payload combinations cannot be written through production APIs;
- idempotency races return one Operation;
- no handler or test owns an alternative state machine.

### D0.6 — Add dispatcher, restart recovery, and shutdown

- wire the single dispatcher after handler registration;
- implement startup recovery-before-pending ordering;
- implement conditional `pending -> running` transition, bounded worker concurrency, active-ID protection, and coalescing wake-up;
- commit type-specific finalization atomically with terminal status;
- integrate shutdown without converting interrupted durable work to cancellation;
- expose focused health/startup failure when persisted types lack handlers.

Completion evidence:

- a crash point after claim but before Execute enters Recover after restart;
- a running row is never executed concurrently by two workers;
- a terminal transition is immutable;
- shutdown leaves unfinished work recoverable;
- pending work is not dependent on an in-memory notification for durability.

### D0.7 — Add durable Operation read surface

- add Session-authorized lookup and bounded listing with status/type/target filters;
- return `202 Accepted` and `Location` from a test integration Command using the common admission path only when a real Release 3 Operation type is available;
- add thin CLI wait/detach rendering with no local persistence, automatic retry, or public cancel;
- keep `initiator_id` and `origin_request_id` internal permanently; the public Operation projection never exposes them.

Do not ship a fake production Operation type merely to exercise D0. Until D2,
D3 Session repair, or Session cleanup supplies a real handler, test the generic
boundary with test-only handlers.

## Test migration inventory

### Preserve and retarget

| Existing suite | Independent invariant to preserve |
| --- | --- |
| `cmd_start_race_test.go` | Start and shutdown have one atomic boundary. |
| `shutdown_test.go`, `shutdown_lifecycle_test.go` | Graceful and force termination share one absolute deadline and run concurrently. |
| `shutdown_gate_test.go` | Work admitted before gate close is supervised; work after close is rejected. |
| `container_lifecycle_unit_test.go`, `container_lifecycle_integration_test.go` | One-shot run cancellation cleanup removes the Engine-returned backend container under admission and shutdown races. |
| `build_staging_test.go` | Staging cleanup precedes MAC lease release; failure retains confinement state. |
| `mount_pin_linux_test.go`, relevant `mac_lifecycle_test.go` cases | Pin cleanup and MAC lease ownership remain ordered and fail closed. |
| `bounded_buffer_test.go`, `build_tail_test.go` | Direct output remains bounded, retains the newest bytes, and reports truncation. |
| `build_audit_test.go`, `audit_test.go`, `logging_audit_correctness_test.go` | Start/finish attribution, sanitized errors, duration, and secret exclusion remain observable without false Operation identity. |
| `run_exit_code_test.go`, `error_contract_test.go` | Docker failure and workload non-zero exit remain distinct and preserve the exit code. |
| `agent_cli_test.go` | Blocking behavior, output routing, truncation warning, signal exit codes, and API error rendering remain stable. |

### Remove or rewrite

- `build_async_test.go` becomes synchronous build request/result and disconnect coverage;
- public cancellation cases in `cancel_test.go` are deleted, while execution cancellation and backend cleanup races move to transient-coordinator tests;
- `operation_cleanup_test.go` is deleted with TTL/count pruning;
- status/log offset tests in `build_test.go`, `run_exit_code_test.go`, `agent_cli_test.go`, and `error_contract_test.go` are replaced by direct result assertions;
- `operationSupervisor`-specific tests are retained only when they protect observable cancellation or cleanup guarantees and are rewritten against their final owner;
- configuration, reload, help, completion, README, man-page, packaging, and agent-skill tests are updated with the selected output-limit compatibility rule.

### New durable invariants

D0 persistence and dispatcher tests must prove:

- Session ownership and cross-Session non-disclosure;
- `ON DELETE CASCADE` for Operation and idempotency rows;
- atomic idempotency under concurrent admission;
- same key/different fingerprint rejection;
- one active worker per Operation;
- recovery, not Execute, for interrupted `running` rows;
- pending and running Session-closing cancellation, including the terminal-result race;
- terminal immutability and status-compatible payloads;
- terminal status and resource finalization in one transaction;
- recovery of the previous supported payload version across daemon upgrade;
- pending work survives a lost wake-up and process restart;
- shutdown leaves interrupted work recoverable;
- no secret or raw backend ID enters durable rows, public errors, or audit records; workload output appears only in the bounded direct Command result and never in durable rows or audit.

## Remaining implementation gate

The public D0 contract, target ownership split, and official Moby client dependency are fixed. D0.1 is the operational architect's gate for the narrow adapter contracts, including cancellation, shutdown, build-stream decoding, one-shot-container cleanup, private-registry authorization translation, and the minimum tested Engine API version. The compatibility spike may refine adapter mechanics but is not permission to reopen the synchronous Command, credential boundary, or durable Operation contracts.

## D0 completion gate

D0 is complete only when all of the following are true:

- build and one-shot run have no public or internal durable Operation identity;
- their CLI remains blocking and their output, exit, cancellation, cleanup, and shutdown behavior is covered through the synchronous production path;
- the old in-memory record, registry, polling, replay, public cancellation, and retention configuration are gone;
- transient execution coordination is the only owner of synchronous cancellation and backend-resource cleanup;
- durable Operation persistence, dispatcher, handler registration, recovery, idempotency, retention-by-Session, and read API have one owner each;
- no fake build/run compatibility layer reproduces the deleted async workflow;
- the implementation map references the actual Release 2.1 symbols and schema;
- documentation and shipped CLI/man/agent contracts match the new behavior.
