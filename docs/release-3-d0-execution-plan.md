# Release 3 D0 Execution Plan

## Status and baseline

This document is the executor-facing implementation plan for D0, the cross-cutting Operation foundation defined by `release-3-operation-model.md`.

The inspected baseline is `main` at `c840d4e197e86e1b7a190d4dcea7dd795975d8a5`. Release 2.1 Launcher delegation is still design-only at this commit. Symbol and schema references below describe that exact baseline and must be reconciled once the Release 2.1 implementation lands.

D0 changes two mechanisms that currently share one in-memory object but have different target semantics:

1. `build` and one-shot `run` become synchronous Commands bound to their HTTP Requests;
2. durable Operation is introduced for managed-container lifecycle and Session cleanup only.

The current in-memory Operation is not migrated or generalized. Its process-lifetime mechanics are separated from its public status/log/cancel contract, then the public contract and record are removed.

## Fixed contract

The following decisions are already binding:

- `build`, one-shot `run`, and non-interactive exec are synchronous Commands;
- interactive exec uses WebSocket and is not an Operation;
- only managed-container lifecycle mutations and `session.cleanup` create durable Operations;
- synchronous Commands do not survive request loss or daemon restart;
- the normal CLI remains blocking and returns the workload exit result;
- output returned by a synchronous Command is bounded and is not replayable;
- durable Operations persist no workload output or progress log;
- public build/run Operation status, log, and cancel workflows are removed;
- a daemon shutdown must still terminate live build/run processes within the existing shared shutdown deadline;
- one-shot `run` cleanup must still remove a container that outlives its Docker CLI process;
- staged build contexts, pinned mounts, cidfiles, and MAC leases retain their current cleanup ordering and failure semantics;
- daemon shutdown does not convert a durable running Operation into a terminal cancellation; restart recovery decides its result;
- no independent Operation retention configuration or delete API exists;
- no hidden queue defers a conflicting lifecycle Command for later execution.

## Current implementation inventory

The current `operation` object owns five unrelated responsibilities:

| Responsibility | Current owner | D0 disposition |
| --- | --- | --- |
| Public build/run status | `operation` fields and `GET /operations/{id}` | Remove for build/run; replace later with the durable representation. |
| Client output replay | `operation.LogBuffer`, offset polling, `/logs` | Remove. Retain only a bounded direct-response buffer. |
| Public cancellation | `/operations/{id}/cancel`, `operationSupervisor.cancel` | Remove. Request/signal loss cancels synchronous work; Session cleanup owns internal durable cancellation. |
| Live process termination | `operation.cmd`, `terminateForShutdown`, force cleanup | Preserve under a transient process supervisor that is not a durable Operation store. |
| Durable execution | None | Add SQLite-backed records, one dispatcher, typed handlers, and restart recovery. |

### Production files

| File | Current responsibility | Required change |
| --- | --- | --- |
| `operation.go` | In-memory record, registry, log buffer, public cancellation, process start, shutdown termination. | Split transient process supervision and bounded output from the deleted public record; add durable Operation types in separate files. |
| `build.go` | Validates and stages, registers Operation, starts Docker, returns `201`, completes in a goroutine. | Execute within the request lifetime, return one bounded terminal response, preserve staging/MAC cleanup. |
| `run.go` | Validates, pins mounts, registers Operation, manages cidfile, returns `201`, completes in a goroutine. | Execute within the request lifetime, return one bounded terminal response, preserve daemon-side container cleanup, pins, cidfile, and MAC cleanup. |
| `api_contract.go` | Build/run created, status, logs, and cancel response shapes. | Replace build/run response with direct result shapes. Later add the durable Operation representation and list envelope. |
| `response.go` | `writeOperationCreated` and generic response envelope. | Remove build/run creation response; keep one owner for direct Command responses. |
| `client.go` | Starts Operations, polls status/logs, cancels. | Replace build/run methods with one-request direct methods; later add durable lookup/list/wait methods. |
| `agent_cli.go` | Poll loop, log offsets, signal-triggered public cancel. | Render direct build/run results; use request-context cancellation on signals. Durable lifecycle waiting is added separately and performs no public cancel. |
| `main.go` | Registers legacy Operation routes and terminates `OperationSupervisor` during shutdown. | Remove legacy routes; wire transient process shutdown separately from the durable dispatcher. Add durable lookup/list routes only with the new model. |
| `app.go` | Stores `OperationSupervisor`; test seams use `operationID` as a runtime key. | Hold separate transient process and durable Operation owners. Rename runtime-key parameters so they do not imply public Operation identity. |
| `config.go`, `config_cli.go`, `reload.go`, `cli.go` | Operation TTL/count and log-buffer configuration. | Remove TTL/count settings. Move the byte limit to direct Command output under the agreed compatibility rule. |
| `database.go` | Session/Principal/MAC schema; immediate expired-Session deletion. | Add durable Operation/idempotency schema only after Release 2.1; Session cleanup replaces immediate deletion in the later integration step. |
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

The build and run handlers remain the owners of their domain validation, Docker argv, typed failure classification, audit metadata, and resource cleanup.

They invoke one shared bounded process primitive that:

- starts exactly one `exec.Cmd` under the transient supervisor's start/shutdown boundary;
- attaches bounded output writers;
- waits exactly once;
- observes request cancellation;
- returns start error, wait error, exit code, duration, retained output, and truncation;
- does not allocate, expose, or persist an Operation ID.

The primitive does not own build staging, mount pinning, cidfiles, Docker error classification, audit events, or HTTP status selection.

### 2. Transient process supervisor

The process supervisor is live daemon state. It owns only:

- an admission gate closed when daemon shutdown begins;
- the active child-process set;
- the start-versus-shutdown race boundary currently protected by `op.mu`;
- graceful signal and force-kill coordination under the existing absolute shutdown deadline;
- an optional command-specific force-cleanup callback.

The one-shot run callback reads the helper-owned cidfile and performs bounded daemon-side container cleanup before force-killing the Docker CLI. Build has no container cleanup callback. Domain handlers continue to clean staging, pins, cidfiles, and MAC leases after the process reaches its terminal local state.

This supervisor has no public lookup, result state, log buffer, retention, Session authorization, or retry semantics. A private per-request runtime key may identify staging/pin/cidfile paths, but it is not an Operation ID and is not returned or audited as one.

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

## Persistent shape after Release 2.1

The final migration must use the actual Release 2.1 Session foreign key and ownership schema. The required logical shape is fixed even if exact column names change.

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

1. Authenticate and authorize before backend access.
2. Normalize and validate the type-specific Command.
3. Begin one SQLite transaction.
4. Recheck resource state and lifecycle conflict conditions inside the transaction.
5. Resolve an optional idempotency key.
6. Insert the `pending` Operation and idempotency association.
7. Apply the resource-specific active mutation reference in the same transaction.
8. Commit, return `202 Accepted` with `Location`, and signal the dispatcher.

If admission loses a conflict, it returns HTTP `409 Conflict` with the conflicting Operation ID. The stable error-code name belongs to the API design. No rejected Command is queued and no Operation row is created.

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

1. close synchronous-process and durable-Operation admission gates;
2. stop claiming new `pending` Operations;
3. cancel active handler contexts with a daemon-shutdown cause;
4. terminate transient child processes within the existing shared absolute deadline;
5. allow a durable handler that reaches a valid terminal commit to keep that result;
6. leave any other durable row `running` for restart recovery;
7. never write `canceled` solely because the daemon stopped.

Pending Operations remain pending. The next daemon instance resumes dispatch after recovering interrupted running work.

## Ordered implementation tasks

Each task is intended to be a focused commit or a small reviewable commit series. Later tasks must not leave the old and new owners active together.

### D0.1 — Extract transient process supervision

- introduce the shutdown/admission/process owner without changing HTTP behavior;
- move the proven start race, SIGTERM, force deadline, single-owner force cleanup, and cidfile callback mechanics out of the public `operation` record;
- keep `boundedBuffer` independent of both supervisors;
- migrate shutdown/race/force-cleanup tests to the new production owner;
- prove old process fields and termination paths are no longer reachable from `operation`.

Completion evidence:

- behavior of build/run status/log/cancel remains unchanged at this intermediate point;
- existing shutdown deadline, simultaneous-operation, start-race, cidfile cleanup, staging, pins, and MAC lease tests still pass through the new owner;
- `operationSupervisor` no longer owns process termination.

### D0.2 — Make build synchronous

- execute Docker build under the request context and transient supervisor;
- return one bounded terminal response;
- remove `newBuildOperation`, build polling, build public cancellation, and `waitBuildCompletion`;
- preserve validation, isolated staging, build-arg ordering, Docker config ownership, audit fields, cleanup order, and MAC lease retention on cleanup failure;
- remove build Operation IDs from API responses and audit records.

Completion evidence:

- the CLI still blocks, prints build output, reports truncation, handles signals, and exits non-zero on build failure;
- request disconnect and daemon shutdown terminate the local build process and clean staging;
- no build path calls the legacy Operation registry or public Operation routes.

### D0.3 — Make one-shot run synchronous

- execute Docker run under the request context and transient supervisor;
- return bounded output, duration, result code, and exit code directly;
- remove `newRunOperation`, run polling, run public cancellation, and `waitRunCompletion`;
- preserve UID/GID selection, MAC backend enforcement, mount validation and pinning, CA injection, Docker config, cidfile cleanup, daemon-side forced container removal, audit metadata, and exit-code mapping;
- remove run Operation IDs from API responses and audit records.

Completion evidence:

- the CLI still blocks and returns the container exit code for `container_exit_nonzero`;
- SIGINT/SIGTERM and request disconnect cannot leave the one-shot container running;
- pin/cidfile/MAC cleanup ordering is unchanged;
- no run path calls the legacy Operation registry or public Operation routes.

### D0.4 — Delete the legacy public Operation mechanism

- remove legacy status/log/cancel handlers, routes, client calls, response types, poll loops, and offset parsing;
- remove in-memory Operation retention and public log-buffer ownership;
- remove `operation_retention_ttl` and `operation_max_completed` from runtime config, reload, CLI help, completion, docs, and tests;
- apply the agreed compatibility treatment to the output byte-limit field;
- update architecture, README, man pages, agent skill, and examples in the same change;
- retain only the process supervisor and direct-response bounded buffer from the old implementation.

Completion evidence:

- searching production code finds no build/run `operation_id`, `/operations/{id}/logs`, public cancel, polling, pruning, or completed-operation registry;
- tests no longer reimplement the deleted workflow;
- current documentation describes synchronous build/run while historical roadmap text is clearly historical.

### D0.5 — Add durable persistence and typed handler boundary

This task starts only after the Release 2.1 implementation is merged and the vocabulary map is rebased to its actual Session/Launcher symbols.

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
- keep `initiator_id` and `origin_request_id` hidden until D9 fixes their authorization rules.

Do not ship a fake production Operation type merely to exercise D0. Until D2 or Session cleanup supplies a real handler, test the generic boundary with test-only handlers.

## Test migration inventory

### Preserve and retarget

| Existing suite | Independent invariant to preserve |
| --- | --- |
| `cmd_start_race_test.go` | Start and shutdown have one atomic boundary. |
| `shutdown_test.go`, `shutdown_lifecycle_test.go` | Graceful and force termination share one absolute deadline and run concurrently. |
| `shutdown_gate_test.go` | Work admitted before gate close is supervised; work after close is rejected. |
| `container_lifecycle_unit_test.go`, `container_lifecycle_integration_test.go` | One-shot run force cleanup removes backend containers and handles cidfile races. |
| `build_staging_test.go` | Staging cleanup precedes MAC lease release; failure retains confinement state. |
| `mount_pin_linux_test.go`, relevant `mac_lifecycle_test.go` cases | Pin cleanup and MAC lease ownership remain ordered and fail closed. |
| `bounded_buffer_test.go`, `build_tail_test.go` | Direct output remains bounded, retains the newest bytes, and reports truncation. |
| `build_audit_test.go`, `audit_test.go`, `logging_audit_correctness_test.go` | Start/finish attribution, sanitized errors, duration, and secret exclusion remain observable without false Operation identity. |
| `run_exit_code_test.go`, `error_contract_test.go` | Docker failure and workload non-zero exit remain distinct and preserve the exit code. |
| `agent_cli_test.go` | Blocking behavior, output routing, truncation warning, signal exit codes, and API error rendering remain stable. |

### Remove or rewrite

- `build_async_test.go` becomes synchronous build request/result and disconnect coverage;
- public cancellation cases in `cancel_test.go` are deleted, while process termination and cleanup races move to transient-supervisor tests;
- `operation_cleanup_test.go` is deleted with TTL/count pruning;
- status/log offset tests in `build_test.go`, `run_exit_code_test.go`, `agent_cli_test.go`, and `error_contract_test.go` are replaced by direct result assertions;
- `operationSupervisor`-specific tests are retained only when they protect process supervision and are rewritten against that owner;
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
- no secret, workload output, or raw backend ID enters durable rows, public errors, or audit records.

## Remaining contract gates

The implementation sequence is fixed, but three public details must be settled before D0.2-D0.4 are assigned for coding:

1. **Direct output shape.** The smallest compatibility change is one combined bounded `output` field, matching current build/run polling and synchronous pull behavior. Splitting stdout/stderr would be a separate public CLI/API change and must not happen accidentally.
2. **Terminal HTTP semantics.** The response must distinguish failure to start Docker, Docker/backend failure, build failure, and a successfully started container that exits non-zero. Exact HTTP statuses and whether `container_exit_nonzero` is a `200` terminal result must be frozen in the API design.
3. **Output-limit configuration migration.** `operation_log_max_bytes` is semantically obsolete but exists in deployed configs and also bounds pull output. The replacement name, upgrade behavior, reload semantics, and whether pull/build/run/exec share one limit require one explicit compatibility decision.

The workload-output-to-journald option is not part of D0 process delivery. Its name, redaction, and scope remain a D5/D9 design gate and must not be conflated with the direct response byte limit.

## D0 completion gate

D0 is complete only when all of the following are true:

- build and one-shot run have no public or internal durable Operation identity;
- their CLI remains blocking and their output, exit, cancellation, cleanup, and shutdown behavior is covered through the synchronous production path;
- the old in-memory record, registry, polling, replay, public cancellation, and retention configuration are gone;
- transient process supervision is the only owner of live child-process shutdown;
- durable Operation persistence, dispatcher, handler registration, recovery, idempotency, retention-by-Session, and read API have one owner each;
- no fake build/run compatibility layer reproduces the deleted async workflow;
- the final implementation map references the actual Release 2.1 symbols and schema;
- documentation and shipped CLI/man/agent contracts match the new behavior.
