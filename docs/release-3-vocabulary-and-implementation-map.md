# Release 3 Vocabulary and Implementation Map

## Purpose

This document maps the Release 3 architecture to the existing docker-helper implementation.

It is intended for the operational architect who decomposes design work into executor-facing tasks. It identifies which existing symbols are retained, split, replaced, or newly introduced and prevents conceptual names from being translated into unnecessary wrapper types.

This map is based on:

- repository: `kivarun/docker-helper`;
- branch: `main`;
- commit: [`c840d4e197e86e1b7a190d4dcea7dd795975d8a5`](https://github.com/kivarun/docker-helper/commit/c840d4e197e86e1b7a190d4dcea7dd795975d8a5);
- Release 2.1 input: `docs/release-2.1-launcher-delegation.md` at the same commit.

Release 2.1 is not implemented at this baseline. Before Release 3 production code begins, this map must be checked against the final Release 2.1 commit. Release 3 must consume the resulting Launcher and Session ownership model rather than implement a second version of it.

## Reading the map

The document distinguishes three categories:

- **existing fact** — directly present at the baseline commit;
- **accepted target** — already fixed by the Release 3 scope and domain designs;
- **implementation gate** — accepted architecture that still requires evidence from the final Release 2.1 code or a bounded backend spike before executor work begins.

Target names describe one logical responsibility. Exact Go visibility follows the final package boundary. Capitalization of a domain term in documentation does not require an exported Go type in the current single-package implementation.

## Canonical vocabulary

| Term | Canonical meaning | Existing implementation | Release 3 rule |
| --- | --- | --- | --- |
| Request | One transport message received by an HTTP or WebSocket endpoint. | Request structs such as `buildRequest` and `runRequest`; `*http.Request`. | Remains a transport concept. It is not a fourth application layer. |
| Response | One transport representation returned to a client. | Response structs in `api_contract.go`. | Remains a transport concept. |
| Command | An application action that may change state or produce an external effect. | Usually implemented directly inside an HTTP handler; no common type. | A conceptual role, not a mandatory `Command` interface or wrapper struct. |
| Query | A read-only application observation. | Usually implemented directly inside an HTTP handler; no common type. | A conceptual role. A Query never creates an Operation merely for uniformity. |
| Operation | A durable execution record for selected asynchronous Commands. | `operation` is an in-memory process record for asynchronous `run` and `build`. | Becomes persisted Session-owned control-plane state for container start, stop, restart, remove, administrator policy repair, explicit Session network repair, and Session cleanup. It contains no process handle or output buffer. |
| Operation type | Discriminator for type-specific execution and recovery. | `operation.Kind string` with internal values `run` and `build`. | Use `type`, not `kind`. Durable values are `container.start`, `container.stop`, `container.restart`, `container.remove`, `container.repair`, `session.repair`, and `session.cleanup`; both current values are removed. |
| Operation status | Durable execution state. | `operationState`: `running`, `succeeded`, `failed`. | `pending`, `running`, `succeeded`, `failed`, `canceled`. |
| Operation handler | Type-specific execution and restart recovery. | No common handler boundary; `build.go` and `run.go` own process completion directly. | One handler per Operation type with separate `Execute` and `Recover` behavior. |
| Managed Container | Session-owned durable docker-helper resource. | No corresponding domain object. A `run` container is ephemeral and uses `--rm`. | New persistent domain object; never an alias for a Docker container ID or Operation. |
| ManagedContainerID | Stable public identity allocated by docker-helper. | Does not exist. | New immutable public identifier: `dhmc_` followed by 32 lowercase hexadecimal characters. |
| Managed Container name | Immutable Session-local user-facing name and DNS alias. | Does not exist; one-shot `run` has no retained name. | Public field `name`; unique within one Session and DNS-label-compatible. Use an explicit caller value unchanged after validation, or default to an already-valid unused image repository basename. Invalid or conflicting defaults require an explicit name. |
| Docker backend name | Diagnostic host-visible Docker object name. | Docker CLI chooses or receives transient names. | Generate `dhmc-<name>-<full-session-id>`. Every named Docker resource owned directly by a Session uses a stable type prefix and the full Session ID; names are not authority or public identity. |
| BackendContainerID | Docker Engine container identifier. | Transient value read through a `--cidfile` for `run` shutdown cleanup. | Persistent internal correlation, never normal public authority. Only the admin orphan surface may accept it directly; ownership-mismatch force removal targets ManagedContainerID and resolves the exact recorded backend internally. |
| Session | Authorization, ownership, isolation, and lifetime boundary. | `Session`; SQLite `sessions` row. | Retained and extended with Release 2.1 Launcher ownership and Release 3 teardown state. |
| Principal | OS identity and maximum delegated policy. | `principals` table and Principal code. | Retained. It is not the direct owner of Release 3 containers or Operations. |
| Launcher | Stable delegated Session owner. | Design-only in Release 2.1; no Go type or table at this baseline. | Inherited from Release 2.1. Release 3 must not recreate it. |
| Credential | Rotatable bearer key owned by one Principal or Launcher. | Principal-only `credentials` model. | Inherited from Release 2.1. Credentials initiate work but do not own it. |
| Owner | Domain object that controls resource lifetime and authorization. | Sessions currently carry nullable `principal_id`. | Always concrete: Launcher owns Session; Session owns Operation and Managed Container. Do not add a generic Owner hierarchy. |
| Initiator | Subject that started an Operation. | Not stored in `operation`; only `auditPrincipalName` is retained for finish audit. | Internal Operation provenance: type plus authorized identifier. It is not ownership and is never part of the public Operation projection. |
| Actor | Subject recorded by an audit event. | No generic `actor` field; current audit has fields such as `principal_name` and `credential_id`. | Audit vocabulary only. Do not rename Operation `initiator` to `actor`. |
| Target | Public resource affected by an Operation. | No common target field. Build/run metadata is embedded directly in `operation`. | Type-specific public target identity; never a Docker backend ID. |
| Management state | Persistent helper-owned lifecycle state. | Session existence is mostly represented by row presence; Managed Container does not exist. | Session and Managed Container state needed for ownership and recovery. It remains internal and is not a second public state machine. |
| Runtime state | Current backend observation normalized by docker-helper. | Inferred from the running Docker CLI process or queried ad hoc. | Public values are `stopped`, `running`, `paused`, `transitioning`, `dead`, `missing`, and `unknown`; they are observations, never desired state or raw Docker inspect status. |
| Management projection | Persistent non-secret data required to authorize, inspect, correlate, and clean up a Managed Container. | No Managed Container record exists. | Not a normalized Docker create request or desired state. It excludes environment values, registry credentials, and recreate-capable backend payloads. |
| Session Network | User-defined bridge owned by one Session. | No per-Session network. | Lazily created, named with the full Session ID, explicitly repaired as a Session-wide invariant when missing with existing Managed Containers, and removed by Session cleanup; it is infrastructure, not a management plane. |
| Resource ceiling | Aggregate maximum permitted to a Root, Principal, Launcher, or Session subtree. | No resource hierarchy. | Narrows down the ownership hierarchy and is enforced by parent cgroups; it is not a reservation ledger. |
| Workload limit | Explicit Docker limit applied to one Managed Container or one-shot run. | Docker defaults are largely inherited. | May be narrower than the Session ceiling; omission selects the Session ceiling, while ancestor cgroups cap aggregate actual use. |
| Publishing grant | Host-port range a Principal, Launcher, or Session may use. | No publishing authorization model. | Narrows monotonically through the ownership hierarchy. |
| Port lease | One host port assigned to a Managed Container publication. | No persistent allocation. | Persists for the Managed Container lifetime and prevents collisions only with other docker-helper leases. |
| Condition | Stable reason why normal management and runtime observations cannot be combined. | No common type. | Bounded public vocabulary: `backend_missing`, `backend_unavailable`, `ownership_mismatch`, `policy_mismatch`, and `cleanup_failed`. Conditions never trigger autonomous mutation. |
| Interactive Stream | Transport for one authorized interactive exec. | Does not exist. | Versioned docker-helper WebSocket protocol; not an Operation or owner. |

## Naming rules

The following rules are binding for Release 3 design and code review:

1. Use `type` for the Operation discriminator. The current `Kind` field and `kind` JSON name do not survive the migration.
2. Retain the established `op_` Operation ID prefix. It is already public and does not collide with `dhs_` Session IDs, `dhcr_` credential IDs, or bearer-token prefixes.
3. Do not use Operation identity as ManagedContainerID or Session identity.
4. Use `initiator` in the Operation model and `actor` only if the audit model adopts that umbrella term.
5. Do not introduce a generic `Owner`, `Resource`, `Job`, or `Task` abstraction where concrete Session ownership and Operation types are sufficient.
6. Command and Query describe application behavior. They do not require base interfaces, one-field wrapper structs, or duplicate transport models.
7. Docker Engine requests, container IDs, process IDs, and attach framing are backend details unless a design explicitly promotes them into the public contract.
8. Existing all-lowercase Go types may remain package-private. A domain term is not renamed solely to match documentation capitalization.
9. Public `name` is the Managed Container's Session-network DNS alias, not a second display name. ManagedContainerID and OperationID never participate in Docker backend names.
10. Named Docker resources owned by a Session include the full Session ID in their diagnostic backend names; immutable ownership labels remain authoritative.

## Existing Operation implementation

At the baseline commit, Operation is not durable:

- `operationSupervisor` owns an in-memory `map[string]*operation`;
- there is no `operations` SQLite table;
- daemon restart loses every Operation and its output;
- Operations begin directly in `running`; there is no `pending` state;
- cancellation is represented as `failed` plus `result_code=cancelled`;
- `run` and `build` both create Operations;
- `operation` contains `*exec.Cmd`, channels, mutexes, shutdown flags, temporary-resource handles, audit metadata, and a rolling `LogBuffer`;
- `GET /operations/{id}/logs` reads the in-memory buffer;
- `POST /operations/{id}/cancel` terminates the live process;
- completed Operations are pruned by TTL and count from memory;
- admission returns HTTP `201 Created` through `writeOperationCreated`.

The Release 3 change is therefore an abstraction split, not a persistence adapter added underneath the current struct.

## Operation refactoring map

| Existing symbol or field | Existing responsibility | Target responsibility | Action | Owner |
| --- | --- | --- | --- | --- |
| `operation` | Domain data, process state, temporary resources, output, cancellation, and audit metadata in one object. | Durable Operation record only. | Split. Remove mutexes, process handles, channels, output buffer, and temporary-resource handles from the persisted model. | D0 |
| `operationSupervisor` | In-memory registry, shutdown gate, pruning, cancel, and process termination. | No single equivalent. | Split into persistent store and durable worker; preserve only the observable shutdown and cleanup guarantees needed by the Engine API execution path. Retire the old name after callers migrate. | D0 |
| `operationSupervisor.ops` | In-memory source of truth. | SQLite-backed lookup and listing. | Replace with an `operationStore`-equivalent boundary. | D0 |
| `operationSupervisor.admit` | Shutdown check plus in-memory registration. | Transactional validation result, Operation insert, idempotency association, and resource conflict reference. | Replace; keep daemon-shutdown admission gating as a separate concern. | D0 |
| `operationSupervisor.lookup` | In-memory lookup. | Persistent lookup plus authorization through owning Session. | Replace. | D0/D9 |
| `operationSupervisor.pruneCompleted` | TTL/count retention in memory. | No independent Operation retention. | Remove. Physical Session deletion cascades Operations. | D0 |
| `operationSupervisor.cancel` | Public cancellation of build/run processes. | Internal type-specific cancellation used by Session cleanup only. | Remove from public API; do not mechanically expose the old function. | D0/D2 |
| `terminateForShutdown` and `terminateOperations` | Graceful and forced Docker CLI process shutdown. | Bounded cancellation and backend-resource cleanup during daemon shutdown. | Preserve the observable deadline and cleanup guarantees, not the child-process mechanism. | D0 |
| `operation.Kind` | Untyped `run` or `build` discriminator. | Typed Operation `type`. | Replace with a bounded discriminator. Remove both current values and add Release 3 types. | D0 |
| `operation.State` | Three-state in-memory process status. | Five-state durable Operation status. | Replace with explicit transition validation. | D0 |
| `operation.ResultCode` | Success, failure, and cancellation classification in one optional string. | Status-dependent `result`, `error`, or `cancellation`. | Split. Do not retain a generic result-code bucket as the canonical model. | D0/D9 |
| `operation.ExitCode` | Docker CLI process exit code. | Direct synchronous `run` result. | Move out of Operation; durable lifecycle Operations do not have workload exit codes. | D0 |
| `operation.Image`, `Context`, `Dockerfile` | Build/run metadata embedded in the generic object. | Synchronous build/run request and execution data. | Move out of the common record; do not persist it as Operation recovery state. | D0/D9 |
| `operation.LogBuffer` | Client-visible rolling Operation log. | Not part of Operation. | Remove. Synchronous build/run return bounded output directly. | D0/D9 |
| `boundedBuffer` | Bounded combined stdout/stderr storage. | Reusable bounded I/O primitive where a synchronous response needs it. | Retain independently if useful for `pull`, synchronous `build`, synchronous `run`, or exec; rename only if its final responsibility changes. | D0/D5/D9 |
| `newBuildOperation` | Creates an already-running in-memory build Operation. | No equivalent. | Remove when `/build` becomes synchronous. | D0/D9 |
| `newRunOperation` | Creates an asynchronous `run` Operation. | No equivalent. | Remove when `/run` becomes synchronous. | D0/D9 |
| `startOperationProcess` | Shared Docker CLI process start for build and run and output attachment. | No direct equivalent. | Replace through the Docker Engine API adapter; the common Operation worker does not assume a process or a backend transport. | D0/D9 |
| `waitBuildCompletion` | Owns asynchronous build completion. | Synchronous `/build` service path. | Move into the request lifetime and direct response contract. | D0/D9 |
| `waitRunCompletion` | Owns asynchronous run completion. | Synchronous `/run` service path. | Move into the request lifetime and direct response contract. | D0/D9 |
| `operationForSession` | In-memory lookup plus Session-ID equality. | Persistent lookup plus common Operation authorization. | Replace; higher-level Release 2.1 authority must be handled without exposing foreign existence. | D0/D9 |
| `writeOperationCreated` | HTTP `201` response for `/build` and `/run`. | HTTP `202 Accepted` response for durable Commands. | Remove from the synchronous build/run path in D0; later add an accepted-response helper that sets `Location`. | D0/D9 |

Working internal boundary names such as `operationStore`, `operationWorker`, `operationHandler`, and `dockerBackend` describe separate responsibilities. They are not permission to create parallel state machines. The architect must choose final names against the code present after Release 2.1 and keep one owner for each responsibility.

## Operation type migration

| Current value | Current behavior | Release 3 mapping |
| --- | --- | --- |
| `build` | In-memory asynchronous process with status, logs, and public cancellation. | Removed from Operation types. `/build` becomes synchronous and returns bounded output and result directly. |
| `run` | In-memory asynchronous process with status, logs, and public cancellation. | Removed from Operation types. `/run` becomes synchronous and returns bounded output and exit status directly. |
| — | No managed-container lifecycle. | Add durable `container.start`, `container.stop`, `container.restart`, `container.remove`, and administrator-only `container.repair` types. `container.create` is synchronous and creates no Operation. |
| — | No Session Network. | Add durable `session.repair` only for explicit whole-network restoration when Managed Containers already depend on it; ordinary lazy provisioning remains synchronous infrastructure inside create/run. |
| — | Session rows are deleted directly. | Add `session.cleanup`. |

There are no persisted Release 2 Operation rows to migrate. Compatibility work concerns public HTTP/CLI behavior, configuration, tests, documentation, and any live-operation assumptions—not database data conversion.

## Operation API migration

| Existing surface | Release 3 surface | Action |
| --- | --- | --- |
| `POST /build` → `201`, `operation_id`, `running` | Synchronous bounded result | Breaking protocol change; preserve the normal blocking CLI experience while removing polling, logs, cancel, and Operation identity. |
| `POST /run` → asynchronous Operation | Synchronous bounded result | Breaking contract change; update handler, client, CLI, tests, docs, and agent skill together. |
| `GET /operations/{id}` | Persistent Operation lookup | Retain route; replace response schema and storage source. |
| No Operation list route | Bounded Session-scoped Operation listing | Add route and filters in the API design. |
| `GET /operations/{id}/logs?offset=N` | No generic Operation log or replay endpoint | Remove after synchronous build/run migration. |
| `POST /operations/{id}/cancel` | No public Operation cancellation | Remove; internal Session-cleanup cancellation is not an HTTP replacement. |
| No idempotency | Optional `Idempotency-Key` on durable Commands | Add at protocol admission only; after authorization, resolve an existing matching record before current-state no-op evaluation. Fresh state-matching no-ops create no record. CLI remains stateless. |

The current CLI polls status, fetches Operation logs, and can cancel both `run` and `build`. Release 3 must not leave compatibility shims that reproduce this workflow locally after the server contract changes.

## Session and ownership migration

### Existing Release 2 baseline

`Session` currently contains:

- `ID`;
- `Workspace`;
- `CreatedAt`;
- `ExpiresAt`;
- nullable `PrincipalID`;
- projected `PrincipalName`.

The SQLite `sessions` table contains `id`, `token_hash`, `workspace`, timestamps, and nullable `principal_id`. Authentication treats a row as active when `expires_at > now`. Session deletion immediately deletes the row and releases the MAC binding. Startup expiry cleanup directly deletes expired rows.

### Release 2.1 dependency

Release 2.1 is expected to add stable Launcher ownership:

- every non-legacy Session has one non-null Launcher owner;
- Principal identity is derived through Launcher;
- creator provenance is separate from owner;
- existing attributable Sessions migrate to a default Launcher;
- invalid legacy admin Sessions are removed during the 2.1 migration.

Release 3 must start from the final implementation of this model. It must not add an alternative `owner_type/owner_id` pair or preserve `principal_id` as a second authorization path.

### Release 3 extension

| Existing symbol or behavior | Release 3 action |
| --- | --- |
| `Session.PrincipalID` as direct owner | Consume the final Release 2.1 `LauncherID`; Principal is derived. |
| Row presence as lifecycle state | Add explicit teardown state required to distinguish active, closing, cleanup failure, and closed tombstone behavior. Exact schema belongs to the Session implementation design. |
| `deleteSession` / `deleteSessionForPrincipal` immediate DELETE | Replace control flow with `session.cleanup` admission and deterministic cleanup. Physical deletion occurs after successful cleanup and a fixed internal ten-minute observation grace. |
| `cleanupExpiredSessions` immediate DELETE at startup | Replace with durable cleanup admission/recovery. Expiry must not bypass container, network, publishing, Operation, or MAC cleanup. Each transiently failed attempt terminates its Operation; the Session remains `closing`, persists attempt count and retry time, and creates a new cleanup Operation when due. Ownership ambiguity remains `cleanup_failed` for Admin action. |
| `findSessionByToken` checks only expiry and Principal enabled state | Also reject non-active lifecycle states and use final Release 2.1 ownership policy. |
| `cleanupStaleSessionRuntimeDirs` treats non-active row absence as cleanup authority | Run only after durable ownership cleanup can prove the directory is stale. It must not race a retained cleanup-failure Session. |
| `sessionRuntimeDir` and Docker config directory | Retain as runtime infrastructure; they are not persistent ownership records. |

## Managed Container introduction

There is no existing Managed Container abstraction or table.

The current `run` path must not be promoted into one:

- it uses Docker `run --rm`;
- it treats the Docker container ID as a transient shutdown-cleanup handle;
- its lifecycle is owned by the Docker CLI process;
- it has no stable public resource ID or persistent ownership row.

Release 3 introduces a new persistent boundary with at least:

- ManagedContainerID;
- owning Session ID;
- nullable BackendContainerID while creation is incomplete;
- management state;
- non-secret management projection required for authorization, inspection, policy, and backend correlation;
- backend ownership metadata version;
- active lifecycle mutation Operation reference;
- creation and update timestamps required for recovery.

The exact schema and Go names belong to D1. The common source-of-truth rule is already fixed: SQLite proves ownership and Docker Engine provides current runtime observation.

Container backend access is isolated behind one docker-helper-owned adapter using the pinned official `github.com/moby/moby/client` Docker Engine API client rather than added as more unrelated `newDockerCommand` calls across handlers. The client negotiates the daemon API version; docker-helper separately documents and tests its minimum supported Engine API. The adapter reads the existing Session registry credential source just in time, passes matching authorization to pull and the required Session-scoped authorization map to build, and never forwards registry credentials to container create or run. Engine request types, response streams, credentials, and backend identifiers do not become the public domain contract.

## Configuration migration

| Existing configuration | Existing purpose | Release 3 action |
| --- | --- | --- |
| `operation_retention_ttl` | Prunes completed in-memory Operations by age. | Remove. Operation lifetime follows Session physical deletion. |
| `operation_max_completed` | Caps completed in-memory Operations. | Remove. It is not compatible with Session-owned durable history. |
| `operation_log_max_bytes` | Bounds pull output and build/run Operation buffers. | Deprecated alias for `command_output_max_bytes`; accepted with a startup warning, rejected when both names are present, and omitted from config CLI operations. |
| `audit_enabled` | Enables structured audit stream. | Retain. It is not the workload-output logging switch. |
| — | Workload-output emission to structured operational logging. | Do not add. Release 3 emits command metadata and normalized outcomes, never workload output, to daemon logs and audit. |

`command_output_max_bytes` retains the existing 4 MiB default, newest-tail behavior, `truncated` result flag, and runtime reload support. It applies to pull, synchronous build/run, and non-interactive exec.

Removal or replacement of existing keys requires config migration, `config show/set/unset`, reload behavior, man pages, completion, and tests to change together.

## Audit migration

Current `auditRecord` contains separate fields such as `principal_name`, `credential_id`, `session_id`, `request_id`, and `operation_id`; it has no generic actor or initiator structure.

Release 3 should extend the audit vocabulary without making it the Operation schema:

- Operation stores `initiator_type` and the permitted identifier needed for internal control-plane attribution, but its public projection exposes neither;
- audit records the actor representation defined by the final Release 2.1 authority model;
- audit includes public Operation type and target;
- public and audit fields never contain bearer secrets or BackendContainerID;
- workload output is not audit data.

The exact audit-field migration belongs to D9 and the security/test design. Avoid keeping `auditPrincipalName` inside the durable Operation record merely because the current in-memory struct does so.

## Test migration map

| Existing test area | Release 3 destination |
| --- | --- |
| `operationSupervisor` concurrency and terminal guards | Durable state-transition, atomic claim, worker shutdown, and process-supervision tests. |
| `build_async_test.go` | Synchronous build response, bounded output, timeout, disconnect, and exit-code tests. |
| `run` polling/log/cancel CLI tests | Synchronous run response, bounded output, timeout, disconnect, and exit-code tests. |
| `/operations/{id}/logs` tests | Remove or move only the reusable bounded-buffer cases to direct-output tests. |
| public cancel tests | Remove public-route expectations; retain process termination and internal Session-cleanup cancellation tests at their actual owners. |
| `cleanupExpiredSessions` tests | Session cleanup Operation and restart-recovery tests. |
| direct Session deletion tests | Closing, cleanup failure, closed tombstone, cascade, and authorization tests. |
| current container lifecycle tests for ephemeral `run --rm` | Keep as one-shot run regression tests; do not treat them as Managed Container lifecycle coverage. |

## Confirmed implementation blockers

The code comparison exposes the following decisions that must be settled before broad executor implementation begins.

### 1. Release 2.1 implementation baseline

Launcher and final Session ownership names are design-only at the inspected commit. D1 and D0 persistence migrations must be based on the final Release 2.1 schema, not written against nullable Release 2 `principal_id` ownership.

### 2. Engine adapter compatibility spike

The backend technology and client are settled. Before broad migration, a focused spike must verify `ImageBuild` stream and error handling against the project's BuildKit-enabled and legacy test environments, private pull and private `FROM` authorization from the existing Session credential source, and one documented minimum Engine API version from the supported daemon matrix. Production migration then moves pull/build directly to their synchronous Engine API path; it must not reproduce the legacy asynchronous workflow on the new backend. This may refine the narrow adapter, not the public capability or credential contracts.

## Executor handoff gate

The operational architect may issue code-reading and D1 interface-design tasks from this map. Ordered D0 implementation and verification tasks are defined in `release-3-d0-execution-plan.md`.

Production implementation tasks that depend on the following must wait until the corresponding blocker is resolved:

- D0 durable persistence and D1 ownership: final Release 2.1 Session/ownership schema;
- D0 synchronous migration: the official Moby client adapter, minimum Engine API version, and ImageBuild compatibility evidence.

When the Release 2.1 commit is available, update the baseline commit and replace every design-only Launcher or Session mapping with the actual symbol, table, column, and migration names before implementation starts.
