# Release 3 Vocabulary and Implementation Map

## Purpose and inspected baseline

This document maps accepted Release 3 concepts to the implementation that
actually exists immediately before D0. It prevents executors from inventing
wrappers, reviving retired symbols, or leaving old and new responsibility
owners active together.

Inspected baseline:

- repository: `kivarun/docker-helper`;
- branch: `main`;
- Phase-0 start SHA: `5dbccdfbc71df9b00639f46bff48ed8201966578`;
- Phase-0 close SHA: `71b6a96d3367d76d4bef2c675ee8686ce9aebe12`;
- Release 2.1 production parent: `54cc853c87ad3706dfe28829a0147a0dc62afbc6`.

Every commit between the Phase-0 start and close SHAs is documentation only:
the consolidated final 2.1 changelog and the Release 3 Phase-0 design
reconciliation. The previous `44281a8` binding is obsolete. If `main` changes
before executor handoff, compare the new head with the Phase-0 close SHA and
revalidate every touched owner below; new documentation-only commits do not
change the ownership facts. A SHA-only edit is not a rebaseline.

`docs/architecture.md` owns implemented truth. Release-3 documents own target
behavior.

## Canonical vocabulary

| Term | Meaning | Current implementation | Release 3 owner/rule |
| --- | --- | --- | --- |
| Request / Response | transport messages | HTTP structs/handlers | transport only; no application base class |
| Command | application action/effect | usually handler/domain function | conceptual role; no mandatory interface |
| Query | read-only observation | handler/domain query | never creates Operation for uniformity |
| Operation | durable record for selected asynchronous Commands | current `operation` is an in-memory build/run process record | SQLite-backed Session-owned state for container start/stop/restart/remove/repair, session repair/cleanup only |
| Operation type | bounded discriminator | `operation.Kind` = build/run | public/internal discriminator is `type`; old values disappear |
| Managed Container | durable Session-owned container identity | absent | new `dhmc_...` object; not Docker ID or Operation |
| Session | authorization/ownership/lifetime boundary | `Session`, `sessions.launcher_id NOT NULL` | gains lifecycle state and remains ownership anchor through cleanup |
| Launcher | stable Session owner under Principal | implemented Release 2.1 object | retained; no parallel R3 owner model |
| Principal | OS identity and delegation ceiling | implemented | retained, derived parent of Session through Launcher |
| Credential | rotatable bearer, never resource owner | Principal or Launcher credential rows | retained; Session bearer remains data-plane authority |
| Initiator | who admitted durable work | not persisted by current Operation | internal Operation provenance, not ownership |
| Target | public resource affected by Operation | absent generic field | typed public ID, never BackendContainerID |
| Condition | stable mismatch/repair reason | ad-hoc current runtime errors | bounded R3 condition vocabulary; observation does not mutate |
| Session Network | Session-owned backend infrastructure | absent | one lazy bridge per Session; repaired/removed through Session lifecycle |
| Resource ceiling | aggregate authority | absent | Root -> Principal -> Launcher -> Session cgroup hierarchy |
| Session quota | capacity-bearing Session count ceiling | absent | daemon/Root/Principal/Launcher atomic create admission |
| Workload limit | concrete per-container/run limit | only `shm_size` today | CPU/memory/PIDs/shm + swap disabled |
| Publishing grant / lease | host-port authority / concrete allocation | absent | hierarchical grant + Managed-Container-lifetime lease |
| Interactive Stream | WebSocket exec transport | absent | not Operation, owner, or durable record |

Naming rules remain those in `AGENTS.md`: one concept/one term, `type` rather
than `kind` for R3 Operation discrimination, no generic `Owner`, `Resource`,
`Job`, or `Task` hierarchy, and no backend identifier promoted to public
identity.

## Current ownership facts that D0 must respect

### Session ownership and deletion

Current Session ownership is already canonicalized through:

- `Session.LauncherID`;
- `sessionOwnershipProjection` joining Session -> Launcher -> Principal;
- `resolveSessionControlScope` / `resolveSessionListScope` for authority;
- `deleteSessionScoped` for scoped physical Session deletion.

The old map's `deleteSession` / `deleteSessionForPrincipal` replacement task is
stale. They are not the production owner to migrate.

Target transition:

| Current symbol/behavior | Final action |
| --- | --- |
| `deleteSessionScoped` selects scope then physically deletes | retain its scope/non-disclosure responsibility; replace the physical DELETE stage with Session close/cleanup claim |
| row presence + `expires_at` represent usable lifetime | add lifecycle state `active`, `closing`, `cleanup_failed`, `closed`; only `active` authenticates/admit normal work |
| startup expiry physically deletes rows | claim expired active Sessions for durable cleanup after migration/handler recovery |
| offline `session cleanup` deletes expired rows | restrict offline mutation to purging already-closed tombstones after grace; backend cleanup is daemon-owned |
| `findSessionByToken` uses existence/expiry/owner enablement | also require lifecycle `active` |
| runtime-dir stale cleanup uses absence/expiry assumptions | lifecycle-aware: `closing` and `cleanup_failed` still own runtime state |
| Session MAC release follows immediate deletion/invalidation | move release to successful Session cleanup after all dependent resources are absent |

Physical Session deletion happens only after successful cleanup and the fixed
closed-tombstone grace.

### Parent lifecycle

`launcher_lifecycle.go` currently owns the serialized Release 2.1 parent
lifecycle. Important production facts:

- `persistLauncherChange` collects and physically deletes Launcher Sessions on
  disable;
- `applyLauncherEnabledChange` / lifecycle paths release deleted Session MAC
  bindings after commit;
- checked deletion quiesces Launcher operation admission before inspecting
  runtime;
- `inspectLauncherRuntime` checks both in-memory running Operations and Docker
  helper containers;
- parent deletion is protected by `lifecycleMu` and checked runtime evidence.

R3 retains `lifecycleMu` as the existing serialization owner unless a concrete
implementation proves a narrower replacement. It does not add a second parent
lifecycle framework.

Target change:

- disable closes admission and claims child active Sessions; it does not delete
  their rows;
- re-enable never revives a claimed Session;
- parent physical delete is checked and cannot cascade a Session row that still
  exists (`active`, `closing`, `cleanup_failed`, or `closed` grace);
- parent cleanup/runtime inspection consumes one combined view of transient
  synchronous execution and durable Operations.

### `operationSupervisor` is wider than legacy build/run

At the Phase-0 baseline `operationSupervisor` owns:

- in-memory build/run registry and public status/log/cancel;
- bounded log-buffer retention/pruning;
- daemon shutdown admission and process/container termination;
- per-Launcher `quiesced` admission state;
- `quiesceLauncher` / `setQuiesced` used by Launcher disable/delete;
- `hasRunningForLauncher` used by checked parent deletion.

Therefore D0 may not simply delete it after synchronous build/run migration.
Responsibility transfer is:

| Current responsibility | Final owner |
| --- | --- |
| build/run public Operation API | removed |
| live synchronous admission/shutdown | synchronous execution coordinator |
| one-shot backend cleanup | synchronous command domain + coordinator |
| Launcher admission closure | Session/lifecycle admission owner consulted by both synchronous and durable admission |
| running transient work by Launcher | synchronous execution coordinator query |
| running durable work by Launcher | durable Operation store/dispatcher query |
| checked parent runtime decision | `launcher_lifecycle.go` consumes the combined result; it does not inspect two private stores itself |

The old supervisor type/name is removed only after all rows in this table have
production replacements and regression coverage.

## Backend migration map

The Phase-0 baseline invokes Docker CLI and `go.mod` contains no Moby client.
Release 3 uses one narrow official Moby adapter. Domain services own policy and
public classification; adapter methods own only Engine protocol mechanics.

| Capability | Current mechanism | Target migration |
| --- | --- | --- |
| pull | Docker CLI + Session `--config` | Engine ImagePull with exact matching Session registry auth |
| registry login | Docker CLI login writes Session runtime Docker config | adapter validates/login interaction; protected Session credential store remains source for later pull/build |
| build | Docker CLI + staged context + in-memory Operation | synchronous Engine build; Session auth map for private `FROM`; staging/MAC cleanup stays build-owned |
| one-shot run | Docker CLI + cidfile + in-memory Operation | synchronous Engine create/start/wait/remove; pins/MAC cleanup stays run-owned |
| checked parent runtime | Docker CLI inspection | later adapter observation with same fail-closed classification |
| Managed Container lifecycle/logs/exec/network | absent | later packages consume the same adapter; no second Engine client boundary |

Registry credentials remain Session runtime secrets, never SQLite Operation
payload. D0.1 must prove parsing, exact registry matching, auth propagation,
private pull/private `FROM`, and secret exclusion before production migration.

## Durable Operation target map

The current `operation` type is not adapted in place. It is split.

| Existing symbol/field | Target | Action |
| --- | --- | --- |
| `operation` | durable row only | replace; no mutex/process/channel/output/temp handles |
| `operationSupervisor.ops` | SQLite Operation source of truth | replace |
| `operationSupervisor.admit` | durable transactional admission or synchronous live admission | split; never one ambiguous method |
| `lookup` / public build-run operation routes | durable lookup only for R3 Operation types | remove legacy route semantics, then add durable read surface |
| `pruneCompleted` | none | remove; Operation lifetime is Session lifetime |
| public `cancel` | none | remove; Session teardown uses internal typed cancellation only |
| `terminateForShutdown` | synchronous execution shutdown + durable handler shutdown/recovery | split by cause; daemon stop never fabricates durable cancellation |
| `Kind` | Operation `type` | replace |
| `LogBuffer` | direct bounded command output | move out of durable model |
| `ExitCode`, build/run metadata | synchronous result/request data | move out of Operation |
| temporary pins/staging/MAC lease handles | command/Managed-Container lifecycle owners | move; never persist as generic Operation handles |

Durable Operation persistence owns: Session FK, type/payload version, status,
initiator provenance, target, normalized bounded input/recovery data,
idempotency association, timestamps, and exactly one terminal result/error/
cancellation payload. It stores no workload output, registry credential, bearer,
or public backend ID.

## Session cleanup and resource lifetime map

R3 `session.cleanup` is the convergence owner for all Session teardown causes:
explicit close, TTL expiry, Principal disable, Launcher disable, startup
recovery, and manual retry.

Ordering is:

1. Session is claimed (`active -> closing`) and bearer/admission closes;
2. pending/running durable Operations receive the common Session-closing
   cancellation protocol;
3. exec/synchronous activity is terminated through its resource lifecycle;
4. unresolved `creating` Managed Containers are recovered/classified;
5. verified Managed Containers are stopped/removed and their lifetime pins/MAC
   state and port leases are released only after backend absence;
6. Session Network is removed after containers;
7. Session runtime credential/config artifacts are removed;
8. Session workspace MAC binding is released last;
9. Session becomes `closed` with `last_cleanup_operation_id`;
10. fixed-grace purge physically deletes the Session and cascades durable rows.

Transient failure leaves `closing` and retains ownership. Ownership ambiguity
sets `cleanup_failed` and retains everything required to prove/repair ownership.

## Managed Container mount/MAC ownership

Current system-mode one-shot run pins mount sources for one live operation.
That mechanism cannot be copied blindly to long-lived Managed Containers.

Target ownership:

- persistent Managed Container/Session state owns the requirement for the
  mount/MAC boundary;
- start/stop Operations do not own the lifetime pin;
- stop preserves the durable mount policy needed for later start;
- daemon restart verifies/re-establishes required helper-owned runtime pins
  before mutating the container;
- remove releases container-specific pin/MAC state only after exact backend
  absence;
- Session cleanup is the final fallback owner and releases Session MAC last.

Exact kernel-handle mechanics remain an implementation choice, but losing a
helper process must not silently make a still-owned Managed Container writable
through a less-safe pathname fallback.

## Configuration and policy ownership

Current `config.go` owns flat configuration, validation, reloadability, and
CLI field vocabulary. R3 extends that owner; feature packages do not parse
config independently.

New Root resource defaults and Session quota defaults are materialized or
normalized by the config owner once. Principal/Launcher/Session explicit policy
lives with those resources in SQLite. No child stores a copied effective value
as a second authority.

The exact public R3 config fields and upgrade behavior are canonical in
`release-3-api-cli.md` and resource semantics in
`release-3-resource-constraints.md`.

## Preconditions and open gates

### D0.1 Engine adapter

No checked-in evidence at the inspected baseline proves the selected Moby
version, minimum Engine API, BuildKit/legacy build behavior, private pull,
private `FROM`, cancellation, or cleanup matrix. `go.mod` has no Moby client.
The single D0.1 gate in `release-3-d0-execution-plan.md` is therefore **OPEN**.

### Aggregate cgroup enforcement

No checked-in result at the inspected baseline proves the mandatory aggregate
CPU/memory/PIDs hierarchy and Docker placement in both system and supported
rootless/user deployment. The feasibility gate defined by
`release-3-resource-constraints.md` and moved forward by the D0 plan is
therefore **OPEN**.

Neither gate authorizes an executor to invent weaker semantics. A failed
mandatory mode is an `AGENTS.md` architecture escalation.

## Executor handoff rule

Before editing a production owner, the executor records:

1. source symbol/file from this map;
2. final owner from this map/D0 plan;
3. dependencies/gates;
4. the commit where the old path becomes unreachable;
5. the observable test that proves transfer.

A task is incomplete while two production owners enforce the same policy or
while removal of an old owner would lose one of its listed responsibilities.
