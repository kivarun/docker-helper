# Release 3 D0 Execution Plan

## Status and baseline

This document owns the executor-facing sequence for D0. It is bound to the
verified Release 2.1 code baseline, not to an earlier planning snapshot.

Phase-0 inspected baseline:

- repository: `kivarun/docker-helper`;
- branch: `main`;
- code/document baseline at Phase-0 close: the head of the Phase-0
  documentation series on `main`; the full SHA is recorded in
  `docs/release-3-vocabulary-and-implementation-map.md`;
- Release 2.1 production behavior is the parent code at
  `54cc853c87ad3706dfe28829a0147a0dc62afbc6`; every commit above it is
  documentation only: the consolidated final 2.1 changelog and the Release 3
  Phase-0 design reconciliation.

If `main` moves before an executor starts D0, the executor must compare the new
head with this baseline and stop on any change touching the owners listed
below. Replacing the SHA without rechecking owners is not sufficient.

`docs/architecture.md` is current-state truth. This document and the other
`release-3-*` documents describe target Release 3 behavior.

## Phase-0 findings that change the old D0 map

The current implementation is materially different from the earlier planning
baseline:

- Session deletion is owned by `deleteSessionScoped`; the old
  `deleteSession` / `deleteSessionForPrincipal` split no longer exists.
- `operationSupervisor` is not only the legacy build/run registry. It also owns
  the per-Launcher operation-admission quiesce, `hasRunningForLauncher`, and the
  admission state used by checked Launcher/Principal lifecycle in
  `launcher_lifecycle.go`.
- Launcher/Principal disable currently deletes child Session rows inside the
  parent lifecycle transaction and releases MAC bindings afterwards.
- startup expiry and the offline `session cleanup` path still physically delete
  expired Session rows.
- current Session MAC/runtime reconciliation uses row presence and
  `expires_at`; that is insufficient once `closing` and `cleanup_failed`
  Sessions continue to own resources.
- registry login currently stores Session-scoped Docker credentials under the
  Session runtime directory and Docker CLI `--config` consumes them. Moby API
  calls will not inherit that behavior automatically.
- production has no Moby dependency and no aggregate cgroup hierarchy yet.

D0 must transfer these responsibilities exactly once. No executor may remove
`operationSupervisor` until every non-legacy responsibility below has its final
owner and tests.

## Fixed Release 3 execution split

There are three different responsibilities and exactly three final owners:

1. **Synchronous execution coordination** owns live `pull`, `build`, one-shot
   `run`, and later non-interactive exec request contexts, daemon-shutdown
   admission, cancellation, bounded response output, and backend-resource
   cleanup needed to establish a synchronous postcondition. It has no public
   Operation identity, retention, retry, or lookup.
2. **Durable Operation store/dispatcher** owns persisted lifecycle work for
   `container.start`, `container.stop`, `container.restart`,
   `container.remove`, `container.repair`, `session.repair`, and
   `session.cleanup`. It owns durable admission, idempotency, claim/recovery,
   terminal state, and worker shutdown semantics. It stores no workload output
   or registry secret.
3. **Session lifecycle service** owns the active -> closing -> cleanup_failed /
   closed state machine, Session bearer invalidation, expiry claiming, manual
   and automatic cleanup-attempt admission, parent-lifecycle propagation,
   tombstone purge, runtime/MAC release ordering, and the coordination needed
   to prevent new work after closure is claimed.

The old `operationSupervisor` is not any of these final owners. Its
responsibilities are transferred as follows:

| Current responsibility | Current owner | Final owner | Old path removed when |
| --- | --- | --- | --- |
| build/run public status, logs, cancel, retention | `operationSupervisor` + `operation` | none | build/run are synchronous and protocol/tests are migrated |
| daemon-shutdown admission for live one-shot work | `operationSupervisor.admit` / `beginShutdown` | synchronous execution coordinator | pull/build/run all use the coordinator |
| process/container cancellation and force cleanup | `operationSupervisor.terminate*` | synchronous execution coordinator plus command-specific cleanup | Engine-backed paths prove the same bounded postconditions |
| Launcher admission quiesce (`quiesceLauncher`, `setQuiesced`) | `operationSupervisor` used from `launcher_lifecycle.go` | Session/lifecycle admission owner shared by synchronous execution and durable Operation admission | both admission classes consult the durable/current owner state under one lifecycle boundary |
| active execution check for checked parent lifecycle (`hasRunningForLauncher`) | `operationSupervisor` | synchronous execution coordinator for transient work + durable Operation store for durable work; the parent lifecycle service consumes one combined query | checked delete/disable tests prove neither class is missed |
| build/run temporary pin/staging/MAC handles | `operation` fields and domain code | build/run domain cleanup; Managed Container mount/MAC lifetime belongs to the Managed Container/Session lifecycle | no temporary handle is retained merely to keep the old supervisor alive |

The replacement admission owner must not create a generic fourth framework.
It may be a narrow lifecycle admission service in `package main`; its API is
only the checks needed by synchronous execution, durable Operation admission,
and parent lifecycle.

## Session lifecycle transition required by D0

D0 persistence is introduced against a Session row that must survive owned
resource cleanup. Therefore the Session lifecycle schema and cleanup claim are
a prerequisite to making `session.cleanup` a production Operation.

### Ownership anchor

A Session row remains the ownership anchor from creation until successful
cleanup has completed and the fixed closed-tombstone grace has expired.

- `active`: bearer may authenticate and new work may be admitted.
- `closing`: bearer is invalid; ownership remains; cleanup may be active,
  waiting for retry, or awaiting a manual retry.
- `cleanup_failed`: bearer is invalid; ownership remains; automatic cleanup is
  stopped because ownership/policy ambiguity requires administrator action.
- `closed`: all owned backend/runtime/MAC resources are proven absent; bearer
  remains invalid; the row is retained for the fixed ten-minute observation
  grace and then physically purged.

A Session is never reactivated from `closing`, `cleanup_failed`, or `closed`.
Re-enabling its Principal or Launcher only permits future work/new Sessions; it
never revives a claimed Session.

### All current invalidation paths

Every current physical-delete path is replaced by one Session-lifecycle owner:

| Current path | Release 3 behavior |
| --- | --- |
| `DELETE /sessions/{id}` -> `deleteSessionScoped` | scope-resolve through the existing owner, claim `active -> closing`, invalidate bearer, admit/return `session.cleanup`; never delete the row before cleanup |
| startup `expires_at <= now` deletion | claim due active Sessions and recover/admit durable cleanup after schema migration and handler registration |
| offline `docker-helper session cleanup` | never delete an active/closing/cleanup_failed Session; offline mode may only purge already-closed tombstones whose fixed grace elapsed; daemon-owned cleanup is required for resource teardown |
| Launcher disable | close new Launcher admission, atomically claim its active Sessions for cleanup, retain Launcher and Session ownership; do not delete Session rows |
| Principal disable | close admission for all child Launchers, atomically claim their active Sessions, retain ownership chain; do not delete Session rows |
| Launcher/Principal delete | checked physical delete only after there are no child Session rows (including closed tombstones); while Sessions remain, return a stable conflict and do not cascade away ownership |

Parent disable is the teardown trigger; parent delete is a checked ownership
removal. This avoids creating a parent-delete Operation type and preserves
`Principal -> Launcher -> Session` until Session cleanup is observable.

### Repeated closure and cleanup

- first explicit close of an active Session returns `202` with the admitted
  `session.cleanup` Operation;
- repeated close while one cleanup Operation is active returns that same active
  Operation and does not create parallel work;
- after a transient failed cleanup attempt, an owning Principal/Launcher or
  administrator may request an immediate new attempt when none is active; the
  automatic retry schedule may independently create the next attempt when due,
  with one transaction deciding the winner;
- `cleanup_failed` does not auto-retry. After the administrator resolves the
  ambiguity, an administrator may request a new cleanup attempt; the previous
  Operation remains immutable history;
- close of `closed` is a successful `204` while the tombstone exists;
- after physical tombstone purge, absent and foreign Sessions are the same
  `404 session_not_found`.

### Migration and startup order

R3 startup ordering is binding:

1. open SQLite and enable foreign keys;
2. apply the Session lifecycle/schema migration without deleting expired rows;
3. materialize/validate the new R3 configuration defaults exactly once: the
   Root resource ceiling computed from Engine-reported capacity, the Root
   publishing grant, and the Principal/Launcher Session-count quotas
   materialized as 100 and 20. Existing Session rows are counted against the
   materialized quotas immediately, including rows that later startup steps
   claim as `closing`; new Session admission stays blocked until counted
   population falls below an effective quota. A failed materialization leaves
   the previous configuration unchanged and fails startup closed;
4. register durable Operation handlers and validate persisted type/payload
   versions;
5. recover interrupted `creating` Managed Containers before Session cleanup can
   make an ownership decision about them;
6. recover `running` durable Operations;
7. claim expired active Sessions and admit/recover `session.cleanup` work;
8. reconcile Session runtime/MAC state using lifecycle ownership, not
   `expires_at` alone;
9. dispatch pending Operations and only then open normal admission/listeners.

No startup helper may classify `closing` or `cleanup_failed` state as stale
merely because `expires_at` is in the past.

### Runtime and MAC lifetime

Release 2.1 Session workspace MAC state is released only after Session cleanup
proves that every Session-owned resource needing that boundary is absent.
A transient/ambiguous cleanup failure retains the boundary.

Managed Container system-mode mount pins and any Managed-Container-specific MAC
state are lifetime resources, not one start-attempt resources:

- create establishes the durable correlation needed to recreate/verify runtime
  attachment safely;
- stop does not release ownership state needed for a later start;
- start/restart may create transient attach handles, but the persistent owner is
  the Managed Container/Session, not an Operation;
- daemon restart re-discovers/re-establishes required pins/MAC state from
  persistent ownership and exact backend evidence before mutation;
- container remove releases container-specific state only after backend absence
  is proved;
- Session cleanup releases remaining container/runtime state before releasing
  the Session workspace MAC binding.

The current `cleanupStaleSessionRuntimeDirs` and MAC reconciliation paths must
be changed to query lifecycle ownership. Row absence/closed-after-grace is the
stale authority; expired time alone is not.

## Docker Engine adapter gate: D0.1

D0.1 remains the single Engine-adapter compatibility gate. Do not create a
second spike/task for the same questions.

Before D0.2 changes a production backend path, D0.1 must record reproducible
results for one reviewed `github.com/moby/moby/client` version against the
repository Go toolchain and supported Engine matrix:

- dependency version and successful `go test`, `go test -race`, and `go vet`;
- minimum supported Docker Engine API and negotiation against one newer Engine;
- BuildKit-enabled `ImageBuild` plus the supported legacy-build behavior;
- public pull and build, private pull, and private `FROM` build;
- Session credential parsing/storage, exact registry matching, pull auth
  encoding, build auth map, and secret canaries absent from SQLite/log/audit/
  public errors;
- request cancellation and daemon-shutdown cancellation;
- one-shot container create/start/wait/remove after disconnect and shutdown;
- stream framing/decoding and typed error classification;
- logs and exec primitives needed by later packages.

`registry login` is part of this migration map, not an implicit leftover CLI
path. Its target owner validates credentials through the adapter, writes only
the protected Session credential store, and later pull/build calls read that
store just in time. No Session registry credential enters durable Operations.

At the Phase-0 baseline there is no Moby dependency in `go.mod` and no
repository evidence satisfying this gate. **D0.1 is OPEN.** This is a production
migration blocker, not an architecture blocker: its contract is fixed here.

## Resource-enforcement prerequisite

The cgroup hierarchy feasibility proof moves from the late D7 risk list to an
input gate for any production path that claims R3 workload/resource enforcement.
It is not a second resource architecture package.

Before D0.3 can be accepted as a Release-3-compliant one-shot `run`, and before
D1/D2 Managed Container creation/start is accepted, a reproducible real-host
spike must prove:

- aggregate CPU, memory, and PIDs hierarchy `Root -> Principal -> Launcher ->
  Session`;
- Docker placement below the verified Session cgroup while concrete Docker
  workload limits are also applied;
- sibling workloads cannot exceed the parent aggregate ceiling;
- system deployment under the shipped systemd hardening and both supported MAC
  backends where applicable;
- supported rootless/user deployment, including controller delegation;
- daemon restart with existing stopped/running Managed Container placement;
- container/Session cleanup without leaked cgroups;
- fail-closed behavior when a required controller or placement cannot be
  proved.

At the Phase-0 baseline no checked-in result proves this matrix. **The cgroup
feasibility gate is OPEN.** User-mode/rootless remains mandatory for R3; failure
of the spike therefore requires an architecture escalation under `AGENTS.md`,
not a silent system-mode-only implementation.

## Ordered implementation tasks

### D0.1 — freeze and prove the Engine API boundary

Run the compatibility gate above. Pin the reviewed Moby client only after the
matrix passes. No production migration is part of this step.

**Gate:** reproducible evidence for all D0.1 bullets; otherwise stop.

### D0.2 — migrate registry login + pull, then synchronous build

Dependencies: D0.1 closed.

1. add the narrow adapter and the Session registry-credential bridge;
2. migrate `registry login` validation/storage through the adapter without
   changing its Session-secret boundary;
3. migrate pull with matching Session authorization only;
4. migrate build synchronously with the Session build-auth map;
5. transfer build request/shutdown cancellation to the synchronous execution
   coordinator;
6. remove build use of `operationSupervisor` and its public Operation
   status/log/cancel path once tests pass.

**Ready boundary:** pull/registry/build have exactly one backend owner and build
has no Operation identity. Legacy run may still use the old supervisor, so the
supervisor itself remains.

### D0.3a — establish Session lifecycle persistence and cleanup admission

Dependencies: D0.1 closed; durable Operation schema primitives may be added in
this step or D0.5 but there is one final store.

- add Session lifecycle fields/state and migrate every 2.1 Session as `active`;
- replace startup/offline immediate expiry deletion with lifecycle-aware claim;
- replace `deleteSessionScoped`'s physical DELETE with scope resolution plus
  cleanup claim;
- change Principal/Launcher disable and delete semantics as specified above;
- make MAC/runtime reconciliation lifecycle-aware;
- implement explicit Session renewal in the same lifecycle owner, serialized
  with expiry claiming and computed from the current global `session_ttl`
  (no delegated, per-owner, or caller-selected TTL);
- add the final `session.cleanup` admission/retry/tombstone contract.

**Ready boundary:** no production path can erase a Session ownership row before
resource cleanup. No Managed Container functionality is required yet.

### D0.3b — make one-shot run synchronous without claiming R3 resource readiness

Dependencies: D0.1 closed. The cgroup feasibility gate must also be closed
before this path is declared Release-3-ready.

- migrate one-shot run to the adapter/coordinator;
- preserve UID/GID, workspace/mount policy, pinning, CA injection, cleanup,
  audit, and exit-code behavior;
- remove run Operation identity and polling/cancel API use;
- keep the path behind the D0 readiness gate until resource hierarchy and
  explicit workload-limit enforcement are implemented together.

There is no interval in which an Engine-backed `run` that lacks mandatory R3
resource enforcement is advertised as the completed R3 contract.

### D0.4 — remove legacy public/in-memory Operation

Dependencies: D0.2 and D0.3b callers migrated; Launcher quiesce/active-execution
responsibilities transferred to their final owners.

Remove legacy `/operations/{id}/logs`, public cancel, build/run polling,
in-memory retention, `operation_retention_ttl`, `operation_max_completed`, and
all `operationSupervisor` code/tests that no longer protect an observable
invariant. Rename `operation_log_max_bytes` to `command_output_max_bytes` under
the accepted compatibility rule.

**Gate:** production search finds no legacy Operation owner and parent lifecycle
still sees/quiesces both transient and durable work.

### D0.5 — durable Operation persistence and dispatcher

Dependencies: Session lifecycle ownership anchor exists.

Add the one SQLite-backed Operation/idempotency model, bounded typed payloads,
conditional claims, one handler registry with `Execute`/`Recover`, one bounded
dispatcher, startup recovery-before-pending ordering, terminal immutability, and
Session-scoped read/list/wait API. Unknown persisted types/versions fail
startup.

Do not create a fake production Operation type. Generic behavior may use
package-local test handlers until `session.cleanup` is wired.

### D0.6 — wire `session.cleanup` as the first real durable handler

The handler consumes the Session lifecycle owner and proves D0 against a real
resource owner. In the pre-D1 state it cleans existing Session runtime/MAC
resources; D1-D3 extend the same handler with Managed Containers/network/leases
rather than replacing it.

This step is where old immediate Session deletion becomes unreachable in
production.

### D0.7 — final D0 integration

- remove obsolete config/help/man/README/skill contracts;
- prove shutdown leaves unfinished durable work recoverable;
- prove Session teardown cancels pending/running Operations at type-safe points;
- prove no registry secret/workload output/raw backend ID enters durable rows;
- run core gates and the full affected UAT matrix.

## Required checks

Every D0 production commit/series ends with:

```text
gofmt
go test ./...
go test -race ./...
go vet ./...
git diff --check
```

Plus applicable real Engine/host/package tests. Tests preserve observable
invariants, not `operationSupervisor` implementation details.

Required migration/regression cases include:

- final 2.1 database -> R3 migration with active and already-expired Sessions;
- explicit close, TTL expiry, Principal disable, Launcher disable, and daemon
  restart all converge on the same Session cleanup owner;
- parent delete cannot erase Sessions in `closing`, `cleanup_failed`, or
  `closed` grace;
- parent re-enable never revives a claimed Session;
- offline cleanup cannot bypass durable ownership cleanup;
- cleanup retry races produce one active attempt and immutable prior attempts;
- MAC/runtime state remains owned through transient and ambiguous failure;
- old build/run supervisor cannot be removed while Launcher admission/runtime
  inspection still calls it;
- private pull/private `FROM` plus registry-login secret canaries;
- rootful/rootless cgroup enforcement before R3 run/container readiness.

## D0 start gate after Phase 0

Architecture and ownership questions are closed by this document and its
companion Phase-0 reconciliations. Production D0 must **not** begin at D0.2.
The exact next executable step is D0.1 Engine compatibility evidence, in
parallel only with the independent cgroup feasibility spike. D0.2 waits for
D0.1; D0.3b/D1/D2 readiness also waits for the cgroup gate.
