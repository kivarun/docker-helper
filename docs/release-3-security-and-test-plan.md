# Release 3 Security and Test Plan

## Purpose

This document defines the cross-cutting security model and release-verification
gate for Release 3. It does not replace the capability-specific verification
requirements in the other Release 3 design documents. It connects those
requirements into one threat model, environment matrix, and acceptance process.

The implementation baseline is Release 2.1 at
`694ca5944c87b17303b761c5f38e4afd390a7d89`. Release 3 must preserve the
authentication, workspace, MAC, secret-handling, packaging, and deployment
boundaries already established there while adding Managed Containers, durable
Operations, Session networking, exec, resource ceilings, and loopback port
publishing.

Exact test-file names, Go structures, SQL DDL, fault-injection seams, and CI job
layout are implementation decisions for the operational architect. The
observable security properties and release gates in this document are binding.

## Security objective

Release 3 gives an authenticated caller only the capabilities authorized by its
credential and owning Session. It must not turn the Docker Engine API migration,
long-lived containers, streaming, or durable work into a route around the
existing authorization and confinement model.

The release must prove that:

- every Managed Container, Operation, Session Network, port lease, and runtime
  policy object has one unambiguous docker-helper owner;
- credential scope can be narrowed by selectors but never expanded;
- foreign and nonexistent resources remain indistinguishable at public
  boundaries;
- backend identity and mutable Docker state never replace SQLite ownership or
  authorization;
- out-of-band backend changes are observed and classified without autonomous
  repair or deletion;
- Session expiration and closure eventually remove every resource whose
  ownership can be proved, while ambiguity fails closed;
- host filesystem, network, process, and resource access remain inside the
  accepted Release 3 policy;
- workload-controlled data and credentials do not enter durable state, audit,
  operational logs, or public errors;
- every input, output, queue, concurrency class, retry delay, scan, and shutdown
  wait has an explicit bound.

## Trust boundaries

| Boundary | Trusted authority | Untrusted or fallible side | Required behavior |
| --- | --- | --- | --- |
| Client to HTTP/WebSocket | docker-helper authentication and authorization | bearer holder, request fields, frames, disconnect timing | Authenticate before target disclosure; validate and bound all input; never infer broader scope from client data. |
| SQLite to Docker Engine | SQLite public identity, ownership, policy, and correlation records | Docker runtime state and objects changed outside docker-helper | Resolve from SQLite first; inspect the exact recorded backend object; verify immutable ownership metadata before mutation. |
| Session to host filesystem | canonical workspace and accepted mount policy | paths, symlinks, image behavior, concurrent filesystem changes | Preserve path pinning and MAC lifecycle; never broaden allowed roots or mount authority. |
| docker-helper to Engine API | one docker-helper-owned adapter and configured daemon endpoint | Engine availability, version, streams, errors, partial effects | Normalize typed failures, compensate partial effects, and keep Moby types and raw errors out of public contracts. |
| Policy hierarchy to workload | Root, Principal, Launcher, and Session ceilings | caller-requested limits and concurrent workloads | Revalidate every ancestor at admission; apply concrete workload limits; enforce aggregate ceilings fail closed. |
| Session network to host network | one Session-owned bridge and explicit loopback leases | workload traffic, foreign Docker objects, unrelated host listeners | Isolate Sessions; expose only allowed TCP ports on `127.0.0.1`; never claim control over foreign listeners. |
| Workload I/O to client | bounded direct response or bounded interactive relay | stdout, stderr, terminal input, Docker frames, stalled peers | Combine output in Engine order, enforce byte/queue/time bounds, and retain no replayable workload history. |
| Audit to operator storage | normalized docker-helper event schema | initiator-controlled values and backend error text | Record public ownership and initiator attribution without secrets, workload data, backend IDs, or copied inspect/error payloads. |

The host administrator and docker-helper administrator remain trusted policy
authorities. Docker Engine is a privileged backend whose availability and
runtime observations are required, but it is not an authorization source. A
user with independent Docker or host-administrator access can change or remove
backend objects; Release 3 detects relevant divergence but does not attempt to
make such access harmless.

The Root resource ceiling covers docker-helper-managed workloads only. It does
not reserve host capacity and does not constrain unrelated host processes,
containers created outside docker-helper, or the Docker daemon itself.

## Security invariants by concern

### Authentication, scope, and non-disclosure

- Administrator tokens, Principal credentials, Launcher credentials, and
  Session tokens use the existing
  authentication owners and revocation semantics.
- Credential scope can authorize control-plane management. The Session token
  authorizes Session workload execution: `pull`, `build`, `run`,
  `registry login`, and both exec modes require a Session bearer. A valid
  Principal or Launcher credential presented directly to a Session
  data-plane endpoint is rejected and is never converted into Session
  execution authority by inference.
- Authorization is evaluated against current durable ownership and policy at
  admission, not copied indefinitely from an earlier authentication result.
- A Session-local name is resolved only inside an explicit or unambiguous
  credential-implied Session. Ambiguity is an error, never a selection rule.
- IDs and optional narrowing flags never expand the credential's subtree.
- Ordinary APIs expose no existence distinction between absent, foreign, and
  out-of-scope resources.
- Administrator-only orphan and force-recovery surfaces are explicit exceptions
  with narrow request and audit contracts; they do not grant adoption.

### Durable ownership and backend correlation

- ManagedContainerID, OperationID, SessionID, LauncherID, and BackendContainerID
  remain distinct types and fields.
- Docker names, aliases, image names, labels supplied by a caller, and object
  similarity never prove ownership.
- Mutations use the exact BackendContainerID recorded for the authorized public
  object and require the complete immutable ownership-label set.
- Missing, ownership-mismatched, policy-mismatched, and unavailable backends use
  separate bounded Conditions and stable errors.
- The one-minute integrity scan, startup observation, read-time observation,
  and mutation preflight share one classifier. Observation never mutates a
  backend object or helper ownership record.

### Commands, Operations, and recovery

- `pull`, `build`, one-shot `run`, `container.create`, and non-interactive exec
  remain synchronous and create no durable Operation.
- Selected lifecycle and Session repair/cleanup Commands use the one durable
  Operation model; no second task, job, queue, or hidden deferred Command exists.
- Validation, authorization, conflict detection, idempotency, and durable
  admission form one transactional boundary.
- At most one worker owns an Operation. Restart recovery never repeats `Execute`
  blindly and never invents success from uncertain backend state.
- Terminal state is immutable. Target finalization and terminal outcome commit
  together where the capability contract requires them.
- Session teardown may request internal cancellation; no public Operation cancel
  surface is introduced.

### Session lifetime and cleanup

- Claiming Session teardown immediately prevents new work and invalidates the
  Session bearer.
- Expiration closes interactive streams and eventually removes Managed
  Containers, port leases, Session Network, Operations, idempotency rows, and
  runtime/MAC resources whose ownership is proved.
- Cleanup treats an already absent backend object as successful absence.
- Transient backend failure retains `closing` state and schedules bounded retry.
- Ownership ambiguity retains `cleanup_failed` and requires an explicit
  administrator decision; it is never converted into automatic deletion.
- Only successfully `closed` Sessions receive the fixed ten-minute observation
  grace. The grace is not TTL renewal or configurable retention.

### Secrets and workload-controlled data

The following never enter SQLite durable records outside their explicitly
authorized credential store, audit, daemon logs, journald, public errors, or
resource projections:

- administrator, Principal, Launcher, and Session bearer material;
- registry credentials or encoded authorization headers;
- environment values and build-argument values;
- argv, interactive input, workload output, and container log payloads;
- raw Docker inspect or error payloads.

BackendContainerID is the one necessary durable private correlation stored on
its Managed Container record. It never enters the public projection, audit, or
errors. Docker exec IDs remain transient and have no durable or public form.

Private-registry credentials are read from the existing Session credential
source just in time. Pull receives only the matching authorization; build
receives only the Session-scoped map required for private `FROM` resolution.
Container create, run, durable Operations, and audit receive none of it.

### Networking and publishing

- Every Session Network is attributable to exactly one Session and uses the
  fixed ownership labels and Session-derived backend name.
- Managed Containers and one-shot runs attach only to the owning Session
  Network; builds do not attach to it.
- DNS aliases are Session-local and never become global selectors.
- Publishing accepts TCP only and binds IPv4 loopback only.
- Root, Principal, Launcher, and Session grants narrow monotonically; grants
  authorize leases but are not reservations.
- Port allocation is atomic across docker-helper state and discloses no foreign
  lease owner. Collision with an unrelated host process is a bounded runtime
  failure, not a resource docker-helper may terminate.
- Engines that cannot prove the required loopback isolation fail publishing
  closed without disabling unrelated capabilities.

### Resource and execution containment

- Every Managed Container and one-shot run receives explicit CPU, memory, PIDs,
  shared-memory, and disabled-swap settings.
- A workload request may narrow but never exceed the effective Session ceiling.
- Parent cgroups enforce aggregate Root, Principal, Launcher, and Session
  ceilings; per-container Docker limits do not substitute for that hierarchy.
- Session-count admission is atomic across daemon, Root, Principal, and Launcher
  quotas.
- Exec inherits the Managed Container user, mounts, network, cgroup hierarchy,
  and remaining Session lifetime. It exposes no user override, privilege,
  capability, mount, device, or network mutation.
- Lifecycle teardown does not wait indefinitely for exec. Detached or
  interruption-resistant processes remain bounded by their container and die
  with its removal.

## Verification layers

Passing unit tests alone is insufficient. Each implemented package uses the
smallest applicable combination of these layers:

| Layer | What it proves |
| --- | --- |
| Domain/unit | normalization, state matrices, scope calculation, bounds, error classification, and pure recovery decisions |
| SQLite integration | schema recognition, migrations, foreign keys, transaction boundaries, idempotency, atomic claims, quota admission, and crash-visible state |
| HTTP/CLI protocol | authentication, non-disclosure, status/code/envelope stability, selector rules, stdout/stderr routing, and thin-client behavior |
| Race and fault injection | concurrent admission, lost wake-ups, disconnects, shutdown, partial backend effects, transaction failure, and cleanup ordering |
| Real Docker Engine | ownership labels, runtime states, network isolation, logs framing, lifecycle effects, exec, port binding, and out-of-band tampering |
| Real host policy | AppArmor/SELinux regression, mount pinning, cgroup hierarchy, rootless/system behavior, and aggregate enforcement |
| Packaging and upgrade | service policy, config migration, dependency delivery, database upgrade, restart recovery, man pages, completion, and packaged skill |

Tests assert public behavior and authoritative state, not private call order,
unless call ordering is itself the security property being protected.

## Work-package acceptance matrix

| Package | Security evidence required before acceptance |
| --- | --- |
| D0 | Moby compatibility evidence; credential translation canaries; bounded synchronous cancellation and cleanup; durable claim/idempotency/recovery races; no legacy async owner remains; the Session data-plane negative case proves a valid Principal or Launcher credential presented directly to `POST /pull`, `POST /build`, `POST /run`, or `POST /registry/login` is rejected and never converted into Session execution authority. |
| D1 | ownership-schema migration; public/backend identity separation; exact label verification; startup/read/preflight/scan classifier consistency; no secret create payload persists. |
| D2 | complete lifecycle matrix; conflict and no-op ordering; restart-step recovery; force-removal authorization; Session-expiry cleanup and ambiguity behavior. |
| D3 | lazy-create convergence; Session isolation and DNS; name conflict; repair recovery; missing-network observation; teardown with exact ownership proof. |
| D4 | bounded newest-output behavior; TTY and non-TTY Engine decoding; logging-backend failures; workload-marker absence from every log and audit sink. |
| D5 | shared exec authorization; inherited identity/policy; concurrency ceilings; request cancellation; lifecycle races; descendant-process observation and teardown; the Session data-plane negative case proves a valid Principal or Launcher credential cannot start non-interactive or interactive exec. |
| D6 | protocol validation; deadline clearing without weakening HTTP; bounded backpressure; one-reader/one-writer ownership; TTY resize; disconnect sequence; raw-mode restoration. |
| D7 | hierarchy calculation and atomic Session quotas; explicit Docker limits; real aggregate cgroup enforcement; unsupported-controller failure; policy repair. |
| D8 | grant narrowing; atomic leases; loopback-only reachability; Engine-version gate; host contention; lease retention/release; cleanup under partial failures. |
| D9 | cross-capability error/audit vocabulary; upgrade and rollback boundary; documentation and CLI consistency; packaging; full security regression suite. |

Each package follows the mandatory repository workflow: accepted architecture,
implementation plan against current code, executor work, architectural review,
then acceptance or correction. A failed package gate is fixed before dependent
work proceeds; implementation findings do not silently rewrite these contracts.

## Mandatory adversarial scenarios

The operational architect must assign explicit tests for at least these races
and failure classes:

- policy, credential, owner, or Session revocation concurrent with admission;
- simultaneous same-target lifecycle Commands, including idempotent replay;
- daemon exit before and after backend side effect, durable claim, and terminal
  commit;
- Session expiration concurrent with create, start, exec, stream upgrade, port
  allocation, network provisioning, and result finalization;
- backend disappearance, replacement, relabeling, policy mutation, pause, and
  Engine outage between preflight and mutation;
- multiple allocators racing for the same port or Session quota slot;
- stopped-container host port occupied by a foreign process before later start;
- output exactly below, at, and above every byte or queue bound;
- stalled HTTP and WebSocket readers, malformed frames, disconnects, and
  processes that ignore terminal interruption;
- partial cleanup where some backend resources are absent, some fail
  transiently, and some have ambiguous ownership;
- configuration reload concurrent with new admission, without retroactively
  changing an already admitted Command or stream unless its contract says so.

Fault-injection tests must exercise failure after every durable commit or
externally visible backend side effect for multi-step create, lifecycle, repair,
and cleanup paths. Recovery assertions are based on the persisted checkpoint and
observed backend reality, not on in-memory continuation.

## Secret-exclusion method

Secret exclusion is verified with unique canary values placed independently in
every secret-bearing or workload-controlled input. After success, denial,
backend failure, cancellation, disconnect, restart recovery, and cleanup
failure, tests search all available outputs:

- HTTP and WebSocket error/result payloads;
- CLI stdout and stderr;
- daemon operational logs and journald capture;
- audit capture;
- SQLite text/blob values and migration leftovers;
- persisted configuration and runtime metadata outside the designated
  credential stores, including the administrator-token file and authorized
  Session registry configuration.

A test that checks only structured audit fields is insufficient; sanitized
messages and wrapped backend errors are part of the boundary. Test diagnostics
must not print the canary values on failure. Separate assertions prove that each
raw secret exists only in the locations explicitly allowed by its credential
contract.

## Environment matrix

Release evidence covers:

- the repository-pinned Go toolchain and race detector;
- user and system deployment modes;
- rootful Docker and the supported rootless configuration;
- the minimum supported Docker Engine/API combination and one representative
  newer supported version;
- BuildKit-enabled and supported legacy build behavior for the D0 compatibility
  spike;
- public and private registry pull plus private `FROM` build;
- AppArmor and SELinux hosts where those shipped policies apply;
- fresh database creation and upgrade from the final Release 2.1 schema.

The D0 Engine compatibility spike records the minimum Engine API and exact
build/credential behavior before broad production migration. The D7 cgroup
spike records which controller hierarchy is enforceable in rootful and rootless
modes. These are implementation evidence gates, not permission to weaken the
public security model silently.

## Capacity and boundedness checks

Release 3 defines no high-load or production-orchestration service-level
objective. It still verifies that bounded mechanisms remain bounded:

- the one-minute integrity scan is measured with a large representative object
  set; elapsed time, Engine API call count, and overlap prevention are recorded;
- Operation workers, exec slots, WebSocket queues, output buffers, and list
  pagination never grow without their documented ceiling;
- only one Session cleanup attempt is active at a time, retry delay is bounded,
  and failed attempts do not accumulate live workers or in-memory state;
- a slow or disconnected client cannot retain unbounded memory, goroutines,
  sockets, staged build data, mount pins, MAC leases, or backend containers;
- full-inheritance policy creates warnings where specified but does not invent
  automatic quota or port-range partitioning.

These checks establish safe local and shared-host behavior. They do not claim
that docker-helper is a production scheduler or that its limits constrain
unmanaged host activity.

## Public-contract and documentation gate

For every capability, one review compares implementation, HTTP contract, CLI
help, completion, man pages, README, architecture, troubleshooting guidance,
and the packaged agent `SKILL.md`.

The review must prove that:

- stable names, selectors, states, Conditions, error codes, and JSON fields have
  one spelling and one owner;
- ordinary examples work with safe defaults and do not require users to learn
  policy internals before completing a useful workflow;
- dangerous administrator actions state the overridden check and the checks
  they do not override;
- troubleshooting recommends only supported docker-helper actions or explicit
  Docker/host diagnosis, never manual SQLite editing;
- deferred capabilities such as adoption, external or UDP publishing, log
  following, exec kill/reconnect, disk quotas, and desired-state reconciliation
  do not appear as implemented behavior.

## Release acceptance gate

Release 3 is accepted only when:

1. D0 through D9 have passed their individual architecture-review gates.
2. The standard repository validation gate passes on the pinned toolchain:
   `gofmt -l .`, `go test ./...`, `go test -race ./...`, `go vet ./...`, and
   `git diff --check`.
3. Required real-Docker, real-host-policy, packaging, upgrade, restart, race,
   disconnect, tampering, and secret-canary suites pass in the environment
   matrix above.
4. The Moby and cgroup compatibility spikes have recorded evidence and the
   documented minimum supported environment matches packaging and user docs.
5. No legacy build/run Operation workflow, alternate ownership path, direct
   Docker CLI lifecycle path, unbounded I/O path, or duplicate policy owner
   remains in production code.
6. Audit preserves public owner, initiator, action, normalized outcome, and
   request/Operation correlation where applicable, without retaining prohibited
   data.
7. Release documentation and shipped client surfaces describe the implemented
   contract without unresolved architectural placeholders.

## Completion criterion

This plan is complete when every Release 3 capability has traceable security
invariants, automated evidence at the appropriate layers, a reviewed
real-environment result where mocks are insufficient, and no implementation
step can be accepted solely because its local unit tests pass.
