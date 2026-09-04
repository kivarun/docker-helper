# Release 3 Decomposition

## Purpose

This document decomposes Release 3 into architectural work packages and defines the dependencies between them.

It does not define the final HTTP API, CLI syntax, database schema, or Docker Engine calls. Public and architectural contracts are produced by the design documents identified below. Exact Go structures, SQL DDL, worker mechanics, Moby call sequences, and test-file layout remain implementation decisions for the operational architect.

Release 3 proceeds package by package: accepted architecture, implementation plan against current code, executor work, architectural review, then acceptance or correction before the next package. The mandatory escalation and review gate is defined in `AGENTS.md`; implementation findings never change accepted architecture silently.

## Architectural center

Release 3 introduces one new durable user-visible domain object: the **Managed Container**.

A Managed Container:

- is created within exactly one Session;
- remains owned by that Session;
- has a stable docker-helper identity independent of its Docker Engine identifier;
- persists beyond the synchronous Request that created it;
- is the authorization target for lifecycle, logs, and exec actions.

The surrounding concepts retain narrower roles:

- a **Session** remains the authorization and isolation boundary;
- a **Session Network** is infrastructure owned by a Session, not a second management plane;
- an **Operation** is a durable execution record for selected asynchronous work, but does not become container identity or wrap every Command;
- an **Interactive Stream** transports an authorized exec interaction, but does not introduce separate ownership or authorization.

All Release 3 capabilities attach to this model. No capability may invent a parallel container identity, ownership rule, or authorization path.

## Cross-cutting execution model

Release 3 keeps Request and Response at the transport layer, Command and Query at the application layer, and Operation as the durable execution record created only by selected asynchronous Commands.

The canonical common contract is `release-3-operation-model.md`. The current-to-target terminology and code migration are fixed in `release-3-vocabulary-and-implementation-map.md`. The executor-facing implementation sequence is defined in `release-3-d0-execution-plan.md`. These contracts apply to asynchronous managed-container start, stop, restart, remove, and administrator repair Commands and to explicit Session network repair and Session cleanup. Feature packages provide type-specific validation, execution, recovery, and outcomes; they must not redefine the common state machine, persistence ownership, idempotency, retention, or thin-client boundary.

`build`, the existing one-shot `run`, `container.create`, and non-interactive exec are synchronous Commands. Process-like Commands return one combined bounded `output`; create returns the stopped Managed Container only after persistent ownership and backend correlation are complete. Interactive exec uses WebSocket. None creates an Operation or persistent output history.

The Release 2.1 authority boundary is frozen: credential scope can authorize
control-plane management, and the Session token authorizes Session workload
execution. Management Queries and Commands on Session-owned resources
(`container.create` and the Managed Container Queries and Commands) use one
common Session-selection contract, including resolving a Session-local name:
Session tokens imply their Session, Launcher and Principal credentials may
omit the selector only when the documented default scope yields one usable
Session, and administrators must select explicitly. Ambiguity is never
resolved by ordering candidates. The Session data-plane Commands (`pull`,
`build`, `run`, `registry login`, and both exec modes) require a Session
bearer and never infer a Session from a Principal or Launcher credential.

## Work packages

### D0. Cross-cutting Operation foundation

This package introduces the single durable Operation model used by Release 3 and removes `build` and `run` from the current in-memory Operation mechanism. Bounded synchronous process execution remains a separate responsibility.

Responsibilities:

- retire the current build/run Operation types, status/log/cancel workflow, and related retention configuration;
- introduce one narrow official Moby Engine API adapter and move `pull`, `build`, and `run` directly to their target synchronous paths without rebuilding the legacy asynchronous workflow on the new backend;
- preserve existing Session-scoped private-registry behavior by explicitly bridging pull and build credentials through the adapter;
- move `build` and `run` into bounded synchronous request handling while preserving their normal blocking CLI behavior;
- define the shared Operation handler boundary for separate `Execute` and `Recover` behavior;
- define durable admission, terminal outcome, idempotency association, Session ownership, and cascade retention;
- define atomic execution claiming, restart scanning, worker concurrency, and daemon-shutdown behavior;
- provide the extension points required by container lifecycle and Session cleanup without introducing a second job abstraction;
- define explicit HTTP, CLI, configuration, test, and documentation compatibility changes for the synchronous build/run migration.

D0 does not implement Managed Container lifecycle semantics. Those handlers belong to D2 and use the shared foundation.

Completion criterion: `build` and `run` no longer depend on Operation and return bounded synchronous results; and a new durable Operation type can be added through one common handler and persistence model with explicit execution and recovery behavior.

### D1. Managed-container domain core

This package defines the durable object and its relationship with existing Sessions.

Responsibilities:

- stable `dhmc_` plus 32-lowercase-hex docker-helper container identity;
- Session ownership;
- one immutable, Session-unique, DNS-label-compatible `name` that is also the network alias, supplied explicitly or derived only from a valid unused image basename;
- immutable image, optional entrypoint override, command, workdir, environment,
  workspace-contained mounts, resource limits, and publications accepted at
  create time;
- persistent management projection required for authorization, inspection, policy, and backend correlation without environment values, registry credentials, or a recreate-capable Docker request;
- lookup and ownership verification;
- projection of backend runtime state into a bounded public status model;
- integrity metadata that distinguishes docker-helper-owned backend objects from foreign objects.
- startup, read-time, mutation-preflight, and fixed once-per-minute read-only
  integrity observation without autonomous mutation.

This package must define behavior when:

- the daemon restarts while a container still exists;
- the backend container is missing;
- the backend container was changed outside docker-helper;
- persistent helper state and backend state disagree;
- the owning Session expires or is removed.

The package also defines the closed-Session tombstone required to observe cleanup completion. A successfully closed Session has one fixed internal ten-minute observation grace; it is not an extension of Session TTL or an operator retention setting. Physical Session deletion cascades to its Managed Containers, Operations, and idempotency records; audit retention remains independent. `closing` and `cleanup_failed` Sessions are never removed by this grace timer. Each cleanup attempt is one immutable Operation; after a transient failure the Session remains `closing`, persists its retry time and attempt count, and creates a new Operation when retry is due. Ownership ambiguity requires administrative resolution.

Restart handling restores management visibility only. It must not restart, stop, recreate, or otherwise reconcile a container toward a desired state.

Completion criterion: docker-helper can resolve a Managed Container by its own identifier, prove its ownership, report a bounded status, and retain that ability across daemon restart without taking autonomous lifecycle action.

### D2. Lifecycle command service

This package implements the explicit Managed Container lifecycle:

- create;
- list and show;
- start;
- stop;
- restart;
- remove;
- administrator policy repair.

Responsibilities:

- authorization before backend access;
- validation of allowed state transitions;
- serialization or conflict handling for concurrent commands against one container;
- bounded timeouts and cancellation behavior;
- consistent failure and partial-failure semantics;
- audit attribution;
- type-specific durable Operation admission, execution, recovery, outcome, and conflict handling through the D0 foundation;
- cleanup or compensation when creation fails after allocating some resources;
- credential-scope listing with narrowing ownership filters and bounded cursor
  pagination;
- administrator force removal for ownership mismatch without exposing a
  general Docker deletion capability;
- user-facing troubleshooting and safe recovery guidance for every public
  runtime state and Condition.

This package must not introduce a second generic job abstraction beside Operation.

`container.create` returns `201 Created` synchronously with a stopped Managed Container and creates no Operation. Image resolution and any required synchronous pull finish under the Request context before the provisional commit. The server then rechecks that the Session remains active and transactionally inserts a `creating` management projection before backend container creation; after that commit point it completes registration or compensation under a short server-owned context and recovers interrupted bookkeeping from the row and immutable backend labels. It accepts no `Idempotency-Key`; Session-local name conflict detection and explicit lost-response resolution avoid a second idempotency subsystem.

A start of an already running container and a stop of an already stopped one return `200 OK` with the current container representation, create no Operation, and create no idempotency record. Lifecycle work that mutates state returns `202 Accepted`. An existing matching idempotency record is resolved before the current-state no-op check so a lost accepted response returns its original Operation. The CLI hides the transport distinction, waits for accepted work by default, and may detach, but remains a stateless protocol adapter. Public Operation cancellation is outside Release 3; internal cancellation exists only where deterministic Session teardown requires it.

List and show are Queries and create no Operation. Their public projection is
docker-helper management data plus normalized runtime observation, never raw
Docker inspect data.

The package must preserve the state and Command matrix in
`release-3-managed-container-lifecycle.md`. In particular, repeated start/stop
postconditions are successful no-ops; start resumes a container paused outside
docker-helper; restart is one Operation composed from the full docker-helper
stop path followed by the full start path, with a persisted internal step that
makes crash recovery idempotent; restart of a stopped container begins at
start; and removal is the explicit supported resolution for verified unusual
states. One reloadable administrator setting, `container_stop_timeout`,
defaults to ten seconds and applies uniformly to stop, restart, remove, and
Session cleanup. Callers cannot select a different timeout or a Docker-style
immediate-kill mode.

Administrator `container remove --force` exists only for the exact recorded
backend after `ownership_mismatch`; it does not alter stop semantics. A missing
backend makes start/stop/restart fail but allows synchronous persistent cleanup
without an Operation. `policy_mismatch` may be repaired only through explicit
administrator `container.repair` or resolved through authorized removal.
Session cleanup automatically deletes all resources with proven Session
ownership, but integrity observation never deletes or repairs anything.
Competing lifecycle mutations still return a non-queued `409` with the active
Operation ID and are not reported as `container_busy`.

Completion criterion: every lifecycle mutation has one ownership check, one state-transition contract, one backend execution path, and one externally observable result.

### D3. Session networking

This package provides isolated communication between containers owned by the same Session.

Responsibilities:

- provisioning and identifying the Session-owned network;
- attaching Managed Containers during creation;
- same-session name resolution;
- preventing accidental attachment to another Session's network;
- backend ownership labels or equivalent integrity markers;
- network cleanup tied to the chosen Session and container lifetime rules;
- restart-safe discovery of the existing network without autonomous service reconciliation;
- explicit whole-Session repair after externally caused network loss.

External port publishing is not part of this package.

Session isolation does not imply an internal-only Docker network or a new host-access path. The accepted egress and host-access boundary is explicit below.

Release 3 provisions the network lazily on the first `container.create` or one-shot `run`; Session creation itself is database-only and Docker-independent. Concurrent first users serialize to one network. Its diagnostic Docker name is `dhsn-<full-session-id>`; all named Docker resources owned directly by a Session use a stable resource-type prefix and include that full Session ID, while labels remain the ownership authority.

Network absence with no Managed Containers is the normal lazy state and the next network-dependent Command may create it. Absence while Managed Containers exist is reported as `network_missing`; network-dependent admission is blocked until an explicit, durable `session.repair` recreates the network and reconnects every container whose ownership is proven. Integrity observation never invokes repair. A foreign network occupying the diagnostic name is neither used nor removed and produces `network_name_conflict`. Cleanup treats an already-absent network as success.

Release 3 retains ordinary Docker outbound connectivity and adds no host alias, host-access grant, or firewall layer. Managed Containers and one-shot `run` attach to the Session network; build does not.

The canonical contract is `release-3-session-networking.md`.

Completion criterion: two containers in one Session can communicate by an approved name, while a container from another Session cannot join or address that network through docker-helper.

### D4. Container logs

This package exposes logs of a Session-owned Managed Container.

Responsibilities:

- target resolution and ownership verification;
- bounded retrieval options;
- combined output consistent with the synchronous Command contract;
- limits that prevent unbounded memory use or response growth;
- consistent behavior for running, stopped, removed, and missing containers;
- audit behavior appropriate to log access.

Container logs are read from Docker Engine under bounded request and response limits. docker-helper does not persist, rotate, or retain a second copy.

Release 3 provides bounded snapshots only. Log following is outside its scope and must not be added implicitly as a side effect of interactive exec streaming.

The public contract is `GET /containers/{id}/logs?tail=200` with `tail` in `1..10000` and a JSON result containing combined `output` and `truncated`. `container_log_max_bytes` is a distinct reloadable limit with a 1 MiB default. Logs are read from the Engine runtime only and are never copied to helper storage, journald, or audit.

Completion criterion: authorized callers can retrieve bounded container logs without receiving direct Docker Engine access or backend-specific identifiers as authority.

### D5. Exec core

This package defines command execution inside a Managed Container independently of transport.

Responsibilities:

- target resolution and ownership verification;
- argv command and optional container-local environment and working-directory;
- explicit absence of non-interactive stdin, detach, timeout, and cancellation contracts;
- container-state preconditions;
- exit status and failure taxonomy;
- audit attribution;
- shared execution semantics for non-interactive and interactive modes.

Non-interactive exec reuses the existing synchronous `run` request/response model. It returns combined bounded output and exit status directly and creates no Operation.

Docker-provided terminal exit codes, including `126` and `127`, remain workload
results. If the Engine rejects start before a trustworthy terminal exec result
exists, the Command fails with HTTP `422` and `exec_start_failed`; docker-helper
never infers an exit code by matching backend error text.

Exec inherits the container's configured user. Release 3 exposes no user override, privileged mode, or additional Linux capabilities. All active exec instances are limited to 16 per container, 32 per Session, 32 per owning Principal, and 64 per daemon. Interactive exec is additionally limited to 4 per container, 16 per Session, 16 per Principal, and 64 per daemon; administrators may tune these defaults.

Interactive exec reuses the same authorization and execution core. It must not be implemented as a separate privileged path.

Active exec instances are transient daemon state. Lifecycle stop, restart, remove, and Session cleanup close exec admission and terminate active processes through container lifecycle action. Exec never blocks teardown and has no restart recovery or output replay contract.

Workload output never enters the daemon logger, journald, or audit stream in Release 3.

Completion criterion: a non-interactive command can run inside an authorized Managed Container with the same bounded synchronous result model as `run`, and both exec modes share one authorization and execution core.

### D6. Interactive WebSocket transport

This package adds streaming transport to an already-authorized interactive exec.

Responsibilities:

- WebSocket upgrade and attachment to one exec instance;
- binary stdin and combined output framing;
- mandatory TTY allocation and terminal resize;
- stream close, process exit, lifecycle interruption, and disconnect cleanup;
- bounded buffering and backpressure;
- authorization behavior when an initiating credential changes or the Session
  expires during a stream;
- audit linkage between the stream and the exec action.

The WebSocket protocol must be docker-helper-owned and versionable. Raw Docker attach framing must not become the public contract.

Interactive exec always allocates a TTY. It has one combined terminal stream,
supports resize, and requires an explicit argv executable without inserting a
shell. Release 3 exposes no non-TTY WebSocket exec mode.

The HTTP upgrade authenticates the bearer, checks target visibility, and
negotiates `docker-helper.exec.v1` through `Sec-WebSocket-Protocol`. The first
client text frame carries argv, environment, workdir, and initial terminal
size. The exec is accepted only after common admission succeeds, the Engine
exec is created and attached, and the server sends a `started` control frame.

Daemon and CLI use `github.com/coder/websocket` behind one narrow package-local
compile-time adapter. Third-party types do not enter the exec core or public
frame model. The adapter remains inside the repository's existing single
`package main`; Release 3 ships no runtime-selectable provider or speculative
second implementation.

The adapter clears inherited HTTP connection deadlines after successful
hijack and then installs the D6 liveness and per-write bounds. Ordinary HTTP
request and response-delivery timeouts remain enabled for every non-WebSocket
route.

No preliminary HTTP request, attachment ticket, or public exec ID exists.

Binary frames carry stdin and combined output; text frames carry controls such as terminal resize and completion. Each connection has a 1 MiB outbound queue. On ordinary disconnect docker-helper makes a best-effort Ctrl-C, waits about one second, closes stdin with Ctrl-D semantics, and then detaches if the process remains alive. Reconnect and an `exec kill` endpoint are outside Release 3; a detached process continues to count until it exits or its container is torn down. An open stream never renews Session TTL; Session expiration closes the stream and teardown removes the owning container without a separate exec grace period.

Completion criterion: interactive exec can be used without exposing a second authorization model, an unbounded relay, or Docker-specific stream framing.

### D7. Resource constraints

This package defines a deliberately bounded resource policy for Managed Containers and one-shot `run`.

Responsibilities:

- the supported CPU, memory, process, and related limit vocabulary;
- daemon, Root, Principal, and Launcher Session-count admission quotas;
- normalized units and validation;
- safe defaults that keep ordinary quick-start workflows free of mandatory resource flags;
- hierarchical root, Principal, Launcher, and Session ceilings;
- enforcement during container creation;
- status representation sufficient to inspect the effective limits;
- stable errors for unsupported or excessive requests.

The public contract exposes docker-helper policy concepts, not arbitrary Docker flags or HostConfig passthrough.

The design distinguishes:

- a caller's requested value;
- the Session's authorized ceiling;
- the effective backend value.

Every Managed Container and one-shot `run` receives explicit CPU, memory, PIDs, and shared-memory limits. Omitted CPU, memory, and PIDs values select the effective Session ceiling, not unbounded Docker behavior or a calculation of remaining quota. Shared memory has its own bounded default below. A caller may narrow inherited values but never widen them.

At initialization, the root workload memory pool defaults to 75% of Docker Engine-reported `MemTotal`, rounded down to 256 MiB. The CPU pool defaults from Engine-reported `NCPU`: logical CPUs minus the larger of 0.5 CPU or 10%, rounded down to 0.1 CPU. The Root PIDs ceiling defaults to 512 and is clamped by the enforceable system boundary. These defaults are materialized as explicit configuration and do not derive from the docker-helper process cgroup. Swap is disabled. Shared memory defaults to the smaller of 256 MiB and the workload memory limit, may be narrowed explicitly, and never exceeds memory. Disk quotas are outside Release 3.

An omitted Principal, Launcher, or Session ceiling inherits its effective parent ceiling. A second Principal or Launcher that still inherits the full parent produces an operator warning rather than an automatic fractional split. The hierarchy is an aggregate runtime security boundary enforced by parent cgroups: multiple containers may each receive the full Session ceiling as their individual limit, while their combined actual usage remains bounded by the Session cgroup and its ancestors. docker-helper performs no resource reservation, remaining-capacity calculation, or scheduling admission. Memory ceilings are decreased only when the subtree has no active workloads; CPU and PIDs decreases apply live; exec-concurrency decreases do not kill existing execs. A cgroup-hierarchy spike must prove aggregate enforcement for both system and rootless deployments before implementation is frozen.

Build resource control is outside this package.

Session admission is checked atomically against a fixed daemon limit and
configurable Root, Principal, and Launcher quotas. The defaults are 10,000 for
the daemon and Root, 100 per Principal, and 20 per Launcher. Creation
reservations plus `active`, `closing`, and `cleanup_failed` Sessions count;
the observation-only `closed` tombstone does not. Lowering a quota never
deletes existing Sessions.

The canonical contract is `release-3-resource-constraints.md`.

Completion criterion: Session creation cannot exceed any applicable count
quota; a Session can start a Managed Container or execute `run` only within
its authorized resource envelope; and effective policy remains inspectable
without exposing the full Docker resource surface.

### D8. Host port publishing

This package provides narrow, explicit exposure of selected container TCP ports from the Session network to host IPv4 loopback.

Responsibilities:

- representation of the container port and protocol;
- the fixed `127.0.0.1` host bind address;
- allocation or validation of host ports;
- collision handling;
- authorization inherited from the Release 2.1 Launcher and Session model;
- persistence and inspection of the effective mapping;
- cleanup and reuse after container removal;
- audit events for publication and release.

Publishing authority originates outside the untrusted Session through the Release 2.1 delegation model. Release 3 must not create a second delegation mechanism merely for ports.

The Session may request an allowed host port or omit it for automatic allocation. The effective mapping is returned by create and shown with Session grants; no separate range-discovery endpoint is required.

Publishing grants narrow through root, Principal, Launcher, and Session. An omitted child range inherits the full effective parent range. A parent authority may replace a child grant only within its own current effective range; a subject cannot widen its own grant. The root default is `20000-29999`; adding a second full-inheriting Principal or Launcher emits an operator warning rather than silently splitting the range. A range cannot be narrowed while an existing descendant lease lies outside it, including a lease held by a stopped container.

Each Managed Container may have at most 16 publications. A publication maps one concrete container TCP port to either one explicitly requested allowed host port or one automatically allocated port. The lease is assigned during create, survives stop/start/restart, and is released by remove or Session cleanup. docker-helper prevents collisions among its own Managed Containers but does not reserve a socket or promise that an unrelated host process cannot occupy a port while its container is stopped.

This package does not expose UDP, external host binding, arbitrary Docker networks, network modes, aliases, or routing configuration. Because Docker Engine releases older than 28.0.0 do not provide the required localhost isolation, publishing fails closed on those daemons without disabling unrelated docker-helper capabilities.

The canonical contract is `release-3-port-publishing.md`.

Completion criterion: an authorized service can be exposed through a narrowly defined mapping, while an untrusted agent cannot freely claim host addresses or ports outside its grant.

### D9. Public surface and release integration

This package integrates the completed domain capabilities into the product surface.

Responsibilities:

- HTTP resource layout, exact request/response contracts, and compatibility policy;
- CLI command hierarchy and output behavior;
- database migrations and upgrade behavior;
- stable error codes;
- audit event vocabulary;
- configuration and policy documentation;
- operator, user, and agent-facing documentation;
- local troubleshooting sections and CLI recovery hints for the capability
  that owns each public Condition;
- compatibility with the normal blocking Release 2 CLI experience for run and build, while intentionally replacing their asynchronous HTTP Operation workflow;
- user-mode initialization and daemon-startup deprecation warnings without
  warning for non-root clients of the system service;
- project-produced tarball installer deprecation warnings while retaining full
  tarball build, install, upgrade, and uninstall acceptance for Release 3;
- Release 3 LTS release notes and migration guidance toward the Release 4
  system-mode-only deployment;
- packaging and service-upgrade verification.

The CLI is deliberately thin. It may read explicit configuration and credentials, validate syntax, issue one request, wait or poll transiently, service a WebSocket, and render results. It must not persist execution state, implement local queues or reconciliation, automatically retry ambiguous mutations, or mirror server state machines. Protocol capabilities that require client-side workflow state may remain API-only.

This is a cross-cutting package, not a final polish phase. API, CLI, persistence, audit, and documentation contracts are developed with each capability, then reconciled here before release.

## Dependency structure

The principal dependencies are:

1. D0 is the foundation for every durable Command and replaces, rather than extends, the existing in-memory build/run Operation mechanism.
2. D1 is the foundation for every Managed Container capability.
3. D2 depends on D0 and D1; D3 depends on D1. Together they form the minimum managed-container platform.
4. D4 and D5 depend on stable D1 ownership and D2 lifecycle semantics.
5. D6 depends on D5; WebSocket transport is not designed before exec semantics.
6. D7 depends on the D1 creation specification and the authorization envelope inherited by a Session.
7. D8 depends on D3 networking and the Release 2.1 delegation contract.
8. D9 spans all packages and closes their public and operational contracts.

The implementation order is therefore:

1. migrate `build` and `run` to bounded synchronous Commands, then implement the D0 durable Operation foundation for lifecycle and Session cleanup;
2. settle the D1 lifetime, identity, and state-authority decisions;
3. design D3, D7, and D8 inputs before freezing the container creation contract;
4. implement the D1 core with Session-network ownership;
5. implement D2 lifecycle management through D0;
6. add D4 bounded runtime-backed logs and D5 synchronous non-interactive exec;
7. add D6 interactive streaming;
8. add D7 resource constraints and D8 publishing against the already-defined creation contract;
9. complete D9 release-wide reconciliation and hardening.

D7 and D8 may be implemented later than the core lifecycle, but their required inputs must be designed before the create contract and persistent specification are considered stable.

## Cross-cutting verification

The canonical release-wide threat model, environment matrix, and acceptance
gate are defined in `release-3-security-and-test-plan.md`.

Every work package must cover:

- ownership and cross-Session denial;
- daemon restart and persistent-state behavior;
- backend object tampering or disappearance;
- concurrent and repeated requests;
- audit attribution without secret disclosure;
- bounded input, output, time, and resource use;
- failure cleanup;
- compatibility with both user and system deployment modes, including the
  supported rootless configuration; Release 3 deprecation does not permit a
  skipped or weakened user-mode gate;
- absence of user-mode deprecation warnings for non-root clients using the
  system service;
- real-Docker integration tests in addition to unit tests.

Interactive streaming, port allocation, lifecycle mutation, and cleanup require dedicated race and disconnect tests; unit-only coverage is insufficient for these boundaries.

## Design-document split

The decomposition produces the following detailed design documents:

1. `release-3-operation-model.md` — cross-cutting durable execution, recovery, idempotency, retention, and client boundaries;
2. `release-3-managed-container-domain.md` — identity, ownership, lifetime, persistence, and runtime status;
3. `release-3-managed-container-lifecycle.md` — accepted commands, token-scope listing, transitions, integrity observation, repair, removal, and troubleshooting;
4. `release-3-session-networking.md` — isolation, naming, attachment, explicit repair, and cleanup;
5. `release-3-logs-and-exec.md` — log retrieval and common exec semantics;
6. `release-3-interactive-streaming.md` — WebSocket and terminal protocol;
7. `release-3-resource-constraints.md` — supported limits, hierarchy, defaults, enforcement, and authorization ceilings;
8. `release-3-port-publishing.md` — grants, allocation, durable leases, binding, collision behavior, and cleanup;
9. `release-3-api-cli.md` — public surface and compatibility;
10. `release-3-security-and-test-plan.md` — threat boundaries and release verification.

The Operation model, Managed Container domain, Managed Container lifecycle,
Session networking, bounded logs, common exec semantics, interactive
streaming, resource-constraint, and port-publishing contracts are accepted
foundation designs.
`release-3-vocabulary-and-implementation-map.md` is their implementation bridge
to the Release 2 codebase and the Release 2.1 Launcher design.
`release-3-d0-execution-plan.md` turns the common Operation foundation into
ordered executor tasks and test gates. Each remaining owner document must be
contract-ready before its package is assigned, but need not prescribe
code-ready mechanics that belong to the operational architect. The immutable
container creation inputs are now fixed. The remaining owner
documents close the integrated public surface and release-wide security
verification.
