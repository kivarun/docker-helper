# Release 3 Scope

## Purpose

Release 3 extends docker-helper from bounded one-shot Docker operations to bounded lifecycle management of containers.

The release adds long-lived managed containers while preserving the authorization, session, workspace, and isolation model established in Release 2 and extended by Release 2.1.

Release 3 does **not** turn docker-helper into a container orchestrator.

## Scope

Release 3 adds the following capabilities.

### Managed containers

A session may create containers that continue to exist after the operation that created them has completed.

Managed containers support an explicit lifecycle:

- create;
- start;
- stop;
- restart;
- inspect status;
- remove.

A managed container remains owned by the session under which it was created.

Its lifetime is bounded by that Session. When the owning Session expires or is explicitly closed, docker-helper tears down its containers, external publications, and Session network before removing the Session record.

An authorized Principal, owning Launcher, or administrator may renew an active Session. Renewal resets its expiration to the effective maximum Session TTL from the time of renewal. A Session cannot renew itself, and renewal is never implicit or activity-based.

### Container logs

Logs of managed containers can be retrieved through docker-helper without exposing direct Docker Engine access.

Log access follows the same authorization and ownership boundaries as other container operations.

Container logs remain runtime-owned data. docker-helper performs bounded retrieval from Docker Engine and does not introduce its own persistent container-log storage, retention, or rotation subsystem.

Release 3 provides only a bounded snapshot with combined output. Log following is outside the release scope.

### Exec

Release 3 supports execution of commands inside managed containers.

Two execution modes are provided:

- **non-interactive exec** — a synchronous Command with the same combined, bounded output and exit-code model as the existing one-shot `run`;
- **interactive exec** — streamed over WebSocket.

Neither mode creates a durable Operation. Interactive streaming is a transport mechanism for an authorized exec Command and does not create an independent authorization model.

Release 3 does not emit workload output to the daemon logger or journald. Audit and operational records contain command metadata and normalized outcomes, never captured command output.

### Durable operations

Operation is used only when accepted work must outlive the originating HTTP request and recover after daemon restart.

The canonical ownership, state, admission, recovery, idempotency, retention, and client contract is defined in `release-3-operation-model.md`.

Release 3 uses durable Operations for:

- managed-container create, start, stop, restart, and remove;
- Session cleanup.

Queries, `build`, `run`, and both exec modes do not become Operations merely for uniformity. `build` and `run` are synchronous Commands with bounded direct results.

Lifecycle Command admission completes validation, authorization, and conflict checks before creating an Operation. The API returns `202 Accepted`; the CLI waits for terminal status by default and may return immediately with `--detach`.

The HTTP API may accept an optional `Idempotency-Key` for Commands that create durable Operations. This protocol capability does not require CLI support. The CLI does not generate, retain, or replay idempotency keys and never automatically retries an ambiguous mutation.

Release 3 does not add persistent Operation logs. Operation stores status, timestamps, attribution, target, and a typed terminal result, error, or cancellation reason. Durable audit history remains in the existing structured audit stream.

### Session networking

Each Session owns a user-defined bridge network. Managed Containers and one-shot `run` containers belonging to the Session attach to that network and may communicate through Session-scoped names.

Container-local ports may be used freely inside that network without host publication.

The network retains ordinary Docker outbound connectivity. Release 3 adds no special host alias, host-access grant, or firewall layer. Its isolation guarantee separates Session networks; it does not claim to be a complete outbound or host-network sandbox.

Build execution does not attach to the Session network.

### Port publishing

A managed container may explicitly publish selected TCP ports from its Session network to IPv4 loopback on the host.

Publishing authority and port ceilings derive from the owning Launcher. The Session may request an allowed host port or omit it for automatic allocation. The effective loopback address and host port are persisted and returned to the caller.

Release 3 does not publish UDP ports or bind to external host interfaces. Port publishing is deliberately narrower than general Docker networking configuration.

### Resource limits

Release 3 adds a bounded set of resource limits for managed containers and one-shot `run`.

The purpose is to constrain agent-controlled workloads, not to expose the complete Docker resource-management surface.

Build resource control is outside this model. The exact supported limits, hierarchical quotas, reservations, and safe defaults are defined separately by the Release 3 resource-limits design. Ordinary quick-start workflows must remain valid without requiring explicit resource-policy flags.

## Architectural invariants

Release 3 preserves the existing docker-helper security model.

In particular:

- untrusted agents do not receive access to `docker.sock`;
- session authorization remains capability-bounded;
- containers and operations remain attributable to their owning session;
- workspace and mount restrictions remain enforced;
- session boundaries also define managed-container ownership;
- new lifecycle and streaming operations must not bypass existing authorization checks;
- common workflows remain usable through safe defaults without requiring callers to reproduce operator policy;
- Docker Engine implementation details must not become part of the public docker-helper contract unless explicitly required.

Release 3 uses the Docker Engine API behind a docker-helper-owned backend boundary. Docker request and stream representations are implementation details and do not become the public API.

Managed containers are an extension of the existing session model, not a parallel management plane.

Request and Response remain transport concepts. Command and Query are application concepts. Operation is a durable execution record created only by selected asynchronous Commands; it is not a mandatory wrapper around every action.

Terminal Operations remain attached to their owning Session and are deleted when that Session record is physically removed. A closed Session may remain as a short-lived tombstone so authorized management callers can observe cleanup completion. Audit retention is independent and is governed by the operator's journald or external log-storage policy.

### Thin CLI

The CLI remains a lightweight protocol adapter.

It may read explicit configuration and credentials, validate command-line syntax, issue a request, wait or poll transiently, service an interactive stream, and render the response. It does not persist execution state, implement local queues or reconciliation, automatically retry ambiguous requests, or duplicate server state machines.

A protocol capability is not required to have a CLI surface when doing so would require local workflow state.

## Dependencies

Release 3 assumes the capabilities delivered by previous releases.

### Release 2

Release 2 provides the underlying multi-user and authorization model, including:

- principals and credentials;
- sessions;
- workspace authorization;
- system service operation;
- persistent state;
- audit and security boundaries.

### Release 2.1

Release 2.1 provides launcher delegation and the additional authorization layer needed for controlled agent-driven session creation.

Release 3 builds on that model rather than introducing another delegation mechanism.

## Explicit non-goals

Release 3 does not provide:

- desired-state management;
- automatic container recovery;
- restart policies;
- scheduling;
- service reconciliation;
- replicas;
- rolling updates;
- cluster management;
- multi-host orchestration;
- general-purpose Docker API compatibility;
- unrestricted Docker networking;
- external-interface or UDP port publishing;
- container-log following;
- support for every Docker runtime option;
- persistent Operation output or log replay;
- workload-output logging to the daemon logger or journald;
- a stateful CLI workflow engine.

A stopped or failed managed container remains stopped or failed until an authorized actor explicitly performs another lifecycle operation. Teardown caused by expiration or explicit closure of the owning Session is the sole ownership-lifecycle exception; it is resource cleanup, not desired-state reconciliation.

docker-helper is responsible for controlled access to container functionality, not for maintaining an application's desired state.

## Release boundary

Release 3 is complete when docker-helper can safely manage the lifecycle, execution, logs, networking exposure, and basic resource constraints of session-owned containers without weakening the authorization and isolation guarantees established by previous releases.

Features that require reconciliation, scheduling, autonomous recovery, or a broader orchestration model belong outside Release 3.
