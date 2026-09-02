# Release 3 Managed Container Domain

## Purpose

This document defines the Release 3 Managed Container domain core.

It covers ownership, lifetime, renewal, identity, persistence authority, status representation, create consistency, restart recovery, and backend-object divergence. The cross-cutting durable Operation model and detailed lifecycle request semantics, networking, resource constraints, publishing, container-log retrieval, and interactive streaming are defined in their dedicated design documents.

## Core invariants

A Managed Container:

- belongs to exactly one Session;
- cannot be transferred to another Session;
- cannot outlive its owning Session;
- has a docker-helper identity distinct from its Docker Engine identity;
- is authorized through persistent docker-helper ownership data, never through Docker labels alone;
- has runtime state observed from Docker Engine rather than maintained as desired state;
- is never recreated, restarted, stopped, or adopted merely because stored and observed state differ.

## Ownership and lifetime

The Session is both the authorization boundary and the resource-lifetime boundary for its Managed Containers.

A Managed Container may outlive the operation that created it, but not the Session that owns it.

While a Session is active, its bearer token may perform the Managed Container operations authorized by the Session contract. The owning Principal, owning Launcher, and administrator retain their higher-level management authority as defined by the Release 2.1 delegation model.

Session ownership remains unchanged throughout the Managed Container lifetime. Release 3 does not support transfer, reassignment, or adoption into a different Session.

## Session renewal

An active Session may be renewed explicitly by:

- its owning Principal;
- its owning Launcher;
- an administrator.

The Session's own bearer token cannot renew the Session.

Renewal accepts no caller-selected duration. The server computes:

```text
new_expires_at = server_now + effective_max_session_ttl
```

The effective maximum TTL is derived from the renewing actor's authorization and delegation boundary.

Renewal has the following properties:

- the existing Session bearer remains unchanged;
- the number of renewals is not limited;
- each renewal grants at most one effective maximum TTL from the renewal time;
- renewal is explicit and audited;
- activity, heartbeat, and ordinary Session requests never extend the deadline;
- only an active Session can be renewed;
- a Session in teardown or cleanup failure cannot be revived.

Renewal and expiration teardown are serialized. Exactly one transition wins: either the new deadline commits while the Session is active, or teardown claims the expired Session and renewal fails.

The audit event records the actor, Session ID, previous expiration, and new expiration without recording bearer material.

## Session teardown

Session expiration and explicit Session closure have the same resource-lifetime result.

Teardown:

1. prevents new Session-authorized operations;
2. terminates active synchronous and interactive exec work as part of container lifecycle shutdown;
3. stops and removes Session-owned Managed Containers;
4. releases their external port publications;
5. removes the Session network;
6. transitions the Session to `closed` after backend cleanup succeeds;
7. physically removes the closed Session and all dependent records after the bounded closed-Session tombstone period.

This is deterministic resource teardown at the end of an ownership lease. It is not desired-state reconciliation or automatic workload recovery.

If teardown cannot finish, the Session and the remaining resource records are retained in cleanup failure state. They accept no normal workload operations. The owning Principal, owning Launcher, or administrator may retry cleanup; the administrator may inspect the failure in detail.

The Session bearer is invalid from the moment teardown claims the Session. A `closed` tombstone exists only so an authorized Principal, owning Launcher, or administrator can observe the terminal `session.cleanup` result. Closed Sessions cannot be renewed. Physical Session deletion cascades to Managed Containers, Operations, and idempotency records. Audit events remain subject to the independent journald or external audit-retention policy.

## Operation integration

The cross-cutting Operation model is defined canonically in `release-3-operation-model.md`. This document defines only the Managed Container side of that relationship.

The following Managed Container lifecycle Commands create durable Operations:

- `container.create`;
- `container.start`;
- `container.stop`;
- `container.restart`;
- `container.remove`.

A create Operation and its Managed Container have separate public identities. ManagedContainerID is allocated before backend creation so that the Operation, persistent ownership row, and Docker ownership metadata can refer to the same target without reusing Operation identity.

Each Managed Container has at most one active lifecycle mutation. The durable `active_mutation_operation_id` relationship is established with Operation admission, survives daemon restart, and is cleared with terminal Operation status. A competing lifecycle Command is rejected; docker-helper does not maintain a hidden queue of user mutations.

Inspect is a Query. `build`, the existing one-shot `run`, non-interactive exec, and interactive exec are not Operations. Exec activity is tracked only in daemon memory and may be terminated by an accepted stop, restart, remove, or Session cleanup. Exec never blocks ownership teardown.

Session teardown coordinates pending and running Operations through the common internal cancellation contract, then observes actual backend state and continues `session.cleanup`. Container-specific execution and recovery rules are defined by the create consistency, restart recovery, and lifecycle designs.

## Identity

Each Managed Container has two identifiers with separate roles.

### ManagedContainerID

`ManagedContainerID` is generated by docker-helper and is the only stable public container identifier.

It is:

- globally unique within one docker-helper deployment;
- immutable;
- safe to expose through the API, CLI, audit records, and operation results;
- the identifier used for lookup and authorization.

The exact textual prefix must be selected against the existing project-wide identifier registry so that it does not collide with Principal, credential, Session, token, Launcher, or Operation identifiers.

### BackendContainerID

`BackendContainerID` is the Docker Engine container identifier.

It is:

- internal implementation data;
- never accepted from a caller as authorization or target identity;
- stored only to correlate the persistent record with the backend object;
- not part of the stable public contract.

A create Operation and the Managed Container it creates have different identifiers. Operation identity must not be reused as container identity.

## Sources of truth

Authority is divided deliberately.

| Data | Authoritative source |
| --- | --- |
| Public Managed Container identity | docker-helper persistent state |
| Owning Session | docker-helper persistent state |
| Requested and effective policy-relevant configuration | docker-helper persistent state |
| Backend correlation | Persistent BackendContainerID plus verified backend metadata |
| Current runtime state | Docker Engine observation |
| Authorization | docker-helper persistent ownership and delegation data |

Docker labels are correlation and integrity metadata. They are not an authorization database.

docker-helper never authorizes an action solely because a Docker object carries docker-helper-looking labels. Conversely, it never reports a cached database value as current runtime state when Docker Engine cannot be queried.

## Backend ownership metadata

Every backend container created for a Managed Container carries immutable docker-helper ownership metadata sufficient to verify:

- the ManagedContainerID;
- the owning Session ID;
- the docker-helper ownership namespace and schema version;
- any additional correlation nonce required to prevent accidental mismatches.

The exact label keys belong to the backend-adapter design and are not public API fields.

Verification requires both a persistent Managed Container record and matching backend metadata. A match on only one side is insufficient.

## Status model

Managed status and runtime status are separate dimensions.

### Management state

Management state is owned by docker-helper persistent state.

| State | Meaning |
| --- | --- |
| `creating` | Identity and ownership are reserved; backend creation may be incomplete. |
| `managed` | Persistent ownership and backend correlation are complete. |
| `removing` | Terminal resource removal is in progress; normal operations are denied. |
| `cleanup_failed` | Backend cleanup or correlation could not be completed safely; only recovery and cleanup actions are allowed. |

Start, stop, and restart do not create database management states such as `starting`, `stopping`, or `restarting`. Their progress belongs to Operation; the resulting runtime state is observed from Docker Engine.

After successful removal, the Managed Container record is deleted. Release 3 does not retain an additional permanent container tombstone. The Operation remains available while its owning Session exists; the audit stream retains historical attribution independently.

### Runtime state

Runtime state is a normalized observation of Docker Engine.

The bounded public vocabulary is:

- `created`;
- `running`;
- `paused`;
- `restarting`;
- `exited`;
- `dead`;
- `missing`;
- `unknown`.

`missing` means the persistent Managed Container exists but its verified backend object does not.

`unknown` means the backend could not provide a trustworthy current observation. A previously observed state may be retained with its observation timestamp for diagnostics, but it must not be presented as current.

### Conditions

Stable conditions provide the reason when management and runtime data cannot be combined normally:

- `backend_unavailable`;
- `backend_missing`;
- `ownership_mismatch`;
- `cleanup_failed`.

Conditions do not trigger autonomous workload repair.

## Create consistency model

SQLite and Docker Engine cannot participate in one atomic transaction. Managed Container creation therefore uses a persistent provisional record and explicit compensation.

The create sequence is:

1. authorize and validate the complete request;
2. resolve Session, workspace, mount, policy, networking, limit, and publishing inputs;
3. generate ManagedContainerID and ownership metadata;
4. insert a persistent `creating` record;
5. create the backend container with matching ownership metadata;
6. receive and verify BackendContainerID and effective backend configuration;
7. persist the correlation and transition `creating` to `managed`;
8. report successful creation only after the final database commit.

If validation or provisional database creation fails, no backend call is made.

If backend creation fails and docker-helper can prove that no object was created, the provisional record is deleted. The failure remains attributable through the Operation while the Session exists and through the independently retained audit record.

If a backend object may have been created, docker-helper performs a bounded correlation check using the unique ownership metadata.

- If no object exists, the provisional record is deleted.
- If exactly one matching object exists and is valid, registration may be completed.
- If a matching object exists but creation cannot be completed, docker-helper attempts compensating removal.
- If compensating removal fails or the result remains ambiguous, the record becomes `cleanup_failed` and a warning is emitted.

Creation never reports success before both persistent ownership and backend correlation are complete.

## Restart recovery

Daemon startup performs bounded recovery of incomplete docker-helper bookkeeping.

For each `creating` record:

- exactly one valid matching backend object allows registration to finish;
- no matching backend object allows the provisional record to be removed;
- ambiguous, conflicting, or invalid metadata produces `cleanup_failed` and a warning.

This recovery may complete or discard an interrupted registration record. It does not start, stop, recreate, or otherwise drive the backend container toward a desired runtime state.

Records already in `managed` are not reconciled toward their stored configuration. Their current backend state is only observed and reported.

## Divergence handling

The following cases fail closed.

| Persistent state | Backend state | Result |
| --- | --- | --- |
| Managed Container exists | Matching backend object exists | Verify ownership and report observed runtime state. |
| Managed Container exists | Backend object absent | Report `missing`; do not recreate. |
| Managed Container exists | Backend object or ownership metadata conflicts | Report `ownership_mismatch`; deny ordinary operations. |
| Managed Container exists | Backend unavailable | Report `unknown` with `backend_unavailable`; do not substitute cached state. |
| No Managed Container exists | Backend object carries docker-helper ownership metadata | Treat as an orphaned backend object; do not adopt automatically. |

## Orphaned backend objects

Discovery of an orphaned backend object emits a structured warning containing its ManagedContainerID, Session ID, and BackendContainerID when those values are safely available.

The warning does not include environment values, bearer material, or other secrets.

Orphan decisions are exposed through an administrator-only CLI surface:

```text
docker-helper container orphan list
docker-helper container orphan show <backend-id>
docker-helper container orphan remove <backend-id>
```

`show` presents the backend state and the policy-relevant image, mounts, network, limits, and publishing configuration. Environment values are not displayed.

`remove` is limited to a verified docker-helper-labelled orphan so that the command cannot become a general Docker container deletion interface.

Session, Launcher, and Principal credentials cannot operate on orphaned objects. Their ownership is absent from persistent state, so only administrator authority may resolve them.

No orphan is adopted or removed automatically.

Orphan adoption is outside Release 3. A later design may add it if operational evidence justifies the additional reconstruction and authorization contract.

## Accepted lifecycle semantics

Lifecycle Commands express an explicit caller intent rather than requiring the caller to reproduce Docker's prerequisite steps.

- `start` for an already running container is a successful no-op and creates no Operation;
- `stop` for an already stopped container is a successful no-op and creates no Operation;
- `restart` restarts a running container and starts a stopped container;
- `remove` stops a running container internally before removing it;
- Release 3 exposes no public force flag and no caller-selected stop timeout;
- stop behavior uses one finite backend default for `stop`, `restart`, `remove`, and Session teardown;
- accepted `stop`, `restart`, `remove`, and Session teardown close exec admission and terminate active exec instances; active exec is not a lifecycle conflict;
- a competing lifecycle mutation returns `409 Conflict` with the active Operation ID and is never queued; the stable error code must not be `container_busy`.

The detailed lifecycle design must map these rules across every observed runtime state and define their recovery evidence without changing the accepted caller-facing behavior.

## Persistent data boundary

Persistent Managed Container data contains only information required for:

- identity and ownership;
- authorization;
- backend correlation;
- policy verification;
- status and recovery;
- audit attribution.

Release 3 does not persist environment secret values merely to reproduce a complete Docker configuration. It does not support autonomous recreation, so a desired-state copy of every backend field is unnecessary.

Exact schema columns, indexes, closed-Session tombstone duration, and migration ordering belong to the implementation design. Field names must preserve the distinction between ManagedContainerID, BackendContainerID, management state, runtime observation, and Operation identity.

## Deferred to subsequent designs

The following decisions are intentionally outside this document:

- detailed runtime-state mapping and recovery evidence for the accepted lifecycle behavior;
- container name and Session-scoped network alias rules;
- the immutable create specification and whether any fields may be updated;
- Session-network provisioning and cleanup mechanics;
- supported resource constraints;
- port-publication grants and allocation;
- logs and exec request contracts;
- WebSocket framing and terminal behavior;
- HTTP and CLI command layout beyond the required orphan administration surface.
