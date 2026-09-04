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
- is never recreated, restarted, stopped, or adopted merely because stored and observed state differ;
- has an immutable create specification and is initially stopped.

## Ownership and lifetime

The Session is both the authorization boundary and the resource-lifetime boundary for its Managed Containers.

A Managed Container outlives the synchronous Request that created it, but not the Session that owns it.

While a Session is active, its bearer token may perform the Managed Container operations authorized by the Session contract. The owning Principal and owning Launcher may act within their delegated subtrees. The administrator may perform every ordinary Managed Container Command and Query and the administrator-only recovery Commands. Higher-level action remains attached to the owning Session, obeys its resource policy, and does not transfer ownership.

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
7. physically removes the closed Session and all dependent records after a fixed internal 10-minute observation grace period.

This is deterministic resource teardown at the end of an ownership lease. It is not desired-state reconciliation or automatic workload recovery. An open interactive stream never extends Session TTL. Expiration closes the stream and removes the owning container through this same teardown path; active exec receives no separate lease or grace period.

If teardown cannot finish transiently, the Session remains `closing` and accepts no normal workload operations. One `session.cleanup` Operation records one immutable attempt: a failed attempt becomes terminal, while the Session stores its attempt count and `cleanup_retry_at`; the due retry creates a new Operation. The owning Principal, owning Launcher, or administrator may request an immediate new attempt when none is active. Ownership mismatch or ambiguous authority moves the Session to `cleanup_failed`, is never resolved through automatic deletion, and requires administrator action.

The Session bearer is invalid from the moment teardown claims the Session. A `closed` tombstone exists only so an authorized Principal, owning Launcher, or administrator can observe the terminal `session.cleanup` result. The observation grace is not an extension of Session TTL or configurable retention. Closed Sessions cannot be renewed. Physical Session deletion cascades to Managed Containers, Operations, and idempotency records. Audit events remain subject to the independent journald or external audit-retention policy.

## Operation integration

The cross-cutting Operation model is defined canonically in `release-3-operation-model.md`. This document defines only the Managed Container side of that relationship.

The following Managed Container lifecycle Commands may create durable Operations when their requested mutation is not already satisfied:

- `container.start`;
- `container.stop`;
- `container.restart`;
- `container.remove`;
- administrator-only `container.repair`.

`container.create` is a synchronous Command and creates no Operation. ManagedContainerID is allocated before backend container creation so that the persistent ownership row and Docker ownership metadata can refer to the same target during crash recovery. A start of an already running container and a stop of an already stopped one return HTTP `200 OK` as successful no-ops and create no Operation; lifecycle work that changes state returns `202 Accepted`.

Each Managed Container has at most one active lifecycle mutation. The durable `active_mutation_operation_id` relationship is established with Operation admission, survives daemon restart, and is cleared with terminal Operation status. A competing lifecycle Command is rejected; docker-helper does not maintain a hidden queue of user mutations.

Inspect is a Query. `container.create`, `build`, the existing one-shot `run`, non-interactive exec, and interactive exec are not Operations. Exec activity is tracked only in daemon memory and may be terminated by an accepted stop, restart, remove, or Session cleanup. Exec never blocks ownership teardown.

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

The external format is `dhmc_` followed by 32 lowercase hexadecimal characters representing 16 random bytes. A database uniqueness conflict causes bounded regeneration rather than exposing the collision.

### Name

Every Managed Container has one immutable `name` unique within its owning Session. A caller may provide a DNS-label-compatible name during create. The supplied value is validated but never normalized, truncated, or rewritten.

If the caller omits `name`, docker-helper removes registry path, tag, and digest from the image reference and uses the repository basename only when it is already a valid, unused DNS label. If that default is invalid, longer than 63 characters, or already occupied in the Session, create requires the caller to provide an explicit name rather than inventing or suffixing one.

The name is:

- always returned by create, including when derived by the server;
- shown by docker-helper list and show Commands;
- exactly the single Session-network DNS alias used for same-Session discovery;
- retained in the management projection and backend ownership labels.

The Docker container name is diagnostic backend data of the form `dhmc-<name>-<full-session-id>`. More generally, every named Docker resource owned directly by a Session includes the full Session ID and a stable resource-type prefix; for example, the Session network uses `dhsn-<full-session-id>`. Session-local names remain human-facing, while the Session suffix prevents deployment-wide backend-name collisions. ManagedContainerID and OperationID never participate in backend naming. Release 3 adds no rename Command or extra caller-defined network aliases.

### BackendContainerID

`BackendContainerID` is the Docker Engine container identifier.

It is:

- internal implementation data;
- never accepted from a caller as authorization or target identity;
- stored only to correlate the persistent record with the backend object;
- not part of the stable public contract.

The administrator-only orphan surface is the sole public exception to the BackendContainerID rule because no persistent helper resource remains to target. Ordinary container APIs never expose or accept it.

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

Internal management state and public runtime status are separate dimensions.

### Management state

Management state is owned by docker-helper persistent state.

| State | Meaning |
| --- | --- |
| `creating` | Identity and ownership are reserved; backend creation may be incomplete. |
| `managed` | Persistent ownership and backend correlation are complete. |
| `removing` | Terminal resource removal is in progress; normal operations are denied. |
| `cleanup_failed` | Backend cleanup or correlation could not be completed safely; only recovery and cleanup actions are allowed. |

Start, stop, and restart do not create database management states such as `starting`, `stopping`, or `restarting`. Their progress belongs to Operation; the resulting runtime state is observed from Docker Engine.

Management state is not exposed in the public Container representation. It is
persistent recovery and cleanup data, not a second state machine that callers
must interpret.

After successful removal, the Managed Container record is deleted. Release 3 does not retain an additional permanent container tombstone. The Operation remains available while its owning Session exists; the audit stream retains historical attribution independently.

### Runtime state

Runtime state is a normalized observation of Docker Engine.

The bounded public vocabulary is:

- `stopped`;
- `running`;
- `paused`;
- `transitioning`;
- `dead`;
- `missing`;
- `unknown`.

`stopped` combines backend `created` and `exited` observations because both
have the same docker-helper lifecycle semantics. `transitioning` combines a
backend restart or removal in progress. `paused` remains visible because a
paused container retains processes and consumes resources; docker-helper does
not expose pause or unpause as capabilities.

`missing` means the persistent Managed Container exists but its verified backend object does not.

`unknown` means the backend could not provide a trustworthy current observation. A previously observed state may be retained with its observation timestamp for diagnostics, but it must not be presented as current.

### Conditions

Stable conditions provide the reason when management and runtime data cannot be combined normally:

- `backend_unavailable`;
- `backend_missing`;
- `ownership_mismatch`;
- `policy_mismatch`;
- `cleanup_failed`.

Conditions do not trigger autonomous workload repair.

### Public show projection

docker-helper never returns raw Docker inspect data. `container show` exposes
the ManagedContainerID, name, owning Session, requested image reference,
normalized runtime state, optional Condition, effective resource limits,
effective port publications, creation time, and optional active lifecycle
Operation identity.

Internal management state, BackendContainerID, raw backend labels and
HostConfig, environment names and values, command vector, workdir, immutable
Docker image ID, full mount configuration, and Docker network or endpoint
identifiers are omitted. The caller created the workload specification;
docker-helper reports only the management, policy, and recovery information it
owns. The exact lifecycle representation and list projection are defined in
`release-3-managed-container-lifecycle.md`.

## Create consistency model

SQLite and Docker Engine cannot participate in one atomic transaction. Managed Container creation therefore uses a persistent provisional record and explicit compensation.

The create sequence is:

1. authorize and validate the complete request, including the explicit or derived name;
2. resolve Session, workspace, mount, policy, network, limit, and publishing inputs without allocating a Managed Container;
3. resolve the image and, when it is absent locally, complete the synchronous pull under the Request context;
4. re-resolve the Session and, in one transaction, require it to remain `active`, allocate ManagedContainerID and any port leases, and insert the persistent `creating` management projection;
5. under the short server-owned context, provision or verify the lazy Session network and create the backend container with the diagnostic name and matching ownership metadata;
6. receive and verify BackendContainerID and effective backend configuration;
7. in one transaction, require the Session and provisional row to remain eligible, persist the correlation, and transition `creating` to `managed`;
8. report successful creation only after the final database commit.

If validation, image resolution or pull, or provisional database creation fails, no backend container is created. Pull deliberately precedes the provisional commit because it may be long-running and remains bound to the client Request.

If backend creation fails and docker-helper can prove that no object was created, the provisional record is deleted. The failure remains attributable through request-correlated audit; synchronous create does not manufacture an Operation solely to retain the failure.

If a backend object may have been created, docker-helper performs a bounded correlation check using the unique ownership metadata.

- If no object exists, the provisional record is deleted.
- If exactly one matching object exists and is valid, registration may be completed.
- If a matching object exists but creation cannot be completed, docker-helper attempts compensating removal.
- If compensating removal fails or the result remains ambiguous, the record becomes `cleanup_failed` and a warning is emitted.

Creation never reports success before both persistent ownership and backend correlation are complete. It returns `201 Created` with a stopped Managed Container and never starts workload execution.

Before inserting `creating`, request cancellation ends the Command without a persistent resource. After that commit point, the handler uses a short server-owned context to complete registration or compensation even if the HTTP client disconnects. If the Session enters `closing` before final registration, the handler removes any created backend container and releases the provisional state rather than registering new work into the closing Session. Daemon restart uses the same `creating` record and ownership labels to finish bookkeeping safely. The CLI never retries an ambiguous create automatically; the caller resolves a lost response through `container list` or an explicitly requested unique name.

`container.create` does not accept the durable-Operation `Idempotency-Key` contract. Extending it would require a separate resource-result association and a safe fingerprint of secret-bearing environment values. Release 3 uses Session-local name conflict detection instead of adding that subsystem.

If the requested image is absent locally, docker-helper performs the synchronous pull before the `creating` commit. An existing local image is used unchanged; callers that want to refresh a mutable tag invoke the existing explicit `pull` Command. The management projection retains the requested image reference and the immutable image ID actually used. Release 3 exposes no create-specific pull-policy flags.

The create request keeps the existing 16 KiB HTTP body limit and the established
`run` validation for entrypoint, command, workdir, environment names, and
workspace-contained bind mounts. It adds the optional name, resource limits,
and at most 16 loopback TCP publications. No caller-requested named volumes,
arbitrary host paths, `volumes-from`, tmpfs surface, or general volume API is
added. The writable layer and image-declared anonymous volumes survive
stop/start/restart and are removed with the Managed Container.

## Restart recovery

Daemon startup performs bounded recovery of incomplete docker-helper bookkeeping. It resolves all `creating` records before dispatching or retrying cleanup for expired or closing Sessions. A live cleanup attempt that encounters `creating` does not discard its ownership row; it fails transiently so that the Session-owned retry schedule can create a later cleanup attempt after create recovery or compensation finishes.

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
| Managed Container exists | Immutable ownership metadata conflicts | Report `ownership_mismatch`; deny ordinary operations. |
| Managed Container exists | Ownership matches but mutable helper policy conflicts | Report `policy_mismatch`; never repair automatically. |
| Managed Container exists | Backend unavailable | Report `unknown` with `backend_unavailable`; do not substitute cached state. |
| No Managed Container exists | Backend object carries the complete valid docker-helper ownership-label set | Treat as an orphaned backend object; do not adopt automatically. |

Names, partial labels, and visually similar Docker objects are not correlation
evidence. A normal lookup starts from persistent Managed Container identity;
absence of that record returns `404` even when Docker contains a similar name.

### Integrity scan

Startup observation, read-time observation, and mutation preflight are
supplemented by a read-only integrity scan once per minute. The scan compares
persistent records with Docker objects in the exact docker-helper ownership
namespace and verifies backend correlation, immutable ownership metadata,
Session-network membership and alias, diagnostic backend name, resource policy,
and verifiable publication data.

The scan detects missing objects, orphans, ownership mismatch, and policy
mismatch. It emits an operational warning and audit observation only when the
detected Condition changes. It never creates an Operation, repairs policy,
adopts an object, starts or stops a workload, or deletes a resource.

The fixed interval avoids another Release 3 configuration setting. A
real-Docker performance test with a large object set must measure complete-pass
time, Docker API call volume, daemon load, and prevention of overlapping scans
before implementation is frozen. The scan detects accidental out-of-band
changes; root and direct Docker-socket access remain outside the docker-helper
threat model.

## Orphaned backend objects

Discovery of an orphaned backend object emits a structured warning containing its ManagedContainerID, Session ID, and BackendContainerID when those values are safely available.

The warning does not include environment values, bearer material, or other secrets.

Orphan decisions are exposed through an administrator-only surface. Its
canonical HTTP collection is `/container-orphans`; the CLI forms are:

```text
docker-helper container orphan list
docker-helper container orphan show <backend-id>
docker-helper container orphan remove <backend-id>
```

`show` presents only the BackendContainerID, complete valid helper ownership
identities, helper-owned name, and normalized runtime state. Image, mounts,
network details, limits, publications, environment, raw labels, and Docker
inspect data remain Docker diagnostics and are not copied into the helper API.

`remove` is limited to a verified docker-helper-labelled orphan so that the command cannot become a general Docker container deletion interface.

Session, Launcher, and Principal credentials cannot operate on orphaned objects. Their ownership is absent from persistent state, so only administrator authority may resolve them.

No orphan is adopted or removed automatically.

Orphan adoption is outside Release 3. A later design may add it if operational evidence justifies the additional reconstruction and authorization contract.

## Accepted lifecycle semantics

The canonical Command, Query, HTTP, CLI, state, repair, removal, and
troubleshooting contracts are defined in
`release-3-managed-container-lifecycle.md`. The domain-level invariants are:

- `create` is synchronous, returns a stopped container, and creates no Operation;
- `start` for an already running container is a successful no-op and creates no Operation;
- `stop` for an already stopped container is a successful no-op and creates no Operation;
- `start` for a container paused outside docker-helper resumes it to `running` without exposing pause or unpause Commands;
- `restart` is one Operation implemented as persisted internal `stop` then `start` steps; it performs the full docker-helper stop path followed by the full docker-helper start path, and a stopped container begins at the `start` step;
- `remove` stops a running container internally before removing it;
- a missing backend satisfies the backend postcondition for remove, so the persistent record and leases are removed synchronously without an Operation;
- administrator `container.repair` is an explicit durable Operation for mutable `policy_mismatch` only;
- ordinary callers receive no force mode; administrator `container remove --force` exists only to delete the exact recorded backend object after `ownership_mismatch` and does not skip graceful stop;
- no caller can select the stop timeout;
- stop behavior uses the reloadable administrator setting `container_stop_timeout`, default `10s`, for `stop`, `restart`, `remove`, and Session teardown;
- accepted `stop`, `restart`, `remove`, and Session teardown close exec admission and terminate active exec instances; active exec is not a lifecycle conflict;
- a competing lifecycle mutation returns `409 Conflict` with the active Operation ID and is never queued; the stable error code must not be `container_busy`.

Remove is the explicit supported resolution for a verified resource that the
caller does not want to repair. No diagnostic state or integrity-scan result
causes automatic deletion. Explicit Session closure and TTL expiration are the
sole ownership-lifecycle exception: Session cleanup automatically removes all
resources whose Session ownership is proven. Policy mismatch and unusual
runtime state do not block that cleanup; ownership ambiguity does and leaves the
Session in `cleanup_failed` for administrator action.

## Persistent data boundary

Persistent Managed Container data contains only information required for:

- identity and ownership;
- authorization;
- backend correlation;
- policy verification;
- status and recovery;
- audit attribution.

The persistent record is a management projection, not a normalized copy of the
Docker create request. It retains identity and ownership, ManagedContainerID
and internal BackendContainerID correlation, name, image reference and
immutable image ID, entrypoint, command and workdir, environment key names without
values, mount descriptors, resource limits, port publications, management
state, runtime-correlation data, and required timestamps.

It does not retain environment values, registry credentials, a secret-bearing Docker create payload, or enough configuration to recreate the container autonomously. Docker Engine remains authoritative for the complete runtime configuration.

Exact schema columns, indexes, and migration ordering belong to the implementation design. Field names must preserve the distinction between ManagedContainerID, BackendContainerID, name, management state, runtime observation, and Operation identity.

## Troubleshooting

Domain troubleshooting follows the source-of-truth boundary: operators may use
Docker inspection to diagnose runtime reality, but they must not repair
docker-helper by editing SQLite manually. The supported actions for missing,
unavailable, ownership-mismatched, policy-mismatched, dead, paused, and orphaned
objects are defined in `release-3-managed-container-lifecycle.md` and must be
repeated in the owning CLI help, man pages, and user documentation when the
capability is implemented.

## Deferred to subsequent designs

The following decisions are owned outside this document:

- Session-network provisioning and cleanup mechanics;
- supported resource constraints and hierarchy;
- port-publication grants and allocation;
- logs and exec request contracts;
- WebSocket framing and terminal behavior;
- exact create, networking, resource-limit, publishing, logs, exec, and streaming request fields owned by their later designs.

The accepted networking and resource contracts are
`release-3-session-networking.md` and
`release-3-resource-constraints.md`. The accepted publishing contract is
`release-3-port-publishing.md`. Their values remain part of the immutable
Managed Container create specification defined here.
