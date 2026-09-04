# Release 3 Managed Container Lifecycle

## Purpose

This document is the canonical Release 3 design for Managed Container
lifecycle Commands and Queries.

It fixes the authorization scope, public resource surface, normalized runtime
states, divergence handling, explicit repair and removal paths, list
pagination, and Session-cleanup interaction. The Managed Container identity,
ownership, persistence, and create-consistency model remain canonical in
`release-3-managed-container-domain.md`; the common durable execution contract
remains canonical in `release-3-operation-model.md`.

Exact Go types, SQL DDL, worker mechanics, and Moby client call sequences are
implementation decisions for the operational architect. They must preserve the
public and security contracts defined here.

## Lifecycle boundary

docker-helper manages its own durable resource rather than proxying Docker's
container API.

- Commands express docker-helper postconditions instead of exposing every
  Docker transition or flag.
- Queries return the bounded docker-helper management projection and a
  normalized runtime observation, not Docker inspect data.
- Stored policy is not desired state. A mismatch never starts automatic
  workload repair, restart, or recreation.
- An integrity scan observes and reports; it never deletes or modifies a
  container.
- Resource deletion begins only through an explicit authorized remove Command
  or deterministic cleanup of an explicitly closed or expired owning Session.

Release 3 exposes no pause, unpause, rename, recreate, update, or general
Docker-inspect capability.

## Authorization and target resolution

### Credential scope

A caller's credential establishes the maximum visible and mutable ownership
subtree:

| Credential | Effective Managed Container scope |
| --- | --- |
| Administrator | All Managed Containers. |
| Principal | Containers in all Launchers and Sessions owned by that Principal. |
| Launcher | Containers in Sessions owned by that Launcher. |
| Session bearer | Containers in that Session only. |

An administrator can invoke every ordinary Managed Container Command and Query
and the administrator-only recovery Commands. Administrative execution still
uses the target's owning Session policy and resource limits, does not transfer
ownership, and records the administrator as initiator.

Selectors and list filters can narrow credential scope but can never expand it.
A foreign and a nonexistent target are indistinguishable at the public
boundary.

### Container selector

Ordinary Managed Container Commands accept either:

- a globally unique ManagedContainerID; or
- the immutable `name`, resolved only within one explicit or unambiguously
  credential-implied Session.

The common Session-selection algorithm is defined in
`release-3-api-cli.md`. It allows a Launcher or Principal credential to omit
the Session when its permitted default scope identifies exactly one usable
Session; an administrator must select a Session explicitly when using a local
name. This is a control-plane management rule: the Session data-plane
capabilities (`pull`, `build`, `run`, `registry login`, and both exec modes)
require a Session bearer and never infer a Session from a Principal or
Launcher credential. The CLI form for an explicit selection is:

```text
docker-helper container show --session dhs_... postgres
```

ManagedContainerID needs no Session argument, but authorization is still
checked against the credential scope. Supplying a Session with an ID only
narrows resolution, and a mismatch is indistinguishable from an absent
container. BackendContainerID is never accepted by ordinary container routes.
The administrator-only orphan surface is the sole exception because an orphan
has no persistent Managed Container identity.

## Public resource surface

The lifecycle HTTP resource layout is:

```text
POST   /containers
GET    /containers
GET    /containers/{container}
POST   /containers/{container}/start
POST   /containers/{container}/stop
POST   /containers/{container}/restart
POST   /containers/{container}/repair
DELETE /containers/{container}
```

Start, stop, restart, and repair have empty request bodies and may accept the
durable Operation `Idempotency-Key` header. Removal has no body and does not
accept that header; its resource-level retry converges to `204 No Content`
after deletion. The only request option is administrator-only
`?force=true` for the narrow ownership-mismatch case defined below. Exact
selector, query-validation, and CLI contracts are canonical in
`release-3-api-cli.md`.

The CLI hierarchy is:

```text
docker-helper container create
docker-helper container list
docker-helper container show NAME_OR_ID
docker-helper container start NAME_OR_ID
docker-helper container stop NAME_OR_ID
docker-helper container restart NAME_OR_ID
docker-helper container repair NAME_OR_ID
docker-helper container remove NAME_OR_ID
```

Every command that accepts a Session-local name also accepts optional
`--session`. Lifecycle Commands that create an Operation accept `--detach` and
otherwise wait for its terminal outcome.

There is no `container inspect`. Operators who need raw Docker configuration
use Docker's own inspection tools. docker-helper reports only identity,
ownership, policy, runtime state, and recovery information that it owns.

### Container representation

The exact direct `container.create` and `container.show` representation is
defined in `release-3-api-cli.md` and contains:

- `id`;
- `name`;
- `session_id`;
- requested image reference;
- `runtime_state`;
- optional `condition`;
- immutable workload limits, current effective ancestor-constrained limits,
  and the disabled-swap policy;
- effective port publications;
- `created_at`;
- optional `active_operation_id` while a lifecycle mutation is active.

It does not expose:

- internal management state;
- BackendContainerID;
- raw Docker labels, HostConfig, network IDs, or endpoint IDs;
- command or exec argv, workdir, or environment names or values;
- immutable Docker image ID;
- raw or complete mount configuration.

Internal management state remains persistent because create recovery and
cleanup require it, but it is not a second public state machine.

Resource responses are direct representations. They do not add an `ok: true`
field merely to assert that the represented object exists.

### Response semantics

| Request result | HTTP result |
| --- | --- |
| Successful create | `201 Created` with the stopped Container and `Location: /containers/{id}`. |
| Show | `200 OK` with the Container. |
| Start already running | `200 OK` with the current Container; no Operation. |
| Stop already stopped | `200 OK` with the current Container; no Operation. |
| Accepted lifecycle mutation | `202 Accepted` with the Operation and `Location`. |
| Remove a persistent record whose backend is already missing | `204 No Content`; no Operation. |
| Target absent from persistent state or outside caller scope | `404 Not Found`. |

## Listing

`container list` starts from credential scope and may narrow it by Principal,
Launcher, or Session. The HTTP filters are `principal`, `launcher_id`, and
`session_id`; the CLI flags are `--principal`, `--launcher`, and `--session`.
Combined filters must describe one valid ownership chain. A filter never grants
visibility beyond the authenticating credential.

An item contains the compact management projection needed to identify the
resource without an additional ownership walk:

```json
{
  "id": "dhmc_...",
  "name": "postgres",
  "principal": "alice",
  "launcher_id": "dhl_...",
  "session_id": "dhs_...",
  "image": "postgres:17",
  "runtime_state": "running"
}
```

`condition` and `active_operation_id` are included only when present. Limits,
publications, and timestamps are omitted from list items and remain available
through `show`.

### Pagination

The HTTP Query accepts:

```text
GET /containers?limit=100&cursor=...
```

- default `limit` is 100;
- maximum `limit` is 1000;
- ordering is newest creation first, with ManagedContainerID as the stable
  tie-breaker;
- `cursor` is opaque and denotes the position after the last returned item;
- `next_cursor` is present only when another page exists;
- no `total`, numeric page, or offset is returned.

The response envelope is:

```json
{
  "containers": [],
  "next_cursor": "..."
}
```

The CLI uses `CURSOR`, never `TOKEN`, as the argument placeholder so that a
pagination cursor cannot be confused with an authorization credential.

```text
docker-helper container list
docker-helper container list --limit 100 --cursor CURSOR --json
```

Without `--limit`, the CLI follows all pages and emits the complete list.
`--limit N` returns at most `N` items and stops. `--cursor` selects the starting
position. JSON output preserves the `containers` and `next_cursor` envelope;
tabular output reports a remaining cursor separately on stderr.

## Runtime state

The public runtime state is a docker-helper normalization of a current Docker
Engine observation. It is not a copy of Docker inspect status.

| Runtime state | Meaning |
| --- | --- |
| `stopped` | Backend is created but not executing, including backend `created` and `exited` states. |
| `running` | Workload is executing. |
| `paused` | Workload was paused outside docker-helper. |
| `transitioning` | Backend is restarting or being removed. |
| `dead` | Backend reports an unrecoverable dead state. |
| `missing` | Persistent Managed Container exists but its verified backend object does not. |
| `unknown` | A trustworthy current observation cannot be obtained. |

`paused` is observable because mapping it to `stopped` would hide retained
processes and memory use. It does not add pause or unpause Commands. Human
`container show` output explains that the state originated outside
docker-helper and directs the caller to `container start` to resume or
`container stop` to stop. The JSON representation contains only the stable
state value.

## Conditions and backend divergence

A Condition explains why the persistent management resource and the observed
backend cannot be used normally.

| Condition | Meaning |
| --- | --- |
| `backend_missing` | The recorded backend object is absent. |
| `backend_unavailable` | Docker Engine cannot currently provide a trustworthy observation. |
| `ownership_mismatch` | The recorded backend object exists but immutable docker-helper ownership metadata does not match persistent state. |
| `policy_mismatch` | Ownership is verified, but mutable helper-owned name, Session-network attachment, alias, or resource policy differs from the stored policy. |
| `cleanup_failed` | A create compensation or ownership cleanup could not reach a safe terminal result. |

An orphan is not a Managed Container Condition. It is a Docker object carrying
the complete valid docker-helper ownership-label set whose BackendContainerID
is not correlated with any existing persistent Managed Container record.
Names, partial labels, or visually similar objects are never enough to classify
an orphan.

SQLite is authoritative for Managed Container existence, public identity,
ownership, and expected helper policy. Docker Engine is authoritative for
current runtime reality. Therefore:

- no persistent record means ordinary `show` returns `404`, even if Docker has
  an object with a similar name;
- a persistent record with no backend returns the resource with
  `runtime_state: missing` and `condition: backend_missing`;
- backend unavailability returns the persistent resource with
  `runtime_state: unknown` and `condition: backend_unavailable`;
- mismatch results are returned as Conditions and never repaired implicitly.

## Observation and integrity scan

Daemon startup, `show`, `list`, and mutation preflight observe backend reality
at their appropriate boundaries. In addition, the daemon performs a read-only
integrity scan once per minute.

The scan compares persistent records with Docker objects in the exact
docker-helper ownership-label namespace and verifies the helper-owned
invariants needed to detect:

- missing correlated objects;
- valid labelled orphans;
- ownership metadata mismatch;
- Session-network attachment or alias mismatch;
- diagnostic backend-name mismatch;
- resource-policy mismatch;
- publication mismatch where the backend exposes verifiable evidence.

It emits an operational warning and audit observation only when the detected
Condition changes. It does not create an Operation, delete an object, restore
policy, start or stop workload execution, or adopt an orphan.

The scan detects accidental or operational out-of-band changes. It is not a
security boundary against an actor with root or direct Docker-socket access;
such an actor is outside the docker-helper threat model.

Absence of the whole Session Network is a Session-level condition rather than
one Managed Container's `policy_mismatch`. Its observation and explicit
`session repair` path are defined in `release-3-session-networking.md`.

The one-minute interval is a fixed Release 3 constant rather than a new
operator setting. Before the implementation is frozen, a real-Docker
performance test must measure complete-pass time, Docker API call volume, and
daemon load with a large object set and must prove that scan passes cannot
overlap. Evidence may justify an implementation optimization or later
configuration, but not weaker ownership verification.

## State and Command matrix

The following matrix applies when ownership is verified, the Session is active,
and no helper lifecycle Operation is already active:

| Runtime state | `start` | `stop` | `restart` | `remove` |
| --- | --- | --- | --- | --- |
| `stopped` | `202`, start Operation | `200`, no-op | `202`, restart beginning at start | `202`, remove Operation |
| `running` | `200`, no-op | `202`, stop Operation | `202`, restart Operation | `202`, remove Operation |
| `paused` | `202`, start Operation resumes to running | `202`, full stop | `202`, full stop then start | `202`, remove Operation |
| `transitioning` | `409 backend_transition_in_progress` | `409 backend_transition_in_progress` | `409 backend_transition_in_progress` | `202`, bounded removal attempt |
| `dead` | `409 container_dead` | `409 container_dead` | `409 container_dead` | `202`, remove Operation |
| `missing` | `409 backend_missing` | `409 backend_missing` | `409 backend_missing` | `204`, remove persistent record and leases synchronously |
| `unknown` | no admission | no admission | no admission | no admission |

Backend unavailability returns `503 backend_unavailable` and creates no
Operation. It is a dependency failure, not evidence that a requested
postcondition is satisfied.

Conditions override ordinary state handling:

- `policy_mismatch` rejects start, stop, and restart; normal remove remains
  available because ownership is proven;
- `ownership_mismatch` rejects every ordinary lifecycle Command;
- `cleanup_failed` permits only the recovery or removal path authorized for the
  proven ownership state;
- `container.repair` is available only to an administrator for
  `policy_mismatch`;
- administrator `container remove --force` is the only Release 3 removal path
  for `ownership_mismatch`.

If a docker-helper lifecycle Operation is already active, every competing
mutation returns `409 operation_in_progress` with `details.operation_id` and is
never queued. An idempotent replay that resolves to the existing Operation is
handled before this conflict check. The error code is deliberately not
`container_busy`.

## Command semantics

### Create

`container.create` is synchronous. It returns `201 Created` with a stopped
Container only after persistent ownership, backend correlation, effective name,
network attachment, limits, and publications are committed and verified. It
creates no Operation. The transactional and crash-consistency sequence is
defined in `release-3-managed-container-domain.md`.

### Start and stop

Start means reach `running`; it resumes a container paused outside
docker-helper without exposing an unpause capability. Stop means reach
`stopped`. Repeated start and stop requests whose postconditions already hold
are successful synchronous no-ops.

Callers cannot select a stop signal, force mode, or timeout. One reloadable
administrator setting, `container_stop_timeout`, defaults to 10 seconds and is
used consistently by stop, restart, remove, and Session cleanup.

### Restart

Restart is one public `container.restart` Operation composed of persisted
internal `stop` then `start` steps. It executes the complete docker-helper stop
path followed by the complete docker-helper start path; it never delegates the
contract to Docker's monolithic restart call.

A stopped container begins at the start step. Recovery repeats the current
idempotent step and never infers completion from timestamps or a guessed
runtime incarnation.

### Remove

Remove is the supported user decision for states that docker-helper does not
repair. When ownership is verified it is available from every observable
backend state, subject to the active-Operation conflict rule. It performs the
normal docker-helper stop path when required, removes the exact correlated
backend object, confirms absence, releases publications and other owned
resources, and finally deletes the persistent Managed Container record.

If the backend is already missing, absence is the achieved backend
postcondition. The Command removes the record and leases synchronously and
returns `204 No Content` without manufacturing an Operation.

`--force` has one narrow administrator-only meaning: permit removal of the
exact BackendContainerID recorded for a Managed Container whose ownership
labels no longer verify. It requires ManagedContainerID as the target. It does
not skip graceful stop, alter `container_stop_timeout`, search by Docker name,
or turn docker-helper into a general Docker deletion interface.

The CLI error for `ownership_mismatch` directs an administrator to the exact
recovery form:

```text
docker-helper container remove dhmc_... --force
```

### Repair

`container.repair` is an administrator-only durable Operation for an explicit
`policy_mismatch`. It reapplies only helper-owned mutable policy that Docker can
restore without recreating the container: effective resource limits,
diagnostic backend name, Session-network attachment, and the Session-local
network alias.

Repair does not start, stop, restart, or recreate workload execution. It does
not rewrite immutable ownership labels or port bindings and cannot resolve an
`ownership_mismatch`. Keeping and re-binding an unverified or orphaned backend
object would be adoption and is outside Release 3.

## Session cleanup

Explicit Session closure and Session TTL expiration are the sole automatic
ownership-lifecycle exception to user-decided removal. Cleanup automatically
removes every Session resource whose ownership is proven by persistent
correlation and matching immutable backend metadata. It does not ask for a
separate per-container decision.

Runtime `paused`, `transitioning`, or `dead` and `policy_mismatch` do not block
cleanup because ownership remains proven. A missing backend satisfies the
backend-removal postcondition and allows persistent cleanup. Backend
unavailability causes the immutable cleanup attempt to fail transiently and
the Session-owned retry schedule to create a later attempt.

An `ownership_mismatch` or other ambiguity that prevents proof of ownership
moves the Session to `cleanup_failed`; cleanup never guesses and never deletes
that backend automatically. An administrator must inspect the discrepancy and
explicitly use the supported force-removal path.

The integrity scan never invokes Session cleanup. Cleanup begins only because
the Session was explicitly closed or its pre-existing TTL expired.

## Orphan administration

Orphan handling remains administrator-only:

```text
docker-helper container orphan list
docker-helper container orphan show BACKEND_CONTAINER_ID
docker-helper container orphan remove BACKEND_CONTAINER_ID
```

The canonical HTTP routes are the separate `/container-orphans` collection
defined in `release-3-api-cli.md`. An orphan is not addressed under
`/containers` because it has no persistent Managed Container resource.

`orphan remove` accepts only an object with the complete valid docker-helper
ownership-label set and no correlated persistent record. It deletes that exact
backend object synchronously, using the common graceful stop timeout when
needed. Principal credentials, Launcher credentials, and Session tokens
cannot inspect or operate
on orphans.

No orphan is adopted or removed automatically. `adopt` and `rebind` are outside
Release 3. The supported Release 3 resolution is explicit administrator
removal.

## Audit and operational visibility

Create, lifecycle admission, no-op outcomes, repair, removal, Session cleanup,
authorization denial, and Condition transitions are auditable with public
resource identities and initiator attribution.

Audit and operational records never contain bearer credentials, environment
values, workload output, or a copied Docker inspect payload. Integrity warnings
are emitted only when the observed Condition changes so the one-minute scan
does not create repetitive log noise.

## Troubleshooting contract

The lifecycle, API/CLI, and later user-facing documents include local
Troubleshooting sections rather than relying on one context-free error list.

| Observation | Supported action |
| --- | --- |
| `paused` | Use `container start` to resume or `container stop` to stop; pause/unpause are not public capabilities. |
| `backend_missing` | Use `container remove` to remove the persistent record and release leases; no recreation occurs. |
| `backend_unavailable` | Restore Docker Engine availability or helper access, then retry; no mutation was admitted. |
| `policy_mismatch` | Administrator uses `container repair`, or an authorized owner chooses normal remove. |
| `ownership_mismatch` | Administrator inspects the exact recorded backend and explicitly uses `container remove dhmc_... --force` if deletion is intended. |
| `dead` | Remove the container; Release 3 does not attempt workload recovery. |
| persistent `transitioning` | Check `active_operation_id`; if no helper Operation owns the transition, an authorized caller may choose remove. |
| orphan | Administrator uses the orphan list/show/remove surface; no adoption is available. |

Whole-Session `network_missing` troubleshooting belongs to
`release-3-session-networking.md`; it is not resolved by iterating
`container repair` manually.

Troubleshooting may direct an administrator to Docker's diagnostic tools, but
must not instruct operators to edit docker-helper SQLite state manually.
Dangerous CLI help must state both what safety check is overridden and what is
not changed. In particular, `container remove --help` documents:

```text
--force  Admin only. Remove the recorded backend container even when its
         ownership labels cannot be verified. Does not skip graceful stop or
         change the stop timeout.
```

## Verification requirements

The lifecycle implementation is not complete without tests for:

- every state and Condition row in the Command matrix;
- cross-Session denial and identical foreign/nonexistent behavior;
- administrator, Principal, Launcher, and Session token scopes and narrowing
  filters;
- name resolution with an explicit Session and globally unique ID resolution;
- state-matching no-ops versus accepted durable mutations;
- active-Operation conflict and idempotent replay ordering;
- persisted restart steps and crash recovery;
- paused-state reporting and start/stop behavior;
- normal removal, missing-backend synchronous removal, policy repair, and
  administrator force removal;
- Session expiration deleting every resource with proven ownership while
  ambiguous ownership remains `cleanup_failed`;
- orphan discovery without automatic adoption or deletion;
- read-time and one-minute scan detection of out-of-band changes;
- no scan-triggered mutation and no repetitive unchanged-condition warnings;
- bounded paginated listing across every credential scope;
- large-object-set scan timing, Docker API call volume, and overlap prevention;
- help, completion, man-page, architecture, README, and agent-skill consistency.

Real-Docker integration tests are required for lifecycle transitions, backend
tampering, immutable-label mismatch handling, resource and network repair,
Session cleanup, and scan behavior. Unit tests alone cannot establish these
contracts.
