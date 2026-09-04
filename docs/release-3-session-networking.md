# Release 3 Session Networking

## Purpose

This document is the canonical Release 3 design for Session-owned networking.

It fixes network ownership, lazy provisioning, workload attachment, name
resolution, integrity observation, explicit recovery, and Session-cleanup
behavior. Port publishing is defined canonically in
`release-3-port-publishing.md`; container identity and lifecycle remain
canonical in `release-3-managed-container-domain.md` and
`release-3-managed-container-lifecycle.md`.

Exact Go types, SQL DDL, Moby client calls, and locking mechanics are
implementation decisions for the operational architect. They must preserve the
public and security contracts defined here.

## Boundary

A Session Network is infrastructure owned by exactly one Session. It is not a
second user-managed resource hierarchy and docker-helper does not expose a
general Docker network API.

Release 3 provides:

- one user-defined bridge network per Session when a workload first needs it;
- same-Session communication through Managed Container names;
- ordinary Docker outbound connectivity;
- ownership verification, bounded diagnostics, explicit repair, and
  deterministic cleanup.

Release 3 does not provide:

- caller-selected Docker networks, drivers, subnets, gateways, static IP
  addresses, or additional aliases;
- host networking, a special host alias, or a host-access grant;
- an internal-only network or a new egress firewall;
- cross-Session attachment or service discovery;
- automatic background repair or reconciliation;
- a public network list, show, create, remove, connect, or disconnect surface.

The Docker Engine API is the backend mechanism. The Session Network uses the
ordinary IPv4 `nat` gateway mode and does not enable direct routing, trusted
host interfaces, or an unprotected gateway mode. This fixed backend policy is
required by the loopback publishing boundary defined in
`release-3-port-publishing.md`. Docker network identifiers and endpoint
identifiers never become public authority.

## Ownership and identity

The Session is the sole network owner. Principal and Launcher scope determine
who may act on the Session but do not become parallel network owners.

The diagnostic Docker name is:

```text
dhsn-<full-session-id>
```

The full Session ID prevents ordinary deployment-wide name collisions. The
name is diagnostic only. Persistent backend correlation plus complete immutable
docker-helper ownership labels prove identity; a matching or similar Docker
name proves nothing.

The helper persists only the correlation and policy data needed to verify,
repair, and remove the network. It does not persist a general Docker network
inspection payload.

If the expected name is occupied by a network whose exact ownership cannot be
proved, docker-helper neither attaches workloads to it nor modifies or removes
it. The request fails with `network_name_conflict`. An administrator diagnoses
and resolves the foreign Docker object using Docker's own tools.

## Topology and attachment

Managed Containers and one-shot `run` workloads attach only to the network of
their owning Session. Build execution does not attach to a Session Network.

Each Managed Container's immutable public `name` is also its only
docker-helper-managed DNS alias on that network. docker-helper does not invent a
second display name, silently normalize the alias, or accept extra aliases.
One-shot `run` may address Managed Containers by those names but does not create
a durable addressable resource of its own.

A workload from another Session cannot request attachment to or address the
network through docker-helper. Direct Docker or root access remains outside the
docker-helper threat boundary.

The network uses ordinary Docker bridge behavior and Engine-managed address
allocation. Release 3 adds no helper subnet allocator or user-facing IPAM
configuration. Backend allocation failure is reported as a sanitized
dependency failure; docker-helper does not silently fall back to host networking
or another Session's network.

## Lazy provisioning

Session creation remains a database-only action and does not require Docker to
be available. The first `container.create` or one-shot `run` that requires the
network provisions it.

Provisioning must:

1. authorize the workload against an active Session;
2. serialize concurrent first users of the same Session;
3. resolve an already-correlated network by backend identity and verify its
   immutable ownership metadata;
4. recover an interrupted helper creation only from the exact Session ownership
   labels, never from the Docker name alone;
5. create and correlate one network when no valid network exists;
6. attach the workload only after the network identity is verified.

Concurrent first requests converge on one network. A Query never provisions
Docker infrastructure.

There is no persistent `network_was_created` flag. Network absence is
interpreted from the Session's dependent resources:

- when the Session has no Managed Containers, absence is a valid unprovisioned
  state even if an earlier transient workload once caused provisioning; the
  next network-dependent Command follows the normal lazy path;
- when the Session has Managed Containers, the network is required and absence
  is divergence that must be reported and repaired explicitly.

This rule avoids retaining meaningless history while distinguishing a harmless
lazy state from broken connectivity.

## Observation and divergence

Startup inspection, read-time observation, mutation preflight, and the common
once-per-minute read-only integrity scan verify:

- correlated network existence;
- exact immutable ownership metadata;
- Session-to-network correlation;
- Managed Container attachment and Session-local alias;
- complete valid helper labels on any uncorrelated network discovered in the
  helper namespace.

Observation emits a warning and audit event only when the condition changes.
It never creates, reconnects, removes, adopts, or otherwise repairs a network.

When a Session has Managed Containers but its correlated network is absent,
`session show` reports `condition: network_missing` and human output directs an
authorized caller to `session repair`. Queries and destructive container
cleanup remain available. Commands whose result requires a valid Session
Network, including new create/run admission and container start or restart, are
rejected with `session_network_missing` until repair succeeds.

A missing individual attachment or alias on an otherwise valid network remains
a Managed Container `policy_mismatch` and follows the administrator-only
`container repair` contract. A missing whole Session Network uses the
Session-level repair path because restoring it affects multiple containers.

Backend unavailability is not network absence. It returns the common
`backend_unavailable` dependency failure and admits no repair Operation.

## Explicit Session repair

The public recovery capability is:

```text
POST /sessions/{session_id}/repair
docker-helper session repair --id SESSION_ID [--detach]
```

The HTTP request body is empty, the Session ID is always explicit, and a
direct protocol client may supply `Idempotency-Key`. The CLI requires `--id`,
waits for accepted work by default, and may return after admission with
`--detach`.

An authorized Session bearer, owning Launcher, owning Principal, or
administrator may request repair within its credential scope. Administrator
authority remains available for every Session. Selectors never expand token
scope, and foreign and nonexistent Sessions remain indistinguishable.

`session repair` is deliberately narrower than a general network management
command. For an active Session with a missing network and existing Managed
Containers, it creates one durable `session.repair` Operation. The handler:

1. rechecks that the Session is active and the correlated network is absent;
2. refuses a foreign object occupying the diagnostic name;
3. creates and durably correlates the canonical Session Network;
4. reconnects every existing Managed Container whose backend identity and
   Session ownership are proven;
5. restores each immutable Session-local alias;
6. confirms the complete network postcondition before succeeding.

The Operation is restart-recoverable and idempotent at each internal step.
Partial attachment failure leaves the Operation `failed` and the
`network_missing` condition observable; a later explicit request creates new
work. docker-helper never claims success for a partially restored Session.

If the Session already has a valid network, or has no Managed Containers and
therefore no broken network invariant, repair is a synchronous successful
no-op with HTTP `200` and `{\"ok\":true}` and creates no Operation or
idempotency record. It does not provision an unused network.

Only one Session network repair or cleanup mutation may be active. While repair
is active, new network-dependent Commands return `409 operation_in_progress`
with the active Operation ID. Session closure and TTL expiration use the common
cleanup coordination rules rather than waiting in a hidden queue.

Repair does not adopt a foreign network, rewrite unverifiable ownership labels,
change network policy, start or stop containers, or delete a conflicting Docker
object. Those actions are outside Release 3.

## Cleanup

Explicit Session closure and TTL expiration remove workloads before the
Session Network. Cleanup deletes only the exact correlated network whose
immutable Session ownership is proven. Network absence after workload removal
already satisfies the deletion postcondition.

Backend unavailability or a bounded removal failure makes that immutable
`session.cleanup` attempt fail and leaves the Session `closing` for its existing
retry schedule. An ownership mismatch moves the Session to `cleanup_failed`;
cleanup never deletes a network by name or guesses which object belongs to the
Session.

The Session record remains authoritative until cleanup confirms that all owned
backend resources are absent. Normal cleanup ordering therefore does not create
an uncorrelated network by deleting persistent ownership first.

## Audit and troubleshooting

Provisioning, repair admission and outcome, cleanup, authorization denial,
name conflict, and network condition transitions are auditable with the public
Session identity and initiator attribution. Audit records contain no bearer
material, Docker inspection payload, workload traffic, or workload output.

User-facing documentation, CLI help, and the manual must include these recovery
paths:

| Observation | Supported action |
| --- | --- |
| No network and no Managed Containers | No action; the next create or run provisions it lazily. |
| `network_missing` | Run `docker-helper session repair --id SESSION_ID`. |
| `network_name_conflict` | Administrator inspects and resolves the conflicting object with Docker, then retries repair. |
| One container has `policy_mismatch` | Administrator uses `container repair`, or an authorized owner removes the container. |
| `backend_unavailable` | Restore Docker Engine availability or helper access, then retry. |
| Session `closing` | Observe or retry the existing Session cleanup contract; do not repair the network. |
| Session `cleanup_failed` | Administrator resolves the reported ownership ambiguity; never edit SQLite manually. |

## Verification requirements

Implementation is not complete without tests for:

- database-only Session creation while Docker is unavailable;
- concurrent lazy provisioning converging on one network;
- exact-label recovery after interruption between backend creation and durable
  correlation;
- rejection of same-name foreign networks and cross-Session attachment;
- Managed Container DNS resolution within one Session and isolation between
  Sessions;
- one-shot `run` attachment and build non-attachment;
- missing-network observation with and without existing Managed Containers;
- successful and partially failed `session.repair`, including daemon-restart
  recovery;
- individual attachment and alias mismatch remaining `policy_mismatch`;
- cleanup success when the network is already absent;
- cleanup refusal when ownership cannot be proved;
- warning and audit deduplication across repeated scan passes;
- help, manual, architecture, and agent-skill consistency.

Real-Docker integration tests are required for bridge isolation, DNS aliases,
outbound connectivity, lazy-create races, repair attachment behavior, ownership
labels, and teardown. Unit tests alone cannot establish these contracts.
