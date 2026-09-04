# Release 3 Port Publishing

## Purpose

This document is the canonical Release 3 design for publishing selected
Managed Container ports to the host.

It fixes the publishing boundary, hierarchical grants, explicit and automatic
allocation, durable leases, container-lifecycle behavior, collision handling,
inspection, cleanup, and troubleshooting. Session-internal communication
remains canonical in `release-3-session-networking.md`; Managed Container
creation and lifecycle remain canonical in
`release-3-managed-container-domain.md` and
`release-3-managed-container-lifecycle.md`.

Exact Go types, SQL DDL, Moby request fields, allocation queries, and public
JSON or CLI spelling are implementation decisions for the operational
architect and `release-3-api-cli.md`. They must preserve the authorization,
lease, and failure contracts defined here.

## Boundary

Port publishing is a narrow capability for exposing a service running in a
Managed Container to software on the same host.

Release 3 supports only:

- a concrete container port;
- TCP;
- IPv4 loopback address `127.0.0.1`;
- an explicitly requested allowed host port or server-selected host port;
- at most 16 publications per Managed Container.

Release 3 does not provide:

- UDP;
- IPv6 publication;
- external-interface or wildcard binding;
- caller-selected host addresses;
- one-shot `run` publication;
- host networking, arbitrary Docker networks, routing, or proxy rules;
- publication mutation after Managed Container creation;
- a standalone port, service, listener, or ingress resource.

External-interface publishing remains outside Release 3. It is not promised for
any particular later release.

docker-helper authorizes and records the mapping, then asks Docker Engine to
apply it. It does not proxy traffic, retain a forwarding socket, inspect
traffic, or implement its own transport protocol.

## Loopback isolation prerequisite

Docker documents that Engine releases older than 28.0.0 can make ports
published to localhost reachable from other hosts in the same L2 segment.
Because docker-helper does not add its own firewall layer, Release 3 enables
port publishing only when the connected Docker Engine reports version 28.0.0
or newer. See Docker's
[port-publishing warning](https://docs.docker.com/engine/network/port-publishing/#publishing-ports).

An older or unidentifiable Engine does not prevent the daemon from serving
unrelated capabilities. A Managed Container create request containing any
publication fails closed with `publishing_backend_unsupported` before a lease
or backend container is created.

If an administrator later connects docker-helper to an older Engine while
published Managed Containers already exist, integrity observation reports
`policy_mismatch` with the unsupported publishing backend as its reason.
docker-helper blocks create, start, and restart for affected containers but
keeps show, stop, remove, and Session cleanup available. It emits an operator
warning and an audit event, but does not stop a running container
autonomously. Docker Engine selection and downgrade remain trusted
administrator actions under the project-wide trust model.

The Session Network remains a normal user-defined IPv4 bridge using Docker's
`nat` gateway mode. docker-helper does not enable direct routing, trusted host
interfaces, or unprotected gateway modes. The Docker Engine and its
administrator-controlled configuration remain trusted according to the
project-wide trust model.

## Publication model

One publication maps:

```text
127.0.0.1:<host-port>/tcp -> <container-port>/tcp
```

The conceptual public fields are:

| Field | Meaning |
| --- | --- |
| Container port | Destination TCP port inside the Managed Container. |
| Host address | Always `127.0.0.1` in Release 3. |
| Host port | Explicit allowed value or concrete value selected by docker-helper. |
| Protocol | Always `tcp` in Release 3. |

The request omits the host port to ask for automatic allocation. It does not use
port zero, a magic string, or a separate preliminary allocation request.

Container and host ports are integers in `1..65535`. The same container port
may appear only once in one Managed Container create request. Docker image
`EXPOSE` metadata is neither required nor authoritative; a caller may publish a
valid port whether or not the image declares it.

Publications belong to the Managed Container create specification and are
immutable. Release 3 has no `container publish`, `unpublish`, or port-update
Command. Changing a mapping requires removing and recreating the Managed
Container through the normal ownership and naming contracts.

The effective address and port are returned by synchronous `container.create`
and retained by `container.show`. List output remains compact and does not
become a port table.

## Publishing grants

A Publishing Grant is authorization to allocate a host port from one inclusive
contiguous range. It is not a reservation of every port in that range.

Grants narrow through the ownership hierarchy:

```text
Root -> Principal -> Launcher -> Session -> Managed Container publication
```

The Root default is:

```text
20000-29999
```

This provides 10,000 unprivileged host ports without requiring configuration in
the ordinary single-user workflow.

An omitted Principal, Launcher, or Session grant inherits its parent's complete
current effective range. An explicit child range must be contained within the
effective parent range when written and is revalidated through the complete
hierarchy when used. An explicit disabled policy permits no publication in that
subtree. The Root policy is either one explicit range or disabled; omission at
initialization selects the default range above.

The effective range is the intersection of every non-inherited range in the
current ownership chain. Consequently, later parent narrowing can reduce a
descendant's effective range without rewriting the descendant's stored policy;
existing leases still impose the update restriction defined below.

Policy-management authority follows ownership:

| Target grant | Who may configure it |
| --- | --- |
| Root | Administrator through server configuration. |
| Principal | Administrator. |
| Launcher | Administrator or owning Principal. |
| Session | Administrator, owning Principal, or owning Launcher. |

A subject cannot widen its own grant. A parent authority may replace a child
grant within its own current effective range. A Session bearer may request a
publication inside the already effective Session grant during container create
but cannot alter that grant. Administrator authority remains available at every
level and still obeys the Root publishing boundary.

Grant replacement is atomic and follows the existing allowed-root style: one
complete `inherit`, restricted-range, or disabled policy replaces the previous
value. The CLI must not implement GET, local modification, then PUT as a hidden
read-modify-write sequence.

`session show` reports the effective allowed range or disabled state together
with the other Session grants. There is no separate endpoint or preliminary
request for discovering available ports. A grant reports authority, not a live
list of unused ports.

Principal, Launcher, and Session show responses use the canonical JSON shape:

```json
{
  "publishing_grant": {
    "mode": "explicit",
    "value": {"start": 24000, "end": 24999},
    "effective": {"start": 24000, "end": 24999}
  }
}
```

`mode` is `inherit`, `explicit`, or `disabled`; Root uses only `explicit` or
`disabled`. `value` appears only for an explicit stored policy. `effective`
appears for every permitted grant and is omitted when disabled. No show
projection reports free, occupied, leased, or remaining ports.

Principal, Launcher, and Session policies are replaced through atomic
`PUT /principals/{username}/publishing-grant`,
`PUT /principals/{username}/launchers/{launcher}/publishing-grant`, and
`PUT /sessions/{session_id}/publishing-grant` subresources. A complete request
selects exactly one of `inherit`, `disabled`, or an `explicit` nested
`value.start`/`value.end` range. The response is the updated
configured/effective `publishing_grant` object. CLI
`principal|launcher|session publishing-grant set` commands expose mutually
exclusive `--inherit`, `--disable`, and `--range START-END` modes and do not
perform hidden read-modify-write.

## Grants are not reservations

Sibling grants may overlap. In particular, the default Principal and Launcher
inheritance gives each child the full parent range. No child owns those ports
until a concrete lease is admitted.

When creation or update leaves a second Principal or a second sibling Launcher
inheriting the same parent's full range, docker-helper emits an operator
warning. It does not:

- split the range into tenths or other fractions;
- reserve a subrange based on creation order;
- reject the child;
- promise either child a minimum number of available ports.

The warning is not emitted merely because several Sessions exist under one
Launcher. Sessions routinely share Launcher authority, and concrete lease
uniqueness already prevents helper-owned collisions.

An administrator may assign disjoint restricted ranges on a shared host when
stronger operational separation is needed. Production evidence may later
justify a stricter policy; Release 3 does not force that complexity into the
single-user quick start.

## Port leases

A Port Lease reserves one concrete tuple within one docker-helper state store:

```text
(127.0.0.1, tcp, host_port)
```

It belongs to exactly one Managed Container publication. A database uniqueness
constraint is the authority against collisions between helper-managed
containers; an in-memory allocator is not.

Lease lifetime equals Managed Container lifetime:

- admitted transactionally with the provisional `creating` container record;
- retained while the container is stopped, running, paused, failed, or being
  restarted;
- retained across docker-helper restart;
- retained after a failed start or partially completed lifecycle Operation;
- released only when container removal or Session cleanup has confirmed the
  backend-removal postcondition and removes the persistent Managed Container;
- released during create compensation only after absence of the backend object
  is established.

Stop never releases a lease. Restart never reallocates it. A lost client
response never grants the port to a second container while create recovery is
still resolving the first.

Separate docker-helper daemons or state stores do not share this lease table.
They, unmanaged Docker containers, and ordinary host processes are external
competitors for the same host socket.

## Allocation

### Explicit host port

An explicit request succeeds only when the port:

- is within `1..65535`;
- lies inside the Session's current effective grant;
- is not leased by another Managed Container in the same state store;
- is not observed as already bound on `127.0.0.1` at admission time.

A request outside the effective grant is an authorization failure. A current
helper lease or observed host bind is a collision, not an authorization
failure.

### Automatic host port

When the host port is omitted, docker-helper selects one candidate from the
Session's effective range that:

- has no helper lease;
- is not observed as already bound on `127.0.0.1` at admission time.

Candidate order is not a public contract. The implementation may choose the
simplest race-safe selection compatible with SQLite and the expected small-host
workload. It must not depend on a prior list call or client-side selection.

Explicit and automatic allocation use the same transaction and uniqueness
constraint. Concurrent requests either obtain distinct leases or one request
retries its automatic candidate. Retries are bounded by the finite effective
range, not by an arbitrary small attempt count. Requests never both
commit the same tuple.

Only after every candidate in the effective range has been rejected may create
fail before backend container creation with `port_range_exhausted`.
docker-helper does not allocate outside the Session grant or fall back to an
external address.

## Host collision boundary

A successful availability probe is only an observation. docker-helper does not
hold the host socket, and a stopped Docker container does not bind its published
port. Therefore a foreign process can claim the port after create or while the
Managed Container is stopped.

docker-helper guarantees lease uniqueness only among Managed Containers using
the same state store. It does not promise exclusive host-port ownership against
root, direct Docker users, other daemon instances, or ordinary host processes.

If Docker cannot bind the retained port during start:

- the start Operation fails with `host_port_unavailable`;
- the Managed Container remains stopped;
- its publication and lease remain unchanged;
- docker-helper does not select a replacement port silently;
- the caller frees the host port and retries start, or removes and recreates the
  Managed Container with a different mapping.

The same rule applies if a restart completes its stop step and the original
port is taken before its start step. Restart fails with the container stopped
and preserves the lease and requested identity. It never turns one restart into
an unannounced endpoint change.

This behavior is a consequence of docker-helper not being a proxy. Permanent
socket reservation for stopped containers would require a separate traffic
owner and is outside Release 3.

## Create and lifecycle integration

`container.create` validates the complete publication list and reserves all
required leases in the same database transaction that inserts the provisional
Managed Container. Partial lease admission is never exposed: either every
publication is reserved or none is.

The backend container is created with exactly those immutable TCP bindings and
the fixed loopback address. Create returns `201 Created` only after backend
correlation and publication verification succeed. The response contains every
automatically selected host port.

Create compensation follows the common `creating` recovery contract. It does
not free leases while a backend container with the bindings may still exist.

Start, stop, and restart use the retained bindings:

- start asks Docker to activate the existing mapping;
- stop releases Docker's live socket but not the helper lease;
- restart performs the accepted full helper stop followed by full helper start
  and retains the same mapping throughout;
- remove stops when required, removes the exact verified backend, then releases
  the persistent publication with the Managed Container record.

No lifecycle Operation owns a second copy of the publication specification.
Its target remains the Managed Container.

## Grant updates with existing leases

A grant update is rejected with `port_grant_in_use` when its new effective
range would exclude any existing descendant lease. Stopped containers count
because their leases remain part of their immutable identity.

docker-helper never responds to a grant reduction by:

- reallocating a port;
- changing a backend binding;
- removing or stopping a Managed Container;
- grandfathering a lease outside the reported effective grant;
- queuing a later policy change.

The administrator or owning parent first removes the affected Managed
Containers, then retries the atomic grant replacement. Widening or narrowing
that preserves every existing lease does not mutate containers.

## Observation and mismatch

Container show and the common integrity scan compare the persistent
publication specification with Docker's verified port-binding configuration.
They never probe, capture, or log application traffic.

If the verified backend binding differs from the persistent publication or a
lease is missing or conflicting, the Managed Container reports
`policy_mismatch`. Port bindings are immutable in Release 3, so
`container.repair` does not rewrite them. The supported resolution is explicit
Managed Container removal followed by create with the intended publication.

A foreign process occupying a correctly configured stopped container's leased
port is not a persistent `policy_mismatch`: it is external runtime contention
reported when Docker start fails. The read-only integrity scan does not
continuously probe every host port.

## Session cleanup

Session cleanup removes verified Managed Containers before releasing their port
leases. It then removes the Session Network according to the networking
contract.

Unusual runtime state or publication `policy_mismatch` does not block cleanup
when backend ownership is proven. Backend unavailability or an ambiguous
removal result keeps the lease and causes the immutable cleanup attempt to fail
under the existing retry contract. Ownership mismatch moves the Session to
`cleanup_failed`; cleanup never frees the lease and leaves an unverified backend
possibly binding the same host port.

An already-missing verified backend satisfies removal, allowing its persistent
record and leases to be deleted synchronously. Physical Session deletion has no
independent live leases left to clean.

## Public representation

The exact JSON keys and CLI flags are defined in `release-3-api-cli.md`. That
surface must preserve these semantics:

- create input gives one container port and an optional host port per mapping;
- TCP and `127.0.0.1` are fixed policy, not caller-controlled choices;
- create and show return the concrete host address, host port, container port,
  and protocol;
- Session show returns its effective grant or disabled state;
- no endpoint returns a speculative list of currently free ports;
- no endpoint mutates an existing Managed Container publication.

Human output should render a mapping directly, for example:

```text
127.0.0.1:23456 -> 8080/tcp
```

The CLI may offer a concise create flag, but it must send the complete intended
publication in one request. It must not allocate, probe, or remember ports
locally.

## Errors and audit

The stable publishing error categories are:

| Code | Meaning |
| --- | --- |
| `invalid_publication` | Container port, host port, duplicate mapping, or request cardinality is invalid. |
| `port_not_allowed` | An explicit host port lies outside the effective Session grant or publishing is disabled. |
| `host_port_unavailable` | A concrete port is leased, observed bound at admission, or rejected by Docker as unavailable during start. |
| `port_range_exhausted` | Automatic allocation found no admissible port in the effective Session range. |
| `port_grant_in_use` | A grant reduction would exclude an existing descendant lease. |
| `publishing_backend_unsupported` | The connected Docker Engine cannot provide the required Release 3 loopback-publishing boundary. |

Authorization and Session resolution happen before errors disclose grant or
lease state. Error details may include the caller's requested port and its own
effective range but never identify the foreign Principal, Launcher, Session,
Managed Container, process, or Docker object occupying it.

Grant creation and replacement, publication admission and release, allocation
failure, Docker bind failure, and detected publication mismatch are audited
with public ownership identities and normalized port mappings. Audit contains
no workload traffic, payload, output, backend container ID, or raw Docker
inspection data.

## Troubleshooting contract

User-facing documentation, CLI help, and the manual must include these paths:

| Observation | Supported action |
| --- | --- |
| `port_not_allowed` | Inspect the effective grant with `session show`; request an allowed port or omit the host port for automatic allocation. |
| `port_range_exhausted` | Remove unused Managed Containers/publications or ask the owning policy manager to widen the Session grant. |
| `host_port_unavailable` during create | Choose another explicit port or use automatic allocation. |
| `host_port_unavailable` during start/restart | Free the foreign host socket and retry, or remove and recreate the Managed Container with another mapping. |
| publication `policy_mismatch` | Remove and recreate the Managed Container; `container repair` does not change immutable bindings. |
| `port_grant_in_use` | Remove containers holding out-of-range leases, then retry the grant replacement. |
| `publishing_backend_unsupported` | Upgrade Docker Engine to version 28.0.0 or newer; docker-helper does not emulate loopback isolation with its own firewall. |

Troubleshooting may direct an administrator to host and Docker diagnostics but
must not tell operators to edit the SQLite lease table. docker-helper does not
claim to identify or terminate the unrelated process holding a host socket.

## Verification requirements

Implementation is not complete without tests for:

- Root default range and inclusive boundary validation;
- inherit, restricted, and disabled grants through Root, Principal, Launcher,
  and Session;
- revalidation against every ancestor at admission;
- Session show returning the effective grant without a free-port endpoint;
- explicit and automatic create mappings;
- automatic allocation under concurrent requests and uniqueness conflicts;
- all-or-nothing allocation of multiple publications;
- the 16-publication and duplicate-container-port limits;
- rejection of UDP, IPv6, external bind addresses, and out-of-range ports;
- fail-closed publication on Docker Engine versions older than 28.0.0 or an
  unidentifiable Engine, without disabling unrelated daemon capabilities;
- backend downgrade observation, blocked start/restart, and retained
  stop/remove/cleanup access without autonomous container mutation;
- no dependency on image `EXPOSE` metadata;
- retained leases across stop, restart, daemon restart, and failed start;
- create compensation and removal releasing leases only after backend absence;
- failed narrowing with descendant leases and successful safe replacement;
- host-port contention at create and at later start;
- publication mismatch observation without automatic mutation;
- Session cleanup in success, missing-backend, transient-failure, and ownership-
  ambiguity cases;
- warning behavior for full-inheriting sibling Principal and Launcher grants;
- help, manual, architecture, and packaged `SKILL.md` consistency.

Real-Docker integration tests are required in both system and rootless modes
for fixed loopback binding, same-host TCP connectivity, rejection of non-host
access in the supported network configuration, Docker start/restart behavior,
host-socket contention, inspection, and cleanup. The supported-daemon matrix
must include the minimum Engine version. Unit tests alone cannot establish
these contracts.
