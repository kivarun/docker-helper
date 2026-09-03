# Release 3 Resource Constraints

## Purpose

This document is the canonical Release 3 design for resource constraints on
Managed Containers and one-shot `run` workloads.

It fixes the supported resource vocabulary, hierarchical authorization model,
safe defaults, workload admission, runtime enforcement, policy updates,
inspection, and failure behavior. Managed Container creation and persistence
remain canonical in `release-3-managed-container-domain.md`; exact public field
and CLI flag syntax belongs to `release-3-api-cli.md`.

Exact Go types, SQL DDL, cgroup paths, Moby request fields, and systemd or
cgroupfs mechanics are implementation decisions for the operational architect.
They must preserve the aggregate and per-workload enforcement contracts below.

## Boundary

Resource constraints protect a local or small shared Docker host from
agent-controlled workloads. They are a security boundary, not a scheduler,
reservation system, or promise of workload performance.

Release 3 supports:

- aggregate CPU ceilings;
- aggregate memory ceilings;
- aggregate process ceilings;
- explicit per-workload CPU, memory, and process limits;
- explicit per-workload shared-memory size;
- disabled workload swap.

Release 3 does not expose arbitrary Docker `HostConfig`, resource flags, or a
generic cgroup interface. It does not add capacity reservations, remaining
quota accounting, workload priorities, CPU pinning, NUMA policy, I/O weights or
bandwidth, GPU allocation, huge pages, disk quotas, or build resource control.

Every Managed Container and one-shot `run` receives concrete limits. Omitted
request fields select safe inherited defaults; they never mean unbounded Docker
behavior.

## Vocabulary

The following terms have distinct meanings:

| Term | Meaning |
| --- | --- |
| Resource ceiling | Maximum aggregate use permitted to one ownership subtree. |
| Workload limit | Concrete maximum applied to one Managed Container or one-shot `run`. |
| Requested limit | Optional value supplied by a workload caller to narrow its authority. |
| Effective ceiling | Intersection of one policy node with all ancestor ceilings and the deployment's enforceable system boundary. |
| Effective workload limit | Concrete workload limit after defaults and ceiling checks are applied. |

Resource ceilings are not reservations. Two children may each be authorized up
to their full parent ceiling, while the parent cgroup prevents their combined
actual use from exceeding it.

`Root` in this document means the docker-helper resource-policy root. It does
not mean the Unix root user and must not be inferred from the daemon process's
own cgroup.

## Ownership hierarchy

Resource ceilings narrow through the existing ownership hierarchy:

```text
Root -> Principal -> Launcher -> Session -> workload
```

Root, Principal, Launcher, and Session ceilings contain CPU, memory, and PIDs.
The effective value at each node cannot exceed its effective parent.

An omitted Principal, Launcher, or Session value inherits its parent's complete
effective value. Inheritance is represented as inheritance, not copied into a
second independent configured number. A later parent reduction therefore
continues to constrain every descendant.

Policy-management authority follows ownership:

| Target ceiling | Who may configure it |
| --- | --- |
| Root | Administrator through server configuration. |
| Principal | Administrator. |
| Launcher | Administrator or owning Principal. |
| Session | Administrator, owning Principal, or owning Launcher. |

A subject cannot widen its own authority. An allowed parent may set or change a
child ceiling only within its own current effective ceiling. A Session bearer
cannot modify hierarchy policy. Administrator access remains available at
every level but does not bypass the Root ceiling for workload execution.

The public management representation must distinguish an explicit configured
value from inheritance and must also show the resulting effective ceiling.
Ordinary quick-start output may emphasize the effective value; automation must
not have to infer policy from human text.

## Default Root ceiling

Initialization derives the default Root ceiling from Docker Engine-reported
capacity, not from the docker-helper process cgroup:

| Dimension | Default |
| --- | --- |
| Memory | 75% of Engine `MemTotal`, rounded down to 256 MiB. |
| CPU | Engine `NCPU` minus the larger of 0.5 CPU or 10%, rounded down to 0.1 CPU. |
| PIDs | 512 processes or threads across the docker-helper workload subtree. |

The calculated values are materialized as explicit server configuration once.
They are not recomputed on every daemon start, so a Docker or host capacity
change never silently changes authority. An administrator may later widen or
narrow them within the actual deployment boundary.

If Docker Engine cannot report usable capacity during initialization,
docker-helper fails the initialization step with a clear diagnostic rather
than inventing an unlimited or host-derived fallback.

The reserved memory and CPU remain available to Docker, the host, and unrelated
workloads; docker-helper controls only its own subtree and does not claim to
reserve host capacity against actors outside it.

## Workload defaults and validation

A Managed Container create request and one-shot `run` may omit or explicitly
narrow CPU, memory, PIDs, and shared memory.

For CPU, memory, and PIDs:

- omission selects the Session's current effective ceiling at admission;
- an explicit request must be positive and no greater than that ceiling;
- the accepted effective value is materialized as a concrete workload limit;
- the caller cannot request `unlimited`, a negative sentinel, or a Docker-native
  alternative representation.

CPU is expressed as a fractional count of logical CPUs with 0.1-CPU
granularity. Memory and shared memory normalize to integer bytes and are
rendered to people using IEC units. PIDs is a positive integer and counts both
processes and threads according to cgroup semantics. Exact JSON and CLI input
spelling belongs to the public-surface design and must map to these single
canonical units.

Shared memory is a per-workload setting rather than a separate aggregate
resource pool:

- omission selects the smaller of 256 MiB and the effective workload memory
  limit;
- an explicit value may only narrow that default;
- shared memory never exceeds the workload memory limit;
- pages consumed through shared memory remain charged to the normal memory
  hierarchy.

Swap is disabled for every Managed Container and one-shot `run`. Release 3 has
no request or hierarchy field that can enable or size swap.

The accepted workload limits are immutable for the lifetime of a Managed
Container. A later ancestor reduction may further constrain actual use through
the hierarchy but does not rewrite the container's create specification. A
later ancestor increase does not silently widen a previously materialized
workload limit. A caller that deliberately selected a smaller value continues
to receive that smaller value.

Exec creates no new resource envelope. Interactive and non-interactive exec
processes remain inside their Managed Container's cgroup and consume its limits
and every ancestor ceiling. Their separate concurrency limits are defined in
`release-3-logs-and-exec.md`.

Build remains outside this policy. The release must not imply that a build is
bounded by Session workload ceilings merely because pull, build, and run share
one Docker Engine adapter.

## Enforcement model

Aggregate ceilings are enforced by a real cgroup hierarchy corresponding to
Root, Principal, Launcher, and Session. Managed Containers and one-shot `run`
workloads are placed below the owning Session cgroup and also receive their
concrete Docker workload limits.

The required aggregate controllers are:

- CPU for subtree-wide execution bandwidth;
- memory for subtree-wide resident and charged memory;
- PIDs for subtree-wide processes and threads.

The hierarchy, not a database sum, is the runtime security boundary. SQLite
stores policy and ownership; it does not continuously calculate consumption.
Docker Engine remains responsible for applying the concrete workload limits
and placing the workload under the verified parent.

The daemon performs no admission calculation based on current use. If a
Session ceiling is 4 GiB, two containers may each have a 4 GiB workload limit;
their combined use still cannot exceed the Session's aggregate 4 GiB cgroup
ceiling. Contention or an OOM outcome under that ceiling is observable workload
behavior, not a reason for docker-helper to schedule, retry, or restart it.

The cgroup path uses stable docker-helper identities rather than caller names.
Direct path syntax and driver-specific identifiers never enter the public API.

## Enforcement availability

Release 3 must prove the hierarchy on both supported deployment modes before
resource implementation is frozen:

- system deployment;
- rootless user deployment.

The implementation spike must verify controller delegation, nested aggregate
enforcement, Docker placement, daemon restart, cleanup, and the Docker cgroup
drivers supported by the project. It must demonstrate that sibling workloads
cannot escape Principal, Launcher, Session, or Root aggregate ceilings.

If the required hierarchy or a mandatory workload limit cannot be enforced,
docker-helper fails closed with `resource_enforcement_unavailable`. It must not
silently omit a controller, degrade to per-container-only limits, or start an
unbounded workload. The implementation may reject an unsupported deployment;
it may not weaken the multi-user contract.

System cgroup paths, Docker backend errors, and controller internals are
sanitized from ordinary client errors and remain available only in bounded
operator diagnostics.

## Policy updates

An authorized policy manager may widen or narrow a configured hierarchy
ceiling within its parent. No update divides capacity automatically or mutates
sibling configuration.

CPU and PIDs ceiling changes apply live through the affected hierarchy. A lower
value constrains existing workloads but does not terminate them deliberately.
If the kernel rejects the change, the policy update fails and the previous
effective value remains authoritative.

A memory ceiling may be increased live. A memory decrease is accepted only
when the entire affected subtree has no active workload. `running`, `paused`,
or externally transitioning Managed Containers, active one-shot `run`, and
active exec count as active. Stopped Managed Containers do not. This prevents a
policy edit from producing an immediate surprise OOM in already executing
work.

Because shared-memory size is materialized in the immutable workload create
specification, it is not rewritten by a hierarchy update. The normal memory
ceiling still bounds actual shared-memory consumption.

Policy persistence and cgroup mutation must have one explicit failure contract.
The implementation plan must not report a new effective ceiling before runtime
enforcement is confirmed, and must recover an interrupted update without
temporarily widening authority. Exact transaction and compensation mechanics
belong to the operational architect.

## Full-inheritance warnings

The single-user quick start intentionally gives the first Principal and
Launcher the complete inherited Root envelope. docker-helper does not force an
ordinary user to partition a machine before running one container.

When creation or update leaves a second Principal or a second sibling Launcher
inheriting the same parent's full ceiling, docker-helper emits a clear operator
warning. It does not:

- reject the child;
- divide the parent automatically;
- reserve half or one tenth for each child;
- claim that either child has guaranteed capacity.

The common ancestor still enforces the aggregate cap, so the warning concerns
contention and possible OOM under shared authority rather than an escape from
the security boundary. Production evidence may later justify requiring
explicit subdivision; Release 3 does not introduce that requirement in
advance.

Sessions do not generate this warning merely because several exist under one
Launcher. They intentionally share the Launcher's aggregate authority, and
automatic fractional allocation would make Session creation order change
policy unexpectedly.

## Persistence and inspection

Persistent policy contains:

- explicit or inherited CPU, memory, and PIDs ceilings for Principal, Launcher,
  and Session;
- materialized Root defaults;
- concrete immutable limits accepted for each Managed Container;
- only the correlation required to verify cgroup placement and Docker workload
  policy.

It does not contain sampled usage history, scheduler state, reservations,
pressure metrics, OOM logs, or a copied Docker inspection response.

`principal show`, `launcher show`, and `session show` expose their effective
resource ceilings and whether each value is explicit or inherited.
`container show` exposes both the concrete immutable workload limits applied at
creation and the current effective maximum after ancestor ceilings, plus the
disabled-swap policy. This distinction matters after a parent policy change.
List output does not grow into a resource-monitoring table; detailed limits
belong to show.

docker-helper does not add CPU or memory usage monitoring in Release 3.
Operators who need backend usage and cgroup diagnostics use the host and Docker
tools directly.

## Errors and audit

The stable resource-policy error categories are:

| Code | Meaning |
| --- | --- |
| `invalid_resource_limit` | A value has an invalid unit, precision, range, or relationship to another requested value. |
| `resource_limit_exceeded` | A requested workload or child ceiling exceeds the caller's effective authorization ceiling. |
| `resource_limit_update_blocked` | A memory reduction targets a subtree with active workloads. |
| `resource_enforcement_unavailable` | The required cgroup or Docker enforcement cannot be proved or applied. |

Errors may return the normalized requested and allowed values to a caller
already authorized for that policy node. Authorization and target resolution
occur first so foreign policy is never disclosed.

Policy creation and update, denied limit requests, enforcement failure, and
detected Docker resource-policy mismatch are audited with public resource
identities and normalized non-secret values. Audit does not contain runtime
usage samples, workload output, raw cgroup paths, or a Docker inspection
payload.

## Agent and operator guidance

The ordinary examples require no resource flags. Safe inherited defaults keep
the quick-start workflow small.

The packaged docker-helper `SKILL.md` must advise agents to choose deliberate
smaller limits for long-lived Managed Containers after inspecting the Session's
effective ceiling. This is guidance, not a daemon-side heuristic: docker-helper
does not guess resource needs from an image, command, or expected lifetime.

Operator documentation must explain that:

- full inheritance grants authority but does not reserve capacity;
- external Docker and host workloads remain outside the helper's Root ceiling;
- parent aggregate enforcement can produce workload OOM under contention;
- larger workloads require explicit administrator policy rather than an
  unbounded fallback;
- disk use is not quota-controlled by Release 3.

## Verification requirements

Implementation is not complete without tests for:

- Root default calculations and one-time materialization;
- inheritance and effective-ceiling calculation at every hierarchy level;
- cross-Principal and cross-Launcher policy denial without existence leaks;
- explicit workload narrowing and rejection of every widening path;
- concrete limits on both Managed Containers and one-shot `run`;
- swap disabled and shared memory bounded by workload memory;
- exec processes remaining inside the Managed Container hierarchy;
- aggregate CPU, memory, and PIDs enforcement across sibling containers and
  Sessions;
- live CPU and PIDs updates;
- allowed memory increase and blocked memory decrease with every active
  workload class;
- full-inheritance warning behavior without automatic splitting;
- daemon restart and cleanup of hierarchy state;
- fail-closed behavior when controllers or Docker placement are unavailable;
- policy mismatch observation and administrator `container repair` restoring
  the stored concrete workload limits;
- help, manual, architecture, and packaged `SKILL.md` consistency.

Real-host integration tests are required in both system and rootless modes.
Unit tests and mocked Docker calls cannot prove aggregate cgroup enforcement.
