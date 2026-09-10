# Release 2.2 allowed-root access modes

## Status and scope

Release 2.2 is a narrow minor release based on Release 2.1.1. It adds one
filesystem-policy capability: an allowed-root entry carries an explicit access
mode in addition to its canonical path.

The release is intentionally limited to this capability and the mandatory
security machinery required to enforce it. It does not add Managed Containers,
new networking, resource limits, durable Operations, remote execution, or any
other Release 3 runtime feature.

Release 2.2 starts from the `v2.1.1` product line, not from the current Release 3
`main` implementation line. Release 3 inherits the completed 2.2 contract after
the release line is merged back into `main`.

The motivating use case is a delegated orchestrator that owns one run tree with
separate data planes:

```text
run-root/
  project/           # read-write agent work product
  pipeline-inputs/   # read-only protected task/plan/stage inputs
  pipeline-outputs/  # read-write declared outputs
```

Path authorization alone cannot express that distinction. A compromised or
misconfigured Launcher must not be able to widen a path that its parent policy
made read-only.

## Non-goals

Release 2.2 does not add:

- arbitrary host mounts or Docker mount passthrough;
- a second filesystem authorization hierarchy;
- per-file ACL management;
- automatic Session revocation when parent policy changes;
- generic secret policy;
- recursive delegation;
- Managed Container lifecycle;
- a new MAC backend or support for running system mode without exactly one
  supported mandatory-access-control backend.

## Canonical vocabulary

An **allowed root** remains one path-policy entry. In Release 2.2 it has two
properties:

```text
path    canonical absolute host path
access  read_write | read_only
```

Canonical access values are exactly:

- `read_write` — read access is allowed and a workload may request a writable
  bind when the complete effective policy permits it;
- `read_only` — reads are allowed, but a workload may not obtain a writable
  host-path exposure through this policy.

There is no boolean spelling (`readonly`, `writable`, `rw`) in the HTTP or
stored policy model. Human CLI shorthands may not create a second semantic
name.

Every pre-2.2 path-only allowed root is equivalent to:

```text
access = read_write
```

That compatibility rule applies to existing config, Principal rows, Launcher
rows, and already-issued Sessions during migration.

## Policy hierarchy

Release 2.2 keeps the existing hierarchy:

```text
global allowed roots
  -> effective Principal allowed roots
    -> effective Launcher allowed roots
      -> Session filesystem snapshot
        -> operation filesystem source
```

The three durable control-plane levels remain policy ceilings. A Session does
not become a new mutable policy owner; it stores an immutable derived snapshot
of the effective filesystem policy that existed when the Session was created.

### Within one policy scope

Overlapping roots are allowed. For a canonical source path, the most-specific
matching root in that scope determines that scope's access mode.

Example:

```text
/opt/work                     read_write
/opt/work/pipeline-inputs     read_only
/opt/work/project             read_write
```

The rule for `/opt/work/pipeline-inputs/task.md` is `read_only`; the rule for
`/opt/work/project/file.go` is `read_write`.

An exact duplicate canonical path in one scope is one policy entry, never two
competing rows. Updating its access mode changes that entry; it does not create
a duplicate.

### Across policy scopes

Path authority and access mode compose independently but atomically:

1. the source must remain inside the allowed path ceiling at every applicable
   level;
2. each level resolves its own most-specific matching entry;
3. access modes are intersected so `read_only` dominates `read_write`;
4. a lower authority can narrow an upstream `read_write` rule to `read_only`
   but can never widen an upstream `read_only` rule.

Conceptually:

```text
read_write ∩ read_write = read_write
read_write ∩ read_only  = read_only
read_only  ∩ read_write = read_only
read_only  ∩ read_only  = read_only
```

Launcher `inherit` remains exactly what it is in 2.1: it adds no Launcher
path/mode rule and inherits the effective Principal ceiling. Launcher
`restricted` contributes its explicit path/mode entries and cannot widen the
Principal result.

The user-mode daemon-owner Principal retains the existing special collapse:
zero stored Principal roots means the Principal ceiling is the global policy.
This does not create a second access-mode rule; the global entry's mode is used.

## Writable-parent rule

Resolving only the mount source itself is insufficient when overlapping roots
exist.

Given:

```text
/run-root                  read_write
/run-root/pipeline-inputs  read_only
```

a writable bind of `/run-root` would expose `pipeline-inputs` writable through
the parent mount and therefore bypass the nested rule.

Release 2.2 therefore uses this fail-closed rule:

> A requested writable bind is allowed only when the source itself is
> effectively `read_write` and the exposed source subtree contains no region
> whose Session-snapshot effective mode is `read_only`.

The daemon never silently converts a requested writable bind to read-only.
When a writable parent spans a protected read-only subtree, the request is
rejected and the caller must mount the intended read-write and read-only
subtrees separately.

A direct writable mount of a more-specific effective `read_write` subtree is
valid even when one of its ancestors is read-only, because the exposed subtree
starts at the narrower read-write boundary.

## Session lifecycle semantics

Release 2.2 preserves the established 2.1 Session lifecycle rule:

> removing or narrowing an allowed root does not invalidate an already-issued
> Session.

Allowed-root paths and modes are evaluated at Session creation and materialized
as an immutable **Session filesystem snapshot** sufficient to evaluate every
operation source inside that Session workspace, including nested mode
transitions.

Consequences:

- policy changes affect newly created Sessions;
- existing Session bearers retain the path/mode grant they were issued with;
- Principal/Launcher disable/delete behavior remains the existing Session
  invalidation mechanism;
- a Session renewal does not silently widen or narrow the snapshot unless a
  later release explicitly changes that contract;
- startup reconciliation must preserve the snapshot exactly rather than
  reconstructing it from current parent policy.

Migration of a pre-2.2 live Session creates the compatibility snapshot:

```text
Session workspace -> read_write
```

This preserves the authority already issued by 2.1.x even if parent roots have
since changed.

The snapshot is derived state, not a fourth mutable allowed-root scope. There is
no Session command for adding, removing, or changing its entries.

## Operation enforcement

Every operation that consumes a host filesystem source follows one canonical
sequence:

1. resolve the source through the existing canonicalization and anti-symlink
   escape machinery;
2. prove the source is inside the Session workspace;
3. resolve its effective access from the immutable Session filesystem snapshot;
4. apply operation-specific access requirements;
5. materialize the resulting trusted mount/build input through the existing
   Docker boundary and active MAC backend.

For `run` mounts:

- requested read-only mount + effective `read_write` -> allowed read-only;
- requested read-only mount + effective `read_only` -> allowed read-only;
- requested read-write mount + effective `read_write` -> allowed only if the
  writable-parent rule also passes;
- requested read-write mount + effective `read_only` -> rejected;
- requested read-write parent covering any effective read-only region ->
  rejected.

The stable public policy-refusal code is:

```text
read_only_root
```

Malformed mount syntax and workspace escape continue to use their existing
error contracts. `read_only_root` means the path is authorized for reading but
the requested writable exposure exceeds its issued policy.

Build contexts and other host inputs that docker-helper consumes read-only are
valid under either access mode. Container-layer writes and image creation do
not write the host source and therefore are outside allowed-root access mode.

## Symlinks and hard-link aliasing

Symlink behavior is unchanged: policy resolution uses the canonical resolved
source, so a symlink alias cannot select a different access mode from the
canonical source it resolves to.

Hard links are a known limitation of a path policy. Two authorized pathnames can
name the same inode. If one pathname lies in a read-write region and another in
a read-only region, writing the inode through the authorized read-write alias
also changes what is observed through the read-only alias. Release 2.2 does not
claim inode-level confidentiality or immutability across hard-link aliases.

This limitation must be documented in the manual and security section; it must
not be hidden by claiming that canonical path resolution handles hard links.

## Public CLI contract

Existing commands remain and existing invocations default to `read_write`:

```text
docker-helper config allowed-root add [--access read_write|read_only] PATH
docker-helper principal allowed-root add [--system] [--endpoint ENDPOINT] [--token-file PATH] [--access read_write|read_only] USER PATH
docker-helper launcher allowed-root add [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--access read_write|read_only] [LAUNCHER] PATH
```

The project CLI parser requires flags to precede positional arguments, so the
optional `--access` flag is always written before the positional PATH; an
option-like token after a positional is rejected with
`flags must precede positional arguments`.

Changing the mode of an existing exact root is explicit:

```text
docker-helper config allowed-root set-access PATH ACCESS
docker-helper principal allowed-root set-access USER PATH ACCESS
docker-helper launcher allowed-root set-access [LAUNCHER] PATH ACCESS
```

`remove`, `list`, and Launcher `inherit` keep their existing meanings. `list`
shows at least `PATH` and `ACCESS`; human output never hides the mode.

Completion treats `read_write` and `read_only` as one canonical vocabulary and
completes them only where an access value is accepted.

## HTTP and JSON compatibility

Per-root mutation requests extend the existing body compatibly:

```json
{
  "path": "/opt/work/pipeline-inputs",
  "access": "read_only"
}
```

Omitted `access` means `read_write`. The field is presence-aware: any
occurrence — including JSON null and the empty string — is an explicitly
supplied value that must be exactly `read_write` or `read_only`, so JSON null
is rejected instead of silently widening the grant to `read_write`.

Complete Launcher restricted-scope replacement accepts rich entries in a new
field while retaining the 2.1 path-only form for compatibility. A request must
not provide both forms in one mutation. Any occurrence of either key — an
empty array, JSON null, or a non-empty array — is the supplied form of that
key: presence and semantic emptiness are distinct, and JSON null keeps the
2.1 value semantics of the supplied legacy form (the nil slice the 2.1 Go
client serializes). The rich field has no null compatibility; a supplied
empty rich form is refused by the scope rules. Rich entries are decoded
strictly: an unknown nested field, a malformed entry type, or trailing JSON
inside the field value is refused.

The 2.1 JSON `allowed_roots: []string` projection remains available throughout
the 2.x line so existing clients do not break. Release 2.2 adds the canonical
rich projection:

```json
"allowed_root_entries": [
  {"path": "/opt/work", "access": "read_write"},
  {"path": "/opt/work/pipeline-inputs", "access": "read_only"}
]
```

For 2.2 responses:

- `allowed_roots` is a compatibility path-only projection of the same entries;
- `allowed_root_entries` is the authoritative mode-bearing representation;
- both projections are generated from one internal policy value; neither is an
  independent owner;
- Release 3 may retire the path-only compatibility projection as a major-version
  cleanup, but Release 2.2 does not.

The global config file accepts the old string-array representation on input and
normalizes every string to `read_write`. The canonical 2.2 representation is an
array of `{path, access}` objects. Config mutation/rewrite may emit only the
canonical object form after a successful 2.2 write.

## Persistence and migration direction

Principal and Launcher allowed-root persistence gains one non-null access
column with a database check for the two canonical values. Existing rows migrate
as `read_write`.

Session persistence gains one derived snapshot representation owned by the
Session lifecycle. It must be transactionally committed with Session creation:
there is no state where a Session bearer exists without its filesystem snapshot.
The implementation may normalize away redundant entries, but the externally
observable policy must be identical to the hierarchy result at the Session
creation linearization point.

Migration must be idempotent and fail closed on unknown access values,
duplicate canonical paths with conflicting state, or snapshot corruption.

## Audit and observability

Allowed-root mutations audit:

- canonical path;
- requested/stored access mode;
- owner scope (global, Principal, Launcher);
- existing ownership provenance;
- success or stable refusal code.

Refusals keep the policy facts the request had already established: once an
access value parsed as the canonical vocabulary, the refusal carries
`requested_access`; the `stored_access` fact appears only when a stored entry
was actually known (never for a refusal that stored or read nothing), and a
value that was never a canonical access mode is never logged as one. Stable
refusal results use the existing family vocabulary (`allowed_root_not_found`,
`user_mode_owner_reserved`, `outside_global_root`, `outside_principal_root`,
`invalid_allowed_root`, ...) instead of a generic error result.

Operation audit continues to record caller-requested mount paths/modes without
credentials, environment values, or workload output. A `read_only_root`
rejection records that result but does not log secret-bearing request data.

Session show/policy introspection must expose enough of the immutable filesystem
snapshot for an owner to understand why a later mount is read-only. It is a
read-only projection of derived Session state, never a policy mutation surface.

## Mandatory access control

Application policy remains the sole semantic owner of allowed-root hierarchy,
most-specific precedence, Session snapshotting, and mount admission.

System-mode Release 2.2 additionally requires the active MAC backend to mirror
the final resolved read-only/read-write exposure as defense in depth. AppArmor
and SELinux do not re-evaluate parent policy and do not invent their own access
modes; they consume the already-resolved Session/mount decision.

The detailed MAC requirements and the mandatory pre-implementation feasibility
gate are owned by [`release-2.2-mac-enforcement.md`](release-2.2-mac-enforcement.md).
Release 2.2 is not complete unless the supported AppArmor and enforcing SELinux
paths both pass their independent write-denial acceptance evidence.

## Acceptance summary

At minimum Release 2.2 must prove:

1. existing path-only policy remains read-write;
2. a read-write project source mounts writable;
3. a read-only input source mounts readable but not writable;
4. an explicit writable request for a read-only source fails before container
   creation with `read_only_root`;
5. a writable parent spanning a nested read-only subtree fails closed;
6. a direct narrower read-write subtree remains writable when policy permits;
7. most-specific precedence is deterministic within a scope;
8. Principal/Launcher rules cannot widen upstream read-only policy;
9. symlink aliases resolve to the canonical source mode;
10. existing Sessions retain their issued snapshot after parent-policy changes;
11. new Sessions observe the changed policy;
12. AppArmor and SELinux independently mirror read-only denial under their
    supported system-mode UAT;
13. no rejected workload/container, Session snapshot, mount pin, generated MAC
    policy, or runtime residue remains;
14. audit exposes paths/modes but no bearer, environment value, or workload
    output.
