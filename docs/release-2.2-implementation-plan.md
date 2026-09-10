# Release 2.2 implementation plan

## Status and baseline

This document owns the implementation sequence for Release 2.2 Allowed Root
Access Modes.

Release 2.2 is based on the published Release 2.1.1 product line:

```text
base tag: v2.1.1
base commit: 88e80c0d35773b75a0f79a13448aab6b92c69df3
release branch: release/2.2
```

Do not base Release 2.2 production work on `main`: `main` already contains
Release 3 D0 production changes. Release 2.2 must not accidentally ship any
Release 3 Engine/lifecycle/runtime work.

After 2.2 is released, the normal release-to-main merge reconciles the completed
2.2 policy capability back into the Release 3 development line.

The design owners are:

- [`release-2.2-allowed-root-access-modes.md`](release-2.2-allowed-root-access-modes.md)
  — public policy/domain/API semantics;
- [`release-2.2-mac-enforcement.md`](release-2.2-mac-enforcement.md) — mandatory
  AppArmor/SELinux defense-in-depth contract and feasibility gate;
- this file — implementation order, owners, gates, and evidence.

## Fixed implementation principles

1. There is one allowed-root semantic owner. AppArmor/SELinux consume a resolved
   decision; they never recompute the hierarchy.
2. `read_only` and `read_write` are the only access-mode values.
3. Existing path-only state is `read_write`.
4. Overlap precedence inside one scope is most-specific canonical path.
5. Across scopes, path authority intersects and `read_only` dominates.
6. A writable parent may not cover any effective read-only descendant region.
7. Session filesystem policy is an immutable snapshot taken at Session creation,
   preserving the Release 2.1 rule that later allowed-root changes do not alter
   already-issued Sessions.
8. A caller-requested writable mount is rejected, never silently downgraded.
9. System mode requires AppArmor/SELinux to mirror the final resolved exposure
   independently as defense in depth.
10. No Release 3 Managed Container, Engine migration, resource, networking, or
    durable-Operation work belongs in this branch.

## Phase M0 — mandatory MAC feasibility evidence

**Status: CLOSED (2026-09-09).** M0-A and M0-S have authoritative passing
evidence in the
[`release-2.2-mac-enforcement.md`](release-2.2-mac-enforcement.md) closure
record. Phase 2.2.1 is unblocked; production implementation and system-mode UAT
are not implied complete by this feasibility result.

Before adding access-mode fields to production config/database/API code, close
both feasibility rows in `release-2.2-mac-enforcement.md`.

### M0-A — AppArmor

Build a disposable proof using the supported AppArmor host showing that one
container can simultaneously:

- write through an exposure resolved `read_write`;
- read through an exposure resolved `read_only`;
- fail to write through that read-only exposure because of AppArmor policy even
  when a test harness deliberately presents the underlying bind writable.

The preferred candidate is a helper-generated workload profile selected by the
Docker AppArmor security option. The proof must include safe generated-path
escaping, profile load-before-exec, audit attribution, and removal/reconciliation
of helper-owned generated state.

Do not mutate production allowed-root semantics in M0.

### M0-S — SELinux

Build a disposable enforcing-SELinux proof showing the same mixed-mode behavior
and, additionally, two concurrent Sessions using the same host tree with
different issued access snapshots without global-mode interference.

The proof must retain the intended docker-helper workload confinement and
produce attributable AVC evidence for the forced-writable/read-only negative
case.

A global `*_ro_t` / `*_rw_t` relabel and a whole-container read-only process
domain are not acceptable proofs.

### M0 outcome

Accepted outcome:

- AppArmor: a helper-owned generated per-workload profile selected explicitly
  through Docker;
- SELinux: a helper-owned per-read-only-exposure `bindfs` passthrough
  projection with the static `docker_helper_ro_projection_t` mount context,
  while read-write exposures remain direct binds.

The exact run, artifact, commit, cleanup, concurrency, and denial evidence is
recorded in `release-2.2-mac-enforcement.md`. The SELinux implementation must
also add and prove the confined projection worker and `/dev/fuse` policy delta;
substituting another projection mechanism reopens M0-S.

Record for each backend:

- exact mechanism;
- supported-host evidence;
- why mixed modes work;
- why shared-tree concurrent Sessions do not interfere;
- generated-state lifecycle/cleanup model;
- test command/run identity.

If either backend cannot satisfy the contract, stop Release 2.2 implementation
and return to architecture. Do not weaken the release requirement silently.

## Phase 2.2.1 — canonical policy value and persistence migration

**Status: CLOSED.** Implemented on `feature/2.2.1-policy-persistence` (base
`release/2.2@9e9c88d`), merged to `release/2.2` as `33ba7a1` after
architectural acceptance. Evidence:
canonical `AllowedRootEntry{Path, Access}` value in `allowed_root.go`;
config decode accepts legacy string entries (normalized `read_write`), the
canonical `{"path","access"}` object form, and mixed arrays, with unknown
access, unknown object fields, and conflicting canonical paths failing closed
(`validateAllowedRootEntryValue`, `resolveAllowedRoots`); 2.2 config writes
persist the object form; `principal_allowed_roots` and `launcher_allowed_roots`
carry `access TEXT NOT NULL CHECK (access IN ('read_write','read_only'))` with
the owner/path unique identity preserved, rebuilt per table from the legacy
path-only shape in one atomic, idempotent, fail-closed transaction
(`classifyAllowedRootsTable`, `migrateAllowedRootsTableToAccessSchema`);
migration, config, constraint, and persistence tests in
`allowed_root_migration_test.go` and `config_allowed_root_test.go`. Not yet
done by design at 2.2.1: the rich HTTP/CLI projection (2.2.3), the Session
snapshot (2.2.4), and runtime enforcement; public `allowed_roots` remains the
2.1 path-only projection.

Dependencies: M0-A and M0-S CLOSED.

Introduce one canonical internal allowed-root value, conceptually:

```text
AllowedRootEntry {
    Path
    Access
}
```

Use the project's normal naming conventions; do not create parallel
`RootPolicy`, `PathGrant`, `MountACL`, or backend-specific equivalents for the
same semantic value.

### Global configuration

Extend global allowed roots so input accepts:

- legacy string entries -> normalized to `read_write`;
- canonical `{path, access}` entries.

The in-memory value is canonical rich entries only. One config owner validates
both forms and rejects:

- unknown access values;
- duplicate canonical paths with conflicting values;
- malformed/noncanonical paths using the existing root-validation rules.

A successful 2.2 mutation may persist the canonical object representation.
Configuration reload remains one atomic/fail-closed policy transition.

### Principal persistence

Add an access column to `principal_allowed_roots`:

```text
NOT NULL
CHECK access IN ('read_write','read_only')
default/migration value: read_write
```

Preserve the existing unique path identity for one Principal.

### Launcher persistence

Add the same access column to `launcher_allowed_roots` with the same migration
rule and exact-path uniqueness semantics.

### Migration

Migration from 2.1.1 must be:

- idempotent;
- transactionally safe;
- fail closed on an unexpected schema/value;
- compatible with DBs upgraded directly from supported earlier 2.x state via
  the existing migration sequence.

Do not silently discard duplicate/conflicting policy state.

**Gate:** old path-only config/DB state loads as byte-for-byte equivalent
`read_write` authority at the public behavior level.

## Phase 2.2.2 — one effective policy resolver

**Status: CLOSED.** Implemented on `feature/2.2.2-effective-policy-resolver`
(base `release/2.2@65f0406`), merged to `release/2.2` as
`6b33a1e24ea03de9152867e46a4f5a4be0ec2e5a` after architectural acceptance. Evidence: the pure domain owner
`allowed_root_policy.go` implements most-specific lookup within one scope
(`lookupAllowedRootAccess`), access-mode meet with `read_only` dominance
(`meetAllowedRootAccess`), scope composition with derived path-only
projections preserved as wrappers (`composeAllowedRootScopes`, and
`intersectAllowedRootScopes` / `computeEffectivePrincipalRoots` /
`computeLauncherEffectiveRoots` delegating to it), the Principal ceiling with
the user-mode daemon-owner collapse (`effectivePrincipalAllowedRoots`),
Launcher inherit/restricted semantics with the fail-closed stale-root
revalidation (`effectiveLauncherAllowedRoots`), canonical ancestor-first
ordering, normalization of redundant transitions
(`normalizeAllowedRootEntries`), the pure Session filesystem snapshot
derivation with source lookup and the single writable-parent query
(`sessionFilesystemSnapshot.LookupAccess`, `CanExposeWritable`). The
required pure/equivalence test matrix lives in
`allowed_root_policy_test.go`. Not implemented by design here: the rich
HTTP/CLI projection (2.2.3), snapshot persistence (2.2.4), and runtime
enforcement (2.2.5); public `allowed_roots` responses and Session creation
behavior are unchanged.

Implement the pure/domain policy layer before wiring mutations or Docker.

The resolver owns:

- canonical path entry ordering;
- most-specific match within one scope;
- global -> Principal -> Launcher path composition;
- access-mode meet where `read_only` dominates;
- Launcher inherit/restricted behavior;
- user-mode daemon-owner collapse onto global policy;
- derivation of the Session filesystem snapshot;
- source access lookup inside that snapshot;
- writable-parent detection.

### Snapshot representation

The Session snapshot must retain every mode transition inside the Session
workspace needed to evaluate future operation sources.

The implementation may normalize redundant entries. For example, a child
`read_write` entry identical to its effective parent does not need to be stored
if removing it cannot change any later lookup. But normalization must be one
canonical algorithm with round-trip/equivalence tests.

A Session whose entire workspace is effectively one mode may use one root
entry. Nested exceptions remain explicit.

### Writable-parent query

Provide one domain query equivalent to:

```text
canExposeWritable(source)
```

It succeeds only when:

- `source` itself resolves `read_write`; and
- no effective `read_only` transition exists at or below `source` within the
  snapshot.

Do not duplicate this logic in CLI, run handler, MAC backend, or tests.

### Required pure tests

Cover at minimum:

- disjoint roots;
- nested RW -> RO;
- nested RO -> RW;
- multiple nesting transitions;
- same-path mode update semantics;
- upstream RO + downstream attempted RW;
- restricted Launcher intersection;
- inherit Launcher;
- root-prefix trap (`/data` vs `/data2`);
- deterministic ordering independent of insertion order;
- writable-parent rejection and narrower RW success;
- user-mode collapse;
- corrupted/out-of-ceiling stored Launcher entry fails closed.

## Phase 2.2.3 — control-plane HTTP/CLI and introspection

**Status: CLOSED.** Implemented on `feature/2.2.3-control-plane-access`
(base `release/2.2@6b33a1e`), merged to `release/2.2` as
`f168d0b99cd7de86c180fcad18f2e30218568b9b` after architectural acceptance. Evidence: the canonical
`AllowedRootEntry{Path,Access}` is carried end-to-end from the 2.2.1/2.2.2
owners through every public boundary — presence-aware `--access` add and
targeted `set-access` on all three families (global config, Principal,
Launcher), with the set-access mutation performed once server-side as one
conditional mutation (no CLI read-modify-write; a missing stored root is
refused `404 allowed_root_not_found`, a same-value request is the idempotent
unchanged no-op, and the reserved user-mode daemon-owner Principal is refused
like every other mutation); the rich `allowed_root_entries` projection beside
the preserved 2.1 `allowed_roots` path-only form on Principal show, Launcher
show/list, effective-roots introspection, Session create-policy, and `config
show`, with human allowed-root lists as PATH/ACCESS tables and CLI field
extraction (`allowed_root_entries` on `principal show`) and completion sharing
the same owners; the Launcher complete-scope PUT extended with the strict rich
entry form while the 2.1 path-only form keeps mapping to `read_write` and the
documented legacy `{"scope":"inherit","allowed_roots":[]}` shape stays valid;
audit records for the access-bearing add/set-access mutations carry
`requested_access` and `stored_access` so an idempotent no-op that ignores a
conflicting request is observable; the JSON `--access` vocabulary is offered
by completion only where an access value is legal. No authority changes:
Principal credential and Session bearer retain no allowed-root mutation
authority. Not implemented by design here: snapshot persistence (2.2.4) and
runtime enforcement (2.2.5); README/architecture prose rework is deferred to
the 2.2.7 documentation pass.

Dependencies: 2.2.1 and 2.2.2.

Extend existing allowed-root commands/routes; do not create a second ACL API.

### Per-root mutations

Support optional access on add:

```text
config allowed-root add [--access ACCESS] PATH
principal allowed-root add [--system] [--endpoint ENDPOINT] [--token-file PATH] [--access ACCESS] USER PATH
launcher allowed-root add [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--access ACCESS] [LAUNCHER] PATH
```

The project CLI parser requires flags to precede positional arguments, so the
optional `--access` flag is always written before the positional PATH.

Omission preserves old behavior: `read_write`.

Add explicit exact-entry mode mutation:

```text
... allowed-root set-access ... ACCESS
```

Changing access must be one server-side conditional mutation, not CLI
read-modify-write.

### Complete Launcher scope replacement

Extend the existing atomic complete-scope route to accept mode-bearing entries.
Preserve the old path-only request form as a 2.x compatibility input mapping to
`read_write`. Reject requests that supply both old and rich forms.

### Responses

Preserve the 2.1 path-only `allowed_roots` projection throughout 2.x and add the
canonical `allowed_root_entries` rich projection. Generate both from the same
internal entries.

Update:

- Principal show;
- Launcher show/list where allowed roots are projected;
- effective Principal roots query;
- Session create-policy query;
- config show/list;
- human allowed-root list output.

The rich projection is authoritative for access modes. Human output always
shows access.

### Completion

Add the canonical access values to completion only where an access value is
legal. Preserve the existing ambiguous Launcher-selector/PATH completion
contract.

### Authority

No authority changes:

- global roots: admin-owned;
- Principal roots: existing admin-owned policy boundary;
- Launcher roots: existing admin/owning-Principal boundary;
- Launcher credential and Session bearer cannot widen/edit their parent
  allowed-root policy.

## Phase 2.2.4 — Session filesystem snapshot persistence

**Status: implemented, awaiting architectural acceptance.** Implemented on
`feature/2.2.4-session-filesystem-snapshot` (base `release/2.2@f168d0b`, final
SHA recorded in the phase report). Evidence summary: the canonical
`session_filesystem_snapshot_entries` child table (exact schema classification
with fail-closed near-match refusal) persists the immutable snapshot as
Session child state; the legacy cutover is table-presence-owned (one
transaction creates the table and backfills `position=0, workspace,
read_write` from `sessions.workspace` alone, ignoring all current parent
policy) and post-cutover missing/partial/corrupt state fails startup closed;
`createSessionWithPolicyLocked` derives the snapshot from
`resolveCreatePolicy`'s effective entries inside the existing `lifecycleMu`
linearization point and commits Session + snapshot in one transaction (MAC
callback unchanged), so no issued Session bearer can exist without its
snapshot; parent-policy mutations never touch an issued snapshot (verified
across restart); `GET /sessions/{id}` + `session show` load the issued
snapshot through the single canonical loader with the Session-control
authorization matrix (Session bearer excluded, non-disclosing 404), a
`session.show` audit event, and a lightweight `session list`. Runtime
enforcement (2.2.5) and MAC projection (2.2.6) remain out of scope.

Dependencies: 2.2.2; schema primitives from 2.2.1.

Create one Session-owned derived snapshot representation.

### Session creation transaction

At the Session creation linearization point:

1. resolve one coherent current global/Principal/Launcher policy;
2. validate the requested workspace;
3. derive the normalized filesystem snapshot relative to/cropped by that
   workspace;
4. prepare the existing concrete workspace MAC coverage;
5. persist Session + snapshot atomically under the existing creation/lifecycle
   ownership boundary;
6. return the bearer only after both Session and snapshot are committed.

There must be no committed Session bearer without a complete snapshot.

### Upgrade of existing Sessions

For every pre-2.2 live Session:

```text
snapshot = [{ path: session.workspace, access: read_write }]
```

This deliberately preserves already-issued 2.1 authority rather than applying
current parent policy retroactively.

### Reads and startup

Every data-plane filesystem policy lookup uses the persisted Session snapshot,
not current Principal/Launcher/global roots.

Startup/reconciliation fails closed when a live Session has:

- no required snapshot;
- malformed paths;
- unknown access mode;
- conflicting duplicate entries;
- entries outside its canonical workspace.

Do not reconstruct a corrupt/missing post-migration snapshot from current
parent policy.

### Introspection

Expose a read-only Session filesystem-policy projection to authorized Session
owners/admin as part of the existing Session show/policy surface selected by the
design. It has no mutation endpoint.

## Phase 2.2.5 — data-plane enforcement

Dependencies: 2.2.4.

### Run mounts

After the existing source canonicalization/workspace containment succeeds:

- resolve source mode from the Session snapshot;
- read-only request succeeds for either access mode;
- writable request requires `canExposeWritable(source)`;
- otherwise reject before any container/Operation state with:

```text
read_only_root
```

Never change a caller's requested RW mount to RO silently.

Keep the existing TOCTOU/mount-pin protections. Access-mode lookup must use the
same canonical source identity those protections mediate; a symlink spelling
must not select policy before resolution.

### Build

Build context/Dockerfile reads remain permitted from either access mode because
the helper consumes those host inputs read-only. Build staging must not write
back into a read-only source tree.

Audit any other host filesystem source used by shipped 2.2 data-plane commands
and route it through the same snapshot resolver where applicable. Do not expand
the release to unrelated host-path features.

### Public errors and audit

`read_only_root` is a policy refusal distinct from `invalid_mount` and workspace
escape.

Audit records include canonical policy-relevant path/access facts needed for
operator explanation while continuing to exclude bearer values, environment
values, registry secrets, and workload output.

## Phase 2.2.6 — MAC workload projection

Dependencies: M0 CLOSED and 2.2.5 common exposure plan implemented.

Implement exactly the mechanisms accepted by M0-A and M0-S.

Both backends consume the same resolved mount exposure plan. Backend code may
translate it into different kernel-policy objects, but neither backend owns
allowed-root precedence or writable-parent semantics.

### AppArmor

Implement the accepted workload policy mechanism and its helper-owned lifecycle.
If M0 selected generated profiles, give them one deterministic internal naming
and correlation scheme and one storage/reconciliation owner.

Do not widen the daemon's existing managed workspace boundary from `r` to `rw`
to satisfy workload access modes.

### SELinux

Implement only the accepted M0 mechanism. Preserve existing
`docker_helper_container_t`/MCS and concrete Session workspace coverage unless
M0 explicitly demonstrated a cleaner single-owner replacement.

Do not introduce global per-mode relabel of allowed-root ceilings.

### Fail-closed ordering

No container may start until required MAC workload state is prepared and
validated. If MAC preparation fails, return a stable existing backend/internal
failure contract without creating the workload.

Cleanup/reconciliation follows proven backend ownership. Never delete ambiguous
foreign policy state.

## Phase 2.2.7 — documentation, packaging, UAT, and release integration

### Current-state docs

Before RC:

- update `docs/architecture.md` completely, not incrementally in isolated
  snippets;
- update README;
- update `docker-helper(1)` and config manual;
- update portable agent skill where allowed-root shape is user-visible;
- update changelog/roadmap release status;
- remove stale path-only current-state wording while retaining historical design
  records as historical.

Final release review MUST perform a full read of `docs/architecture.md` for
stale layered information.

### Migration/upgrade UAT

Upgrade exact released 2.1.1 packages/state to a 2.2 candidate and prove:

- config path-only roots become RW;
- Principal/Launcher rows become RW;
- already-issued Sessions receive RW compatibility snapshots;
- credentials/ownership/session IDs remain intact;
- rollback/failure leaves no half-migrated database or config.

### Functional UAT

Use the issue #8 orchestrator-shaped tree:

```text
run-root/
  project/           read_write
  pipeline-inputs/   read_only
  pipeline-outputs/  read_write
```

Prove through public CLI/API:

1. project mounts RW and writes succeed;
2. pipeline-inputs mounts RO and reads succeed;
3. requested RW pipeline-inputs fails before workload creation with
   `read_only_root`;
4. RW run-root parent fails because it covers nested RO inputs;
5. project direct RW remains valid;
6. symlink aliases cannot widen mode;
7. Principal/global RO cannot be widened by Launcher RW;
8. most-specific transitions are deterministic;
9. old path-only policy is RW;
10. existing Session keeps old snapshot after policy mutation while a new
    Session gets the new mode;
11. audit contains mode/path facts and no secret values;
12. no Session/container/mount/MAC/runtime residue remains.

### Backend-specific UAT

Run the independent MAC matrices from `release-2.2-mac-enforcement.md` on:

- Ubuntu AppArmor system mode;
- openSUSE Tumbleweed enforcing SELinux system mode.

Preserve package/tarball coverage according to the existing Release 2 support
matrix. Do not mark a backend green by skip in a required-mode job.

### Exact-artifact gate

Final release acceptance uses the immutable candidate artifact set produced by
the existing release pipeline. Source-only success is not sufficient.

## Required checks for every implementation series

```text
gofmt -l .
go test ./...
go test -race ./...
go vet ./...
git diff --check
```

Plus the applicable packaging/MAC/UAT gates for changed code.

Tests must assert observable ownership/security invariants rather than duplicate
implementation structure.

## Review boundaries

Perform architecture review after each of these milestones rather than waiting
for one giant final diff:

1. M0 backend mechanism evidence;
2. policy value/resolver + migration;
3. public API/CLI + Session snapshot;
4. run/build enforcement + MAC materialization;
5. full release/UAT/documentation review.

At every review search specifically for:

- a second access-mode vocabulary;
- duplicate hierarchy/resolver code;
- MAC code querying parent policy;
- current-policy reads on existing Session operations;
- writable-parent bypass;
- silent RW -> RO downgrade;
- global SELinux mode relabel;
- stale helper-owned AppArmor/SELinux state;
- accidental Release 3 code in the 2.2 branch.

## Release completion criteria

Release 2.2 is complete only when:

- 2.1 path-only state upgrades compatibly to RW;
- the policy hierarchy and most-specific rules have one implementation owner;
- every Session has an immutable filesystem snapshot;
- writable parent bypass is closed;
- every applicable host source is checked against the snapshot;
- AppArmor and SELinux independently mirror RO denial under system-mode UAT;
- exact candidate artifacts pass the full affected acceptance matrix;
- current docs/man/help are internally consistent;
- compare against `v2.1.1` contains no Release 3 production feature.
