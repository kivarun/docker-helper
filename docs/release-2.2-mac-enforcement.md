# Release 2.2 mandatory-access-control enforcement

## Status

This document owns the Release 2.2 MAC requirements for allowed-root access
modes and the mandatory feasibility gate that must close before production
implementation begins.

**M0-A and M0-S are CLOSED as of 2026-09-09.** The accepted mechanisms and
reproducible evidence are recorded below. This closes mechanism feasibility
only; the production implementation and its full system-mode UAT remain release
gates.

**Production status (Phase 2.2.6, 2026-09-10).** The accepted mechanisms are
implemented on `feature/2.2.6-mac-workload-projection` (base
`release/2.2@d4257406e8802964e6a9056d46d6826bf9490618`, the merge of accepted
Phase 2.2.5 / PR #14), awaiting architectural acceptance:

- `workloadMACCoordinator` (workload_mac.go) is the single operation-lifetime
  owner; it never reads allowed-root tables, Session snapshots,
  `LookupAccess`, or `CanExposeWritable`, and only materializes the accepted
  `sessionFilesystemExposure` plan. Session workspace coverage stays with
  `sessionMACCoordinator`.
- Workload RO/RW follows the caller-requested mode (`RequestedReadOnly`), not
  only `exposure.Access`; snapshot read_write + caller read_only still yields
  a protected RO exposure.
- AppArmor backend (workload_apparmor.go): generated profile
  `docker-helper-workload-<op.ID>` rendered from the Moby docker-default
  baseline with `audit deny "<literal>/{,**}" wkl,` per accepted RO target,
  byte-safe literal encoding (`appArmorPathLiteral`), loaded through
  `apparmor_parser --replace` and verified via the kernel profile inventory
  before Docker starts; Docker receives
  `--security-opt label=disable` plus `--security-opt apparmor=<profile>`.
- SELinux backend (workload_selinux.go): one bindfs passthrough projection
  per RO exposure built strictly from the pinned source, mount context
  `system_u:object_r:docker_helper_ro_projection_t:s0`, worker-alive +
  mountpoint + effective-type proofs, regular-file projections through a
  lower-item bind, and no source relabel.
- Durable ownership state lives under
  `<StateDir>/workload-mac/<operation-id>/` (ownership record committed
  before the first kernel resource; generated AppArmor profile source) and
  `<RuntimeDir>/workload-mac/<operation-id>/` (transient projection state);
  state roots are 0700 helper-owned. The ownership record stores no
  backend-derivable kernel identity: the generated AppArmor profile name is
  derived from the operation ID at validation/cleanup time, so the crash
  window "ownership committed, crash before the profile source was
  written" is safely classifiable (empty owned state; cleanup is a no-op
  while the deterministic profile is absent from the kernel inventory, and
  fails closed when a loaded profile has no safe-unload source). Reserved
  correlation label `com.dockerhelper.operation.id` joins the existing
  runtime label schema. A preparation failure whose partial MAC state
  cannot be rolled back is a typed retained outcome: the run path retains
  the dependent source pins and workspace-use lease until startup
  reconciliation. The ownership-record decoder is exact: exactly one JSON
  value with exactly the current-owner fields, and the operation and
  session IDs must be exactly the canonical issued production shapes
  (exact prefix plus exact lowercase hex length), so a record naming
  foreign identity is retained, never normalized.
- One unified run cleanup owner (`run_cleanup.go`) releases container
  (proven absent) → workload MAC → pins → durable workload ownership
  record/state → workspace lease → cidfile from every terminal path; the
  backend prepared cleanup never removes the durable ownership record
  (it stays as the reconciliation retry marker until the dependent cleanup
  is positively proven done, and durable-state removal is ordered transient
  runtime directory first, record directory last). Startup reconciliation
  cleans only positively identified helper-owned state (foreign/ambiguous
  state is retained; a failed mount-inventory proof or an unverified
  unmount is an error and retains the owned state and its dependent pins).
  Projection release follows the frozen dependency order projection
  unmount → owned worker exit proven → lower file bind unmount →
  projection state removal; both projection kinds create the deterministic
  `mount` mountpoint before the FUSE worker starts.
- Static SELinux policy adds `docker_helper_ro_projection_t` and
  `docker_helper_bindfs_exec_t` to the shipped module with read/execute-only
  workload semantics and minimal daemon/FUSE mount mechanics; bindfs is an
  explicit rpm dependency and the backend fails closed when it is missing.

The application-policy contract is owned by
[`release-2.2-allowed-root-access-modes.md`](release-2.2-allowed-root-access-modes.md).
This document does not create a second policy hierarchy. AppArmor and SELinux
consume already-resolved Session/mount policy and provide defense in depth.

## Release 2.1.1 baseline

System mode already requires exactly one supported active MAC backend.

### AppArmor baseline

Release 2.1.1 AppArmor has two distinct facts:

- the daemon is confined by `docker-helper-system`;
- helper-owned dynamic managed workspace boundaries are included in that daemon
  profile so the daemon can traverse/read the concrete Session workspace it is
  authorized to mediate.

Those managed boundaries are daemon-side host-path coverage. They are not a
workload read/write ACL.

The 2.1.1 workload path disables Docker's SELinux label handling under the
AppArmor backend (`label=disable`). Release 2.2 must not pretend that changing
the daemon's managed-boundary `r` rules alone creates independent read-only
workload enforcement.

### SELinux baseline

Release 2.1.1 SELinux:

- confines the daemon as `docker_helper_t`;
- runs system-mode workloads as the MCS-constrained
  `docker_helper_container_t` type;
- keeps `/home` workspaces on supported `user_home_type` labels;
- gives non-home concrete Session workspaces helper-managed
  `docker_helper_workspace_t` coverage;
- grants `docker_helper_container_t` normal development-tree read/write
  semantics over those workspace types.

The current Session workspace is the MAC lifecycle unit. Global, Principal, and
Launcher allowed-root ceilings do not recursively own or relabel MAC state.
Release 2.2 preserves that principle.

## Security objective

For every system-mode workload exposure derived from an allowed-root policy,
Release 2.2 requires three layers:

1. **application policy** computes the authoritative effective access mode;
2. **VFS/Docker mount configuration** materializes the requested exposure as
   read-only or read-write and rejects a requested widening before container
   creation;
3. **the active MAC backend** independently prevents a workload from writing
   through an exposure whose resolved mode is `read_only`.

The MAC layer is defense in depth. It never makes an access-mode decision on
its own and never repairs an application-policy refusal by silently changing a
mount.

User mode has no mandatory MAC backend. In user mode the 2.2 contract is the
application-policy plus VFS enforcement; the system-mode MAC parity requirement
does not invent a new user-mode host-policy dependency.

## Backend-neutral input

The common policy owner hands the MAC layer a prepared workload exposure plan.
For each caller-visible bind it contains only resolved trusted facts needed by
the backend, conceptually:

```text
container target
resolved access = read_write | read_only
```

The backend does not receive Principal/Launcher credentials, does not query
allowed-root tables, and does not recompute most-specific precedence.

Host source correlation may be passed only where a backend mechanism
technically requires it; it is not a second authorization input.

The common layer remains responsible for:

- canonical host source resolution;
- Session-snapshot lookup;
- writable-parent rejection;
- caller-requested read-only/read-write semantics;
- stable public errors;
- audit attribution.

## Required semantics

A valid MAC implementation must support all of the following simultaneously:

- one workload with both read-write and read-only host binds;
- nested/overlapping access-mode policy;
- direct mount of a narrower read-write subtree beneath a read-only ancestor
  when the effective Session snapshot permits it;
- multiple concurrent Sessions that share the same host tree but were issued
  different access snapshots;
- no recursive relabel or profile mutation merely because a broad global,
  Principal, or Launcher allowed root exists;
- no client-selected MAC label/profile name;
- no widening when MAC preparation fails;
- deterministic cleanup of helper-owned generated MAC state.

A mechanism that works only when an entire container is globally read-only or
globally read-write is insufficient: the motivating orchestrator workload
needs mixed read-write project/output mounts and read-only protected inputs.

## Rejected shortcuts

The following are explicitly not acceptable Release 2.2 designs.

### Reusing AppArmor daemon managed boundaries as workload policy

The existing `managed-boundaries` fragment protects daemon host-path access.
Changing those rules to `rw` for a read-write allowed root would widen the
confined daemon and still would not independently constrain the workload at its
container-visible target path.

The daemon boundary and workload exposure are different responsibilities and
must remain separate.

### Global SELinux `*_ro_t` / `*_rw_t` relabel by allowed-root mode

A filesystem inode has one effective SELinux label in the normal labeled-filesystem
model. The same canonical host tree may legitimately be issued read-only to one
Launcher/Session and read-write to another. A global relabel based on one
control-plane scope would therefore make one subject's delegated policy change
another subject's behavior.

Release 2.2 must not recursively relabel broad allowed-root ceilings into global
read-only/read-write types.

### One SELinux process domain for read-only containers

A container may need both read-only and read-write host paths. Choosing a single
`docker_helper_container_ro_t` versus `docker_helper_container_rw_t` process
type cannot express mixed mount policy and is not sufficient.

### Treating a read-only bind as MAC proof

A kernel/VFS read-only bind is required, but a write failure caused only by the
mount flag does not prove that AppArmor or SELinux independently mirrors the
policy. Release acceptance needs separate MAC evidence.

## Phase M0 — mandatory feasibility gate

No production 2.2 access-mode implementation begins until both backend proofs
below are recorded against supported hosts.

The gate is mechanism evidence, not a commitment to a particular internal
abstraction. If a candidate fails one of the required semantics, discard it
rather than compensating with a second application-policy owner.

### M0-A — AppArmor workload-mode proof

The preferred candidate is a helper-owned workload AppArmor profile selected
explicitly for the container through Docker's AppArmor security option.

The proof must demonstrate a bounded generated profile that:

- preserves the workload compatibility currently provided under the 2.1.1
  AppArmor path;
- contains rules derived only from the final container target/access plan;
- permits normal writes through a read-write target;
- denies writes through a read-only target;
- supports both kinds of target in one container;
- handles target path escaping/globbing safely;
- is loaded before the container can execute;
- has helper-owned lifecycle state and deterministic removal after the
  correlated container is gone;
- leaves no stale profile that can be selected by an untrusted caller;
- does not widen the `docker-helper-system` daemon profile.

A different AppArmor mechanism is acceptable if it proves the same properties
with less state. The profile name and generated file path remain internal.

### M0-S — SELinux workload-mode proof

The SELinux proof must establish a mechanism that independently denies writes
for one read-only exposure while simultaneously permitting a read-write
exposure in the same container.

It must also prove two concurrent Sessions can use the same underlying host tree
with different issued access snapshots without globally relabeling that tree to
one Session's mode.

Candidate mechanisms may use SELinux/container runtime features, mount-specific
security state, or a helper-owned projection only if the resulting semantics
are independently demonstrated on the supported enforcing host. No candidate
is accepted merely because it is theoretically plausible.

The proof must preserve the existing properties of
`docker_helper_container_t`/MCS confinement and the Session workspace MAC
lifecycle, or explicitly replace one existing owner without leaving parallel
state.

If no supported mechanism can satisfy mixed modes plus shared-tree concurrency,
M0-S remains OPEN and Release 2.2 implementation stops for architecture
revision. The fallback is not to weaken SELinux parity silently.

## M0 closure record — 2026-09-09

| Gate | Result | Accepted mechanism | Authoritative evidence |
|---|---|---|---|
| M0-A | **CLOSED** | Helper-owned generated AppArmor workload profile, selected through Docker's AppArmor security option | [run 34377797007](https://github.com/kivarun/docker-helper/actions/runs/34377797007), artifact `release-2.2-m0-apparmor-34377797007-1`, digest `sha256:ada6cd55186393d42c45a99072f63c9ad133c765b3300cab22a91ba4ec127dd3`, tested commit `26b0e9f50338c43d16bf23397f46943cab1aa91b` |
| M0-S | **CLOSED** | Helper-owned writable `bindfs` passthrough projection with an SELinux mount context for each read-only exposure | [run 34383031755](https://github.com/kivarun/docker-helper/actions/runs/34383031755), artifact `release-2.2-m0-selinux-34383031755-1`, digest `sha256:797b22725fd51c9c8d69828c3b03d492209863a0a26488d9556ec203f5d697c1`, tested commit `fc43e012245240d34914757a6e0a4edca777fbf4` |

Both runs include a passing static-check job and a passing live workload-mode
proof job. They are reproducible through
`.github/workflows/release-2.2-m0-apparmor.yml` and
`.github/workflows/release-2.2-m0-selinux.yml` respectively.

### Accepted M0-A mechanism

The AppArmor backend generates one bounded, helper-owned workload profile from
the final container-target/access plan and selects that profile explicitly at
container creation. The proof established:

- simultaneous read-write and read-only targets in one container;
- successful writes through the read-write target;
- AppArmor-attributable `DENIED` records for append, create, and unlink through
  a deliberately VFS-writable read-only target;
- literal-safe target-path encoding, load-before-exec, create-failure cleanup,
  and ownership-bounded startup reconciliation;
- no generated-profile or container residue and no change to the shipped
  `docker-helper-system` daemon profile.

Production must preserve the same split: the common layer resolves policy,
while the AppArmor backend only renders and owns the workload profile. The
backend-only forced-writable path remains proof infrastructure and must not
become a public or production bypass.

### Accepted M0-S mechanism

For each resolved read-only exposure, the SELinux backend creates a writable
`bindfs` passthrough projection from the helper's existing pinned source and
mounts that projection with
`system_u:object_r:docker_helper_ro_projection_t:s0`. The container receives
the projection at the requested target; production also keeps the Docker/VFS
mount read-only. A resolved read-write exposure remains a direct bind of the
pinned source.

The projection has its own FUSE superblock and mount context. Consequently the
workload may retain `docker_helper_container_t` and Docker-assigned MCS
categories while SELinux denies mutation of the projection type. The backing
objects retain their existing `docker_helper_workspace_t` labels. Concurrent
Sessions therefore use independent projections/access plans over live shared
backing objects without a global per-mode relabel. A regular-file source is
handled by projecting a private staging directory and binding the selected file
from that projection.

The enforcing openSUSE Tumbleweed proof established:

- one container with simultaneous read-write and read-only exposures;
- concurrent read-write and read-only Sessions over the same live tree;
- regular-file read-only exposure;
- distinct container MCS categories with matching process/rootfs labels;
- exact source label and device/inode preservation;
- attributable AVC denials from `docker_helper_container_t` to
  `docker_helper_ro_projection_t` while the projection remained VFS-writable;
- create-failure cleanup, ownership-bounded startup reconciliation, and no
  policy-module, mount, or container residue.

OverlayFS is not the accepted mechanism: changing an underlying lower tree
while an overlay is mounted has undefined behavior and cannot satisfy the live
shared-tree requirement. See the kernel's
[OverlayFS documentation](https://docs.kernel.org/filesystems/overlayfs.html).

M0-S acceptance adds the following mandatory production constraints:

- `bindfs` is an explicit SELinux system-mode runtime dependency;
- the shipped policy owns the static `docker_helper_ro_projection_t` type and
  grants no workload mutation permissions to it;
- the confined helper's projection worker, `/dev/fuse` access, mount operation,
  and library/executable permissions must be narrowly added and proven under
  the normal production SELinux UAT; M0 did not grant them to the shipped
  daemon policy;
- projection state is correlated with the container and remains internal;
- cleanup order is container absent, projection unmounted, `bindfs` worker
  released, then source mount pin released;
- startup reconciliation touches only positively identified helper-owned
  projection state;
- any failure to create, label, validate, or later clean the projection fails
  closed. An implementation that replaces this mechanism must reopen M0-S and
  supply equivalent evidence before it can be accepted.

## Independent MAC proof method

Public UAT proves the combined application + VFS + MAC behavior. A second,
bounded backend test must prove the MAC layer itself.

For that backend-only proof, the test harness may deliberately bypass the
application admission check and expose a temporary test source as writable
while applying the generated/selected MAC state for a `read_only` exposure.
The workload write must still fail because of the active LSM.

This bypass exists only in test infrastructure against disposable UAT data. It
is never a public docker-helper flag or production endpoint.

Evidence must distinguish the denial source:

- AppArmor: matching AppArmor denial/audit evidence for the generated workload
  profile;
- SELinux: matching AVC evidence for the docker-helper workload domain/security
  state.

A generic `Permission denied` with no backend attribution is not sufficient for
M0 closure.

## Workload MAC lifecycle

Release 2.2 extends the existing MAC architecture rather than making
allowed-root rows own host policy.

Conceptually there are still two different lifetimes:

1. **Session workspace coverage** — the existing 2.1.1 AppArmor/SELinux state
   required for the daemon and workload to access the concrete Session
   workspace safely;
2. **workload exposure policy** — operation/container-lifetime MAC state needed
   to mirror the already-resolved target read/write plan.

The second lifetime may be implemented without durable state if the chosen
backend proves that safe. If helper-owned generated state is required, it must
have explicit correlation and startup cleanup/reconciliation rules.

Preparation order is fail closed:

```text
resolve Session snapshot + mounts
  -> application policy accepts
    -> prepare/validate active MAC workload policy
      -> create/start container
```

Failure before container creation leaves no workload.

Cleanup order is ownership driven:

```text
container proven absent
  -> release operation/container-specific MAC state
```

A cleanup failure is retained as helper-owned retry/reconciliation state; it is
not forgotten merely to make the next request succeed.

## Interaction with existing special projections

Server-owned projections keep their existing independent semantics:

- trusted CA injection remains read-only;
- `helper_socket` remains a server-owned read-only runtime-directory projection
  whose reachability does not grant authority;
- caller mount overlap checks remain fail closed.

The workload MAC mechanism must coexist with those projections without exposing
helper runtime contents or requiring the caller to name a MAC profile/label.

## AppArmor acceptance matrix

After M0 closes and implementation lands, required AppArmor system-mode UAT
includes:

1. RW source is writable;
2. RO source is readable;
3. RO source write is denied;
4. mixed RW + RO mounts in one container behave independently;
5. writable parent spanning nested RO is rejected before MAC/container create;
6. backend-only forced-RW RO exposure is denied by AppArmor itself;
7. generated profile/state is removed after success, failure, cancellation, and
   daemon restart/reconciliation as applicable;
8. no widening of daemon managed-boundary rules;
9. no AppArmor denial outside the expected negative subcases.

## SELinux acceptance matrix

Required enforcing-SELinux UAT includes the same functional cases plus:

1. workload remains in the intended docker-helper container confinement;
2. mixed RW + RO exposures work in one container;
3. two concurrent Sessions may share the same host tree with different issued
   modes without global-mode interference;
4. backend-only forced-RW RO exposure produces a matching SELinux denial;
5. existing workspace fcontext/MCS lifecycle remains correct;
6. no broad relabel of global/Principal/Launcher allowed roots occurs;
7. no unexpected AVC remains after the bounded test window.

## Release gate

Release 2.2 cannot be tagged stable while either backend lacks independent MAC
write-denial evidence.

The final release report records:

- the selected AppArmor mechanism and evidence;
- the selected SELinux mechanism and evidence;
- why the mechanism supports mixed modes and shared-tree concurrency;
- exact packaged UAT run IDs for both backends;
- residue/reconciliation checks;
- confirmation that application policy remains the only allowed-root semantic
  owner.
