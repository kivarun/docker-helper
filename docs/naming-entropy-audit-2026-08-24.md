# Naming entropy audit — MAC/workspace-path reference area

Date: 2026-08-24

Reference model: `AGENTS.md` § MAC naming grammar.

**Scope:** This audit covers the MAC lifecycle, AppArmor/SELinux native
mechanics, MAC boundaries, canonical path containment, init/reload lifecycle,
and shared workspace-path policy. It is the completed reference area used by
the subsequent
[project-wide naming/architecture review](project-wide-naming-architecture-review-2026-08-24.md).

**This is not a project-wide naming audit.** It makes no claim that naming
across the whole repository is clean. Project-wide findings are recorded in
the separate review linked above.

The identified refactor batches in this reference scope have been applied.
Control review found two actionable naming findings; both were corrected, and
the original reference-area audit/refactor was accepted. A later
project-wide independent follow-up review found one additional
backend-identity residue: `workspaceMACDriver.backendType() string` duplicated
the backend identity despite the already-existing `LSMBackend` domain type. It
was corrected in `9dc5eb5708652c2c52faa8cb98d12117c078d7ce`; backend identity
now uses `LSMBackend` consistently. After that follow-up correction, no
currently known actionable naming issue remains in the reference scope. (The
same follow-up also found the separate user-mode startup composition bug fixed
in `374785a035e96dd3976a9f8e84ca209835328ac9`, but that was a functional
lifecycle defect rather than a naming finding.)

Rule: one domain concept -> one canonical term. Different concepts must not
share one word. Different implementations must not invent synonyms for the
same concept.

## Reference principles

This refactor demonstrates the following principles:

- **One concept -> one canonical term.** Different lifecycle/backend
  implementations must not introduce synonyms for one concept.

- **Lifecycle owner vs native mechanics.** `sessionMACCoordinator` owns
  lifecycle; `appArmorProfileManager` and `selinuxFcontextManager` are
  native mechanics types with no lifecycle decisions.

- **Driver vs backend identity.** `driver` is a `workspaceMACDriver`
  implementation. `backend` is the selected/persisted AppArmor|SELinux
  identity.

- **Domain concept separation.**
  - `allowed root` = authorization ceiling
  - `workspace` = concrete session capability
  - `workspace path` = a host path subject to the shared workspace-path
    admissibility policy
  - `MAC boundary` = AppArmor/SELinux coverage boundary used by MAC mechanics
  - `generic path` = filesystem path where no workspace-policy semantics apply

  An allowed root and a MAC boundary may both be subject to the same
  workspace-path admissibility policy, but they are NOT the same domain concept.

- **Canonicalization separate from containment.** `pathWithin` and
  `pathStrictlyWithin` operate on canonical paths. Callers resolve
  symlinks before calling.

- **Shared implementation does not imply generic semantics.** Helpers
  shared by authorization and MAC boundary code are named after the semantic
  policy they implement:
  - `canonicalizeWorkspacePathForAdd`
  - `validateWorkspacePathPolicy`
  - `validateWorkspacePathSafety`

  Truly generic canonical containment remains separately named:
  - `pathWithin`
  - `pathStrictlyWithin`
  - `path_containment.go`

- **Domain-specific wrappers retain domain vocabulary.**
  - `validateAllowedRootValue` (authorization)
  - `validateBoundaryPathForAdd`, `validateBoundaryPathForRemove`,
    `validateBoundaryLexical` (AppArmor MAC boundary)

- **Test names describe the invariant/role they actually exercise.**
  `TestValidateWorkspacePathSafety`, `TestCanonicalizeWorkspacePathForAdd`,
  not `TestIsForbiddenWorkspaceRoot`.

- **Historical architecture names must not survive after ownership changes.**
  `selinux_workspace.go` -> `selinux_fcontext.go` when the file's
  responsibility is fcontext mechanics, not workspace management.

- **Test seams, test filenames/names and comments must follow current
  ownership; historical architecture should not survive only in tests.**

- **Public CLI vocabulary has higher migration cost and is not renamed
  merely for internal aesthetic consistency.** `docker-helper apparmor root`
  remains the public CLI noun for AppArmor managed MAC boundaries.

## Resolved findings

### Stale MAC lifecycle help/man wording

**Fixed:** `init --help`, `config allowed-root --help`, man pages, and comments
now state the correct lifecycle: `init` configures the bootstrap allowed root;
`config allowed-root add` changes the authorization ceiling; MAC preparation
occurs at session creation in system mode.

### Duplicate/reversed CA containment helper

**Fixed:** Removed `isPathContainedUnder(path, root)` which reversed the
canonical root-first argument order and combined canonicalization with
containment. `validateSystemCASourcePathUnder` now does separate
canonicalization then `pathStrictlyWithin(canonicalRoot, canonicalCAPath)`.
Deleted test-only duplicate `validateSystemCASourcePathWithRoot`.

### MAC driver/backend vocabulary

**Fixed:** Test variables holding `workspaceMACDriver` implementations are now
named `driver`, not `backend`. `backend` is reserved for the persisted
AppArmor/SELinux LSM identity (DB column, `backendType()`).

### SELinux file naming

**Renamed:**
- `selinux_workspace.go` -> `selinux_fcontext.go`
- `selinux_workspace_test.go` -> `selinux_fcontext_test.go`

### isHomeRoot -> isUnderHome

**Renamed:** `isHomeRoot` -> `isUnderHome`. The function receives a workspace
path, not an authorization root.

### AppArmor internal identifier casing

**Renamed:** `apparmorCommand` -> `appArmorCommand`, `apparmorRootCommand` ->
`appArmorRootCommand`, and analogous internal identifiers. Public CLI command
names unchanged.

### Historical Issue N test comments

**Fixed:** Replaced "Issue 1", "Issue 3", etc. audit-era comments in
`mac_lifecycle_test.go` with invariant-oriented descriptions.

### False system-init backend dispatch

**Fixed:** Removed the switch between `LSMAppArmor` and `LSMSELinux` in
`runInit` that called `initSystem` with identical arguments. Backend is now
validated once, then `initSystem` is called once.

### appArmorProfileManager.preflight -> checkPrerequisites

**Renamed:** `appArmorProfileManager.preflight()` ->
`appArmorProfileManager.checkPrerequisites()`. The method checks manager
prerequisites (parser existence, executability, profile existence), not a
generic preflight.

### workspace_root.* -> workspace_path_policy.* (two-step rename)

The first rename (`workspace_root.*` -> `path_safety.*`) was itself too broad.
The code implements workspace-path admissibility policy, including forbidden
system trees, broad namespace restrictions and EUID-dependent exceptions; it
is not a generic filesystem-safety library.

**Final files:**
- `workspace_path_policy.go`
- `workspace_path_policy_test.go`
- `workspace_path_policy_invariant_test.go`

**Final helpers:**
- `canonicalizeWorkspacePathForAdd`
- `validateWorkspacePathPolicy`
- `validateWorkspacePathSafety`

### AppArmor internal root -> boundary vocabulary

Internal AppArmor mechanics previously used authorization-style "root"
vocabulary for MAC boundaries. Renamed to use "boundary" internally.

**Internal vocabulary:**
- `boundaryResult`
- `fragmentSnapshot.boundaries`
- `validateBoundaryLexical`
- `validateBoundaryPathForAdd`
- `validateBoundaryPathForRemove`
- `addManagedBoundary`
- `removeManagedBoundary`
- `listManagedBoundaries`
- `appArmorWorkspaceMACDriver` uses boundary vocabulary

**Explicit compatibility exception** (intentionally retain "root"):
- `docker-helper apparmor root` (public CLI)
- `appArmorRootCommand` / `runAppArmorRoot*` (CLI adapter)
- `managed-roots` (persisted artifact naming)
- `# root-json:` (persisted syntax)

Internal implementation vocabulary is boundary; compatibility adapters retain
root.

### Obsolete architecture residue cleanup

**Deleted:** dead `appArmorManagedRoots` test seam.

**Renamed:** `TestServeSystemModeAppArmorManagedRootsMissing` to
`TestServeSystemModeDoesNotVerifyGlobalRootsAgainstAppArmor` to describe the
current invariant (global allowed roots are authorization-only; serve startup
does not require AppArmor coverage for them).

**Moved:** generic `initSystem` tests out of `selinux_fcontext_test.go` to
`init_test.go`:
- `TestInitSELinuxNoMACPreparation` -> `TestInitSystemNoMACPreparation`
- `TestInitSELinuxCoreFailurePropagates` (duplicate, removed)
- `TestInitSELinuxNilManager` -> `TestInitSystemPassesAllowedRootToCore`

**Moved:** `TestServeDetectLSMError` from `selinux_fcontext_test.go` to
`lsm_test.go`.

**Removed:** unused `reloadDeps.deploymentMode`.

**Fixed:** reload lifecycle comment (reload does not verify MAC coverage for
global roots; MAC state follows session workspace lifecycle).

**Fixed:** `initCore` comment generalized from "no AppArmor operations" to
"file-based initialization only; does not prepare MAC state".

## Canonical vocabulary

### MAC lifecycle

- `sessionMACCoordinator` — lifecycle owner
- `workspaceMACDriver` — interface/adapter for workspace MAC mechanics;
  no lifecycle ownership
- `workspaceMACCoverage` — effective coverage for a concrete workspace
- `HelperOwned` — docker-helper durable ownership of a boundary
- `appArmorProfileManager` — native AppArmor profile/managed-fragment mechanics
- `selinuxFcontextManager` — native SELinux fcontext mechanics
- `MAC boundary` / `boundary` — AppArmor/SELinux coverage boundary
- `backend` — selected/persisted AppArmor|SELinux identity
- `driver` — `workspaceMACDriver` implementation

### Authorization and paths

- `allowed_root` / `AllowedRoots` — authorization ceiling
- `workspace` — concrete session capability path
- `workspace path` — host path governed by workspace-path admissibility policy
- `MAC boundary` — MAC coverage boundary; not an authorization root
- `workspace_path_policy.go` — shared workspace-path admissibility policy
- `path_containment.go` — generic canonical-path containment primitives
- `path` — generic filesystem path only when no more specific domain term applies

### Accepted public CLI vocabulary

- `docker-helper apparmor root` — public CLI for AppArmor managed MAC
  boundaries. The noun "root" is an established operator-facing contract.
  Not treated as an actionable naming defect.
- `docker-helper config allowed-root` — public CLI for authorization ceiling

### Accepted test vocabulary

- `*Preflight*` in CA/serve/init test names — temporal ordering description
  (validation-before-side-effects), accepted

### Out of scope

API DTO file organization (moving shared types to `api_contract.go`) is
code/file layout, not naming cleanup. No recommended batch.

## Control review

Independent control review completed against the current implementation.

### Control review findings

**workspace_path_policy.go internal comments use "workspace root" instead of "workspace path"**

The policy collections `forbiddenSystemTrees`, `forbiddenWideNamespaces`,
and `adminWideNamespaceOverrides` define the shared workspace-path
admissibility policy. Their inputs may be authorization allowed roots,
concrete workspace-capable paths, or MAC boundaries.

Their internal documentation comments currently say:

- `forbiddenSystemTrees`: "must never be workspace roots or ancestors of
  workspace roots"
- `forbiddenWideNamespaces`: "too broad to be workspace roots themselves"
- `adminWideNamespaceOverrides`: "root (uid 0) may use as workspace roots"

These should use "workspace path" / "workspace-path policy" vocabulary,
not "workspace root", because the policy is shared across multiple domain
concepts.

User-facing error strings that say "workspace root" are correctly preserved
as compatibility vocabulary. Only the internal documentation comments are
affected.

**Status:** corrected; verified in final re-review.

**SELinux fcontext internal "root" vocabulary conflates different path roles**

The `workspaceMACDriver`-facing interface already expresses the intended
roles:

    verifyActualType(workspace string)
    restoreconRecursive(workspace string)
    ensureWorkspaceFcontext(workspace string)
    removeWorkspaceFcontext(boundary string)

But `selinuxFcontextManager` implementation still uses "root" broadly:

- `ensureWorkspaceFcontext(root string)` — receives the concrete workspace
  that may become a new fcontext boundary
- `removeWorkspaceFcontext(root string)` — receives an existing MAC boundary
- `checkOverlap(root, ...)` — reasons about the candidate fcontext boundary
- `checkEquivalenceOverlap(root, ...)` — reasons about overlap with that
  candidate boundary
- `verifyActualType(root string)` — verifies a concrete workspace/path, not
  an authorization root
- `fcontextPattern(root string)` — builds the recursive pattern for an
  fcontext boundary
- `TestFcontextPattern` uses a table field named `root` for the same concept

Comments using phrases such as "canonical root", "inside ROOT",
"ancestor of ROOT", "selected ROOT" carry the same conflation.

The issue is NOT that every occurrence must mechanically become "boundary".
The required semantic split for the eventual implementation is:

- `workspace` when the value is a concrete workspace
- `boundary` when the value is a MAC/fcontext coverage boundary
- `path` when the helper genuinely operates on an arbitrary filesystem path
- `root` only when it genuinely means a generic containment/tree root or
  Unix root user / filesystem root

The implementation batch should be designed from actual call semantics,
not a mechanical rename.

**Status:** corrected; verified in final re-review.

### Control review result

**Result: PASSED**

Final re-review found no remaining actionable naming issue within the
defined reference scope.

### Verified invariants (no issues found)

- `backend` is consistently the selected/persisted AppArmor|SELinux identity.
- `driver` is consistently the `workspaceMACDriver` implementation.
- `boundary` is consistently the MAC coverage boundary in AppArmor internals.
- `allowed root` is consistently the authorization ceiling.
- `root` in `pathWithin(root, path)` is the containment root, not an
  authorization root.
- Public/persisted `root` vocabulary is correctly isolated to compatibility
  adapters and never leaks into internal implementation vocabulary.
- Test names, seams, comments and filenames reflect current architecture.
- No dead test seams or unused dependencies remain.
- No duplicate helpers with reversed or inconsistent argument semantics.
- Shared implementation helpers are named after their semantic policy, not
  generically.
- Truly generic primitives (`pathWithin`, `pathStrictlyWithin`) remain
  separate and correctly named.

The reference area is accepted as the reference model used by the separate
project-wide naming/architecture review.

This is NOT a project-wide cleanliness claim. Project-wide findings and
refactor boundaries are maintained in that separate review.
