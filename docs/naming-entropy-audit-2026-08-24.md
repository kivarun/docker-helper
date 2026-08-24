# Naming entropy audit — MAC/path-safety reference area

Date: 2026-08-24

Reference model: `AGENTS.md` § MAC naming grammar.

**Scope:** This audit covers the MAC lifecycle, AppArmor/SELinux, containment,
init dispatch, and shared path-safety vocabulary. It is a completed
reference-area audit/refactoring.

**This is not a project-wide naming audit.** It makes no claim that naming
across the whole repository is clean. The next phase is a fresh project-wide
audit using this area as the quality/reference model.

Within the reference scope covered by this audit, no actionable naming debt
remains. This is not a project-wide cleanliness claim.

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

- **Authorization root vs concrete workspace vs generic path.**
  `allowed_root` is the authorization ceiling. `workspace` is a concrete
  session capability path. `path` is a generic filesystem path.

- **Canonicalization separate from containment.** `pathWithin` and
  `pathStrictlyWithin` operate on canonical paths. Callers resolve
  symlinks before calling.

- **Generic helpers use generic names.** `canonicalizePathForAdd`,
  `validatePathPolicy`, `validatePathSafety` are shared across
  authorization and MAC boundary concerns.

- **Domain-specific wrappers retain domain vocabulary.**
  `validateAllowedRootValue`, `validateRootPathForAdd`,
  `validateRootLexical` keep their domain-specific names.

- **Test names describe the invariant/role they actually exercise.**
  `TestValidatePathSafety`, `TestCanonicalizePathForAdd`, not
  `TestIsForbiddenWorkspaceRoot`.

- **Historical architecture names must not survive after ownership changes.**
  `selinux_workspace.go` -> `selinux_fcontext.go` when the file's
  responsibility is fcontext mechanics, not workspace management.

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

### workspace_root.* -> path_safety.*

**Renamed:**
- `workspace_root.go` -> `path_safety.go`
- `workspace_root_test.go` -> `path_safety_test.go`
- `workspace_root_invariant_test.go` -> `path_safety_invariant_test.go`

### Generic path safety helpers

**Renamed:**
- `canonicalizeWorkspaceRootForAdd` -> `canonicalizePathForAdd`
- `validateWorkspaceRootPolicy` -> `validatePathPolicy`
- `isForbiddenWorkspaceRoot` -> `validatePathSafety`

Public error messages preserved (still say "workspace root").

### appArmorProfileManager.preflight -> checkPrerequisites

**Renamed:** `appArmorProfileManager.preflight()` ->
`appArmorProfileManager.checkPrerequisites()`. The method checks manager
prerequisites (parser existence, executability, profile existence), not a
generic preflight.

## Canonical vocabulary

### MAC lifecycle

- `sessionMACCoordinator` — lifecycle owner
- `workspaceMACDriver` — interface/adapter for workspace MAC mechanics;
  no lifecycle ownership
- `workspaceMACCoverage` — effective coverage for a concrete workspace
- `HelperOwned` — docker-helper durable ownership of a boundary
- `appArmorProfileManager` — native AppArmor profile/managed-fragment mechanics
- `selinuxFcontextManager` — native SELinux fcontext mechanics
- `backend` — selected/persisted AppArmor|SELinux identity
- `driver` — `workspaceMACDriver` implementation

### Authorization and paths

- `allowed_root` / `AllowedRoots` — authorization ceiling
- `workspace` — concrete session capability path
- `path` — generic filesystem path
- `path_safety.go` — generic host path safety/canonicalization

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
