# Naming entropy audit

Date: 2026-08-24

Reference model: `AGENTS.md` § MAC naming grammar.

Rule: one domain concept -> one canonical term. Different concepts must not
share one word. Different implementations must not invent synonyms for the
same concept.

## P1 — terminology obscures architecture/security semantics

### 1. `Root` used for three different concepts

**Current names:** `allowed_root`, `AllowedRoots`, `workspace_root`,
`workspaceRoot`, `workspace_root.go`, `workspaceRootForAdd`, `workspaceRootPolicy`,
`workspaceRootInvariants`, `workspaceRootDir`, `testAllowedRootDir`,
`testWorkspaceDir`, `principal_allowed_roots`, `addPrincipalAllowedRoot`,
`removePrincipalAllowedRoot`

**Actual domain concepts:**
- global allowed root = authorization ceiling
- principal allowed root = authorization narrowing
- workspace = concrete session capability path

**Why ambiguous:** The word "root" conflates authorization ceilings with
concrete workspace paths. `workspace_root` in `workspace_root.go` refers to
the authorization ceiling, not the session workspace. The filename
`workspace_root.go` suggests it owns workspace semantics, but it only owns
authorization-root policy validation. The function
`canonicalizeWorkspaceRootForAdd` operates on an authorization root, not a
workspace. `testAllowedRootDir` and `testWorkspaceDir` create different
things but both use "workspace" in the name.

**Proposed canonical terms:**
- `allowed_root` / `AllowedRoot` — keep for authorization ceiling (config
  field, DB column, CLI subcommand)
- `workspace_root.go` -> `allowed_root_policy.go` — the file owns
  authorization-root policy, not workspace semantics
- `canonicalizeWorkspaceRootForAdd` -> `canonicalizeAllowedRootForAdd`
- `validateWorkspaceRootPolicy` -> `validateAllowedRootPolicy`
- `isForbiddenWorkspaceRoot` -> `isForbiddenAllowedRoot`
- `testAllowedRootDir` -> `testAllowedRootDir` (keep, it creates an allowed
  root test directory)
- `testWorkspaceDir` -> `testWorkspaceDir` (keep, it creates a workspace
  directory under an allowed root)

**Affected production files:** `workspace_root.go`, `config.go`, `config_cli.go`,
`principal.go`, `apparmor.go`

**Affected tests/docs:** `workspace_root_test.go`, `workspace_root_invariant_test.go`,
`test_helpers_test.go`, `run_mount_policy_test.go`, `multi_root_regression_test.go`,
many others

**Behavioral risk:** Low. Pure rename. The concepts are already distinct in
behavior; only the names are misleading.

**Recommended batch:** B1 (allowed-root naming)

### 2. `Preflight` used for two different concerns

**Current names:** `preflight()` on `appArmorProfileManager`,
`TestServeSystemModePreflight*`, `TestInitSystemModePreflight*`,
`TestCAPreflight*`, `ca_config_preflight_test.go`,
`setupCAConfigPreflightTest`, `validateCAConfig`

**Actual domain concepts:**
- AppArmor preflight = verify parser/profile availability before mutation
- CA preflight = validate CA file before config write
- serve/init preflight = verify MAC backend confinement before startup

**Why ambiguous:** "Preflight" is used for three structurally different
checks: (1) tool availability before a mutation, (2) data validation before
a config write, (3) confinement verification before daemon startup. They
happen to all run "before" something, but the semantics are different.

**Proposed canonical terms:**
- `appArmorProfileManager.preflight()` -> `appArmorProfileManager.checkTools()`
  or keep as `preflight()` but document it as "tool availability check"
- CA preflight -> `validateCAConfig` (already exists, this is the canonical name)
- serve/init preflight -> `requireMACConfinement` (already exists in `lsm.go`)

**Affected production files:** `apparmor.go`, `ca.go`, `lsm.go`, `config.go`

**Affected tests:** `apparmor_test.go`, `apparmor_lsm_test.go`,
`ca_config_preflight_test.go`, `lsm_test.go`

**Behavioral risk:** Low. The AppArmor `preflight()` is a narrow internal
method. The CA and serve/init preflight tests already describe the actual
behavior in their names.

**Recommended batch:** B2 (preflight disambiguation)

### 3. `Manager` used for both lifecycle owners and mechanics

**Current names:** `appArmorProfileManager`, `selinuxFcontextManager`

**Actual domain concepts:**
- `appArmorProfileManager` = native AppArmor profile/managed-fragment
  mechanics (no lifecycle decisions)
- `selinuxFcontextManager` = native SELinux fcontext mechanics (no lifecycle
  decisions)

**Why ambiguous:** The MAC naming grammar says `workspaceMACDriver` = backend
mechanics only; no lifecycle decisions. The `*Manager` types are the
native mechanics layer, not lifecycle owners. The word "Manager" suggests
lifecycle/ownership authority. The `sessionMACCoordinator` is the actual
lifecycle owner.

**Proposed canonical terms:**
- `appArmorProfileManager` -> `appArmorProfileManager` (keep — the word
  "Profile" makes it clear this is profile mechanics, not lifecycle)
- `selinuxFcontextManager` -> `selinuxFcontextManager` (keep — the word
  "fcontext" makes it clear this is fcontext mechanics, not lifecycle)

**Verdict:** These names are actually fine because the domain-specific
qualifier ("Profile", "fcontext") makes the scope clear. The MAC naming
grammar already records them. No change needed.

**Classification downgrade:** P1 -> P3 (polish only, names are acceptable)

## P2 — meaningful project-wide inconsistency

### 4. `Request`/`Response` types split across two files

**Current names:**
- `api_contract.go`: `pullRequest`, `buildRequest`, `runRequest`,
  `mountRequest`, `pullResponse`, `operationCreatedResponse`,
  `operationStatusResponse`, `principalSummary`, `listPrincipalsResponse`,
  `rotateAdminTokenResponse`, `operationLogsResponse`, `operationCancelResponse`
- `sessions.go`: `sessionRequest`, `sessionJSON`, `createSessionResponse`,
  `listSessionsResponse`, `sessionAuthContext`
- `principal_handler.go`: `createPrincipalRequest`, `setPrincipalRequest`,
  `allowedRootRequest`, `principalResponse`, `principalChangedResponse`,
  `createCredentialRequest`, `credentialJSON`, `createCredentialResponse`,
  `listCredentialsResponse`, `revokeCredentialResponse`
- `response.go`: `response` (generic error/OK response)

**Actual domain concept:** HTTP request/response types for the API contract.

**Why ambiguous:** Request/response types are split across three files with
no consistent pattern. `api_contract.go` is documented as "Shared API
request/response types" but `sessions.go` and `principal_handler.go` define
their own request/response types. The generic `response` type in
`response.go` is used for error responses and health checks, while
`pullResponse` in `api_contract.go` is a success response with the same
shape.

**Proposed canonical terms:**
- Keep `api_contract.go` as the canonical location for shared types
- Move `sessionRequest`, `sessionJSON`, `createSessionResponse`,
  `listSessionsResponse` from `sessions.go` to `api_contract.go`
- Move `createPrincipalRequest`, `setPrincipalRequest`, `allowedRootRequest`,
  `principalResponse`, `principalChangedResponse`, `createCredentialRequest`,
  `credentialJSON`, `createCredentialResponse`, `listCredentialsResponse`,
  `revokeCredentialResponse` from `principal_handler.go` to `api_contract.go`
- Rename generic `response` in `response.go` to `errorResponse` or
  `healthResponse` to distinguish from `pullResponse`

**Affected production files:** `api_contract.go`, `sessions.go`,
`principal_handler.go`, `response.go`

**Affected tests:** None directly (tests use these types transparently)

**Behavioral risk:** Low. Pure file reorganization.

**Recommended batch:** B3 (API contract consolidation)

### 5. `Fn` seam naming vs `Deps` seam naming vs `Hooks` seam naming

**Current names:**
- `App.PinMountFn`, `App.StageBuildContextFn`, `App.RotateRenameFn` —
  `*Fn` suffix on `App` fields
- `reloadDeps` — `Deps` suffix on struct type
- `stagingHooks` — `Hooks` suffix on struct type
- `stagingSyscall` — `Syscall` suffix on struct type
- `mountSeam` — `Seam` suffix on interface type
- `selinuxSeam` — `Seam` suffix on test struct type

**Actual domain concept:** Test injection points for production dependencies.

**Why ambiguous:** The same concept (injectable production dependency) has
five different naming conventions. `*Fn` is used for function-type seams on
`App`. `*Deps` is used for struct-type dependency injection. `*Hooks` is
used for callback injection points. `*Syscall` is used for syscall
abstraction. `*Seam` is used for both interface types and test mock types.

**Proposed canonical terms:**
- `*Fn` on `App` fields -> keep (standard Go convention for function fields)
- `reloadDeps` -> `reloadDeps` (keep, `Deps` is clear for struct injection)
- `stagingHooks` -> `stagingHooks` (keep, `Hooks` is clear for callbacks)
- `stagingSyscall` -> `stagingSyscall` (keep, `Syscall` is clear)
- `mountSeam` -> `mountSeam` (keep, `Seam` is clear for interface types)
- `selinuxSeam` -> `selinuxSeam` (keep, `Seam` is clear for test mocks)

**Verdict:** The naming is actually consistent by convention:
- `*Fn` = function field on `App`
- `*Deps` = struct holding multiple production dependencies
- `*Hooks` = callback injection points
- `*Syscall` = syscall abstraction
- `*Seam` = interface or test mock

The conventions are different but each is appropriate for its use case.
No change needed.

**Classification downgrade:** P2 -> P3 (polish only, conventions are acceptable)

### 6. `workspace_root.go` filename vs actual concern

**Current names:** `workspace_root.go`, `workspace_root_test.go`,
`workspace_root_invariant_test.go`

**Actual domain concept:** Authorization-root policy validation.

**Why ambiguous:** The filename suggests the file owns "workspace root"
semantics, but it only owns authorization-root policy. The workspace root
is an authorization ceiling, not a workspace. The file should be named
`allowed_root_policy.go` to match its actual concern.

**Proposed canonical terms:**
- `workspace_root.go` -> `allowed_root_policy.go`
- `workspace_root_test.go` -> `allowed_root_policy_test.go`
- `workspace_root_invariant_test.go` -> `allowed_root_invariant_test.go`

**Affected production files:** `workspace_root.go`

**Affected tests:** `workspace_root_test.go`, `workspace_root_invariant_test.go`

**Behavioral risk:** None. Pure file rename.

**Recommended batch:** B1 (allowed-root naming)

### 7. `response` type shadowing in `response.go`

**Current names:** `response` (generic OK/error response in `response.go`),
`pullResponse` (in `api_contract.go`)

**Actual domain concept:** HTTP response body types.

**Why ambiguous:** The generic `response` type has the same shape as
`pullResponse` but is used for error responses and health checks. The name
`response` is too generic and shadows the concept of "response" in general
code. `pullResponse` is a specific success response.

**Proposed canonical terms:**
- `response` -> `genericResponse` or keep as `response` with a clearer
  comment distinguishing it from endpoint-specific response types

**Affected production files:** `response.go`

**Affected tests:** None directly

**Behavioral risk:** None.

**Recommended batch:** B3 (API contract consolidation)

### 8. `sessionJSON` vs `sessionRequest` naming

**Current names:** `sessionJSON` (serializable session representation),
`sessionRequest` (create session request body)

**Actual domain concept:** Session serialization for API.

**Why ambiguous:** `sessionJSON` suggests a JSON-specific representation,
but it's used as the serializable form of `Session`. The name `sessionJSON`
is inconsistent with `sessionRequest` which uses `Request` suffix.

**Proposed canonical terms:**
- `sessionJSON` -> `sessionJSON` (keep — the name is descriptive of its
  purpose as a JSON-serializable form)

**Verdict:** The name is acceptable. It clearly distinguishes the
JSON-serializable form from the internal `Session` type.

**Classification downgrade:** P2 -> P3 (polish only)

## P3 — polish/readability only

### 9. Acronym casing inconsistency

**Current names:** `selinux`, `apparmor`, `apparmor_parser`, `apparmor.d`,
`apparmor_lsm`, `apparmor_cli`, `selinux_workspace`, `selinuxFcontextManager`

**Actual domain concept:** Backend-specific identifiers.

**Why ambiguous:** The MAC naming grammar specifies `AppArmor` and `SELinux`
casing. File names use lowercase (`apparmor.go`, `selinux_workspace.go`),
which is correct for Go file naming. Type names use mixed casing
(`selinuxFcontextManager` — lowercase `selinux`, uppercase `Fcontext`).

**Proposed canonical terms:**
- `selinuxFcontextManager` -> `selinuxFcontextManager` (keep — Go convention
  for unexported types uses lowercase prefix; the MAC grammar casing applies
  to documentation, not Go identifiers)
- File names: keep lowercase (Go convention)

**Verdict:** Acceptable as-is. Go naming conventions take precedence over
documentation casing for identifiers.

### 10. `stagedBuildContext` vs `pinnedMount` — cleanup pattern

**Current names:** `stagedBuildContext.Cleanup()`, `pinnedMount.Cleanup()`

**Actual domain concept:** Resource cleanup with idempotent, concurrency-safe
semantics.

**Why ambiguous:** Not ambiguous. Both follow the same pattern. The names
are clear.

**Verdict:** Acceptable as-is.

### 11. `testWorkspaceMACDriver` vs `failingWorkspaceMACDriver` vs `selinuxTestDriver`

**Current names:** `testWorkspaceMACDriver`, `failingWorkspaceMACDriver`,
`selinuxTestDriver` (all in `mac_lifecycle_test.go`)

**Actual domain concept:** Test mock implementations of `workspaceMACDriver`.

**Why ambiguous:** The naming is descriptive of each mock's behavior.
`testWorkspaceMACDriver` = general-purpose mock, `failingWorkspaceMACDriver`
= always-fails mock, `selinuxTestDriver` = SELinux-specific mock.

**Verdict:** Acceptable as-is. Each name describes its test role.

### 12. `newTestManager` in `selinux_workspace_test.go`

**Current names:** `newTestManager` (creates `selinuxFcontextManager` for tests)

**Actual domain concept:** Test constructor for `selinuxFcontextManager`.

**Why ambiguous:** `Manager` in the function name refers to the type name
`selinuxFcontextManager`, not to lifecycle management. The name is consistent
with the type it creates.

**Verdict:** Acceptable as-is.

## Names that look unusual but SHOULD NOT be changed

- `workspaceMACDriver` — canonical MAC grammar term, correct
- `sessionMACCoordinator` — canonical MAC grammar term, correct
- `workspaceMACCoverage` — canonical MAC grammar term, correct
- `HelperOwned` — canonical MAC grammar term, correct
- `mac_lifecycle.go` — correct filename for MAC lifecycle code
- `mac_lifecycle_test.go` — correct filename for MAC lifecycle tests
- `mountSeam` — correct name for syscall seam interface
- `stagingHooks` — correct name for callback injection
- `reloadDeps` — correct name for dependency injection struct
- `*Fn` suffix on `App` fields — standard Go convention
- `pinnedMount` — correct name for inode-pinning result
- `stagedBuildContext` — correct name for build staging result

## Proposed rename batches

### B1: Allowed-root naming (P1)

Smallest high-impact batch. Fixes the most architecturally misleading names.

**Changes:**
- `workspace_root.go` -> `allowed_root_policy.go`
- `workspace_root_test.go` -> `allowed_root_policy_test.go`
- `workspace_root_invariant_test.go` -> `allowed_root_invariant_test.go`
- `canonicalizeWorkspaceRootForAdd` -> `canonicalizeAllowedRootForAdd`
- `validateWorkspaceRootPolicy` -> `validateAllowedRootPolicy`
- `isForbiddenWorkspaceRoot` -> `isForbiddenAllowedRoot`

**Affected files:** ~15 production + test files

**Risk:** Low. Pure rename. The concepts are already distinct in behavior.

### B2: Preflight disambiguation (P1)

**Changes:**
- `appArmorProfileManager.preflight()` -> `appArmorProfileManager.checkTools()`
- Rename CA preflight test file: `ca_config_preflight_test.go` ->
  `ca_config_validation_test.go`
- Rename `setupCAConfigPreflightTest` -> `setupCAConfigValidationTest`
- Update test names in `apparmor_lsm_test.go` and `lsm_test.go` to use
  `MACConfinement` instead of `Preflight`

**Affected files:** ~5 production + test files

**Risk:** Low. The `preflight()` method is internal to `appArmorProfileManager`.

### B3: API contract consolidation (P2)

**Changes:**
- Move request/response types from `sessions.go` and `principal_handler.go`
  into `api_contract.go`
- Rename generic `response` in `response.go` to `genericResponse`

**Affected files:** `api_contract.go`, `sessions.go`, `principal_handler.go`,
`response.go`

**Risk:** Low. Pure file reorganization.

## Summary

| Priority | Count | Description |
|----------|-------|-------------|
| P1 | 2 | `Root` conflation, `Preflight` conflation |
| P2 | 2 | API contract split, seam naming conventions |
| P3 | 4 | Manager naming (downgraded), seam naming (downgraded), sessionJSON (downgraded), acronym casing |

**Recommended first batch:** B1 (allowed-root naming). It fixes the most
architecturally misleading names with the lowest risk.
