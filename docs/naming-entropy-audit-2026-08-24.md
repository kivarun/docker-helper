# Naming entropy audit

Date: 2026-08-24

Reference model: `AGENTS.md` § MAC naming grammar.

Rule: one domain concept -> one canonical term. Different concepts must not
share one word. Different implementations must not invent synonyms for the
same concept.

## P1 — terminology obscures architecture/security semantics

### 1. `workspace_root` / `Root` / path-safety conflation

**Current names:** `workspace_root.go`, `workspace_root_test.go`,
`workspace_root_invariant_test.go`, `canonicalizeWorkspaceRootForAdd`,
`validateWorkspaceRootPolicy`, `isForbiddenWorkspaceRoot`,
`validateRootPathForAdd`, `validateRootLexical`, `validateRootPathForRemove`

**Production call-site inventory:**

`canonicalizeWorkspaceRootForAdd` (generic path canonicalization + safety):
- `config.go:535` — allowed_roots config field (authorization ceiling)
- `config.go:791` — init allowed_root (authorization ceiling)
- `config.go:1108` — resolveAllowedRoot (authorization ceiling)
- `config_cli.go:350` — config allowed-root add (authorization ceiling)
- `principal.go:75` — principal allowed root add (authorization narrowing)
- `principal.go:139` — principal home directory (authorization narrowing)
- `apparmor.go:121` — AppArmor managed root add (MAC boundary, NOT authorization)

`validateWorkspaceRootPolicy` (pure policy check, no filesystem):
- `config.go:673` — validateAllowedRootValue (authorization ceiling)
- `apparmor.go:594` — check() managed root diagnosis (MAC boundary, NOT authorization)

`isForbiddenWorkspaceRoot` (forbidden-tree check):
- `workspace_root.go:133` — called by canonicalizeWorkspaceRootForAdd
- `workspace_root.go:150` — called by validateWorkspaceRootPolicy
- `init_test.go` — test-only

`validateRootPathForAdd` (AppArmor-specific, wraps canonicalizeWorkspaceRootForAdd):
- `apparmor.go:486` — addManagedRoot (MAC boundary)

`validateRootLexical` (AppArmor-specific fragment format):
- `apparmor.go:127,146,153,164,241` — AppArmor managed fragment operations (MAC boundary)

**Actual domain concepts (four, not three):**

1. Generic host path safety/canonicalization — tilde expansion, absolute path,
   existence, directory check, symlink resolution, forbidden-tree rejection
2. Global allowed root — authorization ceiling
3. Principal allowed root — authorization narrowing
4. AppArmor managed profile boundary — MAC boundary/resource

**Why ambiguous:** The name `canonicalizeWorkspaceRootForAdd` suggests it
operates on "workspace roots" (authorization), but it is genuinely shared
across four concerns. The AppArmor managed root path is a MAC boundary, not
an authorization root, yet it uses the same canonicalization function.
Similarly, `validateWorkspaceRootPolicy` is used for both authorization
roots and MAC boundaries. The word "workspace root" in these function names
conflates generic path admissibility with authorization policy.

The filename `workspace_root.go` suggests the file owns "workspace root"
semantics, but it actually owns generic host path safety. The file has no
authorization-specific logic — it only checks forbidden trees and wide
namespaces.

**Public CLI vocabulary (separate concern, higher migration risk):**

`docker-helper apparmor root list|add|remove` — these "root" objects are
AppArmor managed MAC boundaries, not authorization roots. The public CLI
uses "workspace roots" in the Summary strings. This is a public contract
that operators see. Renaming it changes the CLI help and any scripts that
parse it.

**Proposed canonical terms:**

Generic path safety (neutral, shared):
- `workspace_root.go` -> `path_safety.go`
- `workspace_root_test.go` -> `path_safety_test.go`
- `workspace_root_invariant_test.go` -> `path_safety_invariant_test.go`
- `canonicalizeWorkspaceRootForAdd` -> `canonicalizePathForAdd`
- `validateWorkspaceRootPolicy` -> `validatePathPolicy`
- `isForbiddenWorkspaceRoot` -> `isForbiddenPath`

Authorization-specific callers keep their domain-specific names:
- `validateAllowedRootValue` (config.go) — keep
- `resolveAllowedRoot` (config.go) — keep
- `validateRootPathForAdd` (apparmor.go) — keep (AppArmor-specific)
- `validateRootLexical` (apparmor.go) — keep (AppArmor-specific)

Public CLI contract (classified separately, higher risk):
- `docker-helper apparmor root` — rename to `docker-helper apparmor boundary`
- CLI Summary strings — update to "MAC boundaries" / "profile boundaries"
- Fragment header comment — update "workspace roots" to "MAC boundaries"

**Affected production files:** `workspace_root.go`, `config.go`, `config_cli.go`,
`principal.go`, `apparmor.go`, `apparmor_cli.go`

**Affected tests/docs:** `workspace_root_test.go`, `workspace_root_invariant_test.go`,
`test_helpers_test.go`, `init_test.go`, `apparmor_test.go`, `apparmor_lsm_test.go`,
`packaging_test.go`, many others

**Behavioral risk:**
- Internal Go symbol rename: Low. Pure rename.
- Public CLI contract rename: Medium. Changes CLI help, operator scripts.

**Recommended batch:** B1 (generic path safety), B1c (public CLI contract —
separate sub-batch)

---

### 2. `Preflight` — temporal word reused across domains

**Current names:** `preflight()` on `appArmorProfileManager`,
`TestServeSystemModePreflight*`, `TestInitSystemModePreflight*`,
`TestCAPreflight*`, `ca_config_preflight_test.go`,
`setupCAConfigPreflightTest`

**What each name actually communicates:**

`appArmorProfileManager.preflight()`:
- Checks parser availability AND main profile existence/permissions
- Used before add/remove/check operations
- Not a "tool check" — also validates the profile itself
- This is a prerequisite validation for the profile manager

CA `*Preflight*` tests:
- Prove that CA validation occurs before config mutation
- The word "preflight" here describes the ordering guarantee:
  validation-before-side-effects
- The canonical function is `validateCAConfig` in production code

Serve/init `*Preflight*` tests:
- Prove that MAC confinement check occurs before loadConfig
- The word "preflight" describes the ordering guarantee:
  confinement-before-configuration
- The canonical function is `requireMACConfinement` in production code

**Verdict:** The reuse of "preflight" across these domains is not a naming
collision. The word "preflight" is a temporal descriptor meaning
"validation before side effects." Each domain uses it to describe the same
temporal concept. The production functions have distinct names
(`preflight`, `validateCAConfig`, `requireMACConfinement`). The test names
describe what they prove (ordering), not the production function they call.

**Proposed canonical terms:**
- `appArmorProfileManager.preflight()` -> `appArmorProfileManager.checkPrerequisites()`
  (more accurate than `checkTools()` — it checks both parser AND profile)
- CA test names: keep `*Preflight*` (they describe ordering guarantees)
- Serve/init test names: keep `*Preflight*` (they describe ordering guarantees)

**Affected production files:** `apparmor.go`

**Affected tests:** `apparmor_test.go`

**Behavioral risk:** Low. The `preflight()` method is internal to
`appArmorProfileManager`.

**Classification:** P2 (internal symbol rename only; test names are correct)

---

## P2 — meaningful project-wide inconsistency

### 3. API DTO ownership — shared types not in `api_contract.go`

**Canonical rule:** `api_contract.go` owns DTOs shared by server handlers
and `apiClient`. It does NOT need to own every handler-local request/response
struct.

**Inventory by actual production use-site:**

`sessionRequest` (sessions.go:12):
- Server: `sessions.go:131` — handleCreateSession
- Client: `client.go:142` — apiClient.createSession
- **Shared** -> candidate for `api_contract.go`

`sessionJSON` (sessions.go:16):
- Server: `sessions.go:35,254-260` — sessionToJSON, listSessionsResponse
- Client: `client.go` — not directly used (client uses listSessionsResponse)
- Tests: `client_test.go` — used in test servers
- **Shared** (used by server and test servers) -> candidate for `api_contract.go`

`createSessionResponse` (sessions.go:24):
- Server: `sessions.go:207` — handleCreateSession
- Client: `client.go:158` — apiClient.createSession
- **Shared** -> candidate for `api_contract.go`

`listSessionsResponse` (sessions.go:30):
- Server: `sessions.go:254` — handleListSessions
- Client: `client.go:133` — apiClient.listSessions
- **Shared** -> candidate for `api_contract.go`

`sessionAuthContext` (sessions.go:50):
- Server: `sessions.go` — authenticateSessionRequest
- Client: NOT used
- **NOT shared** -> stays with session authentication

Principal handler types (principal_handler.go):
- `createPrincipalRequest`, `setPrincipalRequest`, `allowedRootRequest`:
  Used by server handlers AND `apiClient` methods in `client.go`
  -> **Shared** -> candidates for `api_contract.go`
- `principalResponse`, `principalChangedResponse`:
  Used by server handlers AND `apiClient` methods AND `principal_cli.go`
  -> **Shared** -> candidates for `api_contract.go`
- `createCredentialRequest`, `credentialJSON`, `createCredentialResponse`,
  `listCredentialsResponse`, `revokeCredentialResponse`:
  Used by server handlers AND `apiClient` methods in `client.go`
  -> **Shared** -> candidates for `api_contract.go`

**Real inconsistency: registry DTO split**

`registryLoginRequest` (registry.go:13):
- Server: `registry.go:27` — handleRegistryLogin
- Client: `client.go:183` — apiClient.registryLogin
- **Shared** but lives in `registry.go`, not `api_contract.go`

`registryLoginResponse` (client.go:177):
- Client: `client.go:203` — apiClient.registryLogin
- Server: NOT used (server uses generic `response` envelope)
- **Client-only** — this is a separate duplicate of the generic response shape

This is a real inconsistency: `registryLoginRequest` is shared but not in
`api_contract.go`, and `registryLoginResponse` is client-only while the
server uses the generic `response` envelope.

**Generic `response` type (response.go:42):**

Production call-sites:
- `response.go:73` — writeError (error responses)
- `response.go:100` — writeUnauthorizedAdmin (401)
- `response.go:109` — writeUnauthorizedSession (401)
- `response.go:186` — handleHealth (200)
- `reload.go:145` — handleReload success (200)

Test call-sites (decode error responses):
- `build_test.go:316,602` — decode error response
- `mounts_test.go:260,851,902,949` — decode error response
- `admin_auth_test.go:127` — decode error response

The `response` type is the generic server-side response envelope. It is used
for error responses, unauthorized responses, and simple success responses.
The name `response` is narrow and unambiguous within the package. It is not
shared with the client (client uses specific response types). No rename needed.

**Proposed canonical terms:**
- Move shared session types from `sessions.go` to `api_contract.go`:
  `sessionRequest`, `sessionJSON`, `createSessionResponse`, `listSessionsResponse`
- Move shared principal types from `principal_handler.go` to `api_contract.go`:
  `createPrincipalRequest`, `setPrincipalRequest`, `allowedRootRequest`,
  `principalResponse`, `principalChangedResponse`,
  `createCredentialRequest`, `credentialJSON`, `createCredentialResponse`,
  `listCredentialsResponse`, `revokeCredentialResponse`
- Move `registryLoginRequest` from `registry.go` to `api_contract.go`
- Keep `sessionAuthContext` in `sessions.go` (not shared)
- Keep `registryLoginResponse` in `client.go` (client-only)
- Keep generic `response` in `response.go` (server-only envelope)

**Affected production files:** `api_contract.go`, `sessions.go`,
`principal_handler.go`, `registry.go`, `client.go`

**Affected tests:** None directly (tests use these types transparently)

**Behavioral risk:** Low. Pure file reorganization.

**Recommended batch:** B2 (API DTO consolidation)

---

## Validated vocabulary — keep as-is

The following were investigated and found to be acceptable:

- `appArmorProfileManager` / `selinuxFcontextManager` — the domain-specific
  qualifier ("Profile", "fcontext") makes the scope clear. The MAC naming
  grammar records them as native mechanics types, not lifecycle owners.

- `*Fn` suffix on `App` fields (`PinMountFn`, `StageBuildContextFn`,
  `RotateRenameFn`) — standard Go convention for function fields.

- `reloadDeps` — `Deps` suffix is clear for struct-type dependency injection.

- `stagingHooks` — `Hooks` suffix is clear for callback injection points.

- `stagingSyscall` — `Syscall` suffix is clear for syscall abstraction.

- `mountSeam` — `Seam` suffix is clear for syscall seam interface.

- `selinuxSeam` — `Seam` suffix is clear for test mock.

- `sessionJSON` / `credentialJSON` — distinguish JSON-serializable forms
  from internal types.

- `stagedBuildContext.Cleanup()` / `pinnedMount.Cleanup()` — consistent
  idempotent cleanup pattern.

- `testWorkspaceMACDriver` / `failingWorkspaceMACDriver` / `selinuxTestDriver` —
  each name describes its test role.

- `newTestManager` — consistent with the type it creates
  (`selinuxFcontextManager`).

- Acronym casing in identifiers (`selinuxFcontextManager`, `apparmor.go`) —
  Go naming conventions take precedence over documentation casing.

- `response` (response.go) — narrow, unambiguous within the package.
  Server-side generic response envelope. Not shared with client.

---

## Second-pass vocabulary boundaries

### allowed root / workspace / path / root / MAC boundary

- `allowed_root` / `AllowedRoots` — authorization ceiling, correct
- `workspace` — concrete session capability path, correct
- `path` — generic filesystem path, correct
- `root` in `validateRootPathForAdd`, `validateRootLexical` — AppArmor
  managed MAC boundary, correct within AppArmor context
- `root` in `docker-helper apparmor root` — public CLI for MAC boundary,
  classified in Finding 1 as public-contract rename

### principal / user / username

- `Principal` — domain type, correct
- `username` — field in Principal, correct
- No conflation found.

### credential / token / credential ID / credential name

- `Credential` — domain type, correct
- `CredentialAuthResult` — auth result, correct
- `credentialJSON` — JSON-serializable form, correct
- `token` — admin token vs credential token, distinct concepts
- No conflation found.

### operation / job / task

- `operation` — domain term, used consistently
- No "job" or "task" found in production code.

### context / workspace / workdir / mount source

- `workspace` — session capability path, correct
- `workdir` — container working directory, correct
- `context` — build context path, correct
- `mount source` — bind mount source, correct
- No conflation found.

### config singular/plural terminology

- `allowed_root` (singular, legacy) vs `allowed_roots` (plural, current) —
  legacy migration handled, correct
- `config set` / `config show` / `config allowed-root` — consistent CLI verbs

### public CLI nouns vs internal domain nouns

- `docker-helper apparmor root` — public CLI for MAC boundary (Finding 1)
- `docker-helper config allowed-root` — public CLI for authorization ceiling, correct
- `docker-helper principal` — public CLI for principal, correct

### test names/comments vs behavior proved

- CA `*Preflight*` tests — prove validation-before-mutation ordering, correct
- Serve/init `*Preflight*` tests — prove confinement-before-config ordering, correct
- No stale test names found beyond those already addressed.

---

## Proposed rename batches

### B1: Generic path safety (P1, internal symbols)

Separates generic host path safety from authorization/MAC-specific concerns.

**Changes:**
- `workspace_root.go` -> `path_safety.go`
- `workspace_root_test.go` -> `path_safety_test.go`
- `workspace_root_invariant_test.go` -> `path_safety_invariant_test.go`
- `canonicalizeWorkspaceRootForAdd` -> `canonicalizePathForAdd`
- `validateWorkspaceRootPolicy` -> `validatePathPolicy`
- `isForbiddenWorkspaceRoot` -> `isForbiddenPath`

**Affected files:** ~15 production + test files

**Risk:** Low. Pure rename. The functions are genuinely shared across
authorization and MAC boundary concerns; the neutral names reflect that.

### B1c: Public CLI contract (P1, public vocabulary)

Higher migration risk. Changes what operators see in CLI help.

**Changes:**
- `docker-helper apparmor root` -> `docker-helper apparmor boundary`
- CLI Summary strings: "workspace roots" -> "MAC boundaries"
- Fragment header: "Managed AppArmor workspace roots" -> "Managed AppArmor MAC boundaries"

**Affected files:** `apparmor_cli.go`, `apparmor.go`, `packaging_test.go`

**Risk:** Medium. Changes CLI help, operator scripts, packaging tests.

### B2: API DTO consolidation (P2)

Moves shared DTOs to `api_contract.go`.

**Changes:**
- Move `sessionRequest`, `sessionJSON`, `createSessionResponse`,
  `listSessionsResponse` from `sessions.go` to `api_contract.go`
- Move `createPrincipalRequest`, `setPrincipalRequest`, `allowedRootRequest`,
  `principalResponse`, `principalChangedResponse`,
  `createCredentialRequest`, `credentialJSON`, `createCredentialResponse`,
  `listCredentialsResponse`, `revokeCredentialResponse`
  from `principal_handler.go` to `api_contract.go`
- Move `registryLoginRequest` from `registry.go` to `api_contract.go`

**Affected files:** `api_contract.go`, `sessions.go`, `principal_handler.go`,
`registry.go`

**Risk:** Low. Pure file reorganization.

### B3: AppArmor preflight rename (P2, internal symbol)

**Changes:**
- `appArmorProfileManager.preflight()` -> `appArmorProfileManager.checkPrerequisites()`

**Affected files:** `apparmor.go`, `apparmor_test.go`

**Risk:** Low. Internal method rename.

---

## Summary

| Priority | Count | Description |
|----------|-------|-------------|
| P1 | 2 | Path safety conflation (internal + public CLI) |
| P2 | 2 | API DTO ownership, AppArmor preflight rename |

**Validated vocabulary (no change needed):** 12 items (Manager naming,
seam conventions, sessionJSON, cleanup pattern, test mocks, acronym casing,
response envelope, credential/operation terminology)

**Recommended first batch:** B1 (generic path safety). It disambiguates the
most architecturally misleading names — functions that are genuinely shared
across authorization and MAC boundary concerns but carry "workspace root"
in their names — with the lowest risk.
