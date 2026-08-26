# Project-wide naming and architecture vocabulary review

Date: 2026-08-24

Review baseline: origin/main at ab48afdd8167009b3d1323ea17caef001b4d654b.

Status: maintained resolved-findings ledger. Implementation findings recorded
here are resolved through 9dc5eb5708652c2c52faa8cb98d12117c078d7ce; this
revision also records the documentation/shipping-vocabulary reconciliation
described in section 9.

This document is a maintained resolution ledger, not an analysis-only
snapshot. Original evidence and line references describe the review baseline
and may no longer match current line numbers; RESOLVED sections describe the
later implementation that addressed each finding. Baseline evidence is not
presented as current source evidence.

The MAC/workspace-path reference area was not re-audited in depth. It is used
as the quality model defined in
[naming-entropy-audit-2026-08-24.md](naming-entropy-audit-2026-08-24.md).
In the original review findings, the only MAC finding was a direct
contradiction between that accepted model and a shipping policy source. Later
independent MAC-related findings are recorded separately in section 9.

## 1. Executive summary

The review covered daemon lifecycle, deployment/listeners, authentication and
authorization, principals, credentials and tokens, sessions and workspaces,
operations, Docker execution, mounts and staging, config/init/reload, API and
persistence vocabulary, audit/logging, trusted CA and registry handling, CLI,
test seams, filenames, comments, packaging, and architecture-facing
documentation.

Actionable findings:

- 5 P1 findings where current vocabulary hides authority, ownership, lifecycle,
  or security-resource identity;
- 11 P2 findings worth fixing before or around Release 2 completion;
- 8 P3 findings limited to local naming, tests, comments, or documentation.

The highest-risk vocabulary collisions are:

1. session capability authentication and session-control authority both use
   the unqualified term session;
2. global, Principal, and effective allowed-root scopes lose their scope
   qualifiers;
3. operationRegistry is the operation lifecycle supervisor, not a passive
   registry;
4. original mount sources and helper-owned pinned bind sources share the field
   name HostPath;
5. updatePrincipalEnabled hides transactional deletion of Session
   capabilities.

Two non-naming findings should be fixed before the naming cleanup:

- Principal disable/delete and direct expired-session cleanup bypass the
  session MAC lifecycle owner;
- two Principal handlers read App.Config outside the synchronized config
  snapshot path.

Verification on the review baseline:

- go test -run '^$' ./... passed;
- go vet ./... passed;
- a full go test ./... run was not a valid repository signal in the review
  environment because Unix sockets are prohibited and the process runs with
  EUID 0, selecting system-mode paths in tests.

## 2. P1 findings

### P1-1. Session capability and session-control authority share one vocabulary

**Status: RESOLVED**

Internal symbols have been renamed to distinguish the two authority domains:

- **requireSessionCapability** authenticates a Session bearer token for data-plane
  actions (run, build, pull, registry login, operation access).
- **sessionControlAuthority** and **authenticateSessionControlRequest** authenticate
  an admin token or Principal credential for session control (create, list, delete).
- **writeUnauthorizedSessionCapability** returns a capability-specific message
  ("Session authentication required.") for data-plane 401 responses.
- **writeUnauthorizedSessionControl** retains the session-management message
  ("Authentication required for session management.") for control-plane 401 responses.
- **TestAuthAuditCredentialNotFound_CreateSession** correctly describes the test
  behavior: non-admin token falls through to Principal credential lookup, which
  fails with credential.not_found.

Test vocabulary was also corrected:

- All `TestRunSessionAuth*` tests renamed to `TestRunSessionCapabilityAuth*`.
- `TestAuthAuditAdminParseFailed*` renamed to `TestAuthAuditSessionControlParseFailed*`.
- `TestAuthAuditSessionParseFailed*` renamed to `TestAuthAuditSessionCapabilityParseFailed*`.
- `TestAuthAuditSessionNotFound*` renamed to `TestAuthAuditSessionCapabilityNotFound*`.
- `TestAuthAuditSessionDatabaseError*` renamed to `TestAuthAuditSessionCapabilityDatabaseError*`.
- `TestAuthAuditNoFailureOnValidSessionAuth*` renamed to
  `TestAuthAuditNoFailureOnValidSessionCapabilityAuth*`.

Explicit response-contract tests were added:

- `TestRunSessionCapabilityAuthResponseContract` asserts HTTP 401, code
  "unauthorized", message "Session authentication required.", and
  WWW-Authenticate: Bearer for missing session capability.
- `TestAuthAuditSessionControlUnauthorizedResponseContract` asserts HTTP 401,
  code "unauthorized", message "Authentication required for session management.",
  and WWW-Authenticate: Bearer for missing session-control authority.

**Previous names (resolved)**

- ~~requireSession~~ → requireSessionCapability
- ~~sessionAuthContext~~ → sessionControlAuthority
- ~~authenticateSessionRequest~~ → authenticateSessionControlRequest
- ~~writeUnauthorizedSession~~ → writeUnauthorizedSessionCapability / writeUnauthorizedSessionControl
- ~~TestAuthAuditAdminWrongToken_CreateSession~~ → TestAuthAuditCredentialNotFound_CreateSession
- ~~authResult~~ (field) → principalCredential

**Compatibility and narrow batch**

Audit event/result strings were not changed in this batch. HTTP message text for
session-capability 401 responses was corrected from the incorrect session-management
message to a capability-specific message. This is an observable change that fixes
semantically wrong wording.

### P1-2. Allowed-root names lose the policy-scope level

**Status: RESOLVED**

Internal symbols now make the authorization hierarchy explicit:

- **intersectAllowedRootScopes(globalAllowedRoots, principalAllowedRoots)**
  returns **effectiveAllowedRoots**.
- **sessionCreatePolicy.EffectiveAllowedRoots** is the already-computed
  effective session-creation scope.
- **CredentialAuthResult.PrincipalAllowedRoots** carries the Principal's
  allowed-root scope from credential authentication.
- **isWithinAnyAllowedRoot** checks containment against any allowed root.
- **validatePrincipalAllowedRootForAdd**, **addPrincipalAllowedRoot**,
  **removePrincipalAllowedRoot** are the Principal-policy operations.
- **handleAddPrincipalAllowedRoot**, **handleRemovePrincipalAllowedRoot**
  are the HTTP handlers.

handleCreateSession now reads:

```
globalAllowedRoots := ...
principalAllowedRoots := auth.PrincipalAllowedRoots
effectiveAllowedRoots := intersectAllowedRootScopes(
    globalAllowedRoots,
    principalAllowedRoots,
)
```

The "launcher credential" comment in credential.go was corrected to
"Principal credential" terminology.

**Previous names (resolved)**

- ~~intersectRoots~~ → intersectAllowedRootScopes
- ~~sessionCreatePolicy.AllowedRoots~~ → EffectiveAllowedRoots
- ~~CredentialAuthResult.AllowedRoots~~ → PrincipalAllowedRoots
- ~~isUnderAnyRoot~~ → isWithinAnyAllowedRoot
- ~~validateAllowedRootForAdd~~ → validatePrincipalAllowedRootForAdd
- ~~addAllowedRoot~~ → addPrincipalAllowedRoot
- ~~removeAllowedRoot~~ → removePrincipalAllowedRoot
- ~~handleAddAllowedRoot~~ → handleAddPrincipalAllowedRoot
- ~~handleRemoveAllowedRoot~~ → handleRemovePrincipalAllowedRoot

**Compatibility**

Config.AllowedRoots and Principal.AllowedRoots were preserved (owner-qualified).
Public allowed_roots JSON, allowed-root CLI vocabulary, and
principal_allowed_roots persistence are unchanged.

### P1-3. operationRegistry is the operation lifecycle supervisor

**Status: RESOLVED**

The type has been renamed to **operationSupervisor** to reflect its actual
responsibility as the in-memory lifecycle owner for asynchronous build/run
operations. The supervisor owns:

- operation admission through **admit**;
- lookup of live/retained operations through **lookup**;
- completed-operation retention pruning through **pruneCompleted**;
- the daemon shutdown admission gate through **beginShutdown**;
- explicit operation cancellation through **cancel**;
- daemon-shutdown termination orchestration through **terminateForShutdown**
  and the shared primitive **terminateOperations**.

**Canonical vocabulary**

- `operationSupervisor` — the lifecycle supervisor type
- `newOperationSupervisor` — constructor
- `App.OperationSupervisor` — App field
- `admit` — atomic admission gate
- `lookup` — read-only operation lookup
- `pruneCompleted` — retention pruning
- `beginShutdown` — close admission for future operations
- `cancel` — explicit user/API cancellation
- `terminateForShutdown` — daemon-shutdown termination
- `terminateOperations` — shared termination primitive

**Previous names (resolved)**

- ~~operationRegistry~~ → operationSupervisor
- ~~newOperationRegistry~~ → newOperationSupervisor
- ~~OperationRegistry~~ → OperationSupervisor
- ~~tryCreate~~ → admit
- ~~get~~ → lookup
- ~~cleanup~~ → pruneCompleted
- ~~setShuttingDown~~ → beginShutdown
- ~~terminateOne~~ → cancel
- ~~terminateAll~~ → terminateForShutdown
- ~~terminateAllOps~~ → terminateOperations

**Compatibility**

Public /operations API vocabulary, Operation JSON schema, operation IDs,
cancellation HTTP status/result behavior, retention semantics, shutdown
timeout semantics, signal ordering, process/container cleanup, MAC leases,
mount pin cleanup, and audit schema are all unchanged.

### P1-4. Original and pinned mount paths share HostPath

**Status: RESOLVED**

The three distinct path concepts are now named differently:

- **resolvedMount.SourcePath** — the canonical validated original source
  pathname inside the workspace.
- **pinnedMount.PinnedPath** — the helper-owned stable inode-pinned path that
  Docker must bind in system mode.
- **dockerBindSource** — the local variable in Docker argv construction that
  selects between SourcePath (user mode) and PinnedPath (system mode).

Pinning function vocabulary:

- **pinWorkspaceMountSource** — production entry point.
- **pinWorkspaceMountSourceWithSyscalls** — implementation accepting the
  syscall seam.
- **mountPinSyscalls** — syscall interface (was mountSeam).
- **linuxMountPinSyscalls** — real Linux implementation (was linuxMountSeam).
- **defaultMountPinSyscalls** — returns the real seam (was defaultSeam).

**Previous names (resolved)**

- ~~resolvedMount.HostPath~~ → SourcePath
- ~~pinnedMount.HostPath~~ → PinnedPath
- ~~hostPath~~ (local) → dockerBindSource
- ~~PinMount~~ → pinWorkspaceMountSource
- ~~pinMount~~ → pinWorkspaceMountSourceWithSyscalls
- ~~mountSeam~~ → mountPinSyscalls
- ~~linuxMountSeam~~ → linuxMountPinSyscalls
- ~~defaultSeam~~ → defaultMountPinSyscalls
- ~~PinMountFn~~ → PinWorkspaceMountSourceFn

**Compatibility**

Mount request JSON (source/target/read_only), workspace containment, Docker
argv construction, and system-mode pinning behavior are all unchanged.

### P1-5. updatePrincipalEnabled hides Session capability revocation

**Status: RESOLVED BY N1**

The original problem was that **updatePrincipalEnabled** appeared to update a
boolean but actually performed a transactional Principal enabled-state
transition with Session deletion, encoding the Changed state through
nil/empty-slice signaling.

The fix split DB persistence, App lifecycle ownership, explicit result, and
MAC release into their real responsibilities.

**Final canonical implementation**

- **`principalEnabledChangeResult`** — explicit result containing:
  - `Changed bool` — whether the enabled state actually transitioned;
  - `RevokedSessionIDs []string` — session IDs deleted when disabling.

- **`persistPrincipalEnabledChange`** — DB-level transactional primitive:
  - reads current enabled state within the transaction;
  - returns `Changed=false` for an already-matching state;
  - when disabling: updates enabled state, collects affected Session IDs,
    deletes those Sessions;
  - commits the transaction before returning success.

- **`App.applyPrincipalEnabledChange`** — App-level lifecycle operation:
  - invokes the DB transition;
  - only after successful DB commit releases deleted Session MAC bindings
    through `releaseSessionBindings`.

- **`deletePrincipalWithMAC`** — App-level Principal deletion lifecycle:
  - performs DB deletion first;
  - after successful DB commit releases deleted Session MAC bindings.

- **`releaseSessionBindings`** — releases Session bindings through
  `MACCoordinator`; does not terminate running operations.

**Lifecycle ownership**

1. The DB transaction owns the authoritative Principal enabled-state
   transition and Session deletion.

2. MAC lifecycle release occurs only after successful DB commit through the
   App-level lifecycle owner.

3. Principal HTTP handlers perform runtime-directory cleanup only after the
   lifecycle transition.

4. Runtime-directory cleanup is best-effort and does NOT own MAC lifecycle.

5. `RuntimeDir` is taken from a synchronized `getConfig()` snapshot.

**Operation invariant**

Disabling or deleting a Principal deletes/revokes its Sessions. It does NOT
terminate already-running operations. Existing workspace-use leases remain
authoritative. MAC coverage remains held until those operation leases are
released.

**Historical vocabulary (resolved)**

~~updatePrincipalEnabled~~ was replaced by the explicit lifecycle vocabulary
above. The solution did not perform a simple rename: it split DB persistence,
App lifecycle ownership, explicit result semantics, and MAC release into
separate responsibilities.

**Compatibility**

HTTP routes, request/response JSON schema, SQLite schema, audit event/result
names, Session token semantics, and operation cancellation semantics are
unchanged.

## 3. P2 findings

### P2-1. Principal disabled is reported as credential disabled

**Status: RESOLVED**

**ErrCredentialDisabled** was renamed to **ErrPrincipalDisabled** with message
"principal disabled". A disabled Principal is not a disabled credential.

**CredentialAuthResult** was renamed to **PrincipalCredentialAuth**.

**CredentialWithPrincipal.Principal** was renamed to
**CredentialWithPrincipal.PrincipalName** (the field contains the Principal
username, not a Principal object).

**Audit result correction:**

The auth-failure result `credential.disabled` was corrected to
`principal.disabled`. This is an intentional Release 2 audit-schema correction.
`credential.not_found` and `credential.revoked` remain credential lifecycle
results. `principal.disabled` represents owner state.

**Authentication path preserved:**

- unknown token → `ErrCredentialNotFound`
- revoked Principal credential → `ErrCredentialRevoked`
- valid credential whose Principal is disabled → `ErrPrincipalDisabled`

**Compatibility**

HTTP routes, request/response JSON schema, SQLite schema, credential token
format, credential IDs, and the JSON field `principal` are unchanged.

### P2-2. generateToken collapses admin-token and Session-token semantics

**Status: RESOLVED**

**generateToken** was split into domain wrappers:

- **generateAdminToken** — admin-token domain, used during init and rotation;
- **generateSessionToken** — Session-token domain, used during Session
  creation.

Both independently represent a distinct authority and lifecycle at their call
sites.

**Shared mechanic preserved:**

Both wrappers delegate to the single low-level **generateOpaqueToken**, which
owns the existing dht_ encoding:
[token.go:9-29](../token.go#L9-L29).

**Domain call sites:**

- admin token during init:
  [config.go:789-805](../config.go#L789-L805);
- admin token during rotation:
  [app.go:87-100](../app.go#L87-L100);
- Session token:
  [session.go:166-177](../session.go#L166-L177).

**Compatibility**

- Existing `dht_ <64 lowercase hex>` external format unchanged.
- Admin init behavior, admin rotation behavior, and Session creation
  behavior unchanged.
- Token hashing, persisted values, and schema unchanged; no migration.
- Principal credential tokens (`dhc_`), Session IDs (`dhs_`), and credential
  IDs (`dhcr_`) are a separate domain and unchanged.

No token interfaces/classes, configurable prefix framework, or migration
layer were introduced.

### P2-3. Daemon lifecycle is named as HTTP serving

**Status: RESOLVED**

The daemon-lifecycle vocabulary replaced the HTTP-serving vocabulary for the
top-level command implementation:

- **runDaemon** — the docker-helper serve command implementation; owns the
  daemon lifecycle (logging, MAC confinement check, config preparation,
  daemon instance locking, admin-token loading, database open/init, expired
  Session cleanup, MAC reconciliation, stale runtime-dir cleanup, route
  registration, listener preparation, shutdown signal handling, operation
  admission shutdown, operation termination, HTTP graceful drain).
- **serveHTTPUntilShutdown** — the HTTP helper; owns listener serving and
  coordinated HTTP drain across all active listeners. A signal or Serve error
  initiates coordinated shutdown/drain.
- **InstanceLockPath** — the daemon instance lock path.
- **acquireDaemonInstanceLock** — acquires the daemon instance lock.
- **withDaemonInstanceLock** — runs the daemon callback with the instance lock
  held.

**Compatibility**

- The public CLI command remains `docker-helper serve`; the serve summary and
  man page now read "Start the docker-helper daemon".
- HTTP routes, socket/TCP behavior, startup/error behavior, shutdown timing,
  and signal behavior are unchanged.
- The on-disk config schema is unchanged; only the internal `Config.LockPath`
  field was renamed to `Config.InstanceLockPath`. The CLI `config show
  lock_path` field name is unchanged.
- No lifecycle reorderings. Operational log values `serve` / `serve_startup`
  and the "daemon listening"/"daemon stopped" messages are unchanged.

The SELinux fcontext manager's own `acquireLock` seam and the CLI config-change
lock are separate lock domains and were not renamed.

### P2-4. operation is overloaded between an async resource and a Docker action

**Status: RESOLVED**

**Operation** is reserved for the asynchronous build/run resource:

- `operation`, `operationSupervisor`, `operationStartResult`,
  `startOperationProcess`, operation state/result, `OperationLog...`,
  `/operations`, `operation_id`.

Docker actions/commands are not Operation resources:

- **newDockerCommand** — the generic Docker command factory (formerly
  `newOperationCmd`). Used by pull, registry login, daemon-side docker kill,
  build, and run. It constructs an `exec.Cmd`; it does not create an Operation
  resource. Pull, registry login, and docker kill create no Operation.
- **writeDockerActionRejected** — the pre-start rejection helper (formerly
  `writeOperationRejected`). Emits `<kind>.rejected` audit and the HTTP error
  response for rejected Docker-action requests (pull/build/run).

**Compatibility**

- `/operations`, `operation_id`, Operation JSON, and build/run/ pull/registry
  HTTP behavior are unchanged.
- Audit event names (`pull.rejected`, `build.rejected`, `run.rejected`,
  `pull.start/finish`, `registry.login.start/finish`, build/run created/finish)
  and operational log field names/values are unchanged.
- Docker argv, process lifecycle, and output/log retention are unchanged.
- Genuine asynchronous-Operation vocabulary (operationSupervisor, operation
  state, startOperationProcess, writeOperationCreated) is preserved where it
  belongs to the build/run resource.

### P2-5. loadConfig is a runtime-preparation pipeline

**Status: RESOLVED**

**loadConfig** was renamed to **loadAndPrepareRuntimeConfig**:
[config.go:306](../config.go#L306). It remains a single runtime-preparation
pipeline that reads and validates config JSON, resolves legacy/current config
inputs and defaults, parses durations/logging settings, resolves deployment
mode, validates system-mode trusted-CA source policy, resolves computed paths,
creates the runtime directory, builds the complete Config snapshot, and
prepares/materializes trusted-CA runtime state when enabled.

The name now states truthfully that the function has filesystem/runtime
preparation side effects rather than merely loading configuration.

**Compatibility and batch**

- Internal only: `loadConfig` -> `loadAndPrepareRuntimeConfig`. Config remains
  the runtime configuration snapshot type. Pure parsing/loading helpers
  (`validateRawConfig`, `resolveEffectiveConfig`, `parseSessionTTL`,
  `parseDurationPositive`, and the CA source-path validator) keep their
  accurate names.
- The pipeline intentionally remains one runtime-preparation pipeline in
  Release 2; this batch did not split or reorder filesystem/CA side effects.
  Runtime-directory creation and trusted-CA preparation remain inside
  `loadAndPrepareRuntimeConfig`.
- No external contract changes: config.json schema, CLI, HTTP, computed paths,
  filesystem layout/permissions, trusted-CA snapshot layout, and error
  semantics are unchanged. Reload, daemon startup, and config show behavior
  are unchanged.

### P2-6. Trusted-CA cryptographic terms are imprecise

**Status: RESOLVED**

The trusted-CA vocabulary now distinguishes the two distinct cryptographic
values precisely:

- **computeOpenSSLSubjectHash** — computes the OpenSSL-compatible X.509
  subject-name hash used for the `<subject-hash>.0` certificate-directory
  symlink. It is the OpenSSL subject hash (`openssl x509 -hash -noout`), not
  a generic hash.
- **trustedCASnapshotDir** — returns the content-addressed prepared CA
  snapshot directory `$runtime_dir/trusted-ca/<sha256-of-source-bytes>/`. The
  directory is selected by SHA-256 of the raw validated CA source bytes; it is
  a prepared CA snapshot, not a certificate fingerprint.
- **snapshotDir** — the local name for the trusted CA snapshot directory
  (replaces `fpDir`).

**Canonical vocabulary**

- `computeOpenSSLSubjectHash` — OpenSSL subject-hash computation
- `trustedCASnapshotDir` — content-addressed trusted CA snapshot directory
- `snapshotDir` — local name for the trusted CA snapshot directory

**Previous names (resolved)**

- ~~computeOpenSSLHash~~ → computeOpenSSLSubjectHash
- ~~fingerprintDir~~ → trustedCASnapshotDir
- ~~fpDir~~ → snapshotDir

**Compatibility**

Internal naming refactor only. The OpenSSL subject-hash algorithm (including
its SHA-1 use), the SHA-256 of raw CA source bytes used for snapshot-directory
naming, the `$runtime_dir/trusted-ca/<sha256>/` layout, the `ca.pem` name, the
`<subject-hash>.0 -> ca.pem` symlink, idempotency behavior, modes/permissions,
CA validation behavior, and externally visible errors are all unchanged.

### P2-7. Audit vocabulary hides the changed resource

**Status: RESOLVED**

The internal audit vocabulary now describes the actual resource and context
enrichment:

- **auditRecord.PrincipalAllowedRoot** — the internal field name for the
  canonical Principal allowed root affected by
  `principal.allowed_root_add` / `principal.allowed_root_remove`. The external
  JSON key remains **principal_path** for Release 2 compatibility; renaming
  the serialized field to `principal_allowed_root` is deferred to an explicit
  schema decision (dual-write/versioning).
- **writeRequestContextAudit** — the helper that enriches an auditRecord from
  the HTTP request context and writes it via writeAudit: it sets `request_id`
  from `requestIDFromContext` and fills `session_id` from
  `sessionIDFromContext` only when `record.SessionID` is not already
  explicitly populated.

**Canonical vocabulary**

- `PrincipalAllowedRoot` — internal auditRecord field (JSON: `principal_path`)
- `writeRequestContextAudit` — request-context audit enrichment

**Previous names (resolved)**

- ~~PrincipalPath~~ → PrincipalAllowedRoot
- ~~writeAuditWithRequestID~~ → writeRequestContextAudit

**Compatibility**

No external audit-schema or behavior change: the external JSON key
`principal_path`, the audit event names `principal.allowed_root_add` /
`principal.allowed_root_remove`, `request_id`, `session_id`, audit record
contents, and which paths emit audit records are all unchanged. Audit
locking/output/error handling, `writeAudit`, and request/session correlation
behavior are unchanged.

### P2-8. Shipping SELinux comments describe a nonexistent lifecycle

**Status: RESOLVED**

The stale comment areas in
[packaging/selinux/docker-helper.te](../packaging/selinux/docker-helper.te)
have been corrected to the accepted Session workspace MAC lifecycle. The
shipping SELinux source now matches the accepted lifecycle model:

- Global and Principal allowed roots are authorization policy only; neither
  adding nor removing an allowed root prepares or mutates SELinux MAC state.
  The retained `docker-helper config allowed-root add /opt` example is
  explicitly documented as authorization-only (no MAC state change).
- The concrete Session workspace is the MAC lifecycle unit.
  `sessionMACCoordinator` owns acquisition and release of workspace MAC
  bindings; the SELinux workspace MAC driver and its native fcontext
  machinery (`selinuxFcontextManager`, semanage fcontext + restorecon)
  provide the concrete SELinux coverage required for non-home Session
  workspaces.
- `/home` workspaces retain the normal supported `user_home_type` label path
  and are not described as prepared by init or an allowed-root command.

References to the nonexistent `docker-helper workspace-root add` command and
to init preparing a managed relabel boundary were removed from both the
header/model workflow comments and the comment above
`docker_helper_workspace_t`.

**Compatibility**

Comment-only, compatibility-free batch. No SELinux policy semantics, rules,
types, attributes, permissions, packaging behavior, CLI behavior, MAC
implementation, or tests changed. The type `docker_helper_workspace_t` and
all allow/type/attribute statements are unchanged.

### P2-9. Credential lifecycle is hidden in Principal files

**Status: RESOLVED**

Principal-credential HTTP/CLI declarations have moved out of Principal-owned
source files into dedicated Credential source files. This was declaration
movement only, with no behavior change:

- **credential_handler.go** now owns the Principal-credential HTTP
  declarations: `isErrCredentialNotFound`, `isErrCredentialExists`,
  `createCredentialRequest`, `credentialJSON`, `createCredentialResponse`,
  `listCredentialsResponse`, `revokeCredentialResponse`, `credentialToJSON`,
  and the `handleCreateCredential` / `handleListCredentials` /
  `handleRevokeCredential` handlers.
- **credential_cli.go** now owns the top-level Principal-credential CLI
  declarations: `credentialCommand` and its `create` / `list` / `revoke` /
  `install` subcommands.
- Principal lifecycle declarations remain in principal_handler.go and
  principal_cli.go.

**Compatibility**

Declaration/file-organization refactor only. No route, command, DTO schema,
auth, or persistence behavior changed:

- HTTP routes (`POST /principals/{username}/credentials`,
  `GET /principals/{username}/credentials`,
  `POST /credentials/{id}/revoke`) and handler names are unchanged.
- Public CLI (`docker-helper credential create|list|revoke|install`) is
  unchanged and remains a top-level command (not nested under principal).
- Request/response JSON fields, HTTP status codes, error codes/messages,
  audit events, admin authorization, credential pre-read before revoke,
  idempotent revoke, logging, command summaries, Usage strings, positional
  argument rules, flags/defaults, stdout/stderr text, exit codes,
  operator-client resolution, install behavior, hidden terminal input, and
  credential.token location/permissions are all unchanged.

No rename of Credential domain symbols, no Principal credential semantic
change, no change to credential DB/storage, and no N4 token-format resolution.

### P2-10. Generic test auth fixtures always select the admin-token branch

**Status: RESOLVED**

The generic-looking test authentication fixtures were renamed to explicitly
identify the admin-token authority branch they exercise:

- **newTestAppWithAuth** → **newTestAppWithAdminToken** — creates an
  admin-authorized test app with the admin token hash set.
- **withAuth** → **withAdminToken** — sets the `Authorization: Bearer
  <testAdminToken>` header.
- **newTestAppWithAuthAndStaging** → **newTestAppWithAdminTokenAndStaging** —
  builds the admin-authorized test app with a staging seam.

**Canonical vocabulary**

- `newTestAppWithAdminToken`
- `withAdminToken`
- `newTestAppWithAdminTokenAndStaging`

**Previous names (resolved)**

- ~~newTestAppWithAuth~~ → newTestAppWithAdminToken
- ~~withAuth~~ → withAdminToken
- ~~newTestAppWithAuthAndStaging~~ → newTestAppWithAdminTokenAndStaging

**Compatibility**

Test-only mechanical rename. Fixture semantics are exactly unchanged:
`newTestAppWithAdminToken` still calls `newTestApp(t)`, hashes
`testAdminToken` with SHA-256, assigns `app.AdminTokenHash`, and returns the
App; `withAdminToken` still sets `Authorization: Bearer <testAdminToken>`;
`newTestAppWithAdminTokenAndStaging` still creates the app via
`newTestAppWithAdminToken(t)` and calls `setupStagingSeam(t, app)`. No test
behavior, requests, assertions, setup order, tokens, headers, expected
statuses, audit expectations, or production source changed. `testAdminToken`,
production admin-token symbols, Principal credential fixtures, Session
capability fixtures, and authentication production code are unchanged.

### P2-11. Documentation uses admin credential as a synonym for admin token

**Status: RESOLVED**

Release 2 authentication terminology is now consistent across the current
documentation. The canonical Release 2 vocabulary is:

- **Admin token** — the concrete administrative bearer token. Never called
  “admin credential” or “administrative credential”.
- **Principal credential** — the current Release 2 Credential entity owned by
  a Principal. A Principal may have multiple named Principal credentials, and
  a Principal credential token is formatted `dhc_...`. Never called “Launcher
  credential”.
- **Session token** — the narrow Session capability for Docker actions.

“Launcher credential” is Release 3 terminology only; the future R3 Launcher
entity is not pulled backward into Release 2. A lowercase/generic “launcher”
remains where it genuinely describes an external caller/client/process.

Affected current documents corrected in this batch:

- **README.md** — the authentication-model introduction now reads “Three
  authentication classes” (Admin token and Session token are not Credential
  domain entities); the Principal-owned class is “Principal credential”;
  “admin credential” reads “admin token”; “launcher token” reads “Principal
  credential token”; all behavior and examples unchanged.
- **docs/architecture.md** — diagrams and lifecycle text now use “Principal
  credential” (`launcher credential (principal-scoped)` →
  `Principal credential (principal-scoped)`; `POST /sessions (launcher
  credential)` → `POST /sessions (Principal credential)`); the CLI summary,
  the Authentication section, and the security sections were updated
  (“Manage Principal credentials”, “Principal credential token”,
  “Principal-credential onboarding”). Generic descriptions of an external
  launcher/client remain unchanged.
- **docs/roadmap.md** — Release 1 / post-1.0 / Release 2 sections now use
  “Principal credential”, “Principal credential token”, “admin token”,
  “session token”, and “Principal-credential revocation”. The Release 3
  section describing the proposed delegated Launcher entity retains its
  legitimate Launcher terminology.
- **docs/release-2-plan.md** — the historical implementation sections use the
  final accepted R2 vocabulary: “Phase 2: Principal credentials”, “Workstream
  2: Principal credentials”, “Principal-credential onboarding”,
  “Principal-credential revocation”, “Principal credential token”, and
  “admin token”. Generic “launcher/client” actor wording remains.
- **packaging/README.release.md** — “admin credential” reads “admin token”.
- **AGENTS.md** — the secret-class list now reads “Principal credential
  tokens”.

**Compatibility**

Documentation-only terminology reconciliation. No API, CLI, schema, auth,
persistence, or behavior change; no Go files changed.

## 4. P3 findings

### P3-1. Historical spelling and suffixes remain in internal symbols

**Status: RESOLVED**

Internal identifiers were renamed mechanically to the canonical spelling:

- **findPrincipalIDByUsername** — canonical `Username` spelling (was
  findPrincipalIDByUserName); the `...InTx` variant is
  findPrincipalIDByUsernameInTx.
- **findPrincipalByUsername** — final control pass found and removed the
  remaining sibling of the already-corrected findPrincipalIDByUsername family
  (was findPrincipalByUserName).
- **parseAPIError** — normal Go acronym casing for API (was parseApiError).
- **operationStatus** — the `Ctx` suffix is historical; this is now the only
  variant and takes `context.Context` as part of its normal contract (was
  operationStatusCtx).
- **operationLogs** — same, the only variant taking `context.Context` (was
  operationLogsCtx).

All production and test call sites, comments, and test diagnostics were
updated consistently. This was an internal mechanical rename with no
compatibility or behavior change: no API/CLI behavior, HTTP routes, JSON,
error strings, audit events, persistence, or token behavior changed, and the
context parameters, request cancellation, HTTP paths, polling, log offsets,
and decoding are exactly as before.

### P3-2. Test call-record types live in the production mount adapter

**Status: RESOLVED**

openat2Args, openTreeArgs, and moveMountArgs are test-only call-record
declarations colocated with the mount syscall mock in mount_pin_linux_test.go,
immediately before `mockMountPinSyscalls`. Their fields and names are
unchanged.

Production mount_pin_seam.go now contains only the production resource and
syscall seam: `pinnedMount` and its `Cleanup`, the `mountPinSyscalls`
interface, and `unixStat` with its methods. The final control pass also
removed the stale test-navigation comment pointing into
mount_pin_linux_test.go; the seam file now describes only its actual
production resource/syscall seam. No production behavior or
compatibility surface changed; mount pinning, syscall invocation, flags, fd
allocation, and cleanup are exactly as before.

### P3-3. Shared test helpers are hidden in feature-specific files

**Status: RESOLVED**

Shared test helpers moved out of feature-specific test files into dedicated
test-only helper files:

- **setupTestLogging** and **setupTestLoggingDiscard** now live in
  `logging_test_helpers_test.go` (behavior unchanged).
- **readConfigJSON** now lives in `config_test_helpers_test.go` (behavior
  unchanged); existing callers in config/reload/allowed-root tests use the
  same helper name.
- The package-level generic **contains** helper was removed in favor of the
  standard-library `slices.Contains`; all test call sites now use
  `slices.Contains`.

No production behavior or compatibility surface changed. This is a
test-only organizational cleanup.

### P3-4. Historical filenames and planning documents no longer describe scope

**Status: RESOLVED**

- **multi_root_regression_test.go** was renamed to
  **allowed_root_policy_integration_test.go** (via `git mv`) without
  splitting, reorganizing, or changing test behavior. The filename now
  describes the file's actual scope: structured allowed-root CLI behavior,
  config persistence/transactions, rollback, daemon reload interaction, and
  global/Principal authorization ceilings. No test function was renamed.
- **docs/test-cleanup-plan.md** is now explicitly an archived historical
  snapshot: it declares itself non-authoritative for the current repository
  state and points to the project-wide review for current verified cleanup
  work. Stale file names, line numbers, and symbols inside that archived body
  (e.g., `workspace_root_test.go`) are intentionally not maintained.
- No production behavior or compatibility surface changed.

### P3-5. Legacy allowed_root appears in current-architecture comments

**Status: RESOLVED**

- **app.go** — `setConfig` now names the current configurable field
  `allowed_roots` instead of the legacy scalar `allowed_root`. `setConfig`
  behavior is unchanged.
- **packaging/apparmor/docker-helper** — the user AppArmor template no longer
  describes manual workspace MAC coverage as a configured `allowed_root`. The
  top instructions now describe AppArmor rules covering the workspace paths
  the daemon needs, note that these rules provide filesystem MAC coverage
  only while configured `allowed_roots` continue to govern authorization, and
  the inline comment reads “Workspace access (manually configured MAC
  coverage)”. `@@WORKSPACE_RULE@@` and the example rules are unchanged.
- Authorization `allowed_roots` and AppArmor MAC coverage remain distinct
  concepts.
- The legacy scalar `allowed_root` remains only where required: JSON legacy
  migration compatibility, `AllowedRootLegacy`, migration/rejection tests,
  compatibility/help text, and explicit historical evidence.
- No runtime behavior or compatibility surface changed.

### P3-6. re-reload describes history rather than responsibility

**Status: RESOLVED**

- **formatReReloadError** was renamed to **formatRollbackReloadError**
  (config_cli.go); its comment now describes a reload after rollback.
- The compensating-reload comment now reads “Reload after rollback to
  synchronize runtime with the restored file.”
- The operator diagnostic now reads `error: config rolled back; reload after
  rollback <suffix>` (e.g. `rejected: ...`, `transport error: ...`,
  `daemon not running`, `failed`). The initial reload error line is unchanged.
- Transaction ordering and failure semantics are unchanged: write new config,
  reload, on failure restore original bytes, reload again to match the
  restored file, and report the compensating-reload failure if it fails. Exit
  codes, rollback write behavior, reload attempt count, reloadResult /
  reloadOutcome values, and transport/rejection classification are unchanged.
- Current production comments, test names, and expected diagnostics use
  “reload after rollback”; tests were updated to match. No new result type or
  abstraction was introduced.

### P3-7. Pruning concurrency test originally overstated its assertion

**Status: RESOLVED**

The current test is **TestPruneCompletedConcurrency**. The arbitrary
sleep/open-ended loops and the `cleanerCount` proof were replaced with bounded
concurrent work synchronized by a start barrier:

- one known eligible completed operation (completed an hour ago) and one known
  running operation are admitted **before** the goroutines start;
- a spawner goroutine admits and completes a fixed number of operations while
  a pruner goroutine runs `pruneCompleted` the same fixed number of times,
  both started together on a shared barrier;
- after both finish, the test asserts the eligible completed operation was
  actually removed (`lookup(expired.ID) == nil`) and the running operation
  remains (`lookup(running.ID) != nil`);
- it does not assert incidental final supervisor counts, which legitimately
  vary with pruning/admission timing.

`go test -race` still exercises concurrent admit/completion/prune access, and
the test would now fail if `pruneCompleted` became a no-op. Production
operationSupervisor behavior was not changed.

### P3-8. Best-effort cancel comment contradicts synchronous behavior

**Status: RESOLVED**

- `cancelOperation` is now explicitly documented as a bounded synchronous
  request: it sends `POST /operations/{id}/cancel` and waits for the daemon
  response or `cancelOperationTimeout`.
- "best-effort" now describes the cancellation guarantee/failure semantics
  (failure is reported to the caller; no unconditional guarantee the remote
  operation was cancelled), not asynchronous execution.
- The signal path is documented as stopping polling, performing an at-most-once
  bounded synchronous best-effort cancel, waiting for the polling goroutine to
  exit, then returning the signal exit.
- `cancelOperationTimeout` (12s), signal handling, HTTP behavior, and operation
  cancellation lifecycle are unchanged. Comment-only cleanup; no executable
  statement changed.

> Final control pass: after all original P3 findings were closed, three
> post-resolution residue corrections were applied — the findPrincipalByUsername
> sibling rename (P3-1), removal of the stale test-navigation comment in
> mount_pin_seam.go (P3-2), and the P3-7 heading correction. These were residue
> corrections and did not reopen any findings.

## 5. Keep-as-is decisions

The following suspicious-looking vocabulary is semantically correct or too
costly to change for no architectural benefit:

- DeploymentMode, ModeUser, and ModeSystem describe deployment rather than
  transport:
  [config.go:23-29](../config.go#L23-L29).
- agentClient and resolveOperatorClient represent real Session-capability and
  management roles:
  [agent_cli.go:42-53](../agent_cli.go#L42-L53),
  [operator_client.go:21-44](../operator_client.go#L21-L44).
- Public and persisted Principal, Credential, Session, workspace, and
  allowed_roots vocabulary remains the Release 2 contract.
- App is a valid application composition root in package main:
  [app.go:21-43](../app.go#L21-L43).
- /operations and operation_id remain correct for asynchronous build/run
  resources; only the broader Docker-action usage should change.
- stagedBuildContext and pinnedMount correctly name helper-owned resources with
  cleanup lifecycles.
- registry is correct Docker-domain vocabulary.
- StateDir and RuntimeDir correctly distinguish persistent and ephemeral state.
- sessionMACCoordinator, workspaceMACDriver, appArmorProfileManager, and
  selinuxFcontextManager match the accepted MAC naming grammar.
- pathWithin and pathStrictlyWithin are genuinely generic canonical containment
  primitives.

## 6. Compatibility and migration surfaces

| Surface | Decision |
| --- | --- |
| Internal Go symbols, files, and tests | Rename mechanically without a compatibility layer |
| CLI commands and flags | Preserve; help and descriptions may change |
| HTTP routes and JSON principal/workspace/allowed_roots | Preserve for Release 2 |
| Unauthorized HTTP messages | Observable contract; update tests and release notes |
| Audit event/result/field names | Treat as external schema; dual-write or version migration |
| SQLite tables and columns | Do not rename for code-vocabulary cleanup |
| Config allowed_roots | Canonical; allowed_root remains migration input only |
| Token prefixes dht_/dhc_/dhcr_ | Preserve; use internal domain wrappers |
| admin.token, credential.token, session-token environment | Preserve |
| Public AppArmor CLI and persisted backend identity | Preserve |

## 7. Suggested narrow refactor batches

1. Release-safety batch: fix bulk Session deletion/MAC coordination and the two
   unsynchronized Config reads.
2. Authentication vocabulary: Session capability versus Session control,
   response helpers, and authority-specific test names.
3. Principal policy/lifecycle: effective allowed-root scope, explicit enabled
   transition result, and Principal-disabled error.
4. Mount identity: original source versus pinned bind source and syscall-adapter
   naming.
5. Operation ownership: operationSupervisor and Docker-action command factory.
6. Daemon/config/CA: daemon lifecycle, instance lock, runtime config loader,
   and CA subject/content-digest terms.
7. Audit vocabulary: internal fields first while retaining current JSON tags.
8. Credential ownership and test fixtures: declaration moves and admin-specific
   fixture names.
9. Comment/test residue: SELinux policy comments, admin-token terminology,
   legacy scalar comments, rollback reload, and stale test/doc names.

Each batch can remain mechanical and reviewable. No package split or
architecture rewrite is required.

## 8. Non-naming observations

### N1. Bulk Session deletion bypasses the MAC lifecycle owner

**Original finding / baseline evidence**

Normal Session deletion calls MACCoordinator.ReleaseSessionBinding:
[session.go:324-363](../session.go#L324-L363),
[session.go:366-415](../session.go#L366-L415).

Principal disable and delete instead remove Session rows directly and handlers
clean only runtime directories:
[principal.go:265-298](../principal.go#L265-L298),
[principal.go:432-489](../principal.go#L432-L489),
[principal_handler.go:805-814](../principal_handler.go#L805-L814).

The coordinator therefore retains stale sessionBindings and
boundaryConsumerCounts, and a helper-owned boundary may remain until daemon
restart:
[mac_lifecycle.go:145-167](../mac_lifecycle.go#L145-L167).

The direct database implementation of session cleanup can cause the same
in-memory divergence when invoked while the daemon is running:
[database.go:153-166](../database.go#L153-L166),
[session_cli.go:208-260](../session_cli.go#L208-L260).

This is a release-significant lifecycle defect. Bulk deletion should return
the deleted IDs to an App-level lifecycle owner that releases every coordinator
binding while preserving operation leases.

**Status: RESOLVED**

**Resolution**

- Principal disable/delete lifecycle now returns revoked/deleted Session IDs
  (`RevokedSessionIDs` on disable, deleted Session IDs on delete).
- The App-level lifecycle owner releases every corresponding MAC Session
  binding after the DB commit
  ([app.go:208-239](../app.go#L208-L239)).
- Active operation workspace-use leases continue to preserve the required MAC
  coverage until the operation releases its lease.
- Standalone/offline session cleanup remains daemon-lock protected where
  applicable.

### N2. Principal handlers can race with Config reload

**Original finding / baseline evidence**

getConfig and setConfig protect App.Config with the App mutex:
[app.go:61-84](../app.go#L61-L84).

Principal disable and delete read a.Config.RuntimeDir directly:
[principal_handler.go:246-255](../principal_handler.go#L246-L255),
[principal_handler.go:805-813](../principal_handler.go#L805-L813).

Use a Config snapshot before cleanup and add a race test covering concurrent
reload with Principal disable/delete.

**Status: RESOLVED**

**Resolution**

- Principal handlers now take a Config snapshot through the synchronized
  config accessor (`getConfig`) before runtime-dir cleanup.
- No Config lock is held over filesystem I/O.
- The previous reload race is removed.

### N3. Session-control database auth failure loses request correlation

**Status: RESOLVED**

The Session-control credential database-error path now routes through the
common auth-failure owner instead of writing an `auth.session` event directly:

- **sessions.go** — `authenticateSessionControlRequest` writes
  `writeAuthFailure(ctx, r, "credential.database_error")`, producing an
  `auth.failure` audit record that retains `method` and `path` request
  correlation.
- The audit result is `credential.database_error`, consistent with the other
  Principal-credential auth results (`credential.not_found`,
  `credential.revoked`, `principal.disabled`) and with the Session-capability
  `session.database_error` owner.
- HTTP 500 with `code = "internal_error"` / `message = "internal server error"`
  is unchanged; the operational log line “session control auth database error”
  with `operation = "session_auth"` remains, and the internal error appears
  only in the operational log, never in the audit record.

**Compatibility**

No API route, auth success semantics, token format, operational logging
semantics, or unrelated audit event/result changed.

### N4. Principal-credential token format has two owners

**Status: RESOLVED**

credential.go is now the single internal owner of the Principal-credential
token format. The canonical constants live in
[credential.go:36-41](../credential.go#L36-L41):

    credentialTokenPrefix       = "dhc_"
    credentialTokenEntropyBytes = 32
    credentialTokenHexLen       = credentialTokenEntropyBytes * 2
    credentialTokenTotalLen     = len(credentialTokenPrefix) + credentialTokenHexLen

- **generateCredentialToken** allocates `credentialTokenEntropyBytes`, reads
  cryptographic randomness exactly as before, and returns
  `credentialTokenPrefix + lowercase hex encoding`.
- **validateCredentialToken** in credential_install.go now consumes the same
  canonical constants (exact total length, exact prefix, lowercase hex only);
  the duplicate `credential_install.go` format constants were removed.
- Generator and install validator therefore share one
  prefix/entropy/derived-length definition. Tests assert the generated token
  has the canonical prefix, total length, encoded suffix length, and is
  accepted by the validator.

The external Principal-credential token format is unchanged:
`dhc_` + 64 lowercase hex characters, 68 total, 32 random bytes / 256 bits
entropy. Error behavior and diagnostics are unchanged.

### N5. Operation cancellation branches on error strings

**Status: RESOLVED**

Cancellation classification now uses typed sentinel errors instead of
formatted error strings:

- **ErrOperationNotFound** — returned by operationSupervisor.cancel for an
  unknown operation ID.
- **ErrOperationAlreadyTerminal** — returned by operationSupervisor.cancel
  when the operation is already terminal.

The HTTP handler classifies with `errors.Is`
[build.go:407-423](../build.go#L407-L423); the legacy `"not_found"` /
`"already_terminal"` string coupling was removed.

**Compatibility**

- Missing operation: 404, code `operation_not_found`, message "operation not
  found".
- Already-terminal race: unchanged idempotent success response.
- Successful cancellation and unexpected internal errors (500): unchanged.
- Cancellation synchronization and shutdown termination behavior unchanged.

## 9. Independent follow-up review

A later independent review, run after the original project-wide audit, found
and fixed the following additional issues. They are recorded here so this
ledger stays internally coherent.

### A. P1 user-mode restart regression — RESOLVED

Fixed by `374785a035e96dd3976a9f8e84ca209835328ac9`.

The original audit baseline predated this defect. In user mode:

- `newWorkspaceMACDriver()` returns nil;
- startup nevertheless constructed a `sessionMACCoordinator` with that nil
  driver;
- persisted Session MAC bindings were not reconstructed on restart;
- old live Sessions failed `/run` and `/build` after restart with
  "no MAC binding for session".

Resolution:

- no active MAC driver => `App.MACCoordinator` remains nil;
- reconciliation only occurs when a coordinator/driver exists;
- a regression test covers persisted Session use through `/run` and `/build`
  after a simulated user-mode restart.

This was a functional release-safety defect discovered after the original
naming audit.

### B. P2 stringly-typed backend identity — RESOLVED

Fixed by `9dc5eb5708652c2c52faa8cb98d12117c078d7ce`.

- `workspaceMACDriver.backendType() string` created a duplicate string
  representation of the MAC backend despite the existing `LSMBackend` domain
  type;
- backend identity now uses `LSMBackend` end-to-end through the MAC lifecycle
  layer;
- the AppArmor/SELinux drivers return `LSMAppArmor` / `LSMSELinux`;
- the SQLite schema and persisted backend values remain unchanged.

### C. P3 shipping Release 2 terminology — RESOLVED

Resolved in the commit that maintains this ledger:

- the man page no longer describes a Release 3 "launcher credential";
- the AppArmor curl fragment no longer says "admin credential";
- current Release 2 / shipping documentation uses the canonical R2 vocabulary
  (Session token, Principal credential, admin token).

### Observable contract changes in refactor commits

Some commits categorized primarily as refactors nevertheless included
intentional observable text changes:

- `ac101e1b277b92efa78376e54e1aadb0e527fc9f` changed the Session-capability
  HTTP 401 message from the incorrect session-management wording to
  "Session authentication required.";
- `7938883e3655b21b9322ab8e38c87b326faa5701` changed CLI stderr terminology
  from "re-reload" to "reload after rollback".

These changes were semantically justified, but HTTP message text and CLI
diagnostic text are observable contract surfaces under project rules.

Process lesson: future commits that intentionally change such observable
surfaces should be classified and reviewed explicitly as contract/fix changes,
even when accompanied by internal refactoring. These historical changes are
not reverted.
