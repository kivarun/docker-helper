# Project-wide naming and architecture vocabulary review

Date: 2026-08-24

Baseline: origin/main at ab48afdd8167009b3d1323ea17caef001b4d654b.

Status: analysis only. This document records findings and narrow refactor
boundaries; it does not change the current Release 2 contract.

The MAC/workspace-path reference area was not re-audited in depth. It is used
as the quality model defined in
[naming-entropy-audit-2026-08-24.md](naming-entropy-audit-2026-08-24.md).
The only MAC finding below is a direct contradiction between that accepted
model and a shipping policy source.

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

**Current names and evidence**

- **intersectRoots(globalRoots, principalRoots)** computes the effective
  authorization scope:
  [session.go:55-89](../session.go#L55-L89).
- The result is stored in the unqualified
  **sessionCreatePolicy.AllowedRoots**:
  [session.go:116-123](../session.go#L116-L123),
  [sessions.go:146-155](../sessions.go#L146-L155).
- **isUnderAnyRoot**, **addAllowedRoot**, **removeAllowedRoot**, and
  **validateAllowedRootForAdd** are Principal-policy operations constrained by
  the global ceiling, but their names do not identify either scope:
  [principal.go:59-79](../principal.go#L59-L79),
  [principal.go:307-395](../principal.go#L307-L395).

**Actual semantic responsibility**

The authorization hierarchy is:

global allowed-root scope → Principal allowed-root scope → effective
Session-creation scope → concrete workspace.

**Why the vocabulary is dangerous**

The unqualified names make it plausible to pass raw Principal roots to Session
creation instead of their intersection with the global ceiling. That is the
same class of failure as the previously discovered global-ceiling bypass.

**Preferred canonical vocabulary**

- intersectAllowedRootScopes;
- sessionCreationScope.EffectiveAllowedRoots;
- isWithinAnyAllowedRoot;
- addPrincipalAllowedRoot;
- removePrincipalAllowedRoot;
- globalAllowedRoots for the global input.

**Compatibility and narrow batch**

Keep public allowed_roots JSON, allowed-root CLI vocabulary, and
principal_allowed_roots persistence. Rename only internal symbols and tests,
and make every policy test name identify both input scopes and the effective
result.

### P1-3. operationRegistry is the operation lifecycle supervisor

**Current names and evidence**

The type owns more than lookup/storage:

- admission and the shutdown gate through **tryCreate**;
- retention pruning through **cleanup**;
- shutdown transition through **setShuttingDown**;
- cancellation and process/container cleanup through **terminateOne**,
  **terminateAll**, and **terminateAllOps**.

Evidence:
[operation.go:138-230](../operation.go#L138-L230),
[operation.go:232-415](../operation.go#L232-L415),
[main.go:333-346](../main.go#L333-L346).

**Actual semantic responsibility**

It is the in-memory supervisor and lifecycle owner for asynchronous build/run
operations.

**Why the vocabulary is dangerous**

Registry suggests a passive map and encourages lifecycle changes to be
implemented beside it. The current type owns admission, retention, shutdown,
cancellation, and force cleanup.

**Preferred canonical vocabulary**

- operationSupervisor;
- admit;
- lookup;
- pruneCompleted;
- beginShutdown;
- cancel;
- terminateForShutdown.

**Compatibility and narrow batch**

All affected names are internal. Perform one mechanical rename across code and
tests without changing the termination algorithm.

### P1-4. Original and pinned mount paths share HostPath

**Current names and evidence**

- **resolvedMount.HostPath** is the canonical original source within the
  workspace:
  [run.go:166-233](../run.go#L166-L233).
- **pinnedMount.HostPath** is the helper-owned stable destination Docker must
  bind:
  [mount_pin_seam.go:12-19](../mount_pin_seam.go#L12-L19).
- Docker argv construction switches between those same-named fields:
  [run.go:596-606](../run.go#L596-L606).

**Actual semantic responsibility**

The first value is a validated source pathname. The second is an
inode-preserving bind source that protects system mode against pathname
replacement.

**Why the vocabulary is dangerous**

Selecting the original HostPath where the pinned path is required bypasses a
security property while remaining type-correct and visually plausible.

**Preferred canonical vocabulary**

- resolvedMount.SourcePath;
- pinnedMount.PinnedPath or BindSourcePath;
- dockerBindSource for the final local value;
- pinWorkspaceMountSource;
- mountPinSyscalls instead of mountSeam.

**Compatibility and narrow batch**

Internal only. Use a mechanical field/function rename and update the existing
mount-policy tests; do not change mount behavior.

### P1-5. updatePrincipalEnabled hides Session capability revocation

**Current names and evidence**

**updatePrincipalEnabled** appears to update a boolean, but disabling a
Principal transactionally queries and deletes all of its Sessions. Nil and an
empty slice implicitly encode the Changed state:
[principal.go:231-304](../principal.go#L231-L304).

The handler treats the returned IDs as a runtime-cleanup plan:
[principal_handler.go:220-277](../principal_handler.go#L220-L277).

**Actual semantic responsibility**

It performs a Principal enabled-state transition that also revokes and deletes
Session capabilities.

**Why the vocabulary is dangerous**

A caller can reasonably treat it as a simple field mutation and omit the
Session, runtime, audit, or MAC lifecycle consequences.

**Preferred canonical vocabulary**

Use **applyPrincipalEnabledChange** with an explicit result containing:

- Changed;
- RevokedSessionIDs.

**Compatibility and narrow batch**

Internal only. Rename the function and replace nil/empty-slice signaling with
an explicit result type without changing the HTTP or database contract.

## 3. P2 findings

### P2-1. Principal disabled is reported as credential disabled

**Current names and evidence**

**ErrCredentialDisabled** is returned when p.enabled is zero; there is no
credential-disabled state:
[credential.go:214-260](../credential.go#L214-L260).

Session-control audit then emits credential.disabled:
[sessions.go:109-116](../sessions.go#L109-L116).

**CredentialWithPrincipal.Principal** actually contains the Principal name:
[credential.go:26-30](../credential.go#L26-L30).

**Actual responsibility**

A Principal credential may be unknown or revoked. Its owning Principal may be
disabled independently of the credential lifecycle.

**Preferred vocabulary**

- ErrPrincipalDisabled;
- principal.disabled in audit;
- CredentialWithPrincipal.PrincipalName;
- PrincipalCredentialAuth for the internal authenticated-authority result.

**Compatibility and batch**

Rename internal errors and fields first. Treat audit result changes as an
external schema migration. Preserve JSON field principal.

### P2-2. generateToken collapses admin-token and Session-token semantics

**Current names and evidence**

One **generateToken** with the dht_ format creates:

- admin tokens during init:
  [config.go:789-805](../config.go#L789-L805);
- admin tokens during rotation:
  [app.go:87-100](../app.go#L87-L100);
- Session tokens:
  [session.go:166-177](../session.go#L166-L177).

The shared generator is defined at
[token.go:9-18](../token.go#L9-L18).

**Actual responsibility**

Admin and Session tokens use the same current encoding but have different
authority and lifecycle.

**Why misleading**

Shared implementation does not make them one domain concept. A generic
call-site hides which capability is being created.

**Preferred vocabulary**

Use generateAdminToken and generateSessionToken wrappers over a shared
generateOpaqueToken mechanic.

**Compatibility and batch**

Keep the dht_ external format for Release 2. Add wrappers, change call-sites,
and split generator tests; no token migration is required.

### P2-3. Daemon lifecycle is named as HTTP serving

**Current names and evidence**

**runServe** owns logging, runtime config preparation, instance lock, database,
migrations, MAC reconciliation, listeners, operation shutdown, and HTTP drain:
[main.go:216-375](../main.go#L216-L375).

**serveWithShutdownMulti** only coordinates HTTP serving/drain; Multi describes
listener cardinality:
[main.go:97-108](../main.go#L97-L108).

The CLI summary says “Start the HTTP server”:
[cli.go:369-383](../cli.go#L369-L383).

**Actual responsibility**

runServe is the daemon lifecycle owner. serveWithShutdownMulti is the HTTP
transport shutdown coordinator.

**Preferred vocabulary**

- runDaemon;
- serveHTTPUntilShutdown;
- InstanceLockPath;
- acquireDaemonInstanceLock;
- withDaemonInstanceLock;
- CLI summary “Start the docker-helper daemon”.

**Compatibility and batch**

Keep the public serve command. Rename internal symbols and update help/man
wording in one daemon-lifecycle batch.

### P2-4. operation is overloaded between an async resource and a Docker action

**Current names and evidence**

The public Operation resource exists for asynchronous build/run. However
**newOperationCmd** is used by pull, registry login, Docker kill, build, and
run:
[run.go:679-687](../run.go#L679-L687),
[registry.go:65-85](../registry.go#L65-L85).

**writeOperationRejected** covers pull/build/run, although pull creates no
Operation resource:
[logging.go:216-237](../logging.go#L216-L237).

**Actual responsibility**

There are two concepts:

- a Docker action or Docker command;
- an asynchronous build/run Operation entity.

**Preferred vocabulary**

Reserve Operation for the asynchronous resource. Use Docker action for the
umbrella and newDockerCommand for process creation.

**Compatibility and batch**

Keep /operations, operation_id, and existing external audit event names.
Rename internal umbrella helpers and comments only.

### P2-5. loadConfig is a runtime-preparation pipeline

**Current names and evidence**

**loadConfig** reads and validates JSON, resolves defaults, computes mode and
paths, creates the runtime directory, and materializes a trusted-CA snapshot:
[config.go:306-339](../config.go#L306-L339),
[config.go:368-437](../config.go#L368-L437).

**Actual responsibility**

It prepares a complete runtime configuration snapshot with filesystem side
effects.

**Preferred vocabulary**

loadRuntimeConfig or loadAndPrepareRuntimeConfig. Config itself can remain
unchanged.

**Compatibility and batch**

Internal only. Rename the loader and comments without splitting the pipeline
or changing reload behavior.

### P2-6. Trusted-CA cryptographic terms are imprecise

**Current names and evidence**

- **computeOpenSSLHash** computes the OpenSSL subject-name hash.
- **fingerprintDir** hashes raw source bytes rather than a certificate
  fingerprint.

Evidence:
[ca.go:468-503](../ca.go#L468-L503).

**Actual responsibility**

The first value indexes an OpenSSL certificate directory by canonical subject.
The second selects a content-addressed prepared CA snapshot.

**Preferred vocabulary**

- computeOpenSSLSubjectHash;
- trustedCASnapshotDir or caContentDigestDir;
- snapshotDir rather than fpDir.

**Compatibility and batch**

Internal only. Keep the current directory layout; rename symbols, locals, and
tests.

### P2-7. Audit vocabulary hides the changed resource

**Current names and evidence**

**auditRecord.PrincipalPath** with JSON key principal_path is used only for a
Principal allowed-root change:
[audit.go:23-29](../audit.go#L23-L29),
[principal_handler.go:354-370](../principal_handler.go#L354-L370).

**writeAuditWithRequestID** also injects Session ID from context:
[logging.go:206-213](../logging.go#L206-L213).

**Actual responsibility**

The field is the Principal allowed root affected by the event. The helper
writes context-enriched audit.

**Preferred vocabulary**

- internal PrincipalAllowedRoot;
- writeContextAudit or writeRequestContextAudit;
- external principal_allowed_root only after an explicit schema decision.

**Compatibility and batch**

The Go field can be renamed while retaining json:"principal_path". Any JSON
key migration requires dual-write or versioning.

### P2-8. Shipping SELinux comments describe a nonexistent lifecycle

**Current comment and evidence**

The policy says non-home boundaries are prepared by
docker-helper workspace-root add or docker-helper init:
[packaging/selinux/docker-helper.te:3-16](../packaging/selinux/docker-helper.te#L3-L16),
[packaging/selinux/docker-helper.te:106-114](../packaging/selinux/docker-helper.te#L106-L114).

**Actual responsibility**

Concrete Session workspace coverage is created and released through
sessionMACCoordinator. Global and Principal allowed roots are authorization
ceilings and do not own MAC state. There is no public workspace-root command.

**Why included despite MAC scope exclusion**

This shipping security source directly contradicts the accepted MAC reference
model and can misdirect policy maintenance.

**Preferred vocabulary and batch**

Replace the stale lifecycle comments with Session binding/coordinator
vocabulary. This is a comment-only, compatibility-free batch and should be
completed before release.

### P2-9. Credential lifecycle is hidden in Principal files

**Current organization and evidence**

principal_handler.go contains all credential DTOs and handlers, including the
top-level credential revoke endpoint:
[principal_handler.go:492-537](../principal_handler.go#L492-L537).

principal_cli.go contains the independent top-level credential command:
[principal_cli.go:14-36](../principal_cli.go#L14-L36).

**Actual responsibility**

Credential is a distinct revocable authentication-key lifecycle nested under a
Principal for creation/listing but independently addressed for revocation and
installation.

**Preferred vocabulary**

Move the existing declarations to credential_handler.go and credential_cli.go.

**Compatibility and batch**

Do not consolidate DTOs or alter routes/commands. Perform only declaration
moves and filename updates.

### P2-10. Generic test auth fixtures always select the admin-token branch

**Current names and evidence**

**newTestAppWithAuth** and **withAuth** install the test admin token:
[test_helpers_test.go:255-267](../test_helpers_test.go#L255-L267).

**newTestAppWithAuthAndStaging** builds on the same fixture:
[build_test_helpers_test.go:21-26](../build_test_helpers_test.go#L21-L26).

**Actual responsibility**

These are admin-authorized fixtures, not generic authentication fixtures.

**Why misleading**

In the three-level authority model, a test can accidentally exercise admin
behavior while its name appears authority-neutral.

**Preferred vocabulary**

- newTestAppWithAdminToken;
- withAdminToken;
- newTestAppWithAdminTokenAndStaging.

**Compatibility and batch**

Test-only mechanical rename.

### P2-11. Documentation uses admin credential as a synonym for admin token

**Current vocabulary and evidence**

README incorrectly labels the current Release 2 Principal credential as a
Launcher credential while defining the three authentication classes:
[README.md:51-61](../README.md#L51-L61).

Later documentation uses “admin credential” or “administrative credential”:
[README.md:1077-1078](../README.md#L1077-L1078),
[release-2-plan.md:162-175](release-2-plan.md#L162-L175).

**Actual responsibility**

Credential is a concrete Principal-owned entity in the Release 2 model; the
canonical term is Principal credential. Launcher credential is reserved for
the proposed Release 3 delegation model. The root administrative capability
is the admin token.

**Preferred vocabulary and batch**

Use Principal credential for the Release 2 entity and admin token for the root
capability consistently in README, release plan, man pages, and packaging
comments. This is terminology-only and has no compatibility cost.

## 4. P3 findings

### P3-1. Historical spelling and suffixes remain in internal symbols

Evidence:

- findPrincipalIDByUserName versus the canonical Username spelling:
  [principal.go:101-102](../principal.go#L101-L102);
- parseApiError versus API acronym casing:
  [client.go:72-76](../client.go#L72-L76);
- operationStatusCtx and operationLogsCtx are described as context-aware
  variants although no non-context variants remain:
  [client.go:293-310](../client.go#L293-L310),
  [client.go:353-370](../client.go#L353-L370).

Preferred vocabulary: ...Username, parseAPIError, operationStatus, and
operationLogs. Internal mechanical batch only.

### P3-2. Test call-record types live in the production mount adapter

openat2Args, openTreeArgs, and moveMountArgs are described as records of calls
and exist for mock assertions, but are declared in production
mount_pin_seam.go:
[mount_pin_seam.go:38-61](../mount_pin_seam.go#L38-L61).

Move call-record types to a test file. Keep only the production resource and
syscall adapter in production code. No compatibility surface.

### P3-3. Shared test helpers are hidden in feature-specific files

setupTestLogging is defined in audit_test.go but is used across many unrelated
test files:
[audit_test.go:705-722](../audit_test.go#L705-L722).

readConfigJSON is defined in config_cli_test.go but is also used by reload and
allowed-root tests:
[config_cli_test.go:69-80](../config_cli_test.go#L69-L80).

The local contains helper is also shared by completion/config tests:
[multi_root_regression_test.go:1295-1305](../multi_root_regression_test.go#L1295-L1305).

Use logging_test_helpers.go and config_test_helpers.go, and replace contains
with slices.Contains. Test-only batch.

### P3-4. Historical filenames and planning documents no longer describe scope

multi_root_regression_test.go includes config transactions, rollback, reload,
and authorization-ceiling behavior rather than only multi-root regression:
[multi_root_regression_test.go:15-29](../multi_root_regression_test.go#L15-L29).

test-cleanup-plan.md references the nonexistent workspace_root_test.go and
mixes unresolved work with completed phases:
[test-cleanup-plan.md:21-34](test-cleanup-plan.md#L21-L34).

Rename the test file to allowed_root_policy_integration_test.go without
splitting it in this batch. Mark the cleanup plan as a historical snapshot or
reduce it to the remaining verified work.

### P3-5. Legacy allowed_root appears in current-architecture comments

setConfig lists allowed_root as the current configurable field:
[app.go:69-74](../app.go#L69-L74).

The AppArmor template says “configured allowed_root”:
[packaging/apparmor/docker-helper:57-61](../packaging/apparmor/docker-helper#L57-L61).

Use allowed_roots or global allowed-root scope. Keep scalar allowed_root only
in migration-specific code and documentation.

### P3-6. re-reload describes history rather than responsibility

formatReReloadError and the output phrase “re-reload” mean a compensating
reload after restoring the previous config:
[config_cli.go:1030-1043](../config_cli.go#L1030-L1043),
[config_cli.go:1193-1208](../config_cli.go#L1193-L1208).

Use formatRollbackReloadError and “reload after rollback”. This affects only
internal names and error wording.

### P3-7. TestCleanupConcurrency overstates its assertion

The test creates and prunes operations concurrently, but its only final proof
is that the cleaner goroutine executed:
[operation_cleanup_test.go:105-158](../operation_cleanup_test.go#L105-L158).

Either rename it to TestOperationRegistryCleanupNoRace for the current
assertion or prove that cleanup actually removed eligible operations.

### P3-8. Best-effort cancel comment contradicts synchronous behavior

cancelOperation says the caller should not block, but performs a synchronous
request with a timeout of up to twelve seconds:
[client.go:313-350](../client.go#L313-L350).

The signal path invokes it synchronously before returning:
[agent_cli.go:128-173](../agent_cli.go#L128-L173).

The current semantic name is bounded synchronous cancel. Correct the comment;
making cancellation asynchronous would be a separate behavioral decision.

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

### N2. Principal handlers can race with Config reload

getConfig and setConfig protect App.Config with the App mutex:
[app.go:61-84](../app.go#L61-L84).

Principal disable and delete read a.Config.RuntimeDir directly:
[principal_handler.go:246-255](../principal_handler.go#L246-L255),
[principal_handler.go:805-813](../principal_handler.go#L805-L813).

Use a Config snapshot before cleanup and add a race test covering concurrent
reload with Principal disable/delete.

### N3. Session-control database auth failure loses request correlation

The database-error path writes auth.session directly without method and path:
[sessions.go:93-105](../sessions.go#L93-L105).

The normal auth-failure owner includes those fields:
[response.go:116-122](../response.go#L116-L122).

Route the database failure through the common auth audit owner.

### N4. Principal-credential token format has two owners

generateCredentialToken contains a literal dhc_ prefix and a 32-byte length:
[credential.go:32-39](../credential.go#L32-L39).

credential_install.go separately owns prefix and encoded-length constants:
[credential_install.go:15-17](../credential_install.go#L15-L17).

Use one internal credential-token format definition without changing the
external token format.

### N5. Operation cancellation branches on error strings

terminateOne returns newly formatted not_found and already_terminal strings:
[operation.go:251-270](../operation.go#L251-L270).

The handler branches on err.Error():
[build.go:406-423](../build.go#L406-L423).

Use sentinel errors or a typed cancellation result. The HTTP contract does not
need to change.
