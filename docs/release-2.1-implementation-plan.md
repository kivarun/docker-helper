# Release 2.1 Launcher Delegation — Binding Implementation Plan

## Status / exact baseline

This document freezes the binding implementation contract for **Release 2.1
Launcher Delegation** against the *actual* current code. It is the reviewed
gate between the design concept and the Stage 1.1 production implementation. It
maps the agreed concept to concrete owners, symbols, tables, and migration
steps. It is documentation only; no production Go, tests, workflows, scripts,
packaging, README, or man pages are changed by this stage.

- Repository: `kivarun/docker-helper`
- Branch: `main` (default branch is `release/2.0`; this work is on `main` only)
- Baseline commit at task creation: `b5cc231e84e33924cd317505ce50ad38a13440c3`
- Design input (conceptual rationale): [`release-2.1-launcher-delegation.md`](release-2.1-launcher-delegation.md)

This plan is the binding contract. The concept document remains the rationale
and is not duplicated here; readers needing the *why* should start there.

Release 3 is **not** implementation scope here. It is a downstream consumer and
a constraint: Release 2.1 must land a final Launcher/Session ownership model
that Release 3 can consume without introducing a second owner. The agreed
Release 3 contracts are read as constraints and are referenced throughout:
[`release-3-scope.md`](release-3-scope.md),
[`release-3-decomposition.md`](release-3-decomposition.md),
[`release-3-operation-model.md`](release-3-operation-model.md),
[`release-3-managed-container-domain.md`](release-3-managed-container-domain.md),
[`release-3-vocabulary-and-implementation-map.md`](release-3-vocabulary-and-implementation-map.md),
and [`release-3-d0-execution-plan.md`](release-3-d0-execution-plan.md).

## Binding decisions

The following are frozen. They are contracts; later stages implement them, they
do not re-litigate them.

### Domain model

```text
Principal
    ├── Principal Credential (0..N)
    └── Launcher
            ├── Launcher Credential (0..1)
            └── Session
                    └── current R2 runtime / Operation resources
```

- A **Credential is a key, never an owner.**
- A **Session has exactly one Launcher owner.**
- Principal identity for a Session is **derived** through
  `Session -> Launcher -> Principal`. It is display/provenance data, not a
  second ownership column.
- There are **no admin-owned or Principal-owned Sessions** in the final 2.1
  model.
- The following are **not** introduced: `generic Owner`, `generic Subject`,
  `Resource` owner hierarchy, `owner_type`, `owner_id`.

### Public identities

| Identity | Format | Notes |
| --- | --- | --- |
| Launcher ID | `dhl_` + 32 lowercase hex chars (16 random bytes) | Analogous to existing stable resource IDs. |
| Credential ID | existing `dhcr_` + 32 hex (retained) | Same format for Principal and Launcher credentials. |
| Credential bearer | existing `dhc_` token format (retained) | No launcher-specific bearer prefix. |
| Session ID / token | unchanged (`dhs_`, existing session token) | |

Credential authentication determines the concrete owner from **persistent
state**, never from a bearer-token prefix.

### Launcher model

Logical fields: `id`, `principal_id`, `name`, `enabled`, `scope_mode`,
`created_at`. `scope_mode` ∈ {`inherit`, `restricted`}.

- Launcher name is unique within one Principal.
- `default` is the conventional default name, not a separate type.
- Launcher allowed roots are stored only for `restricted` Launchers.
- Effective Session-creation policy is current-state evaluation:
  `global roots ∩ Principal roots ∩ Launcher scope`.
  - `inherit` adds no narrowing.
  - `restricted` intersects the current effective Principal roots with the
    Launcher's canonical stored roots.
- Stored Launcher roots are validated when **written** and **revalidated**
  against the current parent ceilings when **used**.
- Launcher roots do **not** own MAC state.

### Credential model

One `credentials` table with exactly one concrete owner. Logical row:
`id`, `principal_id` (nullable), `launcher_id` (nullable), `name` (nullable),
`token_hash`, `created_at`, `revoked_at`.

Constraint:

| Credential | principal_id | launcher_id | name |
| --- | --- | --- | --- |
| Principal | non-null | null | non-null |
| Launcher | null | non-null | null |

- Existing Principal credentials are preserved **byte-for-byte** through
  migration: IDs, names, token hashes, created timestamps, revoked timestamps.
- The current Principal active-name reuse contract is preserved (partial
  unique index over `revoked_at IS NULL`).
- A Launcher owns at most one credential (unique non-null `launcher_id`).
- Launcher rotation updates the **same** credential row: ID unchanged, owner
  unchanged, token hash atomically replaced, old token immediately invalid, new
  secret returned once.
- Deleting the optional Launcher credential removes that singular resource so a
  new one may later be issued.
- Existing Principal credentials are **not** silently reclassified as Launcher
  credentials.
- Principal credential lifecycle remains administrator-controlled in 2.1.
- A Principal credential may manage: its Launchers; those Launchers' optional
  credentials; Sessions under those Launchers. It does **not** issue/revoke
  arbitrary Principal credentials.

### Session public model

Target representation preserves the useful existing projection and adds the
real owner:

```text
id, workspace, created_at, expires_at, launcher_id, launcher, principal
```

`principal` is **derived** display/provenance data through Launcher. No stored
Session `principal_id` remains as a second authority after cutover.

### Session control authority

- Admin: all Launchers/Sessions.
- Principal credential: Launchers attached to its Principal; Sessions under
  those Launchers.
- Launcher credential: only its own Sessions.
- Session bearer: no Session create/list/delete authority.

Cross-Launcher and cross-Principal access is **non-disclosing**: return
`resource not found`, never confirm foreign existence.

### Audit / provenance

- **owner** (Launcher) and **creator** are separate.
- Creator provenance is one of: Admin, Principal credential, Launcher
  credential. It is not authorization state.
- Existing concrete audit fields are extended with narrow Launcher identity
  fields. No generic actor/subject schema is introduced for this release.
- Credential secrets and Session tokens remain excluded from logs/audit.

## Current-to-target map

This maps the actual current owners and symbols to the target. The current
state is the baseline at `b5cc231e84e33924cd317505ce50ad38a13440c3`.

### Session ownership today

- `Session` (`session.go:41`) carries `PrincipalID *int64` and `PrincipalName`.
- `sessions` table (`database.go:36`) has nullable `principal_id`.
- Projection: `scanSessionWithPrincipal` (`session.go:94`), `sessionToJSON`
  (`sessions.go:36`), JSON field `principal`.
- List/delete filter directly by `principal_id`:
  `listSessionsForPrincipal` (`session.go:321`),
  `deleteSessionForPrincipal` (`session.go:398`).
- Admin create: `createSession` (`session.go:271`) → `principal_id` NULL.
- Principal create: `createSessionWithPolicy` (`session.go:127`) →
  `principal_id` set via `sessionCreatePolicy.PrincipalID`.
- Identity for run: `resolveSessionExecutionIdentity` (`session.go:576`) returns
  daemon UID/GID when `PrincipalID == nil`, else stored Principal UID/GID.
- Control authority: `sessionControlAuthority` (`sessions.go:52`) with only
  `isAdmin` and `principalCredential *PrincipalCredentialAuth`.
- Auth: `authenticateSessionControlRequest` (`sessions.go:59`) checks admin
  token then `authenticateCredential`.
- Expiry/session-token: `findSessionByToken` (`session.go:447`).
- MAC/runtime cleanup: `deleteSession`/`deleteSessionForPrincipal` release the
  MAC binding and the handler cleans the runtime dir.

### Principal today

- `Principal`/`PrincipalWithRoots` (`principal.go:20,29`).
- `createPrincipal` (`principal.go:125`), `findPrincipalByID`,
  `findPrincipalByUsername`, `listPrincipalSummaries`, `deletePrincipal`
  (`principal.go:459`), `persistPrincipalEnabledChange` (`principal.go:240`),
  `addPrincipalAllowedRoot`/`removePrincipalAllowedRoot`.
- App-level lifecycle: `applyPrincipalEnabledChange` (`app.go:195`),
  `deletePrincipalWithMAC` (`app.go:220`), `releaseSessionBindings`
  (`app.go:232`). These are the authoritative post-commit MAC/runtime cleanup
  paths.
- Handlers (`principal_handler.go`): `handleCreatePrincipal`,
  `handleShowPrincipal`, `handleListPrincipals`, `handleSetPrincipal`,
  `handleAddPrincipalAllowedRoot`, `handleRemovePrincipalAllowedRoot`,
  `handleDeletePrincipal`. All `requireAdmin`.
- CLI (`principal_cli.go`): `principalCommand` with create/show/list/set/delete
  and allowed-root add/remove.

### Credential today

- `Credential`/`CredentialWithPrincipal` (`credential.go:19,27`).
- Token constants: `credentialTokenPrefix = "dhc_"`, 32-byte entropy hex;
  `generateCredentialToken` (`credential.go:44`), `hashCredentialToken`,
  `generateCredentialID` (`dhcr_`, 16 bytes hex).
- `createCredential`, `listCredentials`, `findCredentialByID`,
  `revokeCredential`.
- Auth result: `PrincipalCredentialAuth` (`credential.go:232`) with
  `PrincipalID`, `PrincipalName`, `CredentialID`, `PrincipalAllowedRoots`.
  `authenticateCredential` (`credential.go:244`) returns it.
- `credentials` table (`database.go:62`) is Principal-only today
  (`principal_id INTEGER NOT NULL`, `name TEXT NOT NULL`).
- Handlers (`credential_handler.go`): `handleCreateCredential`,
  `handleListCredentials`, `handleRevokeCredential`. All `requireAdmin`.
- CLI (`credential_cli.go`): `credentialCommand` with create/list/revoke/install.
- Install (`credential_install.go`): `installCredential`, `credentialPath`,
  `validateCredentialToken`, `safeWriteCredential`.

### Database / migration style

- `initializeDatabase` (`database.go:30`) is the single owner of schema. It is
  additive (`CREATE TABLE IF NOT EXISTS`) plus introspection
  (`pragma_table_info`) plus, where needed, atomic table-rebuild migrations
  (the `credentials` active-name reuse rebuild and the `mac_boundaries`
  composite-key rebuild). Partial unique index
  `credentials_active_name_unique` (`database.go:152`).
- `cleanupExpiredSessions` (`database.go:230`).
- Foreign keys are enabled per-connection in `openDatabase`
  (`_foreign_keys=on`).

### Startup ordering (must be preserved and extended)

`runDaemon` (`main.go:228`) currently holds the daemon instance lock and runs,
in order:

1. `loadAdminToken`
2. `openDatabase`
3. `initializeDatabase`
4. `cleanupExpiredSessions`
5. `newMACCoordinatorForMode` + `ReconcileLiveSessions`
6. `cleanupStaleSessionRuntimeDirs`

Stage 1.3 deliberately extends this ordering to:

```text
loadAdminToken
openDatabase
initializeDatabase
ensureUserModeOwnership        (ModeUser only)
migrateSessionOwnership        (old schema only; mode-aware)
cleanupExpiredSessions
newMACCoordinatorForMode + ReconcileLiveSessions
cleanupStaleSessionRuntimeDirs
```

`ensureUserModeOwnership` must run before Session ownership migration so legacy
user-mode `principal_id IS NULL` Sessions can be attributed to the real
local daemon owner and its `default` Launcher. In system mode no such local
attribution exists; legacy admin-created NULL-owner Sessions are invalidated.

The existing Release-1 additive migration that says “if `sessions.principal_id`
is absent, add it” is **not valid on the final 2.1 schema**. Stage 1.3 must
replace/guard that migration at the same time as the canonical `sessions` schema
changes: a final table containing `launcher_id` must never have `principal_id`
re-added on a later startup. The R1 migration remains applicable only to a
pre-cutover legacy sessions table that has neither final Launcher ownership nor
the old Principal ownership column.

### Operator client / CLI wiring

- `resolveOperatorClient`/`resolveDefaultEndpoint`/`resolveSystemEndpoint`
  (`operator_client.go`). User-mode default: user socket + admin token.
- `registerRoutes` (`main.go:196`) is the single route owner.
- Root command tree in `cli.go:618`; `launcherCommand` will be added here and to
  `completion.go`.

## Persistence migration

The implementation does **not** switch all ownership in the first schema
commit. The ordered, restart-safe sequence is split across stages so that each
ownership boundary is reviewed before the next changes.

### Stage 1.1 — additive Launcher foundation + final Credential owner schema

Apply inside `initializeDatabase` (additive first, then rebuild where required),
under the existing explicit-migration style. Session behavior is unchanged at
the end of this stage.

1. Create `launchers`:

   ```sql
   CREATE TABLE IF NOT EXISTS launchers (
       id            TEXT PRIMARY KEY,
       principal_id  INTEGER NOT NULL,
       name          TEXT NOT NULL,
       enabled       INTEGER NOT NULL DEFAULT 1,
       scope_mode    TEXT NOT NULL,
       created_at    INTEGER NOT NULL,
       FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
       UNIQUE (principal_id, name),
       CHECK (scope_mode IN ('inherit','restricted'))
   );
   ```

   `ON DELETE CASCADE` from Principal to Launcher is acceptable: Principal
   deletion legitimately removes its Launchers, and the Launcher deletion path
   already performs checked Session cleanup first. Launcher→Session does **not**
   use cascade (see below).

2. Create `launcher_allowed_roots`:

   ```sql
   CREATE TABLE IF NOT EXISTS launcher_allowed_roots (
       launcher_id  TEXT NOT NULL,
       root_path    TEXT NOT NULL,
       FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE CASCADE,
       UNIQUE (launcher_id, root_path)
   );
   ```

   Stored only for `restricted` Launchers.

3. Rebuild `credentials` to the final single-table, single-concrete-owner
   shape, preserving existing rows byte-for-byte:

   ```sql
   CREATE TABLE credentials (
       id            TEXT PRIMARY KEY,
       principal_id  INTEGER,
       launcher_id   TEXT,
       name          TEXT,
       token_hash    TEXT NOT NULL UNIQUE,
       created_at    INTEGER NOT NULL,
       revoked_at    INTEGER,
       FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
       FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE CASCADE,
       UNIQUE (launcher_id),
       CHECK (
           (principal_id IS NOT NULL AND launcher_id IS NULL AND name IS NOT NULL)
           OR
           (principal_id IS NULL AND launcher_id IS NOT NULL AND name IS NULL)
       )
   );
   ```

   The rebuild uses the same atomic table-rebuild pattern already used for
   `credentials` and `mac_boundaries`: detect the old schema, create the new
   table, copy rows verbatim, drop the old, rename, recreate the partial active
   unique index `credentials_active_name_unique ON credentials(principal_id,
   name) WHERE revoked_at IS NULL`. Existing Principal rows map
   `principal_id`/`name` unchanged and `launcher_id NULL`; no Launcher rows
   exist yet.

   `ON DELETE CASCADE` on `launcher_id` and `principal_id` deletes credential
   rows when their owner is removed; this is a resource cleanup convenience and
   is **not** the Session-cleanup mechanism.

4. Add indexes for credential and (later) Session lookup by owner and for
   expiry:

   - `launchers(principal_id, name)` is already covered by the UNIQUE.
   - `launcher_allowed_roots(launcher_id)` covered by UNIQUE.
   - `credentials(launcher_id)` covered by UNIQUE.
   - Sessions: see cutover.

At the end of Stage 1.1 no production Session path changes; the additive
tables and the final credential schema exist and are exercised only by new code
reviewed in Stage 1.2.

### Session ownership cutover (Stage 1.3) — ordered, restart-safe

Do **not** add `sessions.launcher_id` as a permanent second authority beside a
kept `principal_id`. The target is a rebuilt `sessions` table without
`principal_id`. Cutover runs inside the daemon lock as a dedicated migration
step `migrateSessionOwnership` invoked from `runDaemon` after
`ensureUserModeOwnership` (when applicable) and before `cleanupExpiredSessions`.

At the same Stage 1.3 boundary, `initializeDatabase` must switch the canonical
fresh-database `sessions` DDL to the final `launcher_id` schema and retire the
old unconditional R1 `principal_id` additive rule for any table that already
has `launcher_id`. This prevents the removed second-authority column from being
reintroduced on the next daemon restart.

Ordered steps:

1. **Create/resolve default Launchers for attributable existing Principals.**
   For every Principal that currently owns at least one Session, create (if
   absent) that Principal's `default` Launcher with `scope_mode = inherit`.
   Idempotent: `INSERT OR IGNORE` on `(principal_id, name)`.

   In user mode, `ensureUserModeOwnership` has already resolved/created the real
   daemon-owner Principal and its `default` Launcher before this migration runs.

2. **Rebuild `sessions`** to the final shape in one atomic transaction:

   ```sql
   CREATE TABLE sessions (
       id            TEXT PRIMARY KEY,
       token_hash    TEXT NOT NULL UNIQUE,
       workspace     TEXT NOT NULL,
       created_at    INTEGER NOT NULL,
       expires_at    INTEGER NOT NULL,
       launcher_id   TEXT NOT NULL REFERENCES launchers(id)
   );
   ```

   Copy rows, resolving the new `launcher_id`:
   - Principal-attributable rows (old `principal_id IS NOT NULL`) →
     that Principal's `default` Launcher.
   - User-mode legacy rows with old `principal_id IS NULL` → the already
     resolved real daemon-owner `default` Launcher.
   - System-mode admin-created rows with old `principal_id IS NULL` →
     **invalidated**, not copied (see step 3).

   `launcher_id` is non-null. There is **no** `ON DELETE CASCADE` from Launcher
   to Session; Launcher deletion must go through the checked Session/runtime/MAC
   lifecycle, not a DB cascade.

3. **Invalidate legacy admin-created Sessions that cannot be attributed.**
   In system mode, old `principal_id IS NULL` rows have no valid Principal →
   Launcher ownership chain and are dropped in the same transaction. In user
   mode, the per-user database and real daemon-owner identity provide the
   attribution described above, so those rows migrate instead of being
   discarded.

4. **Make Launcher ownership non-null and remove `principal_id` from
   authorization and schema.** After the rebuild no production query selects,
   filters, or authorizes on a stored `principal_id`. `Session.PrincipalID` is
   replaced by `Session.LauncherID`; `PrincipalName` becomes a derived
   projection through the Launcher. A subsequent `initializeDatabase` must
   recognize this final schema and must not recreate `principal_id`.

Why invalidated legacy Sessions leave **no permanent helper-owned MAC or
runtime state**: invalidated rows are removed from the DB, so they are absent
from the active Session set. The existing startup steps that already run after
migration therefore clean them:

- `cleanupExpiredSessions` and the cutover both remove rows before the MAC
  coordinator is created, so `ReconcileLiveSessions` never recreates a binding
  for an invalidated Session.
- `sessionMACCoordinator.cleanupStaleBoundaries` /
  `isBoundaryStillNeeded` only retains a workspace boundary while at least one
  live Session still needs it; a boundary whose only consumer was an invalidated
  Session is released. If the same workspace is still used by a surviving
  Session, the boundary is legitimately retained for that Session.
- `cleanupStaleSessionRuntimeDirs` (`session.go:519`) removes runtime
  directories whose Session ID is not in the active set; invalidated Sessions
  are not active, so their runtime directories are removed on the same startup
  pass.

Thus invalidation is a one-time logical removal whose physical MAC/runtime
cleanup is performed by the existing, authoritative startup cleanup paths. No
new cleanup machinery is required, and no invalidated Session leaves durable
helper-owned state.

### Restart safety

Every cutover step is idempotent and guarded by the daemon instance lock. The
`sessions` rebuild is one atomic transaction; a crash before commit leaves the
old schema intact and the next startup re-runs `migrateSessionOwnership`. A
crash after commit means ownership is already final and the migration's
detection (does `sessions` still have `principal_id`? does it have
`launcher_id`?) skips rework. Detection uses `pragma_table_info`, matching the
existing `initializeDatabase` pattern. The final-schema branch of
`initializeDatabase` must treat `launcher_id` as authoritative and must never
re-add the retired `principal_id` column.

## Authentication / authorization

### Credential authentication becomes owner-typed

`authenticateCredential` currently returns `PrincipalCredentialAuth`
(`credential.go:232`). Extend the single lookup to determine the concrete owner
from **persistent state**:

- If `principal_id IS NOT NULL` → a Principal credential: return
  `PrincipalCredentialAuth` (unchanged semantics).
- If `launcher_id IS NOT NULL` → a Launcher credential: return a new narrow
  internal auth-result struct, e.g. `LauncherCredentialAuth{LauncherID,
  PrincipalID, PrincipalName}`.

These two concrete auth-result structs discriminate authenticated Principal and
Launcher credentials. They must **not** become a generic domain `Owner`
hierarchy. A shared `authenticateCredential` stays the single token-lookup
entry point; it returns a discriminated result that both the session-control
path and any future data-plane caller consume.

Launcher credential auth must also reject when the owning Launcher (or its
Principal) is disabled, mirroring today's `ErrPrincipalDisabled` /
`ErrCredentialRevoked` handling.

### Session control authority

Extend `sessionControlAuthority` (`sessions.go:52`) with a Launcher variant so
the final authority set is:

```text
Admin | Principal credential | Launcher credential
```

`authenticateSessionControlRequest` (`sessions.go:59`) keeps the order: admin
token, then credential authentication, with the persistent credential owner
determining Principal vs Launcher authority. A Session bearer never
authenticates a session-control request (that path is data-plane only via
`findSessionByToken`).

### ONE common Session ownership lookup / authorization boundary

Do **not** implement three separate ownership checks in create/list/delete.
Introduce a single internal boundary, `sessionControlScope`, produced by one
resolver method, e.g.:

```go
// resolveSessionControlScope maps an authenticated authority to the Launcher
// scope it may manage. Admin -> all; Principal -> its Launchers; Launcher -> self.
type sessionControlScope struct {
    admin       bool
    principalID int64   // non-zero for Principal and Launcher credential authorities
    launcherIDs map[string]bool // authorized Launcher IDs (empty+admin => all)
}

func (a *App) resolveSessionControlScope(auth *sessionControlAuthority) sessionControlScope
```

All three handlers (`handleCreateSession`, `handleListSessions`,
`handleDeleteSession`) consume this scope. Session existence checks within that
scope are non-disclosing: a Session outside the scope returns `session not
found` (`404`), never `forbidden`/`403`, and never reveals foreign existence.

## Session ownership / default resolution

### Create selectors (HTTP request conceptual shape)

```text
workspace
launcher_id  optional
principal    optional
```

Resolution by authority:

| Authority | launcher_id absent | launcher_id == self | another launcher | principal selector |
| --- | --- | --- | --- | --- |
| Launcher credential | self | self | `404 launcher_not_found` | invalid (`400 invalid_selector`) |
| Principal credential | that Principal's `default` Launcher | must belong to that Principal (else `404 launcher_not_found`) | `404 launcher_not_found` | invalid (`400 invalid_selector`) |
| System-mode Admin | invalid: selector required | explicit Launcher | explicit Launcher | that Principal's `default` Launcher |
| User-mode Admin | local daemon-owner `default` Launcher | explicit Launcher | explicit Launcher | explicit local/known Principal resolution |

System-mode Admin must provide **exactly one** of `launcher_id` or `principal`.
User-mode Admin may omit both: omission is the compatibility default that
resolves the real daemon-owner OS identity's `default` Launcher. No path may
create an ownerless Session.

**Exact invalid-selector behavior:**

- Any caller supplying both `launcher_id` and `principal` → HTTP `400`,
  `conflicting_selectors`.
- Principal credential supplying any `principal` selector (even matching its
  own Principal) → HTTP `400`, `invalid_selector`.
- Principal credential selecting a Launcher outside its Principal → HTTP `404`,
  `launcher_not_found`.
- Launcher credential supplying any `principal` selector → HTTP `400`,
  `invalid_selector`.
- Launcher credential supplying a `launcher_id` other than itself → HTTP `404`,
  `launcher_not_found`, regardless of whether that Launcher exists.
- System-mode Admin supplying neither selector → HTTP `400`,
  `missing_launcher_selector`.
- User-mode Admin supplying neither selector → resolve local daemon-owner
  `default`; this is not an error.

After resolution, **all** callers (Admin, Principal, Launcher, and user-mode)
use the same shared path:

```text
Launcher lookup
enabled checks
effective-root evaluation
Session creation
MAC preparation
persistence
audit
```

Defaults must not create a second policy implementation. `createSessionWithPolicy`
(`session.go:127`) is generalized to carry the resolved `LauncherID` instead of
`PrincipalID`; `createSession` (admin) is removed or reduced to a thin
resolution wrapper so there is no third create path.

### Effective-root evaluation

Generalize `intersectAllowedRootScopes` (`session.go:64`) into a three-level
evaluation that consumes `global roots`, the Principal's current roots, and the
Launcher scope (`inherit` → no narrowing; `restricted` → canonical stored
roots). Launcher stored roots are revalidated against the current effective
Principal roots at use time, rejecting stale or directly injected
out-of-ceiling roots. This evaluation lives in one authoritative function and
is the only place the three-level policy is computed.

### Session representation

`Session` gains `LauncherID`; `PrincipalName` is derived by joining through the
Launcher. The JSON `sessionJSON` (`sessions.go:17`) adds `launcher_id` and
`launcher`, and keeps `principal` as the derived projection. No stored
`principal_id` is exposed as a second authority.

## User-mode compatibility

### Current user-mode reality

User mode runs the daemon as a real OS user, uses the user socket + admin
token, and currently creates Sessions with `principal_id NULL` (admin path) whose
execution identity is the daemon's own UID/GID
(`resolveSessionExecutionIdentity`, `session.go:576`). The quick start must
remain valid in spirit:

```text
docker-helper init
systemctl --user enable --now docker-helper
docker-helper session create --workspace ...
```

Ordinary user-mode users must **not** be required to create a Principal, create
a Launcher, install a Principal credential, or select a Launcher. Yet the final
persistent model must still provide a real Launcher owner for every new Session.

### Selected solution: user-mode collapsed policy + transparent default resolution

**Ownership rule.** Every user-mode Session is owned by the real
**daemon-owner OS identity**'s `default` Launcher:

```text
real daemon-owner OS identity -> its default Launcher -> Session
```

The daemon-owner OS identity is the effective UID that runs the daemon
(`os.Getuid()`/`EffectiveUID()`, the same identity that currently owns
user-mode sessions and runtime state). No synthetic cross-user identity is
invented.

**Automatic provisioning.** In user mode, startup inside the daemon lock runs
`ensureUserModeOwnership` immediately after `initializeDatabase` and before
`migrateSessionOwnership`. It resolves the real daemon-owner OS account from the
process UID, then resolves or creates the corresponding Principal record and
its `default` Launcher. The real OS UID/GID remain the execution identity; the
stored Principal is the persistent ownership link required by the common model.
The ordinary user never has to create or select it.

Legacy user-mode `principal_id IS NULL` Sessions are attributable because the
user-mode state database belongs to that one daemon-owner deployment; Stage 1.3
maps them to this already-resolved default Launcher. System mode does not use
this rule.

**Collapsed policy — no second authority.** The daemon-owner Principal is
created with **no `principal_allowed_roots` rows**. Its effective roots are
defined as the global allowed roots (the single `config.AllowedRoots` owner).
Its `default` Launcher uses `inherit`, adding no narrowing. Therefore the
effective Session-creation roots in user mode are:

```text
global ∩ principal(=global, collapsed) ∩ inherit(=identity) = global
```

This preserves the current user-mode global-root semantics exactly while
gaining persistent Principal/Launcher ownership. Because the user-mode
Principal maintains **no** parallel root rows, there is **no second
manually-synchronized policy authority**: `config.AllowedRoots` remains the one
source, and user mode simply collapses the hierarchy onto it. If an operator
reloads `allowed_roots`, the same single owner changes, and user-mode Sessions
continue to follow it.

**Preferred architectural property.** This is "one Session ownership model +
user-mode collapsed policy/default resolution", **not** a permanent "legacy
Session" branch. After cutover there is no separate legacy Session kind; every
Session — including user-mode ones — has a real Launcher owner through the
normal model. `resolveSessionExecutionIdentity` no longer special-cases
`PrincipalID == nil`; it resolves through the owning Launcher's Principal, which
in user mode resolves to the daemon-owner identity (preserving the current
UID/GID result).

**Non-interactive default.** The `session create` CLI remains unchanged for the
ordinary user; the server performs transparent resolution. If a user-mode
operator explicitly supplies a selector, the normal explicit-resolution rules
apply.

## Lifecycle / cleanup

These lifecycle semantics are frozen (from the concept) and map onto the
existing authoritative owners:

| Action | Effect | Owner path |
| --- | --- | --- |
| Credential revoke/delete | Affects that credential only; existing Sessions survive. | `revokeCredential` (`credential.go:188`) extended for Launcher credentials; Session rows untouched. |
| Launcher disable | Its Launcher credential can no longer authenticate; owned Sessions invalidated/removed through the existing Session cleanup boundary; Launcher identity and credential resource remain. | New `applyLauncherEnabledChange` modeled on `applyPrincipalEnabledChange` (`app.go:195`); reuses `releaseSessionBindings` + runtime-dir cleanup. |
| Launcher re-enable | Does not recreate old Sessions. | Same function, inverse direction; no Session recreation. |
| Launcher delete | Only after checked cleanup of owned Sessions/runtime; then removes Launcher roots and optional credential. | New App-level `deleteLauncherWithMAC` modeled on `deletePrincipalWithMAC` (`app.go:220`); explicit checked cleanup first. No `ON DELETE CASCADE` from Launcher→Session. |
| Principal disable/delete | Applies the same Session invalidation/cleanup across every Launcher attached to that Principal. | Existing `applyPrincipalEnabledChange`/`deletePrincipalWithMAC` extended to collect Sessions across all Launchers of the Principal. |
| Root narrowing | Affects creation of new Sessions; existing Sessions survive. | Effective-root evaluation only; no Session mutation. |

The existing post-commit MAC/runtime cleanup paths (`releaseSessionBindings`,
`cleanupSessionRuntimeDir`, `cleanupStaleSessionRuntimeDirs`,
`sessionMACCoordinator`) remain the authoritative owners. Release 3 Session
closing/tombstone/`session.cleanup` semantics are **not** introduced here.

## HTTP contract

Freeze the agreed resource layout. Session endpoints remain structurally
stable (`POST /sessions`, `GET /sessions`, `DELETE /sessions/{id}`) with the
Session request/response extended as described.

### Principal creation with optional initial credential

Existing `POST /principals` remains administrator-authorized and is extended
without changing omission behavior. Request:

```json
{
  "username": "alice",
  "issue_credential": false
}
```

- `issue_credential` omitted → `false`, preserving existing direct-API
  behavior.
- `issue_credential: false` → create only the Principal.
- `issue_credential: true` → in the same public operation create the Principal
  and its initial Principal credential named `default`; return that bearer
  secret exactly once in the successful response.
- If the combined operation cannot complete, it must not leave a silently
  half-provisioned “success” result; implementation must define one
  transactional/compensating owner for Principal + optional initial credential.
- The daemon never prompts. Interactive prompting is a CLI concern.

The existing plural Principal credential endpoints remain authoritative for
later create/list/revoke operations.

### Launcher endpoints

```text
POST   /principals/{username}/launchers
GET    /principals/{username}/launchers
GET    /launchers/{id}
PATCH  /launchers/{id}
PUT    /launchers/{id}/allowed-roots
DELETE /launchers/{id}

PUT    /launchers/{id}/credential
GET    /launchers/{id}/credential
POST   /launchers/{id}/credential/rotate
DELETE /launchers/{id}/credential
```

### Launcher creation

`POST /principals/{username}/launchers` (admin-authorized; also consumed by
Principal-credential Launcher management under its own Principal). Request:

```json
{
  "name": "default",
  "scope": "inherit",
  "allowed_roots": [],
  "issue_credential": false
}
```

- `name` defaults to `default`.
- `scope` omitted (or `inherit`) with `allowed_roots` omitted → `inherit`.
- `scope: "restricted"` requires `allowed_roots` (one or more); each root is
  validated against the current effective Principal roots on write.
- `issue_credential` defaults to `false` in the raw API for compatibility.
  When `true`, the response returns the new Launcher credential secret exactly
  once.

### Allowed-root replacement

`PUT /launchers/{id}/allowed-roots` is the **single atomic Launcher scope
mutation**. Do not implement a separate add/remove HTTP mutation and do not
make the CLI perform GET → local edit → PUT read-modify-write.

Use an explicit complete replacement:

```json
{ "scope": "inherit" }
```

or

```json
{ "scope": "restricted", "allowed_roots": ["/path"] }
```

`restricted` with an empty/omitted `allowed_roots` is rejected
(`400`, `invalid_allowed_roots`). Setting `inherit` clears stored roots.
`PATCH /launchers/{id}` changes only Launcher scalar identity/state such as
`name` and `enabled`; it does **not** provide a second `scope_mode` mutation
path.

### Credential endpoints (singular Launcher resource)

- `PUT /launchers/{id}/credential` — issue the singular Launcher credential;
  valid only when the Launcher has none (`409` `launcher_credential_exists`
  otherwise). Returns the secret once.
- `GET /launchers/{id}/credential` — read-only metadata (ID, created, revoked);
  never returns a secret.
- `POST /launchers/{id}/credential/rotate` — replaces the bearer secret of the
  same logical credential (ID and owner unchanged, old token immediately
  invalid, new secret returned once). Errors if no credential exists
  (`404`).
- `DELETE /launchers/{id}/credential` — deletes the singular credential so a
  new one may later be issued.

Error codes follow the existing `writeError` style (`error_code` +
`message`). Session token and credential secrets never appear in responses
beyond the single creation/rotation return, never in logs, and never in audit.

## CLI contract

### New `launcher` command tree

Add `launcherCommand` to the root tree (`cli.go:618`) and to `completion.go`.
Subcommands mirror the HTTP ownership model:

```text
docker-helper launcher create [--principal USER] [--name NAME]
    [--allowed-root PATH]... [--issue-credential | --no-credential]
docker-helper launcher list [--principal USER]
docker-helper launcher show LAUNCHER_ID
docker-helper launcher set LAUNCHER_ID --enabled true|false [--name NAME]
docker-helper launcher scope set LAUNCHER_ID --inherit
docker-helper launcher scope set LAUNCHER_ID --allowed-root PATH [--allowed-root PATH]...
docker-helper launcher credential issue LAUNCHER_ID
docker-helper launcher credential rotate LAUNCHER_ID
docker-helper launcher credential delete LAUNCHER_ID
```

`launcher scope set` sends one complete `PUT /launchers/{id}/allowed-roots`
replacement. It never fetches the current list and performs local
read-modify-write. `--inherit` and one-or-more `--allowed-root` are mutually
exclusive; the latter selects `restricted` scope.

### Prompt / default behavior

- **Interactive CLI** may prompt/default. `launcher create` without
  `--principal` infers the Principal from an authenticated Principal
  credential; defaults `name=default`, `scope=inherit`; asks
  "Create launcher credential now? [Y/n]" (default yes) when interactive.
  `principal create` likewise asks whether to issue the initial Principal
  credential; accepting maps to `POST /principals` with
  `issue_credential=true`, not to a hidden second CLI workflow.
- **Non-interactive CLI must explicitly choose** `--issue-credential` or
  `--no-credential` when Principal or Launcher creation would otherwise prompt.
  It must never wait for a prompt.
- **No prompting logic lives in the daemon.** The daemon API takes an explicit
  `issue_credential` boolean; prompting is a CLI concern.

### Credential install

`docker-helper credential install` (`credential_install.go`) is unchanged and
installs a Principal-credential bearer for system-mode non-root clients. It is
not repurposed for Launcher credentials.

### Man pages / help / completion

`launcher` help, man pages (`docs/man/*`), and `completion.go` update together
with the command tree (Stage 1.5 / 1.6). They stay in sync with the CLI
contract as required by `manpage_test.go`, `completion_test.go`, and
`cli_help_test.go`.

## Audit / runtime labels

### Audit / provenance

Extend `auditRecord` (`audit.go:3`) with narrow Launcher identity fields
(e.g. `launcher_id`, and a derived `principal_name` already present).
`owner` (Launcher) and `creator` (Admin | Principal credential | Launcher
credential) are recorded separately. No generic actor/subject schema is
introduced. Credential secrets and Session tokens remain excluded.

Existing audit event names (`session.create`, `principal.enabled_change`,
`principal.credential_revoke`, ...) are retained; Launcher events follow the
same `launcher.*` naming pattern. Audit is provenance, not authorization.

### Runtime labels (Stage 1.4)

For newly started one-shot run containers (`run.go:564`), add helper-owned
correlation labels sufficient to carry Session, Launcher, and Principal
identity, e.g.:

```text
com.dockerhelper.session.id       = <session id>
com.dockerhelper.launcher.id      = <launcher id>
com.dockerhelper.principal.name   = <principal username>
com.dockerhelper.correlation.schema = 1
```

The namespace is deliberately neutral: only Launcher is the Session owner; the
Session and Principal labels are correlation/provenance, not additional owners.

- User input cannot override them (the run request has no label passthrough
  today, and the labels are appended by the helper).
- Labels are **correlation/cleanup evidence, not authorization state**.
- No Managed Container semantics are introduced; Docker backend architecture is
  unchanged (Release 3 owns the Engine API migration).

## Ordered stages

Each production stage is reviewed before the next ownership boundary changes.

1. **1.1 Persistence foundation** — Launcher tables/types/IDs; final Credential
   concrete-owner schema; no Session ownership behavior change.
2. **1.2 Launcher control plane** — Launcher CRUD/policy; Principal-authorized
   Launcher management; Launcher credential issue/rotate/delete; still no
   Session cutover.
3. **1.3 Session ownership cutover** — migration/backfill/invalidation;
   Launcher-only Session ownership; default/explicit resolution;
   Admin/Principal/Launcher Session control; three-level effective-root policy;
   cross-Launcher non-disclosure.
4. **1.4 Lifecycle/runtime integration** — Launcher + Principal disable/delete
   propagation; existing MAC/runtime cleanup integration; audit provenance;
   helper-owned runtime labels.
5. **1.5 CLI / simple defaults** — `launcher` CLI; prompt/default behavior;
   user-mode transparent ownership; credential install; help/completion/
   man-facing contract.
6. **1.6 Release integration** — docs/README/agent skill; v2.0.0 → 2.1 upgrade
   UAT; hierarchy/isolation/lifecycle UAT; final naming/architecture
   reconciliation; update the Release 3 vocabulary map
   (`release-3-vocabulary-and-implementation-map.md`) to actual 2.1
   symbols/schema.

## Test / UAT gates

Protect independent observable invariants; do not reimplement policy in
fixtures. Required coverage (from the concept, mapped to owners):

- Three-level effective-root evaluation in one authoritative policy function;
  rejection of stale/out-of-ceiling Launcher roots.
- Isolation between two Launchers of one Principal (including equal-root
  Launchers with separate Session namespaces).
- Session-management continuity across Launcher credential rotation: old secret
  rejected, replacement authorized, no second Launcher credential created.
- Principal access only to Launchers attached to that Principal; cross-Launcher
  `404` non-disclosure.
- Default vs explicit Launcher selection; system-mode Admin requires exactly
  one selector, while user-mode Admin omission resolves the local default;
  conflicting-selector and invalid-selector behavior.
- Launcher and Principal disable/delete cleanup boundaries (Sessions
  invalidated, MAC/runtime cleaned via existing owners, no cascade substitute).
- Migration: 2.0 credentials preserved byte-for-byte as Principal credentials;
  attributable Principal Sessions → default Launcher; user-mode NULL-owner
  Sessions → local daemon-owner default Launcher; system-mode non-attributable
  admin Sessions invalidated; final startup never re-adds `principal_id`; no
  permanent MAC/runtime state from invalidated Sessions.
- User-mode: transparent daemon-owner ownership; quick start requires no
  Principal/Launcher/credential; effective global-root semantics preserved.
- Principal create with omitted/false/true `issue_credential`, one returned
  secret, and no half-provisioned success contract.
- Atomic Launcher scope replacement; no CLI read-modify-write policy mutation.
- Runtime correlation labels use neutral Session/Launcher/Principal namespaces;
  checked cleanup.
- CLI prompt/default and mandatory non-interactive choice.
- HTTP status/error-code/audit/secret-redaction contracts.

UAT (Stage 1.6): v2.0.0 → 2.1 upgrade on existing databases; hierarchy,
isolation, and lifecycle end-to-end; secret-leak checks on raw audit/log
output.

## R3 compatibility gate

Release 3 must be able to consume the final 2.1 model without a second owner:

- Final `sessions.launcher_id` non-null, no `principal_id` second authority.
- `credentials` single table with one concrete owner; R3 Operation `initiator`
  and audit `actor` map to the real 2.1 Principal/Launcher symbols.
- Launcher is the stable delegated owner R3 derives Session ownership and
  publishing authority from; no empty future fields are added to Launcher now.
- The R3 vocabulary map and D0 plan's "final Release 2.1 Session foreign key and
  ownership symbols" are updated to the actual 2.1 names before R3 production
  begins.

## Explicit non-goals

Do **not** place in Release 2.1 (constraint from the concept and R3):

```text
Session renewal
Session closing / cleanup_failed / closed tombstones
durable session.cleanup Operation
Managed Containers
Docker Engine API adapter
synchronous build/run migration
Session network
ports
resource limits
exec
WebSocket
Operation persistence
```

Also not introduced: `owner_type` / `owner_id`, generic `Owner` / `Subject` /
`Resource` hierarchy, `Job` / `Task` abstractions, desired-state or restart
policy semantics. Launcher may later be the authority source for R3 policy, but
no empty future fields are added now.
