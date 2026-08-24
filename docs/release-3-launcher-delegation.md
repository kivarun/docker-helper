# Release 3 launcher delegation concept

## Status and scope

This document records the proposed Release 3 authorization and ownership model
for delegated launchers. It is a design input, not the current Release 2
contract and not an implementation plan.

The proposal addresses a demonstrated use case: give an agent enough authority
to create Docker Helper sessions for child agents without granting the agent
the principal's entire filesystem policy or making a rotatable bearer key the
owner of long-lived resources.

The design does not add a general agent control plane, recursive delegation, or
agent-specific behavior to the daemon.

## Problem in the Release 2 model

Release 2 credentials authenticate a principal. Multiple credentials for the
same principal differ by ID, name, and revocation state, but receive the same
principal-wide allowed roots and principal-wide session-management authority.

The credential row currently mixes two concepts:

- a bearer secret that should be independently rotated or revoked;
- the apparent identity of a launcher, expressed only through the credential
  name.

Attaching roots or session ownership directly to the credential would make
rotation change the resource owner. It would also make sessions created before
rotation difficult to manage without preserving obsolete credential identity.

## Target domain model

The proposed hierarchy is:

```text
Global policy
└── Principal
    ├── Principal credentials (zero or more)
    └── Launcher
        ├── Launcher credential (zero or one)
        └── Sessions
            └── Operations and Docker containers
```

The roles are deliberately concrete:

- **Principal** owns the OS execution identity and the maximum delegated
  filesystem policy for that identity.
- **Launcher** is a stable delegated subject, filesystem-policy layer, session
  owner, and runtime ownership boundary.
- **Credential** is a rotatable bearer key owned by exactly one Principal or
  exactly one Launcher. It is not a resource owner.
- **Session** is an execution capability owned by exactly one Launcher.
- **Operation and container** belong to their Session and therefore to its
  Launcher.

`Launcher` is intentionally generic. It may represent an interactive client,
CI job, supervisor agent, or another local or remote caller. The daemon does
not model AI agents as a separate domain object.

## Authorization hierarchy

Control-plane authority flows downward:

- the admin token has full control over Principals, Launchers, credentials,
  and sessions;
- a Principal credential controls Launchers attached to that Principal, the
  optional credential of each Launcher, and their sessions;
- a Launcher credential controls only sessions owned by that Launcher;
- a Session token authorizes only pull, build, run, registry, and operation
  requests within that Session.

Higher-level control does not provide direct data-plane execution. Admin and
Principal callers may create a Session and receive its token, but Docker
operations continue to require the Session token.

A Principal credential must not modify its own UID, GID, home, enabled state,
or principal allowed roots. Those remain admin-owned policy.

A Launcher credential must not change its own roots or issue another
credential. Those operations require its Principal or the administrator.

## Session ownership and creation provenance

Every non-legacy Session has exactly one Launcher owner. The actor that created
the Session is separate provenance:

```text
owner:      Launcher
created_by: Admin | Principal | Launcher
```

Authorization and cleanup use the owner. Audit records preserve the creator.
No authorization decision depends on `created_by`.

Launcher selection follows the caller:

- a Launcher credential selects its own Launcher implicitly;
- a Principal credential selects the Principal's `default` Launcher unless an
  attached Launcher is named explicitly;
- an admin token must identify a target Launcher, or use an explicit Principal
  selector that resolves that Principal's `default` Launcher;
- a Session token cannot create another Session.

There are no new admin-owned or principal-owned sessions. Admin and Principal
callers act on behalf of a Launcher.

## Filesystem authorization

The authorization chain is:

```text
session workspace ∈ launcher roots ∈ principal roots ∈ global roots
```

The effective roots for Session creation are evaluated from current state on
every request:

```text
global roots ∩ principal roots ∩ launcher roots
```

A Launcher has one of two scope modes:

- `inherit`: no additional narrowing; effective launcher roots equal the
  current effective Principal roots;
- `restricted`: an explicit set of canonical roots further narrows the
  Principal policy.

Omitting roots when creating a Launcher selects `inherit`. Supplying one or
more roots selects `restricted`. An explicit Launcher root must be within the
current effective Principal roots when stored, and Session creation must still
re-evaluate the complete hierarchy to defend against stale or damaged rows.

Authorization roots do not own MAC state. The existing session MAC lifecycle
continues to prepare and release coverage for the concrete canonical Session
workspace. A broader Principal or Launcher ceiling must never cause recursive
relabeling of that ceiling.

## Default Launcher security trade-off

The `default` Launcher uses `inherit`, so its filesystem authority matches its
Principal's effective authority.

The optional credential of a Launcher represents that Launcher's trust domain.
Therefore a caller holding the credential for the `default` Launcher may list
and delete Sessions created for that Launcher by the Principal or
administrator. It does not receive those Sessions' bearer tokens or
session-scoped registry secrets and cannot call their data-plane endpoints
without the Session token.

The incremental risk is primarily metadata visibility and availability. It is
not a new workspace confidentiality boundary: the same credential can already
create another Session for an allowed workspace.

When session lifecycle isolation is required, use a separate Launcher. Two
Launchers may both use `inherit` and therefore have identical filesystem roots
while retaining separate Session namespaces and cleanup boundaries. Use
`restricted` roots when filesystem isolation is also required.

## Credential lifecycle

The admin token remains the root capability and does not identify a Principal.
Release 2 principal credentials remain Principal credentials in the new model;
they must not be silently reclassified as Launcher credentials.

Every Credential is a technical key with:

- an opaque credential ID;
- exactly one owner, Principal or Launcher;
- a token hash;
- creation and revocation timestamps.

Principal and Launcher credential cardinality deliberately differ:

- a Principal may own zero or more Principal credentials; their existing names
  remain useful for distinguishing independently issued keys;
- a Launcher may own zero or one Launcher credential;
- a Launcher credential has no business name because the stable
  human-readable identity belongs to the Launcher.

Revoking a credential blocks that key but does not change Principal or Launcher
ownership and does not revoke already issued Session tokens. Principal
credentials retain the existing multi-credential lifecycle, including
overlapping replacement when required.

Rotating a Launcher credential atomically replaces the bearer secret of that
same logical credential. The old secret becomes invalid, the credential ID and
Launcher ownership remain unchanged, and no second concurrently owned Launcher
credential is created.

Neither a Principal nor a Launcher requires a credential merely to exist or to
own resources. The administrator can create and manage a credential-less
hierarchy. Credentials are issued only when that subject must authenticate
directly.

## CLI concept

The ordinary interactive flow should not expose separate credential-creation
steps:

```text
docker-helper init
docker-helper principal create USER
  Create principal credential now? [Y/n]
docker-helper credential install
docker-helper launcher create
  Create launcher credential now? [Y/n]
docker-helper session create --workspace PATH
```

For `launcher create`, defaults are:

- Principal: inferred from an authenticated Principal credential;
- name: `default`;
- scope: `inherit`;
- credential issuance: offered interactively and enabled by default.

An admin caller names the target explicitly with `--principal USER`, because
the global admin token does not itself encode a Principal.

Supplying `--name` selects another stable Launcher name. Supplying one or more
`--allowed-root` values selects `restricted` scope. Both flags remain optional
for the ordinary flow.

Interactive `principal create` and `launcher create` ask whether to issue the
initial credential. Non-interactive and JSON invocations must make the choice
explicit with `--issue-credential` or `--no-credential`; they must never wait
for a prompt.

Separate credential operations remain available for rotation and recovery, but
are advanced workflows rather than quick-start steps:

```text
docker-helper principal credential create USER
docker-helper launcher credential issue LAUNCHER_ID
docker-helper launcher credential rotate LAUNCHER_ID
docker-helper credential install
```

`launcher credential issue` is valid only when the Launcher has no credential.
`launcher credential rotate` replaces the secret of the existing credential
and returns the new secret exactly once.

A Principal credential may create a Session for its `default` Launcher without
installing the Launcher credential. The Launcher credential returned during
creation is intended for the delegated agent's environment.

## HTTP concept

Resource management is nested under the stable owner:

```text
POST   /principals
POST   /principals/{username}/credentials
GET    /principals/{username}/credentials

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

Principal and Launcher creation accept `issue_credential`. A successful
issuance response returns the secret exactly once.

The singular Launcher credential resource enforces zero-or-one cardinality.
Rotation updates that resource's bearer secret atomically, preserves its
credential ID and Launcher ownership, invalidates the old secret, and returns
the replacement secret exactly once. Principal credential endpoints remain
plural and continue to support multiple independently revocable credentials.

The Session endpoints remain structurally stable:

```text
POST   /sessions
GET    /sessions
DELETE /sessions/{id}
```

`POST /sessions` accepts an optional Launcher selector. It must be absent or
match self for Launcher authentication, may select an attached Launcher for
Principal authentication, and is required for admin authentication unless an
explicit Principal selector resolves `default`.

Session listing and deletion follow the hierarchy:

- admin: any Session;
- Principal: Sessions under its Launchers;
- Launcher: only its own Sessions.

Cross-Launcher access returns not found rather than revealing whether a Session
exists.

## Database concept

The logical schema adds stable Launchers and their policy:

```sql
CREATE TABLE launchers (
    id            TEXT PRIMARY KEY,
    principal_id  INTEGER NOT NULL,
    name          TEXT NOT NULL,
    enabled       INTEGER NOT NULL,
    scope_mode    TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    FOREIGN KEY (principal_id) REFERENCES principals(id),
    UNIQUE (principal_id, name),
    CHECK (scope_mode IN ('inherit', 'restricted'))
);

CREATE TABLE launcher_allowed_roots (
    launcher_id  TEXT NOT NULL,
    root_path    TEXT NOT NULL,
    FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE CASCADE,
    UNIQUE (launcher_id, root_path)
);
```

One credential table may serve both concrete owner types without introducing a
generic actor hierarchy:

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
    UNIQUE (principal_id, name),
    UNIQUE (launcher_id),
    CHECK (
        (principal_id IS NOT NULL AND launcher_id IS NULL AND name IS NOT NULL)
        OR
        (principal_id IS NULL AND launcher_id IS NOT NULL AND name IS NULL)
    )
);
```

The owner check gives every Credential exactly one concrete owner. The unique
non-null `launcher_id` enforces at most one Credential per Launcher, while
`name` remains available only for the Principal multi-credential model.
Launcher rotation updates the existing row's token hash and lifecycle metadata
rather than inserting a second Launcher-owned row.

Sessions logically store a non-null `launcher_id`. Principal identity is
derived through the Launcher rather than duplicated as an independent owner.
An old physical `principal_id` column may remain during an additive migration
if production queries no longer treat it as a second authority.

Indexes are required for credential and Session lookup by owner and for normal
Session expiry queries.

## Runtime ownership and lifecycle

The in-memory operation model already carries a Session ID. It should retain
Launcher provenance needed for audit and owner-scoped cleanup without creating
a second operation registry.

Helper-started run containers should receive helper-owned labels for Session,
Launcher, and Principal identity. User requests cannot override these labels.
The labels provide external ownership evidence for checked cleanup and restart
reconciliation; they do not replace the existing operation lifecycle.

Lifecycle semantics are:

- credential revoke blocks that key; existing Sessions survive;
- root narrowing affects new Sessions; existing Sessions survive until normal
  deletion or expiry;
- Launcher disable blocks its credential, if present, and invalidates its
  Sessions;
- Launcher deletion is permitted only after checked Session and runtime
  cleanup, then removes its roots and optional credential;
- Principal disable or deletion applies the same lifecycle to every attached
  Launcher;
- Session deletion uses the existing authoritative operation, runtime, and MAC
  cleanup path rather than adding a parallel cascade implementation.

## Migration direction

Release 2 credentials already authenticate Principals. Migration preserves
their IDs, names, and token hashes as Principal credentials. They remain a
multi-credential Principal lifecycle and are not reassigned to Launchers.

Existing Principal-owned Sessions may be assigned to an automatically created
`default` Launcher for that Principal. Existing admin-created Sessions without
a Principal cannot be attributed to a valid ownership chain and should be
invalidated during the Release 3 transition.

User-mode migration may bind legacy local Sessions to the real daemon-owner OS
identity and its default Launcher. It must not invent a synthetic cross-user
Principal.

Migration must be atomic, preserve foreign-key enforcement, and avoid a
permanent legacy authorization branch.

## Test obligations

Tests should protect independent observable invariants rather than repeat the
same authorization matrix at every layer.

Required coverage includes:

- effective-root evaluation across global, Principal, and restricted or
  inherited Launcher policy;
- rejection of stale or directly injected out-of-ceiling Launcher roots;
- isolation between two Launchers of one Principal, including equal-root
  Launchers with separate Session namespaces;
- Session-management continuity across Launcher credential rotation, with the
  old secret rejected, the replacement secret authorized, and no second
  Launcher credential created;
- Principal access only to Launchers attached to that Principal;
- default Launcher selection and explicit Launcher selection;
- admin creation only for an explicit ownership chain;
- Principal overlapping credential replacement and singular Launcher
  credential rotation without ownership change or Session revocation;
- Launcher and Principal disable/delete cleanup boundaries;
- container ownership labels and checked cleanup;
- migration of Release 2 credentials as Principal credentials;
- migration or invalidation of legacy Sessions according to attributable
  ownership;
- CLI prompt/default behavior and mandatory non-interactive choice;
- HTTP status, error-code, audit, and secret-redaction contracts.

Policy combinations should be table-driven in the authoritative policy tests.
Handler and CLI tests should prove only their public mapping and representative
authorization paths. End-to-end tests should cover the hierarchy and lifecycle
without reimplementing policy decisions in fixtures.

## Release boundary

This proposal belongs to Release 3 planning. Release 2 retains its current
Principal-scoped credential and Session contract through UAT and release.

Before implementation, the Release 3 plan must turn this concept into binding
CLI, HTTP, migration, lifecycle, and compatibility contracts. Implementation
must replace the Release 2 ownership path rather than layer a second
authorization or cleanup mechanism beside it.
