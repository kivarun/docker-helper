# Architecture

## Contents

- [Goal and product boundary](#goal-and-product-boundary)
- [High-level architecture](#high-level-architecture)
- [Domain model](#domain-model)
  - [Ownership model](#ownership-model)
  - [Authority model](#authority-model)
  - [Credentials and Session capability](#credentials-and-session-capability)
- [Deployment](#deployment)
  - [User mode](#user-mode)
  - [System mode](#system-mode)
  - [Transports](#transports)
  - [systemd services](#systemd-services)
  - [Mandatory access control](#mandatory-access-control)
- [Trust model](#trust-model)
- [Control-plane lifecycle](#control-plane-lifecycle)
  - [Bootstrap](#bootstrap)
  - [Ownership provisioning](#ownership-provisioning)
  - [Session creation](#session-creation)
  - [Principal and Launcher lifecycle](#principal-and-launcher-lifecycle)
  - [Credential lifecycle](#credential-lifecycle)
  - [Session lifecycle](#session-lifecycle)
  - [Ownership migration](#ownership-migration)
- [Workspace authorization](#workspace-authorization)
  - [Root-policy hierarchy](#root-policy-hierarchy)
  - [Launcher scope](#launcher-scope)
  - [Session workspace](#session-workspace)
  - [Policy introspection](#policy-introspection)
  - [MAC lifecycle](#mac-lifecycle)
- [Control-plane API and CLI mapping](#control-plane-api-and-cli-mapping)
  - [Principal](#principal)
  - [Launcher](#launcher)
  - [Session](#session)
  - [Completion introspection](#completion-introspection)
  - [CLI conventions](#cli-conventions)
  - [Config and reload](#config-and-reload)
- [Data-plane execution](#data-plane-execution)
  - [Operation lifecycle](#operation-lifecycle)
  - [Build](#build)
  - [Run](#run)
  - [Pull](#pull)
  - [Registry login](#registry-login)
  - [Filesystem policy](#filesystem-policy)
  - [Environment and trusted CA](#environment-and-trusted-ca)
  - [Retention and cancellation](#retention-and-cancellation)
- [Service lifecycle](#service-lifecycle)
  - [Shutdown](#shutdown)
  - [systemd units and hardening](#systemd-units-and-hardening)
- [Errors and observability](#errors-and-observability)
  - [Health](#health)
  - [Error contract](#error-contract)
  - [Audit logging](#audit-logging)
  - [Operational logging](#operational-logging)
- [Security considerations](#security-considerations)
- [Current limitations and non-goals](#current-limitations-and-non-goals)

## Goal and product boundary

docker-helper is a small policy-enforcing daemon that provides a restricted
interface to Docker.

A coding agent runs on the same machine as the developer and needs to build
images and run containers. Giving the agent direct access to `docker.sock`
means it can read any file on the host, access any network, and run arbitrary
processes. docker-helper sits between the agent and Docker and enforces
policy:

- filesystem access is restricted to an explicit workspace per session;
- every data-plane operation requires a session token;
- all Docker commands go through a single process;
- the developer controls which workspace each session can access.

docker-helper limits the host paths exposed through its supported Docker
operations. It is not a complete sandbox: Docker/default networking remains
available, and a validation or command-construction defect in this trusted
Docker-facing service can compromise the host.

## High-level architecture

```
Operator / agent
      │
      ├─── admin token (full administrative control)
      ├─── Principal credential (Principal-scoped control plane)
      ├─── Launcher credential (Launcher-scoped Session control)
      └─── session token (Docker data plane)
      │
   +--+--+
   │     │
   ▼     ▼
docker-helper CLI    direct HTTP client
reference client     curl / native adapter
   │     │
   +--+--+
      │
   daemon HTTP API
      │
docker-helper daemon
      │
      ├── Moby Engine API ─── registry login, pull
      │
      └── Docker CLI ─────── build, run
              │
          Docker Engine
```

Backend ownership is currently split: `registry login` and `POST /pull`
execute through the daemon's single shared Moby Engine API adapter, while
`build` and `run` still execute the Docker CLI. The daemon is not yet fully
Moby-only; the remaining D0 Engine API migrations extend the Engine path and
retire the CLI path.

There are exactly four bearer classes, described by the [authority
model](#authority-model): the admin token authenticates the administrator, a
Principal credential authenticates one Principal, a Launcher credential
authenticates one Launcher, and the session token is a Session capability —
a data-plane key for one workspace, not a credential resource.

The daemon HTTP API is the single capability contract. The CLI is a
shipped reference/convenience client of that API. Curl and native adapters
are direct clients of the same API.

The presence of the `docker-helper` binary in the agent image is not a
requirement. Choosing a client interface does not change daemon policy
or security semantics. The supervisor that starts an agent creates a
session and passes the session token to the agent; it is not a mandatory
daemon or control-plane component.

## Domain model

The binding ownership and authority model:

```
Principal (OS identity, authorization ceiling)
    └── Launcher (stable delegated Session owner)
            └── Session (ephemeral capability)
```

- The Launcher is the only Session owner. `sessions.launcher_id` is
  `NOT NULL` and references `launchers(id)`; the retired
  `sessions.principal_id` column no longer exists.
- Principal identity is derived through the Launcher (`Session.LauncherID`
  is stored; `PrincipalName` is a read-time projection via the ownership
  JOIN through `launchers` to `principals`).
- A credential is a rotatable authentication key, never an owner. Ownership
  is derived from persistent state, never from the token.
- User mode is the transparent daemon-owner Principal plus `default`
  Launcher case of this same ownership model, not a different permanent
  ownership class. The pre-delegation ownerless states exist only as
  migration inputs (see [Ownership migration](#ownership-migration)).
- The CLI is never an authorization authority; the daemon resolves and
  enforces all policy.

### Ownership model

`launchers` table: `id` (`dhl_` + 32 hex characters), `principal_id`
(REFERENCES `principals(id)`), `name`, `enabled`, `scope_mode`
(`inherit` or `restricted`), `created_at`. Launcher-scoped roots live in
`launcher_allowed_roots` (only meaningful in `restricted` scope).

A Launcher name is a Principal-scoped, path-safe identifier with the
canonical grammar `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`: 1..63
characters of lowercase ASCII letters, digits, and hyphens, with
alphanumeric first and last characters. Names are identifiers: the exact
supplied value is accepted or rejected, never trimmed or case-folded into
validity. The grammar is enforced by the centralized Launcher write path
(create, rename, and the provisioning insertion of `default`) and
by a CHECK constraint on the `launchers` table; a database created by an
intermediate unreleased build that predates the invariant fails
closed at startup instead of being silently rewritten. Because `_` is
outside the alphabet, Launcher names and Launcher IDs (`dhl_<32 hex>`)
occupy disjoint lexical spaces.

A Launcher name is unique within one Principal and may repeat under
different Principals; there is never a global lookup by Launcher name
(`alice/default` and `bob/default` are different Launchers). `default` is
only the conventional default name — the name used when creation omits
`--name` and when an individual Launcher command omits the selector —
not a subtype or a global singleton.

Every Principal has a real Launcher named `default`, provisioned atomically
at Principal creation (see [Principal provisioning](#principal-provisioning)).
It is a normal stored Launcher object — not a virtual or synthesized
fallback — and it is addressed implicitly only when a caller omits the
Launcher selector. User mode maps all ownership transparently onto one
daemon-owner Principal and its `default` Launcher, so quick start requires
no Principal, Launcher, or credential and preserves the effective
global-root semantics; system mode requires explicit ownership: an
authenticated Principal resolves its own default Launcher when no explicit
selector is supplied.

#### User-mode owner reservation

In user mode the daemon-owner Principal (resolved at startup by
`ensureUserModeOwnership`, identified by the cached
`App.userModeDefault.principalID`) and its `default` Launcher (identified by
`App.userModeDefault.launcherID`) are reserved: the transparent ownership
chain is exactly the state the startup contract requires (Principal enabled
with zero stored roots, deferring completely to the global user-mode roots;
default Launcher enabled, named `default`, `inherit` scope, zero roots).
Public control-plane mutations that would corrupt that chain are rejected
with the stable `409 user_mode_owner_reserved` conflict before any durable
or runtime change:

- daemon-owner Principal: disable, delete, allowed-root add, allowed-root
  remove (re-enabling an already-enabled Principal is the natural no-op);
- daemon-owner `default` Launcher: disable, delete, rename away from
  `default`, restricted scope, and any non-empty inherit replacement
  (re-enable, rename to `default`, and `inherit` with zero roots are
  no-ops; inherit with roots is `400 invalid_allowed_roots` for every
  launcher).

The reservation is owned by one App-aware policy owner
(`usermode_owner.go`); identity is the startup-resolved chain state, never
a username or Launcher name, so system mode and other Principals' `default`
Launchers (and any additional Launchers under the daemon-owner Principal)
remain fully mutable. Each guard runs inside the same `lifecycleMu`
serialization boundary as the mutation it protects, before any quiesce or
durable change, so a rejected mutation cannot strand the running daemon or
turn the next startup into a fail-closed rejection. The lock-owning wrappers
also acquire the current policy snapshot (the global allowed roots) inside
that same critical section, preserving the reload boundary's
`lifecycleMu -> a.mu` ordering: a global-root narrowing that linearizes
before a Principal allowed-root add or Launcher scope replacement is
observed by that mutation. An unknown Principal is not reserved (the
mutation path reports its normal `principal_not_found`); a Principal lookup
failure aborts the mutation fail-closed through the normal internal-error
path. Audit records of a rejected mutation carry the
`user_mode_owner_reserved` result.

### Authority model

There are exactly four authentication classes. The canonical authority and
target-resolution contract:

| Authority | Authenticates | Maximum control scope | Session-create target resolution | Legal narrowing selectors (Session list) |
|---|---|---|---|---|
| Admin token | the administrator | full control plane: all Principals, Launchers, Principal and Launcher credentials, all Sessions, configuration, reload, admin-token rotation | system mode: exactly one explicit selector required (`400 missing_launcher_selector`); user mode: the local daemon-owner `default` Launcher | `?principal=USER` and/or `?launcher=LAUNCHER`; a `dhl_` Launcher ID is valid without a Principal, a Launcher name requires the Principal scope |
| Principal credential | one Principal | that Principal's resources: its Launchers and their credentials, its own Principal credential, `principal show` on itself, and the Sessions owned by its Principal's Launchers | its Principal's `default` Launcher, or an explicit own Launcher | `?launcher=` (name or ID) inside its own scope; `--principal` is illegal, even for its own Principal |
| Launcher credential | one Launcher | that Launcher's Sessions and `GET /auth` self-inspection | its own Launcher (forced) | none — there is no narrowing contract for this authority |
| Session token | one Session | one workspace data plane: `POST /build`, `POST /run`, `POST /pull`, `POST /registry/login`, and that Session's operation endpoints | not a control authority; not accepted by control endpoints or `GET /auth` | none |

Rules shared by every authority:

- **Scope-first visibility.** List surfaces (`session list`, `launcher
  list`, Principal credential list) are Queries: authentication establishes
  the maximum visible scope and optional selectors can only narrow it,
  never expand it. Selector resolution happens server-side inside the
  authority-visible ownership, and one ownership query serves the final
  scope — never a client-side filter and never in-memory enumeration.
- **The daemon is the authority.** The CLI never performs a local
  authorization decision; it resolves targets (target construction only)
  and the daemon authorizes. The CLI performs auth introspection (`GET
  /auth`) only where the wire contract needs the credential's owner, and
  never where the daemon resolves the scope itself.
- **Stable Principal-control targeting.** Principal-owned resource
  families resolve the target Principal under the request authority: a
  Principal credential targets the exact Principal ID it authenticated as —
  the nested username is an authorization selector only — so a stale
  in-flight authority whose Principal was deleted fails closed as
  `404 principal_not_found` and never rebinds to a Principal recreated
  under the same username (IDs are AUTOINCREMENT and never reused); an
  admin authority is name-oriented at the API selector boundary and
  legitimately targets the current same-name Principal.
- **Launcher selectors are Principal-scoped.** Launcher names are never
  searched globally. An exact `dhl_<32 hex>` selector resolves by ID; a
  name resolves as `(principal_id, name)` inside the resolved Principal
  scope. A missing or foreign selector is the same non-disclosing
  `404 launcher_not_found`; an authority-illegal selector is
  `400 invalid_selector`; a Principal-scoped name supplied without a
  Principal scope is `400 launcher_name_requires_principal`.
- **Non-disclosure.** Unknown targets are the same not-found outcome for
  existing and nonexistent selectors; error and audit behavior never
  disclose foreign state.

`GET /auth` reports the authenticated authority to the caller as
`{"authority": "admin"}`, `{"authority": "principal", "principal": "..."}`
or `{"authority": "launcher", "principal": "...", "launcher_id": "..."}`.
It accepts an admin token, Principal credential, or Launcher credential; a
Session token does not authenticate this endpoint. Invalid, revoked, or
disabled credentials follow the non-disclosing authentication
semantics and receive no identity information.

Delegation tiers bound what an agent can reach:

- Principal credential — broader delegated operator capability; may be
  given to a sufficiently trusted agent;
- Launcher credential — narrower delegated operator capability; exact
  Launcher scope;
- Session token — narrow data-plane Session capability for a single
  workspace that expires after the configured TTL.

A Session token alone grants access to one workspace and cannot create or
manage Sessions; a Launcher credential can create and manage only its
Launcher's Sessions; a Principal credential can reach the Sessions owned by
that Principal's Launchers. Choosing the delegation tier is the operator's
trust decision; giving an agent a Principal credential delegates broader
operator capability and is never a default recommendation.

### Credentials and Session capability

Credential token and storage rules:

- Admin token: generated by `docker-helper init`, stored at `admin.token`
  (user mode: user config directory; system mode:
  `/etc/docker-helper/admin.token`), SHA-256 hash loaded into memory at
  server start, sent as `Authorization: Bearer <token>`, compared with
  `crypto/subtle.ConstantTimeCompare`;
- Principal credential: credential token prefixed `dhc_` (64 hex
  characters), credential ID prefixed `dhcr_`, SHA-256 hash stored in
  SQLite, resolved through database lookup by token hash;
- Launcher credential: same token format (`dhc_` + 64 hex characters); the
  token itself carries no owner type — the owner is resolved from
  persistent state at authentication time; at most one credential exists
  per Launcher;
- Session token: generated per session by `POST /sessions`, returned once
  in the creation response, SHA-256 hash stored in SQLite, required for
  the data-plane operations, resolved through database lookup by token
  hash and checked for expiration; deletion removes the session and
  invalidates subsequent requests.

#### Credential install

The `credential install` command installs a non-admin credential token for
`docker-helper --system`. The credential may belong to a Principal or a
Launcher; the daemon resolves its owner and authorization scope when the
token is used. It is not run as root.

- Token format: `dhc_` + 64 lowercase hex characters (68 total).
- Token stored at `${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper/credential.token`
  with mode `0600`; directory created with mode `0700`.
- Input: hidden TTY via `term.ReadPassword` on terminal; `bufio.Scanner` on
  non-TTY stdin. Token never appears in stdout or stderr.
- `--force`: skip existence check; atomic `rename` replaces file without prior
  deletion. Write failure leaves existing file intact.
- Root invocation rejected with clear message.

Token resolution for `--system` mode:
 1. `--token-file` — explicit path, always wins.
 2. Non-root `--system` — credential.token from `credentialPath()`.
 3. Root `--system` — `/etc/docker-helper/admin.token`.

Endpoint and token resolution for default (no `--system`) mode:
 1. `--token-file` — explicit path, always wins.
 2. If the user socket exists, select it and use `admin.token` in the user
    config directory.
 3. Otherwise, if the system socket exists, select it and use non-root
    `credential.token` or root `/etc/docker-helper/admin.token`.
 4. Once selected, an unavailable/failing endpoint is returned as an error;
    the client does not retry another daemon.

## Deployment

### User mode

- **Effective UID**: non-root
- **Config**: `${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper/config.json`
- **State**: `${XDG_STATE_HOME:-$HOME/.local/state}/docker-helper`
- **Runtime**: `$XDG_RUNTIME_DIR/docker-helper`
- **Transport**: Unix socket only, at
  `$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock` with `0600`
  permissions
- **Execution identity**: daemon UID:GID for daemon-owner (user-mode) Sessions

### System mode

- **Effective UID**: root
- **Config**: `/etc/docker-helper/config.json`
- **State**: `/var/lib/docker-helper`
- **Runtime**: `/run/docker-helper`
- **Transports**: Unix socket at
  `/run/docker-helper/docker-helper.sock` with `0666` permissions, plus
  loopback HTTP at `127.0.0.1:52375` by default (configurable via
  `http_address`, startup-only)
- **Execution identity**: the owning Principal's UID:GID

### Transports

- **User mode**: Unix socket only
- **System mode**: Unix socket + loopback HTTP (`127.0.0.1:<port>`)

One handler, one API, one auth policy on both transports. Transport does
not determine identity or authorization. Transports are local only:
non-loopback listeners, TLS, and remote execution are not part of the
current implementation (see [Current limitations and
non-goals](#current-limitations-and-non-goals)).

### systemd services

Both deployment modes ship systemd unit files (see [systemd units and
hardening](#systemd-units-and-hardening)): a user unit installed under the
user's systemd manager and a system unit under the system manager. The
units carry the shutdown/restart contract ([Shutdown](#shutdown)) and the
hardening profile of each mode.

### Mandatory access control

System mode requires exactly one supported enforcing backend:

- AppArmor confines the daemon with the `/etc/apparmor.d/docker-helper-system`
  profile and uses explicit managed workspace boundaries for path-level
  workspace defense in depth. The profile includes the dynamic helper-owned
  boundary state file `/var/lib/docker-helper/apparmor/managed-boundaries`;
  managed boundaries are stored there, outside config.json. These managed
  boundaries are MAC state, not authorization roots;
- SELinux confines the daemon as `docker_helper_t` and system-mode containers
  as the MCS-constrained `docker_helper_container_t` type.

Neither backend, both backends, and permissive SELinux fail closed. SELinux
workspace access is type-based and does not reproduce AppArmor's per-path
managed-boundary rule; canonical application-level allowed-root validation
remains authoritative in both modes.

## Trust model

### Trusted

- the developer who runs `docker-helper init` and `docker-helper serve`;
- the host filesystem outside the allowed roots;
- the Docker Engine and its configuration;
- the `docker-helper` process itself.

### Partially trusted

- the allowed-root directories and their contents;
- the workspace selected at session creation time.

### Untrusted

- the coding agent;
- any input from the agent (JSON payloads, paths, image names);
- Dockerfiles inside the workspace;
- container processes.

The agent is untrusted because it may execute arbitrary code, generate
malicious Dockerfiles, or attempt path traversal. docker-helper validates
every agent input before passing it to Docker.

## Control-plane lifecycle

### Bootstrap

```
docker-helper init
    │
    ├── creates config directory (0700)
    ├── creates state directory (0700)
    ├── writes config.json
    └── generates admin token (dht_<64 hex chars>)
    │
docker-helper serve
    │
    ├── loads config.json
    ├── reads admin token, computes SHA-256 hash
    ├── opens SQLite database
    ├── deletes expired session rows (expires_at <= now)
    ├── runs ownership migration (idempotent; see Ownership migration)
    ├── resolves user-mode ownership (ensureUserModeOwnership)
    └── starts HTTP server on the configured transports
```

### Ownership provisioning

Ownership provisioning is the creation of the durable ownership chain
`Principal └── Launcher`. Session creation never creates ownership state;
it only consumes it.

#### Principal provisioning

`POST /principals` (admin token) is one ownership transaction. It resolves
the OS user (`uid`, `gid`, `home`) and atomically creates:

- the Principal row;
- its initial (default) Principal allowed root — the canonicalized OS home
  directory, which must be inside at least one global allowed root;
- the persisted canonical `default` Launcher: enabled, `inherit` scope,
  zero Launcher roots;
- optionally an initial Principal credential (when the request asks for
  credential issuance; otherwise no credential exists until one is issued
  separately).

Fresh Principal does not exist without its `default` Launcher ownership
anchor: `ensureDefaultLauncher` runs inside the same transaction and any
failure rolls the whole provisioning back. Startup backfills any Principal
that predates that rule (`migrateDefaultLaunchers`); later startups resolve
the default read-only (`findDefaultLauncher`). The CLI is `principal
create`, which prompts for the optional initial Principal credential on a
TTY and requires an explicit `--issue-credential`/`--no-credential` choice
non-interactively.

#### Launcher provisioning

`POST /principals/{username}/launchers` (admin token or owning-Principal
credential) creates a normal persisted Launcher atomically:

```
POST /principals/{username}/launchers
    │
    ├── resolves the owner Principal (Principal-control targeting rules)
    ├── validates the Launcher name against the canonical grammar
    ├── creates the launcher row (dhl_<32 hex> ID, inherit scope by
    │   default, optional initial restricted roots)
    └── optionally issues the Launcher's single credential in the same
        atomic result
```

- The owner Principal is resolved through the stable
  Principal-control targeting rules (see
  [Authority model](#authority-model)); targeting is target construction
  only — the daemon remains the authorization authority.
- Scope policy: `inherit` (the effective Principal ceiling) by default, or
  `restricted` with explicit roots supplied at creation; every narrowing
  must stay inside the effective Principal ceiling.
- The optional singular Launcher credential is issued in the same creation
  result when requested (`--issue-credential` / `--no-credential`; the CLI
  prompts on a TTY); at most one credential exists per Launcher
  (`409 launcher_credential_exists` on a second issuance).
- Creation is atomic: a name conflict is `409 launcher_exists` (message
  naming the Launcher and its Principal).
- When the CLI omits `--name`, it first checks whether the resolved
  Principal already has a `default` Launcher: if it does, the CLI fails
  locally with `launcher "default" already exists for principal "<user>"`
  plus a hint to use `--name NAME`, before prompting for a credential and
  without issuing the doomed create request; any other pre-flight failure
  (for example a transient server error) does not block the create.

### Session creation

One pipeline serves every authority; only target resolution differs.

```
authority
    ↓
resolve exactly one target Launcher
    ↓
derive the owning Principal through the Launcher
    ↓
resolve effective workspace policy
    (global roots ∩ effective Principal roots ∩ launcher restricted roots)
    ↓
validate workspace inside the effective roots
    ↓
create Session with launcher_id
    (session ID dhs_<32 hex>, session token dht_<64 hex>,
     SHA-256 hash stored in SQLite)
    ↓
return session + one-time token
```

The HTTP body of `POST /sessions` accepts
`{"workspace", "launcher_id", "principal"}`:

- `launcher_id` and `principal` are mutually exclusive; both present is
  `400 conflicting_selectors`; an explicitly present but empty or malformed
  selector is `400 invalid_selector`;
- a Launcher credential's target is forced to its own launcher; a
  conflicting explicit selector is rejected;
- with no selectors the request body carries only the workspace.

The CLI maps its selectors onto those wire fields after authenticating
(`GET /auth`). The two selectors are mutually exclusive on the wire: the
resolved target is sent as either `principal` or `launcher_id`, never
both.

#### Admin authority

A system-mode admin token must supply exactly one explicit selector
(`400 missing_launcher_selector`); a user-mode admin token with no
selector resolves the local daemon-owner `default` Launcher.

An admin may send `--principal USER` (mapped to the `principal` wire
field) or `--launcher LAUNCHER` — an ID-shaped selector is forwarded as
`launcher_id` as-is, a Launcher name is resolved to its global ID through
the scope-first launcher list query under the named Principal
(`GET /launchers?principal=USER&launcher=NAME`; a name without
`--principal` is rejected locally because Launcher names are never
searched globally).

#### Principal authority

Principal authority is established by the credential itself. The
`principal` create selector is illegal for this authority — not even the
credential's own Principal is accepted: the CLI rejects `--principal`
locally, and a `principal` wire selector of any value is the daemon's
`400 invalid_selector`. A Principal credential may pass
`--launcher LAUNCHER` only: the name is resolved within the
credential's own visible scope the same way (a foreign or missing
Launcher is the daemon's non-disclosing `launcher not found`). With no
selector the credential's Principal's default Launcher is the target.

#### Launcher authority

A Launcher credential has no Launcher control-plane authority, so its
selector is never resolved through the launcher list: an ID-shaped
`--launcher` is forwarded as `launcher_id` as-is and the daemon's create
admission stays the authority (own -> self, foreign -> non-disclosing
`launcher not found`), and a name-shaped `--launcher` is rejected locally
with an actionable hint to use the Launcher's `dhl_` ID (reported for the
credential by `GET /auth`). For this authority `--principal` is rejected
locally.

### Principal and Launcher lifecycle

Principal disable/delete:

```
PATCH /principals/{username}  (admin token, body: {"enabled": false})
    │
    ├── collects session IDs for runtime cleanup
    ├── deletes all sessions for the principal (no FK cascade)
    ├── sets principal.enabled = 0
    ├── commits transaction
    └── best-effort cleanup of session runtime directories
    │
    Subsequent session token lookup:
    │
    ├── findSessionByToken rejects sessions whose launcher's principal is disabled
    └── disabled launchers' credentials are rejected at authentication time
```

```
DELETE /principals/{username}  (admin token)
    │
    ├── collects session IDs for runtime cleanup
    ├── fails with 409 launcher_runtime_active if a launcher
    │   still has active runtime (durable state unchanged), else
    │   disables each launcher (deleting its sessions) and deletes
    │   the principal (credentials/roots/launchers via FK CASCADE)
    ├── commits the teardown steps
    └── best-effort cleanup of session runtime directories, also for
        sessions invalidated before a later teardown failure
```

Launcher lifecycle and cleanup reuse the existing Session lifecycle and
MAC/runtime cleanup owners:

- disabling a launcher deletes its sessions and cleans their runtime state
  through the existing per-session cleanup path; a disabled launcher
  rejects new session creation and its credential authentication
  (`launcher disabled`);
- deleting a launcher performs a checked delete: if its sessions still
  have active runtime state, the delete fails with
  `409 launcher_runtime_active` and the launcher's durable state —
  including its enabled flag and Sessions — is unchanged; a still-enabled
  launcher can be disabled explicitly first. Once the check passes,
  sessions are deleted and the launcher row is removed. If owner removal
  fails after the durable disable committed, the invalidated sessions
  still receive their runtime-directory cleanup (best-effort) instead of
  waiting for daemon restart;
- principal disable/delete propagates: disabling a principal deletes all
  its sessions; deleting a principal deletes its launchers (FK cascade)
  and fails with `409 launcher_runtime_active` if any launcher still has
  active runtime;
- an individually disabled launcher stays disabled through parent
  enable/disable transitions; re-enabling the principal or parent does not
  re-enable it;
- in user mode the reserved transparent owner chain rejects corrupting
  mutations (see [User-mode owner reservation](#user-mode-owner-reservation)).

### Credential lifecycle

- **Principal credentials** are lifecycle resources of their owning
  Principal (`Principal └── credential (0..N, named)`). The canonical CLI
  is `principal credential create|list|revoke|rotate`; `create` and
  `revoke` remain administrator-controlled.
  - `GET /credentials` is the scope-first principal credential list: the
    authenticated authority establishes the maximum visibility (an admin
    token sees every Principal's credentials, a Principal credential sees
    its own Principal's), and the optional `?principal=NAME` filter can
    only narrow that visibility — never expand it. A Principal credential
    naming another Principal, and an unknown Principal filter, are the
    same non-disclosing `404 principal_not_found` as any other principal
    endpoint; a Launcher credential is `401`. `GET
    /principals/{username}/credentials` remains the single-Principal form
    of the same query.
  - `POST /principals/{username}/credentials/{name}/rotate` rotates a
    named credential in one atomic server-side operation: the token hash
    is replaced in the same transaction (credential ID, name, ownership,
    and created_at are unchanged, no second row is created), the old
    bearer is rejected immediately, and the new bearer is returned exactly
    once. Rotation always targets the current active credential with that
    name: revoked historical rows that share the name through documented
    name reuse are never the target, a name that only has revoked history
    is `409 credential_revoked`, and a name that never existed is
    `404 credential_not_found`; the guarded mutation fails closed against
    stale concurrent state, so a rotation never resurrects a revoked row.
    The mutation is scoped by the exact owning Principal ID resolved under
    the request authority (an admin resolves the current same-name
    Principal; a Principal credential uses its exact authenticated
    Principal ID), never re-keyed by username, so a Principal deleted and
    recreated under the same username can never rebind a rotation onto the
    replacement Principal's credential — a vanished owner fails closed
    without mutating any row.
  - The compatibility CLI `credential create|list|revoke` shares the same
    handlers as the canonical `principal credential` commands;
    `credential create --name` is optional and uses the literal name
    `default` when omitted.
  - CLI resolution is per-command: `list` is the scope-first Query with
    no auth introspection (one server-authorized query; the daemon
    applies the scope-first rule); `create` targets an explicit
    Principal; `revoke` targets the credential ID and performs no
    Principal resolution; `rotate` resolves its target Principal —
    inferred through `GET /auth` where needed (an explicit `PRINCIPAL`
    positional is required for admin authentication).
- **Launcher credentials** are singular per Launcher: issued with `PUT
  /principals/{username}/launchers/{launcher}/credential` (admin or
  owning-Principal authority; the canonical CLI verb is
  `launcher credential create`), replaced by
  `POST .../credential/rotate`, and deleted by `DELETE .../credential`.
  Deleting the credential does not delete the launcher or its sessions; it
  only removes that authentication key. Rotation keeps the launcher
  identity and its sessions: the old bearer is rejected immediately, the
  replacement is authorized, and no second credential row is created.
- **Admin token** rotation (`admin-token rotate`; HTTP
  `POST /admin/token/rotate`) requires the current
  token; the new token is shown once, the old token is invalid
  immediately, and no restart is required.

Revoking a Principal or Launcher credential does not invalidate issued
sessions; deleting a Launcher credential leaves its launcher's sessions
owned and running but removes that authentication key.

### Session lifecycle

```
POST /build or POST /run  (session token)
    │
    ├── resolves session (launcher-owned)
    ├── execution identity = principal UID:GID or daemon UID:GID
    ├── registers operation (supervisor admission — atomic with shutdown gate)
    ├── starts async process (cmd.Start under op.mu)
    ├── captures stdout/stderr into bounded LogBuffer
    ├── completion goroutine owns cmd.Wait()
    ├── transitions operation to succeeded/failed
    └── writes audit record with the session's ownership provenance
    │
GET /operations/{id}  (session token)
    │
    └── status, timestamps, exit code, result code
    │
GET /operations/{id}/logs?offset=N  (session token)
    │
    └── incremental operation output
    │
POST /operations/{id}/cancel  (session token)
    │
    ├── graceful SIGTERM to running process
    ├── bounded force-cleanup fallback if process does not exit
    └── operation becomes terminal (status=failed, result_code=cancelled)
    │
DELETE /sessions/{id}  (admin token, Principal credential, or Launcher credential)
    │
    └── physically deletes session row
    │
subsequent requests with deleted session token
    │
    └── 401 Unauthorized
```

Session token semantics:

- session expiry or deletion blocks future requests; expired sessions are
  rejected immediately by the `expires_at` check in `findSessionByToken`,
  and their database rows are physically removed the next time
  `docker-helper serve` starts (`session cleanup` removes them
  offline);
- disabling the owning principal or its launcher deletes the affected
  sessions and blocks their tokens; disabled launchers also reject
  credential authentication;
- removing an allowed root does not invalidate issued sessions;
- an already-started Docker operation continues its lifecycle.

### Ownership migration

The startup migration from the pre-delegation ownership model is idempotent
and restart-safe, guarded by the daemon instance lock. It is a live
compatibility contract: a state directory created by an older release
migrates transparently at startup.

| Legacy state | Result |
|---|---|
| pre-delegation Principal credential rows | preserved byte-for-byte as Principal credentials (`launcher_id NULL`, no launcher credential fabricated) |
| attributable sessions owned directly by the Principal | re-owned by that principal's `default` launcher |
| user-mode NULL-owner sessions | attributed to the daemon-owner default launcher |
| system-mode NULL-owner (admin) sessions | invalidated (removed; never left ownerless) |
| dangling principal reference | migration fails closed, legacy table intact (transaction rollback) |

A dangling reference, a schema-shape mismatch, or a foreign-key violation
in the rebuilt sessions table aborts the migration before commit. Invalid
sessions leave no permanent helper-owned MAC or runtime state: they are
removed before the MAC coordinator is created, and the existing startup
cleanup paths (`ReconcileLiveSessions`, stale-boundary release, and
`cleanupStaleSessionRuntimeDirs`) release any directories or boundaries
whose only consumer was an invalidated session. After migration the final
schema is authoritative and startup never re-adds the direct-principal
ownership column.

## Workspace authorization

### Root-policy hierarchy

The workspace authorization hierarchy has three policy ceilings, then one
concrete selection:

```
policy ceilings:  global roots
                    ⊇ effective Principal roots
                        ⊇ effective Launcher roots
concrete:               Session workspace (ephemeral)
```

- **Global allowed_roots** (config.json) — the system-wide authorization
  ceiling, managed by `config allowed-root list/add/remove`. Changing
  allowed roots is a policy-only operation; it does NOT prepare MAC state.
- **Principal allowed roots** (database) — per-principal narrowing, managed
  by `principal allowed-root add/remove`. Does not prepare MAC.
- **Launcher allowed roots** (database, `restricted` scope only) —
  per-launcher narrowing beneath one principal; `inherit` scope applies no
  launcher-level narrowing. Evaluated at session-creation time against
  current state. Does not prepare MAC.
- **Session workspace** (ephemeral, not a persisted policy level) —
  selected only at session creation time via `session create --workspace
  PATH`. Must be under a global, the principal, and (when restricted) the
  launcher allowed root.

`effective Principal roots` is the Principal ceiling owned by
`computeEffectivePrincipalRoots`: the intersection of the global roots and
the stored Principal roots, with one documented exception — in user mode the
daemon-owner Principal with zero stored roots collapses onto the global
roots. `effective Launcher roots` are the Principal ceiling for `inherit`
scope, or its intersection with the Launcher's stored roots for `restricted`
scope (stale out-of-ceiling Launcher roots are rejected, never truncated).

MAC state is derived from the concrete live session/workspace lifecycle,
not from the authorization ceiling. Only the session workspace participates
in MAC preparation: AppArmor managed-boundary coverage for the workspace, or
SELinux Session workspace fcontext labeling with MCS constraints. The
authorization roots never own MAC state; a broader ceiling never causes
recursive MAC relabeling. Adding `/opt` as a global allowed root must never
imply recursive relabeling of `/opt/**`.

Distinct from session workspace MAC preparation, system-mode `docker-helper init`
under enforcing SELinux applies the installed fcontext rules to docker-helper's
own deployment state: the helper-owned `/etc/docker-helper/**` (config) and
`/var/lib/docker-helper/**` (state) trees are relabeled to
`docker_helper_config_t` / `docker_helper_state_t` immediately after they are
created and before the admin token is written, so the first daemon start can
open its database. Init also runs an exact-path restorecon on the Docker CLI
executable the daemon will exec (resolved over the same PATH the service uses),
so the confined `docker_helper_t` domain can execute it with the
`container_runtime_exec_t` type the distro/container-selinux fcontext rules
already define — never a recursive `/usr/bin` relabel and never a `bin_t`
execute grant. A relabel failure aborts init (no partial initialization).
AppArmor system mode and user mode perform no SELinux relabel.

Initialization defaults follow the selected deployment identity:

- interactive non-root initialization defaults `allowed_roots` to the current
  user's home directory;
- interactive root initialization defaults `allowed_roots` to `/home`;
- the shared root validator permits root to select exact `/home` or `/opt`,
  while non-root validation continues to reject those broad namespaces;
- non-interactive initialization requires an explicit `--allowed-root`.

When a non-root `docker-helper init` detects an existing system daemon, it uses
the Principal-credential onboarding path instead of creating a competing user
daemon configuration. The standalone `credential install` command exposes the
same user-scoped credential store directly.

Application acceptance of a root does not by itself prove MAC access. AppArmor
requires the corresponding managed boundary rule. SELinux requires a permitted
workspace file type.

### Launcher scope

Launcher scope narrows the Principal authorization ceiling for sessions
created through that launcher; it never widens and never owns MAC state:

| Launcher scope | Effective roots for new sessions |
|---|---|
| `inherit` | the effective Principal ceiling (canonical owner above) |
| `restricted` | effective Principal ceiling ∩ launcher allowed roots |

Evaluation happens at session-creation time against current state; a
launcher root that is no longer under the principal ceiling is rejected
then (never silently truncated), so stale out-of-ceiling roots cannot
produce a session outside the principal's allowed roots.

Scope replacement remains the one complete-scope mutation:
`PUT /principals/{username}/launchers/{launcher}/allowed-roots` accepts
the complete scope (`{"scope": "inherit", "allowed_roots": []}` or
`{"scope": "restricted", "allowed_roots": [...]}`); the CLI exposes it
only as the fixed single-request `launcher allowed-root inherit` verb —
there is no read-modify-write policy mutation through the CLI. The narrow
per-root mutations are separate single-request operations:
`POST .../allowed-roots` adds one root (narrowing an inherit launcher to
restricted scope atomically with the insert) and `DELETE
.../allowed-roots` removes one root; removal never changes the scope mode,
so removing the last root leaves the launcher restricted with an empty
root set (fail-closed: no admissible session workspace until an explicit
inherit). Both reject the user-mode reserved default launcher with
`409 user_mode_owner_reserved`. The CLI verbs are `launcher allowed-root
add/list/remove/inherit` and `principal allowed-root add/list/remove`;
`launcher scope` no longer exists in the CLI.

### Session workspace

Each session is bound to a single workspace directory. An agent with a
session for `/home/user/project-a` cannot access `/home/user/project-b`,
even if both are inside an allowed root.

All paths are resolved through `filepath.EvalSymlinks` before comparison.
This prevents symlink-based escape attacks at validation time. Note:
`EvalSymlinks` resolves the path at a point in time. By itself it
does not solve TOCTOU problems where the filesystem changes between
validation and use. For operations that pass paths to Docker as strings,
additional measures (such as FD-relative traversal or inode pinning) are
required to close the gap; the operation-specific mitigations are under
[Filesystem policy](#filesystem-policy).

The canonical containment API lives in `path_containment.go`:

- `pathWithin(root, path)` — returns true if `path` is within `root`
  (equality allowed). Both arguments must be canonical (absolute, cleaned).
- `pathStrictlyWithin(root, path)` — returns true if `path` is a proper
  descendant of `root`. Equality returns false.

Argument order is always root first, path second. These functions correctly
handle the prefix trap: `pathWithin("/data", "/data2")` returns false.

When a session is created, the workspace path is resolved through
`EvalSymlinks` and the canonical workspace is stored in the database.
When a build or run request specifies a path relative to the workspace,
the resolved path is compared against the canonical workspace; if the
resolved path escapes the workspace, the request is rejected.

### Policy introspection

Two read-only policy introspection surfaces expose the daemon's canonical
policy for completion and tooling. Both are Queries: scope and authority
are checked server-side, the projection is resolved as one coherent
lifecycle snapshot under the same `lifecycleMu` serialization boundary the
real mutations use, and neither surface widens authority.

- `GET /principals/{username}/effective-allowed-roots` — the target
  Principal's effective roots, computed daemon-side by the canonical
  effective-Principal-root policy owner. Authority follows the stable
  Principal-control target owner: an Admin authority follows the current
  same-username Principal, a Principal credential resolves its exact
  authenticated Principal ID (a stale authority whose Principal was deleted
  fails closed as the non-disclosing `404 principal_not_found` and never
  observes a recreated same-username Principal), and a Launcher credential
  is `401`.
- `GET /sessions/create-policy` — the complete Session-create projection
  (target Launcher, ownership names, and the three-ceiling effective root
  scope) that a Session created right now with this authority would use,
  resolved by the same owner as real creation (`resolveCreatePolicy`). The
  query optionally carries the typed create selectors (`principal` = a
  Principal username, `launcher` = a Launcher name or `dhl_` ID); the
  launcher selector is resolved daemon-side through the shared
  Launcher-selector owner (`resolveLauncherSelector`, under the selected
  Principal context for an admin and the authenticated Principal's own
  scope for a Principal credential), so the projection is exactly the
  target a real create with those selectors would use, with the same
  non-disclosing contract for foreign, missing, or authority-illegal
  selectors. Selectorless requests keep the authority-specific default
  resolution (a system-mode admin without a resolvable Launcher receives
  the same missing-selector contract a real create would).

`GET /auth` is the separate identity introspection surface; it reports the
authenticated authority class, not policy (see
[Authority model](#authority-model)).

### MAC lifecycle

MAC state follows the concrete Session lifecycle, not the policy ceilings:

- a created session receives its workspace MAC preparation (AppArmor
  managed-boundary coverage, or SELinux workspace fcontext labeling with
  MCS constraints) as part of the session lifecycle; a preparation failure
  after persistence fails the creation closed (`mac_preparation_failed`);
- a deleted, expired, invalidated, or migrated-away session releases its
  MAC boundary through the existing release paths (including startup
  reconciliation of stale boundaries);
- managed boundaries are helper-owned MAC state (AppArmor's dynamic
  boundary state file), never authorization roots and never config.json
  state.

## Control-plane API and CLI mapping

### Principal

HTTP surface (admin token; Principal-credential authority where stated;
a Launcher credential has no Principal authority):

| Endpoint | Purpose |
|---|---|
| `POST /principals` | atomic Principal provisioning (ownership transaction; optional initial credential) |
| `GET /principals` | list Principals (admin token) |
| `GET /principals/{username}` | show principal (scope-first read: an admin reads any Principal, a Principal credential reads exactly its own — the daemon authorizes the target, the CLI performs no local self-check; a foreign selector is the non-disclosing not-found; a Launcher credential is unauthorized) |
| `PATCH /principals/{username}` | enable / disable (session teardown propagation) |
| `DELETE /principals/{username}` | checked delete (runtime-active guard, FK cascade teardown) |
| `POST /principals/{username}/allowed-roots` | add one Principal allowed root (authorization-only, never MAC preparation) |
| `DELETE /principals/{username}/allowed-roots` | remove one Principal allowed root (authorization-only, never MAC preparation) |
| `GET /principals/{username}/effective-allowed-roots` | Principal effective-root introspection (see [Policy introspection](#policy-introspection)) |
| `POST /principals/{username}/credentials` | create a named Principal credential (one-time token; administrator-controlled) |
| `GET /principals/{username}/credentials` | that Principal's credentials |
| `POST /principals/{username}/credentials/{name}/rotate` | atomic credential rotation |
| `POST /credentials/{id}/revoke` | revoke a credential by its credential ID (administrator-controlled) |
| `GET /credentials` | scope-first Principal credential list (optional `?principal=` narrowing) |
| `DELETE /sessions/{id}` | Session deletion (authority-scoped; see [Session](#session)) |

CLI surface: `principal create|list|show|set|delete`,
`principal allowed-root add|list|remove`,
`principal credential create|list|revoke|rotate`. Every command accepts
the common operator flags (see [CLI conventions](#cli-conventions)).
`principal allowed-root` mutations are authorization-only and never
prepare MAC state; `principal allowed-root list` is a CLI projection of
the show endpoint (`GET /principals/{username}`), not a separate HTTP
list route.

### Launcher

HTTP surface (admin token or owning-Principal credential; a Launcher
credential cannot manage launchers):

| Endpoint | Purpose |
|---|---|
| `POST /principals/{username}/launchers` | launcher provisioning (optional one-time credential issuance) |
| `GET /principals/{username}/launchers` | list that Principal's launchers |
| `GET /launchers` | scope-first launcher list (authority visibility + optional `?principal=` and `?launcher=` narrowing filters) |
| `GET /principals/{username}/launchers/{launcher}` | show launcher |
| `PATCH /principals/{username}/launchers/{launcher}` | rename / enable / disable |
| `PUT /principals/{username}/launchers/{launcher}/allowed-roots` | atomic scope replacement |
| `POST /principals/{username}/launchers/{launcher}/allowed-roots` | add one allowed root (narrow-to-restricted on the first add) |
| `DELETE /principals/{username}/launchers/{launcher}/allowed-roots` | remove one allowed root (never changes scope mode) |
| `DELETE /principals/{username}/launchers/{launcher}` | delete launcher (checked delete) |
| `PUT /principals/{username}/launchers/{launcher}/credential` | issue the launcher's single credential |
| `GET /principals/{username}/launchers/{launcher}/credential` | show credential metadata |
| `POST /principals/{username}/launchers/{launcher}/credential/rotate` | rotate the credential |
| `DELETE /principals/{username}/launchers/{launcher}/credential` | delete the credential |

Individual Launcher control uses the Principal-scoped locator
`/principals/{username}/launchers/{launcher}`: `{launcher}` accepts a
Launcher ID or a grammar-valid Launcher name, resolved under the
already-resolved Principal — an exact `dhl_<32 hex>` selector looks up
that ID under this Principal, a name looks up `(principal_id, name)`,
and a malformed, missing, or foreign selector is the same non-disclosing
`404 launcher_not_found` (never a fallback from an ID-shaped selector to
a name lookup, never a global name scan).

Launcher projection: `{"id", "principal", "name", "enabled", "scope",
"allowed_roots", "created_at"}`. Create response carries the one-time
credential token only when issuance was requested. Exactly one credential
may exist per launcher (`launcher_credential_exists` on a second issuance;
rotation replaces the existing credential and its token).

CLI surface (every Launcher command accepts the common operator flags):

```
docker-helper launcher create [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] [--name NAME]
    [--allowed-root PATH]... [--issue-credential | --no-credential]
docker-helper launcher list [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] [--launcher LAUNCHER] [--json]
docker-helper launcher show [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] [LAUNCHER]
docker-helper launcher set [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] [--name NAME]
    [--enabled true|false] [LAUNCHER]
docker-helper launcher delete [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] [LAUNCHER]
docker-helper launcher allowed-root add [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] [LAUNCHER] PATH
docker-helper launcher allowed-root list [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] [LAUNCHER]
docker-helper launcher allowed-root remove [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] [LAUNCHER] PATH
docker-helper launcher allowed-root inherit [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] [LAUNCHER]
docker-helper launcher credential create [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] [LAUNCHER]
docker-helper launcher credential show [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] [LAUNCHER]
docker-helper launcher credential rotate [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] [LAUNCHER]
docker-helper launcher credential delete [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] [LAUNCHER]
```

`LAUNCHER` is a Launcher name or ID, and omitting it selects the
Principal's `default` Launcher. `create` and every individual Launcher
command resolve the target Principal the same way: a Principal credential
infers its Principal from `GET /auth`; an admin token must name the
Principal explicitly with `--principal` (omission fails; the CLI never
searches for a `default` Launcher globally) — the single exception is an
admin targeting an individual Launcher by its globally-unique `dhl_` ID,
where the owning Principal is resolved from the daemon's scope-first
launcher list query (`GET /launchers?launcher=<ID>`) instead of being
named. Principal inference is target construction only — the daemon
remains the authorization authority.

`launcher list` is the exception: it is a scope-first list Query where the
authenticated authority establishes the visible Launchers (admin without a
filter: every Principal; a Principal credential without a filter: its own)
and the optional `--principal` selector is only a filter that can narrow
visibility, never expand it — a foreign filter is the same non-disclosing
`404 principal_not_found` as the nested list, a Launcher credential is
`401`, and no auth introspection happens in the CLI. The `--launcher`
selector narrows server-side inside the resolved scope: under a resolved
Principal scope (Principal credential, or admin with `--principal`) a
Launcher name or ID is accepted; for an unfiltered admin scope only a
globally-unique Launcher ID is accepted and a name is rejected with
`400 launcher_name_requires_principal` because Launcher names are
Principal-scoped and are never searched globally. A missing selector match
is the same non-disclosing `404 launcher_not_found`.

Because a Launcher holds at most one credential, a second `launcher
credential create` is the daemon's normal `409 launcher_credential_exists`
conflict.

### Session

CLI surface (every command accepts the common operator flags):

```
docker-helper session create [--system] [--endpoint ENDPOINT] [--token-file PATH] --workspace PATH [--principal USER] [--launcher LAUNCHER] [--json]
docker-helper session list [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--launcher LAUNCHER] [--json]
docker-helper session delete [--system] [--endpoint ENDPOINT] [--token-file PATH] --id SESSION_ID [--json]
docker-helper session cleanup
```

`session create` — target resolution, selector mapping, and default
resolution are the canonical
[Session creation](#session-creation) pipeline and authority subsections;
the CLI maps `--principal`/`--launcher` onto the wire selectors after
`GET /auth`, and both are mutually exclusive. Returns the session ID,
token, workspace, creation time, and expiration time; the token is shown
only once and cannot be retrieved later.

`session list` — the scope-first Query (see
[Authority model](#authority-model)): authentication establishes the
maximum visibility (`resolveSessionControlScope`), the optional
`--principal USER` (admin authentication
only) and `--launcher LAUNCHER` selectors can only narrow it, never expand
it; the selectors are resolved server-side inside the authority-visible
ownership and composed into the final Session scope served by one existing
Session ownership query (`listSessionsInScope`) — filtering is never
performed client-side.
`principal + launcher` means "that Launcher under that Principal" (it is
deliberately not a conflicting pair like the create selectors). A missing
or unknown Principal is the non-disclosing `404 principal_not_found`, a
missing or foreign Launcher (name or ID) is the non-disclosing
`404 launcher_not_found`, an authority-illegal selector is
`400 invalid_selector`, and a database or system failure keeps its own
error (never collapsed into not-found). Returns a table of active
sessions with ID, workspace, launcher, creation time, and expiration
time.

`session delete` — permanently removes the session; subsequent requests
with the session's token receive 401 Unauthorized. With admin token: can
delete any session. With Principal credential: can only delete sessions
for its principal. With Launcher credential: can only delete sessions
owned by its launcher; foreign sessions return the same `not_found`
outcome (no existence disclosure).

`session cleanup` — removes expired sessions from the local state
database; does not require a running daemon or admin token. Deletes rows
whose `expires_at` has passed; active sessions are untouched; reports the
number of removed rows.

### Completion introspection

The machine-facing completion introspection surface serves the generated
Bash completion. The daemon remains the ownership and authorization
authority; Bash completion is advisory — a failed query (for example when
the daemon is unavailable) degrades silently, and the daemon stays the
final policy boundary at execution time.

- **`completion bash`** — generate the Bash completion script. The
  generated script keeps ONE canonical completion-input owner: it
  reconstructs the real CLI arguments of the completion line from
  `COMP_LINE` up to `COMP_POINT` with the line's own lexical rules —
  unquoted whitespace separates arguments, a backslash escapes the next
  character, single-quoted text is literal, and double-quoted text honors
  backslash escapes — because Readline's default
  word breaking splits typed arguments at characters like `=` and `:`.
  The reconstruction performs no expansion and no multi-command operator
  handling; every consumer of the word list — the command-path walk,
  flag/value recognition, typed selector extraction, operator-argument
  forwarding, positional counting, and the policy-root query forwarding —
  reads that normalized view, so both the separated
  `--flag VALUE` and the inline `--flag=VALUE` form, and values physically
  broken such as `http://HOST:PORT` endpoints, carry identical logical
  semantics. The user's `COMP_WORDBREAKS` is never modified.
- **`completion selectors principal|launcher`** — machine-facing selector
  introspection for the values of the `--principal`/`--launcher` flags and
  of the positional `[LAUNCHER]` argument and the `principal show` USER
  positional (the same owner for all of them).
  `selectors principal` is command-context aware through the `--command`
  flag: an admin receives the daemon's Principal names on every command
  carrying the selector, a Principal credential receives exactly its own
  username on the Launcher command families and on the `principal show` USER
  positional (where the explicit own selector is legal) and nothing on both
  Session command paths — session
  create rejects every `--principal` under a Principal credential and
  session list rejects every Principal selector, even the credential's own
  Principal — and a Launcher credential receives nothing. `selectors
  launcher` honors the typed `--principal` context: an admin with a
  context receives that Principal's Launcher names, an admin without one
  receives only globally resolvable `dhl_` Launcher IDs (a name is never
  searched globally), a Principal credential receives its own Launchers'
  names — including with its own typed `--principal` context, which the
  daemon authorizes as an in-scope narrowing — and a Launcher credential
  receives nothing. A foreign or missing context fails with the daemon's
  non-disclosing contract and degrades silently.
- **`completion roots principal`** — the target Principal's effective
  allowed roots (target from `--principal` or inferred from the
  credential; the daemon authorizes the query; consumes
  `GET /principals/{username}/effective-allowed-roots`). With
  `--authority-only` it prints only the authenticated operator authority
  for shell-completion introspection; completion authority introspection
  reuses this surface so the parser tree, help tree, and completion tree
  remain identical (no hidden command nodes).
- **`completion roots session`** — the Session-create effective allowed
  roots for the current authority (consumes `GET /sessions/create-policy`).
  The typed `--principal`/`--launcher` selectors (both `--flag VALUE` and
  `--flag=VALUE` forms) are forwarded to the daemon; the daemon resolves
  the same target a real `session create` with those selectors would use
  through its canonical owners, and a rejected selector fails silently so
  completion degrades.

The daemon-backed policy completions are exactly:

| Command flag | Policy query consumed |
|---|---|
| `launcher create --allowed-root` | Principal effective-root query |
| `session create --workspace` | Session create-policy query (typed `--principal`/`--launcher` forwarded; the daemon resolves the same target a real create would) |

Positional `[LAUNCHER] ... PATH` completion on
`launcher allowed-root add/remove` is generic filesystem completion
(directories for add, any filesystem entry for remove); the daemon remains
the final policy boundary and rejects a root outside the effective
Principal ceiling at execution time. `config allowed-root add` and
`principal allowed-root add` remain generic filesystem completion, as do
all other path-valued flags.

Positional completion of `principal show USER [FIELD]`: USER completes
from the same selector-introspection owner as the `--principal` selector
(above, with the `principal show` command context), and FIELD completes
the canonical show-field vocabulary (`username uid gid home enabled
allowed_roots`) that `extractPrincipalField` owns — one shared vocabulary,
so completion can never offer a field the command rejects. The FIELD word
is a local static vocabulary (no daemon exchange), a typed prefix filters
it, a complete USER+FIELD pair offers nothing further, and the operator
flags never shift the positional counting.

### CLI conventions

Operator flags for API-backed commands (`principal`, `launcher`,
`credential`, `session`, `reload`, `admin-token rotate`,
`completion roots`):

```
--system              connect to system daemon (Unix socket)
--endpoint ENDPOINT   explicit endpoint (/path, unix:///path, or http://127.0.0.1:port)
--token-file PATH     token file path (auto-resolved for Unix sockets)
```

The `-h` / `--help` flag is available on every command and subcommand. It
prints usage information and exits 0 without executing the command action.

`help` is a top-level navigation branch accepting an arbitrary-depth
command path: `docker-helper help [command [subcommand ...]]` (for example
`docker-helper help principal credential rotate`). It navigates the same
canonical command tree as the parser; each branch does not carry its own
`help` pseudo-subcommand (`docker-helper principal help` is an unknown
subcommand).

Exit codes:

| Code | Meaning | Examples |
|------|---------|----------|
| 0 | Success or help displayed | `docker-helper version`, `docker-helper serve --help` |
| 1 | Runtime error (config load, API call, server failure) | `docker-helper init` with an unwritable configuration directory, `docker-helper session create` with unreachable server |
| 2 | CLI syntax or argument validation error | unknown command, missing/unknown subcommand, missing required flag, unexpected positional argument, unknown flag |

Agent-facing CLI commands are `pull`, `build`, `run`, and `registry login`
(described under [Data-plane execution](#data-plane-execution)); operator
commands are `serve`, `init`, `reload`, `session`, `config`, `principal`,
`launcher`, `credential`, `admin-token`, `apparmor`, and `selinux`;
general commands are `version` and `help`.

`apparmor` — manage/check managed AppArmor workspace boundaries for an
AppArmor system deployment (the public `apparmor root` command spelling is
a retained compatibility form; it manages managed workspace boundaries,
not authorization roots).

`selinux` — inspect SELinux system-policy state for a SELinux system
deployment. Subcommand: `check` (validate that the `docker_helper` policy
module is loaded and docker-helper-owned file contexts are consistent with
the active policy; read-only operator diagnostics that never mutates
SELinux state and never inspects dynamic Session MAC resources).

### Config and reload

`docker-helper config <subcommand>` — inspect and modify configuration.
Requires a subcommand: `show`, `set`, `unset`, `allowed-root`.

`docker-helper config show [FIELD]` — without FIELD, prints the complete
effective configuration as JSON (admin_token redacted). With FIELD, prints
only that field's scalar value.

`docker-helper config set FIELD VALUE` — sets a writable field.
Reports `updated` or `unchanged`. If the daemon is running, the change is
applied automatically for reloadable fields. `http_address` is startup-only
and requires a daemon restart.

The operation is transactional: the entire read-modify-write-reload cycle
runs under a process-level lock. If the daemon rejects the reload (e.g.
invalid config), the original config.json is restored atomically and the
command exits with a non-zero status. If rollback and reload after rollback
succeed, config.json and the daemon are synchronized. If the reload after
rollback fails, they may diverge until the next manual reload or restart.

In system mode with the daemon stopped, a successful mutation that changes an
active trusted-CA configuration (`trusted_ca_injection=auto` with a source
path) persists the validated config and prints a warning to stderr: the CA
file was validated locally, but confined MAC readability cannot be verified
until daemon startup, and startup fails closed if the source is not readable
under the active MAC policy. The warning is stderr-only and never claims any
MAC policy allows the source; it is a diagnostic, not a second MAC
authority. When the daemon is running, reload under daemon confinement is the
authoritative proof, and a reload/CA-preparation failure still rolls the
change back (see [Environment and trusted CA](#environment-and-trusted-ca)).

`docker-helper config unset FIELD` — removes an optional field to restore
its default. `allowed_roots` and `session_ttl` are required and cannot be
unset. Reports `unset` or `unchanged`. The same transactional rollback
semantics apply.

`docker-helper config allowed-root <list|add|remove> [PATH]` — manages the
global allowed_roots array. `add` canonicalizes and validates the path;
authorization-only, does NOT prepare MAC state.
`remove` resolves and matches the stored canonical form; rejects removal of
the final global root. `list` prints one canonical root per line.

`http_address` is configurable in system mode only and requires a daemon
restart to take effect. It is not included in the reloadable field list.

`docker-helper reload` — ask the running daemon to re-read `config.json`
and apply changes without restarting. Reloadable fields:
`allowed_roots`, `session_ttl`, `log_level`, `audit_enabled`,
`shutdown_timeout`, `operation_retention_ttl`, `operation_max_completed`,
`operation_log_max_bytes`, `trusted_ca_path`, `trusted_ca_injection`.
Startup-only fields (require daemon restart): `http_address`.
Computed paths (socket, database, state) are not changed. If the daemon is
not running, the command fails with a non-zero exit code. If the new
configuration is invalid, the daemon keeps its current configuration and
the command returns an error.

## Data-plane execution

### Operation lifecycle

This section describes the legacy Docker CLI operation lifecycle owned by
`operationSupervisor` — `build` and `run`. The Engine-backed synchronous
requests (`pull`, and `registry login` validation) follow the synchronous
path described under [Pull](#pull) and [Registry login](#registry-login);
they have no Operation identity and never register with the supervisor.

```
Authentication
    │
Request validation
    │
Canonical path resolution
    │
Boundary validation
    │
Operation registration (supervisor admission — atomic with shutdown gate)
    │
Async process start (cmd.Start under op.mu)
    │
Incremental bounded log capture (cmd.Stdout/stderr → boundedBuffer)
    │
Completion goroutine (cmd.Wait → status transition)
    │
Retention cleanup
```

Authentication validates the session token. Request validation checks
required fields and path relativity per operation. Canonical path
resolution resolves the workspace-relative inputs through `EvalSymlinks`.
Boundary validation enforces workspace containment per operation.

Operation registration uses the operation supervisor admission path
(`admit`), which atomically checks the shutdown gate and registers the
operation under the same mutex. If the daemon is shutting down,
registration is rejected with 503.

The process starts asynchronously. `cmd.Start()` is called under
`op.mu` to synchronize with shutdown termination. stdout and stderr are
captured directly into a thread-safe bounded buffer
(`operation_log_max_bytes`). A completion goroutine owns `cmd.Wait()`
and transitions the operation to `succeeded` or `failed` when the process
exits.

Key internal guarantees that make cancel and shutdown safe:

- explicit cancel and daemon shutdown share the same underlying
  termination lifecycle;
- first termination reason wins and cannot be overwritten by a concurrent
  caller;
- terminal transition is single-winner: the first `succeed()` or `fail()`
  to set `CompletedAt` wins; subsequent calls are no-ops;
- completion goroutine is the sole `cmd.Wait()` owner; termination paths
  only Signal/Kill processes, coordinate force cleanup through the shared
  force phase, and never call `cmd.Wait()` themselves; the cancel handler
  waits for terminal `op.done` before returning;
- graceful termination phase is bounded (default 5s);
- force cleanup is single-owner: only the first caller to reach the force
  phase performs daemon-side container cleanup and CLI process kill;
- concurrent followers wait on a shared absolute force-cleanup deadline
  rather than creating independent timers;
- `/run` force cleanup uses cidfile + daemon-side `docker kill` to prevent
  orphan containers;
- `<kind>.finish` audit event is emitted exactly once per operation.

`POST /build` and `POST /run` return HTTP 201 with an `operation_id`;
the client tracks progress through the operation endpoints.

**`GET /operations/{id}`** (session token) — status and metadata:

| Field | Type | Description |
|-------|------|-------------|
| `ok` | boolean | always true on success |
| `operation_id` | string | operation identifier |
| `status` | string | `running`, `succeeded`, or `failed` |
| `created_at` | string | RFC 3339 timestamp |
| `started_at` | string | RFC 3339 timestamp (present when process started) |
| `completed_at` | string | RFC 3339 timestamp (present when finished) |
| `duration` | string | wall-clock duration (present when finished) |
| `exit_code` | number | process exit code (present on failure) |
| `result_code` | string | `succeeded` or failure code (present when finished) |

**`GET /operations/{id}/logs?offset=N`** (session token) — incremental
operation output:

| Field | Type | Description |
|-------|------|-------------|
| `ok` | boolean | always true on success |
| `operation_id` | string | operation identifier |
| `offset` | number | the requested offset |
| `next_offset` | number | offset for the next request |
| `truncated` | boolean | true if older data was evicted |
| `logs` | string | log data from the requested offset |

Logs are a mixed stdout/stderr byte stream: each operation log is stored
in a bounded buffer of `operation_log_max_bytes`; when the limit is
exceeded, the oldest data is evicted, and `truncated` is true when the
requested offset refers to evicted data.

**`POST /operations/{id}/cancel`** (session token):

- running operation → graceful SIGTERM, then bounded force-cleanup
  fallback if the process does not exit in time;
- operation becomes terminal: `status=failed`, `result_code=cancelled`;
- already-terminal operation → idempotent HTTP 200 with current state;
- unknown or foreign operation → HTTP 404 `operation_not_found`;
- operation logs remain accessible after cancel;
- the response returns after the operation reaches terminal state.

### Build

`docker-helper build` hides the async operation lifecycle; it streams
logs and propagates the container exit code. SIGINT/SIGTERM cancels the
operation (exit 130/143). `--context` must be relative to the session
workspace.

Validation details:

- context may be relative (joined with workspace) or absolute (must be
  inside workspace);
- dockerfile must be relative to context;
- all paths are resolved through `EvalSymlinks` before `pathWithin` checks;
- build-arg names must match `^[A-Za-z_][A-Za-z0-9_]*$`;
- build-arg keys are sorted for deterministic Docker argv;
- build-arg values are never logged or audited (only `build_arg_keys`).

### Run

`docker-helper run` uses the same lifecycle semantics as `build`.
`--mount` source must be relative to the session workspace; target is an
absolute container path.

```
Authentication
    │
Request validation
    │
Workdir validation
    │
Environment validation
    │
Mount resolution
    │
Operation registration (supervisor admission — atomic with shutdown gate)
    │
Async docker run process start (cmd.Start under op.mu)
    │
Incremental bounded log capture (cmd.Stdout/stderr → boundedBuffer)
    │
Completion goroutine (cmd.Wait → status transition)
    │
Retention cleanup
```

Request validation checks that the image field is non-empty. Workdir
validation ensures the value is an absolute path if provided.
Environment validation ensures variable names match
`^[A-Za-z_][A-Za-z0-9_]*$`. Mount resolution resolves each source path
against the workspace and checks for duplicate targets.

Container lifecycle:

- `--rm` — container is removed on exit;
- helper-owned `--cidfile` — records container ID for lifecycle management;
- graceful shutdown — Docker CLI receives SIGTERM;
- force fallback — daemon-side `docker kill` by CID, then CLI process
  force-kill/reap if needed;
- helper-owned containers are never left orphan after shutdown.

Validation details:

- workdir must be an absolute path if provided;
- mount source must be relative to workspace;
- mount target must be absolute;
- source is resolved through `EvalSymlinks` and checked via `pathWithin`;
- environment values are never logged (only names in `env_keys`);
- environment names are sorted for deterministic output;
- `shm_size` accepts a plain integer with an optional binary unit (`k`, `m`,
  `g`; case-insensitive); values must be > 0 and <= 2 GiB (hard-coded
  limit); the parsed byte value is passed to Docker as `--shm-size`; this
  is a `/dev/shm` limit only, NOT a general container memory or CPU limit;
- container runs with fixed security policy (see
  [Security considerations](#security-considerations)).

Containers started by docker-helper carry helper-owned labels used only
for correlation and checked cleanup; user input cannot set or override
them:

```
com.dockerhelper.session.id      = <session id>
com.dockerhelper.launcher.id     = <launcher id>
com.dockerhelper.principal.name  = <principal username>
com.dockerhelper.schema = 1
```

Labels are correlation/cleanup evidence, not authorization state. The
namespace is deliberately neutral: only the Launcher is the Session owner;
the Session and Principal labels are provenance.

### Pull

`POST /pull` authenticates, validates that the image field is non-empty,
and pulls the image reference through the Engine API. The endpoint remains
synchronous and returns the execution result directly in the response;
pull progress output is captured into a bounded buffer of
`operation_log_max_bytes`, and when output exceeds the limit the newest
tail is retained with `truncated: true`.

The pull runs through the single production Engine adapter
(`engineClient`), which calls the Engine `/images/create` pull stream —
the same daemon operation the docker CLI pull path delegated to. The App
resolves one shared `engineClient` for its lifetime; both Engine consumers
(`registry login` and `pull`) receive the same adapter instance instead of
per-request Moby clients, and the adapter's pooled connections are released
once at daemon shutdown. The adapter renders the progress stream into the
line-based combined output form and normalizes Engine failures into
docker-helper error categories; Moby request/response types stay inside the
adapter.

Just before the pull, the handler resolves the stored Session credential
for the exact registry the image reference names (Docker reference
grammar, delegated to the Moby reference parser) and hands it to the
Engine in the `X-Registry-Auth` header. A reference with no registry or
nothing stored for it pulls unauthenticated. The credential never enters
argv, environment, logs, audit, SQLite, or error payloads.

The pull is admitted through the synchronous-execution coordinator: while
the daemon is shutting down, new pulls are refused with
`shutting_down` before any pull starts; a live pull is cancelled at
shutdown and answered with the generic pull failure. A pull whose request
context ends (client disconnect) is answered the same way.

Image reference syntax is delegated to Docker. The helper does not
reimplement the Docker reference grammar; it only checks that the image
field is non-empty. The Engine validates the reference when the pull
executes. If the Engine rejects the reference, the endpoint returns its
standard Docker failure response.

### Registry login

`POST /registry/login` authenticates a session with a Docker registry.

```
Authentication
    │
Request validation
    │
Engine adapter registry validation
    │
Session credential store write
```

Request validation checks that `registry`, `username`, and `password` are
all non-empty.

Registry credential validation runs through the single production Engine
adapter (`engineClient`): the handler resolves the App's shared Engine
adapter — created once per daemon lifetime with API negotiation and closed
at daemon shutdown, the same instance the pull path uses — and calls the
Engine `/auth` endpoint through it, the same daemon operation the docker
CLI login path delegated to. The adapter normalizes Engine failures into
docker-helper error categories; Moby request/response types stay inside the
adapter.

On successful validation the handler persists the credential in the
session-scoped Docker config directory at
`runtimeDir/sessions/<session_id>/docker`, created with `0700`
permissions on first login. The persisted representation is the Docker CLI
`config.json` auths map, keyed by the canonical registry address
(host[:port]; scheme and path stripped), written atomically with `0600`
permissions by docker-helper itself. The credential entry is replaced only
for that registry; previously stored valid credentials are left unchanged
when validation fails. Later pull/build operations read the stored
credential just in time: pull encodes it into the Engine `X-Registry-Auth`
header, and the legacy docker CLI build backend keeps consuming the same
file via `--config`. The password never enters argv, environment,
logs, audit, SQLite, or error payloads. The credential is removed with the
Session runtime directory.

On success, the endpoint returns HTTP 200 with `{"ok": true}`. On failure,
it returns the classified status/code contract owned by
`release-3-api-cli.md`: HTTP 422 `registry_auth_denied` for registry
credential denial, HTTP 502 `registry_unavailable` for a registry the
Engine cannot reach, HTTP 503 `backend_unavailable` for an unreachable
Engine, or HTTP 502 `backend_failure` for an unexpected Engine
interaction. The Engine failure payload is never returned to the client;
only a sanitized category message is sent.

### Filesystem policy

#### Bind mounts

Each mount in a `POST /run` request specifies a `source` (relative to the
session workspace) and a `target` (absolute path inside the container).

Allowed:

- `source` is a relative path inside the session workspace;
- `source` resolves to an existing directory or regular file;
- `source` is `.` (the entire workspace);
- `target` is any absolute path;
- `read_only` is true or false;
- the same `source` can be mounted to multiple `target` paths.

Forbidden:

- `source` is an absolute path;
- `source` is empty;
- `source` resolves outside the session workspace (including via symlinks);
- `source` does not exist;
- `source` is not a directory or regular file;
- `target` is empty;
- `target` is not absolute;
- two mounts use the same `target`.

Requiring a relative source ensures the mount is always scoped to the
session workspace; an absolute source could bypass workspace isolation.

#### System-mode run mounts

In system mode, bind-mount sources are first validated with
`pathWithin(workspace, sourcePath)`. The helper then opens "/" as a root
file descriptor. The source path is converted to a root-relative path
and opened with `openat2` using `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`,
and `RESOLVE_NO_MAGICLINKS` relative to the root FD. The resulting inode
is pinned with `open_tree` + `move_mount` into a helper-owned directory
under the runtime path. Docker receives the pinned path, not the original
workspace path.

Pinning requires Linux kernel support for `openat2`, `open_tree`, and
`move_mount`, and `CAP_SYS_ADMIN`. When any of these are unavailable or
fail, the operation fails closed with no pathname fallback. Pinned mounts
are cleaned up as part of the operation lifecycle.

#### User-mode run mounts

In user mode, the resolved mount source must equal the canonical
`session.Workspace`. Subdirectory and file mounts are rejected as
`invalid_mount`.

This restriction exists because user mode lacks `CAP_SYS_ADMIN` for
inode-pinned mounts. The security of the workspace-root mount relies on
the workspace-parent write invariant: the sandboxed agent does not have
host-side write access to the parent directory of the workspace. Since the
agent cannot replace the workspace directory entry, the pathname remains
stable between validation and the Docker bind mount.

#### Build context

The Linux build implementation creates an isolated helper-owned staging
copy of the build context. Traversal is FD-relative and restricted with
`openat2` flags (`RESOLVE_NO_SYMLINKS`, `RESOLVE_BENEATH`). Docker
receives only the staged context and Dockerfile paths, never the
original workspace paths.

On platforms or kernels where `openat2` is unavailable, the operation
fails closed without falling back to original workspace paths.

Staging directories are cleaned up as part of the build operation
lifecycle.

### Environment and trusted CA

Environment variable names must match `^[A-Za-z_][A-Za-z0-9_]*$`. Values
can be any string, including empty. Values are never logged; only variable
names appear in `env_keys`. Environment variables are sorted by name
before being passed to Docker, making the command line deterministic and
reproducible.

Trusted CA injection: when `trusted_ca_injection` is set to `"auto"` and
`trusted_ca_path` points to a valid single PEM X.509 CA certificate,
docker-helper injects the CA into containers started via `POST /run`:

1. **CA validation** — The CA file must be a regular file containing exactly
   one valid PEM-encoded X.509 certificate.

2. **OpenSSL hash** — docker-helper computes the 8-character hex hash
   natively, matching `openssl x509 -hash -noout` (OpenSSL 3.x
   subject_hash). The algorithm canonicalizes the X.509 subject name
   (UTF-8 conversion, lowercase, whitespace normalization), DER-encodes
   it without the outer SEQUENCE wrapper, and takes SHA-1 truncated to
   4 bytes (little-endian hex). No external `openssl` binary is required.

3. **Runtime artifact** — The CA is materialized in the helper-owned runtime
   directory:
   ```
   $RUNTIME_DIR/trusted-ca/<sha256-of-source-bytes>/
       ├── ca.pem (0644)
       └── <openssl-hash>.0 -> ca.pem
   ```
   The directory is created with mode `0755`. The fingerprint directory is
   immutable by content; re-preparing the same CA is idempotent. Changing the
   CA creates a new fingerprint directory.

4. **Mount injection** — A read-only bind mount is added:
   ```
   --mount type=bind,source=<prepared-dir>,target=/run/docker-helper/trusted-ca,readonly
   ```

5. **Environment injection** — The following environment variables are added
   (if not already set by the user):
   ```
   SSL_CERT_DIR=/run/docker-helper/trusted-ca:/etc/ssl/certs:/etc/pki/tls/certs
   NODE_EXTRA_CA_CERTS=/run/docker-helper/trusted-ca/ca.pem
   ```

6. **Explicit-env-wins** — If the user explicitly sets `SSL_CERT_DIR` or
   `NODE_EXTRA_CA_CERTS`, their values are preserved and not overwritten.

7. **Mount overlap rejection** — Agent mounts whose target overlaps with
   `/run/docker-helper/trusted-ca` (exact match, ancestor, or descendant)
   are rejected as `invalid_mount` when injection is enabled.

8. **Audit** — Both `run.start` and `run.finish` audit records include a
   boolean field `trusted_ca_injected` (true when injection is active).
   The audit does not disclose the host CA path or runtime source.

9. **Disabled mode** — When `trusted_ca_injection` is `"disabled"` (the
   effective default), no mount, environment injection, or audit field is
   added. The existing run contract remains unchanged.

10. **Scope** — CA injection applies only to `POST /run`. It does not affect
    `POST /build`, `POST /pull`, or other endpoints.

11. **Limitations** — Only one CA is supported. Java `cacerts` is not
    supported. Other CA-related environment variables like `SSL_CERT_FILE`,
    `REQUESTS_CA_BUNDLE`, or `CURL_CA_BUNDLE` are not used.

`trusted_ca_path` is an absolute path to the accepted CA file. In user mode any
readable absolute path works. In system mode the confined daemon must also be
permitted to read the source under the active MAC backend, so the supported
locations are the helper-owned `/etc/docker-helper` config tree (always
readable by the confined daemon) and the standard system CA-bundle paths the
shipped AppArmor/SELinux policy permits. Paths outside the shipped policy are
the operator's responsibility to make readable under that MAC policy. There is
no silent downgrade: CA preparation and daemon start/reload fail closed when
the source cannot be read. Older configurations continue to work without
migration or copying the CA.

### Retention and cancellation

Completed operations are retained in memory. Cleanup is opportunistic and
runs on access:

- `operation_retention_ttl` — operations older than this are removed;
- `operation_max_completed` — when more completed operations exist than
  this limit, the oldest are removed;
- `operation_log_max_bytes` — per-operation log buffer size; older output
  is evicted when exceeded.

Cleanup is invoked during operation creation (`POST /build`, `POST /run`)
and operation status access (`GET /operations/{id}`). There is no
background retention worker or periodic ticker.

Cancellation contract: `POST /operations/{id}/cancel` (see
[Operation lifecycle](#operation-lifecycle)) shares the same termination
lifecycle as daemon shutdown; the first termination reason wins.

CLI signal handling on `build` and `run`:

- SIGINT -> best-effort cancel + exit 130;
- SIGTERM -> best-effort cancel + exit 143;
- cancel failure prints a diagnostic but does not replace the signal exit
  status.

## Service lifecycle

### Shutdown

docker-helper installs a signal handler for SIGINT and SIGTERM. On stop:

- the legacy operation admission gate closes immediately (no new build/run
  operations accepted by `operationSupervisor`);
- the synchronous execution coordinator closes Engine-backed synchronous
  request admission (no new `pull` requests accepted);
- HTTP drain, legacy operation termination, and synchronous request
  termination share one `shutdown_timeout` budget;
- in-flight HTTP requests are drained;
- running build/run processes receive graceful SIGTERM;
- for run, helper-owned containers are cleaned up via cidfile before
  force-killing the Docker CLI process;
- at the reserved force-cleanup window before the deadline, still-running
  processes are force-killed;
- the completion goroutine owns `cmd.Wait()` and reaps each process;
- live synchronous Engine requests (`pull`) are cancelled by context
  cancellation and answered with the generic pull failure; a pull has no
  durable Operation identity, so there is no persisted cancellation state
  and nothing to recover;
- after synchronous request termination, the shared Engine adapter's pooled
  Moby connections are released;
- the lock is held during the entire drain so a second instance cannot
  start until the first fully stops;
- helper-owned build/run processes and containers are never left unmanaged
  after shutdown.

After `TimeoutStopSec=45s`, systemd sends SIGKILL if any processes
remain. The internal `shutdown_timeout` budget is therefore bounded: its
maximum is `30s` (the default too), so the internal graceful budget always
fits inside `TimeoutStopSec=45s`. The last part of the 30s budget is
reserved by the supervisor for force cleanup, which runs concurrently under
the shared absolute deadline and must finish by it — force cleanup never
starts after `shutdown_timeout`. The remaining 15s between the internal
maximum and `TimeoutStopSec=45s` sits outside the daemon budget and covers
process final exit, scheduler/kernel/systemd overhead, and systemd's SIGKILL
fallback if the process still has not exited; it is not intended for the
regular internal force-cleanup phase. New values above `30s` are rejected by
`config set`. For upgrade compatibility with releases that accepted any
positive `shutdown_timeout`, a persisted value above `30s` is loaded but
bounded to `30s` at startup/reload with an operational warning; `config
show` reports the bounded effective value. The shipped system and user
units both carry `TimeoutStopSec=45s`.

The shutdown budget is read from the daemon's *current* configuration at the
moment shutdown begins: a `shutdown_timeout` changed via reload is honored by
the next stop without a restart.

### systemd units and hardening

Two units are shipped: `packaging/systemd/user/docker-helper.service` and
`packaging/systemd/system/docker-helper.service`. Both are `Type=exec`
with `Restart=on-failure`, `RestartSec=5s`, `TimeoutStopSec=45s`,
`UMask=0077`, and `StartLimitIntervalSec=60s` / `StartLimitBurst=3`
(restart limit: if reached, `systemctl reset-failed` before starting
again).

Shared hardening: `NoNewPrivileges=true`, `RestrictNamespaces=true`,
`RestrictRealtime=true`. `RestrictSUIDSGID` is deliberately omitted in
both units because its seccomp filtering blocks the `openat2` staging
primitive on supported kernels.

User unit: `ExecStart=%h/.local/bin/docker-helper serve` with
`ExecReload` for non-restarting reloads; configuration and state
directories are created by `docker-helper init` using standard XDG paths;
non-standard `XDG_CONFIG_HOME` and `XDG_STATE_HOME` are supported when
they are present in the systemd user manager environment. Logout
behavior follows the user manager: without
`loginctl enable-linger`, the user manager and all services normally stop
after the last user session ends; with linger, the user manager continues
running and the service stays active after logout.

System unit:

- `ExecStart=/usr/bin/docker-helper serve`; `ExecReload=... reload
  --system`.
- Directory declarations: `ConfigurationDirectory=docker-helper`
  (mode `0755`), `StateDirectory=docker-helper` (mode `0700`),
  `RuntimeDirectory=docker-helper` (mode `0755`), and
  `RuntimeDirectoryPreserve=restart` — the RuntimeDirectory inode is
  preserved across service restarts so long-lived agent containers with a
  bind-mount of `/run/docker-helper` continue to see the updated socket
  after `systemctl restart`; normal cleanup semantics still apply on a
  real service stop.
- MAC binding: `AppArmorProfile=docker-helper-system` on AppArmor systems
  and `SELinuxContext=system_u:system_r:docker_helper_t:s0` on SELinux
  systems, guarded by `ConditionSecurity=|apparmor` / `ConditionSecurity=|selinux`.
- Explicit PATH contract: the declared `Environment=PATH` must stay exactly
  synchronized with the daemon's Docker CLI search path (`dockerCLISearchPath`
  in `selinux_deploy.go`) — the daemon resolves the Docker CLI over this
  PATH, and system init relabels that same executable for enforcing
  SELinux; the two lookup rules must never diverge.
- Additional hardening: `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
  AF_NETLINK`, `MemoryDenyWriteExecute=true`, `LockPersonality=true`,
  `ProtectClock=true`, `ProtectHostname=true`, `PrivateTmp=false`.

Filesystem-namespace directives (`ProtectSystem`, `ProtectHome`,
`ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`,
`ProtectControlGroups`, `PrivateDevices`, `PrivateMounts`, and path-based
mount specifications) are deliberately not used in the system unit: any
directive that creates a separate mount namespace hides mount pins created
by docker-helper from dockerd (bind mounts would fail with permission
denied). Access to kernel and cgroup paths is restricted by the AppArmor
default-deny policy instead; ProtectHome is disabled to allow workspace
access. The hardening profile does not by itself create a full security
boundary: access to the Docker socket means the process-level directives
only forbid specific operations.

## Errors and observability

### Health

`GET /health` returns a 200 OK response with a JSON body indicating the
server is running. No authentication is required. This endpoint is
intended for liveness probes and does not perform any audit logging.

### Error contract

The API returns JSON errors with a stable `code` field. Clients can
distinguish error types programmatically. The `duration` field reports
wall-clock time.

Current error codes (non-exhaustive):

| Code | Endpoint | Condition |
|------|----------|-----------|
| `unauthorized` | all protected | missing/invalid token |
| `invalid_json` | all JSON endpoints | request body is not valid JSON |
| `invalid_build_context` | `POST /build` | build request validation failure |
| `invalid_build_args` | `POST /build` | build-arg name invalid |
| `invalid_image` | `POST /run`, `POST /pull` | image name is empty |
| `invalid_mount` | `POST /run` | mount validation failure |
| `invalid_workdir` | `POST /run` | workdir is not an absolute path |
| `invalid_environment` | `POST /run` | environment variable name invalid |
| `invalid_shm_size` | `POST /run` | shm_size invalid, zero, or over 2 GiB |
| `invalid_workspace` | `POST /sessions` | workspace invalid or outside AllowedRoot; the message carries the actionable cause |
| `missing_launcher_selector` | `POST /sessions` | system-mode admin request supplies no launcher selector |
| `launcher_not_found` | `POST /sessions` | the selected launcher does not exist under the resolved principal |
| `launcher_unavailable` | `POST /sessions` | the selected launcher or its principal is durably disabled, or a final stale-owner recheck refuses the creation (422) |
| `invalid_session_id` | `DELETE /sessions/{id}` | session ID is empty |
| `principal_not_found` | `GET /sessions?principal=` | the selected Principal does not exist (list narrowing; non-disclosing) |
| `launcher_not_found` | `GET /sessions?launcher=` | the selected Launcher does not exist inside the narrowed scope (list narrowing; non-disclosing) |
| `launcher_name_requires_principal` | `GET /sessions?launcher=` | a Launcher-name narrowing selector was supplied without a Principal scope (names are never searched globally) |
| `invalid_selector` | `GET /sessions` | a narrowing selector is illegal for the authenticated authority (a Principal selector under a Principal credential, any selector under a Launcher credential) |
| `shutting_down` | `POST /build`, `POST /run`, `POST /pull` | daemon is shutting down |
| `docker_pull_failed` | `POST /pull` | pull: unexpected Engine failure, unreachable Engine, or cancelled pull |
| `image_not_found` | `POST /pull` | pull: image/repository not found |
| `pull_access_denied` | `POST /pull` | pull: authentication/authorization denied |
| `registry_unavailable` | `POST /pull`, `POST /registry/login` | registry/network/backend failure |
| `registry_auth_denied` | `POST /registry/login` | docker login: authentication/authorization denied |
| `backend_unavailable` | `POST /registry/login` | the Engine endpoint cannot be reached or observed |
| `backend_failure` | `POST /registry/login` | unexpected Engine interaction prevents a trustworthy result |
| `operation_not_found` | `GET /operations/{id}`, `GET /operations/{id}/logs`, `POST /operations/{id}/cancel` | operation not found or foreign session |
| `user_mode_owner_reserved` | Principal/Launcher mutation endpoints (user mode) | the target is the reserved transparent user-mode owner chain (daemon-owner Principal or its `default` Launcher) and the mutation would violate the startup contract |

After successful session authentication, every `POST /pull`,
`POST /build`, and `POST /run` request produces exactly one of:

- `<kind>.rejected` — the request was rejected before acceptance; or
- `<kind>.start` — the request was accepted. For `build` and `run` the
  request is accepted as an operation (`operation_id` is carried by the
  start event and the response); for `pull` the request is accepted as a
  synchronous Engine request (`pull.start` carries no `operation_id`).

where `<kind>` is `pull`, `build`, or `run`. Authentication failures
remain owned by the existing `auth.failure` path and do not additionally
emit `<kind>.rejected`.

The rejected event schema contains only:

- `event`: `<kind>.rejected`
- `result`: the public API error code (e.g., `invalid_image`, `invalid_mount`,
  `launcher_unavailable`, `shutting_down`, `internal_error`)
- `principal_name`: when available
- `session_id`: from the authenticated session
- `request_id`: from the request context

The `result` field exactly matches the public API response `code`.
Rejected events intentionally omit request payload metadata (image,
mounts, env, command, context, dockerfile, etc.) to avoid logging
partially validated input. No `operation_id` is included because a
rejected request was never accepted as an operation.

### Audit logging

docker-helper writes structured audit records to **stdout**. Operational
logs are written to **stderr**. Both streams use JSON Lines format.
Timestamps in both streams use UTC in RFC 3339 nanosecond format
(`time.RFC3339Nano`). Every audit record contains `"stream": "audit"`;
every operational record contains `"stream": "operational"`. No runtime
free-form text output is emitted; human-oriented CLI output from `init`,
`version`, `help`, and `session` commands remains unchanged.

Audit output is controlled by the optional `audit_enabled` field in
`config.json`. The effective value is resolved using these rules:

1. Explicit `audit_enabled: true` enables audit.
2. Explicit `audit_enabled: false` disables audit, including when
   `log_level` is `debug`.
3. When `audit_enabled` is absent:
   - **system mode** (running as UID 0): audit is always enabled,
     regardless of `log_level`;
   - **user mode** (running as non-root):
     `log_level=debug` enables audit; every other `log_level` disables it.

`docker-helper init` omits `audit_enabled` from the generated config.
In user mode, since the default `log_level` is `info`, audit is disabled
by default. In system mode, audit is enabled by default. The
`audit_enabled_source` field in `docker-helper config show` indicates how
the effective value was derived: `"explicit"` (set in config.json),
`"system_default"` (absent, system mode), or `"log_level"` (absent, user
mode derived from `log_level`). When audit is disabled, no audit records
are written, no audit encoding or writer errors are emitted, and
operational logging and request handling are unaffected.

Common audit fields:

| Field | Type | Description |
|-------|------|-------------|
| `time` | string | UTC timestamp, RFC 3339 with nanoseconds |
| `stream` | string | always `audit` for these records |
| `event` | string | event name |
| `result` | string | outcome code when the event represents an outcome; omitted on start events |
| `session_id` | string | session identifier (omitted on `auth.failure`) |
| `duration` | string | wall-clock duration, e.g. `"1s"`, `"150ms"` |

Additional fields depend on the event. Fields with empty or zero values
are omitted from the JSON output.

Implemented event families are:

| Area | Events |
|---|---|
| Authentication | `auth.failure`, `auth.session` |
| Sessions | `session.create`, `session.list`, `session.delete` |
| Principals | `principal.create`, `principal.enabled_change`, `principal.allowed_root_add`, `principal.allowed_root_remove`, `principal.delete` |
| Launchers | `launcher.create`, `launcher.list`, `launcher.update`, `launcher.scope_replace`, `launcher.allowed_root_add`, `launcher.allowed_root_remove`, `launcher.delete`, `launcher.credential_issue`, `launcher.credential_rotate`, `launcher.credential_delete` |
| Credentials/admin | `principal.credential_create`, `principal.credential_list`, `principal.credential_rotate`, `principal.credential_revoke`, `admin_token.rotate` |
| Docker operations | `pull.start`, `pull.finish`, `pull.rejected`, `build.start`, `build.finish`, `build.rejected`, `run.start`, `run.finish`, `run.rejected`, `registry.login.start`, `registry.login.finish` |
| Configuration | `config.reload` |

Ownership provenance applies across the event families:

- Successful launcher-control events name the target owner from the
  resolved or resulting Launcher, independent of the caller:
  `principal_name` is the target owner's Principal (never the caller
  identity), with `launcher_id`, `launcher_name`, `launcher_scope`, and
  `launcher_enabled` projecting the resolved or resulting Launcher.
- `session.create` carries `launcher_id`, `launcher_name`, and
  `principal_name` (present on `success` only). `session.delete` records
  the deleted session's ownership (`launcher_id`, `launcher_name`,
  `principal_name`).
- Docker operation events (`build`/`run`/`pull`, including
  `registry.login`) record `principal_name`, `launcher_id`, and
  `launcher_name` from the session's ownership (present for all Sessions).
- Launcher control events keep initiating and target credential provenance
  distinguishable. `initiator_credential_id` names the Principal
  credential that performed the request on every launcher-control event
  (absent for the admin token; Launcher credentials cannot manage
  launchers). `credential_id` carries target-resource semantics: the
  issued, rotated, or revoked Launcher credential on issue/rotate/delete
  events, and the initiating credential on other launcher-control events.
  `credential_name` is recorded where the credential has a name.
- Principal credential events (`principal.credential_list`,
  `principal.credential_rotate`, and the create/revoke events) follow the
  same provenance rule: `principal_name` is the target Principal, and
  `initiator_credential_id` names the initiating Principal credential
  (absent for the admin token). The rotate/list events additionally
  project the target resource (`credential_id`, `credential_name`).

Event schemas with non-obvious fields:

#### build.start

Emitted before a Docker build begins.

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | string | request correlation ID |
| `session_id` | string | session identifier |
| `operation_id` | string | operation identifier |
| `image` | string | target image reference |
| `context` | string | build context path from the request |
| `dockerfile` | string | Dockerfile path from the request |
| `build_arg_keys` | string[] | build-arg names, sorted (present when set; values are never logged) |
| `principal_name` | string | owning Principal name, derived through the Launcher (present for all Sessions) |
| `launcher_id` | string | owning Launcher ID (present for all Sessions) |
| `launcher_name` | string | owning Launcher name (present for all Sessions) |

No `result` or `duration` field.

#### build.finish

Emitted after a Docker build completes (success or failure).
Does not include `request_id` because completion is not request-scoped.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `operation_id` | string | operation identifier |
| `image` | string | target image reference |
| `context` | string | build context path from the request |
| `dockerfile` | string | Dockerfile path from the request |
| `build_arg_keys` | string[] | build-arg names, sorted (present when set; values are never logged) |
| `principal_name` | string | owning Principal name, derived through the Launcher (present for all Sessions) |
| `launcher_id` | string | owning Launcher ID (present for all Sessions) |
| `launcher_name` | string | owning Launcher name (present for all Sessions) |
| `result` | string | `succeeded`, `docker_build_failed`, or `cancelled` |
| `exit_code` | number | present when an exit code is available |
| `duration` | string | build wall-clock time |

#### session.create

Emitted for every `POST /sessions` request after authentication.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier (present on `success` only) |
| `workspace` | string | workspace path from the request |
| `launcher_id` | string | owning launcher (present on `success` only) |
| `launcher_name` | string | owning launcher name (present on `success` only) |
| `principal_name` | string | owning principal (present on `success` only) |
| `credential_id` | string | credential used for the request (non-admin authorities) |
| `result` | string | outcome code |
| `duration` | string | request wall-clock time |

Result codes:

| Code | Condition |
|------|-----------|
| `success` | session created |
| `invalid_json` | request body is not valid JSON |
| `conflicting_selectors` | both `launcher_id` and `principal` selectors present |
| `invalid_selector` | an explicitly present selector is empty or malformed |
| `missing_launcher_selector` | system-mode admin request supplies no selector |
| `launcher_not_found` | the selected launcher does not exist under the resolved principal (404) |
| `launcher_unavailable` | the selected launcher or its principal is durably disabled, or a final stale-owner recheck refuses the creation (422); the launcher may become available again when re-enabled |
| `invalid_workspace` | workspace is empty, does not exist, is not a directory, or is outside the effective allowed roots |
| `mac_preparation_failed` | MAC boundary preparation failed after persistence |
| `database_error` | SQLite write failure |
| `system_error` | cannot resolve `AllowedRoot` path |
| `unknown_error` | unexpected error not classified above |

#### session.delete

Emitted for every `DELETE /sessions/{id}` request after authentication.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier from the URL |
| `workspace` | string | workspace of the session (present when the session was found) |
| `launcher_id` | string | owning launcher ID of the deleted session (present when the session was found) |
| `launcher_name` | string | owning launcher name of the deleted session (present when the session was found) |
| `principal_name` | string | owning principal of the deleted session (present when the session was found) |
| `result` | string | outcome code |
| `duration` | string | request wall-clock time |

Result codes:

| Code | Condition |
|------|-----------|
| `success` | session deleted |
| `invalid_session_id` | session ID is empty in the URL |
| `not_found` | no session with the given ID |
| `database_error` | SQLite failure during delete |
| `unknown_error` | unexpected error not classified above |

#### principal.delete

Emitted for every `DELETE /principals/{username}` request after authentication.

| Field | Type | Description |
|-------|------|-------------|
| `principal_name` | string | principal username from the URL |
| `result` | string | outcome code |
| `duration` | string | request wall-clock time |

Result codes:

| Code | Condition |
|------|-----------|
| `success` | principal deleted |
| `missing_username` | username is empty in the URL |
| `not_found` | no principal with the given username |
| `database_error` | SQLite failure during delete |

#### principal.enabled_change

Emitted for every `PATCH /principals/{username}` request that changes the
`enabled` field, after authentication.

| Field | Type | Description |
|-------|------|-------------|
| `principal_name` | string | principal username from the URL |
| `result` | string | outcome code |
| `duration` | string | request wall-clock time |

Result codes:

| Code | Condition |
|------|-----------|
| `success` | enabled changed |
| `unchanged` | enabled already at requested value |
| `missing_username` | username is empty in the URL |
| `missing_enabled` | enabled field not present in request body |
| `invalid_json` | request body is not valid JSON |
| `not_found` | no principal with the given username |
| `error` | database failure during update |

#### launcher events

Launcher control-plane events share one schema. `launcher.credential_*`
events additionally carry `credential_id` (and `credential_changed` on
rotate when the credential was replaced).

| Field | Type | Description |
|-------|------|-------------|
| `launcher_id` | string | launcher identifier |
| `launcher_name` | string | launcher name (present where known) |
| `launcher_scope` | string | `inherit` or `restricted` (create/scope_replace) |
| `launcher_path` | string | the allowed root a narrow allowed-root mutation touched (allowed_root_add/allowed_root_remove) |
| `launcher_enabled` | boolean | requested enabled state (update) |
| `principal_name` | string | owning principal |
| `result` | string | outcome code |
| `duration` | string | request wall-clock time |

#### run.start

Emitted before a container starts.

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | string | request correlation ID |
| `session_id` | string | session identifier |
| `operation_id` | string | operation identifier |
| `image` | string | container image reference |
| `command_arg_count` | number | number of command arguments (present when command is set) |
| `mounts` | object[] | bind mounts (present when set) |
| `env_keys` | string[] | environment variable names, sorted (present when set; values are never logged) |
| `shm_size` | string | /dev/shm size from the request (present when set) |
| `trusted_ca_injected` | boolean | true when trusted CA injection is active for this run |
| `principal_name` | string | owning Principal name, derived through the Launcher (present for all Sessions) |
| `launcher_id` | string | owning Launcher ID (present for all Sessions) |
| `launcher_name` | string | owning Launcher name (present for all Sessions) |

No `result` or `duration` field.

Each entry in `mounts` has:

| Field | Type | Description |
|-------|------|-------------|
| `source` | string | source path relative to the workspace |
| `target` | string | absolute target path inside the container |
| `read_only` | boolean | whether the mount is read-only |

#### run.finish

Emitted after a container run attempt completes.
Does not include `request_id` because completion is not request-scoped.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `operation_id` | string | operation identifier |
| `image` | string | container image reference |
| `command_arg_count` | number | number of command arguments (present when command is set) |
| `mounts` | object[] | bind mounts (present when set) |
| `env_keys` | string[] | environment variable names, sorted (present when set) |
| `shm_size` | string | /dev/shm size from the request (present when set) |
| `trusted_ca_injected` | boolean | true when trusted CA injection was active for this run |
| `principal_name` | string | owning Principal name, derived through the Launcher (present for all Sessions) |
| `launcher_id` | string | owning Launcher ID (present for all Sessions) |
| `launcher_name` | string | owning Launcher name (present for all Sessions) |
| `result` | string | outcome code |
| `exit_code` | number | container exit code (present when available) |
| `duration` | string | container run attempt wall-clock time |

Result codes:

| Code | Condition |
|------|-----------|
| `succeeded` | container exited with status 0 |
| `docker_run_failed` | Docker failed to start the container |
| `container_exit_nonzero` | container exited with a non-zero status |
| `cancelled` | operation cancelled by client |

#### pull.start

Emitted before a pull begins.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `image` | string | image reference |
| `principal_name` | string | owning Principal name, derived through the Launcher (present for all Sessions) |
| `launcher_id` | string | owning Launcher ID (present for all Sessions) |
| `launcher_name` | string | owning Launcher name (present for all Sessions) |

No `result` or `duration` field.

#### pull.finish

Emitted after a pull completes (success or failure).

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `image` | string | image reference |
| `principal_name` | string | owning Principal name, derived through the Launcher (present for all Sessions) |
| `launcher_id` | string | owning Launcher ID (present for all Sessions) |
| `launcher_name` | string | owning Launcher name (present for all Sessions) |
| `result` | string | `success` or `pull_error` |
| `exit_code` | number | not emitted: the Engine pull path has no CLI exit code |
| `duration` | string | pull wall-clock time |

#### registry.login.start / registry.login.finish

Registry login events record the session's ownership provenance:
`session_id`, `registry`, and `principal_name`, `launcher_id`,
`launcher_name` (the finish event additionally carries `result` =
`success` or `login_failed`, and `duration`). The password and username
are never included in audit records.

#### auth.failure

Emitted for every failed authentication or authorization attempt. No
`session_id` is included because the session is not reliably established.

| Field | Type | Description |
|-------|------|-------------|
| `method` | string | HTTP method of the request |
| `path` | string | request path |
| `result` | string | failure reason |

The `result` vocabulary follows the endpoint family that rejected the
request. The credential-authentication classifier
(`classifyCredentialAuthFailure`) recognizes exactly five failure modes:
unknown credential, revoked credential, disabled Principal, disabled
Launcher, and database failure; every other error fails closed as a
database failure so an unknown failure can never surface as a 401.

Header parse and admin-token codes:

| Code | Condition |
|------|-----------|
| `<family>.parse_failed` | `Authorization` header missing, non-Bearer scheme, or empty/malformed token on a credential-control family (`launcher`, `principal`, `credential`) |
| `auth.parse_failed` | same on `GET /auth` |
| `parse_failed` | header parse failure on a Session-control endpoint |
| `admin.parse_failed` | `Authorization` header missing, non-Bearer, or empty/malformed on an admin endpoint |
| `admin.wrong_token` | Bearer token does not match the configured admin token |
| `session.parse_failed` | header parse failure on a session-token data-plane endpoint |

Credential authentication on Session control (create/list/delete) is
discriminated per failure mode:

| Code | Condition |
|------|-----------|
| `credential.not_found` | no credential matches the bearer token |
| `credential.revoked` | the credential was revoked |
| `principal.disabled` | the credential's Principal is disabled |
| `launcher.disabled` | the credential's Launcher is disabled |

A disabled Launcher is classified as `launcher.disabled` — it is never
folded into `credential.not_found`.

Every other credential-bearing family (Launcher/Principal/credential
management, `GET /auth`) collapses all expected credential failures into
one non-disclosing code, so the audit and wire response do not disclose
which of unknown/revoked/disabled applied:

| Code | Condition |
|------|-----------|
| `<family>.unauthorized` (`launcher.unauthorized`, `principal.unauthorized`, `credential.unauthorized`, `auth.unauthorized`) | any expected credential failure (unknown, revoked, disabled Principal, disabled Launcher); a valid Launcher credential on a Principal-owned resource management family; a Session token on `GET /auth` |
| `<family>.database_error`, `credential.database_error`, `auth.database_error` | database failure during credential lookup (HTTP 500) |

Session-token data-plane codes:

| Code | Condition |
|------|-----------|
| `session.not_found` | No active session matches the token (unknown, expired, or deleted) |
| `session.database_error` | Database error during session lookup |

#### config.reload

Emitted for every `POST /reload` request after admin authentication.

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | string | request correlation ID |
| `result` | string | `success` or `invalid_config` |
| `duration` | string | request wall-clock time |

When `audit_enabled` changes from `true` to `false`, the `config.reload`
success event is written before audit is disabled, ensuring the event
is not lost. When `audit_enabled` changes from `false` to `true`, the
event is written after the new configuration is applied.

Request correlation: every HTTP request receives a server-generated
request ID, returned in the `X-Request-ID` response header, added as
`request_id` to every audit record for that request, and added to every
operational record for that request; `session_id` is added to operational
records when authentication has established a session. The server does
not trust or reuse any client-supplied request ID. Async operation
completion (`build.finish`, `run.finish`) is not request-scoped: these
audit records do not include `request_id`, and correlation for async
events uses `session_id` + `operation_id`. **Audit writer failures** are
logged as operational ERROR records with `audit_event` and `operation_id`
(when present) for correlation; existing `request_id` and `session_id`
are preserved. Audit writer failure is best-effort and does not affect
the request or operation outcome.

Sensitive data — the following are **never** logged to either the audit
or operational streams:

- the raw HTTP request body;
- HTTP request headers;
- `Authorization` header values and the token used for authentication
  (admin tokens, Principal credentials, Launcher credentials, and session
  tokens are never logged);
- environment variable values (only names appear in `env_keys`);
- build-arg values (only names appear in `build_arg_keys`);
- Docker build output or container stdout/stderr;
- command arguments (only `command_arg_count` is recorded);
- registry passwords;
- CA certificate contents.

**Audit records** never contain internal error messages or stack traces.
**Operational ERROR/WARN records** may contain internal error diagnostics
for debugging unexpected failures; these error strings are operational
internals and are not exposed to the API.

The per-operation output buffer accessed via `GET /operations/{id}/logs`
is intentionally separate: it captures the merged stdout/stderr stream
from the Docker CLI process and may contain Docker build/run status
output, container stdout/stderr, and build process output. That stream is
not part of the daemon audit or operational logs.

Examples (ownership provenance fields reflect the documented schema):

Successful build:

```json
{"time":"2026-01-15T10:30:00Z","stream":"audit","event":"build.start","request_id":"req_abcdef1234567890","session_id":"dhs_0a1b2c3d4e5f","operation_id":"op_abcdef1234567890","image":"myapp:v1","context":".","dockerfile":"Dockerfile","principal_name":"alice","launcher_id":"dhl_0f1e2d3c4b5a69788796a5b4c3d2e1f0","launcher_name":"default"}
{"time":"2026-01-15T10:30:05Z","stream":"audit","event":"build.finish","session_id":"dhs_0a1b2c3d4e5f","operation_id":"op_abcdef1234567890","image":"myapp:v1","context":".","dockerfile":"Dockerfile","principal_name":"alice","launcher_id":"dhl_0f1e2d3c4b5a69788796a5b4c3d2e1f0","launcher_name":"default","result":"succeeded","duration":"5s"}
```

Successful session creation:

```json
{"time":"2026-01-15T10:29:55Z","stream":"audit","event":"session.create","session_id":"dhs_0a1b2c3d4e5f","workspace":"/home/alice/project","launcher_id":"dhl_0f1e2d3c4b5a69788796a5b4c3d2e1f0","launcher_name":"default","principal_name":"alice","credential_id":"dhcr_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d","result":"success","duration":"1ms"}
```

Authorization failure:

```json
{"time":"2026-01-15T10:31:00Z","stream":"audit","event":"auth.failure","method":"POST","path":"/run","result":"session.not_found"}
```

Container run:

```json
{"time":"2026-01-15T10:32:00Z","stream":"audit","event":"run.start","request_id":"req_abcdef1234567890","session_id":"dhs_0a1b2c3d4e5f","operation_id":"op_abcdef1234567890","image":"alpine:3.19","command_arg_count":3,"mounts":[{"source":".","target":"/workspace","read_only":true}],"env_keys":["APP_MODE"],"principal_name":"alice","launcher_id":"dhl_0f1e2d3c4b5a69788796a5b4c3d2e1f0","launcher_name":"default"}
{"time":"2026-01-15T10:32:01Z","stream":"audit","event":"run.finish","session_id":"dhs_0a1b2c3d4e5f","operation_id":"op_abcdef1234567890","image":"alpine:3.19","command_arg_count":3,"mounts":[{"source":".","target":"/workspace","read_only":true}],"env_keys":["APP_MODE"],"principal_name":"alice","launcher_id":"dhl_0f1e2d3c4b5a69788796a5b4c3d2e1f0","launcher_name":"default","result":"succeeded","duration":"1s"}
```

### Operational logging

Operational logs are written to **stderr** in JSON Lines with slog's
structured `time`, `level`, and `msg` fields, filtered by `log_level`:

| Value | Records emitted |
|-------|-----------------|
| `debug` | debug, info, warn, error |
| `info` | info, warn, error (default) |
| `warn` | warn, error |
| `error` | error only |

When `log_level` is `debug`, an operational record is emitted after
every HTTP request:

```json
{"time":"...","level":"DEBUG","msg":"request completed","request_id":"req_...","method":"POST","route":"/run","status":200,"duration_ms":401,"stream":"operational"}
```

This record is suppressed at `info`, `warn`, and `error` levels. The
`route` field uses the registered route pattern (e.g.
`DELETE /sessions/{id}`), never the actual request URI or session ID.
Query parameters, request bodies, headers, command arguments, session
tokens, and Docker output are never included. `duration_ms` is a JSON
number.

`GET /sessions` emits `session.list`. `GET /health` intentionally emits no
audit event because it is an unauthenticated liveness endpoint.

Log collection, retention, and rotation are delegated to the process
supervisor (systemd/journald or another log shipper). docker-helper
does not write log files or implement internal rotation.

## Security considerations

### Path traversal

All paths are resolved through `filepath.Abs` and `filepath.EvalSymlinks`
before comparison. The `pathWithin` function uses `filepath.Rel`, which
operates on canonical paths.

For operations that pass paths to Docker, additional measures close the
TOCTOU gap: builds use an isolated staging copy with FD-relative
`openat2` traversal; system-mode run mounts use inode-pinned
helper-owned mounts via `open_tree` + `move_mount`.

### Symlink escape

`EvalSymlinks` resolves all symlinks in a path at validation time.
If a symlink inside the workspace points outside, the resolved path
will fail the `pathWithin` check.

Note: `EvalSymlinks` alone does not prevent TOCTOU attacks where the
filesystem changes between validation and use. The specific operation
mitigations (staging, inode pinning) address this gap.

### Cross-workspace access

Each session is bound to one workspace. Build context and mount sources
are validated against that workspace. An agent cannot access another
session's workspace.

### Token handling

Session tokens are returned once during creation. The full token is never
stored in the database — only its SHA-256 hash. Admin token comparison
uses `ConstantTimeCompare` to prevent timing attacks. Principal and
Launcher credentials and session tokens are resolved through database
lookup by hash. Admin tokens, Principal credentials, Launcher
credentials, and session tokens are never logged (see
[Audit logging](#audit-logging)).

### Direct docker.sock access

docker-helper does not expose `docker.sock`. The agent communicates only
through the HTTP API.

- **User mode**: Unix socket has `0600` permissions.
- **System mode**: Unix socket has `0666` permissions, but security is
  enforced through bearer authentication and authorization, not socket
  permissions alone.

### Container security

docker-helper applies a fixed security policy when running containers:

- `--rm` — remove the container on exit;
- user mode and AppArmor system mode use `--security-opt label=disable`;
- SELinux system mode uses
  `--security-opt label=type:docker_helper_container_t` and keeps MCS
  confinement;
- `--user <uid>:<gid>` — run as the session owner principal's UID and GID,
  or daemon UID:GID for daemon-owner (user-mode) sessions.

## Current limitations and non-goals

Non-goals of the current implementation:

- container orchestration and scheduling;
- Kubernetes integration;
- full Docker API compatibility;
- multi-host execution;
- container health checks (the daemon's own `GET /health` liveness
  endpoint exists and is unrelated);
- managed container lifecycle, interactive exec, container logs, and
  detached execution;
- resource limits beyond the `/dev/shm` size (CPU, memory);
- build caching configuration;
- build secrets;
- registry and credential management beyond per-session
  `registry login` (registry authentication itself is supported);
- network management (creating or configuring Docker networks; containers
  use Docker's default networking);
- volume management beyond bind mounts.

Project purpose, product boundary, and long-lived design principles are
owned by `docs/manifesto.md`; planned work and release scope are owned by
`docs/roadmap.md`.
