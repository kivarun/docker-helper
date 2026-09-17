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
  - [Bounded MAC-command execution](#bounded-mac-command-execution-h8)
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
  - [Helper socket projection](#helper-socket-projection)
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

- filesystem access is restricted to each session's issued immutable
  filesystem snapshot (the workspace plus any issued disjoint roots);
- every data-plane operation requires a session token;
- all Docker commands go through a single process;
- the developer controls which filesystem snapshot each session is issued.

docker-helper limits the host paths exposed through its supported Docker
operations. It is not a complete sandbox: Docker/default networking remains
available — for workload containers and for builds alike (the
Docker/BuildKit builder executes with its own execution and network
position, documented as the accepted build boundary pending the Release 2.4
build sandbox) — and a validation or command-construction defect in this
trusted Docker-facing service can compromise the host.

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
    Docker CLI
      │
    Docker Engine
```

There are exactly four bearer classes, described by the [authority
model](#authority-model): the admin token authenticates the administrator, a
Principal credential authenticates one Principal, a Launcher credential
authenticates one Launcher, and the session token is a Session capability —
a data-plane key for one issued Session's filesystem authority, not a
credential resource.

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
  set-access, allowed-root remove (re-enabling an already-enabled Principal
  is the natural no-op);
- daemon-owner `default` Launcher: disable, delete, rename away from
  `default`, restricted scope, and any non-empty inherit replacement, plus
  every narrow allowed-root mutation — add, set-access, remove
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
| Launcher credential | one Launcher | that Launcher's Sessions and the credential self-introspection surfaces (`GET /auth` authority/classification introspection; `GET /self` own-resource introspection) | its own Launcher (forced) | none — there is no narrowing contract for this authority |
| Session token | one Session | its issued filesystem snapshot's data plane: `POST /build`, `POST /run`, `POST /pull`, `POST /registry/login`, and that Session's operation endpoints | not a control authority; not accepted by control endpoints or `GET /auth` | none |

`GET /self` is the one credential self-introspection surface for all three
self-introspectable classes: the daemon classifies the request bearer and
answers with `{"ok": true, "type": "...", "resource": {...}}` where the
resource is that class's own canonical projection —

- a Principal credential → type `principal`: username, uid, gid, home,
  enabled, stored `allowed_roots`, and effective
  `allowed_roots`, all resolved in one coherent policy generation
  under the lifecycle serialization boundary;
- a Launcher credential → type `launcher`: id, name, owning principal,
  enabled, scope, stored `allowed_roots` (canonically empty for
  inherit scope), and the effective three-level allowed roots;
- a Session bearer → type `session`: the same body `GET /sessions/{id}`
  renders for that Session (identity, ownership, expiry, persisted
  immutable filesystem snapshot), read together with the snapshot in one
  short read transaction through the transactional filesystem-authority
  capture owner.

The admin token has no self resource and is answered with the stable
`404 self_not_available` contract (a narrow self-show HTTP family,
separate from the admin control planes). Unknown, revoked, disabled, and
expired credentials receive the shared non-disclosing 401 authentication
semantics; database failures are HTTP 500 and never a 401. A live
credential whose owning resource vanished between authentication and the
coherent read fails closed with the same non-disclosing 401. The endpoint
is read-only, grants no authority the credential does not already have,
never mutates state, and never carries bearer, hash, or credential
material in its responses or audit records. Successful introspection
records one `self.show` audit event with the authenticated class
(`self_type`); the admin outcome records `result=self_not_available`
without a class.

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
- Session token — narrow data-plane Session capability for one issued
  filesystem snapshot (the workspace plus any issued disjoint roots) that
  expires after the configured TTL.

A Session token alone grants access to its issued filesystem snapshot and
cannot create or
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

Direct shell HTTP examples in the shipped documentation feed bearer
headers to curl through stdin/file-backed input (the header-from-stdin
form) and never expand bearer values into process argv.

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

The Unix listener is authoritative. In system mode the optional loopback
TCP listener is attempted after a successful Unix bind; a TCP bind failure
(a local unprivileged user can occupy the configured port) is DEGRADED
STARTUP, not daemon failure: the Unix listener stays live and serves the
complete API, the TCP listener is absent for this daemon lifetime, and one
bounded operational warning names the configured address and the bind
failure. The bind itself is the authority — no pre-probe, and no
retry/rebind: a port that becomes free later stays unused until the next
normal service restart. Unix creation failure remains fatal. (Historical
note: startup was once described as creating both listeners atomically;
the current contract is Unix-authoritative with degraded-TCP startup.)

### systemd services

Both deployment modes ship systemd unit files (see [systemd units and
hardening](#systemd-units-and-hardening)): a user unit installed under the
user's systemd manager and a system unit under the system manager. The
units carry the shutdown/restart contract ([Shutdown](#shutdown)) and the
hardening profile of each mode.

### Mandatory access control

System mode requires exactly one supported enforcing backend:

- AppArmor confines the daemon with the `/etc/apparmor.d/docker-helper-system`
  profile and uses explicit managed AppArmor MAC boundaries for path-level
  confinement of the concrete issued trees (defense in depth beneath the
  filesystem-snapshot authorization). The profile includes the dynamic
  helper-owned boundary state file `/var/lib/docker-helper/apparmor/managed-boundaries`;
  managed boundaries are stored there, outside config.json. These managed
  boundaries are MAC state, not authorization roots;
- SELinux confines the daemon as `docker_helper_t` and system-mode containers
  as the MCS-constrained `docker_helper_container_t` type.

Neither backend, both backends, and permissive SELinux fail closed. SELinux
workspace access is type-based and does not reproduce AppArmor's per-path
managed-boundary rule; canonical application-level allowed-root validation
remains authoritative in both modes.

Descriptor-safe recursive relabeling (C3): SELinux recursive workspace
relabeling is delegated to the upstream libselinux `selinux_restorecon`
implementation; supported SELinux system mode requires a proven
descriptor-safe implementation — `libselinux1 >= 3.11`, the rewrite that
labels each inode through `/proc/self/fd` paths so a pathname replacement
racing the tree walk cannot redirect a relabel to a foreign inode. The floor
is expressed as an RPM hard dependency and re-proven by the tarball SELinux
installer from rpm package metadata BEFORE any SELinux installation mutation
(the restorecon frontend version is not proof of the loaded libselinux
implementation; the package the linked `libselinux.so.1` belongs to is). A
real procfs is a separate mandatory runtime prerequisite, because the
descriptor-backed context operations use `/proc/self/fd`: without it the
upstream implementation silently falls back to pathname labeling, so the one
recursive workspace relabel owner refuses to run without real procfs
(statfs filesystem identity), fail-closed before any fcontext mutation.
Mount-point safety (`checkTreeRelabelBoundary`) and pathname-TOCTOU safety
are separate invariants with separate owners. Helper-owned recursive
relabels (trusted-CA runtime tree, deployment state, package scripts) are
covered by the same packaged/install-time libselinux guarantee and never
traverse a Principal-mutable tree, so they cannot cross the C3 trust
boundary. No home-grown recursive relabel traversal exists.

The admin-token replacement lifecycle is the one narrow write surface in the
config directory, and it is NOT a generic writable config grant — the two
backends treat config paths differently by their mechanics:

- AppArmor is pathname-mediating: it grants write/rename on exactly two
  pathnames — the canonical `/etc/docker-helper/admin.token` and the fixed
  staging pathname `/etc/docker-helper/.admin-token.new`. The generic
  `/etc/docker-helper/**` rule stays read-only: config.json and every other
  config path remain immutable to the confined daemon, and no broader write
  glob is granted.
- SELinux is type-based and does NOT reproduce AppArmor's per-pathname
  mediation. A dedicated `docker_helper_admin_token_t` file type (MAC
  implementation state, not a domain noun) carries the full replacement
  lifecycle (create/write/setattr/rename/unlink plus the daemon's startup
  read/open/getattr of the token file). Exact fcontext rules assign that
  type to the two token pathnames and are listed before the generic
  config-tree rule, so config.json and every other config path stay
  `docker_helper_config_t` — which remains read-only/immutable for the
  daemon (read/open/getattr): no write, unlink, rename-away, or overwrite
  by a token rename. The token type is CREATION-constrained: a newly
  created staging file receives it only through the EXACT filename
  transition for `.admin-token.new` (no generic config-dir transition), and
  direct creation of an arbitrary fresh config-dir name stays denied (the
  new file would inherit `docker_helper_config_t`, whose create is not
  granted). ACCEPTED SELinux backend mechanic (proven at runtime, release
  owner ruling): SELinux does NOT provide AppArmor-equivalent
  destination-basename mediation for rename — once a token_t inode exists,
  the granted directory namespace permissions may allow it to be renamed to
  an otherwise unused basename in the config directory. This is a backend
  mechanic, not additional product authority: the rotation lifecycle has
  ONE production rename (`.admin-token.new` → `admin.token`), and no
  API/CLI/config surface can request any other config-directory rename.
  The daemon receives only the config-directory namespace operations the
  staged replacement requires (write/add_name/remove_name) and never a
  relabel permission: the deployment relabels of the token pathnames run
  from the unconfined operator/packaging context.

## Trust model

### Trusted

- the developer who runs `docker-helper init` and `docker-helper serve`;
- the host filesystem outside the allowed roots;
- the Docker Engine and its configuration;
- the `docker-helper` process itself.

### Partially trusted

- the allowed-root directories and their contents;
- the workspace and any additional issued filesystem roots selected at
  session creation time.

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
    ├── creates config directory (system mode 0755, user mode 0700)
    ├── creates state directory (0700)
    ├── applies the deployment SELinux relabel to the config/state trees
    │   (system mode, enforcing SELinux; before any file is written)
    ├── writes config.json
    ├── generates admin token (dht_<64 hex chars>)
    ├── applies the exact admin-token relabel to the token file
    │   (system mode, enforcing SELinux; after the token is written)
    └── on relabel failure removes the just-created token file, so no
        partial initialization is left behind (the next init is not
        poisoned by the existing-token preflight)
    │
docker-helper serve
    │
    ├── loads config.json
    ├── reads admin token, computes SHA-256 hash
    ├── opens SQLite database and initializes the schema (DB init)
    ├── provisions user-mode ownership (ensureUserModeOwnership)
    ├── runs the Session ownership migration (idempotent;
    │   see Ownership migration)
    ├── runs the default-Launcher migration (idempotent)
    ├── runs the Session filesystem snapshot migration/integrity gate
    │   (compatibility backfill or fail-closed validation)
    ├── creates the workload MAC coordinator and reconciles
    │   helper-owned workload MAC state (ReconcileStartup)
    ├── creates the Session MAC coordinator (nil in user mode), wires
    │   the pending-workload coverage gate, and reconciles live
    │   sessions' MAC state (ReconcileLiveSessions)
    ├── deletes expired session rows (expires_at <= now) — after both
    │   reconciliations, so the coverage gate could still resolve the
    │   persisted Session filesystem snapshots (the complete issued
    │   coverage) of expired sessions with pending workload state
    ├── removes stale session runtime directories
    └── starts HTTP server on the configured transports
```

### Ownership provisioning

Ownership provisioning is the creation of the durable ownership chain
`Principal └── Launcher`. Session creation never creates ownership state;
it only consumes it.

#### Principal provisioning

`POST /principals` (admin token) is one ownership transaction. The request's
`username` is an OS-account identity spelling, and `validatePrincipalUsername`
owns the Release 2.2 Principal username text grammar: the spelling must be
non-empty and must carry no Unicode control rune (`unicode.IsControl` — the
C0 controls including LF/CR/TAB, DEL, the C1 controls; an embedded NUL is a
C0 control). Every other spelling is accepted exactly as supplied — no trim,
no case-fold, no Unicode normalization, no alphabet, case, or length rule —
and passed unchanged to the OS account resolver, which remains the authority
for whether the account exists. The grammar runs before OS lookup, before
home/path resolution, before the provisioning transaction (Principal row,
default allowed root, `default` Launcher), and before the optional initial
credential, so a control-bearing alias spelling can never resolve through
the OS resolver to one account while persisting a distinct Principal
identity. A refused spelling answers `400 invalid_username` with the bounded
message "invalid username" (the refused spelling is never echoed into the
public error); an empty username keeps `missing_username`; OS account
absence remains `os_user_not_found`; an existing Principal remains
`409 principal_exists`; the structured audit classifies the refused create
`invalid_username` and retains the supplied PrincipalName through its JSON
escaping. The user-mode daemon-owner username (resolved by UID at startup)
passes through the same grammar before it is used as a Principal DB
identity: a control-bearing resolved spelling fails startup closed with no
ownership state inserted and no ownership migration run.

The create resolves the OS user (`uid`, `gid`, `home`) and atomically
creates:

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
non-waiting lifecycle admission (H8)
    (the create never queues behind the lifecycle serialization: while any
     lifecycle transition holds the coordination, the create is refused
     immediately — `503 lifecycle_busy`, no policy state resolved, no
     Session; the client decides whether to retry)
    ↓
resolve exactly one target Launcher
    ↓
derive the owning Principal through the Launcher
    ↓
resolve effective workspace policy
    (the meet of the global, effective Principal, and — when restricted —
     launcher scopes; `read_only` dominance)
    ↓
validate workspace inside the effective roots
    (H3: the raw request spelling is admitted lexically against the
     effective ceiling first — a spelling outside the ceiling is refused
     without any privileged probing and has no resolving-alias
     compatibility admission)
    ↓
canonicalize the workspace
    (the existing Session-create owner: EvalSymlinks + stat of the
     admitted spelling; the canonical containment proof below remains
     the second, mandatory security proof)
    ↓
when the request carries filesystem_roots:
    admit each requested absolute host path lexically against the
    effective Launcher ceiling (clean raw spelling; a spelling outside
    the ceiling is refused invalid_filesystem_policy immediately, with
    zero privileged probes of the requested pathname and no
    compatibility alias that would resolve into it), then canonicalize
    the admitted spelling (resolve symlinks, prove the resolved path
    exists as a directory or regular file), prove the request is a
    narrowing-only composition against the effective Launcher ceiling
    (authorized canonical proof — the second, mandatory security proof;
     explicit read_write under an effective read_only region refused),
    build the requested scope (implicit workspace grant at the effective
    ceiling mode, replaced by an explicit workspace root), and compose
    ceiling ∩ request through the existing composition owner;
    otherwise derive the inherited workspace-only snapshot
    (issuance-time filesystem roots; the request may only narrow, never
    widen)
    ↓
derive the immutable Session filesystem snapshot
    (deriveSessionFilesystemSnapshot(effective entries, workspace) inside
     the lifecycleMu create linearization point)
    ↓
derive the concrete issued MAC trees from that snapshot
    (sessionMACBoundaries(snapshot): every concrete issued tree — the
     workspace plus, in system mode, every additional issued root)
    ↓
prepare and verify MAC coverage for every concrete issued tree through
the sessionMACCoordinator
    (CreateSessionBinding holds the coordinator lock across preparation,
     the create transaction, and any rollback; a preparation failure
     issues no usable Session or bearer)
    ↓
revalidate the authorizing credential at the commit boundary
    (a credential-authority create re-proves its exact credential row —
     still existing, still carrying the authenticated owner identity,
     still active — inside the create transaction's conditional insert,
     evaluated in the same statement as the insert; a revoke or delete
     that committed before the Session commit prevents that Session and
     answers the canonical non-disclosing 401 credential classification;
     the admin authority, which authenticates by in-memory token
     comparison, carries no credential and no revalidation clause)
    ↓
only after successful MAC preparation, commit Session + snapshot
atomically
    (session ID dhs_<32 hex>, session token dht_<64 hex>,
     SHA-256 hash stored in SQLite; snapshot entries persisted in the
     session_filesystem_snapshot_entries child table in one transaction —
     the create transaction's commit point; on commit failure the MAC
     coverage this create prepared is rolled back through the canonical
     removal owner while still serialized)
    ↓
register the Session→MAC binding as a live consumer
    (only after the DB commit)
    ↓
return session + one-time token
    (the bearer is returned only after the whole create boundary has
     succeeded)
```

The whole resolution, narrowing, and snapshot issuance happens inside the
existing `lifecycleMu` create linearization boundary, so a concurrent
parent-policy mutation linearizes wholly before or wholly after the create:
a request is never validated against one ceiling and committed against
another. Session-create admission into that boundary is non-waiting: a
create that arrives while the coordination is held by another transition is
refused immediately (the stable `503 lifecycle_busy` class) before any
policy resolution or MAC work — it never queues on the boundary, so it can
never stack its whole-transition MAC budget behind the held coordination
and lengthen the delay an emergency administrative disable already waits
behind the one in-flight transition. The refused attempt resolves no state
and commits no Session; the client decides whether to retry. The MAC
preparation inside the boundary is bounded (see
[Bounded MAC-command execution](#bounded-mac-command-execution-h8)): a hung
external MAC command can delay a concurrent administrative disable by at
most one transition budget, after which the create fails
(`mac_preparation_failed`) and the coordination is released.

The commit-boundary credential revalidation closes the credential
revocation race: a Principal or Launcher credential that authenticated the
request is re-proven inside the create transaction's conditional insert
(still existing, still carrying the authenticated owner identity, still
active), so a revoke or credential delete that commits before the Session
commit prevents that Session; the winning ordering — the Session commits
before the revoke — leaves the already-issued Session valid under the
accepted revocation contract. The zero-row outcome is classified inside
the same transaction (launcher/principal availability keeps the typed
`422 launcher_unavailable` contract; a credential rejection keeps the
canonical `ErrCredentialRevoked`/`ErrCredentialNotFound` classes), and the
handler answers a credential rejection with the same non-disclosing 401
credential contract as entry authentication: one `auth.failure` record
with the existing `credential.revoked`/`credential.not_found`
classification and no `session.create` record. No Session, bearer,
snapshot, or MAC state exists after the rejection — a prepared MAC
coverage rolls back through the existing create-failure path.

The Session filesystem request is **issuance-time narrowing** (see
[`release-2.2-allowed-root-access-modes.md`](release-2.2-allowed-root-access-modes.md)):
it is not a fourth mutable policy scope, there is no post-create Session
filesystem mutation, and omission preserves the inherited derived snapshot
byte-for-byte. Every authority that may create Sessions (Admin, Principal
credential, Launcher credential) may send it, and for all of them the
request is only a narrowing of the resolved target Launcher's effective
ceiling — even an Admin receives no bypass semantics through this field.
A malformed or widening request is the typed
`ErrInvalidSessionFilesystemPolicy` refusal family, answered before the
Session exists as `400 invalid_filesystem_policy` with the audit result
`invalid_filesystem_policy` and the bounded non-disclosing response message
("invalid session filesystem policy"): the internal diagnostic (the
canonical requested path, which may name a resolved symlink target) stays
in the operational log and never reaches the client; no Session, bearer,
container, pin, or workload-MAC state is created by a refused request.

In user mode the issuance-time narrowing is bounded to the workspace: user
mode has no `CAP_SYS_ADMIN` for inode-pinned mounts (see
[User-mode run mounts](#user-mode-run-mounts)), so every requested root's
canonical path must equal the canonical workspace — an omitted or empty
request issues the inherited workspace-only snapshot, an explicit workspace
root may narrow its access, and any other requested root is the same typed
`invalid_filesystem_policy` refusal. System mode issues the full disjoint
snapshot and pins every issued root through the same inode-pinning owner.

The persisted snapshot is immutable Session child state
(`session_filesystem_snapshot_entries`, ordered `position` entries with
`UNIQUE(session_id, path)` and `ON DELETE CASCADE` from `sessions`), and
carries single-owner integrity metadata (`session_filesystem_snapshot_meta`,
one `entry_count` and digest of the canonical entry representation per
Session, also `ON DELETE CASCADE`). Every load through the single canonical
loader (`loadSessionFilesystemSnapshot`) verifies the metadata against the
entries before constructing the snapshot: a missing, extra, reordered, or
mutated entry — including a deleted trailing row — fails closed on startup
and on the data plane; there is no repair or default. Later
parent-policy mutations never mutate an issued snapshot: the snapshot is
loaded through the single canonical loader
(`loadSessionFilesystemSnapshot`)
and is cleaned up only by Session deletion (FK `ON DELETE CASCADE`).
The compatibility backfill creates both tables and the metadata rows
atomically with the compatibility snapshot.
Startup runs the snapshot migration/owner before any MAC consumer
(the workload `ReconcileStartup` and `ReconcileLiveSessions`) and
before the expired-Session cleanup, which is last: a table-absent (pre-cutover) database gets
one compatibility backfill of `position=0, path=sessions.workspace,
access=read_write` for every remaining Session; a table-present database is
post-cutover and missing/partial/corrupt snapshot state fails startup closed.
Data-plane enforcement of the persisted access modes is the current
Release 2.2 behavior (see
[Data-plane filesystem authority](#data-plane-filesystem-authority)); the
Session MAC lifecycle covers every concrete issued tree, not only the
workspace (see [MAC lifecycle](#mac-lifecycle)).

The HTTP body of `POST /sessions` accepts
`{"workspace", "launcher_id", "principal", "filesystem_roots"}`:

- `launcher_id` and `principal` are mutually exclusive; both present is
  `400 conflicting_selectors`; an explicitly present but empty or malformed
  selector is `400 invalid_selector`;
- a Launcher credential's target is forced to its own launcher; a
  conflicting explicit selector is rejected;
- with no selectors the request body carries only the workspace;
- `filesystem_roots` is the optional issuance-time Session filesystem
  request: omitted or `[]` means the inherited create behavior (workspace
  only), and a non-empty array must be a well-formed list of `{path,
  access}` objects whose `path` is an absolute host path admitted
  lexically inside the effective Launcher ceiling before any privileged
  probing (an admitted spelling must exist as a directory or regular file
  after symlink resolution; the canonical ceiling proof stays the second,
  mandatory security proof) and whose `access` is exactly `read_write` or
  `read_only`; `null` is refused `400 invalid_filesystem_policy`, as are
  malformed entries (relative or traversal paths, unresolvable paths,
  paths of no mountable type, duplicate canonical entries, explicit
  `read_write` under an effective `read_only` region, missing/unknown
  access, unknown nested fields). An explicit root whose canonical path
  equals the canonical workspace replaces the implicit workspace grant
  under the same privilege rule.

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
  immediately, and no restart is required. The replacement lifecycle is
  serialized by the existing admin-token hash commit lock: the
  authorizing hash is verified current before the staging pathname is
  touched, so a stale concurrent rotation commits nothing and never
  touches the winner's staging state. The staging pathname is the ONE
  fixed helper-owned name `.admin-token.new` beside the token file — an
  internal implementation pathname, not a config/API/CLI surface —
  written, chmod'd 0600, fsynced, and atomically renamed onto the token
  file; every failure leaves the current token file and the runtime hash
  unchanged and removes the staging file, and crash residue at the exact
  staging pathname is cleaned by the next rotation. This fixed pathname
  is what the shipped confined MAC policy expresses as a narrow
  file contract (see Mandatory access control); the historical random
  tempfile spelling is gone.

Revoking a Principal or Launcher credential does not invalidate issued
sessions; deleting a Launcher credential leaves its launcher's sessions
owned and running but removes that authentication key. Revocation also
blocks Session creation at the commit boundary: a credential revoked or
deleted between authentication and the Session-commit linearization point
cannot issue a new Session (the create revalidates its authorizing
credential inside the commit transaction), and the refused create is
answered with the same non-disclosing 401 credential contract as entry
authentication.

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
GET /sessions/{id}  (admin token, Principal credential, or Launcher credential)
    │
    └── read-only introspection: session metadata + persisted immutable
        filesystem snapshot (404 session_not_found for missing/foreign)
    │
DELETE /sessions/{id}  (admin token, Principal credential, or Launcher credential)
    │
    └── physically deletes session row (snapshot entries cascade)
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

Every stored allowed root is a canonical rich value `{path, access}` — the
canonical `AllowedRootEntry` — where `access` is exactly `read_write` or
`read_only`; there is no other access vocabulary. A legacy path-only entry
(string in config.json, pre-2.2 database row, or 2.x API input) is the
`read_write` grant.

#### H10 accepted boundary: filesystem capability, not a DAC-preserving ceiling

An allowed root and the issued Session filesystem snapshot are an explicitly
granted filesystem **capability** — path tree plus access modes —
not a path ceiling layered over the Principal's Unix DAC. Accepted semantics
(SC3/H10, 2026-09-16):

- In system mode the root-owned helper may perform the necessary
  helper-mediated reads inside the granted capability regardless of whether
  the specific Principal could read the same inode through its own host
  Unix credentials (the helper does not assume the Principal identity; root
  bypasses DAC). A file inside the capability may enter the staged build
  context (the one current helper content-ingest path, see
  [Build context](#build-context)) even when the host Principal could not
  read it under DAC — deliberate capability semantics, not a missed check.
  No owner-UID check, mode-bit emulation, ACL parser, or check-as-user
  subsystem exists or will be added to emulate Principal DAC.
- `read_only` is an access/integrity mode inside the granted capability: it
  denies the *workload* a writable host-path exposure. It is not a
  confidentiality boundary against the helper.
- Actual workload file access is additionally evaluated by kernel DAC,
  including POSIX ACLs, against the credentials actually supplied to the
  container: Principal `UID:GID` with no capability bypass, plus the
  privilege floor (no capabilities, no-new-privileges). This is
  not a reproduction of the Principal's host login credential set: host
  supplementary groups are not propagated, so permissions depending on
  those group memberships may differ.
- User mode has no separate H10 gap: the non-root daemon is naturally
  bounded by its own DAC identity (the daemon owner is the only Principal).
  This is an implementation consequence of the same capability model, not a
  second filesystem-capability model.
- Release 2.4 does not automatically "close H10". The build sandbox
  redesigns the builder execution/root/network boundary (see
  [`release-2.4-build-sandbox.md`](release-2.4-build-sandbox.md)); moving
  staging/read identity under an unprivileged Principal identity may
  additionally narrow the helper's read authority, but only as a separate
  explicit contract change — the accepted capability semantics never change
  silently as a side effect of 2.4.

The workspace authorization hierarchy has three policy ceilings, then one
concrete selection:

```
policy ceilings:  global roots
                    ⊇ effective Principal roots
                        ⊇ effective Launcher roots
concrete:               Session workspace (ephemeral)
                          └── immutable Session filesystem snapshot
                              (persisted at creation; the single
                              data-plane filesystem authority of the
                              issued Session)
```

Within one scope, the most-specific canonical path wins. Across scopes, the
effective value is the meet of the parent scope and the child scope — path
authority intersects and access meets with `read_only` dominance — so a
lower authority may narrow but never widen its parent. A writable exposure
is admitted only when the source itself resolves `read_write` and covers no
effective nested `read_only` region (the snapshot owner's single
writable-parent query, `CanExposeWritable`); the daemon never silently
downgrades a requested writable mount to read-only — a refused writable
exposure is the stable `read_only_root` policy refusal, and an issued
Session keeps its persisted immutable snapshot regardless of later
parent-policy mutations (see
[Data-plane filesystem authority](#data-plane-filesystem-authority)).

- **Global allowed roots** (config.json `allowed_roots`) — the system-wide
  authorization ceiling, managed by `config allowed-root
  list/add/set-access/remove` (canonical rich `{path, access}` values;
  legacy string input means `read_write`; `config show` projects the same
  canonical `allowed_roots` values). Changing allowed roots is a
  policy-only operation; it does NOT prepare MAC state.
- **Principal allowed roots** (database) — per-principal narrowing, managed
  by `principal allowed-root add/set-access/remove`. Does not prepare MAC.
- **Launcher allowed roots** (database, `restricted` scope only) —
  per-launcher narrowing beneath one principal; `inherit` scope applies no
  launcher-level narrowing. Evaluated at session-creation time against
  current state. Does not prepare MAC.
- **Session workspace** (ephemeral, not a persisted policy level) —
  selected only at session creation time via `session create --workspace
  PATH`. Must be under a global, the principal, and (when restricted) the
  launcher allowed root.
- **Session filesystem snapshot** (persisted, immutable Session child
  state) — derived from the effective entries at the creation
  linearization point, further shaped when the Session-create request
  carries `filesystem_roots` (issuance-time filesystem roots: additional
  absolute roots inside the effective Launcher ceiling and an optional
  explicit workspace grant; see
  [Session creation](#session-creation)), and committed atomically with the
  Session. The snapshot authorizes one or more disjoint canonical root
  trees — the workspace is always authorized, additional roots wherever
  the ceiling allows. It is the
  single data-plane filesystem authority of an existing Session: current
  global/Principal/Launcher policy is never read on the data plane, so
  parent-policy mutations affect only Sessions created afterwards.

`effective Principal roots` is the Principal ceiling owned by
`effectivePrincipalAllowedRoots`: the meet of the global roots and the
stored Principal roots — path intersection with `read_only`-dominant
access meet — with one documented exception: in user mode the
daemon-owner Principal with zero stored roots collapses onto the global
roots. `effective Launcher roots` are the Principal ceiling for `inherit`
scope, or the meet of that ceiling with the Launcher's stored entries for
`restricted` scope (stale out-of-ceiling Launcher roots are rejected,
never truncated).

MAC state is derived from the concrete issued-Session-tree lifecycle, not
from the authorization ceilings. The canonical statement, corrected by the
Release 2.2 final-UAT architectural correction (the workspace-only sentence
it supersedes is recorded in
[`release-2.2-mac-enforcement.md`](release-2.2-mac-enforcement.md)):

  Session MAC preparation covers the concrete filesystem trees issued in
  the immutable Session filesystem snapshot. The workspace is one issued
  tree; additional issued roots participate in the same Session MAC
  lifecycle. Authorization ceilings remain MAC-free and never trigger
  relabeling merely because they could authorize a future Session.

The three layers stay distinct:

- **Authorization ceilings** (global / Principal / Launcher allowed roots):
  no MAC state; a broader ceiling never causes recursive MAC relabeling.
  Adding `/opt` as a global allowed root must never imply recursive
  relabeling of `/opt/**`.
- **Issued Session snapshot**: the concrete granted filesystem capability;
  it derives the Session MAC binding (one canonical minimal boundary set
  per Session, access-agnostic).
- **Workload exposure**: the concrete operation request; the snapshot
  decides access, and the workload MAC materialization owns the per-workload
  read-only/read-write backend defense.

Session MAC binding provides host/backend reachability only. Access modes
(read_write/read_only), the writable-parent rule, and most-specific
transitions remain owned exclusively by the immutable Session filesystem
snapshot and the per-workload exposure materialization; Session MAC
preparation never interprets access modes.

Distinct from Session MAC preparation, system-mode `docker-helper init`
under enforcing SELinux applies the installed fcontext rules to docker-helper's
own deployment state: the helper-owned `/etc/docker-helper/**` (config) and
`/var/lib/docker-helper/**` (state) trees are relabeled to
`docker_helper_config_t` / `docker_helper_state_t` immediately after they are
created and before the admin token is written, so the first daemon start can
open its database. Because the tree relabel runs before the token exists, a
freshly written admin token would otherwise inherit the generic config
directory type — so init additionally applies an EXACT admin-token relabel
immediately after the token is written (the same selinux_deploy owner; the
token pathnames are the only exact-path additions, never a recursive or
whole-tree relabel), so the fresh token carries the dedicated
`docker_helper_admin_token_t` type before the first daemon start and the
first confined rotation succeeds. A relabel failure aborts init (no partial
initialization): on a failed fresh-init token relabel init removes the
just-created token file, so the next init is not poisoned by the
existing-token preflight. Init also runs an exact-path restorecon on the
Docker CLI
executable the daemon will exec (resolved over the same PATH the service
uses), so the confined `docker_helper_t` domain can execute it with the
`container_runtime_exec_t` type the distro/container-selinux fcontext rules
already define — never a recursive `/usr/bin` relabel and never a `bin_t`
execute grant. AppArmor system mode and user mode perform no SELinux
relabel; on upgrade/reinstall the packaged `restorecon -R
/etc/docker-helper` migrates an existing pre-H6 admin token to the
dedicated type without changing its value.

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

### Host-path capability text grammar

Every stored host capability identity — a global/Principal/Launcher allowed
root, an issued Session filesystem tree, a managed MAC boundary — is canonical
text the daemon persists and feeds to line-oriented artifacts (config
serialization, AppArmor managed fragments, persistent SELinux fcontext
records). Control characters are outside the Release 2.2 host-path capability
text grammar: one shared text-grammar owner (`validateHostPathText` in the
shared workspace-path policy) refuses every Unicode control rune — the C0
controls (including LF, CR, TAB), the C1 controls, and DEL — and embedded NUL
explicitly (a host pathname cannot represent an embedded NUL). Control
characters can desynchronize line-oriented tool output, and a tool
synchronization hazard must be excluded before the text becomes a persisted
authorization or MAC identity. Ordinary printable characters — including ASCII
space inside a component, regex metacharacters, and ordinary Unicode — remain
supported; the invariant is tool-synchronization safety, not "reject weird
filenames".

The grammar is applied by the canonical host-path owners, twice: the caller
spelling is refused before any filesystem probing where the canonicalization
owner owns caller syntax, and the resolved canonical path is re-checked after
symlink resolution (a harmless-looking spelling may resolve into a pathname
containing a control character). Every calling surface keeps its existing
canonical error classification (invalid workspace, invalid session filesystem
policy, invalid allowed root / config error, boundary input error). Backends,
handlers, and the CLI duplicate no control-character list.

The authorization path grammar and backend serialization stay separate
concerns. The SELinux `escapeFcontextPath` remains regex-metacharacter
escaping, not a second validator, and the local-fcontext-rule inventory is a
backend mechanic, not product authority: it is parsed from the real
`semanage fcontext -l -C -n` producer grammar, whose pattern column cannot
contain an ordinary space because semanage itself refuses space-carrying file
specifications at add time (captured Tumbleweed policycoreutils 3.11
evidence); unrecognized non-empty records still fail closed. Container target
paths are a different grammar: Docker `--mount` representability is owned by
the bind-mount serializer (see
[Docker bind-mount serialization](#docker-bind-mount-serialization)).

### Launcher scope

Launcher scope narrows the Principal authorization ceiling for sessions
created through that launcher; it never widens and never owns MAC state:

| Launcher scope | Effective roots for new sessions |
|---|---|
| `inherit` | the effective Principal ceiling (canonical owner above) |
| `restricted` | the meet of the effective Principal ceiling with the launcher's stored entries (`read_only` dominance) |

Evaluation happens at session-creation time against current state; a
launcher root that is no longer under the principal ceiling is rejected
then (never silently truncated), so stale out-of-ceiling roots cannot
produce a session outside the principal's allowed roots.

Scope replacement remains the one complete-scope mutation:
`PUT /principals/{username}/launchers/{launcher}/allowed-roots` accepts
the complete scope through the one canonical `allowed_roots` field,
whose elements dispatch by shape: the canonical rich object
(`{"scope": "restricted", "allowed_roots": [{"path": ...,
"access": "read_write"|"read_only"}, ...]}`, `access` required per
object entry) and the 2.x path-only compatibility string
(`{"scope": "inherit", "allowed_roots": []}` or
`{"scope": "restricted", "allowed_roots": [...]}`, every path a
`read_write` grant) stays valid, and the two forms are mutually
exclusive in one request. The CLI exposes it only as the fixed
single-request `launcher allowed-root inherit` verb — there is no
read-modify-write policy mutation through the CLI. The narrow per-root
mutations are separate single-request operations:
`POST .../allowed-roots` adds one root (presence-aware `--access`,
omission is the `read_write` grant; narrowing an inherit launcher to
restricted scope atomically with the insert),
`PATCH .../allowed-roots` changes the access mode of exactly one stored
root (set-access; never changes the scope mode), and `DELETE
.../allowed-roots` removes one root; removal never changes the scope mode,
so removing the last root leaves the launcher restricted with an empty
root set (fail-closed: no admissible session workspace until an explicit
inherit). Every narrow launcher root mutation — add, set-access, and
remove — rejects the user-mode reserved default launcher with
`409 user_mode_owner_reserved`. The CLI verbs are
`launcher allowed-root add/list/set-access/remove/inherit` and
`principal allowed-root add/list/set-access/remove`;
`launcher scope` no longer exists in the CLI.

### Session workspace

Each session is bound to a single workspace directory and its issued
immutable filesystem snapshot (the workspace is always part of it). An
agent with a session for `/home/user/project-a` cannot access
`/home/user/project-b`, even if both are inside an allowed root, and cannot
mount an issued-root region the Session did not request; absolute mount
sources are authorized only through the issued snapshot (see
[Filesystem policy](#filesystem-policy)).

Path comparisons follow the canonical authorization order: structural
request validation, then lexical capability admission of the raw caller
spelling against its issued capability, then privileged filesystem
resolution (`EvalSymlinks`/stat) of an admitted spelling, then the
canonical containment/policy proof. A spelling outside the capability
never reaches the resolver, and a symlink inside the admitted lexical
capability that resolves outside is refused by the canonical proof.
Note: `EvalSymlinks` resolves the path at a point in time. By itself it
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

When a session is created, the workspace path is admitted lexically
against the effective allowed-root ceiling, then resolved through
`EvalSymlinks`, and the canonical workspace is stored in the database.
When a build or run request specifies a path relative to the workspace,
the joined spelling is admitted lexically inside the workspace before any
probing, and the resolved path is compared against the canonical
workspace as the second, mandatory proof; if the resolved path escapes
the workspace, the request is rejected. The issuance-time filesystem
roots apply the same ordering: a requested root spelling outside the
effective Launcher ceiling is refused without probing, and an admitted
spelling is canonicalized before the canonical ceiling proof.

Session-create workspace admission follows the authorization-before-
probing ordering. The raw request spelling is first proven lexically
against the effective allowed-root ceiling without any host filesystem
probing; a spelling outside the ceiling is refused immediately with the
bounded authorization-shape refusal (`workspace must be inside an allowed
root`) and the resolver is never invoked for it, so no existence, error
class, path type, or resolved alias of an unauthorized pathname is ever
collected or disclosed. Release 2.2 tightens the former symlink-alias
admission: a raw spelling outside the ceiling is no longer accepted even
when it would resolve into the ceiling through a symlink — the
caller-controlled raw spelling must carry the lexical capability
admission itself. After admission the privileged probes run normally and
the canonical containment proof remains the second, mandatory security
proof: a symlink inside the lexical ceiling that resolves outside is
still fail-closed, a spelling inside the ceiling that resolves inside is
issued (symlink aliases inside the ceiling keep working), and a missing
workspace inside the ceiling keeps its actionable operator diagnostic.
The run and build data planes apply the same ordering: their raw
spellings are admitted lexically against the issued Session filesystem
capability (the workspace for the relative/relative grammar, the issued
snapshot entries for the absolute mount spelling) before any privileged
probing, the canonical containment proofs after resolution stay
fail-closed (staging and inode pinning unchanged), and their public
refusals (`invalid_mount`, `invalid_build_context`) are stable
non-disclosing contracts identical across unauthorized filesystem
states.

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
  the same missing-selector contract a real create would). Without a
  Session filesystem request this projection is the **maximum filesystem
  ceiling**: a real Session create may further shape its issued snapshot
  against it through `filesystem_roots`, but never widen beyond it.

`GET /auth` is the separate identity introspection surface; it reports the
authenticated authority class, not policy (see
[Authority model](#authority-model)). `GET /self` is the companion
self-introspection surface: it answers the authenticated credential's own
resource document (identity, stored/effective roots for Principal and
Launcher authorities, the Session's own show body with its persisted
snapshot for a Session bearer) under the same classification semantics
(see [Authority model](#authority-model)). Identity introspection (`GET
/auth`), self introspection (`GET /self`), and policy introspection
(`GET /principals/{username}/effective-allowed-roots`,
`GET /sessions/create-policy`) stay separate surfaces; neither widens the
other.

`GET /sessions/{id}` is the separate read-only **issued-Snapshot**
introspection surface: it answers what was actually issued to an existing
Session, not what a Session created now would get. It loads the Session's
persisted immutable filesystem snapshot through the single canonical
snapshot loader (the data-plane enforcement consumer uses the same
owner), under the Session-control authorization matrix (an admin token, a Principal
credential, or a Launcher credential; a Session bearer has no control-plane
introspection authority) and the same ownership scope as list/show/delete — a
missing or foreign Session is the same non-disclosing
`404 session_not_found`. A snapshot corruption discovered after startup is
`500 internal_error` with an operational log, never silently hidden as
not-found. It never recomputes current parent policy.

### MAC lifecycle

MAC state follows the concrete Session lifecycle, not the policy ceilings:

- a created session receives MAC preparation for every filesystem tree
  issued in its immutable snapshot (AppArmor managed-boundary coverage, or
  SELinux fcontext labeling with MCS constraints) as part of the session
  lifecycle. Every concrete issued tree goes through the backend
  preparation path — verify, relabel, and actual-type check — and the
  physical MAC boundaries are deduplicated only after every concrete tree
  has passed preparation: several issued trees may resolve onto one
  covering boundary, and one Session contributes at most one consumer to
  one physical boundary. Preparation happens before the create
  transaction: a preparation failure fails the creation closed
  (`mac_preparation_failed`) and leaves no usable Session or bearer, and
  a create-transaction failure after successful preparation rolls back
  the prepared coverage through the canonical removal owner while still
  serialized. The Session→MAC binding is registered as a live consumer
  only after the DB commit, and the bearer is returned only after the
  whole create boundary has succeeded;
- a deleted, expired, invalidated, or migrated-away session releases its
  complete MAC binding (every issued tree) through the existing release
  paths (including startup reconciliation of stale boundaries). Startup
  reconciliation follows the same semantics: every concrete issued tree of
  the persisted snapshot is verified/required before the physical coverage
  is deduplicated into the reconstructed binding; the persisted immutable
  snapshot stays authoritative (current parent policy is never used to
  reconstruct issued roots). The release is gated on pending helper-owned
  workload state: while a
  workload ownership record for a session is still unresolved at startup
  (its container cannot be proven absent, e.g. Docker is temporarily
  unavailable), the session MAC coordinator defers releasing that
  session's issued coverage — every issued tree, not only the workspace —
  so the unproven workload state keeps the MAC world it needs to finish
  safely; the release happens after workload reconciliation proves the
  cleanup done. When a pending workload's session row or persisted
  snapshot cannot be resolved, every possibly required helper-owned
  boundary is deferred (fail closed). An expired or deleted Session stops
  authorizing new operations immediately; only its host MAC coverage may
  outlive it until the dependent workload state is proven gone.
- removal semantics per backend: the SELinux fcontext removal deletes
  exactly the persistent rule the helper can prove it owns — the rule
  shape derived from the proven boundary kind (a directory boundary owns
  its exact recursive pattern, a regular-file boundary its exact file
  pattern) — and never claims or deletes a compatible operator-owned rule
  sharing the stem. The rule inventory behind the removal and overlap
  decisions is parsed from the real `semanage fcontext -l -C -n` producer
  grammar with no width-dependent split rule (backend mechanics; see
  [Host-path capability text grammar](#host-path-capability-text-grammar)).   All fallible facts (boundary kind, mount safety, the
  owned rule's presence) are proven before the durable rule is deleted; a
  failure after the deletion is an error, never a falsely complete
  transition, and the canonical removal owner retains the ownership
  metadata for retry/reconciliation. Proven path absence (ENOENT) with a
  durable kind removes exactly the proven pattern; the legacy kind-less
  ownership row keeps the same-stem single-unambiguous-rule contract for a
  vanished tree: the stem's single unambiguous workspace-type rule is
  removed, and the ambiguous multi-rule case is refused (ownership
  retained for reconciliation). The AppArmor managed fragment persists each
  boundary's kind (regular-file markers extend the legacy directory-only
  fragment format), so a fragment rewrite triggered by an unrelated
  boundary never re-derives an existing boundary's kind from mutable host
  state;
- managed boundaries are helper-owned MAC state (AppArmor's dynamic
  boundary state file), never authorization roots and never config.json
  state.

#### Bounded MAC-command execution (H8)

Every external MAC one-shot command reachable in the live daemon is bounded,
and every *serialized MAC transition* is bounded as a whole:

- **One fixed budget owner.** A fixed, non-configurable Release-2.2 wall-clock
  budget (`macTransitionBudget`, 60 seconds — selected from measured UAT
  command durations and the documented existing bounded-wait constants) bounds
  one serialized MAC transition: one Session create (backend preparation of
  every issued tree plus its rollback), one Session release, one
  startup-reconciliation session pass, one workload prepare or cleanup, and
  the trusted-CA restorecon of one configuration preparation. Individual
  subprocesses consume the *remaining* budget (context-aware execution), so
  the whole serialized transition is bounded — this matters because the
  reachable command multiplication of one create is bounded only by the
  Session filesystem-roots request grammar (the 16 KiB request-body cap),
  so per-command timeouts alone cannot prove a bounded hold of the
  coordination. A budget-expired command is a failure (`ErrMACTransitionBudgetExceeded`
  inside the `mac_preparation_failed` chain), never successful MAC
  preparation, and the request lifetime is never the security owner: every
  budget context is derived from `context.Background()` by the daemon.
- **Kill/reap and no orphaned child.** Every bounded MAC command is started
  with `Pdeathsig=SIGKILL`, so no external MAC child can outlive the daemon
  process on any exit path (crash, signal, normal exit). During normal
  operation the budget kills and reaps the child at the bound.
- **Lock ordering and bounded side effects.** The lifecycle serialization
  (`lifecycleMu`) and the session MAC coordinator lock are held across
  bounded side effects only: a hung external MAC command can delay a
  concurrent administrative transition (Launcher/Principal disable, config
  reload) by at most one transition budget, and the disable's own
  post-commit MAC release is bounded the same way. The bound is
  queue-independent: Session-create admission into the lifecycle boundary is
  non-waiting (`TryLock` at the existing create owner) — a create that
  arrives while the coordination is held is refused immediately with the
  typed `ErrLifecycleBusy` refusal (`503 lifecycle_busy`, never queued), so
  concurrent creates cannot stack their fresh whole-transition budgets
  behind the held coordination and grow the disable's delay with the
  queued create count; an already-running create keeps its whole-transition
  budget. The backend file locks
  are not equivalent by design: the AppArmor workspace lock is
  fail-closed/non-waiting (`LOCK_EX|LOCK_NB`) and the global SELinux
  fcontext lock is the same — a contended fcontext transition is refused
  immediately with a bounded actionable error ("another SELinux fcontext
  operation is in progress") instead of parking an unbounded blocking
  pre-command wait; there is no polling queue.
- **Fail-closed mutation outcomes.** An AppArmor reload timeout is a
  failure; the fragment rollback consumes the same remaining budget, and an
  unprovable rollback leaves the fragment restored and the error fail-closed
  (the next reload converges the kernel to the fragment). A SELinux add/
  relabel/remove timeout never claims clean success and never deletes
  ownership evidence it cannot prove: the canonical retain/retry/
  reconciliation semantics are unchanged, and a possibly-partial semanage
  mutation on timeout is recoverable by the next ordinary transition or
  startup reconciliation. A workload AppArmor cleanup timeout retains the
  durable ownership state for reconciliation (the run cleanup sequence's
  retained outcome) and the cleanup closure runs its own budget, so the
  operation terminal transition and the bounded shutdown drain cannot be
  held hostage by an orphaned parser process. Startup reconciliation runs
  one budget per session pass.
- **Inventory of the remaining external MAC-adjacent commands.**
  Deployment/init-only relabels (`docker-helper init`: the helper-owned
  config/state trees, the Docker CLI executable, the admin token) run before
  the service exists and cannot delay a live administrative transition; the
  `apparmor check` and `selinux check` CLI diagnostics are separate
  processes that hold no daemon locks; the SELinux workload bindfs worker is
  an intentionally long-lived FUSE worker with its existing readiness
  (10s) and worker-exit (5s) bounds, not a timed one-shot.

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
| `POST /principals/{username}/allowed-roots` | add one Principal allowed root (presence-aware `--access`; authorization-only, never MAC preparation) |
| `PATCH /principals/{username}/allowed-roots` | set-access: change the access mode (`read_write`/`read_only`) of exactly one stored Principal allowed root (matched by the stored canonical identity; never MAC preparation) |
| `DELETE /principals/{username}/allowed-roots` | remove one Principal allowed root (authorization-only, never MAC preparation) |
| `GET /principals/{username}/effective-allowed-roots` | Principal effective-root introspection (see [Policy introspection](#policy-introspection)) |
| `POST /principals/{username}/credentials` | create a named Principal credential (one-time token; administrator-controlled) |
| `GET /principals/{username}/credentials` | that Principal's credentials |
| `POST /principals/{username}/credentials/{name}/rotate` | atomic credential rotation |
| `POST /credentials/{id}/revoke` | revoke a credential by its credential ID (administrator-controlled) |
| `GET /credentials` | scope-first Principal credential list (optional `?principal=` narrowing) |
| `GET /sessions/{id}` | read-only issued-Snapshot introspection (authority-scoped; see [Policy introspection](#policy-introspection)) |
| `DELETE /sessions/{id}` | Session deletion (authority-scoped; see [Session](#session)) |

CLI surface: `principal create|list|show|set|delete`,
`principal allowed-root add|list|set-access|remove`,
`principal credential create|list|revoke|rotate`. Every command accepts
the common operator flags (see [CLI conventions](#cli-conventions)).
`principal allowed-root` mutations are authorization-only and never
prepare MAC state; `principal allowed-root list` is a CLI projection of
the show endpoint (`GET /principals/{username}`), not a separate HTTP
list route. The show response carries the canonical rich `allowed_roots`
projection, and `principal allowed-root
list` prints the 2.1-compatible one canonical root per line by default,
with the explicit `--json` opt-in carrying the canonical rich entries
for access-aware tooling.

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
| `PUT /principals/{username}/launchers/{launcher}/allowed-roots` | atomic complete-scope replacement (the one canonical `allowed_roots` field: rich `{"path","access"}` object elements, or 2.x path-only string elements mapping every path to `read_write`) |
| `POST /principals/{username}/launchers/{launcher}/allowed-roots` | add one allowed root (presence-aware `--access`; narrows an inherit launcher to restricted on the first add) |
| `PATCH /principals/{username}/launchers/{launcher}/allowed-roots` | set-access: change the access mode of exactly one stored launcher allowed root (never changes the scope mode) |
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
"allowed_roots", "created_at"}` — `allowed_roots` is the
authoritative rich projection of the stored restricted roots. Create response carries
the one-time credential token only when issuance was requested. Exactly one credential
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
    [--token-file PATH] [--principal USER] [--access ACCESS] PATH [LAUNCHER]
docker-helper launcher allowed-root set-access [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] PATH ACCESS [LAUNCHER]
docker-helper launcher allowed-root list [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] [--json] [LAUNCHER]
docker-helper launcher allowed-root remove [--system] [--endpoint ENDPOINT]
    [--token-file PATH] [--principal USER] PATH [LAUNCHER]
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
docker-helper session create [--system] [--endpoint ENDPOINT] [--token-file PATH] --workspace PATH [--filesystem-root PATH=ACCESS]... [--principal USER] [--launcher LAUNCHER] [--json]
docker-helper session list [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--launcher LAUNCHER] [--json]
docker-helper session show [--system] [--endpoint ENDPOINT] [--token-file PATH] --id SESSION_ID [--json]
docker-helper session delete [--system] [--endpoint ENDPOINT] [--token-file PATH] --id SESSION_ID [--json]
docker-helper session cleanup
```

`session create` — target resolution, selector mapping, and default
resolution are the canonical
[Session creation](#session-creation) pipeline and authority subsections;
the CLI maps `--principal`/`--launcher` onto the wire selectors after
`GET /auth`, and both are mutually exclusive. The repeatable
`--filesystem-root PATH=ACCESS` flag is the CLI form of the issuance-time
Session filesystem roots: PATH is an absolute host path inside the target
Launcher's effective allowed roots (a directory or a regular file) and
ACCESS the canonical access vocabulary; the CLI validates `PATH=ACCESS`
syntax only, and the daemon decides narrowing against the resolved
Launcher ceiling. `--workspace` remains mandatory and receives the maximum
access the effective policy permits unless an explicit
`--filesystem-root WORKSPACE=ACCESS` replaces that implicit grant. Omitting
the flag preserves the inherited create behavior.
Returns the session ID,
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

`session show` — the read-only introspection surface for one issued
Session: the flat response carries the usual public metadata plus the
persisted immutable `filesystem_snapshot` in its exact persisted canonical
ordering (`entries` is always an array; the top-level `workspace` remains
the canonical owner and is not duplicated inside the snapshot; no token,
token hash, parent live policy, or MAC internals). Human output renders a
compact metadata block and an explicit `FILESYSTEM SNAPSHOT` PATH/ACCESS
table — the access mode is never hidden. The loader is the single canonical
snapshot loader (see [Session creation](#session-creation) and the issued
-snapshot introspection paragraph), so the CLI never recomputes policy.

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
  `GET /principals/{username}/effective-allowed-roots`). With `--stored`
  it instead prints the target Principal's stored roots — the universe of
  the Principal allowed-root existing-entity mutations — through the same
  target resolution. With `--authority-only` it prints only the
  authenticated operator authority for shell-completion introspection;
  completion authority introspection reuses this surface so the parser
  tree, help tree, and completion tree remain identical (no hidden
  command nodes).
- **`completion roots launcher`** — the target Launcher's stored allowed
  roots (the default Launcher of the `--principal`-named Principal, or the
  Principal inferred from the credential; the daemon authorizes the
  query): the universe of the launcher allowed-root existing-entity
  mutations.
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
| `session create --filesystem-root` | Session create-policy query (the same policy source as `--workspace` for the path side; the access side after the `=` delimiter completes the canonical `read_only`/`read_write` vocabulary) |

Positional completion of the allowed-root families follows the shared
grammar-universe rule: each position completes the universe that the
command semantics actually authorize.

`launcher allowed-root add PATH [LAUNCHER]`: PATH completes from the
effective Principal ceiling — the same policy query the `--workspace`
flag value consumes — rendered as navigable boundary segments, with no
generic host-filesystem fallback: the daemon stays the authorization
authority, so an authority context with no resolvable Principal offers
nothing. The optional trailing LAUNCHER positional completes from the
same selector introspection as the `--launcher` flag.

`launcher allowed-root remove PATH [LAUNCHER]` and `launcher allowed-root
set-access PATH ACCESS [LAUNCHER]` are existing-entity mutations: PATH
completes exactly the target Launcher's stored roots (`completion roots
launcher`, the default-Launcher target of the launcher-omitted
invocation), with no generic fallback; the ACCESS word completes the
canonical `read_only`/`read_write` vocabulary; the optional trailing
LAUNCHER positional completes the selector introspection.

`principal allowed-root add USER PATH` completes USER from the
`--principal` selector introspection and PATH as generic directories
(the add creates a NEW root under the global ceiling, which is not
authority-visible to every caller). `principal allowed-root
remove/set-access USER PATH` complete PATH exactly from the target
Principal's stored roots (`completion roots principal --stored`).

`config allowed-root remove PATH` and `config allowed-root set-access
PATH ACCESS` complete PATH exactly from the stored global roots (the
local `config allowed-root list` output, no daemon exchange); add
remains generic directory completion. The stored-root universe is the
recovery-safe list projection, so a stale entry whose directory is gone
stays completable and addressable.

The daemon remains the final policy boundary and rejects a root outside
the effective Principal ceiling at execution time. All other path-valued
flags keep generic filesystem completion.

Positional completion of `principal show USER [FIELD]`: USER completes
from the same selector-introspection owner as the `--principal` selector
(above, with the `principal show` command context), and FIELD completes
the canonical show-field vocabulary (`username uid gid home enabled
allowed_roots`) that `extractPrincipalField` owns
— one shared vocabulary,
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

Agent-facing CLI commands are `pull`, `build`, `run`, `registry login`
(described under [Data-plane execution](#data-plane-execution)), and `self`
— the read-only credential self-introspection command, usable with a
Session bearer as well as Principal and Launcher credentials; operator
commands are `serve`, `init`, `reload`, `session`, `config`, `principal`,
`launcher`, `credential`, `admin-token`, `apparmor`, and `selinux`;
general commands are `version` and `help`.

`apparmor` — manage/check managed AppArmor MAC boundaries for an
AppArmor system deployment (the public `apparmor root` command spelling is
a retained compatibility form; it manages AppArmor MAC boundaries —
confinement resources for concrete issued trees, not authorization roots
and not workspace-only state).

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
only that field's value followed by a newline; most fields are scalar, and
`allowed_roots` prints its rich JSON array.

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

`docker-helper config allowed-root <list|add|set-access|remove> [PATH]` —
manages the global allowed_roots array. `add` canonicalizes and validates the
path; authorization-only, does NOT prepare MAC state.
`set-access` changes the access mode of exactly one stored root, matched by
the stored canonical identity; a root that is not stored is a user-facing
error, never an idempotent no-op.
`remove` resolves and matches the stored canonical form; rejects removal of
the final global root. `list` prints the 2.1-compatible one canonical root
per line by default; the explicit `--json` opt-in prints the canonical rich
entries, so the access mode of every global root is visible to access-aware
tooling.

`list` is the recovery-safe stored-config inspection: every stored entry is
projected to its canonical identity through the shared
`resolveAllowedRootIdentity` owner, so a stale entry whose directory was
deleted outside docker-helper stays visible and addressable. Runtime
validation is unchanged — daemon startup and reload still fail closed on a
missing stored root, and only the removal of the stale entry through
`remove` (which works with the daemon down, like every config mutation)
restores a startable config.

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
the command returns an error. The whole reload transition — including the
trusted-CA runtime preparation — shares the `lifecycleMu` create/reload
linearization boundary and is bounded (the trusted-CA restorecon runs under
the fixed MAC transition budget, see
[Bounded MAC-command execution](#bounded-mac-command-execution-h8)), so a
failed preparation releases the coordination within that bound and the
previous effective configuration stays active.

### Strict config document grammar

Every read of config.json goes through ONE strict ingest boundary
(`decodeStrictConfigDocument` + `validateConfigMemberGrammar` +
`validateRawConfig` + the `fileConfig` projection from the proven map;
composed for fully-validating consumers as `decodeAndValidateConfigDocument`):

- exactly one top-level JSON object; a top-level `null`, array, scalar,
  malformed JSON, or trailing second JSON value fails closed;
- duplicate top-level members fail closed — the persisted config is
  security policy/state, so one JSON member must map to one config
  identity, never "last wins";
- member names are matched by EXACT spelling against the config-file
  vocabulary (`allowed_roots`, `session_ttl`, `log_level`, `audit_enabled`,
  `shutdown_timeout`, `operation_retention_ttl`, `operation_max_completed`,
  `operation_log_max_bytes`, `trusted_ca_path`, `trusted_ca_injection`,
  `http_address`, and the exact legacy migration input `allowed_root`):
  a case variant such as `Operation_Max_Completed` or `Session_TTL` is
  refused as unknown, never treated as an alias — `encoding/json` struct
  matching would silently fold it onto the canonical field, so the refusal
  happens before any `fileConfig` projection. There is no case
  normalization and no alias map;
- computed fields keep the computed diagnostic, deprecated fields the
  rename diagnostic, and retired fields the retired diagnostic — by exact
  spelling only;
- all value semantics stay with their existing owners (`parseSessionTTL`,
  `parseLogLevel`, duration bounds, positive-integer bounds, trusted-CA
  values, `validateHTTPAddress`, the `allowed_roots` schema with the exact
  nested `{"path","access"}` object grammar); the document boundary adds
  no parallel value rules.

Malformed config never reaches effective `Config`: the refusal happens
before the runtime-directory creation, trusted-CA preparation, or any other
runtime side effect, and a reload failure leaves the previous effective
configuration authoritative. The strict boundary serves daemon startup,
reload, `config show`/`show FIELD`, the config transaction preflights, and
`init`'s existing-config inspection alike. A config mutation on an existing
document carrying an unknown, case-variant, or duplicate member is refused
without rewriting the file (a mutation never erases the evidence of
malformed input as a side effect); invalid member VALUES keep their
existing repair semantics — setting or unsetting the invalid field itself
is the documented operator recovery.

The CLI field-selection vocabulary (`config show/set/unset FIELD`) is
already exact and case-sensitive and is unchanged; this grammar is about
the config-file document members, which are the same canonical snake_case
names.

## Data-plane execution

### Operation lifecycle

```
Authentication
    │
Request validation
    │
Request-shape ceilings (caller-mount count)
    │
Lexical capability admission
    │
Canonical filesystem resolution
    │
Canonical containment/policy proof
    │
Capacity reservation (supervisor — atomic with shutdown/quiesce/ceilings)
    │
Expensive preparation (MAC lease, pins, workload MAC, H4 staging)
    │
Final admission (supervisor re-checks lifecycle closure; transfers reservation)
    │
Async process start (cmd.Start under op.mu)
    │
Incremental bounded log capture (cmd.Stdout/stderr → boundedBuffer)
    │
Completion goroutine (cmd.Wait → status transition; capacity released exactly once)
    │
Retention cleanup (independent of capacity)
```

The synchronous surfaces (pull, registry login) share the same
supervisor accounting without the Operation stages: capacity reservation
before any Docker process, whole synchronous execution under the
reservation, exact-once release when the handler returns, and no
registration in the supervisor's Operation map (see
[Synchronous execution capacity](#synchronous-execution-capacity-sc2h5-release-owner-decision)).

Authentication validates the session token. Request validation checks
required fields and path relativity per operation. The H3 authorization
boundary orders every filesystem decision: the raw caller spelling is
proven lexically against its capability first (the effective allowed-root
ceiling at Session create, the issued Session filesystem snapshot for an
absolute run source, the workspace for a workspace-relative run source or
build context), and privileged host-filesystem probing — canonical
resolution through `EvalSymlinks`, stat — runs only after that admission;
there is no compatibility alias for a spelling outside the capability that
would resolve into it. After resolution the canonical containment/policy
proof runs as the second, mandatory security proof: a relative run source
must stay within the session workspace — the structural
workspace-containment rule of the relative grammar — a build context stays
workspace-constrained, and an absolute run source is authorized through
the issued immutable Session filesystem snapshot (see
[Filesystem policy](#filesystem-policy)); workspace containment is that
structural rule, not a universal data-plane authorization rule. A symlink
inside the lexical capability that resolves outside stays fail-closed
through that canonical proof.

Operation admission is the two-step `reserve → admitReserved` flow of the
operation supervisor (SC2/H5). Both steps are atomic under the same
supervisor mutex:

- `reserve(session, launcher, kind)` checks the Operation lifecycle gates
  (daemon shutdown, Launcher quiesce) and the fixed Release-2.2 capacity
  ceilings — Session scope, global scope, and the build sub-ceiling — then
  reserves one capacity slot in the same critical section, so concurrent
  reserves can never oversubscribe. The reservation happens BEFORE any
  expensive preparation: run reserves before the session MAC-use lease,
  mount probing, exposure resolution, pins and workload-MAC
  materialization; build reserves before H4 staging. Cheap
  syntactic/request validation may run first, and the caller-mount count
  ceiling is checked before the reservation (the request is already
  known invalid). No half-prepared Operation is ever registered to
  reserve a slot, and the public Operation model stays `running`,
  `succeeded`, `failed` — the reservation is a narrow internal lease,
  never an API/domain state.
- `admitReserved(op, reservation)` re-checks only the lifecycle closure:
  a reservation obtained before a Launcher quiesce or daemon shutdown is
  NOT an admitted Operation — "once quiesced, no new Operation
  admission" is preserved at final admission, and shutdown may still
  refuse. Already-reserved capacity is never re-checked or re-reserved;
  it transfers to the registered Operation. On refusal the caller cleans
  preparation and releases the reservation.

The same supervisor owns the shared capacity accounting for the
synchronous Session-token Docker execution surfaces: `POST /pull` and
`POST /registry/login` reserve one capacity slot through the same
Session/global counters (`reserveCapacity`, the pure resource-accounting
core that `reserve` also uses) BEFORE their Docker process is started,
and never register an Operation. Capacity is pure resource accounting:
the Operation lifecycle gates are not consulted — pull and registry
login are not closed on Launcher quiesce or on daemon shutdown
(lifecycle policy stays with its Operation-admission owners). The
synchronous reservation covers the whole request execution and is
released exactly once when the handler returns — completion, Docker
failure, and every pre-exec failure path included. There is no waiting,
no queue, no retry logic and no scheduler: at any ceiling the request is
refused immediately.

There is no queue and no waiting admission: at any ceiling the request
is refused immediately with the single bounded
`capacity_unavailable` refusal (HTTP 429) for every Session-token
Docker execution surface — run, build, pull, and registry login, for
both the Session scope and the global scope — the capacity topology is
never exposed — and the client decides whether and when to retry.

**Fixed Release-2.2 capacity ceilings (SC2/H5).** The ceilings are
measured security constants, not Principal/Launcher quotas and not
configurable:

| Ceiling | Value | Basis |
|---------|-------|-------|
| concurrent executions per Session | 4 | 2× the maximum per-Session concurrency exercised by the UAT (2), sized for realistic agent parallelism |
| concurrent executions globally | 8 | keeps at least half of global capacity available to other Sessions when one is saturated |
| concurrent builds globally (sub-ceiling) | 2 | worst-case hostile staging = 2 × 128 MiB (H4) = 256 MiB = 42% of the smallest supported /run tmpfs (3 GiB RAM, ~614 MB); ≥3 concurrent maximal builds would exceed half of it |
| caller mounts per run request | 16 | 16× the maximum single-request mount usage in all tests and UAT; worst kernel mount-table cost (3 entries per mount under SELinux) at the global ceiling is 384 entries = 0.4% of fs.mount-max (100000) |
| raw log bytes per HTTP logs response | 256 KiB | measured worst-case JSON-encoding expansion is 6× (control characters/invalid UTF-8), so one response stays under ~1.6 MiB encoded regardless of retention |

The execution ceilings count every admitted Operation AND every
synchronous pull/registry-login execution: the two concurrency limits
count preparation and running execution of Operations and the whole
execution of every synchronous pull and registry-login request through
the same shared counters. An Operation-backed capacity slot is released
exactly once when the
Operation reaches a terminal state (`succeed`/`fail` invoke the
transferred reservation release inside the winning transition); a
synchronous slot is released exactly once when the request handler
returns. Retained Operation metadata and logs never keep capacity, and
release is never coupled to `pruneCompleted()`. Operation release paths
include: preparation failure after reservation, pin failure,
workload-MAC preparation failure (rolled-back and retained variants),
build staging failure including the H4 refusal, final-admission
refusal, `cmd.Start` failure, pre-start cancellation/shutdown, normal
success, Docker failure, explicit cancel, and daemon-shutdown
termination. The user-mode deployment obeys the same fixed ceilings
without gaining system-mode mechanics.

The narrow build sub-ceiling exists so the generic run concurrency stays
usable while worst-case H4 composition stays safe (see
[Build-context staging ceilings](#build-context-staging-ceilings)); there is no second build scheduler, no build queue and no staging quota
manager.

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

**Bounded response chunks (SC2/H5).** One HTTP logs response carries at
most 256 KiB of raw retained log bytes, independent of the configured
`operation_log_max_bytes` retention. The measured worst-case JSON
encoding of adversarial bytes expands 6× (control characters and invalid
UTF-8 escape to six-character sequences), so a single response stays
under ~1.6 MiB encoded even for JSON-hostile output; one request can
never materialize the whole retained buffer. `next_offset` always
identifies the byte immediately AFTER the bytes actually returned —
never the total length when bytes in between were not returned. When
the requested offset predates the retained data, the read starts at the
oldest retained byte, returns at most one chunk with `truncated=true`,
and `next_offset` follows the returned bytes: no retained bytes are
silently skipped, and the consumer walks the chunks to catch up. There
is no caller-controlled limit parameter. The CLI drains the chunks
through one shared helper: every poll drains all currently available
chunks (real-time pace preserved), and when the operation reaches a
terminal state the same helper drains every remaining chunk before
returning, so successful CLI output is never truncated by chunking.

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
operation (exit 130/143).

Validation details:

- context may be relative (joined with workspace) or absolute (must be
  inside workspace);
- dockerfile must be relative to context;
- authorization-before-probing: the raw context spelling is admitted
  lexically inside the canonical session workspace, and the raw
  Dockerfile spelling lexically inside the resolved build context,
  before any host filesystem probing; a spelling outside is refused
  without probing, and the canonical `EvalSymlinks` + containment proofs
  after admission stay fail-closed (a symlink inside the lexical
  workspace/context that resolves outside is refused);
- build-arg names must match `^[A-Za-z_][A-Za-z0-9_]*$`;
- build-arg keys are sorted for deterministic Docker argv;
- build-arg values are never logged or audited (only `build_arg_keys`);
- build-arg values are passed to the daemon-side `docker` child as
  `--build-arg K=V` argv entries, with the same accepted Release 2.2
  residual as run environment values (observable through
  `/proc/<pid>/cmdline` while the build child runs, where host procfs
  policy permits; accepted M1 disposition, SC3 2026-09-16). Build args
  are explicitly NOT a secret transport and must not be used for
  secrets; Docker/BuildKit may additionally retain ARG-related material
  in image history/provenance — a property of build semantics that does
  not disappear when the CLI argv exposure is later removed. The argv
  class closes with the accepted Release 3 Engine API adapter migration;
  no `--env-file`-style or BuildKit secret knob is introduced for it.

Build context and Dockerfile are read-only host inputs of the helper:
after `validateBuildRequest` canonicalizes both paths, they are evaluated
against the persisted Session filesystem snapshot as read-only
consumption, which is permitted for either snapshot access mode — a build
is never refused because the context or Dockerfile lies in a read_only
region, and a snapshot/integrity evaluation failure here is `500
internal_error` before staging, operation, or Docker state exists. The
staging owner writes only into helper-owned staging under the runtime
directory; it never writes into the source tree, and the staged context
carries no SUID/SGID privilege bits (see
[Container security](#container-security)).

### Run

`docker-helper run` uses the same lifecycle semantics as `build`.
`--mount` source is a relative path (resolved against the session
workspace) or an absolute host path; target is an absolute container
path. Both spellings are authorized only through the issued immutable
Session filesystem snapshot.

```
Authentication + coherent filesystem authority read
    │
Request validation
    │
Workdir validation
    │
Environment validation
    │
Mount admission (lexical capability admission)
    │
Canonical mount-source resolution
    │
Filesystem exposure resolution against the persisted snapshot
    │
Source pinning + workload MAC preparation (system mode; in the
    accepted order with fail-closed rollback, see
    [System-mode run mounts](#system-mode-run-mounts))
    │
Operation registration (supervisor admission — atomic with shutdown gate)
    │
Async docker run process start (cmd.Start under op.mu)
    │
Incremental bounded log capture (cmd.Stdout/stderr → boundedBuffer)
    │
Completion goroutine (cmd.Wait → status transition)
    │
Unified terminal-path cleanup (one ordered owner: proven container
    absence, workload MAC state, source pins, ownership record,
    session-use lease, cidfile/residue)
```

Request validation checks that the image field is non-empty. Workdir
validation ensures the value is an absolute path if provided.
Environment validation ensures variable names match
`^[A-Za-z_][A-Za-z0-9_]*$`. Mount admission orders every mount decision
authorization-first: the raw caller source spelling is admitted lexically
against its capability before any privileged host-filesystem probing — a
relative source through `pathWithin` against the workspace, an absolute
source against the issued Session filesystem snapshot entries. Only
admitted spellings
are resolved to their canonical identity, and duplicate mount targets are
refused once each canonical target is known. After resolution, every mount's
access mode is resolved against the persisted Session filesystem snapshot
(see [Data-plane filesystem authority](#data-plane-filesystem-authority))
— the second, mandatory canonical proof, so a symlink inside the lexical
capability that resolves outside stays fail-closed; a refused writable
exposure is answered `read_only_root` before any pin/operation/Docker
state exists, and the MAC lease is released.

`helper_socket` validation is mode-aware: when the boolean is requested in
user mode the request is rejected (`invalid_helper_socket`) before any
lease, pin, or operation state exists. In system mode the capability is
accepted and a user mount may not use the injected mount point itself
(`invalid_mount`). The capability also owns the socket locator: the daemon
injects the server-owned `DOCKER_HELPER_SOCKET_PATH=/run/docker-helper/docker-helper.sock`
when the caller omitted it, accepts a caller-supplied exactly-canonical
value as one docker argv entry (remaining part of the caller env-key
audit), and refuses a conflicting value fail-closed
(`invalid_helper_socket`) before any lease, pin, operation, or Docker
state exists. The locator is transport reachability only — the Session
bearer is never injected by the daemon; without `helper_socket` the
locator is an ordinary caller environment variable with unchanged
behavior.

Container lifecycle:

- `--rm` — container is removed on exit;
- helper-owned `--cidfile` — records container ID for lifecycle management;
- graceful shutdown — Docker CLI receives SIGTERM;
- force fallback — daemon-side `docker kill` by CID, then CLI process
  force-kill/reap if needed;
- helper-owned containers are never left orphan after shutdown.

Validation details:

- workdir must be an absolute path if provided;
- mount source is a relative path (workspace-relative) or an absolute host
  path;
- mount target must be absolute;
- mount admission is authorization-first: a relative source is checked via
  `pathWithin` against the workspace and an absolute source against the
  issued Session filesystem snapshot entries before any privileged probing;
  the source is resolved through `EvalSymlinks` only after
  admission, and the issued snapshot exposure resolution stays the second,
  mandatory canonical proof;
- environment values are never logged (only names in `env_keys`);
- environment names are sorted for deterministic output;
- `helper_socket` injects the server-owned read-only runtime projection
  described in [Helper socket projection](#helper-socket-projection);
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
com.dockerhelper.operation.id    = <operation id> (run containers only)
com.dockerhelper.schema = 1
```

Labels are correlation/cleanup evidence, not authorization state. The
namespace is deliberately neutral: only the Launcher is the Session owner;
the Session and Principal labels are provenance. The run-only Operation ID
label is the correlation key between a container and its helper-owned
workload MAC state (see
[System-mode run mounts](#system-mode-run-mounts)); reconciliation uses
that label, never a PID.

### Pull

`POST /pull` authenticates, validates that the image field is non-empty,
reserves one shared capacity slot (see
[Synchronous execution capacity](#synchronous-execution-capacity-sc2h5-release-owner-decision)),
and runs `docker pull` with the image reference. The endpoint remains
synchronous and returns the execution result directly in the response;
pull output is captured into a bounded buffer of
`operation_log_max_bytes`, and when output exceeds the limit the newest
tail is retained with `truncated: true`.

Image reference syntax is delegated to Docker. The helper does not
reimplement the Docker reference grammar; it only checks that the image
field is non-empty. Docker CLI validates the reference when the command
executes. If Docker rejects the reference, the endpoint returns its
standard Docker failure response.

**Synchronous execution capacity (SC2/H5 release-owner decision).**
Pull and registry login remain synchronous and are never registered
Operations. Their execution concurrency is finite under the same fixed
Release-2.2 ceilings: each request reserves one capacity slot through
the shared Session/global counters before its Docker process is started
and releases it exactly once when the handler returns, on the same
ceilings as Operation-backed execution — a saturated Session or global
ceiling refuses a pull or registry login immediately with the one
canonical `capacity_unavailable` refusal (HTTP 429), with no waiting,
no queue and no retry logic. The synchronous surfaces are NOT closed on
Launcher quiesce or daemon shutdown: quiesce is the Operation-admission
lifecycle gate ("once quiesced, no new Operation admission"), and the
established refusal contract of those endpoints does not include
shutdown/quiesce codes; lifecycle policy stays separate from the shared
resource accounting. Their materialization channels are bounded as
before: the pull response is the complete retained buffer, bounded per
pull by the configured `operation_log_max_bytes` with the established
`truncated` flag, and registry login retains only a 4 KiB
classification buffer whose output is never exposed.

### Registry login

`POST /registry/login` authenticates a session with a Docker registry.

```
Authentication
    │
Request validation
    │
Shared capacity reservation (no Operation)
    │
Session Docker config directory
    │
Docker invocation
```

Request validation checks that `registry`, `username`, and `password` are
all non-empty. The synchronous capacity reservation happens before the
Docker invocation (see
[Synchronous execution capacity](#synchronous-execution-capacity-sc2h5-release-owner-decision));
the endpoint never registers an Operation.

The session Docker config directory is per-session, located at
`runtimeDir/sessions/<session_id>/docker`. It is created with `0700`
permissions on first login. This directory is used as the Docker config
home via `--config`, so registry credentials are isolated per session.

Docker invocation runs `docker --config <dir> login --username <user>
--password-stdin <registry>`. The password is passed via stdin, never
in argv, environment, logs, or audit records.

On success, the endpoint returns HTTP 200. On failure, it returns a
classified status/code: HTTP 401 `registry_auth_denied` for authentication
denial, HTTP 502 `registry_unavailable` for registry/backend failure, or HTTP
400 `registry_login_failed` for unrecognized failures. The Docker output is
never returned to the client; only a sanitized category message is sent, and
only a bounded amount of stderr is captured (never logged or returned) to
support classification.

### Filesystem policy

#### Bind mounts

Each mount in a `POST /run` request specifies a `source` and a `target`
(absolute path inside the container). The source is either a relative path
(resolved against the session workspace, the existing convenience) or an
absolute host path (an issued Session filesystem root).

Authorization-before-probing: the raw caller spelling is admitted
lexically against the issued filesystem capability FIRST — the canonical
workspace for the relative grammar, the issued snapshot entries for the
absolute grammar — and the privileged host-filesystem probing (symlink
resolution, stat) runs only after that admission. A spelling outside the
capability is refused immediately without probing; there is no
compatibility alias for a spelling outside the capability that would
resolve into it. After resolution the canonical containment proofs stay
fail-closed: the relative grammar re-proves workspace containment on the
resolved path (a symlink inside the workspace that resolves outside is
refused), and the absolute grammar is authorized through the snapshot
exposure resolution.

Allowed:

- `source` is a relative path lexically inside the session workspace, or
  an absolute host path lexically inside the issued Session filesystem
  snapshot;
- `source` resolves to an existing directory or regular file;
- `source` is `.` (the entire workspace);
- `target` is any absolute path;
- `read_only` is true or false;
- the same `source` can be mounted to multiple `target` paths.

Forbidden (structural request validation, before admission):

- `target` is empty;
- `target` is not absolute;
- `target` is `.` or `..`.

Forbidden (refused before any host filesystem probing — the lexical
capability admission):

- a relative `source` whose joined spelling escapes the session workspace
  lexically — the workspace-relative grammar is a structural boundary,
  never an alternate way to reach another issued root: an absolute source
  is the only spelling for that;
- an absolute `source` spelling outside the issued Session filesystem
  snapshot — every mount must carry issued snapshot authority.

Forbidden (after canonical resolution — the canonical proof and later
canonical facts):

- a symlink inside the lexical capability that resolves outside it — the
  relative grammar re-proves workspace containment on the resolved path,
  and the escape protection is unchanged;
- `source` does not exist;
- `source` is not a directory or regular file;
- two mounts use the same `target` (checked once each canonical target is
  known).

The relative grammar keeps the mount scoped to the session workspace; an
absolute source is authorized only through the issued Session filesystem
snapshot, so a path the Launcher allows but this Session did not request
is still not mountable by this Session.

#### Docker bind-mount serialization

One canonical production owner serializes every Docker bind-mount form —
user mounts, the trusted CA injection, and the helper-socket runtime
projection — into exactly one `--mount` argument
(`dockerBindMountSpec`, from the structured facts `{source, target,
readonly}`). Request validation, filesystem authorization, and Docker argv
serialization stay separate layers: the serializer owns only the encoding
and the safe representability of a `--mount` value, never path policy.

The grammar is the authoritative Docker CLI grammar
(`opts/mount.go`, `MountOpt.Set`): one `--mount` value is ONE CSV record
read once, whose fields are `key=value` pairs (first `=` splits) or
boolean flags such as `readonly`; later duplicate keys overwrite earlier
ones. The serializer encodes the record with Go's `encoding/csv` — the
Docker-sanctioned encoding — so a crafted source or target stays exactly
ONE field: commas, quotes, newlines, lone carriage returns, `=` signs, and
backslashes cannot add a mount option, change the target, remove
`readonly`, add `rw`, change the type or source, or create a second
logical field. The former scattered comma prohibitions are gone: a
comma-carrying source or target is now safely representable and mounted
at exactly the intended path and consumption mode.

Representability is a three-boundary invariant, not a list of ad-hoc
prohibitions: an accepted source or target must (1) round-trip through
the `encoding/csv` record unchanged, (2) remain unchanged under Docker's
`MountOpt.Set` value validation — the CLI rejects an empty value and a
value with leading or trailing whitespace — and (3) be representable
through exec argv, which cannot carry an embedded NUL byte. Whitespace
inside a path is representable; whitespace at the edges of a source or
target is not.

Fail closed: a source/target that fails any boundary is refused — the CSV
reader normalizes the literal CRLF pair to LF inside quoted fields, a
whitespace-padded or empty value fails the Docker value validation, and a
NUL byte fails exec argv. Refusal timing follows the two value classes.
Caller-controlled bind facts — the container target in every mode and the
canonical resolved source in user mode, where the resolved host path
itself is the bind source — are proven representable at request
validation: before pinning, before workload-MAC preparation, before the
operation admission, before `run.start`, and before any Docker state, and
such a refusal answers `invalid_mount`. Actual daemon-owned or prepared
bind sources — the system-mode pinned source, the trusted-CA prepared
source, and the helper-socket runtime projection source — become known
only after the pins and the workload MAC state are prepared, so a
serialization failure of one of them surfaces after that preparation but
before the operation admission, before `run.start`, and before Docker
execution and container creation: the prepared state rolls back through
the canonical rollback owner and the run answers `internal_error` with no
admitted Operation. This is the one representability boundary of the
serialization; it lives in the serializer owner, never as scattered
per-caller prohibitions, and no shell escaping is involved (the Docker
argv is structured exec argv).

On top of the structural validation, the access mode of every accepted
mount is enforced against the persisted immutable Session filesystem
snapshot — the only data-plane filesystem authority, issued at Session
creation. The policy decision uses only the canonical source identity
produced by `resolveMount` (lexical capability admission, then
`filepath.Abs`/`EvalSymlinks` + type validation of the admitted spelling,
then the canonical containment proofs), never the caller
spelling: a symlink spelling never selects a different access mode. A
read-only request is permitted for either snapshot access mode; a writable
request is permitted only through the snapshot owner's writable-parent query
(`CanExposeWritable`), so a read_write source spanning a nested read_only
region is refused. A refused writable request is answered with `400
read_only_root` before any mount pin, operation, or Docker state exists —
it is distinct from `invalid_mount` (structural validation) and never
rewrites the request to read-only silently. The Docker bind is
materialized exactly in the caller-requested mode (readonly flag follows
the request, not the snapshot access of the source).

#### Data-plane filesystem authority

Every filesystem-consuming data-plane request (`run` mounts, `build`
context/Dockerfile) resolves its host filesystem decisions exclusively
against the persisted immutable Session filesystem snapshot loaded through
the canonical loader. Current global/Principal/Launcher allowed-root
policy is never read on the data plane: parent-policy mutations cannot
change an already-issued Session's runtime authority, and a Session created
under older policy keeps behaving by its issued snapshot.

The Session bearer authentication and the snapshot load of such a request
read one database generation: the filesystem-capability variant of the
Session auth captures both in one short read transaction. A concurrent
Session deletion or invalidation either linearizes before that read
transaction (the lookup fails closed with 401) or after the captured
immutable authority (the already-started request continues); an
authenticated Session whose snapshot vanished through the deletion cascade
is structurally impossible. The read transaction ends when the authority
is captured and is never held across filesystem I/O, pinning, staging, or
Docker execution. The pathless data-plane actions (pull, registry login,
operation status/logs/cancel) keep the plain Session authentication because
they consume no Session-controlled host filesystem source.

A snapshot that is genuinely corrupt when a request loads it (post-startup
state surgery or filesystem-level damage) is an internal integrity failure:
the request fails closed with `500 internal_error` and the operational log
carries the session ID and the integrity cause. It is never answered as
unauthorized, `invalid_mount`, or `read_only_root`, and it is never repaired
at request time. The failure is audited as exactly one
`<kind>.rejected` event with `result=internal_error` and the session's
ownership provenance (run and build symmetrical; no bearer or secret
values).

The shared decision adapter between the persisted snapshot and the
data-plane consumers is `resolveSessionFilesystemExposure`: it resolves one
canonical source identity against the snapshot for the requested
consumption mode and returns the accepted exposure facts (canonical source,
target, caller-requested read-only mode, effective snapshot access, and the
writable-exposure permission). Run materialization and the workload MAC
projection consume this same accepted exposure plan; the MAC
backends do not load snapshots or recompute writable-parent semantics.

#### System-mode run mounts

The caller-mount count ceiling (SC2/H5) is checked immediately after
request decoding/basic validation, before the Session MAC-use lease,
mount probing, exposure resolution, any pin, workload-MAC preparation,
and the Operation reservation: a run request carrying more than the
fixed 16 caller mounts is refused with the bounded `too_many_mounts`
client-input refusal. Every `req.Mounts` element consumes one slot —
duplicates and read-only requests included; the server-owned
`helper_socket` projection is not a caller mount. The 16 KiB HTTP
request-body limit is not the security owner of this count, and no
private mount namespace is introduced: existing pins remain visible to
dockerd.

In system mode, every bind-mount source has already been accepted by the
filesystem exposure resolution (issued snapshot authority). The helper
then opens "/" as a root file descriptor. The source path is converted
to a root-relative path and opened with `openat2` using
`RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, and `RESOLVE_NO_MAGICLINKS`
relative to the root FD, so any issued absolute source — inside the
workspace or in a disjoint Session filesystem root — is pinned through
the same owner. The resulting inode
is pinned with `open_tree` + `move_mount` into a helper-owned directory
under the runtime path. Docker receives the pinned path, not the original
workspace path. The pins and the workload MAC materialization happen
only after the capacity reservation (see
[Operation lifecycle](#operation-lifecycle)), so a capacity-refused run
creates neither.

Pinning requires Linux kernel support for `openat2`, `open_tree`, and
`move_mount`, and `CAP_SYS_ADMIN`. When any of these are unavailable or
fail, the operation fails closed with no pathname fallback. Pinned mounts
are cleaned up as part of the operation lifecycle.

After the pins and before admission, the workload MAC coordinator
(`workloadMACCoordinator`) materializes the accepted
`sessionFilesystemExposure` plan as an additional mandatory-access-control
layer. The workload RO/RW mode is the caller-requested mode
(`RequestedReadOnly`); the coordinator never reads allowed-root tables,
snapshots, or `LookupAccess`/`CanExposeWritable`, and never narrows an
accepted writable exposure. Under the AppArmor backend it renders one
generated profile `docker-helper-workload-<operation-id>` from the Moby
docker-default baseline. Read-only container targets are distinguished by
their pinned node kind: a regular file receives an exact-path
`audit deny "<encoded-literal>" wkl,` rule protecting the file's own
write/delete/link semantics, and a directory receives a recursive
`audit deny "<encoded-literal>/{,**}" wkl,` rule whose recursion is
scoped around the accepted read-write transitions inside it (a nested
RW target carves a writable subtree out of the RO region; a nested RO
target inside that RW subtree re-scopes protection) — the renderer
consumes only the accepted exposure plan and never resolves policy
itself. The profile is loaded through `apparmor_parser`,
verifies the load through the kernel profile inventory, and passes
`--security-opt label=disable` plus `--security-opt apparmor=<profile>` to
Docker. Under the SELinux backend it builds one bindfs passthrough
projection per read-only exposure from the pinned source with mount context
`system_u:object_r:docker_helper_ro_projection_t:s0` (read-write exposures
bind the pinned source directly; a regular-file source is bound onto a
helper-owned lower item and the lower directory is projected, with the
deterministic `mount` mountpoint created for both projection kinds before
the FUSE worker starts), verifies mountpoint + FUSE worker +
effective SELinux type, and keeps `--security-opt
label=type:docker_helper_container_t` so Docker retains MCS ownership;
accepted read-write exposures still bind the pinned source directly. The
backend-neutral prepared result carries only Docker security options and
per-mount bind sources; build inputs receive no workload MAC material.

Run resources are released by one unified cleanup owner through a frozen
order — container proven absent, workload MAC state, source pins, durable
workload ownership record/state, session-use lease, cidfile — from every
terminal path, including pre-start failures (no container by construction)
and post-start paths with one canonical container-absence proof. The
durable ownership record is removed only after the stages it anchors are
positively proven done, so a failed proof or failed cleanup leaves it as
the reconciliation retry marker for whatever helper state remains; the
backend prepared cleanup itself releases only kernel MAC state and backend
files and never removes the durable record. A partial durable-state removal
fails ordered (transient runtime directory first, durable record
directory last) so a runtime-removal failure cannot strand surviving state
without its owner. A failed proof or failed MAC
cleanup retains dependent state (fail closed) for startup reconciliation,
which runs before the daemon accepts HTTP requests and cleans only
positively identified helper-owned state. A preparation failure whose
partial MAC state could not be rolled back is returned to the run path as
a typed retained outcome (`workloadMACRetainedError`): the run fails, no
container starts, and the dependent source pins and session-use lease
remain until startup reconciliation; any other preparation failure means
the MAC state was fully rolled back and the caller releases the dependent
resources as usual. Reconciliation removes the durable ownership record
only after the correlated container is proven absent, the backend MAC
state is positively gone (mount-inventory proofs; an unverified unmount or
an unknown inventory retains state), and the stale pin residue is
positively removed — a failed stage leaves the record as the retry marker.
Durable ownership records live under `<StateDir>/workload-mac/<operation-id>/`
and are committed before any kernel-side resource; transient projection
state lives under `<RuntimeDir>/workload-mac/<operation-id>/`. The record
carries the exact schema, operation ID, session ID, backend enum, and
timestamp; every backend-specific kernel identity (for example the AppArmor
profile name) is derived deterministically from the schema and the
operation ID at validation/cleanup time, never stored as a second owner.
The decoder is exact (`DisallowUnknownFields`, one JSON value, canonical
issued identity shapes for the operation and session IDs — exact prefix
and exact lowercase hex length, not merely path-safe strings — and exact
backend enum); malformed state is retained, never normalized. Startup
reconciliation proves the exact deterministic runtime shape (real
directories, canonical `mount-<decimal index>` names, expected
`mount`/`lower`/`item` nodes) before any unmount or removal and retains
anything else. Projection release follows a frozen dependency order:
projection unmount with positive absence proof, owned worker exit proven
(a live bindfs worker backs on the lower tree), lower file bind unmount
with positive absence proof, then projection state removal; reconciliation
entries carry no worker handle and never adopt or signal workers by PID.
Container correlation uses the reserved server-owned runtime
labels (schema, `com.dockerhelper.operation.id`, Session ID), never a PID.

#### User-mode run mounts

In user mode, the resolved mount source must equal the canonical
`session.Workspace`. Subdirectory and file mounts are rejected as
`invalid_mount`. The caller-mount count ceiling is mode-independent: a
user-mode run request is refused with `too_many_mounts` beyond the same
fixed 16 caller mounts even though user mode creates no inode pins.

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

Staging is the one current helper content-ingest path (H10 accepted
boundary): the root-owned daemon copies the workspace capability's
contents into the staging tree, so every file inside the granted
capability — not only files the host Principal could read under Unix DAC
— becomes part of the staged context the builder consumes. This is the
deliberate filesystem-capability semantics, not an access check gap; the
builder's own execution/network position is the separately accepted H1
boundary (see [Current limitations and
non-goals](#current-limitations-and-non-goals) and
[`release-2.4-build-sandbox.md`](release-2.4-build-sandbox.md)).

On platforms or kernels where `openat2` is unavailable, the operation
fails closed without falling back to original workspace paths.

**Staging ceilings (Release 2.2, H4).** One staging operation has hard,
measured, non-configurable security ceilings for exactly three
dimensions, enforced by one per-staging budget inside the existing
descriptor-relative walker (`productionBuildStagingCeilings` in
`staging_linux.go`). H5 composes with these ceilings multiplicatively:
the global build sub-ceiling (2 concurrent builds) bounds the worst-case
hostile staging occupancy at 2 × 128 MiB = 256 MiB on the runtime tmpfs
(see [Operation lifecycle](#operation-lifecycle)); the staging budget
owner itself is unchanged. The three dimensions:

- **payload bytes: 128 MiB.** The first staged copy of a unique
  regular-file inode reserves its logical size (`st_size`) before the
  destination file is created or copied — the conservative reservation,
  because the copier de-sparsifies, so a sparse source file occupies its
  logical size. Subsequent hardlink names to the same source inode do
  not reserve the payload a second time; staged symlink targets are
  accounted by their target bytes; directories are governed by the
  entry/depth ceilings. Admission arithmetic is overflow-safe: the
  ceiling comparison runs before any counter mutation, so a near-max
  `st_size` cannot overflow into acceptance.
- **entries: 50000.** "Entry" means every attacker-controlled source
  entry staging would materialize below the context root — regular
  files, hardlink directory entries, symlinks and directories; the
  context root itself is not an attacker-variable entry. Enumeration
  admission is the one reservation owner of every entry: a source name
  is reserved against the single global entry budget when it is
  admitted into a directory enumeration slice, before the append and
  before any materialization, and materialization paths never reserve
  an entry again — every materialized entry has exactly one
  reservation, taken before its corresponding destination entry is
  created. Because a parent's enumeration slice stays live during the
  recursive descent into its children, the sum of all simultaneously
  admitted enumeration entries of one staging operation can never
  exceed the ceiling, whatever the directory iteration order. A
  hardlink consumes another entry even though it does not duplicate the
  file payload inode. The Dockerfile is included in the accounting like
  any other staged file.
- **depth: 64.** The context root is depth 0, a direct child is depth 1.
  A destination directory deeper than the ceiling is admitted before its
  destination `mkdir` and before the recursive descent into it, bounding
  both destination nesting and the walker's Go recursive stack depth.
  Files may sit one level deeper than the deepest admitted directory.

Enumeration itself is bounded: directory enumeration draws from the
same single global entry budget, so a hostile directory is refused
during enumeration — before any of its entries is materialized — and
the daemon can never hold more than the ceiling's number of admitted
names across all live enumeration slices of one staging operation.
There is no pre-scan or second filesystem walker: the same
descriptor-relative traversal measures and reserves as it copies,
before each corresponding expensive destination action.

The ceilings are measured production constants, not configuration:
there is no config.json key, CLI knob, or Principal/Launcher/Session
override, and no quota hierarchy. Measured rationale (Release 2.2): the
largest representative build contexts are repository snapshots with
build artifacts (~35 MB payload, ~2000 entries, depth ≤ 6) and
node_modules-style trees (~2.4k entries); the smallest evidence-backed
UAT environment is the 3 GiB Tumbleweed VM, whose `/run` tmpfs systemd
sizes at 20% of RAM (≈614 MB) with an 800k-inode default. The ceilings
therefore bound one hostile build to ≤ ~21% of that tmpfs (bytes) and
≤ 6.25% of its inode budget (entries) with ≥ ~3.7x / ~21x / >10x
headroom over the measured realistic workloads. One byte/entry/level
over a ceiling refuses; exactly-at-limit succeeds.

A ceiling refusal is a typed expected staging refusal
(`buildStagingCeilingError`: resource `bytes`/`entries`/`depth`, the
fixed ceiling, the attempted reservation). The build handler classifies
it — and only it — into the single canonical
`build_context_too_large` code with HTTP 400, consistent with the
existing build client-input refusal grammar (400 family; a deliberately
new 413 status is not introduced because the `code` field is this API's
programmatic discriminator). The public message names only the
exhausted dimension and carries no source path or file-name material;
operational diagnostics carry the dimension and the numeric
limit/attempted values. Every other staging failure remains
`internal_error`. A refusal leaves no staging residue: the existing
descriptor-relative failure cleanup removes the operation tree before
the handler responds, no Docker invocation or admitted Operation
follows, no `build.start` event exists, and the acquired session MAC-use
lease is released.

Staging directories are cleaned up as part of the build operation
lifecycle.

### Environment and trusted CA

Environment variable names must match `^[A-Za-z_][A-Za-z0-9_]*$`. Values
can be any string, including empty. Values are never logged; only variable
names appear in `env_keys`. Environment variables are sorted by name
before being passed to Docker, making the command line deterministic and
reproducible.

The CLI `run` command additionally accepts `--env-from DEST=SOURCE`. The
value of SOURCE is read from the CLI process's own environment and
delivered as DEST through the same request `environment` contract as
`--env`; the daemon sees no difference between the two flags. Resolution
is a CLI-side concern and is fail-closed: an unset SOURCE stops the
command with exit code 2 before any request is sent, so no run Operation
is created and no runtime residue remains. A SOURCE that is set but empty
is delivered as an empty value. An invalid DEST name is rejected by the
existing daemon environment validation exactly like an invalid `--env`
name. Resolved values exist only in the request body; they are not placed
in the `docker-helper` process's argv, are not printed in CLI diagnostics,
are not inherited from the surrounding process environment, and the
daemon does not log environment values (only names appear in `env_keys`).
Only explicitly requested variables are forwarded; the rest of the CLI
process environment is never inherited. When both `--env` and
`--env-from` define the same name, the `--env-from` value wins.

Known limitation (introduced with the 2.1.x run implementation and still
current in Release 2.2; accepted M1 disposition, SC3 2026-09-16): `run`
starts the workload through the legacy Docker CLI, and the daemon passes
environment values to that child process as `--env DEST=value` argv
entries, so a resolved value is visible in the argv of the daemon-side
`docker` child process for the child's whole execution — a local process
may observe it through `/proc/<pid>/cmdline` where the host procfs policy
permits such observation. This is a deliberately accepted Release 2.2
residual of the daemon-side legacy Docker CLI argv, not a missed check:
no `--env-file` transport, dual transport, temporary secret-file
subsystem, or env-grammar narrowing is introduced, because a partial
closure of `run` only (and only of the subset of the arbitrary-string
env contract a file grammar can represent) would leave `build_args`
exposed and create the false impression that the CLI transport became
secret-safe. `--env-from` therefore scopes its guarantee to the
`docker-helper` CLI process boundary only; it does not promise the value
is absent from every process argv on the system. Migrating `run` (with
`build`) away from the legacy Docker CLI to a docker-helper-owned Docker
Engine API adapter is Release 3 work, not a Release 2.2 goal; that
migration removes the CLI argv exposure.
`--env-from` introduces no new daemon-side concept: the existing
`run.environment` contract fully owns delivery.

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

### Helper socket projection

`--helper-socket` (HTTP field `helper_socket`) is a server-owned special
capability that gives a `POST /run` workload transport reachability to the
existing helper Unix socket through its own existing runtime directory.
The canonical public name is `helper_socket`; no parallel transport or
socket exists.

In system mode the daemon injects one additional read-only bind mount:

```
/run/docker-helper (host runtime directory)
    -> /run/docker-helper (container, readonly)
```

The client selects only the boolean. It never chooses the source, the
target, or the mount mode, and the ordinary mount policy does not change:
mount sources stay workspace-relative (workspace-scoped) or absolute host
paths authorized through the issued Session filesystem snapshot, workspace
escapes stay rejected, and allowed-root semantics are untouched. When the
projection is active, a user mount whose target overlaps the injected
mount point — exact match, ancestor (`/run`, `/`), or descendant
(`/run/docker-helper/docker-helper.sock`) — is rejected as `invalid_mount`:
a caller-owned mount must not be able to shadow, replace, or partially
cover the server-owned projection (same exact + ancestor + descendant
principle as trusted-CA injection). Without `helper_socket` the 2.1.0
mount contract is unchanged.

The projection also carries one server-owned socket locator: with
`helper_socket` the daemon injects
`DOCKER_HELPER_SOCKET_PATH=/run/docker-helper/docker-helper.sock` into the
docker argv when the caller omitted it, accepts a caller-supplied
exactly-canonical value (kept as one argv entry and still part of the
caller env-key audit), and refuses a conflicting value as
`invalid_helper_socket` before any lease, pin, operation, or Docker state
exists. The locator describes transport reachability only; the Session
bearer is never injected (the caller passes `DOCKER_HELPER_SESSION_TOKEN`
explicitly when the workload needs authority), and without
`helper_socket` the variable is an ordinary caller environment variable.

The projection binds the runtime DIRECTORY, not the socket inode. The
systemd unit preserves the runtime directory
(`RuntimeDirectoryPreserve=restart`) and the daemon recreates
`docker-helper.sock` inside the same directory, so a consumer that does
survive daemon replacement — for example an orphaned container in a crash
scenario — observes the recreated socket through its existing directory
bind where a socket inode bind would go stale. This says nothing about
the workload lifecycle: a normal graceful `systemctl restart
docker-helper` still terminates helper-owned run workloads under the
current shutdown lifecycle (see [Shutdown](#shutdown)), and
`helper_socket` does not change that
lifecycle. No workload survival across a service restart or a package
upgrade is promised.

Authority is transport reachability only. The socket grants no
Session/Launcher/Principal/Admin credential, restores no credential from
ownership, does not raise the current Session's authority, and carries no
bearer token; protected operations authenticate exactly as any other API
client, with the credential passed separately (for example through
`--env-from`). The injected mount is read-only, so the workload cannot
create, remove, or replace top-level runtime entries, and helper-private
runtime state (`builds/`, `mounts/`, `sessions/`, the socket lock, and cid
files) remains unreadable for the Principal-UID workload through the
helper-owned directory permissions; the known entry names are not
authority. The server-owned workload privilege floor
(no-new-privileges, dropped capabilities) is what makes that DAC boundary
non-bypassable from inside the workload: with no privilege escalation path
left, the strongest reachable workload identity is the Principal UID:GID,
which the helper-owned `0700` runtime state denies. Hostile live UAT on
both mandatory MAC backends proves the composition (the socket stays
reachable, an unauthenticated call stays refused, the private runtime
stays unreadable and immutable, and the escalation stays dead); under
enforcing SELinux the shipped policy grants the workload
exactly the traversal and socket-connect permissions needed to reach the
socket and nothing else; under AppArmor system mode the workload remains
confined by the generated per-workload
`docker-helper-workload-<operation-id>` profile (Docker's SELinux labeling
is disabled with `label=disable`, which does not disable AppArmor — see
[System-mode run mounts](#system-mode-run-mounts)), and the same isolation
is provided by the helper-owned filesystem permissions, the read-only
mount, the privilege floor, and unchanged bearer authentication:
reachability to the helper socket grants no authority.

In user mode the runtime directory is owned by the daemon owner with
`0700` permissions, and user-mode workloads run under that same UID, so a
directory projection would expose the daemon's full runtime state
(including other Sessions' Docker CLI configuration) to the workload.
`--helper-socket` therefore fails closed in user mode with the stable
`invalid_helper_socket` error. This is a documented limitation (since
2.1.1, still current in Release 2.2), not an oversight.

`run.start` and `run.finish` audit records include a `helper_socket`
boolean (true only when the projection was active for that run). The
injected mount is not part of the user `mounts` audit, matching the
trusted-CA injection precedent.

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

- the operation admission gate closes immediately (no new operations accepted);
- HTTP drain and operation termination share one `shutdown_timeout` budget;
- in-flight HTTP requests are drained;
- running build/run processes receive graceful SIGTERM;
- for run, helper-owned containers are cleaned up via cidfile before
  force-killing the Docker CLI process;
- at the reserved force-cleanup window before the deadline, still-running
  processes are force-killed;
- the completion goroutine owns `cmd.Wait()` and reaps each process;
- the lock is held during the entire drain so a second instance cannot
  start until the first fully stops;
- helper-owned build/run processes and containers are never left unmanaged
  after shutdown;
- external MAC children cannot outlive the stopped daemon: every MAC
  command carries `Pdeathsig=SIGKILL` and every serialized MAC transition
  is bounded (see
  [Bounded MAC-command execution](#bounded-mac-command-execution-h8)), and
  the shipped units' `KillMode` default (`control-group`) kills any process
  remaining in the unit's cgroup when the service stops.

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
  preserved across service restarts, so a consumer that does survive
  daemon replacement observes the recreated socket through its existing
  directory bind; a normal graceful `systemctl restart docker-helper`
  still terminates helper-owned run workloads under the current shutdown
  lifecycle (see [Shutdown](#shutdown)), and normal cleanup semantics
  still apply on a real service stop.
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
denied). No shipped directive hides procfs, and the recursive workspace
relabel depends on real procfs (see [Mandatory access control](#mandatory-access-control)):
any future hardening that would separate the daemon from procfs must also
fail that relabel closed. Access to kernel and cgroup paths is restricted by the AppArmor
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
| `build_context_too_large` | `POST /build` | the build context exceeds one of the fixed build-staging security ceilings (staged payload bytes, entries, or depth); the message names only the exhausted dimension — one canonical code for all three dimensions (see [Build context](#build-context)) |
| `invalid_build_args` | `POST /build` | build-arg name invalid |
| `invalid_image` | `POST /run`, `POST /pull` | image name is empty |
| `invalid_mount` | `POST /run` | mount validation failure |
| `read_only_root` | `POST /run` | the issued Session filesystem snapshot refuses the requested writable exposure of the mount source |
| `invalid_workdir` | `POST /run` | workdir is not an absolute path |
| `invalid_environment` | `POST /run` | environment variable name invalid |
| `invalid_shm_size` | `POST /run` | shm_size invalid, zero, or over 2 GiB |
| `invalid_helper_socket` | `POST /run` | helper_socket requested in user mode (unsupported there) |
| `invalid_workspace` | `POST /sessions` | workspace invalid or outside AllowedRoot; the message carries the actionable cause for a request spelling admitted by the lexical ceiling proof, and the bounded authorization-shape refusal (`workspace must be inside an allowed root`) for a spelling outside it — an unadmitted spelling is refused without any host filesystem probing (authorization-before-probing; see [Session workspace](#session-workspace)) |
| `missing_launcher_selector` | `POST /sessions` | system-mode admin request supplies no launcher selector |
| `launcher_not_found` | `POST /sessions` | the selected launcher does not exist under the resolved principal |
| `launcher_unavailable` | `POST /sessions` | the selected launcher or its principal is durably disabled, or a final stale-owner recheck refuses the creation (422) |
| `lifecycle_busy` | `POST /sessions` | the lifecycle coordination was held by another transition when the create arrived; the non-waiting admission refuses the create without queueing (HTTP 503; no Session, no resolved policy state; the client decides whether to retry) |
| `invalid_filesystem_policy` | `POST /sessions` | the supplied `filesystem_roots` is malformed or is not a narrowing of the effective Launcher ceiling (issuance-time refusal; no Session exists) |
| `invalid_session_id` | `DELETE /sessions/{id}` | session ID is empty |
| `principal_not_found` | `GET /sessions?principal=` | the selected Principal does not exist (list narrowing; non-disclosing) |
| `launcher_not_found` | `GET /sessions?launcher=` | the selected Launcher does not exist inside the narrowed scope (list narrowing; non-disclosing) |
| `launcher_name_requires_principal` | `GET /sessions?launcher=` | a Launcher-name narrowing selector was supplied without a Principal scope (names are never searched globally) |
| `invalid_selector` | `GET /sessions` | a narrowing selector is illegal for the authenticated authority (a Principal selector under a Principal credential, any selector under a Launcher credential) |
| `shutting_down` | `POST /build`, `POST /run` | daemon is shutting down |
| `capacity_unavailable` | `POST /build`, `POST /run`, `POST /pull`, `POST /registry/login` | the fixed Release-2.2 concurrent execution capacity is exhausted (Session scope or global scope; one bounded refusal for all four Session-token Docker execution surfaces, whether Operation-backed or synchronous, HTTP 429 — no queue, the client decides whether to retry) |
| `too_many_mounts` | `POST /run` | the request carries more than the fixed 16 caller mounts (HTTP 400; checked before the MAC lease, probing, pins, MAC preparation and the reservation; individual mount paths are never reported) |
| `docker_pull_failed` | `POST /pull` | docker pull returned non-zero and the failure is not classified |
| `image_not_found` | `POST /pull` | docker pull: image/repository not found |
| `pull_access_denied` | `POST /pull` | docker pull: authentication/authorization denied |
| `registry_unavailable` | `POST /pull`, `POST /registry/login` | registry/network/backend failure |
| `registry_auth_denied` | `POST /registry/login` | docker login: authentication/authorization denied |
| `registry_login_failed` | `POST /registry/login` | docker login failed and the failure is not classified |
| `operation_not_found` | `GET /operations/{id}`, `GET /operations/{id}/logs`, `POST /operations/{id}/cancel` | operation not found or foreign session |
| `user_mode_owner_reserved` | Principal/Launcher mutation endpoints (user mode) | the target is the reserved transparent user-mode owner chain (daemon-owner Principal or its `default` Launcher) and the mutation would violate the startup contract |
| `invalid_username` | `POST /principals` | the supplied username is outside the Principal username text grammar (refused before OS lookup; an empty username is `missing_username`, OS account absence is `os_user_not_found`) |

After successful session authentication, every `POST /pull`,
`POST /build`, and `POST /run` request produces exactly one of:

- `<kind>.rejected` — the request was rejected before acceptance; or
- `<kind>.start` — the request was accepted as an operation.

where `<kind>` is `pull`, `build`, or `run`. Authentication failures
remain owned by the existing `auth.failure` path and do not additionally
emit `<kind>.rejected`.

The generic rejected event schema (`writeDockerActionRejected`) contains
only:

- `event`: `<kind>.rejected`
- `result`: the public API error code (e.g., `invalid_image`, `invalid_mount`,
  `launcher_unavailable`, `shutting_down`, `capacity_unavailable`,
  `too_many_mounts`, `internal_error`)
- `principal_name`: when available
- `session_id`: from the authenticated session
- `request_id`: from the request context

The `result` field exactly matches the public API response `code`.
Rejected events intentionally omit request payload metadata (image,
mounts, env, command, context, dockerfile, etc.) to avoid logging
partially validated input. No `operation_id` is included because a
rejected request was never accepted as an operation.

The one narrow policy-aware exception is `run.rejected` with
`result=read_only_root`: the filesystem-policy refusal adds the ordinary
`mounts` field with exactly one offending exposure record — the caller
`source`, the `target`, the requested mode (`read_only=false`, never
rewritten), the canonical `resolved_source` the snapshot owner decided
on, the effective `access`, and `writable_allowed=false` — plus the
session's ownership provenance. It never lists the contents of a
protected subtree or the specific nested blocker path, and it carries no
`operation_id` because the request was never admitted (the full facts are
described with the run audit schema below).

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
| Self introspection | `self.show` |
| Sessions | `session.create`, `session.list`, `session.show`, `session.delete` |
| Principals | `principal.create`, `principal.enabled_change`, `principal.allowed_root_add`, `principal.allowed_root_set_access`, `principal.allowed_root_remove`, `principal.delete` |
| Launchers | `launcher.create`, `launcher.list`, `launcher.update`, `launcher.scope_replace`, `launcher.allowed_root_add`, `launcher.allowed_root_set_access`, `launcher.allowed_root_remove`, `launcher.delete`, `launcher.credential_issue`, `launcher.credential_rotate`, `launcher.credential_delete` |
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
| `build_context_resolved` | string | canonical build context path the filesystem authority evaluated (present when resolved) |
| `build_context_access` | string | effective snapshot access of the resolved context: `read_write` or `read_only` |
| `build_dockerfile_resolved` | string | canonical Dockerfile path the filesystem authority evaluated (present when resolved) |
| `build_dockerfile_access` | string | effective snapshot access of the resolved Dockerfile |
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

Emitted for every `POST /sessions` request after authentication. A
commit-boundary credential rejection (the authorizing credential was
revoked, deleted, or lost its authenticated owner between authentication
and the Session-commit linearization point) is a credential
authentication-family outcome: it emits one `auth.failure` record with the
existing `credential.revoked`/`credential.not_found` classification
instead of a `session.create` record, and is answered with the shared
non-disclosing 401 contract.

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
| `invalid_filesystem_policy` | `filesystem_roots` is malformed or is not a valid narrowing of the effective Launcher ceiling; the Session was not issued |
| `lifecycle_busy` | the lifecycle coordination was held by another transition; the non-waiting Session-create admission refused the create without queueing (HTTP 503) — no Session, no snapshot, no resolved policy state; the audit record and the HTTP answer carry the same class |
| `mac_preparation_failed` | MAC boundary preparation failed before the create transaction (no Session exists) — HTTP 500; the audit record and the HTTP answer carry the same class |
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
| `launcher_path` | string | the allowed root a narrow allowed-root mutation touched (allowed_root_add/allowed_root_set_access/allowed_root_remove) |
| `launcher_enabled` | boolean | requested enabled state (update) |
| `principal_name` | string | owning principal |
| `result` | string | outcome code |
| `duration` | string | request wall-clock time |

Access-bearing allowed-root mutations
(`principal.allowed_root_add`, `principal.allowed_root_set_access`,
`launcher.allowed_root_add`, `launcher.allowed_root_set_access`) carry
`requested_access` (the access value the caller requested) and
`stored_access` (the access actually stored after the mutation) as
separate facts, so an idempotent no-op that observed a different stored
value is never audited as if the requested access had been stored.
`stored_access` appears only when a stored entry was actually known
(never for a refusal that stored or read nothing), and a value that was
never a canonical access mode is never logged as one.

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
| `helper_socket` | boolean | true when the helper runtime projection is active for this run |
| `workload_mac_backend` | string | system mode only: the MAC backend that materialized the already-accepted filesystem exposure plan for this run (`apparmor` or `selinux`); absent in user mode. This is an observability fact, not a policy authority; generated internal profile/projection paths are deliberately not audited |
| `principal_name` | string | owning Principal name, derived through the Launcher (present for all Sessions) |
| `launcher_id` | string | owning Launcher ID (present for all Sessions) |
| `launcher_name` | string | owning Launcher name (present for all Sessions) |

No `result` or `duration` field.

Each entry in `mounts` has:

| Field | Type | Description |
|-------|------|-------------|
| `source` | string | caller source spelling: a workspace-relative path or an absolute host path |
| `target` | string | absolute target path inside the container |
| `read_only` | boolean | whether the mount is read-only |
| `resolved_source` | string | canonical policy identity the filesystem authority decided on (present when the exposure was resolved) |
| `access` | string | effective snapshot access of the resolved source: `read_write` or `read_only` |
| `writable_allowed` | boolean | whether the snapshot owner permits writable exposure of the source (explicitly `false` for a source spanning a protected read_only region) |

The mount policy facts of a `read_only_root` refusal are recorded on the
`run.rejected` event with `result=read_only_root`: only the offending
mount's exposure facts (caller source, resolved canonical source, target,
requested mode, access, `writable_allowed=false`). The contents of a
protected subtree and the specific nested blocker path are never listed.

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
| `helper_socket` | boolean | true when the helper runtime projection was active for this run |
| `workload_mac_backend` | string | system mode only: the MAC backend that materialized the already-accepted filesystem exposure plan for this run (`apparmor` or `selinux`); absent in user mode. This is an observability fact, not a policy authority; generated internal profile/projection paths are deliberately not audited |
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

Emitted before a Docker pull begins.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `image` | string | image reference |
| `principal_name` | string | owning Principal name, derived through the Launcher (present for all Sessions) |
| `launcher_id` | string | owning Launcher ID (present for all Sessions) |
| `launcher_name` | string | owning Launcher name (present for all Sessions) |

No `result` or `duration` field.

#### pull.finish

Emitted after a Docker pull completes (success or failure).

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `image` | string | image reference |
| `principal_name` | string | owning Principal name, derived through the Launcher (present for all Sessions) |
| `launcher_id` | string | owning Launcher ID (present for all Sessions) |
| `launcher_name` | string | owning Launcher name (present for all Sessions) |
| `result` | string | `success` or `pull_error` |
| `exit_code` | number | present when an exit code is available |
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
| `self.parse_failed` | header parse failure on `GET /self` |
| `self.unauthorized` | credential authentication failure on `GET /self` |
| `self.database_error` | credential or Session lookup database failure on `GET /self` (HTTP 500, never a 401) |

Credential authentication on Session-control endpoints (create, list,
show, delete) is discriminated per failure mode:

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
from the Docker CLI process and may contain Docker pull/build status
output, container stdout/stderr, and build process output. That stream is
not part of the daemon audit or operational logs.

Examples (ownership provenance fields reflect the documented schema):

Successful build:

```json
{"time":"2026-01-15T10:30:00Z","stream":"audit","event":"build.start","request_id":"req_abcdef1234567890abcdef1234567890","session_id":"dhs_0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d","operation_id":"op_abcdef1234567890abcdef1234567890","image":"myapp:v1","context":".","dockerfile":"Dockerfile","build_context_resolved":"/home/alice/project","build_context_access":"read_only","build_dockerfile_resolved":"/home/alice/project/Dockerfile","build_dockerfile_access":"read_only","principal_name":"alice","launcher_id":"dhl_0f1e2d3c4b5a69788796a5b4c3d2e1f0","launcher_name":"default"}
{"time":"2026-01-15T10:30:05Z","stream":"audit","event":"build.finish","session_id":"dhs_0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d","operation_id":"op_abcdef1234567890abcdef1234567890","image":"myapp:v1","context":".","dockerfile":"Dockerfile","principal_name":"alice","launcher_id":"dhl_0f1e2d3c4b5a69788796a5b4c3d2e1f0","launcher_name":"default","result":"succeeded","duration":"5s"}
```

Successful session creation:

```json
{"time":"2026-01-15T10:29:55Z","stream":"audit","event":"session.create","session_id":"dhs_0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d","workspace":"/home/alice/project","launcher_id":"dhl_0f1e2d3c4b5a69788796a5b4c3d2e1f0","launcher_name":"default","principal_name":"alice","credential_id":"dhcr_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d","result":"success","duration":"1ms"}
```

Authorization failure:

```json
{"time":"2026-01-15T10:31:00Z","stream":"audit","event":"auth.failure","method":"POST","path":"/run","result":"session.not_found"}
```

Container run:

```json
{"time":"2026-01-15T10:32:00Z","stream":"audit","event":"run.start","request_id":"req_abcdef1234567890abcdef1234567890","session_id":"dhs_0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d","operation_id":"op_abcdef1234567890abcdef1234567890","image":"alpine:3.19","command_arg_count":3,"mounts":[{"source":".","target":"/workspace","read_only":true,"resolved_source":"/home/alice/project","access":"read_only","writable_allowed":false}],"env_keys":["APP_MODE"],"principal_name":"alice","launcher_id":"dhl_0f1e2d3c4b5a69788796a5b4c3d2e1f0","launcher_name":"default"}
{"time":"2026-01-15T10:32:01Z","stream":"audit","event":"run.finish","session_id":"dhs_0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d","operation_id":"op_abcdef1234567890abcdef1234567890","image":"alpine:3.19","command_arg_count":3,"mounts":[{"source":".","target":"/workspace","read_only":true,"resolved_source":"/home/alice/project","access":"read_only","writable_allowed":false}],"env_keys":["APP_MODE"],"principal_name":"alice","launcher_id":"dhl_0f1e2d3c4b5a69788796a5b4c3d2e1f0","launcher_name":"default","result":"succeeded","duration":"1s"}
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

Path authorization follows the canonical order: structural request
validation, lexical capability admission of the raw caller spelling
against its issued capability, privileged filesystem resolution
(`filepath.Abs`/`filepath.EvalSymlinks`) of an admitted spelling, then
the canonical containment/policy proof. The `pathWithin` function uses
`filepath.Rel`, which operates on canonical paths.

For operations that pass paths to Docker, additional measures close the
TOCTOU gap: builds use an isolated staging copy with FD-relative
`openat2` traversal; system-mode run mounts use inode-pinned
helper-owned mounts via `open_tree` + `move_mount`.

### Symlink escape

An admitted spelling is resolved through `EvalSymlinks`. If a symlink
inside the lexical capability resolves outside it, the resolved path
fails the canonical containment proof — the second, mandatory security
proof; a spelling outside the capability never reaches the resolver.

Note: `EvalSymlinks` alone does not prevent TOCTOU attacks where the
filesystem changes between validation and use. The specific operation
mitigations (staging, inode pinning) address this gap.

### SELinux relabel race

The recursive workspace relabel delegates the tree walk to the upstream
descriptor-safe libselinux restorecon implementation (see
[Mandatory access control](#mandatory-access-control)): a hostile
pathname replacement DURING the walk cannot redirect a relabel to a
foreign inode, because the safe implementation labels through
`/proc/self/fd` paths over pinned descriptors. That pathname-TOCTOU
invariant is separate from mount-point safety
(`checkTreeRelabelBoundary`), and both are enforced before the relabel
runs; without a proven descriptor-safe implementation or real procfs the
relabel fails closed.

### Cross-workspace access

Each session is bound to one workspace and one issued immutable filesystem
snapshot. Build context is validated against the workspace; mount sources
are authorized through the issued snapshot (a workspace-relative source
stays workspace-scoped; an absolute source must carry issued snapshot
authority). A source outside the issued snapshot is rejected even when an
allowed root would authorize it, so an agent cannot access another
session's workspace or an unissued region of a shared tree.

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
- the server-owned workload privilege floor — the run argv owner emits
  `--cap-drop ALL` and `--security-opt no-new-privileges:true` for every
  workload in every mode, before any backend option, and no request field
  can disable or weaken them. Linux no-new-privileges and the dropped
  capability set keep an image-delivered or build-staging-delivered
  SUID/SGID executable at the workload's own execution identity, so the
  strongest privilege a hostile workload can reach is its server-owned
  `--user` identity with no container capabilities;
- user mode and AppArmor system mode pass `--security-opt label=disable`
  (SELinux labeling disabled; this does not disable AppArmor — an AppArmor
  system-mode run workload is additionally confined by the generated
  per-workload AppArmor profile, see
  [System-mode run mounts](#system-mode-run-mounts));
- SELinux system mode uses
  `--security-opt label=type:docker_helper_container_t` and keeps MCS
  confinement;
- `--user <uid>:<gid>` — run as the session owner principal's UID and GID,
  or daemon UID:GID for daemon-owner (user-mode) sessions; the execution
  identity is server-owned and authoritative — the image `USER`/ENTRYPOINT
  never substitutes for it and cannot weaken the privilege floor.

The workload MAC backends stay additional independent confinement layers;
they never compute or relax the privilege floor. The hostile
AppArmor/SELinux workload UAT proves the composition: helper-private
runtime state stays unreadable and immutable from the strongest reachable
workload privilege (see
[Helper socket projection](#helper-socket-projection) for the runtime
projection boundary).

### Build staging privilege bits

The staging owner writes only into helper-owned staging under the runtime
directory. Every staged regular file is created by copying content and then
preserving the source's ordinary permission bits while stripping the SUID
and SGID privilege bits at the single staging copy point: the staged copy is
helper-owned (root-owned in system mode), so transferring a source privilege
bit would deliver a privilege-granting setuid/setgid binary through Docker's
build context. The source file itself is never modified, staged hardlink
entries share the first staged copy's inode and inherit the same stripped
mode, and Docker receives only the staged paths as before.

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
- network management (creating or configuring Docker networks; workload
  containers and builds use the Docker/BuildKit default networking — the
  builder's own execution/network position is the accepted Release 2.2
  build boundary, owned architecturally by the Release 2.4 build sandbox
  design);
- volume management beyond bind mounts.

Project purpose, product boundary, and long-lived design principles are
owned by `docs/manifesto.md`; planned work and release scope are owned by
`docs/roadmap.md`.
