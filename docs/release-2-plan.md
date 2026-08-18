# Release 2 implementation plan

## Goal

Release 2 adds a normally installable multi-user system deployment with remote
access while preserving the existing per-user deployment.

The same `docker-helper` binary supports two deployment profiles:

- **user mode** — Release 1 style: daemon runs as the user, uses XDG paths, and
  listens on that user's Unix socket;
- **system mode** — daemon runs as root, uses system paths, serves multiple
  principals, and exposes both a system Unix socket and HTTP (loopback or
  non-loopback with TLS).

Remote execution is part of Release 2:

- remote sessions do not require a client-side workspace;
- remote build accepts an uploaded or streamed build context;
- remote run is image-based without client-side bind mounts;
- existing session lifecycle (status, logs, cancel) is preserved for remote
  sessions;

Mutable workspace synchronization, helper routing, and control-plane
integration are explicitly deferred.

The HTTP API remains the capability contract. CLI commands are reference clients
of that API and must not bypass the daemon by editing SQLite state directly for
new Release 2 administration features.

## Release branch policy

- `main` contains current development for the next release.
- The latest `release/*` branch is the GitHub default branch and presents the
  README for the current published release.
- Release branches receive release fixes only. The existing `release/**` to
  `main` synchronization keeps those fixes in later development.
- When Release 2 is ready, create `release/2.0` from the final `main`, make it
  the default branch, and tag the release from that state.

Changing the default branch is an operator action and is not part of the code
changes below.

## Phase 0: architecture and repository review — completed

The review was completed before changing Release 2 behavior. Findings were
classified as current correctness issues, Release 2 blockers, or maintenance
preferences. No cleanup was performed merely for style.

## Phase 1: principals — completed

- Principal table with username, uid, gid, home, enabled;
- OS user resolution server-side;
- Principal CRUD via admin token;
- Default allowed root = principal home.

## Phase 2: launcher credentials — completed

- Credential table with token hash, ID, name;
- Credential token format `dhc_` + 32 bytes;
- Credential CRUD via admin token;
- Credential authentication for session creation.

## Phase 3: principal-owned sessions/auth — completed

- `sessions.principal_id` column;
- Principal-owned sessions created via launcher credential;
- Session ownership boundary (principal can list/delete own sessions);
- Session token semantics (credential revoke / principal disable / allowed-root
  removal do not invalidate issued sessions).

## Phase 4: execution identity/audit — completed

- `--user principal.uid:principal.gid` for principal-owned sessions;
- `principal_name` in Docker operation audit events;
- Legacy sessions: `principal_name` omitted.

## Phase 5: deployment modes/paths — completed

- User mode: XDG paths, Unix socket (0600);
- System mode: system paths, Unix socket (0666) + loopback HTTP;
- Default HTTP address `127.0.0.1:52375`;
- `http_address` configurable (restart required).

## Phase 6: dual local listeners — completed

- `serveWithShutdownMulti` for Unix + TCP;
- Atomic listener startup;
- Graceful shutdown closes both listeners.

## Phase 7: operator endpoint selection — completed

- `--system`, `--endpoint`, `--token-file` flags;
- No fallback semantics;
- `reload` command uses operator client.

## Phase 8: system service / packaging — implementation completed, acceptance pending

Implementation completed:
- systemd system service unit;
- system-mode AppArmor integration (mandatory);
- DEB/RPM native packaging;
- package lifecycle scriptlets;
- manpages (docker-helper.1, docker-helper-config.5);
- release workflow publishes tar.gz, DEB, RPM, SHA256SUMS.

Acceptance pending:
- privileged Ubuntu DEB lifecycle (install/upgrade/remove/purge);
- privileged openSUSE RPM lifecycle (install/upgrade/erase);
- coexistence with user-mode installation;
- full Release 2 acceptance matrix.

### Completion criteria

Accepted Release 2 decisions:

### Deployment

- Preserve user mode as a supported deployment profile.
- Add system mode as the normal multi-user packaged deployment.
- The system daemon runs as **root**. This is the simplest model compatible with
  private user workspaces and rootful Docker. A dedicated service account may be
  revisited later if stronger privilege separation is justified.
- Daemon path defaults depend on effective UID:
  - non-root daemon -> user/XDG paths;
  - root daemon -> system paths.
- Existing Release 1 sessions are ephemeral and are not migrated into system
  mode.

### Local transports

- User mode keeps the Release 1 Unix socket.
- System mode exposes two local transports for the same HTTP API and the same
  authorization model:
  - Unix socket, convenient for bind-mounting into sandbox containers;
  - loopback HTTP on `127.0.0.1:52375` by default.
- Port `52375` is configurable. Listener bind failure is fatal; the daemon must
  not silently select another port.
- Unix and loopback transports do not imply identity or authorization. They are
  only transports.
- CLI endpoint selection must be deterministic. Non-root defaults resolve to
  user-mode paths; root defaults resolve to system-mode paths. Explicit system
  or endpoint selection must be available instead of silently falling back to a
  different daemon.

### Principal and credential model

- Multi-user system mode introduces explicit **principals**.
- A system administrator provisions principals through the daemon API using the
  administrative credential; the CLI is only a client of that API.
- A principal is created from an existing OS user. The daemon resolves the OS
  username to UID, GID, and home directory server-side.
- UID, GID, and filesystem policy are never trusted from launcher/client claims.
- Each principal has `allowed_roots`, represented as an array. The default is the
  principal user's home directory.
- Administrative CLI UX should follow the same memorable pattern as config
  management, including `show` and `set`, with addressable add/remove operations
  for `allowed_roots` so the whole array does not need to be rewritten.
- A principal may have multiple opaque launcher credentials. Credentials are
  separate revocable entities, stored only as hashes, and the secret value is
  returned only at creation.
- Launcher credentials identify a principal. The daemon obtains UID/GID and
  `allowed_roots` from its own principal state; the launcher sends only its
  credential and requested workspace.
- Session tokens remain narrow workspace-scoped capabilities and inherit owner
  principal identity.

### Policy-change semantics

- Removing an `allowed_root` prevents creation of new sessions using that root.
- Existing sessions are not dynamically re-evaluated against later principal
  root-policy changes. They remain valid until normal expiry or deletion.
- Immediate revocation/re-evaluation of existing sessions after principal policy
  changes is deferred unless a real need appears.
- Deleting or expiring a session prevents subsequent authenticated requests with
  that session token but does not terminate Docker operations that were already
  started.

### Runtime identity

- In system mode, container UID/GID must come from the authenticated principal,
  not from the daemon process UID/GID and not from request fields.
- Filesystem authorization must be checked against the session workspace and the
  principal's server-side `allowed_roots` when the session is created.

### Administration and audit

- New principal/credential administration is exposed through HTTP API routes;
  the CLI must not modify the system database directly.
- Root/sudo is the initial administrative boundary for provisioning and policy
  changes. Do not add a separate administrative control plane in Release 2.
- Multi-user audit records must carry principal identity in addition to session,
  request, and operation identifiers.

The sections below are the detailed implementation breakdown for each workstream.
The top-level Phase 0–8 progress sequence above is the authoritative roadmap.

## Workstream 1: principal persistence and administrative API

Introduce the multi-user identity objects without changing existing session
behavior yet.

### Principal model

- Add persistent principal state with at least:
  - stable identity/name;
  - OS username;
  - UID;
  - GID;
  - enabled state;
  - `allowed_roots` array.
- Resolve OS user identity on the daemon side during principal creation.
- Default `allowed_roots` to the user's home directory.
- Store roots in normalized/canonical form appropriate for later workspace
  containment checks.
- Adding Release 2 tables to an existing Release 1 SQLite database must be safe;
  do not introduce a generic migration framework without a concrete schema need.

### Administrative API and CLI

- Add admin-authenticated principal routes and matching CLI commands.
- Preserve the existing project rule: HTTP API is authoritative, CLI is a
  reference client.
- CLI UX should include:

      docker-helper principal create USER
      docker-helper principal show USER [FIELD]
      docker-helper principal set USER FIELD VALUE
      docker-helper principal allowed-root add USER PATH
      docker-helper principal allowed-root remove USER PATH

- Prefer the external term `allowed-root` / JSON field `allowed_roots`; avoid the
  overloaded bare term `root`.
- `show`/`set` should follow the existing config-command shape where practical so
  operators do not need to remember unrelated command conventions.

### Completion criteria

- Existing Release 1 user-mode behavior is unchanged.
- Principal creation resolves UID/GID/home server-side.
- A client cannot supply or override UID/GID.
- Default root is the resolved home directory.
- Principal show/set and allowed-root add/remove operate only through the daemon
  API.
- Unit tests cover unknown users, duplicate principals, root normalization,
  authorization failures, and CLI/API round trips.

## Workstream 2: launcher credentials

Add multiple revocable credentials per principal.

- Add a credential table related to principals.
- Generate opaque high-entropy credentials; store only cryptographic hashes.
- Return the secret only once at creation.
- Support multiple named credentials per principal so separate launchers/agents
  can be revoked independently.
- Add admin-authenticated API + CLI operations to create, list, and revoke/delete
  credentials.
- Never expose credential secrets in list/show output, logs, audit, URLs, or
  database plaintext.

### Completion criteria

- Two credentials for the same principal authenticate as the same principal but
  can be revoked independently.
- Revocation of one credential does not affect another credential or an already
  issued session token.
- Audit identifies both the principal and, where useful, the credential ID/name
  without exposing its secret.

## Workstream 3: principal-owned sessions and authorization

Replace the system-mode launcher dependency on the global admin token with
principal credentials for ordinary session lifecycle.

- Principal credentials may create sessions only for their own principal.
- Session creation request contains a workspace, not UID/GID or roots.
- The daemon validates the requested workspace against the principal's current
  `allowed_roots` and stores the owning principal with the session.
- Principals may list/delete their own sessions; administrative credentials may
  retain broader management rights.
- Session-authenticated operation endpoints keep the existing session ownership
  boundary.
- Existing sessions are not re-evaluated if principal roots later change.
- Session deletion/expiry does not terminate already-started operations.

### Completion criteria

- A principal cannot create a session in another principal's allowed root unless
  that root was explicitly granted to it too.
- A forged client UID/GID/root claim has no effect because those fields are not
  accepted as authority.
- One principal cannot list/delete another principal's sessions with its
  launcher credential.
- Existing async operation semantics remain unchanged.

## Workstream 4: deployment profiles, system paths, and runtime UID/GID

Introduce the root system-daemon profile while preserving Release 1 user mode.

### User mode

Preserve current behavior:

- daemon runs as the user;
- XDG config/state/runtime paths;
- per-user Unix socket;
- existing single-owner config/session workflows remain supported.

### System mode

Use conventional Linux/systemd paths, with final concrete filenames documented
before packaging. Expected layout:

- configuration under `/etc/docker-helper`;
- persistent state under `/var/lib/docker-helper`;
- runtime socket/lock/session runtime data under `/run/docker-helper`.

System mode:

- runs as root;
- uses principal UID/GID for Docker `--user` instead of daemon UID/GID;
- uses principal-aware workspace authorization;
- keeps service-owned runtime state isolated between sessions/principals.

### Completion criteria

- Existing non-root user mode continues to pass its regression suite.
- Root/system defaults do not reuse a caller's XDG state accidentally.
- Containers started for principal A run with principal A's configured UID/GID.
- Private user workspaces work without requiring ACL changes for a dedicated
  helper service account.

## Workstream 5: dual local listener lifecycle and client discovery

Generalize the listener lifecycle only as far as required for the accepted two
local transports.

- Keep the Unix listener.
- Add loopback HTTP at configurable `127.0.0.1:52375` in system mode.
- Both listeners serve the same handler/API/authentication model.
- Startup is atomic enough that partial listener failure closes listeners that
  were already opened and releases/removes owned runtime artifacts.
- Shutdown, HTTP drain, operation termination, and process lock continue to use
  one bounded daemon lifecycle.
- Preserve a deterministic CLI endpoint selection model; never silently switch
  between user and system daemons after a failed connection.
- Keep explicit endpoint selection available for host users and integrations.

### Unix socket access

For the first system-mode implementation, the socket may be connectable by all
local users because authentication/authorization is credential-based. A
`docker-helper` group may later be added as an additional coarse access layer if
operational experience justifies it.

### Completion criteria

- User-mode Unix behavior is unchanged.
- System mode serves the same authenticated API over both system Unix socket and
  loopback HTTP.
- A sandbox container can use the bind-mounted Unix socket without host-network
  mode.
- A host client can use either system local transport.
- Listener startup/failure/shutdown tests cover both listeners together.

## Workstream 6: systemd system service and hardening

- Add a system service unit for root system mode.
- Keep the existing user unit for user mode.
- Apply systemd hardening compatible with Docker access, user-workspace access,
  runtime files, and the two local listeners.
- Document the security consequence of rootful Docker access explicitly.
- Ensure audit records include principal identity for multi-user operations.

### Completion criteria

- User and system services have separate paths/state and can be intentionally
  installed on the same host without accidental cross-use.
- System service restart/stop obeys the existing bounded shutdown contract.
- Effective permissions for config, credentials, database, sockets, and runtime
  directories are documented and tested.

## Workstream 7: native distribution and manuals

- Build native DEB and RPM packages.
- Keep openSUSE and Ubuntu as important targets; select the exact RHEL-family
  target before final package acceptance. Fedora is not currently committed.
- Standalone native DEB/RPM artifacts are the Release 2 deliverable.
  Package repositories and update channels are deferred until after package
  format/lifecycle acceptance or a later distribution slice.
- Native packages are system-mode packages. User mode remains supported via
  tarball and user installer.
- Provide at least:
  - `docker-helper(1)`;
  - `docker-helper-config(5)`.
- Add package/service upgrade tests, including an existing Release 1 user-mode
  installation on the same machine.

Release 1 sessions are not migrated to the Release 2 system service. User-mode
state remains user-mode state.

## Workstream 8: Release 2 acceptance

Run the complete regression and system acceptance pass:

- gofmt;
- go test ./...;
- go test -race ./...;
- go vet ./...;
- git diff --check;
- existing user-mode install/start/session/pull/build/run/registry workflows;
- system package install/upgrade/remove;
- principal create/show/set and allowed-root add/remove;
- multiple credentials per principal and independent revocation;
- cross-principal authorization negative tests;
- system Unix socket and `127.0.0.1:52375` HTTP;
- container UID/GID ownership behavior;
- audit attribution by principal;
- bounded restart/shutdown with active operations;
- coexistence of user and system deployment profiles.

Reconcile README, architecture, roadmap, agent skill, package documentation, and
manual pages with the implemented behavior before creating `release/2.0`.

## Explicitly deferred beyond Release 2

- mutable remote workspace delivery and synchronization;
- remote runs coupled to a synchronized mutable workspace;
- multiple helper contexts, target routing, or helper-to-helper forwarding;
- host port publishing and generic Docker network configuration;
- durable operation recovery across daemon restarts;
- immediate re-evaluation or termination of already-issued sessions when a
  principal's `allowed_roots` changes;
- termination of already-started Docker operations merely because their session
  is later deleted or expires;
- dedicated unprivileged service-account architecture unless practical security
  benefit justifies the added filesystem/privilege complexity;
- mandatory `docker-helper` Unix group as an authorization mechanism;
- a separate administrative control plane.
