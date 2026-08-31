# Release 2 implementation plan

## Goal

Release 2 adds a normally installable local multi-user system deployment while
preserving the existing per-user deployment.

The same `docker-helper` binary supports two deployment profiles:

- **user mode** — Release 1 style: daemon runs as the user, uses XDG paths, and
  listens on that user's Unix socket;
- **system mode** — daemon runs as root, uses system paths, serves multiple
  principals, and exposes both a system Unix socket and loopback HTTP.

Remote execution, non-loopback listeners, TLS, workspace synchronization,
helper routing, and control-plane integration are explicitly deferred.

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

## Phase 2: Principal credentials — completed

- Credential table with token hash, ID, name;
- Credential token format `dhc_` + 32 bytes;
- Credential CRUD via admin token;
- Credential authentication for session creation;
- `credential create --name` is optional and defaults to `default`;
- `credential install` atomically stores a non-root user's Principal credential token.

## Phase 3: principal-owned sessions/auth — completed

- `sessions.principal_id` column;
- Principal-owned sessions created via Principal credential;
- Session ownership boundary (principal can list/delete own sessions);
- Session token semantics: credential revocation and allowed-root removal do not
  invalidate issued sessions; disabling a principal deletes its active sessions
  and blocks future authentication.

## Phase 4: execution identity/audit — completed

- `--user principal.uid:principal.gid` for principal-owned sessions;
- `principal_name` in Docker operation audit events;
- Legacy sessions: `principal_name` omitted.

## Phase 5: deployment modes/paths — completed

- User mode: XDG paths, Unix socket (0600);
- System mode: system paths, Unix socket (0666) + loopback HTTP;
- Default HTTP address `127.0.0.1:52375`;
- `http_address` configurable (restart required);
- interactive non-root init defaults to the user's home;
- interactive root init defaults to `/home`, and root validation permits exact
  `/home` and `/opt`.

## Phase 6: dual local listeners — completed

- `serveWithShutdownMulti` for Unix + TCP;
- Atomic listener startup;
- Graceful shutdown closes both listeners.

## Phase 7: operator endpoint selection and onboarding — completed

- `--system`, `--endpoint`, `--token-file` flags;
- automatic default selection of the existing user socket, otherwise the system
  socket, with the matching token source;
- no retry to another daemon after an endpoint has been selected;
- non-root init detects an existing system daemon and enters Principal-credential
  onboarding instead of creating a competing user endpoint;
- `reload` command uses operator client.

## Phase 8: system service / packaging — completed

Implementation completed:
- systemd system service unit;
- mandatory system-mode AppArmor or enforcing SELinux integration;
- DEB/RPM native packaging;
- package lifecycle scriptlets (idempotent MAC cleanup on final erase);
- manpages (docker-helper.1, docker-helper-config.5);
- Bash completion;
- release workflow publishes tar.gz, DEB, RPM, SHA256SUMS.

Release 2 acceptance (actual UAT ownership):

- DEB lifecycle `install(rc.22) -> upgrade(candidate) -> reinstall -> remove ->
  purge` on the Ubuntu/AppArmor package consumer, exercised against real
  scriptlet semantics (`scripts/uat-release2-acceptance.sh`, scenario F).
- RPM lifecycle `install(rc.22) -> upgrade(candidate) -> reinstall -> final
  erase` under BOTH MAC backends: Tumbleweed RPM/AppArmor and Tumbleweed
  RPM/SELinux (`scripts/uat-package-lifecycle-rpm.sh`).
- The rc.22 baseline package is an immutable test fixture with a pinned,
  independently-verified SHA-256 (`scripts/uat-rc22-fixture.sh`); only the
  needed DEB/RPM is downloaded and its bytes are verified before install.
- User/system coexistence, loopback HTTP (`127.0.0.1:52375`), principal
  credential/audit/registry acceptance, and bounded restart/shutdown with
  active operations on the Ubuntu/AppArmor consumer
  (`scripts/uat-release2-acceptance.sh`, scenarios A-E).
- All acceptance scenarios are fail-closed: PASS may continue, FAIL fails the
  gate, BLOCKED (a required scenario not exercised) fails the gate.

### SELinux backend

The backend-neutral detector, fail-closed confinement check, systemd context,
policy module, RPM lifecycle integration, and custom MCS-constrained container
domain are implemented. OpenSUSE enforcing UAT has driven the current
permission set. The accepted distribution contract for Release 2 is Ubuntu
(DEB) + openSUSE (RPM); Fedora/RHEL-family acceptance and cross-distribution
module/package lifecycle are explicitly NOT Release 2 gates (no RHEL-family
target is committed). The SELinux `/opt` workspace contract (an operator-owned
fcontext boundary is required; docker-helper never creates a helper-owned
boundary under `/opt`) is implemented and covered by unit tests
(`mac_lifecycle_test.go`). See
[docs/selinux-support-plan.md](selinux-support-plan.md).

SELinux confines the daemon and container domains but does not provide
per-path allowed-root isolation. The canonical docker-helper path check remains
the authoritative path boundary.

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
- CLI endpoint selection must be deterministic. With no explicit override, the
  operator client selects the user socket when it exists and otherwise the
  system socket, together with the corresponding token. Explicit system,
  endpoint, and token-file selection remains available. The client never
  retries a different daemon after selection.

### Principal and credential model

- Multi-user system mode introduces explicit **principals**.
- A system administrator provisions principals through the daemon API using the
  admin token; the CLI is only a client of that API.
- A principal is created from an existing OS user. The daemon resolves the OS
  username to UID, GID, and home directory server-side.
- UID, GID, and filesystem policy are never trusted from launcher/client claims.
- Each principal has `allowed_roots`, represented as an array. The default is the
  principal user's home directory.
- Administrative CLI UX should follow the same memorable pattern as config
  management, including `show` and `set`, with addressable add/remove operations
  for `allowed_roots` so the whole array does not need to be rewritten.
- A principal may have multiple opaque Principal credentials. Credentials are
  separate revocable entities, stored only as hashes, and the secret value is
  returned only at creation.
- The CLI supplies the stable credential name `default` when `--name` is
  omitted; the HTTP request continues to carry an explicit name.
- A non-root user can install one returned Principal credential token in the standard
  user-scoped credential file. Default endpoint selection then chooses the
  matching credential automatically; explicit endpoint and token overrides
  remain authoritative.
- Principal credentials identify a principal. The daemon obtains UID/GID and
  `allowed_roots` from its own principal state; the launcher sends only its
  credential and requested workspace.
- Session tokens remain narrow workspace-scoped capabilities and inherit owner
  principal identity.

### Policy-change semantics

- Removing an `allowed_root` prevents creation of new sessions using that root.
- Existing sessions are not dynamically re-evaluated after allowed-root removal
  or Principal-credential revocation. They remain valid until normal expiry,
  explicit deletion, principal disable, or principal deletion.
- Disabling a principal transactionally deletes its sessions; re-enabling the
  principal does not revive their tokens.
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

## Workstream 2: Principal credentials

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
- Principals may list/delete their own sessions; the admin token may
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
  Principal credential.
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
- Preserve deterministic default selection: use the existing user socket,
  otherwise the system socket, and never switch daemons after a failed request.
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
- Accepted Release 2 distribution contract: Ubuntu (DEB, AppArmor) and openSUSE
  (RPM, AppArmor and SELinux). No RHEL-family target is selected or committed;
  Fedora/RHEL-family package/lifecycle acceptance is deferred beyond Release 2
  and is not a release gate.
- Standalone native DEB/RPM artifacts are the Release 2 deliverable.
  Package repositories and update channels are deferred until after package
  format/lifecycle acceptance or a later distribution slice.
- Native packages contain both user- and system-mode assets. The tarball's
  normal installer provisions user mode; system mode requires the explicit
  `install-system.sh` path.
- Provide at least:
  - `docker-helper(1)`;
  - `docker-helper-config(5)`.
- Add Bash completion for commands, subcommands, and flags, and ship it with
  native packages and generic release artifacts.
- Trusted CA injection is configuration-driven through a validated
  `trusted_ca_path` and `trusted_ca_injection=auto`. The confined source
  contract is resolved: `trusted_ca_path` may reference a regular file
  anywhere on the host, CA preflight propagates validation errors before
  configuration is persisted, and the black-box UAT covers the full
  control + positive trusted-CA E2E.
- Add package/service upgrade tests, including an existing Release 1 user-mode
  installation on the same machine.

Release 1 sessions are not migrated to the Release 2 system service. User-mode
state remains user-mode state.

## Workstream 8: Release 2 acceptance

The Release 2 acceptance contract is closed by the artifact-gate UAT jobs,
which consume the exact candidate produced by the gate producer. Every
mandatory scenario is fail-closed (PASS -> continue, FAIL -> gate fails,
BLOCKED / not exercised -> gate fails). The v2.0.0-rc.22 package is the
immutable upgrade-baseline test fixture (pinned, independently-verified
SHA-256; bytes verified before install; no private "previous release" is
built; mutable release metadata is never trusted at runtime).

Local validation at final HEAD:
- gofmt -l . (must be empty);
- go test ./...;
- go test -race ./...;
- go vet ./...;
- git diff --check;
- scripts/check-selinux-policy.sh;
- bash scripts/test-release-pipeline.sh.

Installed-system acceptance (Ubuntu DEB/AppArmor consumer,
`scripts/uat-release2-acceptance.sh`):
- DEB native lifecycle install(rc.22) -> upgrade(candidate) -> reinstall ->
  remove -> purge, exercising real scriptlet semantics (version, daemon
  health, config/state persistence, package-owned MAC artifacts, conffile
  cleanup on purge);
- loopback HTTP on `127.0.0.1:52375` (health, authenticated operator op,
  principal session flow, session-authenticated operation, same authorization
  result as the Unix transport; `--endpoint http://127.0.0.1:52375`);
- multiple credentials per principal and independent revocation;
- principal_name in real operation audit (structured audit stream, no secret
  leakage);
- registry login end-to-end with session isolation (self-contained local
  authenticated registry; Docker daemon config is harness-owned and restored);
- bounded restart/shutdown with active operations (no resume, no helper
  subprocess/mount-pin/runtime leak, fresh operation afterwards);
- coexistence of user and system deployment profiles (user-mode daemon started
  before system mode, distinct paths/sockets/state, default endpoint selects
  the user socket, explicit --system selects the system daemon, no cross
  consumption of tokens/state).

Installed-system acceptance (Tumbleweed RPM consumers,
`scripts/uat-package-lifecycle-rpm.sh`):
- RPM native lifecycle install(rc.22) -> upgrade(candidate) -> reinstall ->
  final erase under BOTH AppArmor and SELinux (the exact-candidate black-box
  consumers each run their own lifecycle stage);
- package-owned MAC artifacts correct at each step; no stale active profile /
  SELinux module after erase; idempotent MAC cleanup (no cross-MAC uninstall
  warnings).

Ordinary black-box, SELinux regressions, and tarball/AppArmor + tarball/SELinux
stages keep their existing ownership in the artifact gate.

The pre-UAT blockers recorded in
[`docs/release-2-audit-2026-08-21/`](release-2-audit-2026-08-21/) are resolved:
credential bootstrap, CA preflight error propagation, the SELinux `/opt`
contract, release job policy-build dependencies, the RPM target/dependency
decision, and the confined trusted-CA source contract. Synchronous Docker
subprocess output is bounded, and the logging/audit-schema findings are
settled.

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
