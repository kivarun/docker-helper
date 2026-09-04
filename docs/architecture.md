# Architecture

## Goal

docker-helper is a small policy-enforcing daemon that provides a restricted
interface to Docker.

A coding agent runs on the same machine as the developer and needs to build
images and run containers. Giving the agent direct access to `docker.sock`
means it can read any file on the host, access any network, and run arbitrary
processes. docker-helper sits between the agent and Docker and enforces
policy:

- filesystem access is restricted to an explicit workspace per session;
- every operation requires a session token;
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
      ├─── admin token (full admin)
      ├─── Principal credential (principal-scoped)
      └─── session token (Docker operations)
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

The daemon HTTP API is the single capability contract. The CLI is a
shipped reference/convenience client of that API. Curl and native adapters
are direct clients of the same API.

The presence of the `docker-helper` binary in the agent image is not a
requirement. Choosing a client interface does not change daemon policy
or security semantics.

## Deployment modes

docker-helper supports two deployment modes:

### User mode

- **Effective UID**: non-root
- **Config**: `${XDG_CONFIG_HOME:-$HOME/.config}/docker-helper/config.json`
- **State**: `${XDG_STATE_HOME:-$HOME/.local/state}/docker-helper`
- **Runtime**: `$XDG_RUNTIME_DIR/docker-helper`
- **Transport**: Unix socket only (0600)
- **Execution identity**: daemon UID:GID for legacy/user sessions

### System mode

- **Effective UID**: root
- **Config**: `/etc/docker-helper/config.json`
- **State**: `/var/lib/docker-helper`
- **Runtime**: `/run/docker-helper`
- **Transports**: Unix socket (0666) + loopback HTTP
- **Default HTTP address**: `127.0.0.1:52375` (configurable via `http_address`)
- **Execution identity**: principal UID:GID for principal-owned sessions

The `http_address` field is configurable in system mode but requires a
daemon restart to take effect.

### Mandatory access control in system mode

System mode requires exactly one supported enforcing backend:

- AppArmor confines the daemon with `docker-helper-system` and uses explicit
  managed roots for path-level workspace defense in depth;
- SELinux confines the daemon as `docker_helper_t` and system-mode containers
  as the MCS-constrained `docker_helper_container_t` type.

Neither backend, both backends, and permissive SELinux fail closed. SELinux
workspace access is type-based and does not reproduce AppArmor's per-path
managed-root boundary; canonical application-level allowed-root validation
remains authoritative in both modes.

## Transports

- **User mode**: Unix socket only
- **System mode**: Unix socket + loopback HTTP (`127.0.0.1:<port>`)

One handler/API/auth policy on both transports. Transport does not
determine identity or authorization.

Release 2 transports are local only. Non-loopback listeners, TLS, and remote
execution are deferred to Release 4 or later and remain use-case driven.

The launcher creates a session and passes the client token to the agent.
It is not a mandatory daemon or control plane component.

docker-helper listens on transports determined by deployment mode:

- **User mode**: Unix socket at
  `$XDG_RUNTIME_DIR/docker-helper/docker-helper.sock` with `0600` permissions.
- **System mode**: Unix socket at
  `/run/docker-helper/docker-helper.sock` with `0666` permissions, plus
  loopback HTTP at `127.0.0.1:52375` by default.

## Trust model

### Trusted

- the developer who runs `docker-helper init` and `docker-helper serve`;
- the host filesystem outside `AllowedRoot`;
- the Docker Engine and its configuration;
- the `docker-helper` process itself.

### Partially trusted

- the `AllowedRoot` directory and its contents;
- the workspace selected at session creation time.

### Untrusted

- the coding agent;
- any input from the agent (JSON payloads, paths, image names);
- Dockerfiles inside the workspace;
- container processes.

The agent is untrusted because it may execute arbitrary code, generate
malicious Dockerfiles, or attempt path traversal. docker-helper validates
every agent input before passing it to Docker.

## Session lifecycle

### Admin sessions

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
    ├── runs ownership migration (idempotent; see Launcher ownership)
    └── starts HTTP server on Unix socket
    │
POST /sessions  (admin token)
    │
    ├── resolves the target launcher (explicit selector required in
    │   system mode; local daemon-owner default in user mode)
    ├── validates workspace inside the launcher's effective allowed roots
    ├── generates session ID (dhs_<32 hex chars>)
    ├── generates session token (dht_<64 hex chars>)
    ├── stores SHA-256 hash of token in database
    ├── stores full token in response (one-time)
    └── returns session + token
    │
POST /build or POST /run  (session token)
    │
    ├── computes SHA-256 of provided token
    ├── looks up session by token hash
    ├── checks not expired, not revoked
    ├── validates request against session workspace
    ├── registers operation (tryCreate — atomic with shutdown gate)
    ├── starts async process (cmd.Start under op.mu)
    ├── captures stdout/stderr into bounded LogBuffer
    ├── completion goroutine owns cmd.Wait()
    ├── transitions operation to succeeded/failed
    └── writes audit record (principal_name omitted for daemon-owner sessions)
```

### Principal-owned sessions

```
POST /principals  (admin token)
    │
    ├── resolves OS user (uid, gid, home)
    ├── creates principal record
    └── sets default allowed root = home
    │
POST /principals/{username}/credentials  (admin token)
    │
    ├── generates credential ID (dhcr_<32 hex chars>)
    ├── generates credential token (dhc_<64 hex chars>)
    ├── stores SHA-256 hash in database
    └── returns credential + token (one-time)
    │
DELETE /principals/{username}  (admin token)
    │
    ├── collects session IDs for runtime cleanup
    ├── fails with 409 launcher_runtime_active if a launcher
    │   still has active runtime, else deletes sessions and launchers
    ├── deletes principal (credentials/roots/launchers via FK CASCADE)
    ├── commits transaction
    └── best-effort cleanup of session runtime directories
    │
POST /sessions  (Principal credential)
    │
    ├── validates credential
    ├── resolves principal -> default or explicit launcher
    ├── validates workspace inside global ∩ principal ∩ launcher allowed roots
    ├── generates session ID + token
    ├── stores session with launcher_id
    └── returns session + token
    │
POST /build or POST /run  (session token)
    │
    ├── resolves launcher -> principal through the ownership JOIN
    ├── execution identity = principal.uid:principal.gid
    └── audit record contains principal_name and launcher provenance
```

### Principal lifecycle

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
    ├── principal-owned sessions of disabled principal are rejected
    └── disabled launchers' credentials are rejected at authentication time
```

### Shared session capability lifecycle

```
POST /build or POST /run  (session token)
    │
    ├── resolves session (launcher-owned)
    ├── execution identity = principal UID:GID or daemon UID:GID
    ├── registers operation (tryCreate — atomic with shutdown gate)
    ├── starts async process (cmd.Start under op.mu)
    ├── captures stdout/stderr into bounded LogBuffer
    ├── completion goroutine owns cmd.Wait()
    ├── transitions operation to succeeded/failed
    └── writes audit record
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
DELETE /sessions/{id}  (admin token or Principal credential)
    │
    └── physically deletes session row
    │
subsequent requests with deleted session token
    │
    └── 401 Unauthorized
```

Session token semantics:
- revoking a Principal or Launcher credential does not invalidate issued
  sessions; deleting a Launcher credential leaves its launcher's sessions
  owned and running but removes that authentication key;
- disabling the principal or its launcher deletes the affected sessions and
  blocks their tokens; disabled launchers also reject credential
  authentication;
- removing an allowed root does not invalidate issued sessions;
- session expiry or deletion blocks future requests;
- an already-started Docker operation continues its lifecycle.

A Principal credential stays with the launcher (the human operator or
provisioning tool that starts the agent); the coding agent never receives
it. For delegated agents, the launcher issues a Launcher credential and
gives that to the agent instead. The agent only gets a credential (which
creates sessions) or a session token (which grants access to a single
workspace and expires after the configured TTL). This separation ensures
the agent cannot create sessions for other workspaces, reach other
launchers' sessions, or manage sessions it does not own.

Expired sessions are rejected immediately by the `expires_at` check in
`findSessionByToken`. Their database rows are physically removed the next
time `docker-helper serve` starts.

## Session CLI

docker-helper provides a CLI for session management.

### docker-helper session create

Create a new session. Requires admin token, Principal credential, or
Launcher credential.

```
docker-helper session create [--system] [--endpoint ENDPOINT] [--token-file PATH] --workspace PATH [--json]
```

Flags:

| Flag | Description |
|------|-------------|
| `--workspace PATH` | Workspace directory (required) |
| `--json` | Output in JSON format |

Returns the session ID, token, workspace, creation time, and expiration
time. The token is shown only once and cannot be retrieved later.

The HTTP API additionally accepts explicit ownership selectors in the
request body (`launcher_id` or `principal`, mutually exclusive; see
Session selectors above). The CLI relies on default resolution: a
Principal credential resolves its principal's default launcher, a
Launcher credential is forced to its own launcher, and a user-mode admin
token resolves the local daemon-owner default. A system-mode admin token
requires an explicit selector (`400 missing_launcher_selector`), so
system-mode admin session creation goes through the HTTP API.

### docker-helper session list

List active sessions. Requires admin token, Principal credential, or
Launcher credential.

```
docker-helper session list [--system] [--endpoint ENDPOINT] [--token-file PATH] [--json]
```

Flags:

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format |

Returns a table of active sessions with ID, workspace, launcher, creation
time, and expiration time.

With admin token: lists all sessions.
With Principal credential: lists only sessions for the credential's principal.
With Launcher credential: lists only sessions owned by the credential's launcher.

### docker-helper session delete

Delete a session. Requires admin token, Principal credential, or Launcher
credential.

```
docker-helper session delete [--system] [--endpoint ENDPOINT] [--token-file PATH] --id SESSION_ID [--json]
```

Flags:

| Flag | Description |
|------|-------------|
| `--id SESSION_ID` | Session ID to delete (required) |
| `--json` | Output in JSON format |

Permanently removes the session. Subsequent requests with the session's
token will receive 401 Unauthorized.

With admin token: can delete any session.
With Principal credential: can only delete sessions for its principal.
With Launcher credential: can only delete sessions owned by its launcher;
foreign sessions return the same `not_found` outcome (no existence
disclosure).

### docker-helper session cleanup

Remove expired sessions from the local state database. Does not require
a running daemon or admin token.

```
docker-helper session cleanup
```

Deletes rows whose `expires_at` has passed. Active sessions are
untouched. Reports the number of removed rows.

### Operator flags

API-backed operator commands (principal, credential, session, reload)
support explicit endpoint selection. See `docker-helper <command> --help`
for full syntax:

```
--system              connect to system daemon (Unix socket)
--endpoint ENDPOINT   explicit endpoint (/path, unix:///path, or http://127.0.0.1:port)
--token-file PATH     token file path (auto-resolved for Unix sockets)
```

## CLI reference

### Agent commands

- `pull` — Pull a Docker image.
- `build` — Build a Docker image. Hides async operation lifecycle; streams
  logs; propagates container exit code. SIGINT/SIGTERM cancels the operation
  (exit 130/143). `--context` must be relative to the session workspace.
- `run` — Run a Docker container. Same lifecycle semantics as `build`.
  `--mount` source must be relative to the session workspace; target is an
  absolute container path.
- `registry` — Registry operations. Subcommand: `login`.

### Operator commands

- `serve` — Start the HTTP server.
- `init` — Initialize configuration and admin token.
- `reload` — Reload configuration from disk.
- `session` — Manage sessions. Subcommands: `create`, `list`, `delete`,
  `cleanup`.
- `config` — Inspect and modify configuration. Subcommands: `show`, `set`,
  `unset`.
- `principal` — Manage principals. Subcommands: `create`, `list`, `show`,
  `set`, `delete`, `allowed-root`.
- `launcher` — Manage launchers. Subcommands: `create`, `list`, `show`,
  `set`, `delete`, `scope` (`set`), `credential` (`issue`, `rotate`,
  `delete`). See Launcher ownership above for the full contract.
- `credential` — Manage Principal credentials. Subcommands: `create`, `list`,
  `revoke`, `install`. `credential create --name` is optional and uses the
  literal name `default` when omitted. The same `credential install` command
  stores a Launcher credential token for a delegated agent.
- `admin-token` — Manage the admin token. Subcommand: `rotate` (rotate the
  admin token; requires the current token, new token shown once, old token
  invalid immediately, no restart).
- `apparmor` — Manage/check AppArmor roots for an AppArmor system deployment.
- `selinux` — Inspect SELinux system-policy state for a SELinux system
  deployment. Subcommand: `check` (validate that the `docker_helper` policy
  module is loaded and docker-helper-owned file contexts are consistent with
  the active policy; read-only operator diagnostics that never mutates SELinux
  state and never inspects dynamic Session MAC resources).

### General commands

- `version` — Print version.
- `help` — Show help.
- `completion bash` — Generate Bash completion.

### Signal cancellation (agent commands)

`build` and `run` handle SIGINT and SIGTERM:

- SIGINT -> best-effort cancel + exit 130;
- SIGTERM -> best-effort cancel + exit 143;
- cancel failure prints a diagnostic but does not replace the signal exit
  status.

### `docker-helper config <subcommand>`

Inspect and modify configuration. Requires a subcommand.

Subcommands: `show`, `set`, `unset`, `allowed-root`.

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
change back (see Trusted CA injection).

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

### `docker-helper reload`

Ask the running daemon to re-read `config.json` and apply changes without
restarting. Reloadable fields:
`allowed_roots`, `session_ttl`, `log_level`, `audit_enabled`,
`shutdown_timeout`, `operation_retention_ttl`, `operation_max_completed`,
`operation_log_max_bytes`, `trusted_ca_path`, `trusted_ca_injection`.

Startup-only fields (require daemon restart): `http_address`.

Computed paths (socket, database, state) are not changed. If the daemon is
not running, the command fails with a non-zero exit code. If the new
configuration is invalid, the daemon keeps its current configuration and
the command returns an error.

### `docker-helper session <subcommand>`

Manages sessions. Requires a subcommand.

Subcommands: `create`, `list`, `delete`, `cleanup` (see Session CLI section
above).

### Help flag

The `-h` / `--help` flag is available on every command and session
subcommand. It prints usage information and exits 0 without executing
the command action.

### Exit codes

| Code | Meaning | Examples |
|------|---------|----------|
| 0 | Success or help displayed | `docker-helper version`, `docker-helper serve --help` |
| 1 | Runtime error (config load, API call, server failure) | `docker-helper init` with an unwritable configuration directory, `docker-helper session create` with unreachable server |
| 2 | CLI syntax or argument validation error | unknown command, missing/unknown subcommand, missing required flag, unexpected positional argument, unknown flag |

## systemd user service

docker-helper can run as a systemd user service. The unit file is
installed at `~/.config/systemd/user/docker-helper.service` by the Release 1
installer.

### Installation

```
docker-helper init
systemctl --user daemon-reload
systemctl --user enable --now docker-helper
```

Configuration and state directories are created by `docker-helper init`
using standard XDG paths. Non-standard `XDG_CONFIG_HOME` and
`XDG_STATE_HOME` are supported when they are present in the systemd user
manager environment.

### Stop and restart

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
`config set`. For Release 1 upgrade compatibility (v1.0.2 accepted any
positive `shutdown_timeout`), a persisted value above `30s` is loaded but
bounded to `30s` at startup/reload with an operational warning; `config
show` reports the bounded effective value. The shipped system and user
units both carry `TimeoutStopSec=45s`.

The shutdown budget is read from the daemon's *current* configuration at the
moment shutdown begins: a `shutdown_timeout` changed via reload is honored by
the next stop without a restart.

### Operation lifecycle invariants

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

### Logout

- **without linger** (`loginctl enable-linger` not set): the user manager
  and all services normally stop after the last user session ends;
- **with linger**: the user manager continues running and the service
  stays active after logout.

### StartLimit

The unit limits restarts to 3 attempts within 60 seconds. If this limit
is reached (e.g. when `docker-helper init` has not been run):

```
systemctl --user reset-failed docker-helper
systemctl --user start docker-helper
```

### Hardening

The unit applies process-level hardening (`NoNewPrivileges`,
`RestrictNamespaces`, `RestrictRealtime`). `RestrictSUIDSGID` is deliberately
omitted because its seccomp filtering blocks the `openat2` staging primitive on
supported systems.
Filesystem namespace directives (`ProtectSystem`, `ProtectHome`, etc.)
are not used in the initial unit: their compatibility with docker-helper
depends on the runtime environment and requires per-distribution testing.

The unit does not restrict direct access to the host filesystem. The
process-level directives only forbid specific operations. Access to the
Docker socket means the unit does not create a full security boundary.

## Authentication

Three authentication classes provide different levels of access:

### Admin token

- generated once by `docker-helper init`;
- stored at `admin.token` (user mode: user config directory; system mode:
  `/etc/docker-helper/admin.token`);
- SHA-256 hash loaded into memory at server start;
- grants full administrative access: manage principals, credentials, and
  all sessions;
- sent as `Authorization: Bearer <admin-token>`;
- compared with `crypto/subtle.ConstantTimeCompare` to prevent timing
  attacks.

### Principal credential

- created per principal by `POST /principals/{username}/credentials`
  (admin token required);
- credential token prefixed `dhc_`, credential ID prefixed `dhcr_`;
- SHA-256 hash stored in SQLite;
- grants access scoped to the principal: create sessions for that principal,
  list and delete only that principal's sessions, and manage that principal's
  launchers and their credentials;
- cannot manage other principals, their launchers, or global configuration;
- sent as `Authorization: Bearer <credential-token>`;
- resolved through database lookup by token hash.

### Launcher credential

- at most one credential exists per launcher; issued with
  `PUT /principals/{username}/launchers/{launcher}/credential` (admin or
  owning-principal token required)
  and replaced by `POST /principals/{username}/launchers/{launcher}/credential/rotate`;
- same token format as Principal credentials (`dhc_` + 64 hex characters);
  the token itself carries no owner type — the owner is resolved from
  persistent state at authentication time;
- SHA-256 hash stored in SQLite;
- grants access scoped to one launcher: create sessions owned by that
  launcher, list and delete only that launcher's sessions, and inspect the
  launcher itself via `GET /auth`;
- cannot manage launchers, principals, credentials, or other launchers'
  sessions;
- deleting the credential does not delete the launcher or its sessions; it
  only removes that authentication key.

#### Credential install

The `credential install` command stores a credential token (Principal or
Launcher) for the principal user. It is not run as root.

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

### Session token

- generated per session by `POST /sessions`;
- returned once in the creation response;
- SHA-256 hash stored in SQLite;
- required for Docker operations: `POST /build`, `POST /run`, `POST /pull`,
  `POST /registry/login`;
- sent as `Authorization: Bearer <session-token>`;
- resolved through database lookup by token hash and checked for expiration;
- deletion removes the session and invalidates subsequent requests.

Session management is authenticated by authority:
- admin token -> global session management (create with explicit selector,
  list all, delete any);
- Principal credential -> principal-scoped session management (create for
  the principal's default or an explicit launcher, list and delete only that
  principal's sessions, manage that principal's launchers);
- Launcher credential -> launcher-scoped session management (create for its
  own launcher, list and delete only its launcher's sessions).

`GET /auth` reports the authenticated authority to the caller as
`{"authority": "admin"}`, `{"authority": "principal", "principal": "..."}`
or `{"authority": "launcher", "principal": "...", "launcher_id": "..."}`.
It accepts an admin token, Principal credential, or Launcher credential; a
Session token does not authenticate this endpoint. Invalid, revoked, or
disabled credentials follow the existing non-disclosing authentication
semantics and receive no identity information.

## Launcher ownership

Release 2.1 adds one stable ownership and delegation level between Principal
and Session. The binding domain model is:

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
- A credential is a rotatable authentication key, never an owner. Principal
  credentials initiate and manage work for their principal; Launcher
  credentials initiate and manage work for their launcher. Ownership is
  derived from persistent state, never from the token.
- The CLI is never an authorization authority; the daemon resolves and
  enforces all policy.

### Launcher model

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
(create, rename, and the migration/bootstrap insertion of `default`) and
by a CHECK constraint on the `launchers` table; a database created by an
intermediate unreleased 2.1 build that predates the invariant fails
closed at startup instead of being silently rewritten. Because `_` is
outside the alphabet, Launcher names and Launcher IDs (`dhl_<32 hex>`)
occupy disjoint lexical spaces.

A Launcher name is unique within one Principal and may repeat under
different Principals; there is never a global lookup by Launcher name
(`alice/default` and `bob/default` are different Launchers). `default` is
only the conventional default name — the name used when creation omits
`--name` and when an individual Launcher command omits the selector —
not a subtype or a global singleton.

Every principal has an implicit default Launcher named `default`:

- provisioning is eager and idempotent: Principal creation provisions its
  `default` Launcher in the same transaction
  (`ensureDefaultLauncher`, atomic rollback), and startup backfills any
  Principal that predates that rule (`migrateDefaultLaunchers`); later
  startups resolve it read-only (`findDefaultLauncher`);
- user mode transparently maps all ownership to one daemon-owner principal
  and its default Launcher, so quick start requires no Principal, Launcher,
  or credential and preserves the effective global-root semantics;
- system mode requires explicit ownership: an authenticated Principal
  resolves its own default Launcher when no explicit selector is supplied.

### Launcher scope and effective roots

Launcher scope narrows the Principal authorization ceiling for sessions
created through that launcher; it never widens and never owns MAC state:

| Launcher scope | Effective roots for new sessions |
|---|---|
| `inherit` | global allowed roots ∩ principal allowed roots |
| `restricted` | global ∩ principal ∩ launcher allowed roots |

Evaluation happens at session-creation time against current state; a
launcher root that is no longer under the principal ceiling is rejected
then (never silently truncated), so stale out-of-ceiling roots cannot
produce a session outside the principal's allowed roots.

Scope is replaced atomically:
`PUT /principals/{username}/launchers/{launcher}/allowed-roots` accepts
the complete scope (`{"scope": "inherit", "allowed_roots": []}` or
`{"scope": "restricted", "allowed_roots": [...]}`); there is no
read-modify-write policy mutation through the CLI.

### Launcher control plane

HTTP surface (admin token or owning-principal credential; a Launcher
credential cannot manage launchers):

| Endpoint | Purpose |
|---|---|
| `POST /principals/{username}/launchers` | create launcher (optional one-time credential issuance) |
| `GET /principals/{username}/launchers` | list that principal's launchers |
| `GET /principals/{username}/launchers/{launcher}` | show launcher |
| `PATCH /principals/{username}/launchers/{launcher}` | rename / enable / disable |
| `PUT /principals/{username}/launchers/{launcher}/allowed-roots` | atomic scope replacement |
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
a name lookup, never a global name scan). A Principal credential reaches
only its own Principal (any other username is `404 principal_not_found`);
an admin token targets the explicitly selected Principal; a Launcher
credential cannot manage launchers.

Launcher projection: `{"id", "principal", "name", "enabled", "scope",
"allowed_roots", "created_at"}`. Create response carries the one-time
credential token only when issuance was requested. Exactly one credential
may exist per launcher (`launcher_credential_exists` on a second issuance;
rotation replaces the existing credential and its token).

CLI surface:

```
docker-helper launcher create [--principal USER] [--name NAME]
    [--allowed-root PATH]... [--issue-credential | --no-credential]
docker-helper launcher list [--principal USER]
docker-helper launcher show [--principal USER] [LAUNCHER]
docker-helper launcher set [--principal USER] [--name NAME]
    [--enabled true|false] [LAUNCHER]
docker-helper launcher delete [--principal USER] [LAUNCHER]
docker-helper launcher scope set [--principal USER]
    [--inherit | --allowed-root PATH]... [LAUNCHER]
docker-helper launcher credential issue [--principal USER] [LAUNCHER]
docker-helper launcher credential rotate [--principal USER] [LAUNCHER]
docker-helper launcher credential delete [--principal USER] [LAUNCHER]
```

`LAUNCHER` is a Launcher name or ID, and omitting it selects the
Principal's `default` Launcher. `create`/`list` and every individual
Launcher command resolve the target Principal the same way: a Principal
credential infers its Principal from `GET /auth`; an admin token must
name the Principal explicitly with `--principal` (omission fails; the
CLI never searches for a `default` Launcher globally). Principal
inference is target construction only — the daemon remains the
authorization authority. `create` prompts for the credential choice on a
TTY; non-interactive use must pass `--issue-credential` or
`--no-credential` explicitly.

### Session selectors and default resolution

`POST /sessions` accepts `{"workspace", "launcher_id", "principal"}`:

- `launcher_id` and `principal` are mutually exclusive; both present is
  `400 conflicting_selectors`; an explicitly present but empty or malformed
  selector is `400 invalid_selector`;
- Launcher credential: the owning launcher is forced; a conflicting
  explicit selector is rejected;
- Principal credential with no selector: resolves that principal's default
  launcher;
- Principal credential with `principal` selector: must name the
  authenticated principal (same non-disclosure rules as before);
- admin token (system mode): exactly one selector is required; admin token
  (user mode): omission resolves the local daemon-owner default launcher.

### Launcher lifecycle and cleanup

Launcher disable/delete propagation reuses the existing Session lifecycle
and MAC/runtime cleanup owners:

- disabling a launcher deletes its sessions and cleans their runtime state
  through the existing per-session cleanup path; a disabled launcher
  rejects new session creation and its credential authentication
  (`launcher disabled`);
- deleting a launcher performs a checked delete: if its sessions still
  have active runtime state, the delete fails with
  `409 launcher_runtime_active` and the launcher stays enabled so it can
  be disabled explicitly first; otherwise sessions are deleted and the
  launcher row is removed;
- principal disable/delete propagates: disabling a principal deletes all
  its sessions; deleting a principal deletes its launchers (FK cascade)
  and fails with `409 launcher_runtime_active` if any launcher still has
  active runtime;
- an individually disabled launcher stays disabled through parent
  enable/disable transitions; re-enabling the principal or parent does not
  re-enable it;
- credential rotation keeps the launcher identity and its sessions: the
  old bearer is rejected immediately, the replacement is authorized, and
  no second credential row is created.

### Ownership migration (v2.0 -> 2.1)

Startup migration is idempotent and restart-safe, guarded by the daemon
instance lock:

| Legacy state | Result |
|---|---|
| v2.0 principal credential rows | preserved byte-for-byte as Principal credentials (`launcher_id NULL`, no launcher credential fabricated) |
| attributable principal-owned sessions | re-owned by that principal's `default` launcher |
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
schema is authoritative and startup never re-adds `principal_id`.

### Runtime correlation labels

Containers started by docker-helper carry helper-owned labels used only for
correlation and checked cleanup; user input cannot set or override them:

```
com.dockerhelper.session.id      = <session id>
com.dockerhelper.launcher.id     = <launcher id>
com.dockerhelper.principal.name  = <principal username>
com.dockerhelper.correlation.schema = 1
```

Labels are correlation/cleanup evidence, not authorization state. The
namespace is deliberately neutral: only the Launcher is the Session owner;
the Session and Principal labels are provenance.

### Launcher audit provenance

Launcher audit events carry the full launcher projection fields
(`launcher_id`, `launcher_name`, `launcher_scope`, plus
`launcher_enabled` on update events). `session.create` additionally
carries `launcher_id`, `launcher_name`, and `principal_name`. Docker
operation events (`build`/`run`/`pull`, including `registry.login`)
record `principal_name`, `launcher_id`, and `launcher_name` from the
session's ownership. `session.delete` records the deleted session's
ownership (`launcher_id`, `launcher_name`, `principal_name`). Launcher
control events carry the caller's provenance
(`credential_id`, and `credential_name` where the credential has a
name), except for credential issue/rotate events, which record the newly
issued credential.

## Workspace isolation

Each session is bound to a single workspace directory.

### Initialization and allowed-root defaults

Initialization follows the selected deployment identity:

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
requires the corresponding managed-root rule. SELinux requires a permitted
workspace file type.

### Three-level authorization model

Authorization flows through four narrowing steps (three allowed-root
levels plus the delegated Launcher owner):

1. **Global allowed_roots** (config.json) — the system-wide authorization
   ceiling, managed by `config allowed-root list/add/remove`. Changing
   allowed roots is a policy-only operation; it does NOT prepare MAC state.
2. **Principal allowed roots** (database) — per-principal narrowing, managed
   by `principal allowed-root add/remove`. Does not prepare MAC.
3. **Launcher allowed roots** (database, `restricted` scope only) —
   per-launcher narrowing beneath one principal; `inherit` scope applies no
   launcher-level narrowing. Evaluated at session-creation time against
   current state. Does not prepare MAC.
4. **Session workspace** (ephemeral) — selected only at session creation time
   via `session create --workspace PATH`. Must be under a global, the
   principal, and (when restricted) the launcher allowed root.

MAC state is derived from the concrete live session/workspace lifecycle,
not from the authorization ceiling. Only the session workspace participates
in MAC preparation (AppArmor managed-root rules or SELinux fcontext labels).

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

Adding `/opt` as a global allowed root must never imply recursive relabeling
of `/opt/**`.

### Canonical paths

All paths are resolved through `filepath.EvalSymlinks` before comparison.
This prevents symlink-based escape attacks at validation time.

Note: `EvalSymlinks` resolves the path at a point in time. By itself it
does not solve TOCTOU problems where the filesystem changes between
validation and use. For operations that pass paths to Docker as strings,
additional measures (such as FD-relative traversal or inode pinning) are
required to close the gap.

### Path containment

The canonical containment API lives in `path_containment.go`:

- `pathWithin(root, path)` — returns true if `path` is within `root`
  (equality allowed). Both arguments must be canonical (absolute, cleaned).
- `pathStrictlyWithin(root, path)` — returns true if `path` is a proper
  descendant of `root`. Equality returns false.

Argument order is always root first, path second. These functions correctly
handle the prefix trap: `pathWithin("/data", "/data2")` returns false.

### Symlink escape prevention

When a session is created, the workspace path is resolved through
`EvalSymlinks`. The canonical workspace is stored in the database.

When a build or run request specifies a path relative to the workspace,
the resolved path is compared against the canonical workspace. If the
resolved path escapes the workspace, the request is rejected.

This validation catches static symlink escapes at request time. It does
not by itself prevent a TOCTOU attack where the workspace contents change
between validation and Docker execution. The specific mitigation depends
on the operation:

- **Builds** (both modes): an isolated staging copy eliminates the gap
  (see Build context below).
- **System-mode run mounts**: inode-pinned helper-owned mounts via
  `open_tree` + `move_mount` close the gap (see System-mode mounts
  below).
- **User-mode run mounts**: only the workspace root may be mounted;
  security relies on the workspace-parent write invariant that the agent
  cannot replace the workspace directory entry (see User-mode mounts
  below).

### Per-session workspace

Each session has its own workspace. An agent with a session for
`/home/user/project-a` cannot access `/home/user/project-b`, even if both
are inside `AllowedRoot`.

## Build pipeline

```
Authentication
    │
Request validation
    │
Canonical path resolution
    │
Boundary validation
    │
Operation registration (tryCreate — atomic with shutdown gate)
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
required fields and dockerfile relativity. Canonical path resolution
resolves the workspace and context through `EvalSymlinks`. Boundary
validation ensures the context and dockerfile are inside the workspace
and context respectively.

Operation registration uses `tryCreate`, which atomically checks the
shutdown gate and registers the operation under the same mutex. If the
daemon is shutting down, registration is rejected with 503.

The build process starts asynchronously. `cmd.Start()` is called under
`op.mu` to synchronize with shutdown termination. stdout and stderr are
captured directly into a thread-safe bounded buffer (`operation_log_max_bytes`).

A completion goroutine owns `cmd.Wait()` and transitions the operation
to `succeeded` or `failed` when the process exits.

Validation details:

- context may be relative (joined with workspace) or absolute (must be
  inside workspace);
- dockerfile must be relative to context;
- all paths are resolved through `EvalSymlinks` before `pathWithin` checks;
- build-arg names must match `^[A-Za-z_][A-Za-z0-9_]*$`;
- build-arg keys are sorted for deterministic Docker argv;
- build-arg values are never logged or audited (only `build_arg_keys`).

## Run pipeline

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
Operation registration (tryCreate — atomic with shutdown gate)
    │
Async docker run process start (cmd.Start under op.mu)
    │
Incremental bounded log capture (cmd.Stdout/stderr → boundedBuffer)
    │
Completion goroutine (cmd.Wait → status transition)
    │
Retention cleanup
```

Authentication validates the session token. Request validation checks
that the image field is non-empty. Workdir validation ensures the value
is an absolute path if provided. Environment validation ensures variable
names match `^[A-Za-z_][A-Za-z0-9_]*$`. Mount resolution resolves each
source path against the workspace and checks for duplicate targets.

Operation registration uses `tryCreate`, which atomically checks the
shutdown gate and registers the operation under the same mutex. If the
daemon is shutting down, registration is rejected with 503.

The run process starts asynchronously. `cmd.Start()` is called under
`op.mu` to synchronize with shutdown termination. stdout and stderr are
captured directly into a thread-safe bounded buffer (`operation_log_max_bytes`).

A completion goroutine owns `cmd.Wait()` and transitions the operation
to `succeeded` or `failed` when the process exits.

**Container lifecycle:**

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
  Release 1 limit); the parsed byte value is passed to Docker as
  `--shm-size`; this is a `/dev/shm` limit only, NOT a general container
  memory or CPU limit;
- container runs with fixed security policy (details in implementation).

## Pull pipeline

```
Authentication
    │
Request validation
    │
Docker invocation
```

Authentication validates the session token. Request validation checks
that the image field is non-empty. Docker invocation runs
`docker pull` with the image reference.

Image reference syntax is delegated to Docker. The helper does not
reimplement the Docker reference grammar; it only checks that the image
field is non-empty. Docker CLI validates the reference when the command
executes. If Docker rejects the reference, the endpoint returns its
standard Docker failure response.

## Registry login

`POST /registry/login` authenticates a session with a Docker registry.

```
Authentication
    │
Request validation
    │
Session Docker config directory
    │
Docker invocation
```

Authentication validates the session token. Request validation checks
that `registry`, `username`, and `password` are all non-empty.

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

### Audit

| Event | Fields |
|-------|--------|
| `registry.login.start` | `session_id`, `registry`, `principal_name` (present for principal-owned sessions), `launcher_id`/`launcher_name` (present for launcher-owned sessions) |
| `registry.login.finish` | `session_id`, `registry`, `result`, `duration`, `principal_name` (present for principal-owned sessions), `launcher_id`/`launcher_name` (present for launcher-owned sessions) |

`result` is `success` or `login_failed`. The password and username are
never included in audit records.

### Session delete cleanup

When a session is deleted, its runtime directory (including the Docker
config directory) is removed. Stale session directories from crashed
or expired sessions are cleaned up at daemon startup.

## Health endpoint

`GET /health` returns a 200 OK response with a JSON body indicating the
server is running. No authentication is required. This endpoint is
intended for liveness probes and does not perform any audit logging.

## Operation endpoints

`POST /build` and `POST /run` return HTTP 201 with an `operation_id`.
The client uses the operation endpoints to track progress.

### GET /operations/{id}

Returns the operation status and metadata. Requires the session token
that created the operation.

Response fields:

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

### GET /operations/{id}/logs

Returns incremental operation output. Requires the session token.

Query parameters:

| Parameter | Description |
|-----------|-------------|
| `offset` | Byte offset to start reading from (default: 0) |

Response fields:

| Field | Type | Description |
|-------|------|-------------|
| `ok` | boolean | always true on success |
| `operation_id` | string | operation identifier |
| `offset` | number | the requested offset |
| `next_offset` | number | offset for the next request |
| `truncated` | boolean | true if older data was evicted |
| `logs` | string | log data from the requested offset |

Logs are a mixed stdout/stderr byte stream. Retention: each operation
log is stored in a bounded buffer of `operation_log_max_bytes`. When the
limit is exceeded, the oldest data is evicted. `truncated` is true when
the requested offset refers to evicted data.

### POST /operations/{id}/cancel

Cancels a running operation. Requires the session token that created the
operation.

Contract:

- running operation → graceful SIGTERM, then bounded force-cleanup
  fallback if the process does not exit in time;
- operation becomes terminal: `status=failed`, `result_code=cancelled`;
- already-terminal operation → idempotent HTTP 200 with current state;
- unknown or foreign operation → HTTP 404 `operation_not_found`;
- operation logs remain accessible after cancel;
- the response returns after the operation reaches terminal state.

Cancel and daemon shutdown share the same underlying termination
lifecycle. The first termination reason to be set wins and cannot be
overwritten by a concurrent caller.

## Retention

Completed operations are retained in memory. Cleanup is opportunistic and
runs on access:

- `operation_retention_ttl` — operations older than this are removed;
- `operation_max_completed` — when more completed operations exist than
  this limit, the oldest are removed;
- `operation_log_max_bytes` — per-operation log buffer size; older output
  is evicted when exceeded.

Cleanup is invoked during operation creation (`POST /build`, `POST /run`) and operation
status access (`GET /operations/{id}`). There is no background retention
worker or periodic ticker.

## Filesystem policy

### Bind mounts

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

### System-mode run mounts

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

### User-mode run mounts

In user mode, the resolved mount source must equal the canonical
`session.Workspace`. Subdirectory and file mounts are rejected as
`invalid_mount`.

This restriction exists because user mode lacks `CAP_SYS_ADMIN` for
inode-pinned mounts. The security of the workspace-root mount relies on
the workspace-parent write invariant: the sandboxed agent does not have
host-side write access to the parent directory of the workspace. Since the
agent cannot replace the workspace directory entry, the pathname remains
stable between validation and the Docker bind mount.

### Build context

The Linux build implementation creates an isolated helper-owned staging
copy of the build context. Traversal is FD-relative and restricted with
`openat2` flags (`RESOLVE_NO_SYMLINKS`, `RESOLVE_BENEATH`). Docker
receives only the staged context and Dockerfile paths, never the
original workspace paths.

On platforms or kernels where `openat2` is unavailable, the operation
fails closed without falling back to original workspace paths.

Staging directories are cleaned up as part of the build operation
lifecycle.

### Why source must be relative

Requiring a relative source ensures the mount is always scoped to the
session workspace. An absolute source could bypass workspace isolation.

## Environment policy

Environment variable names must match `^[A-Za-z_][A-Za-z0-9_]*$`.

Values can be any string, including empty.

Values are never logged. Only variable names appear in `env_keys`.

Environment variables are sorted by name before being passed to Docker.
This makes the command line deterministic and reproducible.

### Trusted CA injection

When `trusted_ca_injection` is set to `"auto"` and `trusted_ca_path` points
to a valid single PEM X.509 CA certificate, docker-helper injects the CA
into containers started via `POST /run`:

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
the source cannot be read. Existing Release 1 / earlier Release 2
configurations continue to work without migration or copying the CA.

## Error handling

The API returns JSON errors with a stable `code` field. Clients can
distinguish error types programmatically. The `duration` field reports
wall-clock time.

`POST /build` and `POST /run` return HTTP 201 with an `operation_id` when
accepted. Execution result (success, failure, exit code, logs) appears
through the operation endpoints:

- `GET /operations/{id}` — status, timestamps, exit code, result code;
- `GET /operations/{id}/logs?offset=N` — incremental operation output.

`POST /pull` remains synchronous and returns the execution
result directly in the response. Pull output is captured into a bounded
buffer of `operation_log_max_bytes`. When output exceeds the limit, the
newest tail is retained and `truncated` is set to `true` in the response.

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
| `shutting_down` | `POST /build`, `POST /run` | daemon is shutting down |
| `docker_pull_failed` | `POST /pull` | docker pull returned non-zero and the failure is not classified |
| `image_not_found` | `POST /pull` | docker pull: image/repository not found |
| `pull_access_denied` | `POST /pull` | docker pull: authentication/authorization denied |
| `registry_unavailable` | `POST /pull`, `POST /registry/login` | registry/network/backend failure |
| `registry_auth_denied` | `POST /registry/login` | docker login: authentication/authorization denied |
| `registry_login_failed` | `POST /registry/login` | docker login failed and the failure is not classified |
| `operation_not_found` | `GET /operations/{id}`, `GET /operations/{id}/logs`, `POST /operations/{id}/cancel` | operation not found or foreign session |

`GET /sessions` emits `session.list`. `GET /health` intentionally emits no
audit event because it is an unauthenticated liveness endpoint.

### Rejected Docker-operation requests

After successful session authentication, every POST /pull, POST /build, and
POST /run request produces exactly one of:

- `<kind>.rejected` — the request was rejected before acceptance; or
- `<kind>.start` — the request was accepted as an operation.

where `<kind>` is `pull`, `build`, or `run`.

Authentication failures remain owned by the existing `auth.failure` path and
do not additionally emit `<kind>.rejected`.

The rejected event schema contains only:

- `event`: `<kind>.rejected`
- `result`: the public API error code (e.g., `invalid_image`, `invalid_mount`,
  `launcher_unavailable`, `shutting_down`, `internal_error`)
- `principal_name`: when available
- `session_id`: from the authenticated session
- `request_id`: from the request context

The `result` field exactly matches the public API response `code`.

Rejected events intentionally omit request payload metadata (image, mounts,
env, command, context, dockerfile, etc.). This makes rejected-event metadata
smaller than accepted `*.start` events and avoids logging partially validated
input. No `operation_id` is included because a rejected request was never
accepted as an operation.

## Audit logging

docker-helper writes structured audit records to **stdout**. Operational
logs are written to **stderr**. Both streams use JSON Lines format.
Timestamps in both streams use UTC in RFC 3339 nanosecond format
(`time.RFC3339Nano`).

### Stream separation

| Stream | Destination | Content | Level-filtered |
|--------|-------------|---------|----------------|
| Audit | stdout | Audit records (JSONL) | No (controlled by `audit_enabled`) |
| Operational | stderr | Daemon events (JSONL) | Yes, by `log_level` |

No runtime `fmt.Printf`, `log.Printf`, or other free-form text output
is emitted. Human-oriented CLI output from `init`, `version`, `help`,
and `session` commands remains unchanged.

Every audit record contains `"stream": "audit"`.
Every operational record contains `"stream": "operational"`.

### Audit enablement

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
by default.  In system mode, audit is enabled by default.

The `audit_enabled_source` field in `docker-helper config show` indicates
how the effective value was derived:

| Value | Meaning |
|-------|---------|
| `"explicit"` | `audit_enabled` was set in `config.json` |
| `"system_default"` | `audit_enabled` absent, system mode defaults to enabled |
| `"log_level"` | `audit_enabled` absent, user mode derived from `log_level` |

When audit is disabled:

- no audit records are written to stdout;
- no audit encoding or writer errors are emitted;
- operational logging and request handling are unaffected.

### Operational log levels

The `log_level` field in `config.json` controls operational log verbosity:

| Value | Records emitted |
|-------|-----------------|
| `debug` | debug, info, warn, error |
| `info` | info, warn, error (default) |
| `warn` | warn, error |
| `error` | error only |

### Debug request logging

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

### Request correlation

Every HTTP request receives a server-generated request ID. It is:

- returned in the `X-Request-ID` response header;
- added as `request_id` to every audit record for that request;
- added to every operational record for that request;
- `session_id` is added to operational records when authentication
  has established a session.

The server does not trust or reuse any client-supplied request ID.

**Async operation completion** (build.finish, run.finish) is not
request-scoped. These audit records do not include `request_id`.
Correlation for async events uses `session_id` + `operation_id`.

**Audit writer failures** are logged as operational ERROR records with
`audit_event` and `operation_id` (when present in the original record)
for correlation. Existing `request_id` and `session_id` are preserved.
Audit writer failure is best-effort and does not affect the request
or operation outcome.

### Sensitive data

The following are **never** logged:

- command arguments (only `command_arg_count` appears in audit);
- environment variable values (only names in `env_keys`);
- Docker build output or container stdout/stderr;
- `Authorization` header values;
- raw HTTP request bodies.

### Log collection

Log collection, retention, and rotation are delegated to the process
supervisor (systemd/journald or another log shipper). docker-helper
does not write log files or implement internal rotation.

### Format

JSON Lines: one JSON object per line, UTF-8 encoded. Each line is an
independent record.

Operational records use slog's structured `time`, `level`, and `msg`
fields.

### Common fields

| Field | Type | Description |
|-------|------|-------------|
| `time` | string | UTC timestamp, RFC 3339 with nanoseconds |
| `stream` | string | always `audit` for these records |
| `event` | string | event name |
| `result` | string | outcome code (omitted on `build.start`) |
| `session_id` | string | session identifier (omitted on `auth.failure`) |
| `duration` | string | wall-clock duration, e.g. `"1s"`, `"150ms"` |

Additional fields depend on the event. Fields with empty or zero values
are omitted from the JSON output.

### Events

Implemented event families are:

| Area | Events |
|---|---|
| Authentication | `auth.failure`, `auth.session` |
| Sessions | `session.create`, `session.list`, `session.delete` |
| Principals | `principal.create`, `principal.enabled_change`, `principal.allowed_root_add`, `principal.allowed_root_remove`, `principal.delete` |
| Launchers | `launcher.create`, `launcher.list`, `launcher.update`, `launcher.scope_replace`, `launcher.delete`, `launcher.credential_issue`, `launcher.credential_rotate`, `launcher.credential_delete` |
| Credentials/admin | `principal.credential_create`, `principal.credential_revoke`, `admin_token.rotate` |
| Docker operations | `pull.start`, `pull.finish`, `pull.rejected`, `build.start`, `build.finish`, `build.rejected`, `run.start`, `run.finish`, `run.rejected`, `registry.login.start`, `registry.login.finish` |
| Configuration | `config.reload` |

The detailed schemas below document the Docker-operation and principal/session
events with non-obvious fields. All records also carry `stream=audit`.

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
| `principal_name` | string | principal name (present for principal-owned sessions; omitted for legacy/admin sessions) |
| `launcher_id` | string | owning launcher ID (present for launcher-owned sessions) |
| `launcher_name` | string | owning launcher name (present for launcher-owned sessions) |

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
| `principal_name` | string | principal name (present for principal-owned sessions; omitted for legacy/admin sessions) |
| `launcher_id` | string | owning launcher ID (present for launcher-owned sessions) |
| `launcher_name` | string | owning launcher name (present for launcher-owned sessions) |
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
| `principal_name` | string | principal name (present for principal-owned sessions; omitted for legacy/admin sessions) |
| `launcher_id` | string | owning launcher ID (present for launcher-owned sessions) |
| `launcher_name` | string | owning launcher name (present for launcher-owned sessions) |

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
| `principal_name` | string | principal name (present for principal-owned sessions; omitted for legacy/admin sessions) |
| `launcher_id` | string | owning launcher ID (present for launcher-owned sessions) |
| `launcher_name` | string | owning launcher name (present for launcher-owned sessions) |
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

#### auth.failure

Emitted for every failed authorization attempt. No `session_id` is
included because the session is not reliably established.

| Field | Type | Description |
|-------|------|-------------|
| `method` | string | HTTP method of the request |
| `path` | string | request path |
| `result` | string | failure reason |

Result codes:

| Code | Condition |
|------|-----------|
| `admin.parse_failed` | `Authorization` header is missing, uses a non-Bearer scheme, or the token is empty/malformed on an admin endpoint |
| `admin.wrong_token` | Bearer token does not match the configured admin token |
| `session.parse_failed` | `Authorization` header is missing, uses a non-Bearer scheme, or the token is empty/malformed on a session endpoint |
| `session.not_found` | No active session matches the token (unknown, expired, or deleted) |
| `session.database_error` | Database error during session lookup |

#### pull.start

Emitted before a Docker pull begins.

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `image` | string | image reference |
| `principal_name` | string | principal name (present for principal-owned sessions; omitted for legacy/admin sessions) |
| `launcher_id` | string | owning launcher ID (present for launcher-owned sessions) |
| `launcher_name` | string | owning launcher name (present for launcher-owned sessions) |

No `result` or `duration` field.

#### pull.finish

Emitted after a Docker pull completes (success or failure).

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | string | session identifier |
| `image` | string | image reference |
| `principal_name` | string | principal name (present for principal-owned sessions; omitted for legacy/admin sessions) |
| `launcher_id` | string | owning launcher ID (present for launcher-owned sessions) |
| `launcher_name` | string | owning launcher name (present for launcher-owned sessions) |
| `result` | string | `success` or `pull_error` |
| `exit_code` | number | present when an exit code is available |
| `duration` | string | pull wall-clock time |

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

### What is never logged

The following are **never** logged to either the audit or operational
streams:

- the raw HTTP request body;
- HTTP request headers;
- `Authorization` header values and the token used for authentication;
- environment variable values (only names appear in `env_keys`);
- build-arg values (only names appear in `build_arg_keys`);
- Docker build output or container stdout/stderr;
- command arguments (only `command_arg_count` is recorded);
- registry passwords;
- CA certificate contents.

**Audit records** never contain internal error messages or stack traces.

**Operational ERROR/WARN records** may contain internal error diagnostics
for debugging unexpected failures. These error strings are operational
internals and are not exposed to the API.

This section refers to the daemon's audit and operational logs. The per-operation
output buffer accessed via `GET /operations/{id}/logs` is intentionally separate:
it captures the merged stdout/stderr stream from the Docker CLI process and may
contain Docker pull/build status output, container stdout/stderr, and build
process output. That stream is not part of the daemon audit or operational logs.

### Examples

Successful build:

```json
{"time":"2026-01-15T10:30:00Z","stream":"audit","event":"build.start","request_id":"req_abcdef1234567890","session_id":"dhs_0a1b2c3d4e5f","operation_id":"op_abcdef1234567890","image":"myapp:v1","context":".","dockerfile":"Dockerfile"}
{"time":"2026-01-15T10:30:05Z","stream":"audit","event":"build.finish","session_id":"dhs_0a1b2c3d4e5f","operation_id":"op_abcdef1234567890","image":"myapp:v1","context":".","dockerfile":"Dockerfile","result":"succeeded","duration":"5s"}
```

Successful session creation:

```json
{"time":"2026-01-15T10:29:55Z","stream":"audit","event":"session.create","session_id":"dhs_0a1b2c3d4e5f","workspace":"/home/user/project","result":"success","duration":"1ms"}
```

Authorization failure:

```json
{"time":"2026-01-15T10:31:00Z","stream":"audit","event":"auth.failure","method":"POST","path":"/run","result":"session.not_found"}
```

Container run:

```json
{"time":"2026-01-15T10:32:00Z","stream":"audit","event":"run.start","request_id":"req_abcdef1234567890","session_id":"dhs_0a1b2c3d4e5f","operation_id":"op_abcdef1234567890","image":"alpine:3.19","command_arg_count":3,"mounts":[{"source":".","target":"/workspace","read_only":true}],"env_keys":["APP_MODE"]}
{"time":"2026-01-15T10:32:01Z","stream":"audit","event":"run.finish","session_id":"dhs_0a1b2c3d4e5f","operation_id":"op_abcdef1234567890","image":"alpine:3.19","command_arg_count":3,"mounts":[{"source":".","target":"/workspace","read_only":true}],"env_keys":["APP_MODE"],"result":"succeeded","duration":"1s"}
```

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

### Session token leakage

Session tokens are returned once during creation. The full token is never
stored in the database — only its SHA-256 hash. Admin token comparison
uses `ConstantTimeCompare` to prevent timing attacks. Principal credentials
and session tokens are resolved through database lookup by hash.

### Direct docker.sock access

docker-helper does not expose `docker.sock`. The agent communicates only
through the HTTP API.

- **User mode**: Unix socket has `0600` permissions.
- **System mode**: Unix socket has `0666` permissions, but security is
  enforced through bearer authentication and authorization, not socket
  permissions alone.

### Secret leakage through logs

Command arguments, environment variable values, and Docker output are
never logged. Admin tokens, Principal credentials, and session tokens are
never logged. The audit record for `POST /run` includes `command_arg_count`
but never the arguments themselves.

### Container security

docker-helper applies a fixed security policy when running containers:

- `--rm` — remove the container on exit;
- user mode and AppArmor system mode use `--security-opt label=disable`;
- SELinux system mode uses
  `--security-opt label=type:docker_helper_container_t` and keeps MCS
  confinement;
- `--user <uid>:<gid>` — run as the session owner principal's UID and GID,
  or daemon UID:GID for daemon-owner (user-mode) sessions.

## Design principles

- small API surface;
- deny by default;
- policy enforcement outside the coding agent;
- session-scoped authorization;
- canonical path validation;
- deterministic Docker command generation;
- Docker CLI instead of exposing docker.sock.

## Non-goals of the current implementation

- container orchestration;
- Kubernetes integration;
- full Docker API compatibility;
- multi-host execution;
- container scheduling;
- image registry management;
- network management;
- volume management beyond bind mounts;
- detached container execution;
- container logs endpoint;
- health checks;
- resource limits (CPU, memory);
- build caching configuration;
- build secrets.

## Future work

Items discussed but not yet implemented:

- OpenCode custom tool integration (client-side);
- Release 3 managed-container lifecycle, interactive exec, per-Session
  networking, narrow publishing, and resource limits;
- remote transport and execution contract in Release 4 or later, driven by
  concrete use cases;
- stronger privilege separation if operational evidence justifies it;
- strict SELinux workspace storage based on dedicated/relabelled locations.
