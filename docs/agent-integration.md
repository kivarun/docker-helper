# Agent integration

This document is the current integration contract for coding agents using
docker-helper: delegated identity, filesystem authority, error
interpretation, and supported client interfaces. Sections marked
"historical" record the original Release 1 motivation and constraints;
they are context, not current requirements, and they do not weaken the
current contract.

## Historical: Release 1 goal

Release 1 provided the first-class way for coding agents to use
docker-helper.

The integration belongs at the client edge of the project. Agent-specific
behavior must not be added to the daemon core or change the daemon capability
contract.

## Delegated agent identity (Release 2.1)

A sandboxed agent authenticates with one of two delegated keys; both are
stored with `docker-helper credential install` and sent as a Bearer token
by the CLI and HTTP clients:

- **Launcher credential** (narrowest): bound to exactly one launcher. The
  agent can create sessions owned by that launcher, and can list and
  delete only that launcher's sessions. Sessions use the launcher's
  effective allowed roots (inherit or restricted scope).
- **Principal credential** (broader): bound to a principal. The agent can
  create sessions for that principal's launchers and manage that
  principal's launchers. Suitable when the agent is trusted with the
  principal's full workspace policy.

`GET /auth` reports which authority the installed credential carries
(`{"authority": "launcher", "principal": ..., "launcher_id": ...}` or
`{"authority": "principal", "principal": ...}`); a Session token does not
authenticate this endpoint. Launcher and Principal credential rotation
share the DB-backed response-delivery transaction: the replacement and
complete response are prepared first, the exact target row is CAS-checked,
the response is written while the replacement remains uncommitted, and
the commit follows only after a successful write. A write failure rolls
back to the previous bearer; a concurrent stale rotation is
`409 credential_rotation_conflict`; a commit error after a successful
write is ambiguous and must not be retried automatically. On the normal
committed path the previous bearer is rejected, existing Sessions are
unaffected, and no second Launcher credential row is created. Admin-token
rotation remains the separate file-backed mechanism.

The agent-facing self-introspection surface is `docker-helper self`
(HTTP `GET /self`): the daemon classifies the bearer and answers with
exactly that credential's own resource — for a Session bearer its issued
immutable filesystem snapshot, for a Launcher credential its Launcher
authority, for a Principal credential its Principal authority. A self
read grants no authority over peers.

Skill and adapter authors must treat the installed credential as a
secret: never print it, never copy it into logs or archives.

## Mount contract

The system service is the only daemon deployment; there is no user-mode
workspace-only special case. Mount containment is decided on the canonical
resolved source, never on the caller spelling:

- a workspace-relative source (including `.` for the workspace root) is
  scoped to the Session workspace;
- an absolute host source is authorized only through the issued Session
  filesystem snapshot (the workspace, or an issued filesystem root);
  any other absolute path is refused.

All run mounts use inode pinning (`open_tree` + `move_mount`); pinning
requires Linux kernel support and `CAP_SYS_ADMIN` and fails closed when
unavailable. Read-only semantics are enforced by the issued snapshot
together with mandatory workload MAC: a writable exposure that resolves
to or covers a read-only region is refused `read_only_root`, and a
read-only request is valid for a source in either access mode.

## Issued Session filesystem policy (Release 2.2)

A Session captures its filesystem scope as an immutable snapshot at
creation time and keeps it for its whole lifetime; parent-policy changes
affect only new Sessions. The snapshot is the single data-plane
filesystem authority for every mount and build context of that Session.
The workspace is mandatory; when the creation request supplies
issuance-time filesystem roots, additional absolute host roots inside the
Launcher's effective ceiling may narrow the scope; a widening request is
refused `invalid_filesystem_policy` before the Session exists.

Agent-facing consequences:

- A requested writable mount is refused with `read_only_root` when the
  source resolves to a read-only region of the issued snapshot or covers
  such a region. This is a policy refusal, distinct from the structural
  `invalid_mount`; the daemon never silently downgrades a writable
  request to read-only.
- A read-only request (`:ro` / `read_only: true`) is valid for a source
  in either access mode, so request it read-only when reads suffice.
- The daemon decides on the canonical resolved source identity, never on
  the caller spelling: symlink spellings cannot widen authority, and
  bypassing the helper does not either. Report a policy limitation or
  request a suitable Session from the owner instead of attempting a
  bypass.

## Error interpretation

- Structured HTTP errors (HTTP 4xx with an error `code`) mean the daemon
  responded. This is a request, authentication, or policy rejection, not
  daemon unavailability.
- `invalid_mount` is a request or policy failure — inspect the mount
  specification and the mount/path/snapshot policy (Mount contract), then
  correct the request.
- `read_only_root` is a filesystem-policy refusal of a writable exposure
  by the issued Session snapshot — request the source read-only or report
  the policy limitation; do not retry the same writable request.
- Docker Helper is only unavailable after an actual transport/connectivity
  failure (e.g., cannot connect to the Unix socket).

## Client interfaces

docker-helper exposes two first-class client interfaces:

### CLI

`docker-helper pull`, `build`, `run`, `registry login`, and `self`
(self-introspection of the authenticated credential).

The `docker-helper` binary is a reference/convenience client for the daemon
HTTP API. It is the same binary that provides operator commands (serve, init,
reload, session, config).

The CLI adds client-side convenience semantics:

- hides async operation ID, polling, and log offsets;
- streams operation logs to stdout/stderr;
- waits for terminal result;
- propagates container non-zero exit as CLI exit code;
- SIGINT -> best-effort cancel + exit 130;
- SIGTERM -> best-effort cancel + exit 143;
- cancel failure prints a diagnostic but does not replace the signal exit
  status.

The CLI does not introduce daemon capabilities or policy unavailable through
the HTTP API.

### HTTP API

Direct access to the daemon HTTP API over the Unix socket.

Suitable for:

- `curl`;
- agent images without the `docker-helper` binary;
- native/direct adapters;
- custom integrations.

Both interfaces are supported. The project does not mandate a preference
between them. The consumer chooses the interface appropriate for its
environment.

For the initial local integration, both interfaces talk to the Docker Helper
Unix socket. Loopback HTTP on `127.0.0.1:52375` is also available.

## Skills

A portable skill is available at `.claude/skills/docker-helper/SKILL.md`.

One skill covers both the CLI and HTTP API interfaces for Claude Code and
OpenCode. The skill is auto-discovered by the agent runtime when placed in
a supported skill directory. The exact skill path depends on the agent
runtime (e.g., `.claude/skills/` for Claude Code and OpenCode). The file
in the repository or release bundle is the canonical artifact; it must be
copied or mounted into the agent environment for the runtime to find it.

OpenCode dogfood completed for both interfaces:
- CLI interface (full `docker-helper` binary present);
- HTTP-only interface (no `docker-helper` binary, curl over Unix socket).

Claude Code compatibility is provided by the portable skill format and path,
but Claude Code dogfood has not been executed yet.

Skills must preserve these invariants:

- never invoke Docker directly;
- never access `docker.sock`;
- never expose `DOCKER_HELPER_SESSION_TOKEN`;
- never look for the administrative token;
- never create or manage Sessions unless the environment explicitly provides
  a Principal or Launcher credential with that delegated authority;
  a Session token alone never authorizes Session management.

## Native tools

Native agent-tool adapters are a subsequent experiment. A native adapter is
another HTTP API client, not an independent capability contract.

Implement at least one native adapter and compare it with the CLI + skill path
on real agent tasks. Keep native tools only if they provide a demonstrated
reliability or usability improvement beyond the portable client interfaces.

If native adapters are retained, they should be thin wrappers over the same
client-facing capability contract rather than independent implementations of
the Docker Helper protocol.

OpenCode-specific or Claude-specific code belongs in these adapters, not in the
daemon core.

## Historical: explicit non-goals (Release 1)

These non-goals were the Release 1 integration constraints; they remain
the standing integration boundary unless a current release explicitly
changes one. Do not add the following merely to deliver agent integration:

- a second mandatory daemon or shared runtime;
- MCP server wrapping docker-helper;
- plugin/control-plane infrastructure;
- remote transport design;
- agent-specific logic in the daemon;
- separate client configuration unless real use demonstrates the need;
- a second client binary solely for architectural purity.

The smallest successful integration is a stable daemon HTTP API, a
useful reference CLI, and reusable agent skills supporting both interfaces.
The canonical reusable agent instruction is
[`.claude/skills/docker-helper/SKILL.md`](../.claude/skills/docker-helper/SKILL.md).
