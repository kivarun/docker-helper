# Agent integration

## Release 1 goal

Release 1 provides a first-class way for coding agents to use
docker-helper.

The integration belongs at the client edge of the project. Agent-specific
behavior must not be added to the daemon core or change the daemon capability
contract.

## Launcher invariant for user mode

In user mode, the security of the workspace-root bind mount relies on the
launcher invariant: the sandboxed agent must not have host-side write access
to the parent directory of the session workspace. This ensures the workspace
directory entry cannot be replaced between validation and Docker mount.

If the agent has write access to the workspace parent directory, the TOCTOU
gap is exploitable. In that scenario, use system mode with `CAP_SYS_ADMIN`
for inode-pinned mounts (future implementation).

## Client interfaces

docker-helper exposes two first-class client interfaces:

### CLI

`docker-helper pull`, `build`, `run`, `registry login`.

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
Unix socket. In system mode, loopback HTTP on `127.0.0.1:52375` is also
available.

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
- never create or manage sessions unless the integration is explicitly running
  in an operator/admin context.

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

## Explicit non-goals for Release 1

Do not add the following merely to deliver agent integration:

- a second mandatory daemon or shared runtime;
- MCP server wrapping docker-helper;
- plugin/control-plane infrastructure;
- remote transport design;
- agent-specific logic in the daemon;
- separate client configuration unless real use demonstrates the need;
- a second client binary solely for architectural purity.

The smallest successful Release 1 integration is a stable daemon HTTP API, a
useful reference CLI, and reusable agent skills supporting both interfaces.