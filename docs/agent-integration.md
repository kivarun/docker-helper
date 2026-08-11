# Agent integration

## Release 1 goal

Release 1 provides a first-class way for coding agents to use
docker-helper without requiring them to understand the HTTP transport,
Authorization headers, asynchronous operation polling, or incremental log
offsets.

The integration belongs at the client edge of the project. Agent-specific
behavior must not be added to the daemon core or change the daemon capability
contract.

## Client-facing reference CLI

The `docker-helper` binary is the reference client for the daemon capability
contract. It is the same binary that provides operator commands (serve, init,
reload, session, config).

The agent-facing capability commands are:

- `docker-helper pull`;
- `docker-helper build`;
- `docker-helper run`;
- `docker-helper registry login`.

The client commands use the session token supplied by the launcher through
`DOCKER_HELPER_SESSION_TOKEN`. They must never expose the token in normal
output, diagnostics, or errors.

For the initial local integration, client commands talk to the Docker Helper
Unix socket. Remote endpoint discovery, TCP/TLS transport, and remote client
authentication are Release 2 concerns and are intentionally not designed here.

## External integration options

External tooling has two options, both at the client edge:

a) Invoke the reference CLI (`docker-helper pull`, `build`, `run`, `registry login`).
b) Implement a native/direct adapter to the same daemon API.

Both approaches use the same capability contract. The daemon semantics remain
identical regardless of which client is used.

The CLI is not a second API. It is the reference implementation of the client
edge for the existing daemon API.

## CLI lifecycle

`docker-helper build` and `docker-helper run` present a synchronous CLI
experience even though the daemon executes them asynchronously. The CLI hides:

- async operation ID and polling;
- incremental log offsets;
- status polling loop.

The CLI streams operation logs to stdout/stderr and waits for a terminal
result. Container non-zero exit is propagated as the CLI exit code.

Signal cancellation:

- SIGINT -> best-effort cancel + exit 130;
- SIGTERM -> best-effort cancel + exit 143;
- cancel failure prints a diagnostic but does not replace the signal exit status.

`pull` remains synchronous in the daemon and is exposed directly as a normal
client command.

## Skills

The CLI is completed and dogfooded. Reusable agent skills remain Release 1
work for at least:

- OpenCode;
- Claude Code.

A skill should teach the agent the capability-level workflow and security
rules, not reproduce the full HTTP API reference. The expected primary path is
the client CLI above.

Skills must preserve these invariants:

- never invoke Docker directly as a fallback;
- never access `docker.sock`;
- never expose `DOCKER_HELPER_SESSION_TOKEN`;
- never look for the administrative token;
- never create or manage sessions unless the integration is explicitly running
  in an operator/admin context.

## Native tools

Native agent-tool adapters are a subsequent experiment after the CLI + skills
are dogfooded.

Implement at least one native adapter and compare it with the CLI + skill path
on real agent tasks. Keep native tools only if they provide a demonstrated
reliability or usability improvement beyond the portable client interface.

If native adapters are retained, they should be thin wrappers over the same
client-facing capability contract rather than independent implementations of
the Docker Helper protocol.

OpenCode-specific or Claude-specific code belongs in these adapters, not in the
daemon core.

## Curl fallback

Direct `curl` access to the Unix-socket HTTP API remains supported and
documented as:

- a protocol-level fallback;
- a diagnostic path;
- a way to exercise or debug the daemon independently of higher-level client
  integrations.

Curl is not the preferred normal agent UX once the client commands are
available. It must obey the same token-handling and no-direct-Docker rules.

`docs/agent-instructions.md` remains the detailed protocol reference and curl
fallback documentation.

## Explicit non-goals for Release 1

Do not add the following merely to deliver agent integration:

- a second mandatory daemon or shared runtime;
- MCP server wrapping docker-helper;
- plugin/control-plane infrastructure;
- remote transport design;
- agent-specific logic in the daemon;
- separate client configuration unless real use demonstrates the need;
- a second client binary solely for architectural purity.

The smallest successful Release 1 integration is one existing binary with a
useful client CLI, reusable skills, and the existing HTTP/curl interface as a
fallback.
