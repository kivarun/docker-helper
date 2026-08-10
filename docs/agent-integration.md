# Agent integration

## Release 1 goal

Release 1 should provide a first-class way for coding agents to use
docker-helper without requiring them to understand the HTTP transport,
Authorization headers, asynchronous operation polling, or incremental log
offsets.

The integration belongs at the client edge of the project. Agent-specific
behavior must not be added to the daemon core or change the daemon capability
contract.

## Client-facing CLI

The initial Release 1 integration uses the existing `docker-helper` binary as
both the operator/server CLI and the local client CLI.

The agent-facing capability commands are:

- `docker-helper pull`;
- `docker-helper build`;
- `docker-helper run`;
- `docker-helper registry login`.

`registry login` already exists. `pull`, `build`, and `run` are the next client
commands to add.

The client commands use the session token supplied by the launcher through
`DOCKER_HELPER_SESSION_TOKEN`. They must never expose the token in normal
output, diagnostics, or errors.

For the initial local integration, client commands talk to the Docker Helper
Unix socket. Remote endpoint discovery, TCP/TLS transport, and remote client
authentication are Release 2 concerns and are intentionally not designed here.

## Hide protocol mechanics from the agent

The daemon API remains the stable capability protocol, but normal agent use
should not require direct protocol handling.

In particular, `docker-helper build` and `docker-helper run` should present a
synchronous CLI experience even though the daemon executes them through the
asynchronous operation API. The client owns the transport lifecycle:

1. start the operation;
2. receive the operation ID;
3. poll status;
4. read incremental logs using offsets;
5. stream logs to the caller;
6. wait for a terminal result;
7. return a useful process exit status.

The agent should think in terms of `build` and `run`, not in terms of
`POST /build`, operation IDs, status polling, and `next_offset` bookkeeping.

`pull` remains synchronous in the daemon and is exposed directly as a normal
client command.

## Skills

After the client CLI is usable, ship reusable skills for at least:

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

Native agent-tool adapters are an experiment after the client CLI + skills are
dogfooded.

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
