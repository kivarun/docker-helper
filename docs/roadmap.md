# Roadmap

## Release 1 goal

A stable standalone Docker capability for sandboxed agents, with:
- session-scoped authorization;
- workspace/path isolation;
- pull/build/run;
- audit and operational logging;
- local SQLite state;
- usable CLI/config/session management;
- installable/releasable artifacts.

docker-helper remains a narrow policy-enforcing daemon, not a generic agent control plane.

## Already completed

Verified against current implementation:

- Unix-socket HTTP service (`docker-helper serve`, 0600 permissions);
- admin/session two-token authentication (SHA-256, constant-time compare);
- canonical workspace containment (`EvalSymlinks`, `isInside`);
- mount validation and symlink escape protection;
- environment policy (name validation, sorted, values never logged);
- pull/build/run endpoints;
- config CLI (`show`, `set`, `unset`) and runtime reload;
- audit logging (stdout, JSONL) and operational logging (stderr, slog JSONL);
- SQLite session state;
- session expiration enforcement (`expires_at` check on every request);
- startup expired-session cleanup + `docker-helper session cleanup` CLI;
- strict single-document JSON request decoding (`decodeJSONRequest`);
- graceful shutdown with 30-second drain timeout;
- developer rules in root `AGENTS.md`;
- documentation cleanup (README, architecture, agent instructions);
- version source prepared for ldflags release injection (`var version = "dev"`);
- image-reference syntax delegated to Docker (no home-grown regex).

## Release 1 blockers

### 1. Async Docker operation model

Current pull/build/run execution is synchronous and ties the HTTP request lifetime
to the Docker subprocess.

Release 1 should move long-running Docker execution to an operation model.

Required capabilities to design and implement:

- start a Docker operation and receive an `operation_id`;
- query operation status later;
- retrieve accumulated operation output/logs using polling;
- obtain final result:
  - success/failure;
  - exit code where applicable;
  - duration;
  - Docker output/result metadata.

Do not predefine database schema in the roadmap.

First define the API/lifecycle contract, then choose the minimum state storage
required.

### 2. Operation lifecycle contract

This is the next design task, not something to invent casually in this roadmap.

The contract must decide:
- operation states;
- whether pull/build/run all share the same lifecycle;
- retention of completed operations/logs;
- behavior after daemon restart;
- relationship between session lifetime and operation lifetime;
- behavior when a session is deleted while an operation is running;
- cleanup semantics.

Cancellation must be listed as an explicit design decision:
- determine during operation-lifecycle design whether it is required for 1.0;
- do not assume a cancel endpoint until the lifecycle contract is agreed.

### 3. Process lifetime hardening

Do this after the operation model exists, because process ownership depends on it.

Revisit:
- request/process context ownership;
- cancellation;
- shutdown behavior for running Docker processes;
- timeout policy;
- bounded output/log storage;
- concurrency limits if demonstrated necessary.

Do not implement generic worker pools or schedulers without a concrete requirement.

### 4. Installation / service packaging

Finish the operator installation path.

Include:
- final systemd user service;
- installation locations;
- config/state/runtime path behavior;
- binary installation/update story.

Release 1 remains user-service oriented.
Do not expand to system-wide/root daemon deployment unless separately decided.

### 5. Release build and GitHub release

Add minimal release automation:

- tag-driven release build;
- normal CI checks before artifacts;
- inject release version through:

      -ldflags "-X main.version=<release-version>"

- source default remains:

      var version = "dev"

- produce downloadable release artifacts;
- create GitHub Release from the tag.

Git tag/release tag should be the authoritative release version source.

Do not introduce generated version files.

### 6. Clean-install acceptance test

Before 1.0, test the project as a new operator would use it:

- obtain release artifact;
- install;
- init;
- configure;
- start via systemd user service;
- create session;
- pull;
- build;
- run;
- inspect logs/audit;
- reload configuration;
- session cleanup;
- restart service;
- verify version.

This is an end-to-end release acceptance pass, not another unit-test framework.

## Explicitly not required for Release 1

Record these so they do not accidentally expand Release 1 scope:

- generic host-command execution;
- network/proxy helper;
- secrets helper;
- notification helper;
- shared mandatory toolbox runtime;
- general control plane;
- remote/server API redesign;
- schema migration framework without a real migration;
- periodic/background expired-session cleanup;
- DB VACUUM/maintenance framework;
- generic retry subsystem;
- system-wide/root daemon deployment;
- WebSocket/SSE log streaming unless polling proves insufficient.

## Post-1.0 candidates

Keep this short.

Include:
- evaluate cancellation if not included in 1.0;
- richer log streaming if polling becomes insufficient;
- remote/server-side deployment work;
- network/proxy capability as a separate tool/project;
- notification helper with restricted DBus access;
- packaging improvements.

Do not design their APIs here.

## 2.0

### Database doctor / maintenance CLI

Future administrative command, exact name TBD (`db doctor` or similar).

Possible scope:
- database integrity diagnostics;
- database size/statistics;
- maintenance recommendations;
- explicit VACUUM/optimization;
- safe database maintenance operations.

Do not define the command/API now.
`session cleanup` remains a narrow expired-session command and is not replaced by
this future feature.

## Architectural constraints

- one tool — one capability;
- standalone first;
- integration optional;
- standardize contracts, not mandatory shared runtime/code;
- keep remote/multi-session future possible;
- do not predesign future helpers;
- prefer the smallest implementation that solves a demonstrated problem.

## Documentation ownership

- `docs/roadmap.md` = planned work and release scope;
- `docs/architecture.md` = current architecture/invariants/rationale;
- `README.md` = operator quickstart;
- `docs/agent-instructions.md` = instructions for agents using docker-helper;
- `AGENTS.md` = rules for agents developing docker-helper.
