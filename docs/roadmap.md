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

`pull` remains synchronous in Release 1.

`build` and `run` use an async operation lifecycle:

- start a Docker operation and receive an `operation_id`;
- query operation status later;
- retrieve accumulated operation output/logs using polling;
- obtain final result:
  - success/failure;
  - exit code where applicable;
  - duration;
  - Docker output/result metadata.

**Operation registry is in-memory.** No SQLite operation persistence in Release 1.

**Restart recovery is outside Release 1.** Running operations do not need to
survive daemon restart. Durable/recoverable operations may be considered in
2.0 or later if needed; this is not currently a committed 2.0 feature.

### 2. Log ownership

- **build:** helper-owned bounded in-memory log buffer;
- **run:** Docker-owned logs via detached container + `docker logs`.

### 3. Operation lifecycle

- minimum operation states: `running`, `succeeded`, `failed`;
- container non-zero exit is a successfully executed `run` operation with a
  non-zero exit code;
- Docker/launch failure is an operation failure;
- session expiry/deletion does not terminate an already-started operation;
- later operation access still requires the owning valid session;
- no `cancelled` state;
- client-initiated cancellation remains outside Release 1 unless a concrete
  need appears.

### 4. Shutdown ownership

docker-helper must not intentionally leave helper-owned active operations
running after normal daemon shutdown.

Shutdown direction:

- stop accepting new operations;
- HTTP drain and operation termination share one overall shutdown deadline;
- build CLI receives graceful cancellation, with bounded forced termination
  fallback;
- running run containers receive graceful Docker stop, with force removal as
  fallback;
- retained completed run containers are removed before registry destruction;
- cleanup failures are logged but must not hang shutdown indefinitely.

The overall graceful-shutdown budget should become a configurable configuration
field. The current 30-second default is retained for now.

### 5. Process lifetime hardening

Do this after the operation model exists, because process ownership depends on it.

Revisit:

- request/process context ownership;
- cancellation;
- shutdown behavior for running Docker processes;
- timeout policy;
- bounded output/log storage;
- concurrency limits if demonstrated necessary.

Do not implement generic worker pools or schedulers without a concrete requirement.

### 6. Installation / service packaging

Finish the operator installation path.

Include:

- final systemd user service;
- installation locations;
- config/state/runtime path behavior;
- binary installation/update story.

Release 1 remains user-service oriented.
Do not expand to system-wide/root daemon deployment unless separately decided.

### 7. Release build and GitHub release

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

### 8. Clean-install acceptance test

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
- durable/recoverable operations across daemon restart;
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