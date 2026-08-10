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
- build_args for POST /build (name validation, sorted, audit keys only);
- shm_size for POST /run (Release 1 hard limit 2 GiB, parsed binary units);
- config CLI (`show`, `set`, `unset`) and runtime reload;
- audit logging (stdout, JSONL) and operational logging (stderr, slog JSONL);
- SQLite session state;
- session expiration enforcement (`expires_at` check on every request);
- startup expired-session cleanup + `docker-helper session cleanup` CLI;
- strict single-document JSON request decoding (`decodeJSONRequest`);
- async build/run with operation lifecycle (status, logs, cancel);
- global bounded shutdown lifecycle (one absolute deadline, concurrent drain
  + operation termination, force cleanup);
- developer rules in root `AGENTS.md`;
- documentation cleanup (README, architecture, agent instructions);
- version source prepared for ldflags release injection (`var version = "dev"`);
- image-reference syntax delegated to Docker (no home-grown regex);
- private-registry authentication (`POST /registry/login`, per-session
  Docker config, CLI `registry login` with interactive password prompt).

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

**Completed.** Async operation lifecycle, status polling, incremental logs,
and cancel are implemented.

### 2. Shutdown timeout

`shutdown_timeout` is configurable (default 30s). Shutdown direction:

- stop accepting new operations;
- HTTP drain and operation termination share one overall shutdown deadline;
- build CLI receives graceful cancellation, with bounded forced termination
  fallback;
- running run containers receive daemon-side kill, with force removal as
  fallback;
- cleanup failures are logged but must not hang shutdown indefinitely.

**Completed.** Global bounded shutdown lifecycle with one absolute deadline,
concurrent drain + operation termination, and force cleanup is implemented.

### 3. Private-registry authentication

Agents need to build from and run images from private registries.

**Completed.** `POST /registry/login` authenticates per-session using
a session-scoped Docker config directory. Credentials are isolated per
session and cleaned up on session delete. CLI supports interactive
password prompt and `--password` flag. Audit events track login
attempts without exposing credentials.

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

### 6. Agent-facing integration / dogfood

Validate the API with a real coding agent integration to surface usability
issues before release.

### 7. Clean-install acceptance test

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

### 8. Final hardening and documentation

Address any remaining edge cases, race conditions, or documentation gaps
discovered during integration testing and acceptance.

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