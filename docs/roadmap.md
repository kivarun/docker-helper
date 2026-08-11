# Roadmap

## Release 1 goal

A stable standalone Docker capability for sandboxed agents, with:
- session-scoped authorization;
- workspace/path isolation;
- pull/build/run;
- audit and operational logging;
- local SQLite state;
- usable CLI/config/session management;
- installable/releasable artifacts;
- a first-class agent-facing integration.

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
- documentation cleanup (README, architecture, portable agent skill);
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
password prompt and `--password-stdin` flag. Audit events track login
attempts without exposing credentials.

### 4. Installation / service packaging

Finish the operator installation path.

Release 1 packaging is intentionally user-only:

- helper runs as the installing user;
- binary installs to `~/.local/bin/docker-helper`;
- systemd user unit installs to `~/.config/systemd/user/docker-helper.service`;
- generic release artifact is `tar.gz` with the binary, `install.sh`,
  `uninstall.sh`, user unit, and optional AppArmor integration;
- no native `.deb`/`.rpm` packages in Release 1;
- no system-wide/root daemon deployment in Release 1.

Installer direction:

- no root is required for the helper binary, user unit, init, or user service;
- interactive install should offer to continue directly into `docker-helper init`
  and then enable/start the systemd user service;
- installer checks Docker access but must not automatically add the user to the
  `docker` group or otherwise change Docker authorization;
- installer must not edit shell startup files automatically; if
  `~/.local/bin` is not visible in the current `PATH`, explain how to refresh
  the login environment;
- optional AppArmor host-policy installation/removal may explicitly request
  `sudo`, because it changes host security policy.

Uninstall direction:

- normal uninstall removes installed program/service files while preserving
  Docker Helper configuration, admin token, and state;
- purge uninstall removes configuration and state too;
- expose both an interactive purge question and a non-interactive `--purge`
  option;
- never remove broader parent directories or modify shell startup files.

Release 1 target environment is openSUSE and Ubuntu, plus the generic Linux
`tar.gz` installation path.

**Completed.** `install.sh` and `uninstall.sh` provide user-only installation
to `~/.local/bin/` with systemd user unit, optional AppArmor profile,
and `--yes`/`--purge` flags for non-interactive and hard-remove workflows.

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

**Completed.** Static Linux amd64 build (`build-static.sh`) and
release tarball bundling (`build-bundle.sh`) are implemented. The static
build uses `CGO_ENABLED=1` with musl-gcc (or gcc on Alpine) and
`-extldflags '-static'` for external static linking. Version is injected
via `-ldflags '-X main.version=<version>'`. The release bundle produces
`docker-helper-<version>-linux-amd64.tar.gz` containing the binary,
`install.sh`, `uninstall.sh`, systemd user unit, AppArmor profile,
and the agent skill. A release-specific README is included in the bundle.

Tag-driven GitHub Release workflow (`.github/workflows/release.yml`) is
implemented. Pushing a `v*` tag runs CI checks, builds the static bundle,
and creates a GitHub Release with the tar.gz asset. Prerelease tags
(e.g., `v1.0.0-rc1`) are automatically marked as prerelease.

### 6. Agent-facing integration / dogfood

Validate the API with a real coding agent integration to surface usability
issues before release.

**Completed.** Real OpenCode usage has exercised the helper throughout normal
agent workflows and directly driven usability fixes in async operations, CLI,
help/documentation, logging, and private-registry handling.

### 7. First-class agent integration

Ship a reusable agent-facing integration rather than requiring every deployment
to reproduce hand-written curl instructions.

**Completed:** reference CLI (`pull`, `build`, `run`,
`registry login`) with signal cancellation, synchronous UX, and log streaming.
Direct HTTP API with full async operation lifecycle.
Portable agent skill at `.claude/skills/docker-helper/SKILL.md` covering both
interfaces. OpenCode dogfood completed for both CLI and HTTP-only environments.

Native adapter is a subsequent experiment, implementing the same HTTP
capability contract.

Do not build a mandatory shared runtime or control plane around this integration.
The goal is discoverability and reliable use of docker-helper by agents while
keeping docker-helper standalone.

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
- use the supported agent integration;
- inspect logs/audit;
- reload configuration;
- session cleanup;
- restart service;
- verify version.

This is an end-to-end release acceptance pass, not another unit-test framework.

### 9. Final hardening and documentation

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
- multi-user daemon deployment;
- native `.deb`/`.rpm` packaging;
- distribution repository publishing;
- Unix man pages;
- Fedora/RHEL-specific distribution support;
- WebSocket/SSE log streaming unless polling proves insufficient.

## Post-1.0 candidates

Keep this short.

Include:

- richer log streaming if polling becomes insufficient;
- network/proxy capability as a separate tool/project;
- notification helper with restricted DBus access.

Do not design their APIs here.

## 2.0

### Main goal: remote build

Release 2 adds remote builds without turning docker-helper into a distributed
workspace or control plane.

The supported deployment remains single-owner and user-managed. One client is
configured for either the local Unix socket or one remote HTTPS endpoint.
Multiple helper contexts, routing, and helper-to-helper forwarding are outside
Release 2.

Remote-build scope:

- preserve the existing admin/session token model, session lifecycle, and async
  build operation lifecycle;
- require authenticated HTTPS for the remote endpoint with normal certificate
  validation; do not add an insecure-TLS mode;
- have the client assemble the Docker build context with `.dockerignore`
  semantics and stream it as tar;
- use one multipart build request with JSON metadata first and an
  `application/x-tar` context part second;
- do not introduce a separate upload resource or a second build-job lifecycle;
- build in the Docker daemon attached to the selected helper;
- keep the resulting image and build cache on that remote daemon;
- do not automatically export/download the image or push it to a registry.

Explicitly outside Release 2:

- remote `run`;
- mutable remote workspaces or bidirectional workspace synchronization;
- multi-helper selection or routing;
- system-service and multi-user deployment;
- native distribution packages and package repositories.

## 3.0

### Main goal: system distribution

Release 3 makes docker-helper a normally installable multi-user system service.
System deployment, the access model, and native packages are one architectural
block and should not be split into independent deliverables.

Expected scope:

- decide whether the daemon runs as root or under a dedicated service account;
- define system config, state, runtime, token, and socket paths;
- define local multi-user authentication and authorization;
- define Unix-socket ownership and permissions;
- authorize workspaces per user without widening one global `allowed_root` to
  all of `/home`;
- provide a systemd system unit and the operational hardening required by a
  packaged system daemon;
- provide native DEB and RPM packages;
- publish packages through selected repository/update channels so normal package
  manager install and upgrade workflows work;
- keep openSUSE and Ubuntu as important targets and select the exact RHEL-family
  target when implementation begins; Fedora is not currently committed;
- provide at least `docker-helper(1)` and `docker-helper-config(5)` manual
  pages.

Administrative operations may initially rely on `sudo`. Do not introduce a
separate administrative control plane without a demonstrated need.

## 4.0

### Main goal: full remote environment

Release 4 is the earliest stage for capabilities that turn remote build into a
full remote working environment:

- mutable remote workspace delivery and synchronization;
- remote `run`;
- multiple helper contexts and target selection;
- routing or optional helper-to-helper integration;
- richer asynchronous upload/job protocols if the one-request build upload
  proves insufficient;
- cancellation and recovery across interrupted uploads, connections, or daemon
  restarts;
- durable operation state and other deferred operational capabilities justified
  by real use.

Keep Release 4 use-case driven. Do not predesign these APIs while implementing
Release 2 or Release 3.

## Architectural constraints

- docker-helper is a capability service using Docker as a backend, not a
  restricted Docker API or socket proxy;
- one tool — one capability;
- standalone first;
- integration optional;
- standardize contracts, not mandatory shared runtime/code;
- keep remote/multi-session future possible;
- do not predesign future helpers;
- prefer the smallest implementation that solves a demonstrated problem.

See `docs/manifesto.md` for the project-level rationale behind these constraints.

## Documentation ownership

- `docs/manifesto.md` = project purpose, product boundary, and long-lived design
  principles;
- `docs/roadmap.md` = planned work and release scope;
- `docs/architecture.md` = current architecture/invariants/rationale;
- `README.md` = operator quickstart;
- `.claude/skills/docker-helper/SKILL.md` =
  canonical reusable instructions for agents using docker-helper;
- `AGENTS.md` = rules for agents developing docker-helper.
