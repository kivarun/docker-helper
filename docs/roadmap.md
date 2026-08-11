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

### 6. Agent-facing integration / dogfood

Validate the API with a real coding agent integration to surface usability
issues before release.

**Completed.** Real OpenCode usage has exercised the helper throughout normal
agent workflows and directly driven usability fixes in async operations, CLI,
help/documentation, logging, and private-registry handling.

### 7. First-class agent integration

Ship a reusable agent-facing integration rather than requiring every deployment
to reproduce hand-written curl instructions.

**Completed:** client-facing reference CLI (`pull`, `build`, `run`,
`registry login`) with signal cancellation, synchronous UX, and log streaming.
Real CLI dogfood completed.

Release 1 intentionally supports both:
- reference CLI;
- direct HTTP API.

Neither is deprecated or fallback. Reusable agent skills should cover both
interfaces, since the presence of the `docker-helper` binary in the agent
image is not guaranteed.

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
- durable/recoverable operations across daemon restart;
- network/proxy capability as a separate tool/project;
- notification helper with restricted DBus access.

Do not design their APIs here.

## 2.0

### Main goal: remote operation

The defining goal of Release 2 is remote/server-side access to docker-helper.
System-level deployment and multi-user support are enabling steps toward that
goal, not separate end goals.

Core remote work includes:

- remote transport and network exposure;
- authentication and authorization for remote clients;
- remote session semantics;
- preserving the narrow policy-enforcing security boundary when the client and
  helper no longer share the same local user/session context.

Keep the exact remote API and security model intentionally undesigned until
Release 2 work begins.

### System deployment and multi-user foundation

Add a system-service deployment mode as a foundation for remote operation.
Do not treat a root unit as a mechanical variant of the Release 1 user unit.

Expected scope:

- decide whether the system daemon should run as root or under a dedicated
  service account;
- multi-user client access;
- formal user/system deployment scopes;
- system config/state/runtime paths and systemd system unit;
- explicit local Unix-socket ownership/permission model for clients;
- workspace authorization suitable for multiple users rather than widening one
  global `allowed_root` to all of `/home`;
- administrative operations may initially rely on `sudo`; do not introduce a
  separate administrative control plane unless a demonstrated need appears.

Do not predesign the exact multi-user authorization API during Release 1.

### Distribution packaging, delivery, and platform expansion

Move native distribution packaging and repository delivery out of Release 1.
Release 2 should make docker-helper behave like a normal system package, not
merely produce `.deb` and `.rpm` files as CI artifacts.

Expected scope:

- native `.deb` packaging;
- native `.rpm` packaging;
- publish packages through appropriate selected distribution/package-repository
  channels so normal package-manager install and upgrade workflows work;
- openSUSE and Ubuntu remain important targets;
- RHEL-family support is the likely RPM enterprise target rather than Fedora;
- exact RHEL-family target(s), publication channels, and distro-specific
  security integration should be selected when this work starts.

Fedora is not currently a committed target.

### Unix manual pages

Provide proper system documentation as part of the native/system package
experience.

At minimum:

- `docker-helper(1)` for CLI/operator usage;
- `docker-helper-config(5)` for configuration format and semantics.

Add further sections only when the actual installed interfaces justify them.

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

## 3.0+

Development after 2.0 is explicitly use-case driven. Do not invent a generic
platform roadmap in advance. New capabilities should be justified by observed
operator/agent workflows; a demonstrated use case from a single real operator
is sufficient evidence to investigate a problem.

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
- `docs/agent-instructions.md` = instructions for agents using docker-helper;
- `AGENTS.md` = rules for agents developing docker-helper.
