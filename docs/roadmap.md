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
- admin/session two-token authentication (SHA-256; admin token uses
  constant-time compare, session tokens use database lookup);
- canonical workspace containment (`pathWithin`, `pathStrictlyWithin`);
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

- the helper binary, init, and user service do not themselves require root;
- host preparation may require `sudo`, for example AppArmor policy installation
  or granting the user Docker access/group membership;
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
- notification helper with restricted DBus access;
- immediate re-evaluation/revocation of already-issued sessions after Principal
  credential revocation or allowed-root changes only if real use demonstrates a
  need. Principal disable/delete already removes that principal's sessions.

Do not design their APIs here.

## 2.0

### Main goal: normally installable local multi-user deployment

Release 2 preserves the Release 1 user deployment and adds a local system
deployment. Both modes use the same binary and HTTP capability API.

Implemented contract:

- user mode uses XDG paths and a private per-user Unix socket;
- system mode runs as root, serves explicit principals, and uses a system Unix
  socket plus configurable loopback HTTP (`127.0.0.1:52375` by default);
- transport does not establish identity; admin-token, Principal-credential, and session-token
  capabilities establish authorization;
- operator commands select the existing user socket first and otherwise the
  system socket, together with the matching token source; explicit
  `--system`, `--endpoint`, and `--token-file` overrides remain available;
- principal UID/GID/home are resolved by the daemon, each principal starts with
  its home as an allowed root, and multiple Principal credentials are supported;
- `credential install` stores the Principal credential token for non-root system clients;
- `credential create --name` defaults to `default`;
- root initialization defaults to `/home` and may explicitly accept `/home` or
  `/opt`; non-root initialization defaults to the current user's home;
- system-mode containers run as the authenticated principal UID:GID;
- exactly one supported MAC backend is mandatory in system mode: AppArmor or
  enforcing SELinux;
- native DEB/RPM packages contain both user- and system-mode deployment assets;
   DEB targets Ubuntu; RPM is validated against openSUSE Tumbleweed and carries
   both AppArmor and SELinux runtime toolchain dependencies;
   the release tarball installs user mode normally and requires explicit
   `install-system.sh` for system mode;
- native packages and release artifacts include Bash completion and manuals;
- trusted CA injection is configured through `trusted_ca_path` and
  `trusted_ca_injection=auto`. In system mode, the CA source must be
  under `/etc/docker-helper`; user mode accepts arbitrary absolute paths.
  Managed CA import and broader source-location support are post-Release-2.

Release 2 remains local. Non-loopback listeners, TLS, uploaded build contexts,
and remote image-only runs are deferred to Release 3.

Outstanding work is stabilization and release acceptance, not capability
expansion: finish the naming and abstraction cleanup identified by the
[project-wide review](project-wide-naming-architecture-review-2026-08-24.md),
complete the consolidated regression review of the fixes recorded in
[`docs/release-2-audit-2026-08-21/`](release-2-audit-2026-08-21/), finish
package lifecycle and cross-distribution SELinux/AppArmor UAT, and reconcile
the final support matrix.

Explicitly outside Release 2:

- remote execution and mutable workspace delivery;
- multiple helper contexts, routing, or helper-to-helper forwarding;
- host port publishing and generic Docker network configuration;
- durable operation recovery across daemon restarts;
- dynamic revocation/re-evaluation of issued sessions after Principal-credential
  revocation or allowed-root changes; principal disable/delete already removes
  that principal's sessions;
- termination of started operations solely because a session expires or is
  deleted;
- dedicated unprivileged service-account architecture.

## 3.0

### Main goal: remote execution

Release 3 is the earliest stage for non-loopback and remote capabilities:

- explicit TLS identity and non-loopback transport policy;
- uploaded or streamed build contexts;
- image-only remote runs before mutable workspace synchronization;
- mutable remote workspace delivery only when a concrete use case justifies it;
- multiple contexts, target selection, and optional routing;
- cancellation and recovery across interrupted uploads/connections;
- durable operation state where demonstrated by use;
- host port publishing only under explicit server-side policy.

Release 3 planning includes a proposed delegated Launcher model between a
Principal and its Sessions. Launcher becomes the stable Session/runtime owner;
credentials remain rotatable authentication keys, and Launcher roots add an
optional authorization ceiling without owning MAC state. The agreed concept,
security trade-offs, defaults, and expected CLI/HTTP/database/test changes are
recorded in
[`docs/release-3-launcher-delegation.md`](release-3-launcher-delegation.md).

Keep Release 3 use-case driven; do not predesign these APIs during Release 2
stabilization.

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
