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

`shutdown_timeout` is configurable (default and maximum 30s; the budget must
fit inside the shipped systemd `TimeoutStopSec=45s`). For Release 1 upgrade
compatibility, persisted values above 30s load but are bounded to 30s with a
warning; `config set` still rejects new values above 30s. Shutdown direction:

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
  `trusted_ca_injection=auto`. `trusted_ca_path` is an absolute path to the
  accepted CA file. In user mode any readable absolute path works. In system
  mode the confined daemon must also be permitted to read the source under the
  active MAC backend, so the supported locations are the helper-owned
  `/etc/docker-helper` config tree and the system CA-bundle paths the shipped
  AppArmor/SELinux policy permits; paths outside that policy are the operator's
  responsibility to make readable under the active MAC policy. Managed CA
  import and broader source support are post-Release-2.

Release 2 remains local. Non-loopback listeners, TLS, uploaded build contexts,
and remote image-only runs are deferred to Release 4 or later and remain
use-case driven.

Release 2 implementation workstreams are complete. The naming/architecture
review findings required for Release 2 are closed, the consolidated regression
review is complete, DEB/RPM/tarball lifecycle and enforcing AppArmor/SELinux
UAT are covered by the release gate, and the Release-2 support matrix is
settled. The remaining action is final validation and publication of the stable
release. See [`docs/release-2-plan.md`](release-2-plan.md) and its closure
record rather than a per-item history here.

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

## 2.1

### Main goal: delegated Launcher ownership and default-driven control-plane flows

Release 2.1 is a short, incremental control-plane release after 2.0. It adds
one stable ownership and delegation level between Principal and Session:

- a Principal remains the OS execution identity and authorization ceiling;
- a Launcher becomes the stable Session/runtime owner beneath one Principal;
- Principal and Launcher credentials remain rotatable authentication keys, not
  resource owners;
- Launcher scope inherits or narrows Principal allowed roots without owning MAC
  state;
- existing Session, operation, runtime, and MAC lifecycle owners are extended
  rather than duplicated.

Release 2.1 also provides default-driven control-plane flows for common
Principal, Launcher, credential, and Session operations. These flows are
deterministic compositions of the same public operations and ownership rules:
documented defaults and implicit owner resolution remove routine choices, but
they do not create a workflow engine, scheduler, persisted pipeline, or
separate automation subsystem.

For example, Session creation authenticated by a Principal credential resolves
that Principal's `default` Launcher when no Launcher is selected explicitly; an
admin can name a Principal and resolve that Principal's `default` Launcher.
Explicit authorized selectors remain available when the default is not desired.

Release 2.1 also includes a small operator-UX parity item for mandatory-access
control diagnostics: add `docker-helper selinux check` as the SELinux-side
counterpart to the existing `docker-helper apparmor check`. This command is
diagnostics only; it must not select the active MAC backend or create a second
runtime authority. Backend selection and fail-closed system-mode enforcement
remain owned by the existing backend-neutral MAC detection/confinement path.

These flows do not add desired state, managed-container lifecycle, restart
policy, interactive exec, networking, port publishing, or resource-limit
semantics.

The binding concept, migration direction, and expected CLI/HTTP/database/test
work are recorded in
[`docs/release-2.1-launcher-delegation.md`](release-2.1-launcher-delegation.md).

### Post-2.0 validation and hardening follow-ups

Recorded for Release 2.1 after the stable v2.0.0 is published. None of these
change the Release-2 gate or the already-defined Launcher ownership model above.

- **Packaging integration tests / CI tooling.** Several packaging-oriented Go
  tests currently skip when `nfpm`/`checkpolicy`/`semodule_package`/`musl-gcc`
  are unavailable in the Go-test jobs. Release 2 product correctness is already
  covered by exact-artifact package UAT, so the Release-2 CI workflow is not
  changed here. For 2.1: remove the "green by skip everywhere" ambiguity — either
  provide the required tooling to an appropriate Go integration-test job or
  establish a dedicated packaging integration-test job — while preserving
  end-to-end exact-artifact UAT as the authoritative package proof and without
  turning environment skips into unconditional failures on ordinary developer
  machines.
- **Upgrade baseline fixture lifecycle.** The rc.22 incident showed that a
  pinned SHA protects integrity but GitHub Release asset availability is still
  an external availability dependency. For 2.1: replace the rc.22-specific
  naming with an explicit "upgrade baseline fixture" abstraction; use the
  released stable v2.0.0 as the natural baseline for testing upgrades to 2.1
  candidates; keep exact artifact hashes pinned and verified before
  installation; define a durable availability/recovery strategy for the
  canonical baseline bytes; do not rebuild historical baseline bytes privately;
  and do not make `rc.22` a permanent architectural concept.
- **`trusted_ca_path` confined preflight / diagnostics.** For 2.1 investigate
  operator diagnostics/preflight that can detect likely system-mode MAC
  readability problems earlier, especially when changing config while the
  daemon is stopped. This is diagnostics only: it must not create a second
  MAC-policy authority; backend selection/enforcement remains owned by the
  existing backend-neutral MAC path.
- **X.509/OpenSSL subject-hash independent verification.** For 2.1 add
  independent verification of the custom subject-name canonicalizer: a
  differential corpus generated/verified against supported OpenSSL versions;
  include difficult names (multi-valued RDNs, whitespace, non-ASCII, and
  T61/BMP/Universal strings where applicable); add a fuzz target around the
  DER/subject parsing boundary. Production runtime must not gain an `openssl`
  executable dependency merely to satisfy the test.
- **Minor historical-document hygiene** may be cleaned during 2.1 when touching
  those documents, but is not Release-2 work.

The larger test/package architectural debt stays out of 2.1 and remains later
architectural/test work, especially before or with Release 3: package-main
decomposition; splitting the large `packaging_test.go` architecture; broad
conversion of source-text cross-language assertions; and global test-suite
consolidation/parallelization.

## 3.0

### Main goal: managed-container runtime

Release 3 is reserved for the larger runtime architecture:

- managed containers with explicit create, start, stop, restart, inspect, and
  logs operations;
- synchronous non-interactive exec with bounded direct output;
- interactive exec over WebSocket;
- per-Session networking;
- narrow Launcher-governed port publishing for deliberate external exposure;
- explicit CPU, memory, and related resource limits.

A managed container is not desired state. Release 3 does not add automatic
recovery, reconciliation, or restart-policy semantics.

Begin Release 3 with binding lifecycle, ownership, API, failure, cleanup, and
compatibility contracts. Do not let implementation convenience create a second
runtime owner beside the existing Session/operation lifecycle.

Release 3 foundation documents:

- [`release-3-scope.md`](release-3-scope.md) — binding scope and exclusions;
- [`release-3-decomposition.md`](release-3-decomposition.md) — work packages and dependencies;
- [`release-3-operation-model.md`](release-3-operation-model.md) — durable execution contract;
- [`release-3-managed-container-domain.md`](release-3-managed-container-domain.md) — identity, ownership, and lifetime;
- [`release-3-vocabulary-and-implementation-map.md`](release-3-vocabulary-and-implementation-map.md) — canonical terms and the current-to-target code map.

## 4.0 / use-case driven

Remote capabilities remain a later, separate architecture problem:

- explicit TLS identity and non-loopback transport policy;
- uploaded or streamed build contexts;
- image-only remote runs before mutable workspace synchronization;
- mutable remote workspace delivery only when a concrete use case justifies it;
- multiple contexts, target selection, and optional routing;
- cancellation and recovery across interrupted uploads or connections;
- durable operation state where demonstrated by use.

Do not let remote transport dictate the local Launcher ownership model.

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
