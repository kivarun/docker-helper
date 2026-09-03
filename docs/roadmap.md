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
control diagnostics: `docker-helper selinux check` (implemented) is the
SELinux-side counterpart to the existing `docker-helper apparmor check`. It is
diagnostics only: it validates that the `docker_helper` policy module is loaded
and that docker-helper-owned file contexts are consistent with the active
policy, requires root, is strictly read-only, and never selects the active MAC
backend or creates a second runtime authority. Backend selection and
fail-closed system-mode enforcement remain owned by the existing
backend-neutral MAC detection/confinement path (`detectLSM`).

These flows do not add desired state, managed-container lifecycle, restart
policy, interactive exec, networking, port publishing, or resource-limit
semantics.

The binding concept, migration direction, and expected CLI/HTTP/database/test
work are recorded in
[`docs/release-2.1-launcher-delegation.md`](release-2.1-launcher-delegation.md).

### Post-2.0 validation and hardening follow-ups

Recorded for Release 2.1 after the stable v2.0.0 is published. None of these
change the Release-2 gate or the already-defined Launcher ownership model above.

- **Packaging integration tests / CI tooling (implemented).** The "green by
  skip everywhere" ambiguity is removed on main via a settled fail-closed
  model: a dedicated `packaging-integration` CI job provides the full required
  packaging toolchain and runs exactly the packaging integration tests
  (`scripts/test-packaging-integration.sh`) with
  `DOCKER_HELPER_PACKAGING_INTEGRATION=1`, so a missing required packaging tool
  is a hard failure there; ordinary developer `go test ./...` keeps skipping
  environment-dependent packaging tests when tooling is absent. The pinned nFPM
  identity has one source owner (`scripts/install-nfpm.sh`), consumed by both
  the artifact gate and the packaging-integration job. Exact-artifact UAT
  remains the authoritative package acceptance proof; CI and UAT are separate
  proof layers.
- **Upgrade baseline fixture lifecycle (implemented).** The rc.22 incident
  showed that a pinned SHA protects integrity but GitHub Release asset
  availability is still an external availability dependency. This is resolved
  on main: the rc.22-specific naming is replaced by an explicit "upgrade
  baseline fixture" abstraction
  (`scripts/uat-upgrade-baseline-fixture.sh`), which is the single owner of the
  baseline version, DEB/RPM URLs and pinned SHA-256s; the released stable
  v2.0.0 is the natural baseline for testing upgrades to 2.1 candidates; exact
  artifact hashes are pinned and verified before installation; and a durable
  availability/recovery strategy (optional explicit local PATH or URL source
  overrides that must still contain the same exact bytes, fail-closed, with
  pinned hashes never overridable) covers the canonical baseline bytes. The
  baseline package is never rebuilt privately, mutable release metadata is
  never trusted, and `rc.22` is not a permanent architectural concept.
- **`trusted_ca_path` confined preflight / diagnostics (implemented).**
  In system mode with the daemon stopped, a successful config mutation that
  changes an active trusted-CA configuration (`trusted_ca_injection=auto`)
  persists the validated config and prints a warning to stderr that the CA
  file was validated but confined MAC readability cannot be verified until
  daemon startup, and that startup fails closed if the source is not readable
  under the active MAC policy. The warning is stderr-only; the successful
  stdout contract is unchanged. When the daemon is running, reload under
  confinement remains the authoritative proof, and reload/CA-preparation
  failures still roll back. This is diagnostics only: it does not create a
  second MAC-policy authority; backend selection/enforcement remains owned by
  the existing backend-neutral MAC path.
- **X.509/OpenSSL subject-hash independent verification (implemented).**
  The custom `computeOpenSSLSubjectHash` canonicalizer is verified against the
  independent `openssl x509 -hash -noout` oracle. A checked-in semantic
  differential corpus (`ca_subject_hash_openssl_test.go`) covers simple and
  multi-valued RDNs, ASCII case folding and all six whitespace classes, string
  encodings (Printable/UTF8/IA5/T61/BMP/Universal including non-BMP), Unicode
  edge behavior (non-ASCII next to ASCII uppercase, NBSP not treated as ASCII
  whitespace), multi-valued RDN SET OF ordering in both input orders,
  NumericString non-canonicalization, DER length boundaries (127/128/long
  form), and empty values; expected hashes were generated independently with
  OpenSSL and never by the implementation. A required-mode live differential
  test (`DOCKER_HELPER_OPENSSL_DIFFERENTIAL=1`, fail-closed) proves a three-way
  match (checked-in oracle == live OpenSSL == implementation) against the
  OpenSSL 3.x shipped on CI Ubuntu 24.04 in the dedicated
  `x509-openssl-differential` CI job. VisibleString is excluded from the
  differential corpus because OpenSSL 3.5.x's `openssl x509` refuses to load a
  certificate whose subject is an ISO646String; it remains covered at unit
  level. The fuzz target
  `FuzzComputeOpenSSLSubjectHashRawSubject` hardened the raw-subject
  parser/canonicalizer: hostile declared DER lengths previously caused
  slice-bounds panics in `parseX509RawSubject`, now fixed with bounds checks
  (plus a length-overflow guard in `parseDERLength`) and a permanent regression
  seed. Production runtime has no `openssl` executable dependency; the external
  oracle is test-only.
- **Minor historical-document hygiene (implemented).** Stale current-state
  statements found while touching the SELinux design record were corrected:
  the OpenSSL subject-hash section now reflects the settled checked-in corpus /
  live differential CI / fuzzing / DER bounds-hardening state, and the
  packaging section now reflects the canonical producer installing the SELinux
  compilation tools through the shared Ubuntu platform provisioning path.
  Dated audit claims (for example that Release 2 had no `docker-helper selinux
  check`) are preserved as historical truth. Release-3 documentation debt is
  out of scope.

The larger test/package architectural debt stays out of 2.1 and remains later
architectural/test work, especially before or with Release 3: package-main
decomposition; splitting the large `packaging_test.go` architecture; broad
conversion of source-text cross-language assertions; and global test-suite
consolidation/parallelization.

## 3.0

### Main goal: managed-container runtime

Release 3 is reserved for the larger runtime architecture:

- managed containers with explicit create, list, show, start, stop, restart,
  remove, administrator policy repair, and bounded log-snapshot operations;
- synchronous non-interactive exec with bounded direct output;
- interactive exec over WebSocket;
- per-Session networking;
- narrow Launcher-governed TCP port publishing on host IPv4 loopback;
- explicit CPU, memory, and related resource limits.

Release 3 uses the Docker Engine API behind a docker-helper-owned backend
boundary. Workload output remains a bounded direct client result and is not
copied into daemon logs, audit, or journald.

Managed-container creation is synchronous and returns a stopped container with
its effective Session-local name and DNS alias. State-changing start, stop,
restart, remove, administrator policy repair, and Session cleanup use the
durable Operation model; an already-satisfied start or stop is a synchronous
no-op, while removal of an already-missing backend cleans the persistent record
synchronously. Build, one-shot run, and non-interactive exec remain
synchronous; interactive exec uses WebSocket and ends when expiration cleanup
removes its owning container.

A managed container is not desired state. Release 3 adds a fixed
once-per-minute read-only integrity scan, but no automatic workload recovery,
repair, adoption, diagnostic-triggered deletion, reconciliation, or
restart-policy semantics. Explicit closure and Session TTL expiration remain
the ownership-lifecycle exception and automatically remove resources whose
Session ownership is proven.

Begin Release 3 with binding lifecycle, ownership, API, failure, cleanup, and
compatibility contracts. Do not let implementation convenience create a second
runtime owner beside the existing Session/operation lifecycle.

Release 3 foundation documents:

- [`release-3-scope.md`](release-3-scope.md) — binding scope and exclusions;
- [`release-3-decomposition.md`](release-3-decomposition.md) — work packages and dependencies;
- [`release-3-operation-model.md`](release-3-operation-model.md) — durable execution contract;
- [`release-3-d0-execution-plan.md`](release-3-d0-execution-plan.md) — Operation foundation and synchronous-command migration plan;
- [`release-3-managed-container-domain.md`](release-3-managed-container-domain.md) — identity, ownership, and lifetime;
- [`release-3-managed-container-lifecycle.md`](release-3-managed-container-lifecycle.md) — lifecycle, scoped listing, divergence, repair, removal, and troubleshooting;
- [`release-3-session-networking.md`](release-3-session-networking.md) — Session network ownership, lazy provisioning, isolation, explicit repair, and cleanup;
- [`release-3-resource-constraints.md`](release-3-resource-constraints.md) — resource hierarchy, safe defaults, workload limits, and enforcement;
- [`release-3-port-publishing.md`](release-3-port-publishing.md) — hierarchical grants, loopback TCP allocation, durable leases, and collision handling;
- [`release-3-vocabulary-and-implementation-map.md`](release-3-vocabulary-and-implementation-map.md) — canonical terms and the current-to-target code map.

## Possible 4.0 / use-case driven

If concrete use cases justify remote capabilities, they remain a later,
separate architecture problem:

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
