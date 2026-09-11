# Changelog

This file summarizes user-visible release changes. Commit-level history remains available through the GitHub compare links for each release.

## [2.2.0] (unreleased)

Release 2.2 adds one complete filesystem-policy capability: every allowed root carries an explicit access mode, and system mode independently enforces read-only exposures with the mandatory MAC backend. This entry documents the implemented capability of the release line; the release is not yet tagged or published.

### Highlights

- Access-bearing allowed roots: every allowed root now carries an explicit `read_write` or `read_only` access mode beside its canonical path. `config allowed-root add`, `principal allowed-root add`, and `launcher allowed-root add` accept `--access` (omission is the canonical `read_write` grant), and new `set-access` commands change the mode of exactly one stored root in all three families (global config, Principal, Launcher) as one server-side conditional mutation. The default human `allowed-root list` output remains the 2.1-compatible one canonical root per line; `--json` is the explicit opt-in that prints the canonical rich entries (`{"path","access"}`) for access-aware tooling.
- Hierarchy with read-only dominance: within one scope the most-specific canonical path wins; across scopes (global → Principal → Launcher → Session) the access modes meet with `read_only` dominance, so a lower authority can narrow but never widen its parent. `read_write` and `read_only` are the only access values.
- Immutable Session filesystem snapshots: each Session captures the effective filesystem policy as a persisted immutable snapshot at creation time (`session_filesystem_snapshot_entries`); it is the single data-plane filesystem authority of the Session and is visible through `session show`. Later allowed-root changes affect only new Sessions. Existing pre-2.2 Sessions migrate to a compatibility read-write snapshot of their workspace; missing/corrupt snapshot state fails startup closed.
- Writable-parent protection: a writable bind of a parent is refused when the exposed subtree contains any effective read-only region. The daemon never silently downgrades a writable request to read-only; the refusal is the stable `read_only_root` policy error, distinct from the structural `invalid_mount`, and is answered before any pin, operation, or container state exists.
- AppArmor workload enforcement: each system-mode run under the AppArmor backend executes under a helper-owned generated profile (`docker-helper-workload-<operation-id>`) derived from the resolved exposure plan, which independently denies writes to read-only container targets; the profile is removed with the operation or reconciled at daemon startup.
- SELinux workload enforcement: under enforcing SELinux, each read-only exposure is materialized as a helper-owned `bindfs` passthrough projection mounted with the static `docker_helper_ro_projection_t` context, which independently denies workload writes while the container keeps its `docker_helper_container_t` MCS confinement; the backing tree is never relabeled and read-write exposures remain direct binds.
- Legacy 2.1 compatibility: path-only config entries, database rows, and API inputs are still accepted everywhere and mean `read_write`; `allowed_roots` remains the 2.x path-only projection beside the authoritative rich `allowed_root_entries` projection on show/list/introspection surfaces, and the Launcher complete-scope PUT keeps the documented path-only form alongside the canonical rich form.

### Compatibility

- Legacy roots and sessions migrate as read-write authority: a pre-2.2 path-only config entry, Principal root, Launcher root, or API input without access is the `read_write` grant, and a pre-2.2 live Session carries a compatibility `read_write` snapshot of its workspace. No data migration narrows existing issued authority, and existing credentials, IDs, and ownership are preserved.
- The existing `config allowed-root list`, `principal allowed-root list`, and `launcher allowed-root list` invocations remain compatible: the default human output is the 2.1 one canonical root per line. The canonical rich representation exists as the explicit `--json` opt-in on the same commands, so access-aware tooling can read the exact `{"path","access"}` entries. `session show` and the HTTP rich projections are unchanged.
- When config.json is mutated by 2.2 (`config allowed-root add/set-access`, `reload`, `init`), string roots may be normalized into rich `{"path","access"}` objects on disk. Operationally visible representations (`config show`, `--json` lists, session show) project both the authoritative rich form and the 2.x path-only compatibility form; reading a 2.1.1 config unchanged stays valid.
- SELinux system-mode deployments require `bindfs` for the read-only workload projection. DEB/RPM packages declare it as a package dependency; the tarball system installer aborts before any mutation on an enforcing SELinux host without `bindfs`, and an AppArmor host does not require it.

Full changes since 2.1.1: https://github.com/kivarun/docker-helper/compare/v2.1.1...release/2.2 (release line; no tag has been created yet)

## [2.1.1]

A compatible patch release over 2.1.0 adding two opt-in workload capabilities and targeted CLI usability fixes. Without the new flags, workload behavior is unchanged; the CLI usability fixes apply to every installation.

### Highlights

- Canonical one-time-token install hint: every credential issuance path now prints the same canonical hint after issuing a token (`principal create`, `principal credential create`, `principal credential rotate`, `launcher create`, `launcher credential create`, `launcher credential rotate`). The hint states that the token will not be shown again and names `docker-helper credential install` as the install path for its audience. Machine-readable JSON stdout stays pure — the hint goes to stderr for those commands, while `principal credential create` keeps its human-readable stdout — and the hint never re-prints the token itself; a credential response without a new token (for example `launcher credential show`) prints no hint.
- Fixed the Bash completion of the first positional of `launcher allowed-root add/remove`. The `[LAUNCHER] PATH` grammar is unchanged; with one positional the word is the PATH for the default Launcher, so a relative PATH without a slash is legal and a slash-free word stays grammar-ambiguous: completion offers the union of the daemon-backed Launcher selectors and the filesystem candidates (a failed selector query never removes the PATH candidates). A word containing a slash — which a Launcher name can never contain — is the unambiguous PATH and completes filesystem candidates without a selector query. After an explicit Launcher positional, the next position completes PATH only.
- Added `docker-helper run --env-from DEST=SOURCE`: pass an environment value without placing it in the `docker-helper` command line. The value is read from the CLI process's own environment and delivered through the existing run environment contract: it is not placed in the `docker-helper` argv, is not printed in diagnostics, is not inherited from the surrounding environment, and the daemon does not log environment values. Known 2.1.x limitation: the legacy run implementation starts the workload through the Docker CLI, which receives the value as `--env DEST=value` argv, so the value is visible in that daemon-side child process's argv; `--env-from` guarantees nothing beyond the `docker-helper` process boundary. An unset SOURCE fails closed before any run Operation is created; an explicitly empty SOURCE is delivered as an empty value; `--env` and `--env-from` compose.
- Added `docker-helper run --helper-socket` (HTTP field `helper_socket`): in system mode the daemon injects its own read-only runtime directory bind (`/run/docker-helper` -> `/run/docker-helper`) so the workload can reach the existing helper Unix socket. The client selects only the boolean; source, target, and mount mode are server-owned. The socket provides transport only — protected operations still require a separately passed bearer credential. The directory (not the socket inode) is bound: a consumer that does survive daemon replacement — for example an orphaned container in a crash scenario — observes the recreated socket through its existing directory projection. A normal graceful docker-helper service restart still terminates helper-owned run workloads under the 2.1.x shutdown lifecycle; `helper_socket` does not change that workload lifecycle, and no workload survival across a service restart or a package upgrade is promised.
- `--helper-socket` fails closed in user mode with `invalid_helper_socket`: in user mode the workload runs under the daemon-owner UID, so a runtime directory projection would expose daemon runtime state and is deliberately not offered.
- Ordinary mount policy is unchanged: sources stay workspace-relative, absolute host sources and workspace escapes stay rejected. When the projection is active, a caller mount whose target overlaps the injected mount point (exact, ancestor, or descendant) is rejected as `invalid_mount`; without `helper_socket` the 2.1.0 mount contract is unchanged.
- `run.start` and `run.finish` audit records carry a `helper_socket` boolean when the projection is active. Environment values are never logged (names only), including values delivered through `--env-from`.
- The shipped SELinux policy grants helper containers the narrow transport permissions to reach the helper socket (runtime directory traversal/getattr, socket connect, connectto to the daemon domain) with no runtime file content access.
- New targeted UAT regression groups 15-17 (`scripts/uat-regression-env-from.sh`, `scripts/uat-regression-helper-socket.sh`, `scripts/uat-regression-dogfood-env-socket.sh`) cover secret containment, socket isolation and restart semantics, and the combined delegated-orchestrator scenario (Launcher credential through `--env-from`, child Session through the injected socket, cleanup). Additional targeted UAT evidence: user-mode helper-socket fail-closed behavior (`scripts/uat-regression-user-mode-helper-socket.sh`) and enforcing-SELinux helper-socket confinement (`scripts/uat-regression-selinux-helper-socket.sh`).

Full changes since 2.1.0: https://github.com/kivarun/docker-helper/compare/v2.1.0...v2.1.1

## [2.1.0] - 2026-09-07

Release 2.1 adds stable delegated Launcher ownership between Principals and Sessions while preserving docker-helper's local-first, policy-enforcing scope.

### Highlights

- Added the `Principal -> Launcher -> Session` ownership hierarchy. A Launcher is the stable delegated Session/runtime owner; credentials remain rotatable authentication keys and are never resource owners.
- Added automatically provisioned `default` Launchers so the normal Principal workflow remains short while explicit non-default Launchers can be used for delegated workloads.
- Added Launcher credentials with zero-or-one cardinality per Launcher. Rotation replaces the bearer secret while preserving Launcher ownership and existing Sessions.
- Added delegated Session control: a Launcher credential can create, list, and delete only Sessions owned by its Launcher.
- Added Launcher-scoped filesystem policy. Launchers either `inherit` the Principal ceiling or use a `restricted` allowed-root set that can only narrow it; Session creation evaluates the full global -> Principal -> Launcher policy chain.
- Added narrow Launcher allowed-root operations through `launcher allowed-root add/list/remove/inherit`. Adding a root to an inheriting Launcher atomically narrows it to `restricted`; removing the last restricted root remains fail-closed until explicit `inherit`.
- Added `session create --launcher ...` and scope-first Session listing. Principal and Launcher selectors can only narrow the authenticated authority's visible scope; foreign resources remain non-disclosing, and globally ambiguous Launcher names are never searched without Principal context.
- Added Principal self-read for `principal show` and `principal allowed-root list`: a Principal credential can read exactly its own Principal state while administrative mutations remain admin-only.
- Added global `dhl_...` Launcher-ID targeting for individual Launcher administration without requiring a redundant Principal selector; Launcher names remain Principal-scoped.
- Added `docker-helper selinux check` as the read-only SELinux diagnostics counterpart to `docker-helper apparmor check`.
- Improved Bash completion across the new control plane: authority-aware command availability, scope-aware Principal/Launcher selectors, policy-aware workspace/root paths, positional Launcher and Principal fields, and equivalent behavior for separated and inline flag forms.

### Ownership and authorization

```text
Principal
└── Launcher
    └── Session
```

A Principal remains the OS execution identity and authorization ceiling. A Launcher is the stable delegation and Session ownership boundary. A Credential is only a bearer key: rotating or replacing it does not move ownership of Sessions or runtime resources.

The reserved user-mode owner chain remains transparent to normal user-mode operation and cannot be mutated into an invalid next-start state. Principal and Launcher enablement, ownership, allowed-root policy, Session creation, listing, and deletion are enforced server-side through the authenticated authority; CLI selectors never widen that authority.

Existing Release 2.0 Principal credentials remain Principal credentials through the 2.1 migration and are not silently reclassified. Existing Principal-owned Sessions are migrated into the Launcher hierarchy through the Principal's default Launcher where attribution is valid. Principal credentials remain bound to the stable Principal identity rather than to a reusable username.

### API, CLI, and policy behavior

- Launcher filesystem scope is managed with the narrow allowed-root verbs rather than a generic scope mutation command.
- `session create` and its workspace completion resolve the same current Launcher target and effective roots, so completion does not offer workspaces that the selected Launcher policy would reject.
- `session list` and `GET /sessions` expose server-side scope-first narrowing for admin, Principal, and Launcher authorities without client-side filtering.
- Empty public `allowed_roots` values serialize as `[]`, not `null`, and Launcher allowed-root projections are deterministic.
- CLI help, man pages, README, completion, and the HTTP contract are aligned with the final Principal/Launcher/Session authority model.

### Compatibility and packaging

- Systemd package lifecycle preserves `/run/docker-helper` across service restarts with `RuntimeDirectoryPreserve=restart`, so long-lived containers bind-mounting that runtime directory continue to see the recreated daemon socket during supported DEB/RPM upgrade and reinstall paths.
- AppArmor system mode uses the shipped `docker-helper-system` profile plus helper-owned dynamic boundary state; SELinux remains the alternative supported enforcing backend.
- Release 2.1 intentionally does not add managed-container lifecycle, desired state, restart policy, interactive exec, networking, port publishing, or resource-limit semantics. Those remain later-release work.

Full changes since 2.0.0: https://github.com/kivarun/docker-helper/compare/v2.0.0...v2.1.0

## [2.0.0] - 2026-09-01

Release 2.0 turns the original per-user helper into a normally installable local multi-user service while preserving the existing user-mode deployment.

### Highlights

- Added system mode: one root-owned daemon can serve multiple explicit OS-backed Principals.
- Added Principal identities with daemon-resolved UID, GID, home directory, enabled state, and allowed roots.
- Added multiple independently revocable Principal credentials per Principal. Credential secrets are stored only as hashes and returned only when issued.
- Added Principal-owned Session control and server-side execution identity: system-mode containers run as the authenticated Principal's UID:GID rather than trusting client-supplied identity.
- Added per-Principal filesystem ceilings. New Session workspaces must remain inside the current server-side allowed-root policy.
- Added deterministic operator endpoint selection with explicit `--system`, `--endpoint`, and `--token-file` overrides.
- Added dual local transports in system mode: Unix socket plus configurable loopback HTTP (`127.0.0.1:52375` by default). Transport does not grant authority; tokens remain the authorization boundary.
- Added Principal-aware audit provenance for multi-user operation tracking.
- Added native DEB and RPM packages, a systemd system service, Bash completion, man pages, and release checksum artifacts.
- Added mandatory system-mode MAC integration through exactly one supported backend: AppArmor or enforcing SELinux.
- Added trusted CA injection support for controlled custom CA distribution into Docker operations.
- Preserved Release 1 user mode with XDG paths and the private per-user Unix socket.

### Lifecycle semantics

Revoking a Principal credential blocks that key for new control-plane requests but does not retroactively invalidate already issued Session tokens. Removing an allowed root prevents new Sessions under that root but does not dynamically revoke existing Sessions. Disabling or deleting a Principal invalidates its active Sessions.

Session tokens remain narrow data-plane capabilities: Docker pull, build, run, registry, and operation requests require the Session token rather than an admin or Principal credential.

### Compatibility and scope

Release 2.0 remains local-first. Non-loopback listeners, TLS-based remote access, workspace synchronization, remote helper routing, host port publishing, and generic Docker network configuration are intentionally outside the release scope.

Full changes since 1.0.2: https://github.com/kivarun/docker-helper/compare/v1.0.2...v2.0.0

[2.1.0]: https://github.com/kivarun/docker-helper/releases/tag/v2.1.0
[2.0.0]: https://github.com/kivarun/docker-helper/releases/tag/v2.0.0
