# Changelog

This file summarizes user-visible release changes. Commit-level history remains available through the GitHub compare links for each release.

## [2.1.0-rc.8] - unreleased

RC8 fixes the CLI/UX defects manual UAT found on top of RC7, without expanding Release 2.1 feature scope.

- Removed the `launcher scope` command family from the CLI: launcher filesystem scope is managed with the narrow `launcher allowed-root add/list/remove/inherit` verbs (backed by new single-request `POST`/`DELETE` server operations plus the existing atomic scope replacement), and `principal allowed-root list` completes the allowed-root read surface.
- Narrow allowed-root mutations preserve the established scope semantics: an add on an `inherit` launcher narrows it to `restricted` atomically with the insert, removing the last root leaves the launcher restricted with an empty root set (fail-closed), and only an explicit inherit returns it to the Principal ceiling. The user-mode reserved default launcher stays immutable for both directions.
- `session create --workspace` completion now resolves exactly the Session-create target the typed selectors resolve: the typed `--principal`/`--launcher` values (both `--flag VALUE` and `--flag=VALUE` forms) are forwarded to the daemon's Session-create policy introspection, which resolves them through the same canonical owners real Session creation uses — completing with a restricted launcher offers only that launcher's effective roots, never the wider Principal ceiling.
- Policy-root completion suggestions are now deterministic and duplicate-free: a path qualifying both as an entry anchor and as a directory under a wider root is suggested once.
- `principal show` read authority is scope-first: a principal credential reads exactly its own Principal (including FIELD extraction), a foreign selector is the established non-disclosing not-found, and admin read is unchanged. The CLI still performs no local self-check; the daemon authorizes the target.
- The values of the `--principal`/`--launcher` selector flags now complete from the daemon's scope-aware selector introspection (`completion selectors principal|launcher`): an admin sees Principal names and, with a typed `--principal` context, that Principal's Launcher names (only globally resolvable `dhl_` IDs without a context), a Principal credential sees its own Launchers, a Launcher credential and any foreign scope see nothing. Both `--flag VALUE` and `--flag=VALUE` forms complete, and a partially typed inline form filters like the separated one.
- The positional `[LAUNCHER]` argument of the individual Launcher commands completes from the same selector-introspection owner, and the grammar-ambiguous first positional of `launcher allowed-root add/remove` offers both legal continuations — the applicable Launcher selectors plus the PATH candidates for the default Launcher — as a unique union; with the first positional typed, completion narrows to PATH only.
- The `--principal` selector completion is command-context aware: a Principal credential sees its own username where the explicit own selector is legal and nothing on `session create`; the completion tree reflects the real read authority (a Principal credential sees `principal show` and `principal allowed-root list`, not the admin-only mutations).
- Help, completion, man pages, README, and the architecture document reflect the actual read/mutation contracts; the UAT regression suite gained an RC8 CLI/UX acceptance group covering the packaged CLI.

Full changes since RC7: https://github.com/kivarun/docker-helper/compare/v2.1.0-rc.7...v2.1.0-rc.8

## [2.1.0-rc.7] - 2026-09-06

RC7 restores the Release-2.1 scope-first Session-list narrowing contract that escaped the published RC6.

- Restored scope-first Session-list narrowing: `docker-helper session list` (and `GET /sessions`) accepts optional `--principal USER` / `--launcher LAUNCHER` selectors that only narrow the authenticated authority's visible sessions — admin by Principal and/or Launcher (a `dhl_...` Launcher ID is sufficient without `--principal`; a Launcher name requires it and is never searched globally), a Principal credential by Launcher inside its own scope, and a Launcher credential without selectors. Missing or foreign targets stay non-disclosing and authority-illegal selectors are stable selector errors.

Full changes since RC6: https://github.com/kivarun/docker-helper/compare/v2.1.0-rc.6...v2.1.0-rc.7

## [2.1.0-rc.6] - 2026-09-06

RC6 hardens the RC5 delegated-ownership model without expanding Release 2.1 feature scope.

- The reserved transparent user-mode owner chain (daemon-owner Principal and its `default` Launcher) cannot be mutated into an invalid next-start state: control-plane mutations that would corrupt it are rejected with a stable conflict before any durable or runtime change.
- One canonical effective-root policy across Principal, Launcher, and Session creation: the same three-level narrowing (global roots, Principal ceiling, Launcher scope) is evaluated through a single owner everywhere.
- Coherent effective-policy introspection: the session create-policy endpoint projects the principal, Launcher, and effective roots of a Session that would be created right now, as one consistent snapshot.
- Principal credentials remain bound to the exact Principal identity: deleting and recreating a Principal with the same username does not reattach old credentials.
- Launcher and Principal scope-first control paths were converged without expanding authority: Session management, listing, and deletion authorize through one boundary per authority class.
- The public `allowed_roots` contract is always a JSON array: an empty set serializes as `[]`, never `null`.
- Launcher allowed-root projection is deterministic (stable ordering) across list, introspection, and audit output.
- Documentation reconciliation: completion, help text, man pages, and documented contracts now match the implemented model, including the AppArmor state model (profile `/etc/apparmor.d/docker-helper-system` with dynamic helper-owned boundary state at `/var/lib/docker-helper/apparmor/managed-boundaries`) and the authority-sensitive bearer requirements for direct HTTP clients.
- Security/authority and lifecycle hardening throughout, without expanding Release 2.1 feature scope.

Full changes since RC5: https://github.com/kivarun/docker-helper/compare/v2.1.0-rc.5...v2.1.0-rc.6

## [2.1.0-rc.5] - 2026-09-05

Release 2.1 is a focused control-plane release that adds stable delegated Launcher ownership between Principals and Sessions without expanding docker-helper into a general orchestration system.

### Highlights

- Added the `Principal -> Launcher -> Session` ownership hierarchy. A Launcher is the stable delegated Session/runtime owner; credentials remain rotatable authentication keys and are never resource owners.
- Added automatically provisioned `default` Launchers so the normal Principal workflow remains short while still allowing explicit non-default Launcher selection.
- Added Launcher-scoped filesystem policy:
  - `inherit` uses the Principal's current effective roots;
  - `restricted` further narrows them with Launcher-owned allowed roots.
- Session creation now evaluates the full current authorization chain: global roots, Principal roots, then Launcher scope.
- Added Launcher credentials with zero-or-one cardinality per Launcher. Rotation replaces the bearer secret atomically while preserving the same credential ID and Launcher ownership.
- Added delegated Session control: a Launcher credential can create, list, and delete only Sessions owned by its Launcher.
- Added Principal control of attached Launchers and their optional credentials without granting the Principal credential administrative authority over the Principal's OS identity or maximum policy.
- Added `session create --launcher ...` for selecting non-default Launchers. Principal credentials may target an attached Launcher by Principal-scoped name or `dhl_...` ID; Launcher credentials use their `dhl_...` ID or implicit self-selection.
- Added global `dhl_...` targeting for individual Launcher administration without requiring a redundant `--principal`; Launcher names remain Principal-scoped and are never searched globally.
- Added scope-first Launcher and credential listing: authentication establishes the maximum visible scope and selectors only narrow it.
- Preserved non-disclosing cross-Principal and cross-Launcher behavior for foreign resources.
- Added `docker-helper selinux check` as the read-only SELinux diagnostics counterpart to `docker-helper apparmor check`.
- Improved Bash completion, including authority-aware command availability and policy-aware path completion.
- Added stronger CLI diagnostics for default/duplicate Launcher creation and selector errors.

### Ownership and credential model

```text
Principal
└── Launcher
    └── Session
```

A Principal remains the OS execution identity and authorization ceiling. A Launcher is the stable delegation and Session ownership boundary. A Credential is only a bearer key: rotating or replacing it does not move ownership of Sessions or runtime resources.

Existing Release 2.0 Principal credentials remain Principal credentials through the 2.1 migration and are not silently reclassified. Existing Principal-owned Sessions are migrated into the Launcher hierarchy through the Principal's default Launcher where attribution is valid.

### Compatibility and scope

Release 2.1 intentionally does not add managed-container lifecycle, desired state, restart policy, interactive exec, networking, port publishing, or resource-limit semantics. Those remain later-release work.

Full changes since 2.0.0: https://github.com/kivarun/docker-helper/compare/v2.0.0...v2.1.0-rc.5

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

[2.1.0-rc.7]: https://github.com/kivarun/docker-helper/releases/tag/v2.1.0-rc.7
[2.1.0-rc.6]: https://github.com/kivarun/docker-helper/releases/tag/v2.1.0-rc.6
[2.1.0-rc.5]: https://github.com/kivarun/docker-helper/releases/tag/v2.1.0-rc.5
[2.0.0]: https://github.com/kivarun/docker-helper/releases/tag/v2.0.0
