# Changelog

This file summarizes user-visible release changes. Commit-level history remains available through the GitHub compare links for each release.

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
