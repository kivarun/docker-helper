# Changelog

This file summarizes user-visible release changes. Commit-level history remains available through the GitHub compare links for each release.

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

[2.1.0-rc.5]: https://github.com/kivarun/docker-helper/releases/tag/v2.1.0-rc.5
[2.0.0]: https://github.com/kivarun/docker-helper/releases/tag/v2.0.0
