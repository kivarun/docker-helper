# Release 2.3 System-Mode-Only Cutover

## Status

Accepted as the Release 2.3 architectural goal.

This pulls forward an already accepted later simplification: user-mode daemon
support is removed before the larger Release 3 managed-container runtime work.
Earlier planning placed this cutover after Release 3 (at one point around 3.1,
and the current roadmap later recorded it as the first Release 4 work package).
Release 2.3 supersedes those placements.

The purpose is architectural simplification, not a new capability. By the end
of Release 2.3 docker-helper has one daemon deployment/security model before
build isolation and Release 3 add new runtime surface.

## Decision

Release 2.3 supports one daemon deployment model: the root-owned system
service protected by the existing mandatory AppArmor-or-enforcing-SELinux
boundary.

Non-root CLI and agent access remain first-class. They authenticate to the
system service through Principal, Launcher, and Session credentials; removing
the user-mode daemon must never be implemented as a root-only client
restriction.

The cutover removes the user-mode daemon as a production concept rather than
leaving a disabled compatibility branch.

Removed user-mode-only surfaces include:

- per-user daemon startup and the systemd user service;
- the private per-user daemon socket and daemon endpoint auto-selection;
- per-user daemon configuration/state/admin-token ownership;
- transparent daemon-owner Principal/default-Launcher bootstrap and its
  reservation rules;
- non-root daemon `init`/`serve` behavior and user-mode lifecycle paths;
- user-mode MAC behavior and the supported rootless-Docker deployment contract
  that depends on the user daemon;
- user-mode-only help, completion, packaging, tests, fixtures, and UAT;
- production `user` versus `system` mode branching whose only purpose was to
  preserve both daemon deployments.

Client-side state is not user-mode daemon state. A non-root system client may
still keep installed credentials and ordinary client configuration under its
user-owned configuration directory where the client contract requires it.

## Packaging boundary

Removing user mode does **not** by itself require deleting every non-native
artifact.

Native DEB/RPM packages are the canonical installation path and must contain
only the system daemon/service deployment after the cutover. Any project-built
tarball that remains supported must likewise become system-mode-only: no user
service, no user-mode installer, no hidden user-daemon path. Whether the
project continues publishing a system-mode tarball is a packaging/release
choice and is deliberately decoupled from the daemon security-model cutover.

This supersedes the older plan that coupled user-mode removal and tarball
removal into one later release.

## Migration boundary

There is no compatibility requirement to preserve a running user-mode daemon
inside Release 2.3.

An existing user-mode installation migrates explicitly to the system service:

1. provision the system service and its mandatory MAC backend;
2. create/resolve the user's Principal and `default` Launcher;
3. issue/install the appropriate Principal or Launcher credential for
   non-root control-plane access;
4. create new Sessions under the system service;
5. stop and remove the old user-mode daemon deployment.

Release 2.3 does not adopt, copy, or silently transfer active user-mode
Sessions, Operations, runtime resources, admin tokens, or daemon-owned state.
Historical user-mode state may be left for explicit operator cleanup, but it
must not be discovered or consumed by the system daemon as compatibility
input unless a concrete migration step is separately designed and accepted.

## Architectural result

After the cutover:

```text
non-root operator / agent
        |
        | Principal / Launcher / Session credential
        v
root-owned docker-helper system service
        |
        | mandatory AppArmor OR enforcing SELinux
        v
Docker backend
```

There is one daemon bootstrap path, one ownership model, one mandatory-MAC
contract, and one default endpoint-selection model.

The removal is valuable only if it reduces architecture. Release 2.3 must not
replace user mode with a hidden compatibility daemon, an unsupported
`--user-mode` escape hatch, a second service-account mode, or another daemon
selection abstraction.

## Acceptance direction

The cutover is complete only when:

- no production path can start, discover, authenticate to, or provision a
  user-mode daemon;
- the system socket is the only default local daemon endpoint;
- non-root system clients still work through installed credentials;
- mandatory system-mode MAC enforcement remains fail closed;
- the transparent daemon-owner Principal/default-Launcher bootstrap and its
  special reservation policy are deleted;
- mode-specific production branches collapse instead of being retained as
  dead `ModeUser` cases;
- DEB/RPM fresh-install and upgrade UAT pass on supported distributions;
- any retained project tarball is system-mode-only and passes the same system
  deployment/security acceptance;
- current README/help/man/skill/packaging documentation no longer teaches or
  implies a supported user daemon;
- obsolete user-mode production code, tests, fixtures, scripts, service units,
  and current-contract documentation are deleted rather than merely skipped.

## Relationship to later releases

Release 2.4 build isolation and Release 3 managed-container work assume this
system-mode-only baseline. They do not need to preserve or rediscover a weaker
user-mode security contract.

The bounded Session-lease candidate remains a separate Release 3.1 concept;
user-mode removal is no longer part of the post-Release-3 roadmap.
