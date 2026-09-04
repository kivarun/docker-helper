# Release 4 System-Mode-Only Cutover

## Status

Accepted as the mandatory first Release 4 work package. Detailed implementation
planning begins after Release 3 is complete. No other Release 4 capability may
start before this cutover is implemented, reviewed, and accepted.

## Decision

Release 4 supports one daemon deployment model: the root-owned system service
installed from a native DEB or RPM and protected by the existing mandatory
AppArmor-or-SELinux system-mode boundary.

The cutover removes:

- the user-mode daemon, per-user service, socket, configuration, state, admin
  token, and transparent daemon-owner Principal/default-Launcher bootstrap;
- production selection between user and system daemon modes;
- the supported rootless Docker configuration tied to user-mode operation;
- the project-produced installation tarball, bundle build path, user/system
  tarball installers, and optional user-mode AppArmor template;
- current user-mode/tarball help, README, man-page, packaging, completion, test,
  and UAT contracts.

Release 4 retains non-root CLI and agent access to the system service through
Principal, Launcher, and Session credentials. Removing user-mode daemon support
must not be implemented as a root-only client restriction.

Source remains available, and GitHub-generated source archives are not treated
as supported installation artifacts. Release 4 ships no hidden user-mode flag,
compatibility daemon, or unsupported binary-install path.

## Migration boundary

User-mode installations may remain on the Release 3 LTS line or migrate
explicitly to the system service before installing Release 4. Migration must
provision the system-mode Principal/Launcher/credential chain and must not
adopt, copy, or silently transfer active user-mode Sessions or their runtime
resources.

The Release 4 design pass must define package preflight, clear failure behavior
for attempted non-root daemon startup, configuration migration guidance, exact
supported upgrade paths, and removal evidence. Historical release documents
remain historical records; only current product documentation is rewritten.

## Acceptance direction

The cutover is complete only when:

- no production path can start or discover a user-mode daemon;
- the system socket and installed non-root credential are the only default
  non-root client path;
- mandatory system-mode MAC enforcement remains fail closed;
- DEB/RPM fresh-install and upgrade UAT pass on the supported distributions;
- the project no longer builds or publishes its installation tarball;
- obsolete user-mode and tarball production paths, tests, fixtures, scripts,
  and current-contract documentation are deleted rather than retained as dead
  compatibility code.
