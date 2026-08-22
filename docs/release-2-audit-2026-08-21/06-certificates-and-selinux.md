# Certificates and SELinux architectural review

## Certificate subsystem

### Current design

A configured PEM file must contain exactly one X.509 CA. The helper validates
it, computes an OpenSSL-compatible `X509_NAME_hash`, creates helper-owned runtime
material, and injects it into supported containers. Runtime `openssl` execution
was removed because a confined daemon could not safely execute the broad
`bin_t` domain solely for this calculation.

The current Go implementation is operationally self-contained, but it now owns
a substantial part of OpenSSL subject-name canonicalization: ASN.1 parsing,
string conversion, whitespace/case canonicalization, DER reconstruction,
sorting, and SHA-1 hashing. That is a high-maintenance compatibility boundary,
not a core docker-helper capability.

### Release blocker

`validateCAConfig` calls `computeOpenSSLHash(cert)` and discards both return
values. A certificate accepted by X.509 parsing but rejected by the custom
canonicalizer can therefore be persisted and fail later during daemon
load/reload. Return the wrapped hash error from preflight and add a regression
that proves the config file remains unchanged.

### Release recommendation

Do not rewrite the hash subsystem immediately before Release 2. Fix preflight,
retain the six OpenSSL 3.5.7 common-case golden hashes, and add an independent
differential corpus in CI/build tooling. Exercise real CA injection in both MAC
backends. Before release, settle the source lifecycle: constrain and document a
helper-owned path readable by the active policy, or complete the previously
accepted managed-import workflow. A broader store/standard-bundle abstraction
can follow in the next release.

Other maintenance notes:

- `readValidatedCAFile` uses unbounded `io.ReadAll`; the source is
  operator-controlled, so this is lower priority, but a small certificate-size
  limit would simplify the contract.
- runtime directories are fingerprinted from raw PEM bytes, so harmless PEM
  formatting changes create a new directory until runtime cleanup/reboot;
  document or garbage-collect this in the next release.
- no tracked document uniquely matching a “CA research document” was found in
  this checkout. This review used the implementation, tests, commit history,
  and the CA/SELinux rationale in `docs/selinux-support-plan.md`.

## SELinux subsystem

### Sound boundaries

- `detectLSM` is backend-neutral and fail-closed for neither/both backends and
  permissive SELinux.
- system mode verifies that the daemon is actually in `docker_helper_t`.
- the custom container domain preserves MCS confinement instead of disabling
  labels under SELinux.
- the application allowed-root check remains authoritative; the documentation
  explicitly does not claim per-path SELinux isolation.

### Release blocker: `/opt`

System root policy accepts exact `/home` and `/opt`. The SELinux module grants
daemon/container workspace access through `user_home_type`; it neither validates
the selected root's file type nor grants a reviewed `/opt` type. Consequently,
`init` can accept and persist a root that later fails through AVC denials.

Do not grant broad `usr_t` access as a shortcut. On an enforcing target, inspect
the actual `/opt` label and choose one of:

1. reject the root during SELinux init with a clear unsupported-label error;
2. require an operator-managed dedicated label with explicit instructions; or
3. add a narrowly justified type grant that is portable across every claimed
   target.

### Policy coupling

The module depends on container-selinux attributes and manually reproduces
container rootfs/file-management permissions. Raw `checkmodule` compilation
does not prove that those attributes/interfaces are available or semantically
equivalent on the target host. Treat container-selinux as an explicit package
and compatibility dependency and verify module install, container transition,
MCS isolation, and removal on each target.

### Packaging gaps

- The release job does not install the policy build tools required by
  `build-packages.sh`.
- The RPM hard dependency on both AppArmor and SELinux tooling is not portable
  to a standard SELinux-only Fedora/RHEL installation.
- The DEB package intentionally installs AppArmor assets but no SELinux module;
  this is acceptable only if the support matrix states it clearly.
- CI compiles raw policy source on Ubuntu but does not install the module with
  the target container-selinux/base policy.

### Required enforcing UAT after blockers

Run on openSUSE and the selected Fedora/RHEL-family target:

- fresh install, upgrade, remove, and policy persistence/removal behavior;
- systemd transition into `docker_helper_t`, including audit stdout and
  operational stderr through journald;
- principal/session creation, pull, build/buildx, run, mount-pin, and registry
  login;
- `/home` directory and regular-file mounts;
- the selected `/opt` contract;
- custom CA injection and hash-link consumption;
- custom container domain rootfs behavior and MCS separation;
- negative access to representative `shadow_t` and `ssh_home_t` objects;
- both absence of broad unexpected AVCs and documented harmless probe AVCs.

The existing openSUSE evidence is useful but is not yet the cross-distribution
Release 2 acceptance required by the design.
