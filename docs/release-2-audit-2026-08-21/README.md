# Release 2 audit — 2026-08-21

Audit baseline: `main` at `d269526460d3d84af99870ddb3686023bc7b953c`.

This directory records the pre-release review by responsibility:

- [high-level abstractions](01-high-level-abstractions.md);
- [layering and dead code](02-layering-and-dead-code.md);
- [tests](03-tests.md);
- [documentation](04-documentation.md);
- [logging, events, and output](05-logging-events-output.md);
- [certificates and SELinux](06-certificates-and-selinux.md).

## Priority before continuing UAT

| Priority | Finding | Required result |
|---|---|---|
| P0 | First non-root `docker-helper init` against an existing system daemon reports that a credential is already installed when no credential file exists. | Fix the first-install path and add an end-to-end CLI regression test. |
| P0 | `validateCAConfig` discards the error returned by `computeOpenSSLHash`. | Reject an incompatible CA before persisting configuration and add a preflight regression test. |
| P0 | `/opt` is accepted as a system allowed root, but the SELinux policy grants workspace access only to `user_home_type`. | Prove a safe `/opt` label/policy in enforcing UAT or reject unsupported SELinux roots before saving them. |
| P0 | The release job runs `build-packages.sh` without installing `checkmodule` and `semodule_package`. | Install `checkpolicy` and `semodule-utils` in the release job and exercise the package build before tagging. |
| P1 | The single RPM hard-depends on both `apparmor-parser` and `policycoreutils`. | Either scope Release 2 RPM support to a distribution that can resolve both, or split/soften backend dependencies. |
| P1 | The configured `trusted_ca_path` can point outside paths readable by the active system MAC policy, while the previously accepted managed-import workflow is not implemented. | Choose and test one Release 2 source contract: a documented helper-owned readable location or managed import. |

These findings are more urgent than expanding UAT because they either block a
normal first-use path or can make the release artifact build/install fail.
After they are resolved, resume UAT with the SELinux matrix in
`06-certificates-and-selinux.md`.

## Verification performed

- Repository history and the changes after the previous documentation baseline
  were reviewed through `d269526`.
- `bash -n` passed for the release, installation, and package lifecycle scripts.
- `git diff --check` passed after the documentation edits.
- Go tests, race tests, and vet could not be run in this environment because the
  Go toolchain is not installed.
- The SELinux module could not be compiled locally because `checkmodule` and
  `semodule_package` are not installed. Installing them in this container is
  blocked by its package-manager privilege restrictions.
