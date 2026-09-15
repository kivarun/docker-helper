# Release 4 System-Mode-Only Cutover

## Status

**Superseded.**

The system-mode-only daemon cutover described here was an accepted later
simplification. It is now pulled forward to Release 2.3 and owned by
[`release-2.3-system-mode-only.md`](release-2.3-system-mode-only.md).

Earlier planning placed user-mode removal after Release 3 (at one point around
3.1); the roadmap later recorded it as the mandatory first Release 4 work
package. Release 2.3 supersedes those placements so Release 2.4 build isolation
and Release 3 managed-container work start from one daemon deployment/security
model.

This file remains only as a pointer for historical links. It is not a current
Release 4 scope document.

The old coupling between user-mode removal and deletion of the
project-produced installation tarball is also superseded. Release 2.3 removes
user-mode daemon support. Any retained project tarball must become
system-mode-only; whether the tarball itself remains a supported release
artifact is a separate packaging/release decision.

See:

- [`release-2.3-system-mode-only.md`](release-2.3-system-mode-only.md) — accepted
  system-mode-only cutover;
- [`release-2.4-build-sandbox.md`](release-2.4-build-sandbox.md) — build execution
  isolation that follows the cutover;
- [`roadmap.md`](roadmap.md) — current release ordering.
