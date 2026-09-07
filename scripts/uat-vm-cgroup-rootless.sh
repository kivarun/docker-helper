#!/usr/bin/env bash
#
# Release 3 rootless cgroup evidence gate — environment stop guard.
#
# The aggregate-cgroup proof itself lives in
# scripts/cgroup-feasibility-rootless.sh. This VM wrapper is intentionally
# blocked until Phase 0 has a supported, normally configured rootless Docker
# environment to run that proof against.
#
# The previous iterations started repairing the test environment itself
# (harness-owned dockerd/rootlesskit launch, manually managed containerd,
# distro runtime-config workarounds, and ownership changes to global
# containerd paths). A green result produced by such an environment would no
# longer prove the accepted Release 3 deployment contract.
#
# Do not make this wrapper green by adding more runtime workarounds. Select or
# provision a supported rootless Docker deployment first, then make this
# wrapper invoke the existing cgroup-feasibility-rootless.sh unchanged against
# that environment.

set -euo pipefail

cat >&2 <<'EOF'
[cgroup-rootless-vm] GATE-BLOCKED: supported rootless Docker environment prerequisite is not satisfied.

The Release 3 Phase-0 rootless gate must test a normally configured supported
rootless Docker deployment. The gate harness must not install, repair, emulate,
or replace Docker/containerd runtime internals merely to obtain a green test.

In particular, do NOT reintroduce any of these probe-only workarounds:
  - a harness-owned direct rootlesskit/dockerd fallback instead of the selected supported deployment;
  - a manually pre-launched user-owned containerd;
  - chown or other ownership changes to global /run/containerd or /var/lib/containerd;
  - mutation/removal of distro containerd configuration to force the probe to start;
  - any other host-runtime surgery that would not be part of the supported user deployment.

The Engine gates and the system-mode cgroup gate are independent and may remain
accepted. Only the rootless evidence row is blocked.

NEXT ACTION: choose/provide a CI VM environment with a supported rootless Docker
installation that starts normally for an unprivileged user under the selected
Release 3 deployment model. Then run scripts/cgroup-feasibility-rootless.sh
against that environment without weakening its placement, delegation,
aggregate CPU/memory/PIDs, restart, cleanup, or fail-closed assertions.

Until that prerequisite exists:
PHASE 0 BLOCKED — ROOTLESS ENVIRONMENT EVIDENCE MISSING
EOF

exit 1
