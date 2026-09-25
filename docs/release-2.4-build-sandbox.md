# Release 2.4 Build Sandbox

## Status

Accepted architectural direction for Release 2.4. Detailed implementation
planning begins after Release 2.3 removes user-mode daemon support.

The mandatory M0 build-sandbox feasibility probe is CLOSED (2026-09-21):
composition A — a dedicated unprivileged builder user running rootless
BuildKit under rootlesskit with slirp4netns networking and a client/local
buildctl context transport — proved the required builder boundary on Ubuntu
24.04, Ubuntu 26.04, and openSUSE Tumbleweed. See the M0 closure record below
for the probe contract, mechanics, and authoritative evidence.

The M1 architectural proof (2026-09-21) then rejected one global persistent
`buildkitd` (no upstream tenant-isolation contract; live cross-session cache
leak on the proven composition) and selected the per-build-operation
ephemeral BuildKit lifecycle (candidate C) behind a narrow unprivileged
builder-manager service. See the M1 closure record below. Release 2.4 does
not promise persistent build cache.

Release 2.4 closes the mismatch between docker-helper's ordinary workload
execution contract and Docker build execution. It is deliberately a build
execution-boundary release, not a generic Dockerfile policy engine.

## Problem

For ordinary `run`, docker-helper owns the execution identity and privilege
floor: agent-controlled workload execution is attached to the authenticated
Principal UID:GID, capabilities are dropped, and `no-new-privileges` is
mandatory.

A Docker build is different. A caller supplies a Dockerfile whose `RUN`
instructions are executed by the Docker/BuildKit builder. Those instructions
normally execute as UID 0 inside the build execution environment until the
Dockerfile changes user.

That build-root is not automatically host root, but in the current rootful
builder architecture it is a materially weaker boundary than the ordinary
`run` contract. Agent-controlled code therefore has two execution paths with
different privilege models:

```text
run    -> Principal UID:GID + privilege floor
build  -> builder execution identity, commonly build-container UID 0
```

Release 2.4 makes the second path an explicit sandbox boundary rather than
trying to pretend Dockerfile instructions are equivalent to ordinary run.

The external-audit H1 builder-network finding is one visible consequence of
this broader distinction: the builder has its own execution and network
position. Release 2.2 does not attempt to redesign that boundary; Release 2.4
is the planned architecture point for doing so.

## Non-solution: Dockerfile filtering

docker-helper must not become a security parser for Dockerfile semantics.

In particular, Release 2.4 must not attempt to secure build by:

- rejecting `RUN` based on command text;
- looking for `curl`, `wget`, package managers, shells, or other programs;
- rewriting or injecting `USER` instructions;
- banning legitimate root-requiring build steps such as package installation;
- maintaining an allow/deny grammar for Dockerfile instructions as a substitute
  for execution isolation;
- interpreting arbitrary shell/program behavior inside `RUN`.

A Dockerfile remains Docker/BuildKit input. Security is enforced around the
builder execution environment, not by trying to understand the program being
built.

## Required security outcome

Release 2.4 must provide a builder boundary with this property:

> UID 0 inside agent-controlled build execution is not host UID 0 and does not
> inherit the host authority of the root-owned docker-helper service or rootful
> Docker daemon.

The exact mechanism is intentionally not frozen here. Candidate mechanisms may
include a rootless builder, user-namespace-isolated BuildKit, a dedicated
unprivileged builder service, or another backend that proves the same boundary
on all supported platforms.

A mandatory feasibility phase must choose the smallest mechanism that satisfies
the contract on supported Ubuntu and openSUSE installations. The design must
fail closed if the required isolation cannot be established; silently falling
back to the current rootful builder execution path is not acceptable once the
2.4 contract is active.

## M0 closure record — 2026-09-21

### Composition A (probed)

The feasibility probe exercised one composition end to end:

```text
dedicated unprivileged builder user
  -> rootlesskit --net=slirp4netns --copy-up=/etc --disable-host-loopback
  -> rootless buildkitd (oci worker, overlayfs snapshotter)
  -> private Unix socket owned by the builder
  -> buildctl --local-dir (client/local-source context transport)
  -> --output type=docker -> docker load into the rootful Engine
  -> docker run on the imported image
```

Probed properties (all mandatory per target):

1. build `RUN` executes as sandbox-root: `uid_map` maps the in-build UID 0 to
   a nonzero host-side UID inside the builder's subordinate range, and the
   user/mount/PID namespaces differ from the host's;
2. a root-owned `chmod 600` marker file outside the builder state is not
   readable from build `RUN` (host-root DAC authority absent);
3. the host loopback marker service is unreachable from build `RUN`, and the
   host-side listener records no build traffic (`--disable-host-loopback`);
4. outbound package-repository traffic works from build `RUN` (slirp4netns);
5. `RUN --network=host` and `RUN --security=insecure` are refused without a
   server entitlement;
6. the control socket is builder-owned (0660 builder:builder); root (the
   docker-helper stand-in) can drive it; an ordinary user and an agent-side
   session user cannot;
7. the `type=docker` export -> `docker load` -> `docker run` round trip works;
8. a failed build leaves no usable target image in the Engine.

### Probe mechanics

`scripts/release-2.4-m0-buildkit-proof.sh` (hosted-runner proof, Ubuntu) and
`scripts/release-2.4-m0-buildkit-tw.sh` (guest-side proof) implement the same
composition; `scripts/release-2.4-m0-buildkit-tw-vm.sh` boots the official
openSUSE Tumbleweed Cloud qcow2 through the canonical Tumbleweed VM harness
(`scripts/uat-vm-tumbleweed.sh`) and runs the guest-side proof inside the VM.
`.github/workflows/release-2.4-m0-buildkit.yml` owns the three proof targets
and the static checks. The probe is probe-only: no docker-helper product code,
policy, or RPM behavior is exercised or changed by M0.

BuildKit binaries come from the official upstream release with a pinned and
verified SHA-256 (v0.33.0, digest
`b6242896d343100808dcbe37565caf381e0a444a6a83d7255926bb1519248ead`, verified
against the official release SBOM subject digest); the openSUSE target uses
the distro `buildkit` RPM. The proof runs with Ubuntu's
`apparmor_restrict_unprivileged_userns` restriction enabled (default) and
relies on the distro-shipped rootlesskit AppArmor profile; no diagnostic
sysctl disabling is part of the passing path. The Tumbleweed guest probe must
not chmod host CA material; it verifies builder readability and fails closed.

### Results

| Target | Result | Evidence |
|---|---|---|
| Ubuntu 24.04 (hosted runner) | **PASS** | run [35633765178](https://github.com/kivarun/docker-helper/actions/runs/35633765178), artifact `release-2.4-m0-buildkit-35633765178-1`, digest `sha256:4dfab9cb8bc840ed1ca09edfeb6bc91b619579404cda5e0abae5ed25afefb9ea` |
| Ubuntu 26.04 (hosted runner) | **PASS** | run [35633765178](https://github.com/kivarun/docker-helper/actions/runs/35633765178), artifact `release-2.4-m0-buildkit-2604-35633765178-1`, digest `sha256:b06dc9a47be9146a3a49609d16e5a2bdab112756c23cc2b05be502fcdbecc5dc` |
| openSUSE Tumbleweed (QEMU/KVM VM) | **PASS** | run [35633765178](https://github.com/kivarun/docker-helper/actions/runs/35633765178), artifact `release-2.4-m0-buildkit-tw-35633765178-1`, digest `sha256:0f89409a5b3a954ca75693bd10f0aba7d93ddf65f5dcb5e64986c7633bf7673e` |

Tested commit: `0db79950a24a72e49b876f362f517fc8d042a56e` (the final probe
SHA, including the repo-policy action-SHA pinning). Observed sandbox-root
host-side UIDs: `1002` (24.04, 26.04; mapped into the builder's subordinate
range 231072) and `1001` (Tumbleweed). BuildKit v0.33.0 on the Ubuntu
targets; distro BuildKit 0.32.2 on Tumbleweed.

An equivalent earlier three-target PASS on the same probe mechanics ran at
`15b560f27ae74764e85012cd0899f0a39b82827f` (run 35631196290); the later run
adds only the action-SHA pinning required by the repository policy test.

### Earlier runs and the false-fail fix

All earlier 2.4 M0 runs before `15b560f` ran the same probe scripts against
intermediate probe fixes; the Tumbleweed target reported FAILED even when the
guest proof passed, because the guest probe wrote its PASS marker only into
the evidence file, while the host-side gate grepped the captured guest stdout.
The passing path now emits the marker on both surfaces. The Tumbleweed job
also uploaded a never-populated host evidence directory
(`if-no-files-found: error`), guaranteeing post-proof failure; that step is
removed. The earlier Tumbleweed evidence (for example run 35623061632,
artifact digest `sha256:c242614dbbcd52cf24f497991fcb615334eacd59a37ab7c3bb399766f7202ad5`)
showed the same composition passing inside the guest; the false fail was
harness-side only.

## M1 closure record — 2026-09-21

The implementation-plan review rejected one global long-lived `buildkitd`
unless a separate proof justified sharing build state across unrelated
Sessions (a docker-helper Session is a security boundary; BuildKit does not
advertise multi-tenant isolation). M1 is a probe-only architectural proof:
it reproduces the shared-daemon problem live, evaluates partial mitigations,
and proves the per-build-operation ephemeral alternative (candidate C) end
to end on all three supported targets. No production code, shipped systemd
unit, package policy, public API, Operation semantics, or service hardening
changed.

### Shared-daemon model: live reproduction

One persistent rootless buildkitd (composition A mechanics, dedicated builder
user) driven by independent buildctl client invocations
(`scripts/release-2.4-m1-global-daemon-proof.sh`):

1. cache-mount cross-client leak: build A writes
   `SESSION-A-SECRET-KEY` into a cache mount `id=dh-cross-session-m1`; a
   separate buildctl invocation B (own client Docker config) reads exactly
   that content through the same cache-mount id — **leak confirmed live**;
2. ordinary layer-cache cross-client reuse: **NOT proven in this run**. The
   second build produced build 1's exact exported value, but with no
   `CACHED` verdict for the `RUN` step; the probe was deliberately corrected
   so that coinciding busybox `date` second-truncation values do not count
   as proof. The recorded evidence is the absence of a reuse verdict, not a
   demonstrated leak. This does not change the shared-daemon REJECT: the
   live cache-mount leak above already breaks Session isolation, and no
   upstream stable tenant-isolation contract exists;
3. `BUILDKIT_CACHE_MOUNT_NS` build-arg probe: a reader build supplied a
   distinct namespace build-arg and still observed the writer's un-namespaced
   content — the namespace took effect only as an arg, not as a cache-key
   boundary in this buildctl invocation (mechanism inconclusive as a
   boundary); independent of that quirk it is caller-reachable keying by
   upstream construction, not tenant isolation;
4. `--no-cache` (client flag): the other client's cache-mount secret remains
   present in daemon state — no per-tenant prune;
5. `image-resolve-mode=pull`: per-build bypass of the local image store;
   no tenant-scoping.

### Upstream contract conclusion

No documented tenant-isolation contract exists for shared buildkitd state:

- `RUN --mount=type=cache` documents shared-by-default semantics ("another
  build may overwrite the files"); the cache-mount identity is the caller's
  `id` (+ `sharing` mode), with no per-client component
  (`frontend/dockerfile/docs/reference.md`, issue #1673);
- `BUILDKIT_CACHE_MOUNT_NS` is a client-supplied namespacing build-arg
  (`frontend/dockerui/config.go` `keyCacheNSArg`), not a security boundary;
  per-client cache-mount isolation requests are closed pointing at it
  (issue #2838), and tenant separation for the LAYER cache has no mechanism
  at all (issue #1299, still open);
- `buildkitd.toml` has no multi-tenant/isolation configuration;
- security advisories consistently scope one daemon to one trust domain
  (CVE-2024-23651, GHSA-388v-wmr2-g2v2, CVE-2026-15792: "isolate BuildKit
  daemons per tenant or per pipeline");
- registry credential state is daemon-pooled with cross-session reuse when
  identical credentials appear (util/resolver/authorizer.go); buildctl reads
  `$DOCKER_CONFIG/config.json` client-side and forwards per-session.

Conclusion: **the shared persistent daemon is REJECTED** (alternative A). The
Session is docker-helper's security boundary; sharing ordinary layer cache,
cache mounts, and resolution state across unrelated Sessions is not
acceptable without an upstream tenant-isolation contract that does not exist.

### Candidate C: per-build-operation ephemeral BuildKit

`scripts/release-2.4-m1-ephemeral-proof.sh` (hosted runners) and
`scripts/release-2.4-m1-ephemeral-tw.sh` + `...-tw-vm.sh` (Tumbleweed VM)
prove the composition:

```text
root docker-helper stand-in (probe shell)
  | narrow line protocol over 0660 root:builder manager socket
  v
builder-manager prototype (runs AS the unprivileged builder user)
  | START <op_id> / STOP <op_id> / PURGE (canonical op_ + 32-hex grammar only)
  v
setsid rootlesskit --net=slirp4netns --copy-up=/etc --disable-host-loopback
  v
ephemeral rootless buildkitd
  op-private --root, op-private 0660 control socket
  ^ buildctl runs client-side (root) with DOCKER_CONFIG=session config
```

Probed properties (all PASS on all three targets):

1. protocol strictness: malformed operation ids and unknown commands are
   refused; START returns only the operation-private socket path;
2. socket isolation: the manager socket and every per-op socket deny
   `nobody` and an agent-side user; root can drive both;
3. ephemeral state: build A writes `EPHEMERAL-A-SECRET` through a cache
   mount; the instance is destroyed; a fresh operation with the same cache
   id observes `missing` (with the mandatory negative self-test: A's secret
   provably exists in A's op-private state before teardown);
4. ordinary layer cache: the second operation's RUN step is not `CACHED`
   from the first operation's build (only the pulled base-manifest step
   reports CACHED, which is content dedup, not cross-operation state);
5. teardown: after STOP, op state dir, runtime dir, socket, and process
   tree are all gone, and the surviving concurrent op is unaffected;
6. concurrency: two operations run simultaneously with distinct sockets and
   distinct state roots; both outbound networks work (HTTP 200); both
   host-loopback negatives hold; killing one instance does not affect the
   other; the manager refuses a third START immediately at its hard ceiling
   of 2 (no queue, no waiting);
7. crash/restart: manager restart purges all operation-private
   runtime/state; a STOP for a purged op answers `absent` (no stale socket
   accepted as live); a post-restart operation is fresh and self-contained;
8. M0 invariants hold on the ephemeral composition: build RUN maps to a
   nonzero host-side uid inside the builder's subordinate range (0→1002
   Ubuntu, 0→1001 Tumbleweed), the userns differs from the host's, no
   docker.sock is visible from build RUN, the host-root marker file is not
   readable, host loopback is unreachable, outbound works, `--network=host`
   and `--security=insecure` are refused, and a failed build leaves no
   usable target image.

### Main-daemon hardening

`docker-helper.service` keeps `NoNewPrivileges=true` (the shipped unit is
untouched; `packaging/systemd/system/docker-helper.service:45`). The
builder-launch mechanics live entirely in the separate unprivileged builder
identity, so the root daemon gains no user-namespace manipulation, no
CAP_SYS_ADMIN, and no generic systemd/D-Bus authority. This satisfies the
mandatory NNP constraint and rejects alternatives D (root daemon spawning
rootlesskit directly) and E (transient-unit control from the root daemon)
in their required-weakening forms.

### Results

| Target | Result | Evidence |
|---|---|---|
| Ubuntu 24.04 (hosted runner) | **PASS** | run [35650934104](https://github.com/kivarun/docker-helper/actions/runs/35650934104), artifact `release-2.4-m1-ephemeral-35650934104-1` |
| Ubuntu 26.04 (hosted runner) | **PASS** | run [35650934104](https://github.com/kivarun/docker-helper/actions/runs/35650934104), artifact `release-2.4-m1-ephemeral-2604-35650934104-1` |
| openSUSE Tumbleweed (QEMU/KVM VM) | **PASS** | run [35650934104](https://github.com/kivarun/docker-helper/actions/runs/35650934104), artifact `release-2.4-m1-ephemeral-tw-35650934104-1` |

Tested commit: `f337603ecd74d8a35ed9de440aabf60717d621fc` (probe-side fixes
after 266e514; the authoritative matrix run's head SHA). Shared-daemon
evidence from the same run: artifacts `release-2.4-m1-global-35650934104-1`. AppArmor
userns restriction remained enabled (sysctl `=1`) on both Ubuntu targets;
the Tumbleweed guest (SELinux, kernel 7.2) needed the manager-spawn
`SSL_CERT_FILE` CA handling for per-instance buildkitd (same rootlesskit#225
root cause M0 proved) and passed without sysctl relaxation.

### Alternatives disposition

- **A — one global persistent buildkitd: REJECT.** Live cross-session
  cache-mount leak + cross-client layer-cache reuse on the proven
  composition; no upstream tenant-isolation contract (see above).
- **B — per-Session BuildKit instance: EVALUATE, DO NOT IMPLEMENT.**
  Zero cross-Session state, but introduces a persistent per-Session cache
  lifecycle, stale-Session cleanup, aggregate disk budgeting, and more
  lifecycle coupling for no M1-proven benefit over per-operation instances
  at the current 2-concurrent-build ceiling.
- **C — per-Build-Operation ephemeral BuildKit instance: ACCEPT (M1
  candidate).** Zero cross-operation builder state, no BuildKit GC
  subsystem needed, the existing Operation already owns the lifetime, and
  at most two instances exist under `maxConcurrentBuildsGlobal=2`.
- **D — docker-helper directly spawning rootlesskit: REJECT** as the
  production launch path; it would move userns/rootlesskit mechanics into
  the root daemon and pressure `NoNewPrivileges=true`/confinement.
- **E — systemd instance/transient-unit control directly from
  docker-helper: REJECT** in the form that grants the root daemon generic
  systemd/D-Bus authority. (An unprivileged manager service remains a
  possible backend for the same candidate-C lifecycle.)

### Recommended refined architecture

Keep the M0 composition A runtime envelope (dedicated unprivileged builder
user, rootlesskit slirp4netns, op-private control socket, buildctl
client/local transport, `type=docker` export) but change the state/lifecycle
model to candidate C: a `docker-helper-builder` manager service (dedicated
builder identity, narrow `START/STOP` protocol, canonical operation-id
grammar, startup purge) owns ephemeral per-build-operation BuildKit
instances; registry credentials remain client-side in root docker-helper via
the existing Session Docker config; Release 2.4 explicitly does not promise
persistent build cache. The 2.4 implementation plan builds on this frozen
selection.

## P4-A1 production unit-boundary record — 2026-09-24

P4-A1 installed and proved the REAL production builder service boundary
before packaging: the proposed
`packaging/systemd/system/docker-helper-builder.service` unit runs the real
`docker-helper builder serve` manager (identity, subuids, and subgids
provisioned by the real `packaging/scripts/lib/provision-builder.sh`), which
drives the real per-operation RootlessKit + pinned BuildKit payload. The
proof scripts (`scripts/release-2.4-p4a1-proof.sh` + Tumbleweed guest/
VM-side scripts) and the workflow
(`.github/workflows/release-2.4-p4a1-builder-unit.yml`) follow the M0/M1
harness pattern. Docker on the Ubuntu runner and Docker in the Tumbleweed
guest are not part of the passing path; the buildctl export tar and the
container sanity probes run only when the Engine is reachable.

Proven properties:

1. provisioning is idempotent and fail-closed: the dedicated
   `docker-helper-builder` identity (nologin shell, home = state root), one
   subordinate range of 65536 written to both `/etc/subuid` and `/etc/subgid`
   through `usermod` delegation only; re-run is a no-op. Observed
   allocations: 999/987 with subids `231072:65536` (Ubuntu 24.04),
   475/475 with `165536:65536` (Tumbleweed);
2. the unit starts the manager with the recorded NoNewPrivileges exception
   (`NoNewPrivs: 0`) and the minimal capability floor
   (`CapBnd = 0x802000c2`, `CapEff = 0`);
3. during a real `FROM alpine:3.20` HTTPS build, the manager, the
   RootlessKit leader, the buildkitd child, and the unanchored
   slirp4netns descendant are ALL members of
   `0::/system.slice/docker-helper-builder.service`; the buildkitd
   `uid_map` maps in-namespace root to the builder uid and the provisioned
   subordinate range (0→999, 1→231072 on 24.04; 0→475, 1→165536 on
   Tumbleweed); the child environment is the explicit production contract
   (HOME=state root, USER=builder, per-op XDG_RUNTIME_DIR, fixed PATH,
   SSL_CERT_FILE=resolved bundle);
4. killing the manager (SIGKILL during an active build) restarts the unit
   and settles ALL old children including the unanchored slirp4netns
   (control-group kill); the new generation's startup purge removes the
   residue the wiped runtime tree left behind; a fresh build round-trips;
5. a service stop during an active build settles all children bounded by
   `TimeoutStopSec=30s`; the persistent state residue is cleaned by the
   next start's purge (unit membership is NOT per-op ownership);
6. the startup invariant end to end: ambiguous pid-file-less residue
   (the pre-pid-write crash window and the systemd-wiped runtime tree) and
   truncated pid files are removed at start over the unit boundary, while
   noncanonical ops entries are preserved; the legacy fail-closed purge
   semantics remain unchanged outside the unit boundary;
7. the resolved `SSL_CERT_FILE` is real-path-resolved and readable inside
   the child mount namespace; a real HTTPS build exercises the bundle.

### The capability floor is failed-proof derived

The plan §5 floor (`CAP_SETUID CAP_SETGID`) was insufficient on kernel
6.17; three live failures determined the minimal floor, each fixed only
after the failure:

- `CAP_DAC_OVERRIDE` — the setuid-root `newuidmap` open of the child's
  `/proc/<pid>/uid_map` failed EACCES (run 35981016063);
- `CAP_SYS_ADMIN` — the kernel `map_write` gate ("adjusting namespace
  settings requires capabilities on the target") failed EPERM (run
  35981655091);
- `CAP_SETFCAP` — `verify_root_map` requires the opener to hold it over
  the parent namespace to map in-namespace root (added with the same
  run's fix).

### Other live corrections to the composition

- `USER=` must be part of the explicit child environment: buildkitd
  rootless-mode detection (`isRootlessConfig`) requires a non-root
  `$USER`; without it the daemon's OTEL trace controller mkdirs
  `/run/buildkit` and fails (run 35982869630).
- The per-op socket readiness contract is the containerd
  `sys.GetLocalListener` shape: 0660 builder:builder, never
  world-accessible (run 35983853898; M0 recorded the same `srw-rw----`).
- The unit must not place locked submounts under `/proc`:
  `ProtectKernelTunables`, `ProtectKernelLogs`, and `ProtectHostname` each
  add such submounts, which disqualify the inherited procfs mount from the
  kernel `mount_too_revealing` visibility rule and deny the RUN
  containers' fresh procfs mounts EPERM (runs 35985523417 and 35987764605;
  the direct control composition, run green at 35988943581, isolated the
  unit environment as the differentiator).
- The manager's per-op residue scan now excludes its own process (the
  unit-membership classification matched the manager itself and the purge
  signaled its own group; run 35988943581).

### Capability floor security implications (P4 packaging review, 2026-09-24)

The frozen builder bounding set
(`CAP_DAC_OVERRIDE CAP_SETGID CAP_SETUID CAP_SYS_ADMIN CAP_SETFCAP`) is
reviewed explicitly before packaging freezes it; this section records what
the floor means at the unit's trust boundary.

- **The bounding set is the elevation ceiling for every setuid-root helper,
  not just the intended ones.** With `NoNewPrivileges` deliberately absent,
  exec'ing any setuid-root binary from the unit yields euid 0 with
  permitted/effective caps = inheritable ∪ bounding (capabilities(7)
  root-exec rule; systemd grants the unit no inheritable/ambient
  capabilities, so in practice exactly the five floor capabilities).
  `newuidmap`/`newgidmap` get exactly what they need (proven); so does every
  other setuid-root executable the builder identity can invoke.
- **What CAP_SYS_ADMIN grants that elevation.** The P4-A1 failed proof
  (kernel ≥ 6.17 `map_write` gate, run 35981655091) forces CAP_SYS_ADMIN
  into the *initial* namespaces for the setuid-root mapping write. In that
  context CAP_SYS_ADMIN is host-mount authority (mount/umount, namespace
  operations); together with CAP_DAC_OVERRIDE a setuid-root helper such as
  util-linux `mount` (setuid-root on the supported targets) can mount
  attacker-controlled filesystem images. That is the concrete residual
  exposure of the floor.
- **Why the exposure is bounded.** The elevation is reachable only by code
  running as the dedicated builder identity on the host: the manager (whose
  own capabilities are zero — CapEff 0, proven) and its legitimate children.
  Build-context code executes inside the per-operation user namespace and
  cannot reach the host builder identity. The builder identity holds no
  docker.sock/credential authority, is not a sudo/wheel member, and the
  PATH contract restricts helper resolution to the fixed system paths plus
  the product payload directory. The setuid-root binaries' own gates
  (`su`/`sudo` authentication, `passwd` account checks) still apply.
- **No silent widening.** The five entries are each a failed live proof;
  `TestBuilderSystemUnitFile` pins the exact set and refuses any
  difference. Further widening requires another failed live proof and
  explicit review. The alternative (a lower floor) fails the composition on
  kernel ≥ 6.17 with the recorded EPERM; the alternative (root-side build
  execution) is the boundary Release 2.4 exists to remove.

### Results

| Target | Result | Evidence |
|---|---|---|
| Ubuntu 24.04 (hosted runner) | **PASS** | run [35991353450](https://github.com/kivarun/docker-helper/actions/runs/35991353450), artifact `release-2.4-p4a1-2404-35991353450-1`, digest `sha256:0cd302fd65abe004154cc8cf33c699fb8f12c4e18398aa80f3d64b34e4560466` |
| openSUSE Tumbleweed (QEMU/KVM VM) | **PASS** | run [35991353450](https://github.com/kivarun/docker-helper/actions/runs/35991353450), artifact `release-2.4-p4a1-tw-35991353450-1`, digest `sha256:5fb89075a7fb80be26ea6110f0f4cd62d73cd0f029ffbb6995ec121d969ed0d2` |

Tested commit: `1a625f82896c4d3c841bcaea911bc8c50ebe5d42`. Binary SHA-256
`5f11b22796f954ccea52ba56870e479db3576a899f29739eab426fe0c0e52e49`; unit
`59035ffd88e4499c41f1a42462b7e7c9bae0c6d733b10a8a1d256d98807e32f5`;
provisioner `5ede306828ebffea76e095c539b4b2b930d7b2d333e101d2e08ae89c03594945`;
pinned BuildKit v0.33.0
(`157da954fa081d9ec4f063d62029fbbf12437c1d47ab63080594eae5a85b36f2` buildkitd,
`0b45ae3696f836bf711dbd78138e403924d7733f0b2328ba29a7fcf9ad5f1dfd` buildctl,
`0acdd302ddc5540b2e445b683661bfada9935c702f9008ffb0481abcda16c9b4`
buildkit-runc), tarball digest
`b6242896d343100808dcbe37565caf381e0a444a6a83d7255926bb1519248ead`.
Environments: Ubuntu 24.04.5 LTS, kernel 6.17.0-1022-azure, systemd 255,
`apparmor_restrict_unprivileged_userns=1` (unchanged default; the passing
path does not relax it); openSUSE Tumbleweed 20260922, kernel 7.2.6-1,
systemd 261, SELinux enabled, no user-namespace restrict sysctl.

### Remaining after P4-A1

- Ubuntu 26.04 target (the M0/M1 matrix third target) is not yet exercised
  by the P4 workflows;
- the DEB/RPM/tarball packaging lifecycle and its install-time proofs
  (Ubuntu 24.04 + Tumbleweed, generated packages) are the P4 packaging
  scope; Ubuntu 26.04 join and the main-unit ordering touch-up are part of
  that packaging landing;
- MAC policy (AppArmor/SELinux) for the builder service is P5;
- the daemon startup manager verification / shutdown cleanup integration
  (P6) and the final hostile-build UAT matrix (P7) remain open.

## P5-S1 SELinux builder-bootstrap record — 2026-09-25

P5-S1 proved the SELinux bootstrap boundary for the builder service on the
enforcing openSUSE Tumbleweed Cloud qcow2 through the GENERATED candidate
RPM + tarball (`scripts/release-2.4-p5s1-tw.sh`, orchestrated by
`scripts/release-2.4-p5s1-tw-vm.sh`, workflow
`.github/workflows/release-2.4-p5s1-builder-mac.yml`). The proof covers the
service bootstrap MAC only — the manager domain, its private runtime/state
types, and the forbidden-surface negatives. Full child-process MAC
(rootlesskit/buildkitd/slirp4netns inside the builder domain) is the
separate P5-S2 task and is deliberately NOT granted here.

### Proven properties

1. **Enforcing bootstrap (P2).** The manager runs in
   `system_u:system_r:docker_helper_builder_t:s0` (unit
   `SELinuxContext=` binding), `manager.sock`, `/run/docker-helper-builder`,
   and `/var/lib/docker-helper-builder` carry the dedicated
   `docker_helper_builder_runtime_t`/`docker_helper_builder_state_t` types,
   the manager holds `CapEff 0` with the frozen `CapBnd 0x802000c2` floor
   and `NoNewPrivs: 0`, and the unit-cgroup boundary is active. The
   enforcing bootstrap is preceded by a permissive harvest round (P2h) that
   captured 158 builder-domain AVC records as S2 evidence with zero
   forbidden-surface attempts, and by an audit-pipeline sanity probe (P2a)
   that proves a deliberate builder-domain denial is visible in the audit
   source before any phase depends on AVC evidence.
2. **Enforcing transport (P3, P6).** The root daemon performs a real
   manager RPC roundtrip through the build attempt while the build is
   EXPECTED to fail at the documented child-process boundary. The transport
   proof is the op-ID-matched pair: the daemon journal's `builder_start`
   stage line AND the manager journal's `START <op_id>` handling for the
   SAME operation ID (`op_51ca5bc87dfd35a39943de5fcf2e6ff7` pre-relabel,
   `op_9a78d76ad72342a01bdf210933a33ba8` post-relabel), with both services'
   journals and the AVC window captured for the exact attempt window. An
   arbitrary `docker_build_failed` terminal state is never accepted as the
   RPC proof: the streamed op buffer carries child output only, so the
   daemon-side stage evidence is read from the daemon journal.
3. **Forbidden-surface negatives (P5).** Enforcing AVC evidence that the
   builder domain cannot read the helper config/admin token, reach the
   daemon socket, connect to docker.sock, or read a Session workspace file
   (transient units bound to `docker_helper_builder_t`, uid-0, so DAC
   cannot short-circuit the MAC check).
4. **Upgrade relabel (P6).** Poisoned builder state labels are corrected by
   the existing RPM `%posttrans` deployment lifecycle
   (`rpm -U --replacepkgs`), the builder keeps serving across the upgrade,
   and the transport pair is re-proven post-relabel. The enforcing
   child-process failure is fixed as S2 evidence: the known P3 AVC —
   `rootlesskit` denied `{ lock }` on
   `docker_helper_builder_state_t:file`
   (`ops/<op_id>/rootlesskit-state/lock`, `permissive=0`), corroborated by
   the child's own `[rootlesskit:parent] error: failed to lock ...`
   journal tail.
5. **Tarball lifecycle (P7).** `install-system.sh` on the enforcing host
   loads the module and labels the builder trees; the poisoned-label rerun
   proves the relabel path; the manager process context, the
   runtime/state root labels, and the `manager.sock` label are asserted
   after both the fresh install and the rerun; `docker-helper selinux
   check` reports `SELinux policy valid`.

### The installer reinstall contract gap (reported, not fixed here)

The tarball rerun exposed an `install-system.sh` reinstall-path gap: the
installer stops only the main unit before replacing the binary, so a
still-running builder service (which execs the same
`/usr/bin/docker-helper` binary) makes the binary replacement fail with
`Text file busy`. The proof harness applies the same explicit builder stop
the shipped uninstaller performs before the rerun; the installer gap
belongs to the P4 packaging scope and needs its own fix — not silently
narrowed here.

### Results

| Target | Result | Evidence |
|---|---|---|
| openSUSE Tumbleweed (QEMU/KVM VM, enforcing SELinux) | **PASS** | run [36146864554](https://github.com/kivarun/docker-helper/actions/runs/36146864554), artifact `release-2.4-p5s1-tw-36146864554-1`, digest `sha256:17e343590e1d1d9127709f141f7d01172bb4bd2eb3a1b62cabe93cc771e34727` |

Tested commit: `94ffcb50e7332b5d6caa9eb4bf75ce5c3a72a017`. Candidate set
(`release-2.4-p5s1-candidate-36146864554-1`, digest
`sha256:dddf73139ccf834763efa8cf0bf98f90359993eb8e3ffa10b70c44c97e89ed13`):
RPM `c39f2df32452bf4210e713207bc1998621dc5390a7b899cf5230387f742166ed`,
tarball `f98f7b697073bb4cb1a215aa44d6781b558521b9475b6b191b02b1901e82d4b9`.
Environment: openSUSE Tumbleweed 20260923, kernel 7.2.6-1-default, SELinux
enforcing throughout, auditd enabled for fresh AVC evidence (no sysctl
relaxation anywhere on the passing path). The enforcing build attempts'
nonzero exits and the permissive round's exit code are recorded in the
artifact `digests.txt`.

### Remaining after P5-S1

- **P5-S2 — full child-process MAC:** the rootlesskit `{ lock }` grant on
  the builder state file and the rest of the rootlesskit/buildkitd/slirp4netns
  child surface, each entry evidence-driven from the harvested AVC windows
  (the 158-record permissive harvest is the evidence base);
- the AppArmor builder profile for the Ubuntu targets (the SELinux S1
  boundary has no AppArmor counterpart yet);
- the installer reinstall contract gap above (P4 packaging scope).

## Builder authority

The sandbox is narrower than exposing Docker authority to the caller.

An untrusted agent still never receives `docker.sock`, BuildKit control sockets,
or a generic builder API. docker-helper remains the capability owner and sends
only the build operation implied by its public API.

The sandbox must not grant agent-controlled build steps unrestricted host
mounts, privileged entitlements, host PID/IPC namespaces, host devices, or
other escape hatches that recreate rootful host authority through a different
surface.

Any BuildKit/Docker entitlement that expands the sandbox is denied by default
and may be introduced only through an explicit docker-helper policy decision.

## Network boundary

Build networking is a separate policy dimension from filesystem/identity
isolation.

Release 2.4 must explicitly document and test the builder's network position.
The feasibility/design pass must determine which network modes are supported
and which party owns that choice. At minimum:

- the caller cannot silently escalate to host networking or another privileged
  builder entitlement;
- the effective build network mode is server-owned policy;
- the resulting network position is documented as part of the build security
  contract;
- a future egress allowlist, proxy, or network-deny capability can narrow this
  boundary without requiring Dockerfile analysis.

Release 2.4 does not commit to domain/IP allowlists merely to close the builder
execution boundary. If outbound filtering is later required, it belongs at the
network/sandbox layer.

## Image policy is separate

A future image allowlist/signature policy answers which base/result images may
be used or executed. It does not by itself constrain what an allowed Dockerfile
can execute during `RUN` and is therefore not a substitute for the build
sandbox.

Image policy and build isolation may compose later, but neither should be made
the hidden implementation owner of the other.

## Compatibility boundary

Release 2.4 should preserve ordinary Dockerfile compatibility as far as the
selected sandbox backend permits. A build may continue to believe it is root
inside its build environment so ordinary package-install/chown/chmod workflows
work, provided that root identity is contained by the accepted sandbox.

The public build API should not gain backend-specific rootless/BuildKit knobs
unless a concrete caller decision is required. Backend mechanics remain behind
a docker-helper-owned build boundary.

Private-registry credentials, trusted-CA material, build arguments, context
filesystem policy, output bounds, cancellation, and audit secrecy remain under
their existing owners. The sandbox must not create a second credential or
filesystem-policy model.

## Relationship to Release 2.3 and Release 3

Release 2.3 is a prerequisite because it removes the user-mode daemon and
leaves one deployment/security model. Release 2.4 therefore needs to solve
builder isolation only for the root-owned system service with mandatory MAC.

Release 3 then builds managed-container lifecycle and Engine-API integration on
top of an already explicit build execution boundary. Engine/API migration must
preserve the 2.4 sandbox contract rather than accidentally returning builds to
a weaker rootful execution path.

## Acceptance direction

Release 2.4 is complete only when:

- one build-sandbox owner is selected and documented after a real feasibility
  proof on supported distributions (the M0 proof above closed the feasibility
  half; implementation acceptance remains open);
- agent-controlled build `RUN` code may execute as sandbox-root but cannot use
  host-root authority;
- no Dockerfile parser/filter is introduced as the security boundary;
- privileged builder entitlements and host-network escalation are unavailable
  unless explicitly server-authorized by a separately accepted contract;
- ordinary package-install Dockerfiles still work inside the sandbox;
- workspace/context restrictions remain enforced and cannot be bypassed through
  builder mounts;
- private-registry and other build secrets do not gain new exposure through the
  sandbox transport;
- hostile build UAT demonstrates the boundary on the exact release candidate;
- failure to establish the sandbox is fail closed, never silent fallback;
- current architecture, README/help/man, and Release 3 design records describe
  the same build boundary.

## Explicit non-goals

Release 2.4 does not, by itself, add:

- Dockerfile semantic filtering;
- a general-purpose BuildKit API;
- arbitrary builder configuration supplied by the agent;
- remote builds;
- build-farm scheduling;
- generic egress/domain allowlists;
- image allowlists/signature enforcement;
- Release 3 managed-container lifecycle;
- a replacement Docker daemon architecture.
