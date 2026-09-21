# Release 2.4 Build Sandbox

## Status

Accepted architectural direction for Release 2.4. Detailed implementation
planning begins after Release 2.3 removes user-mode daemon support.

The mandatory M0 build-sandbox feasibility probe is CLOSED (2026-09-21):
composition A — a dedicated unprivileged builder user running rootless
BuildKit under rootlesskit with slirp4netns networking and a client/local
buildctl context transport — proved the required builder boundary on Ubuntu
24.04, Ubuntu 26.04, and openSUSE Tumbleweed. See the M0 closure record below
for the probe contract, mechanics, and authoritative evidence. The 2.4
mechanism selection freezes on this composition unless the architectural
review of the implementation plan shows a concrete deficiency.

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
