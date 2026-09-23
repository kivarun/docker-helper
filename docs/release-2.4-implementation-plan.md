# Release 2.4 Implementation Plan

Status: DRAFT v2 — awaiting architectural review (correction pass applied;
no production code implemented by this document). M0 (feasibility,
composition A) and M1 (shared-state tenancy proof and per-operation
ephemeral alternative) are closed in
[`release-2.4-build-sandbox.md`](release-2.4-build-sandbox.md).

Corrected M1 record commit: `33e2402` ("M1 record: correct the tested SHA and
the layer-cache claim") on `release/2.4`, parent `f54fe48`.

## 0a. Correction pass (plan review 1) — changes applied in this revision

1. Builder NNP: `docker-helper-builder.service` MUST NOT set
   `NoNewPrivileges=true` (RootlessKit needs newuidmap/newgidmap, whose
   elevation NNP disables). Main service NNP stays. Recorded narrow
   exception + `CapabilityBoundingSet=CAP_SETUID CAP_SETGID` evaluation
   gated on a live unit proof + mandatory unit UAT assertions
   (`NoNewPrivs` 1/0 + subordinate-ID mapping proof). See §5.
2. Service dependency: `Requires=` removed; weak `Wants=`/`After=`
   coupling; builder-unavailable fails BUILD closed only; dynamic
   recovery without main-daemon restart; no rootful fallback. See §5, §3a.
3. Manager RPC: bounded dial/read/write deadlines; START ambiguity →
   idempotent STOP on a fresh server-owned cleanup context (never the
   cancelled Operation context); lost-STOP re-STOP convergence; four
   ambiguity tests. See §3, §9.
4. Subuid/subgid mutation: docker-helper computes/validates the range
   but delegates the database mutation to upstream `usermod
   --add-subuids/--add-subgids`; no direct `/etc/subuid`/`/etc/subgid`
   rewriting; cross-distro tooling proof gate; stop for architecture
   review if no common safe primitive exists. See §6.
5. Commit vs cleanup: successful `docker tag` is the irreversible
   success linearization point; `docker rmi <internal>` is bounded
   idempotent cleanup whose failure never downgrades a committed build.
   See §11.
6. Result codes: public `shutdown` code removed (does not exist in the
   current contract); shutdown-terminated builds report
   `docker_build_failed`; `terminationShutdown` stays internal. See §13.
7. Process-tree identity: `instance.pid` is the `setsid` RootlessKit
   session/process-group leader; STOP owns and reaps the complete group;
   descendant-absence proofs (rootlesskit/buildkitd/slirp4netns) with
   negative self-tests. See §4.
8. Image-reference validation: Option B selected — canonical upstream
   Docker/Distribution reference parser as a request-time grammar gate
   with differential tests against Docker; no home-grown grammar.
   See §11.
9. AppArmor transition: confined builder executes the DISTRO rootlesskit
   via explicit transition into the distro profile (no parallel userns
   policy without denial evidence), proven under
   `apparmor_restrict_unprivileged_userns=1`. See §14.

## 0. Corrections recorded before this plan

- The M1 closure record's tested SHA is
  `f337603ecd74d8a35ed9de440aabf60717d621fc` (run 35650934104 head SHA); the
  previously recorded digest was a typo.
- The M1 closure record's shared-daemon layer-cache claim now states that
  ordinary layer-cache reuse was **NOT proven** in that run (no `CACHED`
  verdict on the nondeterministic `RUN`; value coincidence is not evidence).
  The REJECT of alternative A stands on the live cache-mount cross-client
  leak and the absent upstream tenant-isolation contract.

## 1. Frozen architecture (from M0/M1)

```text
docker-helper root daemon
  NoNewPrivileges=true (unchanged)
        |  narrow manager protocol (Unix socket, root-only DAC)
        v
docker-helper-builder service
  dedicated unprivileged system identity (docker-helper-builder)
        |  one ephemeral instance per Build Operation
        v
RootlessKit --net=slirp4netns --copy-up=/etc --disable-host-loopback
        v
rootless buildkitd (upstream payload, pinned version)
  op-private runtime, op-private state, op-private socket
```

Then root docker-helper runs the client side: `buildctl` with the Session
Docker config and the staged context, `--output type=docker` to a
server-owned tar, `docker load`, `docker tag` commit, internal-tag cleanup.

Frozen non-negotiables:

- no persistent BuildKit cache;
- no per-Session builder;
- no global BuildKit daemon;
- no direct root-daemon rootlesskit spawning;
- no generic systemd/D-Bus authority in docker-helper;
- build API/CLI contract unchanged;
- single binary: the builder manager is a role of the same `docker-helper`
  binary (`docker-helper builder serve`).

## 2. Implementation phases (ordered)

| Phase | Scope | New/changed files |
|---|---|---|
| P1 | Operation process-slot refactor (sequential child stages under the existing Operation owner) + mandatory cancellation-race tests | `operation.go`, `operation_process_test.go` (new), small touches in `build.go`/`run.go` call sites |
| P2 | Builder-manager backend role of the existing binary (`builder serve` subcommand, manager runtime/state/protocol) | `builder_manager.go` (new), `builder_manager_protocol.go` (new), `builder_manager_test.go`, `cli.go`, `main.go` |
| P3 | Build execution path: buildctl mapping, export tar, image handoff transaction, commit linearization | `build.go` (rewrite of the child stage), `build_handoff_test.go` (new), `build_mapping_test.go` (new) |
| P4 | Identity + subuid provisioning (one owner), systemd units, packaging (DEB/RPM/tarball), BuildKit payload shipping | `packaging/**`, `packaging_test.go` additions, `build-static.sh`/`build-bundle.sh`/`build-packages.sh` |
| P5 | MAC policy (AppArmor + SELinux) for daemon + builder service, evidence-first | `packaging/apparmor/**`, `packaging/selinux/**`, `apparmor_test.go`, `selinux_fcontext_test.go`, `scripts/check-selinux-policy.sh` |
| P6 | Startup fail-closed wiring (daemon verifies manager), shutdown/cleanup integration, docs | `main.go`/`app.go` startup, `operation_shutdown_test.go` additions, `docs/architecture.md`, `docs/release-2.4-build-sandbox.md`, `docs/roadmap.md`, `README.md`, `docs/man/*` |
| P7 | UAT: promote M1 proofs into release gates + packaging lifecycle UAT | `scripts/uat-*.sh` additions, `.github/workflows/uat-*` |

Each phase is independently testable; P1 is deliberately first because every
later stage rides on the process-slot invariant.

## 3. Exact manager protocol

Transport: Unix stream socket
`/run/docker-helper-builder/manager.sock`, mode `0600`, owner
`docker-helper-builder:docker-helper-builder`. Root docker-helper connects
via root DAC authority (root bypasses the 0600 check); ordinary users get
EACCES. MAC must explicitly permit the daemon to connect (see §14/§15).

Wire format: one request per connection, one response line.

```text
START <operation_id>\n
STOP <operation_id>\n
PURGE\n
```

`<operation_id>` is the canonical Operation ID grammar already owned by
`operation.go`: `op_` + exactly 32 lowercase hex characters
(`operationIDPrefix`, `operationIDHexLength`). The manager validates the
same grammar independently (defense in depth); the daemon never sends
anything else.

Responses:

```text
START -> OK | ERR bad_operation_id | ERR operation_exists | ERR builder_at_ceiling | ERR internal
STOP  -> OK | OK absent | ERR bad_operation_id | ERR internal
PURGE -> OK
```

START must NOT return a filesystem path. The socket location is
deterministically derived by both sides:

```text
/run/docker-helper-builder/ops/<operation_id>/buildkitd.sock
/var/lib/docker-helper-builder/ops/<operation_id>/
```

Root computes the socket path itself, and before first use validates the
expected endpoint (exists, is a socket, owner is the builder identity, mode
is the expected 0600 builder-owned mode). No unprivileged manager response
becomes root-side path authority.

Refusal semantics: `ERR builder_at_ceiling` is an internal backend failure
inside an already-reserved Build Operation (capacity is owned by the
daemon; `maxConcurrentBuildsGlobal = 2` in `operation.go` is the single
ceiling owner), surfaced as `docker_build_failed` — not a new public
capacity topology.

### RPC deadlines and ambiguity handling

Every manager call gets bounded dial/read/write deadlines (single values
owned as implementation constants, not public configuration):

```text
dial    2s
write   2s
read    60s for START (instance launch + bounded readiness wait)
read    10s for STOP / PURGE
```

START is side-effecting. If the response is lost, a deadline or
cancellation fires after the request was transmitted, or the outcome is
otherwise ambiguous, the root daemon MUST treat the operation as possibly
live and issue idempotent `STOP <operation_id>` using a FRESH
server-owned cleanup context (`context.WithTimeout(context.Background(),
...)`) — never the already-cancelled Operation context, which must not be
reused for cleanup work. STOP is idempotent (`OK absent` when nothing
lives), so this converges to a clean state in every ambiguity case:
no live op instance, no op state, no op socket. The ambiguous START is
surfaced as `docker_build_failed`.

The `OK absent` answer is ordered against START dispatch (START/STOP
fence): an accepted START registers a dispatch fence before its
reservation, the fence settles exactly when the reservation is installed
or the START is refused, and a STOP for the same id waits the fence out
instead of reporting convergence — it then converges whatever the START
created (or reports absent when the START was refused). A completed
compensating STOP therefore cannot be overtaken by an earlier accepted
START of the same id. The fence is transient in-flight state (removed
when the START settles), not a tombstone.

The dispatch fence alone covers STARTs already handed to the manager
operation; an accepted-but-unparsed START connection is invisible to it.
The manager therefore also keeps an accept-order ingress barrier: every
accepted connection is registered pending synchronously before the next
connection can be accepted (Linux dequeues unix-socket connections in
connect order, so accept order equals submit order), and a pending
connection settles exactly when its request's admission decision is
visible under the manager lock — for START, its refusal or dispatch-
fence registration, never its launch; for STOP/PURGE, dispatch; for
unauthorized, malformed, dead, or timed-out connections, handler exit.
Before answering `OK absent`, a STOP settles every connection accepted
before its own and then re-checks the map and fences, so no
accepted-but-unparsed START of the same id can reserve and launch after
the STOP reported convergence. The barrier is transient (no pending
entry survives its connection) and bounded (every older connection
settles within its 2s read window at the latest); it holds only the
absent answer, never instance convergence, and never a readiness cycle.

The same rule applies to a lost STOP response: after a STOP
deadline/ambiguity, re-issue STOP once on the fresh cleanup context; an
`OK absent` reply then closes the ambiguity. PURGE failures at daemon
startup are startup diagnostics (fail closed for builds).

Mandatory ambiguity tests (`builder_manager_rpc_test.go`):

- START accepted, reply lost → daemon issues STOP, op instance/state/
  socket absent afterwards;
- cancellation during the START readiness wait → same cleanup
  convergence, `cancelled`;
- timeout after the START request write → same cleanup convergence;
- STOP response lost → re-STOP converges to `absent`;
- every case asserts the live instance/state/socket are GONE (with the
  negative self-test: the instance provably existed before the
  convergence in the accepted-reply-lost case).

### Builder lifecycle semantics

- START: derive op-private runtime/state paths from the operation id
  (deterministic layout, §4); ensure they are absent (a previous
  non-reaped instance for the same id is an internal error: refuse with
  `ERR internal` rather than adopt); create dirs; launch
  `setsid rootlesskit` as the builder identity; wait bounded readiness
  (socket exists + ownership/mode validation data recorded by the
  manager); reply `OK`.
- STOP: kill the exact op process group (the `setsid` RootlessKit
  session leader, see §4), reap, remove op runtime/state/socket; reply
  `OK`. Idempotent: already absent → `OK absent`; the absent answer waits
  out any accepted-but-unsettled START of the same id first (START/STOP
  fence above). The convergence answer additionally awaits the old
  launch's settlement (launch quiescence): every post-claim launch step
  (directory creation, spawn-phase claim check, failed-start convergence
  with its idempotent dir re-removal) runs strictly before the OK, so the
  OK instant carries zero live processes and zero path residue, and an
  immediate same-ID START afterwards is admitted against clean paths.
  There is exactly ONE child Wait owner per leader; stop attempts never
  call Process.Wait and reap through that owner's signal. The OK is
  truthful: the group is proven dead (bounded escalation to SIGKILL plus
  a bounded finalize wait), the leader reaped, and the exact directory
  removal verified. A stop attempt that cannot fully converge replies
  `ERR internal` and RETAINS the map entry and its ceiling capacity for
  retry through the same stop owner; an unexpected leader exit settles
  the remaining group members before removing directories.
- PURGE: terminate every builder-owned op process group, remove all
  op-private runtime/state; reply `OK` only after each converged
  instance's launch settlement (same quiescence contract as STOP) and
  with the same truthful non-convergence semantics (`ERR internal`,
  retained entries). No adoption, no reconciliation, no persistent cache
  recovery.
- Manager startup performs PURGE semantics before accepting requests.

### Backend launch mechanics (P2-refined)

Fixed production paths (canonical constants, no config, no PATH lookup
for rootlesskit/buildkitd):

```text
manager socket:        /run/docker-helper-builder/manager.sock
runtime root:          /run/docker-helper-builder
state root:            /var/lib/docker-helper-builder
rootlesskit:           /usr/bin/rootlesskit
bundled buildkitd:     /usr/libexec/docker-helper/buildkit/buildkitd
```

RootlessKit may find its distro helpers (`newuidmap`, `newgidmap`,
`slirp4netns`) through one manager-owned fixed PATH:
`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin`. No arbitrary
service environment is inherited into child processes; the per-instance
environment is explicitly constructed:

```text
HOME=/var/lib/docker-helper-builder
XDG_RUNTIME_DIR=/run/docker-helper-builder/ops/<op_id>
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
SSL_CERT_FILE=<resolved system CA bundle>   # when required
```

Production argv is manager-owned and immutable (no protocol-supplied
fragment):

```text
/usr/bin/rootlesskit
  --net=slirp4netns
  --copy-up=/etc
  --disable-host-loopback
  --state-dir=/var/lib/docker-helper-builder/ops/<op_id>/rootlesskit-state
  /usr/libexec/docker-helper/buildkit/buildkitd
    --rootless
    --root=/var/lib/docker-helper-builder/ops/<op_id>/root
    --addr=unix:///run/docker-helper-builder/ops/<op_id>/buildkitd.sock
```

No `buildkitd.toml`: the command line owns the required settings and
insecure entitlements stay disabled by default; a demonstrated concrete
config requirement would stop for review, not create a parallel
configuration owner preemptively.

SO_PEERCRED is mandatory on both ends of the manager socket: the manager
authenticates every accepted connection (`SO_PEERCRED.uid == 0` —
DAC alone is insufficient because RootlessKit/buildkitd processes run
under the same builder UID that owns the socket) and the root-side
client verifies the manager's peer UID equals the resolved
`docker-helper-builder` UID before sending a request.

## 3a. Root daemon startup and dynamic recovery

Before docker-helper starts serving requests it connects to the manager
and issues PURGE + a liveness probe (bounded); on success builds are
enabled. The contract is fail closed for BUILDS ONLY:

- builder unavailable → build requests fail with `docker_build_failed`
  (internal backend failure); run/pull/registry-login remain available;
- no rootful-build fallback; no main-daemon restart required for
  recovery;
- the daemon re-verifies the manager DYNAMICALLY: a build attempt that
  finds the manager unavailable retries the connection once against a
  short bounded deadline and, if still unavailable, fails closed; when
  the manager becomes available again, the next build attempt succeeds
  with no main-daemon restart;
- daemon startup PURGE closes the "daemon crashed/restarted while the
  manager stayed alive with old instances" direction; manager startup
  purge closes the inverse direction. No adoption/recovery architecture.

## 4. Filesystem / runtime / state layout

One canonical RootlessKit state owner: `rootlesskit-state/` lives in the
PERSISTENT state tree only (matching the M1 mechanics); no duplicate
resource with the same role in the runtime tree. No `buildkitd.toml` (the
manager argv owns address/root/rootless settings; no parallel config
owner), and no persistent unbounded `buildkitd.log`: instance stdout/
stderr is captured into a fixed-size internal diagnostic buffer (64 KiB
ceiling, not config/API), whose bounded sanitized tail may be emitted to
the manager's operational stderr only on relevant failure.

```text
/run/docker-helper-builder/            # manager runtime root (0750 builder:builder)
  manager.sock                         # 0600 builder:builder
  ops/<operation_id>/                  # per-op runtime
    buildkitd.sock                     # 0600 builder:builder
    instance.pid                       # the setsid RootlessKit session/process-group LEADER pid
/var/lib/docker-helper-builder/        # manager state root (0750)
  ops/<operation_id>/
    root/                              # buildkitd --root (op-private state)
    rootlesskit-state/                 # rootlesskit --state-dir (one canonical owner)
```

`instance.pid` identifies the `setsid` RootlessKit session/process-group
leader (the process the manager launched), NOT the buildkitd child.
Manager STOP kills the negative pid (process group) and reaps the whole
RootlessKit process tree; slirp4netns and buildkitd are descendants of
that group. STOP/crash-cleanup proofs must assert the ABSENCE of the
full descendant set (rootlesskit leader, buildkitd, slirp4netns) — not
just the leader — and the absence assertions require the negative
self-test that the processes existed (matched by their op-scoped
`--root`/`--state-dir` argv) before the kill.

Root daemon server-owned tar for the build export lives under the already
helper-owned build staging tree:

```text
/run/docker-helper/builds/<operation_id>/export.tar
```

(this is the existing `stageBuildContext` owner root
`$RUNTIME_DIR/builds/<operation_id>/`; the tar is an additional server-owned
artifact inside the same operation-scoped directory, cleaned up by the same
staging cleanup owner).

Per-op dirs are created 0700 builder-owned. Nothing under the manager roots
is readable/writable by agents/Principals.

## 5. systemd unit relationship

Weak startup coupling (the builder boundary is fail-closed per build, not
a hard service dependency):

```text
docker-helper-builder.service   # Before= docker-helper.service
docker-helper.service           # Wants= docker-helper-builder.service + After= docker-helper-builder.service
```

NO `Requires=`: builder unavailability must fail BUILD requests closed
while run/pull/registry-login stay available, and the main daemon must
recover dynamically (§3a) when the manager returns — neither holds with a
`Requires=` stop-pulling the main service down. Package activation still
enables both units; the daemon's dynamic manager verification provides the
functional coupling.

### NNP exception (recorded deliberately)

- `docker-helper.service`: `NoNewPrivileges=true` REMAINS (unchanged,
  mandatory).
- `docker-helper-builder.service`: MUST NOT set
  `NoNewPrivileges=true`. RootlessKit's builder-side mechanics need
  `newuidmap`/`newgidmap`, whose setuid/file-capability privilege
  elevation is disabled by NNP. This unit is the narrow, recorded
  exception: it runs as the dedicated unprivileged builder identity
  (`Type=exec`, `ExecStart=/usr/bin/docker-helper builder serve`,
  `User=`/`Group=docker-helper-builder`,
  `RuntimeDirectory=`/`StateDirectory=docker-helper-builder` mode 0750),
  owns only the per-op BuildKit lifecycle, and holds no credentials and
  no Docker/socket authority. The exception is justified by the M0/M1
  evidence chain (rootlesskit + newuidmap mechanics under the builder
  user) and reviewed here explicitly, not inherited silently.

Minimal hardening around the exception:

- evaluate `CapabilityBoundingSet=CAP_SETUID CAP_SETGID` +
  `AmbientCapabilities=` unset: the unit keeps exactly the two
  capabilities the setuid-root `newuidmap`/`newgidmap` path needs to
  function for its own binary transition, bounding everything else. KEEP
  this bounding set ONLY if a live unit proof (a rootlesskit/buildkitd
  instance started under the real unit with exactly that floor) shows
  the composition works; if newuidmap proves to need more (e.g.
  CAP_DAC_OVERRIDE for /etc/subuid reading — it is world-readable, so it
  should not), record the demonstrated minimum instead;
- `RestrictNamespaces` MUST NOT be `true` for this unit: rootlesskit
  requires user/network/mount namespaces for the builder user. Plan:
  omit the directive (systemd default allows user namespaces) — documented
  explicitly, not silently.
- `RestrictSUIDSGID` MUST NOT be enabled: newuidmap/newgidmap are
  setuid-root binaries; the seccomp filter would break them.
- `ProtectHome=read-only` is safe (builder never writes $HOME; buildkitd
  state is under /var/lib/...), but only if the rootlesskit copy-up does
  not need $HOME writes — M0/M1 used HOME only for XDG conventions; the
  buildkitd `--root` is explicit. Keep `ProtectHome=read-only`; revisit if
  UAT shows a requirement.
- `PrivateTmp=false` (no requirement, no mount pins in this unit — mount
  namespace directives that would hide pins from dockerd are irrelevant
  here because the builder unit never creates Docker mount pins; choose
  minimal: do NOT add `ProtectSystem=strict` blindly — buildkitd/rootlesskit
  write only under their declared dirs, so `ReadWritePaths=` is the right
  form IF we adopt `ProtectSystem=full`: plan
  `ProtectSystem=full` + `ReadWritePaths=/run/docker-helper-builder /var/lib/docker-helper-builder`).
- `ProtectKernelTunables/Modules/Logs`, `ProtectControlGroups`,
  `ProtectClock`, `ProtectHostname`: safe to enable (no kernel access
  needed beyond namespaces).
- `Restart=on-failure`, `RestartSec=2s`, `TimeoutStopSec=30s`
  (STOP/PURGE is bounded; children live in the unit cgroup).
- Children (rootlesskit/buildkitd) stay inside the unit's cgroup: on
  service stop/restart systemd kills the whole cgroup — the outer
  process-tree safety net in addition to per-op STOP.

`docker-helper.service` changes: add `Wants=docker-helper-builder.service`
and `After=docker-helper-builder.service` (weak coupling; builder keeps
`Before=`). Everything else — including `NoNewPrivileges=true`, the PATH
contract, MAC binding, and the deliberate omissions documented in
`docs/architecture.md` — is unchanged.

Mandatory unit UAT assertions (all targets, exact release candidate):

- main daemon service process shows `NoNewPrivs: 1`
  (`/proc/<pid>/status`);
- builder manager process shows `NoNewPrivs: 0` (the recorded exception);
- a build under the composition still proves subordinate-ID mapping
  (`uid_map` maps in-build UID 0 to a nonzero host-side uid inside the
  builder's subordinate range) — the NNP exception does not weaken the
  sandbox boundary;
- the capability floor proof: with `CapabilityBoundingSet=CAP_SETUID
  CAP_SETGID` active, the live composition starts and builds succeed; if
  it does not, the demonstrated minimum is recorded and reviewed before
  any wider grant.

## 6. Builder identity + subuid provisioning

Canonical resource stem: `docker-helper-builder` (user, group, unit,
runtime dir, state dir). The M1 prototype names are the same stem; no
aliases.

One provisioning owner: `packaging/scripts/lib/provision-builder.sh` (new,
POSIX sh, sourced/executed by DEB postinst, RPM post scriptlet, and the
tarball installer). `nfpm.yaml` users/groups section is NOT used because
nfpm static user creation cannot allocate collision-free subuid ranges
(the logic below is real policy).

Provisioning algorithm (idempotent, fail-closed):

1. If `docker-helper-builder` user exists:
   - verify nologin shell, verify group exists and matches the user's gid,
     else fail closed with an actionable message;
2. else `useradd --system --home /var/lib/docker-helper-builder --shell
   /usr/sbin/nologin docker-helper-builder` (system user; no login);
3. verify subordinate ranges: both `/etc/subuid` and `/etc/subgid` must
   contain a `docker-helper-builder:` entry with a range >= 65536;
4. if missing, the provisioning script COMPUTES a collision-free
   contiguous 65536 range (integer arithmetic over the existing
   [start, start+count) intervals read from `/etc/subuid`/`/etc/subgid`),
   and then DELEGATES THE MUTATION to upstream account tooling —
   `usermod --add-subuids <start>-<end> --add-subgids <start>-<end>
   docker-helper-builder` (shadow-utils, present on all three supported
   targets) — docker-helper NEVER writes/rewrites `/etc/subuid` or
   `/etc/subgid` directly. The delegation boundary is: docker-helper may
   read, parse, and validate the databases and compute the range; the
   passwd/subid database WRITER is upstream shadow-utils exclusively;
5. ambiguous state (range overlaps an existing allocation, duplicate
   entries, usermod failure) fails closed and prints the conflict; the
   package script aborts with a clear operator message (dpkg/rpm report
   the failure). NO home-grown subid database writer: if no common safe
   primitive proved available on all three targets, this plan stops for
   architecture review rather than inventing one;
6. re-run of the same version is a no-op (all steps verify-first).

Cross-distro tooling proof (P4 gate, recorded in UAT): the exact
`usermod --add-subuids/--add-subgids` invocation must be proven to create
the expected entries on Ubuntu 24.04, Ubuntu 26.04 (shadow-utils) AND
openSUSE Tumbleweed (shadow-utils package; verify Tumbleweed's usermod
carries `--add-subuids` — if the Tumbleweed variant differs, the
provisioning script must fail closed there and the discrepancy goes to
architecture review, not to a hand-rolled writer).

Tarball installer calls the same script; the RPM uses the same script
(called from %post with the same fail-closed semantics).

## 7. BuildKit payload / provenance

Ship the pinned upstream BuildKit runtime in all packages (same backend
version and behavior on every distro; one security/UAT target):

- version: v0.33.0; tarball SHA256 pinned:
  `b6242896d343100808dcbe37565caf381e0a444a6a83d7255926bb1519248ead`
  (verified against the official release SBOM subject digest; no
  `.sha256` sidecar exists upstream);
- payload determination (P4 opening task): inspect the upstream
  release archive and identify the minimal set the proven OCI worker
  actually executes: `buildkitd`, `buildctl`, and any
  `buildkit-runc`/`buildkit-qemu-*` helper binaries the OCI worker shell
  resolves. The probe evidence (M0/M1 logs) plus a packaging UAT that
  greps the actual exec paths settles the exact file list — do NOT assume
  two files suffice because M0 extracted the whole archive;
- install location: `/usr/libexec/docker-helper/buildkit/<binary>`
  (product-owned absolute paths; mode 0755, root-owned);
- `docker-helper builder serve` resolves the payload from this fixed
  prefix (no PATH search, no `docker` involvement);
- provenance: the packaging release pipeline verifies the tarball SHA256
  at build time and records the version + digest in the package
  changelog/metadata; no runtime download, no third-party repository;
- license/notice: include the upstream LICENSE (Apache-2.0) and NOTICE
  material under `/usr/share/doc/docker-helper/buildkit/` in every
  package format;
- the Tumbleweed distro `buildkit` RPM is NOT used (M0/M1 used it only as
  probe convenience); the shipped payload replaces it.

## 8. Operation process-slot refactor (P1)

Current shape: `operation.cmd` is one `exec.Cmd` for the whole Operation
lifetime; `startOperationProcess` starts it under `op.mu`;
`waitBuildCompletion`/`waitRunCompletion` own `cmd.Wait()`; termination
(`terminateOperations`, force cleanup) signals/kills `op.cmd`.

Refactor (no workflow/pipeline abstraction — only enough to run sequential
child processes):

- `op.cmd` becomes the current child-process slot: `currentCmd *exec.Cmd`
  plus the existing `started`/`terminated`/`done` synchronization;
- new internal helper on the Operation owner:
  `startOperationStage(op *operation, makeCmd func(ctx) (*exec.Cmd, context.CancelFunc)) stageResult`
  — atomically under `op.mu`: refuse if `op.terminated`; swap the slot;
  start; return;
- new internal helper `waitCurrentStage(op)` — waits for the current slot's
  process exit (the stage goroutine calls it; the slot is not replaced
  until the previous stage's `Wait` returned);
- the build flow becomes sequential stages in ONE goroutine (the existing
  completion goroutine), each entering via `startOperationStage` and
  leaving via a termination check:

  ```text
  stage 1: manager START (process: none — manager round-trip, still a
           cancellable stage boundary)
  stage 2: buildctl (child process)
  stage 3: builder STOP (manager round-trip; no child)
  stage 4: docker load (child process)
  stage 5: docker image inspect of the internal tag (child process;
           cancellable through the same stage machinery)
  stage 6: final cancellation/commit check (no child; under op.mu)
  stage 7: docker tag + docker rmi internal tag (child processes)
  stage 8: staging cleanup + lease release (existing owners)
  ```

- invariants (all under the existing `op.mu`): at most one cancellable
  child active per Operation; a terminated Operation never starts a later
  stage; the transition and the termination check are synchronized in the
  same critical section as today's `startOperationProcess`;
- run operations keep exactly today's behavior (single stage;
  `startOperationStage` with one child — same code path, no second
  lifecycle);
- capacity/cancellation/shutdown/completion/audit ownership stays in
  Operation and the supervisor — untouched.

## 9. Mandatory cancellation-race tests (P1 gate, before P3)

Test ownership across phases (no test-only fake future BuildKit
architecture is constructed in P1):

- **P1** proves the GENERIC sequential-child cancellation/shutdown
  invariants with synthetic stages (real child processes/seams);
- **P2** owns the manager RPC ambiguity tests (§3);
- **P3** promotes the generic P1 proof to the ACTUAL build stages and
  asserts the manager STOP/image invariants there.

Race-focused tests over the stage boundaries (table-driven; real
production path with `ExecCommandContext` seam for process control):

- cancel before the first child starts → no child spawned, `cancelled`;
- cancel during buildctl → child SIGTERM'd, `cancelled`, no later stage;
- cancel after buildctl exits, before import starts → no `docker load`
  child, `cancelled`, requested image untouched;
- cancel during `docker load` → load child killed, requested image
  untouched, internal tag cleaned;
- cancel during the internal-tag verification → the admitted inspect child
  is signaled, the tag stage is suppressed, internal tag cleaned;
- shutdown during each equivalent window (same assertions; result code
  follows the CURRENT contract: `docker_build_failed` for
  shutdown-terminated builds, `docker_run_failed` for runs — see §13);
- force cleanup while the current child process is active → slot killed,
  later stages never run;
- post-commit cancel: cancel arriving after the commit-phase claim must
  NOT convert a committed build to `cancelled` (see §11);
- STOP/PURGE of the builder instance on every cancel path (manager seam
  records the calls);
- manager RPC ambiguity cases (§3): START reply lost, cancellation during
  the START readiness wait, timeout after the START write, STOP reply
  lost — each converges to no live op instance/state/socket.

Every test proves the reached branch (state transitions observed through
the operation status/audit, not sleeps).

## 10. buildctl mapping for the existing build contract

Existing contract (unchanged): `context`, `dockerfile`, `image`,
`build_args`. Note: the task text lists `shm_size` among existing fields,
but the build contract (`api_contract.go buildRequest`) has no
`shm_size` field today (only `runRequest` does); this plan therefore maps
only the four existing build fields and records the discrepancy — adding
`shm_size` to build would be a new public API field, which this release
does not do. (If review decides build needs `shm_size`, it is a separate
explicit contract change; BuildKit's `--opt shm-size=` exists and maps
trivially.)

Mapping (root daemon side; all paths server-owned):

| API field | buildctl argv/env |
|---|---|
| `context` (staged copy) | `--local context=<staged.ContextPath>` |
| `dockerfile` (relative) | `--local dockerfile=<staged.ContextPath>` + `--opt filename=<dockerfileRel>` |
| `image` | NOT passed to buildctl; used only in the final `docker tag` commit (see §11) |
| `build_args` (sorted keys, existing validation) | `--opt build-arg:KEY=VALUE` per key |

Additional fixed (server-owned, not caller-visible) buildctl options:

- `--addr unix:///run/docker-helper-builder/ops/<op_id>/buildkitd.sock`
- `DOCKER_CONFIG=<session docker config dir>` in the child env
  (existing `ensureSessionDockerDir` owner)
- `--output type=docker,name=<internal-tag>,dest=<staged export tar>`
- `--progress=plain` → streamed into the existing bounded `LogBuffer`
- no `--allow` (entitlements stay refused by the daemon default)
- no frontend override (bundled `dockerfile.v0`)

Explicit mapping tests freeze this table argv-by-argv
(`build_mapping_test.go`), including: dockerfile nested paths, build-arg
ordering determinism, value characters (`=`, spaces), no-image-in-argv.

No caller-controlled: `network.host`, `security.insecure`, cache
namespace, frontend, exporter, socket.

## 11. Image handoff transaction + commit linearization

Internal tag spelling (frozen):

```text
docker-helper-build/<operation_id>
```

(a valid Docker tag: one slash-separated repository component, owned
namespace; spelling chosen over a bare hyphenated name to make
internal tags visually and mechanically distinguishable from user tags;
no aliases).

Flow:

```text
buildctl --output type=docker,name=docker-helper-build/<op_id>,dest=$RUNTIME_DIR/builds/<op_id>/export.tar
docker load < export.tar                     # tar path server-owned
docker image inspect docker-helper-build/<op_id>  # internal-tag verification (cancellable child stage)
[final cancellation/commit check — under op.mu]
docker tag  docker-helper-build/<op_id> <requested-image>
docker rmi  docker-helper-build/<op_id>      # internal tag removed
```

Commit linearization (the exact point cancellation stops winning):

- state: `op.commitClaimed bool` under `op.mu`;
- before the commit check: any cancel/shutdown sets `terminated` under
  `op.mu` as today and wins — the requested image tag is untouched;
- the commit check runs under `op.mu`: if `op.terminated` → no commit;
- otherwise set `op.commitClaimed = true` in the same critical section;
  from this point `terminateOperations` no longer converts the operation
  to `cancelled` — it may still kill a hung child process in the commit
  phase, but the terminal transition follows the commit phase outcome;
- **`docker tag <internal> <requested>` is the irreversible success
  linearization point**: once `docker tag` exits 0, the Operation result
  is `succeeded` and cannot become `docker_build_failed` because of
  internal-tag cleanup. `docker rmi <internal>` is bounded idempotent
  CLEANUP ONLY: a cleanup failure is logged and audited, may leave the
  exact op-owned internal tag in place for operator/retry cleanup, and
  never downgrades a committed build — the requested image remains a
  successful build;
- before a successful `docker tag`, cancel/shutdown still wins and the
  requested image tag is untouched;
- the requested tag changes only via the commit `docker tag`;
- the race "load/tag succeeded then operation reported cancelled" cannot
  occur: `docker tag` is inside the claimed phase and the terminal
  transition happens after it.

Failure/cancel/shutdown cleanup of the internal tag: best-effort
`docker rmi docker-helper-build/<op_id>` on failure/cancel/shutdown paths,
scoped to the exact op-owned internal tag (no global prune). Cleanup
retry is bounded and idempotent (already-absent = success).

### Image-reference validation timing

Today the target image reference is validated by Docker itself at
`docker build --tag` time (the contract delegates image-reference grammar
to Docker; no docker-helper-side grammar exists and none may be invented).
The 2.4 flow moves the reference use to the final `docker tag`, which
would otherwise DELAY Docker-owned validation to the very end of the
build. Explicit choice:

- **Option B (selected): use the canonical upstream Docker/Distribution
  reference parser** (`github.com/distribution/reference`, the same
  grammar Docker itself uses; new vendored upstream dependency — the
  module currently carries only sqlite3/x-sys/x-term, so this is the one
  deliberate dependency addition of 2.4) as a
  REQUEST-TIME validation gate: a build request whose image reference
  fails `reference.ParseNormalizedNamed` is refused up front with the
  existing invalid-request error shape, before staging/capacity work.
  This restores early failure without inventing a home-grown grammar.
  Differential tests: the parser's accept/reject behavior must agree
  with `docker build --tag` on a corpus (valid/invalid references from
  Docker docs and Engine test cases); any disagreement is a bug to fix
  before shipping;
- Option A (late Docker-owned validation with documented/accepted late
  failure) is recorded as the REJECTED alternative: it satisfies the
  no-home-grown-grammar rule but changes user-visible failure timing
  (a full build completes and THEN the tag step fails).

The request-time parser check is VALIDATION ONLY (grammar gate): the
authoritative semantics of what a tag names remain Docker's at commit
time; the parser must not be presented as a docker-helper grammar.

## 12. Credentials and CA handling

Credentials: unchanged owner. buildctl runs as a root-docker-helper child
with `DOCKER_CONFIG=$RUNTIME_DIR/sessions/<session>/docker` (existing
`ensureSessionDockerDir`/registry-login owner). The manager never receives
registry credentials; buildkitd gets no credential store; nothing is copied
into builder-manager state. No credential values in manager protocol,
argv, logs, audit, or errors (existing masking preserved; leak tests use
unique markers).

CA handling (backend mechanics, not user policy):

- the manager derives a per-platform system CA bundle for each per-op
  buildkitd spawn: deterministic resolver
  `/etc/ssl/ca-bundle.pem` → `/var/lib/ca-certificates/ca-bundle.pem` →
  `/etc/pki/tls/certs/ca-bundle.crt` → `/etc/ssl/certs/ca-certificates.crt`
  (first existing readable), passed as `SSL_CERT_FILE` in the buildkitd
  child env (the M0/M1-proven rootlesskit#225 fix);
- no chmod of host CA material; fail closed when no readable bundle exists
  (builder startup diagnostic, not a silent degraded build);
- `trusted_ca_injection` stays the `run` contract and is NOT extended for
  build; private-registry custom CA for BUILD remains a separate explicit
  design question (tracked below in §19) and is not conflated with run
  CA injection.

## 13. Result semantics

No new public result codes. The CURRENT contract (2.3/2.4 unchanged) is
preserved exactly:

```text
docker_build_failed   # any backend/build/import/commit failure,
                      # INCLUDING build terminated by daemon shutdown
cancelled             # explicit cancel only
```

`shutdown` is NOT a public result code and does not exist in the current
contract: a build terminated by daemon shutdown reports
`docker_build_failed` (with the existing "daemon is shutting down"
message), exactly as the 2.3 code path does today
(`build.go` terminated-before-start and error paths check
`op.reason == terminationCancelled` for `cancelled` and use
`docker_build_failed` otherwise). `terminationShutdown` remains an
INTERNAL control state of the operation supervisor only; it never leaks
into `result_code`. For the run kind the analogous current behavior is
`docker_run_failed`. No new public result taxonomy in 2.4.

Stage-to-`exit_code`/`result_code` mapping:

| Stage | Failure mode | exit_code | result_code |
|---|---|---|---|
| manager START | manager unreachable / refused / socket invalid | nil (no docker process) | `docker_build_failed` |
| manager START ambiguous (reply lost/timeout) | cleanup STOP converged | nil | `docker_build_failed` |
| buildctl | nonzero exit | buildctl exit code | `docker_build_failed` |
| buildctl cancelled | SIGTERM/kill | child exit code if available | `cancelled` |
| buildctl terminated by shutdown | SIGTERM/kill | child exit code if available | `docker_build_failed` |
| docker load | nonzero exit | docker exit code | `docker_build_failed` |
| docker image inspect (internal-tag verification, cancellable child stage) | nonzero exit | docker exit code | `docker_build_failed` |
| docker tag (commit, before success) | nonzero exit | docker exit code | `docker_build_failed` |
| docker rmi internal tag (cleanup) | nonzero exit | — | **no effect**: result stays `succeeded` (cleanup logged/audited) |
| any stage cancelled | cancel wins before commit | child exit code if available | `cancelled` |

Operation `exit_code` populates from the FAILED STAGE's child exit code
(the existing `extractExitCode`); manager-protocol stages have no child
and leave `exit_code` nil. Backend topology (manager/sockets/tar paths)
never appears in API errors — messages stay the existing bounded,
non-disclosing forms.

## 14. AppArmor plan (evidence-first)

`docker-helper-system` (main daemon) — narrow additions only, gated on
observed denials during UAT of the actual integration:

- connect to `/run/docker-helper-builder/manager.sock` (unix connect);
- execute/read the bundled buildctl
  `/usr/libexec/docker-helper/buildkit/**` (r + x);
- read/write the server-owned export tar
  `/run/docker-helper/builds/**` (already inside the granted runtime
  tree — verify, likely no change);
- execute the existing `docker` CLI (already permitted for run/build
  mediation — `docker load/tag/rmi` are the same executable; verify no
  new subcommand-specific rule is needed).

No workspace authority broadening.

New `docker-helper-builder` profile (separate domain for the builder
service): runtime/state trees rw, rootlesskit/buildkitd/slirp4netns/newuidmap
execute, userns/mount/network mechanics, system CA read. No Docker socket,
no Session workspace, no helper config/state credentials. Shipped in
`packaging/apparmor/` and asserted by `apparmor_test.go`; expansion only
with demonstrated denials (rule 13 of the repo instructions).

Ubuntu 24.04/26.04 keep `apparmor_restrict_unprivileged_userns=1` (the
distro rootlesskit profile carries the userns permission — M0-proven).

### AppArmor transition for the confined builder executing distro rootlesskit

The builder domain (`docker-helper-builder`) executes the DISTRO
`/usr/bin/rootlesskit` on Ubuntu 24.04/26.04 (the distro-shipped package,
not a product copy). The plan:

- PREFERRED: explicit transition into the DISTRO rootlesskit profile
  (`/etc/apparmor.d/rootlesskit`, shipped by Ubuntu's rootlesskit
  package and proven in M0 to carry the userns permission under
  `apparmor_restrict_unprivileged_userns=1`). Mechanism selection is
  deferred to P5 live proof: plain `ix` does NOT transition — it
  inherits the current (builder) profile — so the actual transition
  must be proven with `px`/`Px`/named transition as appropriate.
  The builder profile itself must then contain NO parallel
  rootlesskit userns policy: the distro profile remains the single
  owner of that permission;
- fallback only on demonstrated denial evidence: if the distro profile
  cannot be attached from a confined non-root domain in practice
  (profile attachment for confined transitions has distro-specific
  quirks), the observed denial defines the minimal builder-side
  addition, reviewed as a dedicated policy change with the denial as its
  justification — not a preemptive duplicate userns policy;
- `buildkitd`/`slirp4netns`/`newuidmap` execution from the builder
  domain follows the same evidence-first shape (execute permission on
  the distro binaries with the transition mechanism chosen in P5;
  newuidmap transitions to its distro profile if one exists);
- UAT asserts the transition works under
  `apparmor_restrict_unprivileged_userns=1` (a real build under the real
  unit on 24.04 and 26.04, dmesg/audit clean of AppArmor DENIED entries
  for the composition).

## 15. SELinux plan (evidence-first)

- `docker-helper.te`: main domain additions for the manager socket
  connect, bundled buildctl execute, export tar access (same list as §14,
  expressed as types; `docker_helper_t` gains only what is demonstrated).
- New builder domain `docker_helper_builder_t` (+ `.fc` entries for
  `/run/docker-helper-builder(/.*)?`, `/var/lib/docker-helper-builder(/.*)?`,
  `/usr/libexec/docker-helper/buildkit(/.*)?`) with type transitions for
  its runtime/state trees; only the mechanics the M1 evidence shows:
  userns/create, exec of rootlesskit/buildkitd/slirp4netns/newuidmap, its
  own trees, system CA read. No docker socket, no workspace types, no
  helper credential types.
- Tumbleweed SELinux stays enforcing (UAT proves the full composition
  inside the enforcing VM, as M0/M1 did).
- `scripts/check-selinux-policy.sh` extends to the new domain/fcontext
  files.

## 16. Packaging lifecycle (DEB/RPM/tarball)

- `docker-helper-builder.service` ships in all three formats
  (`nfpm.yaml` contents + tarball file list); BuildKit payload + license
  material per §7;
- DEB: preinst/postinst call the shared provisioning script; postinst
  `daemon-reload`, then restart ordering handled by unit dependencies
  (builder has `Before=docker-helper.service`; docker-helper carries
  `Wants=` + `After=` weak coupling). Upgrade 2.3 → 2.4: 2.3 has no
  builder unit; the postinst provisions the identity, enables the
  builder unit, and the ordinary `try-restart` of docker-helper picks up
  the new unit relationship;
- RPM: same script from %post; versioned conflicts unchanged;
- tarball: `packaging/install-system.sh` runs the same provisioning
  script and installs both units + payload + MAC policy;
- uninstall: preremove stops docker-helper (builder children die in the
  cgroup); postremove removes builder runtime/state dirs and (package
  removal) leaves the provisioned user in place unless purged (document
  the choice: KEEP the identity on package removal — subuid reallocation
  on reinstall is idempotent; only tarball `--purge` removes it);
- lifecycle UAT matrix (P7): fresh install / upgrade 2.3→2.4 / reinstall /
  restart / stop+start / uninstall — DEB, RPM, tarball (extends
  `uat-artifact-{deb,rpm,tarball}.sh`);
- no network download during install; no rootful-build fallback if the
  builder service is unavailable (fail closed: builds refuse with
  `docker_build_failed` and the daemon logs the backend reason).

## 17. UAT matrix (production gates)

Promote the M1 proofs into `scripts/uat-*.sh` release gates on the exact
release candidate, per target (Ubuntu 24.04, Ubuntu 26.04, Tumbleweed):

service/identity: main daemon process `NoNewPrivs: 1`; builder manager
process `NoNewPrivs: 0` (the recorded NNP exception); sandbox uid mapping
still proves subordinate-ID mapping (in-build UID 0 → nonzero host-side
uid in the builder's subordinate range); capability-floor live proof
(build succeeds with `CapabilityBoundingSet=CAP_SETUID CAP_SETGID` if
adopted); `usermod --add-subuids/--add-subgids` provisioning proof
(§6).

sandbox/network: host-root marker denied; host loopback denied; outbound
works; `network.host` refused; `security.insecure` refused; docker.sock
absent from RUN; manager socket absent from RUN; BuildKit socket absent
from RUN.

isolation/lifecycle: same cache id sequential builds no cross-read;
same cache id concurrent builds no cross-read; third concurrent build
gets existing product capacity semantics (refused, no hidden queue);
failed build leaves the requested target unchanged; cancel before commit
leaves the requested target unchanged; successful build commits the
requested target; no internal temp tag after terminal completion;
builder state/runtime/socket gone after terminal completion; manager
restart purges stale state.

Negative self-tests remain mandatory wherever a zero/absence assertion
could false-pass (pre-teardown existence proofs, marker-injection leak
checks with unique values, and a probe that the asserted endpoint exists
before asserting its absence after teardown).

## 18. Migration 2.3 → 2.4

- 2.3 deployment has one root daemon using rootful `docker build`; no
  builder identity/units exist;
- upgrade path: package postinst provisions identity + subuids
  (§6), installs the builder unit + payload, enables it; docker-helper
  unit gains the weak `Wants=`/`After=` coupling; on first (re)start the
  daemon performs the startup manager verification (§3a) and builds flow
  through the sandbox; a failure to establish the mandatory builder
  boundary is fail closed for BUILDS (builds refuse; ordinary run/pull/
  registry operations are NOT build-sandbox-dependent and keep working —
  the sandbox is a build-execution boundary, not a daemon-availability
  boundary). This split must be explicit: daemon startup verifies the
  manager and logs/audits builder-unavailable; build requests fail
  closed while other operations are unaffected; the daemon recovers
  dynamically when the manager returns (no restart);
- no data migration (no persistent build cache exists in 2.3's contract
  to preserve — the docker daemon's own build cache is outside
  docker-helper state and remains untouched);
- rollback to 2.3: uninstall removes the builder unit/payload; the
  identity remains (harmless, idempotent on reinstall).

## 19. Risks / open questions

1. Upstream payload minimal set (§7) must be proven by inspection, not
   assumed; risk of missing a helper binary shows up as build failure —
   mitigated by the packaging UAT executing real builds.
2. `docker-helper-build/<op_id>` internal tag namespace: verify Docker
   accepts the two-component repository form and that `docker load` of a
   `type=docker` tar with that name behaves (M0/M1 proved single-name
   forms; the namespaced spelling needs one explicit test in P3).
3. Rootful Engine image-store growth: internal tags are removed
   immediately; failed loads may leave partial loads — `docker load` is
   transactional per the Engine; cleanup covers the internal tag, not
   partial layers (Engine-owned GC remains Engine behavior).
4. SELinux builder domain may need additional perms only visible under
   enforcing UAT (evidence-first expansion is planned, but schedule risk
   exists — the Tumbleweed UAT runs late in the pipeline).
5. `RestrictAddressFamilies` for the builder unit: rootlesskit/slirp4netns
   need AF_INET/AF_INET6/AF_UNIX/AF_NETLINK; same set as the main unit
   works — verify in UAT before freezing the unit file.
6. Whether `docker-helper-builder.service` needs `After=network.target`:
   buildkitd binds no TCP; slirp4netns needs no early networking — leave
   out unless UAT shows a need.
7. Log truncation behavior for large builds: the existing bounded Log
   Buffer owner is reused unchanged; large builds lose the tail policy is
   already defined by the buffer — no change.
8. Concurrent `docker load` operations (ceiling 2) serialize on the
   Engine; acceptable, existing capacity semantics cover it.
9. Private-registry custom CA for BUILD: registry-login credentials are
   pinned in the Session docker config (existing registry-login
   semantics), but that config supplies CREDENTIALS ONLY. Upstream
   BuildKit (v0.13.0+; source-verified `session/auth/authprovider`) has
   buildctl fetch registry tokens directly, with token-endpoint TLS
   trusted from the Go default system pool, overridable only by the
   buildctl flag `--registry-auth-tlscontext host=...,ca=...`; per-
   registry custom CA for buildkitd requires a buildkitd.toml
   `[registry."host"] ca=[...]` section. DOCKER_CONFIG therefore does
   NOT supply custom registry CA trust, and the earlier plan claim that
   buildctl reads per-registry CA from DOCKER_CONFIG is withdrawn. What
   IS implemented and unit-tested (P3-D2a): the manager resolves the
   first existing readable system CA bundle and passes it as
   SSL_CERT_FILE to the per-instance buildkitd (fail closed without
   one). Custom registry CA trust for BUILD needs an explicit design
   decision (buildkitd.toml generation vs buildctl flag vs trust-store
   provisioning), carries its own policy/scope questions, and is not
   part of the sandbox boundary. Real TLS/auth behavior against real
   registries is proven in P7 UAT (probes: system-CA pull; token-endpoint
   trust outside system paths; fail-closed against self-signed chains).
10. Capability floor (§5): `CapabilityBoundingSet=CAP_SETUID CAP_SETGID`
    is planned but not yet live-proven; if the live unit proof shows
    newuidmap needs more, the demonstrated minimum is recorded and
    re-reviewed before any wider grant.
11. AppArmor distro-rootlesskit transition from a confined non-root
    builder domain (§14): profile attachment from a confined domain has
    distro-specific quirks; the plan prefers the distro profile
    transition and falls back to evidence-driven minimal additions only.
12. Tumbleweed `usermod` subid support (§6): if Tumbleweed's shadow-utils
    usermod lacks `--add-subuids`, provisioning fails closed there and
    the discrepancy goes to architecture review (no hand-rolled subid
    writer); to be proven in P4 before packaging freezes.

## 20. Ordered commit/phase plan

1. P1: operation process-slot refactor + cancellation-race tests
   (several small commits: slot refactor → stage helpers → race test
   file; gate: full test suite + `-race` green).
2. P2: builder-manager backend role: protocol owner + op lifecycle
   (START/STOP/PURGE) + RPC deadlines/ambiguity convergence + ceilings +
   startup purge; unit tests with a protocol seam (including the §3
   ambiguity tests); no systemd wiring yet.
3. P3: build path integration behind the existing API: mapping tests,
   export tar in the staging tree, handoff transaction, commit
   linearization + tests; internal-tag cleanup.
4. P4: identity/subuid provisioning script (usermod-delegated mutation,
   cross-distro tooling proof) + unit tests; systemd units (builder NNP
   exception + capability floor + main-unit Wants/After); BuildKit
   payload in build-scripts; nfpm/tarball file lists; packaging tests.
5. P5: MAC policy additions (AppArmor + SELinux) with policy tests;
   `check-selinux-policy.sh` extension.
6. P6: daemon startup manager verification (fail closed for builds);
   shutdown cleanup integration; docs updates
   (`architecture.md`, `release-2.4-build-sandbox.md` status, `roadmap.md`,
   `README.md`, man pages, skill only if agent-visible behavior changes).
7. P7: UAT gates (three targets) + packaging lifecycle UAT; release
   candidate.

No production integration starts before this plan is reviewed.
