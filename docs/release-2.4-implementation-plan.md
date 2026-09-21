# Release 2.4 Implementation Plan

Status: DRAFT — awaiting architectural review. No production code is
implemented by this document. M0 (feasibility, composition A) and M1
(shared-state tenancy proof and per-operation ephemeral alternative) are
closed in [`release-2.4-build-sandbox.md`](release-2.4-build-sandbox.md).

Corrected M1 record commit: `33e2402` ("M1 record: correct the tested SHA and
the layer-cache claim") on `release/2.4`, parent `f54fe48`.

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
inside an already-reserved Build Operation (capacity is owned by the daemon;
see §6), surfaced as `docker_build_failed` — not a new public capacity
topology.

## 4. Filesystem / runtime / state layout

```text
/run/docker-helper-builder/            # manager runtime root (0750 builder:builder)
  manager.sock                         # 0600 builder:builder
  ops/<operation_id>/                  # per-op runtime
    buildkitd.sock                     # 0600 builder:builder
    buildkitd.toml                     # generated by the manager (fixed content)
    buildkitd.log                      # instance log (diagnostics only)
    instance.pid                       # buildkitd (rootlesskit child) pid
    rootlesskit-state/                 # rootlesskit state dir
/var/lib/docker-helper-builder/        # manager state root (0750)
  ops/<operation_id>/
    root/                              # buildkitd --root (op-private state)
    rootlesskit-state/                 # rootlesskit state (state dir owned here)
```

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

```text
docker-helper-builder.service   # Before= docker-helper.service
docker-helper.service           # Requires= docker-helper-builder.service
```

`docker-helper-builder.service`:

- `Type=exec`, `ExecStart=/usr/bin/docker-helper builder serve`
- `User=docker-helper-builder`, `Group=docker-helper-builder`
- `RuntimeDirectory=docker-helper-builder` (0750), `StateDirectory=docker-helper-builder` (0750)
- `NoNewPrivileges=true` — KEEP: the builder manager itself never
  gains privileges; rootlesskit/newuidmap mechanics run unprivileged and
  do not need NNP-disabled setuid-style transitions
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

`docker-helper.service` changes: add `Requires=docker-helper-builder.service`
and `After=docker-helper-builder.service`. Everything else — including
`NoNewPrivileges=true`, the PATH contract, MAC binding, and the deliberate
omissions documented in `docs/architecture.md` — is unchanged.

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
4. if missing, allocate a collision-free range: read existing entries in
   `/etc/subuid`/`/etc/subgid`, compute gaps between/after the used
   [start, start+count) intervals (integer arithmetic in awk, no append
   onto an overlapping interval), pick the first free window of 65536
   starting at 65536 and growing upward; write via a locked atomic
   rewrite (`flock` + temp file + rename, preserving all other lines byte
   for byte);
5. ambiguous state (range overlaps an existing allocation, duplicate
   entries, unwritable files) fails closed and prints the conflict; the
   package script aborts with a clear operator message (dpkg/rpm report
   the failure);
6. re-run of the same version is a no-op (all steps verify-first).

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
  stage 5: final cancellation/commit check (no child; under op.mu)
  stage 6: docker tag + docker rmi internal tag (child processes)
  stage 7: staging cleanup + lease release (existing owners)
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

Race-focused tests over the stage boundaries (table-driven; real
production path with `ExecCommandContext` seam for process control):

- cancel before the first child starts → no child spawned, `cancelled`;
- cancel during buildctl → child SIGTERM'd, `cancelled`, no later stage;
- cancel after buildctl exits, before import starts → no `docker load`
  child, `cancelled`, requested image untouched;
- cancel during `docker load` → load child killed, requested image
  untouched, internal tag cleaned;
- shutdown during each equivalent window (same assertions, shutdown
  reason);
- force cleanup while the current child process is active → slot killed,
  later stages never run;
- post-commit cancel: cancel arriving after the commit-phase claim must
  NOT convert a committed build to `cancelled` (see §10);
- STOP/PURGE of the builder instance on every cancel path (manager seam
  records the calls).

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
  to `cancelled`/`shutdown` result — it may still kill a hung child
  process in the commit phase, but the terminal transition is
  `succeeded` (commit ran) or `docker_build_failed` (commit failed);
- the requested tag changes only inside the claimed commit phase;
- the race "load/tag succeeded then operation reported cancelled" cannot
  occur: `docker tag` is inside the claimed phase and the terminal
  transition happens after it.

Failure/cancel/shutdown cleanup of the internal tag: best-effort
`docker rmi docker-helper-build/<op_id>` on failure/cancel/shutdown paths,
scoped to the exact op-owned internal tag (no global prune). Cleanup
retry is bounded and idempotent (already-absent = success).

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

No new public result codes; preserved:

```text
docker_build_failed   # any backend/build/import/commit failure
cancelled             # caller cancellation or client disconnect cancel
shutdown              # daemon shutdown termination
```

Stage-to-`exit_code`/`result_code` mapping:

| Stage | Failure mode | exit_code | result_code |
|---|---|---|---|
| manager START | manager unreachable / refused / socket invalid | nil (no docker process) | `docker_build_failed` |
| buildctl | nonzero exit | buildctl exit code | `docker_build_failed` |
| docker load | nonzero exit | docker exit code | `docker_build_failed` |
| docker tag/rmi (commit) | nonzero exit | docker exit code | `docker_build_failed` |
| any stage cancelled | SIGTERM/kill | child exit code if available | `cancelled` |
| any stage, shutdown | same | same | `shutdown` |

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
distro rootlesskit profile carries the userns permission — M0-proven;
the builder unit relies on the same distro profile, verified in UAT).

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
  (builder has `Before=docker-helper.service`; docker-helper
  `Requires=` builder). Upgrade 2.3 → 2.4: 2.3 has no builder unit; the
  postinst provisions the identity, enables the builder unit, and the
  ordinary `try-restart` of docker-helper picks up the new unit
  relationship;
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

sandbox/identity: uid mapping non-host-root; host-root marker denied;
host loopback denied; outbound works; `network.host` refused;
`security.insecure` refused; docker.sock absent from RUN; manager socket
absent from RUN; BuildKit socket absent from RUN.

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
  unit gains Requires/After; on first (re)start the daemon
  performs the startup manager verification (§19) and builds flow through
  the sandbox; a failure to establish the mandatory builder boundary is
  fail closed for BUILDS (builds refuse; ordinary run/pull/registry
  operations are NOT build-sandbox-dependent and keep working — the
  sandbox is a build-execution boundary, not a daemon-availability
  boundary). This split must be explicit: daemon startup verifies the
  manager and logs/audits builder-unavailable; build requests fail
  closed while other operations are unaffected;
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
9. Private-registry custom CA for BUILD (registry CA pinned in the
   Session docker config via existing registry-login semantics) —
   buildctl reads it client-side from `DOCKER_CONFIG` (the docker CLI
   config layout carries per-registry CA); one explicit P3 test proves
   buildctl honors it; if a gap shows up, it becomes a separate design
   question, not a blocker for the sandbox boundary.

## 20. Ordered commit/phase plan

1. P1: operation process-slot refactor + cancellation-race tests
   (several small commits: slot refactor → stage helpers → race test
   file; gate: full test suite + `-race` green).
2. P2: builder-manager backend role: protocol owner + op lifecycle
   (START/STOP/PURGE) + ceilings + startup purge; unit tests with a
   protocol seam; no systemd wiring yet.
3. P3: build path integration behind the existing API: mapping tests,
   export tar in the staging tree, handoff transaction, commit
   linearization + tests; internal-tag cleanup.
4. P4: identity/subuid provisioning script + unit tests; systemd units
   (builder + main-unit Requires/After); BuildKit payload in
   build-scripts; nfpm/tarball file lists; packaging tests.
5. P5: MAC policy additions (AppArmor + SELinux) with policy tests;
   `check-selinux-policy.sh` extension.
6. P6: daemon startup manager verification (fail closed for builds);
   shutdown cleanup integration; docs updates
   (`architecture.md`, `release-2.4-build-sandbox.md` status, `roadmap.md`,
   `README.md`, man pages, skill only if agent-visible behavior changes).
7. P7: UAT gates (three targets) + packaging lifecycle UAT; release
   candidate.

No production integration starts before this plan is reviewed.
