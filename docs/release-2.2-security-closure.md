# Release 2.2 external security audit closure

## Status and authority

**Status: SC0 CLOSED; SC1 CLOSED; SC2 NEXT (2026-09-15).**

The external audit that triggered this closure reviewed docker-helper 2.0.0 at
commit `7e9762576327b625acde45934a15216d1ff0a56b`. Its finding identifiers are
stable references, but its findings are historical observations until they are
rebased onto the current Release 2.2 production line.

SC0 performed that rebase against:

```text
release branch: release/2.2
SC0 baseline:   3e9d50879b217ae28dd091f4ee9a705b194dc0b5
```

That baseline includes the final allowed-root recovery correction merged through
PR #52. Every Critical, High, and Medium audit finding now has a terminal
current-line disposition. No `VERIFY_CURRENT` finding remains after SC0.

This document is the security-closure owner for Release 2.2. It is a mandatory
overlay to [`release-2.2-implementation-plan.md`](release-2.2-implementation-plan.md):
Phase 2.2.7 final release promotion is blocked until the exit criteria below
are satisfied.

This is a release-plan and security-disposition document, not the canonical
current-state architecture. Accepted implementation changes from SC1-SC3 must
be reflected in [`architecture.md`](architecture.md), help/man/README, and the
applicable design record before the final release review. The final release
review must reread `docs/architecture.md` in full.

## Fixed principles

1. **Keep the Docker Engine/Docker CLI backend in 2.2.** The audit does not by
   itself justify an Engine rewrite, Podman migration, or Release 3 backend
   work. Rootless runtimes/user namespaces remain future defense-in-depth
   candidates unless a current 2.2 finding proves they are required.
2. **Fix the existing owner, not each symptom.** Workload launch invariants,
   bind-mount serialization, authorization linearization, config decoding, MAC
   execution, and path policy each keep one production owner.
3. **No Release 3 quota/control-plane architecture.** Release 2.2 may add hard
   security ceilings needed to remove a demonstrated unbounded host-resource
   attack, but must not pre-build Principal/Launcher quota policy, schedulers,
   desired state, or a generic resource framework.
4. **Preserve current lifecycle contracts unless explicitly changed.** In
   particular, credential revocation does not retroactively revoke already
   issued Sessions, and Session deletion/expiry does not by itself promise to
   terminate an operation that already started. A finding that assumes the
   opposite is not fixed by silently changing the contract.
5. **Current evidence wins over historical code shape.** A 2.0 finding is
   closed only by tracing the current production path and proving the old
   mechanism is gone or unreachable. Conversely, an unchanged vulnerable path
   remains actionable even when adjacent architecture changed.
6. **No silent risk deferral.** A current finding that violates the published
   threat boundary is either fixed before stable release or receives an
   explicit architecture/release-owner disposition that narrows or documents
   the guarantee. "Later" is not a terminal disposition by itself.
7. **Cross-boundary security behavior requires cross-boundary UAT.** Unit tests
   for two components do not prove their composition. Required security UAT
   uses the real package, real systemd unit, real enforcing MAC backend, real
   Docker, and a hostile workload where the finding depends on that stack.
8. **Do not enable `PrivateMounts=true` as a generic answer.** Existing
   inode-pinned mount sources must remain visible to the Docker daemon; any
   mount-namespace change requires a separate proven design.

## Disposition vocabulary

Every Critical, High, and Medium finding ends SC0 in exactly one terminal
state:

- **CLOSED_CURRENT** — the vulnerable 2.0 production path is structurally gone
  in current 2.2 and current regression evidence protects the replacement
  invariant.
- **BLOCKER_FIX** — current 2.2 behavior violates the accepted security or
  correctness boundary and must be fixed before stable release.
- **BLOCKER_DECISION** — the finding exposes a real current trust-boundary or
  contract question whose correct solution is architectural. Stable release is
  blocked until the decision is accepted and either implemented or explicitly
  documented as the supported boundary.
- **ACCEPTED_CONTRACT** — the reported behavior is current but follows an
  already accepted Release 2.x product contract. A security patch may not
  silently reverse that contract.
- **DEFER_HARDENING** — useful hardening with no demonstrated independent
  current violation of the Release 2.2 threat/behavior contract. It does not
  independently block stable release after its disposition is recorded.

`VERIFY_CURRENT` was the temporary SC0 state for a historical finding whose
current status had not yet been proved. **SC0 is closed only because that state
is now absent from the entire C/H/M matrix.**

## SC0 result

SC0 closes with this terminal distribution across the 26 Critical/High/Medium
findings:

```text
BLOCKER_FIX       16
BLOCKER_DECISION   3
CLOSED_CURRENT     3
ACCEPTED_CONTRACT  3
DEFER_HARDENING    1
VERIFY_CURRENT      0
```

The release-blocking implementation queue is intentionally split by owner and
risk rather than by the audit's original severity ordering.

## Current C/H/M disposition matrix

| ID | Audit claim | Release 2.2 disposition | Closure phase | Stable-release requirement |
| --- | --- | --- | --- | --- |
| **C1** | Workload containers lack `no-new-privileges`; SUID/SGID delivery can lead to host root | **CLOSED_CURRENT** | SC1 | Closed through the single server-owned workload privilege floor: the run argv owner emits `--cap-drop ALL` and `--security-opt no-new-privileges:true` for every workload in every mode before any backend option, and the caller has no privilege field. The canonical staging owner strips S_ISUID/S_ISGID from every staged regular file at its single copy point. Hostile source-image and staged-file UAT proved both escalation chains dead (see the SC1 evidence ledger). |
| **C2** | Principal-less/admin-created Session could execute as daemon `0:0` | **CLOSED_CURRENT** | SC0 | Current system-mode Session execution resolves the proven Launcher/Principal execution identity and emits `--user UID:GID`; there is no daemon-UID fallback. Keep the execution-identity regression proof. |
| **C3** | Old libselinux recursive `restorecon` can relabel path-swapped foreign files | **CLOSED_CURRENT** | SC1 | Recursive workspace relabeling is admitted only in the proven descriptor-safe composition: the RPM hard-requires `libselinux1 >= 3.11` (the upstream `selinux_restorecon` rewrite that labels each inode through `/proc/self/fd` paths, closing the pathname-replacement TOCTOU), the tarball SELinux installer re-proves the installed implementation from rpm package metadata before any SELinux mutation (restorecon must link `libselinux.so.1`, the resolved library must be owned by `libselinux1`, its version must satisfy the floor; older/foreign-owned/unverifiable/unparseable provenance fails closed with actionable diagnostics), and one runtime owner refuses the recursive relabel without a real procfs (statfs `PROC_SUPER_MAGIC`, mirroring upstream `probe_proc()` — without procfs libselinux silently falls back to pathname labeling), fail-closed before any fcontext mutation. Mount-boundary safety (`checkTreeRelabelBoundary`) stays the separate mount-point invariant owner; no home-grown recursive relabel walker exists. See the SC1 evidence ledger. |
| **H1** | Builder can fetch arbitrary URLs from a network position unavailable to the agent | **BLOCKER_DECISION** | SC3 | Accept an explicit builder-network threat-boundary design. Fix the network position if the supported promise excludes this access; do not parse Dockerfiles as a substitute policy engine. |
| **H2** | Credential can be revoked after authentication but before Session issuance | **CLOSED_CURRENT** | SC1 | Closed at the existing Session-issuance linearization owner: the create transaction's conditional insert re-proves the authorizing credential (still existing, still owned, still active) in the same statement as the Session insert, so a revoke/delete committing before the Session commit prevents the Session and the refusal answers the canonical non-disclosing 401 credential classification. Winning ordering unchanged: an already-issued Session stays valid. Deterministic parked-query race evidence on both credential paths. |
| **H3** | Privileged filesystem resolution happens before authorization and leaks resolver detail | **CLOSED_CURRENT** | SC1 | Authorization-before-probing ordering established at all four session-facing admission boundaries: the raw spelling is admitted lexically against the issued filesystem capability FIRST (workspace create against the effective ceiling, absolute run mount against the issued snapshot entries, build context/Dockerfile against the workspace, issuance-time `filesystem_roots` against the effective Launcher ceiling), and a spelling outside the capability is refused immediately WITHOUT any privileged filesystem probe — zero-probe seam evidence, not merely equal responses. The former symlink-alias admission (an outside spelling resolving into the capability) is removed as an explicit Release 2.2 security tightening. After admission the canonical `EvalSymlinks` + containment proofs remain the mandatory second security proof (inside-ceiling aliases work; inside-ceiling symlink escapes stay fail-closed); public unauthorized failures stay bounded/non-disclosing; admitted spellings keep their actionable diagnostics; run/build keep their stable public contracts with admission diagnostics retained operationally. The issued snapshot's authority remains the persisted path tree (position/path/access + digest) — a review-round retraction of a live-kind exact-capability inference is recorded below. |
| **H4** | Build staging can consume unbounded tmpfs bytes/inodes/depth/files | **CLOSED_CURRENT** | SC2 | One build staging operation now has fixed, measured, non-configurable security ceilings for exactly three dimensions — payload bytes (128 MiB), entries (50000) and depth (64) — enforced by one per-staging budget inside the existing descriptor-relative walker. Bytes reserve the first staged copy of a unique regular-file inode's logical size (`st_size`, conservative for de-sparsified copies) before destination creation; hardlink names share the payload reservation but each consume an entry; symlink targets are accounted; admission arithmetic is overflow-safe (ceiling comparison before counter mutation). Every attacker-variable entry (regular file, hardlink name, symlink, directory) is reserved exactly once — at enumeration admission, before its append and before any destination materialization, with materialization paths never re-reserving — and directory enumeration draws from the same single global budget, so the sum of simultaneously admitted enumeration entries across parent and child directories can never exceed the ceiling whatever the iteration order (the former unbounded `[]dirEntry` accumulation is gone). Depth (context root = 0, direct child = 1) is admitted before the destination mkdir and before recursive descent. No second walker, no pre-scan, no config/CLI/override surface, no quota hierarchy; all descriptor-relative security invariants unchanged; the typed refusal is owned by the untagged staging surface (compiles for a non-Linux target under a compile-ownership gate) so the untagged build handler classifies — only it — into one canonical `build_context_too_large` code (HTTP 400, dimension-only bounded message); every other staging failure stays `internal_error`; refusal leaves no operation tree, no Docker invocation, no admitted Operation, no `build.start` event and no stale session MAC-use lease. Seam RED/GREEN evidence, exact-boundary unit tests and hostile exact-candidate UAT (sparse-payload, entry-count and depth cases against the packaged service under mandatory MAC) — see the SC2 evidence ledger. |
| **H5** | Logs, mount pins and concurrent/running Operations provide unbounded host-resource channels | **CLOSED_CURRENT** | SC2 | The existing OperationSupervisor is the single concurrency owner with fixed, measured, non-configurable Release-2.2 security ceilings — 4 concurrent Operations per Session, 8 globally, and a narrow build sub-ceiling of 2 concurrent builds — enforced by an atomic `reserve` → `admitReserved` flow: the reservation checks shutdown, Launcher quiesce, the Session ceiling, the global ceiling and the build sub-ceiling in one critical section and is acquired BEFORE any expensive preparation (run: before the MAC-use lease, mount probing, exposure resolution, pins and workload-MAC materialization; build: before H4 staging), so a capacity refusal leaves zero prepared state; final admission re-checks only the lifecycle closure (a reservation obtained before a quiesce or shutdown is not an admitted Operation) and transfers the reservation into the registered Operation without re-reserving; capacity is released exactly once at the terminal transition and on every pre-admission failure path (the frozen cleanup order gains a kernel-independent capacity stage first), never coupled to retention pruning; no queue, no waiter — one bounded `operation_capacity_unavailable` refusal (HTTP 429) for both scopes. POST /run refuses more than 16 caller mounts (`too_many_mounts`, HTTP 400) immediately after request decoding/basic validation, before the lease, probing, pins, MAC preparation and the reservation; duplicates and RO/RW consume slots equally and the server-owned helper_socket projection does not. One HTTP logs response now carries at most 256 KiB raw retained bytes independent of `operation_log_max_bytes` (`Range` gained a bounded read; `next_offset` follows the bytes actually returned and `truncated` keeps its established meaning with the read starting at the oldest retained byte — no retained bytes silently skipped); the measured worst-case JSON expansion (6× for control characters/invalid UTF-8) keeps one response under ~1.6 MiB encoded; the CLI drains bounded chunks through one shared helper (running polls drain all available chunks; the terminal drain empties every remaining chunk), so successful CLI output is never truncated by chunking. Phase-A measurement: amplification 6.0× adversarial / 1.0× ordinary (1 MiB → 6,291,544 encoded bytes), UAT max concurrency 2, all existing mount usage 1–2 per request, smallest host 3 GiB Tumbleweed VM with ~614 MB `/run` and fs.mount-max 100000, H4 multiplication bounded at 2 × 128 MiB = 256 MiB = 42% of the smallest `/run`. Seam RED/GREEN evidence and hostile exact-candidate UAT group 25 (concurrency, refusal-before-expensive-work, mount ceiling, hostile-byte chunk walk, recovery) — see the SC2 evidence ledger. Recorded adjacent boundary for a release-owner decision (H5 inspection item G): pull and registry-login are synchronous non-Operations whose materialization is already retention-bounded (pull response = complete retained buffer with `truncated`; registry-login output discarded, 4 KiB classification buffer), but their execution concurrency remains unbounded; the smallest consistent extension would count concurrent pull/registry-login executions against the existing reservation owner without registering Operations — no scheduler was invented, and the finding is documented in `docs/architecture.md` (Synchronous data-plane boundedness). |
| **H6** | Mandatory MAC policy blocks admin-token rotation | **CLOSED_CURRENT** | SC1 | The admin-token replacement lifecycle is rewritten around ONE fixed staging pathname (`.admin-token.new`, internal implementation pathname, not a config/API/CLI surface), serialized by the existing admin-token hash commit lock with the stale-rotation check BEFORE the staging pathname is touched, crash-residue recovery, and failure-safe cleanup (current token file and runtime hash unchanged, staging removed). The shipped MAC policy is narrowed to the token replacement lifecycle only: AppArmor (pathname-mediating) grants write/rename on exactly the two token pathnames (the generic config tree and config.json stay read-only, no broader write glob); SELinux (type-based) introduces the dedicated `docker_helper_admin_token_t` file type (MAC implementation state) with exact fcontext rules listed before the generic config-tree rule, the full replacement lifecycle granted on the token type only, an EXACT filename transition for `.admin-token.new` (no generic config-dir transition), `docker_helper_config_t:file` strictly read-only, and config-dir namespace operations limited to write/add_name/remove_name. ACCEPTED SELinux backend mechanic (release-owner ruling, PR #57 review round 2): SELinux does NOT provide AppArmor-equivalent destination-basename mediation for rename — once a token_t inode exists, the granted directory namespace + inode permissions may allow it to be renamed to an otherwise unused basename in the config directory; creation stays exact-name constrained, existing `docker_helper_config_t` objects stay immutable, and this is a backend mechanic, not additional product authority (no path-policy framework, token subdirectory architecture, or rename broker; see the H6 evidence ledger). Deployment labeling stays under the selinux_deploy owner: an exact post-create relabel after the initial token is written (the tree relabel runs before the token exists) with failed-relabel recovery (the just-created token file is removed, no partial initialization), and the packaged restorecon migrates a pre-H6 token on upgrade/reinstall without changing its value. Live enforcing UAT on the exact candidate proves rotation through the shipped confined service with old token rejected, new token accepted, no restart, 0600, no staging residue, config.json unchanged, no broader writable config surface, and no unexpected H6-policy denial on both backends. |
| **H7** | A local user can occupy the optional TCP port and drive the service into systemd start-limit failure | **CLOSED_CURRENT** | SC2 | The Unix listener is authoritative: a loopback TCP bind failure after a successful Unix bind is DEGRADED STARTUP, never daemon failure — the Unix listener stays open, its socket is not removed, the complete API keeps serving over Unix, the TCP listener is absent for the daemon lifetime, and one bounded operational warning names the configured address and the bind failure. The bind itself is the authority (no pre-probe); no retry/rebind, timer, or listener supervisor exists. Unix creation failure stays fatal; user mode never attempts TCP; systemd Restart=/StartLimit values are untouched. Seam RED/GREEN evidence and hostile exact-candidate UAT (unprivileged port capture against the packaged service under mandatory MAC) — see the SC2 evidence ledger. |
| **H8** | External MAC commands can hold shared coordination long enough to delay emergency disable | **BLOCKER_FIX** | SC2 | Existing MAC command owners gain bounded cancellation/timeouts and the lifecycle lock path is reviewed so untrusted-size work cannot indefinitely hold administrative disable. Avoid a new queue/framework unless evidence requires it. |
| **H9** | Agent container can receive the helper runtime directory and steal registry secrets/replace CA state | **CLOSED_CURRENT** | SC1 | Closed by composition with C1, without a second socket transport owner: with the privilege floor in place the strongest reachable workload privilege is the Principal UID:GID with no capabilities and no-new-privileges, which the root-owned `0700` helper-private runtime state denies; the read-only projection and unchanged bearer authentication are unchanged. Hostile helper-socket UAT on enforcing AppArmor and enforcing SELinux proved the socket transport functional, unauthenticated calls refused, private runtime/session Docker config unreadable, runtime immutable, and escalation dead (see the SC1 evidence ledger). |
| **H10** | An allowed root lets the root daemon read files the Principal could not read under Unix DAC | **BLOCKER_DECISION** | SC3 | Decide whether a filesystem capability intentionally grants helper-mediated read independent of DAC or must additionally preserve Principal DAC/group/ACL semantics. Do **not** implement an owner-UID check as a fake Unix permission model. |
| **M1** | Environment/build secret values appear in the Docker CLI process argv | **BLOCKER_DECISION** | SC3 | Inventory each secret-bearing channel and choose a supported transport/mitigation. `--env-file` is not assumed equivalent for arbitrary current values. Any residual `/proc` exposure must be explicit in threat/operations docs. |
| **M2** | Documentation puts bearer tokens directly in `curl` argv | **CLOSED_CURRENT** | SC1 | Every executable shipped HTTP example (README quick start, shipped agent skill) now feeds the Authorization header to curl through the header-from-stdin form (`-H @-`) via one environment-backed and one file-backed header producer — the bearer value never appears in any process argv. The admin example uses the existing `config show admin_token_path` path surface. RED synthetic-bearer `/proc` proof, GREEN argv-absence proof, exact-header delivery proof, and a static shipped-guidance regression (see the SC1 evidence ledger). |
| **M3** | Registry credentials are plaintext in the per-Session Docker config | **DEFER_HARDENING** | SC4 | Plaintext storage remains, but the current independent boundary is the root-owned runtime plus per-Session `0700` directory and mandatory MAC. Do not add a keychain/encryption subsystem without demonstrated need. This disposition is conditional: C1/H9 hostile UAT must prove the file remains unreachable from a hostile workload; otherwise promote M3 back to a blocker. |
| **M4** | Raw-config validation and `json.Unmarshal` accept different key grammar; bad values can reach panic-prone consumers | **CLOSED_CURRENT** | SC1 | ONE strict config-document ingest boundary owns JSON object grammar (one object, no trailing tokens), duplicate-member refusal (never last-wins), exact case-sensitive key recognition (case variants refused as unknown, never folded by encoding/json struct matching), the existing value validations, and the fileConfig projection from the proven exact-key map — the original untrusted byte stream is never struct-decoded after raw validation. Malformed config never reaches effective Config or runtime side effects; mutations refuse a malformed document without rewriting it. |
| **M5** | NUL-containing Principal name can resolve through libc as one OS user but persist as a distinct DB identity | **CLOSED_CURRENT** | SC1 | One Principal username text grammar owner (`validatePrincipalUsername`) refuses empty and control-bearing spellings (C0 including LF/CR/TAB, DEL, the C1 controls; embedded NUL) BEFORE OS lookup, home resolution, persistence, and credential issuance — for the created Principal and the user-mode daemon-owner identity alike. Every other spelling is persisted exactly as supplied (no trim/fold/normalization, no invented useradd regex); the OS resolver remains the existence authority. RED alias proof, zero-lookup refusal, and exact-candidate raw-JSON UAT (see the SC1 evidence ledger). |
| **M6** | Audit write failure does not abort the protected operation | **ACCEPTED_CONTRACT** | SC0/SC4 | Current Release 2.x audit is best-effort observability, not a fail-stop transaction boundary. Do not change operation success semantics merely to match the audit recommendation. Improve failure observability only if useful; a new fail-stop audit contract requires separate architecture acceptance. |
| **M7** | Cancellation can leave an untracked running container when cidfile timing loses the race | **CLOSED_CURRENT** | SC0 | System-mode ownership no longer depends on cidfile timing: every run has server-owned operation/session labels, post-run cleanup first proves the correlated container absent through label provenance, and failed cleanup retains durable state for startup reconciliation. Preserve that single cleanup/provenance owner. |
| **M8** | Principal disable/delete or Session deletion does not stop already-started work | **ACCEPTED_CONTRACT** | SC0 | Current 2.x lifecycle deliberately allows an already-started operation to finish after the authority/Session change; future requests are rejected. Existing exact-artifact regression group 3 proves this contract. |
| **M9** | User-mode pathname race exists because Docker resolves a path again without the system-mode pinning boundary | **ACCEPTED_CONTRACT** | SC0/SC4 | User mode does not claim isolation from another process running as the same OS user and Docker authority. System mode owns the stronger inode-pinning guarantee. Keep documentation aligned; extending user-mode pinning is optional hardening, not an implicit contract change. |
| **M10** | Allowed-root symlinks are recomputed after validation without reapplying the safety policy | **CLOSED_CURRENT** | SC0 | The old raw-symlink re-resolution path is gone: current effective allowed-root policy is composed from canonical paths and the Session snapshot persists the issued canonical identity; later data-plane decisions consume that snapshot rather than re-resolving the original stored spelling. Preserve the symlink/path-policy regressions. |
| **M11** | SELinux fcontext input escapes regex syntax but not file-format/control-character hazards | **CLOSED_CURRENT** | SC1 | One shared host-path text-grammar owner (`validateHostPathText`, in the shared workspace-path policy) refuses every Unicode control rune (C0 including LF/CR/TAB, C1, DEL) and embedded NUL explicitly at every host-path policy/canonicalization owner that persists a host capability identity or hands one to a MAC backend — before filesystem probing on the caller spelling and again after symlink resolution. Ordinary printable spelling (spaces inside a component, regex metacharacters, ordinary Unicode) stays supported; no backend, handler, or CLI duplicates the list; `escapeFcontextPath` stays regex escaping. |
| **M12** | `semanage fcontext` output parser disagrees with the producer's long-path spacing | **CLOSED_CURRENT** | SC1 | The record parser follows the captured REAL `semanage fcontext -l -C -n` producer grammar (Tumbleweed policycoreutils 3.11-2.2, exact bytes committed as the test fixture): the record's first whitespace token is the complete pattern (semanage refuses space-carrying file specifications at add time) and its last whitespace token is the complete context; no fixed display width, no whole-line Fields tokenization, no width-dependent split rule. Same-stem/ownership/overlap semantics, `<<None>>` semantics, equivalence parsing, and fail-closed handling of unrecognized records are unchanged. |
| **M13** | Crafted bind-mount target can desynchronize Docker `--mount` CSV and lose `readonly` | **CLOSED_CURRENT** | SC1 | One canonical serializer owns every Docker bind form (user mounts, trusted CA injection, helper-socket runtime projection); the grammar is the authoritative Docker CLI parser (one CSV record read once, `key=value` fields or boolean flags) and the encoding is Go `encoding/csv` — the Docker-sanctioned quoting — so a crafted source/target stays exactly one field and cannot add an option, change the target, remove `readonly`, add `rw`, change type/source, or create a second logical field. Representability is a three-boundary invariant: the value must round-trip through the CSV record, survive Docker `MountOpt.Set` value validation unchanged (non-empty, no leading/trailing whitespace), and be exec-argv representable (no NUL); failing values are refused in the one serializer owner. The Docker argv is built and serialized before the operation admission, so a serialization failure of a daemon-owned value leaves no admitted Operation. Review-round-2 blocker fixes closed with exact-candidate real-Docker evidence (group 22 including the Docker value-validation boundary case, admission-order lifecycle regression). |

The Low findings `L1`-`L14` remain an audit hardening backlog and do not
independently enter the Release 2.2 stable gate unless implementation evidence
promotes one. Do not opportunistically widen a security patch to unrelated Low
findings. A Low finding that touches the exact same owner may be closed in the
same series only when that is the smallest coherent change.

## SC0 evidence ledger

SC0 is an architectural/current-line rebase, not a new test campaign. The
following evidence is the reason the former `VERIFY_CURRENT` findings now have
terminal dispositions.

### H7 — current TCP startup DoS is still reachable

`listener.go` creates the authoritative Unix listener first and then the
optional system-mode TCP listener. A TCP bind failure closes the Unix listener,
removes the Unix socket and fails daemon startup. The shipped systemd unit uses
`Restart=on-failure`, `RestartSec=5s`, `StartLimitIntervalSec=60s`, and
`StartLimitBurst=3`. Therefore a local process holding the configured loopback
port can still turn the optional listener into a persistent whole-service DoS.
H7 is promoted to `BLOCKER_FIX` in SC2.

### H9 — old chain changed, residual AppArmor composition remains

Current `--helper-socket` behavior is materially safer than the audited 2.0
shape:

- it is system-mode-only and server-owned;
- workload execution is under the Principal UID:GID;
- the helper runtime projection is read-only;
- no Session bearer is injected into the workload;
- current UAT proves ordinary Principal-UID workloads cannot read helper-private
  runtime state;
- current SELinux policy permits runtime traversal/socket connection without
  granting read access to the private runtime files.

However, the current generated AppArmor workload profile includes broad `file,`
mediation and relies on DAC for helper-private runtime confidentiality. Because
C1 still permits a hostile image/staged SUID executable to obtain root inside
the workload, that root can bypass the `0700` DAC boundary while the whole
runtime directory is projected read-only. The write half of the old chain is
blocked by the read-only bind; the secret-read half is not independently proven
dead on AppArmor until C1 is closed. H9 therefore becomes `BLOCKER_FIX`, coupled
to C1, not `CLOSED_CURRENT` and not an SC3 redesign request.

### M3 — plaintext remains, but no independent current boundary violation

Registry login still delegates to Docker through `--password-stdin`, and Docker
stores its per-Session config under the helper runtime. In system mode that
Session Docker directory is root-owned and `0700`; ordinary Principal-UID
workloads cannot reach it, and mandatory MAC is an additional boundary. The
remaining demonstrated exploitability is the H9+C1 composition above, which is
already release-blocking. Adding encryption/keychain infrastructure would be a
new owner without independent evidence. M3 therefore becomes
`DEFER_HARDENING`, conditional on the final C1/H9 hostile proof.

### M5 — NUL/alias identity remains current

Principal creation still performs only an empty-string check before
`user.Lookup(username)`, receives UID/GID/home from the OS lookup, and persists
the original request username. It does not establish one canonical accepted
username string before the libc-backed lookup and database identity are
combined. The audited NUL/control-alias class therefore remains actionable and
is promoted to `BLOCKER_FIX` in SC1.

### M7 — cidfile-only ownership race is structurally gone

Current system-mode `run` assigns helper-owned operation/session labels before
container creation. The canonical terminal cleanup first proves the correlated
container absent using those labels, force-removes a proven-owned container when
necessary, and only then removes workload MAC state, pins, durable ownership
state, the Session-use lease and cidfile. Failure retains dependent state for
startup reconciliation. The cidfile is no longer the sole ownership proof, so
the 2.0 race is `CLOSED_CURRENT`.

### M10 — raw allowed-root symlink re-resolution is structurally gone

The current allowed-root resolver canonicalizes the effective policy before it
is composed. Session issuance persists the immutable canonical filesystem
snapshot, and data-plane lookup consumes that snapshot. The audited sequence of
validating one raw symlink spelling and later re-running `EvalSymlinks` on that
same untrusted spelling without reapplying policy no longer owns a production
path. M10 is `CLOSED_CURRENT`.

### M11 — fcontext control-character boundary remains current

The canonical workspace/root policy rejects broad and forbidden roots but does
not reject newline/control characters. `escapeFcontextPath` escapes regular
expression metacharacters but not semanage file-format/control-character
hazards. M11 is therefore promoted to `BLOCKER_FIX` in SC1; the fix belongs at
the canonical host-path policy boundary.

### Rechecked terminal findings

- **C2 remains `CLOSED_CURRENT`:** system-mode execution identity is derived
  from the Session's proven Principal and passed as Docker `--user UID:GID`; no
  daemon-root execution fallback remains.
- **M6 remains `ACCEPTED_CONTRACT`:** audit output is observability, not a
  fail-stop transaction owner in Release 2.x.
- **M8 remains `ACCEPTED_CONTRACT`:** authority/Session invalidation blocks
  later use but does not retroactively cancel already-started work.
- **M9 remains `ACCEPTED_CONTRACT`:** user mode shares the OS user's trust and
  Docker authority; system mode owns the stronger pathname/inode-pinning
  boundary.

## SC1 evidence ledger

### C1 — workload privilege floor and staging privilege bits

Implemented on the current release line through two existing owners, with no
new abstraction:

- **Privilege floor (run argv owner).** `run.go` composes every docker-helper
  `docker run` argv in one production path for both modes. It now emits the
  server-owned `workloadPrivilegeFloor` — `--cap-drop ALL` and
  `--security-opt no-new-privileges:true` — for every workload, before any
  backend `--security-opt` option. The run request contract carries no
  privilege field (strict request decoding rejects unknown fields), so the
  caller cannot disable or weaken the floor, and user mode and system mode
  share the same floor owner (no divergent paths).
- **Staging privilege bits (staging owner).** The canonical staging copier
  creates every staged regular file once and applies the source's ordinary
  permission bits with `S_ISUID`/`S_ISGID` stripped at that single site; no
  second copier or post-processing walk exists. Staged hardlink entries share
  the first staged copy's inode and inherit the stripped mode; the source
  file is never modified.

Evidence:

- RED unit tests on the pre-fix release line proved the docker argv carried
  no floor in user mode and either system backend, and that helper-created
  staging copied `S_ISUID`/`S_ISGID` from the source (including through the
  hardlink path) into Docker's build context.
- Post-fix targeted tests prove the floor flags appear exactly once and
  precede the MAC options, that `--privileged`/`--cap-add` never reach the
  argv, that a privilege-shaped request field is refused, and that staged
  modes are stripped while ordinary bits and the source mode are preserved.
- Hostile live UAT (exact candidate, AppArmor scenario W11, SELinux
  scenario S14): a locally built attacker image with a root-owned SUID
  reporter executed through docker-helper reports `uid=euid=<workload UID>`
  with `CapEff=0000000000000000` — the source-image escalation chain is dead.
- Hostile staged-chain live UAT (AppArmor scenario W12, SELinux scenario
  S15): SUID/SGID executables in the workspace go through the real
  `build` staging into a built image whose build-time `test ! -u`/`test ! -g`
  checks and post-build workload tests hold — the staged-file escalation
  chain is dead.

### H9 — helper runtime confidentiality under the privilege floor

No transport/runtime ownership change: `--helper-socket` remains the one
server-owned projection, the workload runs under the Principal UID:GID, the
projection stays read-only, and no Session bearer is injected. With C1
closed, the strongest workload privilege reachable from image or staging
material is the server-owned `--user` identity without capabilities and
without privilege escalation, so the root-owned `0700` helper-private
runtime state (`sessions/<id>/docker/`, `builds/`, `mounts/`,
`workload-mac/`, the socket lock) is no longer bypassable by DAC, and the
read-only bind keeps the runtime immutable. On enforcing SELinux the shipped
policy grants the workload only runtime traversal and socket connect — no
`file` read on `docker_helper_runtime_t` — independently of DAC.

Evidence (hostile helper-socket UAT, exact candidate; AppArmor scenario
W13, SELinux scenario S16, one baked hostile probe with distinct finding
codes):

- the intended Unix socket stays reachable and `GET /health` succeeds
  through the injected projection;
- an unauthenticated protected call through the socket is refused with
  HTTP 401 — the transport grants no authority and no bearer is injected;
- enumeration and open of `sessions/`, `builds/`, `mounts/`, and
  `workload-mac/` fail, including an exact known-path read of
  `sessions/<session-id>/docker/config.json` (the registry credential
  store addressed by finding M3's condition);
- mutation attempts against the runtime top level and the session Docker
  directory fail;
- the privilege escalation stays dead with the projection mounted
  (`euid` never 0, effective capabilities empty).

The M3 `DEFER_HARDENING` condition is demonstrated at SC1 for this
candidate; the release gate still re-proves it on the final stable
candidate artifact. A skip in either backend's required UAT job is a gate
failure, per the mandatory hostile UAT contract.

### H2 — credential revocation race closed at the Session commit boundary

The 2.0 chain was still reachable on the SC0 baseline: `POST /sessions`
authenticated the credential once at entry and the create transaction's
conditional insert re-checked only the Launcher/Principal enabled state,
so a revoke or credential delete committing between authentication and
the Session commit still issued a new Session behind the revoked
authority.

Closed at the existing Session-issuance linearization owner, with no new
auth path, owner, or error contract:

- `resolveCreatePolicy` projects the authenticated operator authority's
  commit-boundary credential revalidation facts (credential ID plus the
  owner identity the row must still prove) into the resolved create
  policy; the admin authority — which authenticates by in-memory token
  comparison — carries no credential and no revalidation clause, so the
  admin path does not accidentally depend on a credential it does not
  have.
- The create transaction's conditional insert (the existing
  defense-in-depth stale-owner recheck owner, evaluated in the same
  statement as the Session insert) requires the authorizing credential
  row to still exist, still carry the authenticated owner identity, and
  be active (`revoked_at IS NULL`), so a revoke/delete committing before
  the Session commit prevents that Session; SQLite's write-lock
  serialization makes the predicate atomic with the commit, and a losing
  concurrent writer fails closed.
- The zero-row outcome is classified inside the same transaction: the
  launcher/principal availability recheck keeps the pre-existing typed
  `422 launcher_unavailable` contract, and a credential rejection keeps
  the canonical `ErrCredentialRevoked`/`ErrCredentialNotFound` classes.
  The handler answers with the same non-disclosing 401 credential
  contract as entry authentication (one `auth.failure` record with the
  existing `credential.revoked`/`credential.not_found` classification,
  no `session.create` record). No new error code.
- The winning ordering is unchanged: the Session commit before the
  revoke leaves the issued Session valid (accepted revocation contract,
  M8 semantics untouched), and a rejected create leaves no partial
  Session, snapshot, MAC, or credential state (the MAC create binding
  rolls back through the existing insert-failure path).

Evidence:

- RED deterministic race tests on the pre-fix release line, using the
  existing parked-query test seam (test infrastructure on the SQL
  connection seam, no production hook): the create is parked at its
  last pre-boundary authentication read and inside its `lifecycleMu`
  critical section, the concurrent revoke/delete commits while parked,
  and the resumed create issued the Session (201) behind the
  already-revoked/deleted credential — on both the Principal-credential
  path and the Launcher-credential (physical delete) path.
- Post-fix the same parked sequences refuse with 401 `unauthorized` and
  leave no Session row; the mirror parked sequence proves the winning
  ordering (Session commits before the revoke commits) keeps the issued
  Session valid and its bearer authenticating; an unrelated credential
  revoke inside the parked window does not block the create; a
  synthetic ownership-provenance change between authentication and the
  commit is refused; the admin path is unaffected; the audit contract
  test proves exactly one `auth.failure credential.revoked` record, no
  `session.create` record, and no bearer or secret material in the
  audit output.

### H3 — authorization-before-probing at the session-facing admission boundaries

The 2.0 face was still reachable on the SC0 baseline through `POST
/sessions`: the workspace admission resolved the caller spelling
(`EvalSymlinks`/`stat`) before the ceiling containment proof and
returned the resolver's detail as the actionable cause, so an
unauthorized missing, dangling-symlink, or permission-denied spelling
answered with `cannot resolve workspace symlinks: lstat <path>: ...`
while an unauthorized existing directory got the bounded authorization
message — an existence/error-class/resolution oracle over host paths
the authority was never issued. The same probe-before-authorization
ordering existed for the absolute run mount spelling (resolved and
statted before the snapshot exposure decision), for the build
context/Dockerfile spellings (resolved before workspace containment),
and for the issuance-time `filesystem_roots` canonicalization
(`EvalSymlinks`/`stat` of the raw caller spelling before the canonical
ceiling proof — a caller could make the root daemon probe any host
pathname it did not authorize, and an outside alias resolving into the
ceiling was admitted through its resolution).

Closed by establishing the authorization-before-probing ordering at all
four session-facing admission boundaries, as an explicit Release 2.2
security tightening of the symlink-alias semantics:

- the raw caller spelling is admitted lexically against the issued
  filesystem capability FIRST — the effective allowed-root ceiling for
  the Session-create workspace, the issued Session filesystem snapshot
  entries for the absolute run mount source, the canonical session
  workspace for the build context and the resolved context for the
  Dockerfile, and the effective Launcher ceiling for each issuance-time
  `filesystem_roots` entry — without any host filesystem probing;
- a spelling outside the capability is refused immediately WITHOUT
  `EvalSymlinks`/`stat`: no existence, error class, path type, or
  resolved alias of an unauthorized pathname is ever collected or
  disclosed; the public refusals stay the existing bounded
  authorization-shape codes (`invalid_workspace`,
  `invalid_mount`, `invalid_build_context`,
  `invalid_filesystem_policy`) with no new error code;
- the former alias semantics — a raw spelling outside the capability
  that would resolve into it through a symlink — is removed: the
  caller-controlled raw spelling must carry the lexical capability
  admission itself. No compatibility alias is kept;
- after admission the privileged probes run normally and the canonical
  `EvalSymlinks` + containment proofs remain the second, mandatory
  security proof: a symlink inside the lexical capability that resolves
  outside is fail-closed (staging and inode pinning unchanged — no
  TOCTOU regression); a spelling inside the capability that resolves
  inside is issued (aliases inside the ceiling keep working); a missing
  admitted spelling keeps its actionable operator diagnostic;
- run/build keep their stable non-disclosing public contracts, and
  their admission diagnostics are retained in the operational log.

No new policy owner: the admission gates live in the existing
admission owners (`createSessionWithPolicyLocked`, `resolveMount`,
`validateBuildRequest` — with the filesystem_roots admission inside the
existing `canonicalizeSessionFilesystemRoots` canonicalization owner)
reusing the existing lexical containment helpers, and the privileged
probes route through one test seam (`evalSymlinksFn`/`osStatFn`)
covering exactly the four session-facing admission sites.

Evidence:

- RED black-box indistinguishability matrix on the pre-fix release
  line, through the real `POST /sessions` route: an unauthorized
  existing directory answered `workspace must be inside an allowed
  root` while the unauthorized missing, dangling-symlink, and
  (where Unix DAC applies) permission-denied spellings answered with
  the raw resolver detail — distinct public outcomes for host paths
  outside the authority.
- GREEN zero-probe evidence on the fixed line (the property the
  review cycle required, not merely equal responses): deterministic
  seam/counter tests prove the privileged filesystem resolver is
  invoked ZERO times for a workspace spelling outside the ceiling, an
  absolute run mount spelling outside the issued snapshot, a build
  context spelling outside the workspace (existing, missing, dangling,
  and relative-escape spellings), and an issuance-time `filesystem_roots`
  spelling outside the effective Launcher ceiling (existing, missing,
  dangling, and outside-alias spellings) — and that an ADMITTED spelling
  is still resolved, with an inside-ceiling symlink escape still
  fail-closed by the canonical containment proof.
- GREEN indistinguishability matrices (workspace create, run mounts,
  build context) prove the public unauthorized outcomes are identical
  across filesystem states, with the admission diagnostics retained in
  the operational log and the authorized E-H semantics preserved
  (existing issued; missing-inside-ceiling operator diagnostic;
  inside-ceiling alias issued; inside-ceiling symlink escape refused;
  outside-ceiling alias now refused without probing; issuance-time
  filesystem roots: existing, missing, dangling, and outside-alias
  spellings outside the ceiling refused without probing, admitted
  spellings still probed with the canonical ceiling proof fail-closed).

Review-cycle resolution (regular-file extent): an intermediate round
attempted to enforce a regular-file issued root as an exact concrete
authorization capability by stat'ing the live governing pathname at run
time. Review evidence proved that inference reinterprets the immutable
snapshot after issuance: the snapshot persists and digests exactly
position/path/access, so replacing an issued regular-file pathname with
a directory made the live-stat gate admit a descendant the exact-capability
contract promised to refuse — the authorization semantics must come from
the persisted snapshot alone. The live-kind inference is removed; the
accepted authority is the persisted path tree, consistently for directory
and regular-file roots (RED evidence retained in the branch history:
`TestRunMountIssuedFileKindReplacementDoesNotWidenAuthority` proved the
replacement scenario proceeded to pinning instead of refusing). MAC
exact-file semantics remain a defense-in-depth backend fact for
regular-file issued roots, not authorization semantics — the
authorization root is not the MAC boundary. Enforcing an issuance-time
exact-file capability as durable Session filesystem authority (kind in
the persisted snapshot and its digest, kind-aware LookupAccess,
persistence/digest/migration/introspection review) is an explicit
architecture change and is deliberately NOT taken silently inside H3.

### M13 — one canonical Docker bind-mount serialization owner

The audit class: the Docker CLI parses one `--mount` value as ONE CSV
record read once (`opts/mount.go`, `MountOpt.Set` — every field is a
`key=value` pair split on the first `=` or a boolean flag, and later
duplicate keys overwrite earlier ones), while the production run argv
builders concatenated caller-controlled source/target into that record
with `fmt.Sprintf` in three places (user mounts, trusted CA injection,
helper-socket projection) with no encoding and scattered per-caller comma
prohibitions. A crafted target containing an unquoted control character
truncated the record the CLI parses — the trailing `readonly` flag was
silently dropped and the workspace mounted WRITABLE at a different
target (proven RED through the real run path with the authoritative
grammar mirror); quote-carrying values produced a Docker parse error, and
commas were refused scattered instead of represented safely.

Closed with one canonical serializer owner (`dockerBindMountSpec` /
`dockerMountFieldRepresentable`, `docker_mount_spec.go`):

- structured facts `{source, target, readonly}` in, exactly one
  `--mount` argument out; every production bind form (user mounts,
  trusted CA injection, helper-socket runtime projection) builds its argv
  value through the one owner — no second serializer, no per-caller
  ad-hoc concatenation (repo sweep verified);
- the encoding is Go `encoding/csv` — the Docker-sanctioned grammar — so
  commas, quotes, newlines, lone carriage returns, `=` signs, backslashes,
  and internal whitespace stay exactly one field: a crafted value
  cannot add a mount option, change the target, remove `readonly`, add
  `rw`, change type/source, or create a second logical field;
- representability is a three-boundary invariant owned in one place
  (`dockerMountFieldRepresentable`), and a value that fails any boundary
  is refused there: (1) the encoding must round-trip through the
  `encoding/csv` record unchanged — the CSV reader normalizes the literal
  CRLF pair to LF inside quoted fields; (2) the value must survive Docker
  `MountOpt.Set` value validation unchanged — the CLI rejects an empty
  value and a value with leading or trailing whitespace (ASCII or
  Unicode); (3) the value must be exec-argv representable — a Unix exec
  argument cannot carry an embedded NUL byte. Refusal timing follows the
  two value classes. Caller-controlled bind facts — the container target
  in every mode and the canonical resolved source in user mode — are
  proven at request validation: refused `invalid_mount` before pinning,
  before workload-MAC preparation, before the operation admission,
  before `run.start`, and before any Docker state. Actual daemon-owned
  or prepared bind sources — the system-mode pinned source, the
  trusted-CA prepared source, and the helper-socket runtime projection
  source — become known only after the pins and the workload MAC state
  are prepared, so their serialization failure happens after that
  preparation but before the operation admission, before `run.start`,
  and before Docker execution and container creation: the prepared state
  rolls back through the canonical rollback owner and the run answers
  `internal_error` with no admitted Operation;
- the Docker argv is built and serialized after the pins and the workload
  MAC state are prepared — every actual bind source is known — and before
  the operation admission and the `run.start` audit: a serialization
  failure rolls the prepared state back through the canonical rollback
  owner and answers with no admitted Operation left in the supervisor, no
  `run.start` audit event, and no Docker process (proven RED through the
  real user-mode trusted-CA path, where a daemon-owned prepared directory
  carrying a CRLF sequence used to leave one running zombie Operation);
- request validation, filesystem authorization, and Docker argv
  serialization stay separate layers: the serializer owns only the
  encoding/representability, never path policy, and the scattered
  comma prohibitions in `resolveMount` were removed (a comma-carrying
  source/target is now safely representable — an observable public
  change recorded in the CHANGELOG).

Evidence:

- RED through the real run path (exec seam + authoritative grammar
  mirror): hostile targets parsed by the Docker CLI grammar lose the
  intended target and the `readonly` flag on the pre-fix code
  (`TestRunHostileTargetKeepsIntendedBindMountThroughDockerGrammar`).
- GREEN semantic round-trip contract (`TestDockerBindMountSpecContract`):
  ordinary values, both readonly modes, comma/newline/quote/`=`/
  backslash/lone-CR/internal-whitespace and hostile delimiter
  combinations parse back to exactly the intended source/target/readonly
  with exactly the intended key set; CRLF, empty, whitespace-padded
  (ASCII and Unicode NBSP/ideographic-space edges), and NUL-carrying
  fields fail closed.
- GREEN hostile real-Docker evidence (regression group 22,
  `scripts/uat-regression-bind-serialization.sh`, Ubuntu/DEB/AppArmor,
  real Docker): a newline target mounts READ-ONLY at the exact intended
  target (marker readable, write attempt denied, `docker inspect`
  Destination/RW verbatim), the option-injection spelling
  (`/mnt/dta,readonly`) mounts writable at the exact intended target with
  no injected option, a CRLF target is refused `invalid_mount` with no
  container/state residue, and a trailing-space target — representable
  through CSV but rejected by the Docker `MountOpt.Set` value validation
  — is refused `invalid_mount` before Docker with no residue.
- GREEN admission-order evidence through the real user-mode trusted-CA
  path (`TestRunSerializerFailureBeforeAdmissionLeavesNoOperation`): a
  daemon-owned prepared directory carrying a CRLF sequence — reachable
  only with trusted CA injection active — answers `internal_error` with
  no Docker invocation, no admitted Operation left in the supervisor, and
  no `run.start` audit event (pre-fix: one running zombie Operation).
- GREEN exact-candidate UAT on the final closure SHA (full
  `uat-blackbox.yml` scope, producer manifest `source_sha` = workflow
  head SHA): 11/11 jobs success, FAILS 0 / BLOCKED 0, regression groups
  3–22 PASS including group 22 with the Docker value-validation boundary
  case.
 - Server-owned forms serialize through the same owner with unchanged
  behavior (existing CA/helper-socket argv contract tests pass
  unchanged).

## H6 — admin-token rotation through the shipped confined MAC policy

The audit class: `rotateAdminToken` staged the replacement through a
random `os.CreateTemp(configDir, ".admin-token-*")` tempfile. The shipped
confined policy cannot express that lifecycle as a narrow file contract:
AppArmor (`/etc/docker-helper/** r`) denied the tempfile creation
(`apparmor="DENIED" operation="mknod" ... name="/etc/docker-helper/.admin-token-NNN"
requested_mask="c"`) and SELinux denied the config-directory write
(`avc: denied { write } ... tcontext=...docker_helper_config_t:s0
tclass=dir` with `scontext=...docker_helper_t`) — every rotation through
the shipped service failed with `internal_error` (proven RED on the exact
candidate on both backends, 2.2.0-uat).

Closed with a rewritten replacement lifecycle (one owner, the existing
hash commit lock) plus narrowed shipped policy:

- ONE fixed staging pathname `.admin-token.new`, a sibling of the token
  file; an internal implementation pathname, not a config/API/CLI
  surface; no compat path for the old random tempfile spelling;
- the whole lifecycle runs under the existing admin-token hash commit
  lock (no new mutex): the authorizing hash is verified current BEFORE
  the staging pathname is touched — a stale concurrent rotation commits
  nothing and never observes or cleans the winner's staging state;
- crash residue at the exact staging pathname is cleaned by the next
  rotation; create/write/chmod 0600/fsync/close, then the atomic rename
  onto admin.token; every failure — rename included — leaves the current
  token file and the runtime hash unchanged and removes the staging file;
- AppArmor: the ONLY writable config-namespace objects are
  `/etc/docker-helper/admin.token` and `/etc/docker-helper/.admin-token.new`;
  the generic config tree and config.json stay read-only; no broader
  write glob (static regression sweeps every config rule);
- SELinux: dedicated `docker_helper_admin_token_t` file type (MAC
  implementation state, not a domain noun); exact fcontext rules for both
  token pathnames listed before the generic config-tree rule; the full
  replacement lifecycle (create/write/setattr/rename/unlink plus the
  startup read/open/getattr) granted on the token type only; the staging
  object labeled through the EXACT filename transition for
  `.admin-token.new` (no generic config-dir transition);
  `docker_helper_config_t:file` strictly read-only (read/open/getattr)
  and the config directory limited to write/add_name/remove_name; no
  relabel permission granted to the daemon (deployment relabels run from
  the unconfined operator/packaging context);
- ACCEPTED SELinux backend mechanic (release-owner ruling, PR #57 review
  round 2, proven at runtime — see the evidence below): SELinux does NOT
  provide AppArmor-equivalent destination-basename mediation for rename.
  The token type is CREATION-constrained — a newly created staging file
  receives `docker_helper_admin_token_t` only through the exact
  `.admin-token.new` filename transition, and direct creation of an
  arbitrary fresh config-dir name stays denied — but once a token_t inode
  exists, the granted directory namespace
  (write/add_name/remove_name) plus the inode permissions (rename/unlink)
  allow it to be renamed to an otherwise unused basename in the config
  directory. This is an accepted SELinux backend mechanic, NOT additional
  product authority: the rotation lifecycle has ONE production rename
  (`.admin-token.new` -> admin.token) serialized by the existing hash
  commit lock, and no API/CLI/config surface can request an arbitrary
  config-directory rename. No path-policy framework, token subdirectory
  architecture, or rename broker is added to emulate AppArmor pathname
  mediation;
- deployment labeling under the existing selinux_deploy owner: system
  init applies the exact admin-token restorecon immediately after the
  initial token is written (the tree relabel runs before the token
  exists), so a fresh token carries the dedicated type before the first
  daemon start; a failed fresh-init token relabel removes the just-created
  token file (no partial initialization, retry init succeeds; round-2
  blocker fix); the packaged `restorecon -R /etc/docker-helper` migrates
  a pre-H6 token on upgrade/reinstall without changing its value.

Evidence:

- RED AppArmor enforcing (run 34931077818, jobs uat-blackbox-ubuntu,
  uat-blackbox-ubuntu-tarball, uat-blackbox-opensuse-apparmor, exact
  2.2.0-uat artifacts): rotation → `admin_token.rotate result:"error"` /
  500 `internal_error`; `apparmor="DENIED" operation="mknod"
  profile="docker-helper-system" name="/etc/docker-helper/.admin-token-NNN"
  requested_mask="c" denied_mask="c"` captured from the fresh kernel
  audit window.
- RED SELinux enforcing (run 34945281206, job uat-blackbox-opensuse-selinux,
  exact RPM/service in docker_helper_t): rotation → 500 with the daemon
  operational error `cannot create temp token file: open
  /etc/docker-helper/.admin-token-NNN: permission denied`;
  `avc: denied { write } for comm="docker-helper"
  scontext=system_u:system_r:docker_helper_t:s0
  tcontext=unconfined_u:object_r:docker_helper_config_t:s0 tclass=dir`
  captured. Run 34931077818 (uat-blackbox-opensuse-tarball-selinux)
  additionally proved the fresh-install labeling defect of the pre-H6
  artifact: a fresh admin.token inherited
  `unconfined_u:object_r:docker_helper_config_t:s0`.
- GREEN lifecycle regressions: fixed staging pathname as the rename
  source (`TestRotateAdminTokenFixedStagingPath`), crash-residue
  recovery (`TestRotateAdminTokenCrashResidueRecovery`), stale rotation
  never touches the staging pathname
  (`TestRotateAdminTokenStaleDoesNotTouchStaging`), failure cleanup,
  config.json byte-for-byte unchanged
  (`TestRotateAdminTokenConfigJSONUnchanged`); the format/success/mode/
  hash/old-rejected/new-accepted/rename-failure/stale-commit/HTTP-auth/
  audit-leak suites pass unchanged.
- Static policy regressions: AppArmor write-capable config rules only on
  the two exact token pathnames (`TestSystemProfileAdminTokenReplacementSurface`);
  SELinux exact token fcontext rules before the generic rule
  (`TestSELinuxAdminTokenFileContexts`), the token type with the exact
  filename transition, config_t:file read-only, config-dir namespace
  operations limited to write/add_name/remove_name
  (`TestSELinuxPolicyAdminTokenReplacement`); the shipped policy module
  compiles (`scripts/check-selinux-policy.sh`).
- GREEN exact-candidate live enforcing UAT on the final closure SHA
  (full `uat-blackbox.yml` scope, producer manifest `source_sha` =
  workflow head SHA; 11/11 jobs, FAILS 0 / BLOCKED 0):
  - AppArmor (uat-blackbox-ubuntu, uat-blackbox-ubuntu-tarball,
    uat-blackbox-opensuse-apparmor): confinement verified
    `docker-helper-system (enforce)`; installed profile write surface
    asserted = only the two token pathnames; rotation through the public
    CLI succeeded; old token → 401; new token → accepted admin
    operation; admin.token 0600; staging pathname absent; no daemon
    restart (PID unchanged); config.json unchanged; no unexpected
    AppArmor denial on the successful lifecycle.
  - SELinux (uat-blackbox-opensuse-selinux RPM,
    uat-blackbox-opensuse-tarball-selinux): daemon verified
    `docker_helper_t` enforcing; fresh-install labeling proven
    (admin.token=`docker_helper_admin_token_t`,
    config.json=`docker_helper_config_t`); migration/reinstall labeling
    proven (token relabeled `docker_helper_config_t` →
    `docker_helper_admin_token_t` by the exact packaging restorecon
    command, value unchanged); `sesearch` proven no write permission on
    `docker_helper_config_t:file`; rotation through the public CLI
    succeeded; old token → 401; new token → accepted; 0600; staging
    pathname absent; no restart; config.json unchanged; no AVC on the
    successful lifecycle.
- SELinux rename-destination scope proof (run 34955703357,
  uat-blackbox-opensuse-selinux, Tumbleweed enforcing VM, kernel 7.2.4,
  candidate RPM sha256 `eebc701a…`): a controlled exact-policy probe
  executed inside the ENFORCING `docker_helper_t` domain through the
  shipped `SELinuxContext=` transient-service mechanism (operator relabel
  of the probe binary to `docker_helper_exec_t`; no policy change)
  measured the review-round-2 hypothesis and produced the runtime evidence
  behind the ACCEPTED backend limitation above:
  - probe context `system_u:system_r:docker_helper_t:s0`, enforcing;
  - creating `/etc/docker-helper/.admin-token.new` as `docker_helper_t` →
    inode labeled `system_u:object_r:docker_helper_admin_token_t:s0`
    (exact filename transition proven on the create side);
  - VERDICT: renaming that token_t inode to the UNUSED pathname
    `/etc/docker-helper/h6-unused-name` was ALLOWED (and the rename back
    to the staging pathname also allowed) — the exact filename transition
    constrains the CREATED type, not a later rename destination. This
    matches the kernel `may_rename` semantics
    (`security/selinux/hooks.c`): the required permissions are
    `remove_name|search` on the old dir, `rename` on the source inode,
    `add_name|search` on the new dir — all granted; no dir-level `rename`
    permission is checked;
  - existing config objects remain immutable — every negative DENIED
    (EACCES): write-open of config.json, unlink of config.json,
    rename-away of config.json, rename of the token inode ONTO the
    existing config.json (needs unlink on `docker_helper_config_t:file`),
    and creation of an arbitrary fresh config-dir name (no transition →
    inherits `docker_helper_config_t`, create denied). `sesearch` on the
    live policy matched the shipped rules exactly: token file
    `{create getattr open read rename setattr unlink write}`; config dir
    `{add_name remove_name search write}`;
  - admin.token/config.json SHAs and labels unchanged by the probe; the
    probe cleaned up every object it created.
  This investigation machinery (probe + fail-closed UAT stage) was removed
  after the ruling: an ALLOWED rename to an unused basename is NOT a
  permanent required behavior, and a future stricter SELinux/kernel/policy
  would be fine and must not fail UAT. The evidence above is retained as
  the reason the backend limitation is explicitly documented.

## SC1 — M11/M12: host-path text grammar and the real semanage producer grammar

### M11 — control characters are outside the host capability path text grammar

The audit class: the canonical workspace/root policy rejected broad and
forbidden roots but accepted any byte sequence a Unix pathname can carry —
including the control characters that persistent SELinux fcontext records,
AppArmor fragments, and config serialization treat as line-oriented
structure. `escapeFcontextPath` owns only regex-metacharacter escaping, so it
was never the right owner for supported host-path spelling.

Closed at ONE shared text-grammar owner, `validateHostPathText`
(`workspace_path_policy.go`), the single owner of the invariant: a host
capability path must not contain control characters that can desynchronize
line-oriented/tool output or be unrepresentable as a host pathname. The
canonical rule: every rune with `unicode.IsControl` — the C0 controls
(including LF, CR, TAB), the C1 controls, and DEL — is outside the Release
2.2 host-path capability text grammar; embedded NUL is rejected explicitly
for a clearer diagnostic (Unix path syscalls cannot represent an embedded
NUL at all). Ordinary printable characters — ASCII space inside a component,
regex metacharacters, ordinary Unicode — remain supported. It is a
tool-synchronization invariant, not "reject weird filenames".

Owners swept (each consumes the shared owner; no duplicate list in the
SELinux backend, AppArmor backend, handlers, or CLI):

- `canonicalizeWorkspacePathForAdd` — caller spelling refused before any
  filesystem probing; resolved canonical path re-checked through
  `validateWorkspacePathSafety` after symlink resolution;
- `canonicalizeIssuedTreePathForAdd` — caller spelling + resolved canonical
  path (issued-tree MAC hand-off; directory and regular-file kinds both
  covered);
- `validateWorkspacePathPolicy` / `validateWorkspacePathSafety` — the pure
  policy boundary re-checks;
- Session-create admission and `canonicalizeSessionFilesystemRoots` — after
  the H3 lexical ceiling admission (outside-ceiling spellings keep the
  bounded authorization refusal unchanged) and before any privileged probe,
  plus the post-resolution check; every failure keeps its existing canonical
  class (`invalid_workspace` / `invalid_filesystem_policy`);
- `validateBoundaryLexical` delegates the control-character rule to the
  shared owner and keeps only the AppArmor fragment-format grammar;
- every config/CLI/Principal/ownership allowed-root entry point funnels
  through the two canonicalization owners, so no additional surface needed a
  local check.

NUL is special: Unix path syscalls cannot represent an embedded NUL, so NUL
is tested at the pure text-grammar boundary (no real file with NUL can
exist). DEL and other C0/C1 controls are additionally caught at the HTTP JSON
transport boundary for spellings whose JSON encoding the transport itself
rejects — a layered outcome, not the owner.

Evidence:

- RED (commit `637dab6` on the SC1 series, tests run against the pre-fix
  code): 27 failing assertions — real filesystem objects whose final
  component carries LF / CR / TAB / C0 SOH / DEL / C1 NEL accepted by
  `canonicalizeWorkspacePathForAdd`, `canonicalizeIssuedTreePathForAdd`
  (directory and regular-file kinds), and `validateWorkspacePathPolicy`
  (including embedded NUL at the pure boundary); the nonexistent-spelling
  cases prove the pre-fix code answered with the existence error, i.e. the
  unsupported spelling reached the filesystem probe; and the three M12
  real-producer failures below.
- GREEN: the control-character cases are refused with the text-grammar
  diagnostic; the nonexistent control-character spelling is refused with the
  grammar diagnostic and without the existence probe; a symlink spelling
  without controls resolving into a control-character pathname is refused
  after resolution; printable spaces, regex metacharacters, punctuation, and
  ordinary Unicode stay accepted.
- GREEN at the Session boundaries (`TestSessionCreateControlCharacterTextGrammar`,
  `TestFilesystemRootsControlCharacterTextGrammar`): a real control-character
  directory inside the ceiling is refused `invalid_workspace` with zero
  privileged filesystem probes, a harmless symlink alias is refused after
  resolution, and an issuance-time `filesystem_roots` control-character root
  keeps the existing bounded `invalid_filesystem_policy` class and message;
  no live Session exists after any refusal.
- GREEN exact-candidate enforcing-SELinux UAT (regression group 1,
  `scripts/uat-regression-selinux-workspace-lifecycle.sh`): a real directory
  whose pathname carries LF is refused through the public Session-create API
  with the text-grammar diagnostic, the semanage fcontext inventory is
  byte-identical before and after (no semanage mutation, no fcontext
  residue), and the session inventory is unchanged (no Session/MAC
  ownership residue).

### M12 — the fcontext record parser follows the real semanage producer grammar

The audit class: `parseFcontextLine` discovered an ordinary record with
`strings.Index(line, "  ")` — a width-dependent assumption. The real producer
pads the pattern column to a display width and the type column to another;
sufficiently long patterns collapse their padding to the single separator
space and invalidate the assumption.

Closed against the REAL producer, not a synthetic guess. Evidence capture on
the supported Tumbleweed/SELinux UAT guest (policycoreutils 3.11-2.2,
selinux-policy-targeted 20260910-1.1; capture machinery
`scripts/uat-semanage-grammar-evidence.sh` committed with the RED
infrastructure and removed after the evidence was committed): local rules
created through the real `semanage fcontext -a` for a short pattern, a
pattern beyond the display width, a substantially longer one, a long exact
(regular-file) pattern, regex metacharacters escaped exactly as docker-helper
emits them, an equivalence record, and a `<<none>>` probe; the RAW
`semanage fcontext -l -C -n` bytes preserved exactly (printable + `od -c` +
base64) and committed as `testdata/semanage-fcontext-producer-capture.txt`
(byte-verified against the run dumps). The producer source grammar
(`seobject.py` `fcontextRecords`: `"%-50s %-18s %s"` forms) confirms the
record shape.

Real-producer findings:

- an ordinary record's pattern column never contains an ordinary space:
  semanage itself refuses space-carrying file specifications at add time
  ("File specification can not include spaces", captured). A space-carrying
  host path on enforcing SELinux therefore fails closed at backend mechanics
  (unchanged behavior), and the format is NOT ambiguous for any
  docker-helper-supported fcontext spelling — including the trailing-space
  boundary, which the producer refuses at add time as well (captured). No
  new public path restriction was added, so no architecture stop applies;
- the middle type column (e.g. `all files`) may itself contain spaces and is
  padded, so the parser must not tokenize the whole line.

Old-parser failures proven against the captured records (RED, same commit
`637dab6`): for a record whose pattern is at or beyond the pattern column's
padding width, `strings.Index(line, "  ")` lands in the type column's
padding, folding ` all files` into the parsed pattern — the helper's own
rule becomes unfindable (the second ensure re-adds/fails closed as
"unclassifiable") and its removal leaves the rule behind (ownership "proves"
absence for a present rule); and the real-shape `<<None>>` record (with the
type column) failed closed as unparseable, breaking every fcontext operation
while such an operator rule exists.

New parser grammar (one owner, `parseFcontextLine`; no parallel long-rule
path): after the unchanged equivalence-redirect check (`DEST = SOURCE`),
the record's FIRST whitespace token is the complete pattern and its LAST
whitespace token is the complete context — whatever the padding runs
collapsed to — with the padded middle type column ignored for
classification. No fixed display width is encoded, no `strings.Fields`
whole-line tokenization is used, parsing is not dependent on today's path
lengths, and the context classification (`<<None>>`, `object_r:` extraction
covering both the plain and the accepted `gen_context(...)` context shapes)
is byte-for-byte the existing logic. `listLocalFcontextRules` still trims
each line, skips empties, and fails closed on any non-empty unclassifiable
record; the parsed rules feed the SAME `fcontextRule` model and the SAME
overlap/ownership owners (`-C -n` local customizations only; operator
overlap fail-closed; equivalence records checked; regex-literal round-trip
still the authority for literal stems; helper-owned vs operator-compatible
ownership unchanged; removal never deletes an unproven operator rule).

Evidence:

- RED (commit `637dab6`): the three long captured records parse with the
  polluted pattern (`…(/.*)? all files`) and the real-shape `<<None>>`
  record fails closed through `listLocalFcontextRules`.
- GREEN deterministic tests from the captured bytes
  (`TestParseFcontextLineRealProducerRecords`,
  `TestParseFcontextLineFailClosedRealistic`,
  `TestListLocalFcontextRulesRealProducerCapture`): every captured record
  parses to the exact pattern byte-for-byte, the exact type, and the exact
  equivalence identity; the whole capture yields all eight records in
  captured order across two inspections (no loss, no reordering); realistic
  malformed records (type column without a context, context not the final
  token, single token) still fail closed.
- GREEN exact-candidate enforcing-SELinux UAT (regression group 1): a
  workspace whose directory pattern exceeds the producer's padding width
  runs the normal lifecycle twice — create (rule created, raw producer
  record and actual type asserted), second create on the SAME path
  (re-observing the SAME rule through the parser — the RED behavior was the
  "unclassifiable" refusal), consumer-count release (the rule is kept while
  the first consumer still holds the boundary), and final removal (rule
  removed, tree relabeled back) — with no false overlap, no unparseable
  error, and no unexpected AVC in the lifecycle window. The long proof path
  is spelled without spaces per the captured producer evidence above.

## SC1 — M4: one strict config document ingest boundary

The audit class: startup/load validated the raw document (exact canonical
keys) and then decoded the ORIGINAL untrusted byte stream into `fileConfig`
with `encoding/json`, whose struct matching also accepts case-insensitive
matches against the json tag. The two consumers did not share one key
grammar: a later case-variant member silently overwrote a validated
canonical value, and the folded value was never revalidated — reaching
`operationSupervisor.pruneCompleted(..., maxCompleted)`, whose negative cap
deterministically panics at the slice boundary.

Closed with ONE strict ingest boundary and no second decode:

- `decodeStrictConfigDocument` owns the JSON object grammar: exactly one
  top-level object, no trailing tokens, and duplicate top-level members
  fail-closed (the persisted config is security policy/state: one JSON
  member maps to one config identity, never last-wins; no compatibility
  mode). Member names are preserved byte-for-byte.
- `validateConfigMemberGrammar` owns exact key recognition: computed fields
  keep the computed diagnostic, deprecated fields the rename diagnostic,
  retired fields the retired diagnostic, and every other member must be a
  known config-file key with EXACT spelling — `Operation_Max_Completed`,
  `Session_TTL`, `SESSION_TTL`, `Audit_Enabled`, `Allowed_Roots` are refused
  as unknown, never aliases. No case normalization, no alias map.
- `validateRawConfig` composes member grammar + the unchanged value
  validations (one value authority: `parseSessionTTL`, `parseLogLevel`,
  duration/integer bounds, trusted-CA values, `validateHTTPAddress`, the
  `allowed_roots` schema with the exact nested `{"path","access"}` object
  grammar).
- `decodeAndValidateConfigDocument` composes the above and projects
  `fileConfig` from the proven exact-key map — the original untrusted byte
  stream is never struct-decoded after raw validation. Production consumers
  migrated: `loadAndPrepareRuntimeConfig` (startup + reload),
  `initSystem`'s existing-config inspection, `loadRawConfigFile` (all
  config CLI surfaces), and the config transaction preflights. No
  production `json.Unmarshal(originalConfigBytes, &fileConfig)` remains.
- Side-effect ordering: the refusal happens before the runtime-directory
  creation and before trusted-CA preparation; a reload failure leaves the
  previous effective configuration authoritative (the existing reload
  owner unchanged).
- Mutation semantics: a config transaction on an existing document carrying
  an unknown, case-variant, or duplicate member is refused BEFORE any
  mutation, without rewriting the file — no mutation erases the evidence of
  malformed input as a side effect. Invalid member VALUES keep their
  existing repair semantics (setting/unsetting the invalid field itself is
  the documented operator recovery — `TestRegressionRepairInvalidField`
  unchanged).
- Compatibility sweep: no documented stable Release 2.x spelling is rejected.
  The exact legacy `allowed_root` migration input keeps its contract; the
  former silent preservation of unknown members (pinned only by the
  incidental `TestConfigPreservesUnknownMembers`, never documented in any
  man page, architecture, or changelog) is the explicit strict-grammar
  change of this closure.

Evidence:

- RED (commit `262f563`, tests through the existing entry points against the
  pre-fix code): `validateRawConfig` accepted case-variant members and
  unknown top-level members silently; `loadRawConfigFile` accepted duplicate
  top-level members (map decode collapses them, last wins); and the exact
  RED payload — canonical `operation_max_completed: 200` followed by
  `Operation_Max_Completed: -1` — LOADED SUCCESSFULLY through the real
  production ingest (`loadAndPrepareRuntimeConfig`) with an effective
  `OperationMaxCompleted` of -1, while the reverse member ordering yielded
  200 (acceptance depended on JSON member order). A contained
  `pruneCompleted` consumer proof shows the negative cap deterministically
  panics at the slice boundary.
- GREEN: the full key table (every canonical key accepted at its exact
  spelling; a case variant of every key refused as unknown), the exact
  legacy `allowed_root` behavior, deprecated/retired/computed exact-spelling
  diagnostics (case variants answered with the unknown diagnostic),
  structural JSON cases (null/array/scalar/malformed/trailing second value/
  duplicates), and order-independence (a case variant refused before AND
  after its canonical spelling).
- GREEN security regressions: the RED payload is refused; no negative value
  ever reaches effective Config (either the document is refused or the
  effective value is canonical); the refusal occurs with zero runtime-dir
  resolutions (`TestStrictIngestRefusalBeforeRuntimeSideEffects`), so no
  MAC/CA/runtime state can derive from a malformed value.
- GREEN config CLI: `config show` and `config show FIELD` refuse duplicate/
  unknown/case-variant/trailing documents; `config set`, `config unset`,
  and `config allowed-root add` refuse a malformed existing document and
  leave config.json byte-for-byte unchanged; canonical documents keep their
  normal show/set/unset/reload behavior (existing suites unchanged).
- GREEN exact-candidate black-box UAT (regression group 21,
  `scripts/uat-regression-allowed-root-recovery.sh`, Ubuntu/DEB/AppArmor,
  real system service): startup fails closed on the injected RED payload in
  the real `/etc/docker-helper/config.json` with the bounded journal
  diagnostic and no panic evidence (J); restoring the canonical bytes
  restores normal startup (K); reload refuses the malformed document while
  the running daemon keeps serving the previous effective config, and
  reload succeeds again after the restore (L); `config set` and
  `config allowed-root add` refuse the malformed document with the file
  bytes unchanged (sha256 before/after) (M); unknown-member startup refusal
  (N); duplicate-member startup refusal (O); the canonical config still
  starts, reloads, and mutates normally after all refusals (P).

## SC1 — M5: one Principal username text grammar before OS identity resolution

The audit class: system-mode Principal creation checked only non-empty
input, resolved the supplied string through the libc-backed `user.Lookup`,
and persisted the ORIGINAL request string with the resolved UID/GID/home.
Under the C-string OS resolver ABI, the lookup of a NUL-bearing spelling is
interpreted as the truncated canonical spelling, so one OS account answered
for two distinct text identities while SQLite persisted BOTH as Principals
(the NUL-alias create succeeded end to end — 201 with an issued credential
— while `principals.username` kept a value no valid OS account spelling
corresponds to). The user-mode daemon-owner path
(`ensureUserModeOwnership` → `OSUserLookupByUID` →
`insertDaemonOwnerPrincipal`) had the same shape for an OS-returned
username.

Closed with ONE grammar owner, `validatePrincipalUsername`
(`principal.go`), owning the Release 2.2 Principal username text grammar:
non-empty, and no Unicode control rune (`unicode.IsControl` — the C0
controls including LF/CR/TAB, DEL, the C1 controls; an embedded NUL is a
C0 control). Every other spelling is accepted EXACTLY as supplied — no
trim, no case-fold, no Unicode normalization, no alphabet, case, or length
rule, no invented useradd regex — and passed unchanged to the OS account
resolver, which remains the authority for account existence. The refused
class is one domain error (`ErrInvalidPrincipalUsername`); the public
contract is `400 invalid_username` with the bounded message "invalid
username" (the hostile spelling is never echoed into the public error),
keeping the existing `missing_username`, `os_user_not_found`, and
`409 principal_exists` contracts unchanged.

Production wiring (both Principal INSERT paths; no second validator):

- `createPrincipalWithOptionalCredential` runs the grammar FIRST — before
  `OSUserLookup`, before home canonicalization and the global-ceiling
  proof, before the transaction, the Principal INSERT, the default
  Launcher provisioning, and the optional initial credential. The handler
  only maps the domain result to the wire contract and classifies the
  refused create distinctly in the audit (`invalid_username`), retaining
  the supplied PrincipalName through the existing structured-audit JSON
  escaping (no second log sanitizer).
- `ensureUserModeOwnership` runs the same owner on the
  `OSUserLookupByUID`-returned username before that value is used as a
  Principal DB identity: a control-bearing resolved spelling fails
  startup closed, inserting no Principal row and no default Launcher, and
  daemon startup aborts before the ownership migration, so no migration
  runs under that identity. OS resolver semantics are unchanged, and a
  valid resolved spelling remains the stored identity — no
  OS-returned-username substitution in either path.

Evidence:

- Real libc/NSS backend reproduction: the shipped static candidate is
  `CGO_ENABLED=1`, so `os/user` resolves through the libc getpwnam ABI.
  On the musl 1.2.6 evidence environment, a cgo build's
  `user.Lookup("root\x00alias")` returned username "root", uid 0 — the
  NUL-bearing spelling resolved AS the canonical account while remaining a
  distinct Go string; the same aliasing was reproduced with a direct
  `getpwnam("root\0alias")` C probe (the C string terminates at the first
  NUL). The pure-Go backend (`CGO_ENABLED=0`) instead errors on the
  spelling — a backend-dependent interpretation, which is exactly why the
  grammar removes the resolver spelling question from the trust boundary
  entirely rather than trusting either backend's accident.
- RED (commit `8b47725`, tests through the existing entry points against
  the pre-fix code): with the OSUserLookup seam aliasing the NUL spelling
  to the canonical identity (the same uid/gid/home), the NUL-alias create
  answered 201 through the real `POST /principals` route with an issued
  credential and bearer token in the response, the resolver was consulted
  with the hostile spelling, and SQLite persisted two distinct username
  TEXT identities for one OS identity
  (`TestPrincipalCreateNULAliasPersistsDistinctIdentity`, defect
  demonstration); the desired-behavior tests (refusal matrix, distinct
  audit classification, user-mode fail-closed) failed as designed.
- GREEN: the direct grammar matrix (`TestValidatePrincipalUsernameGrammar`);
  the wire refusal matrix through the real handler for NUL-alias, bare
  NUL, LF, CR, TAB, SOH, DEL, and C1 NEL spellings with `issue_credential`
  false and true — every refusal answers `400 invalid_username` with the
  bounded message, consults `OSUserLookup` ZERO times, and leaves no
  Principal, principal_allowed_roots, Launcher, or credential row and no
  token in the response
  (`TestPrincipalCreateControlUsernameRefusedBeforeOSUserLookup`); the
  alias can no longer coexist with the canonical Principal (exactly one
  identity; the canonical create with `issue_credential=true` keeps its
  credential; `TestPrincipalCreateNULAliasCannotCoexistWithCanonical`);
  the domain create path refuses with the typed error class and zero
  resolver calls
  (`TestPrincipalCreateRefusesInvalidUsernameDomainError`); printable
  spellings (spaces, punctuation, printable non-ASCII) are NOT rejected
  and reach the resolver with the exact supplied spelling
  (`TestPrincipalCreatePrintableUsernamePassesToResolverUnchanged`);
  unchanged contracts (`missing_username`, `os_user_not_found`,
  `principal_exists`) plus the audit classification with the
  PrincipalName round-trip and no secret keys
  (`TestPrincipalCreateInvalidUsernameAuditClassified`); the user-mode
  path refuses a control-bearing resolved username before any DB identity
  use and with no ownership state
  (`TestEnsureUserModeOwnershipRefusesControlUsernameBeforeDBIdentity`),
  with the valid user-mode ownership suites unchanged.
- GREEN exact-candidate raw-JSON UAT (Release-2 acceptance suite,
  scenario M5, Ubuntu/DEB/AppArmor, real system service): real disposable
  OS account; raw authenticated `POST /principals` with
  `M5_USER\u0000alias` and `issue_credential=true` → `400
  invalid_username`, no token/credential in the response, no alias row in
  the Principal list, no Launcher for an alias Principal, service healthy;
  canonical create succeeds with the real OS user's UID/GID/home and
  exactly one Principal; the alias retry after the canonical create stays
  `invalid_username` (not `principal_exists`, `os_user_not_found`, or
  `internal_error`), proving grammar admission precedes OS resolution and
  DB uniqueness;   LF/TAB/DEL raw-JSON spellings answer the same bounded
  refusal with no residue; ordinary Principal create/lifecycle still works
  afterward; the CLI surfaces the daemon refusal (no local CLI grammar).

## SC1 — M2: shipped bearer-token examples never expand the bearer into curl argv

The audit class: shipped executable examples constructed the Authorization
header by shell-expanding the real bearer value into curl's argv
(`-H "Authorization: Bearer $TOKEN"`), exposing the secret through
`/proc/<curl>/cmdline` to an observer with sufficient process visibility.
The HTTP protocol itself (`Authorization: Bearer <token>`) is unchanged and
stays unchanged: M2 is a shipped-guidance fix, not an auth/API change.

Inventory (complete sweep of shipped current guidance: README.md,
`.claude/skills/docker-helper/SKILL.md`, docs/agent-integration.md,
docs/man/*, packaging/README.release.md, and the current architecture text;
searched for curl/Authorization/Bearer/token-variable combinations):

- Class A (executable current shell examples — fixed): README.md carried
  ten Session examples (pull, build, build with build_args, operation
  status, operation logs, run, run status, run logs, cancel, registry
  login) spelling `-H "Authorization: Bearer $SESSION_TOKEN"`, plus the
  admin raw-HTTP session listing that read the real token with
  `ADMIN_TOKEN=$(docker-helper config show admin_token)` and expanded it
  into curl argv; SKILL.md carried the delegated-credential Session
  creation reading the credential file into `CREDENTIAL` and expanding it,
  plus four Session examples spelling
  `-H "Authorization: Bearer $DOCKER_HELPER_SESSION_TOKEN"`.
- Deliberately unchanged: conceptual protocol notation (`Authorization:
  Bearer <token>` in architecture.md, the README Bearer-authentication
  security bullet, the agent-integration guide's conceptual Bearer
  mention); historical/plan/audit documents; and internal test/UAT
  scripts (class D, not the audit finding's documentation surface). The
  man pages carried no executable bearer example and were not given one.

Closed with ONE canonical safe pattern for all shipped Bash examples: a
header producer piped into curl's header-from-stdin form (`-H @-`), so the
bearer transits stdin and never enters a process argument:

- `docker_helper_session_header` — the environment-held Session bearer
  (`DOCKER_HELPER_SESSION_TOKEN`, the existing canonical environment name;
  the former unexplained `$SESSION_TOKEN` alias is gone);
- `docker_helper_header_from_file` — a file-backed bearer whose argument
  is only the FILE PATH; the admin example now uses the existing computed
  path surface `ADMIN_TOKEN_FILE="$(docker-helper config show
  admin_token_path)"` (preserving relocated `DOCKER_HELPER_CONFIG`
  behavior); `config show admin_token` product behavior is unchanged.
- No derived Authorization-header temp file, no token printed, no command
  substitution that puts the bearer back into a curl argument, and the
  examples stay copy-paste executable (both producers are defined once per
  guide).

Evidence:

- RED synthetic-bearer argv proof (pre-fix docs, deterministic, no
  daemon, no real secret): with a synthetic marker held in the
  environment, the old executable shape `-H "Authorization: Bearer
  $TOKEN"` places `Bearer <marker>` in the live curl
  `/proc/<pid>/cmdline` (executed and recorded as part of
  `TestShippedHeaderProducersDeliverBearerWithoutArgvExpansion`'s
  detector-sensitivity case, which asserts the leak IS detected). The
  static regression failing on the pre-fix tree is the companion RED
  (first failure: README.md:931).
- GREEN argv-absence proof: executing the shipped environment-backed and
  file-backed producer shapes with the synthetic marker shows the live
  curl argv carrying exactly the literal `-H` and `@-` elements and NOT
  the bearer value (in-memory comparison; the marker never appears in any
  helper process argument).
- Exact-header delivery proof: the same executed pipelines deliver the
  exact `Authorization: Bearer <marker>` header to a local HTTP receiver,
  and the file-backed helper leaves no derived header file (its argument
  is only the token path).
- Static regression owner: `release_2_2_security_hygiene_test.go` —
  `TestShippedDocsNeverExpandBearerIntoCurlArgv` scans the explicit
  shipped current-guidance file set (README.md, SKILL.md,
  docs/agent-integration.md, both man pages) for the failure class
  (`Authorization: Bearer $...`, `$(...)`, backtick forms) and does not
  match conceptual `<token>` notation;
  `TestShippedHeaderProducersDeliverBearerWithoutArgvExpansion` owns the
  executable synthetic-bearer proofs above. No generic documentation
  framework was created.

## Release-cycle integration

Security closure is inserted **after the Release 2.2 feature contract is frozen
and before Phase 2.2.7 can declare the stable release candidate accepted**. No
new product feature may enter Release 2.2 while this gate is open.

The required order is:

```text
existing 2.2 feature work / RC fixes
        |
        v
SC0  current-line audit rebase and terminal classification      CLOSED
        |
        v
SC1  immediate trust-boundary / parser / MAC closure            NEXT
        |
        v
SC2  bounded-resource and liveness closure
        |
        v
SC3  explicit architecture dispositions for remaining questions
        |
        v
SC4  adjacent hardening/documentation cleanup
        |
        v
security cross-boundary UAT on exact candidate artifacts
        |
        v
full Phase 2.2.7 release gate + final architecture/docs review
        |
        v
stable v2.2.0
```

SC1 and SC2 may be implemented as several narrow series. Each series must keep
one owner, establish RED evidence before the production fix where practical,
and run the affected exact-artifact/live-MAC gate. Do not batch unrelated
findings merely because they came from the same audit.

## SC1 — C3: descriptor-safe recursive SELinux restorecon

The audit class: old libselinux recursive `restorecon` walks a tree by
pathname and relabels whatever a path resolves to at relabel time; a hostile
Principal who can replace pathnames DURING the walk (rename/symlink swap of a
workspace path component) can redirect the relabel to a foreign inode outside
the issued workspace. `selinuxFcontextManager.restoreconTree` is the primary
surface: the recursive relabel of Principal-mutable workspace trees.

Recursive-restorecon owner inventory (complete, with classification):

- `selinuxFcontextManager.restoreconTree` (workspace/issued-tree relabel;
  fresh, idempotent, and removal-rollback shapes) — recursive,
  Principal-mutable, executed by the confined `docker_helper_t` daemon.
  THE C3 hostile surface; gated below.
- `restoreconTrustedCATree` (`ca.go`) — recursive over the trusted-CA
  runtime tree; helper/root-owned runtime material in the confined daemon;
  no hostile Principal can create or replace pathnames inside it, so the C3
  race cannot cross the trust boundary there; covered by the same
  packaged/install-time libselinux guarantee.
- `relabelDeploymentConfigState` (`selinux_deploy.go`) — recursive over
  `/etc/docker-helper` and `/var/lib/docker-helper`; helper/root-owned
  deployment state, executed by `init` before the service exists; no
  Principal-mutable content; same guarantee.
- `install-system.sh` / rpm `postinstall.sh` recursive deployment
  restorecons — root package/install context, run after the package
  dependency gate (RPM) or the installer admission gate (tarball);
  helper/root-owned paths only. Exact-path restorecon calls (Docker CLI,
  bindfs, admin token, `/run/docker-helper` dir) are not recursive and are
  not C3 work.

Accepted libselinux implementation rule (Phase A evidence, exact candidate
enforcing Tumbleweed): upstream 3.11+ when proven. Source evidence: the
libselinux 3.11 `selinux_restorecon` rewrite labels every inode through
`/proc/self/fd/<fd>` paths (`fd_path_getfilecon`/`fd_path_setfilecon` over a
pinned directory/file descriptor, eliminating the TOCTOU between label
lookup, context query, and context write) and probes `/proc` once with
`statfs("/proc")` + `PROC_SUPER_MAGIC` (`probe_proc()`); when real procfs is
unavailable it falls back to pathname `lgetfilecon_raw`/`lsetfilecon_raw`
labeling — the pre-3.11 TOCTOU composition. The official 3.11 release notes
state the rewrite ("Rewrote libselinux selinux_restorecon(3) to eliminate
TOCTOU issues in file relabeling if /proc is available ... If /proc is not
available, selinux_restorecon(3) falls back to just passing the full pathname
each time"). The 2022 `7e979b56fd2cee28f647376a7233d2ac2d12ca50` attempt
("pin file to avoid TOCTOU issues") and its revert
`de285252a1801397306032e070793889c9466845` document both the fd-based
mechanism and WHY the pathname fallback exists (chroot environments without
/proc) — which is exactly why the runtime procfs prerequisite is separate and
mandatory for hostile trees. The command frontend (`restorecon(8)`) version
is NOT accepted as proof of the loaded implementation: the finding lives in
libselinux, so the proof target is the libselinux package the restorecon
frontend links against. Package evidence on the supported environment:
Tumbleweed ships `libselinux1-3.11-2.1` and `policycoreutils-3.11-2.2`
(the restorecon frontend, owned by policycoreutils, linking
`libselinux.so.1`); `/proc` is real procfs (fstype `proc`, statfs magic
`0x9fa0`) with usable `/proc/self/fd`. No <3.11 backport exception exists on
the currently supported SELinux path, so no backport table was built.

Closure (three owners, one per responsibility; no second workspace relabel
abstraction, no second fcontext lifecycle):

- Packaging (RPM): the RPM hard-depends on `libselinux1 >= 3.11`
  (`policycoreutils` stays the restorecon frontend dependency; it was NOT
  turned into a version-floor substitute for libselinux). The floor is
  asserted from the BUILT RPM metadata (`rpm -qp --requires` shows
  `libselinux1 >= 3.11`), not merely the nfpm source text; the AppArmor-only
  DEB must not gain libselinux dependencies. With a versioned hard Requires,
  rpm dependency resolution refuses installation against an older installed
  libselinux1 (downgrade refusal is inherent to the floor expression).
- Packaging (tarball): `check_libselinux_floor` in `install-system.sh` runs
  inside `check_selected_mac_tools` — BEFORE any SELinux installation
  mutation — and establishes the installed implementation from the rpm
  package database on the supported openSUSE SELinux path: restorecon must
  link `libselinux.so.1` (ldd), the resolved library must be owned by
  `libselinux1` (rpm -qf on the readlink-resolved path), and that package's
  version must satisfy the floor (bounded numeric compare). Missing rpm
  authority, missing ldd, missing linkage, foreign owning package, older
  version, and unparseable version all fail closed with actionable
  diagnostics before any mutation; no generic-distro version heuristic
  exists and the AppArmor path invokes neither ldd nor rpm.
- Runtime (procfs prerequisite): ONE owner,
  `procfsUsableForRestorecon` (statfs `/proc` vs `PROC_SUPER_MAGIC`,
  mirroring upstream `probe_proc()`), consumed by the recursive workspace
  relabel owner `restoreconTree` immediately before the recursive command,
  and by `ensureTreeFcontext` BEFORE any fcontext state is read or mutated
  (a fresh boundary never adds a rule it may not be able to relabel
  descriptor-safely — no half-applied ownership state; the existing
  restorecon-failure rollback semantics are unchanged). Without real procfs
  the refusal is bounded and actionable and the restorecon command count is
  zero. Mount-boundary safety (`checkTreeRelabelBoundary`) remains the
  separate mount-point invariant owner and was not reinterpreted.

RED evidence (commit `ceeea4b`, tests against the pre-fix code): the defect
demonstrations (`TestC3EnforcingManagerReachesRecursiveRestoreconWithoutAdmission`,
`TestC3RestoreconTreeInvokedForEveryWorkspaceRelabelShape`) proved an
enforcing manager walks a Principal-mutable workspace all the way to the
recursive restorecon invocation with nothing between the fcontext lifecycle
calls and the recursive walk — no descriptor-safe-implementation admission
and no procfs consultation anywhere on the path (pre-fix the manager had no
procfs logic at all, so a non-proc /proc was indistinguishable and the
relabel still ran). The installer fake-tool suite
(`TestInstallSystemSelinuxLibselinuxFloor`) and the nfpm floor assertion
(`TestNfpmConfigFile`) failed as designed pre-fix: the tarball SELinux path
accepted old/unverifiable/missing/malformed libselinux provenance and the
RPM declared no floor. The runtime refusal branch did not exist pre-fix, so
its fail-closed behavior is pinned together with the seam in the fix commit
(`TestC3RecursiveWorkspaceRelabelFailsClosedWithoutRealProcfs`: zero
restorecon invocations, no rule add, bounded actionable error, on the fresh,
idempotent, and removal shapes; the real owner accepts real procfs,
`TestC3ProcfsUsableForRestoreconAcceptsRealProcfs`).

GREEN exact-candidate enforcing UAT (new regression group 7,
`scripts/uat-regression-selinux-c3-restorecon-race.sh`, registered in
`uat-regressions-runner-selinux.sh`): prerequisite evidence on the live
guest (libselinux1 floor satisfied, policycoreutils frontend, restorecon
ownership and linkage, resolved library owned by libselinux1, `/proc` real
procfs with usable `/proc/self/fd`); bounded hostile race — three rounds of
session create/delete while a Principal-owned process (sudo, unprivileged)
swaps the workspace path component `rw/swap` between the real directory and
a symlink to a Principal-owned victim tree OUTSIDE the issued workspace
(4000 swaps per round; the victim starts with a non-workspace type and
`docker_helper_t` holds the `fowner` capability grant, so a labeling escape
WOULD have been observable): the victim file and inner tree never received
`docker_helper_workspace_t` and never changed inode identity, the workspace
relabel completed or failed safely each round, no stale helper-owned
fcontext ownership survived release, the service stayed healthy, and the
normal session/workspace lifecycle (rule creation, workspace type, container
RW, delete) still worked afterward. The host /proc is never altered to
manufacture the negative case; the zero-command refusal is proven at the
runtime seam (section 9). The tarball path additionally exercises the
installer admission live in the tarball/SELinux VM job on real Tumbleweed
(`libselinux1-3.11` present → proceeds).

## SC1 — immediate trust-boundary, parser and MAC closure

**Queue:** none — SC1 is CLOSED. (C1, H9, H2, H3, M13, H6, M11, M12, M4,
M5, M2, and C3 are all closed — see the SC1 evidence ledger below.)

SC1 contains defects that are locally actionable through existing owners and
whose fixes do not require the larger resource-control or architecture
questions of SC2/SC3.

Implementation constraints:

- C1/H9: one workload privilege-floor owner; do not scatter privilege flags
  across `run.go`, MAC backends and tests. Staging strips privilege bits at the
  staging owner.
- C3: prove a safe lower-layer libselinux implementation or fail closed; no
  second recursive traversal implementation. (Closed: RPM floor
  `libselinux1 >= 3.11` proven from the built package, tarball installer
  package-metadata admission before any SELinux mutation, one runtime procfs
  owner gating the recursive relabel owner; see the SC1 evidence ledger.)
- H2: reuse the Session issuance/lifecycle linearization owner.
- H3: preserve rich diagnostics in operational logs while bounding public
  errors.
- H6: MAC changes are as narrow as the token replacement lifecycle; no write
  grant to the whole config directory. (Closed: one fixed staging pathname,
  exact-path AppArmor grants, a dedicated SELinux token type with an exact
  CREATE filename transition, config tree read-only; the accepted SELinux
  rename-destination limitation is a backend mechanic, not a product write
  grant — see the SC1 evidence ledger.)
- M4: one config grammar/decoder owner.
- M5: one accepted Principal username grammar before OS lookup and
  persistence. (Closed: one grammar owner, `validatePrincipalUsername`,
  refusing empty and control-bearing spellings before the resolver on both
  Principal write paths; every other spelling is persisted exactly as
  supplied — no second name grammar, see the SC1 evidence ledger.)
- M11: host-path control-character policy belongs to the shared path owner.
- M12: the parser follows the producer grammar, not terminal-width spacing.

## SC2 — H7: the optional loopback TCP listener is never authoritative

The audit class: `prepareListeners` created the authoritative Unix listener
first and then treated a TCP bind failure as fatal — it closed the live Unix
listener, removed its socket, and failed the whole startup. A local
unprivileged user could bind and hold the configured loopback TCP port
(`127.0.0.1:52375` default) before service startup, denying the authoritative
Unix service and, with the shipped `Restart=on-failure` +
`StartLimitIntervalSec=60s` / `StartLimitBurst=3` unit, driving the whole
system service into a restart storm and start-limit failure.

Closed at the existing listener owner (`prepareListeners` in `listener.go`)
with an explicit narrow return contract — no second listener manager, no
global state:

- the Unix listener is authoritative: Unix creation failure remains a fatal
  startup error, and no TCP bind is attempted after it;
- a TCP bind failure after a successful Unix bind is DEGRADED STARTUP: the
  Unix listener stays open, its socket is not removed, the complete API keeps
  serving over Unix, the TCP listener is absent for this daemon lifetime, and
  exactly one bounded operational warning (existing operational logging
  owner, `serve_startup` operation field) names the configured address and
  the bind failure — never a fatal `daemon startup failed` record, and no
  audit state;
- the bind itself is the authority: no pre-probe (a check-then-bind sequence
  would only add a race), and no retry/rebind, timer, watcher, queue, or
  listener state machine — a port that becomes free later stays unused until
  the next normal service restart;
- `Serve()`-time failures on an already-created TCP listener keep the
  existing shutdown/error semantics (not part of H7); user mode is unchanged
  (the TCP creator is never consulted); cleanup with a nil TCP listener is
  unchanged (nil-safe);
- systemd `Restart=`/`StartLimit*` values are NOT the fix and are untouched.

Evidence:

- RED (commit `1e34c8c`, seam-based, deterministic — no port timing): the
  defect demonstration proved the pre-fix startup failed and DESTROYED the
  successful Unix listener (closed + socket removed) on a deterministic TCP
  EADDRINUSE; the desired-behavior test failed pre-fix as designed. The
  seam-enablement type correction (`ListenerFactory` typed as its interface;
  the comment already promised replaceability) changed no behavior.
- GREEN (commit `bc60f4b`): Unix failure still fatal with zero TCP attempts;
  healthy system mode returns both listeners with no warning; degraded
  startup keeps the Unix listener live and the socket in place, reports the
  degradation to the caller (non-fatal), emits exactly the intended warning
  (configured address + bind failure, at warn level, never a fatal startup
  record), consults the TCP creator exactly once (no retry); user mode never
  attempts TCP; `serveHTTPUntilShutdown` with a nil TCP listener serves the
  complete API over Unix and cleanup with a nil TCP listener closes Unix and
  removes the socket.
- Hostile exact-candidate UAT (new Ubuntu/DEB/AppArmor regression group 23,
  `uat-regression-h7-tcp-port-capture.sh`, real packaged service with
  mandatory MAC active — the finding is not MAC-specific, so no duplicate
  per-MAC logic exists): an ordinary unprivileged local user bound and held
  the configured loopback port; the service restarted and stayed active
  (NRestarts bounded, no start-limit/failed state), the authoritative Unix
  socket existed and served `/health` plus an authenticated API operation,
  the hostile process still owned the port (same pid/uid — docker-helper did
  not steal or replace it), the journal carried exactly one bounded
  degraded-TCP warning containing the configured address and the bind
  failure and no fatal startup record, and after the hostile listener was
  released and the service was normally restarted, both Unix and TCP
  listeners worked again with no degradation warning in the recovery window.

## SC2 — H4: build staging has measured hard ceilings

The audit class: the build flow created the Operation ID and staged the
complete build context before `OperationSupervisor.admit()`, with no
resource ceiling anywhere in `staging_linux.go`: a hostile Session
workspace could drive the helper to copy an unbounded number of payload
bytes into the runtime tmpfs, create an unbounded number of destination
entries (inodes), recurse an unbounded directory depth (destination
nesting plus Go recursive stack), and hold an unbounded
`[]dirEntry` slice in daemon memory while enumerating one very large
directory — `readDirectoryEntries` accumulated the entire directory
before `copyEntry` could make any per-entry decision.

Closed at the existing staging owner (`StageBuildContext` →
`stageBuildContextInternal` → `walkAndCopy`/`readDirectoryEntries`/
`copyEntry` in `staging_linux.go`) with one narrow H4-specific budget
owner — no second filesystem walker, no pre-scan, no generic resource
framework, no configuration surface, and no change to the
descriptor-relative/openat2 security model:

- **Exactly three dimensions, one budget:** a per-staging
  `buildStagingBudget` (created from the fixed
  `productionBuildStagingCeilings`) is threaded through the existing
  walker and consumed by reserve checks before each corresponding
  destination action. It is not exposed outside the staging
  implementation; tests inject tiny ceilings through
  `stageBuildContextInternal` for exact boundary semantics.
- **Payload bytes (128 MiB):** the first staged copy of a unique
  regular-file inode reserves its logical size (`st_size`) before the
  destination file is created or copied — the conservative reservation
  because the copier de-sparsifies a sparse source. Subsequent hardlink
  names share the payload reservation but each consume an entry; staged
  symlink targets are accounted by their target bytes; directories are
  governed by entry/depth. Admission arithmetic is overflow-safe: the
  ceiling comparison runs before the counter mutation, so a near-max
  sparse `st_size` (demonstrated with `st_size = MaxInt64`) cannot
  overflow into acceptance.
- **Entries (50000):** every attacker-variable source entry staging
  would materialize below the context root — regular files, hardlink
  directory entries, symlinks, directories (the context root itself is
  not an attacker-variable entry) — is reserved exactly once, at
  enumeration admission, before its append and before any destination
  materialization; materialization paths never reserve an entry again,
  so every materialized entry has exactly one reservation owner. A
  hardlink consumes another entry even though it does not duplicate the
  payload inode. Enumeration itself is bounded by the same single
  global budget: a parent's enumeration slice stays live during
  recursive descent and a child draws from the same remaining budget,
  so the sum of all simultaneously admitted enumeration entries of one
  staging operation can never exceed the ceiling whatever the directory
  iteration order — an over-ceiling directory is refused during
  enumeration, before any of its entries is materialized.
- **Depth (64):** one exact convention — context root = depth 0, direct
  child = depth 1. The next directory level is admitted before its
  destination `mkdir` and before the recursive descent into it,
  bounding both destination nesting and the walker's recursive stack;
  files may sit one level deeper than the deepest admitted directory.
- **Typed refusal, one public code:** the ceiling refusal is
  `buildStagingCeilingError` (resource `bytes`/`entries`/`depth`,
  ceiling, attempted value; survives `errors.Is`/`errors.As` wrapping;
  no source path material). It is owned by the untagged staging surface
  (`staging.go`), so the untagged build handler classifies it — and only
  it — into the single canonical `build_context_too_large` code with
  HTTP 400, chosen consistently with the existing build client-input
  refusal grammar (400 family; no new 413 status). A non-Linux
  compile-ownership gate (`scripts/check-nonlinux-compile.sh`, wired
  into CI) proves the untagged staging surface plus the non-Linux stub
  type-check for `GOOS=darwin` and pins the documented pre-existing
  non-Linux compile debt of the MAC layer (workload_selinux.go,
  selinux_fcontext.go — reported separately, not part of H4). The
  public message names only the exhausted dimension; operational
  diagnostics carry the dimension and numeric limit/attempted values.
  Every other staging failure stays `internal_error`.
- **Bounded refusal, no residue:** on any ceiling refusal the existing
  descriptor-relative failure cleanup removes the operation tree before
  the handler responds; there is no Docker invocation, no registered or
  admitted Operation, no `build.start` event, and the acquired session
  MAC-use lease is released. H5's concurrent-admission gate is NOT
  implemented here: H4 only establishes the finite maximum cost of ONE
  staging operation.

**Measured ceiling selection (Phase A).** Representative contexts
measured before choosing limits: the docker-helper repository itself
(working tree incl. a 17 MB built binary: ~26 MB payload, ~1800
entries, depth ≤ 3; incl. `.git`: ~35 MB, ~2007 entries, depth ≤ 6);
the existing UAT/build fixtures (a few entries); and generated realistic
coding-agent contexts (repository snapshot with binary: ~17 MB/98/2;
node_modules-style tree: ~2.3 MB/2402 entries/depth 3; media/cache
workspace: ~5.4 MB/64/1). Runtime filesystem characteristics: systemd
sizes `/run` as a tmpfs at `size=20%` of RAM with an 800k-inode default
(`TMPFS_LIMITS_RUN`); the smallest evidence-backed UAT environment is
the 3 GiB Tumbleweed VM (≈614 MB `/run` tmpfs), the Ubuntu UAT runners
have ≈3.2 GB. Selected ceilings therefore keep one hostile build ≤ ~21%
of the smallest `/run` tmpfs (bytes) and ≤ 6.25% of its inode budget
(entries) while leaving ≥ ~3.7x (bytes), ~21x (entries) and >10x
(depth) headroom over the measured realistic workloads. Contexts beyond
these ceilings (e.g. a tree that materializes a huge `node_modules` into
its build context) are refused as the designed trade-off; the Release-3
quota hierarchy was deliberately not imported.

Evidence:

- RED (commit `9d81f5a`, deterministic hostile fixtures against the
  pre-fix production walker, one per missing guard): the sparse-payload
  fixture (sparse `st_size` = 128 MiB + 1) showed pre-fix staging
  succeeded and began materializing the payload (`duringCopy`/
  `afterCreateDest` ran for it); the entry fixture (Dockerfile + 50000
  zero-byte files) showed the whole over-ceiling directory was
  enumerated and staged; the depth fixture (65-deep chain) showed the
  traversal recursed below the proposed ceiling and reached the leaf.
  The enumeration-memory owner itself is proven structurally: pre-fix
  `readDirectoryEntries(fd)` had no remaining-entry admission before
  append (the unbounded slice accumulated before any per-entry
  decision). All three desired-behavior tests failed pre-fix as
  designed; no host DoS was attempted.
- GREEN (commit `914e0e7`): production ceilings refuse each hostile
  fixture before the corresponding expensive destination action; exact
  boundary tests with injected tiny ceilings prove: exactly-at-limit
  succeeds and one byte/entry/level over refuses; refusal happens before
  destination payload creation/write (hook observability); sparse files
  use logical size and are refused without materializing the hole
  (source stays sparse); the `MaxInt64` `st_size` cannot overflow into
  acceptance; unique hardlink payload counted once while the hardlink
  name still consumes an entry; symlink target bytes and entry slot
  counted; directories/symlinks/hardlinks/files all consume entries;
  enumeration refuses before any destination creation of the refused
  directory (shallow many-sibling tree governed by entries, not depth);
  exactly-at-limit depth succeeds and one level over refuses before
  mkdir/descent; the Dockerfile itself is included in the accounting;
  the typed error survives wrapping; refusal removes
  `runtime/builds/<op>`; ordinary contexts stage identically and every
  existing staging test (identity proofs, SUID/SGID stripping, mtime/
  mode preservation, cancellation, parallel cleanup, special-file
  rejection) stays green; `go test -race` green. Handler path: the
  typed refusal is classified into 400 `build_context_too_large` with a
  bounded dimension-only message and a `build.rejected` audit record
  carrying the same code; the real production walker behind the staging
  seam leaves no operation tree, invokes no Docker command, registers no
  operation, and releases the acquired session MAC-use lease
  (`sessionUseLeases` empty); a non-ceiling staging failure remains 500
  `internal_error`.
- Review-round corrections (deterministic, fail-closed): the enumeration
  admission was tightened to the single global reservation owner — the
  nested regression `TestStagingBudgetEnumerationBudgetIsGlobal` failed
  pre-correction under every directory iteration order (the first
  processed root directory's children were materialized beyond one
  budget while the parent slice stayed live) and passes with the
  corrected global reservation, whose Attempted value names the one
  over-budget admission; `TestStagingBudgetNestedEntriesExactlyAtLimitSucceeds`
  proves the single reservation owner end to end (a nested total exactly
  at the ceiling succeeds, so no entry is reserved twice); the pure
  overflow proof (`TestStagingBudgetReserveBytesOverflow`) and the
  filesystem-portable huge-source walker proof
  (`TestStagingBudgetHugeSparseSourceRefused`) keep the byte admission
  arithmetic un-wrappable. The typed refusal moved to the untagged
  staging owner (`staging.go`) and the same-class pre-existing ownership
  defect (`isOperationIDSafe` declared linux-tagged, consumed untagged)
  moved to its canonical untagged owner (`operation.go`); the
  compile-ownership gate fails on the simulated regression (undefined
  staging symbol for GOOS=darwin). The UAT inode evidence validates both
  `df` readings as numeric before arithmetic and fails the assertion
  explicitly when inode figures are unavailable — an empty measurement
  is never reported as proof.
- Hostile exact-candidate UAT (new Ubuntu/DEB/AppArmor regression group
  24, `uat-regression-h4-build-staging-bounds.sh`, real packaged service
  with mandatory MAC active — the finding is not MAC-specific, so no
  duplicate per-MAC logic exists; real production ceilings): a sparse
  source file one byte over the byte ceiling (never allocated for real),
  a Dockerfile + 50000 zero-byte-file context, and a 65-deep tree are
  each refused quickly through the real CLI with the intended
  classification (status 400, `code build_context_too_large`); the
  service stays active and the Unix API healthy after every refusal; no
  `build.start` audit event exists in each refusal window while the
  refused code does; `/run` usage and inode evidence (both `df` readings
  validated numeric before arithmetic; an unavailable measurement fails
  the assertion instead of being reported) proves the sparse case is
  preventative rather than "copy until tmpfs fails"; no staging
  operation tree remains; the workload-MAC inventories are unchanged; a
   subsequent small valid build succeeds and (positive control) does emit
   `build.start`, proving the absence checks are meaningful.

## SC2 — H5: fixed Release-2.2 resource admission ceilings

The audit class: three independent Session-token-controlled host-resource
channels were unbounded. (1) One operation-log request materialized the
whole retained buffer (`Range` copied everything after the offset) and
JSON-expanded it — measured worst-case encoding amplification is 6.0×
for control characters/invalid UTF-8 (1 MiB → 6,291,544 encoded bytes;
ordinary text 1.0×), so an ~80-byte request could produce a ~24 MiB
response plus transient copies against the 4 MiB default retention, per
request. (2) One run request could create hundreds of `open_tree`/
`move_mount` pins — the 16 KiB request-body limit was the only
incidental count bound — and about 185 such runs could exhaust
fs.mount-max = 100000. (3) `OperationSupervisor.admit()` checked only
shutdown/quiesce: no Session or global running-operation ceiling
existed, while run pinned all mount sources and prepared workload MAC
and build staged the entire H4-bounded context BEFORE admission was even
consulted.

Phase-A measurement (recorded in the PR): UAT/tests exercise at most 2
concurrent Operations per Session and 1–2 mounts per run request; the
smallest supported host is the 3 GiB Tumbleweed UAT VM with a ~614 MB
`/run` tmpfs (~20% of RAM) and fs.mount-max 100000; the worst kernel
mount-table cost is 3 entries per caller mount under the SELinux backend
(pin + lower file bind + bindfs projection) plus one FUSE worker per
read-only exposure; H4's per-build staging ceiling multiplied by
concurrent builds exhausts the smallest `/run` at ~4 concurrent maximal
hostile builds.

Closed at the existing owners — the OperationSupervisor (one concurrency
owner), the run request surface (mount count), and the boundedBuffer
Range owner (response chunking) — with no scheduler, no queue, no quota
hierarchy, no configuration surface, and no change to the public
Operation model (`running`/`succeeded`/`failed` only; the reservation is
a narrow internal lease):

- **Capacity (4 per Session / 8 global / 2 concurrent builds):** the
  ceilings are measured security constants documented in
  `docs/architecture.md`; the sub-ceiling exists so ordinary run
  concurrency stays usable while worst-case H4 composition (2 × 128 MiB
  = 256 MiB = 42% of the smallest `/run`) stays safe. `reserve` checks
  shutdown, quiesce, Session ceiling, global ceiling and the build
  sub-ceiling, then reserves, inside one critical section; the
  reservation is acquired BEFORE any expensive preparation in both
  handlers; `admitReserved` re-checks only the lifecycle closure and
  transfers the reservation into the registered Operation without
  re-reserving; release is exactly once at the terminal transition (the
  winning `succeed`/`fail` invokes the transferred closure under the
  operation lock) and on every pre-admission failure path (the frozen
  run-cleanup order gained the kernel-independent capacity stage first,
  so a failed MAC rollback cannot strand capacity of an operation that
  never started). A terminal retained Operation consumes zero capacity
  and release is never coupled to `pruneCompleted()`. No queue and no
  waiter: one bounded `operation_capacity_unavailable` refusal (HTTP
  429) for both scopes, audited through the existing `<kind>.rejected`
  record.
- **Caller mounts (16 per run request):** checked immediately after
  request decoding/basic validation, before the MAC-use lease, probing,
  exposure resolution, pins, workload-MAC preparation and the
  reservation; duplicates and RO/RW consume slots equally; the
  server-owned helper_socket projection is not a caller mount; user
  mode obeys the same ceiling without gaining system-mode mechanics;
  one bounded `too_many_mounts` refusal (HTTP 400) that names no mount
  path; worst-case composition with the ceilings leaves 384 kernel
  mount entries — 0.4% of fs.mount-max. No PrivateMounts: pins remain
  visible to dockerd.
- **Bounded log response (256 KiB raw chunk):** `boundedBuffer.Range`
  grew a `maxBytes` bound; `next_offset` identifies the byte immediately
  after the bytes actually returned; when the offset predates the
  retained data the read starts at the oldest retained byte, returns at
  most one chunk with `truncated=true`, and `next_offset` follows the
  returned bytes — no retained bytes are silently skipped. The
  `operation_log_max_bytes` config is untouched: the response ceiling is
  retention-independent, so no hard bound on the existing operator
  setting is needed for the Session-token threat proof (retention itself
  bounds what a Session-token holder can make the daemon retain for its
  own operations, and retention is trusted-admin operational policy).
  The synchronous pull response and the registry-login classification
  capture keep their complete-retained-range contracts via an explicit
  unbounded Range parameter.
- **CLI drain:** one shared client drain helper fetches bounded chunks
  until a short response ends the stream; the running poll drains all
  currently available chunks (real-time pace preserved) and the terminal
  drain empties every remaining chunk before the CLI returns, so
  successful CLI output is never truncated by chunking.
- RED (commit `1d3c9fa`): five deterministic defect demonstrations —
  five long-lived run Operations under one Session are all admitted (no
  capacity owner refuses the next request); a quiesce-refused run has
  already created its mount pin and a quiesce-refused build has already
  staged its whole context (expensive preparation before admission); a
  run request with 17 caller mounts reaches pin preparation (duplicates
  included); one logs request materializes the full retained log and
  expands it to 4,718,717 encoded bytes against the proposed 1,576,960
  bound. No host DoS was attempted.
- GREEN (commit `e88f847`): supervisor-level exact-boundary tests
  (Session limit, limit+1, other-Session free capacity, global limit,
  terminal release with retained metadata/logs, release exactly once,
  concurrent-reserve race never oversubscribes (200 goroutines, exactly
  the ceiling accepted), reserve→quiesce and reserve→shutdown refused at
  final admission, build sub-ceiling leaves runs available); handler
  tests (capacity refusal with zero pins/zero MAC preparation/zero
  staging/zero Docker invocation/zero `build.start` audit and no
  lease/reservation residue; user mode obeys the same fixed ceilings);
  mount tests (exact limit succeeds, +1 refused before probing/pinning,
  duplicates count, RO/RW count equally, helper_socket consumes no
  slot); bounded-Range tests (exact chunk boundary, one byte over,
  chunked reconstruction with no gap/duplication, rollover/truncated
  bounded chunk, zero-ceiling no-progress); CLI drain tests (multi-chunk
  reconstruction, exact-boundary termination, terminal multi-chunk
  delivery); the documented worst-case composition guard
  (2 × 128 MiB ≤ 45% of the smallest `/run`; 384 mount entries < 1% of
  fs.mount-max). All existing cancellation/shutdown/quiesce tests and
  every H4 staging test stay green; the former `admit()` path was fully
  superseded (all tests register through the production
  reserve → admitReserved path; the admit-rejection tests now drive the
  reserve→shutdown→final-admit race deterministically through the
  mid-request pin/staging seams, keeping the pin/lease and staging/lease
  ordering proofs on the real production path); `go test -race` green.
- Hostile exact-candidate UAT (new Ubuntu/DEB/AppArmor regression group
  25, `uat-regression-h5-resource-admission.sh`, real packaged service
  with mandatory MAC active, real production ceilings): four long-lived
  operations occupy the Session ceiling and the fifth is refused
  immediately with `operation_capacity_unavailable` and no
  container/process/state for the refusal; the second Session admits its
  four operations while the first is saturated (global ceiling reached)
  and the ninth is refused; a terminated operation releases its container
  and capacity immediately and a new operation is admitted; the
  capacity-refused run carries a valid mount yet adds no pin and no
  workload-MAC state and the capacity-refused build adds no staging tree
  (audited through `operation_capacity_unavailable`); exactly 16 caller
  mounts are accepted and 17 are refused with `/proc/self/mountinfo` and
  the canonical pin inventory unchanged; a ~700 KB hostile control-byte
  stream is served in chunks with every encoded response under the
  documented bound, the chunk walk reconstructs the stream exactly
  (boundary sentinels + exact byte count prove no gap/duplication), and
  the ordinary CLI fully delivers terminal output spanning several
  chunks; recovery leaves no pins, staging, workload-MAC state or
  residual capacity and a subsequent ordinary run and build both succeed.

## SC2 — bounded-resource and liveness closure

**Queue:** `H8`. (H4, H5 and H7 closed in SC2 — see the SC2 evidence
ledgers above.)

SC2 removes unbounded host-resource and liveness channels without importing the
Release 3 resource model. Release 2.2 needs hard security ceilings, not a new
quota hierarchy.

Required direction:

- staging has measured maximum bytes, entries and depth; (closed — H4)
- operation/mount/log/concurrency resources have finite admission ceilings;
  (closed — H5)
- resource reservation/admission happens before expensive preparation where the
  attack depends on pre-admission work; (closed — H5)
- external MAC commands have bounded execution/cancellation and cannot hold
  lifecycle coordination indefinitely. (The optional-TCP item was closed in
  SC2 already — see the SC2 evidence ledger above.)

Concrete limits are selected from measurement and UAT, not invented from the
future Release 3 quota design.

## SC3 — explicit architecture decisions

**Queue:** `H1`, `H10`, `M1`.

These findings expose product-boundary questions rather than safe one-line
hardening. Each requires an accepted architecture disposition before coding:

- **H1 builder network:** define which network position the build capability is
  allowed to inherit and how remote Dockerfile fetches fit the threat model.
- **H10 DAC inheritance:** decide whether an issued filesystem capability is the
  complete read authority or must additionally preserve Principal DAC/group/ACL
  semantics.
- **M1 secret transport:** inventory each secret-bearing Docker CLI channel and
  choose compatible transport/mitigation per channel rather than assuming one
  `--env-file` rewrite preserves all contracts.

A decision may retain a behavior only when the supported boundary is made
explicit and the remaining risk is accepted by the release owner. An
unresolved decision blocks stable promotion.

## SC4 — adjacent hardening and audit tail

SC4 owns non-blocking hardening after the release-blocking semantics are closed:

- M3 storage hardening only if a concrete independent use case justifies a new
  secret-storage owner; otherwise retain the documented protected-at-rest
  boundary after C1/H9 UAT passes;
- M6 audit-write failure observability may be improved without changing the
  accepted operation-success contract;
- M9 documentation/hardening may improve user-mode clarity without pretending
  user mode isolates mutually hostile same-UID processes;
- Low findings L1-L14 remain backlog unless implementation evidence promotes
  one into the release gate.

## Mandatory hostile exact-artifact security UAT

The final security candidate must add a small cross-boundary suite. It is not a
second general UAT framework. Each case proves a trust-boundary composition the
ordinary component tests cannot establish.

At minimum:

1. **C1 + H9 workload privilege/runtime proof — AppArmor and SELinux.** Use a
   hostile image and a staged SUID/SGID fixture. Prove workload UID cannot gain
   a stronger host-facing privilege, helper-private runtime/session Docker
   config cannot be read, runtime cannot be modified, and the helper socket
   still works only as the explicitly granted transport capability.
2. **M13 Docker mount grammar.** Use hostile targets including newline/CSV
   delimiters and prove Docker observes exactly the intended target and
   `readonly` mode; malformed/unrepresentable targets fail closed before
   container creation.
3. **H6 admin-token rotation under enforcing MAC.** Rotate through the shipped
   package/service on AppArmor and SELinux; prove old token fails and the new
   token succeeds with no broader writable config surface. (Closed: see the
   SC1 evidence ledger, H6.)
4. **H2 parked revoke/create race.** Park Session issuance across the
   authorization linearization point, revoke/rotate the credential, and prove
   the losing ordering cannot issue a new Session.
5. **H4/H5 resource ceilings.** Exercise each hard ceiling and prove bounded
   refusal before the corresponding expensive resource is consumed, with no
   residual helper/Docker/MAC state.
6. **H7 TCP port capture.** Hold the configured loopback port as an unprivileged
   local process and prove the authoritative Unix service remains usable and
   does not enter a permanent systemd start-limit failure.
7. **H8 MAC timeout/liveness.** Force an external MAC command to hang past its
   budget and prove administrative disable/shutdown remains bounded and
   ownership state remains fail closed.
8. **C3 SELinux lower-layer gate.** On every supported SELinux artifact target,
   prove the active libselinux implementation is the accepted descriptor-safe
   implementation or a verified backport; unsupported unsafe variants fail
   closed before relabel work.

Where a case is backend-specific, a skip in a required-mode job is a failure.
The test consumes exact candidate artifacts produced by the canonical artifact
producer; a source-tree reconstruction is not release evidence.

## Final security exit criteria

Release 2.2 security closure is complete only when all of the following hold on
the same final candidate:

- no C/H/M finding is `VERIFY_CURRENT`;
- no `BLOCKER_FIX` remains open;
- every `BLOCKER_DECISION` has an accepted architecture/release-owner
  disposition and any required implementation/documentation is complete;
- every `CLOSED_CURRENT` finding still has current regression evidence for the
  replacement invariant;
- M3 remains `DEFER_HARDENING` only if the final C1/H9 hostile proof shows the
  plaintext Session Docker config is unreachable from the hostile workload on
  both mandatory MAC backends;
- the hostile cross-boundary suite passes on exact candidate artifacts under
  enforcing AppArmor and enforcing SELinux where applicable;
- existing Release 2.2 functional, migration, packaging, MAC and regression
  gates remain green;
- current architecture/help/man/README reflect all accepted SC1-SC3 changes;
- final release review rereads `docs/architecture.md` in full for stale layered
  information;
- compare against `v2.1.1` contains no accidental Release 3 Engine, quota,
  scheduler, desired-state or generic resource-control architecture.

Only after this gate and the ordinary Phase 2.2.7 gate are green may a stable
`v2.2.0` tag be created.
