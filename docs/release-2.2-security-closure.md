# Release 2.2 external security audit closure

## Status and authority

**Status: MANDATORY PRE-STABLE RELEASE GATE (opened 2026-09-14).**

The external audit that triggered this closure reviewed docker-helper 2.0.0 at
commit `7e9762576327b625acde45934a15216d1ff0a56b`. Its finding identifiers are
stable and are used here as references, but the audit's 40 findings are **not**
automatically 40 current Release 2.2 defects.

The first current-line architectural rebase was performed against
`release/2.2@14f9ffeadab156d5f945ca2d21dc3bb9dd6ba6e9`. Every finding still needs a
current-line terminal disposition before stable promotion; later Release 2.2
commits may change the implementation evidence but do not remove this gate.

This document is the security-closure owner for Release 2.2. It is a mandatory
overlay to [`release-2.2-implementation-plan.md`](release-2.2-implementation-plan.md):
Phase 2.2.7 final release promotion is blocked until the exit criteria below
are satisfied.

This document is a release plan, not a current-state architecture document.
Accepted implementation changes must still be reflected in
[`architecture.md`](architecture.md), help/man/README, and the applicable
design record before the final release review.

## Fixed principles

1. **Keep the Docker Engine/Docker CLI backend in 2.2.** The audit does not by
   itself justify an Engine rewrite, Podman migration, or Release 3 backend
   work. Rootless runtimes/user namespaces remain future defense-in-depth
   candidates unless a current 2.2 finding proves they are required.
2. **Fix the existing owner, not each symptom.** Workload launch invariants,
   bind-mount serialization, authorization linearization, config decoding, MAC
   execution, and path policy each keep one production owner.
3. **No Release 3 quota/control-plane architecture.** 2.2 may add hard security
   ceilings needed to remove an unbounded host-resource attack, but must not
   pre-build Principal/Launcher quota policy, schedulers, desired state, or a
   generic resource framework.
4. **Preserve current lifecycle contracts unless explicitly changed.** In
   particular, credential revocation does not retroactively revoke already
   issued Sessions, and Session deletion/expiry does not by itself promise to
   terminate an operation that already started. A finding that assumes the
   opposite is not fixed by silently changing the contract.
5. **Current evidence wins over historical code shape.** A 2.0 finding may be
   closed only by tracing the current production path and proving the old
   mechanism is gone or unreachable. Conversely, an unchanged vulnerable path
   remains actionable even if adjacent architecture changed.
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

Every C/H/M finding must end Release 2.2 in exactly one terminal state:

- **CLOSED_CURRENT** - the vulnerable 2.0 path is structurally gone in current
  2.2 and regression evidence proves the current contract.
- **BLOCKER_FIX** - current 2.2 behavior violates the accepted security or
  correctness boundary and must be fixed before stable release.
- **BLOCKER_DECISION** - the finding exposes a real current trust-boundary or
  contract question whose correct solution is architectural. Stable release is
  blocked until the decision is accepted and either implemented or explicitly
  documented as the supported boundary.
- **VERIFY_CURRENT** - the audit path is historical and the current status has
  not yet been proved. This is non-terminal and blocks stable release until it
  becomes one of the terminal states above/below.
- **ACCEPTED_CONTRACT** - the reported behavior is current but follows an
  already accepted product contract; no security fix may silently reverse that
  contract. Documentation/hardening may still follow.
- **DEFER_HARDENING** - useful hardening with no demonstrated current violation
  of the Release 2.2 threat/behavior contract. It does not independently block
  stable release after its disposition is recorded.

`VERIFY_CURRENT` is deliberately not a way to postpone work. It is Phase SC0
work and must disappear before final promotion.

## Current C/H/M disposition matrix

The table records the first Release 2.2 architectural rebase. "Current" below
means current-line evidence at or after the baseline above, not merely the
2.0 audit text.

| ID | Audit claim | Release 2.2 disposition | Closure phase | Stable-release requirement |
| --- | --- | --- | --- | --- |
| **C1** | Workload containers lack `no-new-privileges`; SUID/SGID delivery can lead to host root | **BLOCKER_FIX** | SC1 | One workload-execution security owner enforces `no-new-privileges`, drops capabilities by default, strips SUID/SGID from helper-created staging files, and hostile Docker UAT proves the reproduced chain is dead. |
| **C2** | Principal-less/admin-created Session could execute as daemon `0:0` | **CLOSED_CURRENT** | SC0 | Keep regression proof that every system-mode Session has proven Launcher/Principal execution identity; do not reintroduce daemon-UID fallback. |
| **C3** | Old libselinux recursive `restorecon` can relabel path-swapped foreign files | **BLOCKER_FIX** | SC1 | Active SELinux support must prove the descriptor-safe libselinux implementation (3.11 or a verified backport) or fail closed. Do not add a second home-grown recursive relabel walker. |
| **H1** | Builder can fetch arbitrary URLs from a network position unavailable to the agent | **BLOCKER_DECISION** | SC3 | Accept an explicit builder-network threat-boundary design. Fix the network position if the current product promise excludes this access; do not parse Dockerfiles as a substitute policy engine. |
| **H2** | Credential can be revoked after authentication but before Session issuance | **BLOCKER_FIX** | SC1 | Revalidate the credential/owner authority at the Session issuance linearization point in the existing transaction/lock owner. Existing issued Sessions remain unchanged by this fix. |
| **H3** | Privileged filesystem resolution happens before authorization and leaks resolver detail | **BLOCKER_FIX** | SC1 | Authorization/lexical ceiling check precedes privileged probing where possible; public workspace failures are bounded/stable while operational logs retain diagnostics. |
| **H4** | Build staging can consume unbounded tmpfs bytes/inodes/depth/files | **BLOCKER_FIX** | SC2 | Hard measured ceilings for staged bytes, entries and depth, admitted/reserved before staging; failure is bounded and leaves no residue. Do not introduce Release 3 quota hierarchy. |
| **H5** | Logs, mount pins and concurrent/running Operations provide unbounded host-resource channels | **BLOCKER_FIX** | SC2 | Bound response materialization, mounts/pins per operation, and concurrent/running operation admission at Session/global security ceilings. Measure defaults; reserve before expensive work. |
| **H6** | Mandatory MAC policy blocks admin-token rotation | **BLOCKER_FIX** | SC1 | Narrow AppArmor/SELinux write/rename permission for only the token and temporary replacement path; live enforcing UAT proves old token rejected/new token accepted. |
| **H7** | A local user can occupy the optional TCP port and drive the service into systemd start-limit failure | **VERIFY_CURRENT** | SC0 -> SC2 if present | Reproduce against current listener/startup behavior. If still reachable, optional TCP failure must not destroy the authoritative local service or become permanent unauthenticated DoS. |
| **H8** | External MAC commands hold shared coordination long enough to delay emergency disable | **BLOCKER_FIX** | SC2 | Existing MAC command owners gain bounded cancellation/timeouts and the lifecycle lock path is reviewed so untrusted-size work cannot indefinitely hold administrative disable. Avoid a new queue/framework unless evidence requires it. |
| **H9** | Agent container can receive the helper runtime directory and steal registry secrets/replace CA state | **VERIFY_CURRENT** | SC0, then SC3 only if residual | Re-run the chain against the current server-owned `helper_socket` projection, read-only mount, Principal UID execution, and the C1 fix. Close only with current proof; if any independent confidentiality/integrity chain remains, return it to SC3. |
| **H10** | An allowed root lets the root daemon read files the Principal could not read under Unix DAC | **BLOCKER_DECISION** | SC3 | Decide whether a filesystem capability intentionally grants helper-mediated read independent of DAC or must additionally preserve Principal DAC/group/ACL semantics. Do **not** implement an owner-UID check as a fake Unix permission model. |
| **M1** | Environment/build secret values appear in the Docker CLI process argv | **BLOCKER_DECISION** | SC3 | Inventory each secret-bearing channel and choose a supported transport/mitigation. `--env-file` is not assumed equivalent for arbitrary existing values. Any residual `/proc` exposure must be explicit in the threat/operations docs. |
| **M2** | Documentation puts bearer tokens directly in `curl` argv | **BLOCKER_FIX** | SC1 | Rewrite shipped examples to token-file/stdin/environment patterns that do not expand the secret into process argv; keep examples executable. |
| **M3** | Registry credentials are plaintext in the per-Session Docker config | **VERIFY_CURRENT** | SC0 | Re-evaluate as a storage finding after C1/H9. If the runtime tree is not readable by the hostile Principal/workload under the supported model, record the residual at-rest boundary; otherwise promote to SC3. |
| **M4** | Raw-config validation and `json.Unmarshal` accept different key grammar; bad values can reach panic-prone consumers | **BLOCKER_FIX** | SC1 | One strict config decoding/validation path owns key recognition and bounds; malformed/case-variant input fails closed before effective config exists. |
| **M5** | NUL-containing Principal name can resolve through libc as one OS user but persist as a distinct DB identity | **VERIFY_CURRENT** | SC0 -> SC1 if present | Reproduce on supported builds and trace current username validation. If reachable, canonical OS identity/name must be validated once before persistence; no second alias grammar. |
| **M6** | Audit write failure does not abort the protected operation | **ACCEPTED_CONTRACT** | SC0/SC4 | Do not change operation success semantics merely to match the audit recommendation. Improve observability only if useful; a new fail-stop audit contract requires separate architecture acceptance. |
| **M7** | Cancellation can leave an untracked running container when cidfile timing loses the race | **VERIFY_CURRENT** | SC0 -> SC2 if present | Re-test current deterministic ownership/labels, cancellation and startup reconciliation. If a helper-owned workload can still escape lifecycle accounting, fix the existing lifecycle owner. |
| **M8** | Principal disable/delete does not stop already-started work | **ACCEPTED_CONTRACT** | SC0 | Current 2.x lifecycle deliberately does not promise retroactive termination of already-started operations solely because authority/session state changes. Preserve this unless architecture explicitly changes. |
| **M9** | User-mode pathname race exists because Docker resolves a path again without the system-mode pinning boundary | **ACCEPTED_CONTRACT** | SC4 | User mode does not claim isolation from another process running as the same OS user. Correct any documentation that claims stronger protection; extending pinning is optional hardening, not an implicit contract change. |
| **M10** | Allowed-root symlinks are recomputed after validation without reapplying the safety policy | **VERIFY_CURRENT** | SC0 | Trace the current canonical allowed-root/snapshot path. Close with proof if current 2.2 persists/uses one validated identity; otherwise fix the single canonicalization owner. |
| **M11** | SELinux fcontext input escapes regex syntax but not all file-format/control-character hazards | **VERIFY_CURRENT** | SC0 -> SC1 if present | Re-test current path-policy boundary. If reachable, reject unsupported control characters at the canonical path owner rather than only inside one MAC backend. |
| **M12** | `semanage fcontext` output parser disagrees with the producer's long-path spacing | **BLOCKER_FIX** | SC1 | Parse the real `semanage` output grammar robustly and add long-path/backend tests; do not preserve a width-dependent split rule. |
| **M13** | Crafted bind-mount target can desynchronize Docker `--mount` CSV and lose `readonly` | **BLOCKER_FIX** | SC1 | One bind-mount serializer/encoder owns every Docker bind form; hostile target tests must prove exact target and access mode survive the Docker parser. No ad-hoc concatenation per caller. |

The low/hardening findings `L1`-`L14` are retained as an audit backlog but do
not independently enter the 2.2 stable gate unless SC0 evidence promotes one.
Do not opportunistically widen a security patch to unrelated low findings.
A low finding that touches the same owner may be closed in the same series when
that is the smallest coherent change (for example adding `--` to a positional
SELinux command while already changing that exact invocation).

## Release-cycle integration

Security closure is inserted **after the current 2.2 feature contract is frozen
and before Phase 2.2.7 can declare the stable release candidate accepted**.
No new product feature may enter 2.2 while this gate is open.

The required order is:

```text
existing 2.2 feature work / RC fixes
        |
        v
SC0  current-line audit rebase and terminal classification
        |
        v
SC1  immediate trust-boundary / parser / MAC closure
        |
        v
SC2  bounded-resource and liveness closure
        |
        v
SC3  explicit architecture dispositions for remaining trust-boundary questions
        |
        v
SC4  adjacent hardening/documentation cleanup (non-blocking unless promoted)
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

SC1 and SC2 may be implemented as several narrow series, but each series must
start from the current `release/2.2` head and keep one semantic owner. Do not
cherry-pick an old audit-fix branch wholesale across later RC architecture.

### SC0 - rebase the audit onto current 2.2

For every C/H/M row:

1. trace the current production path from the public boundary to the owning
   implementation;
2. reproduce on current 2.2 when the finding is environment-testable;
3. distinguish a removed path from a changed exploit precondition;
4. record the terminal disposition and exact evidence;
5. add a regression for every `CLOSED_CURRENT` security invariant whose future
   regression would recreate the finding.

SC0 completes only when no row remains `VERIFY_CURRENT`.

### SC1 - immediate security-boundary closure

SC1 owns small, local changes whose semantics are already clear:

- C1 workload privilege floor and staging mode sanitization;
- C3 supported SELinux/libselinux safety gate;
- H2 Session-issuance authorization recheck;
- H3 authorization/error boundary;
- H6 admin-token rotation under enforcing MAC;
- M2 safe documentation examples;
- M4 strict config decoding/bounds;
- M12 real fcontext output parsing;
- M13 one bind-mount serializer;
- any M5/M11 item promoted by SC0 current reproduction.

#### C1 implementation boundary

Do not scatter Docker hardening flags through callers. Extend the existing
workload launch owner with one daemon-owned privilege floor that the caller
cannot weaken. At minimum the accepted 2.2 launch invariant must decide and
prove:

- `no-new-privileges` for agent-requested workloads;
- capability drop policy (`ALL` unless a concrete existing capability is
  demonstrated necessary and explicitly returned);
- existing Principal UID:GID execution;
- existing MAC security options;
- SUID/SGID stripping on helper-created staging copies.

This is not a generic Docker-options framework and does not expose new options
to agents.

#### C3 dependency boundary

Do not create a second recursive SELinux relabel implementation merely to own a
dependency bug. The supported SELinux path must prove descriptor-safe behavior
from libselinux 3.11 or a distribution backport. If that cannot be proved at
startup/install/package validation for the active backend, system-mode SELinux
must fail closed with actionable diagnostics.

### SC2 - bounded-resource and liveness closure

SC2 removes demonstrated `small request -> unbounded host work` behavior while
keeping Release 3 resource policy out of scope.

Required classes of hard ceilings:

- build-staging bytes;
- build-staging entry/inode count;
- build-staging depth;
- mounts/pins per operation;
- concurrent/running operations per Session and globally;
- materialized operation-log response/output buffers;
- duration of helper-owned external MAC commands while lifecycle coordination
  is held.

Exact limits are not guessed in this document. They must be selected from
measurement of normal project/agent workloads plus attack reproductions, then
locked by tests. Admission/reservation happens before the expensive resource is
created; failed admission or timeout leaves no Session/operation/mount/MAC
residue.

If H7 remains current after SC0, its transport/start-limit fix belongs here.

### SC3 - architecture dispositions

SC3 exists specifically to prevent a security audit from smuggling a new
platform into a release-candidate branch.

Required decisions:

- **H1 builder network:** define the network boundary of Docker builds. A
  `RUN --network=none`-only answer is insufficient if remote `ADD` or the
  builder itself can still fetch. Prefer controlling the builder's network
  position rather than parsing Dockerfile semantics.
- **H10 DAC:** decide whether an issued filesystem capability authorizes helper
  reads independent of the Principal's DAC or whether helper-mediated reads
  must execute with full Principal DAC/group/ACL semantics. An owner-UID check
  is not equivalent to Unix permissions.
- **M1 argv secrets:** map each value class (`--env`, `--env-from`, build args,
  commands, bearer/token examples) to an actual transport and decide which are
  secrets by contract. Do not assume one Docker CLI mechanism faithfully
  carries all existing values.
- **H9 residual runtime exposure:** only if current reproduction after C1 shows
  an independent chain.

A SC3 finding may close by an implemented fix or by an explicitly accepted
supported-boundary decision. If the latter narrows a user/operator security
expectation, architecture + README/operator documentation must say so before
stable release.

### SC4 - bounded hardening tail

After all blockers/decisions are closed, apply only hardening that is either:

- required to make the accepted fix coherent across all owners/backends; or
- a tiny adjacent change in the exact code path already under review.

Do not use the audit as permission for a general cleanup release. Unrelated low
findings and broader redesign move to the post-2.2 backlog.

## Mandatory cross-boundary security UAT

The security gate adds a small set of end-to-end hostile scenarios to the exact
candidate artifact matrix. They complement, not replace, unit/integration
coverage.

At minimum prove:

1. **C1 hostile-image chain:** a Session bearer cannot use an agent-built
   setuid/setgid payload or a helper-staged SUID/SGID file to obtain host-root
   write authority; launch arguments contain the fixed daemon-owned privilege
   floor.
2. **M13 bind parser:** hostile target strings cannot change the Docker mount
   mode or target; the observed container mount matches the accepted exposure
   plan and audit facts.
3. **H6 token rotation:** under the real shipped AppArmor and enforcing SELinux
   policies, rotation succeeds atomically, old bearer fails, new bearer works,
   and permissions remain 0600.
4. **H2 parked-create race:** a create request authenticated before
   revoke/rotate cannot linearize a new Session after the credential has become
   invalid; the losing request creates no bearer/Session/MAC/runtime residue.
5. **H4/H5 bounds:** sparse/deep/many-entry staging, too many mounts, too many
   concurrent/running operations, and adversarial log materialization fail at
   the configured security ceiling without destabilizing the service/host.
6. **H8 timeout:** deliberately slow/failing MAC backend commands cannot hold
   administrative disable/release indefinitely and leave no ambiguous owned
   MAC state.
7. **C3 SELinux support gate:** supported enforcing-SELinux jobs prove the safe
   libselinux implementation/backport identity; an intentionally unsupported
   identity is refused before unsafe recursive relabel work.
8. Every SC3 item resolved by implementation gets one corresponding hostile
   acceptance scenario. Every SC3 item resolved by supported-boundary
   documentation gets a contract test where practical and an explicit threat
   model statement.

These scenarios run against the immutable candidate DEB/RPM/tarball paths that
are applicable to the existing Release 2 support matrix. A source-only or mock
proof does not close a finding whose exploit depends on real Docker/MAC/systemd
composition.

## Per-series implementation discipline

Every security implementation series follows the normal Release 2.2 rules plus:

1. **UAT/regression first** where a deterministic reproducer exists. Preserve a
   bounded RED proof on the current release SHA before production changes.
2. Inspect every sibling caller of the changed owner before implementation.
3. Do not add a new noun/owner merely because the audit uses different
   vocabulary.
4. Keep public API/CLI contracts unchanged unless the finding itself requires a
   reviewed contract change.
5. Update `architecture.md` only to accepted current behavior, not proposed
   future mechanics.
6. Run the normal validation gate plus the applicable exact-artifact security
   scenarios.
7. Final report records starting SHA, final SHA, changed owner, RED evidence,
   GREEN evidence, artifact-run identity, and any deliberately rejected audit
   recommendation with rationale.

## Final Release 2.2 security exit criteria

Stable `v2.2.0` may be promoted only when all of the following are true:

- every C/H/M finding has a terminal disposition; no `VERIFY_CURRENT` remains;
- no `BLOCKER_FIX` remains open;
- every `BLOCKER_DECISION` has an accepted architecture/release-owner decision
  and the resulting implementation or documented boundary is complete;
- C1 workload privilege-floor and M13 bind-serialization attack UAT pass on the
  real supported Docker path;
- admin-token rotation passes under both required system-mode MAC backends;
- Session issuance cannot cross credential revocation/rotation linearization;
- host-resource work requested by an untrusted Session is bounded at every
  demonstrated H4/H5/H8 channel without importing Release 3 quota architecture;
- active SELinux support proves a safe recursive relabel implementation or
  fails closed before unsafe use;
- the complete existing Release 2.2 functional/regression/MAC/package matrix
  still passes on the same immutable candidate artifacts;
- `docs/architecture.md` receives a full-file final review after all security
  changes, specifically checking stale threat-boundary, workload privilege,
  runtime projection, MAC and lifecycle wording;
- README/help/man/agent skill contain no examples or statements that contradict
  the final security boundary;
- comparison against `v2.1.1` still contains no accidental Release 3 production
  feature or a parallel security-policy owner.

Only after this security gate and the existing Phase 2.2.7 completion criteria
are both green may the branch be tagged as the stable Release 2.2 candidate.
