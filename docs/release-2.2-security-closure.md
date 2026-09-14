# Release 2.2 external security audit closure

## Status and authority

**Status: SC0 CLOSED; SC1 NEXT (2026-09-14).**

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
| **C3** | Old libselinux recursive `restorecon` can relabel path-swapped foreign files | **BLOCKER_FIX** | SC1 | Active SELinux support must prove the descriptor-safe libselinux implementation (3.11 or a verified distribution backport) or fail closed. Do not add a second home-grown recursive relabel walker. |
| **H1** | Builder can fetch arbitrary URLs from a network position unavailable to the agent | **BLOCKER_DECISION** | SC3 | Accept an explicit builder-network threat-boundary design. Fix the network position if the supported promise excludes this access; do not parse Dockerfiles as a substitute policy engine. |
| **H2** | Credential can be revoked after authentication but before Session issuance | **CLOSED_CURRENT** | SC1 | Closed at the existing Session-issuance linearization owner: the create transaction's conditional insert re-proves the authorizing credential (still existing, still owned, still active) in the same statement as the Session insert, so a revoke/delete committing before the Session commit prevents the Session and the refusal answers the canonical non-disclosing 401 credential classification. Winning ordering unchanged: an already-issued Session stays valid. Deterministic parked-query race evidence on both credential paths. |
| **H3** | Privileged filesystem resolution happens before authorization and leaks resolver detail | **CLOSED_CURRENT** | SC1 | Authorization-before-probing ordering established at all three session-facing admission boundaries: the raw spelling is admitted lexically against the issued filesystem capability FIRST (workspace create against the effective ceiling, absolute run mount against the issued snapshot entries, build context/Dockerfile against the workspace), and a spelling outside the capability is refused immediately WITHOUT any privileged filesystem probe — zero-probe seam evidence, not merely equal responses. The former symlink-alias admission (an outside spelling resolving into the capability) is removed as an explicit Release 2.2 security tightening. After admission the canonical `EvalSymlinks` + containment proofs remain the mandatory second security proof (inside-ceiling aliases work; inside-ceiling symlink escapes stay fail-closed); public unauthorized failures stay bounded/non-disclosing; admitted spellings keep their actionable diagnostics; run/build keep their stable public contracts with admission diagnostics retained operationally. |
| **H4** | Build staging can consume unbounded tmpfs bytes/inodes/depth/files | **BLOCKER_FIX** | SC2 | Add measured hard ceilings for staged bytes, entries and depth, admitted/reserved before staging. Failure must be bounded and leave no residue. Do not introduce the Release 3 quota hierarchy. |
| **H5** | Logs, mount pins and concurrent/running Operations provide unbounded host-resource channels | **BLOCKER_FIX** | SC2 | Bound response materialization, mounts/pins per operation, and concurrent/running operation admission at Session/global security ceilings. Measure defaults and reserve before expensive work. |
| **H6** | Mandatory MAC policy blocks admin-token rotation | **BLOCKER_FIX** | SC1 | Narrow AppArmor/SELinux write/rename permission to the token replacement lifecycle only; live enforcing UAT proves old token rejected and new token accepted. |
| **H7** | A local user can occupy the optional TCP port and drive the service into systemd start-limit failure | **BLOCKER_FIX** | SC2 | Current code still creates the Unix listener and then treats TCP bind failure as fatal, while the shipped service has `Restart=on-failure` plus a finite start-limit. The authoritative local Unix service must not be permanently denied by unauthenticated TCP port capture. |
| **H8** | External MAC commands can hold shared coordination long enough to delay emergency disable | **BLOCKER_FIX** | SC2 | Existing MAC command owners gain bounded cancellation/timeouts and the lifecycle lock path is reviewed so untrusted-size work cannot indefinitely hold administrative disable. Avoid a new queue/framework unless evidence requires it. |
| **H9** | Agent container can receive the helper runtime directory and steal registry secrets/replace CA state | **CLOSED_CURRENT** | SC1 | Closed by composition with C1, without a second socket transport owner: with the privilege floor in place the strongest reachable workload privilege is the Principal UID:GID with no capabilities and no-new-privileges, which the root-owned `0700` helper-private runtime state denies; the read-only projection and unchanged bearer authentication are unchanged. Hostile helper-socket UAT on enforcing AppArmor and enforcing SELinux proved the socket transport functional, unauthenticated calls refused, private runtime/session Docker config unreadable, runtime immutable, and escalation dead (see the SC1 evidence ledger). |
| **H10** | An allowed root lets the root daemon read files the Principal could not read under Unix DAC | **BLOCKER_DECISION** | SC3 | Decide whether a filesystem capability intentionally grants helper-mediated read independent of DAC or must additionally preserve Principal DAC/group/ACL semantics. Do **not** implement an owner-UID check as a fake Unix permission model. |
| **M1** | Environment/build secret values appear in the Docker CLI process argv | **BLOCKER_DECISION** | SC3 | Inventory each secret-bearing channel and choose a supported transport/mitigation. `--env-file` is not assumed equivalent for arbitrary current values. Any residual `/proc` exposure must be explicit in threat/operations docs. |
| **M2** | Documentation puts bearer tokens directly in `curl` argv | **BLOCKER_FIX** | SC1 | Rewrite shipped examples to token-file/stdin/environment patterns that do not expand the secret into process argv; keep examples executable. |
| **M3** | Registry credentials are plaintext in the per-Session Docker config | **DEFER_HARDENING** | SC4 | Plaintext storage remains, but the current independent boundary is the root-owned runtime plus per-Session `0700` directory and mandatory MAC. Do not add a keychain/encryption subsystem without demonstrated need. This disposition is conditional: C1/H9 hostile UAT must prove the file remains unreachable from a hostile workload; otherwise promote M3 back to a blocker. |
| **M4** | Raw-config validation and `json.Unmarshal` accept different key grammar; bad values can reach panic-prone consumers | **BLOCKER_FIX** | SC1 | One strict config decoding/validation path owns key recognition and bounds; malformed/case-variant input fails closed before effective config exists. |
| **M5** | NUL-containing Principal name can resolve through libc as one OS user but persist as a distinct DB identity | **BLOCKER_FIX** | SC1 | Current creation checks only non-empty input, resolves it through `user.Lookup`, then persists the original request string. Add one canonical username validation boundary before OS lookup/persistence; reject NUL/control aliases rather than creating a second name grammar. |
| **M6** | Audit write failure does not abort the protected operation | **ACCEPTED_CONTRACT** | SC0/SC4 | Current Release 2.x audit is best-effort observability, not a fail-stop transaction boundary. Do not change operation success semantics merely to match the audit recommendation. Improve failure observability only if useful; a new fail-stop audit contract requires separate architecture acceptance. |
| **M7** | Cancellation can leave an untracked running container when cidfile timing loses the race | **CLOSED_CURRENT** | SC0 | System-mode ownership no longer depends on cidfile timing: every run has server-owned operation/session labels, post-run cleanup first proves the correlated container absent through label provenance, and failed cleanup retains durable state for startup reconciliation. Preserve that single cleanup/provenance owner. |
| **M8** | Principal disable/delete or Session deletion does not stop already-started work | **ACCEPTED_CONTRACT** | SC0 | Current 2.x lifecycle deliberately allows an already-started operation to finish after the authority/Session change; future requests are rejected. Existing exact-artifact regression group 3 proves this contract. |
| **M9** | User-mode pathname race exists because Docker resolves a path again without the system-mode pinning boundary | **ACCEPTED_CONTRACT** | SC0/SC4 | User mode does not claim isolation from another process running as the same OS user and Docker authority. System mode owns the stronger inode-pinning guarantee. Keep documentation aligned; extending user-mode pinning is optional hardening, not an implicit contract change. |
| **M10** | Allowed-root symlinks are recomputed after validation without reapplying the safety policy | **CLOSED_CURRENT** | SC0 | The old raw-symlink re-resolution path is gone: current effective allowed-root policy is composed from canonical paths and the Session snapshot persists the issued canonical identity; later data-plane decisions consume that snapshot rather than re-resolving the original stored spelling. Preserve the symlink/path-policy regressions. |
| **M11** | SELinux fcontext input escapes regex syntax but not file-format/control-character hazards | **BLOCKER_FIX** | SC1 | Current workspace/root policy does not reject newline/control characters and `escapeFcontextPath` only escapes regex metacharacters. Reject unsupported control characters at the canonical host-path policy owner, not only inside the SELinux backend. |
| **M12** | `semanage fcontext` output parser disagrees with the producer's long-path spacing | **BLOCKER_FIX** | SC1 | Parse the real `semanage` output grammar robustly and add long-path/backend tests; do not preserve a width-dependent split rule. |
| **M13** | Crafted bind-mount target can desynchronize Docker `--mount` CSV and lose `readonly` | **BLOCKER_FIX** | SC1 | One bind-mount serializer/encoder owns every Docker bind form; hostile target tests must prove exact target and access mode survive Docker parsing. No ad-hoc concatenation per caller. |

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
statted before the snapshot exposure decision) and for the build
context/Dockerfile spellings (resolved before workspace containment).

Closed by establishing the authorization-before-probing ordering at all
three session-facing admission boundaries, as an explicit Release 2.2
security tightening of the symlink-alias semantics:

- the raw caller spelling is admitted lexically against the issued
  filesystem capability FIRST — the effective allowed-root ceiling for
  the Session-create workspace, the issued Session filesystem snapshot
  entries for the absolute run mount source, the canonical session
  workspace for the build context and the resolved context for the
  Dockerfile — without any host filesystem probing;
- a spelling outside the capability is refused immediately WITHOUT
  `EvalSymlinks`/`stat`: no existence, error class, path type, or
  resolved alias of an unauthorized pathname is ever collected or
  disclosed; the public refusals stay the existing bounded
  authorization-shape codes (`invalid_workspace`,
  `invalid_mount`, `invalid_build_context`) with no new error code;
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
`validateBuildRequest`) reusing the existing lexical containment
helpers, and the privileged probes route through one test seam
(`evalSymlinksFn`/`osStatFn`) covering exactly the three session-facing
admission sites.

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
  absolute run mount spelling outside the issued snapshot, and a build
  context spelling outside the workspace (existing, missing, dangling,
  and relative-escape spellings) — and that an ADMITTED spelling is
  still resolved, with an inside-ceiling symlink escape still
  fail-closed by the canonical containment proof.
- GREEN indistinguishability matrices (workspace create, run mounts,
  build context) prove the public unauthorized outcomes are identical
  across filesystem states, with the admission diagnostics retained in
  the operational log and the authorized E-H semantics preserved
  (existing issued; missing-inside-ceiling operator diagnostic;
  inside-ceiling alias issued; inside-ceiling symlink escape refused;
  outside-ceiling alias now refused without probing).

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

## SC1 — immediate trust-boundary, parser and MAC closure

**Queue:** `C3`, `H6`, `M2`, `M4`, `M5`, `M11`,
`M12`, `M13`. (C1 and H9 closed in SC1 — see the SC1 evidence ledger. H2
and H3 closed in SC1 — see the SC1 evidence ledger below.)

SC1 contains defects that are locally actionable through existing owners and
whose fixes do not require the larger resource-control or architecture
questions of SC2/SC3.

Implementation constraints:

- C1/H9: one workload privilege-floor owner; do not scatter privilege flags
  across `run.go`, MAC backends and tests. Staging strips privilege bits at the
  staging owner.
- C3: prove a safe lower-layer libselinux implementation or fail closed; no
  second recursive traversal implementation.
- H2: reuse the Session issuance/lifecycle linearization owner.
- H3: preserve rich diagnostics in operational logs while bounding public
  errors.
- H6: MAC changes are as narrow as the token replacement lifecycle; no write
  grant to the whole config directory.
- M4: one config grammar/decoder owner.
- M5: one accepted Principal username grammar before OS lookup and persistence.
- M11: host-path control-character policy belongs to the shared path owner.
- M12: the parser follows the producer grammar, not terminal-width spacing.
- M13: one Docker bind serializer for every bind mount form.

## SC2 — bounded-resource and liveness closure

**Queue:** `H4`, `H5`, `H7`, `H8`.

SC2 removes unbounded host-resource and liveness channels without importing the
Release 3 resource model. Release 2.2 needs hard security ceilings, not a new
quota hierarchy.

Required direction:

- staging has measured maximum bytes, entries and depth;
- operation/mount/log/concurrency resources have finite admission ceilings;
- resource reservation/admission happens before expensive preparation where the
  attack depends on pre-admission work;
- optional TCP listener failure cannot destroy availability of the authoritative
  local Unix service;
- external MAC commands have bounded execution/cancellation and cannot hold
  lifecycle coordination indefinitely.

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
   token succeeds with no broader writable config surface.
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
