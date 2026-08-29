# docker-helper — developer instructions

Long-lived development rules for docker-helper, the policy-enforcing Docker
proxy daemon for sandboxed agents. Read the Orientation first. The rules below
encode architectural decisions and lessons from real regressions; treat them as
governance, not as a substitute for `docs/architecture.md`.

## Orientation

- **Single binary, single package.** One Go module (`docker-helper`, Go 1.23),
  all code in `package main` at the repo root: one binary is daemon, CLI, and
  HTTP API. There are no library subpackages, so `go test ./...` is one package
  and `go test -run 'TestName' .` runs one test.
- **Linux-only.** Files guarded by `//go:build linux`/`!linux`
  (`staging_*.go`, `mount_pin_*.go`). Do not assume other OSes.
- **Build:** `go build -o docker-helper .` writes the gitignored
  `./docker-helper`. Release/static tooling: `build-static.sh <version>`,
  `build-bundle.sh`, `build-packages.sh`, `build-manpages.sh`; artifacts land
  in gitignored `dist/`.
- **Entrypoints:** `main.go` (wiring), `cli.go` + `config_cli.go` +
  `agent_cli.go` (command tree), `app.go` (daemon startup), `operation.go`
  (async build/run lifecycle), `mac_lifecycle.go` (AppArmor/SELinux
  confinement lifecycle). Canonical design reference: `docs/architecture.md`.
- **Mode model:** the same binary runs non-root (user mode) or root (system
  mode), decided at runtime by effective UID. Tests simulate both modes
  without root by reassigning package-global seams — `EffectiveUID`
  (`config.go`), `getConfigPathFunc`, `getRuntimeDirFunc`, `systemSocketExists`
  (`operator_client.go`), `trustedCARestorecon` (`ca.go`). These are
  package-global state: never use `t.Parallel()` in tests that swap them.
- **Docker-dependent tests skip** when `docker`/the daemon is unavailable
  (for example `container_lifecycle_integration_test.go`); the rest of the
  suite runs without Docker.
- **Shipped policy is tested.** AppArmor profiles (`packaging/apparmor/`),
  SELinux policy (`packaging/selinux/`), systemd units, and install scripts are
  asserted by root-package tests (`apparmor_test.go`,
  `selinux_fcontext_test.go`, `packaging_test.go`). When daemon behavior that
  touches the host changes, consider whether shipped policy must change too —
  and change the product artifact, not just the test.
- **Man pages are source-controlled** in `docs/man/*.1`/`*.5` and must stay in
  sync with CLI/help text; `build-manpages.sh` compresses them into `dist/man/`.
  `manpage_test.go`, `completion_test.go`, and `cli_help_test.go` guard related
  contracts.
- **Version:** `var version = "dev"` in `main.go`. Official versions come only
  from ldflags (`-X main.version=...`) in the build scripts. Never hardcode a
  release number in source.
- **Docs roles:** `README.md` = operator quick start; `docs/architecture.md` =
  canonical design/API/audit reference; `docs/roadmap.md` + `docs/release-*.md`
  = release scope and plans; `.claude/skills/docker-helper/SKILL.md` =
  instructions for agents USING docker-helper, not developing it.
- **Validation gate** (same core gate as CI): `gofmt -l .` (must be empty),
  `go test ./...`, `go test -race ./...`, `go vet ./...`, `git diff --check`.
  CI-only extras needing additional tools include
  `scripts/check-selinux-policy.sh` and `scripts/check-static-build.sh`.
- **Secrets:** never write admin tokens, Session bearer tokens, Principal
  credential tokens, Authorization headers, or secret environment values into
  logs, audit output, API errors, or CLI stderr.

# Development approach

1. Work incrementally.

Analyze the current implementation before changing it.

For non-trivial cleanup/refactoring tasks:
- trace the existing behavior;
- identify the concrete problem;
- distinguish correctness issues from maintenance/style preferences;
- identify behavior that must remain unchanged;
- choose the smallest appropriate architectural change.

If the task explicitly says `analyze`, `inspect`, `review`, or `do not modify`,
do not edit files or create commits.

2. Do not solve hypothetical problems.

Do not add abstractions, generic frameworks, background workers, retry systems,
migration infrastructure, or configuration switches for possible future needs.

Future extensibility is a constraint, not a requirement to implement future
architecture now.

Generalizing an existing owner so another caller with the same semantics can use
it is not speculative framework-building. Consolidating an already shared
responsibility is different from inventing a framework for hypothetical reuse.

3. Prefer deletion and simplification.

Before adding code, ask whether the correct change is:
- deleting dead state;
- removing duplicate validation;
- delegating semantics to the authoritative underlying tool;
- extending an existing owner;
- documenting an intentional limitation.

Examples:
- Docker owns Docker image-reference grammar;
- SQLite owns database locking/concurrency semantics unless a concrete problem
  requires additional coordination;
- filesystem canonicalization should have one clear ownership boundary;
- expired-session correctness comes from expiry checks, while physical cleanup
  is maintenance.

Do not duplicate behavior of an authoritative underlying component unless
`docker-helper` has a concrete policy reason to do so.

Deletion and simplification remain subordinate to public contracts and explicit
compatibility requirements.

# Scope and contracts

4. Preserve task scope.

Do not opportunistically fix unrelated code. Report additional findings
separately unless they are necessary to preserve the requested behavior or the
single authoritative owner being changed.

A cleanup commit should remain a cleanup commit. A behavior change should be
explicit. Explicit task/file restrictions take precedence.

5. Do not silently change contracts.

Treat these as contracts unless the task explicitly changes them:
- CLI command names, parsing, help, output, exit codes, and stdout/stderr split;
- HTTP status/code/message behavior;
- JSON request/response fields;
- audit event names and fields;
- filesystem/path policy;
- authentication and authorization semantics;
- configuration fields, defaults, and normalization rules.

If implementation and documentation disagree, identify the authoritative source
before changing either. If the conflict would require a public-contract change
and the task or canonical documentation does not resolve it, report the
conflict instead of guessing.

When introducing or reusing a domain error, inspect every public boundary that
may receive it. Expected policy/input/state errors must not silently fall
through to generic internal-error handling.

Prefer typed error inspection (`errors.Is`, `errors.As`, concrete error types,
syscall errors) over matching human-readable strings. Use string matching only
when a dependency exposes no stable typed signal; keep such classifiers narrow
and document why they exist.

Transactional CLI operations must emit success only after the contractual
success/commit point. A rolled-back mutation must never already have been
reported as successful.

# Architecture and domain model

6. One domain concept -> one canonical term.

Different lifecycle/backend implementations must not introduce synonyms for the
same concept. Different concepts must not share one overloaded word merely
because their structures look similar.

Before introducing a new noun, field, selector, reference type, default, or
validation rule, search for the existing domain concept and the abstraction that
owns its semantics.

Backend-native terminology is appropriate when the concept really is
backend-specific (`AppArmor` profile, `SELinux` fcontext, distro trust anchor),
but it must not replace the product-level concept it serves (for example,
Trusted CA preparation).

Use established Go initialism casing consistently. In this repository that
includes, where applicable:

    API  CLI  HTTP  JSON  TLS  CA  PKI  PEM  MAC  UID  ID  ASN1
    AppArmor  SELinux

Do not create a second spelling once a canonical one exists.

7. Defaults and normalization have one owner.

A default is domain semantics, not a convenience to duplicate independently in
sibling commands.

If create/show/revoke/rotate or analogous operations address the same logical
object, selection/defaulting/normalization must happen once at the shared
boundary and all operations must consume the same normalized representation.

Equivalent CLI concepts should share parsing, normalization, validation, and
completion behavior through a common owner. A new command must not reinterpret
an existing concept locally just because its syntax is easy to parse there.

Prefer a small explicit domain reference/selector type when several operations
already share those semantics. Do not introduce wrapper types for a single call
site merely for stylistic uniformity.

8. One production owner per responsibility.

Before adding a helper, registry, lifecycle abstraction, executor, buffer,
cleanup path, validation path, transaction path, or state-transition mechanism,
find the existing owner of that responsibility.

Reusing the same low-level primitives does not count as reusing the existing
abstraction if it reconstructs lifecycle or policy already owned by a higher
level production path.

Do not create a parallel implementation merely because the current owner is
awkward for a new caller. If semantics are the same, extend or adapt the owner.
If the owner is itself wrong, refactor/replace it and migrate callers rather
than layering a second authoritative mechanism beside it.

A difference in one stage does not justify duplicating the surrounding
lifecycle. Isolate the differing stage and keep common invariants under the
existing owner.

A separate implementation is justified only when semantics, invariants, or the
trust boundary are genuinely different. Consolidate by semantic responsibility,
not structural similarity.

When integrating parallel agent/contributor work, explicitly review for:
- duplicate helpers or owners;
- old and new lifecycle paths coexisting;
- callers bypassing a shared client/policy layer;
- slightly different validation/auth/error/audit behavior for the same action;
- test-only abstractions that duplicate production semantics.

Passing tests do not justify retaining duplicate ownership.

9. Separate policy boundaries.

Keep these concerns conceptually and operationally separate:
- authentication;
- authorization;
- lifecycle/state;
- MAC confinement;
- backend mechanics.

An authorization scope does not acquire MAC lifecycle semantics merely because
the same filesystem path appears in both concerns. MAC implements confinement
for an already-defined runtime/authorization model; it must not silently
redefine that model.

Canonical conceptual vocabulary:

    global allowed root
        authorization ceiling only

    principal allowed root
        authorization narrowing only

    workspace
        concrete Session capability path

    MAC boundary
        durable confinement resource

    session MAC binding
        Session -> MAC boundary relationship

Distinctions that must remain visible in code and tests:

    authorization root != MAC boundary
    coverage != ownership
    backend/driver mechanics != lifecycle owner

Current Go identifiers may evolve; `AGENTS.md` does not freeze implementation
names. Preserve the conceptual distinction and update `docs/architecture.md`
when architecture changes.

Containment helpers use root-first argument order:

    pathWithin(root, path)
    pathStrictlyWithin(root, path)

Do not silently reverse this convention in new helpers/callers.

10. Keep docker-helper narrow.

`docker-helper` provides controlled Docker execution for sandboxed agents.
Do not turn it into a general host command executor, generic agent daemon,
secrets manager, network proxy, or general orchestration/control-plane service.

Architectural principle:

    one tool — one coherent responsibility
    standalone first
    integration optional

Standardize contracts where useful; do not create mandatory shared runtimes or
libraries merely to make future tools look uniform.

Do not add reconciliation, desired-state recovery, or restart-policy semantics
merely because Docker objects have lifecycle. Such semantics require an explicit
architecture change, not an incidental implementation choice.

11. Keep release scope out of this file.

`AGENTS.md` contains long-lived development rules, not the state of the current
release. For release-specific work, read the current roadmap and active release
plan and use `docs/architecture.md` for accepted runtime semantics.

Do not encode current release numbers/milestones here, duplicate release feature
lists, move features between releases without an explicit roadmap task, or infer
future API/architecture merely from a roadmap item.

# Security

12. Identify the actual security boundary.

Before calling validation `security`, identify the boundary it protects.
Distinguish, for example:
- shell injection from argv passing;
- path containment from lexical/string validation;
- authentication from authorization;
- authorization from MAC confinement;
- correctness validation from convenience validation.

Do not add restrictive validation merely because input is user-controlled.
Security-sensitive behavior must have focused tests.

13. Security policy changes are evidence-driven.

For SELinux/AppArmor, do not broaden policy preemptively.

Start from either:
- a demonstrated runtime operation that the architecture requires; or
- an observed denial from the confined production path.

Then grant the narrowest permission that satisfies that requirement.

Do not copy policy mechanically between SELinux and AppArmor. Preserve the same
architectural capability while respecting each backend's actual mechanics,
object model, and denial evidence.

Do not turn a local workaround into a generic policy wildcard merely because it
would make UAT pass faster.

14. Secrets must not leak.

Never expose admin tokens, Session bearer tokens, Principal credential tokens,
Authorization headers, or secret environment values through operational logs,
audit logs, CLI stderr, or API error messages.

Preserve existing masking/redaction behavior. Leak tests should use unique
marker values and inspect the raw observable output, not merely expected field
names.

# Filesystem and workspace policy

15. Preserve workspace/path invariants.

For workspace-backed Sessions, the workspace is canonicalized when the Session
is created.

Mount/build path validation must enforce containment after symlink resolution.
Do not duplicate path policy across handlers when an existing invariant already
guarantees it. Do not weaken symlink-escape protection.

When a deployment mode or operation intentionally has no local workspace,
follow the architecture/release-plan contract for that mode instead of inventing
a synthetic workspace solely to reuse local validation code.

Do not infer host-path existence/non-existence from a different mount namespace.
Validate filesystem claims at the boundary that actually owns the path.

# Database

16. SQLite is local state, not a distributed subsystem.

Prefer simple SQL and SQLite's existing transaction/locking behavior. Do not
introduce ORM layers, repository abstractions, background maintenance workers,
or elaborate transaction frameworks without a concrete need.

Existing databases must be considered when changing schema behavior. Do not
create migration machinery solely to remove harmless historical physical
baggage when current queries remain compatible.

The warning against transaction frameworks does not permit duplicated
transaction/recovery semantics. If such behavior already has an owner, extend
that owner.

Historical identity and active logical identity are distinct concerns. When a
record is retained for audit/history, do not assume it must continue occupying
an active logical slot; enforce uniqueness/lifecycle according to the domain
contract, not table-key convenience.

# Tests

17. Every test protects an independent observable invariant.

Before adding a test, inspect existing coverage for the same behavior. Extend or
generalize an existing test when it already protects the same failure mode.

Use table-driven tests when several cases exercise one invariant. Test count and
test LOC are not goals.

Keep regression tests for real bugs, error-contract tests, security-boundary
tests, audit leak tests, and CLI black-box behavior tests. Avoid freezing
incidental implementation structure.

A test name must not claim more than its assertions prove, and its terminology
must follow the same canonical vocabulary/initialism rules as production code.

A shipped repository artifact that is part of the product is a required test
fixture. Its disappearance is normally a regression, not a reason to `Skip`,
unless absence of that artifact is itself an explicitly supported environment.

18. A test must prove it reached the claimed behavior.

A passing negative assertion is not sufficient by itself. Setup must make the
undesired behavior possible and observable.

Examples:
- to prove `no mutation`, mutation must otherwise be possible and observable;
- to prove `no secret leak`, inject a unique marker and inspect raw output;
- to prove `no operational ERROR`, first prove execution reached the intended
  runtime/result branch;
- to prove a stale/concurrent/error branch, arrange the exact state needed to
  reach that branch rather than failing earlier for another reason.

Fault injection must be as narrow as possible and target the exact operation
whose failure is being tested.

For a real bug fix, the regression test should fail against pre-fix behavior
whenever practical. Be able to identify:
1. the exact regression it protects;
2. the assertion that fails when the regression returns;
3. the production path exercised.

If any of these is unclear, strengthen, merge, rename, or remove the test.

19. Tests exercise production semantics, not a reimplementation.

A fake/seam may replace an external dependency, but production code under test
must still own the lifecycle/policy/request semantics being asserted.

Do not implement a second operation lifecycle, log cursor, cleanup path, path
validator, auth decision, or request/response behavior inside tests merely to
make assertions convenient.

Prefer handler/lifecycle/audit/logging/auth tests that enter through the real
production path and assert externally observable results. Direct helper tests
are appropriate for isolated pure behavior.

Use deterministic synchronization signals (state transitions, channels,
callbacks, process state), not arbitrary `time.Sleep` readiness assumptions.
When stabilizing a flaky test, diagnose the timing/lifecycle issue before
changing production behavior.

Keep test infrastructure economical:
- strengthen existing suites before creating parallel test files;
- reuse/extend one clear helper per domain;
- avoid boolean-heavy setup helpers, generic builders with many options, and
  assertion DSLs;
- use `t.Setenv` for test-scoped environment changes;
- check fixture setup errors;
- do not use `t.Parallel()` around package-global seams.

Before completing a task with new/substantially changed tests, ask:
1. What exact invariant does this protect?
2. Is it already protected elsewhere?
3. Did the test prove the intended path was reached?
4. Could it stay green because setup made the bad outcome impossible?
5. What concrete regression makes it fail?

A green suite is necessary, not sufficient evidence that new tests are
meaningful.

When behavior changes from one value to many, test genuinely multi-value
behavior where relevant: multiple values, a non-first value, ordering,
deduplication, and a case that would fail if implementation still effectively
behaved as single-value.

# Documentation ownership

20. Keep documentation roles distinct.

`README.md` owns project introduction, quick start, common operator workflows,
and concise examples.

`docs/architecture.md` owns current architecture/invariants, trust/security
model, lifecycle semantics, detailed API/CLI behavior, and design rationale.

`docs/roadmap.md` owns release sequence/scope, planned work, and explicit
deferrals. `docs/release-*.md` owns the binding implementation plan for a
specific release when such a plan exists.

`.claude/skills/docker-helper/SKILL.md` owns canonical reusable instructions for
agents USING docker-helper.

`AGENTS.md` owns long-lived instructions for agents DEVELOPING docker-helper.

Do not duplicate large reference sections between documents. Prefer links to
the canonical owner.

# Versioning and tunability

21. Version ownership.

Source default:

    var version = "dev"

Development builds must work with plain `go build`. Official versions are
injected through ldflags from release tooling/tag. Do not manually maintain a
release number in source.

22. Make operational policy configurable only when operators need to tune it.

Timeouts, retention periods, resource/count limits, and log/output size limits
should have documented reasonable defaults when they are genuine operational
policy.

This does not mean every constant belongs in configuration. Protocol/domain
invariants such as HTTP status semantics, operation state names, ID formats,
and fixed protocol behavior should remain in code unless a concrete operational
need justifies configuration.

Release-scoped hard limits may remain implementation constants when deliberate
and documented.

# Change procedure

23. Before implementation, perform an ownership check.

For non-trivial feature/refactor work, identify:
- the concrete problem;
- behavior that must remain unchanged;
- where current behavior lives;
- which production abstraction owns its lifecycle/invariants;
- whether the new behavior can use that owner unchanged;
- if not, whether that owner should be generalized or replaced.

Searching only for similarly named functions is insufficient. Trace the current
call path by responsibility and behavior.

Do not introduce a new production path before this check.

`Smallest appropriate change` means the smallest architectural change that
preserves ownership and invariants, not necessarily the smallest diff. A smaller
diff is worse if it creates a second owner, parallel lifecycle, duplicated
policy/validation, or behavior that must later be kept in sync.

Do not require a separate approval step unless the task explicitly asks for
analysis/review first.

24. After implementation, validate both behavior and architecture.

Run:

    gofmt -l .
    go test ./...
    go test -race ./...
    go vet ./...
    git diff --check

`gofmt -l .` must print nothing. Text files must end with a newline.

Review the final diff for unrelated changes. If tests changed, review them
against the proof/independence rules above; passing commands alone are not
enough.

If a production mechanism was added/generalized/replaced, trace final production
paths again and verify:
- old and new owners do not coexist unintentionally;
- no caller bypasses the authoritative path;
- superseded helpers/seams are no longer reachable;
- tests exercise the authoritative path.

Run policy/static-build checks as required by the changed area and available
tooling.

25. Wait for asynchronous state, not estimated durations.

When waiting for CI, builds, deployments, VM boot, background processes, or
other external state, wait for the condition rather than an estimated amount of
time.

Prefer a native blocking/watch command when one exists, for example:

    gh run watch <run-id> --exit-status --interval 10

Otherwise use bounded polling with short intervals:
- check the condition immediately before the first sleep;
- normally poll every 5–15 seconds;
- stop as soon as the operation reaches a terminal, ready, or failure state;
- use an explicit overall timeout;
- report useful progress when appropriate.

Never use one long blind sleep to wait for an asynchronous event, for example:

    sleep 420
    gh run view ...

A long blind sleep delays reaction to early completion/failure and wastes task
time. If an operation is expected to take several minutes, keep waiting on its
state rather than increasing the blind sleep interval.

26. Keep commits and pushes deliberate.

Keep commits focused. Commit messages must describe the code actually present;
do not leave stale claims after amending implementation.

When a task explicitly requests push, push the current working branch unless it
names another. Never use plain `--force`; use `--force-with-lease` only when
history was intentionally amended.

Do not push merely because implementation is complete unless the task requests
it.

27. Review architecture after significant feature blocks.

After multiple commits add a substantial capability, before the next major
phase review for:
- duplicate paths/abstractions;
- obsolete compatibility code;
- contract drift between implementation and documentation;
- help/docs drift;
- tests freezing accidental implementation details;
- parallel test helpers or production lifecycles introduced independently.

This is a backstop, not permission to knowingly create duplicate ownership.
If current work supersedes a production path, consolidate it now unless a
compatibility contract explicitly requires coexistence.

When replacing a path, remove obsolete production helpers, seams, tests,
comments, and documentation that existed solely for the replaced
implementation. Do not preserve dead implementation only because old tests
depend on it.
