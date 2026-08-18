# Development approach

1. Work incrementally.

Analyze the current implementation before changing it.

For non-trivial cleanup/refactoring tasks:
- trace the existing behavior;
- identify the concrete problem;
- distinguish correctness issues from maintenance/style preferences;
- propose the smallest useful change;
- modify code only when the requested task includes implementation.

If the task explicitly says "analyze", "inspect", "review", or "do not modify",
DO NOT edit files or create commits.

2. Do not solve hypothetical problems.

Do not add:
- abstractions for possible future features;
- generic frameworks for one or two call sites;
- background workers without a demonstrated runtime need;
- retry systems without a demonstrated transient-failure problem;
- migration infrastructure before an actual schema migration requires it;
- configuration switches for behavior that has not been requested.

Future extensibility is a constraint, not a requirement to implement future
architecture now.

3. Prefer deletion and simplification.

Before adding code, ask whether the correct change is:
- deleting dead state;
- removing duplicate validation;
- delegating semantics to the authoritative underlying tool;
- reusing an existing primitive;
- documenting an intentional limitation.

Examples from the current architecture:
- Docker owns Docker image-reference grammar;
- SQLite owns database locking/concurrency semantics unless a concrete problem
  requires additional coordination;
- filesystem canonicalization should have one clear ownership boundary;
- expired-session correctness comes from expiry checks, while physical cleanup
  is maintenance.

Do not duplicate the behavior of an underlying authoritative component unless
docker-helper has a concrete policy reason to do so.

# Scope discipline

4. Preserve task scope.

Do not opportunistically fix unrelated code.

When you notice another issue:
- report it separately;
- do not include it in the current commit unless it is necessary for the
  requested change.

A cleanup commit should remain a cleanup commit.
A behavior change should be explicit.

5. Do not silently change contracts.

Treat these as contracts unless the task explicitly changes them:
- CLI command names and output;
- HTTP status/code/message behavior;
- JSON request/response fields;
- audit event names and fields;
- filesystem/path policy;
- session authentication semantics;
- configuration fields/defaults;
- stdout/stderr separation.

If implementation and documentation disagree, identify which is authoritative
before changing either.

# Architecture

6. Keep docker-helper narrow.

docker-helper provides controlled Docker execution for sandboxed agents.

Do not turn it into:
- a general host command executor;
- a generic agent daemon;
- a secrets manager;
- a network proxy;
- a general orchestration/control-plane service.

Related capabilities should remain independently implementable tools.

Architectural principle:

    one tool — one capability
    standalone first
    integration optional

Standardize contracts where useful; do not create mandatory shared runtime or
shared libraries merely to make future tools look uniform.

7. Keep release scope out of this file.

`AGENTS.md` contains long-lived development rules, not the state of the current
release.

Before release-specific work, read the current roadmap and active release plan.
Use the architecture documentation for accepted design and runtime semantics.

Do not:
- encode the current release number or milestone here;
- duplicate release-specific feature lists here;
- move features between releases unless the task explicitly changes the roadmap;
- infer future API or architecture merely from a roadmap item.

# Security

8. Treat security boundaries explicitly.

Before calling validation "security", identify the actual boundary.

Distinguish:
- shell injection from argv passing;
- path containment from string validation;
- authentication from authorization;
- correctness validation from convenience validation.

Do not add restrictive validation merely because input is user-controlled.

Security-sensitive behavior must have focused tests.

9. Secrets must not leak.

Never expose:
- admin tokens;
- session bearer tokens;
- launcher credential tokens;
- Authorization headers;
- secret environment values

through:
- operational logs;
- audit logs;
- CLI stderr;
- API error messages.

Preserve existing masking/redaction behavior.

# Filesystem and workspace policy

10. Preserve workspace/path invariants.

For workspace-backed sessions, the session workspace is canonicalized when the
session is created.

Mount/build path validation for workspace-backed operations must enforce
containment after symlink resolution.

Do not duplicate path policy across handlers when an existing invariant already
guarantees it.

Do not weaken symlink-escape protection.

When a deployment mode or operation intentionally has no local workspace, follow
the architecture and release-plan contract for that mode instead of inventing a
synthetic workspace merely to reuse local validation code.

# Database

11. SQLite is local state, not a distributed subsystem.

Prefer simple SQL and SQLite's existing transaction/locking behavior.

Do not introduce:
- ORM layers;
- repository abstractions;
- background maintenance workers;
- elaborate transaction frameworks

without a concrete need.

Existing databases must be considered when changing schema behavior.

An extra historical column in an old SQLite database is acceptable if current
queries remain compatible; do not create migration machinery solely to remove
unused physical baggage.

# Tests

12. Every test must protect an independent observable invariant.

Before adding a test, inspect existing tests for the same behavior.

Do not add a separate test merely because:
- there is another `if` branch;
- there is another error return;
- the task listed another bullet;
- the same invariant can be exercised with another input.

If an existing test already protects the same failure mode, extend or
generalize that test instead.

Use table-driven tests when several cases exercise the same invariant.

Test count and test LOC are not goals.

Keep:
- regression tests for real past bugs;
- error-contract tests;
- security boundary tests;
- audit leak tests;
- CLI black-box behavior tests.

Avoid tests whose only purpose is freezing an unnecessary implementation
detail.

13. A test must prove that it reached the behavior it claims to test.

A passing negative assertion is not sufficient by itself.

The setup must make the undesired behavior possible and observable.

Examples:
- To prove "no mutation", mutation must otherwise be possible and the test must
  be able to observe whether it was attempted. Do not disable the entire
  database/resource when that independently makes mutation impossible.
- To prove "no secret leak", inject unique marker values and inspect the raw
  observable output for those values. Checking only expected field names or
  schema is insufficient.
- To prove "no operational ERROR", first prove execution reached the intended
  runtime/result branch. Do not let authentication, validation, or unrelated
  setup fail earlier.
- To prove a stale/concurrent/error branch, arrange the exact state necessary to
  reach that branch. A different earlier failure does not count.

Fault injection must be as narrow as possible and target the exact operation
whose failure is being tested.

A test name must not claim more than its assertions prove.

14. Regression tests must discriminate between correct and broken behavior.

For a real bug fix, the regression test should fail against the pre-fix behavior
whenever practical.

Before considering a new or substantially changed test complete, identify:
- the exact regression it protects against;
- the assertion that would fail if that regression returned;
- the production path that the test exercises.

If you cannot identify all three, strengthen, merge, rename, or remove the test.

A test that would still pass if the claimed branch were never executed is not a
valid regression test.

When production paths are consolidated, update regression tests to exercise the
authoritative path. Do not preserve an obsolete implementation merely because a
test depends on it.

15. Tests must exercise the production path.

Do not make a test pass by reimplementing production behavior inside the test,
a fake, or a test-only helper.

In particular, do not create a second implementation of:
- operation lifecycle/state transitions;
- log buffering or incremental log reads;
- cleanup/termination behavior;
- path validation/canonicalization;
- authentication/authorization decisions;
- request/response semantics.

A fake or seam may replace an external dependency, but the production code
under test must still own the semantics being asserted.

Prefer handler/lifecycle/audit/logging/auth tests that enter through the real
production path and assert externally observable results. Direct helper tests
are appropriate for isolated pure behavior, but do not choose inputs that make
the expected result true by construction.

When a test needs readiness or synchronization, observe a real state transition,
process state, channel, callback, or other deterministic signal. Do not use an
arbitrary `time.Sleep` as synchronization or assume that a fixed delay proves
readiness.

When stabilizing a flaky test, first determine whether the test has a timing
assumption or bypasses the real lifecycle. Do not change production behavior,
API contracts, validation, authentication, audit behavior, or 4xx/5xx semantics
merely to make such a test pass unless the production behavior is independently
shown to be wrong.

16. Keep the test suite economical and explicit.

Merge or delete:
- duplicate tests for the same invariant;
- tests superseded by stronger black-box coverage;
- tests that only restate implementation structure;
- tests that cannot distinguish the intended bug from an unrelated failure.

When modifying a feature with an established test suite, prefer strengthening
existing tests over creating a parallel test file.

Extract helpers when setup/behavior is genuinely identical across several
tests.

Before adding a new test helper, search for an existing helper serving the same
domain. Prefer extending or reusing one clear helper over creating parallel
families with slightly different behavior.

Do not combine fixtures from different domains merely because they share a few
filesystem operations.

Avoid:
- boolean-heavy setup helpers;
- generic builders with many optional fields;
- assertion DSLs.

Explicit setup is preferable when the test is intentionally exceptional.

Use `t.Setenv` for test-scoped environment changes.
Check errors from fixture setup operations.

Before adding `t.Parallel()`, inspect whether the test touches package-global
state such as logging/test seams. Do not assume a test is parallel-safe just
because it uses `t.Setenv`.

Before declaring a task complete, review every new or substantially changed
test and answer:
1. What exact invariant does this test protect?
2. Is that invariant already protected elsewhere?
3. Does the test prove the intended branch/path was reached?
4. Could the test remain green because setup made the bad outcome impossible?
5. What concrete regression would make this test fail?

A green test suite is necessary, not sufficient evidence that new tests are
meaningful.

# Production ownership and parallel work

17. One production mechanism per responsibility.

Before adding a new helper, registry, lifecycle abstraction, executor, buffer,
cleanup path, validation path, or state-transition mechanism, search the current
implementation for the existing owner of that responsibility.

Do not create a parallel implementation merely because the existing one is
awkward for the new call site. Prefer extending or adapting the authoritative
path when the semantics are the same.

In particular, avoid introducing a second:
- operation registry;
- operation lifecycle/state machine;
- log buffer/log cursor mechanism;
- Docker command executor;
- cleanup/termination path;
- terminal-transition mechanism;
- path canonicalization/containment implementation;
- operator/client path for an API that already has one.

A separate implementation is justified only when the semantics or trust
boundary are genuinely different. Make that distinction explicit in the code
and tests.

When a regression test depends on an obsolete implementation that is being
consolidated away, move the test to the authoritative path rather than keeping
both implementations for the test.

18. Review parallel contributions for duplicate ownership.

When integrating work produced in parallel by multiple agents/contributors,
review specifically for:
- duplicate helpers with overlapping purpose;
- old and new lifecycle paths coexisting;
- one caller bypassing a shared client or policy layer;
- slightly different validation/auth/error/audit behavior for the same action;
- test-only abstractions that duplicate production semantics.

When duplicate ownership is discovered, consolidate on one owner unless a
compatibility contract or genuinely different trust boundary requires otherwise.
Do not leave both paths merely because both currently pass tests.

# Documentation ownership

19. Keep documentation roles distinct.

`README.md` owns:
- project introduction;
- quick start;
- common operator workflows;
- concise command examples.

`docs/roadmap.md` owns:
- release sequence;
- release scope;
- planned work and explicit deferrals.

`docs/release-*.md` owns:
- the binding implementation plan for a specific release when such a plan exists.

`docs/architecture.md` owns:
- current architecture and invariants;
- trust/security model;
- lifecycle semantics;
- detailed API/CLI behavior;
- design rationale.

`.claude/skills/docker-helper/SKILL.md` owns:
- canonical reusable instructions for agents USING docker-helper.

`AGENTS.md` owns:
- long-lived instructions for agents DEVELOPING docker-helper.

Do not duplicate large reference sections between documents.
Prefer links to the canonical owner.

# Versioning

20. Version ownership.

Source default:

    var version = "dev"

Development builds must work with plain `go build`.

Official release versions are injected through ldflags from the release version
source/tag.

Do not manually maintain a release number in source code.

# Operational tunability

21. Make operational policy values configurable when operators need to tune them.

Values such as these should have documented reasonable defaults when they are
part of operational policy:
- timeouts;
- retention periods;
- resource/count limits;
- log/output size limits.

This does NOT mean every implementation constant belongs in configuration.

Architectural/protocol invariants and implementation constants such as:
- HTTP status codes;
- operation state names;
- ID formats/internal constants;
- fixed protocol semantics

should remain in code unless there is a concrete operational reason to make
them configurable.

Release-scoped hard limits may remain implementation constants when they are
deliberate and documented. They should become configurable only when a concrete
operational need justifies it.

# Change procedure

22. Before implementation.

For non-trivial implementation tasks, inspect and understand the current
behavior before editing.

Identify:
- the concrete problem;
- the smallest appropriate change;
- behavior that must remain unchanged.

Do not require a separate approval step before implementation unless the task
explicitly asks for analysis/review first.

If the task explicitly asks for analysis, inspection, review, or says not to
modify code, stop after the analysis and do not edit files or create commits.

23. After implementation run:

    gofmt
    go test ./...
    go test -race ./...
    go vet ./...
    git diff --check

Text files must end with a newline.

Review the final diff for unrelated changes.

If tests were added or substantially changed, review them against the proof and
independence requirements in the `# Tests` section before considering the task
complete. Passing commands alone are not sufficient.

24. Commits.

Keep commits focused.

Commit messages must describe the code that is actually in the commit.

Do not leave stale commit-message claims after amending implementation.

25. GitHub.

When the task explicitly requests push:
- push the current working branch unless the task explicitly names another;
- never use plain `--force`;
- use `--force-with-lease` only when history was intentionally amended.

Do not push merely because implementation is complete unless the task requests
it.

26. Architecture cleanup after feature blocks.

After a significant feature block (multiple commits adding new capabilities),
before starting the next major phase, do an architecture cleanup/review:
- duplicate paths/abstractions;
- obsolete compatibility code;
- contract drift between implementation and documentation;
- help/docs drift;
- tests freezing accidental implementation details;
- parallel test helpers and production lifecycle implementations introduced by
  independent work.

Do not require cleanup after every small commit.

Focus on deletion and simplification over new abstractions.
