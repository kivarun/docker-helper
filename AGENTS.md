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

7. Keep the current release direction explicit.

Release 2 is the server-side / remote execution release. Do not treat remote
execution as hypothetical future work or move it back out of scope unless the
task explicitly changes the roadmap.

For Release 2 development, preserve these direction constraints:
- a remote session must not require a client-side workspace path;
- remote build accepts a client-provided build context as uploaded/streamed
  data and executes the build on the remote Docker daemon;
- build results and cache remain on that helper unless explicitly pushed or
  exported;
- remote run is image-based and must work without a client workspace or
  client-side bind mounts;
- remote sessions may use build, run, pull/registry authentication, and the
  existing operation status/logs/cancel lifecycle; do not restrict them to
  build-only operation semantics;
- multiple simultaneous sessions/agents must remain possible;
- future optional control-plane integration must remain possible without
  becoming a mandatory runtime dependency.

Do not predesign mutable remote workspace synchronization, helper routing,
helper-to-helper forwarding, or generic orchestration unless a concrete task
brings one of those capabilities into scope.

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

# Filesystem policy

10. Preserve canonical-path invariants without inventing a workspace where none exists.

For workspace-backed sessions, the session workspace is canonicalized when the
session is created.

Mount/build path validation for workspace-backed operations must enforce
containment after symlink resolution.

Do not duplicate path policy across handlers when an existing invariant already
guarantees it.

Do not weaken symlink-escape protection.

Remote workspace-free sessions are different by design:
- do not require or synthesize a client workspace merely to reuse local-session
  validation paths;
- remote run must not accept client host paths or client-side bind mounts;
- a remote build context is uploaded data, not a claim about a path on the
  client or server filesystem, and must be staged/validated according to the
  remote build-context contract rather than local workspace containment.

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

12. Tests should protect behavior, not implementation accidents.

Keep:
- regression tests for real past bugs;
- error-contract tests;
- security boundary tests;
- audit leak tests;
- CLI black-box behavior tests.

Avoid tests whose only purpose is freezing an unnecessary implementation
detail.

13. Tests must exercise the production path.

Do not make a test pass by reimplementing the production behavior inside the
test, a fake, or a test-only helper.

In particular, do not create a second implementation of:
- operation lifecycle/state transitions;
- log buffering or incremental log reads;
- cleanup/termination behavior;
- path validation/canonicalization;
- authentication/authorization decisions;
- request/response semantics.

A fake or seam may replace an external dependency, but the production code
under test must still own the semantics being asserted.

When a test needs readiness or synchronization, observe a real state transition,
process state, channel, callback, or other deterministic signal. Do not use an
arbitrary `time.Sleep` as synchronization or assume that a fixed delay proves
readiness.

When stabilizing a flaky test, first determine whether the test has a timing
assumption or bypasses the real lifecycle. Do not change production behavior,
API contracts, validation, authentication, audit behavior, or 4xx/5xx semantics
merely to make such a test pass unless the production behavior is independently
shown to be wrong.

14. Do not build a test framework.

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

15. Be careful with global state.

Before adding `t.Parallel()`, inspect whether the test touches package-global
state such as logging/test seams.

Do not assume a test is parallel-safe just because it uses `t.Setenv`.

# Parallel implementation avoidance

16. One production mechanism per responsibility.

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

When integrating work produced in parallel by multiple agents/contributors,
review specifically for:
- duplicate helpers with overlapping purpose;
- old and new lifecycle paths coexisting;
- one caller bypassing a shared client or policy layer;
- slightly different validation/auth/error/audit behavior for the same action;
- test-only abstractions that duplicate production semantics.

Do not preserve both implementations for convenience. Consolidate on one owner
unless compatibility requires otherwise.

# Documentation ownership

17. Keep documentation roles distinct.

`README.md` owns:
- project introduction;
- quick start;
- common operator workflows;
- concise command examples.

`docs/architecture.md` owns:
- detailed architecture;
- trust/security model;
- lifecycle semantics;
- detailed API/CLI behavior;
- design decisions and future work.

`.claude/skills/docker-helper/SKILL.md` owns:
- canonical reusable instructions for agents USING docker-helper.

`AGENTS.md` owns:
- instructions for agents DEVELOPING docker-helper.

Do not duplicate large reference sections between documents.
Prefer links to the canonical owner.

# Versioning

18. Version ownership.

Source default:

    var version = "dev"

Development builds must work with plain `go build`.

Official release versions are injected through ldflags from the release version
source/tag.

Do not manually maintain a release number in source code.

# Change procedure

19. Before implementation.

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

20. After implementation run:

    gofmt
    go test ./...
    go test -race ./...
    go vet ./...
    git diff --check

Text files must end with a newline.

Operational policy values must be configurable and have documented
reasonable defaults when operators reasonably need to tune them.

This applies to values such as:
- timeouts;
- retention periods;
- resource/count limits;
- log/output size limits.

It does NOT mean every implementation constant belongs in configuration.

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

Review the final diff for unrelated changes.

21. Commits.

Keep commits focused.

Commit messages must describe the code that is actually in the commit.

Do not leave stale commit-message claims after amending implementation.

22. GitHub.

When the task explicitly requests push:
- push to the existing `github` remote;
- use current `main` unless instructed otherwise;
- never use plain `--force`;
- use `--force-with-lease` only when history was intentionally amended.

Do not push merely because implementation is complete unless the task requests
it.

23. Architecture cleanup after feature blocks.

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

24. shm_size 2 GiB limit.

The POST /run `shm_size` maximum of 2 GiB is a deliberate Release 1
limit. Whether it becomes configurable in a later release is not committed.
