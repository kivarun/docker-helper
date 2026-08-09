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

7. Keep future deployment options open.

Current changes should not unnecessarily prevent:
- remote/server-side use;
- multiple simultaneous sessions/agents;
- optional future control-plane integration.

But DO NOT design APIs for those future systems until they are actually being
implemented.

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
- Authorization headers;
- secret environment values

through:
- operational logs;
- audit logs;
- CLI stderr;
- API error messages.

Preserve existing masking/redaction behavior.

# Filesystem policy

10. Preserve canonical-path invariants.

Session workspace is canonicalized when the session is created.

Mount/build path validation must enforce containment after symlink resolution.

Do not duplicate path policy across handlers when an existing invariant already
guarantees it.

Do not weaken symlink-escape protection.

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

13. Do not build a test framework.

Extract helpers when setup/behavior is genuinely identical across several
tests.

Do not combine fixtures from different domains merely because they share a few
filesystem operations.

Avoid:
- boolean-heavy setup helpers;
- generic builders with many optional fields;
- assertion DSLs.

Explicit setup is preferable when the test is intentionally exceptional.

Use `t.Setenv` for test-scoped environment changes.

Check errors from fixture setup operations.

14. Be careful with global state.

Before adding `t.Parallel()`, inspect whether the test touches package-global
state such as logging/test seams.

Do not assume a test is parallel-safe just because it uses `t.Setenv`.

# Documentation ownership

15. Keep documentation roles distinct.

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

`docs/agent-instructions.md` owns:
- instructions for agents USING docker-helper.

`AGENTS.md` owns:
- instructions for agents DEVELOPING docker-helper.

Do not duplicate large reference sections between documents.
Prefer links to the canonical owner.

# Versioning

16. Version ownership.

Source default:

    var version = "dev"

Development builds must work with plain `go build`.

Official release versions are injected through ldflags from the release version
source/tag.

Do not manually maintain a release number in source code.

# Change procedure

17. Before implementation.

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

18. After implementation run:

    gofmt
    go test ./...
    go test -race ./...
    go vet ./...
    git diff --check

Text files must end with a newline.

Operational policy values must be configurable and have documented
reasonable defaults.

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

Review the final diff for unrelated changes.

19. Commits.

Keep commits focused.

Commit messages must describe the code that is actually in the commit.

Do not leave stale commit-message claims after amending implementation.

20. GitHub.

When the task explicitly requests push:
- push to the existing `github` remote;
- use current `main` unless instructed otherwise;
- never use plain `--force`;
- use `--force-with-lease` only when history was intentionally amended.

Do not push merely because implementation is complete unless the task requests
it.
