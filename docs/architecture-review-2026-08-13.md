# Architecture review — 2026-08-13

Reviewed revision: `a2dfb625fa3678e53426d00fc184ca5c6c61afc1`

## Summary

The Release 2 multi-user ownership and authentication model is coherent and
does not require a redesign. Principal identity, UID/GID, and allowed roots
are resolved server-side. Launcher credentials are principal-scoped, foreign
sessions are not exposed, and the Unix and loopback HTTP listeners share the
same API and authentication path.

No confirmed cross-principal authorization bypass was found.

Before Phase 8, the project should address one direct Docker argument
injection vulnerability and make an explicit security decision about the
filesystem path time-of-check/time-of-use gap.

## Findings

### P0 — Docker option injection through `POST /run`

`handleRun` only verifies that `runRequest.Image` is non-empty. The value is
then appended to the `docker run` argument list immediately before the
request's command:

```go
args = append(args, req.Image)
args = append(args, req.Command...)
```

A direct API client can submit an image value such as:

```json
{
  "image": "--mount=type=bind,source=/,target=/host",
  "command": ["attacker/image", "command"]
}
```

Docker interprets the `image` value as another `docker run` option and the
first command element as the actual image. This bypasses docker-helper's bind
mount source validation and therefore violates the primary host filesystem
boundary.

Required change:

- reject image values beginning with `-` on the server before audit emission,
  Docker-directory creation, or operation registration;
- add a direct API regression test that expects `400 invalid_image` and
  verifies that Docker is not invoked;
- apply consistent identifier validation to pull and registry login, although
  those call sites do not currently provide the same complete policy bypass.

Relevant code: `run.go`, `api_contract.go`, `pull.go`, `registry.go`.

### P1 — Path validation has a TOCTOU gap

`resolveMount` and `validateBuildRequest` resolve symlinks and verify
containment, but later pass the validated pathname to Docker as a string. A
workspace owner can rename the validated object and replace it with a symlink
after validation but before Docker traverses the path.

`filepath.EvalSymlinks` prevents a static symlink escape. It does not bind the
subsequent Docker operation to the inode that was validated.

This needs a separate security design decision rather than a superficial
validation helper. Possible work includes evaluating inode-pinned or
helper-owned mounts using appropriate Linux APIs. If a robust mechanism is not
implemented, the documentation and threat model must state the remaining race
explicitly.

Phase 8 system packaging should not proceed without recording that decision.

Relevant code: `run.go:resolveMount`, `build.go:validateBuildRequest`.

### P2 — Pull audit lifecycle can remain incomplete

`handlePull` writes `pull.start` before calling `ensureSessionDockerDir`. If
directory creation fails, the handler returns `500` without a matching
`pull.finish` event.

Build and run already perform this preflight step before registering an
operation or emitting their start event.

Required change:

- move `ensureSessionDockerDir` before `pull.start`;
- add a test equivalent to the existing build/run Docker-directory failure
  tests, asserting `500`, no Docker invocation, and no `pull.start` event.

Relevant code: `pull.go`, `docker_dir_test.go`, `pull_audit_test.go`.

### P2 — Obsolete single-listener lifecycle remains in production code

Production startup uses `prepareListeners` and `serveWithShutdownMulti`.
`prepareListener` and the substantial `serveWithShutdown` implementation in
`main.go` are retained only by tests.

The old tests contain useful lifecycle coverage, but they currently preserve
a dead implementation path.

Required change:

- port the behavioral tests to `serveWithShutdownMulti` with a nil TCP
  listener where appropriate;
- delete `serveWithShutdown` and the obsolete `prepareListener` wrapper;
- do not introduce another abstraction merely to retain both paths.

Relevant code: `main.go`, `serve_test.go`, `serve_error_test.go`, `listener.go`.

### P2 — Principal and credential CLI duplicates API client behavior

`principal_cli.go` contains repeated implementations of the same sequence for
seven commands: resolve client, marshal request, perform authenticated
request, read response, check status, parse API error, and unmarshal JSON.
`apiClient.readResponseBody` already owns this response contract for other
commands.

There is also a status switch in principal creation where every branch returns
the same exit code.

Required change:

- add focused principal and credential methods to `apiClient`;
- reuse `readResponseBody` and keep only presentation logic in the CLI;
- escape usernames used in URL paths with `url.PathEscape`;
- remove the redundant status switch.

Relevant code: `principal_cli.go`, `client.go`, `operator_client.go`.

### P3 — Dead and test-only compatibility surface

The following internal elements have no production caller or are retained only
by tests:

- `adminAPIPaths`;
- `adminAPITokenSource` and `readAdminTokenPlain` compatibility paths;
- `validateNoDeprecatedFields`;
- `operationRegistry.remove` and `operationRegistry.isShuttingDown`;
- `scanSession` after production moved to `scanSessionWithPrincipal`;
- `isErrInvalidCredentialName` and several trivial `errors.Is` wrappers;
- `ErrInternal`, which is never returned by build validation;
- the URL parsing fallback in `operationIDFromRequest`, retained for direct
  handler tests rather than real mux behavior;
- test-only logging reset helpers that can live in test code.

These should be removed together with tests that claim backward compatibility
for unexported internal functions. Handler tests should exercise the real
`ServeMux` contract where path values matter.

### P3 — Operation cleanup is unnecessarily complex

`operationRegistry.cleanup` holds the registry lock, repeatedly locks
individual operations, and uses a handwritten quadratic sort. The default
completed-operation limit is 200, so this is not a current performance defect,
but it makes lifecycle code harder to reason about.

Required change:

- snapshot immutable completed-operation timestamps once;
- use `sort.Slice` on the snapshot;
- perform TTL and count deletion from that snapshot;
- remove the unused `remove` method.

Relevant code: `operation.go`.

### P3 — Configuration metadata can drift

The `writableFields` test list omits `http_address`, even though set/unset and
help support it. Multiple manual field lists and switches make the test appear
more authoritative than it is.

Required change: use one authoritative registry for writable config fields,
their validation, reload/restart behavior, and help coverage, without building
a generic configuration framework.

Relevant code: `config_cli.go`, `config_cli_test.go`.

### P3 — Test suite contains synthetic and compatibility-preserving tests

Current size:

- production Go: 10,083 lines;
- test Go: 37,226 lines;
- top-level `Test...` functions: 996;
- `t.Run` calls: 38.

The ratio alone is not a defect, and security boundary coverage should not be
removed indiscriminately. Confirmed low-value cases include:

- `TestCredentialIDRandomFailure`, which states that it cannot induce a random
  failure and only repeats successful-format assertions;
- backward-compatibility tests for unexported, obsolete token helpers;
- direct-handler tests that force a production URL parsing fallback;
- writable-field help coverage that omits a real writable field;
- old shutdown tests attached to the dead single-listener implementation.

Consolidation should target duplicated setup and transport cases while
preserving distinct policy, authorization, race, and lifecycle assertions.

## Documentation drift

The following statements should be corrected as part of the corresponding
changes:

- `docs/architecture.md` states that `EvalSymlinks` prevents symlink-based
  escape attacks and that an agent cannot escalate beyond the workspace. Those
  claims omit the TOCTOU window and are currently too strong.
- README, architecture, and roadmap say that session and credential token
  comparisons are constant-time. In the implementation they are SHA-256 hashed
  and looked up through indexed SQL equality. `ConstantTimeCompare` is used for
  the admin token. This is a contract-accuracy issue, not a practical token
  recovery vulnerability for the high-entropy tokens used here.
- `docs/release-2-plan.md` contains two conflicting Phase 4–8 numbering schemes.
- The human-readable admin session table omits the principal even though the
  JSON response contains it.

## Architecture that should be preserved

- Principal identity, UID/GID, home, and allowed roots are server-controlled.
- Launcher credentials can create, list, and delete only sessions owned by
  their principal; foreign sessions are not disclosed.
- Unix and loopback HTTP listeners share one mux, API, authentication model,
  and authorization boundary.
- Issued sessions intentionally remain valid after credential revocation,
  principal disablement, or later allowed-root changes.
- User and system deployment modes remain supported.
- Trusted CA handling and session-specific Docker configuration are isolated
  appropriately.
- The current package size does not justify an artificial package split.

## Recommended order

1. Fix `POST /run` image option injection in an isolated security commit.
2. Record and resolve the filesystem TOCTOU security decision before Phase 8.
3. Repair the pull audit preflight ordering.
4. Remove the obsolete single-listener and test-only compatibility paths while
   porting useful tests.
5. Consolidate principal/credential API client handling and simplify operation
   cleanup.
6. Remove confirmed synthetic tests and synchronize documentation.

## Verification baseline

At the reviewed revision:

- the working tree was clean;
- `git diff --check` passed;
- all shell scripts passed `bash -n`;
- the current GitHub CI run was green, including formatting, tests, race tests,
  and vet;
- Go was not available in the local review environment, so the Go checks were
  verified through CI rather than rerun locally.
