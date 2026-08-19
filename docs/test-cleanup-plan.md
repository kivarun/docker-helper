# Test Cleanup Plan

## Objective

Remove dead code, fix broken tests, consolidate duplicates, and improve test
quality across the test suite.

## Phase 1: Dead Code Removal

**Commit message:** `test: remove dead code and stdlib reimplementations`

### 1.1. `makeBlockingCmd` — dead helper

**File:** `shutdown_helpers_test.go:139-147`

**Problem:** Function defined but never called anywhere in the test suite.
Likely intended for a test that was never written or was removed.

**Action:** Delete the function and its comment block (lines 139-147).

### 1.2. `contains()` / `indexOf()` — stdlib reimplementations

**File:** `workspace_root_test.go:202-214`

**Problem:** Two helper functions that reimplement `strings.Contains` and
`strings.Index` with more complex logic. The `contains` function has a
buggy implementation: `len(s) >= len(substr)` check is redundant, and the
logic `(s == substr || len(substr) == 0 || ...)` is convoluted.

**Action:** Replace call sites with `strings.Contains` / `strings.Index`.
Delete the helper functions.

Call sites to update:
- `workspace_root_test.go` — search for `contains(` and `indexOf(` calls.

### 1.3. `fileExists()` — stdlib reimplementations

**File:** `serve_test.go:673`

**Problem:** Helper that reimplements `os.Stat` error checking.

**Action:** Replace call sites with direct `os.Stat` calls. Delete the helper.

---

## Phase 2: Fix Broken Tests

**Commit message:** `test: fix broken assertions in audit and error contract tests`

### 2.1. `TestAuditNoContainerOutput` — vacuous truth

**File:** `audit_test.go:447-495`

**Problem:** The test name claims to verify that container output is excluded
from audit records. However, the mock command is `/bin/true`, which produces
no output at all. The constant `containerOutput` is defined but never actually
generated. The assertion `!strings.Contains(string(raw), containerOutput)` is
a vacuous truth — the string was never produced, so it can never appear in
audit. The test cannot distinguish between "output is correctly filtered" and
"no output was ever generated".

**Fix:** Replace `/bin/true` with a command that actually produces output:
```go
app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
    return exec.CommandContext(ctx, "/bin/sh", "-c", "echo '"+containerOutput+"'")
}
```

This makes the assertion meaningful: the output IS produced by the process
but is correctly excluded from audit records.

### 2.2. `TestDockerErrorLogPull` — assertion ordering

**File:** `error_contract_test.go:720-777`

**Problem:** The negative assertions about operational logs (lines 748, 752,
756) appear BEFORE the response code check at line 765
(`w.Code != http.StatusInternalServerError`). If the handler returned a
different status code (e.g., 200 for some reason), the test would still check
the logs without first proving the error path was reached.

**Fix:** Move the response code assertions (lines 761-776) to immediately
follow the handler invocation (line 742), before the log assertions. This
ensures the test first proves it reached the intended error path before
asserting on the log output.

---

## Phase 3a: Consolidate Driver Wrappers

**Commit message:** `test: consolidate failExecDriver and failQueryDriver into generic failDriver`

### 3.1. Merge `failExecDriver` + `failQueryDriver`

**Files:** `session_audit_test.go:27-60`, `auth_audit_test.go:25-56`

**Problem:** Two nearly identical driver wrapper implementations for fault
injection:
- `failExecDriver`/`failExecConn` — wraps ExecContext to fail
- `failQueryDriver`/`failQueryConn` — wraps QueryContext to fail

Both share the same structure: `Open()` opens a real SQLite connection,
wraps it in a conn that fails a specific method. The only difference is
which method (ExecContext vs QueryContext) and which interface check
(ExecerContext vs QueryerContext).

**Fix:** Create a single generic `failDriver` with configurable fail modes:
```go
type failDriver struct {
    failExec error // non-nil → ExecContext returns this error
    failQuery error // non-nil → QueryContext returns this error
}
```

The `failConn` implements both `ExecContext` and `QueryContext`, checking
which mode is configured. Both `newFailExecDB` and `newFailQueryDB` become
thin wrappers that set the appropriate flag.

**Call sites to update:**
- `session_audit_test.go` — `newFailExecDB` callers
- `auth_audit_test.go` — `newFailQueryDB` callers

---

## Phase 3b: Remove Duplicate Tests

**Commit message:** `test: remove duplicate tests, consolidate into table-driven`

### 3.2. `TestCleanupExpiredSessionsDeletesExpired` — subsumed

**File:** `session_test.go:438-489`

**Problem:** Tests that expired sessions are deleted and active sessions
remain. This is already covered by `TestCleanupExpiredSessions` (line 365),
which tests the same invariants PLUS the boundary case.

**Action:** Delete the entire test function.

### 3.3. `TestCleanupExpiredSessionsBoundaryEqualsNow` — subsumed

**File:** `session_test.go:491-515`

**Problem:** Tests the boundary case (expires_at == now). This is already
covered by `TestCleanupExpiredSessions` (line 365), which inserts a session
with `expires_at == now` and verifies it is deleted.

**Action:** Delete the entire test function.

### 3.4. `TestPullDockerArgsUnchanged` — cross-file duplicate

**File:** `pull_audit_test.go:221-259`

**Problem:** Structurally nearly identical to `TestPullDockerArgs` in
`pull_test.go:424-462`. Both verify that Docker pull receives the correct
`--config` and `pull` arguments. The only differences are the request
construction method and that the audit version calls
`setupTestLoggingDiscard`.

**Action:** Delete `TestPullDockerArgsUnchanged`. The production path is the
same; `TestPullDockerArgs` already covers the invariant.

### 3.5. `TestValidateShmSizeZero` + `TestValidateShmSizeZeroWithUnit` — table-driven

**File:** `shm_size_test.go:102-114`

**Problem:** Two separate tests for the same invariant (zero shm_size is
rejected) with only the input differing (`"0"` vs `"0m"`).

**Fix:** Merge into a single table-driven test:
```go
func TestValidateShmSizeZero(t *testing.T) {
    for _, tc := range []struct {
        input string
    }{
        {"0"},
        {"0m"},
    } {
        t.Run(tc.input, func(t *testing.T) {
            _, err := validateShmSize(tc.input)
            if err == nil {
                t.Errorf("expected error for %q", tc.input)
            }
        })
    }
}
```

---

## Phase 5: Low Priority Improvements

**Commit message:** `test: strengthen weak tests with assertions and deterministic signals`

### 5.1. `TestCleanupConcurrency` — add assertions

**File:** `operation_cleanup_test.go:104-154`

**Problem:** The test has no assertions at all. It relies entirely on
`go test -race` to detect issues. The 100ms sleep is arbitrary and provides
no guarantee that the spawner and cleaner goroutines have actually interacted.
The test would pass even if `cleanup()` were a no-op.

**Fix:** Add assertions after `wg.Wait()`:
1. Query the registry for completed operations
2. Verify that some completed operations were actually cleaned up
3. Replace `time.Sleep(100ms)` with a deterministic signal: use a counter
   that the cleaner increments, and wait for it to reach a threshold

### 5.2. `TestReloadConcurrent` — rename + add proof

**File:** `reload_test.go` (find the test function)

**Problem:** The test name claims "concurrent reload is safe" but only
verifies no panic/deadlock occurred during 500ms. It does not verify that
reloads were applied correctly, that audit records were written, or that the
config was updated.

**Fix:**
1. Rename to `TestReloadNoPanicUnderConcurrentLoad`
2. Add proof that the goroutines actually executed: use atomic counters for
   logging, audit writes, and reloads; verify counters are > 0 after
   `wg.Wait()`

### 5.3. `TestSignalNoOrphanGoroutine` — deterministic signal

**File:** `agent_cli_test.go` (find the test function, ~line 1069)

**Problem:** The 200ms sleep is described as "giving a moment for any orphan
goroutine to make a request." This is an arbitrary timeout that does not
guarantee the goroutine has exited. If the goroutine takes slightly longer
than 200ms to make its next request, the test would pass falsely.

**Fix:** Replace `time.Sleep(200ms)` with a deterministic signal:
1. Use a channel that the HTTP handler closes when it receives a request
2. Set a reasonable timeout (e.g., 2s) on the channel
3. If the channel fires within the timeout, the test fails (orphan request
   detected)
4. If the timeout expires without a request, the test passes

---

## Deferred (Phase 4 — App Init Consolidation)

**COMPLETED** — `7630582`

- `newTestApp` moved from `session_test.go` → `test_helpers_test.go`
- `newTestAppWithAuth`, `withAuth`, `testAdminToken` moved from
  `admin_auth_test.go` → `test_helpers_test.go`
- `setupReloadApp` remains in `logging_audit_correctness_test.go`
  (serves a different purpose: file-based config loading for reload tests)

---

## Verification

After each phase:
1. `gofmt -l -s -w` on modified files
2. `go test -race -count=1 ./...`
3. `go vet ./...`
4. `git diff --check`
