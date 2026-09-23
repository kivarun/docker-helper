package main

// P3-C1 driver proofs for the image-handoff failure and internal-tag
// cleanup contract, driven through the production build driver: a nonzero
// docker load, an explicit cancel during load, a daemon shutdown during
// load, a failed internal-tag verification, and a failed best-effort
// internal-tag cleanup each keep the requested image untouched (no tag
// child on failed or pre-commit terminated paths), remove exactly the
// operation-owned internal tag, and log cleanup errors without replacing
// the original failure. The successful STOP -> load -> inspect -> tag
// ordering is already proven by the B2 tests; these proofs reuse the same
// fixtures.

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// assertInternalTagRmi proves every recorded internal-tag cleanup child is
// exactly `docker rmi docker-helper-build/<opID>` — the one
// operation-owned internal tag, never the requested image.
func assertInternalTagRmi(t *testing.T, calls *recordedCalls, opID string) {
	t.Helper()
	found := false
	for i := 0; i < calls.count(); i++ {
		args := calls.argv(i)
		if !hasArgvWord(args, "rmi") {
			continue
		}
		found = true
		if len(args) != 2 || args[0] != "rmi" || args[1] != buildInternalTag(opID) {
			t.Errorf("rmi argv = %q, want exactly [rmi %s] (the requested image must not be touched)", args, buildInternalTag(opID))
		}
	}
	if !found {
		t.Fatal("no internal-tag cleanup child ran")
	}
}

// assertNoCleanupFailureDiagnostic proves no cleanup FAILURE diagnostic
// exists in the operational log (the best-effort rmi succeeded; the failure
// record is emitted only on error).
func assertNoCleanupFailureDiagnostic(t *testing.T, opBuf *bytes.Buffer) {
	t.Helper()
	for _, rec := range strings.Split(opBuf.String(), "\n") {
		if strings.Contains(rec, "build stage failed") && strings.Contains(rec, `"stage":"cleanup"`) {
			t.Errorf("unexpected cleanup failure diagnostic:\n%s", rec)
		}
	}
}

// TestBuildDriverImportFailureCleansInternalTag proves the image-handoff
// failure contract: a nonzero docker load and a failed internal-tag
// verification fail the build with docker_build_failed and no tag child
// (the requested image stays untouched); the failing child stage's exit
// code is preserved; a failed best-effort cleanup after an earlier failure
// is logged without replacing the original failure or its exit code; every
// cleanup removes exactly the operation-owned internal tag.
func TestBuildDriverImportFailureCleansInternalTag(t *testing.T) {
	cases := []struct {
		name            string
		loadExit        int
		inspectExit     int
		rmiExit         int
		wantStarted     []string
		wantFailedStage string
		wantCleanupDiag bool
		wantExitCode    int
	}{
		{
			name:            "load nonzero fails and cleans the internal tag",
			loadExit:        7,
			wantStarted:     []string{"load", "rmi"},
			wantFailedStage: "image_import",
			wantExitCode:    7,
		},
		{
			name:            "load ok but internal tag verification fails",
			inspectExit:     3,
			wantStarted:     []string{"load", "inspect", "rmi"},
			wantFailedStage: "image_import_verification",
			wantExitCode:    3,
		},
		{
			name:            "cleanup failure after an earlier failure is logged without replacing it",
			loadExit:        7,
			rmiExit:         5,
			wantStarted:     []string{"load", "rmi"},
			wantFailedStage: "image_import",
			wantCleanupDiag: true,
			wantExitCode:    7,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, opBuf := setupTestLogging(t)
			app, _, result, _, calls := setupBuildBackendTest(t)
			runner := newBackendChildRunner(t, app, calls)
			if tc.loadExit != 0 {
				runner.setLoadExitCode(tc.loadExit)
			}
			if tc.inspectExit != 0 {
				runner.setInspectExitCode(tc.inspectExit)
			}
			if tc.rmiExit != 0 {
				runner.setRmiExitCode(tc.rmiExit)
			}

			op := startBackendBuild(t, app, result.Token, nil)
			select {
			case <-op.done:
			case <-time.After(10 * time.Second):
				t.Fatal("operation did not complete after the import failure")
			}

			// Started handoff children: the failed stage ran, no tag child
			// process started, and the best-effort internal-tag cleanup ran.
			if got := runner.startedImportStages(); !equalStrings(got, tc.wantStarted) {
				t.Errorf("started import stages = %v, want %v\nall children:\n%s", got, tc.wantStarted, calls.all())
			}
			// The requested image is untouched: no tag child was even
			// constructed on a failed import path.
			if got := runner.constructIndexOfImportStage("tag"); got != -1 {
				t.Errorf("tag child constructed on a failed import path (index %d):\n%s", got, calls.all())
			}
			// The cleanup addressed exactly the operation-owned internal tag.
			assertInternalTagRmi(t, calls, op.ID)

			op.mu.Lock()
			state, rc, exitCode := op.State, derefString(op.ResultCode), op.ExitCode
			op.mu.Unlock()
			if state != operationFailed {
				t.Errorf("state = %v, want failed", state)
			}
			if rc != "docker_build_failed" {
				t.Errorf("result_code = %q, want docker_build_failed (unchanged by the cleanup outcome)", rc)
			}
			if exitCode == nil || *exitCode != tc.wantExitCode {
				t.Errorf("exit_code = %v, want %d (the failing child's exit code)", exitCode, tc.wantExitCode)
			}

			assertStageDiagnostic(t, opBuf, tc.wantFailedStage)
			if tc.wantCleanupDiag {
				assertStageDiagnostic(t, opBuf, "cleanup")
			} else {
				assertNoCleanupFailureDiagnostic(t, opBuf)
			}
		})
	}
}

// TestBuildDriverTerminateDuringLoadCleansInternalTag proves the pre-commit
// termination contract while the load child is running: explicit cancel and
// daemon shutdown terminate the load child, keep their classification
// (cancelled vs the kind-specific docker_build_failed), and still run the
// best-effort internal-tag cleanup on a fresh bounded context — the
// termination latch suppresses the tag stage, never the cleanup, and the
// requested image stays untouched.
func TestBuildDriverTerminateDuringLoadCleansInternalTag(t *testing.T) {
	cases := []struct {
		name      string
		terminate func(t *testing.T, supervisor *operationSupervisor, op *operation)
		wantRC    string
	}{
		{
			name: "explicit cancel during load",
			terminate: func(t *testing.T, supervisor *operationSupervisor, op *operation) {
				if err := supervisor.cancel(op.ID, nil); err != nil {
					t.Fatalf("cancel: %v", err)
				}
			},
			wantRC: resultCancelled,
		},
		{
			name: "shutdown during load",
			terminate: func(t *testing.T, supervisor *operationSupervisor, op *operation) {
				supervisor.beginShutdown()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				supervisor.terminateForShutdown(shutdownCtx, nil)
				cancel()
			},
			wantRC: "docker_build_failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, opBuf := setupTestLogging(t)
			app, supervisor, result, _, calls := setupBuildBackendTest(t)
			runner := newBackendChildRunner(t, app, calls)
			runner.setLoadBlocks(true)

			op := startBackendBuild(t, app, result.Token, nil)
			runner.waitChildStartedCount(t, 2)
			if !hasArgvWord(calls.argv(calls.count()-1), "load") {
				t.Fatalf("newest child is not the blocking load child:\n%s", calls.all())
			}

			tc.terminate(t, supervisor, op)
			op.Wait()

			op.mu.Lock()
			latched, state, rc := op.terminationRequested, op.State, derefString(op.ResultCode)
			op.mu.Unlock()
			if !latched {
				t.Error("termination latch not set")
			}

			// The terminated load stage is followed only by the best-effort
			// cleanup; no tag child exists (not even constructed).
			if got := runner.startedImportStages(); !equalStrings(got, []string{"load", "rmi"}) {
				t.Errorf("started import stages = %v, want [load rmi]\nall children:\n%s", got, calls.all())
			}
			if got := runner.constructIndexOfImportStage("tag"); got != -1 {
				t.Errorf("tag child constructed after termination (index %d):\n%s", got, calls.all())
			}

			// The cleanup ran on a FRESH bounded context despite the latch:
			// the rmi child actually started and succeeded — a command bound
			// to the terminated operation context would refuse to start.
			assertInternalTagRmi(t, calls, op.ID)
			assertNoCleanupFailureDiagnostic(t, opBuf)

			if state != operationFailed {
				t.Errorf("state = %v, want failed", state)
			}
			if rc != tc.wantRC {
				t.Errorf("result_code = %q, want %q", rc, tc.wantRC)
			}
		})
	}
}
