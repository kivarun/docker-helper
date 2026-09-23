package main

// P3-C2b driver proofs for successful commit permanence and post-commit
// cleanup semantics, driven through the production build driver with the
// existing B2/C1/C2a fixtures: docker tag exit 0 makes the build succeeded
// irrevocably; the best-effort internal-tag cleanup runs exactly once for
// exactly the operation-owned internal tag (success and failure), its
// failure is an internal diagnostic that cannot replace the committed
// result, a termination during the blocked cleanup keeps the cleanup
// running on its fresh bounded context, and a late cancellation after
// success leaves the terminal state and the child history untouched.

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

// TestBuildDriverCommitSuccessCleanupOutcomes proves the successful-commit
// contract: docker tag exit 0 reports succeeded; the best-effort cleanup
// runs exactly once, addressing exactly the operation-owned internal tag
// and never the requested image; a failing cleanup is recorded as an
// internal diagnostic and cannot replace the committed result.
func TestBuildDriverCommitSuccessCleanupOutcomes(t *testing.T) {
	cases := []struct {
		name            string
		rmiExit         int
		wantCleanupDiag bool
	}{
		{name: "successful commit with successful internal-tag cleanup", rmiExit: 0, wantCleanupDiag: false},
		{name: "successful commit with failing internal-tag cleanup", rmiExit: 9, wantCleanupDiag: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, opBuf := setupTestLogging(t)
			app, _, result, _, calls := setupBuildBackendTest(t)
			runner := newBackendChildRunner(t, app, calls)
			if tc.rmiExit != 0 {
				runner.setRmiExitCode(tc.rmiExit)
			}

			op := startBackendBuild(t, app, result.Token, nil)
			select {
			case <-op.done:
			case <-time.After(10 * time.Second):
				t.Fatal("operation did not complete after the commit")
			}

			// The full successful sequence ran: buildctl, load, inspect,
			// tag, and exactly one internal-tag cleanup child.
			if got := calls.count(); got != 5 {
				t.Errorf("children = %d, want exactly 5 (buildctl, load, inspect, tag, one rmi):\n%s", got, calls.all())
			}
			if got := runner.startedImportStages(); !equalStrings(got, []string{"load", "inspect", "tag", "rmi"}) {
				t.Errorf("started import stages = %v, want [load inspect tag rmi]\nall children:\n%s", got, calls.all())
			}
			// The cleanup addressed exactly the operation-owned internal
			// tag; no cleanup command may target the requested image.
			assertInternalTagRmi(t, calls, op.ID)

			op.mu.Lock()
			state, rc := op.State, derefString(op.ResultCode)
			op.mu.Unlock()
			if state != operationSucceeded {
				t.Errorf("state = %v, want succeeded", state)
			}
			if rc != "succeeded" {
				t.Errorf("result_code = %q, want succeeded (the committed result stands)", rc)
			}

			// The cleanup outcome is internal-only: a failing rmi emits the
			// cleanup diagnostic, a succeeding one does not.
			if tc.wantCleanupDiag {
				assertStageDiagnostic(t, opBuf, "cleanup")
			} else {
				assertNoCleanupFailureDiagnostic(t, opBuf)
			}
		})
	}
}

// TestBuildDriverTerminateDuringPostCommitCleanup proves that terminating
// the operation while the post-commit internal-tag cleanup child is running
// cannot unmake the committed build: commitClaimed was set before the
// termination, the latch is set, the blocked cleanup child is released and
// SUCCEEDS on its fresh bounded context (not the terminated operation
// context), and the final operation is succeeded with no additional tag or
// cleanup child. Explicit cancel and daemon shutdown are separate cases.
func TestBuildDriverTerminateDuringPostCommitCleanup(t *testing.T) {
	cases := []struct {
		name      string
		terminate func(t *testing.T, supervisor *operationSupervisor, op *operation) (done func())
	}{
		{
			name: "explicit cancel during post-commit cleanup",
			terminate: func(t *testing.T, supervisor *operationSupervisor, op *operation) (done func()) {
				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					_ = supervisor.cancel(op.ID, nil)
				}()
				return wg.Wait
			},
		},
		{
			name: "daemon shutdown during post-commit cleanup",
			terminate: func(t *testing.T, supervisor *operationSupervisor, op *operation) (done func()) {
				supervisor.beginShutdown()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				supervisor.terminateForShutdown(shutdownCtx, nil)
				cancel()
				return nil
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, supervisor, result, _, calls := setupBuildBackendTest(t)
			runner := newBackendChildRunner(t, app, calls)
			releasePath := runner.setRmiBlocks(t, true)

			op := startBackendBuild(t, app, result.Token, nil)
			// The blocked cleanup child is the newest started child: the
			// commit child started and exited 0 (irrevocable), the
			// post-commit cleanup is running.
			runner.waitChildStartedCount(t, 5)
			if !hasArgvWord(calls.argv(calls.count()-1), "rmi") {
				t.Fatalf("newest child is not the post-commit cleanup child:\n%s", calls.all())
			}
			// The commit admission was claimed BEFORE the termination.
			op.mu.Lock()
			claimed := op.commitClaimed
			op.mu.Unlock()
			if !claimed {
				t.Fatal("commit admission not claimed before termination")
			}

			done := tc.terminate(t, supervisor, op)
			waitTerminationLatched(t, op)

			// Release the blocked cleanup: it continues on its fresh
			// bounded context (the termination cannot suppress it), exits
			// 0, and the committed result stands.
			if err := os.WriteFile(releasePath, []byte("release"), 0o644); err != nil {
				t.Fatalf("cannot release cleanup child: %v", err)
			}
			if done != nil {
				done() // a cancel that waits for convergence joins here
			}
			op.Wait()

			op.mu.Lock()
			state, rc := op.State, derefString(op.ResultCode)
			op.mu.Unlock()
			if state != operationSucceeded {
				t.Errorf("state = %v, want succeeded (the commit is permanent)", state)
			}
			if rc != "succeeded" {
				t.Errorf("result_code = %q, want succeeded", rc)
			}

			// No additional tag or cleanup child: exactly the five
			// children of the successful sequence.
			if got := calls.count(); got != 5 {
				t.Errorf("children = %d, want exactly 5 (no repeated commit or cleanup):\n%s", got, calls.all())
			}
			if got := runner.startedImportStages(); !equalStrings(got, []string{"load", "inspect", "tag", "rmi"}) {
				t.Errorf("started import stages = %v, want [load inspect tag rmi]\nall children:\n%s", got, calls.all())
			}
			assertInternalTagRmi(t, calls, op.ID)
		})
	}
}

// TestBuildDriverLateCancelAfterSuccessPreservesResult proves terminal
// permanence: after the operation succeeded, a late cancellation is
// refused (already terminal), the terminal state (State, ResultCode,
// ExitCode, CompletedAt) is unchanged, and no commit or cleanup child runs
// again.
func TestBuildDriverLateCancelAfterSuccessPreservesResult(t *testing.T) {
	app, supervisor, result, _, calls := setupBuildBackendTest(t)
	newBackendChildRunner(t, app, calls)

	op := startBackendBuild(t, app, result.Token, nil)
	select {
	case <-op.done:
	case <-time.After(10 * time.Second):
		t.Fatal("operation did not complete")
	}

	op.mu.Lock()
	state, rc := op.State, derefString(op.ResultCode)
	completed := *op.CompletedAt
	op.mu.Unlock()
	if state != operationSucceeded || rc != "succeeded" {
		t.Fatalf("precondition: state=%v rc=%q, want succeeded", state, rc)
	}
	if op.ExitCode != nil {
		t.Fatalf("precondition: exit_code = %v, want nil for a succeeded build", op.ExitCode)
	}
	childrenBefore := calls.count()

	if err := supervisor.cancel(op.ID, nil); !errors.Is(err, ErrOperationAlreadyTerminal) {
		t.Fatalf("late cancel = %v, want ErrOperationAlreadyTerminal", err)
	}

	// The terminal state is unchanged and nothing ran again.
	op.mu.Lock()
	state, rc = op.State, derefString(op.ResultCode)
	op.mu.Unlock()
	if state != operationSucceeded || rc != "succeeded" {
		t.Errorf("state=%v rc=%q after late cancel, want succeeded unchanged", state, rc)
	}
	if op.ExitCode != nil {
		t.Errorf("exit_code = %v after late cancel, want nil", op.ExitCode)
	}
	op.mu.Lock()
	completedAfter := *op.CompletedAt
	op.mu.Unlock()
	if !completedAfter.Equal(completed) {
		t.Errorf("CompletedAt changed after late cancel: %v -> %v", completed, completedAfter)
	}
	if got := calls.count(); got != childrenBefore {
		t.Errorf("children = %d after late cancel, want unchanged %d (no repeated commit or cleanup):\n%s", got, childrenBefore, calls.all())
	}
	assertInternalTagRmi(t, calls, op.ID)
}
