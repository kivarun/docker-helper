package main

// P3-C2a driver proofs for the cancellation / commit-admission boundary,
// driven through the production build driver and the ONE §16 commit-stage
// admission primitive: a termination latched during the admitted
// internal-tag verification child stage signals that child and suppresses
// the commit stage entirely (the tag command is never even constructed),
// while a termination after the commit boundary leaves the commit outcome
// in charge (a killed tag child is docker_build_failed, never cancelled).
// The separate atomic commit-admission orderings are proven by
// TestOperationCommitAdmissionTerminationOrderings. C2b owns successful
// post-commit result permanence; the successful ordering is already proven
// by B2.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// waitTerminationLatched waits bounded for the permanent termination latch.
func waitTerminationLatched(t *testing.T, op *operation) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		op.mu.Lock()
		latched := op.terminationRequested
		op.mu.Unlock()
		if latched {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("termination latch not observed")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestBuildDriverTerminateDuringVerificationCleansInternalTag proves the
// pre-commit termination contract over the cancellable internal-tag
// verification child stage: with the admitted inspect child blocked after
// a successful load, an explicit cancel or a daemon shutdown latches the
// termination in the same critical section that signals the admitted
// child. The child is reaped by the driver's own Wait owner with the
// release file never written (only the signal could have ended the blocked
// child), the current execution-stage slot is cleared, the commit stage is
// suppressed (the tag command is never even constructed), and the
// best-effort internal-tag cleanup still removes exactly the
// operation-owned internal tag on a fresh bounded context. Explicit cancel
// reports cancelled; shutdown keeps the kind-specific docker_build_failed.
func TestBuildDriverTerminateDuringVerificationCleansInternalTag(t *testing.T) {
	cases := []struct {
		name      string
		terminate func(t *testing.T, supervisor *operationSupervisor, op *operation)
		wantRC    string
	}{
		{
			name: "explicit cancel during the admitted verification child",
			terminate: func(t *testing.T, supervisor *operationSupervisor, op *operation) {
				if err := supervisor.cancel(op.ID, nil); err != nil {
					t.Fatalf("cancel: %v", err)
				}
			},
			wantRC: resultCancelled,
		},
		{
			name: "shutdown during the admitted verification child",
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
			releasePath := runner.setInspectBlocks(t, true)

			op := startBackendBuild(t, app, result.Token, nil)
			// The blocked verification child is the newest started child:
			// buildctl and load succeeded, the inspect child was admitted
			// and started.
			runner.waitChildStartedCount(t, 3)
			inspectIdx := runner.constructIndexOfImportStage("inspect")
			if inspectIdx < 0 || !isVerificationArgv(calls.argv(calls.count()-1)) {
				t.Fatalf("newest started child is not the admitted verification child:\n%s", calls.all())
			}

			// The termination path signals the admitted child: the release
			// file is never written, so only the signal can end the blocked
			// child.
			tc.terminate(t, supervisor, op)
			op.Wait()

			op.mu.Lock()
			latched, slotCleared := op.terminationRequested, op.currentCmd == nil && op.currentCancel == nil
			state, rc := op.State, derefString(op.ResultCode)
			op.mu.Unlock()
			if !latched {
				t.Error("termination latch not set")
			}
			if !slotCleared {
				t.Error("current execution-stage slot not cleared after the terminated verification stage")
			}

			// The admitted verification child was signaled and reaped: its
			// release file must not exist (the signal, not a release,
			// ended it), the child must have started (admission), and the
			// driver's Wait owner must have reaped it.
			if _, err := os.Stat(releasePath); !os.IsNotExist(err) {
				t.Errorf("verification release file exists (%v); the signal-only termination proof requires it absent", err)
			}
			if !runner.childStarted(inspectIdx) {
				t.Error("verification child did not start (it must be admitted before termination)")
			}
			if cmd := calls.cmd(inspectIdx); cmd.ProcessState == nil {
				t.Error("verification child was not reaped by the stage Wait owner")
			}

			// The terminated verification stage suppresses the commit stage
			// entirely: the tag command is never even constructed.
			if got := runner.constructIndexOfImportStage("tag"); got != -1 {
				t.Errorf("tag child constructed after the terminated verification stage (index %d):\n%s", got, calls.all())
			}

			// Started handoff children: load, the terminated verification,
			// then only the best-effort internal-tag cleanup.
			if got := runner.startedImportStages(); !equalStrings(got, []string{"load", "inspect", "rmi"}) {
				t.Errorf("started import stages = %v, want [load inspect rmi]\nall children:\n%s", got, calls.all())
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

// TestBuildDriverCancelAfterCommitAdmissionFollowsTagOutcome proves the
// post-admission contract through the driver: with a real tag child
// started and the §16 admission proven claimed, an explicit cancel signals
// the admitted child; the result follows the ACTUAL tag outcome — a killed
// tag child is docker_build_failed, never cancelled, even though the
// termination latch is set — and the best-effort internal-tag cleanup still
// runs with the exact operation-owned tag.
func TestBuildDriverCancelAfterCommitAdmissionFollowsTagOutcome(t *testing.T) {
	app, supervisor, result, _, calls := setupBuildBackendTest(t)
	runner := newBackendChildRunner(t, app, calls)
	runner.setTagBlocks(true)

	op := startBackendBuild(t, app, result.Token, nil)
	// The blocked tag child is the newest started child; the commit stage
	// was admitted (§16 claimed the slot under op.mu).
	runner.waitChildStartedCount(t, 4)
	if !hasArgvWord(calls.argv(calls.count()-1), "tag") {
		t.Fatalf("newest child is not the commit child:\n%s", calls.all())
	}
	op.mu.Lock()
	claimed := op.commitClaimed
	op.mu.Unlock()
	if !claimed {
		t.Fatal("commit admission not claimed before cancellation")
	}

	if err := supervisor.cancel(op.ID, nil); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	op.Wait()

	op.mu.Lock()
	latched, state, rc := op.terminationRequested, op.State, derefString(op.ResultCode)
	op.mu.Unlock()
	if !latched {
		t.Error("termination latch not set")
	}

	// The admitted commit child was killed by the termination path; the
	// outcome owns the result (docker_build_failed), never cancelled.
	if state != operationFailed {
		t.Errorf("state = %v, want failed", state)
	}
	if rc != "docker_build_failed" {
		t.Errorf("result_code = %q, want docker_build_failed (the commit outcome, never cancelled)", rc)
	}

	// The tag child started (the admitted commit) and only the best-effort
	// internal-tag cleanup followed it; the requested image was never
	// tagged by a successful commit.
	if got := runner.startedImportStages(); !equalStrings(got, []string{"load", "inspect", "tag", "rmi"}) {
		t.Errorf("started import stages = %v, want [load inspect tag rmi]\nall children:\n%s", got, calls.all())
	}
	assertInternalTagRmi(t, calls, op.ID)
}

// TestOperationCommitAdmissionTerminationOrderings proves the two legal
// orderings at the atomic commit-admission boundary through the ONE §16
// primitive and the REAL termination path (no second lock or flag):
//
//  1. termination latched first: the admission is refused and the commit
//     child never starts (the boundary has no intermediate state);
//  2. admission first: the child runs, the racing termination signals it,
//     and the commit outcome is a Wait error (the killed-child outcome the
//     driver classifies as docker_build_failed, never cancelled).
func TestOperationCommitAdmissionTerminationOrderings(t *testing.T) {
	t.Run("termination latched first refuses admission", func(t *testing.T) {
		_, supervisor, session, _ := setupBuildTest(t)

		op := newBuildOperation(session.Session.ID, "test:image", ".", "Dockerfile", 4*1024*1024, "", "", "")
		if admitForTest(supervisor, op) != admissionAccepted {
			t.Fatal("admit failed")
		}

		// Real cancel path: the latch is established under op.mu before the
		// admission attempt; the cancel's graceful wait converges when the
		// harness completes the operation below.
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = supervisor.cancel(op.ID, nil)
		}()
		waitTerminationLatched(t, op)

		cmd := boundedSleepCmd(context.Background())
		res := startOperationCommitStage(op, cmd)
		if !res.Terminated {
			t.Errorf("admission result = %+v, want refused by the termination latch", res)
		}
		if cmd.Process != nil {
			t.Errorf("commit child started after the latch (pid %d): the boundary must refuse", cmd.Process.Pid)
		}

		// Complete the operation with the driver's own refused-commit
		// classification so the cancel's graceful wait converges.
		op.fail(resultCancelled, "build cancelled", nil)
		wg.Wait()
	})

	t.Run("admission first leaves the commit outcome in charge", func(t *testing.T) {
		_, supervisor, session, _ := setupBuildTest(t)

		op := newBuildOperation(session.Session.ID, "test:image", ".", "Dockerfile", 4*1024*1024, "", "", "")
		if admitForTest(supervisor, op) != admissionAccepted {
			t.Fatal("admit failed")
		}

		// A blocked commit child whose start proves the admission's
		// critical section completed (Start ran inside op.mu).
		ready := filepath.Join(t.TempDir(), "commit.ready")
		cmd := exec.Command("sh", "-c", "touch "+ready+"; while :; do sleep 0.05; done")

		var wg sync.WaitGroup
		wg.Add(2)
		resCh := make(chan buildStageResult, 1)
		go func() {
			defer wg.Done()
			res := startOperationCommitStage(op, cmd)
			// Like a real sequential-stage driver, the admission goroutine
			// owns the Wait and the terminal transition: the killed commit
			// child classifies as the commit outcome, never cancelled.
			if res.Err != nil {
				op.fail("docker_build_failed", "docker tag failed", res.ExitCode)
			} else {
				op.succeed(nil)
			}
			resCh <- res
		}()
		waitProcessReady(t, ready)
		op.mu.Lock()
		claimed := op.commitClaimed
		op.mu.Unlock()
		if !claimed {
			t.Fatal("commit admission not claimed")
		}

		go func() {
			defer wg.Done()
			_ = supervisor.cancel(op.ID, nil)
		}()

		res := <-resCh
		if res.Terminated {
			t.Error("admitted commit must not report Terminated (the latch never refuses an admitted stage)")
		}
		if res.Err == nil {
			t.Error("the racing termination must kill the blocked commit child (Wait error expected)")
		}
		wg.Wait()

		op.mu.Lock()
		latched, state, rc := op.terminationRequested, op.State, derefString(op.ResultCode)
		op.mu.Unlock()
		if !latched {
			t.Error("termination latch not set")
		}
		if state != operationFailed || rc != "docker_build_failed" {
			t.Errorf("state=%v result_code=%q, want failed/docker_build_failed (commit outcome owns)", state, rc)
		}
		if cmd.ProcessState == nil {
			t.Error("commit child was not reaped by the admission's Wait owner")
		}
	})
}
