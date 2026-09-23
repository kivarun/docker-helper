package main

// P3-C2a driver proofs for the cancellation / commit-admission boundary,
// driven through the production build driver and the ONE §16 commit-stage
// admission primitive: a termination latched before the boundary refuses
// the admission (the commit child never starts) while a termination after
// the boundary leaves the commit outcome in charge (a killed tag child is
// docker_build_failed, never cancelled). The internal-tag cleanup runs on
// every path. C2b owns successful post-commit result permanence; the
// successful ordering is already proven by B2.

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

// TestBuildDriverPreCommitTerminationRefusesCommit proves the pre-commit
// termination contract through the driver: with the internal-tag
// verification blocked after a successful load, an explicit cancel or a
// daemon shutdown latches the termination; releasing the verification
// (which then SUCCEEDS) proves the refused commit admission — the tag
// command is constructed but its process never starts — and the best-effort
// internal-tag cleanup still removes exactly the operation-owned internal
// tag on a fresh bounded context. Explicit cancel reports cancelled;
// shutdown keeps the kind-specific docker_build_failed.
func TestBuildDriverPreCommitTerminationRefusesCommit(t *testing.T) {
	cases := []struct {
		name      string
		terminate func(t *testing.T, supervisor *operationSupervisor, op *operation) (done func())
		wantRC    string
	}{
		{
			name: "explicit cancel while verification pending",
			terminate: func(t *testing.T, supervisor *operationSupervisor, op *operation) (done func()) {
				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					_ = supervisor.cancel(op.ID, nil)
				}()
				return wg.Wait
			},
			wantRC: resultCancelled,
		},
		{
			name: "shutdown while verification pending",
			terminate: func(t *testing.T, supervisor *operationSupervisor, op *operation) (done func()) {
				supervisor.beginShutdown()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				supervisor.terminateForShutdown(shutdownCtx, nil)
				cancel()
				return nil
			},
			wantRC: "docker_build_failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, supervisor, result, _, calls := setupBuildBackendTest(t)
			runner := newBackendChildRunner(t, app, calls)
			releasePath := runner.setInspectBlocks(t, true)

			op := startBackendBuild(t, app, result.Token, nil)
			// The blocked verification child is the newest started child:
			// buildctl and load succeeded, verification is pending.
			runner.waitChildStartedCount(t, 3)
			if !isVerificationArgv(calls.argv(calls.count() - 1)) {
				t.Fatalf("newest child is not the verification child:\n%s", calls.all())
			}

			done := tc.terminate(t, supervisor, op)
			waitTerminationLatched(t, op)

			// Release the blocked verification: the child exits 0, so the
			// driver reaches the commit stage and the latch must refuse its
			// admission. The release is a file write (never a read of the
			// recorded command's process state, which the driver goroutine
			// owns while Start runs).
			if err := os.WriteFile(releasePath, []byte("release"), 0o644); err != nil {
				t.Fatalf("cannot release verification child: %v", err)
			}
			if done != nil {
				done() // the cancel's graceful wait converges on op.done
			}
			op.Wait()

			op.mu.Lock()
			state, rc := op.State, derefString(op.ResultCode)
			op.mu.Unlock()

			// The verification succeeded and the latch refused the commit
			// admission: the tag command was constructed (the atomic
			// refusal artifact) but its process never started.
			tagIdx := runner.constructIndexOfImportStage("tag")
			if tagIdx < 0 {
				t.Error("driver did not attempt the commit stage (expected a constructed tag command)")
			} else if runner.childStarted(tagIdx) {
				t.Error("docker tag process STARTED after the termination latch (admission must be refused)")
			}

			// Started handoff children: load, blocked verification, then
			// only the best-effort internal-tag cleanup.
			if got := runner.startedImportStages(); !equalStrings(got, []string{"load", "inspect", "rmi"}) {
				t.Errorf("started import stages = %v, want [load inspect rmi]\nall children:\n%s", got, calls.all())
			}
			assertInternalTagRmi(t, calls, op.ID)

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
