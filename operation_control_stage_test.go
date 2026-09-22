package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Control-stage (no-child) cancellation hook tests (P3 §3): the no-child
// analogue of the P1 synthetic child-stage proofs, driven through the
// production owners runOperationControlStage / terminateOperations.

// TestOperationControlStageCancelBeforeAdmission: cancel before the control
// stage is admitted — fn never runs, the latch is set.
func TestOperationControlStageCancelBeforeAdmission(t *testing.T) {
	app, supervisor, session, _ := setupBuildTest(t)
	_ = app

	op := newRunOperation(session.Session.ID, "test:image", 4*1024*1024, "", "", "")
	if admitForTest(supervisor, op) != admissionAccepted {
		t.Fatal("admit failed")
	}

	if err := supervisor.cancel(op.ID, nil); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	ran := false
	res := runOperationControlStage(op, func(ctx context.Context) error {
		ran = true
		return nil
	})
	if !res.Terminated {
		t.Fatal("control stage admitted after pre-admission cancel")
	}
	if ran {
		t.Error("control stage fn ran after pre-admission cancel")
	}
	op.mu.Lock()
	latched := op.terminationRequested
	op.mu.Unlock()
	if !latched {
		t.Error("termination latch not set")
	}
}

// TestOperationControlStageCancelDuringRun: cancel while the control stage
// blocks on its context — cancel() fires, fn observes cancellation, and the
// slot clears afterwards.
func TestOperationControlStageCancelDuringRun(t *testing.T) {
	app, supervisor, session, _ := setupBuildTest(t)
	_ = app

	op := newRunOperation(session.Session.ID, "test:image", 4*1024*1024, "", "", "")
	if admitForTest(supervisor, op) != admissionAccepted {
		t.Fatal("admit failed")
	}

	observed := make(chan error, 1)
	release := make(chan struct{})
	go func() {
		res := runOperationControlStage(op, func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
				return nil
			}
		})
		if res.Terminated {
			observed <- errors.New("unexpected termination refusal")
			return
		}
		observed <- res.Err
	}()

	// Wait until the stage has installed its slot, then cancel.
	deadline := time.Now().Add(5 * time.Second)
	for {
		op.mu.Lock()
		installed := op.currentCancel != nil
		op.mu.Unlock()
		if installed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("control stage never installed its cancel slot")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if err := supervisor.cancel(op.ID, nil); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	select {
	case err := <-observed:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("control stage fn did not observe cancellation: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("control stage never returned after cancel")
	}

	op.mu.Lock()
	cleared := op.currentCancel == nil
	latched := op.terminationRequested
	op.mu.Unlock()
	if !cleared {
		t.Error("currentCancel slot not cleared after cancel")
	}
	if !latched {
		t.Error("termination latch not set")
	}

	// A later stage admission is refused by the latch.
	res := runOperationControlStage(op, func(ctx context.Context) error { return nil })
	if !res.Terminated {
		t.Error("later control stage admitted after termination")
	}
}

// TestOperationControlStageNoChildSlotOverlap proves the XOR invariant
// directly: a control stage cannot be admitted while a child slot is
// active, a child cannot be admitted while a control slot is active, and
// terminateOperations fires whichever is present.
func TestOperationControlStageNoChildSlotOverlap(t *testing.T) {
	app, supervisor, session, _ := setupBuildTest(t)
	_ = app

	op := newRunOperation(session.Session.ID, "test:image", 4*1024*1024, "", "", "")
	if admitForTest(supervisor, op) != admissionAccepted {
		t.Fatal("admit failed")
	}

	// Child active -> control admission is a discipline error.
	cmd := exec.Command("sleep", "60")
	if res := startOperationStage(cmd, op); res.Terminated || res.Err != nil {
		t.Fatalf("child stage did not start: %v %v", res.Terminated, res.Err)
	}
	ran := false
	res := runOperationControlStage(op, func(ctx context.Context) error {
		ran = true
		return nil
	})
	if res.Err == nil {
		t.Fatal("control stage admitted while a child slot was active")
	}
	if ran {
		t.Error("control stage fn ran while a child slot was active")
	}
	// Clean up the child stage.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill child: %v", err)
	}
	if err := op.waitCurrentStage(); err == nil {
		t.Fatal("expected wait error from killed child")
	}

	// Control active -> child admission is a discipline error. The control
	// stage blocks on a channel; admit the child from another goroutine.
	release := make(chan struct{})
	entered := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = runOperationControlStage(op, func(ctx context.Context) error {
			close(entered)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
				return nil
			}
		})
	}()
	<-entered

	childStartErr := startOperationStage(exec.Command("sleep", "60"), op)
	if childStartErr.Err == nil {
		t.Fatal("child stage admitted while a control slot was active")
	}

	// terminateOperations fires the cancel (not the child SIGTERM branch).
	if err := supervisor.cancel(op.ID, nil); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	wg.Wait()

	op.mu.Lock()
	cleared := op.currentCmd == nil && op.currentCancel == nil
	op.mu.Unlock()
	if !cleared {
		t.Error("both slots not empty after termination of a control stage")
	}
}

// TestOperationControlStageShutdownDuringRun: shutdown equivalent fires
// currentCancel and the stage observes it.
func TestOperationControlStageShutdownDuringRun(t *testing.T) {
	app, supervisor, session, _ := setupBuildTest(t)
	_ = app

	op := newRunOperation(session.Session.ID, "test:image", 4*1024*1024, "", "", "")
	if admitForTest(supervisor, op) != admissionAccepted {
		t.Fatal("admit failed")
	}

	observed := make(chan error, 1)
	go func() {
		res := runOperationControlStage(op, func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		})
		observed <- res.Err
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		op.mu.Lock()
		installed := op.currentCancel != nil
		op.mu.Unlock()
		if installed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("control stage never installed its cancel slot")
		}
		time.Sleep(2 * time.Millisecond)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	supervisor.terminateForShutdown(shutdownCtx, nil)
	cancel()

	select {
	case err := <-observed:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("control stage fn did not observe shutdown cancellation: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("control stage never returned after shutdown")
	}

	op.mu.Lock()
	reason := op.reason
	op.mu.Unlock()
	if reason != terminationShutdown {
		t.Errorf("termination reason %v, want terminationShutdown", reason)
	}
}

// TestOperationControlStageRaceAdmissionVsCancel races control-stage
// admission against cancel: exactly two legal outcomes — termination wins
// (fn never runs) or admission wins (fn runs and receives the cancel).
func TestOperationControlStageRaceAdmissionVsCancel(t *testing.T) {
	app, supervisor, session, _ := setupBuildTest(t)
	_ = app

	for attempt := 0; attempt < 100; attempt++ {
		op := newRunOperation(session.Session.ID, "test:image", 4*1024*1024, "", "", "")
		if admitForTest(supervisor, op) != admissionAccepted {
			t.Fatal("admit failed")
		}

		var ranMu sync.Mutex
		ran := false
		observed := make(chan error, 1)
		begin := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-begin
			res := runOperationControlStage(op, func(ctx context.Context) error {
				ranMu.Lock()
				ran = true
				ranMu.Unlock()
				<-ctx.Done()
				return ctx.Err()
			})
			if res.Terminated || res.Err != nil {
				observed <- errors.New("refused")
				return
			}
			observed <- nil
		}()
		go func() {
			defer wg.Done()
			<-begin
			_ = supervisor.cancel(op.ID, nil)
		}()
		close(begin)

		select {
		case err := <-observed:
			if err == nil {
				// Admission won: the fn ran and observed cancellation.
				ranMu.Lock()
				didRun := ran
				ranMu.Unlock()
				if !didRun {
					t.Fatalf("attempt %d: stage completed without running", attempt)
				}
			}
			// refused: termination won; nothing more to prove here.
		case <-time.After(10 * time.Second):
			t.Fatalf("attempt %d: race neither admitted nor refused", attempt)
		}
		wg.Wait()

		// Drive the op to a terminal state so the attempt releases capacity.
		op.mu.Lock()
		terminal := op.CompletedAt != nil
		op.mu.Unlock()
		if !terminal {
			op.fail("docker_run_failed", "synthetic harness cleanup", nil)
		}
	}
}

// TestOperationControlStageDisciplineSlotLeakProtection: after a control
// stage returns, the slot is exactly cleared so a subsequent child stage
// starts normally.
func TestOperationControlStageSlotClearedAfterReturn(t *testing.T) {
	app, supervisor, session, _ := setupBuildTest(t)
	_ = app

	op := newRunOperation(session.Session.ID, "test:image", 4*1024*1024, "", "", "")
	if admitForTest(supervisor, op) != admissionAccepted {
		t.Fatal("admit failed")
	}

	res := runOperationControlStage(op, func(ctx context.Context) error { return nil })
	if res.Terminated || res.Err != nil {
		t.Fatalf("control stage did not run cleanly: %v %v", res.Terminated, res.Err)
	}
	op.mu.Lock()
	cleared := op.currentCancel == nil
	op.mu.Unlock()
	if !cleared {
		t.Fatal("slot not cleared after clean return")
	}

	// A child stage can now start (negative self-proof: it was possible).
	cmd := exec.Command("true")
	if res := startOperationStage(cmd, op); res.Terminated || res.Err != nil {
		t.Fatalf("child stage refused after clean control stage: %v %v", res.Terminated, res.Err)
	}
	if err := op.waitCurrentStage(); err != nil {
		t.Fatalf("child wait: %v", err)
	}
	_ = os.Remove
	_ = filepath.Join
	_ = supervisor
}
