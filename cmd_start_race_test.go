package main

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// TestCmdStartRaceShutdownBeforeStart verifies at the primitive level that
// when shutdown acquires the coordination boundary before cmd.Start(), the
// process does not start: terminateForShutdown marks the operation terminated
// while the starter waits, and startOperationProcess then refuses to start.
func TestCmdStartRaceShutdownBeforeStart(t *testing.T) {
	app, supervisor, session, _ := setupRunSupervisorTest(t)

	op := newRunOperation(session.Session.ID, "example:test", 4*1024*1024, "", "", "")
	if supervisor.admit(op) != admissionAccepted {
		t.Fatal("admit failed")
	}

	// Block the starter at the point where it holds op.mu about to call
	// Start(), via the command-creation seam.
	cmdBlocked := make(chan struct{})
	cmdProceed := make(chan struct{})
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		close(cmdBlocked)
		<-cmdProceed
		return exec.CommandContext(ctx, "/bin/sleep", "60")
	}

	started := make(chan operationStartResult, 1)
	go func() {
		cmd := app.newDockerCommand(context.Background(), "sleep", "60")
		started <- startOperationProcess(cmd, op)
	}()

	select {
	case <-cmdBlocked:
	case <-time.After(5 * time.Second):
		t.Fatal("starter did not reach command creation")
	}

	// Trigger shutdown while the starter is blocked.
	supervisor.beginShutdown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	supervisor.terminateForShutdown(shutdownCtx, nil)
	cancel()

	// Unblock the starter — it must see terminated and not start the process.
	close(cmdProceed)
	var res operationStartResult
	select {
	case res = <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("startOperationProcess did not complete")
	}

	if !res.Terminated {
		t.Errorf("startOperationProcess = %+v, want pre-start termination", res)
	}

	// The operation must remain marked terminated so the owning handler
	// path fails it; the supervisor itself must never start the process.
	op.mu.Lock()
	terminated := op.terminated
	startedFlag := op.started
	op.mu.Unlock()

	if !terminated || startedFlag {
		t.Errorf("terminated=%v started=%v, want terminated and never started", terminated, startedFlag)
	}
}

// TestCmdStartRaceStartBeforeShutdown verifies that when the process starts
// before shutdown acquires the boundary, the process is properly terminated
// via graceful SIGTERM.
func TestCmdStartRaceStartBeforeShutdown(t *testing.T) {
	app, supervisor, session, _ := setupRunSupervisorTest(t)
	app.ExecCommandContext = makeSleepCmd()

	op := startRunTestOperation(t, app, session)

	supervisor.beginShutdown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	supervisor.terminateForShutdown(shutdownCtx, nil)
	cancel()

	select {
	case <-op.done:
	case <-time.After(5 * time.Second):
		t.Fatal("op.done was not closed")
	}

	if op.State != operationFailed {
		t.Errorf("expected 'failed', got %q", op.State)
	}
}
