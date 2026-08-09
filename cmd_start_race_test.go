package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestCmdStartRaceShutdownBeforeStart verifies that when shutdown acquires
// the coordination boundary before cmd.Start(), the process does not start.
// This is deterministic: the handler blocks on op.mu while terminateAll
// sets terminated=true, then the handler sees terminated and aborts.
func TestCmdStartRaceShutdownBeforeStart(t *testing.T) {
	app, reg, token := setupBuildTest(t)

	// Block the handler at the point where it holds op.mu about to call Start().
	cmdBlocked := make(chan struct{})
	cmdProceed := make(chan struct{})
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		close(cmdBlocked)
		<-cmdProceed
		return exec.CommandContext(ctx, "/bin/sleep", "60")
	}

	w, _, getOp := startBuildConcurrent(t, app, token)

	// Wait for cmd to be ready (handler blocked waiting for cmdProceed).
	select {
	case <-cmdBlocked:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not reach cmd creation")
	}

	// Trigger shutdown while handler is blocked.
	reg.setShuttingDown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	reg.terminateAll(shutdownCtx)
	cancel()

	// Unblock the handler — it should see terminated and not start.
	close(cmdProceed)
	op := getOp()

	if w.Code != http.StatusCreated {
		t.Errorf("expected %d, got %d", http.StatusCreated, w.Code)
	}
	if op == nil {
		t.Fatal("operation should be in registry")
	}
	if op.State != operationFailed {
		t.Errorf("expected 'failed', got %q", op.State)
	}
}

// TestCmdStartRaceStartBeforeShutdown verifies that when cmd.Start()
// completes before shutdown acquires the boundary, the process is
// properly terminated via graceful SIGTERM.
func TestCmdStartRaceStartBeforeShutdown(t *testing.T) {
	app, reg, token := setupBuildTest(t)
	app.ExecCommandContext = makeSleepCmd()

	op := startBuild(t, app, token)

	reg.setShuttingDown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	reg.terminateAll(shutdownCtx)
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

// TestCmdStartRaceForceKillIgnoringSignal verifies that a process that
// ignores graceful SIGTERM is force-killed after the deadline, even when
// it was properly started before shutdown.
func TestCmdStartRaceForceKillIgnoringSignal(t *testing.T) {
	app, reg, token := setupBuildTest(t)

	// Use a readiness marker so we know the trap is installed.
	readyFile := filepath.Join(app.Config.AllowedRoot, ".process_ready")
	defer os.Remove(readyFile)
	app.ExecCommandContext = makeIgnoringSignalCmd(t, readyFile)

	op := startBuild(t, app, token)

	// Wait for the process to signal readiness (installed TERM trap).
	waitProcessReady(t, readyFile)

	// Trigger shutdown with short deadline.
	reg.setShuttingDown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	start := time.Now()
	reg.terminateAll(shutdownCtx)
	elapsed := time.Since(start)
	cancel()

	// terminateAll should not exceed the deadline significantly.
	if elapsed > 1*time.Second {
		t.Errorf("terminateAll took too long: %v", elapsed)
	}

	// Completion goroutine should reap the process.
	select {
	case <-op.done:
	case <-time.After(5 * time.Second):
		t.Fatal("op.done was not closed")
	}

	if op.State != operationFailed {
		t.Errorf("expected 'failed', got %q", op.State)
	}
}
