package main

import (
	"context"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

// TestLifecycleRaceProcessNotStartedAfterShutdown verifies that when
// a build operation is registered but the process start is delayed,
// shutdown will mark it as terminated and prevent the process from
// starting unmanaged after shutdown has passed.
func TestLifecycleRaceProcessNotStartedAfterShutdown(t *testing.T) {
	app, reg, token := setupBuildTest(t)

	// Block ExecCommandContext so we can trigger shutdown between
	// registration and process start.
	cmdBlocked := make(chan struct{})
	cmdReady := make(chan struct{})
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		close(cmdBlocked)
		<-cmdReady
		return exec.CommandContext(ctx, "/bin/sleep", "60")
	}

	w, _, getOp := startBuildConcurrent(t, app, token)

	// Wait for the handler to block on ExecCommandContext.
	select {
	case <-cmdBlocked:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not reach ExecCommandContext")
	}

	// Trigger shutdown: the operation is registered but cmd is nil.
	reg.setShuttingDown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	reg.terminateAll(shutdownCtx, nil)
	cancel()

	// Unblock the handler — it should detect op.terminated and not start.
	close(cmdReady)
	op := getOp()

	if w.Code != http.StatusCreated {
		t.Errorf("expected %d, got %d", http.StatusCreated, w.Code)
	}
	if op == nil {
		t.Fatal("operation should still be in registry")
	}
	if op.State != operationFailed {
		t.Errorf("expected status 'failed', got %q", op.State)
	}
}

// TestLifecycleRaceProcessAlreadyStartedBeforeShutdown verifies that when
// a build process has already started before shutdown, it is properly
// terminated by terminateAll and the completion goroutine reaps it.
func TestLifecycleRaceProcessAlreadyStartedBeforeShutdown(t *testing.T) {
	app, reg, token := setupBuildTest(t)
	app.ExecCommandContext = makeSleepCmd()

	op := startBuild(t, app, token)

	// Trigger shutdown.
	reg.setShuttingDown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	reg.terminateAll(shutdownCtx, nil)
	cancel()

	// Wait for the completion goroutine to reap the process.
	select {
	case <-op.done:
	case <-time.After(5 * time.Second):
		t.Fatal("op.done was not closed")
	}

	if op.State != operationFailed {
		t.Errorf("expected status 'failed', got %q", op.State)
	}
}
