package main

import (
	"context"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestCmdStartRaceShutdownBeforeStart verifies that when shutdown acquires
// the coordination boundary before cmd.Start(), the process does not start.
// This is deterministic: the handler blocks on op.mu while terminateAll
// sets terminated=true, then the handler sees terminated and aborts.
func TestCmdStartRaceShutdownBeforeStart(t *testing.T) {
	app, supervisor, _, token := setupBuildTest(t)
	attachBackendFixture(t, app)

	// Block the handler at the point where it holds op.mu about to call Start().
	cmdBlocked := make(chan struct{})
	cmdProceed := make(chan struct{})
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if !strings.HasSuffix(name, "buildctl") {
			return exec.CommandContext(ctx, "/bin/true")
		}
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
	supervisor.beginShutdown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	supervisor.terminateForShutdown(shutdownCtx, nil)
	cancel()

	// Unblock the handler — it should see terminated and not start.
	close(cmdProceed)
	op := getOp()

	if w.Code != http.StatusCreated {
		t.Errorf("expected %d, got %d", http.StatusCreated, w.Code)
	}
	if op == nil {
		t.Fatal("operation should be in supervisor")
	}
	// The refused stage returns through the async driver; the terminal
	// transition follows, so wait for it deterministically.
	select {
	case <-op.done:
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not reach its terminal state")
	}
	if op.State != operationFailed {
		t.Errorf("expected 'failed', got %q", op.State)
	}
}

// TestCmdStartRaceStartBeforeShutdown verifies that when cmd.Start()
// completes before shutdown acquires the boundary, the process is
// properly terminated via graceful SIGTERM.
func TestCmdStartRaceStartBeforeShutdown(t *testing.T) {
	app, supervisor, _, token := setupBuildTest(t)
	attachBackendFixture(t, app)
	app.ExecCommandContext = makeSleepCmd()

	op := startBuild(t, app, token)

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
