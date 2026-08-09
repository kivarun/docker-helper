package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestShutdownGracefulSignalsBuild tests that shutdown sends graceful
// SIGTERM to a running build process, and if the process exits after
// the signal, force kill is not needed.
func TestShutdownGracefulSignalsBuild(t *testing.T) {
	app, reg, token := setupBuildTest(t)
	app.ExecCommandContext = makeSleepCmd()

	op := startBuild(t, app, token)

	// Mark registry as shutting down and terminate with generous timeout.
	reg.setShuttingDown()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	startShutdown := time.Now()
	reg.terminateAll(shutdownCtx)
	shutdownDuration := time.Since(startShutdown)
	cancel()

	// Shutdown should complete within the timeout.
	if shutdownDuration > 1500*time.Millisecond {
		t.Errorf("shutdown took too long: %v", shutdownDuration)
	}

	// The operation should have completed (process killed by SIGTERM).
	op.Wait()
	if op.State != operationFailed {
		t.Errorf("expected status 'failed', got %q", op.State)
	}
}

// TestShutdownForceKillsIgnoringSignal tests that a process ignoring
// graceful SIGTERM is force-killed after the deadline.
func TestShutdownForceKillsIgnoringSignal(t *testing.T) {
	app, reg, token := setupBuildTest(t)

	// Use a readiness marker so we know the trap is installed.
	readyFile := filepath.Join(app.Config.AllowedRoot, ".process_ready")
	defer os.Remove(readyFile)
	app.ExecCommandContext = makeIgnoringSignalCmd(t, readyFile)

	op := startBuild(t, app, token)

	// Wait for the process to signal readiness (installed SIGTERM ignore).
	waitProcessReady(t, readyFile)

	// Mark registry as shutting down and terminate with short deadline.
	reg.setShuttingDown()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	startShutdown := time.Now()
	reg.terminateAll(shutdownCtx)
	shutdownDuration := time.Since(startShutdown)
	cancel()

	// terminateAll should not return immediately (graceful phase ran).
	if shutdownDuration < 400*time.Millisecond {
		t.Errorf("terminateAll returned too quickly: %v (graceful phase may not have run)", shutdownDuration)
	}

	// Shutdown should complete within the deadline plus a small buffer for Kill().
	// terminateAll must NOT add a separate fixed wait beyond the deadline.
	if shutdownDuration > 750*time.Millisecond {
		t.Errorf("terminateAll exceeded shutdown budget: took %v (deadline 500ms)", shutdownDuration)
	}

	// The operation should have been force-killed.
	op.Wait()
	if op.State != operationFailed {
		t.Errorf("expected status 'failed', got %q", op.State)
	}
}

// TestShutdownOperationCompletionGoroutineReaps tests that the operation
// completion goroutine properly reaps the process and closes op.done
// even after force kill.
func TestShutdownOperationCompletionGoroutineReaps(t *testing.T) {
	app, reg, token := setupBuildTest(t)
	app.ExecCommandContext = makeSleepCmd()

	op := startBuild(t, app, token)

	// Mark registry as shutting down and terminate with very short deadline.
	reg.setShuttingDown()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	reg.terminateAll(shutdownCtx)
	cancel()

	// op.done should be closed by the completion goroutine.
	select {
	case <-op.done:
		// Good - completion goroutine reaped the process.
	case <-time.After(2 * time.Second):
		t.Fatal("op.done was not closed - completion goroutine did not reap process")
	}

	// Verify operation state is failed.
	if op.State != operationFailed {
		t.Errorf("expected status 'failed', got %q", op.State)
	}
}
