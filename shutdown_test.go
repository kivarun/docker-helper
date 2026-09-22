package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestShutdownGracefulSignalsBuild tests that shutdown sends graceful
// SIGTERM to a running build process, and if the process exits after
// the signal, force kill is not needed.
func TestShutdownGracefulSignalsBuild(t *testing.T) {
	app, supervisor, _, token := setupBuildTest(t)
	app.ExecCommandContext = makeSleepCmd()

	op := startBuild(t, app, token)

	// Mark supervisor as shutting down and terminate with generous timeout.
	supervisor.beginShutdown()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	startShutdown := time.Now()
	supervisor.terminateForShutdown(shutdownCtx, nil)
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
// graceful SIGTERM is force-killed within the shutdown deadline.
func TestShutdownForceKillsIgnoringSignal(t *testing.T) {
	app, supervisor, _, token := setupBuildTest(t)
	attachBackendFixture(t, app)

	// The buildctl stage owns the child; later driver children succeed
	// instantly. The child ignores SIGTERM (trap ':'), signals readiness
	// by touching the marker itself, and busy-waits. The readiness marker
	// is written by the child shell because the driver replaces the
	// buildctl child environment after the seam returns (build_driver.go
	// buildctlStage), so an env-borne READY_FILE never reaches it.
	readyFile := filepath.Join(app.Config.AllowedRoots[0].Path, ".process_ready")
	defer os.Remove(readyFile)
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if strings.HasSuffix(name, "buildctl") {
			return exec.CommandContext(ctx, "/bin/sh", "-c",
				"trap ':' TERM; touch "+readyFile+"; while :; do :; done")
		}
		return exec.CommandContext(ctx, "/bin/true")
	}

	op := startBuild(t, app, token)

	// Wait for the process to signal readiness (installed SIGTERM ignore).
	waitProcessReady(t, readyFile)

	// Mark supervisor as shutting down and terminate with short deadline.
	supervisor.beginShutdown()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	startShutdown := time.Now()
	supervisor.terminateForShutdown(shutdownCtx, nil)
	shutdownDuration := time.Since(startShutdown)
	cancel()

	// With the bounded lifecycle, terminateForShutdown must complete within
	// the shutdown deadline (no additional fixed wait beyond deadline).
	if shutdownDuration > 750*time.Millisecond {
		t.Errorf("terminateForShutdown exceeded shutdown budget: took %v (deadline 500ms)", shutdownDuration)
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
	app, supervisor, _, token := setupBuildTest(t)
	app.ExecCommandContext = makeSleepCmd()

	op := startBuild(t, app, token)

	// Mark supervisor as shutting down and terminate with very short deadline.
	supervisor.beginShutdown()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	supervisor.terminateForShutdown(shutdownCtx, nil)
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
