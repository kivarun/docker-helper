package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
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
				"trap ':' TERM; touch "+readyFile+"; while :; do sleep 0.05; done")
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

// admitShutdownProbeOperation registers one operation on the supervisor
// through the production admission path (reserve + admitReserved) and
// returns it. The operation starts with BOTH current-stage slots empty:
// the exact nonterminal no-child interval a build occupies between
// sequential stages or inside a cleanup-only stage interval.
func admitShutdownProbeOperation(t *testing.T, supervisor *operationSupervisor) *operation {
	t.Helper()
	op := newBuildOperation("session-shutdown-probe", "example:test", ".", "Dockerfile",
		4096, "principal", "launcher-shutdown-probe", "Launcher")
	reservation, decision := supervisor.reserve(op.SessionID, op.LauncherID, op.Kind)
	if decision != admissionAccepted {
		t.Fatalf("reserve = %d, want accepted", decision)
	}
	if decision := supervisor.admitReserved(op, reservation); decision != admissionAccepted {
		t.Fatalf("admitReserved = %d, want accepted", decision)
	}
	return op
}

// TestShutdownMustAwaitBetweenStageCleanup proves that shutdown waits for
// every admitted operation until op.done closes even when the operation
// holds NO current child process and NO current control stage at latch
// time: a between-stage/cleanup-interval operation is still nonterminal,
// so shutdown must not return before its stage driver reaches the
// terminal transition.
//
// Regression shape (external review F2): the pre-fix termination treated
// "no current child/control stage" as completed and skipped both the
// graceful wait and the force cleanup, so shutdown returned while the
// operation's stage driver was still inside its between-stage cleanup.
//
// The driver stand-in parks in the no-child interval, observes the
// permanent termination latch exactly like a real stage driver between
// stages, and then performs an UNINTERRUPTIBLE between-stage cleanup
// interval (a latched termination cannot shorten a manager STOP or a
// staging teardown that runs on a fresh bounded context) before the
// terminal transition. The post-latch delay exceeds the pre-fix early
// return, so the awaited-return assertion is deterministic.
func TestShutdownMustAwaitBetweenStageCleanup(t *testing.T) {
	supervisor := newOperationSupervisor()
	op := admitShutdownProbeOperation(t, supervisor)
	supervisor.beginShutdown()

	observed := &atomic.Bool{}
	done := make(chan struct{})
	go func() {
		for {
			op.mu.Lock()
			latched := op.terminationRequested
			op.mu.Unlock()
			if latched {
				break
			}
			time.Sleep(time.Millisecond)
		}
		observed.Store(true)
		time.Sleep(250 * time.Millisecond)
		op.fail(resultCancelled, "build cancelled", nil)
		close(done)
	}()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	supervisor.terminateForShutdown(shutdownCtx, nil)
	cancel()

	// The instant of return is the assertion point: shutdown must not
	// return while the between-stage operation is still nonterminal. The
	// driver completes only 250ms after it observes the latch, and the
	// latch is set inside terminateForShutdown itself, so a compliant
	// graceful wait always finds op.done already closed here.
	select {
	case <-op.done:
		// Shutdown awaited the between-stage operation's terminal transition.
	default:
		t.Fatal("shutdown returned while the between-stage operation is still nonterminal (op.done open)")
	}
	if !observed.Load() {
		t.Fatal("the stage driver never observed the termination latch; shutdown did not reach the operation")
	}
	<-done
}

// TestShutdownReturnsAfterChildStageDoneCloses proves the positive
// graceful-wait contract on the child-owning path: shutdown returns only
// after the operation's terminal transition closes op.done, and the
// current child stage received the termination signal.
func TestShutdownReturnsAfterChildStageDoneCloses(t *testing.T) {
	supervisor := newOperationSupervisor()
	op := admitShutdownProbeOperation(t, supervisor)
	supervisor.beginShutdown()

	done := make(chan struct{})
	childStarted := make(chan struct{})
	go func() {
		cmd := exec.Command("sleep", "30")
		result := startOperationStage(cmd, op)
		if result.Terminated || result.Err != nil {
			t.Errorf("the child stage was not admitted: terminated=%v err=%v", result.Terminated, result.Err)
			close(childStarted)
			close(done)
			return
		}
		close(childStarted)
		// The single Wait owner: SIGTERM terminates sleep, the Wait
		// returns, and the driver reaches the terminal transition.
		if err := op.waitCurrentStage(); err == nil {
			t.Error("a SIGTERM-terminated child must not report a clean wait")
		}
		op.fail(resultCancelled, "build cancelled", nil)
		close(done)
	}()

	// The child must be the current stage BEFORE the latch fires, so the
	// probe exercises the child-owning graceful path, not the refusal path.
	<-childStarted

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	supervisor.terminateForShutdown(shutdownCtx, nil)
	cancel()

	select {
	case <-op.done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown returned before op.done closed")
	}
	<-done
}

// TestShutdownForceCleanupCoversNonterminalOperation proves that force
// cleanup covers every operation whose op.done is still open at
// forceStart — including a between-stage operation with no current child
// or control stage at latch time, which the pre-fix termination skipped
// entirely (external review F2).
func TestShutdownForceCleanupCoversNonterminalOperation(t *testing.T) {
	supervisor := newOperationSupervisor()
	op := admitShutdownProbeOperation(t, supervisor)
	supervisor.beginShutdown()

	// The driver parks in the no-child interval and never reaches the
	// terminal transition on its own; the test releases it at cleanup.
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		for {
			op.mu.Lock()
			latched := op.terminationRequested
			op.mu.Unlock()
			if latched {
				break
			}
			time.Sleep(time.Millisecond)
		}
		<-release
		op.fail(resultCancelled, "build cancelled", nil)
		close(done)
	}()
	t.Cleanup(func() {
		close(release)
		<-done
	})

	// Deadline 4s: forceStart = deadline - defaultForceCleanupTimeout(3s)
	// leaves a 1s graceful window; the held operation must reach the force
	// phase instead of being skipped.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	supervisor.terminateForShutdown(shutdownCtx, nil)
	cancel()

	op.mu.Lock()
	forceOwned := op.forceOwned
	forceDone := op.forceDone
	op.mu.Unlock()
	if !forceOwned {
		t.Fatal("the held nonterminal operation was never claimed by force cleanup (skipped at latch time)")
	}
	select {
	case <-forceDone:
	default:
		t.Fatal("force cleanup claimed the held operation but never completed its shared phase")
	}
}
