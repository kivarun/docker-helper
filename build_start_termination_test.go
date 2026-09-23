package main

// build_start_termination_test.go proves manager START termination through
// the production build driver (Release-2.4 §3 ambiguity tests, promoted to
// the P3 driver): explicit cancellation and daemon shutdown during a
// blocked START round-trip. The fake manager accepts and records START but
// deliberately withholds its reply; all synchronization is barrier-based.
//
// Frozen invariants (no second STOP-on-ambiguity path in the driver):
//   - the control stage's currentCancel fires (the P2 client's blocked
//     START read observes cancellation);
//   - the P2 client issues the compensating STOP on a fresh context (the
//     only STOP on this path — the driver adds none);
//   - no buildctl/load/tag child ever starts;
//   - explicit cancel terminates cancelled, shutdown terminates
//     docker_build_failed.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// buildTerminalState reads the terminal state of a finished operation.
func buildTerminalState(t *testing.T, op *operation) (state string, resultCode string, exitCode *int) {
	t.Helper()
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.ResultCode != nil {
		resultCode = *op.ResultCode
	}
	return string(op.State), resultCode, op.ExitCode
}

// startBlockedBuild starts a build whose manager START is accepted but
// withheld; it blocks until the fake manager recorded the START (barrier)
// and returns the operation and the recorded START op id.
func startBlockedBuild(t *testing.T, app *App, manager *fakeBuilderManager, token string) (*operation, string) {
	t.Helper()
	manager.setStartWithheld()
	op := startBackendBuild(t, app, token, nil)
	got := manager.waitStartBarrier(t)
	if !strings.HasPrefix(got, "op_") {
		t.Fatalf("recorded START op id %q is not canonical", got)
	}
	return op, got
}

// TestBuildCancelDuringBlockedStart proves the explicit-cancel path:
// cancel during a blocked manager START round-trip fires currentCancel,
// the P2 client compensates with a fresh-context STOP, no child stage
// ever starts, and the operation terminates cancelled.
func TestBuildCancelDuringBlockedStart(t *testing.T) {
	app, supervisor, result, manager, calls := setupBuildBackendTest(t)

	op, _ := startBlockedBuild(t, app, manager, result.Token)

	// Cancel while the START conn is still withheld. cancel() returns
	// only after the op reached its terminal state; the compensating
	// STOP must have arrived before that.
	t0 := time.Now()
	if err := supervisor.cancel(op.ID, nil); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	cancelDuration := time.Since(t0)
	if cancelDuration > 5*time.Second {
		t.Errorf("cancel() took %v; the compensation STOP should converge the graceful wait", cancelDuration)
	}

	op.Wait()
	if got := manager.startCount(); got != 1 {
		t.Errorf("manager START count = %d, want exactly 1", got)
	}
	if got := manager.stopCount(); got != 1 {
		t.Errorf("manager STOP count = %d, want exactly 1 (the P2 compensating STOP; the driver must not add a second)", got)
	}
	if got := calls.count(); got != 0 {
		t.Errorf("children started = %d, want 0 (no buildctl/import after cancelled START):\n%s", got, calls.all())
	}

	state, rc, exitCode := buildTerminalState(t, op)
	if state != "failed" {
		t.Errorf("state = %q, want failed", state)
	}
	if rc != "cancelled" {
		t.Errorf("result_code = %q, want cancelled (explicit cancel)", rc)
	}
	if exitCode != nil {
		t.Errorf("exit_code = %v, want nil (START is a no-child stage)", exitCode)
	}
}

// TestBuildShutdownDuringBlockedStart proves the daemon-shutdown path:
// shutdown during a blocked manager START round-trip fires currentCancel,
// the P2 client compensates with a fresh-context STOP, no child stage
// ever starts, and the operation terminates failed with the current
// contract's docker_build_failed (no public shutdown result code exists).
func TestBuildShutdownDuringBlockedStart(t *testing.T) {
	app, supervisor, result, manager, calls := setupBuildBackendTest(t)

	op, _ := startBlockedBuild(t, app, manager, result.Token)

	// Daemon shutdown: gate closed, then the bounded termination.
	supervisor.beginShutdown()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	supervisor.terminateForShutdown(ctx, nil)

	// terminateForShutdown returns after every operation reached a
	// terminal state; op.Wait() is then a no-op kept as the contract form.
	op.Wait()
	if got := manager.startCount(); got != 1 {
		t.Errorf("manager START count = %d, want exactly 1", got)
	}
	if got := manager.stopCount(); got != 1 {
		t.Errorf("manager STOP count = %d, want exactly 1 (the P2 compensating STOP; the driver must not add a second)", got)
	}
	if got := calls.count(); got != 0 {
		t.Errorf("children started = %d, want 0 (no buildctl/import after shutdown-terminated START):\n%s", got, calls.all())
	}

	state, rc, exitCode := buildTerminalState(t, op)
	if state != "failed" {
		t.Errorf("state = %q, want failed", state)
	}
	if rc != "docker_build_failed" {
		t.Errorf("result_code = %q, want docker_build_failed (shutdown keeps the kind-specific failure code; no public shutdown code exists)", rc)
	}
	if exitCode != nil {
		t.Errorf("exit_code = %v, want nil (START is a no-child stage)", exitCode)
	}
}

// TestBuildCancelDuringBlockedStartManagerStopConcurrent proves the fake
// manager still serves STOP on a separate connection while the START
// connection is held (the blocking START must not block the STOP
// processing): the compensating STOP is recorded while the withheld
// START conn has not been released yet.
func TestBuildCancelDuringBlockedStartManagerStopConcurrent(t *testing.T) {
	app, supervisor, result, manager, calls := setupBuildBackendTest(t)

	op, startID := startBlockedBuild(t, app, manager, result.Token)
	if err := supervisor.cancel(op.ID, nil); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	op.Wait()

	// The exact STOP op id equals the recorded START op id: the
	// compensation targets the same operation.
	stopID := manager.waitStopBarrier(t)
	if stopID != startID {
		t.Errorf("compensating STOP %q does not target the started operation %q", stopID, startID)
	}
	if got := calls.count(); got != 0 {
		t.Errorf("children started = %d, want 0:\n%s", got, calls.all())
	}
}

// TestBuildStartAmbiguousEOFProvenConvergenceBlocksStages proves the
// driver-level lost-reply contract WITHOUT any cancellation: the manager
// records START and closes the connection without a reply (ambiguous
// EOF), the P2 client compensates on a fresh context (STOP → OK absent =
// proven convergence), and the driver — with the termination latch
// UNSET — must fail the build docker_build_failed, never start buildctl
// or any import/tag child, and emit the internal builder_start
// diagnostic. One STOP total: the driver adds no second STOP path.
func TestBuildStartAmbiguousEOFProvenConvergenceBlocksStages(t *testing.T) {
	_, opBuf := setupTestLogging(t)

	app, _, result, manager, calls := setupBuildBackendTest(t)
	manager.setStartDropped()

	op := startBackendBuild(t, app, result.Token, nil)
	manager.waitStartBarrier(t)
	op.Wait()

	if got := manager.startCount(); got != 1 {
		t.Errorf("manager START count = %d, want exactly 1", got)
	}
	if got := manager.stopCount(); got != 1 {
		t.Errorf("manager STOP count = %d, want exactly 1 (the P2 compensating STOP; the driver must not add a second)", got)
	}
	if got := calls.count(); got != 0 {
		t.Errorf("children started = %d, want 0 (a failed START blocks every later stage):\n%s", got, calls.all())
	}

	state, rc, exitCode := buildTerminalState(t, op)
	if state != "failed" {
		t.Errorf("state = %q, want failed", state)
	}
	if rc != "docker_build_failed" {
		t.Errorf("result_code = %q, want docker_build_failed (the ambiguous START surfaces as the current contract's failure code)", rc)
	}
	if exitCode != nil {
		t.Errorf("exit_code = %v, want nil (manager stages have no child)", exitCode)
	}

	// The internal diagnostic names the stage failure (bounded, no
	// protocol topology in the public API — the message below is the
	// operational-log line, not an API error).
	if diag := buildStartDiagnostic(t, opBuf); !strings.Contains(diag, "builder_start") {
		t.Errorf("operational log must carry the builder_start diagnostic, got:\n%s", diag)
	}
}

// TestBuildStartAmbiguousEOFRefusedCompensationBlocksStages proves the
// refused-compensation consequence at the driver level: the ambiguous
// START's compensating STOP is answered with a well-formed ERR (the
// manager cannot prove convergence), the P2 client surfaces the explicit
// refused-compensation failure, and the driver — latch UNSET — still
// blocks every later stage (zero children) and fails docker_build_failed
// with the internal diagnostic carrying the refusal.
func TestBuildStartAmbiguousEOFRefusedCompensationBlocksStages(t *testing.T) {
	_, opBuf := setupTestLogging(t)

	app, _, result, manager, calls := setupBuildBackendTest(t)
	manager.setStartDropped()
	manager.setStopResp(builderManagerRespInternal)

	op := startBackendBuild(t, app, result.Token, nil)
	manager.waitStartBarrier(t)
	op.Wait()

	if got := manager.stopCount(); got != 1 {
		t.Errorf("manager STOP count = %d, want exactly 1", got)
	}
	if got := calls.count(); got != 0 {
		t.Errorf("children started = %d, want 0 (an uncompensated ambiguity must block every later stage):\n%s", got, calls.all())
	}

	state, rc, exitCode := buildTerminalState(t, op)
	if state != "failed" {
		t.Errorf("state = %q, want failed", state)
	}
	if rc != "docker_build_failed" {
		t.Errorf("result_code = %q, want docker_build_failed", rc)
	}
	if exitCode != nil {
		t.Errorf("exit_code = %v, want nil", exitCode)
	}

	// The internal diagnostic carries the refused-compensation failure.
	if diag := buildStartDiagnostic(t, opBuf); !strings.Contains(diag, "compensating STOP was refused") {
		t.Errorf("operational log must carry the refused-compensation diagnostic, got:\n%s", diag)
	}
}

// buildStartDiagnostic returns the captured operational-log output
// (bounded internal diagnostics; never credential material).
func buildStartDiagnostic(t *testing.T, buf *bytes.Buffer) string {
	t.Helper()
	return buf.String()
}

// ensure the recorded child seam stays the single child-process owner for
// these tests
var _ = exec.CommandContext
var _ = httptest.NewRecorder
var _ = json.Unmarshal
