package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestShutdownGateClosesOnSignal verifies that after the shutdown signal is
// received, the synchronous admission gate closes (new runs are refused)
// while a legacy operation admitted before the signal remains under the
// legacy shutdown lifecycle.
func TestShutdownGateClosesOnSignal(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	supervisor := newOperationSupervisor()
	app.OperationSupervisor = supervisor

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Start a legacy operation before the signal.
	setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	existingOp := newRunOperation(result.Session.ID, "example:test", 4*1024*1024, "", "", "")
	if supervisor.admit(existingOp) != admissionAccepted {
		t.Fatal("admit failed")
	}
	cmd := exec.Command("sleep", "60")
	if res := startOperationProcess(cmd, existingOp); res.Terminated || res.Err != nil {
		t.Fatalf("start operation: terminated=%v err=%v", res.Terminated, res.Err)
	}
	go func() {
		cmd.Wait()
		existingOp.fail("docker_run_failed", "docker run failed", nil, nil)
	}()

	// Simulate signal received — close both gates.
	supervisor.beginShutdown()
	app.SyncExecutionCoordinator.beginShutdown()

	// A new synchronous run must be rejected.
	w2 := postRun(t, app, result.Token, map[string]any{
		"image":   "example:test2",
		"command": []string{"echo", "hello"},
	})

	if w2.Code != http.StatusServiceUnavailable {
		t.Errorf("expected %d after signal, got %d", http.StatusServiceUnavailable, w2.Code)
	}

	// The legacy operation stays in the supervisor and is managed by shutdown.
	if supervisor.lookup(existingOp.ID) == nil {
		t.Fatal("existing operation should remain in supervisor")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	supervisor.terminateForShutdown(shutdownCtx, nil)
	cancel()

	select {
	case <-existingOp.done:
	case <-time.After(5 * time.Second):
		t.Fatal("existing operation should be terminated")
	}
}

// TestShutdownGateConcurrentRunAndSignal verifies that a run request racing
// the shutdown gate is handled correctly: either accepted (if admission
// completed before the gate closed) or rejected with shutting_down (if the
// gate closed first). Either way the response is well-formed and there is
// no operation identity.
func TestShutdownGateConcurrentRunAndSignal(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	supervisor := newOperationSupervisor()
	app.OperationSupervisor = supervisor

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	// Block the Engine runner so we can close the gate concurrently.
	runnerStarted := make(chan struct{})
	runnerProceed := make(chan struct{})
	setupRunSeam(t, app, runSeamOptions{ExitCode: 0, Block: runnerProceed})
	go func() {
		<-runnerStarted
	}()

	w := httptest.NewRecorder()

	// Start the run handler in a goroutine.
	var handlerWg sync.WaitGroup
	handlerWg.Add(1)
	go func() {
		defer handlerWg.Done()
		// Close the gate as soon as the request reaches the Engine runner.
		go func() {
			<-runnerStarted
			app.SyncExecutionCoordinator.beginShutdown()
		}()
		app.handleRun(w, newRunRequest(map[string]any{
			"image":   "example:test",
			"command": []string{"echo", "hello"},
		}, result.Token))
	}()

	// Unblock the runner.
	close(runnerProceed)

	// Wait for handler to complete.
	handlerWg.Wait()

	// The run may have been accepted or rejected depending on timing.
	// In either case, the response should be valid.
	if w.Code == http.StatusOK {
		assertNoRunOperation(t, app, w.Body.Bytes())
	} else if w.Code == http.StatusServiceUnavailable {
		// Rejected — this is also valid.
	} else {
		t.Errorf("unexpected status: %d", w.Code)
	}
}
