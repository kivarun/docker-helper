package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestLifecycleRaceCmdAssignedButNotStarted verifies that when op.cmd is
// assigned but op.started is false (cmd.Start() not yet called), shutdown
// will mark the operation as terminated and prevent the process from starting.
//
// This tests the specific window:
// 1. tryCreate(op) → success
// 2. op.cmd = cmd (assigned but not started)
// 3. terminateAll() → op.started == false, sets op.terminated
// 4. cmd.Start() should NOT proceed
func TestLifecycleRaceCmdAssignedButNotStarted(t *testing.T) {
	reg := newOperationRegistry()

	// Create an operation and simulate the state where cmd is assigned
	// but started is false (the race window).
	op := newBuildOperation("test_session", "example:test", ".", "Dockerfile", 1024)
	op.cmd = exec.Command("/bin/sleep", "60")
	// op.started is false by default — cmd assigned but not started.
	reg.create(op)

	// Trigger shutdown — terminateAll should see started == false.
	reg.setShuttingDown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	reg.terminateAll(shutdownCtx)
	cancel()

	// Verify the operation was marked as terminated.
	op.mu.Lock()
	terminated := op.terminated
	op.mu.Unlock()
	if !terminated {
		t.Fatal("operation should be terminated when started is false")
	}

	// Verify op.done is closed (by the handler calling fail).
	// In the real flow, the handler checks terminated and calls fail.
	// Here we simulate that.
	op.fail("docker_build_failed", "build cancelled: daemon is shutting down", nil)

	select {
	case <-op.done:
	case <-time.After(1 * time.Second):
		t.Fatal("op.done should be closed")
	}
}

// TestLifecycleRaceProcessStartedBeforeShutdown verifies that when
// cmd.Start() has already succeeded before shutdown, the process is
// properly terminated by terminateAll.
func TestLifecycleRaceProcessStartedBeforeShutdown(t *testing.T) {
	app := newTestAppWithAuth(t)
	reg := newOperationRegistry()
	app.OperationRegistry = reg

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sleep", "60")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := reg.get(opID)
	if op == nil {
		t.Fatal("operation should be in registry")
	}

	// Wait for process to start.
	time.Sleep(200 * time.Millisecond)

	// Verify process is running and started flag is set.
	op.mu.Lock()
	if !op.started {
		op.mu.Unlock()
		t.Fatal("started flag should be set after cmd.Start()")
	}
	if op.cmd == nil || op.cmd.Process == nil {
		op.mu.Unlock()
		t.Fatal("process should be running")
	}
	pid := op.cmd.Process.Pid
	op.mu.Unlock()

	// Trigger shutdown.
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

	// Verify process is terminated.
	if process, _ := os.FindProcess(pid); process != nil {
		if err := process.Signal(nil); err == nil {
			t.Error("process should be terminated")
		}
	}
}
