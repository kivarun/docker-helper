package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestLifecycleRaceProcessNotStartedAfterShutdown verifies that when
// a build operation is registered but the process start is delayed,
// shutdown will mark it as terminated and prevent the process from
// starting unmanaged after shutdown has passed.
func TestLifecycleRaceProcessNotStartedAfterShutdown(t *testing.T) {
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

	// Block ExecCommandContext so we can trigger shutdown between
	// registration and process start. The handler will be blocked here:
	//   tryCreate(op) → newBuildCmd (blocked) → terminateAll → op.terminated = true
	cmdBlocked := make(chan struct{})
	cmdReady := make(chan struct{})
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmdBlocked <- struct{}{}
		<-cmdReady
		return exec.CommandContext(ctx, "/bin/sleep", "60")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()

	// Start build handler in a goroutine.
	var handlerWg sync.WaitGroup
	handlerWg.Add(1)
	go func() {
		defer handlerWg.Done()
		app.handleBuild(w, req)
	}()

	// Wait for the handler to block on ExecCommandContext.
	select {
	case <-cmdBlocked:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not reach ExecCommandContext")
	}

	// Trigger shutdown: the operation is registered but cmd is nil.
	reg.setShuttingDown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	reg.terminateAll(shutdownCtx)
	cancel()

	// Unblock the handler — it should detect op.terminated and not start.
	close(cmdReady)

	// Wait for the handler to complete.
	handlerWg.Wait()

	// Verify the response.
	if w.Code != http.StatusCreated {
		t.Errorf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := reg.get(opID)
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

	// Wait for the process to actually start by polling op.started.
	for i := 0; i < 50; i++ {
		op.mu.Lock()
		started := op.started
		op.mu.Unlock()
		if started {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Verify the process is running.
	op.mu.Lock()
	if !op.started || op.cmd == nil || op.cmd.Process == nil {
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

	// Wait for the completion goroutine to reap the process.
	select {
	case <-op.done:
	case <-time.After(5 * time.Second):
		t.Fatal("op.done was not closed")
	}

	// Verify the process was terminated.
	if op.State != operationFailed {
		t.Errorf("expected status 'failed', got %q", op.State)
	}

	// Verify the process is no longer running.
	if processStillRunning(pid) {
		t.Error("process should be terminated")
	}
}

func processStillRunning(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Send signal 0 to check if process exists.
	return p.Signal(nil) == nil
}
