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

// TestCmdStartRaceShutdownBeforeStart verifies that when shutdown acquires
// the coordination boundary before cmd.Start(), the process does not start.
// This is deterministic: the handler blocks on op.mu while terminateAll
// sets terminated=true, then the handler sees terminated and aborts.
func TestCmdStartRaceShutdownBeforeStart(t *testing.T) {
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

	// Block the handler at the point where it holds op.mu about to call Start().
	// We use a custom ExecCommandContext that signals when cmd is ready,
	// then blocks until we allow it to proceed.
	cmdReady := make(chan struct{})
	cmdProceed := make(chan struct{})
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		close(cmdReady)
		<-cmdProceed
		return exec.CommandContext(ctx, "/bin/sleep", "60")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()

	var handlerDone sync.WaitGroup
	handlerDone.Add(1)
	go func() {
		defer handlerDone.Done()
		app.handleBuild(w, req)
	}()

	// Wait for cmd to be ready (handler blocked waiting for cmdProceed).
	select {
	case <-cmdReady:
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
	handlerDone.Wait()

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

	// Verify started flag.
	op.mu.Lock()
	if !op.started {
		op.mu.Unlock()
		t.Fatal("started should be true")
	}
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
}

// TestCmdStartRaceForceKillIgnoringSignal verifies that a process that
// ignores graceful SIGTERM is force-killed after the deadline, even when
// it was properly started before shutdown.
func TestCmdStartRaceForceKillIgnoringSignal(t *testing.T) {
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
		return exec.CommandContext(ctx, "/bin/sh", "-c", "trap '' TERM; sleep 60")
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
