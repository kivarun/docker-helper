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

// TestShutdownIntegrationRunningOpIsTerminated is an integration regression
// test that confirms a running build operation actually reaches terminateAll
// during shutdown, not just the unit-test of terminateAll in isolation.
//
// It simulates the full shutdown path: signal → serveWithShutdown returns
// → setShuttingDown → terminateAll with deadline context.
func TestShutdownIntegrationRunningOpIsTerminated(t *testing.T) {
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

	// Process that runs for a while.
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
		t.Fatal("operation not found")
	}

	// Give process time to start.
	time.Sleep(100 * time.Millisecond)

	// Verify operation is running before shutdown.
	if op.State != operationRunning {
		t.Fatalf("expected status 'running', got %q", op.State)
	}

	// Simulate the full shutdown path from main.go:
	// 1. setShuttingDown (prevent new builds)
	reg.setShuttingDown()

	// 2. terminateAll with a deadline context (shared with HTTP drain)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	reg.terminateAll(shutdownCtx)
	cancel()

	// 3. Verify the operation was terminated.
	select {
	case <-op.done:
		// Good - terminateAll reached the operation.
	case <-time.After(5 * time.Second):
		t.Fatal("op.done was not closed - terminateAll did not reach the running operation")
	}

	if op.State != operationFailed {
		t.Errorf("expected status 'failed', got %q", op.State)
	}
}

// TestShutdownIntegrationNewBuildRejectedAfterSetShuttingDown confirms that
// once setShuttingDown is called, new build requests are rejected.
func TestShutdownIntegrationNewBuildRejectedAfterSetShuttingDown(t *testing.T) {
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

	// Mark registry as shutting down before any build.
	reg.setShuttingDown()

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected %d after shutdown, got %d", http.StatusServiceUnavailable, w.Code)
	}
}
