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

// TestShutdownRaceRegistrationRejectedAfterGateClose verifies that when
// the shutdown gate closes between isShuttingDown check and create,
// the operation is rejected and no process starts.
func TestShutdownRaceRegistrationRejectedAfterGateClose(t *testing.T) {
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

	// Block the command start so we can close the gate before registration.
	started := make(chan struct{})
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		close(started)
		// Should never be reached if registration is rejected.
		t.Fatal("ExecCommandContext should not be called after gate closes")
		return exec.CommandContext(ctx, "true")
	}

	// Close the shutdown gate before the build request registers.
	reg.setShuttingDown()

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected %d, got %d", http.StatusServiceUnavailable, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if code, _ := resp["code"].(string); code != "shutting_down" {
		t.Errorf("expected code 'shutting_down', got %q", code)
	}

	// Verify no operation was registered.
	if len(reg.ops) > 0 {
		t.Error("no operation should be registered after gate closes")
	}
}

// TestShutdownRaceOperationRegisteredBeforeGateClose verifies that an
// operation registered before the gate closes remains in the registry
// and is managed by the normal shutdown lifecycle (terminateAll).
func TestShutdownRaceOperationRegisteredBeforeGateClose(t *testing.T) {
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

	// Give process time to start.
	time.Sleep(100 * time.Millisecond)

	// Now close the gate — the operation is already registered and running.
	reg.setShuttingDown()

	// terminateAll should manage this operation.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	reg.terminateAll(shutdownCtx)
	cancel()

	select {
	case <-op.done:
	case <-time.After(5 * time.Second):
		t.Fatal("op.done was not closed")
	}

	if op.State != operationFailed {
		t.Errorf("expected status 'failed', got %q", op.State)
	}
}
