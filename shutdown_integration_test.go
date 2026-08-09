package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestShutdownIntegrationRunningOpIsTerminated is an integration regression
// test that confirms a running build operation actually reaches terminateAll
// during shutdown, not just the unit-test of terminateAll in isolation.
func TestShutdownIntegrationRunningOpIsTerminated(t *testing.T) {
	app, reg, token := setupBuildTest(t)
	app.ExecCommandContext = makeSleepCmd()

	op := startBuild(t, app, token)

	// Simulate the full shutdown path from main.go:
	reg.setShuttingDown()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	reg.terminateAll(shutdownCtx)
	cancel()

	// Verify the operation was terminated.
	select {
	case <-op.done:
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
	app, reg, token := setupBuildTest(t)

	// Mark registry as shutting down before any build.
	reg.setShuttingDown()

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected %d after shutdown, got %d", http.StatusServiceUnavailable, w.Code)
	}
}
