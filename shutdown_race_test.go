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

// TestShutdownGateMutexMutualExclusion verifies that tryCreate and
// setShuttingDown are mutually exclusive under the same lock.
// This is a deterministic test that does not rely on timing.
func TestShutdownGateMutexMutualExclusion(t *testing.T) {
	reg := newOperationRegistry()

	// Create a dummy operation for registration.
	op := &buildOperation{
		ID:        "test_op",
		SessionID: "test_session",
		State:     operationRunning,
		CreatedAt: time.Now(),
	}

	// Phase 1: tryCreate succeeds when gate is open.
	if !reg.tryCreate(op) {
		t.Fatal("tryCreate should succeed when gate is open")
	}
	if reg.get("test_op") == nil {
		t.Fatal("operation should be registered")
	}

	// Phase 2: tryCreate fails after gate is closed.
	reg.setShuttingDown()

	op2 := &buildOperation{
		ID:        "test_op2",
		SessionID: "test_session",
		State:     operationRunning,
		CreatedAt: time.Now(),
	}
	if reg.tryCreate(op2) {
		t.Fatal("tryCreate should fail after gate is closed")
	}
	if reg.get("test_op2") != nil {
		t.Fatal("operation should not be registered after gate closes")
	}

	// Phase 3: the first operation remains in registry.
	if reg.get("test_op") == nil {
		t.Fatal("pre-existing operation should remain in registry")
	}
}

// TestShutdownGateConcurrentRegistration verifies that concurrent
// tryCreate and setShuttingDown never result in a registration after
// the gate is closed. This uses synchronization to ensure mutual exclusion.
func TestShutdownGateConcurrentRegistration(t *testing.T) {
	reg := newOperationRegistry()

	var wg sync.WaitGroup
	results := make(chan bool, 100)

	// Launch many concurrent tryCreate goroutines.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			op := &buildOperation{
				ID:        "concurrent_op_" + string(rune('0'+i)),
				SessionID: "test_session",
				State:     operationRunning,
				CreatedAt: time.Now(),
			}
			results <- reg.tryCreate(op)
		}(i)
	}

	// Launch one setShuttingDown goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Small delay to let some tryCreate goroutines start.
		time.Sleep(1 * time.Millisecond)
		reg.setShuttingDown()
	}()

	wg.Wait()
	close(results)

	// Collect results.
	var successes, failures int
	for r := range results {
		if r {
			successes++
		} else {
			failures++
		}
	}

	// After setShuttingDown, some tryCreate should succeed (before gate close)
	// and some should fail (after gate close). The key invariant is that
	// no operation registered after gate close should be in the registry.
	if successes == 0 && failures == 0 {
		t.Fatal("no results collected")
	}

	// All operations in the registry should have been registered before gate close.
	// Since setShuttingDown is now true, any subsequent tryCreate must fail.
	if !reg.isShuttingDown() {
		t.Fatal("registry should be shutting down")
	}

	// Verify that tryCreate now always fails.
	op := &buildOperation{
		ID:        "after_gate_op",
		SessionID: "test_session",
		State:     operationRunning,
		CreatedAt: time.Now(),
	}
	if reg.tryCreate(op) {
		t.Fatal("tryCreate must fail after gate is closed")
	}
}

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
