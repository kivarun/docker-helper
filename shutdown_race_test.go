package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// TestShutdownGateMutexMutualExclusion verifies that tryCreate and
// setShuttingDown are mutually exclusive under the same lock.
func TestShutdownGateMutexMutualExclusion(t *testing.T) {
	reg := newOperationRegistry()

	op := &operation{
		ID:        "test_op",
		SessionID: "test_session",
		State:     operationRunning,
		CreatedAt: time.Now(),
	}

	if !reg.tryCreate(op) {
		t.Fatal("tryCreate should succeed when gate is open")
	}
	if reg.get("test_op") == nil {
		t.Fatal("operation should be registered")
	}

	reg.setShuttingDown()

	op2 := &operation{
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

	if reg.get("test_op") == nil {
		t.Fatal("pre-existing operation should remain in registry")
	}
}

// TestShutdownGateConcurrentRegistration verifies that concurrent
// tryCreate and setShuttingDown never result in a registration after
// the gate is closed.
func TestShutdownGateConcurrentRegistration(t *testing.T) {
	reg := newOperationRegistry()

	var wg sync.WaitGroup
	results := make(chan bool, 100)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			op := &operation{
				ID:        "concurrent_op_" + string(rune('0'+i)),
				SessionID: "test_session",
				State:     operationRunning,
				CreatedAt: time.Now(),
			}
			results <- reg.tryCreate(op)
		}(i)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(1 * time.Millisecond)
		reg.setShuttingDown()
	}()

	wg.Wait()
	close(results)

	var successes, failures int
	for r := range results {
		if r {
			successes++
		} else {
			failures++
		}
	}

	if successes == 0 && failures == 0 {
		t.Fatal("no results collected")
	}

	if !reg.isShuttingDown() {
		t.Fatal("registry should be shutting down")
	}

	op := &operation{
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
// the shutdown gate closes before registration, the operation is rejected
// and no process starts.
func TestShutdownRaceRegistrationRejectedAfterGateClose(t *testing.T) {
	app, reg, token := setupBuildTest(t)

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		t.Fatal("ExecCommandContext should not be called after gate closes")
		return exec.CommandContext(ctx, "true")
	}

	reg.setShuttingDown()

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected %d, got %d", http.StatusServiceUnavailable, w.Code)
	}

	if len(reg.ops) > 0 {
		t.Error("no operation should be registered after gate closes")
	}
}

// TestShutdownRaceOperationRegisteredBeforeGateClose verifies that an
// operation registered before the gate closes remains in the registry
// and is managed by the normal shutdown lifecycle (terminateAll).
func TestShutdownRaceOperationRegisteredBeforeGateClose(t *testing.T) {
	app, reg, token := setupBuildTest(t)
	app.ExecCommandContext = makeSleepCmd()

	op := startBuild(t, app, token)

	reg.setShuttingDown()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	reg.terminateAll(shutdownCtx, nil)
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
