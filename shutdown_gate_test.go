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

// TestShutdownGateClosesOnSignal verifies that after the shutdown signal
// is received (simulated by beginShutdown), new operations are rejected
// while existing operations remain under shutdown lifecycle.
func TestShutdownGateClosesOnSignal(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	supervisor := newOperationSupervisor()
	app.OperationSupervisor = supervisor

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sleep", "60")
	}

	// Start an operation before the signal.
	req1 := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w1 := httptest.NewRecorder()
	app.handleBuild(w1, req1)

	if w1.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w1.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w1.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	existingOp := supervisor.lookup(opID)
	if existingOp == nil {
		t.Fatal("existing operation should be in supervisor")
	}

	// Simulate signal received — close the gate.
	supervisor.beginShutdown()

	// New operation should be rejected.
	req2 := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test2",
	}, result.Token)
	w2 := httptest.NewRecorder()
	app.handleBuild(w2, req2)

	if w2.Code != http.StatusServiceUnavailable {
		t.Errorf("expected %d after signal, got %d", http.StatusServiceUnavailable, w2.Code)
	}

	// Existing operation should still be in supervisor and managed by shutdown.
	if supervisor.lookup(opID) == nil {
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

// TestShutdownGateConcurrentBuildAndSignal verifies that a build request
// in flight when the signal arrives is handled correctly: either accepted
// (if admit completed before gate close) or rejected (if gate closed first).
func TestShutdownGateConcurrentBuildAndSignal(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	supervisor := newOperationSupervisor()
	app.OperationSupervisor = supervisor

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	// Block ExecCommandContext so we can close the gate concurrently.
	cmdBlocked := make(chan struct{})
	var cmdWg sync.WaitGroup
	cmdWg.Add(1)
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmdWg.Done()
		<-cmdBlocked
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

	// Wait for admit to complete (cmd creation blocked).
	cmdWg.Wait()

	// Close the gate concurrently.
	supervisor.beginShutdown()

	// Unblock cmd creation.
	close(cmdBlocked)

	// Wait for handler to complete.
	handlerWg.Wait()

	// The operation may have been accepted or rejected depending on timing.
	// In either case, the response should be valid.
	if w.Code == http.StatusCreated {
		var resp map[string]any
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		opID, _ := resp["operation_id"].(string)
		op := supervisor.lookup(opID)
		if op == nil {
			t.Fatal("accepted operation should be in supervisor")
		}
		// Clean up.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		supervisor.terminateForShutdown(shutdownCtx, nil)
		cancel()
		<-op.done
	} else if w.Code == http.StatusServiceUnavailable {
		// Rejected — this is also valid.
	} else {
		t.Errorf("unexpected status: %d", w.Code)
	}
}
