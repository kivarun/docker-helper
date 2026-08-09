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

// setupBuildTest creates an app, registry, session and Dockerfile for build tests.
func setupBuildTest(t *testing.T) (*App, *operationRegistry, string) {
	t.Helper()
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

	return app, reg, result.Token
}

// startBuild starts a build request and returns the operation.
// The handler is called synchronously.
func startBuild(t *testing.T, app *App, token string) *buildOperation {
	t.Helper()
	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
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

	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found in registry")
	}
	return op
}

// startBuildConcurrent starts a build request in a goroutine and returns
// the wait group and response recorder for synchronization.
func startBuildConcurrent(t *testing.T, app *App, token string) (*httptest.ResponseRecorder, chan *buildOperation, func() *buildOperation) {
	t.Helper()
	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()

	opCh := make(chan *buildOperation, 1)
	go func() {
		app.handleBuild(w, req)
		var resp map[string]any
		if err := json.NewDecoder(w.Body).Decode(&resp); err == nil {
			if opID, ok := resp["operation_id"].(string); ok {
				opCh <- app.OperationRegistry.get(opID)
			}
		}
	}()

	return w, opCh, func() *buildOperation {
		select {
		case op := <-opCh:
			return op
		case <-time.After(5 * time.Second):
			t.Fatal("build handler did not complete")
			return nil
		}
	}
}

// waitProcessReady waits for a readiness file to appear, polling with short intervals.
// Returns immediately if the file already exists.
func waitProcessReady(t *testing.T, readyFile string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(readyFile); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := os.Stat(readyFile); err != nil {
		t.Fatal("process did not become ready in time")
	}
}

// makeSleepCmd returns an ExecCommandContext that creates a sleep process.
func makeSleepCmd() func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sleep", "60")
	}
}

// makeIgnoringSignalCmd returns an ExecCommandContext that creates a process
// ignoring SIGTERM. If readyFile is non-empty, the process writes to it after
// installing the trap, providing deterministic readiness signaling.
func makeIgnoringSignalCmd(readyFile string) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if readyFile != "" {
			return exec.CommandContext(ctx, "/bin/sh", "-c",
				"trap '' TERM; touch '"+readyFile+"'; sleep 60")
		}
		return exec.CommandContext(ctx, "/bin/sh", "-c", "trap '' TERM; sleep 60")
	}
}

// makeBlockingCmd returns an ExecCommandContext that blocks on blockCh
// before returning the command. This allows tests to control when cmd
// creation completes relative to shutdown.
func makeBlockingCmd(blockCh chan struct{}) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		<-blockCh
		return exec.CommandContext(ctx, "/bin/sleep", "60")
	}
}
