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
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0o644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	// Default staging seam: create a minimal staging directory with the Dockerfile.
	setupStagingSeam(t, app)

	return app, reg, result.Token
}

// startBuild starts a build request and returns the operation.
// The handler is called synchronously.
func startBuild(t *testing.T, app *App, token string) *operation {
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
func startBuildConcurrent(t *testing.T, app *App, token string) (*httptest.ResponseRecorder, chan *operation, func() *operation) {
	t.Helper()
	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()

	opCh := make(chan *operation, 1)
	go func() {
		app.handleBuild(w, req)
		var resp map[string]any
		if err := json.NewDecoder(w.Body).Decode(&resp); err == nil {
			if opID, ok := resp["operation_id"].(string); ok {
				opCh <- app.OperationRegistry.get(opID)
			}
		}
	}()

	return w, opCh, func() *operation {
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
// ignoring SIGTERM. It uses a pre-built helper binary that ignores SIGTERM,
// signals readiness via a file, then blocks.
func makeIgnoringSignalCmd(t *testing.T, readyFile string) func(context.Context, string, ...string) *exec.Cmd {
	// Build the helper binary once per test.
	helperBin := filepath.Join(t.TempDir(), "helper")
	if err := exec.Command("go", "build", "-o", helperBin, "testhelper_ignore_sigterm.go").Run(); err != nil {
		t.Fatalf("failed to build helper binary: %v", err)
	}

	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, helperBin)
		cmd.Env = append(os.Environ(), "READY_FILE="+readyFile)
		return cmd
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
