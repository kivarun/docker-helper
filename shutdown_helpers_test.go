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

// setupBuildTest creates an app, supervisor, session and Dockerfile for build tests.
// setupRunSupervisorTest creates an app with a supervisor, a session, and a
// workspace, for tests that exercise legacy run operations through the
// supervisor. The caller installs its own ExecCommandContext seam before
// starting operations.
func setupRunSupervisorTest(t *testing.T) (*App, *operationSupervisor, *CreatedSession, string) {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	supervisor := newOperationSupervisor()
	app.OperationSupervisor = supervisor

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	return app, supervisor, result, result.Token
}

// startRunTestOperation starts a run request through the production handler and
// returns the registered operation. The caller must have installed an
// ExecCommandContext seam; the handler is called synchronously.
func startRunTestOperation(t *testing.T, app *App, token string) *operation {
	t.Helper()
	req := newRunRequest(map[string]any{
		"image":   "example:test",
		"command": []string{"echo", "hello"},
	}, token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)

	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	return op
}

// startRunOperationConcurrent starts a run request in a goroutine and
// returns the response recorder and the operation channel for
// synchronization.
func startRunOperationConcurrent(t *testing.T, app *App, token string) (*httptest.ResponseRecorder, chan *operation, func() *operation) {
	t.Helper()
	req := newRunRequest(map[string]any{
		"image":   "example:test",
		"command": []string{"echo", "hello"},
	}, token)
	w := httptest.NewRecorder()

	opCh := make(chan *operation, 1)
	go func() {
		app.handleRun(w, req)
		var resp map[string]any
		if err := json.NewDecoder(w.Body).Decode(&resp); err == nil {
			if opID, ok := resp["operation_id"].(string); ok {
				opCh <- app.OperationSupervisor.lookup(opID)
			}
		}
	}()

	return w, opCh, func() *operation {
		select {
		case op := <-opCh:
			return op
		case <-time.After(5 * time.Second):
			t.Fatal("run handler did not complete")
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
