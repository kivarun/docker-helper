package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadContainerIDFromCidfile(t *testing.T) {
	dir := t.TempDir()
	cidfile := filepath.Join(dir, "test.cid")

	// Empty file returns empty string.
	if id := readContainerIDFromCidfile(cidfile); id != "" {
		t.Errorf("expected empty string for missing file, got %q", id)
	}

	// File with container ID returns the ID.
	if err := os.WriteFile(cidfile, []byte("abc123def456\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if id := readContainerIDFromCidfile(cidfile); id != "abc123def456" {
		t.Errorf("expected 'abc123def456', got %q", id)
	}

	// Whitespace-only file returns empty string.
	if err := os.WriteFile(cidfile, []byte("  \n  \t\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if id := readContainerIDFromCidfile(cidfile); id != "" {
		t.Errorf("expected empty string for whitespace, got %q", id)
	}
}

func TestCidfilePathIsUniquePerOperation(t *testing.T) {
	dir := t.TempDir()

	op1 := newRunOperation("session1", "alpine:latest", 1024)
	op1.cidfile = filepath.Join(dir, op1.ID+".cid")

	op2 := newRunOperation("session1", "alpine:latest", 1024)
	op2.cidfile = filepath.Join(dir, op2.ID+".cid")

	if op1.cidfile == op2.cidfile {
		t.Error("cidfile paths should be unique per operation")
	}

	if op1.cidfile == "" || op2.cidfile == "" {
		t.Error("cidfile paths should not be empty")
	}

	// Verify paths are under the runtime directory.
	if !filepath.IsAbs(op1.cidfile) || !filepath.IsAbs(op2.cidfile) {
		t.Error("cidfile paths should be absolute")
	}
}

func TestCidfileCreatedAndCleanedUpOnNormalCompletion(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var cidfilePath string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		for i, arg := range args {
			if arg == "--cidfile" && i+1 < len(args) {
				cidfilePath = args[i+1]
				// Create the cidfile to simulate Docker behavior.
				os.WriteFile(cidfilePath, []byte("fake_container_id\n"), 0644)
				break
			}
		}
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"echo", "hello"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	if cidfilePath == "" {
		t.Fatal("--cidfile was not passed to docker run")
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found")
	}
	op.Wait()

	// cidfile should be cleaned up after normal completion.
	if _, err := os.Stat(cidfilePath); !os.IsNotExist(err) {
		t.Errorf("cidfile should be removed after normal completion, still exists at %s", cidfilePath)
	}
}

func TestCidfileRemovedOnFailedStart(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var cidfilePath string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		for i, arg := range args {
			if arg == "--cidfile" && i+1 < len(args) {
				cidfilePath = args[i+1]
				os.WriteFile(cidfilePath, []byte("fake_container_id\n"), 0644)
				break
			}
		}
		// Simulate failed start.
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 1")
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found")
	}
	op.Wait()

	if op.State != operationFailed {
		t.Errorf("expected failed, got %q", op.State)
	}

	// cidfile should be cleaned up even on failed start.
	if _, err := os.Stat(cidfilePath); !os.IsNotExist(err) {
		t.Errorf("cidfile should be removed after failed start, still exists at %s", cidfilePath)
	}
}

func TestMissingCidfileDuringForceCleanupDoesNotPanic(t *testing.T) {
	// Verify that readContainerIDFromCidfile handles missing files gracefully.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("readContainerIDFromCidfile panicked on missing file: %v", r)
		}
	}()

	id := readContainerIDFromCidfile("/nonexistent/path/to/cidfile")
	if id != "" {
		t.Errorf("expected empty string for missing file, got %q", id)
	}
}

func TestKillContainerBestEffortDoesNotPanicOnMissingDocker(t *testing.T) {
	// Verify that killContainerBestEffort handles errors gracefully.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("killContainerBestEffort panicked: %v", r)
		}
	}()

	// This should not panic even if docker is not available.
	killContainerBestEffort("nonexistent_container_id")
}

func TestTerminateAllWithMissingCidfileDoesNotPanic(t *testing.T) {
	app, reg, token := setupBuildTest(t)
	app.ExecCommandContext = makeSleepCmd()

	op := startBuild(t, app, token)

	// Simulate force shutdown with short deadline.
	reg.setShuttingDown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	reg.terminateAll(shutdownCtx)
	cancel()

	// Wait for operation to complete.
	select {
	case <-op.done:
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not complete")
	}

	if op.State != operationFailed {
		t.Errorf("expected failed, got %q", op.State)
	}
}

func TestCidfileNotExposedInHTTPResponse(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	body := w.Body.String()
	if strings.Contains(body, ".cid") {
		t.Errorf("cidfile path must not appear in HTTP response: %s", body)
	}
}
