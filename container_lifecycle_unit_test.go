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
	"sync"
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

func TestCidfileCreatedAndCleanedUpOnNormalCompletion(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
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
	op := app.OperationSupervisor.lookup(opID)
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
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
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
	op := app.OperationSupervisor.lookup(opID)
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

func TestKillContainerBestEffortDoesNotPanicOnMissingDocker(t *testing.T) {
	// Verify that killContainerBestEffort handles errors gracefully.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("killContainerBestEffort panicked: %v", r)
		}
	}()

	// Use a minimal App to test the method.
	app := &App{}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	app.killContainerBestEffort(ctx, "nonexistent_container_id")
}

func TestCidfileNotExposedInHTTPResponse(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
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

// TestCidfileRaceDelayedPublication verifies that when the cidfile is not
// immediately available after cmd.Start(), the cleanup phase waits for it
// within a bounded context, and performs daemon-side kill when it appears.
func TestCidfileRaceDelayedPublication(t *testing.T) {
	app := newTestAppWithAuth(t)
	supervisor := newOperationSupervisor()
	app.OperationSupervisor = supervisor

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Track docker kill calls.
	var killCalled int32
	var killContainerID string
	var mu sync.Mutex

	// Fake kill callback passed directly to terminateForShutdown.
	fakeKill := func(ctx context.Context, id string) {
		mu.Lock()
		killCalled++
		killContainerID = id
		mu.Unlock()
	}

	// Use a readiness marker so we know the process is running.
	readyFile := filepath.Join(app.Config.AllowedRoots[0], ".race_ready")
	defer os.Remove(readyFile)

	var cidfilePath string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		for i, arg := range args {
			if arg == "--cidfile" && i+1 < len(args) {
				cidfilePath = args[i+1]
				break
			}
		}
		// Build and run the SIGTERM-ignoring helper.
		helperBin := filepath.Join(t.TempDir(), "helper")
		if err := exec.Command("go", "build", "-o", helperBin, "testhelper_ignore_sigterm.go").Run(); err != nil {
			t.Logf("failed to build helper: %v", err)
			return exec.CommandContext(ctx, "/bin/sleep", "60")
		}
		cmd := exec.CommandContext(ctx, helperBin)
		cmd.Env = append(os.Environ(), "READY_FILE="+readyFile)
		return cmd
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sleep", "300"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := supervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found")
	}

	// Wait for the process to signal readiness.
	waitProcessReady(t, readyFile)

	// Verify cidfile path is set but file doesn't exist yet (simulating race).
	if op.cidfile == "" {
		t.Fatal("cidfile path should be set")
	}
	if _, err := os.Stat(op.cidfile); !os.IsNotExist(err) {
		t.Fatal("cidfile should not exist yet (simulating delayed publication)")
	}

	// Start shutdown with short deadline to trigger force cleanup.
	supervisor.beginShutdown()

	// In a separate goroutine, publish the cidfile after a short delay.
	// This simulates Docker daemon publishing the container ID after cmd.Start().
	containerID := "test_container_abc123"
	go func() {
		time.Sleep(50 * time.Millisecond)
		os.WriteFile(cidfilePath, []byte(containerID+"\n"), 0644)
	}()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	supervisor.terminateForShutdown(shutdownCtx, fakeKill)
	cancel()

	// Wait for operation to complete.
	select {
	case <-op.done:
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not complete")
	}

	// Verify docker kill was called with the correct container ID.
	mu.Lock()
	if killCalled != 1 {
		t.Errorf("expected exactly 1 docker kill call, got %d", killCalled)
	}
	if killContainerID != containerID {
		t.Errorf("expected docker kill with %q, got %q", containerID, killContainerID)
	}
	mu.Unlock()

	if op.State != operationFailed {
		t.Errorf("expected failed, got %q", op.State)
	}
}

// TestCidfileRaceContextExpiresWithoutCidfile verifies that when the cleanup
// context expires before the cidfile appears, shutdown still proceeds with
// CLI kill and doesn't hang.
func TestCidfileRaceContextExpiresWithoutCidfile(t *testing.T) {
	app := newTestAppWithAuth(t)
	supervisor := newOperationSupervisor()
	app.OperationSupervisor = supervisor

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sleep", "60")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sleep", "300"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := supervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found")
	}

	// Start shutdown with very short deadline.
	supervisor.beginShutdown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	startTime := time.Now()
	supervisor.terminateForShutdown(shutdownCtx, nil)
	cancel()
	elapsed := time.Since(startTime)

	// terminateForShutdown should not hang — it should complete within the cleanup budget.
	if elapsed > 5*time.Second {
		t.Errorf("terminateForShutdown took too long: %v (should be bounded)", elapsed)
	}

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

// TestWaitForContainerIDReturnsOnDone verifies that waitForContainerID
// returns empty string when the operation completes during polling.
func TestWaitForContainerIDReturnsOnDone(t *testing.T) {
	op := newRunOperation("session1", "alpine:latest", 1024, "")
	op.cidfile = filepath.Join(t.TempDir(), op.ID+".cid")

	// Complete the operation immediately.
	op.fail("test", "test", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	id := waitForContainerID(ctx, op)
	if id != "" {
		t.Errorf("expected empty string when operation is done, got %q", id)
	}
}

// TestWaitForContainerIDReturnsOnContextExpire verifies that waitForContainerID
// returns empty string when the context expires without the cidfile appearing.
func TestWaitForContainerIDReturnsOnContextExpire(t *testing.T) {
	op := newRunOperation("session1", "alpine:latest", 1024, "")
	op.cidfile = filepath.Join(t.TempDir(), op.ID+".cid")

	// Use a very short context.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	id := waitForContainerID(ctx, op)
	if id != "" {
		t.Errorf("expected empty string when context expires, got %q", id)
	}
}

// TestWaitForContainerIDReturnsID verifies that waitForContainerID
// returns the container ID when the cidfile is published.
func TestWaitForContainerIDReturnsID(t *testing.T) {
	op := newRunOperation("session1", "alpine:latest", 1024, "")
	cidfilePath := filepath.Join(t.TempDir(), op.ID+".cid")
	op.cidfile = cidfilePath

	// Publish the cidfile after a short delay.
	go func() {
		time.Sleep(10 * time.Millisecond)
		os.WriteFile(cidfilePath, []byte("test_container_xyz\n"), 0644)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	id := waitForContainerID(ctx, op)
	if id != "test_container_xyz" {
		t.Errorf("expected 'test_container_xyz', got %q", id)
	}
}
