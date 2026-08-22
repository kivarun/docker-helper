package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRunMountUserModeAcceptsWorkspaceRoot(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeUser
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"alpine","mounts":[{"source":".","target":"/data"}]}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
}

func TestRunMountUserModeAcceptsSymlinkToWorkspaceRoot(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeUser
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Create a symlink inside workspace that points to the workspace root.
	linkPath := filepath.Join(result.Session.Workspace, "self-link")
	if err := os.Symlink(result.Session.Workspace, linkPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"alpine","mounts":[{"source":"self-link","target":"/data"}]}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
}

func TestRunMountUserModeRejectsSubdirectory(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeUser

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	dockerCalled := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		dockerCalled = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"alpine","mounts":[{"source":"subdir","target":"/data"}]}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "invalid_mount" {
		t.Errorf("expected code 'invalid_mount', got %q", resp.Code)
	}

	if dockerCalled {
		t.Error("docker should not be called after user-mode mount rejection")
	}
}

func TestRunMountUserModeRejectsFile(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeUser

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	filePath := filepath.Join(result.Session.Workspace, "testfile.txt")
	if err := os.WriteFile(filePath, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"alpine","mounts":[{"source":"testfile.txt","target":"/data"}]}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "invalid_mount" {
		t.Errorf("expected code 'invalid_mount', got %q", resp.Code)
	}
}

func TestRunMountSystemModeAcceptsSubdirectory(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeSystem
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	// Mock PinMount to return a fake pinnedMount.
	app.PinMountFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			HostPath: sourcePath,
			cleanup:  func() error { return nil },
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"alpine","mounts":[{"source":"subdir","target":"/data"}]}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}
}

func TestRunMountUserModeRejectionDoesNotCreateOperation(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeUser
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"alpine","mounts":[{"source":"subdir","target":"/data"}]}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	if len(app.OperationRegistry.ops) != 0 {
		t.Error("operation should not be created after user-mode mount rejection")
	}
}

// getLastOp returns the first operation from the registry (there should be exactly one).
func getLastOp(reg *operationRegistry) *operation {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	for _, op := range reg.ops {
		return op
	}
	return nil
}

// TestRunSecondPinError cleans first pin, registry empty, Docker not called.
func TestRunSecondPinError(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeSystem
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir1 := filepath.Join(result.Session.Workspace, "subdir1")
	subdir2 := filepath.Join(result.Session.Workspace, "subdir2")
	if err := os.MkdirAll(subdir1, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(subdir2, 0755); err != nil {
		t.Fatal(err)
	}

	cleanupOrder := []string{}
	callCount := 0
	app.PinMountFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		callCount++
		if mountIndex == 1 {
			return nil, errors.New("second pin failed")
		}
		return &pinnedMount{
			HostPath: fmt.Sprintf("/pinned/%d", mountIndex),
			cleanup: func() error {
				cleanupOrder = append(cleanupOrder, fmt.Sprintf("pin-%d", mountIndex))
				return nil
			},
		}, nil
	}

	dockerCalled := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		dockerCalled = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{
		"image":"alpine",
		"mounts":[
			{"source":"subdir1","target":"/data1"},
			{"source":"subdir2","target":"/data2"}
		]
	}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// First pin should be cleaned up.
	if len(cleanupOrder) != 1 || cleanupOrder[0] != "pin-0" {
		t.Errorf("cleanup order = %v, want [pin-0]", cleanupOrder)
	}

	// Registry should be empty — operation never registered.
	if len(app.OperationRegistry.ops) != 0 {
		t.Error("registry should be empty after pin error")
	}

	// Docker should not be called.
	if dockerCalled {
		t.Error("docker should not be called after pin error")
	}
}

// TestRunRegistryShuttingDown cleans pins, registry does not receive operation.
func TestRunRegistryShuttingDown(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeSystem
	reg := newOperationRegistry()
	reg.setShuttingDown()
	app.OperationRegistry = reg

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	cleanupCalled := false
	app.PinMountFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			HostPath: "/pinned/0",
			cleanup: func() error {
				cleanupCalled = true
				return nil
			},
		}, nil
	}

	dockerCalled := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		dockerCalled = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{
		"image":"alpine",
		"mounts":[{"source":"subdir","target":"/data"}]
	}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}

	// Pins should be cleaned up.
	if !cleanupCalled {
		t.Error("pins should be cleaned up when registry is shutting down")
	}

	// Registry should not contain the operation.
	if len(reg.ops) != 0 {
		t.Error("registry should not receive operation when shutting down")
	}

	// Docker should not be called.
	if dockerCalled {
		t.Error("docker should not be called when registry is shutting down")
	}
}

// TestRunSystemModeEmptyRuntimeDir does not pass original path to Docker.
func TestRunSystemModeEmptyRuntimeDir(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeSystem
	app.Config.RuntimeDir = ""
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	// PinMountFn should be called (fail-closed), and should fail
	// because RuntimeDir is empty.
	pinMountCalled := false
	app.PinMountFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinMountCalled = true
		return nil, fmt.Errorf("runtimeDir must be absolute: %q", runtimeDir)
	}

	dockerCalled := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		dockerCalled = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{
		"image":"alpine",
		"mounts":[{"source":"subdir","target":"/data"}]
	}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// PinMount must have been called (no RuntimeDir shortcut).
	if !pinMountCalled {
		t.Error("PinMountFn should be called regardless of RuntimeDir")
	}

	// Docker should not be called.
	if dockerCalled {
		t.Error("docker should not be called when pinning fails")
	}

	// Registry should be empty.
	if len(app.OperationRegistry.ops) != 0 {
		t.Error("registry should be empty after pin error")
	}
}

// TestRunSystemModeArgvContainsStablePaths verifies Docker receives pinned paths.
func TestRunSystemModeArgvContainsStablePaths(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeSystem
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	srcFile := filepath.Join(result.Session.Workspace, "srcfile.txt")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcFile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	stablePaths := []string{"/runtime/pinned/0", "/runtime/pinned/1"}
	app.PinMountFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			HostPath: stablePaths[mountIndex],
			cleanup:  func() error { return nil },
		}, nil
	}

	var dockerArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		dockerArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{
		"image":"alpine",
		"mounts":[
			{"source":"subdir","target":"/data1"},
			{"source":"srcfile.txt","target":"/data2"}
		]
	}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Build the args string to search in.
	argsStr := strings.Join(dockerArgs, " ")

	// Stable paths should be present.
	for _, sp := range stablePaths {
		if !strings.Contains(argsStr, sp) {
			t.Errorf("argv should contain stable path %q, got: %v", sp, dockerArgs)
		}
	}

	// Original paths should NOT be present.
	if strings.Contains(argsStr, subdir) {
		t.Errorf("argv should not contain original directory path %q", subdir)
	}
	if strings.Contains(argsStr, srcFile) {
		t.Errorf("argv should not contain original file path %q", srcFile)
	}
}

// TestRunUserModeDoesNotCallPinMount verifies user mode skips pinning.
func TestRunUserModeDoesNotCallPinMount(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeUser
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	pinMountCalled := false
	app.PinMountFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinMountCalled = true
		return nil, errors.New("should not be called")
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{
		"image":"alpine",
		"mounts":[{"source":".","target":"/data"}]
	}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	if pinMountCalled {
		t.Error("PinMountFn should not be called in user mode")
	}
}

// TestRunStartErrorCleansPinsOnce verifies cleanup on cmd.Start failure.
func TestRunStartErrorCleansPinsOnce(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeSystem
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	cleanupCount := int32(0)
	app.PinMountFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			HostPath: fmt.Sprintf("/pinned/%d", mountIndex),
			cleanup: func() error {
				atomic.AddInt32(&cleanupCount, 1)
				return nil
			},
		}, nil
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, "nonexistent_binary_that_fails")
		return cmd
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{
		"image":"alpine",
		"mounts":[{"source":"subdir","target":"/data"}]
	}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	// Wait for the operation to complete.
	op := getLastOp(app.OperationRegistry)
	if op != nil {
		op.Wait()
	}

	count := atomic.LoadInt32(&cleanupCount)
	if count != 1 {
		t.Errorf("cleanup called %d times, want 1", count)
	}
}

// TestRunNormalCompletionCleansPinsOnce verifies cleanup after cmd.Wait.
func TestRunNormalCompletionCleansPinsOnce(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeSystem
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	cleanupCount := int32(0)
	app.PinMountFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			HostPath: fmt.Sprintf("/pinned/%d", mountIndex),
			cleanup: func() error {
				atomic.AddInt32(&cleanupCount, 1)
				return nil
			},
		}, nil
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{
		"image":"alpine",
		"mounts":[{"source":"subdir","target":"/data"}]
	}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	// Wait for the operation to complete.
	op := getLastOp(app.OperationRegistry)
	if op != nil {
		op.Wait()
	}

	count := atomic.LoadInt32(&cleanupCount)
	if count != 1 {
		t.Errorf("cleanup called %d times, want 1", count)
	}
}

// TestRunCleanupReverseOrder verifies cleanup runs in reverse mount order.
func TestRunCleanupReverseOrder(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeSystem
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir1 := filepath.Join(result.Session.Workspace, "subdir1")
	subdir2 := filepath.Join(result.Session.Workspace, "subdir2")
	subdir3 := filepath.Join(result.Session.Workspace, "subdir3")
	for _, d := range []string{subdir1, subdir2, subdir3} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	cleanupOrder := []int{}
	app.PinMountFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		mi := mountIndex
		return &pinnedMount{
			HostPath: fmt.Sprintf("/pinned/%d", mountIndex),
			cleanup: func() error {
				cleanupOrder = append(cleanupOrder, mi)
				return nil
			},
		}, nil
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{
		"image":"alpine",
		"mounts":[
			{"source":"subdir1","target":"/data1"},
			{"source":"subdir2","target":"/data2"},
			{"source":"subdir3","target":"/data3"}
		]
	}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	// Wait for the operation to complete.
	op := getLastOp(app.OperationRegistry)
	if op != nil {
		op.Wait()
	}

	expectedOrder := []int{2, 1, 0}
	if len(cleanupOrder) != len(expectedOrder) {
		t.Errorf("cleanup order = %v, want %v", cleanupOrder, expectedOrder)
	} else {
		for i := range expectedOrder {
			if cleanupOrder[i] != expectedOrder[i] {
				t.Errorf("cleanup order = %v, want %v", cleanupOrder, expectedOrder)
				break
			}
		}
	}
}

// TestRunCleanupErrorDoesNotChangeResult verifies cleanup error doesn't
// override the operation result.
func TestRunCleanupErrorDoesNotChangeResult(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeSystem
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	app.PinMountFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			HostPath: "/pinned/0",
			cleanup:  func() error { return errors.New("cleanup failed") },
		}, nil
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{
		"image":"alpine",
		"mounts":[{"source":"subdir","target":"/data"}]
	}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	// Wait for the operation to complete.
	op := getLastOp(app.OperationRegistry)
	if op != nil {
		op.Wait()
		op.mu.Lock()
		state := op.State
		resultCode := ""
		if op.ResultCode != nil {
			resultCode = *op.ResultCode
		}
		op.mu.Unlock()

		if state != operationSucceeded {
			t.Errorf("operation state = %s, want succeeded (cleanup error should not change result)", state)
		}
		if resultCode != "succeeded" {
			t.Errorf("result code = %s, want succeeded", resultCode)
		}
	}
}

// TestRunAuditContainsUserSourcePaths verifies audit uses user-provided
// source paths, not stable runtime paths.
func TestRunAuditContainsUserSourcePaths(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.Config.Mode = ModeSystem
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	app.PinMountFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			HostPath: "/runtime/pinned/0",
			cleanup:  func() error { return nil },
		}, nil
	}

	// Capture audit via operation's auditMounts field.
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{
		"image":"alpine",
		"mounts":[{"source":"subdir","target":"/data"}]
	}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	// Wait for the operation to complete.
	op := getLastOp(app.OperationRegistry)
	if op != nil {
		op.Wait()
	}

	if op == nil {
		t.Fatal("no operation found in registry")
	}
	op.mu.Lock()
	defer op.mu.Unlock()

	if len(op.auditMounts) != 1 {
		t.Fatalf("expected 1 audit mount, got %d", len(op.auditMounts))
	}

	// Audit should contain user source, not stable runtime path.
	if op.auditMounts[0].Source != "subdir" {
		t.Errorf("audit mount source = %q, want %q", op.auditMounts[0].Source, "subdir")
	}
	if strings.Contains(op.auditMounts[0].Source, "/runtime/") {
		t.Errorf("audit should not contain runtime path: %q", op.auditMounts[0].Source)
	}
}
