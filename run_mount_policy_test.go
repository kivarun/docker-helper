package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunMountUserModeAcceptsWorkspaceRoot(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeUser
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine", "mounts": []map[string]any{{"source": ".", "target": "/data"}}})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	_ = captured
}

func TestRunMountUserModeAcceptsSymlinkToWorkspaceRoot(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeUser
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Create a symlink inside workspace that points to the workspace root.
	linkPath := filepath.Join(result.Session.Workspace, "self-link")
	if err := os.Symlink(result.Session.Workspace, linkPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine", "mounts": []map[string]any{{"source": "self-link", "target": "/data"}}})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	_ = captured
}

func TestRunMountUserModeRejectsSubdirectory(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeUser

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine", "mounts": []map[string]any{{"source": "subdir", "target": "/data"}}})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	resp := decodeRunResponse(t, w)
	if resp.Code != "invalid_mount" {
		t.Errorf("expected code 'invalid_mount', got %q", resp.Code)
	}

	if captured.reached() {
		t.Error("Engine runner must not be called after user-mode mount rejection")
	}
}

func TestRunMountUserModeRejectsFile(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeUser

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	filePath := filepath.Join(result.Session.Workspace, "testfile.txt")
	if err := os.WriteFile(filePath, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine", "mounts": []map[string]any{{"source": "testfile.txt", "target": "/data"}}})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	resp := decodeRunResponse(t, w)
	if resp.Code != "invalid_mount" {
		t.Errorf("expected code 'invalid_mount', got %q", resp.Code)
	}
}

func TestRunMountSystemModeAcceptsSubdirectory(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	// Mock PinWorkspaceMountSourceFn to return a fake pinned mount.
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			PinnedPath: sourcePath,
			cleanup:    func() error { return nil },
		}, nil
	}

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine", "mounts": []map[string]any{{"source": "subdir", "target": "/data"}}})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	_ = captured
}

func TestRunMountUserModeRejectionDoesNotCreateOperation(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeUser
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine", "mounts": []map[string]any{{"source": "subdir", "target": "/data"}}})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	if len(app.OperationSupervisor.ops) != 0 {
		t.Error("operation should not be created after user-mode mount rejection")
	}

	if captured.reached() {
		t.Error("Engine runner must not be called after user-mode mount rejection")
	}
}

// TestRunSecondPinError cleans first pin, supervisor contains no operation, Engine runner not called.
func TestRunSecondPinError(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createSystemSession(t, app)
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
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		callCount++
		if mountIndex == 1 {
			return nil, errors.New("second pin failed")
		}
		return &pinnedMount{
			PinnedPath: fmt.Sprintf("/pinned/%d", mountIndex),
			cleanup: func() error {
				cleanupOrder = append(cleanupOrder, fmt.Sprintf("pin-%d", mountIndex))
				return nil
			},
		}, nil
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine",
		"mounts": []map[string]any{
			{"source": "subdir1", "target": "/data1"},
			{"source": "subdir2", "target": "/data2"},
		},
	})

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// First pin should be cleaned up.
	if len(cleanupOrder) != 1 || cleanupOrder[0] != "pin-0" {
		t.Errorf("cleanup order = %v, want [pin-0]", cleanupOrder)
	}

	// Registry should be empty — operation never registered.
	if len(app.OperationSupervisor.ops) != 0 {
		t.Error("supervisor should be empty after pin error")
	}

	// Engine runner should not be called.
	if captured.reached() {
		t.Error("Engine runner must not be called after pin error")
	}
	_ = callCount
}

// TestRunSupervisorShuttingDown: run is refused by the synchronous
// admission gate during daemon shutdown and the workspace-use lease is
// released; no pins are created.
func TestRunSupervisorShuttingDown(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.SyncExecutionCoordinator.beginShutdown()
	supervisor := newOperationSupervisor()
	app.OperationSupervisor = supervisor

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	pinCalled := false
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinCalled = true
		return &pinnedMount{PinnedPath: "/pinned/0", cleanup: func() error { return nil }}, nil
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image":  "alpine",
		"mounts": []map[string]any{{"source": "subdir", "target": "/data"}},
	})

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}

	// No pins may be created before admission.
	if pinCalled {
		t.Error("pins must not be created when the run is refused by the admission gate")
	}

	// Supervisor should not receive an operation.
	if len(supervisor.ops) != 0 {
		t.Error("supervisor should not receive operation when shutting down")
	}

	// Engine runner should not be called.
	if captured.reached() {
		t.Error("Engine runner must not be called when the run is refused")
	}
}

// TestRunRefusedWhenLauncherQuiesced proves a quiesced Launcher refuses new
// launcher-scoped synchronous run admission with the canonical code, and no
// operation is registered.
func TestRunRefusedWhenLauncherQuiesced(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	app.OperationSupervisor.quiesceLauncher(result.Session.LauncherID)

	pinCalled := false
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinCalled = true
		return &pinnedMount{PinnedPath: "/pinned/0", cleanup: func() error { return nil }}, nil
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image":  "alpine",
		"mounts": []map[string]any{{"source": "subdir", "target": "/data"}},
	})

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d (body %s)", w.Code, w.Body.String())
	}

	resp := decodeRunResponse(t, w)
	if resp.Code != "launcher_unavailable" {
		t.Errorf("expected code 'launcher_unavailable', got %q", resp.Code)
	}

	if pinCalled {
		t.Error("pins must not be created when the launcher is quiesced")
	}

	if len(app.OperationSupervisor.ops) != 0 {
		t.Error("supervisor should not receive operation when the launcher is quiesced")
	}

	if captured.reached() {
		t.Error("Engine runner must not be called when the launcher is quiesced")
	}
}

// TestRunSystemModeEmptyRuntimeDir does not pass original path to Docker.
func TestRunSystemModeEmptyRuntimeDir(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.Config.RuntimeDir = ""
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	// PinWorkspaceMountSourceFn should be called (fail-closed), and should fail
	// because RuntimeDir is empty.
	pinCalled := false
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinCalled = true
		return nil, fmt.Errorf("runtimeDir must be absolute: %q", runtimeDir)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image":  "alpine",
		"mounts": []map[string]any{{"source": "subdir", "target": "/data"}},
	})

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	// PinWorkspaceMountSourceFn must have been called (no RuntimeDir shortcut).
	if !pinCalled {
		t.Error("PinWorkspaceMountSourceFn should be called regardless of RuntimeDir")
	}

	// Engine runner should not be called.
	if captured.reached() {
		t.Error("Engine runner must not be called when pinning fails")
	}

	// Registry should be empty.
	if len(app.OperationSupervisor.ops) != 0 {
		t.Error("supervisor should be empty after pin error")
	}
}

// TestRunSystemModeSpecContainsStablePaths verifies the run spec carries the
// pinned paths, not the caller-visible workspace paths.
func TestRunSystemModeSpecContainsStablePaths(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createSystemSession(t, app)
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
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			PinnedPath: stablePaths[mountIndex],
			cleanup:    func() error { return nil },
		}, nil
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine",
		"mounts": []map[string]any{
			{"source": "subdir", "target": "/data1"},
			{"source": "srcfile.txt", "target": "/data2"},
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	spec := captured.lastSpec()

	// The spec mounts must use the pinned stable paths.
	for i, sp := range stablePaths {
		if i >= len(spec.Mounts) || spec.Mounts[i].Source != sp {
			t.Errorf("mount[%d] = %+v, want source %q", i, spec.Mounts, sp)
		}
	}

	// Original paths should NOT be present.
	for _, m := range spec.Mounts {
		if m.Source == subdir || m.Source == srcFile {
			t.Errorf("spec must not carry the original workspace path %q", m.Source)
		}
	}
}

// TestRunUserModeUsesResolvedMountSourceWithoutPinning verifies user mode skips
// workspace mount source pinning and uses the resolved source path directly.
func TestRunUserModeUsesResolvedMountSourceWithoutPinning(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeUser
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	pinCalled := false
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinCalled = true
		return nil, errors.New("should not be called")
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image":  "alpine",
		"mounts": []map[string]any{{"source": ".", "target": "/data"}},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// A: PinWorkspaceMountSourceFn must not be called in user mode.
	if pinCalled {
		t.Error("PinWorkspaceMountSourceFn should not be called in user mode")
	}

	// B: The run spec must use the resolved workspace path, not a pinned path.
	mounts := captured.lastSpec().Mounts
	if len(mounts) != 1 || mounts[0].Source != result.Session.Workspace || mounts[0].Target != "/data" {
		t.Errorf("mounts = %+v, want resolved workspace source", mounts)
	}
}

// TestRunStartErrorCleansPinsOnce verifies cleanup on Engine adapter failure.
func TestRunStartErrorCleansPinsOnce(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	cleanupCount := int32(0)
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			PinnedPath: fmt.Sprintf("/pinned/%d", mountIndex),
			cleanup: func() error {
				atomic.AddInt32(&cleanupCount, 1)
				return nil
			},
		}, nil
	}

	setupRunSeam(t, app, runSeamOptions{Err: &engineError{kind: engineErrBackendFailure, cause: errors.New("engine probe")}})

	w := postRun(t, app, result.Token, map[string]any{
		"image":  "alpine",
		"mounts": []map[string]any{{"source": "subdir", "target": "/data"}},
	})

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected %d, got %d: %s", http.StatusBadGateway, w.Code, w.Body.String())
	}

	count := atomic.LoadInt32(&cleanupCount)
	if count != 1 {
		t.Errorf("cleanup called %d times, want 1", count)
	}
}

// TestRunNormalCompletionCleansPinsOnce verifies cleanup after normal completion.
func TestRunNormalCompletionCleansPinsOnce(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	cleanupCount := int32(0)
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			PinnedPath: fmt.Sprintf("/pinned/%d", mountIndex),
			cleanup: func() error {
				atomic.AddInt32(&cleanupCount, 1)
				return nil
			},
		}, nil
	}

	setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image":  "alpine",
		"mounts": []map[string]any{{"source": "subdir", "target": "/data"}},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	count := atomic.LoadInt32(&cleanupCount)
	if count != 1 {
		t.Errorf("cleanup called %d times, want 1", count)
	}
}

// TestRunCleanupReverseOrder verifies cleanup runs in reverse mount order.
func TestRunCleanupReverseOrder(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createSystemSession(t, app)
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
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		mi := mountIndex
		return &pinnedMount{
			PinnedPath: fmt.Sprintf("/pinned/%d", mountIndex),
			cleanup: func() error {
				cleanupOrder = append(cleanupOrder, mi)
				return nil
			},
		}, nil
	}

	setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine",
		"mounts": []map[string]any{
			{"source": "subdir1", "target": "/data1"},
			{"source": "subdir2", "target": "/data2"},
			{"source": "subdir3", "target": "/data3"},
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
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
// change the run result.
func TestRunCleanupErrorDoesNotChangeResult(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			PinnedPath: "/pinned/0",
			cleanup:    func() error { return errors.New("cleanup failed") },
		}, nil
	}

	setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image":  "alpine",
		"mounts": []map[string]any{{"source": "subdir", "target": "/data"}},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	resp := decodeRunResponse(t, w)
	if !resp.OK || resp.ExitCode == nil || *resp.ExitCode != 0 {
		t.Errorf("response = %+v, want success (cleanup error must not change the result)", resp)
	}
}

// TestRunAuditContainsUserSourcePaths verifies audit uses user-provided
// source paths, not stable runtime paths.
func TestRunAuditContainsUserSourcePaths(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	mockDetectLSM(t, LSMAppArmor, nil)
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	subdir := filepath.Join(result.Session.Workspace, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			PinnedPath: "/runtime/pinned/0",
			cleanup:    func() error { return nil },
		}, nil
	}

	setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image":  "alpine",
		"mounts": []map[string]any{{"source": "subdir", "target": "/data"}},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) == 0 {
		t.Fatal("no audit records")
	}
	startRec := records[0]
	if len(startRec.Mounts) != 1 {
		t.Fatalf("expected 1 audit mount, got %d", len(startRec.Mounts))
	}

	// Audit should contain user source, not stable runtime path.
	if startRec.Mounts[0].Source != "subdir" {
		t.Errorf("audit mount source = %q, want %q", startRec.Mounts[0].Source, "subdir")
	}
	if strings.Contains(startRec.Mounts[0].Source, "/runtime/") {
		t.Errorf("audit should not contain runtime path: %q", startRec.Mounts[0].Source)
	}
}

// createSystemSession creates a Session in system mode through the canonical
// production owner (createSessionAuthorized): the owning 'default' Launcher is
// provisioned with its Principal via the production Principal-create path (the
// Principal's stored root is its home under the app's global allowed roots),
// the Admin authority selects it with the established principal selector, and
// policy resolution stays with resolveCreatePolicy. The workspace is created
// under the owner's home so it lies inside the resolved effective roots.
func createSystemSession(t *testing.T, app *App) (*CreatedSession, error) {
	t.Helper()
	const username = "runsysowner"
	home := filepath.Join(app.Config.AllowedRoots[0], "runsysowner-home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatalf("cannot create system-owner home: %v", err)
	}
	installOSUserMock(t, map[string]string{username: home})
	if _, err := createPrincipal(app.DB, username, app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(%s): %v", username, err)
	}
	workspace := testWorkspaceDir(t, home)
	return app.createSessionAuthorized(
		&operatorAuthority{class: operatorAuthorityAdmin},
		createSelector{principal: username},
		workspace,
	)
}

// TestRunVisibleToLauncherLifecycleInspection proves that a live
// synchronous run is visible to checked parent-lifecycle inspection through
// the shared Launcher-scoped admission (no second visibility mechanism):
// while the Engine work is in flight the Launcher has live work, and after
// the result it no longer does.
func TestRunVisibleToLauncherLifecycleInspection(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	proceed := make(chan struct{})
	setupRunSeam(t, app, runSeamOptions{ExitCode: 0, Block: proceed})

	done := make(chan struct{})
	go func() {
		w := postRun(t, app, result.Token, map[string]any{"image": "alpine"})
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
		close(done)
	}()

	// Wait until the Engine work is live, then inspect.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if app.SyncExecutionCoordinator.hasLiveForLauncher(result.Session.LauncherID) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !app.SyncExecutionCoordinator.hasLiveForLauncher(result.Session.LauncherID) {
		t.Fatal("the live synchronous run must be visible to Launcher lifecycle inspection")
	}

	close(proceed)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not complete")
	}

	if app.SyncExecutionCoordinator.hasLiveForLauncher(result.Session.LauncherID) {
		t.Error("the completed run must no longer be visible to Launcher lifecycle inspection")
	}
}
