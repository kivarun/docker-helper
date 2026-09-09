package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestMountSourceDotMountsWorkspace(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/workspace"},
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	mounts := captured.lastSpec().Mounts
	if len(mounts) != 1 || mounts[0].Target != "/workspace" || mounts[0].Source == "" {
		t.Errorf("mounts = %+v", mounts)
	}
}

func TestMountRelativeSubdir(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.OperationSupervisor = newOperationSupervisor()
	mockDetectLSM(t, LSMAppArmor, nil)
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			PinnedPath: sourcePath,
			cleanup:    func() error { return nil },
		}, nil
	}

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	inner := filepath.Join(result.Session.Workspace, "inner")
	if err := os.MkdirAll(inner, 0755); err != nil {
		t.Fatalf("cannot create inner: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "inner", "target": "/data"},
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	mounts := captured.lastSpec().Mounts
	if len(mounts) != 1 || mounts[0].Target != "/data" {
		t.Errorf("mounts = %+v", mounts)
	}
}

func TestMountRegularFile(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.OperationSupervisor = newOperationSupervisor()
	mockDetectLSM(t, LSMAppArmor, nil)
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			PinnedPath: sourcePath,
			cleanup:    func() error { return nil },
		}, nil
	}

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	testFile := filepath.Join(result.Session.Workspace, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("cannot create test file: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "test.txt", "target": "/app/config.txt"},
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	mounts := captured.lastSpec().Mounts
	if len(mounts) != 1 || mounts[0].Target != "/app/config.txt" {
		t.Errorf("mounts = %+v", mounts)
	}
}

func TestMountReadOnly(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/workspace", "read_only": true},
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	mounts := captured.lastSpec().Mounts
	if len(mounts) != 1 || !mounts[0].ReadOnly {
		t.Errorf("mounts = %+v, want read-only", mounts)
	}
}

func TestMountSameSourceDifferentTargets(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/workspace"},
			{"source": ".", "target": "/backup"},
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	mounts := captured.lastSpec().Mounts
	if len(mounts) != 2 || mounts[0].Target != "/workspace" || mounts[1].Target != "/backup" {
		t.Errorf("mounts = %+v, want /workspace and /backup", mounts)
	}
}

func TestMountDuplicateTarget(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/workspace"},
			{"source": ".", "target": "/workspace"},
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	resp := decodeRunResponse(t, w)
	if resp.Code != "invalid_mount" {
		t.Errorf("expected code 'invalid_mount', got %q", resp.Code)
	}

	if captured.reached() {
		t.Error("Engine runner must not be called for duplicate targets")
	}
}

func TestMountAbsoluteSource(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "/etc/passwd", "target": "/workspace/passwd"},
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestMountEmptySource(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "", "target": "/workspace"},
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestMountNonExistentSource(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "does-not-exist", "target": "/workspace"},
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestMountSymlinkEscape(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	escapeDir := t.TempDir()
	linkPath := filepath.Join(app.Config.AllowedRoots[0], "escape-link")

	if err := os.Symlink(escapeDir, linkPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "escape-link", "target": "/workspace"},
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestMountRelativeTarget(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "relative/path"},
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestMountEmptyTarget(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": ""},
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestMountTargetRoot(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/"},
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	mounts := captured.lastSpec().Mounts
	if len(mounts) != 1 || mounts[0].Target != "/" {
		t.Errorf("mounts = %+v, want target /", mounts)
	}
}

func TestDockerSecurityOpt(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine:latest"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	spec := captured.lastSpec()
	if len(spec.SecurityOpt) != 1 || spec.SecurityOpt[0] != "label=disable" {
		t.Errorf("securityOpt = %+v, want [label=disable]", spec.SecurityOpt)
	}
}

func TestRunSELinuxSystemModeCustomLabel(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	// Mock SELinux enforcing
	origSEL := selinuxEnabled
	origAA := appArmorLSMActive
	selinuxEnabled = func() (bool, bool, error) { return true, true, nil }
	appArmorLSMActive = func() (bool, error) { return false, nil }
	t.Cleanup(func() {
		selinuxEnabled = origSEL
		appArmorLSMActive = origAA
	})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine:latest"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	spec := captured.lastSpec()
	if len(spec.SecurityOpt) != 1 || spec.SecurityOpt[0] != "label=type:docker_helper_container_t" {
		t.Errorf("securityOpt = %+v, want [label=type:docker_helper_container_t]", spec.SecurityOpt)
	}
}

func TestRunAppArmorContainerSecurityOpt(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	// Mock AppArmor active, SELinux inactive
	origSEL := selinuxEnabled
	origAA := appArmorLSMActive
	selinuxEnabled = func() (bool, bool, error) { return false, false, nil }
	appArmorLSMActive = func() (bool, error) { return true, nil }
	t.Cleanup(func() {
		selinuxEnabled = origSEL
		appArmorLSMActive = origAA
	})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine:latest"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	spec := captured.lastSpec()
	if len(spec.SecurityOpt) != 1 || spec.SecurityOpt[0] != "label=disable" {
		t.Errorf("securityOpt = %+v, want [label=disable]", spec.SecurityOpt)
	}
}

func TestRunLSMDetectionErrorFailsClosed(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	app.OperationSupervisor = newOperationSupervisor()

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	// Mock LSM detection error
	origSEL := selinuxEnabled
	origAA := appArmorLSMActive
	selinuxEnabled = func() (bool, bool, error) { return false, false, fmt.Errorf("test error") }
	appArmorLSMActive = func() (bool, error) { return false, nil }
	t.Cleanup(func() {
		selinuxEnabled = origSEL
		appArmorLSMActive = origAA
	})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine:latest"})

	if captured.reached() {
		t.Error("Engine runner must not be called when LSM detection fails")
	}

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	// No operation may be registered by a failed run.
	app.OperationSupervisor.mu.RLock()
	currentOps := len(app.OperationSupervisor.ops)
	app.OperationSupervisor.mu.RUnlock()
	if currentOps != 0 {
		t.Errorf("supervisor modified by LSM detection failure: got %d ops", currentOps)
	}
}

func TestRunLSMNoneFailsClosed(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	app.OperationSupervisor = newOperationSupervisor()

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	// Mock: no MAC backend active (LSMNone)
	origSEL := selinuxEnabled
	origAA := appArmorLSMActive
	selinuxEnabled = func() (bool, bool, error) { return false, false, nil }
	appArmorLSMActive = func() (bool, error) { return false, nil }
	t.Cleanup(func() {
		selinuxEnabled = origSEL
		appArmorLSMActive = origAA
	})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine:latest"})

	if captured.reached() {
		t.Error("Engine runner must not be called when no MAC backend is active")
	}

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	app.OperationSupervisor.mu.RLock()
	currentOps := len(app.OperationSupervisor.ops)
	app.OperationSupervisor.mu.RUnlock()
	if currentOps != 0 {
		t.Errorf("supervisor must not be modified when LSMNone: got %d ops", currentOps)
	}
}

func TestDockerUser(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine:latest"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// The expected Docker --user identity is the owning Principal's UID:GID,
	// resolved through the Session's Launcher. It is not derived from an
	// unrelated assumption about a hard-coded daemon identity.
	uid, gid, err := resolveSessionExecutionIdentity(app.DB, &result.Session)
	if err != nil {
		t.Fatalf("resolveSessionExecutionIdentity() error: %v", err)
	}
	expected := fmt.Sprintf("%d:%d", uid, gid)

	if spec := captured.lastSpec(); spec.User != expected {
		t.Errorf("user = %q, want %q", spec.User, expected)
	}
}

func TestMountValidationPreventsRunCommand(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "/etc/passwd", "target": "/workspace"},
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	if captured.reached() {
		t.Error("Engine runner must not be called with an invalid mount")
	}
}

func TestMountCommaInTarget(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/data,readonly"},
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	resp := decodeRunResponse(t, w)
	if resp.Code != "invalid_mount" {
		t.Errorf("expected code 'invalid_mount', got %q", resp.Code)
	}

	if captured.reached() {
		t.Error("Engine runner must not be called with comma in target")
	}
}

func TestMountCommaInSource(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	commaDir := filepath.Join(app.Config.AllowedRoots[0], "dir,with,commas")
	if err := os.MkdirAll(commaDir, 0755); err != nil {
		t.Fatalf("cannot create comma dir: %v", err)
	}

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "dir,with,commas", "target": "/data"},
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	resp := decodeRunResponse(t, w)
	if resp.Code != "invalid_mount" {
		t.Errorf("expected code 'invalid_mount', got %q", resp.Code)
	}

	if captured.reached() {
		t.Error("Engine runner must not be called with comma in source")
	}
}

func TestMountDuplicateTargetAfterClean(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/data"},
			{"source": ".", "target": "/data/."},
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	resp := decodeRunResponse(t, w)
	if resp.Code != "invalid_mount" {
		t.Errorf("expected code 'invalid_mount', got %q", resp.Code)
	}

	if captured.reached() {
		t.Error("Engine runner must not be called with duplicate targets")
	}
}

func TestMountNormalizedTargetInRunSpec(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/data/."},
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	mounts := captured.lastSpec().Mounts
	if len(mounts) != 1 || mounts[0].Target != "/data" {
		t.Errorf("mounts = %+v, want normalized target /data", mounts)
	}
}
