package main

import (
	"net/http"
	"testing"
)

func TestRunWorkdirPassedToEngine(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image":   "alpine:latest",
		"workdir": "/workspace",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if spec := captured.lastSpec(); spec.Workdir != "/workspace" {
		t.Errorf("workdir = %q, want /workspace", spec.Workdir)
	}
}

func TestRunNoWorkdir(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine:latest"})

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if spec := captured.lastSpec(); spec.Workdir != "" {
		t.Errorf("workdir = %q, want unset", spec.Workdir)
	}
}

func TestRunRelativeWorkdirRejected(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{
		"image":   "alpine:latest",
		"workdir": "relative/path",
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	resp := decodeRunResponse(t, w)
	if resp.Code != "invalid_workdir" {
		t.Errorf("expected code 'invalid_workdir', got %q", resp.Code)
	}

	if captured.reached() {
		t.Error("Engine runner must not be called for a rejected workdir")
	}
}
