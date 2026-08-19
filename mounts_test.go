package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMountSourceDotMountsWorkspace(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/workspace"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	found := false
	for i, arg := range capturedArgs {
		if arg == "--mount" && i+1 < len(capturedArgs) {
			spec := capturedArgs[i+1]
			if filepath.Base(spec) != "" && len(spec) > 0 {
				found = true
			}
		}
	}

	if !found {
		t.Errorf("expected --mount in args %v", capturedArgs)
	}
}

func TestMountRelativeSubdir(t *testing.T) {
	app := newTestAppWithAuth(t)

	subdir := filepath.Join(app.Config.AllowedRoot, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("cannot create subdir: %v", err)
	}

	result, err := app.createSession(subdir)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	inner := filepath.Join(subdir, "inner")
	if err := os.MkdirAll(inner, 0755); err != nil {
		t.Fatalf("cannot create inner: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "inner", "target": "/data"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}
}

func TestMountRegularFile(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	testFile := filepath.Join(result.Session.Workspace, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("cannot create test file: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "test.txt", "target": "/app/config.txt"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}
}

func TestMountReadOnly(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/workspace", "read_only": true},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	found := false
	for i, arg := range capturedArgs {
		if arg == "--mount" && i+1 < len(capturedArgs) {
			if len(capturedArgs[i+1]) > 0 && capturedArgs[i+1][len(capturedArgs[i+1])-9:] == ",readonly" {
				found = true
				break
			}
		}
	}

	if !found {
		t.Errorf("expected readonly in mount spec, args: %v", capturedArgs)
	}
}

func TestMountSameSourceDifferentTargets(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/workspace"},
			{"source": ".", "target": "/backup"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	mountCount := 0
	for _, arg := range capturedArgs {
		if arg == "--mount" {
			mountCount++
		}
	}

	if mountCount != 2 {
		t.Errorf("expected 2 mounts, got %d", mountCount)
	}
}

func TestMountDuplicateTarget(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/workspace"},
			{"source": ".", "target": "/workspace"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.Code != "invalid_mount" {
		t.Errorf("expected code 'invalid_mount', got %q", resp.Code)
	}
}

func TestMountAbsoluteSource(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "/etc/passwd", "target": "/workspace/passwd"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestMountEmptySource(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "", "target": "/workspace"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestMountNonExistentSource(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "does-not-exist", "target": "/workspace"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestMountSymlinkEscape(t *testing.T) {
	app := newTestAppWithAuth(t)

	escapeDir := t.TempDir()
	linkPath := filepath.Join(app.Config.AllowedRoot, "escape-link")

	if err := os.Symlink(escapeDir, linkPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "escape-link", "target": "/workspace"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestMountRelativeTarget(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "relative/path"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestMountEmptyTarget(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": ""},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestMountTargetRoot(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	found := false
	for i, arg := range capturedArgs {
		if arg == "--mount" && i+1 < len(capturedArgs) {
			spec := capturedArgs[i+1]
			if len(spec) > 0 && spec[len(spec)-8:] == "target=/" {
				found = true
				break
			}
		}
	}

	if !found {
		t.Errorf("expected --mount with target=/ in args %v", capturedArgs)
	}
}

func TestDockerSecurityOpt(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	found := false
	for i, arg := range capturedArgs {
		if arg == "--security-opt" && i+1 < len(capturedArgs) && capturedArgs[i+1] == "label=disable" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected --security-opt label=disable in args %v", capturedArgs)
	}
}

func TestDockerUser(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	uid := os.Getuid()
	gid := os.Getgid()
	expected := fmt.Sprintf("%d:%d", uid, gid)

	found := false
	for i, arg := range capturedArgs {
		if arg == "--user" && i+1 < len(capturedArgs) && capturedArgs[i+1] == expected {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected --user %s in args %v", expected, capturedArgs)
	}
}

func TestMountValidationPreventsRunCommand(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	called := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		called = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "/etc/passwd", "target": "/workspace"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	if called {
		t.Error("ExecCommand should not be called with invalid mount")
	}
}

func TestMountCommaInTarget(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	called := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		called = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/data,readonly"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.Code != "invalid_mount" {
		t.Errorf("expected code 'invalid_mount', got %q", resp.Code)
	}

	if called {
		t.Error("ExecCommand should not be called with comma in target")
	}
}

func TestMountCommaInSource(t *testing.T) {
	app := newTestAppWithAuth(t)

	commaDir := filepath.Join(app.Config.AllowedRoot, "dir,with,commas")
	if err := os.MkdirAll(commaDir, 0755); err != nil {
		t.Fatalf("cannot create comma dir: %v", err)
	}

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	called := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		called = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "dir,with,commas", "target": "/data"},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.Code != "invalid_mount" {
		t.Errorf("expected code 'invalid_mount', got %q", resp.Code)
	}

	if called {
		t.Error("ExecCommand should not be called with comma in source")
	}
}

func TestMountDuplicateTargetAfterClean(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	called := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		called = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/data"},
			{"source": ".", "target": "/data/."},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.Code != "invalid_mount" {
		t.Errorf("expected code 'invalid_mount', got %q", resp.Code)
	}

	if called {
		t.Error("ExecCommand should not be called with duplicate targets")
	}
}

func TestMountNormalizedTargetInDockerArgs(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/data/."},
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	found := false
	for i, arg := range capturedArgs {
		if arg == "--mount" && i+1 < len(capturedArgs) {
			spec := capturedArgs[i+1]
			if strings.HasSuffix(spec, "target=/data") && !strings.Contains(spec, "target=/data/.") {
				found = true
				break
			}
		}
	}

	if !found {
		t.Errorf("expected normalized target=/data in mount spec, args: %v", capturedArgs)
	}
}
