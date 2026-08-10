package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// testBuildCmd creates a test command that writes output and exits with the given code.
func testBuildCmd(ctx context.Context, output string, exitCode int) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		script := "/bin/sh"
		var cmdArgs []string
		if exitCode == 0 {
			cmdArgs = []string{"-c", "printf '%s' '" + output + "'"}
		} else {
			cmdArgs = []string{"-c", "printf '%s' '" + output + "' >&2; exit " + itoa(exitCode)}
		}
		return exec.CommandContext(ctx, script, cmdArgs...)
	}
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

func TestBuildSessionAuthValidToken(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = testBuildCmd(context.Background(), "ok", 0)

	reqBody := map[string]string{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)
}

func TestBuildSessionAuthMissingToken(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestBuildSessionAuthInvalidToken(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dht_wrong_token")
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestBuildSessionAuthInvalidTokenDoesNotRunDocker(t *testing.T) {
	app := newTestAppWithAuth(t)

	called := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		called = true
		return exec.CommandContext(ctx, name, args...)
	}

	reqBody := map[string]string{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dht_wrong_token")
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}

	if called {
		t.Error("ExecCommandContext should not be called with invalid token")
	}
}

func TestBuildContextDotUsesWorkspace(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

	// Check that context path is the workspace
	found := false
	for i := range capturedArgs {
		if i+1 < len(capturedArgs) && capturedArgs[i+1] == result.Session.Workspace {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected workspace path in args %v", capturedArgs)
	}
}

func TestBuildContextRelativeSubdir(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

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

	dockerfilePath := filepath.Join(inner, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"context":    "inner",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)
}

func TestBuildContextAbsoluteInsideWorkspace(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	subdir := filepath.Join(app.Config.AllowedRoot, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("cannot create subdir: %v", err)
	}

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(subdir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"context":    subdir,
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)
}

func TestBuildContextSiblingDirectoryRejected(t *testing.T) {
	app := newTestAppWithAuth(t)

	subdir := filepath.Join(app.Config.AllowedRoot, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("cannot create subdir: %v", err)
	}

	sibling := filepath.Join(app.Config.AllowedRoot, "sibling")
	if err := os.MkdirAll(sibling, 0755); err != nil {
		t.Fatalf("cannot create sibling: %v", err)
	}

	result, err := app.createSession(subdir)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(sibling, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	reqBody := map[string]string{
		"context":    sibling,
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.Code != "invalid_build_context" {
		t.Errorf("expected code 'invalid_build_context', got %q", resp.Code)
	}
}

func TestBuildContextOutsideAllowedRootRejected(t *testing.T) {
	app := newTestAppWithAuth(t)

	escapeDir := t.TempDir()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(escapeDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	reqBody := map[string]string{
		"context":    escapeDir,
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestBuildContextSymlinkEscapeRejected(t *testing.T) {
	app := newTestAppWithAuth(t)

	escapeDir := t.TempDir()
	linkPath := filepath.Join(app.Config.AllowedRoot, "escape-link")

	if err := os.Symlink(escapeDir, linkPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	dockerfilePath := filepath.Join(escapeDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	reqBody := map[string]string{
		"context":    "escape-link",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestBuildWorkspaceIsSymlink(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	realDir := filepath.Join(app.Config.AllowedRoot, "real-dir")
	if err := os.MkdirAll(realDir, 0755); err != nil {
		t.Fatalf("cannot create real dir: %v", err)
	}

	linkDir := filepath.Join(app.Config.AllowedRoot, "link-dir")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	dockerfilePath := filepath.Join(realDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	result, err := app.createSession(linkDir)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)
}

func TestBuildDockerfileInsideContext(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

	// Check that --file contains the full dockerfile path
	found := false
	for i, arg := range capturedArgs {
		if arg == "--file" && i+1 < len(capturedArgs) {
			if capturedArgs[i+1] == dockerfilePath {
				found = true
				break
			}
		}
	}

	if !found {
		t.Errorf("expected --file %s in args %v", dockerfilePath, capturedArgs)
	}
}

func TestBuildDockerfileOutsideContextRejected(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	reqBody := map[string]string{
		"context":    ".",
		"dockerfile": "../Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestBuildDockerReceivesCanonicalContext(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

	// Last arg should be the canonical context path
	if len(capturedArgs) == 0 || capturedArgs[len(capturedArgs)-1] != result.Session.Workspace {
		t.Errorf("expected last arg to be %q, got %v", result.Session.Workspace, capturedArgs)
	}
}

func TestBuildContextErrorContainsCode(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	reqBody := map[string]string{
		"context":    "does-not-exist",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.Code != "invalid_build_context" {
		t.Errorf("expected code 'invalid_build_context', got %q", resp.Code)
	}
}

func TestParseOffset(t *testing.T) {
	tests := []struct {
		input   string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"1", 1, false},
		{"100", 100, false},
		{"9223372036854775807", 9223372036854775807, false},
		{"-1", 0, true},
		{"-100", 0, true},
		{"abc", 0, true},
		{"12foo", 0, true},
		{"foo12", 0, true},
		{"9223372036854775808", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseOffset(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOffset(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseOffset(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestHandleOperationLogsInvalidOffset(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode build response: %v", err)
	}
	opID, _ := resp["operation_id"].(string)

	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatalf("operation %s not found in registry", opID)
	}
	op.Wait()

	cases := []string{"-1", "abc", "12foo"}
	for _, offset := range cases {
		t.Run(offset, func(t *testing.T) {
			logsReq := httptest.NewRequest(http.MethodGet, "/operations/"+opID+"/logs?offset="+offset, nil)
			logsReq.SetPathValue("id", opID)
			logsReq.Header.Set("Authorization", "Bearer "+result.Token)
			logsW := httptest.NewRecorder()
			app.handleOperationLogs(logsW, logsReq)

			if logsW.Code != http.StatusBadRequest {
				t.Errorf("expected status %d, got %d", http.StatusBadRequest, logsW.Code)
			}

			var errResp response
			if err := json.NewDecoder(logsW.Body).Decode(&errResp); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if errResp.Code != "invalid_offset" {
				t.Errorf("expected code 'invalid_offset', got %q", errResp.Code)
			}
		})
	}
}

// TestOperationForSessionNilRegistry verifies that operationForSession
// returns nil when the operation registry is not set.
func TestOperationForSessionNilRegistry(t *testing.T) {
	app := &App{}
	op := app.operationForSession("session-1", "op-1")
	if op != nil {
		t.Error("expected nil for nil registry")
	}
}

// TestOperationForSessionUnknownID verifies that operationForSession
// returns nil for an unknown operation ID.
func TestOperationForSessionUnknownID(t *testing.T) {
	app := &App{OperationRegistry: newOperationRegistry()}
	op := app.operationForSession("session-1", "nonexistent")
	if op != nil {
		t.Error("expected nil for unknown operation ID")
	}
}

// TestOperationForSessionForeignSession verifies that operationForSession
// returns nil when the operation belongs to a different session.
func TestOperationForSessionForeignSession(t *testing.T) {
	reg := newOperationRegistry()
	op := newRunOperation("other-session", "alpine:latest", 1024)
	reg.tryCreate(op)

	app := &App{OperationRegistry: reg}
	result := app.operationForSession("session-1", op.ID)
	if result != nil {
		t.Error("expected nil for foreign session")
	}
}

// TestOperationForSessionOwner verifies that operationForSession
// returns the operation when the session matches.
func TestOperationForSessionOwner(t *testing.T) {
	reg := newOperationRegistry()
	op := newRunOperation("session-1", "alpine:latest", 1024)
	reg.tryCreate(op)

	app := &App{OperationRegistry: reg}
	result := app.operationForSession("session-1", op.ID)
	if result == nil {
		t.Fatal("expected operation for owner session")
	}
	if result.ID != op.ID {
		t.Errorf("expected operation ID %s, got %s", op.ID, result.ID)
	}
}
