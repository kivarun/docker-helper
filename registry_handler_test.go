package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestRegistryLoginMissingSession(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handleRegistryLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRegistryLoginInvalidJSON(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/registry/login", strings.NewReader("not-json"))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRegistryLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestRegistryLoginMissingFields(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	for _, tc := range []map[string]string{
		{},
		{"registry": "reg.io"},
		{"username": "user"},
		{"password": "secret"},
		{"registry": "reg.io", "username": "user"},
		{"registry": "reg.io", "password": "secret"},
		{"username": "user", "password": "secret"},
	} {
		t.Run("", func(t *testing.T) {
			body, _ := json.Marshal(tc)
			req := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+result.Token)
			w := httptest.NewRecorder()

			app.handleRegistryLogin(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
			}

			var resp response
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("cannot decode: %v", err)
			}
			if resp.Code != "invalid_registry_login" {
				t.Errorf("expected code 'invalid_registry_login', got %q", resp.Code)
			}
		})
	}
}

func TestRegistryLoginSuccess(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"registry": "registry.example.com",
		"username": "testuser",
		"password": "testsecret",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRegistryLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode: %v", err)
	}
	if !resp.OK {
		t.Error("expected ok=true")
	}

	// Verify Docker --config was used
	dockerDir := sessionDockerDir(app.Config.RuntimeDir, result.Session.ID)
	foundConfig := false
	for i, arg := range capturedArgs {
		if arg == "--config" && i+1 < len(capturedArgs) && capturedArgs[i+1] == dockerDir {
			foundConfig = true
			break
		}
	}
	if !foundConfig {
		t.Errorf("expected --config %s in args, got %v", dockerDir, capturedArgs)
	}

	// Verify password was passed via stdin, not argv
	passwordFound := false
	for _, arg := range capturedArgs {
		if arg == "testsecret" {
			passwordFound = true
			break
		}
	}
	if passwordFound {
		t.Error("password must not appear in argv")
	}
}

func TestRegistryLoginFailure(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Simulate Docker login failure
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "echo 'login failed' >&2; exit 1")
	}

	reqBody := map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRegistryLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode: %v", err)
	}
	if resp.OK {
		t.Error("expected ok=false")
	}
	if resp.Code != "registry_login_failed" {
		t.Errorf("expected code 'registry_login_failed', got %q", resp.Code)
	}
	// Docker output must not leak
	if resp.Output != "" {
		t.Errorf("expected empty output, got %q", resp.Output)
	}
}

func TestRegistryLoginSessionDockerDirCreated(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerDir := sessionDockerDir(app.Config.RuntimeDir, result.Session.ID)

	// Directory should not exist yet
	if _, err := os.Stat(dockerDir); err == nil {
		t.Fatal("docker dir should not exist before login")
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRegistryLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	// Directory should now exist with 0700 permissions
	info, err := os.Stat(dockerDir)
	if err != nil {
		t.Fatalf("docker dir should exist: %v", err)
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("expected mode 0700, got %o", info.Mode().Perm())
	}
}

func TestRegistryLoginNilExecCommandContext(t *testing.T) {
	// Regression: registry login must not panic when ExecCommandContext is nil
	// (the production default). It must use the real exec.CommandContext fallback.
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Explicitly ensure ExecCommandContext is nil (production default).
	app.ExecCommandContext = nil

	// Make the production fallback exec.CommandContext("docker", ...)
	// deterministically fail by removing docker from PATH.
	t.Setenv("PATH", t.TempDir())

	reqBody := map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	// Must not panic.
	app.handleRegistryLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode: %v", err)
	}
	if resp.OK {
		t.Error("expected ok=false")
	}
	if resp.Code != "registry_login_failed" {
		t.Errorf("expected code 'registry_login_failed', got %q", resp.Code)
	}
}
