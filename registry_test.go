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
	"strings"
	"testing"
)

// --- Registry login handler tests ---

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

	result, err := app.createSession(app.Config.AllowedRoot)
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

	result, err := app.createSession(app.Config.AllowedRoot)
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

	result, err := app.createSession(app.Config.AllowedRoot)
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

	result, err := app.createSession(app.Config.AllowedRoot)
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

	result, err := app.createSession(app.Config.AllowedRoot)
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

// --- Audit tests ---

func TestRegistryLoginAuditStartFinish(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
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

	records := parseAuditRecords(auditBuf)
	var startRec, finishRec *auditRecord
	for i := range records {
		if records[i].Event == "registry.login.start" {
			startRec = &records[i]
		}
		if records[i].Event == "registry.login.finish" {
			finishRec = &records[i]
		}
	}

	if startRec == nil {
		t.Fatal("registry.login.start audit not found")
	}
	if startRec.SessionID != result.Session.ID {
		t.Errorf("start session_id: expected %q, got %q", result.Session.ID, startRec.SessionID)
	}
	if startRec.Registry != "registry.example.com" {
		t.Errorf("start registry: expected 'registry.example.com', got %q", startRec.Registry)
	}

	if finishRec == nil {
		t.Fatal("registry.login.finish audit not found")
	}
	if finishRec.SessionID != result.Session.ID {
		t.Errorf("finish session_id: expected %q, got %q", result.Session.ID, finishRec.SessionID)
	}
	if finishRec.Registry != "registry.example.com" {
		t.Errorf("finish registry: expected 'registry.example.com', got %q", finishRec.Registry)
	}
	if finishRec.Result != "success" {
		t.Errorf("finish result: expected 'success', got %q", finishRec.Result)
	}
	if finishRec.Duration == "" {
		t.Error("finish duration should be set")
	}
}

func TestRegistryLoginAuditPasswordNotLogged(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const secretPassword = "super-secret-password-12345"

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": secretPassword,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRegistryLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	output := auditBuf.String()
	if strings.Contains(output, secretPassword) {
		t.Fatalf("audit must not contain password!\n%s", output)
	}

	// Also verify operational logs don't contain it
	// (They go to stderr in tests, but we check the audit buffer)
}

func TestRegistryLoginAuditUsernameNotLogged(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const secretUsername = "secret-username-12345"

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"registry": "registry.example.com",
		"username": secretUsername,
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

	output := auditBuf.String()
	// Username is not in audit fields, so it should not appear
	if strings.Contains(output, secretUsername) {
		t.Fatalf("audit must not contain username!\n%s", output)
	}
}

// --- Session delete cleanup tests ---

func TestSessionDeleteRemovesRuntimeDir(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Create the session Docker directory
	dockerDir := sessionDockerDir(app.Config.RuntimeDir, result.Session.ID)
	if err := os.MkdirAll(dockerDir, 0700); err != nil {
		t.Fatalf("cannot create docker dir: %v", err)
	}

	// Verify it exists
	if _, err := os.Stat(dockerDir); err != nil {
		t.Fatalf("docker dir should exist: %v", err)
	}

	// Delete the session and clean up runtime
	_, err = app.deleteSession(result.Session.ID)
	if err != nil {
		t.Fatalf("deleteSession: %v", err)
	}

	// Clean up runtime directory (as the handler does)
	cfg := app.getConfig()
	if err := cleanupSessionRuntimeDir(cfg.RuntimeDir, result.Session.ID); err != nil {
		t.Fatalf("cleanupSessionRuntimeDir: %v", err)
	}

	// Runtime directory should be removed
	if _, err := os.Stat(dockerDir); !os.IsNotExist(err) {
		t.Errorf("docker dir should be removed, got %v", err)
	}
}

// --- Stale session cleanup tests ---

func TestCleanupStaleSessionRuntimeDirs(t *testing.T) {
	app := newTestAppWithAuth(t)

	// Create two sessions
	result1, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	result2, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Create Docker directories for both
	dockerDir1 := sessionDockerDir(app.Config.RuntimeDir, result1.Session.ID)
	dockerDir2 := sessionDockerDir(app.Config.RuntimeDir, result2.Session.ID)
	if err := os.MkdirAll(dockerDir1, 0700); err != nil {
		t.Fatalf("cannot create docker dir1: %v", err)
	}
	if err := os.MkdirAll(dockerDir2, 0700); err != nil {
		t.Fatalf("cannot create docker dir2: %v", err)
	}

	// Create a stale session directory (no corresponding DB entry)
	staleDir := filepath.Join(app.Config.RuntimeDir, "sessions", "dhs_stale12345678901234567890")
	if err := os.MkdirAll(staleDir, 0700); err != nil {
		t.Fatalf("cannot create stale dir: %v", err)
	}

	// Delete session2 from DB
	_, err = app.deleteSession(result2.Session.ID)
	if err != nil {
		t.Fatalf("deleteSession: %v", err)
	}

	// Run stale cleanup
	err = cleanupStaleSessionRuntimeDirs(app.DB, app.Config.RuntimeDir)
	if err != nil {
		t.Fatalf("cleanupStaleSessionRuntimeDirs: %v", err)
	}

	// Session1 dir should still exist
	if _, err := os.Stat(dockerDir1); err != nil {
		t.Errorf("session1 docker dir should exist: %v", err)
	}

	// Session2 dir should be removed
	if _, err := os.Stat(dockerDir2); !os.IsNotExist(err) {
		t.Errorf("session2 docker dir should be removed")
	}

	// Stale dir should be removed
	if _, err := os.Stat(staleDir); !os.IsNotExist(err) {
		t.Errorf("stale dir should be removed")
	}
}

func TestCleanupStaleSessionRuntimeDirsPreservesActive(t *testing.T) {
	app := newTestAppWithAuth(t)

	// Create a session
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Create Docker directory
	dockerDir := sessionDockerDir(app.Config.RuntimeDir, result.Session.ID)
	if err := os.MkdirAll(dockerDir, 0700); err != nil {
		t.Fatalf("cannot create docker dir: %v", err)
	}

	// Run stale cleanup (no stale entries)
	err = cleanupStaleSessionRuntimeDirs(app.DB, app.Config.RuntimeDir)
	if err != nil {
		t.Fatalf("cleanupStaleSessionRuntimeDirs: %v", err)
	}

	// Session dir should still exist
	if _, err := os.Stat(dockerDir); err != nil {
		t.Errorf("session docker dir should exist: %v", err)
	}
}

// --- CLI tests ---

func TestRegistryLoginCLIInteractive(t *testing.T) {
	// This test verifies the CLI help and flag parsing
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"registry", "login", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "registry") {
		t.Errorf("expected help text: %s", stdout.String())
	}
}

func TestRegistryLoginCLIMissingFlags(t *testing.T) {
	var stderr bytes.Buffer
	code := runCommandWithWriters([]string{"registry", "login"}, &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestRegistryLoginCLIMissingSessionToken(t *testing.T) {
	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "")

	var stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"registry", "login",
		"--registry", "registry.example.com",
		"--username", "user",
	}, &bytes.Buffer{}, &stderr)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "DOCKER_HELPER_SESSION_TOKEN") {
		t.Errorf("expected error about DOCKER_HELPER_SESSION_TOKEN, got: %s", stderr.String())
	}
}
