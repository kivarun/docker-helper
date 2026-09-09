package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestRunBlockedCredentialStoreFailsClosed proves an unreadable session
// Docker credential store is an operational failure, never a silent
// anonymous fallback: the run fails closed before the Engine is called and
// registers no operation.
func TestRunBlockedCredentialStoreFailsClosed(t *testing.T) {
	dir := t.TempDir()

	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}

	allowedRoot := testAllowedRootDir(t)
	// Block the sessions runtime path with a regular file: any legacy
	// MkdirAll of the session Docker directory would fail loudly.
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0755); err != nil {
		t.Fatal(err)
	}
	sessionsFile := filepath.Join(runtimeDir, "sessions")
	if err := os.WriteFile(sessionsFile, []byte("block"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AllowedRoots:          []string{allowedRoot},
		SessionTTL:            24 * time.Hour,
		SocketPath:            filepath.Join(dir, "test.sock"),
		StateDir:              dir,
		RuntimeDir:            runtimeDir,
		DatabasePath:          dbPath,
		AdminTokenPath:        filepath.Join(dir, "admin.token"),
		ShutdownTimeout:       30 * time.Second,
		OperationRetentionTTL: 10 * time.Minute,
		OperationMaxCompleted: 200,
		OperationLogMaxBytes:  4 * 1024 * 1024,
		Mode:                  ModeUser,
	}

	hash := sha256.Sum256([]byte(testAdminToken))
	app := &App{
		Config:              cfg,
		DB:                  db,
		AdminTokenHash:      hash,
		OperationSupervisor: newOperationSupervisor(),
	}

	// Provision a user-mode daemon-owner Principal + 'default' Launcher so
	// that session creation resolves a valid session owner.
	home := filepath.Join(allowedRoot, "daemon-home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	app.userModeDefault = provisionTestOwner(t, db, allowedRoot, home, os.Getuid(), os.Getgid())

	// Create a session.
	workspace2 := testWorkspaceDir(t, allowedRoot)
	result, err := createDefaultAdminSessionForTest(app, workspace2)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	auditBuf, _ := setupTestLogging(t)

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	// Send run request.
	reqBody := map[string]string{
		"image": "alpine:3.24",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}

	if captured.reached() {
		t.Error("Engine runner must not be reached when the credential store is unreadable")
	}

	assertNoRunOperation(t, app, w.Body.Bytes())

	// No run audit event is written for a rejected run.
	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		if rec.Event == "run.start" || rec.Event == "run.finish" {
			t.Errorf("%s audit event must not appear after a store read failure", rec.Event)
		}
	}
}

// TestPullEnsureSessionDockerDirFails verifies that when
// ensureSessionDockerDir fails during handlePull, the handler
// returns 500 without writing any audit events.
func TestPullEnsureSessionDockerDirFails(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)

	// Block MkdirAll by placing a regular file at the sessions path.
	sessionsFile := filepath.Join(app.Config.RuntimeDir, "sessions")
	if err := os.WriteFile(sessionsFile, []byte("block"), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	auditBuf, _ := setupTestLogging(t)

	dockerCalled := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		dockerCalled = true
		return exec.CommandContext(ctx, "true")
	}

	req := newPullRequest(map[string]any{
		"image": "alpine:3.24",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "internal_error" {
		t.Errorf("expected code 'internal_error', got %q", resp.Code)
	}

	if dockerCalled {
		t.Error("docker command should not be invoked after ensureSessionDockerDir failure")
	}

	records := parseAuditRecords(auditBuf)
	for _, rec := range records {
		if rec.Event == "pull.start" && rec.SessionID == result.Session.ID {
			t.Error("pull.start audit event should not appear after ensureSessionDockerDir failure")
		}
		if rec.Event == "pull.finish" && rec.SessionID == result.Session.ID {
			t.Error("pull.finish audit event should not appear after ensureSessionDockerDir failure")
		}
	}
}
