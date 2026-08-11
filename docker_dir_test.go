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

// TestBuildEnsureSessionDockerDirFails verifies that when
// ensureSessionDockerDir fails during handleBuild, the handler
// returns 500 without registering an operation or writing an audit event.
func TestBuildEnsureSessionDockerDirFails(t *testing.T) {
	dir := t.TempDir()

	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}

	allowedRoot := dir
	// Create a RuntimeDir where MkdirAll will fail: put a regular file
	// at the path where the sessions subdirectory would be created.
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0755); err != nil {
		t.Fatal(err)
	}
	sessionsFile := filepath.Join(runtimeDir, "sessions")
	if err := os.WriteFile(sessionsFile, []byte("block"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AllowedRoot:           allowedRoot,
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
	}

	hash := sha256.Sum256([]byte(testAdminToken))
	app := &App{
		Config:            cfg,
		DB:                db,
		AdminTokenHash:    hash,
		OperationRegistry: newOperationRegistry(),
	}

	// Create a session.
	result, err := app.createSession(allowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Create a minimal build context and Dockerfile.
	ctxDir := filepath.Join(allowedRoot, "buildctx")
	if err := os.MkdirAll(ctxDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctxDir, "Dockerfile"),
		[]byte("FROM alpine:3.24\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Capture audit output.
	auditBuf, _ := setupTestLogging(t)

	// Track whether Docker command was invoked.
	dockerCalled := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "docker" {
			dockerCalled = true
		}
		return exec.CommandContext(ctx, name, args...)
	}

	// Send build request.
	reqBody := map[string]string{
		"context":    "buildctx",
		"dockerfile": "Dockerfile",
		"image":      "test:latest",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	// Verify 500 response.
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

	// Verify no operation was registered.
	if len(app.OperationRegistry.ops) != 0 {
		t.Error("registry should be empty after ensureSessionDockerDir failure")
	}

	// Verify Docker command was not invoked.
	if dockerCalled {
		t.Error("docker command should not be invoked after ensureSessionDockerDir failure")
	}

	// Verify no build.start audit event was written.
	records := parseAuditRecords(auditBuf)
	for _, rec := range records {
		if rec.Event == "build.start" && rec.SessionID == result.Session.ID {
			t.Error("build.start audit event should not appear after ensureSessionDockerDir failure")
		}
	}
}

// TestRunEnsureSessionDockerDirFails verifies that when
// ensureSessionDockerDir fails during handleRun, the handler
// returns 500 without registering an operation or writing an audit event.
func TestRunEnsureSessionDockerDirFails(t *testing.T) {
	dir := t.TempDir()

	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}

	allowedRoot := dir
	// Create a RuntimeDir where MkdirAll will fail: put a regular file
	// at the path where the sessions subdirectory would be created.
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0755); err != nil {
		t.Fatal(err)
	}
	sessionsFile := filepath.Join(runtimeDir, "sessions")
	if err := os.WriteFile(sessionsFile, []byte("block"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AllowedRoot:           allowedRoot,
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
	}

	hash := sha256.Sum256([]byte(testAdminToken))
	app := &App{
		Config:            cfg,
		DB:                db,
		AdminTokenHash:    hash,
		OperationRegistry: newOperationRegistry(),
	}

	// Create a session.
	result, err := app.createSession(allowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Capture audit output.
	auditBuf, _ := setupTestLogging(t)

	// Track whether Docker command was invoked.
	dockerCalled := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "docker" {
			dockerCalled = true
		}
		return exec.CommandContext(ctx, name, args...)
	}

	// Send run request.
	reqBody := map[string]string{
		"image": "alpine:3.24",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	// Verify 500 response.
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

	// Verify no operation was registered.
	if len(app.OperationRegistry.ops) != 0 {
		t.Error("registry should be empty after ensureSessionDockerDir failure")
	}

	// Verify Docker command was not invoked.
	if dockerCalled {
		t.Error("docker command should not be invoked after ensureSessionDockerDir failure")
	}

	// Verify no run.start audit event was written.
	records := parseAuditRecords(auditBuf)
	for _, rec := range records {
		if rec.Event == "run.start" && rec.SessionID == result.Session.ID {
			t.Error("run.start audit event should not appear after ensureSessionDockerDir failure")
		}
	}
}
