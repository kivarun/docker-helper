package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()

	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	allowedRoot := dir
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatalf("cannot create runtime dir: %v", err)
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

	return &App{
		Config: cfg,
		DB:     db,
	}
}

func TestCreateSession(t *testing.T) {
	app := newTestApp(t)
	workspace := app.Config.AllowedRoot

	result, err := app.createSession(workspace)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	if result.Session.ID == "" {
		t.Error("session ID should not be empty")
	}
	if result.Token == "" {
		t.Error("token should not be empty")
	}
	if result.Session.Workspace != workspace {
		t.Errorf("expected workspace %q, got %q", workspace, result.Session.Workspace)
	}
}

func TestCreateSessionCanonicalWorkspace(t *testing.T) {
	app := newTestApp(t)

	subdir := filepath.Join(app.Config.AllowedRoot, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("cannot create subdir: %v", err)
	}

	result, err := app.createSession(subdir)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	if !filepath.IsAbs(result.Session.Workspace) {
		t.Error("workspace should be absolute")
	}
}

func TestCreateSessionIDPrefix(t *testing.T) {
	app := newTestApp(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	if !strings.HasPrefix(result.Session.ID, "dhs_") {
		t.Errorf("session ID should start with 'dhs_', got %q", result.Session.ID)
	}
}

func TestCreateSessionTokenPrefix(t *testing.T) {
	app := newTestApp(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	if !strings.HasPrefix(result.Token, "dht_") {
		t.Errorf("token should start with 'dht_', got %q", result.Token)
	}
}

func TestTokenNotStoredInDatabase(t *testing.T) {
	app := newTestApp(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	rows, err := app.DB.Query("SELECT token_hash FROM sessions WHERE id = ?", result.Session.ID)
	if err != nil {
		t.Fatalf("cannot query sessions: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var tokenHash string
		if err := rows.Scan(&tokenHash); err != nil {
			t.Fatalf("cannot scan token_hash: %v", err)
		}

		if strings.Contains(tokenHash, result.Token) {
			t.Error("full token must not be stored in database")
		}
	}
}

func TestTokenHashIsSHA256(t *testing.T) {
	app := newTestApp(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	expectedHash := sha256.Sum256([]byte(result.Token))
	expectedHashHex := hex.EncodeToString(expectedHash[:])

	var storedHash string
	err = app.DB.QueryRow("SELECT token_hash FROM sessions WHERE id = ?", result.Session.ID).Scan(&storedHash)
	if err != nil {
		t.Fatalf("cannot query token_hash: %v", err)
	}

	if storedHash != expectedHashHex {
		t.Errorf("expected hash %q, got %q", expectedHashHex, storedHash)
	}
}

func TestExpiresAtMatchesSessionTTL(t *testing.T) {
	app := newTestApp(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	expected := result.Session.CreatedAt.Add(app.Config.SessionTTL)
	diff := result.Session.ExpiresAt.Sub(expected)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("expires_at mismatch: expected %v, got %v (diff %v)", expected, result.Session.ExpiresAt, diff)
	}
}

func TestFindSessionByToken(t *testing.T) {
	app := newTestApp(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	session, err := app.findSessionByToken(result.Token)
	if err != nil {
		t.Fatalf("findSessionByToken() error: %v", err)
	}

	if session.ID != result.Session.ID {
		t.Errorf("expected session ID %q, got %q", result.Session.ID, session.ID)
	}
}

func TestFindSessionByTokenNotFound(t *testing.T) {
	app := newTestApp(t)

	_, err := app.findSessionByToken("dht_invalid")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got %v", err)
	}
}

func TestListSessionsReturnsActive(t *testing.T) {
	app := newTestApp(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	sessions, err := app.listSessions()
	if err != nil {
		t.Fatalf("listSessions() error: %v", err)
	}

	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}

	if sessions[0].ID != result.Session.ID {
		t.Errorf("expected session ID %q, got %q", result.Session.ID, sessions[0].ID)
	}
}

func TestListSessionsExcludesExpired(t *testing.T) {
	app := newTestApp(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	_, err = app.DB.Exec("UPDATE sessions SET expires_at = ? WHERE id = ?", time.Now().Add(-time.Hour).Unix(), result.Session.ID)
	if err != nil {
		t.Fatalf("cannot update expires_at: %v", err)
	}

	sessions, err := app.listSessions()
	if err != nil {
		t.Fatalf("listSessions() error: %v", err)
	}

	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestDeleteSession(t *testing.T) {
	app := newTestApp(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	deleted, err := app.deleteSession(result.Session.ID)
	if err != nil {
		t.Fatalf("deleteSession() error: %v", err)
	}

	if deleted == nil {
		t.Error("expected deleted session to be returned")
	}

	sessions, err := app.listSessions()
	if err != nil {
		t.Fatalf("listSessions() error: %v", err)
	}

	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions after deletion, got %d", len(sessions))
	}
}

func TestDeleteSessionNotFound(t *testing.T) {
	app := newTestApp(t)

	deleted, err := app.deleteSession("dhs_nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}

	if deleted != nil {
		t.Error("expected deleted to be nil for nonexistent session")
	}
}

func TestDeleteSessionRepeatedReturnsError(t *testing.T) {
	app := newTestApp(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	_, err = app.deleteSession(result.Session.ID)
	if err != nil {
		t.Fatalf("first deleteSession() error: %v", err)
	}

	_, err = app.deleteSession(result.Session.ID)
	if err == nil {
		t.Fatal("expected error for second deletion")
	}
}

func TestWorkspaceOutsideAllowedRootRejected(t *testing.T) {
	app := newTestApp(t)

	tmpDir := t.TempDir()

	_, err := app.createSession(tmpDir)
	if err == nil {
		t.Error("expected error for workspace outside allowed root")
	}
}

func TestWorkspaceSymlinkEscapeRejected(t *testing.T) {
	app := newTestApp(t)

	escapeDir := t.TempDir()
	linkPath := filepath.Join(app.Config.AllowedRoot, "escape-link")

	if err := os.Symlink(escapeDir, linkPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	_, err := app.createSession(linkPath)
	if err == nil {
		t.Error("expected error for symlink escaping allowed root")
	}
}

func TestCreateSessionUniqueIDs(t *testing.T) {
	app := newTestApp(t)

	result1, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("first createSession() error: %v", err)
	}

	result2, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("second createSession() error: %v", err)
	}

	if result1.Session.ID == result2.Session.ID {
		t.Error("session IDs should be unique")
	}

	if result1.Token == result2.Token {
		t.Error("tokens should be unique")
	}
}

func TestCleanupExpiredSessions(t *testing.T) {
	app := newTestApp(t)

	// Create an expired session (expires_at in the past).
	_, err := app.DB.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"dhs_expired", "hash1", app.Config.AllowedRoot,
		time.Now().Add(-2*time.Hour).Unix(),
		time.Now().Add(-1*time.Hour).Unix(),
	)
	if err != nil {
		t.Fatalf("cannot insert expired session: %v", err)
	}

	// Create a session expiring exactly now (should be cleaned up).
	now := time.Now().Unix()
	_, err = app.DB.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"dhs_expires_now", "hash2", app.Config.AllowedRoot,
		now-3600, now,
	)
	if err != nil {
		t.Fatalf("cannot insert boundary session: %v", err)
	}

	// Create an active session (expires_at in the future).
	_, err = app.DB.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"dhs_active", "hash3", app.Config.AllowedRoot,
		now, now+3600,
	)
	if err != nil {
		t.Fatalf("cannot insert active session: %v", err)
	}

	if _, err := cleanupExpiredSessions(app.DB); err != nil {
		t.Fatalf("cleanupExpiredSessions() error: %v", err)
	}

	// Verify expired session is gone.
	var count int
	err = app.DB.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = 'dhs_expired'").Scan(&count)
	if err != nil {
		t.Fatalf("cannot query expired: %v", err)
	}
	if count != 0 {
		t.Error("expired session should be deleted")
	}

	// Verify boundary session (expires_at == now) is gone.
	err = app.DB.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = 'dhs_expires_now'").Scan(&count)
	if err != nil {
		t.Fatalf("cannot query boundary: %v", err)
	}
	if count != 0 {
		t.Error("session with expires_at == now should be deleted")
	}

	// Verify active session remains.
	err = app.DB.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = 'dhs_active'").Scan(&count)
	if err != nil {
		t.Fatalf("cannot query active: %v", err)
	}
	if count != 1 {
		t.Error("active session should remain")
	}
}

// --- cleanupExpiredSessions tests ---

func TestCleanupExpiredSessionsDeletesExpired(t *testing.T) {
	app := newTestApp(t)

	now := time.Now().Unix()

	// Insert an expired session.
	_, err := app.DB.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"dhs_expired", "hash_expired", app.Config.AllowedRoot, now-7200, now-3600,
	)
	if err != nil {
		t.Fatalf("cannot insert expired: %v", err)
	}

	// Insert an active session.
	_, err = app.DB.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"dhs_active", "hash_active", app.Config.AllowedRoot, now, now+3600,
	)
	if err != nil {
		t.Fatalf("cannot insert active: %v", err)
	}

	n, err := cleanupExpiredSessions(app.DB)
	if err != nil {
		t.Fatalf("cleanupExpiredSessions() error: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 deleted, got %d", n)
	}

	// Verify expired is gone.
	var count int
	err = app.DB.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = 'dhs_expired'").Scan(&count)
	if err != nil {
		t.Fatalf("cannot query expired: %v", err)
	}
	if count != 0 {
		t.Error("expired session should be deleted")
	}

	// Verify active remains.
	err = app.DB.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = 'dhs_active'").Scan(&count)
	if err != nil {
		t.Fatalf("cannot query active: %v", err)
	}
	if count != 1 {
		t.Error("active session should remain")
	}
}

func TestCleanupExpiredSessionsBoundaryEqualsNow(t *testing.T) {
	app := newTestApp(t)

	now := time.Now().Unix()

	// Insert a session with expires_at == now (boundary: should be deleted).
	_, err := app.DB.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"dhs_boundary", "hash_boundary", app.Config.AllowedRoot, now-3600, now,
	)
	if err != nil {
		t.Fatalf("cannot insert boundary: %v", err)
	}

	n, err := cleanupExpiredSessions(app.DB)
	if err != nil {
		t.Fatalf("cleanupExpiredSessions() error: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 deleted, got %d", n)
	}
}

func TestCleanupExpiredSessionsEmpty(t *testing.T) {
	app := newTestApp(t)

	n, err := cleanupExpiredSessions(app.DB)
	if err != nil {
		t.Fatalf("cleanupExpiredSessions() error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 deleted, got %d", n)
	}
}

// --- CLI cleanup tests ---

func TestSessionCleanupCLI(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "docker-helper.db")
	stateDir := filepath.Join(dir, "state", "docker-helper")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}

	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}
	db.Close()

	if err := os.Symlink(dbPath, filepath.Join(stateDir, "docker-helper.db")); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "config.json")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	configData := []byte(`{"allowed_root":"` + dir + `","session_ttl":"12h"}` + "\n")
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		t.Fatalf("cannot write config: %v", err)
	}

	// Insert an expired session directly.
	db, err = openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()
	now := time.Now().Unix()
	if _, err := db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"dhs_cli_expired", "hash_cli", dir, now-7200, now-3600,
	); err != nil {
		t.Fatalf("cannot insert expired session: %v", err)
	}

	// Run the cleanup command.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "cleanup"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d; stderr: %s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "removed 1 expired sessions") {
		t.Errorf("expected 'removed 1 expired sessions' in stdout, got: %s", out)
	}
}

func TestSessionCleanupCLINoneExpired(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "docker-helper.db")
	stateDir := filepath.Join(dir, "state", "docker-helper")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}

	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}
	db.Close()

	if err := os.Symlink(dbPath, filepath.Join(stateDir, "docker-helper.db")); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "config.json")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	configData := []byte(`{"allowed_root":"` + dir + `","session_ttl":"12h"}` + "\n")
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		t.Fatalf("cannot write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "cleanup"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d; stderr: %s", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "removed 0 expired sessions") {
		t.Errorf("expected 'removed 0 expired sessions' in stdout, got: %s", out)
	}
}

func TestSessionCleanupCLIDatabaseError(t *testing.T) {
	t.Setenv("DOCKER_HELPER_CONFIG", "/nonexistent/path/config.json")
	t.Setenv("XDG_STATE_HOME", "/nonexistent/state/path")
	t.Setenv("XDG_RUNTIME_DIR", "")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "cleanup"}, &stdout, &stderr)
	if code == 0 {
		t.Error("expected non-zero exit code for database error")
	}
	if stderr.Len() == 0 {
		t.Error("expected error on stderr")
	}
}

func TestSessionCleanupWithRuntimeDirs(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "docker-helper.db")
	stateDir := filepath.Join(dir, "state", "docker-helper")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}

	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}
	db.Close()

	if err := os.Symlink(dbPath, filepath.Join(stateDir, "docker-helper.db")); err != nil {
		t.Fatal(err)
	}

	runtimeDir := filepath.Join(dir, "runtime", "docker-helper")
	sessionsDir := filepath.Join(runtimeDir, "sessions")
	if err := os.MkdirAll(sessionsDir, 0700); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "config.json")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	configData := []byte(`{"allowed_root":"` + dir + `","session_ttl":"12h"}` + "\n")
	if err := os.WriteFile(configPath, configData, 0600); err != nil {
		t.Fatalf("cannot write config: %v", err)
	}

	db, err = openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	now := time.Now().Unix()

	_, err = db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"dhs_active", "hash_active", dir, now, now+3600,
	)
	if err != nil {
		t.Fatalf("cannot insert active session: %v", err)
	}

	_, err = db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"dhs_expired", "hash_expired", dir, now-7200, now-3600,
	)
	if err != nil {
		t.Fatalf("cannot insert expired session: %v", err)
	}

	activeRuntimeDir := filepath.Join(sessionsDir, "dhs_active")
	expiredRuntimeDir := filepath.Join(sessionsDir, "dhs_expired")
	if err := os.MkdirAll(activeRuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(expiredRuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "cleanup"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d; stderr: %s", code, stderr.String())
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = 'dhs_expired'").Scan(&count)
	if err != nil {
		t.Fatalf("cannot query expired: %v", err)
	}
	if count != 0 {
		t.Error("expired session should be deleted from DB")
	}

	err = db.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = 'dhs_active'").Scan(&count)
	if err != nil {
		t.Fatalf("cannot query active: %v", err)
	}
	if count != 1 {
		t.Error("active session should remain in DB")
	}

	if _, err := os.Stat(expiredRuntimeDir); !os.IsNotExist(err) {
		t.Error("expired session runtime dir should be removed")
	}

	if _, err := os.Stat(activeRuntimeDir); os.IsNotExist(err) {
		t.Error("active session runtime dir should remain")
	}
}
