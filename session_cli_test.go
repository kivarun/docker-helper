package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSessionCleanupDaemonLockHeld verifies that when the daemon lock is
// already held, session cleanup fails without mutating the database or
// cleaning runtime directories.
func TestSessionCleanupDaemonLockHeld(t *testing.T) {
	// Daemon lock already held: session cleanup returns non-zero,
	// expired session row remains, no runtime cleanup occurs.
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Set up XDG seams.
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("XDG_STATE_HOME", stateDir)
	t.Setenv("HOME", dir)

	// Create database with an expired session.
	dbPath := filepath.Join(getStateDir(), "docker-helper.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	launcherID := provisionDefaultLauncherForDB(t, db)
	_, err = db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"sess-expired", "hash1", "/workspace", time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-1*time.Hour).Unix(), launcherID,
	)
	if err != nil {
		t.Fatalf("insert expired session: %v", err)
	}
	db.Close()

	// Create a stale runtime dir for the expired session (to verify it's NOT cleaned).
	sessionsDir := filepath.Join(getRuntimeDirSafe(), "sessions", "sess-expired")
	if err := os.MkdirAll(sessionsDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Hold the daemon lock (simulates running daemon).
	fullRuntimeDir := getRuntimeDirSafe()
	if err := os.MkdirAll(fullRuntimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(fullRuntimeDir, "docker-helper.sock.lock")
	lockFile, err := acquireDaemonInstanceLock(lockPath)
	if err != nil {
		t.Fatalf("acquireDaemonInstanceLock: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runSessionCleanup(&stdout, &stderr)

	// Cleanup should fail because daemon lock is held.
	if code == 0 {
		t.Fatal("expected non-zero exit code when daemon lock is held")
	}
	if !strings.Contains(stderr.String(), "already running") {
		t.Errorf("expected 'already running' in stderr, got: %s", stderr.String())
	}

	// Expired session should still exist.
	db, err = openDatabase(filepath.Join(getStateDir(), "docker-helper.db"))
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id = 'sess-expired'`).Scan(&count)
	if err != nil {
		t.Fatalf("query session: %v", err)
	}
	if count != 1 {
		t.Error("expired session should still exist (daemon was running)")
	}

	// Stale runtime dir should still exist (no cleanup occurred).
	if _, err := os.Stat(sessionsDir); os.IsNotExist(err) {
		t.Error("stale runtime dir should still exist (no cleanup when daemon was running)")
	}

	lockFile.Close()
}

// TestSessionCleanupOffline verifies that when the daemon is not running,
// session cleanup successfully removes expired sessions and stale runtime dirs.
func TestSessionCleanupOffline(t *testing.T) {
	// Daemon not running: command acquires lock, expired sessions are deleted,
	// stale runtime dirs are cleaned.
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Set up XDG seams.
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("XDG_STATE_HOME", stateDir)
	t.Setenv("HOME", dir)

	// Create database with an expired session.
	dbPath := filepath.Join(getStateDir(), "docker-helper.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	launcherID := provisionDefaultLauncherForDB(t, db)
	_, err = db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"sess-expired", "hash1", "/workspace", time.Now().Add(-2*time.Hour).Unix(), time.Now().Add(-1*time.Hour).Unix(), launcherID,
	)
	if err != nil {
		t.Fatalf("insert expired session: %v", err)
	}
	db.Close()

	// Create a stale runtime dir for the expired session.
	sessionsDir := filepath.Join(getRuntimeDirSafe(), "sessions", "sess-expired")
	if err := os.MkdirAll(sessionsDir, 0700); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runSessionCleanup(&stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "removed 1 expired sessions") {
		t.Errorf("expected 'removed 1 expired sessions' in stdout, got: %s", stdout.String())
	}

	// Expired session should be removed.
	db, err = openDatabase(dbPath)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer db.Close()

	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id = 'sess-expired'`).Scan(&count)
	if err != nil {
		t.Fatalf("query session: %v", err)
	}
	if count != 0 {
		t.Error("expired session should be removed")
	}

	// Stale runtime dir should be removed.
	if _, err := os.Stat(sessionsDir); !os.IsNotExist(err) {
		t.Error("stale runtime dir should be removed")
	}
}
