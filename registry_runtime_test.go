package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSessionDeleteRemovesRuntimeDir(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
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

func TestCleanupStaleSessionRuntimeDirs(t *testing.T) {
	app := newTestAppWithAuth(t)

	// Create two sessions
	result1, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	result2, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
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
	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
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
