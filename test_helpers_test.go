package main

import (
	"os"
	"path/filepath"
	"testing"
)

// safeTestBaseDir returns a writable base directory outside the forbidden
// /tmp tree where unique workspace-root test directories can be created.
// Workspace roots must live outside /tmp (see workspace root security
// policy); t.TempDir() is therefore unsuitable for them.
func safeTestBaseDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home directory: %v", err)
	}
	return home
}

// testAllowedRootDir creates a unique directory that is valid as a workspace
// root (outside the forbidden /tmp tree) and returns it in canonical form,
// matching what loadConfig stores in Config.AllowedRoot. Cleanup removes only
// the specific directory returned; tests must never remove a shared parent
// in HOME.
func testAllowedRootDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(safeTestBaseDir(t), ".docker-helper-test-*")
	if err != nil {
		t.Fatalf("cannot create workspace root test dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("cannot canonicalize workspace root test dir: %v", err)
	}
	return canonical
}
