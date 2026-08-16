package main

import (
	"os"
	"path/filepath"
	"testing"
)

// testAllowedRootDir creates a non-forbidden test directory for use as an
// allowed_root in tests. /tmp is forbidden by the workspace root security policy.
// The directory is cleaned up when the test finishes.
func testAllowedRootDir(t *testing.T) string {
	t.Helper()
	home := os.Getenv("HOME")
	if home == "" {
		home = "/home"
	}
	// Use a unique subdirectory per test to avoid conflicts.
	dir := filepath.Join(home, "docker-helper-test", t.Name())
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.RemoveAll(filepath.Join(home, "docker-helper-test"))
	})
	return dir
}

// testAllowedRootPath creates a non-forbidden path with a given name for use
// as a workspace root in AppArmor tests. The path is created if it doesn't exist.
func testAllowedRootPath(t *testing.T, name string) string {
	t.Helper()
	home := os.Getenv("HOME")
	if home == "" {
		home = "/home"
	}
	dir := filepath.Join(home, "docker-helper-test", t.Name(), name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.RemoveAll(filepath.Join(home, "docker-helper-test"))
	})
	return dir
}
