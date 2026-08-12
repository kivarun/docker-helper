package main

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeBrokenAutoCAConfig writes a config with trusted_ca_injection=auto
// pointing to a nonexistent CA file, so CA preflight would fail if attempted.
func writeBrokenAutoCAConfig(t *testing.T, configPath string) {
	t.Helper()
	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         "/tmp/work",
		"session_ttl":          "12h",
		"trusted_ca_path":      "/nonexistent/ca.pem",
		"trusted_ca_injection": "auto",
	})
}

func TestReloadNoCASideEffectCLI(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	writeBrokenAutoCAConfig(t, configPath)
	t.Setenv("PATH", t.TempDir())

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})

	reloadOut, reloadErr := &bytes.Buffer{}, &bytes.Buffer{}
	code := runCommandWithWriters([]string{"reload"}, reloadOut, reloadErr)
	if code != 0 {
		t.Fatalf("reload should succeed without CA/openssl, got code %d: stdout=%s stderr=%s", code, reloadOut.String(), reloadErr.String())
	}
	if !strings.Contains(reloadOut.String(), "reloaded") {
		t.Fatalf("expected 'reloaded' in output, got: %s", reloadOut.String())
	}

	trustedCADir := filepath.Join(runtimeDir, "docker-helper", "trusted-ca")
	if _, err := os.Stat(trustedCADir); !os.IsNotExist(err) {
		t.Error("reload CLI should not create trusted-ca runtime artifacts")
	}
}

func TestSessionListNoCASideEffectCLI(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	writeBrokenAutoCAConfig(t, configPath)
	t.Setenv("PATH", t.TempDir())

	startTestServer(t, socketPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"sessions":[]}`))
	})

	listOut, listErr := &bytes.Buffer{}, &bytes.Buffer{}
	code := runCommandWithWriters([]string{"session", "list"}, listOut, listErr)
	if code != 0 {
		t.Fatalf("session list should succeed without CA/openssl, got code %d: stdout=%s stderr=%s", code, listOut.String(), listErr.String())
	}

	trustedCADir := filepath.Join(runtimeDir, "docker-helper", "trusted-ca")
	if _, err := os.Stat(trustedCADir); !os.IsNotExist(err) {
		t.Error("session list CLI should not create trusted-ca runtime artifacts")
	}
}

func TestSessionCleanupNoCASideEffectCLI(t *testing.T) {
	configPath, _, _, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	stateHome := os.Getenv("XDG_STATE_HOME")
	dbPath := filepath.Join(stateHome, "docker-helper", "docker-helper.db")

	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeDatabase(db); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()

	writeBrokenAutoCAConfig(t, configPath)
	t.Setenv("PATH", t.TempDir())

	cleanupOut, cleanupErr := &bytes.Buffer{}, &bytes.Buffer{}
	code := runCommandWithWriters([]string{"session", "cleanup"}, cleanupOut, cleanupErr)
	if code != 0 {
		t.Fatalf("session cleanup should succeed without CA/openssl, got code %d: stdout=%s stderr=%s", code, cleanupOut.String(), cleanupErr.String())
	}
	if !strings.Contains(cleanupOut.String(), "removed") {
		t.Fatalf("expected 'removed' in output, got: %s", cleanupOut.String())
	}

	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	trustedCADir := filepath.Join(runtimeDir, "docker-helper", "trusted-ca")
	if _, err := os.Stat(trustedCADir); !os.IsNotExist(err) {
		t.Error("session cleanup CLI should not create trusted-ca runtime artifacts")
	}
}

func TestReloadNoXDGRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")

	reloadOut, reloadErr := &bytes.Buffer{}, &bytes.Buffer{}
	code := runCommandWithWriters([]string{"reload"}, reloadOut, reloadErr)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d: stdout=%s stderr=%s", code, reloadOut.String(), reloadErr.String())
	}
	if !strings.Contains(reloadErr.String(), "XDG_RUNTIME_DIR") {
		t.Fatalf("expected stderr to contain 'XDG_RUNTIME_DIR', got: %s", reloadErr.String())
	}
}

func TestSessionListNoXDGRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")

	listOut, listErr := &bytes.Buffer{}, &bytes.Buffer{}
	code := runCommandWithWriters([]string{"session", "list"}, listOut, listErr)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d: stdout=%s stderr=%s", code, listOut.String(), listErr.String())
	}
	if !strings.Contains(listErr.String(), "XDG_RUNTIME_DIR") {
		t.Fatalf("expected stderr to contain 'XDG_RUNTIME_DIR', got: %s", listErr.String())
	}
}
