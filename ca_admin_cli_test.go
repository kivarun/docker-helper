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
		"allowed_root":         testAllowedRootDir(t),
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

	// The offline cleanup owns the system runtime/state directories; the
	// test points both seams at the isolated fixture directories.
	// The offline cleanup owns the system runtime/state directories; the
	// test points both seams at the isolated fixture directories. The state
	// layout is the system one: <state>/docker-helper.db.
	stateHome := os.Getenv("XDG_STATE_HOME")
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	origRuntime := getRuntimeDirFunc
	getRuntimeDirFunc = func() (string, error) { return runtimeDir, nil }
	t.Cleanup(func() { getRuntimeDirFunc = origRuntime })
	origState := getStateDirFunc
	getStateDirFunc = func() string { return stateHome + "-layout" }
	t.Cleanup(func() { getStateDirFunc = origState })
	if err := os.MkdirAll(stateHome+"-layout", 0755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(stateHome+"-layout", "docker-helper.db")

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

	trustedCADir := filepath.Join(runtimeDir, "docker-helper", "trusted-ca")
	if _, err := os.Stat(trustedCADir); !os.IsNotExist(err) {
		t.Error("session cleanup CLI should not create trusted-ca runtime artifacts")
	}
}
