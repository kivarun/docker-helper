package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLoadAndPrepareRuntimeConfigRejectsManualSymlinkToForbidden verifies the runtime policy
// invariant: a config.json hand-edited to point allowed_root at a symlink
// whose target is a forbidden system tree must be rejected by loadAndPrepareRuntimeConfig.
func TestLoadAndPrepareRuntimeConfigRejectsManualSymlinkToForbidden(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	xdgRuntime := filepath.Join(dir, "xdg_runtime")

	// An allowed-looking path (under an allowed namespace) that is a symlink
	// into a forbidden system tree.
	base := testAllowedRootDir(t)
	linkPath := filepath.Join(base, "escape")
	if err := os.Symlink("/var", linkPath); err != nil {
		t.Fatalf("cannot create symlink: %v", err)
	}

	cfg := map[string]any{
		"allowed_root": linkPath,
		"session_ttl":  "12h",
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", xdgRuntime)
	t.Setenv("XDG_STATE_HOME", dir)

	if _, err := loadAndPrepareRuntimeConfig(); err == nil {
		t.Fatal("expected loadAndPrepareRuntimeConfig to reject allowed_root symlink to forbidden tree")
	} else if !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("expected forbidden error, got: %v", err)
	}

	// Invalid config must not leave runtime filesystem side effects.
	runtimeDir := filepath.Join(xdgRuntime, "docker-helper")
	if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
		t.Errorf("runtime dir %s should not be created for invalid config", runtimeDir)
	}
}

// TestLoadAndPrepareRuntimeConfigCanonicalizesManualSymlink verifies that a manually written
// config whose allowed_root is a symlink to an allowed target is accepted,
// and the runtime Config stores the canonical target.
func TestLoadAndPrepareRuntimeConfigCanonicalizesManualSymlink(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	base := testAllowedRootDir(t)
	target := filepath.Join(base, "target")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(base, "link")
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatalf("cannot create symlink: %v", err)
	}
	canonicalTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}

	cfg := map[string]any{
		"allowed_root": linkPath,
		"session_ttl":  "12h",
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "xdg_runtime"))
	t.Setenv("XDG_STATE_HOME", dir)
	if err := os.MkdirAll(filepath.Join(dir, "xdg_runtime"), 0700); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatalf("loadAndPrepareRuntimeConfig() error: %v", err)
	}
	if loaded.AllowedRoots[0] != canonicalTarget {
		t.Errorf("AllowedRoot = %q, want canonical %q", loaded.AllowedRoots[0], canonicalTarget)
	}
}

// TestReloadSymlinkBypassKeepsOldConfig verifies that a reload with a
// manually edited config pointing allowed_root at a forbidden symlink fails
// and leaves the running daemon's configuration unchanged.
func TestReloadSymlinkBypassKeepsOldConfig(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	cfg, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	adminHash, err := loadAdminToken(cfg.AdminTokenPath)
	if err != nil {
		t.Fatal(err)
	}

	db, err := openDatabase(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	app := &App{
		Config:         cfg,
		DB:             db,
		AdminTokenHash: adminHash,
	}
	oldAllowedRoot := app.Config.AllowedRoots[0]

	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", withRequestID(app.handleReload))

	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(socketPath)

	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	// Hand-edit the config: allowed-looking symlink into a forbidden tree.
	base := testAllowedRootDir(t)
	linkPath := filepath.Join(base, "escape")
	if err := os.Symlink("/var", linkPath); err != nil {
		t.Fatalf("cannot create symlink: %v", err)
	}
	badCfg := map[string]any{
		"allowed_root": linkPath,
		"session_ttl":  "12h",
	}
	data, err := json.MarshalIndent(badCfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, 2*time.Second)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	req, err := http.NewRequest("POST", "http://localhost/reload", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-admin-token")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for forbidden symlink allowed_root, got %d", resp.StatusCode)
	}
	if got := app.getConfig().AllowedRoots[0]; got != oldAllowedRoot {
		t.Errorf("runtime allowed_root changed on failed reload: got %q, want %q", got, oldAllowedRoot)
	}
}

// TestConfigSetAllowedRootForbiddenSymlink verifies that config set rejects
// a symlink into a forbidden tree with exit code 2 and leaves the config
// file unchanged.
func TestConfigSetAllowedRootForbiddenSymlink(t *testing.T) {
	base := testAllowedRootDir(t)
	linkPath := filepath.Join(base, "escape")
	if err := os.Symlink("/var", linkPath); err != nil {
		t.Fatalf("cannot create symlink: %v", err)
	}

	cfg := map[string]any{
		"allowed_root": base,
		"session_ttl":  "12h",
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	configPath := setupConfigTestWithData(t, data)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "allowed_root", linkPath}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d, stderr: %s", code, stderr.String())
	}

	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, data) {
		t.Error("config file was modified by rejected config set")
	}
}

// TestInitUserModeStoresCanonicalAllowedRoot verifies the init invariant:
// the init command passes the canonical allowed_root into the written
// config. The CLI resolves (canonicalizes) the allowed root before
// runInit, so the value persisted by initCore is canonical.
func TestInitUserModeStoresCanonicalAllowedRoot(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = origUID }()

	// Standalone user init (no system daemon, Docker accessible).
	restore := mockStandaloneUserInit()
	defer restore()

	base := testAllowedRootDir(t)
	target := filepath.Join(base, "target")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(base, "link")
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatalf("cannot create symlink: %v", err)
	}
	canonicalTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", linkPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init exited %d, stderr: %s", code, stderr.String())
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var fc fileConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		t.Fatal(err)
	}
	if fc.AllowedRoots[0] != canonicalTarget {
		t.Errorf("config allowed_root = %q, want canonical %q", fc.AllowedRoots[0], canonicalTarget)
	}
}

// TestInitSystemModePassesCanonicalToCore verifies the init invariant for
// system mode: the value the CLI resolves (canonical) is what the system
// init orchestration hands to core (initCore).
func TestInitSystemModePassesCanonicalToCore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	EffectiveUID = func() int { return 0 }
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	base := testAllowedRootDir(t)
	target := filepath.Join(base, "target")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(base, "link")
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatalf("cannot create symlink: %v", err)
	}
	canonicalTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}

	// The CLI resolves the flag value before calling runInit.
	resolved, err := resolveAllowedRootForInit(linkPath, nil, io.Discard, false)
	if err != nil {
		t.Fatalf("resolveAllowedRootForInit() error: %v", err)
	}
	if resolved != canonicalTarget {
		t.Fatalf("CLI resolved %q, want %q", resolved, canonicalTarget)
	}

	var coreRoot string
	var stdout, stderr bytes.Buffer
	err = initSystem(resolved, &stdout, &stderr,
		nil,
		func(ar string, so, se io.Writer) error {
			coreRoot = ar
			return nil
		},
	)
	if err != nil {
		t.Fatalf("initSystem() error: %v", err)
	}

	if coreRoot != canonicalTarget {
		t.Errorf("core received allowed_root = %q, want canonical %q", coreRoot, canonicalTarget)
	}
}
