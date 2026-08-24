package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func setupReloadTestEnv(t *testing.T) (configPath, tokenPath, socketPath, lockPath string, cleanup func()) {
	t.Helper()
	dir := t.TempDir()

	configPath = filepath.Join(dir, "config.json")
	tokenPath = filepath.Join(dir, "admin.token")
	runtimeDir := filepath.Join(dir, "xdg_runtime")
	stateHome := filepath.Join(dir, "xdg_state")
	configHome := filepath.Join(dir, "xdg_config")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	stateSubDir := filepath.Join(stateHome, "docker-helper")
	socketPath = filepath.Join(runtimeSubDir, "docker-helper.sock")
	lockPath = socketPath + ".lock"

	allowedRoot := testAllowedRootDir(t)

	cfg := map[string]any{
		"allowed_root": allowedRoot,
		"session_ttl":  "12h",
		"log_level":    "info",
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(tokenPath, []byte("test-admin-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(runtimeSubDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateSubDir, 0700); err != nil {
		t.Fatal(err)
	}

	oldConfig := os.Getenv("DOCKER_HELPER_CONFIG")
	oldRuntime := os.Getenv("XDG_RUNTIME_DIR")
	oldState := os.Getenv("XDG_STATE_HOME")
	oldConfigHome := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("DOCKER_HELPER_CONFIG", configPath)
	os.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	os.Setenv("XDG_STATE_HOME", stateHome)
	os.Setenv("XDG_CONFIG_HOME", configHome)

	// Prevent tests from reaching a real system daemon.
	origSocket := systemSocketExists
	systemSocketExists = func() bool { return false }

	cleanup = func() {
		os.Setenv("DOCKER_HELPER_CONFIG", oldConfig)
		os.Setenv("XDG_RUNTIME_DIR", oldRuntime)
		os.Setenv("XDG_STATE_HOME", oldState)
		os.Setenv("XDG_CONFIG_HOME", oldConfigHome)
		systemSocketExists = origSocket
	}

	return configPath, tokenPath, socketPath, lockPath, cleanup
}

func TestReloadDaemonNotRunning(t *testing.T) {
	_, _, _, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	reloadOut, reloadErr := &bytes.Buffer{}, &bytes.Buffer{}
	code := runCommandWithWriters([]string{"reload"}, reloadOut, reloadErr)
	if code == 0 {
		t.Fatal("expected reload to fail when daemon is not running")
	}
	if !strings.Contains(reloadErr.String(), "error:") {
		t.Fatalf("expected error message, got: %s", reloadErr.String())
	}
}

func TestConfigSetDaemonNotRunning(t *testing.T) {
	configPath, _, _, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	setOut, setErr := &bytes.Buffer{}, &bytes.Buffer{}
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, setOut, setErr)
	if code != 0 {
		t.Fatalf("config set should succeed even when daemon not running, got code %d: stdout=%s stderr=%s", code, setOut.String(), setErr.String())
	}
	if !strings.Contains(setOut.String(), "updated") {
		t.Fatalf("expected 'updated' in output, got: %s", setOut.String())
	}
	if !strings.Contains(setOut.String(), "daemon not running") {
		t.Fatalf("expected 'daemon not running' message, got: %s", setOut.String())
	}
	// Verify config was updated (not rolled back).
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original, restored) {
		t.Error("config should be changed when daemon is not running")
	}
}

func TestConfigUnsetDaemonNotRunning(t *testing.T) {
	configPath, _, _, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_root":  allowedRoot,
		"session_ttl":   "12h",
		"log_level":     "info",
		"audit_enabled": true,
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	unsetOut, unsetErr := &bytes.Buffer{}, &bytes.Buffer{}
	code := runCommandWithWriters([]string{"config", "unset", "audit_enabled"}, unsetOut, unsetErr)
	if code != 0 {
		t.Fatalf("config unset should succeed even when daemon not running, got code %d: stdout=%s stderr=%s", code, unsetOut.String(), unsetErr.String())
	}
	if !strings.Contains(unsetOut.String(), "unset") {
		t.Fatalf("expected 'unset' in output, got: %s", unsetOut.String())
	}
	if !strings.Contains(unsetOut.String(), "daemon not running") {
		t.Fatalf("expected 'daemon not running' message, got: %s", unsetOut.String())
	}
}

func TestConfigSetUnchangedNoReload(t *testing.T) {
	configPath, _, _, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_roots": []string{allowedRoot},
		"session_ttl":   "12h",
		"log_level":     "info",
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	setOut, setErr := &bytes.Buffer{}, &bytes.Buffer{}
	code := runCommandWithWriters([]string{"config", "set", "log_level", "info"}, setOut, setErr)
	if code != 0 {
		t.Fatalf("config set failed with code %d: stdout=%s stderr=%s", code, setOut.String(), setErr.String())
	}
	if !strings.Contains(setOut.String(), "unchanged") {
		t.Fatalf("expected 'unchanged' in output, got: %s", setOut.String())
	}
	if strings.Contains(setOut.String(), "daemon not running") {
		t.Fatalf("unchanged should not trigger reload, got: %s", setOut.String())
	}
}

func TestReloadHelp(t *testing.T) {
	var out bytes.Buffer
	code := runCommandWithWriters([]string{"reload", "--help"}, &out, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("reload --help failed with code %d: %s", code, out.String())
	}
	output := out.String()
	if !strings.Contains(output, "Reload configuration") {
		t.Fatalf("expected help to contain reload description, got: %s", output)
	}
	if !strings.Contains(output, "allowed_roots") {
		t.Fatalf("expected help to mention allowed_roots, got: %s", output)
	}
	if strings.Contains(output, "allowed_root ") ||
		(strings.Contains(output, "allowed_root") && !strings.Contains(output, "allowed_roots")) {
		t.Fatalf("expected help to use allowed_roots, not stale allowed_root, got: %s", output)
	}
	if !strings.Contains(output, "session_ttl") {
		t.Fatalf("expected help to mention session_ttl, got: %s", output)
	}
	if !strings.Contains(output, "log_level") {
		t.Fatalf("expected help to mention log_level, got: %s", output)
	}
	if !strings.Contains(output, "audit_enabled") {
		t.Fatalf("expected help to mention audit_enabled, got: %s", output)
	}
	if !strings.Contains(output, "trusted_ca_path") {
		t.Fatalf("expected help to mention trusted_ca_path, got: %s", output)
	}
	if !strings.Contains(output, "trusted_ca_injection") {
		t.Fatalf("expected help to mention trusted_ca_injection, got: %s", output)
	}
}

func TestConfigSetHelpReloadMention(t *testing.T) {
	var out bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "--help"}, &out, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("config set --help failed with code %d: %s", code, out.String())
	}
	output := out.String()
	if !strings.Contains(output, "daemon") {
		t.Fatalf("expected config set help to mention daemon, got: %s", output)
	}
	if !strings.Contains(output, "set trusted_ca_path first, then set trusted_ca_injection to auto") {
		t.Fatalf("expected config set help to explain CA enablement order, got: %s", output)
	}
}

func TestConfigUnsetHelpReloadMention(t *testing.T) {
	var out bytes.Buffer
	code := runCommandWithWriters([]string{"config", "unset", "--help"}, &out, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("config unset --help failed with code %d: %s", code, out.String())
	}
	output := out.String()
	if !strings.Contains(output, "daemon") {
		t.Fatalf("expected config unset help to mention daemon, got: %s", output)
	}
	if !strings.Contains(output, `trusted_ca_path cannot be unset while trusted_ca_injection is "auto"`) {
		t.Fatalf("expected config unset help to state CA path/auto dependency, got: %s", output)
	}
	if !strings.Contains(output, `Set trusted_ca_injection to "disabled" first`) {
		t.Fatalf("expected config unset help to require disabling auto first, got: %s", output)
	}
}

func TestSystemdExecReload(t *testing.T) {
	data, err := os.ReadFile("packaging/systemd/user/docker-helper.service")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "ExecReload=%h/.local/bin/docker-helper reload") {
		t.Fatalf("systemd unit missing ExecReload, got:\n%s", content)
	}
}

func TestIsDaemonNotRunning(t *testing.T) {
	tests := []struct {
		err    error
		expect bool
	}{
		{nil, false},
		{fmt.Errorf("connection refused"), true},
		{fmt.Errorf("dial unix /tmp/socket: connection refused"), true},
		{fmt.Errorf("API error: status 400"), false},
		{fmt.Errorf("invalid config"), false},
		{fmt.Errorf("no such file or directory"), true},
		// Too-long Unix socket path causes EINVAL, must NOT be daemon-not-running.
		{fmt.Errorf("dial unix /very/long/path/that/exceeds/unix/socket/limit/this/is/a/very/long/path/that/is/definitely/over/108/characters/docker-helper/docker-helper.sock: connect: invalid argument"), false},
	}

	for _, tt := range tests {
		if got := isDaemonNotRunning(tt.err); got != tt.expect {
			t.Errorf("isDaemonNotRunning(%v) = %v, want %v", tt.err, got, tt.expect)
		}
	}
}

func TestReloadInRootHelp(t *testing.T) {
	var out bytes.Buffer
	code := runCommandWithWriters([]string{"--help"}, &out, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("root help failed with code %d: %s", code, out.String())
	}
	output := out.String()
	if !strings.Contains(output, "reload") {
		t.Fatalf("expected root help to mention reload, got: %s", output)
	}
}

// TestReloadEndpoint tests the reload HTTP endpoint directly.
func TestReloadEndpoint(t *testing.T) {
	_, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	opBuf := &bytes.Buffer{}
	initLoggers(opBuf, io.Discard, slog.LevelInfo, false)

	// Create a test server with reload endpoint
	cfg, err := loadConfig()
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

	// Wait for server to start
	waitForDialReady(t, "unix", socketPath)

	// Test reload with valid admin token
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
		t.Fatalf("reload request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("invalid JSON: %s", body)
	}
	if v, ok := result["ok"].(bool); !ok || !v {
		t.Fatalf("expected ok=true, got: %v", result["ok"])
	}
}

// TestReloadEndpointInvalidAdmin tests that reload rejects invalid admin tokens.
func TestReloadEndpointInvalidAdmin(t *testing.T) {
	_, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	cfg, err := loadConfig()
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
	req.Header.Set("Authorization", "Bearer wrong-token")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

// TestReloadEndpointInvalidConfig tests that reload rejects invalid config.
func TestReloadEndpointInvalidConfig(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	cfg, err := loadConfig()
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

	// Write invalid config
	if err := os.WriteFile(configPath, []byte(`{"allowed_roots": ["not-absolute"]}`), 0600); err != nil {
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

	if resp.StatusCode == http.StatusOK {
		t.Fatal("expected reload to fail with invalid config")
	}

	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(body, &result)
	if code, ok := result["code"].(string); !ok || code != "invalid_config" {
		t.Fatalf("expected code=invalid_config, got: %s", body)
	}
}

// TestReloadEndpointUpdatesConfig tests that reload actually updates the config.
func TestReloadEndpointUpdatesConfig(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	opBuf := &bytes.Buffer{}
	initLoggers(opBuf, io.Discard, slog.LevelInfo, false)

	cfg, err := loadConfig()
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

	// Verify initial config
	if app.Config.LogLevel != 0 { // slog.LevelInfo = 0
		t.Fatalf("expected initial log_level=info, got %s", app.Config.LogLevel.String())
	}

	// Update config file
	newAllowedRoot := testAllowedRootDir(t)

	newCfg := map[string]any{
		"allowed_root": newAllowedRoot,
		"session_ttl":  "6h",
		"log_level":    "debug",
	}
	data, err := json.MarshalIndent(newCfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	// Reload
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
		t.Fatalf("reload failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Verify config was updated. The runtime config stores the canonical
	// form of allowed_root.
	cfgAfter := app.getConfig()
	if cfgAfter.LogLevel != -4 { // slog.LevelDebug = -4
		t.Fatalf("expected log_level=debug after reload, got %s", cfgAfter.LogLevel.String())
	}
	wantRoot, err := filepath.EvalSymlinks(newAllowedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if cfgAfter.AllowedRoots[0] != wantRoot {
		t.Fatalf("expected allowed_root=%s, got %s", wantRoot, cfgAfter.AllowedRoots[0])
	}
}

// TestReloadSuccessLogContainsRequestID verifies that the successful reload
// operational log includes stream=operational, the request_id, and the message.
func TestReloadSuccessLogContainsRequestID(t *testing.T) {
	_, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	opBuf := &bytes.Buffer{}
	initLoggers(opBuf, io.Discard, slog.LevelInfo, false)
	defer logging.reset()

	cfg, err := loadConfig()
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
		t.Fatalf("reload failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	output := opBuf.String()
	if !strings.Contains(output, "configuration reloaded") {
		t.Fatalf("expected reload message in operational log:\n%s", output)
	}
	if !strings.Contains(output, `"stream":"operational"`) {
		t.Errorf("expected stream=operational:\n%s", output)
	}
	if !strings.Contains(output, `"request_id":"req_`) {
		t.Errorf("expected request_id in operational log:\n%s", output)
	}
}

// TestReloadRuntimeLogLevel verifies that log_level change takes effect at runtime.
func TestReloadRuntimeLogLevel(t *testing.T) {
	_, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	cfg, err := loadConfig()
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

	// Capture operational logs
	logBuf := &bytes.Buffer{}
	initLoggers(logBuf, io.Discard, slog.LevelInfo, false)

	app := &App{
		Config:         cfg,
		DB:             db,
		AdminTokenHash: adminHash,
	}

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

	// At info level, debug logs should NOT appear
	logBuf.Reset()
	if logging.snapshotLogger() != nil {
		logging.snapshotLogger().Debug("test debug message")
	}
	if logBuf.Len() > 0 {
		t.Fatalf("debug log should not appear at info level, got: %s", logBuf.String())
	}

	// Update config to debug level
	configPath := getConfigPath()
	allowedRoot := testAllowedRootDir(t)
	newCfg := map[string]any{
		"allowed_root": allowedRoot,
		"session_ttl":  "12h",
		"log_level":    "debug",
	}
	data, err := json.MarshalIndent(newCfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	// Reload
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
		t.Fatalf("reload failed: %v", err)
	}
	resp.Body.Close()

	// At debug level, debug logs SHOULD appear
	logBuf.Reset()
	if logging.snapshotLogger() != nil {
		logging.snapshotLogger().Debug("test debug message after reload")
	}
	if logBuf.Len() == 0 {
		t.Fatal("debug log should appear at debug level after reload")
	}
	if !strings.Contains(logBuf.String(), "test debug message after reload") {
		t.Fatalf("debug log message not found, got: %s", logBuf.String())
	}
}

// TestReloadRuntimeAuditEnabled verifies that audit_enabled change takes effect at runtime.
func TestReloadRuntimeAuditEnabled(t *testing.T) {
	_, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	cfg, err := loadConfig()
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

	// Capture audit logs
	auditBuf := &bytes.Buffer{}
	initLoggers(io.Discard, auditBuf, slog.LevelInfo, false)

	app := &App{
		Config:         cfg,
		DB:             db,
		AdminTokenHash: adminHash,
	}

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

	// Audit disabled - no audit records should be written
	auditBuf.Reset()
	writeAudit(auditRecord{Event: "test.event"})
	if auditBuf.Len() > 0 {
		t.Fatalf("audit should be disabled, got: %s", auditBuf.String())
	}

	// Update config to enable audit
	configPath := getConfigPath()
	allowedRoot := testAllowedRootDir(t)
	newCfg := map[string]any{
		"allowed_root":  allowedRoot,
		"session_ttl":   "12h",
		"log_level":     "info",
		"audit_enabled": true,
	}
	data, err := json.MarshalIndent(newCfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	// Reload
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
		t.Fatalf("reload failed: %v", err)
	}
	resp.Body.Close()

	// Audit enabled - audit records SHOULD be written
	auditBuf.Reset()
	writeAudit(auditRecord{Event: "test.event.after.reload"})
	if auditBuf.Len() == 0 {
		t.Fatal("audit should be enabled after reload")
	}
	if !strings.Contains(auditBuf.String(), "test.event.after.reload") {
		t.Fatalf("audit record not found, got: %s", auditBuf.String())
	}
}

// TestTryReloadConfigNoRuntimeDir verifies that config set rolls back
// when XDG_RUNTIME_DIR is absent. A missing runtime dir is a local error,
// NOT proof the daemon is not running (requirement #9).
func TestTryReloadConfigNoRuntimeDir(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	adminTokenPath := filepath.Join(dir, "admin.token")
	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_root": allowedRoot,
		"session_ttl":  "12h",
	}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adminTokenPath, []byte("test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", "")

	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 (local error triggers rollback), got %d, stdout: %s stderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "rolled back") {
		t.Fatalf("expected 'rolled back' in stderr, got: %s", stderr.String())
	}
	if strings.Contains(stdout.String(), "updated") {
		t.Error("must not print 'updated' on rollback")
	}

	// Verify config was rolled back.
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, restored) {
		t.Error("config.json should be byte-for-byte restored after rollback")
	}
}

// TestTryReloadConfigMissingToken verifies that config set rolls back
// when the admin token file is absent. A missing token is a local error,
// NOT proof the daemon is not running (requirement #9).
func TestTryReloadConfigMissingToken(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	runtimeDir := filepath.Join(dir, "runtime")
	configHome := filepath.Join(dir, "xdg_config")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	allowedRoot := testAllowedRootDir(t)
	cfg := map[string]any{
		"allowed_root": allowedRoot,
		"session_ttl":  "12h",
	}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	// No admin.token file created
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 (local error triggers rollback), got %d, stdout: %s stderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "rolled back") {
		t.Fatalf("expected 'rolled back' in stderr, got: %s", stderr.String())
	}
	if strings.Contains(stdout.String(), "updated") {
		t.Error("must not print 'updated' on rollback")
	}

	// Verify config was rolled back.
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, restored) {
		t.Error("config.json should be byte-for-byte restored after rollback")
	}
}

// TestConfigSnapshotRace verifies that concurrent getConfig/setConfig
// does not race. Run with -race flag.
func TestConfigSnapshotRace(t *testing.T) {
	cfg := &Config{
		AllowedRoots: []string{"/workspace/test-work"},
		SessionTTL:   12 * time.Hour,
		LogLevel:     slog.LevelInfo,
		AuditEnabled: false,
		SocketPath:   "/tmp/sock",
		DatabasePath: "/tmp/db",
	}
	app := &App{Config: cfg}

	done := make(chan bool)
	go func() {
		for i := 0; i < 200; i++ {
			c := app.getConfig()
			_ = c.AllowedRoots[0]
			_ = c.SessionTTL
			_ = c.LogLevel
			_ = c.AuditEnabled
			_ = c.SocketPath
			_ = c.DatabasePath
		}
		done <- true
	}()

	for i := 0; i < 200; i++ {
		newCfg := &Config{
			AllowedRoots: []string{"/workspace/test-new-work"},
			SessionTTL:   6 * time.Hour,
			LogLevel:     slog.LevelDebug,
			AuditEnabled: true,
		}
		app.setConfig(newCfg)
	}

	<-done

	// Verify computed paths are preserved
	final := app.getConfig()
	if final.SocketPath != "/tmp/sock" {
		t.Errorf("expected SocketPath /tmp/sock, got %s", final.SocketPath)
	}
	if final.DatabasePath != "/tmp/db" {
		t.Errorf("expected DatabasePath /tmp/db, got %s", final.DatabasePath)
	}
}

// safeBuf is a thread-safe bytes.Buffer for concurrent logger writes in tests.
type safeBuf struct {
	sync.Mutex
	bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	return s.Buffer.Write(p)
}

// TestLoggingReloadConcurrency verifies that concurrent logging/audit
// and runtime reload of log_level/audit_enabled does not race.
func TestLoggingReloadConcurrency(t *testing.T) {
	_, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	cfg, err := loadConfig()
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

	opBuf := &safeBuf{}
	auditBuf := &safeBuf{}
	initLoggers(opBuf, auditBuf, slog.LevelInfo, false)

	app := &App{
		Config:         cfg,
		DB:             db,
		AdminTokenHash: adminHash,
	}

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

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, 2*time.Second)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	configPath := getConfigPath()
	reloadRoot := testAllowedRootDir(t)

	// Concurrently do logging, audit writes, and reloads
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var logCount, auditCount, reloadCount int64

	// Goroutine 1: continuous logging
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				l := logging.snapshotLogger()
				if l != nil {
					l.Info("concurrent log")
					atomic.AddInt64(&logCount, 1)
				}
			}
		}
	}()

	// Goroutine 2: continuous audit writes
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				writeAudit(auditRecord{Event: "concurrent.audit"})
				atomic.AddInt64(&auditCount, 1)
			}
		}
	}()

	// Goroutine 3: continuous reloads
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				newCfg := map[string]any{
					"allowed_root":  reloadRoot,
					"session_ttl":   "12h",
					"log_level":     "debug",
					"audit_enabled": true,
				}
				data, _ := json.MarshalIndent(newCfg, "", "  ")
				os.WriteFile(configPath, data, 0600)

				req, _ := http.NewRequest("POST", "http://localhost/reload", nil)
				req.Header.Set("Authorization", "Bearer test-admin-token")
				resp, err := client.Do(req)
				if err == nil {
					resp.Body.Close()
				}
				atomic.AddInt64(&reloadCount, 1)
				time.Sleep(time.Millisecond)
			}
		}
	}()

	// Let it run for a bit
	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Prove all three goroutines executed concurrently.
	if atomic.LoadInt64(&logCount) == 0 {
		t.Error("logging goroutine did not execute")
	}
	if atomic.LoadInt64(&auditCount) == 0 {
		t.Error("audit goroutine did not execute")
	}
	if atomic.LoadInt64(&reloadCount) == 0 {
		t.Error("reload goroutine did not execute")
	}
}

// TestReloadInvalidConfigNoLeak verifies that when loadConfig fails during
// reload, the HTTP response contains only a stable public message while the
// full internal error is preserved in operational logging.
func TestReloadInvalidConfigNoLeak(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	// Capture operational logs
	opBuf := &bytes.Buffer{}
	initLoggers(opBuf, io.Discard, slog.LevelError, false)

	cfg, err := loadConfig()
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

	// Write invalid config that will produce a descriptive internal error
	if err := os.WriteFile(configPath, []byte(`{"allowed_roots": ["not-absolute"]}`), 0600); err != nil {
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
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("invalid JSON: %s", body)
	}

	// Verify stable public response
	if code, ok := result["code"].(string); !ok || code != "invalid_config" {
		t.Fatalf("expected code=invalid_config, got: %s", body)
	}
	if msg, ok := result["message"].(string); !ok || msg != "invalid configuration" {
		t.Fatalf("expected message='invalid configuration', got: %s", body)
	}

	// Verify no internal details leaked into the response
	if strings.Contains(strings.ToLower(string(body)), "not-absolute") {
		t.Error("response body must not contain the raw invalid value from config")
	}
	if strings.Contains(string(body), configPath) {
		t.Error("response body must not contain the config file path")
	}

	// Verify full error is in operational log
	opLog := opBuf.String()
	if !strings.Contains(opLog, "allowed_root must be a non-empty absolute path") {
		t.Errorf("expected operational log to contain the full error detail, got:\n%s", opLog)
	}
}

// --- Transactional config set/unset tests ---

// TestConfigSetReloadSuccess verifies that a successful set + reload
// keeps the new config and prints "updated".
func TestConfigSetReloadSuccess(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	// Initialize logging so handleReload doesn't panic.
	opBuf := &bytes.Buffer{}
	initLoggers(opBuf, io.Discard, slog.LevelInfo, false)

	cfg, err := loadConfig()
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
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}

	app := &App{Config: cfg, DB: db, AdminTokenHash: adminHash}
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

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated log_level=debug") {
		t.Fatalf("expected 'updated' in stdout, got: %s", stdout.String())
	}
	if strings.Contains(stdout.String(), "daemon not running") {
		t.Error("should not print 'daemon not running' when reload succeeds")
	}

	// Verify config was updated.
	raw := readConfigJSON(t, configPath)
	if v, ok := raw["log_level"]; !ok {
		t.Fatal("log_level not in config")
	} else {
		var s string
		json.Unmarshal(v, &s)
		if s != "debug" {
			t.Errorf("log_level = %q, want debug", s)
		}
	}
}

// TestConfigUnsetReloadSuccess verifies that a successful unset + reload
// keeps the new config and prints "unset".
func TestConfigUnsetReloadSuccess(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	// Initialize logging so handleReload doesn't panic.
	opBuf := &bytes.Buffer{}
	initLoggers(opBuf, io.Discard, slog.LevelInfo, false)

	cfg, err := loadConfig()
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
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}

	// Set log_level first so we can unset it.
	allowedRoot := testAllowedRootDir(t)
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(`{"allowed_root":%q,"session_ttl":"12h","log_level":"debug"}`, allowedRoot)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	app := &App{Config: cfg, DB: db, AdminTokenHash: adminHash}
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

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "unset", "log_level"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "unset log_level") {
		t.Fatalf("expected 'unset' in stdout, got: %s", stdout.String())
	}
}

// TestConfigSetReloadHTTP400 verifies that when the daemon rejects with
// HTTP 400, the config is rolled back and the command exits non-zero.
func TestConfigSetReloadHTTP400(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	// Reject all reloads with 400.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(socketPath)
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d, stdout: %s stderr: %s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "updated") {
		t.Error("must not print 'updated' on reload rejection")
	}
	if !strings.Contains(stderr.String(), "rolled back") {
		t.Errorf("expected 'rolled back' in stderr, got: %s", stderr.String())
	}

	// Verify config was rolled back.
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, restored) {
		t.Error("config.json should be byte-for-byte restored after rollback")
	}
}

// TestConfigSetReloadHTTP401 verifies that when the daemon rejects with
// HTTP 401, the config is rolled back and the command exits non-zero.
func TestConfigSetReloadHTTP401(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(socketPath)
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if strings.Contains(stdout.String(), "updated") {
		t.Error("must not print 'updated' on reload rejection")
	}

	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, restored) {
		t.Error("config should be restored after rollback")
	}
}

// TestConfigSetReloadHTTP500 verifies that when the daemon rejects with
// HTTP 500, the config is rolled back and the command exits non-zero.
func TestConfigSetReloadHTTP500(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(socketPath)
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}

	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, restored) {
		t.Error("config should be restored after rollback")
	}
}

// TestConfigSetHTTPAddressNoReload verifies that http_address set does
// not trigger a reload and prints "restart required".
func TestConfigSetHTTPAddressNoReload(t *testing.T) {
	_, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	// Initialize logging so handleReload doesn't panic.
	opBuf := &bytes.Buffer{}
	initLoggers(opBuf, io.Discard, slog.LevelInfo, false)

	cfg, err := loadConfig()
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
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}

	app := &App{Config: cfg, DB: db, AdminTokenHash: adminHash}
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

	// http_address requires system mode. Set EffectiveUID explicitly so
	// the CLI command runs in system mode even in non-root CI.
	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "http_address", "127.0.0.1:9999"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated http_address") {
		t.Fatalf("expected 'updated' in stdout, got: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "restart required") {
		t.Fatalf("expected 'restart required' in stdout, got: %s", stdout.String())
	}
}

// TestConfigSetConcurrent verifies that concurrent config set operations
// are serialized by the blocking flock. Two commands changing different
// fields both succeed; the final config contains both changes.
func TestConfigSetConcurrent(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	// Initialize logging so handleReload doesn't panic.
	opBuf := &bytes.Buffer{}
	initLoggers(opBuf, io.Discard, slog.LevelInfo, false)

	cfg, err := loadConfig()
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
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}

	app := &App{Config: cfg, DB: db, AdminTokenHash: adminHash}
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

	// Two goroutines change different fields concurrently.
	// The blocking flock serializes them; both succeed.
	var wg sync.WaitGroup
	var stdout1, stderr1, stdout2, stderr2 bytes.Buffer

	wg.Add(2)
	go func() {
		defer wg.Done()
		code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout1, &stderr1)
		if code != 0 {
			t.Errorf("set log_level: exit %d, stderr: %s", code, stderr1.String())
		}
	}()
	go func() {
		defer wg.Done()
		code := runCommandWithWriters([]string{"config", "set", "audit_enabled", "true"}, &stdout2, &stderr2)
		if code != 0 {
			t.Errorf("set audit_enabled: exit %d, stderr: %s", code, stderr2.String())
		}
	}()
	wg.Wait()

	// Both should succeed.
	if !strings.Contains(stdout1.String(), "updated log_level=debug") {
		t.Errorf("expected log_level update, got: %s (stderr: %s)", stdout1.String(), stderr1.String())
	}
	if !strings.Contains(stdout2.String(), "updated audit_enabled=true") {
		t.Errorf("expected audit_enabled update, got: %s (stderr: %s)", stdout2.String(), stderr2.String())
	}

	// Verify both changes are in the config file.
	raw := readConfigJSON(t, configPath)
	if v, ok := raw["log_level"]; !ok {
		t.Error("log_level not in config")
	} else {
		var s string
		json.Unmarshal(v, &s)
		if s != "debug" {
			t.Errorf("log_level = %q, want debug", s)
		}
	}
	if v, ok := raw["audit_enabled"]; !ok {
		t.Error("audit_enabled not in config")
	} else {
		var b bool
		json.Unmarshal(v, &b)
		if !b {
			t.Error("audit_enabled = false, want true")
		}
	}
}

// TestConfigSetRollbackRereloadSuccess verifies that when the first reload
// returns 400 but the second (after restoration) returns 200, the config
// is rolled back and the daemon is synchronized.
func TestConfigSetRollbackRereloadSuccess(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	// Mock server: first reload returns 400, second returns 200.
	var reloadCount int
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reloadCount++
		count := reloadCount
		mu.Unlock()
		if count == 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(socketPath)
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d, stdout: %s stderr: %s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "updated") {
		t.Error("must not print 'updated' on reload rejection")
	}
	if !strings.Contains(stderr.String(), "reload rejected") {
		t.Errorf("expected 'reload rejected' in stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "rolled back") {
		t.Errorf("expected 'rolled back' in stderr, got: %s", stderr.String())
	}

	// Verify two reload requests were made.
	mu.Lock()
	count := reloadCount
	mu.Unlock()
	if count != 2 {
		t.Errorf("expected 2 reload requests, got %d", count)
	}

	// Verify config was rolled back to original bytes.
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, restored) {
		t.Error("config.json should be byte-for-byte restored after rollback")
	}
}

// TestConfigSetRollbackRereloadFail verifies that when both reloads fail,
// the error message includes both the initial reload error and the re-reload error.
func TestConfigSetRollbackRereloadFail(t *testing.T) {
	_, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	// Mock server: both reloads return 400.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(socketPath)
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if strings.Contains(stdout.String(), "updated") {
		t.Error("must not print 'updated' on reload rejection")
	}
	if !strings.Contains(stderr.String(), "reload rejected") {
		t.Errorf("expected 'reload rejected' in stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "rolled back") {
		t.Errorf("expected 'rolled back' in stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "re-reload rejected") {
		t.Errorf("expected 're-reload rejected' in stderr, got: %s", stderr.String())
	}
}

// TestConfigUnsetRollback verifies that unset also performs rollback
// when the daemon rejects the reload.
func TestConfigUnsetRollback(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	// Set log_level first so we can unset it.
	allowedRoot := testAllowedRootDir(t)
	newConfig := fmt.Sprintf(`{"allowed_root":%q,"session_ttl":"12h","log_level":"debug"}`, allowedRoot) + "\n"
	if err := os.WriteFile(configPath, []byte(newConfig), 0600); err != nil {
		t.Fatal(err)
	}
	original := []byte(newConfig)

	// Mock server: reject reload.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(socketPath)
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "unset", "log_level"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d, stdout: %s stderr: %s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "unset log_level") {
		t.Error("must not print 'unset' on reload rejection")
	}
	if !strings.Contains(stderr.String(), "reload rejected") {
		t.Errorf("expected 'reload rejected' in stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "rolled back") {
		t.Errorf("expected 'rolled back' in stderr, got: %s", stderr.String())
	}

	// Verify config was rolled back (log_level still present).
	raw := readConfigJSON(t, configPath)
	if v, ok := raw["log_level"]; !ok {
		t.Error("log_level should still be in config after rollback")
	} else {
		var s string
		json.Unmarshal(v, &s)
		if s != "debug" {
			t.Errorf("log_level = %q, want debug (not rolled back)", s)
		}
	}

	// Verify config bytes match original.
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, restored) {
		t.Error("config.json should be byte-for-byte restored after rollback")
	}
}

// TestConfigSetHTTPAddressNoReloadRequest verifies that http_address set
// makes exactly zero /reload requests.
func TestConfigSetHTTPAddressNoReloadRequest(t *testing.T) {
	_, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	opBuf := &bytes.Buffer{}
	initLoggers(opBuf, io.Discard, slog.LevelInfo, false)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}

	db, err := openDatabase(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	var reloadCount int
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		reloadCount++
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(socketPath)
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	// http_address requires system mode. Set EffectiveUID explicitly so
	// the CLI command runs in system mode even in non-root CI.
	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "http_address", "127.0.0.1:9999"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated http_address") {
		t.Fatalf("expected 'updated' in stdout, got: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "restart required") {
		t.Fatalf("expected 'restart required' in stdout, got: %s", stdout.String())
	}
	if reloadCount != 0 {
		t.Errorf("expected 0 reload requests for http_address, got %d", reloadCount)
	}
}

// TestConfigSetRollbackWriteFail verifies that when the rollback write fails,
// both the initial reload error and the rollback write error are reported.
func TestConfigSetRollbackWriteFail(t *testing.T) {
	_, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	// Mock server: reject reload.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})

	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(socketPath)
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	// Inject a writer that fails on the second call (rollback).
	writeCount := 0
	failingWriter := configWriter(func(path string, data []byte) error {
		writeCount++
		if writeCount == 2 {
			return fmt.Errorf("simulated write failure")
		}
		return safeWriteConfig(path, data)
	})

	var stdout, stderr bytes.Buffer
	code := applyConfigChangeTransactionally(
		configOpSet,
		"log_level",
		"debug",
		json.RawMessage(`"debug"`),
		func(raw map[string]json.RawMessage) {
			raw["log_level"] = json.RawMessage(`"debug"`)
		},
		failingWriter,
		&stdout,
		&stderr,
	)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "reload rejected") {
		t.Errorf("expected 'reload rejected' in stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "rollback write failed") {
		t.Errorf("expected 'rollback write failed' in stderr, got: %s", stderr.String())
	}
}

// TestConfigSetReloadTransportError verifies that a transport error (daemon
// socket disappears mid-request) triggers rollback.
func TestConfigSetReloadTransportError(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	original, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	// Start a server that closes the connection on first /reload request.
	var firstRequest bool
	mux := http.NewServeMux()
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		if !firstRequest {
			firstRequest = true
			// Close the underlying connection to simulate transport error.
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			conn.Close()
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{Handler: mux}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener)
	defer func() {
		server.Close()
		os.Remove(socketPath)
	}()
	waitForDialReady(t, "unix", socketPath)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d, stdout: %s stderr: %s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "updated") {
		t.Error("must not print 'updated' on transport error")
	}
	if !strings.Contains(stderr.String(), "reload") {
		t.Errorf("expected 'reload' in stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "rolled back") {
		t.Errorf("expected 'rolled back' in stderr, got: %s", stderr.String())
	}

	// Verify config was rolled back.
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, restored) {
		t.Error("config.json should be byte-for-byte restored after rollback")
	}
}

// TestReloadCATypedErrorDiagnostic verifies that a CA preparation failure
// whose inner error does NOT contain the literal string "trusted_ca" still
// produces the detailed trusted-CA diagnostic. This is a regression test for
// the brittle strings.Contains(err.Error(), "trusted_ca") check that was
// replaced with errors.As(err, &trustedCAPreparationError).
func TestReloadCATypedErrorDiagnostic(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	// Capture operational logs
	opBuf := &bytes.Buffer{}
	initLoggers(opBuf, io.Discard, slog.LevelError, false)

	cfg, err := loadConfig()
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

	// Write config that triggers CA preparation with a path that will fail
	// with "permission denied" (not containing "trusted_ca").
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	generateTestCAPEM(t, caPath)
	// Make the runtime dir unreadable so symlink creation fails with "permission denied".
	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	if err := os.MkdirAll(runtimeSubDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Remove read permission from runtime dir to trigger "permission denied"
	if err := os.Chmod(runtimeSubDir, 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(runtimeSubDir, 0700) })

	oldRuntime := os.Getenv("XDG_RUNTIME_DIR")
	os.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Cleanup(func() { os.Setenv("XDG_RUNTIME_DIR", oldRuntime) })

	newCfg := map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	}
	data, err := json.MarshalIndent(newCfg, "", "  ")
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
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("invalid JSON: %s", body)
	}

	// The response must contain the detailed CA diagnostic, not just "invalid configuration".
	msg, ok := result["message"].(string)
	if !ok {
		t.Fatalf("expected message string, got: %s", body)
	}
	if !strings.Contains(msg, "trusted CA preparation failed") {
		t.Errorf("expected 'trusted CA preparation failed' in response message, got: %s", msg)
	}
	// The inner error (permission denied) should also be visible.
	if !strings.Contains(msg, "permission denied") && !strings.Contains(msg, "cannot create") {
		// The exact inner error depends on the OS; either is acceptable.
		// The key point is that the message is more specific than "invalid configuration".
		if msg == "invalid configuration" {
			t.Error("got generic 'invalid configuration' instead of detailed CA diagnostic")
		}
	}

	// Verify the operational log contains the diagnostic field.
	opLog := opBuf.String()
	if !strings.Contains(opLog, "trusted CA preparation failed") {
		t.Errorf("expected 'trusted CA preparation failed' in operational log, got:\n%s", opLog)
	}
}

// TestReloadRejectsOutsideCASourceSystemMode verifies that the reload endpoint
// rejects a config.json with trusted_ca_injection=auto and trusted_ca_path
// outside /etc/docker-helper when running in system mode.
//
// This exercises the real path:
//
//	handleReload -> loadConfig -> validateSystemCASourcePath
//
// and proves the active runtime config is unchanged after rejection.
func TestReloadRejectsOutsideCASourceSystemMode(t *testing.T) {
	configPath, _, socketPath, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	opBuf := &bytes.Buffer{}
	initLoggers(opBuf, io.Discard, slog.LevelInfo, false)

	// 1. Load a valid initial config and create App.
	cfg, err := loadConfig()
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

	// 2. Snapshot the active runtime config.
	originalConfig := app.getConfig()

	// 3. Set up the HTTP server with the real handleReload.
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

	// 4. Create a valid CA file outside /etc/docker-helper.
	caFile := filepath.Join(t.TempDir(), "outside-ca.pem")
	generateTestCAPEM(t, caFile)

	// 5. Switch EffectiveUID to 0 (system mode) for the reload attempt.
	origEffectiveUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origEffectiveUID }()

	// 6. Manually replace config.json with a structurally valid config
	//    containing trusted_ca_injection=auto and an outside CA path.
	newCfg := map[string]any{
		"allowed_root":         originalConfig.AllowedRoots[0],
		"session_ttl":          "12h",
		"log_level":            "info",
		"trusted_ca_injection": "auto",
		"trusted_ca_path":      caFile,
	}
	data, err := json.MarshalIndent(newCfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	// 7. Call the real POST /reload endpoint with valid admin auth.
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
		t.Fatalf("reload request failed: %v", err)
	}
	defer resp.Body.Close()

	// 8. Prove HTTP status is 400.
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	// 9. Prove response code is invalid_config.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("invalid JSON: %s", body)
	}
	if code, ok := result["code"].(string); !ok || code != "invalid_config" {
		t.Fatalf("expected code=invalid_config, got: %s", body)
	}

	// 10. Prove the App's active runtime config is unchanged.
	currentConfig := app.getConfig()
	if currentConfig.AllowedRoots[0] != originalConfig.AllowedRoots[0] {
		t.Errorf("AllowedRoot changed: got %q, want %q", currentConfig.AllowedRoots[0], originalConfig.AllowedRoots[0])
	}
	if currentConfig.SessionTTL != originalConfig.SessionTTL {
		t.Errorf("SessionTTL changed: got %v, want %v", currentConfig.SessionTTL, originalConfig.SessionTTL)
	}
	if currentConfig.LogLevel != originalConfig.LogLevel {
		t.Errorf("LogLevel changed: got %v, want %v", currentConfig.LogLevel, originalConfig.LogLevel)
	}

	// 11. In particular, trusted_ca_injection and trusted_ca_path are not replaced.
	if currentConfig.TrustedCAInjection != originalConfig.TrustedCAInjection {
		t.Errorf("TrustedCAInjection changed: got %q, want %q", currentConfig.TrustedCAInjection, originalConfig.TrustedCAInjection)
	}
	if currentConfig.TrustedCAPath != originalConfig.TrustedCAPath {
		t.Errorf("TrustedCAPath changed: got %q, want %q", currentConfig.TrustedCAPath, originalConfig.TrustedCAPath)
	}

	// 12. Prove the rejection was caused by the system CA source containment
	//     policy, not an unrelated later failure. The operational log contains
	//     the error from validateSystemCASourcePath.
	opLogs := opBuf.String()
	if !strings.Contains(opLogs, systemCASourceRoot) {
		t.Errorf("expected reload error log to contain %q (system CA source policy), got:\n%s", systemCASourceRoot, opLogs)
	}
}

// TestReloadNoGlobalRootMACVerification verifies that reload does NOT
// perform MAC verification for global allowed_roots. Global roots are
// authorization-only; MAC state follows session workspaces.
func TestReloadNoGlobalRootMACVerification(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}

	opBuf := &bytes.Buffer{}
	initLoggers(opBuf, io.Discard, slog.LevelError, false)

	db, err := openDatabase(filepath.Join(stateDir, "docker-helper.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	token := "test-admin-token"
	adminHash := sha256.Sum256([]byte(token))

	app := &App{
		Config: &Config{
			AllowedRoots: []string{"/home"},
			SessionTTL:   12 * time.Hour,
			LogLevel:     slog.LevelInfo,
			Mode:         ModeSystem,
		},
		DB:             db,
		AdminTokenHash: adminHash,
	}

	// Reload with a global root that has no MAC coverage.
	// This must succeed — global roots are authorization-only.
	deps := reloadDeps{
		loadConfig: func() (*Config, error) {
			return &Config{
				AllowedRoots: []string{"/opt"},
				SessionTTL:   12 * time.Hour,
				LogLevel:     slog.LevelInfo,
				Mode:         ModeSystem,
			}, nil
		},
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/reload", nil)
	req.Header.Set("Authorization", "Bearer test-admin-token")

	app.handleReloadWithDeps(recorder, req, deps)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body: %s", recorder.Code, recorder.Body.Bytes())
	}

	// Config was updated.
	currentConfig := app.getConfig()
	if currentConfig.AllowedRoots[0] != "/opt" {
		t.Errorf("AllowedRoot not updated: got %q, want /opt", currentConfig.AllowedRoots[0])
	}
}
