package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	stateSubDir := filepath.Join(stateHome, "docker-helper")
	socketPath = filepath.Join(runtimeSubDir, "docker-helper.sock")
	lockPath = socketPath + ".lock"

	cfg := map[string]any{
		"allowed_root": "/tmp/work",
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
	os.Setenv("DOCKER_HELPER_CONFIG", configPath)
	os.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	os.Setenv("XDG_STATE_HOME", stateHome)

	cleanup = func() {
		os.Setenv("DOCKER_HELPER_CONFIG", oldConfig)
		os.Setenv("XDG_RUNTIME_DIR", oldRuntime)
		os.Setenv("XDG_STATE_HOME", oldState)
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
	_, _, _, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

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
}

func TestConfigUnsetDaemonNotRunning(t *testing.T) {
	configPath, _, _, _, cleanup := setupReloadTestEnv(t)
	defer cleanup()

	cfg := map[string]any{
		"allowed_root":  "/tmp/work",
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

	cfg := map[string]any{
		"allowed_root": "/tmp/work",
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
	if !strings.Contains(output, "allowed_root") {
		t.Fatalf("expected help to mention allowed_root, got: %s", output)
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
}

func TestSystemdExecReload(t *testing.T) {
	data, err := os.ReadFile("packaging/systemd/user/docker-helper.service")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.Contains(content, "ExecReload=/usr/bin/docker-helper reload") {
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
	time.Sleep(100 * time.Millisecond)

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

	time.Sleep(100 * time.Millisecond)

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

	time.Sleep(100 * time.Millisecond)

	// Write invalid config
	if err := os.WriteFile(configPath, []byte(`{"allowed_root": "not-absolute"}`), 0600); err != nil {
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

	time.Sleep(100 * time.Millisecond)

	// Verify initial config
	if app.Config.LogLevel != 0 { // slog.LevelInfo = 0
		t.Fatalf("expected initial log_level=info, got %s", app.Config.LogLevel.String())
	}

	// Update config file
	newCfg := map[string]any{
		"allowed_root": "/tmp/new-work",
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

	// Verify config was updated
	if app.Config.LogLevel != -4 { // slog.LevelDebug = -4
		t.Fatalf("expected log_level=debug after reload, got %s", app.Config.LogLevel.String())
	}
	if app.Config.AllowedRoot != "/tmp/new-work" {
		t.Fatalf("expected allowed_root=/tmp/new-work, got %s", app.Config.AllowedRoot)
	}
}
