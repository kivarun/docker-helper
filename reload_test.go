package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	cfgAfter := app.getConfig()
	if cfgAfter.LogLevel != -4 { // slog.LevelDebug = -4
		t.Fatalf("expected log_level=debug after reload, got %s", cfgAfter.LogLevel.String())
	}
	if cfgAfter.AllowedRoot != "/tmp/new-work" {
		t.Fatalf("expected allowed_root=/tmp/new-work, got %s", cfgAfter.AllowedRoot)
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

	time.Sleep(100 * time.Millisecond)

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
	newCfg := map[string]any{
		"allowed_root": "/tmp/work",
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

	time.Sleep(100 * time.Millisecond)

	// Audit disabled - no audit records should be written
	auditBuf.Reset()
	writeAudit(auditRecord{Event: "test.event"})
	if auditBuf.Len() > 0 {
		t.Fatalf("audit should be disabled, got: %s", auditBuf.String())
	}

	// Update config to enable audit
	configPath := getConfigPath()
	newCfg := map[string]any{
		"allowed_root":  "/tmp/work",
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

// TestTryReloadConfigNoRuntimeDir verifies that config set prints
// "daemon not running" when XDG_RUNTIME_DIR is absent (early return path).
func TestTryReloadConfigNoRuntimeDir(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	adminTokenPath := filepath.Join(dir, "admin.token")
	if err := os.WriteFile(configPath, []byte(`{"allowed_root":"/tmp/work","session_ttl":"12h"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adminTokenPath, []byte("test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", "")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "daemon not running") {
		t.Fatalf("expected 'daemon not running' message, got: %s", stdout.String())
	}
}

// TestTryReloadConfigMissingToken verifies that config set prints
// "daemon not running" when the admin token file is absent (early return path).
func TestTryReloadConfigMissingToken(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`{"allowed_root":"/tmp/work","session_ttl":"12h"}`), 0600); err != nil {
		t.Fatal(err)
	}
	// No admin.token file created
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "log_level", "debug"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "daemon not running") {
		t.Fatalf("expected 'daemon not running' message, got: %s", stdout.String())
	}
}

// TestConfigSnapshotRace verifies that concurrent getConfig/setConfig
// does not race. Run with -race flag.
func TestConfigSnapshotRace(t *testing.T) {
	cfg := &Config{
		AllowedRoot:  "/tmp/work",
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
			_ = c.AllowedRoot
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
			AllowedRoot:  "/tmp/new-work",
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
	time.Sleep(100 * time.Millisecond)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, 2*time.Second)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	configPath := getConfigPath()

	// Concurrently do logging, audit writes, and reloads
	stop := make(chan struct{})
	var wg sync.WaitGroup

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
					"allowed_root":  "/tmp/work",
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
				time.Sleep(time.Millisecond)
			}
		}
	}()

	// Let it run for a bit
	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()
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

	time.Sleep(100 * time.Millisecond)

	// Write invalid config that will produce a descriptive internal error
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
