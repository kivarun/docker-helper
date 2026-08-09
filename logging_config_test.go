package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Audit enabled resolution tests ---

func TestResolveAuditEnabled(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name     string
		cfg      *bool
		level    string
		expected bool
	}{
		{"explicit true with info", &trueVal, "info", true},
		{"explicit false with debug", &falseVal, "debug", false},
		{"absent with debug", nil, "debug", true},
		{"absent with info", nil, "info", false},
		{"absent with warn", nil, "warn", false},
		{"absent with error", nil, "error", false},
		{"explicit true with debug", &trueVal, "debug", true},
		{"explicit false with info", &falseVal, "info", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level, _ := parseLogLevel(tt.level)
			got := resolveAuditEnabled(tt.cfg, level)
			if got != tt.expected {
				t.Errorf("resolveAuditEnabled(%v, %s) = %v, want %v", tt.cfg, tt.level, got, tt.expected)
			}
		})
	}
}

func TestConfigLoadAuditEnabledAbsentInfo(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	configDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Config with log_level=info, no audit_enabled
	configData := []byte(`{"allowed_root":"` + dir + `","session_ttl":"12h","log_level":"info"}`)
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), configData, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.AuditEnabled {
		t.Error("audit should be disabled when audit_enabled absent and log_level=info")
	}
}

func TestConfigLoadAuditEnabledAbsentDebug(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	configDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	configData := []byte(`{"allowed_root":"` + dir + `","session_ttl":"12h","log_level":"debug"}`)
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), configData, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if !cfg.AuditEnabled {
		t.Error("audit should be enabled when audit_enabled absent and log_level=debug")
	}
}

func TestConfigLoadAuditEnabledExplicitFalseDebug(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	configDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	configData := []byte(`{"allowed_root":"` + dir + `","session_ttl":"12h","log_level":"debug","audit_enabled":false}`)
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), configData, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if cfg.AuditEnabled {
		t.Error("audit should be disabled when audit_enabled=false even with log_level=debug")
	}
}

func TestConfigLoadAuditEnabledExplicitTrueInfo(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_RUNTIME_DIR", dir)

	configDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	configData := []byte(`{"allowed_root":"` + dir + `","session_ttl":"12h","log_level":"info","audit_enabled":true}`)
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), configData, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	if !cfg.AuditEnabled {
		t.Error("audit should be enabled when audit_enabled=true with log_level=info")
	}
}

// --- Disabled audit behavior tests ---

func TestDisabledAuditNoOutput(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo, false)
	defer func() {
		opLogger = nil
		auditWriter = nil
		auditEnabled = false
	}()

	writeAudit(auditRecord{Event: "test.no_output"})

	if auditBuf.Len() != 0 {
		t.Errorf("audit output should be empty when disabled, got: %s", auditBuf.String())
	}
}

func TestDisabledAuditNoWriteAttempt(t *testing.T) {
	// Use a writer that panics on Write to verify it's never called.
	panicWriter := &panicOnWriteWriter{}
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, panicWriter, slog.LevelInfo, false)
	defer func() {
		opLogger = nil
		auditWriter = nil
		auditEnabled = false
	}()

	// Should not panic because audit is disabled.
	writeAudit(auditRecord{Event: "test.no_write"})
}

// panicOnWriteWriter panics on Write to verify it's never called.
type panicOnWriteWriter struct{}

func (w *panicOnWriteWriter) Write(p []byte) (int, error) {
	panic("writeAudit should not write when audit is disabled")
}

// --- Init omits audit_enabled ---

func TestInitOmitsAuditEnabled(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_STATE_HOME", dir)

	if err := runInit(dir, io.Discard, io.Discard); err != nil {
		t.Fatalf("runInit: %v", err)
	}

	configPath := filepath.Join(dir, "docker-helper", "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	if strings.Contains(string(data), "audit_enabled") {
		t.Fatalf("generated config should not contain audit_enabled:\n%s", data)
	}
}

// --- Startup record tests ---

func TestStartupRecordFormat(t *testing.T) {
	opBuf := new(bytes.Buffer)
	auditBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo, false)
	defer func() {
		opLogger = nil
		auditWriter = nil
		auditEnabled = false
	}()

	// Simulate the exact log call used in main.go
	opLogger.Info("daemon listening",
		"socket", "/run/user/1000/docker-helper/docker-helper.sock",
	)

	opOutput := opBuf.String()
	if opOutput == "" {
		t.Fatal("operational output is empty")
	}

	for _, line := range strings.Split(strings.TrimSpace(opOutput), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("invalid JSON: %s: %v", line, err)
			continue
		}

		msg, _ := m["msg"].(string)
		if msg == "daemon listening" {
			if _, hasLogLevel := m["log_level"]; hasLogLevel {
				t.Error("startup record must not contain log_level field")
			}
			if m["stream"] != "operational" {
				t.Errorf("expected stream=operational, got %v", m["stream"])
			}
			if m["socket"] == nil {
				t.Error("startup record must contain socket field")
			}
			return
		}
	}

	t.Error("daemon listening record not found in operational output")
}

// --- Timestamp RFC3339Nano tests ---

func TestOperationalTimestampRFC3339Nano(t *testing.T) {
	opBuf := new(bytes.Buffer)
	auditBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo, false)
	defer func() {
		opLogger = nil
		auditWriter = nil
		auditEnabled = false
	}()

	opLogger.Info("timestamp test")

	line := strings.TrimSpace(opBuf.String())
	if line == "" {
		t.Fatal("operational output is empty")
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("cannot parse operational record: %v", err)
	}

	timeStr, ok := m["time"].(string)
	if !ok {
		t.Fatal("time field not found or not a string")
	}

	tm, err := time.Parse(time.RFC3339Nano, timeStr)
	if err != nil {
		t.Fatalf("operational time not RFC3339Nano: %q: %v", timeStr, err)
	}

	if !tm.IsZero() && tm.UTC() != tm {
		t.Errorf("operational time not UTC: %v", tm)
	}
}

func TestAuditTimestampRFC3339Nano(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo, true)
	defer func() {
		opLogger = nil
		auditWriter = nil
		auditEnabled = false
	}()

	writeAudit(auditRecord{Event: "test.timestamp"})

	line := strings.TrimSpace(auditBuf.String())
	if line == "" {
		t.Fatal("audit output is empty")
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("cannot parse audit record: %v", err)
	}

	timeStr, ok := m["time"].(string)
	if !ok {
		t.Fatal("time field not found or not a string")
	}

	tm, err := time.Parse(time.RFC3339Nano, timeStr)
	if err != nil {
		t.Fatalf("audit time not RFC3339Nano: %q: %v", timeStr, err)
	}

	if !tm.IsZero() && tm.UTC() != tm {
		t.Errorf("audit time not UTC: %v", tm)
	}
}

// --- Debug request log tests ---

func TestDebugRequestLogEmitAtDebug(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelDebug, true)
	defer func() {
		opLogger = nil
		auditWriter = nil
		auditEnabled = false
	}()

	app := newTestAppWithAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler := withRequestID(withLogging(app.handleHealth))
	handler(w, req)

	opOutput := opBuf.String()
	if !strings.Contains(opOutput, "request completed") {
		t.Fatalf("expected 'request completed' at debug level:\n%s", opOutput)
	}
}

func TestDebugRequestLogSuppressedAtInfo(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo, true)
	defer func() {
		opLogger = nil
		auditWriter = nil
		auditEnabled = false
	}()

	app := newTestAppWithAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler := withRequestID(withLogging(app.handleHealth))
	handler(w, req)

	opOutput := opBuf.String()
	if strings.Contains(opOutput, "request completed") {
		t.Fatalf("'request completed' should be suppressed at info level:\n%s", opOutput)
	}
}

func TestDebugRequestLogFields(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelDebug, true)
	defer func() {
		opLogger = nil
		auditWriter = nil
		auditEnabled = false
	}()

	app := newTestAppWithAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/health?foo=bar", nil)
	req.Pattern = "GET /health"
	w := httptest.NewRecorder()

	handler := withRequestID(withLogging(app.handleHealth))
	handler(w, req)

	opOutput := opBuf.String()
	for _, line := range strings.Split(strings.TrimSpace(opOutput), "\n") {
		if line == "" || !strings.Contains(line, "request completed") {
			continue
		}

		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("cannot parse debug record: %v: %s", err, line)
		}

		// Check required fields
		if m["msg"] != "request completed" {
			t.Errorf("expected msg='request completed', got %v", m["msg"])
		}
		if m["request_id"] == nil || m["request_id"] == "" {
			t.Error("expected request_id to be present")
		}
		if m["method"] != "GET" {
			t.Errorf("expected method='GET', got %v", m["method"])
		}
		if m["route"] != "GET /health" {
			t.Errorf("expected route='GET /health', got %v", m["route"])
		}
		if m["status"] == nil {
			t.Error("expected status to be present")
		} else {
			status, ok := m["status"].(float64)
			if !ok || status != 200 {
				t.Errorf("expected status=200, got %v", m["status"])
			}
		}
		if m["duration_ms"] == nil {
			t.Error("expected duration_ms to be present")
		} else {
			// Verify it's a number, not a string
			if _, ok := m["duration_ms"].(float64); !ok {
				t.Errorf("expected duration_ms to be a number, got %T", m["duration_ms"])
			}
		}
		if m["stream"] != "operational" {
			t.Errorf("expected stream=operational, got %v", m["stream"])
		}

		// Verify no query string leakage
		if strings.Contains(line, "foo=bar") {
			t.Error("debug record must not contain query parameters")
		}

		return
	}

	t.Fatal("no 'request completed' record found")
}

func TestDebugRequestLogNoSessionIDLeak(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelDebug, true)
	defer func() {
		opLogger = nil
		auditWriter = nil
		auditEnabled = false
	}()

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)
	w := httptest.NewRecorder()

	handler := withRequestID(withLogging(app.handleRun))
	handler(w, req)

	opOutput := opBuf.String()
	for _, line := range strings.Split(strings.TrimSpace(opOutput), "\n") {
		if line == "" || !strings.Contains(line, "request completed") {
			continue
		}

		// The session ID should not appear in the route field
		if strings.Contains(line, result.Session.ID) {
			t.Errorf("debug record must not contain actual session ID:\n%s", line)
		}

		return
	}

	t.Fatal("no 'request completed' record found")
}

func TestDebugRequestLogParameterizedRoute(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelDebug, true)
	defer func() {
		opLogger = nil
		auditWriter = nil
		auditEnabled = false
	}()

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/sessions/"+result.Session.ID, nil)
	req.Pattern = "DELETE /sessions/{id}"
	withAuth(req)
	w := httptest.NewRecorder()

	handler := withRequestID(withLogging(app.handleDeleteSession))
	handler(w, req)

	opOutput := opBuf.String()
	for _, line := range strings.Split(strings.TrimSpace(opOutput), "\n") {
		if line == "" || !strings.Contains(line, "request completed") {
			continue
		}

		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("cannot parse debug record: %v: %s", err, line)
		}

		route, ok := m["route"].(string)
		if !ok {
			t.Fatalf("route not found in debug record")
		}

		// Route should use pattern format, not actual session ID
		if strings.Contains(route, result.Session.ID) {
			t.Errorf("route must not contain actual session ID: %q", route)
		}

		// Route should contain the pattern format with {id}
		if !strings.Contains(route, "/sessions/{id}") {
			t.Errorf("expected route to contain /sessions/{id}, got %q", route)
		}

		return
	}

	t.Fatal("no 'request completed' record found")
}

func TestDebugRequestLogIncludesHealth(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelDebug, true)
	defer func() {
		opLogger = nil
		auditWriter = nil
		auditEnabled = false
	}()

	app := newTestAppWithAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler := withRequestID(withLogging(app.handleHealth))
	handler(w, req)

	opOutput := opBuf.String()
	if !strings.Contains(opOutput, "request completed") {
		t.Fatalf("expected 'request completed' for /health at debug level:\n%s", opOutput)
	}
}

func TestDebugRequestLogNon200Status(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelDebug, true)
	defer func() {
		opLogger = nil
		auditWriter = nil
		auditEnabled = false
	}()

	app := newTestAppWithAuth(t)

	req := httptest.NewRequest(http.MethodPost, "/run", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer invalid-token")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler := withRequestID(withLogging(app.handleRun))
	handler(w, req)

	opOutput := opBuf.String()
	for _, line := range strings.Split(strings.TrimSpace(opOutput), "\n") {
		if line == "" || !strings.Contains(line, "request completed") {
			continue
		}

		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("cannot parse debug record: %v: %s", err, line)
		}

		status, ok := m["status"].(float64)
		if !ok {
			t.Fatalf("status not a number in debug record")
		}
		if status != 401 {
			t.Errorf("expected status=401 for unauthorized request, got %v", status)
		}

		return
	}

	t.Fatal("no 'request completed' record found")
}
