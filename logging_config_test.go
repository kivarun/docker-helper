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
	defer logging.reset()

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
	defer logging.reset()

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
	defer logging.reset()

	// Simulate the exact log call used in main.go
	logging.snapshotLogger().Info("daemon listening",
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
	defer logging.reset()

	logging.snapshotLogger().Info("timestamp test")

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
	defer logging.reset()

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
	defer logging.reset()

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
	defer logging.reset()

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
	defer logging.reset()

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
	defer logging.reset()

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
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
	defer logging.reset()

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /sessions/{id}", withRequestID(withLogging(app.handleDeleteSession)))

	req := httptest.NewRequest(http.MethodDelete, "/sessions/"+result.Session.ID, nil)
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

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
	defer logging.reset()

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
	defer logging.reset()

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

// TestStatusResponseWriterCapturesFirstWriteHeader verifies that
// statusResponseWriter records only the first WriteHeader call,
// matching net/http semantics.
func TestStatusResponseWriterCapturesFirstWriteHeader(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelDebug, true)
	defer logging.reset()

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.WriteHeader(http.StatusInternalServerError)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	withRequestID(withLogging(handler))(w, req)

	// Verify actual response status is 201 (first WriteHeader).
	if w.Code != http.StatusCreated {
		t.Errorf("expected response status 201, got %d", w.Code)
	}

	// Verify operational log contains status=201.
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
			t.Fatal("expected status to be a number")
		}
		if status != 201 {
			t.Errorf("expected logged status=201, got %v", status)
		}
		return
	}

	t.Fatal("no 'request completed' record found")
}

// TestStatusResponseWriterImplicitOKOnWrite verifies that when Write()
// is called before WriteHeader, the middleware captures status=200
// (implicit OK from net/http semantics).
func TestStatusResponseWriterImplicitOKOnWrite(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelDebug, true)
	defer logging.reset()

	handler := func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
		w.WriteHeader(http.StatusBadGateway)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	withRequestID(withLogging(handler))(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected response status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if body != "ok" {
		t.Errorf("expected body 'ok', got %q", body)
	}

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
			t.Fatal("expected status to be a number")
		}
		if status != 200 {
			t.Errorf("expected logged status=200, got %v", status)
		}
		return
	}

	t.Fatal("no 'request completed' record found")
}

// TestMiddlewareWrapsUnknownRoute verifies that an unmatched request
// gets request_id, request completed log with status=404, and route=<unmatched>.
func TestMiddlewareWrapsUnknownRoute(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelDebug, true)
	defer logging.reset()

	mux := http.NewServeMux()
	handler := withRequestID(withLogging(http.HandlerFunc(mux.ServeHTTP)))

	req := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}

	rid := w.Header().Get("X-Request-ID")
	if rid == "" {
		t.Error("expected X-Request-ID header on unknown route")
	}

	opOutput := opBuf.String()
	for _, line := range strings.Split(strings.TrimSpace(opOutput), "\n") {
		if line == "" || !strings.Contains(line, "request completed") {
			continue
		}

		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("cannot parse record: %v: %s", err, line)
		}

		if m["request_id"] != rid {
			t.Errorf("expected request_id=%s, got %v", rid, m["request_id"])
		}
		status, ok := m["status"].(float64)
		if !ok || status != 404 {
			t.Errorf("expected status=404, got %v", m["status"])
		}
		if m["route"] != "<unmatched>" {
			t.Errorf("expected route=<unmatched>, got %v", m["route"])
		}

		// Verify raw path did not leak.
		if strings.Contains(line, "/unknown/path") {
			t.Error("raw unknown path must not appear in log")
		}
		return
	}

	t.Fatal("no 'request completed' record found")
}

// TestMiddlewareWrapsMethodMismatch verifies that a 405 on an existing
// route gets request_id and request completed log with status=405.
func TestMiddlewareWrapsMethodMismatch(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelDebug, true)
	defer logging.reset()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {})
	handler := withRequestID(withLogging(http.HandlerFunc(mux.ServeHTTP)))

	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}

	rid := w.Header().Get("X-Request-ID")
	if rid == "" {
		t.Error("expected X-Request-ID header on method mismatch")
	}

	opOutput := opBuf.String()
	for _, line := range strings.Split(strings.TrimSpace(opOutput), "\n") {
		if line == "" || !strings.Contains(line, "request completed") {
			continue
		}

		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("cannot parse record: %v: %s", err, line)
		}

		if m["request_id"] != rid {
			t.Errorf("expected request_id=%s, got %v", rid, m["request_id"])
		}
		status, ok := m["status"].(float64)
		if !ok || status != 405 {
			t.Errorf("expected status=405, got %v", m["status"])
		}
		return
	}

	t.Fatal("no 'request completed' record found")
}

// TestMiddlewareSingleLogForMatchedRoute verifies that a matched request
// produces exactly one request completed log entry.
func TestMiddlewareSingleLogForMatchedRoute(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelDebug, true)
	defer logging.reset()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {})
	handler := withRequestID(withLogging(http.HandlerFunc(mux.ServeHTTP)))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	opOutput := opBuf.String()
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(opOutput), "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, "request completed") {
			count++
		}
	}

	if count != 1 {
		t.Errorf("expected exactly 1 request completed log, got %d", count)
	}
}
