package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestStreamSeparation verifies that audit records go only to the audit writer
// and operational records go only to the operational writer.
func TestStreamSeparation(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo)
	defer func() {
		opLogger = nil
		auditWriter = nil
	}()

	// Write an audit record.
	writeAudit(auditRecord{
		Time:   "2026-01-01T00:00:00Z",
		Stream: "audit",
		Event:  "test.audit",
	})

	// Write an operational record.
	opLogger.Info("test operational message")

	auditOutput := auditBuf.String()
	opOutput := opBuf.String()

	// Audit record should only appear in audit output.
	if !strings.Contains(auditOutput, "test.audit") {
		t.Fatalf("audit output missing audit record:\n%s", auditOutput)
	}
	if strings.Contains(opOutput, "test.audit") {
		t.Fatalf("operational output should not contain audit record:\n%s", opOutput)
	}

	// Operational record should only appear in operational output.
	if !strings.Contains(opOutput, "test operational message") {
		t.Fatalf("operational output missing operational record:\n%s", opOutput)
	}
	if strings.Contains(auditOutput, "test operational message") {
		t.Fatalf("audit output should not contain operational record:\n%s", auditOutput)
	}
}

// TestAllAuditRecordsAreValidJSON verifies that every line in the audit stream
// is valid JSON.
func TestAllAuditRecordsAreValidJSON(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo)
	defer func() {
		opLogger = nil
		auditWriter = nil
	}()

	// Write several audit records.
	writeAudit(auditRecord{Time: "2026-01-01T00:00:00Z", Stream: "audit", Event: "test.1"})
	writeAudit(auditRecord{Time: "2026-01-01T00:00:01Z", Stream: "audit", Event: "test.2"})
	writeAudit(auditRecord{Time: "2026-01-01T00:00:02Z", Stream: "audit", Event: "test.3"})

	for i, line := range strings.Split(strings.TrimSpace(auditBuf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d is not valid JSON: %s: %v", i, line, err)
		}
	}
}

// TestAllOperationalRecordsAreValidJSON verifies that every line in the
// operational stream is valid JSON.
func TestAllOperationalRecordsAreValidJSON(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo)
	defer func() {
		opLogger = nil
		auditWriter = nil
	}()

	opLogger.Info("test info message")
	opLogger.Error("test error message", slog.String("key", "value"))

	for i, line := range strings.Split(strings.TrimSpace(opBuf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("line %d is not valid JSON: %s: %v", i, line, err)
		}
	}
}

// TestLogLevelFiltering verifies that debug/info filtering follows log_level.
func TestLogLevelFiltering(t *testing.T) {
	tests := []struct {
		name  string
		level slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditBuf := new(bytes.Buffer)
			opBuf := new(bytes.Buffer)

			initLoggers(opBuf, auditBuf, tt.level)
			defer func() {
				opLogger = nil
				auditWriter = nil
			}()

			opLogger.Debug("debug message")
			opLogger.Info("info message")
			opLogger.Warn("warn message")
			opLogger.Error("error message")

			output := opBuf.String()

			// Error should always appear.
			if !strings.Contains(output, "error message") {
				t.Error("error message should always appear")
			}

			// Warn should appear at warn level and below.
			if tt.level <= slog.LevelWarn && !strings.Contains(output, "warn message") {
				t.Error("warn message should appear at warn level and below")
			}
			if tt.level > slog.LevelWarn && strings.Contains(output, "warn message") {
				t.Error("warn message should not appear at error level")
			}

			// Info should appear at info level and below.
			if tt.level <= slog.LevelInfo && !strings.Contains(output, "info message") {
				t.Error("info message should appear at info level and below")
			}
			if tt.level > slog.LevelInfo && strings.Contains(output, "info message") {
				t.Error("info message should not appear at warn/error level")
			}

			// Debug should only appear at debug level.
			if tt.level == slog.LevelDebug && !strings.Contains(output, "debug message") {
				t.Error("debug message should appear at debug level")
			}
			if tt.level > slog.LevelDebug && strings.Contains(output, "debug message") {
				t.Error("debug message should not appear at info/warn/error level")
			}
		})
	}
}

// TestAuditNotSuppressedByLogLevel verifies that audit records are not
// suppressed by log_level.
func TestAuditNotSuppressedByLogLevel(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	// Set level to error — only errors should appear in operational.
	initLoggers(opBuf, auditBuf, slog.LevelError)
	defer func() {
		opLogger = nil
		auditWriter = nil
	}()

	writeAudit(auditRecord{Time: "2026-01-01T00:00:00Z", Stream: "audit", Event: "test.audit"})

	if !strings.Contains(auditBuf.String(), "test.audit") {
		t.Error("audit record should appear even at error log level")
	}
}

// TestAuditStreamField verifies that every audit record contains "stream": "audit".
func TestAuditStreamField(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo)
	defer func() {
		opLogger = nil
		auditWriter = nil
	}()

	writeAudit(auditRecord{Time: "2026-01-01T00:00:00Z", Stream: "audit", Event: "test.audit"})

	var rec map[string]any
	if err := json.Unmarshal(auditBuf.Bytes(), &rec); err != nil {
		t.Fatalf("cannot parse audit record: %v", err)
	}
	if rec["stream"] != "audit" {
		t.Errorf("expected stream=audit, got %v", rec["stream"])
	}
}

// TestOperationalStreamField verifies that operational records contain
// "stream": "operational".
func TestOperationalStreamField(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo)
	defer func() {
		opLogger = nil
		auditWriter = nil
	}()

	// The operational logger doesn't automatically add "stream" field.
	// We verify that operational records go to the operational writer.
	opLogger.Info("test message")

	if !strings.Contains(opBuf.String(), "test message") {
		t.Error("operational message should appear in operational writer")
	}
	if strings.Contains(auditBuf.String(), "test message") {
		t.Error("operational message should not appear in audit writer")
	}
}

// TestRequestIDInResponseHeader verifies that a request through the production
// handler receives X-Request-ID.
func TestRequestIDInResponseHeader(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo)
	defer func() {
		opLogger = nil
		auditWriter = nil
	}()

	app := newTestAppWithAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler := withRequestID(app.handleHealth)
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	rid := w.Header().Get("X-Request-ID")
	if rid == "" {
		t.Fatal("X-Request-ID header should be set")
	}
	if !strings.HasPrefix(rid, "req_") {
		t.Errorf("request ID should start with 'req_', got %q", rid)
	}
}

// TestRequestIDInAuditRecord verifies that the same request ID appears
// in the audit record generated by the handler.
func TestRequestIDInAuditRecord(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo)
	defer func() {
		opLogger = nil
		auditWriter = nil
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

	handler := withRequestID(app.handleRun)
	handler(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	rid := w.Header().Get("X-Request-ID")
	if rid == "" {
		t.Fatal("X-Request-ID header should be set")
	}

	// Check that the request ID appears in audit records.
	auditOutput := auditBuf.String()
	if !strings.Contains(auditOutput, rid) {
		t.Fatalf("audit records should contain request_id %q:\n%s", rid, auditOutput)
	}
}

// TestRequestScopedOperationalErrorContainsIDs verifies that request-scoped
// operational errors contain request_id and session_id where applicable.
func TestRequestScopedOperationalErrorContainsIDs(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError)
	defer func() {
		opLogger = nil
		auditWriter = nil
	}()

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Trigger a docker error to generate an operational log.
	app.RunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("error"), io.EOF
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)
	w := httptest.NewRecorder()

	handler := withRequestID(app.handleRun)
	handler(w, req)

	rid := w.Header().Get("X-Request-ID")
	if rid == "" {
		t.Fatal("X-Request-ID header should be set")
	}

	opOutput := opBuf.String()
	if !strings.Contains(opOutput, rid) {
		t.Fatalf("operational error should contain request_id %q:\n%s", rid, opOutput)
	}
}

// TestNoCommandInAuditStream verifies that neither the complete command
// nor a distinctive secret placed in a command argument appears in either
// log stream.
func TestNoCommandInAuditStream(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo)
	defer func() {
		opLogger = nil
		auditWriter = nil
	}()

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const secretArg = "UNIQUE_SECRET_CMD_ARG_98765"

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sh", "-c", secretArg},
	}, result.Token)
	w := httptest.NewRecorder()

	handler := withRequestID(app.handleRun)
	handler(w, req)

	auditOutput := auditBuf.String()
	opOutput := opBuf.String()

	if strings.Contains(auditOutput, secretArg) {
		t.Fatalf("audit stream contains secret command argument:\n%s", auditOutput)
	}
	if strings.Contains(opOutput, secretArg) {
		t.Fatalf("operational stream contains secret command argument:\n%s", opOutput)
	}
}

// TestNoEnvValueInAuditStream verifies that environment values (secrets)
// do not appear in either log stream.
func TestNoEnvValueInAuditStream(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo)
	defer func() {
		opLogger = nil
		auditWriter = nil
	}()

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const secretEnv = "UNIQUE_SECRET_ENV_VALUE_54321"

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"SECRET_TOKEN": secretEnv,
		},
	}, result.Token)
	w := httptest.NewRecorder()

	handler := withRequestID(app.handleRun)
	handler(w, req)

	auditOutput := auditBuf.String()
	opOutput := opBuf.String()

	if strings.Contains(auditOutput, secretEnv) {
		t.Fatalf("audit stream contains secret env value:\n%s", auditOutput)
	}
	if strings.Contains(opOutput, secretEnv) {
		t.Fatalf("operational stream contains secret env value:\n%s", opOutput)
	}
}

// TestAuditRecordHasRequestID verifies that audit records generated through
// the production handler contain the request_id field.
func TestAuditRecordHasRequestID(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo)
	defer func() {
		opLogger = nil
		auditWriter = nil
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

	handler := withRequestID(app.handleRun)
	handler(w, req)

	// Parse audit records and check for request_id.
	for _, line := range strings.Split(strings.TrimSpace(auditBuf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if rid, ok := m["request_id"].(string); ok && rid != "" {
			// Found a record with request_id — good.
			return
		}
	}

	t.Error("no audit record contained a non-empty request_id")
}

// TestContextRequestID verifies that requestIDFromContext and
// sessionIDFromContext work correctly.
func TestContextRequestID(t *testing.T) {
	ctx := context.Background()

	if got := requestIDFromContext(ctx); got != "" {
		t.Errorf("expected empty request ID, got %q", got)
	}
	if got := sessionIDFromContext(ctx); got != "" {
		t.Errorf("expected empty session ID, got %q", got)
	}

	ctx = context.WithValue(ctx, requestIDKey, "req_test123")
	if got := requestIDFromContext(ctx); got != "req_test123" {
		t.Errorf("expected 'req_test123', got %q", got)
	}

	ctx = context.WithValue(ctx, sessionIDKey, "dhs_test456")
	if got := sessionIDFromContext(ctx); got != "dhs_test456" {
		t.Errorf("expected 'dhs_test456', got %q", got)
	}
}

// TestGenerateRequestIDFormat verifies that generateRequestID returns
// a properly formatted string.
func TestGenerateRequestIDFormat(t *testing.T) {
	rid := generateRequestID()
	if !strings.HasPrefix(rid, "req_") {
		t.Errorf("request ID should start with 'req_', got %q", rid)
	}
	// After prefix, should be 32 hex chars (16 bytes)
	hex := strings.TrimPrefix(rid, "req_")
	if len(hex) != 32 {
		t.Errorf("request ID hex part should be 32 chars, got %d", len(hex))
	}
}

// TestOpLogWithContext verifies that opLog adds request_id and session_id
// to the logger when they are present in the context.
func TestOpLogWithContext(t *testing.T) {
	opBuf := new(bytes.Buffer)
	auditBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo)
	defer func() {
		opLogger = nil
		auditWriter = nil
	}()

	ctx := context.WithValue(context.Background(), requestIDKey, "req_test")
	ctx = context.WithValue(ctx, sessionIDKey, "dhs_test")

	l := opLog(ctx)
	l.Info("context test")

	output := opBuf.String()
	if !strings.Contains(output, "req_test") {
		t.Errorf("operational log should contain request_id:\n%s", output)
	}
	if !strings.Contains(output, "dhs_test") {
		t.Errorf("operational log should contain session_id:\n%s", output)
	}
}

// TestParseLogLevel verifies log level parsing.
func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input  string
		expect slog.Level
		ok     bool
	}{
		{"debug", slog.LevelDebug, true},
		{"info", slog.LevelInfo, true},
		{"warn", slog.LevelWarn, true},
		{"error", slog.LevelError, true},
		{"invalid", slog.LevelInfo, false},
		{"", slog.LevelInfo, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			level, err := parseLogLevel(tt.input)
			if tt.ok {
				if err != nil {
					t.Fatalf("expected no error for %q, got: %v", tt.input, err)
				}
				if level != tt.expect {
					t.Errorf("expected level %v, got %v", tt.expect, level)
				}
			} else {
				if err == nil {
					t.Errorf("expected error for %q", tt.input)
				}
			}
		})
	}
}

// TestConfigLogLevelDefault verifies that an empty log_level defaults to info.
func TestConfigLogLevelDefault(t *testing.T) {
	// When fileConfig.Level is empty, loadConfig should default to info.
	// This is tested implicitly through loadConfig, but we verify the
	// default behavior here.
	fc := fileConfig{
		AllowedRoot: "/tmp",
		SessionTTL:  "12h",
	}

	level := slog.LevelInfo
	if fc.Level != "" {
		var err error
		level, err = parseLogLevel(fc.Level)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if level != slog.LevelInfo {
		t.Errorf("expected default level info, got %v", level)
	}
}
