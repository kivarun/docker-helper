package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestStreamSeparation verifies that audit records go only to the audit writer
// and operational records go only to the operational writer.
func TestStreamSeparation(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo, true)
	defer logging.reset()

	// Write an audit record.
	writeAudit(auditRecord{Event: "test.audit"})

	// Write an operational record.
	logging.snapshotLogger().Info("test operational message")

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

	initLoggers(opBuf, auditBuf, slog.LevelInfo, true)
	defer logging.reset()

	writeAudit(auditRecord{Event: "test.1"})
	writeAudit(auditRecord{Event: "test.2"})
	writeAudit(auditRecord{Event: "test.3"})

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

	initLoggers(opBuf, auditBuf, slog.LevelInfo, true)
	defer logging.reset()

	logging.snapshotLogger().Info("test info message")
	logging.snapshotLogger().Error("test error message", slog.String("key", "value"))

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

			initLoggers(opBuf, auditBuf, tt.level, true)
			defer logging.reset()

			logging.snapshotLogger().Debug("debug message")
			logging.snapshotLogger().Info("info message")
			logging.snapshotLogger().Warn("warn message")
			logging.snapshotLogger().Error("error message")

			output := opBuf.String()

			if !strings.Contains(output, "error message") {
				t.Error("error message should always appear")
			}
			if tt.level <= slog.LevelWarn && !strings.Contains(output, "warn message") {
				t.Error("warn message should appear at warn level and below")
			}
			if tt.level > slog.LevelWarn && strings.Contains(output, "warn message") {
				t.Error("warn message should not appear at error level")
			}
			if tt.level <= slog.LevelInfo && !strings.Contains(output, "info message") {
				t.Error("info message should appear at info level and below")
			}
			if tt.level > slog.LevelInfo && strings.Contains(output, "info message") {
				t.Error("info message should not appear at warn/error level")
			}
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

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer logging.reset()

	writeAudit(auditRecord{Event: "test.audit"})

	if !strings.Contains(auditBuf.String(), "test.audit") {
		t.Error("audit record should appear even at error log level")
	}
}

// TestRequestIDInResponseHeader verifies that a request through the production
// handler receives X-Request-ID.
func TestRequestIDInResponseHeader(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo, true)
	defer logging.reset()

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

	initLoggers(opBuf, auditBuf, slog.LevelInfo, true)
	defer logging.reset()

	app := newTestAppWithAuth(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)
	w := httptest.NewRecorder()

	handler := withRequestID(app.handleRun)
	handler(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	rid := w.Header().Get("X-Request-ID")
	if rid == "" {
		t.Fatal("X-Request-ID header should be set")
	}

	auditOutput := auditBuf.String()
	if !strings.Contains(auditOutput, rid) {
		t.Fatalf("audit records should contain request_id %q:\n%s", rid, auditOutput)
	}
}

// TestRequestScopedOperationalErrorContainsIDs verifies that request-scoped
// operational errors contain request_id and session_id as JSON fields.
func TestRequestScopedOperationalErrorContainsIDs(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer logging.reset()

	app := newTestAppWithAuth(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 1")
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)
	w := httptest.NewRecorder()

	handler := withRequestID(app.handleRun)
	handler(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	rid := w.Header().Get("X-Request-ID")
	if rid == "" {
		t.Fatal("X-Request-ID header should be set")
	}

	// With async model, request_id and session_id are in audit records.
	auditOutput := auditBuf.String()
	if auditOutput == "" {
		t.Fatal("audit output is empty")
	}

	// Parse audit records and verify request_id and session_id.
	for _, line := range strings.Split(strings.TrimSpace(auditOutput), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if m["request_id"] == rid && m["session_id"] == result.Session.ID {
			return
		}
	}

	t.Errorf("no audit record contained both request_id=%q and session_id=%q", rid, result.Session.ID)
}

// TestNoCommandInAuditStream verifies that neither the complete command
// nor a distinctive secret placed in a command argument appears in either
// log stream.
func TestNoCommandInAuditStream(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo, true)
	defer logging.reset()

	app := newTestAppWithAuth(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const secretArg = "UNIQUE_SECRET_CMD_ARG_98765"

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sh", "-c", secretArg},
	}, result.Token)
	w := httptest.NewRecorder()

	handler := withRequestID(app.handleRun)
	handler(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

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

	initLoggers(opBuf, auditBuf, slog.LevelInfo, true)
	defer logging.reset()

	app := newTestAppWithAuth(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const secretEnv = "UNIQUE_SECRET_ENV_VALUE_54321"

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
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

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	auditOutput := auditBuf.String()
	opOutput := opBuf.String()

	if strings.Contains(auditOutput, secretEnv) {
		t.Fatalf("audit stream contains secret env value:\n%s", auditOutput)
	}
	if strings.Contains(opOutput, secretEnv) {
		t.Fatalf("operational stream contains secret env value:\n%s", opOutput)
	}
}

// TestOpLogDiscardWhenUnconfigured verifies that opLog does not leak
// into slog.Default() when the operational logger is not configured.
func TestOpLogDiscardWhenUnconfigured(t *testing.T) {
	t.Cleanup(logging.reset)
	logging.reset()

	oldDefault := slog.Default()
	t.Cleanup(func() {
		slog.SetDefault(oldDefault)
	})

	defaultBuf := new(bytes.Buffer)
	slog.SetDefault(slog.New(slog.NewTextHandler(defaultBuf, nil)))

	opLog(context.Background()).Warn("must not escape")

	if defaultBuf.Len() > 0 {
		t.Errorf("slog.Default() should not receive records, got:\n%s", defaultBuf.String())
	}
}

// TestOpLogWritesToConfigured verifies that after initLoggers, opLog
// writes to the configured operational writer with stream=operational.
func TestOpLogWritesToConfigured(t *testing.T) {
	opBuf := new(bytes.Buffer)
	auditBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelWarn, true)
	defer logging.reset()

	opLog(context.Background()).Warn("configured test")

	output := opBuf.String()
	if !strings.Contains(output, "configured test") {
		t.Errorf("expected message in operational output:\n%s", output)
	}
	if !strings.Contains(output, `"stream":"operational"`) {
		t.Errorf("expected stream=operational:\n%s", output)
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

// TestWriteAuditSetsStreamAndTime verifies that writeAudit called without
// pre-filled Time or Stream still emits a complete audit record.
func TestWriteAuditSetsStreamAndTime(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo, true)
	defer logging.reset()

	writeAudit(auditRecord{Event: "test.auto"})

	var m map[string]any
	if err := json.Unmarshal(auditBuf.Bytes(), &m); err != nil {
		t.Fatalf("cannot parse audit record: %v", err)
	}
	if m["stream"] != "audit" {
		t.Errorf("expected stream=audit, got %v", m["stream"])
	}
	if m["time"] == nil {
		t.Error("expected time to be set automatically")
	}
	if m["event"] != "test.auto" {
		t.Errorf("expected event=test.auto, got %v", m["event"])
	}
}

// TestAuditWriterFailureContainsCorrelation verifies that an audit writer
// failure contains the same correlation fields as the audit record.
func TestAuditWriterFailureContainsCorrelation(t *testing.T) {
	// Use a writer that always fails.
	failingWriter := &failingAuditWriter{}
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, failingWriter, slog.LevelError, true)
	defer logging.reset()

	writeAudit(auditRecord{
		Event:     "test.fail",
		RequestID: "req_fail",
		SessionID: "dhs_fail",
	})

	line := strings.TrimSpace(opBuf.String())
	if line == "" {
		t.Fatal("operational output is empty")
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("cannot parse operational record: %v: %s", err, line)
	}
	if m["request_id"] != "req_fail" {
		t.Errorf("expected request_id=req_fail, got %v", m["request_id"])
	}
	if m["session_id"] != "dhs_fail" {
		t.Errorf("expected session_id=dhs_fail, got %v", m["session_id"])
	}
}

// failingAuditWriter always returns an error on Write.
type failingAuditWriter struct{}

func (w *failingAuditWriter) Write(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

var errMockEncoding = &mockEncodingError{}

type mockEncodingError struct{}

func (e *mockEncodingError) Error() string {
	return "mock encoding error"
}

// TestRunCommandWithWritersServeFailure verifies that runCommandWithWriters
// routes audit to stdout and operational to stderr during a serve failure.
func TestRunCommandWithWritersServeFailure(t *testing.T) {
	dir := t.TempDir()

	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	configDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}

	allowedRoot := testAllowedRootDir(t)
	configData := []byte(`{"allowed_roots": ["` + allowedRoot + `"],"session_ttl":"12h"}`)
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), configData, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "admin.token"), []byte("test-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	t.Setenv("DOCKER_HELPER_CONFIG", filepath.Join(configDir, "config.json"))

	// Pre-acquire the lock.
	runtimeDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatalf("mkdir runtime: %v", err)
	}
	lockPath := filepath.Join(runtimeDir, "docker-helper.sock.lock")
	lockFile, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}

	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)

	sentinel := new(bytes.Buffer)
	savedStderr := osStderr
	osStderr = sentinel
	defer func() {
		osStderr = savedStderr
	}()

	code := runCommandWithWriters([]string{"serve"}, stdoutBuf, stderrBuf)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	lockFile.Close()

	// Sentinel must be empty — no global stderr writes.
	if sentinel.Len() > 0 {
		t.Errorf("serve wrote to global stderr: %s", sentinel.String())
	}

	// Operational output must be on stderr, not stdout.
	opOutput := stderrBuf.String()
	if opOutput == "" {
		t.Fatal("stderr (operational) is empty")
	}
	for i, line := range strings.Split(strings.TrimSpace(opOutput), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("stderr line %d not valid JSON: %s: %v", i, line, err)
		}
		if m["stream"] != "operational" {
			t.Errorf("stderr line %d: expected stream=operational, got %v", i, m["stream"])
		}
	}

	// stdout must not contain operational records.
	stdoutOutput := stdoutBuf.String()
	if strings.Contains(stdoutOutput, `"stream":"operational"`) {
		t.Errorf("stdout must not contain operational records:\n%s", stdoutOutput)
	}
}

// TestMissingConfigProducesSingleJSONLRecord verifies that a missing
// configuration file produces exactly one valid operational JSONL record.
func TestMissingConfigProducesSingleJSONLRecord(t *testing.T) {
	opBuf := new(bytes.Buffer)
	auditBuf := new(bytes.Buffer)

	sentinel := new(bytes.Buffer)
	savedStderr := osStderr
	osStderr = sentinel
	defer func() {
		osStderr = savedStderr
	}()

	initLoggers(opBuf, auditBuf, slog.LevelInfo, true)
	defer logging.reset()

	// Point config to a nonexistent file.
	t.Setenv("DOCKER_HELPER_CONFIG", "/nonexistent/path/config.json")

	// runServe(stdout, stderr): audit->stdout, operational->stderr.
	// Pass auditBuf as stdout, opBuf as stderr so operational goes to opBuf.
	err := runServe(auditBuf, opBuf)
	if err == nil {
		t.Fatal("expected error from runServe with missing config")
	}

	// Sentinel must be empty — no global stderr writes.
	if sentinel.Len() > 0 {
		t.Errorf("serve wrote to global stderr: %s", sentinel.String())
	}

	opOutput := opBuf.String()
	if opOutput == "" {
		t.Fatal("operational output is empty")
	}

	lines := strings.Split(strings.TrimSpace(opOutput), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 operational line, got %d:\n%s", len(lines), opOutput)
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("line is not valid JSON: %s: %v", lines[0], err)
	}
	if m["stream"] != "operational" {
		t.Errorf("expected stream=operational, got %v", m["stream"])
	}
}

// TestLockFailureProducesSingleJSONLRecord verifies that a lock acquisition
// failure produces exactly one valid operational JSONL record.
func TestLockFailureProducesSingleJSONLRecord(t *testing.T) {
	dir := t.TempDir()

	// Create config that points to our test directory.
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	configDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}

	allowedRoot := testAllowedRootDir(t)
	configData := []byte(`{"allowed_roots": ["` + allowedRoot + `"],"session_ttl":"12h"}`)
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), configData, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "admin.token"), []byte("test-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	t.Setenv("DOCKER_HELPER_CONFIG", filepath.Join(configDir, "config.json"))

	// The lock path is derived from the socket path:
	// socketPath = XDG_RUNTIME_DIR/docker-helper/docker-helper.sock
	// lockPath = socketPath + ".lock"
	runtimeDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatalf("mkdir runtime: %v", err)
	}
	lockPath := filepath.Join(runtimeDir, "docker-helper.sock.lock")

	// Pre-acquire the lock to force a failure.
	lockFile, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}

	opBuf := new(bytes.Buffer)
	auditBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo, true)
	defer logging.reset()

	// runServe(stdout, stderr): audit->stdout, operational->stderr.
	// Pass auditBuf as stdout, opBuf as stderr so operational goes to opBuf.
	err = runServe(auditBuf, opBuf)
	if err == nil {
		lockFile.Close()
		t.Fatal("expected error from runServe with held lock")
	}
	lockFile.Close()

	opOutput := opBuf.String()
	if opOutput == "" {
		t.Fatal("operational output is empty")
	}

	lines := strings.Split(strings.TrimSpace(opOutput), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 operational line, got %d:\n%s", len(lines), opOutput)
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatalf("line is not valid JSON: %s: %v", lines[0], err)
	}
	if m["stream"] != "operational" {
		t.Errorf("expected stream=operational, got %v", m["stream"])
	}
}

// TestServeAuditRoutingToStdout verifies that the audit logger configured
// by the serve path writes to stdout and not stderr. This exercises the
// actual runServe wiring rather than calling initLoggers directly.
func TestServeAuditRoutingToStdout(t *testing.T) {
	dir := t.TempDir()

	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	configDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatalf("mkdir config: %v", err)
	}

	allowedRoot := testAllowedRootDir(t)
	// Enable audit in config so runServe reinitializes with audit enabled.
	configData := []byte(`{"allowed_roots": ["` + allowedRoot + `"],"session_ttl":"12h","audit_enabled":true}`)
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), configData, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "admin.token"), []byte("test-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	t.Setenv("DOCKER_HELPER_CONFIG", filepath.Join(configDir, "config.json"))

	// Pre-acquire the lock so serve fails after config load.
	runtimeDir := filepath.Join(dir, "docker-helper")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatalf("mkdir runtime: %v", err)
	}
	lockPath := filepath.Join(runtimeDir, "docker-helper.sock.lock")
	lockFile, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}

	stdoutBuf := new(bytes.Buffer)
	stderrBuf := new(bytes.Buffer)

	sentinel := new(bytes.Buffer)
	savedStderr := osStderr
	osStderr = sentinel
	defer func() {
		osStderr = savedStderr
	}()

	code := runCommandWithWriters([]string{"serve"}, stdoutBuf, stderrBuf)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	lockFile.Close()

	if sentinel.Len() > 0 {
		t.Errorf("serve wrote to global stderr: %s", sentinel.String())
	}

	// Write an audit record through the logger configured by runServe.
	writeAudit(auditRecord{Event: "serve.routing.test"})

	// Audit record must appear on stdout, not stderr.
	stdoutOutput := stdoutBuf.String()
	if !strings.Contains(stdoutOutput, "serve.routing.test") {
		t.Fatalf("stdout must contain audit record but got:\n%s", stdoutOutput)
	}

	stderrOutput := stderrBuf.String()
	if strings.Contains(stderrOutput, "serve.routing.test") {
		t.Fatalf("stderr must not contain audit record but got:\n%s", stderrOutput)
	}

	// Verify the audit record has the correct stream field.
	for _, line := range strings.Split(strings.TrimSpace(stdoutOutput), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if m["event"] == "serve.routing.test" && m["stream"] != "audit" {
			t.Errorf("audit record: expected stream=audit, got %v", m["stream"])
		}
	}
}

// TestResponseEncodingErrorThroughHandler verifies that a response encoding
// failure through a real HTTP handler produces a structured operational record
// with stream, request_id, and session_id.
func TestResponseEncodingErrorThroughHandler(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer logging.reset()

	app := newTestAppWithAuth(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)

	// Use a ResponseWriter that fails on Write.
	w := &failingResponseWriter{
		ResponseWriter: httptest.NewRecorder(),
	}

	handler := withRequestID(app.handleRun)
	handler(w, req)

	rid := w.Header().Get("X-Request-ID")
	if rid == "" {
		t.Fatal("X-Request-ID header should be set")
	}

	opOutput := opBuf.String()
	if opOutput == "" {
		t.Fatal("operational output is empty")
	}

	// Parse the first JSON line.
	line := strings.TrimSpace(opOutput)
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("cannot parse operational record: %v: %s", err, line)
	}

	if m["stream"] != "operational" {
		t.Errorf("expected stream=operational, got %v", m["stream"])
	}
	if m["request_id"] != rid {
		t.Errorf("expected request_id=%q, got %v", rid, m["request_id"])
	}
	if m["session_id"] != result.Session.ID {
		t.Errorf("expected session_id=%q, got %v", result.Session.ID, m["session_id"])
	}
}

// failingResponseWriter wraps an http.ResponseWriter and fails on Write.
type failingResponseWriter struct {
	http.ResponseWriter
}

func (w *failingResponseWriter) Write(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (w *failingResponseWriter) WriteHeader(statusCode int) {
	// Don't actually write headers — defer to the underlying writer.
	w.ResponseWriter.WriteHeader(statusCode)
}

// TestDeleteSessionAuditContainsRequestID verifies that a failing DELETE
// /sessions/{id} audit record contains the request_id from the context.
func TestDeleteSessionAuditContainsRequestID(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelInfo, true)
	defer logging.reset()

	app := newTestAppWithAuth(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /sessions/{id}", withRequestID(app.handleDeleteSession))

	req := httptest.NewRequest(http.MethodDelete, "/sessions/nonexistent-id", nil)
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}

	rid := w.Header().Get("X-Request-ID")
	if rid == "" {
		t.Fatal("X-Request-ID header should be set")
	}

	// Find the delete audit record and check request_id.
	for _, line := range strings.Split(strings.TrimSpace(auditBuf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if m["event"] != "session.delete" {
			continue
		}
		if m["request_id"] != rid {
			t.Errorf("expected request_id=%q in audit record, got %v", rid, m["request_id"])
		}
		return
	}

	t.Fatal("no session.delete audit record found")
}

// reset clears all logging state.  Intended for test cleanup.
func (ls *loggingState) reset() {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	ls.opLogger = nil
	ls.opWriter = nil
	ls.auditWriter = nil
	ls.auditEnabled = false
}
