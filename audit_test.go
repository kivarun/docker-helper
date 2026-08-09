package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newRunRequest(body map[string]any, token string) *http.Request {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func parseAuditRecords(buf *bytes.Buffer) []auditRecord {
	var records []auditRecord
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec auditRecord
		if err := json.Unmarshal([]byte(line), &rec); err == nil {
			records = append(records, rec)
		}
	}
	return records
}

func filterBySession(records []auditRecord, sessionID string) []auditRecord {
	var filtered []auditRecord
	for _, rec := range records {
		if rec.SessionID == sessionID {
			filtered = append(filtered, rec)
		}
	}
	return filtered
}

func auditRawLinesBySession(buf *bytes.Buffer, sessionID string) []string {
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if sid, ok := m["session_id"].(string); ok && sid == sessionID {
			lines = append(lines, line)
		}
	}
	return lines
}

func TestRunStartAndFinish(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"echo", "hello"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	startRec := records[0]
	if startRec.Event != "run.start" {
		t.Errorf("first record event: expected 'run.start', got %q", startRec.Event)
	}
	if startRec.Image != "alpine:latest" {
		t.Errorf("start image: expected 'alpine:latest', got %q", startRec.Image)
	}
	if startRec.CommandArgCount == nil || *startRec.CommandArgCount != 2 {
		t.Errorf("start command_arg_count: expected 2, got %v", startRec.CommandArgCount)
	}

	finishRec := records[1]
	if finishRec.Event != "run.finish" {
		t.Errorf("second record event: expected 'run.finish', got %q", finishRec.Event)
	}
	if finishRec.Result != "success" {
		t.Errorf("finish result: expected 'success', got %q", finishRec.Result)
	}
	if finishRec.Duration == "" {
		t.Error("finish duration should be set")
	}
}

func TestAuditEnvKeysNoValues(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	const secretValue = "super-secret-token-12345"

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"SECRET_KEY": secretValue,
			"APP_MODE":   "test",
		},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	output := auditBuf.String()

	// Check that raw secret is absent from everything (audit + debug)
	if strings.Contains(output, secretValue) {
		t.Fatalf("audit contains raw env value!\n%s", output)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	// Verify audit records only contain env_keys, not values
	for _, rec := range records {
		foundSecret := false
		foundApp := false
		for _, key := range rec.EnvKeys {
			if key == "SECRET_KEY" {
				foundSecret = true
			}
			if key == "APP_MODE" {
				foundApp = true
			}
		}
		if !foundSecret {
			t.Error("expected SECRET_KEY in env_keys")
		}
		if !foundApp {
			t.Error("expected APP_MODE in env_keys")
		}

		// Serialize the record and check no raw values appear
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), secretValue) {
			t.Fatalf("audit record contains raw env value!\n%s", raw)
		}
	}
}

func TestAuditDebugNoRawValue(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	const secretValue = "my-password-do-not-log"

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"DB_PASSWORD": secretValue,
		},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	output := auditBuf.String()

	// The raw secret must never appear anywhere in audit
	if strings.Contains(output, secretValue) {
		t.Fatalf("audit contains raw env value!\n%s", output)
	}

	// Verify audit records only contain env_keys, not values
	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), secretValue) {
			t.Fatalf("audit record contains raw env value!\n%s", raw)
		}
	}
}

func TestAuditNonZeroExit(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("error output"), &mockExitError{code: 7, msg: "exit status 7"}
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sh", "-c", "exit 7"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	finishRec := records[1]
	if finishRec.Event != "run.finish" {
		t.Errorf("expected 'run.finish', got %q", finishRec.Event)
	}
	if finishRec.Result != "container_exit_nonzero" {
		t.Errorf("expected result 'container_exit_nonzero', got %q", finishRec.Result)
	}
	if finishRec.ExitCode == nil || *finishRec.ExitCode != 7 {
		t.Errorf("expected exit_code 7, got %v", finishRec.ExitCode)
	}
}

func TestAuditDockerError(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("docker not found"), errors.New("exec: docker not found")
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != 500 {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	finishRec := records[1]
	if finishRec.Result != "docker_error" {
		t.Errorf("expected result 'docker_error', got %q", finishRec.Result)
	}
}

func TestAuditDockerExit125HasExitCode(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("image not found"), &mockExitError{code: 125, msg: "exit status 125"}
	}

	req := newRunRequest(map[string]any{
		"image": "nonexistent:latest",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != 500 {
		t.Fatalf("expected 500 (docker error), got %d", w.Code)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	finishRec := records[1]
	if finishRec.Result != "docker_error" {
		t.Errorf("expected result 'docker_error', got %q", finishRec.Result)
	}
	if finishRec.ExitCode == nil || *finishRec.ExitCode != 125 {
		t.Errorf("expected exit_code 125 in audit, got %v", finishRec.ExitCode)
	}
}

func TestAuditMountsRelativeSource(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/workspace", "read_only": true},
		},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	startRec := records[0]
	if len(startRec.Mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(startRec.Mounts))
	}
	if startRec.Mounts[0].Source != "." {
		t.Errorf("expected relative source '.', got %q", startRec.Mounts[0].Source)
	}
	if startRec.Mounts[0].Target != "/workspace" {
		t.Errorf("expected target '/workspace', got %q", startRec.Mounts[0].Target)
	}
	if !startRec.Mounts[0].ReadOnly {
		t.Error("expected read_only to be true")
	}
}

func TestAuditNoContainerOutput(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	const containerOutput = "this-is-container-stdout-and-stderr"

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(containerOutput), nil
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), containerOutput) {
			t.Fatalf("audit record contains container output!\n%s", raw)
		}
	}
}

func TestAuditRecordTimeIsRFC3339(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) == 0 {
		t.Fatal("expected audit records")
	}

	for _, rec := range records {
		if _, err := time.Parse(time.RFC3339, rec.Time); err != nil {
			t.Errorf("time not RFC3339: %q: %v", rec.Time, err)
		}
	}
}

func TestAuditCommandArgCount(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sh", "-c", "echo hello world"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	startRec := records[0]
	if startRec.CommandArgCount == nil || *startRec.CommandArgCount != 3 {
		t.Fatalf("expected command_arg_count 3, got %v", startRec.CommandArgCount)
	}

	// Verify that the raw command arguments do NOT appear in the audit record
	raw, _ := json.Marshal(startRec)
	if strings.Contains(string(raw), "echo hello world") {
		t.Fatalf("audit record contains raw command argument!\n%s", raw)
	}
}

func TestAuditNoCommandInRecord(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	const secretCmd = "SECRET_CMD_ARG_UNIQUE_12345"

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sh", "-c", secretCmd},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), secretCmd) {
			t.Fatalf("audit record contains secret command argument!\n%s", raw)
		}
	}
}

// setupTestLogging initializes the logging infrastructure with test buffers.
// Returns the audit buffer and operational buffer.
func setupTestLogging(t *testing.T) (*bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)
	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	t.Cleanup(func() {
		opLogger = nil
		auditWriter = nil
		auditEnabled = false
	})
	return auditBuf, opBuf
}

// setupTestLoggingDiscard initializes the logging infrastructure with
// discard writers for tests that don't need to capture logs.
func setupTestLoggingDiscard(t *testing.T) {
	t.Helper()
	initLoggers(io.Discard, io.Discard, slog.LevelError, true)
	t.Cleanup(func() {
		opLogger = nil
		auditWriter = nil
		auditEnabled = false
	})
}
