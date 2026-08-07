package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type stderrCapture struct {
	old *os.File
	r   *os.File
	w   *os.File
	buf *bytes.Buffer
	done chan struct{}
}

func captureStderr(t *testing.T) *stderrCapture {
	t.Helper()

	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("cannot create pipe: %v", err)
	}
	os.Stderr = w

	buf := new(bytes.Buffer)
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(buf, r)
		close(done)
	}()

	return &stderrCapture{
		old: old,
		r:   r,
		w:   w,
		buf: buf,
		done: done,
	}
}

func (c *stderrCapture) flush() {
	c.w.Close()
	<-c.done
	c.r.Close()
	os.Stderr = c.old
}

func (c *stderrCapture) buffer() *bytes.Buffer {
	return c.buf
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

func newRunRequest(body map[string]any, token string) *http.Request {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestRunStartAndFinish(t *testing.T) {
	cap := captureStderr(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
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

	cap.flush()

	records := filterBySession(parseAuditRecords(cap.buffer()), result.Session.ID)
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
	if len(startRec.Command) != 2 || startRec.Command[0] != "echo" || startRec.Command[1] != "hello" {
		t.Errorf("start command: expected [echo hello], got %v", startRec.Command)
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
	cap := captureStderr(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	const secretValue = "super-secret-token-12345"

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
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

	cap.flush()

	output := cap.buffer().String()

	// Check that raw secret is absent from everything (audit + debug)
	if strings.Contains(output, secretValue) {
		t.Fatalf("stderr contains raw env value!\n%s", output)
	}

	records := filterBySession(parseAuditRecords(cap.buffer()), result.Session.ID)
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
	cap := captureStderr(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	const secretValue = "my-password-do-not-log"

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
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

	cap.flush()

	output := cap.buffer().String()

	// The raw secret must never appear anywhere in stderr (audit + debug)
	if strings.Contains(output, secretValue) {
		t.Fatalf("stderr contains raw env value!\n%s", output)
	}

	// Verify audit records only contain env_keys, not values
	records := filterBySession(parseAuditRecords(cap.buffer()), result.Session.ID)
	for _, rec := range records {
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), secretValue) {
			t.Fatalf("audit record contains raw env value!\n%s", raw)
		}
	}
}

func TestAuditNonZeroExit(t *testing.T) {
	cap := captureStderr(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
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

	cap.flush()

	records := filterBySession(parseAuditRecords(cap.buffer()), result.Session.ID)
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
	cap := captureStderr(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
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

	cap.flush()

	records := filterBySession(parseAuditRecords(cap.buffer()), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	finishRec := records[1]
	if finishRec.Result != "docker_error" {
		t.Errorf("expected result 'docker_error', got %q", finishRec.Result)
	}
}

func TestAuditDockerExit125HasExitCode(t *testing.T) {
	cap := captureStderr(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
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

	cap.flush()

	records := filterBySession(parseAuditRecords(cap.buffer()), result.Session.ID)
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

func TestAuditDebugContainsMaskedValue(t *testing.T) {
	// Test that maskEnvValue produces the correct masked format
	const secretValue = "my-long-secret-token-value"
	masked := maskEnvValue("API_KEY", secretValue)

	// Raw secret must not appear in masked output
	if strings.Contains(masked, secretValue) {
		t.Fatalf("masked value contains raw secret: %s", masked)
	}

	// Must contain key name
	if !strings.Contains(masked, "API_KEY") {
		t.Errorf("expected API_KEY in masked value: %s", masked)
	}

	// Must contain first char + ***
	if !strings.Contains(masked, "m***") {
		t.Errorf("expected masked value m***: %s", masked)
	}

	// Must contain length
	if !strings.Contains(masked, "(length=26)") {
		t.Errorf("expected (length=26): %s", masked)
	}
}

func TestAuditMountsRelativeSource(t *testing.T) {
	cap := captureStderr(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
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

	cap.flush()

	records := filterBySession(parseAuditRecords(cap.buffer()), result.Session.ID)
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
	cap := captureStderr(t)

	const containerOutput = "this-is-container-stdout-and-stderr"

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(containerOutput), nil
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	cap.flush()

	records := filterBySession(parseAuditRecords(cap.buffer()), result.Session.ID)
	for _, rec := range records {
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), containerOutput) {
			t.Fatalf("audit record contains container output!\n%s", raw)
		}
	}
}

func TestMaskEnvNoRawValue(t *testing.T) {
	secret := "my-super-secret-value-12345"
	result := maskEnvValue("API_KEY", secret)

	if strings.Contains(result, secret) {
		t.Fatalf("masked value contains raw secret: %s", result)
	}

	if !strings.Contains(result, "API_KEY") {
		t.Errorf("masked value should contain key name: %s", result)
	}

	if !strings.Contains(result, "(length=") {
		t.Errorf("masked value should contain length: %s", result)
	}
}

func TestAuditRecordTimeIsRFC3339(t *testing.T) {
	cap := captureStderr(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	cap.flush()

	records := filterBySession(parseAuditRecords(cap.buffer()), result.Session.ID)
	if len(records) == 0 {
		t.Fatal("expected audit records")
	}

	for _, rec := range records {
		if _, err := time.Parse(time.RFC3339, rec.Time); err != nil {
			t.Errorf("time not RFC3339: %q: %v", rec.Time, err)
		}
	}
}

func TestAuditCommandPreservesBoundaries(t *testing.T) {
	cap := captureStderr(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sh", "-c", "echo hello world"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	cap.flush()

	records := filterBySession(parseAuditRecords(cap.buffer()), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	startRec := records[0]
	if len(startRec.Command) != 3 {
		t.Fatalf("expected 3 command args, got %d: %v", len(startRec.Command), startRec.Command)
	}
	if startRec.Command[0] != "sh" {
		t.Errorf("expected 'sh', got %q", startRec.Command[0])
	}
	if startRec.Command[1] != "-c" {
		t.Errorf("expected '-c', got %q", startRec.Command[1])
	}
	if startRec.Command[2] != "echo hello world" {
		t.Errorf("expected 'echo hello world', got %q", startRec.Command[2])
	}
}