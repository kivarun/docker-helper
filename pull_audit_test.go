package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPullStartContainsFields(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newPullRequest(map[string]any{
		"image": "alpine:3.24",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	startRec := records[0]
	if startRec.Event != "pull.start" {
		t.Errorf("expected 'pull.start', got %q", startRec.Event)
	}
	if startRec.SessionID != result.Session.ID {
		t.Errorf("expected session_id %q, got %q", result.Session.ID, startRec.SessionID)
	}
	if startRec.Image != "alpine:3.24" {
		t.Errorf("expected image 'alpine:3.24', got %q", startRec.Image)
	}
}

func TestPullFinishSuccess(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newPullRequest(map[string]any{
		"image": "alpine:3.24",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	finishRec := records[1]
	if finishRec.Event != "pull.finish" {
		t.Errorf("expected 'pull.finish', got %q", finishRec.Event)
	}
	if finishRec.Result != "success" {
		t.Errorf("expected result 'success', got %q", finishRec.Result)
	}
	if finishRec.Duration == "" {
		t.Error("expected duration to be set")
	}
}

func TestPullFinishErrorWithExitCode(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("pull failed"), &mockExitError{code: 1, msg: "exit status 1"}
	}

	req := newPullRequest(map[string]any{
		"image": "nonexistent:latest",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != 500 {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	finishRec := records[1]
	if finishRec.Event != "pull.finish" {
		t.Errorf("expected 'pull.finish', got %q", finishRec.Event)
	}
	if finishRec.Result != "pull_error" {
		t.Errorf("expected result 'pull_error', got %q", finishRec.Result)
	}
	if finishRec.ExitCode == nil || *finishRec.ExitCode != 1 {
		t.Errorf("expected exit_code 1, got %v", finishRec.ExitCode)
	}
}

func TestPullAuditNoPullOutput(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	const pullOutput = "Digest: sha256:abc123\nStatus: Downloaded newer image for alpine:3.24\n"

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(pullOutput), nil
	}

	req := newPullRequest(map[string]any{
		"image": "alpine:3.24",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	rawLines := auditRawLinesBySession(auditBuf, result.Session.ID)
	if len(rawLines) < 2 {
		t.Fatalf("expected at least 2 audit lines, got %d", len(rawLines))
	}

	for _, line := range rawLines {
		if strings.Contains(line, pullOutput) {
			t.Fatalf("audit line contains pull output!\n%s", line)
		}

		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("cannot parse audit line: %v", err)
		}
		if _, ok := m["output"]; ok {
			t.Fatalf("audit line has output key!\n%s", line)
		}
	}
}

func TestPullAuditNoErrorOutput(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	const pullErrorOutput = "ERROR: failed to pull: access denied\n"

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(pullErrorOutput), &mockExitError{code: 1, msg: "exit status 1"}
	}

	req := newPullRequest(map[string]any{
		"image": "private:latest",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	rawLines := auditRawLinesBySession(auditBuf, result.Session.ID)
	if len(rawLines) < 2 {
		t.Fatalf("expected at least 2 audit lines, got %d", len(rawLines))
	}

	for _, line := range rawLines {
		if strings.Contains(line, pullErrorOutput) {
			t.Fatalf("audit line contains pull error output!\n%s", line)
		}

		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("cannot parse audit line: %v", err)
		}
		if _, ok := m["output"]; ok {
			t.Fatalf("audit line has output key!\n%s", line)
		}
	}
}

func TestPullDockerArgsUnchanged(t *testing.T) {
	setupTestLoggingDiscard(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		capturedArgs = args
		return []byte("ok"), nil
	}

	req := newPullRequest(map[string]any{
		"image": "alpine:3.24",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	dockerDir := sessionDockerDir(app.Config.RuntimeDir, result.Session.ID)
	expectedArgs := []string{"--config", dockerDir, "pull", "alpine:3.24"}

	if len(capturedArgs) != len(expectedArgs) {
		t.Fatalf("expected %d args, got %d: %v", len(expectedArgs), len(capturedArgs), capturedArgs)
	}

	for i, exp := range expectedArgs {
		if capturedArgs[i] != exp {
			t.Errorf("arg[%d]: expected %q, got %q", i, exp, capturedArgs[i])
		}
	}
}

func TestPullImageHyphenRejected(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	execCalled := false
	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		execCalled = true
		return []byte("ok"), nil
	}

	req := newPullRequest(map[string]any{
		"image": "-v",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if resp["code"] != "invalid_image" {
		t.Errorf("expected code 'invalid_image', got %v", resp["code"])
	}

	if execCalled {
		t.Error("ExecCommand must not be called when image starts with '-'")
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		if rec.Event == "pull.start" || rec.Event == "pull.finish" {
			t.Errorf("pull audit event must not appear: %s", rec.Event)
		}
	}
}

func newPullRequest(body map[string]any, token string) *http.Request {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return req
}
