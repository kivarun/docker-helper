package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPullStartContainsFields(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, puller := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

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
	select {
	case <-puller.entered:
	default:
		t.Error("expected the pull to run")
	}
}

func TestPullFinishSuccess(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, _ := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

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

// TestPullFinishError proves a failed pull finishes with result pull_error
// and no exit_code: the Engine path has no CLI process exit code to report.
func TestPullFinishError(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, puller := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	puller.err = normalizeEnginePullError(context.DeadlineExceeded)

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
	if finishRec.ExitCode != nil {
		t.Errorf("expected no exit_code on the Engine pull path, got %v", *finishRec.ExitCode)
	}
}

func TestPullAuditNoPullOutput(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	const pullOutput = "Digest: sha256:abc123\nStatus: Downloaded newer image for alpine:3.24\n"

	app, puller := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	puller.result = enginePullResult{Output: pullOutput}

	req := newPullRequest(map[string]any{
		"image": "alpine:3.24",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

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

	app, puller := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	puller.result = enginePullResult{Output: pullErrorOutput}
	puller.err = normalizeEnginePullError(context.DeadlineExceeded)

	req := newPullRequest(map[string]any{
		"image": "private:latest",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != 500 {
		t.Fatalf("expected 500, got %d", w.Code)
	}

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

func TestPullImageHyphenRejected(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, puller := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

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

	select {
	case <-puller.entered:
		t.Error("the pull must not run when image starts with '-'")
	default:
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		if rec.Event == "pull.start" || rec.Event == "pull.finish" {
			t.Errorf("pull audit event must not appear: %s", rec.Event)
		}
	}
}

func newPullRequest(body any, token string) *http.Request {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return req
}
