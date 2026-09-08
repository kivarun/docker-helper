package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decodeBuildResponse decodes the synchronous build response.
func decodeBuildResponse(t *testing.T, w *httptest.ResponseRecorder) buildResponse {
	t.Helper()
	var resp buildResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode build response: %v", err)
	}
	return resp
}

func TestBuildStartContainsFields(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminTokenAndStaging(t)
	setupBuildSeam(t, app, buildSeamOptions{Output: "ok\n"})
	setupBuildSeam(t, app, buildSeamOptions{Output: "ok\n"})

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	startRec := records[0]
	if startRec.Event != "build.start" {
		t.Errorf("expected 'build.start', got %q", startRec.Event)
	}
	if startRec.SessionID != result.Session.ID {
		t.Errorf("expected session_id %q, got %q", result.Session.ID, startRec.SessionID)
	}
	if startRec.Image != "example:test" {
		t.Errorf("expected image 'example:test', got %q", startRec.Image)
	}
	if startRec.Context != "." {
		t.Errorf("expected context '.', got %q", startRec.Context)
	}
	if startRec.Dockerfile != "Dockerfile" {
		t.Errorf("expected dockerfile 'Dockerfile', got %q", startRec.Dockerfile)
	}
}

func TestBuildFinishSuccess(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminTokenAndStaging(t)
	setupBuildSeam(t, app, buildSeamOptions{Output: "ok\n"})

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	finishRec := records[len(records)-1]
	if finishRec.Event != "build.finish" {
		t.Errorf("expected 'build.finish', got %q", finishRec.Event)
	}
	if finishRec.Result != "succeeded" {
		t.Errorf("expected result 'succeeded', got %q", finishRec.Result)
	}
	if finishRec.Duration == "" {
		t.Error("expected duration to be set")
	}
}

func TestBuildFinishError(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminTokenAndStaging(t)
	setupBuildSeam(t, app, buildSeamOptions{
		Err: &engineError{kind: engineErrBuildFailed, cause: errors.New("build failed")},
	})

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected %d, got %d", http.StatusUnprocessableEntity, w.Code)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	finishRec := records[len(records)-1]
	if finishRec.Event != "build.finish" {
		t.Errorf("expected 'build.finish', got %q", finishRec.Event)
	}
	if finishRec.Result != "docker_build_failed" {
		t.Errorf("expected result 'docker_build_failed', got %q", finishRec.Result)
	}
	if finishRec.ExitCode != nil {
		t.Errorf("a synchronous build finish must not carry exit_code, got %v", *finishRec.ExitCode)
	}
	if finishRec.OperationID != "" {
		t.Errorf("a synchronous build finish must not carry operation_id, got %q", finishRec.OperationID)
	}
}

func TestBuildAuditNoSuccessOutput(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	const buildOutput = "Step 1/1 : FROM alpine\n ---> somehash\nSuccessfully built abc123\n"

	app := newTestAppWithAdminTokenAndStaging(t)
	setupBuildSeam(t, app, buildSeamOptions{Output: "ok\n"})

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	rawLines := auditRawLinesBySession(auditBuf, result.Session.ID)
	if len(rawLines) < 2 {
		t.Fatalf("expected at least 2 audit lines, got %d", len(rawLines))
	}

	for _, line := range rawLines {
		if strings.Contains(line, buildOutput) {
			t.Fatalf("audit line contains build output!\n%s", line)
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

func TestBuildAuditNoErrorOutput(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	const buildOutput = "ERROR: failed to solve: something went wrong\n"

	app := newTestAppWithAdminTokenAndStaging(t)
	setupBuildSeam(t, app, buildSeamOptions{Output: "ok\n"})

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	rawLines := auditRawLinesBySession(auditBuf, result.Session.ID)
	if len(rawLines) < 2 {
		t.Fatalf("expected at least 2 audit lines, got %d", len(rawLines))
	}

	for _, line := range rawLines {
		if strings.Contains(line, buildOutput) {
			t.Fatalf("audit line contains build error output!\n%s", line)
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

func newBuildRequest(body map[string]any, token string) *http.Request {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return req
}
