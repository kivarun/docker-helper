package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildStartContainsFields(t *testing.T) {
	cap := captureStderr(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.BuildCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	cap.flush()

	records := filterBySession(parseAuditRecords(cap.buffer()), result.Session.ID)
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
	cap := captureStderr(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.BuildCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	cap.flush()

	records := filterBySession(parseAuditRecords(cap.buffer()), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	finishRec := records[1]
	if finishRec.Event != "build.finish" {
		t.Errorf("expected 'build.finish', got %q", finishRec.Event)
	}
	if finishRec.Result != "success" {
		t.Errorf("expected result 'success', got %q", finishRec.Result)
	}
	if finishRec.Duration == "" {
		t.Error("expected duration to be set")
	}
}

func TestBuildFinishErrorWithExitCode(t *testing.T) {
	cap := captureStderr(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.BuildCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("build failed"), &mockExitError{code: 1, msg: "exit status 1"}
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != 500 {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	cap.flush()

	records := filterBySession(parseAuditRecords(cap.buffer()), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	finishRec := records[1]
	if finishRec.Event != "build.finish" {
		t.Errorf("expected 'build.finish', got %q", finishRec.Event)
	}
	if finishRec.Result != "build_error" {
		t.Errorf("expected result 'build_error', got %q", finishRec.Result)
	}
	if finishRec.ExitCode == nil || *finishRec.ExitCode != 1 {
		t.Errorf("expected exit_code 1, got %v", finishRec.ExitCode)
	}
}

func TestBuildAuditNoSuccessOutput(t *testing.T) {
	cap := captureStderr(t)

	const buildOutput = "Step 1/1 : FROM alpine\n ---> somehash\nSuccessfully built abc123\n"

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.BuildCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(buildOutput), nil
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	cap.flush()

	rawLines := auditRawLinesBySession(cap.buffer(), result.Session.ID)
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
	cap := captureStderr(t)

	const buildOutput = "ERROR: failed to solve: something went wrong\n"

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.BuildCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(buildOutput), &mockExitError{code: 1, msg: "exit status 1"}
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	cap.flush()

	rawLines := auditRawLinesBySession(cap.buffer(), result.Session.ID)
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

func TestBuildDockerArgsUnchanged(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	var capturedArgs []string
	app.BuildCommand = func(name string, args ...string) ([]byte, error) {
		capturedArgs = args
		return []byte("ok"), nil
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	expectedArgs := []string{
		"build",
		"--pull",
		"--provenance=false",
		"--sbom=false",
		"--file", dockerfilePath,
		"--tag", "example:test",
		app.Config.AllowedRoot,
	}

	if len(capturedArgs) != len(expectedArgs) {
		t.Fatalf("expected %d args, got %d: %v", len(expectedArgs), len(capturedArgs), capturedArgs)
	}

	for i, exp := range expectedArgs {
		if capturedArgs[i] != exp {
			t.Errorf("arg[%d]: expected %q, got %q", i, exp, capturedArgs[i])
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