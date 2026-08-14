package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// waitBuild waits for a build operation to complete.
func waitBuild(t *testing.T, app *App, w *httptest.ResponseRecorder) {
	t.Helper()
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode build response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatalf("operation %s not found in registry", opID)
	}
	op.Wait()
}

func TestBuildStartContainsFields(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

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

	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

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

func TestBuildFinishErrorWithExitCode(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 1")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

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
	if finishRec.ExitCode == nil || *finishRec.ExitCode != 1 {
		t.Errorf("expected exit_code 1, got %v", finishRec.ExitCode)
	}
}

func TestBuildAuditNoSuccessOutput(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	const buildOutput = "Step 1/1 : FROM alpine\n ---> somehash\nSuccessfully built abc123\n"

	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%s' '"+buildOutput+"'")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	waitBuild(t, app, w)

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

	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%s' '"+buildOutput+"' >&2; exit 1")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	waitBuild(t, app, w)

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

func TestBuildDockerArgsUnchanged(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitBuild(t, app, w)

	dockerDir := sessionDockerDir(app.Config.RuntimeDir, result.Session.ID)

	// Verify arg structure (staged paths replace workspace paths).
	if len(capturedArgs) < 10 {
		t.Fatalf("expected at least 10 args, got %d: %v", len(capturedArgs), capturedArgs)
	}

	// Check fixed args.
	expectedPrefix := []string{
		"--config", dockerDir,
		"build",
		"--pull",
		"--provenance=false",
		"--sbom=false",
		"--file",
	}
	for i, exp := range expectedPrefix {
		if capturedArgs[i] != exp {
			t.Errorf("arg[%d]: expected %q, got %q", i, exp, capturedArgs[i])
		}
	}

	// --file value should be a staged path (contains "context").
	fileArg := capturedArgs[7]
	if !strings.Contains(fileArg, "context") {
		t.Errorf("--file should be a staged path containing 'context', got %q", fileArg)
	}

	// --tag should be present.
	if capturedArgs[8] != "--tag" || capturedArgs[9] != "example:test" {
		t.Errorf("expected --tag example:test, got %v", capturedArgs[8:11])
	}

	// Last arg should be a staged context path (contains "context").
	lastArg := capturedArgs[len(capturedArgs)-1]
	if !strings.Contains(lastArg, "context") {
		t.Errorf("last arg should be a staged context path containing 'context', got %q", lastArg)
	}
}

func newBuildRequest(body map[string]any, token string) *http.Request {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return req
}
