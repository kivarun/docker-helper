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
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatalf("operation %s not found in supervisor", opID)
	}
	op.Wait()
}

func TestBuildStartContainsFields(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
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

	app, _, result, _, _ := setupBuildBackendTest(t)

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

	app, _, result, _, _ := setupBuildBackendTest(t)

	// The buildctl stage fails with exit 1; later stages never run.
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if strings.HasSuffix(name, "buildctl") {
			return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 1")
		}
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

	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
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

	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
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
	app, _, result, _, calls := setupBuildBackendTest(t)

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

	// The P3 backend runs buildctl as the execution child: verify the exact
	// server-owned argv contract (§8) — fixed frontend/progress, staged
	// --local paths, the op-internal tag exporter, and no requested image.
	args := buildctlCall(t, calls)
	expectedFixed := []string{
		"build",
		"--progress=plain",
		"--frontend=dockerfile.v0",
		"--local", "context=" + calls.contextPathOf(calls.buildctlIndex()),
		"--local", "dockerfile=" + calls.contextPathOf(calls.buildctlIndex()),
		"--opt", "filename=Dockerfile",
	}
	sliceEqual := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	found := false
	for i := 0; i+len(expectedFixed) <= len(args); i++ {
		if sliceEqual(args[i:i+len(expectedFixed)], expectedFixed) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("fixed buildctl prefix not found in argv: %v", args)
	}

	// --output carries the internal tag + staged export tar.
	var outputArg string
	for i, arg := range args {
		if arg == "--output" && i+1 < len(args) {
			outputArg = args[i+1]
		}
	}
	if !strings.Contains(outputArg, "name=docker-helper-build/") {
		t.Errorf("--output must carry the internal tag, got %q", outputArg)
	}
	if !strings.Contains(outputArg, ",dest=") {
		t.Errorf("--output must carry the export tar dest, got %q", outputArg)
	}
	if strings.Contains(strings.Join(args, "\x00"), "example:test") {
		t.Errorf("requested image must not appear in buildctl argv: %v", args)
	}
}

func newBuildRequest(body map[string]any, token string) *http.Request {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return req
}
