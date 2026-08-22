package main

import (
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

// TestBuildStartFailureReturns201WithFailedOperation proves that when
// cmd.Start() fails, POST /build returns 201 with a failed operation.
func TestBuildStartFailureReturns201WithFailedOperation(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/nonexistent/binary/that/does/not/exist")
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

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}

	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found in registry")
	}

	op.Wait()

	if op.State != operationFailed {
		t.Errorf("expected status 'failed', got %q", op.State)
	}
	if op.ResultCode == nil || *op.ResultCode != "docker_build_failed" {
		t.Errorf("expected result_code 'docker_build_failed', got %v", op.ResultCode)
	}
}

// TestBuildLiveOutput proves build output becomes visible through logs
// while the command is still running.
func TestBuildLiveOutput(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	syncDir := t.TempDir()
	readyFile := filepath.Join(syncDir, "ready")
	releaseFile := filepath.Join(syncDir, "release")

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		// Write output, signal readiness, then block until release file appears.
		// This creates an explicit handshake: the test controls when the
		// process is allowed to complete, ensuring it stays running while
		// we verify logs and operation state.
		return exec.CommandContext(ctx, "/bin/sh", "-c",
			"echo line1; echo line2; touch "+readyFile+
				"; while [ ! -f "+releaseFile+" ]; do sleep 0.1; done")
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

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)

	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatalf("operation %s not found in registry", opID)
	}

	// Wait for the process to signal that it has produced output.
	waitProcessReady(t, readyFile)

	// Read logs while the operation is still running.
	logsReq := httptest.NewRequest(http.MethodGet, "/operations/"+opID+"/logs", nil)
	logsReq.Header.Set("Authorization", "Bearer "+result.Token)
	logsW := httptest.NewRecorder()
	newOperationMux(app).ServeHTTP(logsW, logsReq)

	var logsResp map[string]any
	if err := json.NewDecoder(logsW.Body).Decode(&logsResp); err != nil {
		t.Fatalf("decode logs: %v", err)
	}
	logs, _ := logsResp["logs"].(string)
	if logs == "" {
		t.Fatal("expected output in logs while build was running")
	}

	// Verify operation is still running.
	op.mu.Lock()
	status := op.State
	op.mu.Unlock()
	if status != operationRunning {
		t.Fatalf("expected operation to be running, got %s", status)
	}

	// Release the child process so it can complete.
	if err := os.WriteFile(releaseFile, nil, 0644); err != nil {
		t.Fatalf("create release file: %v", err)
	}

	// Wait for normal completion.
	<-op.done

	// Verify final state.
	op.mu.Lock()
	finalStatus := op.State
	op.mu.Unlock()
	if finalStatus != operationSucceeded {
		t.Fatalf("expected operation to succeed, got %s", finalStatus)
	}
}

// TestBuildSuccessTransition proves running -> succeeded transition.
func TestBuildSuccessTransition(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
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

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)

	op := app.OperationRegistry.get(opID)
	op.Wait()

	if op.State != operationSucceeded {
		t.Errorf("expected status 'succeeded', got %q", op.State)
	}
	if op.CompletedAt == nil {
		t.Error("expected CompletedAt to be set")
	}
	if op.Duration == nil {
		t.Error("expected Duration to be set")
	}
	if op.ResultCode == nil || *op.ResultCode != "succeeded" {
		t.Errorf("expected result_code 'succeeded', got %v", op.ResultCode)
	}
}

// TestBuildNonZeroExitTransition proves running -> failed with exit code.
func TestBuildNonZeroExitTransition(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 42")
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

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)

	op := app.OperationRegistry.get(opID)
	op.Wait()

	if op.State != operationFailed {
		t.Errorf("expected status 'failed', got %q", op.State)
	}
	if op.ExitCode == nil || *op.ExitCode != 42 {
		t.Errorf("expected exit_code 42, got %v", op.ExitCode)
	}
	if op.ResultCode == nil || *op.ResultCode != "docker_build_failed" {
		t.Errorf("expected result_code 'docker_build_failed', got %v", op.ResultCode)
	}
}

// TestAuditFinishEmittedOnce proves the build.finish audit event
// is emitted exactly once.
func TestAuditFinishEmittedOnce(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
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
	finishCount := 0
	for _, rec := range records {
		if rec.Event == "build.finish" {
			finishCount++
		}
	}

	if finishCount != 1 {
		t.Errorf("expected exactly 1 build.finish audit record, got %d", finishCount)
	}
}

// TestBuildStdoutStderrNoDeadlock proves that concurrent stdout/stderr
// capture does not deadlock when both streams produce output before
// the process exits. This is a regression test for the old
// io.MultiReader(stdout, stderr) approach which could block.
func TestBuildStdoutStderrNoDeadlock(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	// Write substantial data to both stdout and stderr before exiting.
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c",
			"for i in 1 2 3 4 5; do echo \"stdout-$i\"; echo \"stderr-$i\" >&2; done")
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

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)

	op := app.OperationRegistry.get(opID)
	op.Wait()

	if op.State != operationSucceeded {
		t.Fatalf("expected status 'succeeded', got %q", op.State)
	}

	// Fetch all logs.
	logsReq := httptest.NewRequest(http.MethodGet, "/operations/"+opID+"/logs", nil)
	logsReq.Header.Set("Authorization", "Bearer "+result.Token)
	logsW := httptest.NewRecorder()
	newOperationMux(app).ServeHTTP(logsW, logsReq)

	var logsResp map[string]any
	if err := json.NewDecoder(logsW.Body).Decode(&logsResp); err != nil {
		t.Fatalf("decode logs: %v", err)
	}
	logs, ok := logsResp["logs"].(string)
	if !ok {
		t.Fatal("expected logs field")
	}

	// Both stdout and stderr lines must be present.
	for i := 1; i <= 5; i++ {
		if !strings.Contains(logs, "stdout-"+string(rune('0'+i))) {
			t.Errorf("missing stdout-%d in logs", i)
		}
		if !strings.Contains(logs, "stderr-"+string(rune('0'+i))) {
			t.Errorf("missing stderr-%d in logs", i)
		}
	}
}
