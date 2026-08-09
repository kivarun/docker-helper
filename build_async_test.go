package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestBuildStartFailureReturns201WithFailedOperation proves that when
// cmd.Start() fails, POST /build returns 201 with a failed operation.
func TestBuildStartFailureReturns201WithFailedOperation(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
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
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c",
			"echo line1; echo line2; sleep 0.5; echo line3")
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

	// Poll for output while the build is still running.
	foundOutput := false
	for i := 0; i < 50; i++ {
		logsReq := httptest.NewRequest(http.MethodGet, "/operations/"+opID+"/logs", nil)
		logsReq.SetPathValue("id", opID)
		logsReq.Header.Set("Authorization", "Bearer "+result.Token)
		logsW := httptest.NewRecorder()
		app.handleOperationLogs(logsW, logsReq)

		var logsResp map[string]any
		if err := json.NewDecoder(logsW.Body).Decode(&logsResp); err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		logs, _ := logsResp["logs"].(string)
		if len(logs) > 0 {
			foundOutput = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !foundOutput {
		t.Fatal("no output became available while build was running")
	}

	// Wait for build to complete.
	op := app.OperationRegistry.get(opID)
	op.Wait()
}

// TestBuildSuccessTransition proves running -> succeeded transition.
func TestBuildSuccessTransition(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
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
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
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

// TestShutdownSignalsBuild proves shutdown signals a running build
// and does not block past the deadline.
func TestShutdownSignalsBuild(t *testing.T) {
	app := newTestAppWithAuth(t)
	reg := newOperationRegistry()
	app.OperationRegistry = reg

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(app.Config.AllowedRoot, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sleep", "30")
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

	// Verify operation is running.
	op := reg.get(opID)
	if op == nil {
		t.Fatal("operation not found")
	}

	// Give the process time to start.
	time.Sleep(100 * time.Millisecond)

	// Mark registry as shutting down and terminate.
	reg.setShuttingDown()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	startShutdown := time.Now()
	reg.terminateAll(shutdownCtx)
	shutdownDuration := time.Since(startShutdown)
	cancel()

	// Shutdown should not block past the deadline.
	if shutdownDuration > 6*time.Second {
		t.Errorf("shutdown took too long: %v", shutdownDuration)
	}

	// The operation should have been terminated.
	op.Wait()
}

// TestAuditFinishEmittedOnce proves the build.finish audit event
// is emitted exactly once.
func TestAuditFinishEmittedOnce(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
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
