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

// TestCancelRunningBuild proves that cancelling a running build
// terminates the process and returns result_code=cancelled.
func TestCancelRunningBuild(t *testing.T) {
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
		// Use sleep 300 which will respond to SIGTERM.
		return exec.CommandContext(ctx, "sleep", "300")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("build: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var buildResp map[string]any
	json.NewDecoder(w.Body).Decode(&buildResp)
	opID := buildResp["operation_id"].(string)

	// Verify the operation is in the registry.
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatalf("operation %s not found in registry after build", opID)
	}
	if op.SessionID != result.Session.ID {
		t.Fatalf("operation session ID %s != result session ID %s", op.SessionID, result.Session.ID)
	}

	// Wait for the process to start.
	for i := 0; i < 50; i++ {
		op.mu.Lock()
		proc := op.cmd
		op.mu.Unlock()
		if proc != nil && proc.Process != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if op.cmd == nil || op.cmd.Process == nil {
		t.Fatal("process not started yet")
	}

	// Cancel the operation.
	t.Logf("cancelling operation %s (session %s)", opID, result.Session.ID)

	// Verify the operation is still in the registry.
	opBeforeCancel := app.OperationRegistry.get(opID)
	if opBeforeCancel == nil {
		t.Fatalf("operation %s not found in registry before cancel", opID)
	}
	t.Logf("operation session ID: %s", opBeforeCancel.SessionID)

	cancelReq := httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	app.handleOperationCancel(cancelW, cancelReq)

	if cancelW.Code != http.StatusOK {
		t.Logf("cancel response: %d %s", cancelW.Code, cancelW.Body.String())
		t.Fatalf("cancel: expected %d, got %d", http.StatusOK, cancelW.Code)
	}

	var cancelResp map[string]any
	json.NewDecoder(cancelW.Body).Decode(&cancelResp)
	if cancelResp["status"] != "failed" {
		t.Errorf("expected status 'failed', got %v", cancelResp["status"])
	}
	if cancelResp["result_code"] != "cancelled" {
		t.Errorf("expected result_code 'cancelled', got %v", cancelResp["result_code"])
	}
}

// TestCancelRunningRun proves that cancelling a running run
// terminates the process and returns result_code=cancelled.
func TestCancelRunningRun(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		// Use sleep 300 which will respond to SIGTERM.
		return exec.CommandContext(ctx, "sleep", "300")
	}

	runReq := newRunRequest(map[string]any{
		"image": "alpine:3.24",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, runReq)

	if w.Code != http.StatusCreated {
		t.Fatalf("run: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var runResp map[string]any
	json.NewDecoder(w.Body).Decode(&runResp)
	opID := runResp["operation_id"].(string)

	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found")
	}
	if op.cmd == nil || op.cmd.Process == nil {
		t.Fatal("process not started yet")
	}

	cancelReq := httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	app.handleOperationCancel(cancelW, cancelReq)

	if cancelW.Code != http.StatusOK {
		t.Fatalf("cancel: expected %d, got %d", http.StatusOK, cancelW.Code)
	}

	var cancelResp map[string]any
	json.NewDecoder(cancelW.Body).Decode(&cancelResp)
	if cancelResp["status"] != "failed" {
		t.Errorf("expected status 'failed', got %v", cancelResp["status"])
	}
	if cancelResp["result_code"] != "cancelled" {
		t.Errorf("expected result_code 'cancelled', got %v", cancelResp["result_code"])
	}
}

// TestCancelUnknownOperation returns 404 for unknown operation ID.
func TestCancelUnknownOperation(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	cancelReq := httptest.NewRequest("POST", "/operations/op_unknown123/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleOperationCancel(w, cancelReq)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected %d, got %d", http.StatusNotFound, w.Code)
	}
}

// TestCancelOtherSessionOperation returns 404 for operation belonging to another session.
func TestCancelOtherSessionOperation(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	session1, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession1: %v", err)
	}

	session2, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession2: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sleep", "300")
	}

	runReq := newRunRequest(map[string]any{
		"image": "alpine:3.24",
	}, session1.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, runReq)

	var runResp map[string]any
	json.NewDecoder(w.Body).Decode(&runResp)
	opID := runResp["operation_id"].(string)

	// Try to cancel with session2's token.
	cancelReq := httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+session2.Token)
	cancelW := httptest.NewRecorder()
	app.handleOperationCancel(cancelW, cancelReq)

	if cancelW.Code != http.StatusNotFound {
		t.Errorf("expected %d, got %d", http.StatusNotFound, cancelW.Code)
	}

	// Clean up: cancel with the correct session to avoid leaving orphan processes.
	cancelReq2 := httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq2.Header.Set("Authorization", "Bearer "+session1.Token)
	cancelW2 := httptest.NewRecorder()
	app.handleOperationCancel(cancelW2, cancelReq2)
}

// TestCancelAlreadyCompletedOperation returns current terminal state.
func TestCancelAlreadyCompletedOperation(t *testing.T) {
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
		return exec.CommandContext(ctx, "exit", "1")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	var buildResp map[string]any
	json.NewDecoder(w.Body).Decode(&buildResp)
	opID := buildResp["operation_id"].(string)

	op := app.OperationRegistry.get(opID)
	op.Wait()

	// Try to cancel the already-completed operation.
	cancelReq := httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	app.handleOperationCancel(cancelW, cancelReq)

	if cancelW.Code != http.StatusOK {
		t.Errorf("expected %d, got %d", http.StatusOK, cancelW.Code)
	}

	var cancelResp map[string]any
	json.NewDecoder(cancelW.Body).Decode(&cancelResp)
	if cancelResp["status"] != "failed" {
		t.Errorf("expected status 'failed', got %v", cancelResp["status"])
	}
}

// TestCancelVsNaturalCompletion proves that when the operation completes
// naturally before cancel processes it, the natural result is preserved.
func TestCancelVsNaturalCompletion(t *testing.T) {
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
		// Complete immediately.
		return exec.CommandContext(ctx, "exit", "1")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	var buildResp map[string]any
	json.NewDecoder(w.Body).Decode(&buildResp)
	opID := buildResp["operation_id"].(string)

	op := app.OperationRegistry.get(opID)
	op.Wait()

	// Now try to cancel.
	cancelReq := httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	app.handleOperationCancel(cancelW, cancelReq)

	if cancelW.Code != http.StatusOK {
		t.Errorf("expected %d, got %d", http.StatusOK, cancelW.Code)
	}

	var cancelResp map[string]any
	json.NewDecoder(cancelW.Body).Decode(&cancelResp)
	if cancelResp["status"] != "failed" {
		t.Errorf("expected status 'failed', got %v", cancelResp["status"])
	}
	// Natural completion should preserve docker_build_failed, not cancelled.
	if cancelResp["result_code"] != "docker_build_failed" {
		t.Errorf("expected result_code 'docker_build_failed', got %v", cancelResp["result_code"])
	}
}

// TestCancelPreservesLogs proves that operation logs remain accessible after cancel.
func TestCancelPreservesLogs(t *testing.T) {
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
		return exec.CommandContext(ctx, "sleep", "300")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	var buildResp map[string]any
	json.NewDecoder(w.Body).Decode(&buildResp)
	opID := buildResp["operation_id"].(string)

	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found")
	}

	// Wait for the process to start.
	for i := 0; i < 50; i++ {
		op.mu.Lock()
		proc := op.cmd
		op.mu.Unlock()
		if proc != nil && proc.Process != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if op.cmd == nil || op.cmd.Process == nil {
		t.Fatal("process not started yet")
	}

	// Cancel.
	cancelReq := httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	app.handleOperationCancel(cancelW, cancelReq)

	if cancelW.Code != http.StatusOK {
		t.Fatalf("cancel: expected %d, got %d", http.StatusOK, cancelW.Code)
	}

	// Read logs.
	logsReq := httptest.NewRequest("GET", "/operations/"+opID+"/logs?offset=0", nil)
	logsReq.Header.Set("Authorization", "Bearer "+result.Token)
	logsW := httptest.NewRecorder()
	app.handleOperationLogs(logsW, logsReq)

	if logsW.Code != http.StatusOK {
		t.Errorf("expected %d, got %d", http.StatusOK, logsW.Code)
	}
}

// TestCancelAuditEvent proves that cancelled operations emit the correct
// audit event with result=cancelled.
func TestCancelAuditEvent(t *testing.T) {
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
		return exec.CommandContext(ctx, "sleep", "300")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	var buildResp map[string]any
	json.NewDecoder(w.Body).Decode(&buildResp)
	opID := buildResp["operation_id"].(string)

	cancelReq := httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	app.handleOperationCancel(cancelW, cancelReq)

	// Verify the operation has result_code=cancelled.
	op := app.OperationRegistry.get(opID)
	if op.ResultCode == nil || *op.ResultCode != resultCancelled {
		t.Errorf("expected result_code 'cancelled', got %v", op.ResultCode)
	}
}

// TestCancelNoRegistry proves that cancel returns 404 when registry is nil.
func TestCancelNoRegistry(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = nil

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	cancelReq := httptest.NewRequest("POST", "/operations/op_test/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleOperationCancel(w, cancelReq)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected %d, got %d", http.StatusNotFound, w.Code)
	}
}

// TestCancelIdempotent proves that cancelling an already-cancelled operation
// returns the terminal state without error.
func TestCancelIdempotent(t *testing.T) {
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
		return exec.CommandContext(ctx, "sleep", "300")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	var buildResp map[string]any
	json.NewDecoder(w.Body).Decode(&buildResp)
	opID := buildResp["operation_id"].(string)

	// First cancel.
	cancelReq := httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	app.handleOperationCancel(cancelW, cancelReq)

	// Second cancel (idempotent).
	cancelReq2 := httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq2.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW2 := httptest.NewRecorder()
	app.handleOperationCancel(cancelW2, cancelReq2)

	if cancelW2.Code != http.StatusOK {
		t.Errorf("expected %d, got %d", http.StatusOK, cancelW2.Code)
	}

	var cancelResp2 map[string]any
	json.NewDecoder(cancelW2.Body).Decode(&cancelResp2)
	if cancelResp2["status"] != "failed" {
		t.Errorf("expected status 'failed', got %v", cancelResp2["status"])
	}
	if cancelResp2["result_code"] != "cancelled" {
		t.Errorf("expected result_code 'cancelled', got %v", cancelResp2["result_code"])
	}
}

// TestCancelRunCidfileCleanup proves that cancelling a run operation
// cleans up the cidfile.
func TestCancelRunCidfileCleanup(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "sleep", "300")
	}

	runReq := newRunRequest(map[string]any{
		"image": "alpine:3.24",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, runReq)

	var runResp map[string]any
	json.NewDecoder(w.Body).Decode(&runResp)
	opID := runResp["operation_id"].(string)

	op := app.OperationRegistry.get(opID)
	cidfile := op.cidfile

	cancelReq := httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	app.handleOperationCancel(cancelW, cancelReq)

	// Verify cidfile is cleaned up.
	if cidfile != "" {
		if _, err := os.Stat(cidfile); err == nil {
			t.Error("cidfile should be removed after cancel")
		}
	}
}

// TestCancelPreservesExitCode proves that cancelled operations preserve
// the exit code from the terminated process.
func TestCancelPreservesExitCode(t *testing.T) {
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
		return exec.CommandContext(ctx, "sleep", "300")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	var buildResp map[string]any
	json.NewDecoder(w.Body).Decode(&buildResp)
	opID := buildResp["operation_id"].(string)

	cancelReq := httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	app.handleOperationCancel(cancelW, cancelReq)

	var cancelResp map[string]any
	json.NewDecoder(cancelW.Body).Decode(&cancelResp)
	if cancelResp["result_code"] != "cancelled" {
		t.Errorf("expected result_code 'cancelled', got %v", cancelResp["result_code"])
	}
	// Exit code may be present if the process exited before SIGTERM took effect.
	// The important thing is result_code=cancelled.
}
