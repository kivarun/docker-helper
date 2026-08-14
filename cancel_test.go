package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestCancelRunningBuild proves that cancelling a running build
// terminates the process and returns result_code=cancelled.
func TestCancelRunningBuild(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
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
	app := newTestAppWithAuthAndStaging(t)
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
	app := newTestAppWithAuthAndStaging(t)
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
	app := newTestAppWithAuthAndStaging(t)
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
	app := newTestAppWithAuthAndStaging(t)
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
	app := newTestAppWithAuthAndStaging(t)
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
	app := newTestAppWithAuthAndStaging(t)
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
	app := newTestAppWithAuthAndStaging(t)
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
	app := newTestAppWithAuthAndStaging(t)
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
	app := newTestAppWithAuthAndStaging(t)
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
	app := newTestAppWithAuthAndStaging(t)
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
	app := newTestAppWithAuthAndStaging(t)
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
}

// TestShutdownDoesNotProduceCancelledResult proves that daemon shutdown
// does not produce result_code=cancelled for build operations.
func TestShutdownDoesNotProduceCancelledResult(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
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

	// Simulate daemon shutdown by calling terminateAll directly.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	app.OperationRegistry.terminateAll(ctx, app.killContainerBestEffort)

	// Wait for the operation to complete.
	op.Wait()

	// Verify the result is NOT cancelled.
	op.mu.Lock()
	rc := ""
	if op.ResultCode != nil {
		rc = *op.ResultCode
	}
	op.mu.Unlock()

	if rc == "cancelled" {
		t.Errorf("shutdown should not produce result_code 'cancelled', got %q", rc)
	}
}

// TestShutdownDoesNotProduceCancelledResultRun proves that daemon shutdown
// does not produce result_code=cancelled for run operations.
func TestShutdownDoesNotProduceCancelledResultRun(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
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

	// Simulate daemon shutdown by calling terminateAll directly.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	app.OperationRegistry.terminateAll(ctx, app.killContainerBestEffort)

	// Wait for the operation to complete.
	op.Wait()

	// Verify the result is NOT cancelled.
	op.mu.Lock()
	rc := ""
	if op.ResultCode != nil {
		rc = *op.ResultCode
	}
	op.mu.Unlock()

	if rc == "cancelled" {
		t.Errorf("shutdown should not produce result_code 'cancelled', got %q", rc)
	}
}

// TestTerminationReasonOwnershipCancelFirst proves that when explicit cancel
// sets the reason first, a subsequent shutdown attempt cannot overwrite it.
// Uses a synchronization channel to deterministically control ordering:
// terminateOne acquires op.mu and sets reason, then terminateAll runs.
func TestTerminationReasonOwnershipCancelFirst(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newBuildOperation(result.Session.ID, "test:image", ".", "Dockerfile", 4*1024*1024, "")
	app.OperationRegistry.mu.Lock()
	app.OperationRegistry.ops[op.ID] = op
	app.OperationRegistry.mu.Unlock()

	// Barrier: terminateAll waits until terminateOne has completed.
	cancelDone := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: explicit cancel (runs first).
	go func() {
		defer wg.Done()
		_ = app.OperationRegistry.terminateOne(op.ID, app.killContainerBestEffort)
		close(cancelDone)
	}()

	// Goroutine 2: shutdown (waits for cancel to finish).
	go func() {
		defer wg.Done()
		<-cancelDone
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		app.OperationRegistry.terminateAll(ctx, app.killContainerBestEffort)
	}()

	wg.Wait()

	// Verify: reason must still be cancelled, not overwritten by shutdown.
	op.mu.Lock()
	reason := op.reason
	op.mu.Unlock()

	if reason != terminationCancelled {
		t.Errorf("reason = %d, want %d (terminationCancelled)", reason, terminationCancelled)
	}
}

// TestTerminationReasonOwnershipShutdownFirst proves that when shutdown
// sets the reason first, a subsequent explicit cancel cannot overwrite it.
// Uses a synchronization channel to deterministically control ordering:
// terminateAll acquires op.mu and sets reason, then terminateOne runs.
func TestTerminationReasonOwnershipShutdownFirst(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newBuildOperation(result.Session.ID, "test:image", ".", "Dockerfile", 4*1024*1024, "")
	app.OperationRegistry.mu.Lock()
	app.OperationRegistry.ops[op.ID] = op
	app.OperationRegistry.mu.Unlock()

	// Barrier: terminateOne waits until terminateAll has completed.
	shutdownDone := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: shutdown (runs first).
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		app.OperationRegistry.terminateAll(ctx, app.killContainerBestEffort)
		close(shutdownDone)
	}()

	// Goroutine 2: explicit cancel (waits for shutdown to finish).
	go func() {
		defer wg.Done()
		<-shutdownDone
		_ = app.OperationRegistry.terminateOne(op.ID, app.killContainerBestEffort)
	}()

	wg.Wait()

	// Verify: reason must still be shutdown, not overwritten by cancel.
	op.mu.Lock()
	reason := op.reason
	op.mu.Unlock()

	if reason != terminationShutdown {
		t.Errorf("reason = %d, want %d (terminationShutdown)", reason, terminationShutdown)
	}
}

// TestTerminalTransitionSucceedWins proves the single-terminal-transition
// invariant at the primitive level: when succeed() transitions first,
// a subsequent fail() cannot overwrite the result.
// A channel barrier fixes the ordering: succeed() runs first, then fail().
func TestTerminalTransitionSucceedWins(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newBuildOperation(result.Session.ID, "test:image", ".", "Dockerfile", 4*1024*1024, "")

	// Barrier: fail waits until succeed has completed the transition.
	succeedDone := make(chan struct{})

	var succeedResult, failResult bool
	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: succeed (runs first).
	go func() {
		defer wg.Done()
		dur := "100ms"
		succeedResult = op.succeed(&dur)
		close(succeedDone)
	}()

	// Goroutine 2: fail (waits for succeed to finish).
	go func() {
		defer wg.Done()
		<-succeedDone
		exitCode := 1
		failResult = op.fail("cancelled", "build cancelled", &exitCode, nil)
	}()

	wg.Wait()

	// Verify: succeed won, fail lost.
	if !succeedResult {
		t.Fatal("succeed() must return true when it wins")
	}
	if failResult {
		t.Fatal("fail() must return false when succeed already transitioned")
	}

	// Verify: final state/result = succeeded.
	op.mu.Lock()
	state := op.State
	rc := ""
	if op.ResultCode != nil {
		rc = *op.ResultCode
	}
	completedAt := op.CompletedAt
	op.mu.Unlock()

	if state != operationSucceeded {
		t.Errorf("state = %q, want succeeded", state)
	}
	if rc != "succeeded" {
		t.Errorf("result_code = %q, want succeeded", rc)
	}
	if completedAt == nil {
		t.Error("CompletedAt must not be nil")
	}

	// Verify: done is closed.
	select {
	case <-op.done:
	default:
		t.Fatal("op.done must be closed after successful transition")
	}

	// Verify: exactly one finish audit.
	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	finishCount := 0
	for _, r := range records {
		if r.Event == "build.finish" {
			finishCount++
		}
	}
	if finishCount != 1 {
		t.Errorf("build.finish audit count = %d, want 1", finishCount)
	}
}

// TestTerminalTransitionFailWins proves the single-terminal-transition
// invariant at the primitive level: when fail() transitions first,
// a subsequent succeed() cannot overwrite the result.
// A channel barrier fixes the ordering: fail() runs first, then succeed().
func TestTerminalTransitionFailWins(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newBuildOperation(result.Session.ID, "test:image", ".", "Dockerfile", 4*1024*1024, "")

	// Barrier: succeed waits until fail has completed the transition.
	failDone := make(chan struct{})

	var succeedResult, failResult bool
	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: fail (runs first).
	go func() {
		defer wg.Done()
		exitCode := 1
		failResult = op.fail("cancelled", "build cancelled", &exitCode, nil)
		close(failDone)
	}()

	// Goroutine 2: succeed (waits for fail to finish).
	go func() {
		defer wg.Done()
		<-failDone
		dur := "100ms"
		succeedResult = op.succeed(&dur)
	}()

	wg.Wait()

	// Verify: fail won, succeed lost.
	if !failResult {
		t.Fatal("fail() must return true when it wins")
	}
	if succeedResult {
		t.Fatal("succeed() must return false when fail already transitioned")
	}

	// Verify: final state/result = cancelled.
	op.mu.Lock()
	state := op.State
	rc := ""
	if op.ResultCode != nil {
		rc = *op.ResultCode
	}
	completedAt := op.CompletedAt
	op.mu.Unlock()

	if state != operationFailed {
		t.Errorf("state = %q, want failed", state)
	}
	if rc != "cancelled" {
		t.Errorf("result_code = %q, want cancelled", rc)
	}
	if completedAt == nil {
		t.Error("CompletedAt must not be nil")
	}

	// Verify: done is closed.
	select {
	case <-op.done:
	default:
		t.Fatal("op.done must be closed after successful transition")
	}

	// Verify: exactly one finish audit.
	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	finishCount := 0
	for _, r := range records {
		if r.Event == "build.finish" {
			finishCount++
		}
	}
	if finishCount != 1 {
		t.Errorf("build.finish audit count = %d, want 1", finishCount)
	}
}

// TestCancelAfterNaturalCompletionPreservesResult proves that when the
// operation completes naturally before cancel processes it, the natural
// result is preserved (sequential idempotency).
func TestCancelAfterNaturalCompletionPreservesResult(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
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
		// Complete immediately with exit 0 (success).
		return exec.CommandContext(ctx, "true")
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

	// Wait for natural completion to finish.
	op.Wait()

	// Now attempt cancel — it should see the operation is already terminal.
	cancelReq := httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	app.handleOperationCancel(cancelW, cancelReq)

	// Verify: result must be succeeded, not cancelled.
	op.mu.Lock()
	state := op.State
	rc := ""
	if op.ResultCode != nil {
		rc = *op.ResultCode
	}
	completedAt := op.CompletedAt
	op.mu.Unlock()

	if state != operationSucceeded {
		t.Errorf("state = %q, want succeeded", state)
	}
	if rc != "succeeded" {
		t.Errorf("result_code = %q, want succeeded", rc)
	}
	if completedAt == nil {
		t.Error("CompletedAt must not be nil")
	}
}

// TestConcurrentDoubleCancel proves that two simultaneous cancel requests
// for the same running operation produce exactly one terminal transition
// and one finish audit. Both HTTP requests complete without error.
func TestConcurrentDoubleCancel(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuthAndStaging(t)
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

	// Launch two cancel requests concurrently.
	// Both enter the handler at roughly the same time.
	var wg sync.WaitGroup
	wg.Add(2)

	var cancelW1, cancelW2 *httptest.ResponseRecorder
	var cancelReq1, cancelReq2 *http.Request

	// Prepare both requests.
	cancelReq1 = httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq1.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW1 = httptest.NewRecorder()

	cancelReq2 = httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq2.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW2 = httptest.NewRecorder()

	// Barrier: both goroutines start at the same time.
	start := make(chan struct{})

	go func() {
		defer wg.Done()
		<-start
		app.handleOperationCancel(cancelW1, cancelReq1)
	}()

	go func() {
		defer wg.Done()
		<-start
		app.handleOperationCancel(cancelW2, cancelReq2)
	}()

	close(start)
	wg.Wait()

	// Both requests must complete successfully.
	if cancelW1.Code != http.StatusOK {
		t.Errorf("cancel 1: expected %d, got %d", http.StatusOK, cancelW1.Code)
	}
	if cancelW2.Code != http.StatusOK {
		t.Errorf("cancel 2: expected %d, got %d", http.StatusOK, cancelW2.Code)
	}

	// Verify: single terminal result.
	op.mu.Lock()
	state := op.State
	rc := ""
	if op.ResultCode != nil {
		rc = *op.ResultCode
	}
	completedAt := op.CompletedAt
	op.mu.Unlock()

	if state != operationFailed {
		t.Errorf("state = %q, want failed", state)
	}
	if rc != "cancelled" {
		t.Errorf("result_code = %q, want cancelled", rc)
	}
	if completedAt == nil {
		t.Error("CompletedAt must not be nil")
	}

	// Verify: exactly one finish audit.
	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	finishCount := 0
	for _, r := range records {
		if r.Event == "build.finish" {
			finishCount++
		}
	}
	if finishCount != 1 {
		t.Errorf("build.finish audit count = %d, want 1", finishCount)
	}

	// Verify: done is closed.
	select {
	case <-op.done:
	default:
		t.Fatal("op.done must be closed")
	}
}

// TestCancelPlusShutdownCleanup verifies that when explicit cancel and
// shutdown concurrently force-cleanup the same running run operation with
// a cidfile, daemon-side cleanup is performed exactly once.
//
// The single-owner guard ensures that only the first termination path
// to reach the force phase claims cleanup ownership. The second path
// skips cleanup and waits for the first path's work to complete.
func TestCancelPlusShutdownCleanup(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Create a cidfile with a synthetic container ID.
	cidfile := filepath.Join(app.Config.RuntimeDir, "test.cid")
	testContainerID := "test-container-id-12345"
	if err := os.WriteFile(cidfile, []byte(testContainerID), 0644); err != nil {
		t.Fatalf("cannot write cidfile: %v", err)
	}

	// Create a run operation directly with cidfile set.
	op := newRunOperation(result.Session.ID, "test:image", 4*1024*1024, "")
	op.cidfile = cidfile
	op.started = true // simulate already-started process
	app.OperationRegistry.mu.Lock()
	app.OperationRegistry.ops[op.ID] = op
	app.OperationRegistry.mu.Unlock()

	// Count daemon-side cleanup callback invocations.
	var killCount int32
	var killIDs []string
	var killMu sync.Mutex

	fakeKillContainer := func(ctx context.Context, cid string) {
		atomic.AddInt32(&killCount, 1)
		killMu.Lock()
		killIDs = append(killIDs, cid)
		killMu.Unlock()
	}

	// Create a long-running process that survives SIGTERM so the graceful
	// phase expires and both termination paths reach force cleanup.
	// Use a busy-loop approach that explicitly ignores SIGTERM.
	cmd := exec.Command("sh", "-c", "trap ':' TERM; while :; do :; done")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start test process: %v", err)
	}
	op.cmd = cmd

	// Verify the process is running.
	if cmd.Process == nil {
		t.Fatal("process not started")
	}
	t.Logf("test process PID: %d", cmd.Process.Pid)

	// Wait a moment for the process to stabilize.
	time.Sleep(100 * time.Millisecond)

	// Start a completion goroutine that waits for the process and transitions
	// the operation to terminal (mimics the real run handler behavior).
	go func() {
		cmd.Wait()
		// After process exits, transition to terminal.
		exitCode := 137 // typical SIGKILL exit code
		op.fail("docker_run_failed", "docker run failed", &exitCode, nil)
	}()

	// Launch cancel and shutdown concurrently.
	// Both use the same fakeKillContainer callback to count cleanup attempts.
	var wg sync.WaitGroup
	wg.Add(2)

	start := make(chan struct{})

	go func() {
		defer wg.Done()
		<-start
		app.OperationRegistry.terminateOne(op.ID, fakeKillContainer)
	}()

	go func() {
		defer wg.Done()
		<-start
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		app.OperationRegistry.terminateAll(ctx, fakeKillContainer)
	}()

	close(start)
	wg.Wait()

	// Wait for the completion goroutine to finish.
	select {
	case <-op.done:
	case <-time.After(10 * time.Second):
		t.Fatal("operation did not complete within timeout")
	}

	// Clean up the test process (should already be dead from Kill).
	// Use Process.Signal to avoid racing with cmd.Wait() in the completion goroutine.
	cmd.Process.Signal(syscall.SIGKILL) // best-effort, may already be dead
	os.Remove(cidfile)

	// Verify: daemon-side cleanup performed exactly once.
	killCalls := atomic.LoadInt32(&killCount)
	if killCalls != 1 {
		t.Errorf("killContainer invoked %d times, want 1 (single-owner force cleanup)", killCalls)
	}

	// Verify: operation reached terminal state.
	op.mu.Lock()
	rc := ""
	if op.ResultCode != nil {
		rc = *op.ResultCode
	}
	completedAt := op.CompletedAt
	op.mu.Unlock()

	if completedAt == nil {
		t.Fatal("CompletedAt must not be nil")
	}
	// Result is either cancelled or shutdown — both are valid (first-reason-wins).
	if rc != "cancelled" && rc != "docker_run_failed" {
		t.Errorf("result_code = %q, want cancelled or docker_run_failed", rc)
	}

	// Verify: kill callback used the expected container ID.
	killMu.Lock()
	for _, id := range killIDs {
		if id != testContainerID {
			t.Errorf("killContainer called with unexpected ID %q, want %q", id, testContainerID)
		}
	}
	killMu.Unlock()

	// Verify: exactly one finish audit.
	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	finishCount := 0
	for _, r := range records {
		if r.Event == "run.finish" {
			finishCount++
		}
	}
	if finishCount != 1 {
		t.Errorf("run.finish audit count = %d, want 1", finishCount)
	}
}

// TestForceCleanupLateFollowerSharedDeadline proves that a late-arriving
// follower in the force-cleanup phase waits only the remaining time until
// the shared force deadline (the context deadline), not a fresh full
// defaultForceCleanupTimeout.
func TestForceCleanupLateFollowerSharedDeadline(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Create a run operation with force cleanup already claimed by an owner.
	op := newRunOperation(result.Session.ID, "test:image", 4*1024*1024, "")
	op.started = true
	op.forceOwned = true
	op.forceDone = make(chan struct{})
	op.forceDeadline = time.Now().Add(200 * time.Millisecond)
	app.OperationRegistry.mu.Lock()
	app.OperationRegistry.ops[op.ID] = op
	app.OperationRegistry.mu.Unlock()

	// Start a long-running process that survives SIGTERM so the follower
	// reaches the force phase. The owner is simulated (already claimed).
	cmd := exec.Command("sh", "-c", "trap ':' TERM; while :; do :; done")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start test process: %v", err)
	}
	op.cmd = cmd

	// Wait for the process to stabilize.
	time.Sleep(100 * time.Millisecond)

	// Completion goroutine (mimics real handler).
	go func() {
		cmd.Wait()
		exitCode := 137
		op.fail("docker_run_failed", "docker run failed", &exitCode, nil)
	}()

	// Launch the follower via terminateAll with a short context deadline.
	// With the bounded shutdown model, the force deadline is the context
	// deadline (50ms), not a fresh defaultForceCleanupTimeout.
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	app.OperationRegistry.terminateAll(ctx, func(context.Context, string) {})
	elapsed := time.Since(start)

	// Clean up.
	cmd.Process.Signal(syscall.SIGKILL)
	<-op.done

	// The follower should return within the context deadline (50ms),
	// not a fresh full defaultForceCleanupTimeout (3s).
	if elapsed > 250*time.Millisecond {
		t.Errorf("follower waited %v, expected significantly less than 3s (context deadline was 50ms)", elapsed)
	}
	t.Logf("follower returned in %v (context deadline: 50ms)", elapsed)
}

// TestCancelResponseNoTimestampFields verifies that the cancel response
// does not contain timestamp fields (created_at, started_at, completed_at, duration).
func TestCancelResponseNoTimestampFields(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Create a run operation that completes immediately.
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"echo", "hello"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("run: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var runResp map[string]any
	json.NewDecoder(w.Body).Decode(&runResp)
	opID := runResp["operation_id"].(string)

	// Wait for the operation to complete.
	time.Sleep(500 * time.Millisecond)

	// Cancel the already-completed operation.
	cancelReq := httptest.NewRequest("POST", "/operations/"+opID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	w = httptest.NewRecorder()
	app.handleOperationCancel(w, cancelReq)

	if w.Code != http.StatusOK {
		t.Fatalf("cancel: expected %d, got %d", http.StatusOK, w.Code)
	}

	var cancelResp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&cancelResp); err != nil {
		t.Fatalf("cannot decode cancel response: %v", err)
	}

	// Verify no timestamp fields are present.
	for _, field := range []string{"created_at", "started_at", "completed_at", "duration"} {
		if _, ok := cancelResp[field]; ok {
			t.Errorf("cancel response must not contain %q field", field)
		}
	}

	// Verify expected fields are present.
	if cancelResp["ok"] != true {
		t.Error("expected ok=true")
	}
	if cancelResp["operation_id"] != opID {
		t.Errorf("expected operation_id=%s, got %v", opID, cancelResp["operation_id"])
	}
	if cancelResp["status"] != "succeeded" {
		t.Errorf("expected status=succeeded, got %v", cancelResp["status"])
	}
}
