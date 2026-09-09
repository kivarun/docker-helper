package main

import (
	"context"
	"encoding/json"
	"errors"
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

// TestCancelRunningRunOperation proves at the route level that cancelling a
// running legacy operation terminates it and reports result_code=cancelled.
// Run no longer registers operations; the operation is constructed through
// the production supervisor primitives, and the legacy cancel route stays
// contract-tested until the operation framework removal (D0.4).
func TestCancelRunningRunOperation(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newRunOperation(result.Session.ID, "example:test", 4*1024*1024, "", "", "")
	if app.OperationSupervisor.admit(op) != admissionAccepted {
		t.Fatal("admit failed")
	}

	cmd := exec.Command("sleep", "300")
	if res := startOperationProcess(cmd, op); res.Terminated || res.Err != nil {
		t.Fatalf("start operation: terminated=%v err=%v", res.Terminated, res.Err)
	}
	go func() {
		cmd.Wait()
		op.fail("cancelled", "run cancelled", nil, nil)
	}()

	// Cancel the operation through the route.
	cancelReq := httptest.NewRequest("POST", "/operations/"+op.ID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	mux := newOperationMux(app)
	mux.ServeHTTP(cancelW, cancelReq)

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
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	cancelReq := httptest.NewRequest("POST", "/operations/op_unknown123/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	newOperationMux(app).ServeHTTP(w, cancelReq)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected %d, got %d", http.StatusNotFound, w.Code)
	}
}

// TestCancelOtherSessionOperation returns 404 for operation belonging to another session.
func TestCancelOtherSessionOperation(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	session1, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession1: %v", err)
	}

	session2, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession2: %v", err)
	}

	op := newRunOperation(session1.Session.ID, "alpine:3.24", 4*1024*1024, "", "", "")
	if app.OperationSupervisor.admit(op) != admissionAccepted {
		t.Fatal("admit failed")
	}

	// Try to cancel with session2's token.
	cancelReq := httptest.NewRequest("POST", "/operations/"+op.ID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+session2.Token)
	cancelW := httptest.NewRecorder()
	mux := newOperationMux(app)
	mux.ServeHTTP(cancelW, cancelReq)

	if cancelW.Code != http.StatusNotFound {
		t.Errorf("expected %d, got %d", http.StatusNotFound, cancelW.Code)
	}
}

// TestCancelPreservesLogs proves that operation logs remain accessible after
// cancel. The legacy cancel route stays contract-tested until the operation
// framework removal (D0.4).
func TestCancelPreservesLogsRunOperation(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newRunOperation(result.Session.ID, "example:test", 4*1024*1024, "", "", "")
	if app.OperationSupervisor.admit(op) != admissionAccepted {
		t.Fatal("admit failed")
	}

	cmd := exec.Command("sleep", "300")
	if res := startOperationProcess(cmd, op); res.Terminated || res.Err != nil {
		t.Fatalf("start operation: terminated=%v err=%v", res.Terminated, res.Err)
	}
	go func() {
		cmd.Wait()
		op.fail("cancelled", "run cancelled", nil, nil)
	}()

	// Cancel.
	cancelReq := httptest.NewRequest("POST", "/operations/"+op.ID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	mux := newOperationMux(app)
	mux.ServeHTTP(cancelW, cancelReq)

	if cancelW.Code != http.StatusOK {
		t.Fatalf("cancel: expected %d, got %d", http.StatusOK, cancelW.Code)
	}

	// Read logs after the cancel completed.
	logsReq := httptest.NewRequest("GET", "/operations/"+op.ID+"/logs?offset=0", nil)
	logsReq.Header.Set("Authorization", "Bearer "+result.Token)
	logsW := httptest.NewRecorder()
	newOperationMux(app).ServeHTTP(logsW, logsReq)

	if logsW.Code != http.StatusOK {
		t.Errorf("expected %d, got %d", http.StatusOK, logsW.Code)
	}
}

// TestCancelAuditEvent proves that cancelling a running legacy operation
// reports result_code=cancelled, classified by the cancellation reason
// exactly as the legacy run lifecycle classified it.
func TestCancelAuditEvent(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newRunOperation(result.Session.ID, "example:test", 4*1024*1024, "", "", "")
	if app.OperationSupervisor.admit(op) != admissionAccepted {
		t.Fatal("admit failed")
	}

	cmd := exec.Command("sleep", "300")
	if res := startOperationProcess(cmd, op); res.Terminated || res.Err != nil {
		t.Fatalf("start operation: terminated=%v err=%v", res.Terminated, res.Err)
	}
	go func() {
		cmd.Wait()
		// Classify like the legacy run lifecycle: by termination reason.
		op.mu.Lock()
		reason := op.reason
		op.mu.Unlock()
		if reason == terminationCancelled {
			op.fail(resultCancelled, "run cancelled", nil, nil)
		} else {
			op.fail("docker_run_failed", "docker run failed", nil, nil)
		}
	}()

	if err := app.OperationSupervisor.cancel(op.ID, app.killContainerBestEffort); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	select {
	case <-op.done:
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not complete after cancel")
	}

	op.mu.Lock()
	rc := ""
	if op.ResultCode != nil {
		rc = *op.ResultCode
	}
	op.mu.Unlock()

	if rc != resultCancelled {
		t.Errorf("expected result_code 'cancelled', got %q", rc)
	}
}

// TestCancelNoRegistry proves that cancel returns 404 when supervisor is nil.
func TestCancelNoSupervisor(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = nil

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	cancelReq := httptest.NewRequest("POST", "/operations/op_test/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	newOperationMux(app).ServeHTTP(w, cancelReq)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected %d, got %d", http.StatusNotFound, w.Code)
	}
}

// TestCancelClassificationUsesSentinels proves that cancellation
// classification is typed via sentinel errors rather than error-string text.
// The handler classifies with errors.Is; the legacy "not_found" and
// "already_terminal" strings must no longer be relied upon.
func TestCancelClassificationUsesSentinels(t *testing.T) {
	sup := newOperationSupervisor()

	// Missing operation -> ErrOperationNotFound.
	err := sup.cancel("op_missing", nil)
	if !errors.Is(err, ErrOperationNotFound) {
		t.Fatalf("cancel(missing) = %v, want ErrOperationNotFound", err)
	}
	if err.Error() == "not_found" {
		t.Error("classification must not depend on the legacy 'not_found' error string")
	}

	// Terminal operation -> ErrOperationAlreadyTerminal.
	op := newRunOperation("sess", "img", 4*1024*1024, "", "", "")
	if sup.admit(op) != admissionAccepted {
		t.Fatal("admit failed")
	}
	op.succeed(nil)
	err = sup.cancel(op.ID, nil)
	if !errors.Is(err, ErrOperationAlreadyTerminal) {
		t.Fatalf("cancel(terminal) = %v, want ErrOperationAlreadyTerminal", err)
	}
	if err.Error() == "already_terminal" {
		t.Error("classification must not depend on the legacy 'already_terminal' error string")
	}
}

// TestCancelIdempotent proves that cancelling an already-cancelled legacy
// operation returns the terminal state without error.
func TestCancelIdempotent(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newRunOperation(result.Session.ID, "example:test", 4*1024*1024, "", "", "")
	if app.OperationSupervisor.admit(op) != admissionAccepted {
		t.Fatal("admit failed")
	}

	cmd := exec.Command("sleep", "300")
	if res := startOperationProcess(cmd, op); res.Terminated || res.Err != nil {
		t.Fatalf("start operation: terminated=%v err=%v", res.Terminated, res.Err)
	}
	go func() {
		cmd.Wait()
		op.mu.Lock()
		reason := op.reason
		op.mu.Unlock()
		if reason == terminationCancelled {
			op.fail(resultCancelled, "run cancelled", nil, nil)
		} else {
			op.fail("docker_run_failed", "docker run failed", nil, nil)
		}
	}()

	mux := newOperationMux(app)

	// First cancel.
	cancelReq := httptest.NewRequest("POST", "/operations/"+op.ID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	mux.ServeHTTP(cancelW, cancelReq)
	if cancelW.Code != http.StatusOK {
		t.Fatalf("first cancel: expected %d, got %d", http.StatusOK, cancelW.Code)
	}

	select {
	case <-op.done:
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not complete after cancel")
	}

	// Second cancel (idempotent).
	cancelReq2 := httptest.NewRequest("POST", "/operations/"+op.ID+"/cancel", nil)
	cancelReq2.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW2 := httptest.NewRecorder()
	mux.ServeHTTP(cancelW2, cancelReq2)

	if cancelW2.Code != http.StatusOK {
		t.Fatalf("second cancel: expected %d, got %d", http.StatusOK, cancelW2.Code)
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

// TestShutdownDoesNotProduceCancelledResult proves that daemon shutdown
// does not produce result_code=cancelled for a running legacy operation:
// the shutdown reason classifies to the natural backend failure result.
func TestShutdownDoesNotProduceCancelledResult(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newRunOperation(result.Session.ID, "example:test", 4*1024*1024, "", "", "")
	if app.OperationSupervisor.admit(op) != admissionAccepted {
		t.Fatal("admit failed")
	}

	cmd := exec.Command("sleep", "300")
	if res := startOperationProcess(cmd, op); res.Terminated || res.Err != nil {
		t.Fatalf("start operation: terminated=%v err=%v", res.Terminated, res.Err)
	}
	go func() {
		cmd.Wait()
		op.mu.Lock()
		reason := op.reason
		op.mu.Unlock()
		if reason == terminationCancelled {
			op.fail(resultCancelled, "run cancelled", nil, nil)
		} else {
			op.fail("docker_run_failed", "docker run failed", nil, nil)
		}
	}()

	// Simulate daemon shutdown by calling terminateForShutdown directly.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	app.OperationSupervisor.terminateForShutdown(ctx, app.killContainerBestEffort)

	// Wait for the operation to complete.
	select {
	case <-op.done:
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not complete after shutdown")
	}

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
// cancel acquires op.mu and sets reason, then terminateForShutdown runs.
func TestTerminationReasonOwnershipCancelFirst(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newRunOperation(result.Session.ID, "test:image", 4*1024*1024, "", "", "")
	app.OperationSupervisor.mu.Lock()
	app.OperationSupervisor.ops[op.ID] = op
	app.OperationSupervisor.mu.Unlock()

	// Barrier: terminateForShutdown waits until cancel has completed.
	cancelDone := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: explicit cancel (runs first).
	go func() {
		defer wg.Done()
		_ = app.OperationSupervisor.cancel(op.ID, app.killContainerBestEffort)
		close(cancelDone)
	}()

	// Goroutine 2: shutdown (waits for cancel to finish).
	go func() {
		defer wg.Done()
		<-cancelDone
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		app.OperationSupervisor.terminateForShutdown(ctx, app.killContainerBestEffort)
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
// terminateForShutdown acquires op.mu and sets reason, then cancel runs.
func TestTerminationReasonOwnershipShutdownFirst(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newRunOperation(result.Session.ID, "test:image", 4*1024*1024, "", "", "")
	app.OperationSupervisor.mu.Lock()
	app.OperationSupervisor.ops[op.ID] = op
	app.OperationSupervisor.mu.Unlock()

	// Barrier: cancel waits until terminateForShutdown has completed.
	shutdownDone := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: shutdown (runs first).
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		app.OperationSupervisor.terminateForShutdown(ctx, app.killContainerBestEffort)
		close(shutdownDone)
	}()

	// Goroutine 2: explicit cancel (waits for shutdown to finish).
	go func() {
		defer wg.Done()
		<-shutdownDone
		_ = app.OperationSupervisor.cancel(op.ID, app.killContainerBestEffort)
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

	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newRunOperation(result.Session.ID, "test:image", 4*1024*1024, "", "", "")

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
		failResult = op.fail("cancelled", "run cancelled", &exitCode, nil)
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
		if r.Event == "run.finish" {
			finishCount++
		}
	}
	if finishCount != 1 {
		t.Errorf("run.finish audit count = %d, want 1", finishCount)
	}
}

// TestTerminalTransitionFailWins proves the single-terminal-transition
// invariant at the primitive level: when fail() transitions first,
// a subsequent succeed() cannot overwrite the result.
// A channel barrier fixes the ordering: fail() runs first, then succeed().
func TestTerminalTransitionFailWins(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newRunOperation(result.Session.ID, "test:image", 4*1024*1024, "", "", "")

	// Barrier: succeed waits until fail has completed the transition.
	failDone := make(chan struct{})

	var succeedResult, failResult bool
	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine 1: fail (runs first).
	go func() {
		defer wg.Done()
		exitCode := 1
		failResult = op.fail("cancelled", "run cancelled", &exitCode, nil)
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
		if r.Event == "run.finish" {
			finishCount++
		}
	}
	if finishCount != 1 {
		t.Errorf("run.finish audit count = %d, want 1", finishCount)
	}
}

// TestCancelAfterNaturalCompletionPreservesResult proves that when the
// legacy operation completes naturally before cancel processes it, the
// natural result is preserved (sequential idempotency).
func TestCancelAfterNaturalCompletionPreservesResult(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newRunOperation(result.Session.ID, "example:test", 4*1024*1024, "", "", "")
	if app.OperationSupervisor.admit(op) != admissionAccepted {
		t.Fatal("admit failed")
	}

	// Complete immediately with exit 0 (success).
	cmd := exec.Command("true")
	if res := startOperationProcess(cmd, op); res.Terminated || res.Err != nil {
		t.Fatalf("start operation: terminated=%v err=%v", res.Terminated, res.Err)
	}
	go func() {
		cmd.Wait()
		op.succeed(nil)
	}()

	// Wait for natural completion to finish.
	select {
	case <-op.done:
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not complete")
	}

	// Now attempt cancel — it should see the operation is already terminal.
	cancelReq := httptest.NewRequest("POST", "/operations/"+op.ID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	newOperationMux(app).ServeHTTP(cancelW, cancelReq)
	if cancelW.Code != http.StatusOK {
		t.Fatalf("cancel: expected %d, got %d", http.StatusOK, cancelW.Code)
	}

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

// TestCancelAfterNaturalFailurePreservesResult proves that cancelling an
// operation that already completed with a natural failure result does not
// overwrite the result to "cancelled".
func TestCancelAfterNaturalFailurePreservesResult(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Register an already-terminal build operation with a natural failure.
	op := newRunOperation(result.Session.ID, "test:image", 4*1024*1024, "", "", "")
	op.fail("docker_run_failed", "run failed", nil)
	app.OperationSupervisor.mu.Lock()
	app.OperationSupervisor.ops[op.ID] = op
	app.OperationSupervisor.mu.Unlock()

	// Cancel the already-terminal operation.
	cancelReq := httptest.NewRequest("POST", "/operations/"+op.ID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	newOperationMux(app).ServeHTTP(cancelW, cancelReq)

	if cancelW.Code != http.StatusOK {
		t.Fatalf("cancel: expected %d, got %d", http.StatusOK, cancelW.Code)
	}

	var cancelResp map[string]any
	json.NewDecoder(cancelW.Body).Decode(&cancelResp)
	if cancelResp["result_code"] != "docker_run_failed" {
		t.Errorf("expected result_code 'docker_build_failed', got %v", cancelResp["result_code"])
	}

	// Verify stored result is unchanged.
	op.mu.Lock()
	rc := ""
	if op.ResultCode != nil {
		rc = *op.ResultCode
	}
	op.mu.Unlock()

	if rc != "docker_run_failed" {
		t.Errorf("stored result_code = %q, want 'docker_build_failed'", rc)
	}
}

// TestConcurrentDoubleCancel proves that two simultaneous cancel requests
// for the same running legacy operation produce exactly one terminal
// transition and one finish audit. Both requests complete without error.
func TestConcurrentDoubleCancel(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newRunOperation(result.Session.ID, "example:test", 4*1024*1024, "", "", "")
	if app.OperationSupervisor.admit(op) != admissionAccepted {
		t.Fatal("admit failed")
	}

	cmd := exec.Command("sleep", "300")
	if res := startOperationProcess(cmd, op); res.Terminated || res.Err != nil {
		t.Fatalf("start operation: terminated=%v err=%v", res.Terminated, res.Err)
	}
	go func() {
		cmd.Wait()
		op.mu.Lock()
		reason := op.reason
		op.mu.Unlock()
		if reason == terminationCancelled {
			op.fail(resultCancelled, "run cancelled", nil, nil)
		} else {
			op.fail("docker_run_failed", "docker run failed", nil, nil)
		}
	}()

	// Launch two cancel requests concurrently.
	var wg sync.WaitGroup
	wg.Add(2)

	var cancelW1, cancelW2 *httptest.ResponseRecorder
	var cancelReq1, cancelReq2 *http.Request

	cancelReq1 = httptest.NewRequest("POST", "/operations/"+op.ID+"/cancel", nil)
	cancelReq1.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW1 = httptest.NewRecorder()

	cancelReq2 = httptest.NewRequest("POST", "/operations/"+op.ID+"/cancel", nil)
	cancelReq2.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW2 = httptest.NewRecorder()

	start := make(chan struct{})

	go func() {
		defer wg.Done()
		<-start
		newOperationMux(app).ServeHTTP(cancelW1, cancelReq1)
	}()

	go func() {
		defer wg.Done()
		<-start
		newOperationMux(app).ServeHTTP(cancelW2, cancelReq2)
	}()

	close(start)
	wg.Wait()

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
		if r.Event == "run.finish" {
			finishCount++
		}
	}
	if finishCount != 1 {
		t.Errorf("run.finish audit count = %d, want 1", finishCount)
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

	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
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
	op := newRunOperation(result.Session.ID, "test:image", 4*1024*1024, "", "", "")
	op.cidfile = cidfile
	op.started = true // simulate already-started process
	app.OperationSupervisor.mu.Lock()
	app.OperationSupervisor.ops[op.ID] = op
	app.OperationSupervisor.mu.Unlock()

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
	readyFile := filepath.Join(t.TempDir(), "proc.ready")
	cmd := exec.Command("sh", "-c", "trap ':' TERM; touch "+readyFile+"; while :; do :; done")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start test process: %v", err)
	}
	op.cmd = cmd

	// Verify the process is running.
	if cmd.Process == nil {
		t.Fatal("process not started")
	}
	t.Logf("test process PID: %d", cmd.Process.Pid)

	// Wait for the process to install its SIGTERM trap.
	waitProcessReady(t, readyFile)

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
		app.OperationSupervisor.cancel(op.ID, fakeKillContainer)
	}()

	go func() {
		defer wg.Done()
		<-start
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		app.OperationSupervisor.terminateForShutdown(ctx, fakeKillContainer)
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
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Create a run operation with force cleanup already claimed by an owner.
	op := newRunOperation(result.Session.ID, "test:image", 4*1024*1024, "", "", "")
	op.started = true
	op.forceOwned = true
	op.forceDone = make(chan struct{})
	op.forceDeadline = time.Now().Add(200 * time.Millisecond)
	app.OperationSupervisor.mu.Lock()
	app.OperationSupervisor.ops[op.ID] = op
	app.OperationSupervisor.mu.Unlock()

	// Start a long-running process that survives SIGTERM so the follower
	// reaches the force phase. The owner is simulated (already claimed).
	readyFile := filepath.Join(t.TempDir(), "proc.ready")
	cmd := exec.Command("sh", "-c", "trap ':' TERM; touch "+readyFile+"; while :; do :; done")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cannot start test process: %v", err)
	}
	op.cmd = cmd

	// Wait for the process to install its SIGTERM trap.
	waitProcessReady(t, readyFile)

	// Completion goroutine (mimics real handler).
	go func() {
		cmd.Wait()
		exitCode := 137
		op.fail("docker_run_failed", "docker run failed", &exitCode, nil)
	}()

	// Launch the follower via terminateForShutdown with a short context deadline.
	// With the bounded shutdown model, the force deadline is the context
	// deadline (50ms), not a fresh defaultForceCleanupTimeout.
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	app.OperationSupervisor.terminateForShutdown(ctx, func(context.Context, string) {})
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
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	op := newRunOperation(result.Session.ID, "alpine:3.24", 4*1024*1024, "", "", "")
	if app.OperationSupervisor.admit(op) != admissionAccepted {
		t.Fatal("admit failed")
	}
	op.succeed(nil)

	// Cancel the already-completed operation.
	cancelReq := httptest.NewRequest("POST", "/operations/"+op.ID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	newOperationMux(app).ServeHTTP(w, cancelReq)

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
	if cancelResp["operation_id"] != op.ID {
		t.Errorf("expected operation_id=%s, got %v", op.ID, cancelResp["operation_id"])
	}
	if cancelResp["status"] != "succeeded" {
		t.Errorf("expected status=succeeded, got %v", cancelResp["status"])
	}
}
