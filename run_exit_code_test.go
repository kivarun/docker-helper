package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
)

type mockExitError struct {
	code int
	msg  string
}

func (e *mockExitError) Error() string { return e.msg }
func (e *mockExitError) ExitCode() int { return e.code }
func (e *mockExitError) Unwrap() error { return nil }

func TestRunNonZeroExit(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf 'container output\n'; exit 7")
	}

	reqBody := map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sh", "-c", "exit 7"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
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
	if op.ResultCode == nil || *op.ResultCode != "container_exit_nonzero" {
		t.Errorf("expected result_code 'container_exit_nonzero', got %v", op.ResultCode)
	}
	if op.ExitCode == nil {
		t.Fatal("expected exit_code to be set")
	}
	if *op.ExitCode != 7 {
		t.Errorf("expected exit_code 7, got %d", *op.ExitCode)
	}
	if op.Duration == nil || *op.Duration == "" {
		t.Error("expected duration to be set")
	}

	// Check operation logs for output.
	logsReq := httptest.NewRequest(http.MethodGet, "/operations/"+opID+"/logs", nil)
	logsReq.SetPathValue("id", opID)
	logsReq.Header.Set("Authorization", "Bearer "+result.Token)
	logsW := httptest.NewRecorder()
	app.handleOperationLogs(logsW, logsReq)

	if logsW.Code != http.StatusOK {
		t.Fatalf("expected 200 from operation logs, got %d", logsW.Code)
	}

	var logsResp map[string]any
	if err := json.NewDecoder(logsW.Body).Decode(&logsResp); err != nil {
		t.Fatalf("decode operation logs: %v", err)
	}
	logs, _ := logsResp["logs"].(string)
	if logs != "container output\n" {
		t.Errorf("expected output 'container output\\n', got %q", logs)
	}
}

func TestRunNonZeroExitCodeZero(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"image": "alpine:latest",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
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

	if op.State != operationSucceeded {
		t.Errorf("expected status 'succeeded', got %q", op.State)
	}
}

func TestRunDockerErrorStill500(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%s' 'docker: not found\\n'; exit 125")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
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
	if op.ResultCode == nil || *op.ResultCode != "docker_run_failed" {
		t.Errorf("expected result_code 'docker_run_failed', got %v", op.ResultCode)
	}
	// Exit code 125 is set for docker errors.
	if op.ExitCode == nil || *op.ExitCode != 125 {
		t.Errorf("expected exit_code 125 for docker error, got %v", op.ExitCode)
	}
}

func TestRunSuccessNoExitCode(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
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

	if op.State != operationSucceeded {
		t.Errorf("expected status 'succeeded', got %q", op.State)
	}
	if op.ExitCode != nil {
		t.Errorf("expected no exit_code for success, got %d", *op.ExitCode)
	}
}

func TestExtractExitCode(t *testing.T) {
	err := &mockExitError{code: 42, msg: "test"}
	code := extractExitCode(err)
	if code == nil {
		t.Fatal("expected exit code to be extracted")
	}
	if *code != 42 {
		t.Errorf("expected 42, got %d", *code)
	}
}

func TestExtractExitCodeNil(t *testing.T) {
	err := errors.New("plain error")
	code := extractExitCode(err)
	if code != nil {
		t.Errorf("expected nil, got %d", *code)
	}
}

func TestRunNonZeroExitCode125(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%s' 'image not found\\n'; exit 125")
	}

	reqBody := map[string]any{
		"image": "nonexistent:latest",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
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
	if op.ResultCode == nil || *op.ResultCode != "docker_run_failed" {
		t.Errorf("expected result_code 'docker_run_failed', got %v", op.ResultCode)
	}
}
