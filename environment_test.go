package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

func TestRunEnvironmentSingleVar(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"KEY": "value",
		},
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
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	found := false
	for i, arg := range capturedArgs {
		if arg == "--env" && i+1 < len(capturedArgs) && capturedArgs[i+1] == "KEY=value" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected --env KEY=value in args %v", capturedArgs)
	}
}

func TestRunEnvironmentMultipleVars(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"A": "1",
			"B": "2",
		},
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
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	envCount := 0
	for _, arg := range capturedArgs {
		if arg == "--env" {
			envCount++
		}
	}

	if envCount != 2 {
		t.Errorf("expected 2 --env flags, got %d", envCount)
	}
}

func TestRunEnvironmentEmptyValue(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"FLAG": "",
		},
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
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	found := false
	for i, arg := range capturedArgs {
		if arg == "--env" && i+1 < len(capturedArgs) && capturedArgs[i+1] == "FLAG=" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected --env FLAG= in args %v", capturedArgs)
	}
}

func TestRunEnvironmentInvalidName(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"INVALID-NAME": "value",
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestRunEnvironmentNameStartsWithDigit(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"1NAME": "value",
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestRunEnvironmentNameWithSpace(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"NAME WITH SPACE": "value",
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestRunEnvironmentNameWithDash(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"NAME-DASH": "value",
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestRunEnvironmentDockerArgsOrder(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]any{
		"image":       "alpine:latest",
		"entrypoint":  "/bin/sh",
		"command":     []string{"-c", "echo hello"},
		"environment": map[string]string{"KEY": "value"},
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
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	// --config is first, then --cidfile is inserted after --user, before other options.
	dockerDir := sessionDockerDir(app.Config.RuntimeDir, result.Session.ID)
	baseArgs := []string{"--config", dockerDir, "run", "--rm", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--security-opt", "label=disable"}
	for i, expected := range baseArgs {
		if capturedArgs[i] != expected {
			t.Fatalf("arg[%d]: expected %q, got %q", i, expected, capturedArgs[i])
		}
	}
	if len(capturedArgs) < 8 || capturedArgs[8] != "--cidfile" {
		t.Fatalf("expected --cidfile at arg[8], got %v", capturedArgs)
	}
	if len(capturedArgs) < 9 || capturedArgs[9] == "" {
		t.Fatalf("expected cidfile path at arg[9], got %v", capturedArgs)
	}
	// Skip the cidfile args for the rest of the comparison.
	remainingArgs := capturedArgs[10:]
	expectedRemaining := []string{"--entrypoint", "/bin/sh", "--env", "KEY=value", "alpine:latest", "-c", "echo hello"}
	if len(remainingArgs) != len(expectedRemaining) {
		t.Fatalf("expected %d remaining args, got %d: %v", len(expectedRemaining), len(remainingArgs), remainingArgs)
	}

	for i, expected := range expectedRemaining {
		if remainingArgs[i] != expected {
			t.Errorf("remaining arg[%d]: expected %q, got %q", i, expected, remainingArgs[i])
		}
	}
}
