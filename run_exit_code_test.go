package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("container output\n"), &mockExitError{code: 7, msg: "exit status 7"}
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

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.OK {
		t.Error("expected ok to be false")
	}
	if resp.Code != "container_exit_nonzero" {
		t.Errorf("expected code 'container_exit_nonzero', got %q", resp.Code)
	}
	if resp.Message != "container exited with non-zero status" {
		t.Errorf("expected message 'container exited with non-zero status', got %q", resp.Message)
	}
	if resp.ExitCode == nil {
		t.Fatal("expected exit_code to be set")
	}
	if *resp.ExitCode != 7 {
		t.Errorf("expected exit_code 7, got %d", *resp.ExitCode)
	}
	if resp.Output != "container output\n" {
		t.Errorf("expected output 'container output\\n', got %q", resp.Output)
	}
	if resp.Duration == "" {
		t.Error("expected duration to be set")
	}
}

func TestRunNonZeroExitCodeZero(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), &mockExitError{code: 0, msg: "exit status 0"}
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.OK {
		t.Error("expected ok to be false (exit code 0 is still an error from RunCommand)")
	}
	if resp.Code != "container_exit_nonzero" {
		t.Errorf("expected code 'container_exit_nonzero', got %q", resp.Code)
	}
	if resp.ExitCode == nil {
		t.Fatal("expected exit_code to be set")
	}
	if *resp.ExitCode != 0 {
		t.Errorf("expected exit_code 0, got %d", *resp.ExitCode)
	}
}

func TestRunDockerErrorStill500(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("docker: not found\n"), errors.New("exec: \"docker\": executable file not found in $PATH")
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.OK {
		t.Error("expected ok to be false")
	}
	if resp.Code != "docker_run_failed" {
		t.Errorf("expected code 'docker_run_failed', got %q", resp.Code)
	}
	if resp.ExitCode != nil {
		t.Errorf("expected no exit_code for docker error, got %d", *resp.ExitCode)
	}
}

func TestRunSuccessNoExitCode(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("success"), nil
	}

	reqBody := map[string]any{
		"image": "alpine:latest",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if !resp.OK {
		t.Error("expected ok to be true")
	}
	if resp.ExitCode != nil {
		t.Errorf("expected no exit_code for success, got %d", *resp.ExitCode)
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

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("image not found\n"), &mockExitError{code: 125, msg: "exit status 125"}
	}

	reqBody := map[string]any{
		"image": "nonexistent:latest",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d (docker error 125), got %d", http.StatusInternalServerError, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.OK {
		t.Error("expected ok to be false")
	}
	if resp.Code != "docker_run_failed" {
		t.Errorf("expected code 'docker_run_failed', got %q", resp.Code)
	}
}
