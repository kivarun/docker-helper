package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRunWorkdirPassedToDocker(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.RunCommand = func(name string, args ...string) ([]byte, error) {
		capturedArgs = args
		return []byte("ok"), nil
	}

	reqBody := map[string]any{
		"image":   "alpine:latest",
		"workdir": "/workspace",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	found := false
	for i, arg := range capturedArgs {
		if arg == "--workdir" && i+1 < len(capturedArgs) && capturedArgs[i+1] == "/workspace" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected --workdir /workspace in docker args, got %v", capturedArgs)
	}
}

func TestRunNoWorkdir(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.RunCommand = func(name string, args ...string) ([]byte, error) {
		capturedArgs = args
		return []byte("ok"), nil
	}

	reqBody := map[string]string{
		"image": "alpine:latest",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	for _, arg := range capturedArgs {
		if arg == "--workdir" {
			t.Errorf("expected no --workdir in docker args, got %v", capturedArgs)
			break
		}
	}
}

func TestRunRelativeWorkdirRejected(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
		t.Fatal("RunCommand should not be called for relative workdir")
		return nil, nil
	}

	reqBody := map[string]any{
		"image":   "alpine:latest",
		"workdir": "relative/path",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.Code != "invalid_workdir" {
		t.Errorf("expected code 'invalid_workdir', got %q", resp.Code)
	}
}
