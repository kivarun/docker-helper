package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestRunEnvironmentSingleVar(t *testing.T) {
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

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

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

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

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

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

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

	result, err := app.createSession(app.Config.AllowedRoot)
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

	result, err := app.createSession(app.Config.AllowedRoot)
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

	result, err := app.createSession(app.Config.AllowedRoot)
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

	result, err := app.createSession(app.Config.AllowedRoot)
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

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	expectedOrder := []string{"run", "--rm", "--security-opt", "label=disable", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "--entrypoint", "/bin/sh", "--env", "KEY=value", "alpine:latest", "-c", "echo hello"}
	if len(capturedArgs) != len(expectedOrder) {
		t.Fatalf("expected %d args, got %d: %v", len(expectedOrder), len(capturedArgs), capturedArgs)
	}

	for i, expected := range expectedOrder {
		if capturedArgs[i] != expected {
			t.Errorf("arg[%d]: expected %q, got %q", i, expected, capturedArgs[i])
		}
	}
}
