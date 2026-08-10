package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

func TestRegistryLoginAuditStartFinish(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRegistryLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	records := parseAuditRecords(auditBuf)
	var startRec, finishRec *auditRecord
	for i := range records {
		if records[i].Event == "registry.login.start" {
			startRec = &records[i]
		}
		if records[i].Event == "registry.login.finish" {
			finishRec = &records[i]
		}
	}

	if startRec == nil {
		t.Fatal("registry.login.start audit not found")
	}
	if startRec.SessionID != result.Session.ID {
		t.Errorf("start session_id: expected %q, got %q", result.Session.ID, startRec.SessionID)
	}
	if startRec.Registry != "registry.example.com" {
		t.Errorf("start registry: expected 'registry.example.com', got %q", startRec.Registry)
	}

	if finishRec == nil {
		t.Fatal("registry.login.finish audit not found")
	}
	if finishRec.SessionID != result.Session.ID {
		t.Errorf("finish session_id: expected %q, got %q", result.Session.ID, finishRec.SessionID)
	}
	if finishRec.Registry != "registry.example.com" {
		t.Errorf("finish registry: expected 'registry.example.com', got %q", finishRec.Registry)
	}
	if finishRec.Result != "success" {
		t.Errorf("finish result: expected 'success', got %q", finishRec.Result)
	}
	if finishRec.Duration == "" {
		t.Error("finish duration should be set")
	}
}

func TestRegistryLoginAuditPasswordNotLogged(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const secretPassword = "super-secret-password-12345"

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": secretPassword,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRegistryLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	output := auditBuf.String()
	if strings.Contains(output, secretPassword) {
		t.Fatalf("audit must not contain password!\n%s", output)
	}

	// Also verify operational logs don't contain it
	// (They go to stderr in tests, but we check the audit buffer)
}

func TestRegistryLoginAuditUsernameNotLogged(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const secretUsername = "secret-username-12345"

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"registry": "registry.example.com",
		"username": secretUsername,
		"password": "secret",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRegistryLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	output := auditBuf.String()
	// Username is not in audit fields, so it should not appear
	if strings.Contains(output, secretUsername) {
		t.Fatalf("audit must not contain username!\n%s", output)
	}
}
