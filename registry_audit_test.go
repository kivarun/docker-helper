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

	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
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

func TestRegistryLoginRegistryHyphenRejected(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	execCalled := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		execCalled = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{
		"registry": "-v",
		"username": "user",
		"password": "secret",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRegistryLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if resp["code"] != "invalid_registry_login" {
		t.Errorf("expected code 'invalid_registry_login', got %v", resp["code"])
	}

	if execCalled {
		t.Error("ExecCommandContext must not be called when registry starts with '-'")
	}

	records := parseAuditRecords(auditBuf)
	for _, rec := range records {
		if rec.Event == "registry.login.start" || rec.Event == "registry.login.finish" {
			t.Errorf("registry login audit event must not appear: %s", rec.Event)
		}
	}
}

func TestRegistryLoginAuditPasswordNotLogged(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const secretPassword = "super-secret-password-12345"

	// Use failure path so the operational logger actually writes.
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 1")
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

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}

	auditOutput := auditBuf.String()
	if strings.Contains(auditOutput, secretPassword) {
		t.Fatalf("audit must not contain password:\n%s", auditOutput)
	}

	opOutput := opBuf.String()
	if strings.Contains(opOutput, secretPassword) {
		t.Fatalf("operational log must not contain password:\n%s", opOutput)
	}
}

func TestRegistryLoginAuditUsernameNotLogged(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const secretUsername = "secret-username-12345"

	// Use failure path so the operational logger actually writes.
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 1")
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

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}

	auditOutput := auditBuf.String()
	if strings.Contains(auditOutput, secretUsername) {
		t.Fatalf("audit must not contain username:\n%s", auditOutput)
	}

	opOutput := opBuf.String()
	if strings.Contains(opOutput, secretUsername) {
		t.Fatalf("operational log must not contain username:\n%s", opOutput)
	}
}
