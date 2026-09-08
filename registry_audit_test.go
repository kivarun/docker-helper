package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegistryLoginAuditStartFinish(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, _ := newTestAppWithEngineAuth(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	w := postRegistryLogin(t, app, result.Token, map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	})

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

	app, _ := newTestAppWithEngineAuth(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	adapterCalled := false
	app.NewEngineClientFn = func() (engineRegistryAuthenticator, error) {
		adapterCalled = true
		return &fakeEngineAuth{}, nil
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

	if adapterCalled {
		t.Error("the engine adapter must not be constructed when registry starts with '-'")
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

	app, fake := newTestAppWithEngineAuth(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const secretPassword = "super-secret-password-12345"

	// Use failure path so the operational logger actually writes.
	fake.err = &engineError{kind: engineErrBackendFailure, cause: errors.New("engine failure")}

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

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected %d, got %d", http.StatusBadGateway, w.Code)
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

	app, fake := newTestAppWithEngineAuth(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const secretUsername = "secret-username-12345"

	// Use failure path so the operational logger actually writes.
	fake.err = &engineError{kind: engineErrBackendFailure, cause: errors.New("engine failure")}

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

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected %d, got %d", http.StatusBadGateway, w.Code)
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

func TestRegistryLoginRawEnginePayloadNotLogged(t *testing.T) {
	_, opBuf := setupTestLogging(t)

	app, fake := newTestAppWithEngineAuth(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const rawBackendMarker = "RAW-ENGINE-PAYLOAD-MUST-NOT-REACH-JOURNAL"
	fake.err = &engineError{kind: engineErrBackendFailure, cause: errors.New(rawBackendMarker)}

	w := postRegistryLogin(t, app, result.Token, map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	})
	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected %d, got %d", http.StatusBadGateway, w.Code)
	}
	if strings.Contains(opBuf.String(), rawBackendMarker) {
		t.Fatalf("operational log contains raw Engine payload:\n%s", opBuf.String())
	}
}

func TestRegistryLoginAuditFinishOnEngineConstructionFailure(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)

	app, _ := newTestAppWithEngineAuth(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const rawConstructorMarker = "RAW-ENGINE-CONSTRUCTOR-DETAIL"
	app.NewEngineClientFn = func() (engineRegistryAuthenticator, error) {
		return nil, errors.New(rawConstructorMarker)
	}

	w := postRegistryLogin(t, app, result.Token, map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected %d, got %d", http.StatusInternalServerError, w.Code)
	}
	if strings.Contains(opBuf.String(), rawConstructorMarker) {
		t.Fatalf("operational log contains raw Engine constructor detail:\n%s", opBuf.String())
	}

	assertRegistryLoginAuditPair(t, auditBuf, result.Session.ID, "registry.example.com", "login_failed")
}

func TestRegistryLoginAuditFinishOnCredentialStoreFailure(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, _ := newTestAppWithEngineAuth(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerDir, err := ensureSessionDockerDir(app.Config.RuntimeDir, result.Session.ID)
	if err != nil {
		t.Fatalf("ensure Docker dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dockerDir, "config.json"), []byte("{"), 0600); err != nil {
		t.Fatalf("seed malformed config: %v", err)
	}

	w := postRegistryLogin(t, app, result.Token, map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	})
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected %d, got %d", http.StatusInternalServerError, w.Code)
	}

	assertRegistryLoginAuditPair(t, auditBuf, result.Session.ID, "registry.example.com", "login_failed")
}

func assertRegistryLoginAuditPair(t *testing.T, auditBuf *bytes.Buffer, sessionID, registry, result string) {
	t.Helper()

	records := parseAuditRecords(auditBuf)
	var starts, finishes int
	for _, rec := range records {
		switch rec.Event {
		case "registry.login.start":
			starts++
			if rec.SessionID != sessionID || rec.Registry != registry {
				t.Fatalf("unexpected start audit: %+v", rec)
			}
		case "registry.login.finish":
			finishes++
			if rec.SessionID != sessionID || rec.Registry != registry || rec.Result != result || rec.Duration == "" {
				t.Fatalf("unexpected finish audit: %+v", rec)
			}
		}
	}
	if starts != 1 || finishes != 1 {
		t.Fatalf("expected exactly one start/finish pair, got starts=%d finishes=%d", starts, finishes)
	}
}
