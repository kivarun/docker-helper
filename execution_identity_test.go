package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacySessionUsesDaemonUIDGID(t *testing.T) {
	app := newTestAppWithAuth(t)

	// Create admin session (principal_id = NULL).
	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	uid, gid, err := resolveSessionExecutionIdentity(app.DB, &result.Session)
	if err != nil {
		t.Fatalf("resolveSessionExecutionIdentity() error: %v", err)
	}

	daemonUID := os.Getuid()
	daemonGID := os.Getgid()
	if uid != daemonUID {
		t.Errorf("UID = %d, want %d (daemon UID)", uid, daemonUID)
	}
	if gid != daemonGID {
		t.Errorf("GID = %d, want %d (daemon GID)", gid, daemonGID)
	}
}

func TestPrincipalSessionUsesPrincipalUIDGID(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "execuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "2001", "2001", home, nil
	}

	if _, err := createPrincipal(app.DB, "execuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	_, token, err := createCredential(app.DB, "execuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	// Resolve identity for the principal session.
	session, err := app.findSessionByToken(resp.Token)
	if err != nil {
		t.Fatalf("findSessionByToken() error: %v", err)
	}

	uid, gid, err := resolveSessionExecutionIdentity(app.DB, session)
	if err != nil {
		t.Fatalf("resolveSessionExecutionIdentity() error: %v", err)
	}

	if uid != 2001 {
		t.Errorf("UID = %d, want 2001", uid)
	}
	if gid != 2001 {
		t.Errorf("GID = %d, want 2001", gid)
	}
}

func TestDifferentPrincipalsDifferentUIDGID(t *testing.T) {
	app := newTestAppWithAuth(t)

	home1 := filepath.Join(app.Config.AllowedRoots[0], "home", "diffuser1")
	home2 := filepath.Join(app.Config.AllowedRoots[0], "home", "diffuser2")
	if err := os.MkdirAll(filepath.Join(home1, "proj"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home2, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		switch username {
		case "diffuser1":
			return "3001", "3001", home1, nil
		case "diffuser2":
			return "3002", "3002", home2, nil
		}
		return "", "", "", fmt.Errorf("not found")
	}

	if _, err := createPrincipal(app.DB, "diffuser1", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(diffuser1) error: %v", err)
	}
	if _, err := createPrincipal(app.DB, "diffuser2", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(diffuser2) error: %v", err)
	}

	_, token1, err := createCredential(app.DB, "diffuser1", "oc")
	if err != nil {
		t.Fatalf("createCredential(diffuser1) error: %v", err)
	}
	_, token2, err := createCredential(app.DB, "diffuser2", "oc")
	if err != nil {
		t.Fatalf("createCredential(diffuser2) error: %v", err)
	}

	reqBody1 := map[string]string{"workspace": filepath.Join(home1, "proj")}
	body1, _ := json.Marshal(reqBody1)
	reqBody2 := map[string]string{"workspace": filepath.Join(home2, "proj")}
	body2, _ := json.Marshal(reqBody2)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	// Create session for diffuser1.
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body1))
	req.Header.Set("Authorization", "Bearer "+token1)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("diffuser1 create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp1 createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp1); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	// Create session for diffuser2.
	req = httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body2))
	req.Header.Set("Authorization", "Bearer "+token2)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("diffuser2 create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp2 createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp2); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	// Resolve identities.
	session1, _ := app.findSessionByToken(resp1.Token)
	session2, _ := app.findSessionByToken(resp2.Token)

	uid1, gid1, _ := resolveSessionExecutionIdentity(app.DB, session1)
	uid2, gid2, _ := resolveSessionExecutionIdentity(app.DB, session2)

	if uid1 == uid2 {
		t.Errorf("different principals should have different UIDs: %d == %d", uid1, uid2)
	}
	if gid1 == gid2 {
		t.Errorf("different principals should have different GIDs: %d == %d", gid1, gid2)
	}
}

func TestDisabledPrincipalSessionInvalidated(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "disabledexecuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "4001", "4001", home, nil
	}

	if _, err := createPrincipal(app.DB, "disabledexecuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	_, token, err := createCredential(app.DB, "disabledexecuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	// Disable the principal.
	if _, err := persistPrincipalEnabledChange(app.DB, "disabledexecuser", false); err != nil {
		t.Fatalf("persistPrincipalEnabledChange() error: %v", err)
	}

	// Session should be invalidated after disable.
	_, err = app.findSessionByToken(resp.Token)
	if err == nil {
		t.Fatal("findSessionByToken() should fail after principal disable")
	}
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got: %v", err)
	}
}

func TestRevokedCredentialSessionStillRuns(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "revokedexecuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "5001", "5001", home, nil
	}

	if _, err := createPrincipal(app.DB, "revokedexecuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	cred, token, err := createCredential(app.DB, "revokedexecuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	// Revoke the credential.
	if _, err := revokeCredential(app.DB, cred.ID); err != nil {
		t.Fatalf("revokeCredential() error: %v", err)
	}

	// Session should still be usable.
	session, err := app.findSessionByToken(resp.Token)
	if err != nil {
		t.Fatalf("findSessionByToken() error after revoke: %v", err)
	}

	// Identity resolution should still work.
	uid, gid, err := resolveSessionExecutionIdentity(app.DB, session)
	if err != nil {
		t.Fatalf("resolveSessionExecutionIdentity() error after revoke: %v", err)
	}
	if uid != 5001 {
		t.Errorf("UID = %d, want 5001", uid)
	}
	if gid != 5001 {
		t.Errorf("GID = %d, want 5001", gid)
	}
}

func TestRunRequestRejectsUserField(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions/{id}/run", app.handleRun)

	reqBody := map[string]interface{}{
		"image":   "alpine:latest",
		"command": []string{"echo", "hello"},
		"user":    "0:0",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sessions/"+result.Session.ID+"/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Should be rejected as unknown field.
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

func TestPrincipalIdentityDBError(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "dberruser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "6001", "6001", home, nil
	}

	if _, err := createPrincipal(app.DB, "dberruser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	_, token, err := createCredential(app.DB, "dberruser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	session, err := app.findSessionByToken(resp.Token)
	if err != nil {
		t.Fatalf("findSessionByToken() error: %v", err)
	}

	// Close the DB to simulate a DB error.
	app.DB.Close()

	// Identity resolution should fail.
	_, _, err = resolveSessionExecutionIdentity(app.DB, session)
	if err == nil {
		t.Fatal("expected error for DB failure")
	}
}

func TestPrincipalSessionAuditContainsPrincipalName(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "auditexecuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "7001", "7001", home, nil
	}

	if _, err := createPrincipal(app.DB, "auditexecuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	_, token, err := createCredential(app.DB, "auditexecuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	// Verify the session has the principal name.
	session, err := app.findSessionByToken(resp.Token)
	if err != nil {
		t.Fatalf("findSessionByToken() error: %v", err)
	}
	if session.PrincipalName != "auditexecuser" {
		t.Errorf("PrincipalName = %q, want %q", session.PrincipalName, "auditexecuser")
	}

	// Verify audit contains principal name.
	raw := auditBuf.String()
	if !strings.Contains(raw, "auditexecuser") {
		t.Errorf("audit should contain principal name: %s", raw)
	}
}

func TestResolveSessionExecutionIdentityFromDB(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "fromdbuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "8001", "8001", home, nil
	}

	if _, err := createPrincipal(app.DB, "fromdbuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	_, token, err := createCredential(app.DB, "fromdbuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	session, err := app.findSessionByToken(resp.Token)
	if err != nil {
		t.Fatalf("findSessionByToken() error: %v", err)
	}

	// Change the OS user lookup to return different values.
	// The identity should still come from the DB.
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "9999", "9999", home, nil
	}

	uid, gid, err := resolveSessionExecutionIdentity(app.DB, session)
	if err != nil {
		t.Fatalf("resolveSessionExecutionIdentity() error: %v", err)
	}

	// Should use DB values, not OS lookup.
	if uid != 8001 {
		t.Errorf("UID = %d, want 8001 (from DB)", uid)
	}
	if gid != 8001 {
		t.Errorf("GID = %d, want 8001 (from DB)", gid)
	}
}
