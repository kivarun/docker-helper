package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"
)

func TestHTTPCreateSession(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	reqBody := map[string]string{"workspace": testWorkspaceDir(t, app.Config.AllowedRoots[0])}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	withAdminToken(req)
	w := httptest.NewRecorder()

	app.handleCreateSession(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if !resp.OK {
		t.Error("expected ok to be true")
	}
	if resp.Session.ID == "" {
		t.Error("session ID should not be empty")
	}
	if resp.Token == "" {
		t.Error("token should not be empty")
	}
}

func TestHTTPCreateSessionInvalidJSON(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte("invalid")))
	withAdminToken(req)
	w := httptest.NewRecorder()

	app.handleCreateSession(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHTTPCreateSessionMissingWorkspace(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	reqBody := map[string]string{}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	withAdminToken(req)
	w := httptest.NewRecorder()

	app.handleCreateSession(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHTTPListSessions(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	_, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	withAdminToken(req)
	w := httptest.NewRecorder()

	app.handleListSessions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp listSessionsResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if !resp.OK {
		t.Error("expected ok to be true")
	}
	if len(resp.Sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(resp.Sessions))
	}
}

func TestHTTPDeleteSession(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /sessions/{id}", withRequestID(withLogging(app.handleDeleteSession)))

	req := httptest.NewRequest(http.MethodDelete, "/sessions/"+result.Session.ID, nil)
	withAdminToken(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
	}
}

func TestHTTPDeleteSessionNotFound(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /sessions/{id}", withRequestID(withLogging(app.handleDeleteSession)))

	req := httptest.NewRequest(http.MethodDelete, "/sessions/dhs_nonexistent", nil)
	withAdminToken(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestHTTPCreateSessionRFC3339(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	reqBody := map[string]string{"workspace": testWorkspaceDir(t, app.Config.AllowedRoots[0])}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	withAdminToken(req)
	w := httptest.NewRecorder()

	app.handleCreateSession(w, req)

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if _, err := time.Parse(time.RFC3339, resp.Session.CreatedAt); err != nil {
		t.Errorf("created_at is not RFC3339: %v", err)
	}

	if _, err := time.Parse(time.RFC3339, resp.Session.ExpiresAt); err != nil {
		t.Errorf("expires_at is not RFC3339: %v", err)
	}
}

func TestIntersectAllowedRootScopes_GlobalInsidePrincipal(t *testing.T) {
	// global = /root/project, principal = /root
	// effective should be /root/project
	global := []string{"/root/project"}
	principal := []string{"/root"}
	result := intersectAllowedRootScopes(global, principal)
	if len(result) != 1 || result[0] != "/root/project" {
		t.Errorf("expected [/root/project], got %v", result)
	}
}

func TestIntersectAllowedRootScopes_PrincipalInsideGlobal(t *testing.T) {
	// global = /root, principal = /root/project
	// effective should be /root/project
	global := []string{"/root"}
	principal := []string{"/root/project"}
	result := intersectAllowedRootScopes(global, principal)
	if len(result) != 1 || result[0] != "/root/project" {
		t.Errorf("expected [/root/project], got %v", result)
	}
}

func TestIntersectAllowedRootScopes_Equal(t *testing.T) {
	global := []string{"/root/project"}
	principal := []string{"/root/project"}
	result := intersectAllowedRootScopes(global, principal)
	if len(result) != 1 || result[0] != "/root/project" {
		t.Errorf("expected [/root/project], got %v", result)
	}
}

func TestIntersectAllowedRootScopes_Disjoint(t *testing.T) {
	global := []string{"/a"}
	principal := []string{"/b"}
	result := intersectAllowedRootScopes(global, principal)
	if len(result) != 0 {
		t.Errorf("expected [], got %v", result)
	}
}

func TestIntersectAllowedRootScopes_NoDuplicates(t *testing.T) {
	// Two principal roots both contain the same global root
	global := []string{"/root/project"}
	principal := []string{"/root", "/root/parent"}
	result := intersectAllowedRootScopes(global, principal)
	sort.Strings(result)
	if len(result) != 1 || result[0] != "/root/project" {
		t.Errorf("expected [/root/project], got %v", result)
	}
}
