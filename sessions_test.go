package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestAppWithDB(t *testing.T) *App {
	t.Helper()
	app := newTestApp(t)
	return app
}

func TestHTTPCreateSession(t *testing.T) {
	app := newTestAppWithDB(t)

	reqBody := map[string]string{"workspace": app.Config.AllowedRoot}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
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
	app := newTestAppWithDB(t)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()

	app.handleCreateSession(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHTTPCreateSessionMissingWorkspace(t *testing.T) {
	app := newTestAppWithDB(t)

	reqBody := map[string]string{}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handleCreateSession(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHTTPListSessions(t *testing.T) {
	app := newTestAppWithDB(t)

	_, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
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
	app := newTestAppWithDB(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/sessions/"+result.Session.ID, nil)
	w := httptest.NewRecorder()

	app.handleDeleteSession(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
	}
}

func TestHTTPDeleteSessionNotFound(t *testing.T) {
	app := newTestAppWithDB(t)

	req := httptest.NewRequest(http.MethodDelete, "/sessions/dhs_nonexistent", nil)
	w := httptest.NewRecorder()

	app.handleDeleteSession(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestHTTPCreateSessionRFC3339(t *testing.T) {
	app := newTestAppWithDB(t)

	reqBody := map[string]string{"workspace": app.Config.AllowedRoot}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
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
