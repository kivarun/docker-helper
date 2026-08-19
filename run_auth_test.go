package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
	"time"
)

func TestRunSessionAuthValidToken(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
	}
}

func TestRunSessionAuthMissingAuthorization(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRunSessionAuthWrongScheme(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRunSessionAuthEmptyBearer(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer ")
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRunSessionAuthInvalidToken(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dht_wrong_token")
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRunSessionAuthExpiredSession(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	_, err = app.DB.Exec("UPDATE sessions SET expires_at = ? WHERE id = ?", time.Now().Add(-time.Hour).Unix(), result.Session.ID)
	if err != nil {
		t.Fatalf("cannot update expires_at: %v", err)
	}

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRunSessionAuthDeletedSession(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	deleted, err := app.deleteSession(result.Session.ID)
	if err != nil {
		t.Fatalf("deleteSession() error: %v", err)
	}
	if deleted == nil {
		t.Fatal("expected session to be deleted")
	}

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRunSessionAuthResponseContainsCode(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.Code != "unauthorized" {
		t.Errorf("expected code 'unauthorized', got %q", resp.Code)
	}
}

func TestRunSessionAuthResponseContainsWWWAuthenticate(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("expected WWW-Authenticate: Bearer, got %q", w.Header().Get("WWW-Authenticate"))
	}
}

func TestRunSessionAuthInvalidTokenDoesNotRunDocker(t *testing.T) {
	app := newTestAppWithAuth(t)

	called := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		called = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dht_wrong_token")
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}

	if called {
		t.Error("ExecCommandContext should not be called with invalid token")
	}
}

func TestRunSessionAuthAdminTokenRejected(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d (admin token should not work for /run), got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRunSessionAuthHashIsComputed(t *testing.T) {
	token := "dht_test_session_token"
	hash := sha256.Sum256([]byte(token))

	app := newTestApp(t)
	app.AdminTokenHash = hash

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	session, err := app.findSessionByToken(result.Token)
	if err != nil {
		t.Fatalf("findSessionByToken() error: %v", err)
	}

	if session == nil {
		t.Error("expected session to be found")
	}
}
