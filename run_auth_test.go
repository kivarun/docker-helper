package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunSessionCapabilityAuthValidToken(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestRunSessionCapabilityAuthMissingAuthorization(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRunSessionCapabilityAuthWrongScheme(t *testing.T) {
	app := newTestAppWithAdminToken(t)

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

func TestRunSessionCapabilityAuthEmptyBearer(t *testing.T) {
	app := newTestAppWithAdminToken(t)

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

func TestRunSessionCapabilityAuthInvalidToken(t *testing.T) {
	app := newTestAppWithAdminToken(t)

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

func TestRunSessionCapabilityAuthExpiredSession(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
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

func TestRunSessionCapabilityAuthDeletedSession(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	deleted, err := app.deleteSessionScoped(result.Session.ID, sessionControlScope{admin: true})
	if err != nil {
		t.Fatalf("deleteSessionScoped() error: %v", err)
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

func TestRunSessionCapabilityAuthResponseContract(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.Code != "unauthorized" {
		t.Errorf("expected code 'unauthorized', got %q", resp.Code)
	}
	if resp.Message != "Session authentication required." {
		t.Errorf("expected message 'Session authentication required.', got %q", resp.Message)
	}
	if w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("expected WWW-Authenticate: Bearer, got %q", w.Header().Get("WWW-Authenticate"))
	}
}

func TestRunSessionCapabilityAuthInvalidTokenDoesNotRunDocker(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	reqBody := map[string]string{"image": "alpine:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dht_wrong_token")
	w := httptest.NewRecorder()

	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}

	if captured.reached() {
		t.Error("Engine runner must not be called with an invalid token")
	}
}

func TestRunSessionCapabilityAuthAdminTokenRejected(t *testing.T) {
	app := newTestAppWithAdminToken(t)

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

func TestRunSessionCapabilityAuthHashIsComputed(t *testing.T) {
	token := "dht_test_session_token"
	hash := sha256.Sum256([]byte(token))

	app := newTestApp(t)
	app.AdminTokenHash = hash

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	session, err := app.findSessionByToken(result.Token)
	if err != nil {
		t.Fatalf("findSessionByToken() error: %v", err)
	}

	if session == nil {
		t.Error("expected session to be found")
	}
}
