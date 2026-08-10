package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPullSessionAuthValidToken(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestPullSessionAuthMissingAuthorization(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthWrongScheme(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthEmptyBearer(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer ")
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthInvalidToken(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dht_wrong_token")
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthExpiredSession(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	_, err = app.DB.Exec("UPDATE sessions SET expires_at = ? WHERE id = ?", time.Now().Add(-time.Hour).Unix(), result.Session.ID)
	if err != nil {
		t.Fatalf("cannot update expires_at: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthDeletedSession(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
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

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthResponseContainsCode(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.Code != "unauthorized" {
		t.Errorf("expected code 'unauthorized', got %q", resp.Code)
	}
}

func TestPullSessionAuthResponseContainsWWWAuthenticate(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("expected WWW-Authenticate: Bearer, got %q", w.Header().Get("WWW-Authenticate"))
	}
}

func TestPullSessionAuthInvalidTokenDoesNotRunDocker(t *testing.T) {
	app := newTestAppWithAuth(t)

	called := false
	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		called = true
		return []byte("ok"), nil
	}

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dht_wrong_token")
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}

	if called {
		t.Error("ExecCommand should not be called with invalid token")
	}
}

func TestPullSessionAuthAdminTokenRejected(t *testing.T) {
	app := newTestAppWithAuth(t)

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d (admin token should not work for /pull), got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullImageRequired(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	reqBody := map[string]string{}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.Message != "image is required" {
		t.Errorf("expected 'image is required', got %q", resp.Message)
	}
}

func TestPullInvalidJSON(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPullUnknownFieldsRejected(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	reqBody := map[string]any{"image": "alpine:3.24", "extra": "field"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPullSuccessResponse(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("pull output"), nil
	}

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if !resp.OK {
		t.Error("expected ok to be true")
	}
	if resp.Message != "image pulled successfully" {
		t.Errorf("expected 'image pulled successfully', got %q", resp.Message)
	}
	if resp.Output != "pull output" {
		t.Errorf("expected output 'pull output', got %q", resp.Output)
	}
	if resp.Duration == "" {
		t.Error("expected duration to be set")
	}
}

func TestPullErrorResponse(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("error output"), &mockExitError{code: 1, msg: "exit status 1"}
	}

	reqBody := map[string]string{"image": "nonexistent:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.OK {
		t.Error("expected ok to be false")
	}
	if resp.Output != "error output" {
		t.Errorf("expected output 'error output', got %q", resp.Output)
	}
}

func TestPullDockerArgs(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		capturedArgs = args
		return []byte("ok"), nil
	}

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	dockerDir := sessionDockerDir(app.Config.RuntimeDir, result.Session.ID)
	expectedArgs := []string{"--config", dockerDir, "pull", "alpine:3.24"}
	if len(capturedArgs) != len(expectedArgs) {
		t.Fatalf("expected %d args, got %d: %v", len(expectedArgs), len(capturedArgs), capturedArgs)
	}

	for i, exp := range expectedArgs {
		if capturedArgs[i] != exp {
			t.Errorf("arg[%d]: expected %q, got %q", i, exp, capturedArgs[i])
		}
	}
}
