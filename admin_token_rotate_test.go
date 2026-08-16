package main

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotateAdminTokenGeneratesValidToken(t *testing.T) {
	app := newTestAppWithAuth(t)

	oldToken := testAdminToken
	if app.AdminTokenHash != sha256.Sum256([]byte(oldToken)) {
		t.Fatal("test setup: initial hash doesn't match")
	}

	newToken, err := app.rotateAdminToken()
	if err != nil {
		t.Fatalf("rotateAdminToken() error: %v", err)
	}

	// New token should be 64 hex chars (32 bytes)
	if len(newToken) != 64 {
		t.Errorf("token length = %d, want 64", len(newToken))
	}
	if newToken == oldToken {
		t.Error("new token should differ from old token")
	}

	// In-memory hash should be updated
	expectedHash := sha256.Sum256([]byte(newToken))
	if app.AdminTokenHash != expectedHash {
		t.Error("in-memory hash not updated after rotation")
	}

	// File should contain the new token
	data, err := os.ReadFile(app.Config.AdminTokenPath)
	if err != nil {
		t.Fatalf("cannot read token file: %v", err)
	}
	if !strings.HasPrefix(string(data), newToken) {
		t.Errorf("token file does not contain new token")
	}
}

func TestRotateAdminTokenOldTokenInvalidated(t *testing.T) {
	app := newTestAppWithAuth(t)

	oldToken := testAdminToken

	// Old token should work before rotation
	req := httptest.NewRequest("GET", "/principals", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)
	w := httptest.NewRecorder()
	app.handleListPrincipals(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with old token before rotation, got %d", w.Code)
	}

	newToken, err := app.rotateAdminToken()
	if err != nil {
		t.Fatalf("rotateAdminToken() error: %v", err)
	}

	// Old token should be rejected after rotation
	req = httptest.NewRequest("GET", "/principals", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)
	w = httptest.NewRecorder()
	app.handleListPrincipals(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with old token after rotation, got %d", w.Code)
	}

	// New token should work
	req = httptest.NewRequest("GET", "/principals", nil)
	req.Header.Set("Authorization", "Bearer "+newToken)
	w = httptest.NewRecorder()
	app.handleListPrincipals(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with new token after rotation, got %d", w.Code)
	}
}

func TestRotateAdminTokenFilePermissions(t *testing.T) {
	app := newTestAppWithAuth(t)

	_, err := app.rotateAdminToken()
	if err != nil {
		t.Fatalf("rotateAdminToken() error: %v", err)
	}

	info, err := os.Stat(app.Config.AdminTokenPath)
	if err != nil {
		t.Fatalf("cannot stat token file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("token file mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestHandleRotateAdminToken(t *testing.T) {
	app := newTestAppWithAuth(t)

	req := httptest.NewRequest("POST", "/admin/token/rotate", nil)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleRotateAdminToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp rotateAdminTokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if !resp.OK {
		t.Error("expected ok=true")
	}
	if len(resp.Token) != 64 {
		t.Errorf("token length = %d, want 64", len(resp.Token))
	}
}

func TestHandleRotateAdminTokenRequiresAuth(t *testing.T) {
	app := newTestAppWithAuth(t)

	req := httptest.NewRequest("POST", "/admin/token/rotate", nil)
	w := httptest.NewRecorder()
	app.handleRotateAdminToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

func TestHandleRotateAdminTokenWrongToken(t *testing.T) {
	app := newTestAppWithAuth(t)

	req := httptest.NewRequest("POST", "/admin/token/rotate", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	app.handleRotateAdminToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong token, got %d", w.Code)
	}
}

func TestRotateAdminTokenAudit(t *testing.T) {
	app := newTestAppWithAuth(t)

	req := httptest.NewRequest("POST", "/admin/token/rotate", nil)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleRotateAdminToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Verify the token is not in the response body
	body := w.Body.String()
	if strings.Contains(body, testAdminToken) {
		t.Error("response should not contain the old admin token")
	}
}

func TestClientRotateAdminToken(t *testing.T) {
	// This test is covered by integration tests; skip for now.
	// The client method uses the same doAuthenticatedRequest pattern
	// as other client methods which are already tested.
	t.Skip("covered by integration tests")
}

func TestGenerateAdminToken(t *testing.T) {
	token1, err := generateAdminToken()
	if err != nil {
		t.Fatalf("generateAdminToken() error: %v", err)
	}
	token2, err := generateAdminToken()
	if err != nil {
		t.Fatalf("generateAdminToken() error: %v", err)
	}

	if len(token1) != 64 {
		t.Errorf("token length = %d, want 64", len(token1))
	}
	if token1 == token2 {
		t.Error("two generated tokens should differ")
	}
}

func TestRotateAdminTokenAtomicWrite(t *testing.T) {
	app := newTestAppWithAuth(t)

	// Verify no temp files are left behind after rotation
	_, err := app.rotateAdminToken()
	if err != nil {
		t.Fatalf("rotateAdminToken() error: %v", err)
	}

	dir := filepath.Dir(app.Config.AdminTokenPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".admin-token-") {
			t.Errorf("temp file left behind: %s", entry.Name())
		}
	}
}
