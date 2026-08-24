package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrincipalDeleteRemovesAllData(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "deluser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1050", "1050", home, nil
	}

	if _, err := createPrincipal(app.DB, "deluser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	if _, _, err := addAllowedRoot(app.DB, "deluser", home, app.Config.AllowedRoots); err != nil {
		t.Fatalf("addAllowedRoot: %v", err)
	}

	_, credToken, err := createCredential(app.DB, "deluser", "laptop")
	if err != nil {
		t.Fatalf("createCredential: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+credToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create session: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if _, err := deletePrincipal(app.DB, "deluser"); err != nil {
		t.Fatalf("deletePrincipal: %v", err)
	}

	_, err = findPrincipalIDByUserName(app.DB, "deluser")
	if !errors.Is(err, ErrPrincipalNotFound) {
		t.Error("principal should be deleted")
	}

	_, err = app.findSessionByToken(resp.Token)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Error("session should be deleted")
	}

	rows, err := app.DB.Query(`SELECT COUNT(*) FROM principal_allowed_roots`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var count int
	if rows.Next() {
		rows.Scan(&count)
	}
	if count != 0 {
		t.Errorf("allowed roots should be deleted (FK cascade), got %d", count)
	}
}

func TestPrincipalDeleteSessionTokenInvalidated(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "deltokenuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1051", "1051", home, nil
	}

	if _, err := createPrincipal(app.DB, "deltokenuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	_, credToken, err := createCredential(app.DB, "deltokenuser", "laptop")
	if err != nil {
		t.Fatalf("createCredential: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+credToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create session: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if _, err := deletePrincipal(app.DB, "deltokenuser"); err != nil {
		t.Fatalf("deletePrincipal: %v", err)
	}

	_, err = app.findSessionByToken(resp.Token)
	if err == nil {
		t.Fatal("session token should be invalidated after delete")
	}
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got: %v", err)
	}
}

func TestPrincipalDeleteCredentialTokenInvalidated(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "delcreduser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1052", "1052", home, nil
	}

	if _, err := createPrincipal(app.DB, "delcreduser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	_, credToken, err := createCredential(app.DB, "delcreduser", "laptop")
	if err != nil {
		t.Fatalf("createCredential: %v", err)
	}

	if _, err := deletePrincipal(app.DB, "delcreduser"); err != nil {
		t.Fatalf("deletePrincipal: %v", err)
	}

	_, err = authenticateCredential(app.DB, credToken)
	if !errors.Is(err, ErrCredentialNotFound) {
		t.Error("credential token should be invalidated after delete")
	}
}

func TestPrincipalDeleteAdminSessionUnaffected(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "deladminuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1053", "1053", home, nil
	}

	adminResult, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	if _, err := createPrincipal(app.DB, "deladminuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}
	if _, err := deletePrincipal(app.DB, "deladminuser"); err != nil {
		t.Fatalf("deletePrincipal: %v", err)
	}

	session, err := app.findSessionByToken(adminResult.Token)
	if err != nil {
		t.Fatalf("admin session should still work: %v", err)
	}
	if session.ID != adminResult.Session.ID {
		t.Errorf("session ID mismatch: got %q, want %q", session.ID, adminResult.Session.ID)
	}
}

func TestPrincipalDisableDeletesSessions(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "disuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1055", "1055", home, nil
	}

	if _, err := createPrincipal(app.DB, "disuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	_, credToken, err := createCredential(app.DB, "disuser", "laptop")
	if err != nil {
		t.Fatalf("createCredential: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+credToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create session: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if _, err := persistPrincipalEnabledChange(app.DB, "disuser", false); err != nil {
		t.Fatalf("persistPrincipalEnabledChange: %v", err)
	}

	_, err = app.findSessionByToken(resp.Token)
	if err == nil {
		t.Fatal("session should be deleted after disable")
	}
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got: %v", err)
	}
}

func TestPrincipalDisableIdempotent(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "disidempuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1056", "1056", home, nil
	}

	if _, err := createPrincipal(app.DB, "disidempuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	result, err := persistPrincipalEnabledChange(app.DB, "disidempuser", false)
	if err != nil {
		t.Fatalf("first disable: %v", err)
	}
	if !result.Changed {
		t.Error("first disable should report changed")
	}

	result, err = persistPrincipalEnabledChange(app.DB, "disidempuser", false)
	if err != nil {
		t.Fatalf("second disable: %v", err)
	}
	if result.Changed {
		t.Error("second disable should report unchanged")
	}

	p, err := findPrincipalByUserName(app.DB, "disidempuser")
	if err != nil {
		t.Fatalf("findPrincipal: %v", err)
	}
	if p.Enabled {
		t.Error("principal should still be disabled")
	}
}

func TestPrincipalEnableDoesNotRestoreSessions(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "disenuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1057", "1057", home, nil
	}

	if _, err := createPrincipal(app.DB, "disenuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	_, credToken, err := createCredential(app.DB, "disenuser", "laptop")
	if err != nil {
		t.Fatalf("createCredential: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+credToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create session: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if _, err := persistPrincipalEnabledChange(app.DB, "disenuser", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := persistPrincipalEnabledChange(app.DB, "disenuser", true); err != nil {
		t.Fatalf("enable: %v", err)
	}

	_, err = app.findSessionByToken(resp.Token)
	if err == nil {
		t.Fatal("session should not be restored after enable")
	}
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got: %v", err)
	}

	p, err := findPrincipalByUserName(app.DB, "disenuser")
	if err != nil {
		t.Fatalf("findPrincipal: %v", err)
	}
	if !p.Enabled {
		t.Error("principal should be enabled")
	}
}

func TestPrincipalDeleteAPI204(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "api204user")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1059", "1059", home, nil
	}

	if _, err := createPrincipal(app.DB, "api204user", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /principals/{username}", app.handleDeletePrincipal)

	req := httptest.NewRequest(http.MethodDelete, "/principals/api204user", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

func TestPrincipalDeleteAPI404(t *testing.T) {
	app := newTestAppWithAuth(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /principals/{username}", app.handleDeletePrincipal)

	req := httptest.NewRequest(http.MethodDelete, "/principals/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}

	var apiErr apiError
	if err := json.NewDecoder(w.Body).Decode(&apiErr); err != nil {
		t.Fatalf("cannot decode error: %v", err)
	}
	if apiErr.Code != "principal_not_found" {
		t.Errorf("expected principal_not_found, got %s", apiErr.Code)
	}
}

func TestPrincipalDeleteAPI401(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "api401user")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1060", "1060", home, nil
	}

	if _, err := createPrincipal(app.DB, "api401user", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /principals/{username}", app.handleDeletePrincipal)

	req := httptest.NewRequest(http.MethodDelete, "/principals/api401user", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestPrincipalDeleteCLI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /principals/{username}", func(w http.ResponseWriter, r *http.Request) {
		username := r.PathValue("username")
		if username != "clitestuser" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	tokenDir := t.TempDir()
	tokenPath := filepath.Join(tokenDir, "token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "delete",
		"--endpoint", server.URL,
		"--token-file", tokenPath,
		"clitestuser",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "deleted principal clitestuser") {
		t.Errorf("output should contain 'deleted principal clitestuser', got: %s", out)
	}
}

func TestPrincipalDeleteCLINotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /principals/{username}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	tokenDir := t.TempDir()
	tokenPath := filepath.Join(tokenDir, "token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "delete",
		"--endpoint", server.URL,
		"--token-file", tokenPath,
		"nonexistent",
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit code for not found")
	}

	if !strings.Contains(stderr.String(), "404") {
		t.Errorf("stderr should indicate not found, got: %s", stderr.String())
	}
}

func TestPrincipalDeleteCLIHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "delete", "--help",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("help exited %d", code)
	}

	out := stdout.String()
	if !strings.Contains(out, "delete") {
		t.Error("help should mention 'delete'")
	}
}

func TestPrincipalDisableCredentialStillWorks(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "discreduser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1061", "1061", home, nil
	}

	if _, err := createPrincipal(app.DB, "discreduser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	_, credToken, err := createCredential(app.DB, "discreduser", "laptop")
	if err != nil {
		t.Fatalf("createCredential: %v", err)
	}

	if _, err := persistPrincipalEnabledChange(app.DB, "discreduser", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := persistPrincipalEnabledChange(app.DB, "discreduser", true); err != nil {
		t.Fatalf("enable: %v", err)
	}

	cred, err := authenticateCredential(app.DB, credToken)
	if err != nil {
		t.Fatalf("credential should still exist: %v", err)
	}
	if cred.PrincipalName != "discreduser" {
		t.Errorf("credential principal mismatch: got %q", cred.PrincipalName)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+credToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create session: expected %d, got %d", http.StatusCreated, w.Code)
	}
}

func TestPrincipalDisableSessionTokenUnauthorized(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "disauthuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1062", "1062", home, nil
	}

	if _, err := createPrincipal(app.DB, "disauthuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	_, credToken, err := createCredential(app.DB, "disauthuser", "laptop")
	if err != nil {
		t.Fatalf("createCredential: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+credToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create session: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if _, err := persistPrincipalEnabledChange(app.DB, "disauthuser", false); err != nil {
		t.Fatalf("disable: %v", err)
	}

	listMux := http.NewServeMux()
	listMux.HandleFunc("GET /sessions", app.handleListSessions)

	req = httptest.NewRequest(http.MethodGet, "/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Token)
	w = httptest.NewRecorder()
	listMux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestPrincipalDeleteAuditEvent(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "auditdeluser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1064", "1064", home, nil
	}

	if _, err := createPrincipal(app.DB, "auditdeluser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	var auditBuf bytes.Buffer
	initLoggers(io.Discard, &auditBuf, slog.LevelError, true)
	defer initLoggers(io.Discard, io.Discard, slog.LevelError, false)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /principals/{username}", app.handleDeletePrincipal)

	req := httptest.NewRequest(http.MethodDelete, "/principals/auditdeluser", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}

	var record auditRecord
	if err := json.NewDecoder(bytes.NewReader(auditBuf.Bytes())).Decode(&record); err != nil {
		t.Fatalf("cannot decode audit: %v", err)
	}
	if record.Event != "principal.delete" {
		t.Errorf("expected event 'principal.delete', got %q", record.Event)
	}
	if record.PrincipalName != "auditdeluser" {
		t.Errorf("expected principal_name 'auditdeluser', got %q", record.PrincipalName)
	}
	if record.Result != "success" {
		t.Errorf("expected result 'success', got %q", record.Result)
	}
	if record.Duration == "" {
		t.Error("duration should be set")
	}
}

func TestPrincipalDeleteAuditNotFound(t *testing.T) {
	app := newTestAppWithAuth(t)

	var auditBuf bytes.Buffer
	initLoggers(io.Discard, &auditBuf, slog.LevelError, true)
	defer initLoggers(io.Discard, io.Discard, slog.LevelError, false)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /principals/{username}", app.handleDeletePrincipal)

	req := httptest.NewRequest(http.MethodDelete, "/principals/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}

	var record auditRecord
	if err := json.NewDecoder(bytes.NewReader(auditBuf.Bytes())).Decode(&record); err != nil {
		t.Fatalf("cannot decode audit: %v", err)
	}
	if record.Event != "principal.delete" {
		t.Errorf("expected event 'principal.delete', got %q", record.Event)
	}
	if record.Result != "not_found" {
		t.Errorf("expected result 'not_found', got %q", record.Result)
	}
}

func TestPrincipalDeleteAuditNoTokenInOutput(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "audittokenuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1065", "1065", home, nil
	}

	if _, err := createPrincipal(app.DB, "audittokenuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	_, credToken, err := createCredential(app.DB, "audittokenuser", "laptop")
	if err != nil {
		t.Fatalf("createCredential: %v", err)
	}

	var auditBuf bytes.Buffer
	initLoggers(io.Discard, &auditBuf, slog.LevelError, true)
	defer initLoggers(io.Discard, io.Discard, slog.LevelError, false)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /principals/{username}", app.handleDeletePrincipal)

	req := httptest.NewRequest(http.MethodDelete, "/principals/audittokenuser", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}

	auditOutput := auditBuf.String()
	if strings.Contains(auditOutput, credToken) {
		t.Error("credential token must not appear in audit output")
	}
	if strings.Contains(auditOutput, testAdminToken) {
		t.Error("admin token must not appear in audit output")
	}
}

func TestPrincipalDeleteMultipleSessions(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "delsessuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1067", "1067", home, nil
	}

	if _, err := createPrincipal(app.DB, "delsessuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	_, credToken, err := createCredential(app.DB, "delsessuser", "laptop")
	if err != nil {
		t.Fatalf("createCredential: %v", err)
	}

	var sessionTokens []string
	for i := 0; i < 3; i++ {
		reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
		body, _ := json.Marshal(reqBody)

		mux := http.NewServeMux()
		mux.HandleFunc("POST /sessions", app.handleCreateSession)

		req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+credToken)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("create session %d: expected %d, got %d", i, http.StatusCreated, w.Code)
		}

		var resp createSessionResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode response %d: %v", i, err)
		}
		sessionTokens = append(sessionTokens, resp.Token)
	}

	if _, err := deletePrincipal(app.DB, "delsessuser"); err != nil {
		t.Fatalf("deletePrincipal: %v", err)
	}

	for i, token := range sessionTokens {
		_, err := app.findSessionByToken(token)
		if err == nil {
			t.Errorf("session %d should be deleted", i)
		}
		if !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("session %d: expected ErrSessionNotFound, got: %v", i, err)
		}
	}
}

func TestPrincipalDeleteWithExpiredSessions(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "delexpuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1068", "1068", home, nil
	}

	if _, err := createPrincipal(app.DB, "delexpuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	_, credToken, err := createCredential(app.DB, "delexpuser", "laptop")
	if err != nil {
		t.Fatalf("createCredential: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+credToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create session: expected %d, got %d", http.StatusCreated, w.Code)
	}

	now := time.Now().Unix()
	_, err = app.DB.Exec(
		`UPDATE sessions SET expires_at = ? WHERE expires_at > ?`,
		now-3600, now,
	)
	if err != nil {
		t.Fatalf("expire session: %v", err)
	}

	if _, err := deletePrincipal(app.DB, "delexpuser"); err != nil {
		t.Fatalf("deletePrincipal: %v", err)
	}

	_, err = findPrincipalIDByUserName(app.DB, "delexpuser")
	if !errors.Is(err, ErrPrincipalNotFound) {
		t.Error("principal should be deleted")
	}
}
