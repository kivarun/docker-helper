package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreateCredential(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "creduser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1001", "1001", home, nil
	}

	if _, err := createPrincipal(app.DB, "creduser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	cred, token, err := createCredential(app.DB, "creduser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	if cred.Name != "oc" {
		t.Errorf("name = %q, want %q", cred.Name, "oc")
	}
	if cred.PrincipalName != "creduser" {
		t.Errorf("principal = %q, want %q", cred.PrincipalName, "creduser")
	}
	if !strings.HasPrefix(token, "dhc_") {
		t.Errorf("token should have prefix dhc_, got %q", token)
	}
	if len(token) < 10 {
		t.Errorf("token too short: %d", len(token))
	}
}

func TestCreateCredentialPrincipalNotFound(t *testing.T) {
	app := newTestApp(t)

	_, _, err := createCredential(app.DB, "nonexistent", "oc")
	if err == nil {
		t.Fatal("expected error")
	}
	if !isErrPrincipalNotFound(err) {
		t.Errorf("expected ErrPrincipalNotFound, got: %v", err)
	}
}

func TestCreateCredentialDuplicateName(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "dupnameuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1002", "1002", home, nil
	}

	if _, err := createPrincipal(app.DB, "dupnameuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	if _, _, err := createCredential(app.DB, "dupnameuser", "oc"); err != nil {
		t.Fatalf("first createCredential() error: %v", err)
	}

	_, _, err := createCredential(app.DB, "dupnameuser", "oc")
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
	if !isErrCredentialExists(err) {
		t.Errorf("expected ErrCredentialExists, got: %v", err)
	}
}

func TestCreateCredentialSameNameDifferentPrincipals(t *testing.T) {
	app := newTestApp(t)

	home1 := filepath.Join(app.Config.AllowedRoots[0], "home", "user1")
	home2 := filepath.Join(app.Config.AllowedRoots[0], "home", "user2")
	if err := os.MkdirAll(home1, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(home2, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		switch username {
		case "user1":
			return "1003", "1003", home1, nil
		case "user2":
			return "1004", "1004", home2, nil
		}
		return "", "", "", fmt.Errorf("not found")
	}

	if _, err := createPrincipal(app.DB, "user1", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(user1) error: %v", err)
	}
	if _, err := createPrincipal(app.DB, "user2", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(user2) error: %v", err)
	}

	if _, _, err := createCredential(app.DB, "user1", "oc"); err != nil {
		t.Fatalf("createCredential(user1, oc) error: %v", err)
	}
	if _, _, err := createCredential(app.DB, "user2", "oc"); err != nil {
		t.Fatalf("createCredential(user2, oc) error: %v", err)
	}
}

func TestCreateCredentialTokenNotStored(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "tokentestuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1005", "1005", home, nil
	}

	if _, err := createPrincipal(app.DB, "tokentestuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	_, token, err := createCredential(app.DB, "tokentestuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	// Check that the plaintext token is NOT stored in the database.
	var storedHash string
	err = app.DB.QueryRow(
		`SELECT token_hash FROM credentials WHERE name = ?`,
		"oc",
	).Scan(&storedHash)
	if err != nil {
		t.Fatalf("cannot query token_hash: %v", err)
	}

	// The stored hash should be the SHA-256 of the token.
	expectedHash := hashCredentialToken(token)
	if storedHash != expectedHash {
		t.Errorf("stored hash does not match SHA-256 of token")
	}

	// The plaintext token should NOT be in the hash.
	if strings.Contains(storedHash, token) {
		t.Error("plaintext token found in stored hash")
	}
}

func TestListCredentials(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "listuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1006", "1006", home, nil
	}

	if _, err := createPrincipal(app.DB, "listuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	if _, _, err := createCredential(app.DB, "listuser", "oc"); err != nil {
		t.Fatalf("createCredential(oc) error: %v", err)
	}
	if _, _, err := createCredential(app.DB, "listuser", "laptop"); err != nil {
		t.Fatalf("createCredential(laptop) error: %v", err)
	}

	creds, err := listCredentials(app.DB, "listuser")
	if err != nil {
		t.Fatalf("listCredentials() error: %v", err)
	}

	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}

	names := make(map[string]bool)
	for _, c := range creds {
		names[c.Name] = true
	}
	if !names["oc"] || !names["laptop"] {
		t.Errorf("missing expected credential names: %v", names)
	}

	// Check that token/token_hash is not in the response.
	for _, c := range creds {
		if c.ID == "" {
			t.Error("credential ID should not be empty")
		}
	}
}

func TestListCredentialsPrincipalNotFound(t *testing.T) {
	app := newTestApp(t)

	_, err := listCredentials(app.DB, "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
	if !isErrPrincipalNotFound(err) {
		t.Errorf("expected ErrPrincipalNotFound, got: %v", err)
	}
}

func TestRevokeCredential(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "revokeuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1007", "1007", home, nil
	}

	if _, err := createPrincipal(app.DB, "revokeuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	cred, _, err := createCredential(app.DB, "revokeuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	changed, err := revokeCredential(app.DB, cred.ID)
	if err != nil {
		t.Fatalf("revokeCredential() error: %v", err)
	}
	if !changed {
		t.Error("expected changed to be true")
	}

	// Verify revoked_at is set.
	fetched, err := findCredentialByID(app.DB, cred.ID)
	if err != nil {
		t.Fatalf("findCredentialByID() error: %v", err)
	}
	if fetched.RevokedAt == nil {
		t.Error("expected RevokedAt to be set")
	}
}

func TestRevokeCredentialIdempotent(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "idemrevokeuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1008", "1008", home, nil
	}

	if _, err := createPrincipal(app.DB, "idemrevokeuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	cred, _, err := createCredential(app.DB, "idemrevokeuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	if _, err := revokeCredential(app.DB, cred.ID); err != nil {
		t.Fatalf("first revokeCredential() error: %v", err)
	}

	changed, err := revokeCredential(app.DB, cred.ID)
	if err != nil {
		t.Fatalf("second revokeCredential() error: %v", err)
	}
	if changed {
		t.Error("expected changed to be false (idempotent)")
	}
}

func TestRevokeCredentialNotFound(t *testing.T) {
	app := newTestApp(t)

	_, err := revokeCredential(app.DB, "dhcr_nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
	if !isErrCredentialNotFound(err) {
		t.Errorf("expected ErrCredentialNotFound, got: %v", err)
	}
}

func TestRevokedCredentialRemainsInList(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "revlistuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1009", "1009", home, nil
	}

	if _, err := createPrincipal(app.DB, "revlistuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	cred, _, err := createCredential(app.DB, "revlistuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	if _, err := revokeCredential(app.DB, cred.ID); err != nil {
		t.Fatalf("revokeCredential() error: %v", err)
	}

	creds, err := listCredentials(app.DB, "revlistuser")
	if err != nil {
		t.Fatalf("listCredentials() error: %v", err)
	}

	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].RevokedAt == nil {
		t.Error("expected RevokedAt to be set")
	}
}

func TestCredentialHTTPCreate(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "httpcreduser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1010", "1010", home, nil
	}

	if _, err := createPrincipal(app.DB, "httpcreduser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	reqBody := map[string]string{"name": "oc"}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/credentials", app.handleCreateCredential)

	req := httptest.NewRequest(http.MethodPost, "/principals/httpcreduser/credentials", bytes.NewReader(body))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var resp createCredentialResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if resp.Credential.Name != "oc" {
		t.Errorf("name = %q, want %q", resp.Credential.Name, "oc")
	}
	if resp.Token == "" {
		t.Error("token should not be empty")
	}
	if !strings.HasPrefix(resp.Token, "dhc_") {
		t.Errorf("token should have prefix dhc_, got %q", resp.Token)
	}
}

func TestCredentialHTTPCreatePrincipalNotFound(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"name": "oc"}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/credentials", app.handleCreateCredential)

	req := httptest.NewRequest(http.MethodPost, "/principals/nonexistent/credentials", bytes.NewReader(body))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestCredentialHTTPCreateDuplicateName(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "dupnamehttpuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1011", "1011", home, nil
	}

	if _, err := createPrincipal(app.DB, "dupnamehttpuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	if _, _, err := createCredential(app.DB, "dupnamehttpuser", "oc"); err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"name": "oc"}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/credentials", app.handleCreateCredential)

	req := httptest.NewRequest(http.MethodPost, "/principals/dupnamehttpuser/credentials", bytes.NewReader(body))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status %d, got %d", http.StatusConflict, w.Code)
	}
}

func TestCredentialHTTPList(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "listhttpuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1012", "1012", home, nil
	}

	if _, err := createPrincipal(app.DB, "listhttpuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	if _, _, err := createCredential(app.DB, "listhttpuser", "oc"); err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /principals/{username}/credentials", app.handleListCredentials)

	req := httptest.NewRequest(http.MethodGet, "/principals/listhttpuser/credentials", nil)
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp listCredentialsResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if len(resp.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(resp.Credentials))
	}
	// Verify no token in response.
	body := w.Body.String()
	if strings.Contains(body, "token") {
		t.Error("list response should not contain token")
	}
}

func TestCredentialHTTPRevoke(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "revokehttpuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1013", "1013", home, nil
	}

	if _, err := createPrincipal(app.DB, "revokehttpuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	cred, _, err := createCredential(app.DB, "revokehttpuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /credentials/{id}/revoke", app.handleRevokeCredential)

	req := httptest.NewRequest(http.MethodPost, "/credentials/"+cred.ID+"/revoke", nil)
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp revokeCredentialResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if !resp.Changed {
		t.Error("expected changed to be true")
	}

	// Second revoke of the same credential — idempotent.
	req2 := httptest.NewRequest(http.MethodPost, "/credentials/"+cred.ID+"/revoke", nil)
	withAuth(req2)
	w2 := httptest.NewRecorder()

	mux.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("second revoke: expected status %d, got %d, body: %s", http.StatusOK, w2.Code, w2.Body.String())
	}

	var resp2 revokeCredentialResponse
	if err := json.NewDecoder(w2.Body).Decode(&resp2); err != nil {
		t.Fatalf("cannot decode second response: %v", err)
	}
	if resp2.Changed {
		t.Error("second revoke: expected changed to be false (idempotent)")
	}
	if resp2.Message != "unchanged" {
		t.Errorf("second revoke: expected message 'unchanged', got %q", resp2.Message)
	}
}
func TestCredentialHTTPRevokeNotFound(t *testing.T) {
	app := newTestAppWithAuth(t)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /credentials/{id}/revoke", app.handleRevokeCredential)

	req := httptest.NewRequest(http.MethodPost, "/credentials/dhcr_nonexistent/revoke", nil)
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestCredentialHTTPAdminAuth(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"name": "oc"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/principals/user/credentials", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handleCreateCredential(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestCredentialCascadeDelete(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "cascadecreduser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1015", "1015", home, nil
	}

	if _, err := createPrincipal(app.DB, "cascadecreduser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	if _, _, err := createCredential(app.DB, "cascadecreduser", "oc"); err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	// Delete the principal directly to test cascade.
	_, err := app.DB.Exec("DELETE FROM principals WHERE username = ?", "cascadecreduser")
	if err != nil {
		t.Fatalf("DELETE FROM principals error: %v", err)
	}

	// Verify credentials were cascade-deleted.
	var count int
	err = app.DB.QueryRow("SELECT COUNT(*) FROM credentials").Scan(&count)
	if err != nil {
		t.Fatalf("cannot query credentials: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 credentials after cascade delete, got %d", count)
	}
}

func TestInitializeDatabaseWithCredentialsTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='credentials';").Scan(&name)
	if err != nil {
		t.Fatalf("credentials table not found: %v", err)
	}
}

func TestInitializeDatabasePreservesAllTables(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	// Create DB with only the old R1 sessions schema.
	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL UNIQUE,
			workspace TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		);
	`)
	if err != nil {
		t.Fatalf("create sessions table: %v", err)
	}

	_, err = db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		"dhs_existing", "abc123", "/workspace", 1000000000, 9999999999,
	)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	db.Close()

	// Reopen and run current initializeDatabase.
	db, err = openDatabase(path)
	if err != nil {
		t.Fatalf("reopenDatabase() error: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	// Verify all tables exist.
	for _, table := range []string{"sessions", "principals", "principal_allowed_roots", "credentials"} {
		var name string
		err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", table).Scan(&name)
		if err != nil {
			t.Fatalf("%s table not found after init: %v", table, err)
		}
	}

	// Verify old session row preserved.
	var id, workspace string
	err = db.QueryRow(`SELECT id, workspace FROM sessions WHERE id = ?`, "dhs_existing").Scan(&id, &workspace)
	if err != nil {
		if err == sql.ErrNoRows {
			t.Fatal("existing session row was lost after initializeDatabase")
		}
		t.Fatalf("query session: %v", err)
	}
}

func TestCredentialAuditNoToken(t *testing.T) {
	rec := auditRecord{
		Event:          "principal.credential_create",
		PrincipalName:  "testuser",
		CredentialID:   "dhcr_test",
		CredentialName: "oc",
		Result:         "success",
	}

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("cannot marshal auditRecord: %v", err)
	}

	body := string(data)
	// Verify no token fields in audit.
	if strings.Contains(body, "token") {
		t.Error("audit record should not contain token")
	}
	if strings.Contains(body, "token_hash") {
		t.Error("audit record should not contain token_hash")
	}
}

func TestCredentialHTTPCreateMissingName(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "missingnameuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1016", "1016", home, nil
	}

	if _, err := createPrincipal(app.DB, "missingnameuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	reqBody := map[string]string{"name": ""}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/credentials", app.handleCreateCredential)

	req := httptest.NewRequest(http.MethodPost, "/principals/missingnameuser/credentials", bytes.NewReader(body))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCredentialHTTPCreateInvalidJSON(t *testing.T) {
	app := newTestAppWithAuth(t)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/credentials", app.handleCreateCredential)

	req := httptest.NewRequest(http.MethodPost, "/principals/user/credentials", bytes.NewReader([]byte("not json")))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCredentialMultipleForOnePrincipal(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "multiuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1017", "1017", home, nil
	}

	if _, err := createPrincipal(app.DB, "multiuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	names := []string{"oc", "laptop", "ci-launcher"}
	for _, name := range names {
		if _, _, err := createCredential(app.DB, "multiuser", name); err != nil {
			t.Fatalf("createCredential(%s) error: %v", name, err)
		}
	}

	creds, err := listCredentials(app.DB, "multiuser")
	if err != nil {
		t.Fatalf("listCredentials() error: %v", err)
	}

	if len(creds) != 3 {
		t.Fatalf("expected 3 credentials, got %d", len(creds))
	}
}

func TestCredentialTokenFormat(t *testing.T) {
	token, err := generateCredentialToken()
	if err != nil {
		t.Fatalf("generateCredentialToken() error: %v", err)
	}

	if !strings.HasPrefix(token, "dhc_") {
		t.Errorf("token should have prefix dhc_, got %q", token)
	}
	// 32 bytes = 64 hex chars + 4 prefix = 68 total.
	if len(token) != 68 {
		t.Errorf("token length = %d, want 68", len(token))
	}
}

func TestCredentialIDFormat(t *testing.T) {
	id, err := generateCredentialID()
	if err != nil {
		t.Fatalf("generateCredentialID() error: %v", err)
	}
	if !strings.HasPrefix(id, "dhcr_") {
		t.Errorf("ID should have prefix dhcr_, got %q", id)
	}
	// 16 bytes = 32 hex chars + 5 prefix = 37 total.
	if len(id) != 37 {
		t.Errorf("ID length = %d, want 37", len(id))
	}
}

func TestCredentialHashMatches(t *testing.T) {
	token, err := generateCredentialToken()
	if err != nil {
		t.Fatalf("generateCredentialToken() error: %v", err)
	}

	hash := hashCredentialToken(token)
	// SHA-256 hex = 64 chars.
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}

	// Verify the hash is correct.
	expected := sha256.Sum256([]byte(token))
	expectedHex := fmt.Sprintf("%x", expected)
	if hash != expectedHex {
		t.Error("hash does not match SHA-256 of token")
	}
}

func TestCredentialCreatedAtIndex(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "timeuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1018", "1018", home, nil
	}

	if _, err := createPrincipal(app.DB, "timeuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	before := time.Now().Add(-time.Second)
	cred, _, err := createCredential(app.DB, "timeuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}
	after := time.Now().Add(time.Second)

	if cred.CreatedAt.Before(before) || cred.CreatedAt.After(after) {
		t.Errorf("CreatedAt %v not between %v and %v", cred.CreatedAt, before, after)
	}
}

func TestCredentialCLIHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"credential", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("credential --help exited %d", code)
	}
	out := stdout.String()
	for _, want := range []string{"create", "list", "revoke"} {
		if !strings.Contains(out, want) {
			t.Errorf("credential --help should contain %q, got:\n%s", want, out)
		}
	}
}

func TestCredentialCLICreateSyntax(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"credential", "create", "--name", "oc", "testuser"}, &stdout, &stderr)
	// Should fail with missing admin token or connection error, not argument parsing error.
	errOut := stderr.String()
	if strings.Contains(errOut, "flag provided but not defined") ||
		strings.Contains(errOut, "too many arguments") ||
		strings.Contains(errOut, "accepts") {
		t.Fatalf("argument parsing failed: exit=%d stderr=%s", code, errOut)
	}
}

func TestCredentialCLICreateSyntaxRegression(t *testing.T) {
	// Verify the Usage string matches what the parser actually accepts.
	usage := credentialCreateCommand.Usage
	if !strings.Contains(usage, "--name") {
		t.Errorf("Usage should contain --name: %q", usage)
	}
	// The Usage should show --name before USER.
	nameIdx := strings.Index(usage, "--name")
	userIdx := strings.LastIndex(usage, "USER")
	if nameIdx < 0 || userIdx < 0 {
		t.Fatalf("Usage missing --name or USER: %q", usage)
	}
	if nameIdx > userIdx {
		t.Errorf("Usage should show --name before USER: %q", usage)
	}
}

func TestCredentialCLICreateDefaultName(t *testing.T) {
	// Verify that --name is optional and defaults to "default".
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"credential", "create", "testuser"}, &stdout, &stderr)
	// Should fail with missing admin token or connection error, not validation error.
	errOut := stderr.String()
	if strings.Contains(errOut, "--name is required") {
		t.Fatalf("--name should be optional: exit=%d stderr=%s", code, errOut)
	}
}

func TestCredentialHTTPRevokeDBError(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "dberruser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1020", "1020", home, nil
	}

	if _, err := createPrincipal(app.DB, "dberruser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	cred, _, err := createCredential(app.DB, "dberruser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	// Close the DB to simulate a DB error.
	app.DB.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /credentials/{id}/revoke", app.handleRevokeCredential)

	req := httptest.NewRequest(http.MethodPost, "/credentials/"+cred.ID+"/revoke", nil)
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	// Should get 500 (internal error) when DB is closed.
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusInternalServerError, w.Code, w.Body.String())
	}
}

func TestCredentialDuplicateTokenHashRejected(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "duphashuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1022", "1022", home, nil
	}

	if _, err := createPrincipal(app.DB, "duphashuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	// Create a credential.
	_, token, err := createCredential(app.DB, "duphashuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	// Try to manually insert a duplicate token_hash.
	tokenHash := hashCredentialToken(token)
	_, err = app.DB.Exec(
		`INSERT INTO credentials (id, principal_id, name, token_hash, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"dhcr_duplicate", 1, "duplicate", tokenHash, time.Now().Unix(),
	)
	if err == nil {
		t.Fatal("expected error for duplicate token_hash")
	}
	if !isSQLiteUniqueError(err) {
		t.Errorf("expected UNIQUE constraint error, got: %v", err)
	}
}
