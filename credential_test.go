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
	"slices"
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
	if !strings.HasPrefix(token, credentialTokenPrefix) {
		t.Errorf("token should have prefix %q, got %q", credentialTokenPrefix, token)
	}
	if len(token) != credentialTokenTotalLen {
		t.Errorf("token length = %d, want %d", len(token), credentialTokenTotalLen)
	}
	if err := validateCredentialToken(token); err != nil {
		t.Errorf("generated token must be accepted by validateCredentialToken: %v", err)
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

// TestCredentialNameReusableAfterRevoke verifies that after revoking a
// credential, a new credential with the same name can be created, receiving a
// new ID and token, while the revoked record is preserved as history.
func TestCredentialNameReusableAfterRevoke(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "reuseuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1011", "1011", home, nil
	}

	if _, err := createPrincipal(app.DB, "reuseuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	cred1, token1, err := createCredential(app.DB, "reuseuser", "oc")
	if err != nil {
		t.Fatalf("first createCredential() error: %v", err)
	}

	if _, err := revokeCredential(app.DB, cred1.ID); err != nil {
		t.Fatalf("revokeCredential() error: %v", err)
	}

	cred2, token2, err := createCredential(app.DB, "reuseuser", "oc")
	if err != nil {
		t.Fatalf("re-create same name after revoke error: %v", err)
	}

	if cred2.ID == cred1.ID {
		t.Errorf("new credential ID = %q, want distinct from revoked %q", cred2.ID, cred1.ID)
	}
	if token2 == token1 {
		t.Error("new credential token must be distinct from the revoked one")
	}

	// The revoked record remains as history; the new active record also present.
	creds, err := listCredentials(app.DB, "reuseuser")
	if err != nil {
		t.Fatalf("listCredentials() error: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials (revoked + active), got %d", len(creds))
	}
}

// TestCredentialUpgradeRc18DBReusesName verifies that an existing rc.18
// database (hard UNIQUE(principal_id, name), a revoked credential) migrates
// so the name can be reused while the revoked record is preserved.
func TestCredentialUpgradeRc18DBReusesName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}

	// Build an rc.18 schema: hard UNIQUE(principal_id, name).
	_, err = db.Exec(`
		CREATE TABLE principals (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			uid INTEGER NOT NULL,
			gid INTEGER NOT NULL,
			home TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1
		);
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			UNIQUE(principal_id, name)
		);
	`)
	if err != nil {
		t.Fatalf("create rc.18 schema: %v", err)
	}

	// Principal 1 with a revoked credential named "oc".
	_, err = db.Exec(
		`INSERT INTO principals (username, uid, gid, home, enabled) VALUES ('alice', 2001, 2001, '/home/alice', 1)`,
	)
	if err != nil {
		t.Fatalf("insert principal: %v", err)
	}
	_, err = db.Exec(
		`INSERT INTO credentials (id, principal_id, name, token_hash, created_at, revoked_at)
		 VALUES ('dhcr_old', 1, 'oc', 'oldhash', 1000, 2000)`,
	)
	if err != nil {
		t.Fatalf("insert revoked credential: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen and run the current migration.
	db, err = openDatabase(path)
	if err != nil {
		t.Fatalf("reopenDatabase() error: %v", err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	// Same name can now be created for the same principal.
	cred2, _, err := createCredential(db, "alice", "oc")
	if err != nil {
		t.Fatalf("create after upgrade error: %v", err)
	}
	if cred2.ID == "dhcr_old" {
		t.Error("new credential must have a distinct ID")
	}

	// Old revoked record preserved.
	var revokedAt sql.NullInt64
	err = db.QueryRow(`SELECT revoked_at FROM credentials WHERE id='dhcr_old'`).Scan(&revokedAt)
	if err != nil {
		t.Fatalf("old record missing: %v", err)
	}
	if !revokedAt.Valid {
		t.Error("expected old record to remain revoked")
	}

	// Active-name uniqueness still enforced: creating "oc" again must fail.
	if _, _, err := createCredential(db, "alice", "oc"); err == nil {
		t.Fatal("expected duplicate active name to be rejected after upgrade")
	}
}

// TestCredentialUpgradeIdempotent verifies the migration is safe to re-run on
// an already-migrated database: running initializeDatabase a second time does
// not rebuild or lose rows, and the name-reuse contract still holds.
func TestCredentialUpgradeIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}

	// Build an rc.18 schema: hard UNIQUE(principal_id, name).
	_, err = db.Exec(`
		CREATE TABLE principals (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			uid INTEGER NOT NULL,
			gid INTEGER NOT NULL,
			home TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1
		);
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			UNIQUE(principal_id, name)
		);
	`)
	if err != nil {
		t.Fatalf("create rc.18 schema: %v", err)
	}
	_, err = db.Exec(
		`INSERT INTO principals (username, uid, gid, home, enabled) VALUES ('alice', 2001, 2001, '/home/alice', 1)`,
	)
	if err != nil {
		t.Fatalf("insert principal: %v", err)
	}
	_, err = db.Exec(
		`INSERT INTO credentials (id, principal_id, name, token_hash, created_at, revoked_at)
		 VALUES ('dhcr_old', 1, 'oc', 'oldhash', 1000, 2000)`,
	)
	if err != nil {
		t.Fatalf("insert revoked credential: %v", err)
	}

	// First migration run rebuilds the table.
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("first initializeDatabase() error: %v", err)
	}

	// Second run on the already-migrated database must be safe and idempotent.
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("second initializeDatabase() (idempotent) error: %v", err)
	}

	// The old revoked record is preserved across both runs.
	var revokedAt sql.NullInt64
	err = db.QueryRow(`SELECT revoked_at FROM credentials WHERE id='dhcr_old'`).Scan(&revokedAt)
	if err != nil {
		t.Fatalf("old record missing after idempotent migration: %v", err)
	}
	if !revokedAt.Valid {
		t.Error("expected old record to remain revoked")
	}

	// Name reuse still works after the idempotent second run.
	cred2, _, err := createCredential(db, "alice", "oc")
	if err != nil {
		t.Fatalf("create after idempotent migration error: %v", err)
	}
	if cred2.ID == "dhcr_old" {
		t.Error("new credential must have a distinct ID")
	}
	db.Close()
}

// TestCredentialUpgradeConflictFailsClearly verifies that if a database somehow
// contains more than one active credential with the same (principal_id, name)
// (a corrupt state the canonical schema cannot produce), the migration fails
// clearly rather than silently discarding or renaming rows.
func TestCredentialUpgradeConflictFailsClearly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}

	// Credentials table with NO hard UNIQUE(principal_id, name) constraint,
	// holding two active credentials with the same name.
	_, err = db.Exec(`
		CREATE TABLE principals (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			uid INTEGER NOT NULL,
			gid INTEGER NOT NULL,
			home TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1
		);
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE
		);
	`)
	if err != nil {
		t.Fatalf("create corrupt schema: %v", err)
	}
	_, err = db.Exec(
		`INSERT INTO principals (username, uid, gid, home, enabled) VALUES ('alice', 2001, 2001, '/home/alice', 1)`,
	)
	if err != nil {
		t.Fatalf("insert principal: %v", err)
	}
	_, err = db.Exec(
		`INSERT INTO credentials (id, principal_id, name, token_hash, created_at, revoked_at)
		 VALUES ('dhcr_a', 1, 'oc', 'hashA', 1000, NULL)`,
	)
	if err != nil {
		t.Fatalf("insert first active credential: %v", err)
	}
	_, err = db.Exec(
		`INSERT INTO credentials (id, principal_id, name, token_hash, created_at, revoked_at)
		 VALUES ('dhcr_b', 1, 'oc', 'hashB', 1001, NULL)`,
	)
	if err != nil {
		t.Fatalf("insert second active credential: %v", err)
	}

	// Migration must fail clearly rather than delete or rename a conflicting row.
	err = initializeDatabase(db)
	if err == nil {
		t.Fatal("expected migration to fail on conflicting active rows, but it succeeded")
	}
	if !strings.Contains(err.Error(), "credential") {
		t.Errorf("expected a clear credential-related error, got: %v", err)
	}

	// Neither conflicting row may have been discarded.
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE principal_id=1 AND name='oc'`).Scan(&count)
	if err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	if count != 2 {
		t.Errorf("expected both conflicting rows preserved, got %d", count)
	}
	db.Close()
}

func TestCredentialHTTPCreate(t *testing.T) {
	app := newTestAppWithAdminToken(t)

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
	withAdminToken(req)
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
	if !strings.HasPrefix(resp.Token, credentialTokenPrefix) {
		t.Errorf("token should have prefix %q, got %q", credentialTokenPrefix, resp.Token)
	}
}

func TestCredentialHTTPCreatePrincipalNotFound(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	reqBody := map[string]string{"name": "oc"}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/credentials", app.handleCreateCredential)

	req := httptest.NewRequest(http.MethodPost, "/principals/nonexistent/credentials", bytes.NewReader(body))
	withAdminToken(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestCredentialHTTPCreateDuplicateName(t *testing.T) {
	app := newTestAppWithAdminToken(t)

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
	withAdminToken(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status %d, got %d", http.StatusConflict, w.Code)
	}
}

func TestCredentialHTTPList(t *testing.T) {
	app := newTestAppWithAdminToken(t)

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
	withAdminToken(req)
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
	app := newTestAppWithAdminToken(t)

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
	withAdminToken(req)
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
	withAdminToken(req2)
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
	app := newTestAppWithAdminToken(t)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /credentials/{id}/revoke", app.handleRevokeCredential)

	req := httptest.NewRequest(http.MethodPost, "/credentials/dhcr_nonexistent/revoke", nil)
	withAdminToken(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestCredentialHTTPAdminAuth(t *testing.T) {
	app := newTestAppWithAdminToken(t)

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
	app := newTestAppWithAdminToken(t)

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
	withAdminToken(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestCredentialHTTPCreateInvalidJSON(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/credentials", app.handleCreateCredential)

	req := httptest.NewRequest(http.MethodPost, "/principals/user/credentials", bytes.NewReader([]byte("not json")))
	withAdminToken(req)
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

	if !strings.HasPrefix(token, credentialTokenPrefix) {
		t.Errorf("token should have prefix %q, got %q", credentialTokenPrefix, token)
	}
	if len(token) != credentialTokenTotalLen {
		t.Errorf("token length = %d, want %d", len(token), credentialTokenTotalLen)
	}
	suffix := token[len(credentialTokenPrefix):]
	if len(suffix) != credentialTokenHexLen {
		t.Errorf("encoded suffix length = %d, want %d", len(suffix), credentialTokenHexLen)
	}
	if err := validateCredentialToken(token); err != nil {
		t.Errorf("generated token must be accepted by validateCredentialToken: %v", err)
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

// TestCredentialRevokeHelpExplainsCredentialID verifies the revoke help
// explains CREDENTIAL_ID (dhcr_...) and how to obtain it via credential list.
func TestCredentialRevokeHelpExplainsCredentialID(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"credential", "revoke", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("credential revoke --help exited %d", code)
	}
	out := stdout.String()
	for _, want := range []string{"CREDENTIAL_ID", "dhcr_", "credential list USER"} {
		if !strings.Contains(out, want) {
			t.Errorf("credential revoke --help should mention %q, got:\n%s", want, out)
		}
	}
}

// TestCredentialListHumanOutput verifies the list output uses explicit column
// headers (ID, NAME, CREATED, REVOKED) and renders revoked and active rows.
func TestCredentialListHumanOutput(t *testing.T) {
	activeCreated := "2026-08-26T10:00:00+03:00"
	revokedCreated := "2026-08-25T09:00:00+03:00"
	revokedAt := "2026-08-26T08:00:00+03:00"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /principals/alice/credentials", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(listCredentialsResponse{
			OK: true,
			Credentials: []credentialJSON{
				{ID: "dhcr_active", Principal: "alice", Name: "oc", CreatedAt: activeCreated},
				{ID: "dhcr_revoked", Principal: "alice", Name: "laptop", CreatedAt: revokedCreated, RevokedAt: &revokedAt},
			},
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	token := "test-token"
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"credential", "list", "--endpoint", server.URL, "--token-file", tokenPath, "alice"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr: %s)", code, stderr.String())
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (header + 2 rows), got %d: %q", len(lines), stdout.String())
	}
	header := strings.Fields(lines[0])
	if !slices.Equal(header, []string{"ID", "NAME", "CREATED", "REVOKED"}) {
		t.Errorf("header = %v, want [ID NAME CREATED REVOKED]", header)
	}
	active := strings.Fields(lines[1])
	if active[0] != "dhcr_active" || active[1] != "oc" {
		t.Errorf("active row = %v, want ID dhcr_active NAME oc", active)
	}
	revoked := strings.Fields(lines[2])
	if revoked[0] != "dhcr_revoked" || revoked[1] != "laptop" {
		t.Errorf("revoked row = %v, want ID dhcr_revoked NAME laptop", revoked)
	}
	if len(revoked) < 4 || revoked[3] == "-" {
		t.Errorf("revoked row should show revoked timestamp, got: %v", revoked)
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
	app := newTestAppWithAdminToken(t)

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
	withAdminToken(req)
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
