package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupInitialCredentialPrincipal(t *testing.T, app *App, username string) {
	t.Helper()
	home := filepath.Join(app.Config.AllowedRoots[0], "home", username)
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{username: home})
}

func TestPrincipalCreateInitialCredentialHTTP(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupInitialCredentialPrincipal(t, app, "pam")

	mux := http.NewServeMux()
	registerRoutes(mux, app)
	req := httptest.NewRequest(http.MethodPost, "/principals", strings.NewReader(
		`{"username":"pam","issue_credential":true}`))
	withAdminToken(req)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", w.Code, w.Body.String())
	}
	var resp principalResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Credential == nil {
		t.Fatal("expected credential in response")
	}
	if resp.Credential.Name != "default" || resp.Credential.Principal != "pam" {
		t.Errorf("unexpected credential: %+v", resp.Credential)
	}
	if !strings.HasPrefix(resp.Token, credentialTokenPrefix) {
		t.Errorf("expected dhc_ token, got %q", resp.Token)
	}
	if strings.Contains(w.Body.String(), "token_hash") {
		t.Errorf("response must not contain token_hash: %s", w.Body.String())
	}

	// Credential authenticates as a Principal.
	res, err := authenticateCredential(app.DB, resp.Token)
	if err != nil {
		t.Fatalf("issued credential should authenticate: %v", err)
	}
	if res.Principal == nil || res.Principal.PrincipalName != "pam" {
		t.Fatalf("expected pam Principal auth, got %+v", res)
	}

	// DB has exactly one active Principal credential named default.
	var count int
	if err := app.DB.QueryRow(
		`SELECT COUNT(*) FROM credentials WHERE principal_id = (SELECT id FROM principals WHERE username='pam') AND name='default' AND revoked_at IS NULL`,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected exactly 1 active default credential, got %d", count)
	}
}

func TestPrincipalCreateOmissionKeepsBehavior(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupInitialCredentialPrincipal(t, app, "q")

	mux := http.NewServeMux()
	registerRoutes(mux, app)
	req := httptest.NewRequest(http.MethodPost, "/principals", strings.NewReader(`{"username":"q"}`))
	withAdminToken(req)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Errorf("omission must not return a credential/token: %s", w.Body.String())
	}
	var resp principalResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Credential != nil || resp.Token != "" {
		t.Errorf("expected no credential for omitted issue_credential, got %+v", resp)
	}
}

func TestPrincipalCreateFalseKeepsBehavior(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupInitialCredentialPrincipal(t, app, "r")

	mux := http.NewServeMux()
	registerRoutes(mux, app)
	req := httptest.NewRequest(http.MethodPost, "/principals", strings.NewReader(
		`{"username":"r","issue_credential":false}`))
	withAdminToken(req)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Errorf("false must not return a credential/token: %s", w.Body.String())
	}
}

// TestPrincipalCreateInitialCredentialAtomicRollback proves that a forced
// credential insertion failure rolls back the Principal and its allowed-root
// row: no half-created Principal remains.
func TestPrincipalCreateInitialCredentialAtomicRollback(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	home := filepath.Join(globalRoots[0], "home", "s")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"s": home})

	// Force the credential token generation to fail deterministically.
	orig := generateCredentialTokenFn
	generateCredentialTokenFn = func() (string, error) {
		return "", errors.New("forced token failure")
	}
	defer func() { generateCredentialTokenFn = orig }()

	_, _, _, err := createPrincipalWithOptionalCredential(db, "s", globalRoots, true)
	if err == nil {
		t.Fatal("expected credential insertion failure")
	}

	// No Principal, allowed-root, or credential row may remain.
	var principalCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM principals WHERE username='s'`).Scan(&principalCount); err != nil {
		t.Fatal(err)
	}
	if principalCount != 0 {
		t.Errorf("expected no Principal after rollback, got %d", principalCount)
	}
	var rootCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM principal_allowed_roots r JOIN principals p ON p.id=r.principal_id WHERE p.username='s'`,
	).Scan(&rootCount); err != nil {
		t.Fatal(err)
	}
	if rootCount != 0 {
		t.Errorf("expected no allowed-root row after rollback, got %d", rootCount)
	}
	var credCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM credentials c JOIN principals p ON p.id=c.principal_id WHERE p.username='s'`,
	).Scan(&credCount); err != nil {
		t.Fatal(err)
	}
	if credCount != 0 {
		t.Errorf("expected no credential after rollback, got %d", credCount)
	}
}

// TestPrincipalCreateInitialCredentialReturnsProjectionWithoutPostCommitLookup
// proves createPrincipalWithOptionalCredential returns a projection built from
// committed values, so a successful commit cannot be followed by a fallible DB
// lookup that would lose the one-time bearer secret.
func TestPrincipalCreateInitialCredentialReturnsProjectionWithoutPostCommitLookup(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	home := filepath.Join(globalRoots[0], "home", "t")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"t": home})

	p, cred, token, err := createPrincipalWithOptionalCredential(db, "t", globalRoots, true)
	if err != nil {
		t.Fatalf("createPrincipalWithOptionalCredential: %v", err)
	}
	// Projection returned from committed values.
	if p.Username != "t" || !p.Enabled || p.Home != home {
		t.Errorf("unexpected principal projection: %+v", p)
	}
	if len(p.AllowedRoots) != 1 || p.AllowedRoots[0] != home {
		t.Errorf("expected default allowed root in projection, got %v", p.AllowedRoots)
	}
	if cred == nil || cred.Name != "default" || !strings.HasPrefix(token, credentialTokenPrefix) {
		t.Fatalf("expected issued credential/token, got cred=%+v token=%q", cred, token)
	}
	// The issued credential still authenticates, proving commit persisted it.
	res, err := authenticateCredential(db, token)
	if err != nil || res.Principal == nil || res.Principal.PrincipalName != "t" {
		t.Fatalf("issued principal token should authenticate, got err=%v res=%+v", err, res)
	}
}
