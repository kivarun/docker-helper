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

// TestPrincipalCreateProvisionsDefaultLauncherAtomically proves Principal
// creation provisions the canonical 'default' Launcher in the same
// transaction: a successful create leaves an enabled inherit-scope default
// Launcher with no roots and no credential, and a rolled-back create (forced
// credential failure) leaves no Launcher row either — no half-provisioned
// Principal.
func TestPrincipalCreateProvisionsDefaultLauncherAtomically(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}

	t.Run("success", func(t *testing.T) {
		home := filepath.Join(globalRoots[0], "home", "prov")
		if err := os.MkdirAll(home, 0755); err != nil {
			t.Fatal(err)
		}
		installOSUserMock(t, map[string]string{"prov": home})

		if _, _, _, err := createPrincipalWithOptionalCredential(db, "prov", globalRoots, false); err != nil {
			t.Fatalf("createPrincipalWithOptionalCredential: %v", err)
		}
		pid, err := findPrincipalIDByUsername(db, "prov")
		if err != nil {
			t.Fatal(err)
		}
		launcherID, err := findDefaultLauncher(db, int64(pid))
		if err != nil {
			t.Fatalf("expected auto-provisioned default Launcher, got %v", err)
		}
		if !strings.HasPrefix(launcherID, launcherIDPrefix) {
			t.Errorf("expected dhl_ prefix, got %q", launcherID)
		}
		var enabled int
		var scope string
		if err := db.QueryRow(`SELECT enabled, scope_mode FROM launchers WHERE id=?`, launcherID).Scan(&enabled, &scope); err != nil {
			t.Fatal(err)
		}
		if enabled != 1 || scope != string(LauncherScopeInherit) {
			t.Errorf("expected enabled inherit-scope default Launcher, got enabled=%d scope=%s", enabled, scope)
		}
		var rootCount, credCount int
		if err := db.QueryRow(`SELECT COUNT(*) FROM launcher_allowed_roots WHERE launcher_id=?`, launcherID).Scan(&rootCount); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE launcher_id=?`, launcherID).Scan(&credCount); err != nil {
			t.Fatal(err)
		}
		if rootCount != 0 || credCount != 0 {
			t.Errorf("expected no roots and no credential on the default Launcher, got roots=%d creds=%d", rootCount, credCount)
		}
	})

	t.Run("rollback", func(t *testing.T) {
		home := filepath.Join(globalRoots[0], "home", "rb")
		if err := os.MkdirAll(home, 0755); err != nil {
			t.Fatal(err)
		}
		installOSUserMock(t, map[string]string{"rb": home})

		// Force the credential token generation to fail deterministically.
		orig := generateCredentialTokenFn
		generateCredentialTokenFn = func() (string, error) {
			return "", errors.New("forced token failure")
		}
		defer func() { generateCredentialTokenFn = orig }()

		if _, _, _, err := createPrincipalWithOptionalCredential(db, "rb", globalRoots, true); err == nil {
			t.Fatal("expected credential insertion failure")
		}

		var launcherCount int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM launchers l JOIN principals p ON p.id=l.principal_id WHERE p.username='rb'`,
		).Scan(&launcherCount); err != nil {
			t.Fatal(err)
		}
		if launcherCount != 0 {
			t.Errorf("expected no Launcher after rollback, got %d", launcherCount)
		}
	})
}

// TestMigrateDefaultLaunchersBackfillsMissing proves the startup backfill
// provisions a default Launcher exactly for Principals that lack one, is
// idempotent (a second run provisions nothing), and never touches existing
// defaults.
func TestMigrateDefaultLaunchersBackfillsMissing(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}

	// One Principal with an explicit non-default launcher (as a 2.0-era
	// Principal without its default Launcher would look).
	home := filepath.Join(globalRoots[0], "home", "legacy")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"legacy": home})
	p, _, _, err := createPrincipalWithOptionalCredential(db, "legacy", globalRoots, false)
	if err != nil {
		t.Fatalf("createPrincipalWithOptionalCredential: %v", err)
	}
	if _, _, _, err := createLauncher(db, int64(p.ID), "agent", LauncherScopeInherit, nil, globalRoots, false); err != nil {
		t.Fatalf("createLauncher: %v", err)
	}
	// Remove the auto-provisioned default to reproduce the pre-invariant state.
	if _, err := db.Exec(`DELETE FROM launchers WHERE principal_id=? AND name='default'`, p.ID); err != nil {
		t.Fatal(err)
	}

	created, err := migrateDefaultLaunchers(db)
	if err != nil {
		t.Fatalf("migrateDefaultLaunchers: %v", err)
	}
	if created != 1 {
		t.Fatalf("expected 1 provisioned default Launcher, got %d", created)
	}
	launcherID, err := findDefaultLauncher(db, int64(p.ID))
	if err != nil {
		t.Fatalf("expected backfilled default Launcher, got %v", err)
	}
	var scope string
	if err := db.QueryRow(`SELECT scope_mode FROM launchers WHERE id=?`, launcherID).Scan(&scope); err != nil {
		t.Fatal(err)
	}
	if scope != string(LauncherScopeInherit) {
		t.Errorf("expected inherit-scope backfilled default, got %s", scope)
	}

	// Idempotent: a second run provisions nothing.
	again, err := migrateDefaultLaunchers(db)
	if err != nil {
		t.Fatalf("second migrateDefaultLaunchers: %v", err)
	}
	if again != 0 {
		t.Fatalf("expected idempotent second run, got %d provisioned", again)
	}
}

// TestPrincipalCreateInitialCredentialReturnsProjectionWithoutPostCommitLookup
// proves createPrincipalWithOptionalCredential returns a projection built from
// committed values: with every query after the transaction's own pre-commit
// reads rejected, the function still succeeds and returns the one-time bearer
// secret because it never queries the DB after commit (it only Execs within the
// transaction). Were the removed post-commit findPrincipalByUsername still
// performed, that query would be rejected here. The two pre-commit queries the
// driver must permit are ensureDefaultLauncher's lookup and its post-insert
// canonical re-read.
func TestPrincipalCreateInitialCredentialReturnsProjectionWithoutPostCommitLookup(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"
	db, err := openDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	globalRoots := []string{testAllowedRootDir(t)}
	home := filepath.Join(globalRoots[0], "home", "t")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"t": home})

	// Permit the transaction's pre-commit queries, reject everything after.
	fq := newFailQueryAfterDB(t, path, 2, errMockQueryFail)
	defer fq.Close()

	p, cred, token, err := createPrincipalWithOptionalCredential(fq, "t", globalRoots, true)
	if err != nil {
		t.Fatalf("createPrincipalWithOptionalCredential under query failure: %v", err)
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
	// The issued credential still authenticates on the real DB, proving commit
	// persisted it.
	res, err := authenticateCredential(db, token)
	if err != nil || res.Principal == nil || res.Principal.PrincipalName != "t" {
		t.Fatalf("issued principal token should authenticate, got err=%v res=%+v", err, res)
	}
}
