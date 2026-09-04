package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errMockRotateDB is the injected UPDATE failure marker for rotation
// atomicity tests.
var errMockRotateDB = errors.New("mock_rotate_db_error")

// principalCredentialApp provisions an app, an owned Principal credential
// bearer, and a named credential on the same principal, mirroring the
// ownership chain used by the Principal-credential control handlers.
func principalCredentialApp(t *testing.T, username string) (*App, string, *httptest.ResponseRecorder) {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	home := filepath.Join(app.Config.AllowedRoots[0], "home", username)
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(u string) (string, string, string, error) {
		return "2101", "2101", home, nil
	}
	if _, err := createPrincipal(app.DB, username, app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(%s): %v", username, err)
	}
	_, callerToken, err := createCredential(app.DB, username, "caller")
	if err != nil {
		t.Fatalf("createCredential(%s): %v", username, err)
	}
	return app, callerToken, nil
}

// createNamedCredential issues an additional named Principal credential for
// the given username via the production path and returns its bearer.
func createNamedCredential(t *testing.T, app *App, username, name string) string {
	t.Helper()
	_, token, err := createCredential(app.DB, username, name)
	if err != nil {
		t.Fatalf("createCredential(%s, %s): %v", username, name, err)
	}
	return token
}

// TestPrincipalCredentialRotateAtomicReplacement proves one rotate call atomically
// replaces the named credential's bearer secret: the old bearer is rejected
// immediately, the new one authenticates, the credential ID and name are
// preserved, and no second credential row exists.
func TestPrincipalCredentialRotateAtomicReplacement(t *testing.T) {
	app, otherToken, _ := principalCredentialApp(t, "rotuser")
	oldToken := createNamedCredential(t, app, "rotuser", "default")

	// The rotation must run under the principal's own credential.
	w := launcherRequest(t, app, http.MethodPost, "/principals/rotuser/credentials/default/rotate", oldToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("rotate: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp createCredentialResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token == "" {
		t.Fatal("rotate response must carry the new one-time bearer token")
	}
	if resp.Credential.Name != "default" {
		t.Errorf("credential name = %q, want default (name is preserved)", resp.Credential.Name)
	}
	if resp.Credential.Principal != "rotuser" {
		t.Errorf("credential principal = %q, want rotuser", resp.Credential.Principal)
	}

	// The old bearer of the rotated credential is rejected immediately; the
	// new one authenticates with the same principal identity.
	w = launcherRequest(t, app, "GET", "/auth", oldToken, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("old bearer after rotate: expected 401, got %d", w.Code)
	}
	w = launcherRequest(t, app, "GET", "/auth", resp.Token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("new bearer after rotate: expected 200, got %d", w.Code)
	}
	var auth authResponse
	if err := json.Unmarshal(w.Body.Bytes(), &auth); err != nil {
		t.Fatal(err)
	}
	if auth.Authority != "principal" || auth.Principal != "rotuser" {
		t.Errorf("auth = %+v, want authority=principal principal=rotuser", auth)
	}

	// A different credential of the same principal is untouched by the
	// rotation.
	w = launcherRequest(t, app, "GET", "/auth", otherToken, "")
	if w.Code != http.StatusOK {
		t.Errorf("sibling credential bearer must keep working: got %d", w.Code)
	}

	// Exactly one credential row named default remains for the principal.
	creds, err := listCredentialsForScope(app.DB, principalIDPtr(t, app.DB, "rotuser"))
	if err != nil {
		t.Fatalf("listCredentialsForScope: %v", err)
	}
	active := 0
	for _, c := range creds {
		if c.Name == "default" && c.RevokedAt == nil {
			active++
		}
	}
	if active != 1 {
		t.Errorf("active 'default' rows = %d, want 1 (no second credential row)", active)
	}
}

// TestPrincipalCredentialRotateSelfRotation proves rotating the credential the
// caller is authenticated with follows the same atomic replacement contract.
func TestPrincipalCredentialRotateSelfRotation(t *testing.T) {
	app, _, _ := principalCredentialApp(t, "selfrot")
	selfToken := createNamedCredential(t, app, "selfrot", "default")

	w := launcherRequest(t, app, http.MethodPost, "/principals/selfrot/credentials/default/rotate", selfToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("rotate: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp createCredentialResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	w = launcherRequest(t, app, "GET", "/auth", selfToken, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("self old bearer: expected 401, got %d", w.Code)
	}
	w = launcherRequest(t, app, "GET", "/auth", resp.Token, "")
	if w.Code != http.StatusOK {
		t.Errorf("self new bearer: expected 200, got %d", w.Code)
	}
}

// TestPrincipalCredentialRotateNameSelector proves --name semantics: an
// explicit name selects another named credential, and the default name is used
// when absent.
func TestPrincipalCredentialRotateNameSelector(t *testing.T) {
	app, _, _ := principalCredentialApp(t, "namerot")
	createNamedCredential(t, app, "namerot", "default")
	laptopToken := createNamedCredential(t, app, "namerot", "laptop")

	// The principal credential rotates its default credential while the
	// laptop bearer is still valid.
	w := launcherRequest(t, app, http.MethodPost, "/principals/namerot/credentials/default/rotate", laptopToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("principal rotate default: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}

	// Admin rotates the laptop credential explicitly.
	w = launcherRequest(t, app, http.MethodPost, "/principals/namerot/credentials/laptop/rotate", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin rotate laptop: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestPrincipalCredentialRotateErrors covers the error contract: foreign
// principal (non-disclosing 404), missing credential (404), revoked credential
// (409), launcher credential authority (401), and missing bearer (401).
func TestPrincipalCredentialRotateErrors(t *testing.T) {
	app, aliceToken, _ := principalCredentialApp(t, "alice")
	bobHome := filepath.Join(app.Config.AllowedRoots[0], "home", "bob")
	if err := os.MkdirAll(bobHome, 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(u string) (string, string, string, error) {
		return "2102", "2102", bobHome, nil
	}
	if _, err := createPrincipal(app.DB, "bob", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(bob): %v", err)
	}

	// Alice's credential cannot rotate Bob's credential: non-disclosing 404.
	w := launcherRequest(t, app, http.MethodPost, "/principals/bob/credentials/default/rotate", aliceToken, "")
	if w.Code != http.StatusNotFound {
		t.Errorf("foreign rotate: expected 404, got %d (body=%s)", w.Code, w.Body.String())
	}

	// Missing credential name.
	w = launcherRequest(t, app, http.MethodPost, "/principals/alice/credentials/nosuch/rotate", aliceToken, "")
	if w.Code != http.StatusNotFound {
		t.Errorf("missing rotate: expected 404, got %d (body=%s)", w.Code, w.Body.String())
	}

	// Revoked target credential: rotating it is a conflict (409) for a valid
	// caller. A revoked credential cannot even authenticate, so the request
	// uses the still-valid caller credential.
	deadToken := createNamedCredential(t, app, "alice", "dead")
	revokedID := ""
	creds, err := listCredentialsForScope(app.DB, principalIDPtr(t, app.DB, "alice"))
	if err != nil {
		t.Fatalf("listCredentialsForScope: %v", err)
	}
	for _, c := range creds {
		if c.Name == "dead" {
			revokedID = c.ID
		}
	}
	if revokedID == "" {
		t.Fatal("fixture error: dead credential not found")
	}
	if _, err := revokeCredential(app.DB, revokedID); err != nil {
		t.Fatalf("revokeCredential: %v", err)
	}
	// Precondition: the revoked bearer can no longer authenticate at all.
	w = launcherRequest(t, app, "GET", "/auth", deadToken, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("precondition: revoked bearer must not authenticate, got %d", w.Code)
	}
	w = launcherRequest(t, app, http.MethodPost, "/principals/alice/credentials/dead/rotate", aliceToken, "")
	if w.Code != http.StatusConflict {
		t.Errorf("revoked rotate: expected 409, got %d (body=%s)", w.Code, w.Body.String())
	}

	// A Launcher credential has no control-plane authority.
	l, _, launcherToken, err := createLauncher(app.DB, principalIDByName(t, app.DB, "alice"), "agent", LauncherScopeInherit, nil, app.Config.AllowedRoots, true)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}
	w = launcherRequest(t, app, http.MethodPost, "/principals/alice/credentials/default/rotate", launcherToken, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("launcher authority rotate: expected 401, got %d (body=%s)", w.Code, w.Body.String())
	}
	_ = l

	// No bearer at all.
	w = launcherRequest(t, app, http.MethodPost, "/principals/alice/credentials/default/rotate", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no bearer rotate: expected 401, got %d", w.Code)
	}
}

// TestPrincipalCredentialRotateAtomicityOnFailure proves a rotation whose
// durable UPDATE fails leaves the old bearer working and creates no second
// credential row: the operation commits or does nothing.
func TestPrincipalCredentialRotateAtomicityOnFailure(t *testing.T) {
	app, oldToken, _ := principalCredentialApp(t, "atomicrot")
	rotateToken := createNamedCredential(t, app, "atomicrot", "default")
	dbPath := app.Config.DatabasePath
	app.DB.Close()

	failDB := newFailExecMatchDB(t, dbPath, "UPDATE credentials", errMockRotateDB)
	_, _, err := rotatePrincipalCredential(failDB, "atomicrot", "default")
	failDB.Close()
	if err == nil {
		t.Fatal("rotate must fail under the injected UPDATE failure")
	}

	realDB, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer realDB.Close()

	// The old bearer still authenticates: nothing committed.
	if _, err := authenticateCredential(realDB, oldToken); err != nil {
		t.Errorf("old bearer must still authenticate after failed rotation: %v", err)
	}
	// The rotate credential's hash is unchanged: authenticating with it still
	// works and no additional active row was created.
	if _, err := authenticateCredential(realDB, rotateToken); err != nil {
		t.Errorf("unrotated credential bearer must still authenticate: %v", err)
	}
	creds, err := listCredentialsForScope(realDB, principalIDPtr(t, realDB, "atomicrot"))
	if err != nil {
		t.Fatalf("listCredentialsForScope: %v", err)
	}
	active := 0
	for _, c := range creds {
		if c.Name == "default" && c.RevokedAt == nil {
			active++
		}
	}
	if active != 1 {
		t.Errorf("active 'default' rows = %d, want 1 (target only, no partial rotation)", active)
	}
}

// TestPrincipalCredentialListScope proves the scope-aware list contract:
// a Principal credential lists its own principal's credentials without an
// explicit selector, a foreign selector is a non-disclosing 404, the admin
// token may target any principal explicitly, and launcher credentials are
// unauthorized.
func TestPrincipalCredentialListScope(t *testing.T) {
	app, aliceToken, _ := principalCredentialApp(t, "alice")
	bobHome := filepath.Join(app.Config.AllowedRoots[0], "home", "bob")
	if err := os.MkdirAll(bobHome, 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(u string) (string, string, string, error) {
		return "2103", "2103", bobHome, nil
	}
	if _, err := createPrincipal(app.DB, "bob", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(bob): %v", err)
	}
	createNamedCredential(t, app, "alice", "extra")
	createNamedCredential(t, app, "bob", "default")

	// Own list: 200 with exactly alice's credentials.
	w := launcherRequest(t, app, "GET", "/principals/alice/credentials", aliceToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("own list: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var own listCredentialsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &own); err != nil {
		t.Fatal(err)
	}
	if len(own.Credentials) != 2 {
		t.Errorf("own credentials = %d, want 2 (caller + extra)", len(own.Credentials))
	}
	for _, c := range own.Credentials {
		if c.Principal != "alice" {
			t.Errorf("credential principal = %q, want alice", c.Principal)
		}
	}

	// Foreign list: non-disclosing 404.
	w = launcherRequest(t, app, "GET", "/principals/bob/credentials", aliceToken, "")
	if w.Code != http.StatusNotFound {
		t.Errorf("foreign list: expected 404, got %d (body=%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "bob") && strings.Contains(w.Body.String(), "principal_not_found") {
		// 404 must not disclose whether bob exists beyond the generic message;
		// the body must not carry bob-specific data.
		t.Errorf("foreign list body leaks target: %s", w.Body.String())
	}

	// Admin explicit selector: any principal.
	w = launcherRequest(t, app, "GET", "/principals/bob/credentials", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin list: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var admin listCredentialsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &admin); err != nil {
		t.Fatal(err)
	}
	if len(admin.Credentials) != 1 || admin.Credentials[0].Principal != "bob" {
		t.Errorf("admin list = %+v, want bob's credential", admin.Credentials)
	}

	// Launcher credential: unauthorized.
	_, _, launcherToken, err := createLauncher(app.DB, principalIDByName(t, app.DB, "alice"), "agent", LauncherScopeInherit, nil, app.Config.AllowedRoots, true)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}
	w = launcherRequest(t, app, "GET", "/principals/alice/credentials", launcherToken, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("launcher authority list: expected 401, got %d (body=%s)", w.Code, w.Body.String())
	}
}

// TestPrincipalCredentialRotateAfterNameReuse proves rotation after
// documented name reuse targets the current active credential: create
// TestPrincipalCredentialRotateAfterNameReuse proves rotation after
// documented name reuse targets the current active credential: create
// default A, revoke A, create default B, rotate default. B's row is rotated
// in place while the revoked historical A row stays byte-for-byte unchanged
// and no additional credential row is created.
func TestPrincipalCredentialRotateAfterNameReuse(t *testing.T) {
	app, callerToken, _ := principalCredentialApp(t, "reuserot")

	// A: first credential named default; its bearer must stop working after
	// the documented revoke.
	aToken := createNamedCredential(t, app, "reuserot", "default")
	var aID, aHash string
	if err := app.DB.QueryRow(
		`SELECT id, token_hash FROM credentials
		 WHERE principal_id = ? AND name = 'default'`,
		principalIDByName(t, app.DB, "reuserot"),
	).Scan(&aID, &aHash); err != nil {
		t.Fatalf("read credential A: %v", err)
	}
	if _, err := revokeCredential(app.DB, aID); err != nil {
		t.Fatalf("revokeCredential(A): %v", err)
	}
	// The historical state that must survive the rotation of B is A's
	// post-revoke row (revoked token hash and revoked_at timestamp).
	var aRevokedAt sql.NullInt64
	if err := app.DB.QueryRow(
		`SELECT token_hash, revoked_at FROM credentials WHERE id = ?`, aID,
	).Scan(&aHash, &aRevokedAt); err != nil {
		t.Fatalf("read revoked credential A: %v", err)
	}
	if !aRevokedAt.Valid {
		t.Fatal("fixture: credential A must be revoked before name reuse")
	}

	// Name reuse: B is the new active 'default' next to revoked historical A.
	bOldToken := createNamedCredential(t, app, "reuserot", "default")
	creds, err := listCredentialsForScope(app.DB, principalIDPtr(t, app.DB, "reuserot"))
	if err != nil {
		t.Fatalf("listCredentialsForScope: %v", err)
	}
	if len(creds) != 3 { // caller + revoked A + active B
		t.Fatalf("fixture: expected 3 credential rows, got %d", len(creds))
	}
	var bID string
	for _, c := range creds {
		if c.Name == "default" && c.RevokedAt == nil {
			bID = c.ID
		}
	}
	if bID == "" || bID == aID {
		t.Fatalf("fixture: active B row not found (aID=%s, bID=%s)", aID, bID)
	}

	// Rotate 'default' with a valid caller: the active row must be the target.
	w := launcherRequest(t, app, http.MethodPost, "/principals/reuserot/credentials/default/rotate", callerToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("rotate after name reuse: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp createCredentialResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Credential.ID != bID {
		t.Errorf("rotated credential ID = %q, want the active B row %q", resp.Credential.ID, bID)
	}

	// B's old bearer is rejected; the replacement bearer authenticates.
	w = launcherRequest(t, app, "GET", "/auth", bOldToken, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("B old bearer after rotate: expected 401, got %d", w.Code)
	}
	w = launcherRequest(t, app, "GET", "/auth", resp.Token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("replacement bearer: expected 200, got %d", w.Code)
	}
	var auth authResponse
	if err := json.Unmarshal(w.Body.Bytes(), &auth); err != nil {
		t.Fatal(err)
	}
	if auth.Authority != "principal" || auth.Principal != "reuserot" {
		t.Errorf("auth = %+v, want authority=principal principal=reuserot", auth)
	}

	// Historical A row is byte-for-byte unchanged: same hash, same revoked_at.
	// A rotation must never resurrect a revoked row.
	var aHashAfter string
	var aRevokedAfter sql.NullInt64
	if err := app.DB.QueryRow(
		`SELECT token_hash, revoked_at FROM credentials WHERE id = ?`, aID,
	).Scan(&aHashAfter, &aRevokedAfter); err != nil {
		t.Fatalf("read credential A after rotate: %v", err)
	}
	if aHashAfter != aHash || aRevokedAfter != aRevokedAt {
		t.Errorf("revoked historical row changed: hash %q -> %q, revoked_at %v -> %v",
			aHash, aHashAfter, aRevokedAt, aRevokedAfter)
	}

	// Exactly one active 'default' remains and no additional credential row
	// was created (still caller + A + B).
	creds, err = listCredentialsForScope(app.DB, principalIDPtr(t, app.DB, "reuserot"))
	if err != nil {
		t.Fatalf("listCredentialsForScope after rotate: %v", err)
	}
	active := 0
	for _, c := range creds {
		if c.Name == "default" && c.RevokedAt == nil {
			active++
		}
	}
	if active != 1 || len(creds) != 3 {
		t.Errorf("rows = %d with %d active 'default', want 3 rows with exactly 1 active", len(creds), active)
	}

	// A's revoked bearer stays invalid (never resurrected by the rotation).
	w = launcherRequest(t, app, "GET", "/auth", aToken, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("revoked A bearer after rotate of B: expected 401, got %d", w.Code)
	}
}

// TestPrincipalCredentialRotateFailsClosedOnStaleState proves the rotation
// mutation is guarded by the active-state predicate: when the guarded UPDATE
// matches no row (the target stopped being the active credential between
// lookup and mutation), the operation fails closed, leaves the old bearer
// valid, and creates no second credential row.
func TestPrincipalCredentialRotateFailsClosedOnStaleState(t *testing.T) {
	app, _, _ := principalCredentialApp(t, "stalerot")
	oldToken := createNamedCredential(t, app, "stalerot", "default")
	dbPath := app.Config.DatabasePath
	app.DB.Close()

	zeroDB := newZeroRowsExecMatchDB(t, dbPath, "UPDATE credentials")
	_, _, err := rotatePrincipalCredential(zeroDB, "stalerot", "default")
	zeroDB.Close()
	if err == nil {
		t.Fatal("guarded rotation must fail closed when the UPDATE matches no row")
	}
	if !errors.Is(err, ErrCredentialRevoked) {
		t.Errorf("stale-state rotation error = %v, want ErrCredentialRevoked", err)
	}

	realDB, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer realDB.Close()

	// Nothing was mutated: the old bearer still authenticates and no
	// additional credential row exists.
	if _, err := authenticateCredential(realDB, oldToken); err != nil {
		t.Errorf("old bearer must still authenticate after fail-closed rotation: %v", err)
	}
	creds, err := listCredentialsForScope(realDB, principalIDPtr(t, realDB, "stalerot"))
	if err != nil {
		t.Fatalf("listCredentialsForScope: %v", err)
	}
	activeDefault := 0
	for _, c := range creds {
		if c.Name == "default" && c.RevokedAt == nil {
			activeDefault++
		}
	}
	if activeDefault != 1 || len(creds) != 2 {
		t.Errorf("credential rows = %d with %d active 'default', want 2 rows (caller + target), 1 active", len(creds), activeDefault)
	}
}

// TestPrincipalCredentialRotateAuditProvenance proves the rotate audit event
// carries the target provenance (principal_name, credential_id, credential_name)
// and, for a Principal-credential caller, the separate initiator provenance,
// while bearer secrets never reach the audit stream.
func TestPrincipalCredentialRotateAuditProvenance(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, _, _ := principalCredentialApp(t, "rotaudit")
	rotateToken := createNamedCredential(t, app, "rotaudit", "laptop")

	w := launcherRequest(t, app, http.MethodPost, "/principals/rotaudit/credentials/laptop/rotate", rotateToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("rotate: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp createCredentialResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	raw := findAuditLine(auditBuf, "principal.credential_rotate")
	if raw == "" {
		t.Fatalf("expected principal.credential_rotate audit line, got none\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)

	if m["principal_name"] != "rotaudit" {
		t.Errorf("principal_name = %v, want rotaudit", m["principal_name"])
	}
	if m["credential_id"] != resp.Credential.ID {
		t.Errorf("credential_id = %v, want %s", m["credential_id"], resp.Credential.ID)
	}
	if m["credential_name"] != "laptop" {
		t.Errorf("credential_name = %v, want laptop", m["credential_name"])
	}
	if m["result"] != "success" {
		t.Errorf("result = %v, want success", m["result"])
	}
	if m["initiator_credential_id"] == "" {
		t.Error("principal-authenticated rotate must carry initiator_credential_id")
	}

	assertNoSecrets(t, raw, m, resp.Token, testAdminToken)
	if strings.Contains(raw, rotateToken) {
		t.Error("audit contains the authenticating principal credential bearer")
	}
	if strings.Contains(auditBuf.String(), resp.Token) {
		t.Error("audit stream contains the rotated bearer token")
	}
}

// TestPrincipalCredentialRotateAdminAuditNoInitiator proves an
// admin-authenticated rotation records the same target provenance without an
// initiator_credential_id.
func TestPrincipalCredentialRotateAdminAuditNoInitiator(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, _, _ := principalCredentialApp(t, "rotaudit2")
	createNamedCredential(t, app, "rotaudit2", "default")

	w := launcherRequest(t, app, http.MethodPost, "/principals/rotaudit2/credentials/default/rotate", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin rotate: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp createCredentialResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	raw := findAuditLine(auditBuf, "principal.credential_rotate")
	if raw == "" {
		t.Fatalf("expected principal.credential_rotate audit line, got none\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)

	if m["principal_name"] != "rotaudit2" {
		t.Errorf("principal_name = %v, want rotaudit2", m["principal_name"])
	}
	if m["credential_id"] != resp.Credential.ID {
		t.Errorf("credential_id = %v, want %s", m["credential_id"], resp.Credential.ID)
	}
	if m["initiator_credential_id"] != nil {
		t.Errorf("admin rotate must not carry initiator_credential_id: %v", m["initiator_credential_id"])
	}
	assertNoSecrets(t, raw, m, resp.Token, testAdminToken)
}

// TestPrincipalCredentialListAuditProvenance proves the newly scope-aware list
// emits an audit record naming the target principal and the initiating
// credential.
func TestPrincipalCredentialListAuditProvenance(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, aliceToken, _ := principalCredentialApp(t, "listaudit")

	w := launcherRequest(t, app, "GET", "/principals/listaudit/credentials", aliceToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}

	raw := findAuditLine(auditBuf, "principal.credential_list")
	if raw == "" {
		t.Fatalf("expected principal.credential_list audit line, got none\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)
	if m["principal_name"] != "listaudit" {
		t.Errorf("principal_name = %v, want listaudit", m["principal_name"])
	}
	if m["result"] != "success" {
		t.Errorf("result = %v, want success", m["result"])
	}
	if m["initiator_credential_id"] == "" {
		t.Error("principal-authenticated list must carry initiator_credential_id")
	}
	assertNoSecrets(t, raw, m, aliceToken, testAdminToken)
}
