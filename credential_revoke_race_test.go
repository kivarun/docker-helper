package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// setupCredentialRacePrincipal provisions a racing Principal with a real
// workspace directory and one active Principal credential. The directories
// are real because Session-create admission canonicalizes against the
// filesystem.
func setupCredentialRacePrincipal(t *testing.T, app *App, username string) (workspace string, credentialID string, bearer string) {
	t.Helper()
	root := app.Config.AllowedRoots[0].Path
	home := filepath.Join(root, "home", username)
	workspace = filepath.Join(home, "work")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{username: home})
	if _, err := createPrincipal(app.DB, username, app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(%s): %v", username, err)
	}
	cred, token, err := createPrincipalCredential(app.DB, username, "oc")
	if err != nil {
		t.Fatalf("createPrincipalCredential(%s): %v", username, err)
	}
	return workspace, cred.ID, token
}

// TestRaceCredentialRevokedBeforeSessionCommitRefusesSessionCreate proves the
// commit-boundary credential revalidation: the create is parked at its last
// pre-boundary read (the credential authentication), released into its
// lifecycleMu critical section, parked again at its in-boundary ownership
// read, and only then the concurrent revoke commits. When the create resumes
// toward its Session-commit point, its authorizing credential is already
// revoked, so the commit boundary must refuse the creation: no new Session
// may exist after a committed revoke, and the answer is the canonical
// non-disclosing 401 credential contract. An implementation without the
// commit-boundary revalidation creates the Session (201) behind a revoked
// credential — the race this test pins.
func TestRaceCredentialRevokedBeforeSessionCommitRefusesSessionCreate(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	workspace, credentialID, token := setupCredentialRacePrincipal(t, app1, "revracer")

	// Park points (distinct patterns from every other query in the phase):
	//   door     - the create's last pre-boundary read (the credential
	//              authentication's principal read);
	//   boundary - the create's in-boundary ownership-snapshot read, the
	//              point after which only host-filesystem resolution and the
	//              Session commit remain.
	doorPoint := newParkedQueryPoint("SELECT username, enabled FROM principals WHERE id")
	boundaryPoint := newParkedQueryPoint("SELECT l.id, l.name, l.enabled")
	app := &App{
		Config:         app1.Config,
		DB:             openParkedQueryDB(t, app1.Config.DatabasePath, doorPoint, boundaryPoint),
		AdminTokenHash: app1.AdminTokenHash,
	}

	runSinglePinnedP(t, func() {
		// 1. The create authenticates its credential and parks at its last
		//    pre-boundary read: the credential is active here.
		createDone := make(chan *httptest.ResponseRecorder, 1)
		go func() { createDone <- createSessionThroughMux(app, token, workspace) }()
		<-doorPoint.parked
		close(doorPoint.release)

		// 2. The create parks inside its lifecycleMu critical section.
		<-boundaryPoint.parked

		// 3. The concurrent revoke commits while the create is parked:
		//    credential revocation is a plain credential-store mutation and
		//    is not lifecycleMu-serialized.
		changed, err := revokePrincipalCredential(app.DB, credentialID)
		if err != nil {
			t.Fatalf("revokePrincipalCredential: %v", err)
		}
		if !changed {
			t.Fatal("revokePrincipalCredential reported no change")
		}

		// 4. The create resumes toward its Session-commit linearization
		//    point with an already-revoked authorizing credential.
		close(boundaryPoint.release)
		resp := <-createDone

		// 5. The commit boundary must refuse: 401 unauthorized, and no
		//    Session row may exist for the revoked credential's create.
		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("create: expected 401, got %d (body=%s)", resp.Code, resp.Body.String())
		}
		if code := decodeAPIError(t, resp.Body.Bytes()).Code; code != "unauthorized" {
			t.Fatalf("create: expected unauthorized code, got %q (body=%s)", code, resp.Body.String())
		}

		// No partial state: the refused creation left no Session row.
		var count int
		if err := app.DB.QueryRow(
			`SELECT COUNT(*) FROM sessions s JOIN launchers l ON l.id = s.launcher_id
			 JOIN principals p ON p.id = l.principal_id WHERE p.username = 'revracer'`,
		).Scan(&count); err != nil {
			t.Fatalf("count refused sessions: %v", err)
		}
		if count != 0 {
			t.Fatalf("refused creation left %d Session row(s) behind", count)
		}
	})
}

// TestRaceLauncherCredentialDeletedBeforeSessionCommitRefusesSessionCreate
// proves the same commit-boundary revalidation for the delegated path: a
// Launcher credential authenticates the create, the concurrent physical
// credential delete (the Launcher credential's revocation form) commits
// while the create is parked inside its lifecycleMu critical section, and
// the resumed create must refuse at its commit boundary. A delegated
// Session issued after the delete committed would recreate authentication
// authority the operator removed — the same race on the Launcher path.
func TestRaceLauncherCredentialDeletedBeforeSessionCommitRefusesSessionCreate(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	workspace, _, _ := setupCredentialRacePrincipal(t, app1, "delracer")
	principalID := principalIDByName(t, app1.DB, "delracer")
	launcherID := mustAddDefaultLauncher(t, app1.DB, principalID)
	_, token, err := issueLauncherCredential(app1.DB, launcherID)
	if err != nil {
		t.Fatalf("issueLauncherCredential: %v", err)
	}

	// Park points:
	//   door     - the Launcher credential authentication's launcher read;
	//   boundary - the create's in-boundary ownership-snapshot read.
	doorPoint := newParkedQueryPoint("SELECT l.name, l.enabled, l.principal_id")
	boundaryPoint := newParkedQueryPoint("SELECT l.id, l.name, l.enabled")
	app := &App{
		Config:         app1.Config,
		DB:             openParkedQueryDB(t, app1.Config.DatabasePath, doorPoint, boundaryPoint),
		AdminTokenHash: app1.AdminTokenHash,
	}

	runSinglePinnedP(t, func() {
		// 1. The create authenticates the Launcher credential and parks at
		//    its last pre-boundary read.
		createDone := make(chan *httptest.ResponseRecorder, 1)
		go func() { createDone <- createSessionThroughMux(app, token, workspace) }()
		<-doorPoint.parked
		close(doorPoint.release)

		// 2. The create parks inside its lifecycleMu critical section.
		<-boundaryPoint.parked

		// 3. The concurrent credential delete commits while the create is
		//    parked (a plain credential-store mutation).
		if _, err := deleteLauncherCredential(app.DB, launcherID); err != nil {
			t.Fatalf("deleteLauncherCredential: %v", err)
		}

		// 4. The create resumes toward its commit point.
		close(boundaryPoint.release)
		resp := <-createDone

		// 5. The commit boundary must refuse the deleted credential's
		//    create: 401 unauthorized and no Session row.
		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("create: expected 401, got %d (body=%s)", resp.Code, resp.Body.String())
		}
		if code := decodeAPIError(t, resp.Body.Bytes()).Code; code != "unauthorized" {
			t.Fatalf("create: expected unauthorized code, got %q (body=%s)", code, resp.Body.String())
		}

		var count int
		if err := app.DB.QueryRow(
			`SELECT COUNT(*) FROM sessions WHERE launcher_id = ?`, launcherID,
		).Scan(&count); err != nil {
			t.Fatalf("count refused sessions: %v", err)
		}
		if count != 0 {
			t.Fatalf("refused creation left %d Session row(s) behind", count)
		}
	})
}

// TestSessionCommitBeforeCredentialRevokeKeepsIssuedSession proves the
// accepted-contract mirror of the commit-boundary revalidation: the Session
// commit linearizes wholly before the concurrent revoke commit, so the
// issued Session exists and stays valid. Credential revocation does not
// retroactively revoke already-issued Sessions — the revalidation closes the
// losing ordering only, never the winning one.
func TestSessionCommitBeforeCredentialRevokeKeepsIssuedSession(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	workspace, credentialID, token := setupCredentialRacePrincipal(t, app1, "winracer")

	// Park the revoke at its durable UPDATE: while it is parked, the create
	// runs to its commit point and finishes, so the Session commit provably
	// linearizes before the revoke commit.
	revokePoint := newParkedQueryPoint("UPDATE credentials SET revoked_at")
	app := &App{
		Config:         app1.Config,
		DB:             openParkedQueryDB(t, app1.Config.DatabasePath, revokePoint),
		AdminTokenHash: app1.AdminTokenHash,
	}

	runSinglePinnedP(t, func() {
		// 1. The create runs wholly to its commit: the Session exists.
		resp := createSessionThroughMux(app, token, workspace)
		if resp.Code != http.StatusCreated {
			t.Fatalf("create: expected 201, got %d (body=%s)", resp.Code, resp.Body.String())
		}
		sessionID := decodeCreateSessionID(t, resp.Body.String())

		// 2. The revoke starts and parks at its durable UPDATE.
		revokeDone := make(chan error, 1)
		go func() {
			_, err := revokePrincipalCredential(app.DB, credentialID)
			revokeDone <- err
		}()
		<-revokePoint.parked

		// 3. The issued Session is live before the revoke commits.
		if _, err := app.findSessionByToken(extractSessionToken(t, resp.Body.String())); err != nil {
			t.Fatalf("session bearer must authenticate before the revoke commits: %v", err)
		}

		// 4. The revoke commits.
		close(revokePoint.release)
		if err := <-revokeDone; err != nil {
			t.Fatalf("revokePrincipalCredential: %v", err)
		}

		// 5. The already-issued Session stays valid: revocation never
		//    retroactively invalidates issued Sessions.
		if _, err := app.findSessionByToken(extractSessionToken(t, resp.Body.String())); err != nil {
			t.Fatalf("issued session must stay valid after the credential revoke: %v", err)
		}
		var count int
		if err := app.DB.QueryRow(
			`SELECT COUNT(*) FROM sessions WHERE id = ?`, sessionID,
		).Scan(&count); err != nil {
			t.Fatalf("count issued session: %v", err)
		}
		if count != 1 {
			t.Fatalf("issued session rows = %d, want 1", count)
		}
	})
}

// extractSessionToken reads the one-time Session bearer from a create
// response body.
func extractSessionToken(t *testing.T, body string) string {
	t.Helper()
	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("cannot parse create response: %v", err)
	}
	if parsed.Token == "" {
		t.Fatal("create response carries no token")
	}
	return parsed.Token
}

// TestRaceUnrelatedCredentialRevokeDoesNotBlockSessionCreate proves the
// revalidation is scoped to the authorizing credential: another Principal's
// credential is revoked while a create is parked inside its lifecycleMu
// critical section, and the create commits normally.
func TestRaceUnrelatedCredentialRevokeDoesNotBlockSessionCreate(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	workspace, _, token := setupCredentialRacePrincipal(t, app1, "scoperacer")
	_, _, otherToken := setupCredentialRacePrincipal(t, app1, "other")
	otherCred, err := findPrincipalCredentialByBearer(app1.DB, otherToken)
	if err != nil {
		t.Fatalf("find unrelated credential: %v", err)
	}

	doorPoint := newParkedQueryPoint("SELECT username, enabled FROM principals WHERE id")
	boundaryPoint := newParkedQueryPoint("SELECT l.id, l.name, l.enabled")
	app := &App{
		Config:         app1.Config,
		DB:             openParkedQueryDB(t, app1.Config.DatabasePath, doorPoint, boundaryPoint),
		AdminTokenHash: app1.AdminTokenHash,
	}

	runSinglePinnedP(t, func() {
		createDone := make(chan *httptest.ResponseRecorder, 1)
		go func() { createDone <- createSessionThroughMux(app, token, workspace) }()
		<-doorPoint.parked
		close(doorPoint.release)
		<-boundaryPoint.parked

		// The unrelated revoke commits inside the parked window.
		if _, err := revokePrincipalCredential(app.DB, otherCred.ID); err != nil {
			t.Fatalf("revoke unrelated credential: %v", err)
		}

		close(boundaryPoint.release)
		resp := <-createDone
		if resp.Code != http.StatusCreated {
			t.Fatalf("create: expected 201, got %d (body=%s)", resp.Code, resp.Body.String())
		}
	})
}

// findPrincipalCredentialByBearer resolves the credential row a bearer
// authenticated as (test fixture lookup).
func findPrincipalCredentialByBearer(db *sql.DB, token string) (*PrincipalCredential, error) {
	var credID string
	err := db.QueryRow(
		`SELECT id FROM credentials WHERE token_hash = ? AND revoked_at IS NULL`,
		hashCredentialToken(token),
	).Scan(&credID)
	if err != nil {
		return nil, err
	}
	return findPrincipalCredentialByID(db, credID)
}

// TestCredentialOwnershipProvenanceChangeRefusesSessionCreate proves the
// ownership clause of the commit-boundary predicate: the credential row must
// still belong to the Principal it authenticated as when the Session
// commits. The row is re-owned (synthetic stale state; no production
// mutation re-owns a credential row) while the create is parked inside its
// lifecycleMu critical section — between the first authentication and the
// commit — so the authority chain is no longer provable at the commit point
// and the creation is refused.
func TestCredentialOwnershipProvenanceChangeRefusesSessionCreate(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	workspace, credentialID, token := setupCredentialRacePrincipal(t, app1, "ownracer")

	// The re-own target: a second Principal without a credential (the
	// (principal_id, name) uniqueness would otherwise collide with the
	// ownracer credential being re-owned).
	otherHome := filepath.Join(app1.Config.AllowedRoots[0].Path, "home", "otherowner")
	if err := os.MkdirAll(otherHome, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"otherowner": otherHome})
	if _, err := createPrincipal(app1.DB, "otherowner", app1.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(otherowner): %v", err)
	}
	otherPrincipalID := principalIDByName(t, app1.DB, "otherowner")

	doorPoint := newParkedQueryPoint("SELECT username, enabled FROM principals WHERE id")
	boundaryPoint := newParkedQueryPoint("SELECT l.id, l.name, l.enabled")
	app := &App{
		Config:         app1.Config,
		DB:             openParkedQueryDB(t, app1.Config.DatabasePath, doorPoint, boundaryPoint),
		AdminTokenHash: app1.AdminTokenHash,
	}

	runSinglePinnedP(t, func() {
		// 1. The create authenticates the credential under its ownracer
		//    owner and parks inside its lifecycleMu critical section.
		createDone := make(chan *httptest.ResponseRecorder, 1)
		go func() { createDone <- createSessionThroughMux(app, token, workspace) }()
		<-doorPoint.parked
		close(doorPoint.release)
		<-boundaryPoint.parked

		// 2. Between authentication and the commit point, the credential
		//    row's owner identity silently changes: the commit-boundary
		//    predicate must refuse the unprovable authority chain.
		if _, err := app.DB.Exec(
			`UPDATE credentials SET principal_id = ? WHERE id = ?`,
			otherPrincipalID, credentialID,
		); err != nil {
			t.Fatalf("re-own credential row: %v", err)
		}

		// 3. The create resumes toward its commit point.
		close(boundaryPoint.release)
		resp := <-createDone
		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("create: expected 401, got %d (body=%s)", resp.Code, resp.Body.String())
		}

		var count int
		if err := app.DB.QueryRow(
			`SELECT COUNT(*) FROM sessions s JOIN launchers l ON l.id = s.launcher_id
			 JOIN principals p ON p.id = l.principal_id WHERE p.username = 'ownracer'`,
		).Scan(&count); err != nil {
			t.Fatalf("count refused sessions: %v", err)
		}
		if count != 0 {
			t.Fatalf("refused creation left %d Session row(s) behind", count)
		}
	})
}

// TestAdminSessionCreateIndependentOfCredentialRevalidation proves the admin
// authority is unaffected: the admin path has no credential row, so its
// Session create must not depend on credential revalidation (no clause, no
// accidental dependency).
func TestAdminSessionCreateIndependentOfCredentialRevalidation(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	workspace := testWorkspaceDir(t, app.Config.AllowedRoots[0].Path)

	resp := createAdminSessionThroughMux(app, workspace)
	if resp.Code != http.StatusCreated {
		t.Fatalf("admin create: expected 201, got %d (body=%s)", resp.Code, resp.Body.String())
	}
}

// TestCommitBoundaryCredentialRejectionAuditContract proves the public and
// audit contract of the commit-boundary rejection: the canonical auth.failure
// record with the existing credential.revoked classification, no
// session.create record (authentication-family failures are owned by the
// auth.failure path), the non-disclosing 401 body, and no bearer or secret
// value in the audit output.
func TestCommitBoundaryCredentialRejectionAuditContract(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	auditBuf, _ := setupTestLogging(t)
	workspace, credentialID, token := setupCredentialRacePrincipal(t, app1, "auditracer")

	doorPoint := newParkedQueryPoint("SELECT username, enabled FROM principals WHERE id")
	boundaryPoint := newParkedQueryPoint("SELECT l.id, l.name, l.enabled")
	app := &App{
		Config:         app1.Config,
		DB:             openParkedQueryDB(t, app1.Config.DatabasePath, doorPoint, boundaryPoint),
		AdminTokenHash: app1.AdminTokenHash,
	}

	runSinglePinnedP(t, func() {
		createDone := make(chan *httptest.ResponseRecorder, 1)
		go func() { createDone <- createSessionThroughMux(app, token, workspace) }()
		<-doorPoint.parked
		close(doorPoint.release)
		<-boundaryPoint.parked
		if _, err := revokePrincipalCredential(app.DB, credentialID); err != nil {
			t.Fatalf("revokePrincipalCredential: %v", err)
		}
		close(boundaryPoint.release)
		resp := <-createDone

		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("create: expected 401, got %d (body=%s)", resp.Code, resp.Body.String())
		}
		if code := decodeAPIError(t, resp.Body.Bytes()).Code; code != "unauthorized" {
			t.Fatalf("create: expected unauthorized code, got %q", code)
		}

		failures := findAuditLinesByEvent(auditBuf, "auth.failure")
		if len(failures) != 1 {
			t.Fatalf("auth.failure records = %d, want 1 (%s)", len(failures), auditBuf.String())
		}
		m := parseAuditMap(t, failures[0])
		if m["result"] != "credential.revoked" {
			t.Fatalf("auth.failure result = %v, want credential.revoked", m["result"])
		}
		if creates := findAuditLinesByEvent(auditBuf, "session.create"); len(creates) != 0 {
			t.Fatalf("session.create records = %d, want 0 for a credential-family rejection", len(creates))
		}
		assertNoSecrets(t, auditBuf.String(), m, token, testAdminToken)
	})
}
