package main

import (
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
// credential — the audited H2 race.
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
		Config:          app1.Config,
		DB:              openParkedQueryDB(t, app1.Config.DatabasePath, doorPoint, boundaryPoint),
		AdminTokenHash:  app1.AdminTokenHash,
		userModeDefault: app1.userModeDefault,
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
// authority the operator removed — the same H2 race on the Launcher path.
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
		Config:          app1.Config,
		DB:              openParkedQueryDB(t, app1.Config.DatabasePath, doorPoint, boundaryPoint),
		AdminTokenHash:  app1.AdminTokenHash,
		userModeDefault: app1.userModeDefault,
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
