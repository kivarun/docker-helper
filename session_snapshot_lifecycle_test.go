package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// snapshotRowsFor returns the persisted (position, path, access) rows of one
// Session in persisted position order, as raw database facts.
func snapshotRowsFor(t *testing.T, db *sql.DB, sessionID string) []AllowedRootEntry {
	t.Helper()
	rows, err := db.Query(
		`SELECT position, path, access FROM session_filesystem_snapshot_entries
		 WHERE session_id = ? ORDER BY position`,
		sessionID,
	)
	if err != nil {
		t.Fatalf("read snapshot rows: %v", err)
	}
	defer rows.Close()
	var out []AllowedRootEntry
	for rows.Next() {
		var position int
		var path, access string
		if err := rows.Scan(&position, &path, &access); err != nil {
			t.Fatalf("scan snapshot row: %v", err)
		}
		if position != len(out) {
			t.Fatalf("snapshot positions not exactly 0..N-1: index %d carries position %d", len(out), position)
		}
		out = append(out, AllowedRootEntry{Path: path, Access: AllowedRootAccess(access)})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// assertSnapshotRows asserts the exact persisted snapshot rows of one Session.
func assertSnapshotRows(t *testing.T, db *sql.DB, sessionID string, want []AllowedRootEntry) {
	t.Helper()
	got := snapshotRowsFor(t, db, sessionID)
	if len(got) != len(want) {
		t.Fatalf("persisted snapshot rows = %v, want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("persisted snapshot row %d = %v, want %v", i, got[i], want[i])
		}
	}
}

// TestNewSessionPersistsExactDerivedSnapshot proves the Session-create
// derivation and persistence contract: the snapshot is derived from the
// effective policy at the creation linearization point and persisted with
// canonical positions; normalization through the existing canonical owner
// keeps only the real transitions (a same-mode child inside the workspace is
// not one), and the persisted state reloads byte-for-byte through the
// production loader.
func TestNewSessionPersistsExactDerivedSnapshot(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	root := app.Config.AllowedRoots[0].Path
	job := filepath.Join(root, "job")
	inputs := filepath.Join(job, "inputs")
	project := filepath.Join(job, "project")
	for _, d := range []string{inputs, project} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	app.Config.AllowedRoots = []AllowedRootEntry{
		allowedRootEntry(root),
		{Path: inputs, Access: AllowedRootAccessReadOnly},
		{Path: project, Access: AllowedRootAccessReadWrite},
	}

	created, err := createDefaultAdminSessionForTest(app, job)
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	// The derived snapshot: the workspace with its effective mode plus every
	// real effective transition strictly inside it. The read_write project
	// entry is the same mode as its containing workspace region and is
	// normalized away by the existing derivation owner; the test asserts the
	// canonical result of that accepted owner, not a second policy algorithm.
	want := []AllowedRootEntry{
		{Path: job, Access: AllowedRootAccessReadWrite},
		{Path: inputs, Access: AllowedRootAccessReadOnly},
	}
	if got := created.FilesystemSnapshot.Entries; len(got) != len(want) {
		t.Fatalf("derived snapshot entries = %v, want exactly %v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("derived snapshot entry %d = %v, want %v", i, got[i], want[i])
			}
		}
	}

	assertSnapshotRows(t, app.DB, created.Session.ID, want)

	// The single canonical loader reloads the persisted state to the same
	// snapshot value Session creation returned.
	reloaded, err := loadSessionFilesystemSnapshot(app.DB, created.Session.ID, job)
	if err != nil {
		t.Fatalf("canonical loader: %v", err)
	}
	if len(reloaded.Entries) != len(want) {
		t.Fatalf("reloaded snapshot entries = %v, want exactly %v", reloaded.Entries, want)
	}
	for i := range want {
		if reloaded.Entries[i] != want[i] {
			t.Fatalf("reloaded snapshot entry %d = %v, want %v", i, reloaded.Entries[i], want[i])
		}
	}
}

// TestParentPolicyChangeNeverMutatesIssuedSnapshot is the mandatory Release
// 2.2 lifecycle invariant: after a Session is issued, parent-policy mutations
// never touch its persisted snapshot — across restarts — while new Sessions
// observe the changed policy. No adoption/reconciliation with current parent
// policy exists.
func TestParentPolicyChangeNeverMutatesIssuedSnapshot(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path

	home := filepath.Join(root, "home", "snapshot-owner")
	// The Session workspace is a proper subdirectory of the home root (the
	// workspace admission rule requires a strict descendant).
	workspace := filepath.Join(home, "work")
	inputs := filepath.Join(workspace, "inputs")
	for _, d := range []string{inputs} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	installOSUserMock(t, map[string]string{"snapshot-owner": home})
	if _, err := createPrincipal(app.DB, "snapshot-owner", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(snapshot-owner): %v", err)
	}
	// Add the nested inputs root and make it read-only: the effective policy
	// under home becomes home RW + inputs RO (the read-only transition).
	if _, _, err := addPrincipalAllowedRoot(app.DB, "snapshot-owner", inputs, AllowedRootAccessReadOnly, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("addPrincipalAllowedRoot(inputs): %v", err)
	}

	_, token, err := createPrincipalCredential(app.DB, "snapshot-owner", "oc")
	if err != nil {
		t.Fatalf("createPrincipalCredential: %v", err)
	}
	credential, err := authenticateCredential(app.DB, token)
	if err != nil {
		t.Fatalf("authenticateCredential: %v", err)
	}
	auth := &operatorAuthority{class: operatorAuthorityPrincipal, principal: credential.Principal}

	// 1. Create Session S under policy A and capture its persisted snapshot.
	created, err := app.createSessionAuthorized(auth, createSelector{}, workspace, nil)
	if err != nil {
		t.Fatalf("createSessionAuthorized(S): %v", err)
	}
	snapshotA := []AllowedRootEntry{
		{Path: workspace, Access: AllowedRootAccessReadWrite},
		{Path: inputs, Access: AllowedRootAccessReadOnly},
	}
	assertSnapshotRows(t, app.DB, created.Session.ID, snapshotA)

	// 2. Change the parent policy through the real mutation owner.
	if changed, _, err := app.setPrincipalAllowedRootAccessWithLifecycle("snapshot-owner", inputs, AllowedRootAccessReadWrite); err != nil {
		t.Fatalf("setPrincipalAllowedRootAccessWithLifecycle: %v", err)
	} else if !changed {
		t.Fatal("setPrincipalAllowedRootAccessWithLifecycle reported no change")
	}

	// 3. The persisted rows of S are unchanged.
	assertSnapshotRows(t, app.DB, created.Session.ID, snapshotA)

	// 4. Restart simulation: reopen the database, run the startup snapshot
	//    migration (post-cutover validation), and reload the snapshot.
	reopened, err := openDatabase(app.Config.DatabasePath)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer reopened.Close()
	if _, err := migrateSessionFilesystemSnapshots(reopened); err != nil {
		t.Fatalf("startup snapshot migration after parent change: %v", err)
	}
	if _, err := loadSessionFilesystemSnapshot(reopened, created.Session.ID, workspace); err != nil {
		t.Fatalf("canonical loader after restart: %v", err)
	}
	if got := snapshotRowsFor(t, reopened, created.Session.ID); len(got) != len(snapshotA) {
		t.Fatalf("snapshot after restart = %v, want exactly %v", got, snapshotA)
	} else {
		for i := range snapshotA {
			if got[i] != snapshotA[i] {
				t.Fatalf("snapshot after restart row %d = %v, want %v", i, got[i], snapshotA[i])
			}
		}
	}

	// 5. A new Session observes the changed policy: inputs read_write is the
	//    same mode as its containing region and is normalized away, so the
	//    new snapshot has only the workspace root entry.
	created2, err := app.createSessionAuthorized(auth, createSelector{}, workspace, nil)
	if err != nil {
		t.Fatalf("createSessionAuthorized(S2): %v", err)
	}
	assertSnapshotRows(t, app.DB, created2.Session.ID, []AllowedRootEntry{
		{Path: workspace, Access: AllowedRootAccessReadWrite},
	})
}

// sessionWithSnapshot creates one live admin Session with persisted snapshot
// rows on a fresh app and returns the app and the Session ID.
func sessionWithSnapshot(t *testing.T) (*App, string) {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0].Path)
	created, err := createDefaultAdminSessionForTest(app, ws)
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}
	return app, created.Session.ID
}

// launcherIDForSession resolves the owning Launcher of a Session.
func launcherIDForSession(t *testing.T, db *sql.DB, sessionID string) string {
	t.Helper()
	var launcherID string
	if err := db.QueryRow(`SELECT launcher_id FROM sessions WHERE id = ?`, sessionID).Scan(&launcherID); err != nil {
		t.Fatalf("read session launcher: %v", err)
	}
	return launcherID
}

// principalNameForSession resolves the owning Principal username of a Session
// through its Launcher ownership chain.
func principalNameForSession(t *testing.T, db *sql.DB, sessionID string) string {
	t.Helper()
	var username string
	if err := db.QueryRow(
		`SELECT p.username FROM sessions s
		 JOIN launchers l ON l.id = s.launcher_id
		 JOIN principals p ON p.id = l.principal_id
		 WHERE s.id = ?`,
		sessionID,
	).Scan(&username); err != nil {
		t.Fatalf("read session principal: %v", err)
	}
	return username
}

// TestSnapshotCascadeLifecycle proves the snapshot rows are Session
// child state owned solely by the FK ON DELETE CASCADE: every Session removal
// lifecycle owner (session delete, Launcher delete, Principal disable, expiry
// cleanup) removes the snapshot rows with the Session, and no manual
// per-path snapshot cleanup exists.
func TestSnapshotCascadeLifecycle(t *testing.T) {
	// principalSession creates a live Session owned by a real (non-reserved)
	// Principal through its default Launcher and returns app + session ID.
	principalSession := func(t *testing.T, app *App, username string) string {
		t.Helper()
		root := app.Config.AllowedRoots[0].Path
		home := filepath.Join(root, "home", username)
		workspace := filepath.Join(home, "work")
		if err := os.MkdirAll(workspace, 0755); err != nil {
			t.Fatal(err)
		}
		installOSUserMock(t, map[string]string{username: home})
		if _, err := createPrincipal(app.DB, username, app.Config.AllowedRoots); err != nil {
			t.Fatalf("createPrincipal: %v", err)
		}
		_, token, err := createPrincipalCredential(app.DB, username, "oc")
		if err != nil {
			t.Fatalf("createPrincipalCredential: %v", err)
		}
		credential, err := authenticateCredential(app.DB, token)
		if err != nil {
			t.Fatalf("authenticateCredential: %v", err)
		}
		auth := &operatorAuthority{class: operatorAuthorityPrincipal, principal: credential.Principal}
		created, err := app.createSessionAuthorized(auth, createSelector{}, workspace, nil)
		if err != nil {
			t.Fatalf("createSessionAuthorized: %v", err)
		}
		return created.Session.ID
	}

	cases := []struct {
		name string
		// run prepares one live Session on its own app and returns its ID
		// before the removal owner runs.
		run func(t *testing.T) (*App, string, string, func())
	}{
		{
			name: "session delete",
			run: func(t *testing.T) (*App, string, string, func()) {
				app, sessionID := sessionWithSnapshot(t)
				return app, sessionID, sessionID, func() {
					if _, err := app.deleteSessionScoped(sessionID, sessionControlScope{admin: true}); err != nil {
						t.Fatalf("deleteSessionScoped: %v", err)
					}
				}
			},
		},
		{
			name: "expired session cleanup",
			run: func(t *testing.T) (*App, string, string, func()) {
				app, sessionID := sessionWithSnapshot(t)
				if _, err := app.DB.Exec(
					`UPDATE sessions SET expires_at = 1 WHERE id = ?`, sessionID,
				); err != nil {
					t.Fatal(err)
				}
				return app, sessionID, sessionID, func() {
					if _, err := cleanupExpiredSessions(app.DB); err != nil {
						t.Fatalf("cleanupExpiredSessions: %v", err)
					}
				}
			},
		},
		{
			name: "launcher delete invalidation",
			run: func(t *testing.T) (*App, string, string, func()) {
				app := newTestAppWithAdminToken(t)
				username := "cascade-launcher"
				sessionID := principalSession(t, app, username)
				launcherID := launcherIDForSession(t, app.DB, sessionID)
				return app, launcherID, sessionID, func() {
					// The Launcher delete lifecycle owner invalidates its
					// Sessions; the cascade removes the snapshot rows.
					if _, err := app.deleteLauncherChecked(context.Background(), launcherID); err != nil {
						t.Fatalf("deleteLauncherChecked: %v", err)
					}
				}
			},
		},
		{
			name: "principal disable invalidation",
			run: func(t *testing.T) (*App, string, string, func()) {
				app := newTestAppWithAdminToken(t)
				username := "cascade-principal"
				sessionID := principalSession(t, app, username)
				return app, username, sessionID, func() {
					result, err := app.disablePrincipalLaunchers(username)
					if err != nil {
						t.Fatalf("disablePrincipalLaunchers: %v", err)
					}
					if !result.Changed {
						t.Fatal("disablePrincipalLaunchers reported no change")
					}
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, removalTarget, sessionID, remove := tc.run(t)

			if got := snapshotRowsFor(t, app.DB, sessionID); len(got) == 0 {
				t.Fatal("precondition: the live session has persisted snapshot rows")
			}

			remove()

			var sessions int
			if err := app.DB.QueryRow(
				`SELECT COUNT(*) FROM sessions WHERE id = ?`, sessionID,
			).Scan(&sessions); err != nil || sessions != 0 {
				t.Fatalf("session rows after removal = %d (err %v), want 0", sessions, err)
			}
			// The FK cascade is the single owner: the snapshot entries are
			// gone without any manual per-path snapshot deletion.
			if got := snapshotRowsFor(t, app.DB, sessionID); len(got) != 0 {
				t.Fatalf("snapshot rows survived the removal lifecycle (%s): %v", removalTarget, got)
			}
		})
	}
}

// TestSessionCreateRollsBackWholeTransactionWhenSnapshotPersistFails is the
// discriminating atomicity test: a test-only trigger fails the snapshot
// insert after the Session INSERT succeeded. The whole transaction rolls
// back — no Session row, no snapshot rows, no usable bearer.
func TestSessionCreateRollsBackWholeTransactionWhenSnapshotPersistFails(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0].Path)

	if _, err := app.DB.Exec(`
		CREATE TRIGGER session_snapshot_fail_test
		BEFORE INSERT ON session_filesystem_snapshot_entries
		WHEN NEW.position = 0
		BEGIN
			SELECT RAISE(ABORT, 'injected snapshot persistence failure');
		END
	`); err != nil {
		t.Fatalf("create test trigger: %v", err)
	}

	created, err := createDefaultAdminSessionForTest(app, ws)
	if err == nil {
		t.Fatal("createSessionAuthorized() must fail when snapshot persistence fails")
	}
	if created != nil {
		t.Fatalf("a partial authority was returned: %+v", created)
	}

	var sessions int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("session rows after failed creation = %d (err %v), want 0", sessions, err)
	}
	var entries int
	if err := app.DB.QueryRow(
		`SELECT COUNT(*) FROM session_filesystem_snapshot_entries`,
	).Scan(&entries); err != nil || entries != 0 {
		t.Fatalf("snapshot rows after failed creation = %d (err %v), want 0", entries, err)
	}

	// No surviving bearer: any token lookup finds no session.
	if _, err := app.findSessionByToken("dht_not_issued"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("bearer lookup after failed creation: err = %v, want SessionNotFound", err)
	}

	// Remove the injected failure: a new Session persists atomically.
	if _, err := app.DB.Exec(`DROP TRIGGER session_snapshot_fail_test`); err != nil {
		t.Fatal(err)
	}
	if _, err := createDefaultAdminSessionForTest(app, ws); err != nil {
		t.Fatalf("createSessionAuthorized() after clearing the fault: %v", err)
	}
}

// TestMACSessionBindingRollsBackWhenSnapshotPersistFails proves the MAC
// callback interaction under the existing coordinator semantics: when the
// persistence callback (Session + snapshot commit) fails, no Session row, no
// snapshot rows, and no surviving MAC binding or prepared boundary residue.
func TestMACSessionBindingRollsBackWhenSnapshotPersistFails(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)
	setupTestLoggingDiscard(t)
	workspace := testWorkspaceDir(t, app.Config.AllowedRoots[0].Path)

	if _, err := app.DB.Exec(`
		CREATE TRIGGER session_snapshot_fail_mac
		BEFORE INSERT ON session_filesystem_snapshot_entries
		WHEN NEW.position = 0
		BEGIN
			SELECT RAISE(ABORT, 'injected snapshot persistence fault');
		END
	`); err != nil {
		t.Fatalf("create test trigger: %v", err)
	}

	_, err := app.createSessionAuthorized(&operatorAuthority{class: operatorAuthorityAdmin}, createSelector{}, workspace, nil)
	if err == nil {
		t.Fatal("createSessionAuthorized() must fail when the snapshot commit fails inside the MAC callback")
	}

	mac.mu.Lock()
	bindings := len(mac.sessionBindings)
	mac.mu.Unlock()
	if bindings != 0 {
		t.Fatalf("surviving MAC session bindings = %d, want 0", bindings)
	}
	if _, err := driver.verifyCoverage(workspace); err == nil {
		t.Fatal("no durable MAC boundary may survive a failed session commit")
	}
	var sessions, entries int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("session rows = %d (err %v), want 0", sessions, err)
	}
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM session_filesystem_snapshot_entries`).Scan(&entries); err != nil || entries != 0 {
		t.Fatalf("snapshot rows after failed creation = %d (err %v), want 0", entries, err)
	}
}
