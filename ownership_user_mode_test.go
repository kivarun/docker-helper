package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// userModeOwnershipDB returns a fresh initialized DB plus a policy-legal,
// non-forbidden daemon-owner home directory under an allowed root.
func userModeOwnershipDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := openDatabase(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}
	allowedRoot := testAllowedRootDir(t)
	home := filepath.Join(allowedRoot, "daemon-home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatalf("cannot create daemon-home: %v", err)
	}
	return db, home
}

// setUserModeDaemonOSSeams stubs the daemon-owner OS identity: EffectiveUID
// returns the given uid and OSUserLookupByUID resolves that uid to the given
// username/gid/home. It returns a restore func.
func setUserModeDaemonOSSeams(t *testing.T, uid, gid int, username, home string) func() {
	t.Helper()
	uidOrig := EffectiveUID
	lookupOrig := OSUserLookupByUID
	EffectiveUID = func() int { return uid }
	OSUserLookupByUID = func(resolvedUID int) (string, string, string, error) {
		return username, strconv.Itoa(gid), home, nil
	}
	return func() {
		EffectiveUID = uidOrig
		OSUserLookupByUID = lookupOrig
	}
}

// TestEnsureUserModeOwnershipCreatesCanonical verifies a missing daemon-owner
// chain is provisioned as the canonical transparent object (enabled, zero
// principal_allowed_roots, inherit default launcher with zero roots).
func TestEnsureUserModeOwnershipCreatesCanonical(t *testing.T) {
	db, home := userModeOwnershipDB(t)
	restore := setUserModeDaemonOSSeams(t, 1001, 1001, "dho", home)
	defer restore()

	owner, err := ensureUserModeOwnership(db, ModeUser)
	if err != nil {
		t.Fatalf("ensureUserModeOwnership() error: %v", err)
	}
	if owner == nil || owner.launcherID == "" || owner.principalID == 0 {
		t.Fatalf("unexpected owner: %+v", owner)
	}
	// Re-run: idempotent and passes the transparent contract.
	if _, err := ensureUserModeOwnership(db, ModeUser); err != nil {
		t.Fatalf("second ensureUserModeOwnership() error: %v", err)
	}
}

// TestEnsureUserModeOwnershipRejectsDisabledPrincipal verifies an existing
// disabled daemon-owner Principal is rejected (fail closed), never auto-enabled.
func TestEnsureUserModeOwnershipRejectsDisabledPrincipal(t *testing.T) {
	db, home := userModeOwnershipDB(t)
	const username = "dho"
	restore := setUserModeDaemonOSSeams(t, 1002, 1002, username, home)
	defer restore()

	pid, err := insertDaemonOwnerPrincipal(db, username, 1002, 1002, home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE principals SET enabled = 0 WHERE id = ?`, pid); err != nil {
		t.Fatal(err)
	}

	_, err = ensureUserModeOwnership(db, ModeUser)
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected fail-closed on disabled principal, got %v", err)
	}
}

// TestEnsureUserModeOwnershipRejectsRootedPrincipal verifies an existing
// daemon-owner Principal carrying principal_allowed_roots rows is rejected.
func TestEnsureUserModeOwnershipRejectsRootedPrincipal(t *testing.T) {
	db, home := userModeOwnershipDB(t)
	const username = "dho"
	restore := setUserModeDaemonOSSeams(t, 1003, 1003, username, home)
	defer restore()

	pid, err := insertDaemonOwnerPrincipal(db, username, 1003, 1003, home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO principal_allowed_roots (principal_id, root_path) VALUES (?, ?)`, pid, home); err != nil {
		t.Fatal(err)
	}

	_, err = ensureUserModeOwnership(db, ModeUser)
	if err == nil || !strings.Contains(err.Error(), "principal_allowed_roots") {
		t.Fatalf("expected fail-closed on rooted principal, got %v", err)
	}
}

// TestEnsureUserModeOwnershipRejectsHomeConflict verifies an existing
// daemon-owner Principal whose UID/GID/home diverges from the resolved OS
// identity is rejected.
func TestEnsureUserModeOwnershipRejectsHomeConflict(t *testing.T) {
	db, home := userModeOwnershipDB(t)
	const username = "dho"
	restore := setUserModeDaemonOSSeams(t, 1004, 1004, username, home)
	defer restore()

	if _, err := insertDaemonOwnerPrincipal(db, username, 1004, 1004, home); err != nil {
		t.Fatal(err)
	}
	// Change the stored home to a different real directory, then fail on reuse.
	otherHome := filepath.Join(filepath.Dir(home), "other-home")
	if err := os.MkdirAll(otherHome, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE principals SET home = ? WHERE username = ?`, otherHome, username); err != nil {
		t.Fatal(err)
	}

	_, err := ensureUserModeOwnership(db, ModeUser)
	if err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("expected fail-closed on home conflict, got %v", err)
	}
}

// runDefaultLauncherContract is exercised through ensureUserModeOwnership after
// the Principal already exists; the default Launcher is validated fail-closed.
func TestEnsureUserModeOwnershipRejectsBadDefaultLauncher(t *testing.T) {
	db, home := userModeOwnershipDB(t)
	const username = "dho"
	restore := setUserModeDaemonOSSeams(t, 1005, 1005, username, home)
	defer restore()

	pid, err := insertDaemonOwnerPrincipal(db, username, 1005, 1005, home)
	if err != nil {
		t.Fatal(err)
	}
	launcherID, err := ensureDefaultLauncher(db, pid)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		mutate     func(t *testing.T)
		wantErrSub string
	}{
		{
			name: "disabled",
			mutate: func(t *testing.T) {
				if _, err := db.Exec(`UPDATE launchers SET enabled = 0 WHERE id = ?`, launcherID); err != nil {
					t.Fatal(err)
				}
			},
			wantErrSub: "disabled",
		},
		{
			name: "restricted_scope",
			mutate: func(t *testing.T) {
				if _, err := db.Exec(`UPDATE launchers SET scope_mode = 'restricted' WHERE id = ?`, launcherID); err != nil {
					t.Fatal(err)
				}
			},
			wantErrSub: "not inherit",
		},
		{
			name: "has_launcher_roots",
			mutate: func(t *testing.T) {
				if _, err := db.Exec(`INSERT INTO launcher_allowed_roots (launcher_id, root_path) VALUES (?, ?)`, launcherID, home); err != nil {
					t.Fatal(err)
				}
			},
			wantErrSub: "launcher_allowed_roots",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Restore a clean canonical launcher for each subcase.
			if _, err := db.Exec(`UPDATE launchers SET enabled = 1, scope_mode = 'inherit' WHERE id = ?`, launcherID); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`DELETE FROM launcher_allowed_roots WHERE launcher_id = ?`, launcherID); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t)

			_, err := ensureUserModeOwnership(db, ModeUser)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("expected fail-closed (%s), got %v", tc.wantErrSub, err)
			}
		})
	}
}

// TestEnsureUserModeOwnershipSymlinkedHomeIdempotent verifies B6: the OS home
// returned through a symlink is canonicalized once and compared to the stored
// canonical home, so a restart (re-run on the same DB) with the same symlinked
// OS home succeeds instead of failing on the raw-vs-canonical mismatch.
func TestEnsureUserModeOwnershipSymlinkedHomeIdempotent(t *testing.T) {
	db, realHome := userModeOwnershipDB(t)
	const username = "dho"

	// A symlink to the same real home; the OS lookup reports the symlink path.
	linkHome := filepath.Join(filepath.Dir(realHome), "home-link")
	if err := os.Symlink(realHome, linkHome); err != nil {
		t.Fatalf("cannot create home symlink: %v", err)
	}
	t.Cleanup(func() { os.Remove(linkHome) })

	restore := setUserModeDaemonOSSeams(t, 1006, 1006, username, linkHome)
	defer restore()

	if _, err := ensureUserModeOwnership(db, ModeUser); err != nil {
		t.Fatalf("first startup with symlinked home: %v", err)
	}
	// Restart: same DB, same symlinked OS home — must pass, not hit a
	// raw-vs-canonical home mismatch.
	if _, err := ensureUserModeOwnership(db, ModeUser); err != nil {
		t.Fatalf("restart with symlinked home must be idempotent, got %v", err)
	}
}
