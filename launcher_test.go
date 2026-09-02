package main

import (
	"database/sql"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// openFreshTestDB opens a new temporary database and runs initializeDatabase.
func openFreshTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := openDatabase(dir + "/test.db")
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}
	return db
}

// openFreshTestDBNoFK opens a fresh test database with foreign-key enforcement
// disabled, then runs initializeDatabase. It is used only where a fixture must
// create a referentially dangling row that production would never tolerate.
func openFreshTestDBNoFK(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + url.PathEscape(dir+"/test.db") + "?_foreign_keys=off"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}
	return db
}

func TestGenerateLauncherID(t *testing.T) {
	id, err := generateLauncherID()
	if err != nil {
		t.Fatalf("generateLauncherID() error: %v", err)
	}

	if !strings.HasPrefix(id, launcherIDPrefix) {
		t.Errorf("expected prefix %q, got %q", launcherIDPrefix, id)
	}
	suffix := strings.TrimPrefix(id, launcherIDPrefix)
	if len(suffix) != launcherIDEntropyBytes*2 {
		t.Errorf("expected %d hex chars after prefix, got %d", launcherIDEntropyBytes*2, len(suffix))
	}
	if !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(suffix) {
		t.Errorf("suffix %q is not valid lowercase hex", suffix)
	}

	// Two calls are not expected to produce the same ID.
	other, err := generateLauncherID()
	if err != nil {
		t.Fatalf("generateLauncherID() error: %v", err)
	}
	if other == id {
		t.Errorf("two generateLauncherID() calls returned the same ID %q", id)
	}
}

func TestFreshDBLaunchersTable(t *testing.T) {
	db := openFreshTestDB(t)

	var name string
	err := db.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='launchers'`,
	).Scan(&name)
	if err != nil {
		t.Fatalf("launchers table not found: %v", err)
	}
	if name != "launchers" {
		t.Errorf("expected table launchers, got %q", name)
	}
}

// insertTestPrincipal inserts a principal and returns its ID.
func insertTestPrincipal(t *testing.T, db *sql.DB, username string, uid int) int64 {
	t.Helper()
	res, err := db.Exec(
		`INSERT INTO principals (username, uid, gid, home, enabled) VALUES (?, ?, ?, ?, 1)`,
		username, uid, uid, "/home/"+username,
	)
	if err != nil {
		t.Fatalf("insert principal: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("last insert id: %v", err)
	}
	return id
}

func TestLauncherPrincipalFK(t *testing.T) {
	db := openFreshTestDB(t)

	pid := insertTestPrincipal(t, db, "alice", 2001)

	launcherID, err := generateLauncherID()
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(
		`INSERT INTO launchers (id, principal_id, name, enabled, scope_mode, created_at)
		 VALUES (?, ?, 'default', 1, 'inherit', 1000)`,
		launcherID, pid,
	)
	if err != nil {
		t.Fatalf("insert launcher: %v", err)
	}

	// Referencing a nonexistent Principal is rejected by the FK.
	_, err = db.Exec(
		`INSERT INTO launchers (id, principal_id, name, enabled, scope_mode, created_at)
		 VALUES (?, 99999, 'x', 1, 'inherit', 1000)`,
		launcherID+"x",
	)
	if err == nil || !strings.Contains(err.Error(), "FOREIGN KEY") {
		t.Errorf("expected FOREIGN KEY failure for nonexistent principal, got: %v", err)
	}
}

func TestLauncherNameUniqueWithinPrincipal(t *testing.T) {
	db := openFreshTestDB(t)

	pid1 := insertTestPrincipal(t, db, "alice", 2001)
	pid2 := insertTestPrincipal(t, db, "bob", 2002)

	insert := func(principalID int64, name string) error {
		id, err := generateLauncherID()
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec(
			`INSERT INTO launchers (id, principal_id, name, enabled, scope_mode, created_at)
			 VALUES (?, ?, ?, 1, 'inherit', 1000)`,
			id, principalID, name,
		)
		return err
	}

	if err := insert(pid1, "default"); err != nil {
		t.Fatalf("insert first launcher: %v", err)
	}
	// Duplicate (principal_id, name) within the same Principal is rejected.
	if err := insert(pid1, "default"); err == nil {
		t.Error("expected UNIQUE(principal_id, name) violation for duplicate name")
	}
	// The same name is allowed under a different Principal.
	if err := insert(pid2, "default"); err != nil {
		t.Errorf("expected same name allowed under different principal, got: %v", err)
	}
}

func TestLauncherScopeModeCheck(t *testing.T) {
	db := openFreshTestDB(t)
	pid := insertTestPrincipal(t, db, "alice", 2001)

	insert := func(name, scope string) error {
		id, err := generateLauncherID()
		if err != nil {
			t.Fatal(err)
		}
		_, err = db.Exec(
			`INSERT INTO launchers (id, principal_id, name, enabled, scope_mode, created_at)
			 VALUES (?, ?, ?, 1, ?, 1000)`,
			id, pid, name, scope,
		)
		return err
	}

	if err := insert("inherit-launcher", "inherit"); err != nil {
		t.Errorf("inherit scope should be accepted, got: %v", err)
	}
	if err := insert("restricted-launcher", "restricted"); err != nil {
		t.Errorf("restricted scope should be accepted, got: %v", err)
	}
	if err := insert("bogus-launcher", "bogus"); err == nil {
		t.Error("unknown scope_mode should be rejected by CHECK")
	}
}

func TestLauncherAllowedRoots(t *testing.T) {
	db := openFreshTestDB(t)
	pid := insertTestPrincipal(t, db, "alice", 2001)

	launcherID, err := generateLauncherID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO launchers (id, principal_id, name, enabled, scope_mode, created_at)
		 VALUES (?, ?, 'default', 1, 'restricted', 1000)`,
		launcherID, pid,
	); err != nil {
		t.Fatalf("insert launcher: %v", err)
	}

	// A Launcher root can be stored.
	if _, err := db.Exec(
		`INSERT INTO launcher_allowed_roots (launcher_id, root_path) VALUES (?, '/home/alice')`,
		launcherID,
	); err != nil {
		t.Fatalf("insert allowed root: %v", err)
	}

	// Duplicate (launcher_id, root_path) is rejected.
	if _, err := db.Exec(
		`INSERT INTO launcher_allowed_roots (launcher_id, root_path) VALUES (?, '/home/alice')`,
		launcherID,
	); err == nil {
		t.Error("expected UNIQUE(launcher_id, root_path) violation for duplicate root")
	}

	// A root for a nonexistent Launcher is rejected by the FK.
	if _, err := db.Exec(
		`INSERT INTO launcher_allowed_roots (launcher_id, root_path) VALUES ('dhl_missing', '/x')`,
	); err == nil || !strings.Contains(err.Error(), "FOREIGN KEY") {
		t.Errorf("expected FOREIGN KEY failure for nonexistent launcher, got: %v", err)
	}
}

// TestSessionsFinalSchemaInvariant protects the Stage 1.3 cutover boundary:
// after initializeDatabase on a fresh DB, sessions must carry launcher_id and
// must NOT carry principal_id. Legacy schemas are handled only by the
// classifier/migration path, never by re-adding principal_id to the live DDL.
func TestSessionsFinalSchemaInvariant(t *testing.T) {
	db := openFreshTestDB(t)

	var principalCol int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='principal_id'`,
	).Scan(&principalCol); err != nil {
		t.Fatalf("cannot inspect sessions schema: %v", err)
	}
	if principalCol != 0 {
		t.Errorf("expected final schema to NOT have principal_id, found %d", principalCol)
	}

	var launcherCol int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='launcher_id'`,
	).Scan(&launcherCol); err != nil {
		t.Fatalf("cannot inspect sessions schema: %v", err)
	}
	if launcherCol != 1 {
		t.Errorf("expected final schema to have launcher_id, found %d", launcherCol)
	}
}
