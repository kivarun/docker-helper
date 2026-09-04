package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestOpenDatabase(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Errorf("database not reachable after open: %v", err)
	}
}

func TestInitializeDatabase(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}
}

func TestSessionsTableExists(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions';").Scan(&name)
	if err != nil {
		t.Fatalf("sessions table not found: %v", err)
	}

	if name != "sessions" {
		t.Errorf("expected table name 'sessions', got %q", name)
	}
}

func TestInitializeDatabaseIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("first initializeDatabase() error: %v", err)
	}

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("second initializeDatabase() error: %v", err)
	}
}

// TestInitializeDatabaseRejectsLaunchersTableWithoutNameInvariant fails the
// startup initialization when the launchers table predates the Release 2.1
// launcher-name invariant (the shape written by intermediate unreleased 2.1
// development commits). The intermediate shape must really be unconstrained,
// so the fixture proves an invalid name inserts successfully there before the
// invariant check rejects the schema. Such a database is unsupported: the
// operator must restore a pre-2.1 backup or discard the state (see
// verifyLaunchersNameInvariant).
func TestInitializeDatabaseRejectsLaunchersTableWithoutNameInvariant(t *testing.T) {
	db := openFreshTestDB(t)

	insertTestPrincipal(t, db, "alice", 2001)
	if _, err := db.Exec(`DROP TABLE launchers`); err != nil {
		t.Fatalf("drop launchers: %v", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE launchers (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			scope_mode TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			UNIQUE (principal_id, name),
			CHECK (scope_mode IN ('inherit', 'restricted'))
		)`); err != nil {
		t.Fatalf("create pre-invariant launchers shape: %v", err)
	}

	// The pre-invariant shape does not enforce the grammar: prove it accepts
	// a name the invariant rejects, so the failure below is attributable to
	// the schema verification and not to the database.
	if _, err := db.Exec(
		`INSERT INTO launchers (id, principal_id, name, enabled, scope_mode, created_at)
		 VALUES ('dhl_' || printf('%032d', 0), (SELECT id FROM principals WHERE username = 'alice'), 'Foo', 1, 'inherit', 1000)`); err != nil {
		t.Fatalf("pre-invariant shape must accept grammar-invalid names: %v", err)
	}

	err := initializeDatabase(db)
	if err == nil {
		t.Fatal("initializeDatabase must fail closed on the pre-invariant launchers shape")
	}
	if !strings.Contains(err.Error(), "launcher-name invariant") {
		t.Errorf("actionable error expected, got: %v", err)
	}
}

// TestVerifyLaunchersNameInvariantRequiresCanonicalCheck proves the verifier
// matches the exact canonical CHECK expression rather than merely the grammar
// fragments occurring somewhere in the DDL: a reordered expression, fragments
// scattered across several weaker CHECK constraints, or a partial grammar all
// describe schemas this binary does not write and must fail closed, while the
// schema initializeDatabase actually writes is accepted.
func TestVerifyLaunchersNameInvariantRequiresCanonicalCheck(t *testing.T) {
	// The schema initializeDatabase writes must pass.
	canonical := openFreshTestDB(t)
	if err := verifyLaunchersNameInvariant(canonical); err != nil {
		t.Fatalf("canonical schema must pass: %v", err)
	}

	db := openFreshTestDB(t)
	openLaunchersFixture := func(t *testing.T, ddl string) {
		t.Helper()
		if _, err := db.Exec(`DROP TABLE launchers`); err != nil {
			t.Fatalf("drop launchers: %v", err)
		}
		if _, err := db.Exec(ddl); err != nil {
			t.Fatalf("create launchers fixture: %v", err)
		}
	}

	for _, tc := range []struct {
		name string
		ddl  string
	}{
		{
			name: "reordered clauses",
			ddl: `
		CREATE TABLE launchers (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			scope_mode TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			UNIQUE (principal_id, name),
			CHECK (scope_mode IN ('inherit', 'restricted')),
			CHECK (
				name NOT GLOB '-*'
				AND length(name) BETWEEN 1 AND 63
				AND name NOT GLOB '*-'
				AND name NOT GLOB '*[^a-z0-9-]*'
			)
		)`,
		},
		{
			name: "fragments scattered across several checks",
			ddl: `
		CREATE TABLE launchers (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 63),
			enabled INTEGER NOT NULL DEFAULT 1 CHECK (name NOT GLOB '*[^a-z0-9-]*'),
			scope_mode TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			UNIQUE (principal_id, name),
			CHECK (name NOT GLOB '-*'),
			CHECK (name NOT GLOB '*-'),
			CHECK (scope_mode IN ('inherit', 'restricted'))
		)`,
		},
		{
			name: "canonical check only inside a comment",
			ddl: `
		CREATE TABLE launchers (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			scope_mode TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			UNIQUE (principal_id, name),
			CHECK (scope_mode IN ('inherit', 'restricted'))
			-- CHECK (length(name) BETWEEN 1 AND 63 AND name NOT GLOB '*[^a-z0-9-]*' AND name NOT GLOB '-*' AND name NOT GLOB '*-')
		)`,
		},
		{
			name: "canonical text as a quoted constraint name",
			ddl: `
		CREATE TABLE launchers (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			scope_mode TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			CONSTRAINT "check(length(name)between1and63andnamenotglob'*[^a-z0-9-]*'andnamenotglob'-*'andnamenotglob'*-')" UNIQUE (principal_id, name),
			CHECK (scope_mode IN ('inherit', 'restricted'))
		)`,
		},
		{
			name: "partial grammar",
			ddl: `
		CREATE TABLE launchers (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			scope_mode TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			UNIQUE (principal_id, name),
			CHECK (scope_mode IN ('inherit', 'restricted')),
			CHECK (
				length(name) BETWEEN 1 AND 63
				AND name NOT GLOB '*[^a-z0-9-]*'
				AND name NOT GLOB '-*'
			)
		)`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			openLaunchersFixture(t, tc.ddl)
			err := verifyLaunchersNameInvariant(db)
			if err == nil {
				t.Fatal("expected verifyLaunchersNameInvariant to fail closed on a non-canonical launchers schema")
			}
			if !strings.Contains(err.Error(), "launcher-name invariant") {
				t.Errorf("actionable error expected, got: %v", err)
			}
		})
	}
}

func TestJournalModeWAL(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	var mode string
	err = db.QueryRow("PRAGMA journal_mode;").Scan(&mode)
	if err != nil {
		t.Fatalf("cannot query journal_mode: %v", err)
	}

	if mode != "wal" {
		t.Errorf("expected journal_mode 'wal', got %q", mode)
	}
}

func TestForeignKeyEnforcementPooledConnection(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(4)

	_, err = db.Exec("CREATE TABLE parent (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
	if err != nil {
		t.Fatalf("create parent table: %v", err)
	}

	_, err = db.Exec("CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL, FOREIGN KEY (parent_id) REFERENCES parent(id))")
	if err != nil {
		t.Fatalf("create child table: %v", err)
	}

	ctx := context.Background()

	conn1, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("db.Conn() error: %v", err)
	}
	defer conn1.Close()

	_, err = db.Exec("INSERT INTO parent (id, name) VALUES (1, 'parent1')")
	if err != nil {
		t.Fatalf("insert parent: %v", err)
	}

	_, err = db.Exec("INSERT INTO child (id, parent_id) VALUES (1, 999)")
	if err == nil {
		t.Fatal("expected foreign key constraint violation, got nil")
	}

	if !strings.Contains(err.Error(), "FOREIGN KEY constraint") {
		t.Fatalf("expected FOREIGN KEY constraint error, got: %v", err)
	}
}

func TestOpenDatabaseDSNSpecialCharacters(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test file?weird#hash.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() with special chars error: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("database not reachable: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database file not found at expected path: %v", err)
	}
}

func TestDatabaseClose(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	if err := db.Close(); err != nil {
		t.Fatalf("db.Close() error: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database file should exist after close: %v", err)
	}
}
