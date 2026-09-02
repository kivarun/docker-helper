package main

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// insertTestLauncher inserts a launcher for the given principal and returns its ID.
func insertTestLauncher(t *testing.T, db *sql.DB, principalID int64, name, scope string) string {
	t.Helper()
	id, err := generateLauncherID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO launchers (id, principal_id, name, enabled, scope_mode, created_at)
		 VALUES (?, ?, ?, 1, ?, 1000)`,
		id, principalID, name, scope,
	); err != nil {
		t.Fatalf("insert launcher: %v", err)
	}
	return id
}

func TestCredentialsFinalColumns(t *testing.T) {
	db := openFreshTestDB(t)

	for _, col := range []string{"id", "principal_id", "launcher_id", "name", "token_hash", "created_at", "revoked_at"} {
		var n int
		if err := db.QueryRow(
			`SELECT COUNT(*) FROM pragma_table_info('credentials') WHERE name=?`, col,
		).Scan(&n); err != nil {
			t.Fatalf("inspect credentials column %q: %v", col, err)
		}
		if n != 1 {
			t.Errorf("expected credentials column %q, not found", col)
		}
	}
}

// credentialsInsertResult reports whether an insert was allowed.
func tryInsertCredential(db *sql.DB, cols, vals string, args ...any) error {
	_, err := db.Exec(
		`INSERT INTO credentials (`+cols+`) VALUES (`+vals+`)`, args...,
	)
	return err
}

func TestCredentialsOwnerConstraints(t *testing.T) {
	db := openFreshTestDB(t)
	pid := insertTestPrincipal(t, db, "alice", 2001)
	launcherID := insertTestLauncher(t, db, pid, "default", "inherit")

	// Valid Principal credential.
	if err := tryInsertCredential(db,
		"id, principal_id, launcher_id, name, token_hash, created_at",
		"?, ?, ?, ?, ?, ?", "dhcr_p1", pid, nil, "pc", "hashP1", 1000,
	); err != nil {
		t.Errorf("valid Principal credential insert failed: %v", err)
	}

	// Valid Launcher credential.
	if err := tryInsertCredential(db,
		"id, principal_id, launcher_id, name, token_hash, created_at",
		"?, ?, ?, ?, ?, ?", "dhcr_l1", nil, launcherID, nil, "hashL1", 1001,
	); err != nil {
		t.Errorf("valid Launcher credential insert failed: %v", err)
	}

	// No owner fails.
	if err := tryInsertCredential(db,
		"id, principal_id, launcher_id, name, token_hash, created_at",
		"?, ?, ?, ?, ?, ?", "dhcr_none", nil, nil, nil, "hashNone", 1002,
	); err == nil {
		t.Error("expected CHECK failure for no-owner credential")
	}

	// Both owners fails.
	if err := tryInsertCredential(db,
		"id, principal_id, launcher_id, name, token_hash, created_at",
		"?, ?, ?, ?, ?, ?", "dhcr_both", pid, launcherID, nil, "hashBoth", 1003,
	); err == nil {
		t.Error("expected CHECK failure for both-owner credential")
	}

	// Principal credential with NULL name fails.
	if err := tryInsertCredential(db,
		"id, principal_id, launcher_id, name, token_hash, created_at",
		"?, ?, ?, ?, ?, ?", "dhcr_pnull", pid, nil, nil, "hashPNull", 1004,
	); err == nil {
		t.Error("expected CHECK failure for Principal credential with NULL name")
	}

	// Launcher credential with non-NULL name fails.
	if err := tryInsertCredential(db,
		"id, principal_id, launcher_id, name, token_hash, created_at",
		"?, ?, ?, ?, ?, ?", "dhcr_lnull", nil, launcherID, "some-name", "hashLNull", 1005,
	); err == nil {
		t.Error("expected CHECK failure for Launcher credential with non-NULL name")
	}
}

func TestCredentialsOneCredentialPerLauncher(t *testing.T) {
	db := openFreshTestDB(t)
	pid := insertTestPrincipal(t, db, "alice", 2001)
	launcherA := insertTestLauncher(t, db, pid, "a", "inherit")
	launcherB := insertTestLauncher(t, db, pid, "b", "inherit")

	insertFor := func(id string, launcher string) error {
		return tryInsertCredential(db,
			"id, principal_id, launcher_id, name, token_hash, created_at",
			"?, ?, ?, ?, ?, ?", id, nil, launcher, nil, "hash-"+id, 1000,
		)
	}

	if err := insertFor("dhcr_a1", launcherA); err != nil {
		t.Fatalf("insert first launcher credential: %v", err)
	}
	// A second credential for the same Launcher is rejected by UNIQUE(launcher_id).
	if err := insertFor("dhcr_a2", launcherA); err == nil {
		t.Error("expected UNIQUE(launcher_id) violation for second credential on one launcher")
	}
	// Two different Launchers may each own one credential.
	if err := insertFor("dhcr_b1", launcherB); err != nil {
		t.Errorf("expected second launcher to own a credential, got: %v", err)
	}
}

// TestMigrateV2CredentialsPreservation builds a faithful v2.0 credentials schema
// (Principal-only, partial active-name index), inserts representative Principal
// credentials, migrates, and proves every row is preserved exactly with
// launcher_id NULL and a clean foreign-key check.
func TestMigrateV2CredentialsPreservation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}

	// Deliberate v2.0 schema fixture (not what initializeDatabase currently
	// creates — an independent representation of the shipped v2.0 contract).
	if _, err := db.Exec(`
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
		CREATE UNIQUE INDEX credentials_active_name_unique
			ON credentials(principal_id, name) WHERE revoked_at IS NULL;
	`); err != nil {
		t.Fatalf("create v2.0 schema: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO principals (username, uid, gid, home, enabled) VALUES ('alice', 2001, 2001, '/home/alice', 1)`,
	); err != nil {
		t.Fatalf("insert principal: %v", err)
	}

	type row struct {
		id, principalID, name, tokenHash string
		createdAt, revokedAt             sql.NullInt64
	}
	rows := []row{
		{"dhcr_active", "1", "main", "activehash", int64OrNull(5000), nullOrInt(0)},
		{"dhcr_revoked", "1", "old", "revokedhash", int64OrNull(4000), int64OrNull(4500)},
		{"dhcr_second", "1", "deploy", "secondhash", int64OrNull(5100), nullOrInt(0)},
	}
	for _, r := range rows {
		if _, err := db.Exec(
			`INSERT INTO credentials (id, principal_id, name, token_hash, created_at, revoked_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			r.id, r.principalID, r.name, r.tokenHash, r.createdAt, r.revokedAt,
		); err != nil {
			t.Fatalf("insert credential %s: %v", r.id, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen and migrate.
	db, err = openDatabase(path)
	if err != nil {
		t.Fatalf("reopenDatabase() error: %v", err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	// Every row still exists, exactly preserved, launcher_id NULL.
	for _, r := range rows {
		var got row
		var launcherID sql.NullString
		err := db.QueryRow(
			`SELECT id, principal_id, name, token_hash, created_at, revoked_at, launcher_id
			 FROM credentials WHERE id=?`, r.id,
		).Scan(&got.id, &got.principalID, &got.name, &got.tokenHash, &got.createdAt, &got.revokedAt, &launcherID)
		if err != nil {
			t.Fatalf("credential %s missing after migration: %v", r.id, err)
		}
		if got != r {
			t.Errorf("credential %s changed: got %+v want %+v", r.id, got, r)
		}
		if launcherID.Valid {
			t.Errorf("credential %s must have launcher_id NULL, got %q", r.id, launcherID.String)
		}
	}

	// No Launcher credential was fabricated.
	var launcherCreds int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM credentials WHERE launcher_id IS NOT NULL`,
	).Scan(&launcherCreds); err != nil {
		t.Fatalf("count launcher credentials: %v", err)
	}
	if launcherCreds != 0 {
		t.Errorf("expected 0 launcher credentials after migration, got %d", launcherCreds)
	}

	// foreign_key_check must be clean.
	assertForeignKeysClean(t, db)

	// Idempotence: running again must not mutate rows or schema.
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("second initializeDatabase() error: %v", err)
	}
	for _, r := range rows {
		var got row
		var launcherID sql.NullString
		if err := db.QueryRow(
			`SELECT id, principal_id, name, token_hash, created_at, revoked_at, launcher_id
			 FROM credentials WHERE id=?`, r.id,
		).Scan(&got.id, &got.principalID, &got.name, &got.tokenHash, &got.createdAt, &got.revokedAt, &launcherID); err != nil {
			t.Fatalf("credential %s missing after idempotent run: %v", r.id, err)
		}
		if got != r || launcherID.Valid {
			t.Errorf("credential %s mutated by idempotent run: got %+v launcher=%v", r.id, got, launcherID.Valid)
		}
	}
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM credentials`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != len(rows) {
		t.Errorf("expected %d rows after idempotent run, got %d", len(rows), total)
	}
}

func TestMigrateHistoricalHardUniqueCompat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}

	// Historical schema with table-level UNIQUE(principal_id, name).
	if _, err := db.Exec(`
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
	`); err != nil {
		t.Fatalf("create historical schema: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO principals (username, uid, gid, home, enabled) VALUES ('alice', 2001, 2001, '/home/alice', 1)`,
	); err != nil {
		t.Fatalf("insert principal: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO credentials (id, principal_id, name, token_hash, created_at, revoked_at)
		 VALUES ('dhcr_hist', 1, 'oc', 'histhash', 1000, 2000)`,
	); err != nil {
		t.Fatalf("insert revoked credential: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = openDatabase(path)
	if err != nil {
		t.Fatalf("reopenDatabase() error: %v", err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	// Data preserved.
	var revokedAt sql.NullInt64
	if err := db.QueryRow(`SELECT revoked_at FROM credentials WHERE id='dhcr_hist'`).Scan(&revokedAt); err != nil {
		t.Fatalf("historical credential missing: %v", err)
	}
	if !revokedAt.Valid {
		t.Error("expected historical credential to remain revoked")
	}

	// The old table-level hard UNIQUE is gone; uniqueness is the partial index.
	var ddl string
	if err := db.QueryRow(
		`SELECT sql FROM sqlite_master WHERE type='table' AND name='credentials'`,
	).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(ddl), "unique(principal_id,name)") {
		t.Error("table-level UNIQUE(principal_id, name) must be gone after migration")
	}

	// After revoking an old credential, a new active credential with the same
	// name can be created (name reuse).
	cred, _, err := createCredential(db, "alice", "oc")
	if err != nil {
		t.Fatalf("create same-name after upgrade: %v", err)
	}
	if cred.ID == "dhcr_hist" {
		t.Error("new credential must have a distinct ID")
	}

	// Two simultaneous active credentials with the same name are rejected.
	if _, _, err := createCredential(db, "alice", "oc"); err == nil {
		t.Error("expected duplicate active name to be rejected")
	}

	assertForeignKeysClean(t, db)
}

// assertForeignKeysClean fails if PRAGMA foreign_key_check reports any row.
func assertForeignKeysClean(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate foreign_key_check: %v", err)
	}
	if n != 0 {
		t.Errorf("foreign_key_check reported %d violation(s)", n)
	}
}

func int64OrNull(v int64) sql.NullInt64 { return sql.NullInt64{Int64: v, Valid: true} }
func nullOrInt(v int64) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: v, Valid: true}
}

// TestCredentialsSchemaClassifierSupported verifies the classifier accepts both
// the pre-2.1 Principal-only source schema and the valid final concrete-owner
// schema.
func TestCredentialsSchemaClassifierSupported(t *testing.T) {
	// Case 1: old Principal-only schema classifies as a migration source.
	dir := t.TempDir()
	db, err := openDatabase(dir + "/test.db")
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	if _, err := db.Exec(`
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
	`); err != nil {
		t.Fatalf("create v2.0 schema: %v", err)
	}
	class, err := classifyCredentialsSchema(db)
	if err != nil {
		t.Fatalf("classify pre-2.1 schema: %v", err)
	}
	if class != credentialsSchemaPre21 {
		t.Errorf("expected pre-2.1 class, got %v", class)
	}
	db.Close()

	// Case 2: valid final schema classifies as final and stays untouched.
	final := openFreshTestDB(t)
	class, err = classifyCredentialsSchema(final)
	if err != nil {
		t.Fatalf("classify final schema: %v", err)
	}
	if class != credentialsSchemaFinal {
		t.Errorf("expected final class, got %v", class)
	}
	// A valid final schema must not be mutated by a repeated migration.
	if err := migrateCredentialsToConcreteOwnerSchema(final); err != nil {
		t.Fatalf("re-migrate final schema: %v", err)
	}
	if class, err = classifyCredentialsSchema(final); err != nil {
		t.Fatalf("reclassify final schema: %v", err)
	}
	if class != credentialsSchemaFinal {
		t.Errorf("expected final class after re-migrate, got %v", class)
	}
}

// mustFailClosedOnCredentialsSchema builds a credentials table with the given
// DDL and asserts initializeDatabase fails closed with a clear
// "unsupported credentials schema" error rather than accepting or normalizing it.
func mustFailClosedOnCredentialsSchema(t *testing.T, ddl string) {
	t.Helper()
	dir := t.TempDir()
	db, err := openDatabase(dir + "/test.db")
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(ddl); err != nil {
		t.Fatalf("create credentials schema: %v", err)
	}
	err = initializeDatabase(db)
	if err == nil {
		t.Fatalf("expected initializeDatabase to fail closed on unsupported credentials schema")
	}
	if !strings.Contains(err.Error(), "unsupported credentials schema") {
		t.Errorf("expected clear unsupported credentials schema error, got: %v", err)
	}
}

// TestCredentialsSchemaPartialLauncherFailsClosed: launcher_id added manually
// but the final constraints (nullable owner/name, FKs, UNIQUE, CHECK) are
// absent. The database must fail closed rather than accept it as final.
func TestCredentialsSchemaPartialLauncherFailsClosed(t *testing.T) {
	mustFailClosedOnCredentialsSchema(t, `
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			launcher_id TEXT,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE
		);
	`)
}

// TestCredentialsSchemaLauncherFKMissingFailsClosed: launcher_id present but the
// launcher_id foreign key is missing.
func TestCredentialsSchemaLauncherFKMissingFailsClosed(t *testing.T) {
	mustFailClosedOnCredentialsSchema(t, `
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER,
			launcher_id TEXT,
			name TEXT,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			UNIQUE (launcher_id),
			CHECK (
				(principal_id IS NOT NULL AND launcher_id IS NULL AND name IS NOT NULL)
				OR
				(principal_id IS NULL AND launcher_id IS NOT NULL AND name IS NULL)
			)
		);
	`)
}

// TestCredentialsSchemaLauncherUniqueMissingFailsClosed: launcher_id present but
// UNIQUE(launcher_id) is missing.
func TestCredentialsSchemaLauncherUniqueMissingFailsClosed(t *testing.T) {
	mustFailClosedOnCredentialsSchema(t, `
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER,
			launcher_id TEXT,
			name TEXT,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE CASCADE,
			CHECK (
				(principal_id IS NOT NULL AND launcher_id IS NULL AND name IS NOT NULL)
				OR
				(principal_id IS NULL AND launcher_id IS NOT NULL AND name IS NULL)
			)
		);
	`)
}

// TestCredentialsSchemaCheckMissingFailsClosed: launcher_id present but the
// concrete-owner CHECK is missing.
func TestCredentialsSchemaCheckMissingFailsClosed(t *testing.T) {
	mustFailClosedOnCredentialsSchema(t, `
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER,
			launcher_id TEXT,
			name TEXT,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE CASCADE,
			UNIQUE (launcher_id)
		);
	`)
}

// TestCredentialsSchemaExtraColumnFailsClosed: an unsupported pre-2.1 schema
// with an unexpected extra column must fail closed rather than silently
// dropping that column through migration.
func TestCredentialsSchemaExtraColumnFailsClosed(t *testing.T) {
	mustFailClosedOnCredentialsSchema(t, `
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER,
			extra_column TEXT
		);
	`)
}

// TestCredentialsSchemaFKNoActionFailsClosed: the final schema with an owner
// foreign key that uses the default NO ACTION (instead of ON DELETE CASCADE)
// must fail closed. ON DELETE CASCADE is canonical.
func TestCredentialsSchemaFKNoActionFailsClosed(t *testing.T) {
	mustFailClosedOnCredentialsSchema(t, `
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER,
			launcher_id TEXT,
			name TEXT,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER,
			FOREIGN KEY (principal_id) REFERENCES principals(id),
			FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE CASCADE,
			UNIQUE (launcher_id),
			CHECK (
				(principal_id IS NOT NULL AND launcher_id IS NULL AND name IS NOT NULL)
				OR
				(principal_id IS NULL AND launcher_id IS NOT NULL AND name IS NULL)
			)
		);
	`)
}

// TestCredentialsPre21MissingTokenHashUniqueFailsClosed: a pre-2.1 Principal-only
// lookalike without UNIQUE(token_hash) must fail closed.
func TestCredentialsPre21MissingTokenHashUniqueFailsClosed(t *testing.T) {
	mustFailClosedOnCredentialsSchema(t, `
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE
		);
	`)
}

// TestCredentialsPre21MissingPrincipalFKFailsClosed: a pre-2.1 Principal-only
// lookalike without the principal_id -> principals(id) foreign key must fail
// closed.
func TestCredentialsPre21MissingPrincipalFKFailsClosed(t *testing.T) {
	mustFailClosedOnCredentialsSchema(t, `
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER
		);
	`)
}

// TestCredentialsSchemaOwnerCheckOrOneFailsClosed: the owner CHECK with an
// added `OR 1=1` (which changes validity) must fail closed, even though both
// canonical branch substrings are present in the DDL.
func TestCredentialsSchemaOwnerCheckOrOneFailsClosed(t *testing.T) {
	mustFailClosedOnCredentialsSchema(t, `
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER,
			launcher_id TEXT,
			name TEXT,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE CASCADE,
			UNIQUE (launcher_id),
			CHECK (
				(principal_id IS NOT NULL AND launcher_id IS NULL AND name IS NOT NULL)
				OR
				(principal_id IS NULL AND launcher_id IS NOT NULL AND name IS NULL)
				OR 1=1
			)
		);
	`)
}

// TestCredentialsSchemaExtraCheckFailsClosed: the final schema with an
// additional contradictory CHECK that changes credential cardinality/validity
// must fail closed.
func TestCredentialsSchemaExtraCheckFailsClosed(t *testing.T) {
	mustFailClosedOnCredentialsSchema(t, `
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER,
			launcher_id TEXT,
			name TEXT,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE CASCADE,
			UNIQUE (launcher_id),
			CHECK (
				(principal_id IS NOT NULL AND launcher_id IS NULL AND name IS NOT NULL)
				OR
				(principal_id IS NULL AND launcher_id IS NOT NULL AND name IS NULL)
			),
			CHECK (name IS NOT NULL OR launcher_id IS NOT NULL)
		);
	`)
}

// TestCredentialsSchemaExtraUniquePrincipalFailsClosed: the final schema with an
// additional UNIQUE(principal_id) that changes the credential cardinality
// contract must fail closed.
func TestCredentialsSchemaExtraUniquePrincipalFailsClosed(t *testing.T) {
	mustFailClosedOnCredentialsSchema(t, `
		CREATE TABLE credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER,
			launcher_id TEXT,
			name TEXT,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE CASCADE,
			UNIQUE (launcher_id),
			UNIQUE (principal_id),
			CHECK (
				(principal_id IS NOT NULL AND launcher_id IS NULL AND name IS NOT NULL)
				OR
				(principal_id IS NULL AND launcher_id IS NOT NULL AND name IS NULL)
			)
		);
	`)
}
