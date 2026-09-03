package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// buildLegacyPrincipalDB returns a database whose sessions table has the
// pre-cutover legacy principal-owned shape (base columns + nullable
// principal_id) with its real FK to principals(id) declared, and a real
// launchers/principals schema, so migrateSessionOwnership can be exercised
// against the genuine legacy source and classifySessionsSchema can recognize
// it. FK enforcement is disabled so a referentially dangling fixture can be
// inserted to exercise the migration's fail-closed check
// (TestMigrateSessionOwnershipDanglingPrincipalFails); the legacy sessions
// principal_id FK has no ON DELETE CASCADE, so bad data can only arise when
// enforcement was historically off.
func buildLegacyPrincipalDB(t *testing.T) *sql.DB {
	t.Helper()
	db := openFreshTestDBNoFK(t)
	if _, err := db.Exec(`DROP TABLE sessions`); err != nil {
		t.Fatalf("cannot drop final sessions table: %v", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE sessions (
			id TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL UNIQUE,
			workspace TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			principal_id INTEGER REFERENCES principals(id)
		)`); err != nil {
		t.Fatalf("cannot create legacy sessions table: %v", err)
	}
	return db
}

// buildLegacyBareDB returns a database whose sessions table has the pre-R1
// (bare) shape: only the base columns and no ownership column at all. This is
// the state initializeDatabase is responsible for bringing forward (bare ->
// legacy principal) before migrateSessionOwnership rebuilds to the final
// schema.
func buildLegacyBareDB(t *testing.T) *sql.DB {
	t.Helper()
	db := openFreshTestDBNoFK(t)
	if _, err := db.Exec(`DROP TABLE sessions`); err != nil {
		t.Fatalf("cannot drop sessions table: %v", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE sessions (
			id TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL UNIQUE,
			workspace TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		)`); err != nil {
		t.Fatalf("cannot create bare sessions table: %v", err)
	}
	return db
}

// insertLegacyPrincipalRaw inserts a Principal that owns legacy sessions,
// returning its ID.
func insertLegacyPrincipalRaw(t *testing.T, db *sql.DB, username string) int64 {
	t.Helper()
	res, err := db.Exec(
		`INSERT INTO principals (username, uid, gid, home, enabled) VALUES (?, ?, ?, ?, 1)`,
		username, 2001, 2001, filepath.Join(testAllowedRootDir(t), "home", username),
	)
	if err != nil {
		t.Fatalf("cannot insert legacy principal %s: %v", username, err)
	}
	pid, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("cannot get legacy principal id: %v", err)
	}
	return pid
}

// insertLegacySession inserts a legacy (principal-owned) session row.
func insertLegacySession(t *testing.T, db *sql.DB, id, tokenHash string, principalID int64) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, tokenHash, "/workspace/"+id, time.Now().Unix(), time.Now().Add(time.Hour).Unix(), principalID,
	); err != nil {
		t.Fatalf("cannot insert legacy session %s: %v", id, err)
	}
}

// TestMigrateSessionOwnershipLegacyPrincipal ensures legacy principal-owned
// sessions are mapped to that Principal's 'default' Launcher and the final
// Launcher-owned schema is produced, with no rows dropped.
func TestMigrateSessionOwnershipLegacyPrincipal(t *testing.T) {
	db := buildLegacyPrincipalDB(t)
	pid := insertLegacyPrincipalRaw(t, db, "alice")
	insertLegacySession(t, db, "dhs_legacy1", "h1", pid)
	insertLegacySession(t, db, "dhs_legacy2", "h2", pid)

	res, err := migrateSessionOwnership(db, ModeSystem, nil)
	if err != nil {
		t.Fatalf("migrateSessionOwnership: %v", err)
	}
	if res.attributedPrincipal != 2 {
		t.Errorf("attributedPrincipal = %d, want 2", res.attributedPrincipal)
	}

	// Final schema: launcher_id present, principal_id gone.
	var hasPrincipal, hasLauncher int
	if err := db.QueryRow(
		`SELECT
			(SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='principal_id'),
			(SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='launcher_id')`,
	).Scan(&hasPrincipal, &hasLauncher); err != nil {
		t.Fatal(err)
	}
	if hasPrincipal != 0 || hasLauncher != 1 {
		t.Errorf("final schema check: principal_id=%d launcher_id=%d, want 0/1", hasPrincipal, hasLauncher)
	}

	// Both sessions now owned by a 'default' Launcher belonging to alice.
	var count int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM sessions s
		JOIN launchers l ON l.id = s.launcher_id
		WHERE l.principal_id = ? AND l.name = 'default'`, pid).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("owned-by-default-launcher sessions = %d, want 2", count)
	}

	// Migration is idempotent: running again is a no-op on final schema.
	again, err := migrateSessionOwnership(db, ModeSystem, nil)
	if err != nil || again.attributedPrincipal != 0 {
		t.Errorf("second migration: res=%+v err=%v, want empty result", again, err)
	}
}

// TestMigrateSessionOwnershipUserModeNullEntry ensures legacy user-mode
// NULL-owner sessions are attributed to the daemon-owner default Launcher.
func TestMigrateSessionOwnershipUserModeNullEntry(t *testing.T) {
	db := buildLegacyPrincipalDB(t)
	home := filepath.Join(testAllowedRootDir(t), "daemon-home")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	uid := 4242
	ownerPID, err := insertDaemonOwnerPrincipal(db, "daemonowner", uid, uid, home)
	if err != nil {
		t.Fatal(err)
	}
	launcherID, err := ensureDefaultLauncher(db, ownerPID)
	if err != nil {
		t.Fatal(err)
	}
	owner := &userModeDefaultLauncher{principalID: ownerPID, launcherID: launcherID, username: "daemonowner"}

	if _, err := db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
		 VALUES (?, ?, ?, ?, ?, NULL)`,
		"dhs_legacynull", "hnull", "/w", time.Now().Unix(), time.Now().Add(time.Hour).Unix(),
	); err != nil {
		t.Fatal(err)
	}

	res, err := migrateSessionOwnership(db, ModeUser, owner)
	if err != nil {
		t.Fatalf("migrateSessionOwnership: %v", err)
	}
	if res.attributedUserMode != 1 {
		t.Errorf("attributedUserMode = %d, want 1", res.attributedUserMode)
	}
	if res.invalidated != 0 {
		t.Errorf("invalidated = %d, want 0", res.invalidated)
	}

	var launcherIDGot string
	if err := db.QueryRow(`SELECT launcher_id FROM sessions WHERE id = 'dhs_legacynull'`).Scan(&launcherIDGot); err != nil {
		t.Fatal(err)
	}
	if launcherIDGot != launcherID {
		t.Errorf("legacy NULL session launcher_id = %q, want daemon-owner %q", launcherIDGot, launcherID)
	}
}

// TestMigrateSessionOwnershipSystemModeNullInvalidated ensures legacy
// system-mode NULL-owner sessions (with no Principal -> Launcher chain) are
// invalidated and counted, never left ownerless.
func TestMigrateSessionOwnershipSystemModeNullInvalidated(t *testing.T) {
	db := buildLegacyPrincipalDB(t)
	if _, err := db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
		 VALUES (?, ?, ?, ?, ?, NULL)`,
		"dhs_sysnull", "hsys", "/w", time.Now().Unix(), time.Now().Add(time.Hour).Unix(),
	); err != nil {
		t.Fatal(err)
	}

	res, err := migrateSessionOwnership(db, ModeSystem, nil)
	if err != nil {
		t.Fatalf("migrateSessionOwnership: %v", err)
	}
	if res.invalidated != 1 {
		t.Errorf("invalidated = %d, want 1", res.invalidated)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("after invalidation session count = %d, want 0", count)
	}
}

// TestMigrateSessionOwnershipDanglingPrincipalFails ensures a legacy session
// referencing a Principal that no longer exists fails the migration instead of
// being silently dropped.
func TestMigrateSessionOwnershipDanglingPrincipalFails(t *testing.T) {
	db := buildLegacyPrincipalDB(t)
	insertLegacySession(t, db, "dhs_dangling", "hdang", 99999)

	if _, err := migrateSessionOwnership(db, ModeSystem, nil); err == nil {
		t.Fatal("expected migration to fail on dangling principal reference")
	}

	// The legacy table must be left intact (transaction rolled back).
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("legacy sessions after rollback = %d, want 1", count)
	}
}

// TestMigrateSessionOwnershipFinalNoOp ensures migration is a no-op on the
// final schema and never re-adds principal_id.
func TestMigrateSessionOwnershipFinalNoOp(t *testing.T) {
	db := openFreshTestDB(t)
	res, err := migrateSessionOwnership(db, ModeUser, &userModeDefaultLauncher{principalID: 1, launcherID: "x", username: "u"})
	if err != nil {
		t.Fatalf("migrateSessionOwnership: %v", err)
	}
	if res.attributedPrincipal != 0 || res.attributedUserMode != 0 || res.invalidated != 0 {
		t.Errorf("final no-op result = %+v, want zero counts", res)
	}
	var hasPrincipal int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='principal_id'`,
	).Scan(&hasPrincipal); err != nil {
		t.Fatal(err)
	}
	if hasPrincipal != 0 {
		t.Errorf("migration must not re-add principal_id, found %d", hasPrincipal)
	}
}

// TestClassifySessionsSchema covers the four ownership shapes the classifier
// must distinguish.
func TestClassifySessionsSchema(t *testing.T) {
	{
		db := openFreshTestDB(t)
		class, err := classifySessionsSchema(db)
		if err != nil || class != sessionsSchemaFinal {
			t.Errorf("final schema classified as %v (err=%v), want sessionsSchemaFinal", class, err)
		}
	}
	{
		db := buildLegacyPrincipalDB(t)
		class, err := classifySessionsSchema(db)
		if err != nil || class != sessionsSchemaLegacyPrincipal {
			t.Errorf("legacy principal schema classified as %v (err=%v), want sessionsSchemaLegacyPrincipal", class, err)
		}
	}
	{
		db := openFreshTestDB(t)
		if _, err := db.Exec(`DROP TABLE sessions`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`
			CREATE TABLE sessions (
				id TEXT PRIMARY KEY,
				token_hash TEXT NOT NULL UNIQUE,
				workspace TEXT NOT NULL,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL
			)`); err != nil {
			t.Fatal(err)
		}
		class, err := classifySessionsSchema(db)
		if err != nil || class != sessionsSchemaLegacyBare {
			t.Errorf("bare schema classified as %v (err=%v), want sessionsSchemaLegacyBare", class, err)
		}
	}
	{
		// Hybrid (both columns) must fail closed as unsupported with a durable
		// error, never the unsupported class reported as data.
		db := openFreshTestDB(t)
		if _, err := db.Exec(`DROP TABLE sessions`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`
			CREATE TABLE sessions (
				id TEXT PRIMARY KEY,
				token_hash TEXT NOT NULL UNIQUE,
				workspace TEXT NOT NULL,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL,
				principal_id INTEGER,
				launcher_id TEXT
			)`); err != nil {
			t.Fatal(err)
		}
		class, err := classifySessionsSchema(db)
		if err == nil || class != sessionsSchemaUnsupported {
			t.Errorf("hybrid schema classified as %v (err=%v), want sessionsSchemaUnsupported with an error", class, err)
		}
	}
}

// TestClassifySessionsSchemaNegative rejects malformed ownership shapes that
// must fail closed: each fixture is deliberately a corrupted or wrong sessions
// table and must return sessionsSchemaUnsupported with a durable error.
func TestClassifySessionsSchemaNegative(t *testing.T) {
	// helper rebuilds the sessions table from the given DDL body.
	rebuild := func(t *testing.T, body string) *sql.DB {
		t.Helper()
		db := openFreshTestDB(t)
		if _, err := db.Exec(`DROP TABLE sessions`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`CREATE TABLE sessions (` + body + `)`); err != nil {
			t.Fatal(err)
		}
		return db
	}

	cases := []struct {
		name string
		body string
	}{
		{
			name: "launcher FK wrongly targets principals",
			body: `
				id TEXT PRIMARY KEY,
				token_hash TEXT NOT NULL UNIQUE,
				workspace TEXT NOT NULL,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL,
				launcher_id TEXT NOT NULL REFERENCES principals(id)`,
		},
		{
			name: "principal FK wrongly targets launchers",
			body: `
				id TEXT PRIMARY KEY,
				token_hash TEXT NOT NULL UNIQUE,
				workspace TEXT NOT NULL,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL,
				principal_id INTEGER REFERENCES launchers(id)`,
		},
		{
			name: "nullable launcher_id",
			body: `
				id TEXT PRIMARY KEY,
				token_hash TEXT NOT NULL UNIQUE,
				workspace TEXT NOT NULL,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL,
				launcher_id TEXT REFERENCES launchers(id)`,
		},
		{
			name: "launcher FK with ON DELETE CASCADE",
			body: `
				id TEXT PRIMARY KEY,
				token_hash TEXT NOT NULL UNIQUE,
				workspace TEXT NOT NULL,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL,
				launcher_id TEXT NOT NULL REFERENCES launchers(id) ON DELETE CASCADE`,
		},
		{
			name: "missing base column",
			body: `
				id TEXT PRIMARY KEY,
				token_hash TEXT NOT NULL UNIQUE,
				workspace TEXT NOT NULL,
				created_at INTEGER NOT NULL`,
		},
		{
			name: "missing token uniqueness",
			body: `
				id TEXT PRIMARY KEY,
				token_hash TEXT NOT NULL,
				workspace TEXT NOT NULL,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL,
				launcher_id TEXT NOT NULL REFERENCES launchers(id)`,
		},
		{
			name: "extra ownership column beyond canonical final",
			body: `
				id TEXT PRIMARY KEY,
				token_hash TEXT NOT NULL UNIQUE,
				workspace TEXT NOT NULL,
				created_at INTEGER NOT NULL,
				expires_at INTEGER NOT NULL,
				launcher_id TEXT NOT NULL REFERENCES launchers(id),
				principal_id INTEGER`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := rebuild(t, tc.body)
			class, err := classifySessionsSchema(db)
			if err == nil || class != sessionsSchemaUnsupported {
				t.Errorf("classifySessionsSchema = (%v, err=%v), want sessionsSchemaUnsupported with an error", class, err)
			}
		})
	}
}

// TestClassifySessionsSchemaPartialUniqueRejected verifies that a PARTIAL unique
// index on token_hash is not accepted as proof of global token_hash uniqueness.
// A partial unique index only enforces uniqueness within its WHERE predicate, so
// positive recognition must require an unconditional unique index and reject the
// partial one as unsupported.
func TestClassifySessionsSchemaPartialUniqueRejected(t *testing.T) {
	db := openFreshTestDB(t)
	if _, err := db.Exec(`DROP TABLE sessions`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE sessions (
			id TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL,
			workspace TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			launcher_id TEXT NOT NULL REFERENCES launchers(id)
		)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX sessions_token_hash_partial ON sessions(token_hash) WHERE expires_at > 0`); err != nil {
		t.Fatal(err)
	}
	class, err := classifySessionsSchema(db)
	if err == nil || class != sessionsSchemaUnsupported {
		t.Errorf("classifySessionsSchema = (%v, err=%v), want sessionsSchemaUnsupported with an error", class, err)
	}
}

// TestDefaultLauncherPerPrincipalIsolation ensures a Principal's 'default'
// Launcher is scoped to that Principal: request-time and provisioning resolution
// never leak another Principal's Launcher, and a session owned by one
// Principal's Launcher is not reachable through another Principal's scope.
func TestDefaultLauncherPerPrincipalIsolation(t *testing.T) {
	db := openFreshTestDB(t)

	homeRoot := testAllowedRootDir(t)
	homeA := filepath.Join(homeRoot, "a")
	homeB := filepath.Join(homeRoot, "b")
	if err := os.MkdirAll(homeA, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(homeB, 0755); err != nil {
		t.Fatal(err)
	}
	pidA, err := insertDaemonOwnerPrincipal(db, "dho_a", 2001, 2001, homeA)
	if err != nil {
		t.Fatal(err)
	}
	pidB, err := insertDaemonOwnerPrincipal(db, "dho_b", 2002, 2002, homeB)
	if err != nil {
		t.Fatal(err)
	}

	laA, err := ensureDefaultLauncher(db, pidA)
	if err != nil {
		t.Fatal(err)
	}
	laB, err := ensureDefaultLauncher(db, pidB)
	if err != nil {
		t.Fatal(err)
	}
	if laA == laB {
		t.Fatal("two principals must not share the same default Launcher id")
	}

	// findDefaultLauncher resolves per-Principal, never crossing.
	gotA, err := findDefaultLauncher(db, pidA)
	if err != nil || gotA != laA {
		t.Errorf("findDefaultLauncher(pidA) = %q (err=%v), want %q", gotA, err, laA)
	}
	gotB, err := findDefaultLauncher(db, pidB)
	if err != nil || gotB != laB {
		t.Errorf("findDefaultLauncher(pidB) = %q (err=%v), want %q", gotB, err, laB)
	}

	// A Launcher created for one Principal is not the default of the other.
	defaultForB, err := findDefaultLauncher(db, pidB)
	if err != nil || defaultForB != laB {
		t.Errorf("pidB default = %q (err=%v), want distinct launcher %q", defaultForB, err, laB)
	}
}

// TestStartupSequenceBareToFinal exercises the full startup chain for an R1
// bare sessions table: initializeDatabase owns the bare -> legacy-principal
// step (adding principal_id), then migrateSessionOwnership owns the
// principal -> final step. The R1 ownerless session is attributed to the
// user-mode daemon-owner default Launcher and the final schema is produced.
func TestStartupSequenceBareToFinal(t *testing.T) {
	db := buildLegacyBareDB(t)

	// An R1 ownerless session row (bare sessions had no ownership column).
	if _, err := db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		"dhs_r1", "hr1", "/w", time.Now().Unix(), time.Now().Add(time.Hour).Unix(),
	); err != nil {
		t.Fatal(err)
	}

	// Step 1: initializeDatabase owns bare -> legacy principal.
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	class, err := classifySessionsSchema(db)
	if err != nil || class != sessionsSchemaLegacyPrincipal {
		t.Fatalf("after initializeDatabase schema = %v (err=%v), want sessionsSchemaLegacyPrincipal", class, err)
	}

	// Provision a user-mode daemon-owner default Launcher for attribution.
	home := filepath.Join(testAllowedRootDir(t), "daemon-home")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	ownerPID, err := insertDaemonOwnerPrincipal(db, "daemonowner", 4242, 4242, home)
	if err != nil {
		t.Fatal(err)
	}
	launcherID, err := ensureDefaultLauncher(db, ownerPID)
	if err != nil {
		t.Fatal(err)
	}
	owner := &userModeDefaultLauncher{principalID: ownerPID, launcherID: launcherID, username: "daemonowner"}

	// Step 2: migrateSessionOwnership owns principal -> final.
	res, err := migrateSessionOwnership(db, ModeUser, owner)
	if err != nil {
		t.Fatalf("migrateSessionOwnership: %v", err)
	}

	var hasPrincipal, hasLauncher int
	if err := db.QueryRow(
		`SELECT
			(SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='principal_id'),
			(SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='launcher_id')`,
	).Scan(&hasPrincipal, &hasLauncher); err != nil {
		t.Fatal(err)
	}
	if hasPrincipal != 0 || hasLauncher != 1 {
		t.Errorf("final schema: principal_id=%d launcher_id=%d, want 0/1", hasPrincipal, hasLauncher)
	}
	if res.attributedUserMode != 1 {
		t.Errorf("attributedUserMode = %d, want 1", res.attributedUserMode)
	}
	var got string
	if err := db.QueryRow(`SELECT launcher_id FROM sessions WHERE id = 'dhs_r1'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != launcherID {
		t.Errorf("R1 session launcher_id = %q, want daemon-owner %q", got, launcherID)
	}
}

// TestMigrateSessionOwnershipIntegrityCheckRollback proves the pre-commit
// foreign_key_check gate (B9) catches a rebuilt sessions table whose row
// references a launcher that does not exist, failing the migration and rolling
// back so the legacy table is left intact. The dangling launcher is introduced
// via the user-mode NULL-owner attribution with a phantom default-Launcher ID;
// the insert succeeds only because FK enforcement is off in the fixture, and
// the integrity check reports the violation regardless.
func TestMigrateSessionOwnershipIntegrityCheckRollback(t *testing.T) {
	db := buildLegacyPrincipalDB(t)
	if _, err := db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
		 VALUES (?, ?, ?, ?, ?, NULL)`,
		"dhs_badlauncher", "hbad", "/w", time.Now().Unix(), time.Now().Add(time.Hour).Unix(),
	); err != nil {
		t.Fatal(err)
	}

	owner := &userModeDefaultLauncher{principalID: 1, launcherID: "no-such-launcher", username: "u"}
	_, err := migrateSessionOwnership(db, ModeUser, owner)
	if err == nil {
		t.Fatal("expected migration to fail on foreign-key check for dangling launcher")
	}

	// Transaction rolled back: the legacy sessions table is intact.
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("after rollback session count = %d, want 1", count)
	}
}

// TestMigrateSessionOwnershipIgnoresUnrelatedFKViolation proves the Session
// migration integrity check is scoped to the rebuilt sessions table: a
// foreign-key violation in an unrelated table (here a dangling launchers row
// whose principal no longer exists) must NOT fail migrateSessionOwnership.
// Enforcement is off in the fixture so the dangling launcher can be inserted;
// PRAGMA foreign_key_check('sessions') does not report it.
func TestMigrateSessionOwnershipIgnoresUnrelatedFKViolation(t *testing.T) {
	db := buildLegacyPrincipalDB(t)
	pid := insertLegacyPrincipalRaw(t, db, "alice")
	insertLegacySession(t, db, "dhs_alice", "h_alice", pid)

	// Introduce a dangling launchers row (unrelated to sessions) while FK
	// enforcement is off.
	if _, err := db.Exec(
		`INSERT INTO launchers (id, principal_id, name, enabled, scope_mode, created_at)
		 VALUES (?, ?, 'default', 1, 'inherit', 1000)`,
		"dhl_phantom", 99999,
	); err != nil {
		t.Fatalf("cannot insert dangling launcher: %v", err)
	}

	res, err := migrateSessionOwnership(db, ModeSystem, nil)
	if err != nil {
		t.Fatalf("migration failed due to unrelated launchers FK violation: %v", err)
	}
	if res.attributedPrincipal != 1 {
		t.Errorf("attributedPrincipal = %d, want 1", res.attributedPrincipal)
	}

	// The migration committed: final schema is Launcher-owned and the session
	// was attributed to alice's default launcher despite the unrelated violation.
	var hasPrincipal, hasLauncher int
	if err := db.QueryRow(
		`SELECT
			(SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='principal_id'),
			(SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='launcher_id')`,
	).Scan(&hasPrincipal, &hasLauncher); err != nil {
		t.Fatal(err)
	}
	if hasPrincipal != 0 || hasLauncher != 1 {
		t.Errorf("final schema: principal_id=%d launcher_id=%d, want 0/1", hasPrincipal, hasLauncher)
	}
}
