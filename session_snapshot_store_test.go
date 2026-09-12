package main

import (
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// openStartupTestDB opens a database that went through the schema
// initialization only: the canonical snapshot table is absent, which is the
// exact state a pre-2.2.4 database reaches right before the startup migration
// owner runs.
func openStartupTestDB(t *testing.T) *sql.DB {
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
	return db
}

// seedLegacySession inserts one legacy live Session (the 2.1.1 issuance shape:
// workspace stored canonically, no snapshot representation) owned by a fresh
// Principal and its default Launcher. parentAccess, when non-empty, marks the
// current 2.2 parent policy on the same workspace path: the migration must
// ignore it.
func seedLegacySession(t *testing.T, db *sql.DB, workspace, parentAccess string) string {
	t.Helper()
	result, err := db.Exec(
		`INSERT INTO principals (username, uid, gid, home, enabled) VALUES ('legacyowner', 2001, 2001, ?, 1)`,
		workspace,
	)
	if err != nil {
		t.Fatalf("insert legacy principal: %v", err)
	}
	principalID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO launchers (id, principal_id, name, enabled, scope_mode, created_at)
		 VALUES ('dhl_legacy', ?, 'default', 1, 'inherit', 1)`,
		principalID,
	); err != nil {
		t.Fatalf("insert legacy launcher: %v", err)
	}
	if parentAccess != "" {
		if _, err := db.Exec(
			`INSERT INTO principal_allowed_roots (principal_id, root_path, access) VALUES (?, ?, ?)`,
			principalID, workspace, parentAccess,
		); err != nil {
			t.Fatalf("insert legacy principal root: %v", err)
		}
	}
	if _, err := db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id)
		 VALUES ('dhs_old', 'legacyhash', ?, 1, 9999999999, 'dhl_legacy')`,
		workspace,
	); err != nil {
		t.Fatalf("insert legacy session: %v", err)
	}
	return "dhs_old"
}

// readSnapshotRows returns the persisted (position, path, access) rows of one
// Session in persisted position order.
func readSnapshotRows(t *testing.T, db *sql.DB, sessionID string) []AllowedRootEntry {
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

// TestFreshDatabaseSnapshotTableIsOwnedByMigrationOwner protects the cutover
// marker: initializeDatabase alone must not create the canonical snapshot
// table (a legacy database would then be indistinguishable from a corrupted
// post-cutover one), and the migration owner is what transitions absent ->
// canonical with an empty database backfilling nothing.
func TestFreshDatabaseSnapshotTableIsOwnedByMigrationOwner(t *testing.T) {
	db := openStartupTestDB(t)

	class, err := classifySessionFilesystemSnapshotSchema(db)
	if err != nil {
		t.Fatalf("classify fresh schema: %v", err)
	}
	if class != sessionSnapshotSchemaAbsent {
		t.Fatalf("fresh initializeDatabase snapshot class = %d, want absent (the cutover marker must stay intact)", class)
	}

	result, err := migrateSessionFilesystemSnapshots(db)
	if err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots() error: %v", err)
	}
	if result.backfilled != 0 {
		t.Fatalf("empty database backfilled %d session(s), want 0", result.backfilled)
	}
	class, err = classifySessionFilesystemSnapshotSchema(db)
	if err != nil || class != sessionSnapshotSchemaCanonical {
		t.Fatalf("post-migration snapshot class = %d, err = %v, want canonical", class, err)
	}
}

// TestCanonicalSnapshotSchemaIsExact proves the canonical table stores
// exactly the canonical DDL shape: the stored definition (normalized, comments
// stripped) is the canonical one, so a foreign near-match cannot pass.
func TestCanonicalSnapshotSchemaIsExact(t *testing.T) {
	db := openStartupTestDB(t)
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots() error: %v", err)
	}

	var ddl string
	if err := db.QueryRow(
		`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'session_filesystem_snapshot_entries'`,
	).Scan(&ddl); err != nil {
		t.Fatalf("read snapshot table DDL: %v", err)
	}
	if got, want := normalizeSchemaSQL(ddl), normalizeSchemaSQL(sessionFilesystemSnapshotEntriesDDL); got != want {
		t.Fatalf("canonical snapshot DDL mismatch:\n got: %s\nwant: %s", got, want)
	}

	// Idempotence: a second startup migration is a no-op on the canonical
	// table and never rewrites it.
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("second migrateSessionFilesystemSnapshots() error: %v", err)
	}
	var after string
	if err := db.QueryRow(
		`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'session_filesystem_snapshot_entries'`,
	).Scan(&after); err != nil {
		t.Fatalf("re-read snapshot table DDL: %v", err)
	}
	if normalizeSchemaSQL(after) != normalizeSchemaSQL(ddl) {
		t.Fatalf("second migration changed the canonical snapshot DDL")
	}
}

// TestSnapshotSchemaNearMatchVariantsFailClosed proves the exact schema
// classification rejects every unsupported near-match shape instead of
// accepting it, and never destructively normalizes it.
func TestSnapshotSchemaNearMatchVariantsFailClosed(t *testing.T) {
	cases := []struct {
		name    string
		ddl     string
		wantErr string
	}{
		{
			name: "access column declares a read_write default",
			ddl: `
				CREATE TABLE session_filesystem_snapshot_entries (
					session_id TEXT NOT NULL,
					position INTEGER NOT NULL,
					path TEXT NOT NULL,
					access TEXT NOT NULL DEFAULT 'read_write',
					PRIMARY KEY (session_id, position),
					UNIQUE (session_id, path),
					FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
					CHECK (position >= 0),
					CHECK (access IN ('read_write', 'read_only'))
				)`,
			wantErr: "must not declare a default",
		},
		{
			name: "access column is nullable",
			ddl: `
				CREATE TABLE session_filesystem_snapshot_entries (
					session_id TEXT NOT NULL,
					position INTEGER NOT NULL,
					path TEXT NOT NULL,
					access TEXT,
					PRIMARY KEY (session_id, position),
					UNIQUE (session_id, path),
					FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
					CHECK (position >= 0),
					CHECK (access IN ('read_write', 'read_only'))
				)`,
			wantErr: "must be NOT NULL",
		},
		{
			name: "missing UNIQUE(session_id, path)",
			ddl: `
				CREATE TABLE session_filesystem_snapshot_entries (
					session_id TEXT NOT NULL,
					position INTEGER NOT NULL,
					path TEXT NOT NULL,
					access TEXT NOT NULL,
					PRIMARY KEY (session_id, position),
					FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
					CHECK (position >= 0),
					CHECK (access IN ('read_write', 'read_only'))
				)`,
			wantErr: "expected exactly one unique (session_id, path) index, found 0",
		},
		{
			name: "unique index on the wrong column pair",
			ddl: `
				CREATE TABLE session_filesystem_snapshot_entries (
					session_id TEXT NOT NULL,
					position INTEGER NOT NULL,
					path TEXT NOT NULL,
					access TEXT NOT NULL,
					PRIMARY KEY (session_id, position),
					UNIQUE (session_id, access),
					FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
					CHECK (position >= 0),
					CHECK (access IN ('read_write', 'read_only'))
				)`,
			wantErr: "unique index is not (session_id, path)",
		},
		{
			name: "foreign key references the wrong parent table",
			ddl: `
				CREATE TABLE session_filesystem_snapshot_entries (
					session_id TEXT NOT NULL,
					position INTEGER NOT NULL,
					path TEXT NOT NULL,
					access TEXT NOT NULL,
					PRIMARY KEY (session_id, position),
					UNIQUE (session_id, path),
					FOREIGN KEY (session_id) REFERENCES launchers(id) ON DELETE CASCADE,
					CHECK (position >= 0),
					CHECK (access IN ('read_write', 'read_only'))
				)`,
			wantErr: "expected exactly one session_id -> sessions(id) foreign key with ON DELETE CASCADE",
		},
		{
			name: "foreign key without ON DELETE CASCADE",
			ddl: `
				CREATE TABLE session_filesystem_snapshot_entries (
					session_id TEXT NOT NULL,
					position INTEGER NOT NULL,
					path TEXT NOT NULL,
					access TEXT NOT NULL,
					PRIMARY KEY (session_id, position),
					UNIQUE (session_id, path),
					FOREIGN KEY (session_id) REFERENCES sessions(id),
					CHECK (position >= 0),
					CHECK (access IN ('read_write', 'read_only'))
				)`,
			wantErr: "expected exactly one session_id -> sessions(id) foreign key with ON DELETE CASCADE",
		},
		{
			name: "position lacks its bound CHECK",
			ddl: `
				CREATE TABLE session_filesystem_snapshot_entries (
					session_id TEXT NOT NULL,
					position INTEGER NOT NULL,
					path TEXT NOT NULL,
					access TEXT NOT NULL,
					PRIMARY KEY (session_id, position),
					UNIQUE (session_id, path),
					FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
					CHECK (access IN ('read_write', 'read_only'))
				)`,
			wantErr: "expected exactly two check constraints, found 1",
		},
		{
			name: "extra competing mode column",
			ddl: `
				CREATE TABLE session_filesystem_snapshot_entries (
					session_id TEXT NOT NULL,
					position INTEGER NOT NULL,
					path TEXT NOT NULL,
					access TEXT NOT NULL,
					mode TEXT NOT NULL,
					PRIMARY KEY (session_id, position),
					UNIQUE (session_id, path),
					FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
					CHECK (position >= 0),
					CHECK (access IN ('read_write', 'read_only'))
				)`,
			wantErr: "unexpected column set",
		},
		{
			name: "canonical check text hidden in a comment is not a check",
			ddl: `
				CREATE TABLE session_filesystem_snapshot_entries (
					session_id TEXT NOT NULL,
					position INTEGER NOT NULL,
					path TEXT NOT NULL,
					access TEXT NOT NULL,
					-- CHECK (position >= 0) and CHECK (access IN ('read_write', 'read_only')) are only documented here
					PRIMARY KEY (session_id, position),
					UNIQUE (session_id, path),
					FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
				)`,
			wantErr: "expected exactly two check constraints, found 0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := openStartupTestDB(t)
			if _, err := db.Exec(tc.ddl); err != nil {
				t.Fatalf("create near-match variant: %v", err)
			}
			// The integrity metadata table is part of the canonical
			// post-cutover state; the variants exercise the entries-table
			// shape, so the canonical metadata must be present for the
			// intended classification error to surface.
			if _, err := db.Exec(sessionFilesystemSnapshotMetaDDL); err != nil {
				t.Fatalf("create canonical metadata table: %v", err)
			}

			result, err := migrateSessionFilesystemSnapshots(db)
			if err == nil {
				t.Fatalf("migrateSessionFilesystemSnapshots accepted a near-match schema: %+v", result)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("migration error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestLegacyCutoverBackfillPreservesIssuedWorkspaceAuthority is the mandatory
// v2.1.1-style migration compatibility test: the compatibility snapshot is
// derived from the already-issued Session row alone (sessions.workspace ->
// read_write). Even when the current 2.2 parent policy marks the same
// workspace read_only, the migration must never consult it and must never
// narrow the issued grant.
func TestLegacyCutoverBackfillPreservesIssuedWorkspaceAuthority(t *testing.T) {
	db := openStartupTestDB(t)

	workspace := filepath.Join(testAllowedRootDir(t), "home", "legacy", "job")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	sessionID := seedLegacySession(t, db, workspace, string(AllowedRootAccessReadOnly))

	// The canonical snapshot table must be absent before the migration: this
	// is the cutover marker of a database that never had snapshots.
	class, err := classifySessionFilesystemSnapshotSchema(db)
	if err != nil || class != sessionSnapshotSchemaAbsent {
		t.Fatalf("pre-migration snapshot class = %d, err = %v, want absent", class, err)
	}

	result, err := migrateSessionFilesystemSnapshots(db)
	if err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots() error: %v", err)
	}
	if result.backfilled != 1 {
		t.Fatalf("backfilled = %d, want 1", result.backfilled)
	}

	// Exactly one compatibility entry: position 0, the stored workspace,
	// read_write — regardless of the read_only principal policy row.
	want := []AllowedRootEntry{{Path: workspace, Access: AllowedRootAccessReadWrite}}
	if got := readSnapshotRows(t, db, sessionID); len(got) != 1 || got[0] != want[0] {
		t.Fatalf("persisted snapshot = %v, want exactly %v", got, want)
	}

	snapshot, err := loadSessionFilesystemSnapshot(db, sessionID, workspace)
	if err != nil {
		t.Fatalf("canonical loader on the migrated snapshot: %v", err)
	}
	if snapshot.Workspace != workspace || len(snapshot.Entries) != 1 || snapshot.Entries[0] != want[0] {
		t.Fatalf("loaded snapshot = %+v, want one %v entry", snapshot, want)
	}
}

// TestLegacyMigrationIsRestartSafeAndIdempotent proves the cutover transaction
// semantics: a fault before the commit rolls the created table and backfill
// rows back so the next startup repeats the migration, and a completed
// migration is never repeated.
func TestLegacyMigrationIsRestartSafeAndIdempotent(t *testing.T) {
	db := openStartupTestDB(t)

	workspace := filepath.Join(testAllowedRootDir(t), "home", "legacy", "job")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	sessionID := seedLegacySession(t, db, workspace, "")

	// Injected failure after the canonical table and backfill rows were
	// written inside the transaction: the whole migration must roll back,
	// leaving the table absent and the sessions intact.
	sessionSnapshotBackfillFault = func() error { return errors.New("injected migration fault") }

	if _, err := migrateSessionFilesystemSnapshots(db); err == nil {
		t.Fatal("migrateSessionFilesystemSnapshots() must fail on the injected fault")
	}
	sessionSnapshotBackfillFault = nil
	class, err := classifySessionFilesystemSnapshotSchema(db)
	if err != nil || class != sessionSnapshotSchemaAbsent {
		t.Fatalf("after a rolled-back migration the table must be absent again, got class %d err %v", class, err)
	}
	var sessions int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("sessions after rollback = %d, err = %v, want 1 intact session", sessions, err)
	}

	// The next startup repeats the migration and completes it.
	result, err := migrateSessionFilesystemSnapshots(db)
	if err != nil {
		t.Fatalf("repeated startup migration: %v", err)
	}
	if result.backfilled != 1 {
		t.Fatalf("repeated migration backfilled = %d, want 1", result.backfilled)
	}

	// Second startup: the post-cutover validation path runs, backfills
	// nothing, and never mutates the persisted rows.
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("idempotent second migration: %v", err)
	}
	var entryCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM session_filesystem_snapshot_entries WHERE session_id = ?`, sessionID,
	).Scan(&entryCount); err != nil || entryCount != 1 {
		t.Fatalf("snapshot entries after idempotent migration = %d (err %v), want 1", entryCount, err)
	}
}

// TestPostCutoverMissingSnapshotIsNeverBackfilled protects the post-cutover
// contract: once the canonical table exists, a Session without snapshot rows
// is corruption. Startup fails closed and does not repair, replace, or
// reconstruct the authority from any policy.
func TestPostCutoverMissingSnapshotIsNeverBackfilled(t *testing.T) {
	app := newTestApp(t)
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0].Path)
	created, err := createDefaultAdminSessionForTest(app, ws)
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	if _, err := app.DB.Exec(
		`DELETE FROM session_filesystem_snapshot_entries WHERE session_id = ?`,
		created.Session.ID,
	); err != nil {
		t.Fatal(err)
	}

	err = verifySessionFilesystemSnapshotIntegrity(app.DB)
	if err == nil {
		t.Fatal("startup integrity validation must fail for a Session with no snapshot entries")
	}
	if !strings.Contains(err.Error(), created.Session.ID) || !strings.Contains(err.Error(), "no persisted filesystem snapshot") {
		t.Fatalf("integrity error = %v, want the session ID and the missing-snapshot invariant", err)
	}

	// The startup migration owner refuses rather than repairing.
	if _, err := migrateSessionFilesystemSnapshots(app.DB); err == nil {
		t.Fatal("startup migration must refuse rather than repairing the missing snapshot")
	}
	// Nothing was backfilled: the rows stay absent.
	if got := readSnapshotRows(t, app.DB, created.Session.ID); len(got) != 0 {
		t.Fatalf("no backfill must happen: persisted snapshot rows = %v", got)
	}
}

// TestPostCutoverCorruptionFailsClosed proves every persisted corruption
// class fails startup through the canonical loader/constructor without any
// repair, normalization, or read_write defaulting.
func TestPostCutoverCorruptionFailsClosed(t *testing.T) {
	cases := []struct {
		name         string
		buildEntries func(t *testing.T, db *sql.DB, sessionID, workspace string)
		wantErr      string
	}{
		{
			name: "gapped positions",
			buildEntries: func(t *testing.T, db *sql.DB, sessionID, workspace string) {
				// Re-move the second entry from position 1 to 2: the
				// persisted positions become 0,2 — the gap must fail the
				// loader's contiguous-position proof (the metadata is kept
				// consistent so the constructor proof, not the digest gate,
				// is what fails).
				if _, err := db.Exec(
					`UPDATE session_filesystem_snapshot_entries SET position = 2
					 WHERE session_id = ? AND position = 1`,
					sessionID,
				); err != nil {
					t.Fatalf("insert gapped entry: %v", err)
				}
			},
			wantErr: "positions are not exactly 0..N-1",
		},
		{
			name: "workspace loses its authorization",
			buildEntries: func(t *testing.T, db *sql.DB, sessionID, workspace string) {
				if _, err := db.Exec(
					`UPDATE session_filesystem_snapshot_entries SET path = '/run/other' WHERE session_id = ? AND position = 0`,
					sessionID,
				); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "does not authorize the workspace",
		},
		{
			name: "unordered canonical transitions",
			buildEntries: func(t *testing.T, db *sql.DB, sessionID, workspace string) {
				// Canonical persisted order is workspace, workspace/a,
				// workspace/z (byte order). Swapping the two siblings'
				// paths breaks the normalized-representation proof.
				if _, err := db.Exec(
					`UPDATE session_filesystem_snapshot_entries SET path = ?
					 WHERE session_id = ? AND position = 1`,
					filepath.Join(workspace, "z"), sessionID,
				); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(
					`INSERT INTO session_filesystem_snapshot_entries (session_id, position, path, access)
					 VALUES (?, 2, ?, 'read_only')`,
					sessionID, filepath.Join(workspace, "a"),
				); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "not the canonical normalized representation",
		},
		{
			name: "redundant same-mode transition",
			buildEntries: func(t *testing.T, db *sql.DB, sessionID, workspace string) {
				if _, err := db.Exec(
					`INSERT INTO session_filesystem_snapshot_entries (session_id, position, path, access)
					 VALUES (?, 2, ?, 'read_write')`,
					sessionID, filepath.Join(workspace, "project"),
				); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "not the canonical normalized representation",
		},
		{
			name: "noncanonical disjoint insertion",
			buildEntries: func(t *testing.T, db *sql.DB, sessionID, workspace string) {
				sibling := filepath.Join(filepath.Dir(workspace), "elsewhere")
				if _, err := db.Exec(
					`INSERT INTO session_filesystem_snapshot_entries (session_id, position, path, access)
					 VALUES (?, 2, ?, 'read_only')`,
					sessionID, sibling,
				); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "not the canonical normalized representation",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := newTestApp(t)
			root := app.Config.AllowedRoots[0].Path
			workspace := filepath.Join(root, "ws")
			inputs := filepath.Join(workspace, "inputs")
			for _, d := range []string{inputs} {
				if err := os.MkdirAll(d, 0755); err != nil {
					t.Fatal(err)
				}
			}
			app.Config.AllowedRoots = []AllowedRootEntry{
				allowedRootEntry(root),
				{Path: inputs, Access: AllowedRootAccessReadOnly},
			}
			created, err := createDefaultAdminSessionForTest(app, workspace)
			if err != nil {
				t.Fatalf("createSessionAuthorized() error: %v", err)
			}
			if len(created.FilesystemSnapshot.Entries) != 2 {
				t.Fatalf("precondition: snapshot = %v, want two entries", created.FilesystemSnapshot.Entries)
			}

			tc.buildEntries(t, app.DB, created.Session.ID, workspace)
			alignSnapshotMetadataForTest(t, app.DB, created.Session.ID)

			if err := verifySessionFilesystemSnapshotIntegrity(app.DB); err == nil {
				t.Fatal("startup integrity validation must fail on corrupt snapshot state")
			} else if !strings.Contains(err.Error(), created.Session.ID) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("integrity error = %v, want it to contain the session ID and %q", err, tc.wantErr)
			}
			if _, err := migrateSessionFilesystemSnapshots(app.DB); err == nil {
				t.Fatal("startup migration must fail closed on corrupt state")
			}
		})
	}
}

// TestUnknownAccessAndDuplicatePathForeignStateFailsClosed proves the state
// paths the canonical CHECK/UNIQUE constraints normally prevent: a foreign
// schema without those constraints cannot be smuggled past startup either.
// The schema classification itself fails closed — the daemon never defaults
// unknown access to read_write and never accepts a foreign shape.
func TestForeignSnapshotSchemaWithUnknownAccessFailsClosed(t *testing.T) {
	db := openStartupTestDB(t)
	// A foreign near-match without the access CHECK and without the
	// (session_id, path) UNIQUE constraint.
	if _, err := db.Exec(`
		CREATE TABLE session_filesystem_snapshot_entries (
			session_id TEXT NOT NULL,
			position INTEGER NOT NULL,
			path TEXT NOT NULL,
			access TEXT NOT NULL,
			PRIMARY KEY (session_id, position),
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
			CHECK (position >= 0)
		)
	`); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(testAllowedRootDir(t), "home", "legacy", "job")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	sessionID := seedLegacySession(t, db, workspace, "")
	if _, err := db.Exec(
		`INSERT INTO session_filesystem_snapshot_entries (session_id, position, path, access)
		 VALUES (?, 0, ?, 'write')`,
		sessionID, workspace,
	); err != nil {
		t.Fatalf("insert foreign-schema row: %v", err)
	}

	if _, err := migrateSessionFilesystemSnapshots(db); err == nil {
		t.Fatal("startup must refuse the foreign schema/state instead of defaulting the access mode")
	}
	// The corrupt row is untouched: the classifier never repairs state.
	var access string
	if err := db.QueryRow(
		`SELECT access FROM session_filesystem_snapshot_entries WHERE session_id = ? AND position = 0`,
		sessionID,
	).Scan(&access); err != nil || access != "write" {
		t.Fatalf("foreign row must be left untouched, got access=%q err=%v", access, err)
	}
}

// TestOrphanSnapshotFailsStartupWithoutForeignKeys proves the startup
// integrity proof does not rely on foreign-key enforcement: an orphan row
// written with FK enforcement disabled still fails startup and is never
// cleaned up silently.
func TestOrphanSnapshotFailsStartupWithoutForeignKeys(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + url.PathEscape(filepath.Join(dir, "test.db")) + "?_foreign_keys=off"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots() error: %v", err)
	}

	// Deliberately bypass FK enforcement: a snapshot row with no session row.
	if _, err := db.Exec(
		`INSERT INTO session_filesystem_snapshot_entries (session_id, position, path, access)
		 VALUES ('dhs_orphan', 0, '/run/orphan', 'read_write')`,
	); err != nil {
		t.Fatalf("insert orphan snapshot row: %v", err)
	}

	_, err = migrateSessionFilesystemSnapshots(db)
	if err == nil {
		t.Fatal("startup must fail on an orphaned snapshot row")
	}
	if !strings.Contains(err.Error(), "dhs_orphan") || !strings.Contains(err.Error(), "nonexistent session") {
		t.Fatalf("orphan error = %v, want the orphan session ID and the orphan invariant", err)
	}
}

// alignSnapshotMetadataForTest rewrites one session's integrity metadata row
// from the currently persisted entries, so a corruption test exercises the
// canonical-constructor proof under a consistent-but-noncanonical state
// instead of the earlier digest gate. The metadata is never rewritten like
// this in production: the loader fails closed on any mismatch.
func alignSnapshotMetadataForTest(t *testing.T, db *sql.DB, sessionID string) {
	t.Helper()
	rows, err := db.Query(
		`SELECT path, access FROM session_filesystem_snapshot_entries
		 WHERE session_id = ? ORDER BY position`, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	var entries []AllowedRootEntry
	for rows.Next() {
		var path, access string
		if err := rows.Scan(&path, &access); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		entries = append(entries, AllowedRootEntry{Path: path, Access: AllowedRootAccess(access)})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`UPDATE session_filesystem_snapshot_meta SET entry_count = ?, digest = ? WHERE session_id = ?`,
		len(entries), sessionFilesystemSnapshotDigest(entries), sessionID,
	); err != nil {
		t.Fatal(err)
	}
}

// TestSnapshotTruncatedTailFailsClosed proves F7: deleting the trailing
// snapshot row (a syntactically valid state that would widen the rights of
// a RW workspace with a nested RO entry) is detected by both the startup
// integrity gate and the runtime canonical loader, and never repaired.
func TestSnapshotTruncatedTailFailsClosed(t *testing.T) {
	app := newTestApp(t)
	root := app.Config.AllowedRoots[0].Path
	workspace := filepath.Join(root, "ws")
	inputs := filepath.Join(workspace, "inputs")
	if err := os.MkdirAll(inputs, 0755); err != nil {
		t.Fatal(err)
	}
	app.Config.AllowedRoots = []AllowedRootEntry{
		allowedRootEntry(root),
		{Path: inputs, Access: AllowedRootAccessReadOnly},
	}
	created, err := createDefaultAdminSessionForTest(app, workspace)
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}
	if len(created.FilesystemSnapshot.Entries) != 2 {
		t.Fatalf("precondition: snapshot = %v, want two entries", created.FilesystemSnapshot.Entries)
	}

	// Truncate the tail: the nested RO row disappears and the remaining
	// single-entry snapshot would widen the workspace to full read_write.
	if _, err := app.DB.Exec(
		`DELETE FROM session_filesystem_snapshot_entries
		 WHERE session_id = ? AND position = 1`,
		created.Session.ID,
	); err != nil {
		t.Fatal(err)
	}

	if err := verifySessionFilesystemSnapshotIntegrity(app.DB); err == nil {
		t.Fatal("startup integrity validation must fail on a truncated snapshot tail")
	} else if !strings.Contains(err.Error(), created.Session.ID) ||
		!strings.Contains(err.Error(), "integrity metadata records") {
		t.Fatalf("integrity error = %v, want the session ID and the metadata count mismatch", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(app.DB); err == nil {
		t.Fatal("startup migration must fail closed on a truncated snapshot tail")
	}

	// The runtime canonical loader detects the same corruption fail-closed.
	if _, err := loadSessionFilesystemSnapshot(app.DB, created.Session.ID, workspace); err == nil {
		t.Fatal("runtime loader must fail closed on a truncated snapshot tail")
	}
	if got := readSnapshotRows(t, app.DB, created.Session.ID); len(got) != 1 {
		t.Fatalf("corrupt state must never be repaired, rows = %v", got)
	}
}
