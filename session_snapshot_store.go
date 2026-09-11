package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

// This file owns the persisted Session filesystem snapshot: the canonical
// child table, its exact schema classification, the startup migration with
// the legacy cutover marker, the canonical loader, and the transactional
// insert used by Session creation. The snapshot value itself and its
// derivation are owned by allowed_root_policy.go; this file owns only the
// persisted representation of that accepted domain value.

// sessionFilesystemSnapshotEntriesDDL is the canonical CREATE TABLE statement
// of the Session filesystem snapshot entries child table. Only this statement
// (executed inside the cutover migration transaction) writes the table, so the
// schema classifier may require its exact semantic shape.
const sessionFilesystemSnapshotEntriesDDL = `
	CREATE TABLE session_filesystem_snapshot_entries (
		session_id TEXT NOT NULL,
		position INTEGER NOT NULL,
		path TEXT NOT NULL,
		access TEXT NOT NULL,
		PRIMARY KEY (session_id, position),
		UNIQUE (session_id, path),
		FOREIGN KEY (session_id)
			REFERENCES sessions(id)
			ON DELETE CASCADE,
		CHECK (position >= 0),
		CHECK (access IN ('read_write', 'read_only'))
	)
`

// sessionFilesystemSnapshotMetaDDL is the canonical CREATE TABLE statement
// of the Session filesystem snapshot integrity metadata table. It is created
// atomically with the entries table inside the cutover migration transaction
// and owned by the same snapshot store: one meta row per Session proves the
// completeness of the issued immutable snapshot.
const sessionFilesystemSnapshotMetaDDL = `
	CREATE TABLE session_filesystem_snapshot_meta (
		session_id TEXT NOT NULL,
		entry_count INTEGER NOT NULL,
		digest TEXT NOT NULL,
		PRIMARY KEY (session_id),
		FOREIGN KEY (session_id)
			REFERENCES sessions(id)
			ON DELETE CASCADE
	)
`

// sessionFilesystemSnapshotMetaColumns is the canonical column contract of
// the snapshot integrity metadata table.
var sessionFilesystemSnapshotMetaColumns = []tableColumnSpec{
	{"session_id", "TEXT", true, 1},
	{"entry_count", "INTEGER", true, 0},
	{"digest", "TEXT", true, 0},
}

// sessionSnapshotSchemaClass identifies the persisted snapshot-table state.
// The entries table's presence is the canonical legacy cutover marker: absent
// is the pre-2.2 state where the compatibility backfill is required, canonical
// is the post-cutover state where a missing snapshot is corruption and must
// never be repaired, and unsupported is any other schema (fail closed).
type sessionSnapshotSchemaClass int

const (
	sessionSnapshotSchemaUnsupported sessionSnapshotSchemaClass = iota
	sessionSnapshotSchemaAbsent
	sessionSnapshotSchemaCanonical
)

// sessionSnapshotColumns is the canonical column contract of the snapshot
// entries table: exact declared types, NOT NULL, and primary-key positions
// (session_id, position) as SQLite reports them through pragma_table_info.
var sessionSnapshotColumns = []tableColumnSpec{
	{"session_id", "TEXT", true, 1},
	{"position", "INTEGER", true, 2},
	{"path", "TEXT", true, 0},
	{"access", "TEXT", true, 0},
}

// sessionSnapshotPositionCheck is the canonical position CHECK expression,
// normalized (lowercase, whitespace-stripped) as produced by
// sqliteCheckExpressions from the declared schema.
const sessionSnapshotPositionCheck = "position>=0"

// classifySessionFilesystemSnapshotSchema classifies the snapshot table from
// SQLite semantic metadata. Positive recognition is exact: the canonical
// four-column contract (no declared defaults), exactly one
// session_id -> sessions(id) foreign key with ON DELETE CASCADE, exactly one
// user unique index on (session_id, path), and exactly the two canonical
// CHECK constraints (the position bound and the access vocabulary) recognized
// as real SQL CHECK syntax in the stored DDL. Any other shape is unsupported
// state and fails closed rather than being accepted as a near match.
func classifySessionFilesystemSnapshotSchema(db *sql.DB) (sessionSnapshotSchemaClass, error) {
	const table = "session_filesystem_snapshot_entries"
	var tableCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`,
		table,
	).Scan(&tableCount); err != nil {
		return sessionSnapshotSchemaUnsupported, fmt.Errorf("cannot inspect %s table presence: %w", table, err)
	}
	if tableCount == 0 {
		// Table absent: the canonical pre-2.2 cutover marker.
		return sessionSnapshotSchemaAbsent, nil
	}

	// The integrity metadata table is part of the canonical post-cutover
	// state: it is created atomically with the entries table, and an
	// entries table without it is unsupported (fail closed, never
	// backfilled).
	const metaTable = "session_filesystem_snapshot_meta"
	var metaTableCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`,
		metaTable,
	).Scan(&metaTableCount); err != nil {
		return sessionSnapshotSchemaUnsupported, fmt.Errorf("cannot inspect %s table presence: %w", metaTable, err)
	}
	if metaTableCount == 0 {
		return sessionSnapshotSchemaUnsupported, unsupportedTableSchema(table,
			"snapshot integrity metadata table is absent after the cutover")
	}

	cols, err := readTableColumns(db, table)
	if err != nil {
		return sessionSnapshotSchemaUnsupported, err
	}
	if err := verifyTableColumns(table, cols, sessionSnapshotColumns); err != nil {
		return sessionSnapshotSchemaUnsupported, err
	}

	fks, err := readTableForeignKeys(db, table)
	if err != nil {
		return sessionSnapshotSchemaUnsupported, err
	}
	if len(fks) != 1 ||
		fks[0] != (tableForeignKey{table: "sessions", from: "session_id", to: "id", onDelete: "CASCADE"}) {
		return sessionSnapshotSchemaUnsupported, unsupportedTableSchema(table,
			"expected exactly one session_id -> sessions(id) foreign key with ON DELETE CASCADE")
	}

	metaCols, err := readTableColumns(db, metaTable)
	if err != nil {
		return sessionSnapshotSchemaUnsupported, err
	}
	if err := verifyTableColumns(metaTable, metaCols, sessionFilesystemSnapshotMetaColumns); err != nil {
		return sessionSnapshotSchemaUnsupported, err
	}
	metaFKs, err := readTableForeignKeys(db, metaTable)
	if err != nil {
		return sessionSnapshotSchemaUnsupported, err
	}
	if len(metaFKs) != 1 ||
		metaFKs[0] != (tableForeignKey{table: "sessions", from: "session_id", to: "id", onDelete: "CASCADE"}) {
		return sessionSnapshotSchemaUnsupported, unsupportedTableSchema(metaTable,
			"expected exactly one session_id -> sessions(id) foreign key with ON DELETE CASCADE")
	}

	// Exactly one user-declared unique index on (session_id, path): one
	// canonical policy path per Session, independent of the primary key.
	indexRows, err := db.Query(
		`SELECT name, "partial" FROM pragma_index_list(?) WHERE "unique"=1 AND "origin"!='pk'`,
		table,
	)
	if err != nil {
		return sessionSnapshotSchemaUnsupported, fmt.Errorf("cannot read %s unique indexes: %w", table, err)
	}
	var uniqueIndexes [][]string
	for indexRows.Next() {
		var name string
		var partial int
		if err := indexRows.Scan(&name, &partial); err != nil {
			indexRows.Close()
			return sessionSnapshotSchemaUnsupported, fmt.Errorf("cannot scan %s unique index: %w", table, err)
		}
		if partial == 1 {
			indexRows.Close()
			return sessionSnapshotSchemaUnsupported, unsupportedTableSchema(table, "unexpected partial unique index")
		}
		indexCols, err := credentialsIndexColumns(db, name)
		if err != nil {
			indexRows.Close()
			return sessionSnapshotSchemaUnsupported, err
		}
		uniqueIndexes = append(uniqueIndexes, indexCols)
	}
	if err := indexRows.Err(); err != nil {
		indexRows.Close()
		return sessionSnapshotSchemaUnsupported, fmt.Errorf("iterate %s unique indexes: %w", table, err)
	}
	indexRows.Close()
	if len(uniqueIndexes) != 1 {
		return sessionSnapshotSchemaUnsupported, unsupportedTableSchema(table,
			fmt.Sprintf("expected exactly one unique (session_id, path) index, found %d", len(uniqueIndexes)))
	}
	if len(uniqueIndexes[0]) != 2 || uniqueIndexes[0][0] != "session_id" || uniqueIndexes[0][1] != "path" {
		return sessionSnapshotSchemaUnsupported, unsupportedTableSchema(table,
			"unique index is not (session_id, path)")
	}

	// CHECK constraints are recognized only through the stored table DDL.
	var ddl sql.NullString
	err = db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&ddl)
	if err != nil {
		return sessionSnapshotSchemaUnsupported, fmt.Errorf("cannot inspect %s table definition: %w", table, err)
	}
	if !ddl.Valid || ddl.String == "" {
		return sessionSnapshotSchemaUnsupported, unsupportedTableSchema(table, "table definition unavailable")
	}
	checks := sqliteCheckExpressions(ddl.String)
	if len(checks) != 2 {
		return sessionSnapshotSchemaUnsupported, unsupportedTableSchema(table,
			fmt.Sprintf("expected exactly two check constraints, found %d", len(checks)))
	}
	checkSet := map[string]bool{}
	for _, expr := range checks {
		checkSet[expr] = true
	}
	if !checkSet[sessionSnapshotPositionCheck] || !checkSet[allowedRootAccessCheck] {
		return sessionSnapshotSchemaUnsupported, unsupportedTableSchema(table,
			"non-canonical check constraints (want the position bound and the access vocabulary check)")
	}
	return sessionSnapshotSchemaCanonical, nil
}

// sessionFilesystemSnapshotDigest is the single owner of the canonical
// digest over an issued immutable snapshot representation: the canonical
// representation is the entry list in persisted position order, each entry
// framed as position, path, access separated by NUL bytes and terminated by
// one NUL byte. Filesystem paths cannot contain NUL, so the framing is
// unambiguous and order-, path-, and access-sensitive: a missing entry, an
// extra entry, a changed path, a changed access, or a changed order yields a
// different digest.
func sessionFilesystemSnapshotDigest(entries []AllowedRootEntry) string {
	var sb strings.Builder
	for i, e := range entries {
		fmt.Fprintf(&sb, "%d\x00%s\x00%s\x00", i, e.Path, string(e.Access))
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

// sessionSnapshotBackfillFault is a narrow test-only seam that fails the
// legacy cutover migration at a chosen point after the canonical table and
// compatibility rows were written inside its transaction, proving the atomic
// rollback. It is never set in production.
var sessionSnapshotBackfillFault func() error

// migrateSessionFilesystemSnapshots is the startup owner of the Session
// filesystem snapshot persistence. The canonical snapshot table's presence is
// the legacy cutover marker:
//
//   - table absent: the pre-2.2 state. One transaction creates the exact
//     canonical table and writes exactly one compatibility entry per remaining
//     Session (position 0, path = sessions.workspace, access read_write), then
//     verifies the result through the canonical loader before committing. This
//     is the only place where a missing snapshot is created, and it consults
//     only sessions.workspace — never current global/Principal/Launcher policy,
//     so already-issued 2.1 authority is preserved byte-for-byte.
//   - table present: the post-cutover state. The schema must classify
//     canonical, and every remaining Session's snapshot must prove intact
//     through the canonical loader. A missing, partial, gapped, noncanonical,
//     or orphaned snapshot fails startup; it is never backfilled or repaired.
//
// A crash before the legacy transaction's commit leaves the table absent, and
// the next startup repeats the migration; a crash after the commit leaves the
// table present, and the next startup treats the database as post-cutover. The
// table presence alone owns that transition; no separate migration flag exists.
func migrateSessionFilesystemSnapshots(db *sql.DB) (*sessionSnapshotMigrationResult, error) {
	class, err := classifySessionFilesystemSnapshotSchema(db)
	if err != nil {
		return nil, err
	}
	switch class {
	case sessionSnapshotSchemaAbsent:
		return backfillSessionFilesystemSnapshots(db)
	default:
		if err := verifySessionFilesystemSnapshotIntegrity(db); err != nil {
			return nil, err
		}
		return &sessionSnapshotMigrationResult{}, nil
	}
}

// sessionSnapshotMigrationResult reports the outcome of the startup snapshot
// migration: the number of compatibility snapshots written by the legacy
// cutover (zero in the post-cutover validation path).
type sessionSnapshotMigrationResult struct {
	backfilled int
}

// backfillSessionFilesystemSnapshots performs the legacy cutover migration in
// one transaction: create the exact canonical table, backfill one
// workspace-read_write entry per remaining Session, and verify the result
// through the canonical loader before committing. Any failure rolls the whole
// transaction back, leaving the table absent so the next startup retries.
func backfillSessionFilesystemSnapshots(db *sql.DB) (*sessionSnapshotMigrationResult, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("cannot begin session filesystem snapshot migration: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(sessionFilesystemSnapshotEntriesDDL); err != nil {
		return nil, fmt.Errorf("cannot create session filesystem snapshot table: %w", err)
	}
	if _, err := tx.Exec(sessionFilesystemSnapshotMetaDDL); err != nil {
		return nil, fmt.Errorf("cannot create session filesystem snapshot metadata table: %w", err)
	}

	// The compatibility authority comes from the already-issued 2.1 Session
	// row alone: sessions.workspace is the stored canonical workspace and
	// every pre-2.2 grant is read_write. Current parent policy is never read.
	result, err := tx.Exec(`
		INSERT INTO session_filesystem_snapshot_entries (session_id, position, path, access)
		SELECT id, 0, workspace, 'read_write' FROM sessions
	`)
	if err != nil {
		return nil, fmt.Errorf("cannot backfill session filesystem snapshots: %w", err)
	}

	// The compatibility integrity metadata is written in the same
	// transaction: one meta row per backfilled Session carrying the entry
	// count (exactly one workspace-read_write entry) and the canonical
	// digest of that issued snapshot.
	rows, err := tx.Query(`SELECT id, workspace FROM sessions ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("cannot enumerate sessions for snapshot metadata backfill: %w", err)
	}
	for rows.Next() {
		var id, workspace string
		if err := rows.Scan(&id, &workspace); err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot scan session row for snapshot metadata backfill: %w", err)
		}
		digest := sessionFilesystemSnapshotDigest([]AllowedRootEntry{{Path: workspace, Access: AllowedRootAccess("read_write")}})
		if _, err := tx.Exec(
			`INSERT INTO session_filesystem_snapshot_meta (session_id, entry_count, digest) VALUES (?, 1, ?)`,
			id, digest,
		); err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot backfill snapshot metadata for session %s: %w", id, err)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions for snapshot metadata backfill: %w", err)
	}

	if sessionSnapshotBackfillFault != nil {
		if err := sessionSnapshotBackfillFault(); err != nil {
			return nil, fmt.Errorf("session filesystem snapshot migration fault: %w", err)
		}
	}

	var sessionCount, entryCount int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&sessionCount); err != nil {
		return nil, fmt.Errorf("cannot count sessions for snapshot migration: %w", err)
	}
	backfilled, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("cannot check snapshot backfill result: %w", err)
	}
	if err := verifySessionFilesystemSnapshots(tx); err != nil {
		return nil, fmt.Errorf("session filesystem snapshot migration produced an invalid state: %w", err)
	}
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM session_filesystem_snapshot_entries`,
	).Scan(&entryCount); err != nil {
		return nil, fmt.Errorf("cannot count backfilled snapshot entries: %w", err)
	}
	if entryCount != sessionCount || int(backfilled) != sessionCount {
		return nil, fmt.Errorf("session filesystem snapshot migration backfilled %d of %d session(s)", backfilled, sessionCount)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("cannot commit session filesystem snapshot migration: %w", err)
	}
	return &sessionSnapshotMigrationResult{backfilled: sessionCount}, nil
}

// sessionSnapshotIntegrityError formats a fail-closed startup integrity
// failure with the affected Session ID and the invariant that failed. It
// carries no bearer, token hash, or other secret-bearing data.
func sessionSnapshotIntegrityError(sessionID string, err error) error {
	return fmt.Errorf("session filesystem snapshot integrity failure: session %s: %w", sessionID, err)
}

// verifySessionFilesystemSnapshotIntegrity proves the persisted snapshot
// integrity of every remaining Session in the post-cutover state.
func verifySessionFilesystemSnapshotIntegrity(db *sql.DB) error {
	if err := verifySessionFilesystemSnapshots(db); err != nil {
		return fmt.Errorf("session filesystem snapshot integrity check failed: %w", err)
	}
	return nil
}

// verifySessionFilesystemSnapshots proves the persisted snapshot integrity of
// every remaining Session readable through q: every Session has a snapshot
// that passes the canonical loader, and no snapshot row belongs to a
// nonexistent Session. The orphan check is expressed in SQL directly so it
// holds regardless of whether foreign-key enforcement happened to be enabled
// on the connection that wrote the rows.
func verifySessionFilesystemSnapshots(q txQuerier) error {
	rows, err := q.Query(`
		SELECT session_id FROM (
			SELECT e.session_id FROM session_filesystem_snapshot_entries e
			WHERE NOT EXISTS (SELECT 1 FROM sessions s WHERE s.id = e.session_id)
			UNION
			SELECT m.session_id FROM session_filesystem_snapshot_meta m
			WHERE NOT EXISTS (SELECT 1 FROM sessions s WHERE s.id = m.session_id)
		)
		LIMIT 1
	`)
	if err != nil {
		return fmt.Errorf("cannot check for orphaned snapshot rows: %w", err)
	}
	orphan := ""
	haveOrphan := false
	for rows.Next() {
		if err := rows.Scan(&orphan); err != nil {
			rows.Close()
			return fmt.Errorf("cannot scan orphan snapshot check: %w", err)
		}
		haveOrphan = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate orphan snapshot check: %w", err)
	}
	if haveOrphan {
		return sessionSnapshotIntegrityError(orphan, fmt.Errorf("snapshot rows reference a nonexistent session"))
	}

	sessionRows, err := q.Query(`SELECT id, workspace FROM sessions`)
	if err != nil {
		return fmt.Errorf("cannot enumerate sessions for snapshot integrity: %w", err)
	}
	defer sessionRows.Close()
	for sessionRows.Next() {
		var id, workspace string
		if err := sessionRows.Scan(&id, &workspace); err != nil {
			return fmt.Errorf("cannot scan session id for snapshot integrity: %w", err)
		}
		if _, err := loadSessionFilesystemSnapshot(q, id, workspace); err != nil {
			return sessionSnapshotIntegrityError(id, err)
		}
	}
	if err := sessionRows.Err(); err != nil {
		return fmt.Errorf("iterate sessions for snapshot integrity: %w", err)
	}
	return nil
}

// loadSessionFilesystemSnapshot is the single canonical persisted snapshot
// loader: it reads one Session's snapshot entries in persisted position order
// and proves the persisted representation before handing it to the canonical
// constructor. Positions must be exactly 0,1,2,...,N-1 with no gap, the table
// must carry at least one entry, and newSessionFilesystemSnapshot proves the
// workspace-anchored canonical shape (canonical absolute workspace, entry 0 ==
// workspace, containment, valid access values, no duplicate paths, canonical
// normalized order without redundant transitions). The loader never repairs
// persisted state: sorting, deduplicating, renumbering, or normalizing a
// corrupt snapshot would invent issued authority, so any noncanonical state
// fails closed.
func loadSessionFilesystemSnapshot(q txQuerier, sessionID, workspace string) (*sessionFilesystemSnapshot, error) {
	var entryCount int
	var digest string
	err := q.QueryRow(
		`SELECT entry_count, digest FROM session_filesystem_snapshot_meta WHERE session_id = ?`,
		sessionID,
	).Scan(&entryCount, &digest)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session %s filesystem snapshot integrity metadata is missing", sessionID)
		}
		return nil, fmt.Errorf("cannot load session %s filesystem snapshot integrity metadata: %w", sessionID, err)
	}

	rows, err := q.Query(
		`SELECT position, path, access FROM session_filesystem_snapshot_entries
		 WHERE session_id = ?
		 ORDER BY position`,
		sessionID,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot load session %s filesystem snapshot: %w", sessionID, err)
	}
	defer rows.Close()

	var entries []AllowedRootEntry
	for rows.Next() {
		var position int
		var path, access string
		if err := rows.Scan(&position, &path, &access); err != nil {
			return nil, fmt.Errorf("cannot scan session %s filesystem snapshot entry: %w", sessionID, err)
		}
		if position != len(entries) {
			return nil, fmt.Errorf(
				"session %s filesystem snapshot positions are not exactly 0..N-1: index %d carries position %d",
				sessionID, len(entries), position)
		}
		entries = append(entries, AllowedRootEntry{Path: path, Access: AllowedRootAccess(access)})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate session %s filesystem snapshot entries: %w", sessionID, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("session %s has no persisted filesystem snapshot", sessionID)
	}
	// Integrity metadata: the issued immutable snapshot is complete only
	// when the persisted entries match the recorded count and digest. Any
	// mismatch — a missing or extra entry, a changed path, access, or
	// order — fails closed and is never repaired.
	if entryCount != len(entries) {
		return nil, fmt.Errorf(
			"session %s filesystem snapshot integrity metadata records %d entries, found %d",
			sessionID, entryCount, len(entries))
	}
	if digest != sessionFilesystemSnapshotDigest(entries) {
		return nil, fmt.Errorf(
			"session %s filesystem snapshot does not match its issued integrity digest", sessionID)
	}

	snapshot, err := newSessionFilesystemSnapshot(workspace, entries)
	if err != nil {
		return nil, fmt.Errorf("session %s filesystem snapshot is not canonical: %w", sessionID, err)
	}
	return snapshot, nil
}

// insertSessionFilesystemSnapshot writes every snapshot entry with its
// canonical position plus the integrity metadata row (entry count and
// canonical digest of the issued snapshot) inside the caller's transaction.
// It runs only as part of the atomic Session+snapshot creation transaction,
// so a failure anywhere leaves no Session row behind.
func insertSessionFilesystemSnapshot(tx *sql.Tx, sessionID string, entries []AllowedRootEntry) error {
	for i, e := range entries {
		if _, err := tx.Exec(
			`INSERT INTO session_filesystem_snapshot_entries (session_id, position, path, access)
			 VALUES (?, ?, ?, ?)`,
			sessionID, i, e.Path, string(e.Access),
		); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO session_filesystem_snapshot_meta (session_id, entry_count, digest)
		 VALUES (?, ?, ?)`,
		sessionID, len(entries), sessionFilesystemSnapshotDigest(entries),
	); err != nil {
		return err
	}
	return nil
}
