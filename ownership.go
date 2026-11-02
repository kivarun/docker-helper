package main

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// findDefaultLauncher is the read-only request-time resolver for a Principal's
// 'default' Launcher. Unlike ensureDefaultLauncher it never mutates state:
// request-time default resolution must not create Launchers.
func findDefaultLauncher(q sqlExecutor, principalID int64) (string, error) {
	var id string
	err := q.QueryRow(
		`SELECT id FROM launchers WHERE principal_id = ? AND name = 'default'`,
		principalID,
	).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrLauncherNotFound
		}
		return "", err
	}
	return id, nil
}

// sqlExecutor abstracts the narrow database operations used to resolve/create
// default Launchers so the same helper can run against *sql.DB (startup
// provisioning) and *sql.Tx (migration). It intentionally exposes only the
// operations this ownership path needs; it is not a generic repository.
type sqlExecutor interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

// ensureDefaultLauncher returns the ID of the given Principal's 'default'
// inherit-scope Launcher, creating it idempotently if absent. Uniqueness is
// enforced by UNIQUE(principal_id, name). This is deliberately a narrow insert
// (no roots, no credential) and does not route through createLauncher, so it
// is safe to call inside a transaction for migration.
func ensureDefaultLauncher(q sqlExecutor, principalID int64) (string, error) {
	var id string
	err := q.QueryRow(
		`SELECT id FROM launchers WHERE principal_id = ? AND name = 'default'`,
		principalID,
	).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	// The migration/bootstrap insertion uses the centralized Launcher write
	// path's name validator, so a grammar that would make 'default' invalid
	// fails closed here instead of silently inserting an invalid name.
	if _, err := validateLauncherName(defaultLauncherName); err != nil {
		return "", fmt.Errorf("default Launcher name rejected by the launcher-name grammar: %w", err)
	}
	newID, err := generateLauncherID()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	if _, err := q.Exec(
		`INSERT OR IGNORE INTO launchers (id, principal_id, name, enabled, scope_mode, created_at)
		 VALUES (?, ?, 'default', 1, 'inherit', ?)`,
		newID, principalID, now,
	); err != nil {
		return "", err
	}
	// A concurrent identical insert (or a prior partial run) may have won;
	// re-read the canonical row.
	err = q.QueryRow(
		`SELECT id FROM launchers WHERE principal_id = ? AND name = 'default'`,
		principalID,
	).Scan(&id)
	if err != nil {
		return "", err
	}
	return id, nil
}

// sessionMigrationResult reports the outcome of a Session ownership cutover.
type sessionMigrationResult struct {
	// attributedPrincipal counts legacy principal-owned Session rows mapped to
	// that Principal's default Launcher.
	attributedPrincipal int
	// invalidated counts legacy NULL-owner Session rows that were dropped
	// because they have no Principal -> Launcher ownership chain.
	invalidated int
}

// migrateSessionOwnership rebuilds a pre-cutover sessions table to the final
// Launcher-owned schema in one atomic transaction. It is idempotent and
// restart-safe: on the final schema it is a no-op, and a crash before commit
// leaves the legacy table intact for the next startup to retry.
//
// Legacy principal-owned rows (old principal_id IS NOT NULL) map to that
// Principal's 'default' Launcher (created idempotently if absent). Legacy
// NULL-owner rows are invalidated (dropped) in the same transaction: a
// Session owner is always a Launcher, and a NULL-owner row carries no
// Principal -> Launcher ownership chain to rebuild. A dangling non-null
// Principal reference fails the migration rather than silently dropping.
//
// This must not call createLauncher (which opens a nested transaction); it uses
// the narrow ensureDefaultLauncher insert helper.
func migrateSessionOwnership(db *sql.DB) (*sessionMigrationResult, error) {
	class, err := classifySessionsSchema(db)
	if err != nil {
		return nil, err
	}
	if class == sessionsSchemaFinal {
		// Already at the final Launcher-owned schema; never re-add principal_id.
		return &sessionMigrationResult{}, nil
	}
	// The bare R1 shape is owned by initializeDatabase, which adds
	// principal_id before this rebuild runs. This function therefore only ever
	// consumes the legacy principal-owned source (principal_id present,
	// launcher_id absent) or the final schema handled above; anything else is
	// unsupported and fails closed.
	if class != sessionsSchemaLegacyPrincipal {
		return nil, fmt.Errorf("unsupported sessions schema for ownership migration")
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("cannot begin session ownership migration: %w", err)
	}
	defer tx.Rollback()

	// Resolve default Launchers for every Principal that owns at least one
	// Session, counting attributable rows. A Session referencing a non-existent
	// Principal is a dangling reference and must fail the migration, never be
	// silently dropped.
	rows, err := tx.Query(`SELECT DISTINCT principal_id FROM sessions WHERE principal_id IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("cannot enumerate principal-owned sessions: %w", err)
	}
	type principalDefault struct {
		launcherID string
		count      int
	}
	defaultByPrincipal := make(map[int64]principalDefault)
	for rows.Next() {
		var pid int64
		if err := rows.Scan(&pid); err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot scan principal id: %w", err)
		}
		var exists int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM principals WHERE id = ?`, pid).Scan(&exists); err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot check session principal: %w", err)
		}
		if exists == 0 {
			rows.Close()
			return nil, fmt.Errorf("session references principal %d which no longer exists", pid)
		}
		launcherID, err := ensureDefaultLauncher(tx, pid)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot provision default Launcher for principal %d: %w", pid, err)
		}
		var count int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM sessions WHERE principal_id = ?`, pid).Scan(&count); err != nil {
			rows.Close()
			return nil, fmt.Errorf("cannot count principal-owned sessions: %w", err)
		}
		defaultByPrincipal[pid] = principalDefault{launcherID: launcherID, count: count}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate principal-owned sessions: %w", err)
	}

	// Determine whether legacy NULL-owner rows exist; they are invalidated.
	var nullCount int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sessions WHERE principal_id IS NULL`).Scan(&nullCount); err != nil {
		return nil, fmt.Errorf("cannot count legacy ownerless sessions: %w", err)
	}

	if _, err := tx.Exec(`
		CREATE TABLE sessions_new (
			id TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL UNIQUE,
			workspace TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			launcher_id TEXT NOT NULL REFERENCES launchers(id)
		)`,
	); err != nil {
		return nil, fmt.Errorf("cannot create new sessions table: %w", err)
	}

	// Copy principal-owned rows, resolving each to its default Launcher. Any
	// attributable Principal that could not be mapped would be silently
	// dropped, so the per-Principal row count guard below fails closed instead.
	principalOwned := 0
	for pid, pd := range defaultByPrincipal {
		if _, err := tx.Exec(
			`INSERT INTO sessions_new (id, token_hash, workspace, created_at, expires_at, launcher_id)
			 SELECT id, token_hash, workspace, created_at, expires_at, ?
			 FROM sessions WHERE principal_id = ?`,
			pd.launcherID, pid,
		); err != nil {
			return nil, fmt.Errorf("cannot migrate principal-owned sessions: %w", err)
		}
		principalOwned += pd.count
	}

	// Verify no attributable principal-owned Session was dropped.
	var totalPrincipalOwned int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sessions WHERE principal_id IS NOT NULL`).Scan(&totalPrincipalOwned); err != nil {
		return nil, fmt.Errorf("cannot count attributable principal-owned sessions: %w", err)
	}
	if principalOwned != totalPrincipalOwned {
		return nil, fmt.Errorf("session ownership migration would drop %d principal-owned session(s)", totalPrincipalOwned-principalOwned)
	}

	// Legacy NULL-owner rows are not copied; they are invalidated.

	if _, err := tx.Exec(`DROP TABLE sessions`); err != nil {
		return nil, fmt.Errorf("cannot drop old sessions table: %w", err)
	}
	if _, err := tx.Exec(`ALTER TABLE sessions_new RENAME TO sessions`); err != nil {
		return nil, fmt.Errorf("cannot rename sessions table: %w", err)
	}

	// Integrity gate before commit: the rebuilt sessions table must have no
	// foreign-key violations (e.g. a dangling launcher_id). Fail (and roll back,
	// leaving the legacy table intact) rather than commit a corrupt result. This
	// is independent of whether FK enforcement is on for this connection: the
	// check reports existing violations even when enforcement is disabled.
	if err := checkSessionsForeignKeys(tx); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("cannot commit session ownership migration: %w", err)
	}

	result := &sessionMigrationResult{
		attributedPrincipal: principalOwned,
		invalidated:         nullCount,
	}
	return result, nil
}

// checkSessionsForeignKeys fails the migration if any foreign-key violation
// exists in the rebuilt sessions table. PRAGMA foreign_key_check('sessions')
// returns one row per violation in that table regardless of whether FK
// enforcement is enabled on this connection; no rows means the rebuilt
// sessions table's foreign keys hold. Scoping to sessions keeps the check
// specific to this migration: an unrelated FK violation in another table must
// not fail migrateSessionOwnership.
func checkSessionsForeignKeys(tx *sql.Tx) error {
	var table, parent string
	var rowid int64
	var fkid int
	err := tx.QueryRow(`PRAGMA foreign_key_check('sessions')`).Scan(&table, &rowid, &parent, &fkid)
	if err == nil {
		return fmt.Errorf("session ownership migration integrity check failed: foreign key violation in %s (rowid %d, parent %s, fkid %d)", table, rowid, parent, fkid)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return fmt.Errorf("cannot run session ownership integrity check: %w", err)
}

// migrateDefaultLaunchers backfills the canonical 'default' Launcher for every
// Principal that does not have one yet: Principals created by earlier releases
// and those without migrated Session rows. The Launcher-owned Session model
// requires every Principal to have its default ownership anchor, so request-time
// default resolution never fails for missing ownership. It is idempotent and
// restart-safe: Principals that already carry a 'default' Launcher are skipped,
// and each backfill is an independent idempotent insert, so a crash mid-way
// leaves earlier Principals backfilled for the next startup to continue. It
// returns the number of default Launchers provisioned by this run.
func migrateDefaultLaunchers(db *sql.DB) (int, error) {
	rows, err := db.Query(`SELECT id FROM principals`)
	if err != nil {
		return 0, fmt.Errorf("cannot enumerate principals: %w", err)
	}
	var principalIDs []int64
	for rows.Next() {
		var pid int64
		if err := rows.Scan(&pid); err != nil {
			rows.Close()
			return 0, fmt.Errorf("cannot scan principal id: %w", err)
		}
		principalIDs = append(principalIDs, pid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate principals: %w", err)
	}

	created := 0
	for _, pid := range principalIDs {
		if _, err := findDefaultLauncher(db, pid); err == nil {
			continue
		} else if !errors.Is(err, ErrLauncherNotFound) {
			return 0, fmt.Errorf("cannot resolve default Launcher for principal %d: %w", pid, err)
		}
		if _, err := ensureDefaultLauncher(db, pid); err != nil {
			return 0, fmt.Errorf("cannot provision default Launcher for principal %d: %w", pid, err)
		}
		created++
	}
	return created, nil
}
