package main

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func openDatabase(path string) (*sql.DB, error) {
	encoded := url.PathEscape(path)
	dsn := "file:" + encoded + "?_foreign_keys=on"

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("cannot open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("cannot connect to database: %w", err)
	}

	return db, nil
}

func initializeDatabase(db *sql.DB) error {
	if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
		return fmt.Errorf("cannot set journal_mode: %w", err)
	}

	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL UNIQUE,
			workspace TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			principal_id INTEGER REFERENCES principals(id)
		);

		CREATE TABLE IF NOT EXISTS principals (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			uid INTEGER NOT NULL,
			gid INTEGER NOT NULL,
			home TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1
		);

		CREATE TABLE IF NOT EXISTS principal_allowed_roots (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			principal_id INTEGER NOT NULL,
			root_path TEXT NOT NULL,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			UNIQUE(principal_id, root_path)
		);

		CREATE TABLE IF NOT EXISTS credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE
		);
	`)
	if err != nil {
		return fmt.Errorf("cannot create tables: %w", err)
	}

	// Additive migration: add principal_id to sessions if it doesn't exist.
	// This allows upgrading from an R1 database that only has sessions without principal_id.
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='principal_id';`).Scan(&count)
	if err != nil {
		return fmt.Errorf("cannot check sessions schema: %w", err)
	}
	if count == 0 {
		_, err = db.Exec(`ALTER TABLE sessions ADD COLUMN principal_id INTEGER REFERENCES principals(id)`)
		if err != nil {
			return fmt.Errorf("cannot add principal_id to sessions: %w", err)
		}
	}

	// Credential lifecycle migration: a credential name must be reusable after
	// its previous credential is revoked. The old schema enforced a hard
	// UNIQUE(principal_id, name), permanently reserving a name after revoke.
	// Replace it with a partial unique index over active (revoked_at IS NULL)
	// credentials, preserving revoked records as history.
	//
	// Detect the old table-level UNIQUE constraint by inspecting the stored
	// table DDL (the canonical schema this code created). If present, rebuild
	// the table without the constraint so the name can be reused after revoke.
	var credTableSQL string
	err = db.QueryRow(
		`SELECT sql FROM sqlite_master WHERE type='table' AND name='credentials'`,
	).Scan(&credTableSQL)
	if err != nil {
		return fmt.Errorf("cannot inspect credentials schema: %w", err)
	}
	normalized := strings.ToLower(strings.Join(strings.Fields(credTableSQL), ""))
	if strings.Contains(normalized, "unique(principal_id,name)") {
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("cannot begin credentials migration: %w", err)
		}
		_, err = tx.Exec(`
			CREATE TABLE credentials_new (
				id TEXT PRIMARY KEY,
				principal_id INTEGER NOT NULL,
				name TEXT NOT NULL,
				token_hash TEXT NOT NULL UNIQUE,
				created_at INTEGER NOT NULL,
				revoked_at INTEGER,
				FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE
			);
		`)
		if err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("cannot create new credentials table: %w", err)
		}
		_, err = tx.Exec(`INSERT INTO credentials_new SELECT id, principal_id, name, token_hash, created_at, revoked_at FROM credentials`)
		if err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("cannot migrate credentials data: %w", err)
		}
		_, err = tx.Exec(`DROP TABLE credentials`)
		if err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("cannot drop old credentials table: %w", err)
		}
		_, err = tx.Exec(`ALTER TABLE credentials_new RENAME TO credentials`)
		if err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("cannot rename credentials table: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("cannot commit credentials migration: %w", err)
		}
	}

	// Enforce active-name uniqueness with a partial unique index. On a fresh
	// database this is created after the initial CREATE TABLE; after the
	// migration above it is created on the rebuilt table. The old hard
	// UNIQUE guaranteed no duplicate active (principal_id, name) rows, so this
	// index creation cannot fail on migrated data.
	_, err = db.Exec(`
		CREATE UNIQUE INDEX IF NOT EXISTS credentials_active_name_unique
		ON credentials(principal_id, name) WHERE revoked_at IS NULL;
	`)
	if err != nil {
		return fmt.Errorf("cannot create active credential unique index: %w", err)
	}

	// Additive migration: mac_boundaries tracks docker-helper-owned MAC boundaries.
	// Primary key is (backend, boundary) so that stale ownership for another LSM
	// cannot silently block current backend ownership for the same filesystem boundary.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS mac_boundaries (
			backend TEXT NOT NULL,
			boundary TEXT NOT NULL,
			PRIMARY KEY (backend, boundary)
		);
	`)
	if err != nil {
		return fmt.Errorf("cannot create mac_boundaries table: %w", err)
	}

	// Additive migration: if the table existed with the old schema (boundary as
	// sole PK), migrate to the new composite key schema.
	var colCount int
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('mac_boundaries') WHERE name='backend' AND pk > 0;`).Scan(&colCount)
	if err != nil {
		return fmt.Errorf("cannot check mac_boundaries schema: %w", err)
	}
	if colCount == 0 {
		// Old schema: boundary is the sole PK. Migrate to (backend, boundary)
		// in a single atomic transaction so that partial failures leave the
		// database in a consistent state.
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("cannot begin mac_boundaries migration: %w", err)
		}
		_, err = tx.Exec(`
			CREATE TABLE mac_boundaries_new (
				backend TEXT NOT NULL,
				boundary TEXT NOT NULL,
				PRIMARY KEY (backend, boundary)
			);
		`)
		if err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("cannot create new mac_boundaries table: %w", err)
		}
		_, err = tx.Exec(`INSERT OR IGNORE INTO mac_boundaries_new SELECT backend, boundary FROM mac_boundaries`)
		if err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("cannot migrate mac_boundaries data: %w", err)
		}
		_, err = tx.Exec(`DROP TABLE mac_boundaries`)
		if err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("cannot drop old mac_boundaries table: %w", err)
		}
		_, err = tx.Exec(`ALTER TABLE mac_boundaries_new RENAME TO mac_boundaries`)
		if err != nil {
			tx.Rollback() //nolint:errcheck
			return fmt.Errorf("cannot rename mac_boundaries table: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("cannot commit mac_boundaries migration: %w", err)
		}
	}

	return nil
}

// cleanupExpiredSessions removes expired session rows from the database.
//
// Precondition: the caller must ensure no live daemon instance is running.
// During daemon startup, this is guaranteed because startup holds the daemon
// instance lock and calls this function before creating the MAC coordinator.
// For offline cleanup (docker-helper session cleanup), the caller acquires
// the daemon lock first.
func cleanupExpiredSessions(db *sql.DB) (int, error) {
	now := time.Now().Unix()

	result, err := db.Exec("DELETE FROM sessions WHERE expires_at <= ?", now)
	if err != nil {
		return 0, fmt.Errorf("cannot clean up expired sessions: %w", err)
	}

	n, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("cannot check cleanup result: %w", err)
	}

	return int(n), nil
}
