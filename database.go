package main

import (
	"database/sql"
	"fmt"
	"net/url"
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

		CREATE TABLE IF NOT EXISTS launchers (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			scope_mode TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			UNIQUE (principal_id, name),
			CHECK (scope_mode IN ('inherit', 'restricted'))
		);

		CREATE TABLE IF NOT EXISTS launcher_allowed_roots (
			launcher_id TEXT NOT NULL,
			root_path TEXT NOT NULL,
			FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE CASCADE,
			UNIQUE (launcher_id, root_path)
		);

		CREATE TABLE IF NOT EXISTS credentials (
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
			)
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

	// Migrate any pre-2.1 credentials table to the final single-table,
	// single-concrete-owner schema. Existing Principal credential rows are
	// preserved byte-for-byte with launcher_id left NULL. On a fresh database
	// the table already has the final schema and this is a no-op.
	if err := migrateCredentialsToConcreteOwnerSchema(db); err != nil {
		return err
	}

	// Enforce active Principal-credential name uniqueness with a partial unique
	// index over active (revoked_at IS NULL) credentials, preserving revoked
	// records as history so a name can be reused after revoke. On a fresh
	// database this is created after the initial CREATE TABLE; after the
	// migration above it is created on the rebuilt table. The old hard
	// UNIQUE(principal_id, name) guaranteed no duplicate active rows, so this
	// index creation cannot fail on migrated data unless the source was already
	// corrupt with two active same-name rows.
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

// migrateCredentialsToConcreteOwnerSchema migrates a pre-2.1 credentials table
// to the final single-table, single-concrete-owner schema in one atomic
// transaction. Every existing Principal credential row is preserved exactly:
// id, principal_id, name, token_hash, created_at, revoked_at remain unchanged
// and launcher_id is set to NULL. No Launcher credential is fabricated and no
// existing credential is issued or revoked during migration.
//
// Detection is by schema introspection: if the credentials table already has
// the launcher_id column it is already at the final schema and this is a no-op.
// This covers both the current v2.0 schema (principal_id NOT NULL, partial
// active-name index) and the older schema with a table-level
// UNIQUE(principal_id, name): both lack launcher_id and are rebuilt. The
// table-level hard UNIQUE is dropped by the rebuild; active-name uniqueness is
// re-enforced by the partial index created by the caller after this returns.
//
// A crash before commit leaves the old table usable; a crash after commit
// leaves the final table usable and the next call detects the final schema.
func migrateCredentialsToConcreteOwnerSchema(db *sql.DB) error {
	var launcherCol int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM pragma_table_info('credentials') WHERE name='launcher_id';`,
	).Scan(&launcherCol)
	if err != nil {
		return fmt.Errorf("cannot inspect credentials schema: %w", err)
	}
	if launcherCol > 0 {
		// Already at the final concrete-owner schema.
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("cannot begin credentials migration: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		CREATE TABLE credentials_new (
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
			)
		);
	`)
	if err != nil {
		return fmt.Errorf("cannot create new credentials table: %w", err)
	}

	_, err = tx.Exec(`
		INSERT INTO credentials_new (id, principal_id, launcher_id, name, token_hash, created_at, revoked_at)
		SELECT id, principal_id, NULL, name, token_hash, created_at, revoked_at
		FROM credentials
	`)
	if err != nil {
		return fmt.Errorf("cannot migrate credentials data: %w", err)
	}

	_, err = tx.Exec(`DROP TABLE credentials`)
	if err != nil {
		return fmt.Errorf("cannot drop old credentials table: %w", err)
	}

	_, err = tx.Exec(`ALTER TABLE credentials_new RENAME TO credentials`)
	if err != nil {
		return fmt.Errorf("cannot rename credentials table: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cannot commit credentials migration: %w", err)
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
