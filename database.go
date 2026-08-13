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

		CREATE TABLE IF NOT EXISTS credentials (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			revoked_at INTEGER,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			UNIQUE(principal_id, name)
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

	return nil
}

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
