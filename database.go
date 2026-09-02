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

// credentialsSchemaClass identifies the supported credentials table shapes.
type credentialsSchemaClass int

const (
	// credentialsSchemaUnsupported is any schema the classifier does not
	// recognize. Database initialization fails closed rather than guessing.
	credentialsSchemaUnsupported credentialsSchemaClass = iota
	// credentialsSchemaPre21 is the supported Principal-only source schema
	// (with or without the historical table-level UNIQUE(principal_id, name)).
	credentialsSchemaPre21
	// credentialsSchemaFinal is the canonical concrete-owner schema.
	credentialsSchemaFinal
)

// unsupportedCredentialsSchema returns a clear fail-closed error for an
// unrecognized credentials schema. The detail is a narrow human-readable
// reason; no destructive normalization is attempted.
func unsupportedCredentialsSchema(detail string) error {
	return fmt.Errorf("unsupported credentials schema: %s", detail)
}

// credentialsColumn captures the schema fields of one column.
type credentialsColumn struct {
	name    string
	notNull bool
	pk      int
}

// readCredentialsColumns returns the credentials columns in declared order.
func readCredentialsColumns(db *sql.DB) ([]credentialsColumn, error) {
	rows, err := db.Query(
		`SELECT name, "notnull", pk FROM pragma_table_info('credentials') ORDER BY cid`,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot read credentials columns: %w", err)
	}
	defer rows.Close()

	var cols []credentialsColumn
	for rows.Next() {
		var c credentialsColumn
		if err := rows.Scan(&c.name, &c.notNull, &c.pk); err != nil {
			return nil, fmt.Errorf("cannot scan credentials column: %w", err)
		}
		cols = append(cols, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credentials columns: %w", err)
	}
	return cols, nil
}

// verifyCredentialsForeignKeys fails unless the schema declares the concrete
// owner FKs: principal_id -> principals(id) and launcher_id -> launchers(id).
func verifyCredentialsForeignKeys(db *sql.DB) error {
	rows, err := db.Query(
		`SELECT "table", "from", "to" FROM pragma_foreign_key_list('credentials')`,
	)
	if err != nil {
		return fmt.Errorf("cannot read credentials foreign keys: %w", err)
	}
	defer rows.Close()

	foundPrincipal := false
	foundLauncher := false
	for rows.Next() {
		var tbl, from, to string
		if err := rows.Scan(&tbl, &from, &to); err != nil {
			return fmt.Errorf("cannot scan credentials foreign key: %w", err)
		}
		if tbl == "principals" && from == "principal_id" && to == "id" {
			foundPrincipal = true
		}
		if tbl == "launchers" && from == "launcher_id" && to == "id" {
			foundLauncher = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate credentials foreign keys: %w", err)
	}
	if !foundPrincipal {
		return unsupportedCredentialsSchema("missing principal_id foreign key")
	}
	if !foundLauncher {
		return unsupportedCredentialsSchema("missing launcher_id foreign key")
	}
	return nil
}

// indexColumns returns the column names covered by the named index.
func indexColumns(db *sql.DB, idxName string) ([]string, error) {
	rows, err := db.Query(`SELECT name FROM pragma_index_info(?)`, idxName)
	if err != nil {
		return nil, fmt.Errorf("cannot read index %q columns: %w", idxName, err)
	}
	defer rows.Close()

	var cols []string
	for rows.Next() {
		var name sql.NullString
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("cannot scan index %q column: %w", idxName, err)
		}
		if name.Valid {
			cols = append(cols, name.String)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate index %q columns: %w", idxName, err)
	}
	return cols, nil
}

// hasUniqueIndexOnColumn reports whether a user-declared UNIQUE index covers
// exactly the given column.
func hasUniqueIndexOnColumn(db *sql.DB, col string) (bool, error) {
	rows, err := db.Query(
		`SELECT name FROM pragma_index_list('credentials') WHERE "unique"=1 AND "origin"='u'`,
	)
	if err != nil {
		return false, fmt.Errorf("cannot read credentials indexes: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var idxName string
		if err := rows.Scan(&idxName); err != nil {
			return false, fmt.Errorf("cannot scan credentials index: %w", err)
		}
		cols, err := indexColumns(db, idxName)
		if err != nil {
			return false, err
		}
		if len(cols) == 1 && cols[0] == col {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate credentials indexes: %w", err)
	}
	return false, nil
}

// verifyCredentialsOwnerCheck fails unless the credentials table declares the
// concrete-owner CHECK. SQLite exposes CHECK constraints only through the stored
// table DDL, so sqlite_master is inspected here (normalized) and nowhere else.
func verifyCredentialsOwnerCheck(db *sql.DB) error {
	var ddl sql.NullString
	err := db.QueryRow(
		`SELECT sql FROM sqlite_master WHERE type='table' AND name='credentials'`,
	).Scan(&ddl)
	if err != nil {
		return fmt.Errorf("cannot inspect credentials table definition: %w", err)
	}
	if !ddl.Valid || ddl.String == "" {
		return unsupportedCredentialsSchema("credentials table definition unavailable")
	}
	normalized := strings.ToLower(strings.Join(strings.Fields(ddl.String), ""))
	if !strings.Contains(normalized, "check(") {
		return unsupportedCredentialsSchema("missing concrete-owner check")
	}
	if !strings.Contains(normalized, "principal_idisnotnullandlauncher_idisnullandnameisnotnull") {
		return unsupportedCredentialsSchema("missing Principal credential owner check")
	}
	if !strings.Contains(normalized, "principal_idisnullandlauncher_idisnotnullandnameisnull") {
		return unsupportedCredentialsSchema("missing Launcher credential owner check")
	}
	return nil
}

// classifyCredentialsSchema classifies the credentials table as a supported
// migration source (pre-2.1 Principal-only), the final concrete-owner schema,
// or unsupported. A mere launcher_id column is not enough to be considered
// final: the full structural invariants (nullable owner/name shape, concrete
// owner foreign keys, UNIQUE(launcher_id), and the concrete-owner CHECK) must
// hold, otherwise initialization fails closed instead of accepting a
// partial/corrupt schema as final.
func classifyCredentialsSchema(db *sql.DB) (credentialsSchemaClass, error) {
	cols, err := readCredentialsColumns(db)
	if err != nil {
		return credentialsSchemaUnsupported, err
	}

	colSet := make(map[string]credentialsColumn, len(cols))
	for _, c := range cols {
		colSet[c.name] = c
	}

	if _, hasLauncher := colSet["launcher_id"]; !hasLauncher {
		// Pre-2.1 Principal-only source. Must be exactly the six canonical
		// columns with the Principal-only required semantics.
		required := []string{"id", "principal_id", "name", "token_hash", "created_at", "revoked_at"}
		if len(cols) != len(required) {
			return credentialsSchemaUnsupported, unsupportedCredentialsSchema("unexpected credentials column set")
		}
		for _, name := range required {
			if _, ok := colSet[name]; !ok {
				return credentialsSchemaUnsupported, unsupportedCredentialsSchema(fmt.Sprintf("missing column %q", name))
			}
		}
		if colSet["id"].pk != 1 {
			return credentialsSchemaUnsupported, unsupportedCredentialsSchema("id is not the primary key")
		}
		for _, name := range []string{"principal_id", "name", "token_hash", "created_at"} {
			if !colSet[name].notNull {
				return credentialsSchemaUnsupported, unsupportedCredentialsSchema(fmt.Sprintf("column %q must be NOT NULL", name))
			}
		}
		return credentialsSchemaPre21, nil
	}

	// launcher_id present -> must be the final concrete-owner schema.
	required := []string{"id", "principal_id", "launcher_id", "name", "token_hash", "created_at", "revoked_at"}
	if len(cols) != len(required) {
		return credentialsSchemaUnsupported, unsupportedCredentialsSchema("unexpected credentials column set")
	}
	for _, name := range required {
		if _, ok := colSet[name]; !ok {
			return credentialsSchemaUnsupported, unsupportedCredentialsSchema(fmt.Sprintf("missing column %q", name))
		}
	}
	// Owner/name columns are nullable in the final schema.
	for _, name := range []string{"principal_id", "launcher_id", "name"} {
		if colSet[name].notNull {
			return credentialsSchemaUnsupported, unsupportedCredentialsSchema(fmt.Sprintf("column %q must be nullable", name))
		}
	}
	if colSet["id"].pk != 1 {
		return credentialsSchemaUnsupported, unsupportedCredentialsSchema("id is not the primary key")
	}
	for _, name := range []string{"token_hash", "created_at"} {
		if !colSet[name].notNull {
			return credentialsSchemaUnsupported, unsupportedCredentialsSchema(fmt.Sprintf("column %q must be NOT NULL", name))
		}
	}
	if err := verifyCredentialsForeignKeys(db); err != nil {
		return credentialsSchemaUnsupported, err
	}
	for _, name := range []string{"launcher_id", "token_hash"} {
		ok, err := hasUniqueIndexOnColumn(db, name)
		if err != nil {
			return credentialsSchemaUnsupported, err
		}
		if !ok {
			return credentialsSchemaUnsupported, unsupportedCredentialsSchema(fmt.Sprintf("missing UNIQUE(%s)", name))
		}
	}
	if err := verifyCredentialsOwnerCheck(db); err != nil {
		return credentialsSchemaUnsupported, err
	}
	return credentialsSchemaFinal, nil
}

// migrateCredentialsToConcreteOwnerSchema migrates a pre-2.1 credentials table
// to the final single-table, single-concrete-owner schema in one atomic
// transaction. Every existing Principal credential row is preserved exactly:
// id, principal_id, name, token_hash, created_at, revoked_at remain unchanged
// and launcher_id is set to NULL. No Launcher credential is fabricated and no
// existing credential is issued or revoked during migration.
//
// The schema is classified before any mutation. A valid final concrete-owner
// schema is accepted unchanged; an unsupported or partial schema fails closed
// and is never destructively normalized. The pre-2.1 source covers both the
// current v2.0 schema (principal_id NOT NULL, partial active-name index) and
// the older schema with a table-level UNIQUE(principal_id, name): both lack
// launcher_id and are rebuilt. The table-level hard UNIQUE is dropped by the
// rebuild; active-name uniqueness is re-enforced by the partial index created
// by the caller after this returns.
//
// A crash before commit leaves the old table usable; a crash after commit
// leaves the final table usable and the next call classifies it as final.
func migrateCredentialsToConcreteOwnerSchema(db *sql.DB) error {
	class, err := classifyCredentialsSchema(db)
	if err != nil {
		return err
	}
	if class == credentialsSchemaFinal {
		// Already at the final concrete-owner schema; never mutate it.
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
