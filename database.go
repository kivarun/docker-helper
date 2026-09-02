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
			launcher_id TEXT NOT NULL REFERENCES launchers(id)
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

	// Classify the sessions schema and bring pre-cutover tables forward.
	//
	// The canonical fresh-database sessions table is the final Launcher-owned
	// shape (launcher_id NOT NULL, no principal_id). A final table must NEVER
	// have principal_id re-added on a later startup, so the R1 additive rule is
	// retired for any table that already carries launcher_id.
	class, err := classifySessionsSchema(db)
	if err != nil {
		return err
	}
	switch class {
	case sessionsSchemaFinal:
		// Canonical Launcher-owned schema; no cutover work needed here.
	case sessionsSchemaLegacyBare:
		// R1 sessions table with neither ownership column. This is the only
		// remaining case where the old principal_id additive rule applies: it
		// turns the bare table into the legacy principal-owned source that
		// migrateSessionOwnership (run from runDaemon) later rebuilds.
		if _, err := db.Exec(`ALTER TABLE sessions ADD COLUMN principal_id INTEGER REFERENCES principals(id)`); err != nil {
			return fmt.Errorf("cannot add principal_id to sessions: %w", err)
		}
	case sessionsSchemaLegacyPrincipal:
		// principal_id present and no launcher_id: the legitimate pre-cutover
		// source for Session ownership cutover. initializeDatabase leaves it
		// in place; migrateSessionOwnership rebuilds it to the final schema.
	case sessionsSchemaUnsupported:
		return fmt.Errorf("unsupported sessions schema")
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

// sessionsSchemaClass classifies the sessions table ownership shape. Ownership
// is exactly one of: legacy bare (neither column), legacy principal-owned
// (principal_id, no launcher_id), final Launcher-owned (launcher_id, no
// principal_id), or unsupported (hybrid/other => fail closed).
type sessionsSchemaClass int

const (
	// sessionsSchemaUnsupported is any hybrid or unrecognized shape (for
	// example both principal_id and launcher_id present). Initialization fails
	// closed rather than guessing at ownership.
	sessionsSchemaUnsupported sessionsSchemaClass = iota
	// sessionsSchemaLegacyBare is a pre-cutover R1 table with neither the old
	// principal_id nor the final launcher_id.
	sessionsSchemaLegacyBare
	// sessionsSchemaLegacyPrincipal is the pre-cutover principal-owned source
	// (principal_id present, launcher_id absent) that migrateSessionOwnership
	// rebuilds to the final schema.
	sessionsSchemaLegacyPrincipal
	// sessionsSchemaFinal is the canonical Launcher-owned schema (launcher_id
	// present, principal_id absent).
	sessionsSchemaFinal
)

// sessionsColumn captures the schema fields of one sessions column.
type sessionsColumn struct {
	name    string
	notNull bool
	pk      int
}

// readSessionsColumns returns the sessions columns in declared order.
func readSessionsColumns(db *sql.DB) ([]sessionsColumn, error) {
	rows, err := db.Query(
		`SELECT name, "notnull", pk FROM pragma_table_info('sessions') ORDER BY cid`,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot read sessions columns: %w", err)
	}
	defer rows.Close()

	var cols []sessionsColumn
	for rows.Next() {
		var c sessionsColumn
		if err := rows.Scan(&c.name, &c.notNull, &c.pk); err != nil {
			return nil, fmt.Errorf("cannot scan sessions column: %w", err)
		}
		cols = append(cols, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions columns: %w", err)
	}
	return cols, nil
}

// sessionsFK captures one foreign key declared on the sessions table.
type sessionsFK struct {
	table    string
	from     string
	to       string
	onDelete string
}

// readSessionsForeignKeys returns all foreign keys declared on sessions.
func readSessionsForeignKeys(db *sql.DB) ([]sessionsFK, error) {
	rows, err := db.Query(
		`SELECT "table", "from", "to", "on_delete" FROM pragma_foreign_key_list('sessions')`,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot read sessions foreign keys: %w", err)
	}
	defer rows.Close()

	var out []sessionsFK
	for rows.Next() {
		var fk sessionsFK
		if err := rows.Scan(&fk.table, &fk.from, &fk.to, &fk.onDelete); err != nil {
			return nil, fmt.Errorf("cannot scan sessions foreign key: %w", err)
		}
		out = append(out, fk)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions foreign keys: %w", err)
	}
	return out, nil
}

// sessionsUniqueIndex captures one user-declared unique index on the sessions
// table (origin 'u' from a UNIQUE constraint or 'c' from a CREATE UNIQUE INDEX
// statement; never the primary key index).
type sessionsUniqueIndex struct {
	name    string
	cols    []string
	partial bool
}

// readSessionsUniqueTokenIndexes returns the user-declared unique indexes on
// the sessions table with their columns and partial-index flag.
func readSessionsUniqueTokenIndexes(db *sql.DB) ([]sessionsUniqueIndex, error) {
	rows, err := db.Query(
		`SELECT name, "partial" FROM pragma_index_list('sessions') WHERE "unique"=1 AND "origin"!='pk'`,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot read sessions unique indexes: %w", err)
	}
	defer rows.Close()

	var out []sessionsUniqueIndex
	for rows.Next() {
		var idx sessionsUniqueIndex
		var partial int
		if err := rows.Scan(&idx.name, &partial); err != nil {
			return nil, fmt.Errorf("cannot scan sessions unique index: %w", err)
		}
		idx.partial = partial == 1
		cols, err := credentialsIndexColumns(db, idx.name)
		if err != nil {
			return nil, err
		}
		idx.cols = cols
		out = append(out, idx)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions unique indexes: %w", err)
	}
	return out, nil
}

// verifySessionsTokenHashUnique fails unless token_hash has an unconditional
// (non-partial) UNIQUE index. A partial unique index does not establish global
// token_hash uniqueness, so it is not accepted as proof of it.
func verifySessionsTokenHashUnique(db *sql.DB) error {
	indexes, err := readSessionsUniqueTokenIndexes(db)
	if err != nil {
		return err
	}
	for _, idx := range indexes {
		if !idx.partial && len(idx.cols) == 1 && idx.cols[0] == "token_hash" {
			return nil
		}
	}
	return unsupportedSessionsSchema("missing UNIQUE(token_hash)")
}

// unsupportedSessionsSchema returns a fail-closed error for an unrecognized
// sessions schema. The detail is a narrow human-readable reason; no destructive
// normalization is attempted.
func unsupportedSessionsSchema(detail string) error {
	return fmt.Errorf("unsupported sessions schema: %s", detail)
}

// sessionsBaseColumns is the canonical base column set shared by every
// supported sessions generation.
var sessionsBaseColumns = []string{"id", "token_hash", "workspace", "created_at", "expires_at"}

// classifySessionsSchema positively recognizes the supported sessions table
// ownership shapes from SQLite semantic metadata. A malformed table — hybrid
// owner columns, wrong/missing owner FK, nullable launcher_id, a Launcher FK
// with ON DELETE CASCADE, missing required base column, broken
// nullability/PK/unique structure, or an unexpected ownership shape — is
// rejected as unsupported rather than silently accepted merely because it
// contains a launcher_id column.
func classifySessionsSchema(db *sql.DB) (sessionsSchemaClass, error) {
	cols, err := readSessionsColumns(db)
	if err != nil {
		return sessionsSchemaUnsupported, err
	}
	colSet := make(map[string]sessionsColumn, len(cols))
	for _, c := range cols {
		colSet[c.name] = c
	}

	// Every supported generation shares the canonical base columns and their
	// required nullability/PK invariants: id primary key; token_hash NOT NULL
	// and unique; workspace/created_at/expires_at NOT NULL.
	for _, name := range sessionsBaseColumns {
		c, ok := colSet[name]
		if !ok {
			return sessionsSchemaUnsupported, unsupportedSessionsSchema(fmt.Sprintf("missing base column %q", name))
		}
		if name == "id" {
			if c.pk != 1 {
				return sessionsSchemaUnsupported, unsupportedSessionsSchema("id is not the primary key")
			}
			continue
		}
		if !c.notNull {
			return sessionsSchemaUnsupported, unsupportedSessionsSchema(fmt.Sprintf("column %q must be NOT NULL", name))
		}
	}
	if err := verifySessionsTokenHashUnique(db); err != nil {
		return sessionsSchemaUnsupported, err
	}

	hasPrincipal := false
	var principalCol sessionsColumn
	if c, ok := colSet["principal_id"]; ok {
		hasPrincipal = true
		principalCol = c
	}
	hasLauncher := false
	var launcherCol sessionsColumn
	if c, ok := colSet["launcher_id"]; ok {
		hasLauncher = true
		launcherCol = c
	}

	// Hybrid owner columns (both principal_id and launcher_id) are never a
	// supported generation.
	if hasPrincipal && hasLauncher {
		return sessionsSchemaUnsupported, unsupportedSessionsSchema("hybrid ownership columns (principal_id and launcher_id) present")
	}

	fks, err := readSessionsForeignKeys(db)
	if err != nil {
		return sessionsSchemaUnsupported, err
	}

	switch {
	case !hasPrincipal && !hasLauncher:
		if len(cols) != len(sessionsBaseColumns) {
			return sessionsSchemaUnsupported, unsupportedSessionsSchema("unexpected bare sessions column set")
		}
		if len(fks) != 0 {
			return sessionsSchemaUnsupported, unsupportedSessionsSchema("bare sessions schema must not declare foreign keys")
		}
		return sessionsSchemaLegacyBare, nil

	case hasPrincipal && !hasLauncher:
		if len(cols) != len(sessionsBaseColumns)+1 {
			return sessionsSchemaUnsupported, unsupportedSessionsSchema("unexpected legacy-principal sessions column set")
		}
		if principalCol.notNull {
			return sessionsSchemaUnsupported, unsupportedSessionsSchema("column principal_id must be nullable")
		}
		if !hasExactSessionsFK(fks, []sessionsFK{{table: "principals", from: "principal_id", to: "id", onDelete: "NO ACTION"}}) {
			return sessionsSchemaUnsupported, unsupportedSessionsSchema("legacy-principal sessions must declare exactly one principal_id -> principals(id) foreign key with no ON DELETE CASCADE")
		}
		return sessionsSchemaLegacyPrincipal, nil

	case !hasPrincipal && hasLauncher:
		if len(cols) != len(sessionsBaseColumns)+1 {
			return sessionsSchemaUnsupported, unsupportedSessionsSchema("unexpected final sessions column set")
		}
		if !launcherCol.notNull {
			return sessionsSchemaUnsupported, unsupportedSessionsSchema("column launcher_id must be NOT NULL")
		}
		if !hasExactSessionsFK(fks, []sessionsFK{{table: "launchers", from: "launcher_id", to: "id", onDelete: "NO ACTION"}}) {
			return sessionsSchemaUnsupported, unsupportedSessionsSchema("final sessions must declare exactly one launcher_id -> launchers(id) foreign key with no ON DELETE CASCADE")
		}
		return sessionsSchemaFinal, nil
	}
	return sessionsSchemaUnsupported, unsupportedSessionsSchema("unexpected ownership shape")
}

// hasExactSessionsFK reports whether the sessions table's foreign keys are
// exactly the given set (order-insensitive). An additional FK, a missing
// canonical FK, or a canonical FK with unexpected ON DELETE behavior is not
// accepted.
func hasExactSessionsFK(got, want []sessionsFK) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
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

// credentialsFK captures one foreign key declared on the credentials table.
type credentialsFK struct {
	table    string
	from     string
	to       string
	onDelete string
}

// readCredentialsForeignKeys returns all foreign keys declared on credentials.
func readCredentialsForeignKeys(db *sql.DB) ([]credentialsFK, error) {
	rows, err := db.Query(
		`SELECT "table", "from", "to", "on_delete" FROM pragma_foreign_key_list('credentials')`,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot read credentials foreign keys: %w", err)
	}
	defer rows.Close()

	var out []credentialsFK
	for rows.Next() {
		var fk credentialsFK
		if err := rows.Scan(&fk.table, &fk.from, &fk.to, &fk.onDelete); err != nil {
			return nil, fmt.Errorf("cannot scan credentials foreign key: %w", err)
		}
		out = append(out, fk)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credentials foreign keys: %w", err)
	}
	return out, nil
}

// verifyCredentialsForeignKeySet fails unless the credentials table's foreign
// keys are exactly the given canonical set (order-insensitive). Positive
// recognition is exact: an additional FK is unsupported, and a canonical FK
// with anything other than ON DELETE CASCADE is unsupported.
func verifyCredentialsForeignKeySet(db *sql.DB, want []credentialsFK) error {
	got, err := readCredentialsForeignKeys(db)
	if err != nil {
		return err
	}
	if len(got) != len(want) {
		return unsupportedCredentialsSchema(fmt.Sprintf("expected exactly %d foreign key(s), found %d", len(want), len(got)))
	}
	for _, w := range want {
		if !containsCredentialsFK(got, w) {
			return unsupportedCredentialsSchema(fmt.Sprintf("missing %s -> %s(%s) foreign key with ON DELETE CASCADE", w.from, w.table, w.to))
		}
	}
	return nil
}

func containsCredentialsFK(fks []credentialsFK, want credentialsFK) bool {
	for _, fk := range fks {
		if fk == want {
			return true
		}
	}
	return false
}

// credentialsIndexColumns returns the column names covered by the named index.
func credentialsIndexColumns(db *sql.DB, idxName string) ([]string, error) {
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

// credentialsUniqueIndex captures one user-declared unique index on the
// credentials table (origin 'u' from a UNIQUE constraint or 'c' from a
// CREATE UNIQUE INDEX statement; never the primary key index).
type credentialsUniqueIndex struct {
	name    string
	cols    []string
	partial bool
	where   string
}

// readCredentialsUniqueIndexes returns the user-declared unique indexes on the
// credentials table, with their columns and (for partial indexes) normalized
// WHERE clause.
func readCredentialsUniqueIndexes(db *sql.DB) ([]credentialsUniqueIndex, error) {
	rows, err := db.Query(
		`SELECT name, "partial" FROM pragma_index_list('credentials') WHERE "unique"=1 AND "origin"!='pk'`,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot read credentials unique indexes: %w", err)
	}
	defer rows.Close()

	var out []credentialsUniqueIndex
	for rows.Next() {
		var idx credentialsUniqueIndex
		var partial int
		if err := rows.Scan(&idx.name, &partial); err != nil {
			return nil, fmt.Errorf("cannot scan credentials unique index: %w", err)
		}
		idx.partial = partial == 1
		cols, err := credentialsIndexColumns(db, idx.name)
		if err != nil {
			return nil, err
		}
		idx.cols = cols
		if idx.partial {
			var sqlText sql.NullString
			if err := db.QueryRow(
				`SELECT sql FROM sqlite_master WHERE type='index' AND name=?`,
				idx.name,
			).Scan(&sqlText); err != nil {
				return nil, fmt.Errorf("cannot inspect index %q: %w", idx.name, err)
			}
			if sqlText.Valid {
				idx.where = strings.ToLower(strings.Join(strings.Fields(sqlText.String), ""))
			}
		}
		out = append(out, idx)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credentials unique indexes: %w", err)
	}
	return out, nil
}

// isActiveNameIndex reports whether idx is the canonical Principal active-name
// partial unique index: credentials_active_name_unique on (principal_id, name)
// with the exact normalized predicate WHERE revoked_at IS NULL. Positive
// recognition is exact; a predicate such as "revoked_at IS NULL OR 1=1" is
// not canonical.
func isActiveNameIndex(idx credentialsUniqueIndex) bool {
	return idx.partial &&
		idx.name == "credentials_active_name_unique" &&
		len(idx.cols) == 2 &&
		idx.cols[0] == "principal_id" &&
		idx.cols[1] == "name" &&
		strings.HasSuffix(idx.where, "whererevoked_atisnull")
}

// verifyCredentialsUniqueness fails unless the final schema's unique indexes
// are exactly the canonical set: UNIQUE(token_hash), UNIQUE(launcher_id), and
// (when present) the expected Principal active-name partial unique index. Any
// additional unique constraint/index that changes credential cardinality (for
// example UNIQUE(principal_id)) is rejected.
func verifyCredentialsUniqueness(db *sql.DB) error {
	indexes, err := readCredentialsUniqueIndexes(db)
	if err != nil {
		return err
	}

	foundTokenHash := false
	foundLauncher := false
	for _, idx := range indexes {
		switch {
		case !idx.partial && len(idx.cols) == 1 && idx.cols[0] == "token_hash":
			foundTokenHash = true
		case !idx.partial && len(idx.cols) == 1 && idx.cols[0] == "launcher_id":
			foundLauncher = true
		case isActiveNameIndex(idx):
			// Expected Principal active-name partial unique index; canonical when present.
		default:
			return unsupportedCredentialsSchema(fmt.Sprintf("unexpected unique index on %q", idx.cols))
		}
	}
	if !foundTokenHash {
		return unsupportedCredentialsSchema("missing UNIQUE(token_hash)")
	}
	if !foundLauncher {
		return unsupportedCredentialsSchema("missing UNIQUE(launcher_id)")
	}
	return nil
}

// verifyPre21NameUniqueness fails unless the pre-2.1 source has exactly one
// supported name-uniqueness generation: either the historical table-level
// UNIQUE(principal_id, name) or the current credentials_active_name_unique
// partial index on (principal_id, name) WHERE revoked_at IS NULL. Neither or
// both is unsupported. token_hash must also be UNIQUE.
func verifyPre21NameUniqueness(db *sql.DB) error {
	indexes, err := readCredentialsUniqueIndexes(db)
	if err != nil {
		return err
	}

	foundTokenHash := false
	hasHardUnique := false
	hasActiveName := false
	for _, idx := range indexes {
		switch {
		case !idx.partial && len(idx.cols) == 1 && idx.cols[0] == "token_hash":
			foundTokenHash = true
		case !idx.partial && len(idx.cols) == 2 && idx.cols[0] == "principal_id" && idx.cols[1] == "name":
			// Historical generation: table-level hard UNIQUE(principal_id, name).
			hasHardUnique = true
		case isActiveNameIndex(idx):
			// Current generation: active-name partial unique index.
			hasActiveName = true
		default:
			return unsupportedCredentialsSchema(fmt.Sprintf("unexpected unique index on %q", idx.cols))
		}
	}
	if !foundTokenHash {
		return unsupportedCredentialsSchema("missing UNIQUE(token_hash)")
	}
	if hasHardUnique == hasActiveName {
		if hasHardUnique {
			return unsupportedCredentialsSchema("both name-uniqueness generations present")
		}
		return unsupportedCredentialsSchema("missing name-uniqueness generation")
	}
	return nil
}

// verifyCredentialsOwnerCheck fails unless the credentials table declares the
// one canonical concrete-owner CHECK expression. SQLite exposes CHECK constraints
// only through the stored table DDL, so sqlite_master is inspected here
// (normalized) and nowhere else. Do not accept merely because both branch
// substrings occur somewhere in DDL; require the exact canonical expression.
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
	// The canonical CHECK must be the exact expression:
	// ((principal_id IS NOT NULL AND launcher_id IS NULL AND name IS NOT NULL)
	//  OR (principal_id IS NULL AND launcher_id IS NOT NULL AND name IS NULL))
	// Normalize whitespace and case, then match the exact expression.
	expected := "((principal_idisnotnullandlauncher_idisnullandnameisnotnull)or(principal_idisnullandlauncher_idisnotnullandnameisnull))"
	if !strings.Contains(normalized, "check"+expected) {
		return unsupportedCredentialsSchema("non-canonical concrete-owner check")
	}
	// Reject additional CHECK constraints that change credential cardinality.
	// Count occurrences of "check(" - there must be exactly one.
	checkCount := strings.Count(normalized, "check(")
	if checkCount != 1 {
		return unsupportedCredentialsSchema(fmt.Sprintf("expected exactly one check constraint, found %d", checkCount))
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
		// columns with the Principal-only required semantics:
		// - id primary key
		// - token_hash UNIQUE
		// - principal_id -> principals(id) ON DELETE CASCADE
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
		// Exactly one supported name-uniqueness generation plus UNIQUE(token_hash).
		if err := verifyPre21NameUniqueness(db); err != nil {
			return credentialsSchemaUnsupported, err
		}
		// Exactly one FK: the canonical Principal FK.
		if err := verifyCredentialsForeignKeySet(db, []credentialsFK{
			{table: "principals", from: "principal_id", to: "id", onDelete: "CASCADE"},
		}); err != nil {
			return credentialsSchemaUnsupported, err
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
	if err := verifyCredentialsForeignKeySet(db, []credentialsFK{
		{table: "principals", from: "principal_id", to: "id", onDelete: "CASCADE"},
		{table: "launchers", from: "launcher_id", to: "id", onDelete: "CASCADE"},
	}); err != nil {
		return credentialsSchemaUnsupported, err
	}
	if err := verifyCredentialsUniqueness(db); err != nil {
		return credentialsSchemaUnsupported, err
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
