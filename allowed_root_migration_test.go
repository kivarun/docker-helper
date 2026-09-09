package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// assertAllowedRootsAccessSchema verifies the canonical access-bearing schema
// invariants of one allowed-roots table through SQLite semantic metadata:
// the access column is NOT NULL, the declared CHECK is exactly the canonical
// two-value constraint, the owner/path unique identity is preserved, and the
// owner FK keeps ON DELETE CASCADE.
func assertAllowedRootsAccessSchema(t *testing.T, db *sql.DB, table, ownerCol, ownerTable string, withID bool) {
	t.Helper()

	cols, err := readAllowedRootsColumns(db, table)
	if err != nil {
		t.Fatalf("read %s columns: %v", table, err)
	}
	colSet := make(map[string]allowedRootsColumn, len(cols))
	for _, c := range cols {
		colSet[c.name] = c
	}
	if withID {
		if len(cols) != 4 {
			t.Fatalf("%s has %d columns, want 4", table, len(cols))
		}
		if colSet["id"].pk != 1 {
			t.Errorf("%s id is not the primary key", table)
		}
	} else if len(cols) != 3 {
		t.Fatalf("%s has %d columns, want 3", table, len(cols))
	}
	if _, ok := colSet["access"]; !ok {
		t.Fatalf("%s has no access column", table)
	}
	if !colSet["access"].notNull {
		t.Errorf("%s access must be NOT NULL", table)
	}
	if !colSet[ownerCol].notNull {
		t.Errorf("%s %s must be NOT NULL", table, ownerCol)
	}
	if !colSet["root_path"].notNull {
		t.Errorf("%s root_path must be NOT NULL", table)
	}

	fks, err := readAllowedRootsForeignKeys(db, table)
	if err != nil {
		t.Fatalf("read %s foreign keys: %v", table, err)
	}
	if len(fks) != 1 || fks[0] != (allowedRootsFK{table: ownerTable, from: ownerCol, to: "id", onDelete: "CASCADE"}) {
		t.Errorf("%s foreign keys = %+v, want the canonical %s -> %s(id) CASCADE", table, fks, ownerCol, ownerTable)
	}

	indexRows, err := db.Query(
		`SELECT name FROM pragma_index_list(?) WHERE "unique"=1 AND "origin"!='pk'`,
		table,
	)
	if err != nil {
		t.Fatalf("read %s unique indexes: %v", table, err)
	}
	var indexNames []string
	for indexRows.Next() {
		var name string
		if err := indexRows.Scan(&name); err != nil {
			t.Fatalf("scan %s unique index: %v", table, err)
		}
		indexNames = append(indexNames, name)
	}
	indexRows.Close()
	if err := indexRows.Err(); err != nil {
		t.Fatalf("iterate %s unique indexes: %v", table, err)
	}
	var canonicalUnique int
	for _, name := range indexNames {
		indexCols, err := credentialsIndexColumns(db, name)
		if err != nil {
			t.Fatalf("read %s index %q columns: %v", table, name, err)
		}
		if len(indexCols) == 2 && indexCols[0] == ownerCol && indexCols[1] == "root_path" {
			canonicalUnique++
		}
	}
	if len(indexNames) != 1 || canonicalUnique != 1 {
		t.Errorf("%s unique indexes = %v, want exactly one unique (%s, root_path)", table, indexNames, ownerCol)
	}

	var ddl sql.NullString
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&ddl); err != nil {
		t.Fatalf("read %s ddl: %v", table, err)
	}
	checks := sqliteCheckExpressions(ddl.String)
	if len(checks) != 1 || checks[0] != allowedRootAccessCheck {
		t.Errorf("%s CHECK constraints = %v, want exactly the canonical access check", table, checks)
	}
}

// TestInitializeDatabaseCreatesAllowedRootsAccessSchema proves the fresh 2.2
// database declares the canonical access-bearing allowed-roots schema for both
// tables and that initialization is idempotent on it.
func TestInitializeDatabaseCreatesAllowedRootsAccessSchema(t *testing.T) {
	db := openFreshTestDB(t)

	assertAllowedRootsAccessSchema(t, db, "principal_allowed_roots", "principal_id", "principals", true)
	assertAllowedRootsAccessSchema(t, db, "launcher_allowed_roots", "launcher_id", "launchers", false)

	// Idempotency: a second initialization must not change the schema.
	assertAllowedRootsAccessSchema(t, db, "principal_allowed_roots", "principal_id", "principals", true)
	assertAllowedRootsAccessSchema(t, db, "launcher_allowed_roots", "launcher_id", "launchers", false)
}

// v211AllowedRootsFixture captures the stable identifiers and stored paths of
// the exact v2.1.1-shaped fixture for migration assertions.
type v211AllowedRootsFixture struct {
	aliceID, bobID int64
	launcherID     string
	sessionID      string
	aliceHome      string
	aliceExtra     string
	bobHome        string
}

// createV211AllowedRootsFixture writes the exact v2.1.1-shaped database state:
// two Principals with their allowed roots, inherit and restricted Launchers
// with launcher roots, Principal and Launcher credentials, and a live Session.
func createV211AllowedRootsFixture(t *testing.T, db *sql.DB) v211AllowedRootsFixture {
	t.Helper()
	if _, err := db.Exec(`
		CREATE TABLE sessions (
			id TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL UNIQUE,
			workspace TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			launcher_id TEXT NOT NULL REFERENCES launchers(id)
		);
		CREATE TABLE principals (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			uid INTEGER NOT NULL,
			gid INTEGER NOT NULL,
			home TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1
		);
		CREATE TABLE principal_allowed_roots (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			principal_id INTEGER NOT NULL,
			root_path TEXT NOT NULL,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			UNIQUE(principal_id, root_path)
		);
		CREATE TABLE launchers (
			id TEXT PRIMARY KEY,
			principal_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			scope_mode TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
			UNIQUE (principal_id, name),
			CHECK (scope_mode IN ('inherit', 'restricted')),
			CHECK (
				length(name) BETWEEN 1 AND 63
				AND name NOT GLOB '*[^a-z0-9-]*'
				AND name NOT GLOB '-*'
				AND name NOT GLOB '*-'
			)
		);
		CREATE TABLE launcher_allowed_roots (
			launcher_id TEXT NOT NULL,
			root_path TEXT NOT NULL,
			FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE CASCADE,
			UNIQUE (launcher_id, root_path)
		);
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
			)
		);
	`); err != nil {
		t.Fatalf("create v2.1.1 schema: %v", err)
	}

	f := v211AllowedRootsFixture{
		launcherID: "dhl_" + strings.Repeat("b", 32),
		sessionID:  "dhs_live",
		aliceHome:  filepath.Join(testAllowedRootDir(t), "home", "alice"),
		aliceExtra: filepath.Join(testAllowedRootDir(t), "inputs"),
		bobHome:    filepath.Join(testAllowedRootDir(t), "home", "bob"),
	}
	for _, dir := range []string{f.aliceHome, f.aliceExtra, f.bobHome} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}

	result, err := db.Exec(
		`INSERT INTO principals (username, uid, gid, home, enabled) VALUES ('alice', 2001, 2001, ?, 1)`,
		f.aliceHome,
	)
	if err != nil {
		t.Fatalf("insert alice: %v", err)
	}
	f.aliceID, err = result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	result, err = db.Exec(
		`INSERT INTO principals (username, uid, gid, home, enabled) VALUES ('bob', 2002, 2002, ?, 1)`,
		f.bobHome,
	)
	if err != nil {
		t.Fatalf("insert bob: %v", err)
	}
	f.bobID, err = result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(
		`INSERT INTO principal_allowed_roots (principal_id, root_path) VALUES (?, ?), (?, ?)`,
		f.aliceID, f.aliceHome, f.aliceID, f.aliceExtra,
	); err != nil {
		t.Fatalf("insert alice roots: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO principal_allowed_roots (principal_id, root_path) VALUES (?, ?)`,
		f.bobID, f.bobHome,
	); err != nil {
		t.Fatalf("insert bob root: %v", err)
	}

	if _, err := db.Exec(
		`INSERT INTO launchers (id, principal_id, name, enabled, scope_mode, created_at)
		 VALUES (?, ?, 'default', 1, 'restricted', 1000)`,
		f.launcherID, f.aliceID,
	); err != nil {
		t.Fatalf("insert restricted launcher: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO launcher_allowed_roots (launcher_id, root_path) VALUES (?, ?), (?, ?)`,
		f.launcherID, f.aliceHome, f.launcherID, f.aliceExtra,
	); err != nil {
		t.Fatalf("insert launcher roots: %v", err)
	}
	bobLauncher := "dhl_" + strings.Repeat("c", 32)
	if _, err := db.Exec(
		`INSERT INTO launchers (id, principal_id, name, enabled, scope_mode, created_at)
		 VALUES (?, ?, 'default', 1, 'inherit', 1001)`,
		bobLauncher, f.bobID,
	); err != nil {
		t.Fatalf("insert bob launcher: %v", err)
	}

	// Unrelated state that must survive migration byte-for-byte.
	if _, err := db.Exec(
		`INSERT INTO credentials (id, principal_id, launcher_id, name, token_hash, created_at, revoked_at)
		 VALUES ('dhcr_principal', ?, NULL, 'main', 'alicehash', 5000, NULL)`,
		f.aliceID,
	); err != nil {
		t.Fatalf("insert principal credential: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO credentials (id, principal_id, launcher_id, name, token_hash, created_at, revoked_at)
		 VALUES ('dhcr_launcher', NULL, ?, NULL, 'launcherhash', 5001, NULL)`,
		f.launcherID,
	); err != nil {
		t.Fatalf("insert launcher credential: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id)
		 VALUES (?, 'sessionhash', ?, 6000, 7000, ?)`,
		f.sessionID, f.aliceHome, f.launcherID,
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	return f
}

// TestMigrateV211AllowedRootsToReadWrite proves the exact v2.1.1-shaped state
// migrates to the canonical schema: every legacy root becomes read_write,
// owner/path cardinality and identities are fully preserved, and unrelated
// credentials and Sessions survive untouched. The second initialization is an
// idempotent no-op.
func TestMigrateV211AllowedRootsToReadWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	f := createV211AllowedRootsFixture(t, db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen and run the normal initialization/migration.
	db, err = openDatabase(path)
	if err != nil {
		t.Fatalf("reopenDatabase() error: %v", err)
	}
	defer db.Close()
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	// Both tables now carry the canonical access-bearing schema.
	assertAllowedRootsAccessSchema(t, db, "principal_allowed_roots", "principal_id", "principals", true)
	assertAllowedRootsAccessSchema(t, db, "launcher_allowed_roots", "launcher_id", "launchers", false)

	// Every legacy root became read_write; owner/path cardinality is intact.
	type rootRow struct {
		username string
		path     string
		access   string
	}
	rows, err := db.Query(
		`SELECT p.username, r.root_path, r.access FROM principal_allowed_roots r
		 JOIN principals p ON p.id = r.principal_id ORDER BY p.username, r.root_path`,
	)
	if err != nil {
		t.Fatalf("query principal roots: %v", err)
	}
	var gotPrincipalRoots []rootRow
	for rows.Next() {
		var r rootRow
		if err := rows.Scan(&r.username, &r.path, &r.access); err != nil {
			t.Fatalf("scan principal root: %v", err)
		}
		gotPrincipalRoots = append(gotPrincipalRoots, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate principal roots: %v", err)
	}
	// The expected lexical order depends on the allocated temp-dir names,
	// so both sides are compared in sorted-by-path order.
	want := []rootRow{
		{"alice", f.aliceHome, "read_write"},
		{"alice", f.aliceExtra, "read_write"},
		{"bob", f.bobHome, "read_write"},
	}
	sort.Slice(want, func(i, j int) bool {
		if want[i].username != want[j].username {
			return want[i].username < want[j].username
		}
		return want[i].path < want[j].path
	})
	if len(gotPrincipalRoots) != len(want) {
		t.Fatalf("principal roots after migration = %v, want %v", gotPrincipalRoots, want)
	}
	for i, g := range gotPrincipalRoots {
		if g != want[i] {
			t.Errorf("principal root %d = %+v, want %+v", i, g, want[i])
		}
	}

	// The restricted Launcher kept both roots, each as read_write.
	rows, err = db.Query(
		`SELECT root_path, access FROM launcher_allowed_roots WHERE launcher_id = ? ORDER BY root_path`,
		f.launcherID,
	)
	if err != nil {
		t.Fatalf("query launcher roots: %v", err)
	}
	var gotLauncherRoots []rootRow
	for rows.Next() {
		var r rootRow
		r.username = f.launcherID
		if err := rows.Scan(&r.path, &r.access); err != nil {
			t.Fatalf("scan launcher root: %v", err)
		}
		gotLauncherRoots = append(gotLauncherRoots, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate launcher roots: %v", err)
	}
	wantLauncherPaths := []string{f.aliceHome, f.aliceExtra}
	sort.Strings(wantLauncherPaths)
	if len(gotLauncherRoots) != 2 {
		t.Fatalf("launcher roots after migration = %v, want %v", gotLauncherRoots, wantLauncherPaths)
	}
	for i, g := range gotLauncherRoots {
		if g.path != wantLauncherPaths[i] {
			t.Errorf("launcher root %d path = %q, want %q", i, g.path, wantLauncherPaths[i])
		}
		if g.access != "read_write" {
			t.Errorf("launcher root %q access = %q, want read_write", g.path, g.access)
		}
	}

	// Identities preserved.
	var aliceUsername string
	if err := db.QueryRow(`SELECT username FROM principals WHERE id = ?`, f.aliceID).Scan(&aliceUsername); err != nil || aliceUsername != "alice" {
		t.Errorf("alice identity: got (%q, %v), want alice", aliceUsername, err)
	}
	var scope string
	if err := db.QueryRow(`SELECT scope_mode FROM launchers WHERE id = ?`, f.launcherID).Scan(&scope); err != nil || scope != "restricted" {
		t.Errorf("launcher identity/scope: got (%q, %v), want restricted", scope, err)
	}

	// Unrelated state survived untouched.
	var credCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM credentials`).Scan(&credCount); err != nil {
		t.Fatal(err)
	}
	if credCount != 2 {
		t.Errorf("credentials after migration = %d, want 2", credCount)
	}
	var launcherCredHash string
	if err := db.QueryRow(`SELECT token_hash FROM credentials WHERE id = 'dhcr_launcher'`).Scan(&launcherCredHash); err != nil || launcherCredHash != "launcherhash" {
		t.Errorf("launcher credential changed: got (%q, %v)", launcherCredHash, err)
	}
	var sessionCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id = ?`, f.sessionID).Scan(&sessionCount); err != nil {
		t.Fatalf("query session: %v", err)
	}
	if sessionCount != 1 {
		t.Errorf("session %s missing after migration", f.sessionID)
	}

	// foreign_key_check must be clean.
	assertForeignKeysClean(t, db)

	// Idempotency: a second initialization must not duplicate rows or change
	// state.
	before := snapshotAllowedRootsRows(t, db)
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("second initializeDatabase() error: %v", err)
	}
	after := snapshotAllowedRootsRows(t, db)
	if len(before) != len(after) {
		t.Fatalf("allowed-root row count changed on idempotent run: %d -> %d", len(before), len(after))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("idempotent run changed row %d: %q -> %q", i, before[i], after[i])
		}
	}
}

// snapshotAllowedRootsRows reads the full canonical content of both
// allowed-roots tables in a stable order for idempotency comparison.
func snapshotAllowedRootsRows(t *testing.T, db *sql.DB) []string {
	t.Helper()
	var out []string
	for _, spec := range []struct{ table, ownerCol string }{
		{"principal_allowed_roots", "principal_id"},
		{"launcher_allowed_roots", "launcher_id"},
	} {
		rows, err := db.Query(
			`SELECT ` + spec.ownerCol + `, root_path, access FROM ` + spec.table + ` ORDER BY 1, 2`,
		)
		if err != nil {
			t.Fatalf("snapshot %s: %v", spec.table, err)
		}
		for rows.Next() {
			var owner, path, access string
			if err := rows.Scan(&owner, &path, &access); err != nil {
				t.Fatalf("snapshot %s row: %v", spec.table, err)
			}
			out = append(out, owner+"|"+path+"|"+access)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatalf("snapshot %s iterate: %v", spec.table, err)
		}
	}
	return out
}

// TestAllowedRootsAccessConstraintRejectsInvalidValues proves the canonical
// CHECK constraint is real enforcement, not decoration: direct SQL writes with
// non-canonical access values are rejected by SQLite, and the owner/path
// unique identity keeps rejecting duplicates regardless of the access value.
func TestAllowedRootsAccessConstraintRejectsInvalidValues(t *testing.T) {
	db := openFreshTestDB(t)
	if _, err := db.Exec(
		`INSERT INTO principals (username, uid, gid, home, enabled) VALUES ('cuser', 2001, 2001, '/home/canon', 1)`,
	); err != nil {
		t.Fatalf("insert principal: %v", err)
	}

	// Canonical values are accepted.
	if _, err := db.Exec(
		`INSERT INTO principal_allowed_roots (principal_id, root_path, access) VALUES (?, '/opt/work', 'read_only')`,
		1,
	); err != nil {
		t.Fatalf("insert read_only root: %v", err)
	}

	for _, bad := range []string{"rw", "readonly", "", "garbage", "read-write", "READ_WRITE"} {
		if _, err := db.Exec(
			`INSERT INTO principal_allowed_roots (principal_id, root_path, access) VALUES (?, '/opt/other', ?)`,
			1, bad,
		); err == nil {
			t.Errorf("insert access %q accepted, want CHECK rejection", bad)
		}
	}
	// NULL access is rejected by NOT NULL.
	if _, err := db.Exec(
		`INSERT INTO principal_allowed_roots (principal_id, root_path, access) VALUES (?, '/opt/other', NULL)`,
		1,
	); err == nil {
		t.Error("insert NULL access accepted, want NOT NULL rejection")
	}
	// UPDATE to an invalid value is rejected too.
	if _, err := db.Exec(
		`UPDATE principal_allowed_roots SET access = 'ro' WHERE principal_id = ? AND root_path = '/opt/work'`,
		1,
	); err == nil {
		t.Error("update access to 'ro' accepted, want CHECK rejection")
	}

	// Launcher table: same proof, no id column.
	if _, err := db.Exec(
		`INSERT INTO launchers (id, principal_id, name, enabled, scope_mode, created_at)
		 VALUES ('dhl_x', 1, 'x', 1, 'restricted', 1)`,
	); err != nil {
		t.Fatalf("insert launcher: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO launcher_allowed_roots (launcher_id, root_path, access) VALUES ('dhl_x', '/opt/work', 'read_only')`,
	); err != nil {
		t.Fatalf("insert launcher read_only root: %v", err)
	}
	for _, bad := range []string{"rw", "readonly", "", "garbage"} {
		if _, err := db.Exec(
			`INSERT INTO launcher_allowed_roots (launcher_id, root_path, access) VALUES ('dhl_x', '/opt/more', ?)`,
			bad,
		); err == nil {
			t.Errorf("launcher insert access %q accepted, want CHECK rejection", bad)
		}
	}

	// Duplicate owner/path still rejected regardless of access value.
	if _, err := db.Exec(
		`INSERT INTO principal_allowed_roots (principal_id, root_path, access) VALUES (?, '/opt/work', 'read_only')`,
		1,
	); err == nil || !strings.Contains(err.Error(), "UNIQUE constraint failed") {
		t.Errorf("duplicate principal root with different access: err = %v, want UNIQUE rejection", err)
	}
	if _, err := db.Exec(
		`INSERT INTO launcher_allowed_roots (launcher_id, root_path, access) VALUES ('dhl_x', '/opt/work', 'read_write')`,
	); err == nil || !strings.Contains(err.Error(), "UNIQUE constraint failed") {
		t.Errorf("duplicate launcher root with different access: err = %v, want UNIQUE rejection", err)
	}
	assertForeignKeysClean(t, db)
}

// TestMigrateV211AllowedRootsCorruptSchemasFailClosed proves startup refuses
// unsupported allowed-roots schemas instead of guessing: an access column
// without the canonical CHECK, a wrong or extra CHECK, unexpected columns,
// missing unique/FK invariants, and duplicate legacy rows (possible only
// without the unique constraint) all fail closed with no migration performed.
func TestMigrateV211AllowedRootsCorruptSchemasFailClosed(t *testing.T) {
	tests := []struct {
		name  string
		table string // which allowed-roots table the corruption is applied to
		ddl   string // corrupt table definition replacing the canonical one
		rows  string // optional seed rows after the corrupt table is created
	}{
		{
			name:  "access column without check constraint",
			table: "principal_allowed_roots",
			ddl: `
				CREATE TABLE principal_allowed_roots (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					principal_id INTEGER NOT NULL,
					root_path TEXT NOT NULL,
					access TEXT NOT NULL,
					FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
					UNIQUE(principal_id, root_path)
				)`,
		},
		{
			name:  "access check without root_path",
			table: "launcher_allowed_roots",
			ddl: `
				CREATE TABLE launcher_allowed_roots (
					launcher_id TEXT NOT NULL,
					root_path TEXT NOT NULL,
					access TEXT NOT NULL,
					FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE CASCADE,
					UNIQUE (launcher_id, root_path),
					CHECK (length(access) > 0)
				)`,
		},
		{
			name:  "extra check constraint beside the canonical one",
			table: "launcher_allowed_roots",
			ddl: `
				CREATE TABLE launcher_allowed_roots (
					launcher_id TEXT NOT NULL,
					root_path TEXT NOT NULL,
					access TEXT NOT NULL,
					FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE CASCADE,
					UNIQUE (launcher_id, root_path),
					CHECK (access IN ('read_write', 'read_only')),
					CHECK (root_path != '')
				)`,
		},
		{
			name:  "unexpected extra column with access",
			table: "principal_allowed_roots",
			ddl: `
				CREATE TABLE principal_allowed_roots (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					principal_id INTEGER NOT NULL,
					root_path TEXT NOT NULL,
					access TEXT NOT NULL,
					origin TEXT,
					FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
					UNIQUE(principal_id, root_path),
					CHECK (access IN ('read_write', 'read_only'))
				)`,
		},
		{
			name:  "access nullable",
			table: "launcher_allowed_roots",
			ddl: `
				CREATE TABLE launcher_allowed_roots (
					launcher_id TEXT NOT NULL,
					root_path TEXT NOT NULL,
					access TEXT,
					FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE CASCADE,
					UNIQUE (launcher_id, root_path),
					CHECK (access IN ('read_write', 'read_only'))
				)`,
		},
		{
			name:  "legacy table missing unique identity",
			table: "principal_allowed_roots",
			ddl: `
				CREATE TABLE principal_allowed_roots (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					principal_id INTEGER NOT NULL,
					root_path TEXT NOT NULL,
					FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE
				)`,
			rows: `
				INSERT INTO principals (username, uid, gid, home, enabled) VALUES ('dupuser', 2001, 2001, '/home/dup', 1);
				INSERT INTO principal_allowed_roots (principal_id, root_path) VALUES (1, '/opt/a'), (1, '/opt/a')`,
		},
		{
			name:  "legacy table with wrong foreign key action",
			table: "launcher_allowed_roots",
			ddl: `
				CREATE TABLE launcher_allowed_roots (
					launcher_id TEXT NOT NULL,
					root_path TEXT NOT NULL,
					FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE NO ACTION,
					UNIQUE (launcher_id, root_path)
				)`,
		},
		{
			name:  "legacy table with unexpected extra column",
			table: "principal_allowed_roots",
			ddl: `
				CREATE TABLE principal_allowed_roots (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					principal_id INTEGER NOT NULL,
					root_path TEXT NOT NULL,
					origin TEXT,
					FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE,
					UNIQUE(principal_id, root_path)
				)`,
		},
		{
			name:  "legacy table with unexpected check constraint",
			table: "launcher_allowed_roots",
			ddl: `
				CREATE TABLE launcher_allowed_roots (
					launcher_id TEXT NOT NULL,
					root_path TEXT NOT NULL,
					FOREIGN KEY (launcher_id) REFERENCES launchers(id) ON DELETE CASCADE,
					UNIQUE (launcher_id, root_path),
					CHECK (root_path != '')
				)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openFreshTestDB(t)
			defer db.Close()

			// Drop the canonical table created by initializeDatabase and
			// replace it with the corrupt shape, seeded when provided.
			if _, err := db.Exec(`DROP TABLE ` + tt.table); err != nil {
				t.Fatalf("drop %s: %v", tt.table, err)
			}
			if _, err := db.Exec(tt.ddl); err != nil {
				t.Fatalf("create corrupt table: %v", err)
			}
			if tt.rows != "" {
				if _, err := db.Exec(tt.rows); err != nil {
					t.Fatalf("seed corrupt rows: %v", err)
				}
			}

			err := initializeDatabase(db)
			if err == nil {
				t.Fatalf("initializeDatabase() accepted corrupt %s schema", tt.table)
			}
			if !strings.Contains(err.Error(), "unsupported") {
				t.Errorf("error = %v, want an unsupported-schema refusal", err)
			}
		})
	}
}
