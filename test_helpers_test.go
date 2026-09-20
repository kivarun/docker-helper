package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// candidateBasePaths returns the allocator's candidate bases in priority
// order: the user's home directory, then the test process working directory.
func candidateBasePaths() []string {
	var candidates []string
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, home)
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd)
	}
	return candidates
}

// testAllowedRootDir creates a unique directory that is valid as a workspace
// root and returns it in canonical form, matching what loadAndPrepareRuntimeConfig stores in
// Config.AllowedRoots[0]. Candidate bases are tried in order: the user's home
// directory, the test process working directory, and "/" as a last resort.
// A base does not have to be policy-legal itself (root's home is /root, a
// forbidden system tree); the created directory is what must pass the
// production workspace-root policy. Cleanup removes only the specific
// directory returned; tests must never remove a shared parent.
func testAllowedRootDir(t *testing.T) string {
	t.Helper()
	dir, err := allocateTestWorkspaceRoot(append(candidateBasePaths(), "/"))
	if err != nil {
		t.Fatalf("cannot allocate workspace root test dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// allocateTestWorkspaceRoot tries each candidate base in order and returns
// the first unique directory it can create there that passes the production
// workspace-root policy. A base that does not exist, is not writable, or
// whose created child is policy-forbidden is skipped; a created-but-rejected
// directory is removed before moving to the next candidate.
func allocateTestWorkspaceRoot(candidates []string) (string, error) {
	for _, c := range candidates {
		base, err := filepath.EvalSymlinks(c)
		if err != nil {
			continue
		}
		dir, err := os.MkdirTemp(base, ".docker-helper-test-*")
		if err != nil {
			continue
		}
		canonical, err := filepath.EvalSymlinks(dir)
		if err != nil {
			os.RemoveAll(dir)
			continue
		}
		if err := validateWorkspacePathPolicy(canonical); err != nil {
			os.RemoveAll(dir)
			continue
		}
		return canonical, nil
	}
	return "", fmt.Errorf("no workspace root test dir could be allocated from candidates %v", candidates)
}

// TestWorkspaceRootAllocationForbiddenCandidates verifies the allocator's
// core invariant with a controlled candidate list: the bases themselves need
// not be policy-legal workspace roots. The first candidate is a writable
// base whose created children are policy-forbidden (it lives under the
// forbidden /var tree; /var/tmp is world-writable, so the fixture is
// deterministic for a non-root test user); the allocator must reject the
// created child, remove it, and fall through to the policy-legal base.
func TestWorkspaceRootAllocationForbiddenCandidates(t *testing.T) {
	// Controlled rejected base: a fresh directory under the world-writable
	// /var/tmp, so every child created in it is rejected by the production
	// policy (under the forbidden /var tree), yet the test owns the
	// directory it inspects.
	rejectedBase, err := os.MkdirTemp("/var/tmp", ".docker-helper-test-*")
	if err != nil {
		t.Skipf("cannot create the controlled forbidden base under /var/tmp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(rejectedBase) })
	if err := validateWorkspacePathPolicy(filepath.Join(rejectedBase, "child")); err == nil {
		t.Skipf("base %s is policy-legal; cannot exercise policy rejection", rejectedBase)
	}

	// A policy-legal, writable base for the allocator to fall through to
	// (the controlled forbidden base above is unusable by policy).
	var goodBase string
	for _, c := range candidateBasePaths() {
		canonical, err := filepath.EvalSymlinks(c)
		if err != nil || validateWorkspacePathPolicy(canonical) != nil {
			continue
		}
		probe, err := os.MkdirTemp(canonical, ".docker-helper-test-*")
		if err != nil {
			continue
		}
		os.RemoveAll(probe)
		goodBase = canonical
		break
	}
	if goodBase == "" {
		t.Skip("no policy-legal, writable base available for the controlled test")
	}

	dir, err := allocateTestWorkspaceRoot([]string{rejectedBase, goodBase})
	if err != nil {
		t.Fatalf("allocateTestWorkspaceRoot: %v", err)
	}
	defer os.RemoveAll(dir)

	if err := validateWorkspacePathPolicy(dir); err != nil {
		t.Fatalf("allocated root %q rejected by production policy: %v", dir, err)
	}
	if !strings.HasPrefix(dir, goodBase+string(filepath.Separator)) {
		t.Fatalf("allocated root %q, want under fallback base %s", dir, goodBase)
	}
	// The policy-rejected child must not linger in the controlled base.
	entries, err := os.ReadDir(rejectedBase)
	if err != nil {
		t.Fatalf("cannot read %s: %v", rejectedBase, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".docker-helper-test-") {
			t.Fatalf("policy-rejected child %s not removed", e.Name())
		}
	}
}

// TestWorkspaceRootAllocationForbiddenHome verifies the default candidate
// list with a root-like $HOME that is a forbidden system tree: the home
// candidate's created child must be rejected by the policy gate and a later
// candidate used. /var/tmp is world-writable and lives under the forbidden
// /var tree, so the rejection comes from the policy, not from permissions,
// making this deterministic without UID 0 (/tmp is a wide namespace root
// whose descendants are policy-legal, so it is no longer a forbidden-home
// fixture).
func TestWorkspaceRootAllocationForbiddenHome(t *testing.T) {
	if _, err := os.Stat("/var/tmp"); err != nil {
		t.Skipf("/var/tmp not available: %v", err)
	}
	t.Setenv("HOME", "/var/tmp")

	root := testAllowedRootDir(t)

	if err := validateWorkspacePathPolicy(root); err != nil {
		t.Fatalf("workspace root %q rejected by production policy: %v", root, err)
	}
	if strings.HasPrefix(root, "/var/tmp/") {
		t.Fatalf("workspace root %q must not be under forbidden /var/tmp", root)
	}
}

// TestWorkspaceRootAllocationRootFallback verifies the root scenario end to
// end: both regular candidates are forbidden (HOME=/root, cwd=/root/...), and
// the "/" fallback yields a valid root-level workspace root. It requires the
// ability to create directories directly under "/" and is skipped otherwise.
func TestWorkspaceRootAllocationRootFallback(t *testing.T) {
	// Probe whether "/" is writable so non-root runs skip cleanly.
	probe, err := os.MkdirTemp("/", ".docker-helper-allocator-probe-*")
	if err != nil {
		t.Skipf("cannot create directories in /: %v (root fallback not exercisable)", err)
	}
	os.RemoveAll(probe)

	dir, err := allocateTestWorkspaceRoot([]string{"/root", "/var/tmp", "/"})
	if err != nil {
		t.Fatalf("allocateTestWorkspaceRoot: %v", err)
	}
	defer os.RemoveAll(dir)

	if err := validateWorkspacePathPolicy(dir); err != nil {
		t.Fatalf("allocated root %q rejected by production policy: %v", dir, err)
	}
	if !strings.HasPrefix(dir, "/.docker-helper-test-") {
		t.Fatalf("expected root-level fallback dir, got %q", dir)
	}
}

// waitForDialReady polls until a TCP/unix listener accepts connections.
// Use it after starting an in-process test server instead of a fixed sleep.
func waitForDialReady(t *testing.T, network, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.Dial(network, addr)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("listener %s://%s not ready after 5s", network, addr)
}

// writeTestTokenFile writes a test admin/launcher token file, failing the
// test if the write fails. Security-sensitive fixtures must not proceed
// with a missing token file.
func writeTestTokenFile(t *testing.T, path, token string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		t.Fatalf("cannot write token file %s: %v", path, err)
	}
}

// testAdminToken is the admin token used in unit tests.
const testAdminToken = "dht_test_admin_token"

// initializeTestDatabase runs the startup database owners a test database
// needs before it can create Sessions: the schema initialization followed by
// the Session filesystem snapshot migration, mirroring the production startup
// order for tests that build an App without the full daemon startup.
func initializeTestDatabase(t *testing.T, db *sql.DB) {
	t.Helper()
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}
	// Session filesystem snapshot persistence: the test database goes through
	// the same startup migration owner, so session creation tests exercise the
	// canonical snapshot table.
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots() error: %v", err)
	}
}

// insertTestSessionSnapshot issues the persisted filesystem snapshot rows for
// a directly seeded test session: the canonical issuance backfill is the
// single-entry workspace-read_write snapshot, exactly what the startup
// migration derives for a legacy Session. The coherent run/build authority
// read fails closed without these rows.
func insertTestSessionSnapshot(t *testing.T, db *sql.DB, sessionID, workspace string) {
	t.Helper()
	insertTestSessionSnapshotEntries(t, db, sessionID, []AllowedRootEntry{
		{Path: workspace, Access: AllowedRootAccessReadWrite},
	})
}

// insertTestSessionSnapshotEntries issues an exact persisted filesystem
// snapshot for a seeded test session, replacing any rows the Session-create
// owner already derived. Enforcement tests use it to control the issued
// data-plane authority precisely; snapshot derivation from live parent
// policy is separately owned by the Session-create tests.
func insertTestSessionSnapshotEntries(t *testing.T, db *sql.DB, sessionID string, entries []AllowedRootEntry) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin snapshot insert: %v", err)
	}
	if _, err := tx.Exec(`DELETE FROM session_filesystem_snapshot_entries WHERE session_id = ?`, sessionID); err != nil {
		tx.Rollback()
		t.Fatalf("clear snapshot for seeded session %s: %v", sessionID, err)
	}
	if _, err := tx.Exec(`DELETE FROM session_filesystem_snapshot_meta WHERE session_id = ?`, sessionID); err != nil {
		tx.Rollback()
		t.Fatalf("clear snapshot metadata for seeded session %s: %v", sessionID, err)
	}
	if err := insertSessionFilesystemSnapshot(tx, sessionID, entries); err != nil {
		tx.Rollback()
		t.Fatalf("insert snapshot for seeded session %s: %v", sessionID, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit snapshot insert: %v", err)
	}
}

// newTestApp creates a minimal *App with an in-memory SQLite database,
// a valid allowed root, and a runtime directory. It does not set
// AdminTokenHash; use newTestAppWithAdminToken for tests that require admin authorization.
func newTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()

	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	initializeTestDatabase(t, db)

	allowedRoot := testAllowedRootDir(t)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatalf("cannot create runtime dir: %v", err)
	}
	cfg := &Config{
		AllowedRoots:          []AllowedRootEntry{allowedRootEntry(allowedRoot)},
		SessionTTL:            24 * time.Hour,
		SocketPath:            filepath.Join(dir, "test.sock"),
		StateDir:              dir,
		RuntimeDir:            runtimeDir,
		DatabasePath:          dbPath,
		AdminTokenPath:        filepath.Join(dir, "admin.token"),
		ShutdownTimeout:       30 * time.Second,
		OperationRetentionTTL: 10 * time.Minute,
		OperationMaxCompleted: 200,
		OperationLogMaxBytes:  4 * 1024 * 1024,
	}

	app := &App{
		Config: cfg,
		DB:     db,
		// Default to no observable helper runtime so ordinary lifecycle tests
		// that do not exercise Docker can delete Launchers/Principals cleanly.
		// Docker runtime-inspection tests override this seam explicitly.
		InspectHelperContainers: func(ctx context.Context, launcherID string) ([]helperContainer, error) {
			return nil, nil
		},
	}

	// Provision the test owner Principal + 'default' Launcher so that session
	// creation through the shared model works without a manual owner. The
	// system-only ownership model has no daemon-owner special case: the owner
	// Principal carries a stored allowed root covering the test allowed root,
	// so its effective ceiling is the ordinary stored-root composition.
	home := filepath.Join(allowedRoot, "owner-home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatalf("cannot create owner home: %v", err)
	}
	provisionTestOwner(t, db, allowedRoot, home, os.Getuid(), os.Getgid())

	// The system-only run path pins every mount source through the
	// inode-pinning primitive, which requires CAP_SYS_ADMIN. The default
	// fixture stubs that primitive; mount-pinning tests install their own
	// seam or exercise the real syscall path explicitly.
	app.PinMountSourceFn = func(sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{PinnedPath: sourcePath, cleanup: func() error { return nil }}, nil
	}

	// The mandatory workload MAC is part of the system-only run path, so the
	// default fixture installs a real test-seamed coordinator: production
	// renderers, drivers, and lifecycle owners run unchanged; only the LSM
	// kernel mechanics are replaced. Tests needing a specific backend install
	// their own coordinator after this one.
	installTestWorkloadMACForTest(t, app, LSMAppArmor)

	return app
}

// testOwner is the test fixture identity of the provisioned owner Principal:
// the DB row identity the session authority chain resolves through.
type testOwner struct {
	principalID int64
	launcherID  string
	username    string
}

// testOwnerUsername is the fixed username of the provisioned test owner
// Principal.
const testOwnerUsername = "dhtestowner"

// provisionTestOwner provisions an enabled Principal (with the given explicit
// uid/gid identity), a stored allowed root covering the test allowed root,
// and its 'default' inherit-scope Launcher, mirroring the production
// principal-row insert and default-Launcher provisioning. home must be a
// valid, non-forbidden absolute directory under allowedRoot. Execution
// identity is owned explicitly by the caller so identity tests control the
// exact uid/gid rather than relying on an implicit owner.
func provisionTestOwner(t *testing.T, db *sql.DB, allowedRoot, home string, uid, gid int) *testOwner {
	t.Helper()
	pid, err := insertTestPrincipalWithRoots(db, testOwnerUsername, uid, gid, home, []AllowedRootEntry{allowedRootEntry(allowedRoot)})
	if err != nil {
		t.Fatalf("cannot provision test owner principal: %v", err)
	}
	launcherID, err := ensureDefaultLauncher(db, pid)
	if err != nil {
		t.Fatalf("cannot provision test owner default launcher: %v", err)
	}
	return &testOwner{principalID: pid, launcherID: launcherID, username: testOwnerUsername}
}

// insertTestPrincipalWithRoots inserts an enabled Principal row with the
// explicit uid/gid identity (no OS-account lookup) and the given stored
// allowed roots, in one transaction. This mirrors the principal INSERT of the
// production creation path for a principal whose OS account is not resolved
// from the host.
func insertTestPrincipalWithRoots(db *sql.DB, username string, uid, gid int, home string, roots []AllowedRootEntry) (int64, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(
		`INSERT INTO principals (username, uid, gid, home, enabled)
		 VALUES (?, ?, ?, ?, 1)`,
		username, uid, gid, home,
	)
	if err != nil {
		return 0, err
	}
	pid, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	for _, root := range roots {
		if _, err := tx.Exec(
			`INSERT INTO principal_allowed_roots (principal_id, root_path, access)
			 VALUES (?, ?, ?)`,
			pid, root.Path, string(root.Access),
		); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return pid, nil
}

// decodeAPIError decodes the stable error envelope of a rejected request.
func decodeAPIError(t *testing.T, body []byte) response {
	t.Helper()
	var resp response
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode error response: %v (body=%s)", err, body)
	}
	if resp.OK {
		t.Fatalf("expected ok=false, got body=%s", body)
	}
	return resp
}

// narrowCfg copies the app's current configuration with the global allowed
// roots narrowed to narrowRoot. The real reload setConfig merges only
// configurable fields, so the copy keeps the rest of the runtime state.
func narrowCfg(t *testing.T, app *App, narrowRoot string) *Config {
	t.Helper()
	cfg := app.getConfig()
	cfg.AllowedRoots = []AllowedRootEntry{allowedRootEntry(narrowRoot)}
	return &cfg
}

// testOwnerLauncherID resolves the provisioned test owner's default Launcher
// ID through the production ownership query. It panics on failure: a missing
// owner fixture is always a test bug, never a testable outcome.
func testOwnerLauncherID(app *App) string {
	launcherID, err := findDefaultLauncher(app.DB, testOwnerPrincipalID(app))
	if err != nil {
		panic("test owner default launcher missing: " + err.Error())
	}
	return launcherID
}

// testOwnerPrincipalID resolves the provisioned test owner's Principal DB ID
// through the production ownership query.
func testOwnerPrincipalID(app *App) int64 {
	id, err := findPrincipalIDByUsername(app.DB, testOwnerUsername)
	if err != nil {
		panic("test owner principal missing: " + err.Error())
	}
	return int64(id)
}

// mustTestOwner resolves the provisioned test owner's DB identity through the
// production ownership queries.
func mustTestOwner(t *testing.T, app *App) *testOwner {
	t.Helper()
	pid, err := findPrincipalIDByUsername(app.DB, testOwnerUsername)
	if err != nil {
		t.Fatalf("cannot resolve test owner principal: %v", err)
	}
	launcherID, err := findDefaultLauncher(app.DB, int64(pid))
	if err != nil {
		t.Fatalf("cannot resolve test owner default launcher: %v", err)
	}
	return &testOwner{principalID: int64(pid), launcherID: launcherID, username: testOwnerUsername}
}

// mustAddDefaultLauncher resolves a named Principal's 'default' inherit
// Launcher and returns its ID, failing the test on error. Principal creation
// auto-provisions the canonical default Launcher, so this normally resolves the
// existing row; for a Principal that predates provisioning it provisions it
// through the production ownership helper.
func mustAddDefaultLauncher(t *testing.T, db *sql.DB, principalID int64) string {
	t.Helper()
	id, err := ensureDefaultLauncher(db, principalID)
	if err != nil {
		t.Fatalf("ensureDefaultLauncher for principal %d: %v", principalID, err)
	}
	return id
}

// principalIDByName resolves a test-created Principal's internal ID.
func principalIDByName(t *testing.T, db *sql.DB, username string) int64 {
	t.Helper()
	id, err := findPrincipalIDByUsername(db, username)
	if err != nil {
		t.Fatalf("findPrincipalIDByUsername(%s): %v", username, err)
	}
	return int64(id)
}

// principalIDPtr resolves a test-created Principal's internal ID as the
// single-Principal scope argument of the scope-first list queries.
func principalIDPtr(t *testing.T, db *sql.DB, username string) *int64 {
	t.Helper()
	id := principalIDByName(t, db, username)
	return &id
}

// removePrincipalAllowedRootForTest invokes the canonical Principal-root
// remove persistence owner (removePrincipalAllowedRootCascaded) with the test
// app's own policy state, so DB-level remove tests exercise the production
// persistence path instead of a reimplementation. The test app's global
// entries are already canonical resolved paths.
func removePrincipalAllowedRootForTest(t *testing.T, app *App, username, rootPath string) (changed bool, canonicalPath string, err error) {
	t.Helper()
	cfg := app.getConfig()
	changed, canonicalPath, _, err = removePrincipalAllowedRootCascaded(
		app.DB, username, rootPath, cfg.AllowedRoots,
	)
	return changed, canonicalPath, err
}

// newTestAppWithAdminToken creates an admin-authorized test app with the
// admin token hash set.
func newTestAppWithAdminToken(t *testing.T) *App {
	t.Helper()
	app := newTestApp(t)
	hash := sha256.Sum256([]byte(testAdminToken))
	app.AdminTokenHash = hash
	return app
}

// withAdminToken sets the Authorization header on a request using the
// test admin token.
func withAdminToken(r *http.Request) {
	r.Header.Set("Authorization", "Bearer "+testAdminToken)
}

// testWorkspaceDir creates a subdirectory inside the allowed root that can
// be used as a session workspace. The allowed root itself is no longer a
// valid workspace (must be a proper subdirectory). The created directory is
// cleaned up when the allowed root is cleaned up by testAllowedRootDir.
func testWorkspaceDir(t *testing.T, allowedRoot string) string {
	t.Helper()
	dir, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatalf("cannot create workspace dir: %v", err)
	}
	return dir
}

// createDefaultAdminSessionForTest creates a Session fixture through the
// canonical production owner: a valid Admin authority selecting the test
// owner Principal, so policy resolution stays with resolveCreatePolicy (the
// owner's 'default' Launcher under its stored-root composition). It never
// computes effective roots or manufactures a sessionCreatePolicy.
func createDefaultAdminSessionForTest(app *App, workspace string) (*CreatedSession, error) {
	return app.createSessionAuthorized(&operatorAuthority{class: operatorAuthorityAdmin}, createSelector{principal: testOwnerUsername}, workspace, nil)
}

// admitForTest registers an operation through the production admission path
// (reserve → admitReserved) and returns the same decision contract. Tests that
// need more concurrent operations than the fixed Release-2.2 ceilings allow
// must raise the supervisor's ceilings explicitly first — the ceilings are
// production semantics, never silently bypassed by a helper.
func admitForTest(s *operationSupervisor, op *operation) admissionDecision {
	res, decision := s.reserve(op.SessionID, op.LauncherID, op.Kind)
	if decision != admissionAccepted {
		return decision
	}
	return s.admitReserved(op, res)
}
