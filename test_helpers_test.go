package main

import (
	"crypto/sha256"
	"database/sql"
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
// forbidden /tmp tree, the root scenario where HOME=/root or /tmp is a
// candidate); the allocator must reject the created child, remove it, and
// fall through to the policy-legal base.
func TestWorkspaceRootAllocationForbiddenCandidates(t *testing.T) {
	// Controlled rejected base: t.TempDir() lives under the forbidden /tmp
	// tree, so every child created in it is rejected by the production
	// policy, yet the test owns the directory it inspects.
	rejectedBase := t.TempDir()
	if err := validateWorkspacePathPolicy(filepath.Join(rejectedBase, "child")); err == nil {
		t.Skipf("temp base %s is policy-legal; cannot exercise policy rejection", rejectedBase)
	}

	// A policy-legal, writable base for the allocator to fall through to
	// (t.TempDir() is unusable: /tmp is a forbidden tree).
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
// candidate used. /tmp is world-writable, so the rejection comes from the
// policy, not from permissions, making this deterministic without UID 0.
func TestWorkspaceRootAllocationForbiddenHome(t *testing.T) {
	if _, err := os.Stat("/tmp"); err != nil {
		t.Skipf("/tmp not available: %v", err)
	}
	t.Setenv("HOME", "/tmp")

	root := testAllowedRootDir(t)

	if err := validateWorkspacePathPolicy(root); err != nil {
		t.Fatalf("workspace root %q rejected by production policy: %v", root, err)
	}
	if strings.HasPrefix(root, "/tmp/") {
		t.Fatalf("workspace root %q must not be under forbidden /tmp", root)
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

	dir, err := allocateTestWorkspaceRoot([]string{"/root", "/tmp", "/"})
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

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	allowedRoot := testAllowedRootDir(t)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatalf("cannot create runtime dir: %v", err)
	}
	cfg := &Config{
		AllowedRoots:          []string{allowedRoot},
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
		Mode:                  ModeUser,
	}

	app := &App{
		Config: cfg,
		DB:     db,
	}

	// Provision a user-mode daemon-owner Principal + 'default' Launcher so that
	// session creation through the shared model works without a manual owner.
	// The daemon-owner Principal has no allowed-root rows (collapsed global).
	home := filepath.Join(allowedRoot, "daemon-home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatalf("cannot create daemon-owner home: %v", err)
	}
	owner := provisionTestOwner(t, db, allowedRoot, home)
	app.userModeDefault = owner

	return app
}

// provisionTestOwner provisions an enabled Principal and its 'default'
// inherit-scope Launcher via the production ownership helpers. The Principal is
// created with no allowed-root rows (collapsed global policy). home must be a
// valid, non-forbidden absolute directory.
func provisionTestOwner(t *testing.T, db *sql.DB, allowedRoot, home string) *userModeDefaultLauncher {
	t.Helper()
	const username = "dhtestowner"
	pid, err := insertDaemonOwnerPrincipal(db, username, 1000, 1000, home)
	if err != nil {
		t.Fatalf("cannot provision test owner principal: %v", err)
	}
	launcherID, err := ensureDefaultLauncher(db, pid)
	if err != nil {
		t.Fatalf("cannot provision test owner default launcher: %v", err)
	}
	return &userModeDefaultLauncher{principalID: pid, launcherID: launcherID, username: username}
}

// mustAddDefaultLauncher provisions a named Principal's 'default' inherit
// Launcher and returns its ID, failing the test on error. It is the shared
// setup for tests that create Sessions via a Principal credential, because in
// the cutover model those Sessions are owned by the Principal's default
// Launcher.
func mustAddDefaultLauncher(t *testing.T, db *sql.DB, principalID int64) string {
	t.Helper()
	l, _, _, err := createLauncher(db, principalID, "default", LauncherScopeInherit, nil, nil, false)
	if err != nil {
		t.Fatalf("createLauncher(default) for principal %d: %v", principalID, err)
	}
	return l.ID
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

// mockStandaloneUserInit mocks systemSocketExists and checkDockerAccess so
// that runInit takes the "standalone user init" path (no system daemon,
// Docker accessible). Returns a restore function that should be deferred.
func mockStandaloneUserInit() func() {
	origSocket := systemSocketExists
	origDockerAccess := checkDockerAccess
	systemSocketExists = func() bool { return false }
	checkDockerAccess = func() error { return nil }
	return func() {
		systemSocketExists = origSocket
		checkDockerAccess = origDockerAccess
	}
}
