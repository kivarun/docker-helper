package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// removedBoundary records one removeBoundary call with the durable kind the
// coordinator resolved for it.
type removedBoundary struct {
	Boundary string
	Kind     macBoundaryKind
}

// testSessionMACDriver is a mock sessionMACDriver for testing the coordinator.
type testSessionMACDriver struct {
	mu                    sync.Mutex
	coverageMap           map[string]string // workspace -> boundary
	helperOwnedBoundaries map[string]bool   // boundary -> is helper-owned
	removeErrors          map[string]bool   // boundary -> should removal fail
	ensureFailures        map[string]bool   // tree -> should ensureCoverage fail
	boundaryBackend       LSMBackend
	preparedTrees         []string // every concrete tree ensureCoverage saw, in order
	verifiedTrees         []string // every concrete tree verifyCoverage saw, in order
	removedBoundaries     []removedBoundary
}

func newTestSessionMACDriver(backend LSMBackend) *testSessionMACDriver {
	return &testSessionMACDriver{
		coverageMap:           make(map[string]string),
		helperOwnedBoundaries: make(map[string]bool),
		removeErrors:          make(map[string]bool),
		boundaryBackend:       backend,
	}
}

func (b *testSessionMACDriver) ensureCoverage(workspace string) (sessionMACCoverage, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.preparedTrees = append(b.preparedTrees, workspace)

	if b.ensureFailures[workspace] {
		return sessionMACCoverage{}, false, fmt.Errorf("ensureCoverage failure injected for %s", workspace)
	}

	if boundary, ok := b.coverageMap[workspace]; ok {
		return sessionMACCoverage{Boundary: boundary, HelperOwned: b.helperOwnedBoundaries[boundary]}, false, nil
	}

	b.coverageMap[workspace] = workspace
	b.helperOwnedBoundaries[workspace] = true
	return sessionMACCoverage{Boundary: workspace, HelperOwned: true, Kind: macBoundaryDirectory}, true, nil
}

func (b *testSessionMACDriver) verifyCoverage(workspace string) (sessionMACCoverage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.verifiedTrees = append(b.verifiedTrees, workspace)

	if boundary, ok := b.coverageMap[workspace]; ok {
		return sessionMACCoverage{Boundary: boundary, HelperOwned: b.helperOwnedBoundaries[boundary]}, nil
	}
	return sessionMACCoverage{}, fmt.Errorf("no coverage for %s", workspace)
}

func (b *testSessionMACDriver) removeBoundary(boundary string, kind macBoundaryKind) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.removedBoundaries = append(b.removedBoundaries, removedBoundary{Boundary: boundary, Kind: kind})

	if b.removeErrors[boundary] {
		return fmt.Errorf("removeBoundary failed for %s", boundary)
	}
	delete(b.coverageMap, boundary)
	delete(b.helperOwnedBoundaries, boundary)
	return nil
}

func (b *testSessionMACDriver) discoverHelperOwnedBoundaries() ([]helperOwnedBoundary, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var result []helperOwnedBoundary
	for boundary := range b.helperOwnedBoundaries {
		result = append(result, helperOwnedBoundary{Boundary: boundary, Kind: macBoundaryDirectory})
	}
	return result, nil
}

func (b *testSessionMACDriver) backend() LSMBackend {
	return b.boundaryBackend
}

// setupTestMACCoordinator creates a test app with a MAC coordinator and mock driver.
func setupTestMACCoordinator(t *testing.T) (*App, *sessionMACCoordinator, *testSessionMACDriver) {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}

	driver := newTestSessionMACDriver(LSMBackend("test"))
	mac := newSessionMACCoordinator(db, driver)

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
		Config:         cfg,
		DB:             db,
		MACCoordinator: mac,
	}

	// Provision a user-mode daemon-owner Principal + 'default' Launcher so that
	// sessions created through the shared model reference a real launcher_id.
	home := filepath.Join(allowedRoot, "daemon-home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatalf("cannot create daemon-owner home: %v", err)
	}
	app.userModeDefault = provisionTestOwner(t, db, allowedRoot, home, os.Getuid(), os.Getgid())

	return app, mac, driver
}

// TestNewSessionMACCoordinatorRejectsNilDriver verifies that the coordinator
// constructor fails fast on a nil driver. A coordinator without a driver is
// forbidden architecture: absence of MAC is represented only by
// App.MACCoordinator == nil.
func TestNewSessionMACCoordinatorRejectsNilDriver(t *testing.T) {
	app := newTestApp(t)
	defer func() {
		if recover() == nil {
			t.Fatal("newSessionMACCoordinator(db, nil) must panic")
		}
	}()
	newSessionMACCoordinator(app.DB, nil)
}

// insertTestSession inserts a test session into the database.
func insertTestSession(t *testing.T, db *sql.DB, launcherID, sessionID, workspace string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sessionID, "hash1", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID,
	)
	if err != nil {
		t.Fatalf("insertTestSession: %v", err)
	}
	insertTestSessionSnapshot(t, db, sessionID, workspace)
}

// seedTestSessionSnapshot issues the workspace-only persisted snapshot for a
// session row without the *testing.T helper shape, matching the inherited
// create behavior. Used where a test inserts session rows inline.
func seedTestSessionSnapshot(t *testing.T, db *sql.DB, sessionID, workspace string) {
	t.Helper()
	insertTestSessionSnapshot(t, db, sessionID, workspace)
}

// TestLeaseReleaseConditionalBoundaryCleanup verifies that when a session is
// deleted while an operation is running, the operation's lease release
// triggers conditional boundary cleanup.
func TestLeaseReleaseConditionalBoundaryCleanup(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create session binding.
	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-1", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Acquire use lease (simulates operation starting).
	_, leaseRelease, err := mac.AcquireSessionUse("sess-1", workspace)
	if err != nil {
		t.Fatalf("AcquireSessionUse: %v", err)
	}

	// Verify boundary count is 2 (session + operation).
	mac.mu.Lock()
	count := mac.boundaryConsumerCounts[workspace]
	mac.mu.Unlock()
	if count != 2 {
		t.Errorf("expected boundaryConsumerCounts count 2, got %d", count)
	}

	// Delete session (simulates session deletion while operation running).
	mac.ReleaseSessionBinding("sess-1")

	// Boundary count should be 1 (only operation lease remains).
	mac.mu.Lock()
	count = mac.boundaryConsumerCounts[workspace]
	mac.mu.Unlock()
	if count != 1 {
		t.Errorf("expected boundaryConsumerCounts count 1 after session release, got %d", count)
	}

	// Operation completes: release lease.
	leaseRelease()

	// Boundary should now be removed (count reaches 0, no other consumers).
	mac.mu.Lock()
	count = mac.boundaryConsumerCounts[workspace]
	_, hasBinding := mac.sessionBindings["sess-1"]
	mac.mu.Unlock()

	if count != 0 {
		t.Errorf("expected boundaryConsumerCounts count 0 after lease release, got %d", count)
	}
	if hasBinding {
		t.Error("session binding should be removed")
	}

	// Verify boundary was actually removed from driver.
	_, err = driver.verifyCoverage(workspace)
	if err == nil {
		t.Error("expected error verifying removed boundary")
	}
}

// insertTestSessionTx inserts a test session plus its inherited
// workspace-only persisted snapshot (used inside insertFn callbacks; the
// real create transaction commits Session + snapshot together).
func insertTestSessionTx(db *sql.DB, launcherID, sessionID, workspace string) error {
	tokenHash := fmt.Sprintf("hash_%s", sessionID)
	_, err := db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sessionID, tokenHash, workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID,
	)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertSessionFilesystemSnapshot(tx, sessionID, []AllowedRootEntry{
		{Path: workspace, Access: AllowedRootAccessReadWrite},
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// testMACLauncherID provisions an enabled daemon-owner Principal and its
// 'default' Launcher for tests that build their own DB outside
// setupTestMACCoordinator, returning a valid launcher_id for session inserts.
func testMACLauncherID(t *testing.T, db *sql.DB) string {
	t.Helper()
	// Reuse an already-provisioned daemon-owner default Launcher if present so
	// that multiple session inserts in one test share a single launcher_id.
	const username = "dhtestowner"
	if p, err := findPrincipalByUsername(db, username); err == nil {
		if lid, lerr := findDefaultLauncher(db, int64(p.ID)); lerr == nil {
			return lid
		}
	}
	allowedRoot := testAllowedRootDir(t)
	home := filepath.Join(allowedRoot, "home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatalf("cannot create launcher home: %v", err)
	}
	return provisionTestOwner(t, db, allowedRoot, home, os.Getuid(), os.Getgid()).launcherID
}

// TestMACLifecycleWarningUsesOperationalLogger verifies that MAC
// warning/recovery records flow through the operational logger owner (JSONL,
// stream=operational) rather than a package-global logger, and that they are
// gated by the current runtime log_level: a reload raising the level
// suppresses them, and a reload back to warn surfaces them again.
func TestMACLifecycleWarningUsesOperationalLogger(t *testing.T) {
	opBuf := new(bytes.Buffer)
	audBuf := new(bytes.Buffer)
	initLoggers(opBuf, audBuf, slog.LevelWarn, true)
	defer logging.reset()

	app, mac, driver := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace := filepath.Join(allowedRoot, "mac-warn-ws")
	if err := os.MkdirAll(workspace, 0700); err != nil {
		t.Fatal(err)
	}

	// triggerWarning creates a session binding, then releases it with boundary
	// removal failing, forcing the recovery-warning path.
	triggerWarning := func(sessionID string) {
		t.Helper()
		if _, err := mac.CreateSessionBinding(sessionID, []string{workspace}, func([]sessionMACCoverage) error {
			return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, sessionID, workspace)
		}); err != nil {
			t.Fatalf("CreateSessionBinding: %v", err)
		}
		driver.removeErrors[workspace] = true
		mac.ReleaseSessionBinding(sessionID)
	}

	const wantMsg = "MAC boundary removal failed, ownership preserved for retry"

	// Warn level: the recovery warning reaches the operational log.
	triggerWarning("sess-mac-warn-1")
	if got := strings.Count(opBuf.String(), wantMsg); got != 1 {
		t.Fatalf("expected exactly 1 MAC warning at warn level, got %d:\n%s", got, opBuf.String())
	}
	// The record must be JSON with stream=operational (the operational owner).
	if !strings.Contains(opBuf.String(), `"stream":"operational"`) {
		t.Fatalf("MAC warning must be an operational JSONL record:\n%s", opBuf.String())
	}

	// Reload raises log_level to error: the same recovery path stays silent.
	logging.configure(opBuf, audBuf, slog.LevelError, true)
	triggerWarning("sess-mac-warn-2")
	if got := strings.Count(opBuf.String(), wantMsg); got != 1 {
		t.Fatalf("reload to error level must suppress the MAC warning (still %d records):\n%s", got, opBuf.String())
	}

	// Reload back to warn: the recovery path is logged again.
	logging.configure(opBuf, audBuf, slog.LevelWarn, true)
	triggerWarning("sess-mac-warn-3")
	if got := strings.Count(opBuf.String(), wantMsg); got != 2 {
		t.Fatalf("expected the MAC warning again after reload back to warn (got %d records):\n%s", got, opBuf.String())
	}
}

// TestDBInsertFailurePreservesOwnership verifies that when a session DB insert
// fails and boundary removal also fails, ownership metadata is preserved.
func TestDBInsertFailurePreservesOwnership(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Make boundary removal fail.
	driver.removeErrors[workspace] = true

	// Create session binding with a failing DB insert.
	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		return fmt.Errorf("simulated DB insert failure")
	})
	if err == nil {
		t.Fatal("expected error from CreateSessionBinding")
	}

	// Ownership should still be recorded (removal failed, so we keep it).
	mac.mu.Lock()
	owned, lookupErr := mac.isBoundaryOwnedByHelper(workspace)
	mac.mu.Unlock()
	if lookupErr != nil {
		t.Fatalf("isBoundaryOwnedByHelper: %v", lookupErr)
	}
	if !owned {
		t.Error("ownership should be preserved when boundary removal fails")
	}
}

// TestDBInsertFailureRemovesOwnershipOnSuccessfulRemoval verifies that when
// a session DB insert fails and boundary removal succeeds, ownership is removed.
func TestDBInsertFailureRemovesOwnershipOnSuccessfulRemoval(t *testing.T) {
	app, mac, _ := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Boundary removal succeeds (default).
	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		return fmt.Errorf("simulated DB insert failure")
	})
	if err == nil {
		t.Fatal("expected error from CreateSessionBinding")
	}

	// Ownership should be removed (removal succeeded).
	mac.mu.Lock()
	owned, lookupErr := mac.isBoundaryOwnedByHelper(workspace)
	mac.mu.Unlock()
	if lookupErr != nil {
		t.Fatalf("isBoundaryOwnedByHelper: %v", lookupErr)
	}
	if owned {
		t.Error("ownership should be removed when boundary removal succeeds")
	}
}

// TestSessionMACRemovalUsesDurableKindAcrossRestart proves the coordinator
// resolves the removal kind from the durable ownership metadata and that the
// identity survives a restart: a boundary created as a directory is removed
// through reconciliation with that same durable kind, even after the
// coordinator (and its in-memory bindings) were rebuilt from the database.
func TestSessionMACRemovalUsesDurableKindAcrossRestart(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace, err := os.MkdirTemp(allowedRoot, "durable-kind-*")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := mac.CreateSessionBinding("sess-durable", []string{workspace}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-durable", workspace)
	}); err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// The creation-proven kind is persisted with the ownership metadata.
	kind, err := mac.boundaryOwnedKind(workspace)
	if err != nil {
		t.Fatalf("boundaryOwnedKind: %v", err)
	}
	if kind != macBoundaryDirectory {
		t.Fatalf("durable kind = %s, want directory", macBoundaryKindName(kind))
	}

	// First removal attempt fails: ownership is retained.
	driver.removeErrors[workspace] = true
	mac.ReleaseSessionBinding("sess-durable")
	if owned, err := func() (bool, error) {
		mac.mu.Lock()
		defer mac.mu.Unlock()
		return mac.isBoundaryOwnedByHelper(workspace)
	}(); err != nil || !owned {
		t.Fatalf("ownership must be retained after the failed removal (owned=%v err=%v)", owned, err)
	}

	// The session row is gone (production deletes it before releasing the
	// binding); simulate the restart with a fresh coordinator on the same
	// database.
	if _, err := app.DB.Exec(`DELETE FROM sessions WHERE id = ?`, "sess-durable"); err != nil {
		t.Fatalf("delete session row: %v", err)
	}
	restartedDriver := newTestSessionMACDriver(LSMBackend("test"))
	restarted := newSessionMACCoordinator(app.DB, restartedDriver)
	if err := restarted.ReconcileLiveSessions(); err != nil {
		t.Fatalf("ReconcileLiveSessions: %v", err)
	}

	// The stale owned boundary must be removed through the reconciliation
	// owner with exactly the durable kind, and the ownership metadata must
	// be forgotten only after that successful completion.
	found := false
	for _, removed := range restartedDriver.removedBoundaries {
		if removed.Boundary == workspace {
			found = true
			if removed.Kind != macBoundaryDirectory {
				t.Errorf("restart removal kind = %s, want the durable creation-proven kind directory", macBoundaryKindName(removed.Kind))
			}
		}
	}
	if !found {
		t.Error("the restart reconciliation must remove the stale owned boundary")
	}
	restarted.mu.Lock()
	owned, err := restarted.isBoundaryOwnedByHelper(workspace)
	restarted.mu.Unlock()
	if err != nil {
		t.Fatalf("isBoundaryOwnedByHelper after restart: %v", err)
	}
	if owned {
		t.Error("ownership metadata must be forgotten after the completed removal")
	}
}

// TestSessionMACCleanupResumesAfterPartialRemoval proves the cleanup
// transition is explicitly retryable (the B2 review defect): after a failed
// removal attempt retains the ownership metadata, the next reconciliation
// completes the removal and forgets the ownership only at final completion.
// The driver must be attempted exactly twice for the same boundary: once
// failed, once completing.
func TestSessionMACCleanupResumesAfterPartialRemoval(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace, err := os.MkdirTemp(allowedRoot, "resume-*")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := mac.CreateSessionBinding("sess-resume", []string{workspace}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-resume", workspace)
	}); err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Attempt 1: the removal fails; the ownership state is retained for the
	// canonical retry/reconciliation owner.
	driver.removeErrors[workspace] = true
	mac.ReleaseSessionBinding("sess-resume")
	mac.mu.Lock()
	owned, err := mac.isBoundaryOwnedByHelper(workspace)
	mac.mu.Unlock()
	if err != nil {
		t.Fatalf("isBoundaryOwnedByHelper: %v", err)
	}
	if !owned {
		t.Fatal("ownership must be retained after the failed removal attempt")
	}

	// The session row is gone; the next reconciliation retries and completes.
	if _, err := app.DB.Exec(`DELETE FROM sessions WHERE id = ?`, "sess-resume"); err != nil {
		t.Fatalf("delete session row: %v", err)
	}
	driver.removeErrors[workspace] = false
	if err := mac.ReconcileLiveSessions(); err != nil {
		t.Fatalf("ReconcileLiveSessions: %v", err)
	}

	attempts := 0
	for _, removed := range driver.removedBoundaries {
		if removed.Boundary == workspace {
			attempts++
		}
	}
	if attempts != 2 {
		t.Errorf("removal attempts for %s = %d, want exactly two (failed, completing)", workspace, attempts)
	}
	mac.mu.Lock()
	owned, err = mac.isBoundaryOwnedByHelper(workspace)
	mac.mu.Unlock()
	if err != nil {
		t.Fatalf("isBoundaryOwnedByHelper after completion: %v", err)
	}
	if owned {
		t.Error("ownership metadata must be removed only at final completion")
	}
}

// TestLegacyAppArmorOwnershipReconciliation verifies that existing AppArmor
// helper-owned boundaries are imported into ownership metadata during reconciliation.
func TestLegacyAppArmorOwnershipReconciliation(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}

	// Simulate pre-existing helper-owned boundary (in fragment but not in mac_boundaries).
	driver := newTestSessionMACDriver(LSMAppArmor)
	driver.coverageMap["/data/workspace"] = "/data"
	driver.helperOwnedBoundaries["/data"] = true

	mac := newSessionMACCoordinator(db, driver)

	// Directly call importHelperOwnedBoundaries to test the import logic.
	mac.mu.Lock()
	if err := mac.importHelperOwnedBoundaries(); err != nil {
		t.Fatalf("importHelperOwnedBoundaries: %v", err)
	}
	mac.mu.Unlock()

	// Verify ownership was imported by checking the DB directly.
	var dbBackend string
	err = db.QueryRow(`SELECT backend FROM mac_boundaries WHERE boundary = ?`, "/data").Scan(&dbBackend)
	if err != nil {
		t.Fatalf("DB query for /data: %v", err)
	}
	if dbBackend != "apparmor" {
		t.Errorf("expected backend 'apparmor', got '%s'", dbBackend)
	}
}

// TestSELinuxCoverageListFailureFailsClosed verifies that when
// listCoveringFcontexts fails, ensureCoverage and verifyCoverage return errors.
func TestSELinuxCoverageListFailureFailsClosed(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}

	// Create a mock SELinux manager that fails on listCoveringFcontexts.
	mgr := &selinuxFcontextManager{
		semanagePath:   "/usr/sbin/semanage",
		restoreconPath: "/usr/sbin/restorecon",
		runCommand: func(cmd string, args ...string) ([]byte, error) {
			return nil, fmt.Errorf("semanage failed")
		},
		readPathCon: func(path string) (string, error) {
			return "docker_helper_workspace_t", nil
		},
		selinuxActive: func() (bool, bool, error) {
			return true, true, nil
		},
		readMountinfo: func() ([]byte, error) {
			return []byte(""), nil
		},
		treeKind: fakeTreeKindDirectory,
		acquireLock: func() (func() error, error) {
			return func() error { return nil }, nil
		},
	}

	driver := &selinuxMACDriver{mgr: mgr, treeKind: fakeTreeKindDirectory}

	// ensureCoverage should fail when listCoveringFcontexts fails.
	_, _, err = driver.ensureCoverage("/data/workspace")
	if err == nil {
		t.Error("ensureCoverage should fail when listCoveringFcontexts fails")
	}

	// verifyCoverage should fail when listCoveringFcontexts fails.
	_, err = driver.verifyCoverage("/data/workspace")
	if err == nil {
		t.Error("verifyCoverage should fail when listCoveringFcontexts fails")
	}
}

// TestMACPreparationErrorClassification verifies that MAC preparation errors
// from CreateSessionBinding are classified as ErrMAC, not ErrDatabase.
func TestMACPreparationErrorClassification(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}

	// Create a driver that fails on ensureCoverage.
	driver := &failingSessionMACDriver{err: fmt.Errorf("MAC setup failed")}
	mac := newSessionMACCoordinator(db, driver)

	// CreateSessionBinding should return an error wrapped with ErrMACPreparation.
	_, err = mac.CreateSessionBinding("sess-1", []string{"/data/workspace"}, func([]sessionMACCoverage) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error from CreateSessionBinding")
	}

	// Verify the error chain contains ErrMACPreparation.
	if !errors.Is(err, ErrMACPreparation) {
		t.Errorf("expected ErrMACPreparation in error chain, got: %v", err)
	}

	// Verify classifyCreateSessionError returns mac_preparation_failed.
	wrappedErr := fmt.Errorf("cannot create session: %w: %w", err, ErrMAC)
	classification := classifyCreateSessionError(wrappedErr)
	if classification != "mac_preparation_failed" {
		t.Errorf("expected mac_preparation_failed, got %s", classification)
	}
}

// TestDBInsertErrorRemainsDatabaseError verifies that DB insert errors from
// CreateSessionBinding remain classified as ErrDatabase.
func TestDBInsertErrorRemainsDatabaseError(t *testing.T) {
	app, mac, _ := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create session binding with a failing DB insert.
	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		return fmt.Errorf("database locked")
	})
	if err == nil {
		t.Fatal("expected error from CreateSessionBinding")
	}

	// The error should NOT be wrapped with ErrMACPreparation.
	if errors.Is(err, ErrMACPreparation) {
		t.Error("DB insert error should not be classified as MAC preparation error")
	}
}

// failingSessionMACDriver is a mock driver that always fails on ensureCoverage.
type failingSessionMACDriver struct {
	err error
}

func (b *failingSessionMACDriver) ensureCoverage(workspace string) (sessionMACCoverage, bool, error) {
	return sessionMACCoverage{}, false, b.err
}

func (b *failingSessionMACDriver) verifyCoverage(workspace string) (sessionMACCoverage, error) {
	return sessionMACCoverage{}, b.err
}

func (b *failingSessionMACDriver) removeBoundary(boundary string, kind macBoundaryKind) error {
	return nil
}

func (b *failingSessionMACDriver) discoverHelperOwnedBoundaries() ([]helperOwnedBoundary, error) {
	return nil, nil
}

func (b *failingSessionMACDriver) backend() LSMBackend {
	return LSMBackend("test")
}

// =============================================================================
// SELinux verifyCoverage/ensureCoverage with actual type verification
// =============================================================================

// selinuxTestDriver is a mock SELinux driver for testing actual type verification.
type selinuxTestDriver struct {
	mu                   sync.Mutex
	coveringFcontexts    map[string][]string // workspace -> covering boundaries
	actualType           string              // returned type for verifyActualType
	restoreconCalls      int
	restoreconFail       bool
	verifyActualTypeFail bool
}

func (b *selinuxTestDriver) ensureCoverage(workspace string) (sessionMACCoverage, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if boundaries, ok := b.coveringFcontexts[workspace]; ok && len(boundaries) > 0 {
		// Existing compatible coverage: run restorecon and verify actual type.
		if b.restoreconFail {
			return sessionMACCoverage{}, false, fmt.Errorf("restorecon failed for %s", workspace)
		}
		b.restoreconCalls++
		if b.verifyActualTypeFail {
			return sessionMACCoverage{}, false, fmt.Errorf("actual type verification failed for %s", workspace)
		}
		return sessionMACCoverage{Boundary: boundaries[0], HelperOwned: false}, false, nil
	}

	// No existing coverage: create new boundary.
	return sessionMACCoverage{Boundary: workspace, HelperOwned: true}, true, nil
}

func (b *selinuxTestDriver) verifyCoverage(workspace string) (sessionMACCoverage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if boundaries, ok := b.coveringFcontexts[workspace]; ok && len(boundaries) > 0 {
		// Boundary exists — verify actual on-disk type.
		if b.verifyActualTypeFail {
			return sessionMACCoverage{}, fmt.Errorf("existing SELinux boundary %s exists but actual type for %s is incorrect: wrong_type", boundaries[0], workspace)
		}
		return sessionMACCoverage{Boundary: boundaries[0], HelperOwned: false}, nil
	}

	// No boundary — check workspace itself.
	if b.verifyActualTypeFail {
		return sessionMACCoverage{}, fmt.Errorf("workspace %s not covered by any SELinux boundary", workspace)
	}
	return sessionMACCoverage{Boundary: workspace, HelperOwned: false}, nil
}

func (b *selinuxTestDriver) removeBoundary(boundary string, kind macBoundaryKind) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return nil
}

func (b *selinuxTestDriver) discoverHelperOwnedBoundaries() ([]helperOwnedBoundary, error) {
	return nil, nil
}

func (b *selinuxTestDriver) backend() LSMBackend {
	return LSMSELinux
}

func TestSELinuxAncestorRuleCorrectType(t *testing.T) {
	// Existing ancestor rule + correct actual type -> verify succeeds.
	driver := &selinuxTestDriver{
		coveringFcontexts: map[string][]string{
			"/data/workspace": {"/data"},
		},
		actualType: "docker_helper_workspace_t",
	}

	cov, err := driver.verifyCoverage("/data/workspace")
	if err != nil {
		t.Fatalf("verifyCoverage should succeed with correct type: %v", err)
	}
	if cov.Boundary != "/data" {
		t.Errorf("expected boundary /data, got %s", cov.Boundary)
	}
}

func TestSELinuxAncestorRuleWrongType(t *testing.T) {
	// Existing ancestor rule + wrong actual type -> verify fails.
	driver := &selinuxTestDriver{
		coveringFcontexts: map[string][]string{
			"/data/workspace": {"/data"},
		},
		verifyActualTypeFail: true,
	}

	_, err := driver.verifyCoverage("/data/workspace")
	if err == nil {
		t.Fatal("verifyCoverage should fail with wrong actual type")
	}
	if !strings.Contains(err.Error(), "incorrect") {
		t.Errorf("expected 'incorrect' in error, got: %v", err)
	}
}

func TestSELinuxEnsureExistingAncestorWrongType(t *testing.T) {
	// ensure on existing ancestor rule + wrong actual type -> restorecon/verify fails.
	driver := &selinuxTestDriver{
		coveringFcontexts: map[string][]string{
			"/data/workspace": {"/data"},
		},
		restoreconFail:       false,
		verifyActualTypeFail: true,
	}

	_, _, err := driver.ensureCoverage("/data/workspace")
	if err == nil {
		t.Fatal("ensureCoverage should fail when actual type verification fails")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("expected 'verification failed' in error, got: %v", err)
	}
}

func TestSELinuxRestoreconFailureFailsClosed(t *testing.T) {
	// restorecon/verification failure -> session/startup fails closed.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}

	driver := &selinuxTestDriver{
		coveringFcontexts: map[string][]string{
			"/data/workspace": {"/data"},
		},
		restoreconFail: true,
	}

	mac := newSessionMACCoordinator(db, driver)

	_, err = mac.CreateSessionBinding("sess-1", []string{"/data/workspace"}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(db, testMACLauncherID(t, db), "sess-1", "/data/workspace")
	})
	if err == nil {
		t.Fatal("CreateSessionBinding should fail when restorecon fails")
	}
	if !errors.Is(err, ErrMACPreparation) {
		t.Errorf("expected ErrMACPreparation, got: %v", err)
	}
}

// =============================================================================
// Lease release idempotency
// =============================================================================

func TestLeaseReleaseIdempotent(t *testing.T) {
	app, mac, _ := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create session binding.
	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-1", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Acquire lease.
	_, release, err := mac.AcquireSessionUse("sess-1", workspace)
	if err != nil {
		t.Fatalf("AcquireSessionUse: %v", err)
	}

	// Record state before first release.
	mac.mu.Lock()
	countBefore := mac.boundaryConsumerCounts[workspace]
	leaseCountBefore := len(mac.sessionUseLeases)
	mac.mu.Unlock()

	// First release.
	release()

	mac.mu.Lock()
	countAfterFirst := mac.boundaryConsumerCounts[workspace]
	leaseCountAfterFirst := len(mac.sessionUseLeases)
	boundaryRemoved := func() bool {
		_, err := mac.driver.verifyCoverage(workspace)
		return err != nil
	}()
	mac.mu.Unlock()

	// Second release (must be no-op).
	release()

	mac.mu.Lock()
	countAfterSecond := mac.boundaryConsumerCounts[workspace]
	leaseCountAfterSecond := len(mac.sessionUseLeases)
	boundaryRemovedSecond := func() bool {
		_, err := mac.driver.verifyCoverage(workspace)
		return err != nil
	}()
	mac.mu.Unlock()

	// Verify second release changed nothing.
	if countAfterFirst != countAfterSecond {
		t.Errorf("second release changed boundaryConsumerCounts: first=%d, second=%d", countAfterFirst, countAfterSecond)
	}
	if leaseCountAfterFirst != leaseCountAfterSecond {
		t.Errorf("second release changed leases: first=%d, second=%d", leaseCountAfterFirst, leaseCountAfterSecond)
	}
	if boundaryRemoved != boundaryRemovedSecond {
		t.Errorf("second release changed driver boundary state: first=%v, second=%v", boundaryRemoved, boundaryRemovedSecond)
	}
	// Verify the boundary count was decremented exactly once.
	if countBefore != countAfterFirst+1 {
		t.Errorf("expected count decremented by 1: before=%d, after=%d", countBefore, countAfterFirst)
	}
	// Verify the lease was removed exactly once.
	if leaseCountBefore != leaseCountAfterFirst+1 {
		t.Errorf("expected lease count decremented by 1: before=%d, after=%d", leaseCountBefore, leaseCountAfterFirst)
	}
}

// =============================================================================
// Deferred nested-boundary cleanup
// =============================================================================

func TestDeferredBoundaryCleanupChildThenParent(t *testing.T) {
	// Child boundary, parent boundary, delete child, delete parent -> both gone.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}

	driver := newTestSessionMACDriver(LSMBackend("test"))
	mac := newSessionMACCoordinator(db, driver)

	parentWS := "/data/parent"
	childWS := "/data/parent/child"

	// Create parent session binding.
	_, err = mac.CreateSessionBinding("sess-parent", []string{parentWS}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(db, testMACLauncherID(t, db), "sess-parent", parentWS)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding parent: %v", err)
	}

	// Create child session binding.
	_, err = mac.CreateSessionBinding("sess-child", []string{childWS}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(db, testMACLauncherID(t, db), "sess-child", childWS)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding child: %v", err)
	}

	// Delete child first.
	mac.ReleaseSessionBinding("sess-child")

	// Child boundary should be deferred (parent still needs it via overlap).
	mac.mu.Lock()
	childActive := mac.boundaryConsumerCounts[childWS]
	childDeferred := mac.deferredBoundaries[childWS]
	parentActive := mac.boundaryConsumerCounts[parentWS]
	mac.mu.Unlock()

	if childActive != 0 {
		t.Errorf("child active count should be 0 after release, got %d", childActive)
	}
	if !childDeferred {
		t.Error("child boundary should be deferred (parent still overlaps)")
	}
	if parentActive != 1 {
		t.Errorf("parent active count should be 1, got %d", parentActive)
	}

	// Delete parent.
	mac.ReleaseSessionBinding("sess-parent")

	// Both boundaries should now be gone.
	mac.mu.Lock()
	parentActive = mac.boundaryConsumerCounts[parentWS]
	parentDeferred := mac.deferredBoundaries[parentWS]
	childActive = mac.boundaryConsumerCounts[childWS]
	childDeferred = mac.deferredBoundaries[childWS]
	mac.mu.Unlock()

	if parentActive != 0 {
		t.Errorf("parent active count should be 0, got %d", parentActive)
	}
	if parentDeferred {
		t.Error("parent boundary should not be deferred after all consumers gone")
	}
	if childActive != 0 {
		t.Errorf("child active count should be 0, got %d", childActive)
	}
	if childDeferred {
		t.Error("child boundary should not be deferred after all consumers gone")
	}

	// Verify both boundaries were removed from driver.
	_, err = driver.verifyCoverage(parentWS)
	if err == nil {
		t.Error("parent boundary should be removed from driver")
	}
	_, err = driver.verifyCoverage(childWS)
	if err == nil {
		t.Error("child boundary should be removed from driver")
	}
}

func TestDeferredBoundaryCleanupParentThenChild(t *testing.T) {
	// Reverse deletion order: delete parent first, then child.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}

	driver := newTestSessionMACDriver(LSMBackend("test"))
	mac := newSessionMACCoordinator(db, driver)

	parentWS := "/data/parent"
	childWS := "/data/parent/child"

	// Create parent session binding.
	_, err = mac.CreateSessionBinding("sess-parent", []string{parentWS}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(db, testMACLauncherID(t, db), "sess-parent", parentWS)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding parent: %v", err)
	}

	// Create child session binding.
	_, err = mac.CreateSessionBinding("sess-child", []string{childWS}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(db, testMACLauncherID(t, db), "sess-child", childWS)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding child: %v", err)
	}

	// Delete parent first.
	mac.ReleaseSessionBinding("sess-parent")

	// Parent boundary should be deferred (child still overlaps).
	mac.mu.Lock()
	parentActive := mac.boundaryConsumerCounts[parentWS]
	parentDeferred := mac.deferredBoundaries[parentWS]
	childActive := mac.boundaryConsumerCounts[childWS]
	mac.mu.Unlock()

	if parentActive != 0 {
		t.Errorf("parent active count should be 0 after release, got %d", parentActive)
	}
	if !parentDeferred {
		t.Error("parent boundary should be deferred (child still overlaps)")
	}
	if childActive != 1 {
		t.Errorf("child active count should be 1, got %d", childActive)
	}

	// Delete child.
	mac.ReleaseSessionBinding("sess-child")

	// Both boundaries should now be gone.
	mac.mu.Lock()
	parentActive = mac.boundaryConsumerCounts[parentWS]
	parentDeferred = mac.deferredBoundaries[parentWS]
	childActive = mac.boundaryConsumerCounts[childWS]
	childDeferred := mac.deferredBoundaries[childWS]
	mac.mu.Unlock()

	if parentActive != 0 {
		t.Errorf("parent active count should be 0, got %d", parentActive)
	}
	if parentDeferred {
		t.Error("parent boundary should not be deferred after all consumers gone")
	}
	if childActive != 0 {
		t.Errorf("child active count should be 0, got %d", childActive)
	}
	if childDeferred {
		t.Error("child boundary should not be deferred after all consumers gone")
	}
}

func TestDeferredBoundaryExactMatch(t *testing.T) {
	// Two sessions on the same exact workspace boundary.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}

	driver := newTestSessionMACDriver(LSMBackend("test"))
	mac := newSessionMACCoordinator(db, driver)

	workspace := "/data/workspace"

	// Create two session bindings on the same workspace.
	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(db, testMACLauncherID(t, db), "sess-1", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding sess-1: %v", err)
	}

	_, err = mac.CreateSessionBinding("sess-2", []string{workspace}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(db, testMACLauncherID(t, db), "sess-2", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding sess-2: %v", err)
	}

	mac.mu.Lock()
	countBefore := mac.boundaryConsumerCounts[workspace]
	mac.mu.Unlock()
	if countBefore != 2 {
		t.Errorf("expected count 2, got %d", countBefore)
	}

	// Delete first session.
	mac.ReleaseSessionBinding("sess-1")

	mac.mu.Lock()
	countAfterFirst := mac.boundaryConsumerCounts[workspace]
	deferred := mac.deferredBoundaries[workspace]
	mac.mu.Unlock()

	// Count should be 1, no deferral needed (sess-2 still has direct count).
	if countAfterFirst != 1 {
		t.Errorf("expected count 1 after first release, got %d", countAfterFirst)
	}
	if deferred {
		t.Error("should not be deferred when direct consumer remains")
	}

	// Delete second session.
	mac.ReleaseSessionBinding("sess-2")

	mac.mu.Lock()
	countAfterSecond := mac.boundaryConsumerCounts[workspace]
	deferred = mac.deferredBoundaries[workspace]
	mac.mu.Unlock()

	if countAfterSecond != 0 {
		t.Errorf("expected count 0, got %d", countAfterSecond)
	}
	if deferred {
		t.Error("should not be deferred after last consumer gone")
	}

	// Verify boundary was removed from driver.
	_, err = driver.verifyCoverage(workspace)
	if err == nil {
		t.Error("boundary should be removed from driver")
	}
}

// =============================================================================
// Pending-workload coverage gate on Session deletion (canonical removal owner)
// =============================================================================

// TestSessionDeleteDefersBoundaryWhilePendingWorkloadUnproven drives the real
// production Session deletion path (deleteSessionScoped) with pending
// helper-owned workload state still referencing the Session (container
// absence not yet provable — the startup reconciliation retains the workload
// state), and proves the deletion cannot drop the Session's MAC coverage
// before that state is proven gone. After the workload state is proven
// cleaned, the canonical retry path removes the boundary.
func TestSessionDeleteDefersBoundaryWhilePendingWorkloadUnproven(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	const sessionID = "sess-pending-workload"
	_, err = mac.CreateSessionBinding(sessionID, []string{workspace}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, sessionID, workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Wire the workload MAC coordinator's pending-workload coverage gate to
	// report this Session: its helper-owned workload state is retained for
	// reconciliation and its container absence is not yet proven.
	mac.pendingWorkloadSessions = func() map[string]bool {
		return map[string]bool{sessionID: true}
	}

	// The canonical removal owner classifies the boundary as covering the
	// pending session's workspace while the row still resolves.
	mac.mu.Lock()
	classified := mac.boundaryMayBeRemoved(workspace, map[string]bool{workspace: true}, false)
	mac.mu.Unlock()
	if classified {
		t.Fatal("canonical removal owner must classify the boundary as pending-workload covered before deletion")
	}

	// Delete the Session through the real production deletion path.
	session, err := app.deleteSessionScoped(sessionID, sessionControlScope{admin: true})
	if err != nil {
		t.Fatalf("deleteSessionScoped: %v", err)
	}
	if session == nil || session.ID != sessionID {
		t.Fatalf("deleted session mismatch: %+v", session)
	}

	// Session deletion semantics remain what the product contract requires:
	// the row is gone, so the session no longer exists in the database.
	var rowCount int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id = ?`, sessionID).Scan(&rowCount); err != nil {
		t.Fatalf("count session rows: %v", err)
	}
	if rowCount != 0 {
		t.Fatalf("session row must be deleted by deleteSessionScoped, found %d", rowCount)
	}

	// The MAC coverage must remain while the pending workload state is
	// unproven: the boundary stays in the driver, ownership metadata stays,
	// and the boundary is registered for the retry path.
	if _, err := driver.verifyCoverage(workspace); err != nil {
		t.Fatalf("boundary coverage must remain while pending workload is unproven: %v", err)
	}
	mac.mu.Lock()
	owned, oerr := mac.isBoundaryOwnedByHelper(workspace)
	deferred := mac.deferredBoundaries[workspace]
	mac.mu.Unlock()
	if oerr != nil {
		t.Fatalf("isBoundaryOwnedByHelper: %v", oerr)
	}
	if !owned {
		t.Error("boundary ownership metadata must remain while pending workload is unproven")
	}
	if !deferred {
		t.Error("boundary must be registered deferred for the retry path while pending workload is unproven")
	}

	// The pending workload dependency stays classifiable/reconcilable: the
	// workload coordinator still reports the pending session, and after the
	// row deletion the coverage pass classifies it fail-closed (the workspace
	// can no longer be resolved), so the canonical owner keeps blocking.
	mac.mu.Lock()
	pendingRoots, deferAll := mac.pendingWorkloadCoverage()
	removable := mac.boundaryMayBeRemoved(workspace, pendingRoots, deferAll)
	reported := mac.pendingWorkloadSessions()
	mac.mu.Unlock()
	if !reported[sessionID] {
		t.Error("pending workload state must remain reported for reconciliation after the Session row is deleted")
	}
	if !deferAll {
		t.Errorf("coverage pass must fail closed when the deleted session row cannot be resolved (deferAll=%v, pending=%v)", deferAll, pendingRoots)
	}
	if removable {
		t.Error("canonical removal owner must still block the boundary while pending workload is unproven")
	}

	// After the pending workload state is proven cleaned, the canonical retry
	// path may remove the boundary.
	mac.pendingWorkloadSessions = func() map[string]bool { return nil }
	mac.mu.Lock()
	mac.retryDeferredBoundaries()
	ownedAfter, oerrAfter := mac.isBoundaryOwnedByHelper(workspace)
	mac.mu.Unlock()
	if oerrAfter != nil {
		t.Fatalf("isBoundaryOwnedByHelper after retry: %v", oerrAfter)
	}
	if ownedAfter {
		t.Error("boundary ownership metadata must be removed after the pending workload is proven cleaned")
	}
	if _, err := driver.verifyCoverage(workspace); err == nil {
		t.Error("boundary must be removed from the driver after the pending workload is proven cleaned")
	}
}

// TestSessionDeleteKeepsBoundaryWhenPendingWorkloadUnresolvable proves the
// fail-closed branch of the canonical removal owner: a pending workload
// session ID exists but its workspace cannot be resolved (no session row),
// so the whole removal pass defers and the deleted Session's boundary MUST
// NOT be removed.
func TestSessionDeleteKeepsBoundaryWhenPendingWorkloadUnresolvable(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	const sessionID = "sess-real-session"
	_, err = mac.CreateSessionBinding(sessionID, []string{workspace}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, sessionID, workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// The pending workload references a session ID whose row cannot be
	// resolved: the pending-workload coverage resolution fails closed.
	mac.pendingWorkloadSessions = func() map[string]bool {
		return map[string]bool{"dhs_unresolvable0000000000000000000000": true}
	}

	if _, err := app.deleteSessionScoped(sessionID, sessionControlScope{admin: true}); err != nil {
		t.Fatalf("deleteSessionScoped: %v", err)
	}

	// The boundary MUST NOT be removed: coverage and ownership remain and the
	// boundary is deferred until the pending workload state resolves or is
	// proven cleaned.
	if _, err := driver.verifyCoverage(workspace); err != nil {
		t.Fatalf("boundary coverage must remain when pending workload workspace is unresolvable: %v", err)
	}
	mac.mu.Lock()
	owned, oerr := mac.isBoundaryOwnedByHelper(workspace)
	deferred := mac.deferredBoundaries[workspace]
	mac.mu.Unlock()
	if oerr != nil {
		t.Fatalf("isBoundaryOwnedByHelper: %v", oerr)
	}
	if !owned {
		t.Error("boundary ownership metadata must remain when pending workload workspace is unresolvable")
	}
	if !deferred {
		t.Error("boundary must be deferred when pending workload workspace is unresolvable")
	}
}

// =============================================================================
// Backend-safe ownership key
// =============================================================================

func TestBackendSwitchOwnership(t *testing.T) {
	// Switch from "apparmor" driver to "selinux" driver.
	// The new driver must be able to claim ownership of the same boundary
	// without being blocked by stale ownership from the old driver.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}

	// Create lifecycle with "apparmor" driver.
	apparmorDriver := newTestSessionMACDriver(LSMAppArmor)
	mac1 := newSessionMACCoordinator(db, apparmorDriver)

	workspace := "/data/workspace"

	// Create boundary with apparmor driver.
	_, err = mac1.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(db, testMACLauncherID(t, db), "sess-1", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding with apparmor: %v", err)
	}

	// Verify apparmor owns the boundary.
	mac1.mu.Lock()
	owned, err := mac1.isBoundaryOwnedByHelper(workspace)
	mac1.mu.Unlock()
	if err != nil {
		t.Fatalf("isBoundaryOwnedByHelper: %v", err)
	}
	if !owned {
		t.Error("apparmor should own the boundary")
	}

	// Release the session.
	mac1.ReleaseSessionBinding("sess-1")

	// Now create lifecycle with "selinux" driver.
	selinuxDriver := newTestSessionMACDriver(LSMSELinux)
	mac2 := newSessionMACCoordinator(db, selinuxDriver)

	// selinux should NOT see apparmor's ownership.
	mac2.mu.Lock()
	ownedBySELinux, err := mac2.isBoundaryOwnedByHelper(workspace)
	mac2.mu.Unlock()
	if err != nil {
		t.Fatalf("isBoundaryOwnedByHelper: %v", err)
	}
	if ownedBySELinux {
		t.Error("selinux should not see apparmor's ownership")
	}

	// selinux can create its own boundary at the same path.
	_, err = mac2.CreateSessionBinding("sess-2", []string{workspace}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(db, testMACLauncherID(t, db), "sess-2", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding with selinux: %v", err)
	}

	// Verify selinux now owns the boundary.
	mac2.mu.Lock()
	ownedBySELinux, err = mac2.isBoundaryOwnedByHelper(workspace)
	mac2.mu.Unlock()
	if err != nil {
		t.Fatalf("isBoundaryOwnedByHelper: %v", err)
	}
	if !ownedBySELinux {
		t.Error("selinux should own the boundary after creation")
	}

	// Verify both drivers have their own records in the DB.
	var apparmorCount, selinuxCount int
	err = db.QueryRow(`SELECT COUNT(*) FROM mac_boundaries WHERE backend = 'apparmor' AND boundary = ?`, workspace).Scan(&apparmorCount)
	if err != nil {
		t.Fatalf("query apparmor: %v", err)
	}
	err = db.QueryRow(`SELECT COUNT(*) FROM mac_boundaries WHERE backend = 'selinux' AND boundary = ?`, workspace).Scan(&selinuxCount)
	if err != nil {
		t.Fatalf("query selinux: %v", err)
	}
	if apparmorCount != 0 {
		t.Errorf("apparmor record should have been removed, got %d", apparmorCount)
	}
	if selinuxCount != 1 {
		t.Errorf("selinux should have 1 record, got %d", selinuxCount)
	}
}

// =============================================================================
// Production-path ordering tests (real handler tests)
// =============================================================================

// TestRunHandlerPinCleanupFailureRetainsLease drives the actual handleRun
// handler with a pinned mount whose Cleanup fails, and verifies that the
// MAC lease is retained (not released) by inspecting the lifecycle state.
func TestRunHandlerPinCleanupFailureRetainsLease(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	initializeTestDatabase(t, db)

	driver := newTestSessionMACDriver(LSMBackend("test"))
	mac := newSessionMACCoordinator(db, driver)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AllowedRoots:          []AllowedRootEntry{allowedRootEntry(dir)},
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
		Mode:                  ModeSystem,
	}

	app := &App{
		Config:              cfg,
		DB:                  db,
		MACCoordinator:      mac,
		OperationSupervisor: newOperationSupervisor(),
	}

	installTestWorkloadMACForTest(t, app, LSMAppArmor)
	// Create workspace and session.
	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}

	// Generate auth token for the session.
	token, err := generateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte(token))

	launcherID := testMACLauncherID(t, db)

	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// The coherent run/build authority read loads the persisted snapshot
	// rows of the directly seeded session; issue them for the fixture.
	insertTestSessionSnapshot(t, db, "sess-1", workspace)

	// Inject a pinned mount with a failing Cleanup.
	sentinelErr := errors.New("injected pinned mount cleanup error")
	app.PinMountSourceFn = func(sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			PinnedPath: "/tmp/test-mount",
			cleanup: func() error {
				return sentinelErr
			},
		}, nil
	}

	// Create a mount source so the handler doesn't reject the request.
	mountSource := filepath.Join(workspace, "src")
	if err := os.MkdirAll(mountSource, 0755); err != nil {
		t.Fatal(err)
	}

	// Execute command succeeds (true).
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	// Drive handleRun.
	req := httptest.NewRequest(http.MethodPost, "/run",
		bytes.NewReader([]byte(`{"image":"alpine","mounts":[{"source":"src","target":"/mnt"}]}`)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("handleRun: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Wait for operation to complete.
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	// Verify: the MAC lease was NOT released because cleanup failed.
	// The boundary count should still reflect the session binding + the
	// unreleased lease (the lease was never released due to cleanup failure).
	mac.mu.Lock()
	boundaryCount := mac.boundaryConsumerCounts[workspace]
	leaseCount := len(mac.sessionUseLeases)
	mac.mu.Unlock()

	// The session binding contributes 1. The lease was acquired but NOT
	// released because cleanup failed. The lease entry should still exist.
	if leaseCount != 1 {
		t.Errorf("expected 1 lease retained (cleanup failed), got %d", leaseCount)
	}
	if boundaryCount != 2 {
		t.Errorf("expected boundaryConsumerCounts=2 (session + unreleased lease), got %d", boundaryCount)
	}
}

// TestRunHandlerCleanupSuccessReleasesLease drives handleRun with a
// successful pinned mount cleanup and verifies the MAC lease IS released.
func TestRunHandlerCleanupSuccessReleasesLease(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	initializeTestDatabase(t, db)

	driver := newTestSessionMACDriver(LSMBackend("test"))
	mac := newSessionMACCoordinator(db, driver)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AllowedRoots:          []AllowedRootEntry{allowedRootEntry(dir)},
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
		Mode:                  ModeSystem,
	}

	app := &App{
		Config:              cfg,
		DB:                  db,
		MACCoordinator:      mac,
		OperationSupervisor: newOperationSupervisor(),
	}

	installTestWorkloadMACForTest(t, app, LSMAppArmor)
	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}

	// Generate auth token for the session.
	token, err := generateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte(token))

	launcherID := testMACLauncherID(t, db)

	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// The coherent run/build authority read loads the persisted snapshot
	// rows of the directly seeded session; issue them for the fixture.
	insertTestSessionSnapshot(t, db, "sess-1", workspace)

	// Inject a pinned mount with a successful Cleanup.
	app.PinMountSourceFn = func(sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			PinnedPath: "/tmp/test-mount",
			cleanup: func() error {
				return nil
			},
		}, nil
	}

	mountSource := filepath.Join(workspace, "src")
	if err := os.MkdirAll(mountSource, 0755); err != nil {
		t.Fatal(err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	req := httptest.NewRequest(http.MethodPost, "/run",
		bytes.NewReader([]byte(`{"image":"alpine","mounts":[{"source":"src","target":"/mnt"}]}`)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("handleRun: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found")
	}
	op.Wait()

	// Verify: the MAC lease WAS released because cleanup succeeded.
	mac.mu.Lock()
	leaseCount := len(mac.sessionUseLeases)
	mac.mu.Unlock()

	if leaseCount != 0 {
		t.Errorf("expected 0 leases (cleanup succeeded, lease released), got %d", leaseCount)
	}
}

// TestBuildHandlerStagingCleanupFailureRetainsLease drives handleBuild with
// a staging seam that fails Cleanup, and verifies the MAC lease is retained.
func TestBuildHandlerStagingCleanupFailureRetainsLease(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	initializeTestDatabase(t, db)

	driver := newTestSessionMACDriver(LSMBackend("test"))
	mac := newSessionMACCoordinator(db, driver)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AllowedRoots:          []AllowedRootEntry{allowedRootEntry(dir)},
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
		Config:              cfg,
		DB:                  db,
		MACCoordinator:      mac,
		OperationSupervisor: newOperationSupervisor(),
	}

	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Generate auth token for the session.
	token, err := generateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte(token))

	launcherID := testMACLauncherID(t, db)

	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// The coherent run/build authority read loads the persisted snapshot
	// rows of the directly seeded session; issue them for the fixture.
	insertTestSessionSnapshot(t, db, "sess-1", workspace)

	// Inject staging seam with failing Cleanup.
	sentinelErr := errors.New("injected staging cleanup error")
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		stagingDir := t.TempDir()
		opDir := filepath.Join(stagingDir, opID)
		if err := os.MkdirAll(opDir, 0o700); err != nil {
			return nil, err
		}
		ctxDir := filepath.Join(opDir, "context")
		if err := os.MkdirAll(ctxDir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(ctxDir, dfrel), []byte("FROM scratch\n"), 0o644); err != nil {
			return nil, err
		}
		return &stagedBuildContext{
			ContextPath:    ctxDir,
			DockerfilePath: filepath.Join(ctxDir, dfrel),
			cleanupPath:    opDir,
			removeAll: func(path string) error {
				return sentinelErr
			},
		}, nil
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	reqBody := map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "test:latest",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("handleBuild: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found")
	}
	op.Wait()

	// Verify: the MAC lease was NOT released because staging cleanup failed.
	mac.mu.Lock()
	leaseCount := len(mac.sessionUseLeases)
	mac.mu.Unlock()

	if leaseCount != 1 {
		t.Errorf("expected 1 lease retained (staging cleanup failed), got %d", leaseCount)
	}
}

// TestBuildHandlerCleanupSuccessReleasesLease drives handleBuild with a
// successful staging cleanup and verifies the MAC lease IS released.
func TestBuildHandlerCleanupSuccessReleasesLease(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	initializeTestDatabase(t, db)

	driver := newTestSessionMACDriver(LSMBackend("test"))
	mac := newSessionMACCoordinator(db, driver)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AllowedRoots:          []AllowedRootEntry{allowedRootEntry(dir)},
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
		Config:              cfg,
		DB:                  db,
		MACCoordinator:      mac,
		OperationSupervisor: newOperationSupervisor(),
	}

	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Generate auth token for the session.
	token, err := generateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte(token))

	launcherID := testMACLauncherID(t, db)

	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// The coherent run/build authority read loads the persisted snapshot
	// rows of the directly seeded session; issue them for the fixture.
	insertTestSessionSnapshot(t, db, "sess-1", workspace)

	// Inject staging seam with successful Cleanup.
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		stagingDir := t.TempDir()
		opDir := filepath.Join(stagingDir, opID)
		if err := os.MkdirAll(opDir, 0o700); err != nil {
			return nil, err
		}
		ctxDir := filepath.Join(opDir, "context")
		if err := os.MkdirAll(ctxDir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(ctxDir, dfrel), []byte("FROM scratch\n"), 0o644); err != nil {
			return nil, err
		}
		return &stagedBuildContext{
			ContextPath:    ctxDir,
			DockerfilePath: filepath.Join(ctxDir, dfrel),
			cleanupPath:    opDir,
		}, nil
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	reqBody := map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "test:latest",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("handleBuild: expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found")
	}
	op.Wait()

	// Verify: the MAC lease WAS released because staging cleanup succeeded.
	mac.mu.Lock()
	leaseCount := len(mac.sessionUseLeases)
	mac.mu.Unlock()

	if leaseCount != 0 {
		t.Errorf("expected 0 leases (staging cleanup succeeded), got %d", leaseCount)
	}
}

// TestAdmitRejectionRunPinsBeforeLease drives handleRun with admit
// rejection and verifies pins are cleaned up before the lease is released.
func TestAdmitRejectionRunPinsBeforeLease(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	initializeTestDatabase(t, db)

	driver := newTestSessionMACDriver(LSMBackend("test"))
	mac := newSessionMACCoordinator(db, driver)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AllowedRoots:          []AllowedRootEntry{allowedRootEntry(dir)},
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
		Mode:                  ModeSystem,
	}

	app := &App{
		Config:              cfg,
		DB:                  db,
		MACCoordinator:      mac,
		OperationSupervisor: newOperationSupervisor(),
	}

	installTestWorkloadMACForTest(t, app, LSMAppArmor)
	// Force admit rejection.
	app.OperationSupervisor.beginShutdown()

	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}

	// Generate auth token for the session.
	token, err := generateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte(token))

	launcherID := testMACLauncherID(t, db)

	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// The coherent run/build authority read loads the persisted snapshot
	// rows of the directly seeded session; issue them for the fixture.
	insertTestSessionSnapshot(t, db, "sess-1", workspace)

	var cleanupOrder []string
	app.PinMountSourceFn = func(sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			PinnedPath: "/tmp/test-mount",
			cleanup: func() error {
				cleanupOrder = append(cleanupOrder, "pin_cleanup")
				return nil
			},
		}, nil
	}

	mountSource := filepath.Join(workspace, "src")
	if err := os.MkdirAll(mountSource, 0755); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/run",
		bytes.NewReader([]byte(`{"image":"alpine","mounts":[{"source":"src","target":"/mnt"}]}`)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}

	// Verify: pin cleanup was called (production code cleaned up pins).
	if len(cleanupOrder) != 1 || cleanupOrder[0] != "pin_cleanup" {
		t.Errorf("expected [pin_cleanup], got %v", cleanupOrder)
	}

	// Verify: lease was released after pin cleanup.
	mac.mu.Lock()
	leaseCount := len(mac.sessionUseLeases)
	mac.mu.Unlock()
	if leaseCount != 0 {
		t.Errorf("expected 0 leases after admit rejection, got %d", leaseCount)
	}
}

// TestAdmitRejectionBuildStagingBeforeLease drives handleBuild with
// admit rejection and verifies staging is cleaned up before the lease is released.
func TestAdmitRejectionBuildStagingBeforeLease(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	initializeTestDatabase(t, db)

	driver := newTestSessionMACDriver(LSMBackend("test"))
	mac := newSessionMACCoordinator(db, driver)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AllowedRoots:          []AllowedRootEntry{allowedRootEntry(dir)},
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
		Config:              cfg,
		DB:                  db,
		MACCoordinator:      mac,
		OperationSupervisor: newOperationSupervisor(),
	}

	// Force admit rejection.
	app.OperationSupervisor.beginShutdown()

	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Generate auth token for the session.
	token, err := generateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte(token))

	launcherID := testMACLauncherID(t, db)

	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// The coherent run/build authority read loads the persisted snapshot
	// rows of the directly seeded session; issue them for the fixture.
	insertTestSessionSnapshot(t, db, "sess-1", workspace)

	var cleanupCalled bool
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		stagingDir := t.TempDir()
		opDir := filepath.Join(stagingDir, opID)
		if err := os.MkdirAll(opDir, 0o700); err != nil {
			return nil, err
		}
		ctxDir := filepath.Join(opDir, "context")
		if err := os.MkdirAll(ctxDir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(ctxDir, dfrel), []byte("FROM scratch\n"), 0o644); err != nil {
			return nil, err
		}
		return &stagedBuildContext{
			ContextPath:    ctxDir,
			DockerfilePath: filepath.Join(ctxDir, dfrel),
			cleanupPath:    opDir,
			removeAll: func(path string) error {
				cleanupCalled = true
				return os.RemoveAll(path)
			},
		}, nil
	}

	reqBody := map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "test:latest",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}

	// Verify: staging cleanup was called.
	if !cleanupCalled {
		t.Error("staging cleanup must be called on admit rejection")
	}

	// Verify: lease was released after staging cleanup.
	mac.mu.Lock()
	leaseCount := len(mac.sessionUseLeases)
	mac.mu.Unlock()
	if leaseCount != 0 {
		t.Errorf("expected 0 leases after admit rejection, got %d", leaseCount)
	}
}

// =============================================================================
// SELinux durable coverage with real selinuxMACDriver
// =============================================================================

// selinuxSeam is an injectable mock selinuxFcontextManager for testing
// the real selinuxMACDriver path.
type selinuxSeam struct {
	coveringFcontexts []string // returned by listCoveringFcontexts
	fcontextErr       error    // returned by listCoveringFcontexts
	actualTypeErr     error    // returned by verifyActualType
	restoreconErr     error    // returned by restoreconTree
	ensureCalled      bool     // tracks whether ensureTreeFcontext was called
	ensureCreated     bool     // newlyCreated from ensureTreeFcontext
	ensureErr         error    // error from ensureTreeFcontext
	removeErr         error    // error from removeWorkspaceFcontext
}

func (s *selinuxSeam) listCoveringFcontexts(workspace string) ([]string, error) {
	if s.fcontextErr != nil {
		return nil, s.fcontextErr
	}
	return s.coveringFcontexts, nil
}

func (s *selinuxSeam) verifyActualType(workspace string) error {
	return s.actualTypeErr
}

func (s *selinuxSeam) restoreconTree(tree string, kind macBoundaryKind) error {
	return s.restoreconErr
}

func (s *selinuxSeam) ensureTreeFcontext(tree string, kind macBoundaryKind) (bool, error) {
	s.ensureCalled = true
	return s.ensureCreated, s.ensureErr
}

func (s *selinuxSeam) removeFcontextBoundary(boundary string, kind macBoundaryKind) error {
	return s.removeErr
}

func TestSELinuxRealDriverAncestorCorrectType(t *testing.T) {
	// Persistent ancestor + correct actual type -> verify succeeds.
	seam := &selinuxSeam{
		coveringFcontexts: []string{"/data"},
		actualTypeErr:     nil,
	}
	driver := &selinuxMACDriver{mgr: seam, treeKind: fakeTreeKindDirectory}

	cov, err := driver.verifyCoverage("/data/workspace")
	if err != nil {
		t.Fatalf("verifyCoverage should succeed: %v", err)
	}
	if cov.Boundary != "/data" {
		t.Errorf("expected boundary /data, got %s", cov.Boundary)
	}
}

func TestSELinuxRealDriverAncestorWrongType(t *testing.T) {
	// Persistent ancestor + wrong type -> verify fails.
	seam := &selinuxSeam{
		coveringFcontexts: []string{"/data"},
		actualTypeErr:     errors.New("wrong type"),
	}
	driver := &selinuxMACDriver{mgr: seam, treeKind: fakeTreeKindDirectory}

	_, err := driver.verifyCoverage("/data/workspace")
	if err == nil {
		t.Fatal("verifyCoverage should fail with wrong actual type")
	}
	if !strings.Contains(err.Error(), "incorrect") {
		t.Errorf("expected 'incorrect' in error, got: %v", err)
	}
}

func TestSELinuxRealDriverNoBoundaryCorrectXattrFails(t *testing.T) {
	// No persistent boundary + correct current xattr -> verify FAILS.
	// This is the key invariant: operator-compatible xattr alone is not durable.
	seam := &selinuxSeam{
		coveringFcontexts: nil,
		actualTypeErr:     nil, // correct type but no persistent boundary
	}
	driver := &selinuxMACDriver{mgr: seam, treeKind: fakeTreeKindDirectory}

	_, err := driver.verifyCoverage("/data/workspace")
	if err == nil {
		t.Fatal("verifyCoverage must fail when no persistent fcontext boundary exists")
	}
	if !strings.Contains(err.Error(), "no persistent") {
		t.Errorf("expected 'no persistent' in error, got: %v", err)
	}
}

func TestSELinuxRealDriverEnsureRepairsWrongType(t *testing.T) {
	// ensureCoverage with existing ancestor + restorecon/verify succeeds.
	seam := &selinuxSeam{
		coveringFcontexts: []string{"/data"},
		restoreconErr:     nil,
		actualTypeErr:     nil,
	}
	driver := &selinuxMACDriver{mgr: seam, treeKind: fakeTreeKindDirectory}

	cov, changed, err := driver.ensureCoverage("/data/workspace")
	if err != nil {
		t.Fatalf("ensureCoverage should succeed: %v", err)
	}
	if changed {
		t.Error("ensureCoverage should not report changed for existing boundary")
	}
	if cov.Boundary != "/data" {
		t.Errorf("expected boundary /data, got %s", cov.Boundary)
	}
}

func TestSELinuxRealDriverEnsureCreatesNewBoundary(t *testing.T) {
	// No existing boundary -> ensureCoverage creates new one.
	seam := &selinuxSeam{
		coveringFcontexts: nil,
		ensureCreated:     true,
		ensureErr:         nil,
	}
	driver := &selinuxMACDriver{mgr: seam, treeKind: fakeTreeKindDirectory}

	cov, changed, err := driver.ensureCoverage("/data/workspace")
	if err != nil {
		t.Fatalf("ensureCoverage should succeed: %v", err)
	}
	if !changed {
		t.Error("ensureCoverage should report changed for new boundary")
	}
	if cov.Boundary != "/data/workspace" {
		t.Errorf("expected boundary /data/workspace, got %s", cov.Boundary)
	}
}

func TestSELinuxOptNoExistingBoundaryFails(t *testing.T) {
	// workspace = /opt, no existing compatible boundary.
	// Expected: failure, ensureTreeFcontext is NOT called.
	seam := &selinuxSeam{
		coveringFcontexts: nil,
	}
	driver := &selinuxMACDriver{mgr: seam, treeKind: fakeTreeKindDirectory}

	_, _, err := driver.ensureCoverage("/opt")
	if err == nil {
		t.Fatal("ensureCoverage must fail for /opt with no existing boundary")
	}
	if !strings.Contains(err.Error(), "/opt") {
		t.Errorf("expected '/opt' in error, got: %v", err)
	}
	if seam.ensureCalled {
		t.Error("ensureTreeFcontext must NOT be called for /opt")
	}
}

func TestSELinuxOptExistingBoundarySucceeds(t *testing.T) {
	// workspace = /opt, compatible operator fcontext boundary already exists,
	// actual type verifies correctly.
	// Expected: coverage succeeds, Boundary == /opt, HelperOwned == false,
	// no new boundary is created.
	seam := &selinuxSeam{
		coveringFcontexts: []string{"/opt"},
		restoreconErr:     nil,
		actualTypeErr:     nil,
	}
	driver := &selinuxMACDriver{mgr: seam, treeKind: fakeTreeKindDirectory}

	cov, changed, err := driver.ensureCoverage("/opt")
	if err != nil {
		t.Fatalf("ensureCoverage should succeed with existing /opt boundary: %v", err)
	}
	if changed {
		t.Error("ensureCoverage should not report changed for existing boundary")
	}
	if cov.Boundary != "/opt" {
		t.Errorf("expected boundary /opt, got %s", cov.Boundary)
	}
	if cov.HelperOwned {
		t.Error("existing operator boundary must not be helper-owned")
	}
	if seam.ensureCalled {
		t.Error("ensureTreeFcontext must NOT be called when compatible boundary exists")
	}
}

func TestSELinuxReconcileCreatesDurableCoverage(t *testing.T) {
	// No persistent boundary -> ReconcileLiveSessions calls verifyCoverage (fails)
	// -> ensureCoverage (succeeds) -> durable coverage created.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}

	// Seam: no persistent boundary initially, ensureCoverage creates one.
	seam := &selinuxSeam{
		coveringFcontexts: nil,
		actualTypeErr:     nil,
		ensureCreated:     true,
		ensureErr:         nil,
	}
	driver := &selinuxMACDriver{mgr: seam, treeKind: fakeTreeKindDirectory}
	mac := newSessionMACCoordinator(db, driver)
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}

	// Insert a live session so ReconcileLiveSessions has something to reconcile.
	workspace := "/data/workspace"
	launcherID := testMACLauncherID(t, db)
	_, err = db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id) VALUES (?, ?, ?, ?, ?, ?)`,
		"sess-reconcile", "hash", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	insertTestSessionSnapshot(t, db, "sess-reconcile", workspace)

	// ReconcileLiveSessions must call verifyCoverage (fails) then ensureCoverage (succeeds).
	err = mac.ReconcileLiveSessions()
	if err != nil {
		t.Fatalf("ReconcileLiveSessions failed: %v", err)
	}

	// Verify: the session binding was created with the new boundary.
	mac.mu.Lock()
	binding, hasBinding := mac.sessionBindings["sess-reconcile"]
	active := mac.boundaryConsumerCounts[workspace]
	mac.mu.Unlock()

	if !hasBinding {
		t.Fatal("session binding must exist after reconciliation")
	}
	if len(binding) != 1 || binding[0].Boundary != workspace {
		t.Errorf("binding = %+v, want one coverage boundary %q", binding, workspace)
	}
	if active != 1 {
		t.Errorf("boundaryConsumerCounts = %d, want 1", active)
	}

	// Update seam to reflect the new boundary now exists.
	seam.coveringFcontexts = []string{workspace}

	// Verify: verifyCoverage now succeeds.
	cov, err := driver.verifyCoverage(workspace)
	if err != nil {
		t.Fatalf("verifyCoverage should succeed after reconciliation: %v", err)
	}
	if cov.Boundary != workspace {
		t.Errorf("expected boundary %s, got %s", workspace, cov.Boundary)
	}
}

// =============================================================================
// Atomic mac_boundaries migration test
// =============================================================================

func TestMACBoundariesAtomicMigration(t *testing.T) {
	// Start from the old schema: boundary TEXT PRIMARY KEY, backend TEXT NOT NULL
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	// Create the old schema manually.
	_, err = db.Exec(`
		CREATE TABLE mac_boundaries (
			boundary TEXT PRIMARY KEY,
			backend TEXT NOT NULL
		);
	`)
	if err != nil {
		t.Fatalf("create old schema: %v", err)
	}

	// Insert data into old schema.
	_, err = db.Exec(`INSERT INTO mac_boundaries (boundary, backend) VALUES ('/data/ws1', 'apparmor')`)
	if err != nil {
		t.Fatalf("insert old data: %v", err)
	}
	_, err = db.Exec(`INSERT INTO mac_boundaries (boundary, backend) VALUES ('/data/ws2', 'selinux')`)
	if err != nil {
		t.Fatalf("insert old data: %v", err)
	}

	// Run initializeDatabase which should migrate to new schema.
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase migration: %v", err)
	}

	// Verify data survived migration.
	var ws1Backend, ws2Backend string
	err = db.QueryRow(`SELECT backend FROM mac_boundaries WHERE boundary = '/data/ws1'`).Scan(&ws1Backend)
	if err != nil {
		t.Fatalf("query ws1: %v", err)
	}
	if ws1Backend != "apparmor" {
		t.Errorf("ws1 backend = %q, want 'apparmor'", ws1Backend)
	}

	err = db.QueryRow(`SELECT backend FROM mac_boundaries WHERE boundary = '/data/ws2'`).Scan(&ws2Backend)
	if err != nil {
		t.Fatalf("query ws2: %v", err)
	}
	if ws2Backend != "selinux" {
		t.Errorf("ws2 backend = %q, want 'selinux'", ws2Backend)
	}

	// Verify the final PK is (backend, boundary).
	var backendPK, boundaryPK int
	err = db.QueryRow(`SELECT pk FROM pragma_table_info('mac_boundaries') WHERE name = 'backend'`).Scan(&backendPK)
	if err != nil {
		t.Fatalf("query backend pk: %v", err)
	}
	err = db.QueryRow(`SELECT pk FROM pragma_table_info('mac_boundaries') WHERE name = 'boundary'`).Scan(&boundaryPK)
	if err != nil {
		t.Fatalf("query boundary pk: %v", err)
	}
	if backendPK == 0 {
		t.Error("backend should be part of PK")
	}
	if boundaryPK == 0 {
		t.Error("boundary should be part of PK")
	}
}

// =============================================================================
// Deferred stale-boundary cleanup from cleanupStaleBoundaries
// =============================================================================

func TestDeferredStaleBoundaryCleanup(t *testing.T) {
	// Construct an owned stale boundary that is NOT already in deferredBoundaries,
	// then prove cleanupStaleBoundaries itself adds it.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	if _, err := migrateSessionFilesystemSnapshots(db); err != nil {
		t.Fatalf("migrateSessionFilesystemSnapshots: %v", err)
	}

	driver := newTestSessionMACDriver(LSMBackend("test"))
	mac := newSessionMACCoordinator(db, driver)

	parentWS := "/data/parent"
	childWS := "/data/parent/child"

	// Create parent session binding (the only live consumer).
	_, err = mac.CreateSessionBinding("sess-parent", []string{parentWS}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(db, testMACLauncherID(t, db), "sess-parent", parentWS)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding parent: %v", err)
	}

	// Manually insert a child boundary into mac_boundaries so it is owned
	// by docker-helper but has no active consumer and is not in deferredBoundaries.
	_, err = db.Exec(`INSERT INTO mac_boundaries (backend, boundary) VALUES (?, ?)`,
		driver.backend(), childWS)
	if err != nil {
		t.Fatalf("insert child boundary: %v", err)
	}

	// Verify: child is NOT in deferredBoundaries before cleanupStaleBoundaries.
	mac.mu.Lock()
	childInDeferredBefore := mac.deferredBoundaries[childWS]
	mac.mu.Unlock()
	if childInDeferredBefore {
		t.Fatal("child must not be in deferredBoundaries before cleanupStaleBoundaries")
	}

	// Call cleanupStaleBoundaries: it must discover the orphaned child boundary
	// and register it as deferred because the parent still overlaps.
	err = mac.cleanupStaleBoundaries()
	if err != nil {
		t.Fatalf("cleanupStaleBoundaries: %v", err)
	}

	// Prove: cleanupStaleBoundaries added the child to deferredBoundaries.
	mac.mu.Lock()
	childInDeferredAfter := mac.deferredBoundaries[childWS]
	mac.mu.Unlock()
	if !childInDeferredAfter {
		t.Fatal("cleanupStaleBoundaries must add orphaned child to deferredBoundaries (parent overlaps)")
	}

	// Delete parent — this triggers retryDeferredBoundaries which should
	// clean up the deferred child boundary.
	mac.ReleaseSessionBinding("sess-parent")

	// Both boundaries should now be gone.
	mac.mu.Lock()
	parentDeferred := mac.deferredBoundaries[parentWS]
	childDeferred := mac.deferredBoundaries[childWS]
	mac.mu.Unlock()

	if parentDeferred {
		t.Error("parent should not be deferred after all consumers gone")
	}
	if childDeferred {
		t.Error("child should not be deferred after all consumers gone")
	}

	// Verify both boundaries were removed from driver.
	_, err = driver.verifyCoverage(parentWS)
	if err == nil {
		t.Error("parent boundary should be removed from driver")
	}
	_, err = driver.verifyCoverage(childWS)
	if err == nil {
		t.Error("child boundary should be removed from driver")
	}
}

// =============================================================================
// Principal disable/delete MAC binding release
// =============================================================================

func TestPrincipalDisableReleasesMACBindings(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create a principal.
	home := filepath.Join(allowedRoot, "home", "macdisuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1070", "1070", home, nil
	}

	if _, err := createPrincipal(app.DB, "macdisuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	principalID, err := findPrincipalIDByUsername(app.DB, "macdisuser")
	if err != nil {
		t.Fatalf("findPrincipalIDByUsername: %v", err)
	}
	launcherID := mustAddDefaultLauncher(t, app.DB, int64(principalID))

	// Create a session with MAC binding.
	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		_, err := app.DB.Exec(
			`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", "hash1", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID,
		)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Verify binding exists.
	mac.mu.Lock()
	_, hasBinding := mac.sessionBindings["sess-1"]
	mac.mu.Unlock()
	if !hasBinding {
		t.Fatal("session binding should exist")
	}

	// Disable principal via the production Principal lifecycle owner.
	result, err := app.disablePrincipalLaunchers("macdisuser")
	if err != nil {
		t.Fatalf("disablePrincipalLaunchers: %v", err)
	}
	if !result.Changed {
		t.Fatal("expected Changed=true")
	}
	if len(result.RevokedSessionIDs) != 1 {
		t.Fatalf("expected 1 revoked session, got %d", len(result.RevokedSessionIDs))
	}

	// Verify binding was released.
	mac.mu.Lock()
	_, hasBinding = mac.sessionBindings["sess-1"]
	count := mac.boundaryConsumerCounts[workspace]
	mac.mu.Unlock()
	if hasBinding {
		t.Error("session binding should be released after principal disable")
	}
	if count != 0 {
		t.Errorf("boundaryConsumerCounts should be 0, got %d", count)
	}

	// Verify boundary was removed from driver.
	_, err = driver.verifyCoverage(workspace)
	if err == nil {
		t.Error("boundary should be removed from driver after binding release")
	}
}

func TestPrincipalDeleteReleasesMACBindings(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create a principal.
	home := filepath.Join(allowedRoot, "home", "macdeluser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1071", "1071", home, nil
	}

	if _, err := createPrincipal(app.DB, "macdeluser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	principalID, err := findPrincipalIDByUsername(app.DB, "macdeluser")
	if err != nil {
		t.Fatalf("findPrincipalIDByUsername: %v", err)
	}
	launcherID := mustAddDefaultLauncher(t, app.DB, int64(principalID))

	// Create a session with MAC binding.
	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		_, err := app.DB.Exec(
			`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", "hash1", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID,
		)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Verify binding exists.
	mac.mu.Lock()
	_, hasBinding := mac.sessionBindings["sess-1"]
	mac.mu.Unlock()
	if !hasBinding {
		t.Fatal("session binding should exist")
	}

	// Delete principal via App-level lifecycle.
	sessionIDs, err := app.deletePrincipalWithMAC("macdeluser")
	if err != nil {
		t.Fatalf("deletePrincipalWithMAC: %v", err)
	}
	if len(sessionIDs) != 1 {
		t.Fatalf("expected 1 session ID, got %d", len(sessionIDs))
	}

	// Verify binding was released.
	mac.mu.Lock()
	_, hasBinding = mac.sessionBindings["sess-1"]
	count := mac.boundaryConsumerCounts[workspace]
	mac.mu.Unlock()
	if hasBinding {
		t.Error("session binding should be released after principal delete")
	}
	if count != 0 {
		t.Errorf("boundaryConsumerCounts should be 0, got %d", count)
	}

	// Verify boundary was removed from driver.
	_, err = driver.verifyCoverage(workspace)
	if err == nil {
		t.Error("boundary should be removed from driver after binding release")
	}
}

func TestPrincipalDisableLeasePreserved(t *testing.T) {
	// Session has MAC binding, operation acquires session-use lease,
	// principal disable removes session, boundary NOT removed while lease exists,
	// lease release allows boundary removal.
	app, mac, driver := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create a principal.
	home := filepath.Join(allowedRoot, "home", "leaseuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1072", "1072", home, nil
	}

	if _, err := createPrincipal(app.DB, "leaseuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	principalID, err := findPrincipalIDByUsername(app.DB, "leaseuser")
	if err != nil {
		t.Fatalf("findPrincipalIDByUsername: %v", err)
	}
	launcherID := mustAddDefaultLauncher(t, app.DB, int64(principalID))

	// Create a session with MAC binding.
	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		_, err := app.DB.Exec(
			`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", "hash1", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID,
		)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Operation acquires session-use lease.
	_, leaseRelease, err := mac.AcquireSessionUse("sess-1", workspace)
	if err != nil {
		t.Fatalf("AcquireSessionUse: %v", err)
	}

	// Verify boundary count is 2 (session + operation lease).
	mac.mu.Lock()
	count := mac.boundaryConsumerCounts[workspace]
	mac.mu.Unlock()
	if count != 2 {
		t.Fatalf("expected boundaryConsumerCounts=2, got %d", count)
	}

	// Disable principal via the production Principal lifecycle owner — removes
	// the session binding while the session-use lease keeps holding.
	result, err := app.disablePrincipalLaunchers("leaseuser")
	if err != nil {
		t.Fatalf("disablePrincipalLaunchers: %v", err)
	}
	if !result.Changed {
		t.Fatal("expected Changed=true")
	}

	// Boundary count should be 1 (only operation lease remains).
	mac.mu.Lock()
	count = mac.boundaryConsumerCounts[workspace]
	mac.mu.Unlock()
	if count != 1 {
		t.Errorf("expected boundaryConsumerCounts=1 after session release, got %d", count)
	}

	// Boundary should NOT be removed from driver (lease still active).
	_, err = driver.verifyCoverage(workspace)
	if err != nil {
		t.Errorf("boundary should still exist while lease is active: %v", err)
	}

	// Operation completes: release lease.
	leaseRelease()

	// Boundary should now be removed.
	mac.mu.Lock()
	count = mac.boundaryConsumerCounts[workspace]
	mac.mu.Unlock()
	if count != 0 {
		t.Errorf("expected boundaryConsumerCounts=0 after lease release, got %d", count)
	}

	// Verify boundary was removed from driver.
	_, err = driver.verifyCoverage(workspace)
	if err == nil {
		t.Error("boundary should be removed from driver after lease release")
	}
}

func TestPrincipalDeleteLeasePreserved(t *testing.T) {
	// Same as TestPrincipalDisableLeasePreserved but for delete.
	app, mac, driver := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create a principal.
	home := filepath.Join(allowedRoot, "home", "leasedeluser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1073", "1073", home, nil
	}

	if _, err := createPrincipal(app.DB, "leasedeluser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	principalID, err := findPrincipalIDByUsername(app.DB, "leasedeluser")
	if err != nil {
		t.Fatalf("findPrincipalIDByUsername: %v", err)
	}
	launcherID := mustAddDefaultLauncher(t, app.DB, int64(principalID))

	// Create a session with MAC binding.
	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		_, err := app.DB.Exec(
			`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", "hash1", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID,
		)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Operation acquires session-use lease.
	_, leaseRelease, err := mac.AcquireSessionUse("sess-1", workspace)
	if err != nil {
		t.Fatalf("AcquireSessionUse: %v", err)
	}

	// Delete principal — removes session binding.
	_, err = app.deletePrincipalWithMAC("leasedeluser")
	if err != nil {
		t.Fatalf("deletePrincipalWithMAC: %v", err)
	}

	// Boundary count should be 1 (only operation lease remains).
	mac.mu.Lock()
	count := mac.boundaryConsumerCounts[workspace]
	mac.mu.Unlock()
	if count != 1 {
		t.Errorf("expected boundaryConsumerCounts=1 after session release, got %d", count)
	}

	// Boundary should NOT be removed from driver (lease still active).
	_, err = driver.verifyCoverage(workspace)
	if err != nil {
		t.Errorf("boundary should still exist while lease is active: %v", err)
	}

	// Operation completes: release lease.
	leaseRelease()

	// Boundary should now be removed.
	mac.mu.Lock()
	count = mac.boundaryConsumerCounts[workspace]
	mac.mu.Unlock()
	if count != 0 {
		t.Errorf("expected boundaryConsumerCounts=0 after lease release, got %d", count)
	}

	// Verify boundary was actually removed from driver.
	_, err = driver.verifyCoverage(workspace)
	if err == nil {
		t.Error("boundary should be removed from driver after lease release")
	}
}

func TestSharedBoundaryAccounting(t *testing.T) {
	// Two sessions on the same boundary, principal delete removes both,
	// boundary accounting remains correct.
	app, mac, driver := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0].Path
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create a principal.
	home := filepath.Join(allowedRoot, "home", "shareduser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1074", "1074", home, nil
	}

	if _, err := createPrincipal(app.DB, "shareduser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	principalID, err := findPrincipalIDByUsername(app.DB, "shareduser")
	if err != nil {
		t.Fatalf("findPrincipalIDByUsername: %v", err)
	}
	launcherID := mustAddDefaultLauncher(t, app.DB, int64(principalID))

	// Create two sessions on the same workspace boundary.
	_, err = mac.CreateSessionBinding("sess-1", []string{workspace}, func([]sessionMACCoverage) error {
		_, err := app.DB.Exec(
			`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", "hash1", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID,
		)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding sess-1: %v", err)
	}

	_, err = mac.CreateSessionBinding("sess-2", []string{workspace}, func([]sessionMACCoverage) error {
		_, err := app.DB.Exec(
			`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-2", "hash2", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID,
		)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding sess-2: %v", err)
	}

	// Verify boundary count is 2 (two sessions).
	mac.mu.Lock()
	count := mac.boundaryConsumerCounts[workspace]
	mac.mu.Unlock()
	if count != 2 {
		t.Fatalf("expected boundaryConsumerCounts=2, got %d", count)
	}

	// Delete principal — removes both sessions.
	sessionIDs, err := app.deletePrincipalWithMAC("shareduser")
	if err != nil {
		t.Fatalf("deletePrincipalWithMAC: %v", err)
	}
	if len(sessionIDs) != 2 {
		t.Fatalf("expected 2 session IDs, got %d", len(sessionIDs))
	}

	// Boundary count should be 0 (both sessions released).
	mac.mu.Lock()
	count = mac.boundaryConsumerCounts[workspace]
	mac.mu.Unlock()
	if count != 0 {
		t.Errorf("expected boundaryConsumerCounts=0, got %d", count)
	}

	// Verify boundary was removed from driver.
	_, err = driver.verifyCoverage(workspace)
	if err == nil {
		t.Error("boundary should be removed from driver after all bindings released")
	}
}

// =============================================================================
// Stale-auth Session creation race regression
// =============================================================================

func TestStaleAuthSessionCreationRace(t *testing.T) {
	// Regression test: a Principal credential is authenticated while the
	// Principal is enabled, the Principal is then disabled, and a Session
	// creation attempt is made with the previously authenticated authority.
	// Authentication identity may be stale, but policy is never supplied by
	// the caller: createSessionAuthorized resolves it through the current
	// production owner (resolveCreatePolicy), so the canonical resolver
	// observes the current durable enabled state and refuses with the
	// established typed result. No Session row; no MAC binding; no
	// helper-owned boundary.
	app, mac, driver := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0].Path

	// Create a principal.
	home := filepath.Join(allowedRoot, "home", "staleauthuser")
	projDir := filepath.Join(home, "proj")
	if err := os.MkdirAll(projDir, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1080", "1080", home, nil
	}

	if _, err := createPrincipal(app.DB, "staleauthuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}

	// Create a credential for the principal.
	_, token, err := createPrincipalCredential(app.DB, "staleauthuser", "test-cred")
	if err != nil {
		t.Fatalf("createCredential: %v", err)
	}

	// Authenticate the credential while the principal is enabled: the resulting
	// authority is authentication identity only and may go stale.
	auth, err := authenticateCredential(app.DB, token)
	if err != nil {
		t.Fatalf("authenticateCredential: %v", err)
	}
	if auth.Principal == nil {
		t.Fatal("expected a Principal credential auth result")
	}

	// Disable the principal through the production Principal lifecycle owner
	// (simulates a concurrent disable after authentication).
	result, err := app.disablePrincipalLaunchers("staleauthuser")
	if err != nil {
		t.Fatalf("disablePrincipalLaunchers: %v", err)
	}
	if !result.Changed {
		t.Fatal("expected Changed=true")
	}

	// Record binding count before the failed creation attempt.
	mac.mu.Lock()
	bindingsBefore := len(mac.sessionBindings)
	mac.mu.Unlock()

	// Attempt Session creation with the stale authenticated authority through
	// the canonical production owner. No policy is supplied: the current
	// production resolver observes the disabled Principal and refuses with the
	// typed stale-owner contract instead of accepting a precomputed root
	// scope that no longer matches durable policy.
	_, err = app.createSessionAuthorized(
		&operatorAuthority{class: operatorAuthorityPrincipal, principal: auth.Principal},
		createSelector{},
		projDir,
		nil,
	)
	if !errors.Is(err, ErrLauncherUnavailable) {
		t.Fatalf("expected ErrLauncherUnavailable for stale disabled principal, got %v", err)
	}

	// Verify no Session row was created.
	var count int
	err = app.DB.QueryRow(
		`SELECT COUNT(*) FROM sessions WHERE workspace = ?`,
		projDir,
	).Scan(&count)
	if err != nil {
		t.Fatalf("query session: %v", err)
	}
	if count != 0 {
		t.Error("no Session row should exist for disabled principal")
	}

	// Verify no new MAC binding was left behind (rollback occurred).
	mac.mu.Lock()
	bindingsAfter := len(mac.sessionBindings)
	mac.mu.Unlock()

	if bindingsAfter != bindingsBefore {
		t.Errorf("MAC bindings leaked after failed session creation: before=%d after=%d",
			bindingsBefore, bindingsAfter)
	}

	// Verify no boundary was created (rollback occurred).
	_, err = driver.verifyCoverage(projDir)
	if err == nil {
		t.Error("boundary should not exist after failed session creation")
	}
}

// fakeTreeKindDirectory classifies every issued tree as a directory for the
// coordinator driver tests that do not exercise real path kinds.
func fakeTreeKindDirectory(string) (macBoundaryKind, error) {
	return macBoundaryDirectory, nil
}
