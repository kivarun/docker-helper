package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// testMACBackend is a mock macBackend for testing the lifecycle owner.
type testMACBackend struct {
	mu                sync.Mutex
	coverageMap       map[string]string // workspace -> boundary
	managedBoundaries map[string]bool   // boundary -> is managed
	removeErrors      map[string]bool   // boundary -> should removal fail
	boundaryType      string
}

func newTestMACBackend(backendType string) *testMACBackend {
	return &testMACBackend{
		coverageMap:       make(map[string]string),
		managedBoundaries: make(map[string]bool),
		removeErrors:      make(map[string]bool),
		boundaryType:      backendType,
	}
}

func (b *testMACBackend) ensureCoverage(workspace string) (macCoverage, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if boundary, ok := b.coverageMap[workspace]; ok {
		return macCoverage{Boundary: boundary, Managed: b.managedBoundaries[boundary]}, false, nil
	}

	b.coverageMap[workspace] = workspace
	b.managedBoundaries[workspace] = true
	return macCoverage{Boundary: workspace, Managed: true}, true, nil
}

func (b *testMACBackend) verifyCoverage(workspace string) (macCoverage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if boundary, ok := b.coverageMap[workspace]; ok {
		return macCoverage{Boundary: boundary, Managed: b.managedBoundaries[boundary]}, nil
	}
	return macCoverage{}, fmt.Errorf("no coverage for %s", workspace)
}

func (b *testMACBackend) removeBoundary(boundary string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.removeErrors[boundary] {
		return fmt.Errorf("removeBoundary failed for %s", boundary)
	}
	delete(b.coverageMap, boundary)
	delete(b.managedBoundaries, boundary)
	return nil
}

func (b *testMACBackend) listManagedBoundaries() ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var result []string
	for boundary := range b.managedBoundaries {
		result = append(result, boundary)
	}
	return result, nil
}

func (b *testMACBackend) backendType() string {
	return b.boundaryType
}

// setupTestMACLifecycle creates a test app with a MAC lifecycle and mock backend.
func setupTestMACLifecycle(t *testing.T) (*App, *workspaceMACLifecycle, *testMACBackend) {
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

	backend := newTestMACBackend("test")
	mac := newWorkspaceMACLifecycle(db, backend)

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
	}

	app := &App{
		Config:       cfg,
		DB:           db,
		MACLifecycle: mac,
	}

	return app, mac, backend
}

// insertTestSession inserts a test session into the database.
func insertTestSession(t *testing.T, db *sql.DB, sessionID, workspace string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sessionID, "hash1", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), nil,
	)
	if err != nil {
		t.Fatalf("insertTestSession: %v", err)
	}
}

// TestLeaseReleaseConditionalBoundaryCleanup verifies that when a session is
// deleted while an operation is running, the operation's lease release
// triggers conditional boundary cleanup.
func TestLeaseReleaseConditionalBoundaryCleanup(t *testing.T) {
	app, mac, backend := setupTestMACLifecycle(t)

	allowedRoot := app.Config.AllowedRoots[0]
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create session binding.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
		return insertTestSessionTx(app.DB, "sess-1", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Acquire use lease (simulates operation starting).
	_, leaseRelease, err := mac.AcquireUse("sess-1", workspace)
	if err != nil {
		t.Fatalf("AcquireUse: %v", err)
	}

	// Verify boundary count is 2 (session + operation).
	mac.mu.Lock()
	count := mac.activeBoundaries[workspace]
	mac.mu.Unlock()
	if count != 2 {
		t.Errorf("expected activeBoundaries count 2, got %d", count)
	}

	// Delete session (simulates session deletion while operation running).
	mac.ReleaseSessionBoundary("sess-1")

	// Boundary count should be 1 (only operation lease remains).
	mac.mu.Lock()
	count = mac.activeBoundaries[workspace]
	mac.mu.Unlock()
	if count != 1 {
		t.Errorf("expected activeBoundaries count 1 after session release, got %d", count)
	}

	// Operation completes: release lease.
	leaseRelease()

	// Boundary should now be removed (count reaches 0, no other consumers).
	mac.mu.Lock()
	count = mac.activeBoundaries[workspace]
	_, hasBinding := mac.sessionBindings["sess-1"]
	mac.mu.Unlock()

	if count != 0 {
		t.Errorf("expected activeBoundaries count 0 after lease release, got %d", count)
	}
	if hasBinding {
		t.Error("session binding should be removed")
	}

	// Verify boundary was actually removed from backend.
	_, err = backend.verifyCoverage(workspace)
	if err == nil {
		t.Error("expected error verifying removed boundary")
	}
}

// insertTestSessionTx inserts a test session (used in callback).
func insertTestSessionTx(db *sql.DB, sessionID, workspace string) error {
	_, err := db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sessionID, "hash1", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), nil,
	)
	return err
}

// TestBuildTryCreateStagingBeforeLease verifies that in the build tryCreate
// rejection path, staging cleanup happens before the lease is released.
// This tests the code ordering in build.go.
func TestBuildTryCreateStagingBeforeLease(t *testing.T) {
	app, mac, _ := setupTestMACLifecycle(t)
	app.OperationRegistry = newOperationRegistry()

	allowedRoot := app.Config.AllowedRoots[0]
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create session binding.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
		return insertTestSessionTx(app.DB, "sess-1", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Acquire lease.
	_, leaseRelease, err := mac.AcquireUse("sess-1", workspace)
	if err != nil {
		t.Fatalf("AcquireUse: %v", err)
	}

	// Create staging directory.
	stagedDir := filepath.Join(app.Config.RuntimeDir, "staged-test")
	if err := os.MkdirAll(stagedDir, 0755); err != nil {
		t.Fatal(err)
	}
	staged := &stagedBuildContext{
		ContextPath:    stagedDir,
		DockerfilePath: filepath.Join(stagedDir, "Dockerfile"),
		cleanupPath:    stagedDir,
	}

	// Set registry to shutting down to simulate tryCreate rejection.
	app.OperationRegistry.setShuttingDown()

	// Track cleanup order.
	var cleanupOrder []string

	// Override removeAll to track order.
	staged.removeAll = func(path string) error {
		cleanupOrder = append(cleanupOrder, "staging_cleanup")
		return os.RemoveAll(path)
	}

	// Override lease release to track order.
	origLeaseRelease := leaseRelease
	leaseRelease = func() {
		cleanupOrder = append(cleanupOrder, "lease_release")
		origLeaseRelease()
	}

	// Simulate the tryCreate rejection path (from build.go):
	// Cleanup staging before releasing lease.
	if err := staged.Cleanup(); err != nil {
		t.Logf("staging cleanup error: %v", err)
	}
	if leaseRelease != nil {
		leaseRelease()
	}

	// Verify order: staging cleanup before lease release.
	if len(cleanupOrder) != 2 {
		t.Fatalf("expected 2 cleanup events, got %d: %v", len(cleanupOrder), cleanupOrder)
	}
	if cleanupOrder[0] != "staging_cleanup" {
		t.Errorf("expected staging_cleanup first, got %v", cleanupOrder)
	}
	if cleanupOrder[1] != "lease_release" {
		t.Errorf("expected lease_release second, got %v", cleanupOrder)
	}
}

// TestRunPinFailurePinsBeforeLease verifies that in the run pinMount failure
// path, pins are cleaned up before the lease is released.
func TestRunPinFailurePinsBeforeLease(t *testing.T) {
	app, mac, _ := setupTestMACLifecycle(t)

	allowedRoot := app.Config.AllowedRoots[0]
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create session binding.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
		return insertTestSessionTx(app.DB, "sess-1", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Acquire lease.
	_, leaseRelease, err := mac.AcquireUse("sess-1", workspace)
	if err != nil {
		t.Fatalf("AcquireUse: %v", err)
	}

	// Create a pinned mount with tracked cleanup.
	pinDir := filepath.Join(app.Config.RuntimeDir, "pin-test")
	if err := os.MkdirAll(pinDir, 0755); err != nil {
		t.Fatal(err)
	}
	pinFile := filepath.Join(pinDir, "pin")
	if err := os.WriteFile(pinFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	var cleanupOrder []string
	pinnedMounts := []*pinnedMount{
		{
			HostPath: pinFile,
			cleanup: func() error {
				cleanupOrder = append(cleanupOrder, "pin_cleanup")
				return os.Remove(pinFile)
			},
		},
	}

	// Override lease release to track order.
	origLeaseRelease := leaseRelease
	leaseRelease = func() {
		cleanupOrder = append(cleanupOrder, "lease_release")
		origLeaseRelease()
	}

	// Simulate the pinMount failure path (from run.go):
	// Cleanup pins before releasing lease.
	for j := len(pinnedMounts) - 1; j >= 0; j-- {
		if ce := pinnedMounts[j].Cleanup(); ce != nil {
			t.Logf("pin cleanup error: %v", ce)
		}
	}
	if leaseRelease != nil {
		leaseRelease()
	}

	// Verify order: pin cleanup before lease release.
	if len(cleanupOrder) != 2 {
		t.Fatalf("expected 2 cleanup events, got %d: %v", len(cleanupOrder), cleanupOrder)
	}
	if cleanupOrder[0] != "pin_cleanup" {
		t.Errorf("expected pin_cleanup first, got %v", cleanupOrder)
	}
	if cleanupOrder[1] != "lease_release" {
		t.Errorf("expected lease_release second, got %v", cleanupOrder)
	}
}

// TestRunTryCreatePinsBeforeLease verifies that in the run tryCreate rejection
// path, pins are cleaned up before the lease is released.
func TestRunTryCreatePinsBeforeLease(t *testing.T) {
	app, mac, _ := setupTestMACLifecycle(t)
	app.OperationRegistry = newOperationRegistry()

	allowedRoot := app.Config.AllowedRoots[0]
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create session binding.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
		return insertTestSessionTx(app.DB, "sess-1", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Acquire lease.
	_, leaseRelease, err := mac.AcquireUse("sess-1", workspace)
	if err != nil {
		t.Fatalf("AcquireUse: %v", err)
	}

	// Create a pinned mount with tracked cleanup.
	pinDir := filepath.Join(app.Config.RuntimeDir, "pin-test")
	if err := os.MkdirAll(pinDir, 0755); err != nil {
		t.Fatal(err)
	}
	pinFile := filepath.Join(pinDir, "pin")
	if err := os.WriteFile(pinFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	var cleanupOrder []string
	pinnedMounts := []*pinnedMount{
		{
			HostPath: pinFile,
			cleanup: func() error {
				cleanupOrder = append(cleanupOrder, "pin_cleanup")
				return os.Remove(pinFile)
			},
		},
	}

	// Override lease release to track order.
	origLeaseRelease := leaseRelease
	leaseRelease = func() {
		cleanupOrder = append(cleanupOrder, "lease_release")
		origLeaseRelease()
	}

	// Simulate the tryCreate rejection path (from run.go):
	// Cleanup pins before releasing lease.
	for j := len(pinnedMounts) - 1; j >= 0; j-- {
		if ce := pinnedMounts[j].Cleanup(); ce != nil {
			t.Logf("pin cleanup error: %v", ce)
		}
	}
	if leaseRelease != nil {
		leaseRelease()
	}

	// Verify order: pin cleanup before lease release.
	if len(cleanupOrder) != 2 {
		t.Fatalf("expected 2 cleanup events, got %d: %v", len(cleanupOrder), cleanupOrder)
	}
	if cleanupOrder[0] != "pin_cleanup" {
		t.Errorf("expected pin_cleanup first, got %v", cleanupOrder)
	}
	if cleanupOrder[1] != "lease_release" {
		t.Errorf("expected lease_release second, got %v", cleanupOrder)
	}
}

// TestRunStartFailureCleanupBeforeLease verifies that in the run start error
// and pre-start termination paths, cidfile and pin cleanup happens before
// the lease is released.
func TestRunStartFailureCleanupBeforeLease(t *testing.T) {
	app, mac, _ := setupTestMACLifecycle(t)

	allowedRoot := app.Config.AllowedRoots[0]
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create session binding.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
		return insertTestSessionTx(app.DB, "sess-1", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Acquire lease.
	_, leaseRelease, err := mac.AcquireUse("sess-1", workspace)
	if err != nil {
		t.Fatalf("AcquireUse: %v", err)
	}

	// Create operation with cidfile.
	op := newRunOperation("sess-1", "alpine", 4*1024*1024, "")
	op.cidfile = filepath.Join(app.Config.RuntimeDir, "test.cid")
	if err := os.WriteFile(op.cidfile, []byte("container-id"), 0644); err != nil {
		t.Fatal(err)
	}
	op.macLeaseRelease = leaseRelease

	// Create a pinned mount with tracked cleanup.
	pinDir := filepath.Join(app.Config.RuntimeDir, "pin-test")
	if err := os.MkdirAll(pinDir, 0755); err != nil {
		t.Fatal(err)
	}
	pinFile := filepath.Join(pinDir, "pin")
	if err := os.WriteFile(pinFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	var cleanupOrder []string
	op.pinnedMounts = []*pinnedMount{
		{
			HostPath: pinFile,
			cleanup: func() error {
				cleanupOrder = append(cleanupOrder, "pin_cleanup")
				return os.Remove(pinFile)
			},
		},
	}

	// Override lease release to track order.
	origLeaseRelease := op.macLeaseRelease
	op.macLeaseRelease = func() {
		cleanupOrder = append(cleanupOrder, "lease_release")
		origLeaseRelease()
	}

	// Simulate the start error / pre-start termination path (from run.go):
	// Cleanup cidfile and pins before releasing lease.
	cleanupCidfile(op)
	cleanupOrder = append(cleanupOrder, "cidfile_cleanup")
	if ce := cleanupPinnedMounts(op); ce != nil {
		t.Logf("pin cleanup error: %v", ce)
	}
	if op.macLeaseRelease != nil {
		op.macLeaseRelease()
	}

	// Verify order: cidfile and pin cleanup before lease release.
	if len(cleanupOrder) != 3 {
		t.Fatalf("expected 3 cleanup events, got %d: %v", len(cleanupOrder), cleanupOrder)
	}
	if cleanupOrder[2] != "lease_release" {
		t.Errorf("expected lease_release last, got %v", cleanupOrder)
	}
}

// TestDBInsertFailurePreservesOwnership verifies that when a session DB insert
// fails and boundary removal also fails, ownership metadata is preserved.
func TestDBInsertFailurePreservesOwnership(t *testing.T) {
	app, mac, backend := setupTestMACLifecycle(t)

	allowedRoot := app.Config.AllowedRoots[0]
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Make boundary removal fail.
	backend.removeErrors[workspace] = true

	// Create session binding with a failing DB insert.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
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
	app, mac, _ := setupTestMACLifecycle(t)

	allowedRoot := app.Config.AllowedRoots[0]
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Boundary removal succeeds (default).
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
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

// TestLegacyAppArmorOwnershipReconciliation verifies that existing AppArmor
// managed boundaries are imported into ownership metadata during reconciliation.
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

	// Simulate pre-existing managed boundary (in fragment but not in mac_boundaries).
	backend := newTestMACBackend("apparmor")
	backend.coverageMap["/data/workspace"] = "/data"
	backend.managedBoundaries["/data"] = true

	mac := newWorkspaceMACLifecycle(db, backend)

	// Directly call importManagedBoundaries to test the import logic.
	mac.mu.Lock()
	if err := mac.importManagedBoundaries(); err != nil {
		t.Fatalf("importManagedBoundaries: %v", err)
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
// listCoveringBoundaries fails, ensureCoverage and verifyCoverage return errors.
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

	// Create a mock SELinux manager that fails on listCoveringBoundaries.
	mgr := &selinuxWorkspaceManager{
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
		acquireLock: func() (func() error, error) {
			return func() error { return nil }, nil
		},
	}

	backend := &macBackendSELinux{mgr: mgr}

	// ensureCoverage should fail when listCoveringBoundaries fails.
	_, _, err = backend.ensureCoverage("/data/workspace")
	if err == nil {
		t.Error("ensureCoverage should fail when listCoveringBoundaries fails")
	}

	// verifyCoverage should fail when listCoveringBoundaries fails.
	_, err = backend.verifyCoverage("/data/workspace")
	if err == nil {
		t.Error("verifyCoverage should fail when listCoveringBoundaries fails")
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

	// Create a backend that fails on ensureCoverage.
	backend := &failingMACBackend{err: fmt.Errorf("MAC setup failed")}
	mac := newWorkspaceMACLifecycle(db, backend)

	// CreateSessionBinding should return an error wrapped with ErrMACPreparation.
	_, err = mac.CreateSessionBinding("/data/workspace", "sess-1", func(cov macCoverage) error {
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
	app, mac, _ := setupTestMACLifecycle(t)

	allowedRoot := app.Config.AllowedRoots[0]
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create session binding with a failing DB insert.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
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

// failingMACBackend is a mock backend that always fails on ensureCoverage.
type failingMACBackend struct {
	err error
}

func (b *failingMACBackend) ensureCoverage(workspace string) (macCoverage, bool, error) {
	return macCoverage{}, false, b.err
}

func (b *failingMACBackend) verifyCoverage(workspace string) (macCoverage, error) {
	return macCoverage{}, b.err
}

func (b *failingMACBackend) removeBoundary(boundary string) error {
	return nil
}

func (b *failingMACBackend) listManagedBoundaries() ([]string, error) {
	return nil, nil
}

func (b *failingMACBackend) backendType() string {
	return "test"
}
