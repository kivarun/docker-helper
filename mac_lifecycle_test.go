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

// testWorkspaceMACDriver is a mock workspaceMACDriver for testing the coordinator.
type testWorkspaceMACDriver struct {
	mu                    sync.Mutex
	coverageMap           map[string]string // workspace -> boundary
	helperOwnedBoundaries map[string]bool   // boundary -> is helper-owned
	removeErrors          map[string]bool   // boundary -> should removal fail
	boundaryType          string
}

func newTestWorkspaceMACDriver(backendType string) *testWorkspaceMACDriver {
	return &testWorkspaceMACDriver{
		coverageMap:           make(map[string]string),
		helperOwnedBoundaries: make(map[string]bool),
		removeErrors:          make(map[string]bool),
		boundaryType:          backendType,
	}
}

func (b *testWorkspaceMACDriver) ensureCoverage(workspace string) (workspaceMACCoverage, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if boundary, ok := b.coverageMap[workspace]; ok {
		return workspaceMACCoverage{Boundary: boundary, HelperOwned: b.helperOwnedBoundaries[boundary]}, false, nil
	}

	b.coverageMap[workspace] = workspace
	b.helperOwnedBoundaries[workspace] = true
	return workspaceMACCoverage{Boundary: workspace, HelperOwned: true}, true, nil
}

func (b *testWorkspaceMACDriver) verifyCoverage(workspace string) (workspaceMACCoverage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if boundary, ok := b.coverageMap[workspace]; ok {
		return workspaceMACCoverage{Boundary: boundary, HelperOwned: b.helperOwnedBoundaries[boundary]}, nil
	}
	return workspaceMACCoverage{}, fmt.Errorf("no coverage for %s", workspace)
}

func (b *testWorkspaceMACDriver) removeBoundary(boundary string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.removeErrors[boundary] {
		return fmt.Errorf("removeBoundary failed for %s", boundary)
	}
	delete(b.coverageMap, boundary)
	delete(b.helperOwnedBoundaries, boundary)
	return nil
}

func (b *testWorkspaceMACDriver) discoverHelperOwnedBoundaries() ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var result []string
	for boundary := range b.helperOwnedBoundaries {
		result = append(result, boundary)
	}
	return result, nil
}

func (b *testWorkspaceMACDriver) backendType() string {
	return b.boundaryType
}

// setupTestMACCoordinator creates a test app with a MAC coordinator and mock driver.
func setupTestMACCoordinator(t *testing.T) (*App, *sessionMACCoordinator, *testWorkspaceMACDriver) {
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

	driver := newTestWorkspaceMACDriver("test")
	mac := newSessionMACCoordinator(db, driver)

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
		Config:         cfg,
		DB:             db,
		MACCoordinator: mac,
	}

	return app, mac, driver
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
	app, mac, driver := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0]
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create session binding.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
		return insertTestSessionTx(app.DB, "sess-1", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Acquire use lease (simulates operation starting).
	_, leaseRelease, err := mac.AcquireWorkspaceUse("sess-1", workspace)
	if err != nil {
		t.Fatalf("AcquireWorkspaceUse: %v", err)
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

// insertTestSessionTx inserts a test session (used in callback).
func insertTestSessionTx(db *sql.DB, sessionID, workspace string) error {
	tokenHash := fmt.Sprintf("hash_%s", sessionID)
	_, err := db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sessionID, tokenHash, workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), nil,
	)
	return err
}

// TestDBInsertFailurePreservesOwnership verifies that when a session DB insert
// fails and boundary removal also fails, ownership metadata is preserved.
func TestDBInsertFailurePreservesOwnership(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0]
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Make boundary removal fail.
	driver.removeErrors[workspace] = true

	// Create session binding with a failing DB insert.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
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

	allowedRoot := app.Config.AllowedRoots[0]
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Boundary removal succeeds (default).
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
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

	// Simulate pre-existing helper-owned boundary (in fragment but not in mac_boundaries).
	driver := newTestWorkspaceMACDriver("apparmor")
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
		acquireLock: func() (func() error, error) {
			return func() error { return nil }, nil
		},
	}

	driver := &selinuxWorkspaceMACDriver{mgr: mgr}

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

	// Create a driver that fails on ensureCoverage.
	driver := &failingWorkspaceMACDriver{err: fmt.Errorf("MAC setup failed")}
	mac := newSessionMACCoordinator(db, driver)

	// CreateSessionBinding should return an error wrapped with ErrMACPreparation.
	_, err = mac.CreateSessionBinding("/data/workspace", "sess-1", func(cov workspaceMACCoverage) error {
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

	allowedRoot := app.Config.AllowedRoots[0]
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create session binding with a failing DB insert.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
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

// failingWorkspaceMACDriver is a mock driver that always fails on ensureCoverage.
type failingWorkspaceMACDriver struct {
	err error
}

func (b *failingWorkspaceMACDriver) ensureCoverage(workspace string) (workspaceMACCoverage, bool, error) {
	return workspaceMACCoverage{}, false, b.err
}

func (b *failingWorkspaceMACDriver) verifyCoverage(workspace string) (workspaceMACCoverage, error) {
	return workspaceMACCoverage{}, b.err
}

func (b *failingWorkspaceMACDriver) removeBoundary(boundary string) error {
	return nil
}

func (b *failingWorkspaceMACDriver) discoverHelperOwnedBoundaries() ([]string, error) {
	return nil, nil
}

func (b *failingWorkspaceMACDriver) backendType() string {
	return "test"
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

func (b *selinuxTestDriver) ensureCoverage(workspace string) (workspaceMACCoverage, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if boundaries, ok := b.coveringFcontexts[workspace]; ok && len(boundaries) > 0 {
		// Existing compatible coverage: run restorecon and verify actual type.
		if b.restoreconFail {
			return workspaceMACCoverage{}, false, fmt.Errorf("restorecon failed for %s", workspace)
		}
		b.restoreconCalls++
		if b.verifyActualTypeFail {
			return workspaceMACCoverage{}, false, fmt.Errorf("actual type verification failed for %s", workspace)
		}
		return workspaceMACCoverage{Boundary: boundaries[0], HelperOwned: false}, false, nil
	}

	// No existing coverage: create new boundary.
	return workspaceMACCoverage{Boundary: workspace, HelperOwned: true}, true, nil
}

func (b *selinuxTestDriver) verifyCoverage(workspace string) (workspaceMACCoverage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if boundaries, ok := b.coveringFcontexts[workspace]; ok && len(boundaries) > 0 {
		// Boundary exists — verify actual on-disk type.
		if b.verifyActualTypeFail {
			return workspaceMACCoverage{}, fmt.Errorf("existing SELinux boundary %s exists but actual type for %s is incorrect: wrong_type", boundaries[0], workspace)
		}
		return workspaceMACCoverage{Boundary: boundaries[0], HelperOwned: false}, nil
	}

	// No boundary — check workspace itself.
	if b.verifyActualTypeFail {
		return workspaceMACCoverage{}, fmt.Errorf("workspace %s not covered by any SELinux boundary", workspace)
	}
	return workspaceMACCoverage{Boundary: workspace, HelperOwned: false}, nil
}

func (b *selinuxTestDriver) removeBoundary(boundary string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return nil
}

func (b *selinuxTestDriver) discoverHelperOwnedBoundaries() ([]string, error) {
	return nil, nil
}

func (b *selinuxTestDriver) backendType() string {
	return "selinux"
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

	driver := &selinuxTestDriver{
		coveringFcontexts: map[string][]string{
			"/data/workspace": {"/data"},
		},
		restoreconFail: true,
	}

	mac := newSessionMACCoordinator(db, driver)

	_, err = mac.CreateSessionBinding("/data/workspace", "sess-1", func(cov workspaceMACCoverage) error {
		return insertTestSessionTx(db, "sess-1", "/data/workspace")
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

	allowedRoot := app.Config.AllowedRoots[0]
	workspace, err := os.MkdirTemp(allowedRoot, "workspace-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create session binding.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
		return insertTestSessionTx(app.DB, "sess-1", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Acquire lease.
	_, release, err := mac.AcquireWorkspaceUse("sess-1", workspace)
	if err != nil {
		t.Fatalf("AcquireWorkspaceUse: %v", err)
	}

	// Record state before first release.
	mac.mu.Lock()
	countBefore := mac.boundaryConsumerCounts[workspace]
	leaseCountBefore := len(mac.workspaceUseLeases)
	mac.mu.Unlock()

	// First release.
	release()

	mac.mu.Lock()
	countAfterFirst := mac.boundaryConsumerCounts[workspace]
	leaseCountAfterFirst := len(mac.workspaceUseLeases)
	boundaryRemoved := func() bool {
		_, err := mac.driver.verifyCoverage(workspace)
		return err != nil
	}()
	mac.mu.Unlock()

	// Second release (must be no-op).
	release()

	mac.mu.Lock()
	countAfterSecond := mac.boundaryConsumerCounts[workspace]
	leaseCountAfterSecond := len(mac.workspaceUseLeases)
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

	driver := newTestWorkspaceMACDriver("test")
	mac := newSessionMACCoordinator(db, driver)

	parentWS := "/data/parent"
	childWS := "/data/parent/child"

	// Create parent session binding.
	_, err = mac.CreateSessionBinding(parentWS, "sess-parent", func(cov workspaceMACCoverage) error {
		return insertTestSessionTx(db, "sess-parent", parentWS)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding parent: %v", err)
	}

	// Create child session binding.
	_, err = mac.CreateSessionBinding(childWS, "sess-child", func(cov workspaceMACCoverage) error {
		return insertTestSessionTx(db, "sess-child", childWS)
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

	driver := newTestWorkspaceMACDriver("test")
	mac := newSessionMACCoordinator(db, driver)

	parentWS := "/data/parent"
	childWS := "/data/parent/child"

	// Create parent session binding.
	_, err = mac.CreateSessionBinding(parentWS, "sess-parent", func(cov workspaceMACCoverage) error {
		return insertTestSessionTx(db, "sess-parent", parentWS)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding parent: %v", err)
	}

	// Create child session binding.
	_, err = mac.CreateSessionBinding(childWS, "sess-child", func(cov workspaceMACCoverage) error {
		return insertTestSessionTx(db, "sess-child", childWS)
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

	driver := newTestWorkspaceMACDriver("test")
	mac := newSessionMACCoordinator(db, driver)

	workspace := "/data/workspace"

	// Create two session bindings on the same workspace.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
		return insertTestSessionTx(db, "sess-1", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding sess-1: %v", err)
	}

	_, err = mac.CreateSessionBinding(workspace, "sess-2", func(cov workspaceMACCoverage) error {
		return insertTestSessionTx(db, "sess-2", workspace)
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

	// Create lifecycle with "apparmor" driver.
	apparmorDriver := newTestWorkspaceMACDriver("apparmor")
	mac1 := newSessionMACCoordinator(db, apparmorDriver)

	workspace := "/data/workspace"

	// Create boundary with apparmor driver.
	_, err = mac1.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
		return insertTestSessionTx(db, "sess-1", workspace)
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
	selinuxDriver := newTestWorkspaceMACDriver("selinux")
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
	_, err = mac2.CreateSessionBinding(workspace, "sess-2", func(cov workspaceMACCoverage) error {
		return insertTestSessionTx(db, "sess-2", workspace)
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

	driver := newTestWorkspaceMACDriver("test")
	mac := newSessionMACCoordinator(db, driver)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AllowedRoots:          []string{dir},
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

	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), nil)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Inject a pinned mount with a failing Cleanup.
	sentinelErr := errors.New("injected pinned mount cleanup error")
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
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
	leaseCount := len(mac.workspaceUseLeases)
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

	driver := newTestWorkspaceMACDriver("test")
	mac := newSessionMACCoordinator(db, driver)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AllowedRoots:          []string{dir},
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

	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), nil)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Inject a pinned mount with a successful Cleanup.
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
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
	leaseCount := len(mac.workspaceUseLeases)
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

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}

	driver := newTestWorkspaceMACDriver("test")
	mac := newSessionMACCoordinator(db, driver)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AllowedRoots:          []string{dir},
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

	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), nil)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

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
	leaseCount := len(mac.workspaceUseLeases)
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

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}

	driver := newTestWorkspaceMACDriver("test")
	mac := newSessionMACCoordinator(db, driver)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AllowedRoots:          []string{dir},
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

	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), nil)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

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
	leaseCount := len(mac.workspaceUseLeases)
	mac.mu.Unlock()

	if leaseCount != 0 {
		t.Errorf("expected 0 leases (staging cleanup succeeded), got %d", leaseCount)
	}
}

// TestAdmitRejectionRunPinsBeforeLease drives handleRun with admit
// rejection and verifies pins are cleaned up before the lease is released.
func TestAdmitRejectionRunPinsBeforeLease(t *testing.T) {
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

	driver := newTestWorkspaceMACDriver("test")
	mac := newSessionMACCoordinator(db, driver)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AllowedRoots:          []string{dir},
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

	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), nil)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	var cleanupOrder []string
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
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
	leaseCount := len(mac.workspaceUseLeases)
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

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}

	driver := newTestWorkspaceMACDriver("test")
	mac := newSessionMACCoordinator(db, driver)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		AllowedRoots:          []string{dir},
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

	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), nil)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

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
	leaseCount := len(mac.workspaceUseLeases)
	mac.mu.Unlock()
	if leaseCount != 0 {
		t.Errorf("expected 0 leases after admit rejection, got %d", leaseCount)
	}
}

// =============================================================================
// SELinux durable coverage with real selinuxWorkspaceMACDriver
// =============================================================================

// selinuxSeam is an injectable mock selinuxFcontextManager for testing
// the real selinuxWorkspaceMACDriver path.
type selinuxSeam struct {
	coveringFcontexts []string // returned by listCoveringFcontexts
	fcontextErr       error    // returned by listCoveringFcontexts
	actualTypeErr     error    // returned by verifyActualType
	restoreconErr     error    // returned by restoreconRecursive
	ensureCalled      bool     // tracks whether ensureWorkspaceFcontext was called
	ensureCreated     bool     // newlyCreated from ensureWorkspaceFcontext
	ensureErr         error    // error from ensureWorkspaceFcontext
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

func (s *selinuxSeam) restoreconRecursive(workspace string) error {
	return s.restoreconErr
}

func (s *selinuxSeam) ensureWorkspaceFcontext(workspace string) (bool, error) {
	s.ensureCalled = true
	return s.ensureCreated, s.ensureErr
}

func (s *selinuxSeam) removeFcontextBoundary(boundary string) error {
	return s.removeErr
}

func TestSELinuxRealDriverAncestorCorrectType(t *testing.T) {
	// Persistent ancestor + correct actual type -> verify succeeds.
	seam := &selinuxSeam{
		coveringFcontexts: []string{"/data"},
		actualTypeErr:     nil,
	}
	driver := &selinuxWorkspaceMACDriver{mgr: seam}

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
	driver := &selinuxWorkspaceMACDriver{mgr: seam}

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
	driver := &selinuxWorkspaceMACDriver{mgr: seam}

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
	driver := &selinuxWorkspaceMACDriver{mgr: seam}

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
	driver := &selinuxWorkspaceMACDriver{mgr: seam}

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
	// Expected: failure, ensureWorkspaceFcontext is NOT called.
	seam := &selinuxSeam{
		coveringFcontexts: nil,
	}
	driver := &selinuxWorkspaceMACDriver{mgr: seam}

	_, _, err := driver.ensureCoverage("/opt")
	if err == nil {
		t.Fatal("ensureCoverage must fail for /opt with no existing boundary")
	}
	if !strings.Contains(err.Error(), "/opt") {
		t.Errorf("expected '/opt' in error, got: %v", err)
	}
	if seam.ensureCalled {
		t.Error("ensureWorkspaceFcontext must NOT be called for /opt")
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
	driver := &selinuxWorkspaceMACDriver{mgr: seam}

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
		t.Error("ensureWorkspaceFcontext must NOT be called when compatible boundary exists")
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

	// Seam: no persistent boundary initially, ensureCoverage creates one.
	seam := &selinuxSeam{
		coveringFcontexts: nil,
		actualTypeErr:     nil,
		ensureCreated:     true,
		ensureErr:         nil,
	}
	driver := &selinuxWorkspaceMACDriver{mgr: seam}
	mac := newSessionMACCoordinator(db, driver)

	// Insert a live session so ReconcileLiveSessions has something to reconcile.
	workspace := "/data/workspace"
	_, err = db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id) VALUES (?, ?, ?, ?, ?, ?)`,
		"sess-reconcile", "hash", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), nil)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}

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
	if binding.Boundary != workspace {
		t.Errorf("boundary = %q, want %q", binding.Boundary, workspace)
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

	driver := newTestWorkspaceMACDriver("test")
	mac := newSessionMACCoordinator(db, driver)

	parentWS := "/data/parent"
	childWS := "/data/parent/child"

	// Create parent session binding (the only live consumer).
	_, err = mac.CreateSessionBinding(parentWS, "sess-parent", func(cov workspaceMACCoverage) error {
		return insertTestSessionTx(db, "sess-parent", parentWS)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding parent: %v", err)
	}

	// Manually insert a child boundary into mac_boundaries so it is owned
	// by docker-helper but has no active consumer and is not in deferredBoundaries.
	_, err = db.Exec(`INSERT INTO mac_boundaries (backend, boundary) VALUES (?, ?)`,
		driver.backendType(), childWS)
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

	allowedRoot := app.Config.AllowedRoots[0]
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

	principalID, err := findPrincipalIDByUserName(app.DB, "macdisuser")
	if err != nil {
		t.Fatalf("findPrincipalIDByUserName: %v", err)
	}

	// Create a session with MAC binding.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
		_, err := app.DB.Exec(
			`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", "hash1", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), principalID,
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

	// Disable principal via App-level lifecycle.
	result, err := app.applyPrincipalEnabledChange("macdisuser", false)
	if err != nil {
		t.Fatalf("applyPrincipalEnabledChange: %v", err)
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

	allowedRoot := app.Config.AllowedRoots[0]
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

	principalID, err := findPrincipalIDByUserName(app.DB, "macdeluser")
	if err != nil {
		t.Fatalf("findPrincipalIDByUserName: %v", err)
	}

	// Create a session with MAC binding.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
		_, err := app.DB.Exec(
			`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", "hash1", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), principalID,
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
	// Session has MAC binding, operation acquires workspace-use lease,
	// principal disable removes session, boundary NOT removed while lease exists,
	// lease release allows boundary removal.
	app, mac, driver := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0]
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

	principalID, err := findPrincipalIDByUserName(app.DB, "leaseuser")
	if err != nil {
		t.Fatalf("findPrincipalIDByUserName: %v", err)
	}

	// Create a session with MAC binding.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
		_, err := app.DB.Exec(
			`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", "hash1", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), principalID,
		)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Operation acquires workspace-use lease.
	_, leaseRelease, err := mac.AcquireWorkspaceUse("sess-1", workspace)
	if err != nil {
		t.Fatalf("AcquireWorkspaceUse: %v", err)
	}

	// Verify boundary count is 2 (session + operation lease).
	mac.mu.Lock()
	count := mac.boundaryConsumerCounts[workspace]
	mac.mu.Unlock()
	if count != 2 {
		t.Fatalf("expected boundaryConsumerCounts=2, got %d", count)
	}

	// Disable principal — removes session binding.
	result, err := app.applyPrincipalEnabledChange("leaseuser", false)
	if err != nil {
		t.Fatalf("applyPrincipalEnabledChange: %v", err)
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

	allowedRoot := app.Config.AllowedRoots[0]
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

	principalID, err := findPrincipalIDByUserName(app.DB, "leasedeluser")
	if err != nil {
		t.Fatalf("findPrincipalIDByUserName: %v", err)
	}

	// Create a session with MAC binding.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
		_, err := app.DB.Exec(
			`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", "hash1", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), principalID,
		)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Operation acquires workspace-use lease.
	_, leaseRelease, err := mac.AcquireWorkspaceUse("sess-1", workspace)
	if err != nil {
		t.Fatalf("AcquireWorkspaceUse: %v", err)
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

	allowedRoot := app.Config.AllowedRoots[0]
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

	principalID, err := findPrincipalIDByUserName(app.DB, "shareduser")
	if err != nil {
		t.Fatalf("findPrincipalIDByUserName: %v", err)
	}

	// Create two sessions on the same workspace boundary.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov workspaceMACCoverage) error {
		_, err := app.DB.Exec(
			`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", "hash1", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), principalID,
		)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding sess-1: %v", err)
	}

	_, err = mac.CreateSessionBinding(workspace, "sess-2", func(cov workspaceMACCoverage) error {
		_, err := app.DB.Exec(
			`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-2", "hash2", workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), principalID,
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
	// Regression test: Principal credential authenticated while enabled,
	// Principal disabled, then session creation attempt using stale authority
	// through the real production path (createSessionWithPolicy).
	// Session creation MUST fail; no Session row; no MAC binding;
	// any helper-owned boundary must be rolled back.
	app, mac, driver := setupTestMACCoordinator(t)

	allowedRoot := app.Config.AllowedRoots[0]

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
	_, token, err := createCredential(app.DB, "staleauthuser", "test-cred")
	if err != nil {
		t.Fatalf("createCredential: %v", err)
	}

	// Authenticate the credential while the principal is enabled.
	auth, err := authenticateCredential(app.DB, token)
	if err != nil {
		t.Fatalf("authenticateCredential: %v", err)
	}
	stalePrincipalID := auth.PrincipalID
	staleAllowedRoots := auth.PrincipalAllowedRoots

	// Disable the principal (simulates concurrent disable).
	result, err := persistPrincipalEnabledChange(app.DB, "staleauthuser", false)
	if err != nil {
		t.Fatalf("persistPrincipalEnabledChange: %v", err)
	}
	if !result.Changed {
		t.Fatal("expected Changed=true")
	}

	// Record binding count before the failed creation attempt.
	mac.mu.Lock()
	bindingsBefore := len(mac.sessionBindings)
	mac.mu.Unlock()

	// Attempt session creation through the real production path
	// using the stale authenticated authority.
	effectiveRoots := intersectAllowedRootScopes(app.getConfig().AllowedRoots, staleAllowedRoots)
	_, err = app.createSessionWithPolicy(&sessionCreatePolicy{
		Workspace:             projDir,
		EffectiveAllowedRoots: effectiveRoots,
		PrincipalID:           &stalePrincipalID,
	})

	// createSessionWithPolicy must fail because the principal is disabled.
	if err == nil {
		t.Fatal("expected error from createSessionWithPolicy for stale principal")
	}

	// Verify no Session row was created.
	var count int
	err = app.DB.QueryRow(
		`SELECT COUNT(*) FROM sessions WHERE principal_id = ?`,
		stalePrincipalID,
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
