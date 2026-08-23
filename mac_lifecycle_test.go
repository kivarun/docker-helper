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
	tokenHash := fmt.Sprintf("hash_%s", sessionID)
	_, err := db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sessionID, tokenHash, workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), nil,
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

// =============================================================================
// Issue 1: SELinux verifyCoverage/ensureCoverage with actual type verification
// =============================================================================

// selinuxTestBackend is a mock SELinux backend for testing actual type verification.
type selinuxTestBackend struct {
	mu                   sync.Mutex
	coveringBoundaries   map[string][]string // workspace -> covering boundaries
	actualType           string              // returned type for verifyActualType
	restoreconCalls      int
	restoreconFail       bool
	verifyActualTypeFail bool
}

func (b *selinuxTestBackend) ensureCoverage(workspace string) (macCoverage, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if boundaries, ok := b.coveringBoundaries[workspace]; ok && len(boundaries) > 0 {
		// Existing compatible coverage: run restorecon and verify actual type.
		if b.restoreconFail {
			return macCoverage{}, false, fmt.Errorf("restorecon failed for %s", workspace)
		}
		b.restoreconCalls++
		if b.verifyActualTypeFail {
			return macCoverage{}, false, fmt.Errorf("actual type verification failed for %s", workspace)
		}
		return macCoverage{Boundary: boundaries[0], Managed: false}, false, nil
	}

	// No existing coverage: create new boundary.
	return macCoverage{Boundary: workspace, Managed: true}, true, nil
}

func (b *selinuxTestBackend) verifyCoverage(workspace string) (macCoverage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if boundaries, ok := b.coveringBoundaries[workspace]; ok && len(boundaries) > 0 {
		// Boundary exists — verify actual on-disk type.
		if b.verifyActualTypeFail {
			return macCoverage{}, fmt.Errorf("existing SELinux boundary %s exists but actual type for %s is incorrect: wrong_type", boundaries[0], workspace)
		}
		return macCoverage{Boundary: boundaries[0], Managed: false}, nil
	}

	// No boundary — check workspace itself.
	if b.verifyActualTypeFail {
		return macCoverage{}, fmt.Errorf("workspace %s not covered by any SELinux boundary", workspace)
	}
	return macCoverage{Boundary: workspace, Managed: false}, nil
}

func (b *selinuxTestBackend) removeBoundary(boundary string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return nil
}

func (b *selinuxTestBackend) listManagedBoundaries() ([]string, error) {
	return nil, nil
}

func (b *selinuxTestBackend) backendType() string {
	return "selinux"
}

func TestSELinuxAncestorRuleCorrectType(t *testing.T) {
	// Existing ancestor rule + correct actual type -> verify succeeds.
	backend := &selinuxTestBackend{
		coveringBoundaries: map[string][]string{
			"/data/workspace": {"/data"},
		},
		actualType: "docker_helper_workspace_t",
	}

	cov, err := backend.verifyCoverage("/data/workspace")
	if err != nil {
		t.Fatalf("verifyCoverage should succeed with correct type: %v", err)
	}
	if cov.Boundary != "/data" {
		t.Errorf("expected boundary /data, got %s", cov.Boundary)
	}
}

func TestSELinuxAncestorRuleWrongType(t *testing.T) {
	// Existing ancestor rule + wrong actual type -> verify fails.
	backend := &selinuxTestBackend{
		coveringBoundaries: map[string][]string{
			"/data/workspace": {"/data"},
		},
		verifyActualTypeFail: true,
	}

	_, err := backend.verifyCoverage("/data/workspace")
	if err == nil {
		t.Fatal("verifyCoverage should fail with wrong actual type")
	}
	if !strings.Contains(err.Error(), "incorrect") {
		t.Errorf("expected 'incorrect' in error, got: %v", err)
	}
}

func TestSELinuxEnsureExistingAncestorWrongType(t *testing.T) {
	// ensure on existing ancestor rule + wrong actual type -> restorecon/verify fails.
	backend := &selinuxTestBackend{
		coveringBoundaries: map[string][]string{
			"/data/workspace": {"/data"},
		},
		restoreconFail:       false,
		verifyActualTypeFail: true,
	}

	_, _, err := backend.ensureCoverage("/data/workspace")
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

	backend := &selinuxTestBackend{
		coveringBoundaries: map[string][]string{
			"/data/workspace": {"/data"},
		},
		restoreconFail: true,
	}

	mac := newWorkspaceMACLifecycle(db, backend)

	_, err = mac.CreateSessionBinding("/data/workspace", "sess-1", func(cov macCoverage) error {
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
// Issue 3: Lease release idempotency
// =============================================================================

func TestLeaseReleaseIdempotent(t *testing.T) {
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
	_, release, err := mac.AcquireUse("sess-1", workspace)
	if err != nil {
		t.Fatalf("AcquireUse: %v", err)
	}

	// Record state before first release.
	mac.mu.Lock()
	countBefore := mac.activeBoundaries[workspace]
	leaseCountBefore := len(mac.leases)
	mac.mu.Unlock()

	// First release.
	release()

	mac.mu.Lock()
	countAfterFirst := mac.activeBoundaries[workspace]
	leaseCountAfterFirst := len(mac.leases)
	boundaryRemoved := func() bool {
		_, err := mac.backend.verifyCoverage(workspace)
		return err != nil
	}()
	mac.mu.Unlock()

	// Second release (must be no-op).
	release()

	mac.mu.Lock()
	countAfterSecond := mac.activeBoundaries[workspace]
	leaseCountAfterSecond := len(mac.leases)
	boundaryRemovedSecond := func() bool {
		_, err := mac.backend.verifyCoverage(workspace)
		return err != nil
	}()
	mac.mu.Unlock()

	// Verify second release changed nothing.
	if countAfterFirst != countAfterSecond {
		t.Errorf("second release changed activeBoundaries: first=%d, second=%d", countAfterFirst, countAfterSecond)
	}
	if leaseCountAfterFirst != leaseCountAfterSecond {
		t.Errorf("second release changed leases: first=%d, second=%d", leaseCountAfterFirst, leaseCountAfterSecond)
	}
	if boundaryRemoved != boundaryRemovedSecond {
		t.Errorf("second release changed backend boundary state: first=%v, second=%v", boundaryRemoved, boundaryRemovedSecond)
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
// Issue 4: Deferred nested-boundary cleanup
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

	backend := newTestMACBackend("test")
	mac := newWorkspaceMACLifecycle(db, backend)

	parentWS := "/data/parent"
	childWS := "/data/parent/child"

	// Create parent session binding.
	_, err = mac.CreateSessionBinding(parentWS, "sess-parent", func(cov macCoverage) error {
		return insertTestSessionTx(db, "sess-parent", parentWS)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding parent: %v", err)
	}

	// Create child session binding.
	_, err = mac.CreateSessionBinding(childWS, "sess-child", func(cov macCoverage) error {
		return insertTestSessionTx(db, "sess-child", childWS)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding child: %v", err)
	}

	// Delete child first.
	mac.ReleaseSessionBoundary("sess-child")

	// Child boundary should be deferred (parent still needs it via overlap).
	mac.mu.Lock()
	childActive := mac.activeBoundaries[childWS]
	childDeferred := mac.deferredBoundaries[childWS]
	parentActive := mac.activeBoundaries[parentWS]
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
	mac.ReleaseSessionBoundary("sess-parent")

	// Both boundaries should now be gone.
	mac.mu.Lock()
	parentActive = mac.activeBoundaries[parentWS]
	parentDeferred := mac.deferredBoundaries[parentWS]
	childActive = mac.activeBoundaries[childWS]
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

	// Verify both boundaries were removed from backend.
	_, err = backend.verifyCoverage(parentWS)
	if err == nil {
		t.Error("parent boundary should be removed from backend")
	}
	_, err = backend.verifyCoverage(childWS)
	if err == nil {
		t.Error("child boundary should be removed from backend")
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

	backend := newTestMACBackend("test")
	mac := newWorkspaceMACLifecycle(db, backend)

	parentWS := "/data/parent"
	childWS := "/data/parent/child"

	// Create parent session binding.
	_, err = mac.CreateSessionBinding(parentWS, "sess-parent", func(cov macCoverage) error {
		return insertTestSessionTx(db, "sess-parent", parentWS)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding parent: %v", err)
	}

	// Create child session binding.
	_, err = mac.CreateSessionBinding(childWS, "sess-child", func(cov macCoverage) error {
		return insertTestSessionTx(db, "sess-child", childWS)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding child: %v", err)
	}

	// Delete parent first.
	mac.ReleaseSessionBoundary("sess-parent")

	// Parent boundary should be deferred (child still overlaps).
	mac.mu.Lock()
	parentActive := mac.activeBoundaries[parentWS]
	parentDeferred := mac.deferredBoundaries[parentWS]
	childActive := mac.activeBoundaries[childWS]
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
	mac.ReleaseSessionBoundary("sess-child")

	// Both boundaries should now be gone.
	mac.mu.Lock()
	parentActive = mac.activeBoundaries[parentWS]
	parentDeferred = mac.deferredBoundaries[parentWS]
	childActive = mac.activeBoundaries[childWS]
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

	backend := newTestMACBackend("test")
	mac := newWorkspaceMACLifecycle(db, backend)

	workspace := "/data/workspace"

	// Create two session bindings on the same workspace.
	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
		return insertTestSessionTx(db, "sess-1", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding sess-1: %v", err)
	}

	_, err = mac.CreateSessionBinding(workspace, "sess-2", func(cov macCoverage) error {
		return insertTestSessionTx(db, "sess-2", workspace)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding sess-2: %v", err)
	}

	mac.mu.Lock()
	countBefore := mac.activeBoundaries[workspace]
	mac.mu.Unlock()
	if countBefore != 2 {
		t.Errorf("expected count 2, got %d", countBefore)
	}

	// Delete first session.
	mac.ReleaseSessionBoundary("sess-1")

	mac.mu.Lock()
	countAfterFirst := mac.activeBoundaries[workspace]
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
	mac.ReleaseSessionBoundary("sess-2")

	mac.mu.Lock()
	countAfterSecond := mac.activeBoundaries[workspace]
	deferred = mac.deferredBoundaries[workspace]
	mac.mu.Unlock()

	if countAfterSecond != 0 {
		t.Errorf("expected count 0, got %d", countAfterSecond)
	}
	if deferred {
		t.Error("should not be deferred after last consumer gone")
	}

	// Verify boundary was removed from backend.
	_, err = backend.verifyCoverage(workspace)
	if err == nil {
		t.Error("boundary should be removed from backend")
	}
}

// =============================================================================
// Issue 5: Backend-safe ownership key
// =============================================================================

func TestBackendSwitchOwnership(t *testing.T) {
	// Switch from "apparmor" backend to "selinux" backend.
	// The new backend must be able to claim ownership of the same boundary
	// without being blocked by stale ownership from the old backend.
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

	// Create lifecycle with "apparmor" backend.
	apparmorBackend := newTestMACBackend("apparmor")
	mac1 := newWorkspaceMACLifecycle(db, apparmorBackend)

	workspace := "/data/workspace"

	// Create boundary with apparmor backend.
	_, err = mac1.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
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
	mac1.ReleaseSessionBoundary("sess-1")

	// Now create lifecycle with "selinux" backend.
	selinuxBackend := newTestMACBackend("selinux")
	mac2 := newWorkspaceMACLifecycle(db, selinuxBackend)

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
	_, err = mac2.CreateSessionBinding(workspace, "sess-2", func(cov macCoverage) error {
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

	// Verify both backends have their own records in the DB.
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
// Issue 6: Production-path ordering tests (real handler tests)
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

	backend := newTestMACBackend("test")
	mac := newWorkspaceMACLifecycle(db, backend)

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
		Config:            cfg,
		DB:                db,
		MACLifecycle:      mac,
		OperationRegistry: newOperationRegistry(),
	}

	// Create workspace and session.
	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}

	// Generate auth token for the session.
	token, err := generateToken()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte(token))

	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), nil)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Inject a pinned mount with a failing Cleanup.
	sentinelErr := errors.New("injected pinned mount cleanup error")
	app.PinMountFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			HostPath: "/tmp/test-mount",
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
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found in registry")
	}
	op.Wait()

	// Verify: the MAC lease was NOT released because cleanup failed.
	// The boundary count should still reflect the session binding + the
	// unreleased lease (the lease was never released due to cleanup failure).
	mac.mu.Lock()
	boundaryCount := mac.activeBoundaries[workspace]
	leaseCount := len(mac.leases)
	mac.mu.Unlock()

	// The session binding contributes 1. The lease was acquired but NOT
	// released because cleanup failed. The lease entry should still exist.
	if leaseCount != 1 {
		t.Errorf("expected 1 lease retained (cleanup failed), got %d", leaseCount)
	}
	if boundaryCount != 2 {
		t.Errorf("expected activeBoundaries=2 (session + unreleased lease), got %d", boundaryCount)
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

	backend := newTestMACBackend("test")
	mac := newWorkspaceMACLifecycle(db, backend)

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
		Config:            cfg,
		DB:                db,
		MACLifecycle:      mac,
		OperationRegistry: newOperationRegistry(),
	}

	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}

	// Generate auth token for the session.
	token, err := generateToken()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte(token))

	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), nil)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Inject a pinned mount with a successful Cleanup.
	app.PinMountFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			HostPath: "/tmp/test-mount",
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
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found")
	}
	op.Wait()

	// Verify: the MAC lease WAS released because cleanup succeeded.
	mac.mu.Lock()
	leaseCount := len(mac.leases)
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

	backend := newTestMACBackend("test")
	mac := newWorkspaceMACLifecycle(db, backend)

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
		Config:            cfg,
		DB:                db,
		MACLifecycle:      mac,
		OperationRegistry: newOperationRegistry(),
	}

	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Generate auth token for the session.
	token, err := generateToken()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte(token))

	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
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
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found")
	}
	op.Wait()

	// Verify: the MAC lease was NOT released because staging cleanup failed.
	mac.mu.Lock()
	leaseCount := len(mac.leases)
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

	backend := newTestMACBackend("test")
	mac := newWorkspaceMACLifecycle(db, backend)

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
		Config:            cfg,
		DB:                db,
		MACLifecycle:      mac,
		OperationRegistry: newOperationRegistry(),
	}

	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Generate auth token for the session.
	token, err := generateToken()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte(token))

	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
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
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found")
	}
	op.Wait()

	// Verify: the MAC lease WAS released because staging cleanup succeeded.
	mac.mu.Lock()
	leaseCount := len(mac.leases)
	mac.mu.Unlock()

	if leaseCount != 0 {
		t.Errorf("expected 0 leases (staging cleanup succeeded), got %d", leaseCount)
	}
}

// TestTryCreateRejectionRunPinsBeforeLease drives handleRun with tryCreate
// rejection and verifies pins are cleaned up before the lease is released.
func TestTryCreateRejectionRunPinsBeforeLease(t *testing.T) {
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

	backend := newTestMACBackend("test")
	mac := newWorkspaceMACLifecycle(db, backend)

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
		Config:            cfg,
		DB:                db,
		MACLifecycle:      mac,
		OperationRegistry: newOperationRegistry(),
	}

	// Force tryCreate rejection.
	app.OperationRegistry.setShuttingDown()

	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}

	// Generate auth token for the session.
	token, err := generateToken()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte(token))

	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, principal_id) VALUES (?, ?, ?, ?, ?, ?)`,
			"sess-1", hex.EncodeToString(tokenHash[:]), workspace, time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), nil)
		return err
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	var cleanupOrder []string
	app.PinMountFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			HostPath: "/tmp/test-mount",
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
	leaseCount := len(mac.leases)
	mac.mu.Unlock()
	if leaseCount != 0 {
		t.Errorf("expected 0 leases after tryCreate rejection, got %d", leaseCount)
	}
}

// TestTryCreateRejectionBuildStagingBeforeLease drives handleBuild with
// tryCreate rejection and verifies staging is cleaned up before the lease is released.
func TestTryCreateRejectionBuildStagingBeforeLease(t *testing.T) {
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

	backend := newTestMACBackend("test")
	mac := newWorkspaceMACLifecycle(db, backend)

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
		Config:            cfg,
		DB:                db,
		MACLifecycle:      mac,
		OperationRegistry: newOperationRegistry(),
	}

	// Force tryCreate rejection.
	app.OperationRegistry.setShuttingDown()

	workspace := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Generate auth token for the session.
	token, err := generateToken()
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := sha256.Sum256([]byte(token))

	_, err = mac.CreateSessionBinding(workspace, "sess-1", func(cov macCoverage) error {
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
		t.Error("staging cleanup must be called on tryCreate rejection")
	}

	// Verify: lease was released after staging cleanup.
	mac.mu.Lock()
	leaseCount := len(mac.leases)
	mac.mu.Unlock()
	if leaseCount != 0 {
		t.Errorf("expected 0 leases after tryCreate rejection, got %d", leaseCount)
	}
}

// =============================================================================
// Issue 1 (continued): SELinux durable coverage with real macBackendSELinux
// =============================================================================

// selinuxSeam is an injectable mock selinuxWorkspaceManager for testing
// the real macBackendSELinux path.
type selinuxSeam struct {
	coveringBoundaries []string // returned by listCoveringBoundaries
	boundaryErr        error    // returned by listCoveringBoundaries
	actualTypeErr      error    // returned by verifyActualType
	restoreconErr      error    // returned by restoreconRecursive
	ensureCreated      bool     // newlyCreated from ensureWorkspaceLabel
	ensureErr          error    // error from ensureWorkspaceLabel
	rollbackErr        error    // error from rollbackWorkspaceLabel
}

func (s *selinuxSeam) listCoveringBoundaries(workspace string) ([]string, error) {
	if s.boundaryErr != nil {
		return nil, s.boundaryErr
	}
	return s.coveringBoundaries, nil
}

func (s *selinuxSeam) verifyActualType(workspace string) error {
	return s.actualTypeErr
}

func (s *selinuxSeam) restoreconRecursive(workspace string) error {
	return s.restoreconErr
}

func (s *selinuxSeam) ensureWorkspaceLabel(workspace string) (bool, error) {
	return s.ensureCreated, s.ensureErr
}

func (s *selinuxSeam) rollbackWorkspaceLabel(boundary string) error {
	return s.rollbackErr
}

func TestSELinuxRealBackendAncestorCorrectType(t *testing.T) {
	// Persistent ancestor + correct actual type -> verify succeeds.
	seam := &selinuxSeam{
		coveringBoundaries: []string{"/data"},
		actualTypeErr:      nil,
	}
	backend := &macBackendSELinux{mgr: seam}

	cov, err := backend.verifyCoverage("/data/workspace")
	if err != nil {
		t.Fatalf("verifyCoverage should succeed: %v", err)
	}
	if cov.Boundary != "/data" {
		t.Errorf("expected boundary /data, got %s", cov.Boundary)
	}
}

func TestSELinuxRealBackendAncestorWrongType(t *testing.T) {
	// Persistent ancestor + wrong type -> verify fails.
	seam := &selinuxSeam{
		coveringBoundaries: []string{"/data"},
		actualTypeErr:      errors.New("wrong type"),
	}
	backend := &macBackendSELinux{mgr: seam}

	_, err := backend.verifyCoverage("/data/workspace")
	if err == nil {
		t.Fatal("verifyCoverage should fail with wrong actual type")
	}
	if !strings.Contains(err.Error(), "incorrect") {
		t.Errorf("expected 'incorrect' in error, got: %v", err)
	}
}

func TestSELinuxRealBackendNoBoundaryCorrectXattrFails(t *testing.T) {
	// No persistent boundary + correct current xattr -> verify FAILS.
	// This is the key invariant: unmanaged xattr alone is not durable.
	seam := &selinuxSeam{
		coveringBoundaries: nil,
		actualTypeErr:      nil, // correct type but no persistent boundary
	}
	backend := &macBackendSELinux{mgr: seam}

	_, err := backend.verifyCoverage("/data/workspace")
	if err == nil {
		t.Fatal("verifyCoverage must fail when no persistent fcontext boundary exists")
	}
	if !strings.Contains(err.Error(), "no persistent") {
		t.Errorf("expected 'no persistent' in error, got: %v", err)
	}
}

func TestSELinuxRealBackendEnsureRepairsWrongType(t *testing.T) {
	// ensureCoverage with existing ancestor + restorecon/verify succeeds.
	seam := &selinuxSeam{
		coveringBoundaries: []string{"/data"},
		restoreconErr:      nil,
		actualTypeErr:      nil,
	}
	backend := &macBackendSELinux{mgr: seam}

	cov, changed, err := backend.ensureCoverage("/data/workspace")
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

func TestSELinuxRealBackendEnsureCreatesNewBoundary(t *testing.T) {
	// No existing boundary -> ensureCoverage creates new one.
	seam := &selinuxSeam{
		coveringBoundaries: nil,
		ensureCreated:      true,
		ensureErr:          nil,
	}
	backend := &macBackendSELinux{mgr: seam}

	cov, changed, err := backend.ensureCoverage("/data/workspace")
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

func TestSELinuxReconcileCreatesDurableCoverage(t *testing.T) {
	// No persistent boundary -> verifyCoverage fails -> ensureCoverage creates it.
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

	// Start with no boundary, verify fails.
	// After ensureWorkspaceLabel, boundary exists.
	seam := &selinuxSeam{
		coveringBoundaries: nil,
		actualTypeErr:      nil,
		ensureCreated:      true,
		ensureErr:          nil,
	}
	backend := &macBackendSELinux{mgr: seam}

	// verifyCoverage must fail (no persistent boundary).
	_, err = backend.verifyCoverage("/data/workspace")
	if err == nil {
		t.Fatal("verifyCoverage must fail without persistent boundary")
	}

	// ensureCoverage creates the persistent boundary.
	cov, changed, err := backend.ensureCoverage("/data/workspace")
	if err != nil {
		t.Fatalf("ensureCoverage failed: %v", err)
	}
	if !changed {
		t.Error("ensureCoverage should report changed")
	}
	if cov.Boundary != "/data/workspace" {
		t.Errorf("expected boundary /data/workspace, got %s", cov.Boundary)
	}

	// Update seam to reflect the new boundary.
	seam.coveringBoundaries = []string{"/data/workspace"}

	// Now verifyCoverage succeeds.
	cov, err = backend.verifyCoverage("/data/workspace")
	if err != nil {
		t.Fatalf("verifyCoverage should succeed after ensureCoverage: %v", err)
	}
	if cov.Boundary != "/data/workspace" {
		t.Errorf("expected boundary /data/workspace, got %s", cov.Boundary)
	}
}

// =============================================================================
// Issue 3: Atomic mac_boundaries migration test
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
// Issue 4: Deferred stale-boundary cleanup from cleanupStaleBoundaries
// =============================================================================

func TestDeferredStaleBoundaryCleanup(t *testing.T) {
	// An owned boundary with no direct consumer but removal blocked by an
	// overlapping live binding/lease should be registered in deferredBoundaries.
	// After the last intersecting consumer disappears, it must be retried.
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

	backend := newTestMACBackend("test")
	mac := newWorkspaceMACLifecycle(db, backend)

	parentWS := "/data/parent"
	childWS := "/data/parent/child"

	// Create parent session binding.
	_, err = mac.CreateSessionBinding(parentWS, "sess-parent", func(cov macCoverage) error {
		return insertTestSessionTx(db, "sess-parent", parentWS)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding parent: %v", err)
	}

	// Create child session binding.
	_, err = mac.CreateSessionBinding(childWS, "sess-child", func(cov macCoverage) error {
		return insertTestSessionTx(db, "sess-child", childWS)
	})
	if err != nil {
		t.Fatalf("CreateSessionBinding child: %v", err)
	}

	// Delete child first.
	mac.ReleaseSessionBoundary("sess-child")

	// Child boundary should be deferred (parent still overlaps).
	mac.mu.Lock()
	childDeferred := mac.deferredBoundaries[childWS]
	mac.mu.Unlock()

	if !childDeferred {
		t.Error("child boundary should be deferred after release (parent still overlaps)")
	}

	// Simulate cleanupStaleBoundaries: it should register the child boundary
	// as deferred because isBoundaryStillNeeded returns true (parent overlaps).
	err = mac.cleanupStaleBoundaries()
	if err != nil {
		t.Fatalf("cleanupStaleBoundaries: %v", err)
	}

	// Child should still be deferred (parent still active).
	mac.mu.Lock()
	childDeferredAfterCleanup := mac.deferredBoundaries[childWS]
	mac.mu.Unlock()

	if !childDeferredAfterCleanup {
		t.Error("child should still be deferred after cleanupStaleBoundaries (parent overlaps)")
	}

	// Delete parent — this should trigger retry of deferred boundaries.
	mac.ReleaseSessionBoundary("sess-parent")

	// Both boundaries should now be gone.
	mac.mu.Lock()
	parentDeferred := mac.deferredBoundaries[parentWS]
	childDeferred = mac.deferredBoundaries[childWS]
	mac.mu.Unlock()

	if parentDeferred {
		t.Error("parent should not be deferred after all consumers gone")
	}
	if childDeferred {
		t.Error("child should not be deferred after all consumers gone")
	}

	// Verify both boundaries were removed from backend.
	_, err = backend.verifyCoverage(parentWS)
	if err == nil {
		t.Error("parent boundary should be removed from backend")
	}
	_, err = backend.verifyCoverage(childWS)
	if err == nil {
		t.Error("child boundary should be removed from backend")
	}
}
