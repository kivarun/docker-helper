package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// setupAppArmorMACCoordinator builds the coordinator on the REAL AppArmor
// workspace MAC driver with the test-isolated managed fragment, so the
// issued-tree lifecycle runs through the production boundary owner.
func setupAppArmorMACCoordinator(t *testing.T) (*App, *sessionMACCoordinator, *appArmorWorkspaceMACDriver, *appArmorProfileManager) {
	t.Helper()
	mockAppArmorActive(t, true)
	saved := EffectiveUID
	EffectiveUID = func() int { return 0 }
	t.Cleanup(func() { EffectiveUID = saved })

	dir, mgr, _ := setupAppArmorTest(t)

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

	driver := &appArmorWorkspaceMACDriver{
		addManagedBoundary:    func(path string) (boundaryResult, error) { return mgr.addManagedBoundary(path) },
		removeManagedBoundary: func(path string) (boundaryResult, error) { return mgr.removeManagedBoundary(path) },
		listManagedBoundaries: func() ([]string, error) { return mgr.listManagedBoundaries() },
	}
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
	app := &App{Config: cfg, DB: db, MACCoordinator: mac}
	home := filepath.Join(allowedRoot, "daemon-home")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatalf("cannot create daemon home: %v", err)
	}
	app.userModeDefault = provisionTestOwner(t, db, allowedRoot, home, os.Getuid(), os.Getgid())
	return app, mac, driver, mgr
}

// TestAppArmorDriverExternalTreeThroughSameOwner proves the AppArmor driver
// manages an external issued tree (directory and regular file) through the
// same boundary owner, with kind-aware fragment rules, and releases it
// through the coordinator's canonical removal path.
func TestAppArmorDriverExternalTreeThroughSameOwner(t *testing.T) {
	app, mac, driver, mgr := setupAppArmorMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	extDir, err := os.MkdirTemp(allowedRoot, "aa-ext-*")
	if err != nil {
		t.Fatal(err)
	}
	extFile := filepath.Join(allowedRoot, "aa-ext-file")
	if err := os.WriteFile(extFile, []byte("token"), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := mac.CreateSessionBinding("sess-aa", []string{extDir, extFile}, func([]workspaceMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-aa", extDir)
	}); err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Both issued trees must be covered by the real AppArmor driver.
	for _, tree := range []string{extDir, extFile} {
		if _, err := driver.verifyCoverage(tree); err != nil {
			t.Errorf("issued tree %s must be covered after creation: %v", tree, err)
		}
	}

	// The managed fragment must carry the exact-file rule for the file tree
	// and the directory rules for the directory tree.
	fragmentBytes, err := os.ReadFile(mgr.managedFragmentPath)
	if err != nil {
		t.Fatalf("read fragment: %v", err)
	}
	fragment := string(fragmentBytes)
	if !strings.Contains(fragment, "\""+escapeAppArmorPath(extFile)+"\" r,\n") {
		t.Errorf("the file boundary must render the exact-file rule:\n%s", fragment)
	}
	if strings.Contains(fragment, "\""+escapeAppArmorPath(extFile)+"/\"") {
		t.Errorf("the file boundary must not render directory rules:\n%s", fragment)
	}
	if !strings.Contains(fragment, "\""+escapeAppArmorPath(extDir)+"/**\" r,\n") {
		t.Errorf("the directory boundary must render the descendant rule:\n%s", fragment)
	}

	// Release: the canonical removal owner drops both boundaries.
	mac.ReleaseSessionBinding("sess-aa")
	for _, tree := range []string{extDir, extFile} {
		if _, err := driver.verifyCoverage(tree); err == nil {
			t.Errorf("boundary %s must be removed after the only consumer released it", tree)
		}
	}
}

// TestAppArmorDriverOverlapRelease proves the AppArmor parent/child overlap
// semantics: deleting the parent session keeps the child covered; deleting
// the child session removes both through the canonical owner.
func TestAppArmorDriverOverlapRelease(t *testing.T) {
	app, mac, driver, _ := setupAppArmorMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	parent, err := os.MkdirTemp(allowedRoot, "aa-parent-*")
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "cache")
	if err := os.MkdirAll(child, 0755); err != nil {
		t.Fatal(err)
	}

	if _, err := mac.CreateSessionBinding("sess-aa-parent", []string{parent}, func([]workspaceMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-aa-parent", parent)
	}); err != nil {
		t.Fatalf("CreateSessionBinding(parent): %v", err)
	}
	if _, err := mac.CreateSessionBinding("sess-aa-child", []string{child}, func([]workspaceMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-aa-child", child)
	}); err != nil {
		t.Fatalf("CreateSessionBinding(child): %v", err)
	}

	mac.mu.Lock()
	childCount := mac.boundaryConsumerCounts[parent]
	mac.mu.Unlock()
	if childCount != 2 {
		t.Fatalf("the child tree resolved onto the parent boundary; consumer count = %d, want 2", childCount)
	}

	// Delete the parent session first: the child session still holds the
	// boundary.
	mac.ReleaseSessionBinding("sess-aa-parent")
	if _, err := driver.verifyCoverage(child); err != nil {
		t.Fatalf("child coverage must survive the parent session deletion: %v", err)
	}

	mac.ReleaseSessionBinding("sess-aa-child")
	if _, err := driver.verifyCoverage(parent); err == nil {
		t.Error("the boundary must be removed once every consumer released it")
	}
}
