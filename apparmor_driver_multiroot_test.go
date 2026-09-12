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
func setupAppArmorMACCoordinator(t *testing.T) (*App, *sessionMACCoordinator, *appArmorMACDriver, *appArmorProfileManager) {
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

	driver := &appArmorMACDriver{
		addManagedBoundary:    func(path string) (boundaryResult, error) { return mgr.addManagedBoundary(path) },
		removeManagedBoundary: func(path string) (boundaryResult, error) { return mgr.removeManagedBoundary(path) },
		listManagedBoundaries: func() ([]appArmorManagedBoundary, error) { return mgr.listManagedBoundaries() },
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

	if _, err := mac.CreateSessionBinding("sess-aa", []string{extDir, extFile}, func([]sessionMACCoverage) error {
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

	if _, err := mac.CreateSessionBinding("sess-aa-parent", []string{parent}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-aa-parent", parent)
	}); err != nil {
		t.Fatalf("CreateSessionBinding(parent): %v", err)
	}
	if _, err := mac.CreateSessionBinding("sess-aa-child", []string{child}, func([]sessionMACCoverage) error {
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

// TestAppArmorDriverFileBoundaryNeverCoversDescendant proves the kind-aware
// coverage semantics (the B3 review repair): a persisted regular-file
// boundary covers exactly its canonical path and NEVER a descendant path,
// in both ensure and verify. The check runs through the real fragment-backed
// driver, not a reimplemented predicate.
func TestAppArmorDriverFileBoundaryNeverCoversDescendant(t *testing.T) {
	app, mac, driver, mgr := setupAppArmorMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	treeFile := filepath.Join(allowedRoot, "aa-file-boundary")
	if err := os.WriteFile(treeFile, []byte("token"), 0644); err != nil {
		t.Fatal(err)
	}
	// A descendant path of the FILE boundary (reachable only if the host
	// object were replaced by a directory).
	child := filepath.Join(treeFile, "child")

	if _, err := mac.CreateSessionBinding("sess-aa-file-kind", []string{treeFile}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-aa-file-kind", allowedRoot)
	}); err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// The fragment persists the boundary as a regular-file boundary.
	fragmentBytes, err := os.ReadFile(mgr.managedFragmentPath)
	if err != nil {
		t.Fatalf("read fragment: %v", err)
	}
	if !strings.Contains(string(fragmentBytes), appArmorBoundaryFileMarker) {
		t.Fatalf("the file boundary must persist its regular-file kind:\n%s", fragmentBytes)
	}

	// verify: the exact file is covered; a descendant is not.
	if _, err := driver.verifyCoverage(treeFile); err != nil {
		t.Fatalf("verifyCoverage(exact file): %v", err)
	}
	if _, err := driver.verifyCoverage(child); err == nil {
		t.Error("a regular-file boundary must never cover a descendant path")
	}

	// ensure: the exact file is covered by the persisted boundary. A
	// descendant of a regular-file boundary can never be satisfied by it:
	// the kind-aware verify proof above already refuses the descendant, and
	// the real descendant-boundary preparation is proven by
	// TestAppArmorDriverFileBoundaryNotWidenedByKindChange.
	coverage, created, err := driver.ensureCoverage(treeFile)
	if err != nil {
		t.Fatalf("ensureCoverage(exact file): %v", err)
	}
	if created || coverage.Boundary != treeFile || coverage.Kind != macBoundaryRegularFile {
		t.Errorf("coverage = %+v created=%v, want the persisted exact-file boundary with its kind", coverage, created)
	}
}

// TestAppArmorDriverFileBoundaryNotWidenedByKindChange proves that replacing
// the host file with a directory neither widens the persisted exact-file
// rule nor re-derives its kind: the old boundary stays exact-file, and a new
// coverage requirement for the replaced directory tree is prepared as its
// own directory boundary (the B3 review repair).
func TestAppArmorDriverFileBoundaryNotWidenedByKindChange(t *testing.T) {
	app, mac, driver, mgr := setupAppArmorMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	treeFile := filepath.Join(allowedRoot, "aa-file-replaced")
	if err := os.WriteFile(treeFile, []byte("token"), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := mac.CreateSessionBinding("sess-aa-replaced", []string{treeFile}, func([]sessionMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-aa-replaced", allowedRoot)
	}); err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// The operator replaces the file with a directory at the same path.
	if err := os.Remove(treeFile); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(treeFile, 0755); err != nil {
		t.Fatal(err)
	}

	// The persisted exact-file boundary must not become recursive coverage:
	// ensure for the exact path returns the persisted boundary unchanged.
	coverage, created, err := driver.ensureCoverage(treeFile)
	if err != nil {
		t.Fatalf("ensureCoverage(replaced tree): %v", err)
	}
	if created || coverage.Boundary != treeFile || coverage.Kind != macBoundaryRegularFile {
		t.Errorf("coverage = %+v created=%v, want the persisted exact-file boundary with its unchanged kind", coverage, created)
	}

	// The fragment still renders the exact-file rule and no directory rules
	// for that boundary.
	fragmentBytes, err := os.ReadFile(mgr.managedFragmentPath)
	if err != nil {
		t.Fatalf("read fragment: %v", err)
	}
	fragment := string(fragmentBytes)
	if !strings.Contains(fragment, "\""+escapeAppArmorPath(treeFile)+"\" r,\n") {
		t.Errorf("the persisted exact-file rule must survive the kind change:\n%s", fragment)
	}
	if strings.Contains(fragment, "\""+escapeAppArmorPath(treeFile)+"/\"") {
		t.Errorf("the exact-file boundary must never widen into directory rules:\n%s", fragment)
	}

	// A new coverage requirement for a tree the exact-file rule cannot
	// serve is prepared as its own directory boundary.
	descendant := filepath.Join(treeFile, "sub")
	if err := os.MkdirAll(descendant, 0755); err != nil {
		t.Fatal(err)
	}
	descCoverage, created, err := driver.ensureCoverage(descendant)
	if err != nil {
		t.Fatalf("ensureCoverage(descendant): %v", err)
	}
	if !created || descCoverage.Boundary != descendant || descCoverage.Kind != macBoundaryDirectory {
		t.Errorf("coverage = %+v created=%v, want a new directory boundary for the descendant tree", descCoverage, created)
	}
}
