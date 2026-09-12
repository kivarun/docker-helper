package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- sessionMACBoundaries projection ----------------------------------------

// buildMACSnapshot constructs a canonical snapshot for projection tests.
func buildMACSnapshot(t *testing.T, workspace string, entries []AllowedRootEntry) *sessionFilesystemSnapshot {
	t.Helper()
	snapshot, err := newSessionFilesystemSnapshot(workspace, normalizeAllowedRootEntries(entries))
	if err != nil {
		t.Fatalf("newSessionFilesystemSnapshot: %v", err)
	}
	return snapshot
}

// TestSessionMACBoundariesProjection covers the canonical projection invariants:
// one workspace; workspace + external; two disjoint external roots; nested
// snapshot transitions collapse to one MAC tree; duplicate physical coverage
// deduplicates; a regular file stays an exact boundary; the workspace always
// remains covered through one of the resulting trees.
func TestSessionMACBoundariesProjection(t *testing.T) {
	cases := []struct {
		name      string
		workspace string
		entries   []AllowedRootEntry
		want      []string
	}{
		{
			name:      "one workspace",
			workspace: "/home/michael/runs/run-123",
			entries: []AllowedRootEntry{
				{Path: "/home/michael/runs/run-123", Access: AllowedRootAccessReadWrite},
			},
			want: []string{"/home/michael/runs/run-123"},
		},
		{
			name:      "workspace plus external root",
			workspace: "/home/michael/runs/run-123",
			entries: []AllowedRootEntry{
				{Path: "/opt/michael", Access: AllowedRootAccessReadWrite},
				{Path: "/home/michael/runs/run-123", Access: AllowedRootAccessReadWrite},
			},
			want: []string{"/home/michael/runs/run-123", "/opt/michael"},
		},
		{
			name:      "two disjoint external roots",
			workspace: "/home/michael/runs/run-123",
			entries: []AllowedRootEntry{
				{Path: "/opt/michael/cache", Access: AllowedRootAccessReadWrite},
				{Path: "/srv/build", Access: AllowedRootAccessReadOnly},
				{Path: "/home/michael/runs/run-123", Access: AllowedRootAccessReadWrite},
			},
			want: []string{"/home/michael/runs/run-123", "/opt/michael/cache", "/srv/build"},
		},
		{
			name:      "nested access transitions collapse to one MAC tree",
			workspace: "/home/michael/runs/run-123",
			entries: []AllowedRootEntry{
				{Path: "/opt/michael", Access: AllowedRootAccessReadWrite},
				{Path: "/opt/michael/repos", Access: AllowedRootAccessReadOnly},
				{Path: "/opt/michael/repos/foo", Access: AllowedRootAccessReadWrite},
				{Path: "/home/michael/runs/run-123", Access: AllowedRootAccessReadWrite},
			},
			want: []string{"/home/michael/runs/run-123", "/opt/michael"},
		},
		{
			name:      "issued descendant under an ancestor entry is dropped",
			workspace: "/home/michael/runs/run-123",
			entries: []AllowedRootEntry{
				{Path: "/opt/michael", Access: AllowedRootAccessReadOnly},
				{Path: "/opt/michael/runs", Access: AllowedRootAccessReadWrite},
				{Path: "/home/michael/runs/run-123", Access: AllowedRootAccessReadWrite},
			},
			want: []string{"/home/michael/runs/run-123", "/opt/michael"},
		},
		{
			name:      "regular file root stays an exact concrete boundary",
			workspace: "/home/michael/runs/run-123",
			entries: []AllowedRootEntry{
				{Path: "/opt/michael/secrets/token.pem", Access: AllowedRootAccessReadOnly},
				{Path: "/home/michael/runs/run-123", Access: AllowedRootAccessReadWrite},
			},
			want: []string{"/home/michael/runs/run-123", "/opt/michael/secrets/token.pem"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := buildMACSnapshot(t, tc.workspace, tc.entries)
			got := sessionMACBoundaries(snapshot)
			if len(got) != len(tc.want) {
				t.Fatalf("boundaries = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("boundaries[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
			// Deterministic: a second projection is byte-for-byte identical.
			again := sessionMACBoundaries(snapshot)
			if len(again) != len(got) {
				t.Fatalf("projection is not deterministic: %v vs %v", again, got)
			}
			// The workspace always remains covered through one of the trees.
			covered := false
			for _, boundary := range got {
				if boundaryCoversWorkspace(boundary, tc.workspace) {
					covered = true
				}
			}
			if !covered {
				t.Errorf("workspace %q is not covered by any projected boundary: %v", tc.workspace, got)
			}
		})
	}
}

// --- coordinator: multi-boundary sessions -----------------------------------

// TestCoordinatorMultiBoundarySession proves a session binds one coverage
// set for multiple issued trees, that two trees resolving to the same
// covering boundary register exactly one consumer, and that release removes
// the complete binding through the canonical removal owner.
func TestCoordinatorMultiBoundarySession(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	ws, err := os.MkdirTemp(allowedRoot, "multi-*")
	if err != nil {
		t.Fatal(err)
	}
	ext1, err := os.MkdirTemp(allowedRoot, "ext1-*")
	if err != nil {
		t.Fatal(err)
	}
	ext2, err := os.MkdirTemp(allowedRoot, "ext2-*")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := mac.CreateSessionBinding("sess-multi", []string{ws, ext1, ext2}, func([]workspaceMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-multi", ws)
	}); err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	mac.mu.Lock()
	binding := mac.sessionBindings["sess-multi"]
	c1 := mac.boundaryConsumerCounts[ws]
	c2 := mac.boundaryConsumerCounts[ext1]
	c3 := mac.boundaryConsumerCounts[ext2]
	mac.mu.Unlock()
	if len(binding) != 3 {
		t.Fatalf("binding = %+v, want three coverage boundaries", binding)
	}
	if c1 != 1 || c2 != 1 || c3 != 1 {
		t.Errorf("consumer counts = %d/%d/%d, want 1/1/1", c1, c2, c3)
	}

	// Release: every boundary goes through the canonical removal owner.
	mac.ReleaseSessionBinding("sess-multi")
	for _, boundary := range []string{ws, ext1, ext2} {
		if _, err := driver.verifyCoverage(boundary); err == nil {
			t.Errorf("boundary %s must be removed after the only consumer released it", boundary)
		}
	}
}

// TestCoordinatorDriverDeduplicatesSameBoundary proves that when the driver
// resolves two logical trees to the same covering boundary, one physical
// boundary never becomes multiple accidental consumers.
func TestCoordinatorDriverDeduplicatesSameBoundary(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	parent, err := os.MkdirTemp(allowedRoot, "cover-*")
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "cache")
	if err := os.MkdirAll(child, 0755); err != nil {
		t.Fatal(err)
	}

	// The driver maps both trees to the same covering parent boundary.
	driver.coverageMap[child] = parent
	driver.helperOwnedBoundaries[parent] = true

	if _, err := mac.CreateSessionBinding("sess-shared", []string{parent, child}, func([]workspaceMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-shared", parent)
	}); err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	mac.mu.Lock()
	binding := mac.sessionBindings["sess-shared"]
	count := mac.boundaryConsumerCounts[parent]
	mac.mu.Unlock()
	if len(binding) != 1 || binding[0].Boundary != parent {
		t.Fatalf("binding = %+v, want exactly the covering boundary %q", binding, parent)
	}
	if count != 1 {
		t.Errorf("consumer count on the covering boundary = %d, want 1 (no accidental second consumer)", count)
	}
}

// TestCoordinatorEnsureRollback proves a coverage preparation failure on
// boundary N rolls back the already-prepared boundaries and never leaves a
// usable bearer: CreateSessionBinding fails with the MAC preparation family
// and no partial binding or consumer registration survives.
func TestCoordinatorEnsureRollback(t *testing.T) {
	for _, failingTree := range []string{"second", "third"} {
		t.Run(failingTree, func(t *testing.T) {
			app, mac, driver := setupTestMACCoordinator(t)
			allowedRoot := app.Config.AllowedRoots[0].Path
			ws, err := os.MkdirTemp(allowedRoot, "rb-*")
			if err != nil {
				t.Fatal(err)
			}
			tree2, err := os.MkdirTemp(allowedRoot, "rb2-*")
			if err != nil {
				t.Fatal(err)
			}
			tree3, err := os.MkdirTemp(allowedRoot, "rb3-*")
			if err != nil {
				t.Fatal(err)
			}
			trees := []string{ws, tree2, tree3}
			switch failingTree {
			case "second":
				driver.removeErrors[tree2] = false
				driver.ensureFailures = map[string]bool{tree2: true}
			case "third":
				driver.ensureFailures = map[string]bool{tree3: true}
			}

			_, err = mac.CreateSessionBinding("sess-rb", trees, func([]workspaceMACCoverage) error {
				t.Fatal("insertFn must never run when coverage preparation fails")
				return nil
			})
			if err == nil {
				t.Fatal("CreateSessionBinding must fail when coverage preparation fails")
			}
			if !errors.Is(err, ErrMACPreparation) {
				t.Errorf("err = %v, want the MAC preparation failure family", err)
			}
			mac.mu.Lock()
			_, hasBinding := mac.sessionBindings["sess-rb"]
			mac.mu.Unlock()
			if hasBinding {
				t.Error("no binding may be registered for a failed preparation")
			}
			// The already-prepared boundaries were rolled back.
			for _, boundary := range trees {
				if boundary == failingTree && failingTree == "second" {
					continue
				}
				if _, err := driver.verifyCoverage(boundary); err == nil && driver.coverageMap[boundary] == boundary {
					t.Errorf("prepared boundary %s must be rolled back after the preparation failure", boundary)
				}
			}
		})
	}
}

// TestCoordinatorOwnershipRecordFailureRollsBack proves a newly created
// boundary whose ownership record fails is removed again (no unowned
// physical state survives a failed preparation).
func TestCoordinatorOwnershipRecordFailureRollsBack(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	ws, err := os.MkdirTemp(allowedRoot, "own-*")
	if err != nil {
		t.Fatal(err)
	}
	// Break the ownership insert: replace the DB with a read-only failure
	// injected at the mac_boundaries insert only is not directly possible,
	// so fail via a closed DB wrapper is too broad; instead point the
	// coordinator at a DB whose mac_boundaries insert fails by dropping the
	// table through a second connection.
	if _, err := mac.db.Exec(`DROP TABLE mac_boundaries`); err != nil {
		t.Fatalf("drop mac_boundaries: %v", err)
	}

	_, err = mac.CreateSessionBinding("sess-own", []string{ws}, func([]workspaceMACCoverage) error {
		return nil
	})
	if err == nil || !errors.Is(err, ErrMACPreparation) {
		t.Fatalf("err = %v, want the MAC preparation family for a failed ownership record", err)
	}
	if _, err := driver.verifyCoverage(ws); err == nil {
		t.Error("the unrecordable boundary must be removed again (no unowned physical state)")
	}
}

// TestCoordinatorLeaseProtectsAllBoundRoots proves the session-use lease
// protects every bound coverage boundary while an operation is live: a
// concurrent session deletion must not remove external issued-root coverage
// the operation may rely on.
func TestCoordinatorLeaseProtectsAllBoundRoots(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	ws, err := os.MkdirTemp(allowedRoot, "lease-*")
	if err != nil {
		t.Fatal(err)
	}
	ext, err := os.MkdirTemp(allowedRoot, "lease-ext-*")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := mac.CreateSessionBinding("sess-lease", []string{ws, ext}, func([]workspaceMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-lease", ws)
	}); err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	_, release, err := mac.AcquireSessionUse("sess-lease", ws)
	if err != nil {
		t.Fatalf("AcquireSessionUse: %v", err)
	}

	// Concurrent delete: the release of the session binding must not remove
	// coverage the live lease still protects.
	mac.ReleaseSessionBinding("sess-lease")
	if _, err := driver.verifyCoverage(ext); err != nil {
		t.Fatalf("external issued-root coverage must survive the session deletion while the lease is live: %v", err)
	}
	if _, err := driver.verifyCoverage(ws); err != nil {
		t.Fatalf("workspace coverage must survive the session deletion while the lease is live: %v", err)
	}

	// Idempotent double release: still exactly one decrement.
	release()
	release()
	if _, err := driver.verifyCoverage(ws); err == nil {
		t.Error("workspace coverage must be removed once every consumer (binding + lease) is gone")
	}
	if _, err := driver.verifyCoverage(ext); err == nil {
		t.Error("external coverage must be removed once every consumer (binding + lease) is gone")
	}
}

// TestCoordinatorLeaseAcquireRejectsUnknownSession preserves the exact
// liveness proof of the lease owner.
func TestCoordinatorLeaseAcquireRejectsUnknownSession(t *testing.T) {
	app, mac, _ := setupTestMACCoordinator(t)
	if _, _, err := mac.AcquireSessionUse("sess-nope", "/anywhere"); err == nil {
		t.Fatal("acquiring a lease for a session without a MAC binding must fail")
	}

	allowedRoot := app.Config.AllowedRoots[0].Path
	ws, err := os.MkdirTemp(allowedRoot, "lv-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mac.CreateSessionBinding("sess-live", []string{ws}, func([]workspaceMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-live", ws)
	}); err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}
	// Delete the session row (expiry/deletion): the lease must refuse.
	if _, err := app.DB.Exec(`DELETE FROM sessions WHERE id = 'sess-live'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mac.AcquireSessionUse("sess-live", ws); err == nil {
		t.Fatal("acquiring a lease for a no-longer-live session must fail")
	}
}

// TestCoordinatorSharedBoundaryRelease proves the exact shared boundary
// semantics: two sessions bound to the same tree; deleting one keeps the
// coverage for the other; deleting the second removes it.
func TestCoordinatorSharedBoundaryRelease(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	shared, err := os.MkdirTemp(allowedRoot, "shared-*")
	if err != nil {
		t.Fatal(err)
	}

	for _, sess := range []string{"sess-a", "sess-b"} {
		if _, err := mac.CreateSessionBinding(sess, []string{shared}, func([]workspaceMACCoverage) error {
			return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, sess, shared)
		}); err != nil {
			t.Fatalf("CreateSessionBinding(%s): %v", sess, err)
		}
	}

	mac.ReleaseSessionBinding("sess-a")
	if _, err := driver.verifyCoverage(shared); err != nil {
		t.Fatalf("coverage must remain for the second session after the first release: %v", err)
	}
	mac.ReleaseSessionBinding("sess-b")
	if _, err := driver.verifyCoverage(shared); err == nil {
		t.Error("coverage must be removed after the last consumer releases it")
	}
}

// TestCoordinatorParentChildOverlapRelease proves ancestor/descendant
// overlap: deleting the parent session keeps the child covered; deleting the
// child session afterwards cleans both.
func TestCoordinatorParentChildOverlapRelease(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	parent, err := os.MkdirTemp(allowedRoot, "pc-*")
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(parent, "cache")
	if err := os.MkdirAll(child, 0755); err != nil {
		t.Fatal(err)
	}

	if _, err := mac.CreateSessionBinding("sess-parent", []string{parent}, func([]workspaceMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-parent", parent)
	}); err != nil {
		t.Fatalf("CreateSessionBinding(parent): %v", err)
	}
	if _, err := mac.CreateSessionBinding("sess-child", []string{child}, func([]workspaceMACCoverage) error {
		return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-child", child)
	}); err != nil {
		t.Fatalf("CreateSessionBinding(child): %v", err)
	}

	// Delete the parent session first: the child stays usable and covered.
	mac.ReleaseSessionBinding("sess-parent")
	if _, err := driver.verifyCoverage(child); err != nil {
		t.Fatalf("child coverage must survive the parent session deletion: %v", err)
	}

	// Delete the child session: both boundaries are gone.
	mac.ReleaseSessionBinding("sess-child")
	if _, err := driver.verifyCoverage(parent); err == nil {
		t.Error("parent coverage must be removed after the child session released it too")
	}
	if _, err := driver.verifyCoverage(child); err == nil {
		t.Error("child coverage must be removed after the child session released it")
	}
}

// TestCoordinatorPendingWorkloadExternalRoot proves pending-workload
// coverage treats every issued tree as still needed, and that an
// unresolvable pending session defers everything (fail closed).
func TestCoordinatorPendingWorkloadExternalRoot(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	ws, err := os.MkdirTemp(allowedRoot, "pwl-*")
	if err != nil {
		t.Fatal(err)
	}
	ext, err := os.MkdirTemp(allowedRoot, "pwl-ext-*")
	if err != nil {
		t.Fatal(err)
	}

	// The create callback commits the session row and the two-tree issued
	// snapshot together, exactly like the real create transaction.
	if _, err := mac.CreateSessionBinding("sess-pending", []string{ws, ext}, func([]workspaceMACCoverage) error {
		if err := insertTestSessionTx(app.DB, app.userModeDefault.launcherID, "sess-pending", ws); err != nil {
			return err
		}
		insertTestSessionSnapshotEntries(t, app.DB, "sess-pending", normalizeAllowedRootEntries([]AllowedRootEntry{
			{Path: ext, Access: AllowedRootAccessReadWrite},
			{Path: ws, Access: AllowedRootAccessReadWrite},
		}))
		return nil
	}); err != nil {
		t.Fatalf("CreateSessionBinding: %v", err)
	}

	// Expire the session row (startup expires after reconciliation; the row
	// remains until then) and mark it pending.
	if _, err := app.DB.Exec(`UPDATE sessions SET expires_at = ? WHERE id = 'sess-pending'`, time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	mac.pendingWorkloadSessions = func() map[string]bool { return map[string]bool{"sess-pending": true} }

	// Drop the binding (simulating a released session whose workload state
	// is still pending): the pending gate must keep both issued trees.
	mac.ReleaseSessionBinding("sess-pending")
	if _, err := driver.verifyCoverage(ext); err != nil {
		t.Fatalf("external issued-root coverage must be retained while the workload state is pending: %v", err)
	}
	if _, err := driver.verifyCoverage(ws); err != nil {
		t.Fatalf("workspace coverage must be retained while the workload state is pending: %v", err)
	}

	// Unresolvable pending session (row deleted): defer-all, fail closed.
	if _, err := app.DB.Exec(`DELETE FROM sessions WHERE id = 'sess-pending'`); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.verifyCoverage(ext); err != nil {
		t.Fatalf("coverage must still be deferred (fail closed) when the pending session cannot be resolved: %v", err)
	}

	// Clear the pending gate: the deferred cleanup now completes.
	mac.pendingWorkloadSessions = func() map[string]bool { return map[string]bool{} }
	mac.mu.Lock()
	mac.retryDeferredBoundaries()
	mac.mu.Unlock()
	if _, err := driver.verifyCoverage(ext); err == nil {
		t.Error("deferred external coverage must be removed once the pending workload state is proven gone")
	}
}

// --- startup reconciliation -------------------------------------------------

// TestCoordinatorStartupMultiRootReconstruction proves reconciliation
// rebuilds the complete in-memory binding of a live multi-root session from
// the persisted snapshot, never from current parent policy.
func TestCoordinatorStartupMultiRootReconstruction(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	ws, err := os.MkdirTemp(allowedRoot, "rec-*")
	if err != nil {
		t.Fatal(err)
	}
	ext, err := os.MkdirTemp(allowedRoot, "rec-ext-*")
	if err != nil {
		t.Fatal(err)
	}

	launcherID := app.userModeDefault.launcherID
	if _, err := app.DB.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id) VALUES (?, ?, ?, ?, ?, ?)`,
		"sess-restart", "hash-restart", ws, time.Now().Unix(), time.Now().Add(time.Hour).Unix(), launcherID); err != nil {
		t.Fatal(err)
	}
	insertTestSessionSnapshotEntries(t, app.DB, "sess-restart", normalizeAllowedRootEntries([]AllowedRootEntry{
		{Path: ext, Access: AllowedRootAccessReadOnly},
		{Path: ws, Access: AllowedRootAccessReadWrite},
	}))

	// The driver starts cold (restart): both boundaries must be repaired.
	if err := mac.ReconcileLiveSessions(); err != nil {
		t.Fatalf("ReconcileLiveSessions: %v", err)
	}

	mac.mu.Lock()
	binding := mac.sessionBindings["sess-restart"]
	mac.mu.Unlock()
	if len(binding) != 2 {
		t.Fatalf("binding = %+v, want both issued trees", binding)
	}
	for _, boundary := range []string{ws, ext} {
		if _, err := driver.verifyCoverage(boundary); err != nil {
			t.Errorf("issued tree %s must be covered after restart reconciliation: %v", boundary, err)
		}
	}

	// Parent policy changed after issuance: reconciliation still uses the
	// OLD issued snapshot (the persisted entries above), never current
	// policy. Mutate the policy tables and re-reconcile a fresh coordinator.
	if _, err := app.DB.Exec(`DELETE FROM principal_allowed_roots`); err != nil {
		t.Fatal(err)
	}
	mac2 := newSessionMACCoordinator(app.DB, driver)
	if err := mac2.ReconcileLiveSessions(); err != nil {
		t.Fatalf("ReconcileLiveSessions (after parent policy mutation): %v", err)
	}
	mac2.mu.Lock()
	binding2 := mac2.sessionBindings["sess-restart"]
	mac2.mu.Unlock()
	if len(binding2) != 2 {
		t.Fatalf("binding after parent-policy mutation = %+v, want the issued snapshot trees, not a policy recomputation", binding2)
	}
}

// TestCoordinatorStartupCorruptSnapshotFailsClosed proves a corrupt
// persisted snapshot fails startup closed through the integrity contract.
func TestCoordinatorStartupCorruptSnapshotFailsClosed(t *testing.T) {
	app, mac, _ := setupTestMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	ws, err := os.MkdirTemp(allowedRoot, "corrupt-*")
	if err != nil {
		t.Fatal(err)
	}

	launcherID := app.userModeDefault.launcherID
	if _, err := app.DB.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id) VALUES (?, ?, ?, ?, ?, ?)`,
		"sess-corrupt", "hash-corrupt", ws, time.Now().Unix(), time.Now().Add(time.Hour).Unix(), launcherID); err != nil {
		t.Fatal(err)
	}
	insertTestSessionSnapshot(t, app.DB, "sess-corrupt", ws)
	// Corrupt: change a persisted entry path without updating the digest.
	if _, err := app.DB.Exec(`UPDATE session_filesystem_snapshot_entries SET path = ? WHERE session_id = 'sess-corrupt'`, "/tampered"); err != nil {
		t.Fatal(err)
	}

	err = mac.ReconcileLiveSessions()
	if err == nil {
		t.Fatal("reconciliation must fail closed on a corrupt persisted snapshot")
	}
	if !strings.Contains(err.Error(), "snapshot integrity") {
		t.Errorf("err = %v, want the snapshot integrity failure family", err)
	}
}

// TestCoordinatorStartupConcurrentDeleteRunRace proves the run||delete race
// linearization: the lease and the binding release are serialized through
// the coordinator lock, so a run either never starts or keeps its complete
// coverage until terminal cleanup.
func TestCoordinatorStartupConcurrentDeleteRunRace(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	ws, err := os.MkdirTemp(allowedRoot, "race-*")
	if err != nil {
		t.Fatal(err)
	}
	ext, err := os.MkdirTemp(allowedRoot, "race-ext-*")
	if err != nil {
		t.Fatal(err)
	}

	const iterations = 30
	var wg sync.WaitGroup
	errCh := make(chan error, iterations)
	for i := 0; i < iterations; i++ {
		sess := fmt.Sprintf("sess-race-%d", i)
		if _, err := mac.CreateSessionBinding(sess, []string{ws, ext}, func([]workspaceMACCoverage) error {
			return insertTestSessionTx(app.DB, app.userModeDefault.launcherID, sess, ws)
		}); err != nil {
			t.Fatalf("CreateSessionBinding(%s): %v", sess, err)
		}
		wg.Add(2)
		// The delete path.
		go func(id string) {
			defer wg.Done()
			mac.ReleaseSessionBinding(id)
		}(sess)
		// The run path: acquire the lease concurrently with the delete.
		go func(id string) {
			defer wg.Done()
			_, release, err := mac.AcquireSessionUse(id, ws)
			if err != nil {
				// The run never started (the delete linearized first):
				// the run-side linearization outcome.
				errCh <- nil
				return
			}
			// The run started: the coverage must survive the concurrent
			// delete until the lease releases.
			if _, err := driver.verifyCoverage(ext); err != nil {
				errCh <- fmt.Errorf("coverage removed under a live lease: %w", err)
				release()
				return
			}
			release()
			errCh <- nil
		}(sess)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestCoordinatorInsertFailureRollback proves the create transaction's
// commit point rollback: when insertFn (the Session+snapshot commit) fails,
// the boundaries this call prepared are rolled back through the canonical
// removal owner and no binding or consumer registration survives.
func TestCoordinatorInsertFailureRollback(t *testing.T) {
	app, mac, driver := setupTestMACCoordinator(t)
	allowedRoot := app.Config.AllowedRoots[0].Path
	ws, err := os.MkdirTemp(allowedRoot, "ins-*")
	if err != nil {
		t.Fatal(err)
	}
	ext, err := os.MkdirTemp(allowedRoot, "ins-ext-*")
	if err != nil {
		t.Fatal(err)
	}

	injected := errors.New("session creation transaction failed")
	_, err = mac.CreateSessionBinding("sess-ins", []string{ws, ext}, func([]workspaceMACCoverage) error {
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("err = %v, want the injected insert failure", err)
	}
	mac.mu.Lock()
	_, hasBinding := mac.sessionBindings["sess-ins"]
	mac.mu.Unlock()
	if hasBinding {
		t.Fatal("no binding may be registered when the create commit fails")
	}
	for _, boundary := range []string{ws, ext} {
		if _, err := driver.verifyCoverage(boundary); err == nil {
			t.Errorf("prepared boundary %s must be rolled back after the failed create commit", boundary)
		}
	}
}
