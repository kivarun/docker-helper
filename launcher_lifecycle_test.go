package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// launcherLifecycleDB returns a fresh DB with a Principal and two Launchers
// (a and b), with Sessions created for each Launcher.
func launcherLifecycleDB(t *testing.T) (*sql.DB, string, string) {
	t.Helper()
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "owner")

	la, _, _, err := createLauncher(db, pid, "default", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatalf("createLauncher(a): %v", err)
	}
	lb, _, _, err := createLauncher(db, pid, "second", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatalf("createLauncher(b): %v", err)
	}

	insert := func(launcherID, id string) {
		t.Helper()
		sum := sha256.Sum256([]byte("token-" + id))
		_, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id) VALUES (?, ?, ?, ?, ?, ?)`,
			id, hex.EncodeToString(sum[:]), filepath.Join(globalRoots[0], "ws", id), time.Now().Unix(), time.Now().Add(24*time.Hour).Unix(), launcherID)
		if err != nil {
			t.Fatalf("insert session %s: %v", id, err)
		}
	}
	insert(la.ID, "dhs_a")
	insert(la.ID, "dhs_a2")
	insert(lb.ID, "dhs_b")

	return db, la.ID, lb.ID
}

// TestPersistLauncherEnabledChangeDisableInvalidatesOnlyOwnSessions proves a
// Launcher disable invalidates exactly that Launcher's Sessions transactionally
// while leaving sibling Launchers' Sessions valid.
func TestPersistLauncherEnabledChangeDisableInvalidatesOnlyOwnSessions(t *testing.T) {
	db, laID, lbID := launcherLifecycleDB(t)

	result, err := persistLauncherEnabledChange(db, laID, false)
	if err != nil {
		t.Fatalf("persistLauncherEnabledChange: %v", err)
	}
	if !result.Changed {
		t.Error("expected changed=true on first disable")
	}
	if len(result.RevokedSessionIDs) != 2 {
		t.Fatalf("expected 2 revoked session ids, got %v", result.RevokedSessionIDs)
	}

	var laCount, lbCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id=?`, laID).Scan(&laCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id=?`, lbID).Scan(&lbCount); err != nil {
		t.Fatal(err)
	}
	if laCount != 0 {
		t.Errorf("expected launcher a sessions deleted, got %d", laCount)
	}
	if lbCount != 1 {
		t.Errorf("expected sibling launcher b session preserved, got %d", lbCount)
	}

	var enabled int
	if err := db.QueryRow(`SELECT enabled FROM launchers WHERE id=?`, laID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Error("expected launcher a disabled")
	}
}

// TestPersistLauncherEnabledChangeDisableRetrySafe proves a re-invoked disable
// on an already-disabled Launcher still invalidates/cleans its Sessions rather
// than skipping cleanup because enabled was already false.
func TestPersistLauncherEnabledChangeDisableRetrySafe(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)

	if _, err := persistLauncherEnabledChange(db, laID, false); err != nil {
		t.Fatalf("first disable: %v", err)
	}
	// Re-inject a Session to simulate one left behind by a prior partial
	// failure that retry must clean up.
	sum := sha256.Sum256([]byte("token-orphan"))
	if _, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id) VALUES (?, ?, ?, ?, ?, ?)`,
		"dhs_orphan", hex.EncodeToString(sum[:]), "/orphan", time.Now().Unix(), time.Now().Add(time.Hour).Unix(), laID); err != nil {
		t.Fatal(err)
	}

	result, err := persistLauncherEnabledChange(db, laID, false)
	if err != nil {
		t.Fatalf("second disable: %v", err)
	}
	if result.Changed {
		t.Error("expected changed=false on re-disable")
	}
	if len(result.RevokedSessionIDs) != 1 || result.RevokedSessionIDs[0] != "dhs_orphan" {
		t.Fatalf("expected orphan session revoked on re-disable, got %v", result.RevokedSessionIDs)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id=?`, laID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected no sessions after re-disable cleanup, got %d", count)
	}
}

// TestPersistLauncherEnabledChangeEnableDoesNotRecreateSessions proves re-enable
// only flips enabled state and never recreates invalidated Sessions.
func TestPersistLauncherEnabledChangeEnableDoesNotRecreateSessions(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)

	if _, err := persistLauncherEnabledChange(db, laID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	result, err := persistLauncherEnabledChange(db, laID, true)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !result.Changed {
		t.Error("expected changed=true on enable")
	}
	if len(result.RevokedSessionIDs) != 0 {
		t.Errorf("expected no revoked sessions on enable, got %v", result.RevokedSessionIDs)
	}
	var enabled, count int
	if err := db.QueryRow(`SELECT enabled FROM launchers WHERE id=?`, laID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 1 {
		t.Error("expected launcher re-enabled")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id=?`, laID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected no sessions after re-enable, got %d", count)
	}
}

func TestPersistLauncherEnabledChangeNotFound(t *testing.T) {
	db, _, _ := launcherLifecycleDB(t)
	if _, err := persistLauncherEnabledChange(db, "dhl_missing", false); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("expected ErrLauncherNotFound, got %v", err)
	}
}

// deleteLifecycleApp returns an App with a controllable inspect seam and an
// operation supervisor.
func deleteLifecycleApp(t *testing.T, db *sql.DB) *App {
	t.Helper()
	app := &App{
		Config: &Config{
			RuntimeDir:   t.TempDir(),
			AllowedRoots: []string{testAllowedRootDir(t)},
		},
		DB: db,
		InspectHelperContainers: func(ctx context.Context, launcherID string) ([]helperContainer, error) {
			return nil, nil
		},
	}
	app.OperationSupervisor = newOperationSupervisor()
	return app
}

func TestDeleteLauncherCheckedClean(t *testing.T) {
	db, laID, lbID := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	sessionIDs, err := app.deleteLauncherChecked(context.Background(), laID)
	if err != nil {
		t.Fatalf("deleteLauncherChecked: %v", err)
	}
	if len(sessionIDs) != 2 {
		t.Errorf("expected 2 deleted session ids, got %v", sessionIDs)
	}
	if _, err := findLauncherByID(db, laID); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("expected launcher a gone, got %v", err)
	}
	// Sibling launcher + session unaffected.
	if _, err := findLauncherByID(db, lbID); err != nil {
		t.Fatalf("sibling launcher should remain: %v", err)
	}
	var lbCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id=?`, lbID).Scan(&lbCount); err != nil {
		t.Fatal(err)
	}
	if lbCount != 1 {
		t.Errorf("expected sibling session preserved, got %d", lbCount)
	}
}

func TestDeleteLauncherCheckedActiveRunningOpRefuses(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	op := newTestOperation(t, operationRunning, time.Time{})
	op.LauncherID = laID
	app.OperationSupervisor.admit(op)

	revoked, err := app.deleteLauncherChecked(context.Background(), laID)
	if !errors.Is(err, ErrLauncherRuntimeActive) {
		t.Fatalf("expected ErrLauncherRuntimeActive for running op, got %v (revoked=%v)", err, revoked)
	}
	if len(revoked) != 2 {
		t.Errorf("expected the running launcher's 2 sessions reported revoked, got %v", revoked)
	}
	// The launcher row is preserved but left disabled, and its Sessions are
	// invalidated (the sanctioned 409 semantics of the destructive delete).
	if _, err := findLauncherByID(db, laID); err != nil {
		t.Fatalf("launcher row should be preserved: %v", err)
	}
	var enabled int
	if err := db.QueryRow(`SELECT enabled FROM launchers WHERE id=?`, laID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Error("expected refused delete to leave launcher disabled")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id=?`, laID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected sessions invalidated by refused delete, got %d", count)
	}
	// The Launcher remains durably disabled, so its operation admission stays
	// closed: quiesce is the runtime companion of disabled state and is NOT
	// released merely because the delete was refused.
	if !app.OperationSupervisor.isLauncherQuiesced(laID) {
		t.Error("expected quiesce kept after refused delete (launcher durably disabled)")
	}
}

// TestDeleteLauncherCheckedActiveContainerRefusesWithoutProvenance proves
// restart-style detection: an attributable running container blocks deletion
// even with no in-memory operation provenance (labels are evidence). The 409
// leaves the Launcher disabled and its Sessions invalidated, row preserved.
func TestDeleteLauncherCheckedActiveContainerRefusesWithoutProvenance(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		if launcherID == laID {
			return []helperContainer{{ID: "abc123", Running: true}}, nil
		}
		return nil, nil
	}

	if _, err := app.deleteLauncherChecked(context.Background(), laID); !errors.Is(err, ErrLauncherRuntimeActive) {
		t.Fatalf("expected ErrLauncherRuntimeActive for running container, got %v", err)
	}
	// Launcher row preserved but disabled; sessions invalidated.
	if _, err := findLauncherByID(db, laID); err != nil {
		t.Fatalf("launcher should be preserved: %v", err)
	}
	var enabled int
	if err := db.QueryRow(`SELECT enabled FROM launchers WHERE id=?`, laID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Error("expected refused delete to leave launcher disabled")
	}
}

func TestDeleteLauncherCheckedStaleContainerRemoved(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	var removed []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "docker" && len(args) >= 2 && args[0] == "rm" {
			removed = append(removed, args[len(args)-1])
		}
		return exec.CommandContext(ctx, "true")
	}
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		if launcherID == laID {
			return []helperContainer{{ID: "stale123", Running: false}}, nil
		}
		return nil, nil
	}

	if _, err := app.deleteLauncherChecked(context.Background(), laID); err != nil {
		t.Fatalf("deleteLauncherChecked with stale container: %v", err)
	}
	if len(removed) != 1 || removed[0] != "stale123" {
		t.Errorf("expected stale container removed, got %v", removed)
	}
}

// TestDeleteLauncherCheckedInspectErrorFailClosed proves an unclassifiable
// inspection preserves the Launcher and surfaces the failure.
func TestDeleteLauncherCheckedInspectErrorFailClosed(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)
	sentinel := errors.New("inspect failure")
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		return nil, sentinel
	}

	if _, err := app.deleteLauncherChecked(context.Background(), laID); !errors.Is(err, sentinel) {
		t.Fatalf("expected inspect error propagated, got %v", err)
	}
	if _, err := findLauncherByID(db, laID); err != nil {
		t.Fatalf("launcher should be preserved on inspect failure: %v", err)
	}
}

// TestDeleteLauncherCheckedRetryAfterExit proves a delete refused while a
// container runs succeeds after the runtime exits and inspection is revised.
func TestDeleteLauncherCheckedRetryAfterExit(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	running := true
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		if launcherID == laID {
			if running {
				return []helperContainer{{ID: "abc123", Running: true}}, nil
			}
			return []helperContainer{{ID: "abc123", Running: false}}, nil
		}
		return nil, nil
	}

	if _, err := app.deleteLauncherChecked(context.Background(), laID); !errors.Is(err, ErrLauncherRuntimeActive) {
		t.Fatalf("expected first delete refused, got %v", err)
	}
	running = false
	if _, err := app.deleteLauncherChecked(context.Background(), laID); err != nil {
		t.Fatalf("expected retry delete to succeed after exit, got %v", err)
	}
}

// TestHasRunningForLauncherSiblingIsolation proves the supervisor provenance
// check is scoped to one Launcher and never reports siblings.
func TestHasRunningForLauncherSiblingIsolation(t *testing.T) {
	supervisor := newOperationSupervisor()
	runA := newTestOperation(t, operationRunning, time.Time{})
	runA.LauncherID = "la"
	doneB := newTestOperation(t, operationSucceeded, time.Now())
	doneB.LauncherID = "lb"
	supervisor.admit(runA)
	supervisor.admit(doneB)

	if !supervisor.hasRunningForLauncher("la") {
		t.Error("expected running op reported for launcher la")
	}
	if supervisor.hasRunningForLauncher("lb") {
		t.Error("expected completed op not reported for launcher lb")
	}
	if supervisor.hasRunningForLauncher("missing") {
		t.Error("expected false for absent launcher")
	}
}

// TestDeletePrincipalCheckedBlockedThenSucceeds proves Principal deletion is
// refused while a Launcher's attributable runtime is active, preserves the
// Principal and Launcher records, and succeeds once the runtime exits.
func TestDeletePrincipalCheckedBlockedThenSucceeds(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	running := true
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		if launcherID == laID {
			if running {
				return []helperContainer{{ID: "abc123", Running: true}}, nil
			}
			return []helperContainer{{ID: "abc123", Running: false}}, nil
		}
		return nil, nil
	}

	if _, err := app.deletePrincipalChecked(context.Background(), "owner"); !errors.Is(err, ErrLauncherRuntimeActive) {
		t.Fatalf("expected ErrLauncherRuntimeActive while runtime active, got %v", err)
	}
	if _, err := findPrincipalByUsername(db, "owner"); err != nil {
		t.Fatalf("principal should be preserved while runtime active: %v", err)
	}

	running = false
	if _, err := app.deletePrincipalChecked(context.Background(), "owner"); err != nil {
		t.Fatalf("deletePrincipalChecked after runtime exit: %v", err)
	}
	if _, err := findPrincipalByUsername(db, "owner"); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("expected principal gone, got %v", err)
	}
	if _, err := findLauncherByID(db, laID); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("expected launcher gone with principal, got %v", err)
	}
}

// TestInspectHelperContainersParsesAndFailsClosed exercises the real
// Docker-CLI parsing path: well-formed lines are classified, malformed lines
// fail closed so a Launcher is never deleted unclassifiably.
func TestInspectHelperContainersParsesAndFailsClosed(t *testing.T) {
	app := deleteLifecycleApp(t, openFreshTestDB(t))

	cases := []struct {
		name    string
		output  string
		wantIDs []string
		wantErr bool
	}{
		{name: "empty", output: "", wantIDs: nil},
		{name: "one running", output: "abc123 true\n", wantIDs: []string{"abc123"}},
		{name: "one exited", output: "def456 false", wantIDs: []string{"def456"}},
		{name: "blank lines ignored", output: "\nabc123 true\n\n", wantIDs: []string{"abc123"}},
		{name: "malformed fails closed", output: "abc123 true extra\n", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app.InspectHelperContainers = nil
			app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
				out := strippedStringCmd(t, tc.output)
				return out
			}
			got, err := app.inspectHelperContainersForLauncher(context.Background(), "launcher")
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected fail-closed error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.wantIDs) {
				t.Fatalf("expected %d containers, got %d: %+v", len(tc.wantIDs), len(got), got)
			}
			for i := range got {
				if got[i].ID != tc.wantIDs[i] {
					t.Errorf("container[%d] id: expected %q, got %q", i, tc.wantIDs[i], got[i].ID)
				}
			}
		})
	}
}

func TestDeleteLauncherCheckedSiblingIsolation(t *testing.T) {
	db, laID, lbID := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		if launcherID == lbID {
			return []helperContainer{{ID: "runningB", Running: true}}, nil
		}
		return nil, nil
	}

	if _, err := app.deleteLauncherChecked(context.Background(), laID); err != nil {
		t.Fatalf("delete launcher a should succeed despite sibling b runtime: %v", err)
	}
	if _, err := findLauncherByID(db, lbID); err != nil {
		t.Fatalf("sibling launcher b should remain: %v", err)
	}
	if _, err := app.deleteLauncherChecked(context.Background(), lbID); !errors.Is(err, ErrLauncherRuntimeActive) {
		t.Fatalf("expected sibling b refused while its runtime active, got %v", err)
	}
}

// strippedStringCmd runs `sh -c` with printf so command Output() returns the
// exact fixture string without a trailing newline/quoting surprises.
func strippedStringCmd(t *testing.T, s string) *exec.Cmd {
	t.Helper()
	return exec.Command("sh", "-c", "printf '%s' '"+strings.ReplaceAll(s, "'", "'\\''")+"'")
}

// quiesceBarrier app returns an app whose InspectHelperContainers seam blocks
// the first call (which occurs AFTER deleteLauncherChecked/deletePrincipalChecked
// has disabled the launcher and quiesced operation admission) until the test
// releases it. It returns a channel that is closed when the delete is parked at
// the admission-closing point, and a release channel the test closes to let the
// delete proceed.
func quiesceBarrierApp(t *testing.T, db *sql.DB) (*App, chan struct{}, chan struct{}) {
	t.Helper()
	app := deleteLifecycleApp(t, db)
	atQuiesce := make(chan struct{})
	release := make(chan struct{})
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		// The seam is invoked at the runtime-inspection point, which checked
		// deletion reaches only after disabling the launcher and quiescing
		// operation admission. Blocking here deterministically parks the delete
		// at its admission-closing point before the final owner removal.
		close(atQuiesce)
		<-release
		return nil, nil
	}
	return app, atQuiesce, release
}

// TestRaceLauncherConcurrentOperationAdmissionRefused proves that once checked
// deletion crosses its admission-closing point (disable + quiesce), a concurrent
// Operation admission for that Launcher is refused. Without the quiesce, the
// delete would remove the Launcher while that Operation runs.
func TestRaceLauncherConcurrentOperationAdmissionRefused(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app, atQuiesce, release := quiesceBarrierApp(t, db)

	var deleteErr error
	deleteDone := make(chan struct{})
	go func() {
		defer close(deleteDone)
		_, deleteErr = app.deleteLauncherChecked(context.Background(), laID)
	}()

	// Wait until the delete has disabled + quiesced the launcher and is parked
	// at the runtime inspection, before the final row removal.
	<-atQuiesce

	// A session that was already authorized before the quiesce now tries to
	// admit a running Operation for this Launcher, concurrently with the delete.
	op := newTestOperation(t, operationRunning, time.Time{})
	op.LauncherID = laID
	if admitted := app.OperationSupervisor.admit(op); admitted {
		t.Fatal("operation admitted after checked deletion closed admission; delete would remove launcher while it runs")
	}

	close(release)
	<-deleteDone
	if deleteErr != nil {
		t.Fatalf("delete should succeed with no running runtime, got %v", deleteErr)
	}
	if _, err := findLauncherByID(db, laID); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("expected launcher deleted, got %v", err)
	}
}

// TestRaceLauncherPreQuiescedRunningOperationBlocksDelete proves an Operation
// admitted immediately before the quiesce is visible to the runtime check, so
// delete refuses (409) and does not remove the Launcher while it runs.
func TestRaceLauncherPreQuiescedRunningOperationBlocksDelete(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	op := newTestOperation(t, operationRunning, time.Time{})
	op.LauncherID = laID
	app.OperationSupervisor.admit(op)

	if _, err := app.deleteLauncherChecked(context.Background(), laID); !errors.Is(err, ErrLauncherRuntimeActive) {
		t.Fatalf("expected ErrLauncherRuntimeActive for pre-quiesced running op, got %v", err)
	}
	if _, err := findLauncherByID(db, laID); err != nil {
		t.Fatalf("launcher row must be preserved while op runs: %v", err)
	}
}

// TestRaceNoNewSessionAfterQuiesce proves that once checked deletion has crossed
// its admission-closing point, concurrent Session creation for that Launcher
// fails (the DB-level enabled-conditional insert admits no row).
func TestRaceNoNewSessionAfterQuiesce(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app, atQuiesce, release := quiesceBarrierApp(t, db)

	ws := testWorkspaceDir(t, testAllowedRootDir(t))

	var deleteErr error
	deleteDone := make(chan struct{})
	go func() {
		defer close(deleteDone)
		_, deleteErr = app.deleteLauncherChecked(context.Background(), laID)
	}()

	<-atQuiesce

	// A concurrent Session creation for this Launcher must be refused now that
	// the launcher is disabled by the delete's admission-closing point.
	_, err := app.createSessionWithPolicy(&sessionCreatePolicy{
		Workspace:             ws,
		EffectiveAllowedRoots: app.Config.AllowedRoots,
		LauncherID:            laID,
		LauncherName:          "default",
		PrincipalName:         "owner",
	})
	if err == nil {
		t.Fatal("session admitted for launcher after checked deletion closed admission")
	}

	close(release)
	<-deleteDone
	if deleteErr != nil {
		t.Fatalf("delete should succeed, got %v", deleteErr)
	}
}

// TestRaceLauncherRetryAfterOperationExits proves retry (C): a delete refused
// while an admitted Operation runs succeeds once that Operation finishes
// naturally, without killing it.
func TestRaceLauncherRetryAfterOperationExits(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	op := newTestOperation(t, operationRunning, time.Time{})
	op.LauncherID = laID
	app.OperationSupervisor.admit(op)

	if _, err := app.deleteLauncherChecked(context.Background(), laID); !errors.Is(err, ErrLauncherRuntimeActive) {
		t.Fatalf("expected first delete refused while op runs, got %v", err)
	}
	if _, err := findLauncherByID(db, laID); err != nil {
		t.Fatalf("launcher preserved on first refused delete: %v", err)
	}

	// The admitted Operation finishes naturally (terminal state).
	op.fail("cancelled", "cancelled", nil)

	// Repeating DELETE now succeeds.
	if _, err := app.deleteLauncherChecked(context.Background(), laID); err != nil {
		t.Fatalf("expected retry delete to succeed after op exit, got %v", err)
	}
	if _, err := findLauncherByID(db, laID); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("expected launcher deleted on retry, got %v", err)
	}
}

// TestRacePrincipalRunningOperationPreservesLaunchers proves (D): Principal
// deletion cannot cascade away Launcher rows while an Operation admitted under
// one of them is still running. It returns 409 and preserves Principal and
// Launcher rows.
func TestRacePrincipalRunningOperationPreservesLaunchers(t *testing.T) {
	db, laID, lbID := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	// An Operation admitted under Launcher a is running.
	op := newTestOperation(t, operationRunning, time.Time{})
	op.LauncherID = laID
	app.OperationSupervisor.admit(op)

	if _, err := app.deletePrincipalChecked(context.Background(), "owner"); !errors.Is(err, ErrLauncherRuntimeActive) {
		t.Fatalf("expected principal delete refused while an op runs under a launcher, got %v", err)
	}
	// Principal and both Launcher rows preserved.
	if _, err := findPrincipalByUsername(db, "owner"); err != nil {
		t.Fatalf("principal should be preserved: %v", err)
	}
	if _, err := findLauncherByID(db, laID); err != nil {
		t.Fatalf("launcher a should be preserved: %v", err)
	}
	if _, err := findLauncherByID(db, lbID); err != nil {
		t.Fatalf("launcher b should be preserved: %v", err)
	}

	// After the Operation finishes naturally, the Principal delete succeeds.
	op.fail("cancelled", "cancelled", nil)
	if _, err := app.deletePrincipalChecked(context.Background(), "owner"); err != nil {
		t.Fatalf("principal delete after op exit should succeed, got %v", err)
	}
	if _, err := findPrincipalByUsername(db, "owner"); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("expected principal gone, got %v", err)
	}
	if _, err := findLauncherByID(db, laID); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("expected launcher a gone, got %v", err)
	}
	if _, err := findLauncherByID(db, lbID); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("expected launcher b gone, got %v", err)
	}
}

// TestRaceLauncherSessionResolvedBeforeDisableAdmissionRefusedAfterDelete proves
// the reviewer scenario: a request authenticates and resolves its Session
// successfully, then is paused BEFORE OperationSupervisor.admit(). While it is
// paused, the Launcher is deleted, and the DELETE returns 409 because another
// Operation under the same Launcher is running. When the paused request is
// released and calls admit(), its admission MUST be refused even though the
// DELETE has already returned. This is the case that regressed when quiesce was
// restored on the 409 path while the Launcher stayed durably disabled.
func TestRaceLauncherSessionResolvedBeforeDisableAdmissionRefusedAfterDelete(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	// The in-flight request resolves its Session through the real production
	// path BEFORE the disable. The session exists and launcher+principal are
	// enabled, so resolution succeeds.
	sess, err := app.findSessionByToken("token-dhs_a")
	if err != nil {
		t.Fatalf("session should resolve before disable: %v", err)
	}

	resolved := make(chan struct{})
	release := make(chan struct{})
	admitted := make(chan bool, 1)
	go func() {
		close(resolved)
		<-release
		pausedOp := newTestOperation(t, operationRunning, time.Time{})
		pausedOp.LauncherID = sess.LauncherID
		admitted <- app.OperationSupervisor.admit(pausedOp)
	}()

	// Pause the in-flight request right after its Session resolution, before
	// admit(). Meanwhile, DELETE the Launcher; it is refused (409) because a
	// separate running Operation is admitted under the same Launcher.
	<-resolved
	blocking := newTestOperation(t, operationRunning, time.Time{})
	blocking.LauncherID = laID
	app.OperationSupervisor.admit(blocking)

	if _, err := app.deleteLauncherChecked(context.Background(), laID); !errors.Is(err, ErrLauncherRuntimeActive) {
		t.Fatalf("expected delete refused by running operation, got %v", err)
	}
	// The DELETE already returned; the Launcher stays disabled, so its admission
	// must remain closed.
	if !app.OperationSupervisor.isLauncherQuiesced(laID) {
		t.Fatal("expected launcher still quiesced after refused delete returned")
	}

	// Release the paused in-flight request. Its admission must be refused even
	// though its Session was resolved before the disable and the DELETE already
	// returned.
	close(release)
	if got := <-admitted; got {
		t.Fatal("in-flight request admitted after launcher disabled + deleted (409); would run with no persisted owner")
	}
}

// TestDisableEnableFreshSessionCanAdmit proves the full enable-lifetime: after
// disable (admission closed) then re-enable (admission reopened), a fresh valid
// Session for the re-enabled Launcher can admit Operations again.
func TestDisableEnableFreshSessionCanAdmit(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	op := func() *operation {
		o := newTestOperation(t, operationRunning, time.Time{})
		o.LauncherID = laID
		return o
	}

	// Disable: admission is closed, so an Operation cannot admit.
	if _, err := app.disableLauncher(laID); err != nil {
		t.Fatalf("disableLauncher: %v", err)
	}
	if admitted := app.OperationSupervisor.admit(op()); admitted {
		t.Fatal("operation admitted while launcher disabled")
	}

	// Re-enable: admission reopens, but old invalidated Sessions are NOT
	// recreated, so a stale session token no longer resolves.
	if err := app.enableLauncher(laID); err != nil {
		t.Fatalf("enableLauncher: %v", err)
	}
	if app.OperationSupervisor.isLauncherQuiesced(laID) {
		t.Fatal("expected launcher unquiesced after re-enable")
	}
	if _, err := app.findSessionByToken("token-dhs_a"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected stale session not recreated, got %v", err)
	}

	// A fresh valid Session for the re-enabled Launcher can admit Operations.
	allowedRoot := testAllowedRootDir(t)
	app.Config.AllowedRoots = []string{allowedRoot}
	ws := testWorkspaceDir(t, allowedRoot)
	created, err := app.createSessionWithPolicy(&sessionCreatePolicy{
		Workspace:             ws,
		EffectiveAllowedRoots: app.Config.AllowedRoots,
		LauncherID:            laID,
		LauncherName:          "default",
		PrincipalName:         "owner",
	})
	if err != nil {
		t.Fatalf("create fresh session after re-enable: %v", err)
	}
	fresh := newTestOperation(t, operationRunning, time.Time{})
	fresh.LauncherID = created.Session.LauncherID
	if admitted := app.OperationSupervisor.admit(fresh); !admitted {
		t.Fatal("expected fresh session's operation admitted after re-enable")
	}
}

// TestPrincipalDisableEnableQuiescesAllLaunchers proves the Principal-level
// companion invariant (requirement 4): disabling a Principal quiesces Operation
// admission across EVERY Launcher beneath it and keeps it closed, while a
// successful re-enable reopens admission across all of them.
func TestPrincipalDisableEnableQuiescesAllLaunchers(t *testing.T) {
	db, laID, lbID := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	opFor := func(id string) *operation {
		o := newTestOperation(t, operationRunning, time.Time{})
		o.LauncherID = id
		return o
	}

	if _, err := app.disablePrincipalLaunchers("owner"); err != nil {
		t.Fatalf("disablePrincipalLaunchers: %v", err)
	}
	for _, id := range []string{laID, lbID} {
		if !app.OperationSupervisor.isLauncherQuiesced(id) {
			t.Fatalf("expected launcher %s quiesced after principal disable", id)
		}
		if admitted := app.OperationSupervisor.admit(opFor(id)); admitted {
			t.Fatalf("operation admitted for launcher %s after principal disable", id)
		}
	}

	if _, err := app.enablePrincipalLaunchers("owner"); err != nil {
		t.Fatalf("enablePrincipalLaunchers: %v", err)
	}
	for _, id := range []string{laID, lbID} {
		if app.OperationSupervisor.isLauncherQuiesced(id) {
			t.Fatalf("expected launcher %s unquiesced after principal enable", id)
		}
		if admitted := app.OperationSupervisor.admit(opFor(id)); !admitted {
			t.Fatalf("operation refused for launcher %s after principal enable", id)
		}
	}
}

// launcherRunningOp builds an operation in the running state attributed to the
// given Launcher, for admission tests.
func launcherRunningOp(t *testing.T, id string) *operation {
	t.Helper()
	o := newTestOperation(t, operationRunning, time.Time{})
	o.LauncherID = id
	return o
}

// TestHierarchyPrincipalReenableRespectsIndividuallyDisabledLauncher (A): with
// Launcher A enabled and Launcher B individually disabled, disabling then
// re-enabling the Principal must leave A's admission open and keep B's closed.
func TestHierarchyPrincipalReenableRespectsIndividuallyDisabledLauncher(t *testing.T) {
	db, laID, lbID := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	// B is individually disabled; A stays enabled.
	if _, err := app.disableLauncher(lbID); err != nil {
		t.Fatalf("disable launcher B: %v", err)
	}

	// Principal disable closes admission across both child Launchers.
	if _, err := app.disablePrincipalLaunchers("owner"); err != nil {
		t.Fatalf("disablePrincipalLaunchers: %v", err)
	}
	for _, id := range []string{laID, lbID} {
		if !app.OperationSupervisor.isLauncherQuiesced(id) {
			t.Fatalf("expected launcher %s quiesced while principal disabled", id)
		}
	}

	// Principal enable reopens only Launchers whose own launcher.enabled=true.
	if _, err := app.enablePrincipalLaunchers("owner"); err != nil {
		t.Fatalf("enablePrincipalLaunchers: %v", err)
	}
	if app.OperationSupervisor.isLauncherQuiesced(laID) {
		t.Fatal("expected launcher A admission open after principal re-enable")
	}
	if admitted := app.OperationSupervisor.admit(launcherRunningOp(t, laID)); !admitted {
		t.Fatal("expected operation admitted for enabled launcher A after principal re-enable")
	}
	if !app.OperationSupervisor.isLauncherQuiesced(lbID) {
		t.Fatal("expected individually-disabled launcher B to stay quiesced after principal re-enable")
	}
	if admitted := app.OperationSupervisor.admit(launcherRunningOp(t, lbID)); admitted {
		t.Fatal("expected operation refused for individually-disabled launcher B after principal re-enable")
	}
}

// TestHierarchyLauncherEnableWhilePrincipalDisabledStaysClosed (B): enabling a
// Launcher while its Principal remains disabled commits launcher.enabled=true
// but must keep runtime admission closed; it opens only once the Principal is
// re-enabled.
func TestHierarchyLauncherEnableWhilePrincipalDisabledStaysClosed(t *testing.T) {
	db, _, lbID := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	// B is individually disabled, then the whole Principal is disabled.
	if _, err := app.disableLauncher(lbID); err != nil {
		t.Fatalf("disable launcher B: %v", err)
	}
	if _, err := app.disablePrincipalLaunchers("owner"); err != nil {
		t.Fatalf("disablePrincipalLaunchers: %v", err)
	}

	// Enable Launcher B while the Principal is still disabled: launcher.enabled
	// becomes true, but runtime admission MUST remain closed.
	if err := app.enableLauncher(lbID); err != nil {
		t.Fatalf("enable launcher B while principal disabled: %v", err)
	}
	var lEnabled int
	if err := db.QueryRow(`SELECT enabled FROM launchers WHERE id=?`, lbID).Scan(&lEnabled); err != nil {
		t.Fatal(err)
	}
	if lEnabled != 1 {
		t.Fatalf("expected launcher B launcher.enabled=true after enable, got %d", lEnabled)
	}
	if !app.OperationSupervisor.isLauncherQuiesced(lbID) {
		t.Fatal("expected launcher B admission still closed while principal disabled")
	}
	if admitted := app.OperationSupervisor.admit(launcherRunningOp(t, lbID)); admitted {
		t.Fatal("expected operation refused for launcher B while principal disabled")
	}

	// Re-enabling the Principal now (launcher B is enabled) opens its admission.
	if _, err := app.enablePrincipalLaunchers("owner"); err != nil {
		t.Fatalf("enablePrincipalLaunchers: %v", err)
	}
	if app.OperationSupervisor.isLauncherQuiesced(lbID) {
		t.Fatal("expected launcher B admission open after principal re-enable")
	}
	if admitted := app.OperationSupervisor.admit(launcherRunningOp(t, lbID)); !admitted {
		t.Fatal("expected operation admitted for launcher B after principal re-enable")
	}
}

// TestHierarchyPrincipalDisableEnablePreservesLauncherEnabled (C): Principal
// disable/enable must not mutate any child Launcher.enabled value.
func TestHierarchyPrincipalDisableEnablePreservesLauncherEnabled(t *testing.T) {
	db, laID, lbID := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	// Leave A enabled, individually disable B.
	if _, err := app.disableLauncher(lbID); err != nil {
		t.Fatalf("disable launcher B: %v", err)
	}
	launcherEnabled := func(id string) int {
		t.Helper()
		var v int
		if err := db.QueryRow(`SELECT enabled FROM launchers WHERE id=?`, id).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	wantA, wantB := launcherEnabled(laID), launcherEnabled(lbID)

	if _, err := app.disablePrincipalLaunchers("owner"); err != nil {
		t.Fatalf("disablePrincipalLaunchers: %v", err)
	}
	if _, err := app.enablePrincipalLaunchers("owner"); err != nil {
		t.Fatalf("enablePrincipalLaunchers: %v", err)
	}

	if got := launcherEnabled(laID); got != wantA {
		t.Errorf("launcher A launcher.enabled mutated by principal disable/enable: got %d, want %d", got, wantA)
	}
	if got := launcherEnabled(lbID); got != wantB {
		t.Errorf("launcher B launcher.enabled mutated by principal disable/enable: got %d, want %d", got, wantB)
	}
}
