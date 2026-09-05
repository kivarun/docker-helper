package main

import (
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
	"slices"
	"strings"
	"sync"
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

	la, _, _, err := createLauncher(db, pid, "la", LauncherScopeInherit, nil, globalRoots, false)
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

// TestPersistLauncherChangeDisableInvalidatesOnlyOwnSessions proves a
// Launcher disable invalidates exactly that Launcher's Sessions transactionally
// while leaving sibling Launchers' Sessions valid.
func TestPersistLauncherChangeDisableInvalidatesOnlyOwnSessions(t *testing.T) {
	db, laID, lbID := launcherLifecycleDB(t)

	disabled := false
	result, err := persistLauncherChange(db, laID, nil, &disabled)
	if err != nil {
		t.Fatalf("persistLauncherChange: %v", err)
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

// TestPersistLauncherChangeDisableRetrySafe proves a re-invoked disable
// on an already-disabled Launcher still invalidates/cleans its Sessions rather
// than skipping cleanup because enabled was already false.
func TestPersistLauncherChangeDisableRetrySafe(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)

	disabled := false
	if _, err := persistLauncherChange(db, laID, nil, &disabled); err != nil {
		t.Fatalf("first disable: %v", err)
	}
	// Re-inject a Session to simulate one left behind by a prior partial
	// failure that retry must clean up.
	sum := sha256.Sum256([]byte("token-orphan"))
	if _, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id) VALUES (?, ?, ?, ?, ?, ?)`,
		"dhs_orphan", hex.EncodeToString(sum[:]), "/orphan", time.Now().Unix(), time.Now().Add(time.Hour).Unix(), laID); err != nil {
		t.Fatal(err)
	}

	result, err := persistLauncherChange(db, laID, nil, &disabled)
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

// TestPersistLauncherChangeEnableDoesNotRecreateSessions proves re-enable
// only flips enabled state and never recreates invalidated Sessions.
func TestPersistLauncherChangeEnableDoesNotRecreateSessions(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)

	disabled := false
	if _, err := persistLauncherChange(db, laID, nil, &disabled); err != nil {
		t.Fatalf("disable: %v", err)
	}
	enabled := true
	result, err := persistLauncherChange(db, laID, nil, &enabled)
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !result.Changed {
		t.Error("expected changed=true on enable")
	}
	if len(result.RevokedSessionIDs) != 0 {
		t.Errorf("expected no revoked sessions on enable, got %v", result.RevokedSessionIDs)
	}
	var enabledState, count int
	if err := db.QueryRow(`SELECT enabled FROM launchers WHERE id=?`, laID).Scan(&enabledState); err != nil {
		t.Fatal(err)
	}
	if enabledState != 1 {
		t.Error("expected launcher re-enabled")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id=?`, laID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected no sessions after re-enable, got %d", count)
	}
}

func TestPersistLauncherChangeNotFound(t *testing.T) {
	db, _, _ := launcherLifecycleDB(t)
	disabled := false
	if _, err := persistLauncherChange(db, "dhl_missing", nil, &disabled); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("expected ErrLauncherNotFound, got %v", err)
	}
}

// TestLauncherPatchRenameDisableAtomic proves the PATCH owner commits rename
// and disable as one transaction: when the durable enabled-state change fails
// after a successful rename, the rename rolls back with it — no partial rename
// is left behind, the Launcher stays enabled with its Sessions intact, and
// admission is restored for the still effectively-enabled Launcher. Under the
// former rename-then-disable sequence the rename would have persisted.
func TestLauncherPatchRenameDisableAtomic(t *testing.T) {
	db, dbPath := freshFileTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "owner")
	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}
	lID := l.ID
	sum := sha256.Sum256([]byte("token-patch"))
	if _, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id) VALUES (?, ?, ?, ?, ?, ?)`,
		"dhs_patch", hex.EncodeToString(sum[:]), "/patch", time.Now().Unix(), time.Now().Add(time.Hour).Unix(), lID); err != nil {
		t.Fatal(err)
	}

	// Fail exactly the durable enabled-state UPDATE, after the rename UPDATE
	// and the Session deletion have succeeded inside the same transaction.
	failDB := newFailExecMatchDB(t, dbPath, "UPDATE launchers SET enabled", errMockDeleteDB)
	app := deleteLifecycleApp(t, failDB)

	newName := "renamed"
	disabled := false
	_, _, err = app.updateLauncherWithLifecycle(lID, &newName, &disabled)
	if err == nil {
		t.Fatal("expected failing durable disable to fail the PATCH, got nil")
	} else if !errors.Is(err, errMockDeleteDB) {
		t.Fatalf("expected the original DB error to be preserved, got %v", err)
	}

	var name string
	if err := failDB.QueryRow(`SELECT name FROM launchers WHERE id = ?`, lID).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "work" {
		t.Fatalf("partial rename survived a failed disable: name = %q, want %q", name, "work")
	}
	if enabled, err := launcherEnabledState(failDB, lID); err != nil {
		t.Fatal(err)
	} else if !enabled {
		t.Fatal("expected launcher to stay enabled after failed PATCH disable")
	}
	var sessions int
	if err := failDB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id = ?`, lID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("expected the launcher's session to survive the failed PATCH, got %d", sessions)
	}
	if app.OperationSupervisor.isLauncherQuiesced(lID) {
		t.Fatal("supervisor must not stay quiesced after a failed PATCH disable of an enabled launcher")
	}
}

// TestLauncherPatchCollidingRenameAbortsDisable proves a rename that collides
// with a sibling Launcher's name aborts a requested disable as well: the whole
// transaction rolls back, leaving the Launcher enabled with its Sessions
// intact and its admission re-opened after the prologue quiesce.
func TestLauncherPatchCollidingRenameAbortsDisable(t *testing.T) {
	db, _ := freshFileTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "owner")
	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}
	if _, _, _, err := createLauncher(db, pid, "other", LauncherScopeInherit, nil, globalRoots, false); err != nil {
		t.Fatalf("createLauncher(other): %v", err)
	}
	lID := l.ID
	sum := sha256.Sum256([]byte("token-collide"))
	if _, err := db.Exec(`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id) VALUES (?, ?, ?, ?, ?, ?)`,
		"dhs_collide", hex.EncodeToString(sum[:]), "/collide", time.Now().Unix(), time.Now().Add(time.Hour).Unix(), lID); err != nil {
		t.Fatal(err)
	}

	app := deleteLifecycleApp(t, db)
	dup := "other"
	disabled := false
	if _, _, err := app.updateLauncherWithLifecycle(lID, &dup, &disabled); !errors.Is(err, ErrLauncherExists) {
		t.Fatalf("expected ErrLauncherExists, got: %v", err)
	}

	if enabled, err := launcherEnabledState(db, lID); err != nil {
		t.Fatal(err)
	} else if !enabled {
		t.Fatal("expected launcher to stay enabled after aborted PATCH")
	}
	var sessions int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id = ?`, lID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("expected the launcher's session to survive the aborted PATCH, got %d", sessions)
	}
	if app.OperationSupervisor.isLauncherQuiesced(lID) {
		t.Fatal("supervisor must not stay quiesced after an aborted PATCH disable")
	}
}

// TestLauncherCheckedDeleteCleansRuntimeDirsWhenRowRemovalFails proves a
// checked delete whose owner removal fails after the durable disable
// committed still runs the runtime-directory cleanup for the invalidated
// Sessions: the delete handler returns an error, but the revoked Session IDs
// are preserved through the failure instead of being dropped until daemon
// restart. Enters through the real DELETE handler.
func TestLauncherCheckedDeleteCleansRuntimeDirsWhenRowRemovalFails(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	globalRoots := app.Config.AllowedRoots
	home := filepath.Join(globalRoots[0], "home", "lnccleanrow")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(string) (string, string, string, error) {
		return "2001", "2001", home, nil
	}
	p, err := createPrincipal(app.DB, "lnccleanrow", globalRoots)
	if err != nil {
		t.Fatalf("createPrincipal: %v", err)
	}
	l, _, credToken, err := createLauncher(app.DB, int64(p.ID), "agent", LauncherScopeInherit, nil, globalRoots, true)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}

	workspace := filepath.Join(home, "proj")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	sessMux := http.NewServeMux()
	sessMux.HandleFunc("POST /sessions", app.handleCreateSession)
	sessReq := httptest.NewRequest(http.MethodPost, "/sessions",
		strings.NewReader(`{"workspace":"`+workspace+`"}`))
	sessReq.Header.Set("Authorization", "Bearer "+credToken)
	sessW := httptest.NewRecorder()
	sessMux.ServeHTTP(sessW, sessReq)
	if sessW.Code != http.StatusCreated {
		t.Fatalf("session create: expected 201, got %d (body=%s)", sessW.Code, sessW.Body.String())
	}
	var sessResp createSessionResponse
	if err := json.Unmarshal(sessW.Body.Bytes(), &sessResp); err != nil {
		t.Fatal(err)
	}
	sessionID := sessResp.Session.ID

	// Give cleanup something observable to remove.
	sessRTDir := sessionRuntimeDir(app.Config.RuntimeDir, sessionID)
	if err := os.MkdirAll(sessRTDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessRTDir, "sentinel"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	// Fail exactly the owner-removal exec: the durable disable's statements
	// (session deletion, enabled update) do not match, so the disable commits
	// and only DELETE FROM launchers fails.
	failDB := newFailExecMatchDB(t, app.Config.DatabasePath, "DELETE FROM launchers", errMockDeleteDB)
	app.DB = failDB

	delMux := http.NewServeMux()
	registerRoutes(delMux, app)
	delReq := httptest.NewRequest(http.MethodDelete, "/principals/lnccleanrow/launchers/"+l.ID, nil)
	withAdminToken(delReq)
	delW := httptest.NewRecorder()
	delMux.ServeHTTP(delW, delReq)
	if delW.Code != http.StatusInternalServerError {
		t.Fatalf("delete: expected 500, got %d (body=%s)", delW.Code, delW.Body.String())
	}

	// The invalidated session's runtime directory is cleaned even though the
	// delete failed.
	if _, err := os.Stat(sessRTDir); !os.IsNotExist(err) {
		t.Fatalf("session runtime dir survived the failed delete: %v", err)
	}
	// The durable disable committed; the launcher row remains.
	if enabled, err := launcherEnabledState(failDB, l.ID); err != nil {
		t.Fatal(err)
	} else if enabled {
		t.Fatal("expected launcher durably disabled after committed disable")
	}
	var sessions int
	if err := failDB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id = ?`, l.ID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("expected sessions invalidated, got %d", sessions)
	}
	var rows int
	if err := failDB.QueryRow(`SELECT COUNT(*) FROM launchers WHERE id = ?`, l.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("expected the launcher row to survive the failed owner removal, got %d rows", rows)
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

// launcherEnabledState reports the Launcher's current enabled value directly
// from the database, for asserting durable enabled state in lifecycle tests.
func launcherEnabledState(db *sql.DB, launcherID string) (bool, error) {
	var v int
	if err := db.QueryRow(`SELECT enabled FROM launchers WHERE id = ?`, launcherID).Scan(&v); err != nil {
		return false, fmt.Errorf("cannot read launcher enabled state: %w", err)
	}
	return v != 0, nil
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
	// The refusal is side-effect free: no Sessions were invalidated...
	if len(revoked) != 0 {
		t.Errorf("expected no sessions revoked by refused delete, got %v", revoked)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id=?`, laID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("expected sessions preserved by refused delete, got %d", count)
	}
	// ...and the Launcher stays enabled so it can be disabled explicitly first.
	if _, err := findLauncherByID(db, laID); err != nil {
		t.Fatalf("launcher row should be preserved: %v", err)
	}
	if enabled, err := launcherEnabledState(db, laID); err != nil {
		t.Fatal(err)
	} else if !enabled {
		t.Error("expected refused delete to leave launcher enabled")
	}
	// Admission is re-synced from the authorities: the prologue quiesce is
	// undone for the effectively-enabled Launcher, so Operations can be
	// admitted again without an enable/disable cycle.
	if app.OperationSupervisor.isLauncherQuiesced(laID) {
		t.Error("expected prologue quiesce undone after refused delete (launcher enabled)")
	}
	if admitted := app.OperationSupervisor.admit(launcherRunningOp(t, laID)); admitted != admissionAccepted {
		t.Error("expected operation admitted for launcher after refused delete restored admission")
	}
}

// TestDeleteLauncherCheckedActiveContainerRefusesWithoutProvenance proves
// restart-style detection: an attributable running container blocks deletion
// even with no in-memory operation provenance (labels are evidence). The 409
// is side-effect free: the Launcher stays enabled, its Sessions are preserved,
// and its operation admission is re-opened.
func TestDeleteLauncherCheckedActiveContainerRefusesWithoutProvenance(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		if launcherID == laID {
			return []helperContainer{{ID: "abc123", State: "running"}}, nil
		}
		return nil, nil
	}

	if _, err := app.deleteLauncherChecked(context.Background(), laID); !errors.Is(err, ErrLauncherRuntimeActive) {
		t.Fatalf("expected ErrLauncherRuntimeActive for running container, got %v", err)
	}
	// Launcher row preserved and enabled; sessions preserved.
	if _, err := findLauncherByID(db, laID); err != nil {
		t.Fatalf("launcher should be preserved: %v", err)
	}
	if enabled, err := launcherEnabledState(db, laID); err != nil {
		t.Fatal(err)
	} else if !enabled {
		t.Error("expected refused delete to leave launcher enabled")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id=?`, laID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("expected sessions preserved by refused delete, got %d", count)
	}
	if app.OperationSupervisor.isLauncherQuiesced(laID) {
		t.Error("expected prologue quiesce undone after refused delete (launcher enabled)")
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
			return []helperContainer{{ID: "stale123", State: "exited"}}, nil
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

// TestDeleteLauncherCheckedContainerStateClassification proves checked delete
// classifies every Docker container state explicitly: running/paused/
// restarting/removing refuse with ErrLauncherRuntimeActive and are never passed
// to docker rm, created/exited/dead are the only removable (stale) states, and
// an unrecognized state fails closed as a classification error without
// mutating the Launcher or its Sessions.
func TestDeleteLauncherCheckedContainerStateClassification(t *testing.T) {
	cases := []struct {
		name         string
		state        string
		wantActive   bool // ErrLauncherRuntimeActive refusal
		wantClassErr bool // fail-closed classification error
		wantRemoved  bool // container passed to docker rm
	}{
		{name: "running", state: "running", wantActive: true},
		{name: "paused", state: "paused", wantActive: true},
		{name: "restarting", state: "restarting", wantActive: true},
		{name: "removing", state: "removing", wantActive: true},
		{name: "created", state: "created", wantRemoved: true},
		{name: "exited", state: "exited", wantRemoved: true},
		{name: "dead", state: "dead", wantRemoved: true},
		{name: "unknown state fails closed", state: "zombie", wantClassErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
					return []helperContainer{{ID: "c1", State: tc.state}}, nil
				}
				return nil, nil
			}

			_, err := app.deleteLauncherChecked(context.Background(), laID)

			switch {
			case tc.wantActive:
				if !errors.Is(err, ErrLauncherRuntimeActive) {
					t.Fatalf("state %q: expected ErrLauncherRuntimeActive, got %v", tc.state, err)
				}
			case tc.wantClassErr:
				if err == nil || errors.Is(err, ErrLauncherRuntimeActive) {
					t.Fatalf("state %q: expected fail-closed classification error, got %v", tc.state, err)
				}
			default:
				if err != nil {
					t.Fatalf("state %q: expected delete to succeed, got %v", tc.state, err)
				}
			}

			// Active and unclassifiable states are never passed to docker rm.
			if (tc.wantActive || tc.wantClassErr) && len(removed) != 0 {
				t.Errorf("state %q: container passed to docker rm: %v", tc.state, removed)
			}
			if tc.wantRemoved && (len(removed) != 1 || removed[0] != "c1") {
				t.Errorf("state %q: expected stale container removed, got %v", tc.state, removed)
			}

			if !tc.wantRemoved {
				// The refusal is side-effect free: the Launcher row, its
				// enabled state, and its Sessions are untouched, and admission
				// is re-opened.
				if _, err := findLauncherByID(db, laID); err != nil {
					t.Fatalf("state %q: launcher should be preserved: %v", tc.state, err)
				}
				if enabled, err := launcherEnabledState(db, laID); err != nil {
					t.Fatal(err)
				} else if !enabled {
					t.Errorf("state %q: expected refusal to leave launcher enabled", tc.state)
				}
				var count int
				if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id=?`, laID).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 2 {
					t.Errorf("state %q: expected sessions preserved by refusal, got %d", tc.state, count)
				}
				if app.OperationSupervisor.isLauncherQuiesced(laID) {
					t.Errorf("state %q: expected prologue quiesce undone after refusal", tc.state)
				}
			}
		})
	}
}

// TestDeleteLauncherCheckedStaleRemovalFailureAborts proves stale-container
// removal is authoritative: a docker rm failure aborts the delete before any
// durable state changes, leaving the Launcher enabled with its Sessions
// preserved and its admission re-opened, so the operator can retry.
func TestDeleteLauncherCheckedStaleRemovalFailureAborts(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "false")
	}
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		if launcherID == laID {
			return []helperContainer{{ID: "stale123", State: "exited"}}, nil
		}
		return nil, nil
	}

	if _, err := app.deleteLauncherChecked(context.Background(), laID); err == nil {
		t.Fatal("expected stale-removal failure to abort the delete, got nil")
	}
	if _, err := findLauncherByID(db, laID); err != nil {
		t.Fatalf("launcher should be preserved on stale-removal failure: %v", err)
	}
	if enabled, err := launcherEnabledState(db, laID); err != nil {
		t.Fatal(err)
	} else if !enabled {
		t.Error("expected aborted delete to leave launcher enabled")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE launcher_id=?`, laID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("expected sessions preserved by aborted delete, got %d", count)
	}
	if app.OperationSupervisor.isLauncherQuiesced(laID) {
		t.Error("expected prologue quiesce undone after aborted delete (launcher enabled)")
	}
}

// TestDeleteLauncherCheckedInspectErrorFailClosed proves an unclassifiable
// inspection preserves the Launcher, refuses the delete, and — because the
// runtime could not be classified rather than being confirmed active — leaves
// the Launcher exactly as it was: enabled, Sessions preserved, and admission
// re-opened instead of wedged. This is the UAT regression where a Docker
// inspection failure must not wedge a Launcher.
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
	// The Launcher row is preserved.
	if _, err := findLauncherByID(db, laID); err != nil {
		t.Fatalf("launcher should be preserved on inspect failure: %v", err)
	}
	// The Launcher stays enabled (never durably disabled by the refusal).
	if enabled, err := launcherEnabledState(db, laID); err != nil {
		t.Fatal(err)
	} else if !enabled {
		t.Errorf("expected inspect-failure delete to leave launcher enabled=1")
	}
	// Admission is re-opened: a fresh Operation for the Launcher can be admitted
	// again, exactly as the post-UAT mount-pin/session flow requires.
	if app.OperationSupervisor.isLauncherQuiesced(laID) {
		t.Error("expected launcher admission re-opened after inspect-failure delete (not quiesced)")
	}
	if admitted := app.OperationSupervisor.admit(launcherRunningOp(t, laID)); admitted != admissionAccepted {
		t.Error("expected operation admitted for launcher after inspect-failure delete restored it")
	}
}

// TestDeleteLauncherCheckedInspectErrorPreservesDisabledLauncher proves that a
// Launcher which was ALREADY individually disabled before a delete attempt stays
// disabled and admission-closed when the delete then fails on inspection: the
// restore must not reopen a launcher the operator had intentionally disabled.
func TestDeleteLauncherCheckedInspectErrorPreservesDisabledLauncher(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)
	if _, err := app.disableLauncher(laID); err != nil {
		t.Fatalf("disable launcher: %v", err)
	}
	sentinel := errors.New("inspect failure")
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		return nil, sentinel
	}

	if _, err := app.deleteLauncherChecked(context.Background(), laID); !errors.Is(err, sentinel) {
		t.Fatalf("expected inspect error propagated, got %v", err)
	}
	var enabled int
	if err := db.QueryRow(`SELECT enabled FROM launchers WHERE id=?`, laID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Errorf("expected previously-disabled launcher to stay disabled, got %d", enabled)
	}
	if !app.OperationSupervisor.isLauncherQuiesced(laID) {
		t.Error("expected previously-disabled launcher to stay admission-closed")
	}
}

// TestDeleteLauncherCheckedRetryAfterExit proves a delete refused while a
// container runs succeeds after the runtime exits and inspection is revised.
func TestDeleteLauncherCheckedRetryAfterExit(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)
	// Stale-container removal is authoritative, so the retry's docker rm must
	// succeed for the delete to complete.
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	running := true
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		if launcherID == laID {
			if running {
				return []helperContainer{{ID: "abc123", State: "running"}}, nil
			}
			return []helperContainer{{ID: "abc123", State: "exited"}}, nil
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
	// Stale-container removal is authoritative, so the successful delete's
	// docker rm must succeed.
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	running := true
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		if launcherID == laID {
			if running {
				return []helperContainer{{ID: "abc123", State: "running"}}, nil
			}
			return []helperContainer{{ID: "abc123", State: "exited"}}, nil
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

// TestDeletePrincipalCheckedInspectErrorRestoresLaunchers proves the UAT
// scenario: when runtime inspection fails (e.g. Docker CLI unavailable on a
// confined host), a Principal delete is refused AND its Launchers are left
// enabled with admission re-opened. It must never leave the Principal
// half-torn-down with all Launchers durably disabled, which would wedge every
// subsequent session create for that Principal.
func TestDeletePrincipalCheckedInspectErrorRestoresLaunchers(t *testing.T) {
	db, laID, lbID := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)
	sentinel := errors.New("inspect failure")
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		return nil, sentinel
	}

	if _, err := app.deletePrincipalChecked(context.Background(), "owner"); !errors.Is(err, sentinel) {
		t.Fatalf("expected inspect error propagated, got %v", err)
	}
	// Principal and Launcher rows preserved.
	if _, err := findPrincipalByUsername(db, "owner"); err != nil {
		t.Fatalf("principal should be preserved: %v", err)
	}
	if _, err := findLauncherByID(db, laID); err != nil {
		t.Fatalf("launcher a should be preserved: %v", err)
	}
	if _, err := findLauncherByID(db, lbID); err != nil {
		t.Fatalf("launcher b should be preserved: %v", err)
	}
	// Every Launcher stays enabled with admission re-opened so fresh Sessions
	// and Operations can be created afterwards (the mount-pin/session flow
	// that previously failed with "launcher is not available").
	for _, id := range []string{laID, lbID} {
		enabled, err := launcherEnabledState(db, id)
		if err != nil {
			t.Fatal(err)
		}
		if !enabled {
			t.Errorf("expected launcher %s to stay enabled=1 after inspect-failure principal delete", id)
		}
		if app.OperationSupervisor.isLauncherQuiesced(id) {
			t.Errorf("expected launcher %s admission re-opened after inspect-failure principal delete", id)
		}
	}
}

// TestInspectHelperContainersParsesAndFailsClosed exercises the real
// Docker-CLI parsing path: well-formed lines are classified, malformed lines
// fail closed so a Launcher is never deleted unclassifiably.
func TestInspectHelperContainersParsesAndFailsClosed(t *testing.T) {
	app := deleteLifecycleApp(t, openFreshTestDB(t))

	cases := []struct {
		name       string
		output     string
		wantIDs    []string
		wantStates []string
		wantErr    bool
	}{
		{name: "empty", output: "", wantIDs: nil, wantStates: nil},
		{name: "one running", output: "abc123 running\n", wantIDs: []string{"abc123"}, wantStates: []string{"running"}},
		{name: "one exited", output: "def456 exited", wantIDs: []string{"def456"}, wantStates: []string{"exited"}},
		{name: "one created", output: "ghi789 created", wantIDs: []string{"ghi789"}, wantStates: []string{"created"}},
		{name: "one paused", output: "jkl012 paused", wantIDs: []string{"jkl012"}, wantStates: []string{"paused"}},
		{name: "blank lines ignored", output: "\nabc123 running\n\n", wantIDs: []string{"abc123"}, wantStates: []string{"running"}},
		{name: "malformed fails closed", output: "abc123 running extra\n", wantErr: true},
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
				if got[i].State != tc.wantStates[i] {
					t.Errorf("container[%d] state: expected %q, got %q", i, tc.wantStates[i], got[i].State)
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
			return []helperContainer{{ID: "runningB", State: "running"}}, nil
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
// has quiesced operation admission for the launcher, but BEFORE the durable
// disable) until the test releases it. It returns a channel that is closed when
// the delete is parked at the runtime check, and a release channel the test
// closes to let the delete proceed.
func quiesceBarrierApp(t *testing.T, db *sql.DB) (*App, chan struct{}, chan struct{}) {
	t.Helper()
	app := deleteLifecycleApp(t, db)
	atQuiesce := make(chan struct{})
	release := make(chan struct{})
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		// The seam is invoked at the side-effect-free runtime-check point,
		// which checked deletion reaches after quiescing operation admission
		// but before the durable disable, while still holding the lifecycle
		// lock. Blocking here deterministically parks the delete at its
		// admission-closing point before the durable transitions and owner
		// removal.
		close(atQuiesce)
		<-release
		return nil, nil
	}
	return app, atQuiesce, release
}

// TestRaceLauncherConcurrentOperationAdmissionRefused proves that once checked
// deletion crosses its admission-closing point (quiesce, before the runtime
// check), a concurrent Operation admission for that Launcher is refused. Without
// the quiesce, the delete would remove the Launcher while that Operation runs.
func TestRaceLauncherConcurrentOperationAdmissionRefused(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app, atQuiesce, release := quiesceBarrierApp(t, db)

	var deleteErr error
	deleteDone := make(chan struct{})
	go func() {
		defer close(deleteDone)
		_, deleteErr = app.deleteLauncherChecked(context.Background(), laID)
	}()

	// Wait until the delete has quiesced the launcher and is parked at the
	// side-effect-free runtime check, before the durable disable and row
	// removal.
	<-atQuiesce

	// A session that was already authorized before the quiesce now tries to
	// admit a running Operation for this Launcher, concurrently with the delete.
	op := newTestOperation(t, operationRunning, time.Time{})
	op.LauncherID = laID
	if admitted := app.OperationSupervisor.admit(op); admitted == admissionAccepted {
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

// TestRaceNoNewSessionAfterCheckedDelete proves that a concurrent Session
// creation for a Launcher under checked deletion cannot slip in mid-delete: the
// create serializes behind the delete's lifecycle lock and, once the owner is
// removed, refuses with launcher-not-found.
func TestRaceNoNewSessionAfterCheckedDelete(t *testing.T) {
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

	// A concurrent Session creation for this Launcher is serialized behind the
	// delete's lifecycle lock — it cannot complete while the delete is parked —
	// and once the delete removes the owner it must be refused rather than
	// producing a Session against a deleted Launcher.
	createDone := make(chan error, 1)
	go func() {
		_, err := app.createSessionWithPolicy(&sessionCreatePolicy{
			Workspace:             ws,
			EffectiveAllowedRoots: app.Config.AllowedRoots,
			LauncherID:            laID,
			LauncherName:          "default",
			PrincipalName:         "owner",
		})
		createDone <- err
	}()

	close(release)
	<-deleteDone
	if deleteErr != nil {
		t.Fatalf("delete should succeed, got %v", deleteErr)
	}
	if err := <-createDone; err == nil {
		t.Fatal("session admitted for launcher after checked deletion removed the owner")
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

// TestRaceLauncherSessionResolvedBeforeRefusedDeleteCanAdmit proves a refused
// (409) checked delete does not wedge the Launcher: the refusal is side-effect
// free (Sessions and enabled state preserved) and re-opens operation admission,
// so an in-flight request that resolved its Session before the delete — and was
// paused before admit() — can still admit once the DELETE has returned, exactly
// as the enabled Launcher's live Sessions require.
func TestRaceLauncherSessionResolvedBeforeRefusedDeleteCanAdmit(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	// The in-flight request resolves its Session through the real production
	// path BEFORE the delete. The session exists and launcher+principal are
	// enabled, so resolution succeeds.
	sess, err := app.findSessionByToken("token-dhs_a")
	if err != nil {
		t.Fatalf("session should resolve before delete: %v", err)
	}

	resolved := make(chan struct{})
	release := make(chan struct{})
	admitted := make(chan admissionDecision, 1)
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
	// The refusal is side-effect free: the Launcher stays enabled and its
	// Sessions (including the resolved one) are preserved, so its admission
	// must be re-opened.
	if enabled, err := launcherEnabledState(db, laID); err != nil {
		t.Fatal(err)
	} else if !enabled {
		t.Fatal("expected launcher still enabled after refused delete")
	}
	if _, err := app.findSessionByToken("token-dhs_a"); err != nil {
		t.Fatalf("expected resolved session preserved by refused delete, got %v", err)
	}
	if app.OperationSupervisor.isLauncherQuiesced(laID) {
		t.Fatal("expected launcher admission re-opened after refused delete")
	}

	// Release the paused in-flight request. Its admission must be accepted: the
	// delete was refused, the owner and Session are live, and the refusal
	// re-opened admission.
	close(release)
	if got := <-admitted; got != admissionAccepted {
		t.Fatalf("in-flight request refused after side-effect-free refused delete (decision %v); wedged launcher", got)
	}
}

// TestRaceLauncherSessionResolvedBeforeSuccessfulDeleteCannotAdmit proves the
// vanishing-owner guard: a request that resolved its Session before a checked
// delete that SUCCEEDS must not admit an Operation afterwards. Its Session was
// invalidated by the delete's disable, and the supervisor's quiesce entry —
// which deliberately outlives the owner removal — refuses the admission, so no
// Operation can run against a Launcher whose owner row is already gone.
func TestRaceLauncherSessionResolvedBeforeSuccessfulDeleteCannotAdmit(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	// The in-flight request resolves its Session through the real production
	// path BEFORE the delete.
	sess, err := app.findSessionByToken("token-dhs_a")
	if err != nil {
		t.Fatalf("session should resolve before delete: %v", err)
	}

	resolved := make(chan struct{})
	release := make(chan struct{})
	admitted := make(chan admissionDecision, 1)
	go func() {
		close(resolved)
		<-release
		pausedOp := newTestOperation(t, operationRunning, time.Time{})
		pausedOp.LauncherID = sess.LauncherID
		admitted <- app.OperationSupervisor.admit(pausedOp)
	}()

	// Pause the in-flight request right after its Session resolution, before
	// admit(). Meanwhile, DELETE the Launcher; no attributable runtime is
	// active, so the delete succeeds.
	<-resolved
	if _, err := app.deleteLauncherChecked(context.Background(), laID); err != nil {
		t.Fatalf("delete should succeed with no active runtime, got %v", err)
	}
	if _, err := findLauncherByID(db, laID); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("expected launcher deleted, got %v", err)
	}

	// Release the paused in-flight request. Its admission must be refused even
	// though the DELETE has already returned: the quiesce set by the delete
	// outlives the owner removal.
	close(release)
	if got := <-admitted; got == admissionAccepted {
		t.Fatal("in-flight request admitted after owner removal; would run with no persisted owner")
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
	if admitted := app.OperationSupervisor.admit(op()); admitted == admissionAccepted {
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
	if admitted := app.OperationSupervisor.admit(fresh); admitted != admissionAccepted {
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
		if admitted := app.OperationSupervisor.admit(opFor(id)); admitted == admissionAccepted {
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
		if admitted := app.OperationSupervisor.admit(opFor(id)); admitted != admissionAccepted {
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
	if admitted := app.OperationSupervisor.admit(launcherRunningOp(t, laID)); admitted != admissionAccepted {
		t.Fatal("expected operation admitted for enabled launcher A after principal re-enable")
	}
	if !app.OperationSupervisor.isLauncherQuiesced(lbID) {
		t.Fatal("expected individually-disabled launcher B to stay quiesced after principal re-enable")
	}
	if admitted := app.OperationSupervisor.admit(launcherRunningOp(t, lbID)); admitted == admissionAccepted {
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
	if admitted := app.OperationSupervisor.admit(launcherRunningOp(t, lbID)); admitted == admissionAccepted {
		t.Fatal("expected operation refused for launcher B while principal disabled")
	}

	// Re-enabling the Principal now (launcher B is enabled) opens its admission.
	if _, err := app.enablePrincipalLaunchers("owner"); err != nil {
		t.Fatalf("enablePrincipalLaunchers: %v", err)
	}
	if app.OperationSupervisor.isLauncherQuiesced(lbID) {
		t.Fatal("expected launcher B admission open after principal re-enable")
	}
	if admitted := app.OperationSupervisor.admit(launcherRunningOp(t, lbID)); admitted != admissionAccepted {
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

// TestRaceLauncherDeleteExcludesConcurrentEnable proves the lifecycle lock
// serializes a checked Launcher delete against a concurrent enable that contends
// for the same ownership. The delete holds lifecycleMu across its side-effect-
// free runtime check (after the quiesce prologue and before the durable disable
// and owner removal), so the concurrent enable cannot reach its own critical
// section and reopen operation admission before the delete removes the Launcher
// row; once the delete releases the lock the enable runs and finds the owner
// gone (ErrLauncherNotFound), rather than resurrecting an owner for an Operation.
// This is proven deterministically by (a) the point-in-time state at the barrier
// and (b) the enable's final outcome, both of which require the serialization.
func TestRaceLauncherDeleteExcludesConcurrentEnable(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app, atQuiesce, release := quiesceBarrierApp(t, db)

	var deleteErr error
	deleteDone := make(chan struct{})
	go func() {
		defer close(deleteDone)
		_, deleteErr = app.deleteLauncherChecked(context.Background(), laID)
	}()

	// The delete has quiesced the launcher and parked at the side-effect-free
	// runtime check, still holding lifecycleMu.
	<-atQuiesce

	// Launch a concurrent enable that contends for the same lifecycle lock.
	enableDone := make(chan error, 1)
	go func() {
		enableDone <- app.enableLauncher(laID)
	}()

	// Point-in-time state at the barrier: the check is side-effect free, so the
	// Launcher is NOT yet disabled (the durable disable happens only after the
	// check passes), and the delete's prologue quiesce stands — proving the
	// serialized enable has not interleaved (it would have cleared the
	// quiesce).
	if enabled, err := launcherEnabledState(db, laID); err != nil {
		t.Fatal(err)
	} else if !enabled {
		t.Fatal("launcher disabled before the runtime check completed; check is not side-effect free")
	}
	if !app.OperationSupervisor.isLauncherQuiesced(laID) {
		t.Fatal("operation admission reopened while the delete holds the lifecycle lock")
	}
	op := newTestOperation(t, operationRunning, time.Time{})
	op.LauncherID = laID
	if app.OperationSupervisor.admit(op) == admissionAccepted {
		t.Fatal("operation admitted against a launcher being concurrently deleted")
	}

	close(release)
	<-deleteDone
	if deleteErr != nil {
		t.Fatalf("delete should succeed, got %v", deleteErr)
	}

	// Final outcome: because the delete held lifecycleMu across the row removal,
	// the serialized enable runs only after the owner is gone. It must refuse
	// (ErrLauncherNotFound) rather than reopen admission for a vanishing owner.
	if err := <-enableDone; !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("concurrent enable should refuse the deleted launcher, got %v", err)
	}
	if _, err := findLauncherByID(db, laID); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("expected launcher deleted, got %v", err)
	}
}

// TestRacePrincipalDeleteExcludesConcurrentLauncherCreate proves the lifecycle
// lock serializes a checked Principal delete against a concurrent Launcher
// create that contends for the same ownership beneath that Principal. The delete
// holds lifecycleMu across its runtime inspection, so no Launcher can be created
// (unchecked) while the delete owns the ownership; the create's locked section
// (inside handleCreateLauncher) runs only after the delete's critical section.
// After the delete wins, the create fails principal-not-found. Proven
// deterministically by (a) the point-in-time launcher count at the barrier and
// (b) the create's final 404. The create is driven through the real locked
// handler.
func TestRacePrincipalDeleteExcludesConcurrentLauncherCreate(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()
	setupLauncherHandlerPrincipal(t, app, "owner")

	atInspect := make(chan struct{})
	release := make(chan struct{})
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		close(atInspect)
		<-release
		return nil, nil
	}
	// One launcher beneath the Principal so the delete has something to inspect.
	pid := principalIDByName(t, app.DB, "owner")
	mustAddDefaultLauncher(t, app.DB, pid)

	var deleteCode int
	deleteDone := make(chan struct{})
	go func() {
		defer close(deleteDone)
		deleteCode = launcherRequest(t, app, http.MethodDelete, "/principals/owner", testAdminToken, "").Code
	}()

	// The delete has quiesced the launcher and parked at the side-effect-free
	// runtime check, still holding lifecycleMu.
	<-atInspect

	// Launch a concurrent Launcher create that contends for the same lifecycle
	// lock as the delete.
	createDone := make(chan int, 1)
	go func() {
		createDone <- launcherRequest(t, app, http.MethodPost, "/principals/owner/launchers", testAdminToken,
			`{"name":"new","scope":"inherit"}`).Code
	}()

	// Point-in-time barrier: no Launcher was created mid-delete — the Principal
	// still has exactly its single launcher (the delete's quiesce prologue
	// stands).
	ids, err := principalLaunchers(app.DB, pid)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected no launcher created mid-delete (1 total), got %d", len(ids))
	}

	close(release)
	<-deleteDone
	if deleteCode != http.StatusNoContent {
		t.Fatalf("delete principal: expected 204, got %d", deleteCode)
	}

	// After the delete wins (Principal removed), the create fails
	// principal-not-found rather than producing an orphaned/unchecked launcher.
	if code := <-createDone; code != http.StatusNotFound {
		t.Fatalf("concurrent create after principal delete: expected 404, got %d", code)
	}
}

// TestRaceConcurrentDisableEnableFinalAdmissionAgrees proves that bursts of
// concurrent Launcher disable/enable, serialized by the lifecycle lock, always
// leave the supervisor admission agreeing with the durable hierarchical
// authorities (Principal.enabled && Launcher.enabled). It forbids the two
// inconsistent states: enabled=false + unquiesced, and effectively-enabled +
// quiesced.
func TestRaceConcurrentDisableEnableFinalAdmissionAgrees(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	const rounds = 50
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < rounds; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			app.disableLauncher(laID)
		}()
		go func() {
			defer wg.Done()
			<-start
			app.enableLauncher(laID)
		}()
	}
	close(start)
	wg.Wait()

	// Final invariant: supervisor admission agrees with durable authorities.
	closed, err := effectiveLauncherClosed(db, laID)
	if err != nil {
		t.Fatal(err)
	}
	if got := app.OperationSupervisor.isLauncherQuiesced(laID); got != closed {
		t.Fatalf("final supervisor admission disagrees with durable authorities: quiesced=%v effectiveClosed=%v", got, closed)
	}
}

// TestRaceInspectionErrorRestoreExcludesConcurrentEnable proves the lifecycle
// lock also serializes a concurrent enable against an inspection-error delete,
// so the checked-deletion refusal cannot be overwritten by a concurrent
// transition. The delete parks at the runtime check (holding lifecycleMu), the
// inspection errors, and the concurrent enable can only run after the delete
// releases the lock; it then runs against the already-restored, re-synced state
// and leaves admission consistent with the durable authorities. This preserves
// the 0a36d16 inspection-error refusal semantics under concurrency. Proven
// deterministically by the point-in-time admit() refusal at the barrier and the
// final restored-state + admission-consistency assertions.
func TestRaceInspectionErrorRestoreExcludesConcurrentEnable(t *testing.T) {
	db, laID, _ := launcherLifecycleDB(t)
	app := deleteLifecycleApp(t, db)

	atInspect := make(chan struct{})
	release := make(chan struct{})
	sentinel := errors.New("docker cli unavailable")
	app.InspectHelperContainers = func(ctx context.Context, launcherID string) ([]helperContainer, error) {
		close(atInspect)
		<-release
		return nil, sentinel
	}

	var deleteErr error
	deleteDone := make(chan struct{})
	go func() {
		defer close(deleteDone)
		_, deleteErr = app.deleteLauncherChecked(context.Background(), laID)
	}()

	<-atInspect

	// Launch a concurrent enable that contends for the same lifecycle lock.
	enableDone := make(chan error, 1)
	go func() {
		enableDone <- app.enableLauncher(laID)
	}()

	// Point-in-time barrier: operation admission must be refused while the
	// delete owns the ownership and the enable contends for the same lock.
	op := newTestOperation(t, operationRunning, time.Time{})
	op.LauncherID = laID
	if app.OperationSupervisor.admit(op) == admissionAccepted {
		t.Fatal("operation admitted while delete pending and enable serialized behind it")
	}

	close(release)
	<-deleteDone
	if !errors.Is(deleteErr, sentinel) {
		t.Fatalf("expected inspection error to refuse the delete, got %v", deleteErr)
	}
	// The side-effect-free refusal left the Launcher enabled.
	if enabled, err := launcherEnabledState(db, laID); err != nil {
		t.Fatal(err)
	} else if !enabled {
		t.Fatal("inspection-error delete did not leave the launcher enabled")
	}
	// The serialized enable now runs against the restored, re-synced state and
	// must leave admission consistent with the durable authorities.
	if err := <-enableDone; err != nil {
		t.Fatalf("enable after restore should succeed, got %v", err)
	}
	closed, err := effectiveLauncherClosed(db, laID)
	if err != nil {
		t.Fatal(err)
	}
	if got := app.OperationSupervisor.isLauncherQuiesced(laID); got != closed {
		t.Fatalf("admission disagrees with authorities after restore+enable: quiesced=%v effectiveClosed=%v", got, closed)
	}
}

// freshFileTestDB opens and initializes a fresh SQLite database at a known path
// under t's temp dir, returning the live *sql.DB and the path. The path is
// exposed so a test can reopen the same committed file through a failing
// driver (newFailExecDB / newFailQueryAfterDB) to exercise error paths
// deterministically against a real, already-populated schema.
func freshFileTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase: %v", err)
	}
	return db, dbPath
}

// TestDisableFailedRepeatedDisableKeepsSupervisorQuiesced (A): a repeated disable
// of an ALREADY-disabled Launcher whose DB transition fails must NOT re-open
// admission. The durable authority (launcher.enabled=false) keeps the supervisor
// quiesced. This is the fail-closed error-path restoration that replaced the old
// unconditional re-open.
func TestDisableFailedRepeatedDisableKeepsSupervisorQuiesced(t *testing.T) {
	db, dbPath := freshFileTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "owner")
	la, _, _, err := createLauncher(db, pid, "la", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}
	laID := la.ID

	// Disable the launcher for real first, so it is already disabled before the
	// failing repeated disable, and its Sessions are gone.
	disabled := false
	if _, err := persistLauncherChange(db, laID, nil, &disabled); err != nil {
		t.Fatalf("initial disable: %v", err)
	}
	if enabled, err := launcherEnabledState(db, laID); err != nil {
		t.Fatal(err)
	} else if enabled {
		t.Fatal("expected launcher already disabled before failing repeated disable")
	}

	// Reopen the same committed file with a driver that fails every Exec, so the
	// repeated disable's DB transition fails deterministically while reads (the
	// post-failure authority re-read) still work.
	failDB := newFailExecDB(t, dbPath, errMockCreateDB)
	app := deleteLifecycleApp(t, failDB)

	if _, err := app.disableLauncher(laID); err == nil {
		t.Fatal("expected repeated disable to fail, got nil")
	} else if !errors.Is(err, errMockCreateDB) {
		t.Fatalf("expected the original DB error to be preserved, got %v", err)
	}

	// Durable authority still says disabled...
	if enabled, err := launcherEnabledState(failDB, laID); err != nil {
		t.Fatal(err)
	} else if enabled {
		t.Fatal("expected enabled=false after failed repeated disable")
	}
	// ...and admission must remain quiesced (fail closed, not re-opened).
	if !app.OperationSupervisor.isLauncherQuiesced(laID) {
		t.Fatal("supervisor must remain quiesced after failed repeated disable of an already-disabled launcher")
	}
}

// TestPrincipalDisableFailureRestoresAdmissionPerChildAuthorities (B): when a
// Principal disable's DB transition fails, with Launcher A enabled and Launcher
// B individually disabled, A must be restored admission-open while B remains
// admission-closed, and neither child's launcher.enabled flag may change. The
// old unconditional re-open of every child would have wrongly opened B.
func TestPrincipalDisableFailureRestoresAdmissionPerChildAuthorities(t *testing.T) {
	db, dbPath := freshFileTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "owner")
	la, _, _, err := createLauncher(db, pid, "a", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatalf("createLauncher(a): %v", err)
	}
	lb, _, _, err := createLauncher(db, pid, "b", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatalf("createLauncher(b): %v", err)
	}
	laID, lbID := la.ID, lb.ID

	// B is individually disabled; A stays enabled.
	disabled := false
	if _, err := persistLauncherChange(db, lbID, nil, &disabled); err != nil {
		t.Fatalf("disable launcher B: %v", err)
	}

	// Reopen the same committed file with a driver that fails every Exec, so the
	// Principal disable transition fails deterministically while reads (the
	// per-child authority re-reads) still work.
	failDB := newFailExecDB(t, dbPath, errMockDeleteDB)
	app := deleteLifecycleApp(t, failDB)

	if _, err := app.disablePrincipalLaunchers("owner"); err == nil {
		t.Fatal("expected principal disable to fail, got nil")
	} else if !errors.Is(err, errMockDeleteDB) {
		t.Fatalf("expected the original principal DB error preserved, got %v", err)
	}

	// A is restored admission-open (Principal still enabled && A enabled).
	if app.OperationSupervisor.isLauncherQuiesced(laID) {
		t.Fatal("expected launcher A admission open after failed principal disable")
	}
	if admitted := app.OperationSupervisor.admit(launcherRunningOp(t, laID)); admitted != admissionAccepted {
		t.Fatal("expected operation admitted for enabled launcher A after failed principal disable")
	}
	// B remains admission-closed (individually disabled).
	if !app.OperationSupervisor.isLauncherQuiesced(lbID) {
		t.Fatal("expected individually-disabled launcher B to remain quiesced after failed principal disable")
	}
	if admitted := app.OperationSupervisor.admit(launcherRunningOp(t, lbID)); admitted == admissionAccepted {
		t.Fatal("expected operation refused for individually-disabled launcher B after failed principal disable")
	}
	// Child enabled flags unchanged: A still enabled, B still disabled.
	if enabled, err := launcherEnabledState(failDB, laID); err != nil {
		t.Fatal(err)
	} else if !enabled {
		t.Fatal("expected launcher A still enabled")
	}
	if enabled, err := launcherEnabledState(failDB, lbID); err != nil {
		t.Fatal(err)
	} else if enabled {
		t.Fatal("expected launcher B still disabled")
	}
}

// TestDisableAuthorityReReadFailureKeepsAdmissionQuiesced (C): when the disable's
// DB transition fails AND the subsequent durable-authority re-read also fails,
// admission must remain quiesced (fail closed) — never re-opened. The launchers
// table is dropped so both the disable's own read and the recovery re-read fail
// with a real SQL error.
func TestDisableAuthorityReReadFailureKeepsAdmissionQuiesced(t *testing.T) {
	db, _ := freshFileTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "owner")
	la, _, _, err := createLauncher(db, pid, "la", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}
	laID := la.ID

	// Drop the launchers table so every launcher read — including the disable's
	// own authority read and the post-failure recovery re-read — fails with a
	// real SQL error. Admission must stay quiesced (fail closed).
	dropTableBreakFK(t, db, "launchers")
	app := deleteLifecycleApp(t, db)

	if _, err := app.disableLauncher(laID); err == nil {
		t.Fatal("expected disable to fail when the launchers table is broken, got nil")
	}
	if !app.OperationSupervisor.isLauncherQuiesced(laID) {
		t.Fatal("admission must remain quiesced when the authoritative re-read itself fails (fail closed)")
	}
}

// TestLauncherEnableCommitsWithoutPostCommitLookup proves the enable path can
// no longer produce a "committed but 500": with every query after the
// pre-commit reads rejected, the enable succeeds, applies its admission
// decision (reopening the prologue-quiesced Launcher), and persists
// enabled=true. Under the former post-commit admission re-read, that extra
// query would be rejected here after the durable success.
func TestLauncherEnableCommitsWithoutPostCommitLookup(t *testing.T) {
	db, dbPath := freshFileTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "owner")
	l, _, _, err := createLauncher(db, pid, "la", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}
	lID := l.ID

	// Disable for real first, so the enable is a genuine transition.
	disabled := false
	if _, err := persistLauncherChange(db, lID, nil, &disabled); err != nil {
		t.Fatalf("initial disable: %v", err)
	}

	// The PATCH owner performs two projection-lookup queries and the
	// transition's own authority read before commit; permit exactly those and
	// fail every later query.
	failDB := newFailQueryAfterDB(t, dbPath, 3, errMockQueryFail)
	app := deleteLifecycleApp(t, failDB)
	// Mirror the disabled-state runtime companion so the committed enable must
	// reopen admission in memory.
	app.OperationSupervisor.quiesceLauncher(lID)

	enabled := true
	if _, _, err := app.updateLauncherWithLifecycle(lID, nil, &enabled); err != nil {
		t.Fatalf("enable under post-commit query failure: %v", err)
	}

	if enabledState, err := launcherEnabledState(db, lID); err != nil {
		t.Fatal(err)
	} else if !enabledState {
		t.Fatal("expected launcher durably enabled after committed enable")
	}
	if app.OperationSupervisor.isLauncherQuiesced(lID) {
		t.Fatal("expected the transactionally decided admission to reopen the launcher after enable")
	}
	if admitted := app.OperationSupervisor.admit(launcherRunningOp(t, lID)); admitted != admissionAccepted {
		t.Fatal("expected operation admitted for launcher after committed enable")
	}
}

// TestLauncherScopeReplaceCommitsWithoutPostCommitLookup proves a successful
// scope replacement composes its result from the authoritative pre-change
// projection: with exactly the pre-commit reads permitted (the Launcher
// projection lookup, its stored-roots read, and the Principal-ceiling read)
// and every later query rejected, the replacement succeeds and the returned
// projection carries the pre-change Launcher metadata the mutation did not
// touch plus the committed scope/roots. Under the former post-commit
// findLauncherByID, that extra lookup would be rejected here after the
// durable success, reporting the committed change as a failure.
func TestLauncherScopeReplaceCommitsWithoutPostCommitLookup(t *testing.T) {
	db, dbPath := freshFileTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, home := setupPrincipalForLauncherTest(t, db, globalRoots, "owner")
	l, _, _, err := createLauncher(db, pid, "la", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}

	// Rename and disable for real first, so the returned projection must
	// carry pre-change metadata the scope replacement did not touch.
	renamed := "renamed"
	disabled := false
	if _, err := persistLauncherChange(db, l.ID, &renamed, &disabled); err != nil {
		t.Fatalf("initial rename/disable: %v", err)
	}

	// Permit exactly the three pre-commit reads and fail every later query.
	failDB := newFailQueryAfterDB(t, dbPath, 3, errMockQueryFail)
	app := deleteLifecycleApp(t, failDB)
	app.Config.AllowedRoots = globalRoots

	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0755); err != nil {
		t.Fatal(err)
	}

	updated, err := app.replaceLauncherScopeWithLifecycle(l.ID, LauncherScopeRestricted, []string{proj})
	if err != nil {
		t.Fatalf("scope replace under post-commit query failure: %v", err)
	}
	if updated.ID != l.ID || updated.PrincipalID != pid || updated.PrincipalName != "owner" ||
		updated.Name != renamed || updated.Enabled || !updated.CreatedAt.Equal(l.CreatedAt) {
		t.Errorf("returned projection lost pre-change metadata: %+v", updated)
	}
	if updated.ScopeMode != LauncherScopeRestricted || !slices.Equal(updated.AllowedRoots, []string{proj}) {
		t.Errorf("returned projection lost the committed scope/roots: %+v", updated)
	}

	var scope string
	if err := db.QueryRow(`SELECT scope_mode FROM launchers WHERE id = ?`, l.ID).Scan(&scope); err != nil {
		t.Fatal(err)
	}
	if scope != string(LauncherScopeRestricted) {
		t.Errorf("committed scope = %q, want restricted", scope)
	}
}

// TestLauncherScopeReplaceTransactionFailureKeepsOldState proves a failed
// durable replacement reports failure without mutating the old state: the
// scope UPDATE inside the transaction fails, the transaction rolls back, and
// a fresh projection read still reports the pre-change scope/roots.
func TestLauncherScopeReplaceTransactionFailureKeepsOldState(t *testing.T) {
	db, dbPath := freshFileTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, home := setupPrincipalForLauncherTest(t, db, globalRoots, "owner")

	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0755); err != nil {
		t.Fatal(err)
	}
	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeRestricted, []string{proj}, testEffectivePrincipalRoots(t, db, pid, globalRoots), false)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}

	failDB := newFailExecMatchDB(t, dbPath, "UPDATE launchers SET scope_mode", errMockQueryFail)
	cur, err := findLauncherByID(failDB, l.ID)
	if err != nil {
		t.Fatalf("findLauncherByID: %v", err)
	}
	if _, err := replaceLauncherScope(failDB, cur, LauncherScopeInherit, nil, globalRoots); err == nil {
		t.Fatal("expected the failed scope UPDATE to abort the replacement, got success")
	}

	after, err := findLauncherByID(db, l.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.ScopeMode != LauncherScopeRestricted || !slices.Equal(after.AllowedRoots, []string{proj}) {
		t.Errorf("scope/roots changed after failed replacement: %+v", after)
	}
}

// TestPrincipalEnableAppliesAllChildAdmissionsWithoutPostCommitLookup proves
// the Principal enable commits durable state and then applies EVERY child
// Launcher's admission in one non-fallible step: with all pre-commit reads
// permitted and every post-commit query rejected, the enable succeeds and both
// individually-enabled children reopen. Under the former per-child admission
// re-sync, the first child's post-commit re-read would already be rejected
// after the durable success, leaving the remaining children un-synced and
// returning a committed-but-error result.
func TestPrincipalEnableAppliesAllChildAdmissionsWithoutPostCommitLookup(t *testing.T) {
	db, dbPath := freshFileTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "owner")
	la, _, _, err := createLauncher(db, pid, "a", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatalf("createLauncher(a): %v", err)
	}
	lb, _, _, err := createLauncher(db, pid, "b", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatalf("createLauncher(b): %v", err)
	}
	laID, lbID := la.ID, lb.ID

	// Disable the Principal for real first, so the enable is a genuine
	// transition whose commit must reopen the individually-enabled children.
	if _, err := persistPrincipalEnabledChange(db, "owner", false); err != nil {
		t.Fatalf("initial principal disable: %v", err)
	}

	// Permit the transition's own pre-commit reads and fail every later query.
	failDB := newFailQueryAfterDB(t, dbPath, 5, errMockQueryFail)
	app := deleteLifecycleApp(t, failDB)
	// Mirror the disabled-state runtime companion for every child Launcher.
	app.OperationSupervisor.quiesceLauncher(laID)
	app.OperationSupervisor.quiesceLauncher(lbID)

	if _, err := app.enablePrincipalLaunchers("owner"); err != nil {
		t.Fatalf("principal enable under post-commit query failure: %v", err)
	}

	var pEnabled int
	if err := db.QueryRow(`SELECT enabled FROM principals WHERE id = ?`, pid).Scan(&pEnabled); err != nil {
		t.Fatal(err)
	}
	if pEnabled != 1 {
		t.Fatal("expected principal durably enabled after committed enable")
	}
	for _, id := range []string{laID, lbID} {
		if app.OperationSupervisor.isLauncherQuiesced(id) {
			t.Fatalf("expected child launcher %s admission reopened by the committed principal enable", id)
		}
		if admitted := app.OperationSupervisor.admit(launcherRunningOp(t, id)); admitted != admissionAccepted {
			t.Fatalf("expected operation admitted for child launcher %s after committed principal enable", id)
		}
	}
}
