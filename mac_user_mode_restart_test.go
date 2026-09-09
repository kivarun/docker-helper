package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestUserModeRestartKeepsPersistedSessionsUsable is a regression test for
// user-mode daemon restart: the startup wiring must not construct a session
// MAC coordinator (App.MACCoordinator stays nil when no MAC driver is active),
// and a live Session persisted before the restart must remain usable for
// Docker action handling instead of failing with "no MAC binding for session".
func TestUserModeRestartKeepsPersistedSessionsUsable(t *testing.T) {
	// Persist a live session before the simulated restart.
	first := newTestAppWithAdminToken(t)
	first.OperationSupervisor = newOperationSupervisor()
	workspace := testWorkspaceDir(t, first.Config.AllowedRoots[0])
	result, err := createDefaultAdminSessionForTest(first, workspace)
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}
	db := first.DB

	// Startup wiring: user mode with no active MAC driver must produce a nil
	// coordinator so App.MACCoordinator stays nil after restart.
	coordinator, err := newMACCoordinatorForMode(db, ModeUser, detectLSM)
	if err != nil {
		t.Fatalf("newMACCoordinatorForMode(user) error: %v", err)
	}
	if coordinator != nil {
		t.Fatal("user mode must not construct a session MAC coordinator")
	}

	// Compose the restarted daemon's App exactly as user-mode runDaemon does:
	// same database, MACCoordinator taken from the startup wiring (nil here).
	app := &App{
		Config:                   first.Config,
		DB:                       db,
		AdminTokenHash:           first.AdminTokenHash,
		OperationSupervisor:      newOperationSupervisor(),
		MACCoordinator:           coordinator,
		SyncExecutionCoordinator: newSyncExecutionCoordinator(),
	}
	app.StageBuildContextFn = newStagingSeam(t, stagingSeamOptions{})
	setupBuildSeam(t, app, buildSeamOptions{Output: "ok\n"})

	dockerfilePath := filepath.Join(workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	// /run on the persisted pre-restart session must not fail with
	// "no MAC binding for session".
	runBody, _ := json.Marshal(map[string]string{"image": "alpine:latest"})
	runReq := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(runBody))
	runReq.Header.Set("Authorization", "Bearer "+result.Token)
	runW := httptest.NewRecorder()
	app.handleRun(runW, runReq)
	if runW.Code != http.StatusOK {
		t.Errorf("restarted user-mode daemon: /run returned %d (body %s); persisted session should remain usable", runW.Code, runW.Body.String())
		return
	}

	// /build on the persisted pre-restart session must also remain usable.
	buildBody, _ := json.Marshal(map[string]string{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	})
	buildReq := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(buildBody))
	buildReq.Header.Set("Authorization", "Bearer "+result.Token)
	buildW := httptest.NewRecorder()
	app.handleBuild(buildW, buildReq)
	if buildW.Code != http.StatusOK {
		t.Errorf("restarted user-mode daemon: /build returned %d (body %s); persisted session should remain usable", buildW.Code, buildW.Body.String())
		return
	}
}

// TestMACCoordinatorForModeSystemDriverActive verifies the system-mode side of
// the startup wiring: with an active MAC driver the helper still constructs a
// session MAC coordinator, so live-session reconciliation is not skipped.
func TestMACCoordinatorForModeSystemDriverActive(t *testing.T) {
	app := newTestApp(t)
	fakeDetect := func() (LSMBackend, error) { return LSMAppArmor, nil }
	coordinator, err := newMACCoordinatorForMode(app.DB, ModeSystem, fakeDetect)
	if err != nil {
		t.Fatalf("newMACCoordinatorForMode(system) error: %v", err)
	}
	if coordinator == nil {
		t.Fatal("system mode with an active LSM must construct a session MAC coordinator")
	}
	if coordinator.driver == nil {
		t.Fatal("system-mode coordinator must have a non-nil driver")
	}
}
