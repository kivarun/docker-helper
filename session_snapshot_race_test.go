package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// setupSnapshotRacePrincipal provisions the racing Principal: stored roots
// [home RW, inputs RO] under the global ceiling, a credential, and the nested
// transition inside the Session workspace (home/work) that distinguishes the
// pre- and post-narrowing snapshots ([workspace RW, inputs RO] vs [workspace
// RW]). Both directories are real: the workspace admission and the allowed
// root add canonicalize against the filesystem.
func setupSnapshotRacePrincipal(t *testing.T, app *App) (workspace string, inputs string, token string) {
	t.Helper()
	root := app.Config.AllowedRoots[0].Path
	home := filepath.Join(root, "home", "snapracer")
	workspace = filepath.Join(home, "work")
	inputs = filepath.Join(workspace, "inputs")
	for _, d := range []string{inputs} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	installOSUserMock(t, map[string]string{"snapracer": home})
	if _, err := createPrincipal(app.DB, "snapracer", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(snapracer): %v", err)
	}
	if _, _, err := addPrincipalAllowedRoot(app.DB, "snapracer", inputs, AllowedRootAccessReadOnly, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("addPrincipalAllowedRoot(inputs): %v", err)
	}
	_, token, err := createPrincipalCredential(app.DB, "snapracer", "oc")
	if err != nil {
		t.Fatalf("createPrincipalCredential(snapracer): %v", err)
	}
	return workspace, inputs, token
}

// createSessionThroughMux issues a real POST /sessions through the route mux
// and returns the recorded response.
func createSessionThroughMux(app *App, token, workspace string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	registerRoutes(mux, app)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(fmt.Sprintf(`{"workspace":%q}`, workspace))))
	req.Header.Set("Authorization", "Bearer "+token)
	mux.ServeHTTP(rec, req)
	return rec
}

// TestRaceSessionCreateCommitsSnapshotWhollyBeforeNarrowing proves the
// Session-create linearization: the create is parked INSIDE its lifecycleMu
// critical section (its ownership-snapshot read) while the narrowing contender
// is blocked on the same boundary, so the Session commits with the wholly
// pre-narrowing snapshot and the narrowing then commits — no mixed snapshot,
// no Session row without snapshot, no partly-mutated derivation.
func TestRaceSessionCreateCommitsSnapshotWhollyBeforeNarrowing(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	workspace, inputs, token := setupSnapshotRacePrincipal(t, app1)

	// Park points (distinct patterns from every other query in the phase):
	//   door    - the create's last pre-boundary read (credential auth).
	//   create  - the create's in-boundary ownership snapshot read.
	//   mutation- the narrowing's first in-boundary principal lookup.
	doorPoint := newParkedQueryPoint("SELECT username, enabled FROM principals WHERE id")
	createBoundaryPoint := newParkedQueryPoint("FROM launchers l JOIN principals p")
	mutationPoint := newParkedQueryPoint("SELECT id FROM principals WHERE username")
	app := &App{
		Config:          app1.Config,
		DB:              openParkedQueryDB(t, app1.Config.DatabasePath, doorPoint, createBoundaryPoint, mutationPoint),
		userModeDefault: app1.userModeDefault,
	}

	runSinglePinnedP(t, func() {
		// 1. The create is pinned at its last pre-boundary read.
		createDone := make(chan *httptest.ResponseRecorder, 1)
		go func() { createDone <- createSessionThroughMux(app, token, workspace) }()
		<-doorPoint.parked
		close(doorPoint.release)

		// 2. The create parks inside its lifecycleMu critical section.
		<-createBoundaryPoint.parked

		// 3. The narrowing contender starts and can only block on the same
		//    boundary (the create holds it): it cannot commit anything.
		narrowingStarted := make(chan struct{})
		narrowingDone := make(chan narrowingResult, 1)
		go func() {
			close(narrowingStarted)
			changed, _, err := app.removePrincipalAllowedRootWithLifecycle("snapracer", inputs)
			narrowingDone <- narrowingResult{changed: changed, err: err}
		}()
		<-narrowingStarted

		// 4. The create commits with the pre-narrowing policy and releases
		//    the boundary.
		close(createBoundaryPoint.release)
		resp := <-createDone
		if resp.Code != http.StatusCreated {
			t.Fatalf("create: expected 201, got %d (body=%s)", resp.Code, resp.Body.String())
		}

		// 5. Only now does the narrowing acquire the boundary and commit.
		<-mutationPoint.parked
		close(mutationPoint.release)
		got := <-narrowingDone
		if got.err != nil {
			t.Fatalf("removePrincipalAllowedRootWithLifecycle: %v", got.err)
		}
		if !got.changed {
			t.Fatal("removePrincipalAllowedRootWithLifecycle reported no change")
		}

		// The committed snapshot is the wholly pre-narrowing one.
		want := []AllowedRootEntry{
			{Path: workspace, Access: AllowedRootAccessReadWrite},
			{Path: inputs, Access: AllowedRootAccessReadOnly},
		}
		sessionID := decodeCreateSessionID(t, resp.Body.String())
		assertSnapshotRows(t, app.DB, sessionID, want)
	})
}

// TestRaceSessionCreateCommitsSnapshotWhollyAfterNarrowing proves the mirror
// linearization: the narrowing holds the boundary and commits its durable
// mutation while the create is pinned at its pre-boundary authentication
// read, so the create can only resolve policy inside the post-narrowing
// state — the new Session commits the wholly post-narrowing snapshot (or is
// refused), never the old one and never a mixed snapshot.
func TestRaceSessionCreateCommitsSnapshotWhollyAfterNarrowing(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	workspace, inputs, token := setupSnapshotRacePrincipal(t, app1)

	mutationPoint := newParkedQueryPoint("SELECT id FROM principals WHERE username")
	doorPoint := newParkedQueryPoint("SELECT username, enabled FROM principals WHERE id")
	app := &App{
		Config:          app1.Config,
		DB:              openParkedQueryDB(t, app1.Config.DatabasePath, mutationPoint, doorPoint),
		userModeDefault: app1.userModeDefault,
	}

	runSinglePinnedP(t, func() {
		// 1. The narrowing parks inside its lifecycleMu critical section,
		//    before its durable DELETE.
		narrowingDone := make(chan narrowingResult, 1)
		go func() {
			changed, _, err := app.removePrincipalAllowedRootWithLifecycle("snapracer", inputs)
			narrowingDone <- narrowingResult{changed: changed, err: err}
		}()
		<-mutationPoint.parked

		// 2. The create runs its pre-boundary authentication and parks there.
		createDone := make(chan *httptest.ResponseRecorder, 1)
		go func() { createDone <- createSessionThroughMux(app, token, workspace) }()
		<-doorPoint.parked
		close(doorPoint.release)

		// 3. The narrowing commits and releases the boundary.
		close(mutationPoint.release)
		got := <-narrowingDone
		if got.err != nil {
			t.Fatalf("removePrincipalAllowedRootWithLifecycle: %v", got.err)
		}
		if !got.changed {
			t.Fatal("removePrincipalAllowedRootWithLifecycle reported no change")
		}

		// 4. The create resolves wholly inside the post-narrowing state.
		resp := <-createDone
		if resp.Code != http.StatusCreated {
			t.Fatalf("create: expected 201, got %d (body=%s)", resp.Code, resp.Body.String())
		}

		// The committed snapshot is the wholly post-narrowing one: only the
		// workspace root entry (the narrowed-away inputs transition is gone).
		want := []AllowedRootEntry{
			{Path: workspace, Access: AllowedRootAccessReadWrite},
		}
		sessionID := decodeCreateSessionID(t, resp.Body.String())
		assertSnapshotRows(t, app.DB, sessionID, want)
	})
}

// decodeCreateSessionID extracts the Session ID from a 201 create response.
func decodeCreateSessionID(t *testing.T, body string) string {
	t.Helper()
	var parsed struct {
		Session struct {
			ID string `json:"id"`
		} `json:"session"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("decode create response: %v (body=%s)", err, body)
	}
	if parsed.Session.ID == "" {
		t.Fatalf("create response carries no session id: %s", body)
	}
	return parsed.Session.ID
}
