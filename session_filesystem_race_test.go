package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// createNarrowedSessionThroughMux issues a real POST /sessions with an
// explicit issuance-time filesystem_roots request through the route mux
// and returns the recorded response.
func createNarrowedSessionThroughMux(app *App, token, workspace, roots string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	registerRoutes(mux, app)
	rec := httptest.NewRecorder()
	body := fmt.Sprintf(`{"workspace":%q,"filesystem_roots":%s}`, workspace, roots)
	req := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	mux.ServeHTTP(rec, req)
	return rec
}

// wideningRoots requests read_write for the workspace's inputs subtree: under
// the pre-mutation ceiling (inputs protected read-only) this is an
// issuance-time widening; under the post-mutation ceiling it is a valid
// narrowing. The ceiling generation the create observes decides the outcome,
// and the boundary guarantees exactly one generation is observed.
func wideningRoots(inputs string) string {
	return fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, inputs)
}

// TestRaceNarrowedSessionCreateLinearizesBeforeParentMutation proves the
// create-with-narrowing linearization: the create is parked INSIDE its
// lifecycleMu critical section while the parent-policy mutation is blocked on
// the same boundary, so the request is proven against the wholly
// pre-mutation ceiling (the widening request is refused) and the mutation can
// only commit after the create finished — there is no state where the request
// is validated against one ceiling generation and committed against another.
func TestRaceNarrowedSessionCreateLinearizesBeforeParentMutation(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	workspace, inputs, token := setupSnapshotRacePrincipal(t, app1)

	// Park points (distinct patterns from every other query in the phase):
	//   door    - the create's last pre-boundary read (credential auth).
	//   create  - the create's in-boundary ownership snapshot read.
	//   mutation- the parent-policy mutation's first in-boundary lookup.
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
		go func() { createDone <- createNarrowedSessionThroughMux(app, token, workspace, wideningRoots(inputs)) }()
		<-doorPoint.parked
		close(doorPoint.release)

		// 2. The create parks inside its lifecycleMu critical section.
		<-createBoundaryPoint.parked

		// 3. The parent-policy mutation starts and can only block on the
		//    same boundary (the create holds it): it cannot commit anything.
		mutationStarted := make(chan struct{})
		mutationDone := make(chan narrowingResult, 1)
		go func() {
			close(mutationStarted)
			changed, _, err := app.removePrincipalAllowedRootWithLifecycle("snapracer", inputs)
			mutationDone <- narrowingResult{changed: changed, err: err}
		}()
		<-mutationStarted

		// 4. The create resolves wholly inside the pre-mutation ceiling and
		//    releases the boundary: the widening request is refused by the
		//    issuance-time contract, not by any mutation interleaving.
		close(createBoundaryPoint.release)
		resp := <-createDone
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("create: expected 400, got %d (body=%s)", resp.Code, resp.Body.String())
		}
		if !strings.Contains(resp.Body.String(), "invalid_filesystem_policy") {
			t.Errorf("create refusal body lacks invalid_filesystem_policy: %s", resp.Body.String())
		}

		// 5. Only now does the mutation acquire the boundary and commit.
		<-mutationPoint.parked
		close(mutationPoint.release)
		got := <-mutationDone
		if got.err != nil {
			t.Fatalf("removePrincipalAllowedRootWithLifecycle: %v", got.err)
		}
		if !got.changed {
			t.Fatal("removePrincipalAllowedRootWithLifecycle reported no change")
		}
	})
}

// TestRaceNarrowedSessionCreateLinearizesAfterParentMutation proves the mirror
// linearization: the parent-policy mutation holds the boundary and commits
// while the create is pinned at its pre-boundary authentication read, so the
// create can only resolve the ceiling inside the post-mutation state — the
// same widening request is now a valid narrowing and commits the wholly
// post-mutation snapshot, never the pre-mutation refusal and never a mixed
// state.
func TestRaceNarrowedSessionCreateLinearizesAfterParentMutation(t *testing.T) {
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
		// 1. The mutation parks inside its lifecycleMu critical section,
		//    before its durable DELETE.
		mutationDone := make(chan narrowingResult, 1)
		go func() {
			changed, _, err := app.removePrincipalAllowedRootWithLifecycle("snapracer", inputs)
			mutationDone <- narrowingResult{changed: changed, err: err}
		}()
		<-mutationPoint.parked

		// 2. The create runs its pre-boundary authentication and parks there.
		createDone := make(chan *httptest.ResponseRecorder, 1)
		go func() { createDone <- createNarrowedSessionThroughMux(app, token, workspace, wideningRoots(inputs)) }()
		<-doorPoint.parked
		close(doorPoint.release)

		// 3. The mutation commits and releases the boundary.
		close(mutationPoint.release)
		got := <-mutationDone
		if got.err != nil {
			t.Fatalf("removePrincipalAllowedRootWithLifecycle: %v", got.err)
		}
		if !got.changed {
			t.Fatal("removePrincipalAllowedRootWithLifecycle reported no change")
		}

		// 4. The create resolves wholly inside the post-mutation ceiling:
		//    the request is proven against the widened ceiling and commits.
		resp := <-createDone
		if resp.Code != http.StatusCreated {
			t.Fatalf("create: expected 201, got %d (body=%s)", resp.Code, resp.Body.String())
		}

		// The committed snapshot is the wholly post-mutation narrowing: the
		// workspace root is read-write and the inputs read_write request no
		// longer introduces a transition, so only the root entry remains.
		sessionID := decodeCreateSessionID(t, resp.Body.String())
		assertSnapshotRows(t, app.DB, sessionID, []AllowedRootEntry{
			{Path: workspace, Access: AllowedRootAccessReadWrite},
		})
	})
}
