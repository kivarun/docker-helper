package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file proves the stored allowed-root descendant reconciliation: a
// canonical parent-ceiling mutation (Principal-root remove, global-ceiling
// reload, daemon startup) commits its cascaded stored descendants atomically
// through the one reconciliation owner, while already-issued Session
// filesystem snapshots stay immutable and the fail-closed stale-root
// revalidation remains the corruption defense for state outside canonical
// mutation paths.

// mustLauncherStoredRoots reads a Launcher's stored allowed-root entries.
func mustLauncherStoredRoots(t *testing.T, app *App, launcherID string) []AllowedRootEntry {
	t.Helper()
	roots, err := readLauncherAllowedRoots(app.DB, launcherID)
	if err != nil {
		t.Fatalf("read launcher roots %s: %v", launcherID, err)
	}
	return roots
}

// mustLauncherStoredRootPaths is the path-only projection of
// mustLauncherStoredRoots for order-insensitive set assertions.
func mustLauncherStoredRootPaths(t *testing.T, app *App, launcherID string) []string {
	t.Helper()
	return allowedRootPaths(mustLauncherStoredRoots(t, app, launcherID))
}

// mustLauncherScopeMode reads a Launcher's stored scope mode.
func mustLauncherScopeMode(t *testing.T, app *App, launcherID string) LauncherScopeMode {
	t.Helper()
	var scope string
	if err := app.DB.QueryRow(`SELECT scope_mode FROM launchers WHERE id = ?`, launcherID).Scan(&scope); err != nil {
		t.Fatalf("read launcher scope %s: %v", launcherID, err)
	}
	return LauncherScopeMode(scope)
}

// mustStoredPrincipalRootPaths is the order-insensitive path-only projection
// of a Principal's stored roots.
func mustStoredPrincipalRootPaths(t *testing.T, app *App, username string) []string {
	t.Helper()
	return allowedRootPaths(mustStoredPrincipalEntries(t, app, username))
}

// pathSetEqual compares two path sets order-insensitively.
func pathSetEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]int, len(got))
	for _, p := range got {
		seen[p]++
	}
	for _, p := range want {
		seen[p]--
		if seen[p] < 0 {
			return false
		}
	}
	return true
}

// mustDir creates a real directory under the test allowed root.
func mustDir(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.MkdirAll(p, 0755); err != nil {
			t.Fatal(err)
		}
	}
}

// mustRestrictedLauncher creates a restricted Launcher with the given stored
// roots through the production creation owner.
func mustRestrictedLauncher(t *testing.T, app *App, principalID int64, name string, roots ...string) *LauncherWithPrincipal {
	t.Helper()
	l, _, _, err := createLauncher(app.DB, principalID, name, LauncherScopeRestricted, roots, allowedRootPaths(app.getConfig().AllowedRoots), false)
	if err != nil {
		t.Fatalf("createLauncher(%s): %v", name, err)
	}
	return l
}

// TestPrincipalRootRemoveCascadesLauncherDescendants proves the
// Principal-to-Launcher cascade: removing one stored Principal root deletes
// exactly the restricted-Launcher descendants the resulting effective
// Principal ceiling no longer wholly contains, across every Launcher of that
// Principal, and preserves the chain covered by a surviving Principal root.
// The Launcher scope mode never changes.
func TestPrincipalRootRemoveCascadesLauncherDescendants(t *testing.T) {
	app := newTestApp(t)
	root := app.Config.AllowedRoots[0].Path

	home, _ := setupLauncherHandlerPrincipal(t, app, "casc")
	pa := filepath.Join(root, "casc-a")
	pb := filepath.Join(root, "casc-b")
	mustDir(t, pa, filepath.Join(pa, "proj"), pb, filepath.Join(pb, "cache"))
	if _, _, err := addPrincipalAllowedRoot(app.DB, "casc", pa, AllowedRootAccessReadWrite, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("add pa: %v", err)
	}
	if _, _, err := addPrincipalAllowedRoot(app.DB, "casc", pb, AllowedRootAccessReadWrite, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("add pb: %v", err)
	}
	pid := principalIDByName(t, app.DB, "casc")
	l := mustRestrictedLauncher(t, app, pid, "work",
		filepath.Join(pa, "proj"), filepath.Join(pb, "cache"))

	changed, _, err := removePrincipalAllowedRootForTest(t, app, "casc", pa)
	if err != nil {
		t.Fatalf("remove pa: %v", err)
	}
	if !changed {
		t.Fatal("remove pa reported no change")
	}

	// The descendant under the removed root is cascaded away; the root under
	// the surviving Principal root stays; the scope stays restricted.
	if got := mustLauncherStoredRootPaths(t, app, l.ID); !pathSetEqual(got, []string{filepath.Join(pb, "cache")}) {
		t.Fatalf("launcher roots after the cascade = %v, want [%s]", got, filepath.Join(pb, "cache"))
	}
	if got := mustLauncherScopeMode(t, app, l.ID); got != LauncherScopeRestricted {
		t.Fatalf("launcher scope after the cascade = %q, want restricted", got)
	}
	// The Principal keeps the surviving root (and the auto home root).
	if got := mustStoredPrincipalRootPaths(t, app, "casc"); !pathSetEqual(got, []string{home, pb}) {
		t.Fatalf("principal roots after the remove = %v, want [%s %s]", got, home, pb)
	}
}

// TestPrincipalRootRemoveCascadesLastLauncherRootKeepsRestricted proves the
// last stored root of a restricted Launcher cascades away without a scope
// demotion: the Launcher stays restricted with zero roots (fail-closed), and
// the follow-up Session create under the former root is refused by the
// ordinary narrowed-authority contract (invalid_workspace), never
// launcher_unavailable.
func TestPrincipalRootRemoveCascadesLastLauncherRootKeepsRestricted(t *testing.T) {
	app := newTestApp(t)
	root := app.Config.AllowedRoots[0].Path

	setupLauncherHandlerPrincipal(t, app, "lastroot")
	pa := filepath.Join(root, "last-a")
	proj := filepath.Join(pa, "proj")
	ws := filepath.Join(proj, "ws")
	mustDir(t, pa, proj, ws)
	if _, _, err := addPrincipalAllowedRoot(app.DB, "lastroot", pa, AllowedRootAccessReadWrite, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("add pa: %v", err)
	}
	pid := principalIDByName(t, app.DB, "lastroot")
	l := mustRestrictedLauncher(t, app, pid, "work", proj)

	changed, _, err := removePrincipalAllowedRootForTest(t, app, "lastroot", pa)
	if err != nil {
		t.Fatalf("remove pa: %v", err)
	}
	if !changed {
		t.Fatal("remove pa reported no change")
	}
	if got := mustLauncherStoredRoots(t, app, l.ID); len(got) != 0 {
		t.Fatalf("launcher roots after the cascade = %v, want none", got)
	}
	if got := mustLauncherScopeMode(t, app, l.ID); got != LauncherScopeRestricted {
		t.Fatalf("launcher scope after the cascade = %q, want restricted", got)
	}

	// The follow-up create is the ordinary workspace refusal of the narrowed
	// authority, never the stale-root contract.
	_, err = app.createSessionAuthorized(&operatorAuthority{class: operatorAuthorityAdmin},
		createSelector{launcherID: l.ID}, ws, nil)
	if !errors.Is(err, ErrInvalidWorkspace) {
		t.Fatalf("session create after the cascade: err = %v, want ErrInvalidWorkspace", err)
	}
}

// TestPrincipalRootRemoveIdempotentNoCascade proves an idempotent remove of a
// root that was not stored is the unchanged no-op: it runs no cascade and is
// never a general repair operation — even an out-of-ceiling injected row
// stays untouched when the remove changed nothing.
func TestPrincipalRootRemoveIdempotentNoCascade(t *testing.T) {
	app := newTestApp(t)
	root := app.Config.AllowedRoots[0].Path

	setupLauncherHandlerPrincipal(t, app, "noop")
	pa := filepath.Join(root, "noop-a")
	proj := filepath.Join(pa, "proj")
	stale := filepath.Join(root, "noop-stale")
	mustDir(t, pa, proj, stale)
	if _, _, err := addPrincipalAllowedRoot(app.DB, "noop", pa, AllowedRootAccessReadWrite, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("add pa: %v", err)
	}
	pid := principalIDByName(t, app.DB, "noop")
	l := mustRestrictedLauncher(t, app, pid, "work", proj)
	// Inject an out-of-ceiling row outside every canonical mutation path:
	// only a parent-ceiling mutation may reconcile it away.
	if _, err := app.DB.Exec(
		`INSERT INTO launcher_allowed_roots (launcher_id, root_path, access) VALUES (?, ?, ?)`,
		l.ID, stale, string(AllowedRootAccessReadWrite),
	); err != nil {
		t.Fatalf("inject stale row: %v", err)
	}

	missing := filepath.Join(root, "never-added")
	changed, _, err := removePrincipalAllowedRootForTest(t, app, "noop", missing)
	if err != nil {
		t.Fatalf("idempotent remove: %v", err)
	}
	if changed {
		t.Fatal("remove of a missing root reported a change")
	}
	if got := mustStoredPrincipalRootPaths(t, app, "noop"); !pathSetEqual(got, mustStoredPrincipalRootPaths(t, app, "noop")) || len(got) == 0 {
		t.Fatalf("principal roots changed by an idempotent remove: %v", got)
	}
	if got := mustLauncherStoredRootPaths(t, app, l.ID); !pathSetEqual(got, []string{proj, stale}) {
		t.Fatalf("launcher roots changed by an idempotent remove: %v, want [%s %s]", got, proj, stale)
	}
}

// TestGlobalCeilingNarrowingCascadesThroughReload proves the reload's
// global-ceiling transition prunes stored Principal roots that no new global
// root wholly contains and then cascades the restricted-Launcher descendants,
// all before the new runtime policy is published.
func TestGlobalCeilingNarrowingCascadesThroughReload(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path

	setupLauncherHandlerPrincipal(t, app, "gcr")
	pa := filepath.Join(root, "gcr-a")
	pb := filepath.Join(root, "gcr-b")
	proj := filepath.Join(pa, "proj")
	cache := filepath.Join(pb, "cache")
	ws := filepath.Join(proj, "ws")
	mustDir(t, pa, proj, pb, cache, ws)
	if _, _, err := addPrincipalAllowedRoot(app.DB, "gcr", pa, AllowedRootAccessReadWrite, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("add pa: %v", err)
	}
	if _, _, err := addPrincipalAllowedRoot(app.DB, "gcr", pb, AllowedRootAccessReadWrite, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("add pb: %v", err)
	}
	pid := principalIDByName(t, app.DB, "gcr")
	l := mustRestrictedLauncher(t, app, pid, "work", proj, cache)

	// The positive precondition: a session inside the stored chain succeeds
	// before the narrowing.
	if _, err := app.createSessionAuthorized(&operatorAuthority{class: operatorAuthorityAdmin},
		createSelector{launcherID: l.ID}, ws, nil); err != nil {
		t.Fatalf("pre-narrowing session create: %v", err)
	}

	narrowTo := pa
	narrowed := narrowCfg(t, app, narrowTo)
	deps := reloadDeps{
		loadAndPrepareRuntimeConfig: func() (*Config, error) { return narrowed, nil },
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	app.handleReloadWithDeps(rec, req, deps)
	if rec.Code != http.StatusOK {
		t.Fatalf("reload: expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	if got := app.getConfig().AllowedRoots; len(got) != 1 || got[0].Path != narrowTo {
		t.Fatalf("reload did not publish the narrowed ceiling: %v", got)
	}
	// The Principal roots outside the new global ceiling are pruned, and the
	// Launcher descendants outside the resulting effective Principal ceiling
	// are cascaded in the same transition.
	if got := mustStoredPrincipalRootPaths(t, app, "gcr"); !pathSetEqual(got, []string{pa}) {
		t.Fatalf("principal roots after the reload = %v, want [%s]", got, pa)
	}
	if got := mustLauncherStoredRootPaths(t, app, l.ID); !pathSetEqual(got, []string{proj}) {
		t.Fatalf("launcher roots after the reload = %v, want [%s]", got, proj)
	}
	// The narrowed authority governs the next create.
	if _, err := app.createSessionAuthorized(&operatorAuthority{class: operatorAuthorityAdmin},
		createSelector{launcherID: l.ID}, filepath.Join(cache, "ws"), nil); !errors.Is(err, ErrInvalidWorkspace) {
		t.Fatalf("session create outside the narrowed ceiling: err = %v, want ErrInvalidWorkspace", err)
	}
}

// TestGlobalCeilingNarrowingPreservesCoveredChain proves the surviving-parent
// rule on the task's exact shape: narrowing the global ceiling to one of two
// disjoint roots deletes the Principal and Launcher chain of the removed root
// and preserves the whole chain of the surviving root.
func TestGlobalCeilingNarrowingPreservesCoveredChain(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path

	homeRoot := filepath.Join(root, "home")
	optRoot := filepath.Join(root, "opt")
	mustDir(t, homeRoot, optRoot)
	cfg := app.getConfig()
	cfg.AllowedRoots = []AllowedRootEntry{allowedRootEntry(homeRoot), allowedRootEntry(optRoot)}
	app.setConfig(&cfg)

	home := filepath.Join(homeRoot, "alice")
	mustDir(t, home)
	installOSUserMock(t, map[string]string{"alice": home})
	if _, err := createPrincipal(app.DB, "alice", app.getConfig().AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(alice): %v", err)
	}
	optAlice := filepath.Join(optRoot, "alice")
	optCache := filepath.Join(optAlice, "cache")
	homeProject := filepath.Join(home, "project")
	mustDir(t, optAlice, optCache, homeProject)
	if _, _, err := addPrincipalAllowedRoot(app.DB, "alice", optAlice, AllowedRootAccessReadWrite, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("add opt/alice: %v", err)
	}
	pid := principalIDByName(t, app.DB, "alice")
	l := mustRestrictedLauncher(t, app, pid, "work", homeProject, optCache)

	narrowed := narrowCfg(t, app, optRoot)
	deps := reloadDeps{
		loadAndPrepareRuntimeConfig: func() (*Config, error) { return narrowed, nil },
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	app.handleReloadWithDeps(rec, req, deps)
	if rec.Code != http.StatusOK {
		t.Fatalf("reload: expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// The removed-root chain is cascaded away; the surviving-root chain stays.
	if got := mustStoredPrincipalRootPaths(t, app, "alice"); !pathSetEqual(got, []string{optAlice}) {
		t.Fatalf("principal roots after the narrowing = %v, want [%s]", got, optAlice)
	}
	if got := mustLauncherStoredRootPaths(t, app, l.ID); !pathSetEqual(got, []string{optCache}) {
		t.Fatalf("launcher roots after the narrowing = %v, want [%s]", got, optCache)
	}
}

// TestReloadReconciliationFailureKeepsPolicyAndRows proves the reload failure
// contract: when the cascade persistence fails, the new runtime config is not
// published and no partial child deletion is committed.
func TestReloadReconciliationFailureKeepsPolicyAndRows(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path

	setupLauncherHandlerPrincipal(t, app, "gcfail")
	pa := filepath.Join(root, "gcfail-a")
	proj := filepath.Join(pa, "proj")
	mustDir(t, pa, proj)
	if _, _, err := addPrincipalAllowedRoot(app.DB, "gcfail", pa, AllowedRootAccessReadWrite, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("add pa: %v", err)
	}
	pid := principalIDByName(t, app.DB, "gcfail")
	l := mustRestrictedLauncher(t, app, pid, "work", proj)

	// Narrow fault injection: the reconciliation's launcher-root stage fails
	// on a missing table, after the same transaction already deleted
	// Principal rows — the rollback must undo those too.
	if _, err := app.DB.Exec(`DROP TABLE launcher_allowed_roots`); err != nil {
		t.Fatalf("drop table: %v", err)
	}

	narrowed := narrowCfg(t, app, pa)
	deps := reloadDeps{
		loadAndPrepareRuntimeConfig: func() (*Config, error) { return narrowed, nil },
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	app.handleReloadWithDeps(rec, req, deps)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("reload with a failing reconciliation: expected 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeAPIError(t, rec.Body.Bytes()).Code; code != "database_error" {
		t.Errorf("failure code = %q, want database_error", code)
	}

	// The narrowed runtime config was NOT published.
	if got := app.getConfig().AllowedRoots; len(got) != 1 || got[0].Path != root {
		t.Fatalf("runtime config published despite the reconciliation failure: %v", got)
	}
	// No partial child deletion committed: the Principal rows are intact.
	if got := mustStoredPrincipalRootPaths(t, app, "gcfail"); !pathSetEqual(got, []string{filepath.Join(root, "home", "gcfail"), pa}) {
		t.Fatalf("principal roots after the failed reload = %v, want the pre-reload set", got)
	}
	_ = l
}

// TestStartupReconciliationConvergesStoredRootsBeforeServing proves the
// startup reconciliation: stored roots valid under an old global config but
// invalid under a narrower startup config are pruned before serving, through
// the exact call shape the startup path makes into the shared reconciliation
// owner.
func TestStartupReconciliationConvergesStoredRootsBeforeServing(t *testing.T) {
	app := newTestApp(t)
	root := app.Config.AllowedRoots[0].Path

	setupLauncherHandlerPrincipal(t, app, "bootrec")
	pa := filepath.Join(root, "bootrec-a")
	pb := filepath.Join(root, "bootrec-b")
	proj := filepath.Join(pa, "proj")
	cache := filepath.Join(pb, "cache")
	mustDir(t, pa, proj, pb, cache)
	if _, _, err := addPrincipalAllowedRoot(app.DB, "bootrec", pa, AllowedRootAccessReadWrite, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("add pa: %v", err)
	}
	if _, _, err := addPrincipalAllowedRoot(app.DB, "bootrec", pb, AllowedRootAccessReadWrite, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("add pb: %v", err)
	}
	pid := principalIDByName(t, app.DB, "bootrec")
	l := mustRestrictedLauncher(t, app, pid, "work", proj, cache)

	// The narrower startup config: only pa is admitted.
	narrowRoot := pa
	narrowed := narrowCfg(t, app, narrowRoot)

	result, err := reconcileStoredAllowedRootsToGlobalCeiling(
		app.DB, narrowed.AllowedRoots, true, app.userModeDefault.principalID)
	if err != nil {
		t.Fatalf("startup reconciliation: %v", err)
	}
	if !pathSetEqual(principalPrunedPaths(result), []string{filepath.Join(root, "home", "bootrec"), pb}) {
		t.Fatalf("reconciliation pruned principal roots = %v, want the out-of-ceiling pair", result.PrincipalRoots)
	}
	if !pathSetEqual(launcherPrunedPaths(result), []string{cache}) {
		t.Fatalf("reconciliation pruned launcher roots = %v, want [%s]", launcherPrunedPaths(result), cache)
	}
	if got := mustStoredPrincipalRootPaths(t, app, "bootrec"); !pathSetEqual(got, []string{pa}) {
		t.Fatalf("principal roots after startup reconciliation = %v, want [%s]", got, pa)
	}
	if got := mustLauncherStoredRootPaths(t, app, l.ID); !pathSetEqual(got, []string{proj}) {
		t.Fatalf("launcher roots after startup reconciliation = %v, want [%s]", got, proj)
	}
}

// principalPrunedPaths projects the reconciliation result's Principal rows.
func principalPrunedPaths(result storedRootCascadeResult) []string {
	paths := make([]string, 0, len(result.PrincipalRoots))
	for _, p := range result.PrincipalRoots {
		paths = append(paths, p.Path)
	}
	return paths
}

// launcherPrunedPaths projects the reconciliation result's Launcher rows.
func launcherPrunedPaths(result storedRootCascadeResult) []string {
	paths := make([]string, 0, len(result.LauncherRoots))
	for _, p := range result.LauncherRoots {
		paths = append(paths, p.Path)
	}
	return paths
}

// TestRaceReloadNarrowingCommitsWhollyCascadedHierarchy proves the reload
// atomicity race: a Session create parked inside its lifecycleMu critical
// section commits with the wholly old complete hierarchy while the narrowing
// reload is blocked on the same boundary; the reload then commits the wholly
// new cascaded hierarchy — the created Session's immutable snapshot is never
// rewritten, and no intermediate new-parent-plus-stale-children state is
// observable.
func TestRaceReloadNarrowingCommitsWhollyCascadedHierarchy(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app1.Config.AllowedRoots[0].Path

	home, _ := setupLauncherHandlerPrincipal(t, app1, "racer")
	pa := filepath.Join(root, "racer-a")
	proj := filepath.Join(pa, "proj")
	ws := filepath.Join(proj, "ws")
	mustDir(t, pa, proj, ws)
	if _, _, err := addPrincipalAllowedRoot(app1.DB, "racer", pa, AllowedRootAccessReadWrite, allowedRootPaths(app1.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("add pa: %v", err)
	}
	pid := principalIDByName(t, app1.DB, "racer")
	l := mustRestrictedLauncher(t, app1, pid, "work", proj)

	// Park points (distinct patterns from every other query in the phase):
	//   create  - the create's in-boundary ownership snapshot read.
	createBoundaryPoint := newParkedQueryPoint("FROM launchers l JOIN principals p")
	app := &App{
		Config:          app1.Config,
		DB:              openParkedQueryDB(t, app1.Config.DatabasePath, createBoundaryPoint),
		AdminTokenHash:  app1.AdminTokenHash,
		userModeDefault: app1.userModeDefault,
	}

	runSinglePinnedP(t, func() {
		// 1. The create parks inside its lifecycleMu critical section.
		createDone := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			mux := http.NewServeMux()
			registerRoutes(mux, app)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/sessions",
				bytes.NewReader([]byte(fmt.Sprintf(`{"launcher_id":%q,"workspace":%q}`, l.ID, ws))))
			req.Header.Set("Authorization", "Bearer "+testAdminToken)
			mux.ServeHTTP(rec, req)
			createDone <- rec
		}()
		<-createBoundaryPoint.parked

		// 2. The narrowing reload starts and blocks on the held boundary: it
		//    can commit nothing while the create runs.
		holding := make(chan struct{})
		gate := make(chan struct{})
		narrowRoot := filepath.Join(root, "racer-narrow")
		mustDir(t, narrowRoot)
		narrowed := narrowCfg(t, app, narrowRoot)
		deps := reloadDeps{
			loadAndPrepareRuntimeConfig: func() (*Config, error) {
				close(holding)
				<-gate
				return narrowed, nil
			},
		}
		reloadDone := make(chan int, 1)
		go func() {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/reload", nil)
			req.Header.Set("Authorization", "Bearer "+testAdminToken)
			app.handleReloadWithDeps(rec, req, deps)
			reloadDone <- rec.Code
		}()

		// 3. The create commits with the wholly old complete hierarchy and
		//    releases the boundary.
		close(createBoundaryPoint.release)
		resp := <-createDone
		if resp.Code != http.StatusCreated {
			t.Fatalf("create: expected 201, got %d (body=%s)", resp.Code, resp.Body.String())
		}
		sessionID := decodeCreateSessionID(t, resp.Body.String())

		// 4. The reload acquires the boundary, runs its reconciliation and
		//    publishes the narrowed ceiling.
		close(gate)
		if code := <-reloadDone; code != http.StatusOK {
			t.Fatalf("reload: expected 200, got %d", code)
		}
		_ = holding

		// 5. The committed state is the wholly new cascaded hierarchy: every
		//    Principal and Launcher row outside the narrowed ceiling is gone.
		if got := mustStoredPrincipalRootPaths(t, app, "racer"); len(got) != 0 {
			t.Fatalf("principal roots after the reload = %v, want the reconciled empty set", got)
		}
		if got := mustLauncherStoredRootPaths(t, app, l.ID); len(got) != 0 {
			t.Fatalf("launcher roots after the reload = %v, want the reconciled empty set", got)
		}

		// 6. The issued Session is immutable: its snapshot rows still carry
		//    exactly the pre-narrowing authority.
		want := []AllowedRootEntry{{Path: ws, Access: AllowedRootAccessReadWrite}}
		assertSnapshotRows(t, app.DB, sessionID, want)
	})
	_ = home
}

// TestSessionImmutabilityUnderPrincipalRootCascade proves the Session
// immutability contract: removing a parent Principal root cascades the stored
// Launcher descendant but never rewrites the issued Session filesystem
// snapshot; the existing bearer keeps its issued authority for its normal
// lifecycle, and the next create follows the narrowed authority.
func TestSessionImmutabilityUnderPrincipalRootCascade(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path

	setupLauncherHandlerPrincipal(t, app, "immu")
	pa := filepath.Join(root, "immu-a")
	proj := filepath.Join(pa, "proj")
	ws := filepath.Join(proj, "ws")
	mustDir(t, pa, proj, ws)
	if _, _, err := addPrincipalAllowedRoot(app.DB, "immu", pa, AllowedRootAccessReadWrite, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("add pa: %v", err)
	}
	pid := principalIDByName(t, app.DB, "immu")
	l := mustRestrictedLauncher(t, app, pid, "work", proj)

	created, err := app.createSessionAuthorized(&operatorAuthority{class: operatorAuthorityAdmin},
		createSelector{launcherID: l.ID}, ws, nil)
	if err != nil {
		t.Fatalf("session create: %v", err)
	}

	changed, _, _, err := app.removePrincipalAllowedRootWithLifecycle("immu", pa)
	if err != nil {
		t.Fatalf("remove pa: %v", err)
	}
	if !changed {
		t.Fatal("remove pa reported no change")
	}
	if got := mustLauncherStoredRoots(t, app, l.ID); len(got) != 0 {
		t.Fatalf("launcher roots after the cascade = %v, want none", got)
	}

	// The issued Session survives with its issued authority: the bearer still
	// authenticates and the persisted snapshot rows are unchanged.
	s, err := app.findSessionByToken(created.Token)
	if err != nil {
		t.Fatalf("issued bearer rejected after the cascade: %v", err)
	}
	if s.ID != created.Session.ID || s.Workspace != ws {
		t.Fatalf("issued session identity changed: %+v", s)
	}
	want := []AllowedRootEntry{{Path: ws, Access: AllowedRootAccessReadWrite}}
	assertSnapshotRows(t, app.DB, created.Session.ID, want)

	// The next create follows the narrowed authority: the former workspace is
	// now the ordinary out-of-authority refusal.
	_, err = app.createSessionAuthorized(&operatorAuthority{class: operatorAuthorityAdmin},
		createSelector{launcherID: l.ID}, ws, nil)
	if !errors.Is(err, ErrInvalidWorkspace) {
		t.Fatalf("follow-up create after the cascade: err = %v, want ErrInvalidWorkspace", err)
	}
}

// TestInjectedStaleLauncherRootFailsClosed proves the retained corruption
// defense: a stale Launcher root injected outside every canonical mutation
// path is still refused fail-closed by the Session-create revalidation with
// the existing unavailable contract, never silently accepted and never
// repaired by a read path.
func TestInjectedStaleLauncherRootFailsClosed(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path

	setupLauncherHandlerPrincipal(t, app, "corrupt")
	pa := filepath.Join(root, "corrupt-a")
	proj := filepath.Join(pa, "proj")
	ws := filepath.Join(proj, "ws")
	stale := filepath.Join(root, "corrupt-stale")
	mustDir(t, pa, proj, ws, stale)
	if _, _, err := addPrincipalAllowedRoot(app.DB, "corrupt", pa, AllowedRootAccessReadWrite, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("add pa: %v", err)
	}
	pid := principalIDByName(t, app.DB, "corrupt")
	l := mustRestrictedLauncher(t, app, pid, "work", proj)

	// Inject the out-of-ceiling row directly: unsupported direct DB
	// modification, never a canonical mutation.
	if _, err := app.DB.Exec(
		`INSERT INTO launcher_allowed_roots (launcher_id, root_path, access) VALUES (?, ?, ?)`,
		l.ID, stale, string(AllowedRootAccessReadWrite),
	); err != nil {
		t.Fatalf("inject stale row: %v", err)
	}

	_, err := app.createSessionAuthorized(&operatorAuthority{class: operatorAuthorityAdmin},
		createSelector{launcherID: l.ID}, ws, nil)
	if !errors.Is(err, ErrLauncherUnavailable) {
		t.Fatalf("session create with an injected stale root: err = %v, want ErrLauncherUnavailable", err)
	}

	// The same refusal through the public API surface keeps the stable
	// launcher_unavailable contract.
	mux := http.NewServeMux()
	registerRoutes(mux, app)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sessions",
		strings.NewReader(fmt.Sprintf(`{"launcher_id":%q,"workspace":%q}`, l.ID, ws)))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("stale-root session create: expected 422, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeAPIError(t, rec.Body.Bytes()).Code; code != "launcher_unavailable" {
		t.Errorf("stale-root code = %q, want launcher_unavailable", code)
	}
}
