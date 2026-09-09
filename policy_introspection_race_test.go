package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// runSinglePinnedP runs f with GOMAXPROCS=1 and restores the previous value.
// With a single P the two race contenders are scheduled deterministically
// from the release order of the test's synchronization points: no sleeps and
// no runtime.Gosched.
//
// Regression-detection note: a hypothetical unserialized introspection is
// caught whenever the scheduler runs its resolution inside the mutation's
// parked window (verified against the pre-fix implementation); the shipped
// invariant proof itself — the response corresponds wholly to one policy
// state while the other contender holds or waits on the boundary — is
// deterministic and does not depend on that scheduling.
func runSinglePinnedP(t *testing.T, f func()) {
	t.Helper()
	prev := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prev)
	f()
}

// parkedQueryPoint parks (never fails) a query whose SQL contains match on
// its first occurrence across all connections, until the test releases the
// point. It pins a lifecycle mutation or a read-only introspection at a
// deterministic point of its boundary sequencing, in the same spirit as the
// injected reload runtime-config barrier: test infrastructure only, never a
// production hook.
type parkedQueryPoint struct {
	match   string
	parked  chan struct{}
	release chan struct{}
	once    sync.Once
}

func newParkedQueryPoint(match string) *parkedQueryPoint {
	return &parkedQueryPoint{
		match:   match,
		parked:  make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (p *parkedQueryPoint) maybePark(query string) {
	if !strings.Contains(query, p.match) {
		return
	}
	p.once.Do(func() { close(p.parked) })
	// After release the point stays open: later occurrences (including on
	// fresh pooled connections) fall straight through.
	<-p.release
}

type parkedQueryConn struct {
	driver.Conn
	points    []*parkedQueryPoint
	keepAlive *sql.DB
}

func (c *parkedQueryConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	for _, p := range c.points {
		p.maybePark(query)
	}
	if queryer, ok := c.Conn.(driver.QueryerContext); ok {
		return queryer.QueryContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

func (c *parkedQueryConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	for _, p := range c.points {
		p.maybePark(query)
	}
	if execer, ok := c.Conn.(driver.ExecerContext); ok {
		return execer.ExecContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

func (c *parkedQueryConn) Close() error {
	c.keepAlive.Close()
	return c.Conn.Close()
}

type parkedQueryDriver struct {
	points []*parkedQueryPoint
}

func (d *parkedQueryDriver) Open(dsn string) (driver.Conn, error) {
	realConn, keepAlive, err := openRealSQLiteConn(dsn)
	if err != nil {
		return nil, err
	}
	return &parkedQueryConn{Conn: realConn, keepAlive: keepAlive, points: d.points}, nil
}

// openParkedQueryDB reopens an already-initialized database file through the
// parked-query driver. The fixture must have been prepared on a normal
// connection first: park points would otherwise trip during setup.
func openParkedQueryDB(t *testing.T, dbPath string, points ...*parkedQueryPoint) *sql.DB {
	t.Helper()
	name := nextMockDriverName("pqp")
	sql.Register(name, &parkedQueryDriver{points: points})
	db, err := sql.Open(name, dbPath)
	if err != nil {
		t.Fatalf("sql.Open(parked): %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("parked db ping: %v", err)
	}
	return db
}

// TestRaceReloadSerializesPrincipalEffectiveRootsIntrospection proves the
// Principal effective-roots introspection observes one coherent policy state
// under the lifecycle serialization boundary. The reload parks inside its
// lifecycleMu critical section (the injected runtime-config barrier) before
// committing the narrowed global roots; the introspection is pinned at its
// last pre-boundary read (its credential authentication) and released into
// the held boundary, so its whole projection — identity and roots — can only
// resolve after the reload's setConfig commit and must observe the narrowed
// roots wholly. An unserialized read would resolve while the parked reload is
// still pre-commit and answer with the pre-reload roots.
func TestRaceReloadSerializesPrincipalEffectiveRootsIntrospection(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	rootA := app1.Config.AllowedRoots[0].Path

	// Principal rootview with stored roots [home, stale]: home sits under the
	// narrowed global root, stale only under the wider pre-reload root A, so
	// the effective projection distinguishes the pre-reload state
	// ([home, stale]) from the narrowed one ([home]).
	narrow := filepath.Join(rootA, "narrow")
	stale := filepath.Join(rootA, "stale")
	home := filepath.Join(narrow, "rootview")
	for _, d := range []string{narrow, stale, home} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	installOSUserMock(t, map[string]string{"rootview": home})
	if _, err := createPrincipal(app1.DB, "rootview", app1.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(rootview): %v", err)
	}
	w := launcherRequest(t, app1, http.MethodPost, "/principals/rootview/allowed-roots", testAdminToken, fmt.Sprintf(`{"path":%q}`, stale))
	if w.Code != http.StatusOK {
		t.Fatalf("add stale root: %d %s", w.Code, w.Body.String())
	}
	_, token, err := createPrincipalCredential(app1.DB, "rootview", "oc")
	if err != nil {
		t.Fatalf("createPrincipalCredential(rootview): %v", err)
	}

	// Baseline: the effective projection is the full stored-root scope under A.
	w = launcherRequest(t, app1, http.MethodGet, "/principals/rootview/effective-allowed-roots", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("baseline introspection: %d %s", w.Code, w.Body.String())
	}
	if got := decodePolicyRoots(t, w.Body.String()); len(got.AllowedRoots) != 2 {
		t.Fatalf("baseline allowed_roots = %v, want [%s %s]", got.AllowedRoots, home, stale)
	}

	// Park the introspection at its last pre-boundary read (the credential
	// authentication's principal read): after this release the only step
	// before the boundary in the serialized implementation is the lifecycleMu
	// acquire the parked reload still holds. The pattern is distinct from
	// every other query in the race phase.
	doorPoint := newParkedQueryPoint("SELECT username, enabled FROM principals WHERE id")
	app := &App{
		Config:          app1.Config,
		DB:              openParkedQueryDB(t, app1.Config.DatabasePath, doorPoint),
		AdminTokenHash:  app1.AdminTokenHash,
		userModeDefault: app1.userModeDefault,
	}

	// The race phase runs on a single P: the reload and the introspection
	// are ordered purely by their synchronization points (the injected
	// reload barrier and the parked pre-boundary read), in release order.
	runSinglePinnedP(t, func() {
		// The reload parks after acquiring lifecycleMu, before its setConfig
		// commit: the same injected-barrier arrangement the mutation race
		// tests use for the reload path.
		holding := make(chan struct{})
		gate := make(chan struct{})
		deps := reloadDeps{
			loadAndPrepareRuntimeConfig: func() (*Config, error) {
				close(holding)
				<-gate
				return narrowCfg(t, app, narrow), nil
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
		<-holding

		// The introspection is served through the real mux (the {username}
		// path value) while the reload holds the boundary.
		introspectionDone := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			mux := http.NewServeMux()
			registerRoutes(mux, app)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/principals/rootview/effective-allowed-roots", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			mux.ServeHTTP(rec, req)
			introspectionDone <- rec
		}()
		<-doorPoint.parked
		close(doorPoint.release)

		// The reload commits the narrowed configuration and releases the
		// boundary; the introspection then resolves wholly inside the
		// post-reload policy state.
		close(gate)
		if code := <-reloadDone; code != http.StatusOK {
			t.Fatalf("reload: expected 200, got %d", code)
		}
		resp := decodePolicyRoots(t, (<-introspectionDone).Body.String())
		if !resp.OK || resp.Principal != "rootview" {
			t.Fatalf("introspection response = %+v", resp)
		}
		if len(resp.AllowedRoots) != 1 || resp.AllowedRoots[0] != home {
			t.Fatalf("introspection observed a pre-reload or mixed policy state: allowed_roots = %v, want [%s]", resp.AllowedRoots, home)
		}
	})
}

// TestRacePrincipalRootNarrowingSerializesCreatePolicyIntrospection proves
// the Session-create policy introspection returns one coherent projection
// under the lifecycle serialization boundary. The Principal allowed-root
// narrowing (the same mutation owner real Session create serializes with)
// parks inside its lifecycleMu critical section before its durable DELETE;
// the introspection is pinned at its last pre-boundary read, released into
// the held boundary, and can only resolve after the narrowing committed, so
// the returned projection is the wholly post-narrowing state (the narrowed
// roots with the same default Launcher). An unserialized read would resolve
// between the narrowing's components and return the pre-narrowing mixed
// projection.
func TestRacePrincipalRootNarrowingSerializesCreatePolicyIntrospection(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app1.Config.AllowedRoots[0].Path

	// Principal raceowner with stored roots [home, extra] and a credential.
	home := filepath.Join(root, "home", "raceowner")
	extra := filepath.Join(home, "extra")
	if err := os.MkdirAll(extra, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"raceowner": home})
	if _, err := createPrincipal(app1.DB, "raceowner", app1.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(raceowner): %v", err)
	}
	w := launcherRequest(t, app1, http.MethodPost, "/principals/raceowner/allowed-roots", testAdminToken, fmt.Sprintf(`{"path":%q}`, extra))
	if w.Code != http.StatusOK {
		t.Fatalf("add extra root: %d %s", w.Code, w.Body.String())
	}
	_, token, err := createPrincipalCredential(app1.DB, "raceowner", "oc")
	if err != nil {
		t.Fatalf("createPrincipalCredential(raceowner): %v", err)
	}

	// Baseline: the introspection resolves the default Launcher under the
	// full stored-root scope.
	w = launcherRequest(t, app1, http.MethodGet, "/sessions/create-policy", token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("baseline introspection: %d %s", w.Code, w.Body.String())
	}
	base := decodeCreatePolicy(t, w.Body.String())
	if !base.OK || base.Principal != "raceowner" || base.Launcher != "default" {
		t.Fatalf("baseline response = %+v", base)
	}
	if len(base.AllowedRoots) != 2 {
		t.Fatalf("baseline allowed_roots = %v, want [%s %s]", base.AllowedRoots, home, extra)
	}
	for _, want := range []string{home, extra} {
		if !stringSliceContains(base.AllowedRoots, want) {
			t.Fatalf("baseline allowed_roots = %v, want [%s %s]", base.AllowedRoots, home, extra)
		}
	}

	// Park points:
	//   mutation      - the narrowing's first in-boundary principal lookup
	//                   (SELECT id FROM principals WHERE username = ?);
	//   introspection - the credential auth's principal read (SELECT
	//                   username, enabled FROM principals WHERE id = ?), the
	//                   introspection's last pre-boundary read.
	// The patterns are distinct from every other query in the race phase.
	mutationPoint := newParkedQueryPoint("SELECT id FROM principals WHERE username")
	introspectionPoint := newParkedQueryPoint("SELECT username, enabled FROM principals WHERE id")
	app := &App{
		Config:          app1.Config,
		DB:              openParkedQueryDB(t, app1.Config.DatabasePath, mutationPoint, introspectionPoint),
		AdminTokenHash:  app1.AdminTokenHash,
		userModeDefault: app1.userModeDefault,
	}

	// The race phase runs on a single P: the narrowing and the
	// introspection are ordered purely by their synchronization points, in
	// release order.
	runSinglePinnedP(t, func() {
		// 1. The narrowing parks inside its lifecycleMu boundary, before its
		//    durable DELETE commits.
		narrowingDone := make(chan narrowingResult, 1)
		go func() {
			changed, _, err := app.removePrincipalAllowedRootWithLifecycle("raceowner", extra)
			narrowingDone <- narrowingResult{changed: changed, err: err}
		}()
		<-mutationPoint.parked

		// 2. The introspection runs its pre-boundary authentication, is
		//    pinned at its last pre-boundary read, and after release can
		//    only proceed into the boundary the narrowing still holds.
		introspectionDone := make(chan string, 1)
		go func() {
			mux := http.NewServeMux()
			registerRoutes(mux, app)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/sessions/create-policy", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			mux.ServeHTTP(rec, req)
			introspectionDone <- rec.Body.String()
		}()
		<-introspectionPoint.parked
		close(introspectionPoint.release)

		// 3. The narrowing commits and releases the boundary.
		close(mutationPoint.release)
		got := <-narrowingDone
		if got.err != nil {
			t.Fatalf("removePrincipalAllowedRootWithLifecycle: %v", got.err)
		}
		if !got.changed {
			t.Fatal("removePrincipalAllowedRootWithLifecycle reported no change")
		}

		// 4. The introspection observes the wholly post-narrowing
		//    projection: the narrowed stored-root scope with the same
		//    default Launcher.
		resp := decodeCreatePolicy(t, <-introspectionDone)
		if !resp.OK || resp.Principal != "raceowner" || resp.Launcher != "default" {
			t.Fatalf("introspection response = %+v", resp)
		}
		if len(resp.AllowedRoots) != 1 || resp.AllowedRoots[0] != home {
			t.Fatalf("introspection observed a pre-narrowing or mixed policy state: allowed_roots = %v, want [%s]", resp.AllowedRoots, home)
		}
	})
}

// narrowingResult carries the narrowing mutation's outcome across goroutines.
type narrowingResult struct {
	changed bool
	err     error
}

// TestRacePrincipalDeleteSerializesEffectiveRootsIntrospection proves the
// effective-roots introspection resolves the CURRENT target Principal inside
// the lifecycle boundary. The checked Principal deletion parks inside its
// lifecycleMu critical section before its durable commit; the introspection
// is pinned at its last pre-boundary read (its credential authentication) and
// released into the held boundary, so the deletion commits first and the
// in-boundary re-resolution finds no Principal: the endpoint answers
// 404 principal_not_found, never a successful projection for a disappeared
// incarnation (the pre-boundary identity resolution regression). After the
// race, recreating the same username resolves a wholly new-incarnation
// projection.
func TestRacePrincipalDeleteSerializesEffectiveRootsIntrospection(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app1.Config.AllowedRoots[0].Path

	// Principal victim with stored roots [home, extra] and a credential.
	home := filepath.Join(root, "home", "victim")
	extra := filepath.Join(home, "extra")
	if err := os.MkdirAll(extra, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"victim": home})
	if _, err := createPrincipal(app1.DB, "victim", app1.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(victim): %v", err)
	}
	w := launcherRequest(t, app1, http.MethodPost, "/principals/victim/allowed-roots", testAdminToken, fmt.Sprintf(`{"path":%q}`, extra))
	if w.Code != http.StatusOK {
		t.Fatalf("add extra root: %d %s", w.Code, w.Body.String())
	}

	// Park the deletion at its launcher inventory read (SELECT id FROM
	// launchers WHERE principal_id = ?), reached inside its lifecycleMu
	// boundary after its own non-destructive Principal lookups: while parked,
	// the Principal incarnation and its credential rows are still intact.
	// The introspection below uses the admin authority, whose in-memory
	// authentication cannot be affected by the concurrent deletion, so the
	// 404-after-disappearance outcome is deterministic under every
	// scheduling. The pattern is distinct from every other query in the race
	// phase.
	deletionPoint := newParkedQueryPoint("SELECT id FROM launchers WHERE principal_id")
	app := &App{
		Config:                  app1.Config,
		DB:                      openParkedQueryDB(t, app1.Config.DatabasePath, deletionPoint),
		AdminTokenHash:          app1.AdminTokenHash,
		userModeDefault:         app1.userModeDefault,
		InspectHelperContainers: app1.InspectHelperContainers,
	}
	app.OperationSupervisor = newOperationSupervisor()

	// The race phase runs on a single P: the deletion and the introspection
	// are ordered purely by their synchronization points, in release order.
	runSinglePinnedP(t, func() {
		// 1. The checked deletion parks inside its lifecycleMu boundary,
		//    after its own lookups, before its durable commit.
		deletionDone := make(chan error, 1)
		go func() {
			_, err := app.deletePrincipalChecked(context.Background(), "victim")
			deletionDone <- err
		}()
		<-deletionPoint.parked

		// 2. The introspection is started while the deletion owns the
		//    boundary; its in-boundary re-resolution can only run after the
		//    deletion's commit.
		introspectionDone := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			mux := http.NewServeMux()
			registerRoutes(mux, app)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/principals/victim/effective-allowed-roots", nil)
			req.Header.Set("Authorization", "Bearer "+testAdminToken)
			mux.ServeHTTP(rec, req)
			introspectionDone <- rec
		}()

		// 3. The deletion commits and releases the boundary.
		close(deletionPoint.release)
		if err := <-deletionDone; err != nil {
			t.Fatalf("deletePrincipalChecked(victim): %v", err)
		}

		// 4. The introspection re-resolves the disappeared target inside the
		//    boundary: 404 principal_not_found, never a successful projection.
		rec := <-introspectionDone
		if rec.Code != http.StatusNotFound {
			t.Fatalf("introspection after deletion: expected 404, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		if code := decodeAPIError(t, rec.Body.Bytes()).Code; code != "principal_not_found" {
			t.Fatalf("introspection after deletion: expected principal_not_found, got %q", code)
		}
	})

	// 5. Recreating the same username: the projection belongs wholly to the
	//    newly resolved incarnation (its seeded home root, not the deleted
	//    incarnation's [home, extra] set).
	if _, err := createPrincipal(app.DB, "victim", app.Config.AllowedRoots); err != nil {
		t.Fatalf("recreate victim: %v", err)
	}
	w = launcherRequest(t, app, http.MethodGet, "/principals/victim/effective-allowed-roots", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("introspection after recreation: %d %s", w.Code, w.Body.String())
	}
	resp := decodePolicyRoots(t, w.Body.String())
	if !resp.OK || resp.Principal != "victim" {
		t.Fatalf("introspection after recreation: response = %+v", resp)
	}
	if len(resp.AllowedRoots) != 1 || resp.AllowedRoots[0] != home {
		t.Fatalf("introspection after recreation: allowed_roots = %v, want the new incarnation's [%s]", resp.AllowedRoots, home)
	}
}

// TestRaceEffectiveRootsIntrospectionLinearizesBeforePrincipalDelete proves
// the inverse legal linearization: the introspection acquires lifecycleMu
// first — parked inside its in-boundary resolution at the Principal-roots
// read — and answers the complete old-incarnation projection (identity and
// effective roots) while the checked deletion waits on the held boundary; the
// deletion commits only afterwards.
func TestRaceEffectiveRootsIntrospectionLinearizesBeforePrincipalDelete(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app1.Config.AllowedRoots[0].Path

	home := filepath.Join(root, "home", "victim")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"victim": home})
	if _, err := createPrincipal(app1.DB, "victim", app1.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(victim): %v", err)
	}
	_, token, err := createPrincipalCredential(app1.DB, "victim", "oc")
	if err != nil {
		t.Fatalf("createPrincipalCredential(victim): %v", err)
	}

	// Park the introspection at its first in-boundary Principal-roots read
	// (SELECT root_path, access FROM principal_allowed_roots WHERE principal_id = ?),
	// reached while it holds lifecycleMu. The pattern is distinct from every
	// other query in the race phase.
	introspectionPoint := newParkedQueryPoint("SELECT root_path, access FROM principal_allowed_roots WHERE principal_id")
	app := &App{
		Config:                  app1.Config,
		DB:                      openParkedQueryDB(t, app1.Config.DatabasePath, introspectionPoint),
		AdminTokenHash:          app1.AdminTokenHash,
		userModeDefault:         app1.userModeDefault,
		InspectHelperContainers: app1.InspectHelperContainers,
	}
	app.OperationSupervisor = newOperationSupervisor()

	// The race phase runs on a single P: the introspection and the deletion
	// are ordered purely by their synchronization points, in release order.
	runSinglePinnedP(t, func() {
		// 1. The introspection resolves into its boundary and parks at its
		//    in-boundary Principal-roots read, holding lifecycleMu.
		introspectionDone := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			mux := http.NewServeMux()
			registerRoutes(mux, app)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/principals/victim/effective-allowed-roots", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			mux.ServeHTTP(rec, req)
			introspectionDone <- rec
		}()
		<-introspectionPoint.parked

		// 2. The checked deletion is started while the introspection owns
		//    the boundary.
		deletionDone := make(chan error, 1)
		go func() {
			_, err := app.deletePrincipalChecked(context.Background(), "victim")
			deletionDone <- err
		}()

		// 3. The introspection completes with the wholly old-incarnation
		//    projection: the deletion cannot commit while the boundary is
		//    held.
		close(introspectionPoint.release)
		rec := <-introspectionDone
		if rec.Code != http.StatusOK {
			t.Fatalf("introspection before deletion: expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		resp := decodePolicyRoots(t, rec.Body.String())
		if !resp.OK || resp.Principal != "victim" {
			t.Fatalf("introspection before deletion: response = %+v", resp)
		}
		if len(resp.AllowedRoots) != 1 || resp.AllowedRoots[0] != home {
			t.Fatalf("introspection before deletion: allowed_roots = %v, want the old incarnation's [%s]", resp.AllowedRoots, home)
		}

		// 4. The deletion then acquires the boundary and commits.
		if err := <-deletionDone; err != nil {
			t.Fatalf("deletePrincipalChecked(victim): %v", err)
		}
	})
}

// TestRaceCreatePolicyIntrospectionLinearizesBeforeRootNarrowing proves the
// inverse legal linearization of the create-policy introspection race: the
// introspection acquires lifecycleMu first — pinned inside its in-boundary
// resolution at the default-Launcher lookup — and observes the pre-narrowing
// policy state completely, while the Principal allowed-root narrowing waits
// on the held boundary and only commits afterwards. Because the
// introspection is pinned inside the same boundary real Session creation
// uses, this also proves introspection and actual Session creation share one
// policy semantics owner. An unserialized introspection would not hold the
// boundary, so the narrowing could commit while it resolves and the response
// would leak the post-narrowing roots.
func TestRaceCreatePolicyIntrospectionLinearizesBeforeRootNarrowing(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app1.Config.AllowedRoots[0].Path

	home := filepath.Join(root, "home", "raceowner")
	extra := filepath.Join(home, "extra")
	if err := os.MkdirAll(extra, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"raceowner": home})
	if _, err := createPrincipal(app1.DB, "raceowner", app1.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(raceowner): %v", err)
	}
	w := launcherRequest(t, app1, http.MethodPost, "/principals/raceowner/allowed-roots", testAdminToken, fmt.Sprintf(`{"path":%q}`, extra))
	if w.Code != http.StatusOK {
		t.Fatalf("add extra root: %d %s", w.Code, w.Body.String())
	}
	_, token, err := createPrincipalCredential(app1.DB, "raceowner", "oc")
	if err != nil {
		t.Fatalf("createPrincipalCredential(raceowner): %v", err)
	}

	// Park points:
	//   introspection - the default-Launcher lookup, the introspection's
	//                   first in-boundary policy read (SELECT id FROM
	//                   launchers WHERE principal_id = ? AND name = 'default');
	//   mutation      - the narrowing's durable DELETE.
	// The patterns are distinct from every other query in the race phase.
	introspectionPoint := newParkedQueryPoint("SELECT id FROM launchers WHERE principal_id")
	mutationPoint := newParkedQueryPoint("DELETE FROM principal_allowed_roots")
	app := &App{
		Config:          app1.Config,
		DB:              openParkedQueryDB(t, app1.Config.DatabasePath, introspectionPoint, mutationPoint),
		AdminTokenHash:  app1.AdminTokenHash,
		userModeDefault: app1.userModeDefault,
	}

	// The race phase runs on a single P: the introspection and the
	// narrowing are ordered purely by their synchronization points, in
	// release order.
	runSinglePinnedP(t, func() {
		// 1. The introspection resolves into its boundary and parks at its
		//    first in-boundary policy read, holding lifecycleMu.
		introspectionDone := make(chan string, 1)
		go func() {
			mux := http.NewServeMux()
			registerRoutes(mux, app)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/sessions/create-policy", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			mux.ServeHTTP(rec, req)
			introspectionDone <- rec.Body.String()
		}()
		<-introspectionPoint.parked

		// 2. The narrowing is started while the introspection owns the
		//    boundary.
		narrowingDone := make(chan narrowingResult, 1)
		go func() {
			changed, _, err := app.removePrincipalAllowedRootWithLifecycle("raceowner", extra)
			narrowingDone <- narrowingResult{changed: changed, err: err}
		}()

		// 3. The narrowing's DELETE barrier opens before the introspection
		//    resumes: a serialized narrowing is blocked on the held
		//    boundary and cannot have committed, while an unserialized
		//    narrowing commits here.
		// 3. The narrowing's DELETE barrier opens before the introspection
		//    resumes: a serialized narrowing is blocked on the held
		//    boundary and cannot have committed, while an unserialized
		//    narrowing commits here.
		close(mutationPoint.release)

		// 4. The introspection completes with the wholly pre-narrowing
		//    projection: the serialized narrowing cannot commit while the
		//    boundary is held.
		close(introspectionPoint.release)
		resp := decodeCreatePolicy(t, <-introspectionDone)
		if !resp.OK || resp.Principal != "raceowner" || resp.Launcher != "default" {
			t.Fatalf("introspection response = %+v", resp)
		}
		if len(resp.AllowedRoots) != 2 {
			t.Fatalf("introspection observed a post-narrowing or mixed policy state: allowed_roots = %v, want [%s %s]", resp.AllowedRoots, home, extra)
		}
		for _, want := range []string{home, extra} {
			if !stringSliceContains(resp.AllowedRoots, want) {
				t.Fatalf("introspection observed a post-narrowing or mixed policy state: allowed_roots = %v, want [%s %s]", resp.AllowedRoots, home, extra)
			}
		}

		// 5. The narrowing then acquires the boundary, commits its DELETE,
		//    and completes.
		got := <-narrowingDone
		if got.err != nil {
			t.Fatalf("removePrincipalAllowedRootWithLifecycle: %v", got.err)
		}
		if !got.changed {
			t.Fatal("removePrincipalAllowedRootWithLifecycle reported no change")
		}
	})
}

func stringSliceContains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
