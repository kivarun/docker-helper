package main

// The narrow Launcher allowed-root mutations (add/remove) and the explicit
// inherit replacement: authority never broadens — an add narrows an
// inherit-scope Launcher to restricted scope inside the effective Principal
// ceiling, a remove never changes the scope mode (removing the last restricted
// root leaves a fail-closed restricted-with-zero-roots Launcher, never an
// automatic inherit), and returning to inherited roots is the explicit inherit
// operation only.

import (
	"database/sql"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// setupLauncherAllowedRootDomain provisions a system-mode Principal and an
// inherit-scope Launcher named 'agent', returning the db, launcher, the
// global root, and an in-ceiling directory.
func setupLauncherAllowedRootDomain(t *testing.T) (*sql.DB, *LauncherWithPrincipal, string, string) {
	t.Helper()
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, home := setupPrincipalForLauncherTest(t, db, globalRoots, "owner")
	inRoot := filepath.Join(home, "proj")
	if err := os.MkdirAll(inRoot, 0755); err != nil {
		t.Fatal(err)
	}
	l, _, _, err := createLauncher(db, pid, "agent", LauncherScopeInherit, nil, nil, false)
	if err != nil {
		t.Fatalf("createLauncher(agent): %v", err)
	}
	return db, l, globalRoots[0], inRoot
}

func readLauncherScopeMode(t *testing.T, db *sql.DB, launcherID string) LauncherScopeMode {
	t.Helper()
	var mode string
	if err := db.QueryRow(`SELECT scope_mode FROM launchers WHERE id = ?`, launcherID).Scan(&mode); err != nil {
		t.Fatalf("read launcher scope: %v", err)
	}
	return LauncherScopeMode(mode)
}

func readLauncherStoredRoots(t *testing.T, db *sql.DB, launcherID string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT root_path FROM launcher_allowed_roots WHERE launcher_id = ? ORDER BY root_path`, launcherID)
	if err != nil {
		t.Fatalf("read launcher roots: %v", err)
	}
	defer rows.Close()
	var roots []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return roots
}

func TestLauncherAllowedRootAddNarrowsInherit(t *testing.T) {
	db, l, globalRoot, inRoot := setupLauncherAllowedRootDomain(t)

	committed, changed, canonical, err := addLauncherAllowedRoot(db, l, inRoot, testEffectivePrincipalRoots(t, db, l.PrincipalID, []string{globalRoot}))
	if err != nil {
		t.Fatalf("addLauncherAllowedRoot: %v", err)
	}
	if !changed || canonical != inRoot {
		t.Fatalf("add = (changed=%v, %q), want (true, %q)", changed, canonical, inRoot)
	}
	if got := readLauncherScopeMode(t, db, l.ID); got != LauncherScopeRestricted {
		t.Fatalf("scope after first add = %q, want restricted", got)
	}
	if got := readLauncherStoredRoots(t, db, l.ID); !slices.Equal(got, []string{inRoot}) {
		t.Fatalf("stored roots = %v, want [%s]", got, inRoot)
	}
	// The committed projection reports the post-mutation state without any
	// post-commit read: the first add commits the restricted scope with the
	// added root as the stored root set.
	if committed.ScopeMode != LauncherScopeRestricted {
		t.Fatalf("committed projection scope = %q, want restricted", committed.ScopeMode)
	}
	if !slices.Equal(committed.AllowedRoots, []string{inRoot}) {
		t.Fatalf("committed projection roots = %v, want [%s]", committed.AllowedRoots, inRoot)
	}

	// Adding the same root again is the idempotent no-op and must not disturb
	// the committed scope; the committed projection keeps reflecting the
	// actual committed state (restricted, unchanged roots).
	committed, changed, _, err = addLauncherAllowedRoot(db, committed, inRoot, testEffectivePrincipalRoots(t, db, l.PrincipalID, []string{globalRoot}))
	if err != nil {
		t.Fatalf("second addLauncherAllowedRoot: %v", err)
	}
	if changed {
		t.Fatal("second add reported changed")
	}
	if got := readLauncherScopeMode(t, db, l.ID); got != LauncherScopeRestricted {
		t.Fatalf("scope after duplicate add = %q, want unchanged restricted", got)
	}
	if committed.ScopeMode != LauncherScopeRestricted || !slices.Equal(committed.AllowedRoots, []string{inRoot}) {
		t.Fatalf("committed projection after duplicate add = (%q, %v), want (restricted, [%s])", committed.ScopeMode, committed.AllowedRoots, inRoot)
	}
}

func TestLauncherAllowedRootRemoveLastStaysRestricted(t *testing.T) {
	db, l, globalRoot, inRoot := setupLauncherAllowedRootDomain(t)
	ceiling := testEffectivePrincipalRoots(t, db, l.PrincipalID, []string{globalRoot})
	if _, _, _, err := addLauncherAllowedRoot(db, l, inRoot, ceiling); err != nil {
		t.Fatalf("addLauncherAllowedRoot: %v", err)
	}

	changed, _, err := removeLauncherAllowedRoot(db, l.ID, inRoot)
	if err != nil {
		t.Fatalf("removeLauncherAllowedRoot: %v", err)
	}
	if !changed {
		t.Fatal("remove reported no change")
	}
	// Removing the last restricted root must NOT silently return to inherit:
	// that would broaden authority. The Launcher stays restricted with zero
	// stored roots, the fail-closed state with no admissible Session workspace.
	if got := readLauncherScopeMode(t, db, l.ID); got != LauncherScopeRestricted {
		t.Fatalf("scope after removing the last root = %q, want restricted (no silent inherit)", got)
	}
	if got := readLauncherStoredRoots(t, db, l.ID); len(got) != 0 {
		t.Fatalf("stored roots after removing the last root = %v, want none", got)
	}
	snap, err := loadSessionOwnershipSnapshot(db, l.ID)
	if err != nil {
		t.Fatalf("loadSessionOwnershipSnapshot: %v", err)
	}
	effective, err := computeLauncherEffectiveRoots([]string{globalRoot}, snap, 0, false)
	if err != nil {
		t.Fatalf("computeLauncherEffectiveRoots: %v", err)
	}
	if len(effective) != 0 {
		t.Fatalf("effective roots after removing the last root = %v, want the empty fail-closed set", effective)
	}
}

func TestLauncherAllowedRootExplicitInheritRestoresCeiling(t *testing.T) {
	db, l, globalRoot, inRoot := setupLauncherAllowedRootDomain(t)
	ceiling := testEffectivePrincipalRoots(t, db, l.PrincipalID, []string{globalRoot})
	if _, _, _, err := addLauncherAllowedRoot(db, l, inRoot, ceiling); err != nil {
		t.Fatalf("addLauncherAllowedRoot: %v", err)
	}
	cur, err := findLauncherByID(db, l.ID)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := replaceLauncherScope(db, cur, LauncherScopeInherit, nil, ceiling)
	if err != nil {
		t.Fatalf("explicit inherit replaceLauncherScope: %v", err)
	}
	if updated.ScopeMode != LauncherScopeInherit {
		t.Fatalf("scope after explicit inherit = %q, want inherit", updated.ScopeMode)
	}
	if got := readLauncherStoredRoots(t, db, l.ID); len(got) != 0 {
		t.Fatalf("stored roots after explicit inherit = %v, want none", got)
	}
	snap, err := loadSessionOwnershipSnapshot(db, l.ID)
	if err != nil {
		t.Fatalf("loadSessionOwnershipSnapshot: %v", err)
	}
	effective, err := computeLauncherEffectiveRoots([]string{globalRoot}, snap, 0, false)
	if err != nil {
		t.Fatalf("computeLauncherEffectiveRoots: %v", err)
	}
	// Inherit applies the Principal ceiling unchanged: the Principal's stored
	// root (its home) is the effective root, not the removed launcher root.
	if !slices.Equal(effective, []string{globalRoot + "/home/owner"}) {
		t.Fatalf("effective roots after explicit inherit = %v, want the Principal ceiling", effective)
	}
}

func TestLauncherAllowedRootOutsideCeilingRejected(t *testing.T) {
	db, l, globalRoot, _ := setupLauncherAllowedRootDomain(t)
	outside := filepath.Join(filepath.Dir(globalRoot), "outside-ceiling")
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(outside) })

	ceiling := testEffectivePrincipalRoots(t, db, l.PrincipalID, []string{globalRoot})
	_, _, _, err := addLauncherAllowedRoot(db, l, outside, ceiling)
	if !errors.Is(err, ErrLauncherRootOutsidePrincipal) {
		t.Fatalf("add outside the ceiling = %v, want ErrLauncherRootOutsidePrincipal", err)
	}
	if got := readLauncherScopeMode(t, db, l.ID); got != LauncherScopeInherit {
		t.Fatalf("rejected add must not change the scope, got %q", got)
	}
	if got := readLauncherStoredRoots(t, db, l.ID); len(got) != 0 {
		t.Fatalf("rejected add must not store a root, got %v", got)
	}
}

// TestLauncherAllowedRootCommittedProjectionCanonicalOrder proves the
// committed Launcher projection carries the same canonical lexical root
// ordering as a fresh DB projection, composed without any post-commit read:
// adding /a to a launcher whose stored root is /z commits [/a /z].
func TestLauncherAllowedRootCommittedProjectionCanonicalOrder(t *testing.T) {
	db, l, globalRoot, inRoot := setupLauncherAllowedRootDomain(t)
	zRoot := filepath.Join(inRoot, "z-dir")
	aRoot := filepath.Join(inRoot, "a-dir")
	for _, dir := range []string{zRoot, aRoot} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	ceiling := testEffectivePrincipalRoots(t, db, l.PrincipalID, []string{globalRoot})

	// current roots: [/z]; then add /a.
	committed, changed, _, err := addLauncherAllowedRoot(db, l, zRoot, ceiling)
	if err != nil {
		t.Fatalf("add z root: %v", err)
	}
	if !changed {
		t.Fatal("z add reported no change")
	}
	committed, changed, _, err = addLauncherAllowedRoot(db, committed, aRoot, ceiling)
	if err != nil {
		t.Fatalf("add a root: %v", err)
	}
	if !changed {
		t.Fatal("a add reported no change")
	}

	// The committed projection is canonically ordered: [/a /z], never the
	// append order [/z /a].
	if !slices.Equal(committed.AllowedRoots, []string{aRoot, zRoot}) {
		t.Fatalf("committed projection roots = %v, want [%s %s]", committed.AllowedRoots, aRoot, zRoot)
	}
	// The fresh DB projection has the same canonical order.
	if got := readLauncherStoredRoots(t, db, l.ID); !slices.Equal(got, []string{aRoot, zRoot}) {
		t.Fatalf("fresh DB roots = %v, want [%s %s]", got, aRoot, zRoot)
	}
}

func TestLauncherAllowedRootRemoveMatchesCanonicalPath(t *testing.T) {
	db, l, globalRoot, inRoot := setupLauncherAllowedRootDomain(t)
	ceiling := testEffectivePrincipalRoots(t, db, l.PrincipalID, []string{globalRoot})
	if _, _, _, err := addLauncherAllowedRoot(db, l, inRoot, ceiling); err != nil {
		t.Fatalf("addLauncherAllowedRoot: %v", err)
	}

	// Relative paths are rejected before any lookup.
	if _, _, err := removeLauncherAllowedRoot(db, l.ID, filepath.Base(inRoot)); !errors.Is(err, ErrInvalidAllowedRoot) {
		t.Fatalf("relative remove = %v, want ErrInvalidAllowedRoot", err)
	}
	// A nonexistent path with the canonical spelling still matches the stored
	// root (removal does not require the path to exist).
	os.RemoveAll(inRoot)
	changed, _, err := removeLauncherAllowedRoot(db, l.ID, inRoot)
	if err != nil {
		t.Fatalf("remove of nonexistent path: %v", err)
	}
	if !changed {
		t.Fatal("remove of the stored root reported no change")
	}
}

func TestLauncherAllowedRootLifecycleOwners(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	root := app.Config.AllowedRoots[0]
	setupLauncherHandlerPrincipal(t, app, "owner")
	pa, err := findPrincipalByUsername(app.DB, "owner")
	if err != nil {
		t.Fatal(err)
	}
	l, _, _, err := createLauncher(app.DB, int64(pa.ID), "agent", LauncherScopeInherit, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	// The only in-ceiling candidate is inside the Principal's stored root
	// (its home): the ceiling is the global root narrowed by the stored roots.
	inRoot := filepath.Join(root, "home", "owner", "in-root")
	if err := os.MkdirAll(inRoot, 0755); err != nil {
		t.Fatal(err)
	}

	// The add owner resolves the ceiling and refuses an outside-ceiling root.
	if _, _, _, err := app.addLauncherAllowedRootWithLifecycle(l.ID, filepath.Dir(root)); !errors.Is(err, ErrLauncherRootOutsidePrincipal) {
		t.Fatalf("owner add outside ceiling = %v, want ErrLauncherRootOutsidePrincipal", err)
	}
	committed, changed, _, err := app.addLauncherAllowedRootWithLifecycle(l.ID, inRoot)
	if err != nil {
		t.Fatalf("owner add: %v", err)
	}
	if !changed {
		t.Fatal("owner add reported no change")
	}
	// The owner returns the committed post-mutation projection without any
	// post-commit read: the first add commits the restricted scope.
	if committed.ScopeMode != LauncherScopeRestricted {
		t.Fatalf("owner committed projection scope = %q, want restricted", committed.ScopeMode)
	}
	// Unknown Launcher is not found.
	if _, _, _, err := app.addLauncherAllowedRootWithLifecycle("dhl_00000000000000000000000000000000", inRoot); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("owner add unknown launcher = %v, want ErrLauncherNotFound", err)
	}
	// The remove owner never changes the scope mode.
	changed, _, err = app.removeLauncherAllowedRootWithLifecycle(l.ID, inRoot)
	if err != nil {
		t.Fatalf("owner remove: %v", err)
	}
	if !changed {
		t.Fatal("owner remove reported no change")
	}
	if got := readLauncherScopeMode(t, app.DB, l.ID); got != LauncherScopeRestricted {
		t.Fatalf("scope after owner remove = %q, want restricted (fail-closed)", got)
	}
	if _, _, err := app.removeLauncherAllowedRootWithLifecycle("dhl_00000000000000000000000000000000", inRoot); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("owner remove unknown launcher = %v, want ErrLauncherNotFound", err)
	}

	// The Principal credential of another Principal cannot drive these owners
	// through the HTTP surface: the non-disclosing 404 covers the narrow
	// mutations exactly like every other Launcher route.
	_, otherToken := setupLauncherHandlerPrincipal(t, app, "other")
	_, _, _, err = createLauncher(app.DB, int64(pa.ID), "foreign", LauncherScopeInherit, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if w := launcherRequest(t, app, http.MethodPost, "/principals/owner/launchers/foreign/allowed-roots", otherToken, `{"path":"`+inRoot+`"}`); w.Code != http.StatusNotFound {
		t.Fatalf("foreign principal add: expected 404, got %d (body=%s)", w.Code, w.Body.String())
	}
	if w := launcherRequest(t, app, http.MethodDelete, "/principals/owner/launchers/foreign/allowed-roots", otherToken, `{"path":"`+inRoot+`"}`); w.Code != http.StatusNotFound {
		t.Fatalf("foreign principal remove: expected 404, got %d (body=%s)", w.Code, w.Body.String())
	}

}
