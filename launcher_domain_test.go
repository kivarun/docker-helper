package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupPrincipalForLauncherTest creates a Principal with a real home directory
// under the first global root and returns its ID and home path.
func setupPrincipalForLauncherTest(t *testing.T, db *sql.DB, globalRoots []string, username string) (int64, string) {
	t.Helper()
	home := filepath.Join(globalRoots[0], "home", username)
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	t.Cleanup(func() { OSUserLookup = orig })
	OSUserLookup = func(u string) (string, string, string, error) {
		return "2001", "2001", home, nil
	}
	p, err := createPrincipal(db, username, globalRoots)
	if err != nil {
		t.Fatalf("createPrincipal(%s): %v", username, err)
	}
	return int64(p.ID), home
}

func TestLauncherCreateInheritRejectsRootsAtDomain(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, home := setupPrincipalForLauncherTest(t, db, globalRoots, "a")
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0755); err != nil {
		t.Fatal(err)
	}

	_, _, _, err := createLauncher(db, pid, "work", LauncherScopeInherit, []string{proj}, globalRoots, false)
	if !errors.Is(err, ErrInvalidAllowedRoots) {
		t.Fatalf("expected ErrInvalidAllowedRoots for inherit+roots, got: %v", err)
	}
	// The Principal's auto-provisioned 'default' Launcher is the only row; the
	// rejected creation added nothing.
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM launchers WHERE principal_id=?`, pid).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected no launcher added by rejected creation, got %d", count)
	}
}

func TestLauncherCreateRestrictedEmptyRejectedAtDomain(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "b")

	_, _, _, err := createLauncher(db, pid, "work", LauncherScopeRestricted, nil, globalRoots, false)
	if !errors.Is(err, ErrInvalidAllowedRoots) {
		t.Fatalf("expected ErrInvalidAllowedRoots for restricted without roots, got: %v", err)
	}
}

func TestLauncherScopeReplaceInheritRejectsRootsAtDomain(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, home := setupPrincipalForLauncherTest(t, db, globalRoots, "c")

	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0755); err != nil {
		t.Fatal(err)
	}

	// inherit + roots must be rejected at the domain boundary.
	if _, err := replaceLauncherScope(db, l.ID, LauncherScopeInherit, []string{proj}, globalRoots); !errors.Is(err, ErrInvalidAllowedRoots) {
		t.Fatalf("expected ErrInvalidAllowedRoots for inherit+roots, got: %v", err)
	}
	// Prior scope/roots unchanged.
	after, err := findLauncherByID(db, l.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.ScopeMode != LauncherScopeInherit || len(after.AllowedRoots) != 0 {
		t.Errorf("scope/roots changed after failed replacement: %+v", after)
	}

	// Restricted with empty roots must also be rejected at the domain boundary.
	if _, err := replaceLauncherScope(db, l.ID, LauncherScopeRestricted, nil, globalRoots); !errors.Is(err, ErrInvalidAllowedRoots) {
		t.Fatalf("expected ErrInvalidAllowedRoots for restricted without roots, got: %v", err)
	}
	after2, err := findLauncherByID(db, l.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after2.ScopeMode != LauncherScopeInherit || len(after2.AllowedRoots) != 0 {
		t.Errorf("scope/roots changed after failed replacement: %+v", after2)
	}
}

// TestLauncherCreateWithCredentialReturnsProjectionWithoutPostCommitLookup
// proves createLauncher returns a projection built from committed values: a
// query-throttled DB that permits exactly the single pre-commit owner lookup
// (findPrincipalByID) and fails any further query still returns the one-time
// bearer secret successfully. Were the removed post-commit findLauncherByID
// still performed, it would be the second query and would be rejected.
func TestLauncherCreateWithCredentialReturnsProjectionWithoutPostCommitLookup(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"
	db, err := openDatabase(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "d")

	// Allow the one pre-commit owner query, fail all subsequent queries.
	fq := newFailQueryAfterDB(t, path, 1, errMockQueryFail)
	defer fq.Close()

	l, cred, token, err := createLauncher(fq, pid, "work", LauncherScopeInherit, nil, globalRoots, true)
	if err != nil {
		t.Fatalf("createLauncher under post-commit-query failure: %v", err)
	}
	// Projection returned from committed values.
	if l.PrincipalName != "d" || l.Name != "work" || !l.Enabled || l.ScopeMode != LauncherScopeInherit {
		t.Errorf("unexpected launcher projection: %+v", l)
	}
	if len(l.AllowedRoots) != 0 {
		t.Errorf("expected no roots for inherit, got %v", l.AllowedRoots)
	}
	if cred == nil || !strings.HasPrefix(token, credentialTokenPrefix) {
		t.Fatalf("expected issued credential/token, got cred=%+v token=%q", cred, token)
	}
	// Credential still authenticates on the real DB, proving commit persisted it.
	res, err := authenticateCredential(db, token)
	if err != nil || res.Launcher == nil || res.Launcher.LauncherID != l.ID {
		t.Fatalf("issued launcher token should authenticate, got err=%v res=%+v", err, res)
	}
}

func TestLauncherUpdateNameUniqueConflictMappedToExists(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "e")

	_, _, _, err := createLauncher(db, pid, "a", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	l2, _, _, err := createLauncher(db, pid, "b", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}

	// Force the UPDATE to hit the canonical UNIQUE(principal_id, name)
	// constraint directly, bypassing the pre-check equivalence, by using the
	// name that already exists under the same Principal. The translation to
	// ErrLauncherExists is what a concurrent rename surfaces.
	dup := "a"
	if _, err := persistLauncherChange(db, l2.ID, &dup, nil); !errors.Is(err, ErrLauncherExists) {
		t.Fatalf("expected ErrLauncherExists from UPDATE unique conflict, got: %v", err)
	}
}

func TestLauncherCreateInherit(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "alice")

	l, cred, token, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}
	if !strings.HasPrefix(l.ID, launcherIDPrefix) {
		t.Errorf("expected dhl_ prefix, got %q", l.ID)
	}
	if l.ScopeMode != LauncherScopeInherit || len(l.AllowedRoots) != 0 {
		t.Errorf("expected inherit with no roots, got scope=%s roots=%v", l.ScopeMode, l.AllowedRoots)
	}
	if cred != nil || token != "" {
		t.Errorf("expected no credential, got %+v token=%q", cred, token)
	}
}

func TestLauncherCreateRestricted(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, home := setupPrincipalForLauncherTest(t, db, globalRoots, "bob")

	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0755); err != nil {
		t.Fatal(err)
	}
	l, _, _, err := createLauncher(db, pid, "ci", LauncherScopeRestricted, []string{proj}, globalRoots, false)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}
	if l.ScopeMode != LauncherScopeRestricted {
		t.Errorf("expected restricted scope, got %s", l.ScopeMode)
	}
	if len(l.AllowedRoots) != 1 || l.AllowedRoots[0] != proj {
		t.Errorf("expected stored root %q, got %v", proj, l.AllowedRoots)
	}
}

func TestLauncherCreateRestrictedOutsidePrincipalRejected(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "carol")

	outside := filepath.Join(globalRoots[0], "outside", "proj")
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := createLauncher(db, pid, "ci", LauncherScopeRestricted, []string{outside}, globalRoots, false)
	if err == nil || !errors.Is(err, ErrLauncherRootOutsidePrincipal) {
		t.Fatalf("expected ErrLauncherRootOutsidePrincipal, got: %v", err)
	}
	// No launcher row from the rejected creation must remain: only the
	// Principal's auto-provisioned 'default' Launcher.
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM launchers WHERE principal_id=?`, pid).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected no launcher added by rejected creation, got %d", count)
	}
}

func TestLauncherDuplicateNameWithinPrincipal(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "dave")
	pid2, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "erin")

	if _, _, _, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, false); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, _, _, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, false); !errors.Is(err, ErrLauncherExists) {
		t.Fatalf("expected ErrLauncherExists for duplicate name, got: %v", err)
	}
	if _, _, _, err := createLauncher(db, pid2, "work", LauncherScopeInherit, nil, globalRoots, false); err != nil {
		t.Fatalf("same name under another principal should be allowed: %v", err)
	}
}

// TestLauncherNameValidatorSharedByCreateAndRename proves create and rename
// reject exactly the same invalid names through the single centralized
// validator: no trimming or case folding on either path.
func TestLauncherNameValidatorSharedByCreateAndRename(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "frida")

	for _, bad := range []string{"Foo", " agent1 ", "agent1 ", "foo_bar", "-agent", "agent-"} {
		if _, _, _, err := createLauncher(db, pid, bad, LauncherScopeInherit, nil, globalRoots, false); !errors.Is(err, ErrInvalidLauncherName) {
			t.Fatalf("create(%q): expected ErrInvalidLauncherName, got %v", bad, err)
		}
	}

	l, _, _, err := createLauncher(db, pid, "agent1", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatalf("create(agent1): %v", err)
	}
	for _, bad := range []string{"Foo", " agent2 ", "foo_bar"} {
		if _, err := persistLauncherChange(db, l.ID, &bad, nil); !errors.Is(err, ErrInvalidLauncherName) {
			t.Fatalf("rename(%q): expected ErrInvalidLauncherName, got %v", bad, err)
		}
	}
	renamed := "build-agent-2"
	if _, err := persistLauncherChange(db, l.ID, &renamed, nil); err != nil {
		t.Fatalf("rename(agent1 -> %s): %v", renamed, err)
	}
	updated, err := findLauncherByID(db, l.ID)
	if err != nil {
		t.Fatalf("findLauncherByID after rename: %v", err)
	}
	if updated.Name != renamed {
		t.Errorf("renamed name = %q, want %q", updated.Name, renamed)
	}
}

func TestLauncherFindListScoped(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "frank")

	a, _, _, err := createLauncher(db, pid, "a", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := createLauncher(db, pid, "b", LauncherScopeInherit, nil, globalRoots, false); err != nil {
		t.Fatal(err)
	}

	got, err := findLauncherByID(db, a.ID)
	if err != nil {
		t.Fatalf("findLauncherByID: %v", err)
	}
	if got.Name != "a" || got.PrincipalName != "frank" {
		t.Errorf("unexpected launcher: %+v", got)
	}

	list, err := listLaunchersForPrincipal(db, pid)
	if err != nil {
		t.Fatalf("listLaunchersForPrincipal: %v", err)
	}
	// "a", "b", plus the Principal's auto-provisioned 'default' Launcher.
	if len(list) != 3 {
		t.Fatalf("expected 3 launchers, got %d", len(list))
	}

	if _, err := findLauncherByID(db, "dhl_missing"); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("expected ErrLauncherNotFound, got: %v", err)
	}
}

// TestLauncherScopedSelectorResolution proves the (Principal, selector) ->
// Launcher resolution rules at the domain level: 'default' under two
// Principals resolves independently, the name and the ID of the same Launcher
// resolve to the same row, a foreign ID and a foreign same-name Launcher are
// indistinguishable from a missing one through the wrong Principal, and
// malformed or ID-shaped selectors never fall back to any other lookup.
func TestLauncherScopedSelectorResolution(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pidA, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "hal")
	pidB, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "ivan")

	aliceDefaultID := mustAddDefaultLauncher(t, db, pidA)
	bobDefaultID := mustAddDefaultLauncher(t, db, pidB)
	agent, _, _, err := createLauncher(db, pidA, "build-agent", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}

	// 'default' under two Principals resolves independently.
	got, err := findLauncherForPrincipal(db, pidA, "default")
	if err != nil || got.ID != aliceDefaultID {
		t.Errorf("alice/default: got (%v, %v), want %q", got, err, aliceDefaultID)
	}
	got, err = findLauncherForPrincipal(db, pidB, "default")
	if err != nil || got.ID != bobDefaultID {
		t.Errorf("bob/default: got (%v, %v), want %q", got, err, bobDefaultID)
	}

	// Name and ID resolve the same Launcher.
	byName, err := findLauncherForPrincipal(db, pidA, "build-agent")
	if err != nil {
		t.Fatalf("resolve by name: %v", err)
	}
	byID, err := findLauncherForPrincipal(db, pidA, agent.ID)
	if err != nil {
		t.Fatalf("resolve by ID: %v", err)
	}
	if byName.ID != agent.ID || byID.ID != agent.ID {
		t.Errorf("name/ID resolution disagree: %q vs %q, want %q", byName.ID, byID.ID, agent.ID)
	}

	// A foreign ID under another Principal is the same not-found as a missing
	// Launcher, and a foreign same-name Launcher is never found through the
	// wrong Principal.
	for _, tc := range []struct {
		name     string
		pid      int64
		selector string
	}{
		{"foreign ID under wrong principal", pidB, agent.ID},
		{"malformed selector", pidA, "Foo"},
		{"malformed selector with space", pidA, "agent one"},
		{"ID-shaped nonexistent ID", pidA, "dhl_00000000000000000000000000000000"},
		{"uppercase ID prefix", pidA, "DHL_0000000000000000000000000000000a"},
	} {
		if _, err := findLauncherForPrincipal(db, tc.pid, tc.selector); !errors.Is(err, ErrLauncherNotFound) {
			t.Errorf("%s (%q): expected ErrLauncherNotFound, got %v", tc.name, tc.selector, err)
		}
	}

	// A foreign same-name Launcher is never found through the wrong Principal,
	// proven against a real launcher: the name resolves for bob (its owner)
	// but never for alice.
	if _, _, _, err := createLauncher(db, pidB, "foreign-name", LauncherScopeInherit, nil, globalRoots, false); err != nil {
		t.Fatalf("create bob/foreign-name: %v", err)
	}
	if _, err := findLauncherForPrincipal(db, pidA, "foreign-name"); !errors.Is(err, ErrLauncherNotFound) {
		t.Errorf("foreign same-name through wrong principal: expected ErrLauncherNotFound, got %v", err)
	}
	got, err = findLauncherForPrincipal(db, pidB, "foreign-name")
	if err != nil {
		t.Fatalf("same name under the owning principal must resolve: %v", err)
	}
	if got.PrincipalID != pidB {
		t.Errorf("resolved wrong owner: %d, want %d", got.PrincipalID, pidB)
	}
}

func TestLauncherUpdateName(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "gina")

	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	name := "renamed"
	if _, err := persistLauncherChange(db, l.ID, &name, nil); err != nil {
		t.Fatalf("persistLauncherChange: %v", err)
	}
	updated, err := findLauncherByID(db, l.ID)
	if err != nil {
		t.Fatalf("findLauncherByID: %v", err)
	}
	if updated.Name != "renamed" {
		t.Errorf("expected name renamed, got %q", updated.Name)
	}

	// Duplicate name within principal is rejected.
	_, _, _, err = createLauncher(db, pid, "other", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	dup := "other"
	if _, err := persistLauncherChange(db, l.ID, &dup, nil); !errors.Is(err, ErrLauncherExists) {
		t.Fatalf("expected ErrLauncherExists, got: %v", err)
	}
}

func TestLauncherUpdateEnabled(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "hank")

	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	enabled := false
	if _, err := persistLauncherChange(db, l.ID, nil, &enabled); err != nil {
		t.Fatalf("persistLauncherChange: %v", err)
	}
	updated, err := findLauncherByID(db, l.ID)
	if err != nil {
		t.Fatalf("findLauncherByID: %v", err)
	}
	if updated.Enabled {
		t.Error("expected launcher disabled")
	}
}

func TestLauncherScopeReplaceInheritToRestricted(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, home := setupPrincipalForLauncherTest(t, db, globalRoots, "iris")

	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0755); err != nil {
		t.Fatal(err)
	}

	updated, err := replaceLauncherScope(db, l.ID, LauncherScopeRestricted, []string{proj}, globalRoots)
	if err != nil {
		t.Fatalf("replaceLauncherScope: %v", err)
	}
	if updated.ScopeMode != LauncherScopeRestricted || len(updated.AllowedRoots) != 1 {
		t.Errorf("expected restricted with one root, got %+v", updated)
	}
}

func TestLauncherScopeReplaceRestrictedToInheritClearsRoots(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, home := setupPrincipalForLauncherTest(t, db, globalRoots, "judy")

	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0755); err != nil {
		t.Fatal(err)
	}
	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeRestricted, []string{proj}, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}

	updated, err := replaceLauncherScope(db, l.ID, LauncherScopeInherit, nil, globalRoots)
	if err != nil {
		t.Fatalf("replaceLauncherScope: %v", err)
	}
	if updated.ScopeMode != LauncherScopeInherit || len(updated.AllowedRoots) != 0 {
		t.Errorf("expected inherit with cleared roots, got %+v", updated)
	}
	// Stored rows cleared.
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM launcher_allowed_roots WHERE launcher_id=?`, l.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0 stored roots, got %d", count)
	}
}

func TestLauncherScopeReplaceInvalidRootRejectedAtomically(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, home := setupPrincipalForLauncherTest(t, db, globalRoots, "kevin")

	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0755); err != nil {
		t.Fatal(err)
	}
	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeRestricted, []string{proj}, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}

	outside := filepath.Join(globalRoots[0], "outside")
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := replaceLauncherScope(db, l.ID, LauncherScopeRestricted, []string{outside}, globalRoots); !errors.Is(err, ErrLauncherRootOutsidePrincipal) {
		t.Fatalf("expected ErrLauncherRootOutsidePrincipal, got: %v", err)
	}
	// Old scope/roots unchanged.
	after, err := findLauncherByID(db, l.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.ScopeMode != LauncherScopeRestricted || len(after.AllowedRoots) != 1 || after.AllowedRoots[0] != proj {
		t.Errorf("scope/roots changed after failed replacement: %+v", after)
	}
}

func TestLauncherDeleteRemovesRootsAndCredential(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, home := setupPrincipalForLauncherTest(t, db, globalRoots, "liam")

	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0755); err != nil {
		t.Fatal(err)
	}
	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeRestricted, []string{proj}, globalRoots, true)
	if err != nil {
		t.Fatal(err)
	}

	if err := deleteLauncherRow(db, l.ID); err != nil {
		t.Fatalf("deleteLauncherRow: %v", err)
	}
	if _, err := findLauncherByID(db, l.ID); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("expected launcher gone, got: %v", err)
	}
	var roots, creds int
	if err := db.QueryRow(`SELECT COUNT(*) FROM launcher_allowed_roots WHERE launcher_id=?`, l.ID).Scan(&roots); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE launcher_id=?`, l.ID).Scan(&creds); err != nil {
		t.Fatal(err)
	}
	if roots != 0 || creds != 0 {
		t.Errorf("expected roots/credential cascaded, got roots=%d creds=%d", roots, creds)
	}
}

func TestLauncherDeleteNotFound(t *testing.T) {
	db := openFreshTestDB(t)
	if err := deleteLauncherRow(db, "dhl_missing"); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("expected ErrLauncherNotFound, got: %v", err)
	}
}

func TestLauncherCredentialIssueSingular(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "mia")

	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	cred, token, err := issueLauncherCredential(db, l.ID)
	if err != nil {
		t.Fatalf("issueLauncherCredential: %v", err)
	}
	if !strings.HasPrefix(cred.ID, "dhcr_") {
		t.Errorf("expected dhcr_ credential id, got %q", cred.ID)
	}
	if !strings.HasPrefix(token, credentialTokenPrefix) {
		t.Errorf("expected dhc_ token, got %q", token)
	}

	// Second issue conflicts.
	if _, _, err := issueLauncherCredential(db, l.ID); !errors.Is(err, ErrLauncherCredentialExists) {
		t.Fatalf("expected ErrLauncherCredentialExists, got: %v", err)
	}
}

func TestLauncherCredentialMetadataNoSecret(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "noah")

	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := issueLauncherCredential(db, l.ID); err != nil {
		t.Fatal(err)
	}
	meta, err := findLauncherCredential(db, l.ID)
	if err != nil {
		t.Fatalf("findLauncherCredential: %v", err)
	}
	// Metadata never carries the secret or hash (they are not in the struct).
	if meta.ID == "" || meta.CreatedAt.IsZero() {
		t.Errorf("unexpected metadata: %+v", meta)
	}
}

func TestLauncherCredentialRotate(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "olivia")

	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	cred, oldToken, err := issueLauncherCredential(db, l.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Old token authenticates before rotate.
	if _, err := authenticateCredential(db, oldToken); err != nil {
		t.Fatalf("old token should authenticate before rotate: %v", err)
	}

	newCred, newToken, err := rotateLauncherCredential(db, l.ID)
	if err != nil {
		t.Fatalf("rotateLauncherCredential: %v", err)
	}
	if newCred.ID != cred.ID {
		t.Errorf("credential ID changed on rotate: %s -> %s", cred.ID, newCred.ID)
	}

	// New token authenticates.
	if _, err := authenticateCredential(db, newToken); err != nil {
		t.Fatalf("new token should authenticate after rotate: %v", err)
	}
	// Old token fails after rotate.
	if _, err := authenticateCredential(db, oldToken); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("old token should fail after rotate, got: %v", err)
	}
	// No second credential row.
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE launcher_id=?`, l.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 credential row, got %d", count)
	}
}

func TestLauncherCredentialRotateNotFound(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "peter")

	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rotateLauncherCredential(db, l.ID); !errors.Is(err, ErrLauncherCredentialNotFound) {
		t.Fatalf("expected ErrLauncherCredentialNotFound, got: %v", err)
	}
}

func TestLauncherCredentialDeleteAndReissue(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "quinn")

	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	cred, token, err := issueLauncherCredential(db, l.ID)
	if err != nil {
		t.Fatal(err)
	}

	if err := deleteLauncherCredential(db, l.ID); err != nil {
		t.Fatalf("deleteLauncherCredential: %v", err)
	}
	if _, err := authenticateCredential(db, token); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("old token should be invalid after delete, got: %v", err)
	}
	if _, err := findLauncherCredential(db, l.ID); !errors.Is(err, ErrLauncherCredentialNotFound) {
		t.Fatalf("expected GET to be not found, got: %v", err)
	}

	// Re-issue gets a NEW credential ID.
	newCred, _, err := issueLauncherCredential(db, l.ID)
	if err != nil {
		t.Fatalf("re-issue: %v", err)
	}
	if newCred.ID == cred.ID {
		t.Error("re-issued credential should have a new ID")
	}
}

func TestLauncherCredentialDeleteNotFound(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "rose")

	l, _, _, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := deleteLauncherCredential(db, l.ID); !errors.Is(err, ErrLauncherCredentialNotFound) {
		t.Fatalf("expected ErrLauncherCredentialNotFound, got: %v", err)
	}
}

func TestLauncherCredentialAuth(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "sam")

	l, _, token, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, true)
	if err != nil {
		t.Fatal(err)
	}
	res, err := authenticateCredential(db, token)
	if err != nil {
		t.Fatalf("authenticateCredential: %v", err)
	}
	if res.Principal != nil || res.Launcher == nil {
		t.Fatalf("expected Launcher auth result, got %+v", res)
	}
	if res.Launcher.LauncherID != l.ID || res.Launcher.PrincipalName != "sam" {
		t.Errorf("unexpected launcher auth: %+v", res.Launcher)
	}
}

func TestLauncherCredentialAuthDisabledLauncher(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "tina")

	l, _, token, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, true)
	if err != nil {
		t.Fatal(err)
	}
	falseVal := false
	if _, err := persistLauncherChange(db, l.ID, nil, &falseVal); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticateCredential(db, token); !errors.Is(err, ErrLauncherDisabled) {
		t.Fatalf("expected ErrLauncherDisabled, got: %v", err)
	}
}

func TestLauncherCredentialAuthDisabledPrincipal(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "uma")

	_, _, token, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistPrincipalEnabledChange(db, "uma", false); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticateCredential(db, token); !errors.Is(err, ErrPrincipalDisabled) {
		t.Fatalf("expected ErrPrincipalDisabled, got: %v", err)
	}
}

// TestLauncherCredentialCannotControlSessions proves a valid Launcher
// TestLauncherCredentialControlsOwnSessions verifies the Stage 1.3 selector
// matrix for Session control: a Launcher credential is authorized to create,
// list, and delete Sessions within exactly its own Launcher, while a foreign or
// invalid selector is rejected non-disclosing (never a principal-selector
// leak), and access to a Session outside its scope is a 404.
func TestLauncherCredentialControlsOwnSessions(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	globalRoots := app.Config.AllowedRoots
	home := filepath.Join(globalRoots[0], "home", "victor")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(u string) (string, string, string, error) {
		return "2001", "2001", home, nil
	}
	p, err := createPrincipal(app.DB, "victor", globalRoots)
	if err != nil {
		t.Fatal(err)
	}
	_, _, token, err := createLauncher(app.DB, int64(p.ID), "work", LauncherScopeInherit, nil, globalRoots, true)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	// Create with a selectable invalid selector: a launcher_id other than self
	// is non-disclosing 404, regardless of existence.
	badBody := strings.NewReader(`{"workspace":"/x","launcher_id":"dhl_elsewhere"}`)
	req := httptest.NewRequest(http.MethodPost, "/sessions", badBody)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "launcher_not_found") {
		t.Errorf("launcher credential foreign selector: expected 404 launcher_not_found, got %d %s", w.Code, w.Body.String())
	}

	// A principal selector on a Launcher credential is invalid (not a 401);
	// the credential is authorized but the selector form is rejected.
	selBody := strings.NewReader(`{"workspace":"/x","principal":"victor"}`)
	req = httptest.NewRequest(http.MethodPost, "/sessions", selBody)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_selector") {
		t.Errorf("launcher credential principal selector: expected 400 invalid_selector, got %d %s", w.Code, w.Body.String())
	}

	// Create with a valid workspace (inside the principal's home, which is its
	// effective allowed-root ceiling) succeeds: Launcher credential is
	// authorized within its own scope (not 401).
	workspace := testWorkspaceDir(t, home)
	okBody := strings.NewReader(`{"workspace":"` + workspace + `"}`)
	req = httptest.NewRequest(http.MethodPost, "/sessions", okBody)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("launcher credential session create: expected 201, got %d %s", w.Code, w.Body.String())
	}
	var created createSessionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Session.LauncherID == "" {
		t.Error("created session must carry a launcher_id")
	}

	// List: the Launcher credential sees exactly its own Session (200).
	mux.HandleFunc("GET /sessions", app.handleListSessions)
	lreq := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	lreq.Header.Set("Authorization", "Bearer "+token)
	lw := httptest.NewRecorder()
	mux.ServeHTTP(lw, lreq)
	if lw.Code != http.StatusOK {
		t.Errorf("launcher credential session list: expected 200, got %d", lw.Code)
	} else {
		var listed listSessionsResponse
		if err := json.Unmarshal(lw.Body.Bytes(), &listed); err != nil {
			t.Fatal(err)
		}
		if len(listed.Sessions) != 1 || listed.Sessions[0].ID != created.Session.ID {
			t.Errorf("launcher credential must list only its own session, got %d sessions", len(listed.Sessions))
		}
	}

	// Delete of a Session outside its scope is a non-disclosing 404, and the
	// Launcher credential is not denied with 401.
	mux.HandleFunc("DELETE /sessions/{id}", app.handleDeleteSession)
	dreq := httptest.NewRequest(http.MethodDelete, "/sessions/dhs_foreign", nil)
	dreq.Header.Set("Authorization", "Bearer "+token)
	dw := httptest.NewRecorder()
	mux.ServeHTTP(dw, dreq)
	if dw.Code != http.StatusNotFound || !strings.Contains(dw.Body.String(), "session_not_found") {
		t.Errorf("launcher credential foreign session delete: expected 404 session_not_found, got %d %s", dw.Code, dw.Body.String())
	}
}

// TestLauncherCredentialNotRevocableByPrincipalPath proves revokeCredential is
// Principal-credential-only: passing a Launcher credential ID returns
// ErrCredentialNotFound, leaves revoked_at NULL, and the token still
// authenticates afterward.
func TestLauncherCredentialNotRevocableByPrincipalPath(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "w")

	// Setup a Principal credential to prove the same path still revokes it.
	if _, _, err := createCredential(db, "w", "oc"); err != nil {
		t.Fatal(err)
	}
	// Issue a Launcher credential.
	l, launcherCred, launcherToken, err := createLauncher(db, pid, "work", LauncherScopeInherit, nil, globalRoots, true)
	if err != nil {
		t.Fatal(err)
	}

	// Attempting to revoke the Launcher credential behaves as unknown.
	changed, err := revokeCredential(db, launcherCred.ID)
	if err == nil || !isErrCredentialNotFound(err) {
		t.Fatalf("expected ErrCredentialNotFound for launcher credential revoke, got changed=%v err=%v", changed, err)
	}

	// revoked_at must remain NULL and the token still authenticates.
	var revokedAt sql.NullInt64
	if err := db.QueryRow(`SELECT revoked_at FROM credentials WHERE id=?`, launcherCred.ID).Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if revokedAt.Valid {
		t.Errorf("expected revoked_at NULL for launcher credential, got %d", revokedAt.Int64)
	}
	if res, err := authenticateCredential(db, launcherToken); err != nil || res.Launcher == nil || res.Launcher.LauncherID != l.ID {
		t.Fatalf("launcher credential should still authenticate after refused revoke, err=%v res=%+v", err, res)
	}
}

// TestPrincipalRevokeUnchanged proves the Principal-credential revoke path
// still behaves exactly as before after the ownership predicate was added.
func TestPrincipalRevokeUnchanged(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	home := filepath.Join(globalRoots[0], "home", "x")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	t.Cleanup(func() { OSUserLookup = orig })
	OSUserLookup = func(u string) (string, string, string, error) {
		return "2001", "2001", home, nil
	}
	if _, err := createPrincipal(db, "x", globalRoots); err != nil {
		t.Fatal(err)
	}
	pc, token, err := createCredential(db, "x", "oc")
	if err != nil {
		t.Fatal(err)
	}

	// Token authenticates before revoke.
	if _, err := authenticateCredential(db, token); err != nil {
		t.Fatalf("token should authenticate before revoke: %v", err)
	}

	changed, err := revokeCredential(db, pc.ID)
	if err != nil || !changed {
		t.Fatalf("principal revoke should succeed with changed=true, got changed=%v err=%v", changed, err)
	}
	// Revoked credential no longer authenticates.
	if _, err := authenticateCredential(db, token); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatalf("revoked credential should not authenticate, got err=%v", err)
	}
	// Idempotent second revoke returns changed=false.
	changed2, err := revokeCredential(db, pc.ID)
	if err != nil || changed2 {
		t.Fatalf("second revoke should be idempotent changed=false, got changed=%v err=%v", changed2, err)
	}
}
