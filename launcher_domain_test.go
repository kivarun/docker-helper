package main

import (
	"database/sql"
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

func TestLauncherCreateInherit(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "alice")

	l, cred, token, err := createLauncher(db, pid, "alice", "default", LauncherScopeInherit, nil, globalRoots, false)
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
	l, _, _, err := createLauncher(db, pid, "bob", "ci", LauncherScopeRestricted, []string{proj}, globalRoots, false)
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
	_, _, _, err := createLauncher(db, pid, "carol", "ci", LauncherScopeRestricted, []string{outside}, globalRoots, false)
	if err == nil || !errors.Is(err, ErrLauncherRootOutsidePrincipal) {
		t.Fatalf("expected ErrLauncherRootOutsidePrincipal, got: %v", err)
	}
	// No launcher row must remain.
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM launchers WHERE principal_id=?`, pid).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0 launchers after rejected creation, got %d", count)
	}
}

func TestLauncherDuplicateNameWithinPrincipal(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "dave")
	pid2, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "erin")

	if _, _, _, err := createLauncher(db, pid, "dave", "default", LauncherScopeInherit, nil, globalRoots, false); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, _, _, err := createLauncher(db, pid, "dave", "default", LauncherScopeInherit, nil, globalRoots, false); !errors.Is(err, ErrLauncherExists) {
		t.Fatalf("expected ErrLauncherExists for duplicate name, got: %v", err)
	}
	if _, _, _, err := createLauncher(db, pid2, "erin", "default", LauncherScopeInherit, nil, globalRoots, false); err != nil {
		t.Fatalf("same name under another principal should be allowed: %v", err)
	}
}

func TestLauncherFindListScoped(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "frank")

	a, _, _, err := createLauncher(db, pid, "frank", "a", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := createLauncher(db, pid, "frank", "b", LauncherScopeInherit, nil, globalRoots, false); err != nil {
		t.Fatal(err)
	}

	got, err := findLauncherByID(db, a.ID)
	if err != nil {
		t.Fatalf("findLauncherByID: %v", err)
	}
	if got.Name != "a" || got.PrincipalName != "frank" {
		t.Errorf("unexpected launcher: %+v", got)
	}

	byName, err := findLauncherByPrincipalAndName(db, pid, "a")
	if err != nil {
		t.Fatalf("findLauncherByPrincipalAndName: %v", err)
	}
	if byName.ID != a.ID {
		t.Errorf("expected launcher %s, got %s", a.ID, byName.ID)
	}

	list, err := listLaunchersForPrincipal(db, pid)
	if err != nil {
		t.Fatalf("listLaunchersForPrincipal: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 launchers, got %d", len(list))
	}

	if _, err := findLauncherByID(db, "dhl_missing"); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("expected ErrLauncherNotFound, got: %v", err)
	}
}

func TestLauncherUpdateName(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "gina")

	l, _, _, err := createLauncher(db, pid, "gina", "default", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	name := "renamed"
	updated, err := updateLauncher(db, l.ID, &name, nil)
	if err != nil {
		t.Fatalf("updateLauncher: %v", err)
	}
	if updated.Name != "renamed" {
		t.Errorf("expected name renamed, got %q", updated.Name)
	}

	// Duplicate name within principal is rejected.
	_, _, _, err = createLauncher(db, pid, "gina", "other", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	dup := "other"
	if _, err := updateLauncher(db, l.ID, &dup, nil); !errors.Is(err, ErrLauncherExists) {
		t.Fatalf("expected ErrLauncherExists, got: %v", err)
	}
}

func TestLauncherUpdateEnabled(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "hank")

	l, _, _, err := createLauncher(db, pid, "hank", "default", LauncherScopeInherit, nil, globalRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	enabled := false
	updated, err := updateLauncher(db, l.ID, nil, &enabled)
	if err != nil {
		t.Fatalf("updateLauncher: %v", err)
	}
	if updated.Enabled {
		t.Error("expected launcher disabled")
	}
}

func TestLauncherScopeReplaceInheritToRestricted(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, home := setupPrincipalForLauncherTest(t, db, globalRoots, "iris")

	l, _, _, err := createLauncher(db, pid, "iris", "default", LauncherScopeInherit, nil, globalRoots, false)
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
	l, _, _, err := createLauncher(db, pid, "judy", "default", LauncherScopeRestricted, []string{proj}, globalRoots, false)
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
	l, _, _, err := createLauncher(db, pid, "kevin", "default", LauncherScopeRestricted, []string{proj}, globalRoots, false)
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
	l, _, _, err := createLauncher(db, pid, "liam", "default", LauncherScopeRestricted, []string{proj}, globalRoots, true)
	if err != nil {
		t.Fatal(err)
	}

	if err := deleteLauncher(db, l.ID); err != nil {
		t.Fatalf("deleteLauncher: %v", err)
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
	if err := deleteLauncher(db, "dhl_missing"); !errors.Is(err, ErrLauncherNotFound) {
		t.Fatalf("expected ErrLauncherNotFound, got: %v", err)
	}
}

func TestLauncherCredentialIssueSingular(t *testing.T) {
	db := openFreshTestDB(t)
	globalRoots := []string{testAllowedRootDir(t)}
	pid, _ := setupPrincipalForLauncherTest(t, db, globalRoots, "mia")

	l, _, _, err := createLauncher(db, pid, "mia", "default", LauncherScopeInherit, nil, globalRoots, false)
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

	l, _, _, err := createLauncher(db, pid, "noah", "default", LauncherScopeInherit, nil, globalRoots, false)
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

	l, _, _, err := createLauncher(db, pid, "olivia", "default", LauncherScopeInherit, nil, globalRoots, false)
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

	l, _, _, err := createLauncher(db, pid, "peter", "default", LauncherScopeInherit, nil, globalRoots, false)
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

	l, _, _, err := createLauncher(db, pid, "quinn", "default", LauncherScopeInherit, nil, globalRoots, false)
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

	l, _, _, err := createLauncher(db, pid, "rose", "default", LauncherScopeInherit, nil, globalRoots, false)
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

	l, _, token, err := createLauncher(db, pid, "sam", "default", LauncherScopeInherit, nil, globalRoots, true)
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

	l, _, token, err := createLauncher(db, pid, "tina", "default", LauncherScopeInherit, nil, globalRoots, true)
	if err != nil {
		t.Fatal(err)
	}
	falseVal := false
	if _, err := updateLauncher(db, l.ID, nil, &falseVal); err != nil {
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

	_, _, token, err := createLauncher(db, pid, "uma", "default", LauncherScopeInherit, nil, globalRoots, true)
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
// credential cannot yet create/list/delete Sessions in Stage 1.2.
func TestLauncherCredentialCannotControlSessions(t *testing.T) {
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
	_, _, token, err := createLauncher(app.DB, int64(p.ID), "victor", "default", LauncherScopeInherit, nil, globalRoots, true)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)
	body := strings.NewReader(`{"workspace":"/nonexistent"}`)
	req := httptest.NewRequest(http.MethodPost, "/sessions", body)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for Launcher credential session create, got %d", w.Code)
	}
}
