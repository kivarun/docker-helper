package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupScopeListPrincipals creates two principals (alice, bob), each with one
// additional Launcher and one additional named credential beyond the
// auto-provisioned defaults, and returns the app with alice's principal
// credential bearer and alice's Launcher credential bearer.
func setupScopeListPrincipals(t *testing.T) (*App, string, string) {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	homes := map[string]string{}
	for _, u := range []string{"alice", "bob"} {
		homes[u] = filepath.Join(app.Config.AllowedRoots[0], "home", u)
		if err := os.MkdirAll(homes[u], 0755); err != nil {
			t.Fatal(err)
		}
	}
	installOSUserMock(t, homes)
	for _, u := range []string{"alice", "bob"} {
		if _, err := createPrincipal(app.DB, u, app.Config.AllowedRoots); err != nil {
			t.Fatalf("createPrincipal(%s): %v", u, err)
		}
	}
	_, aliceToken, err := createCredential(app.DB, "alice", "caller")
	if err != nil {
		t.Fatalf("createCredential(alice): %v", err)
	}
	createNamedCredential(t, app, "bob", "bobcred")

	if _, _, _, err := createLauncher(app.DB, principalIDByName(t, app.DB, "alice"), "agent", LauncherScopeInherit, nil, nil, false); err != nil {
		t.Fatalf("createLauncher(alice/agent): %v", err)
	}
	if _, _, _, err := createLauncher(app.DB, principalIDByName(t, app.DB, "bob"), "work", LauncherScopeInherit, nil, nil, false); err != nil {
		t.Fatalf("createLauncher(bob/work): %v", err)
	}

	_, _, launcherToken, err := createLauncher(app.DB, principalIDByName(t, app.DB, "alice"), "bearer", LauncherScopeInherit, nil, nil, true)
	if err != nil {
		t.Fatalf("createLauncher(alice/bearer): %v", err)
	}
	return app, aliceToken, launcherToken
}

// TestLauncherListScopeFirstMatrix proves the scope-first launcher list rule:
// the authority establishes maximum visibility (admin: every Principal; a
// Principal credential: its own), the ?principal= filter can only narrow it,
// a foreign filter stays a non-disclosing 404, and a Launcher credential is
// unauthorized on every list surface.
func TestLauncherListScopeFirstMatrix(t *testing.T) {
	app, aliceToken, launcherToken := setupScopeListPrincipals(t)

	// Admin without filter: every visible Launcher — both principals' rows
	// plus the test app's provisioned daemon-owner Launcher.
	w := launcherRequest(t, app, http.MethodGet, "/launchers", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin unfiltered list: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var all listLaunchersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &all); err != nil {
		t.Fatal(err)
	}
	var aliceRows, bobRows int
	for _, l := range all.Launchers {
		switch l.Principal {
		case "alice":
			aliceRows++
		case "bob":
			bobRows++
		case "dhtestowner":
			// The test app's daemon-owner identity with its 'default' Launcher.
		default:
			t.Errorf("admin list contains unexpected owner %q", l.Principal)
		}
	}
	if aliceRows != 3 { // default + agent + bearer
		t.Errorf("admin unfiltered list has %d alice rows, want 3", aliceRows)
	}
	if bobRows != 2 { // default + work
		t.Errorf("admin unfiltered list has %d bob rows, want 2", bobRows)
	}

	// Admin with explicit Principal filter: only that Principal, narrowed.
	w = launcherRequest(t, app, http.MethodGet, "/launchers?principal=alice", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin filtered list: expected 200, got %d", w.Code)
	}
	var filtered listLaunchersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &filtered); err != nil {
		t.Fatal(err)
	}
	if len(filtered.Launchers) != 3 { // default + agent + bearer
		t.Fatalf("admin filtered list = %d rows, want alice's 3", len(filtered.Launchers))
	}
	for _, l := range filtered.Launchers {
		if l.Principal != "alice" {
			t.Errorf("admin filtered list contains owner %q", l.Principal)
		}
	}

	// Admin with a nonexistent filter: honest principal_not_found.
	w = launcherRequest(t, app, http.MethodGet, "/launchers?principal=nosuch", testAdminToken, "")
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "principal_not_found") {
		t.Errorf("admin nonexistent filter: expected 404 principal_not_found, got %d %s", w.Code, w.Body.String())
	}

	// Principal credential without filter: own Launchers only (no filter can
	// expand this), the same set as its own explicit filter.
	w = launcherRequest(t, app, http.MethodGet, "/launchers", aliceToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("principal unfiltered list: expected 200, got %d", w.Code)
	}
	var own listLaunchersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &own); err != nil {
		t.Fatal(err)
	}
	for _, l := range own.Launchers {
		if l.Principal != "alice" {
			t.Errorf("principal unfiltered list disclosed owner %q", l.Principal)
		}
	}
	w = launcherRequest(t, app, http.MethodGet, "/launchers?principal=alice", aliceToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("principal own-filter list: expected 200, got %d", w.Code)
	}
	var ownFiltered listLaunchersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &ownFiltered); err != nil {
		t.Fatal(err)
	}
	if len(ownFiltered.Launchers) != len(own.Launchers) {
		t.Errorf("own filter changed visibility: %d vs %d rows", len(ownFiltered.Launchers), len(own.Launchers))
	}

	// Principal credential with a foreign filter: non-disclosing 404.
	w = launcherRequest(t, app, http.MethodGet, "/launchers?principal=bob", aliceToken, "")
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "principal_not_found") {
		t.Errorf("principal foreign filter: expected 404 principal_not_found, got %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "bob") {
		t.Errorf("foreign filter body leaks the target: %s", w.Body.String())
	}

	// Launcher credential: unauthorized on the scope-first surface.
	w = launcherRequest(t, app, http.MethodGet, "/launchers", launcherToken, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("launcher authority list: expected 401, got %d", w.Code)
	}

	// Launcher credential: unauthorized on the nested single-principal surface.
	w = launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers", launcherToken, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("launcher authority nested list: expected 401, got %d", w.Code)
	}

	// No bearer: unauthorized.
	w = launcherRequest(t, app, http.MethodGet, "/launchers", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("missing bearer list: expected 401, got %d", w.Code)
	}
}

// TestPrincipalCredentialListScopeFirstMatrix proves the scope-first principal
// credential list rule with the same authority/filter model: admin sees every
// Principal's credentials unfiltered and narrows with the filter, a Principal
// credential sees only its own scope (own filter narrows to the same rows), a
// foreign filter stays non-disclosing, and a Launcher credential is
// unauthorized.
func TestPrincipalCredentialListScopeFirstMatrix(t *testing.T) {
	app, aliceToken, launcherToken := setupScopeListPrincipals(t)

	// Admin without filter: credentials of every Principal.
	w := launcherRequest(t, app, http.MethodGet, "/credentials", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin unfiltered list: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var all listCredentialsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &all); err != nil {
		t.Fatal(err)
	}
	owners := map[string]int{}
	for _, c := range all.Credentials {
		owners[c.Principal]++
	}
	if owners["alice"] == 0 || owners["bob"] == 0 {
		t.Errorf("admin unfiltered list owners = %v, want rows for both principals", owners)
	}

	// Admin with explicit Principal filter: only that Principal's rows.
	w = launcherRequest(t, app, http.MethodGet, "/credentials?principal=bob", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin filtered list: expected 200, got %d", w.Code)
	}
	var bobOnly listCredentialsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &bobOnly); err != nil {
		t.Fatal(err)
	}
	if len(bobOnly.Credentials) != 1 || bobOnly.Credentials[0].Principal != "bob" {
		t.Errorf("admin filtered list = %+v, want only bob's row", bobOnly.Credentials)
	}

	// Admin with a nonexistent filter: honest principal_not_found.
	w = launcherRequest(t, app, http.MethodGet, "/credentials?principal=nosuch", testAdminToken, "")
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "principal_not_found") {
		t.Errorf("admin nonexistent filter: expected 404 principal_not_found, got %d %s", w.Code, w.Body.String())
	}

	// Principal credential without filter: exactly alice's rows.
	w = launcherRequest(t, app, http.MethodGet, "/credentials", aliceToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("principal unfiltered list: expected 200, got %d", w.Code)
	}
	var own listCredentialsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &own); err != nil {
		t.Fatal(err)
	}
	if len(own.Credentials) == 0 {
		t.Fatal("principal unfiltered list unexpectedly empty")
	}
	for _, c := range own.Credentials {
		if c.Principal != "alice" {
			t.Errorf("principal unfiltered list disclosed owner %q", c.Principal)
		}
	}

	// Principal credential with own filter: the same visible scope narrowed
	// to itself — the filter never expands visibility.
	w = launcherRequest(t, app, http.MethodGet, "/credentials?principal=alice", aliceToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("principal own-filter list: expected 200, got %d", w.Code)
	}
	var ownFiltered listCredentialsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &ownFiltered); err != nil {
		t.Fatal(err)
	}
	if len(ownFiltered.Credentials) != len(own.Credentials) {
		t.Errorf("own filter changed visibility: %d vs %d rows", len(ownFiltered.Credentials), len(own.Credentials))
	}

	// Principal credential with a foreign filter: non-disclosing 404 that
	// names no target.
	w = launcherRequest(t, app, http.MethodGet, "/credentials?principal=bob", aliceToken, "")
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "principal_not_found") {
		t.Errorf("principal foreign filter: expected 404 principal_not_found, got %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "bob") {
		t.Errorf("foreign filter body leaks the target: %s", w.Body.String())
	}

	// Launcher credential: unauthorized on the scope-first surface.
	w = launcherRequest(t, app, http.MethodGet, "/credentials", launcherToken, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("launcher authority list: expected 401, got %d", w.Code)
	}

	// No bearer: unauthorized.
	w = launcherRequest(t, app, http.MethodGet, "/credentials", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("missing bearer list: expected 401, got %d", w.Code)
	}
}

// TestLauncherListNestedContractUnchanged proves the nested single-Principal
// launcher list keeps its established contract under the shared scope model:
// admin targets any named principal, a Principal credential cannot target a
// foreign one, and the filtered list matches the principal-scoped list.
func TestLauncherListNestedContractUnchanged(t *testing.T) {
	app, aliceToken, _ := setupScopeListPrincipals(t)

	w := launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("nested admin list: expected 200, got %d", w.Code)
	}
	var nested listLaunchersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &nested); err != nil {
		t.Fatal(err)
	}

	w = launcherRequest(t, app, http.MethodGet, "/launchers?principal=alice", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("filtered scope list: expected 200, got %d", w.Code)
	}
	var filtered listLaunchersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &filtered); err != nil {
		t.Fatal(err)
	}
	if len(nested.Launchers) != len(filtered.Launchers) {
		t.Fatalf("nested and filtered lists differ: %d vs %d rows", len(nested.Launchers), len(filtered.Launchers))
	}

	// Principal credential: nested foreign path stays non-disclosing 404.
	w = launcherRequest(t, app, http.MethodGet, "/principals/bob/launchers", aliceToken, "")
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "principal_not_found") {
		t.Errorf("nested foreign list: expected 404 principal_not_found, got %d %s", w.Code, w.Body.String())
	}
}
