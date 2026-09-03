package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installOSUserMock installs an OSUserLookup returning the given homes.
func installOSUserMock(t *testing.T, homes map[string]string) {
	t.Helper()
	orig := OSUserLookup
	t.Cleanup(func() { OSUserLookup = orig })
	OSUserLookup = func(username string) (string, string, string, error) {
		h, ok := homes[username]
		if !ok {
			return "", "", "", fmt.Errorf("no such user %q", username)
		}
		return "2001", "2001", h, nil
	}
}

// setupLauncherHandlerPrincipal creates a Principal under the app's allowed
// root with a Principal credential, returning the home and the credential
// bearer token.
func setupLauncherHandlerPrincipal(t *testing.T, app *App, username string) (string, string) {
	t.Helper()
	home := filepath.Join(app.Config.AllowedRoots[0], "home", username)
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{username: home})
	if _, err := createPrincipal(app.DB, username, app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(%s): %v", username, err)
	}
	_, token, err := createCredential(app.DB, username, "oc")
	if err != nil {
		t.Fatalf("createCredential(%s): %v", username, err)
	}
	return home, token
}

// launcherRequest sends an HTTP request through the full route mux with the
// given bearer token and returns the recorder.
func launcherRequest(t *testing.T, app *App, method, path, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	registerRoutes(mux, app)
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func decodeLauncher(t *testing.T, w *httptest.ResponseRecorder) launcherJSON {
	t.Helper()
	var resp launcherJSON
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode launcher: %v (body=%s)", err, w.Body.String())
	}
	return resp
}

func TestLauncherHandlerAdminLifecycle(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupLauncherHandlerPrincipal(t, app, "alice")

	// Create with issue_credential=true.
	w := launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers", testAdminToken,
		`{"name":"default","scope":"inherit","allowed_roots":[],"issue_credential":true}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d body=%s", w.Code, w.Body.String())
	}
	var created createLauncherResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	l := created.Launcher
	if l.Principal != "alice" || l.Name != "default" || l.Scope != "inherit" || !l.Enabled {
		t.Errorf("unexpected launcher JSON: %+v", l)
	}
	if created.Credential == nil || !strings.HasPrefix(created.Token, credentialTokenPrefix) {
		t.Errorf("expected issued credential and token, got %+v", created)
	}

	// List.
	w = launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", w.Code)
	}
	var list listLaunchersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Launchers) != 1 {
		t.Fatalf("expected 1 launcher, got %d", len(list.Launchers))
	}

	// Show.
	w = launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers/"+l.ID, testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("show: expected 200, got %d body=%s", w.Code, w.Body.String())
	}

	// Patch name + enabled.
	w = launcherRequest(t, app, http.MethodPatch, "/principals/alice/launchers/"+l.ID, testAdminToken,
		`{"name":"renamed","enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("patch: expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	updated := decodeLauncher(t, w)
	if updated.Name != "renamed" || updated.Enabled {
		t.Errorf("expected renamed+disabled, got %+v", updated)
	}

	// Scope replace inherit -> restricted.
	home := filepath.Join(app.Config.AllowedRoots[0], "home", "alice")
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0755); err != nil {
		t.Fatal(err)
	}
	w = launcherRequest(t, app, http.MethodPut, "/principals/alice/launchers/"+l.ID+"/allowed-roots", testAdminToken,
		fmt.Sprintf(`{"scope":"restricted","allowed_roots":[%q]}`, proj))
	if w.Code != http.StatusOK {
		t.Fatalf("scope: expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	restricted := decodeLauncher(t, w)
	if restricted.Scope != "restricted" || len(restricted.AllowedRoots) != 1 {
		t.Errorf("expected restricted with one root, got %+v", restricted)
	}

	// Get credential metadata.
	w = launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers/"+l.ID+"/credential", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("get credential: expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "token") {
		t.Errorf("get credential must not expose token, body=%s", w.Body.String())
	}

	// Rotate.
	w = launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers/"+l.ID+"/credential/rotate", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("rotate: expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var rotated launcherCredentialResponse
	if err := json.Unmarshal(w.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Token == "" {
		t.Error("rotate should return a new token")
	}

	// Delete credential.
	w = launcherRequest(t, app, http.MethodDelete, "/principals/alice/launchers/"+l.ID+"/credential", testAdminToken, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete credential: expected 204, got %d", w.Code)
	}
	w = launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers/"+l.ID+"/credential", testAdminToken, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("get credential after delete: expected 404, got %d", w.Code)
	}

	// Delete launcher.
	w = launcherRequest(t, app, http.MethodDelete, "/principals/alice/launchers/"+l.ID, testAdminToken, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d", w.Code)
	}
	w = launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers/"+l.ID, testAdminToken, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("show after delete: expected 404, got %d", w.Code)
	}
}

func TestLauncherHandlerCreateValidation(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	home, _ := setupLauncherHandlerPrincipal(t, app, "alice")

	// inherit with roots -> 400 invalid_allowed_roots
	w := launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers", testAdminToken,
		fmt.Sprintf(`{"scope":"inherit","allowed_roots":[%q]}`, home))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_allowed_roots") {
		t.Fatalf("inherit+roots: expected 400 invalid_allowed_roots, got %d %s", w.Code, w.Body.String())
	}

	// restricted without roots -> 400 invalid_allowed_roots
	w = launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers", testAdminToken,
		`{"scope":"restricted","allowed_roots":[]}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_allowed_roots") {
		t.Fatalf("restricted no roots: expected 400 invalid_allowed_roots, got %d %s", w.Code, w.Body.String())
	}

	// invalid scope -> 400 invalid_scope
	w = launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers", testAdminToken,
		`{"scope":"bogus"}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_scope") {
		t.Fatalf("bogus scope: expected 400 invalid_scope, got %d %s", w.Code, w.Body.String())
	}

	// duplicate name -> 409 launcher_exists
	w = launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers", testAdminToken,
		`{"name":"default","scope":"inherit"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create: expected 201, got %d %s", w.Code, w.Body.String())
	}
	w = launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers", testAdminToken,
		`{"name":"default","scope":"inherit"}`)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "launcher_exists") {
		t.Fatalf("duplicate: expected 409 launcher_exists, got %d %s", w.Code, w.Body.String())
	}
}

// TestLauncherHandlerCreateNamePresence proves the frozen Launcher-create name
// contract: an omitted "name" field selects defaultLauncherName, while an
// explicitly supplied value — the empty string, JSON null, or any
// grammar-invalid value — is validated exactly as supplied and rejected
// instead of being reinterpreted as omission.
func TestLauncherHandlerCreateNamePresence(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	// Each case gets its own principal so successes and rejections are
	// independent (no cross-case launcher_exists interference).
	cases := []struct {
		username string
		body     string
		wantCode int
		wantName string
	}{
		{"presence1", `{"scope":"inherit"}`, http.StatusCreated, "default"},
		{"presence2", `{"name":"default","scope":"inherit"}`, http.StatusCreated, "default"},
		{"presence3", `{"name":"","scope":"inherit"}`, http.StatusBadRequest, ""},
		{"presence4", `{"name":" Foo ","scope":"inherit"}`, http.StatusBadRequest, ""},
		{"presence5", `{"name":null,"scope":"inherit"}`, http.StatusBadRequest, ""},
	}
	for _, tc := range cases {
		t.Run(tc.body, func(t *testing.T) {
			setupLauncherHandlerPrincipal(t, app, tc.username)

			w := launcherRequest(t, app, http.MethodPost,
				"/principals/"+tc.username+"/launchers", testAdminToken, tc.body)
			if w.Code != tc.wantCode {
				t.Fatalf("create %s: expected %d, got %d body=%s", tc.body, tc.wantCode, w.Code, w.Body.String())
			}
			if tc.wantCode == http.StatusCreated {
				var created createLauncherResponse
				if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
					t.Fatal(err)
				}
				if got := created.Launcher.Name; got != tc.wantName {
					t.Fatalf("create %s: expected launcher name %q, got %q", tc.body, tc.wantName, got)
				}
				return
			}
			if !strings.Contains(w.Body.String(), "invalid_launcher_name") {
				t.Fatalf("create %s: expected invalid_launcher_name, got %s", tc.body, w.Body.String())
			}
			// Rejection must not have created anything.
			w = launcherRequest(t, app, http.MethodGet,
				"/principals/"+tc.username+"/launchers", testAdminToken, "")
			if w.Code != http.StatusOK {
				t.Fatalf("list after rejected create: expected 200, got %d", w.Code)
			}
			var list listLaunchersResponse
			if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
				t.Fatal(err)
			}
			if len(list.Launchers) != 0 {
				t.Fatalf("rejected create %s must not create a launcher, got %d", tc.body, len(list.Launchers))
			}
		})
	}
}

func TestLauncherHandlerRestrictedRootOutsidePrincipal(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	_, _ = setupLauncherHandlerPrincipal(t, app, "alice")

	outside := filepath.Join(app.Config.AllowedRoots[0], "outside")
	if err := os.MkdirAll(outside, 0755); err != nil {
		t.Fatal(err)
	}
	w := launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers", testAdminToken,
		fmt.Sprintf(`{"name":"ci","scope":"restricted","allowed_roots":[%q]}`, outside))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "outside_principal_root") {
		t.Fatalf("expected 400 outside_principal_root, got %d %s", w.Code, w.Body.String())
	}
}

func TestLauncherHandlerPrincipalCredentialManagesOwn(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	_, credToken := setupLauncherHandlerPrincipal(t, app, "alice")

	// Create under self.
	w := launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers", credToken,
		`{"name":"default","scope":"inherit","issue_credential":true}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d body=%s", w.Code, w.Body.String())
	}
	var created createLauncherResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	l := created.Launcher

	// List own.
	w = launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers", credToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", w.Code)
	}
	// Show own.
	w = launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers/"+l.ID, credToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("show own: expected 200, got %d", w.Code)
	}
	// Patch own.
	w = launcherRequest(t, app, http.MethodPatch, "/principals/alice/launchers/"+l.ID, credToken, `{"enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("patch own: expected 200, got %d", w.Code)
	}
	// Scope own.
	w = launcherRequest(t, app, http.MethodPut, "/principals/alice/launchers/"+l.ID+"/allowed-roots", credToken, `{"scope":"inherit"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("scope own: expected 200, got %d", w.Code)
	}
	// Rotate own credential.
	w = launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers/"+l.ID+"/credential/rotate", credToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("rotate own credential: expected 200, got %d", w.Code)
	}
	// Delete own credential.
	w = launcherRequest(t, app, http.MethodDelete, "/principals/alice/launchers/"+l.ID+"/credential", credToken, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete own credential: expected 204, got %d", w.Code)
	}
	// Delete own.
	w = launcherRequest(t, app, http.MethodDelete, "/principals/alice/launchers/"+l.ID, credToken, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete own: expected 204, got %d", w.Code)
	}
}

func TestLauncherHandlerPrincipalCredentialForeignPrincipalPath(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	_, credToken := setupLauncherHandlerPrincipal(t, app, "alice")

	// Foreign username (whether or not it exists) is non-disclosing 404.
	w := launcherRequest(t, app, http.MethodPost, "/principals/bob/launchers", credToken,
		`{"name":"default"}`)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "principal_not_found") {
		t.Fatalf("expected 404 principal_not_found, got %d %s", w.Code, w.Body.String())
	}
	w = launcherRequest(t, app, http.MethodGet, "/principals/bob/launchers", credToken, "")
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "principal_not_found") {
		t.Fatalf("list foreign: expected 404 principal_not_found, got %d %s", w.Code, w.Body.String())
	}
}

func TestLauncherHandlerPrincipalCredentialForeignLauncher(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	_, credToken := setupLauncherHandlerPrincipal(t, app, "alice")

	// bob is a real principal with a real launcher.
	homeBob := filepath.Join(app.Config.AllowedRoots[0], "home", "bob")
	if err := os.MkdirAll(homeBob, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"bob": homeBob})
	if _, err := createPrincipal(app.DB, "bob", app.Config.AllowedRoots); err != nil {
		t.Fatal(err)
	}
	pb, err := findPrincipalByUsername(app.DB, "bob")
	if err != nil {
		t.Fatal(err)
	}
	bobsLauncher, _, _, err := createLauncher(app.DB, int64(pb.ID), "default", LauncherScopeInherit, nil, app.Config.AllowedRoots, false)
	if err != nil {
		t.Fatal(err)
	}

	// alice's credential cannot see bob's launcher: non-disclosing 404.
	w := launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers/"+bobsLauncher.ID, credToken, "")
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "launcher_not_found") {
		t.Fatalf("expected 404 launcher_not_found, got %d %s", w.Code, w.Body.String())
	}
}

// TestLauncherHandlerScopedSelectorResolution proves the Principal-scoped
// Launcher selector contract: a name and an ID of the same Launcher resolve to
// the same row, the same name under two Principals resolves independently, a
// foreign same-name Launcher is never found through the wrong Principal, and
// malformed or ID-shaped-missing selectors are the same non-disclosing 404
// with no fallback lookup.
func TestLauncherHandlerScopedSelectorResolution(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	_, _ = setupLauncherHandlerPrincipal(t, app, "alice")

	homeBob := filepath.Join(app.Config.AllowedRoots[0], "home", "bob")
	if err := os.MkdirAll(homeBob, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"bob": homeBob})
	if _, err := createPrincipal(app.DB, "bob", app.Config.AllowedRoots); err != nil {
		t.Fatal(err)
	}
	pa, err := findPrincipalByUsername(app.DB, "alice")
	if err != nil {
		t.Fatal(err)
	}
	pb, err := findPrincipalByUsername(app.DB, "bob")
	if err != nil {
		t.Fatal(err)
	}
	aliceAlpha, _, _, err := createLauncher(app.DB, int64(pa.ID), "alpha", LauncherScopeInherit, nil, app.Config.AllowedRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	aliceDefault, _, _, err := createLauncher(app.DB, int64(pa.ID), "default", LauncherScopeInherit, nil, app.Config.AllowedRoots, false)
	if err != nil {
		t.Fatal(err)
	}
	bobDefault, _, _, err := createLauncher(app.DB, int64(pb.ID), "default", LauncherScopeInherit, nil, app.Config.AllowedRoots, false)
	if err != nil {
		t.Fatal(err)
	}

	// Name and ID resolve the same Launcher.
	byName := launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers/alpha", testAdminToken, "")
	if byName.Code != http.StatusOK {
		t.Fatalf("show by name: expected 200, got %d body=%s", byName.Code, byName.Body.String())
	}
	byID := launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers/"+aliceAlpha.ID, testAdminToken, "")
	if byID.Code != http.StatusOK {
		t.Fatalf("show by ID: expected 200, got %d body=%s", byID.Code, byID.Body.String())
	}
	if got := decodeLauncher(t, byName); got.ID != aliceAlpha.ID {
		t.Errorf("show by name resolved %q, want %q", got.ID, aliceAlpha.ID)
	}
	if got := decodeLauncher(t, byID); got.ID != aliceAlpha.ID {
		t.Errorf("show by ID resolved %q, want %q", got.ID, aliceAlpha.ID)
	}

	// The same name under two Principals resolves independently.
	aliceDef := launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers/default", testAdminToken, "")
	if got := decodeLauncher(t, aliceDef); aliceDef.Code != http.StatusOK || got.ID != aliceDefault.ID {
		t.Errorf("alice/default: expected %q, got %q (http=%d)", aliceDefault.ID, got.ID, aliceDef.Code)
	}
	bobDef := launcherRequest(t, app, http.MethodGet, "/principals/bob/launchers/default", testAdminToken, "")
	if got := decodeLauncher(t, bobDef); bobDef.Code != http.StatusOK || got.ID != bobDefault.ID {
		t.Errorf("bob/default: expected %q, got %q (http=%d)", bobDefault.ID, got.ID, bobDef.Code)
	}

	// A name that exists only under another Principal is not found through the
	// wrong Principal: same non-disclosing 404 as a missing Launcher.
	w := launcherRequest(t, app, http.MethodGet, "/principals/bob/launchers/alpha", testAdminToken, "")
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "launcher_not_found") {
		t.Fatalf("foreign name through wrong principal: expected 404 launcher_not_found, got %d %s", w.Code, w.Body.String())
	}

	// A malformed selector never triggers a global or fallback lookup.
	w = launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers/Foo", testAdminToken, "")
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "launcher_not_found") {
		t.Fatalf("malformed selector: expected 404 launcher_not_found, got %d %s", w.Code, w.Body.String())
	}

	// An ID-shaped selector never falls back to name lookup: a well-formed but
	// nonexistent ID is the same 404.
	w = launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers/dhl_00000000000000000000000000000000", testAdminToken, "")
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "launcher_not_found") {
		t.Fatalf("nonexistent ID selector: expected 404 launcher_not_found, got %d %s", w.Code, w.Body.String())
	}
}

// TestLauncherHandlerScopedNameSelectorEveryRoute proves every individual
// Launcher control-plane route resolves through the canonical Principal-scoped
// resolver using the Launcher NAME (a global ID-only lookup could not resolve
// it): set/patch, scope replacement, credential rotation, and checked delete.
func TestLauncherHandlerScopedNameSelectorEveryRoute(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	_, _ = setupLauncherHandlerPrincipal(t, app, "alice")

	w := launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers", testAdminToken,
		`{"name":"alpha","scope":"inherit","issue_credential":true}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d body=%s", w.Code, w.Body.String())
	}

	w = launcherRequest(t, app, http.MethodPatch, "/principals/alice/launchers/alpha", testAdminToken, `{"enabled":false}`)
	if w.Code != http.StatusOK || decodeLauncher(t, w).Enabled {
		t.Fatalf("patch by name: expected 200 enabled=false, got %d %s", w.Code, w.Body.String())
	}
	w = launcherRequest(t, app, http.MethodPatch, "/principals/alice/launchers/alpha", testAdminToken, `{"enabled":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("re-enable by name: expected 200, got %d %s", w.Code, w.Body.String())
	}

	w = launcherRequest(t, app, http.MethodPut, "/principals/alice/launchers/alpha/allowed-roots", testAdminToken, `{"scope":"inherit"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("scope replace by name: expected 200, got %d %s", w.Code, w.Body.String())
	}

	w = launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers/alpha/credential/rotate", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("credential rotate by name: expected 200, got %d %s", w.Code, w.Body.String())
	}

	w = launcherRequest(t, app, http.MethodDelete, "/principals/alice/launchers/alpha", testAdminToken, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete by name: expected 204, got %d", w.Code)
	}
}

func TestLauncherHandlerLauncherCredentialUnauthorizedControl(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	_, _ = setupLauncherHandlerPrincipal(t, app, "alice")

	// Create a launcher with a credential; grab the launcher bearer.
	var launcherToken string
	{
		mux := http.NewServeMux()
		registerRoutes(mux, app)
		req := httptest.NewRequest(http.MethodPost, "/principals/alice/launchers", strings.NewReader(
			`{"name":"default","scope":"inherit","issue_credential":true}`))
		withAdminToken(req)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		var created createLauncherResponse
		if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
			t.Fatal(err)
		}
		launcherToken = created.Token
		if launcherToken == "" {
			t.Fatal("expected launcher token")
		}
	}

	// The Launcher credential cannot manage the Launcher control plane.
	w := launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers/self", launcherToken, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("launcher credential on control plane: expected 401, got %d", w.Code)
	}
	// Nor can it create a launcher.
	w = launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers", launcherToken,
		`{"name":"x"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("launcher credential create: expected 401, got %d", w.Code)
	}
	// A Launcher credential can create Sessions within its own scope (Stage 1.3
	// selector matrix), so it is NOT denied here with 401; an invalid workspace
	// reaches the workspace-validation path instead of an authorization failure.
	w = launcherRequest(t, app, http.MethodPost, "/sessions", launcherToken, `{"workspace":"/x"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("launcher credential session create: expected 400 invalid_workspace, got %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid_workspace") {
		t.Fatalf("launcher credential session create: expected invalid_workspace code, got %s", w.Body.String())
	}
}

func TestLauncherHandlerUnknownBearerUnauthorized(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	_, _ = setupLauncherHandlerPrincipal(t, app, "alice")

	w := launcherRequest(t, app, http.MethodGet, "/principals/alice/launchers/dhl_missing", "dhc_unknown", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown bearer: expected 401, got %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "dhl_missing") || strings.Contains(w.Body.String(), "not found") {
		t.Errorf("unknown bearer must not disclose object: %s", w.Body.String())
	}
}

func TestLauncherHandlerCredentialRotateNotFound(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	_, _ = setupLauncherHandlerPrincipal(t, app, "alice")

	w := launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers", testAdminToken,
		`{"name":"default","scope":"inherit"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", w.Code)
	}
	var created createLauncherResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	l := created.Launcher

	// No credential issued, so rotate -> 404 launcher_credential_not_found.
	w = launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers/"+l.ID+"/credential/rotate", testAdminToken, "")
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "launcher_credential_not_found") {
		t.Fatalf("expected 404 launcher_credential_not_found, got %d %s", w.Code, w.Body.String())
	}
}

func TestLauncherHandlerCredentialSecondIssueConflict(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	_, _ = setupLauncherHandlerPrincipal(t, app, "alice")

	w := launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers", testAdminToken,
		`{"name":"default","scope":"inherit"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", w.Code)
	}
	var created createLauncherResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	l := created.Launcher

	w = launcherRequest(t, app, http.MethodPut, "/principals/alice/launchers/"+l.ID+"/credential", testAdminToken, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("first issue: expected 201, got %d", w.Code)
	}
	w = launcherRequest(t, app, http.MethodPut, "/principals/alice/launchers/"+l.ID+"/credential", testAdminToken, "")
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "launcher_credential_exists") {
		t.Fatalf("second issue: expected 409 launcher_credential_exists, got %d %s", w.Code, w.Body.String())
	}
}
