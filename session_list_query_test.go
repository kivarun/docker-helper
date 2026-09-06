package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// sessionListQueryFixture is the Session-list narrowing fixture: two
// Principals (alice, bob), each with its auto-provisioned 'default' Launcher
// and one additional named Launcher (alpha, beta), and one active Session
// under each of the four Launchers, created through the production
// createSessionAuthorized owner.
type sessionListQueryFixture struct {
	app                *App
	aliceToken         string // alice Principal credential bearer
	alphaLauncherToken string // alice/alpha Launcher credential bearer
	aliceID            int64
	bobID              int64
	alphaID            string
	betaID             string
	sessions           map[string]string // A-default/A-alpha/B-default/B-beta -> Session ID
}

const (
	sessionListADefault = "A-default"
	sessionListAAlpha   = "A-alpha"
	sessionListBDefault = "B-default"
	sessionListBBeta    = "B-beta"
)

// setupSessionListQueryFixture builds the four-Session ownership fixture used
// by both the scope-resolver matrix and the HTTP handler matrix, so every
// selector case selects real ownership rows.
func setupSessionListQueryFixture(t *testing.T) *sessionListQueryFixture {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	homes := map[string]string{}
	for _, u := range []string{"alice", "bob"} {
		homes[u] = filepath.Join(app.Config.AllowedRoots[0], "home", u)
		if err := os.MkdirAll(homes[u], 0o755); err != nil {
			t.Fatal(err)
		}
	}
	installOSUserMock(t, homes)
	for _, u := range []string{"alice", "bob"} {
		if _, err := createPrincipal(app.DB, u, app.Config.AllowedRoots); err != nil {
			t.Fatalf("createPrincipal(%s): %v", u, err)
		}
	}
	_, aliceToken, err := createPrincipalCredential(app.DB, "alice", "caller")
	if err != nil {
		t.Fatalf("createPrincipalCredential(alice): %v", err)
	}

	aliceID := principalIDByName(t, app.DB, "alice")
	bobID := principalIDByName(t, app.DB, "bob")
	defaultAlice := mustAddDefaultLauncher(t, app.DB, aliceID)
	defaultBob := mustAddDefaultLauncher(t, app.DB, bobID)

	alpha, _, alphaLauncherToken, err := createLauncher(app.DB, aliceID, "alpha", LauncherScopeInherit, nil, nil, true)
	if err != nil {
		t.Fatalf("createLauncher(alice/alpha): %v", err)
	}
	beta, _, _, err := createLauncher(app.DB, bobID, "beta", LauncherScopeInherit, nil, nil, false)
	if err != nil {
		t.Fatalf("createLauncher(bob/beta): %v", err)
	}

	// Every Principal's workspace ceiling is its daemon-resolved home under
	// the global allowed root, so Session fixtures live under their owner's
	// home.
	workspaces := map[string]string{}
	for owner, home := range homes {
		for _, sub := range []string{"default", "extra"} {
			ws := filepath.Join(home, sub)
			if err := os.MkdirAll(ws, 0o755); err != nil {
				t.Fatal(err)
			}
			workspaces[owner+sub] = ws
		}
	}

	create := func(sel createSelector, workspace string) string {
		result, err := app.createSessionAuthorized(&operatorAuthority{class: operatorAuthorityAdmin}, sel, workspace)
		if err != nil {
			t.Fatalf("createSessionAuthorized(%+v): %v", sel, err)
		}
		return result.Session.ID
	}

	f := &sessionListQueryFixture{
		app:                app,
		aliceToken:         aliceToken,
		alphaLauncherToken: alphaLauncherToken,
		aliceID:            aliceID,
		bobID:              bobID,
		alphaID:            alpha.ID,
		betaID:             beta.ID,
		sessions: map[string]string{
			sessionListADefault: create(createSelector{launcherID: defaultAlice}, workspaces["alicedefault"]),
			sessionListAAlpha:   create(createSelector{launcherID: alpha.ID}, workspaces["aliceextra"]),
			sessionListBDefault: create(createSelector{launcherID: defaultBob}, workspaces["bobdefault"]),
			sessionListBBeta:    create(createSelector{launcherID: beta.ID}, workspaces["bobextra"]),
		},
	}
	return f
}

// TestSessionListScopeSelectorMatrix proves the scope-first Session-list
// narrowing rule through the real resolver: the authority establishes the
// maximum visibility (resolveSessionControlScope), the optional selectors can
// only narrow it, Launcher names are Principal-scoped and never searched
// globally, foreign/missing targets are the non-disclosing launcher_not_found,
// authority-illegal selectors are the stable invalid_selector, and a Launcher
// credential never gains a narrowing contract.
func TestSessionListScopeSelectorMatrix(t *testing.T) {
	f := setupSessionListQueryFixture(t)
	app := f.app
	unknownID := "dhl_" + strings.Repeat("ef", 16)
	malformedID := "dhl_" + strings.Repeat("zz", 16)
	adminAuth := &operatorAuthority{class: operatorAuthorityAdmin}

	// Credential authorities are resolved through the production token
	// authentication.
	aliceAuth, err := app.authenticateOperatorToken(f.aliceToken)
	if err != nil {
		t.Fatalf("authenticate alice principal credential: %v", err)
	}
	alphaAuth, err := app.authenticateOperatorToken(f.alphaLauncherToken)
	if err != nil {
		t.Fatalf("authenticate alpha launcher credential: %v", err)
	}

	cases := []struct {
		name      string
		auth      *operatorAuthority
		principal string
		launcher  string
		want      sessionControlScope
		wantErr   error
	}{
		// --- Admin authority ---
		{name: "admin no selector keeps full scope", auth: adminAuth, want: sessionControlScope{admin: true}},
		{name: "admin principal selector narrows to that principal", auth: adminAuth, principal: "alice", want: sessionControlScope{principalID: f.aliceID}},
		{name: "admin global launcher id narrows to that launcher", auth: adminAuth, launcher: f.alphaID, want: sessionControlScope{launcherID: f.alphaID}},
		{name: "admin principal plus launcher name narrows to that launcher", auth: adminAuth, principal: "alice", launcher: "alpha", want: sessionControlScope{launcherID: f.alphaID}},
		{name: "admin principal plus launcher id narrows to that launcher", auth: adminAuth, principal: "alice", launcher: f.alphaID, want: sessionControlScope{launcherID: f.alphaID}},
		{name: "admin principal plus foreign launcher id is launcher_not_found", auth: adminAuth, principal: "alice", launcher: f.betaID, wantErr: ErrLauncherNotFound},
		{name: "admin launcher name without principal is rejected, never global", auth: adminAuth, launcher: "alpha", wantErr: ErrLauncherNameRequiresPrincipal},
		{name: "admin unknown launcher id is launcher_not_found", auth: adminAuth, launcher: unknownID, wantErr: ErrLauncherNotFound},
		{name: "admin malformed launcher selector without principal needs principal context", auth: adminAuth, launcher: malformedID, wantErr: ErrLauncherNameRequiresPrincipal},
		{name: "admin unknown principal is principal_not_found", auth: adminAuth, principal: "nosuch", wantErr: ErrPrincipalNotFound},
		{name: "admin unknown principal wins over launcher selector", auth: adminAuth, principal: "nosuch", launcher: "alpha", wantErr: ErrPrincipalNotFound},
		// --- Principal-credential authority (alice) ---
		{name: "principal no selector keeps own scope", auth: aliceAuth, want: sessionControlScope{principalID: f.aliceID}},
		{name: "principal own launcher name narrows inside scope", auth: aliceAuth, launcher: "alpha", want: sessionControlScope{launcherID: f.alphaID}},
		{name: "principal own launcher id narrows inside scope", auth: aliceAuth, launcher: f.alphaID, want: sessionControlScope{launcherID: f.alphaID}},
		{name: "principal foreign launcher name is non-disclosing not-found", auth: aliceAuth, launcher: "beta", wantErr: ErrLauncherNotFound},
		{name: "principal foreign launcher id is non-disclosing not-found", auth: aliceAuth, launcher: f.betaID, wantErr: ErrLauncherNotFound},
		{name: "principal own principal selector is invalid", auth: aliceAuth, principal: "alice", wantErr: ErrInvalidSelector},
		{name: "principal foreign principal selector is invalid", auth: aliceAuth, principal: "bob", wantErr: ErrInvalidSelector},
		// --- Launcher-credential authority (alice/alpha) ---
		{name: "launcher no selector keeps own scope", auth: alphaAuth, want: sessionControlScope{launcherID: f.alphaID}},
		{name: "launcher own id selector is invalid", auth: alphaAuth, launcher: f.alphaID, wantErr: ErrInvalidSelector},
		{name: "launcher principal selector is invalid", auth: alphaAuth, principal: "alice", wantErr: ErrInvalidSelector},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope, err := app.resolveSessionListScope(tc.auth, tc.principal, tc.launcher)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveSessionListScope() error: %v", err)
			}
			if scope != tc.want {
				t.Fatalf("scope = %+v, want %+v", scope, tc.want)
			}
		})
	}
}

// TestSessionListSelectorLookupDBFailureNotNotFound proves a database failure
// while resolving a list selector keeps its own error contract: it surfaces as
// the internal-error contract through the handler and is never collapsed into
// a non-disclosing not-found.
func TestSessionListSelectorLookupDBFailureNotNotFound(t *testing.T) {
	cases := []struct {
		name   string
		broken string
		// query is rendered with the subcase's own launcher ID.
		query func(launcherID string) string
	}{
		{name: "principal selector lookup failure is 500", broken: "principals", query: func(string) string { return "?principal=alice" }},
		{name: "launcher selector lookup failure is 500", broken: "launchers", query: func(launcherID string) string { return "?launcher=" + launcherID }},
		{name: "scoped launcher selector lookup failure is 500", broken: "launchers", query: func(string) string { return "?principal=alice&launcher=alpha" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh fixture per subcase: the dropped table must exist when
			// the subcase breaks it, and a prior drop must not leak.
			f := setupSessionListQueryFixture(t)
			dropTableBreakFK(t, f.app.DB, tc.broken)

			w := launcherRequest(t, f.app, http.MethodGet, "/sessions"+tc.query(f.alphaID), testAdminToken, "")
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
			}
			if !bytes.Contains(w.Body.Bytes(), []byte("internal_error")) {
				t.Errorf("body %q does not contain internal_error", w.Body.String())
			}
			if bytes.Contains(w.Body.Bytes(), []byte("not_found")) {
				t.Errorf("database failure was collapsed into not-found: %s", w.Body.String())
			}
		})
	}
}

// TestSessionListQueryHTTPMatrix drives the real GET /sessions route through
// the production mux and asserts the exact Session IDs each selector returns,
// proving both presence inside the requested narrowing scope and absence of
// everything outside it.
func TestSessionListQueryHTTPMatrix(t *testing.T) {
	f := setupSessionListQueryFixture(t)
	app := f.app
	unknownID := "dhl_" + strings.Repeat("ef", 16)

	cases := []struct {
		name       string
		path       string
		bearer     string
		wantStatus int
		wantCode   string
		wantIDs    []string
	}{
		// --- Admin authority ---
		{
			name:       "admin unfiltered lists all four",
			path:       "/sessions",
			bearer:     testAdminToken,
			wantStatus: http.StatusOK,
			wantIDs:    []string{sessionListADefault, sessionListAAlpha, sessionListBDefault, sessionListBBeta},
		},
		{
			name:       "admin principal=alice lists alice sessions only",
			path:       "/sessions?principal=alice",
			bearer:     testAdminToken,
			wantStatus: http.StatusOK,
			wantIDs:    []string{sessionListADefault, sessionListAAlpha},
		},
		{
			name:       "admin principal=bob lists bob sessions only",
			path:       "/sessions?principal=bob",
			bearer:     testAdminToken,
			wantStatus: http.StatusOK,
			wantIDs:    []string{sessionListBDefault, sessionListBBeta},
		},
		{
			name:       "admin launcher id lists only that launcher",
			path:       "/sessions?launcher=" + f.alphaID,
			bearer:     testAdminToken,
			wantStatus: http.StatusOK,
			wantIDs:    []string{sessionListAAlpha},
		},
		{
			name:       "admin principal plus launcher name lists only that launcher",
			path:       "/sessions?principal=alice&launcher=alpha",
			bearer:     testAdminToken,
			wantStatus: http.StatusOK,
			wantIDs:    []string{sessionListAAlpha},
		},
		{
			name:       "admin principal plus launcher id lists only that launcher",
			path:       "/sessions?principal=alice&launcher=" + f.alphaID,
			bearer:     testAdminToken,
			wantStatus: http.StatusOK,
			wantIDs:    []string{sessionListAAlpha},
		},
		{
			name:       "admin principal plus foreign launcher id is non-disclosing",
			path:       "/sessions?principal=alice&launcher=" + f.betaID,
			bearer:     testAdminToken,
			wantStatus: http.StatusNotFound,
			wantCode:   "launcher_not_found",
		},
		{
			name:       "admin launcher name without principal is rejected",
			path:       "/sessions?launcher=alpha",
			bearer:     testAdminToken,
			wantStatus: http.StatusBadRequest,
			wantCode:   "launcher_name_requires_principal",
		},
		{
			name:       "admin unknown principal is non-disclosing",
			path:       "/sessions?principal=nosuch",
			bearer:     testAdminToken,
			wantStatus: http.StatusNotFound,
			wantCode:   "principal_not_found",
		},
		{
			name:       "admin unknown launcher id is non-disclosing",
			path:       "/sessions?launcher=" + unknownID,
			bearer:     testAdminToken,
			wantStatus: http.StatusNotFound,
			wantCode:   "launcher_not_found",
		},
		// --- Principal-credential authority (alice) ---
		{
			name:       "principal unfiltered lists own sessions only",
			path:       "/sessions",
			bearer:     f.aliceToken,
			wantStatus: http.StatusOK,
			wantIDs:    []string{sessionListADefault, sessionListAAlpha},
		},
		{
			name:       "principal launcher name narrows inside own scope",
			path:       "/sessions?launcher=alpha",
			bearer:     f.aliceToken,
			wantStatus: http.StatusOK,
			wantIDs:    []string{sessionListAAlpha},
		},
		{
			name:       "principal launcher id narrows inside own scope",
			path:       "/sessions?launcher=" + f.alphaID,
			bearer:     f.aliceToken,
			wantStatus: http.StatusOK,
			wantIDs:    []string{sessionListAAlpha},
		},
		{
			name:       "principal foreign launcher is non-disclosing",
			path:       "/sessions?launcher=" + f.betaID,
			bearer:     f.aliceToken,
			wantStatus: http.StatusNotFound,
			wantCode:   "launcher_not_found",
		},
		{
			name:       "principal principal selector is invalid even for self",
			path:       "/sessions?principal=alice",
			bearer:     f.aliceToken,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_selector",
		},
		// --- Launcher-credential authority (alice/alpha) ---
		{
			name:       "launcher credential lists own sessions only",
			path:       "/sessions",
			bearer:     f.alphaLauncherToken,
			wantStatus: http.StatusOK,
			wantIDs:    []string{sessionListAAlpha},
		},
		{
			name:       "launcher credential launcher selector is invalid",
			path:       "/sessions?launcher=" + f.alphaID,
			bearer:     f.alphaLauncherToken,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_selector",
		},
		{
			name:       "launcher credential principal selector is invalid",
			path:       "/sessions?principal=alice",
			bearer:     f.alphaLauncherToken,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_selector",
		},
		// --- Authentication ---
		{
			name:       "no bearer is unauthorized",
			path:       "/sessions",
			bearer:     "",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := launcherRequest(t, app, http.MethodGet, tc.path, tc.bearer, "")
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantCode != "" {
				if !strings.Contains(w.Body.String(), tc.wantCode) {
					t.Fatalf("body %q does not contain %q", w.Body.String(), tc.wantCode)
				}
				// Non-disclosing failures must not name an ownership target.
				if tc.wantCode != "principal_not_found" && bytes.Contains(w.Body.Bytes(), []byte("alice")) {
					t.Errorf("error body discloses a selector target: %s", w.Body.String())
				}
				return
			}
			got := sessionListIDsFromBody(t, w.Body.Bytes())
			if len(got) != len(tc.wantIDs) {
				t.Fatalf("sessions = %v, want exactly %v", got, tc.wantIDs)
			}
			for _, want := range tc.wantIDs {
				if !got[f.sessions[want]] {
					t.Fatalf("sessions %v missing %q (%s)", got, want, f.sessions[want])
				}
			}
			// Absence proof: every fixture Session outside the narrowed set
			// must be missing from the response.
			for label, id := range f.sessions {
				if slices.Contains(tc.wantIDs, label) {
					continue
				}
				if got[id] {
					t.Fatalf("narrowed list leaked %q (%s)", label, id)
				}
			}
		})
	}
}

// sessionListIDsFromBody decodes a session list response body into the set of
// returned Session IDs.
func sessionListIDsFromBody(t *testing.T, body []byte) map[string]bool {
	t.Helper()
	var resp listSessionsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode session list: %v (body=%s)", err, body)
	}
	out := map[string]bool{}
	for _, s := range resp.Sessions {
		out[s.ID] = true
	}
	return out
}
