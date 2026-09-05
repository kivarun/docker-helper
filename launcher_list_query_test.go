package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// launcherListRows decodes a launcher list response body into its rows.
func launcherListRows(t *testing.T, wBody []byte) []launcherJSON {
	t.Helper()
	var resp listLaunchersResponse
	if err := json.Unmarshal(wBody, &resp); err != nil {
		t.Fatalf("decode launcher list: %v", err)
	}
	return resp.Launchers
}

// launcherIDByOwnerName resolves a Launcher's stable ID through the
// persistence helpers, so matrix cases select real targets.
func launcherIDByOwnerName(t *testing.T, app *App, owner, name string) string {
	t.Helper()
	p, err := findPrincipalByUsername(app.DB, owner)
	if err != nil {
		t.Fatalf("find principal %s: %v", owner, err)
	}
	l, err := findLauncherForPrincipal(app.DB, int64(p.ID), name)
	if err != nil {
		t.Fatalf("find launcher %s/%s: %v", owner, name, err)
	}
	return l.ID
}

// TestLauncherListQueryMatrix proves the unified launcher-list Query over its
// two HTTP entry shapes: the authenticated authority establishes maximum
// visibility (resolveListScope resolves it BEFORE the Launcher selector is
// interpreted), the ?principal= filter can only narrow it, and the ?launcher=
// selector narrows the resolved scope server-side — a name is only legal
// under a resolved Principal, a foreign target stays non-disclosing, and a
// Launcher credential is unauthorized on every surface.
func TestLauncherListQueryMatrix(t *testing.T) {
	app, aliceToken, launcherToken := setupScopeListPrincipals(t)
	aliceAgentID := launcherIDByOwnerName(t, app, "alice", "agent")
	bobWorkID := launcherIDByOwnerName(t, app, "bob", "work")
	const unknownID = "dhl_00000000000000000000000000000000"

	cases := []struct {
		name       string
		path       string
		bearer     string
		wantStatus int
		wantCode   string
		// wantOwner/wantName assert the single narrowed row.
		wantOwner string
		wantName  string
		// wantOwnerRows counts rows for one owner (multi-row scopes).
		wantOwnerRows map[string]int
	}{
		// --- Admin authority ---
		{
			name:          "admin no filters",
			path:          "/launchers",
			bearer:        testAdminToken,
			wantStatus:    http.StatusOK,
			wantOwnerRows: map[string]int{"alice": 3, "bob": 2, "dhtestowner": 1},
		},
		{
			name:          "admin principal only",
			path:          "/launchers?principal=alice",
			bearer:        testAdminToken,
			wantStatus:    http.StatusOK,
			wantOwnerRows: map[string]int{"alice": 3},
		},
		{
			name:       "admin global launcher id only",
			path:       "/launchers?launcher=" + bobWorkID,
			bearer:     testAdminToken,
			wantStatus: http.StatusOK,
			wantOwner:  "bob",
			wantName:   "work",
		},
		{
			name:       "admin principal plus launcher name",
			path:       "/launchers?principal=alice&launcher=agent",
			bearer:     testAdminToken,
			wantStatus: http.StatusOK,
			wantOwner:  "alice",
			wantName:   "agent",
		},
		{
			name:       "admin principal plus own launcher id",
			path:       "/launchers?principal=alice&launcher=" + aliceAgentID,
			bearer:     testAdminToken,
			wantStatus: http.StatusOK,
			wantOwner:  "alice",
			wantName:   "agent",
		},
		{
			name:       "admin principal plus foreign launcher id",
			path:       "/launchers?principal=alice&launcher=" + bobWorkID,
			bearer:     testAdminToken,
			wantStatus: http.StatusNotFound,
			wantCode:   "launcher_not_found",
		},
		{
			name:       "admin global launcher name without principal",
			path:       "/launchers?launcher=work",
			bearer:     testAdminToken,
			wantStatus: http.StatusBadRequest,
			wantCode:   "launcher_name_requires_principal",
		},
		{
			name:       "admin unknown launcher id",
			path:       "/launchers?launcher=" + unknownID,
			bearer:     testAdminToken,
			wantStatus: http.StatusNotFound,
			wantCode:   "launcher_not_found",
		},
		{
			// The Principal scope resolves before the Launcher selector is
			// interpreted: an unknown Principal is never reclassified by the
			// selector.
			name:       "admin unknown principal with launcher selector",
			path:       "/launchers?principal=nosuch&launcher=agent",
			bearer:     testAdminToken,
			wantStatus: http.StatusNotFound,
			wantCode:   "principal_not_found",
		},
		// --- Principal-credential authority ---
		{
			name:          "principal no filters",
			path:          "/launchers",
			bearer:        aliceToken,
			wantStatus:    http.StatusOK,
			wantOwnerRows: map[string]int{"alice": 3},
		},
		{
			name:          "principal self filter",
			path:          "/launchers?principal=alice",
			bearer:        aliceToken,
			wantStatus:    http.StatusOK,
			wantOwnerRows: map[string]int{"alice": 3},
		},
		{
			name:       "principal foreign filter",
			path:       "/launchers?principal=bob",
			bearer:     aliceToken,
			wantStatus: http.StatusNotFound,
			wantCode:   "principal_not_found",
		},
		{
			name:       "principal own launcher name",
			path:       "/launchers?launcher=agent",
			bearer:     aliceToken,
			wantStatus: http.StatusOK,
			wantOwner:  "alice",
			wantName:   "agent",
		},
		{
			name:       "principal own launcher id",
			path:       "/launchers?launcher=" + aliceAgentID,
			bearer:     aliceToken,
			wantStatus: http.StatusOK,
			wantOwner:  "alice",
			wantName:   "agent",
		},
		{
			// A foreign ID is indistinguishable from a missing one.
			name:       "principal foreign launcher id",
			path:       "/launchers?launcher=" + bobWorkID,
			bearer:     aliceToken,
			wantStatus: http.StatusNotFound,
			wantCode:   "launcher_not_found",
		},
		{
			name:       "principal unknown launcher name",
			path:       "/launchers?launcher=nosuch",
			bearer:     aliceToken,
			wantStatus: http.StatusNotFound,
			wantCode:   "launcher_not_found",
		},
		// --- Authentication ---
		{
			name:       "launcher credential unauthorized",
			path:       "/launchers?launcher=" + aliceAgentID,
			bearer:     launcherToken,
			wantStatus: http.StatusUnauthorized,
		},
		{
			// The nested entry converges onto the same Query owner: the same
			// Principal scope as the explicit ?principal= filter.
			name:          "nested admin entry same owner",
			path:          "/principals/alice/launchers",
			bearer:        testAdminToken,
			wantStatus:    http.StatusOK,
			wantOwnerRows: map[string]int{"alice": 3},
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
				return
			}
			rows := launcherListRows(t, w.Body.Bytes())
			if tc.wantOwner != "" {
				if len(rows) != 1 {
					t.Fatalf("rows = %d, want 1: %+v", len(rows), rows)
				}
				if rows[0].Principal != tc.wantOwner || rows[0].Name != tc.wantName {
					t.Fatalf("row = %+v, want %s/%s", rows[0], tc.wantOwner, tc.wantName)
				}
				return
			}
			counts := map[string]int{}
			for _, r := range rows {
				counts[r.Principal]++
			}
			if len(counts) != len(tc.wantOwnerRows) {
				t.Fatalf("owners %v, want %v", counts, tc.wantOwnerRows)
			}
			for owner, want := range tc.wantOwnerRows {
				if counts[owner] != want {
					t.Fatalf("owner %s rows = %d, want %d (all: %v)", owner, counts[owner], want, counts)
				}
			}
		})
	}
}

// TestLauncherListQuerySharedErrorSeam proves filtered and unfiltered list
// requests converge onto the same domain Query seam: an injected failure of
// the launcher-list database query yields the identical shared outcome — HTTP
// 500 internal_error and exactly one launcher.list audit record with
// result=error — and the failure lands only after the Principal scope has
// been resolved (scope-first: the resolved Principal is still named in the
// audit). The injected error text must not reach the audit stream.
func TestLauncherListQuerySharedErrorSeam(t *testing.T) {
	// Without a Principal filter the launcher-list query is the request's
	// first database query (admin authentication is in-memory), so a fail-all
	// driver hits exactly that seam for the unfiltered and the global-ID
	// request. With a Principal filter the scope resolution runs first (and
	// must succeed); allow=1 lets the narrow Principal identity lookup
	// complete and fails the Launcher lookup.
	cases := []struct {
		name      string
		path      string
		failQuery bool
		allow     int
	}{
		{name: "unfiltered", path: "/launchers", failQuery: true},
		{name: "filtered by launcher id", path: "/launchers?launcher=dhl_00000000000000000000000000000000", failQuery: true},
		{name: "filtered after principal scope resolved", path: "/launchers?principal=alice&launcher=agent", allow: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auditBuf, _ := setupTestLogging(t)
			app, _, _ := setupScopeListPrincipals(t)

			dbPath := app.Config.DatabasePath
			app.DB.Close()
			var failDB *sql.DB
			if tc.failQuery {
				failDB = newFailQueryDB(t, dbPath, errMockQueryFail)
			} else {
				failDB = newFailQueryAfterDB(t, dbPath, tc.allow, errMockQueryFail)
			}
			app.DB = failDB
			defer app.DB.Close()

			w := launcherRequest(t, app, http.MethodGet, tc.path, testAdminToken, "")
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusInternalServerError, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "internal_error") {
				t.Fatalf("body %q does not contain internal_error", w.Body.String())
			}
			lines := findAuditLinesByEvent(auditBuf, "launcher.list")
			if len(lines) != 1 {
				t.Fatalf("expected exactly 1 launcher.list audit line, got %d\n%s", len(lines), auditBuf.String())
			}
			m := parseAuditMap(t, lines[0])
			if m["result"] != "error" {
				t.Errorf("result = %v, want error", m["result"])
			}
			if tc.allow > 0 && m["principal_name"] != "alice" {
				t.Errorf("principal_name = %v, want alice (scope resolved before the failing query)", m["principal_name"])
			}
			assertNoInjectedError(t, lines[0], errMockQueryFail.Error())
			assertNoSecrets(t, lines[0], m, "", testAdminToken)
		})
	}
}
