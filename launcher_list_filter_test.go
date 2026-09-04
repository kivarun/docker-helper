package main

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func launcherListRows(t *testing.T, wBody []byte) []launcherJSON {
	t.Helper()
	var resp listLaunchersResponse
	if err := json.Unmarshal(wBody, &resp); err != nil {
		t.Fatalf("decode launcher list: %v", err)
	}
	return resp.Launchers
}

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

func TestLauncherListLauncherFilterMatrix(t *testing.T) {
	app, aliceToken, launcherToken := setupScopeListPrincipals(t)
	aliceAgentID := launcherIDByOwnerName(t, app, "alice", "agent")
	bobWorkID := launcherIDByOwnerName(t, app, "bob", "work")

	cases := []struct {
		name       string
		path       string
		bearer     string
		wantStatus int
		wantCode   string
		wantOwner  string
		wantName   string
	}{
		{
			name:       "admin principal plus name",
			path:       "/launchers?principal=alice&launcher=agent",
			bearer:     testAdminToken,
			wantStatus: http.StatusOK,
			wantOwner:  "alice",
			wantName:   "agent",
		},
		{
			name:       "admin principal plus id",
			path:       "/launchers?principal=alice&launcher=" + aliceAgentID,
			bearer:     testAdminToken,
			wantStatus: http.StatusOK,
			wantOwner:  "alice",
			wantName:   "agent",
		},
		{
			name:       "admin global id",
			path:       "/launchers?launcher=" + bobWorkID,
			bearer:     testAdminToken,
			wantStatus: http.StatusOK,
			wantOwner:  "bob",
			wantName:   "work",
		},
		{
			name:       "admin global name rejected",
			path:       "/launchers?launcher=work",
			bearer:     testAdminToken,
			wantStatus: http.StatusBadRequest,
			wantCode:   "launcher_name_requires_principal",
		},
		{
			name:       "principal implicit own scope by name",
			path:       "/launchers?launcher=agent",
			bearer:     aliceToken,
			wantStatus: http.StatusOK,
			wantOwner:  "alice",
			wantName:   "agent",
		},
		{
			name:       "principal foreign principal remains non-disclosing",
			path:       "/launchers?principal=bob&launcher=work",
			bearer:     aliceToken,
			wantStatus: http.StatusNotFound,
			wantCode:   "principal_not_found",
		},
		{
			name:       "principal foreign id remains non-disclosing",
			path:       "/launchers?launcher=" + bobWorkID,
			bearer:     aliceToken,
			wantStatus: http.StatusNotFound,
			wantCode:   "launcher_not_found",
		},
		{
			name:       "launcher credential remains unauthorized",
			path:       "/launchers?launcher=" + aliceAgentID,
			bearer:     launcherToken,
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
				return
			}
			if tc.wantStatus != http.StatusOK {
				return
			}
			rows := launcherListRows(t, w.Body.Bytes())
			if len(rows) != 1 {
				t.Fatalf("rows = %d, want 1: %+v", len(rows), rows)
			}
			if rows[0].Principal != tc.wantOwner || rows[0].Name != tc.wantName {
				t.Fatalf("row = %+v, want %s/%s", rows[0], tc.wantOwner, tc.wantName)
			}
		})
	}
}

func TestLauncherListCommandExposesLauncherFilter(t *testing.T) {
	flags := collectFlagsForCommand(launcherListCommand)
	for _, want := range []string{"--launcher", "--principal", "--json", "--system", "--endpoint", "--token-file"} {
		if !slices.Contains(flags, want) {
			t.Errorf("launcher list flags %v missing %s", flags, want)
		}
	}
	if launcherListCommand.Usage != "docker-helper launcher list [--system] [--endpoint ENDPOINT] [--token-file PATH] [--principal USER] [--launcher LAUNCHER] [--json]" {
		t.Errorf("unexpected launcher list usage: %q", launcherListCommand.Usage)
	}
}
