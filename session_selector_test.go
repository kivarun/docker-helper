package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCreateSessionSelectorMatrix verifies the Session create selector contract:
// true request-field presence distinguishes omitted from explicitly-supplied
// empty, malformed selector values (null / non-string) are rejected as invalid
// selectors (not silently treated as omitted), and structural conflict takes
// precedence over value/lookup validation.
func TestCreateSessionSelectorMatrix(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0])

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(body))
		withAdminToken(req)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	cases := []struct {
		name string
		body string
		want int
		code string
	}{
		{name: "omitted", body: `{"workspace":"` + ws + `"}`, want: http.StatusCreated, code: ""},
		{name: "empty launcher_id", body: `{"workspace":"` + ws + `","launcher_id":""}`, want: http.StatusBadRequest, code: "invalid_selector"},
		{name: "empty principal", body: `{"workspace":"` + ws + `","principal":""}`, want: http.StatusBadRequest, code: "invalid_selector"},
		{name: "null launcher_id", body: `{"workspace":"` + ws + `","launcher_id":null}`, want: http.StatusBadRequest, code: "invalid_selector"},
		{name: "null principal", body: `{"workspace":"` + ws + `","principal":null}`, want: http.StatusBadRequest, code: "invalid_selector"},
		{name: "non-string launcher_id", body: `{"workspace":"` + ws + `","launcher_id":123}`, want: http.StatusBadRequest, code: "invalid_selector"},
		{name: "non-string principal", body: `{"workspace":"` + ws + `","principal":123}`, want: http.StatusBadRequest, code: "invalid_selector"},
		{name: "both supplied valid", body: `{"workspace":"` + ws + `","launcher_id":"l","principal":"p"}`, want: http.StatusBadRequest, code: "conflicting_selectors"},
		{name: "both supplied one empty", body: `{"workspace":"` + ws + `","launcher_id":"l","principal":""}`, want: http.StatusBadRequest, code: "conflicting_selectors"},
		{name: "both supplied both empty", body: `{"workspace":"` + ws + `","launcher_id":"","principal":""}`, want: http.StatusBadRequest, code: "conflicting_selectors"},
		{name: "both supplied one null", body: `{"workspace":"` + ws + `","launcher_id":null,"principal":"p"}`, want: http.StatusBadRequest, code: "conflicting_selectors"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := post(tc.body)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body %s", w.Code, tc.want, w.Body.String())
			}
			if tc.code != "" && !bytes.Contains(w.Body.Bytes(), []byte(tc.code)) {
				t.Fatalf("code %q not in body: %s", tc.code, w.Body.String())
			}
		})
	}
}

// TestSessionCreateCLISelectorMatrix proves the CLI-side selector mapping for
// session create: name-shaped --launcher selectors resolve to the global ID
// through the daemon's scope-first list query (one query; a foreign or missing
// Launcher is the daemon's non-disclosing launcher-not-found and no create is
// issued), admin may target a Principal directly or resolve a Launcher name
// only under an explicitly named Principal, an admin Launcher ID selector is
// forwarded as-is without a list query, --principal is admin-only, explicit
// empty values are rejected locally before any request, and the no-selector
// path is unchanged (no /auth introspection, workspace-only body).
func TestSessionCreateCLISelectorMatrix(t *testing.T) {
	id := "dhl_" + strings.Repeat("ab", 16)
	ws := t.TempDir()

	cases := []struct {
		name          string
		args          []string
		authBody      string
		listStatus    int
		listBody      string
		wantListQuery string
		wantPOST      string
		wantErr       string
		wantExit      int
	}{
		{
			name:          "principal credential resolves own launcher name in scope",
			args:          []string{"--launcher", "agent"},
			authBody:      `{"authority":"principal","principal":"alice"}`,
			listStatus:    http.StatusOK,
			listBody:      `{"ok":true,"launchers":[{"id":"` + id + `","principal":"alice","name":"agent","enabled":true}]}`,
			wantListQuery: "launcher=agent",
			wantPOST:      `{"workspace":"` + ws + `","launcher_id":"` + id + `"}`,
		},
		{
			name:          "principal credential foreign launcher name stays non-disclosing",
			args:          []string{"--launcher", "agent"},
			authBody:      `{"authority":"principal","principal":"alice"}`,
			listStatus:    http.StatusNotFound,
			listBody:      `{"code":"launcher_not_found","message":"launcher not found"}`,
			wantListQuery: "launcher=agent",
			wantErr:       "launcher not found",
		},
		{
			name:          "launcher credential resolves self launcher name",
			args:          []string{"--launcher", "agent"},
			authBody:      `{"authority":"launcher","principal":"alice","launcher_id":"` + id + `"}`,
			listStatus:    http.StatusOK,
			listBody:      `{"ok":true,"launchers":[{"id":"` + id + `","principal":"alice","name":"agent","enabled":true}]}`,
			wantListQuery: "launcher=agent",
			wantPOST:      `{"workspace":"` + ws + `","launcher_id":"` + id + `"}`,
		},
		{
			name:          "launcher credential foreign launcher name stays non-disclosing",
			args:          []string{"--launcher", "foreign"},
			authBody:      `{"authority":"launcher","principal":"alice","launcher_id":"` + id + `"}`,
			listStatus:    http.StatusNotFound,
			listBody:      `{"code":"launcher_not_found","message":"launcher not found"}`,
			wantListQuery: "launcher=foreign",
			wantErr:       "launcher not found",
		},
		{
			name:     "admin principal-only selector maps to principal field",
			args:     []string{"--principal", "bob"},
			authBody: `{"authority":"admin"}`,
			wantPOST: `{"workspace":"` + ws + `","principal":"bob"}`,
		},
		{
			name:          "admin resolves launcher name under named principal",
			args:          []string{"--principal", "bob", "--launcher", "agent"},
			authBody:      `{"authority":"admin"}`,
			listStatus:    http.StatusOK,
			listBody:      `{"ok":true,"launchers":[{"id":"` + id + `","principal":"bob","name":"agent","enabled":true}]}`,
			wantListQuery: "launcher=agent&principal=bob",
			wantPOST:      `{"workspace":"` + ws + `","launcher_id":"` + id + `"}`,
		},
		{
			name:     "admin launcher ID selector is sent as-is without a list query",
			args:     []string{"--launcher", id},
			authBody: `{"authority":"admin"}`,
			wantPOST: `{"workspace":"` + ws + `","launcher_id":"` + id + `"}`,
		},
		{
			name:     "admin launcher name without principal is rejected locally",
			args:     []string{"--launcher", "agent"},
			authBody: `{"authority":"admin"}`,
			wantErr:  "admin authentication requires --principal USER",
		},
		{
			name:     "principal credential rejects --principal selector",
			args:     []string{"--principal", "bob"},
			authBody: `{"authority":"principal","principal":"alice"}`,
			wantErr:  "--principal is only valid with admin authentication",
		},
		{
			name:     "empty --principal value is rejected locally",
			args:     []string{"--principal", ""},
			wantErr:  "--principal value must not be empty",
			wantExit: 2,
		},
		{
			name:     "empty --launcher value is rejected locally",
			args:     []string{"--launcher", ""},
			wantErr:  "--launcher value must not be empty",
			wantExit: 2,
		},
		{
			name:     "no selectors keeps the workspace-only contract",
			authBody: "",
			wantPOST: `{"workspace":"` + ws + `"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/auth" && tc.authBody != "":
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, tc.authBody)
				case r.URL.Path == "/launchers" && tc.listStatus != 0:
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.listStatus)
					_, _ = io.WriteString(w, tc.listBody)
				case r.URL.Path == "/sessions" && r.Method == http.MethodPost:
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
					_, _ = io.WriteString(w, `{"ok":true,"session":{"id":"dhs_1","workspace":"`+ws+`","created_at":"now","expires_at":"later"},"token":"tok"}`)
				default:
					http.NotFound(w, r)
				}
			})

			args := append([]string{"session", "create", "--endpoint", endpoint, "--token-file", tokenPath, "--workspace", ws}, tc.args...)
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(args, &stdout, &stderr)

			if tc.wantErr == "" {
				if code != 0 {
					t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
				}
			} else {
				wantExit := tc.wantExit
				if wantExit == 0 {
					wantExit = 1
				}
				if code != wantExit {
					t.Fatalf("exit = %d, want %d (stderr=%s)", code, wantExit, stderr.String())
				}
				if !strings.Contains(stderr.String(), tc.wantErr) {
					t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.wantErr)
				}
			}

			var wantSeq []string
			if tc.authBody != "" {
				wantSeq = append(wantSeq, "/auth")
			}
			if tc.listStatus != 0 {
				wantSeq = append(wantSeq, "/launchers")
			}
			if tc.wantPOST != "" {
				wantSeq = append(wantSeq, "/sessions")
			}
			if len(*requests) != len(wantSeq) {
				t.Fatalf("requests = %+v, want sequence %v", *requests, wantSeq)
			}
			for i, want := range wantSeq {
				if got := (*requests)[i].path; got != want {
					t.Errorf("request[%d].path = %q, want %q", i, got, want)
				}
			}
			for _, req := range *requests {
				if req.path == "/launchers" && req.query != tc.wantListQuery {
					t.Errorf("list query = %q, want %q", req.query, tc.wantListQuery)
				}
				if req.method == http.MethodPost && req.path == "/sessions" && req.body != tc.wantPOST {
					t.Errorf("create body = %s, want %s", req.body, tc.wantPOST)
				}
				if req.path == "/auth" && tc.authBody == "" {
					t.Errorf("unexpected /auth introspection without selectors")
				}
			}
		})
	}
}
