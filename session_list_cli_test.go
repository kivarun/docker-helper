package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestSessionListCLISelectorMatrix proves the Session-list CLI sends the
// optional narrowing selectors as one GET /sessions query through the single
// request builder (proper net/url escaping), keeps the no-selector path
// exactly /sessions, performs no client-side filtering, rejects explicit
// empty values locally before any request, and leaves server errors visible.
func TestSessionListCLISelectorMatrix(t *testing.T) {
	launcherID := "dhl_" + strings.Repeat("ab", 16)

	cases := []struct {
		name         string
		args         []string
		listStatus   int
		listBody     string
		wantQuery    string
		wantIDs      []string
		wantErr      string
		wantExit     int
		wantRequests int
		wantSessions int // 0: not asserted
		wantJSON     bool
	}{
		{
			name:         "no selector stays the plain /sessions request",
			wantRequests: 1,
			listStatus:   http.StatusOK,
			listBody:     `{"ok":true,"sessions":[{"id":"dhs_1","workspace":"/w","created_at":"now","expires_at":"later","launcher_id":"` + launcherID + `"}]}`,
			wantQuery:    "",
			wantIDs:      []string{"dhs_1"},
			wantJSON:     true,
		},
		{
			name:         "principal selector is sent as a query parameter",
			args:         []string{"--principal", "alice", "--json"},
			wantRequests: 1,
			listStatus:   http.StatusOK,
			listBody:     `{"ok":true,"sessions":[{"id":"dhs_a1"},{"id":"dhs_a2"}]}`,
			wantQuery:    "principal=alice",
			wantIDs:      []string{"dhs_a1", "dhs_a2"},
		},
		{
			name:         "launcher selector is sent as a query parameter",
			args:         []string{"--launcher", launcherID, "--json"},
			wantRequests: 1,
			listStatus:   http.StatusOK,
			listBody:     `{"ok":true,"sessions":[{"id":"dhs_a1"}]}`,
			wantQuery:    "launcher=" + launcherID,
			wantIDs:      []string{"dhs_a1"},
		},
		{
			name:         "both selectors are sent as query parameters",
			args:         []string{"--principal", "alice", "--launcher", launcherID, "--json"},
			wantRequests: 1,
			listStatus:   http.StatusOK,
			listBody:     `{"ok":true,"sessions":[{"id":"dhs_a1"}]}`,
			wantQuery:    "launcher=" + launcherID + "&principal=alice",
			wantIDs:      []string{"dhs_a1"},
		},
		{
			name:         "selector values are net/url escaped",
			args:         []string{"--principal", "al ice+b", "--json"},
			wantRequests: 1,
			listStatus:   http.StatusOK,
			listBody:     `{"ok":true,"sessions":[]}`,
			wantQuery:    "principal=al+ice%2Bb",
			wantIDs:      []string{},
		},
		{
			name:         "narrowed JSON output is the daemon response, not filtered client-side",
			args:         []string{"--launcher", launcherID, "--json"},
			wantRequests: 1,
			listStatus:   http.StatusOK,
			listBody:     `{"ok":true,"sessions":[{"id":"dhs_a1","launcher_id":"` + launcherID + `","principal":"alice"}]}`,
			wantQuery:    "launcher=" + launcherID,
			wantIDs:      []string{"dhs_a1"},
			wantSessions: 1,
		},
		{
			name:         "launcher_not_found server error remains visible",
			args:         []string{"--launcher", launcherID, "--json"},
			wantRequests: 1,
			listStatus:   http.StatusNotFound,
			listBody:     `{"code":"launcher_not_found","message":"launcher not found"}`,
			wantQuery:    "launcher=" + launcherID,
			wantErr:      "launcher not found",
		},
		{
			name:         "invalid_selector server error remains visible",
			args:         []string{"--principal", "alice", "--json"},
			wantRequests: 1,
			listStatus:   http.StatusBadRequest,
			listBody:     `{"code":"invalid_selector","message":"invalid session selector"}`,
			wantQuery:    "principal=alice",
			wantErr:      "invalid session selector",
		},
		{
			name:         "server failure stays visible as an error",
			args:         []string{"--launcher", launcherID, "--json"},
			wantRequests: 1,
			listStatus:   http.StatusInternalServerError,
			listBody:     `{"code":"internal_error","message":"internal server error"}`,
			wantQuery:    "launcher=" + launcherID,
			wantErr:      "internal server error",
		},
		{
			name:         "empty --principal value is rejected locally",
			args:         []string{"--principal="},
			wantRequests: 0,
			wantErr:      "--principal value must not be empty",
			wantExit:     2,
		},
		{
			name:         "empty --launcher value is rejected locally",
			args:         []string{"--launcher="},
			wantRequests: 0,
			wantErr:      "--launcher value must not be empty",
			wantExit:     2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/sessions" && r.Method == http.MethodGet {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.listStatus)
					_, _ = w.Write([]byte(tc.listBody))
					return
				}
				http.NotFound(w, r)
			})

			args := append([]string{"session", "list", "--endpoint", endpoint, "--token-file", tokenPath}, tc.args...)
			if tc.wantJSON {
				args = append(args, "--json")
			}
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(args, &stdout, &stderr)

			if tc.wantErr != "" {
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
			} else if code != 0 {
				t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
			}

			if len(*requests) != tc.wantRequests {
				t.Fatalf("requests = %+v, want %d", *requests, tc.wantRequests)
			}
			for _, req := range *requests {
				if req.path != "/sessions" {
					t.Errorf("unexpected request path %q", req.path)
				}
				if req.query != tc.wantQuery {
					t.Errorf("query = %q, want %q", req.query, tc.wantQuery)
				}
			}
			if tc.wantIDs != nil {
				var resp listSessionsResponse
				if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
					t.Fatalf("decode stdout JSON: %v (stdout=%s)", err, stdout.String())
				}
				if !resp.OK {
					t.Errorf("stdout JSON ok = false: %s", stdout.String())
				}
				if tc.wantSessions != 0 && len(resp.Sessions) != tc.wantSessions {
					t.Errorf("stdout JSON sessions = %d, want %d", len(resp.Sessions), tc.wantSessions)
				}
				got := map[string]bool{}
				for _, s := range resp.Sessions {
					got[s.ID] = true
				}
				for _, id := range tc.wantIDs {
					if !got[id] {
						t.Errorf("stdout JSON missing session %q: %s", id, stdout.String())
					}
				}
				if len(got) != len(tc.wantIDs) {
					t.Errorf("stdout JSON sessions %v, want exactly %v", got, tc.wantIDs)
				}
			}
		})
	}
}

// TestSessionListHelpShowsNarrowingSelectors protects the escaped completion
// and help defect: `session list` help must surface both narrowing selectors
// with accurate descriptions alongside the operator and JSON flags.
func TestSessionListHelpShowsNarrowingSelectors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "list", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("help exit = %d (stderr=%s)", code, stderr.String())
	}
	for _, want := range []string{
		"[--principal USER]",
		"[--launcher LAUNCHER]",
		"--principal",
		"--launcher",
		"narrowing only",
		"admin without --principal must use an ID",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("session list help missing %q:\n%s", want, stdout.String())
		}
	}
}
