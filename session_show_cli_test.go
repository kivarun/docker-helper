package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// TestSessionShowCLIMatrix proves the `session show` CLI contract: the
// Session ID is the primary positional identity, it issues exactly one
// GET /sessions/{id}, renders the compact human block with the explicit
// FILESYSTEM SNAPSHOT PATH/ACCESS table (the access mode is never hidden),
// passes --json through unchanged, rejects a missing ID positional locally,
// and keeps server errors visible.
func TestSessionShowCLIMatrix(t *testing.T) {
	showBody := `{"id":"dhs_show","workspace":"/run/job","created_at":"now","expires_at":"later","launcher_id":"dhl_default","filesystem_snapshot":{"entries":[{"path":"/run/job","access":"read_write"},{"path":"/run/job/pipeline-inputs","access":"read_only"}]}}`

	cases := []struct {
		name       string
		args       []string
		showStatus int
		showBody   string
		wantErr    string
		wantExit   int
		wantPath   string
		human      bool
		noTarget   bool
	}{
		{
			name:       "human output renders the snapshot table",
			showStatus: http.StatusOK,
			showBody:   showBody,
			wantPath:   "/sessions/dhs_show",
			human:      true,
		},
		{
			name:       "json output is the daemon response",
			args:       []string{"--json"},
			showStatus: http.StatusOK,
			showBody:   showBody,
			wantPath:   "/sessions/dhs_show",
		},
		{
			name:       "missing session stays visible as an error",
			showStatus: http.StatusNotFound,
			showBody:   `{"code":"session_not_found","message":"session not found"}`,
			wantErr:    "session not found",
			wantPath:   "/sessions/dhs_show",
		},
		{
			name:     "missing SESSION_ID positional is rejected locally",
			wantErr:  "missing required argument(s)",
			wantExit: 2,
			noTarget: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/sessions/") && r.Method == http.MethodGet {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.showStatus)
					_, _ = w.Write([]byte(tc.showBody))
					return
				}
				http.NotFound(w, r)
			})

			args := []string{"session", "show", "--endpoint", endpoint, "--token-file", tokenPath}
			if !tc.noTarget {
				args = append(args, "dhs_show")
			}
			args = append(args, tc.args...)
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
				return
			} else if code != 0 {
				t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
			}

			if tc.wantExit == 2 {
				return
			}
			if len(*requests) != 1 {
				t.Fatalf("requests = %+v, want 1", *requests)
			}
			if (*requests)[0].path != tc.wantPath {
				t.Errorf("request path = %q, want %q", (*requests)[0].path, tc.wantPath)
			}

			stdoutText := stdout.String()
			if !tc.human {
				if !strings.Contains(stdoutText, `"filesystem_snapshot"`) {
					t.Errorf("json stdout missing filesystem_snapshot: %s", stdoutText)
				}
				return
			}

			// Human output: the compact metadata block and the explicit
			// snapshot table with the access mode never hidden.
			for _, want := range []string{
				"ID:        dhs_show",
				"WORKSPACE: /run/job",
				"FILESYSTEM SNAPSHOT",
				"PATH", "ACCESS",
				"/run/job", "read_write",
				"/run/job/pipeline-inputs", "read_only",
			} {
				if !strings.Contains(stdoutText, want) {
					t.Errorf("human output missing %q:\n%s", want, stdoutText)
				}
			}
		})
	}
}

// TestSessionShowHelpDocumentsPositionalIdentity protects the help
// invariant: the show command help documents the positional SESSION_ID
// identity (the canonical resource-show targeting) and the operator flags,
// and the legacy `session delete --id` grammar stays untouched.
func TestSessionShowHelpDocumentsPositionalIdentity(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"session", "show", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("help exit = %d (stderr=%s)", code, stderr.String())
	}
	help := stdout.String()
	for _, want := range []string{"SESSION_ID", "session show"} {
		if !strings.Contains(help, want) {
			t.Errorf("session show help missing %q:\n%s", want, help)
		}
	}
	if strings.Contains(help, "--id") {
		t.Errorf("session show help must not carry the retired --id selector:\n%s", help)
	}

	// The legacy pre-2.2 delete grammar is compatibility and unchanged.
	var delOut, delErr bytes.Buffer
	delUsage := runCommandWithWriters([]string{"session", "delete", "--help"}, &delOut, &delErr)
	if delUsage != 0 || !strings.Contains(delOut.String(), "--id SESSION_ID") {
		t.Errorf("session delete must keep its legacy --id grammar (exit=%d):\n%s", delUsage, delOut.String())
	}
}
