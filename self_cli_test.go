package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestSelfCLIHumanOutput proves the self command renders the human output for
// each class from the daemon's envelope and never issues any request besides
// the single GET /self: no local classification, no /auth introspection, no
// target resolution.
func TestSelfCLIHumanOutput(t *testing.T) {
	cases := []struct {
		name       string
		resource   any
		wantType   string
		wantStdout []string
	}{
		{
			name:     "principal",
			wantType: "principal",
			resource: principalSelfResource{
				Username: "alice", UID: 1001, GID: 1001, Home: "/home/alice", Enabled: true,
				AllowedRootEntries:          []AllowedRootEntry{{Path: "/home/alice", Access: AllowedRootAccessReadWrite}},
				EffectiveAllowedRootEntries: []AllowedRootEntry{{Path: "/home/alice", Access: AllowedRootAccessReadWrite}},
			},
			wantStdout: []string{
				"TYPE: principal",
				"USERNAME: alice",
				"UID:      1001",
				"ENABLED:  true",
				"ALLOWED ROOTS (STORED)",
				"/home/alice read_write",
				"ALLOWED ROOTS (EFFECTIVE)",
			},
		},
		{
			name:     "launcher",
			wantType: "launcher",
			resource: launcherSelfResource{
				ID: "dhl_abc", Name: "default", Principal: "alice", Enabled: true, Scope: "inherit",
				AllowedRootEntries:          []AllowedRootEntry{},
				EffectiveAllowedRootEntries: []AllowedRootEntry{{Path: "/home/alice", Access: AllowedRootAccessReadWrite}},
			},
			wantStdout: []string{
				"TYPE: launcher",
				"ID:        dhl_abc",
				"NAME:      default",
				"PRINCIPAL: alice",
				"SCOPE:     inherit",
				"ALLOWED ROOTS (STORED)",
				"ALLOWED ROOTS (EFFECTIVE)",
				"/home/alice read_write",
			},
		},
		{
			name:     "session",
			wantType: "session",
			resource: sessionShowJSON{
				sessionJSON: sessionJSON{
					ID: "dhs_1", Workspace: "/home/alice/proj",
					CreatedAt: "2026-01-01T00:00:00Z", ExpiresAt: "2026-01-02T00:00:00Z",
					LauncherID: "dhl_abc",
				},
				FilesystemSnapshot: sessionFilesystemSnapshotJSON{
					Entries: []AllowedRootEntry{{Path: "/home/alice/proj", Access: AllowedRootAccessReadWrite}},
				},
			},
			wantStdout: []string{
				"TYPE: session",
				"ID:        dhs_1",
				"WORKSPACE: /home/alice/proj",
				"FILESYSTEM SNAPSHOT",
				"/home/alice/proj read_write",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/self" && r.Method == http.MethodGet {
					body, err := json.Marshal(selfResponse{OK: true, Type: tc.wantType, Resource: mustJSON(t, tc.resource)})
					if err != nil {
						t.Fatal(err)
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(body)
					return
				}
				http.NotFound(w, r)
			})

			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters([]string{
				"self", "--endpoint", endpoint, "--token-file", tokenPath,
			}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit = %d, stderr: %s", code, stderr.String())
			}
			if len(*requests) != 1 || (*requests)[0].method != http.MethodGet || (*requests)[0].path != "/self" {
				t.Fatalf("requests = %+v, want exactly one GET /self", *requests)
			}
			out := stdout.String()
			for _, want := range tc.wantStdout {
				if !strings.Contains(out, want) {
					t.Errorf("human output missing %q; output:\n%s", want, out)
				}
			}
		})
	}
}

// TestSelfCLIJSONOutput proves --json prints the raw response envelope.
func TestSelfCLIJSONOutput(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/self" && r.Method == http.MethodGet {
			body, err := json.Marshal(selfResponse{
				OK:       true,
				Type:     "principal",
				Resource: mustJSON(t, principalSelfResource{Username: "alice", UID: 1001, GID: 1001, Home: "/home/alice", Enabled: true}),
			})
			if err != nil {
				t.Fatal(err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"self", "--endpoint", endpoint, "--token-file", tokenPath, "--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr: %s", code, stderr.String())
	}
	if len(*requests) != 1 || (*requests)[0].path != "/self" {
		t.Fatalf("requests = %+v, want exactly one GET /self", *requests)
	}
	var envelope map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("json output is not a document: %v (%s)", err, stdout.String())
	}
	if envelope["type"] != "principal" || envelope["ok"] != true {
		t.Errorf("json envelope = %v, want ok/type principal", envelope)
	}
}

// TestSelfCLIAdminAndFailureContract proves the CLI surfaces the daemon's
// contracts verbatim: the admin self_not_available is an error exit without a
// fabricated target, and an unauthorized credential is a runtime error (exit
// 1), never a CLI usage error.
func TestSelfCLIAdminAndFailureContract(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantExit   int
		wantStderr string
	}{
		{
			name:       "admin self_not_available",
			status:     http.StatusNotFound,
			body:       `{"ok":false,"code":"self_not_available","message":"no self resource for this authority"}`,
			wantExit:   1,
			wantStderr: "self_not_available",
		},
		{
			name:       "unauthorized credential",
			status:     http.StatusUnauthorized,
			body:       `{"ok":false,"code":"unauthorized","message":"Authentication required."}`,
			wantExit:   1,
			wantStderr: "unauthorized",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/self" && r.Method == http.MethodGet {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(tc.body))
					return
				}
				http.NotFound(w, r)
			})

			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters([]string{
				"self", "--endpoint", endpoint, "--token-file", tokenPath,
			}, &stdout, &stderr)
			if code != tc.wantExit {
				t.Fatalf("exit = %d, want %d, stderr: %s", code, tc.wantExit, stderr.String())
			}
			if len(*requests) != 1 || (*requests)[0].path != "/self" {
				t.Fatalf("requests = %+v, want exactly one GET /self (no /auth introspection)", *requests)
			}
			if !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Errorf("stderr = %s, want it to carry %q", stderr.String(), tc.wantStderr)
			}
			if strings.Contains(stderr.String(), "dht_") {
				t.Errorf("stderr leaks bearer material: %s", stderr.String())
			}
		})
	}
}

// mustJSON marshals v for the stub server responses, failing the test on an
// encoding error.
func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("cannot marshal stub resource: %v", err)
	}
	return body
}
