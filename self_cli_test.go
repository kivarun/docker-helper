package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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
				AllowedRoots:          []AllowedRootEntry{{Path: "/home/alice", Access: AllowedRootAccessReadWrite}},
				EffectiveAllowedRoots: []AllowedRootEntry{{Path: "/home/alice", Access: AllowedRootAccessReadWrite}},
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
				AllowedRoots:          []AllowedRootEntry{},
				EffectiveAllowedRoots: []AllowedRootEntry{{Path: "/home/alice", Access: AllowedRootAccessReadWrite}},
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

// TestSelfCLIJSONOutput proves --json prints the raw response envelope and
// pins its invariant: the envelope is exactly {ok, type, resource} — the
// discriminated union over Principal / Launcher / Session self resources, so
// the envelope's type selects which resource shape resource carries and the
// union cannot project one fixed bare resource schema.
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
	if len(envelope) != 3 || envelope["type"] != "principal" || envelope["ok"] != true {
		t.Fatalf("json envelope = %v, want exactly {ok, type, resource}", envelope)
	}
	resource, ok := envelope["resource"].(map[string]any)
	if !ok || resource["username"] != "alice" {
		t.Errorf("envelope resource = %v, want the decoded principal self resource", envelope["resource"])
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

// TestSelfCLIEnvSessionBearer proves the agent-context self path: with no
// --token-file, the CLI resolves DOCKER_HELPER_SESSION_TOKEN through the
// agent client owner (exactly one GET /self with that bearer) and renders the
// envelope; an embedded-whitespace env value is refused before any request.
func TestSelfCLIEnvSessionBearer(t *testing.T) {
	envBearer := "dht_env-session-bearer-token"
	var gotBearer atomic.Value
	endpoint, _, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotBearer.Store(r.Header.Get("Authorization"))
		if r.URL.Path == "/self" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(mustJSON(t, selfResponse{
				OK:       true,
				Type:     "session",
				Resource: []byte(`{"id":"dhs_probe","workspace":"/tmp/ws"}`),
			})))
			return
		}
		http.NotFound(w, r)
	})

	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", envBearer)
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"self", "--endpoint", "http://" + strings.TrimPrefix(endpoint, "http://")}, &stdout, &stderr)
	// The explicit endpoint is an http endpoint for agent commands: no token
	// file is required there.
	if code != 0 {
		t.Fatalf("exit = %d, want 0, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "session") || !strings.Contains(stdout.String(), "dhs_probe") {
		t.Errorf("stdout = %s, want the session self resource rendered", stdout.String())
	}
	if len(*requests) != 1 || (*requests)[0].path != "/self" {
		t.Fatalf("requests = %+v, want exactly one GET /self", *requests)
	}
	if bearer, _ := gotBearer.Load().(string); bearer != "Bearer "+envBearer {
		t.Errorf("bearer = %q, want the session env bearer", bearer)
	}

	// Whitespace-bearing env values are refused before any request.
	before := len(*requests)
	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "dht_broken value")
	var stdout2, stderr2 bytes.Buffer
	code2 := runCommandWithWriters([]string{"self", "--endpoint", endpoint}, &stdout2, &stderr2)
	if code2 == 0 {
		t.Fatal("a whitespace-bearing DOCKER_HELPER_SESSION_TOKEN must fail")
	}
	if len(*requests) != before {
		t.Errorf("the refused env value must not issue any request")
	}
}

// requireBearerSource asserts the recorded Authorization header equals
// "Bearer "+want and never echoes bearer material in diagnostics: on a
// mismatch only the bearer's length is reported.
func requireBearerSource(t *testing.T, what, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: unexpected bearer source (got %d-byte bearer, want the %s)", what, len(got), what)
	}
}

// TestSelfCLITokenFileWinsOverSessionEnv proves the first precedence rule of
// the dual-authority self surface: with both the explicit --token-file and a
// DOCKER_HELPER_SESSION_TOKEN present, the explicit token file is the
// selected bearer and the session env value does not reach the daemon.
func TestSelfCLITokenFileWinsOverSessionEnv(t *testing.T) {
	envBearer := "dht_env-fixture-token"
	var gotBearer atomic.Value
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotBearer.Store(r.Header.Get("Authorization"))
		if r.URL.Path == "/self" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(mustJSON(t, selfResponse{
				OK:       true,
				Type:     "session",
				Resource: []byte(`{"id":"dhs_probe","workspace":"/tmp/ws"}`),
			})))
			return
		}
		http.NotFound(w, r)
	})

	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", envBearer)
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"self", "--endpoint", "http://" + strings.TrimPrefix(endpoint, "http://"), "--token-file", tokenPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0, stderr: %s", code, stderr.String())
	}
	if len(*requests) != 1 || (*requests)[0].path != "/self" {
		t.Fatalf("requests = %+v, want exactly one GET /self", *requests)
	}
	requireBearerSource(t, "self with --token-file and session env", gotBearer.Load().(string), "Bearer test-token")
	for _, out := range []string{stdout.String(), stderr.String()} {
		if strings.Contains(out, envBearer) {
			t.Errorf("bearer material leaked into command output")
		}
	}
}

// startSelfUnixStub starts a unix-socket self stub for the operator
// credential-resolution cases: it captures the Authorization bearer and the
// request count and answers GET /self with a session self resource.
func startSelfUnixStub(t *testing.T, socketPath string) (bearer *atomic.Value, requestCount *int) {
	t.Helper()
	bearer = &atomic.Value{}
	counter := 0
	requestCount = &counter
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer.Store(r.Header.Get("Authorization"))
		*requestCount++
		if r.URL.Path == "/self" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(mustJSON(t, selfResponse{
				OK:       true,
				Type:     "session",
				Resource: []byte(`{"id":"dhs_probe","workspace":"/tmp/ws"}`),
			})))
			return
		}
		http.NotFound(w, r)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	waitForDialReady(t, "unix", socketPath)
	return bearer, requestCount
}

// installOperatorCredentialFixture writes the installed operator credential
// the operator credential resolution would find (XDG_CONFIG_HOME) and sets
// the environment for it. The token value is a fabricated test fixture and
// is never printed in diagnostics.
func installOperatorCredentialFixture(t *testing.T) string {
	t.Helper()
	xdgConfigHome := t.TempDir()
	dir := filepath.Join(xdgConfigHome, "docker-helper")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "credential.token"), []byte("dhc_installed-fixture-token"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", xdgConfigHome)
	return "Bearer dhc_installed-fixture-token"
}

// TestSelfCLISessionEnvWinsOverInstalledCredential proves the second
// precedence rule: with a non-empty DOCKER_HELPER_SESSION_TOKEN and an
// installed operator credential present (the operator fallback source), self
// uses the Session env bearer — an installed credential must never silently
// turn the dual-authority introspection into the operator credential path.
func TestSelfCLISessionEnvWinsOverInstalledCredential(t *testing.T) {
	envBearer := "Bearer dht_env-fixture-token"
	installed := installOperatorCredentialFixture(t)

	dir := t.TempDir()
	bearer, requestCount := startSelfUnixStub(t, filepath.Join(dir, "self.sock"))

	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "dht_env-fixture-token")
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"self", "--endpoint", "unix://" + filepath.Join(dir, "self.sock")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0, stderr: %s", code, stderr.String())
	}
	if *requestCount != 1 {
		t.Fatalf("requests = %d, want exactly one /self request", *requestCount)
	}
	requireBearerSource(t, "self with session env and installed credential", bearer.Load().(string), envBearer)
	// The installed operator credential must not be the selected bearer.
	if got := bearer.Load().(string); got == installed {
		t.Errorf("the installed operator credential was selected instead of the session env bearer")
	}
}

// TestSelfCLINoSessionEnvFallsBackToOperatorCredential proves the third
// precedence rule: with no --token-file and no DOCKER_HELPER_SESSION_TOKEN,
// self falls back to the normal operator credential source (the installed
// credential file resolution).
func TestSelfCLINoSessionEnvFallsBackToOperatorCredential(t *testing.T) {
	installed := installOperatorCredentialFixture(t)

	dir := t.TempDir()
	bearer, requestCount := startSelfUnixStub(t, filepath.Join(dir, "self.sock"))

	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "")
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"self", "--endpoint", "unix://" + filepath.Join(dir, "self.sock")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, want 0, stderr: %s", code, stderr.String())
	}
	if *requestCount != 1 {
		t.Fatalf("requests = %d, want exactly one /self request", *requestCount)
	}
	requireBearerSource(t, "self without session env", bearer.Load().(string), installed)
}
