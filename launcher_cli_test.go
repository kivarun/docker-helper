package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// startLauncherCLITestServer starts an HTTP operator endpoint returning the
// given handler responses, and writes an operator token file. It returns the
// http endpoint and the token file path for runCommandWithWriters CLI tests.
func startLauncherCLITestServer(t *testing.T, handler http.HandlerFunc) (endpoint, tokenPath string) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	tokenPath = filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return server.URL, tokenPath
}

// ---- GET /auth endpoint ----

func TestHandleAuthAdmin(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	w := launcherRequest(t, app, "GET", "/auth", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	var resp authResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Authority != "admin" || resp.Principal != "" || resp.LauncherID != "" {
		t.Errorf("auth = %+v, want authority=admin", resp)
	}
}

func TestHandleAuthPrincipal(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	_, token := setupLauncherHandlerPrincipal(t, app, "alice")
	w := launcherRequest(t, app, "GET", "/auth", token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	var resp authResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Authority != "principal" || resp.Principal != "alice" || resp.LauncherID != "" {
		t.Errorf("auth = %+v, want authority=principal principal=alice", resp)
	}
}

func TestHandleAuthLauncher(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupLauncherHandlerPrincipal(t, app, "alice")

	// Create a launcher with a credential via the admin HTTP path, and capture
	// its bearer token (returned exactly once on creation).
	w := launcherRequest(t, app, http.MethodPost, "/principals/alice/launchers", testAdminToken,
		`{"name":"default","scope":"inherit","allowed_roots":[],"issue_credential":true}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d body=%s", w.Code, w.Body.String())
	}
	var created createLauncherResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Credential == nil || created.Token == "" {
		t.Fatalf("expected issued credential + token, got %+v", created)
	}

	w = launcherRequest(t, app, "GET", "/auth", created.Token, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	var resp authResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Authority != "launcher" || resp.LauncherID != created.Launcher.ID || resp.Principal != "alice" {
		t.Errorf("auth = %+v, want authority=launcher launcher_id=%s principal=alice", resp, created.Launcher.ID)
	}
}

func TestHandleAuthInvalidToken(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	w := launcherRequest(t, app, "GET", "/auth", "no-such-token", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "no-such-token") {
		t.Errorf("invalid token leaked in body: %s", w.Body.String())
	}
}

func TestHandleAuthNoBearer(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	w := launcherRequest(t, app, "GET", "/auth", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

// ---- principal inference helper ----

func TestResolveLauncherPrincipalForCLI(t *testing.T) {
	tests := []struct {
		name     string
		explicit string
		rawBody  string
		want     string
		wantErr  string
	}{
		{
			name:     "explicit principal skips introspection",
			explicit: "bob",
			rawBody:  `{"authority":"admin"}`,
			want:     "bob",
		},
		{
			name:    "principal credential inferred",
			rawBody: `{"authority":"principal","principal":"alice"}`,
			want:    "alice",
		},
		{
			name:    "admin credential errors",
			rawBody: `{"authority":"admin"}`,
			wantErr: "--principal is required for admin authentication",
		},
		{
			name:    "launcher credential errors",
			rawBody: `{"authority":"launcher","launcher_id":"dhl_1","principal":"alice"}`,
			wantErr: "Launcher credentials do not manage Launchers",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newStubClient(t, http.StatusOK, tc.rawBody)
			got, err := resolveLauncherPrincipalForCLI(client, tc.explicit)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ---- prompt helper ----

func TestResolveIssueCredential(t *testing.T) {
	t.Run("issue flag", func(t *testing.T) {
		got, err := resolveIssueCredential(true, false, "p", strings.NewReader(""), &bytes.Buffer{}, false)
		if err != nil || !got {
			t.Errorf("got %v, %v; want true, nil", got, err)
		}
	})
	t.Run("no-credential flag", func(t *testing.T) {
		got, err := resolveIssueCredential(false, true, "p", strings.NewReader(""), &bytes.Buffer{}, false)
		if err != nil || got {
			t.Errorf("got %v, %v; want false, nil", got, err)
		}
	})
	t.Run("both flags error", func(t *testing.T) {
		_, err := resolveIssueCredential(true, true, "p", strings.NewReader(""), &bytes.Buffer{}, false)
		if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("err = %v, want mutually exclusive", err)
		}
	})
	t.Run("non-interactive requires flag", func(t *testing.T) {
		_, err := resolveIssueCredential(false, false, "p", strings.NewReader(""), &bytes.Buffer{}, false)
		if err == nil || !strings.Contains(err.Error(), "non-interactive creation requires") {
			t.Fatalf("err = %v, want non-interactive error", err)
		}
	})
	t.Run("interactive yes default", func(t *testing.T) {
		got, err := resolveIssueCredential(false, false, "p", strings.NewReader("\n"), &bytes.Buffer{}, true)
		if err != nil || !got {
			t.Errorf("got %v, %v; want true, nil", got, err)
		}
	})
	t.Run("interactive no", func(t *testing.T) {
		got, err := resolveIssueCredential(false, false, "p", strings.NewReader("n\n"), &bytes.Buffer{}, true)
		if err != nil || got {
			t.Errorf("got %v, %v; want false, nil", got, err)
		}
	})
	t.Run("interactive invalid then valid", func(t *testing.T) {
		var stderr bytes.Buffer
		got, err := resolveIssueCredential(false, false, "p", strings.NewReader("maybe\ny\n"), &stderr, true)
		if err != nil || !got {
			t.Errorf("got %v, %v; want true, nil", got, err)
		}
		if !strings.Contains(stderr.String(), "Please answer yes or no.") {
			t.Errorf("expected reprompt, stderr=%q", stderr.String())
		}
	})
}

// ---- launcher create request mapping ----

func TestLauncherCreateRequestDefaults(t *testing.T) {
	build := func(allowedRoots []string) string {
		req := createLauncherClientRequest{Name: "default", IssueCredential: false}
		if len(allowedRoots) == 0 {
			req.Scope = "inherit"
			req.AllowedRoots = []string{}
		} else {
			req.Scope = "restricted"
			req.AllowedRoots = append([]string{}, allowedRoots...)
		}
		b, _ := json.Marshal(req)
		return string(b)
	}

	if got := build(nil); got != `{"name":"default","scope":"inherit","allowed_roots":[],"issue_credential":false}` {
		t.Errorf("inherit body = %s", got)
	}
	if got := build([]string{"/a"}); got != `{"name":"default","scope":"restricted","allowed_roots":["/a"],"issue_credential":false}` {
		t.Errorf("restricted body = %s", got)
	}
}

// ---- launcher create CLI end-to-end ----

func TestLauncherCreateCLINonInteractive(t *testing.T) {
	endpoint, tokenPath := startLauncherCLITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(authResponse{Authority: "admin"})
			return
		}
		if r.URL.Path == "/principals/alice/launchers" && r.Method == http.MethodPost {
			var req createLauncherClientRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.Name != "default" || req.Scope != "inherit" || req.IssueCredential {
				t.Errorf("request = %+v, want default inherit, no credential", req)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(createLauncherResponse{
				OK:       true,
				Launcher: launcherJSON{ID: "dhl_1", Principal: "alice", Name: "default", Scope: "inherit"},
			})
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath,
		"--no-credential", "--principal", "alice",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
}

func TestLauncherCreateCLIAdminWithoutPrincipalErrors(t *testing.T) {
	endpoint, tokenPath := startLauncherCLITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(authResponse{Authority: "admin"})
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath, "--no-credential",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr=%s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--principal is required for admin authentication") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestLauncherCreateCLILauncherCredentialErrors(t *testing.T) {
	endpoint, tokenPath := startLauncherCLITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(authResponse{Authority: "launcher", LauncherID: "dhl_1", Principal: "alice"})
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath, "--no-credential",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr=%s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Launcher credentials do not manage Launchers") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// ---- scope set / set validation ----

func TestLauncherScopeSetValidation(t *testing.T) {
	endpoint, tokenPath := startLauncherCLITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"inherit valid", []string{"launcher", "scope", "set", "--endpoint", endpoint, "--token-file", tokenPath, "--inherit", "dhl_1"}, ""},
		{"restricted valid", []string{"launcher", "scope", "set", "--endpoint", endpoint, "--token-file", tokenPath, "--allowed-root", "/a", "dhl_1"}, ""},
		{"neither", []string{"launcher", "scope", "set", "--endpoint", endpoint, "--token-file", tokenPath, "dhl_1"}, "requires at least one"},
		{"both exclusive", []string{"launcher", "scope", "set", "--endpoint", endpoint, "--token-file", tokenPath, "--inherit", "--allowed-root", "/a", "dhl_1"}, "mutually exclusive"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(tc.args, &stdout, &stderr)
			if tc.wantErr == "" {
				if code != 1 {
					t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
				}
				return
			}
			if code != 2 {
				t.Fatalf("exit = %d, want 2; stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.wantErr) {
				t.Errorf("stderr = %q, want containing %q", stderr.String(), tc.wantErr)
			}
		})
	}
}

func TestLauncherSetValidation(t *testing.T) {
	endpoint, tokenPath := startLauncherCLITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"launcher", "set", "--endpoint", endpoint, "--token-file", tokenPath, "dhl_1"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr=%s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "at least one of --name or --enabled") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

// ---- principal create credential flag ----

func TestPrincipalCreateCLINonInteractiveFailsWithoutFlag(t *testing.T) {
	endpoint, tokenPath := startLauncherCLITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "create", "--endpoint", endpoint, "--token-file", tokenPath, "bob",
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr=%s)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "non-interactive creation requires") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestPrincipalCreateCLINoCredential(t *testing.T) {
	var capturedBody string
	endpoint, tokenPath := startLauncherCLITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/principals" && r.Method == http.MethodPost {
			buf := new(strings.Builder)
			_, _ = io.Copy(buf, r.Body)
			capturedBody = buf.String()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(principalResponse{Username: "bob"})
			return
		}
		http.NotFound(w, r)
	})
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "create", "--endpoint", endpoint, "--token-file", tokenPath, "--no-credential", "bob",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if capturedBody != `{"username":"bob"}` {
		t.Errorf("body = %q, want issue_credential omitted", capturedBody)
	}
}

// ---- credential secret handling ----

func TestLauncherCredentialSecretPrintedOnce(t *testing.T) {
	endpoint, tokenPath := startLauncherCLITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/launchers/dhl_1/credential" && r.Method == http.MethodPut {
			json.NewEncoder(w).Encode(launcherCredentialResponse{
				OK:         true,
				Credential: &launcherCredentialJSON{ID: "dhc_1"},
				Token:      "secret-issue-abc",
			})
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"launcher", "credential", "issue", "--endpoint", endpoint, "--token-file", tokenPath, "dhl_1"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if got := strings.Count(stdout.String(), "secret-issue-abc"); got != 1 {
		t.Errorf("secret printed %d times, want 1; stdout=%s", got, stdout.String())
	}
}

func TestLauncherCredentialDeletePrintsNoSecret(t *testing.T) {
	endpoint, tokenPath := startLauncherCLITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/launchers/dhl_1/credential" && r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"launcher", "credential", "delete", "--endpoint", endpoint, "--token-file", tokenPath, "dhl_1"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "secret") || strings.Contains(stdout.String(), "dhc_") {
		t.Errorf("delete printed secret-like data: %s", stdout.String())
	}
}
