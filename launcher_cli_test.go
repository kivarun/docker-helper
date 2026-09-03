package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startLauncherCLITestServer starts an HTTP operator endpoint returning the
// given handler responses, and writes an operator token file. It returns the
// http endpoint and the token file path for runCommandWithWriters CLI tests.
func startLauncherCLITestServer(t *testing.T, handler http.HandlerFunc) (endpoint, tokenPath string) {
	t.Helper()
	endpoint, tokenPath, _ = startRecordingLauncherCLIServer(t, handler)
	return endpoint, tokenPath
}

// recordedRequest captures one HTTP request made by the CLI against the stub
// operator endpoint.
type recordedRequest struct {
	method string
	path   string
	body   string
}

// startRecordingLauncherCLIServer is the shared stub operator endpoint: it
// records every request (method, path, body) and answers via the given
// responder, so tests can assert request order and bodies (proof that e.g. no
// extra GET or mutation was issued).
func startRecordingLauncherCLIServer(t *testing.T, respond func(w http.ResponseWriter, r *http.Request)) (endpoint, tokenPath string, requests *[]recordedRequest) {
	t.Helper()
	requests = &[]recordedRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		*requests = append(*requests, recordedRequest{r.Method, r.URL.Path, string(buf)})
		r.Body = io.NopCloser(bytes.NewReader(buf))
		respond(w, r)
	}))
	t.Cleanup(server.Close)
	tokenPath = filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return server.URL, tokenPath, requests
}

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
	for _, answer := range []string{"y", "Y", "yes", "YES"} {
		t.Run("interactive yes form "+answer, func(t *testing.T) {
			got, err := resolveIssueCredential(false, false, "p", strings.NewReader(answer+"\n"), &bytes.Buffer{}, true)
			if err != nil || !got {
				t.Errorf("got %v, %v; want true, nil", got, err)
			}
		})
	}
	for _, answer := range []string{"n", "N", "no", "NO"} {
		t.Run("interactive no form "+answer, func(t *testing.T) {
			got, err := resolveIssueCredential(false, false, "p", strings.NewReader(answer+"\n"), &bytes.Buffer{}, true)
			if err != nil || got {
				t.Errorf("got %v, %v; want false, nil", got, err)
			}
		})
	}
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

// ---- GET /auth rejection matrix ----

// TestHandleAuthSessionTokenRejected proves an active Session bearer token
// (valid on the Session control plane) does not authenticate GET /auth and
// receives no identity information.
func TestHandleAuthSessionTokenRejected(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	token := "dhs_session_bearer_for_auth_test"
	hash := sha256.Sum256([]byte(token))
	_, err := app.DB.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at, launcher_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"dhs_authtest", hex.EncodeToString(hash[:]), app.Config.AllowedRoots[0],
		time.Now().Add(-time.Minute).Unix(), time.Now().Add(time.Hour).Unix(),
		app.userModeDefault.launcherID,
	)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}

	// The setup must yield a token that IS valid on the Session plane.
	if _, err := app.findSessionByToken(token); err != nil {
		t.Fatalf("setup token must authenticate the session plane: %v", err)
	}

	w := launcherRequest(t, app, "GET", "/auth", token, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "dhtestowner") || strings.Contains(body, app.userModeDefault.launcherID) {
		t.Errorf("session token leaked identity information: %s", body)
	}
}

// TestHandleAuthRevokedCredential proves a credential that authenticated
// before revocation stops authenticating and is non-disclosing afterwards.
func TestHandleAuthRevokedCredential(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	home := filepath.Join(app.Config.AllowedRoots[0], "home", "alice")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"alice": home})
	if _, err := createPrincipal(app.DB, "alice", app.Config.AllowedRoots); err != nil {
		t.Fatal(err)
	}
	cred, token, err := createCredential(app.DB, "alice", "oc")
	if err != nil {
		t.Fatal(err)
	}

	if w := launcherRequest(t, app, "GET", "/auth", token, ""); w.Code != http.StatusOK {
		t.Fatalf("pre-revoke status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}

	if _, err := revokeCredential(app.DB, cred.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	w := launcherRequest(t, app, "GET", "/auth", token, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("post-revoke status = %d, want 401 (body=%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "alice") {
		t.Errorf("revoked credential leaked identity: %s", w.Body.String())
	}
}

// TestHandleAuthDisabledPrincipal proves a Principal credential whose owner
// was enabled before disabling stops authenticating.
func TestHandleAuthDisabledPrincipal(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	_, token := setupLauncherHandlerPrincipal(t, app, "alice")

	if w := launcherRequest(t, app, "GET", "/auth", token, ""); w.Code != http.StatusOK {
		t.Fatalf("pre-disable status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}

	if _, err := persistPrincipalEnabledChange(app.DB, "alice", false); err != nil {
		t.Fatalf("disable principal: %v", err)
	}
	w := launcherRequest(t, app, "GET", "/auth", token, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("post-disable status = %d, want 401 (body=%s)", w.Code, w.Body.String())
	}
}

// TestHandleAuthDisabledLauncher proves a Launcher credential whose owning
// Launcher was enabled before disabling stops authenticating.
func TestHandleAuthDisabledLauncher(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	home := filepath.Join(app.Config.AllowedRoots[0], "home", "alice")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	installOSUserMock(t, map[string]string{"alice": home})
	if _, err := createPrincipal(app.DB, "alice", app.Config.AllowedRoots); err != nil {
		t.Fatal(err)
	}
	pid, err := findPrincipalIDByUsername(app.DB, "alice")
	if err != nil {
		t.Fatal(err)
	}
	launcher, _, token, err := createLauncher(app.DB, int64(pid), "default", LauncherScopeInherit, nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}

	if w := launcherRequest(t, app, "GET", "/auth", token, ""); w.Code != http.StatusOK {
		t.Fatalf("pre-disable status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}

	disabled := false
	if _, err := updateLauncher(app.DB, launcher.ID, nil, &disabled); err != nil {
		t.Fatalf("disable launcher: %v", err)
	}
	w := launcherRequest(t, app, "GET", "/auth", token, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("post-disable status = %d, want 401 (body=%s)", w.Code, w.Body.String())
	}
}

// ---- recording stub server for request-order/body assertions ----

func writeJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---- principal inference end-to-end ----

// TestLauncherCreateCLIInfersPrincipalFromCredential proves the full CLI path:
// --principal omitted -> GET /auth (principal authority) -> canonical nested
// POST /principals/{username}/launchers with the returned username and the
// simple-default body.
func TestLauncherCreateCLIInfersPrincipalFromCredential(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
		case r.URL.Path == "/principals/alice/launchers" && r.Method == http.MethodPost:
			writeJSONResponse(w, http.StatusCreated, createLauncherResponse{
				OK:       true,
				Launcher: launcherJSON{ID: "dhl_9", Principal: "alice", Name: "default", Scope: "inherit", Enabled: true},
			})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath, "--no-credential",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}

	if len(*requests) != 2 {
		t.Fatalf("requests = %+v, want exactly /auth then create", *requests)
	}
	if (*requests)[0].path != "/auth" || (*requests)[1].path != "/principals/alice/launchers" {
		t.Fatalf("request order = %s %s, %s %s", (*requests)[0].method, (*requests)[0].path, (*requests)[1].method, (*requests)[1].path)
	}
	var req createLauncherClientRequest
	if err := json.Unmarshal([]byte((*requests)[1].body), &req); err != nil {
		t.Fatalf("decode create body %q: %v", (*requests)[1].body, err)
	}
	if req.Name != "default" || req.Scope != "inherit" || req.IssueCredential || len(req.AllowedRoots) != 0 {
		t.Errorf("create body = %+v, want default/inherit/no-credential", req)
	}
	if !strings.Contains(stdout.String(), "alice") {
		t.Errorf("stdout missing inferred principal: %s", stdout.String())
	}
}

// TestLauncherListCLIInfersPrincipalFromCredential proves list uses the same
// inference: /auth lookup then the canonical nested list endpoint.
func TestLauncherListCLIInfersPrincipalFromCredential(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
		case r.URL.Path == "/principals/alice/launchers" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, listLaunchersResponse{
				OK:        true,
				Launchers: []launcherJSON{{ID: "dhl_9", Principal: "alice", Name: "default", Scope: "inherit", Enabled: true}},
			})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"launcher", "list", "--endpoint", endpoint, "--token-file", tokenPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 2 || (*requests)[0].path != "/auth" || (*requests)[1].path != "/principals/alice/launchers" {
		t.Fatalf("requests = %+v, want /auth then nested list", *requests)
	}
	if !strings.Contains(stdout.String(), "dhl_9") {
		t.Errorf("stdout missing launcher id: %s", stdout.String())
	}
}

// ---- launcher create restricted + credential token exactly once ----

// TestLauncherCreateCLIRestrictedIssuesCredentialTokenOnce proves
// --allowed-root selects restricted scope and that an issued credential's
// bearer secret is printed exactly once.
func TestLauncherCreateCLIRestrictedIssuesCredentialTokenOnce(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth" && r.Method == http.MethodGet:
			writeJSONResponse(w, http.StatusOK, authResponse{Authority: "principal", Principal: "alice"})
		case r.URL.Path == "/principals/alice/launchers" && r.Method == http.MethodPost:
			writeJSONResponse(w, http.StatusCreated, createLauncherResponse{
				OK:         true,
				Launcher:   launcherJSON{ID: "dhl_9", Principal: "alice", Name: "default", Scope: "restricted", AllowedRoots: []string{"/a", "/b"}, Enabled: true},
				Credential: &launcherCredentialJSON{ID: "dhc_9"},
				Token:      "secret-create-once-42",
			})
		default:
			http.NotFound(w, r)
		}
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"launcher", "create", "--endpoint", endpoint, "--token-file", tokenPath,
		"--allowed-root", "/a", "--allowed-root", "/b", "--issue-credential",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}

	var req createLauncherClientRequest
	if err := json.Unmarshal([]byte((*requests)[len(*requests)-1].body), &req); err != nil {
		t.Fatalf("decode create body %q: %v", (*requests)[len(*requests)-1].body, err)
	}
	if req.Scope != "restricted" || len(req.AllowedRoots) != 2 || req.AllowedRoots[0] != "/a" || req.AllowedRoots[1] != "/b" || !req.IssueCredential {
		t.Errorf("create body = %+v, want restricted [/a /b] with credential", req)
	}
	if got := strings.Count(stdout.String(), "secret-create-once-42"); got != 1 {
		t.Errorf("token printed %d times, want exactly once; stdout=%s", got, stdout.String())
	}
}

// ---- scope set: single atomic PUT, no read-modify-write ----

// TestLauncherScopeSetCLIAtomicReplace proves launcher scope set issues exactly
// one PUT /launchers/{id}/allowed-roots with the complete replacement body —
// no GET and no read-modify-write — for both inherit and restricted forms.
func TestLauncherScopeSetCLIAtomicReplace(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantBody string
	}{
		{
			name:     "inherit",
			args:     []string{"--inherit"},
			wantBody: `{"scope":"inherit","allowed_roots":[]}`,
		},
		{
			name:     "restricted single root",
			args:     []string{"--allowed-root", "/a"},
			wantBody: `{"scope":"restricted","allowed_roots":["/a"]}`,
		},
		{
			name:     "restricted multiple roots",
			args:     []string{"--allowed-root", "/a", "--allowed-root", "/b"},
			wantBody: `{"scope":"restricted","allowed_roots":["/a","/b"]}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/launchers/dhl_1/allowed-roots" && r.Method == http.MethodPut {
					writeJSONResponse(w, http.StatusOK, launcherJSON{ID: "dhl_1", Principal: "alice", Name: "default", Scope: "inherit", Enabled: true})
					return
				}
				http.NotFound(w, r)
			})

			args := append([]string{"launcher", "scope", "set", "--endpoint", endpoint, "--token-file", tokenPath}, tc.args...)
			args = append(args, "dhl_1")
			var stdout, stderr bytes.Buffer
			code := runCommandWithWriters(args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
			}
			if len(*requests) != 1 {
				t.Fatalf("requests = %+v, want exactly one PUT (no read-modify-write)", *requests)
			}
			if (*requests)[0].method != http.MethodPut || (*requests)[0].path != "/launchers/dhl_1/allowed-roots" {
				t.Fatalf("request = %s %s, want PUT /launchers/dhl_1/allowed-roots", (*requests)[0].method, (*requests)[0].path)
			}
			if strings.TrimSpace((*requests)[0].body) != tc.wantBody {
				t.Errorf("body = %q, want %q", (*requests)[0].body, tc.wantBody)
			}
		})
	}
}

// ---- set / delete representative success ----

// TestLauncherSetCLIRepresentativeSuccess proves launcher set issues one PATCH
// carrying exactly the requested name/enabled change.
func TestLauncherSetCLIRepresentativeSuccess(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/launchers/dhl_1" && r.Method == http.MethodPatch {
			writeJSONResponse(w, http.StatusOK, launcherJSON{ID: "dhl_1", Principal: "alice", Name: "ops", Enabled: false, Scope: "inherit"})
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"launcher", "set", "--endpoint", endpoint, "--token-file", tokenPath,
		"--name", "ops", "--enabled", "false", "dhl_1",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 1 || (*requests)[0].method != http.MethodPatch {
		t.Fatalf("requests = %+v, want one PATCH", *requests)
	}
	var req patchLauncherRequest
	if err := json.Unmarshal([]byte((*requests)[0].body), &req); err != nil {
		t.Fatalf("decode patch body %q: %v", (*requests)[0].body, err)
	}
	if req.Name == nil || *req.Name != "ops" || req.Enabled == nil || *req.Enabled {
		t.Errorf("patch body = %+v, want name=ops enabled=false", req)
	}
}

// TestLauncherDeleteCLIRepresentativeSuccess proves launcher delete issues one
// DELETE and succeeds on 204 without printing secret-like data.
func TestLauncherDeleteCLIRepresentativeSuccess(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/launchers/dhl_1" && r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"launcher", "delete", "--endpoint", endpoint, "--token-file", tokenPath, "dhl_1",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 1 || (*requests)[0].method != http.MethodDelete || (*requests)[0].path != "/launchers/dhl_1" {
		t.Fatalf("requests = %+v, want one DELETE /launchers/dhl_1", *requests)
	}
}

// ---- structured API error propagation ----

// TestLauncherCLIStructuredErrorPropagation proves daemon error codes are
// propagated through the CLI as-is (no reclassification into new CLI concepts).
func TestLauncherCLIStructuredErrorPropagation(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		status int
		code   string
	}{
		{
			name:   "show launcher_not_found",
			args:   []string{"launcher", "show"},
			status: http.StatusNotFound,
			code:   "launcher_not_found",
		},
		{
			name:   "delete launcher_runtime_active",
			args:   []string{"launcher", "delete"},
			status: http.StatusConflict,
			code:   "launcher_runtime_active",
		},
		{
			name:   "credential issue launcher_credential_exists",
			args:   []string{"launcher", "credential", "issue"},
			status: http.StatusConflict,
			code:   "launcher_credential_exists",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, tokenPath := startLauncherCLITestServer(t, func(w http.ResponseWriter, r *http.Request) {
				writeJSONResponse(w, tc.status, struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}{Code: tc.code, Message: "conflict"})
			})

			id := "dhl_1"
			args := append(append([]string{}, tc.args...), "--endpoint", endpoint, "--token-file", tokenPath, id)
			var stdout, stderr bytes.Buffer
			exit := runCommandWithWriters(args, &stdout, &stderr)
			if exit != 1 {
				t.Fatalf("exit = %d, want 1 (stderr=%s)", exit, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.code) {
				t.Errorf("stderr = %q, want containing %q", stderr.String(), tc.code)
			}
		})
	}
}

// ---- credential rotate ----

// TestLauncherCredentialRotateCLIPreservesIdentity proves rotate returns the
// same logical credential (identity exposed by the API) with the new secret
// printed exactly once.
func TestLauncherCredentialRotateCLIPreservesIdentity(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/launchers/dhl_1/credential/rotate" && r.Method == http.MethodPost {
			writeJSONResponse(w, http.StatusOK, launcherCredentialResponse{
				OK:         true,
				Credential: &launcherCredentialJSON{ID: "dhc_1"},
				Token:      "secret-rotated-77",
			})
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"launcher", "credential", "rotate", "--endpoint", endpoint, "--token-file", tokenPath, "dhl_1",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 1 || (*requests)[0].method != http.MethodPost || (*requests)[0].path != "/launchers/dhl_1/credential/rotate" {
		t.Fatalf("requests = %+v, want one POST rotate", *requests)
	}
	if !strings.Contains(stdout.String(), "dhc_1") {
		t.Errorf("stdout missing preserved credential id: %s", stdout.String())
	}
	if got := strings.Count(stdout.String(), "secret-rotated-77"); got != 1 {
		t.Errorf("token printed %d times, want exactly once; stdout=%s", got, stdout.String())
	}
}

// ---- principal create with issue-credential ----

// TestPrincipalCreateCLIIssueCredentialSendsTrueAndPrintsSecretOnce proves the
// combined POST /principals owner receives issue_credential=true and the
// bearer secret is surfaced exactly once.
func TestPrincipalCreateCLIIssueCredentialSendsTrueAndPrintsSecretOnce(t *testing.T) {
	endpoint, tokenPath, requests := startRecordingLauncherCLIServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/principals" && r.Method == http.MethodPost {
			writeJSONResponse(w, http.StatusCreated, principalResponse{
				OK:         true,
				Username:   "bob",
				Credential: &credentialJSON{ID: "dhcr_1", Principal: "bob", Name: "default"},
				Token:      "secret-principal-77",
			})
			return
		}
		http.NotFound(w, r)
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"principal", "create", "--endpoint", endpoint, "--token-file", tokenPath,
		"--issue-credential", "bob",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if len(*requests) != 1 {
		t.Fatalf("requests = %+v, want exactly one POST /principals", *requests)
	}
	if got := (*requests)[0].body; got != `{"username":"bob","issue_credential":true}` {
		t.Errorf("body = %q, want issue_credential true", got)
	}
	if got := strings.Count(stdout.String(), "secret-principal-77"); got != 1 {
		t.Errorf("token printed %d times, want exactly once; stdout=%s", got, stdout.String())
	}
	if !strings.Contains(stdout.String(), "dhcr_1") {
		t.Errorf("stdout missing credential metadata: %s", stdout.String())
	}
}
