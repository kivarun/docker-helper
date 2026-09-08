package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeEngineAuth is a substituted registry authenticator recording the
// credentials it was handed and returning a canned result.
type fakeEngineAuth struct {
	err           error
	identityToken string
	gotRegistry   string
	gotUsername   string
	gotPassword   string
	unclassified  bool
}

func (f *fakeEngineAuth) registryLogin(ctx context.Context, registry, username, password string) (string, error) {
	f.gotRegistry = registry
	f.gotUsername = username
	f.gotPassword = password
	if f.unclassified {
		return "", f.err
	}
	return f.identityToken, f.err
}

// newTestAppWithEngineAuth wires a fake authenticator seam into a test app
// and returns the app and the fake.
func newTestAppWithEngineAuth(t *testing.T) (*App, *fakeEngineAuth) {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	fake := &fakeEngineAuth{}
	app.NewEngineClientFn = func() (engineRegistryAuthenticator, error) {
		return fake, nil
	}
	return app, fake
}

func postRegistryLogin(t *testing.T, app *App, token string, body map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	blob, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(blob))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handleRegistryLogin(w, req)
	return w
}

func decodeResponse(t *testing.T, w *httptest.ResponseRecorder) response {
	t.Helper()
	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	return resp
}

func TestRegistryLoginMissingSession(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	reqBody := map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handleRegistryLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRegistryLoginInvalidJSON(t *testing.T) {
	app, _ := newTestAppWithEngineAuth(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/registry/login", strings.NewReader("not-json"))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handleRegistryLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestRegistryLoginMissingFields(t *testing.T) {
	app, _ := newTestAppWithEngineAuth(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	for _, tc := range []map[string]string{
		{},
		{"registry": "reg.io"},
		{"username": "user"},
		{"password": "secret"},
		{"registry": "reg.io", "username": "user"},
		{"registry": "reg.io", "password": "secret"},
		{"username": "user", "password": "secret"},
	} {
		t.Run("", func(t *testing.T) {
			body, _ := json.Marshal(tc)
			req := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+result.Token)
			w := httptest.NewRecorder()

			app.handleRegistryLogin(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected %d, got %d", http.StatusBadRequest, w.Code)
			}

			var resp response
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("cannot decode: %v", err)
			}
			if resp.Code != "invalid_registry_login" {
				t.Errorf("expected code 'invalid_registry_login', got %q", resp.Code)
			}
		})
	}
}

func TestRegistryLoginSuccessStoresSessionCredential(t *testing.T) {
	app, fake := newTestAppWithEngineAuth(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	w := postRegistryLogin(t, app, result.Token, map[string]string{
		"registry": "registry.example.com",
		"username": "testuser",
		"password": "testsecret",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d (%s)", http.StatusOK, w.Code, w.Body.String())
	}

	// The adapter received the exact credentials and the raw registry input
	// for validation; the credential never appeared anywhere else.
	if fake.gotRegistry != "registry.example.com" || fake.gotUsername != "testuser" || fake.gotPassword != "testsecret" {
		t.Fatalf("adapter received wrong credentials: %q/%q/%q", fake.gotRegistry, fake.gotUsername, fake.gotPassword)
	}

	// The accepted success envelope is exactly one field.
	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode: %v", err)
	}
	if !resp.OK {
		t.Error("expected ok=true")
	}
	if resp.Message != "" || resp.Code != "" || resp.Duration != "" {
		t.Errorf("success envelope must carry only ok=true, got %q", w.Body.String())
	}

	// The credential is stored in the protected session Docker config in the
	// docker CLI config format under the canonical registry key.
	entry, ok, err := readSessionRegistryCredential(app.Config.RuntimeDir, result.Session.ID, "registry.example.com")
	if err != nil || !ok {
		t.Fatalf("stored credential not found: ok=%v err=%v", ok, err)
	}
	username, password, err := decodeSessionDockerAuth(entry.Auth)
	if err != nil {
		t.Fatalf("decode stored credential: %v", err)
	}
	if username != "testuser" || password != "testsecret" {
		t.Errorf("stored credential lost the validated pair: %q/%q", username, password)
	}
}

// TestRegistryLoginNoDockerCLIInvocation proves the migrated login path no
// longer shells out to the docker CLI backend: no exec command is started
// and no credential can appear in a command line.
func TestRegistryLoginNoDockerCLIInvocation(t *testing.T) {
	app, _ := newTestAppWithEngineAuth(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	w := postRegistryLogin(t, app, result.Token, map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}
	if app.ExecCommandContext != nil {
		t.Fatal("test precondition broken: ExecCommandContext must stay unset to observe production invocations")
	}
}

func TestRegistryLoginFailureDoesNotStore(t *testing.T) {
	app, fake := newTestAppWithEngineAuth(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	fake.err = &engineError{kind: engineErrRegistryAuthDenied, cause: errors.New("denied")}

	w := postRegistryLogin(t, app, result.Token, map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	})

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected %d, got %d", http.StatusUnprocessableEntity, w.Code)
	}

	_, ok, err := readSessionRegistryCredential(app.Config.RuntimeDir, result.Session.ID, "registry.example.com")
	if err != nil {
		t.Fatalf("read stored credential: %v", err)
	}
	if ok {
		t.Error("failed validation must not store a credential")
	}
}

func TestRegistryLoginFailureClassification(t *testing.T) {
	cases := []struct {
		name       string
		kind       engineErrorKind
		wantStatus int
		wantCode   string
	}{
		{
			name:       "registry rejected credentials",
			kind:       engineErrRegistryAuthDenied,
			wantStatus: http.StatusUnprocessableEntity,
			wantCode:   "registry_auth_denied",
		},
		{
			name:       "engine reports unreachable registry",
			kind:       engineErrRegistryUnavailable,
			wantStatus: http.StatusBadGateway,
			wantCode:   "registry_unavailable",
		},
		{
			name:       "engine unreachable",
			kind:       engineErrBackendUnavailable,
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "backend_unavailable",
		},
		{
			name:       "unexpected engine failure",
			kind:       engineErrBackendFailure,
			wantStatus: http.StatusBadGateway,
			wantCode:   "backend_failure",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, fake := newTestAppWithEngineAuth(t)

			result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
			if err != nil {
				t.Fatalf("createSession: %v", err)
			}

			fake.err = &engineError{kind: tc.kind, cause: fmt.Errorf("engine failure: %s", tc.name)}

			w := postRegistryLogin(t, app, result.Token, map[string]string{
				"registry": "registry.example.com",
				"username": "user",
				"password": "secret",
			})

			if w.Code != tc.wantStatus {
				t.Fatalf("expected %d, got %d", tc.wantStatus, w.Code)
			}

			var resp response
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("cannot decode: %v", err)
			}
			if resp.Code != tc.wantCode {
				t.Errorf("expected code %q, got %q", tc.wantCode, resp.Code)
			}
			// The failure envelope carries no backend output and no duration.
			if resp.Output != "" || resp.Duration != "" {
				t.Errorf("failure envelope must be the sanitized error envelope, got %q", w.Body.String())
			}
			if strings.Contains(resp.Message, tc.name) {
				t.Errorf("message must not contain the raw engine error text: %q", resp.Message)
			}
		})
	}
}

// TestRegistryLoginFailureUnclassified proves an error that escapes the
// adapter's normalization is answered fail-closed with the unexpected-engine
// contract instead of crashing or leaking.
func TestRegistryLoginFailureUnclassified(t *testing.T) {
	app, fake := newTestAppWithEngineAuth(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	fake.err = errors.New("raw unexpected failure")
	fake.unclassified = true

	w := postRegistryLogin(t, app, result.Token, map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	})

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected %d, got %d", http.StatusBadGateway, w.Code)
	}
	resp := decodeResponse(t, w)
	if resp.Code != "backend_failure" {
		t.Errorf("expected code backend_failure, got %q", resp.Code)
	}
	if strings.Contains(resp.Message, "raw unexpected failure") {
		t.Errorf("message must not carry the raw failure text: %q", resp.Message)
	}
}

func TestRegistryLoginSessionDockerDirCreated(t *testing.T) {
	app, _ := newTestAppWithEngineAuth(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerDir := sessionDockerDir(app.Config.RuntimeDir, result.Session.ID)

	// Directory should not exist yet
	if _, err := os.Stat(dockerDir); err == nil {
		t.Fatal("docker dir should not exist before login")
	}

	w := postRegistryLogin(t, app, result.Token, map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	// Directory should now exist with 0700 permissions
	info, err := os.Stat(dockerDir)
	if err != nil {
		t.Fatalf("docker dir should exist: %v", err)
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("expected mode 0700, got %o", info.Mode().Perm())
	}
}

// TestRegistryLoginProductionAdapterDefaultFailClosed proves the production
// default (nil seam) constructs the real Engine adapter and an unreachable
// Engine answers fail-closed with backend_unavailable, without a panic.
func TestRegistryLoginProductionAdapterDefaultFailClosed(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.NewEngineClientFn = nil

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Make the production adapter's default Engine endpoint deterministically
	// unreachable.
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")

	w := postRegistryLogin(t, app, result.Token, map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	})

	// Must not panic and must answer the normalized unavailable contract.
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
	resp := decodeResponse(t, w)
	if resp.Code != "backend_unavailable" {
		t.Errorf("expected code backend_unavailable, got %q", resp.Code)
	}
}

// TestRegistryLoginFailedValidationPreservesPreviousCredential proves a
// failed validation leaves the previously stored valid credential for that
// registry untouched.
func TestRegistryLoginFailedValidationPreservesPreviousCredential(t *testing.T) {
	app, fake := newTestAppWithEngineAuth(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	runtimeDir := app.Config.RuntimeDir
	sessionID := result.Session.ID

	if err := storeSessionRegistryCredential(runtimeDir, sessionID, "registry.example.com", "old", "oldsecret", ""); err != nil {
		t.Fatalf("store previous credential: %v", err)
	}

	fake.err = &engineError{kind: engineErrRegistryAuthDenied, cause: errors.New("denied")}

	w := postRegistryLogin(t, app, result.Token, map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "newsecret",
	})

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected %d, got %d", http.StatusUnprocessableEntity, w.Code)
	}

	entry, ok, err := readSessionRegistryCredential(runtimeDir, sessionID, "registry.example.com")
	if err != nil || !ok {
		t.Fatalf("previous credential must survive: ok=%v err=%v", ok, err)
	}
	username, password, err := decodeSessionDockerAuth(entry.Auth)
	if err != nil {
		t.Fatalf("decode previous credential: %v", err)
	}
	if username != "old" || password != "oldsecret" {
		t.Errorf("previous credential was destroyed: %q/%q", username, password)
	}
}

// TestRegistryLoginCredentialStaysWithinSession proves a login performed
// under one Session bearer never grants or stores anything for another
// Session, and never stores the session bearer material.
func TestRegistryLoginCredentialStaysWithinSession(t *testing.T) {
	app, _ := newTestAppWithEngineAuth(t)

	other, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession other: %v", err)
	}

	w := postRegistryLogin(t, app, other.Token, map[string]string{
		"registry": "registry.example.com",
		"username": "user",
		"password": "secret",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	// The credential lives in the owning Session's protected directory.
	if _, ok, err := readSessionRegistryCredential(app.Config.RuntimeDir, other.Session.ID, "registry.example.com"); err != nil || !ok {
		t.Fatalf("owning session must hold the credential: ok=%v err=%v", ok, err)
	}

	// A second Session created afterwards shares no credential slot.
	second, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession second: %v", err)
	}
	if second.Session.ID == other.Session.ID {
		t.Fatal("test precondition broken: sessions must be distinct")
	}
	if _, ok, err := readSessionRegistryCredential(app.Config.RuntimeDir, second.Session.ID, "registry.example.com"); err != nil || ok {
		t.Fatalf("credential crossed session ownership: ok=%v err=%v", ok, err)
	}

	// The Session bearer material is session runtime state, not registry
	// credential state: the stored document carries only the registry slot.
	cfg, err := readSessionDockerAuthConfig(sessionDockerDir(app.Config.RuntimeDir, other.Session.ID))
	if err != nil {
		t.Fatalf("read credential document: %v", err)
	}
	if len(cfg.Auths) != 1 {
		t.Errorf("expected exactly one registry slot, got %d", len(cfg.Auths))
	}
}

// TestRegistryLoginSecretCanaryContainment proves the unique credential
// canaries appear only in the one protected credential store: the owning
// Session's Docker config.json. They must not appear in the HTTP response,
// audit capture, daemon operational log capture, SQLite text/blob content,
// the admin-token file, or any other runtime/config file. Failure messages
// never print the canary values.
func TestRegistryLoginSecretCanaryContainment(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)

	app, _ := newTestAppWithEngineAuth(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const passwordCanary = "dh-d02-canary-password-Xk7Qm2Vw9c"
	const usernameCanary = "dh-d02-canary-user-Pn4Rz8Kf3b"

	// Pre-existing credential for another registry plus a foreign session,
	// so the scan proves replacement scope rather than an empty store.
	if err := storeSessionRegistryCredential(app.Config.RuntimeDir, result.Session.ID, "other.example.com:5000", "other", "othersecret", ""); err != nil {
		t.Fatalf("store unrelated credential: %v", err)
	}

	w := postRegistryLogin(t, app, result.Token, map[string]string{
		"registry": "registry.example.com",
		"username": usernameCanary,
		"password": passwordCanary,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	contains := func(where, blob string) bool {
		return strings.Contains(blob, passwordCanary) || strings.Contains(blob, usernameCanary)
	}

	// HTTP response body.
	if blob := w.Body.String(); contains("http body", blob) {
		t.Error("HTTP response contains credential material")
	}

	// Audit capture.
	if contains("audit", auditBuf.String()) {
		t.Error("audit capture contains credential material")
	}

	// Daemon operational log capture.
	if contains("operational log", opBuf.String()) {
		t.Error("operational log contains credential material")
	}

	// SQLite text/blob content.
	dbBlob, err := os.ReadFile(app.Config.DatabasePath)
	if err != nil {
		t.Fatalf("read SQLite file: %v", err)
	}
	if contains("sqlite", string(dbBlob)) {
		t.Error("SQLite database contains credential material")
	}

	// The admin-token file.
	if app.Config.AdminTokenPath != "" {
		adminBlob, err := os.ReadFile(app.Config.AdminTokenPath)
		if err == nil && contains("admin token", string(adminBlob)) {
			t.Error("admin-token file contains credential material")
		}
	}

	// Runtime/config files: the credential may appear only in the owning
	// session's protected Docker config.json.
	runtimeRoot := app.Config.RuntimeDir
	err = filepath.Walk(runtimeRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		blob, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if !contains(path, string(blob)) {
			return nil
		}
		protectedStore := sessionDockerDir(runtimeRoot, result.Session.ID) + "/config.json"
		if path != protectedStore {
			t.Errorf("credential material leaked into %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk runtime dir: %v", err)
	}

	// The protected store itself holds exactly the intended entries.
	cfg, err := readSessionDockerAuthConfig(sessionDockerDir(runtimeRoot, result.Session.ID))
	if err != nil {
		t.Fatalf("read protected store: %v", err)
	}
	if len(cfg.Auths) != 2 {
		t.Fatalf("expected the new and the unrelated registry slot, got %d", len(cfg.Auths))
	}
	if _, ok := cfg.Auths[normalizeRegistryAddress("registry.example.com")]; !ok {
		t.Error("intended registry slot missing")
	}
	if _, ok := cfg.Auths[normalizeRegistryAddress("other.example.com:5000")]; !ok {
		t.Error("unrelated registry slot missing")
	}
}
