package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
)

// fakePuller is a substituted Engine puller recording the request it was
// handed and returning a canned result.
type fakePuller struct {
	result           enginePullResult
	err              error
	gotContext       context.Context
	gotImage         string
	gotCredential    *sessionRegistryCredential
	gotOutputLimit   int64
	blockUntilCancel bool
	enteredOnce      sync.Once
	entered          chan struct{}
}

func newFakePuller() *fakePuller {
	return &fakePuller{entered: make(chan struct{})}
}

func (f *fakePuller) imagePull(ctx context.Context, imageRef string, credential *sessionRegistryCredential, outputLimit int64) (enginePullResult, error) {
	f.gotContext = ctx
	f.gotImage = imageRef
	f.gotCredential = credential
	f.gotOutputLimit = outputLimit
	f.enteredOnce.Do(func() { close(f.entered) })
	if f.blockUntilCancel {
		<-ctx.Done()
		return enginePullResult{}, normalizeEnginePullError(ctx.Err())
	}
	return f.result, f.err
}

// newTestAppWithEnginePuller wires a fake puller seam into a test app and
// returns the app and the fake.
func newTestAppWithEnginePuller(t *testing.T) (*App, *fakePuller) {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	puller := newFakePuller()
	app.NewEnginePullFn = func() (engineImagePuller, error) {
		return puller, nil
	}
	return app, puller
}

// newTestSession creates a session against the app's first allowed root.
func newTestSession(t *testing.T, app *App) *CreatedSession {
	t.Helper()
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}
	return result
}

// postPull posts a pull request body as the given session.
func postPull(t *testing.T, app *App, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	blob, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal pull request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(blob))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)
	return w
}

// decodePullResponse decodes the pull response envelope.
func decodePullResponse(t *testing.T, w *httptest.ResponseRecorder) pullResponse {
	t.Helper()
	var resp pullResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode pull response: %v (%s)", err, w.Body.String())
	}
	return resp
}

func TestPullSessionAuthValidToken(t *testing.T) {
	app, _ := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	w := postPull(t, app, result.Token, map[string]string{"image": "alpine:3.24"})

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestPullSessionAuthMissingAuthorization(t *testing.T) {
	app, _ := newTestAppWithEnginePuller(t)

	w := postPull(t, app, "", map[string]string{"image": "alpine:3.24"})

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthWrongScheme(t *testing.T) {
	app, _ := newTestAppWithEnginePuller(t)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader([]byte(`{"image":"alpine:3.24"}`)))
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthEmptyBearer(t *testing.T) {
	app, _ := newTestAppWithEnginePuller(t)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader([]byte(`{"image":"alpine:3.24"}`)))
	req.Header.Set("Authorization", "Bearer ")
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthInvalidToken(t *testing.T) {
	app, _ := newTestAppWithEnginePuller(t)

	w := postPull(t, app, "dht_wrong_token", map[string]string{"image": "alpine:3.24"})

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthExpiredSession(t *testing.T) {
	app, _ := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	if _, err := app.DB.Exec("UPDATE sessions SET expires_at = ? WHERE id = ?", time.Now().Add(-time.Hour).Unix(), result.Session.ID); err != nil {
		t.Fatalf("cannot update expires_at: %v", err)
	}

	w := postPull(t, app, result.Token, map[string]string{"image": "alpine:3.24"})

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthDeletedSession(t *testing.T) {
	app, _ := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	deleted, err := app.deleteSessionScoped(result.Session.ID, sessionControlScope{admin: true})
	if err != nil {
		t.Fatalf("deleteSessionScoped() error: %v", err)
	}
	if deleted == nil {
		t.Fatal("expected session to be deleted")
	}

	w := postPull(t, app, result.Token, map[string]string{"image": "alpine:3.24"})

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthResponseContainsCode(t *testing.T) {
	app, _ := newTestAppWithEnginePuller(t)

	w := postPull(t, app, "", map[string]string{"image": "alpine:3.24"})

	resp := decodePullResponse(t, w)
	if resp.Code != "unauthorized" {
		t.Errorf("expected code 'unauthorized', got %q", resp.Code)
	}
}

func TestPullSessionAuthResponseContainsWWWAuthenticate(t *testing.T) {
	app, _ := newTestAppWithEnginePuller(t)

	w := postPull(t, app, "", map[string]string{"image": "alpine:3.24"})

	if w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("expected WWW-Authenticate: Bearer, got %q", w.Header().Get("WWW-Authenticate"))
	}
}

// TestPullSessionAuthInvalidTokenDoesNotConstructPuller proves authorization
// happens before any Engine adapter construction.
func TestPullSessionAuthInvalidTokenDoesNotConstructPuller(t *testing.T) {
	app, _ := newTestAppWithEnginePuller(t)
	constructed := false
	app.NewEnginePullFn = func() (engineImagePuller, error) {
		constructed = true
		return newFakePuller(), nil
	}

	w := postPull(t, app, "dht_wrong_token", map[string]string{"image": "alpine:3.24"})

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
	if constructed {
		t.Error("engine puller must not be constructed with an invalid token")
	}
}

func TestPullSessionAuthAdminTokenRejected(t *testing.T) {
	app, _ := newTestAppWithEnginePuller(t)

	w := postPull(t, app, testAdminToken, map[string]string{"image": "alpine:3.24"})

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d (admin token should not work for /pull), got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullImageRequired(t *testing.T) {
	app, _ := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	w := postPull(t, app, result.Token, map[string]string{})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
	resp := decodePullResponse(t, w)
	if resp.Message != "image is required" {
		t.Errorf("expected 'image is required', got %q", resp.Message)
	}
}

func TestPullInvalidJSON(t *testing.T) {
	app, _ := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPullUnknownFieldsRejected(t *testing.T) {
	app, _ := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	w := postPull(t, app, result.Token, map[string]any{"image": "alpine:3.24", "extra": "field"})

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPullSuccessResponse(t *testing.T) {
	app, puller := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	puller.result = enginePullResult{Output: "pull output\n"}

	w := postPull(t, app, result.Token, map[string]string{"image": "alpine:3.24"})

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
	resp := decodePullResponse(t, w)
	if !resp.OK {
		t.Error("expected ok to be true")
	}
	if resp.Message != "image pulled successfully" {
		t.Errorf("expected 'image pulled successfully', got %q", resp.Message)
	}
	if resp.Output != "pull output\n" {
		t.Errorf("expected output 'pull output\\n', got %q", resp.Output)
	}
	if resp.Duration == "" {
		t.Error("expected duration to be set")
	}
}

// TestPullFailureClassification verifies that expected Engine pull failures
// (image not found, access denied, registry unreachable) are classified into
// precise HTTP status/code/message pairs instead of a generic 500, while the
// rendered pull output is preserved for the client.
func TestPullFailureClassification(t *testing.T) {
	cases := []struct {
		name       string
		pullErr    error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "image not found",
			pullErr:    fmt.Errorf("manifest unknown: %w", cerrdefs.ErrNotFound),
			wantStatus: http.StatusNotFound,
			wantCode:   "image_not_found",
		},
		{
			name:       "pull access denied",
			pullErr:    fmt.Errorf("401 Unauthorized: %w", cerrdefs.ErrUnauthenticated),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "pull_access_denied",
		},
		{
			name:       "registry network failure",
			pullErr:    fmt.Errorf(`Get "https://registry-1.docker.io/v2/": dial tcp: lookup registry-1.docker.io: no such host`),
			wantStatus: http.StatusBadGateway,
			wantCode:   "registry_unavailable",
		},
		{
			name:       "unrecognized failure stays generic",
			pullErr:    fmt.Errorf("some other docker error"),
			wantStatus: http.StatusInternalServerError,
			wantCode:   "docker_pull_failed",
		},
		{
			name:       "engine unreachable stays generic",
			pullErr:    &engineError{kind: engineErrBackendUnavailable, cause: fmt.Errorf("cannot connect")},
			wantStatus: http.StatusInternalServerError,
			wantCode:   "docker_pull_failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, puller := newTestAppWithEnginePuller(t)
			result := newTestSession(t, app)

			puller.result = enginePullResult{Output: "progress before failure\n"}
			puller.err = normalizeEnginePullError(tc.pullErr)

			w := postPull(t, app, result.Token, map[string]string{"image": "nonexistent:latest"})

			if w.Code != tc.wantStatus {
				t.Errorf("expected status %d, got %d", tc.wantStatus, w.Code)
			}
			resp := decodePullResponse(t, w)
			if resp.Code != tc.wantCode {
				t.Errorf("expected code %q, got %q", tc.wantCode, resp.Code)
			}
			if resp.Output != "progress before failure\n" {
				t.Errorf("expected pull output preserved, got %q", resp.Output)
			}
		})
	}
}

// TestClassifyDockerError proves the coarse classifier distinguishes the
// categories Docker's stable stderr lines support.
func TestClassifyDockerError(t *testing.T) {
	cases := []struct {
		output string
		want   dockerErrorKind
	}{
		{"manifest unknown", dockerErrorImageNotFound},
		{"Error response from daemon: manifest for alpine:x not found: manifest unknown", dockerErrorImageNotFound},
		{"pull access denied for repo, repository does not exist", dockerErrorAuthDenied},
		{"unauthorized: authentication required", dockerErrorAuthDenied},
		{"failed with status: 401 Unauthorized", dockerErrorAuthDenied},
		{"no basic auth credentials", dockerErrorAuthDenied},
		{"dial tcp: lookup registry-1.docker.io: no such host", dockerErrorNetwork},
		{"connection refused", dockerErrorNetwork},
		// Network markers are checked first: a mixed stream that also carries
		// an auth marker must classify as network, never as an auth denial.
		{"proxyconnect tcp: connection refused; failed with status: 401 Unauthorized", dockerErrorNetwork},
		{"some unrelated error text", dockerErrorUnknown},
		{"", dockerErrorUnknown},
	}
	for _, tc := range cases {
		if got := classifyDockerError(tc.output); got != tc.want {
			t.Errorf("classifyDockerError(%q) = %v, want %v", tc.output, got, tc.want)
		}
	}
}

// TestPullCredentialResolutionExactRegistry proves the pull path resolves the
// stored Session credential for exactly the registry the image reference
// names, including the Docker Hub store key, and pulls unauthenticated when
// nothing is stored for that registry.
func TestPullCredentialResolutionExactRegistry(t *testing.T) {
	app, puller := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	if err := storeSessionRegistryCredential(app.Config.RuntimeDir, result.Session.ID, "registry.example.com", "user", "stored-pass", ""); err != nil {
		t.Fatalf("cannot store registry credential: %v", err)
	}
	if err := storeSessionRegistryCredential(app.Config.RuntimeDir, result.Session.ID, "docker.io", "hub-user", "hub-pass", ""); err != nil {
		t.Fatalf("cannot store hub credential: %v", err)
	}

	cases := []struct {
		image        string
		wantRegistry string
		wantUsername string
	}{
		{"registry.example.com/team/image:v1", "registry.example.com", "user"},
		{"docker.io/library/alpine:3.24", dockerHubAuthConfigKey, "hub-user"},
		{"alpine:3.24", dockerHubAuthConfigKey, "hub-user"},
		{"other-registry.example.net/team/image:v1", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.image, func(t *testing.T) {
			w := postPull(t, app, result.Token, map[string]string{"image": tc.image})
			if w.Code != http.StatusOK {
				t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
			}
			if tc.wantRegistry == "" {
				if puller.gotCredential != nil {
					t.Errorf("pull from a registry without stored credentials must be unauthenticated, got %+v", puller.gotCredential)
				}
				return
			}
			if puller.gotCredential == nil {
				t.Fatal("expected the stored credential to be resolved")
			}
			if puller.gotCredential.Registry != tc.wantRegistry {
				t.Errorf("credential registry = %q, want %q", puller.gotCredential.Registry, tc.wantRegistry)
			}
			if puller.gotCredential.Username != tc.wantUsername {
				t.Errorf("credential username = %q, want %q", puller.gotCredential.Username, tc.wantUsername)
			}
		})
	}
}

// TestPullCredentialResolutionIdentityToken proves a stored identity token is
// resolved as the credential for its registry.
func TestPullCredentialResolutionIdentityToken(t *testing.T) {
	app, puller := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	if err := storeSessionRegistryCredential(app.Config.RuntimeDir, result.Session.ID, "registry.example.com", "user", "", "tok-123"); err != nil {
		t.Fatalf("cannot store registry credential: %v", err)
	}

	w := postPull(t, app, result.Token, map[string]string{"image": "registry.example.com/team/image:v1"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}
	if puller.gotCredential == nil || puller.gotCredential.IdentityToken != "tok-123" || puller.gotCredential.Password != "" {
		t.Errorf("expected the identity token as credential, got %+v", puller.gotCredential)
	}
}

// TestPullCredentialResolutionMalformedStoreRejected proves an unparseable
// stored credential is an operational error answered with the sanitized
// internal-error contract before any pull starts.
func TestPullCredentialResolutionMalformedStoreRejected(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, puller := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	dockerDir := sessionDockerDir(app.Config.RuntimeDir, result.Session.ID)
	if err := os.MkdirAll(dockerDir, 0700); err != nil {
		t.Fatalf("cannot create docker dir: %v", err)
	}
	configJSON := `{"auths":{"registry.example.com":{"auth":"!!not-base64!!"}}}`
	if err := os.WriteFile(filepath.Join(dockerDir, "config.json"), []byte(configJSON), 0600); err != nil {
		t.Fatalf("cannot seed malformed config: %v", err)
	}

	w := postPull(t, app, result.Token, map[string]string{"image": "registry.example.com/team/image:v1"})

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected %d, got %d", http.StatusInternalServerError, w.Code)
	}
	resp := decodePullResponse(t, w)
	if resp.Code != "internal_error" {
		t.Errorf("expected code 'internal_error', got %q", resp.Code)
	}
	select {
	case <-puller.entered:
		t.Error("the pull must not start when the stored credential cannot be read")
	default:
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		if rec.Event == "pull.start" || rec.Event == "pull.finish" {
			t.Errorf("pull audit event must not appear: %s", rec.Event)
		}
		if rec.Event == "pull.rejected" && rec.Result != "internal_error" {
			t.Errorf("expected pull.rejected internal_error, got %q", rec.Result)
		}
	}
}

// TestPullCredentialResolutionUnparseableReferenceProves... proves an image
// reference outside the Docker grammar is not rejected by helper validation;
// the pull proceeds unauthenticated and the Engine decides the outcome.
func TestPullCredentialResolutionUnparseableReference(t *testing.T) {
	app, puller := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	puller.result = enginePullResult{Output: "out\n"}

	w := postPull(t, app, result.Token, map[string]string{"image": "UPPER:CASE!!"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}
	if puller.gotCredential != nil {
		t.Errorf("an unparseable reference must pull unauthenticated, got %+v", puller.gotCredential)
	}
	if puller.gotImage != "UPPER:CASE!!" {
		t.Errorf("expected the reference passed through unchanged, got %q", puller.gotImage)
	}
}

// TestPullNoCredentialCanaryLeak proves a resolved credential and the raw
// backend failure text never reach the response, audit, or operational log;
// the canary markers double as positive controls for every surface checked.
func TestPullNoCredentialCanaryLeak(t *testing.T) {
	const credentialCanary = "dht-credential-canary-1f8e2"
	const backendCanary = "dht-backend-canary-9b41c"

	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)
	initLoggers(opBuf, auditBuf, slog.LevelInfo, true)
	t.Cleanup(logging.reset)

	app, puller := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	if err := storeSessionRegistryCredential(app.Config.RuntimeDir, result.Session.ID, "registry.example.com", "user", credentialCanary, ""); err != nil {
		t.Fatalf("cannot store registry credential: %v", err)
	}
	puller.result = enginePullResult{Output: "progress\n"}
	puller.err = &engineError{
		kind:  engineErrBackendFailure,
		cause: fmt.Errorf("engine failed while using password %s and reported %s", credentialCanary, backendCanary),
	}

	w := postPull(t, app, result.Token, map[string]string{"image": "registry.example.com/team/image:v1"})

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "docker_pull_failed") {
		t.Fatalf("expected the generic pull failure response, got %s", body)
	}
	if strings.Contains(body, credentialCanary) || strings.Contains(body, backendCanary) {
		t.Errorf("the pull response leaked a canary: %s", body)
	}

	rawAudit := auditBuf.String()
	if !strings.Contains(rawAudit, `"pull.finish"`) {
		t.Fatalf("expected the pull.finish audit event, got %s", rawAudit)
	}
	if strings.Contains(rawAudit, credentialCanary) || strings.Contains(rawAudit, backendCanary) {
		t.Errorf("the audit log leaked a canary: %s", rawAudit)
	}

	rawOp := opBuf.String()
	if !strings.Contains(rawOp, `"pull failed"`) {
		t.Fatalf("expected the pull failure operational log, got %s", rawOp)
	}
	if strings.Contains(rawOp, credentialCanary) || strings.Contains(rawOp, backendCanary) {
		t.Errorf("the operational log leaked a canary: %s", rawOp)
	}
}

// TestPullRequestCancellation proves a disconnected client ends the pull: the
// Engine request context is cancelled and the handler answers the generic
// pull failure without an operational log entry.
func TestPullRequestCancellation(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)

	app, puller := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	puller.blockUntilCancel = true

	ctx, cancel := context.WithCancel(context.Background())
	req := newPullRequest(map[string]string{"image": "alpine:3.24"}, result.Token).WithContext(ctx)
	w := httptest.NewRecorder()

	handlerDone := make(chan struct{})
	go func() {
		app.handlePull(w, req)
		close(handlerDone)
	}()

	select {
	case <-puller.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the pull never started")
	}

	cancel()

	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handlePull did not return after context cancellation")
	}

	if puller.gotContext.Err() == nil {
		t.Error("the Engine request context must be cancelled with the request")
	}
	resp := decodePullResponse(t, w)
	if w.Code != http.StatusInternalServerError || resp.Code != "docker_pull_failed" {
		t.Errorf("a cancelled pull must answer the generic pull failure, got %d %q", w.Code, resp.Code)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	var finished bool
	for _, rec := range records {
		if rec.Event == "pull.finish" && rec.Result == "pull_error" {
			finished = true
		}
	}
	if !finished {
		t.Error("a cancelled pull must finish with result pull_error")
	}
	if strings.Contains(opBuf.String(), "ERROR") || strings.Contains(opBuf.String(), "WARN") {
		t.Errorf("a cancelled pull must not produce an operational log entry, got:\n%s", opBuf.String())
	}
}

// TestPullRefusedWhenShuttingDown proves daemon shutdown closes pull
// admission: the request is answered with the sanitized shutting-down
// contract before any pull starts.
func TestPullRefusedWhenShuttingDown(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, puller := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	app.SyncExecutionCoordinator.beginShutdown()

	w := postPull(t, app, result.Token, map[string]string{"image": "alpine:3.24"})

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
	resp := decodePullResponse(t, w)
	if resp.Code != "shutting_down" {
		t.Errorf("expected code 'shutting_down', got %q", resp.Code)
	}
	select {
	case <-puller.entered:
		t.Error("the pull must not start while the daemon is shutting down")
	default:
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	var rejected int
	for _, rec := range records {
		switch rec.Event {
		case "pull.start", "pull.finish":
			t.Errorf("pull audit event must not appear: %s", rec.Event)
		case "pull.rejected":
			rejected++
			if rec.Result != "shutting_down" {
				t.Errorf("expected pull.rejected shutting_down, got %q", rec.Result)
			}
		}
	}
	if rejected != 1 {
		t.Errorf("expected exactly 1 pull.rejected event, got %d", rejected)
	}
}

// TestPullTerminatedByDaemonShutdown proves production-like shutdown ends an
// in-flight pull: the coordinator cancels the Engine request, the handler
// releases the request and answers the client, and termination returns
// bounded by the shutdown deadline.
func TestPullTerminatedByDaemonShutdown(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, puller := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	puller.blockUntilCancel = true

	mux := http.NewServeMux()
	mux.HandleFunc("POST /pull", app.handlePull)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot create listener: %v", err)
	}
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()

	waitForDialReady(t, "tcp", listener.Addr().String())

	req, err := http.NewRequest(http.MethodPost, "http://"+listener.Addr().String()+"/pull", bytes.NewReader([]byte(`{"image":"alpine:3.24"}`)))
	if err != nil {
		t.Fatalf("cannot create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+result.Token)
	req.Header.Set("Content-Type", "application/json")

	type requestResult struct {
		status int
		code   string
	}
	reqDone := make(chan requestResult, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("pull request failed: %v", err)
			return
		}
		defer resp.Body.Close()
		var body pullResponse
		_ = json.NewDecoder(resp.Body).Decode(&body)
		reqDone <- requestResult{status: resp.StatusCode, code: body.Code}
	}()

	select {
	case <-puller.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the pull never started")
	}

	// Production shutdown order: admission gates close, then HTTP drain and
	// synchronous-request termination run concurrently under one deadline.
	terminateDone := make(chan struct{})
	drainDone := make(chan error, 1)
	go func() {
		defer close(terminateDone)
		app.SyncExecutionCoordinator.beginShutdown()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)

		go func() {
			shutdownErr := server.Shutdown(shutdownCtx)
			var drainErr error
			if shutdownErr == context.DeadlineExceeded {
				server.Close()
				drainErr = fmt.Errorf("graceful shutdown timeout after %v", 2*time.Second)
			} else if shutdownErr != nil {
				drainErr = shutdownErr
			}
			drainDone <- drainErr
			shutdownCancel()
		}()

		app.SyncExecutionCoordinator.terminateForShutdown(shutdownCtx)
	}()

	select {
	case result := <-reqDone:
		if result.status != http.StatusInternalServerError || result.code != "docker_pull_failed" {
			t.Errorf("a pull cancelled by shutdown must answer the generic pull failure, got %d %q", result.status, result.code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the HTTP request did not complete after shutdown")
	}

	select {
	case <-terminateDone:
	case <-time.After(5 * time.Second):
		t.Fatal("terminateForShutdown did not return after the pull was released")
	}

	select {
	case err := <-drainDone:
		if err != nil {
			t.Errorf("graceful drain reported an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("graceful drain did not complete")
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	var finished bool
	for _, rec := range records {
		if rec.Event == "pull.finish" && rec.Result == "pull_error" {
			finished = true
		}
	}
	if !finished {
		t.Error("a pull cancelled by shutdown must finish with result pull_error")
	}
}

// TestPullOutputSurfacing proves the handler forwards the configured output
// limit to the Engine puller and surfaces the rendered output and truncation
// flag verbatim, on success and failure alike, with truncation omitted from
// the JSON while false.
func TestPullOutputSurfacing(t *testing.T) {
	cases := []struct {
		name        string
		outputLimit int64
		result      enginePullResult
		err         error
		wantStatus  int
		wantCode    string
	}{
		{
			name:        "success untruncated",
			outputLimit: 4 * 1024 * 1024,
			result:      enginePullResult{Output: "small output\n"},
			wantStatus:  http.StatusOK,
			wantCode:    "",
		},
		{
			name:        "success truncated",
			outputLimit: 64,
			result:      enginePullResult{Output: strings.Repeat("A", 64), Truncated: true},
			wantStatus:  http.StatusOK,
			wantCode:    "",
		},
		{
			name:        "failure truncated",
			outputLimit: 64,
			result:      enginePullResult{Output: strings.Repeat("B", 64), Truncated: true},
			err:         normalizeEnginePullError(fmt.Errorf("some other docker error")),
			wantStatus:  http.StatusInternalServerError,
			wantCode:    "docker_pull_failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, puller := newTestAppWithEnginePuller(t)
			result := newTestSession(t, app)

			app.Config.OperationLogMaxBytes = tc.outputLimit
			puller.result = tc.result
			puller.err = tc.err

			w := postPull(t, app, result.Token, map[string]string{"image": "alpine:3.24"})

			if w.Code != tc.wantStatus {
				t.Fatalf("expected status %d, got %d", tc.wantStatus, w.Code)
			}
			resp := decodePullResponse(t, w)
			if puller.gotOutputLimit != tc.outputLimit {
				t.Errorf("output limit forwarded = %d, want %d", puller.gotOutputLimit, tc.outputLimit)
			}
			if resp.Output != tc.result.Output || resp.Truncated != tc.result.Truncated {
				t.Errorf("output/truncated = %q/%v, want %q/%v", resp.Output, resp.Truncated, tc.result.Output, tc.result.Truncated)
			}
			if resp.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", resp.Code, tc.wantCode)
			}
			if tc.wantCode == "" && strings.Contains(w.Body.String(), "truncated") {
				t.Errorf("truncated field should be omitted when false, got: %s", w.Body.String())
			}
		})
	}
}

// TestImageReferenceNotRejectedByHelper verifies that valid Docker image
// reference grammars pass through helper validation unchanged and reach the
// Engine pull request. The puller is faked to avoid requiring a real daemon.
func TestImageReferenceNotRejectedByHelper(t *testing.T) {
	app, puller := newTestAppWithEnginePuller(t)
	result := newTestSession(t, app)

	for _, image := range []string{
		"registry.example.com:5000/team/image:tag", // registry with explicit port
		"alpine@sha256:abc123def456",               // digest reference
		"alpine",                                   // untagged reference
		"localhost:5000/image:tag",                 // localhost with port
	} {
		t.Run(image, func(t *testing.T) {
			w := postPull(t, app, result.Token, map[string]string{"image": image})

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
			}
			if puller.gotImage != image {
				t.Errorf("image reference passed through = %q, want %q", puller.gotImage, image)
			}
		})
	}
}
