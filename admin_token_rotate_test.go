package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// assertAdminTokenFormat verifies the unified bearer token contract:
// dht_ followed by 64 lowercase hex characters. The same invariant applies
// to init/session/credential tokens.
func assertAdminTokenFormat(t *testing.T, token string) {
	t.Helper()
	if !strings.HasPrefix(token, "dht_") {
		t.Fatalf("admin token should have prefix dht_, got %q", token)
	}
	payload := strings.TrimPrefix(token, "dht_")
	if len(payload) != 64 {
		t.Fatalf("admin token hex payload length = %d, want 64", len(payload))
	}
	for _, c := range payload {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("admin token payload contains non-hex character %q", c)
		}
	}
}

func TestRotateAdminTokenFormat(t *testing.T) {
	app := newTestAppWithAuth(t)

	newToken, err := app.rotateAdminToken(app.getAdminTokenHash())
	if err != nil {
		t.Fatalf("rotateAdminToken() error: %v", err)
	}

	assertAdminTokenFormat(t, newToken)
	if newToken == testAdminToken {
		t.Error("new token should differ from old token")
	}
}

func TestRotateAdminTokenSuccess(t *testing.T) {
	app := newTestAppWithAuth(t)

	// Old token is valid before rotation.
	req := httptest.NewRequest("GET", "/principals", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	app.handleListPrincipals(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with old token before rotation, got %d", w.Code)
	}

	newToken, err := app.rotateAdminToken(app.getAdminTokenHash())
	if err != nil {
		t.Fatalf("rotateAdminToken() error: %v", err)
	}
	assertAdminTokenFormat(t, newToken)

	// File content is EXACTLY newToken + "\n".
	tokenPath := app.getConfig().AdminTokenPath
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("cannot read token file: %v", err)
	}
	if string(data) != newToken+"\n" {
		t.Errorf("token file content = %q, want %q", string(data), newToken+"\n")
	}

	// File mode 0600.
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("cannot stat token file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("token file mode = %o, want 0600", info.Mode().Perm())
	}

	// Runtime hash matches the new token.
	if app.getAdminTokenHash() != sha256.Sum256([]byte(newToken)) {
		t.Error("in-memory hash not updated after rotation")
	}

	// Old token immediately rejected, new token immediately accepted.
	req = httptest.NewRequest("GET", "/principals", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w = httptest.NewRecorder()
	app.handleListPrincipals(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with old token after rotation, got %d", w.Code)
	}

	req = httptest.NewRequest("GET", "/principals", nil)
	req.Header.Set("Authorization", "Bearer "+newToken)
	w = httptest.NewRecorder()
	app.handleListPrincipals(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with new token after rotation, got %d", w.Code)
	}
}

// TestRotateAdminTokenRenameFailure verifies the failure-safe contract:
// when the atomic rename fails, the runtime hash is unchanged, the old
// token remains valid, the token file is unchanged, and no temp file is
// left behind.
func TestRotateAdminTokenRenameFailure(t *testing.T) {
	app := newTestAppWithAuth(t)

	tokenPath := app.getConfig().AdminTokenPath
	writeTestTokenFile(t, tokenPath, testAdminToken+"\n")
	oldFile, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("cannot read token file: %v", err)
	}

	app.RotateRenameFn = func(oldpath, newpath string) error {
		return os.ErrInvalid
	}

	_, err = app.rotateAdminToken(app.getAdminTokenHash())
	if err == nil {
		t.Fatal("expected error for failed rename")
	}

	// Runtime hash unchanged.
	if app.getAdminTokenHash() != sha256.Sum256([]byte(testAdminToken)) {
		t.Error("runtime hash changed despite failed rotation")
	}

	// Old token still passes requireAdmin.
	req := httptest.NewRequest("GET", "/principals", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	app.handleListPrincipals(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with old token after failed rotation, got %d", w.Code)
	}

	// Token file unchanged.
	newFile, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("cannot read token file: %v", err)
	}
	if !bytes.Equal(newFile, oldFile) {
		t.Error("token file changed despite failed rotation")
	}

	// No temp files left behind.
	dir := filepath.Dir(tokenPath)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read dir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".admin-token-") {
			t.Errorf("temp file left behind: %s", entry.Name())
		}
	}
}

// TestRotateAdminTokenStaleCommit verifies that a rotation whose
// authorizing token is no longer current at commit time is rejected as
// stale and leaves the winner's state untouched.
func TestRotateAdminTokenStaleCommit(t *testing.T) {
	app := newTestAppWithAuth(t)
	oldHash := app.getAdminTokenHash()

	first, err := app.rotateAdminToken(oldHash)
	if err != nil {
		t.Fatalf("first rotateAdminToken() error: %v", err)
	}
	tokenPath := app.getConfig().AdminTokenPath
	firstFile, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("cannot read token file: %v", err)
	}

	// A request authenticated before the first rotation that commits after
	// it must be rejected as stale.
	_, err = app.rotateAdminToken(oldHash)
	if !errors.Is(err, ErrStaleRotation) {
		t.Fatalf("expected ErrStaleRotation, got %v", err)
	}

	// State unchanged from the first rotation.
	if app.getAdminTokenHash() != sha256.Sum256([]byte(first)) {
		t.Error("runtime hash changed by stale commit")
	}
	secondFile, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("cannot read token file: %v", err)
	}
	if !bytes.Equal(secondFile, firstFile) {
		t.Error("token file changed by stale commit")
	}

	// The old token is invalid; the first token is valid.
	req := httptest.NewRequest("GET", "/principals", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	app.handleListPrincipals(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with original token, got %d", w.Code)
	}
	req = httptest.NewRequest("GET", "/principals", nil)
	req.Header.Set("Authorization", "Bearer "+first)
	w = httptest.NewRecorder()
	app.handleListPrincipals(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with first rotated token, got %d", w.Code)
	}
}

func TestHandleRotateAdminToken(t *testing.T) {
	app := newTestAppWithAuth(t)

	req := httptest.NewRequest("POST", "/admin/token/rotate", nil)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleRotateAdminToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp rotateAdminTokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if !resp.OK {
		t.Error("expected ok=true")
	}
	assertAdminTokenFormat(t, resp.Token)
}

func TestHandleRotateAdminTokenAuth(t *testing.T) {
	app := newTestAppWithAuth(t)

	// Actual session token.
	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}
	sessionToken := result.Token

	// Actual launcher credential token.
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		if username == "rotateuser" {
			return "1006", "1006", filepath.Join(app.Config.AllowedRoot, "home", "rotateuser"), nil
		}
		return "", "", "", os.ErrNotExist
	}
	home := filepath.Join(app.Config.AllowedRoot, "home", "rotateuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := createPrincipal(app.DB, "rotateuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	var credToken string
	_, credToken, err = createCredential(app.DB, "rotateuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	tests := []struct {
		name     string
		token    string
		noAuth   bool
		wantCode int
	}{
		{name: "admin", token: testAdminToken, wantCode: http.StatusOK},
		{name: "missing", noAuth: true, wantCode: http.StatusUnauthorized},
		{name: "wrong_admin", token: "dht_wrong_token", wantCode: http.StatusUnauthorized},
		{name: "session_token", token: sessionToken, wantCode: http.StatusUnauthorized},
		{name: "launcher_credential", token: credToken, wantCode: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/admin/token/rotate", nil)
			if !tt.noAuth {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			w := httptest.NewRecorder()
			app.handleRotateAdminToken(w, req)
			if w.Code != tt.wantCode {
				t.Errorf("expected %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}
		})
	}

	// The successful admin rotation above replaced the token; the old
	// admin token must now be rejected as stale.
	req := httptest.NewRequest("POST", "/admin/token/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	app.handleRotateAdminToken(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with stale previous admin token, got %d", w.Code)
	}
}

// TestHandleRotateAdminTokenConcurrent runs two simultaneous rotations with
// the same old token: exactly one succeeds, the other is rejected, the file
// matches the winner's token, and the winner is the only active token.
// This test is expected to run under the race detector.
func TestHandleRotateAdminTokenConcurrent(t *testing.T) {
	app := newTestAppWithAuth(t)

	type outcome struct {
		code  int
		token string
	}
	results := make(chan outcome, 2)

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("POST", "/admin/token/rotate", nil)
			req.Header.Set("Authorization", "Bearer "+testAdminToken)
			w := httptest.NewRecorder()
			app.handleRotateAdminToken(w, req)
			out := outcome{code: w.Code}
			if w.Code == http.StatusOK {
				var resp rotateAdminTokenResponse
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Errorf("cannot decode response: %v", err)
					return
				}
				out.token = resp.Token
			}
			results <- out
		}()
	}
	wg.Wait()
	close(results)

	var winners, rejects int
	var winnerToken string
	for out := range results {
		switch {
		case out.code == http.StatusOK:
			winners++
			winnerToken = out.token
		case out.code == http.StatusUnauthorized:
			rejects++
		default:
			t.Fatalf("unexpected status %d", out.code)
		}
	}
	if winners != 1 {
		t.Fatalf("expected exactly 1 successful rotation, got %d", winners)
	}
	if rejects != 1 {
		t.Fatalf("expected exactly 1 rejected rotation, got %d", rejects)
	}

	// File contains the winner's token.
	data, err := os.ReadFile(app.getConfig().AdminTokenPath)
	if err != nil {
		t.Fatalf("cannot read token file: %v", err)
	}
	if string(data) != winnerToken+"\n" {
		t.Errorf("token file = %q, want %q", string(data), winnerToken+"\n")
	}

	// The winner's token is the only active runtime token.
	if app.getAdminTokenHash() != sha256.Sum256([]byte(winnerToken)) {
		t.Error("runtime hash does not match winner token")
	}
	req := httptest.NewRequest("GET", "/principals", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()
	app.handleListPrincipals(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with old token, got %d", w.Code)
	}
	req = httptest.NewRequest("GET", "/principals", nil)
	req.Header.Set("Authorization", "Bearer "+winnerToken)
	w = httptest.NewRecorder()
	app.handleListPrincipals(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 with winner token, got %d", w.Code)
	}
}

func TestRotateAdminTokenAuditSuccess(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)

	app := newTestAppWithAuth(t)

	req := httptest.NewRequest("POST", "/admin/token/rotate", nil)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleRotateAdminToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp rotateAdminTokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	records := parseAuditRecords(auditBuf)
	var rotateRec *auditRecord
	for i := range records {
		if records[i].Event == "admin_token.rotate" {
			rotateRec = &records[i]
		}
	}
	if rotateRec == nil {
		t.Fatalf("no admin_token.rotate audit record, got: %s", auditBuf.String())
	}
	if rotateRec.Result != "success" {
		t.Errorf("audit result = %q, want success", rotateRec.Result)
	}

	// Neither token may appear in audit or operational logs.
	for name, raw := range map[string]string{"audit": auditBuf.String(), "operational": opBuf.String()} {
		if strings.Contains(raw, testAdminToken) {
			t.Errorf("%s log contains old token", name)
		}
		if strings.Contains(raw, resp.Token) {
			t.Errorf("%s log contains new token", name)
		}
		if strings.Contains(raw, "Authorization") {
			t.Errorf("%s log contains Authorization header", name)
		}
	}
}

func TestRotateAdminTokenAuditFailure(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)

	app := newTestAppWithAuth(t)
	app.RotateRenameFn = func(oldpath, newpath string) error {
		return os.ErrInvalid
	}

	req := httptest.NewRequest("POST", "/admin/token/rotate", nil)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleRotateAdminToken(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}

	records := parseAuditRecords(auditBuf)
	var rotateRec *auditRecord
	for i := range records {
		if records[i].Event == "admin_token.rotate" {
			rotateRec = &records[i]
		}
	}
	if rotateRec == nil {
		t.Fatalf("no admin_token.rotate audit record on failure, got: %s", auditBuf.String())
	}
	if rotateRec.Result != "error" {
		t.Errorf("audit result = %q, want error", rotateRec.Result)
	}

	// No token in audit, operational log, or the error response.
	for name, raw := range map[string]string{
		"audit":       auditBuf.String(),
		"operational": opBuf.String(),
		"response":    w.Body.String(),
	} {
		if strings.Contains(raw, testAdminToken) {
			t.Errorf("%s contains old token", name)
		}
	}
}

// TestRotateAdminTokenBothTransports verifies that the Unix socket and
// loopback HTTP listeners share one App/auth state: a rotation performed
// through one transport is immediately effective on both.
func TestRotateAdminTokenBothTransports(t *testing.T) {
	app := newTestAppWithAuth(t)

	mux := http.NewServeMux()
	registerRoutes(mux, app)

	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	unixListener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer os.Remove(socketPath)

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}

	server := &http.Server{Handler: mux}
	go server.Serve(unixListener)
	go server.Serve(tcpListener)
	t.Cleanup(func() { server.Close() })

	unixClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
	tcpClient := &http.Client{}
	tcpURL := "http://" + tcpListener.Addr().String()

	doGet := func(client *http.Client, baseURL, token string) int {
		req, err := http.NewRequest("GET", baseURL+"/principals", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /principals: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	doRotate := func(client *http.Client, baseURL, token string) (int, string) {
		req, err := http.NewRequest("POST", baseURL+"/admin/token/rotate", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST /admin/token/rotate: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		return resp.StatusCode, string(body)
	}

	const oldToken = testAdminToken

	// Old token works on both transports before rotation.
	if code := doGet(unixClient, "http://unix", oldToken); code != http.StatusOK {
		t.Fatalf("unix: expected 200 before rotation, got %d", code)
	}
	if code := doGet(tcpClient, tcpURL, oldToken); code != http.StatusOK {
		t.Fatalf("tcp: expected 200 before rotation, got %d", code)
	}

	// Rotate through the Unix socket.
	code, body := doRotate(unixClient, "http://unix", oldToken)
	if code != http.StatusOK {
		t.Fatalf("rotate: expected 200, got %d: %s", code, body)
	}
	var resp rotateAdminTokenResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	assertAdminTokenFormat(t, resp.Token)

	// Old token immediately rejected on both transports.
	if code := doGet(unixClient, "http://unix", oldToken); code != http.StatusUnauthorized {
		t.Errorf("unix: expected 401 with old token after rotation, got %d", code)
	}
	if code := doGet(tcpClient, tcpURL, oldToken); code != http.StatusUnauthorized {
		t.Errorf("tcp: expected 401 with old token after rotation, got %d", code)
	}

	// New token immediately accepted on both transports.
	if code := doGet(unixClient, "http://unix", resp.Token); code != http.StatusOK {
		t.Errorf("unix: expected 200 with new token, got %d", code)
	}
	if code := doGet(tcpClient, tcpURL, resp.Token); code != http.StatusOK {
		t.Errorf("tcp: expected 200 with new token, got %d", code)
	}
}

// ---------- CLI behavior ----------

const cliNewAdminToken = "dht_" + "abababababababababababababababababababababababababababababababab"

// startRotateCLITestServer serves POST /admin/token/rotate on an HTTP
// endpoint, requiring the given Bearer token.
func startRotateCLITestServer(t *testing.T, wantToken string) (endpoint string, tokenPath string) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/token/rotate", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+wantToken {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "code": "unauthorized"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(rotateAdminTokenResponse{OK: true, Token: cliNewAdminToken})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	tokenPath = filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(wantToken), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	return server.URL, tokenPath
}

func TestAdminTokenRotateCLIHuman(t *testing.T) {
	endpoint, tokenPath := startRotateCLITestServer(t, "test-token")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"admin", "token", "rotate", "--endpoint", endpoint, "--token-file", tokenPath}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}
	if stderr.Len() > 0 {
		t.Errorf("expected empty stderr, got: %s", stderr.String())
	}
	if got := stdout.String(); got != cliNewAdminToken+"\n" {
		t.Errorf("stdout = %q, want %q (token shown once, directly copyable)", got, cliNewAdminToken+"\n")
	}
}

func TestAdminTokenRotateCLIJson(t *testing.T) {
	endpoint, tokenPath := startRotateCLITestServer(t, "test-token")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"admin", "token", "rotate", "--endpoint", endpoint, "--token-file", tokenPath, "--json"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
	}
	if stderr.Len() > 0 {
		t.Errorf("expected empty stderr, got: %s", stderr.String())
	}

	var decoded rotateAdminTokenResponse
	if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (output: %s)", err, stdout.String())
	}
	if !decoded.OK {
		t.Error("expected ok=true")
	}
	if decoded.Token != cliNewAdminToken {
		t.Errorf("token = %q, want %q", decoded.Token, cliNewAdminToken)
	}
}

func TestAdminTokenRotateCLIAuthFailure(t *testing.T) {
	endpoint, _ := startRotateCLITestServer(t, "server-token")

	// Client token file does not match the server's current token.
	wrongPath := filepath.Join(t.TempDir(), "wrong-token")
	if err := os.WriteFile(wrongPath, []byte("stale-client-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"admin", "token", "rotate", "--endpoint", endpoint, "--token-file", wrongPath}, &stdout, &stderr)

	if code == 0 {
		t.Fatal("expected non-zero exit on auth failure")
	}
	if stdout.Len() > 0 {
		t.Errorf("stdout must be empty on auth failure, got: %s", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Error("expected error on stderr")
	}
}

// TestAdminTokenRotationConcurrentSessionAuth proves that concurrent admin
// token rotation and admin-authenticated session requests do not produce
// a data race on AdminTokenHash.
func TestAdminTokenRotationConcurrentSessionAuth(t *testing.T) {
	app := newTestAppWithAuth(t)
	workspace := testWorkspaceDir(t, app.Config.AllowedRoot)

	var wg sync.WaitGroup
	start := make(chan struct{})

	// Goroutine 1: continuously rotate the admin token.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 50; i++ {
			hash := app.getAdminTokenHash()
			_, _ = app.rotateAdminToken(hash)
		}
	}()

	// Goroutine 2: send admin-authenticated session create requests.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 50; i++ {
			reqBody := map[string]string{"workspace": workspace}
			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+testAdminToken)
			w := httptest.NewRecorder()
			app.handleCreateSession(w, req)
		}
	}()

	close(start)
	wg.Wait()

	// Final token is valid for admin auth.
	finalHash := app.getAdminTokenHash()
	if finalHash == [sha256.Size]byte{} {
		t.Error("admin token hash must not be zero after rotations")
	}
}
