package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// --- injected error for DB failure ---

var errMockQueryFail = errors.New("mock_query_injection_error_for_testing")

// newFailQueryDB opens the same SQLite file with a driver that fails QueryContext.
func newFailQueryDB(t *testing.T, dbPath string, failErr error) *sql.DB {
	t.Helper()
	name := nextMockDriverName("fq")
	sql.Register(name, &failDriver{failQuery: failErr})

	db, err := sql.Open(name, dbPath)
	if err != nil {
		t.Fatalf("newFailQueryDB: cannot open: %v", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatalf("newFailQueryDB: ping failed: %v", err)
	}
	return db
}

// --- helpers ---

func findAuthFailureRawLines(buf *bytes.Buffer) []string {
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if evt, ok := m["event"].(string); ok && evt == "auth.failure" {
			lines = append(lines, line)
		}
	}
	return lines
}

// validateAuthFailureRaw checks every required property on the raw audit JSON
// for an auth.failure event.
//
// Parameters:
//   - raw: the raw JSON line from stderr
//   - expectedMethod, expectedPath, expectedResult: structural checks
//   - injectedToken: the actual bearer token value sent in the request
//   - injectedErrText: injected DB error text (for database_error tests)
//   - authHeader: the full Authorization header value (e.g. "Bearer dht_xxx" or "Basic dXNlcjpwYXNz")
//   - headerMarker: a custom header value that must not appear in audit
//   - bodyMarker: a request-body value that must not appear in audit
func validateAuthFailureRaw(t *testing.T, raw string, expectedMethod, expectedPath, expectedResult, injectedToken, injectedErrText, authHeader, headerMarker, bodyMarker string) {
	t.Helper()

	m := parseAuditMap(t, raw)

	// --- required fields ---
	if m["event"] != "auth.failure" {
		t.Errorf("event: expected 'auth.failure', got %v", m["event"])
	}
	if m["method"] != expectedMethod {
		t.Errorf("method: expected %q, got %v", expectedMethod, m["method"])
	}
	if m["path"] != expectedPath {
		t.Errorf("path: expected %q, got %v", expectedPath, m["path"])
	}
	if m["result"] != expectedResult {
		t.Errorf("result: expected %q, got %v", expectedResult, m["result"])
	}

	// --- session_id must be completely absent ---
	if _, exists := m["session_id"]; exists {
		t.Error("session_id key must not be present in auth.failure audit record")
	}

	// --- generic secret-leak checks ---
	assertNoSecrets(t, raw, m, injectedToken, "")

	// --- no full Authorization header value ---
	if authHeader != "" && strings.Contains(raw, authHeader) {
		t.Errorf("raw JSON contains Authorization header value %q", authHeader)
	}

	// --- no injected error text ---
	assertNoInjectedError(t, raw, injectedErrText)

	// --- no internal error text ---
	for _, text := range []string{
		"session not found",
		"ErrSessionNotFound",
		"cannot find session",
		"sql.ErrNoRows",
	} {
		if strings.Contains(raw, text) {
			t.Errorf("raw JSON contains internal error text %q", text)
		}
	}

	// --- no request body content ---
	if strings.Contains(raw, "alpine:latest") {
		t.Error("raw JSON contains request body content (image)")
	}
	if strings.Contains(raw, "Content-Type") {
		t.Error("raw JSON contains request header Content-Type")
	}

	// --- no custom header marker ---
	if headerMarker != "" && strings.Contains(raw, headerMarker) {
		t.Errorf("raw JSON contains custom header marker %q", headerMarker)
	}

	// --- no body marker ---
	if bodyMarker != "" && strings.Contains(raw, bodyMarker) {
		t.Errorf("raw JSON contains body marker %q", bodyMarker)
	}
}

func assertNoAuthFailure(t *testing.T, buf *bytes.Buffer) {
	t.Helper()
	lines := findAuthFailureRawLines(buf)
	if len(lines) > 0 {
		t.Errorf("expected no auth.failure records, got %d", len(lines))
	}
}

// ========================
// session-control parse_failed
// ========================

func TestAuthAuditSessionControlParseFailed_MissingHeader(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	const headerMarker = "hdr_admin_parse_secret_x7k2m"
	const bodyMarker = "body_admin_parse_secret_p9q4n"

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(`{"workspace":"`+bodyMarker+`"}`)))
	req.Header.Set("X-Test-Secret", headerMarker)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/sessions", "parse_failed", "", "", "", headerMarker, bodyMarker)
}

func TestAuthAuditSessionControlParseFailed_WrongScheme(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	const authHeader = "Basic dXNlcjpwYXNz"

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", authHeader)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/sessions", "parse_failed", "", "", authHeader, "", "")
}

func TestAuthAuditSessionControlParseFailed_EmptyBearer(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	const authHeader = "Bearer "

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", authHeader)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/sessions", "parse_failed", "", "", authHeader, "", "")
}

// ========================
// session-control unauthorized response contract
// ========================

func TestAuthAuditSessionControlUnauthorizedResponseContract(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if resp.Code != "unauthorized" {
		t.Errorf("expected code 'unauthorized', got %q", resp.Code)
	}
	if resp.Message != "Authentication required for session management." {
		t.Errorf("expected session-management message, got %q", resp.Message)
	}
	if w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("expected WWW-Authenticate: Bearer, got %q", w.Header().Get("WWW-Authenticate"))
	}
}

// ========================
// credential.not_found (token not admin, not valid credential)
// ========================

func TestAuthAuditCredentialNotFound_CreateSession(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	const token = "dht_wrong_admin_token_xyz"
	const authHeader = "Bearer " + token
	const headerMarker = "hdr_admin_wrong_secret_a3b7c"
	const bodyMarker = "body_admin_wrong_secret_d5e9f"

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(`{"workspace":"`+bodyMarker+`"}`)))
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-Test-Secret", headerMarker)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/sessions", "credential.not_found", token, "", authHeader, headerMarker, bodyMarker)
}

// ========================
// credential.revoked (valid credential, then revoked)
// ========================

func TestAuthAuditPrincipalCredentialRevoked_CreateSession(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "auditrevoked")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "2001", "2001", home, nil
	}

	if _, err := createPrincipal(app.DB, "auditrevoked", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	cred, token, err := createCredential(app.DB, "auditrevoked", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	if _, err := revokeCredential(app.DB, cred.ID); err != nil {
		t.Fatalf("revokeCredential() error: %v", err)
	}

	authHeader := "Bearer " + token
	const headerMarker = "hdr_principal_revoked_secret_h1x2"
	const bodyMarker = "body_principal_revoked_secret_d9p5"

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(`{"workspace":"`+bodyMarker+`"}`)))
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-Test-Secret", headerMarker)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/sessions", "credential.revoked", token, "", authHeader, headerMarker, bodyMarker)
}

// ========================
// principal.disabled (active credential, owning Principal disabled)
// ========================

func TestAuthAuditPrincipalDisabled_CreateSession(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "auditdisabled")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "2002", "2002", home, nil
	}

	if _, err := createPrincipal(app.DB, "auditdisabled", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	_, token, err := createCredential(app.DB, "auditdisabled", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	if _, err := persistPrincipalEnabledChange(app.DB, "auditdisabled", false); err != nil {
		t.Fatalf("persistPrincipalEnabledChange() error: %v", err)
	}

	authHeader := "Bearer " + token
	const headerMarker = "hdr_principal_disabled_secret_k7y3"
	const bodyMarker = "body_principal_disabled_secret_z1q8"

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(`{"workspace":"`+bodyMarker+`"}`)))
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-Test-Secret", headerMarker)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/sessions", "principal.disabled", token, "", authHeader, headerMarker, bodyMarker)

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("expected WWW-Authenticate: Bearer, got %q", w.Header().Get("WWW-Authenticate"))
	}
	if resp.Code != "unauthorized" {
		t.Errorf("expected code 'unauthorized', got %q", resp.Code)
	}
	if resp.Message != "Authentication required for session management." {
		t.Errorf("expected session-management message, got %q", resp.Message)
	}
}

// ========================
// session.parse_failed (session capability)
// ========================

func TestAuthAuditSessionCapabilityParseFailed_MissingHeader_Run(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	const headerMarker = "hdr_session_parse_secret_g2h6j"
	const bodyMarker = "auth_test_body_session_parse:v1"

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"`+bodyMarker+`"}`)))
	req.Header.Set("X-Test-Secret", headerMarker)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/run", "session.parse_failed", "", "", "", headerMarker, bodyMarker)
}

func TestAuthAuditSessionCapabilityParseFailed_WrongScheme_Run(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	const authHeader = "Basic dXNlcjpwYXNz"

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"alpine:latest"}`)))
	req.Header.Set("Authorization", authHeader)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/run", "session.parse_failed", "", "", authHeader, "", "")
}

func TestAuthAuditSessionCapabilityParseFailed_EmptyBearer_Run(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	const authHeader = "Bearer "

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"alpine:latest"}`)))
	req.Header.Set("Authorization", authHeader)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/run", "session.parse_failed", "", "", authHeader, "", "")
}

func TestAuthAuditSessionCapabilityParseFailed_MissingHeader_Build(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/build", "session.parse_failed", "", "", "", "", "")
}

// ========================
// session.not_found (session capability)
// ========================

func TestAuthAuditSessionCapabilityNotFound_UnknownToken(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	const token = "dht_unknown_token_abc123"
	const authHeader = "Bearer " + token
	const headerMarker = "hdr_session_nfound_secret_k4l8n"
	const bodyMarker = "auth_test_body_session_nfound:v1"

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"`+bodyMarker+`"}`)))
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-Test-Secret", headerMarker)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/run", "session.not_found", token, "", authHeader, headerMarker, bodyMarker)
}

// ========================
// session.database_error (session capability)
// ========================

func TestAuthAuditSessionCapabilityDatabaseError_Run(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	// Create a real session so the token is known.
	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Replace DB with one that fails QueryContext.
	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailQueryDB(t, dbPath, errMockQueryFail)
	defer app.DB.Close()

	authHeader := "Bearer " + result.Token
	const headerMarker = "hdr_session_dberr_secret_m6n1p"
	const bodyMarker = "auth_test_body_session_dberr:v1"

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"`+bodyMarker+`"}`)))
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-Test-Secret", headerMarker)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/run", "session.database_error", result.Token, "mock_query_injection_error_for_testing", authHeader, headerMarker, bodyMarker)
}

// ========================
// Successful auth — no auth.failure
// ========================

func TestAuthAuditNoFailureOnValidAdminAuth_CreateSession(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	reqBody := map[string]string{"workspace": testWorkspaceDir(t, app.Config.AllowedRoots[0])}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	withAdminToken(req)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	assertNoAuthFailure(t, auditBuf)
}
func TestAuthAuditNoFailureOnValidSessionCapabilityAuth_Run(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"alpine:latest"}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	assertNoAuthFailure(t, auditBuf)
}

// ========================
// Health — no auth, no auth.failure
// ========================

func TestAuthAuditHealthNoAuthFailure(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	app.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	assertNoAuthFailure(t, auditBuf)
}

// ========================
// Admin token hash must not leak
// ========================

func TestAuthAuditAdminHashNotLeaked(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	adminHash := sha256.Sum256([]byte(testAdminToken))
	hashHex := strings.ToLower(fmt.Sprintf("%x", adminHash[:]))

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer dht_wrong_token")
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	raw := auditBuf.String()
	if strings.Contains(raw, hashHex) {
		t.Error("audit output contains admin token hash")
	}
}

// ========================
// Raw JSON structure — comprehensive
// ========================
// ========================
// No internal error text leaks
// ========================
