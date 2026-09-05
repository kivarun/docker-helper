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
	validateAuthFailureRaw(t, lines[0], authFailureExpectation{Method: http.MethodPost, Path: "/sessions", Result: "parse_failed", HeaderMarker: headerMarker, BodyMarker: bodyMarker})
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
	validateAuthFailureRaw(t, lines[0], authFailureExpectation{Method: http.MethodPost, Path: "/sessions", Result: "parse_failed", AuthHeader: authHeader})
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
	validateAuthFailureRaw(t, lines[0], authFailureExpectation{Method: http.MethodPost, Path: "/sessions", Result: "parse_failed", AuthHeader: authHeader})
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
	validateAuthFailureRaw(t, lines[0], authFailureExpectation{Method: http.MethodPost, Path: "/sessions", Result: "credential.not_found", InjectedToken: token, AuthHeader: authHeader, HeaderMarker: headerMarker, BodyMarker: bodyMarker})
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

	cred, token, err := createPrincipalCredential(app.DB, "auditrevoked", "oc")
	if err != nil {
		t.Fatalf("createPrincipalCredential() error: %v", err)
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
	validateAuthFailureRaw(t, lines[0], authFailureExpectation{Method: http.MethodPost, Path: "/sessions", Result: "credential.revoked", InjectedToken: token, AuthHeader: authHeader, HeaderMarker: headerMarker, BodyMarker: bodyMarker})
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

	_, token, err := createPrincipalCredential(app.DB, "auditdisabled", "oc")
	if err != nil {
		t.Fatalf("createPrincipalCredential() error: %v", err)
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
	validateAuthFailureRaw(t, lines[0], authFailureExpectation{Method: http.MethodPost, Path: "/sessions", Result: "principal.disabled", InjectedToken: token, AuthHeader: authHeader, HeaderMarker: headerMarker, BodyMarker: bodyMarker})

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
// credential.database_error (session control)
// ========================

func TestAuthAuditSessionControlCredentialDatabaseError_CreateSession(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminTokenAndStaging(t)

	// Replace DB with one that fails QueryContext so the Principal-credential
	// lookup returns a database error instead of not_found/revoked/disabled.
	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailQueryDB(t, dbPath, errMockQueryFail)
	defer app.DB.Close()

	// A non-admin bearer value reaches the Principal-credential lookup.
	const token = "dht_unknown_credential_token_q2w4"
	const authHeader = "Bearer " + token
	const headerMarker = "hdr_cred_dberr_secret_r5t7"
	const bodyMarker = "auth_test_body_cred_dberr:v1"

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(`{"workspace":"`+bodyMarker+`"}`)))
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-Test-Secret", headerMarker)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], authFailureExpectation{Method: http.MethodPost, Path: "/sessions", Result: "credential.database_error", InjectedToken: token, InjectedErr: "mock_query_injection_error_for_testing", AuthHeader: authHeader, HeaderMarker: headerMarker, BodyMarker: bodyMarker})

	if raw := findAuditLine(auditBuf, "auth.session"); raw != "" {
		t.Errorf("legacy auth.session audit event must not be emitted, got: %s", raw)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if resp.Code != "internal_error" {
		t.Errorf("expected code 'internal_error', got %q", resp.Code)
	}
	if resp.Message != "internal server error" {
		t.Errorf("expected message 'internal server error', got %q", resp.Message)
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
	validateAuthFailureRaw(t, lines[0], authFailureExpectation{Method: http.MethodPost, Path: "/run", Result: "session.parse_failed", HeaderMarker: headerMarker, BodyMarker: bodyMarker})
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
	validateAuthFailureRaw(t, lines[0], authFailureExpectation{Method: http.MethodPost, Path: "/run", Result: "session.parse_failed", AuthHeader: authHeader})
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
	validateAuthFailureRaw(t, lines[0], authFailureExpectation{Method: http.MethodPost, Path: "/run", Result: "session.parse_failed", AuthHeader: authHeader})
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
	validateAuthFailureRaw(t, lines[0], authFailureExpectation{Method: http.MethodPost, Path: "/build", Result: "session.parse_failed"})
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
	validateAuthFailureRaw(t, lines[0], authFailureExpectation{Method: http.MethodPost, Path: "/run", Result: "session.not_found", InjectedToken: token, AuthHeader: authHeader, HeaderMarker: headerMarker, BodyMarker: bodyMarker})
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
	validateAuthFailureRaw(t, lines[0], authFailureExpectation{Method: http.MethodPost, Path: "/run", Result: "session.database_error", InjectedToken: result.Token, InjectedErr: "mock_query_injection_error_for_testing", AuthHeader: authHeader, HeaderMarker: headerMarker, BodyMarker: bodyMarker})
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
