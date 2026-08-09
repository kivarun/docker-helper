package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// --- injected error for DB failure ---

var errMockQueryFail = errors.New("mock_query_injection_error_for_testing")

// --- failQueryDriver: wraps sqlite3 and fails QueryContext ---

type failQueryDriver struct {
	fail error
}

func (d *failQueryDriver) Open(dsn string) (driver.Conn, error) {
	realConn, db, err := openRealSQLiteConn(dsn)
	if err != nil {
		return nil, err
	}
	return &failQueryConn{Conn: realConn, fail: d.fail, db: db}, nil
}

type failQueryConn struct {
	driver.Conn
	fail error
	db   *sql.DB
}

func (c *failQueryConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if c.fail != nil {
		return nil, c.fail
	}
	if queryer, ok := c.Conn.(driver.QueryerContext); ok {
		return queryer.QueryContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

func (c *failQueryConn) Close() error {
	c.db.Close()
	return c.Conn.Close()
}

func newFailQueryDB(t *testing.T, dbPath string, failErr error) *sql.DB {
	t.Helper()
	name := nextMockDriverName("fq")
	sql.Register(name, &failQueryDriver{fail: failErr})

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
// admin.parse_failed
// ========================

func TestAuthAuditAdminParseFailed_MissingHeader(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

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
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/sessions", "admin.parse_failed", "", "", "", headerMarker, bodyMarker)
}

func TestAuthAuditAdminParseFailed_WrongScheme(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

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
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/sessions", "admin.parse_failed", "", "", authHeader, "", "")
}

func TestAuthAuditAdminParseFailed_EmptyBearer(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

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
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/sessions", "admin.parse_failed", "", "", authHeader, "", "")
}

// ========================
// admin.wrong_token
// ========================

func TestAuthAuditAdminWrongToken_CreateSession(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

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
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/sessions", "admin.wrong_token", token, "", authHeader, headerMarker, bodyMarker)
}

func TestAuthAuditAdminWrongToken_ListSessions(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	const token = "dht_wrong_admin_token_abc"
	const authHeader = "Bearer " + token

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	req.Header.Set("Authorization", authHeader)
	w := httptest.NewRecorder()
	app.handleListSessions(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodGet, "/sessions", "admin.wrong_token", token, "", authHeader, "", "")
}

func TestAuthAuditAdminWrongToken_DeleteSession(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	const token = "dht_wrong_admin_token_del"
	const authHeader = "Bearer " + token

	req := httptest.NewRequest(http.MethodDelete, "/sessions/dhs_123", nil)
	req.Header.Set("Authorization", authHeader)
	w := httptest.NewRecorder()
	app.handleDeleteSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodDelete, "/sessions/dhs_123", "admin.wrong_token", token, "", authHeader, "", "")
}

// ========================
// session.parse_failed
// ========================

func TestAuthAuditSessionParseFailed_MissingHeader_Run(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

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

func TestAuthAuditSessionParseFailed_WrongScheme_Run(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

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

func TestAuthAuditSessionParseFailed_EmptyBearer_Run(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

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

func TestAuthAuditSessionParseFailed_MissingHeader_Build(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

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
// session.not_found
// ========================

func TestAuthAuditSessionNotFound_UnknownToken(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

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

func TestAuthAuditSessionNotFound_ExpiredSession(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	_, err = app.DB.Exec("UPDATE sessions SET expires_at = ? WHERE id = ?",
		time.Now().Add(-time.Hour).Unix(), result.Session.ID)
	if err != nil {
		t.Fatalf("expire session: %v", err)
	}

	authHeader := "Bearer " + result.Token

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
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/run", "session.not_found", result.Token, "", authHeader, "", "")
}

func TestAuthAuditSessionNotFound_DeletedSession(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	_, err = app.DB.Exec("DELETE FROM sessions WHERE id = ?", result.Session.ID)
	if err != nil {
		t.Fatalf("delete session: %v", err)
	}

	authHeader := "Bearer " + result.Token

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
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/run", "session.not_found", result.Token, "", authHeader, "", "")
}

func TestAuthAuditSessionNotFound_AdminTokenOnRun(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	const authHeader = "Bearer " + testAdminToken

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
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/run", "session.not_found", testAdminToken, "", authHeader, "", "")
}

func TestAuthAuditSessionNotFound_UnknownToken_Build(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	const token = "dht_unknown_build_token"
	const authHeader = "Bearer " + token

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", authHeader)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/build", "session.not_found", token, "", authHeader, "", "")
}

// ========================
// session.database_error
// ========================

func TestAuthAuditSessionDatabaseError_Run(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	// Create a real session so the token is known.
	result, err := app.createSession(app.Config.AllowedRoot)
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

func TestAuthAuditSessionDatabaseError_Build(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailQueryDB(t, dbPath, errMockQueryFail)
	defer app.DB.Close()

	authHeader := "Bearer " + result.Token

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", authHeader)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected 1 auth.failure line, got %d", len(lines))
	}
	validateAuthFailureRaw(t, lines[0], http.MethodPost, "/build", "session.database_error", result.Token, "mock_query_injection_error_for_testing", authHeader, "", "")
}

// ========================
// Successful auth — no auth.failure
// ========================

func TestAuthAuditNoFailureOnValidAdminAuth_CreateSession(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"workspace": app.Config.AllowedRoot}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	assertNoAuthFailure(t, auditBuf)
}

func TestAuthAuditNoFailureOnValidAdminAuth_ListSessions(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleListSessions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	assertNoAuthFailure(t, auditBuf)
}

func TestAuthAuditNoFailureOnValidAdminAuth_DeleteSession(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/sessions/"+result.Session.ID, nil)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleDeleteSession(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}

	assertNoAuthFailure(t, auditBuf)
}

func TestAuthAuditNoFailureOnValidSessionAuth_Run(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"alpine:latest"}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	assertNoAuthFailure(t, auditBuf)
}

func TestAuthAuditNoFailureOnValidSessionAuth_Build(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Create a minimal Dockerfile in the workspace so validation passes.
	dfPath := app.Config.AllowedRoot + "/Dockerfile"
	if err := os.WriteFile(dfPath, []byte("FROM scratch"), 0644); err != nil {
		t.Fatalf("cannot write Dockerfile: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("ok"), nil
	}

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader([]byte(
		`{"context":".","dockerfile":"Dockerfile","image":"example:test"}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	assertNoAuthFailure(t, auditBuf)
}

// ========================
// Health — no auth, no auth.failure
// ========================

func TestAuthAuditHealthNoAuthFailure(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

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
	app := newTestAppWithAuth(t)

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

func TestAuthAuditRawJSONStructure_Complete(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"alpine:latest"}`)))
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	raw := strings.TrimSpace(auditBuf.String())

	// Must be valid JSON
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("not valid JSON: %v\nraw: %s", err, raw)
	}

	// Must have time
	if m["time"] == "" {
		t.Error("expected time field to be set")
	}

	// session_id must be completely absent
	if _, exists := m["session_id"]; exists {
		t.Error("session_id key must not be present in auth.failure audit record")
	}

	// Must NOT have token/authorization keys in any case
	for _, key := range []string{"token", "Token", "TOKEN", "authorization", "Authorization", "AUTHORIZATION"} {
		if _, exists := m[key]; exists {
			t.Errorf("unexpected key %q in audit record", key)
		}
	}

	// Must NOT contain the actual Authorization header value
	if strings.Contains(raw, "Bearer") && strings.Contains(raw, "dht_") {
		t.Error("audit output contains Bearer token")
	}
}

// ========================
// No internal error text leaks
// ========================

func TestAuthAuditNoInternalErrorText_UnknownToken(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"alpine:latest"}`)))
	req.Header.Set("Authorization", "Bearer dht_nonexistent")
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	raw := auditBuf.String()

	for _, text := range []string{
		"session not found",
		"ErrSessionNotFound",
		"cannot find session",
		"sql.ErrNoRows",
	} {
		if strings.Contains(raw, text) {
			t.Errorf("audit output contains internal error text %q", text)
		}
	}
}

func TestAuthAuditNoInternalErrorText_DatabaseError(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailQueryDB(t, dbPath, errMockQueryFail)
	defer app.DB.Close()

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"alpine:latest"}`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	raw := auditBuf.String()

	for _, text := range []string{
		"mock_query_injection_error_for_testing",
		"session not found",
		"ErrSessionNotFound",
		"cannot find session",
		"sql.ErrNoRows",
	} {
		if strings.Contains(raw, text) {
			t.Errorf("audit output contains internal error text %q", text)
		}
	}
}
