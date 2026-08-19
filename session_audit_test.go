package main

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// --- injected error markers ---

var errMockCreateDB = errors.New("mock_create_db_error")
var errMockDeleteDB = errors.New("mock_delete_db_error")

// --- DB wrapper for controlled error injection ---

// failDriver wraps the real sqlite3 driver and optionally fails ExecContext
// and/or QueryContext with given errors.
type failDriver struct {
	failExec  error // non-nil → ExecContext returns this error
	failQuery error // non-nil → QueryContext returns this error
}

func (d *failDriver) Open(dsn string) (driver.Conn, error) {
	realConn, db, err := openRealSQLiteConn(dsn)
	if err != nil {
		return nil, err
	}
	return &failConn{Conn: realConn, failExec: d.failExec, failQuery: d.failQuery, db: db}, nil
}

// failConn wraps a real sqlite3 connection; ExecContext and/or QueryContext
// may fail depending on the driver configuration.
type failConn struct {
	driver.Conn
	failExec  error
	failQuery error
	db        *sql.DB // kept open so the underlying conn stays valid
}

func (c *failConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if c.failExec != nil {
		return nil, c.failExec
	}
	if execer, ok := c.Conn.(driver.ExecerContext); ok {
		return execer.ExecContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

func (c *failConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if c.failQuery != nil {
		return nil, c.failQuery
	}
	if queryer, ok := c.Conn.(driver.QueryerContext); ok {
		return queryer.QueryContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

func (c *failConn) Close() error {
	c.db.Close()
	return c.Conn.Close()
}

// --- shared mock driver plumbing ---

var mockDriverMu sync.Mutex
var mockDriverSeq int64

func nextMockDriverName(prefix string) string {
	mockDriverMu.Lock()
	mockDriverSeq++
	seq := mockDriverSeq
	mockDriverMu.Unlock()
	return fmt.Sprintf("mock_sqlite_%s_%d", prefix, seq)
}

// openRealSQLiteConn opens the real sqlite3 database, pins a connection,
// and extracts the underlying driver.Conn. The returned *sql.DB must be
// kept alive for the lifetime of the driver.Conn.
func openRealSQLiteConn(dsn string) (driver.Conn, *sql.DB, error) {
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, nil, err
	}
	sqlConn, err := db.Conn(context.Background())
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	var realConn driver.Conn
	err = sqlConn.Raw(func(v any) error {
		realConn = v.(driver.Conn)
		return nil
	})
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	return realConn, db, nil
}

// newFailExecDB opens the same SQLite file with a driver that fails Exec.
func newFailExecDB(t *testing.T, dbPath string, failErr error) *sql.DB {
	t.Helper()
	name := nextMockDriverName("fe")
	sql.Register(name, &failDriver{failExec: failErr})

	db, err := sql.Open(name, dbPath)
	if err != nil {
		t.Fatalf("newFailExecDB: cannot open: %v", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatalf("newFailExecDB: ping failed: %v", err)
	}
	return db
}

// --- audit helpers ---

// findAuditLine returns the first raw audit JSON line whose event matches.
func findAuditLine(buf *bytes.Buffer, event string) string {
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if m["event"] == event {
			return line
		}
	}
	return ""
}

// parseAuditMap unmarshals raw audit JSON; fails the test on error.
func parseAuditMap(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("cannot parse audit JSON: %v: %s", err, raw)
	}
	return m
}

// auditHasSecretKey returns true when the map contains a key whose
// lower-case form is "token" or "authorization".
func auditHasSecretKey(m map[string]any) bool {
	for k := range m {
		lk := strings.ToLower(k)
		if lk == "token" || lk == "authorization" {
			return true
		}
	}
	return false
}

// assertNoSecrets verifies that raw audit JSON does not leak tokens or
// Authorization header values, and does not carry secret keys.
func assertNoSecrets(t *testing.T, raw string, m map[string]any, token, adminToken string) {
	t.Helper()
	if auditHasSecretKey(m) {
		t.Error("audit has secret key (token/authorization)")
	}
	if token != "" && strings.Contains(raw, token) {
		t.Error("audit contains session token")
	}
	if adminToken != "" && strings.Contains(raw, adminToken) {
		t.Error("audit contains admin token")
	}
	if strings.Contains(raw, "Authorization") {
		t.Error("audit contains Authorization")
	}
}

// assertNoInjectedError checks that the raw audit JSON does not contain
// the injected error text (full string, not just the result field).
func assertNoInjectedError(t *testing.T, raw string, injected string) {
	t.Helper()
	if injected == "" {
		return
	}
	if strings.Contains(raw, injected) {
		t.Errorf("audit leaks injected error text %q in raw JSON", injected)
	}
}

// --- session.create handler tests ---

func TestSessionCreateAuditSuccess(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	workspace := testWorkspaceDir(t, app.Config.AllowedRoot)
	reqBody := map[string]string{"workspace": workspace}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != 201 {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	rawLines := auditRawLinesBySession(auditBuf, resp.Session.ID)
	if len(rawLines) != 1 {
		t.Fatalf("expected 1 audit line, got %d", len(rawLines))
	}
	raw := rawLines[0]
	m := parseAuditMap(t, raw)

	if m["event"] != "session.create" {
		t.Errorf("event: expected 'session.create', got %v", m["event"])
	}
	if m["result"] != "success" {
		t.Errorf("result: expected 'success', got %v", m["result"])
	}
	if m["session_id"] != resp.Session.ID {
		t.Errorf("session_id: expected %q, got %v", resp.Session.ID, m["session_id"])
	}
	if m["workspace"] != workspace {
		t.Errorf("workspace: expected %q, got %v", workspace, m["workspace"])
	}
	if _, ok := m["duration"]; !ok {
		t.Error("expected duration in audit record")
	}

	assertNoSecrets(t, raw, m, resp.Token, testAdminToken)
}

func TestSessionCreateAuditInvalidJSON(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte("not-json")))
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	raw := findAuditLine(auditBuf, "session.create")
	if raw == "" {
		t.Fatalf("expected session.create audit line, got none\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)

	if m["result"] != "invalid_json" {
		t.Errorf("result: expected 'invalid_json', got %v", m["result"])
	}
	if _, ok := m["duration"]; !ok {
		t.Error("expected duration in audit record")
	}

	assertNoSecrets(t, raw, m, "", testAdminToken)
}

func TestSessionCreateAuditInvalidWorkspace(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"workspace": "/tmp/outside-workspace"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	raw := findAuditLine(auditBuf, "session.create")
	if raw == "" {
		t.Fatalf("expected session.create audit line, got none\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)

	if m["result"] != "invalid_workspace" {
		t.Errorf("result: expected 'invalid_workspace', got %v", m["result"])
	}
	if _, ok := m["duration"]; !ok {
		t.Error("expected duration in audit record")
	}

	assertNoSecrets(t, raw, m, "", testAdminToken)
}

// TestSessionCreateAuditDatabaseError uses a failExec driver so INSERT
// returns a known error. The error text must not appear in audit JSON.
func TestSessionCreateAuditDatabaseError(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	// Controlled injection: replace DB with one that fails Exec.
	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailExecDB(t, dbPath, errMockCreateDB)
	defer app.DB.Close()

	reqBody := map[string]string{"workspace": testWorkspaceDir(t, app.Config.AllowedRoot)}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != 500 {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	raw := findAuditLine(auditBuf, "session.create")
	if raw == "" {
		t.Fatalf("expected session.create audit line, got none\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)

	if m["result"] != "database_error" {
		t.Errorf("result: expected 'database_error', got %v", m["result"])
	}
	if _, ok := m["duration"]; !ok {
		t.Error("expected duration in audit record")
	}

	assertNoSecrets(t, raw, m, "", testAdminToken)
	assertNoInjectedError(t, raw, "mock_create_db_error")
}

// TestSessionCreateAuditSystemError uses a broken symlink for AllowedRoot
// so that EvalSymlinks fails with system_error.
func TestSessionCreateAuditSystemError(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	// Valid workspace that passes steps 1-5.
	validWorkspace := t.TempDir()

	// Broken symlink for AllowedRoot — EvalSymlinks fails at step 6.
	brokenDir := t.TempDir()
	brokenLink := filepath.Join(brokenDir, "broken")
	if err := os.Symlink("/nonexistent-path-xyz-12345", brokenLink); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	app.Config.AllowedRoot = brokenLink

	reqBody := map[string]string{"workspace": validWorkspace}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != 500 {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	raw := findAuditLine(auditBuf, "session.create")
	if raw == "" {
		t.Fatalf("expected session.create audit line, got none\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)

	if m["result"] != "system_error" {
		t.Errorf("result: expected 'system_error', got %v", m["result"])
	}
	if _, ok := m["duration"]; !ok {
		t.Error("expected duration in audit record")
	}

	assertNoSecrets(t, raw, m, "", testAdminToken)
	assertNoInjectedError(t, raw, "/nonexistent-path-xyz-12345")
}

// --- session.delete handler tests ---

func TestSessionDeleteAuditSuccess(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	workspace := testWorkspaceDir(t, app.Config.AllowedRoot)
	result, err := app.createSession(workspace)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /sessions/{id}", withRequestID(withLogging(app.handleDeleteSession)))

	req := httptest.NewRequest(http.MethodDelete, "/sessions/"+result.Session.ID, nil)
	withAuth(req)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 204 {
		t.Fatalf("expected 204, got %d", w.Code)
	}

	rawLines := auditRawLinesBySession(auditBuf, result.Session.ID)
	if len(rawLines) != 1 {
		t.Fatalf("expected 1 audit line, got %d", len(rawLines))
	}
	raw := rawLines[0]
	m := parseAuditMap(t, raw)

	if m["event"] != "session.delete" {
		t.Errorf("event: expected 'session.delete', got %v", m["event"])
	}
	if m["result"] != "success" {
		t.Errorf("result: expected 'success', got %v", m["result"])
	}
	if m["session_id"] != result.Session.ID {
		t.Errorf("session_id: expected %q, got %v", result.Session.ID, m["session_id"])
	}
	if m["workspace"] != workspace {
		t.Errorf("workspace: expected %q, got %v", workspace, m["workspace"])
	}
	if _, ok := m["duration"]; !ok {
		t.Error("expected duration in audit record")
	}

	assertNoSecrets(t, raw, m, result.Token, testAdminToken)
}

func TestSessionDeleteAuditNotFound(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /sessions/{id}", withRequestID(withLogging(app.handleDeleteSession)))

	req := httptest.NewRequest(http.MethodDelete, "/sessions/dhs_nonexistent", nil)
	withAuth(req)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}

	rawLines := auditRawLinesBySession(auditBuf, "dhs_nonexistent")
	if len(rawLines) != 1 {
		t.Fatalf("expected 1 audit line, got %d", len(rawLines))
	}
	raw := rawLines[0]
	m := parseAuditMap(t, raw)

	if m["event"] != "session.delete" {
		t.Errorf("event: expected 'session.delete', got %v", m["event"])
	}
	if m["result"] != "not_found" {
		t.Errorf("result: expected 'not_found', got %v", m["result"])
	}
	if _, ok := m["duration"]; !ok {
		t.Error("expected duration in audit record")
	}

	assertNoSecrets(t, raw, m, "", testAdminToken)
}

// TestSessionDeleteAuditDatabaseError uses a failExec driver so that
// SELECT succeeds (Query is not intercepted) but DELETE fails with a
// known error. The workspace must be preserved in the audit.
func TestSessionDeleteAuditDatabaseError(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	workspace := testWorkspaceDir(t, app.Config.AllowedRoot)
	result, err := app.createSession(workspace)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	// Controlled injection: replace DB with one that fails Exec.
	// SELECT uses Query (passes through), DELETE uses Exec (fails).
	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailExecDB(t, dbPath, errMockDeleteDB)
	defer app.DB.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /sessions/{id}", withRequestID(withLogging(app.handleDeleteSession)))

	req := httptest.NewRequest(http.MethodDelete, "/sessions/"+result.Session.ID, nil)
	withAuth(req)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 500 {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	raw := findAuditLine(auditBuf, "session.delete")
	if raw == "" {
		t.Fatalf("expected session.delete audit line, got none\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)

	if m["result"] != "database_error" {
		t.Errorf("result: expected 'database_error', got %v", m["result"])
	}
	// workspace must be present because SELECT succeeded.
	if m["workspace"] != workspace {
		t.Errorf("workspace: expected %q, got %v", workspace, m["workspace"])
	}
	if _, ok := m["duration"]; !ok {
		t.Error("expected duration in audit record")
	}

	assertNoSecrets(t, raw, m, result.Token, testAdminToken)
	assertNoInjectedError(t, raw, "mock_delete_db_error")
}
