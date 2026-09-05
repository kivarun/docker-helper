package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// dropTableBreakFK drops the named table even though other tables hold FKs to
// it, by disabling SQLite FK enforcement on a dedicated connection. This
// corrupts the query that would JOIN it, so the affected DB operation fails
// with a real SQL error (suitable for proving errors are not masked), while
// leaving other tables intact.
func dropTableBreakFK(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("cannot get connection: %v", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=off`); err != nil {
		t.Fatalf("cannot disable foreign keys: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `DROP TABLE `+table); err != nil {
		t.Fatalf("cannot drop %s table: %v", table, err)
	}
}

// TestListSessionsDBFailureIs500 proves an owner-scope query failure propagates
// as 500. It drops the launchers table (the ownership JOIN source) after a real
// session is created; a scoped list/delete must not turn that into an empty
// result or a 404.
func TestListSessionsDBFailureIs500(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	if _, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0])); err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dropTableBreakFK(t, app.DB, "launchers")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /sessions", app.handleListSessions)

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	withAdminToken(req)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("list with broken DB: status %d, want 500; body %s", w.Code, w.Body.String())
	}
}

// TestPrincipalListSessionsDBFailureIs500 proves a Principal-scoped list DB
// failure is not masked into an empty success. The scope is expressed directly
// in the ownership query; a broken JOIN must surface as 500.
func TestPrincipalListSessionsDBFailureIs500(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "listdbfail")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "2071", "2071", home, nil
	}

	p, err := createPrincipal(app.DB, "listdbfail", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p.ID))
	_, token, err := createPrincipalCredential(app.DB, "listdbfail", "oc")
	if err != nil {
		t.Fatalf("createPrincipalCredential() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)
	mux.HandleFunc("GET /sessions", app.handleListSessions)

	// Create a session within this Principal's scope so a list has a row.
	body, _ := json.Marshal(map[string]string{"workspace": filepath.Join(home, "proj")})
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: status %d, want 201; body %s", w.Code, w.Body.String())
	}

	dropTableBreakFK(t, app.DB, "launchers")

	req = httptest.NewRequest(http.MethodGet, "/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("principal-scoped list with broken DB: status %d, want 500; body %s", w.Code, w.Body.String())
	}
}

// TestPrincipalDeleteSessionsDBFailureIs500 proves a Principal-scoped delete DB
// failure is not masked into a misleading 404.
func TestPrincipalDeleteSessionsDBFailureIs500(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "deldbfail")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "2072", "2072", home, nil
	}

	p, err := createPrincipal(app.DB, "deldbfail", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p.ID))
	_, token, err := createPrincipalCredential(app.DB, "deldbfail", "oc")
	if err != nil {
		t.Fatalf("createPrincipalCredential() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)
	mux.HandleFunc("DELETE /sessions/{id}", withRequestID(withLogging(app.handleDeleteSession)))

	body, _ := json.Marshal(map[string]string{"workspace": filepath.Join(home, "proj")})
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: status %d, want 201; body %s", w.Code, w.Body.String())
	}
	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode create response: %v", err)
	}

	dropTableBreakFK(t, app.DB, "launchers")

	req = httptest.NewRequest(http.MethodDelete, "/sessions/"+resp.Session.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("principal-scoped delete with broken DB: status %d, want 500; body %s", w.Code, w.Body.String())
	}
}

// TestCreateSelectorMissingPrincipalIs404 proves a genuinely absent selected
// Principal (admin + principal selector) still maps to the non-disclosing
// contract not-found, not an internal error.
func TestCreateSelectorMissingPrincipalIs404(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0])

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	body, _ := json.Marshal(map[string]string{"workspace": ws, "principal": "no_such_principal"})
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	withAdminToken(req)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound || !bytes.Contains(w.Body.Bytes(), []byte("launcher_not_found")) {
		t.Fatalf("missing principal selector: status %d body %s, want 404 launcher_not_found", w.Code, w.Body.String())
	}
}

// TestCreateSelectorPrincipalLookupDBFailureIs500 proves a database/system
// failure while resolving the admin principal selector is not masked into a
// non-disclosing 404: it must surface as 500.
func TestCreateSelectorPrincipalLookupDBFailureIs500(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0])

	dropTableBreakFK(t, app.DB, "principals")

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	body, _ := json.Marshal(map[string]string{"workspace": ws, "principal": "someprincipal"})
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	withAdminToken(req)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("principal lookup DB failure: status %d body %s, want 500", w.Code, w.Body.String())
	}
}
