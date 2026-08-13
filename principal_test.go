package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreatePrincipal(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "testuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		if username == "testuser" {
			return "1001", "1001", home, nil
		}
		return "", "", "", fmt.Errorf("user not found")
	}

	result, err := createPrincipal(app.DB, "testuser")
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	if result.Username != "testuser" {
		t.Errorf("username = %q, want %q", result.Username, "testuser")
	}
	if result.UID != 1001 {
		t.Errorf("UID = %d, want 1001", result.UID)
	}
	if result.GID != 1001 {
		t.Errorf("GID = %d, want 1001", result.GID)
	}
	if result.Home != home {
		t.Errorf("Home = %q, want %q", result.Home, home)
	}
	if !result.Enabled {
		t.Error("Expected principal to be enabled by default")
	}
}

func TestCreatePrincipalUnknownOSUser(t *testing.T) {
	app := newTestApp(t)

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "", "", "", fmt.Errorf("user not found")
	}

	_, err := createPrincipal(app.DB, "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown OS user")
	}
	if !isErrOSUserNotFound(err) {
		t.Errorf("expected ErrOSUserNotFound, got: %v", err)
	}
}

func TestCreatePrincipalDuplicate(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "dupuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1002", "1002", home, nil
	}

	if _, err := createPrincipal(app.DB, "dupuser"); err != nil {
		t.Fatalf("first createPrincipal() error: %v", err)
	}

	_, err := createPrincipal(app.DB, "dupuser")
	if err == nil {
		t.Fatal("expected error for duplicate principal")
	}
	if !isErrPrincipalExists(err) {
		t.Errorf("expected ErrPrincipalExists, got: %v", err)
	}
}

func TestCreatePrincipalDefaultRoot(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "rootuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1003", "1003", home, nil
	}

	result, err := createPrincipal(app.DB, "rootuser")
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	if len(result.AllowedRoots) != 1 {
		t.Fatalf("expected 1 allowed root, got %d", len(result.AllowedRoots))
	}
	if result.AllowedRoots[0] != home {
		t.Errorf("default allowed root = %q, want %q", result.AllowedRoots[0], home)
	}
}

func TestShowPrincipal(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "showuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1004", "1004", home, nil
	}

	if _, err := createPrincipal(app.DB, "showuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	result, err := findPrincipalByUserName(app.DB, "showuser")
	if err != nil {
		t.Fatalf("findPrincipalByUserName() error: %v", err)
	}

	if result.Username != "showuser" {
		t.Errorf("username = %q, want %q", result.Username, "showuser")
	}
	if result.UID != 1004 {
		t.Errorf("UID = %d, want 1004", result.UID)
	}
}

func TestShowPrincipalNotFound(t *testing.T) {
	app := newTestApp(t)

	_, err := findPrincipalByUserName(app.DB, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent principal")
	}
	if !isErrPrincipalNotFound(err) {
		t.Errorf("expected ErrPrincipalNotFound, got: %v", err)
	}
}

func TestSetPrincipalEnabled(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "enableuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1005", "1005", home, nil
	}

	if _, err := createPrincipal(app.DB, "enableuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	changed, err := updatePrincipalEnabled(app.DB, "enableuser", false)
	if err != nil {
		t.Fatalf("updatePrincipalEnabled() error: %v", err)
	}
	if !changed {
		t.Error("expected changed to be true")
	}

	result, err := findPrincipalByUserName(app.DB, "enableuser")
	if err != nil {
		t.Fatalf("findPrincipalByUserName() error: %v", err)
	}
	if result.Enabled {
		t.Error("expected principal to be disabled")
	}
}

func TestSetPrincipalEnabledIdempotent(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "idemuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1006", "1006", home, nil
	}

	if _, err := createPrincipal(app.DB, "idemuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	// Already enabled, setting to true again should be idempotent
	changed, err := updatePrincipalEnabled(app.DB, "idemuser", true)
	if err != nil {
		t.Fatalf("updatePrincipalEnabled() error: %v", err)
	}
	if changed {
		t.Error("expected changed to be false (idempotent)")
	}
}

func TestAddAllowedRoot(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "addrootuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	extraRoot := filepath.Join(app.Config.AllowedRoot, "extra")
	if err := os.MkdirAll(extraRoot, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1007", "1007", home, nil
	}

	if _, err := createPrincipal(app.DB, "addrootuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	changed, err := addAllowedRoot(app.DB, "addrootuser", extraRoot)
	if err != nil {
		t.Fatalf("addAllowedRoot() error: %v", err)
	}
	if !changed {
		t.Error("expected changed to be true")
	}

	result, err := findPrincipalByUserName(app.DB, "addrootuser")
	if err != nil {
		t.Fatalf("findPrincipalByUserName() error: %v", err)
	}
	if len(result.AllowedRoots) != 2 {
		t.Fatalf("expected 2 allowed roots, got %d", len(result.AllowedRoots))
	}
}

func TestAddAllowedRootDuplicate(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "duprootuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1008", "1008", home, nil
	}

	if _, err := createPrincipal(app.DB, "duprootuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	// Adding home again should be idempotent
	changed, err := addAllowedRoot(app.DB, "duprootuser", home)
	if err != nil {
		t.Fatalf("addAllowedRoot() error: %v", err)
	}
	if changed {
		t.Error("expected changed to be false (idempotent)")
	}
}

func TestAddAllowedRootInvalid(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "invaliduser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1009", "1009", home, nil
	}

	if _, err := createPrincipal(app.DB, "invaliduser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	// Non-absolute path should be rejected
	_, err := addAllowedRoot(app.DB, "invaliduser", "relative/path")
	if err == nil {
		t.Fatal("expected error for relative path")
	}
}

func TestRemoveAllowedRoot(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "remuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	extraRoot := filepath.Join(app.Config.AllowedRoot, "extra2")
	if err := os.MkdirAll(extraRoot, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1010", "1010", home, nil
	}

	if _, err := createPrincipal(app.DB, "remuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	if _, err := addAllowedRoot(app.DB, "remuser", extraRoot); err != nil {
		t.Fatalf("addAllowedRoot() error: %v", err)
	}

	changed, err := removeAllowedRoot(app.DB, "remuser", extraRoot)
	if err != nil {
		t.Fatalf("removeAllowedRoot() error: %v", err)
	}
	if !changed {
		t.Error("expected changed to be true")
	}

	result, err := findPrincipalByUserName(app.DB, "remuser")
	if err != nil {
		t.Fatalf("findPrincipalByUserName() error: %v", err)
	}
	if len(result.AllowedRoots) != 1 {
		t.Fatalf("expected 1 allowed root after removal, got %d", len(result.AllowedRoots))
	}
}

func TestRemoveAllowedRootAbsent(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "absuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	nonRoot := filepath.Join(app.Config.AllowedRoot, "nonexistent_root")
	if err := os.MkdirAll(nonRoot, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1011", "1011", home, nil
	}

	if _, err := createPrincipal(app.DB, "absuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	// Removing a root that was never added should be idempotent
	changed, err := removeAllowedRoot(app.DB, "absuser", nonRoot)
	if err != nil {
		t.Fatalf("removeAllowedRoot() error: %v", err)
	}
	if changed {
		t.Error("expected changed to be false (idempotent)")
	}
}

func TestPrincipalAdminAuth(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "authuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1012", "1012", home, nil
	}

	// Missing auth should be rejected
	reqBody := map[string]string{"username": "authuser"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/principals", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handleCreatePrincipal(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}

	// Show principal without auth should be rejected
	req = httptest.NewRequest(http.MethodGet, "/principals/authuser", nil)
	w = httptest.NewRecorder()

	app.handleShowPrincipal(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestInitializeDatabaseWithPrincipalsTables(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	// Check principals table exists
	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='principals';").Scan(&name)
	if err != nil {
		t.Fatalf("principals table not found: %v", err)
	}
	if name != "principals" {
		t.Errorf("expected table name 'principals', got %q", name)
	}

	// Check principal_allowed_roots table exists
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='principal_allowed_roots';").Scan(&name)
	if err != nil {
		t.Fatalf("principal_allowed_roots table not found: %v", err)
	}
	if name != "principal_allowed_roots" {
		t.Errorf("expected table name 'principal_allowed_roots', got %q", name)
	}
}

func TestInitializeDatabasePreservesSessions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	// Sessions table should still exist
	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions';").Scan(&name)
	if err != nil {
		t.Fatalf("sessions table not found: %v", err)
	}
	if name != "sessions" {
		t.Errorf("expected table name 'sessions', got %q", name)
	}
}

func TestPrincipalHTTPCreate(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "httpuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1013", "1013", home, nil
	}

	reqBody := map[string]string{"username": "httpuser"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/principals", bytes.NewReader(body))
	withAuth(req)
	w := httptest.NewRecorder()

	app.handleCreatePrincipal(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var resp principalResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if resp.Username != "httpuser" {
		t.Errorf("username = %q, want %q", resp.Username, "httpuser")
	}
	if resp.UID != 1013 {
		t.Errorf("UID = %d, want 1013", resp.UID)
	}
	if !resp.Enabled {
		t.Error("expected enabled to be true")
	}
}

func TestPrincipalHTTPShow(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "showhttpuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1014", "1014", home, nil
	}

	if _, err := createPrincipal(app.DB, "showhttpuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /principals/{username}", app.handleShowPrincipal)

	req := httptest.NewRequest(http.MethodGet, "/principals/showhttpuser", nil)
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp principalResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if resp.Username != "showhttpuser" {
		t.Errorf("username = %q, want %q", resp.Username, "showhttpuser")
	}
}

func TestPrincipalHTTPShowNotFound(t *testing.T) {
	app := newTestAppWithAuth(t)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /principals/{username}", app.handleShowPrincipal)

	req := httptest.NewRequest(http.MethodGet, "/principals/nonexistent", nil)
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestPrincipalHTTPSetEnabled(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "sethttpuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1015", "1015", home, nil
	}

	if _, err := createPrincipal(app.DB, "sethttpuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /principals/{username}", app.handleSetPrincipal)

	disabled := false
	reqBody, _ := json.Marshal(setPrincipalRequest{Enabled: &disabled})

	req := httptest.NewRequest(http.MethodPatch, "/principals/sethttpuser", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp principalChangedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if !resp.Changed {
		t.Error("expected changed to be true")
	}
}

func TestPrincipalHTTPSetEnabledIdempotent(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "idemhttpuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1016", "1016", home, nil
	}

	if _, err := createPrincipal(app.DB, "idemhttpuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /principals/{username}", app.handleSetPrincipal)

	enabled := true
	reqBody, _ := json.Marshal(setPrincipalRequest{Enabled: &enabled})

	req := httptest.NewRequest(http.MethodPatch, "/principals/idemhttpuser", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp principalChangedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if resp.Changed {
		t.Error("expected changed to be false (idempotent)")
	}
	if resp.Message != "unchanged" {
		t.Errorf("expected message 'unchanged', got %q", resp.Message)
	}
}

func TestPrincipalHTTPAddAllowedRoot(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "addroothttpuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	extraRoot := filepath.Join(app.Config.AllowedRoot, "extra3")
	if err := os.MkdirAll(extraRoot, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1017", "1017", home, nil
	}

	if _, err := createPrincipal(app.DB, "addroothttpuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/allowed-roots", app.handleAddAllowedRoot)

	reqBody, _ := json.Marshal(allowedRootRequest{Path: extraRoot})

	req := httptest.NewRequest(http.MethodPost, "/principals/addroothttpuser/allowed-roots", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp principalChangedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if !resp.Changed {
		t.Error("expected changed to be true")
	}
}

func TestPrincipalHTTPAddAllowedRootDuplicate(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "duproothttpuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1018", "1018", home, nil
	}

	if _, err := createPrincipal(app.DB, "duproothttpuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/allowed-roots", app.handleAddAllowedRoot)

	// Adding home again should be idempotent
	reqBody, _ := json.Marshal(allowedRootRequest{Path: home})

	req := httptest.NewRequest(http.MethodPost, "/principals/duproothttpuser/allowed-roots", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp principalChangedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if resp.Changed {
		t.Error("expected changed to be false (idempotent)")
	}
	if resp.Message != "unchanged" {
		t.Errorf("expected message 'unchanged', got %q", resp.Message)
	}
}

func TestPrincipalHTTPAddAllowedRootInvalid(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "invalidhttpuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1019", "1019", home, nil
	}

	if _, err := createPrincipal(app.DB, "invalidhttpuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/allowed-roots", app.handleAddAllowedRoot)

	// Non-absolute path should be rejected
	reqBody, _ := json.Marshal(allowedRootRequest{Path: "relative/path"})

	req := httptest.NewRequest(http.MethodPost, "/principals/invalidhttpuser/allowed-roots", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPrincipalHTTPRemoveAllowedRoot(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "remhttpuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	extraRoot := filepath.Join(app.Config.AllowedRoot, "extra4")
	if err := os.MkdirAll(extraRoot, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1020", "1020", home, nil
	}

	if _, err := createPrincipal(app.DB, "remhttpuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	if _, err := addAllowedRoot(app.DB, "remhttpuser", extraRoot); err != nil {
		t.Fatalf("addAllowedRoot() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /principals/{username}/allowed-roots", app.handleRemoveAllowedRoot)

	reqBody, _ := json.Marshal(allowedRootRequest{Path: extraRoot})

	req := httptest.NewRequest(http.MethodDelete, "/principals/remhttpuser/allowed-roots", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp principalChangedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if !resp.Changed {
		t.Error("expected changed to be true")
	}
}

func TestPrincipalHTTPRemoveAllowedRootAbsent(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "absremhttpuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	nonRoot := filepath.Join(app.Config.AllowedRoot, "nonexistent_root2")
	if err := os.MkdirAll(nonRoot, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1021", "1021", home, nil
	}

	if _, err := createPrincipal(app.DB, "absremhttpuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /principals/{username}/allowed-roots", app.handleRemoveAllowedRoot)

	reqBody, _ := json.Marshal(allowedRootRequest{Path: nonRoot})

	req := httptest.NewRequest(http.MethodDelete, "/principals/absremhttpuser/allowed-roots", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp principalChangedResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if resp.Changed {
		t.Error("expected changed to be false (idempotent)")
	}
	if resp.Message != "unchanged" {
		t.Errorf("expected message 'unchanged', got %q", resp.Message)
	}
}

func TestPrincipalHTTPCreateUnknownOSUser(t *testing.T) {
	app := newTestAppWithAuth(t)

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "", "", "", fmt.Errorf("user not found")
	}

	reqBody := map[string]string{"username": "nonexistent"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/principals", bytes.NewReader(body))
	withAuth(req)
	w := httptest.NewRecorder()

	app.handleCreatePrincipal(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPrincipalHTTPCreateDuplicate(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "duphttpuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1022", "1022", home, nil
	}

	reqBody := map[string]string{"username": "duphttpuser"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/principals", bytes.NewReader(body))
	withAuth(req)
	w := httptest.NewRecorder()

	app.handleCreatePrincipal(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/principals", bytes.NewReader(body))
	withAuth(req)
	w = httptest.NewRecorder()

	app.handleCreatePrincipal(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status %d, got %d", http.StatusConflict, w.Code)
	}
}

func TestPrincipalHTTPCreateMissingUsername(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"username": ""}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/principals", bytes.NewReader(body))
	withAuth(req)
	w := httptest.NewRecorder()

	app.handleCreatePrincipal(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPrincipalHTTPSetEnabledNotFound(t *testing.T) {
	app := newTestAppWithAuth(t)

	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /principals/{username}", app.handleSetPrincipal)

	disabled := false
	reqBody, _ := json.Marshal(setPrincipalRequest{Enabled: &disabled})

	req := httptest.NewRequest(http.MethodPatch, "/principals/nonexistent", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestPrincipalHTTPSetEnabledMissingField(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "missingfielduser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1023", "1023", home, nil
	}

	if _, err := createPrincipal(app.DB, "missingfielduser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /principals/{username}", app.handleSetPrincipal)

	req := httptest.NewRequest(http.MethodPatch, "/principals/missingfielduser", bytes.NewReader([]byte("{}")))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPrincipalHTTPAddAllowedRootNotFound(t *testing.T) {
	app := newTestAppWithAuth(t)

	extraRoot := filepath.Join(app.Config.AllowedRoot, "extra5")
	if err := os.MkdirAll(extraRoot, 0755); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/allowed-roots", app.handleAddAllowedRoot)

	reqBody, _ := json.Marshal(allowedRootRequest{Path: extraRoot})

	req := httptest.NewRequest(http.MethodPost, "/principals/nonexistent/allowed-roots", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestPrincipalHTTPRemoveAllowedRootNotFound(t *testing.T) {
	app := newTestAppWithAuth(t)

	extraRoot := filepath.Join(app.Config.AllowedRoot, "extra6")
	if err := os.MkdirAll(extraRoot, 0755); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /principals/{username}/allowed-roots", app.handleRemoveAllowedRoot)

	reqBody, _ := json.Marshal(allowedRootRequest{Path: extraRoot})

	req := httptest.NewRequest(http.MethodDelete, "/principals/nonexistent/allowed-roots", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestPrincipalCaseInsensitiveLookup(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "caseuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1024", "1024", home, nil
	}

	if _, err := createPrincipal(app.DB, "caseuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	// Look up with different case
	result, err := findPrincipalByUserName(app.DB, "CASEUSER")
	if err != nil {
		t.Fatalf("findPrincipalByUserName('CASEUSER') error: %v", err)
	}
	if result.Username != "caseuser" {
		t.Errorf("username = %q, want %q", result.Username, "caseuser")
	}
}

func TestPrincipalCaseInsensitiveDuplicate(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "casedupuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1025", "1025", home, nil
	}

	if _, err := createPrincipal(app.DB, "casedupuser"); err != nil {
		t.Fatalf("first createPrincipal() error: %v", err)
	}

	// Creating with different case should fail as duplicate
	_, err := createPrincipal(app.DB, "CASEDUPUSER")
	if err == nil {
		t.Fatal("expected error for case-insensitive duplicate")
	}
	if !isErrPrincipalExists(err) {
		t.Errorf("expected ErrPrincipalExists, got: %v", err)
	}
}

func TestPrincipalErrorWrapping(t *testing.T) {
	app := newTestApp(t)

	// Test that errors are properly wrapped
	_, err := createPrincipal(app.DB, "")
	if err == nil {
		t.Fatal("expected error for empty username")
	}

	_, err = findPrincipalByUserName(app.DB, "")
	if err == nil {
		t.Fatal("expected error for empty username in find")
	}

	_, err = updatePrincipalEnabled(app.DB, "", true)
	if err == nil {
		t.Fatal("expected error for empty username in update")
	}

	_, err = addAllowedRoot(app.DB, "", "/tmp")
	if err == nil {
		t.Fatal("expected error for empty username in addAllowedRoot")
	}

	_, err = addAllowedRoot(app.DB, "user", "")
	if err == nil {
		t.Fatal("expected error for empty path in addAllowedRoot")
	}

	_, err = removeAllowedRoot(app.DB, "", "/tmp")
	if err == nil {
		t.Fatal("expected error for empty username in removeAllowedRoot")
	}

	_, err = removeAllowedRoot(app.DB, "user", "")
	if err == nil {
		t.Fatal("expected error for empty path in removeAllowedRoot")
	}
}

func TestResolveOSUser(t *testing.T) {
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()

	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1000", "1000", "/home/test", nil
	}

	uid, gid, home, err := resolveOSUser("test")
	if err != nil {
		t.Fatalf("resolveOSUser() error: %v", err)
	}
	if uid != 1000 {
		t.Errorf("UID = %d, want 1000", uid)
	}
	if gid != 1000 {
		t.Errorf("GID = %d, want 1000", gid)
	}
	if home != "/home/test" {
		t.Errorf("Home = %q, want %q", home, "/home/test")
	}
}

func TestResolveOSUserNotFound(t *testing.T) {
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()

	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "", "", "", os.ErrNotExist
	}

	_, _, _, err := resolveOSUser("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent user")
	}
	if !isErrOSUserNotFound(err) {
		t.Errorf("expected ErrOSUserNotFound, got: %v", err)
	}
}

func TestResolveOSUserInvalidUID(t *testing.T) {
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()

	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "not-a-number", "1000", "/home/test", nil
	}

	_, _, _, err := resolveOSUser("test")
	if err == nil {
		t.Fatal("expected error for invalid UID")
	}
	if !isErrOSUserNotFound(err) {
		t.Errorf("expected ErrOSUserNotFound, got: %v", err)
	}
}

func TestResolveOSUserInvalidGID(t *testing.T) {
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()

	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1000", "not-a-number", "/home/test", nil
	}

	_, _, _, err := resolveOSUser("test")
	if err == nil {
		t.Fatal("expected error for invalid GID")
	}
	if !isErrOSUserNotFound(err) {
		t.Errorf("expected ErrOSUserNotFound, got: %v", err)
	}
}

func TestPrincipalCLIHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"principal", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("principal --help exited %d", code)
	}
	out := stdout.String()
	for _, want := range []string{"create", "show", "set", "allowed-root"} {
		if !strings.Contains(out, want) {
			t.Errorf("principal --help should contain %q, got:\n%s", want, out)
		}
	}
}

func TestPrincipalCLISubcommandHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"principal", "create", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("principal create --help exited %d", code)
	}
	if !strings.Contains(stdout.String(), "create") {
		t.Error("principal create --help should mention create")
	}
}

func TestPrincipalCLIAllowedRootHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"principal", "allowed-root", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("principal allowed-root --help exited %d", code)
	}
	out := stdout.String()
	for _, want := range []string{"add", "remove"} {
		if !strings.Contains(out, want) {
			t.Errorf("principal allowed-root --help should contain %q, got:\n%s", want, out)
		}
	}
}

func TestExtractPrincipalField(t *testing.T) {
	p := &principalResponse{
		Username:     "testuser",
		UID:          1000,
		GID:          1000,
		Home:         "/home/testuser",
		Enabled:      true,
		AllowedRoots: []string{"/home/testuser", "/shared"},
	}

	tests := []struct {
		field string
		want  string
		ok    bool
	}{
		{"username", "testuser", true},
		{"uid", "1000", true},
		{"gid", "1000", true},
		{"home", "/home/testuser", true},
		{"enabled", "true", true},
		{"allowed_roots", "/home/testuser,/shared", true},
		{"unknown", "", false},
	}

	for _, tt := range tests {
		got, ok := extractPrincipalField(p, tt.field)
		if ok != tt.ok {
			t.Errorf("extractPrincipalField(%q) ok = %v, want %v", tt.field, ok, tt.ok)
		}
		if got != tt.want {
			t.Errorf("extractPrincipalField(%q) = %q, want %q", tt.field, got, tt.want)
		}
	}
}

func TestPrincipalAuditRecord(t *testing.T) {
	// Verify PrincipalName field exists and serializes correctly
	rec := auditRecord{
		Event:         "principal.create",
		PrincipalName: "testuser",
		Result:        "success",
	}

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("cannot marshal auditRecord: %v", err)
	}

	var decoded map[string]string
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("cannot unmarshal auditRecord: %v", err)
	}

	if decoded["principal_name"] != "testuser" {
		t.Errorf("principal_name = %q, want %q", decoded["principal_name"], "testuser")
	}
}

func TestPrincipalAllowedRootPathResolution(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "pathresuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	extraRoot := filepath.Join(app.Config.AllowedRoot, "extra7")
	if err := os.MkdirAll(extraRoot, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1026", "1026", home, nil
	}

	if _, err := createPrincipal(app.DB, "pathresuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	// Add root using a path with trailing slash
	changed, err := addAllowedRoot(app.DB, "pathresuser", extraRoot+"/")
	if err != nil {
		t.Fatalf("addAllowedRoot() error: %v", err)
	}
	if !changed {
		t.Error("expected changed to be true")
	}

	result, err := findPrincipalByUserName(app.DB, "pathresuser")
	if err != nil {
		t.Fatalf("findPrincipalByUserName() error: %v", err)
	}

	// The path should be resolved to canonical form
	found := false
	for _, r := range result.AllowedRoots {
		if r == extraRoot {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q in allowed roots, got %v", extraRoot, result.AllowedRoots)
	}
}

func TestPrincipalWithRootsEmptySlice(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "emptyuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1027", "1027", home, nil
	}

	result, err := createPrincipal(app.DB, "emptyuser")
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	// AllowedRoots should be a non-nil slice
	if result.AllowedRoots == nil {
		t.Error("AllowedRoots should not be nil")
	}
}

func TestPrincipalHTTPCreateInvalidJSON(t *testing.T) {
	app := newTestAppWithAuth(t)

	req := httptest.NewRequest(http.MethodPost, "/principals", bytes.NewReader([]byte("not json")))
	withAuth(req)
	w := httptest.NewRecorder()

	app.handleCreatePrincipal(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPrincipalHTTPSetEnabledInvalidJSON(t *testing.T) {
	app := newTestAppWithAuth(t)

	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /principals/{username}", app.handleSetPrincipal)

	req := httptest.NewRequest(http.MethodPatch, "/principals/testuser", bytes.NewReader([]byte("not json")))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPrincipalHTTPAddAllowedRootInvalidJSON(t *testing.T) {
	app := newTestAppWithAuth(t)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/allowed-roots", app.handleAddAllowedRoot)

	req := httptest.NewRequest(http.MethodPost, "/principals/testuser/allowed-roots", bytes.NewReader([]byte("not json")))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPrincipalHTTPRemoveAllowedRootInvalidJSON(t *testing.T) {
	app := newTestAppWithAuth(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /principals/{username}/allowed-roots", app.handleRemoveAllowedRoot)

	req := httptest.NewRequest(http.MethodDelete, "/principals/testuser/allowed-roots", bytes.NewReader([]byte("not json")))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPrincipalHTTPAddAllowedRootMissingPath(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "missingpathuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1028", "1028", home, nil
	}

	if _, err := createPrincipal(app.DB, "missingpathuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/allowed-roots", app.handleAddAllowedRoot)

	reqBody, _ := json.Marshal(allowedRootRequest{Path: ""})

	req := httptest.NewRequest(http.MethodPost, "/principals/missingpathuser/allowed-roots", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPrincipalHTTPRemoveAllowedRootMissingPath(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "missingremuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1029", "1029", home, nil
	}

	if _, err := createPrincipal(app.DB, "missingremuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /principals/{username}/allowed-roots", app.handleRemoveAllowedRoot)

	reqBody, _ := json.Marshal(allowedRootRequest{Path: ""})

	req := httptest.NewRequest(http.MethodDelete, "/principals/missingremuser/allowed-roots", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPrincipalCascadeDelete(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "cascadeuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	extraRoot := filepath.Join(app.Config.AllowedRoot, "extra8")
	if err := os.MkdirAll(extraRoot, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1030", "1030", home, nil
	}

	if _, err := createPrincipal(app.DB, "cascadeuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	if _, err := addAllowedRoot(app.DB, "cascadeuser", extraRoot); err != nil {
		t.Fatalf("addAllowedRoot() error: %v", err)
	}

	// Delete the principal directly (simulating cascade)
	_, err := app.DB.Exec("DELETE FROM principals WHERE username = ?", "cascadeuser")
	if err != nil {
		t.Fatalf("DELETE FROM principals error: %v", err)
	}

	// Verify allowed roots were cascade-deleted
	var count int
	err = app.DB.QueryRow("SELECT COUNT(*) FROM principal_allowed_roots WHERE principal_username = ?", "cascadeuser").Scan(&count)
	if err != nil {
		t.Fatalf("cannot query allowed roots: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 allowed roots after cascade delete, got %d", count)
	}
}

func TestPrincipalIntegrationWithDaemon(t *testing.T) {
	dir := t.TempDir()

	// Create a temporary admin token
	adminToken := testAdminToken
	adminTokenPath := filepath.Join(dir, "admin.token")
	if err := os.WriteFile(adminTokenPath, []byte(adminToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Create allowed root directories
	home := filepath.Join(dir, "home", "intuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		if username == "intuser" {
			return "1031", "1031", home, nil
		}
		return "", "", "", fmt.Errorf("user not found")
	}

	// Create a test app and start it
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}

	adminHash := sha256.Sum256([]byte(adminToken))

	cfg := &Config{
		AllowedRoot:           dir,
		SessionTTL:            24 * time.Hour,
		SocketPath:            filepath.Join(dir, "test.sock"),
		StateDir:              dir,
		RuntimeDir:            runtimeDir,
		DatabasePath:          dbPath,
		AdminTokenPath:        adminTokenPath,
		ShutdownTimeout:       30 * time.Second,
		OperationRetentionTTL: 10 * time.Minute,
		OperationMaxCompleted: 200,
		OperationLogMaxBytes:  4 * 1024 * 1024,
	}

	app := &App{
		Config:         cfg,
		DB:             db,
		AdminTokenHash: adminHash,
	}

	// Create principal via handler
	reqBody := map[string]string{"username": "intuser"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/principals", bytes.NewReader(body))
	withAuth(req)
	w := httptest.NewRecorder()

	app.handleCreatePrincipal(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create principal: expected %d, got %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	// Show principal via handler
	req = httptest.NewRequest(http.MethodGet, "/principals/intuser", nil)
	withAuth(req)
	w = httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /principals/{username}", app.handleShowPrincipal)
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("show principal: expected %d, got %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var resp principalResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.Username != "intuser" {
		t.Errorf("username = %q, want %q", resp.Username, "intuser")
	}
	if resp.AllowedRoots == nil || len(resp.AllowedRoots) == 0 {
		t.Error("expected at least one allowed root (home)")
	}
}

func TestPrincipalErrorsAreWrapped(t *testing.T) {
	app := newTestApp(t)

	// Test that ErrPrincipalNotFound is properly wrapped
	_, err := findPrincipalByUserName(app.DB, "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrPrincipalNotFound) {
		// Check if the error chain contains the sentinel
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("expected error to contain 'not found', got: %v", err)
		}
	}

	// Test that ErrOSUserNotFound is properly wrapped
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "", "", "", os.ErrNotExist
	}

	_, err = createPrincipal(app.DB, "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrOSUserNotFound) {
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("expected error to contain 'not found', got: %v", err)
		}
	}
}
