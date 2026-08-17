package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestCreatePrincipalDefaultRootCanonicalized(t *testing.T) {
	app := newTestApp(t)

	realHome := filepath.Join(app.Config.AllowedRoot, "home", "canonuser")
	if err := os.MkdirAll(realHome, 0755); err != nil {
		t.Fatal(err)
	}
	symlinkHome := filepath.Join(app.Config.AllowedRoot, "home-link")
	if err := os.Symlink(realHome, symlinkHome); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1050", "1050", symlinkHome, nil
	}

	result, err := createPrincipal(app.DB, "canonuser")
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	if len(result.AllowedRoots) != 1 {
		t.Fatalf("expected 1 allowed root, got %d", len(result.AllowedRoots))
	}
	if result.AllowedRoots[0] != realHome {
		t.Errorf("default allowed root = %q, want canonical %q", result.AllowedRoots[0], realHome)
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

	changed, _, err := addAllowedRoot(app.DB, "duprootuser", home)
	if err != nil {
		t.Fatalf("addAllowedRoot() error: %v", err)
	}
	if changed {
		t.Error("expected changed to be false (idempotent)")
	}
}

func TestAddAllowedRootTildeRejected(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "tildeuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1010", "1010", home, nil
	}

	if _, err := createPrincipal(app.DB, "tildeuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	_, _, err := addAllowedRoot(app.DB, "tildeuser", "~/some/path")
	if err == nil {
		t.Fatal("expected error for tilde path")
	}
	if !isErrInvalidAllowedRoot(err) {
		t.Errorf("expected ErrInvalidAllowedRoot, got: %v", err)
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

	if _, _, err := addAllowedRoot(app.DB, "remuser", extraRoot); err != nil {
		t.Fatalf("addAllowedRoot() error: %v", err)
	}

	changed, _, err := removeAllowedRoot(app.DB, "remuser", extraRoot)
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

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1011", "1011", home, nil
	}

	if _, err := createPrincipal(app.DB, "absuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	nonRoot := filepath.Join(app.Config.AllowedRoot, "never-added")
	changed, _, err := removeAllowedRoot(app.DB, "absuser", nonRoot)
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

	reqBody := map[string]string{"username": "authuser"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/principals", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handleCreatePrincipal(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/principals/authuser", nil)
	w = httptest.NewRecorder()

	app.handleShowPrincipal(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPrincipalCaseSensitive(t *testing.T) {
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

	// Different case should NOT find the principal (case-sensitive).
	_, err := findPrincipalByUserName(app.DB, "CASEUSER")
	if err == nil {
		t.Fatal("expected error for different case username")
	}
	if !isErrPrincipalNotFound(err) {
		t.Errorf("expected ErrPrincipalNotFound, got: %v", err)
	}

	// Different case should be allowed as separate principal (if OS user exists).
	home2 := filepath.Join(app.Config.AllowedRoot, "home", "CASEUSER")
	if err := os.MkdirAll(home2, 0755); err != nil {
		t.Fatal(err)
	}
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		if username == "CASEUSER" {
			return "1025", "1025", home2, nil
		}
		return "1024", "1024", home, nil
	}

	result, err := createPrincipal(app.DB, "CASEUSER")
	if err != nil {
		t.Fatalf("createPrincipal('CASEUSER') error: %v", err)
	}
	if result.Username != "CASEUSER" {
		t.Errorf("username = %q, want %q", result.Username, "CASEUSER")
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

func TestPrincipalHTTPAddAllowedRootRelativeRejected(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "relhttpuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1040", "1040", home, nil
	}

	if _, err := createPrincipal(app.DB, "relhttpuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/allowed-roots", app.handleAddAllowedRoot)

	reqBody, _ := json.Marshal(allowedRootRequest{Path: "relative/path"})

	req := httptest.NewRequest(http.MethodPost, "/principals/relhttpuser/allowed-roots", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPrincipalHTTPRemoveAllowedRootDeletedDir(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "delhttpuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	extraRoot := filepath.Join(app.Config.AllowedRoot, "extra-del-http")
	if err := os.MkdirAll(extraRoot, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1041", "1041", home, nil
	}

	if _, err := createPrincipal(app.DB, "delhttpuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	if _, _, err := addAllowedRoot(app.DB, "delhttpuser", extraRoot); err != nil {
		t.Fatalf("addAllowedRoot() error: %v", err)
	}

	// Delete directory from filesystem
	if err := os.RemoveAll(extraRoot); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /principals/{username}/allowed-roots", app.handleRemoveAllowedRoot)

	reqBody, _ := json.Marshal(allowedRootRequest{Path: extraRoot})

	req := httptest.NewRequest(http.MethodDelete, "/principals/delhttpuser/allowed-roots", bytes.NewReader(reqBody))
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

func TestPrincipalHTTPAddAllowedRootNonexistent(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "nonexistuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1042", "1042", home, nil
	}

	if _, err := createPrincipal(app.DB, "nonexistuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/allowed-roots", app.handleAddAllowedRoot)

	reqBody, _ := json.Marshal(allowedRootRequest{Path: "/no/such/path/that/exists"})

	req := httptest.NewRequest(http.MethodPost, "/principals/nonexistuser/allowed-roots", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp map[string]json.RawMessage
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	var code string
	if err := json.Unmarshal(resp["code"], &code); err != nil {
		t.Fatalf("cannot decode code: %v", err)
	}
	if code != "invalid_allowed_root" {
		t.Errorf("expected code 'invalid_allowed_root', got %q", resp["code"])
	}
}

func TestPrincipalHTTPAddAllowedRootIsFile(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "fileuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	regFile := filepath.Join(app.Config.AllowedRoot, "a-file")
	if err := os.WriteFile(regFile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1043", "1043", home, nil
	}

	if _, err := createPrincipal(app.DB, "fileuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /principals/{username}/allowed-roots", app.handleAddAllowedRoot)

	reqBody, _ := json.Marshal(allowedRootRequest{Path: regFile})

	req := httptest.NewRequest(http.MethodPost, "/principals/fileuser/allowed-roots", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp map[string]json.RawMessage
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	var code string
	if err := json.Unmarshal(resp["code"], &code); err != nil {
		t.Fatalf("cannot decode code: %v", err)
	}
	if code != "invalid_allowed_root" {
		t.Errorf("expected code 'invalid_allowed_root', got %q", resp["code"])
	}
}

func TestPrincipalHTTPRemoveAllowedRootRelativeRejected(t *testing.T) {
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "relremuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1044", "1044", home, nil
	}

	if _, err := createPrincipal(app.DB, "relremuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /principals/{username}/allowed-roots", app.handleRemoveAllowedRoot)

	reqBody, _ := json.Marshal(allowedRootRequest{Path: "relative/path"})

	req := httptest.NewRequest(http.MethodDelete, "/principals/relremuser/allowed-roots", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp map[string]json.RawMessage
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	var code string
	if err := json.Unmarshal(resp["code"], &code); err != nil {
		t.Fatalf("cannot decode code: %v", err)
	}
	if code != "invalid_allowed_root" {
		t.Errorf("expected code 'invalid_allowed_root', got %q", resp["code"])
	}
}

func TestCreatePrincipalRelativeHomeRejected(t *testing.T) {
	app := newTestApp(t)

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1050", "1050", "relative/home", nil
	}

	_, err := createPrincipal(app.DB, "relhomeuser")
	if err == nil {
		t.Fatal("expected error for relative home")
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
		{"allowed_roots", `["/home/testuser","/shared"]`, true},
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

func TestPrincipalAuditEnabledChange(t *testing.T) {
	enabled := true
	rec := auditRecord{
		Event:            "principal.enabled_change",
		PrincipalName:    "testuser",
		PrincipalEnabled: &enabled,
		Result:           "success",
	}

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("cannot marshal auditRecord: %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("cannot unmarshal auditRecord: %v", err)
	}

	var enabledVal bool
	if err := json.Unmarshal(decoded["principal_enabled"], &enabledVal); err != nil {
		t.Fatalf("cannot decode principal_enabled: %v", err)
	}
	if !enabledVal {
		t.Error("expected principal_enabled to be true")
	}
}

func TestPrincipalAuditPath(t *testing.T) {
	rec := auditRecord{
		Event:         "principal.allowed_root_add",
		PrincipalName: "testuser",
		PrincipalPath: "/shared",
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

	if decoded["principal_path"] != "/shared" {
		t.Errorf("principal_path = %q, want %q", decoded["principal_path"], "/shared")
	}
}

func TestPrincipalCLISetEnabledOnlyTrueFalse(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"principal", "set", "user", "enabled", "1"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 for '1', got %d", code)
	}
	if !strings.Contains(stderr.String(), "must be true or false") {
		t.Errorf("expected 'must be true or false' error, got: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"principal", "set", "user", "enabled", "yes"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 for 'yes', got %d", code)
	}
}

func TestPrincipalErrorWrapping(t *testing.T) {
	app := newTestApp(t)

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

	_, _, err = addAllowedRoot(app.DB, "", "/tmp")
	if err == nil {
		t.Fatal("expected error for empty username in addAllowedRoot")
	}

	_, _, err = addAllowedRoot(app.DB, "user", "")
	if err == nil {
		t.Fatal("expected error for empty path in addAllowedRoot")
	}

	_, _, err = removeAllowedRoot(app.DB, "", "/tmp")
	if err == nil {
		t.Fatal("expected error for empty username in removeAllowedRoot")
	}

	_, _, err = removeAllowedRoot(app.DB, "user", "")
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

	if result.AllowedRoots == nil {
		t.Error("AllowedRoots should not be nil")
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

	if _, _, err := addAllowedRoot(app.DB, "cascadeuser", extraRoot); err != nil {
		t.Fatalf("addAllowedRoot() error: %v", err)
	}

	// Delete the principal directly to test cascade
	_, err := app.DB.Exec("DELETE FROM principals WHERE username = ?", "cascadeuser")
	if err != nil {
		t.Fatalf("DELETE FROM principals error: %v", err)
	}

	// Verify allowed roots were cascade-deleted
	var count int
	err = app.DB.QueryRow("SELECT COUNT(*) FROM principal_allowed_roots").Scan(&count)
	if err != nil {
		t.Fatalf("cannot query allowed roots: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 allowed roots after cascade delete, got %d", count)
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

	changed, _, err := addAllowedRoot(app.DB, "pathresuser", extraRoot+"/")
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

func TestListPrincipalSummaries(t *testing.T) {
	app := newTestApp(t)

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		switch username {
		case "alice":
			return "1001", "1001", filepath.Join(app.Config.AllowedRoot, "home", "alice"), nil
		case "bob":
			return "1002", "1002", filepath.Join(app.Config.AllowedRoot, "home", "bob"), nil
		default:
			return "", "", "", os.ErrNotExist
		}
	}

	for _, user := range []string{"alice", "bob"} {
		home := filepath.Join(app.Config.AllowedRoot, "home", user)
		if err := os.MkdirAll(home, 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := createPrincipal(app.DB, user); err != nil {
			t.Fatalf("createPrincipal(%q) error: %v", user, err)
		}
	}

	summaries, err := listPrincipalSummaries(app.DB)
	if err != nil {
		t.Fatalf("listPrincipalSummaries() error: %v", err)
	}
	if len(summaries) != 2 {
		t.Fatalf("expected 2 principals, got %d", len(summaries))
	}

	// Verify sorted by username
	if summaries[0].Username != "alice" {
		t.Errorf("first principal = %q, want %q", summaries[0].Username, "alice")
	}
	if summaries[1].Username != "bob" {
		t.Errorf("second principal = %q, want %q", summaries[1].Username, "bob")
	}

	// Summary fields carry the stored identity
	wantAlice := principalSummary{
		Username: "alice",
		UID:      1001,
		GID:      1001,
		Home:     filepath.Join(app.Config.AllowedRoot, "home", "alice"),
		Enabled:  true,
	}
	if summaries[0] != wantAlice {
		t.Errorf("alice summary = %+v, want %+v", summaries[0], wantAlice)
	}
}

func TestPrincipalHTTPList(t *testing.T) {
	app := newTestAppWithAuth(t)

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		switch username {
		case "carol":
			return "1003", "1003", filepath.Join(app.Config.AllowedRoot, "home", "carol"), nil
		default:
			return "", "", "", os.ErrNotExist
		}
	}

	home := filepath.Join(app.Config.AllowedRoot, "home", "carol")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := createPrincipal(app.DB, "carol"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/principals", nil)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleListPrincipals(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if strings.Contains(body, "allowed_roots") {
		t.Errorf("list response must not include allowed_roots: %s", body)
	}

	var resp listPrincipalsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if !resp.OK {
		t.Error("expected ok=true")
	}
	if len(resp.Principals) != 1 {
		t.Fatalf("expected 1 principal, got %d", len(resp.Principals))
	}
	want := principalSummary{
		Username: "carol",
		UID:      1003,
		GID:      1003,
		Home:     home,
		Enabled:  true,
	}
	if resp.Principals[0] != want {
		t.Errorf("summary = %+v, want %+v", resp.Principals[0], want)
	}
}

func TestPrincipalHTTPListEmpty(t *testing.T) {
	app := newTestAppWithAuth(t)

	req := httptest.NewRequest("GET", "/principals", nil)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleListPrincipals(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"ok":true,"principals":[]}` {
		t.Errorf("empty list body = %q, want %q", got, `{"ok":true,"principals":[]}`)
	}
}

func TestPrincipalHTTPListDisabledIncluded(t *testing.T) {
	app := newTestAppWithAuth(t)

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		switch username {
		case "dave":
			return "1004", "1004", filepath.Join(app.Config.AllowedRoot, "home", "dave"), nil
		default:
			return "", "", "", os.ErrNotExist
		}
	}

	home := filepath.Join(app.Config.AllowedRoot, "home", "dave")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := createPrincipal(app.DB, "dave"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	if _, err := updatePrincipalEnabled(app.DB, "dave", false); err != nil {
		t.Fatalf("updatePrincipalEnabled() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/principals", nil)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleListPrincipals(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp listPrincipalsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if len(resp.Principals) != 1 {
		t.Fatalf("expected 1 principal, got %d", len(resp.Principals))
	}
	if resp.Principals[0].Username != "dave" {
		t.Fatalf("username = %q, want dave", resp.Principals[0].Username)
	}
	if resp.Principals[0].Enabled {
		t.Error("disabled principal must be listed with enabled=false")
	}
}

func TestPrincipalListAuth(t *testing.T) {
	app := newTestAppWithAuth(t)

	// Session token (legacy admin session).
	sessionResult, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}
	sessionToken := sessionResult.Token

	// Launcher credential token (principal-scoped).
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		if username == "launchuser" {
			return "1005", "1005", filepath.Join(app.Config.AllowedRoot, "home", "launchuser"), nil
		}
		return "", "", "", os.ErrNotExist
	}
	home := filepath.Join(app.Config.AllowedRoot, "home", "launchuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := createPrincipal(app.DB, "launchuser"); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	_, credentialToken, err := createCredential(app.DB, "launchuser", "oc")
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
		{name: "launcher_credential", token: credentialToken, wantCode: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/principals", nil)
			if !tt.noAuth {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			w := httptest.NewRecorder()
			app.handleListPrincipals(w, req)
			if w.Code != tt.wantCode {
				t.Errorf("expected %d, got %d: %s", tt.wantCode, w.Code, w.Body.String())
			}
		})
	}
}
