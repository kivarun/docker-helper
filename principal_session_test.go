package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCredentialAuthValid(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "authuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1030", "1030", home, nil
	}

	if _, err := createPrincipal(app.DB, "authuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	cred, token, err := createCredential(app.DB, "authuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	auth, err := authenticateCredential(app.DB, token)
	if err != nil {
		t.Fatalf("authenticateCredential() error: %v", err)
	}
	if auth.Principal == nil {
		t.Fatal("expected a Principal credential auth result")
	}
	if auth.Principal.PrincipalName != "authuser" {
		t.Errorf("principal = %q, want %q", auth.Principal.PrincipalName, "authuser")
	}
	if auth.Principal.CredentialID != cred.ID {
		t.Errorf("credential ID = %q, want %q", auth.Principal.CredentialID, cred.ID)
	}
	if len(auth.Principal.PrincipalAllowedRoots) == 0 {
		t.Error("expected at least one allowed root")
	}
}

func TestCredentialAuthRandomToken(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	_, err := authenticateCredential(app.DB, "dhc_randomtoken1234567890abcdef1234567890abcdef1234567890abcdef")
	if err == nil {
		t.Fatal("expected error for random token")
	}
	if !isErrCredentialNotFound(err) {
		t.Errorf("expected ErrCredentialNotFound, got: %v", err)
	}
}

func TestCredentialAuthRevoked(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "revokeduser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1031", "1031", home, nil
	}

	if _, err := createPrincipal(app.DB, "revokeduser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	_, token, err := createCredential(app.DB, "revokeduser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	// Revoke the credential.
	creds, err := listCredentialsForScope(app.DB, principalIDPtr(t, app.DB, "revokeduser"))
	if err != nil {
		t.Fatalf("listCredentialsForScope() error: %v", err)
	}
	if _, err := revokeCredential(app.DB, creds[0].ID); err != nil {
		t.Fatalf("revokeCredential() error: %v", err)
	}

	_, err = authenticateCredential(app.DB, token)
	if err == nil {
		t.Fatal("expected error for revoked credential")
	}
	if !errors.Is(err, ErrCredentialRevoked) {
		t.Errorf("expected ErrCredentialRevoked, got: %v", err)
	}
}

func TestCredentialAuthPrincipalDisabled(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "disableduser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1032", "1032", home, nil
	}

	if _, err := createPrincipal(app.DB, "disableduser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	_, token, err := createCredential(app.DB, "disableduser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	// Disable the principal.
	if _, err := persistPrincipalEnabledChange(app.DB, "disableduser", false); err != nil {
		t.Fatalf("persistPrincipalEnabledChange() error: %v", err)
	}

	_, err = authenticateCredential(app.DB, token)
	if err == nil {
		t.Fatal("expected error for disabled principal")
	}
	if !errors.Is(err, ErrPrincipalDisabled) {
		t.Errorf("expected ErrPrincipalDisabled, got: %v", err)
	}
}

func TestCredentialAuthDBError(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	// Close the DB to simulate a DB error.
	app.DB.Close()

	_, err := authenticateCredential(app.DB, "dhc_testtoken")
	if err == nil {
		t.Fatal("expected error for DB failure")
	}
	// Should be a generic error, not credential-specific.
	if errors.Is(err, ErrCredentialNotFound) || errors.Is(err, ErrCredentialRevoked) || errors.Is(err, ErrPrincipalDisabled) {
		t.Errorf("expected generic DB error, got: %v", err)
	}
}

func TestCredentialCreatesSessionWithPrincipalID(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "sessuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1033", "1033", home, nil
	}

	p, err := createPrincipal(app.DB, "sessuser", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p.ID))

	_, token, err := createCredential(app.DB, "sessuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	// The session must be owned by the principal's default Launcher. Verify
	// the stored launcher_id points at a Launcher owned by the principal, and
	// that the JSON principal projection shows the principal's name.
	if resp.Session.LauncherID == "" {
		t.Fatal("expected session to have a launcher_id")
	}
	if resp.Session.Principal == nil {
		t.Fatal("expected principal name in session JSON")
	}
	if *resp.Session.Principal != "sessuser" {
		t.Errorf("expected principal %q, got %q", "sessuser", *resp.Session.Principal)
	}
	var ownerID int64
	err = app.DB.QueryRow(
		`SELECT l.principal_id FROM launchers l JOIN sessions s ON s.launcher_id = l.id WHERE s.id = ?`,
		resp.Session.ID,
	).Scan(&ownerID)
	if err != nil {
		t.Fatalf("cannot query owning launcher principal: %v", err)
	}
	if ownerID != int64(p.ID) {
		t.Errorf("session launcher owned by principal %d, want %d", ownerID, int64(p.ID))
	}
}

func TestAdminCreatesSessionWithNULLPrincipalID(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	reqBody := map[string]string{"workspace": testWorkspaceDir(t, app.Config.AllowedRoots[0])}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	withAdminToken(req)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	// In the Launcher-owned model there is no principal_id column and no
	// ownerless session. An admin-created session (user mode, no selector) is
	// owned by the daemon-owner default Launcher.
	if resp.Session.LauncherID != app.userModeDefault.launcherID {
		t.Errorf("admin session launcher_id = %q, want daemon-owner default %q", resp.Session.LauncherID, app.userModeDefault.launcherID)
	}

	var launcherID string
	err := app.DB.QueryRow(`SELECT launcher_id FROM sessions WHERE id = ?`, resp.Session.ID).Scan(&launcherID)
	if err != nil {
		t.Fatalf("cannot query session launcher_id: %v", err)
	}
	if launcherID != app.userModeDefault.launcherID {
		t.Errorf("stored launcher_id = %q, want %q", launcherID, app.userModeDefault.launcherID)
	}

	var colCount int
	err = app.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'principal_id'`).Scan(&colCount)
	if err != nil {
		t.Fatalf("cannot inspect sessions schema: %v", err)
	}
	if colCount != 0 {
		t.Errorf("sessions schema must not have a principal_id column, found %d", colCount)
	}
}

func TestPrincipalWorkspaceInsideFirstRoot(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "wsuser1")
	subdir := filepath.Join(home, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1034", "1034", home, nil
	}

	p, err := createPrincipal(app.DB, "wsuser1", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p.ID))

	_, token, err := createCredential(app.DB, "wsuser1", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": subdir}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}
}

func TestPrincipalWorkspaceInsideSecondRoot(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "wsuser2")
	secondRoot := filepath.Join(app.Config.AllowedRoots[0], "second")
	subdir := filepath.Join(secondRoot, "subdir")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1035", "1035", home, nil
	}

	p, err := createPrincipal(app.DB, "wsuser2", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p.ID))

	// Add second allowed root.
	if _, _, err := addPrincipalAllowedRoot(app.DB, "wsuser2", secondRoot, app.Config.AllowedRoots); err != nil {
		t.Fatalf("addPrincipalAllowedRoot() error: %v", err)
	}

	_, token, err := createCredential(app.DB, "wsuser2", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": subdir}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}
}

func TestPrincipalWorkspaceOutsideAllRootsRejected(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "wsuser3")
	outsideRoot := filepath.Join(app.Config.AllowedRoots[0], "outside")
	subdir := filepath.Join(outsideRoot, "subdir")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1036", "1036", home, nil
	}

	p, err := createPrincipal(app.DB, "wsuser3", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p.ID))

	// Do NOT add outsideRoot as allowed root.
	_, token, err := createCredential(app.DB, "wsuser3", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": subdir}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

func TestPrincipalSeesOnlyOwnSessions(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home1 := filepath.Join(app.Config.AllowedRoots[0], "home", "owner1")
	home2 := filepath.Join(app.Config.AllowedRoots[0], "home", "owner2")
	if err := os.MkdirAll(filepath.Join(home1, "proj"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home2, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		switch username {
		case "owner1":
			return "1037", "1037", home1, nil
		case "owner2":
			return "1038", "1038", home2, nil
		}
		return "", "", "", fmt.Errorf("not found")
	}

	p1, err := createPrincipal(app.DB, "owner1", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal(owner1) error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p1.ID))
	p2, err := createPrincipal(app.DB, "owner2", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal(owner2) error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p2.ID))

	_, token1, err := createCredential(app.DB, "owner1", "oc")
	if err != nil {
		t.Fatalf("createCredential(owner1) error: %v", err)
	}
	_, token2, err := createCredential(app.DB, "owner2", "oc")
	if err != nil {
		t.Fatalf("createCredential(owner2) error: %v", err)
	}

	// owner1 creates a session.
	reqBody := map[string]string{"workspace": filepath.Join(home1, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)
	mux.HandleFunc("GET /sessions", app.handleListSessions)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token1)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("owner1 create: expected %d, got %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	// owner2 creates a session.
	reqBody2 := map[string]string{"workspace": filepath.Join(home2, "proj")}
	body2, _ := json.Marshal(reqBody2)
	req = httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body2))
	req.Header.Set("Authorization", "Bearer "+token2)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("owner2 create: expected %d, got %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	// owner1 lists sessions — should see only own.
	req = httptest.NewRequest(http.MethodGet, "/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token1)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("owner1 list: expected %d, got %d", http.StatusOK, w.Code)
	}

	var resp listSessionsResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if len(resp.Sessions) != 1 {
		t.Errorf("owner1 should see 1 session, got %d", len(resp.Sessions))
	}
}

func TestPrincipalDoesNotSeeLegacySessions(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "legacyuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1039", "1039", home, nil
	}

	if _, err := createPrincipal(app.DB, "legacyuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	// Create a legacy session (principal_id = NULL) via admin.
	adminResult, err := app.createSession(home)
	if err != nil {
		t.Fatalf("admin createSession() error: %v", err)
	}
	_ = adminResult

	_, token, err := createCredential(app.DB, "legacyuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /sessions", app.handleListSessions)

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	var resp listSessionsResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if len(resp.Sessions) != 0 {
		t.Errorf("principal should see 0 sessions, got %d", len(resp.Sessions))
	}
}

func TestAdminSeesAllSessions(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "adminseesuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1040", "1040", home, nil
	}

	p, err := createPrincipal(app.DB, "adminseesuser", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p.ID))

	// Create admin session.
	adminResult, err := app.createSession(home)
	if err != nil {
		t.Fatalf("admin createSession() error: %v", err)
	}
	_ = adminResult

	// Create principal session.
	_, token, err := createCredential(app.DB, "adminseesuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)
	mux.HandleFunc("GET /sessions", app.handleListSessions)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("principal create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	// Admin lists sessions — should see all.
	req = httptest.NewRequest(http.MethodGet, "/sessions", nil)
	withAdminToken(req)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("admin list: expected %d, got %d", http.StatusOK, w.Code)
	}

	var resp listSessionsResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if len(resp.Sessions) != 2 {
		t.Errorf("admin should see 2 sessions, got %d", len(resp.Sessions))
	}
}

func TestPrincipalDeletesOwnSession(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "delownuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1041", "1041", home, nil
	}

	p, err := createPrincipal(app.DB, "delownuser", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p.ID))

	_, token, err := createCredential(app.DB, "delownuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)
	mux.HandleFunc("DELETE /sessions/{id}", withRequestID(withLogging(app.handleDeleteSession)))

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	// Delete own session.
	req = httptest.NewRequest(http.MethodDelete, "/sessions/"+resp.Session.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusNoContent, w.Code, w.Body.String())
	}
}

func TestPrincipalDeletingOtherPrincipalSessionReturns404(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home1 := filepath.Join(app.Config.AllowedRoots[0], "home", "delother1")
	home2 := filepath.Join(app.Config.AllowedRoots[0], "home", "delother2")
	if err := os.MkdirAll(filepath.Join(home1, "proj"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home2, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		switch username {
		case "delother1":
			return "1042", "1042", home1, nil
		case "delother2":
			return "1043", "1043", home2, nil
		}
		return "", "", "", fmt.Errorf("not found")
	}

	p1, err := createPrincipal(app.DB, "delother1", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal(delother1) error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p1.ID))
	p2, err := createPrincipal(app.DB, "delother2", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal(delother2) error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p2.ID))

	_, token1, err := createCredential(app.DB, "delother1", "oc")
	if err != nil {
		t.Fatalf("createCredential(delother1) error: %v", err)
	}
	_, token2, err := createCredential(app.DB, "delother2", "oc")
	if err != nil {
		t.Fatalf("createCredential(delother2) error: %v", err)
	}

	// delother2 creates a session.
	reqBody := map[string]string{"workspace": filepath.Join(home2, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)
	mux.HandleFunc("DELETE /sessions/{id}", withRequestID(withLogging(app.handleDeleteSession)))

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("delother2 create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	// delother1 tries to delete delother2's session.
	req = httptest.NewRequest(http.MethodDelete, "/sessions/"+resp.Session.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token1)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusNotFound, w.Code, w.Body.String())
	}
}

func TestPrincipalDeletingLegacySessionReturns404(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "dellegacyuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1044", "1044", home, nil
	}

	if _, err := createPrincipal(app.DB, "dellegacyuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	// Create a legacy session (principal_id = NULL) via admin.
	adminResult, err := app.createSession(home)
	if err != nil {
		t.Fatalf("admin createSession() error: %v", err)
	}

	_, token, err := createCredential(app.DB, "dellegacyuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /sessions/{id}", withRequestID(withLogging(app.handleDeleteSession)))

	// Principal tries to delete legacy session.
	req := httptest.NewRequest(http.MethodDelete, "/sessions/"+adminResult.Session.ID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusNotFound, w.Code, w.Body.String())
	}
}

func TestAdminDeletesAnySession(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "admindeluser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1045", "1045", home, nil
	}

	p, err := createPrincipal(app.DB, "admindeluser", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p.ID))

	_, token, err := createCredential(app.DB, "admindeluser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)
	mux.HandleFunc("DELETE /sessions/{id}", withRequestID(withLogging(app.handleDeleteSession)))

	// Principal creates a session.
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("principal create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	// Admin deletes principal's session.
	req = httptest.NewRequest(http.MethodDelete, "/sessions/"+resp.Session.ID, nil)
	withAdminToken(req)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d, body: %s", http.StatusNoContent, w.Code, w.Body.String())
	}
}

func TestSessionTokenSurvivesCredentialRevoke(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "surviveuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1046", "1046", home, nil
	}

	p, err := createPrincipal(app.DB, "surviveuser", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p.ID))

	cred, token, err := createCredential(app.DB, "surviveuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	sessionToken := resp.Token

	// Revoke the credential.
	if _, err := revokeCredential(app.DB, cred.ID); err != nil {
		t.Fatalf("revokeCredential() error: %v", err)
	}

	// Session token should still work.
	session, err := app.findSessionByToken(sessionToken)
	if err != nil {
		t.Fatalf("findSessionByToken() error after credential revoke: %v", err)
	}
	if session.ID != resp.Session.ID {
		t.Errorf("session ID mismatch: got %q, want %q", session.ID, resp.Session.ID)
	}
}

func TestConcurrentRevokeOnlyOneChanged(t *testing.T) {
	app := newTestApp(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "concurrentuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1048", "1048", home, nil
	}

	if _, err := createPrincipal(app.DB, "concurrentuser", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	cred, _, err := createCredential(app.DB, "concurrentuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	const goroutines = 10
	var changedCount int32
	var errs []error
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			changed, err := revokeCredential(app.DB, cred.ID)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			if changed {
				atomic.AddInt32(&changedCount, 1)
			}
		}()
	}

	wg.Wait()

	if len(errs) > 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if changedCount != 1 {
		t.Errorf("expected exactly 1 changed, got %d", changedCount)
	}
}

func TestSessionTokenInvalidatedOnPrincipalDisable(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "survivedisuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1047", "1047", home, nil
	}

	p, err := createPrincipal(app.DB, "survivedisuser", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p.ID))

	_, token, err := createCredential(app.DB, "survivedisuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	sessionToken := resp.Token

	// Disable the principal.
	if _, err := persistPrincipalEnabledChange(app.DB, "survivedisuser", false); err != nil {
		t.Fatalf("persistPrincipalEnabledChange() error: %v", err)
	}

	// Session token should be invalidated.
	_, err = app.findSessionByToken(sessionToken)
	if err == nil {
		t.Fatal("findSessionByToken() should fail after principal disable")
	}
	if !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound, got: %v", err)
	}
}

func TestR1SessionsTableUpgrade(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	// Create DB with only the old R1 sessions schema (no principal_id).
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL UNIQUE,
			workspace TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		);
	`)
	if err != nil {
		t.Fatalf("create sessions table: %v", err)
	}

	_, err = db.Exec(
		`INSERT INTO sessions (id, token_hash, workspace, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		"dhs_r1", "abc123", dir, 1000000000, 9999999999,
	)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	db.Close()

	// Reopen and run current initializeDatabase.
	db, err = openDatabase(dbPath)
	if err != nil {
		t.Fatalf("reopenDatabase() error: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	// Verify principal_id column exists.
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name='principal_id';`).Scan(&count)
	if err != nil {
		t.Fatalf("cannot check principal_id column: %v", err)
	}
	if count == 0 {
		t.Fatal("principal_id column not found after upgrade")
	}

	// Verify old session row preserved with NULL principal_id.
	var id, workspace string
	var principalID sql.NullInt64
	err = db.QueryRow(
		`SELECT id, workspace, principal_id FROM sessions WHERE id = ?`,
		"dhs_r1",
	).Scan(&id, &workspace, &principalID)
	if err != nil {
		if err == sql.ErrNoRows {
			t.Fatal("R1 session row was lost after upgrade")
		}
		t.Fatalf("query session: %v", err)
	}
	if principalID.Valid {
		t.Error("R1 session should have NULL principal_id")
	}
}

func TestSessionAuditNoTokens(t *testing.T) {
	rec := auditRecord{
		Event:         "session.create",
		PrincipalName: "testuser",
		CredentialID:  "dhcr_test",
		SessionID:     "dhs_test",
		Workspace:     "/workspace",
		Result:        "success",
	}

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("cannot marshal auditRecord: %v", err)
	}

	body := string(data)
	// Verify no token fields in audit.
	if strings.Contains(body, "token") && !strings.Contains(body, "session_token") {
		// Check specifically for credential token or session token.
		if strings.Contains(body, "dhc_") || strings.Contains(body, "dht_") {
			t.Error("audit record should not contain plaintext tokens")
		}
	}
}

func TestCredentialAuthNoAdminFailureAudit(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "noadminfail")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1060", "1060", home, nil
	}

	p, err := createPrincipal(app.DB, "noadminfail", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p.ID))

	_, token, err := createCredential(app.DB, "noadminfail", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	// Verify no admin.wrong_token in auth failures.
	lines := findAuthFailureRawLines(auditBuf)
	for _, line := range lines {
		if strings.Contains(line, "admin.wrong_token") {
			t.Errorf("credential auth should not produce admin.wrong_token: %s", line)
		}
	}
}

func TestInvalidCredentialSingleAuthFailure(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	reqBody := map[string]string{"workspace": testWorkspaceDir(t, app.Config.AllowedRoots[0])}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dhc_invalidtoken1234567890abcdef1234567890abcdef1234567890abcdef")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, w.Code)
	}

	lines := findAuthFailureRawLines(auditBuf)
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 auth.failure, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "credential.not_found") {
		t.Errorf("expected credential.not_found in auth failure: %s", lines[0])
	}
}

func TestSessionManagementGenericUnauthorizedMessage(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte("{}")))
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	msg, _ := resp["message"].(string)
	if strings.Contains(msg, "Administrative") {
		t.Errorf("session management should not mention 'Administrative': %s", msg)
	}
}

func TestCredentialCreateSessionReturnsPrincipal(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "principalresp")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1061", "1061", home, nil
	}

	p, err := createPrincipal(app.DB, "principalresp", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p.ID))

	_, token, err := createCredential(app.DB, "principalresp", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	reqBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	body, _ := json.Marshal(reqBody)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var resp createSessionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.Session.Principal == nil {
		t.Fatal("expected principal name in response")
	}
	if *resp.Session.Principal != "principalresp" {
		t.Errorf("expected principal 'principalresp', got %q", *resp.Session.Principal)
	}
}

func TestCredentialSessionListAudit(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "listaudit")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1063", "1063", home, nil
	}

	if _, err := createPrincipal(app.DB, "listaudit", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}

	cred, token, err := createCredential(app.DB, "listaudit", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /sessions", withRequestID(withLogging(app.handleListSessions)))

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	// Check audit for principal and credential ID.
	raw := auditBuf.String()
	if !strings.Contains(raw, "session.list") || !strings.Contains(raw, "success") {
		t.Error("expected session.list success in audit")
	}
	if !strings.Contains(raw, "listaudit") {
		t.Errorf("list audit should contain principal name: %s", raw)
	}
	if !strings.Contains(raw, cred.ID) {
		t.Errorf("list audit should contain credential ID: %s", raw)
	}
}

func TestGlobalPolicyNarrowing(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	broadRoot := filepath.Join(app.Config.AllowedRoots[0], "broad")
	narrowRoot := filepath.Join(broadRoot, "narrow")
	otherDir := filepath.Join(broadRoot, "other")
	if err := os.MkdirAll(filepath.Join(narrowRoot, "project"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(otherDir, "project"), 0755); err != nil {
		t.Fatal(err)
	}

	home := filepath.Join(broadRoot, "home")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1050", "1050", home, nil
	}

	p, err := createPrincipal(app.DB, "narrowuser", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p.ID))

	// Add the broad root to the principal.
	if _, _, err := addPrincipalAllowedRoot(app.DB, "narrowuser", broadRoot, app.Config.AllowedRoots); err != nil {
		t.Fatalf("addPrincipalAllowedRoot() error: %v", err)
	}

	_, token, err := createCredential(app.DB, "narrowuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	// Narrow global policy to the narrower root.
	app.setConfig(&Config{
		AllowedRoots:          []string{narrowRoot},
		SessionTTL:            app.Config.SessionTTL,
		LogLevel:              app.Config.LogLevel,
		AuditEnabled:          app.Config.AuditEnabled,
		ShutdownTimeout:       app.Config.ShutdownTimeout,
		OperationRetentionTTL: app.Config.OperationRetentionTTL,
		OperationMaxCompleted: app.Config.OperationMaxCompleted,
		OperationLogMaxBytes:  app.Config.OperationLogMaxBytes,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	// Session inside the narrow global root should succeed.
	reqBody := map[string]string{"workspace": filepath.Join(narrowRoot, "project")}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("session in narrow root: expected %d, got %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	// Session in broad root but outside narrow global should be rejected.
	reqBody = map[string]string{"workspace": filepath.Join(otherDir, "project")}
	body, _ = json.Marshal(reqBody)
	req = httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("session outside narrow global: expected %d, got %d, body: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

func TestStalePrincipalRootOutsideGlobal(t *testing.T) {
	app := newTestAppWithAdminToken(t)

	staleRoot := filepath.Join(app.Config.AllowedRoots[0], "stale")
	newGlobalRoot := filepath.Join(app.Config.AllowedRoots[0], "newglobal")
	if err := os.MkdirAll(filepath.Join(staleRoot, "project"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(newGlobalRoot, "project"), 0755); err != nil {
		t.Fatal(err)
	}

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "staleuser")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1051", "1051", home, nil
	}

	p, err := createPrincipal(app.DB, "staleuser", app.Config.AllowedRoots)
	if err != nil {
		t.Fatalf("createPrincipal() error: %v", err)
	}
	mustAddDefaultLauncher(t, app.DB, int64(p.ID))

	// Add a root that will become stale.
	if _, _, err := addPrincipalAllowedRoot(app.DB, "staleuser", staleRoot, app.Config.AllowedRoots); err != nil {
		t.Fatalf("addPrincipalAllowedRoot() error: %v", err)
	}

	_, token, err := createCredential(app.DB, "staleuser", "oc")
	if err != nil {
		t.Fatalf("createCredential() error: %v", err)
	}

	// Change global policy so staleRoot is no longer covered.
	app.setConfig(&Config{
		AllowedRoots:          []string{newGlobalRoot},
		SessionTTL:            app.Config.SessionTTL,
		LogLevel:              app.Config.LogLevel,
		AuditEnabled:          app.Config.AuditEnabled,
		ShutdownTimeout:       app.Config.ShutdownTimeout,
		OperationRetentionTTL: app.Config.OperationRetentionTTL,
		OperationMaxCompleted: app.Config.OperationMaxCompleted,
		OperationLogMaxBytes:  app.Config.OperationLogMaxBytes,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	// Session under stale principal root (outside new global) must be rejected.
	reqBody := map[string]string{"workspace": filepath.Join(staleRoot, "project")}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("stale root session: expected %d, got %d, body: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}
