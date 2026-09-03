package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// launcherAuditApp provisions an app, an owned Principal credential, a
// launcher beneath that principal, and the launcher's credential bearer,
// mirroring the production ownership chain used by the launcher-control and
// session-create handlers under test. Returns the principal credential
// (launcher-management authority) and the launcher credential bearer
// (session-control authority).
func launcherAuditApp(t *testing.T, username string) (*App, string, string, *LauncherWithPrincipal) {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	globalRoots := app.Config.AllowedRoots
	home := filepath.Join(globalRoots[0], "home", username)
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(u string) (string, string, string, error) {
		return "2001", "2001", home, nil
	}
	p, err := createPrincipal(app.DB, username, globalRoots)
	if err != nil {
		t.Fatalf("createPrincipal(%s): %v", username, err)
	}
	_, credToken, err := createCredential(app.DB, username, "audit")
	if err != nil {
		t.Fatalf("createCredential(%s): %v", username, err)
	}
	l, _, launcherToken, err := createLauncher(app.DB, int64(p.ID), "default", LauncherScopeInherit, nil, globalRoots, true)
	if err != nil {
		t.Fatalf("createLauncher: %v", err)
	}
	return app, credToken, launcherToken, l
}

// launcherAuditRequest sends a launcher-control request with the given bearer
// and returns the recorder.
func launcherAuditRequest(t *testing.T, app *App, method, path, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	registerRoutes(mux, app)
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// TestLauncherCreateAuditProvenance proves the launcher.create success audit
// event carries the full launcher projection (launcher_id, launcher_name,
// launcher_scope, principal_name) and no bearer secret.
func TestLauncherCreateAuditProvenance(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, credToken, _, _ := launcherAuditApp(t, "lncaudit")

	// A second launcher created via the principal credential must emit the
	// create audit event with the full projection.
	w := launcherAuditRequest(t, app, http.MethodPost, "/principals/lncaudit/launchers", credToken, `{"name":"probe"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create launcher: expected 201, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp createLauncherResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	raw := findAuditLine(auditBuf, "launcher.create")
	if raw == "" {
		t.Fatalf("expected launcher.create audit line, got none\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)

	if m["launcher_id"] != resp.Launcher.ID {
		t.Errorf("launcher_id = %v, want %s", m["launcher_id"], resp.Launcher.ID)
	}
	if m["launcher_name"] != resp.Launcher.Name {
		t.Errorf("launcher_name = %v, want %s", m["launcher_name"], resp.Launcher.Name)
	}
	if m["launcher_scope"] != resp.Launcher.Scope {
		t.Errorf("launcher_scope = %v, want %s", m["launcher_scope"], resp.Launcher.Scope)
	}
	if m["principal_name"] != "lncaudit" {
		t.Errorf("principal_name = %v, want lncaudit", m["principal_name"])
	}
	assertNoSecrets(t, raw, m, credToken, testAdminToken)
}

// TestLauncherCredentialRotateAuditNoBearerLeak proves the rotation audit
// event records launcher provenance and the rotated credential ID, while the
// one-time bearer tokens never appear in the audit stream — the response
// token is exactly the strongest secret that must not leak.
func TestLauncherCredentialRotateAuditNoBearerLeak(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, credToken, _, l := launcherAuditApp(t, "lncaudit2")

	// The rotation precondition must hold: the launcher has a credential.
	w := launcherAuditRequest(t, app, http.MethodPost, "/launchers/"+l.ID+"/credential/rotate", credToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("rotate launcher credential: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp launcherCredentialResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token == "" {
		t.Fatal("rotate response must carry the new one-time bearer token")
	}

	raw := findAuditLine(auditBuf, "launcher.credential_rotate")
	if raw == "" {
		t.Fatalf("expected launcher.credential_rotate audit line, got none\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)

	if m["launcher_id"] != l.ID {
		t.Errorf("launcher_id = %v, want %s", m["launcher_id"], l.ID)
	}
	if m["credential_id"] != resp.Credential.ID {
		t.Errorf("credential_id = %v, want %s", m["credential_id"], resp.Credential.ID)
	}
	if m["result"] != "success" {
		t.Errorf("result = %v, want success", m["result"])
	}

	// The new bearer (and the authenticating principal credential) must never
	// appear in the audit stream.
	assertNoSecrets(t, raw, m, resp.Token, testAdminToken)
	if strings.Contains(raw, credToken) {
		t.Error("audit contains the authenticating launcher/principal credential bearer")
	}
	// The whole audit stream must not contain the bearer either.
	if strings.Contains(auditBuf.String(), resp.Token) {
		t.Error("audit stream contains the rotated bearer token")
	}
}

// TestSessionCreateAuditLauncherProvenance proves the session.create success
// audit event attributes the session to its owning Launcher and Principal
// (launcher_id, launcher_name, principal_name), and carries the credential
// provenance of the creating authority without any bearer secret.
func TestSessionCreateAuditLauncherProvenance(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, _, launcherToken, _ := launcherAuditApp(t, "lncaudit3")

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	// The workspace must be inside the launcher principal's own allowed root
	// (its home), not merely inside the global root.
	workspace := filepath.Join(app.Config.AllowedRoots[0], "home", "lncaudit3", "ws")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	body := `{"workspace":"` + workspace + `"}`
	req := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+launcherToken)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("session create: expected 201, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp createSessionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	raw := findAuditLine(auditBuf, "session.create")
	if raw == "" {
		t.Fatalf("expected session.create audit line, got none\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)

	if m["session_id"] != resp.Session.ID {
		t.Errorf("session_id = %v, want %s", m["session_id"], resp.Session.ID)
	}
	if m["launcher_id"] != resp.Session.LauncherID {
		t.Errorf("launcher_id = %v, want %s", m["launcher_id"], resp.Session.LauncherID)
	}
	if m["launcher_name"] != "default" {
		t.Errorf("launcher_name = %v, want default", m["launcher_name"])
	}
	if m["principal_name"] != "lncaudit3" {
		t.Errorf("principal_name = %v, want lncaudit3", m["principal_name"])
	}
	if m["credential_id"] == "" {
		t.Error("session.create must carry the creating credential_id for a launcher authority")
	}
	assertNoSecrets(t, raw, m, resp.Token, testAdminToken)
	if strings.Contains(raw, launcherToken) {
		t.Error("audit contains the authenticating launcher credential bearer")
	}
}

// TestLauncherCredentialIssueAuditNoBearerLeak proves the issue audit event
// records the launcher provenance and credential ID, and the one-time bearer
// token returned by the response never reaches the audit stream.
func TestLauncherCredentialIssueAuditNoBearerLeak(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, credToken, _, l := launcherAuditApp(t, "lncaudit4")

	// The precondition must hold: the launcher has no credential yet.
	// First delete the provisioning-time credential via the production path.
	if del := launcherAuditRequest(t, app, http.MethodDelete, "/launchers/"+l.ID+"/credential", credToken, ""); del.Code != http.StatusNoContent {
		t.Fatalf("delete provisioning credential: expected 204, got %d", del.Code)
	}

	w := launcherAuditRequest(t, app, http.MethodPut, "/launchers/"+l.ID+"/credential", credToken, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("issue launcher credential: expected 201, got %d (body=%s)", w.Code, w.Body.String())
	}
	var resp launcherCredentialResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token == "" {
		t.Fatal("issue response must carry the one-time bearer token")
	}

	raw := findAuditLine(auditBuf, "launcher.credential_issue")
	if raw == "" {
		t.Fatalf("expected launcher.credential_issue audit line, got none\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)

	if m["launcher_id"] != l.ID {
		t.Errorf("launcher_id = %v, want %s", m["launcher_id"], l.ID)
	}
	if m["credential_id"] != resp.Credential.ID {
		t.Errorf("credential_id = %v, want %s", m["credential_id"], resp.Credential.ID)
	}
	assertNoSecrets(t, raw, m, resp.Token, testAdminToken)
	if strings.Contains(auditBuf.String(), resp.Token) {
		t.Error("audit stream contains the issued bearer token")
	}
}

// TestLauncherAuditBufferIsJSONLines guards the helper assumption used by the
// provenance tests: each audit line parses as one JSON object with stream=audit.
func TestLauncherAuditBufferIsJSONLines(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, credToken, _, _ := launcherAuditApp(t, "lncaudit5")

	if w := launcherAuditRequest(t, app, http.MethodGet, "/principals/lncaudit5/launchers", credToken, ""); w.Code != http.StatusOK {
		t.Fatalf("list launchers: expected 200, got %d", w.Code)
	}

	lines := strings.Split(strings.TrimSpace(auditBuf.String()), "\n")
	if len(lines) == 0 {
		t.Fatal("expected audit lines")
	}
	for _, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("audit line is not JSON: %v: %s", err, line)
		}
		if m["stream"] != "audit" {
			t.Errorf("stream = %v, want audit", m["stream"])
		}
	}
}
