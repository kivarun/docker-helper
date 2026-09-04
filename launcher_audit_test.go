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
	l, _, launcherToken, err := createLauncher(app.DB, int64(p.ID), "agent", LauncherScopeInherit, nil, globalRoots, true)
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
	w := launcherAuditRequest(t, app, http.MethodPost, "/principals/lncaudit2/launchers/"+l.ID+"/credential/rotate", credToken, "")
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
	if m["launcher_name"] != "agent" {
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
	if del := launcherAuditRequest(t, app, http.MethodDelete, "/principals/lncaudit4/launchers/"+l.ID+"/credential", credToken, ""); del.Code != http.StatusNoContent {
		t.Fatalf("delete provisioning credential: expected 204, got %d", del.Code)
	}

	w := launcherAuditRequest(t, app, http.MethodPut, "/principals/lncaudit4/launchers/"+l.ID+"/credential", credToken, "")
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

// TestLauncherControlAuditCreatorProvenance proves launcher-control events
// performed with a Principal credential carry the creator provenance: the
// acting principal and its credential ID, without leaking the bearer secret.
// The issued launcher credential's own ID is preserved on credential events.
func TestLauncherControlAuditCreatorProvenance(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, credToken, _, l := launcherAuditApp(t, "lncauditprov")

	// launcher.credential_rotate performed with the Principal credential: the
	// record's credential_id is the rotated launcher credential.
	var rotated launcherCredentialResponse
	if w := launcherAuditRequest(t, app, http.MethodPost, "/principals/lncauditprov/launchers/"+l.ID+"/credential/rotate", credToken, ""); w.Code != http.StatusOK {
		t.Fatalf("rotate: expected 200, got %d", w.Code)
	} else if err := json.Unmarshal(w.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}

	var creatorCredID string
	{
		raw := findAuditLine(auditBuf, "launcher.credential_rotate")
		if raw == "" {
			t.Fatalf("expected launcher.credential_rotate audit line\n%s", auditBuf.String())
		}
		m := parseAuditMap(t, raw)
		if m["credential_id"] != rotated.Credential.ID {
			t.Errorf("credential_rotate credential_id = %v, want rotated %s", m["credential_id"], rotated.Credential.ID)
		}
		if m["principal_name"] != "lncauditprov" {
			t.Errorf("credential_rotate principal_name = %v", m["principal_name"])
		}
		assertNoSecrets(t, raw, m, credToken, rotated.Token)
	}

	// A fresh launcher credential to authenticate the controlled launcher's
	// sessions... not needed here; instead use the Principal credential for a
	// scope replace and a delete, which have no other credential_id to carry.
	if w := launcherAuditRequest(t, app, http.MethodPut, "/principals/lncauditprov/launchers/"+l.ID+"/allowed-roots", credToken,
		`{"scope":"inherit","allowed_roots":[]}`); w.Code != http.StatusOK {
		t.Fatalf("scope replace: expected 200, got %d", w.Code)
	}

	raw := findAuditLine(auditBuf, "launcher.scope_replace")
	if raw == "" {
		t.Fatalf("expected launcher.scope_replace audit line\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)
	if m["principal_name"] != "lncauditprov" {
		t.Errorf("scope_replace principal_name = %v, want lncauditprov", m["principal_name"])
	}
	if m["credential_id"] == "" {
		t.Fatal("scope_replace must carry the creator credential_id")
	}
	creatorCredID, _ = m["credential_id"].(string)
	assertNoSecrets(t, raw, m, credToken, "")

	// The creator credential ID matches the Principal credential "audit"
	// created by launcherAuditApp.
	var dbCredID string
	if err := app.DB.QueryRow(
		`SELECT id FROM credentials WHERE principal_id = (SELECT id FROM principals WHERE username='lncauditprov') AND name='audit'`,
	).Scan(&dbCredID); err != nil {
		t.Fatalf("resolve creator credential: %v", err)
	}
	if creatorCredID != dbCredID {
		t.Errorf("creator credential_id = %q, want %q", creatorCredID, dbCredID)
	}

	// launcher.delete with the Principal credential.
	if w := launcherAuditRequest(t, app, http.MethodDelete, "/principals/lncauditprov/launchers/"+l.ID, credToken, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d", w.Code)
	}
	raw = findAuditLine(auditBuf, "launcher.delete")
	if raw == "" {
		t.Fatalf("expected launcher.delete audit line\n%s", auditBuf.String())
	}
	m = parseAuditMap(t, raw)
	if m["principal_name"] != "lncauditprov" {
		t.Errorf("delete principal_name = %v", m["principal_name"])
	}
	if m["credential_id"] != creatorCredID {
		t.Errorf("delete credential_id = %v, want creator %q", m["credential_id"], creatorCredID)
	}
	assertNoSecrets(t, raw, m, credToken, "")
}

// TestLauncherControlAuditInitiatorCredentialProvenance proves the initiating
// Principal credential stays distinguishable from the credential resource an
// issue/rotate event concerns: initiator_credential_id always names the
// credential that performed the request (verified against two different
// Principal credentials), while credential_id keeps its target-resource
// semantics (the issued or rotated Launcher credential). Admin-token events
// carry no initiator credential, and no bearer secret appears anywhere.
func TestLauncherControlAuditInitiatorCredentialProvenance(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, credAToken, _, l := launcherAuditApp(t, "lncinitiator")
	_, credBToken, err := createCredential(app.DB, "lncinitiator", "second")
	if err != nil {
		t.Fatalf("create second principal credential: %v", err)
	}

	var credAID, credBID string
	for _, tc := range []struct {
		name   string
		credID *string
	}{
		{"audit", &credAID},
		{"second", &credBID},
	} {
		if err := app.DB.QueryRow(
			`SELECT id FROM credentials WHERE principal_id = (SELECT id FROM principals WHERE username = 'lncinitiator') AND name = ?`,
			tc.name,
		).Scan(tc.credID); err != nil {
			t.Fatalf("resolve %s credential id: %v", tc.name, err)
		}
	}

	// Drop the provisioning credential so the launcher's credential can be
	// issued fresh, initiated by credential A.
	if del := launcherAuditRequest(t, app, http.MethodDelete, "/principals/lncinitiator/launchers/"+l.ID+"/credential", credAToken, ""); del.Code != http.StatusNoContent {
		t.Fatalf("delete provisioning credential: expected 204, got %d", del.Code)
	}
	w := launcherAuditRequest(t, app, http.MethodPut, "/principals/lncinitiator/launchers/"+l.ID+"/credential", credAToken, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("issue launcher credential: expected 201, got %d (body=%s)", w.Code, w.Body.String())
	}
	var issued launcherCredentialResponse
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}

	raw := findAuditLine(auditBuf, "launcher.credential_issue")
	if raw == "" {
		t.Fatalf("expected launcher.credential_issue audit line\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)
	if m["credential_id"] != issued.Credential.ID {
		t.Errorf("issue credential_id = %v, want issued %s", m["credential_id"], issued.Credential.ID)
	}
	if m["initiator_credential_id"] != credAID {
		t.Errorf("issue initiator_credential_id = %v, want initiating principal credential %s", m["initiator_credential_id"], credAID)
	}
	if m["credential_id"] == m["initiator_credential_id"] {
		t.Error("issue event must keep target (credential_id) and initiator distinguishable")
	}
	assertNoSecrets(t, raw, m, issued.Token, testAdminToken)
	if strings.Contains(auditBuf.String(), credAToken) || strings.Contains(auditBuf.String(), issued.Token) {
		t.Error("audit stream contains a bearer secret")
	}

	// Rotate initiated by the second Principal credential: the initiator
	// switches to credential B while the target is the rotated credential.
	if w := launcherAuditRequest(t, app, http.MethodPost, "/principals/lncinitiator/launchers/"+l.ID+"/credential/rotate", credBToken, ""); w.Code != http.StatusOK {
		t.Fatalf("rotate launcher credential: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	rotateRaw := findAuditLine(auditBuf, "launcher.credential_rotate")
	if rotateRaw == "" {
		t.Fatalf("expected launcher.credential_rotate audit line\n%s", auditBuf.String())
	}
	// Recover the rotated credential ID from the DB (the audit assertion must
	// hold regardless of response parsing order).
	var rotatedCredID string
	if err := app.DB.QueryRow(
		`SELECT id FROM credentials WHERE launcher_id = ? AND revoked_at IS NULL`, l.ID,
	).Scan(&rotatedCredID); err != nil {
		t.Fatalf("resolve rotated launcher credential: %v", err)
	}
	m = parseAuditMap(t, rotateRaw)
	if m["credential_id"] != rotatedCredID {
		t.Errorf("rotate credential_id = %v, want rotated %s", m["credential_id"], rotatedCredID)
	}
	if m["initiator_credential_id"] != credBID {
		t.Errorf("rotate initiator_credential_id = %v, want initiating principal credential %s", m["initiator_credential_id"], credBID)
	}
	if m["credential_id"] == m["initiator_credential_id"] {
		t.Error("rotate event must keep target (credential_id) and initiator distinguishable")
	}
	assertNoSecrets(t, rotateRaw, m, credBToken, testAdminToken)
	if strings.Contains(auditBuf.String(), credBToken) {
		t.Error("audit stream contains the rotating principal credential bearer")
	}

	// An admin-token launcher-control event carries no initiator credential.
	if w := launcherAuditRequest(t, app, http.MethodPatch, "/principals/lncinitiator/launchers/"+l.ID, testAdminToken, `{"name":"renamed"}`); w.Code != http.StatusOK {
		t.Fatalf("admin patch: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	updateRaw := findAuditLine(auditBuf, "launcher.update")
	if updateRaw == "" {
		t.Fatalf("expected launcher.update audit line\n%s", auditBuf.String())
	}
	m = parseAuditMap(t, updateRaw)
	if _, present := m["initiator_credential_id"]; present {
		t.Errorf("admin-authenticated launcher.update must not carry initiator_credential_id: %v", m)
	}
	assertNoSecrets(t, updateRaw, m, "", testAdminToken)
}

// TestRunAuditLauncherProvenance proves run.start and run.finish carry the
// owning session's launcher identity (launcher_id, launcher_name), so a
// Docker operation's audit trail names its Launcher owner directly.
func TestRunAuditLauncherProvenance(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, _, launcherToken, l := launcherAuditApp(t, "lncauditrun")
	app.OperationSupervisor = newOperationSupervisor()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /run", app.handleRun)
	mux.HandleFunc("POST /sessions", app.handleCreateSession)

	workspace := filepath.Join(app.Config.AllowedRoots[0], "home", "lncauditrun", "ws")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	sreq := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(`{"workspace":"`+workspace+`"}`))
	sreq.Header.Set("Authorization", "Bearer "+launcherToken)
	sw := httptest.NewRecorder()
	mux.ServeHTTP(sw, sreq)
	if sw.Code != http.StatusCreated {
		t.Fatalf("session create: expected 201, got %d (body=%s)", sw.Code, sw.Body.String())
	}
	var sresp createSessionResponse
	if err := json.Unmarshal(sw.Body.Bytes(), &sresp); err != nil {
		t.Fatal(err)
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"echo", "hello"},
	}, sresp.Token)
	rw := httptest.NewRecorder()
	mux.ServeHTTP(rw, req)
	if rw.Code != http.StatusCreated {
		t.Fatalf("run: expected 201, got %d (body=%s)", rw.Code, rw.Body.String())
	}
	waitRun(t, app, rw)

	startRaw := findAuditLine(auditBuf, "run.start")
	finishRaw := findAuditLine(auditBuf, "run.finish")
	if startRaw == "" || finishRaw == "" {
		t.Fatalf("expected run.start and run.finish audit lines\n%s", auditBuf.String())
	}
	start := parseAuditMap(t, startRaw)
	finish := parseAuditMap(t, finishRaw)

	for _, tc := range []struct {
		event string
		m     map[string]any
	}{
		{"run.start", start},
		{"run.finish", finish},
	} {
		if tc.m["launcher_id"] != l.ID {
			t.Errorf("%s launcher_id = %v, want %s", tc.event, tc.m["launcher_id"], l.ID)
		}
		if tc.m["launcher_name"] != "agent" {
			t.Errorf("%s launcher_name = %v, want agent", tc.event, tc.m["launcher_name"])
		}
	}
	assertNoSecrets(t, startRaw, start, sresp.Token, launcherToken)
	assertNoSecrets(t, finishRaw, finish, sresp.Token, launcherToken)
}

// TestSessionDeleteAuditOwnershipProvenance proves a successful session.delete
// audit record names the deleted session's ownership: launcher_id,
// launcher_name, and principal_name, even when the delete is performed by an
// admin (whose authority carries no credential provenance).
func TestSessionDeleteAuditOwnershipProvenance(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, _, launcherToken, l := launcherAuditApp(t, "lncauditdel")

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", app.handleCreateSession)
	mux.HandleFunc("DELETE /sessions/{id}", app.handleDeleteSession)

	workspace := filepath.Join(app.Config.AllowedRoots[0], "home", "lncauditdel", "ws")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}
	sreq := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(`{"workspace":"`+workspace+`"}`))
	sreq.Header.Set("Authorization", "Bearer "+launcherToken)
	sw := httptest.NewRecorder()
	mux.ServeHTTP(sw, sreq)
	if sw.Code != http.StatusCreated {
		t.Fatalf("session create: expected 201, got %d (body=%s)", sw.Code, sw.Body.String())
	}
	var sresp createSessionResponse
	if err := json.Unmarshal(sw.Body.Bytes(), &sresp); err != nil {
		t.Fatal(err)
	}

	dreq := httptest.NewRequest(http.MethodDelete, "/sessions/"+sresp.Session.ID, nil)
	withAdminToken(dreq)
	dw := httptest.NewRecorder()
	mux.ServeHTTP(dw, dreq)
	if dw.Code != http.StatusNoContent {
		t.Fatalf("session delete: expected 204, got %d (body=%s)", dw.Code, dw.Body.String())
	}

	raw := findAuditLine(auditBuf, "session.delete")
	if raw == "" {
		t.Fatalf("expected session.delete audit line\n%s", auditBuf.String())
	}
	m := parseAuditMap(t, raw)
	if m["result"] != "success" {
		t.Errorf("result = %v, want success", m["result"])
	}
	if m["launcher_id"] != l.ID {
		t.Errorf("launcher_id = %v, want %s", m["launcher_id"], l.ID)
	}
	if m["launcher_name"] != "agent" {
		t.Errorf("launcher_name = %v, want agent", m["launcher_name"])
	}
	if m["principal_name"] != "lncauditdel" {
		t.Errorf("principal_name = %v, want lncauditdel", m["principal_name"])
	}
	assertNoSecrets(t, raw, m, sresp.Token, launcherToken)
	if strings.Contains(raw, testAdminToken) {
		t.Error("audit contains admin token")
	}
}
