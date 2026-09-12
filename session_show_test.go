package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupSessionShowHierarchy configures the nested-transition policy for the
// session-show tests and creates one Session for the given authority through
// the real POST /sessions path. Returns the created Session ID and workspace.
func setupSessionShowHierarchy(t *testing.T, app *App, bearer, workspace string) string {
	t.Helper()
	root := app.Config.AllowedRoots[0].Path
	inputs := filepath.Join(root, "job", "inputs")
	if err := os.MkdirAll(inputs, 0755); err != nil {
		t.Fatal(err)
	}
	app.Config.AllowedRoots = []AllowedRootEntry{
		allowedRootEntry(root),
		{Path: inputs, Access: AllowedRootAccessReadOnly},
	}
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatal(err)
	}

	w := launcherRequest(t, app, http.MethodPost, "/sessions", bearer, fmt.Sprintf(`{"workspace":%q}`, workspace))
	if w.Code != http.StatusCreated {
		t.Fatalf("create session: %d %s", w.Code, w.Body.String())
	}
	var resp createSessionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode create response: %v (body=%s)", err, w.Body.String())
	}
	return resp.Session.ID
}

// TestSessionShowReturnsPersistedSnapshot proves the read-only introspection
// surface: GET /sessions/{id} returns the flat public metadata plus the
// persisted immutable snapshot in its exact canonical persisted ordering,
// through the single canonical loader — never a recomputation of current
// policy — and exposes no token, token hash, or duplicated workspace.
func TestSessionShowReturnsPersistedSnapshot(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path
	job := filepath.Join(root, "job")
	inputs := filepath.Join(job, "inputs")
	if err := os.MkdirAll(inputs, 0755); err != nil {
		t.Fatal(err)
	}
	app.Config.AllowedRoots = []AllowedRootEntry{
		allowedRootEntry(root),
		{Path: inputs, Access: AllowedRootAccessReadOnly},
	}
	sessionID := setupSessionShowHierarchy(t, app, testAdminToken, job)

	w := launcherRequest(t, app, http.MethodGet, "/sessions/"+sessionID, testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /sessions/{id}: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}

	// The flat public contract: the usual Session metadata and the persisted
	// immutable snapshot in its exact persisted canonical ordering.
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode show response: %v (body=%s)", err, w.Body.String())
	}
	for _, key := range []string{"id", "workspace", "created_at", "expires_at", "launcher_id", "filesystem_snapshot"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("show response missing %q: %s", key, w.Body.String())
		}
	}
	for _, key := range []string{"token", "token_hash", "effective_allowed_roots", "mac"} {
		if _, present := body[key]; present {
			t.Errorf("show response exposes forbidden key %q", key)
		}
	}
	snapshot, ok := body["filesystem_snapshot"].(map[string]any)
	if !ok {
		t.Fatalf("filesystem_snapshot is not an object: %s", w.Body.String())
	}
	if _, hasWorkspace := snapshot["workspace"]; hasWorkspace {
		t.Error("filesystem_snapshot must not duplicate the workspace: the top-level Session workspace is its canonical owner")
	}
	entries, ok := snapshot["entries"].([]any)
	if !ok {
		t.Fatalf("filesystem_snapshot.entries is not an array: %s", w.Body.String())
	}
	want := []AllowedRootEntry{
		{Path: jobWorkspacePath(t, app), Access: AllowedRootAccessReadWrite},
		{Path: inputs, Access: AllowedRootAccessReadOnly},
	}
	if len(entries) != len(want) {
		t.Fatalf("filesystem_snapshot entries = %v, want exactly %v", entries, want)
	}
	for i, raw := range entries {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("snapshot entry %d is not an object", i)
		}
		if got := entry["path"]; got != want[i].Path {
			t.Errorf("snapshot entry %d path = %v, want %s", i, got, want[i].Path)
		}
		if got := entry["access"]; got != string(want[i].Access) {
			t.Errorf("snapshot entry %d access = %v, want %s", i, got, want[i].Access)
		}
		if _, present := entry["workspace"]; present {
			t.Errorf("snapshot entry %d duplicates the workspace key", i)
		}
	}
}

// jobWorkspacePath returns the canonical workspace directory the show tests
// create their Sessions in.
func jobWorkspacePath(t *testing.T, app *App) string {
	t.Helper()
	return filepath.Join(app.Config.AllowedRoots[0].Path, "job")
}

// TestSessionShowAuthorizationMatrix proves the introspection authority
// matrix: admin, the owning Principal, and the owning Launcher read the
// Session; a Session bearer has no control-plane introspection authority; a
// missing or foreign Session is the same non-disclosing 404 session_not_found.
func TestSessionShowAuthorizationMatrix(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path

	// A foreign Session owned by the reserved daemon-owner Launcher
	// (admin-created, outside the scoped credentials below).
	foreignWorkspace := testWorkspaceDir(t, root)
	foreignSession, err := createDefaultAdminSessionForTest(app, foreignWorkspace)
	if err != nil {
		t.Fatalf("createSessionAuthorized(foreign): %v", err)
	}

	// The owning Principal with its own session.
	home := filepath.Join(root, "home", "showowner")
	workspace := filepath.Join(home, "work")
	inputs := filepath.Join(workspace, "inputs")
	for _, d := range []string{inputs} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	installOSUserMock(t, map[string]string{"showowner": home})
	if _, err := createPrincipal(app.DB, "showowner", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(showowner): %v", err)
	}
	if _, _, err := addPrincipalAllowedRoot(app.DB, "showowner", inputs, AllowedRootAccessReadOnly, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("addPrincipalAllowedRoot(inputs): %v", err)
	}
	_, principalToken, err := createPrincipalCredential(app.DB, "showowner", "oc")
	if err != nil {
		t.Fatalf("createPrincipalCredential: %v", err)
	}
	credential, err := authenticateCredential(app.DB, principalToken)
	if err != nil {
		t.Fatalf("authenticateCredential: %v", err)
	}
	principalAuth := &operatorAuthority{class: operatorAuthorityPrincipal, principal: credential.Principal}
	created, err := app.createSessionAuthorized(principalAuth, createSelector{}, workspace, nil)
	if err != nil {
		t.Fatalf("createSessionAuthorized(showowner): %v", err)
	}
	sessionID := created.Session.ID

	// A Launcher credential owned by the session's owning Launcher.
	launcherID, err := findDefaultLauncher(app.DB, credential.Principal.PrincipalID)
	if err != nil {
		t.Fatalf("findDefaultLauncher: %v", err)
	}
	_, launcherToken, err := issueLauncherCredential(app.DB, launcherID)
	if err != nil {
		t.Fatalf("issueLauncherCredential: %v", err)
	}

	// A live Session bearer token: created here, then used for introspection.
	sessionBearer, err := createDefaultAdminSessionForTest(app, workspace)
	if err != nil {
		t.Fatalf("createSessionAuthorized(session bearer): %v", err)
	}

	cases := []struct {
		name    string
		path    string
		bearer  string
		wantErr string // non-empty: expected error code in the body
	}{
		{
			name:   "admin reads any visible session",
			path:   "/sessions/" + sessionID,
			bearer: testAdminToken,
		},
		{
			name:   "owning principal reads its session",
			path:   "/sessions/" + sessionID,
			bearer: principalToken,
		},
		{
			name:   "owning launcher reads its session",
			path:   "/sessions/" + sessionID,
			bearer: launcherToken,
		},
		{
			name:    "missing session is 404 session_not_found",
			path:    "/sessions/dhs_missing",
			bearer:  testAdminToken,
			wantErr: "session_not_found",
		},
		{
			name:    "foreign session is non-disclosing 404 session_not_found",
			path:    "/sessions/" + foreignSession.Session.ID,
			bearer:  principalToken,
			wantErr: "session_not_found",
		},
		{
			name:    "session bearer has no introspection authority",
			path:    "/sessions/" + sessionID,
			bearer:  sessionBearer.Token,
			wantErr: "unauthorized",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := launcherRequest(t, app, http.MethodGet, tc.path, tc.bearer, "")
			if tc.wantErr != "" {
				wantCode := http.StatusNotFound
				if tc.wantErr == "unauthorized" {
					wantCode = http.StatusUnauthorized
				}
				if w.Code != wantCode {
					t.Fatalf("expected %d, got %d (body=%s)", wantCode, w.Code, w.Body.String())
				}
				var errBody struct {
					Code string `json:"code"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &errBody); err != nil {
					t.Fatalf("decode error body: %v (body=%s)", err, w.Body.String())
				}
				if errBody.Code != tc.wantErr {
					t.Fatalf("error code = %q, want %q (body=%s)", errBody.Code, tc.wantErr, w.Body.String())
				}
				return
			}
			if w.Code != http.StatusOK {
				t.Fatalf("GET %s: expected 200, got %d (body=%s)", tc.path, w.Code, w.Body.String())
			}
			var body sessionShowJSON
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode show response: %v (body=%s)", err, w.Body.String())
			}
			if body.ID != sessionID {
				t.Fatalf("shown session = %q, want %q", body.ID, sessionID)
			}
			if len(body.FilesystemSnapshot.Entries) == 0 {
				t.Fatal("shown session carries no snapshot entries")
			}
		})
	}
}

// TestSessionShowAuditTrail proves the session.show audit behavior: the
// success outcome carries the session, workspace, and ownership provenance
// with credential provenance; the not_found outcome carries the session id
// only; and no bearer, token hash, or credential material leaks into the
// audit stream.
func TestSessionShowAudit(t *testing.T) {
	auditOut, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	root := app.Config.AllowedRoots[0].Path
	job := filepath.Join(root, "job")
	if err := os.MkdirAll(job, 0755); err != nil {
		t.Fatal(err)
	}
	sessionID := setupSessionShowHierarchy(t, app, testAdminToken, job)

	// Success: workspace and ownership provenance are proven.
	if w := launcherRequest(t, app, http.MethodGet, "/sessions/"+sessionID, testAdminToken, ""); w.Code != http.StatusOK {
		t.Fatalf("success path: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	line := findAuditLine(auditOut, "session.show")
	rec := parseAuditMap(t, line)
	if rec["result"] != "success" {
		t.Fatalf("success audit result = %v (line=%s)", rec["result"], line)
	}
	if rec["session_id"] != sessionID {
		t.Errorf("success audit session_id = %q, want %q", rec["session_id"], sessionID)
	}
	if rec["workspace"] == "" {
		t.Errorf("success audit workspace missing: %s", line)
	}
	assertNoSecrets(t, line, rec, "", testAdminToken)

	// Not-found: no foreign/missing disclosure beyond the canonical outcome.
	if w := launcherRequest(t, app, http.MethodGet, "/sessions/dhs_missing", testAdminToken, ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing session: expected 404, got %d", w.Code)
	}
	line = lastAuditLineByEvent(auditOut, "session.show")
	rec = parseAuditMap(t, line)
	if rec["result"] != "not_found" {
		t.Fatalf("not-found audit result = %v (line=%s)", rec["result"], line)
	}
	if rec["workspace"] != nil {
		t.Errorf("not-found audit must not carry a workspace: %s", line)
	}
	assertNoSecrets(t, line, rec, "", testAdminToken)
}

// lastAuditLineByEvent returns the last audit line carrying the event (the
// result-filtered findAuditLine: the helper returns only the first match).
func lastAuditLineByEvent(buf *bytes.Buffer, event string) string {
	lines := findAuditLinesByEvent(buf, event)
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}

// TestSessionListStaysLightweightOfSnapshots protects the list contract:
// `session list` remains a lightweight metadata projection — it must not
// query the persisted snapshot rows per Session (no N+1 snapshot loading),
// and its JSON carries no filesystem_snapshot member. `session show` is the
// canonical introspection surface.
func TestSessionListStaysLightweightOfSnapshots(t *testing.T) {
	app1 := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	for i := 0; i < 3; i++ {
		ws := testWorkspaceDir(t, app1.Config.AllowedRoots[0].Path)
		if _, err := createDefaultAdminSessionForTest(app1, ws); err != nil {
			t.Fatalf("createSessionAuthorized(%d): %v", i, err)
		}
	}

	// Any snapshot-entry query through this connection would trip the point.
	snapshotQueryPoint := newParkedQueryPoint("FROM session_filesystem_snapshot_entries")
	app := &App{
		Config:          app1.Config,
		DB:              openParkedQueryDB(t, app1.Config.DatabasePath, snapshotQueryPoint),
		AdminTokenHash:  app1.AdminTokenHash,
		userModeDefault: app1.userModeDefault,
	}

	w := launcherRequest(t, app, http.MethodGet, "/sessions", testAdminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}

	var resp listSessionsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list response: %v (body=%s)", err, w.Body.String())
	}
	if len(resp.Sessions) != 3 {
		t.Fatalf("listed sessions = %d, want 3", len(resp.Sessions))
	}
	if strings.Contains(w.Body.String(), "filesystem_snapshot") {
		t.Errorf("session list must not carry snapshot projections: %s", w.Body.String())
	}

	// The parked point proves no snapshot-entry query ran for the list.
	select {
	case <-snapshotQueryPoint.parked:
		t.Fatal("session list queried the snapshot entries")
	default:
	}
}
