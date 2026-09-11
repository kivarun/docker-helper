package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupSessionNarrowingFixture provisions the canonical dynamic-run shape for
// the issuance-time narrowing tests: a Principal whose effective ceiling is
// its run tree read_write with a protected read-only pipeline-inputs region,
// a default Launcher (inherit), a Principal credential, and a Launcher
// credential. The run workspace with project/, pipeline-inputs/, and
// pipeline-outputs/ is real: entry canonicalization resolves against the
// filesystem.
func setupSessionNarrowingFixture(t *testing.T, app *App) (principalToken, launcherToken, launcherID, workspace string) {
	t.Helper()
	root := app.Config.AllowedRoots[0].Path
	tree := filepath.Join(root, "runs")
	workspace = filepath.Join(tree, "run-1")
	inputs := filepath.Join(workspace, "pipeline-inputs")
	for _, d := range []string{inputs, filepath.Join(workspace, "project"), filepath.Join(workspace, "pipeline-outputs")} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(inputs, "plan.md"), []byte("plan"), 0644); err != nil {
		t.Fatal(err)
	}

	installOSUserMock(t, map[string]string{"narrower": tree})
	if _, err := createPrincipal(app.DB, "narrower", app.Config.AllowedRoots); err != nil {
		t.Fatalf("createPrincipal(narrower): %v", err)
	}
	if _, _, err := addPrincipalAllowedRoot(app.DB, "narrower", inputs, AllowedRootAccessReadOnly, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("addPrincipalAllowedRoot(inputs): %v", err)
	}
	launcherID = mustAddDefaultLauncher(t, app.DB, principalIDByName(t, app.DB, "narrower"))

	_, principalToken, err := createPrincipalCredential(app.DB, "narrower", "oc")
	if err != nil {
		t.Fatalf("createPrincipalCredential(narrower): %v", err)
	}
	_, launcherToken, err = issueLauncherCredential(app.DB, launcherID)
	if err != nil {
		t.Fatalf("issueLauncherCredential: %v", err)
	}
	return principalToken, launcherToken, launcherID, workspace
}

// postSessionThroughMux issues a real POST /sessions through the route mux
// and returns the recorded response.
func postSessionThroughMux(t *testing.T, app *App, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	return launcherRequest(t, app, http.MethodPost, "/sessions", token, body)
}

// showSessionThroughMux issues a real GET /sessions/{id} through the route
// mux and returns the recorded response.
func showSessionThroughMux(t *testing.T, app *App, token, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	return launcherRequest(t, app, http.MethodGet, "/sessions/"+sessionID, token, "")
}

// createdSessionID decodes the created Session ID from a 201 response.
func createdSessionID(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp createSessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("cannot decode create response: %v", err)
	}
	return resp.Session.ID
}

// assertRefusal asserts the stable issuance-time refusal contract.
func assertRefusal(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	var resp response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("cannot decode error response: %v", err)
	}
	if resp.Code != "invalid_filesystem_policy" {
		t.Errorf("error code = %q, want invalid_filesystem_policy", resp.Code)
	}
}

// countLiveSessions counts the Session rows: the no-state-on-refusal proof.
func countLiveSessions(t *testing.T, app *App) int {
	t.Helper()
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil {
		t.Fatalf("cannot count sessions: %v", err)
	}
	return count
}

// narrowingRequestBody builds a Session create body with a caller-supplied
// filesystem_entries array value (including "null" and "[]").
func narrowingRequestBody(workspace, entries string) string {
	return fmt.Sprintf(`{"workspace":%q,"filesystem_entries":%s}`, workspace, entries)
}

// successfulNarrowingEntries is the motivating dynamic-run request: the
// workspace root is narrowed read-only while the authorized read-write
// subtrees stay explicit read-write exceptions no wider than the ceiling.
func successfulNarrowingEntries() string {
	return `[{"path":".","access":"read_only"},{"path":"project","access":"read_write"},{"path":"pipeline-inputs","access":"read_only"},{"path":"pipeline-outputs","access":"read_write"}]`
}

// wantSnapshotJSON builds the exact canonical persisted snapshot JSON for the
// dynamic-run shape: root read-only plus the two retained read-write
// exceptions (the redundant pipeline-inputs read_only entry is normalized
// away because the root is already read-only).
func wantSnapshotJSON(workspace string) string {
	return fmt.Sprintf(`[{"path":%q,"access":"read_only"},{"path":%q,"access":"read_write"},{"path":%q,"access":"read_write"}]`,
		workspace, filepath.Join(workspace, "pipeline-outputs"), filepath.Join(workspace, "project"))
}

// TestHTTPSessionFilesystemOmittedInheritsCeiling proves the compatibility
// contract: a create without filesystem_entries produces the exact inherited
// derived snapshot — the workspace root with its effective ceiling mode plus
// every ceiling transition strictly inside the workspace.
func TestHTTPSessionFilesystemOmittedInheritsCeiling(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)

	rec := postSessionThroughMux(t, app, launcherToken, fmt.Sprintf(`{"workspace":%q}`, workspace))
	if rec.Code != http.StatusCreated {
		t.Fatalf("omitted-field create = %d, want 201: %s", rec.Code, rec.Body.String())
	}

	showRec := showSessionThroughMux(t, app, testAdminToken, createdSessionID(t, rec))
	if showRec.Code != http.StatusOK {
		t.Fatalf("show = %d: %s", showRec.Code, showRec.Body.String())
	}
	var show sessionShowJSON
	if err := json.Unmarshal(showRec.Body.Bytes(), &show); err != nil {
		t.Fatalf("cannot decode show body: %v", err)
	}
	want := fmt.Sprintf(`[{"path":%q,"access":"read_write"},{"path":%q,"access":"read_only"}]`,
		workspace, filepath.Join(workspace, "pipeline-inputs"))
	if got, err := json.Marshal(show.FilesystemSnapshot.Entries); err != nil || string(got) != want {
		t.Errorf("inherited snapshot = %s, want %s (err=%v)", got, want, err)
	}
}

// TestHTTPSessionFilesystemPresenceRefusals proves the one-code presence
// contract of filesystem_entries: an explicit occurrence must be a non-empty,
// structurally valid array; every malformed shape is refused
// 400 invalid_filesystem_policy before the Session exists.
func TestHTTPSessionFilesystemPresenceRefusals(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)

	for name, entries := range map[string]string{
		"json null":            `null`,
		"empty array":          `[]`,
		"unknown nested field": `[{"path":".","access":"read_only","extra":1}]`,
		"unknown access":       `[{"path":".","access":"writable"}]`,
		"missing access":       `[{"path":"."}]`,
		"null access":          `[{"path":".","access":null}]`,
		"absolute path":        `[{"path":"/etc","access":"read_only"}]`,
		"parent traversal":     `[{"path":"../escape","access":"read_only"}]`,
		"inner traversal":      `[{"path":"project/../escape","access":"read_only"}]`,
		"dot-prefixed path":    `[{"path":"./project","access":"read_write"}]`,
		"non-object entry":     `["."]`,
		"wrong entry type":     `[{"path":5,"access":"read_only"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			before := countLiveSessions(t, app)
			rec := postSessionThroughMux(t, app, launcherToken, narrowingRequestBody(workspace, entries))
			assertRefusal(t, rec)
			if after := countLiveSessions(t, app); after != before {
				t.Errorf("refused create left %d sessions, want %d", after, before)
			}
		})
	}
}

// TestHTTPSessionFilesystemCanonicalizationRefusals proves the relative-path
// identity contract: entries are canonicalized against the real workspace,
// and an unresolvable or duplicate-canonical entry is refused before the
// Session exists.
func TestHTTPSessionFilesystemCanonicalizationRefusals(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)

	for name, entries := range map[string]string{
		"nonexistent path":         `[{"path":".","access":"read_only"},{"path":"missing","access":"read_write"}]`,
		"duplicate canonical path": `[{"path":".","access":"read_only"},{"path":"project","access":"read_write"},{"path":"project","access":"read_write"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			before := countLiveSessions(t, app)
			rec := postSessionThroughMux(t, app, launcherToken, narrowingRequestBody(workspace, entries))
			assertRefusal(t, rec)
			if after := countLiveSessions(t, app); after != before {
				t.Errorf("refused create left %d sessions, want %d", after, before)
			}
		})
	}

	// A symlink inside the workspace pointing outside it cannot name a
	// canonical identity inside the workspace.
	escape := filepath.Join(workspace, "escape-link")
	if err := os.Symlink(filepath.Join(app.Config.AllowedRoots[0].Path, "outside"), escape); err != nil {
		t.Fatal(err)
	}
	rec := postSessionThroughMux(t, app, launcherToken, narrowingRequestBody(workspace,
		`[{"path":".","access":"read_only"},{"path":"escape-link","access":"read_write"}]`))
	assertRefusal(t, rec)

	// The literal "." workspace entry is a raw request-shape invariant: a
	// symlink alias that resolves to the workspace itself (rootlink -> .)
	// never satisfies it. A request carrying only the alias is refused even
	// though its canonical entry equals the workspace root.
	rootlink := filepath.Join(workspace, "rootlink")
	if err := os.Symlink(".", rootlink); err != nil {
		t.Fatal(err)
	}
	rec = postSessionThroughMux(t, app, launcherToken, narrowingRequestBody(workspace,
		`[{"path":"rootlink","access":"read_only"},{"path":"project","access":"read_write"}]`))
	assertRefusal(t, rec)
	if after := countLiveSessions(t, app); after != 0 {
		t.Errorf("refused rootlink-only create left %d sessions, want 0", after)
	}
}

// TestHTTPSessionFilesystemRefusalDoesNotDiscloseCanonicalPath proves the
// non-disclosing refusal contract: the HTTP refusal carries the stable code
// and the bounded message only — never the resolved canonical symlink target
// or any upstream policy path. The internal diagnostic (which does carry the
// canonical requested path) stays in the operational log.
func TestHTTPSessionFilesystemRefusalDoesNotDiscloseCanonicalPath(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)

	// A symlink alias inside the workspace resolving into the protected
	// read-only region: the canonicalized entry names the canonical target
	// path in the internal diagnostic, and the widening request is refused.
	alias := filepath.Join(workspace, "alias")
	if err := os.Symlink(filepath.Join(workspace, "pipeline-inputs"), alias); err != nil {
		t.Fatal(err)
	}
	rec := postSessionThroughMux(t, app, launcherToken, narrowingRequestBody(workspace,
		`[{"path":".","access":"read_only"},{"path":"alias","access":"read_write"}]`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	var resp response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("cannot decode error response: %v", err)
	}
	if resp.Code != "invalid_filesystem_policy" {
		t.Errorf("error code = %q, want invalid_filesystem_policy", resp.Code)
	}
	if resp.Message != sessionFilesystemPolicyMessage {
		t.Errorf("message = %q, want the bounded non-disclosing message %q", resp.Message, sessionFilesystemPolicyMessage)
	}
	body := rec.Body.String()
	if strings.Contains(body, "pipeline-inputs") || strings.Contains(body, filepath.Join(workspace, "pipeline-inputs")) {
		t.Errorf("refusal discloses the resolved canonical target: %s", body)
	}
	if strings.Contains(body, "/") && strings.Contains(body, app.Config.AllowedRoots[0].Path) {
		t.Errorf("refusal discloses a host path: %s", body)
	}
}

// TestHTTPLauncherCredentialNarrowing proves the motivating capability under
// a Launcher credential: the credential narrows its own Session at issuance
// time, the issued snapshot is exactly the canonical normalized semantics,
// and an attempted widening is refused with no additional Session created.
func TestHTTPLauncherCredentialNarrowing(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	auditBuf, _ := setupTestLogging(t)
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)

	before := countLiveSessions(t, app)
	rec := postSessionThroughMux(t, app, launcherToken, narrowingRequestBody(workspace, successfulNarrowingEntries()))
	if rec.Code != http.StatusCreated {
		t.Fatalf("narrowed create = %d, want 201: %s", rec.Code, rec.Body.String())
	}

	showRec := showSessionThroughMux(t, app, launcherToken, createdSessionID(t, rec))
	if showRec.Code != http.StatusOK {
		t.Fatalf("show = %d: %s", showRec.Code, showRec.Body.String())
	}
	var show sessionShowJSON
	if err := json.Unmarshal(showRec.Body.Bytes(), &show); err != nil {
		t.Fatalf("cannot decode show body: %v", err)
	}
	if got, err := json.Marshal(show.FilesystemSnapshot.Entries); err != nil || string(got) != wantSnapshotJSON(workspace) {
		t.Errorf("issued snapshot = %s, want %s (err=%v)", got, wantSnapshotJSON(workspace), err)
	}
	snapshot, err := newSessionFilesystemSnapshot(show.Workspace, show.FilesystemSnapshot.Entries)
	if err != nil {
		t.Fatalf("issued snapshot is not the canonical representation: %v", err)
	}
	// The read-only protection of pipeline-inputs survives normalization:
	// the redundant explicit entry is gone, the effective semantics remain.
	if access, ok := snapshot.LookupAccess(filepath.Join(workspace, "pipeline-inputs")); !ok || access != AllowedRootAccessReadOnly {
		t.Errorf("pipeline-inputs effective access = %q (ok=%v), want read_only", access, ok)
	}
	if snapshot.CanExposeWritable(filepath.Join(workspace, "pipeline-inputs")) {
		t.Error("pipeline-inputs must not be writable-exposable")
	}

	// Attempted widening: read_write under the effective read_only region is
	// refused before the Session exists; no additional Session is created.
	widening := `[{"path":".","access":"read_only"},{"path":"pipeline-inputs","access":"read_write"}]`
	rec = postSessionThroughMux(t, app, launcherToken, narrowingRequestBody(workspace, widening))
	assertRefusal(t, rec)
	if after := countLiveSessions(t, app); after != before+1 {
		t.Errorf("refusal left %d sessions, want %d", after, before+1)
	}

	// The refusal is audited with the stable issuance-time result and carries
	// no bearer material.
	var refused bool
	for _, r := range parseAuditRecords(auditBuf) {
		if r.Event == "session.create" && r.Result == "invalid_filesystem_policy" {
			refused = true
		}
	}
	if !refused {
		t.Error("audit does not record the invalid_filesystem_policy refusal")
	}
}

// TestHTTPSessionFilesystemAuthoritySymmetry proves the narrowing contract is
// one Session-create contract for every authority: Admin (with an explicit
// Launcher selector) and a Principal credential get the same narrowed
// snapshot as the Launcher credential and receive the same widening refusal.
func TestHTTPSessionFilesystemAuthoritySymmetry(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	principalToken, _, launcherID, workspace := setupSessionNarrowingFixture(t, app)

	for name, token := range map[string]string{
		"admin":                testAdminToken,
		"principal credential": principalToken,
	} {
		t.Run(name, func(t *testing.T) {
			body := fmt.Sprintf(`{"workspace":%q,"launcher_id":%q,"filesystem_entries":%s}`,
				workspace, launcherID, successfulNarrowingEntries())
			rec := postSessionThroughMux(t, app, token, body)
			if rec.Code != http.StatusCreated {
				t.Fatalf("narrowed create = %d, want 201: %s", rec.Code, rec.Body.String())
			}
			showRec := showSessionThroughMux(t, app, testAdminToken, createdSessionID(t, rec))
			if showRec.Code != http.StatusOK {
				t.Fatalf("show = %d: %s", showRec.Code, showRec.Body.String())
			}
			var show sessionShowJSON
			if err := json.Unmarshal(showRec.Body.Bytes(), &show); err != nil {
				t.Fatalf("cannot decode show body: %v", err)
			}
			if got, err := json.Marshal(show.FilesystemSnapshot.Entries); err != nil || string(got) != wantSnapshotJSON(workspace) {
				t.Errorf("issued snapshot = %s, want %s (err=%v)", got, wantSnapshotJSON(workspace), err)
			}

			// The widening attempt is structurally and canonically valid: it
			// carries the required literal "." entry, so it passes the raw
			// request-shape invariant and entry canonicalization, and it is
			// refused specifically because pipeline-inputs=read_write tries
			// to widen the effective read_only ceiling at that path.
			afterNarrow := countLiveSessions(t, app)
			widening := fmt.Sprintf(`{"workspace":%q,"launcher_id":%q,"filesystem_entries":[{"path":".","access":"read_only"},{"path":"pipeline-inputs","access":"read_write"}]}`,
				workspace, launcherID)
			rec = postSessionThroughMux(t, app, token, widening)
			assertRefusal(t, rec)
			// The refused create issued no Session: the count after the
			// refusal equals the count after the accepted narrowed create.
			if after := countLiveSessions(t, app); after != afterNarrow {
				t.Errorf("refused widening create left %d sessions, want %d", after, afterNarrow)
			}
		})
	}
}
