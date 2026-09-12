package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupSessionNarrowingFixture provisions the canonical dynamic-run shape
// for the issuance-time filesystem-roots tests: a Principal whose effective
// ceiling is the global root read_write with a protected read-only
// pipeline-inputs region, a default Launcher (inherit), a Principal
// credential, and a Launcher credential. The run workspace with project/,
// pipeline-inputs/, and pipeline-outputs/, the external helper root, and the
// external cache root are real: root canonicalization resolves against the
// filesystem. Returns the canonical external root paths through the
// helper/cache outputs.
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
	// External filesystem roots inside the same Principal ceiling (the run
	// tree): the read-only helper repo and the read-write cache tree.
	helper := filepath.Join(tree, "repos", "helper")
	cache := filepath.Join(tree, "cache")
	for _, d := range []string{helper, cache} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(helper, "main.go"), []byte("helper"), 0644); err != nil {
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

// rootsRequestBody builds a Session create body with a caller-supplied
// filesystem_roots array value (including "null" and "[]").
func rootsRequestBody(workspace, roots string) string {
	return fmt.Sprintf(`{"workspace":%q,"filesystem_roots":%s}`, workspace, roots)
}

// successfulNarrowingRoots is the motivating dynamic-run request: the
// workspace is explicitly narrowed read-only, the authorized read-write
// subtree inside it stays an explicit read-write exception no wider than the
// ceiling, and two external absolute roots are issued read-only and
// read-write.
func successfulNarrowingRoots(app *App) string {
	tree := filepath.Join(app.Config.AllowedRoots[0].Path, "runs")
	return fmt.Sprintf(`[{"path":%q,"access":"read_only"},{"path":%q,"access":"read_write"},{"path":%q,"access":"read_write"},{"path":%q,"access":"read_only"},{"path":%q,"access":"read_write"}]`,
		filepath.Join(tree, "run-1"),
		filepath.Join(tree, "run-1", "pipeline-outputs"),
		filepath.Join(tree, "run-1", "project"),
		filepath.Join(tree, "repos", "helper"),
		filepath.Join(tree, "cache"))
}

// wantSnapshotJSON builds the exact canonical persisted snapshot JSON for
// the multi-root dynamic-run shape, in canonical byte order: the external
// cache root, the external helper root, the workspace read-only root with
// its two retained read-write exceptions (the redundant pipeline-inputs
// read_only entry is normalized away because the workspace root is already
// read-only).
func wantSnapshotJSON(app *App) string {
	tree := filepath.Join(app.Config.AllowedRoots[0].Path, "runs")
	workspace := filepath.Join(tree, "run-1")
	return fmt.Sprintf(`[{"path":%q,"access":"read_write"},{"path":%q,"access":"read_only"},{"path":%q,"access":"read_only"},{"path":%q,"access":"read_write"},{"path":%q,"access":"read_write"}]`,
		filepath.Join(tree, "cache"),
		filepath.Join(tree, "repos", "helper"),
		workspace,
		filepath.Join(workspace, "pipeline-outputs"),
		filepath.Join(workspace, "project"))
}

// TestHTTPSessionFilesystemOmittedInheritsCeiling proves the compatibility
// contract: a create without filesystem_roots produces the exact inherited
// derived snapshot — the workspace root with its effective ceiling mode plus
// every ceiling transition strictly inside the workspace.
func TestHTTPSessionFilesystemOmittedInheritsCeiling(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	// The full multi-root issuance contract (external absolute roots) is a
	// system-mode capability; user mode restricts filesystem roots to the
	// canonical workspace and is proven separately.
	app.Config.Mode = ModeSystem
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

// TestHTTPSessionFilesystemEmptyArrayInherits proves the empty-array
// presence contract: an explicit empty filesystem_roots array is the
// workspace-only create — the inherited derived snapshot, byte-for-byte.
func TestHTTPSessionFilesystemEmptyArrayInherits(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	setupTestLoggingDiscard(t)
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)

	rec := postSessionThroughMux(t, app, launcherToken, rootsRequestBody(workspace, `[]`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("empty-array create = %d, want 201: %s", rec.Code, rec.Body.String())
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
		t.Errorf("empty-array snapshot = %s, want %s (err=%v)", got, want, err)
	}
}

// TestHTTPSessionFilesystemPresenceRefusals proves the one-code presence
// contract of filesystem_roots: null and every malformed shape are refused
// 400 invalid_filesystem_policy before the Session exists (the empty array
// is the inherited workspace-only create, proven separately).
func TestHTTPSessionFilesystemPresenceRefusals(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	setupTestLoggingDiscard(t)
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)

	for name, roots := range map[string]string{
		"json null":            `null`,
		"unknown nested field": `[{"path":"/opt/x","access":"read_only","extra":1}]`,
		"unknown access":       `[{"path":"/opt/x","access":"writable"}]`,
		"missing access":       `[{"path":"/opt/x"}]`,
		"null access":          `[{"path":"/opt/x","access":null}]`,
		"relative path":        `[{"path":"project","access":"read_write"}]`,
		"parent traversal":     `[{"path":"../escape","access":"read_only"}]`,
		"non-object root":      `["/opt/x"]`,
		"wrong entry type":     `[{"path":5,"access":"read_only"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			before := countLiveSessions(t, app)
			rec := postSessionThroughMux(t, app, launcherToken, rootsRequestBody(workspace, roots))
			assertRefusal(t, rec)
			if after := countLiveSessions(t, app); after != before {
				t.Errorf("refused create left %d sessions, want %d", after, before)
			}
		})
	}
}

// TestHTTPSessionFilesystemCanonicalizationRefusals proves the absolute-path
// identity contract: roots are canonicalized as absolute host paths (symlink
// resolution, existing directory or regular file), and an unresolvable root
// or a duplicate canonical identity is refused before the Session exists.
func TestHTTPSessionFilesystemCanonicalizationRefusals(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	setupTestLoggingDiscard(t)
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)
	tree := filepath.Join(app.Config.AllowedRoots[0].Path, "runs")
	helper := filepath.Join(tree, "repos", "helper")

	for name, roots := range map[string]string{
		"nonexistent path": fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, filepath.Join(tree, "missing")),
		"unresolvable symlink": func() string {
			link := filepath.Join(tree, "dangling-link")
			if err := os.Symlink(filepath.Join(tree, "not-there"), link); err != nil {
				t.Fatal(err)
			}
			return fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, link)
		}(),
		"duplicate canonical path": func() string {
			alias := filepath.Join(tree, "helper-alias")
			if err := os.Symlink(helper, alias); err != nil {
				t.Fatal(err)
			}
			return fmt.Sprintf(`[{"path":%q,"access":"read_only"},{"path":%q,"access":"read_write"}]`, helper, alias)
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			before := countLiveSessions(t, app)
			rec := postSessionThroughMux(t, app, launcherToken, rootsRequestBody(workspace, roots))
			assertRefusal(t, rec)
			if after := countLiveSessions(t, app); after != before {
				t.Errorf("refused create left %d sessions, want %d", after, before)
			}
		})
	}

	// A canonical symlink alias is one identity, never a second authority:
	// the alias spelling resolves to the canonical root and is accepted as
	// that root (an explicit workspace-root alias replaces the implicit
	// grant under the same rule).
	alias := filepath.Join(tree, "helper-alias2")
	if err := os.Symlink(helper, alias); err != nil {
		t.Fatal(err)
	}
	rec := postSessionThroughMux(t, app, launcherToken, rootsRequestBody(workspace,
		fmt.Sprintf(`[{"path":%q,"access":"read_only"}]`, alias)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("alias create = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	showRec := showSessionThroughMux(t, app, testAdminToken, createdSessionID(t, rec))
	if showRec.Code != http.StatusOK {
		t.Fatalf("show = %d: %s", showRec.Code, showRec.Body.String())
	}
	var show sessionShowJSON
	if err := json.Unmarshal(showRec.Body.Bytes(), &show); err != nil {
		t.Fatalf("cannot decode show body: %v", err)
	}
	// The canonical snapshot: the alias resolved to the helper root, and the
	// workspace implicit grant keeps the protected pipeline-inputs ceiling
	// transition.
	want := fmt.Sprintf(`[{"path":%q,"access":"read_only"},{"path":%q,"access":"read_write"},{"path":%q,"access":"read_only"}]`,
		helper, workspace, filepath.Join(workspace, "pipeline-inputs"))
	if got, err := json.Marshal(show.FilesystemSnapshot.Entries); err != nil || string(got) != want {
		t.Errorf("alias snapshot = %s, want %s (err=%v)", got, want, err)
	}
}

// TestHTTPSessionFilesystemCeilingRefusals proves the privilege rule: an
// explicit read_write under an effective read_only region and a root outside
// the effective Launcher ceiling are refused before the Session exists.
func TestHTTPSessionFilesystemCeilingRefusals(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	setupTestLoggingDiscard(t)
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)
	tree := filepath.Join(app.Config.AllowedRoots[0].Path, "runs")

	for name, roots := range map[string]string{
		"widen pipeline-inputs": fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, filepath.Join(workspace, "pipeline-inputs")),
		"outside ceiling":       `[{"path":"/srv/elsewhere","access":"read_write"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			before := countLiveSessions(t, app)
			rec := postSessionThroughMux(t, app, launcherToken, rootsRequestBody(workspace, roots))
			assertRefusal(t, rec)
			if after := countLiveSessions(t, app); after != before {
				t.Errorf("refused create left %d sessions, want %d", after, before)
			}
		})
	}

	// Explicit workspace root replacement may not widen either: read_write
	// for a workspace whose effective ceiling mode is read_only.
	roWorkspaceRoot := filepath.Join(tree, "ro-ws")
	if err := os.MkdirAll(filepath.Join(roWorkspaceRoot, "data"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := addPrincipalAllowedRoot(app.DB, "narrower", roWorkspaceRoot, AllowedRootAccessReadOnly, allowedRootPaths(app.getConfig().AllowedRoots)); err != nil {
		t.Fatalf("addPrincipalAllowedRoot(ro-ws): %v", err)
	}
	rec := postSessionThroughMux(t, app, launcherToken, rootsRequestBody(roWorkspaceRoot,
		fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, roWorkspaceRoot)))
	assertRefusal(t, rec)
}

// TestHTTPSessionFilesystemRefusalDoesNotDiscloseCanonicalPath proves the
// non-disclosing refusal contract: the HTTP refusal carries the stable code
// and the bounded message only — never the resolved canonical symlink target
// or any upstream policy path. The internal diagnostic (which does carry the
// canonical requested path) stays in the operational log.
func TestHTTPSessionFilesystemRefusalDoesNotDiscloseCanonicalPath(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	setupTestLoggingDiscard(t)
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)

	// A symlink alias resolving into the protected read-only region: the
	// canonicalized root names the canonical target path in the internal
	// diagnostic, and the widening request is refused.
	alias := filepath.Join(workspace, "alias")
	if err := os.Symlink(filepath.Join(workspace, "pipeline-inputs"), alias); err != nil {
		t.Fatal(err)
	}
	rec := postSessionThroughMux(t, app, launcherToken, rootsRequestBody(workspace,
		fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, alias)))
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

// TestSessionFilesystemOutsideCeilingBranchIsCeilingCheck proves the branch
// distinction behind the MR3 UAT proof: for an existing path outside the
// effective Launcher ceiling, the canonicalization stage (the existence/
// resolvability branch) succeeds, and the refusal is reached in the ceiling
// check — the domain diagnostic names the outside-the-effective-launcher-policy
// refusal, never an unresolvable-path canonicalization failure. The same
// public invalid_filesystem_policy family has a different branch per cause.
func TestSessionFilesystemOutsideCeilingBranchIsCeilingCheck(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "marker.txt"), []byte("outside"), 0644); err != nil {
		t.Fatal(err)
	}

	// The existing outside path passes canonicalization: existence and
	// resolvability are proven, so any refusal downstream is not the
	// unresolvable-path branch.
	canonical, err := canonicalizeSessionFilesystemRoots([]sessionFilesystemRootEntry{
		{Path: outside, Access: "read_write"},
	})
	if err != nil {
		t.Fatalf("existing outside path failed canonicalization (wrong branch): %v", err)
	}
	if len(canonical) != 1 || canonical[0].Path != outside {
		t.Fatalf("canonicalization identity = %v, want [%s]", canonical, outside)
	}

	// The ceiling check is the reached branch: the refusal names the
	// outside-the-effective-launcher-policy diagnostic (a stable internal
	// fact this lower-level owner owns) and carries the typed family.
	ceiling := []AllowedRootEntry{{Path: app.Config.AllowedRoots[0].Path, Access: AllowedRootAccessReadWrite}}
	_, err = narrowSessionFilesystemPolicy(ceiling, app.Config.AllowedRoots[0].Path, canonical)
	if !errors.Is(err, ErrInvalidSessionFilesystemPolicy) {
		t.Fatalf("refusal = %v, want the ErrInvalidSessionFilesystemPolicy family", err)
	}
	if !strings.Contains(err.Error(), "outside the effective launcher policy") {
		t.Errorf("refusal = %v, want the ceiling-check branch diagnostic", err)
	}
	if strings.Contains(err.Error(), "cannot be resolved") || strings.Contains(err.Error(), "cannot be accessed") {
		t.Errorf("refusal reached the canonicalization branch instead of the ceiling check: %v", err)
	}
}

// TestHTTPLauncherCredentialRoots proves the motivating capability under a
// Launcher credential: the credential issues its Session with external
// absolute filesystem roots and an explicitly narrowed workspace, the issued
// snapshot is exactly the canonical normalized multi-root semantics, and an
// attempted widening is refused with no additional Session created.
func TestHTTPLauncherCredentialRoots(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	auditBuf, _ := setupTestLogging(t)
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)

	before := countLiveSessions(t, app)
	rec := postSessionThroughMux(t, app, launcherToken, rootsRequestBody(workspace, successfulNarrowingRoots(app)))
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
	if got, err := json.Marshal(show.FilesystemSnapshot.Entries); err != nil || string(got) != wantSnapshotJSON(app) {
		t.Errorf("issued snapshot = %s, want %s (err=%v)", got, wantSnapshotJSON(app), err)
	}
	snapshot, err := newSessionFilesystemSnapshot(show.Workspace, show.FilesystemSnapshot.Entries)
	if err != nil {
		t.Fatalf("issued snapshot is not the canonical representation: %v", err)
	}
	tree := filepath.Join(app.Config.AllowedRoots[0].Path, "runs")
	// The external roots resolve through the snapshot, each with its own
	// effective semantics.
	if access, ok := snapshot.LookupAccess(filepath.Join(tree, "repos", "helper", "main.go")); !ok || access != AllowedRootAccessReadOnly {
		t.Errorf("helper effective access = %q (ok=%v), want read_only", access, ok)
	}
	if snapshot.CanExposeWritable(filepath.Join(tree, "repos", "helper")) {
		t.Error("helper must not be writable-exposable")
	}
	if access, ok := snapshot.LookupAccess(filepath.Join(tree, "cache", "out.bin")); !ok || access != AllowedRootAccessReadWrite {
		t.Errorf("cache effective access = %q (ok=%v), want read_write", access, ok)
	}
	if !snapshot.CanExposeWritable(filepath.Join(tree, "cache")) {
		t.Error("cache must be writable-exposable")
	}
	// The workspace explicit read-only narrowing survives normalization and
	// keeps the pipeline-inputs protection effective.
	if access, ok := snapshot.LookupAccess(filepath.Join(workspace, "pipeline-inputs")); !ok || access != AllowedRootAccessReadOnly {
		t.Errorf("pipeline-inputs effective access = %q (ok=%v), want read_only", access, ok)
	}
	if snapshot.CanExposeWritable(workspace) {
		t.Error("explicitly narrowed workspace must not be writable-exposable")
	}

	// Attempted widening: read_write under the effective read_only region is
	// refused before the Session exists; no additional Session is created.
	widening := fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, filepath.Join(workspace, "pipeline-inputs"))
	rec = postSessionThroughMux(t, app, launcherToken, rootsRequestBody(workspace, widening))
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

// TestHTTPSessionFilesystemAuthoritySymmetry proves the filesystem-roots
// contract is one Session-create contract for every authority: Admin (with
// an explicit Launcher selector) and a Principal credential get the same
// multi-root snapshot as the Launcher credential and receive the same
// widening refusal.
func TestHTTPSessionFilesystemAuthoritySymmetry(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	setupTestLoggingDiscard(t)
	principalToken, _, launcherID, workspace := setupSessionNarrowingFixture(t, app)

	for name, token := range map[string]string{
		"admin":                testAdminToken,
		"principal credential": principalToken,
	} {
		t.Run(name, func(t *testing.T) {
			body := fmt.Sprintf(`{"workspace":%q,"launcher_id":%q,"filesystem_roots":%s}`,
				workspace, launcherID, successfulNarrowingRoots(app))
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
			if got, err := json.Marshal(show.FilesystemSnapshot.Entries); err != nil || string(got) != wantSnapshotJSON(app) {
				t.Errorf("issued snapshot = %s, want %s (err=%v)", got, wantSnapshotJSON(app), err)
			}

			// The widening attempt is a structurally valid absolute-root
			// request refused specifically because
			// pipeline-inputs=read_write tries to widen the effective
			// read_only ceiling at that path.
			afterNarrow := countLiveSessions(t, app)
			widening := fmt.Sprintf(`{"workspace":%q,"launcher_id":%q,"filesystem_roots":[{"path":%q,"access":"read_write"}]}`,
				workspace, launcherID, filepath.Join(workspace, "pipeline-inputs"))
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
