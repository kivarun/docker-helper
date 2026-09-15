package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// workspaceOracleCases builds the unauthorized workspace fixtures outside the
// test allowed root: an existing directory, a missing path, a dangling
// symlink, and — when the process cannot bypass Unix DAC — a child of a
// non-searchable directory. Every spelling is outside the effective ceiling,
// so the public outcomes must not depend on the host filesystem state.
func workspaceOracleCases(t *testing.T, root string) []struct {
	name      string
	workspace string
} {
	t.Helper()
	base := filepath.Dir(root)
	outsideExisting := filepath.Join(base, "oracle-existing")
	if err := os.MkdirAll(outsideExisting, 0755); err != nil {
		t.Fatal(err)
	}
	outsideMissing := filepath.Join(base, "oracle-missing")
	dangling := filepath.Join(base, "oracle-dangling-link")
	if err := os.Symlink(outsideMissing, dangling); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(dangling) })

	cases := []struct {
		name      string
		workspace string
	}{
		{name: "existing outside ceiling", workspace: outsideExisting},
		{name: "missing outside ceiling", workspace: outsideMissing},
		{name: "dangling symlink outside ceiling", workspace: dangling},
	}
	if runtime.GOOS != "windows" && os.Getuid() != 0 {
		denied := filepath.Join(base, "oracle-denied")
		if err := os.MkdirAll(denied, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(denied, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(denied, 0755) })
		cases = append(cases, struct {
			name      string
			workspace string
		}{name: "permission denied outside ceiling", workspace: filepath.Join(denied, "child")})
	}
	return cases
}

// TestUnauthorizedWorkspaceRefusalsAreIndistinguishable proves the
// authorization-gated resolver-detail boundary: for workspace request
// spellings that are not inside the effective allowed-root ceiling, the
// public Session-create outcome must be identical regardless of the host
// filesystem state of the requested path — existing, missing, dangling
// symlink, or permission-denied. A distinct outcome for any of these states
// discloses host filesystem detail for paths the authority was never issued:
// the audited H3 filesystem oracle.
func TestUnauthorizedWorkspaceRefusalsAreIndistinguishable(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path

	var firstCode, firstMessage string
	for _, tc := range workspaceOracleCases(t, root) {
		resp := createSessionThroughMux(app, testAdminToken, tc.workspace)
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d (body=%s)", tc.name, resp.Code, resp.Body.String())
		}
		err := decodeAPIError(t, resp.Body.Bytes())
		if err.Code != "invalid_workspace" {
			t.Fatalf("%s: expected invalid_workspace, got %q (body=%s)", tc.name, err.Code, resp.Body.String())
		}
		if firstCode == "" {
			firstCode, firstMessage = err.Code, err.Message
			continue
		}
		if err.Message != firstMessage {
			t.Fatalf("%s: message %q differs from the first unauthorized outcome %q — host filesystem detail disclosed for an unauthorized path",
				tc.name, err.Message, firstMessage)
		}
	}
}

// TestAuthorizedWorkspaceFilesystemSemanticsPreserved proves the authorized
// workspace states keep their current correct filesystem semantics: an
// existing workspace inside the ceiling is issued, a missing workspace
// inside the ceiling keeps its actionable operator diagnostic, a symlink
// alias resolving inside the ceiling is issued, and a symlink escaping the
// ceiling is refused by the canonical containment proof.
func TestAuthorizedWorkspaceFilesystemSemanticsPreserved(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path
	home := filepath.Join(root, "home", "wsauth")
	work := filepath.Join(home, "work")
	if err := os.MkdirAll(work, 0755); err != nil {
		t.Fatal(err)
	}

	// E: authorized existing workspace.
	resp := createSessionThroughMux(app, testAdminToken, work)
	if resp.Code != http.StatusCreated {
		t.Fatalf("authorized existing: expected 201, got %d (body=%s)", resp.Code, resp.Body.String())
	}

	// F: authorized missing workspace — an operator mistake inside their own
	// ceiling keeps the actionable diagnostic.
	missing := filepath.Join(home, "not-created-yet")
	resp = createSessionThroughMux(app, testAdminToken, missing)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("authorized missing: expected 400, got %d (body=%s)", resp.Code, resp.Body.String())
	}
	errResp := decodeAPIError(t, resp.Body.Bytes())
	if errResp.Code != "invalid_workspace" {
		t.Fatalf("authorized missing: expected invalid_workspace, got %q", errResp.Code)
	}
	if errResp.Message == "workspace must be inside an allowed root" {
		t.Fatalf("authorized missing workspace lost its actionable diagnostic: %q", errResp.Message)
	}

	// G (Release 2.2 security tightening): a raw spelling outside the
	// ceiling is no longer admitted even when it would resolve inside it
	// through a symlink — bounded authorization refusal, and the resolver is
	// never invoked for the unadmitted spelling (zero-probe proof below).
	alias := filepath.Join(filepath.Dir(root), "oracle-authorized-alias")
	if err := os.Symlink(home, alias); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(alias) })
	aliasWorkspace := filepath.Join(alias, "work")
	resp = createSessionThroughMux(app, testAdminToken, aliasWorkspace)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("outside lexical alias: expected 400, got %d (body=%s)", resp.Code, resp.Body.String())
	}
	if msg := decodeAPIError(t, resp.Body.Bytes()).Message; msg != "workspace must be inside an allowed root" {
		t.Fatalf("outside lexical alias: expected the bounded authorization refusal, got %q", msg)
	}

	// G2 (preserved): a symlink spelling INSIDE the lexical ceiling that
	// resolves inside the ceiling is still issued — the alias semantics
	// remain for spellings that carry the lexical capability admission.
	insideAlias := filepath.Join(home, "work-alias")
	if err := os.Symlink(work, insideAlias); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(insideAlias) })
	resp = createSessionThroughMux(app, testAdminToken, insideAlias)
	if resp.Code != http.StatusCreated {
		t.Fatalf("inside-ceiling alias: expected 201, got %d (body=%s)", resp.Code, resp.Body.String())
	}

	// H: authorized-spelling symlink escaping the ceiling — the resolved path
	// fails the canonical containment proof.
	escape := filepath.Join(home, "escape-link")
	if err := os.Symlink(filepath.Dir(root), escape); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(escape) })
	resp = createSessionThroughMux(app, testAdminToken, escape)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("authorized escape: expected 400, got %d (body=%s)", resp.Code, resp.Body.String())
	}
	if msg := decodeAPIError(t, resp.Body.Bytes()).Message; msg != "workspace must be inside an allowed root" {
		t.Fatalf("authorized escape: expected the containment refusal, got %q", msg)
	}
}

// sessionBearerWorkspace provisions an admin-issued Session whose workspace
// is inside the test allowed root and returns the app and session bearer.
func sessionBearerWorkspace(t *testing.T, app *App, name string) (string, string) {
	t.Helper()
	root := app.Config.AllowedRoots[0].Path
	home := filepath.Join(root, "home", name)
	work := filepath.Join(home, "work")
	if err := os.MkdirAll(work, 0755); err != nil {
		t.Fatal(err)
	}
	created, err := app.createSessionAuthorized(&operatorAuthority{class: operatorAuthorityAdmin}, createSelector{}, work, nil)
	if err != nil {
		t.Fatalf("createSessionAuthorized(%s): %v", name, err)
	}
	return work, created.Token
}

// TestUnauthorizedRunMountRefusalsAreIndistinguishable proves the run data
// plane's public boundary: mount sources outside the issued Session
// filesystem snapshot — existing, missing, or a dangling symlink — answer
// the same stable non-disclosing invalid_mount contract, and the resolver's
// host-filesystem diagnostics stay in the operational log.
func TestUnauthorizedRunMountRefusalsAreIndistinguishable(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	auditBuf, opBuf := setupTestLogging(t)
	initLoggers(opBuf, auditBuf, slog.LevelWarn, true)
	_, token := sessionBearerWorkspace(t, app, "mountoracle")

	base := filepath.Dir(app.Config.AllowedRoots[0].Path)
	existing := filepath.Join(base, "oracle-run-existing")
	if err := os.MkdirAll(existing, 0755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(base, "oracle-run-missing")
	dangling := filepath.Join(base, "oracle-run-dangling")
	if err := os.Symlink(missing, dangling); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(dangling) })

	var firstBody string
	for _, source := range []string{existing, missing, dangling} {
		body := fmt.Sprintf(`{"image":"alpine:latest","mounts":[{"source":%q,"target":"/data","read_only":true}]}`, source)
		req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		app.handleRun(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("source %q: expected 400, got %d (body=%s)", source, w.Code, w.Body.String())
		}
		got := w.Body.String()
		if !strings.Contains(got, "invalid_mount") {
			t.Fatalf("source %q: expected invalid_mount, got %s", source, got)
		}
		if firstBody == "" {
			firstBody = got
			continue
		}
		if got != firstBody {
			t.Fatalf("source %q: response %s differs from the first unauthorized outcome %s — host filesystem state disclosed",
				source, got, firstBody)
		}
	}

	// The admission diagnostics are retained operationally (the resolver is
	// never invoked for an unadmitted spelling, so no filesystem detail
	// exists — only the authorization fact).
	if !strings.Contains(opBuf.String(), "outside the issued session filesystem snapshot") {
		t.Fatalf("admission diagnostics lost from the operational log: %s", opBuf.String())
	}
	if strings.Contains(opBuf.String(), "no such file or directory") {
		t.Fatalf("unadmitted spelling reached the filesystem resolver: %s", opBuf.String())
	}
}

// TestUnauthorizedBuildContextRefusalsAreIndistinguishable proves the build
// data plane's public boundary: build-context spellings outside the session
// workspace — existing, missing, or a dangling symlink — answer the same
// stable non-disclosing invalid_build_context contract, and the resolver's
// host-filesystem diagnostics stay in the operational log.
func TestUnauthorizedBuildContextRefusalsAreIndistinguishable(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	auditBuf, opBuf := setupTestLogging(t)
	initLoggers(opBuf, auditBuf, slog.LevelWarn, true)
	_, token := sessionBearerWorkspace(t, app, "buildoracle")

	base := filepath.Dir(app.Config.AllowedRoots[0].Path)
	existing := filepath.Join(base, "oracle-build-existing")
	if err := os.MkdirAll(existing, 0755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(base, "oracle-build-missing")
	dangling := filepath.Join(base, "oracle-build-dangling")
	if err := os.Symlink(missing, dangling); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(dangling) })

	var firstBody string
	for _, context := range []string{existing, missing, dangling} {
		body := fmt.Sprintf(`{"image":"alpine:latest","context":%q,"dockerfile":"Dockerfile"}`, context)
		req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		app.handleBuild(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("context %q: expected 400, got %d (body=%s)", context, w.Code, w.Body.String())
		}
		got := w.Body.String()
		if !strings.Contains(got, "invalid_build_context") {
			t.Fatalf("context %q: expected invalid_build_context, got %s", context, got)
		}
		if firstBody == "" {
			firstBody = got
			continue
		}
		if got != firstBody {
			t.Fatalf("context %q: response %s differs from the first unauthorized outcome %s — host filesystem state disclosed",
				context, got, firstBody)
		}
	}

	if !strings.Contains(opBuf.String(), "context must be inside workspace") {
		t.Fatalf("admission diagnostics lost from the operational log: %s", opBuf.String())
	}
	if strings.Contains(opBuf.String(), "no such file or directory") {
		t.Fatalf("unadmitted spelling reached the filesystem resolver: %s", opBuf.String())
	}
}

// TestUnauthorizedWorkspaceDiagnosticRetainedInOperationalLog proves the
// operational-log contract of the authorization-before-probing boundary:
// an unadmitted spelling is refused with only the authorization fact (no
// host filesystem detail exists to retain, because the resolver is never
// invoked), while an admitted spelling keeps its full internal resolution
// diagnostic in the operational log — the actionable cause stays where the
// contract promises it, and no secret material is ever logged.
func TestUnauthorizedWorkspaceDiagnosticRetainedInOperationalLog(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	auditBuf, opBuf := setupTestLogging(t)
	initLoggers(opBuf, auditBuf, slog.LevelWarn, true)
	root := app.Config.AllowedRoots[0].Path

	// Unadmitted spellings: bounded refusals only — the resolver is never
	// invoked, so no existence/error-class/pathname detail exists.
	for _, tc := range workspaceOracleCases(t, root) {
		resp := createSessionThroughMux(app, testAdminToken, tc.workspace)
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d (body=%s)", tc.name, resp.Code, resp.Body.String())
		}
	}
	for _, leaked := range []string{"no such file or directory", "permission denied", "lstat "} {
		if strings.Contains(opBuf.String(), leaked) {
			t.Fatalf("unadmitted spelling produced a filesystem diagnostic %q: %s", leaked, opBuf.String())
		}
	}

	// An admitted spelling keeps its internal resolution diagnostic in the
	// operational log (the authorized-missing operator mistake).
	home := filepath.Join(root, "home", "diagretained")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(home, "not-created-yet")
	resp := createSessionThroughMux(app, testAdminToken, missing)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("admitted missing workspace: expected 400, got %d (body=%s)", resp.Code, resp.Body.String())
	}
	if !strings.Contains(opBuf.String(), "cannot resolve workspace symlinks") {
		t.Fatalf("admitted-spelling resolution diagnostic lost from the operational log: %s", opBuf.String())
	}
	assertNoSecrets(t, opBuf.String(), map[string]any{}, testAdminToken, testAdminToken)
}

// countSessionPathProbes swaps the session-facing filesystem-probe seams
// (evalSymlinksFn/osStatFn — the privileged host-filesystem probes of the
// workspace admission, filesystem-roots canonicalization, mount resolution,
// and build-input validation sites) with counting wrappers and returns a
// reset, a counter reader, and a reader for the probed pathname arguments.
// Test infrastructure only; the wrapped defaults restore on cleanup.
func countSessionPathProbes(t *testing.T) (reset func(), probes func() int, probePaths func() []string) {
	t.Helper()
	origEval, origStat := evalSymlinksFn, osStatFn
	var calls int
	var paths []string
	evalSymlinksFn = func(p string) (string, error) {
		calls++
		paths = append(paths, p)
		return origEval(p)
	}
	osStatFn = func(p string) (os.FileInfo, error) {
		calls++
		paths = append(paths, p)
		return origStat(p)
	}
	t.Cleanup(func() {
		evalSymlinksFn, osStatFn = origEval, origStat
	})
	return func() { calls = 0; paths = nil }, func() int { return calls }, func() []string { return paths }
}

// TestWorkspaceCreateOutsideCeilingProbesNothing proves the
// authorization-before-probing ordering at the Session-create workspace
// boundary: a raw spelling outside the effective allowed-root ceiling is
// refused WITHOUT a single privileged filesystem probe — not merely with an
// equal HTTP response. Any probe would collect existence/error-class/
// alias detail for a pathname the authority was never issued.
func TestWorkspaceCreateOutsideCeilingProbesNothing(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path

	reset, probes, _ := countSessionPathProbes(t)
	for _, tc := range workspaceOracleCases(t, root) {
		reset()
		resp := createSessionThroughMux(app, testAdminToken, tc.workspace)
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d (body=%s)", tc.name, resp.Code, resp.Body.String())
		}
		if n := probes(); n != 0 {
			t.Fatalf("%s: %d privileged filesystem probe(s) before lexical admission", tc.name, n)
		}
		if msg := decodeAPIError(t, resp.Body.Bytes()).Message; msg != "workspace must be inside an allowed root" {
			t.Fatalf("%s: expected the bounded authorization refusal, got %q", tc.name, msg)
		}
	}
}

// TestRunMountOutsideSnapshotProbesNothing proves the run data plane's
// ordering: an absolute mount source spelling outside the issued Session
// filesystem snapshot is refused without a single privileged filesystem
// probe; the resolution and stat of an admitted spelling (and the final
// canonical containment proof) are unchanged.
func TestRunMountOutsideSnapshotProbesNothing(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	_, token := sessionBearerWorkspace(t, app, "probefreemount")

	base := filepath.Dir(app.Config.AllowedRoots[0].Path)
	existing := filepath.Join(base, "oracle-probe-existing")
	if err := os.MkdirAll(existing, 0755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(base, "oracle-probe-missing")
	dangling := filepath.Join(base, "oracle-probe-dangling")
	if err := os.Symlink(missing, dangling); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(dangling) })

	reset, probes, _ := countSessionPathProbes(t)
	for _, source := range []string{existing, missing, dangling} {
		reset()
		body := fmt.Sprintf(`{"image":"alpine","mounts":[{"source":%q,"target":"/data","read_only":true}]}`, source)
		req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		app.handleRun(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("source %q: expected 400, got %d (body=%s)", source, w.Code, w.Body.String())
		}
		if n := probes(); n != 0 {
			t.Fatalf("source %q: %d privileged filesystem probe(s) before lexical admission", source, n)
		}
	}
}

// TestBuildContextOutsideWorkspaceProbesNothing proves the build data
// plane's ordering: a context spelling outside the session workspace —
// absolute outside, relative escape, or dangling-symlink alias — is refused
// without a single privileged filesystem probe.
func TestBuildContextOutsideWorkspaceProbesNothing(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	_, token := sessionBearerWorkspace(t, app, "probefreebuild")

	base := filepath.Dir(app.Config.AllowedRoots[0].Path)
	existing := filepath.Join(base, "oracle-bprobe-existing")
	if err := os.MkdirAll(existing, 0755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(base, "oracle-bprobe-missing")
	dangling := filepath.Join(base, "oracle-bprobe-dangling")
	if err := os.Symlink(missing, dangling); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(dangling) })

	reset, probes, _ := countSessionPathProbes(t)
	for _, context := range []string{existing, missing, dangling, "../probe-escape"} {
		reset()
		body := fmt.Sprintf(`{"image":"alpine","context":%q,"dockerfile":"Dockerfile"}`, context)
		req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		app.handleBuild(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("context %q: expected 400, got %d (body=%s)", context, w.Code, w.Body.String())
		}
		if n := probes(); n != 0 {
			t.Fatalf("context %q: %d privileged filesystem probe(s) before lexical admission", context, n)
		}
	}
}

// TestAdmittedSpellingStillProbesAndStaysContained proves the second half of
// the ordering: after lexical admission the privileged probes still run, and
// a symlink inside the lexical capability that resolves outside is still
// fail-closed by the canonical containment proof (no probe-free shortcut for
// admitted spellings).
func TestAdmittedSpellingStillProbesAndStaysContained(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path
	home := filepath.Join(root, "home", "admitted")
	work := filepath.Join(home, "work")
	if err := os.MkdirAll(work, 0755); err != nil {
		t.Fatal(err)
	}

	// An admitted missing spelling still resolves: the probe count is
	// non-zero (the resolver runs for admitted spellings).
	reset, probes, _ := countSessionPathProbes(t)
	resp := createSessionThroughMux(app, testAdminToken, filepath.Join(home, "missing"))
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("admitted missing: expected 400, got %d (body=%s)", resp.Code, resp.Body.String())
	}
	if probes() == 0 {
		t.Fatal("admitted spelling was not resolved by the filesystem resolver")
	}
	reset()

	// A symlink inside the lexical ceiling that resolves outside is still
	// refused by the canonical containment proof.
	escape := filepath.Join(home, "escape-link")
	if err := os.Symlink(filepath.Dir(root), escape); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(escape) })
	resp = createSessionThroughMux(app, testAdminToken, escape)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("escape link: expected 400, got %d (body=%s)", resp.Code, resp.Body.String())
	}
	if msg := decodeAPIError(t, resp.Body.Bytes()).Message; msg != "workspace must be inside an allowed root" {
		t.Fatalf("escape link: expected the containment refusal, got %q", msg)
	}
}

// filesystemRootsOracleCases builds the issuance-time filesystem_roots
// fixtures outside the effective launcher ceiling: an existing directory, a
// missing path, a dangling symlink, and an outside symlink alias resolving
// into the ceiling. Every spelling is outside the ceiling, so the public
// outcomes must not depend on the host filesystem state of the requested
// root.
func filesystemRootsOracleCases(t *testing.T, root, tree string) []struct {
	name string
	path string
} {
	t.Helper()
	base := filepath.Dir(root)
	outsideExisting := filepath.Join(base, "oracle-roots-existing")
	if err := os.MkdirAll(outsideExisting, 0755); err != nil {
		t.Fatal(err)
	}
	outsideMissing := filepath.Join(base, "oracle-roots-missing")
	dangling := filepath.Join(base, "oracle-roots-dangling-link")
	if err := os.Symlink(outsideMissing, dangling); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(dangling) })

	// The outside alias resolves INTO the ceiling: the pre-tightening
	// canonicalization admitted it through its resolution. The lexical
	// admission must refuse it without probing (no compatibility alias).
	alias := filepath.Join(base, "oracle-roots-alias")
	if err := os.Symlink(tree, alias); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(alias) })

	return []struct {
		name string
		path string
	}{
		{name: "existing outside ceiling", path: outsideExisting},
		{name: "missing outside ceiling", path: outsideMissing},
		{name: "dangling symlink outside ceiling", path: dangling},
		{name: "outside alias into ceiling", path: alias},
	}
}

// TestFilesystemRootsOutsideCeilingProbesNothing proves the
// authorization-before-probing ordering at the issuance-time filesystem_roots
// boundary: a caller-supplied root spelling outside the effective launcher
// ceiling is refused invalid_filesystem_policy without a single privileged
// filesystem probe of the requested pathname — existing, missing, dangling
// symlink, or an outside alias resolving into the ceiling (the same alias
// tightening as the workspace boundary: no compatibility admission through
// resolution). No Session state exists after any refusal, only the two
// workspace-admission probes run, and no probe argument names the requested
// root spelling.
func TestFilesystemRootsOutsideCeilingProbesNothing(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	setupTestLoggingDiscard(t)
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)
	root := app.Config.AllowedRoots[0].Path
	tree := filepath.Join(root, "runs")

	reset, probes, probePaths := countSessionPathProbes(t)
	for _, tc := range filesystemRootsOracleCases(t, root, tree) {
		reset()
		rec := postSessionThroughMux(t, app, launcherToken, rootsRequestBody(workspace, fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, tc.path)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d (body=%s)", tc.name, rec.Code, rec.Body.String())
		}
		errResp := decodeAPIError(t, rec.Body.Bytes())
		if errResp.Code != "invalid_filesystem_policy" {
			t.Fatalf("%s: expected invalid_filesystem_policy, got %q (body=%s)", tc.name, errResp.Code, rec.Body.String())
		}
		if errResp.Message != sessionFilesystemPolicyMessage {
			t.Fatalf("%s: message %q, want the bounded non-disclosing message %q", tc.name, errResp.Message, sessionFilesystemPolicyMessage)
		}
		if n := countLiveSessions(t, app); n != 0 {
			t.Fatalf("%s: %d live session(s) exist after the refusal", tc.name, n)
		}
		// Zero privileged probes of the requested root: exactly the two
		// workspace-admission probes run, and no probe argument names the
		// requested root spelling.
		if n := probes(); n != 2 {
			t.Fatalf("%s: %d privileged filesystem probe(s) before lexical admission (want exactly the 2 workspace-admission probes)", tc.name, n)
		}
		for _, p := range probePaths() {
			if strings.Contains(p, tc.path) {
				t.Fatalf("%s: privileged probe of the unadmitted root spelling %q", tc.name, p)
			}
		}
	}
}

// TestRunMountFileRootDescendantFollowsSnapshotTreeSemantics proves the
// accepted snapshot path-tree authority semantics at the run admission: a
// strict descendant of an issued root is admitted lexically against the
// issued snapshot entries regardless of the governing pathname's live kind,
// and the privileged resolver runs on it (a descendant of a regular-file
// root that still is a regular file is refused by the live filesystem
// mechanics — the child cannot resolve — with the stable public contract).
// The probe recording is the regression guard: any kind-gate that refuses
// before probing would silence the resolver for an admitted spelling.
func TestRunMountFileRootDescendantFollowsSnapshotTreeSemantics(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path
	tree := filepath.Join(root, "runs")
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)
	fileRoot := filepath.Join(tree, "repos", "data.bin")
	if err := os.WriteFile(fileRoot, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	rec := postSessionThroughMux(t, app, launcherToken, rootsRequestBody(workspace, fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, fileRoot)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("file-root create: expected 201, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("cannot decode create response: %v", err)
	}
	if created.Token == "" {
		t.Fatal("file-root create response carries no session bearer")
	}

	descendant := filepath.Join(fileRoot, "child")
	_, probes, probePaths := countSessionPathProbes(t)
	body := fmt.Sprintf(`{"image":"alpine","mounts":[{"source":%q,"target":"/data","read_only":true}]}`, descendant)
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+created.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("file-root descendant: expected 400, got %d (body=%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid_mount") {
		t.Fatalf("file-root descendant: expected invalid_mount, got %s", w.Body.String())
	}
	// The admitted descendant spelling reached the privileged resolver: the
	// refusal is the live-mechanics one (the child cannot resolve below a
	// regular file), never an authorization short-circuit.
	paths := probePaths()
	if n := probes(); n != 1 {
		t.Fatalf("file-root descendant: %d privileged probes, want exactly the resolver probe of the admitted spelling", n)
	}
	if len(paths) != 1 || paths[0] != descendant {
		t.Fatalf("file-root descendant: probed paths %v, want exactly the admitted descendant spelling %q", paths, descendant)
	}
}

// TestRunMountIssuedFileRootKeepsSnapshotPathTreeAuthority proves the
// accepted immutable-snapshot authority semantics the review round pinned:
// the Session snapshot persists and digests exactly position/path/access,
// and its authority is the issued PATH TREE — a root issued while it is a
// regular file authorizes the same pathname subtree after the live pathname
// is replaced by a directory, exactly as a directory issued root does. The
// authorization decision is made only from the persisted snapshot through
// the canonical loader (digest/integrity verified) and the snapshot
// exposure owner — never from live kind inference.
func TestRunMountIssuedFileRootKeepsSnapshotPathTreeAuthority(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path
	tree := filepath.Join(root, "runs")
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)
	fileRoot := filepath.Join(tree, "repos", "data.bin")
	if err := os.WriteFile(fileRoot, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	rec := postSessionThroughMux(t, app, launcherToken, rootsRequestBody(workspace, fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, fileRoot)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("file-root create: expected 201, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		Session struct {
			ID string `json:"id"`
		} `json:"session"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("cannot decode create response: %v", err)
	}
	if created.Session.ID == "" {
		t.Fatal("file-root create response carries no session ID")
	}

	// After issuance: replace the issued pathname with a directory and
	// create a descendant under it.
	if err := os.Remove(fileRoot); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(fileRoot, "child")
	if err := os.MkdirAll(fileRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(child, []byte("child"), 0644); err != nil {
		t.Fatal(err)
	}

	// The persisted immutable snapshot (digest/integrity verified by the
	// canonical loader) authorizes the descendant: the authority is the
	// issued path tree, independent of the live pathname kind.
	snapshot, err := loadSessionFilesystemSnapshot(app.DB, created.Session.ID, workspace)
	if err != nil {
		t.Fatalf("loadSessionFilesystemSnapshot: %v", err)
	}
	resolved, err := resolveMount(mountRequest{Source: child, Target: "/data", ReadOnly: true}, workspace, snapshot)
	if err != nil {
		t.Fatalf("descendant of the issued path tree: %v", err)
	}
	exposure, err := resolveSessionFilesystemExposure(snapshot, resolved.SourcePath, "/data", true)
	if err != nil {
		t.Fatalf("snapshot exposure of the descendant: %v", err)
	}
	if exposure.Access != AllowedRootAccessReadWrite {
		t.Fatalf("descendant exposure access = %q, want the issued root's read_write", exposure.Access)
	}

	// The boundary stays the snapshot: a spelling outside the issued path
	// tree is still refused without probing.
	reset, probes, _ := countSessionPathProbes(t)
	_, err = resolveMount(mountRequest{Source: filepath.Join(root, "elsewhere"), Target: "/data", ReadOnly: true}, workspace, snapshot)
	if err == nil || !strings.Contains(err.Error(), "outside the issued session filesystem snapshot") {
		t.Fatalf("outside-snapshot control: expected the bounded admission refusal, got %v", err)
	}
	if n := probes(); n != 0 {
		t.Fatalf("outside-snapshot control: %d privileged probes before lexical admission", n)
	}
	reset()
}

// TestFilesystemRootsAdmittedSpellingSemantics proves the second half of the
// filesystem_roots ordering: an admitted spelling is still resolved by the
// privileged probes (an existing directory root inside the ceiling is
// issued), the canonical ceiling proof stays fail-closed after probing (a
// symlink inside the lexical ceiling that resolves outside is refused), and
// an admitted missing root keeps its bounded unresolvable-root refusal — no
// probe-free shortcut for admitted spellings.
func TestFilesystemRootsAdmittedSpellingSemantics(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	setupTestLoggingDiscard(t)
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)
	root := app.Config.AllowedRoots[0].Path
	tree := filepath.Join(root, "runs")
	cache := filepath.Join(tree, "cache")

	// E: existing directory root inside the ceiling — probed and issued.
	reset, probes, _ := countSessionPathProbes(t)
	rec := postSessionThroughMux(t, app, launcherToken, rootsRequestBody(workspace, fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, cache)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("E existing root: expected 201, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if n := probes(); n != 4 { // 2 workspace-admission probes + 1 resolution + 1 stat of the root
		t.Fatalf("E existing root: %d probes, want 4", n)
	}

	// F: symlink inside the lexical ceiling resolving outside the ceiling —
	// probed, then refused by the canonical ceiling proof.
	reset()
	escape := filepath.Join(workspace, "roots-escape-link")
	if err := os.Symlink(filepath.Dir(root), escape); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(escape) })
	rec = postSessionThroughMux(t, app, launcherToken, rootsRequestBody(workspace, fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, escape)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("F escape root: expected 400, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeAPIError(t, rec.Body.Bytes()).Code; code != "invalid_filesystem_policy" {
		t.Fatalf("F escape root: expected invalid_filesystem_policy, got %q", code)
	}
	if n := probes(); n != 4 { // 2 workspace-admission probes + resolution + stat of the resolved target
		t.Fatalf("F escape root: %d probes, want 4 (probes ran before the canonical refusal)", n)
	}

	// G: missing root inside the ceiling — probed, then the bounded
	// unresolvable-root refusal.
	reset()
	missing := filepath.Join(cache, "missing-root")
	rec = postSessionThroughMux(t, app, launcherToken, rootsRequestBody(workspace, fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, missing)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("G missing root: expected 400, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if code := decodeAPIError(t, rec.Body.Bytes()).Code; code != "invalid_filesystem_policy" {
		t.Fatalf("G missing root: expected invalid_filesystem_policy, got %q", code)
	}
	if n := probes(); n != 3 { // 2 workspace-admission probes + 1 failed resolution
		t.Fatalf("G missing root: %d probes, want 3", n)
	}
}

// --- SC1/M11: the shared host-path text grammar at the Session admission ---

// TestSessionCreateControlCharacterTextGrammar proves the shared host-path
// text grammar at the Session-create admission boundary with its existing
// canonical error class: a REAL directory inside the ceiling whose pathname
// carries a control character that Unix permits (LF, TAB, DEL, C1) is
// refused invalid_workspace without a single privileged filesystem probe
// (the raw admitted spelling suffices), and a harmless-looking symlink
// spelling that resolves into a control-character pathname is refused after
// resolution by the post-resolution grammar check. No Session exists after
// either refusal. (DEL and the other C0/C1 runes are JSON-escaped
// explicitly: the transport-level encoding of such spellings is not the
// subject here — the grammar refusal is.)
func TestSessionCreateControlCharacterTextGrammar(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path
	home := filepath.Join(root, "home", "m11ws")
	mux := http.NewServeMux()
	registerRoutes(mux, app)
	post := func(workspace string) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]string{"workspace": workspace})
		if err != nil {
			t.Fatalf("cannot encode the workspace request: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+testAdminToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	raw := []struct {
		name string
		path string
	}{
		{"LF", filepath.Join(home, "with\nlf")},
		{"TAB", filepath.Join(home, "with\ttab")},
		{"DEL", filepath.Join(home, "with\x7fdel")},
		{"C1", filepath.Join(home, "with\u0085c1")},
	}
	for _, r := range raw {
		if err := os.MkdirAll(r.path, 0755); err != nil {
			t.Fatalf("%s: cannot create the real control-character directory: %v", r.name, err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(r.path) })
	}

	reset, probes, _ := countSessionPathProbes(t)
	for _, r := range raw {
		reset()
		resp := post(r.path)
		if resp.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d (body=%s)", r.name, resp.Code, resp.Body.String())
		}
		errResp := decodeAPIError(t, resp.Body.Bytes())
		if errResp.Code != "invalid_workspace" {
			t.Fatalf("%s: expected invalid_workspace, got %q (body=%s)", r.name, errResp.Code, resp.Body.String())
		}
		if !strings.Contains(errResp.Message, "control character") {
			t.Fatalf("%s: message %q, want the host-path text-grammar diagnostic", r.name, errResp.Message)
		}
		if n := probes(); n != 0 {
			t.Fatalf("%s: %d privileged filesystem probe(s) for a spelling the text grammar refuses", r.name, n)
		}
		if n := countLiveSessions(t, app); n != 0 {
			t.Fatalf("%s: %d live session(s) exist after the refusal", r.name, n)
		}
	}

	// Symlink spelling without controls resolving into a control-character
	// pathname: refused after resolution (probes ran — the spelling was
	// admitted — and the resolved canonical identity is refused).
	reset()
	target := filepath.Join(home, "resolved\ncontrol")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(target) })
	link := filepath.Join(home, "clean-alias")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
	symResp := post(link)
	if symResp.Code != http.StatusBadRequest {
		t.Fatalf("symlink alias: expected 400, got %d (body=%s)", symResp.Code, symResp.Body.String())
	}
	if errResp := decodeAPIError(t, symResp.Body.Bytes()); !strings.Contains(errResp.Message, "control character") {
		t.Fatalf("symlink alias: message %q, want the post-resolution text-grammar diagnostic", errResp.Message)
	}
	if probes() == 0 {
		t.Fatal("symlink alias: the admitted spelling was never resolved")
	}
	if n := countLiveSessions(t, app); n != 0 {
		t.Fatalf("symlink alias: %d live session(s) exist after the refusal", n)
	}
}

// TestFilesystemRootsControlCharacterTextGrammar proves the shared host-path
// text grammar at the issuance-time filesystem_roots boundary: a REAL
// directory root inside the ceiling whose pathname carries a control
// character is refused with the existing bounded invalid_filesystem_policy
// class and message, with no privileged probe of the requested root spelling
// and no Session state.
func TestFilesystemRootsControlCharacterTextGrammar(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	setupTestLoggingDiscard(t)
	_, launcherToken, _, workspace := setupSessionNarrowingFixture(t, app)
	root := app.Config.AllowedRoots[0].Path
	tree := filepath.Join(root, "runs")
	controlRoot := filepath.Join(tree, "cache\nlf")
	if err := os.MkdirAll(controlRoot, 0755); err != nil {
		t.Fatalf("cannot create the real control-character filesystem root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(controlRoot) })

	_, probes, probePaths := countSessionPathProbes(t)
	rec := postSessionThroughMux(t, app, launcherToken, rootsRequestBody(workspace, fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, controlRoot)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	errResp := decodeAPIError(t, rec.Body.Bytes())
	if errResp.Code != "invalid_filesystem_policy" {
		t.Fatalf("expected invalid_filesystem_policy, got %q (body=%s)", errResp.Code, rec.Body.String())
	}
	if errResp.Message != sessionFilesystemPolicyMessage {
		t.Fatalf("message %q, want the bounded non-disclosing message %q", errResp.Message, sessionFilesystemPolicyMessage)
	}
	if n := countLiveSessions(t, app); n != 0 {
		t.Fatalf("%d live session(s) exist after the refusal", n)
	}
	if n := probes(); n != 2 {
		t.Fatalf("%d privileged filesystem probe(s) (want exactly the 2 workspace-admission probes)", n)
	}
	for _, p := range probePaths() {
		if strings.Contains(p, controlRoot) {
			t.Fatalf("privileged probe of the control-character root spelling %q", p)
		}
	}
}
