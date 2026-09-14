package main

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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

	// G: authorized symlink alias — a raw spelling outside the ceiling that
	// resolves inside it is issued (canonical containment on the resolved
	// path).
	alias := filepath.Join(filepath.Dir(root), "oracle-authorized-alias")
	if err := os.Symlink(home, alias); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(alias) })
	aliasWorkspace := filepath.Join(alias, "work")
	resp = createSessionThroughMux(app, testAdminToken, aliasWorkspace)
	if resp.Code != http.StatusCreated {
		t.Fatalf("authorized alias: expected 201, got %d (body=%s)", resp.Code, resp.Body.String())
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
