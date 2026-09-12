package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// userModeRootsSession creates a user-mode Session through the canonical
// production owner with the given issuance-time filesystem roots (nil when
// omitted), resolving the daemon-owner default Launcher.
func userModeRootsSession(t *testing.T, app *App, workspace string, roots []sessionFilesystemRootEntry) (*CreatedSession, error) {
	t.Helper()
	return app.createSessionAuthorized(&operatorAuthority{class: operatorAuthorityAdmin}, createSelector{}, workspace, roots)
}

// runRequest executes a real POST /run against the App and returns the
// recorder.
func runUserModeRequest(t *testing.T, app *App, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)
	return w
}

// TestUserModeOmittedRootsIssuesWorkspaceSnapshot proves the user-mode
// compatibility contract: an omitted/[] filesystem_roots request issues the
// inherited workspace-only derived snapshot byte-for-byte (workspace grant at
// the effective ceiling mode).
func TestUserModeOmittedRootsIssuesWorkspaceSnapshot(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0].Path)

	result, err := userModeRootsSession(t, app, ws, nil)
	if err != nil {
		t.Fatalf("omitted-roots create: %v", err)
	}
	got, err := json.Marshal(result.FilesystemSnapshot.Entries)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, ws)
	if string(got) != want {
		t.Errorf("omitted-roots snapshot = %s, want %s", got, want)
	}

	empty, err := userModeRootsSession(t, app, ws, []sessionFilesystemRootEntry{})
	if err != nil {
		t.Fatalf("empty-array create: %v", err)
	}
	got, err = json.Marshal(empty.FilesystemSnapshot.Entries)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("empty-array snapshot = %s, want %s", got, want)
	}
}

// TestUserModeExplicitWorkspaceRoots proves the explicit workspace-root forms
// of the user-mode restriction: an explicit read_write root and an explicit
// read_only root at the canonical workspace are both accepted (the read_only
// narrowing), and every additional root — an external disjoint directory, a
// child of the workspace, a workspace child regular file — is refused
// invalid_filesystem_policy before any Session or bearer exists.
func TestUserModeExplicitWorkspaceRoots(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	root := app.Config.AllowedRoots[0].Path
	ws := testWorkspaceDir(t, root)
	external := filepath.Join(root, "external-uat")
	child := filepath.Join(ws, "child")
	if err := os.MkdirAll(external, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(child, 0755); err != nil {
		t.Fatal(err)
	}

	// Explicit workspace read_write under a read_write ceiling is accepted.
	rw, err := userModeRootsSession(t, app, ws, []sessionFilesystemRootEntry{{Path: ws, Access: "read_write"}})
	if err != nil {
		t.Fatalf("explicit workspace RW create: %v", err)
	}
	got, err := json.Marshal(rw.FilesystemSnapshot.Entries)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`[{"path":%q,"access":"read_write"}]`, ws)
	if string(got) != want {
		t.Errorf("explicit RW snapshot = %s, want %s", got, want)
	}

	// Explicit workspace read_only is accepted and issues the narrowed
	// read-only workspace grant.
	ro, err := userModeRootsSession(t, app, ws, []sessionFilesystemRootEntry{{Path: ws, Access: "read_only"}})
	if err != nil {
		t.Fatalf("explicit workspace RO create: %v", err)
	}
	got, err = json.Marshal(ro.FilesystemSnapshot.Entries)
	if err != nil {
		t.Fatal(err)
	}
	wantRO := fmt.Sprintf(`[{"path":%q,"access":"read_only"}]`, ws)
	if string(got) != wantRO {
		t.Errorf("explicit RO snapshot = %s, want %s", got, wantRO)
	}

	for name, roots := range map[string][]sessionFilesystemRootEntry{
		"external disjoint directory": {{Path: external, Access: "read_write"}},
		"workspace child directory":   {{Path: child, Access: "read_write"}},
		"workspace child regular file": func() []sessionFilesystemRootEntry {
			f := filepath.Join(ws, "note.txt")
			if err := os.WriteFile(f, []byte("note"), 0644); err != nil {
				t.Fatal(err)
			}
			return []sessionFilesystemRootEntry{{Path: f, Access: "read_only"}}
		}(),
		"workspace plus external": {
			{Path: ws, Access: "read_write"},
			{Path: external, Access: "read_only"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			before := countLiveSessions(t, app)
			_, err := userModeRootsSession(t, app, ws, roots)
			if err == nil {
				t.Fatal("user-mode additional filesystem root was accepted")
			}
			if !strings.Contains(err.Error(), ErrInvalidSessionFilesystemPolicy.Error()) {
				t.Errorf("refusal is not the invalid filesystem policy family: %v", err)
			}
			if after := countLiveSessions(t, app); after != before {
				t.Errorf("refused create left %d sessions, want %d", after, before)
			}
		})
	}
}

// TestUserModeWorkspaceAliasRootAccepted proves the canonical-identity rule of
// the user-mode restriction: a symlink spelling whose resolved canonical path
// equals the canonical workspace is accepted as the workspace root (an
// explicit read_only narrowing through the alias).
func TestUserModeWorkspaceAliasRootAccepted(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	setupTestLoggingDiscard(t)
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0].Path)
	aliasParent := filepath.Join(app.Config.AllowedRoots[0].Path, "alias-holder")
	if err := os.MkdirAll(aliasParent, 0755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(aliasParent, "ws-alias")
	if err := os.Symlink(ws, alias); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	result, err := userModeRootsSession(t, app, ws, []sessionFilesystemRootEntry{{Path: alias, Access: "read_only"}})
	if err != nil {
		t.Fatalf("workspace alias create: %v", err)
	}
	got, err := json.Marshal(result.FilesystemSnapshot.Entries)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`[{"path":%q,"access":"read_only"}]`, ws)
	if string(got) != want {
		t.Errorf("alias snapshot = %s, want %s (canonical identity)", got, want)
	}
}

// TestUserModeRunAcceptsExactWorkspaceSpellings proves the accepted source
// shapes of the user-mode run boundary: relative "." and an absolute spelling
// resolving exactly to the canonical workspace are both accepted.
func TestUserModeRunAcceptsExactWorkspaceSpellings(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeUser
	app.OperationSupervisor = newOperationSupervisor()
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0].Path)
	result, err := userModeRootsSession(t, app, ws, nil)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	for name, source := range map[string]string{
		"relative dot":         ".",
		"absolute workspace":   ws,
		"workspace dot suffix": ws + "/.",
	} {
		t.Run(name, func(t *testing.T) {
			body := fmt.Sprintf(`{"image":"alpine","mounts":[{"source":%q,"target":"/data"}]}`, source)
			w := runUserModeRequest(t, app, result.Token, body)
			if w.Code != http.StatusCreated {
				t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

// TestUserModeRunRejectsNonWorkspaceSources proves the refused source shapes
// of the user-mode run boundary: a workspace child directory, a child regular
// file, and a disjoint absolute source are refused invalid_mount before any
// operation or Docker state exists.
func TestUserModeRunRejectsNonWorkspaceSources(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeUser
	app.OperationSupervisor = newOperationSupervisor()
	root := app.Config.AllowedRoots[0].Path
	ws := testWorkspaceDir(t, root)
	result, err := userModeRootsSession(t, app, ws, nil)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	child := filepath.Join(ws, "child")
	if err := os.MkdirAll(child, 0755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(ws, "f.txt")
	if err := os.WriteFile(file, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(root, "external-run")
	if err := os.MkdirAll(external, 0755); err != nil {
		t.Fatal(err)
	}

	for name, source := range map[string]string{
		"relative child":         "child",
		"relative child file":    "f.txt",
		"absolute child":         child,
		"absolute child file":    file,
		"absolute disjoint root": external,
	} {
		t.Run(name, func(t *testing.T) {
			dockerCalled := false
			app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
				dockerCalled = true
				return exec.CommandContext(ctx, "/bin/true")
			}
			body := fmt.Sprintf(`{"image":"alpine","mounts":[{"source":%q,"target":"/data"}]}`, source)
			w := runUserModeRequest(t, app, result.Token, body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "invalid_mount") {
				t.Errorf("refusal is not invalid_mount: %s", w.Body.String())
			}
			if dockerCalled {
				t.Error("docker must not be called for a refused user-mode source")
			}
			if len(app.OperationSupervisor.ops) != 0 {
				t.Error("a refused user-mode mount must not create an operation")
			}
		})
	}
}

// TestUserModeRunRefusesReadOnlyWorkspaceWritableExposure proves the
// access-mode owner is unchanged by the source-shape boundary: a Session
// explicitly narrowed to a read-only workspace accepts the read-only mount
// and refuses the writable exposure of the same workspace root with the
// stable read_only_root contract before any operation or Docker state exists.
func TestUserModeRunRefusesReadOnlyWorkspaceWritableExposure(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeUser
	app.OperationSupervisor = newOperationSupervisor()
	ws := testWorkspaceDir(t, app.Config.AllowedRoots[0].Path)
	if err := os.WriteFile(filepath.Join(ws, "keep.txt"), []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := userModeRootsSession(t, app, ws, []sessionFilesystemRootEntry{{Path: ws, Access: "read_only"}})
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	dockerCalled := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		dockerCalled = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	// The read-only mount of the workspace root is allowed.
	ro := runUserModeRequest(t, app, result.Token, `{"image":"alpine","mounts":[{"source":".","target":"/data","read_only":true}]}`)
	if ro.Code != http.StatusCreated {
		t.Fatalf("read-only mount = %d, want 201: %s", ro.Code, ro.Body.String())
	}
	if len(app.OperationSupervisor.ops) != 1 {
		t.Fatalf("read-only mount created %d operations, want 1", len(app.OperationSupervisor.ops))
	}

	// The writable exposure of the same source is refused read_only_root.
	dockerCalled = false
	w := runUserModeRequest(t, app, result.Token, `{"image":"alpine","mounts":[{"source":".","target":"/data"}]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("writable exposure = %d, want 400: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "read_only_root") {
		t.Errorf("refusal is not read_only_root: %s", w.Body.String())
	}
	if dockerCalled {
		t.Error("docker must not be called for a refused writable exposure")
	}
	if len(app.OperationSupervisor.ops) != 1 {
		t.Error("a refused writable exposure must not create an additional operation")
	}
}
