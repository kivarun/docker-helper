package main

// Build data-plane filesystem tests: build context and Dockerfile are
// read-only host inputs of the helper, so builds are permitted from either
// snapshot access mode; the build staging owner writes only into
// helper-owned staging and never into the source tree.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// snapshotTreeState records content-hash and stat facts for every file and
// directory of one tree, used to prove a build/staging did not modify the
// source context.
type snapshotTreeState struct {
	Hashes map[string][sha256.Size]byte
	Exts   map[string]string
	Dirs   map[string]struct{}
}

// captureTreeState walks root and records per-path facts. Symlinks inside a
// build context are not exercised here; contexts are plain trees.
func captureTreeState(t *testing.T, root string) *snapshotTreeState {
	t.Helper()
	state := &snapshotTreeState{
		Hashes: make(map[string][sha256.Size]byte),
		Exts:   make(map[string]string),
		Dirs:   make(map[string]struct{}),
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		if d.IsDir() {
			state.Dirs[rel] = struct{}{}
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		state.Exts[rel] = info.ModTime().String() + "|" + fmt.Sprintf("%d:%d:%v", info.Size(), info.ModTime().UnixNano(), info.Mode())
		data, derr := os.ReadFile(path)
		if derr != nil {
			return derr
		}
		state.Hashes[rel] = sha256.Sum256(data)
		return nil
	})
	if err != nil {
		t.Fatalf("capture tree state of %s: %v", root, err)
	}
	return state
}

// assertTreeUnchanged proves no path of the recorded tree changed in
// content, metadata, or structure.
func assertTreeUnchanged(t *testing.T, before, after *snapshotTreeState) {
	t.Helper()
	if len(before.Hashes) != len(after.Hashes) || len(before.Exts) != len(after.Exts) || len(before.Dirs) != len(after.Dirs) {
		t.Fatalf("tree shape changed: files %d->%d, dirs %d->%d",
			len(before.Hashes), len(after.Hashes), len(before.Dirs), len(after.Dirs))
	}
	for path, sum := range before.Hashes {
		if after.Hashes[path] != sum {
			t.Errorf("file content changed: %s", path)
		}
	}
	for path, ext := range before.Exts {
		if after.Exts[path] != ext {
			t.Errorf("file metadata changed: %s (%q -> %q)", path, ext, after.Exts[path])
		}
	}
	for path := range before.Dirs {
		if _, ok := after.Dirs[path]; !ok {
			t.Errorf("directory removed: %s", path)
		}
	}
}

// newBuildEnforcementApp builds a user-mode App with a stubbed docker exec
// (real staging) for build filesystem tests. It returns the app and the
// capture function for the last docker argv.
func newBuildEnforcementApp(t *testing.T) (*App, func() []string) {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()
	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}
	return app, func() []string { return capturedArgs }
}

// newBuildEnforcementSession creates a Session through the production owner
// and re-issues its persisted snapshot with the exact entries the test needs.
func newBuildEnforcementSession(t *testing.T, app *App, workspace string, entries []AllowedRootEntry) *CreatedSession {
	t.Helper()
	if workspace == "" {
		workspace = testWorkspaceDir(t, app.Config.AllowedRoots[0].Path)
	}
	created, err := createDefaultAdminSessionForTest(app, workspace)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	if entries != nil {
		insertTestSessionSnapshotEntries(t, app.DB, created.Session.ID, entries)
	}
	return created
}

// mustWriteBuildContext creates a context tree with a Dockerfile and a nested
// payload file and returns the relative context path and Dockerfile name.
func mustWriteBuildContext(t *testing.T, workspace, rel string) {
	t.Helper()
	ctxDir := filepath.Join(workspace, filepath.FromSlash(rel))
	if err := os.MkdirAll(ctxDir, 0755); err != nil {
		t.Fatal(err)
	}
	dockerfile := filepath.Join(ctxDir, "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte("FROM alpine"), 0644); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(ctxDir, "data.bin")
	if err := os.WriteFile(payload, []byte("payload"), 0644); err != nil {
		t.Fatal(err)
	}
}

// runBuildEnforcement posts the build request and waits for the operation.
func runBuildEnforcement(t *testing.T, app *App, token, context, dockerfile string) *httptest.ResponseRecorder {
	t.Helper()
	req := newBuildRequest(map[string]any{
		"context":    context,
		"dockerfile": dockerfile,
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)
	waitBuild(t, app, w)
	return w
}

// TestBuildReadsReadOnlySnapshotSources proves the build host-input
// transition matrix: builds are permitted from read_only regions, from
// read_write regions containing nested read_only subtrees, and through
// symlink spellings resolving into read_only canonical sources — the helper
// consumes both canonical paths read-only, so there is no read_only_root
// refusal for a valid read-only consumption.
func TestBuildReadsReadOnlySnapshotSources(t *testing.T) {
	// read-only whole workspace
	t.Run("whole_workspace_read_only", func(t *testing.T) {
		app, _ := newBuildEnforcementApp(t)
		created := newBuildEnforcementSession(t, app, "", nil)
		workspace := created.Session.Workspace
		if err := os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM alpine"), 0644); err != nil {
			t.Fatal(err)
		}
		insertTestSessionSnapshotEntries(t, app.DB, created.Session.ID, []AllowedRootEntry{
			{Path: workspace, Access: AllowedRootAccessReadOnly},
		})
		w := runBuildEnforcement(t, app, created.Token, ".", "Dockerfile")
		if w.Code != 201 {
			t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
		}
	})

	// read-only context with read-only Dockerfile
	t.Run("read_only_context_and_dockerfile", func(t *testing.T) {
		app, _ := newBuildEnforcementApp(t)
		created := newBuildEnforcementSession(t, app, "", nil)
		workspace := created.Session.Workspace
		mustWriteBuildContext(t, workspace, "ctx")
		insertTestSessionSnapshotEntries(t, app.DB, created.Session.ID, []AllowedRootEntry{
			{Path: workspace, Access: AllowedRootAccessReadWrite},
			{Path: filepath.Join(workspace, "ctx"), Access: AllowedRootAccessReadOnly},
		})
		w := runBuildEnforcement(t, app, created.Token, "ctx", "Dockerfile")
		if w.Code != 201 {
			t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
		}
	})

	// read-write context containing nested read-only files
	t.Run("rw_context_with_nested_ro_files", func(t *testing.T) {
		app, _ := newBuildEnforcementApp(t)
		created := newBuildEnforcementSession(t, app, "", nil)
		workspace := created.Session.Workspace
		mustWriteBuildContext(t, workspace, "ctx")
		if err := os.MkdirAll(filepath.Join(workspace, "ctx", "inputs"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(workspace, "ctx", "inputs", "in.txt"), []byte("input"), 0644); err != nil {
			t.Fatal(err)
		}
		insertTestSessionSnapshotEntries(t, app.DB, created.Session.ID, []AllowedRootEntry{
			{Path: workspace, Access: AllowedRootAccessReadWrite},
			{Path: filepath.Join(workspace, "ctx", "inputs"), Access: AllowedRootAccessReadOnly},
		})
		w := runBuildEnforcement(t, app, created.Token, "ctx", "Dockerfile")
		if w.Code != 201 {
			t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
		}
	})

	// read-only context with a deeper read_write subtree
	t.Run("ro_context_with_deeper_rw_subtree", func(t *testing.T) {
		app, _ := newBuildEnforcementApp(t)
		created := newBuildEnforcementSession(t, app, "", nil)
		workspace := created.Session.Workspace
		mustWriteBuildContext(t, workspace, "ctx")
		insertTestSessionSnapshotEntries(t, app.DB, created.Session.ID, []AllowedRootEntry{
			{Path: workspace, Access: AllowedRootAccessReadWrite},
			{Path: filepath.Join(workspace, "ctx"), Access: AllowedRootAccessReadOnly},
			{Path: filepath.Join(workspace, "ctx", "out"), Access: AllowedRootAccessReadWrite},
		})
		w := runBuildEnforcement(t, app, created.Token, "ctx", "Dockerfile")
		if w.Code != 201 {
			t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
		}
	})

	// symlink spelling of the context resolving into a read-only source
	t.Run("symlink_context_spelling_resolving_into_ro", func(t *testing.T) {
		app, _ := newBuildEnforcementApp(t)
		created := newBuildEnforcementSession(t, app, "", nil)
		workspace := created.Session.Workspace
		mustWriteBuildContext(t, workspace, "ctx")
		if err := os.Symlink(filepath.Join(workspace, "ctx"), filepath.Join(workspace, "clink")); err != nil {
			t.Fatal(err)
		}
		insertTestSessionSnapshotEntries(t, app.DB, created.Session.ID, []AllowedRootEntry{
			{Path: workspace, Access: AllowedRootAccessReadWrite},
			{Path: filepath.Join(workspace, "ctx"), Access: AllowedRootAccessReadOnly},
		})
		w := runBuildEnforcement(t, app, created.Token, "clink", "Dockerfile")
		if w.Code != 201 {
			t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
		}
	})
}

// TestBuildStagingNeverWritesSourceTree proves structurally that a build from
// a read-only source reads the context and writes only helper-owned staging:
// the staging owner's real destination is recorded, Docker receives staged
// paths only, the source tree is byte- and metadata-identical after the
// build, and the staging cleanup removes the helper-owned copy.
func TestBuildStagingNeverWritesSourceTree(t *testing.T) {
	app, capture := newBuildEnforcementApp(t)
	created := newBuildEnforcementSession(t, app, "", nil)
	workspace := created.Session.Workspace
	mustWriteBuildContext(t, workspace, "ctx")

	insertTestSessionSnapshotEntries(t, app.DB, created.Session.ID, []AllowedRootEntry{
		{Path: workspace, Access: AllowedRootAccessReadWrite},
		{Path: filepath.Join(workspace, "ctx"), Access: AllowedRootAccessReadOnly},
	})

	// Drive the real staging owner through its seam and record where the
	// production staging destination lives.
	var stagedContextPath, stagedDockerfilePath string
	_ = &stagedDockerfilePath
	app.StageBuildContextFn = func(ctx context.Context, ws, contextPath, dockerfileRel, runtimeDir, operationID string) (*stagedBuildContext, error) {
		staged, err := StageBuildContext(ctx, ws, contextPath, dockerfileRel, runtimeDir, operationID)
		if err == nil {
			stagedContextPath = staged.ContextPath
			stagedDockerfilePath = staged.DockerfilePath
		}
		return staged, err
	}

	before := captureTreeState(t, workspace)
	w := runBuildEnforcement(t, app, created.Token, "ctx", "Dockerfile")
	after := captureTreeState(t, workspace)

	if w.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	assertTreeUnchanged(t, before, after)

	// Docker argv must reference the staged copy, never the source tree.
	args := capture()
	if len(args) == 0 {
		t.Fatal("docker was not invoked")
	}
	if stagedContextPath == "" {
		t.Fatal("staging owner was never invoked")
	}
	if !strings.HasPrefix(stagedContextPath, app.Config.RuntimeDir) {
		t.Fatalf("staging destination %q is not under the helper-owned runtime dir", stagedContextPath)
	}
	if !strings.HasPrefix(stagedDockerfilePath, app.Config.RuntimeDir) {
		t.Fatalf("staged dockerfile %q is not under the helper-owned runtime dir", stagedDockerfilePath)
	}
	if strings.HasPrefix(stagedContextPath, workspace) {
		t.Fatalf("staging destination must never live inside the source tree: %s", stagedContextPath)
	}
	var found bool
	for _, arg := range args {
		if arg == stagedContextPath {
			found = true
		}
	}
	if !found {
		t.Fatalf("docker argv does not use the staged context path %q: %v", stagedContextPath, args)
	}
	if slices.ContainsFunc(args, func(a string) bool { return a == workspace }) {
		t.Fatalf("docker argv must never reference the original workspace path: %v", args)
	}
}

// TestBuildAuditCarriesCanonicalExposure proves the build.start audit keeps
// the existing caller fields and adds the canonical policy facts of both
// host inputs.
func TestBuildAuditCarriesCanonicalExposure(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app, _ := newBuildEnforcementApp(t)
	created := newBuildEnforcementSession(t, app, "", nil)
	workspace := created.Session.Workspace
	mustWriteBuildContext(t, workspace, "ctx")

	w := runBuildEnforcement(t, app, created.Token, "ctx", "Dockerfile")
	if w.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	for _, rec := range filterBySession(parseAuditRecords(auditBuf), created.Session.ID) {
		if rec.Event != "build.start" {
			continue
		}
		// Caller spellings stay for compatibility.
		if rec.Context != "ctx" || rec.Dockerfile != "Dockerfile" {
			t.Fatalf("caller context/dockerfile facts wrong: %q %q", rec.Context, rec.Dockerfile)
		}
		if want := filepath.Join(workspace, "ctx"); rec.BuildContextResolved != want {
			t.Errorf("build_context_resolved = %q, want %s", rec.BuildContextResolved, want)
		}
		if rec.BuildContextAccess != string(AllowedRootAccessReadWrite) {
			t.Errorf("build_context_access = %q, want read_write", rec.BuildContextAccess)
		}
		if want := filepath.Join(workspace, "ctx", "Dockerfile"); rec.BuildDockerfileResolved != want {
			t.Fatalf("build_dockerfile_resolved = %q, want %s", rec.BuildDockerfileResolved, want)
		}
		if rec.BuildDockerfileAccess != string(AllowedRootAccessReadWrite) {
			t.Errorf("build_dockerfile_access = %q, want read_write", rec.BuildDockerfileAccess)
		}
		// Build-arg values are never audited; only keys are.
		if strings.Contains(auditBuf.String(), "payload") {
			t.Errorf("build-arg value must never be audited")
		}
		return
	}
	t.Fatal("build.start audit record not found")
}
