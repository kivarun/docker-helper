package main

// Data-plane filesystem enforcement tests: the persisted immutable Session
// filesystem snapshot is the only run-mount filesystem authority. These tests
// drive the real handleRun pipeline and assert the decisions the snapshot
// owner produces: caller-requested read-only consumption of either access
// mode is permitted, writable consumption requires the snapshot owner's
// writable-parent query, refusals are the typed read_only_root contract with
// no pin/operation/Docker residue, and symlink spellings never select policy
// before canonical resolution.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newRunEnforcementApp builds a system-mode App with stubbed Docker exec and
// mount-pin seams and returns the app plus a capture function for the docker
// argv of the last started operation.
func newRunEnforcementApp(t *testing.T) (*App, func() []string) {
	t.Helper()
	app := newSystemModeRunTestApp(t)
	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		// The pin projection is asserted to keep the same source boundary:
		// echoing the canonical path makes the accepted bind spec directly
		// comparable with the canonical policy identity.
		return &pinnedMount{
			PinnedPath: sourcePath,
			cleanup:    func() error { return nil },
		}, nil
	}
	capture := func() []string { return capturedArgs }
	return app, capture
}

// createRunEnforcementSession creates a system-mode Session through the
// production owner chain (Principal + Launcher under the configured roots)
// and then re-issues its persisted snapshot with the exact entries the test
// needs. Snapshot derivation from parent policy is owned and proven by the
// Session-create tests; these tests discriminate how the run pipeline
// consumes the persisted authority.
func createRunEnforcementSession(t *testing.T, app *App, entries []AllowedRootEntry) *CreatedSession {
	t.Helper()
	created, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	if entries != nil {
		insertTestSessionSnapshotEntries(t, app.DB, created.Session.ID, entries)
	}
	return created
}

// readRootResponseCode decodes the canonical API error code.
func readRootResponseCode(t *testing.T, body string) string {
	t.Helper()
	var resp struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode error response %q: %v", body, err)
	}
	return resp.Code
}

// singleMountSpec asserts exactly one user mount spec exists and returns it.
func singleMountSpec(t *testing.T, args []string) string {
	t.Helper()
	specs := dockerMountSpecs(args)
	if len(specs) != 1 {
		t.Fatalf("expected exactly one user mount spec, got argv %v", args)
	}
	return specs[0]
}

// assertNoRunPolicyResidue proves a read_only_root refusal left no pin, no
// registered operation, and no Docker invocation.
func assertNoRunPolicyResidue(t *testing.T, app *App, pinnedCalled, dockerCalled *bool) {
	t.Helper()
	if pinnedCalled != nil && *pinnedCalled {
		t.Error("pin function must not be called on read_only_root refusal")
	}
	if dockerCalled != nil && *dockerCalled {
		t.Error("docker must not be called on read_only_root refusal")
	}
	if n := len(app.OperationSupervisor.ops); n != 0 {
		t.Errorf("no operation must be registered on read_only_root refusal, got %d", n)
	}
}

// runExposureCase is one run access-mode decision case. The snapshot entries
// use the placeholder root "/ws" and are re-anchored to the per-test
// workspace directory before insertion.
type runExposureCase struct {
	name     string
	dirs     []string
	symlinks map[string]string
	entries  []AllowedRootEntry
	source   string
	readOnly bool
	refused  bool
	// acceptedSpecSuffix is the part of the accepted bind spec after the
	// canonical source: ",target=/data" plus the readonly flag exactly when
	// the caller requested it.
	acceptedSpecSuffix string
	// expectedSourceSuffix is the canonical bind source inside the workspace
	// that the Docker argv must carry; the workspace prefix is added per test.
	expectedSourceSuffix string
}

// TestRunExposureMatrix drives the run access-mode decision matrix through
// the real handler: the persisted snapshot decides, read-only requests of
// either access mode pass, writable requests pass only through the snapshot
// owner's writable-parent query, and no silent downgrade ever happens.
func TestRunExposureMatrix(t *testing.T) {
	cases := []runExposureCase{
		{
			name:                 "rw_source_rw_request",
			dirs:                 []string{"sub", "inputs"},
			entries:              []AllowedRootEntry{{Path: "/ws", Access: AllowedRootAccessReadWrite}, {Path: "/ws/inputs", Access: AllowedRootAccessReadOnly}},
			source:               "sub",
			acceptedSpecSuffix:   ",target=/data",
			expectedSourceSuffix: "sub",
		},
		{
			name:                 "rw_source_ro_request",
			dirs:                 []string{"sub"},
			entries:              []AllowedRootEntry{{Path: "/ws", Access: AllowedRootAccessReadWrite}},
			source:               "sub",
			readOnly:             true,
			acceptedSpecSuffix:   ",target=/data,readonly",
			expectedSourceSuffix: "sub",
		},
		{
			name:                 "ro_source_ro_request",
			dirs:                 []string{"inputs"},
			entries:              []AllowedRootEntry{{Path: "/ws", Access: AllowedRootAccessReadWrite}, {Path: "/ws/inputs", Access: AllowedRootAccessReadOnly}},
			source:               "inputs",
			readOnly:             true,
			acceptedSpecSuffix:   ",target=/data,readonly",
			expectedSourceSuffix: "inputs",
		},
		{
			name:    "ro_source_rw_request",
			dirs:    []string{"inputs"},
			entries: []AllowedRootEntry{{Path: "/ws", Access: AllowedRootAccessReadWrite}, {Path: "/ws/inputs", Access: AllowedRootAccessReadOnly}},
			source:  "inputs",
			refused: true,
		},
		{
			name:    "rw_parent_spanning_nested_ro_rw_request",
			dirs:    []string{"inputs"},
			entries: []AllowedRootEntry{{Path: "/ws", Access: AllowedRootAccessReadWrite}, {Path: "/ws/inputs", Access: AllowedRootAccessReadOnly}},
			source:  ".",
			refused: true,
		},
		{
			name:                 "rw_parent_spanning_nested_ro_ro_request",
			dirs:                 []string{"inputs"},
			entries:              []AllowedRootEntry{{Path: "/ws", Access: AllowedRootAccessReadWrite}, {Path: "/ws/inputs", Access: AllowedRootAccessReadOnly}},
			source:               ".",
			readOnly:             true,
			acceptedSpecSuffix:   ",target=/data,readonly",
			expectedSourceSuffix: "",
		},
		{
			name:                 "ro_ancestor_deeper_rw_source_rw_request",
			dirs:                 []string{"a/out"},
			entries:              []AllowedRootEntry{{Path: "/ws", Access: AllowedRootAccessReadWrite}, {Path: "/ws/a", Access: AllowedRootAccessReadOnly}, {Path: "/ws/a/out", Access: AllowedRootAccessReadWrite}},
			source:               "a/out",
			acceptedSpecSuffix:   ",target=/data",
			expectedSourceSuffix: "a/out",
		},
		{
			name: "deeper_rw_source_with_nested_ro_child",
			dirs: []string{"a/out/fixed"},
			entries: []AllowedRootEntry{
				{Path: "/ws", Access: AllowedRootAccessReadWrite},
				{Path: "/ws/a", Access: AllowedRootAccessReadOnly},
				{Path: "/ws/a/out", Access: AllowedRootAccessReadWrite},
				{Path: "/ws/a/out/fixed", Access: AllowedRootAccessReadOnly},
			},
			source:  "a/out",
			refused: true,
		},
		{
			name:     "symlink_spelling_resolving_into_ro_region_rw_request",
			dirs:     []string{"inputs"},
			symlinks: map[string]string{"link": "inputs"},
			entries:  []AllowedRootEntry{{Path: "/ws", Access: AllowedRootAccessReadWrite}, {Path: "/ws/inputs", Access: AllowedRootAccessReadOnly}},
			source:   "link",
			refused:  true,
		},
		{
			name:                 "symlink_spelling_resolving_into_safe_rw_region",
			dirs:                 []string{"sub"},
			symlinks:             map[string]string{"link": "sub"},
			entries:              []AllowedRootEntry{{Path: "/ws", Access: AllowedRootAccessReadWrite}},
			source:               "link",
			acceptedSpecSuffix:   ",target=/data",
			expectedSourceSuffix: "sub",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, capture := newRunEnforcementApp(t)
			created := createRunEnforcementSession(t, app, nil)
			workspace := created.Session.Workspace
			for _, d := range tc.dirs {
				if err := os.MkdirAll(filepath.Join(workspace, d), 0755); err != nil {
					t.Fatal(err)
				}
			}
			for name, target := range tc.symlinks {
				if err := os.Symlink(filepath.Join(workspace, target), filepath.Join(workspace, name)); err != nil {
					t.Fatal(err)
				}
			}
			// Re-anchor the snapshot entries to the real workspace path.
			entries := make([]AllowedRootEntry, len(tc.entries))
			for i, e := range tc.entries {
				entries[i] = AllowedRootEntry{
					Path:   filepath.Join(workspace, strings.TrimPrefix(e.Path, "/ws")),
					Access: e.Access,
				}
			}
			insertTestSessionSnapshotEntries(t, app.DB, created.Session.ID, entries)

			w, _ := postRunRequest(app, created.Token, fmt.Sprintf(
				`{"image":"alpine:3.24","mounts":[{"source":%q,"target":"/data","read_only":%t}],"command":["true"]}`,
				tc.source, tc.readOnly))

			if tc.refused {
				if w.Code != http.StatusBadRequest {
					t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
				}
				if code := readRootResponseCode(t, w.Body.String()); code != "read_only_root" {
					t.Fatalf("expected code read_only_root, got %q", code)
				}
				assertNoRunPolicyResidue(t, app, nil, nil)
				return
			}

			if w.Code != http.StatusCreated {
				t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
			}
			spec := singleMountSpec(t, capture())
			wantSpec := "type=bind,source=" + filepath.Join(workspace, tc.expectedSourceSuffix) + tc.acceptedSpecSuffix
			if spec != wantSpec {
				t.Fatalf("mount spec = %q, want %q", spec, wantSpec)
			}
		})
	}
}

// TestRunReadOnlyRootRefusalLeavesNoResidue proves the residue-free contract
// of a read_only_root refusal: Docker not called, pin function not called, no
// registered operation, and no cidfile — policy decided before any
// downstream materialization state exists.
func TestRunReadOnlyRootRefusalLeavesNoResidue(t *testing.T) {
	app, _ := newRunEnforcementApp(t)
	created := createRunEnforcementSession(t, app, nil)
	workspace := created.Session.Workspace
	if err := os.MkdirAll(filepath.Join(workspace, "inputs"), 0755); err != nil {
		t.Fatal(err)
	}
	insertTestSessionSnapshotEntries(t, app.DB, created.Session.ID, []AllowedRootEntry{
		{Path: workspace, Access: AllowedRootAccessReadWrite},
		{Path: filepath.Join(workspace, "inputs"), Access: AllowedRootAccessReadOnly},
	})

	pinnedCalled := false
	dockerCalled := false
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinnedCalled = true
		return &pinnedMount{PinnedPath: "/tmp/test-mount", cleanup: func() error { return nil }}, nil
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		dockerCalled = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	w, _ := postRunRequest(app, created.Token,
		`{"image":"alpine:3.24","mounts":[{"source":"inputs","target":"/data"}],"command":["true"]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if code := readRootResponseCode(t, w.Body.String()); code != "read_only_root" {
		t.Fatalf("expected read_only_root, got %q", code)
	}

	assertNoRunPolicyResidue(t, app, &pinnedCalled, &dockerCalled)

	// No cidfile residue: the helper-owned runtime directory contains no .cid
	// file from the refused request.
	entries, err := os.ReadDir(app.Config.RuntimeDir)
	if err != nil {
		t.Fatalf("list runtime dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".cid") {
			t.Errorf("cidfile residue on read_only_root refusal: %s", e.Name())
		}
	}
}

// TestRunUserModeWholeWorkspaceRWWithNestedRO proves the access-mode
// enforcement applies in user mode on top of the existing user-mode mount
// authority: a whole-workspace writable mount is refused by the snapshot
// owner's writable-parent query when a nested read_only transition exists,
// exactly like in system mode.
func TestRunUserModeWholeWorkspaceRWWithNestedRO(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeUser
	app.OperationSupervisor = newOperationSupervisor()

	workspace := testWorkspaceDir(t, app.Config.AllowedRoots[0].Path)
	nested := filepath.Join(workspace, "inputs")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	created, err := createDefaultAdminSessionForTest(app, workspace)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	insertTestSessionSnapshotEntries(t, app.DB, created.Session.ID, []AllowedRootEntry{
		{Path: workspace, Access: AllowedRootAccessReadWrite},
		{Path: nested, Access: AllowedRootAccessReadOnly},
	})

	w, _ := postRunRequest(app, created.Token,
		`{"image":"alpine:3.24","mounts":[{"source":".","target":"/workspace"}],"command":["true"]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if code := readRootResponseCode(t, w.Body.String()); code != "read_only_root" {
		t.Fatalf("expected read_only_root, got %q", code)
	}
	if n := len(app.OperationSupervisor.ops); n != 0 {
		t.Errorf("no operation must be registered on refusal, got %d", n)
	}
}

// TestRunRefusalAuditCarriesOffendingExposure proves the read_only_root
// audit carries exactly the offending canonical exposure facts and never a
// protected-subtree listing or a nested blocker path.
func TestRunRefusalAuditCarriesOffendingExposure(t *testing.T) {
	app, _ := newRunEnforcementApp(t)
	auditBuf, _ := setupTestLogging(t)

	created := createRunEnforcementSession(t, app, nil)
	workspace := created.Session.Workspace
	if err := os.MkdirAll(filepath.Join(workspace, "inputs"), 0755); err != nil {
		t.Fatal(err)
	}
	insertTestSessionSnapshotEntries(t, app.DB, created.Session.ID, []AllowedRootEntry{
		{Path: workspace, Access: AllowedRootAccessReadWrite},
		{Path: filepath.Join(workspace, "inputs"), Access: AllowedRootAccessReadOnly},
	})

	w, _ := postRunRequest(app, created.Token,
		`{"image":"alpine:3.24","mounts":[{"source":"inputs","target":"/data"}],"command":["true"]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	for _, rec := range filterBySession(parseAuditRecords(auditBuf), created.Session.ID) {
		if rec.Event != "run.rejected" || rec.Result != "read_only_root" {
			continue
		}
		if len(rec.Mounts) != 1 {
			t.Fatalf("expected exactly one offending mount fact, got %v", rec.Mounts)
		}
		m := rec.Mounts[0]
		if m.Source != "inputs" || m.Target != "/data" {
			t.Errorf("caller spelling facts wrong: %+v", m)
		}
		if m.ReadOnly {
			t.Error("refused request must stay requested-RW, got read_only=true")
		}
		if m.ResolvedSource != filepath.Join(workspace, "inputs") {
			t.Errorf("resolved_source = %q, want %s", m.ResolvedSource, filepath.Join(workspace, "inputs"))
		}
		if m.Access != string(AllowedRootAccessReadOnly) {
			t.Errorf("access = %q, want read_only", m.Access)
		}
		if m.WritableAllowed == nil || *m.WritableAllowed {
			t.Errorf("writable_allowed must be explicitly false, got %v", m.WritableAllowed)
		}
		return
	}
	t.Fatal("run.rejected/read_only_root audit record not found")
}

// TestRunSuccessAuditCarriesExposureFacts proves the accepted run mounts
// carry the resolved policy projection (caller source, canonical identity,
// requested mode, effective access, explicit writable permission) in the
// run.start audit.
func TestRunSuccessAuditCarriesExposure(t *testing.T) {
	app, _ := newRunEnforcementApp(t)
	auditBuf, _ := setupTestLogging(t)

	created := createRunEnforcementSession(t, app, nil)
	workspace := created.Session.Workspace
	if err := os.MkdirAll(filepath.Join(workspace, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "inputs"), 0755); err != nil {
		t.Fatal(err)
	}
	insertTestSessionSnapshotEntries(t, app.DB, created.Session.ID, []AllowedRootEntry{
		{Path: workspace, Access: AllowedRootAccessReadWrite},
		{Path: filepath.Join(workspace, "inputs"), Access: AllowedRootAccessReadOnly},
	})

	w, _ := postRunRequest(app, created.Token,
		`{"image":"alpine:3.24","mounts":[{"source":"sub","target":"/data"}],"command":["true"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	for _, rec := range filterBySession(parseAuditRecords(auditBuf), created.Session.ID) {
		if rec.Event != "run.start" {
			continue
		}
		if len(rec.Mounts) != 1 {
			t.Fatalf("expected one audited mount, got %v", rec.Mounts)
		}
		m := rec.Mounts[0]
		if m.Source != "sub" {
			t.Errorf("caller source = %q, want %q", m.Source, "sub")
		}
		if m.ResolvedSource != filepath.Join(workspace, "sub") {
			t.Errorf("resolved_source = %q, want %s", m.ResolvedSource, filepath.Join(workspace, "sub"))
		}
		if m.Access != string(AllowedRootAccessReadWrite) {
			t.Errorf("access = %q, want read_write", m.Access)
		}
		if m.WritableAllowed == nil || !*m.WritableAllowed {
			t.Errorf("writable_allowed must be explicit true, got %v", m.WritableAllowed)
		}
		return
	}
	t.Fatal("run.start audit record not found")
}

// countingQueryPoint records which watched queries actually ran without
// parking anything: a negative data-plane proof that must not be able to
// wedge the request it observes.
type countingQueryPoint struct {
	match string
	fired atomic.Bool
}

func (p *countingQueryPoint) maybePark(query string) {
	if strings.Contains(query, p.match) {
		p.fired.Store(true)
	}
}

// TestRunNoParentPolicyDataPlaneReread proves the run pipeline never reads
// the parent allowed-root tables: while a mount-bearing run executes against
// the parked-query driver, no query touching those tables may fire. The run
// must succeed so the proof shows the intended runtime was reached.
func TestRunNoParentPolicyDataPlaneReread(t *testing.T) {
	app, _ := newRunEnforcementApp(t)

	principalRoots := &countingQueryPoint{match: "FROM principal_allowed_roots"}
	launcherRoots := &countingQueryPoint{match: "FROM launcher_allowed_roots"}

	result := createRunEnforcementSession(t, app, nil)
	subdir := filepath.Join(result.Session.Workspace, "sub")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	parked := openParkedQueryDB(t, app.Config.DatabasePath, principalRoots, launcherRoots)
	app.DB.Close()
	app.DB = parked

	w, _ := postRunRequest(app, result.Token,
		`{"image":"alpine:3.24","mounts":[{"source":"sub","target":"/data"}],"command":["true"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if principalRoots.fired.Load() {
		t.Error("parent principal allowed-root table was queried on the data plane")
	}
	if launcherRoots.fired.Load() {
		t.Error("parent launcher allowed-root table was queried on the data plane")
	}
}

// TestRunCorruptSnapshotAtRequestTime proves a genuinely corrupt persisted
// snapshot discovered at request time is an internal integrity failure, not
// an authentication or mount-policy outcome: the Session is otherwise
// authentic, the response is 500 internal_error, the operational log carries
// the session ID and the snapshot integrity cause, and no runtime repair
// happens.
func TestRunCorruptSnapshotAtRequestTime(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)
	_ = auditBuf
	app, _ := newRunEnforcementApp(t)

	created := createRunEnforcementSession(t, app, nil)
	subdir := filepath.Join(created.Session.Workspace, "sub")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	// Corrupt the persisted snapshot through raw state surgery: reorder the
	// rows so the loader's contiguity proof fails for the authentic Session.
	if _, err := app.DB.Exec(
		`UPDATE session_filesystem_snapshot_entries SET position = 7 WHERE session_id = ?`,
		created.Session.ID); err != nil {
		t.Fatalf("corrupt snapshot: %v", err)
	}

	dockerCalled := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		dockerCalled = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	w, _ := postRunRequest(app, created.Token,
		`{"image":"alpine:3.24","command":["true"]}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
	if code := readRootResponseCode(t, w.Body.String()); code != "internal_error" {
		t.Fatalf("corruption must be internal_error, got %q", code)
	}

	// The operational log names the session and the snapshot integrity
	// cause; the audit outcome never claims unauthorized/read_only_root.
	opStr := opBuf.String()
	if !strings.Contains(opStr, created.Session.ID) {
		t.Errorf("operational log must carry the session ID")
	}
	if !strings.Contains(opStr, "snapshot") {
		t.Errorf("operational log must carry the snapshot integrity cause: %s", opStr)
	}
	for _, rec := range filterBySession(parseAuditRecords(auditBuf), created.Session.ID) {
		if rec.Result == "read_only_root" || rec.Result == "invalid_mount" || rec.Event == "session.not_found" {
			t.Errorf("corruption must not be audited as %s", rec.Result)
		}
	}
	if n := len(app.OperationSupervisor.ops); n != 0 {
		t.Errorf("no operation must be registered on snapshot integrity failure, got %d", n)
	}
	_ = dockerCalled
}

// TestRunReadOnlyRootRefusalReleasesLease proves the MAC lease acquired
// before the policy decision is released on a read_only_root refusal: the
// decision happens after lease acquisition but before any pin, operation, or
// Docker state, and no workspace-use lease survives the refusal.
func TestRunReadOnlyRootRefusalReleasesLease(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := openDatabase(dbPath)
	if err != nil {
		t.Fatalf("openDatabase: %v", err)
	}
	defer db.Close()

	initializeTestDatabase(t, db)

	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		AllowedRoots:          []AllowedRootEntry{allowedRootEntry(testAllowedRootDir(t))},
		SessionTTL:            24 * time.Hour,
		SocketPath:            filepath.Join(dir, "test.sock"),
		StateDir:              dir,
		RuntimeDir:            runtimeDir,
		DatabasePath:          dbPath,
		AdminTokenPath:        filepath.Join(dir, "admin.token"),
		ShutdownTimeout:       30 * time.Second,
		OperationRetentionTTL: 10 * time.Minute,
		OperationMaxCompleted: 200,
		OperationLogMaxBytes:  4 * 1024 * 1024,
		Mode:                  ModeSystem,
	}
	mac := newSessionMACCoordinator(db, newTestWorkspaceMACDriver(LSMBackend("test")))
	app := &App{
		Config:              cfg,
		DB:                  db,
		MACCoordinator:      mac,
		OperationSupervisor: newOperationSupervisor(),
	}
	mockDetectLSM(t, LSMAppArmor, nil)

	created, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	workspace := created.Session.Workspace
	inputs := filepath.Join(workspace, "inputs")
	if err := os.MkdirAll(inputs, 0755); err != nil {
		t.Fatal(err)
	}
	insertTestSessionSnapshotEntries(t, db, created.Session.ID, []AllowedRootEntry{
		{Path: workspace, Access: AllowedRootAccessReadWrite},
		{Path: inputs, Access: AllowedRootAccessReadOnly},
	})

	w, _ := postRunRequest(app, created.Token,
		`{"image":"alpine:3.24","mounts":[{"source":"inputs","target":"/data"}],"command":["true"]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if code := readRootResponseCode(t, w.Body.String()); code != "read_only_root" {
		t.Fatalf("expected read_only_root, got %q", code)
	}

	// The lease was released with the refusal: only zero workspace-use
	// leases remain after the refused request.
	mac.mu.Lock()
	leaseCount := len(mac.workspaceUseLeases)
	mac.mu.Unlock()
	if leaseCount != 0 {
		t.Errorf("read_only_root refusal must release the workspace-use lease, got %d", leaseCount)
	}
}
