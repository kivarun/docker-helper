package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newSystemModeRunTestApp creates a test app whose deployment mode is system
// with a stubbed MAC backend, mirroring how the shipped system service runs
// (no real MAC coordinator in tests).
func newSystemModeRunTestApp(t *testing.T) *App {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeSystem
	app.OperationSupervisor = newOperationSupervisor()
	mockDetectLSM(t, LSMAppArmor, nil)
	return app
}

func TestHelperSocketSystemModeInjectsReadOnlyRuntimeMount(t *testing.T) {

	app := newSystemModeRunTestApp(t)

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token,
		map[string]any{"image": "alpine:3.24", "helper_socket": true, "command": []string{"true"}})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	spec := captured.lastSpec()
	var found *engineRunMount
	for i, m := range spec.Mounts {
		if m.Target == helperSocketContainerDir {
			found = &spec.Mounts[i]
		}
	}
	if found == nil {
		t.Fatalf("expected helper runtime projection in run spec mounts %v", spec.Mounts)
	}
	// The client must not choose source, target, or mode: the injected mount
	// is the fixed server-owned projection.
	if found.Source != app.Config.RuntimeDir || !found.ReadOnly {
		t.Errorf("helper runtime projection = %+v, want source %s read-only", *found, app.Config.RuntimeDir)
	}
}

func TestHelperSocketOmittedByDefault(t *testing.T) {

	app := newSystemModeRunTestApp(t)

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine:3.24", "command": []string{"true"}})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	for _, m := range captured.lastSpec().Mounts {
		if m.Target == helperSocketContainerDir {
			t.Errorf("helper runtime mount must not appear without helper_socket: %+v", captured.lastSpec().Mounts)
		}
	}
}

func TestHelperSocketUserModeFailClosed(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeUser
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	req := newRunRequest(map[string]any{
		"image":         "alpine:3.24",
		"helper_socket": true,
		"command":       []string{"true"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid_helper_socket") {
		t.Fatalf("expected invalid_helper_socket, got %s", w.Body.String())
	}

	if captured.reached() {
		t.Errorf("helper_socket must fail closed before Engine container creation")
	}
}

func TestHelperSocketUserMountOverlapRejected(t *testing.T) {
	overlapCases := []struct {
		name   string
		target string
	}{
		{name: "exact", target: helperSocketContainerDir},
		{name: "descendant", target: helperSocketContainerDir + "/subdir"},
		{name: "ancestor", target: "/run"},
	}

	for _, tc := range overlapCases {
		t.Run(tc.name, func(t *testing.T) {
			app := newSystemModeRunTestApp(t)

			result, err := createSystemSession(t, app)
			if err != nil {
				t.Fatalf("createSession: %v", err)
			}

			markerPath := filepath.Join(result.Session.Workspace, "marker")
			if err := os.WriteFile(markerPath, []byte("x"), 0o644); err != nil {
				t.Fatalf("write marker: %v", err)
			}

			captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

			reqBody := map[string]any{
				"image":         "alpine:3.24",
				"helper_socket": true,
				"mounts": []map[string]any{
					{"source": "marker", "target": tc.target},
				},
			}

			w := postRun(t, app, result.Token, reqBody)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "invalid_mount") {
				t.Fatalf("expected invalid_mount, got %s", w.Body.String())
			}

			if captured.reached() {
				t.Errorf("overlapping mount must be rejected before the Engine is called")
			}
		})
	}
}

func TestHelperSocketMountOverlapTable(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		overlaps bool
	}{
		{"exact", "/run/docker-helper", true},
		{"descendant", "/run/docker-helper/sub", true},
		{"ancestor", "/run", true},
		{"prefix-sibling", "/run/docker-socket", false},
		{"disjoint", "/opt", false},
	}

	for _, tc := range cases {
		if got := isHelperSocketMountOverlap(tc.target); got != tc.overlaps {
			t.Errorf("%s: isHelperSocketMountOverlap(%q) = %v, want %v", tc.name, tc.target, got, tc.overlaps)
		}
	}
}

func TestHelperSocketUserMountExactTargetAllowedWithoutCapability(t *testing.T) {
	app := newSystemModeRunTestApp(t)
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{PinnedPath: sourcePath, cleanup: func() error { return nil }}, nil
	}

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	markerPath := filepath.Join(result.Session.Workspace, "marker")
	if err := os.WriteFile(markerPath, []byte("x"), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	req := newRunRequest(map[string]any{
		"image": "alpine:3.24",
		"mounts": []map[string]any{
			{"source": "marker", "target": helperSocketContainerDir, "read_only": true},
		},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Without helper_socket, the caller's own mount target is policy as
	// before; the projection is only protected when it is actually injected.
	spec := captured.lastSpec()
	if len(spec.Mounts) != 1 || spec.Mounts[0].Target != helperSocketContainerDir {
		t.Errorf("caller mount must pass unchanged: %+v", spec.Mounts)
	}
	if spec.Mounts[0].Source == app.Config.RuntimeDir {
		t.Errorf("caller mount must not be served from the helper runtime directory: %+v", spec.Mounts[0])
	}
}

func TestHelperSocketAuditRecordsCapability(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newSystemModeRunTestApp(t)

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token,
		map[string]any{"image": "alpine:3.24", "helper_socket": true, "command": []string{"true"}})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	_ = captured

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected run.start and run.finish, got %d", len(records))
	}
	for _, rec := range records {
		if rec.Event != "run.start" && rec.Event != "run.finish" {
			continue
		}
		if !rec.HelperSocket {
			t.Errorf("%s must record the helper_socket capability fact: %+v", rec.Event, rec)
		}
	}
	// The injected projection is not a caller mount: the audit mounts stay
	// exactly the caller mounts (none here).
	for _, rec := range records {
		if len(rec.Mounts) != 0 {
			t.Errorf("%s must not audit the injected projection as a caller mount: %+v", rec.Event, rec.Mounts)
		}
	}
}

func TestHelperSocketAuditAbsentByDefault(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newSystemModeRunTestApp(t)

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine:3.24", "command": []string{"true"}})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	_ = captured

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		if rec.HelperSocket {
			t.Errorf("helper_socket must not be recorded without the capability: %+v", rec)
		}
	}
}

func TestHelperSocketCLIRequestField(t *testing.T) {
	app := newSystemModeRunTestApp(t)

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token,
		map[string]any{"image": "alpine:3.24", "helper_socket": true})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if !captured.lastSpec().hasHelperRuntimeProjection(app.Config.RuntimeDir) {
		t.Errorf("CLI helper-socket must request the server-owned projection: %+v", captured.lastSpec().Mounts)
	}
}

func TestHelperSocketCLIOmittedByDefault(t *testing.T) {
	app := newSystemModeRunTestApp(t)

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, result.Token, map[string]any{"image": "alpine:3.24"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if captured.lastSpec().hasHelperRuntimeProjection(app.Config.RuntimeDir) {
		t.Errorf("projection must not appear without helper_socket: %+v", captured.lastSpec().Mounts)
	}
}

func TestHelperSocketCLIFlagWithEnvFrom(t *testing.T) {
	app := newSystemModeRunTestApp(t)

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	// helper_socket composes with the CLI-side env mechanism: the resolved
	// environment reaches the Engine create configuration.
	w := postRun(t, app, result.Token, map[string]any{
		"image":         "alpine:3.24",
		"helper_socket": true,
		"environment":   map[string]string{"PROBE_KEY": "probe-value"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	spec := captured.lastSpec()
	if !spec.hasHelperRuntimeProjection(app.Config.RuntimeDir) {
		t.Errorf("projection missing: %+v", spec.Mounts)
	}
	if spec.Env["PROBE_KEY"] != "probe-value" {
		t.Errorf("environment not delivered: %+v", spec.Env)
	}
}

// hasHelperRuntimeProjection reports whether the spec carries the fixed
// server-owned helper runtime projection: a read-only bind of the daemon's
// own runtime directory at the canonical container target.
func (s engineRunSpec) hasHelperRuntimeProjection(runtimeDir string) bool {
	for _, m := range s.Mounts {
		if m.Target == helperSocketContainerDir && m.Source == runtimeDir && m.ReadOnly {
			return true
		}
	}
	return false
}
