package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// newCapacityTestApp creates a user-mode test app with a supervisor and one
// admin Session whose workspace exists, wired for long-lived fake Docker
// processes. The terminateForShutdown cleanup bounds every fake process.
func newCapacityTestApp(t *testing.T) (*App, *CreatedSession) {
	t.Helper()
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		// sleep responds to SIGTERM, matching the real termination paths.
		return exec.CommandContext(ctx, "sleep", "300")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		app.OperationSupervisor.terminateForShutdown(ctx, nil)
	})
	return app, result
}

// runCapacityRequest posts one run request through the real handler.
func runCapacityRequest(t *testing.T, app *App, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := newRunRequest(map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"true"},
	}, token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)
	return w
}

// decodeRejectedResponse extracts the public error code of a refusal.
func decodeRejectedResponse(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("cannot decode refusal response %q: %v", w.Body.String(), err)
	}
	return resp.Code
}

// TestRunSessionCapacityRefusedImmediately proves the Session-scope concurrent
// Operation ceiling: exactly maxConcurrentOperationsPerSession long-lived
// operations are admitted, the next request is refused immediately with the
// single bounded capacity refusal, and the refusal leaves no admitted
// Operation behind.
func TestRunSessionCapacityRefusedImmediately(t *testing.T) {
	app, result := newCapacityTestApp(t)

	for i := 0; i < maxConcurrentOperationsPerSession; i++ {
		w := runCapacityRequest(t, app, result.Token)
		if w.Code != http.StatusCreated {
			t.Fatalf("operation %d at the Session ceiling: expected %d, got %d (%s)",
				i+1, http.StatusCreated, w.Code, w.Body.String())
		}
	}

	// The next request is refused immediately: no queue, no wait.
	w := runCapacityRequest(t, app, result.Token)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("capacity refusal: expected %d at the Session ceiling, got %d (%s)",
			http.StatusTooManyRequests, w.Code, w.Body.String())
	}
	if code := decodeRejectedResponse(t, w); code != "operation_capacity_unavailable" {
		t.Fatalf("capacity refusal code: expected operation_capacity_unavailable, got %q", code)
	}

	// The refusal admitted no Operation: the Session still holds exactly the
	// ceiling of running operations and nothing else was registered.
	if got := len(app.OperationSupervisor.ops); got != maxConcurrentOperationsPerSession {
		t.Fatalf("refused request must not consume capacity: %d registered operations", got)
	}
}

// TestRunOtherSessionUsesFreeGlobalCapacity proves the Session ceiling does
// not expose global topology: when one Session holds its full share, another
// Session can still use free global capacity.
func TestRunOtherSessionUsesFreeGlobalCapacity(t *testing.T) {
	app, first := newCapacityTestApp(t)
	second, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	for i := 0; i < maxConcurrentOperationsPerSession; i++ {
		if w := runCapacityRequest(t, app, first.Token); w.Code != http.StatusCreated {
			t.Fatalf("first session operation %d: expected %d, got %d (%s)",
				i+1, http.StatusCreated, w.Code, w.Body.String())
		}
	}

	// Another Session can use free global capacity.
	w := runCapacityRequest(t, app, second.Token)
	if w.Code != http.StatusCreated {
		t.Fatalf("second session must use free global capacity: expected %d, got %d (%s)",
			http.StatusCreated, w.Code, w.Body.String())
	}
}

// TestRunTerminalOperationFreesCapacityImmediately proves that capacity ends
// at the terminal state, not at retention pruning: a finished operation frees
// its slot while its metadata and logs remain retained.
func TestRunTerminalOperationFreesCapacityImmediately(t *testing.T) {
	app, result := newCapacityTestApp(t)

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	for i := 0; i < maxConcurrentOperationsPerSession; i++ {
		if w := runCapacityRequest(t, app, result.Token); w.Code != http.StatusCreated {
			t.Fatalf("operation %d: expected %d, got %d (%s)", i+1, http.StatusCreated, w.Code, w.Body.String())
		}
	}
	if w := runCapacityRequest(t, app, result.Token); w.Code != http.StatusTooManyRequests {
		t.Fatalf("capacity refusal: expected %d, got %d (%s)", http.StatusTooManyRequests, w.Code, w.Body.String())
	}

	// Let the /bin/true operations reach a terminal state. Their metadata and
	// logs remain retained, but the capacity must be reusable immediately.
	app.OperationSupervisor.mu.RLock()
	ops := make([]*operation, 0, len(app.OperationSupervisor.ops))
	for _, op := range app.OperationSupervisor.ops {
		ops = append(ops, op)
	}
	app.OperationSupervisor.mu.RUnlock()
	for _, op := range ops {
		select {
		case <-op.done:
		case <-time.After(5 * time.Second):
			t.Fatal("operation did not reach a terminal state")
		}
	}

	w := runCapacityRequest(t, app, result.Token)
	if w.Code != http.StatusCreated {
		t.Fatalf("terminal operations must free capacity: expected %d, got %d (%s)",
			http.StatusCreated, w.Code, w.Body.String())
	}
}

// TestRunQuiesceRefusalLeavesNoPreparedState proves the
// reservation-before-expensive-work ordering: a run refused at admission
// (quiesced Launcher) creates no mount pins. The launcher quiesce is reached
// through the same capacity reservation gate, so the refusal happens before
// any pin, MAC lease, or Docker state. RED evidence at the starting SHA: the
// old flow pins every mount source before admit() is consulted, so a
// quiesce-refused run leaves prepared pins behind.
func TestRunQuiesceRefusalLeavesNoPreparedState(t *testing.T) {
	app := newSystemModeRunTestApp(t)
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	mountDir := filepath.Join(result.Session.Workspace, "mountdir")
	if err := os.MkdirAll(mountDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mountDir, "file.txt"), []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	var pinCount atomic.Int32
	app.PinMountSourceFn = func(sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinCount.Add(1)
		return &pinnedMount{
			PinnedPath: filepath.Join(t.TempDir(), "pin", fmt.Sprintf("%d", mountIndex)),
			cleanup:    func() error { return nil },
		}, nil
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	// Quiesce the Session's Launcher: no new Operation may be admitted for it.
	app.OperationSupervisor.quiesceLauncher(result.Session.LauncherID)

	req := newRunRequest(map[string]any{
		"image": "alpine:3.24",
		"mounts": []map[string]any{
			{"source": "mountdir", "target": "/data"},
		},
		"command": []string{"true"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	// The established quiesce contract is unchanged.
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("quiesce refusal: expected %d, got %d (%s)", http.StatusUnprocessableEntity, w.Code, w.Body.String())
	}
	if code := decodeRejectedResponse(t, w); code != "launcher_unavailable" {
		t.Fatalf("quiesce refusal code: expected launcher_unavailable, got %q", code)
	}

	// The refusal must happen before any expensive preparation.
	if got := pinCount.Load(); got != 0 {
		t.Fatalf("quiesce-refused run created %d mount pins before admission", got)
	}
}

// TestBuildQuiesceRefusalLeavesNoStaging proves the reservation-before-staging
// ordering for build: a build refused at admission does not stage its H4
// context. RED evidence at the starting SHA: the old flow stages the whole
// context before admit() is consulted.
func TestBuildQuiesceRefusalLeavesNoStaging(t *testing.T) {
	app, result := newCapacityTestApp(t)

	if err := os.WriteFile(filepath.Join(result.Session.Workspace, "Dockerfile"), []byte("FROM alpine\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var stagingCalls atomic.Int32
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		stagingCalls.Add(1)
		return newTestStagedContext(t, dfrel, nil), nil
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	app.OperationSupervisor.quiesceLauncher(result.Session.LauncherID)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("quiesce refusal: expected %d, got %d (%s)", http.StatusUnprocessableEntity, w.Code, w.Body.String())
	}
	if got := stagingCalls.Load(); got != 0 {
		t.Fatalf("quiesce-refused build staged its context %d time(s) before admission", got)
	}
}
