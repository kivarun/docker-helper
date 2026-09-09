package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

// dockerAvailable skips the test unless a Docker Engine is reachable from
// the environment through the Docker CLI. The D0 real-Engine integration
// tests use it to run in any environment and to drive the Engine matrix.
func dockerAvailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not found in PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skipf("Docker daemon not reachable: %v", err)
	}
}

// TestRunEngineIntegration validates the migrated production one-shot run
// path end to end against a real Docker Engine:
//
//   - a started workload returns the flat synchronous result directly, with
//     combined bounded output and the actual exit code;
//   - a non-zero workload exit is a workload result, not a backend failure;
//   - environment, entrypoint, and workdir reach the workload through the
//     Engine create config, never through a daemon-side CLI argv;
//   - a workspace-relative mount reads daemon-written content and a
//     read-only mount refuses writes through the bind mount;
//   - request cancellation and daemon shutdown terminate the workload and
//     remove the transient container deterministically, with run-owned
//     audit attribution and no operation identity;
//   - no helper-owned transient container survives any terminal result;
//   - an unreachable Engine is a bounded backend-unavailable failure that
//     guesses no exit code;
//   - workload material and backend identifiers never reach the log sinks;
//   - run registers no operations.
//
// The helper_socket / trusted-CA projection rows run in system mode and are
// exercised only on a root environment with an active supported MAC backend;
// they are skipped otherwise with the environment constraint recorded.
//
// The test skips unless a Docker Engine is reachable.
func TestRunEngineIntegration(t *testing.T) {
	dockerAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 480*time.Second)
	defer cancel()

	provisioning, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("construct engine provisioning client: %v", err)
	}

	// Pull the base image once through the provisioning client; the run
	// path's own auto-pull behavior is part of the adapter contract already
	// covered by the D0 pull gates and the seam tests.
	pullReader, err := provisioning.ImagePull(ctx, "alpine:3.24", client.ImagePullOptions{})
	if err != nil {
		t.Fatalf("pull base image: %v", err)
	}
	if err := pullReader.Wait(ctx); err != nil {
		t.Fatalf("pull base image: %v", err)
	}

	auditBuf, opBuf := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	app.NewEngineRunFn = nil // production path: real shared adapter

	session, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Row 1: a successful workload returns the flat synchronous result
	// with combined bounded output and the real exit code.
	w := boundedRunRow(t, app, session.Token, map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"sh", "-ec", "echo RUN-OUT-OK; echo RUN-ERR-OK >&2"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("exit-0 run: %d %s", w.Code, w.Body.String())
	}
	success := decodeRunResponse(t, w)
	if !success.OK || success.ExitCode == nil || *success.ExitCode != 0 {
		t.Errorf("exit-0 response = %+v", success)
	}
	if success.Code != "" {
		t.Errorf("successful run must carry no failure code: %+v", success)
	}
	if !strings.Contains(success.Output, "RUN-OUT-OK") || !strings.Contains(success.Output, "RUN-ERR-OK") {
		t.Errorf("combined output must capture stdout and stderr: %+v", success)
	}
	if success.Truncated {
		t.Errorf("short output must not be truncated: %+v", success)
	}
	if success.Duration == "" {
		t.Error("successful run must report a duration")
	}
	assertRunFinishResult(t, auditBuf, session.Session.ID, "succeeded")
	assertNoHelperOwnedContainers(ctx, t, provisioning, session.Session.ID)

	// Row 2: a non-zero workload exit is a workload result with the
	// actual exit code and the preserved bounded output.
	w = boundedRunRow(t, app, session.Token, map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"sh", "-ec", "echo BEFORE-FAIL; exit 7"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("non-zero-exit run: %d %s", w.Code, w.Body.String())
	}
	failed := decodeRunResponse(t, w)
	if failed.OK {
		t.Errorf("non-zero exit must not be ok: %+v", failed)
	}
	if failed.Code != "container_exit_nonzero" {
		t.Errorf("code = %q, want container_exit_nonzero", failed.Code)
	}
	if failed.ExitCode == nil || *failed.ExitCode != 7 {
		t.Errorf("exit_code = %+v, want 7", failed.ExitCode)
	}
	if !strings.Contains(failed.Output, "BEFORE-FAIL") {
		t.Errorf("failed workload must preserve its output: %+v", failed)
	}
	assertRunFinishResult(t, auditBuf, session.Session.ID, "container_exit_nonzero")
	assertNoHelperOwnedContainers(ctx, t, provisioning, session.Session.ID)

	// Row 3: environment values reach the workload through the create
	// config environment, not through any CLI argv.
	w = boundedRunRow(t, app, session.Token, map[string]any{
		"image":       "alpine:3.24",
		"environment": map[string]any{"RUN_INTEG_KEY": "RUN_INTEG_VALUE"},
		"command":     []string{"sh", "-ec", "echo KEY=$RUN_INTEG_KEY"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("env run: %d %s", w.Code, w.Body.String())
	}
	envResult := decodeRunResponse(t, w)
	if !strings.Contains(envResult.Output, "KEY=RUN_INTEG_VALUE") {
		t.Errorf("environment not visible to the workload: %+v", envResult)
	}

	// Row 4: entrypoint and workdir are honored through the create config.
	w = boundedRunRow(t, app, session.Token, map[string]any{
		"image":      "alpine:3.24",
		"entrypoint": "/bin/sh",
		"workdir":    "/tmp",
		"command":    []string{"-c", "pwd"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("entrypoint/workdir run: %d %s", w.Code, w.Body.String())
	}
	wdResult := decodeRunResponse(t, w)
	if !strings.Contains(wdResult.Output, "/tmp") {
		t.Errorf("workdir not honored: %+v", wdResult)
	}

	// Row 5: a workspace-relative mount reads daemon-written content
	// through the resolved workspace source; ordinary mounts stay ordinary
	// workspace mounts (no arbitrary absolute host mount).
	if err := os.WriteFile(filepath.Join(session.Session.Workspace, "run-in.txt"),
		[]byte("RUN-INTEGRATION-CONTENT\n"), 0o644); err != nil {
		t.Fatalf("write workspace file: %v", err)
	}
	w = boundedRunRow(t, app, session.Token, map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"sh", "-ec", "cat /mnt/run-in.txt"},
		"mounts":  []map[string]any{{"source": ".", "target": "/mnt"}},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("mounted run: %d %s", w.Code, w.Body.String())
	}
	mounted := decodeRunResponse(t, w)
	if !strings.Contains(mounted.Output, "RUN-INTEGRATION-CONTENT") {
		t.Errorf("workspace mount content not visible in the workload: %+v", mounted)
	}

	// Row 6: a read-only mount refuses writes as a workload result.
	w = boundedRunRow(t, app, session.Token, map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"sh", "-ec", "touch /mnt/no-write && echo wrote"},
		"mounts": []map[string]any{
			{"source": ".", "target": "/mnt", "read_only": true},
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("read-only run: %d %s", w.Code, w.Body.String())
	}
	roResult := decodeRunResponse(t, w)
	if roResult.OK {
		t.Errorf("read-only mount write must fail, response = %+v", roResult)
	}
	if roResult.Code != "container_exit_nonzero" {
		t.Errorf("read-only write rejection = %q, want a workload result", roResult.Code)
	}

	// Row 7: request cancellation terminates the workload and removes the
	// transient container. The handler owns the removal through the
	// request-scoped adapter context; no orphan remains.
	cancelReq, cancel := context.WithCancel(context.Background())
	cancelDone := runRunAsync(t, app, session.Token, map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"sleep", "300"},
	}, cancelReq)

	cancelContainer := waitHelperRunningContainer(ctx, t, provisioning, session.Session.ID)
	if cancelContainer == "" {
		t.Fatal("cancelled run never started its workload container")
	}

	cancel()

	select {
	case respCode := <-cancelDone:
		if respCode != http.StatusInternalServerError {
			t.Errorf("cancelled run response = %d, want 500 docker_run_failed", respCode)
		}
		assertRunFinishResult(t, auditBuf, session.Session.ID, "cancelled")
	case <-time.After(60 * time.Second):
		t.Fatal("cancelled run did not return")
	}
	waitHelperContainerGone(ctx, t, provisioning, cancelContainer)
	assertNoHelperOwnedContainers(ctx, t, provisioning, session.Session.ID)

	// Row 8: daemon shutdown terminates an admitted run through the
	// coordinator ordering: close admission, cancel live request contexts,
	// handler performs run-owned cleanup, handler ends.
	shutdownCtx, cancelShutdown := context.WithCancel(context.Background())
	_ = cancelShutdown
	shutdownDone := runRunAsync(t, app, session.Token, map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"sleep", "300"},
	}, shutdownCtx)

	shutdownContainer := waitHelperRunningContainer(ctx, t, provisioning, session.Session.ID)
	if shutdownContainer == "" {
		t.Fatal("shutdown run never started its workload container")
	}

	app.SyncExecutionCoordinator.beginShutdown()
	termCtx, cancelTerm := context.WithTimeout(context.Background(), 30*time.Second)
	app.SyncExecutionCoordinator.terminateForShutdown(termCtx)
	cancelTerm()

	select {
	case respCode := <-shutdownDone:
		if respCode != http.StatusInternalServerError {
			t.Errorf("shutdown run response = %d, want 500 docker_run_failed", respCode)
		}
		assertRunFinishResult(t, auditBuf, session.Session.ID, "cancelled")
	case <-time.After(60 * time.Second):
		t.Fatal("shutdown run did not return")
	}
	waitHelperContainerGone(ctx, t, provisioning, shutdownContainer)
	assertNoHelperOwnedContainers(ctx, t, provisioning, session.Session.ID)

	// Row 9: an unreachable Engine is a bounded backend-unavailable
	// failure; no exit code is guessed. A fresh app is used because row 8
	// left its coordinator in the shutdown state.
	deadApp := newTestAppWithAdminToken(t)
	deadSession, deadSessionErr := createDefaultAdminSessionForTest(deadApp, testWorkspaceDir(t, deadApp.Config.AllowedRoots[0]))
	if deadSessionErr != nil {
		t.Fatalf("createSession for unreachable-engine row: %v", deadSessionErr)
	}
	deadSocket := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := deadSocket.URL
	deadSocket.Close()
	deadApp.NewEngineRunFn = func() (engineContainerRunner, error) {
		return newEngineClientAgainstFake(t, deadURL), nil
	}
	w = boundedRunRow(t, deadApp, deadSession.Token, map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"echo", "hi"},
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("transport-failure run: %d %s", w.Code, w.Body.String())
	}
	transportFailed := decodeRunResponse(t, w)
	if transportFailed.OK || transportFailed.Code != "backend_unavailable" {
		t.Errorf("transport-failure response = %+v", transportFailed)
	}
	if transportFailed.ExitCode != nil {
		t.Errorf("transport failure must not guess an exit code: %+v", transportFailed)
	}
	assertRunFinishResult(t, auditBuf, deadSession.Session.ID, "docker_run_failed")

	// Workload material never reaches the log sinks.
	for _, sink := range []struct{ name, blob string }{
		{"audit", auditBuf.String()},
		{"operational log", opBuf.String()},
	} {
		for _, canary := range []string{"RUN-OUT-OK", "RUN-ERR-OK", "RUN_INTEG_KEY", "RUN_INTEG_VALUE", "RUN-INTEGRATION-CONTENT"} {
			if strings.Contains(sink.blob, canary) {
				t.Errorf("%s contains workload material %q", sink.name, canary)
			}
		}
	}

	// Run must not register operations: the supervisor no longer accepts
	// run work at all.
	app.OperationSupervisor.mu.RLock()
	opCount := len(app.OperationSupervisor.ops)
	app.OperationSupervisor.mu.RUnlock()
	if opCount != 0 {
		t.Errorf("run must not register operations, supervisor has %d", opCount)
	}

	// Rows 10+: helper_socket projection and trusted-CA coexistence
	// require system mode with an active supported MAC backend; exercise
	// them only where the Session MAC bindings can be prepared.
	if os.Geteuid() != 0 {
		t.Log("skipping system-mode helper_socket rows: not running as root")
		return
	}
	backend, lsmErr := detectLSM()
	if lsmErr != nil {
		t.Fatalf("detect LSM in system-mode run row: %v", lsmErr)
	}
	if backend == LSMNone {
		t.Skip("system mode requires an active supported MAC backend; none detected")
	}

	systemApp := newTestAppWithAdminToken(t)
	systemApp.Config.Mode = ModeSystem
	systemResult, err := createSystemSession(t, systemApp)
	if err != nil {
		t.Fatalf("create system session: %v", err)
	}

	// helper_socket true: the workload sees the daemon-owned read-only
	// projection at /run/docker-helper and cannot write through it. The
	// caller mount surface stays ordinary workspace mount policy.
	w = boundedRunRow(t, systemApp, systemResult.Token, map[string]any{
		"image":         "alpine:3.24",
		"helper_socket": true,
		"command": []string{"sh", "-ec",
			"test -d /run/docker-helper && touch /run/docker-helper/no-write 2>/dev/null && echo wrote-projection || echo projection-readonly"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("helper_socket run: %d %s", w.Code, w.Body.String())
	}
	socketResult := decodeRunResponse(t, w)
	if !strings.Contains(socketResult.Output, "projection-readonly") {
		t.Errorf("helper_socket projection not mounted read-only: %+v", socketResult)
	}

	// Trusted-CA injection and helper_socket projection coexist: the CA
	// environment is present and the socket projection is mounted.
	setupCADir(t, systemApp)
	w = boundedRunRow(t, systemApp, systemResult.Token, map[string]any{
		"image":         "alpine:3.24",
		"helper_socket": true,
		"command": []string{"sh", "-ec",
			"test -n \"$SSL_CERT_FILE\" && test -f /etc/ssl/certs/ca-certificates.crt && test -d /run/docker-helper && echo coexist-ok || echo coexist-fail"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("CA+helper_socket run: %d %s", w.Code, w.Body.String())
	}
	coexist := decodeRunResponse(t, w)
	if !strings.Contains(coexist.Output, "coexist-ok") {
		t.Errorf("trusted CA and helper_socket projections must coexist: %+v", coexist)
	}
	assertNoHelperOwnedContainers(ctx, t, provisioning, systemResult.Session.ID)
}

// boundedRunRow drives one synchronous integration row with a bounded
// request context. The workloads in the rows are short-lived; a wedged
// Engine wait must surface as the classified cancellation (with the
// handler-owned container cleanup) instead of hanging the whole job.
func boundedRunRow(t *testing.T, app *App, token string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	reqCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return postRunCtx(t, app, token, body, reqCtx)
}

// runRunAsync drives one blocking synchronous run through the production
// handler with the given request context and returns the response recorder.
func runRunAsync(t *testing.T, app *App, token string, body map[string]any, reqCtx context.Context) <-chan int {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal run request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(data)).WithContext(reqCtx)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	done := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		app.handleRun(w, req)
		done <- w.Code
	}()
	return done
}

// waitHelperRunningContainer polls the Engine until a helper-owned container
// for the Session is running and returns its ID. Empty means never appeared.
func waitHelperRunningContainer(ctx context.Context, t *testing.T, provisioning *client.Client, sessionID string) string {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		list, err := provisioning.ContainerList(ctx, client.ContainerListOptions{
			Filters: client.Filters{}.Add("label", runtimeLabelSessionID+"="+sessionID),
			All:     true,
		})
		if err != nil {
			t.Fatalf("list helper containers: %v", err)
		}
		for _, c := range list.Items {
			if c.State == "running" {
				return c.ID
			}
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(200 * time.Millisecond):
		}
	}
	return ""
}

// waitHelperContainerGone polls the Engine until the container no longer
// exists, bounded by the context.
func waitHelperContainerGone(ctx context.Context, t *testing.T, provisioning *client.Client, containerID string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := provisioning.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{}); err != nil {
			if cerrdefs.IsNotFound(err) {
				return
			}
			t.Fatalf("inspect transient container: %v", err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("transient container %s still present at context end", containerID)
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatalf("transient container still present after cleanup deadline")
}

// assertNoHelperOwnedContainers proves the helper-owned label set leaves no
// transient container behind after a terminal result.
func assertNoHelperOwnedContainers(ctx context.Context, t *testing.T, provisioning *client.Client, sessionID string) {
	t.Helper()
	list, err := provisioning.ContainerList(ctx, client.ContainerListOptions{
		Filters: client.Filters{}.Add("label", runtimeLabelSessionID+"="+sessionID),
		All:     true,
	})
	if err != nil {
		t.Fatalf("list helper containers: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("helper-owned transient containers must not survive terminal results: %d remain", len(list.Items))
	}
}

// assertRunFinishResult asserts the run.finish audit result for the Session.
func assertRunFinishResult(t *testing.T, auditBuf *bytes.Buffer, sessionID, wantResult string) {
	t.Helper()

	var last *auditRecord
	for _, rec := range filterBySession(parseAuditRecords(auditBuf), sessionID) {
		if rec.Event == "run.finish" {
			copy := rec
			last = &copy
		}
	}
	if last == nil {
		t.Fatal("run.finish audit event not found")
	}
	if last.Result != wantResult {
		t.Fatalf("run.finish result = %q, want %q", last.Result, wantResult)
	}
	if last.OperationID != "" {
		t.Errorf("run audit must carry no operation identity, got %q", last.OperationID)
	}
}
