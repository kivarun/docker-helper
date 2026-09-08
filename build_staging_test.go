//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// setupSyncStagingBuildTest creates an app with supervisor, staging seam,
// build seam, and a session, for synchronous staging-path tests.
func setupSyncStagingBuildTest(t *testing.T, opts buildSeamOptions) (*App, *operationSupervisor, *CreatedSession, *capturedBuild, string) {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	supervisor := newOperationSupervisor()
	app.OperationSupervisor = supervisor

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	if err := writeTestDockerfile(t, result.Session.Workspace); err != nil {
		t.Fatal(err)
	}

	setupStagingSeam(t, app)
	captured := setupBuildSeam(t, app, opts)

	return app, supervisor, result, captured, result.Token
}

func writeTestDockerfile(t *testing.T, workspace string) error {
	t.Helper()
	return os.WriteFile(filepath.Join(workspace, "Dockerfile"), []byte("FROM alpine"), 0o644)
}

// TestBuildStagingReceivesCanonicalPaths proves staging receives the
// canonical Session workspace paths — never the raw request paths — and the
// Engine build consumes the staged copies, not the workspace.
func TestBuildStagingReceivesCanonicalPaths(t *testing.T) {
	app, _, result, _, token := setupSyncStagingBuildTest(t, buildSeamOptions{Output: "ok\n"})

	var capture capturedStaging
	var stagedContextPath, stagedDockerfilePath string
	app.StageBuildContextFn = newStagingSeam(t, stagingSeamOptions{
		Capture: &capture,
		Staged:  &stagedContextPath,
	})

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	if capture.dockerfileRel != "Dockerfile" {
		t.Errorf("staged dockerfile = %q, want the canonical relative path", capture.dockerfileRel)
	}
	if stagedContextPath == "" || stagedContextPath == result.Session.Workspace {
		t.Error("the Engine build must consume a staged context, not the workspace")
	}
	if stagedDockerfilePath == filepath.Join(result.Session.Workspace, "Dockerfile") {
		t.Error("the Engine build must consume the staged Dockerfile, not the workspace path")
	}

	// After the handler the staged directory is cleaned up.
	if _, err := os.Stat(stagedContextPath); err == nil {
		t.Error("staged context must be cleaned up after the build")
	}
}

// TestBuildDockerfileDotSlash proves "./Dockerfile" is normalized to the
// canonical relative path before staging.
func TestBuildDockerfileDotSlash(t *testing.T) {
	app, _, _, _, token := setupSyncStagingBuildTest(t, buildSeamOptions{Output: "ok\n"})

	var capture capturedStaging
	app.StageBuildContextFn = stagingSeamWithCapture(t, &capture)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "./Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}
	if capture.dockerfileRel != "Dockerfile" {
		t.Errorf("dockerfileRel = %q, want %q", capture.dockerfileRel, "Dockerfile")
	}
}

// TestBuildDockerfileDotDotPath proves a normalizable ".." inside the
// context resolves to the canonical relative path before staging.
func TestBuildDockerfileDotDotPath(t *testing.T) {
	app, _, result, _, token := setupSyncStagingBuildTest(t, buildSeamOptions{Output: "ok\n"})

	if err := os.MkdirAll(filepath.Join(app.Config.AllowedRoots[0], "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}

	var capture capturedStaging
	app.StageBuildContextFn = stagingSeamWithCapture(t, &capture)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "subdir/../Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}
	if capture.dockerfileRel != "Dockerfile" {
		t.Errorf("dockerfileRel = %q, want %q", capture.dockerfileRel, "Dockerfile")
	}
	_ = result
}

// TestBuildDockerfileSymlink proves a symlinked Dockerfile inside the
// context is resolved to the real file before staging.
func TestBuildDockerfileSymlink(t *testing.T) {
	app, _, result, _, token := setupSyncStagingBuildTest(t, buildSeamOptions{Output: "ok\n"})

	if err := os.Remove(filepath.Join(result.Session.Workspace, "Dockerfile")); err != nil {
		t.Fatal(err)
	}
	realDockerfile := filepath.Join(result.Session.Workspace, "real.Dockerfile")
	if err := os.WriteFile(realDockerfile, []byte("FROM alpine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.Dockerfile", filepath.Join(result.Session.Workspace, "Dockerfile")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	var capture capturedStaging
	app.StageBuildContextFn = stagingSeamWithCapture(t, &capture)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}
	if capture.dockerfileRel != "real.Dockerfile" {
		t.Errorf("dockerfileRel = %q, want the symlink target inside the context", capture.dockerfileRel)
	}
}

// TestBuildStagingFailureDoesNotReachEngine proves a staging failure is a
// synchronous failure with no Engine call and no registered operation.
func TestBuildStagingFailureDoesNotReachEngine(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, supervisor, result, _, token := setupSyncStagingBuildTest(t, buildSeamOptions{})
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, stagingID string) (*stagedBuildContext, error) {
		return nil, os.ErrInvalid
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected %d, got %d", http.StatusInternalServerError, w.Code)
	}

	supervisor.mu.RLock()
	opCount := len(supervisor.ops)
	supervisor.mu.RUnlock()
	if opCount != 0 {
		t.Errorf("no operation may be registered for a build failure, supervisor has %d", opCount)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	startCount, finishCount := 0, 0
	for _, rec := range records {
		switch rec.Event {
		case "build.start":
			startCount++
		case "build.finish":
			finishCount++
			if rec.Result != "docker_build_failed" {
				t.Errorf("finish result = %q, want docker_build_failed", rec.Result)
			}
		}
	}
	if startCount != 1 || finishCount != 1 {
		t.Errorf("audit records: %d starts, %d finishes", startCount, finishCount)
	}
}

// TestBuildAdmissionRefusalStagesNothing proves admission happens before
// staging: a refused build never creates staging state to clean up.
func TestBuildAdmissionRefusalStagesNothing(t *testing.T) {
	app, _, result, _, token := setupSyncStagingBuildTest(t, buildSeamOptions{})
	app.beginShutdown()

	var stagingAttempts atomic.Int32
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, stagingID string) (*stagedBuildContext, error) {
		stagingAttempts.Add(1)
		return nil, os.ErrInvalid
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, w.Code)
	}
	if stagingAttempts.Load() != 0 {
		t.Error("a refused build must not stage anything")
	}
	_ = result
}

// TestBuildSuccessCleansStaging proves the success path cleans the staging
// directory exactly once.
func TestBuildSuccessCleansStaging(t *testing.T) {
	var rmCount atomic.Int32
	app, _, _, _, token := setupSyncStagingBuildTest(t, buildSeamOptions{Output: "ok\n"})
	app.StageBuildContextFn = stagingSeamWithCleanupCount(t, &capturedStaging{}, &rmCount)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}
	if got := rmCount.Load(); got != 1 {
		t.Errorf("staging cleanup ran %d times, want 1", got)
	}
}

// TestBuildBuildFailureCleansStaging proves the build-failure path cleans
// the staging directory exactly once.
func TestBuildBuildFailureCleansStaging(t *testing.T) {
	var rmCount atomic.Int32
	app, _, _, _, token := setupSyncStagingBuildTest(t, buildSeamOptions{
		Err: &engineError{kind: engineErrBuildFailed, cause: errors.New("build failed")},
	})
	app.StageBuildContextFn = stagingSeamWithCleanupCount(t, &capturedStaging{}, &rmCount)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected %d, got %d", http.StatusUnprocessableEntity, w.Code)
	}
	if got := rmCount.Load(); got != 1 {
		t.Errorf("staging cleanup ran %d times, want 1", got)
	}
}

// TestBuildCancellationCleansStaging proves the cancellation path cleans
// the staging directory exactly once.
func TestBuildCancellationCleansStaging(t *testing.T) {
	var rmCount atomic.Int32
	block := make(chan struct{})
	app, _, _, captured, token := setupSyncStagingBuildTest(t, buildSeamOptions{
		StreamBlock: block,
	})
	app.StageBuildContextFn = stagingSeamWithCleanupCount(t, &capturedStaging{}, &rmCount)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	reqCtx, cancelReq := context.WithCancel(req.Context())
	req = req.WithContext(reqCtx)

	w := httptest.NewRecorder()
	done := make(chan int, 1)
	go func() {
		app.handleBuild(w, req)
		done <- w.Code
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if captured.reachedBuild() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !captured.reachedBuild() {
		t.Fatal("the handler never reached the build")
	}

	cancelReq()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the handler never returned after cancellation")
	}
	if got := rmCount.Load(); got != 1 {
		t.Errorf("staging cleanup ran %d times, want 1", got)
	}
}

// TestBuildDaemonShutdownCancelsBuild proves the coordinator's bounded
// shutdown termination cancels an in-flight synchronous build: the handler
// completes with the cancelled result and cleans staging.
func TestBuildDaemonShutdownCancelsBuild(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	var rmCount atomic.Int32
	app, _, result, _, token := setupSyncStagingBuildTest(t, buildSeamOptions{
		StreamBlock: make(chan struct{}),
	})
	app.StageBuildContextFn = stagingSeamWithCleanupCount(t, &capturedStaging{}, &rmCount)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	done := make(chan int, 1)
	go func() {
		app.handleBuild(w, req)
		done <- w.Code
	}()

	// Wait until the handler is inside the build, then shut down the daemon.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !app.SyncExecutionCoordinator.hasLiveForLauncher(result.Session.LauncherID) {
			continue
		}
		break
	}

	app.beginShutdown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	app.SyncExecutionCoordinator.terminateForShutdown(shutdownCtx)

	select {
	case code := <-done:
		if code != http.StatusInternalServerError {
			t.Fatalf("expected %d, got %d", http.StatusInternalServerError, code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the handler never returned after daemon shutdown")
	}
	if got := rmCount.Load(); got != 1 {
		t.Errorf("staging cleanup ran %d times, want 1", got)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	finishCount, cancelledCount := 0, 0
	for _, rec := range records {
		if rec.Event == "build.finish" {
			finishCount++
			if rec.Result == "cancelled" {
				cancelledCount++
			}
		}
	}
	if finishCount != 1 || cancelledCount != 1 {
		t.Errorf("audit records: %d finishes (%d cancelled)", finishCount, cancelledCount)
	}
}

// TestBuildStagingCleanupErrorLogged proves a staging cleanup error is
// logged operationally and the synchronous result is unaffected.
func TestBuildStagingCleanupErrorLogged(t *testing.T) {
	_, opLogBuf := setupTestLogging(t)

	app, _, _, _, token := setupSyncStagingBuildTest(t, buildSeamOptions{Output: "ok\n"})
	app.StageBuildContextFn = stagingSeamWithCleanupError(t, sentinelCleanupErr)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	opLogContent := opLogBuf.String()
	if !strings.Contains(opLogContent, "staging cleanup failed") {
		t.Errorf("operational log should contain the cleanup error, got: %s", opLogContent)
	}
}

// TestBuildCleanupErrorPreservesSuccessResult proves a cleanup error does
// not change the synchronous success result.
func TestBuildCleanupErrorPreservesSuccessResult(t *testing.T) {
	auditBuf, opLogBuf := setupTestLogging(t)

	app, _, result, _, token := setupSyncStagingBuildTest(t, buildSeamOptions{Output: "ok\n"})
	app.StageBuildContextFn = stagingSeamWithCleanupError(t, sentinelCleanupErr)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	var resp buildResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Errorf("response = %+v, want success despite the cleanup error", resp)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	found := false
	for _, rec := range records {
		if rec.Event == "build.finish" && rec.Result == "succeeded" {
			found = true
		}
	}
	if !found {
		t.Error("build.finish succeeded must be audited despite the cleanup error")
	}
	if !strings.Contains(opLogBuf.String(), "staging cleanup failed") {
		t.Error("the cleanup error must be logged")
	}
}

// TestBuildCleanupErrorPreservesFailureResult proves a cleanup error does
// not change the synchronous build-failure result.
func TestBuildCleanupErrorPreservesFailureResult(t *testing.T) {
	auditBuf, opLogBuf := setupTestLogging(t)

	app, _, result, _, token := setupSyncStagingBuildTest(t, buildSeamOptions{
		Err: &engineError{kind: engineErrBuildFailed, cause: errors.New("build failed")},
	})
	app.StageBuildContextFn = stagingSeamWithCleanupError(t, sentinelCleanupErr)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected %d, got %d", http.StatusUnprocessableEntity, w.Code)
	}

	var resp buildResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Code != "build_failed" {
		t.Errorf("response = %+v, want the build failure despite the cleanup error", resp)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	found := false
	for _, rec := range records {
		if rec.Event == "build.finish" && rec.Result == "docker_build_failed" {
			found = true
		}
	}
	if !found {
		t.Error("build.finish docker_build_failed must be audited despite the cleanup error")
	}
	if !strings.Contains(opLogBuf.String(), "staging cleanup failed") {
		t.Error("the cleanup error must be logged")
	}
}

// TestStagedCleanupReturnsError verifies that Cleanup() returns the error
// from the injected removeAll and that repeated calls return the same error.
func TestStagedCleanupReturnsError(t *testing.T) {
	var rmCount atomic.Int32
	s := newTestStagedContext(t, "Dockerfile", func(path string) error {
		rmCount.Add(1)
		return sentinelCleanupErr
	})

	if err := s.Cleanup(); !errors.Is(err, sentinelCleanupErr) {
		t.Errorf("first Cleanup() error = %v, want sentinelCleanupErr", err)
	}
	if err := s.Cleanup(); !errors.Is(err, sentinelCleanupErr) {
		t.Errorf("second Cleanup() error = %v, want sentinelCleanupErr", err)
	}
	if got := rmCount.Load(); got != 1 {
		t.Errorf("removeAll called %d times, want 1", got)
	}
}

// TestStagedCleanupConcurrentExactlyOnce verifies that concurrent Cleanup()
// calls invoke removeAll exactly once and all callers get the same error.
func TestStagedCleanupConcurrentExactlyOnce(t *testing.T) {
	var rmCount atomic.Int32
	s := newTestStagedContext(t, "Dockerfile", func(path string) error {
		rmCount.Add(1)
		return sentinelCleanupErr
	})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Cleanup(); !errors.Is(err, sentinelCleanupErr) {
				t.Errorf("Cleanup() error = %v, want sentinelCleanupErr", err)
			}
		}()
	}
	wg.Wait()

	if got := rmCount.Load(); got != 1 {
		t.Errorf("removeAll called %d times, want 1", got)
	}
}
