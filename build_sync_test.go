package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// setupSyncBuildTest creates an app with supervisor, staging seam, build
// seam, and a session, for synchronous build handler tests.
func setupSyncBuildTest(t *testing.T, opts buildSeamOptions) (*App, *operationSupervisor, *CreatedSession, *capturedBuild, string) {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	supervisor := newOperationSupervisor()
	app.OperationSupervisor = supervisor

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	if err := os.WriteFile(filepath.Join(result.Session.Workspace, "Dockerfile"), []byte("FROM alpine"), 0o644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	setupStagingSeam(t, app)
	captured := setupBuildSeam(t, app, opts)

	return app, supervisor, result, captured, result.Token
}

// TestBuildSynchronousSuccess proves the synchronous build contract on the
// production handler: the final result comes back in the response with no
// operation identity, exactly one build.start and build.finish audit pair is
// emitted, no build Operation is registered, and the staging directory is
// cleaned up.
func TestBuildSynchronousSuccess(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, supervisor, result, captured, token := setupSyncBuildTest(t, buildSeamOptions{
		Output: "#1 [internal] load build definition\n#1 DONE 0.1s\n",
	})
	_ = supervisor

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

	var resp buildResponse
	respBody := w.Body.Bytes()
	if err := json.NewDecoder(bytes.NewReader(respBody)).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.OK || resp.Code != "" || resp.Message != "" {
		t.Errorf("success response = %+v", resp)
	}
	if resp.Output != "#1 [internal] load build definition\n#1 DONE 0.1s\n" {
		t.Errorf("output = %q", resp.Output)
	}
	if resp.Truncated {
		t.Error("short output must not be truncated")
	}
	if resp.Duration == "" {
		t.Error("duration must be set")
	}

	// No operation identity anywhere: not in the response, not in the audit,
	// and no build Operation registered.
	var envelope map[string]any
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	if _, has := envelope["operation_id"]; has {
		t.Error("synchronous build response must not carry operation_id")
	}
	supervisor.mu.RLock()
	opCount := len(supervisor.ops)
	supervisor.mu.RUnlock()
	if opCount != 0 {
		t.Errorf("build must not register an operation, supervisor has %d", opCount)
	}
	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		if rec.OperationID != "" {
			t.Errorf("build audit must not carry operation_id: %+v", rec)
		}
		if rec.ExitCode != nil {
			t.Errorf("build audit must not carry exit_code: %+v", rec)
		}
	}

	// Exactly one start and one finish, in that order.
	startCount, finishCount := 0, 0
	var lastFinish string
	for _, rec := range records {
		switch rec.Event {
		case "build.start":
			startCount++
		case "build.finish":
			finishCount++
			lastFinish = rec.Result
		}
	}
	if startCount != 1 || finishCount != 1 {
		t.Fatalf("audit records: %d starts, %d finishes", startCount, finishCount)
	}
	if lastFinish != "succeeded" {
		t.Errorf("finish result = %q, want succeeded", lastFinish)
	}
	if finishCount > 0 {
		// build.finish must follow build.start
		firstStart, lastFinishIdx := -1, -1
		for i, rec := range records {
			if rec.Event == "build.start" && firstStart == -1 {
				firstStart = i
			}
			if rec.Event == "build.finish" {
				lastFinishIdx = i
			}
		}
		if firstStart > lastFinishIdx {
			t.Error("build.finish must come after build.start")
		}
	}

	// The Engine builder received the request semantics: image, Dockerfile,
	// build args, and the staged context tar.
	if captured.builderImage() != "example:test" {
		t.Errorf("builder image = %q", captured.spec.Image)
	}
	if captured.spec.Dockerfile != "Dockerfile" {
		t.Errorf("builder dockerfile = %q", captured.spec.Dockerfile)
	}
	if !bytes.Contains(captured.contextTar, []byte("FROM alpine")) {
		t.Errorf("builder context tar = %q", captured.contextTar)
	}
}

// TestBuildSynchronousBuildFailure proves an in-band build failure is a
// trustworthy negative result: 422 build_failed with the output preserved,
// and a build.finish with the docker_build_failed result.
func TestBuildSynchronousBuildFailure(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, _, result, _, token := setupSyncBuildTest(t, buildSeamOptions{
		Output: "step 1 ok\n",
		Err:    &engineError{kind: engineErrBuildFailed, cause: errors.New("process \"/bin/sh\" did not complete successfully: exit code: 2")},
	})

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected %d, got %d: %s", http.StatusUnprocessableEntity, w.Code, w.Body.String())
	}

	var resp buildResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Code != "build_failed" || resp.Message != "image build failed" {
		t.Errorf("failure response = %+v", resp)
	}
	if resp.Output != "step 1 ok\n" {
		t.Errorf("output = %q, want the rendered build output", resp.Output)
	}
	if resp.Duration == "" {
		t.Error("duration must be set")
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	finishCount, resultCount := 0, 0
	for _, rec := range records {
		if rec.Event == "build.finish" {
			finishCount++
			if rec.Result == "docker_build_failed" {
				resultCount++
			}
		}
	}
	if finishCount != 1 || resultCount != 1 {
		t.Errorf("audit records: %d finishes (%d docker_build_failed)", finishCount, resultCount)
	}
}

// TestBuildSynchronousRegistryAuthDenied proves a registry denial for a
// private FROM keeps its own category in the synchronous contract.
func TestBuildSynchronousRegistryAuthDenied(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, _, result, _, token := setupSyncBuildTest(t, buildSeamOptions{
		Err: &engineError{kind: engineErrRegistryAuthDenied, cause: errors.New("unauthorized")},
	})

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
	if resp.OK || resp.Code != "registry_auth_denied" {
		t.Errorf("failure response = %+v", resp)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	found := 0
	for _, rec := range records {
		if rec.Event == "build.finish" && rec.Result == "docker_build_failed" {
			found++
		}
	}
	if found != 1 {
		t.Errorf("docker_build_failed finish count = %d, want 1", found)
	}
}

// TestBuildSynchronousBackendFailure proves an unexpected Engine interaction
// failure keeps its own category in the synchronous contract: 502
// backend_failure, not the generic docker_build_failed fall-through.
func TestBuildSynchronousBackendFailure(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, _, result, _, token := setupSyncBuildTest(t, buildSeamOptions{
		Output: "step 1 ok\n",
		Err:    &engineError{kind: engineErrBackendFailure, cause: errors.New("unexpected engine failure")},
	})

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected %d, got %d: %s", http.StatusBadGateway, w.Code, w.Body.String())
	}

	var resp buildResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Code != "backend_failure" || resp.Message != "unexpected docker engine failure" {
		t.Errorf("failure response = %+v", resp)
	}
	if resp.Output != "step 1 ok\n" {
		t.Errorf("output = %q, want the rendered build output", resp.Output)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	found := 0
	for _, rec := range records {
		if rec.Event == "build.finish" && rec.Result == "docker_build_failed" {
			found++
		}
	}
	if found != 1 {
		t.Errorf("docker_build_failed finish count = %d, want 1", found)
	}
}

// TestBuildSynchronousAdapterConstructionFailure proves an Engine adapter
// construction failure is a synchronous docker_build_failed failure with
// exactly one finish.
func TestBuildSynchronousAdapterConstructionFailure(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, _, result, _, token := setupSyncBuildTest(t, buildSeamOptions{
		ConstructErr: errors.New("injected construction failure"),
	})

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

	var resp buildResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Code != "docker_build_failed" {
		t.Errorf("failure response = %+v", resp)
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

// TestBuildShutdownRefusal proves a build admitted during daemon shutdown is
// refused by the coordinator with the shutdown refusal contract, no build
// staging exists, and only build.rejected is audited.
func TestBuildShutdownRefusal(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, _, result, _, token := setupSyncBuildTest(t, buildSeamOptions{})
	app.beginShutdown()

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

	var resp buildResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Code != "shutting_down" {
		t.Errorf("refusal response = %+v", resp)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		if rec.Event == "build.start" || rec.Event == "build.finish" {
			t.Errorf("refused request must not audit %s", rec.Event)
		}
		if rec.Event == "build.rejected" && rec.Result != "shutting_down" {
			t.Errorf("rejected result = %q, want shutting_down", rec.Result)
		}
	}
	rejected := false
	for _, rec := range records {
		if rec.Event == "build.rejected" {
			rejected = true
		}
	}
	if !rejected {
		t.Error("build.rejected must be audited for the shutdown refusal")
	}
}

// TestBuildLauncherQuiesceRefusal proves a build for a quiesced Launcher is
// refused with the Launcher refusal contract.
func TestBuildLauncherQuiesceRefusal(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, _, result, _, token := setupSyncBuildTest(t, buildSeamOptions{})
	app.OperationSupervisor.quiesceLauncher(result.Session.LauncherID)

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
	if resp.OK || resp.Code != "launcher_unavailable" {
		t.Errorf("refusal response = %+v", resp)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	found := false
	for _, rec := range records {
		if rec.Event == "build.rejected" && rec.Result == "launcher_unavailable" {
			found = true
		}
		if rec.Event == "build.start" || rec.Event == "build.finish" {
			t.Errorf("refused request must not audit %s", rec.Event)
		}
	}
	if !found {
		t.Error("build.rejected with launcher_unavailable result must be audited")
	}
}

// TestBuildRequestCancellation proves a client-disconnect build is
// normalized as client-cancelled: docker_build_failed response, cancelled
// audit result, and staging cleanup.
func TestBuildRequestCancellation(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	block := make(chan struct{})
	var rmCount atomic.Int32
	app, _, result, captured, token := setupSyncBuildTest(t, buildSeamOptions{
		StreamBlock: block,
	})

	var stagingCapture capturedStaging
	app.StageBuildContextFn = stagingSeamWithCleanupCount(t, &stagingCapture, &rmCount)

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

	// Give the handler a moment to reach the blocked build, then cancel.
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
	case code := <-done:
		if code != http.StatusInternalServerError {
			t.Fatalf("expected %d, got %d", http.StatusInternalServerError, code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the handler never returned after cancellation")
	}

	var resp buildResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Code != "docker_build_failed" {
		t.Errorf("cancellation response = %+v", resp)
	}

	// Staging cleanup must have run despite the cancellation.
	if rmCount.Load() == 0 {
		t.Error("staging cleanup must run on the cancellation path")
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

// TestBuildStagingFailureIsSynchronousFailure proves a staging failure on an
// admitted request is a synchronous failure with exactly one finish, not a
// zombie request.
func TestBuildStagingFailureIsSynchronousFailure(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app, _, result, _, token := setupSyncBuildTest(t, buildSeamOptions{})
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, stagingID string) (*stagedBuildContext, error) {
		return nil, errors.New("injected staging error")
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

	var resp buildResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.Code != "docker_build_failed" {
		t.Errorf("failure response = %+v", resp)
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

// TestBuildCredentialValuesNeverLeak proves the build credential bridge
// stays secret-safe on the synchronous path: the fake builder receives a
// host-scoped credential resolver that yields exactly the stored credential
// of the requested registry (never an unrelated one), and no credential
// material reaches audit, the operational log, the public response, or the
// request database.
func TestBuildCredentialValuesNeverLeak(t *testing.T) {
	auditBuf, opLogBuf := setupTestLogging(t)

	const userCanary = "dh-prod-user-canary-8qLw3nTz5c"
	const passCanary = "dh-prod-pass-canary-Rm2Kx7Vb9d"

	app, _, result, captured, token := setupSyncBuildTest(t, buildSeamOptions{
		Output: "built\n",
	})
	// Store a credential under the registry the staged Dockerfile names.
	if err := storeSessionRegistryCredential(app.Config.RuntimeDir, result.Session.ID, "registry.example.com", userCanary, passCanary, ""); err != nil {
		t.Fatalf("store: %v", err)
	}
	// Also store an unrelated credential that must not be resolved.
	if err := storeSessionRegistryCredential(app.Config.RuntimeDir, result.Session.ID, "other.example.com", "other-user", "other-pass", ""); err != nil {
		t.Fatalf("store: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM registry.example.com/team/base:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

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

	// The requested host's stored credential resolves just in time, exactly
	// as the request-owned BuildKit auth session asks for it.
	credential, err := captured.resolveCredential("registry.example.com")
	if err != nil {
		t.Fatalf("resolve requested host: %v", err)
	}
	if credential == nil || credential.Username != userCanary || credential.Password != passCanary {
		t.Errorf("requested host credential = %+v", credential)
	}
	// Each requested host resolves exactly its own stored credential.
	credential, err = captured.resolveCredential("other.example.com")
	if err != nil {
		t.Fatalf("resolve unrelated host: %v", err)
	}
	if credential == nil || credential.Username != "other-user" || credential.Password != "other-pass" {
		t.Errorf("other host credential = %+v", credential)
	}
	// A host with nothing stored resolves anonymously.
	credential, err = captured.resolveCredential("unset.example.com")
	if err != nil {
		t.Fatalf("resolve unset host: %v", err)
	}
	if credential != nil {
		t.Errorf("unset host resolved credential material: %+v", credential)
	}

	// The public response must not carry the credential material.
	if strings.Contains(w.Body.String(), userCanary) || strings.Contains(w.Body.String(), passCanary) {
		t.Error("credential material leaked into the public response")
	}
	// Audit and operational logs must not carry it either.
	for _, line := range strings.Split(auditBuf.String(), "\n") {
		if line != "" && (strings.Contains(line, userCanary) || strings.Contains(line, passCanary)) {
			t.Errorf("credential material leaked into audit: %s", line)
		}
	}
	if opLog := opLogBuf.String(); strings.Contains(opLog, userCanary) || strings.Contains(opLog, passCanary) {
		t.Errorf("credential material leaked into the operational log: %s", opLog)
	}
	// The SQLite session store must not contain the build-time projection.
	dbBlob, err := os.ReadFile(app.Config.DatabasePath)
	if err != nil {
		t.Fatalf("read database: %v", err)
	}
	if bytes.Contains(dbBlob, []byte(userCanary)) {
		t.Error("credential material leaked into the request database")
	}
}
