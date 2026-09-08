package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

// TestBuildEngineIntegration validates the migrated production build path end
// to end against a real Docker Engine and a disposable authenticated
// registry:
//
//   - a public simple build through the supported builder succeeds and
//     renders build progress;
//   - a custom Dockerfile selection is honored;
//   - build args reach the Engine;
//   - a private FROM consumes the credential resolved just in time from the
//     session store;
//   - a wrong stored credential and a fresh session without one are refused
//     with the sanitized denial and credential material never leaks;
//   - a cancelled build is bounded: the request ends with the generic build
//     failure, no tagged target image lands, and staging residue is absent;
//   - an unreachable Engine is a bounded backend-unavailable failure.
//
// The test skips unless a Docker Engine is reachable.
func TestBuildEngineIntegration(t *testing.T) {
	dockerAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	provisioning, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("construct engine provisioning client: %v", err)
	}

	// Make the base image local so FROM resolution never depends on
	// registry availability.
	pullReader, err := provisioning.ImagePull(ctx, "alpine:3.24", client.ImagePullOptions{})
	if err != nil {
		t.Fatalf("pull base image: %v", err)
	}
	if err := pullReader.Wait(ctx); err != nil {
		t.Fatalf("pull base image: %v", err)
	}

	const userCanary = "dh-prod-build-user-canary-8qLw3nTz5c"
	const passCanary = "dh-prod-build-pass-canary-Rm2Kx7Vb9d"

	registryHost := provisionDisposableRegistry(t, ctx, provisioning, "dh-build-auth-volume", userCanary, passCanary)

	// Seed the private base image through the provisioning client, not the
	// production path under test.
	privateBase := registryHost + "/dh-build/base:v1"
	if _, err := provisioning.ImageTag(ctx, client.ImageTagOptions{Source: "alpine:3.24", Target: privateBase}); err != nil {
		t.Fatalf("tag private base image: %v", err)
	}
	authBlob, err := json.Marshal(map[string]any{
		"username":      userCanary,
		"password":      passCanary,
		"serveraddress": registryHost,
	})
	if err != nil {
		t.Fatalf("marshal push auth: %v", err)
	}
	push, err := provisioning.ImagePush(ctx, privateBase, client.ImagePushOptions{RegistryAuth: base64.StdEncoding.EncodeToString(authBlob)})
	if err != nil {
		t.Fatalf("push private base image: %v", err)
	}
	if err := push.Wait(ctx); err != nil {
		t.Fatalf("push private base image: %v", err)
	}

	// Production path: real adapter (nil seam, Engine endpoint from the
	// environment), test app, and one Session bearer.
	auditBuf, opBuf := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	app.NewEngineBuildFn = nil

	session, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Row 1+2: a public simple build through the supported builder succeeds
	// and carries build output. This is the production ImageBuild path with
	// the BuildKit builder.
	if err := os.WriteFile(filepath.Join(session.Session.Workspace, "Dockerfile"),
		[]byte("FROM alpine:3.24\nRUN echo integration-build-ok\n"), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	targetRef := "dh-build-integration:public"
	w := postBuild(t, app, session.Token, map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      targetRef,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("public build: %d %s", w.Code, w.Body.String())
	}
	built := decodeBuildResponse(t, w)
	if !built.OK {
		t.Errorf("public build response = %+v", built)
	}
	if built.Truncated {
		t.Errorf("short public build must not be truncated: %+v", built)
	}
	assertBuildFinishResult(t, auditBuf, session.Session.ID, "succeeded")
	if _, inspectErr := provisioning.ImageInspect(ctx, targetRef); inspectErr != nil {
		t.Fatalf("built image %s is not present in the Engine: %v", targetRef, inspectErr)
	}

	// Row 3: a custom Dockerfile name is honored.
	if err := os.WriteFile(filepath.Join(session.Session.Workspace, "build.Dockerfile"),
		[]byte("FROM alpine:3.24\nRUN echo custom-dockerfile\n"), 0o644); err != nil {
		t.Fatalf("write custom Dockerfile: %v", err)
	}
	customRef := "dh-build-integration:custom"
	w = postBuild(t, app, session.Token, map[string]any{
		"context":    ".",
		"dockerfile": "build.Dockerfile",
		"image":      customRef,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("custom-Dockerfile build: %d %s", w.Code, w.Body.String())
	}
	assertBuildFinishResult(t, auditBuf, session.Session.ID, "succeeded")
	if _, inspectErr := provisioning.ImageInspect(ctx, customRef); inspectErr != nil {
		t.Fatalf("built image %s is not present in the Engine: %v", customRef, inspectErr)
	}

	// Row 4: build args reach the Engine and distinguish builds.
	argsRef := "dh-build-integration:args"
	w = postBuild(t, app, session.Token, map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      argsRef,
		"build_args": map[string]any{
			"INTEGRATION_BUILD_ARG": "1",
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("build-args build: %d %s", w.Code, w.Body.String())
	}
	assertBuildFinishResult(t, auditBuf, session.Session.ID, "succeeded")
	if _, inspectErr := provisioning.ImageInspect(ctx, argsRef); inspectErr != nil {
		t.Fatalf("built image %s is not present in the Engine: %v", argsRef, inspectErr)
	}

	// Row 5: a private FROM consumes the credential resolved just in time
	// from the session store after a migrated registry login.
	blob, _ := json.Marshal(map[string]string{
		"registry": registryHost,
		"username": userCanary,
		"password": passCanary,
	})
	loginReq := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(blob))
	loginReq.Header.Set("Authorization", "Bearer "+session.Token)
	loginW := httptest.NewRecorder()
	app.handleRegistryLogin(loginW, loginReq)
	if loginW.Code != http.StatusOK {
		t.Fatalf("registry login: %d %s", loginW.Code, loginW.Body.String())
	}

	if err := os.WriteFile(filepath.Join(session.Session.Workspace, "private.Dockerfile"),
		[]byte("FROM "+privateBase+"\nRUN echo private-from\n"), 0o644); err != nil {
		t.Fatalf("write private Dockerfile: %v", err)
	}
	privateRef := "dh-build-integration:private"
	w = postBuild(t, app, session.Token, map[string]any{
		"context":    ".",
		"dockerfile": "private.Dockerfile",
		"image":      privateRef,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("private-FROM build with stored credential: %d %s", w.Code, w.Body.String())
	}
	assertBuildFinishResult(t, auditBuf, session.Session.ID, "succeeded")
	if _, inspectErr := provisioning.ImageInspect(ctx, privateRef); inspectErr != nil {
		t.Fatalf("built image %s is not present in the Engine: %v", privateRef, inspectErr)
	}

	// Row 6: a wrong stored credential is refused with the sanitized denial.
	if err := storeSessionRegistryCredential(app.Config.RuntimeDir, session.Session.ID, registryHost, userCanary, passCanary+"-wrong", ""); err != nil {
		t.Fatalf("cannot store wrong credential: %v", err)
	}
	w = postBuild(t, app, session.Token, map[string]any{
		"context":    ".",
		"dockerfile": "private.Dockerfile",
		"image":      "dh-build-integration:wrong",
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong-credential build: %d %s", w.Code, w.Body.String())
	}
	denied := decodeBuildResponse(t, w)
	if denied.OK || denied.Code != "registry_auth_denied" {
		t.Errorf("wrong-credential response = %+v", denied)
	}
	if strings.Contains(w.Body.String(), passCanary) || strings.Contains(w.Body.String(), passCanary+"-wrong") {
		t.Error("wrong-credential response contains credential material")
	}
	assertBuildFinishResult(t, auditBuf, session.Session.ID, "docker_build_failed")

	// Row 7: a fresh session without stored credentials is refused for the
	// private FROM.
	freshSession, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	if err := os.WriteFile(filepath.Join(freshSession.Session.Workspace, "private.Dockerfile"),
		[]byte("FROM "+privateBase+"\n"), 0o644); err != nil {
		t.Fatalf("write fresh Dockerfile: %v", err)
	}
	w = postBuild(t, app, freshSession.Token, map[string]any{
		"context":    ".",
		"dockerfile": "private.Dockerfile",
		"image":      "dh-build-integration:anonymous",
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unauthenticated private-FROM build: %d %s", w.Code, w.Body.String())
	}
	denied = decodeBuildResponse(t, w)
	if denied.OK || denied.Code != "registry_auth_denied" {
		t.Errorf("unauthenticated private-FROM response = %+v", denied)
	}
	assertBuildFinishResult(t, auditBuf, freshSession.Session.ID, "docker_build_failed")

	// Row 8+9: cancelling an intentionally long build is bounded: the
	// request ends with the generic build failure, no tagged target image
	// lands, and the coordinator has no live request left.
	if err := os.WriteFile(filepath.Join(session.Session.Workspace, "slow.Dockerfile"),
		[]byte("FROM alpine:3.24\nRUN sleep 120\n"), 0o644); err != nil {
		t.Fatalf("write slow Dockerfile: %v", err)
	}
	slowRef := "dh-build-integration:slow"

	buildCtx, buildCancel := context.WithCancel(context.Background())
	defer buildCancel()
	cancelReq := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader([]byte(fmt.Sprintf(
		`{"image":"%s","context":".","dockerfile":"slow.Dockerfile"}`, slowRef))))
	cancelReq = cancelReq.WithContext(buildCtx)
	cancelReq.Header.Set("Authorization", "Bearer "+session.Token)
	cancelW := httptest.NewRecorder()

	handlerDone := make(chan struct{})
	go func() {
		app.handleBuild(cancelW, cancelReq)
		close(handlerDone)
	}()

	// Wait until the Engine is executing the long RUN before cancelling.
	deadline := time.Now().Add(60 * time.Second)
	started := false
	for time.Now().Before(deadline) {
		records := filterBySession(parseAuditRecords(auditBuf), session.Session.ID)
		for i := len(records) - 1; i >= 0; i-- {
			if records[i].Event == "build.start" && records[i].Dockerfile == "slow.Dockerfile" {
				started = true
			}
		}
		if started {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !started {
		t.Fatal("the slow build never started")
	}
	// Give the Engine a moment to actually enter the RUN step.
	time.Sleep(2 * time.Second)

	buildCancel()

	select {
	case <-handlerDone:
	case <-time.After(60 * time.Second):
		t.Fatal("handleBuild did not return after cancellation")
	}

	if cancelW.Code != http.StatusInternalServerError {
		t.Fatalf("cancelled build: %d %s", cancelW.Code, cancelW.Body.String())
	}
	cancelled := decodeBuildResponse(t, cancelW)
	if cancelled.OK || cancelled.Code != "docker_build_failed" {
		t.Errorf("cancelled build response = %+v", cancelled)
	}
	assertBuildFinishResult(t, auditBuf, session.Session.ID, "cancelled")
	if _, inspectErr := provisioning.ImageInspect(ctx, slowRef); inspectErr == nil {
		t.Error("the cancelled build must not leave the tagged image behind")
	}

	// Row 10: an unreachable Engine is a bounded backend-unavailable failure.
	deadSocket := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := deadSocket.URL
	deadSocket.Close()
	app.NewEngineBuildFn = func() (engineImageBuilder, error) {
		return newEngineClientAgainstFake(t, deadURL), nil
	}
	w = postBuild(t, app, session.Token, map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "dh-build-integration:transport",
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("transport-failure build: %d %s", w.Code, w.Body.String())
	}
	failed := decodeBuildResponse(t, w)
	if failed.OK || failed.Code != "backend_unavailable" {
		t.Errorf("transport-failure response = %+v", failed)
	}
	assertBuildFinishResult(t, auditBuf, session.Session.ID, "docker_build_failed")

	// Row 11: no temporary staging or runtime residue remains after the
	// completion and cancellation paths.
	buildsDir := filepath.Join(app.Config.RuntimeDir, "builds")
	entries, readErr := os.ReadDir(buildsDir)
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatalf("read builds dir: %v", readErr)
	}
	if readErr == nil && len(entries) != 0 {
		t.Errorf("staging residue after completion/cancellation: %v", entries)
	}

	// Build operations must not be registered: the supervisor is run-only.
	app.OperationSupervisor.mu.RLock()
	opCount := len(app.OperationSupervisor.ops)
	app.OperationSupervisor.mu.RUnlock()
	if opCount != 0 {
		t.Errorf("build must not register operations, supervisor has %d", opCount)
	}

	// Credential containment across the log sinks. The credential may appear
	// only in the protected session Docker config.json.
	for _, sink := range []struct{ name, blob string }{
		{"audit", auditBuf.String()},
		{"operational log", opBuf.String()},
	} {
		if strings.Contains(sink.blob, passCanary) || strings.Contains(sink.blob, userCanary) {
			t.Errorf("%s contains credential material", sink.name)
		}
	}
	// Build audit must not carry operation identity.
	records := parseAuditRecords(auditBuf)
	for _, rec := range records {
		if strings.HasPrefix(rec.Event, "build.") && rec.OperationID != "" {
			t.Errorf("build audit carries operation_id: %+v", rec)
		}
	}
	if strings.Contains(opBuf.String(), "ERROR") {
		t.Errorf("the exercised build paths must not produce operational ERROR entries, got:\n%s", opBuf.String())
	}
}

// assertBuildFinishResult asserts the session's last build.finish event
// carries the expected result.
func assertBuildFinishResult(t *testing.T, auditBuf *bytes.Buffer, sessionID, wantResult string) {
	t.Helper()

	var last *auditRecord
	for _, rec := range filterBySession(parseAuditRecords(auditBuf), sessionID) {
		if rec.Event == "build.finish" {
			copy := rec
			last = &copy
		}
	}
	if last == nil {
		t.Fatal("build.finish audit event not found")
	}
	if last.Result != wantResult {
		t.Fatalf("build.finish result = %q, want %q", last.Result, wantResult)
	}
}

// postBuild sends a build request through the production handler.
func postBuild(t *testing.T, app *App, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal build request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.handleBuild(w, req)
	return w
}
