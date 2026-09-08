package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

// TestBuildEngineIntegration validates the migrated production build path end
// to end against a real Docker Engine and a disposable authenticated
// registry. The build hands Dockerfile and source semantics to Docker and
// BuildKit through a request-owned BuildKit session; docker-helper never
// parses the Dockerfile or pre-pulls base images:
//
//   - a public build through the supported builder succeeds and renders
//     build progress;
//   - a multi-stage build with a stage alias resolves natively through
//     BuildKit, with no helper-side FROM parsing or base pre-pull;
//   - a stage alias named like a real image, and an unresolvable stage
//     alias, are not treated as external images to pull;
//   - an ARG-based FROM resolves with its default and with a build-arg
//     override;
//   - a custom Dockerfile selection and build args are honored;
//   - private sources — a FROM, an ARG-substituted FROM, and an external
//     COPY --from remote source — consume the credential the request-owned
//     BuildKit auth session resolves just in time for exactly the requested
//     registry host;
//   - the daemon refreshes a re-pushed base image at the same tag, preserving
//     the base-image freshness of the previous docker CLI --pull;
//   - a wrong stored credential and a fresh session without one are refused
//     with the sanitized denial and credential material never leaks;
//   - a cancelled build is bounded: the request ends with the generic build
//     failure, no tagged target image lands, and no BuildKit session
//     goroutine survives;
//   - an unreachable Engine is a bounded backend-unavailable failure;
//   - no staging residue remains, the supervisor stays run-only, and build
//     audit carries no operation identity.
//
// The test skips unless a Docker Engine is reachable.
func TestBuildEngineIntegration(t *testing.T) {
	dockerAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 480*time.Second)
	defer cancel()

	provisioning, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("construct engine provisioning client: %v", err)
	}

	// Pull the public base image once through the provisioning client; the
	// builds under test still refresh their bases remotely themselves.
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
	// production path under test. The base carries /base1 only; the
	// freshness rows re-push the same tag with /base2 later.
	privateBase := registryHost + "/dh-build/base:v1"
	buildPrivateBaseWithMarker(t, ctx, provisioning, privateBase, registryHost, userCanary, passCanary, "base1")

	// Production path: real adapter (nil seam, Engine endpoint from the
	// environment), test app, and one Session bearer.
	auditBuf, opBuf := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	app.NewEngineBuildFn = nil

	session, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Row 1: a public build through the supported builder succeeds and
	// carries build output. The build refreshes its base remotely through
	// the request-owned BuildKit session.
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

	// Row 2: a multi-stage build with a stage alias resolves natively:
	// BuildKit treats "base" as the first stage, not as an external image.
	// A helper-side FROM parser would pre-pull docker.io/library/base and
	// fail the build.
	if err := os.WriteFile(filepath.Join(session.Session.Workspace, "stage.Dockerfile"),
		[]byte("FROM alpine:3.24 AS base\nRUN echo hello >/hello\n\nFROM base AS final\nCOPY --from=base /hello /hello\n"), 0o644); err != nil {
		t.Fatalf("write stage Dockerfile: %v", err)
	}
	stageRef := "dh-build-integration:stage-alias"
	w = postBuild(t, app, session.Token, map[string]any{
		"context":    ".",
		"dockerfile": "stage.Dockerfile",
		"image":      stageRef,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("multi-stage alias build: %d %s", w.Code, w.Body.String())
	}
	assertBuildFinishResult(t, auditBuf, session.Session.ID, "succeeded")
	if _, inspectErr := provisioning.ImageInspect(ctx, stageRef); inspectErr != nil {
		t.Fatalf("built image %s is not present in the Engine: %v", stageRef, inspectErr)
	}

	// Row 3: a stage alias named like a real image is a stage, not an
	// external image: the helper must not refresh or pull Docker Hub
	// ubuntu. (The unresolvable-alias row below makes any reintroduced
	// helper-side FROM parsing fail the build observably.)
	if err := os.WriteFile(filepath.Join(session.Session.Workspace, "alias.Dockerfile"),
		[]byte("FROM alpine:3.24 AS ubuntu\nRUN echo stage-alias >/stage-alias\n\nFROM ubuntu\nRUN test -f /stage-alias\n"), 0o644); err != nil {
		t.Fatalf("write alias Dockerfile: %v", err)
	}
	aliasRef := "dh-build-integration:alias-like-image"
	w = postBuild(t, app, session.Token, map[string]any{
		"context":    ".",
		"dockerfile": "alias.Dockerfile",
		"image":      aliasRef,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("stage-alias-named-like-image build: %d %s", w.Code, w.Body.String())
	}
	assertBuildFinishResult(t, auditBuf, session.Session.ID, "succeeded")

	// Row 4: an unresolvable stage alias is a stage, not an image. A
	// helper-side FROM parser would pre-pull the nonexistent Docker Hub
	// image and fail the build.
	if err := os.WriteFile(filepath.Join(session.Session.Workspace, "unresolvable.Dockerfile"),
		[]byte("FROM alpine:3.24 AS dh-nosuch-stage-8qlw\nRUN echo alias >/alias\n\nFROM dh-nosuch-stage-8qlw\nRUN test -f /alias\n"), 0o644); err != nil {
		t.Fatalf("write unresolvable Dockerfile: %v", err)
	}
	unresolvableRef := "dh-build-integration:unresolvable-alias"
	w = postBuild(t, app, session.Token, map[string]any{
		"context":    ".",
		"dockerfile": "unresolvable.Dockerfile",
		"image":      unresolvableRef,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("unresolvable-stage-alias build: %d %s", w.Code, w.Body.String())
	}
	assertBuildFinishResult(t, auditBuf, session.Session.ID, "succeeded")

	// Row 5: an ARG-based FROM resolves with its declared default.
	if err := os.WriteFile(filepath.Join(session.Session.Workspace, "arg.Dockerfile"),
		[]byte("ARG BASE=alpine:3.24\nFROM ${BASE}\nRUN echo arg-from\n"), 0o644); err != nil {
		t.Fatalf("write arg Dockerfile: %v", err)
	}
	argRef := "dh-build-integration:arg-from"
	w = postBuild(t, app, session.Token, map[string]any{
		"context":    ".",
		"dockerfile": "arg.Dockerfile",
		"image":      argRef,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("ARG-based FROM build: %d %s", w.Code, w.Body.String())
	}
	built = decodeBuildResponse(t, w)
	if !built.OK || !strings.Contains(built.Output, "alpine:3.24") {
		t.Errorf("ARG default FROM build = %+v, want the default base in the output", built)
	}
	assertBuildFinishResult(t, auditBuf, session.Session.ID, "succeeded")

	// Row 6: a build-arg override of the FROM resolves the overridden base.
	w = postBuild(t, app, session.Token, map[string]any{
		"context":    ".",
		"dockerfile": "arg.Dockerfile",
		"image":      "dh-build-integration:arg-override",
		"build_args": map[string]any{
			"BASE": "alpine:3.19",
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("ARG-override FROM build: %d %s", w.Code, w.Body.String())
	}
	built = decodeBuildResponse(t, w)
	if !built.OK || !strings.Contains(built.Output, "alpine:3.19") {
		t.Errorf("ARG override FROM build = %+v, want the overridden base in the output", built)
	}
	assertBuildFinishResult(t, auditBuf, session.Session.ID, "succeeded")

	// Row 7: a custom Dockerfile name is honored.
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

	// Row 8: build args reach the Engine and distinguish builds.
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

	// Migrated registry login for the private rows: the Session credential
	// store stays the one durable credential owner, and the request-owned
	// BuildKit auth session resolves it just in time.
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

	// Row 9: a private FROM consumes the credential resolved just in time
	// for exactly the requested registry host.
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

	// Row 10: a private ARG-substituted FROM consumes the stored credential
	// through the request-owned BuildKit auth session without any
	// helper-side Dockerfile parsing.
	if err := os.WriteFile(filepath.Join(session.Session.Workspace, "private-arg.Dockerfile"),
		[]byte("ARG BASE\nFROM ${BASE}\nRUN echo private-arg-from\n"), 0o644); err != nil {
		t.Fatalf("write private arg Dockerfile: %v", err)
	}
	privateArgRef := "dh-build-integration:private-arg-from"
	w = postBuild(t, app, session.Token, map[string]any{
		"context":    ".",
		"dockerfile": "private-arg.Dockerfile",
		"image":      privateArgRef,
		"build_args": map[string]any{
			"BASE": privateBase,
		},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("private ARG-based FROM build: %d %s", w.Code, w.Body.String())
	}
	assertBuildFinishResult(t, auditBuf, session.Session.ID, "succeeded")

	// Row 11: an external private remote source the Dockerfile never names
	// in a FROM — COPY --from=<registry image> — is resolved through the
	// request-owned BuildKit auth session with the stored credential.
	if err := os.WriteFile(filepath.Join(session.Session.Workspace, "external.Dockerfile"),
		[]byte("FROM alpine:3.24\nCOPY --from="+privateBase+" /etc/alpine-release /copied-alpine-release\n"), 0o644); err != nil {
		t.Fatalf("write external-source Dockerfile: %v", err)
	}
	externalRef := "dh-build-integration:external-source"
	w = postBuild(t, app, session.Token, map[string]any{
		"context":    ".",
		"dockerfile": "external.Dockerfile",
		"image":      externalRef,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("external COPY --from build: %d %s", w.Code, w.Body.String())
	}
	assertBuildFinishResult(t, auditBuf, session.Session.ID, "succeeded")

	// Row 12: the base-image freshness of the previous docker CLI --pull is
	// preserved: a re-pushed base at the same tag is refreshed remotely by
	// the build. The rebuilt base carries /base2 only, so this build can
	// only succeed if the daemon resolved the fresh manifest instead of a
	// stale local base.
	buildPrivateBaseWithMarker(t, ctx, provisioning, privateBase, registryHost, userCanary, passCanary, "base2")
	if err := os.WriteFile(filepath.Join(session.Session.Workspace, "fresh.Dockerfile"),
		[]byte("FROM "+privateBase+"\nRUN test -f /base2\n"), 0o644); err != nil {
		t.Fatalf("write freshness Dockerfile: %v", err)
	}
	freshRef := "dh-build-integration:fresh-base"
	w = postBuild(t, app, session.Token, map[string]any{
		"context":    ".",
		"dockerfile": "fresh.Dockerfile",
		"image":      freshRef,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("freshness build: %d %s", w.Code, w.Body.String())
	}
	assertBuildFinishResult(t, auditBuf, session.Session.ID, "succeeded")

	// Row 13: a wrong stored credential is refused with the sanitized
	// denial.
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

	// Row 14: a fresh session without stored credentials is refused for the
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

	// Row 15: cancelling an intentionally long build is bounded: the request
	// ends with the generic build failure, no tagged target image lands,
	// and the coordinator has no live request left.
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

	// Wait until the coordinator carries the admitted request, then give
	// the long RUN time to be executing before cancelling. The audit
	// buffer is only read after the handler goroutine has joined.
	deadline := time.Now().Add(60 * time.Second)
	live := false
	for time.Now().Before(deadline) {
		if app.SyncExecutionCoordinator.hasLiveForLauncher(session.Session.LauncherID) {
			live = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !live {
		t.Fatal("the slow build was never admitted")
	}
	// Give the Engine time to enter the RUN step.
	time.Sleep(2 * time.Second)
	if !app.SyncExecutionCoordinator.hasLiveForLauncher(session.Session.LauncherID) {
		t.Fatal("the slow build was no longer live before cancellation")
	}

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

	// No request-owned BuildKit session goroutine may survive the handler.
	assertNoBuildkitSessionGoroutines(t)

	// Row 16: an unreachable Engine is a bounded backend-unavailable failure.
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

	// Row 17: no temporary staging or runtime residue remains after the
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
	if app.OperationSupervisor != nil {
		app.OperationSupervisor.mu.RLock()
		opCount := len(app.OperationSupervisor.ops)
		app.OperationSupervisor.mu.RUnlock()
		if opCount != 0 {
			t.Errorf("build must not register operations, supervisor has %d", opCount)
		}
	}

	// Credential containment across the log sinks. The credentials may
	// appear only in the protected session Docker config.json; an unrelated
	// registry credential stored for another host is never returned for the
	// requested one, so neither canary may reach any observable output.
	otherUserCanary := "dh-prod-other-user-canary-Cv5Rm9Yt4x"
	otherPassCanary := "dh-prod-other-pass-canary-Wn7Kj2Hs6q"
	if err := storeSessionRegistryCredential(app.Config.RuntimeDir, session.Session.ID, "other.example.com", otherUserCanary, otherPassCanary, ""); err != nil {
		t.Fatalf("cannot store unrelated credential: %v", err)
	}
	for _, sink := range []struct{ name, blob string }{
		{"audit", auditBuf.String()},
		{"operational log", opBuf.String()},
	} {
		for _, canary := range []string{passCanary, userCanary, otherPassCanary, otherUserCanary} {
			if strings.Contains(sink.blob, canary) {
				t.Errorf("%s contains credential material %q", sink.name, canary)
			}
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

	// No BuildKit session goroutine survives any exercised path.
	assertNoBuildkitSessionGoroutines(t)
}

// buildPrivateBaseWithMarker builds one private base image from the public
// base, carrying exactly one marker file, and pushes it to the disposable
// registry through the provisioning client. The same tag is re-pushed with a
// different marker by the freshness rows.
func buildPrivateBaseWithMarker(t *testing.T, ctx context.Context, provisioning *client.Client, privateBase, registryHost, userCanary, passCanary, marker string) {
	t.Helper()

	contextDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(contextDir, "Dockerfile"),
		[]byte("FROM alpine:3.24\nRUN touch /"+marker+"\n"), 0o644); err != nil {
		t.Fatalf("write base Dockerfile: %v", err)
	}

	var contextBlob bytes.Buffer
	tw := tar.NewWriter(&contextBlob)
	blob, err := os.ReadFile(filepath.Join(contextDir, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "Dockerfile", Mode: 0o644, Size: int64(len(blob))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(blob); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	buildReader, err := provisioning.ImageBuild(ctx, &contextBlob, client.ImageBuildOptions{
		Tags:       []string{privateBase},
		Dockerfile: "Dockerfile",
		Remove:     true,
	})
	if err != nil {
		t.Fatalf("build private base image: %v", err)
	}
	// Drain the build stream to EOF so the daemon completes the build; a
	// fixture failure surfaces through the push below.
	if _, err := io.Copy(io.Discard, buildReader.Body); err != nil {
		t.Fatalf("drain private base build stream: %v", err)
	}
	if err := buildReader.Body.Close(); err != nil {
		t.Fatalf("close private base build stream: %v", err)
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
}

// assertNoBuildkitSessionGoroutines proves no request-owned BuildKit session
// goroutine survives the build handler: a leaked session goroutine carries
// BuildKit frames in its stack. The check settles within a bounded deadline
// so it does not race an in-flight teardown.
func assertNoBuildkitSessionGoroutines(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		blob := make([]byte, 1<<21)
		n := runtime.Stack(blob, true)
		stacks := string(blob[:n])
		if !strings.Contains(stacks, "moby/buildkit") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("BuildKit session goroutines leaked:\n%s", stacks)
		}
		time.Sleep(200 * time.Millisecond)
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
