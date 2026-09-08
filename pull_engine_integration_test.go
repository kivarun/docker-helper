package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

// TestPullEngineIntegration validates the migrated production pull path end
// to end against a real Docker Engine and a disposable authenticated
// registry:
//
//   - a public pull after image removal succeeds and renders progress output;
//   - a private pull consumes the credential resolved just in time from the
//     session store after a migrated registry login;
//   - a wrong stored credential is refused with the sanitized denial and
//     credential material never leaks through the response or logs;
//   - a session without stored credentials pulls unauthenticated and is
//     refused for a private image;
//   - a cancelled pull is bounded: the request ends with the generic pull
//     failure, no image lands, and no operational error is logged.
//
// The test skips unless a Docker Engine is reachable.
func TestPullEngineIntegration(t *testing.T) {
	dockerAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	provisioning, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("construct engine provisioning client: %v", err)
	}

	const userCanary = "dh-prod-pull-user-canary-8qLw3nTz5c"
	const passCanary = "dh-prod-pull-pass-canary-Rm2Kx7Vb9d"

	registryHost := provisionDisposableRegistry(t, ctx, provisioning, "dh-pull-auth-volume", userCanary, passCanary)

	// Seed the private image through the provisioning client, not the
	// production path under test.
	privateRef := registryHost + "/dh-pull/private:v1"
	if _, err := provisioning.ImageTag(ctx, client.ImageTagOptions{Source: "alpine:3.24", Target: privateRef}); err != nil {
		t.Fatalf("tag private image: %v", err)
	}
	authBlob, err := json.Marshal(map[string]any{
		"username":      userCanary,
		"password":      passCanary,
		"serveraddress": registryHost,
	})
	if err != nil {
		t.Fatalf("marshal push auth: %v", err)
	}
	push, err := provisioning.ImagePush(ctx, privateRef, client.ImagePushOptions{RegistryAuth: base64.StdEncoding.EncodeToString(authBlob)})
	if err != nil {
		t.Fatalf("push private image: %v", err)
	}
	if err := push.Wait(ctx); err != nil {
		t.Fatalf("push private image: %v", err)
	}

	// Production path: real adapter (nil seam, Engine endpoint from the
	// environment), test app, and one Session bearer.
	auditBuf, opBuf := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	app.NewEnginePullFn = nil

	session, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Row 1: a public pull after image removal succeeds and renders the
	// daemon's progress output.
	if _, err := provisioning.ImageRemove(ctx, "alpine:3.24", client.ImageRemoveOptions{Force: true}); err != nil {
		t.Fatalf("remove alpine:3.24: %v", err)
	}
	w := postPull(t, app, session.Token, map[string]string{"image": "alpine:3.24"})
	if w.Code != http.StatusOK {
		t.Fatalf("public pull: %d %s", w.Code, w.Body.String())
	}
	pulled := decodePullResponse(t, w)
	if !pulled.OK || pulled.Message != "image pulled successfully" {
		t.Errorf("public pull response = %+v", pulled)
	}
	if !strings.Contains(pulled.Output, "Downloaded newer image for alpine:3.24") {
		t.Errorf("public pull output lost the daemon progress lines: %q", pulled.Output)
	}
	assertPullFinishResult(t, auditBuf, session.Session.ID, "success")

	// Row 2: registry login through the migrated production path persists
	// the credential; the private pull resolves it just in time and succeeds.
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

	w = postPull(t, app, session.Token, map[string]string{"image": privateRef})
	if w.Code != http.StatusOK {
		t.Fatalf("private pull with stored credential: %d %s", w.Code, w.Body.String())
	}
	pulled = decodePullResponse(t, w)
	if !pulled.OK || pulled.Message != "image pulled successfully" {
		t.Errorf("private pull response = %+v", pulled)
	}
	assertPullFinishResult(t, auditBuf, session.Session.ID, "success")

	// Row 3: a wrong stored credential is refused with the sanitized denial.
	if err := storeSessionRegistryCredential(app.Config.RuntimeDir, session.Session.ID, registryHost, userCanary, passCanary+"-wrong", ""); err != nil {
		t.Fatalf("cannot store wrong credential: %v", err)
	}
	w = postPull(t, app, session.Token, map[string]string{"image": privateRef})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-credential pull: %d %s", w.Code, w.Body.String())
	}
	denied := decodePullResponse(t, w)
	if denied.OK || denied.Code != "pull_access_denied" {
		t.Errorf("wrong-credential response = %+v", denied)
	}
	if strings.Contains(w.Body.String(), passCanary) || strings.Contains(w.Body.String(), passCanary+"-wrong") {
		t.Error("wrong-credential response contains credential material")
	}
	assertPullFinishResult(t, auditBuf, session.Session.ID, "pull_error")

	// Row 4: a session without stored credentials pulls unauthenticated and
	// is refused for the private image.
	otherSession, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	w = postPull(t, app, otherSession.Token, map[string]string{"image": privateRef})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated private pull: %d %s", w.Code, w.Body.String())
	}
	denied = decodePullResponse(t, w)
	if denied.OK || denied.Code != "pull_access_denied" {
		t.Errorf("unauthenticated private pull response = %+v", denied)
	}
	assertPullFinishResult(t, auditBuf, otherSession.Session.ID, "pull_error")

	// Row 5: a cancelled pull is bounded. A stall registry holds the
	// manifest request; cancelling the request context ends the pull with
	// the generic failure and no image lands.
	manifestSeen := new(sync.Once)
	manifestReached := make(chan struct{})
	stall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/manifests/"):
			manifestSeen.Do(func() { close(manifestReached) })
			// Hold the manifest request until the pull client gives up.
			// The hold is bounded: dockerd notices an aborted API client
			// only through a failed progress write, and a stalled pull
			// produces none, so the daemon may keep this connection open
			// after the cancellation. The server must always be closable.
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		case strings.Contains(r.URL.Path, "/blobs/"):
			http.Error(w, `{"errors":[{"code":"NAME_UNKNOWN"}]}`, http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer stall.Close()
	stallRef := strings.TrimPrefix(stall.URL, "http://") + "/dh-pull-stall/repo:v1"

	pullCtx, pullCancel := context.WithCancel(context.Background())
	defer pullCancel()
	cancelReq := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader([]byte(`{"image":"`+stallRef+`"}`)))
	cancelReq = cancelReq.WithContext(pullCtx)
	cancelReq.Header.Set("Authorization", "Bearer "+session.Token)
	cancelW := httptest.NewRecorder()

	handlerDone := make(chan struct{})
	go func() {
		app.handlePull(cancelW, cancelReq)
		close(handlerDone)
	}()

	select {
	case <-manifestReached:
	case <-time.After(30 * time.Second):
		t.Fatal("the Engine never requested the manifest from the stall registry")
	}

	pullCancel()

	select {
	case <-handlerDone:
	case <-time.After(30 * time.Second):
		t.Fatal("handlePull did not return after cancellation")
	}

	if cancelW.Code != http.StatusInternalServerError {
		t.Fatalf("cancelled pull: %d %s", cancelW.Code, cancelW.Body.String())
	}
	cancelled := decodePullResponse(t, cancelW)
	if cancelled.OK || cancelled.Code != "docker_pull_failed" {
		t.Errorf("cancelled pull response = %+v", cancelled)
	}
	assertPullFinishResult(t, auditBuf, session.Session.ID, "pull_error")
	if _, inspectErr := provisioning.ImageInspect(ctx, stallRef); inspectErr == nil {
		t.Error("the cancelled pull must not leave the image behind")
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
	if strings.Contains(opBuf.String(), "ERROR") {
		t.Errorf("the exercised pull paths must not produce operational ERROR entries, got:\n%s", opBuf.String())
	}
}

// assertPullFinishResult asserts the session's last pull.finish event carries
// the expected result.
func assertPullFinishResult(t *testing.T, auditBuf *bytes.Buffer, sessionID, wantResult string) {
	t.Helper()

	var last *auditRecord
	for _, rec := range filterBySession(parseAuditRecords(auditBuf), sessionID) {
		if rec.Event == "pull.finish" {
			copy := rec
			last = &copy
		}
	}
	if last == nil {
		t.Fatal("pull.finish audit event not found")
	}
	if last.Result != wantResult {
		t.Fatalf("pull.finish result = %q, want %q", last.Result, wantResult)
	}
}
