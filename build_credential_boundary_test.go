package main

// P3-D1 credential-boundary proof through the production handlers and
// driver: registry login stores the session's credential into the
// session-scoped Docker config dir through the real handler (the fake
// docker login child receives it on stdin, exactly like real docker
// login); the build handler hands the build driver that Session's config
// dir; the driver passes DOCKER_CONFIG ONLY to the buildctl child; the
// manager receives no credentials. Two Sessions with distinct credential
// markers prove isolation, and the markers are swept across every
// observable surface (manager requests, child argv/env, operational logs,
// audit, public bodies). Synthetic children prove plumbing only; real
// buildctl registry authentication remains an integration/UAT item and no
// CA behavior is asserted here (deferred to D2).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBuildDriverSessionDockerConfigIsolation proves the credential
// boundary with two Sessions carrying distinct credential markers:
// each build's buildctl child env is exactly its own Session's
// DOCKER_CONFIG directory (never the other Session's), no build child
// carries a --config flag, and neither marker appears in any observable
// surface — manager requests, child argv/env, operational logs, audit, or
// public response bodies (the failing login's sanitized public error
// included). The failed Session stored no credential at all.
func TestBuildDriverSessionDockerConfigIsolation(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)
	app, _, sessionA, manager, calls := setupBuildBackendTest(t)

	markerA := "uat-d1-credential-A-7f3b91"
	markerB := "uat-d1-credential-B-2e9c45"

	sessionB, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSessionB: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sessionB.Session.Workspace, "Dockerfile"), []byte("FROM alpine"), 0o644); err != nil {
		t.Fatalf("cannot create session B Dockerfile: %v", err)
	}

	dirA := sessionDockerDir(app.Config.RuntimeDir, sessionA.Session.ID)
	dirB := sessionDockerDir(app.Config.RuntimeDir, sessionB.Session.ID)
	if dirA == dirB {
		t.Fatal("distinct sessions must own distinct Docker config directories")
	}

	// Registry logins through the REAL handler: the fake docker login
	// child reads the credential from stdin and stores it into the
	// --config directory exactly like real docker login would (session A
	// succeeds and stores its marker; session B fails and stores nothing).
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if hasArgvWord(args, "login") {
			// The fake docker login child keeps the handler's argv (its
			// script addresses the --config dir as $1) and reads the
			// credential from stdin, exactly like real docker login.
			var script string
			if len(args) > 1 && args[0] == "--config" && args[1] == dirA {
				script = `printf '{"auths":{"registry.example.com":{"auth":"'}} > "$1/config.json"; cat >> "$1/config.json"; printf '"}}' >> "$1/config.json"`
			} else {
				script = "exit 1"
			}
			return exec.CommandContext(ctx, "/bin/sh", append([]string{"-c", script}, args...)...)
		}
		return exec.CommandContext(ctx, "/bin/true")
	}
	registryLogin := func(token, password string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{
			"registry": "registry.example.com",
			"username": "uat-d1-user",
			"password": password,
		})
		req := httptest.NewRequest(http.MethodPost, "/registry/login", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		app.handleRegistryLogin(w, req)
		return w
	}
	wA := registryLogin(sessionA.Token, markerA)
	if wA.Code != http.StatusOK {
		t.Fatalf("session A login: expected 200, got %d: %s", wA.Code, wA.Body.String())
	}
	wB := registryLogin(sessionB.Token, markerB)
	if wB.Code == http.StatusOK {
		t.Fatal("session B login: expected the failing login not to succeed")
	}

	// Stored credential state: exactly the successful session's config
	// dir holds its marker; the failed session stored nothing.
	data, err := os.ReadFile(filepath.Join(dirA, "config.json"))
	if err != nil || !strings.Contains(string(data), markerA) {
		t.Errorf("session A credential not stored in its own config dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dirB, "config.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the failed session B login stored a credential: %v", err)
	}

	// The build phase: the recording child seam.
	newBackendChildRunner(t, app, calls)
	build := func(token string) (string, *operation) {
		body := map[string]any{"context": ".", "dockerfile": "Dockerfile", "image": "example:test"}
		req := newBuildRequest(body, token)
		w := httptest.NewRecorder()
		app.handleBuild(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("build: expected 201, got %d: %s", w.Code, w.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode build response: %v", err)
		}
		opID, _ := resp["operation_id"].(string)
		op := app.OperationSupervisor.lookup(opID)
		if op == nil {
			t.Fatal("operation not found in supervisor")
		}
		return w.Body.String(), op
	}
	bodyA, opA := build(sessionA.Token)
	bodyB, opB := build(sessionB.Token)
	select {
	case <-opA.done:
	case <-time.After(10 * time.Second):
		t.Fatal("session A build did not complete")
	}
	select {
	case <-opB.done:
	case <-time.After(10 * time.Second):
		t.Fatal("session B build did not complete")
	}

	for _, op := range []*operation{opA, opB} {
		op.mu.Lock()
		state, rc := op.State, derefString(op.ResultCode)
		op.mu.Unlock()
		if state != operationSucceeded || rc != "succeeded" {
			t.Errorf("build %s: state=%v result_code=%q, want succeeded", op.ID, state, rc)
		}
	}

	// Credential-owner boundary: each build's buildctl child env is
	// exactly its OWN Session's Docker config dir.
	var buildctlIdx []int
	for i := 0; i < calls.count(); i++ {
		if strings.HasSuffix(calls.childName(i), "buildctl") {
			buildctlIdx = append(buildctlIdx, i)
		}
	}
	if len(buildctlIdx) != 2 {
		t.Fatalf("buildctl children = %d, want one per session:\n%s", len(buildctlIdx), calls.all())
	}
	for _, tc := range []struct {
		label string
		env   []string
		dir   string
	}{
		{label: "session A", env: calls.env(buildctlIdx[0]), dir: dirA},
		{label: "session B", env: calls.env(buildctlIdx[1]), dir: dirB},
	} {
		if len(tc.env) != 1 || tc.env[0] != "DOCKER_CONFIG="+tc.dir {
			t.Errorf("%s buildctl env = %d entries (first %q), want exactly [DOCKER_CONFIG=%s]", tc.label, len(tc.env), firstEnvEntry(tc.env), tc.dir)
		}
	}

	// The driver passes the credential owner ONLY through the buildctl
	// env: no build child carries a --config flag at all.
	for i := 0; i < calls.count(); i++ {
		if hasArgvWord(calls.argv(i), "--config") {
			t.Errorf("build child %d carries --config (the driver must pass DOCKER_CONFIG only):\n%v", i, calls.argv(i))
		}
	}

	// The credential-marker sweep: no marker in any observable surface.
	for _, marker := range []string{markerA, markerB} {
		for _, id := range append(manager.startIDs(), manager.stopIDs()...) {
			if strings.Contains(id, marker) {
				t.Errorf("credential marker reached the manager request for %s", id)
			}
		}
		for i := 0; i < calls.count(); i++ {
			if strings.Contains(strings.Join(calls.argv(i), "\x00"), marker) {
				t.Errorf("credential marker in child %d argv:\n%v", i, calls.argv(i))
			}
			if strings.Contains(strings.Join(calls.env(i), "\x00"), marker) {
				t.Errorf("credential marker in child %d env:\n%s", i, firstEnvEntry(calls.env(i)))
			}
		}
		if strings.Contains(opBuf.String(), marker) {
			t.Error("credential marker in operational logs")
		}
		if strings.Contains(auditBuf.String(), marker) {
			t.Error("credential marker in audit")
		}
		for _, surface := range []string{bodyA, bodyB, wA.Body.String(), wB.Body.String()} {
			if strings.Contains(surface, marker) {
				t.Errorf("credential marker in a public response body")
			}
		}
	}
}
