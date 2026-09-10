package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
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
	installTestWorkloadMACForTest(t, app, LSMAppArmor)
	return app
}

// postRunRequest posts a run request body with the session token, waits for
// the created operation to finish, and returns the recorder and operation.
// The recorder body is left fully readable for later assertions.
func postRunRequest(app *App, token string, body string) (*httptest.ResponseRecorder, *operation) {
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)
	var resp struct {
		OperationID string `json:"operation_id"`
	}
	if json.Unmarshal(w.Body.Bytes(), &resp) == nil && resp.OperationID != "" {
		op := app.OperationSupervisor.lookup(resp.OperationID)
		if op != nil {
			op.Wait()
		}
	}
	return w, nil
}

// dockerMountSpecs returns the values of all --mount flag arguments in the
// captured docker argv.
func dockerMountSpecs(args []string) []string {
	specs := make([]string, 0)
	for i, arg := range args {
		if arg == "--mount" && i+1 < len(args) {
			specs = append(specs, args[i+1])
		}
	}
	return specs
}

func TestHelperSocketSystemModeInjectsReadOnlyRuntimeMount(t *testing.T) {

	app := newSystemModeRunTestApp(t)

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if len(args) > 0 && args[0] == "--config" && args[2] == "run" {
			capturedArgs = args
		}
		return exec.CommandContext(ctx, "/bin/true")
	}

	w, _ := postRunRequest(app, result.Token,
		`{"image":"alpine:3.24","helper_socket":true,"command":["true"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	specs := dockerMountSpecs(capturedArgs)
	expected := fmt.Sprintf("type=bind,source=%s,target=/run/docker-helper,readonly", app.Config.RuntimeDir)
	found := false
	for _, spec := range specs {
		if spec == expected {
			found = true
		}
	}
	if !found {
		t.Errorf("expected helper runtime mount %q in docker args %v", expected, capturedArgs)
	}
	// The client must not choose source, target, or mode: the injected mount
	// is the fixed server-owned projection.
	for _, spec := range specs {
		if strings.Contains(spec, "target=/run/docker-helper,") && spec != expected {
			t.Errorf("unexpected helper runtime mount variation: %s", spec)
		}
	}
}

func TestHelperSocketOmittedByDefault(t *testing.T) {

	app := newSystemModeRunTestApp(t)

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if len(args) > 0 && args[0] == "--config" && args[2] == "run" {
			capturedArgs = args
		}
		return exec.CommandContext(ctx, "/bin/true")
	}

	w, _ := postRunRequest(app, result.Token, `{"image":"alpine:3.24","command":["true"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	for _, spec := range dockerMountSpecs(capturedArgs) {
		if strings.Contains(spec, "target=/run/docker-helper") {
			t.Errorf("helper runtime mount must not appear without helper_socket: %v", capturedArgs)
		}
	}
}

func TestHelperSocketUserModeFailClosed(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.Config.Mode = ModeUser
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerCalled := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		dockerCalled = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	w, _ := postRunRequest(app, result.Token,
		`{"image":"alpine:3.24","helper_socket":true,"command":["true"]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if resp["code"] != "invalid_helper_socket" {
		t.Errorf("expected invalid_helper_socket code, got %v", resp)
	}
	if dockerCalled {
		t.Error("user-mode helper_socket must fail closed before any docker call")
	}
	if resp["operation_id"] != nil {
		t.Error("user-mode helper_socket rejection must not create an operation")
	}
}

func TestHelperSocketUserMountOverlapRejected(t *testing.T) {
	// With helper_socket the caller-owned mount must not shadow, replace, or
	// partially cover the server-owned projection: exact, ancestor, and
	// descendant targets are all rejected through the real handler path.
	table := []struct {
		name   string
		target string
	}{
		{name: "exact projection target", target: "/run/docker-helper"},
		{name: "ancestor of the projection", target: "/run"},
		{name: "descendant of the projection", target: "/run/docker-helper/docker-helper.sock"},
	}
	for _, tc := range table {
		t.Run(tc.name, func(t *testing.T) {
			app := newSystemModeRunTestApp(t)
			app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
				return &pinnedMount{PinnedPath: "/tmp/test-mount", cleanup: func() error { return nil }}, nil
			}

			result, err := createSystemSession(t, app)
			if err != nil {
				t.Fatalf("createSession: %v", err)
			}

			dockerCalled := false
			app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
				dockerCalled = true
				return exec.CommandContext(ctx, "/bin/true")
			}

			w, _ := postRunRequest(app, result.Token,
				`{"image":"alpine:3.24","helper_socket":true,"command":["true"],"mounts":[{"source":".","target":"`+tc.target+`"}]}`)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
			var resp map[string]any
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("cannot decode response: %v", err)
			}
			if resp["code"] != "invalid_mount" {
				t.Errorf("expected invalid_mount code, got %v", resp)
			}
			if dockerCalled {
				t.Error("conflicting helper runtime mount must be rejected before any docker call")
			}
		})
	}
}

func TestHelperSocketMountOverlapTable(t *testing.T) {
	table := []struct {
		target  string
		overlap bool
	}{
		{"/run/docker-helper", true},
		{"/run/docker-helper/foo", true},
		{"/run/docker-helper/docker-helper.sock", true},
		{"/run", true},
		{"/", true},
		{"/run-other", false},
		{"/run/docker-helper-other", false},
	}
	for _, tc := range table {
		if got := isHelperSocketMountOverlap(tc.target); got != tc.overlap {
			t.Errorf("isHelperSocketMountOverlap(%q) = %v, want %v", tc.target, got, tc.overlap)
		}
	}
}

func TestHelperSocketUserMountExactTargetAllowedWithoutCapability(t *testing.T) {
	// Without helper_socket the 2.1.0 mount contract is unchanged: the target
	// itself is not newly policed by this feature.

	app := newSystemModeRunTestApp(t)
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{PinnedPath: "/tmp/test-mount", cleanup: func() error { return nil }}, nil
	}

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	w, _ := postRunRequest(app, result.Token,
		`{"image":"alpine:3.24","command":["true"],"mounts":[{"source":".","target":"/run/docker-helper"}]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 without helper_socket, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHelperSocketAuditRecordsCapability(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newSystemModeRunTestApp(t)

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	w, _ := postRunRequest(app, result.Token,
		`{"image":"alpine:3.24","helper_socket":true,"command":["true"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	started := false
	for _, rec := range records {
		if rec.Event == "run.start" {
			started = true
			if !rec.HelperSocket {
				t.Error("run.start must record helper_socket=true when the capability is requested")
			}
		}
		if rec.Event == "run.finish" && !rec.HelperSocket {
			t.Error("run.finish must record helper_socket=true when the capability is requested")
		}
	}
	if !started {
		t.Fatal("run.start audit record not found")
	}
}

func TestHelperSocketAuditAbsentByDefault(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newSystemModeRunTestApp(t)

	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	w, _ := postRunRequest(app, result.Token, `{"image":"alpine:3.24","command":["true"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	for _, rec := range filterBySession(parseAuditRecords(auditBuf), result.Session.ID) {
		if rec.HelperSocket {
			t.Errorf("audit record %s must not claim helper_socket without the flag", rec.Event)
		}
	}
}

func TestHelperSocketCLIRequestField(t *testing.T) {
	// The CLI --helper-socket flag must produce helper_socket:true in the
	// request body, and the flag must be absent from a plain request.
	srv := newEnvFromRunTestServer()

	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--helper-socket", "--", "true",
	}, "", func(s *agentCLITestServer) {
		registerEnvFromRunHandlers(s, srv)
	})

	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d, stderr: %s", exitCode, stderr.String())
	}
	body := srv.waitForRunBody(t)
	if !body.HelperSocket {
		t.Errorf("expected helper_socket:true in the request body, got %+v", body)
	}
}

func TestHelperSocketCLIOmittedByDefault(t *testing.T) {
	srv := newEnvFromRunTestServer()

	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--", "true",
	}, "", func(s *agentCLITestServer) {
		registerEnvFromRunHandlers(s, srv)
	})

	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d, stderr: %s", exitCode, stderr.String())
	}
	body := srv.waitForRunBody(t)
	if body.HelperSocket {
		t.Errorf("helper_socket must be omitted without the flag, got %+v", body)
	}
}

func TestHelperSocketCLIFlagWithEnvFrom(t *testing.T) {
	// The combined CLI surface: --helper-socket and --env-from together
	// produce one request carrying both.
	srv := newEnvFromRunTestServer()
	t.Setenv("ORCHESTRATOR_LLM_KEY", "uat-combined-marker")

	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--helper-socket",
		"--env-from", "LLM_KEY=ORCHESTRATOR_LLM_KEY", "--", "true",
	}, "", func(s *agentCLITestServer) {
		registerEnvFromRunHandlers(s, srv)
	})

	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d, stderr: %s", exitCode, stderr.String())
	}
	body := srv.waitForRunBody(t)
	if !body.HelperSocket {
		t.Errorf("expected helper_socket:true, got %+v", body)
	}
	if body.Environment["LLM_KEY"] != "uat-combined-marker" {
		t.Errorf("expected resolved LLM_KEY, got %v", body.Environment)
	}
}

// dockerEnvSpecs returns the values of all --env flag arguments in the
// captured docker argv.
func dockerEnvSpecs(args []string) []string {
	specs := make([]string, 0)
	for i, arg := range args {
		if arg == "--env" && i+1 < len(args) {
			specs = append(specs, args[i+1])
		}
	}
	return specs
}

// countEnvOccurrences counts how many docker argv entries carry the given
// environment variable assignment.
func countEnvOccurrences(args []string, name string) int {
	n := 0
	for _, spec := range dockerEnvSpecs(args) {
		if strings.HasPrefix(spec, name+"=") {
			n++
		}
	}
	return n
}

// TestHelperSocketInjectsCanonicalLocatorEnv proves the server-owned socket
// locator: with the helper runtime projection the docker argv carries the
// canonical DOCKER_HELPER_SOCKET_PATH exactly once, and the injected locator
// is not a caller env key (the run.start audit env keys stay caller-only).
func TestHelperSocketInjectsCanonicalLocatorEnv(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newSystemModeRunTestApp(t)
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if len(args) > 0 && args[0] == "--config" && args[2] == "run" {
			capturedArgs = args
		}
		return exec.CommandContext(ctx, "/bin/true")
	}

	w, _ := postRunRequest(app, result.Token,
		`{"image":"alpine:3.24","helper_socket":true,"command":["true"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if n := countEnvOccurrences(capturedArgs, helperSocketLocatorEnv); n != 1 {
		t.Errorf("docker argv carries %d DOCKER_HELPER_SOCKET_PATH entries, want exactly one: %v", n, capturedArgs)
	}
	want := "--env " + helperSocketLocatorEnv + "=" + helperSocketLocatorEnvValue
	if !strings.Contains(strings.Join(capturedArgs, " "), want) {
		t.Errorf("expected the canonical locator %q in docker args %v", want, capturedArgs)
	}

	for _, rec := range filterBySession(parseAuditRecords(auditBuf), result.Session.ID) {
		if rec.Event == "run.start" {
			for _, key := range rec.EnvKeys {
				if key == helperSocketLocatorEnv {
					t.Error("server-injected locator must not be audited as a caller env key")
				}
			}
		}
	}
}

// TestHelperSocketOmitsLocatorWithoutCapability proves the locator injection
// is bound to the helper_socket capability: without it the environment
// behavior is unchanged (no injected locator), and a caller-supplied locator
// stays an ordinary caller environment variable.
func TestHelperSocketOmitsLocatorWithoutCapability(t *testing.T) {
	app := newSystemModeRunTestApp(t)
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if len(args) > 0 && args[0] == "--config" && args[2] == "run" {
			capturedArgs = args
		}
		return exec.CommandContext(ctx, "/bin/true")
	}

	w, _ := postRunRequest(app, result.Token,
		`{"image":"alpine:3.24","command":["true"],"environment":{"DOCKER_HELPER_SOCKET_PATH":"/some/caller/path"}}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	specs := dockerEnvSpecs(capturedArgs)
	found := false
	for _, spec := range specs {
		if spec == helperSocketLocatorEnv+"=/some/caller/path" {
			found = true
		}
	}
	if !found {
		t.Errorf("without helper_socket the caller locator must pass through unchanged: %v", specs)
	}
	if n := countEnvOccurrences(capturedArgs, helperSocketLocatorEnv); n != 1 {
		t.Errorf("docker argv carries %d DOCKER_HELPER_SOCKET_PATH entries, want the caller's single value: %v", n, capturedArgs)
	}
}

// TestHelperSocketCallerCanonicalLocatorAcceptedOnce proves the accepted
// caller path: a caller-supplied exactly-canonical locator is accepted, kept
// as one docker argv entry, and remains part of the caller env-key audit.
func TestHelperSocketCallerCanonicalLocatorAcceptedOnce(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newSystemModeRunTestApp(t)
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if len(args) > 0 && args[0] == "--config" && args[2] == "run" {
			capturedArgs = args
		}
		return exec.CommandContext(ctx, "/bin/true")
	}

	w, _ := postRunRequest(app, result.Token,
		`{"image":"alpine:3.24","helper_socket":true,"command":["true"],"environment":{"DOCKER_HELPER_SOCKET_PATH":"`+helperSocketLocatorEnvValue+`"}}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if n := countEnvOccurrences(capturedArgs, helperSocketLocatorEnv); n != 1 {
		t.Errorf("docker argv carries %d DOCKER_HELPER_SOCKET_PATH entries, want exactly one: %v", n, capturedArgs)
	}
	want := "--env " + helperSocketLocatorEnv + "=" + helperSocketLocatorEnvValue
	if !strings.Contains(strings.Join(capturedArgs, " "), want) {
		t.Errorf("expected the canonical locator %q in docker args %v", want, capturedArgs)
	}

	// The caller-provided key remains part of the caller env-key audit.
	audited := false
	for _, rec := range filterBySession(parseAuditRecords(auditBuf), result.Session.ID) {
		if rec.Event == "run.start" {
			for _, key := range rec.EnvKeys {
				if key == helperSocketLocatorEnv {
					audited = true
				}
			}
		}
	}
	if !audited {
		t.Error("caller-supplied canonical locator must remain part of the caller env-key audit")
	}
}

// TestHelperSocketConflictingLocatorRejected proves the fail-closed refusal:
// a caller-supplied locator that differs from the canonical value is refused
// through the existing helper-socket refusal family before any pin,
// operation, or Docker state exists.
func TestHelperSocketConflictingLocatorRejected(t *testing.T) {
	app := newSystemModeRunTestApp(t)
	pinCalled := false
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinCalled = true
		return &pinnedMount{PinnedPath: "/tmp/test-mount", cleanup: func() error { return nil }}, nil
	}
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerCalled := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		dockerCalled = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	w, _ := postRunRequest(app, result.Token,
		`{"image":"alpine:3.24","helper_socket":true,"command":["true"],"environment":{"DOCKER_HELPER_SOCKET_PATH":"/wrong/other.sock"}}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	if resp["code"] != "invalid_helper_socket" {
		t.Errorf("expected invalid_helper_socket code, got %v", resp)
	}
	if dockerCalled {
		t.Error("conflicting locator must be rejected before any docker call")
	}
	if pinCalled {
		t.Error("conflicting locator must be rejected before any mount pin exists")
	}
	if resp["operation_id"] != nil {
		t.Error("conflicting locator rejection must not create an operation")
	}
}

// TestHelperSocketNeverInjectsSessionToken proves the capability separation:
// the server-owned locator injection never injects the Session bearer; the
// socket is transport reachability only.
func TestHelperSocketNeverInjectsSessionToken(t *testing.T) {
	app := newSystemModeRunTestApp(t)
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if len(args) > 0 && args[0] == "--config" && args[2] == "run" {
			capturedArgs = args
		}
		return exec.CommandContext(ctx, "/bin/true")
	}

	w, _ := postRunRequest(app, result.Token,
		`{"image":"alpine:3.24","helper_socket":true,"command":["true"]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	for _, spec := range dockerEnvSpecs(capturedArgs) {
		if strings.HasPrefix(spec, "DOCKER_HELPER_SESSION_TOKEN=") {
			t.Errorf("the daemon must never inject the Session token into docker argv: %v", capturedArgs)
		}
	}
}
