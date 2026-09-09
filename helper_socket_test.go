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
		capturedArgs = args
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
		capturedArgs = args
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
