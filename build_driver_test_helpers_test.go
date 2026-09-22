package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// P3 build-driver test fixtures: a controllable backend so tests drive the
// real production driver (handleBuild -> buildDriver.run) with a fake
// manager endpoint and child-process seam.

// fakeBuilderManager is a test unix endpoint that records manager requests
// and answers from a script.
type fakeBuilderManager struct {
	t *testing.T

	mu        sync.Mutex
	starts    []string // recorded START op ids
	stops     []string // recorded STOP op ids
	startResp string   // response for START
	stopResp  string   // response for STOP
}

func newFakeBuilderManager(t *testing.T) *fakeBuilderManager {
	t.Helper()
	m := &fakeBuilderManager{t: t, startResp: "OK", stopResp: "OK"}
	path := filepath.Join(t.TempDir(), "manager.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("cannot create fake manager endpoint: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go m.handleConn(conn)
		}
	}()
	orig := builderClientSocketPath
	builderClientSocketPath = path
	t.Cleanup(func() { builderClientSocketPath = orig })
	// Manager peer credential seams: fake builder identity.
	origUID := builderClientManagerUID
	builderClientManagerUID = func() (int, int, error) { return 4312, 4312, nil }
	t.Cleanup(func() { builderClientManagerUID = origUID })
	origPeer := builderClientPeerCredentials
	builderClientPeerCredentials = func(*net.UnixConn) (int, int, int, error) { return 4312, 4312, 0, nil }
	t.Cleanup(func() { builderClientPeerCredentials = origPeer })
	return m
}

func (m *fakeBuilderManager) handleConn(conn *net.UnixConn) {
	defer conn.Close()
	buf := make([]byte, builderManagerRequestCeiling)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	line := strings.TrimRight(string(buf[:n]), "\n")
	m.mu.Lock()
	switch {
	case strings.HasPrefix(line, builderManagerCmdStart+" "):
		m.starts = append(m.starts, strings.TrimPrefix(line, builderManagerCmdStart+" "))
		_, _ = conn.Write([]byte(m.startResp + "\n"))
	case strings.HasPrefix(line, builderManagerCmdStop+" "):
		m.stops = append(m.stops, strings.TrimPrefix(line, builderManagerCmdStop+" "))
		_, _ = conn.Write([]byte(m.stopResp + "\n"))
	}
	m.mu.Unlock()
}

func (m *fakeBuilderManager) startCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.starts)
}

func (m *fakeBuilderManager) stopCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.stops)
}

func (m *fakeBuilderManager) setStartResp(resp string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startResp = resp
}

// recordedCalls captures every child process invocation of the App seam.
type recordedCalls struct {
	mu    sync.Mutex
	names []string
	argss [][]string
	envs  [][]string
}

func (r *recordedCalls) record(name string, args []string, env []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names = append(r.names, name)
	r.argss = append(r.argss, args)
	r.envs = append(r.envs, env)
}

func (r *recordedCalls) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.names)
}

func (r *recordedCalls) argv(i int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.argss) {
		return nil
	}
	return r.argss[i]
}

// buildctlIndex returns the index of the first recorded buildctl child
// (name ends in buildctl), or -1.
func (r *recordedCalls) buildctlIndex() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, n := range r.names {
		if strings.HasSuffix(n, "buildctl") {
			return i
		}
	}
	return -1
}

func (r *recordedCalls) env(i int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.envs) {
		return nil
	}
	return r.envs[i]
}

func (r *recordedCalls) all() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var parts []string
	for i := range r.names {
		parts = append(parts, r.names[i]+" "+strings.Join(r.argss[i], " "))
	}
	return strings.Join(parts, "\n")
}

// setupBuildBackendTest wires the full P3 driver path: staging seam (real
// staged layout), fake manager, socket-validation pass, and the recording
// child seam (children succeed by default).
func setupBuildBackendTest(t *testing.T) (*App, *operationSupervisor, *CreatedSession, *fakeBuilderManager, *recordedCalls) {
	t.Helper()
	app, supervisor, result, token := setupBuildTest(t)
	_ = token
	manager := newFakeBuilderManager(t)
	calls := &recordedCalls{}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calls.record(name, args, os.Environ())
		// The recording seam keeps the child runnable (the "true"
		// binary's real Path), while Args[0] preserves the exact
		// production identity for argv assertions.
		cmd := exec.CommandContext(ctx, "true")
		cmd.Path = "/bin/true"
		cmd.Args = append([]string{"/bin/true"}, args...)
		return cmd
	}
	app.validateBuildKitSocketFn = func(string) error { return nil }
	return app, supervisor, result, manager, calls
}

// startBackendBuild starts a build through the production handler and
// returns the operation (waiting until the handler answered).
func startBackendBuild(t *testing.T, app *App, token string, buildArgs map[string]any) *operation {
	t.Helper()
	body := map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}
	for k, v := range buildArgs {
		body[k] = v
	}
	req := newBuildRequest(body, token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)
	if w.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	return op
}

// setupBuildBackendFrom attaches the fake manager + socket-validation pass
// to an existing setupBuildTest app and a recording child seam returning
// the fixed child behavior (by default successful true).
func attachBackendFixture(t *testing.T, app *App) (*fakeBuilderManager, *recordedCalls) {
	t.Helper()
	manager := newFakeBuilderManager(t)
	calls := &recordedCalls{}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calls.record(name, args, os.Environ())
		cmd := exec.CommandContext(ctx, "true")
		cmd.Path = "/bin/true"
		cmd.Args = append([]string{"/bin/true"}, args...)
		return cmd
	}
	app.validateBuildKitSocketFn = func(string) error { return nil }
	return manager, calls
}

// contextPathOf returns the staged context path recorded for call i (from
// the --local context=... argv value).
func (r *recordedCalls) contextPathOf(i int) string {
	args := r.argv(i)
	for j, arg := range args {
		if arg == "--local" && j+1 < len(args) {
			if v, ok := strings.CutPrefix(args[j+1], "context="); ok {
				return v
			}
		}
	}
	return ""
}

// optValue extracts VALUE from a "--opt KEY=VALUE" pair.
func optValue(t *testing.T, args []string, key string) string {
	t.Helper()
	for i, arg := range args {
		if arg == "--opt" && i+1 < len(args) {
			if v, ok := strings.CutPrefix(args[i+1], key+"="); ok {
				return v
			}
		}
	}
	return ""
}
