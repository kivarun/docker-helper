package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
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

	// withholdStartReply makes handleConn record a START but never answer
	// it: the connection is held open until withholdRelease is closed (the
	// blocked START conn does not affect other connections). Used for the
	// START-ambiguity proofs.
	withholdStartReply bool
	withholdRelease    chan struct{}
	// dropStartReply makes handleConn record a START and then close the
	// connection without any reply: the P2 client sees EOF after write —
	// ambiguous — without needing a cancellation.
	dropStartReply bool

	// startedCh/stoppedCh are the deterministic record barriers: one
	// buffered signal per recorded request (no sleeps).
	startedCh chan string
	stoppedCh chan string

	// behavior, when set, runs before the default scripted reply and owns
	// the reply for its command (it may withhold it: barriers for the
	// P3-B2 STOP proofs).
	behavior func(command, opID string, reply func(string))
}

func newFakeBuilderManager(t *testing.T) *fakeBuilderManager {
	t.Helper()
	m := &fakeBuilderManager{
		t:               t,
		startResp:       "OK",
		stopResp:        "OK",
		startedCh:       make(chan string, 16),
		stoppedCh:       make(chan string, 16),
		withholdRelease: make(chan struct{}),
	}
	path := filepath.Join(t.TempDir(), "manager.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("cannot create fake manager endpoint: %v", err)
	}
	t.Cleanup(func() {
		listener.Close()
		close(m.withholdRelease)
	})
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
		opID := strings.TrimPrefix(line, builderManagerCmdStart+" ")
		m.starts = append(m.starts, opID)
		withheld := m.withholdStartReply
		dropped := m.dropStartReply
		behavior := m.behavior
		m.mu.Unlock()
		m.startedCh <- opID
		if behavior != nil {
			// A behavior script owns the reply for this command (it may
			// withhold it: the P3-B2 gating proofs); B1's fixed modes
			// apply only when no script is set.
			m.dispatchBehavior(builderManagerCmdStart, opID, func(resp string) {
				_, _ = conn.Write([]byte(resp + "\n"))
			})
			return
		}
		if dropped {
			// Close without any reply: the client's read sees EOF after
			// its write — ambiguous — with no cancellation involved.
			return
		}
		if withheld {
			// Deliberately withhold the reply: hold the accepted START
			// connection open without answering. Other connections
			// (STOP) keep being served concurrently. The conn closes
			// when the test releases or cleanup closes the channel.
			<-m.withholdRelease
			return
		}
		m.mu.Lock()
		_, _ = conn.Write([]byte(m.startResp + "\n"))
		m.mu.Unlock()
	case strings.HasPrefix(line, builderManagerCmdStop+" "):
		opID := strings.TrimPrefix(line, builderManagerCmdStop+" ")
		m.stops = append(m.stops, opID)
		resp := m.stopResp
		behavior := m.behavior
		m.mu.Unlock()
		m.stoppedCh <- opID
		if behavior != nil {
			m.dispatchBehavior(builderManagerCmdStop, opID, func(reply string) {
				_, _ = conn.Write([]byte(reply + "\n"))
			})
			return
		}
		_, _ = conn.Write([]byte(resp + "\n"))
	default:
		m.mu.Unlock()
	}
}

// dispatchBehavior routes one recorded request through the optional
// behavior script (with the fixture lock released); with no script, the
// default per-command response applies.
func (m *fakeBuilderManager) dispatchBehavior(command, opID string, reply func(string)) {
	m.mu.Lock()
	behavior := m.behavior
	startResp, stopResp := m.startResp, m.stopResp
	m.mu.Unlock()
	if behavior != nil {
		behavior(command, opID, reply)
		return
	}
	switch command {
	case builderManagerCmdStart:
		reply(startResp)
	case builderManagerCmdStop:
		reply(stopResp)
	}
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

// setStopResp scripts the response of the default (non-behavior) STOP path.
func (m *fakeBuilderManager) setStopResp(resp string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopResp = resp
}

// setStartWithheld switches the manager into the START-ambiguity mode:
// accepted, recorded, reply deliberately withheld. Returns the release
// channel (test-controlled; cleanup closes it).
func (m *fakeBuilderManager) setStartWithheld() chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.withholdStartReply = true
	return m.withholdRelease
}

// setStartDropped switches the manager into the lost-START-reply mode:
// accepted, recorded, connection closed without a reply (ambiguous EOF
// for the client, no cancellation involved).
func (m *fakeBuilderManager) setStartDropped() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropStartReply = true
}

// waitStartBarrier waits for one recorded START (deterministic barrier,
// no sleeps) and returns its op id.
func (m *fakeBuilderManager) waitStartBarrier(t *testing.T) string {
	t.Helper()
	select {
	case opID := <-m.startedCh:
		return opID
	case <-time.After(10 * time.Second):
		t.Fatal("START never reached the fake manager")
		return ""
	}
}

// waitStopBarrier waits for one recorded STOP (deterministic barrier,
// no sleeps) and returns its op id.
func (m *fakeBuilderManager) waitStopBarrier(t *testing.T) string {
	t.Helper()
	select {
	case opID := <-m.stoppedCh:
		return opID
	case <-time.After(10 * time.Second):
		t.Fatal("STOP never reached the fake manager")
		return ""
	}
}

// stopIDs returns a copy of the recorded STOP operation IDs.
func (m *fakeBuilderManager) stopIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.stops...)
}

// recordedCalls captures every child process invocation of the App seam.
type recordedCalls struct {
	mu    sync.Mutex
	names []string
	argss [][]string
	cmds  []*exec.Cmd
}

// record stores one child invocation. The command is stored by reference:
// the driver assigns cmd.Env after the seam returns, so env(i) must be
// read only after the operation has completed.
func (r *recordedCalls) record(name string, args []string, cmd *exec.Cmd) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names = append(r.names, name)
	r.argss = append(r.argss, args)
	r.cmds = append(r.cmds, cmd)
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

// env returns the final environment of the child command at index i.
// The driver assigns cmd.Env after the seam returns, so this must be read
// only after the operation has completed.
func (r *recordedCalls) env(i int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.cmds) {
		return nil
	}
	return r.cmds[i].Env
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
		cmd := exec.CommandContext(ctx, "true")
		cmd.Path = "/bin/true"
		cmd.Args = append([]string{"/bin/true"}, args...)
		calls.record(name, args, cmd)
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
		cmd := exec.CommandContext(ctx, "true")
		cmd.Path = "/bin/true"
		cmd.Args = append([]string{"/bin/true"}, args...)
		calls.record(name, args, cmd)
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
