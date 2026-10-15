package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
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

// fakeManagerEndpoint mounts a test unix endpoint for the builder-manager
// client seams and serves every request line with the given response line
// (the established rpc-test pattern: the real client speaks the real wire
// vocabulary against a test endpoint).
func fakeManagerEndpoint(t *testing.T, reply func(line string) string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "manager.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("cannot create the test manager endpoint: %v", err)
	}
	origPath := builderClientSocketPath
	builderClientSocketPath = path
	done := make(chan struct{})
	var handlers sync.WaitGroup
	t.Cleanup(func() {
		listener.Close()
		<-done
		handlers.Wait()
		// The seam restores only after every handler goroutine ended, so
		// no in-flight round trip can read the restored path.
		builderClientSocketPath = origPath
	})

	go func() {
		defer close(done)
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer conn.Close()
				buf := make([]byte, builderManagerRequestCeiling)
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := conn.Read(buf)
				if err != nil && n == 0 {
					return
				}
				line := string(buf[:n])
				if idx := indexByte(line, '\n'); idx >= 0 {
					line = line[:idx]
				}
				if resp := reply(line); resp != "" {
					_, _ = io.WriteString(conn, resp+"\n")
				}
			}()
		}
	}()
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// seamManagerPeerIdentity points the client-side and manager-side peer
// credential verification at the test process's own identity, so the real
// client ↔ endpoint exchange passes the SO_PEERCRED contracts in-process.
func seamManagerPeerIdentity(t *testing.T) {
	t.Helper()
	uid, gid := os.Getuid(), os.Getgid()
	origUID := builderClientManagerUID
	builderClientManagerUID = func() (int, int, error) { return uid, gid, nil }
	origPeer := builderClientPeerCredentials
	builderClientPeerCredentials = func(*net.UnixConn) (int, int, int, error) { return uid, gid, 0, nil }
	t.Cleanup(func() {
		builderClientManagerUID = origUID
		builderClientPeerCredentials = origPeer
	})
}

// newAdmissionTestApp builds the build-handler fixture: admin-authorized
// app with staging seam, supervisor, and one authorized Session with a
// Dockerfile in its workspace.
func newAdmissionTestApp(t *testing.T) (*App, *operationSupervisor, *CreatedSession) {
	t.Helper()
	app := newTestAppWithAdminTokenAndStaging(t)
	supervisor := newOperationSupervisor()
	app.OperationSupervisor = supervisor
	// One command seam for the whole fixture: async run cleanup and the
	// build driver both read it concurrently, so the test must never
	// reassign it after a request started an operation.
	app.ExecCommandContext = testBuildCmd("ok", 0)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}
	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}
	return app, supervisor, result
}

func postAdmissionBuild(app *App, token string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	})
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)
	return w
}

// TestBuilderAdmissionGateReconcilesBuilderManagerState pins the gate's
// reconciliation state machine: the startup PURGE opens admission for the
// daemon generation, a refused PURGE keeps it closed, and the NEXT build
// attempt re-runs the bounded reconciliation so manager recovery never
// requires restarting the main daemon (external review F1).
func TestBuilderAdmissionGateReconcilesBuilderManagerState(t *testing.T) {
	purgeCalls := func(counter *atomic.Int32, result *error) func() error {
		return func() error {
			counter.Add(1)
			if result != nil {
				return *result
			}
			return nil
		}
	}

	t.Run("startup purge opens admission without re-purging", func(t *testing.T) {
		var calls atomic.Int32
		gate := newBuilderAdmissionGate()
		if err := gate.reconcileStartup(purgeCalls(&calls, nil)); err != nil {
			t.Fatalf("reconcileStartup = %v, want nil", err)
		}
		if !gate.ensureOpen(context.Background(), purgeCalls(&calls, nil)) {
			t.Fatal("build admission is closed after a successful startup PURGE")
		}
		if got := calls.Load(); got != 1 {
			t.Fatalf("the open gate re-purged: %d PURGE calls, want 1", got)
		}
	})

	t.Run("refused startup purge keeps admission closed", func(t *testing.T) {
		var calls atomic.Int32
		refused := errBuilderStopNotConverged
		gate := newBuilderAdmissionGate()
		if err := gate.reconcileStartup(purgeCalls(&calls, &refused)); err == nil {
			t.Fatal("reconcileStartup succeeded over a refused PURGE")
		}
		if gate.ensureOpen(context.Background(), purgeCalls(&calls, &refused)) {
			t.Fatal("build admission opened while the manager state is unknown")
		}
		if got := calls.Load(); got != 2 {
			t.Fatalf("the closed gate did not recheck: %d PURGE calls, want 2", got)
		}
	})

	t.Run("manager recovery reopens without a restart", func(t *testing.T) {
		var calls atomic.Int32
		refused := errBuilderStopNotConverged
		gate := newBuilderAdmissionGate()
		if err := gate.reconcileStartup(purgeCalls(&calls, &refused)); err == nil {
			t.Fatal("reconcileStartup succeeded over a refused PURGE")
		}
		// The manager becomes available: the next build's recheck converges.
		if !gate.ensureOpen(context.Background(), purgeCalls(&calls, nil)) {
			t.Fatal("build admission stayed closed after the manager recovered")
		}
		if got := calls.Load(); got != 2 {
			t.Fatalf("the recovery recheck did not run exactly one PURGE: %d calls, want 2", got)
		}
		if !gate.ensureOpen(context.Background(), purgeCalls(&calls, nil)) {
			t.Fatal("build admission closed again after recovery")
		}
		if got := calls.Load(); got != 2 {
			t.Fatalf("the open gate re-purged after recovery: %d calls, want 2", got)
		}
	})
}

// TestBuildAdmissionRefusedWhileManagerStateUnknown proves the handler
// contract (external review F1): while the builder-manager state is not
// proven for this daemon generation, the build is refused closed after its
// lifecycle/capacity reservation was acquired and released exactly once
// (re-review R2 places the reservation first), the run surface stays
// available, and a later build rechecks/reconciles and succeeds without a
// main-daemon restart. The real client speaks the real wire protocol to a
// test endpoint.
func TestBuildAdmissionRefusedWhileManagerStateUnknown(t *testing.T) {
	app, supervisor, session := newAdmissionTestApp(t)
	token := session.Token
	app.BuilderAdmission = newBuilderAdmissionGate()
	seamManagerPeerIdentity(t)

	refuse := true
	fakeManagerEndpoint(t, func(line string) string {
		if refuse {
			return builderManagerRespInternal
		}
		return builderManagerRespOK
	})

	// The run surface never consults the gate: it stays available while
	// the builder-manager state is unknown.
	runBody, _ := json.Marshal(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"echo", "hello"},
	})
	runReq := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(runBody))
	runReq.Header.Set("Authorization", "Bearer "+token)
	runW := httptest.NewRecorder()
	app.handleRun(runW, runReq)
	if runW.Code != http.StatusCreated {
		t.Fatalf("POST /run over an unproven builder-manager state = %d, want 201 (the run surface must stay available)", runW.Code)
	}

	// The build is refused closed BEFORE operation admission: the stable
	// internal classification, and no operation exists in the supervisor.
	w := postAdmissionBuild(app, token)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("POST /build over an unproven manager state = %d, want 500 (fail closed)", w.Code)
	}
	if code := decodeAPIError(t, w.Body.Bytes()).Code; code != "internal_error" {
		t.Fatalf("build refusal code = %q, want internal_error", code)
	}
	supervisor.mu.RLock()
	buildAdmitted := 0
	for _, op := range supervisor.ops {
		if op.Kind == operationKindBuild {
			buildAdmitted++
		}
	}
	supervisor.mu.RUnlock()
	if buildAdmitted != 0 {
		t.Fatalf("%d build operations were admitted while the builder-manager state was unknown", buildAdmitted)
	}

	// The manager becomes available: the next build rechecks/reconciles
	// through the same gate and is admitted — no main-daemon restart.
	refuse = false
	w = postAdmissionBuild(app, token)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /build after manager recovery = %d, want 201: %s", w.Code, w.Body.String())
	}
	supervisor.mu.RLock()
	admitted := len(supervisor.ops)
	supervisor.mu.RUnlock()
	if admitted != 2 {
		t.Fatalf("%d operations admitted after recovery, want 2 (the run operation and the recovered build)", admitted)
	}

	// Await the recovered build's terminal transition before the test
	// returns: the driver's manager RPCs run on their own goroutine and
	// must not outlive the endpoint seams this test restores on cleanup.
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode the created operation: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := supervisor.lookup(opID)
	if op == nil {
		t.Fatal("the recovered build operation was not registered")
	}
	op.Wait()
}

// TestBuilderAdmissionStartupReconcilePurgesLiveManagerState simulates the
// main-daemon restart against a still-alive manager holding a live
// instance from the previous generation (external review F1): the new
// generation's startup reconciliation is one real PURGE round-trip
// through the real client to the real manager serve loop, the live
// instance and its directories converge, and build admission opens for
// the next build.
func TestBuilderAdmissionStartupReconcilePurgesLiveManagerState(t *testing.T) {
	m, _, _ := processTestManager(t)
	seamCA(t)
	fakeLeaderSeam(t, true)
	seamManagerPeerIdentity(t)

	// The manager-side authentication must accept this test process as the
	// root daemon it serves in production.
	origServerPeer := builderPeerCredentials
	builderPeerCredentials = func(*net.UnixConn) (int, int, int, error) { return 0, 0, 0, nil }
	t.Cleanup(func() { builderPeerCredentials = origServerPeer })

	sockPath := filepath.Join(t.TempDir(), "mgr.sock")
	origPath := builderClientSocketPath
	builderClientSocketPath = sockPath
	t.Cleanup(func() { builderClientSocketPath = origPath })

	// The manager dispatch loop: the production per-connection handler
	// (parse, peer authentication, START/STOP/PURGE dispatch, one bounded
	// response line) over a test endpoint. The production serve loop's
	// socket setup verifies the production roots, which do not exist in
	// the test environment; the F1 target here is the client PURGE over
	// live manager state, not the service socket mechanics.
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatalf("cannot mount the test manager endpoint: %v", err)
	}
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go m.handleConnection(conn, io.Discard, 0)
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-acceptDone
	})

	// Wait for the manager endpoint to accept connections.
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.Dial("unix", sockPath)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the manager endpoint never opened: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// A live instance from the "previous" daemon generation.
	opID := "op_0123456789abcdef0123456789abcdef"
	startResp := make(chan string, 1)
	go func() { startResp <- m.start(opID, nil) }()
	if !waitInstance(t, m, opID, true) {
		t.Fatal("the previous generation's instance was not admitted")
	}
	bindFakeBuildkitdSocket(t, opID)
	select {
	case resp := <-startResp:
		if resp != builderManagerRespOK {
			t.Fatalf("START = %q, want OK", resp)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("START did not converge")
	}

	// The new generation's startup reconciliation: one bounded PURGE
	// through the real client.
	app := &App{}
	gate := newBuilderAdmissionGate()
	if err := gate.reconcileStartup(app.builderManagerPurge); err != nil {
		t.Fatalf("the startup reconciliation did not converge the live manager state: %v", err)
	}

	if !waitInstance(t, m, opID, false) {
		t.Fatal("the live instance survived the startup reconciliation PURGE")
	}
	assertDirsAbsentAt(t, opID)
	if !gate.ensureOpen(context.Background(), func() error { return nil }) {
		t.Fatal("build admission stayed closed after the successful startup reconciliation")
	}
}

// TestReviewBuildAtCapacityMustNotQueueBehindReconciliation proves the
// handler ordering contract (re-review R2): the lifecycle/capacity
// reservation is the immediate admission boundary and runs BEFORE any
// blocking backend preparation, so a build at an exhausted capacity
// ceiling is refused immediately with the single bounded capacity refusal
// and never queues behind — or triggers — the closed admission gate's
// builder-manager reconciliation.
//
// Regression shape: the pre-fix handler consulted the gate before the
// reservation, so the same saturated build waited for the in-flight
// bounded PURGE (here: a reconciliation that never completes while the
// test observes) before its immediate capacity refusal.
func TestReviewBuildAtCapacityMustNotQueueBehindReconciliation(t *testing.T) {
	app, supervisor, session := newAdmissionTestApp(t)
	app.BuilderAdmission = newBuilderAdmissionGate()
	seamManagerPeerIdentity(t)

	// The closed gate's reconciliation PURGE never completes while the
	// test observes: any handler that queues behind it cannot answer
	// within the observation window. The counter proves whether the
	// refused request consulted the gate at all.
	var purges atomic.Int32
	releasePurge := make(chan struct{})
	fakeManagerEndpoint(t, func(line string) string {
		if line == builderManagerCmdPurge {
			purges.Add(1)
			<-releasePurge
		}
		return builderManagerRespOK
	})

	// Saturate the Session ceiling exactly: four live reservations, pure
	// capacity accounting, no admitted operations.
	var held []*capacityReservation
	done := make(chan struct{})
	w := httptest.NewRecorder()
	t.Cleanup(func() {
		// The blocked reconciliation (if any) unblocks first, then the
		// handler drains against the still-saturated ceiling, and only
		// then is the capacity accounting released — so a pre-fix handler
		// resumed by this cleanup can never admit an operation.
		close(releasePurge)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
		for _, r := range held {
			r.Release()
		}
	})
	for i := 0; i < maxConcurrentOperationsPerSession; i++ {
		res, decision := supervisor.reserve(session.Session.ID, session.Session.LauncherID, operationKindRun)
		if decision != admissionAccepted {
			t.Fatalf("saturation reservation %d refused: %d", i+1, decision)
		}
		held = append(held, res)
	}

	body, _ := json.Marshal(map[string]string{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	})
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+session.Token)
	go func() {
		defer close(done)
		app.handleBuild(w, req)
	}()

	// The instant of the answer is the assertion point: the refusal must
	// come from the immediate capacity accounting, not from the gate.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("the build at exhausted capacity did not answer within the observation window: it queued behind the closed admission gate's reconciliation (%d PURGE attempts observed)", purges.Load())
	}
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("build at the capacity ceiling = %d, want %d (%s)", w.Code, http.StatusTooManyRequests, w.Body.String())
	}
	if code := decodeRejectedResponse(t, w); code != capacityRefusalCode {
		t.Fatalf("capacity refusal code = %q, want %q", code, capacityRefusalCode)
	}
	// The refused request never consulted the closed gate: no
	// reconciliation PURGE was even attempted.
	if got := purges.Load(); got != 0 {
		t.Fatalf("the capacity-refused build consulted the closed admission gate: %d PURGE attempts", got)
	}
}

// --- A1: the bounded, cancellation-aware closed-gate admission wait ---

// gateProofEvents is the ordered observation log of one scenario run.
// Every append is mutex-serialized; the asserted orderings are exactly the
// ones carried by causal chains (channel handoffs between the test
// goroutine, the HTTP handler goroutines, and the endpoint handler
// goroutines), so the recorded order is deterministic, not timing-based.
type gateProofEvents struct {
	mu    sync.Mutex
	items []string
}

func (e *gateProofEvents) add(event string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.items = append(e.items, event)
}

func (e *gateProofEvents) snapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.items...)
}

// gateProofEventIndex returns the position of the first event with the
// given prefix, or -1.
func gateProofEventIndex(events []string, prefix string) int {
	for i, event := range events {
		if strings.HasPrefix(event, prefix) {
			return i
		}
	}
	return -1
}

// gateProofAwaitEvent waits for one channel signal with a hard bound.
func gateProofAwaitEvent(t *testing.T, what string, ch <-chan struct{}, timeout time.Duration) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for %s", what)
	}
}

// gateProofWaitFor waits for an observable state transition with a hard
// bound. The 1ms poll is the bounded observation of an externally visible
// transition (the supervisor capacity counters), the established pattern of
// the shutdown tests; every actual synchronization step uses channels.
func gateProofWaitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

// gateProofAwaitRequest awaits one in-flight request's completion with a
// hard bound and returns its HTTP status, public error code, and (for an
// admitted build) its operation id.
func gateProofAwaitRequest(t *testing.T, what string, w *httptest.ResponseRecorder, done <-chan struct{}) (int, string, string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for %s", what)
	}
	if w.Code != http.StatusCreated {
		return w.Code, decodeAPIError(t, w.Body.Bytes()).Code, ""
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode the admitted operation: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	return w.Code, "", opID
}

// gateProofDrain awaits a registered operation's terminal transition
// (bounded; the fake build completes on its own) so no driver goroutine
// outlives the endpoint seams.
func gateProofDrain(t *testing.T, supervisor *operationSupervisor, opID string) {
	t.Helper()
	if opID == "" {
		return
	}
	op := supervisor.lookup(opID)
	if op == nil {
		t.Fatalf("the admitted operation %s was not registered", opID)
	}
	select {
	case <-op.done:
	case <-time.After(10 * time.Second):
		if err := supervisor.cancel(opID, nil); err != nil && err != ErrOperationAlreadyTerminal {
			t.Fatalf("cannot cancel the admitted operation: %v", err)
		}
		select {
		case <-op.done:
		case <-time.After(10 * time.Second):
			t.Fatal("the admitted operation did not reach a terminal state")
		}
	}
}

// newProofBuildRequest posts one valid build request with an explicit
// request context (the cancellation scenarios replace it).
func newProofBuildRequest(t *testing.T, token string, ctx context.Context) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	})
	if err != nil {
		t.Fatalf("cannot encode the build request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	return req.WithContext(ctx)
}

// gateProofHarness is the shared A1 scenario fixture: the real handler
// path (POST /build -> validation -> OperationSupervisor reservation ->
// builderAdmissionGate.ensureOpen -> the real builder-manager client PURGE
// round trip) against a controlled test endpoint where EVERY reconciliation
// PURGE is individually observable and individually released. Every
// blocking step resolves through channels with hard bounds, and the
// cleanup releases every PURGE the scenario failed to release, so no
// scenario can hang the test process.
type gateProofHarness struct {
	t          *testing.T
	app        *App
	supervisor *operationSupervisor
	token      string
	events     *gateProofEvents
	purges     atomic.Int32
	opLog      *bytes.Buffer
	auditLog   *bytes.Buffer
	purgeStart []chan struct{}
	purgeFree  []chan string
}

// gateProofControlledPurges bounds the endpoint's controllable PURGE slots;
// the scenarios use at most two.
const gateProofControlledPurges = 4

func newGateProofHarness(t *testing.T) *gateProofHarness {
	t.Helper()
	app, supervisor, session := newAdmissionTestApp(t)
	app.BuilderAdmission = newBuilderAdmissionGate()
	seamManagerPeerIdentity(t)

	// Capture the production operational/audit streams for the secret
	// observation (the admission-refusal paths log one static warn line).
	logging.reset()
	opBuf, auditBuf := new(bytes.Buffer), new(bytes.Buffer)
	initLoggers(opBuf, auditBuf, slog.LevelWarn, true)
	t.Cleanup(logging.reset)

	h := &gateProofHarness{
		t:          t,
		app:        app,
		supervisor: supervisor,
		token:      session.Token,
		events:     &gateProofEvents{},
		opLog:      opBuf,
		auditLog:   auditBuf,
	}
	h.purgeStart = make([]chan struct{}, gateProofControlledPurges)
	h.purgeFree = make([]chan string, gateProofControlledPurges)
	for i := range h.purgeStart {
		h.purgeStart[i] = make(chan struct{})
		h.purgeFree[i] = make(chan string, 1)
	}
	fakeManagerEndpoint(t, func(line string) string {
		if line != builderManagerCmdPurge {
			return builderManagerRespOK
		}
		n := int(h.purges.Add(1))
		if n > gateProofControlledPurges {
			h.events.add(fmt.Sprintf("purge%d:start-unexpected", n))
			return builderManagerRespInternal
		}
		h.events.add(fmt.Sprintf("purge%d:start", n))
		close(h.purgeStart[n-1])
		reply := <-h.purgeFree[n-1]
		h.events.add(fmt.Sprintf("purge%d:reply:%s", n, reply))
		return reply
	})
	// Guaranteed unblock: even a failing assertion releases every
	// controlled PURGE so no handler goroutine can outlive the test.
	t.Cleanup(func() {
		for _, ch := range h.purgeFree {
			select {
			case ch <- builderManagerRespInternal:
			default:
			}
		}
	})
	return h
}

// postBuild dispatches one valid build request through the real handler.
func (h *gateProofHarness) postBuild(ctx context.Context) (*httptest.ResponseRecorder, <-chan struct{}) {
	w, done := httptest.NewRecorder(), make(chan struct{})
	go func() {
		defer close(done)
		h.app.handleBuild(w, newProofBuildRequest(h.t, h.token, ctx))
	}()
	return w, done
}

// awaitPurgeStart waits for the Nth (1-based) controlled PURGE to start.
func (h *gateProofHarness) awaitPurgeStart(n int) {
	h.t.Helper()
	gateProofAwaitEvent(h.t, fmt.Sprintf("PURGE #%d start", n), h.purgeStart[n-1], 5*time.Second)
}

// freePurge releases the Nth (1-based) controlled PURGE with the given
// manager reply (OK opens the gate; ERR internal refuses it).
func (h *gateProofHarness) freePurge(n int, reply string) {
	h.t.Helper()
	h.purgeFree[n-1] <- reply
}

// buildSlots reports the supervisor's held global build slots.
func (h *gateProofHarness) buildSlots() int {
	h.supervisor.mu.RLock()
	defer h.supervisor.mu.RUnlock()
	return h.supervisor.globalBuildCount
}

// globalOps reports the supervisor's registered operations.
func (h *gateProofHarness) globalOps() int {
	h.supervisor.mu.RLock()
	defer h.supervisor.mu.RUnlock()
	return len(h.supervisor.ops)
}

// drainAndVerify closes one scenario: every capacity slot must be released
// (after any admitted operation drained to its terminal state) and no
// bearer-token material may appear in the response bodies or the captured
// production operational/audit streams.
func (h *gateProofHarness) drainAndVerify(bodies ...string) {
	h.t.Helper()
	for _, body := range bodies {
		if strings.Contains(body, h.token) {
			h.t.Fatal("the session bearer token leaked into a response body")
		}
	}
	for _, stream := range []struct{ name, text string }{
		{"the operational log", h.opLog.String()},
		{"the audit log", h.auditLog.String()},
	} {
		if strings.Contains(stream.text, h.token) {
			h.t.Fatalf("the session bearer token leaked into %s", stream.name)
		}
	}
	if h.buildSlots() != 0 {
		h.t.Fatalf("capacity leaked: %d global build slots still held", h.buildSlots())
	}
}

// TestBuilderAdmissionConcurrentClosedGateWait pins the A1 admission
// semantics through the real production handler path: at most one
// reconciliation PURGE at a time; a concurrent request joins the in-flight
// attempt and receives exactly its result; the request context bounds each
// request's own participation; the fail-closed and capacity contracts are
// preserved on every path.
func TestBuilderAdmissionConcurrentClosedGateWait(t *testing.T) {
	t.Run("leader refusal propagates to the joined follower without a second PURGE", func(t *testing.T) {
		h := newGateProofHarness(t)

		// The leader holds the closed gate with its blocked PURGE.
		aW, aDone := h.postBuild(context.Background())
		h.awaitPurgeStart(1)
		select {
		case <-aDone:
			t.Fatal("the leader completed while its PURGE was still blocked")
		default:
		}

		// The follower joins the leader's attempt: it acquires its capacity
		// reservation (the reservation is taken immediately before the
		// gate, so a reserved, not-yet-completed request is inside the
		// ensureOpen wait) and cannot complete while the gate is held.
		bW, bDone := h.postBuild(context.Background())
		if !gateProofWaitFor(t, "the follower's capacity reservation", 5*time.Second,
			func() bool { return h.buildSlots() == 2 }) {
			t.Fatal("the follower never acquired its capacity reservation")
		}
		h.events.add("b:reserved")
		select {
		case <-bDone:
			t.Fatal("the follower completed while the leader still held the closed gate")
		default:
		}

		// A third build at the occupied ceiling is refused immediately at
		// its capacity reservation, while the leader's PURGE is still
		// blocked: it never reaches the gate and never purges.
		cW, cDone := h.postBuild(context.Background())
		cCode, cErrCode, _ := gateProofAwaitRequest(t, "the third build's completion", cW, cDone)
		h.events.add("c:refused")
		if cCode != http.StatusTooManyRequests || cErrCode != capacityRefusalCode {
			t.Fatalf("the third build at the occupied ceiling = %d/%q, want 429/%q",
				cCode, cErrCode, capacityRefusalCode)
		}
		if got := h.purges.Load(); got != 1 {
			t.Fatalf("the capacity-refused build consulted the gate: %d PURGE attempts, want 1", got)
		}

		// The leader's PURGE is refused: the joined follower receives the
		// refusal of the attempt it joined, WITHOUT a PURGE of its own.
		h.freePurge(1, builderManagerRespInternal)
		aCode, aErrCode, _ := gateProofAwaitRequest(t, "the leader's completion", aW, aDone)
		bCode, bErrCode, _ := gateProofAwaitRequest(t, "the follower's completion", bW, bDone)
		h.events.add("refusals:done")
		if aCode != http.StatusInternalServerError || aErrCode != "internal_error" {
			t.Fatalf("the refused leader = %d/%q, want 500/internal_error", aCode, aErrCode)
		}
		if bCode != http.StatusInternalServerError || bErrCode != "internal_error" {
			t.Fatalf("the refused follower = %d/%q, want 500/internal_error", bCode, bErrCode)
		}
		if got := h.purges.Load(); got != 1 {
			t.Fatalf("the follower started its own PURGE after the joined attempt was refused: %d PURGE attempts, want 1", got)
		}
		// Causal order: the follower was inside the gate wait (reserved,
		// not completed) before the leader's refusal reply, and its refusal
		// followed the joined attempt's resolution.
		events := h.events.snapshot()
		i1, ib := gateProofEventIndex(events, "purge1:start"), gateProofEventIndex(events, "b:reserved")
		ir, ic := gateProofEventIndex(events, "purge1:reply"), gateProofEventIndex(events, "c:refused")
		if !(i1 < ib && ib < ir && ic < ir) {
			t.Fatalf("unexpected event order (purge1 start %d, follower reserved %d, purge1 reply %d, third refused %d): %s",
				i1, ib, ir, ic, strings.Join(events, " -> "))
		}

		// A NEW request arriving after the failed attempt resolved starts
		// the next reconciliation, which may open the gate.
		dW, dDone := h.postBuild(context.Background())
		h.awaitPurgeStart(2)
		h.freePurge(2, builderManagerRespOK)
		dCode, _, dOpID := gateProofAwaitRequest(t, "the re-purging request's completion", dW, dDone)
		if dCode != http.StatusCreated {
			t.Fatalf("the request after the refused attempt = %d, want 201: %s", dCode, dW.Body.String())
		}
		gateProofDrain(t, h.supervisor, dOpID)
		if got := h.globalOps(); got != 1 {
			t.Fatalf("%d operations registered, want exactly the admitted post-refusal build", got)
		}
		h.drainAndVerify(aW.Body.String(), bW.Body.String(), cW.Body.String(), dW.Body.String())
	})

	t.Run("one successful reconciliation admits both joined participants", func(t *testing.T) {
		h := newGateProofHarness(t)

		aW, aDone := h.postBuild(context.Background())
		h.awaitPurgeStart(1)

		bW, bDone := h.postBuild(context.Background())
		if !gateProofWaitFor(t, "the follower's capacity reservation", 5*time.Second,
			func() bool { return h.buildSlots() == 2 }) {
			t.Fatal("the follower never acquired its capacity reservation")
		}

		// The single reconciliation succeeds: the gate opens for both
		// valid participants, and neither runs a PURGE of its own.
		h.freePurge(1, builderManagerRespOK)
		aCode, _, aOpID := gateProofAwaitRequest(t, "the leader's completion", aW, aDone)
		bCode, _, bOpID := gateProofAwaitRequest(t, "the follower's completion", bW, bDone)
		if aCode != http.StatusCreated || bCode != http.StatusCreated {
			t.Fatalf("the successful reconciliation admitted %d and %d, want 201 and 201 (%s / %s)",
				aCode, bCode, aW.Body.String(), bW.Body.String())
		}
		if got := h.purges.Load(); got != 1 {
			t.Fatalf("%d PURGE attempts for two admitted builds, want exactly the one shared reconciliation", got)
		}
		gateProofDrain(t, h.supervisor, aOpID)
		gateProofDrain(t, h.supervisor, bOpID)
		if got := h.globalOps(); got != 2 {
			t.Fatalf("%d operations registered, want exactly the two admitted builds", got)
		}
		h.drainAndVerify(aW.Body.String(), bW.Body.String())
	})

	t.Run("a cancelled follower stops waiting, starts no PURGE, releases capacity", func(t *testing.T) {
		h := newGateProofHarness(t)

		aW, aDone := h.postBuild(context.Background())
		h.awaitPurgeStart(1)

		bCtx, bCancel := context.WithCancel(context.Background())
		bW, bDone := h.postBuild(bCtx)
		if !gateProofWaitFor(t, "the follower's capacity reservation", 5*time.Second,
			func() bool { return h.buildSlots() == 2 }) {
			t.Fatal("the follower never acquired its capacity reservation")
		}

		// Cancel the waiting follower: it must stop waiting while the
		// leader's PURGE is still blocked — without starting a PURGE and
		// without waiting for the attempt's resolution.
		bCancel()
		bCode, bErrCode, _ := gateProofAwaitRequest(t, "the cancelled follower's completion", bW, bDone)
		h.events.add("b:cancelled-done")
		if bCode != http.StatusInternalServerError || bErrCode != "internal_error" {
			t.Fatalf("the cancelled follower = %d/%q, want the fail-closed 500/internal_error", bCode, bErrCode)
		}
		if got := h.purges.Load(); got != 1 {
			t.Fatalf("the cancelled follower started a PURGE: %d attempts, want 1", got)
		}
		if got := h.buildSlots(); got != 1 {
			t.Fatalf("the cancelled follower kept its capacity reservation: %d build slots held, want 1 (the leader's)", got)
		}
		select {
		case <-aDone:
			t.Fatal("the leader completed while its PURGE was still blocked")
		default:
		}

		// The leader's own reconciliation is then refused: nothing else
		// changes, the gate stays closed.
		h.freePurge(1, builderManagerRespInternal)
		aCode, aErrCode, _ := gateProofAwaitRequest(t, "the leader's completion", aW, aDone)
		if aCode != http.StatusInternalServerError || aErrCode != "internal_error" {
			t.Fatalf("the refused leader = %d/%q, want 500/internal_error", aCode, aErrCode)
		}
		if got := h.globalOps(); got != 0 {
			t.Fatalf("%d operations were registered by refused or cancelled requests", got)
		}
		h.drainAndVerify(aW.Body.String(), bW.Body.String())
	})

	t.Run("a cancelled leader is not admitted; the proven PURGE still opens the gate", func(t *testing.T) {
		h := newGateProofHarness(t)

		aCtx, aCancel := context.WithCancel(context.Background())
		aW, aDone := h.postBuild(aCtx)
		h.awaitPurgeStart(1)

		// Cancel the leader while its own PURGE is blocked. The
		// already-started PURGE still completes within its bound, and the
		// gate result must come from the purge's own outcome alone.
		aCancel()
		h.freePurge(1, builderManagerRespOK)

		aCode, aErrCode, _ := gateProofAwaitRequest(t, "the cancelled leader's completion", aW, aDone)
		if aCode != http.StatusInternalServerError || aErrCode != "internal_error" {
			t.Fatalf("the cancelled leader = %d/%q, want the fail-closed 500/internal_error (no admission after cancellation)", aCode, aErrCode)
		}
		if got := h.globalOps(); got != 0 {
			t.Fatalf("the cancelled leader was admitted: %d operations registered", got)
		}
		if got := h.buildSlots(); got != 0 {
			t.Fatalf("the cancelled leader kept its capacity reservation: %d build slots held", got)
		}

		// The gate opened on the PROVEN successful PURGE: a later valid
		// request passes without any reconciliation of its own.
		dW, dDone := h.postBuild(context.Background())
		dCode, _, dOpID := gateProofAwaitRequest(t, "the post-recovery request's completion", dW, dDone)
		if dCode != http.StatusCreated {
			t.Fatalf("the request after the proven reconciliation = %d, want 201: %s", dCode, dW.Body.String())
		}
		if got := h.purges.Load(); got != 1 {
			t.Fatalf("%d PURGE attempts, want 1: the open gate must not re-purge", got)
		}
		gateProofDrain(t, h.supervisor, dOpID)
		if got := h.globalOps(); got != 1 {
			t.Fatalf("%d operations registered, want exactly the post-recovery build", got)
		}
		h.drainAndVerify(aW.Body.String(), dW.Body.String())
	})
}
