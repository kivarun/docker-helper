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
		if !gate.ensureOpen(purgeCalls(&calls, nil)) {
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
		if gate.ensureOpen(purgeCalls(&calls, &refused)) {
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
		if !gate.ensureOpen(purgeCalls(&calls, nil)) {
			t.Fatal("build admission stayed closed after the manager recovered")
		}
		if got := calls.Load(); got != 2 {
			t.Fatalf("the recovery recheck did not run exactly one PURGE: %d calls, want 2", got)
		}
		if !gate.ensureOpen(purgeCalls(&calls, nil)) {
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
	if !gate.ensureOpen(func() error { return nil }) {
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

// --- A1 proof: the concurrent closed-gate wait (proof only, no production change) ---

// gateProofEvents is the ordered observation log of one proof scenario.
// Every append is mutex-serialized; the asserted orderings are exactly the
// ones carried by causal chains (channel handoffs between the test
// goroutine, the HTTP handler goroutines, and the endpoint handler
// goroutines), so the recorded order is deterministic, not timing-dependent.
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

// index returns the position of the first event with the given prefix.
func (e *gateProofEvents) index(prefix string) int {
	for i, event := range e.snapshot() {
		if strings.HasPrefix(event, prefix) {
			return i
		}
	}
	return -1
}

// gateProofOutcome carries every requested observation of one scenario run.
type gateProofOutcome struct {
	events                  []string
	purges                  int
	followerStartedOwnPurge bool
	aCode                   int
	aErrCode                string
	bCode                   int
	bErrCode                string
	bOperationID            string
	opLogOutput             string
	auditOutput             string
	heldBuildSlots          int
	heldGlobalSlots         int
	registeredOps           int
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
func gateProofWaitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// supervisorBuildSlotsHeld reads the supervisor's held global build slots.
func supervisorBuildSlotsHeld(s *operationSupervisor) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.globalBuildCount
}

// newProofBuildRequest posts one valid build request with an explicit
// request context (the cancellation scenario replaces it).
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

// runGateReconciliationProof drives the A1 scenario through the real
// production handler path: POST /build -> validation -> OperationSupervisor
// reservation -> builderAdmissionGate.ensureOpen -> the real builder-manager
// client PURGE round trip against the test endpoint. Two concurrent valid
// build requests hit a closed gate; the first caller's PURGE is blocked by
// the endpoint and is then released with a controlled outcome; the
// secondPurgeReply decides the follower's own PURGE outcome (a refusal ends
// the scenario closed; OK opens the gate and admits the follower's build).
// Every blocking step has a bounded wait and a guaranteed cleanup release,
// so the scenario cannot hang the test process.
func runGateReconciliationProof(t *testing.T, cancelFollower bool, secondPurgeReply string) gateProofOutcome {
	t.Helper()
	app, supervisor, session := newAdmissionTestApp(t)
	app.BuilderAdmission = newBuilderAdmissionGate()
	seamManagerPeerIdentity(t)

	// Capture the production operational/audit streams for the secret
	// observation (the refusal path logs one static warn line).
	logging.reset()
	opBuf, auditBuf := new(bytes.Buffer), new(bytes.Buffer)
	initLoggers(opBuf, auditBuf, slog.LevelWarn, true)
	t.Cleanup(logging.reset)

	var purges atomic.Int32
	events := &gateProofEvents{}
	purge1Started := make(chan struct{})
	purge1Replied := make(chan struct{})
	purge2Started := make(chan struct{})
	release1 := make(chan string, 1)
	release2 := make(chan string, 1)
	fakeManagerEndpoint(t, func(line string) string {
		if line != builderManagerCmdPurge {
			return builderManagerRespOK
		}
		switch n := purges.Add(1); n {
		case 1:
			events.add("purge1:start")
			close(purge1Started)
			reply := <-release1
			events.add("purge1:reply:" + reply)
			close(purge1Replied)
			return reply
		case 2:
			events.add("purge2:start")
			close(purge2Started)
			reply := <-release2
			events.add("purge2:reply:" + reply)
			return reply
		default:
			events.add(fmt.Sprintf("purge%d:start-unexpected", n))
			return builderManagerRespInternal
		}
	})
	// Guaranteed unblock: even a failing assertion releases every
	// controlled PURGE so no handler goroutine can outlive the test.
	t.Cleanup(func() {
		for _, ch := range []chan string{release1, release2} {
			select {
			case ch <- builderManagerRespInternal:
			default:
			}
		}
	})

	// Request A: reaches the closed gate first and holds it with its
	// blocked PURGE.
	aW, aDone := httptest.NewRecorder(), make(chan struct{})
	go func() {
		defer close(aDone)
		app.handleBuild(aW, newProofBuildRequest(t, session.Token, context.Background()))
	}()
	gateProofAwaitEvent(t, "the first caller's PURGE start", purge1Started, 5*time.Second)
	select {
	case <-aDone:
		t.Fatal("the first caller completed while its PURGE was still blocked")
	default:
	}

	// Request B: dispatched while A holds the gate. Its capacity
	// reservation is observable before the first PURGE is released; the
	// reservation is taken immediately before the gate in the production
	// order, so a reserved, not-yet-completed B is already inside the
	// ensureOpen wait (the gate mutex is the only blocking step left).
	bCtx, bCancel := context.WithCancel(context.Background())
	defer bCancel()
	bW, bDone := httptest.NewRecorder(), make(chan struct{})
	go func() {
		defer close(bDone)
		app.handleBuild(bW, newProofBuildRequest(t, session.Token, bCtx))
	}()
	gateProofWaitFor(t, "the second caller's capacity reservation", 5*time.Second,
		func() bool { return supervisorBuildSlotsHeld(supervisor) == 2 })
	events.add("b:reserved")
	select {
	case <-bDone:
		t.Fatal("the second caller completed while the first caller still held the closed gate")
	default:
	}

	if cancelFollower {
		bCancel()
		events.add("b:cancelled")
	}

	// Release the first PURGE with a refusal: A fails closed.
	release1 <- builderManagerRespInternal
	gateProofAwaitEvent(t, "the first PURGE reply", purge1Replied, 5*time.Second)
	select {
	case <-aDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for the first caller's completion")
	}
	events.add("a:done")

	// The A1 observation: after the in-flight PURGE is refused, does the
	// follower complete without a reconciliation of its own (the
	// documented bound), or does it start an additional PURGE?
	select {
	case <-purge2Started:
		out := gateProofOutcome{followerStartedOwnPurge: true}
		out.events = events.snapshot()
		out.purges = int(purges.Load())
		out.aCode, out.aErrCode = proofResponseCode(t, aW)
		// Resolve the follower's own PURGE with the scenario's outcome and
		// await its completion.
		release2 <- secondPurgeReply
		select {
		case <-bDone:
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for the second caller's completion after its own PURGE")
		}
		events.add("b:done")
		out.bCode, out.bErrCode = proofResponseCode(t, bW)
		out.bOperationID = proofOperationID(t, bW)
		proofDrain(t, supervisor, out.bOperationID)
		out.opLogOutput, out.auditOutput = opBuf.String(), auditBuf.String()
		out.heldBuildSlots, out.heldGlobalSlots, out.registeredOps = proofCapacity(t, supervisor)
		return out
	case <-bDone:
		out := gateProofOutcome{followerStartedOwnPurge: false}
		out.events = events.snapshot()
		out.purges = int(purges.Load())
		out.aCode, out.aErrCode = proofResponseCode(t, aW)
		out.bCode, out.bErrCode = proofResponseCode(t, bW)
		out.opLogOutput, out.auditOutput = opBuf.String(), auditBuf.String()
		out.heldBuildSlots, out.heldGlobalSlots, out.registeredOps = proofCapacity(t, supervisor)
		return out
	case <-time.After(5 * time.Second):
		t.Fatalf("neither an additional PURGE nor the follower's completion within the observation window (events: %s)",
			strings.Join(events.snapshot(), " -> "))
		return gateProofOutcome{}
	}
}

// proofResponseCode records one request's HTTP status and public error code.
func proofResponseCode(t *testing.T, w *httptest.ResponseRecorder) (int, string) {
	t.Helper()
	if w.Code != http.StatusInternalServerError {
		return w.Code, ""
	}
	return w.Code, decodeAPIError(t, w.Body.Bytes()).Code
}

// proofOperationID extracts the admitted operation id from a 201 body.
func proofOperationID(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != http.StatusCreated {
		return ""
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode the admitted operation: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	return opID
}

// proofDrain awaits a registered operation's terminal transition (bounded;
// the fake build completes on its own) so no driver goroutine outlives the
// endpoint seams.
func proofDrain(t *testing.T, supervisor *operationSupervisor, opID string) {
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

// proofCapacity snapshots the supervisor's held slots and registered
// operations after the scenario drained.
func proofCapacity(t *testing.T, s *operationSupervisor) (int, int, int) {
	t.Helper()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.globalBuildCount, s.globalRunning, len(s.ops)
}

// assertNoProofSecret proves neither the public error bodies nor the
// captured operational/audit streams carry the session bearer token.
func assertNoProofSecret(t *testing.T, out gateProofOutcome, token string) {
	t.Helper()
	for _, stream := range map[string]string{
		"the first response body":  fmt.Sprint(out.aErrCode),
		"the second response body": fmt.Sprint(out.bErrCode),
		"the operational log":      out.opLogOutput,
		"the audit log":            out.auditOutput,
	} {
		if strings.Contains(stream, token) {
			t.Fatalf("the session bearer token leaked into %s", stream)
		}
	}
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

// TestBuilderAdmissionConcurrentClosedGateWait is the A1 proof (proof only,
// no production change): two concurrent valid build requests at a closed
// builder-admission gate, the first caller's PURGE blocked by the test
// endpoint and then refused. It separates three questions:
//
//  1. the documented admission bound (build.go): a follower at the closed
//     gate "waits at most for the in-flight bounded PURGE" — after the
//     in-flight PURGE is REFUSED, the follower must therefore complete
//     without a reconciliation of its own;
//  2. the observed serialization behavior (each closed-gate caller runs
//     its own bounded PURGE after a refused in-flight one);
//  3. the request-cancellation behavior during the gate wait.
//
// The gate mutex wait itself is bounded by the in-flight PURGE (that part
// of the documented claim holds); the first subtest fails exactly because
// the refused in-flight PURGE is FOLLOWED by the follower's own bounded
// PURGE, a second bounded interval the documented sentence does not state.
func TestBuilderAdmissionConcurrentClosedGateWait(t *testing.T) {
	t.Run("documented bound: the follower completes within the in-flight PURGE", func(t *testing.T) {
		out := runGateReconciliationProof(t, false, builderManagerRespInternal)
		// RED at the proof baseline: the follower started its own PURGE
		// after the in-flight PURGE was refused. The documented claim
		// ("waits at most for the in-flight bounded PURGE") does not hold
		// for the refusal path: the follower's gate wait spans the
		// in-flight PURGE AND its own bounded PURGE. This assertion is the
		// reproducing red check and must not be weakened to green.
		if out.followerStartedOwnPurge {
			t.Fatalf("the follower started its own PURGE after the in-flight PURGE was refused: %d PURGE attempts total (events: %s)",
				out.purges, strings.Join(out.events, " -> "))
		}
	})

	t.Run("observed serialization: each closed-gate caller runs its own bounded PURGE", func(t *testing.T) {
		out := runGateReconciliationProof(t, false, builderManagerRespInternal)
		if out.purges != 2 {
			t.Fatalf("observed %d PURGE attempts, want 2 (the in-flight one and the follower's own)", out.purges)
		}
		// Causal event order: the follower was already inside the gate
		// wait (reserved, not completed) before the in-flight PURGE was
		// released; the follower's own PURGE started only after the
		// in-flight PURGE's refusal reply.
		i1, ib := gateProofEventIndex(out.events, "purge1:start"), gateProofEventIndex(out.events, "b:reserved")
		ir, i2 := gateProofEventIndex(out.events, "purge1:reply"), gateProofEventIndex(out.events, "purge2:start")
		if !(i1 < ib && ib < ir && ir < i2) {
			t.Fatalf("unexpected event order (purge1 start %d, follower reserved %d, purge1 reply %d, purge2 start %d): %s",
				i1, ib, ir, i2, strings.Join(out.events, " -> "))
		}
		if out.aCode != http.StatusInternalServerError || out.aErrCode != "internal_error" {
			t.Fatalf("the refused leader = %d/%q, want 500/internal_error", out.aCode, out.aErrCode)
		}
		if out.bCode != http.StatusInternalServerError || out.bErrCode != "internal_error" {
			t.Fatalf("the refused follower = %d/%q, want 500/internal_error", out.bCode, out.bErrCode)
		}
		// The fail-closed invariant: both refusals left the public shape
		// intact and released every held resource.
		if out.heldBuildSlots != 0 || out.heldGlobalSlots != 0 {
			t.Fatalf("capacity leaked after both refusals: build slots %d, global slots %d", out.heldBuildSlots, out.heldGlobalSlots)
		}
		if out.registeredOps != 0 {
			t.Fatalf("%d operations were registered by refused builds", out.registeredOps)
		}
	})

	t.Run("request cancellation is not honored during the gate wait", func(t *testing.T) {
		out := runGateReconciliationProof(t, true, builderManagerRespOK)
		// The follower's request context was cancelled BEFORE the in-flight
		// PURGE was released; the follower still ran its own PURGE
		// afterwards and, with it succeeding, still ADMITTED its build.
		ic := gateProofEventIndex(out.events, "b:cancelled")
		ir, i2 := gateProofEventIndex(out.events, "purge1:reply"), gateProofEventIndex(out.events, "purge2:start")
		if !(ic >= 0 && ic < ir && ir < i2) {
			t.Fatalf("unexpected cancellation event order (cancelled %d, purge1 reply %d, purge2 start %d): %s",
				ic, ir, i2, strings.Join(out.events, " -> "))
		}
		if out.purges != 2 {
			t.Fatalf("observed %d PURGE attempts, want 2: the cancelled follower still reconciled", out.purges)
		}
		if out.bCode != http.StatusCreated {
			t.Fatalf("the cancelled follower = %d, want 201: the abandoned request still completed its admission", out.bCode)
		}
		if out.aCode != http.StatusInternalServerError || out.aErrCode != "internal_error" {
			t.Fatalf("the refused leader = %d/%q, want 500/internal_error", out.aCode, out.aErrCode)
		}
		// The abandoned request's build became a real operation and held
		// its capacity until it reached a terminal state (drained by the
		// runner); nothing else was registered.
		if out.registeredOps != 1 {
			t.Fatalf("%d operations registered, want exactly the cancelled follower's admitted build", out.registeredOps)
		}
		if out.heldBuildSlots != 0 || out.heldGlobalSlots != 0 {
			t.Fatalf("capacity leaked after the admitted build drained: build slots %d, global slots %d",
				out.heldBuildSlots, out.heldGlobalSlots)
		}
	})
}
