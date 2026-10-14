package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
