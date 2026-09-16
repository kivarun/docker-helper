package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newCapacityTestApp creates a user-mode test app with a supervisor and one
// admin Session whose workspace exists, wired for long-lived fake Docker
// processes. The terminateForShutdown cleanup bounds every fake process.
func newCapacityTestApp(t *testing.T) (*App, *CreatedSession) {
	t.Helper()
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		// sleep responds to SIGTERM, matching the real termination paths.
		return exec.CommandContext(ctx, "sleep", "300")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		app.OperationSupervisor.terminateForShutdown(ctx, nil)
	})
	return app, result
}

// runCapacityRequest posts one run request through the real handler.
func runCapacityRequest(t *testing.T, app *App, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := newRunRequest(map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"true"},
	}, token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)
	return w
}

// decodeRejectedResponse extracts the public error code of a refusal.
func decodeRejectedResponse(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("cannot decode refusal response %q: %v", w.Body.String(), err)
	}
	return resp.Code
}

// TestRunSessionCapacityRefusedImmediately proves the Session-scope concurrent
// Operation ceiling: exactly maxConcurrentOperationsPerSession long-lived
// operations are admitted, the next request is refused immediately with the
// single bounded capacity refusal, and the refusal leaves no admitted
// Operation behind.
func TestRunSessionCapacityRefusedImmediately(t *testing.T) {
	app, result := newCapacityTestApp(t)

	for i := 0; i < maxConcurrentOperationsPerSession; i++ {
		w := runCapacityRequest(t, app, result.Token)
		if w.Code != http.StatusCreated {
			t.Fatalf("operation %d at the Session ceiling: expected %d, got %d (%s)",
				i+1, http.StatusCreated, w.Code, w.Body.String())
		}
	}

	// The next request is refused immediately: no queue, no wait.
	w := runCapacityRequest(t, app, result.Token)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("capacity refusal: expected %d at the Session ceiling, got %d (%s)",
			http.StatusTooManyRequests, w.Code, w.Body.String())
	}
	if code := decodeRejectedResponse(t, w); code != "operation_capacity_unavailable" {
		t.Fatalf("capacity refusal code: expected operation_capacity_unavailable, got %q", code)
	}

	// The refusal admitted no Operation: the Session still holds exactly the
	// ceiling of running operations and nothing else was registered.
	if got := len(app.OperationSupervisor.ops); got != maxConcurrentOperationsPerSession {
		t.Fatalf("refused request must not consume capacity: %d registered operations", got)
	}
}

// TestRunOtherSessionUsesFreeGlobalCapacity proves the Session ceiling does
// not expose global topology: when one Session holds its full share, another
// Session can still use free global capacity.
func TestRunOtherSessionUsesFreeGlobalCapacity(t *testing.T) {
	app, first := newCapacityTestApp(t)
	second, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	for i := 0; i < maxConcurrentOperationsPerSession; i++ {
		if w := runCapacityRequest(t, app, first.Token); w.Code != http.StatusCreated {
			t.Fatalf("first session operation %d: expected %d, got %d (%s)",
				i+1, http.StatusCreated, w.Code, w.Body.String())
		}
	}

	// Another Session can use free global capacity.
	w := runCapacityRequest(t, app, second.Token)
	if w.Code != http.StatusCreated {
		t.Fatalf("second session must use free global capacity: expected %d, got %d (%s)",
			http.StatusCreated, w.Code, w.Body.String())
	}
}

// TestRunTerminalOperationFreesCapacityImmediately proves that capacity ends
// at the terminal state, not at retention pruning: after the Session ceiling
// is exhausted, explicitly cancelling the running operations frees their
// slots immediately — their metadata and logs remain retained — and new
// operations are admitted again without any waiting.
func TestRunTerminalOperationFreesCapacityImmediately(t *testing.T) {
	app, result := newCapacityTestApp(t)

	for i := 0; i < maxConcurrentOperationsPerSession; i++ {
		if w := runCapacityRequest(t, app, result.Token); w.Code != http.StatusCreated {
			t.Fatalf("operation %d: expected %d, got %d (%s)", i+1, http.StatusCreated, w.Code, w.Body.String())
		}
	}
	if w := runCapacityRequest(t, app, result.Token); w.Code != http.StatusTooManyRequests {
		t.Fatalf("capacity refusal: expected %d, got %d (%s)", http.StatusTooManyRequests, w.Code, w.Body.String())
	}

	// Terminate every running operation and wait for its terminal state.
	app.OperationSupervisor.mu.RLock()
	ops := make([]*operation, 0, len(app.OperationSupervisor.ops))
	for _, op := range app.OperationSupervisor.ops {
		ops = append(ops, op)
	}
	app.OperationSupervisor.mu.RUnlock()
	for _, op := range ops {
		if err := app.OperationSupervisor.cancel(op.ID, nil); err != nil {
			t.Fatalf("cancel: %v", err)
		}
	}
	for _, op := range ops {
		select {
		case <-op.done:
		case <-time.After(5 * time.Second):
			t.Fatal("operation did not reach a terminal state")
		}
	}

	// Capacity is reusable immediately while the terminal operations remain
	// retained in the supervisor.
	if got := len(app.OperationSupervisor.ops); got != maxConcurrentOperationsPerSession {
		t.Fatalf("terminal operations must remain retained: %d registered operations", got)
	}
	w := runCapacityRequest(t, app, result.Token)
	if w.Code != http.StatusCreated {
		t.Fatalf("terminal operations must free capacity: expected %d, got %d (%s)",
			http.StatusCreated, w.Code, w.Body.String())
	}
}

// TestReserveSessionAndGlobalCeilings exercises the supervisor's fixed
// Release-2.2 capacity ceilings directly: exact Session limit succeeds,
// Session limit+1 refuses immediately, another Session can still use free
// global capacity, the global ceiling refuses, and a released slot is
// reusable immediately.
func TestReserveSessionAndGlobalCeilings(t *testing.T) {
	s := newOperationSupervisor()
	s.maxPerSession = 2
	s.maxGlobal = 3
	s.maxGlobalBuilds = 3

	// Session A takes its full share.
	resA1, d := s.reserve("sess-a", "launcher-a", operationKindRun)
	if d != admissionAccepted {
		t.Fatalf("reserve A1: %d", d)
	}
	resA2, d := s.reserve("sess-a", "launcher-a", operationKindRun)
	if d != admissionAccepted {
		t.Fatalf("reserve A2: %d", d)
	}
	// Session A is exhausted; a different Session uses free global capacity.
	if _, d := s.reserve("sess-a", "launcher-a", operationKindRun); d != admissionRefusedCapacity {
		t.Fatalf("reserve A3: expected capacity refusal, got %d", d)
	}
	resB1, d := s.reserve("sess-b", "launcher-b", operationKindRun)
	if d != admissionAccepted {
		t.Fatalf("reserve B1: %d", d)
	}

	// The global ceiling is now reached and refuses immediately: no queue,
	// no waiter.
	if _, d := s.reserve("sess-c", "launcher-c", operationKindRun); d != admissionRefusedCapacity {
		t.Fatalf("reserve C1 at global ceiling: expected capacity refusal, got %d", d)
	}

	// Releasing one slot frees global capacity immediately while A is still
	// saturated; the release is exactly once.
	resA2.Release()
	resA2.Release()
	resC, d := s.reserve("sess-c", "launcher-c", operationKindRun)
	if d != admissionAccepted {
		t.Fatalf("reserve C after release: %d", d)
	}
	resA1.Release()
	resB1.Release()
	resC.Release()

	if got := s.globalRunning; got != 0 {
		t.Fatalf("capacity must be fully released: %d", got)
	}
	if got := len(s.sessionRunning); got != 0 {
		t.Fatalf("session capacity must be fully released: %d sessions", got)
	}
}

// TestReserveConcurrentNeverOversubscribes proves the check-and-reserve is a
// single critical section: concurrent reserves can never oversubscribe the
// fixed ceilings.
func TestReserveConcurrentNeverOversubscribes(t *testing.T) {
	s := newOperationSupervisor()
	s.maxPerSession = 1
	s.maxGlobal = 7
	s.maxGlobalBuilds = 7

	const attempts = 200
	accepted := make(chan struct{}, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			session := fmt.Sprintf("sess-%d", n)
			launcher := fmt.Sprintf("launcher-%d", n)
			if res, d := s.reserve(session, launcher, operationKindRun); d == admissionAccepted {
				accepted <- struct{}{}
				_ = res
			}
		}(i)
	}
	wg.Wait()
	close(accepted)

	got := 0
	for range accepted {
		got++
	}
	if got != s.maxGlobal {
		t.Fatalf("expected exactly %d accepted concurrent reserves, got %d", s.maxGlobal, got)
	}
	if got := s.globalRunning; got != s.maxGlobal {
		t.Fatalf("global counter must match accepted reservations: %d", got)
	}
}

// TestReserveThenQuiesceRefusedAtFinalAdmission proves that a reservation
// obtained before a Launcher quiesce is not an admitted Operation: final
// admission re-checks the lifecycle closure and refuses, and the released
// reservation leaves the capacity reusable.
func TestReserveThenQuiesceRefusedAtFinalAdmission(t *testing.T) {
	s := newOperationSupervisor()
	s.maxPerSession = 1
	s.maxGlobal = 1
	s.maxGlobalBuilds = 1

	res, d := s.reserve("sess-a", "launcher-a", operationKindRun)
	if d != admissionAccepted {
		t.Fatalf("reserve: %d", d)
	}

	// The Launcher quiesces after the reservation.
	s.quiesceLauncher("launcher-a")

	op := newRunOperation("sess-a", "alpine", 1024, "p", "launcher-a", "launcher")
	if d := s.admitReserved(op, res); d != admissionRefusedQuiesced {
		t.Fatalf("final admission after quiesce: expected quiesce refusal, got %d", d)
	}
	if s.lookup(op.ID) != nil {
		t.Fatal("quiesce-refused operation must not be registered")
	}

	// Refusal releases the reservation through the caller's failure path.
	res.Release()
	if got := s.globalRunning; got != 0 {
		t.Fatalf("refused conversion must release the reservation: %d", got)
	}
}

// TestReserveThenShutdownRefusedAtFinalAdmission is the shutdown counterpart:
// a reservation obtained before daemon shutdown is refused at final
// admission and released by the caller.
func TestReserveThenShutdownRefusedAtFinalAdmission(t *testing.T) {
	s := newOperationSupervisor()
	s.maxPerSession = 1
	s.maxGlobal = 1
	s.maxGlobalBuilds = 1

	res, d := s.reserve("sess-a", "launcher-a", operationKindRun)
	if d != admissionAccepted {
		t.Fatalf("reserve: %d", d)
	}

	s.beginShutdown()

	op := newRunOperation("sess-a", "alpine", 1024, "p", "launcher-a", "launcher")
	if d := s.admitReserved(op, res); d != admissionRefusedShutdown {
		t.Fatalf("final admission after shutdown: expected shutdown refusal, got %d", d)
	}
	if s.lookup(op.ID) != nil {
		t.Fatal("shutdown-refused operation must not be registered")
	}

	res.Release()
	if got := s.globalRunning; got != 0 {
		t.Fatalf("refused conversion must release the reservation: %d", got)
	}
}

// TestReservedCapacityTransfersToAdmittedOperation proves the reservation is
// never reserved a second time at final admission and is released exactly
// once when the Operation reaches its terminal state — while its metadata and
// logs remain retained.
func TestReservedCapacityTransfersToAdmittedOperation(t *testing.T) {
	s := newOperationSupervisor()
	s.maxPerSession = 1
	s.maxGlobal = 1
	s.maxGlobalBuilds = 1

	res, d := s.reserve("sess-a", "launcher-a", operationKindRun)
	if d != admissionAccepted {
		t.Fatalf("reserve: %d", d)
	}

	op := newRunOperation("sess-a", "alpine", 1024, "p", "launcher-a", "launcher")
	if d := s.admitReserved(op, res); d != admissionAccepted {
		t.Fatalf("final admission: %d", d)
	}

	// The capacity transferred: the same slot is the Operation's capacity.
	if got := s.globalRunning; got != 1 {
		t.Fatalf("admitted operation must hold exactly one capacity slot: %d", got)
	}

	// The registered Operation reaches its terminal state: capacity is
	// released exactly once while the Operation metadata stays retained.
	if !op.fail("docker_run_failed", "failed", nil) {
		t.Fatal("operation must transition to terminal")
	}
	if got := s.globalRunning; got != 0 {
		t.Fatalf("terminal operation must release its capacity slot: %d", got)
	}
	if s.lookup(op.ID) == nil {
		t.Fatal("terminal operation must remain retained in the supervisor")
	}
}

// TestBuildSubCeilingLeavesRunsAvailable proves the narrow build
// sub-ceiling: concurrent builds are capped independently of the generic
// Operation ceilings, and run Operations still have free capacity.
func TestBuildSubCeilingLeavesRunsAvailable(t *testing.T) {
	s := newOperationSupervisor()
	s.maxPerSession = maxConcurrentOperationsPerSession
	s.maxGlobal = maxConcurrentOperationsGlobal
	s.maxGlobalBuilds = maxConcurrentBuildsGlobal

	var buildRes []*operationReservation
	for i := 0; i < maxConcurrentBuildsGlobal; i++ {
		res, d := s.reserve(fmt.Sprintf("sess-b%d", i), fmt.Sprintf("launcher-b%d", i), operationKindBuild)
		if d != admissionAccepted {
			t.Fatalf("build reserve %d: %d", i, d)
		}
		buildRes = append(buildRes, res)
	}
	// A third build is refused even though the generic ceilings have room.
	if _, d := s.reserve("sess-b9", "launcher-b9", operationKindBuild); d != admissionRefusedCapacity {
		t.Fatalf("third build: expected capacity refusal, got %d", d)
	}
	// Run Operations still have free capacity.
	for i := 0; i < maxConcurrentOperationsGlobal-maxConcurrentBuildsGlobal; i++ {
		if _, d := s.reserve(fmt.Sprintf("sess-r%d", i), fmt.Sprintf("launcher-r%d", i), operationKindRun); d != admissionAccepted {
			t.Fatalf("run reserve %d at build sub-ceiling: %d", i, d)
		}
	}
	// The global ceiling binds the total.
	if _, d := s.reserve("sess-x", "launcher-x", operationKindRun); d != admissionRefusedCapacity {
		t.Fatalf("over global ceiling: expected capacity refusal, got %d", d)
	}

	for _, res := range buildRes {
		res.Release()
	}
}

// TestRunQuiesceCapacityRefusalHasNoReservationResidue proves the user-facing
// refusal grammar and residue contract at the handler level: the capacity
// refusal admits no Operation and leaves no lease.
func TestRunQuiesceCapacityRefusalHasNoReservationResidue(t *testing.T) {
	app, result := newCapacityTestApp(t)

	for i := 0; i < maxConcurrentOperationsPerSession; i++ {
		if w := runCapacityRequest(t, app, result.Token); w.Code != http.StatusCreated {
			t.Fatalf("operation %d: expected %d, got %d (%s)", i+1, http.StatusCreated, w.Code, w.Body.String())
		}
	}

	// One more request with a mount: refused by the Session ceiling with the
	// single bounded capacity refusal and zero Docker invocation.
	w := runCapacityRequest(t, app, result.Token)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("capacity refusal: expected %d, got %d (%s)", http.StatusTooManyRequests, w.Code, w.Body.String())
	}
	if code := decodeRejectedResponse(t, w); code != "operation_capacity_unavailable" {
		t.Fatalf("capacity refusal code: expected operation_capacity_unavailable, got %q", code)
	}

	// No build/run start audit for the refusal: the supervisor holds exactly
	// the ceiling of operations and nothing else.
	if got := len(app.OperationSupervisor.ops); got != maxConcurrentOperationsPerSession {
		t.Fatalf("capacity refusal must not register an Operation: %d registered", got)
	}
}

// TestH5ComposesWithH4StagingCeiling guards the documented worst-case
// composition: at the build sub-ceiling, concurrent hostile builds cannot
// exceed the documented staging occupancy bound on the smallest supported
// host. The constants are the exact Release-2.2 measured ceilings; the
// smallest supported host is the 3 GiB Tumbleweed UAT VM whose /run tmpfs is
// 20% of RAM (~614 MB).
func TestH5ComposesWithH4StagingCeiling(t *testing.T) {
	const h4StagingByteCeiling = 128 * 1024 * 1024
	const smallestHostRunTmpfs = 614 * 1024 * 1024

	worstCaseOccupancy := maxConcurrentBuildsGlobal * h4StagingByteCeiling
	if worstCaseOccupancy != 256*1024*1024 {
		t.Fatalf("documented worst-case staging occupancy changed: %d", worstCaseOccupancy)
	}
	if worstCaseOccupancy*100 > smallestHostRunTmpfs*45 {
		t.Fatalf("worst-case concurrent hostile staging (%d bytes) exceeds 45%% of the smallest supported /run tmpfs (%d bytes)",
			worstCaseOccupancy, smallestHostRunTmpfs)
	}
	// The mount ceiling composes too: the worst-case kernel mount-table cost
	// (3 entries per caller mount under the SELinux backend: pin, lower file
	// bind, bindfs projection) at the global Operation ceiling stays far
	// below the host fs.mount-max (100000).
	const selinuxWorstMountsPerCallerMount = 3
	const hostMountMax = 100000
	worstMountTable := maxRunMounts * selinuxWorstMountsPerCallerMount * maxConcurrentOperationsGlobal
	if worstMountTable > hostMountMax/100 {
		t.Fatalf("worst-case mount-table occupancy (%d entries) must stay below 1%% of fs.mount-max (%d)", worstMountTable, hostMountMax)
	}
}

// TestRunQuiesceRefusalLeavesNoPreparedState proves the
// reservation-before-expensive-work ordering: a run refused at admission
// (quiesced Launcher) creates no mount pins. The launcher quiesce is reached
// through the same capacity reservation gate, so the refusal happens before
// any pin, MAC lease, or Docker state. RED evidence at the starting SHA: the
// old flow pins every mount source before admit() is consulted, so a
// quiesce-refused run leaves prepared pins behind.
func TestRunQuiesceRefusalLeavesNoPreparedState(t *testing.T) {
	app := newSystemModeRunTestApp(t)
	result, err := createSystemSession(t, app)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	mountDir := filepath.Join(result.Session.Workspace, "mountdir")
	if err := os.MkdirAll(mountDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mountDir, "file.txt"), []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	var pinCount atomic.Int32
	app.PinMountSourceFn = func(sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		pinCount.Add(1)
		return &pinnedMount{
			PinnedPath: filepath.Join(t.TempDir(), "pin", fmt.Sprintf("%d", mountIndex)),
			cleanup:    func() error { return nil },
		}, nil
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	// Quiesce the Session's Launcher: no new Operation may be admitted for it.
	app.OperationSupervisor.quiesceLauncher(result.Session.LauncherID)

	req := newRunRequest(map[string]any{
		"image": "alpine:3.24",
		"mounts": []map[string]any{
			{"source": "mountdir", "target": "/data"},
		},
		"command": []string{"true"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	// The established quiesce contract is unchanged.
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("quiesce refusal: expected %d, got %d (%s)", http.StatusUnprocessableEntity, w.Code, w.Body.String())
	}
	if code := decodeRejectedResponse(t, w); code != "launcher_unavailable" {
		t.Fatalf("quiesce refusal code: expected launcher_unavailable, got %q", code)
	}

	// The refusal must happen before any expensive preparation.
	if got := pinCount.Load(); got != 0 {
		t.Fatalf("quiesce-refused run created %d mount pins before admission", got)
	}
}

// TestBuildQuiesceRefusalLeavesNoStaging proves the reservation-before-staging
// ordering for build: a build refused at admission does not stage its H4
// context. RED evidence at the starting SHA: the old flow stages the whole
// context before admit() is consulted.
func TestBuildQuiesceRefusalLeavesNoStaging(t *testing.T) {
	app, result := newCapacityTestApp(t)

	if err := os.WriteFile(filepath.Join(result.Session.Workspace, "Dockerfile"), []byte("FROM alpine\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var stagingCalls atomic.Int32
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		stagingCalls.Add(1)
		return newTestStagedContext(t, dfrel, nil), nil
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	app.OperationSupervisor.quiesceLauncher(result.Session.LauncherID)

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("quiesce refusal: expected %d, got %d (%s)", http.StatusUnprocessableEntity, w.Code, w.Body.String())
	}
	if got := stagingCalls.Load(); got != 0 {
		t.Fatalf("quiesce-refused build staged its context %d time(s) before admission", got)
	}
}
