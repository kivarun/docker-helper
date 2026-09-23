package main

// P3-B2 driver proofs for the frozen build stage sequence
// START -> buildctl -> STOP -> load -> verify -> tag commit, driven through
// the production build driver (handleBuild -> buildDriver.run) with the
// existing fake manager endpoint and recording child seam. All
// synchronization uses explicit handshakes (ready-marker files written by
// real child processes and barrier channels in the fake manager), never
// timing-dependent sleeps: waits bounded-poll a deterministic condition
// (the same idiom as the existing waitProcessReady harness).

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// backendChildRunner is the recording child seam with per-invocation
// behavior control: every STARTED child touches a ready file (proving the
// real child process ran, not merely that a command was constructed); the
// buildctl child optionally blocks on a release file and/or exits with a
// fixed nonzero code, and the import stages (load, inspect, rmi) carry
// their own scripted failure/termination behavior for the C1 failure-path
// proofs (the tag child is only reached on the success path).
type backendChildRunner struct {
	app      *App
	calls    *recordedCalls
	readyDir string

	mu               sync.Mutex
	buildctlBlocks   bool
	buildctlExitCode int
	loadBlocks       bool
	loadExitCode     int
	inspectBlocks    bool
	inspectExitCode  int
	rmiExitCode      int
	tagBlocks        bool

	// inspectReleasePath is the blocked verification child's release file
	// (set once by setInspectBlocks).
	inspectReleasePath string
}

func newBackendChildRunner(t *testing.T, app *App, calls *recordedCalls) *backendChildRunner {
	t.Helper()
	r := &backendChildRunner{app: app, calls: calls, readyDir: t.TempDir()}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		idx := calls.count()
		ready := r.readyPath(idx)
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", r.childScript(name, args, ready))
		calls.record(name, args, cmd)
		return cmd
	}
	return r
}

// childScript returns the shell script of one recorded child: every child
// touches its ready marker (the real-start proof); buildctl and the import
// stages add their scripted blocking/failure behavior on top.
func (r *backendChildRunner) childScript(name string, args []string, ready string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	blocked := "touch " + ready + "; while :; do sleep 0.05; done"
	failed := func(code int) string {
		return "touch " + ready + "; exit " + strconv.Itoa(code)
	}
	switch {
	case strings.HasSuffix(name, "buildctl"):
		switch {
		case r.buildctlBlocks:
			return blocked
		case r.buildctlExitCode != 0:
			return failed(r.buildctlExitCode)
		}
	case hasArgvWord(args, "load"):
		switch {
		case r.loadBlocks:
			return blocked
		case r.loadExitCode != 0:
			return failed(r.loadExitCode)
		}
	case isVerificationArgv(args):
		switch {
		case r.inspectBlocks:
			// Blocked verification: real child, ready marker, then hold
			// until its release path exists (the test's deterministic
			// mid-test release; the binary-liveness guard bounds a
			// never-released child). The child then exits 0, so the
			// driver reaches the commit stage and the latch refuses it.
			return "touch " + ready + "; while [ ! -e " + r.inspectReleasePath + " ] && [ -d /proc/" + strconv.Itoa(os.Getpid()) + " ]; do sleep 0.05; done"
		case r.inspectExitCode != 0:
			return failed(r.inspectExitCode)
		}
	case hasArgvWord(args, "tag"):
		if r.tagBlocks {
			// Blocked commit child: real child killed by the termination
			// path (no trap: the commit outcome must be a killed child).
			return "touch " + ready + "; while :; do sleep 0.05; done"
		}
	case hasArgvWord(args, "rmi"):
		if r.rmiExitCode != 0 {
			return failed(r.rmiExitCode)
		}
	}
	return "touch " + ready
}

func (r *backendChildRunner) setBuildctlBlocks(blocks bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buildctlBlocks = blocks
}

func (r *backendChildRunner) setBuildctlExitCode(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buildctlExitCode = code
}

func (r *backendChildRunner) setLoadBlocks(blocks bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loadBlocks = blocks
}

func (r *backendChildRunner) setLoadExitCode(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loadExitCode = code
}

func (r *backendChildRunner) setInspectExitCode(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inspectExitCode = code
}

func (r *backendChildRunner) setInspectBlocks(t *testing.T, blocks bool) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inspectBlocks = blocks
	if blocks && r.inspectReleasePath == "" {
		r.inspectReleasePath = filepath.Join(r.readyDir, "verify.release")
	}
	release := r.inspectReleasePath
	if blocks {
		// Release any still-blocked verification child on cleanup; the
		// binary-liveness guard in the script bounds a missed write.
		t.Cleanup(func() { _ = os.WriteFile(release, []byte("release"), 0o644) })
	}
	return release
}

func (r *backendChildRunner) setTagBlocks(blocks bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tagBlocks = blocks
}

func (r *backendChildRunner) setRmiExitCode(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rmiExitCode = code
}

func (r *backendChildRunner) readyPath(idx int) string {
	return filepath.Join(r.readyDir, "child."+strconv.Itoa(idx)+".ready")
}

// waitChildStartedCount waits until at least wantCount children were
// constructed AND the newest one's real process touched its ready file —
// distinguishing command construction from actual child start.
func (r *backendChildRunner) waitChildStartedCount(t *testing.T, wantCount int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if r.calls.count() >= wantCount {
			if _, err := os.Stat(r.readyPath(r.calls.count() - 1)); err == nil {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d started children, have %d", wantCount, r.calls.count())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// childName returns the recorded child name of invocation i.
func (r *recordedCalls) childName(i int) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i >= len(r.names) {
		return ""
	}
	return r.names[i]
}

// lastRecordedName returns the name of the most recent recorded child (or
// "" when none).
func lastRecordedName(calls *recordedCalls) string {
	i := calls.count() - 1
	if i < 0 {
		return ""
	}
	return calls.childName(i)
}

// stopBarrierState is the fake manager STOP scripting: a barrier for
// observing that a STOP request reached the manager and optional
// withholding/releasing of the STOP response.
type stopBarrierState struct {
	mu sync.Mutex

	// stopReached is closed exactly once on the first STOP request that
	// reaches the manager.
	stopReached chan struct{}
	stopOnce    sync.Once

	// gate, when non-nil, holds every STOP response until it is closed.
	gate chan struct{}

	// pendingReply is the scripted reply text released after the gate.
	pendingReply string
}

func newStopBarrier() *stopBarrierState {
	return &stopBarrierState{stopReached: make(chan struct{})}
}

// gateStopUntil withholds STOP responses until the returned gate channel is
// closed; after the gate, the manager replies with reply.
func (s *stopBarrierState) gateStopUntil(reply string) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gate = make(chan struct{})
	s.pendingReply = reply
	return s.gate
}

// recordStop implements the fake manager behavior hook: START replies OK
// (default fixture behavior), STOP is observed and optionally gated.
func (s *stopBarrierState) recordStop(command, _ string, reply func(string)) {
	if command == builderManagerCmdStart {
		reply(builderManagerRespOK)
		return
	}
	if command != builderManagerCmdStop {
		return
	}
	s.mu.Lock()
	gate := s.gate
	replyText := s.pendingReply
	s.mu.Unlock()
	s.stopOnce.Do(func() { close(s.stopReached) })
	if gate != nil {
		<-gate
	}
	reply(replyText)
}

// waitForStopReached proves a STOP request reached the fake manager.
func waitForStopReached(t *testing.T, barrier *stopBarrierState) {
	t.Helper()
	select {
	case <-barrier.stopReached:
	case <-time.After(10 * time.Second):
		t.Fatal("STOP never reached the fake manager")
	}
}

// stopAttemptCounter counts STOP requests observed by the fake manager
// (a counting barrier, not timing).
type stopAttemptCounter struct {
	mu    sync.Mutex
	count int
}

func (c *stopAttemptCounter) bump() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	return c.count
}

func (c *stopAttemptCounter) value() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// isVerificationArgv reports whether the argv is docker image inspect (the
// internal-tag verification stage).
func isVerificationArgv(args []string) bool {
	for i, arg := range args {
		if arg == "image" && i+1 < len(args) && args[i+1] == "inspect" {
			return true
		}
	}
	return false
}

// importStageSequence classifies the recorded children by their post-STOP
// image-handoff stage labels, in construction order: load, inspect, tag,
// rmi. buildctl children are skipped.
func importStageSequence(calls *recordedCalls) []string {
	var out []string
	n := calls.count()
	for i := 0; i < n; i++ {
		argv := calls.argv(i)
		switch {
		case hasArgvWord(argv, "load"):
			out = append(out, "load")
		case isVerificationArgv(argv):
			out = append(out, "inspect")
		case hasArgvWord(argv, "tag"):
			out = append(out, "tag")
		case hasArgvWord(argv, "rmi"):
			out = append(out, "rmi")
		}
	}
	return out
}

// hasArgvWord reports whether any argv element equals the exact word.
func hasArgvWord(args []string, word string) bool {
	for _, arg := range args {
		if arg == word {
			return true
		}
	}
	return false
}

// startedImportStages returns the image-handoff stages (load, inspect, tag,
// rmi) whose child process ACTUALLY started — proven by the child's own
// ready-marker file, never by command construction alone — in construction
// order. A constructed command whose child never started (refused admission)
// is excluded.
func (r *backendChildRunner) startedImportStages() []string {
	var out []string
	n := r.calls.count()
	for i := 0; i < n; i++ {
		if _, err := os.Stat(r.readyPath(i)); err != nil {
			continue // constructed but the child never started
		}
		argv := r.calls.argv(i)
		switch {
		case hasArgvWord(argv, "load"):
			out = append(out, "load")
		case isVerificationArgv(argv):
			out = append(out, "inspect")
		case hasArgvWord(argv, "tag"):
			out = append(out, "tag")
		case hasArgvWord(argv, "rmi"):
			out = append(out, "rmi")
		}
	}
	return out
}

// hasStartedImportChild reports whether any load/inspect/tag child process
// actually started (rmi is bounded cleanup, not the image handoff).
func (r *backendChildRunner) hasStartedImportChild() bool {
	for _, stage := range r.startedImportStages() {
		if stage != "rmi" {
			return true
		}
	}
	return false
}

// constructIndexOfImportStage returns the construction index of the first
// recorded child of the given import stage, or -1.
func (r *backendChildRunner) constructIndexOfImportStage(stage string) int {
	n := r.calls.count()
	for i := 0; i < n; i++ {
		argv := r.calls.argv(i)
		switch stage {
		case "load":
			if hasArgvWord(argv, "load") {
				return i
			}
		case "inspect":
			if isVerificationArgv(argv) {
				return i
			}
		case "tag":
			if hasArgvWord(argv, "tag") {
				return i
			}
		case "rmi":
			if hasArgvWord(argv, "rmi") {
				return i
			}
		}
	}
	return -1
}

// childStarted reports whether the recorded child i actually started (its
// ready-marker file exists — written by the real child process).
func (r *backendChildRunner) childStarted(i int) bool {
	_, err := os.Stat(r.readyPath(i))
	return err == nil
}

// assertStageDiagnostic proves the internal stage diagnostic reached the
// operational log (the bounded internal diagnostic; never a public API
// field). It requires setupTestLogging to have run before the build.
func assertStageDiagnostic(t *testing.T, opBuf *bytes.Buffer, stage string) {
	t.Helper()
	out := opBuf.String()
	if !strings.Contains(out, "build stage failed") || !strings.Contains(out, `"stage":"`+stage+`"`) {
		t.Errorf("operational log missing internal %q stage diagnostic:\n%s", stage, out)
	}
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// assertNoImportStartsWhile polls a short window while the condition holds
// and fails when a load / inspect / tag child process STARTS (ready-marker
// proof) — the synthetic proof that an unresolved STOP parks the single
// driver goroutine before the image handoff.
func assertNoImportStartsWhile(t *testing.T, runner *backendChildRunner, condition func() bool, description string) {
	t.Helper()
	deadline := time.Now().Add(25 * time.Millisecond)
	for time.Now().Before(deadline) {
		if runner.hasStartedImportChild() {
			t.Fatalf("%s: image handoff child process started:\n%s", description, runner.calls.all())
		}
		if !condition() {
			return
		}
		time.Sleep(1 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// §2: successful path and STOP ordering.
// ---------------------------------------------------------------------------

// TestBuildDriverStopsBeforeImportOrdering proves the frozen stage order on
// the successful path through the production driver: START succeeded and
// buildctl exited successfully; the STOP request REACHED the manager before
// any image-handoff child exists (while STOP is unresolved, the driver is
// parked in the gated round-trip); after STOP convergence, the driver
// proceeds load -> internal-tag verification -> tag commit -> internal-tag
// cleanup in order, every handoff child constructed after STOP arrival.
func TestBuildDriverStopsBeforeImportOrdering(t *testing.T) {
	app, _, result, manager, calls := setupBuildBackendTest(t)
	runner := newBackendChildRunner(t, app, calls)

	// Synthetic ordering proof: the manager accepts STOP but withholds its
	// response until the test releases the gate.
	barrier := newStopBarrier()
	gate := barrier.gateStopUntil(builderManagerRespOK)
	var gateOnce sync.Once
	t.Cleanup(func() { gateOnce.Do(func() { close(gate) }) })
	manager.mu.Lock()
	manager.behavior = barrier.recordStop
	manager.mu.Unlock()

	op := startBackendBuild(t, app, result.Token, nil)

	// The buildctl child ran (command construction AND real child start).
	runner.waitChildStartedCount(t, 1)
	if got := lastRecordedName(calls); !strings.HasSuffix(got, "buildctl") {
		t.Fatalf("first child = %q, want buildctl", got)
	}

	// While STOP is unresolved: no image handoff child may exist.
	assertNoImportStartsWhile(t, runner, func() bool {
		select {
		case <-gate:
			return false
		default:
			return true
		}
	}, "STOP unresolved")

	// STOP reached the manager; the reply is withheld.
	waitForStopReached(t, barrier)
	assertNoImportStartsWhile(t, runner, func() bool {
		select {
		case <-gate:
			return false
		default:
			return true
		}
	}, "STOP reached, reply withheld")
	callsAtStop := calls.count()

	// STOP reply confirms convergence: the image handoff proceeds.
	gateOnce.Do(func() { close(gate) })

	select {
	case <-op.done:
	case <-time.After(10 * time.Second):
		t.Fatal("operation did not complete after STOP reply")
	}

	// Ordering after the STOP reply: load, internal-tag verification, tag
	// commit, internal-tag cleanup.
	if got, want := importStageSequence(calls), []string{"load", "inspect", "tag", "rmi"}; !equalStrings(got, want) {
		t.Fatalf("stage order after STOP reply = %v, want %v\nall children:\n%s", got, want, calls.all())
	}
	// Every handoff child was constructed after the STOP request arrived.
	for i := 0; i < calls.count(); i++ {
		argv := calls.argv(i)
		isHandoff := hasArgvWord(argv, "load") || hasArgvWord(argv, "tag") || isVerificationArgv(argv) || hasArgvWord(argv, "rmi")
		if isHandoff && i < callsAtStop {
			t.Fatalf("handoff child %d constructed before the STOP request arrived", i)
		}
	}

	// START once; STOP exactly once for this operation.
	if got := manager.startCount(); got != 1 {
		t.Errorf("START count = %d, want 1", got)
	}
	stopIDs := manager.stopIDs()
	if len(stopIDs) != 1 || stopIDs[0] != op.ID {
		t.Errorf("STOP ids = %v, want exactly [%s]", stopIDs, op.ID)
	}

	op.mu.Lock()
	state, rc := op.State, derefString(op.ResultCode)
	op.mu.Unlock()
	if state != operationSucceeded {
		t.Errorf("state = %v, want succeeded", state)
	}
	if rc != "succeeded" {
		t.Errorf("result_code = %q, want succeeded", rc)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// §3: START failure.
// ---------------------------------------------------------------------------

// TestBuildDriverStartErrorNoStopNoImport proves the START-failure contract
// through the driver: a well-formed START ERR is a definitive refusal (the
// manager answered; nothing is ambiguous), so no convergence STOP runs, no
// child process is ever started, and the operation fails
// docker_build_failed with the internal START diagnostic.
func TestBuildDriverStartErrorNoStopNoImport(t *testing.T) {
	_, opBuf := setupTestLogging(t)
	app, _, result, manager, calls := setupBuildBackendTest(t)
	newBackendChildRunner(t, app, calls)
	manager.setStartResp(builderManagerRespInternal)

	op := startBackendBuild(t, app, result.Token, nil)
	select {
	case <-op.done:
	case <-time.After(10 * time.Second):
		t.Fatal("operation did not complete after START ERR")
	}

	// No child process at all (no buildctl, no STOP round-trip child, no
	// import children).
	if got := calls.count(); got != 0 {
		t.Errorf("children started = %d, want 0:\n%s", got, calls.all())
	}
	// No STOP: the START outcome was definitive, not ambiguous.
	if got := manager.stopCount(); got != 0 {
		t.Errorf("STOP count = %d, want 0 (definitive ERR needs no convergence)", got)
	}

	op.mu.Lock()
	state, rc := op.State, derefString(op.ResultCode)
	op.mu.Unlock()
	if state != operationFailed {
		t.Errorf("state = %v, want failed", state)
	}
	if rc != "docker_build_failed" {
		t.Errorf("result_code = %q, want docker_build_failed", rc)
	}

	assertStageDiagnostic(t, opBuf, "builder_start")
}

// ---------------------------------------------------------------------------
// §3: STOP failure and ambiguity.
// ---------------------------------------------------------------------------

// TestBuildDriverStopErrorPreventsImport proves the fail-closed STOP
// contract: a well-formed STOP ERR means the STOP is NOT proven converged —
// no image handoff child may run, the operation fails docker_build_failed,
// and the internal diagnostic records the stage. The single attempt is the
// P2 contract; the driver adds no retries (exactly one STOP was seen).
func TestBuildDriverStopErrorPreventsImport(t *testing.T) {
	_, opBuf := setupTestLogging(t)
	app, _, result, manager, calls := setupBuildBackendTest(t)
	runner := newBackendChildRunner(t, app, calls)
	manager.setStopResp(builderManagerRespInternal)

	op := startBackendBuild(t, app, result.Token, nil)
	select {
	case <-op.done:
	case <-time.After(10 * time.Second):
		t.Fatal("operation did not complete after STOP ERR")
	}

	// No image handoff child after an unproven STOP; buildctl ran.
	if runner.hasStartedImportChild() {
		t.Fatalf("image handoff child started after STOP ERR:\n%s", runner.calls.all())
	}
	if calls.buildctlIndex() < 0 {
		t.Error("buildctl child did not run")
	}
	// Exactly one STOP attempt: a well-formed ERR is definitive, so the P2
	// client does not retry and the driver never retries.
	if got := manager.stopCount(); got != 1 {
		t.Errorf("STOP count = %d, want exactly 1", got)
	}

	op.mu.Lock()
	state, rc := op.State, derefString(op.ResultCode)
	op.mu.Unlock()
	if state != operationFailed {
		t.Errorf("state = %v, want failed", state)
	}
	if rc != "docker_build_failed" {
		t.Errorf("result_code = %q, want docker_build_failed", rc)
	}

	assertStageDiagnostic(t, opBuf, "builder_stop")
}

// TestBuildDriverStopLostReplyThenOKAbsent proves the lost-first-STOP-reply
// contract through the driver: the first STOP attempt is unknowable (the
// connection closes without a reply), the fresh-context retry answers
// `OK absent`, and the driver then proceeds to the image handoff and
// commits the requested image.
func TestBuildDriverStopLostReplyThenOKAbsent(t *testing.T) {
	app, _, result, manager, calls := setupBuildBackendTest(t)
	newBackendChildRunner(t, app, calls)

	attempts := &stopAttemptCounter{}
	manager.mu.Lock()
	manager.behavior = func(command, _ string, reply func(string)) {
		if command == builderManagerCmdStart {
			reply(builderManagerRespOK)
			return
		}
		if command != builderManagerCmdStop {
			return
		}
		if attempts.bump() == 1 {
			// First attempt: unknowable — the reply is lost entirely.
			return
		}
		reply(builderManagerRespOKAbsent)
	}
	manager.mu.Unlock()

	op := startBackendBuild(t, app, result.Token, nil)
	select {
	case <-op.done:
	case <-time.After(10 * time.Second):
		t.Fatal("operation did not complete after lost-then-OK-absent STOP")
	}

	if got := attempts.value(); got != 2 {
		t.Errorf("STOP attempts = %d, want exactly 2", got)
	}

	// Convergence: the image handoff ran and the build committed.
	if got, want := importStageSequence(calls), []string{"load", "inspect", "tag", "rmi"}; !equalStrings(got, want) {
		t.Errorf("stage order = %v, want %v\nall children:\n%s", got, want, calls.all())
	}
	op.mu.Lock()
	state, rc := op.State, derefString(op.ResultCode)
	op.mu.Unlock()
	if state != operationSucceeded {
		t.Errorf("state = %v, want succeeded", state)
	}
	if rc != "succeeded" {
		t.Errorf("result_code = %q, want succeeded", rc)
	}
}

// TestBuildDriverStopTwiceUnknowablePreventsImport proves the
// both-attempts-unknowable STOP contract through the driver: exactly two
// STOP attempts, no image handoff child, failed operation with
// docker_build_failed and the internal builder_stop diagnostic.
func TestBuildDriverStopTwiceUnknowablePreventsImport(t *testing.T) {
	_, opBuf := setupTestLogging(t)
	app, _, result, manager, calls := setupBuildBackendTest(t)
	runner := newBackendChildRunner(t, app, calls)

	attempts := &stopAttemptCounter{}
	manager.mu.Lock()
	manager.behavior = func(command, _ string, reply func(string)) {
		if command == builderManagerCmdStart {
			reply(builderManagerRespOK)
			return
		}
		if command != builderManagerCmdStop {
			return
		}
		attempts.bump()
		// Both attempts unknowable: no reply at all.
		_ = reply
	}
	manager.mu.Unlock()

	op := startBackendBuild(t, app, result.Token, nil)
	select {
	case <-op.done:
	case <-time.After(10 * time.Second):
		t.Fatal("operation did not complete after twice-unknowable STOP")
	}

	if got := attempts.value(); got != 2 {
		t.Errorf("STOP attempts = %d, want exactly 2", got)
	}
	if runner.hasStartedImportChild() {
		t.Fatalf("image handoff child started after twice-unknowable STOP:\n%s", runner.calls.all())
	}
	op.mu.Lock()
	state, rc := op.State, derefString(op.ResultCode)
	op.mu.Unlock()
	if state != operationFailed {
		t.Errorf("state = %v, want failed", state)
	}
	if rc != "docker_build_failed" {
		t.Errorf("result_code = %q, want docker_build_failed", rc)
	}
	assertStageDiagnostic(t, opBuf, "builder_stop")
}

// ---------------------------------------------------------------------------
// §4: buildctl failure and termination.
// ---------------------------------------------------------------------------

// TestBuildDriverBuildctlNonzeroStopsAndFails proves: a nonzero buildctl
// exit fails the build, the mandatory STOP still runs afterwards (fresh
// bounded context), no image handoff child exists, the child exit code is
// preserved, and only the generic build.start/build.finish audit events are
// emitted (no per-stage public audit events).
func TestBuildDriverBuildctlNonzeroStopsAndFails(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)
	app, _, result, manager, calls := setupBuildBackendTest(t)
	runner := newBackendChildRunner(t, app, calls)
	runner.setBuildctlExitCode(42)

	op := startBackendBuild(t, app, result.Token, nil)
	select {
	case <-op.done:
	case <-time.After(10 * time.Second):
		t.Fatal("operation did not complete after nonzero buildctl")
	}

	// buildctl only: STOP cleanup ran (recorded by the manager) but no
	// image handoff child exists.
	if calls.count() != 1 || calls.buildctlIndex() != 0 {
		t.Fatalf("children = %d, want exactly the one buildctl child:\n%s", calls.count(), calls.all())
	}
	if got := manager.stopCount(); got != 1 {
		t.Errorf("STOP count = %d, want 1 (mandatory cleanup after buildctl failure)", got)
	}

	op.mu.Lock()
	state, rc, exitCode := op.State, derefString(op.ResultCode), op.ExitCode
	op.mu.Unlock()
	if state != operationFailed {
		t.Errorf("state = %v, want failed", state)
	}
	if rc != "docker_build_failed" {
		t.Errorf("result_code = %q, want docker_build_failed", rc)
	}
	if exitCode == nil || *exitCode != 42 {
		t.Errorf("exit_code = %v, want 42", exitCode)
	}

	assertStageDiagnostic(t, opBuf, "buildctl")

	// Audit: only the generic build.start/build.finish events.
	for _, rec := range filterBySession(parseAuditRecords(auditBuf), result.Session.ID) {
		if rec.Event != "build.start" && rec.Event != "build.finish" {
			t.Errorf("unexpected public audit event %q (no per-stage events allowed)", rec.Event)
		}
	}
}

// TestBuildDriverCancelDuringBuildctlMandatoryStop proves the termination
// path through the production driver: explicit cancel during buildctl
// terminates the child, the mandatory STOP runs on a fresh bounded context,
// no image handoff child starts, and the result classification is
// cancelled.
func TestBuildDriverCancelDuringBuildctlMandatoryStop(t *testing.T) {
	app, supervisor, result, manager, calls := setupBuildBackendTest(t)
	runner := newBackendChildRunner(t, app, calls)
	runner.setBuildctlBlocks(true)

	op := startBackendBuild(t, app, result.Token, nil)
	runner.waitChildStartedCount(t, 1)

	if err := supervisor.cancel(op.ID, nil); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	op.Wait()

	// buildctl only: STOP cleanup ran, no image handoff child process
	// started (a constructed-but-refused import command proves the latch).
	if calls.count() != 1 || calls.buildctlIndex() != 0 {
		t.Fatalf("children = %d, want exactly the one buildctl child:\n%s", calls.count(), calls.all())
	}
	if got := manager.stopCount(); got != 1 {
		t.Errorf("STOP count = %d, want 1 (mandatory STOP after cancelled buildctl)", got)
	}
	stopIDs := manager.stopIDs()
	if len(stopIDs) != 1 || stopIDs[0] != op.ID {
		t.Errorf("STOP ids = %v, want [%s]", stopIDs, op.ID)
	}

	op.mu.Lock()
	state, rc := op.State, derefString(op.ResultCode)
	op.mu.Unlock()
	if state != operationFailed {
		t.Errorf("state = %v, want failed", state)
	}
	if rc != resultCancelled {
		t.Errorf("result_code = %q, want cancelled", rc)
	}
}

// TestBuildDriverShutdownDuringBuildctlMandatoryStop proves the shutdown
// equivalent: shutdown during buildctl invokes the mandatory STOP, prevents
// the image handoff, and keeps the current kind-specific failure
// classification (docker_build_failed; no public shutdown result code).
func TestBuildDriverShutdownDuringBuildctlMandatoryStop(t *testing.T) {
	app, supervisor, result, manager, calls := setupBuildBackendTest(t)
	runner := newBackendChildRunner(t, app, calls)
	runner.setBuildctlBlocks(true)

	op := startBackendBuild(t, app, result.Token, nil)
	runner.waitChildStartedCount(t, 1)

	supervisor.beginShutdown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	supervisor.terminateForShutdown(shutdownCtx, nil)
	cancel()
	op.Wait()

	// buildctl only: STOP cleanup ran, no image handoff child.
	if calls.count() != 1 || calls.buildctlIndex() != 0 {
		t.Fatalf("children = %d, want exactly the one buildctl child:\n%s", calls.count(), calls.all())
	}
	if got := manager.stopCount(); got != 1 {
		t.Errorf("STOP count = %d, want 1 (mandatory STOP after shutdown during buildctl)", got)
	}

	op.mu.Lock()
	state, rc := op.State, derefString(op.ResultCode)
	op.mu.Unlock()
	if state != operationFailed {
		t.Errorf("state = %v, want failed", state)
	}
	if rc != "docker_build_failed" {
		t.Errorf("result_code = %q, want docker_build_failed (shutdown is not a public code)", rc)
	}
}

// TestBuildDriverStopCleanupFailsDuringCancelPreservesClassification proves
// that a STOP cleanup which fails during a cancelled buildctl does not
// downgrade the cancellation: the result stays cancelled, the STOP error is
// recorded in the internal diagnostic, and no image handoff child exists.
func TestBuildDriverStopCleanupFailsDuringCancelPreservesClassification(t *testing.T) {
	_, opBuf := setupTestLogging(t)
	app, supervisor, result, manager, calls := setupBuildBackendTest(t)
	runner := newBackendChildRunner(t, app, calls)
	runner.setBuildctlBlocks(true)
	manager.setStopResp(builderManagerRespInternal)

	op := startBackendBuild(t, app, result.Token, nil)
	runner.waitChildStartedCount(t, 1)

	if err := supervisor.cancel(op.ID, nil); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	op.Wait()

	// buildctl only (no image handoff child; the failed STOP cannot be
	// retried at driver level).
	if calls.count() != 1 || calls.buildctlIndex() != 0 {
		t.Fatalf("children = %d, want exactly the one buildctl child:\n%s", calls.count(), calls.all())
	}
	if got := manager.stopCount(); got != 1 {
		t.Errorf("STOP count = %d, want exactly 1 (definitive ERR, no driver retry)", got)
	}

	op.mu.Lock()
	state, rc := op.State, derefString(op.ResultCode)
	op.mu.Unlock()
	if state != operationFailed {
		t.Errorf("state = %v, want failed", state)
	}
	if rc != resultCancelled {
		t.Errorf("result_code = %q, want cancelled (classification preserved)", rc)
	}

	assertStageDiagnostic(t, opBuf, "builder_stop")
}

// ---------------------------------------------------------------------------
// §5: cancellation while STOP pending.
// ---------------------------------------------------------------------------

// TestBuildDriverCancelWhileStopPendingLatches proves: with the successful
// STOP reply withheld, explicit cancel latches the permanent termination;
// releasing STOP afterwards proves STOP convergence (the manager answers
// OK), the latch prevents every later stage, no load/verification/commit
// process starts (only the best-effort internal-tag rmi cleanup runs), and
// the operation reports cancelled.
func TestBuildDriverCancelWhileStopPendingLatches(t *testing.T) {
	app, supervisor, result, manager, calls := setupBuildBackendTest(t)
	runner := newBackendChildRunner(t, app, calls)

	barrier := newStopBarrier()
	gate := barrier.gateStopUntil(builderManagerRespOK)
	var gateOnce sync.Once
	t.Cleanup(func() { gateOnce.Do(func() { close(gate) }) })
	manager.mu.Lock()
	manager.behavior = barrier.recordStop
	manager.mu.Unlock()

	op := startBackendBuild(t, app, result.Token, nil)
	runner.waitChildStartedCount(t, 1)

	// The STOP request reached the manager; its reply is withheld.
	waitForStopReached(t, barrier)
	assertNoImportStartsWhile(t, runner, func() bool {
		select {
		case <-gate:
			return false
		default:
			return true
		}
	}, "STOP pending")

	// Cancel while STOP is unresolved, then release the gate only after the
	// latch is observed: the handshake keeps the gate closed until the
	// termination is provably latched, so the converged STOP cannot race a
	// not-yet-latched driver.
	if err := supervisor.cancel(op.ID, nil); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		op.mu.Lock()
		latched := op.terminationRequested
		op.mu.Unlock()
		if latched {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("termination latch not observed after cancel")
		}
		time.Sleep(2 * time.Millisecond)
	}
	gateOnce.Do(func() { close(gate) })
	op.Wait()

	// STOP converged (the manager answered after the gate) and the latch
	// prevented every later execution stage.
	if got := manager.stopCount(); got != 1 {
		t.Errorf("STOP count = %d, want 1", got)
	}
	op.mu.Lock()
	latched := op.terminationRequested
	state, rc := op.State, derefString(op.ResultCode)
	op.mu.Unlock()
	if !latched {
		t.Error("termination latch not set")
	}

	// No load / verification / commit child PROCESS may exist after the
	// latch. The constructed load command is the expected latch-refusal
	// artifact (construction is not a start; its child never ran). The
	// best-effort internal-tag rmi cleanup is the only permitted post-latch
	// STARTED child.
	if runner.hasStartedImportChild() {
		t.Fatalf("load/verify/commit child process started after latch:\n%s", runner.calls.all())
	}
	if got, want := runner.startedImportStages(), []string{"rmi"}; !equalStrings(got, want) {
		t.Errorf("started import stages = %v, want only [rmi] (best-effort cleanup)\nall children:\n%s", got, runner.calls.all())
	}
	// Distinguish construction from start: the load command was constructed
	// (the latch refused its admission) but its process never started.
	loadIdx := runner.constructIndexOfImportStage("load")
	if loadIdx < 0 {
		t.Error("driver did not attempt the load stage (expected a constructed load command)")
	} else if runner.childStarted(loadIdx) {
		t.Error("docker load child STARTED after the termination latch (latch must refuse)")
	}

	if state != operationFailed {
		t.Errorf("state = %v, want failed", state)
	}
	if rc != resultCancelled {
		t.Errorf("result_code = %q, want cancelled", rc)
	}
}
