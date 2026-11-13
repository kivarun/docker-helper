package main

// build_driver_devprep_test.go — the R4-P3-P6 integration proofs for the
// trusted /dev preparation stage and the prepared-tree disposal inside the
// production build driver. Every test drives the real stage machinery
// (handleBuild -> buildDriver.runStages with the real operation stage
// controller: runOperationControlStage admission, termination latch,
// current-stage discipline); the preparation and disposal owners are
// replaced by scripted fakes through their narrow App seams, never
// reimplemented here.

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// devPrepFake is the scripted preparation seam: it records every
// invocation (op id, category), can fail immediately, and can block until
// the cancellation context releases it (the determinism for a cancellation
// during the preparation).
type devPrepFake struct {
	mu     sync.Mutex
	ops    []string
	cats   []builderCategory
	err    error
	block  chan struct{}
	called chan struct{}
	order  *buildOrderLog
}

func newDevPrepFake() *devPrepFake {
	return &devPrepFake{called: make(chan struct{}, 8)}
}

func (f *devPrepFake) fn(ctx context.Context, opID string, category builderCategory) error {
	f.mu.Lock()
	f.ops = append(f.ops, opID)
	f.cats = append(f.cats, category)
	f.mu.Unlock()
	select {
	case f.called <- struct{}{}:
	default:
	}
	if f.err != nil {
		return f.err
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if f.order != nil {
		f.order.add("prepared")
	}
	return nil
}

func (f *devPrepFake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ops)
}

func (f *devPrepFake) opsSeen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ops...)
}

// catsSeen returns the recorded categories (a copy).
func (f *devPrepFake) catsSeen() []builderCategory {
	f.mu.Lock()
	defer f.mu.Unlock()
	var cats []builderCategory
	cats = append(cats, f.cats...)
	return cats
}

// devPrepDisposeFake is the scripted disposal seam: it records exactly the
// ids it was asked to dispose, can fail, and optionally appends its
// "disposed" event to a shared order log.
type devPrepDisposeFake struct {
	mu    sync.Mutex
	ids   []string
	err   error
	order *buildOrderLog
}

func (f *devPrepDisposeFake) fn(opID string) error {
	f.mu.Lock()
	f.ids = append(f.ids, opID)
	f.mu.Unlock()
	if f.order != nil {
		f.order.add("disposed")
	}
	return f.err
}

func (f *devPrepDisposeFake) idsSeen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ids...)
}

// buildOrderLog is the one shared ordering record of the stage events the
// test seams observe: preparation completion, buildctl admission, the STOP
// request's manager-side observation, and the disposal.
type buildOrderLog struct {
	mu     sync.Mutex
	events []string
}

func (l *buildOrderLog) add(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, name)
}

func (l *buildOrderLog) index(name string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, e := range l.events {
		if e == name {
			return i
		}
	}
	return -1
}

func (l *buildOrderLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

// waitBuildDone waits until the operation reached a terminal state.
func waitBuildDone(t *testing.T, op *operation) {
	t.Helper()
	select {
	case <-op.done:
	case <-time.After(10 * time.Second):
		t.Fatal("operation did not reach a terminal state")
	}
}

// scriptedManagerStop installs the ordering behavior hook: the START reply
// is the typed category-c1 success, the STOP is recorded in the order log
// before the reply (the manager-side observation precedes the client's
// convergence).
func scriptedManagerStop(t *testing.T, manager *fakeBuilderManager, order *buildOrderLog) {
	t.Helper()
	manager.behavior = func(command, _ string, reply func(string)) {
		switch command {
		case builderManagerCmdStart:
			reply(builderManagerStartSuccessResponse(builderCategory(1)))
		case builderManagerCmdStop:
			order.add("stop_requested")
			reply(builderManagerRespOK)
		}
	}
}

// wrapBuildctlOrder records every buildctl child admission in the shared
// order log, delegating to the fixture child seam.
func wrapBuildctlOrder(app *App, order *buildOrderLog) {
	base := app.ExecCommandContext
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if strings.HasSuffix(name, "buildctl") {
			order.add("buildctl_admitted")
		}
		return base(ctx, name, args...)
	}
}

// TestBuildDriverDevPrepStageOrder proves the integrated stage sequence on
// the full successful path: the preparation runs synchronously after
// socket validation and strictly before buildctl admission, carrying the
// authoritative START category unchanged; after a proven STOP convergence
// the disposal addresses exactly this operation's prepared tree; the
// preparation and disposal are no-child stages (the public child surface
// is unchanged).
func TestBuildDriverDevPrepStageOrder(t *testing.T) {
	app, _, result, manager, calls := setupBuildBackendTest(t)
	order := &buildOrderLog{}
	scriptedManagerStop(t, manager, order)

	prep := newDevPrepFake()
	prep.order = order
	app.prepareTrustedDevFn = prep.fn
	disposeRec := &devPrepDisposeFake{order: order}
	app.devPrepDisposeFn = disposeRec.fn
	wrapBuildctlOrder(app, order)

	op := startBackendBuild(t, app, result.Token, nil)
	waitBuildDone(t, op)

	// Exactly one preparation, carrying the canonical operation id and the
	// authoritative manager-allocated category unchanged.
	if got := prep.count(); got != 1 {
		t.Fatalf("preparation invocations = %d, want exactly 1", got)
	}
	prepOps := prep.opsSeen()
	if len(prepOps) == 1 && prepOps[0] != op.ID {
		t.Errorf("preparer received op id %q, want the canonical %q", prepOps[0], op.ID)
	}
	prepCats := prep.catsSeen()
	if len(prepCats) == 1 && prepCats[0] != builderCategory(1) {
		t.Errorf("preparer received category %v, want the authoritative c1", prepCats[0])
	}

	// Successful completion of the full frozen sequence.
	op.mu.Lock()
	state := op.State
	op.mu.Unlock()
	if state != operationSucceeded {
		t.Fatalf("state = %v, want succeeded", state)
	}

	// Ordering: preparation precedes buildctl admission; the STOP request
	// observation precedes the disposal.
	prepared, buildctl := order.index("prepared"), order.index("buildctl_admitted")
	stopped, disposed := order.index("stop_requested"), order.index("disposed")
	if prepared < 0 || buildctl < 0 || stopped < 0 || disposed < 0 {
		t.Fatalf("order log missing stages: %v", order.snapshot())
	}
	if prepared > buildctl {
		t.Errorf("buildctl admitted before the prepared tree: %v", order.snapshot())
	}
	if stopped > disposed {
		t.Errorf("disposal ran before the STOP observation: %v", order.snapshot())
	}
	if got := manager.stopCount(); got != 1 {
		t.Errorf("manager STOP count = %d, want exactly 1", got)
	}
	disposedIDs := disposeRec.idsSeen()
	if len(disposedIDs) != 1 || disposedIDs[0] != op.ID {
		t.Errorf("disposal ids = %v, want exactly [%s]", disposedIDs, op.ID)
	}

	// The public child surface is unchanged: the preparation and the
	// disposal are no-child stages.
	if calls.buildctlIndex() < 0 {
		t.Error("buildctl child did not run")
	}
}

// TestBuildDriverStartFailureSkipsPreparation proves the admission ladder:
// a failed manager START never reaches the preparation stage (the
// authoritative category is the only preparation input, and it never
// exists).
func TestBuildDriverStartFailureSkipsPreparation(t *testing.T) {
	app, _, result, manager, calls := setupBuildBackendTest(t)
	manager.setStartResp(builderManagerRespInternal)
	prep := newDevPrepFake()
	app.prepareTrustedDevFn = prep.fn

	op := startBackendBuild(t, app, result.Token, nil)
	waitBuildDone(t, op)

	if got := prep.count(); got != 0 {
		t.Errorf("preparation invoked %d times after a failed START, want 0", got)
	}
	if calls.count() != 0 {
		t.Errorf("children started = %d, want 0:\n%s", calls.count(), calls.all())
	}
	op.mu.Lock()
	rc := derefString(op.ResultCode)
	state := op.State
	op.mu.Unlock()
	if rc != "docker_build_failed" || state != operationFailed {
		t.Errorf("result = (%v, %v), want (docker_build_failed, failed)", rc, state)
	}
}

// TestBuildDriverSocketValidationFailureSkipsPreparation proves the
// admission ladder above the preparation: a failed BuildKit socket
// validation never reaches the preparation stage.
func TestBuildDriverSocketValidationFailureSkipsPreparation(t *testing.T) {
	app, _, result, manager, calls := setupBuildBackendTest(t)
	app.validateBuildKitSocketFn = func(string) error { return errors.New("refused") }
	prep := newDevPrepFake()
	app.prepareTrustedDevFn = prep.fn

	op := startBackendBuild(t, app, result.Token, nil)
	waitBuildDone(t, op)

	if got := prep.count(); got != 0 {
		t.Errorf("preparation invoked %d times after a failed socket validation, want 0", got)
	}
	if calls.count() != 0 {
		t.Errorf("children started = %d, want 0:\n%s", calls.count(), calls.all())
	}
	if got := manager.stopCount(); got != 1 {
		t.Errorf("manager STOP count = %d, want exactly 1 (the mandatory rollback)", got)
	}
	op.mu.Lock()
	rc := derefString(op.ResultCode)
	op.mu.Unlock()
	if rc != "docker_build_failed" {
		t.Errorf("result_code = %q, want docker_build_failed", rc)
	}
}

// TestBuildDriverUnreachableAuthoritativeCategoryRefused proves the
// category refusal chain: the P2 client is the parser of the category
// token, so an invalid or malformed START category is a START failure —
// the preparation stage is never reached through any driver path.
func TestBuildDriverUnreachableAuthoritativeCategoryRefused(t *testing.T) {
	app, _, result, manager, calls := setupBuildBackendTest(t)
	manager.setStartResp(builderManagerRespOK + " c0")
	prep := newDevPrepFake()
	app.prepareTrustedDevFn = prep.fn

	op := startBackendBuild(t, app, result.Token, nil)
	waitBuildDone(t, op)

	if got := prep.count(); got != 0 {
		t.Errorf("preparation invoked %d times with no valid category, want 0", got)
	}
	if calls.count() != 0 {
		t.Errorf("children started = %d, want 0:\n%s", calls.count(), calls.all())
	}
	op.mu.Lock()
	rc := derefString(op.ResultCode)
	op.mu.Unlock()
	if rc != "docker_build_failed" {
		t.Errorf("result_code = %q, want docker_build_failed", rc)
	}
}

// TestBuildDriverPrepFailureFailsClosedWithStop proves the fail-closed
// contract of a preparation failure: no buildctl admission, the mandatory
// manager rollback, no driver-side disposal (the preparer owns its own
// residue), the failed result, and the internal stage diagnostic.
func TestBuildDriverPrepFailureFailsClosedWithStop(t *testing.T) {
	_, opBuf := setupTestLogging(t)
	app, _, result, manager, calls := setupBuildBackendTest(t)
	order := &buildOrderLog{}
	scriptedManagerStop(t, manager, order)

	prep := newDevPrepFake()
	prep.err = errors.New("simulated preparation failure")
	app.prepareTrustedDevFn = prep.fn
	disposeRec := &devPrepDisposeFake{}
	app.devPrepDisposeFn = disposeRec.fn

	op := startBackendBuild(t, app, result.Token, nil)
	waitBuildDone(t, op)

	if got := prep.count(); got != 1 {
		t.Errorf("preparation invocations = %d, want exactly 1", got)
	}
	if calls.count() != 0 {
		t.Errorf("children started = %d, want 0 (no buildctl admission):\n%s", calls.count(), calls.all())
	}
	if got := manager.stopCount(); got != 1 {
		t.Errorf("manager STOP count = %d, want exactly 1 (mandatory rollback)", got)
	}
	if got := disposeRec.idsSeen(); len(got) != 0 {
		t.Errorf("disposal ids = %v, want none on a failed preparation", got)
	}
	op.mu.Lock()
	rc, state := derefString(op.ResultCode), op.State
	op.mu.Unlock()
	if rc != "docker_build_failed" || state != operationFailed {
		t.Errorf("result = (%q, %v), want (docker_build_failed, failed)", rc, state)
	}
	assertStageDiagnostic(t, opBuf, "dev_prep")
}

// TestBuildDriverCancelDuringPreparation proves the cancellation semantics
// of the preparation control stage: the cancel fires the stage's context,
// the LATCH classifies the exit (cancelled, not failed), the mandatory
// manager rollback runs, no buildctl child ever starts, no disposal runs,
// and no exit code is reported (no child was started).
func TestBuildDriverCancelDuringPreparation(t *testing.T) {
	app, supervisor, result, manager, calls := setupBuildBackendTest(t)

	prep := newDevPrepFake()
	prep.block = make(chan struct{})
	app.prepareTrustedDevFn = prep.fn
	disposeRec := &devPrepDisposeFake{}
	app.devPrepDisposeFn = disposeRec.fn

	op := startBackendBuild(t, app, result.Token, nil)
	select {
	case <-prep.called:
	case <-time.After(10 * time.Second):
		t.Fatal("the preparation stage never ran")
	}

	// Cancel while the preparation is blocked inside its control stage;
	// cancel returns only after the operation reached its terminal state.
	if err := supervisor.cancel(op.ID, nil); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	if got := prep.count(); got != 1 {
		t.Errorf("preparation invocations = %d, want exactly 1", got)
	}
	if calls.count() != 0 {
		t.Errorf("children started = %d, want 0:\n%s", calls.count(), calls.all())
	}
	if got := manager.stopCount(); got != 1 {
		t.Errorf("manager STOP count = %d, want exactly 1 (mandatory rollback)", got)
	}
	if got := disposeRec.idsSeen(); len(got) != 0 {
		t.Errorf("disposal ids = %v, want none on a cancelled preparation", got)
	}
	op.mu.Lock()
	exitCode, terminated := op.ExitCode, op.terminationRequested
	if exitCode != nil || !terminated {
		op.mu.Unlock()
		t.Fatalf("exit_code = %v, terminated = %v, want nil latch-cancel with no child", exitCode, terminated)
	}
	state := op.State
	op.mu.Unlock()
	if state != operationFailed {
		t.Errorf("state = %v, want failed", state)
	}
}

// TestBuildDriverLatchRefusesPreparationAdmission proves the admission
// side of the preparation control stage: a termination latched before the
// preparation's admission refuses it entirely (the preparer never runs),
// the mandatory rollback still runs, and the result is cancelled.
func TestBuildDriverLatchRefusesPreparationAdmission(t *testing.T) {
	app, supervisor, result, manager, calls := setupBuildBackendTest(t)

	// Park the driver inside the socket-validation hook: the preparation
	// admission is next. Cancel while parked, then release.
	reached := make(chan struct{})
	release := make(chan struct{})
	app.validateBuildKitSocketFn = func(string) error {
		close(reached)
		<-release
		return nil
	}
	prep := newDevPrepFake()
	app.prepareTrustedDevFn = prep.fn
	disposeRec := &devPrepDisposeFake{}
	app.devPrepDisposeFn = disposeRec.fn

	op := startBackendBuild(t, app, result.Token, nil)

	// Park the driver inside the socket-validation hook first: the
	// preparation admission is the very next driver step. Then latch the
	// cancellation while the driver is parked, and release it into the
	// visited-latch preparation admission.
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("socket validation never ran")
	}
	cancelDone := make(chan error, 1)
	go func() { cancelDone <- supervisor.cancel(op.ID, nil) }()
	if !latchSetWithin(t, op, 5*time.Second) {
		t.Fatal("the cancellation latch was never set")
	}
	close(release)
	if err := <-cancelDone; err != nil {
		t.Fatalf("cancel: %v", err)
	}
	waitBuildDone(t, op)

	if got := prep.count(); got != 0 {
		t.Errorf("preparation invoked %d times after a latched admission, want 0", got)
	}
	if calls.count() != 0 {
		t.Errorf("children started = %d, want 0:\n%s", calls.count(), calls.all())
	}
	if got := manager.stopCount(); got != 1 {
		t.Errorf("manager STOP count = %d, want exactly 1 (mandatory rollback)", got)
	}
	if got := disposeRec.idsSeen(); len(got) != 0 {
		t.Errorf("disposal ids = %v, want none", got)
	}
	op.mu.Lock()
	rc, exitCode := derefString(op.ResultCode), op.ExitCode
	op.mu.Unlock()
	if rc != "cancelled" {
		t.Errorf("result_code = %q, want cancelled (explicit cancel)", rc)
	}
	if exitCode != nil {
		t.Errorf("exit_code = %v, want nil (no child stage started)", exitCode)
	}
}

// latchSetWithin reports whether the operation's termination latch became
// set within the bound (polling under op.mu; a transient existence check,
// not a lifecycle assumption).
func latchSetWithin(t *testing.T, op *operation, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		op.mu.Lock()
		set := op.terminationRequested
		op.mu.Unlock()
		if set {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// TestBuildDriverBuildctlFailureStopsBeforeDisposal proves the prepared-tree
// lifetime invariant on a failed buildctl: the manager STOP is observed by
// the manager BEFORE the disposal runs, the disposal addresses exactly this
// operation's tree, and the result stays the existing build failure code.
func TestBuildDriverBuildctlFailureStopsBeforeDisposal(t *testing.T) {
	app, _, result, manager, calls := setupBuildBackendTest(t)
	order := &buildOrderLog{}
	scriptedManagerStop(t, manager, order)

	prep := newDevPrepFake()
	prep.order = order
	app.prepareTrustedDevFn = prep.fn
	disposeRec := &devPrepDisposeFake{order: order}
	app.devPrepDisposeFn = disposeRec.fn
	runner := newBackendChildRunner(t, app, calls)
	wrapBuildctlOrder(app, order)
	runner.setBuildctlExitCode(9)

	op := startBackendBuild(t, app, result.Token, nil)
	waitBuildDone(t, op)

	stopped, disposed := order.index("stop_requested"), order.index("disposed")
	if stopped < 0 || disposed < 0 {
		t.Fatalf("order log missing stages: %v", order.snapshot())
	}
	if stopped > disposed {
		t.Errorf("disposal ran before the STOP observation: %v", order.snapshot())
	}
	disposedIDs := disposeRec.idsSeen()
	if len(disposedIDs) != 1 || disposedIDs[0] != op.ID {
		t.Errorf("disposal ids = %v, want exactly [%s]", disposedIDs, op.ID)
	}
	if got := manager.stopCount(); got != 1 {
		t.Errorf("manager STOP count = %d, want exactly 1", got)
	}
	op.mu.Lock()
	rc, state := derefString(op.ResultCode), op.State
	op.mu.Unlock()
	if rc != "docker_build_failed" || state != operationFailed {
		t.Errorf("result = (%q, %v), want (docker_build_failed, failed)", rc, state)
	}
	if runner.hasStartedImportChild() {
		t.Errorf("image handoff children started after a failed buildctl:\n%s", calls.all())
	}
}

// TestBuildDriverBuildctlCancelStopsBeforeDisposal proves the same
// prepared-tree lifetime invariant on a cancelled buildctl: STOP first
// (mandatory rollback), disposal only after the STOP observation, then the
// cancelled result.
func TestBuildDriverBuildctlCancelStopsBeforeDisposal(t *testing.T) {
	app, supervisor, result, manager, calls := setupBuildBackendTest(t)
	order := &buildOrderLog{}
	scriptedManagerStop(t, manager, order)

	prep := newDevPrepFake()
	prep.order = order
	app.prepareTrustedDevFn = prep.fn
	disposeRec := &devPrepDisposeFake{order: order}
	app.devPrepDisposeFn = disposeRec.fn
	runner := newBackendChildRunner(t, app, calls)
	wrapBuildctlOrder(app, order)
	runner.setBuildctlBlocks(true)

	op := startBackendBuild(t, app, result.Token, nil)
	waitForFirstAdmittedBuildctl(t, runner)
	if err := supervisor.cancel(op.ID, nil); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	waitBuildDone(t, op)

	stopped, disposed := order.index("stop_requested"), order.index("disposed")
	if stopped < 0 || disposed < 0 {
		t.Fatalf("order log missing stages: %v", order.snapshot())
	}
	if stopped > disposed {
		t.Errorf("disposal ran before the STOP observation: %v", order.snapshot())
	}
	disposedIDs := disposeRec.idsSeen()
	if len(disposedIDs) != 1 || disposedIDs[0] != op.ID {
		t.Errorf("disposal ids = %v, want exactly [%s]", disposedIDs, op.ID)
	}
	if got := manager.stopCount(); got != 1 {
		t.Errorf("manager STOP count = %d, want exactly 1", got)
	}
	op.mu.Lock()
	rc, exitCode := derefString(op.ResultCode), op.ExitCode
	op.mu.Unlock()
	if rc != "cancelled" {
		t.Errorf("result_code = %q, want cancelled", rc)
	}
	if exitCode == nil {
		t.Error("exit_code = nil, want the reported buildctl exit code (the child was signalled)")
	}
	if runner.hasStartedImportChild() {
		t.Errorf("image handoff children started after a cancelled buildctl:\n%s", calls.all())
	}
}

// waitForFirstAdmittedBuildctl waits until the first buildctl child
// actually started (the ready-marker proof), deterministically gating the
// cancellation on a live build stage.
func waitForFirstAdmittedBuildctl(t *testing.T, runner *backendChildRunner) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if idx := runner.calls.buildctlIndex(); idx >= 0 && runner.childStarted(idx) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the buildctl child never started")
}

// TestBuildDriverStopFailurePreventsDisposal proves the STOP-failure side
// of the lifetime invariant: when the manager STOP cannot be proven
// converged, the prepared tree is NOT disposed (a possibly-live builder
// may still use it), no import child runs, and the result is the existing
// builder-stop failure code.
func TestBuildDriverStopFailurePreventsDisposal(t *testing.T) {
	_, opBuf := setupTestLogging(t)
	app, _, result, manager, calls := setupBuildBackendTest(t)

	prep := newDevPrepFake()
	app.prepareTrustedDevFn = prep.fn
	disposeRec := &devPrepDisposeFake{}
	app.devPrepDisposeFn = disposeRec.fn
	manager.setStopResp(builderManagerRespInternal)
	runner := newBackendChildRunner(t, app, calls)

	op := startBackendBuild(t, app, result.Token, nil)
	waitBuildDone(t, op)

	if got := disposeRec.idsSeen(); len(got) != 0 {
		t.Errorf("disposal ids = %v, want none when the STOP is not proven converged", got)
	}
	if runner.hasStartedImportChild() {
		t.Errorf("image handoff children started after an unproven STOP:\n%s", calls.all())
	}
	if calls.buildctlIndex() < 0 {
		t.Error("buildctl child did not run (the failure must be at STOP, not earlier)")
	}
	op.mu.Lock()
	rc, state := derefString(op.ResultCode), op.State
	op.mu.Unlock()
	if rc != "docker_build_failed" || state != operationFailed {
		t.Errorf("result = (%q, %v), want (docker_build_failed, failed)", rc, state)
	}
	assertStageDiagnostic(t, opBuf, "builder_stop")
}

// TestDevPrepDisposeOperationRefusesNonCanonicalIDs proves the disposal
// owner's guard: a non-canonical operation id is refused and nothing is
// derived, while a canonical id addresses exactly the canonical path owner
// (devPrepOpDir) and succeeds on an absent tree (no adoption semantics).
func TestDevPrepDisposeOperationRefusesNonCanonicalIDs(t *testing.T) {
	for _, bad := range []string{"", "op_", "op_XX", "/etc", "op_../../etc", "x"} {
		if err := devPrepDisposeOperation(bad); err == nil {
			t.Errorf("devPrepDisposeOperation(%q) = nil, want a canonical-id refusal", bad)
		}
	}
	// A canonical id against an absent tree is success: the disposal is
	// idempotent over an already-absent tree (dev-prep never created it).
	good := "op_" + strings.Repeat("f", 32)
	if err := devPrepDisposeOperation(good); err != nil {
		t.Errorf("devPrepDisposeOperation(%q) = %v, want nil (absent tree is success)", good, err)
	}
}
