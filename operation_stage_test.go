package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Synthetic sequential-child harness for the Operation current-child slot
// and the permanent termination latch (P1). Stages are REAL child
// processes: a shell that writes its stage marker file on start and then
// busy-waits for a stage release file. The stage driver mirrors the
// production driver shape: startOperationStage (production owner) ->
// waitCurrentStage (production Wait owner) -> next stage. Termination uses
// the real supervisor paths - the sole cancellation/shutdown owner.

// syntheticStageCmd returns the stage child: write the marker, then block
// until the release file appears (busy loop; default SIGTERM disposition —
// a cancel's graceful signal ends it, and force cleanup escalates if
// needed).
func syntheticStageCmd(markerPath, releasePath string) *exec.Cmd {
	return exec.Command("sh", "-c",
		"echo started > "+markerPath+
			"; while [ ! -e "+releasePath+" ]; do :; done")
}

// syntheticStageDriver runs sequential stages of op through the production
// start/wait owners and records which stages actually started.
type syntheticStageDriver struct {
	t *testing.T

	op *operation

	markers [2]string // marker file per stage (written by the child on start)
	release [2]string // release file per stage (touch to end the stage)

	mu      sync.Mutex
	started map[int]bool // stages whose child actually started
}

func newSyntheticStageDriver(t *testing.T, op *operation, base string) *syntheticStageDriver {
	t.Helper()
	d := &syntheticStageDriver{t: t, op: op, started: map[int]bool{}}
	for i := range d.markers {
		d.markers[i] = filepath.Join(base, "stage"+string(rune('1'+i))+".started")
		d.release[i] = filepath.Join(base, "stage"+string(rune('1'+i))+".release")
	}
	return d
}

func (d *syntheticStageDriver) stageStarted(i int) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.started[i]
}

// runStage admits and starts stage i through the production owner, waits
// for the real child to start, then returns the *exec.Cmd. It records the
// started stage. Refusal (termination latch) or start error returns nil.
func (d *syntheticStageDriver) runStage(i int) *exec.Cmd {
	cmd := syntheticStageCmd(d.markers[i], d.release[i])
	res := startOperationStage(cmd, d.op)
	if res.Terminated || res.Err != nil {
		return nil
	}
	d.mu.Lock()
	d.started[i] = true
	d.mu.Unlock()
	waitForFileOrTimeout(d.t, d.markers[i], 5*time.Second)
	return cmd
}

// tryAdmitStage admits stage i through the production owner and records
// admission WITHOUT waiting for the child's marker file: the racing
// cancel may terminate the child before its marker write, and the test
// then proves the death from the reaped state. Returns the started cmd
// on admission, nil on refusal (latch) or start error.
func (d *syntheticStageDriver) tryAdmitStage(i int) *exec.Cmd {
	cmd := syntheticStageCmd(d.markers[i], d.release[i])
	res := startOperationStage(cmd, d.op)
	if res.Terminated || res.Err != nil {
		return nil
	}
	d.mu.Lock()
	d.started[i] = true
	d.mu.Unlock()
	return cmd
}

// endStage ends a running stage cleanly: release the child, SIGKILL it
// (a killed child makes Wait return a non-nil error; the production Wait
// owner clears the slot regardless), then Wait through the production
// owner so the slot is cleared exactly as the driver would.
func (d *syntheticStageDriver) endStage(i int, cmd *exec.Cmd) {
	if err := os.WriteFile(d.release[i], []byte("x"), 0644); err != nil {
		d.t.Fatalf("cannot write stage release marker: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		d.t.Fatalf("cannot kill stage child: %v", err)
	}
	_ = d.op.waitCurrentStage()
}

// waitForFileOrTimeout polls until path exists or the timeout elapses.
func waitForFileOrTimeout(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("file %s did not appear within %v", path, timeout)
}

// TestOperationStageCancelBeforeFirstStart (A): cancel before stage 1
// starts - stage 1 never starts, stage 2 never starts, termination latched.
func TestOperationStageCancelBeforeFirstStart(t *testing.T) {
	app, supervisor, session, _ := setupBuildTest(t)
	_ = app

	op := newRunOperation(session.Session.ID, "test:image", 4*1024*1024, "", "", "")
	if admitForTest(supervisor, op) != admissionAccepted {
		t.Fatal("admit failed")
	}
	d := newSyntheticStageDriver(t, op, t.TempDir())

	// Cancel BEFORE any stage admission.
	if err := supervisor.cancel(op.ID, nil); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	if cmd := d.runStage(0); cmd != nil {
		t.Error("stage 1 admitted after pre-start cancel")
	}
	if d.stageStarted(0) {
		t.Error("stage 1 started despite pre-start cancel")
	}
	if d.stageStarted(1) {
		t.Error("stage 2 started despite pre-start cancel")
	}
	op.mu.Lock()
	latched := op.terminationRequested
	op.mu.Unlock()
	if !latched {
		t.Error("termination latch not set")
	}
}

// TestOperationStageCancelDuringStage (B): cancel while stage 1 runs - the
// child receives termination, the force phase kills it, the Wait completes,
// and stage 2 never starts.
func TestOperationStageCancelDuringStage(t *testing.T) {
	app, supervisor, session, _ := setupBuildTest(t)
	_ = app

	op := newRunOperation(session.Session.ID, "test:image", 4*1024*1024, "", "", "")
	if admitForTest(supervisor, op) != admissionAccepted {
		t.Fatal("admit failed")
	}
	d := newSyntheticStageDriver(t, op, t.TempDir())

	cmd := d.runStage(0)
	if cmd == nil {
		t.Fatal("stage 1 did not start")
	}
	op.mu.Lock()
	active := op.currentCmd != nil
	op.mu.Unlock()
	if !active {
		t.Fatal("stage 1 child not active")
	}

	// A real stage driver owns the Wait and the terminal transition while
	// cancel runs; own both now so cancel's graceful wait converges on
	// op.done instead of its full budget (the synthetic harness must not
	// spend time the production driver never spends): on the Wait error
	// after termination the driver classifies the cancelled failure.
	waitDone := make(chan error, 1)
	go func() {
		waitErr := op.waitCurrentStage()
		op.mu.Lock()
		latched := op.terminationRequested
		op.mu.Unlock()
		if waitErr != nil && latched {
			op.fail(resultCancelled, "cancelled", nil)
		} else if waitErr != nil {
			op.fail("docker_run_failed", "stage failed", nil)
		} else {
			op.succeed(nil)
		}
		waitDone <- waitErr
	}()

	// Cancel while the child runs. The child busy-loops, so the cancel
	// path's graceful SIGTERM kills it (sh does not trap here); the
	// completion goroutine reaps the child and completes the op with the
	// stage-failure classification of a real driver.
	if err := supervisor.cancel(op.ID, nil); err != nil {
		t.Fatalf("cancel: %v", err)
	}

	// The child's death is proven from the reaped state (polling
	// kill(pid,0) cannot prove termination: an unreaped zombie still
	// answers kill(pid,0)).
	select {
	case <-waitDone:
	case <-time.After(20 * time.Second):
		t.Fatal("waitCurrentStage did not return after cancel during stage 1")
	}
	if cmd.ProcessState == nil {
		t.Fatal("stage 1 child was not reaped after cancel during stage 1")
	}
	op.mu.Lock()
	cleared := op.currentCmd == nil
	op.mu.Unlock()
	if !cleared {
		t.Fatal("current slot not cleared after cancel during stage 1")
	}
	op.mu.Lock()
	terminal := op.CompletedAt != nil
	op.mu.Unlock()
	if !terminal {
		// Cancel won and the child was reaped with a Wait error: the
		// real driver classifies this as the cancelled failure.
		op.fail(resultCancelled, "cancelled", nil)
	}

	// Stage 2 must never start.
	if cmd2 := d.runStage(1); cmd2 != nil {
		t.Error("stage 2 admitted after cancel during stage 1")
	}
	if d.stageStarted(1) {
		t.Error("stage 2 started after cancel during stage 1")
	}
}

// TestOperationStageCancelBetweenStages (C): the critical regression proof.
// Stage 1 exits and the slot clears; cancel latches termination; the
// attempted stage 2 admission is refused and its marker never appears.
// Negative self-test: the same harness WITHOUT cancel starts stage 2, so
// absence cannot false-pass.
func TestOperationStageCancelBetweenStages(t *testing.T) {
	app, supervisor, session, _ := setupBuildTest(t)
	_ = app

	runBetween := func(cancel bool) (stage2Started, latched bool) {
		op := newRunOperation(session.Session.ID, "test:image", 4*1024*1024, "", "", "")
		if admitForTest(supervisor, op) != admissionAccepted {
			t.Fatal("admit failed")
		}
		d := newSyntheticStageDriver(t, op, t.TempDir())

		cmd1 := d.runStage(0)
		if cmd1 == nil {
			t.Fatal("stage 1 did not start")
		}
		d.endStage(0, cmd1)

		op.mu.Lock()
		slotCleared := op.currentCmd == nil
		op.mu.Unlock()
		if !slotCleared {
			t.Error("current slot not cleared after stage 1 Wait")
			return false, false
		}

		if cancel {
			if err := supervisor.cancel(op.ID, nil); err != nil {
				t.Fatalf("cancel: %v", err)
			}
		}

		// Attempt stage 2 admission exactly as a stage driver would.
		cmd2 := d.runStage(1)
		if !cancel {
			// Negative self-test: without cancellation the same harness
			// MUST start stage 2.
			if cmd2 == nil {
				t.Error("negative self-test failed: stage 2 did not start without cancellation - absence would false-pass")
				return false, false
			}
			d.endStage(1, cmd2)
		} else if cmd2 != nil {
			t.Error("stage 2 admitted after cancellation - termination not permanent")
		}

		op.mu.Lock()
		latched = op.terminationRequested
		op.mu.Unlock()
		return d.stageStarted(1), latched
	}

	// Negative self-test first: without cancel the same harness starts
	// stage 2.
	if started, _ := runBetween(false); !started {
		t.Fatal("negative self-test failed: stage 2 did not start without cancellation")
	}

	stage2Started, latched := runBetween(true)
	if stage2Started {
		t.Error("stage 2 STARTED after cancel between stages (regression)")
	}
	if !latched {
		t.Error("termination latch not set by cancel between stages")
	}
}

// TestOperationStageCancelSimultaneousAdmissionRace (D): cancel racing
// stage-2 admission repeatedly. Only two legal outcomes: stage 2 wins
// admission under op.mu and then receives termination, or termination wins
// and stage 2 never starts. Forbidden: termination returns/claims the
// operation and THEN stage 2 starts.
func TestOperationStageCancelSimultaneousAdmissionRace(t *testing.T) {
	app, supervisor, session, _ := setupBuildTest(t)
	_ = app

	for attempt := 0; attempt < 100; attempt++ {
		op := newRunOperation(session.Session.ID, "test:image", 4*1024*1024, "", "", "")
		if admitForTest(supervisor, op) != admissionAccepted {
			t.Fatal("admit failed")
		}
		d := newSyntheticStageDriver(t, op, t.TempDir())

		// Stage 1 completes and clears the slot.
		cmd1 := d.runStage(0)
		if cmd1 == nil {
			t.Fatal("stage 1 did not start")
		}
		d.endStage(0, cmd1)

		// Race: stage-2 admission vs cancel, started together.
		admitted := make(chan *exec.Cmd, 1)
		refused := make(chan struct{}, 1)
		begin := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-begin
			if cmd2 := d.tryAdmitStage(1); cmd2 != nil {
				admitted <- cmd2
			} else {
				refused <- struct{}{}
			}
		}()
		go func() {
			defer wg.Done()
			<-begin
			_ = supervisor.cancel(op.ID, nil)
		}()
		close(begin)

		var stage2Cmd *exec.Cmd
		select {
		case cmd2 := <-admitted:
			stage2Cmd = cmd2
		case <-refused:
		case <-time.After(10 * time.Second):
			t.Fatalf("attempt %d: admission neither admitted nor refused", attempt)
		}

		if stage2Cmd != nil {
			// Legal outcome 1: stage 2 won admission. The latch must be
			// set once cancel has also run. The latch read is ordered
			// AFTER wg.Wait(): the admitted channel only proves
			// tryAdmitStage returned, not that the racing cancel already
			// acquired op.mu and latched termination (reading it earlier
			// reported a legal interleaving as a forbidden outcome).
			wg.Wait()
			op.mu.Lock()
			latched := op.terminationRequested
			op.mu.Unlock()
			if !latched {
				t.Fatalf("attempt %d: stage 2 admitted but termination latch not set", attempt)
			}
			// The admitted child received SIGTERM from the cancel path;
			// the child ignores SIGTERM, so the cancel force phase must
			// kill it. Reap it through the production Wait owner (the
			// reaped ProcessState proves termination; polling kill(pid,0)
			// cannot: an unreaped zombie still answers).
			waitDone := make(chan error, 1)
			go func() { waitDone <- d.op.waitCurrentStage() }()
			select {
			case <-waitDone:
			case <-time.After(20 * time.Second):
				t.Fatalf("attempt %d: waitCurrentStage did not return after cancel", attempt)
			}
			if stage2Cmd.ProcessState == nil {
				t.Fatalf("attempt %d: admitted stage 2 child was not reaped after termination", attempt)
			}
		} else {
			// The refused branch never joined the cancel goroutine yet.
			wg.Wait()
		}

		// Complete the operation so the attempt does not hold session
		// capacity for the next attempt (the harness never drives the op
		// to a terminal state).
		op.mu.Lock()
		terminal := op.CompletedAt != nil
		op.mu.Unlock()
		if !terminal {
			op.fail("docker_run_failed", "synthetic harness cleanup", nil)
		}
	}
}

// TestOperationStageShutdownBetweenStages (E): shutdown equivalent of the
// inter-stage proof with the shutdown reason. Public semantics stay:
// explicit cancel -> cancelled; shutdown -> existing kind-specific failure
// (docker_run_failed / docker_build_failed); no public shutdown code.
func TestOperationStageShutdownBetweenStages(t *testing.T) {
	app, supervisor, session, _ := setupBuildTest(t)
	_ = app

	op := newRunOperation(session.Session.ID, "test:image", 4*1024*1024, "", "", "")
	if admitForTest(supervisor, op) != admissionAccepted {
		t.Fatal("admit failed")
	}
	d := newSyntheticStageDriver(t, op, t.TempDir())

	cmd1 := d.runStage(0)
	if cmd1 == nil {
		t.Fatal("stage 1 did not start")
	}
	d.endStage(0, cmd1)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	supervisor.terminateForShutdown(shutdownCtx, nil)
	cancel()

	if cmd2 := d.runStage(1); cmd2 != nil {
		t.Error("stage 2 admitted after shutdown between stages")
	}
	if d.stageStarted(1) {
		t.Error("stage 2 started after shutdown between stages")
	}
	op.mu.Lock()
	reason := op.reason
	latched := op.terminationRequested
	op.mu.Unlock()
	if reason != terminationShutdown {
		t.Errorf("termination reason %v, want terminationShutdown", reason)
	}
	if !latched {
		t.Error("termination latch not set by shutdown")
	}
}

// TestOperationStageForceCleanupKillsCurrentStage (F): with stage 1
// blocked, force cleanup kills the current stage, and future stage
// admission is refused.
func TestOperationStageForceCleanupKillsCurrentStage(t *testing.T) {
	app, supervisor, session, _ := setupBuildTest(t)
	_ = app

	op := newRunOperation(session.Session.ID, "test:image", 4*1024*1024, "", "", "")
	if admitForTest(supervisor, op) != admissionAccepted {
		t.Fatal("admit failed")
	}
	d := newSyntheticStageDriver(t, op, t.TempDir())

	cmd := d.runStage(0)
	if cmd == nil {
		t.Fatal("stage 1 did not start")
	}

	// Cancel with a tiny budget so the graceful phase expires immediately
	// and force cleanup kills the current child.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	supervisor.terminateOperations(shutdownCtx, op, nil, terminationCancelled, false)
	cancel()

	// The child must die (graceful SIGTERM; force SIGKILL on timeout).
	// Wait it through the production Wait owner, which reaps the child
	// and clears the slot; the death is proven from the reaped state.
	waitDone := make(chan error, 1)
	go func() { waitDone <- op.waitCurrentStage() }()
	select {
	case <-waitDone:
	case <-time.After(20 * time.Second):
		t.Fatal("waitCurrentStage did not return after force cleanup")
	}
	if cmd.ProcessState == nil {
		t.Fatal("force cleanup did not kill the current stage child")
	}

	op.mu.Lock()
	latched := op.terminationRequested
	forceOwned := op.forceOwned
	op.mu.Unlock()
	if !latched {
		t.Error("termination latch not set")
	}
	if !forceOwned {
		t.Error("force cleanup was not claimed")
	}

	// Future stage admission must be refused.
	if cmd2 := d.runStage(1); cmd2 != nil {
		t.Error("stage 2 admitted after force cleanup - termination not permanent")
	}
	if d.stageStarted(1) {
		t.Error("stage 2 started after force cleanup")
	}
}
