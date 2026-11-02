package main

// workload_selinux_worker_exit_test.go — deterministic regression tests for
// the bindfs projection worker's exit accounting: the recorded cmd.Wait()
// result is repeatable by every observer, a proven nonzero exit (with its
// stderr) is distinct from an unproven exit, and the cleanup classification
// keeps the fail-closed retention exactly for the unproven case while
// accepting a proven exited-and-reaped worker regardless of its exit code.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// startRealWorkerForTest starts one real child process as the projection
// worker and returns the production worker handle. The child runs the given
// shell script so every exit shape is exercised through the real cmd.Wait()
// path.
func startRealWorkerForTest(t *testing.T, script string) (*bindfsWorker, *exec.Cmd) {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", script)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start real worker fixture: %v", err)
	}
	w := newBindfsWorker(cmd, stderr)
	go w.recordExit()
	return w, cmd
}

// killTestFixture terminates a still-running test child. This is the test's
// own fixture control, never the production exit proof; the production
// recordExit goroutine still performs the one real reaping Wait.
func killTestFixture(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func TestBindfsWorkerWaitExitIsRepeatableForCleanExit(t *testing.T) {
	w, _ := startRealWorkerForTest(t, "exit 0")
	if err := w.waitExit(5 * time.Second); err != nil {
		t.Fatalf("a clean worker exit must read nil, got %v", err)
	}
	if err := w.waitExit(5 * time.Second); err != nil {
		t.Fatalf("the same clean exit result must be readable again, got %v", err)
	}
	if w.alive() {
		t.Error("a reaped worker must not report alive")
	}
}

func TestBindfsWorkerWaitExitIsRepeatableForNonzeroExitAndKeepsStderr(t *testing.T) {
	w, _ := startRealWorkerForTest(t, "echo fuse: failed to execute /bin/mount: Permission denied >&2; exit 4")
	first := w.waitExit(5 * time.Second)
	if first == nil {
		t.Fatal("a nonzero worker exit must read non-nil")
	}
	second := w.waitExit(5 * time.Second)
	if second == nil || first.Error() != second.Error() {
		t.Fatalf("the same exit result must be readable again, got %q then %q", first, second)
	}
	if !strings.Contains(first.Error(), "fuse: failed to execute /bin/mount: Permission denied") {
		t.Errorf("the recorded exit must keep the worker stderr, got %q", first)
	}
	var exitErr *exec.ExitError
	if !errors.As(first, &exitErr) || exitErr.ExitCode() != 4 {
		t.Errorf("the recorded exit must keep the wrapped exit status, got %v", first)
	}
}

func TestBindfsWorkerExitUnprovenWithinBudgetThenProven(t *testing.T) {
	w, cmd := startRealWorkerForTest(t, "sleep 0.3; exit 7")
	defer killTestFixture(cmd)
	err := w.waitExit(50 * time.Millisecond)
	if err == nil {
		t.Fatal("a still-running worker's exit must not be proven within a tiny budget")
	}
	var unproven *workerExitUnprovenError
	if !errors.As(err, &unproven) {
		t.Fatalf("the unproven exit must be the typed unproven error, got %v", err)
	}
	if unproven.Error() != "bindfs worker did not exit after unmount" {
		t.Errorf("the unproven message must stay the established diagnostic text, got %q", unproven.Error())
	}
	proven := w.waitExit(5 * time.Second)
	if proven == nil {
		t.Fatal("the later real exit must be proven")
	}
	var exitErr *exec.ExitError
	if !errors.As(proven, &exitErr) || exitErr.ExitCode() != 7 {
		t.Errorf("the proven exit must keep the wrapped exit status, got %v", proven)
	}
}

func TestBindfsWorkerConcurrentExitObserversSeeTheSameResult(t *testing.T) {
	w, _ := startRealWorkerForTest(t, "sleep 0.2; exit 9")
	const observers = 4
	results := make([]error, observers)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = w.waitExit(5 * time.Second)
		}(i)
	}
	wg.Wait()
	for i, err := range results {
		if err == nil || err.Error() != results[0].Error() {
			t.Fatalf("observer %d must read the same proven exit result, got %v vs %v", i, err, results[0])
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 9 {
			t.Errorf("observer %d must read the wrapped exit status, got %v", i, err)
		}
	}
}

// TestSELinuxPrepareProjectionAcceptsProvenNonzeroWorkerExitAfterMountAbsence
// is the regression for the production RED run: the worker exited nonzero
// before the projection mounted, the readiness wait already surfaced its
// exit error, and the rollback cleanup must release the owned projection
// state after the positive mount-absence proof instead of reporting the
// consumed-result timeout and retaining the state.
func TestSELinuxPrepareProjectionAcceptsProvenNonzeroWorkerExitAfterMountAbsence(t *testing.T) {
	b, _ := newTestSELinuxBackend(t)
	b.startWorker = func(_ func(string) (string, error), _, _, _ string) (projectionWorker, error) {
		// The mount never appears (the RED canary shape); the worker dies
		// immediately with the observed stderr.
		w, _ := startRealWorkerForTest(t, "echo fuse: failed to execute /bin/mount: Permission denied >&2; exit 4")
		return w, nil
	}
	runtimeDir := t.TempDir()
	p := workloadPreparation{RuntimeDir: runtimeDir, PinnedSources: []string{t.TempDir()}}
	_, err := b.prepareProjection(p, 0)
	if err == nil {
		t.Fatal("a projection whose worker exited before mounting must fail preparation")
	}
	if !strings.Contains(err.Error(), "bindfs projection worker exited before the projection mounted") ||
		!strings.Contains(err.Error(), "fuse: failed to execute /bin/mount: Permission denied") {
		t.Fatalf("the failure must name the worker exit and its stderr, got %v", err)
	}
	var retained *workloadMACRollbackRetainedError
	if errors.As(err, &retained) {
		t.Fatalf("a proven worker exit after the positive mount-absence proof must not be retained, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(runtimeDir, "mount-0")); !os.IsNotExist(statErr) {
		t.Errorf("the projection state must be released after the proven exit, got %v", statErr)
	}
}

// TestSELinuxPrepareProjectionRetainsUnprovenLiveWorkerExit proves the
// fail-closed side of the classification against a real still-running
// worker: the readiness proof fails while the worker is alive, the cleanup
// exit wait times out for real, and the partial state must be retained for
// reconciliation.
func TestSELinuxPrepareProjectionRetainsUnprovenLiveWorkerExit(t *testing.T) {
	b, seam := newTestSELinuxBackend(t)
	seam.typeErr = errors.New("xattr proof unavailable")
	var fixtureCmd *exec.Cmd
	b.startWorker = func(_ func(string) (string, error), _, mountpoint, _ string) (projectionWorker, error) {
		w, cmd := startRealWorkerForTest(t, "sleep 30")
		fixtureCmd = cmd
		seam.mounted[mountpoint] = true
		return w, nil
	}
	t.Cleanup(func() { killTestFixture(fixtureCmd) })
	runtimeDir := t.TempDir()
	p := workloadPreparation{RuntimeDir: runtimeDir, PinnedSources: []string{t.TempDir()}}
	_, err := b.prepareProjection(p, 0)
	if err == nil {
		t.Fatal("a projection whose live worker exit cannot be proven must fail preparation")
	}
	var retained *workloadMACRollbackRetainedError
	if !errors.As(err, &retained) {
		t.Fatalf("an unproven worker exit must classify as retained, got %v", err)
	}
	if !strings.Contains(err.Error(), "bindfs worker did not exit after unmount") {
		t.Errorf("the retained failure must name the unproven exit, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(runtimeDir, "mount-0")); statErr != nil {
		t.Errorf("the partial projection runtime state must be retained for reconciliation, got %v", statErr)
	}
}

// TestSELinuxCleanupProceedsForNaturallyExitedWorker proves no regression on
// the ordinary release path: the worker lives through the readiness proof,
// exits cleanly on its own, and the cleanup accepts the proven clean exit.
func TestSELinuxCleanupProceedsForNaturallyExitedWorker(t *testing.T) {
	b, seam := newTestSELinuxBackend(t)
	b.startWorker = func(_ func(string) (string, error), _, mountpoint, _ string) (projectionWorker, error) {
		w, _ := startRealWorkerForTest(t, "sleep 0.5; exit 0")
		seam.mounted[mountpoint] = true
		return w, nil
	}
	runtimeDir := t.TempDir()
	p := workloadPreparation{RuntimeDir: runtimeDir, PinnedSources: []string{t.TempDir()}}
	entry, err := b.prepareProjection(p, 0)
	if err != nil {
		t.Fatalf("a successful projection must prepare: %v", err)
	}
	if err := b.cleanupOwnedProjectionEntry(entry); err != nil {
		t.Fatalf("cleanup must accept the proven clean worker exit, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(runtimeDir, "mount-0")); !os.IsNotExist(statErr) {
		t.Errorf("the projection state must be released, got %v", statErr)
	}
}

// TestSELinuxCleanupRetainsFakeUnprovenWorkerExit pins the classification
// decision point with the fake worker: only the typed unproven error keeps
// the owned state reserved; a plain failure record is a proven exit.
func TestSELinuxCleanupRetainsFakeUnprovenWorkerExit(t *testing.T) {
	b, seam := newTestSELinuxBackend(t)
	b.startWorker = func(_ func(string) (string, error), _, mountpoint, _ string) (projectionWorker, error) {
		seam.mounted[mountpoint] = true
		return &testProjectionWorker{
			isAlive:     false,
			seam:        seam,
			mountpoint:  mountpoint,
			waitExitErr: &workerExitUnprovenError{timeout: workloadWorkerExitTimeout},
		}, nil
	}
	runtimeDir := t.TempDir()
	p := workloadPreparation{RuntimeDir: runtimeDir, PinnedSources: []string{t.TempDir()}}
	_, err := b.prepareProjection(p, 0)
	if err == nil {
		t.Fatal("a projection whose worker exit is unproven must fail preparation")
	}
	var retained *workloadMACRollbackRetainedError
	if !errors.As(err, &retained) {
		t.Fatalf("an unproven worker exit must classify as retained, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(runtimeDir, "mount-0")); statErr != nil {
		t.Errorf("the partial projection runtime state must be retained, got %v", statErr)
	}
}

// TestSELinuxCleanupAcceptsFakeProvenNonzeroWorkerExit pins the other side
// of the classification with the fake worker: a proven nonzero exit (a plain
// error record) releases the owned state after the mount-absence proof.
func TestSELinuxCleanupAcceptsFakeProvenNonzeroWorkerExit(t *testing.T) {
	b, seam := newTestSELinuxBackend(t)
	b.startWorker = func(_ func(string) (string, error), _, mountpoint, _ string) (projectionWorker, error) {
		seam.mounted[mountpoint] = true
		return &testProjectionWorker{
			isAlive:     false,
			seam:        seam,
			mountpoint:  mountpoint,
			waitExitErr: fmt.Errorf("bindfs worker exited with error: exit status 4 (stderr: synthetic)"),
		}, nil
	}
	runtimeDir := t.TempDir()
	p := workloadPreparation{RuntimeDir: runtimeDir, PinnedSources: []string{t.TempDir()}}
	_, err := b.prepareProjection(p, 0)
	if err == nil {
		t.Fatal("a projection whose worker exited before proving readiness must fail preparation")
	}
	var retained *workloadMACRollbackRetainedError
	if errors.As(err, &retained) {
		t.Fatalf("a proven worker exit must not be retained, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(runtimeDir, "mount-0")); !os.IsNotExist(statErr) {
		t.Errorf("the projection state must be released after the proven exit, got %v", statErr)
	}
}
