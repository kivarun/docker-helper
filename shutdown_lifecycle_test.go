package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestShutdownGlobalDeadlineOwnership proves that for daemon shutdown,
// the operation's forceDeadline is non-zero and equal to the root shutdown deadline.
// Old code failed this because it used time.Now().Add(defaultForceCleanupTimeout).
func TestShutdownGlobalDeadlineOwnership(t *testing.T) {
	app, reg, _, token := setupBuildTest(t)

	readyFile := filepath.Join(app.Config.AllowedRoots[0], ".lifecycle_ready")
	defer os.Remove(readyFile)
	app.ExecCommandContext = makeIgnoringSignalCmd(t, readyFile)

	op := startBuild(t, app, token)
	waitProcessReady(t, readyFile)

	reg.setShuttingDown()

	// Short root deadline (200ms).
	shutdownDeadline := time.Now().Add(200 * time.Millisecond)
	shutdownCtx, cancel := context.WithDeadline(context.Background(), shutdownDeadline)

	reg.terminateAll(shutdownCtx, nil)
	cancel()

	// Verify: forceDeadline is non-zero and equals the root shutdown deadline.
	op.mu.Lock()
	forceDL := op.forceDeadline
	op.mu.Unlock()

	if forceDL.IsZero() {
		t.Fatal("forceDeadline must be non-zero for shutdown")
	}
	if !forceDL.Equal(shutdownDeadline) {
		t.Errorf("forceDeadline %v != root shutdown deadline %v", forceDL, shutdownDeadline)
	}

	op.Wait()
	if op.State != operationFailed {
		t.Errorf("expected status 'failed', got %q", op.State)
	}
}

// TestShutdownTwoStuckOpsOneBudget proves that two stuck operations
// are terminated within one wall-clock shutdown budget, not sequentially.
func TestShutdownTwoStuckOpsOneBudget(t *testing.T) {
	app := newTestAppWithAuth(t)
	reg := newOperationRegistry()
	app.OperationRegistry = reg

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Create two run operations that ignore SIGTERM.
	readyDir := t.TempDir()
	readyFile1 := filepath.Join(readyDir, "ready1")
	readyFile2 := filepath.Join(readyDir, "ready2")

	makeIgnoringCmd := func(readyFile string) func(context.Context, string, ...string) *exec.Cmd {
		return func(ctx context.Context, name string, args ...string) *exec.Cmd {
			cmd := exec.Command("sh", "-c",
				"trap ':' TERM; touch "+readyFile+"; while :; do :; done")
			return cmd
		}
	}

	// Start first operation.
	app.ExecCommandContext = makeIgnoringCmd(readyFile1)
	op1 := newRunOperation(result.Session.ID, "test:image1", 4*1024*1024, "")
	if !reg.tryCreate(op1) {
		t.Fatal("tryCreate op1 failed")
	}
	cmd1 := app.newOperationCmd(context.Background(), "sh", "-c",
		"trap ':' TERM; touch "+readyFile1+"; while :; do :; done")
	res1 := startOperationProcess(cmd1, op1)
	if res1.Terminated || res1.Err != nil {
		t.Fatalf("start op1: terminated=%v err=%v", res1.Terminated, res1.Err)
	}
	go func() {
		cmd1.Wait()
		exitCode := 137
		op1.fail("docker_run_failed", "docker run failed", &exitCode, nil)
	}()

	// Start second operation.
	app.ExecCommandContext = makeIgnoringCmd(readyFile2)
	op2 := newRunOperation(result.Session.ID, "test:image2", 4*1024*1024, "")
	if !reg.tryCreate(op2) {
		t.Fatal("tryCreate op2 failed")
	}
	cmd2 := app.newOperationCmd(context.Background(), "sh", "-c",
		"trap ':' TERM; touch "+readyFile2+"; while :; do :; done")
	res2 := startOperationProcess(cmd2, op2)
	if res2.Terminated || res2.Err != nil {
		t.Fatalf("start op2: terminated=%v err=%v", res2.Terminated, res2.Err)
	}
	go func() {
		cmd2.Wait()
		exitCode := 137
		op2.fail("docker_run_failed", "docker run failed", &exitCode, nil)
	}()

	// Wait for both processes to signal readiness.
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(readyFile1); err == nil {
			if _, err := os.Stat(readyFile2); err == nil {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := os.Stat(readyFile1); err != nil {
		t.Fatal("op1 did not become ready")
	}
	if _, err := os.Stat(readyFile2); err != nil {
		t.Fatal("op2 did not become ready")
	}

	reg.setShuttingDown()

	// Short shutdown deadline (300ms).
	shutdownBudget := 300 * time.Millisecond
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownBudget)
	start := time.Now()
	reg.terminateAll(shutdownCtx, nil)
	cancel()
	elapsed := time.Since(start)

	// Wait for both operations to complete.
	for _, op := range []*operation{op1, op2} {
		select {
		case <-op.done:
		case <-time.After(5 * time.Second):
			t.Fatal("operation did not complete")
		}
	}

	// Verify: total shutdown time is within the budget plus small tolerance.
	// Must NOT be 2x the budget (sequential force cleanup).
	tolerance := 200 * time.Millisecond
	if elapsed > shutdownBudget+tolerance {
		t.Errorf("shutdown took %v, expected within %v (budget %v + tolerance %v); sequential cleanup suspected",
			elapsed, shutdownBudget+tolerance, shutdownBudget, tolerance)
	}

	// Verify: both processes are killed.
	for _, op := range []*operation{op1, op2} {
		if op.State != operationFailed {
			t.Errorf("op state = %q, want failed", op.State)
		}
	}
}

// TestShutdownRunContainerCleanup proves that with two run operations
// and synthetic cidfiles, daemon-side kill is called at most once per
// operation, both cleanup callbacks proceed concurrently, and no operation
// gets a fresh deadline.
func TestShutdownRunContainerCleanup(t *testing.T) {
	app := newTestAppWithAuth(t)
	reg := newOperationRegistry()
	app.OperationRegistry = reg

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Create synthetic cidfiles.
	cidfile1 := filepath.Join(app.Config.RuntimeDir, "op1.cid")
	cidfile2 := filepath.Join(app.Config.RuntimeDir, "op2.cid")
	testContainerID1 := "test-container-1"
	testContainerID2 := "test-container-2"
	if err := os.WriteFile(cidfile1, []byte(testContainerID1), 0644); err != nil {
		t.Fatalf("write cidfile1: %v", err)
	}
	if err := os.WriteFile(cidfile2, []byte(testContainerID2), 0644); err != nil {
		t.Fatalf("write cidfile2: %v", err)
	}

	// Track kill invocations.
	var killCount int32
	var killIDs []string
	var killMu sync.Mutex
	fakeKill := func(ctx context.Context, cid string) {
		atomic.AddInt32(&killCount, 1)
		killMu.Lock()
		killIDs = append(killIDs, cid)
		killMu.Unlock()
	}

	// Create two run operations with cidfiles.
	op1 := newRunOperation(result.Session.ID, "test:image1", 4*1024*1024, "")
	op1.cidfile = cidfile1
	op1.started = true
	ready1 := filepath.Join(t.TempDir(), "op1.ready")
	cmd1 := exec.Command("sh", "-c", "trap ':' TERM; touch "+ready1+"; while :; do :; done")
	if err := cmd1.Start(); err != nil {
		t.Fatalf("start cmd1: %v", err)
	}
	op1.cmd = cmd1
	reg.mu.Lock()
	reg.ops[op1.ID] = op1
	reg.mu.Unlock()

	op2 := newRunOperation(result.Session.ID, "test:image2", 4*1024*1024, "")
	op2.cidfile = cidfile2
	op2.started = true
	ready2 := filepath.Join(t.TempDir(), "op2.ready")
	cmd2 := exec.Command("sh", "-c", "trap ':' TERM; touch "+ready2+"; while :; do :; done")
	if err := cmd2.Start(); err != nil {
		t.Fatalf("start cmd2: %v", err)
	}
	op2.cmd = cmd2
	reg.mu.Lock()
	reg.ops[op2.ID] = op2
	reg.mu.Unlock()

	// Wait for both processes to install their SIGTERM trap, so the
	// graceful phase reliably finds them alive and force cleanup runs.
	waitProcessReady(t, ready1)
	waitProcessReady(t, ready2)

	// Completion goroutines.
	go func() {
		cmd1.Wait()
		exitCode := 137
		op1.fail("docker_run_failed", "docker run failed", &exitCode, nil)
	}()
	go func() {
		cmd2.Wait()
		exitCode := 137
		op2.fail("docker_run_failed", "docker run failed", &exitCode, nil)
	}()

	reg.setShuttingDown()

	// Short shutdown deadline.
	shutdownBudget := 300 * time.Millisecond
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownBudget)
	start := time.Now()
	reg.terminateAll(shutdownCtx, fakeKill)
	cancel()
	elapsed := time.Since(start)

	// Wait for operations to complete.
	for _, op := range []*operation{op1, op2} {
		select {
		case <-op.done:
		case <-time.After(5 * time.Second):
			t.Fatal("operation did not complete")
		}
	}

	// Verify: shutdown within budget.
	tolerance := 200 * time.Millisecond
	if elapsed > shutdownBudget+tolerance {
		t.Errorf("shutdown took %v, expected within %v", elapsed, shutdownBudget+tolerance)
	}

	// Verify: daemon-side kill called exactly once per operation.
	killCalls := atomic.LoadInt32(&killCount)
	if killCalls != 2 {
		t.Errorf("killContainer invoked %d times, want 2 (one per operation)", killCalls)
	}

	// Verify: correct container IDs.
	killMu.Lock()
	seenIDs := make(map[string]int)
	for _, id := range killIDs {
		seenIDs[id]++
	}
	killMu.Unlock()

	if seenIDs[testContainerID1] != 1 {
		t.Errorf("container %q killed %d times, want 1", testContainerID1, seenIDs[testContainerID1])
	}
	if seenIDs[testContainerID2] != 1 {
		t.Errorf("container %q killed %d times, want 1", testContainerID2, seenIDs[testContainerID2])
	}

	// Clean up.
	os.Remove(cidfile1)
	os.Remove(cidfile2)
}
