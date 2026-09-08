package main

import (
	"context"
	"testing"
	"time"
)

// TestSyncExecutionCoordinatorAdmitAndEnd proves admission derives a live
// request context and end releases it, so shutdown termination has nothing
// left to wait for.
func TestSyncExecutionCoordinatorAdmitAndEnd(t *testing.T) {
	coord := newSyncExecutionCoordinator()

	ctx, req, ok := coord.admit(context.Background())
	if !ok {
		t.Fatal("admission refused while shutdown is closed")
	}
	if ctx.Err() != nil {
		t.Fatalf("admitted context is already cancelled: %v", ctx.Err())
	}

	req.end()
	if ctx.Err() == nil {
		t.Error("end must cancel the admitted request context")
	}

	terminated := make(chan struct{})
	go func() {
		coord.terminateForShutdown(context.Background())
		close(terminated)
	}()
	select {
	case <-terminated:
	case <-time.After(2 * time.Second):
		t.Fatal("terminateForShutdown waited for a released request")
	}
}

// TestSyncExecutionCoordinatorShutdownRefusesAdmission proves the shutdown
// gate closes admission and admit reports the refusal to the caller.
func TestSyncExecutionCoordinatorShutdownRefusesAdmission(t *testing.T) {
	coord := newSyncExecutionCoordinator()
	coord.beginShutdown()

	_, _, ok := coord.admit(context.Background())
	if ok {
		t.Fatal("admission must be refused after shutdown began")
	}
}

// TestSyncExecutionCoordinatorTerminateCancelsLiveRequests proves daemon
// shutdown cancels every live request context and waits for the owning
// handler to release it.
func TestSyncExecutionCoordinatorTerminateCancelsLiveRequests(t *testing.T) {
	coord := newSyncExecutionCoordinator()

	ctx, req, ok := coord.admit(context.Background())
	if !ok {
		t.Fatal("admission refused while shutdown is closed")
	}
	released := make(chan struct{})
	go func() {
		<-ctx.Done()
		req.end()
		close(released)
	}()

	terminated := make(chan struct{})
	go func() {
		coord.terminateForShutdown(context.Background())
		close(terminated)
	}()
	select {
	case <-terminated:
	case <-time.After(2 * time.Second):
		t.Fatal("terminateForShutdown did not cancel and release the live request")
	}
	<-released
}

// TestSyncExecutionCoordinatorTerminateAbandonsPastDeadline proves
// termination is bounded by the shutdown deadline: a handler that has not
// released its request by then is abandoned instead of blocking shutdown.
func TestSyncExecutionCoordinatorTerminateAbandonsPastDeadline(t *testing.T) {
	coord := newSyncExecutionCoordinator()

	_, req, ok := coord.admit(context.Background())
	if !ok {
		t.Fatal("admission refused while shutdown is closed")
	}

	termCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	terminated := make(chan struct{})
	go func() {
		coord.terminateForShutdown(termCtx)
		close(terminated)
	}()
	select {
	case <-terminated:
	case <-time.After(2 * time.Second):
		t.Fatal("terminateForShutdown did not honor its deadline")
	}

	// The handler releases only after termination already gave up.
	req.end()
}

// TestSyncExecutionCoordinatorLauncherScopedAdmission proves the
// Launcher-scoped admission contract: a quiesced Launcher is refused with the
// quiesced decision, an open Launcher is admitted with its Launcher tagged,
// and the tagged request is visible to checked parent-lifecycle inspection
// until it ends.
func TestSyncExecutionCoordinatorLauncherScopedAdmission(t *testing.T) {
	c := newSyncExecutionCoordinator()

	quiesced := map[string]bool{"la": true}
	quiesceClosed := func(launcherID string) bool { return quiesced[launcherID] }

	if _, _, decision := c.admitLauncherScoped(context.Background(), "la", quiesceClosed); decision != admissionRefusedQuiesced {
		t.Fatalf("quiesced admission decision = %v, want refused-quiesced", decision)
	}

	_, req, decision := c.admitLauncherScoped(context.Background(), "lb", quiesceClosed)
	if decision != admissionAccepted {
		t.Fatalf("open admission decision = %v, want accepted", decision)
	}
	if !c.hasLiveForLauncher("lb") {
		t.Error("the admitted request must be visible to Launcher inspection while live")
	}
	if c.hasLiveForLauncher("la") {
		t.Error("a refused request must not be visible")
	}
	if c.hasLiveForLauncher("other") {
		t.Error("a foreign Launcher must not see live work")
	}

	req.end()
	if c.hasLiveForLauncher("lb") {
		t.Error("the ended request must no longer be live")
	}
}

// TestSyncExecutionCoordinatorShutdownRefusesLauncherScopedAdmission proves
// the shutdown gate wins for Launcher-scoped admission as well.
func TestSyncExecutionCoordinatorShutdownRefusesLauncherScopedAdmission(t *testing.T) {
	c := newSyncExecutionCoordinator()
	c.beginShutdown()

	if _, _, decision := c.admitLauncherScoped(context.Background(), "lb", func(string) bool { return false }); decision != admissionRefusedShutdown {
		t.Fatalf("shutdown admission decision = %v, want refused-shutdown", decision)
	}
}
