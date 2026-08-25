package main

import (
	"sync"
	"testing"
	"time"
)

// newTestOperation creates an operation with the given state and completedAt.
// If completedAt is zero, the field is nil.
func newTestOperation(t *testing.T, state operationState, completedAt time.Time) *operation {
	t.Helper()
	op := &operation{
		ID:        generateOperationID(),
		SessionID: "test-session",
		Kind:      "build",
		State:     state,
		CreatedAt: time.Now(),
		done:      make(chan struct{}),
		LogBuffer: newBoundedBuffer(1024),
	}
	if !completedAt.IsZero() {
		op.CompletedAt = &completedAt
		op.ResultCode = ptrOf("succeeded")
	}
	return op
}

func TestPruneCompletedRemovesExpired(t *testing.T) {
	supervisor := newOperationSupervisor()

	now := time.Now()
	expired := newTestOperation(t, operationSucceeded, now.Add(-11*time.Minute))
	fresh := newTestOperation(t, operationSucceeded, now.Add(-1*time.Minute))
	running := newTestOperation(t, operationRunning, time.Time{})

	supervisor.admit(expired)
	supervisor.admit(fresh)
	supervisor.admit(running)

	supervisor.pruneCompleted(10*time.Minute, 200)

	if supervisor.lookup(expired.ID) != nil {
		t.Error("expired operation should be removed")
	}
	if supervisor.lookup(fresh.ID) == nil {
		t.Error("fresh operation should remain")
	}
	if supervisor.lookup(running.ID) == nil {
		t.Error("running operation should remain")
	}
}

func TestPruneCompletedCapsCompleted(t *testing.T) {
	supervisor := newOperationSupervisor()

	now := time.Now()
	ops := make([]*operation, 5)
	for i := range ops {
		ops[i] = newTestOperation(t, operationSucceeded, now.Add(time.Duration(i)*time.Minute))
		supervisor.admit(ops[i])
	}

	supervisor.pruneCompleted(10*time.Minute, 3)

	// Oldest 2 should be removed, newest 3 remain.
	for i := 0; i < 2; i++ {
		if supervisor.lookup(ops[i].ID) != nil {
			t.Errorf("operation %d should be removed by cap", i)
		}
	}
	for i := 2; i < 5; i++ {
		if supervisor.lookup(ops[i].ID) == nil {
			t.Errorf("operation %d should remain", i)
		}
	}
}

func TestPruneCompletedMaxCompletedZero(t *testing.T) {
	supervisor := newOperationSupervisor()

	now := time.Now()
	op1 := newTestOperation(t, operationSucceeded, now.Add(-1*time.Minute))
	op2 := newTestOperation(t, operationSucceeded, now.Add(-2*time.Minute))
	running := newTestOperation(t, operationRunning, time.Time{})

	supervisor.admit(op1)
	supervisor.admit(op2)
	supervisor.admit(running)

	supervisor.pruneCompleted(10*time.Minute, 0)

	if supervisor.lookup(op1.ID) != nil {
		t.Error("completed operation should be removed when maxCompleted=0")
	}
	if supervisor.lookup(op2.ID) != nil {
		t.Error("completed operation should be removed when maxCompleted=0")
	}
	if supervisor.lookup(running.ID) == nil {
		t.Error("running operation should remain when maxCompleted=0")
	}
}

func TestPruneCompletedConcurrency(t *testing.T) {
	supervisor := newOperationSupervisor()

	// Pre-seed known operations before any concurrent work.
	expired := newTestOperation(t, operationSucceeded, time.Now().Add(-time.Hour))
	running := newTestOperation(t, operationRunning, time.Time{})
	supervisor.admit(expired)
	supervisor.admit(running)

	const iterations = 100
	start := make(chan struct{})
	var wg sync.WaitGroup

	// Spawner: create and complete operations concurrently.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			op := newTestOperation(t, operationRunning, time.Time{})
			if supervisor.admit(op) {
				// Complete the operation.
				op.mu.Lock()
				now := time.Now()
				op.State = operationSucceeded
				op.CompletedAt = &now
				rc := "succeeded"
				op.ResultCode = &rc
				op.mu.Unlock()
				close(op.done)
			}
		}
	}()

	// Pruner: run retention pruning concurrently.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			supervisor.pruneCompleted(50*time.Millisecond, 50)
		}
	}()

	close(start)
	wg.Wait()

	if supervisor.lookup(expired.ID) != nil {
		t.Error("eligible completed operation was not pruned under concurrent access")
	}
	if supervisor.lookup(running.ID) == nil {
		t.Error("running operation was removed by concurrent pruning")
	}
}
