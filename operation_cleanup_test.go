package main

import (
	"sync"
	"sync/atomic"
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

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var cleanerCount int64

	// Spawner: continuously create and complete operations.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
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

	// Pruner: continuously run retention pruning.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			supervisor.pruneCompleted(50*time.Millisecond, 50)
			atomic.AddInt64(&cleanerCount, 1)
		}
	}()

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()

	if cleanerCount == 0 {
		t.Error("cleaner goroutine did not execute")
	}
}
