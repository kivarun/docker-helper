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

func TestCleanupRemovesExpired(t *testing.T) {
	reg := newOperationRegistry()

	now := time.Now()
	expired := newTestOperation(t, operationSucceeded, now.Add(-11*time.Minute))
	fresh := newTestOperation(t, operationSucceeded, now.Add(-1*time.Minute))
	running := newTestOperation(t, operationRunning, time.Time{})

	reg.tryCreate(expired)
	reg.tryCreate(fresh)
	reg.tryCreate(running)

	reg.cleanup(10*time.Minute, 200)

	if reg.get(expired.ID) != nil {
		t.Error("expired operation should be removed")
	}
	if reg.get(fresh.ID) == nil {
		t.Error("fresh operation should remain")
	}
	if reg.get(running.ID) == nil {
		t.Error("running operation should remain")
	}
}

func TestCleanupCapsCompleted(t *testing.T) {
	reg := newOperationRegistry()

	now := time.Now()
	ops := make([]*operation, 5)
	for i := range ops {
		ops[i] = newTestOperation(t, operationSucceeded, now.Add(time.Duration(i)*time.Minute))
		reg.tryCreate(ops[i])
	}

	reg.cleanup(10*time.Minute, 3)

	// Oldest 2 should be removed, newest 3 remain.
	for i := 0; i < 2; i++ {
		if reg.get(ops[i].ID) != nil {
			t.Errorf("operation %d should be removed by cap", i)
		}
	}
	for i := 2; i < 5; i++ {
		if reg.get(ops[i].ID) == nil {
			t.Errorf("operation %d should remain", i)
		}
	}
}

func TestCleanupMaxCompletedZero(t *testing.T) {
	reg := newOperationRegistry()

	now := time.Now()
	op1 := newTestOperation(t, operationSucceeded, now.Add(-1*time.Minute))
	op2 := newTestOperation(t, operationSucceeded, now.Add(-2*time.Minute))
	running := newTestOperation(t, operationRunning, time.Time{})

	reg.tryCreate(op1)
	reg.tryCreate(op2)
	reg.tryCreate(running)

	reg.cleanup(10*time.Minute, 0)

	if reg.get(op1.ID) != nil {
		t.Error("completed operation should be removed when maxCompleted=0")
	}
	if reg.get(op2.ID) != nil {
		t.Error("completed operation should be removed when maxCompleted=0")
	}
	if reg.get(running.ID) == nil {
		t.Error("running operation should remain when maxCompleted=0")
	}
}

func TestCleanupConcurrency(t *testing.T) {
	reg := newOperationRegistry()

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
			if reg.tryCreate(op) {
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

	// Cleaner: continuously run cleanup.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			reg.cleanup(50*time.Millisecond, 50)
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
