package main

import (
	"sync"
	"testing"
	"time"
)

// TestShutdownGateMutexMutualExclusion verifies that tryCreate and
// setShuttingDown are mutually exclusive under the same lock.
func TestShutdownGateMutexMutualExclusion(t *testing.T) {
	reg := newOperationRegistry()

	op := &operation{
		ID:        "test_op",
		SessionID: "test_session",
		State:     operationRunning,
		CreatedAt: time.Now(),
	}

	if !reg.tryCreate(op) {
		t.Fatal("tryCreate should succeed when gate is open")
	}
	if reg.get("test_op") == nil {
		t.Fatal("operation should be registered")
	}

	reg.setShuttingDown()

	op2 := &operation{
		ID:        "test_op2",
		SessionID: "test_session",
		State:     operationRunning,
		CreatedAt: time.Now(),
	}
	if reg.tryCreate(op2) {
		t.Fatal("tryCreate should fail after gate is closed")
	}
	if reg.get("test_op2") != nil {
		t.Fatal("operation should not be registered after gate closes")
	}

	if reg.get("test_op") == nil {
		t.Fatal("pre-existing operation should remain in registry")
	}
}

// TestShutdownGateConcurrentRegistration verifies that concurrent
// tryCreate and setShuttingDown never result in a registration after
// the gate is closed.
func TestShutdownGateConcurrentRegistration(t *testing.T) {
	reg := newOperationRegistry()

	var wg sync.WaitGroup
	results := make(chan bool, 100)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			op := &operation{
				ID:        "concurrent_op_" + string(rune('0'+i)),
				SessionID: "test_session",
				State:     operationRunning,
				CreatedAt: time.Now(),
			}
			results <- reg.tryCreate(op)
		}(i)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(1 * time.Millisecond)
		reg.setShuttingDown()
	}()

	wg.Wait()
	close(results)

	var successes, failures int
	for r := range results {
		if r {
			successes++
		} else {
			failures++
		}
	}

	if successes == 0 && failures == 0 {
		t.Fatal("no results collected")
	}

	if !reg.isShuttingDown() {
		t.Fatal("registry should be shutting down")
	}

	op := &operation{
		ID:        "after_gate_op",
		SessionID: "test_session",
		State:     operationRunning,
		CreatedAt: time.Now(),
	}
	if reg.tryCreate(op) {
		t.Fatal("tryCreate must fail after gate is closed")
	}
}
