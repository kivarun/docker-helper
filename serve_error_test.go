package main

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestServeErrorPathTerminatesOperations verifies that when server.Serve()
// returns an error without a shutdown signal, running operations are still
// terminated and no panic occurs.
func TestServeErrorPathTerminatesOperations(t *testing.T) {
	dir := t.TempDir()
	socketPath := dir + "/test.sock"

	reg := newOperationRegistry()

	// Create a running operation that hasn't started a process yet.
	op := newBuildOperation("test_session", "example:test", ".", "Dockerfile", 1024)
	reg.create(op)
	// op.started is false by default — simulate pre-start state.

	// Create a server and listener.
	mux := http.NewServeMux()
	server := &http.Server{Handler: mux}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	signalCtx, signalCancel := context.WithCancel(context.Background())
	defer signalCancel()

	// Close the listener to force Serve to error out.
	listener.Close()

	// serveWithShutdown will get the serve error (not signal path).
	shutdownCtx, shutdownCancel, err := serveWithShutdown(signalCtx, server, listener, 2*time.Second, func() {
		reg.setShuttingDown()
	})
	defer shutdownCancel()

	// serveWithShutdown should return the serve error.
	if err == nil {
		t.Fatal("expected serve error")
	}

	// shutdownCtx should be valid (not nil).
	if shutdownCtx == nil {
		t.Fatal("shutdownCtx must not be nil on serve error path")
	}

	// terminateAll should not panic with the returned context.
	reg.setShuttingDown()
	reg.terminateAll(shutdownCtx)

	// The operation should have been handled (no panic).
	// Since op.cmd is nil, terminateAll marks it as terminated.
	op.mu.Lock()
	terminated := op.terminated
	op.mu.Unlock()
	if !terminated {
		t.Error("operation should be marked as terminated")
	}
}
