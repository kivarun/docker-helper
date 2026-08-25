package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestServeErrorPathDrainsAndClosesGate verifies that when server.Serve()
// returns an error without a shutdown signal, the daemon:
//  1. closes the operation gate automatically (no manual beginShutdown);
//  2. drains in-flight HTTP connections;
//  3. returns the original Serve error.
func TestServeErrorPathDrainsAndClosesGate(t *testing.T) {
	dir := t.TempDir()
	socketPath := dir + "/test.sock"

	supervisor := newOperationSupervisor()

	// Track whether the shutdown callback was invoked.
	var callbackCalled atomic.Bool

	// Create a handler that blocks until released.
	var handlerEntered sync.WaitGroup
	handlerEntered.Add(1)
	releaseHandler := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /block", func(w http.ResponseWriter, r *http.Request) {
		// Drain the request body so the connection stays clean.
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		handlerEntered.Done()
		// Block until the test releases us.
		<-releaseHandler
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{Handler: mux}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	signalCtx, signalCancel := context.WithCancel(context.Background())
	defer signalCancel()

	// Start serveHTTPUntilShutdown in a goroutine so we can close the listener
	// to trigger the Serve error path.
	type result struct {
		shutdownCtx    context.Context
		shutdownCancel func()
		drainDone      <-chan error
		serveErr       error
	}
	resultCh := make(chan result, 1)

	go func() {
		sc, scancel, dd, e := serveHTTPUntilShutdown(signalCtx, server, listener, nil, 3*time.Second, func() {
			callbackCalled.Store(true)
			supervisor.beginShutdown()
		})
		resultCh <- result{sc, scancel, dd, e}
	}()

	// Wait for Serve to start accepting connections.
	waitForDialReady(t, "unix", socketPath)

	// Connect a client that enters the blocking handler.
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send the blocking request.
	go func() {
		req, _ := http.NewRequest("POST", "/block", nil)
		req.Write(conn) //nolint:errcheck // best effort
	}()

	// Wait for the handler to enter.
	handlerEntered.Wait()

	// Close the listener to force Serve() to return an error.
	listener.Close()

	// Collect the result from serveHTTPUntilShutdown.
	res := <-resultCh

	// Verify the Serve error was returned.
	if res.serveErr == nil {
		t.Fatal("expected serve error")
	}

	// Verify the shutdown callback was called (operation gate closed).
	if !callbackCalled.Load() {
		t.Fatal("shutdown callback was not called on Serve error")
	}

	// Verify that the operation gate is now closed.
	op := newBuildOperation("test_session", "example:test", ".", "Dockerfile", 1024, "")
	if supervisor.admit(op) {
		t.Error("admit should fail after shutdown callback closes gate")
	}

	// Verify that drain is still in progress (handler hasn't finished yet).
	select {
	case <-res.drainDone:
		t.Fatal("drain should not complete while handler is still running")
	case <-time.After(100 * time.Millisecond):
		// Expected: drain is still waiting.
	}

	// Release the handler.
	close(releaseHandler)

	// Drain should now complete.
	select {
	case drainErr := <-res.drainDone:
		if drainErr != nil {
			t.Logf("drain error (may be expected): %v", drainErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not complete after handler released")
	}

	// Clean up.
	res.shutdownCancel()
}
