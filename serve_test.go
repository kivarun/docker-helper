package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestLockSecondCannotAcquire(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "test.lock")

	f1, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("first acquireLock() error: %v", err)
	}

	_, err = acquireLock(lockPath)
	if err == nil {
		f1.Close()
		t.Fatal("expected error when acquiring second lock")
	}

	if got := err.Error(); got != "another docker-helper instance is already running" {
		f1.Close()
		t.Errorf("unexpected error: %v", err)
	}

	f1.Close()
}

func TestSecondLaunchDoesNotDeleteSocket(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "test.lock")
	socketPath := filepath.Join(dir, "test.sock")

	f1, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("acquireLock() error: %v", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("net.Listen() error: %v", err)
	}

	exists := fileExists(socketPath)
	if !exists {
		listener.Close()
		f1.Close()
		t.Fatal("socket should exist after Listen")
	}

	_, err = acquireLock(lockPath)
	if err == nil {
		listener.Close()
		f1.Close()
		t.Fatal("expected error when acquiring second lock")
	}

	exists = fileExists(socketPath)
	if !exists {
		listener.Close()
		f1.Close()
		t.Error("socket should still exist after second lock attempt fails")
	}

	listener.Close()
	f1.Close()
}

func TestLockReacquireAfterRelease(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "test.lock")

	f1, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("first acquireLock() error: %v", err)
	}

	f1.Close()

	f2, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("re-acquireLock() error: %v", err)
	}

	f2.Close()
}

func TestPrepareListenerStaleSocket(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	f, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("cannot create socket: %v", err)
	}

	addr := &syscall.SockaddrUnix{Name: socketPath}
	if err := syscall.Bind(f, addr); err != nil {
		syscall.Close(f)
		t.Fatalf("cannot bind socket: %v", err)
	}
	syscall.Close(f)

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Fatal("stale socket should still exist on disk after Close")
	}

	listener, created, err := prepareListener(socketPath)
	if err != nil {
		t.Fatalf("prepareListener() error: %v", err)
	}
	defer listener.Close()
	if !created {
		t.Error("should report socket created")
	}

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Fatal("new socket should exist")
	}
}

func TestPrepareListenerLiveSocket(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("net.Listen() error: %v", err)
	}
	defer listener.Close()

	_, created, err := prepareListener(socketPath)
	if err == nil {
		t.Fatal("expected error when socket has a live listener")
	}
	if created {
		t.Error("should not report socket created when live socket exists")
	}

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("live socket should not be deleted")
	}
}

func TestPrepareListenerRegularFile(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	if err := os.WriteFile(socketPath, nil, 0600); err != nil {
		t.Fatalf("cannot create file: %v", err)
	}

	_, created, err := prepareListener(socketPath)
	if err == nil {
		t.Fatal("expected error when socket path is a regular file")
	}
	if created {
		t.Error("should not report socket created for regular file")
	}

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("regular file should not be deleted")
	}
}

func TestPrepareListenerDirectory(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	if err := os.Mkdir(socketPath, 0700); err != nil {
		t.Fatalf("cannot create directory: %v", err)
	}

	_, created, err := prepareListener(socketPath)
	if err == nil {
		t.Fatal("expected error when socket path is a directory")
	}
	if created {
		t.Error("should not report socket created for directory")
	}
}

func TestPrepareListenerNewSocket(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	listener, created, err := prepareListener(socketPath)
	if err != nil {
		t.Fatalf("prepareListener() error: %v", err)
	}
	defer listener.Close()
	if !created {
		t.Error("should report socket created")
	}

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("socket should exist: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Error("created path should be a Unix socket")
	}
}

func TestLockFileNotDeletedOnRelease(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "test.lock")

	f, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("acquireLock() error: %v", err)
	}

	f.Close()

	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
		t.Error("lock file should not be deleted after release")
	}
}

func TestLockHeldDuringServe(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "test.lock")

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("cannot open lock file: %v", err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		t.Fatalf("cannot lock: %v", err)
	}

	otherFD, err := syscall.Open(lockPath, syscall.O_RDWR, 0600)
	if err != nil {
		f.Close()
		t.Fatalf("cannot open lock for check: %v", err)
	}

	err = syscall.Flock(otherFD, syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		syscall.Close(otherFD)
		f.Close()
		t.Error("second lock should fail while first is held")
	}

	syscall.Close(otherFD)
	f.Close()
}

func TestCheckSocketLive(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("net.Listen() error: %v", err)
	}
	defer listener.Close()

	live, err := checkSocket(socketPath)
	if err != nil {
		t.Fatalf("checkSocket() error: %v", err)
	}
	if !live {
		t.Error("listening socket should be detected as live")
	}
}

func TestCheckSocketECONNREFUSED(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	f, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("cannot create socket: %v", err)
	}
	addr := &syscall.SockaddrUnix{Name: socketPath}
	if err := syscall.Bind(f, addr); err != nil {
		syscall.Close(f)
		t.Fatalf("cannot bind socket: %v", err)
	}
	syscall.Close(f)

	live, err := checkSocket(socketPath)
	if err != nil {
		t.Fatalf("checkSocket() error: %v", err)
	}
	if live {
		t.Error("stale socket should not be detected as live")
	}
}

func TestCheckSocketUnknownError(t *testing.T) {
	orig := dialUnixFunc
	defer func() { dialUnixFunc = orig }()

	dialUnixFunc = func(addr string, timeout time.Duration) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "unix", Err: syscall.EACCES}
	}

	live, err := checkSocket("/tmp/does-not-matter.sock")
	if err == nil {
		t.Fatal("expected error for unknown dial error")
	}
	if live {
		t.Error("should not report live on error")
	}
}

func TestPrepareListenerUnknownDialError(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	f, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("cannot create socket: %v", err)
	}
	addr := &syscall.SockaddrUnix{Name: socketPath}
	if err := syscall.Bind(f, addr); err != nil {
		syscall.Close(f)
		t.Fatalf("cannot bind socket: %v", err)
	}
	syscall.Close(f)

	orig := dialUnixFunc
	defer func() { dialUnixFunc = orig }()

	dialUnixFunc = func(a string, timeout time.Duration) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "unix", Err: errors.New("unexpected failure")}
	}

	_, created, err := prepareListener(socketPath)
	if err == nil {
		t.Fatal("expected error from prepareListener on unknown dial error")
	}
	if created {
		t.Error("should not report socket created on unknown dial error")
	}

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("socket should not be deleted on unknown dial error")
	}
}

func TestSocketDisappearsDuringCheck(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	sa := &syscall.SockaddrUnix{Name: socketPath}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		t.Fatalf("Bind: %v", err)
	}
	syscall.Close(fd)

	orig := dialUnixFunc
	defer func() { dialUnixFunc = orig }()

	dialUnixFunc = func(a string, timeout time.Duration) (net.Conn, error) {
		os.Remove(socketPath)
		return nil, &net.OpError{Op: "dial", Net: "unix", Err: errors.New("unexpected")}
	}

	listener, created, err := prepareListener(socketPath)
	if err != nil {
		t.Fatalf("prepareListener: %v", err)
	}
	defer listener.Close()
	if !created {
		t.Error("should report socket created")
	}
}

// --- Lifecycle tests using runWithLock ---

// Callback error: lock released, socket removed, lock file remains.
func TestStartupErrorReleasesLock(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	lockPath := socketPath + ".lock"

	err := runWithLock(lockPath, func() error {
		return errors.New("simulated startup error")
	})
	if err == nil {
		t.Fatal("expected error from runWithLock")
	}

	// Lock must be released.
	lockFile, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("lock not released after error: %v", err)
	}
	lockFile.Close()

	// Socket must be removed.
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("socket should be removed after callback error")
	}

	// Lock file must remain.
	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
		t.Error("lock file should remain after callback error")
	}
}

// Normal callback return: socket removed, lock file remains, flock released.
func TestCallbackReturnCleansSocket(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	lockPath := socketPath + ".lock"

	err := runWithLock(lockPath, func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("runWithLock: %v", err)
	}

	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("socket should be removed after callback returns")
	}

	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
		t.Error("lock file should remain")
	}

	lockFile, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("flock not released: %v", err)
	}
	lockFile.Close()
}

// prepareListener error inside runWithLock: callback not called, lock released,
// regular file untouched (content, size, mode), lock file remains.
func TestPrepareListenerErrorReleasesLock(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	lockPath := socketPath + ".lock"

	// Place a regular file where the socket would be.
	const stub = "stub"
	if err := os.WriteFile(socketPath, []byte(stub), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	before := mustStat(t, socketPath)

	// Callback that tries to create a listener where a regular file exists.
	called := false
	err := runWithLock(lockPath, func() error {
		called = true
		_, err := net.Listen("unix", socketPath)
		return err
	})
	if err == nil {
		t.Fatal("expected error from runWithLock")
	}
	if !called {
		t.Error("callback must be called; listener creation error should propagate")
	}

	// Regular file must be untouched: size, mode, and content.
	after := mustStat(t, socketPath)
	if before.Size() != after.Size() || before.Mode() != after.Mode() {
		t.Error("regular file must not be modified")
	}
	data, err := os.ReadFile(socketPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != stub {
		t.Errorf("file content = %q, want %q", string(data), stub)
	}

	// Lock must be released.
	lockFile, err := acquireLock(lockPath)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	lockFile.Close()

	// Lock file must remain.
	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
		t.Error("lock file should remain")
	}
}

// After first instance finishes, a subsequent startup is possible.
func TestSubsequentStartupAfterShutdown(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	lockPath := socketPath + ".lock"

	err := runWithLock(lockPath, func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("first runWithLock: %v", err)
	}

	err = runWithLock(lockPath, func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("second runWithLock: %v", err)
	}
}

// Parallel startup: one holder keeps the lock; competitors all fail;
// after release the holder cleans up and a subsequent start works.
func TestParallelStartupRace(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	lockPath := socketPath + ".lock"

	const competitors = 8

	// --- Phase 1: start the holder and wait for it to enter the callback ---
	holderStarted := make(chan struct{})
	holderProceed := make(chan struct{})
	holderResult := make(chan error, 1)
	holderDone := make(chan struct{})

	go func() {
		defer close(holderDone)
		holderResult <- runWithLock(lockPath, func() error {
			close(holderStarted)
			// Create a listener so the socket exists.
			listener, err := net.Listen("unix", socketPath)
			if err != nil {
				return err
			}
			defer listener.Close()
			defer os.Remove(socketPath)
			<-holderProceed
			return nil
		})
	}()

	var proceedOnce sync.Once
	t.Cleanup(func() {
		proceedOnce.Do(func() { close(holderProceed) })
		<-holderDone
	})

	// Wait for holder to enter callback or fail prematurely.
	select {
	case <-holderStarted:
		// Holder is in the callback, holding the lock.
	case err := <-holderResult:
		t.Fatalf("holder runWithLock returned before callback: %v", err)
	}

	// Socket must exist while the holder is active.
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Fatal("socket should exist while holder is active")
	}

	// --- Phase 2: launch competitors while holder blocks ---
	compReady := make(chan struct{}, competitors)
	compGo := make(chan struct{})
	compResults := make(chan error, competitors)
	compCallbackCalled := make(chan bool, competitors)

	for i := 0; i < competitors; i++ {
		go func() {
			compReady <- struct{}{}
			<-compGo

			err := runWithLock(lockPath, func() error {
				compCallbackCalled <- true
				return nil
			})
			compResults <- err
		}()
	}

	// Wait for all competitors to be ready (before they attempt the lock).
	for i := 0; i < competitors; i++ {
		<-compReady
	}

	// Release all competitors simultaneously.
	close(compGo)

	// Collect all competitor results BEFORE releasing the holder.
	for i := 0; i < competitors; i++ {
		err := <-compResults
		if err == nil {
			t.Errorf("competitor %d should fail, got nil", i)
		}
	}

	// No competitor callback should have been called.
	select {
	case called := <-compCallbackCalled:
		t.Fatalf("competitor callback must not be called (called=%v)", called)
	default:
	}

	// Socket must still exist (competitors must not have deleted it).
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("socket should exist while holder blocks competitors")
	}

	// --- Phase 3: release the holder and verify result ---
	proceedOnce.Do(func() { close(holderProceed) })

	// Read holder result exactly once (buffered channel).
	holderErr := <-holderResult
	if holderErr != nil {
		t.Fatalf("holder runWithLock returned error: %v", holderErr)
	}

	// Holder must have cleaned up the socket.
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("socket should be removed after holder completes")
	}

	// --- Phase 4: subsequent startup must work ---
	err := runWithLock(lockPath, func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("subsequent runWithLock: %v", err)
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// --- Graceful shutdown tests ---

// After shutdown starts, new connections are rejected.
func TestGracefulShutdownRejectsNewConnections(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	mux := http.NewServeMux()
	server := &http.Server{Handler: mux}
	signalCtx, signalCancel := context.WithCancel(context.Background())

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer os.Remove(socketPath)

	serveDone := make(chan error, 1)
	go func() {
		_, shutdownCancel, drainCh, serveDoneErr := serveWithShutdown(signalCtx, server, listener, 30*time.Second, nil)
		<-drainCh
		shutdownCancel()
		serveDone <- serveDoneErr
	}()

	// Initiate shutdown before any connections.
	signalCancel()

	err = <-serveDone
	if err != nil {
		t.Fatalf("serveWithShutdown: %v", err)
	}

	// New connection must fail.
	if _, err := net.Dial("unix", socketPath); err == nil {
		t.Fatal("connection should be rejected after shutdown")
	}
}

// After graceful shutdown, subsequent startup is possible.
func TestGracefulShutdownAllowsSubsequentStart(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	lockPath := socketPath + ".lock"

	mux := http.NewServeMux()
	server := &http.Server{Handler: mux}
	signalCtx, signalCancel := context.WithCancel(context.Background())

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- runWithLock(lockPath, func() error {
			listener, err := net.Listen("unix", socketPath)
			if err != nil {
				return err
			}
			defer listener.Close()
			defer os.Remove(socketPath)
			_, shutdownCancel, drainCh, err := serveWithShutdown(signalCtx, server, listener, 30*time.Second, nil)
			<-drainCh
			shutdownCancel()
			return err
		})
	}()

	// Initiate shutdown before any connections.
	signalCancel()

	err := <-serveDone
	if err != nil {
		t.Fatalf("first serveWithShutdown: %v", err)
	}

	// Subsequent startup must work.
	err = runWithLock(lockPath, func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("subsequent runWithLock: %v", err)
	}
}

// Serve error before shutdown is not lost.
func TestServeErrorBeforeShutdown(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	mux := http.NewServeMux()
	server := &http.Server{Handler: mux}
	signalCtx, signalCancel := context.WithCancel(context.Background())
	defer signalCancel()

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer os.Remove(socketPath)

	serveDone := make(chan error, 1)
	go func() {
		_, shutdownCancel, drainCh, serveDoneErr := serveWithShutdown(signalCtx, server, listener, 30*time.Second, nil)
		<-drainCh
		shutdownCancel()
		serveDone <- serveDoneErr
	}()

	// Close listener to force Serve error.
	listener.Close()

	err = <-serveDone
	if err == nil {
		t.Fatal("expected error from serveWithShutdown when listener is closed")
	}
}

// Graceful shutdown drains in-flight requests and holds the lock until drain completes.
func TestGracefulShutdownDrainsRequestAndHoldsLock(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	lockPath := socketPath + ".lock"

	// Synchronization channels.
	listenerReady := make(chan struct{})
	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})

	// Shared error variables — safe to read after corresponding done channel closes.
	var serverErr error
	serverDone := make(chan struct{})
	var requestErr error
	requestDone := make(chan struct{})
	var subErr error

	mux := http.NewServeMux()
	server := &http.Server{Handler: mux}
	signalCtx, signalCancel := context.WithCancel(context.Background())

	mux.HandleFunc("POST /drain", func(w http.ResponseWriter, r *http.Request) {
		close(handlerStarted)
		<-releaseHandler
		w.WriteHeader(http.StatusOK)
	})

	// Start server in a goroutine via runWithLock.
	go func() {
		defer close(serverDone)
		serverErr = runWithLock(lockPath, func() error {
			listener, err := net.Listen("unix", socketPath)
			if err != nil {
				return err
			}
			defer listener.Close()
			defer os.Remove(socketPath)
			close(listenerReady)
			_, shutdownCancel, drainCh, err := serveWithShutdown(signalCtx, server, listener, 30*time.Second, nil)
			<-drainCh
			shutdownCancel()
			return err
		})
	}()

	// Wait for listener to be ready.
	select {
	case <-listenerReady:
	case <-serverDone:
		t.Fatalf("server returned before listener ready: %v", serverErr)
	}

	// Create HTTP client that dials the Unix socket.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, 2*time.Second)
		},
	}
	client := &http.Client{Transport: transport}

	// Send request in a goroutine.
	go func() {
		defer close(requestDone)
		req, err := http.NewRequestWithContext(context.Background(), "POST", "http://localhost/drain", nil)
		if err != nil {
			requestErr = err
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			requestErr = err
			return
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			requestErr = fmt.Errorf("unexpected status: %d", resp.StatusCode)
		}
	}()

	// Emergency cleanup — registered before any t.Fatalf so goroutines
	// are always drained even if an early assertion fails.
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseHandler)
		})
	}

	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			release()
			signalCancel()
			_ = server.Close()
			transport.CloseIdleConnections()
		})
	}

	t.Cleanup(func() {
		cleanup()
		<-serverDone
		<-requestDone
	})

	// Wait for handler to start.
	select {
	case <-handlerStarted:
	case <-requestDone:
		t.Fatalf("request finished before handler started: %v", requestErr)
	}

	// Initiate shutdown.
	signalCancel()

	// Wait for shutdown to take effect: listener must stop accepting new connections.
	listenerClosed := false
	testDeadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(testDeadline) {
		conn, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
		if err != nil {
			listenerClosed = true
			break
		}
		_ = conn.Close()
	}

	if !listenerClosed {
		t.Fatal("listener still accepts connections after shutdown started")
	}

	// Verify server has not returned yet (handler still active).
	select {
	case <-serverDone:
		t.Fatalf("server returned while handler was active: %v", serverErr)
	default:
	}

	// Attempt second runWithLock — must fail because lock is held.
	secondCalled := false
	secondLockErr := runWithLock(lockPath, func() error {
		secondCalled = true
		return nil
	})
	if secondLockErr == nil {
		t.Fatal("second runWithLock should fail while server drains")
	}
	if secondCalled {
		t.Fatal("second callback must not be called while lock is held")
	}

	// Release handler and wait for request to complete.
	release()

	<-requestDone
	if requestErr != nil {
		t.Fatalf("request failed after handler released: %v", requestErr)
	}

	// Wait for server to finish.
	<-serverDone
	if serverErr != nil {
		t.Fatalf("server returned error: %v", serverErr)
	}

	// Subsequent runWithLock must succeed.
	subErr = runWithLock(lockPath, func() error {
		return nil
	})
	if subErr != nil {
		t.Fatalf("subsequent runWithLock: %v", subErr)
	}
}

// When the shutdown deadline expires, serveWithShutdown forces server.Close()
// and the drain goroutine completes.
func TestGracefulShutdownTimeoutForcesClose(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	shutdownTimeout := 100 * time.Millisecond

	mux := http.NewServeMux()
	server := &http.Server{Handler: mux}
	signalCtx, signalCancel := context.WithCancel(context.Background())
	defer signalCancel()

	handlerStarted := make(chan struct{})
	handlerDone := make(chan struct{})

	mux.HandleFunc("POST /hang", func(w http.ResponseWriter, r *http.Request) {
		close(handlerStarted)
		defer close(handlerDone)

		<-r.Context().Done()
	})

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer os.Remove(socketPath)

	serverDone := make(chan struct{})
	var drainErr error

	go func() {
		defer close(serverDone)
		_, shutdownCancel, drainCh, _ := serveWithShutdown(signalCtx, server, listener, shutdownTimeout, nil)
		drainErr = <-drainCh
		shutdownCancel()
	}()

	// Create HTTP client that dials the Unix socket.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}

	requestCtx, cancelRequest := context.WithCancel(context.Background())

	var requestErr error
	requestDone := make(chan struct{})

	go func() {
		defer close(requestDone)
		req, err := http.NewRequestWithContext(requestCtx, "POST", "http://localhost/hang", nil)
		if err != nil {
			requestErr = err
			return
		}
		resp, err := (&http.Client{Transport: transport}).Do(req)
		if err != nil {
			requestErr = err
			return
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			requestErr = fmt.Errorf("unexpected status: %d", resp.StatusCode)
		}
	}()

	// Emergency cleanup.
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			signalCancel()
			cancelRequest()
			_ = server.Close()
			_ = listener.Close()
			transport.CloseIdleConnections()
		})
	}
	t.Cleanup(func() {
		cleanup()
		<-serverDone
		<-requestDone
	})

	// Wait for handler to start.
	select {
	case <-handlerStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not start")
	}

	// Initiate shutdown — Shutdown will hit its deadline, then server.Close().
	signalCancel()

	// Wait for serveWithShutdown + drain to return.
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("serveWithShutdown did not return")
	}

	// Force-close may not cancel in-flight request contexts reliably.
	// Cancel the request explicitly to unblock the handler.
	cancelRequest()

	// Handler should finish after request context is cancelled.
	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish after forced close")
	}

	// Request should complete with an error.
	select {
	case <-requestDone:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not finish")
	}

	if requestErr == nil {
		t.Fatal("expected active request to be interrupted by forced close")
	}

	// Verify drain reported timeout error.
	if drainErr == nil {
		t.Fatal("expected drain error, got nil")
	}
	if !strings.Contains(drainErr.Error(), "graceful shutdown timeout") {
		t.Fatalf("unexpected drain error: %v", drainErr)
	}
}

// TestServerErrorLogGoesToOperational verifies that http.Server.ErrorLog
// is bridged to the operational logging pipeline so that internal net/http
// diagnostics appear as structured JSON with stream=operational.
func TestServerErrorLogGoesToOperational(t *testing.T) {
	opBuf := new(bytes.Buffer)
	auditBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer logging.reset()

	server := newHTTPServer(http.NewServeMux())

	server.ErrorLog.Print("synthetic http server error")

	output := opBuf.String()
	if !strings.Contains(output, "synthetic http server error") {
		t.Fatalf("expected error in operational log:\n%s", output)
	}

	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not valid JSON: %s: %v", line, err)
		}
		if m["stream"] != "operational" {
			t.Errorf("expected stream=operational, got %v", m["stream"])
		}
		if m["level"] != "ERROR" {
			t.Errorf("expected level=ERROR, got %v", m["level"])
		}
	}
}
