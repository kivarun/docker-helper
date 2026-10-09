package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	f1, err := acquireDaemonInstanceLock(lockPath)
	if err != nil {
		t.Fatalf("first acquireDaemonInstanceLock() error: %v", err)
	}

	_, err = acquireDaemonInstanceLock(lockPath)
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

	f1, err := acquireDaemonInstanceLock(lockPath)
	if err != nil {
		t.Fatalf("acquireDaemonInstanceLock() error: %v", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("net.Listen() error: %v", err)
	}

	_, statErr := os.Stat(socketPath)
	exists := statErr == nil
	if !exists {
		listener.Close()
		f1.Close()
		t.Fatal("socket should exist after Listen")
	}

	_, err = acquireDaemonInstanceLock(lockPath)
	if err == nil {
		listener.Close()
		f1.Close()
		t.Fatal("expected error when acquiring second lock")
	}

	_, statErr = os.Stat(socketPath)
	exists = statErr == nil
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

	f1, err := acquireDaemonInstanceLock(lockPath)
	if err != nil {
		t.Fatalf("first acquireDaemonInstanceLock() error: %v", err)
	}

	f1.Close()

	f2, err := acquireDaemonInstanceLock(lockPath)
	if err != nil {
		t.Fatalf("re-acquireDaemonInstanceLock() error: %v", err)
	}

	f2.Close()
}

func TestPrepareListenersStaleSocket(t *testing.T) {
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

	unixListener, tcpListener, _, err := prepareListeners(socketPath, "")
	if err != nil {
		t.Fatalf("prepareListeners() error: %v", err)
	}
	defer unixListener.Close()
	defer func() {
		if tcpListener != nil {
			tcpListener.Close()
		}
	}()
	if tcpListener == nil {
		t.Error("TCP listener should be bound on the default HTTP address")
	}

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Fatal("new socket should exist")
	}
}

func TestPrepareListenersLiveSocket(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("net.Listen() error: %v", err)
	}
	defer listener.Close()

	unixListener, tcpListener, _, err := prepareListeners(socketPath, "")
	if err == nil {
		t.Fatal("expected error when socket has a live listener")
	}
	if unixListener != nil {
		t.Error("Unix listener should be nil on error")
	}
	if tcpListener != nil {
		t.Error("TCP listener should be nil on error")
	}

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("live socket should not be deleted")
	}
}

func TestPrepareListenersRegularFile(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	if err := os.WriteFile(socketPath, nil, 0600); err != nil {
		t.Fatalf("cannot create file: %v", err)
	}

	unixListener, tcpListener, _, err := prepareListeners(socketPath, "")
	if err == nil {
		t.Fatal("expected error when socket path is a regular file")
	}
	if unixListener != nil {
		t.Error("Unix listener should be nil on error")
	}
	if tcpListener != nil {
		t.Error("TCP listener should be nil on error")
	}

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("regular file should not be deleted")
	}
}

func TestPrepareListenersDirectory(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	if err := os.Mkdir(socketPath, 0700); err != nil {
		t.Fatalf("cannot create directory: %v", err)
	}

	unixListener, tcpListener, _, err := prepareListeners(socketPath, "")
	if err == nil {
		t.Fatal("expected error when socket path is a directory")
	}
	if unixListener != nil {
		t.Error("Unix listener should be nil on error")
	}
	if tcpListener != nil {
		t.Error("TCP listener should be nil on error")
	}
}

func TestPrepareListenersNewSocket(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	unixListener, tcpListener, _, err := prepareListeners(socketPath, "")
	if err != nil {
		t.Fatalf("prepareListeners() error: %v", err)
	}
	defer unixListener.Close()
	defer func() {
		if tcpListener != nil {
			tcpListener.Close()
		}
	}()
	if tcpListener == nil {
		t.Error("TCP listener should be bound on the default HTTP address")
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

	f, err := acquireDaemonInstanceLock(lockPath)
	if err != nil {
		t.Fatalf("acquireDaemonInstanceLock() error: %v", err)
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

func TestPrepareListenersUnknownDialError(t *testing.T) {
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

	unixListener, tcpListener, _, err := prepareListeners(socketPath, "")
	if err == nil {
		t.Fatal("expected error from prepareListeners on unknown dial error")
	}
	if unixListener != nil {
		t.Error("Unix listener should be nil on error")
	}
	if tcpListener != nil {
		t.Error("TCP listener should be nil on error")
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

	unixListener, tcpListener, _, err := prepareListeners(socketPath, "")
	if err != nil {
		t.Fatalf("prepareListeners: %v", err)
	}
	defer unixListener.Close()
	defer func() {
		if tcpListener != nil {
			tcpListener.Close()
		}
	}()
	if tcpListener == nil {
		t.Error("TCP listener should be bound on the default HTTP address")
	}
}

// --- Lifecycle tests using withDaemonInstanceLock ---

// Callback error: lock released, socket removed, lock file remains.
func TestStartupErrorReleasesLock(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	lockPath := socketPath + ".lock"

	err := withDaemonInstanceLock(lockPath, func() error {
		return errors.New("simulated startup error")
	})
	if err == nil {
		t.Fatal("expected error from withDaemonInstanceLock")
	}

	// Lock must be released.
	lockFile, err := acquireDaemonInstanceLock(lockPath)
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

	err := withDaemonInstanceLock(lockPath, func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("withDaemonInstanceLock: %v", err)
	}

	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("socket should be removed after callback returns")
	}

	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
		t.Error("lock file should remain")
	}

	lockFile, err := acquireDaemonInstanceLock(lockPath)
	if err != nil {
		t.Fatalf("flock not released: %v", err)
	}
	lockFile.Close()
}

// Listener creation error inside withDaemonInstanceLock: callback called, lock released,
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
	err := withDaemonInstanceLock(lockPath, func() error {
		called = true
		_, err := net.Listen("unix", socketPath)
		return err
	})
	if err == nil {
		t.Fatal("expected error from withDaemonInstanceLock")
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
	lockFile, err := acquireDaemonInstanceLock(lockPath)
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

	err := withDaemonInstanceLock(lockPath, func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("first withDaemonInstanceLock: %v", err)
	}

	err = withDaemonInstanceLock(lockPath, func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("second withDaemonInstanceLock: %v", err)
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
		holderResult <- withDaemonInstanceLock(lockPath, func() error {
			// Create a listener so the socket exists.
			listener, err := net.Listen("unix", socketPath)
			if err != nil {
				return err
			}
			defer listener.Close()
			defer os.Remove(socketPath)
			// Signal only after lock acquired + listener created.
			close(holderStarted)
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
		t.Fatalf("holder withDaemonInstanceLock returned before callback: %v", err)
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

			err := withDaemonInstanceLock(lockPath, func() error {
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
		t.Fatalf("holder withDaemonInstanceLock returned error: %v", holderErr)
	}

	// Holder must have cleaned up the socket.
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("socket should be removed after holder completes")
	}

	// --- Phase 4: subsequent startup must work ---
	err := withDaemonInstanceLock(lockPath, func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("subsequent withDaemonInstanceLock: %v", err)
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
		_, shutdownCancel, drainCh, serveDoneErr := serveHTTPUntilShutdown(signalCtx, server, listener, nil, func() time.Duration { return 30 * time.Second }, nil)
		<-drainCh
		shutdownCancel()
		serveDone <- serveDoneErr
	}()

	// Initiate shutdown before any connections.
	signalCancel()

	err = <-serveDone
	if err != nil {
		t.Fatalf("serveHTTPUntilShutdown: %v", err)
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
		serveDone <- withDaemonInstanceLock(lockPath, func() error {
			listener, err := net.Listen("unix", socketPath)
			if err != nil {
				return err
			}
			defer listener.Close()
			defer os.Remove(socketPath)
			_, shutdownCancel, drainCh, err := serveHTTPUntilShutdown(signalCtx, server, listener, nil, func() time.Duration { return 30 * time.Second }, nil)
			<-drainCh
			shutdownCancel()
			return err
		})
	}()

	// Initiate shutdown before any connections.
	signalCancel()

	err := <-serveDone
	if err != nil {
		t.Fatalf("first serveHTTPUntilShutdown: %v", err)
	}

	// Subsequent startup must work.
	err = withDaemonInstanceLock(lockPath, func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("subsequent withDaemonInstanceLock: %v", err)
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
		_, shutdownCancel, drainCh, serveDoneErr := serveHTTPUntilShutdown(signalCtx, server, listener, nil, func() time.Duration { return 30 * time.Second }, nil)
		<-drainCh
		shutdownCancel()
		serveDone <- serveDoneErr
	}()

	// Close listener to force Serve error.
	listener.Close()

	err = <-serveDone
	if err == nil {
		t.Fatal("expected error from serveHTTPUntilShutdown when listener is closed")
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

	// Start server in a goroutine via withDaemonInstanceLock.
	go func() {
		defer close(serverDone)
		serverErr = withDaemonInstanceLock(lockPath, func() error {
			listener, err := net.Listen("unix", socketPath)
			if err != nil {
				return err
			}
			defer listener.Close()
			defer os.Remove(socketPath)
			close(listenerReady)
			_, shutdownCancel, drainCh, err := serveHTTPUntilShutdown(signalCtx, server, listener, nil, func() time.Duration { return 30 * time.Second }, nil)
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

	// Attempt second withDaemonInstanceLock — must fail because lock is held.
	secondCalled := false
	secondLockErr := withDaemonInstanceLock(lockPath, func() error {
		secondCalled = true
		return nil
	})
	if secondLockErr == nil {
		t.Fatal("second withDaemonInstanceLock should fail while server drains")
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

	// Subsequent withDaemonInstanceLock must succeed.
	subErr = withDaemonInstanceLock(lockPath, func() error {
		return nil
	})
	if subErr != nil {
		t.Fatalf("subsequent withDaemonInstanceLock: %v", subErr)
	}
}

// When the shutdown deadline expires, serveHTTPUntilShutdown forces server.Close()
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
		_, shutdownCancel, drainCh, _ := serveHTTPUntilShutdown(signalCtx, server, listener, nil, func() time.Duration { return shutdownTimeout }, nil)
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

	// Wait for serveHTTPUntilShutdown + drain to return.
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("serveHTTPUntilShutdown did not return")
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

// TestServeShutdownBudgetReflectsReloadedValue verifies that the shutdown
// budget is read from the ACTUAL App configuration at the moment shutdown
// begins, so a reload (setConfig) changes the observed shutdown budget. The
// daemon startup value must NOT be used after a reload.
func TestServeShutdownBudgetReflectsReloadedValue(t *testing.T) {
	// Startup configuration: 2s budget.
	app := &App{Config: &Config{ShutdownTimeout: 2 * time.Second}}

	// Simulate an operator reload that raises shutdown_timeout to 5s.
	app.setConfig(&Config{ShutdownTimeout: 5 * time.Second})

	signalCtx, signalCancel := context.WithCancel(context.Background())
	defer signalCancel()

	server := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	type result struct {
		shutdownCtx    context.Context
		shutdownCancel func()
		drainDone      <-chan error
		serveErr       error
	}
	resultCh := make(chan result, 1)
	go func() {
		sc, scancel, dd, e := serveHTTPUntilShutdown(signalCtx, server, listener, nil,
			func() time.Duration { return app.getConfig().ShutdownTimeout }, nil)
		resultCh <- result{sc, scancel, dd, e}
	}()

	// Trigger shutdown; the budget must now reflect the reloaded 5s.
	signalCancel()
	res := <-resultCh
	defer res.shutdownCancel()

	// The shutdown context deadline must carry the RELOADED 5s budget, never
	// the 2s value captured at daemon startup.
	deadline, ok := res.shutdownCtx.Deadline()
	if !ok {
		t.Fatal("shutdown context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining > 5*time.Second || remaining < 4*time.Second {
		t.Fatalf("shutdown budget should reflect reloaded 5s, got %v", remaining)
	}

	select {
	case <-res.drainDone:
	case <-time.After(10 * time.Second):
		t.Fatal("drain did not complete")
	}
	if res.serveErr != nil {
		t.Fatalf("serve error: %v", res.serveErr)
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

// --- serveHTTPUntilShutdown deadlock regression tests ---

// Single listener: unexpected Serve error -> function completes drain, no hang.
func TestServeHTTPUntilShutdownUserModeServeError(t *testing.T) {
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

	done := make(chan error, 1)
	go func() {
		_, shutdownCancel, drainDone, serveErr := serveHTTPUntilShutdown(signalCtx, server, listener, nil, func() time.Duration { return 30 * time.Second }, nil)
		if shutdownCancel != nil {
			<-drainDone
			shutdownCancel()
		}
		done <- serveErr
	}()

	listener.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error from serveHTTPUntilShutdown")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveHTTPUntilShutdown did not return (possible deadlock)")
	}
}

// System mode: Unix Serve error -> TCP also closed, drain completes.
func TestServeHTTPUntilShutdownUnixServeError(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	mux := http.NewServeMux()
	server := &http.Server{Handler: mux}
	signalCtx, signalCancel := context.WithCancel(context.Background())
	defer signalCancel()

	unixListener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer os.Remove(socketPath)

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, shutdownCancel, drainDone, serveErr := serveHTTPUntilShutdown(signalCtx, server, unixListener, tcpListener, func() time.Duration { return 30 * time.Second }, nil)
		if shutdownCancel != nil {
			<-drainDone
			shutdownCancel()
		}
		done <- serveErr
	}()

	unixListener.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error from serveHTTPUntilShutdown")
		}
		if _, dialErr := net.Dial("tcp", tcpListener.Addr().String()); dialErr == nil {
			t.Error("TCP listener should be closed after Unix serve error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveHTTPUntilShutdown did not return (possible deadlock)")
	}
}

// System mode: TCP Serve error -> Unix also closed, drain completes.
func TestServeHTTPUntilShutdownTCPServeError(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	mux := http.NewServeMux()
	server := &http.Server{Handler: mux}
	signalCtx, signalCancel := context.WithCancel(context.Background())
	defer signalCancel()

	unixListener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer os.Remove(socketPath)

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, shutdownCancel, drainDone, serveErr := serveHTTPUntilShutdown(signalCtx, server, unixListener, tcpListener, func() time.Duration { return 30 * time.Second }, nil)
		if shutdownCancel != nil {
			<-drainDone
			shutdownCancel()
		}
		done <- serveErr
	}()

	tcpListener.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error from serveHTTPUntilShutdown")
		}
		if _, dialErr := net.Dial("unix", socketPath); dialErr == nil {
			t.Error("Unix listener should be closed after TCP serve error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveHTTPUntilShutdown did not return (possible deadlock)")
	}
}

// --- safe Unix socket preparation tests (factory) ---

// Regular file at socket path -> error, file not deleted.
func TestCreateUnixListenerRegularFile(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	const stub = "stub"
	if err := os.WriteFile(socketPath, []byte(stub), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := ListenerFactory.createUnixListener(socketPath)
	if err == nil {
		t.Fatal("expected error when socket path is a regular file")
	}

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatal("regular file should not be deleted")
	}
	if info.Mode()&os.ModeType != 0 {
		t.Error("regular file should not be modified")
	}
	data, err := os.ReadFile(socketPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != stub {
		t.Errorf("file content = %q, want %q", string(data), stub)
	}
}

// Live socket at path -> error, socket not deleted.
func TestCreateUnixListenerLiveSocket(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer listener.Close()

	_, err = ListenerFactory.createUnixListener(socketPath)
	if err == nil {
		t.Fatal("expected error when socket has a live listener")
	}

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("live socket should not be deleted")
	}
}

// Stale socket -> replaced.
func TestCreateUnixListenerStaleSocket(t *testing.T) {
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

	listener, err := ListenerFactory.createUnixListener(socketPath)
	if err != nil {
		t.Fatalf("createUnixListener: %v", err)
	}
	defer listener.Close()

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Fatal("new socket should exist")
	}
}

// System mode -> 0666 permissions.
func TestCreateUnixListenerPermissionsSystem(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	listener, err := ListenerFactory.createUnixListener(socketPath)
	if err != nil {
		t.Fatalf("createUnixListener: %v", err)
	}
	defer listener.Close()

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0666 {
		t.Errorf("permissions = %o, want 0666", perm)
	}
}

// --- the optional loopback TCP listener is never authoritative ---

// stubH7Listener is a net.Listener whose Close state is observable. It is
// never served; these tests only exercise listener acquisition.
type stubH7Listener struct {
	closed bool
}

func (l *stubH7Listener) Accept() (net.Conn, error) {
	return nil, net.ErrClosed
}

func (l *stubH7Listener) Close() error {
	l.closed = true
	return nil
}

func (l *stubH7Listener) Addr() net.Addr {
	return stubH7Addr{}
}

type stubH7Addr struct{}

func (stubH7Addr) Network() string { return "unix" }
func (stubH7Addr) String() string  { return "/tmp/stub-h7.sock" }

// stubH7Factory is a listenerFactory seam recording how often each creator
// was consulted (no retry/loop may consult the TCP creator more than once).
type stubH7Factory struct {
	unixListener net.Listener
	unixErr      error
	tcpListener  net.Listener
	tcpErr       error
	unixCalls    int
	tcpCalls     int
	tcpAddress   string
}

func (f *stubH7Factory) createUnixListener(socketPath string) (net.Listener, error) {
	f.unixCalls++
	return f.unixListener, f.unixErr
}

func (f *stubH7Factory) createTCPListener(address string) (net.Listener, error) {
	f.tcpCalls++
	f.tcpAddress = address
	return f.tcpListener, f.tcpErr
}

// h7AddrInUse builds the deterministic TCP bind failure the hostile UAT
// reproduces on the real service: an unprivileged local user holds the
// configured loopback port, so the daemon's bind answers EADDRINUSE.
func h7AddrInUse(addr string) error {
	return &net.OpError{
		Op:  "listen",
		Net: "tcp",
		Err: syscall.EADDRINUSE,
	}
}

// TestH7TCPPortCaptureLeavesUnixListenerAuthoritative is the contract: the
// Unix listener is authoritative, so after a successful Unix bind a TCP
// EADDRINUSE is DEGRADED STARTUP, not daemon failure — the Unix listener
// stays live, its socket is not removed, the API keeps serving over Unix,
// the TCP listener is absent for this daemon lifetime, exactly one bounded
// operational warning names the configured address and the bind failure, and
// no retry consults the TCP creator again.
func TestH7TCPPortCaptureLeavesUnixListenerAuthoritative(t *testing.T) {
	// Capture operational output at warn level: the degraded-startup
	// diagnostic is a Warn record.
	opBuf := new(bytes.Buffer)
	initLoggers(opBuf, io.Discard, slog.LevelWarn, true)
	t.Cleanup(logging.reset)
	factory := &stubH7Factory{unixListener: &stubH7Listener{}, tcpErr: h7AddrInUse(DefaultHTTPAddress)}
	orig := ListenerFactory
	t.Cleanup(func() { ListenerFactory = orig })
	ListenerFactory = factory

	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	if err := os.WriteFile(socketPath, []byte("sentinel"), 0600); err != nil {
		t.Fatal(err)
	}

	unixListener, tcpListener, tcpDegraded, err := prepareListeners(socketPath, DefaultHTTPAddress)
	if err != nil {
		t.Fatalf("TCP port capture must not deny the authoritative Unix service, got: %v", err)
	}
	if tcpDegraded == nil {
		t.Error("the TCP degradation must be reported to the caller (non-fatal)")
	}
	if unixListener == nil {
		t.Fatal("Unix listener must be returned")
	}
	if factory.unixListener.(*stubH7Listener).closed {
		t.Error("the successful Unix listener must stay open on TCP degradation")
	}
	if tcpListener != nil {
		t.Error("the TCP listener must be absent for this daemon lifetime")
	}
	if _, statErr := os.Stat(socketPath); statErr != nil {
		t.Errorf("the Unix socket must not be removed on TCP failure: %v", statErr)
	}
	if factory.tcpCalls != 1 {
		t.Errorf("no retry may consult the TCP creator again, got %d calls", factory.tcpCalls)
	}
	out := opBuf.String()
	if !strings.Contains(out, DefaultHTTPAddress) {
		t.Errorf("the degraded-startup warning must contain the configured address:\n%s", out)
	}
	if !strings.Contains(out, "address already in use") {
		t.Errorf("the degraded-startup warning must contain the bind failure:\n%s", out)
	}
	if strings.Contains(out, "daemon startup failed") {
		t.Errorf("degradation must not be logged as a fatal startup failure:\n%s", out)
	}
}

// TestH7UnixFailureStillFatal proves the Unix listener stays authoritative:
// Unix creation failure remains a fatal startup error and no TCP bind is
// attempted after it.
func TestH7UnixFailureStillFatal(t *testing.T) {
	setupTestLoggingDiscard(t)
	factory := &stubH7Factory{unixErr: errors.New("cannot listen on /run/docker-helper/docker-helper.sock: permission denied")}
	orig := ListenerFactory
	t.Cleanup(func() { ListenerFactory = orig })
	ListenerFactory = factory

	unixListener, tcpListener, _, err := prepareListeners("/run/docker-helper/docker-helper.sock", DefaultHTTPAddress)
	if err == nil {
		t.Fatal("Unix listener creation failure must remain fatal")
	}
	if unixListener != nil || tcpListener != nil {
		t.Error("no listener may be returned on fatal Unix failure")
	}
	if factory.tcpCalls != 0 {
		t.Errorf("TCP creation must not be attempted after fatal Unix failure, got %d calls", factory.tcpCalls)
	}
}

// TestH7SystemModeBothListenersServed proves the healthy system-mode path is
// unchanged: Unix success + TCP success returns both listeners and emits no
// degradation warning.
func TestH7SystemModeBothListenersServed(t *testing.T) {
	opBuf, _ := setupTestLogging(t)
	factory := &stubH7Factory{unixListener: &stubH7Listener{}, tcpListener: &stubH7Listener{}}
	orig := ListenerFactory
	t.Cleanup(func() { ListenerFactory = orig })
	ListenerFactory = factory

	unixListener, tcpListener, _, err := prepareListeners("/tmp/stub-h7.sock", DefaultHTTPAddress)
	if err != nil {
		t.Fatalf("healthy system-mode listener acquisition must succeed: %v", err)
	}
	if unixListener == nil || tcpListener == nil {
		t.Fatal("both listeners must be returned on success")
	}
	if out := opBuf.String(); strings.Contains(out, "unavailable") {
		t.Errorf("no degradation warning may be emitted on the healthy path:\n%s", out)
	}
}

// TestH7ServeAndCleanupWithNilTCP proves the degraded-startup runtime path is
// correct: a system-shaped server with a live Unix listener and a nil TCP
// listener serves the complete API over Unix (nil TCP is simply not served,
// like the unconditional binding), and cleanup with a nil TCP listener closes the
// Unix listener and removes its socket without error.
func TestH7ServeAndCleanupWithNilTCP(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	server := &http.Server{Handler: mux}
	signalCtx, signalCancel := context.WithCancel(context.Background())
	defer signalCancel()

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := os.Chmod(socketPath, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	serveDone := make(chan error, 1)
	go func() {
		_, shutdownCancel, drainCh, serveDoneErr := serveHTTPUntilShutdown(signalCtx, server, listener, nil, func() time.Duration { return 30 * time.Second }, nil)
		<-drainCh
		shutdownCancel()
		serveDone <- serveDoneErr
	}()

	// The degraded daemon serves /health over Unix only.
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
	resp, err := client.Get("http://localhost/health")
	if err != nil {
		t.Fatalf("GET /health over Unix during degraded startup: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /health status = %d, want 200", resp.StatusCode)
	}

	// TCP was never served: no listener exists on the TCP side for this
	// daemon lifetime (nothing to dial).
	signalCancel()
	if err := <-serveDone; err != nil {
		t.Fatalf("serveHTTPUntilShutdown: %v", err)
	}

	// Normal cleanup with a nil TCP listener: closes Unix, removes socket.
	cleanupListeners(listener, nil, socketPath)
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Errorf("cleanup must remove the Unix socket, got stat error: %v", err)
	}
}
