package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
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

	err := runWithLock(lockPath, socketPath, func(net.Listener) error {
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

	err := runWithLock(lockPath, socketPath, func(net.Listener) error {
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

// While first callback is blocked, second instance cannot get lock and does not delete socket.
func TestBlockedCallbackPreventsSecondInstance(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	lockPath := socketPath + ".lock"

	started := make(chan struct{})
	proceed := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		runWithLock(lockPath, socketPath, func(net.Listener) error {
			close(started)
			<-proceed
			return nil
		})
	}()

	<-started

	// Second instance must fail.
	err := runWithLock(lockPath, socketPath, func(net.Listener) error {
		return nil
	})
	if err == nil {
		t.Fatal("second instance should fail")
	}

	// Socket must still exist.
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("socket should exist while first callback is blocked")
	}

	// Release first instance and wait for it to finish.
	close(proceed)
	<-done

	// Socket must be cleaned up.
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("socket should be removed after first instance completes")
	}
}

// After first instance finishes, a subsequent startup is possible.
func TestSubsequentStartupAfterShutdown(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	lockPath := socketPath + ".lock"

	err := runWithLock(lockPath, socketPath, func(net.Listener) error {
		return nil
	})
	if err != nil {
		t.Fatalf("first runWithLock: %v", err)
	}

	err = runWithLock(lockPath, socketPath, func(net.Listener) error {
		return nil
	})
	if err != nil {
		t.Fatalf("second runWithLock: %v", err)
	}
}

// Parallel startup: only one succeeds, winner is held via channels, properly cleaned up.
func TestParallelStartupRace(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")
	lockPath := socketPath + ".lock"

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

	const n = 10
	ready := make(chan struct{}, n)
	start := make(chan struct{})
	hasLock := make(chan struct{})
	proceed := make(chan struct{})
	results := make(chan error, n)

	for i := 0; i < n; i++ {
		go func() {
			ready <- struct{}{}
			<-start

			err := runWithLock(lockPath, socketPath, func(net.Listener) error {
				hasLock <- struct{}{}
				<-proceed
				return nil
			})
			results <- err
		}()
	}

	// Wait for all goroutines to be ready.
	for i := 0; i < n; i++ {
		<-ready
	}

	// Release all goroutines simultaneously.
	close(start)

	// Wait for the winner to signal it holds the lock.
	<-hasLock

	// Socket must exist while winner holds the lock.
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		t.Error("socket should exist while winner holds lock")
	}

	// Release the winner.
	close(proceed)

	// Collect all results.
	var successes, failures int
	for i := 0; i < n; i++ {
		err := <-results
		if err == nil {
			successes++
		} else {
			failures++
		}
	}

	if successes != 1 {
		t.Errorf("expected exactly 1 success, got %d", successes)
	}
	if failures != n-1 {
		t.Errorf("expected %d failures, got %d", n-1, failures)
	}

	// Winner cleaned up the socket.
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Error("socket should be removed after winner completes")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
