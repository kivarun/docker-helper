package main

import (
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

	// Create a stale socket by binding and closing at the syscall level.
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

	listener, err := prepareListener(socketPath)
	if err != nil {
		t.Fatalf("prepareListener() error: %v", err)
	}
	defer listener.Close()

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

	_, err = prepareListener(socketPath)
	if err == nil {
		t.Fatal("expected error when socket has a live listener")
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

	_, err := prepareListener(socketPath)
	if err == nil {
		t.Fatal("expected error when socket path is a regular file")
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

	_, err := prepareListener(socketPath)
	if err == nil {
		t.Fatal("expected error when socket path is a directory")
	}
}

func TestPrepareListenerNewSocket(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	listener, err := prepareListener(socketPath)
	if err != nil {
		t.Fatalf("prepareListener() error: %v", err)
	}
	defer listener.Close()

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

func TestIsLiveSocket(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "test.sock")

	if isLiveSocket(socketPath) {
		t.Error("non-existent socket should not be live")
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("net.Listen() error: %v", err)
	}

	if !isLiveSocket(socketPath) {
		listener.Close()
		t.Error("listening socket should be live")
	}

	listener.Close()

	time.Sleep(100 * time.Millisecond)

	if isLiveSocket(socketPath) {
		t.Error("closed socket should not be live")
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
