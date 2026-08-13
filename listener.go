package main

import (
	"fmt"
	"net"
	"os"
)

// DefaultHTTPAddress is the loopback TCP address for system mode.
const DefaultHTTPAddress = "127.0.0.1:52375"

// ListenerFactory creates listeners for the daemon.
// Can be replaced in tests.
var ListenerFactory = &defaultListenerFactory{}

// listenerFactory defines how listeners are created.
type listenerFactory interface {
	// createUnixListener creates a Unix socket listener with mode-appropriate permissions.
	createUnixListener(socketPath string, mode DeploymentMode) (net.Listener, error)
	// createTCPListener creates a loopback TCP listener.
	createTCPListener(address string) (net.Listener, error)
}

type defaultListenerFactory struct{}

// safePrepareUnixListener creates a Unix listener with safe preparation.
// It checks for existing files, live sockets, and stale sockets before creating.
// perm is the file mode to set on the socket (e.g., 0600 for user mode, 0666 for system mode).
// Returns the listener, a flag indicating whether a new socket was created, and an error if any.
func safePrepareUnixListener(socketPath string, perm os.FileMode) (net.Listener, bool, error) {
	info, err := os.Stat(socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return createUnixListenerWithPerm(socketPath, perm)
		}
		return nil, false, fmt.Errorf("cannot stat socket %s: %w", socketPath, err)
	}

	if info.Mode()&os.ModeSocket == 0 {
		if info.IsDir() {
			return nil, false, fmt.Errorf("socket path %s is a directory", socketPath)
		}
		return nil, false, fmt.Errorf("socket path %s exists and is not a socket", socketPath)
	}

	// It's a socket — check if it's live or stale.
	live, err := checkSocket(socketPath)
	if err != nil {
		// Path may have disappeared during check — re-stat.
		if _, statErr := os.Stat(socketPath); os.IsNotExist(statErr) {
			return createUnixListenerWithPerm(socketPath, perm)
		}
		return nil, false, fmt.Errorf("cannot check socket %s: %w", socketPath, err)
	}
	if live {
		return nil, false, fmt.Errorf("another docker-helper is already listening on %s", socketPath)
	}

	// Stale socket — remove and create new listener.
	if err := os.Remove(socketPath); err != nil {
		if os.IsNotExist(err) {
			return createUnixListenerWithPerm(socketPath, perm)
		}
		return nil, false, fmt.Errorf("cannot remove stale socket %s: %w", socketPath, err)
	}

	return createUnixListenerWithPerm(socketPath, perm)
}

func createUnixListenerWithPerm(socketPath string, perm os.FileMode) (net.Listener, bool, error) {
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, false, fmt.Errorf("cannot listen on %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, perm); err != nil {
		l.Close()
		os.Remove(socketPath)
		return nil, false, fmt.Errorf("cannot set socket permissions: %w", err)
	}
	return l, true, nil
}

func (f *defaultListenerFactory) createUnixListener(socketPath string, mode DeploymentMode) (net.Listener, error) {
	perm := os.FileMode(0600)
	if mode == ModeSystem {
		perm = 0666
	}
	l, _, err := safePrepareUnixListener(socketPath, perm)
	return l, err
}

func (f *defaultListenerFactory) createTCPListener(address string) (net.Listener, error) {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve TCP address %s: %w", address, err)
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on TCP %s: %w", address, err)
	}

	return listener, nil
}

// prepareListeners creates listeners for the given deployment mode.
// In user mode, only Unix listener is created.
// In system mode, both Unix and TCP listeners are created atomically.
// httpAddress is the TCP listen address for system mode.
// If any listener fails, all created listeners are cleaned up.
func prepareListeners(mode DeploymentMode, socketPath, httpAddress string) (unixListener, tcpListener net.Listener, err error) {
	unixListener, err = ListenerFactory.createUnixListener(socketPath, mode)
	if err != nil {
		return nil, nil, err
	}

	if mode == ModeSystem {
		tcpListener, err = ListenerFactory.createTCPListener(httpAddress)
		if err != nil {
			unixListener.Close()
			os.Remove(socketPath)
			return nil, nil, err
		}
	}

	return unixListener, tcpListener, nil
}

// cleanupListeners closes all listeners and removes the Unix socket.
func cleanupListeners(unixListener, tcpListener net.Listener, socketPath string) {
	if unixListener != nil {
		unixListener.Close()
	}
	if tcpListener != nil {
		tcpListener.Close()
	}
	os.Remove(socketPath)
}
