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

func (f *defaultListenerFactory) createUnixListener(socketPath string, mode DeploymentMode) (net.Listener, error) {
	// Remove stale socket if present.
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("cannot remove stale socket %s: %w", socketPath, err)
	}

	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve Unix address %s: %w", socketPath, err)
	}

	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on Unix socket %s: %w", socketPath, err)
	}

	// Set socket permissions based on deployment mode.
	perm := os.FileMode(0600)
	if mode == ModeSystem {
		perm = 0666
	}
	if err := os.Chmod(socketPath, perm); err != nil {
		listener.Close()
		os.Remove(socketPath)
		return nil, fmt.Errorf("cannot set socket permissions: %w", err)
	}

	return listener, nil
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
// If any listener fails, all created listeners are cleaned up.
func prepareListeners(mode DeploymentMode, socketPath string) (unixListener, tcpListener net.Listener, err error) {
	unixListener, err = ListenerFactory.createUnixListener(socketPath, mode)
	if err != nil {
		return nil, nil, err
	}

	if mode == ModeSystem {
		tcpListener, err = ListenerFactory.createTCPListener(DefaultHTTPAddress)
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
