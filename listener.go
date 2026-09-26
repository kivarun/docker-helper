package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
)

// DefaultHTTPAddress is the loopback TCP address of the daemon.
const DefaultHTTPAddress = "127.0.0.1:52375"

// ListenerFactory creates listeners for the daemon.
// Can be replaced in tests.
var ListenerFactory listenerFactory = &defaultListenerFactory{}

// listenerFactory defines how listeners are created.
type listenerFactory interface {
	// createUnixListener creates a Unix socket listener.
	createUnixListener(socketPath string) (net.Listener, error)
	// createTCPListener creates a loopback TCP listener.
	createTCPListener(address string) (net.Listener, error)
}

type defaultListenerFactory struct{}

// safePrepareUnixListener creates a Unix listener with safe preparation.
// It checks for existing files, live sockets, and stale sockets before creating.
// perm is the file mode to set on the socket.
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

func (f *defaultListenerFactory) createUnixListener(socketPath string) (net.Listener, error) {
	l, _, err := safePrepareUnixListener(socketPath, 0666)
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

// prepareListeners creates the daemon listeners.
//
// The Unix listener is authoritative: its creation failure is a fatal
// startup error and no TCP bind is attempted after it. The optional loopback
// TCP listener is attempted after a successful Unix bind; a TCP bind failure
// is DEGRADED STARTUP, not daemon failure — the Unix listener stays live,
// its socket is not removed, the complete API keeps serving over Unix, the
// TCP listener is absent for this daemon lifetime (no retry/rebind: the bind
// itself is the authority, so a port that becomes free later stays free
// until the next normal service restart), and exactly one bounded
// operational warning names the configured address and the bind failure. A
// hostile unprivileged local user can therefore hold the TCP port without
// denying the authoritative Unix service.
func prepareListeners(socketPath, httpAddress string) (unixListener, tcpListener net.Listener, tcpDegradedErr, err error) {
	unixListener, err = ListenerFactory.createUnixListener(socketPath)
	if err != nil {
		return nil, nil, nil, err
	}

	tcpListener, tcpDegradedErr = ListenerFactory.createTCPListener(httpAddress)
	if tcpDegradedErr != nil {
		tcpListener = nil
		opLog(context.Background()).Warn(
			"loopback TCP listener unavailable; continuing with Unix transport until the next restart",
			slog.String("operation", "serve_startup"),
			slog.String("http", httpAddress),
			slog.String("error", tcpDegradedErr.Error()),
		)
	}

	return unixListener, tcpListener, tcpDegradedErr, nil
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
