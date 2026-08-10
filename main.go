package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

func loadAdminToken(path string) ([sha256.Size]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return [sha256.Size]byte{}, fmt.Errorf("admin token not found: %w", err)
		}
		return [sha256.Size]byte{}, fmt.Errorf("cannot read admin token: %w", err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return [sha256.Size]byte{}, errors.New("admin token is empty")
	}

	hash := sha256.Sum256([]byte(token))
	return hash, nil
}

// acquireLock opens the lock file and acquires an exclusive non-blocking flock.
// Returns the open file that must stay open for the lock to remain held.
func acquireLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open lock file %s: %w", path, err)
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, errors.New("another docker-helper instance is already running")
		}
		return nil, fmt.Errorf("cannot acquire lock: %w", err)
	}

	return f, nil
}

// prepareListener checks the socket path and creates a Unix listener.
// The caller must hold the lock when calling this function.
// Returns the listener, a flag indicating whether the socket was created
// by this call (true means the caller should clean it up on shutdown),
// and an error if any.
func prepareListener(socketPath string) (net.Listener, bool, error) {
	info, err := os.Stat(socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			l, err := createListener(socketPath)
			return l, err == nil, err
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
			l, err := createListener(socketPath)
			return l, err == nil, err
		}
		return nil, false, fmt.Errorf("cannot check socket %s: %w", socketPath, err)
	}
	if live {
		return nil, false, fmt.Errorf("another docker-helper is already listening on %s", socketPath)
	}

	// Stale socket — remove and create new listener.
	if err := os.Remove(socketPath); err != nil {
		if os.IsNotExist(err) {
			// Disappeared during remove — try creating.
			l, err := createListener(socketPath)
			return l, err == nil, err
		}
		return nil, false, fmt.Errorf("cannot remove stale socket %s: %w", socketPath, err)
	}

	l, err := createListener(socketPath)
	return l, err == nil, err
}

func createListener(socketPath string) (net.Listener, error) {
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on %s: %w", socketPath, err)
	}

	if err := os.Chmod(socketPath, 0600); err != nil {
		listener.Close()
		os.Remove(socketPath)
		return nil, fmt.Errorf("cannot set socket permissions: %w", err)
	}

	return listener, nil
}

// dialUnixFunc is the dial function used to probe a Unix socket.
// It can be replaced in tests to simulate specific dial errors.
var dialUnixFunc = func(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", addr, timeout)
}

// checkSocket returns (true, nil) if a process is listening on the socket,
// (false, nil) if the socket is stale (ECONNREFUSED),
// or (false, err) for any other dial error.
func checkSocket(socketPath string) (bool, error) {
	conn, err := dialUnixFunc(socketPath, 2*time.Second)
	if err != nil {
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Err != nil {
			if errors.Is(opErr.Err, syscall.ECONNREFUSED) {
				return false, nil
			}
		}
		return false, fmt.Errorf("cannot determine socket status: %w", err)
	}
	conn.Close()
	return true, nil
}

// runWithLock acquires the lock, prepares a listener, runs the callback,
// and performs production cleanup: close listener → remove socket → release lock.
// If prepareListener fails, the lock is released and the error is returned.
// If the callback fails, the listener is closed, the socket is removed (if created),
// and the lock is released.
func runWithLock(lockPath, socketPath string, fn func(net.Listener) error) error {
	lockFile, err := acquireLock(lockPath)
	if err != nil {
		return err
	}

	listener, created, err := prepareListener(socketPath)
	if err != nil {
		lockFile.Close()
		return err
	}

	// Cleanup order: close listener → remove socket → release lock.
	defer lockFile.Close()
	defer func() {
		if created {
			os.Remove(socketPath)
		}
	}()
	defer listener.Close()

	return fn(listener)
}

// serveWithShutdown runs server.Serve(listener) in a background goroutine and
// waits for either signalCtx cancellation (graceful shutdown) or a Serve error.
// On signalCtx cancellation it invokes onSignal (if non-nil), creates a shutdown
// context with the given timeout, and starts server.Shutdown in a goroutine.
// Returns the shutdown context, its cancel func, and a drain-done channel that
// carries the drain result (nil on success, timeout error on deadline expiry).
// The caller runs operation termination concurrently, then waits for drain.
// The caller must call shutdownCancel() after both terminateAll and drain complete.
// The callback in runWithLock must not return until drain completes so the
// lock stays held during the entire drain.
func serveWithShutdown(
	signalCtx context.Context,
	server *http.Server,
	listener net.Listener,
	timeout time.Duration,
	onSignal func(),
) (shutdownCtx context.Context, shutdownCancel func(), drainDone <-chan error, err error) {
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(listener)
	}()

	drainDoneCh := make(chan error, 1)

	select {
	case <-signalCtx.Done():
		if onSignal != nil {
			onSignal()
		}
		shutdownCtx, shutdownCancel = context.WithTimeout(context.Background(), timeout)

		// Start HTTP drain in background; caller runs operation termination
		// concurrently, then waits for drain to complete.
		go func() {
			shutdownErr := server.Shutdown(shutdownCtx)
			var drainErr error
			if shutdownErr == context.DeadlineExceeded {
				server.Close()
				drainErr = fmt.Errorf("graceful shutdown timeout after %v", timeout)
			} else if shutdownErr != nil {
				drainErr = shutdownErr
			}
			// Drain serveDone to avoid leaking the goroutine.
			<-serveDone
			drainDoneCh <- drainErr
		}()

		drainDone = drainDoneCh
		return

	case serveErr := <-serveDone:
		// Serve returned an error without a shutdown signal.
		// Create a bounded cleanup context so terminateAll can still
		// shut down running operations without panicking on nil ctx.
		shutdownCtx, shutdownCancel = context.WithTimeout(context.Background(), timeout)
		drainDoneCh <- nil
		drainDone = drainDoneCh
		err = serveErr
		return
	}
}

func runServe(stdout, stderr io.Writer) error {
	// Initialize logging before any other work so all errors are structured.
	initLoggers(stderr, stdout, slog.LevelInfo, false)

	cfg, err := loadConfig()
	if err != nil {
		hint := "run docker-helper init"
		if errors.Is(err, os.ErrNotExist) {
			hint = "configuration not found; run docker-helper init"
		}
		serveStartupError(err, hint)
		return err
	}

	// Re-initialize with the configured log level and audit setting.
	initLoggers(stderr, stdout, cfg.LogLevel, cfg.AuditEnabled)

	callbackEntered := false
	err = runWithLock(cfg.LockPath, cfg.SocketPath, func(listener net.Listener) error {
		callbackEntered = true
		adminHash, err := loadAdminToken(cfg.AdminTokenPath)
		if err != nil {
			serveStartupError(err, "run docker-helper init")
			return err
		}

		db, err := openDatabase(cfg.DatabasePath)
		if err != nil {
			serveStartupError(err, "")
			return err
		}
		defer db.Close()

		if err := initializeDatabase(db); err != nil {
			serveStartupError(err, "")
			return err
		}

		if _, err := cleanupExpiredSessions(db); err != nil {
			serveStartupError(err, "")
			return err
		}

		app := &App{
			Config:            cfg,
			DB:                db,
			AdminTokenHash:    adminHash,
			OperationRegistry: newOperationRegistry(),
		}

		mux := http.NewServeMux()
		mux.HandleFunc("POST /build", app.handleBuild)
		mux.HandleFunc("GET /health", app.handleHealth)
		mux.HandleFunc("POST /pull", app.handlePull)
		mux.HandleFunc("POST /run", app.handleRun)
		mux.HandleFunc("POST /sessions", app.handleCreateSession)
		mux.HandleFunc("GET /sessions", app.handleListSessions)
		mux.HandleFunc("DELETE /sessions/{id}", app.handleDeleteSession)
		mux.HandleFunc("POST /reload", app.handleReload)
		mux.HandleFunc("GET /operations/{id}", app.handleOperationStatus)
		mux.HandleFunc("GET /operations/{id}/logs", app.handleOperationLogs)
		mux.HandleFunc("POST /operations/{id}/cancel", app.handleOperationCancel)

		server := newHTTPServer(withRequestID(withLogging(http.HandlerFunc(mux.ServeHTTP))))

		logger := logging.snapshotLogger()

		if logger != nil {
			logger.Info("daemon listening",
				slog.String("socket", cfg.SocketPath),
			)
		}

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		shutdownCtx, shutdownCancel, drainDone, err := serveWithShutdown(ctx, server, listener, cfg.ShutdownTimeout, func() {
			// Signal received — close the operation gate before shutdown starts.
			if app.OperationRegistry != nil {
				app.OperationRegistry.setShuttingDown()
			}
		})

		// Terminate running operations with the same absolute deadline used
		// by HTTP drain. HTTP drain and operation termination proceed
		// concurrently under the one wall-clock shutdown budget.
		if app.OperationRegistry != nil {
			app.OperationRegistry.terminateAll(shutdownCtx, app.killContainerBestEffort)
		}

		// Wait for HTTP drain to complete before cancelling the shutdown
		// context. The drain goroutine runs server.Shutdown(shutdownCtx)
		// and must not be interrupted by premature context cancellation.
		drainErr := <-drainDone
		shutdownCancel()

		// Use drain error if no serve error was returned.
		if err == nil {
			err = drainErr
		}

		logger = logging.snapshotLogger()

		if err != nil {
			if logger != nil {
				logger.Error("daemon serve error",
					slog.String("operation", "serve"),
					slog.String("error", err.Error()),
				)
			}
		} else {
			if logger != nil {
				logger.Info("daemon stopped")
			}
		}

		return err
	})

	// Log lock/listener errors that runWithLock returns before entering the callback.
	// Errors inside the callback (admin token, database, serve) are already logged.
	if err != nil && !callbackEntered {

		logger := logging.snapshotLogger()

		if logger != nil {
			logger.Error("daemon startup failed",
				slog.String("operation", "serve_startup"),
				slog.String("error", err.Error()),
			)
		}
	}

	return err
}

func main() {
	exitCode := runCommand(os.Args[1:])
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

// newHTTPServer creates the production HTTP server with operational
// ErrorLog bridged to the configured operational logger.
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog: slog.NewLogLogger(
			opLog(context.Background()).Handler(), slog.LevelError),
	}
}
