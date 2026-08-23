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
	"sync"
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

// runWithLock acquires the daemon lock and runs the callback with the lock held.
// The callback is responsible for creating and managing listeners.
// The lock is released when the callback returns.
func runWithLock(lockPath string, fn func() error) error {
	lockFile, err := acquireLock(lockPath)
	if err != nil {
		return err
	}

	defer lockFile.Close()

	return fn()
}

// serveWithShutdownMulti handles both Unix and TCP listeners.
// In user mode, tcpListener is nil and only unixListener is served.
// In system mode, both listeners are served concurrently.
// A signal or error on ANY listener triggers shutdown of all.
func serveWithShutdownMulti(
	signalCtx context.Context,
	server *http.Server,
	unixListener net.Listener,
	tcpListener net.Listener,
	timeout time.Duration,
	onShutdown func(),
) (shutdownCtx context.Context, shutdownCancel func(), drainDone <-chan error, err error) {
	var wg sync.WaitGroup

	firstErr := make(chan error, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if serveErr := server.Serve(unixListener); serveErr != nil {
			select {
			case firstErr <- serveErr:
			default:
			}
		}
	}()

	if tcpListener != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if serveErr := server.Serve(tcpListener); serveErr != nil {
				select {
				case firstErr <- serveErr:
				default:
				}
			}
		}()
	}

	drainDoneCh := make(chan error, 1)

	startShutdown := func(serveErr error) {
		if onShutdown != nil {
			onShutdown()
		}
		shutdownCtx, shutdownCancel = context.WithTimeout(context.Background(), timeout)

		go func() {
			shutdownErr := server.Shutdown(shutdownCtx)
			var drainErr error
			if shutdownErr == context.DeadlineExceeded {
				server.Close()
				drainErr = fmt.Errorf("graceful shutdown timeout after %v", timeout)
			} else if shutdownErr != nil {
				drainErr = shutdownErr
			}
			// Wait for all Serve goroutines to finish.
			wg.Wait()
			drainDoneCh <- drainErr
		}()
	}

	// Wait for signal or any listener error.
	if tcpListener != nil {
		select {
		case <-signalCtx.Done():
			startShutdown(nil)
			drainDone = drainDoneCh
			return
		case serveErr := <-firstErr:
			startShutdown(serveErr)
			drainDone = drainDoneCh
			err = serveErr
			return
		}
	} else {
		// User mode: only Unix listener.
		select {
		case <-signalCtx.Done():
			startShutdown(nil)
			drainDone = drainDoneCh
			return
		case serveErr := <-firstErr:
			startShutdown(serveErr)
			drainDone = drainDoneCh
			err = serveErr
			return
		}
	}
}

// registerRoutes registers all production API endpoints on the given mux.
func registerRoutes(mux *http.ServeMux, app *App) {
	mux.HandleFunc("POST /build", app.handleBuild)
	mux.HandleFunc("GET /health", app.handleHealth)
	mux.HandleFunc("POST /pull", app.handlePull)
	mux.HandleFunc("POST /run", app.handleRun)
	mux.HandleFunc("POST /registry/login", app.handleRegistryLogin)
	mux.HandleFunc("POST /sessions", app.handleCreateSession)
	mux.HandleFunc("GET /sessions", app.handleListSessions)
	mux.HandleFunc("DELETE /sessions/{id}", app.handleDeleteSession)
	mux.HandleFunc("POST /reload", app.handleReload)
	mux.HandleFunc("GET /operations/{id}", app.handleOperationStatus)
	mux.HandleFunc("GET /operations/{id}/logs", app.handleOperationLogs)
	mux.HandleFunc("POST /operations/{id}/cancel", app.handleOperationCancel)
	mux.HandleFunc("POST /principals", app.handleCreatePrincipal)
	mux.HandleFunc("GET /principals", app.handleListPrincipals)
	mux.HandleFunc("GET /principals/{username}", app.handleShowPrincipal)
	mux.HandleFunc("PATCH /principals/{username}", app.handleSetPrincipal)
	mux.HandleFunc("DELETE /principals/{username}", app.handleDeletePrincipal)
	mux.HandleFunc("POST /principals/{username}/allowed-roots", app.handleAddAllowedRoot)
	mux.HandleFunc("DELETE /principals/{username}/allowed-roots", app.handleRemoveAllowedRoot)
	mux.HandleFunc("POST /principals/{username}/credentials", app.handleCreateCredential)
	mux.HandleFunc("GET /principals/{username}/credentials", app.handleListCredentials)
	mux.HandleFunc("POST /credentials/{id}/revoke", app.handleRevokeCredential)
	mux.HandleFunc("POST /admin/token/rotate", app.handleRotateAdminToken)
}

func runServe(stdout, stderr io.Writer) error {
	// Initialize logging before any other work so all errors are structured.
	// Audit JSONL -> stdout; operational JSONL -> stderr.
	initLoggers(stderr, stdout, slog.LevelInfo, false)

	// System mode requires MAC confinement. Check before loadConfig()
	// to avoid side effects (runtime directory creation) when confinement
	// is not satisfied.
	if resolveDeploymentMode() == ModeSystem {
		if err := requireMACConfinement(); err != nil {
			serveStartupError(err, "")
			return err
		}
	}

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
	// Audit JSONL -> stdout; operational JSONL -> stderr.
	initLoggers(stderr, stdout, cfg.LogLevel, cfg.AuditEnabled)

	callbackEntered := false
	err = runWithLock(cfg.LockPath, func() error {
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

		// Create MAC coordinator and reconcile live sessions.
		macDriver, err := newWorkspaceMACDriver(cfg.Mode, detectLSM)
		if err != nil {
			serveStartupError(err, "")
			return err
		}
		macCoordinator := newSessionMACCoordinator(db, macDriver)

		// Reconcile: ensure all live sessions have valid MAC state.
		if err := macCoordinator.ReconcileLiveSessions(); err != nil {
			serveStartupError(err, "MAC state for live sessions cannot be reconciled")
			return err
		}

		// Clean up stale session runtime directories that no longer
		// correspond to an active session.
		if err := cleanupStaleSessionRuntimeDirs(db, cfg.RuntimeDir); err != nil {
			opLog(context.Background()).Warn("stale session runtime cleanup failed",
				slog.String("operation", "session_runtime_cleanup"),
				slog.String("error", err.Error()),
			)
		}

		app := &App{
			Config:            cfg,
			DB:                db,
			AdminTokenHash:    adminHash,
			OperationRegistry: newOperationRegistry(),
			MACCoordinator:    macCoordinator,
		}

		mux := http.NewServeMux()
		registerRoutes(mux, app)

		server := newHTTPServer(withRequestID(withLogging(http.HandlerFunc(mux.ServeHTTP))))

		// Prepare listeners based on deployment mode.
		unixListener, tcpListener, err := prepareListeners(cfg.Mode, cfg.SocketPath, cfg.HTTPAddress)
		if err != nil {
			serveStartupError(err, "")
			return err
		}
		defer cleanupListeners(unixListener, tcpListener, cfg.SocketPath)

		logger := logging.snapshotLogger()

		if logger != nil {
			if cfg.Mode == ModeSystem {
				logger.Info("daemon listening",
					slog.String("socket", cfg.SocketPath),
					slog.String("http", cfg.HTTPAddress),
				)
			} else {
				logger.Info("daemon listening",
					slog.String("socket", cfg.SocketPath),
				)
			}
		}

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		shutdownCtx, shutdownCancel, drainDone, err := serveWithShutdownMulti(ctx, server, unixListener, tcpListener, cfg.ShutdownTimeout, func() {
			// Shutdown triggered (signal or Serve error) — close the operation
			// gate so no new operations are accepted.
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
