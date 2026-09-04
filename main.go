package main

import (
	"bufio"
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

// acquireDaemonInstanceLock opens the daemon instance lock file and acquires
// an exclusive non-blocking flock. Returns the open file that must stay open
// for the lock to remain held.
func acquireDaemonInstanceLock(path string) (*os.File, error) {
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

// withDaemonInstanceLock acquires the daemon instance lock and runs the
// callback with the lock held. The callback is responsible for creating and
// managing listeners. The lock is released when the callback returns.
func withDaemonInstanceLock(lockPath string, fn func() error) error {
	lockFile, err := acquireDaemonInstanceLock(lockPath)
	if err != nil {
		return err
	}

	defer lockFile.Close()

	return fn()
}

// serveHTTPUntilShutdown handles both Unix and TCP listeners.
// In user mode, tcpListener is nil and only unixListener is served.
// In system mode, both listeners are served concurrently.
// A signal or error on ANY listener triggers shutdown of all.
// shutdownTimeout is resolved at the moment shutdown begins, so the budget
// always reflects the ACTUAL App configuration (a reload may have changed
// shutdown_timeout since daemon startup).
func serveHTTPUntilShutdown(
	signalCtx context.Context,
	server *http.Server,
	unixListener net.Listener,
	tcpListener net.Listener,
	shutdownTimeout func() time.Duration,
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
		timeout := shutdownTimeout()
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
	mux.HandleFunc("GET /auth", app.handleAuth)
	mux.HandleFunc("GET /principals/{username}", app.handleShowPrincipal)
	mux.HandleFunc("PATCH /principals/{username}", app.handleSetPrincipal)
	mux.HandleFunc("DELETE /principals/{username}", app.handleDeletePrincipal)
	mux.HandleFunc("POST /principals/{username}/allowed-roots", app.handleAddPrincipalAllowedRoot)
	mux.HandleFunc("DELETE /principals/{username}/allowed-roots", app.handleRemovePrincipalAllowedRoot)
	mux.HandleFunc("POST /principals/{username}/credentials", app.handleCreateCredential)
	mux.HandleFunc("GET /principals/{username}/credentials", app.handleListCredentials)
	mux.HandleFunc("POST /principals/{username}/credentials/{name}/rotate", app.handleRotatePrincipalCredential)
	mux.HandleFunc("POST /credentials/{id}/revoke", app.handleRevokeCredential)
	mux.HandleFunc("POST /principals/{username}/launchers", app.handleCreateLauncher)
	mux.HandleFunc("GET /principals/{username}/launchers", app.handleListLaunchers)
	mux.HandleFunc("GET /principals/{username}/launchers/{launcher}", app.handleShowLauncher)
	mux.HandleFunc("PATCH /principals/{username}/launchers/{launcher}", app.handlePatchLauncher)
	mux.HandleFunc("PUT /principals/{username}/launchers/{launcher}/allowed-roots", app.handleReplaceLauncherAllowedRoots)
	mux.HandleFunc("DELETE /principals/{username}/launchers/{launcher}", app.handleDeleteLauncher)
	mux.HandleFunc("PUT /principals/{username}/launchers/{launcher}/credential", app.handleIssueLauncherCredential)
	mux.HandleFunc("GET /principals/{username}/launchers/{launcher}/credential", app.handleGetLauncherCredential)
	mux.HandleFunc("POST /principals/{username}/launchers/{launcher}/credential/rotate", app.handleRotateLauncherCredential)
	mux.HandleFunc("DELETE /principals/{username}/launchers/{launcher}/credential", app.handleDeleteLauncherCredential)
	mux.HandleFunc("POST /admin/token/rotate", app.handleRotateAdminToken)
}

// runDaemon implements the docker-helper serve command. It owns the daemon
// lifecycle: logging initialization, system-mode MAC confinement check, config
// preparation, daemon instance locking, admin-token loading, database open/init,
// expired Session cleanup, MAC reconciliation, stale runtime-dir cleanup, route
// registration, listener preparation, shutdown signal handling, operation
// admission shutdown, operation termination, and HTTP graceful drain.
func runDaemon(stdout, stderr io.Writer) error {
	// Initialize logging before any other work so all errors are structured.
	// Audit JSONL -> stdout; operational JSONL -> stderr.
	initLoggers(stderr, stdout, slog.LevelInfo, false)

	// System mode requires MAC confinement. Check before loadAndPrepareRuntimeConfig()
	// to avoid side effects (runtime directory creation) when confinement
	// is not satisfied.
	if resolveDeploymentMode() == ModeSystem {
		if err := requireMACConfinement(); err != nil {
			serveStartupError(err, "")
			return err
		}
	}

	cfg, err := loadAndPrepareRuntimeConfig()
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
	err = withDaemonInstanceLock(cfg.InstanceLockPath, func() error {
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

		// User-mode ownership provisioning: resolve the real daemon-owner OS
		// identity and its Principal/'default' Launcher. System mode skips this.
		userModeDefault, err := ensureUserModeOwnership(db, cfg.Mode)
		if err != nil {
			serveStartupError(err, "")
			return err
		}

		// Session ownership cutover: rebuild any pre-cutover (principal-owned)
		// sessions table to the final Launcher-owned schema. Idempotent: a no-op
		// on the final schema. Must run after user-mode ownership provisioning
		// and before any other Session consumers.
		if _, err := migrateSessionOwnership(db, cfg.Mode, userModeDefault); err != nil {
			serveStartupError(err, "")
			return err
		}

		// Default-Launcher backfill: every Principal must carry its canonical
		// 'default' Launcher so the Launcher-owned Session model never fails
		// for missing ownership. Idempotent: a no-op once every Principal has
		// one. Runs after the ownership cutover, which already provisions
		// defaults for Principals with migrated Session rows.
		if _, err := migrateDefaultLaunchers(db); err != nil {
			serveStartupError(err, "")
			return err
		}

		if _, err := cleanupExpiredSessions(db); err != nil {
			serveStartupError(err, "")
			return err
		}

		// Create MAC coordinator and reconcile live sessions.
		// User mode (or no active MAC driver) leaves MACCoordinator nil, per the
		// documented App invariant, so persisted live sessions remain usable
		// without in-memory MAC bindings.
		macCoordinator, err := newMACCoordinatorForMode(db, cfg.Mode, detectLSM)
		if err != nil {
			serveStartupError(err, "")
			return err
		}

		// Reconcile: ensure all live sessions have valid MAC state.
		if macCoordinator != nil {
			if err := macCoordinator.ReconcileLiveSessions(); err != nil {
				serveStartupError(err, "MAC state for live sessions cannot be reconciled")
				return err
			}
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
			Config:              cfg,
			DB:                  db,
			AdminTokenHash:      adminHash,
			OperationSupervisor: newOperationSupervisor(),
			MACCoordinator:      macCoordinator,
			userModeDefault:     userModeDefault,
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

		shutdownCtx, shutdownCancel, drainDone, err := serveHTTPUntilShutdown(ctx, server, unixListener, tcpListener, func() time.Duration {
			return app.getConfig().ShutdownTimeout
		}, func() {
			// Shutdown triggered (signal or Serve error) — close the operation
			// gate so no new operations are accepted.
			if app.OperationSupervisor != nil {
				app.OperationSupervisor.beginShutdown()
			}
		})

		// Terminate running operations with the same absolute deadline used
		// by HTTP drain. HTTP drain and operation termination proceed
		// concurrently under the one wall-clock shutdown budget.
		if app.OperationSupervisor != nil {
			app.OperationSupervisor.terminateForShutdown(shutdownCtx, app.killContainerBestEffort)
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

	// Log lock/listener errors that withDaemonInstanceLock returns before entering the callback.
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

// HTTP connection-lifetime bounds.
//
// These bound the three confirmed resource-retention cases (slow request body,
// idle keep-alive connection, slow response reader) without imposing any
// timeout on legitimate handler computation such as a long synchronous docker
// pull. They are deliberate production constants, not configuration.
const (
	// serverReadHeaderTimeout bounds reading the request headers.
	serverReadHeaderTimeout = 10 * time.Second
	// serverReadTimeout bounds reading the complete request including the
	// body. Request bodies are capped at maxRequestBody (16 KiB), so 30s is
	// generous for legitimate local API traffic while terminating slow-body
	// senders.
	serverReadTimeout = 30 * time.Second
	// serverIdleTimeout bounds how long a completed keep-alive connection may
	// sit idle before it is closed, so it cannot hold an FD/goroutine forever.
	serverIdleTimeout = 30 * time.Second
	// serverResponseDeliveryTimeout bounds delivering the response from the
	// FIRST response write until the handler completes. It deliberately does
	// not bound pre-response handler computation.
	serverResponseDeliveryTimeout = 30 * time.Second
)

// serverTimeouts groups the HTTP connection-lifetime bounds. The zero value
// disables the corresponding net/http timeout, matching http.Server
// semantics. This is an unexported test seam: production uses
// productionServerTimeouts and focused tests use millisecond-scale values.
// These are not product configuration.
type serverTimeouts struct {
	readHeader       time.Duration
	read             time.Duration
	idle             time.Duration
	responseDelivery time.Duration
}

func productionServerTimeouts() serverTimeouts {
	return serverTimeouts{
		readHeader:       serverReadHeaderTimeout,
		read:             serverReadTimeout,
		idle:             serverIdleTimeout,
		responseDelivery: serverResponseDeliveryTimeout,
	}
}

// newHTTPServer creates the production HTTP server with operational
// ErrorLog bridged to the configured operational logger and the production
// connection-lifetime bounds.
func newHTTPServer(handler http.Handler) *http.Server {
	return newHTTPServerWithTimeouts(handler, productionServerTimeouts())
}

// newHTTPServerWithTimeouts creates an HTTP server with explicit connection
// lifetime bounds. Production goes through newHTTPServer; focused
// connection-lifecycle tests supply millisecond-scale values through this
// unexported seam.
func newHTTPServerWithTimeouts(handler http.Handler, to serverTimeouts) *http.Server {
	if to.responseDelivery > 0 {
		handler = boundResponseDelivery(handler, to.responseDelivery)
	}
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: to.readHeader,
		ReadTimeout:       to.read,
		IdleTimeout:       to.idle,
		ErrorLog: slog.NewLogLogger(
			opLog(context.Background()).Handler(), slog.LevelError),
	}
}

// boundResponseDelivery wraps handler so a single response-delivery deadline
// starts at the FIRST response write (WriteHeader or Write) and runs for
// window. Handler computation before the first write is NOT bounded: long
// synchronous operations such as a docker pull may run for any duration. The
// net/http server clears the connection write deadline after each request in
// its keep-alive loop, so an expired deadline cannot poison the next request
// on the same connection.
func boundResponseDelivery(handler http.Handler, window time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(&deliveryBoundedWriter{
			ResponseWriter: w,
			window:         window,
		}, r)
	})
}

// deliveryBoundedWriter arms the response-delivery deadline on the first
// response write. It forwards the optional interfaces net/http exposes
// (Flusher, Hijacker, Pusher, ReaderFrom) so existing handler behavior is
// preserved, and exposes Unwrap so http.ResponseController can reach the
// underlying writer to arm the deadline on the real connection.
type deliveryBoundedWriter struct {
	http.ResponseWriter
	window      time.Duration
	deadlineSet bool
}

// Unwrap lets http.ResponseController and other unwrapping machinery reach the
// underlying ResponseWriter.
func (w *deliveryBoundedWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// arm arms the response-delivery deadline exactly once, on the first write.
func (w *deliveryBoundedWriter) arm() {
	if w.deadlineSet {
		return
	}
	w.deadlineSet = true
	if w.window > 0 {
		_ = http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(w.window))
	}
}

func (w *deliveryBoundedWriter) WriteHeader(status int) {
	w.arm()
	w.ResponseWriter.WriteHeader(status)
}

func (w *deliveryBoundedWriter) Write(p []byte) (int, error) {
	w.arm()
	return w.ResponseWriter.Write(p)
}

// Flush forwards http.Flusher when the underlying writer supports it. A flush
// is a response write, so it arms the response-delivery deadline like
// WriteHeader, Write, and ReadFrom do.
func (w *deliveryBoundedWriter) Flush() {
	w.arm()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards http.Hijacker when the underlying writer supports it.
func (w *deliveryBoundedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported")
}

// Push forwards http.Pusher when the underlying writer supports it.
func (w *deliveryBoundedWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

// ReadFrom forwards io.ReaderFrom when the underlying writer supports it so
// io.Copy into the wrapped writer keeps its optimized path.
func (w *deliveryBoundedWriter) ReadFrom(r io.Reader) (int64, error) {
	w.arm()
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(w.ResponseWriter, r)
}
