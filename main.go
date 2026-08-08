package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

const version = "0.1.0"

const shutdownTimeout = 30 * time.Second

func printHelp() {
	fmt.Println("Usage: docker-helper <command>")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  serve    Start the HTTP server")
	fmt.Println("  init     Initialize configuration and admin token")
	fmt.Println("  version  Print version")
	fmt.Println("  help     Show this help message")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -h, --help  Show this help message")
}

func loadAdminToken(path string) ([sha256.Size]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stderr, "error: admin token not found")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Run the following to initialize:")
			fmt.Fprintln(os.Stderr, "  docker-helper init")
			return [sha256.Size]byte{}, err
		}
		fmt.Fprintln(os.Stderr, "error: cannot read admin token")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Run the following to initialize:")
		fmt.Fprintln(os.Stderr, "  docker-helper init")
		return [sha256.Size]byte{}, err
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		fmt.Fprintln(os.Stderr, "error: admin token is empty")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Run the following to initialize:")
		fmt.Fprintln(os.Stderr, "  docker-helper init")
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
// waits for either ctx cancellation (graceful shutdown) or a Serve error.
// On ctx cancellation it calls server.Shutdown with the given timeout.
// If Shutdown exceeds the timeout, server.Close is called and an error returned.
// The callback in runWithLock must not return until Shutdown completes so the
// lock stays held during the entire drain.
func serveWithShutdown(
	ctx context.Context,
	server *http.Server,
	listener net.Listener,
	timeout time.Duration,
) error {
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(listener)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		shutdownErr := server.Shutdown(shutdownCtx)

		// Serve goroutine returns ErrServerClosed after Shutdown closes the listener.
		// Drain it so we do not leak the goroutine.
		<-serveDone

		if shutdownErr == context.DeadlineExceeded {
			server.Close()
			return fmt.Errorf("graceful shutdown timeout after %v", timeout)
		}
		return shutdownErr

	case err := <-serveDone:
		return err
	}
}

func runServe() error {
	cfg, err := loadConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stderr, "error: configuration not found")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Run the following to initialize:")
			fmt.Fprintln(os.Stderr, "  docker-helper init")
			return err
		}
		return err
	}

	return runWithLock(cfg.LockPath, cfg.SocketPath, func(listener net.Listener) error {
		adminHash, err := loadAdminToken(cfg.AdminTokenPath)
		if err != nil {
			return err
		}

		db, err := openDatabase(cfg.DatabasePath)
		if err != nil {
			return err
		}
		defer db.Close()

		if err := initializeDatabase(db); err != nil {
			return err
		}

		if err := cleanupExpiredSessions(db); err != nil {
			return err
		}

		app := &App{
			Config:         cfg,
			DB:             db,
			AdminTokenHash: adminHash,
		}

		mux := http.NewServeMux()
		mux.HandleFunc("POST /build", app.handleBuild)
		mux.HandleFunc("GET /health", app.handleHealth)
		mux.HandleFunc("POST /pull", app.handlePull)
		mux.HandleFunc("POST /run", app.handleRun)
		mux.HandleFunc("POST /sessions", app.handleCreateSession)
		mux.HandleFunc("GET /sessions", app.handleListSessions)
		mux.HandleFunc("DELETE /sessions/{id}", app.handleDeleteSession)

		server := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}

		fmt.Printf("docker-helper listening on %s\n", cfg.SocketPath)

		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		return serveWithShutdown(ctx, server, listener, shutdownTimeout)
	})
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		printHelp()
		os.Exit(0)
	}

	exitCode := runCommand(args)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func runCommand(args []string) int {
	switch args[0] {
	case "serve":
		if err := runServe(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}

	case "init":
		if err := runInit(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}

	case "version":
		fmt.Println(version)

	case "help", "-h", "--help":
		printHelp()

	case "session":
		code := runSessionCommand(args[1:])
		if code != 0 {
			return code
		}

	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", args[0])
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Run the following for usage information:")
		fmt.Fprintln(os.Stderr, "  docker-helper help")
		return 1
	}

	return 0
}

func runSessionCommand(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "error: session subcommand required (list)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Run the following for usage information:")
		fmt.Fprintln(os.Stderr, "  docker-helper session list --help")
		return 2
	}

	switch args[0] {
	case "list":
		for _, arg := range args[1:] {
			if arg == "help" || arg == "-h" || arg == "--help" {
				fmt.Println("Usage: docker-helper session list [--json]")
				fmt.Println()
				fmt.Println("List active sessions.")
				fmt.Println()
				fmt.Println("Flags:")
				fmt.Println("  --json  Output in JSON format")
				return 0
			}
		}
		return runSessionList(args[1:])
	case "help", "-h", "--help":
		fmt.Println("Usage: docker-helper session list [--json]")
		fmt.Println()
		fmt.Println("List active sessions.")
		fmt.Println()
		fmt.Println("Flags:")
		fmt.Println("  --json  Output in JSON format")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "error: unknown session subcommand %q\n", args[0])
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Run the following for usage information:")
		fmt.Fprintln(os.Stderr, "  docker-helper session list --help")
		return 2
	}
}

func parseSessionListFlags(args []string) (jsonOutput bool, err error) {
	for _, arg := range args {
		switch arg {
		case "--json":
			jsonOutput = true
		default:
			return false, fmt.Errorf("unknown flag: %s", arg)
		}
	}
	return jsonOutput, nil
}

func runSessionList(args []string) int {
	return runSessionListWithWriters(args, os.Stdout, os.Stderr)
}

func runSessionListWithWriters(args []string, stdout, stderr io.Writer) int {
	jsonOutput, err := parseSessionListFlags(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	client := newUnixAPIClient(cfg.SocketPath, func() (string, error) {
		return readAdminTokenPlain(cfg.AdminTokenPath)
	})

	result, err := client.listSessions()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintf(stderr, "error: cannot encode JSON: %v\n", err)
			return 1
		}
		return 0
	}

	printSessionsTable(stdout, result.Sessions)
	return 0
}

func printSessionsTable(w io.Writer, sessions []sessionJSON) {
	tw := tabwriter.NewWriter(w, 0, 0, 1, ' ', 0)

	fmt.Fprintln(tw, "ID\tWORKSPACE\tCREATED\tEXPIRES")

	for _, s := range sessions {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			s.ID, s.Workspace, s.CreatedAt, s.ExpiresAt)
	}

	tw.Flush()
}
