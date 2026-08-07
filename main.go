package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

const version = "0.1.0"

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
func prepareListener(socketPath string) (net.Listener, error) {
	info, err := os.Stat(socketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return createListener(socketPath)
		}
		return nil, fmt.Errorf("cannot stat socket %s: %w", socketPath, err)
	}

	if info.Mode()&os.ModeSocket == 0 {
		if info.IsDir() {
			return nil, fmt.Errorf("socket path %s is a directory", socketPath)
		}
		return nil, fmt.Errorf("socket path %s exists and is not a socket", socketPath)
	}

	// It's a socket — check if it's live or stale.
	live, err := checkSocket(socketPath)
	if err != nil {
		return nil, fmt.Errorf("cannot check socket %s: %w", socketPath, err)
	}
	if live {
		return nil, fmt.Errorf("another docker-helper is already listening on %s", socketPath)
	}

	// Stale socket — remove and create new listener.
	if err := os.Remove(socketPath); err != nil {
		return nil, fmt.Errorf("cannot remove stale socket %s: %w", socketPath, err)
	}

	return createListener(socketPath)
}

func createListener(socketPath string) (net.Listener, error) {
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on %s: %w", socketPath, err)
	}

	if err := os.Chmod(socketPath, 0600); err != nil {
		listener.Close()
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

	lockFile, err := acquireLock(cfg.LockPath)
	if err != nil {
		return err
	}
	defer lockFile.Close()

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

	listener, err := prepareListener(cfg.SocketPath)
	if err != nil {
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

	// server.Serve blocks until the server is stopped.
	// On exit, lockFile is closed by defer, releasing the lock.
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		printHelp()
		os.Exit(0)
	}

	switch args[0] {
	case "serve":
		if err := runServe(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

	case "init":
		if err := runInit(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

	case "version":
		fmt.Println(version)

	case "help", "-h", "--help":
		printHelp()

	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n", args[0])
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Run the following for usage information:")
		fmt.Fprintln(os.Stderr, "  docker-helper help")
		os.Exit(1)
	}
}
