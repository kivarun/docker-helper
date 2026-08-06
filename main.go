package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
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

	if _, err := os.Stat(cfg.AdminTokenPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintln(os.Stderr, "error: admin token not found")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Run the following to initialize:")
			fmt.Fprintln(os.Stderr, "  docker-helper init")
			return err
		}
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

	if err := os.RemoveAll(cfg.SocketPath); err != nil {
		return fmt.Errorf("cannot remove old socket: %w", err)
	}

	listener, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", cfg.SocketPath, err)
	}

	if err := os.Chmod(cfg.SocketPath, 0600); err != nil {
		return fmt.Errorf("cannot set socket permissions: %w", err)
	}

	app := &App{
		Config: cfg,
		DB:     db,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /build", app.handleBuild)
	mux.HandleFunc("GET /health", app.handleHealth)
	mux.HandleFunc("POST /run", app.handleRun)

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("docker-helper listening on %s\n", cfg.SocketPath)

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
