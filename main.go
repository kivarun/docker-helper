package main

import (
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

const socketPath = "/run/user/1000/docker-helper.sock"

func main() {
	if err := os.RemoveAll(socketPath); err != nil {
		log.Fatal(err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatal(err)
	}

	if err := os.Chmod(socketPath, 0600); err != nil {
		log.Fatal(err)
	}

	app := &App{}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /build", app.handleBuild)
	mux.HandleFunc("GET /health", app.handleHealth)
	mux.HandleFunc("POST /run", app.handleRun)

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("docker-helper listening on %s", socketPath)

	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}