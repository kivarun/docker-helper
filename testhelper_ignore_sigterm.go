//go:build ignore
// +build ignore

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Ignore SIGTERM so the process survives graceful shutdown signals.
	signal.Ignore(syscall.SIGTERM)

	// Signal readiness via the file specified in READY_FILE env var.
	readyFile := os.Getenv("READY_FILE")
	if readyFile != "" {
		os.WriteFile(readyFile, nil, 0644)
	}

	// Block indefinitely until killed.
	// Use syscall.pause() which blocks until a signal is received.
	// Since SIGTERM is ignored, the process will only exit on SIGKILL.
	for {
		syscall.Pause()
	}
}
