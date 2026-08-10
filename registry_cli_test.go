package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRegistryLoginCLIInteractive(t *testing.T) {
	// This test verifies the CLI help and flag parsing
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"registry", "login", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "registry") {
		t.Errorf("expected help text: %s", stdout.String())
	}
}

func TestRegistryLoginCLIMissingFlags(t *testing.T) {
	var stderr bytes.Buffer
	code := runCommandWithWriters([]string{"registry", "login"}, &bytes.Buffer{}, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}

func TestRegistryLoginCLIMissingSessionToken(t *testing.T) {
	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "")

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	pw.WriteString("password\n")
	pw.Close()

	oldStdin := os.Stdin
	os.Stdin = pr
	defer func() {
		os.Stdin = oldStdin
		pr.Close()
	}()

	var stderr bytes.Buffer
	code := runCommandWithWriters([]string{
		"registry", "login",
		"--registry", "registry.example.com",
		"--username", "user",
		"--password-stdin",
	}, &bytes.Buffer{}, &stderr)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stderr.String(), "DOCKER_HELPER_SESSION_TOKEN") {
		t.Errorf("expected error about DOCKER_HELPER_SESSION_TOKEN, got: %s", stderr.String())
	}
}

// TestRegistryLoginNoConfigFile verifies that registry login works without config.json.
// Agent containers only have DOCKER_HELPER_SESSION_TOKEN + socket mount.
func TestRegistryLoginNoConfigFile(t *testing.T) {
	tempDir := t.TempDir()
	socketPath := tempDir + "/docker-helper.sock"

	listener, listenErr := net.Listen("unix", socketPath)
	if listenErr != nil {
		t.Fatal(listenErr)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /registry/login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Registry string `json:"registry"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"message": "registry login successful",
		})
	})

	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	time.Sleep(50 * time.Millisecond)

	oldSocket := os.Getenv("DOCKER_HELPER_SOCKET_PATH")
	oldToken := os.Getenv("DOCKER_HELPER_SESSION_TOKEN")
	defer func() {
		os.Setenv("DOCKER_HELPER_SOCKET_PATH", oldSocket)
		os.Setenv("DOCKER_HELPER_SESSION_TOKEN", oldToken)
	}()

	os.Setenv("DOCKER_HELPER_SOCKET_PATH", socketPath)
	os.Setenv("DOCKER_HELPER_SESSION_TOKEN", "test-token")
	os.Unsetenv("DOCKER_HELPER_CONFIG")

	// Create a pipe to simulate stdin with password
	pr, pw, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatal(pipeErr)
	}
	pw.WriteString("secret-password\n")
	pw.Close()

	oldStdin := os.Stdin
	os.Stdin = pr
	defer func() {
		os.Stdin = oldStdin
		pr.Close()
	}()

	var out, stderr bytes.Buffer
	exitCode := runCommandWithWriters([]string{
		"registry", "login",
		"--registry", "registry.example.com",
		"--username", "user",
		"--password-stdin",
	}, &out, &stderr)

	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d, stderr: %s", exitCode, stderr.String())
	}
	if !strings.Contains(out.String(), "Login succeeded") {
		t.Errorf("expected success message, got: %s", out.String())
	}
}
