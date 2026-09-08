package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
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
	waitForDialReady(t, "unix", socketPath)

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

// TestRegistryLoginUsageListsAgentEndpointFlags proves the explicit
// registry login Usage names the agent endpoint flags its parser
// registers (--system/--endpoint; agent commands authenticate only with
// the Session token and accept no --token-file). This is the agent-family
// counterpart of the launcher synopsis drift protection.
func TestRegistryLoginUsageListsAgentEndpointFlags(t *testing.T) {
	for _, want := range []string{"--system", "--endpoint ENDPOINT"} {
		if !strings.Contains(registryLoginCommand.Usage, want) {
			t.Errorf("registry login usage %q is missing %s", registryLoginCommand.Usage, want)
		}
	}
	flags := collectFlagsForCommand(registryLoginCommand)
	for _, want := range []string{"--system", "--endpoint"} {
		if !slices.Contains(flags, want) {
			t.Errorf("registry login flags %v missing %s", flags, want)
		}
	}
	for _, flag := range flags {
		if flag == "--token-file" {
			t.Errorf("agent command registry login must not register --token-file: %v", flags)
		}
	}
}

// TestRegistryLoginCLISuccessJSONEnvelope proves JSON mode prints the exact
// one-field server response and the human success line names the registry.
func TestRegistryLoginCLISuccessJSONEnvelope(t *testing.T) {
	stdout, stderr := runRegistryLoginCLIAgainstFake(t, []string{"--json"}, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Registry string `json:"registry"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	if stderr != "" {
		t.Errorf("unexpected stderr: %s", stderr)
	}
	if strings.Contains(stdout, "Login succeeded") {
		t.Errorf("JSON mode must print the server response verbatim, got: %s", stdout)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("JSON mode must print JSON, got: %s", stdout)
	}
	if len(resp) != 1 || resp["ok"] != true {
		t.Errorf("expected exactly {\"ok\":true}, got: %s", stdout)
	}
}

// TestRegistryLoginCLIHumanSuccessLine proves human mode prints its own
// success line naming the registry without echoing credential material.
func TestRegistryLoginCLIHumanSuccessLine(t *testing.T) {
	stdout, stderr := runRegistryLoginCLIAgainstFake(t, nil, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	if stderr != "" {
		t.Errorf("unexpected stderr: %s", stderr)
	}
	if !strings.Contains(stdout, "Login succeeded for registry.example.com") {
		t.Errorf("expected human success line, got: %s", stdout)
	}
}

// TestRegistryLoginCLISecretCanary proves the CLI never echoes the supplied
// password or encoded credential material on success or failure.
func TestRegistryLoginCLISecretCanary(t *testing.T) {
	const passwordCanary = "cli-registry-canary-Zq9Lm4Xw7b"
	const usernameCanary = "cli-registry-user-canary-Rn3Kp8Qf6c"

	run := func(fail bool) {
		stdout, stderr := runRegistryLoginCLIAgainstFake(t, nil, func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Registry string `json:"registry"`
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if req.Password != passwordCanary || req.Username != usernameCanary {
				t.Errorf("CLI must send the supplied credentials unchanged: %q/%q", req.Username, req.Password)
			}
			if fail {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnprocessableEntity)
				json.NewEncoder(w).Encode(map[string]any{
					"ok":      false,
					"code":    "registry_auth_denied",
					"message": "the registry rejected the supplied username and password",
				})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": true})
		})
		for _, output := range []string{stdout, stderr} {
			if strings.Contains(output, passwordCanary) {
				t.Error("CLI output must not contain the password")
			}
			if strings.Contains(output, usernameCanary) {
				t.Error("CLI output must not contain the username")
			}
		}
	}
	run(false)
	run(true)
}

// runRegistryLoginCLIAgainstFake runs the registry login CLI against a fake
// daemon HTTP server and returns stdout and stderr. extraArgs are appended
// after the base flags (e.g. --json). The password is fed via stdin;
// --password-stdin is the only input mode (no terminal in tests).
func runRegistryLoginCLIAgainstFake(t *testing.T, extraArgs []string, handler http.HandlerFunc) (string, string) {
	t.Helper()
	tempDir := t.TempDir()
	socketPath := tempDir + "/docker-helper.sock"

	listener, listenErr := net.Listen("unix", socketPath)
	if listenErr != nil {
		t.Fatal(listenErr)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /registry/login", handler)
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	waitForDialReady(t, "unix", socketPath)

	t.Setenv("DOCKER_HELPER_SOCKET_PATH", socketPath)
	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "test-token")

	pr, pw, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatal(pipeErr)
	}
	pw.WriteString("cli-registry-canary-Zq9Lm4Xw7b\n")
	pw.Close()

	oldStdin := os.Stdin
	os.Stdin = pr
	t.Cleanup(func() {
		os.Stdin = oldStdin
		pr.Close()
	})

	var out, stderr bytes.Buffer
	args := append([]string{
		"registry", "login",
		"--registry", "registry.example.com",
		"--username", "cli-registry-user-canary-Rn3Kp8Qf6c",
		"--password-stdin",
	}, extraArgs...)
	exitCode := runCommandWithWriters(args, &out, &stderr)

	if exitCode != 0 && exitCode != 1 {
		t.Errorf("unexpected exit code %d, stderr: %s", exitCode, stderr.String())
	}
	return out.String(), stderr.String()
}
