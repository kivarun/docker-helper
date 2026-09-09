package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

type agentCLITestServer struct {
	mux *http.ServeMux
}

func (s *agentCLITestServer) handlePull(handler func(http.ResponseWriter, *http.Request)) {
	s.mux.HandleFunc("POST /pull", handler)
}

func (s *agentCLITestServer) handleBuild(handler func(http.ResponseWriter, *http.Request)) {
	s.mux.HandleFunc("POST /build", handler)
}

func (s *agentCLITestServer) handleRun(handler func(http.ResponseWriter, *http.Request)) {
	s.mux.HandleFunc("POST /run", handler)
}

func (s *agentCLITestServer) handleOperationStatus(handler func(http.ResponseWriter, *http.Request)) {
	s.mux.HandleFunc("GET /operations/{id}", handler)
}

func (s *agentCLITestServer) handleOperationLogs(handler func(http.ResponseWriter, *http.Request)) {
	s.mux.HandleFunc("GET /operations/{id}/logs", handler)
}

func (s *agentCLITestServer) handleOperationCancel(handler func(http.ResponseWriter, *http.Request)) {
	s.mux.HandleFunc("POST /operations/{id}/cancel", handler)
}

func runAgentCLITestWithServer(t *testing.T, args []string, token string, setupServer func(*agentCLITestServer)) (stdout bytes.Buffer, stderr bytes.Buffer, exitCode int) {
	t.Helper()

	tempDir := t.TempDir()
	runtimeDir := tempDir + "/runtime"
	if mkErr := os.MkdirAll(runtimeDir+"/docker-helper", 0700); mkErr != nil {
		t.Fatal(mkErr)
	}
	socketPath := runtimeDir + "/docker-helper/docker-helper.sock"

	mux := http.NewServeMux()
	if setupServer != nil {
		srv := &agentCLITestServer{mux: mux}
		setupServer(srv)
	}

	listener, lErr := net.Listen("unix", socketPath)
	if lErr != nil {
		t.Fatal(lErr)
	}
	defer listener.Close()

	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	oldSocket := os.Getenv("DOCKER_HELPER_SOCKET_PATH")
	oldToken := os.Getenv("DOCKER_HELPER_SESSION_TOKEN")
	defer func() {
		os.Setenv("DOCKER_HELPER_SOCKET_PATH", oldSocket)
		os.Setenv("DOCKER_HELPER_SESSION_TOKEN", oldToken)
	}()

	os.Setenv("DOCKER_HELPER_SOCKET_PATH", socketPath)
	if token == "" {
		token = "test-session-token"
	}
	os.Setenv("DOCKER_HELPER_SESSION_TOKEN", token)

	exitCode = runCommandWithWriters(args, &stdout, &stderr)

	return stdout, stderr, exitCode
}

func TestPullMissingSessionToken(t *testing.T) {
	oldSocket := os.Getenv("DOCKER_HELPER_SOCKET_PATH")
	oldToken := os.Getenv("DOCKER_HELPER_SESSION_TOKEN")
	defer func() {
		os.Setenv("DOCKER_HELPER_SOCKET_PATH", oldSocket)
		os.Setenv("DOCKER_HELPER_SESSION_TOKEN", oldToken)
	}()

	os.Unsetenv("DOCKER_HELPER_SOCKET_PATH")
	os.Unsetenv("DOCKER_HELPER_SESSION_TOKEN")

	var out, err bytes.Buffer
	exitCode := runCommandWithWriters([]string{"pull", "alpine:3.24"}, &out, &err)
	if exitCode != 1 {
		t.Errorf("expected exit 1, got %d", exitCode)
	}
	if !strings.Contains(err.String(), "DOCKER_HELPER_SESSION_TOKEN") {
		t.Errorf("expected token error, got: %s", err.String())
	}
}

func TestPullMissingImage(t *testing.T) {
	_, _, exitCode := runAgentCLITestWithServer(t, []string{"pull"}, "", nil)
	if exitCode != 2 {
		t.Errorf("expected exit 2, got %d", exitCode)
	}
}

func TestBuildMissingFlags(t *testing.T) {
	_, err, exitCode := runAgentCLITestWithServer(t, []string{"build", "--image", "app:test"}, "", nil)
	if exitCode != 2 {
		t.Errorf("expected exit 2, got %d", exitCode)
	}
	if !strings.Contains(err.String(), "--context is required") {
		t.Errorf("expected context error, got: %s", err.String())
	}
}

func TestRunContainerExitNonzero(t *testing.T) {
	exitCode := 42
	stdout, stderr, actualExit := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--", "sh", "-c", "exit 42",
	}, "", func(s *agentCLITestServer) {
		s.handleRun(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"ok":        false,
				"code":      "container_exit_nonzero",
				"message":   "workload exited with a non-zero status",
				"output":    "workload output\n",
				"truncated": false,
				"duration":  "1s",
				"exit_code": exitCode,
			})
		})
	})

	if actualExit != 42 {
		t.Errorf("expected exit 42, got %d (stderr %s)", actualExit, stderr.String())
	}
	if !strings.Contains(stdout.String(), "workload output") {
		t.Errorf("expected workload output on stdout, got: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "container_exit_nonzero") {
		t.Errorf("expected container_exit_nonzero diagnostic, got: %s", stderr.String())
	}
}

func TestTokenNotInOutput(t *testing.T) {
	const token = "dht_super_secret_session_token_12345"

	out, err, exitCode := runAgentCLITestWithServer(t, []string{
		"pull", "alpine:3.24",
	}, token, func(s *agentCLITestServer) {
		s.handlePull(func(w http.ResponseWriter, r *http.Request) {
			expectedAuth := "Bearer " + token
			if r.Header.Get("Authorization") != expectedAuth {
				t.Errorf("expected Authorization %q, got %q", expectedAuth, r.Header.Get("Authorization"))
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"ok":      true,
				"message": "image pulled successfully",
			})
		})
	})

	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if strings.Contains(out.String(), token) {
		t.Error("token must not appear in stdout")
	}
	if strings.Contains(err.String(), token) {
		t.Error("token must not appear in stderr")
	}
}

func TestPullNoConfigFile(t *testing.T) {
	tempDir := t.TempDir()
	socketPath := tempDir + "/docker-helper.sock"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /pull", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"message": "image pulled successfully",
			"output":  "Status: pulled\n",
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

	var out, stderr bytes.Buffer
	exitCode := runCommandWithWriters([]string{"pull", "alpine:3.24"}, &out, &stderr)

	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "pulled") {
		t.Errorf("expected pull output, got: %s", out.String())
	}
}

// TestWaitForOperationFinalLogsRace tests the race condition where:
// - first logs request returns empty (next_offset=0)
// - status is already terminal
// - final logs request returns output
// TestRunInvalidMountOption verifies that unknown mount options are rejected.
func TestRunInvalidMountOption(t *testing.T) {
	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--mount", ".:/workspace:rw", "--", "echo", "hi",
	}, "", nil)
	if exitCode != 2 {
		t.Errorf("expected exit 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "invalid mount option") {
		t.Errorf("expected mount option error, got: %s", stderr.String())
	}
}

// TestRunMountAbsoluteSourceRejected verifies that absolute source paths
// are rejected at CLI level with a clear error.
func TestRunMountAbsoluteSourceRejected(t *testing.T) {
	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--mount", "/workspace/probe.txt:/target", "--", "echo", "hi",
	}, "", nil)
	if exitCode != 2 {
		t.Errorf("expected exit 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "source must be relative to session workspace") {
		t.Errorf("expected source relative error, got: %s", stderr.String())
	}
}

// TestRunFailedDiagnostics verifies that failed run prints diagnostics.
func TestRunFailedDiagnostics(t *testing.T) {
	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--", "echo", "hi",
	}, "", func(s *agentCLITestServer) {
		s.handleRun(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]any{
				"ok":      false,
				"code":    "backend_failure",
				"message": "unexpected Engine interaction",
			})
		})
	})

	if exitCode != 1 {
		t.Errorf("expected exit 1, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "backend_failure") {
		t.Errorf("expected result code in error, got: %s", stderr.String())
	}
}

// TestPullFailedPreservesOutput verifies that failed pull preserves Docker
// output and routes it to stderr with the summary error (errors belong on
// stderr), while stdout stays clean on failure.
func TestPullFailedPreservesOutput(t *testing.T) {
	out, stderr, exitCode := runAgentCLITestWithServer(t, []string{"pull", "invalid:tag"}, "", func(s *agentCLITestServer) {
		s.handlePull(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{
				"ok":      false,
				"code":    "docker_pull_failed",
				"message": "docker pull failed",
				"output":  "Error: invalid reference\n",
			})
		})
	})

	if exitCode != 1 {
		t.Errorf("expected exit 1, got %d", exitCode)
	}
	// Docker error output and summary error both go to stderr on failure.
	if !strings.Contains(stderr.String(), "invalid reference") {
		t.Errorf("expected Docker output in stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "docker pull failed") {
		t.Errorf("expected error message in stderr, got: %s", stderr.String())
	}
	if out.String() != "" {
		t.Errorf("expected empty stdout on failure, got: %s", out.String())
	}
}

// TestPullStreamContractSuccess verifies the pull CLI stdout contract on
// success: successful pull progress goes to stdout and stderr stays clean.
func TestPullStreamContractSuccess(t *testing.T) {
	out, stderr, exitCode := runAgentCLITestWithServer(t, []string{"pull", "alpine:3.24"}, "", func(s *agentCLITestServer) {
		s.handlePull(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"ok":      true,
				"message": "image pulled successfully",
				"output":  "Status: pulled\n",
			})
		})
	})
	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "pulled") {
		t.Errorf("expected pull output on stdout, got: %s", out.String())
	}
	if stderr.String() != "" {
		t.Errorf("expected empty stderr on success, got: %s", stderr.String())
	}
}

// TestPullStreamContractFailure verifies the pull CLI stderr contract on
// failure: docker diagnostics and the classification message go to stderr and
// stdout stays clean.
func TestPullStreamContractFailure(t *testing.T) {
	out, stderr, exitCode := runAgentCLITestWithServer(t, []string{"pull", "invalid:tag"}, "", func(s *agentCLITestServer) {
		s.handlePull(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{
				"ok":      false,
				"code":    "image_not_found",
				"message": "image not found",
				"output":  "Error response from daemon: manifest unknown\n",
			})
		})
	})
	if exitCode != 1 {
		t.Errorf("expected exit 1, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "manifest unknown") {
		t.Errorf("expected docker diagnostic on stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "image not found") {
		t.Errorf("expected classification message on stderr, got: %s", stderr.String())
	}
	if out.String() != "" {
		t.Errorf("expected empty stdout on failure, got: %s", out.String())
	}
}

// TestPullContract verifies that pull sends the expected JSON contract.
func TestPullContract(t *testing.T) {
	received := false
	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{"pull", "alpine:3.24"}, "", func(s *agentCLITestServer) {
		s.handlePull(func(w http.ResponseWriter, r *http.Request) {
			var req pullRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("cannot decode request: %v", err)
			}
			if req.Image != "alpine:3.24" {
				t.Errorf("expected image alpine:3.24, got %s", req.Image)
			}
			received = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": true})
		})
	})
	if !received {
		t.Fatal("pull request not received")
	}
	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d, stderr: %s", exitCode, stderr.String())
	}
}

// TestBuildContract verifies that build sends the expected JSON contract.
func TestBuildContract(t *testing.T) {
	opID := "op_build"
	received := false
	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"build", "--context", ".", "--dockerfile", "Dockerfile", "--image", "myapp:latest",
		"--build-arg", "FOO=bar", "--build-arg", "BAZ=qux",
	}, "", func(s *agentCLITestServer) {
		s.handleBuild(func(w http.ResponseWriter, r *http.Request) {
			var req buildRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("cannot decode request: %v", err)
			}
			if req.Context != "." {
				t.Errorf("expected context '.', got %s", req.Context)
			}
			if req.Dockerfile != "Dockerfile" {
				t.Errorf("expected dockerfile 'Dockerfile', got %s", req.Dockerfile)
			}
			if req.Image != "myapp:latest" {
				t.Errorf("expected image 'myapp:latest', got %s", req.Image)
			}
			if req.BuildArgs["FOO"] != "bar" {
				t.Errorf("expected FOO=bar, got %s", req.BuildArgs["FOO"])
			}
			if req.BuildArgs["BAZ"] != "qux" {
				t.Errorf("expected BAZ=qux, got %s", req.BuildArgs["BAZ"])
			}
			received = true
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"ok":           true,
				"operation_id": opID,
				"status":       "running",
			})
		})
		s.handleOperationStatus(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"ok":           true,
				"operation_id": opID,
				"status":       "succeeded",
			})
		})
		s.handleOperationLogs(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"ok":           true,
				"operation_id": opID,
				"offset":       int64(0),
				"next_offset":  int64(0),
				"truncated":    false,
				"logs":         "",
			})
		})
	})
	if !received {
		t.Fatal("build request not received")
	}
	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d, stderr: %s", exitCode, stderr.String())
	}
}

// TestRunContract verifies that run sends the expected JSON contract.
// TestRunContract verifies that the CLI sends the accepted run request shape
// and returns success through the synchronous flat result.
func TestRunContract(t *testing.T) {
	received := false
	stdout, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24",
		"--env", "KEY=value",
		"--mount", ".:/workspace:ro",
		"--shm-size", "128m",
		"--", "echo", "hello",
	}, "", func(s *agentCLITestServer) {
		s.handleRun(func(w http.ResponseWriter, r *http.Request) {
			var req runRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("cannot decode request: %v", err)
			}
			if req.Image != "alpine:3.24" {
				t.Errorf("expected image alpine:3.24, got %s", req.Image)
			}
			if req.Environment["KEY"] != "value" {
				t.Errorf("expected KEY=value, got %s", req.Environment["KEY"])
			}
			if len(req.Mounts) != 1 {
				t.Fatalf("expected 1 mount, got %d", len(req.Mounts))
			}
			if req.Mounts[0].Source != "." {
				t.Errorf("expected mount source '.', got %s", req.Mounts[0].Source)
			}
			if req.Mounts[0].Target != "/workspace" {
				t.Errorf("expected mount target '/workspace', got %s", req.Mounts[0].Target)
			}
			if !req.Mounts[0].ReadOnly {
				t.Error("expected mount to be read-only")
			}
			if req.ShmSize != "128m" {
				t.Errorf("expected shm_size '128m', got %s", req.ShmSize)
			}
			if len(req.Command) != 2 || req.Command[0] != "echo" || req.Command[1] != "hello" {
				t.Errorf("unexpected command: %v", req.Command)
			}
			received = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"ok":        true,
				"output":    "hello",
				"truncated": false,
				"duration":  "1s",
				"exit_code": 0,
			})
		})
	})
	if !received {
		t.Fatal("run request not received")
	}
	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d, stderr: %s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "hello") {
		t.Errorf("expected run output on stdout, got: %s", stdout.String())
	}
}

// TestRunTruncatedOutputWarns verifies that a truncated synchronous run
// result produces the warning on stderr and the bounded output on stdout.
func TestRunTruncatedOutputWarns(t *testing.T) {
	stdout, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24",
	}, "", func(s *agentCLITestServer) {
		s.handleRun(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"ok":        true,
				"output":    "newest output",
				"truncated": true,
				"duration":  "1s",
				"exit_code": 0,
			})
		})
	})
	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d, stderr: %s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "newest output") {
		t.Errorf("expected bounded output on stdout, got: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "truncated") {
		t.Errorf("expected truncation warning, got: %s", stderr.String())
	}
}

// TestSignalExitCodes proves the conventional CLI exit codes for signals.
func TestSignalExitCodes(t *testing.T) {
	if got := signalExitCode(syscall.SIGINT); got != 130 {
		t.Errorf("signalExitCode(SIGINT) = %d, want 130", got)
	}
	if got := signalExitCode(syscall.SIGTERM); got != 143 {
		t.Errorf("signalExitCode(SIGTERM) = %d, want 143", got)
	}
	if got := signalExitCode(syscall.SIGHUP); got != 1 {
		t.Errorf("signalExitCode(other) = %d, want 1", got)
	}
}

// TestRunSignalExitsWithSignalCode verifies that SIGINT during a blocking
// synchronous run cancels the request and reports the conventional signal
// error: runWithSignalCh cancels the request context, waits for the request
// to return, and produces a signalExitError carrying the signal.
func TestRunSignalExitsWithSignalCode(t *testing.T) {
	tempDir := t.TempDir()
	socketPath := tempDir + "/docker-helper.sock"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	requested := make(chan struct{})
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("POST /run", func(w http.ResponseWriter, r *http.Request) {
		close(requested)
		// Hold the request open until the test releases it; the CLI must
		// already have cancelled the in-flight request by then.
		<-release
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok":       false,
			"code":     "docker_run_failed",
			"duration": "1s",
		})
	})

	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	waitForDialReady(t, "unix", socketPath)

	c := newUnixAPIClient(socketPath, func() (string, error) { return "test-token", nil }, nil)

	sigCh := make(chan os.Signal, 1)
	var out, errBuf bytes.Buffer
	// Deliver the injected signal once the daemon handler is inside the
	// blocking run request.
	go func() {
		<-requested
		sigCh <- syscall.SIGINT
	}()

	resp, err := runWithSignalCh(c, runRequest{Image: "alpine:3.24", Command: []string{"sleep", "300"}}, sigCh, &out, &errBuf)
	if resp != nil {
		t.Fatalf("interrupted run must not produce a usable result, got %+v", resp)
	}
	sigErr, ok := err.(*signalExitError)
	if !ok {
		t.Fatalf("expected signalExitError, got %v", err)
	}
	if sigErr.Signal != syscall.SIGINT {
		t.Errorf("signal = %v, want SIGINT", sigErr.Signal)
	}
	if !strings.Contains(errBuf.String(), "run did not return a result") {
		t.Errorf("expected no-result warning, got: %s", errBuf.String())
	}
	// runWithSignalCh returning guarantees the request goroutine exited
	// (no orphan) after the cancellation.
	close(release)
}

func TestBuildContextAbsoluteRejected(t *testing.T) {
	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"build", "--context", "/absolute/path", "--dockerfile", "Dockerfile", "--image", "app:test",
	}, "", nil)
	if exitCode != 2 {
		t.Errorf("expected exit 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "relative") {
		t.Errorf("expected relative path error, got: %s", stderr.String())
	}
}

func TestResolveAgentSocketPathExplicitWins(t *testing.T) {
	t.Setenv("DOCKER_HELPER_SOCKET_PATH", "/explicit/path.sock")
	t.Setenv("XDG_RUNTIME_DIR", "/xdg/runtime")
	got := resolveAgentSocketPath()
	if got != "/explicit/path.sock" {
		t.Errorf("resolveAgentSocketPath() = %q, want %q", got, "/explicit/path.sock")
	}
}

func TestResolveAgentSocketPathXDGUserSocketExists(t *testing.T) {
	runtimeDir := t.TempDir()
	userSocket := filepath.Join(runtimeDir, "docker-helper", "docker-helper.sock")
	if err := os.MkdirAll(filepath.Dir(userSocket), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userSocket, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_HELPER_SOCKET_PATH", "")
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	got := resolveAgentSocketPath()
	if got != userSocket {
		t.Errorf("resolveAgentSocketPath() = %q, want %q", got, userSocket)
	}
}

func TestResolveAgentSocketPathXDGNoUserSocketFallsBackToSystem(t *testing.T) {
	// XDG_RUNTIME_DIR is set but the user-mode socket does not exist: the
	// agent CLI must fall back to the system socket rather than fail.
	t.Setenv("DOCKER_HELPER_SOCKET_PATH", "")
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	got := resolveAgentSocketPath()
	want := "/run/docker-helper/docker-helper.sock"
	if got != want {
		t.Errorf("resolveAgentSocketPath() = %q, want %q", got, want)
	}
}

func TestResolveAgentSocketPathFallback(t *testing.T) {
	t.Setenv("DOCKER_HELPER_SOCKET_PATH", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	got := resolveAgentSocketPath()
	want := "/run/docker-helper/docker-helper.sock"
	if got != want {
		t.Errorf("resolveAgentSocketPath() = %q, want %q", got, want)
	}
}

// TestResolveAgentClientSystemFlag verifies --system selects the system daemon
// socket even when DOCKER_HELPER_SOCKET_PATH points elsewhere. It binds a real
// Unix listener at the system socket path (via the test seam) and drives a pull
// request through the resolved client's transport to prove the actual dial
// target, not just the shared baseURL.
func TestResolveAgentClientSystemFlag(t *testing.T) {
	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "system.sock")

	var received int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /pull", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", socketPath)

	origSystemSocket := systemSocketPath
	systemSocketPath = socketPath
	t.Cleanup(func() { systemSocketPath = origSystemSocket })

	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "tok")
	t.Setenv("DOCKER_HELPER_SOCKET_PATH", filepath.Join(tempDir, "elsewhere.sock"))
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	c, err := resolveAgentClient(agentClientOptions{System: true})
	if err != nil {
		t.Fatalf("resolveAgentClient(--system): %v", err)
	}
	if _, err := c.pull(pullRequest{Image: "alpine:3.24"}); err != nil {
		t.Fatalf("pull through --system client: %v", err)
	}
	if atomic.LoadInt32(&received) != 1 {
		t.Errorf("expected request to reach system socket, got %d", atomic.LoadInt32(&received))
	}
}

// TestResolveAgentClientEndpointUnixScheme verifies --endpoint unix:///path
// selects the Unix socket at that path by driving a request through the client
// transport to a real listener, even when DOCKER_HELPER_SOCKET_PATH points
// elsewhere.
func TestResolveAgentClientEndpointUnixScheme(t *testing.T) {
	tempDir := t.TempDir()
	endpointSocket := filepath.Join(tempDir, "custom.sock")

	var received int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /pull", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	listener, err := net.Listen("unix", endpointSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "unix", endpointSocket)

	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "tok")
	t.Setenv("DOCKER_HELPER_SOCKET_PATH", filepath.Join(tempDir, "elsewhere.sock"))

	c, err := resolveAgentClient(agentClientOptions{Endpoint: "unix://" + endpointSocket})
	if err != nil {
		t.Fatalf("resolveAgentClient(--endpoint unix://): %v", err)
	}
	if _, err := c.pull(pullRequest{Image: "alpine:3.24"}); err != nil {
		t.Fatalf("pull through --endpoint unix:// client: %v", err)
	}
	if atomic.LoadInt32(&received) != 1 {
		t.Errorf("expected request to reach endpoint socket, got %d", atomic.LoadInt32(&received))
	}
}

// TestResolveAgentClientEndpointHTTP verifies --endpoint http://127.0.0.1:PORT
// selects the loopback HTTP daemon by driving a request through the client
// transport to a real TCP listener.
func TestResolveAgentClientEndpointHTTP(t *testing.T) {
	var received int32
	mux := http.NewServeMux()
	mux.HandleFunc("POST /pull", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()
	waitForDialReady(t, "tcp", listener.Addr().String())

	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "tok")
	t.Setenv("DOCKER_HELPER_SOCKET_PATH", filepath.Join(t.TempDir(), "elsewhere.sock"))

	c, err := resolveAgentClient(agentClientOptions{Endpoint: fmt.Sprintf("http://127.0.0.1:%d", port)})
	if err != nil {
		t.Fatalf("resolveAgentClient(--endpoint http): %v", err)
	}
	if _, err := c.pull(pullRequest{Image: "alpine:3.24"}); err != nil {
		t.Fatalf("pull through --endpoint http client: %v", err)
	}
	if atomic.LoadInt32(&received) != 1 {
		t.Errorf("expected request to reach HTTP listener, got %d", atomic.LoadInt32(&received))
	}
}

// TestResolveAgentClientEndpointVerifiesExplicitEndpoint verifies --endpoint
// selects an explicit unix socket path.
func TestResolveAgentClientEndpoint(t *testing.T) {
	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "tok")
	t.Setenv("DOCKER_HELPER_SOCKET_PATH", "/some/other/path.sock")

	c, err := resolveAgentClient(agentClientOptions{Endpoint: "/explicit.sock"})
	if err != nil {
		t.Fatalf("resolveAgentClient(--endpoint): %v", err)
	}
	token, err := c.tokenSource()
	if err != nil {
		t.Fatalf("token source: %v", err)
	}
	if token != "tok" {
		t.Errorf("token = %q, want session token", token)
	}
}

// TestValidateAgentEndpointOptionsMutuallyExclusive verifies --system and
// --endpoint cannot be combined, and that this CLI usage error is raised before
// any runtime authentication lookup.
func TestValidateAgentEndpointOptionsMutuallyExclusive(t *testing.T) {
	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "")
	err := validateAgentEndpointOptions(agentClientOptions{System: true, Endpoint: "/x.sock"})
	if err == nil {
		t.Fatal("expected mutual-exclusion error")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestValidateAgentEndpointOptionsInvalid verifies an invalid --endpoint is
// reported as a CLI usage error regardless of session token state.
func TestValidateAgentEndpointOptionsInvalid(t *testing.T) {
	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "")
	if err := validateAgentEndpointOptions(agentClientOptions{Endpoint: "not-a-scheme"}); err == nil {
		t.Fatal("expected endpoint validation error")
	}
	if err := validateAgentEndpointOptions(agentClientOptions{}); err != nil {
		t.Fatalf("default options should validate: %v", err)
	}
}

// TestResolveAgentClientMissingSessionToken verifies the session token is still
// required even when an endpoint is supplied (no Principal token semantics).
func TestResolveAgentClientMissingSessionToken(t *testing.T) {
	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "")
	_, err := resolveAgentClient(agentClientOptions{System: true})
	if err == nil {
		t.Fatal("expected missing-session-token error")
	}
	if !strings.Contains(err.Error(), "DOCKER_HELPER_SESSION_TOKEN") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestAgentFlagsPresentInHelp verifies the new --system/--endpoint flags are
// discoverable on every agent-facing command.
func TestAgentFlagsPresentInHelp(t *testing.T) {
	cases := []struct {
		cmd  string
		args []string
	}{
		{cmd: "pull"},
		{cmd: "build"},
		{cmd: "run"},
		{cmd: "registry", args: []string{"login"}},
	}
	for _, tc := range cases {
		args := append([]string{tc.cmd}, tc.args...)
		args = append(args, "--help")
		var out, errB bytes.Buffer
		exitCode := runCommandWithWriters(args, &out, &errB)
		if exitCode != 0 {
			t.Errorf("%v: expected exit 0, got %d", tc.cmd, exitCode)
		}
		for _, flag := range []string{"--system", "--endpoint"} {
			if !strings.Contains(out.String(), flag) {
				t.Errorf("%v --help: missing flag %q", tc.cmd, flag)
			}
		}
	}
}

// TestAgentCLIMutuallyExclusiveExit2 verifies pull --system --endpoint is a CLI
// usage error (exit 2) with a mutual-exclusion diagnostic, and that this holds
// whether or not the session token is present.
func TestAgentCLIMutuallyExclusiveExit2(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
	}{
		{name: "with token", token: "tok"},
		{name: "without token", token: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DOCKER_HELPER_SESSION_TOKEN", tc.token)
			var out, errB bytes.Buffer
			exitCode := runCommandWithWriters([]string{"pull", "--system", "--endpoint", "/x", "alpine:3.24"}, &out, &errB)
			if exitCode != 2 {
				t.Errorf("exit code = %d, want 2", exitCode)
			}
			if !strings.Contains(errB.String(), "mutually exclusive") {
				t.Errorf("stderr = %q, want mutual-exclusion diagnostic", errB.String())
			}
		})
	}
}

// TestAgentCLIInvalidEndpointExit2 verifies an invalid --endpoint is reported as
// a CLI argument error (exit 2) even when the session token is missing: the CLI
// error must win over the missing-token runtime error.
func TestAgentCLIInvalidEndpointExit2(t *testing.T) {
	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "")
	var out, errB bytes.Buffer
	exitCode := runCommandWithWriters([]string{"pull", "--endpoint", "not-a-scheme", "alpine:3.24"}, &out, &errB)
	if exitCode != 2 {
		t.Errorf("exit code = %d, want 2", exitCode)
	}
	if strings.Contains(errB.String(), "DOCKER_HELPER_SESSION_TOKEN") {
		t.Errorf("stderr = %q, want endpoint validation error (not missing-token)", errB.String())
	}
	if !strings.Contains(errB.String(), "endpoint") {
		t.Errorf("stderr = %q, want endpoint validation diagnostic", errB.String())
	}
}

// TestAgentCLIMissingTokenRuntimeError verifies that a valid endpoint selection
// with a missing session token is a runtime/auth error (exit 1), not a CLI
// usage error.
func TestAgentCLIMissingTokenRuntimeError(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "system", args: []string{"pull", "--system", "alpine:3.24"}},
		{name: "endpoint", args: []string{"pull", "--endpoint", "/run/docker-helper/docker-helper.sock", "alpine:3.24"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "")
			var out, errB bytes.Buffer
			exitCode := runCommandWithWriters(tc.args, &out, &errB)
			if exitCode != 1 {
				t.Errorf("exit code = %d, want 1", exitCode)
			}
			if !strings.Contains(errB.String(), "DOCKER_HELPER_SESSION_TOKEN") {
				t.Errorf("stderr = %q, want missing-token error", errB.String())
			}
		})
	}
}

// TestPullCLITruncatedSuccess verifies that a truncated successful pull
// prints the output plus one truncation warning to stderr.
func TestPullCLITruncatedSuccess(t *testing.T) {
	out, stderr, exitCode := runAgentCLITestWithServer(t, []string{"pull", "alpine:3.24"}, "", func(s *agentCLITestServer) {
		s.handlePull(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"ok":        true,
				"message":   "image pulled successfully",
				"output":    "layer data\n",
				"truncated": true,
			})
		})
	})

	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d, stderr: %s", exitCode, stderr.String())
	}
	if !strings.Contains(out.String(), "layer data") {
		t.Errorf("expected output in stdout, got: %s", out.String())
	}
	if !strings.Contains(stderr.String(), "pull output was truncated") {
		t.Errorf("expected truncation warning in stderr, got: %s", stderr.String())
	}
}

// TestPullCLITruncatedFailure verifies that a truncated failed pull
// prints the retained output and the truncation warning alongside the error.
func TestPullCLITruncatedFailure(t *testing.T) {
	out, stderr, exitCode := runAgentCLITestWithServer(t, []string{"pull", "invalid:tag"}, "", func(s *agentCLITestServer) {
		s.handlePull(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{
				"ok":        false,
				"code":      "docker_pull_failed",
				"message":   "docker pull failed",
				"output":    "retained tail\n",
				"truncated": true,
			})
		})
	})

	if exitCode != 1 {
		t.Errorf("expected exit 1, got %d", exitCode)
	}
	// On failure the retained docker output and the truncation warning both
	// belong on stderr.
	if !strings.Contains(stderr.String(), "retained tail") {
		t.Errorf("expected retained output in stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "pull output was truncated") {
		t.Errorf("expected truncation warning in stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "docker pull failed") {
		t.Errorf("expected error message in stderr, got: %s", stderr.String())
	}
	if out.String() != "" {
		t.Errorf("expected empty stdout on failure, got: %s", out.String())
	}
}

// TestPullCLINonTruncated verifies that a non-truncated pull prints no warning.
func TestPullCLINonTruncated(t *testing.T) {
	out, stderr, exitCode := runAgentCLITestWithServer(t, []string{"pull", "alpine:3.24"}, "", func(s *agentCLITestServer) {
		s.handlePull(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"ok":      true,
				"message": "image pulled successfully",
				"output":  "layer data\n",
			})
		})
	})

	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d, stderr: %s", exitCode, stderr.String())
	}
	if !strings.Contains(out.String(), "layer data") {
		t.Errorf("expected output in stdout, got: %s", out.String())
	}
	if strings.Contains(stderr.String(), "truncated") {
		t.Errorf("expected no truncation warning, got: %s", stderr.String())
	}
}
