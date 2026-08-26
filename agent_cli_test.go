package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
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
	opID := "op_test123"
	exitCode := 42
	_, _, actualExit := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--", "sh", "-c", "exit 42",
	}, "", func(s *agentCLITestServer) {
		s.handleRun(func(w http.ResponseWriter, r *http.Request) {
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
				"status":       "failed",
				"result_code":  "container_exit_nonzero",
				"exit_code":    exitCode,
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

	if actualExit != 42 {
		t.Errorf("expected exit 42, got %d", actualExit)
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
func TestWaitForOperationFinalLogsRace(t *testing.T) {
	opID := "op_test"
	callCount := 0

	tempDir := t.TempDir()
	socketPath := tempDir + "/docker-helper.sock"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /operations/"+opID, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"operation_id": opID,
			"status":       "succeeded",
		})
	})
	mux.HandleFunc("GET /operations/"+opID+"/logs", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 {
			// First request: empty logs, next_offset=0
			json.NewEncoder(w).Encode(map[string]any{
				"ok":           true,
				"operation_id": opID,
				"offset":       int64(0),
				"next_offset":  int64(0),
				"truncated":    false,
				"logs":         "",
			})
		} else {
			// Final request: has output
			json.NewEncoder(w).Encode(map[string]any{
				"ok":           true,
				"operation_id": opID,
				"offset":       int64(0),
				"next_offset":  int64(10),
				"truncated":    false,
				"logs":         "Final output\n",
			})
		}
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

	var out bytes.Buffer
	c := &apiClient{
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var dialer net.Dialer
					return dialer.DialContext(ctx, "unix", socketPath)
				},
			},
		},
		baseURL:     "http://localhost",
		tokenSource: func() (string, error) { return "test-token", nil },
	}

	status, err := waitForOperationContext(context.Background(), c, opID, &out, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("waitForOperation failed: %v", err)
	}
	if status.Status != operationSucceeded {
		t.Errorf("expected succeeded, got %s", status.Status)
	}
	if !strings.Contains(out.String(), "Final output") {
		t.Errorf("expected final output, got: %s", out.String())
	}
}

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
	opID := "op_test"
	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--", "echo", "hi",
	}, "", func(s *agentCLITestServer) {
		s.handleRun(func(w http.ResponseWriter, r *http.Request) {
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
				"status":       "failed",
				"result_code":  "docker_run_failed",
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

	if exitCode != 1 {
		t.Errorf("expected exit 1, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "docker_run_failed") {
		t.Errorf("expected result_code in error, got: %s", stderr.String())
	}
}

// TestPullFailedPreservesOutput verifies that failed pull preserves Docker output.
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
	// Output goes to stdout, error message to stderr
	if !strings.Contains(out.String(), "invalid reference") {
		t.Errorf("expected Docker output in stdout, got: %s", out.String())
	}
	if !strings.Contains(stderr.String(), "docker pull failed") {
		t.Errorf("expected error message in stderr, got: %s", stderr.String())
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
func TestRunContract(t *testing.T) {
	opID := "op_run"
	received := false
	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
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
		t.Fatal("run request not received")
	}
	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d, stderr: %s", exitCode, stderr.String())
	}
}

// TestTruncatedOnlyInFinalLogs verifies that truncation in final logs
// still produces the warning.
func TestTruncatedOnlyInFinalLogs(t *testing.T) {
	opID := "op_test"
	callCount := 0

	tempDir := t.TempDir()
	socketPath := tempDir + "/docker-helper.sock"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /operations/"+opID, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"operation_id": opID,
			"status":       string(operationSucceeded),
		})
	})
	mux.HandleFunc("GET /operations/"+opID+"/logs", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"ok":           true,
			"operation_id": opID,
			"offset":       int64(0),
			"next_offset":  int64(0),
			"truncated":    false,
			"logs":         "",
		}
		// Only the final request (second call) has truncation
		if callCount == 2 {
			resp["truncated"] = true
			resp["logs"] = "final output\n"
		}
		json.NewEncoder(w).Encode(resp)
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

	var out, stderr bytes.Buffer
	c := &apiClient{
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var dialer net.Dialer
					return dialer.DialContext(ctx, "unix", socketPath)
				},
			},
		},
		baseURL:     "http://localhost",
		tokenSource: func() (string, error) { return "test-token", nil },
	}

	_, err = waitForOperationContext(context.Background(), c, opID, &out, &stderr)
	if err != nil {
		t.Fatalf("waitForOperation failed: %v", err)
	}
	if !strings.Contains(stderr.String(), "warning: operation log was truncated") {
		t.Errorf("expected truncation warning from final logs, got: %s", stderr.String())
	}
	if !strings.Contains(out.String(), "final output") {
		t.Errorf("expected final output, got: %s", out.String())
	}
}

// TestTruncatedMultiplePollsSingleWarning verifies that when truncation
// appears across multiple polls, the warning is printed exactly once.
func TestTruncatedMultiplePollsSingleWarning(t *testing.T) {
	opID := "op_test"
	statusCallCount := 0
	logsCallCount := 0

	tempDir := t.TempDir()
	socketPath := tempDir + "/docker-helper.sock"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /operations/"+opID, func(w http.ResponseWriter, r *http.Request) {
		statusCallCount++
		w.Header().Set("Content-Type", "application/json")
		// First two status checks return running, third returns succeeded
		status := string(operationRunning)
		if statusCallCount >= 3 {
			status = string(operationSucceeded)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"operation_id": opID,
			"status":       status,
		})
	})
	mux.HandleFunc("GET /operations/"+opID+"/logs", func(w http.ResponseWriter, r *http.Request) {
		logsCallCount++
		w.Header().Set("Content-Type", "application/json")
		// All logs requests return truncated=true
		json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"operation_id": opID,
			"offset":       int64(0),
			"next_offset":  int64(100),
			"truncated":    true,
			"logs":         "output\n",
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

	var out, stderr bytes.Buffer
	c := &apiClient{
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var dialer net.Dialer
					return dialer.DialContext(ctx, "unix", socketPath)
				},
			},
		},
		baseURL:     "http://localhost",
		tokenSource: func() (string, error) { return "test-token", nil },
	}

	_, err = waitForOperationContext(context.Background(), c, opID, &out, &stderr)
	if err != nil {
		t.Fatalf("waitForOperation failed: %v", err)
	}

	warningCount := strings.Count(stderr.String(), "warning: operation log was truncated")
	if warningCount != 1 {
		t.Errorf("expected exactly one truncation warning, got %d: %s", warningCount, stderr.String())
	}
}

// TestSignalCancel verifies that waitForOperationWithSignalCh handles
// SIGINT and SIGTERM correctly: cancels once, exits with proper code, stops polling.
func TestSignalCancel(t *testing.T) {
	cases := []struct {
		name     string
		signal   syscall.Signal
		exitCode int
	}{
		{"SIGINT", syscall.SIGINT, 130},
		{"SIGTERM", syscall.SIGTERM, 143},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opID := "op_signal_" + tc.name
			cancelCalled := int32(0)
			pollCount := int32(0)

			tempDir := t.TempDir()
			socketPath := tempDir + "/docker-helper.sock"

			listener, err := net.Listen("unix", socketPath)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			mux := http.NewServeMux()
			mux.HandleFunc("GET /operations/"+opID, func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&pollCount, 1)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"ok":           true,
					"operation_id": opID,
					"status":       "running",
				})
			})
			mux.HandleFunc("GET /operations/"+opID+"/logs", func(w http.ResponseWriter, r *http.Request) {
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
			mux.HandleFunc("POST /operations/"+opID+"/cancel", func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&cancelCalled, 1)
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"ok":           true,
					"operation_id": opID,
					"status":       "failed",
					"result_code":  "cancelled",
				})
			})

			server := &http.Server{Handler: mux}
			go server.Serve(listener)
			waitForDialReady(t, "unix", socketPath)

			c := &apiClient{
				httpClient: &http.Client{
					Transport: &http.Transport{
						DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
							var dialer net.Dialer
							return dialer.DialContext(ctx, "unix", socketPath)
						},
					},
				},
				baseURL:     "http://localhost",
				tokenSource: func() (string, error) { return "test-token", nil },
			}

			sigCh := make(chan os.Signal, 1)
			sigCh <- tc.signal

			var out, stderr bytes.Buffer
			_, err = waitForOperationWithSignalCh(c, opID, &out, &stderr, sigCh)
			if err == nil {
				t.Fatal("expected error from signal")
			}
			sigErr, ok := err.(*signalExitError)
			if !ok {
				t.Fatalf("expected *signalExitError, got %T: %v", err, err)
			}
			if sigErr.Signal != tc.signal {
				t.Errorf("expected %v, got %v", tc.signal, sigErr.Signal)
			}
			if code := signalExitCode(sigErr.Signal); code != tc.exitCode {
				t.Errorf("expected exit code %d, got %d", tc.exitCode, code)
			}
			if atomic.LoadInt32(&cancelCalled) != 1 {
				t.Errorf("expected cancel called exactly once, got %d", atomic.LoadInt32(&cancelCalled))
			}
			polls := atomic.LoadInt32(&pollCount)
			if polls > 2 {
				t.Errorf("expected polling to stop after signal, got %d polls", polls)
			}
		})
	}
}

// TestSignalCancelErrorDiagnostic verifies that a cancel endpoint error
// prints a diagnostic but does not change the signal exit code.
func TestSignalCancelErrorDiagnostic(t *testing.T) {
	opID := "op_cancel_err"

	tempDir := t.TempDir()
	socketPath := tempDir + "/docker-helper.sock"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /operations/"+opID, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"operation_id": opID,
			"status":       "running",
		})
	})
	mux.HandleFunc("GET /operations/"+opID+"/logs", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("POST /operations/"+opID+"/cancel", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"code":    "internal_error",
			"message": "daemon internal error",
		})
	})

	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	waitForDialReady(t, "unix", socketPath)

	c := &apiClient{
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var dialer net.Dialer
					return dialer.DialContext(ctx, "unix", socketPath)
				},
			},
		},
		baseURL:     "http://localhost",
		tokenSource: func() (string, error) { return "test-token", nil },
	}

	// Pre-load signal.
	sigCh := make(chan os.Signal, 1)
	sigCh <- syscall.SIGINT

	var out, stderr bytes.Buffer
	_, err = waitForOperationWithSignalCh(c, opID, &out, &stderr, sigCh)
	if err == nil {
		t.Fatal("expected error from signal")
	}
	sigErr, ok := err.(*signalExitError)
	if !ok {
		t.Fatalf("expected *signalExitError, got %T: %v", err, err)
	}
	// Signal exit code is preserved despite cancel error.
	if code := signalExitCode(sigErr.Signal); code != 130 {
		t.Errorf("expected exit code 130, got %d", code)
	}

	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "warning: cancel failed") {
		t.Errorf("expected cancel error diagnostic in stderr, got: %s", stderrStr)
	}
}

// TestSignalExitCodes verifies that signalExitCode returns correct values.
func TestSignalExitCodes(t *testing.T) {
	if got := signalExitCode(syscall.SIGINT); got != 130 {
		t.Errorf("SIGINT: expected 130, got %d", got)
	}
	if got := signalExitCode(syscall.SIGTERM); got != 143 {
		t.Errorf("SIGTERM: expected 143, got %d", got)
	}
	if got := signalExitCode(syscall.SIGHUP); got != 1 {
		t.Errorf("SIGHUP: expected 1, got %d", got)
	}
}

// TestSignalNoOrphanGoroutine verifies that after signal, the poll goroutine
// exits cleanly and no further HTTP requests are made.
func TestSignalNoOrphanGoroutine(t *testing.T) {
	opID := "op_no_orphan"
	requestAfterCancel := int32(0)
	cancelDone := int32(0)
	statusCalls := int32(0)

	tempDir := t.TempDir()
	socketPath := tempDir + "/docker-helper.sock"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /operations/"+opID, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&statusCalls, 1)
		// After cancel completes, any further request means orphan goroutine.
		if atomic.LoadInt32(&cancelDone) == 1 {
			atomic.AddInt32(&requestAfterCancel, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"operation_id": opID,
			"status":       "running",
		})
	})
	mux.HandleFunc("GET /operations/"+opID+"/logs", func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&cancelDone) == 1 {
			atomic.AddInt32(&requestAfterCancel, 1)
		}
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
	mux.HandleFunc("POST /operations/"+opID+"/cancel", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"operation_id": opID,
			"status":       "failed",
			"result_code":  "cancelled",
		})
		atomic.StoreInt32(&cancelDone, 1)
	})

	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	waitForDialReady(t, "unix", socketPath)

	c := &apiClient{
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var dialer net.Dialer
					return dialer.DialContext(ctx, "unix", socketPath)
				},
			},
		},
		baseURL:     "http://localhost",
		tokenSource: func() (string, error) { return "test-token", nil },
	}

	sigCh := make(chan os.Signal, 1)

	var out, stderr bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = waitForOperationWithSignalCh(c, opID, &out, &stderr, sigCh)
		close(done)
	}()

	// Wait for the first poll request to be observed, then interrupt.
	deadline := time.Now().Add(5 * time.Second)
	for atomic.LoadInt32(&statusCalls) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("poll goroutine did not send a status request")
		}
		time.Sleep(5 * time.Millisecond)
	}
	sigCh <- syscall.SIGINT

	<-done

	// Wait for any orphan request with a bounded observation window.
	observeDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(observeDeadline) {
		if atomic.LoadInt32(&requestAfterCancel) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if atomic.LoadInt32(&requestAfterCancel) > 0 {
		t.Errorf("expected no HTTP requests after signal, got %d", atomic.LoadInt32(&requestAfterCancel))
	}
}

// TestBuildContextAbsoluteRejected verifies that build rejects absolute --context.
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

// TestResolveAgentClientSystemFlag verifies --system selects the system socket
// regardless of XDG_RUNTIME_DIR / DOCKER_HELPER_SOCKET_PATH.
func TestResolveAgentClientSystemFlag(t *testing.T) {
	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "tok")
	t.Setenv("DOCKER_HELPER_SOCKET_PATH", "/some/other/path.sock")
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	c, err := resolveAgentClient(agentClientOptions{System: true})
	if err != nil {
		t.Fatalf("resolveAgentClient(--system): %v", err)
	}
	if c.baseURL != "http://localhost" {
		t.Errorf("baseURL = %q, want http://localhost", c.baseURL)
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

// TestResolveAgentClientMutuallyExclusive verifies --system and --endpoint
// cannot be combined.
func TestResolveAgentClientMutuallyExclusive(t *testing.T) {
	t.Setenv("DOCKER_HELPER_SESSION_TOKEN", "tok")
	_, err := resolveAgentClient(agentClientOptions{System: true, Endpoint: "/x.sock"})
	if err == nil {
		t.Fatal("expected mutual-exclusion error")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("unexpected error: %v", err)
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
	if !strings.Contains(out.String(), "retained tail") {
		t.Errorf("expected retained output in stdout, got: %s", out.String())
	}
	if !strings.Contains(stderr.String(), "pull output was truncated") {
		t.Errorf("expected truncation warning in stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "docker pull failed") {
		t.Errorf("expected error message in stderr, got: %s", stderr.String())
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
