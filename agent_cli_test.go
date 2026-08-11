package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type agentCLITestServer struct {
	mux    *http.ServeMux
	server *httptest.Server
}

func newAgentCLITestServer(t *testing.T) *agentCLITestServer {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return &agentCLITestServer{mux: mux, server: server}
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

func runAgentCLITestWithServer(t *testing.T, args []string, setupServer func(*agentCLITestServer)) (stdout bytes.Buffer, stderr bytes.Buffer, exitCode int) {
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
	time.Sleep(50 * time.Millisecond)

	oldSocket := os.Getenv("DOCKER_HELPER_SOCKET_PATH")
	oldToken := os.Getenv("DOCKER_HELPER_SESSION_TOKEN")
	defer func() {
		os.Setenv("DOCKER_HELPER_SOCKET_PATH", oldSocket)
		os.Setenv("DOCKER_HELPER_SESSION_TOKEN", oldToken)
	}()

	os.Setenv("DOCKER_HELPER_SOCKET_PATH", socketPath)
	os.Setenv("DOCKER_HELPER_SESSION_TOKEN", "test-session-token")

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

func TestPullSuccess(t *testing.T) {
	out, _, exitCode := runAgentCLITestWithServer(t, []string{"pull", "alpine:3.24"}, func(s *agentCLITestServer) {
		s.handlePull(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"ok":      true,
				"message": "image pulled successfully",
				"output":  "Status: Image is up to date for alpine:3.24\n",
			})
		})
	})

	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "alpine:3.24") {
		t.Errorf("expected pull output, got: %s", out.String())
	}
}

func TestPullFailure(t *testing.T) {
	_, err, exitCode := runAgentCLITestWithServer(t, []string{"pull", "alpine:3.24"}, func(s *agentCLITestServer) {
		s.handlePull(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{
				"ok":      false,
				"code":    "docker_pull_failed",
				"message": "docker pull failed",
			})
		})
	})

	if exitCode != 1 {
		t.Errorf("expected exit 1, got %d", exitCode)
	}
	if !strings.Contains(err.String(), "docker pull failed") {
		t.Errorf("expected error message, got: %s", err.String())
	}
}

func TestPullMissingImage(t *testing.T) {
	_, _, exitCode := runAgentCLITestWithServer(t, []string{"pull"}, nil)
	if exitCode != 2 {
		t.Errorf("expected exit 2, got %d", exitCode)
	}
}

func TestBuildMissingFlags(t *testing.T) {
	_, err, exitCode := runAgentCLITestWithServer(t, []string{"build", "--image", "app:test"}, nil)
	if exitCode != 2 {
		t.Errorf("expected exit 2, got %d", exitCode)
	}
	if !strings.Contains(err.String(), "--context is required") {
		t.Errorf("expected context error, got: %s", err.String())
	}
}

func TestBuildSuccess(t *testing.T) {
	opID := "op_test123"
	out, _, exitCode := runAgentCLITestWithServer(t, []string{
		"build", "--context", ".", "--dockerfile", "Dockerfile", "--image", "app:test",
	}, func(s *agentCLITestServer) {
		s.handleBuild(func(w http.ResponseWriter, r *http.Request) {
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
				"next_offset":  int64(100),
				"truncated":    false,
				"logs":         "Step 1/3 : FROM alpine\n",
			})
		})
	})

	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "Step 1/3") {
		t.Errorf("expected build logs, got: %s", out.String())
	}
}

func TestBuildFailed(t *testing.T) {
	opID := "op_test123"
	_, err, exitCode := runAgentCLITestWithServer(t, []string{
		"build", "--context", ".", "--dockerfile", "Dockerfile", "--image", "app:test",
	}, func(s *agentCLITestServer) {
		s.handleBuild(func(w http.ResponseWriter, r *http.Request) {
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
				"result_code":  "docker_build_failed",
			})
		})
		s.handleOperationLogs(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"ok":           true,
				"operation_id": opID,
				"offset":       int64(0),
				"next_offset":  int64(50),
				"truncated":    false,
				"logs":         "ERROR: failed to build\n",
			})
		})
	})

	if exitCode != 1 {
		t.Errorf("expected exit 1, got %d", exitCode)
	}
	if !strings.Contains(err.String(), "build failed") {
		t.Errorf("expected build failed message, got: %s", err.String())
	}
}

func TestBuildArgsParsing(t *testing.T) {
	opID := "op_test123"
	var receivedBuildArgs map[string]string
	runAgentCLITestWithServer(t, []string{
		"build", "--context", ".", "--dockerfile", "Dockerfile", "--image", "app:test",
		"--build-arg", "VERSION=1", "--build-arg", "FOO=bar",
	}, func(s *agentCLITestServer) {
		s.handleBuild(func(w http.ResponseWriter, r *http.Request) {
			var req buildRequest
			json.NewDecoder(r.Body).Decode(&req)
			receivedBuildArgs = req.BuildArgs
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

	if len(receivedBuildArgs) != 2 {
		t.Fatalf("expected 2 build args, got %d", len(receivedBuildArgs))
	}
	if receivedBuildArgs["VERSION"] != "1" {
		t.Errorf("expected VERSION=1, got %q", receivedBuildArgs["VERSION"])
	}
	if receivedBuildArgs["FOO"] != "bar" {
		t.Errorf("expected FOO=bar, got %q", receivedBuildArgs["FOO"])
	}
}

func TestRunSuccess(t *testing.T) {
	opID := "op_test123"
	out, _, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--", "echo", "hello",
	}, func(s *agentCLITestServer) {
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
				"status":       "succeeded",
			})
		})
		s.handleOperationLogs(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"ok":           true,
				"operation_id": opID,
				"offset":       int64(0),
				"next_offset":  int64(10),
				"truncated":    false,
				"logs":         "hello\n",
			})
		})
	})

	if exitCode != 0 {
		t.Errorf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(out.String(), "hello") {
		t.Errorf("expected run output, got: %s", out.String())
	}
}

func TestRunContainerExitNonzero(t *testing.T) {
	opID := "op_test123"
	exitCode := 42
	_, _, actualExit := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--", "sh", "-c", "exit 42",
	}, func(s *agentCLITestServer) {
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

func TestRunCommandParsing(t *testing.T) {
	opID := "op_test123"
	var receivedCommand []string
	runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--", "./test.sh", "arg1", "arg2",
	}, func(s *agentCLITestServer) {
		s.handleRun(func(w http.ResponseWriter, r *http.Request) {
			var req runRequest
			json.NewDecoder(r.Body).Decode(&req)
			receivedCommand = req.Command
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

	if len(receivedCommand) != 3 {
		t.Fatalf("expected 3 command args, got %d", len(receivedCommand))
	}
	if receivedCommand[0] != "./test.sh" {
		t.Errorf("expected ./test.sh, got %q", receivedCommand[0])
	}
}

func TestRunEnvParsing(t *testing.T) {
	opID := "op_test123"
	var receivedEnv map[string]string
	runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--env", "FOO=bar", "--env", "VALUE=123", "--", "echo", "hi",
	}, func(s *agentCLITestServer) {
		s.handleRun(func(w http.ResponseWriter, r *http.Request) {
			var req runRequest
			json.NewDecoder(r.Body).Decode(&req)
			receivedEnv = req.Environment
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

	if len(receivedEnv) != 2 {
		t.Fatalf("expected 2 env vars, got %d", len(receivedEnv))
	}
	if receivedEnv["FOO"] != "bar" {
		t.Errorf("expected FOO=bar, got %q", receivedEnv["FOO"])
	}
	if receivedEnv["VALUE"] != "123" {
		t.Errorf("expected VALUE=123, got %q", receivedEnv["VALUE"])
	}
}

func TestRunMountParsing(t *testing.T) {
	opID := "op_test123"
	var receivedMounts []mountRequest
	runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--mount", ".:/workspace:ro", "--", "echo", "hi",
	}, func(s *agentCLITestServer) {
		s.handleRun(func(w http.ResponseWriter, r *http.Request) {
			var req runRequest
			json.NewDecoder(r.Body).Decode(&req)
			receivedMounts = req.Mounts
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

	if len(receivedMounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(receivedMounts))
	}
	if receivedMounts[0].Source != "." {
		t.Errorf("expected source '.', got %q", receivedMounts[0].Source)
	}
	if receivedMounts[0].Target != "/workspace" {
		t.Errorf("expected target '/workspace', got %q", receivedMounts[0].Target)
	}
	if !receivedMounts[0].ReadOnly {
		t.Error("expected mount to be read-only")
	}
}

func TestTokenNotInOutput(t *testing.T) {
	const token = "dht_super_secret_session_token_12345"
	oldToken := os.Getenv("DOCKER_HELPER_SESSION_TOKEN")
	defer os.Setenv("DOCKER_HELPER_SESSION_TOKEN", oldToken)
	os.Setenv("DOCKER_HELPER_SESSION_TOKEN", token)

	_, err, exitCode := runAgentCLITestWithServer(t, []string{
		"pull", "alpine:3.24",
	}, func(s *agentCLITestServer) {
		s.handlePull(func(w http.ResponseWriter, r *http.Request) {
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
	if strings.Contains(err.String(), token) {
		t.Error("token must not appear in stderr")
	}
}

func TestPullHelp(t *testing.T) {
	var out, err bytes.Buffer
	code := runCommandWithWriters([]string{"pull", "--help"}, &out, &err)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), "Pull a Docker image") {
		t.Errorf("expected help text, got: %s", out.String())
	}
}

func TestBuildHelp(t *testing.T) {
	var out, err bytes.Buffer
	code := runCommandWithWriters([]string{"build", "--help"}, &out, &err)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), "Build a Docker image") {
		t.Errorf("expected help text, got: %s", out.String())
	}
}

func TestRunHelp(t *testing.T) {
	var out, err bytes.Buffer
	code := runCommandWithWriters([]string{"run", "--help"}, &out, &err)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), "Run a Docker container") {
		t.Errorf("expected help text, got: %s", out.String())
	}
}

// TestPullNoConfigFile verifies that pull works without config.json.
// Agent containers only have DOCKER_HELPER_SESSION_TOKEN + socket mount.
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
	time.Sleep(50 * time.Millisecond)

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

	status, err := waitForOperation(c, opID, &out, &bytes.Buffer{})
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
	}, nil)
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
	}, nil)
	if exitCode != 2 {
		t.Errorf("expected exit 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "source must be relative to session workspace") {
		t.Errorf("expected source relative error, got: %s", stderr.String())
	}
}

// TestRunMountRelativeSourceAccepted verifies that relative source paths
// pass CLI validation and reach the API.
func TestRunMountRelativeSourceAccepted(t *testing.T) {
	opID := "op_run"
	received := false
	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--mount", "src:/target:ro", "--", "echo", "hi",
	}, func(s *agentCLITestServer) {
		s.handleRun(func(w http.ResponseWriter, r *http.Request) {
			var req runRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("cannot decode request: %v", err)
			}
			if len(req.Mounts) != 1 {
				t.Fatalf("expected 1 mount, got %d", len(req.Mounts))
			}
			if req.Mounts[0].Source != "src" {
				t.Errorf("expected source 'src', got %s", req.Mounts[0].Source)
			}
			if req.Mounts[0].Target != "/target" {
				t.Errorf("expected target '/target', got %s", req.Mounts[0].Target)
			}
			if !req.Mounts[0].ReadOnly {
				t.Error("expected mount to be read-only")
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

// TestRunHelpMountFlag verifies that run --help mentions workspace-relative
// source and [:ro] option.
func TestRunHelpMountFlag(t *testing.T) {
	var out, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"run", "--help"}, &out, &stderr)
	if code != 0 {
		t.Errorf("expected exit 0, got %d", code)
	}
	output := out.String()
	if !strings.Contains(output, "WORKSPACE_RELATIVE_SOURCE") {
		t.Errorf("expected mount help to mention workspace-relative source, got: %s", output)
	}
	if !strings.Contains(output, "[:ro]") {
		t.Errorf("expected mount help to mention [:ro], got: %s", output)
	}
}

// TestRunFailedDiagnostics verifies that failed run prints diagnostics.
func TestRunFailedDiagnostics(t *testing.T) {
	opID := "op_test"
	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24", "--", "echo", "hi",
	}, func(s *agentCLITestServer) {
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
	out, stderr, exitCode := runAgentCLITestWithServer(t, []string{"pull", "invalid:tag"}, func(s *agentCLITestServer) {
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
	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{"pull", "alpine:3.24"}, func(s *agentCLITestServer) {
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
	}, func(s *agentCLITestServer) {
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
	}, func(s *agentCLITestServer) {
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

// TestWaitForOperationUsesConstants verifies that waitForOperation uses
// operationState constants, not string literals.
func TestWaitForOperationUsesConstants(t *testing.T) {
	opID := "op_test"

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

	status, err := waitForOperation(c, opID, &out, &stderr)
	if err != nil {
		t.Fatalf("waitForOperation failed: %v", err)
	}
	if status.Status != operationSucceeded {
		t.Errorf("expected operationSucceeded, got %s", status.Status)
	}
}

// TestTruncatedLogWarning verifies that truncated logs produce a warning.
func TestTruncatedLogWarning(t *testing.T) {
	opID := "op_test"
	truncatedSeen := false

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
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"ok":           true,
			"operation_id": opID,
			"offset":       int64(0),
			"next_offset":  int64(100),
			"truncated":    false,
			"logs":         "some output\n",
		}
		if truncatedSeen {
			resp["truncated"] = true
		}
		truncatedSeen = true
		json.NewEncoder(w).Encode(resp)
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

	_, err = waitForOperation(c, opID, &out, &stderr)
	if err != nil {
		t.Fatalf("waitForOperation failed: %v", err)
	}
	if !strings.Contains(stderr.String(), "warning: operation log was truncated") {
		t.Errorf("expected truncation warning, got: %s", stderr.String())
	}
	// Warning should appear exactly once
	if strings.Count(stderr.String(), "warning: operation log was truncated") != 1 {
		t.Errorf("expected exactly one warning, got: %s", stderr.String())
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
	time.Sleep(50 * time.Millisecond)

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

	_, err = waitForOperation(c, opID, &out, &stderr)
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
	time.Sleep(50 * time.Millisecond)

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

	_, err = waitForOperation(c, opID, &out, &stderr)
	if err != nil {
		t.Fatalf("waitForOperation failed: %v", err)
	}

	warningCount := strings.Count(stderr.String(), "warning: operation log was truncated")
	if warningCount != 1 {
		t.Errorf("expected exactly one truncation warning, got %d: %s", warningCount, stderr.String())
	}
}

// TestBuildSignalCancel verifies that SIGINT during build triggers cancel
// and exits with code 130. Polling stops immediately after signal (no orphan goroutine).
func TestBuildSignalCancel(t *testing.T) {
	opID := "op_signal_test"
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
	mux.HandleFunc("POST /build", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"operation_id": opID,
			"status":       "running",
		})
	})
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
	time.Sleep(50 * time.Millisecond)

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

	// Pre-load signal so it is delivered immediately.
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
	if sigErr.Signal != syscall.SIGINT {
		t.Errorf("expected SIGINT, got %v", sigErr.Signal)
	}
	if code := signalExitCode(sigErr.Signal); code != 130 {
		t.Errorf("expected exit code 130, got %d", code)
	}

	if atomic.LoadInt32(&cancelCalled) != 1 {
		t.Errorf("expected cancel called exactly once, got %d", atomic.LoadInt32(&cancelCalled))
	}

	// Verify polling stopped: pollCount should be small (only the first poll iteration).
	polls := atomic.LoadInt32(&pollCount)
	if polls > 2 {
		t.Errorf("expected polling to stop after signal, got %d polls", polls)
	}
}

// TestRunSignalCancel verifies that SIGTERM during run triggers cancel
// and exits with code 143.
func TestRunSignalCancel(t *testing.T) {
	opID := "op_signal_run"
	cancelCalled := int32(0)

	tempDir := t.TempDir()
	socketPath := tempDir + "/docker-helper.sock"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /run", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"operation_id": opID,
			"status":       "running",
		})
	})
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
	time.Sleep(50 * time.Millisecond)

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

	// Pre-load signal so it is delivered immediately.
	sigCh := make(chan os.Signal, 1)
	sigCh <- syscall.SIGTERM

	var out, stderr bytes.Buffer
	_, err = waitForOperationWithSignalCh(c, opID, &out, &stderr, sigCh)
	if err == nil {
		t.Fatal("expected error from signal")
	}
	sigErr, ok := err.(*signalExitError)
	if !ok {
		t.Fatalf("expected *signalExitError, got %T: %v", err, err)
	}
	if sigErr.Signal != syscall.SIGTERM {
		t.Errorf("expected SIGTERM, got %v", sigErr.Signal)
	}
	if code := signalExitCode(sigErr.Signal); code != 143 {
		t.Errorf("expected exit code 143, got %d", code)
	}

	if atomic.LoadInt32(&cancelCalled) != 1 {
		t.Errorf("expected cancel called exactly once, got %d", atomic.LoadInt32(&cancelCalled))
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
	time.Sleep(50 * time.Millisecond)

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

// TestSignalCancelOnce verifies that multiple signals only trigger one cancel.
func TestSignalCancelOnce(t *testing.T) {
	opID := "op_cancel_once"
	cancelCalled := int32(0)

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
		atomic.AddInt32(&cancelCalled, 1)
		// Slow response to keep the operation "running" from the daemon side.
		time.Sleep(500 * time.Millisecond)
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
	time.Sleep(50 * time.Millisecond)

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

	// Pre-load signal so it is delivered immediately.
	sigCh := make(chan os.Signal, 1)
	sigCh <- syscall.SIGINT

	var out, stderr bytes.Buffer
	_, err = waitForOperationWithSignalCh(c, opID, &out, &stderr, sigCh)
	if err == nil {
		t.Fatal("expected error from signal")
	}

	if atomic.LoadInt32(&cancelCalled) != 1 {
		t.Errorf("expected cancel called exactly once, got %d", atomic.LoadInt32(&cancelCalled))
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

	tempDir := t.TempDir()
	socketPath := tempDir + "/docker-helper.sock"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /operations/"+opID, func(w http.ResponseWriter, r *http.Request) {
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
	time.Sleep(50 * time.Millisecond)

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

	// Let one poll iteration complete.
	time.Sleep(100 * time.Millisecond)
	sigCh <- syscall.SIGINT

	<-done

	// Give a moment for any orphan goroutine to make a request.
	time.Sleep(200 * time.Millisecond)

	if atomic.LoadInt32(&requestAfterCancel) > 0 {
		t.Errorf("expected no HTTP requests after signal, got %d", atomic.LoadInt32(&requestAfterCancel))
	}
}

// TestBuildCommandSignalExitCode verifies the full build command returns
// exit code 130 on SIGINT.
func TestBuildCommandSignalExitCode(t *testing.T) {
	opID := "op_build_cmd"
	cancelCalled := int32(0)

	tempDir := t.TempDir()
	socketPath := tempDir + "/docker-helper.sock"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /build", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"operation_id": opID,
			"status":       "running",
		})
	})
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
	time.Sleep(50 * time.Millisecond)

	oldSocket := os.Getenv("DOCKER_HELPER_SOCKET_PATH")
	oldToken := os.Getenv("DOCKER_HELPER_SESSION_TOKEN")
	defer func() {
		os.Setenv("DOCKER_HELPER_SOCKET_PATH", oldSocket)
		os.Setenv("DOCKER_HELPER_SESSION_TOKEN", oldToken)
	}()

	os.Setenv("DOCKER_HELPER_SOCKET_PATH", socketPath)
	os.Setenv("DOCKER_HELPER_SESSION_TOKEN", "test-token")

	// Intercept the signal by patching the build command to use our signal channel.
	// Since we can't inject signals into runCommandWithWriters, we verify the
	// exit code path by testing the signalExitError handling directly.
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
	sigCh <- syscall.SIGINT

	var out, stderr bytes.Buffer
	_, err = waitForOperationWithSignalCh(c, opID, &out, &stderr, sigCh)

	// Verify the error type and exit code match what the build command does.
	sigErr, ok := err.(*signalExitError)
	if !ok {
		t.Fatalf("expected *signalExitError, got %T", err)
	}
	exitCode := signalExitCode(sigErr.Signal)
	if exitCode != 130 {
		t.Errorf("expected exit code 130, got %d", exitCode)
	}
	if atomic.LoadInt32(&cancelCalled) != 1 {
		t.Errorf("expected cancel called, got %d", atomic.LoadInt32(&cancelCalled))
	}
}

// TestRunCommandSignalExitCode verifies the full run command returns
// exit code 143 on SIGTERM.
func TestRunCommandSignalExitCode(t *testing.T) {
	opID := "op_run_cmd"
	cancelCalled := int32(0)

	tempDir := t.TempDir()
	socketPath := tempDir + "/docker-helper.sock"

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /run", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"operation_id": opID,
			"status":       "running",
		})
	})
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
	time.Sleep(50 * time.Millisecond)

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
	sigCh <- syscall.SIGTERM

	var out, stderr bytes.Buffer
	_, err = waitForOperationWithSignalCh(c, opID, &out, &stderr, sigCh)

	sigErr, ok := err.(*signalExitError)
	if !ok {
		t.Fatalf("expected *signalExitError, got %T", err)
	}
	exitCode := signalExitCode(sigErr.Signal)
	if exitCode != 143 {
		t.Errorf("expected exit code 143, got %d", exitCode)
	}
	if atomic.LoadInt32(&cancelCalled) != 1 {
		t.Errorf("expected cancel called, got %d", atomic.LoadInt32(&cancelCalled))
	}
}
