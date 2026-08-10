package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

func runAgentCLITestWithServer(t *testing.T, args []string, setupServer func(*agentCLITestServer)) (stdout bytes.Buffer, stderr bytes.Buffer, exitCode int) {
	t.Helper()

	tempDir := t.TempDir()
	configPath := tempDir + "/config.json"
	tokenPath := tempDir + "/admin.token"

	if writeErr := os.WriteFile(configPath, []byte(`{"allowed_root":"`+tempDir+`","session_ttl":"12h"}`), 0600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if writeErr := os.WriteFile(tokenPath, []byte("test-token\n"), 0600); writeErr != nil {
		t.Fatal(writeErr)
	}

	runtimeDir := tempDir + "/runtime"
	if err := os.MkdirAll(runtimeDir+"/docker-helper", 0700); err != nil {
		t.Fatal(err)
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

	oldConfig := os.Getenv("DOCKER_HELPER_CONFIG")
	oldRuntime := os.Getenv("XDG_RUNTIME_DIR")
	oldToken := os.Getenv("DOCKER_HELPER_SESSION_TOKEN")
	defer func() {
		os.Setenv("DOCKER_HELPER_CONFIG", oldConfig)
		os.Setenv("XDG_RUNTIME_DIR", oldRuntime)
		os.Setenv("DOCKER_HELPER_SESSION_TOKEN", oldToken)
	}()

	os.Setenv("DOCKER_HELPER_CONFIG", configPath)
	os.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	os.Setenv("DOCKER_HELPER_SESSION_TOKEN", "test-session-token")

	exitCode = runCommandWithWriters(args, &stdout, &stderr)

	return stdout, stderr, exitCode
}

func TestPullMissingSessionToken(t *testing.T) {
	tempDir := t.TempDir()
	configPath := tempDir + "/config.json"
	if writeErr := os.WriteFile(configPath, []byte(`{"allowed_root":"`+tempDir+`","session_ttl":"12h"}`), 0600); writeErr != nil {
		t.Fatal(writeErr)
	}

	oldConfig := os.Getenv("DOCKER_HELPER_CONFIG")
	oldRuntime := os.Getenv("XDG_RUNTIME_DIR")
	oldToken := os.Getenv("DOCKER_HELPER_SESSION_TOKEN")
	defer func() {
		os.Setenv("DOCKER_HELPER_CONFIG", oldConfig)
		os.Setenv("XDG_RUNTIME_DIR", oldRuntime)
		os.Setenv("DOCKER_HELPER_SESSION_TOKEN", oldToken)
	}()

	os.Setenv("DOCKER_HELPER_CONFIG", configPath)
	os.Setenv("XDG_RUNTIME_DIR", tempDir+"/runtime")
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
