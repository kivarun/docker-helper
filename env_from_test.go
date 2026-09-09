package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// envFromRunTestServer records the decoded POST /run request body so tests
// can assert on the delivered environment contract, and counts handler
// invocations so tests can prove that a rejected CLI invocation never
// reached the daemon.
type envFromRunTestServer struct {
	runBodies chan runRequest
	runCalls  atomic.Int64
}

func newEnvFromRunTestServer() *envFromRunTestServer {
	return &envFromRunTestServer{runBodies: make(chan runRequest, 8)}
}

// waitForRunBody waits for the recorded POST /run body. It fails the test
// when no run request arrived (proving the daemon was never contacted).
func (s *envFromRunTestServer) waitForRunBody(t *testing.T) runRequest {
	t.Helper()
	select {
	case body := <-s.runBodies:
		return body
	default:
		t.Fatalf("expected a POST /run request, but the daemon was never contacted")
		return runRequest{}
	}
}

func TestEnvFromDeliversResolvedValue(t *testing.T) {
	srv := newEnvFromRunTestServer()
	t.Setenv("ORCHESTRATOR_LLM_KEY", "uat-env-from-marker-value")

	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24",
		"--env-from", "LLM_KEY=ORCHESTRATOR_LLM_KEY",
		"--", "true",
	}, "", func(s *agentCLITestServer) {
		registerEnvFromRunHandlers(s, srv)
	})

	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d, stderr: %s", exitCode, stderr.String())
	}

	body := srv.waitForRunBody(t)
	if body.Environment["LLM_KEY"] != "uat-env-from-marker-value" {
		t.Errorf("expected environment LLM_KEY to carry the resolved value, got %q", body.Environment)
	}

	// The resolved value must not appear in the CLI diagnostics.
	if strings.Contains(stderr.String(), "uat-env-from-marker-value") {
		t.Error("resolved value must not appear in CLI stderr")
	}
}

func TestEnvFromMissingSourceRejectedBeforeOperation(t *testing.T) {
	srv := newEnvFromRunTestServer()

	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24",
		"--env-from", "LLM_KEY=UAT_DEFINITELY_MISSING_ENV_VAR",
		"--", "true",
	}, "", func(s *agentCLITestServer) {
		registerEnvFromRunHandlers(s, srv)
	})

	if exitCode != 2 {
		t.Fatalf("expected exit 2 for missing source variable, got %d, stderr: %s", exitCode, stderr.String())
	}
	if srv.runCalls.Load() != 0 {
		t.Errorf("missing source must fail closed before any run request, got %d requests", srv.runCalls.Load())
	}
	if strings.Contains(stderr.String(), "UAT_DEFINITELY_MISSING_ENV_VAR=") {
		t.Errorf("diagnostic must not embed the source variable value: %s", stderr.String())
	}
}

func TestEnvFromExplicitEmptyValueDelivered(t *testing.T) {
	srv := newEnvFromRunTestServer()
	t.Setenv("UAT_EMPTY_SOURCE_VAR", "")

	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24",
		"--env-from", "FLAG=UAT_EMPTY_SOURCE_VAR",
		"--", "true",
	}, "", func(s *agentCLITestServer) {
		registerEnvFromRunHandlers(s, srv)
	})

	if exitCode != 0 {
		t.Fatalf("expected exit 0 for explicitly empty source, got %d, stderr: %s", exitCode, stderr.String())
	}

	body := srv.waitForRunBody(t)
	value, exists := body.Environment["FLAG"]
	if !exists {
		t.Fatal("expected FLAG to exist in the delivered environment")
	}
	if value != "" {
		t.Errorf("expected empty value for FLAG, got %q", value)
	}
}

func TestEnvFromNeighborEnvironmentDoesNotLeak(t *testing.T) {
	srv := newEnvFromRunTestServer()
	t.Setenv("UAT_NEIGHBOR_SENTINEL", "neighbor-value-must-not-leak")
	t.Setenv("ORCHESTRATOR_LLM_KEY", "uat-env-from-marker-value")

	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24",
		"--env-from", "LLM_KEY=ORCHESTRATOR_LLM_KEY",
		"--", "true",
	}, "", func(s *agentCLITestServer) {
		registerEnvFromRunHandlers(s, srv)
	})

	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d, stderr: %s", exitCode, stderr.String())
	}

	body := srv.waitForRunBody(t)
	if _, exists := body.Environment["UAT_NEIGHBOR_SENTINEL"]; exists {
		t.Error("neighboring CLI process environment must not leak into the workload environment")
	}
	if len(body.Environment) != 1 {
		t.Errorf("expected exactly the explicitly requested variable, got %v", body.Environment)
	}
}

func TestEnvFromAndEnvWorkTogether(t *testing.T) {
	srv := newEnvFromRunTestServer()
	t.Setenv("ORCHESTRATOR_LLM_KEY", "uat-env-from-marker-value")

	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24",
		"--env", "PLAIN_KEY=plain-value",
		"--env-from", "LLM_KEY=ORCHESTRATOR_LLM_KEY",
		"--", "true",
	}, "", func(s *agentCLITestServer) {
		registerEnvFromRunHandlers(s, srv)
	})

	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d, stderr: %s", exitCode, stderr.String())
	}

	body := srv.waitForRunBody(t)
	if body.Environment["PLAIN_KEY"] != "plain-value" {
		t.Errorf("expected --env PLAIN_KEY delivered, got %v", body.Environment)
	}
	if body.Environment["LLM_KEY"] != "uat-env-from-marker-value" {
		t.Errorf("expected --env-from LLM_KEY delivered, got %v", body.Environment)
	}
	if strings.Contains(stderr.String(), "uat-env-from-marker-value") {
		t.Error("resolved value must not appear in CLI stderr")
	}
}

func TestEnvFromInvalidDestRejectedLikeEnv(t *testing.T) {
	// The daemon owns environment-name validation; an invalid DEST must be
	// rejected exactly like an invalid --env name: exit 1 with the public
	// invalid_environment diagnostic, no operation.
	for _, tc := range []struct {
		name string
		flag []string
	}{
		{name: "env", flag: []string{"--env", "BAD-NAME=value"}},
		{name: "env-from", flag: []string{"--env-from", "BAD-NAME=ORCHESTRATOR_LLM_KEY"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newEnvFromRunTestServer()
			t.Setenv("ORCHESTRATOR_LLM_KEY", "uat-env-from-marker-value")

			args := append([]string{"run", "--image", "alpine:3.24"}, tc.flag...)
			args = append(args, "--", "true")

			_, stderr, exitCode := runAgentCLITestWithServer(t, args, "", func(s *agentCLITestServer) {
				registerEnvFromRejectedRunHandlers(s, srv)
			})

			if exitCode != 1 {
				t.Fatalf("expected exit 1 (daemon rejection), got %d, stderr: %s", exitCode, stderr.String())
			}
			if !strings.Contains(stderr.String(), "invalid environment variable name") {
				t.Errorf("expected the daemon invalid_environment diagnostic, got: %s", stderr.String())
			}
			if srv.runCalls.Load() != 1 {
				t.Fatalf("expected exactly one run request, got %d", srv.runCalls.Load())
			}
		})
	}
}

func TestEnvFromMissingSeparatorRejectedLikeEnv(t *testing.T) {
	_, stderr, exitCode := runAgentCLITestWithServer(t, []string{
		"run", "--image", "alpine:3.24",
		"--env-from", "NOSEPARATOR",
		"--", "true",
	}, "", func(s *agentCLITestServer) {
		registerEnvFromRunHandlers(s, nil)
	})

	if exitCode != 2 {
		t.Fatalf("expected exit 2 for invalid env-from format, got %d, stderr: %s", exitCode, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid env-from format") {
		t.Errorf("expected invalid env-from format diagnostic, got: %s", stderr.String())
	}
}

// registerEnvFromRunHandlers registers a run endpoint that accepts the
// request, records the body, and completes the operation synchronously.
func registerEnvFromRunHandlers(s *agentCLITestServer, srv *envFromRunTestServer) {
	opID := "op_envfrom_test"
	s.handleRun(func(w http.ResponseWriter, r *http.Request) {
		if srv != nil {
			srv.runCalls.Add(1)
			var body runRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			srv.runBodies <- body
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"ok":           true,
			"operation_id": opID,
			"status":       "running",
		})
	})
	registerEnvFromOperationTerminal(s, opID)
}

// registerEnvFromRejectedRunHandlers registers a run endpoint that rejects
// the request with the daemon's invalid_environment contract (400), proving
// no operation is created for an invalid DEST.
func registerEnvFromRejectedRunHandlers(s *agentCLITestServer, srv *envFromRunTestServer) {
	s.handleRun(func(w http.ResponseWriter, r *http.Request) {
		if srv != nil {
			srv.runCalls.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"ok":      false,
			"code":    "invalid_environment",
			"message": "invalid environment variable name",
		})
	})
}

func registerEnvFromOperationTerminal(s *agentCLITestServer, opID string) {
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
			"ok":          true,
			"offset":      int64(0),
			"next_offset": int64(0),
			"truncated":   false,
			"logs":        "",
		})
	})
}
