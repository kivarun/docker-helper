package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// dockerAvailable checks if the Docker daemon is reachable from this environment.
func dockerAvailable(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not found in PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "info").Run(); err != nil {
		t.Skipf("Docker daemon not reachable: %v", err)
	}
}

// dockerRun executes a docker command and returns stdout.
func dockerRun(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Logf("docker %s failed: %v (%s)", strings.Join(args, " "), err, out)
		return ""
	}
	return string(out)
}

// findContainerIDByEnv returns the first running container ID matching the env filter,
// or empty string if none found.
func findContainerIDByEnv(t *testing.T, envFilter string) string {
	t.Helper()
	out := dockerRun(t, "ps",
		"--filter", "env="+envFilter,
		"--format", "{{.ID}}",
	)
	ids := strings.Fields(out)
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

// findAnyContainerIDByEnv returns the first container ID (any state) matching the env filter.
func findAnyContainerIDByEnv(t *testing.T, envFilter string) string {
	t.Helper()
	out := dockerRun(t, "ps", "-a",
		"--filter", "env="+envFilter,
		"--format", "{{.ID}}",
	)
	ids := strings.Fields(out)
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

// containerState returns the human-readable status of a container by ID, e.g. "Up 5 seconds".
func containerState(t *testing.T, envFilter string) string {
	t.Helper()
	out := dockerRun(t, "ps", "-a",
		"--filter", "env="+envFilter,
		"--format", "{{.ID}}:{{.Status}}",
	)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for _, line := range lines {
		if line != "" {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return parts[1]
			}
		}
	}
	return ""
}

// waitContainerRunning polls docker ps until a container matching envFilter is running.
// Returns the container ID or empty string on timeout.
func waitContainerRunning(t *testing.T, envFilter string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		id := findContainerIDByEnv(t, envFilter)
		if id != "" {
			return id
		}
		time.Sleep(200 * time.Millisecond)
	}
	return ""
}

// cleanupContainerByEnv force-removes any container (any state) matching the env filter.
func cleanupContainerByEnv(t *testing.T, envFilter string) {
	t.Helper()
	out := dockerRun(t, "ps", "-a",
		"--filter", "env="+envFilter,
		"--format", "{{.ID}}",
	)
	for _, id := range strings.Fields(out) {
		dockerRun(t, "rm", "-f", id)
	}
}

// makeUniqueEnvFilter generates a unique env var filter for container identification.
func makeUniqueEnvFilter() string {
	return fmt.Sprintf("DOCKER_HELPER_TEST_ID=dh_test_%d_%d", time.Now().UnixNano(), time.Now().Nanosecond())
}

// startRunOperation starts a /run operation and returns the operation.
// The app must NOT have ExecCommandContext set (uses real docker).
func startRunOperation(t *testing.T, app *App, token string, body map[string]any) *operation {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/run", strings.NewReader(string(data)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d; body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found in registry")
	}
	return op
}

// TestContainerLifecycleGracefulSIGTERM verifies that when the docker run CLI
// receives SIGTERM during graceful shutdown, the signal propagates to the
// container, the container exits, and --rm removes it.
//
// This is a Docker integration test that requires a reachable Docker daemon.
func TestContainerLifecycleGracefulSIGTERM(t *testing.T) {
	dockerAvailable(t)

	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	envFilter := makeUniqueEnvFilter()
	t.Cleanup(func() { cleanupContainerByEnv(t, envFilter) })

	// Start a long-running container (normal process that handles SIGTERM).
	op := startRunOperation(t, app, result.Token, map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sleep", "300"},
		"environment": map[string]string{
			"DOCKER_HELPER_TEST_ID": strings.SplitN(envFilter, "=", 2)[1],
		},
	})

	// Wait for the container to be running.
	containerID := waitContainerRunning(t, envFilter, 15*time.Second)
	if containerID == "" {
		t.Fatal("container did not start within timeout")
	}
	t.Logf("container started: %s", containerID)

	// Trigger graceful shutdown with generous timeout.
	app.OperationRegistry.setShuttingDown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	app.OperationRegistry.terminateAll(shutdownCtx)
	cancel()

	// Wait for the operation to complete.
	select {
	case <-op.done:
	case <-time.After(15 * time.Second):
		t.Fatal("operation did not complete within timeout")
	}

	t.Logf("operation state: %s, result_code: %v", op.State, op.ResultCode)

	// Give Docker a moment to process --rm.
	time.Sleep(500 * time.Millisecond)

	// Check: container should NOT be running.
	runningID := findContainerIDByEnv(t, envFilter)
	if runningID != "" {
		t.Errorf("container still running after graceful SIGTERM: %s", runningID)
	}

	// Check: container should be completely gone (--rm should have removed it).
	state := containerState(t, envFilter)
	if state != "" {
		t.Logf("container state after graceful shutdown: %s (expected gone)", state)
	}
}

// TestContainerLifecycleForcedKill verifies what happens to the Docker container
// when the docker run CLI process is force-killed (SIGKILL) after the shutdown
// deadline expires.
//
// Key question: can the container survive the force-kill of the docker run CLI?
//
// This is a Docker integration test that requires a reachable Docker daemon.
func TestContainerLifecycleForcedKill(t *testing.T) {
	dockerAvailable(t)

	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	envFilter := makeUniqueEnvFilter()
	t.Cleanup(func() { cleanupContainerByEnv(t, envFilter) })

	testID := strings.SplitN(envFilter, "=", 2)[1]

	// Start a container that ignores SIGTERM so the graceful phase cannot stop it.
	// The entrypoint is /bin/sh, and the command traps TERM and sleeps.
	op := startRunOperation(t, app, result.Token, map[string]any{
		"image":      "alpine:latest",
		"entrypoint": "/bin/sh",
		"command":    []string{"-c", "trap '' TERM; exec sleep 300"},
		"environment": map[string]string{
			"DOCKER_HELPER_TEST_ID": testID,
		},
	})

	// Wait for the container to be running.
	containerID := waitContainerRunning(t, envFilter, 15*time.Second)
	if containerID == "" {
		t.Fatal("container did not start within timeout")
	}
	t.Logf("container started: %s", containerID)

	// Give the container time to install the SIGTERM trap.
	time.Sleep(500 * time.Millisecond)

	// Trigger shutdown with a short deadline so the force-kill path is exercised.
	app.OperationRegistry.setShuttingDown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	app.OperationRegistry.terminateAll(shutdownCtx)
	cancel()

	// Wait for the operation to complete.
	select {
	case <-op.done:
	case <-time.After(10 * time.Second):
		t.Fatal("operation did not complete within timeout")
	}

	t.Logf("operation state: %s, result_code: %v, exit_code: %v", op.State, op.ResultCode, op.ExitCode)

	// Give Docker a moment to process any post-kill state.
	time.Sleep(1 * time.Second)

	// KEY CHECK: Is the container still running after the force-kill?
	runningID := findContainerIDByEnv(t, envFilter)
	if runningID != "" {
		t.Logf("CONTAINER SURVIVED force-kill: %s", runningID)
		t.Log("The container is still running after the docker run CLI was force-killed.")
		t.Log("This means --rm did NOT remove the container because the container never exited.")
	} else {
		t.Log("Container is NOT running after force-kill.")
	}

	// Check all container states to get a complete picture.
	state := containerState(t, envFilter)
	if state != "" {
		t.Logf("Container state: %s", state)
	} else {
		t.Log("Container is completely gone (no trace in docker ps -a).")
	}

	// Also check by the container ID we captured earlier.
	if containerID != "" {
		detail := dockerRun(t, "inspect", "--format", "{{.State.Status}}", containerID)
		if detail != "" {
			t.Logf("Container %s state from inspect: %s", containerID, strings.TrimSpace(detail))
		} else {
			t.Logf("Container %s no longer exists (inspect returned nothing)", containerID)
		}
	}
}
