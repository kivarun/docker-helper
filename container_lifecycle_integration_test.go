package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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

// dockerInspectField runs docker inspect and returns the value of the given
// Go template, or empty string on error.
func dockerInspectField(t *testing.T, containerID, format string) string {
	t.Helper()
	out := dockerRun(t, "inspect", "--format", format, containerID)
	return strings.TrimSpace(out)
}

// isContainerRunning returns true if the container exists and is running.
func isContainerRunning(t *testing.T, containerID string) bool {
	t.Helper()
	status := dockerInspectField(t, containerID, "{{.State.Running}}")
	return status == "true"
}

// containerInspectError returns the error from docker inspect, or nil if the
// container exists. Used to distinguish "not found" from other errors.
func containerInspectError(t *testing.T, containerID string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := exec.CommandContext(ctx, "docker", "inspect", containerID).CombinedOutput()
	return err
}

// waitForCidfile polls the cidfile until a valid container ID appears or the
// timeout expires. Returns the container ID or empty string.
func waitForCidfile(t *testing.T, cidfile string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if id := readContainerIDFromCidfile(cidfile); id != "" {
			return id
		}
		time.Sleep(100 * time.Millisecond)
	}
	return ""
}

// waitForContainerRunning polls docker inspect until the container is running
// or the timeout expires.
func waitForContainerRunning(t *testing.T, containerID string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if isContainerRunning(t, containerID) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// waitForContainerGone polls docker inspect until the container no longer exists
// or the timeout expires. Returns true if the container is gone.
func waitForContainerGone(t *testing.T, containerID string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := containerInspectError(t, containerID); err != nil {
			// Container not found — it's gone.
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// cleanupContainerByID force-removes a specific container by ID (best-effort).
func cleanupContainerByID(t *testing.T, containerID string) {
	t.Helper()
	if containerID != "" {
		dockerRun(t, "rm", "-f", containerID)
	}
}

// TestShmSizeIntegration verifies that a container started with a non-default
// shm_size has the expected /dev/shm size inside the container.
//
// This is a Docker integration test that requires a reachable Docker daemon.
func TestShmSizeIntegration(t *testing.T) {
	dockerAvailable(t)

	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Start a container with a 64 MiB shm_size that measures /dev/shm.
	op := startRunOperation(t, app, result.Token, map[string]any{
		"image":    "alpine:latest",
		"shm_size": "64m",
		"command":  []string{"sh", "-c", "df -B1 /dev/shm | tail -1 | awk '{print $2}'"},
	})

	// Wait for the operation to complete.
	select {
	case <-op.done:
	case <-time.After(30 * time.Second):
		t.Fatal("operation did not complete within timeout")
	}

	if op.State != operationSucceeded {
		t.Fatalf("expected status 'succeeded', got %q; result_code: %v", op.State, op.ResultCode)
	}

	// Read the logs to get the /dev/shm size.
	logsReq := httptest.NewRequest(http.MethodGet, "/operations/"+op.ID+"/logs", nil)
	logsReq.SetPathValue("id", op.ID)
	logsReq.Header.Set("Authorization", "Bearer "+result.Token)
	logsW := httptest.NewRecorder()
	app.handleOperationLogs(logsW, logsReq)

	if logsW.Code != http.StatusOK {
		t.Fatalf("expected 200 from operation logs, got %d", logsW.Code)
	}

	var logsResp map[string]any
	if err := json.NewDecoder(logsW.Body).Decode(&logsResp); err != nil {
		t.Fatalf("decode operation logs: %v", err)
	}
	logs, _ := logsResp["logs"].(string)

	// Parse the expected shm size in bytes.
	wantShmSize := "67108864" // 64 * 1024 * 1024
	gotShmSize := strings.TrimSpace(logs)
	if gotShmSize != wantShmSize {
		t.Errorf("expected /dev/shm size %s, got %s", wantShmSize, gotShmSize)
	}
}

// waitReadyFile polls for a file to appear, bounded by timeout.
// Returns true if the file exists within the timeout.
func waitReadyFile(t *testing.T, path string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
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

	// Start a long-running container (normal process that handles SIGTERM).
	op := startRunOperation(t, app, result.Token, map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sleep", "300"},
	})

	// Get the cidfile from the operation and wait for the container ID.
	if op.cidfile == "" {
		t.Fatal("cidfile not set on operation")
	}
	containerID := waitForCidfile(t, op.cidfile, 15*time.Second)
	if containerID == "" {
		t.Fatal("container ID not published in cidfile within timeout")
	}
	t.Logf("container ID from cidfile: %s", containerID)

	// Clean up the container regardless of test outcome.
	t.Cleanup(func() { cleanupContainerByID(t, containerID) })

	// Wait for the container to actually be running.
	if !waitForContainerRunning(t, containerID, 15*time.Second) {
		t.Fatal("container did not become running within timeout")
	}
	t.Logf("container is running: %s", containerID)

	// Trigger graceful shutdown with generous timeout.
	app.OperationRegistry.setShuttingDown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	app.OperationRegistry.terminateAll(shutdownCtx, app.killContainerBestEffort)
	cancel()

	// Wait for the operation to complete.
	select {
	case <-op.done:
	case <-time.After(15 * time.Second):
		t.Fatal("operation did not complete within timeout")
	}

	t.Logf("operation state: %s, result_code: %v", op.State, op.ResultCode)

	// Wait for the container to be gone (bounded polling, no arbitrary sleep).
	if !waitForContainerGone(t, containerID, 10*time.Second) {
		// Container still exists — report its state for diagnostics.
		status := dockerInspectField(t, containerID, "{{.State.Status}}")
		running := dockerInspectField(t, containerID, "{{.State.Running}}")
		t.Errorf("container not gone after graceful shutdown: status=%s running=%s", status, running)
	}
}

// TestContainerLifecycleForcedKill verifies that when the docker run CLI
// process is force-killed after the shutdown deadline, the helper performs
// daemon-side cleanup (docker kill) to stop the container, preventing
// orphan/zombie containers.
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

	// Create a readiness marker directory inside the session workspace
	// so it can be bind-mounted into the container.
	readyDir := filepath.Join(app.Config.AllowedRoot, "test_ready")
	if err := os.MkdirAll(readyDir, 0755); err != nil {
		t.Fatalf("cannot create ready dir: %v", err)
	}
	readyFile := filepath.Join(readyDir, "ready")

	// Start a container that ignores SIGTERM so the graceful phase cannot stop it.
	// The shell command:
	// 1. Installs trap to ignore SIGTERM
	// 2. Touches the readiness file to signal the trap is installed
	// 3. Enters long-running sleep
	op := startRunOperation(t, app, result.Token, map[string]any{
		"image":      "alpine:latest",
		"entrypoint": "/bin/sh",
		"command":    []string{"-c", "trap '' TERM; touch /ready/ready; exec sleep 300"},
		"mounts": []map[string]any{
			{"source": "test_ready", "target": "/ready", "read_only": false},
		},
	})

	// Get the cidfile from the operation and wait for the container ID.
	if op.cidfile == "" {
		t.Fatal("cidfile not set on operation")
	}
	containerID := waitForCidfile(t, op.cidfile, 15*time.Second)
	if containerID == "" {
		t.Fatal("container ID not published in cidfile within timeout")
	}
	t.Logf("container ID from cidfile: %s", containerID)

	// Clean up the container regardless of test outcome.
	t.Cleanup(func() { cleanupContainerByID(t, containerID) })

	// Wait for the container to actually be running.
	if !waitForContainerRunning(t, containerID, 15*time.Second) {
		t.Fatal("container did not become running within timeout")
	}
	t.Logf("container is running: %s", containerID)

	// Wait for the readiness marker — deterministic handshake proving
	// the SIGTERM trap is installed, no arbitrary sleep needed.
	if !waitReadyFile(t, readyFile, 10*time.Second) {
		t.Fatal("container did not signal readiness within timeout")
	}
	t.Log("container SIGTERM trap confirmed via readiness marker")

	// Trigger shutdown with a short deadline so the force-kill path is exercised.
	app.OperationRegistry.setShuttingDown()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	app.OperationRegistry.terminateAll(shutdownCtx, app.killContainerBestEffort)
	cancel()

	// Wait for the operation to complete.
	select {
	case <-op.done:
	case <-time.After(10 * time.Second):
		t.Fatal("operation did not complete within timeout")
	}

	t.Logf("operation state: %s, result_code: %v, exit_code: %v", op.State, op.ResultCode, op.ExitCode)

	// KEY CHECK: container should NOT be running after daemon-side cleanup.
	// The fix ensures that terminateAll reads the container ID from the cidfile
	// and executes "docker kill" before force-killing the docker run CLI.
	//
	// Wait for the container to be gone (bounded polling, no arbitrary sleep).
	if !waitForContainerGone(t, containerID, 10*time.Second) {
		// Container still exists — report its state for diagnostics.
		status := dockerInspectField(t, containerID, "{{.State.Status}}")
		running := dockerInspectField(t, containerID, "{{.State.Running}}")
		t.Errorf("container not gone after forced cleanup: status=%s running=%s", status, running)
	}
}

// TestContainerLifecycleGracefulCancel verifies that an explicit cancel
// of a running /run operation terminates the container via SIGTERM,
// the container exits, --rm removes it, and the operation reaches
// result_code=cancelled with cidfile cleaned up.
//
// This is a Docker integration test that requires a reachable Docker daemon.
func TestContainerLifecycleGracefulCancel(t *testing.T) {
	dockerAvailable(t)

	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Start a long-running container (normal process that handles SIGTERM).
	op := startRunOperation(t, app, result.Token, map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sleep", "300"},
	})

	// Get the cidfile from the operation and wait for the container ID.
	if op.cidfile == "" {
		t.Fatal("cidfile not set on operation")
	}
	containerID := waitForCidfile(t, op.cidfile, 15*time.Second)
	if containerID == "" {
		t.Fatal("container ID not published in cidfile within timeout")
	}
	t.Logf("container ID from cidfile: %s", containerID)

	// Clean up the container regardless of test outcome.
	t.Cleanup(func() { cleanupContainerByID(t, containerID) })

	// Wait for the container to actually be running.
	if !waitForContainerRunning(t, containerID, 15*time.Second) {
		t.Fatal("container did not become running within timeout")
	}
	t.Logf("container is running: %s", containerID)

	// Cancel the operation via HTTP endpoint.
	start := time.Now()
	cancelReq := httptest.NewRequest("POST", "/operations/"+op.ID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	app.handleOperationCancel(cancelW, cancelReq)
	elapsed := time.Since(start)

	if cancelW.Code != http.StatusOK {
		t.Fatalf("cancel: expected %d, got %d; body: %s", http.StatusOK, cancelW.Code, cancelW.Body.String())
	}

	// Sanity bound: graceful cancel should complete in reasonable time.
	if elapsed > 15*time.Second {
		t.Errorf("cancel took %v, expected significantly less than 15s", elapsed)
	}

	// Verify operation terminal state.
	var cancelResp map[string]any
	json.NewDecoder(cancelW.Body).Decode(&cancelResp)
	if cancelResp["status"] != "failed" {
		t.Errorf("status = %q, want failed", cancelResp["status"])
	}
	if cancelResp["result_code"] != "cancelled" {
		t.Errorf("result_code = %q, want cancelled", cancelResp["result_code"])
	}

	// Verify container is gone (--rm removes it on normal exit).
	if !waitForContainerGone(t, containerID, 10*time.Second) {
		status := dockerInspectField(t, containerID, "{{.State.Status}}")
		running := dockerInspectField(t, containerID, "{{.State.Running}}")
		t.Errorf("container not gone after graceful cancel: status=%s running=%s", status, running)
	}

	// Verify cidfile is cleaned up.
	if _, err := os.Stat(op.cidfile); !os.IsNotExist(err) {
		t.Errorf("cidfile %s should be removed after cancel", op.cidfile)
	}
}

// TestContainerLifecycleForcedCancel verifies that when a container process
// ignores SIGTERM, the explicit cancel deadline expires, the helper performs
// daemon-side docker kill, and the container is removed (no orphan).
//
// This is a Docker integration test that requires a reachable Docker daemon.
func TestContainerLifecycleForcedCancel(t *testing.T) {
	dockerAvailable(t)

	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Create a readiness marker directory inside the session workspace
	// so it can be bind-mounted into the container.
	readyDir := filepath.Join(app.Config.AllowedRoot, "test_cancel_ready")
	if err := os.MkdirAll(readyDir, 0755); err != nil {
		t.Fatalf("cannot create ready dir: %v", err)
	}
	readyFile := filepath.Join(readyDir, "ready")

	// Start a container that ignores SIGTERM.
	// The shell command:
	// 1. Installs trap to ignore SIGTERM
	// 2. Touches the readiness file to signal the trap is installed
	// 3. Enters long-running sleep
	op := startRunOperation(t, app, result.Token, map[string]any{
		"image":      "alpine:latest",
		"entrypoint": "/bin/sh",
		"command":    []string{"-c", "trap '' TERM; touch /ready/ready; exec sleep 300"},
		"mounts": []map[string]any{
			{"source": "test_cancel_ready", "target": "/ready", "read_only": false},
		},
	})

	// Get the cidfile from the operation and wait for the container ID.
	if op.cidfile == "" {
		t.Fatal("cidfile not set on operation")
	}
	containerID := waitForCidfile(t, op.cidfile, 15*time.Second)
	if containerID == "" {
		t.Fatal("container ID not published in cidfile within timeout")
	}
	t.Logf("container ID from cidfile: %s", containerID)

	// Clean up the container regardless of test outcome.
	t.Cleanup(func() { cleanupContainerByID(t, containerID) })

	// Wait for the container to actually be running.
	if !waitForContainerRunning(t, containerID, 15*time.Second) {
		t.Fatal("container did not become running within timeout")
	}
	t.Logf("container is running: %s", containerID)

	// Wait for the readiness marker — deterministic handshake proving
	// the SIGTERM trap is installed.
	if !waitReadyFile(t, readyFile, 10*time.Second) {
		t.Fatal("container did not signal readiness within timeout")
	}
	t.Log("container SIGTERM trap confirmed via readiness marker")

	// Cancel the operation — this will exercise the forced cleanup path.
	start := time.Now()
	cancelReq := httptest.NewRequest("POST", "/operations/"+op.ID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+result.Token)
	cancelW := httptest.NewRecorder()
	app.handleOperationCancel(cancelW, cancelReq)
	elapsed := time.Since(start)

	if cancelW.Code != http.StatusOK {
		t.Fatalf("cancel: expected %d, got %d; body: %s", http.StatusOK, cancelW.Code, cancelW.Body.String())
	}

	// Sanity bound: forced cancel should complete within reasonable time.
	// The graceful phase is ~5s + cleanup ~3s = ~8s worst case.
	// Allow generous margin for CI slowness.
	if elapsed > 15*time.Second {
		t.Errorf("forced cancel took %v, expected significantly less than 15s", elapsed)
	}

	// Verify operation terminal state.
	var cancelResp map[string]any
	json.NewDecoder(cancelW.Body).Decode(&cancelResp)
	if cancelResp["status"] != "failed" {
		t.Errorf("status = %q, want failed", cancelResp["status"])
	}
	if cancelResp["result_code"] != "cancelled" {
		t.Errorf("result_code = %q, want cancelled", cancelResp["result_code"])
	}

	// KEY CHECK: container must NOT be running after forced cleanup.
	// This is the regression test for the orphan-container bug.
	if !waitForContainerGone(t, containerID, 10*time.Second) {
		status := dockerInspectField(t, containerID, "{{.State.Status}}")
		running := dockerInspectField(t, containerID, "{{.State.Running}}")
		t.Errorf("container not gone after forced cancel: status=%s running=%s", status, running)
	}

	// Verify cidfile is cleaned up.
	if _, err := os.Stat(op.cidfile); !os.IsNotExist(err) {
		t.Errorf("cidfile %s should be removed after cancel", op.cidfile)
	}
}
