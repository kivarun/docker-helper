package main

import (
	"context"
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
