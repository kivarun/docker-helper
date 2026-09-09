package main

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadContainerIDFromCidfile(t *testing.T) {
	dir := t.TempDir()
	cidfile := filepath.Join(dir, "test.cid")

	// Empty file returns empty string.
	if id := readContainerIDFromCidfile(cidfile); id != "" {
		t.Errorf("expected empty string for missing file, got %q", id)
	}

	// File with container ID returns the ID.
	if err := os.WriteFile(cidfile, []byte("abc123def456\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if id := readContainerIDFromCidfile(cidfile); id != "abc123def456" {
		t.Errorf("expected 'abc123def456', got %q", id)
	}

	// Whitespace-only file returns empty string.
	if err := os.WriteFile(cidfile, []byte("  \n  \t\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if id := readContainerIDFromCidfile(cidfile); id != "" {
		t.Errorf("expected empty string for whitespace, got %q", id)
	}
}

func TestKillContainerBestEffortDoesNotPanicOnMissingDocker(t *testing.T) {
	// Verify that killContainerBestEffort handles errors gracefully.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("killContainerBestEffort panicked: %v", r)
		}
	}()

	// Use a minimal App to test the method.
	app := &App{}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	app.killContainerBestEffort(ctx, "nonexistent_container_id")
}

func TestCidfileNotExposedInHTTPResponse(t *testing.T) {
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	body := w.Body.String()
	if strings.Contains(body, ".cid") {
		t.Errorf("cidfile path must not appear in HTTP response: %s", body)
	}
}

// TestCidfileRaceContextExpiresWithoutCidfile verifies that when the cleanup
// context expires before the cidfile appears, shutdown still proceeds with
// CLI kill and doesn't hang.
// TestWaitForContainerIDReturnsOnDone verifies that waitForContainerID
// returns empty string when the operation completes during polling.
func TestWaitForContainerIDReturnsOnDone(t *testing.T) {
	op := newRunOperation("session1", "alpine:latest", 1024, "", "", "")
	op.cidfile = filepath.Join(t.TempDir(), op.ID+".cid")

	// Complete the operation immediately.
	op.fail("test", "test", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	id := waitForContainerID(ctx, op)
	if id != "" {
		t.Errorf("expected empty string when operation is done, got %q", id)
	}
}

// TestWaitForContainerIDReturnsOnContextExpire verifies that waitForContainerID
// returns empty string when the context expires without the cidfile appearing.
func TestWaitForContainerIDReturnsOnContextExpire(t *testing.T) {
	op := newRunOperation("session1", "alpine:latest", 1024, "", "", "")
	op.cidfile = filepath.Join(t.TempDir(), op.ID+".cid")

	// Use a very short context.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	id := waitForContainerID(ctx, op)
	if id != "" {
		t.Errorf("expected empty string when context expires, got %q", id)
	}
}

// TestWaitForContainerIDReturnsID verifies that waitForContainerID
// returns the container ID when the cidfile is published.
func TestWaitForContainerIDReturnsID(t *testing.T) {
	op := newRunOperation("session1", "alpine:latest", 1024, "", "", "")
	cidfilePath := filepath.Join(t.TempDir(), op.ID+".cid")
	op.cidfile = cidfilePath

	// Publish the cidfile after a short delay.
	go func() {
		time.Sleep(10 * time.Millisecond)
		os.WriteFile(cidfilePath, []byte("test_container_xyz\n"), 0644)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	id := waitForContainerID(ctx, op)
	if id != "test_container_xyz" {
		t.Errorf("expected 'test_container_xyz', got %q", id)
	}
}
