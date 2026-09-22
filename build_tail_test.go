package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestBuildTailOutputNotLost verifies that the final chunk of output
// written by the process just before exit is captured in the log buffer.
// This is a regression test for the pipe lifecycle race where cmd.Wait()
// could close StdoutPipe/StderrPipe before io.Copy goroutines finished reading.
func TestBuildTailOutputNotLost(t *testing.T) {
	app, supervisor, result, _, _ := setupBuildBackendTest(t)

	// The buildctl stage writes a distinctive final line right before exit.
	const tailMarker = "TAIL_OUTPUT_MARKER_12345"
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if strings.HasSuffix(name, "buildctl") {
			return exec.CommandContext(ctx, "/bin/sh", "-c",
				"echo 'line1'; echo 'line2'; echo '"+tailMarker+"'")
		}
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newBuildRequest(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)

	op := supervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found")
	}

	// Wait for operation to complete.
	select {
	case <-op.done:
	case <-time.After(10 * time.Second):
		t.Fatal("operation did not complete in time")
	}

	// Fetch logs and verify the tail marker is present.
	data, _, _ := op.LogBuffer.Range(0, rangeUnbounded)
	logs := string(data)

	if !strings.Contains(logs, "line1") {
		t.Error("missing 'line1' in logs")
	}
	if !strings.Contains(logs, "line2") {
		t.Error("missing 'line2' in logs")
	}
	if !strings.Contains(logs, tailMarker) {
		t.Errorf("tail marker not found in logs — tail output was lost.\nLogs: %q", logs)
	}
}
