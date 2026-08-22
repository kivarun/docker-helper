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

// TestBuildTailOutputNotLost verifies that the final chunk of output
// written by the process just before exit is captured in the log buffer.
// This is a regression test for the pipe lifecycle race where cmd.Wait()
// could close StdoutPipe/StderrPipe before io.Copy goroutines finished reading.
func TestBuildTailOutputNotLost(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	reg := newOperationRegistry()
	app.OperationRegistry = reg

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dockerfilePath := filepath.Join(result.Session.Workspace, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM alpine"), 0644); err != nil {
		t.Fatalf("cannot create Dockerfile: %v", err)
	}

	// Process that writes a distinctive final line right before exit.
	const tailMarker = "TAIL_OUTPUT_MARKER_12345"
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c",
			"echo 'line1'; echo 'line2'; echo '"+tailMarker+"'")
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

	op := reg.get(opID)
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
	data, _, _ := op.LogBuffer.Range(0)
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
