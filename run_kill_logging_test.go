package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os/exec"
	"strings"
	"testing"
)

func TestKillContainerBestEffortLogsToOperational(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelWarn, true)
	defer logging.reset()

	app := &App{}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 1")
	}

	ctx := context.Background()
	containerID := "abc123def456"
	app.killContainerBestEffort(ctx, containerID)

	output := opBuf.String()
	if output == "" {
		t.Fatal("expected operational log output, got nothing")
	}

	var record map[string]any
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("operational log line is not valid JSON: %s: %v", line, err)
		}
		break
	}

	if record == nil {
		t.Fatal("expected at least one JSON record in operational output")
	}

	if record["stream"] != "operational" {
		t.Errorf("expected stream=operational, got %v", record["stream"])
	}

	if record["level"] != "WARN" {
		t.Errorf("expected level=WARN, got %v", record["level"])
	}

	msg, _ := record["msg"].(string)
	if !strings.Contains(msg, "daemon-side container cleanup failed") {
		t.Errorf("expected cleanup failure message, got %q", msg)
	}

	if strings.Contains(output, containerID) {
		t.Error("container ID must not appear in the log")
	}

	auditOutput := auditBuf.String()
	if strings.Contains(auditOutput, "daemon-side container cleanup failed") {
		t.Error("cleanup warning must not appear in audit stream")
	}
}
