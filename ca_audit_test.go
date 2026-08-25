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
)

func TestRunAuditCAInjectedAuto(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	preparedDir := filepath.Join(app.Config.RuntimeDir, "trusted-ca", "test-snapshot")
	if err := os.MkdirAll(preparedDir, 0755); err != nil {
		t.Fatalf("cannot create prepared dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(preparedDir, "ca.pem"), []byte("test-ca"), 0644); err != nil {
		t.Fatalf("cannot write ca.pem: %v", err)
	}
	app.Config.TrustedCAInjection = "auto"
	app.Config.TrustedCAPath = "/test-docker-helper-ca-path/ca.pem"
	app.Config.TrustedCAPreparedDir = preparedDir

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"echo", "hello"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitRun(t, app, w)

	rawLines := auditRawLinesBySession(auditBuf, result.Session.ID)
	if len(rawLines) != 2 {
		t.Fatalf("expected 2 audit lines, got %d", len(rawLines))
	}

	var startRaw, finishRaw string
	for _, line := range rawLines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if m["event"] == "run.start" {
			startRaw = line
		} else if m["event"] == "run.finish" {
			finishRaw = line
		}
	}
	if startRaw == "" {
		t.Fatal("run.start audit line not found")
	}
	if finishRaw == "" {
		t.Fatal("run.finish audit line not found")
	}

	// Check parsed TrustedCAInjected.
	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	var startRec, finishRec *auditRecord
	for i := range records {
		if records[i].Event == "run.start" {
			startRec = &records[i]
		} else if records[i].Event == "run.finish" {
			finishRec = &records[i]
		}
	}
	if startRec == nil || !startRec.TrustedCAInjected {
		t.Error("run.start TrustedCAInjected should be true")
	}
	if finishRec == nil || !finishRec.TrustedCAInjected {
		t.Error("run.finish TrustedCAInjected should be true")
	}

	// Check raw JSON contains trusted_ca_injected:true.
	if !strings.Contains(startRaw, `"trusted_ca_injected":true`) {
		t.Error("run.start raw JSON should contain trusted_ca_injected:true")
	}
	if !strings.Contains(finishRaw, `"trusted_ca_injected":true`) {
		t.Error("run.finish raw JSON should contain trusted_ca_injected:true")
	}

	// Check raw JSON does not leak host CA paths.
	for _, label := range []string{"run.start", "run.finish"} {
		raw := startRaw
		if label == "run.finish" {
			raw = finishRaw
		}
		if strings.Contains(raw, app.Config.TrustedCAPath) {
			t.Errorf("%s raw JSON should not leak TrustedCAPath", label)
		}
		if strings.Contains(raw, app.Config.TrustedCAPreparedDir) {
			t.Errorf("%s raw JSON should not leak TrustedCAPreparedDir", label)
		}
	}
}

func TestRunAuditCAInjectedDisabled(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.Config.TrustedCAInjection = "disabled"
	app.Config.TrustedCAPreparedDir = ""

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"echo", "hello"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitRun(t, app, w)

	rawLines := auditRawLinesBySession(auditBuf, result.Session.ID)
	if len(rawLines) != 2 {
		t.Fatalf("expected 2 audit lines, got %d", len(rawLines))
	}

	for _, label := range []string{"run.start", "run.finish"} {
		var raw string
		for _, line := range rawLines {
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				continue
			}
			if m["event"] == label {
				raw = line
				break
			}
		}
		if raw == "" {
			t.Fatalf("%s audit line not found", label)
		}
		if strings.Contains(raw, "trusted_ca_injected") {
			t.Errorf("%s raw JSON should not contain trusted_ca_injected", label)
		}
	}
}
