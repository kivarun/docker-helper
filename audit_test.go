package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newRunRequest(body map[string]any, token string) *http.Request {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func parseAuditRecords(buf *bytes.Buffer) []auditRecord {
	var records []auditRecord
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec auditRecord
		if err := json.Unmarshal([]byte(line), &rec); err == nil {
			records = append(records, rec)
		}
	}
	return records
}

func filterBySession(records []auditRecord, sessionID string) []auditRecord {
	var filtered []auditRecord
	for _, rec := range records {
		if rec.SessionID == sessionID {
			filtered = append(filtered, rec)
		}
	}
	return filtered
}

func auditRawLinesBySession(buf *bytes.Buffer, sessionID string) []string {
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		if sid, ok := m["session_id"].(string); ok && sid == sessionID {
			lines = append(lines, line)
		}
	}
	return lines
}

func TestRunStartAndFinish(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"echo", "hello"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	startRec := records[0]
	if startRec.Event != "run.start" {
		t.Errorf("first record event: expected 'run.start', got %q", startRec.Event)
	}
	if startRec.Image != "alpine:latest" {
		t.Errorf("start image: expected 'alpine:latest', got %q", startRec.Image)
	}
	if startRec.CommandArgCount == nil || *startRec.CommandArgCount != 2 {
		t.Errorf("start command_arg_count: expected 2, got %v", startRec.CommandArgCount)
	}

	finishRec := records[1]
	if finishRec.Event != "run.finish" {
		t.Errorf("second record event: expected 'run.finish', got %q", finishRec.Event)
	}
	if finishRec.Result != "succeeded" {
		t.Errorf("finish result: expected 'succeeded', got %q", finishRec.Result)
	}
	if finishRec.Duration == "" {
		t.Error("finish duration should be set")
	}
}

func TestAuditEnvKeysNoValues(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	const secretValue = "super-secret-token-12345"

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"SECRET_KEY": secretValue,
			"APP_MODE":   "test",
		},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	output := auditBuf.String()

	// Check that raw secret is absent from everything (audit + debug)
	if strings.Contains(output, secretValue) {
		t.Fatalf("audit contains raw env value!\n%s", output)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	// Verify audit records only contain env_keys, not values
	for _, rec := range records {
		foundSecret := false
		foundApp := false
		for _, key := range rec.EnvKeys {
			if key == "SECRET_KEY" {
				foundSecret = true
			}
			if key == "APP_MODE" {
				foundApp = true
			}
		}
		if !foundSecret {
			t.Error("expected SECRET_KEY in env_keys")
		}
		if !foundApp {
			t.Error("expected APP_MODE in env_keys")
		}

		// Serialize the record and check no raw values appear
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), secretValue) {
			t.Fatalf("audit record contains raw env value!\n%s", raw)
		}
	}
}

func TestAuditDebugNoRawValue(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	const secretValue = "my-password-do-not-log"

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
		"environment": map[string]string{
			"DB_PASSWORD": secretValue,
		},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	output := auditBuf.String()

	// The raw secret must never appear anywhere in audit
	if strings.Contains(output, secretValue) {
		t.Fatalf("audit contains raw env value!\n%s", output)
	}

	// Verify audit records only contain env_keys, not values
	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), secretValue) {
			t.Fatalf("audit record contains raw env value!\n%s", raw)
		}
	}
}

func TestAuditNonZeroExit(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%s' 'error output'; exit 7")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sh", "-c", "exit 7"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	finishRec := records[1]
	if finishRec.Event != "run.finish" {
		t.Errorf("expected 'run.finish', got %q", finishRec.Event)
	}
	if finishRec.Result != "container_exit_nonzero" {
		t.Errorf("expected result 'container_exit_nonzero', got %q", finishRec.Result)
	}
	if finishRec.ExitCode == nil || *finishRec.ExitCode != 7 {
		t.Errorf("expected exit_code 7, got %v", finishRec.ExitCode)
	}
}

func TestAuditDockerError(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%s' 'docker not found'; exit 125")
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	finishRec := records[1]
	if finishRec.Result != "docker_run_failed" {
		t.Errorf("expected result 'docker_run_failed', got %q", finishRec.Result)
	}
}
func TestAuditMountsRelativeSource(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": ".", "target": "/workspace", "read_only": true},
		},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	startRec := records[0]
	if len(startRec.Mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(startRec.Mounts))
	}
	if startRec.Mounts[0].Source != "." {
		t.Errorf("expected relative source '.', got %q", startRec.Mounts[0].Source)
	}
	if startRec.Mounts[0].Target != "/workspace" {
		t.Errorf("expected target '/workspace', got %q", startRec.Mounts[0].Target)
	}
	if !startRec.Mounts[0].ReadOnly {
		t.Error("expected read_only to be true")
	}
}

func TestAuditNoContainerOutput(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	const containerOutput = "this-is-container-stdout-and-stderr"

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), containerOutput) {
			t.Fatalf("audit record contains container output!\n%s", raw)
		}
	}
}

func TestAuditRecordTimeIsRFC3339(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image": "alpine:latest",
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) == 0 {
		t.Fatal("expected audit records")
	}

	for _, rec := range records {
		if _, err := time.Parse(time.RFC3339, rec.Time); err != nil {
			t.Errorf("time not RFC3339: %q: %v", rec.Time, err)
		}
	}
}

func TestAuditCommandArgCount(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sh", "-c", "echo hello world"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	if len(records) < 2 {
		t.Fatalf("expected at least 2 audit records, got %d", len(records))
	}

	startRec := records[0]
	if startRec.CommandArgCount == nil || *startRec.CommandArgCount != 3 {
		t.Fatalf("expected command_arg_count 3, got %v", startRec.CommandArgCount)
	}

	// Verify that the raw command arguments do NOT appear in the audit record
	raw, _ := json.Marshal(startRec)
	if strings.Contains(string(raw), "echo hello world") {
		t.Fatalf("audit record contains raw command argument!\n%s", raw)
	}
}

func TestAuditNoCommandInRecord(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	const secretCmd = "SECRET_CMD_ARG_UNIQUE_12345"

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"sh", "-c", secretCmd},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
	}
	op.Wait()

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		raw, _ := json.Marshal(rec)
		if strings.Contains(string(raw), secretCmd) {
			t.Fatalf("audit record contains secret command argument!\n%s", raw)
		}
	}
}

func TestRunShutdownGateNoStartAudit(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	// Close the admission gate before the request.
	app.OperationSupervisor.beginShutdown()

	called := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		called = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:latest",
		"command": []string{"echo", "hello"},
	}, result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected %d, got %d", http.StatusServiceUnavailable, w.Code)
	}

	if called {
		t.Error("executor must not be called when admission gate is closed")
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	for _, rec := range records {
		if rec.Event == "run.start" {
			t.Error("run.start must not be written when operation is rejected by shutdown gate")
		}
		if rec.Event == "run.finish" {
			t.Error("run.finish must not be written when operation is rejected by shutdown gate")
		}
	}
}

// --- Docker-operation rejection audit events ---

func TestPullRejectedAudit(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatal(err)
	}

	// Send a pull request with empty image (invalid_image).
	reqBody := map[string]any{"image": ""}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp pullResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != "invalid_image" {
		t.Fatalf("expected code invalid_image, got %q", resp.Code)
	}

	records := parseAuditRecords(auditBuf)
	count := 0
	for _, rec := range records {
		if rec.Event == "pull.rejected" {
			count++
			if rec.Result != "invalid_image" {
				t.Errorf("result = %q, want invalid_image", rec.Result)
			}
			if rec.SessionID == "" {
				t.Error("session_id must be present")
			}
			if rec.Image != "" {
				t.Error("rejected event must not contain image")
			}
			if rec.OperationID != "" {
				t.Error("rejected event must not contain operation_id")
			}
		}
		if rec.Event == "pull.start" {
			t.Error("pull.start must not be emitted for rejected request")
		}
		if rec.Event == "pull.finish" {
			t.Error("pull.finish must not be emitted for rejected request")
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 pull.rejected event, got %d", count)
	}
}

func TestBuildRejectedAudit(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatal(err)
	}

	// Create a valid build context.
	ctxDir := result.Session.Workspace
	dockerfilePath := filepath.Join(ctxDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Send a build request with invalid build args.
	reqBody := map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "test:latest",
		"build_args": map[string]string{"INVALID-KEY": "value"},
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != "invalid_build_args" {
		t.Fatalf("expected code invalid_build_args, got %q", resp.Code)
	}

	records := parseAuditRecords(auditBuf)
	found := false
	for _, rec := range records {
		if rec.Event == "build.rejected" {
			found = true
			if rec.Result != "invalid_build_args" {
				t.Errorf("result = %q, want invalid_build_args", rec.Result)
			}
			if rec.SessionID == "" {
				t.Error("session_id must be present")
			}
		}
		if rec.Event == "build.start" {
			t.Error("build.start must not be emitted for rejected request")
		}
		if rec.Event == "build.finish" {
			t.Error("build.finish must not be emitted for rejected request")
		}
	}
	if !found {
		t.Fatal("build.rejected event not found in audit records")
	}
}

func TestRunRejectedAudit(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatal(err)
	}

	// Send a run request with invalid mount (source outside workspace).
	reqBody := map[string]any{
		"image":   "alpine:3.24",
		"mounts":  []map[string]any{{"source": "/tmp/outside", "target": "/data"}},
		"command": []string{"echo", "hello"},
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != "invalid_mount" {
		t.Fatalf("expected code invalid_mount, got %q", resp.Code)
	}

	records := parseAuditRecords(auditBuf)
	found := false
	for _, rec := range records {
		if rec.Event == "run.rejected" {
			found = true
			if rec.Result != "invalid_mount" {
				t.Errorf("result = %q, want invalid_mount", rec.Result)
			}
			if rec.SessionID == "" {
				t.Error("session_id must be present")
			}
			// Rejected events must not contain sensitive request data.
			if len(rec.Mounts) > 0 {
				t.Error("rejected event must not contain mounts")
			}
			if len(rec.EnvKeys) > 0 {
				t.Error("rejected event must not contain env_keys")
			}
			if rec.Image != "" {
				t.Error("rejected event must not contain image")
			}
		}
		if rec.Event == "run.start" {
			t.Error("run.start must not be emitted for rejected request")
		}
		if rec.Event == "run.finish" {
			t.Error("run.finish must not be emitted for rejected request")
		}
	}
	if !found {
		t.Fatal("run.rejected event not found in audit records")
	}
}

func TestRejectedInvalidJSON(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatal(err)
	}

	// Send invalid JSON to pull.
	req := httptest.NewRequest(http.MethodPost, "/pull", strings.NewReader("not-json"))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	records := parseAuditRecords(auditBuf)
	found := false
	for _, rec := range records {
		if rec.Event == "pull.rejected" {
			found = true
			if rec.Result != "invalid_json" {
				t.Errorf("result = %q, want invalid_json", rec.Result)
			}
		}
	}
	if !found {
		t.Fatal("pull.rejected event not found for invalid JSON")
	}
}

func TestRejectedShuttingDown(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()
	app.OperationSupervisor.beginShutdown()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatal(err)
	}

	// Create a valid build context.
	ctxDir := result.Session.Workspace
	dockerfilePath := filepath.Join(ctxDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	reqBody := map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "test:latest",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}

	records := parseAuditRecords(auditBuf)
	found := false
	for _, rec := range records {
		if rec.Event == "build.rejected" {
			found = true
			if rec.Result != "shutting_down" {
				t.Errorf("result = %q, want shutting_down", rec.Result)
			}
		}
		if rec.Event == "build.start" {
			t.Error("build.start must not be emitted for shutting_down rejection")
		}
	}
	if !found {
		t.Fatal("build.rejected event not found for shutting_down")
	}
}

func TestRejectedNoSensitiveData(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatal(err)
	}

	secretValue := "SECRET_PASSWORD_DO_NOT_LEAK"

	// Send a run request with a secret environment value that will be rejected
	// due to invalid environment variable name.
	reqBody := map[string]any{
		"image":       "alpine:3.24",
		"environment": map[string]string{"INVALID-KEY": secretValue},
		"command":     []string{"echo", "hello"},
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	// The raw audit output must not contain the secret.
	rawAudit := auditBuf.String()
	if strings.Contains(rawAudit, secretValue) {
		t.Fatalf("audit output contains secret value:\n%s", rawAudit)
	}

	// Also verify no sensitive metadata in the rejected event.
	records := parseAuditRecords(auditBuf)
	for _, rec := range records {
		if rec.Event == "run.rejected" {
			if len(rec.EnvKeys) > 0 {
				t.Error("rejected event must not contain env_keys")
			}
			if rec.Image != "" {
				t.Error("rejected event must not contain image")
			}
			if rec.CommandArgCount != nil {
				t.Error("rejected event must not contain command_arg_count")
			}
		}
	}
}

func TestAcceptedOperationNoRejectedEvent(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatal(err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	// Send a valid pull request.
	reqBody := map[string]any{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	records := parseAuditRecords(auditBuf)
	for _, rec := range records {
		if rec.Event == "pull.rejected" {
			t.Error("accepted request must not emit pull.rejected")
		}
	}
}

func TestBuildRejectedInternalError(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatal(err)
	}

	// Make staging itself fail before operation registration.
	sentinelErr := errors.New("injected staging error")
	app.StageBuildContextFn = func(ctx context.Context, ws, cpath, dfrel, rdir, opID string) (*stagedBuildContext, error) {
		return nil, sentinelErr
	}

	// Create a valid build context (staging will fail regardless).
	ctxDir := result.Session.Workspace
	dockerfilePath := filepath.Join(ctxDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}

	reqBody := map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "test:latest",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != "internal_error" {
		t.Fatalf("expected code internal_error, got %q", resp.Code)
	}

	records := parseAuditRecords(auditBuf)
	count := 0
	for _, rec := range records {
		if rec.Event == "build.rejected" {
			count++
			if rec.Result != "internal_error" {
				t.Errorf("result = %q, want internal_error", rec.Result)
			}
		}
		if rec.Event == "build.start" {
			t.Error("build.start must not be emitted for rejected request")
		}
		if rec.Event == "build.finish" {
			t.Error("build.finish must not be emitted for rejected request")
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 build.rejected event, got %d", count)
	}
}

func TestRejectedWithRequestID(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatal(err)
	}

	// Use the real mux with withRequestID middleware.
	mux := http.NewServeMux()
	mux.HandleFunc("POST /pull", withRequestID(app.handlePull))

	reqBody := map[string]any{"image": ""}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	// Assert X-Request-ID header is non-empty.
	rid := w.Header().Get("X-Request-ID")
	if rid == "" {
		t.Fatal("X-Request-ID header must be non-empty")
	}

	records := parseAuditRecords(auditBuf)
	found := false
	for _, rec := range records {
		if rec.Event == "pull.rejected" {
			found = true
			if rec.RequestID == "" {
				t.Error("rejected event request_id must be non-empty")
			}
			if rec.RequestID != rid {
				t.Errorf("audit request_id = %q, want %q (X-Request-ID)", rec.RequestID, rid)
			}
			if rec.SessionID != result.Session.ID {
				t.Errorf("session_id = %q, want %q", rec.SessionID, result.Session.ID)
			}
		}
	}
	if !found {
		t.Fatal("pull.rejected event not found")
	}
}

func TestRejectedUnauthenticatedNoRejectedEvent(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	// Send pull request without authentication.
	reqBody := map[string]any{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	records := parseAuditRecords(auditBuf)

	// Exactly one auth.failure must be emitted.
	authFailureCount := 0
	for _, rec := range records {
		if rec.Event == "auth.failure" {
			authFailureCount++
		}
		if rec.Event == "pull.rejected" {
			t.Error("unauthenticated request must not emit pull.rejected")
		}
		if rec.Event == "build.rejected" {
			t.Error("unauthenticated request must not emit build.rejected")
		}
		if rec.Event == "run.rejected" {
			t.Error("unauthenticated request must not emit run.rejected")
		}
	}
	if authFailureCount != 1 {
		t.Errorf("expected exactly 1 auth.failure event, got %d", authFailureCount)
	}
}
