package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func setupReloadApp(t *testing.T, auditEnabled bool) (*App, string, string, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	configPath, tokenPath, _, _, cleanup := setupReloadTestEnv(t)
	t.Cleanup(cleanup)

	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)
	initLoggers(opBuf, auditBuf, slog.LevelInfo, auditEnabled)
	t.Cleanup(logging.reset)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	adminHash, err := loadAdminToken(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	db, err := openDatabase(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := initializeDatabase(db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	// Read the actual admin token from the token file.
	tokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	adminToken := strings.TrimSpace(string(tokenData))

	return &App{Config: cfg, DB: db, AdminTokenHash: adminHash}, configPath, adminToken, auditBuf, opBuf
}

func writeReloadConfig(t *testing.T, configPath string, cfg *Config, auditEnabled *bool) {
	t.Helper()
	newCfg := map[string]any{
		"allowed_root": cfg.AllowedRoot,
		"session_ttl":  "12h",
		"log_level":    "info",
	}
	if auditEnabled != nil {
		newCfg["audit_enabled"] = *auditEnabled
	}
	data, _ := json.MarshalIndent(newCfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
}

// --- Reload audit ---

func TestReloadAuditTrueToFalse(t *testing.T) {
	app, configPath, adminToken, auditBuf, _ := setupReloadApp(t, true)
	enabled := false
	writeReloadConfig(t, configPath, app.Config, &enabled)

	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	app.handleReload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !hasAuditEvent(auditBuf, "config.reload", "success") {
		t.Fatal("config.reload success must be written when audit_enabled changes true->false")
	}
}

func TestReloadAuditFalseToTrue(t *testing.T) {
	app, configPath, adminToken, auditBuf, _ := setupReloadApp(t, false)
	enabled := true
	writeReloadConfig(t, configPath, app.Config, &enabled)

	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	app.handleReload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !hasAuditEvent(auditBuf, "config.reload", "success") {
		t.Fatal("config.reload success must be written when audit_enabled changes false->true")
	}
}

func TestReloadAuditInvalidConfig(t *testing.T) {
	app, configPath, adminToken, auditBuf, _ := setupReloadApp(t, true)
	if err := os.WriteFile(configPath, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	app.handleReload(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	rec := findAuditEvent(auditBuf, "config.reload")
	if rec == nil || rec.Result != "invalid_config" {
		t.Fatal("config.reload audit with result=invalid_config must be written")
	}
	if rec.Duration == "" {
		t.Error("config.reload invalid_config audit must include duration")
	}
}

func TestReloadAuditNoConfigContents(t *testing.T) {
	app, _, adminToken, auditBuf, _ := setupReloadApp(t, true)

	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	app.handleReload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	for _, rec := range parseAuditRecords(auditBuf) {
		if rec.Event == "config.reload" {
			data, _ := json.Marshal(rec)
			for _, f := range []string{"allowed_root", "session_ttl", "log_level", "audit_enabled"} {
				if strings.Contains(string(data), f) {
					t.Errorf("config.reload audit must not contain %q", f)
				}
			}
		}
	}
}

func TestReloadAuditTrueToTrueSingleEvent(t *testing.T) {
	app, _, adminToken, auditBuf, _ := setupReloadApp(t, true)

	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	app.handleReload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	count := countAuditEvents(auditBuf, "config.reload", "success")
	if count != 1 {
		t.Errorf("expected exactly 1 config.reload success event, got %d", count)
	}
}

func TestReloadAuditFalseToFalseNoEvent(t *testing.T) {
	app, _, adminToken, auditBuf, _ := setupReloadApp(t, false)

	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	app.handleReload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if hasAuditEvent(auditBuf, "config.reload", "success") {
		t.Error("config.reload audit must not be written when audit is disabled")
	}
}

func TestReloadAuditTrueToFalseThenTrue(t *testing.T) {
	app, configPath, adminToken, auditBuf, _ := setupReloadApp(t, true)

	// Step 1: true -> false
	enabled := false
	writeReloadConfig(t, configPath, app.Config, &enabled)
	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	app.handleReload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("step 1: expected 200, got %d", w.Code)
	}

	// Step 2: false -> true
	enabled = true
	writeReloadConfig(t, configPath, app.Config, &enabled)
	req = httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	app.handleReload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("step 2: expected 200, got %d", w.Code)
	}

	count := countAuditEvents(auditBuf, "config.reload", "success")
	if count != 2 {
		t.Errorf("expected 2 config.reload success events, got %d", count)
	}
	writeAudit(auditRecord{Event: "test.after.reenable"})
	if !strings.Contains(auditBuf.String(), "test.after.reenable") {
		t.Fatal("audit must work after re-enabling")
	}
}

// --- Credential revoke ---

func TestRevokeCredentialPreReadBeforeMutation(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "revoke-test")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1000", "1000", home, nil
	}

	principal, err := createPrincipal(app.DB, "revoke-test")
	if err != nil {
		t.Fatal(err)
	}
	cred, _, err := createCredential(app.DB, principal.Username, "test-cred")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/principals/revoke-test/credentials/"+cred.ID+"/revoke", nil)
	req.SetPathValue("username", "revoke-test")
	req.SetPathValue("id", cred.ID)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleRevokeCredential(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	rec := findAuditEvent(auditBuf, "principal.credential_revoke")
	if rec == nil || rec.Result != "success" {
		t.Fatal("credential_revoke success audit not found")
	}
	if rec.CredentialID != cred.ID || rec.CredentialName != cred.Name || rec.PrincipalName != cred.Principal {
		t.Fatalf("audit missing metadata: id=%q name=%q principal=%q", rec.CredentialID, rec.CredentialName, rec.PrincipalName)
	}
}

func TestRevokeCredentialNotFoundNoMutation(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	req := httptest.NewRequest(http.MethodPost, "/principals/test/credentials/dhcr_nonexistent/revoke", nil)
	req.SetPathValue("username", "test")
	req.SetPathValue("id", "dhcr_nonexistent")
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleRevokeCredential(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}

	rec := findAuditEvent(auditBuf, "principal.credential_revoke")
	if rec == nil || rec.Result != "credential_not_found" {
		t.Fatal("credential_revoke credential_not_found audit not found")
	}
	if rec.CredentialID != "" || rec.CredentialName != "" || rec.PrincipalName != "" {
		t.Error("credential_not_found audit should not have credential metadata")
	}
}

func TestRevokeCredentialIdempotentHandler(t *testing.T) {
	_, _ = setupTestLogging(t)
	app := newTestAppWithAuth(t)

	home := filepath.Join(app.Config.AllowedRoot, "home", "idempotent-test")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1001", "1001", home, nil
	}

	principal, err := createPrincipal(app.DB, "idempotent-test")
	if err != nil {
		t.Fatal(err)
	}
	cred, _, err := createCredential(app.DB, principal.Username, "test-cred")
	if err != nil {
		t.Fatal(err)
	}

	// First revoke.
	req := httptest.NewRequest(http.MethodPost, "/principals/idempotent-test/credentials/"+cred.ID+"/revoke", nil)
	req.SetPathValue("username", "idempotent-test")
	req.SetPathValue("id", cred.ID)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleRevokeCredential(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first revoke: expected 200, got %d", w.Code)
	}

	// Second revoke (idempotent).
	req = httptest.NewRequest(http.MethodPost, "/principals/idempotent-test/credentials/"+cred.ID+"/revoke", nil)
	req.SetPathValue("username", "idempotent-test")
	req.SetPathValue("id", cred.ID)
	withAuth(req)
	w = httptest.NewRecorder()
	app.handleRevokeCredential(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("second revoke: expected 200, got %d", w.Code)
	}

	var resp revokeCredentialResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Changed || resp.Message != "unchanged" {
		t.Fatalf("second revoke should have changed=false, message='unchanged', got changed=%v message=%q", resp.Changed, resp.Message)
	}
}

func TestRevokeCredentialPreReadErrorNoMutation(t *testing.T) {
	_, opBuf := setupTestLogging(t)
	app := newTestAppWithAuth(t)
	app.DB.Close()

	req := httptest.NewRequest(http.MethodPost, "/principals/test/credentials/dhcr_test/revoke", nil)
	req.SetPathValue("username", "test")
	req.SetPathValue("id", "dhcr_test")
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleRevokeCredential(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	if !strings.Contains(opBuf.String(), "credential revoke pre-read failed") {
		t.Fatalf("expected operational ERROR for pre-read failure, got:\n%s", opBuf.String())
	}
}

// --- Pull log level ---

func TestPullNonZeroNoOperationalError(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatal(err)
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 1")
	}

	req := newPullRequest(map[string]any{"image": "nonexistent:latest"}, result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)
	if w.Code != 500 {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	var finishFound bool
	for _, rec := range records {
		if rec.Event == "pull.finish" && rec.Result == "pull_error" {
			finishFound = true
			if rec.ExitCode == nil || *rec.ExitCode != 1 {
				t.Errorf("expected exit_code 1, got %v", rec.ExitCode)
			}
			break
		}
	}
	if !finishFound {
		t.Fatal("pull.finish audit not found")
	}
	if strings.Contains(opBuf.String(), "ERROR") {
		t.Fatalf("pull non-zero exit must not produce operational ERROR, got:\n%s", opBuf.String())
	}
}

func TestPullStartFailureOperationalError(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatal(err)
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "nonexistent-docker-binary")
	}

	req := newPullRequest(map[string]any{"image": "alpine:3.24"}, result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)
	if w.Code != 500 {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	if !strings.Contains(opBuf.String(), "cannot start docker pull") {
		t.Fatalf("pull start failure must produce operational ERROR, got:\n%s", opBuf.String())
	}

	records := filterBySession(parseAuditRecords(auditBuf), result.Session.ID)
	var finishFound bool
	for _, rec := range records {
		if rec.Event == "pull.finish" {
			finishFound = true
			break
		}
	}
	if !finishFound {
		t.Fatal("pull.finish audit must be written even on start failure")
	}
}

// --- Audit writer failure ---

func TestAuditWriterFailureContainsCorrelationFields(t *testing.T) {
	opBuf := new(bytes.Buffer)
	initLoggers(opBuf, &failingAuditWriter{}, slog.LevelError, true)
	defer logging.reset()

	writeAudit(auditRecord{
		Event: "build.finish", SessionID: "dhs_test", OperationID: "op_test123",
		Result: "succeeded", Duration: "5s",
	})

	opOutput := opBuf.String()
	if !strings.Contains(opOutput, "build.finish") {
		t.Fatalf("expected audit_event in error, got:\n%s", opOutput)
	}
	if !strings.Contains(opOutput, "op_test123") {
		t.Fatalf("expected operation_id in error, got:\n%s", opOutput)
	}
}

func TestAuditWriterFailurePreservesRequestSessionID(t *testing.T) {
	opBuf := new(bytes.Buffer)
	initLoggers(opBuf, &failingAuditWriter{}, slog.LevelInfo, true)
	defer logging.reset()

	writeAudit(auditRecord{
		Event: "session.create", RequestID: "req_test123", SessionID: "dhs_test456",
		Result: "success", Duration: "1ms",
	})

	opOutput := opBuf.String()
	if !strings.Contains(opOutput, "req_test123") {
		t.Fatalf("expected request_id in audit writer failure, got:\n%s", opOutput)
	}
	if !strings.Contains(opOutput, "dhs_test456") {
		t.Fatalf("expected session_id in audit writer failure, got:\n%s", opOutput)
	}
}

func TestAuditWriterFailureDoesNotBreakRequest(t *testing.T) {
	app, _, adminToken, _, opBuf := setupReloadApp(t, true)
	initLoggers(opBuf, &failingAuditWriter{}, slog.LevelInfo, true)
	defer logging.reset()

	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	app.handleReload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (audit writer failure must not break request)", w.Code)
	}
}

// --- Operational diagnostics ---

func TestBuildStartFailureOperationalDiagnostic(t *testing.T) {
	_, opBuf := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatal(err)
	}
	ctxDir := filepath.Join(result.Session.Workspace, "buildctx")
	if err := os.MkdirAll(ctxDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctxDir, "Dockerfile"), []byte("FROM alpine"), 0644); err != nil {
		t.Fatal(err)
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "nonexistent-docker-binary")
	}

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader([]byte(fmt.Sprintf(
		`{"image":"test:latest","context":"%s","dockerfile":"Dockerfile","build_args":{"SECRET":"password"}}`, ctxDir))))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.handleBuild(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	opOutput := opBuf.String()
	if !strings.Contains(opOutput, "cannot start build process") {
		t.Fatalf("build start failure must produce operational ERROR, got:\n%s", opOutput)
	}
	if strings.Contains(opOutput, "password") {
		t.Fatal("operational ERROR must not contain build-arg values")
	}
}

func TestRunStartFailureOperationalDiagnostic(t *testing.T) {
	_, opBuf := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatal(err)
	}
	mountRel := "mountdir"
	mountDir := filepath.Join(result.Session.Workspace, mountRel)
	if err := os.MkdirAll(mountDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mountDir, "file.txt"), []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "nonexistent-docker-binary")
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(fmt.Sprintf(
		`{"image":"alpine:3.24","command":["echo","hello"],"environment":{"SECRET":"password"},"mounts":[{"source":"%s","target":"/mnt"}]}`, mountRel))))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.handleRun(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	opOutput := opBuf.String()
	if !strings.Contains(opOutput, "cannot start run process") {
		t.Fatalf("run start failure must produce operational ERROR, got:\n%s", opOutput)
	}
	if strings.Contains(opOutput, "password") || strings.Contains(opOutput, "hello") {
		t.Fatal("operational ERROR must not contain env/command values")
	}
}

func TestAdminTokenRotateInternalErrorDiagnostic(t *testing.T) {
	auditBuf, opBuf := setupTestLogging(t)
	app := newTestAppWithAuth(t)
	app.RotateRenameFn = func(oldPath, newPath string) error { return errors.New("rename failed") }

	req := httptest.NewRequest(http.MethodPost, "/admin/token/rotate", nil)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleRotateAdminToken(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	if !strings.Contains(opBuf.String(), "admin token rotate failed") {
		t.Fatalf("admin token rotate internal error must produce operational ERROR, got:\n%s", opBuf.String())
	}
	if !hasAuditEvent(auditBuf, "admin_token.rotate", "error") {
		t.Fatal("admin_token.rotate audit with result=error not found")
	}
}

func TestAdminTokenRotateStaleTokenNoOperationalError(t *testing.T) {
	_, opBuf := setupTestLogging(t)
	app := newTestAppWithAuth(t)

	newToken, err := app.rotateAdminToken(app.getAdminTokenHash())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/token/rotate", nil)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleRotateAdminToken(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if strings.Contains(opBuf.String(), "admin token rotate failed") {
		t.Fatalf("stale-token case must not produce operational ERROR, got:\n%s", opBuf.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/token/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+newToken)
	w = httptest.NewRecorder()
	app.handleRotateAdminToken(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with new token, got %d", w.Code)
	}
}

// --- Async finish ---

func TestAsyncFinishAuditNoRequestID(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	writeAuditWithRequestID(context.Background(), auditRecord{
		Event: "build.finish", SessionID: "dhs_test", OperationID: "op_test",
		Result: "succeeded", Duration: "5s",
	})
	records := parseAuditRecords(auditBuf)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].RequestID != "" {
		t.Error("async finish audit must not contain request_id")
	}
}

// --- Helpers ---

func hasAuditEvent(buf *bytes.Buffer, event, result string) bool {
	for _, rec := range parseAuditRecords(buf) {
		if rec.Event == event && rec.Result == result {
			return true
		}
	}
	return false
}

func findAuditEvent(buf *bytes.Buffer, event string) *auditRecord {
	for _, rec := range parseAuditRecords(buf) {
		if rec.Event == event {
			return &rec
		}
	}
	return nil
}

func countAuditEvents(buf *bytes.Buffer, event, result string) int {
	count := 0
	for _, rec := range parseAuditRecords(buf) {
		if rec.Event == event && rec.Result == result {
			count++
		}
	}
	return count
}
