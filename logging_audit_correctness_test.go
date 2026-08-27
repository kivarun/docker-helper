package main

import (
	"bytes"
	"context"
	"database/sql"
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
	"time"
)

func setupReloadApp(t *testing.T, auditEnabled bool) (*App, string, string, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	configPath, tokenPath, _, _, cleanup := setupReloadTestEnv(t)
	t.Cleanup(cleanup)

	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)
	initLoggers(opBuf, auditBuf, slog.LevelInfo, auditEnabled)
	t.Cleanup(logging.reset)

	cfg, err := loadAndPrepareRuntimeConfig()
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
		"allowed_root": cfg.AllowedRoots[0],
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

func TestReloadAuditTransition(t *testing.T) {
	tests := []struct {
		name           string
		startAudit     bool
		newAudit       *bool // nil = don't set (keep absent)
		wantHTTP       int
		wantAuditCount int // number of config.reload success events
		wantResult     string
	}{
		{
			name:           "true -> false",
			startAudit:     true,
			newAudit:       ptrOf(false),
			wantHTTP:       http.StatusOK,
			wantAuditCount: 1,
			wantResult:     "success",
		},
		{
			name:           "false -> true",
			startAudit:     false,
			newAudit:       ptrOf(true),
			wantHTTP:       http.StatusOK,
			wantAuditCount: 1,
			wantResult:     "success",
		},
		{
			name:           "true -> true",
			startAudit:     true,
			newAudit:       ptrOf(true),
			wantHTTP:       http.StatusOK,
			wantAuditCount: 1,
			wantResult:     "success",
		},
		{
			name:           "false -> false",
			startAudit:     false,
			newAudit:       ptrOf(false),
			wantHTTP:       http.StatusOK,
			wantAuditCount: 0,
			wantResult:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, configPath, adminToken, auditBuf, _ := setupReloadApp(t, tt.startAudit)
			writeReloadConfig(t, configPath, app.Config, tt.newAudit)

			req := httptest.NewRequest(http.MethodPost, "/reload", nil)
			req.Header.Set("Authorization", "Bearer "+adminToken)
			w := httptest.NewRecorder()
			// Wrap with request ID middleware so request_id is available in context.
			withRequestID(app.handleReload)(w, req)
			if w.Code != tt.wantHTTP {
				t.Fatalf("expected %d, got %d", tt.wantHTTP, w.Code)
			}

			count := countAuditEvents(auditBuf, "config.reload", tt.wantResult)
			if count != tt.wantAuditCount {
				t.Errorf("expected %d config.reload %q events, got %d", tt.wantAuditCount, tt.wantResult, count)
			}

			// Verify audit records have duration and request_id when present.
			if tt.wantAuditCount > 0 {
				rec := findAuditEvent(auditBuf, "config.reload")
				if rec == nil {
					t.Fatal("expected config.reload audit record")
				}
				if rec.Duration == "" {
					t.Error("config.reload audit must include duration")
				}
				if rec.RequestID == "" {
					t.Error("config.reload audit must include request_id")
				}
			}
		})
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
	withRequestID(app.handleReload)(w, req)
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

// TestReloadAuditWriterRecover verifies the independent invariant:
// audit writer works again after disable -> re-enable cycle.
func TestReloadAuditWriterRecover(t *testing.T) {
	app, configPath, adminToken, auditBuf, _ := setupReloadApp(t, true)

	// Step 1: true -> false
	enabled := false
	writeReloadConfig(t, configPath, app.Config, &enabled)
	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	withRequestID(app.handleReload)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("step 1: expected 200, got %d", w.Code)
	}

	// Step 2: false -> true
	enabled = true
	writeReloadConfig(t, configPath, app.Config, &enabled)
	req = httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w = httptest.NewRecorder()
	withRequestID(app.handleReload)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("step 2: expected 200, got %d", w.Code)
	}

	// Verify audit writer works after re-enable.
	writeAudit(auditRecord{Event: "test.after.reenable"})
	if !strings.Contains(auditBuf.String(), "test.after.reenable") {
		t.Fatal("audit must work after re-enabling")
	}
}

// TestReloadAuditNoSensitiveValues verifies that config.reload audit records
// do not contain sensitive config values. Uses unique marker values for both
// allowed_root and trusted_ca_path and checks the raw audit JSON for absence
// of those specific values.
func TestReloadAuditNoSensitiveValues(t *testing.T) {
	app, configPath, adminToken, auditBuf, _ := setupReloadApp(t, true)

	// Create a workspace root with a unique marker name so we can detect
	// if its value leaks into the audit JSON.
	markerRoot := "audit-sensitive-root-marker-7f3a9c"
	allowedRoot, err := allocateTestWorkspaceRoot(append(candidateBasePaths(), "/"))
	if err != nil {
		t.Fatalf("cannot allocate workspace root: %v", err)
	}
	// Rename to our marker name for deterministic detection.
	markerRootPath := filepath.Join(filepath.Dir(allowedRoot), markerRoot)
	if err := os.Rename(allowedRoot, markerRootPath); err != nil {
		t.Fatalf("rename to marker: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(markerRootPath) })

	markerCA := "audit-sensitive-ca-marker-4b2e8d"

	newCfg := map[string]any{
		"allowed_root":    markerRootPath,
		"session_ttl":     "12h",
		"log_level":       "info",
		"trusted_ca_path": "/" + markerCA,
	}
	data, _ := json.MarshalIndent(newCfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	withRequestID(app.handleReload)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Verify the reload actually produced an audit record (proves we reached the path).
	rec := findAuditEvent(auditBuf, "config.reload")
	if rec == nil {
		t.Fatal("expected config.reload audit record — test did not reach the audit path")
	}

	// Check raw audit JSON for both unique marker values.
	auditRaw := auditBuf.String()
	if strings.Contains(auditRaw, markerRoot) {
		t.Errorf("config.reload audit must not contain allowed_root value %q", markerRoot)
	}
	if strings.Contains(auditRaw, markerCA) {
		t.Errorf("config.reload audit must not contain trusted_ca_path value %q", markerCA)
	}
}

// --- Credential revoke ---

func TestRevokeCredentialPreReadBeforeMutation(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "revoke-test")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1000", "1000", home, nil
	}

	principal, err := createPrincipal(app.DB, "revoke-test", app.Config.AllowedRoots)
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
	withAdminToken(req)
	w := httptest.NewRecorder()
	app.handleRevokeCredential(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	rec := findAuditEvent(auditBuf, "principal.credential_revoke")
	if rec == nil || rec.Result != "success" {
		t.Fatal("credential_revoke success audit not found")
	}
	if rec.CredentialID != cred.ID || rec.CredentialName != cred.Name || rec.PrincipalName != cred.PrincipalName {
		t.Fatalf("audit missing metadata: id=%q name=%q principal=%q", rec.CredentialID, rec.CredentialName, rec.PrincipalName)
	}
}

func TestRevokeCredentialNotFoundNoMutation(t *testing.T) {
	auditBuf, _ := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	req := httptest.NewRequest(http.MethodPost, "/principals/test/credentials/dhcr_nonexistent/revoke", nil)
	req.SetPathValue("username", "test")
	req.SetPathValue("id", "dhcr_nonexistent")
	withAdminToken(req)
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
	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "idempotent-test")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1001", "1001", home, nil
	}

	principal, err := createPrincipal(app.DB, "idempotent-test", app.Config.AllowedRoots)
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
	withAdminToken(req)
	w := httptest.NewRecorder()
	app.handleRevokeCredential(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first revoke: expected 200, got %d", w.Code)
	}

	// Second revoke (idempotent).
	req = httptest.NewRequest(http.MethodPost, "/principals/idempotent-test/credentials/"+cred.ID+"/revoke", nil)
	req.SetPathValue("username", "idempotent-test")
	req.SetPathValue("id", cred.ID)
	withAdminToken(req)
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
	app := newTestAppWithAdminToken(t)

	// Create a real credential that can be revoked.
	home := filepath.Join(app.Config.AllowedRoots[0], "home", "preread-test")
	if err := os.MkdirAll(home, 0755); err != nil {
		t.Fatal(err)
	}
	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1002", "1002", home, nil
	}
	principal, err := createPrincipal(app.DB, "preread-test", app.Config.AllowedRoots)
	if err != nil {
		t.Fatal(err)
	}
	cred, _, err := createCredential(app.DB, principal.Username, "test-cred")
	if err != nil {
		t.Fatal(err)
	}

	// Replace DB with one that fails Query (pre-read) but allows Exec (mutation).
	// This proves: if mutation were attempted, it would succeed.
	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailQueryDB(t, dbPath, errors.New("mock_query_fail_for_testing"))
	defer app.DB.Close()

	req := httptest.NewRequest(http.MethodPost, "/principals/preread-test/credentials/"+cred.ID+"/revoke", nil)
	req.SetPathValue("username", "preread-test")
	req.SetPathValue("id", cred.ID)
	withAdminToken(req)
	w := httptest.NewRecorder()
	app.handleRevokeCredential(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	if !strings.Contains(opBuf.String(), "credential revoke pre-read failed") {
		t.Fatalf("expected operational ERROR for pre-read failure, got:\n%s", opBuf.String())
	}

	// Reopen the real DB and verify the credential was NOT revoked.
	// Since Exec would have succeeded, the only explanation for
	// the credential still being active is that mutation was never attempted.
	realDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer realDB.Close()
	var revokedAt sql.NullInt64
	err = realDB.QueryRow(
		`SELECT c.revoked_at FROM credentials c WHERE c.id = ?`, cred.ID,
	).Scan(&revokedAt)
	if err != nil {
		t.Fatal(err)
	}
	if revokedAt.Valid {
		t.Error("credential must NOT be revoked — mutation path must not have been reached")
	}
}

// --- Pull log level ---

// TestPullNonZeroNoOperationalError verifies the logging invariant:
// a successfully started docker process with non-zero exit is a workload
// result, not a daemon operational error.
func TestPullNonZeroNoOperationalError(t *testing.T) {
	_, opBuf := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
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

	if strings.Contains(opBuf.String(), "ERROR") {
		t.Fatalf("pull non-zero exit must not produce operational ERROR, got:\n%s", opBuf.String())
	}
}

// TestPullStartFailureOperationalError verifies the logging invariant:
// a docker Start failure (process never started) is an operational error.
func TestPullStartFailureOperationalError(t *testing.T) {
	_, opBuf := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
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
}

// --- Audit writer failure ---

// TestAuditWriterFailureCorrelation verifies that when the audit writer
// fails, the operational error record contains all available correlation
// fields: audit_event, operation_id, request_id, and session_id.
func TestAuditWriterFailureCorrelation(t *testing.T) {
	opBuf := new(bytes.Buffer)
	initLoggers(opBuf, &failingAuditWriter{}, slog.LevelError, true)
	defer logging.reset()

	writeAudit(auditRecord{
		Event:       "build.finish",
		SessionID:   "dhs_test",
		OperationID: "op_test123",
		RequestID:   "req_abc456",
		Result:      "succeeded",
		Duration:    "5s",
	})

	opOutput := opBuf.String()
	for _, field := range []string{
		"build.finish", // audit_event
		"op_test123",   // operation_id
		"req_abc456",   // request_id
		"dhs_test",     // session_id
	} {
		if !strings.Contains(opOutput, field) {
			t.Errorf("expected %q in audit writer failure record, got:\n%s", field, opOutput)
		}
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
	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
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
	app := newTestAppWithAdminToken(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
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
	app := newTestAppWithAdminToken(t)
	app.RotateRenameFn = func(oldPath, newPath string) error { return errors.New("rename failed") }

	req := httptest.NewRequest(http.MethodPost, "/admin/token/rotate", nil)
	withAdminToken(req)
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

// --- Build cleanup correlation fields ---

// TestBuildCleanupCorrelationFields verifies that build cleanup logs emit
// operation="build" and operation_id=<ID> instead of operation=<ID>.
//
// This test uses a staging seam that forces Cleanup() to fail so the
// cleanup error log is guaranteed to be emitted.
func TestBuildCleanupCorrelationFields(t *testing.T) {
	_, opBuf := setupTestLogging(t)
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatal(err)
	}

	// Force admit rejection so the cleanup path runs.
	app.OperationSupervisor.shutting = true

	// Use a staging seam that forces Cleanup() to fail.
	sentinelErr := errors.New("injected staging cleanup error")
	app.StageBuildContextFn = stagingSeamWithCleanupError(t, sentinelErr)

	// Create a real build context so staging succeeds.
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

	// Parse operational JSON and find the cleanup log.
	opOutput := opBuf.String()
	foundCleanup := false
	for _, line := range strings.Split(strings.TrimSpace(opOutput), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		msg, _ := rec["msg"].(string)
		if !strings.HasPrefix(msg, "staging cleanup failed after admit rejection") {
			continue
		}
		foundCleanup = true

		// Assert operation == "build".
		opField, ok := rec["operation"].(string)
		if !ok {
			t.Fatal("cleanup log missing operation field")
		}
		if opField != "build" {
			t.Errorf("cleanup log operation = %q, want \"build\"", opField)
		}

		// Assert operation_id is non-empty.
		opID, ok := rec["operation_id"].(string)
		if !ok {
			t.Fatal("cleanup log missing operation_id field")
		}
		if opID == "" {
			t.Error("cleanup log operation_id is empty")
		}

		// Assert operation != operation_id.
		if opField == opID {
			t.Errorf("operation and operation_id must differ, both are %q", opField)
		}

		// Assert the error contains our sentinel.
		errField, _ := rec["error"].(string)
		if !strings.Contains(errField, sentinelErr.Error()) {
			t.Errorf("cleanup log error = %q, expected to contain %q", errField, sentinelErr.Error())
		}
	}
	if !foundCleanup {
		t.Fatalf("cleanup log not found in operational output:\n%s", opOutput)
	}
}

// --- Session correlation fields ---

// TestSessionCleanupCorrelationField verifies that session cleanup logs
// use session_id instead of session.
//
// This test creates a real session for a principal, makes the session
// runtime directory non-removable, then deletes the principal to trigger
// the cleanup failure path.
func TestSessionCleanupCorrelationField(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)
	initLoggers(opBuf, auditBuf, slog.LevelWarn, true)
	defer logging.reset()

	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "sessioncleanupuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1050", "1050", home, nil
	}

	username := "sessioncleanupuser"
	if _, err := createPrincipal(app.DB, username, app.Config.AllowedRoots); err != nil {
		t.Fatal(err)
	}

	// Create a credential and session for the principal.
	_, credToken, err := createCredential(app.DB, username, "laptop")
	if err != nil {
		t.Fatal(err)
	}

	sessMux := http.NewServeMux()
	sessMux.HandleFunc("POST /sessions", app.handleCreateSession)

	sessBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	sessData, _ := json.Marshal(sessBody)
	sessReq := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(sessData))
	sessReq.Header.Set("Authorization", "Bearer "+credToken)
	sessW := httptest.NewRecorder()
	sessMux.ServeHTTP(sessW, sessReq)
	if sessW.Code != http.StatusCreated {
		t.Fatalf("create session: expected %d, got %d: %s", http.StatusCreated, sessW.Code, sessW.Body.String())
	}

	var sessResp createSessionResponse
	if err := json.NewDecoder(sessW.Body).Decode(&sessResp); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	sessionID := sessResp.Session.ID

	// Create the session runtime directory so cleanup has something to remove.
	sessRuntimeDir := sessionRuntimeDir(app.Config.RuntimeDir, sessionID)
	if err := os.MkdirAll(sessRuntimeDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Replace the sessions parent directory with a regular file so that
	// os.RemoveAll on .../sessions/<sessionID> fails with ENOTDIR. This is
	// deterministic regardless of process privileges (unlike chmod).
	sessionsParentDir := filepath.Dir(sessRuntimeDir)
	if err := os.RemoveAll(sessionsParentDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sessionsParentDir, nil, 0644); err != nil {
		t.Fatal(err)
	}

	// Delete the principal — this triggers session runtime cleanup.
	delMux := http.NewServeMux()
	delMux.HandleFunc("DELETE /principals/{username}", app.handleDeletePrincipal)

	delReq := httptest.NewRequest(http.MethodDelete, "/principals/"+username, nil)
	delReq.Header.Set("Authorization", "Bearer "+testAdminToken)
	delW := httptest.NewRecorder()
	delMux.ServeHTTP(delW, delReq)

	if delW.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", delW.Code, delW.Body.String())
	}

	// Parse operational JSON and find the cleanup failure log.
	opOutput := opBuf.String()
	foundCleanup := false
	for _, line := range strings.Split(strings.TrimSpace(opOutput), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		msg, _ := rec["msg"].(string)
		if msg != "failed to clean up session runtime directory" {
			continue
		}
		foundCleanup = true

		// Assert session_id is present and matches.
		sid, ok := rec["session_id"].(string)
		if !ok {
			t.Fatal("cleanup log missing session_id field")
		}
		if sid != sessionID {
			t.Errorf("session_id = %q, want %q", sid, sessionID)
		}

		// Assert obsolete "session" field is absent.
		if _, hasSession := rec["session"]; hasSession {
			t.Error("cleanup log uses obsolete \"session\" field instead of \"session_id\"")
		}
	}
	if !foundCleanup {
		t.Fatalf("cleanup log not found in operational output:\n%s", opOutput)
	}
}

// TestSessionDeleteCleanupCorrelation verifies that when session runtime
// directory cleanup fails during session deletion, the operational log
// contains the correct correlation fields: operation=session_delete,
// session_id, error.
func TestSessionDeleteCleanupCorrelation(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)
	initLoggers(opBuf, auditBuf, slog.LevelWarn, true)
	defer logging.reset()

	app := newTestAppWithAdminToken(t)

	home := filepath.Join(app.Config.AllowedRoots[0], "home", "sessiondeleteuser")
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0755); err != nil {
		t.Fatal(err)
	}

	orig := OSUserLookup
	defer func() { OSUserLookup = orig }()
	OSUserLookup = func(username string) (uid, gid, homeDir string, err error) {
		return "1051", "1051", home, nil
	}

	username := "sessiondeleteuser"
	if _, err := createPrincipal(app.DB, username, app.Config.AllowedRoots); err != nil {
		t.Fatal(err)
	}

	// Create a credential and session for the principal.
	_, credToken, err := createCredential(app.DB, username, "laptop")
	if err != nil {
		t.Fatal(err)
	}

	sessMux := http.NewServeMux()
	sessMux.HandleFunc("POST /sessions", app.handleCreateSession)

	sessBody := map[string]string{"workspace": filepath.Join(home, "proj")}
	sessData, _ := json.Marshal(sessBody)
	sessReq := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(sessData))
	sessReq.Header.Set("Authorization", "Bearer "+credToken)
	sessW := httptest.NewRecorder()
	sessMux.ServeHTTP(sessW, sessReq)
	if sessW.Code != http.StatusCreated {
		t.Fatalf("create session: expected %d, got %d: %s", http.StatusCreated, sessW.Code, sessW.Body.String())
	}

	var sessResp createSessionResponse
	if err := json.NewDecoder(sessW.Body).Decode(&sessResp); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	sessionID := sessResp.Session.ID

	// Create the session runtime directory so cleanup has something to remove.
	sessRuntimeDir := sessionRuntimeDir(app.Config.RuntimeDir, sessionID)
	if err := os.MkdirAll(sessRuntimeDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Replace the sessions parent directory with a regular file so that
	// os.RemoveAll fails with ENOTDIR.
	sessionsParentDir := filepath.Dir(sessRuntimeDir)
	if err := os.RemoveAll(sessionsParentDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sessionsParentDir, nil, 0644); err != nil {
		t.Fatal(err)
	}

	// Delete the session using the principal's credential.
	delMux := http.NewServeMux()
	delMux.HandleFunc("DELETE /sessions/{id}", app.handleDeleteSession)

	delReq := httptest.NewRequest(http.MethodDelete, "/sessions/"+sessionID, nil)
	delReq.Header.Set("Authorization", "Bearer "+credToken)
	delW := httptest.NewRecorder()
	delMux.ServeHTTP(delW, delReq)

	if delW.Code != http.StatusNoContent {
		t.Fatalf("expected %d, got %d: %s", http.StatusNoContent, delW.Code, delW.Body.String())
	}

	// Parse operational JSON and find the cleanup log.
	opOutput := opBuf.String()
	foundCleanup := false
	for _, line := range strings.Split(strings.TrimSpace(opOutput), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		msg, _ := rec["msg"].(string)
		if msg != "cannot remove session runtime directory" {
			continue
		}
		foundCleanup = true

		// Assert operation == "session_delete".
		opField, ok := rec["operation"].(string)
		if !ok {
			t.Fatal("cleanup log missing operation field")
		}
		if opField != "session_delete" {
			t.Errorf("cleanup log operation = %q, want \"session_delete\"", opField)
		}

		// Assert session_id is non-empty and matches.
		sid, ok := rec["session_id"].(string)
		if !ok {
			t.Fatal("cleanup log missing session_id field")
		}
		if sid == "" {
			t.Error("cleanup log session_id is empty")
		}
		if sid != sessionID {
			t.Errorf("session_id = %q, want %q", sid, sessionID)
		}

		// Assert error is non-empty.
		errField, ok := rec["error"].(string)
		if !ok {
			t.Fatal("cleanup log missing error field")
		}
		if errField == "" {
			t.Error("cleanup log error is empty")
		}
	}
	if !foundCleanup {
		t.Fatalf("cleanup log not found in operational output:\n%s", opOutput)
	}
}

// --- Startup fallback timestamp ---

// TestStartupFallbackTimeFormat verifies that the fallback timestamp
// format preserves nanosecond precision (RFC3339Nano, not RFC3339).
func TestStartupFallbackTimeFormat(t *testing.T) {
	fixed := time.Date(2026, 8, 15, 12, 30, 45, 123456789, time.UTC)
	got := formatStartupFallbackTime(fixed)

	// RFC3339Nano preserves the nanosecond fraction.
	// RFC3339 would produce "2026-08-15T12:30:45Z" (no fraction).
	// RFC3339Nano produces "2026-08-15T12:30:45.123456789Z".
	if !strings.Contains(got, ".") {
		t.Fatalf("timestamp has no fractional seconds (RFC3339, not RFC3339Nano): %q", got)
	}
	if !strings.Contains(got, "123456789") {
		t.Fatalf("timestamp does not preserve nanoseconds: %q", got)
	}

	// Verify it parses as RFC3339Nano.
	parsed, err := time.Parse(time.RFC3339Nano, got)
	if err != nil {
		t.Fatalf("timestamp not valid RFC3339Nano: %v", err)
	}
	if parsed.Nanosecond() != 123456789 {
		t.Errorf("nanosecond = %d, want 123456789", parsed.Nanosecond())
	}
}

// TestStartupFallbackTimestampRFC3339Nano verifies that the emergency
// pre-logger JSON fallback uses RFC3339Nano timestamps.
func TestStartupFallbackTimestampRFC3339Nano(t *testing.T) {
	// Reset logging so snapshotLogger returns nil.
	logging.reset()

	stderrCapture := &bytes.Buffer{}
	oldStderr := osStderr
	osStderr = stderrCapture
	defer func() { osStderr = oldStderr }()

	serveStartupError(fmt.Errorf("test startup error"), "test hint")

	output := stderrCapture.String()
	if output == "" {
		t.Fatal("serveStartupError produced no output")
	}

	var rec map[string]any
	if err := json.Unmarshal([]byte(output), &rec); err != nil {
		t.Fatalf("fallback not valid JSON: %v: %s", err, output)
	}

	timeStr, ok := rec["time"].(string)
	if !ok {
		t.Fatal("fallback record missing time field")
	}

	// Verify it parses as RFC3339Nano.
	if _, err := time.Parse(time.RFC3339Nano, timeStr); err != nil {
		t.Fatalf("time not RFC3339Nano: %q: %v", timeStr, err)
	}

	// Verify the record contains the expected fields.
	if rec["stream"] != "operational" {
		t.Errorf("stream = %q, want \"operational\"", rec["stream"])
	}
	if rec["level"] != "ERROR" {
		t.Errorf("level = %q, want \"ERROR\"", rec["level"])
	}
	if rec["operation"] != "serve_startup" {
		t.Errorf("operation = %q, want \"serve_startup\"", rec["operation"])
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

// TestRunPinnedMountCleanupCorrelation verifies that when pinned mount cleanup
// fails during run completion, the operational log contains the correct
// correlation fields: operation=run, operation_id, session_id, error.
func TestRunPinnedMountCleanupCorrelation(t *testing.T) {
	mockDetectLSM(t, LSMAppArmor, nil)
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)
	initLoggers(opBuf, auditBuf, slog.LevelWarn, true)
	defer logging.reset()

	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()
	app.Config.Mode = ModeSystem

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	token := result.Token

	// Inject a pinned mount with a failing Cleanup.
	sentinelErr := errors.New("injected pinned mount cleanup error")
	app.PinWorkspaceMountSourceFn = func(workspace, sourcePath, runtimeDir, operationID string, mountIndex int) (*pinnedMount, error) {
		return &pinnedMount{
			PinnedPath: "/tmp/test-mount",
			cleanup: func() error {
				return sentinelErr
			},
		}, nil
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{"image":"alpine","mounts":[{"source":".","target":"/workspace"}]}`)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	// Wait for the operation to complete.
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found")
	}
	op.Wait()

	// Parse operational JSON and find the cleanup log.
	opOutput := opBuf.String()
	foundCleanup := false
	for _, line := range strings.Split(strings.TrimSpace(opOutput), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		msg, _ := rec["msg"].(string)
		if !strings.HasPrefix(msg, "pinned mount cleanup failed") {
			continue
		}
		foundCleanup = true

		// Assert operation == "run".
		opField, ok := rec["operation"].(string)
		if !ok {
			t.Fatal("cleanup log missing operation field")
		}
		if opField != "run" {
			t.Errorf("cleanup log operation = %q, want \"run\"", opField)
		}

		// Assert operation_id is non-empty and matches.
		opIDField, ok := rec["operation_id"].(string)
		if !ok {
			t.Fatal("cleanup log missing operation_id field")
		}
		if opIDField == "" {
			t.Error("cleanup log operation_id is empty")
		}
		if opIDField != opID {
			t.Errorf("operation_id = %q, want %q", opIDField, opID)
		}

		// Assert session_id is non-empty and matches.
		sid, ok := rec["session_id"].(string)
		if !ok {
			t.Fatal("cleanup log missing session_id field")
		}
		if sid == "" {
			t.Error("cleanup log session_id is empty")
		}
		if sid != result.Session.ID {
			t.Errorf("session_id = %q, want %q", sid, result.Session.ID)
		}

		// Assert the error contains our sentinel.
		errField, _ := rec["error"].(string)
		if !strings.Contains(errField, sentinelErr.Error()) {
			t.Errorf("cleanup log error = %q, expected to contain %q", errField, sentinelErr.Error())
		}
	}
	if !foundCleanup {
		t.Fatalf("cleanup log not found in operational output:\n%s", opOutput)
	}
}

// TestBuildStagingCleanupCorrelation verifies that when staging cleanup
// fails during build completion, the operational log contains the correct
// correlation fields: operation=build, operation_id, session_id, error.
func TestBuildStagingCleanupCorrelation(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)
	initLoggers(opBuf, auditBuf, slog.LevelWarn, true)
	defer logging.reset()

	app, _, result, token := setupBuildTest(t)

	// Inject a staging seam with a failing Cleanup.
	sentinelErr := errors.New("injected staging cleanup error")
	app.StageBuildContextFn = stagingSeamWithCleanupError(t, sentinelErr)

	// Create a real build context so staging succeeds.
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
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	// Wait for the operation to complete.
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, _ := resp["operation_id"].(string)
	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found")
	}
	op.Wait()

	// Parse operational JSON and find the cleanup log.
	opOutput := opBuf.String()
	foundCleanup := false
	for _, line := range strings.Split(strings.TrimSpace(opOutput), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		msg, _ := rec["msg"].(string)
		if !strings.HasPrefix(msg, "staging cleanup failed") {
			continue
		}
		foundCleanup = true

		// Assert operation == "build".
		opField, ok := rec["operation"].(string)
		if !ok {
			t.Fatal("cleanup log missing operation field")
		}
		if opField != "build" {
			t.Errorf("cleanup log operation = %q, want \"build\"", opField)
		}

		// Assert operation_id is non-empty and matches.
		opIDField, ok := rec["operation_id"].(string)
		if !ok {
			t.Fatal("cleanup log missing operation_id field")
		}
		if opIDField == "" {
			t.Error("cleanup log operation_id is empty")
		}
		if opIDField != opID {
			t.Errorf("operation_id = %q, want %q", opIDField, opID)
		}

		// Assert session_id is non-empty and matches.
		sid, ok := rec["session_id"].(string)
		if !ok {
			t.Fatal("cleanup log missing session_id field")
		}
		if sid == "" {
			t.Error("cleanup log session_id is empty")
		}
		if sid != result.Session.ID {
			t.Errorf("session_id = %q, want %q", sid, result.Session.ID)
		}

		// Assert the error contains our sentinel.
		errField, _ := rec["error"].(string)
		if !strings.Contains(errField, sentinelErr.Error()) {
			t.Errorf("cleanup log error = %q, expected to contain %q", errField, sentinelErr.Error())
		}
	}
	if !foundCleanup {
		t.Fatalf("cleanup log not found in operational output:\n%s", opOutput)
	}
}
