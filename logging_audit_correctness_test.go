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
	app := newTestAppWithAuth(t)

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
	withAuth(req)
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
	app := newTestAppWithAuth(t)

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
	app := newTestAppWithAuth(t)

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
	app := newTestAppWithAuth(t)

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
	app := newTestAppWithAuth(t)

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
