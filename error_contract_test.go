package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// ---------- invalid JSON ----------

// TestErrorContractInvalidJSON verifies that every JSON endpoint rejects a
// malformed body with the same contract: 400, ok=false, code
// "invalid_json", message "invalid JSON request".
func TestErrorContractInvalidJSON(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		admin   bool // use admin auth instead of the session token
		handler func(http.ResponseWriter, *http.Request)
	}{
		{name: "build", path: "/build", handler: app.handleBuild},
		{name: "pull", path: "/pull", handler: app.handlePull},
		{name: "run", path: "/run", handler: app.handleRun},
		{name: "sessions", path: "/sessions", admin: true, handler: app.handleCreateSession},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewReader([]byte(`{bad`)))
			if tt.admin {
				withAuth(req)
			} else {
				req.Header.Set("Authorization", "Bearer "+result.Token)
			}
			w := httptest.NewRecorder()
			tt.handler(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", w.Code)
			}

			var resp response
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.OK {
				t.Error("expected ok=false")
			}
			if resp.Code != "invalid_json" {
				t.Errorf("expected code 'invalid_json', got %q", resp.Code)
			}
			if resp.Message != "invalid JSON request" {
				t.Errorf("unexpected message: %q", resp.Message)
			}
		})
	}
}

// ---------- invalid image ----------

func TestErrorContractInvalidImage(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	for _, tt := range []struct {
		name    string
		path    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{name: "pull", path: "/pull", handler: app.handlePull},
		{name: "run", path: "/run", handler: app.handleRun},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reqBody, _ := json.Marshal(map[string]string{"image": ""})
			req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewReader(reqBody))
			req.Header.Set("Authorization", "Bearer "+result.Token)
			w := httptest.NewRecorder()
			tt.handler(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", w.Code)
			}

			var resp response
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.Code != "invalid_image" {
				t.Errorf("expected code 'invalid_image', got %q", resp.Code)
			}
			if resp.Message != "image is required" {
				t.Errorf("unexpected message: %q", resp.Message)
			}
		})
	}
}

// ---------- invalid environment ----------

func TestErrorContractInvalidEnvName(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	reqBody, _ := json.Marshal(map[string]any{
		"image":       "alpine:latest",
		"environment": map[string]string{"bad name!": "value"},
	})
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "invalid_environment" {
		t.Errorf("expected code 'invalid_environment', got %q", resp.Code)
	}
	if resp.Message != "invalid environment variable name" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
}

// ---------- build/mount errors do not leak paths ----------

func TestErrorContractBuildErrorNoPathLeak(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	reqBody, _ := json.Marshal(map[string]any{
		"context":    "nonexistent-dir-xyz",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	})
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "invalid_build_context" {
		t.Errorf("expected code 'invalid_build_context', got %q", resp.Code)
	}
	if resp.Message != "invalid build context" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
}

func TestErrorContractMountErrorNoPathLeak(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	reqBody, _ := json.Marshal(map[string]any{
		"image": "alpine:latest",
		"mounts": []map[string]any{
			{"source": "does-not-exist-xyz", "target": "/data"},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "invalid_mount" {
		t.Errorf("expected code 'invalid_mount', got %q", resp.Code)
	}
	if resp.Message != "invalid mount" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
}

// ---------- session creation errors ----------

func TestErrorContractInvalidWorkspace(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)

	reqBody, _ := json.Marshal(map[string]string{"workspace": "/nonexistent-path-xyz"})
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "invalid_workspace" {
		t.Errorf("expected code 'invalid_workspace', got %q", resp.Code)
	}
	if resp.Message != "invalid workspace" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
}

func TestErrorContractSessionCreateInternalError(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)

	// Replace DB with one that fails Exec.
	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailExecDB(t, dbPath, sql.ErrTxDone)
	defer app.DB.Close()

	reqBody, _ := json.Marshal(map[string]string{"workspace": testWorkspaceDir(t, app.Config.AllowedRoots[0])})
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(reqBody))
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "internal_error" {
		t.Errorf("expected code 'internal_error', got %q", resp.Code)
	}
	if resp.Message != "internal server error" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
}

// ---------- list/delete session errors ----------

func TestErrorContractListSessionsInternalError(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)

	// Close DB so query fails.
	app.DB.Close()

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleListSessions(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "internal_error" {
		t.Errorf("expected code 'internal_error', got %q", resp.Code)
	}
	if resp.Message != "internal server error" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
}

func TestErrorContractDeleteSessionNotFound(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /sessions/{id}", withRequestID(withLogging(app.handleDeleteSession)))

	req := httptest.NewRequest(http.MethodDelete, "/sessions/dhs_nonexistent", nil)
	withAuth(req)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "session_not_found" {
		t.Errorf("expected code 'session_not_found', got %q", resp.Code)
	}
	if resp.Message != "session not found" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
}

func TestErrorContractDeleteSessionInternalError(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Replace DB with one that fails Exec.
	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailExecDB(t, dbPath, sql.ErrTxDone)
	defer app.DB.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /sessions/{id}", withRequestID(withLogging(app.handleDeleteSession)))

	req := httptest.NewRequest(http.MethodDelete, "/sessions/"+result.Session.ID, nil)
	withAuth(req)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "internal_error" {
		t.Errorf("expected code 'internal_error', got %q", resp.Code)
	}
	if resp.Message != "internal server error" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
}

// ---------- requireSessionCapability DB error ----------

func TestErrorContractRequireSessionDBError(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Replace DB with one that fails Query.
	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailQueryDB(t, dbPath, sql.ErrTxDone)
	defer app.DB.Close()

	reqBody, _ := json.Marshal(map[string]string{"image": "alpine:latest"})
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "internal_error" {
		t.Errorf("expected code 'internal_error', got %q", resp.Code)
	}
}

func TestErrorContractRequireSessionNotFoundStill401(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)

	reqBody, _ := json.Marshal(map[string]string{"image": "alpine:latest"})
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer dht_nonexistent_token")
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "unauthorized" {
		t.Errorf("expected code 'unauthorized', got %q", resp.Code)
	}
}

// ---------- container_exit_nonzero unchanged ----------

func TestErrorContractContainerExitNonzeroUnchanged(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()
	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%s' 'container output\\n'; exit 7")
	}

	reqBody, _ := json.Marshal(map[string]string{"image": "alpine:latest"})
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}

	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found in registry")
	}
	op.Wait()

	if op.State != operationFailed {
		t.Errorf("expected status 'failed', got %q", op.State)
	}
	if op.ResultCode == nil || *op.ResultCode != "container_exit_nonzero" {
		t.Errorf("expected result_code 'container_exit_nonzero', got %v", op.ResultCode)
	}
	if op.ExitCode == nil || *op.ExitCode != 7 {
		t.Errorf("expected exit_code 7, got %v", op.ExitCode)
	}

	// Check logs contain output.
	logsReq := httptest.NewRequest(http.MethodGet, "/operations/"+opID+"/logs", nil)
	logsReq.Header.Set("Authorization", "Bearer "+result.Token)
	logsW := httptest.NewRecorder()
	newOperationMux(app).ServeHTTP(logsW, logsReq)

	if logsW.Code != http.StatusOK {
		t.Fatalf("expected 200 from operation logs, got %d", logsW.Code)
	}

	var logsResp map[string]any
	if err := json.NewDecoder(logsW.Body).Decode(&logsResp); err != nil {
		t.Fatalf("decode operation logs: %v", err)
	}
	logs, _ := logsResp["logs"].(string)
	if !strings.Contains(logs, "container output") {
		t.Errorf("expected output in logs, got %q", logs)
	}
}

// ---------- all ok:false responses have non-empty code ----------

func TestErrorContractAllFalseResponsesHaveCode(t *testing.T) {
	app := newTestAppWithAuthAndStaging(t)
	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	tests := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		req     *http.Request
	}{
		{
			name:    "invalid_json_run",
			handler: func(w http.ResponseWriter, r *http.Request) { app.handleRun(w, r) },
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{bad`)))
				r.Header.Set("Authorization", "Bearer "+result.Token)
				return r
			}(),
		},
		{
			name:    "invalid_json_build",
			handler: func(w http.ResponseWriter, r *http.Request) { app.handleBuild(w, r) },
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader([]byte(`{bad`)))
				r.Header.Set("Authorization", "Bearer "+result.Token)
				return r
			}(),
		},
		{
			name:    "invalid_json_pull",
			handler: func(w http.ResponseWriter, r *http.Request) { app.handlePull(w, r) },
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader([]byte(`{bad`)))
				r.Header.Set("Authorization", "Bearer "+result.Token)
				return r
			}(),
		},
		{
			name:    "invalid_json_sessions",
			handler: func(w http.ResponseWriter, r *http.Request) { app.handleCreateSession(w, r) },
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(`{bad`)))
				withAuth(r)
				return r
			}(),
		},
		{
			name:    "invalid_environment",
			handler: func(w http.ResponseWriter, r *http.Request) { app.handleRun(w, r) },
			req: func() *http.Request {
				b, _ := json.Marshal(map[string]any{
					"image":       "alpine:latest",
					"environment": map[string]string{"bad!": "v"},
				})
				r := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(b))
				r.Header.Set("Authorization", "Bearer "+result.Token)
				return r
			}(),
		},
		{
			name:    "invalid_mount",
			handler: func(w http.ResponseWriter, r *http.Request) { app.handleRun(w, r) },
			req: func() *http.Request {
				b, _ := json.Marshal(map[string]any{
					"image":  "alpine:latest",
					"mounts": []map[string]any{{"source": "", "target": "/x"}},
				})
				r := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(b))
				r.Header.Set("Authorization", "Bearer "+result.Token)
				return r
			}(),
		},
		{
			name:    "invalid_build_context",
			handler: func(w http.ResponseWriter, r *http.Request) { app.handleBuild(w, r) },
			req: func() *http.Request {
				b, _ := json.Marshal(map[string]any{
					"context":    "",
					"dockerfile": "Dockerfile",
					"image":      "example:test",
				})
				r := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(b))
				r.Header.Set("Authorization", "Bearer "+result.Token)
				return r
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tt.handler(w, tt.req)

			var resp response
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.OK {
				t.Fatalf("expected ok=false, got ok=true, status=%d", w.Code)
			}
			if resp.Code == "" {
				t.Errorf("ok=false response has empty code, status=%d", w.Code)
			}
		})
	}
}

// ---------- docker failure: error contract + no log leakage ----------

// TestDockerErrorLogBuild verifies the failed-build contract end to end:
// the operation fails with result_code "docker_build_failed", the build
// output is preserved in operation logs, and neither the Docker output nor
// the session token leaks into the operational log.
func TestDockerErrorLogBuild(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer logging.reset()

	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()
	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dfPath := result.Session.Workspace + "/Dockerfile"
	if err := os.WriteFile(dfPath, []byte("FROM scratch"), 0644); err != nil {
		t.Fatalf("cannot write Dockerfile: %v", err)
	}

	const dockerOutput = "build-output-secret-xyz"
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%s' '"+dockerOutput+"\\n'; exit 1")
	}

	reqBody, _ := json.Marshal(map[string]any{
		"context":    ".",
		"dockerfile": "Dockerfile",
		"image":      "example:test",
	})
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	// Extract operation_id from response.
	var createResp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, ok := createResp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatalf("expected operation_id in response")
	}

	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatalf("operation %s not found in registry", opID)
	}
	op.Wait()

	// Check operation status for failure.
	opReq := httptest.NewRequest(http.MethodGet, "/operations/"+opID, nil)
	opReq.Header.Set("Authorization", "Bearer "+result.Token)
	opW := httptest.NewRecorder()
	newOperationMux(app).ServeHTTP(opW, opReq)

	if opW.Code != http.StatusOK {
		t.Fatalf("expected 200 from operation status, got %d, body: %s", opW.Code, opW.Body.String())
	}

	var opResp map[string]any
	if err := json.NewDecoder(opW.Body).Decode(&opResp); err != nil {
		t.Fatalf("decode operation status: %v", err)
	}
	if opResp["status"] != "failed" {
		t.Errorf("expected status 'failed', got %v", opResp["status"])
	}
	if opResp["result_code"] != "docker_build_failed" {
		t.Errorf("expected result_code 'docker_build_failed', got %v", opResp["result_code"])
	}
	if exitCode, ok := opResp["exit_code"].(float64); !ok || exitCode != 1 {
		t.Errorf("expected exit_code 1, got %v", opResp["exit_code"])
	}

	// Check logs contain build output.
	logsReq := httptest.NewRequest(http.MethodGet, "/operations/"+opID+"/logs", nil)
	logsReq.Header.Set("Authorization", "Bearer "+result.Token)
	logsW := httptest.NewRecorder()
	newOperationMux(app).ServeHTTP(logsW, logsReq)

	if logsW.Code != http.StatusOK {
		t.Fatalf("expected 200 from operation logs, got %d", logsW.Code)
	}

	var logsResp map[string]any
	if err := json.NewDecoder(logsW.Body).Decode(&logsResp); err != nil {
		t.Fatalf("decode operation logs: %v", err)
	}
	logs, _ := logsResp["logs"].(string)
	if !strings.Contains(logs, dockerOutput) {
		t.Errorf("expected build output in operation logs, got %q", logs)
	}

	// Verify docker output is NOT in the operational log.
	raw := opBuf.String()
	if strings.Contains(raw, dockerOutput) {
		t.Error("Docker output must not appear in operational log")
	}
	if strings.Contains(raw, result.Token) {
		t.Error("session token must not appear in log")
	}
}

func TestDockerErrorLogPull(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer logging.reset()

	app := newTestAppWithAuthAndStaging(t)
	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const dockerOutput = "pull-output-secret-xyz"
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "echo '"+dockerOutput+"'; exit 1")
	}

	reqBody, _ := json.Marshal(map[string]string{"image": "alpine:latest"})
	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	// Client response — prove we reached the error path before checking logs.
	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
	if resp.Code != "docker_pull_failed" {
		t.Fatalf("expected code 'docker_pull_failed', got %q", resp.Code)
	}
	if resp.Message != "docker pull failed" {
		t.Fatalf("unexpected message: %q", resp.Message)
	}
	if resp.Output != dockerOutput+"\n" {
		t.Fatalf("expected output preserved, got %q", resp.Output)
	}

	raw := opBuf.String()

	// Non-zero exit is a workload result, not an operational error.
	// No ERROR should be logged for non-zero exit.
	if strings.Contains(raw, "ERROR") {
		t.Errorf("pull non-zero exit must not produce operational ERROR, got:\n%s", raw)
	}
	// Docker output not logged
	if strings.Contains(raw, dockerOutput) {
		t.Error("Docker output must not appear in log")
	}
	// Token not logged
	if strings.Contains(raw, result.Token) {
		t.Error("session token must not appear in log")
	}
}

func TestDockerErrorLogRun(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer logging.reset()

	app := newTestAppWithAuthAndStaging(t)
	app.OperationRegistry = newOperationRegistry()
	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const dockerOutput = "run-output-secret-xyz"
	const envValue = "env-secret-value-abc"
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%s' '"+dockerOutput+"\\n'; exit 125")
	}

	reqBody, _ := json.Marshal(map[string]any{
		"image":       "alpine:latest",
		"environment": map[string]string{"SECRET_KEY": envValue},
	})
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}

	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatal("operation not found in registry")
	}
	op.Wait()

	if op.State != operationFailed {
		t.Errorf("expected status 'failed', got %q", op.State)
	}

	// Check operation status for failure.
	opReq := httptest.NewRequest(http.MethodGet, "/operations/"+opID, nil)
	opReq.Header.Set("Authorization", "Bearer "+result.Token)
	opW := httptest.NewRecorder()
	newOperationMux(app).ServeHTTP(opW, opReq)

	if opW.Code != http.StatusOK {
		t.Fatalf("expected 200 from operation status, got %d", opW.Code)
	}

	var opResp map[string]any
	if err := json.NewDecoder(opW.Body).Decode(&opResp); err != nil {
		t.Fatalf("decode operation status: %v", err)
	}
	if opResp["result_code"] != "docker_run_failed" {
		t.Errorf("expected result_code 'docker_run_failed', got %v", opResp["result_code"])
	}

	// Check logs contain run output.
	logsReq := httptest.NewRequest(http.MethodGet, "/operations/"+opID+"/logs", nil)
	logsReq.Header.Set("Authorization", "Bearer "+result.Token)
	logsW := httptest.NewRecorder()
	newOperationMux(app).ServeHTTP(logsW, logsReq)

	if logsW.Code != http.StatusOK {
		t.Fatalf("expected 200 from operation logs, got %d", logsW.Code)
	}

	var logsResp map[string]any
	if err := json.NewDecoder(logsW.Body).Decode(&logsResp); err != nil {
		t.Fatalf("decode operation logs: %v", err)
	}
	logs, _ := logsResp["logs"].(string)
	if !strings.Contains(logs, dockerOutput) {
		t.Errorf("expected run output in operation logs, got %q", logs)
	}

	// Verify docker output is NOT in the operational log.
	raw := opBuf.String()
	if strings.Contains(raw, dockerOutput) {
		t.Error("Docker output must not appear in operational log")
	}
	if strings.Contains(raw, result.Token) {
		t.Error("session token must not appear in log")
	}
	// Environment value not logged
	if strings.Contains(raw, envValue) {
		t.Error("environment value must not appear in log")
	}
}

// ---------- image reference grammar ----------

// TestImageReferenceNotRejectedByHelper verifies that valid Docker image
// reference grammars pass through helper validation and reach the docker CLI
// unchanged. The Docker CLI is mocked to avoid requiring a real daemon.
func TestImageReferenceNotRejectedByHelper(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer logging.reset()

	app := newTestAppWithAuthAndStaging(t)
	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	for _, image := range []string{
		"registry.example.com:5000/team/image:tag", // registry with explicit port
		"alpine@sha256:abc123def456",               // digest reference
		"alpine",                                   // untagged reference
		"localhost:5000/image:tag",                 // localhost with port
	} {
		t.Run(image, func(t *testing.T) {
			reqBody, _ := json.Marshal(map[string]string{"image": image})
			req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(reqBody))
			req.Header.Set("Authorization", "Bearer "+result.Token)

			app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
				if name != "docker" {
					t.Fatalf("unexpected command: %s", name)
				}
				for _, arg := range args {
					if arg == image {
						return exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%s' 'Pulled "+image+"\\n'")
					}
				}
				t.Fatalf("image argument not found in args: %v", args)
				return exec.CommandContext(ctx, "true")
			}

			w := httptest.NewRecorder()
			app.handlePull(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
			}
		})
	}
}
