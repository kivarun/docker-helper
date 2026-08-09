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

func TestErrorContractInvalidJSON_Build(t *testing.T) {
	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader([]byte(`{bad`)))
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
	if resp.OK {
		t.Error("expected ok=false")
	}
	if resp.Code != "invalid_json" {
		t.Errorf("expected code 'invalid_json', got %q", resp.Code)
	}
	if resp.Message != "invalid JSON request" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
}

func TestErrorContractInvalidJSON_Pull(t *testing.T) {
	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader([]byte(`{bad`)))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "invalid_json" {
		t.Errorf("expected code 'invalid_json', got %q", resp.Code)
	}
}

func TestErrorContractInvalidJSON_Run(t *testing.T) {
	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader([]byte(`{bad`)))
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
	if resp.Code != "invalid_json" {
		t.Errorf("expected code 'invalid_json', got %q", resp.Code)
	}
}

func TestErrorContractInvalidJSON_Sessions(t *testing.T) {
	app := newTestAppWithAuth(t)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(`{bad`)))
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
	if resp.Code != "invalid_json" {
		t.Errorf("expected code 'invalid_json', got %q", resp.Code)
	}
}

// ---------- invalid image ----------

func TestErrorContractInvalidImage_PullEmpty(t *testing.T) {
	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	reqBody, _ := json.Marshal(map[string]string{"image": ""})
	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

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
}

func TestErrorContractInvalidImage_RunEmpty(t *testing.T) {
	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	reqBody, _ := json.Marshal(map[string]string{"image": ""})
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
	if resp.Code != "invalid_image" {
		t.Errorf("expected code 'invalid_image', got %q", resp.Code)
	}
}

// ---------- invalid environment ----------

func TestErrorContractInvalidEnvName(t *testing.T) {
	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
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
	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
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
	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
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

// ---------- docker errors ----------

func TestErrorContractDockerBuildFailed(t *testing.T) {
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dfPath := app.Config.AllowedRoot + "/Dockerfile"
	if err := os.WriteFile(dfPath, []byte("FROM scratch"), 0644); err != nil {
		t.Fatalf("cannot write Dockerfile: %v", err)
	}
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%s' 'build output here\\n'; exit 1")
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
	opReq.SetPathValue("id", opID)
	opReq.Header.Set("Authorization", "Bearer "+result.Token)
	opW := httptest.NewRecorder()
	app.handleOperationStatus(opW, opReq)

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
	logsReq.SetPathValue("id", opID)
	logsReq.Header.Set("Authorization", "Bearer "+result.Token)
	logsW := httptest.NewRecorder()
	app.handleOperationLogs(logsW, logsReq)

	if logsW.Code != http.StatusOK {
		t.Fatalf("expected 200 from operation logs, got %d", logsW.Code)
	}

	var logsResp map[string]any
	if err := json.NewDecoder(logsW.Body).Decode(&logsResp); err != nil {
		t.Fatalf("decode operation logs: %v", err)
	}
	logs, _ := logsResp["logs"].(string)
	if !strings.Contains(logs, "build output here") {
		t.Errorf("expected build output in logs, got %q", logs)
	}
}

func TestErrorContractDockerPullFailed(t *testing.T) {
	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("pull error output\n"), &mockExitError{code: 1, msg: "exit status 1"}
	}

	reqBody, _ := json.Marshal(map[string]string{"image": "alpine:latest"})
	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "docker_pull_failed" {
		t.Errorf("expected code 'docker_pull_failed', got %q", resp.Code)
	}
	if resp.Message != "docker pull failed" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
	if resp.Output != "pull error output\n" {
		t.Errorf("expected output preserved, got %q", resp.Output)
	}
}

func TestErrorContractDockerRunFailed(t *testing.T) {
	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("run error output\n"), &mockExitError{code: 125, msg: "exit status 125"}
	}

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
	if resp.Code != "docker_run_failed" {
		t.Errorf("expected code 'docker_run_failed', got %q", resp.Code)
	}
	if resp.Message != "docker run failed" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
	if resp.Output != "run error output\n" {
		t.Errorf("expected output preserved, got %q", resp.Output)
	}
}

// ---------- session creation errors ----------

func TestErrorContractInvalidWorkspace(t *testing.T) {
	app := newTestAppWithAuth(t)

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
	app := newTestAppWithAuth(t)

	// Replace DB with one that fails Exec.
	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailExecDB(t, dbPath, sql.ErrTxDone)
	defer app.DB.Close()

	reqBody, _ := json.Marshal(map[string]string{"workspace": app.Config.AllowedRoot})
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
	app := newTestAppWithAuth(t)

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
	app := newTestAppWithAuth(t)

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
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
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

// ---------- requireSession DB error ----------

func TestErrorContractRequireSessionDBError(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
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
	app := newTestAppWithAuth(t)

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
	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("container output\n"), &mockExitError{code: 7, msg: "exit status 7"}
	}

	reqBody, _ := json.Marshal(map[string]string{"image": "alpine:latest"})
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.OK {
		t.Error("expected ok=false")
	}
	if resp.Code != "container_exit_nonzero" {
		t.Errorf("expected code 'container_exit_nonzero', got %q", resp.Code)
	}
	if resp.Message != "container exited with non-zero status" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
	if resp.Output != "container output\n" {
		t.Errorf("expected output preserved, got %q", resp.Output)
	}
	if resp.ExitCode == nil || *resp.ExitCode != 7 {
		t.Errorf("expected exit_code 7, got %v", resp.ExitCode)
	}
}

// ---------- all ok:false responses have non-empty code ----------

func TestErrorContractAllFalseResponsesHaveCode(t *testing.T) {
	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
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

// ---------- Docker error logging ----------

func TestImageReferenceNotRejectedByHelper_RegistryPort(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer logging.reset()

	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// This image reference should pass through helper validation.
	// Docker CLI is mocked to avoid requiring a real daemon.
	reqBody, _ := json.Marshal(map[string]string{"image": "registry.example.com:5000/team/image:tag"})
	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)

	var stdout bytes.Buffer
	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		if name != "docker" {
			t.Fatalf("unexpected command: %s", name)
		}
		// Verify the image argument is passed through unchanged.
		for i, arg := range args {
			if arg == "registry.example.com:5000/team/image:tag" {
				stdout.WriteString("Pulled registry.example.com:5000/team/image:tag\n")
				return stdout.Bytes(), nil
			}
			if i == 0 && arg == "pull" {
				continue
			}
		}
		t.Fatalf("image argument not found in args: %v", args)
		return nil, nil
	}

	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestImageReferenceNotRejectedByHelper_Digest(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer logging.reset()

	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Digest references should pass through helper validation.
	reqBody, _ := json.Marshal(map[string]string{"image": "alpine@sha256:abc123def456"})
	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)

	var stdout bytes.Buffer
	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		if name != "docker" {
			t.Fatalf("unexpected command: %s", name)
		}
		for i, arg := range args {
			if arg == "alpine@sha256:abc123def456" {
				stdout.WriteString("Pulled alpine@sha256:abc123def456\n")
				return stdout.Bytes(), nil
			}
			if i == 0 && arg == "pull" {
				continue
			}
		}
		t.Fatalf("image argument not found in args: %v", args)
		return nil, nil
	}

	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestImageReferenceNotRejectedByHelper_Untagged(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer logging.reset()

	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Untagged references should pass through helper validation.
	reqBody, _ := json.Marshal(map[string]string{"image": "alpine"})
	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)

	var stdout bytes.Buffer
	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		if name != "docker" {
			t.Fatalf("unexpected command: %s", name)
		}
		for i, arg := range args {
			if arg == "alpine" {
				stdout.WriteString("Pulled alpine\n")
				return stdout.Bytes(), nil
			}
			if i == 0 && arg == "pull" {
				continue
			}
		}
		t.Fatalf("image argument not found in args: %v", args)
		return nil, nil
	}

	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestImageReferenceNotRejectedByHelper_LocalhostPort(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer logging.reset()

	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	// Localhost with port should pass through helper validation.
	reqBody, _ := json.Marshal(map[string]string{"image": "localhost:5000/image:tag"})
	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)

	var stdout bytes.Buffer
	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		if name != "docker" {
			t.Fatalf("unexpected command: %s", name)
		}
		for i, arg := range args {
			if arg == "localhost:5000/image:tag" {
				stdout.WriteString("Pulled localhost:5000/image:tag\n")
				return stdout.Bytes(), nil
			}
			if i == 0 && arg == "pull" {
				continue
			}
		}
		t.Fatalf("image argument not found in args: %v", args)
		return nil, nil
	}

	w := httptest.NewRecorder()
	app.handlePull(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestDockerErrorLogBuild(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer logging.reset()

	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dfPath := app.Config.AllowedRoot + "/Dockerfile"
	if err := os.WriteFile(dfPath, []byte("FROM scratch"), 0644); err != nil {
		t.Fatalf("cannot write Dockerfile: %v", err)
	}

	const errMarker = "test_build_error_marker_abc123"
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
	opReq.SetPathValue("id", opID)
	opReq.Header.Set("Authorization", "Bearer "+result.Token)
	opW := httptest.NewRecorder()
	app.handleOperationStatus(opW, opReq)

	if opW.Code != http.StatusOK {
		t.Fatalf("expected 200 from operation status, got %d", opW.Code)
	}

	var opResp map[string]any
	if err := json.NewDecoder(opW.Body).Decode(&opResp); err != nil {
		t.Fatalf("decode operation status: %v", err)
	}
	if opResp["result_code"] != "docker_build_failed" {
		t.Errorf("expected result_code 'docker_build_failed', got %v", opResp["result_code"])
	}

	// Check logs contain build output.
	logsReq := httptest.NewRequest(http.MethodGet, "/operations/"+opID+"/logs", nil)
	logsReq.SetPathValue("id", opID)
	logsReq.Header.Set("Authorization", "Bearer "+result.Token)
	logsW := httptest.NewRecorder()
	app.handleOperationLogs(logsW, logsReq)

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

	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const errMarker = "test_pull_error_marker_def456"
	const dockerOutput = "pull-output-secret-xyz"
	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(dockerOutput + "\n"), &mockExitError{code: 1, msg: errMarker}
	}

	reqBody, _ := json.Marshal(map[string]string{"image": "alpine:latest"})
	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handlePull(w, req)

	raw := opBuf.String()

	// Error marker is logged
	if !strings.Contains(raw, errMarker) {
		t.Errorf("expected error marker %q in log, got:\n%s", errMarker, raw)
	}
	// Docker output not logged
	if strings.Contains(raw, dockerOutput) {
		t.Error("Docker output must not appear in log")
	}
	// Token not logged
	if strings.Contains(raw, result.Token) {
		t.Error("session token must not appear in log")
	}

	// Client response
	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.Code)
	}
	if resp.Code != "docker_pull_failed" {
		t.Errorf("expected code 'docker_pull_failed', got %q", resp.Code)
	}
	if resp.Message != "docker pull failed" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
	if resp.Output != dockerOutput+"\n" {
		t.Errorf("expected output preserved, got %q", resp.Output)
	}
}

func TestDockerErrorLogRun(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer logging.reset()

	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const errMarker = "test_run_error_marker_ghi789"
	const dockerOutput = "run-output-secret-xyz"
	const envValue = "env-secret-value-abc"
	app.ExecCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(dockerOutput + "\n"), &mockExitError{code: 125, msg: errMarker}
	}

	reqBody, _ := json.Marshal(map[string]any{
		"image":       "alpine:latest",
		"environment": map[string]string{"SECRET_KEY": envValue},
	})
	req := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	raw := opBuf.String()

	// Error marker is logged
	if !strings.Contains(raw, errMarker) {
		t.Errorf("expected error marker %q in log, got:\n%s", errMarker, raw)
	}
	// Docker output not logged
	if strings.Contains(raw, dockerOutput) {
		t.Error("Docker output must not appear in log")
	}
	// Token not logged
	if strings.Contains(raw, result.Token) {
		t.Error("session token must not appear in log")
	}
	// Environment value not logged
	if strings.Contains(raw, envValue) {
		t.Error("environment value must not appear in log")
	}

	// Client response
	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.Code)
	}
	if resp.Code != "docker_run_failed" {
		t.Errorf("expected code 'docker_run_failed', got %q", resp.Code)
	}
	if resp.Message != "docker run failed" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
	if resp.Output != dockerOutput+"\n" {
		t.Errorf("expected output preserved, got %q", resp.Output)
	}
}
