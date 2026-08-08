package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestErrorContractInvalidImage_PullBadFormat(t *testing.T) {
	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	reqBody, _ := json.Marshal(map[string]string{"image": "bad image!"})
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
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dfPath := app.Config.AllowedRoot + "/Dockerfile"
	if err := os.WriteFile(dfPath, []byte("FROM scratch"), 0644); err != nil {
		t.Fatalf("cannot write Dockerfile: %v", err)
	}

	app.BuildCommand = func(name string, args ...string) ([]byte, error) {
		return []byte("build output here\n"), &mockExitError{code: 1, msg: "exit status 1"}
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

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Code != "docker_build_failed" {
		t.Errorf("expected code 'docker_build_failed', got %q", resp.Code)
	}
	if resp.Message != "docker build failed" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
	if resp.Output != "build output here\n" {
		t.Errorf("expected output preserved, got %q", resp.Output)
	}
}

func TestErrorContractDockerPullFailed(t *testing.T) {
	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	app.PullCommand = func(name string, args ...string) ([]byte, error) {
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

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
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

	req := httptest.NewRequest(http.MethodDelete, "/sessions/dhs_nonexistent", nil)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleDeleteSession(w, req)

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

	req := httptest.NewRequest(http.MethodDelete, "/sessions/"+result.Session.ID, nil)
	withAuth(req)
	w := httptest.NewRecorder()
	app.handleDeleteSession(w, req)

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

	app.RunCommand = func(name string, args ...string) ([]byte, error) {
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
			name:    "invalid_image_run",
			handler: func(w http.ResponseWriter, r *http.Request) { app.handleRun(w, r) },
			req: func() *http.Request {
				b, _ := json.Marshal(map[string]string{"image": ""})
				r := httptest.NewRequest(http.MethodPost, "/run", bytes.NewReader(b))
				r.Header.Set("Authorization", "Bearer "+result.Token)
				return r
			}(),
		},
		{
			name:    "invalid_image_pull",
			handler: func(w http.ResponseWriter, r *http.Request) { app.handlePull(w, r) },
			req: func() *http.Request {
				b, _ := json.Marshal(map[string]string{"image": ""})
				r := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(b))
				r.Header.Set("Authorization", "Bearer "+result.Token)
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

func TestDockerErrorLogBuild(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer func() {
		opLogger = nil
		auditWriter = nil
	}()

	app := newTestAppWithAuth(t)
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
	app.BuildCommand = func(name string, args ...string) ([]byte, error) {
		return []byte(dockerOutput + "\n"), &mockExitError{code: 1, msg: errMarker}
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
	if resp.Code != "docker_build_failed" {
		t.Errorf("expected code 'docker_build_failed', got %q", resp.Code)
	}
	if resp.Message != "docker build failed" {
		t.Errorf("unexpected message: %q", resp.Message)
	}
	if resp.Output != dockerOutput+"\n" {
		t.Errorf("expected output preserved, got %q", resp.Output)
	}
}

func TestDockerErrorLogPull(t *testing.T) {
	auditBuf := new(bytes.Buffer)
	opBuf := new(bytes.Buffer)

	initLoggers(opBuf, auditBuf, slog.LevelError, true)
	defer func() {
		opLogger = nil
		auditWriter = nil
	}()

	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const errMarker = "test_pull_error_marker_def456"
	const dockerOutput = "pull-output-secret-xyz"
	app.PullCommand = func(name string, args ...string) ([]byte, error) {
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
	defer func() {
		opLogger = nil
		auditWriter = nil
	}()

	app := newTestAppWithAuth(t)
	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	const errMarker = "test_run_error_marker_ghi789"
	const dockerOutput = "run-output-secret-xyz"
	const envValue = "env-secret-value-abc"
	app.RunCommand = func(name string, args ...string) ([]byte, error) {
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
