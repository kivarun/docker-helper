package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// ---------- invalid JSON ----------

// TestErrorContractInvalidJSON verifies that every JSON endpoint rejects a
// malformed body with the same contract: 400, ok=false, code
// "invalid_json", message "invalid JSON request".
func TestErrorContractInvalidJSON(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
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
				withAdminToken(req)
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
	app := newTestAppWithAdminTokenAndStaging(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
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
	app := newTestAppWithAdminTokenAndStaging(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
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
	app := newTestAppWithAdminTokenAndStaging(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
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
	app := newTestAppWithAdminTokenAndStaging(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
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
	app := newTestAppWithAdminTokenAndStaging(t)

	reqBody, _ := json.Marshal(map[string]string{"principal": testOwnerUsername, "workspace": "/nonexistent-path-xyz"})
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(reqBody))
	withAdminToken(req)
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
	// The client must receive an actionable cause, not the generic fallback,
	// so the user can tell a missing workspace from other validation failures.
	if resp.Message == "invalid workspace" {
		t.Errorf("expected an actionable workspace message, got generic %q", resp.Message)
	}
	if resp.Message == "" {
		t.Error("expected non-empty workspace message")
	}
}

// TestErrorContractWorkspaceMessageDistinct verifies that distinct workspace
// failure causes yield distinct actionable messages (not a shared generic
// "invalid workspace"), proving the client can act on the actual problem.
func TestErrorContractWorkspaceMessageDistinct(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)

	root := app.Config.AllowedRoots[0].Path
	ws := testWorkspaceDir(t, root)
	filePath := filepath.Join(ws, "regular-file.txt")
	if err := os.WriteFile(filePath, []byte("x"), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	create := func(workspace string) string {
		t.Helper()
		reqBody, _ := json.Marshal(map[string]string{"principal": testOwnerUsername, "workspace": workspace})
		req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(reqBody))
		withAdminToken(req)
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
			t.Fatalf("expected code 'invalid_workspace', got %q", resp.Code)
		}
		return resp.Message
	}

	// A regular file is not a directory.
	fileMsg := create(filePath)
	if !strings.Contains(fileMsg, "not a directory") {
		t.Errorf("expected not-a-directory cause, got %q", fileMsg)
	}

	// An existing directory outside the allowed root.
	outside := filepath.Join(filepath.Dir(root), "outside-dir")
	if err := os.MkdirAll(outside, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	outsideMsg := create(outside)
	if !strings.Contains(outsideMsg, "allowed root") {
		t.Errorf("expected allowed-root cause, got %q", outsideMsg)
	}

	if fileMsg == outsideMsg {
		t.Error("distinct causes must yield distinct messages")
	}
}

func TestErrorContractSessionCreateInternalError(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)

	// Replace DB with one that fails Exec.
	dbPath := app.Config.DatabasePath
	app.DB.Close()
	app.DB = newFailExecDB(t, dbPath, sql.ErrTxDone)
	defer app.DB.Close()

	reqBody, _ := json.Marshal(map[string]string{"principal": testOwnerUsername, "workspace": testWorkspaceDir(t, app.Config.AllowedRoots[0].Path)})
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(reqBody))
	withAdminToken(req)
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
	app := newTestAppWithAdminTokenAndStaging(t)

	// Close DB so query fails.
	app.DB.Close()

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	withAdminToken(req)
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
	app := newTestAppWithAdminTokenAndStaging(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /sessions/{id}", withRequestID(withLogging(app.handleDeleteSession)))

	req := httptest.NewRequest(http.MethodDelete, "/sessions/dhs_nonexistent", nil)
	withAdminToken(req)
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
	app := newTestAppWithAdminTokenAndStaging(t)

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
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
	withAdminToken(req)
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

// TestErrorContractSessionAuthorityDBErrorOneDocument pins the shared
// Session-filesystem-authority database-error contract for every data-plane
// handler that consumes it: exactly ONE HTTP status, exactly ONE JSON error
// document on the wire, and no trailing content after that document. The
// decoder reads the ENTIRE response body and requires io.EOF after the first
// JSON value — a second JSON object after the first is the duplicate-write
// regression and fails the test (the pre-fix /run and /build paths wrote the
// internal-error document twice).
func TestErrorContractSessionAuthorityDBErrorOneDocument(t *testing.T) {
	cases := []struct {
		kind   string
		method string
		path   string
		body   []byte
	}{
		{
			kind:   "run",
			method: http.MethodPost,
			path:   "/run",
			body:   []byte(`{"image":"alpine:latest"}`),
		},
		{
			kind:   "build",
			method: http.MethodPost,
			path:   "/build",
			body:   []byte(`{"image":"alpine:latest"}`),
		},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			app := newTestAppWithAdminTokenAndStaging(t)

			created, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
			if err != nil {
				t.Fatalf("createSession: %v", err)
			}

			// Replace the DB with one whose queries fail: the live-Session
			// lookup inside the transactional filesystem-authority capture
			// fails with a database error (never the non-disclosing
			// not-found), which routes the shared authority failure path.
			dbPath := app.Config.DatabasePath
			app.DB.Close()
			app.DB = newFailQueryDB(t, dbPath, sql.ErrTxDone)
			defer app.DB.Close()

			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer "+created.Token)
			w := httptest.NewRecorder()
			if tc.kind == "build" {
				app.handleBuild(w, req)
			} else {
				app.handleRun(w, req)
			}

			if w.Code != http.StatusInternalServerError {
				t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
			}

			// Exactly one JSON document, then EOF: read the ENTIRE body and
			// decode strictly. A second JSON value after the first (the
			// duplicate-write regression) fails here.
			dec := json.NewDecoder(bytes.NewReader(w.Body.Bytes()))
			var resp response
			if err := dec.Decode(&resp); err != nil {
				t.Fatalf("cannot decode the error document: %v (body: %q)", err, w.Body.String())
			}
			var trailing struct{}
			if err := dec.Decode(&trailing); err != nil {
				if err != io.EOF {
					t.Fatalf("trailing content after the error document is not valid JSON: %v (body: %q)", err, w.Body.String())
				}
			} else {
				t.Fatalf("a second JSON document follows the error document (duplicate write): body %q", w.Body.String())
			}

			if resp.OK {
				t.Errorf("ok = true, want false")
			}
			if resp.Code != "internal_error" {
				t.Errorf("code = %q, want %q", resp.Code, "internal_error")
			}
			if resp.Message != "internal server error" {
				t.Errorf("message = %q, want %q", resp.Message, "internal server error")
			}
		})
	}
}

func TestErrorContractRequireSessionNotFoundStill401(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)

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
	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
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

	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
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
	app := newTestAppWithAdminTokenAndStaging(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
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
				withAdminToken(r)
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

	app := newTestAppWithAdminTokenAndStaging(t)
	attachBackendFixture(t, app)
	app.OperationSupervisor = newOperationSupervisor()
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	dfPath := result.Session.Workspace + "/Dockerfile"
	if err := os.WriteFile(dfPath, []byte("FROM scratch"), 0644); err != nil {
		t.Fatalf("cannot write Dockerfile: %v", err)
	}

	const dockerOutput = "build-output-secret-xyz"
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		// The buildctl stage fails with captured live output; the
		// trusted-side children (STOP, load, tag, rmi) succeed.
		if strings.HasSuffix(name, "buildctl") {
			return exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%s' '"+dockerOutput+"\\n'; exit 1")
		}
		return exec.CommandContext(ctx, "/bin/true")
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

	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatalf("operation %s not found in supervisor", opID)
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

	app := newTestAppWithAdminTokenAndStaging(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
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

	app := newTestAppWithAdminTokenAndStaging(t)
	app.OperationSupervisor = newOperationSupervisor()
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
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

	op := app.OperationSupervisor.lookup(opID)
	if op == nil {
		t.Fatal("operation not found in supervisor")
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

	app := newTestAppWithAdminTokenAndStaging(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
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

// ---------- D2/D3/D4/D7 path-resolution diagnostics ----------

// postedRequestResult pairs the public body of a posted request with the
// HTTP status it was answered with, so the path-diagnostics regressions
// assert the full public contract — HTTP status plus JSON code/message —
// instead of the decoded body alone. A success body decodes into the
// embedded response with OK=true and empty code/message; the raw body is
// kept so a success control can prove the real creation contract.
type postedRequestResult struct {
	response
	status int
	raw    []byte
}

// decodePostedBody decodes a posted request's public body leniently: both a
// refusal envelope (ok=false with code/message) and a success body (ok=true;
// the embedded response simply ignores the success-only fields) decode.
func decodePostedBody(t *testing.T, body []byte) response {
	t.Helper()
	var resp response
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode posted response: %v (body=%s)", err, body)
	}
	return resp
}

// postSessionCreate posts a session-create body to the real production
// handler with an Admin authority and returns the HTTP status and decoded
// public body. Callers that need a Launcher selector include it in the body.
func postSessionCreate(t *testing.T, app *App, body string) postedRequestResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(body)))
	withAdminToken(req)
	w := httptest.NewRecorder()
	app.handleCreateSession(w, req)
	return postedRequestResult{
		response: decodePostedBody(t, w.Body.Bytes()),
		status:   w.Code,
		raw:      w.Body.Bytes(),
	}
}

// postBuild posts a build body to the real production handler and returns
// the HTTP status and decoded public body.
func postBuild(t *testing.T, app *App, token string, body string) postedRequestResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/build", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	app.handleBuild(w, req)
	return postedRequestResult{
		response: decodePostedBody(t, w.Body.Bytes()),
		status:   w.Code,
		raw:      w.Body.Bytes(),
	}
}

// requireRefused asserts the refusal half of the public contract: the HTTP
// status and the JSON code/message.
func requireRefused(t *testing.T, resp postedRequestResult, wantStatus int, wantCode string) {
	t.Helper()
	if resp.status != wantStatus {
		t.Errorf("expected HTTP %d, got %d", wantStatus, resp.status)
	}
	if resp.Code != wantCode {
		t.Errorf("expected code %q, got %q", wantCode, resp.Code)
	}
	if resp.OK {
		t.Error("expected ok=false for a refusal")
	}
}

// TestErrorContractBuildMissingField proves the malformed-request family of
// the build surface: a missing required field is the missing_field request
// error naming the field, not the invalid_build_context authorization/path
// contract; ordinary invalid context spellings keep invalid_build_context
// with its stable bounded message.
func TestErrorContractBuildMissingField(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0].Path))
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	for _, missing := range []string{"context", "dockerfile", "image"} {
		t.Run(missing, func(t *testing.T) {
			fields := map[string]string{"context": "buildctx", "dockerfile": "Dockerfile", "image": "example:test"}
			delete(fields, missing)
			body, _ := json.Marshal(fields)
			resp := postBuild(t, app, result.Token, string(body))

			requireRefused(t, resp, http.StatusBadRequest, "missing_field")
			if resp.Message != missing+" is required" {
				t.Errorf("expected message naming the missing field, got %q", resp.Message)
			}
		})
	}

	// Control: an ordinary invalid context spelling keeps the stable
	// invalid_build_context contract with its bounded message.
	resp := postBuild(t, app, result.Token,
		`{"context":"../outside","dockerfile":"Dockerfile","image":"example:test"}`)
	requireRefused(t, resp, http.StatusBadRequest, "invalid_build_context")
	if resp.Message != "invalid build context" {
		t.Errorf("expected the bounded build-context message, got %q", resp.Message)
	}
}

// TestErrorContractWorkspacePathDoesNotExist proves the missing-path
// diagnosis of an admitted workspace spelling: the public cause identifies
// the nonexistent path itself — not a symlink-resolution problem — while
// the code stays invalid_workspace; a valid workspace still creates.
func TestErrorContractWorkspacePathDoesNotExist(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	root := app.Config.AllowedRoots[0].Path
	ws := testWorkspaceDir(t, root)

	resp := postSessionCreate(t, app, `{"principal":"`+testOwnerUsername+`","workspace":"`+filepath.ToSlash(filepath.Join(ws, "does-not-exist"))+`"}`)
	requireRefused(t, resp, http.StatusBadRequest, "invalid_workspace")
	if !strings.Contains(resp.Message, "does not exist") {
		t.Errorf("expected the missing-path cause, got %q", resp.Message)
	}
	for _, incidental := range []string{"symlink", "no such file", "lstat"} {
		if strings.Contains(resp.Message, incidental) {
			t.Errorf("message %q must not present the failure as %q", resp.Message, incidental)
		}
	}

	// Control: a valid workspace still creates through the same handler —
	// the real success contract, not merely the absence of two refusals.
	valid := postSessionCreate(t, app, `{"principal":"`+testOwnerUsername+`","workspace":"`+filepath.ToSlash(ws)+`"}`)
	requireSessionCreated(t, valid, ws)
}

// requireSessionCreated asserts the real success contract of a
// session-create control: HTTP 201 with ok=true and a decoded created
// Session carrying its own ID and bearer token for the requested workspace.
func requireSessionCreated(t *testing.T, resp postedRequestResult, workspace string) {
	t.Helper()
	if resp.status != http.StatusCreated {
		t.Errorf("expected HTTP 201 for a successful Session creation, got %d", resp.status)
	}
	if !resp.OK {
		t.Errorf("expected ok=true for a successful Session creation, got body=%s", resp.raw)
	}
	var created createSessionResponse
	if err := json.Unmarshal(resp.raw, &created); err != nil {
		t.Fatalf("decode created Session %s: %v", resp.raw, err)
	}
	if created.Session.ID == "" || created.Token == "" {
		t.Errorf("successful creation must carry the created Session identity and token, got %s", resp.raw)
	}
	if workspace != "" && created.Session.Workspace != workspace {
		t.Errorf("created Session workspace = %q, want %q", created.Session.Workspace, workspace)
	}
}

// TestErrorContractWorkspaceSymlinkEscapeStillRefused proves the workspace
// symlink-escape refusal keeps its stable workspace-authority meaning: a
// spelling that resolves outside the allowed root is refused with the
// bounded containment message, not an incidental errno.
func TestErrorContractWorkspaceSymlinkEscapeStillRefused(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	root := app.Config.AllowedRoots[0].Path
	ws := testWorkspaceDir(t, root)

	escape := filepath.Join(ws, "escape")
	outside := filepath.Join(filepath.Dir(root), "escape-target")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(outside) })
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}

	resp := postSessionCreate(t, app, `{"principal":"`+testOwnerUsername+`","workspace":"`+filepath.ToSlash(escape)+`"}`)
	requireRefused(t, resp, http.StatusBadRequest, "invalid_workspace")
	if resp.Message != "workspace must be inside an allowed root" {
		t.Errorf("expected the stable containment refusal, got %q", resp.Message)
	}
}

// TestErrorContractWorkspaceDeniedResolutionIsPolicyRefusal proves the
// denied-resolution normalization (the confined-backend presentation of a
// symlink escape): when the daemon may not resolve or consume an admitted
// workspace spelling, the public message is the stable bounded
// workspace-authority refusal — never the probe's errno or any probed or
// resolved pathname — and a genuine resolution failure of the admitted
// spelling keeps its own bare diagnosis without errno or pathname detail.
func TestErrorContractWorkspaceDeniedResolutionIsPolicyRefusal(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	root := app.Config.AllowedRoots[0].Path
	ws := testWorkspaceDir(t, root)
	spelling := filepath.ToSlash(filepath.Join(ws, "unresolvable"))

	for _, tc := range []struct {
		name        string
		spellTarget func() string
		failStat    bool
		probeErr    error
		wantMessage string
		forbidden   []string
	}{
		{
			name:        "denied resolution answers the bounded workspace-authority refusal",
			spellTarget: func() string { return spelling },
			probeErr:    os.ErrPermission,
			wantMessage: "workspace must be inside an allowed root",
			forbidden:   []string{"permission denied", "lstat ", spelling},
		},
		{
			name: "denied post-resolution stat answers the same bounded refusal",
			// The spelling resolves on the real filesystem, so the injected
			// stat failure is the step the production path reaches.
			spellTarget: func() string { return ws },
			failStat:    true,
			probeErr:    os.ErrPermission,
			wantMessage: "workspace must be inside an allowed root",
			forbidden:   []string{"permission denied", "stat ", ws},
		},
		{
			name:        "a genuine resolution failure keeps its own bare diagnosis",
			spellTarget: func() string { return spelling },
			probeErr:    syscall.ELOOP,
			wantMessage: "cannot resolve workspace symlinks",
			forbidden:   []string{"too many levels", "lstat ", spelling},
		},
		{
			name: "a genuine post-resolution access failure keeps its own bare diagnosis",
			// The spelling resolves on the real filesystem, so the injected
			// stat failure is the step the production path reaches.
			spellTarget: func() string { return ws },
			failStat:    true,
			probeErr:    syscall.EIO,
			wantMessage: "cannot access workspace",
			forbidden:   []string{"input/output error", "stat ", ws},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// One probe step fails per subtest: the seam is swapped only for
			// the failing step (evalSymlinksFn for the resolution failure,
			// osStatFn for the post-resolution access failure), so the
			// production path reaches exactly the claimed branch.
			origEval, origStat := evalSymlinksFn, osStatFn
			if tc.failStat {
				osStatFn = func(string) (os.FileInfo, error) { return nil, tc.probeErr }
			} else {
				evalSymlinksFn = func(string) (string, error) { return "", tc.probeErr }
			}
			t.Cleanup(func() { evalSymlinksFn, osStatFn = origEval, origStat })

			resp := postSessionCreate(t, app, `{"principal":"`+testOwnerUsername+`","workspace":"`+tc.spellTarget()+`"}`)
			requireRefused(t, resp, http.StatusBadRequest, "invalid_workspace")
			if resp.Message != tc.wantMessage {
				t.Errorf("expected message %q, got %q", tc.wantMessage, resp.Message)
			}
			for _, forbiddenDetail := range tc.forbidden {
				if strings.Contains(resp.Message, forbiddenDetail) {
					t.Errorf("message %q discloses incidental detail %q", resp.Message, forbiddenDetail)
				}
			}
		})
	}
}

// TestErrorContractFilesystemRootMissing proves the path-resolution family
// of the issuance-time filesystem refusal: a requested root admitted by the
// lexical ceiling whose privileged resolution or stat fails answers
// invalid_filesystem_policy with the bounded resolution message —
// distinguishable from the generic bounded policy refusal of a genuine
// ceiling/access-mode refusal — while a valid requested root still creates.
func TestErrorContractFilesystemRootMissing(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	root := app.Config.AllowedRoots[0].Path
	ws := testWorkspaceDir(t, root)

	missingRoot := filepath.ToSlash(filepath.Join(ws, "no-such-root"))

	resp := postSessionCreate(t, app,
		`{"principal":"`+testOwnerUsername+`","workspace":"`+filepath.ToSlash(ws)+`","filesystem_roots":[{"path":"`+missingRoot+`","access":"read_write"}]}`)
	requireRefused(t, resp, http.StatusBadRequest, "invalid_filesystem_policy")
	if resp.Message != "requested filesystem root does not exist or cannot be resolved" {
		t.Errorf("expected the bounded resolution message, got %q", resp.Message)
	}

	// Controls: a genuine ceiling refusal and an access-mode refusal keep
	// the generic bounded policy message.
	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "root outside the ceiling",
			body: `{"principal":"` + testOwnerUsername + `","workspace":"` + filepath.ToSlash(ws) + `","filesystem_roots":[{"path":"/etc","access":"read_write"}]}`,
		},
		{
			name: "invalid access mode",
			body: `{"principal":"` + testOwnerUsername + `","workspace":"` + filepath.ToSlash(ws) + `","filesystem_roots":[{"path":"` + filepath.ToSlash(ws) + `","access":"sometimes"}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := postSessionCreate(t, app, tc.body)
			requireRefused(t, resp, http.StatusBadRequest, "invalid_filesystem_policy")
			if resp.Message != "invalid session filesystem policy" {
				t.Errorf("expected the generic bounded policy message, got %q", resp.Message)
			}
		})
	}

	// Control: a valid requested root still creates through the same
	// handler — the real success contract, not merely the absence of the
	// refusal code.
	resp = postSessionCreate(t, app,
		`{"principal":"`+testOwnerUsername+`","workspace":"`+filepath.ToSlash(ws)+`","filesystem_roots":[{"path":"`+filepath.ToSlash(ws)+`","access":"read_write"}]}`)
	requireSessionCreated(t, resp, filepath.ToSlash(ws))
}

// TestErrorContractFilesystemRootDeniedResolutionStaysPolicyRefusal proves
// the denied-resolution presentation of the issuance-time filesystem
// refusal: when the daemon may not resolve or consume an admitted requested
// root (the confined-backend presentation of a symlink escape), the public
// message stays the generic bounded policy refusal — the same meaning a
// successfully-resolved escape receives from the canonical ceiling proof —
// with no errno and no resolved pathname.
func TestErrorContractFilesystemRootDeniedResolutionStaysPolicyRefusal(t *testing.T) {
	app := newTestAppWithAdminTokenAndStaging(t)
	root := app.Config.AllowedRoots[0].Path
	ws := testWorkspaceDir(t, root)
	missingRoot := filepath.ToSlash(filepath.Join(ws, "denied-root"))
	existingRoot := filepath.ToSlash(filepath.Join(ws, "denied-stat-root"))
	if err := os.MkdirAll(existingRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	body := func(spelling string) string {
		return `{"principal":"` + testOwnerUsername + `","workspace":"` + filepath.ToSlash(ws) + `","filesystem_roots":[{"path":"` + spelling + `","access":"read_write"}]}`
	}

	for _, tc := range []struct {
		name      string
		spelling  string
		failStat  bool
		probeErr  error
		forbidden []string
	}{
		{
			name:      "denied resolution of a nonexistent requested root",
			spelling:  missingRoot,
			probeErr:  os.ErrPermission,
			forbidden: []string{"permission denied", "lstat ", missingRoot},
		},
		{
			name:      "denied post-resolution stat of a resolvable requested root",
			spelling:  existingRoot,
			failStat:  true,
			probeErr:  os.ErrPermission,
			forbidden: []string{"permission denied", "stat ", existingRoot},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The probe seams are package-global and shared by the workspace
			// admission and the filesystem-root canonicalization, so each
			// seam fails ONLY for the requested filesystem root and passes
			// every other probe (the workspace spelling) through to the real
			// implementation — the production path reaches exactly the
			// claimed filesystem-root probe step.
			origEval, origStat := evalSymlinksFn, osStatFn
			target := tc.spelling
			if tc.failStat {
				osStatFn = func(p string) (os.FileInfo, error) {
					if p == target {
						return nil, tc.probeErr
					}
					return origStat(p)
				}
			} else {
				evalSymlinksFn = func(p string) (string, error) {
					if p == target {
						return "", tc.probeErr
					}
					return origEval(p)
				}
			}
			t.Cleanup(func() { evalSymlinksFn, osStatFn = origEval, origStat })

			resp := postSessionCreate(t, app, body(tc.spelling))
			requireRefused(t, resp, http.StatusBadRequest, "invalid_filesystem_policy")
			if resp.Message != "invalid session filesystem policy" {
				t.Errorf("expected the generic bounded policy message, got %q", resp.Message)
			}
			for _, forbiddenDetail := range tc.forbidden {
				if strings.Contains(resp.Message, forbiddenDetail) {
					t.Errorf("message %q discloses incidental detail %q", resp.Message, forbiddenDetail)
				}
			}
		})
	}
}
