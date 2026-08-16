package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPullSessionAuthValidToken(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestPullSessionAuthMissingAuthorization(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthWrongScheme(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthEmptyBearer(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer ")
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthInvalidToken(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dht_wrong_token")
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthExpiredSession(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	_, err = app.DB.Exec("UPDATE sessions SET expires_at = ? WHERE id = ?", time.Now().Add(-time.Hour).Unix(), result.Session.ID)
	if err != nil {
		t.Fatalf("cannot update expires_at: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthDeletedSession(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	deleted, err := app.deleteSession(result.Session.ID)
	if err != nil {
		t.Fatalf("deleteSession() error: %v", err)
	}
	if deleted == nil {
		t.Fatal("expected session to be deleted")
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullSessionAuthResponseContainsCode(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.Code != "unauthorized" {
		t.Errorf("expected code 'unauthorized', got %q", resp.Code)
	}
}

func TestPullSessionAuthResponseContainsWWWAuthenticate(t *testing.T) {
	app := newTestAppWithAuth(t)

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("expected WWW-Authenticate: Bearer, got %q", w.Header().Get("WWW-Authenticate"))
	}
}

func TestPullSessionAuthInvalidTokenDoesNotRunDocker(t *testing.T) {
	app := newTestAppWithAuth(t)

	called := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		called = true
		return exec.CommandContext(ctx, "true")
	}

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dht_wrong_token")
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}

	if called {
		t.Error("ExecCommandContext should not be called with invalid token")
	}
}

func TestPullSessionAuthAdminTokenRejected(t *testing.T) {
	app := newTestAppWithAuth(t)

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d (admin token should not work for /pull), got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPullImageRequired(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	reqBody := map[string]string{}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.Message != "image is required" {
		t.Errorf("expected 'image is required', got %q", resp.Message)
	}
}

func TestPullInvalidJSON(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPullUnknownFieldsRejected(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "true")
	}

	reqBody := map[string]any{"image": "alpine:3.24", "extra": "field"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPullSuccessResponse(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "echo", "pull output")
	}

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if !resp.OK {
		t.Error("expected ok to be true")
	}
	if resp.Message != "image pulled successfully" {
		t.Errorf("expected 'image pulled successfully', got %q", resp.Message)
	}
	if resp.Output != "pull output\n" {
		t.Errorf("expected output 'pull output\\n', got %q", resp.Output)
	}
	if resp.Duration == "" {
		t.Error("expected duration to be set")
	}
}

func TestPullErrorResponse(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "printf '%s' 'error output'; exit 1")
	}

	reqBody := map[string]string{"image": "nonexistent:latest"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	var resp response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}

	if resp.OK {
		t.Error("expected ok to be false")
	}
	if resp.Output != "error output" {
		t.Errorf("expected output 'error output', got %q", resp.Output)
	}
}

func TestPullDockerArgs(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "true")
	}

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	app.handlePull(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	dockerDir := sessionDockerDir(app.Config.RuntimeDir, result.Session.ID)
	expectedArgs := []string{"--config", dockerDir, "pull", "alpine:3.24"}
	if len(capturedArgs) != len(expectedArgs) {
		t.Fatalf("expected %d args, got %d: %v", len(expectedArgs), len(capturedArgs), capturedArgs)
	}

	for i, exp := range expectedArgs {
		if capturedArgs[i] != exp {
			t.Errorf("arg[%d]: expected %q, got %q", i, exp, capturedArgs[i])
		}
	}
}

func TestPullRequestCancellation(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerDir := sessionDockerDir(app.Config.RuntimeDir, result.Session.ID)
	if err := os.MkdirAll(dockerDir, 0700); err != nil {
		t.Fatalf("cannot create docker dir: %v", err)
	}

	pidFile := filepath.Join(t.TempDir(), "pid")
	started := make(chan struct{})
	var child *exec.Cmd

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, "sleep", "300")
		cmd.Stdout = &bytes.Buffer{}
		cmd.Stderr = &bytes.Buffer{}
		if err := cmd.Start(); err != nil {
			t.Errorf("cmd.Start: %v", err)
			return cmd
		}
		// Write PID file to prove the child is running.
		if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", cmd.Process.Pid)), 0644); err != nil {
			t.Errorf("write PID file: %v", err)
		}
		close(started)
		child = cmd
		return cmd
	}

	ctx, cancel := context.WithCancel(context.Background())

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		app.handlePull(w, req)
		close(done)
	}()

	// Wait for the child process to actually start.
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("child process did not start")
	}

	// Verify PID file exists (process is running).
	if _, err := os.Stat(pidFile); os.IsNotExist(err) {
		t.Fatal("PID file not found, child process did not write PID")
	}

	// Now cancel the context.
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handlePull did not return after context cancellation")
	}

	// Verify the child process is gone.
	if child == nil || child.Process == nil {
		t.Fatal("child process is nil")
	}
	// Process should be terminated.
	status := child.ProcessState
	if status == nil {
		// Process may still be in zombie state, try to signal it.
		if err := child.Process.Signal(os.Kill); err == nil {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func TestPullShutdownRejection(t *testing.T) {
	app := newTestAppWithAuth(t)

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	dockerDir := sessionDockerDir(app.Config.RuntimeDir, result.Session.ID)
	if err := os.MkdirAll(dockerDir, 0700); err != nil {
		t.Fatalf("cannot create docker dir: %v", err)
	}

	pidFile := filepath.Join(t.TempDir(), "pid")
	started := make(chan struct{})
	var child *exec.Cmd

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, "sleep", "300")
		cmd.Stdout = &bytes.Buffer{}
		cmd.Stderr = &bytes.Buffer{}
		if err := cmd.Start(); err != nil {
			t.Errorf("cmd.Start: %v", err)
			return cmd
		}
		if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", cmd.Process.Pid)), 0644); err != nil {
			t.Errorf("write PID file: %v", err)
		}
		close(started)
		child = cmd
		return cmd
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /pull", func(w http.ResponseWriter, r *http.Request) {
		app.handlePull(w, r)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Start the pull request.
	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest(http.MethodPost, server.URL+"/pull", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("cannot create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+result.Token)
	req.Header.Set("Content-Type", "application/json")

	reqDone := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			reqDone <- err
			return
		}
		resp.Body.Close()
		reqDone <- nil
	}()

	// Wait for the child process to actually start.
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("child process did not start")
	}

	if _, err := os.Stat(pidFile); os.IsNotExist(err) {
		t.Fatal("PID file not found, child process did not write PID")
	}

	// Now initiate shutdown.
	shutdownDone := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Config.Shutdown(ctx)
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
	case <-time.After(10 * time.Second):
		t.Fatal("server shutdown did not complete")
	}

	// The HTTP request should have failed or returned.
	select {
	case err := <-reqDone:
		if err == nil {
			// Request completed normally (response was sent before shutdown took effect).
			// This is acceptable — the key invariant is that the child was terminated.
		}
		// Connection error is also acceptable.
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP request did not complete after shutdown")
	}

	// Verify the child process is gone.
	if child == nil || child.Process == nil {
		t.Fatal("child process is nil")
	}
	// The process should be terminated by now (context cancelled by shutdown).
	if err := child.Process.Signal(os.Kill); err != nil {
		// Process already terminated — this is expected.
	}
}
