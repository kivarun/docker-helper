package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
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
	var childPid int

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		// Return an UNSTARTED command that writes PID on start.
		cmd := exec.CommandContext(ctx, "sh", "-c",
			`echo $$ > "$1"; exec sleep 300`,
			"sh", pidFile,
		)
		return cmd
	}

	ctx, cancel := context.WithCancel(context.Background())

	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/pull", bytes.NewReader(body))
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+result.Token)
	w := httptest.NewRecorder()

	handlerDone := make(chan struct{})
	go func() {
		app.handlePull(w, req)
		close(handlerDone)
	}()

	// Wait for the child process to actually start (PID file appears).
	pidReady := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			if _, err := os.Stat(pidFile); err == nil {
				close(pidReady)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	select {
	case <-pidReady:
	case <-time.After(5 * time.Second):
		t.Fatal("child process did not start (no PID file)")
	}

	// Read the PID.
	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("cannot read PID file: %v", err)
	}
	fmt.Sscanf(string(pidData), "%d", &childPid)
	if childPid <= 0 {
		t.Fatalf("invalid PID: %d", childPid)
	}

	// Verify the process exists.
	if err := syscall.Kill(childPid, 0); err != nil {
		t.Fatalf("child process does not exist: %v", err)
	}

	// Cleanup: kill child if test fails.
	t.Cleanup(func() {
		_ = syscall.Kill(childPid, syscall.SIGKILL)
		_, _ = syscall.Wait4(childPid, nil, syscall.WNOHANG, nil)
	})

	// Now cancel the request context.
	cancel()

	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handlePull did not return after context cancellation")
	}

	// Verify the child process is gone.
	if err := syscall.Kill(childPid, 0); err == nil {
		t.Error("child process still exists after cancellation")
		// Don't SIGKILL here — that would mask the failure.
	}
}

func TestPullTerminatedByDaemonShutdown(t *testing.T) {
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
	var childPid int

	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		// Return an UNSTARTED command that writes PID on start.
		cmd := exec.CommandContext(ctx, "sh", "-c",
			`echo $$ > "$1"; exec sleep 300`,
			"sh", pidFile,
		)
		return cmd
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /pull", func(w http.ResponseWriter, r *http.Request) {
		app.handlePull(w, r)
	})

	// Use a real listener for production-like shutdown.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot create listener: %v", err)
	}

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start serving.
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Close()

	// Wait for server to be ready.
	waitForDialReady(t, "tcp", listener.Addr().String())

	// Start the pull request.
	reqBody := map[string]string{"image": "alpine:3.24"}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest(http.MethodPost, "http://"+listener.Addr().String()+"/pull", bytes.NewReader(body))
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

	// Wait for the child process to actually start (PID file appears).
	pidReady := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			if _, err := os.Stat(pidFile); err == nil {
				close(pidReady)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	select {
	case <-pidReady:
	case <-time.After(5 * time.Second):
		t.Fatal("child process did not start (no PID file)")
	}

	// Read the PID.
	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("cannot read PID file: %v", err)
	}
	fmt.Sscanf(string(pidData), "%d", &childPid)
	if childPid <= 0 {
		t.Fatalf("invalid PID: %d", childPid)
	}

	// Verify the process exists.
	if err := syscall.Kill(childPid, 0); err != nil {
		t.Fatalf("child process does not exist: %v", err)
	}

	// Cleanup: kill child if test fails.
	t.Cleanup(func() {
		_ = syscall.Kill(childPid, syscall.SIGKILL)
		_, _ = syscall.Wait4(childPid, nil, syscall.WNOHANG, nil)
	})

	// Now trigger production-like shutdown using serveWithShutdownMulti semantics.
	// We simulate: signal -> startShutdown -> server.Shutdown(deadline) -> server.Close() -> context cancel
	shutdownTimeout := 2 * time.Second

	drainDone := make(chan error, 1)
	go func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer shutdownCancel()

		shutdownErr := server.Shutdown(shutdownCtx)
		var drainErr error
		if shutdownErr == context.DeadlineExceeded {
			server.Close()
			drainErr = fmt.Errorf("graceful shutdown timeout after %v", shutdownTimeout)
		} else if shutdownErr != nil {
			drainErr = shutdownErr
		}
		drainDone <- drainErr
	}()

	select {
	case <-drainDone:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown did not complete")
	}

	// The HTTP request should have completed (success or error).
	select {
	case <-reqDone:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP request did not complete after shutdown")
	}

	// Verify the child process is gone, giving the process table a short
	// bounded window to reap it.
	childGone := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(childPid, 0); err != nil {
			childGone = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !childGone {
		t.Error("child process still exists after daemon shutdown")
		// Don't SIGKILL here — that would mask the failure.
	}
}
