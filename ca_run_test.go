package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// waitRun waits for a run operation to complete.
func waitRun(t *testing.T, app *App, w *httptest.ResponseRecorder) {
	t.Helper()
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode run response: %v", err)
	}
	opID, ok := resp["operation_id"].(string)
	if !ok || opID == "" {
		t.Fatal("expected operation_id in response")
	}
	op := app.OperationRegistry.get(opID)
	if op == nil {
		t.Fatalf("operation %s not found in registry", opID)
	}
	op.Wait()
}

func setupRunTestApp(t *testing.T) (*App, string) {
	t.Helper()
	app := newTestAppWithAuth(t)
	app.OperationRegistry = newOperationRegistry()

	result, err := app.createSession(app.Config.AllowedRoot)
	if err != nil {
		t.Fatalf("createSession() error: %v", err)
	}

	return app, result.Token
}

func TestRunCAAutoAddsMountAndEnv(t *testing.T) {
	app, token := setupRunTestApp(t)

	// Set up CA injection config directly.
	preparedDir := filepath.Join(app.Config.RuntimeDir, "trusted-ca", "test-fingerprint")
	if err := os.MkdirAll(preparedDir, 0755); err != nil {
		t.Fatalf("cannot create prepared dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(preparedDir, "ca.pem"), []byte("test-ca"), 0644); err != nil {
		t.Fatalf("cannot write ca.pem: %v", err)
	}
	app.Config.TrustedCAInjection = "auto"
	app.Config.TrustedCAPreparedDir = preparedDir

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"echo", "hello"},
	}, token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitRun(t, app, w)

	// Verify CA mount is present and readonly.
	foundMount := false
	expectedMount := "type=bind,source=" + preparedDir + ",target=/run/docker-helper/trusted-ca,readonly"
	for i, arg := range capturedArgs {
		if arg == "--mount" && i+1 < len(capturedArgs) {
			if capturedArgs[i+1] == expectedMount {
				foundMount = true
			}
		}
	}
	if !foundMount {
		t.Errorf("expected CA mount %q not found in args: %v", expectedMount, capturedArgs)
	}

	// Verify SSL_CERT_DIR env var.
	foundSSLDir := false
	for i, arg := range capturedArgs {
		if arg == "--env" && i+1 < len(capturedArgs) {
			next := capturedArgs[i+1]
			if strings.HasPrefix(next, "SSL_CERT_DIR=") {
				val := strings.TrimPrefix(next, "SSL_CERT_DIR=")
				if val != trustedCAEnvSSLDirValue {
					t.Errorf("SSL_CERT_DIR = %q, want %q", val, trustedCAEnvSSLDirValue)
				}
				foundSSLDir = true
			}
		}
	}
	if !foundSSLDir {
		t.Errorf("SSL_CERT_DIR env not found in args: %v", capturedArgs)
	}

	// Verify NODE_EXTRA_CA_CERTS env var.
	foundNodeExtra := false
	for i, arg := range capturedArgs {
		if arg == "--env" && i+1 < len(capturedArgs) {
			next := capturedArgs[i+1]
			if strings.HasPrefix(next, "NODE_EXTRA_CA_CERTS=") {
				val := strings.TrimPrefix(next, "NODE_EXTRA_CA_CERTS=")
				if val != trustedCAEnvNodeExtraValue {
					t.Errorf("NODE_EXTRA_CA_CERTS = %q, want %q", val, trustedCAEnvNodeExtraValue)
				}
				foundNodeExtra = true
			}
		}
	}
	if !foundNodeExtra {
		t.Errorf("NODE_EXTRA_CA_CERTS env not found in args: %v", capturedArgs)
	}
}

func TestRunCAExplicitEnvWins(t *testing.T) {
	app, token := setupRunTestApp(t)

	preparedDir := filepath.Join(app.Config.RuntimeDir, "trusted-ca", "test-fingerprint")
	if err := os.MkdirAll(preparedDir, 0755); err != nil {
		t.Fatalf("cannot create prepared dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(preparedDir, "ca.pem"), []byte("test-ca"), 0644); err != nil {
		t.Fatalf("cannot write ca.pem: %v", err)
	}
	app.Config.TrustedCAInjection = "auto"
	app.Config.TrustedCAPreparedDir = preparedDir

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"echo", "hello"},
		"environment": map[string]string{
			"SSL_CERT_DIR":        "/custom/certs",
			"NODE_EXTRA_CA_CERTS": "/custom/ca.pem",
		},
	}, token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitRun(t, app, w)

	// Verify user values are preserved.
	for i, arg := range capturedArgs {
		if arg == "--env" && i+1 < len(capturedArgs) {
			next := capturedArgs[i+1]
			if strings.HasPrefix(next, "SSL_CERT_DIR=") {
				val := strings.TrimPrefix(next, "SSL_CERT_DIR=")
				if val != "/custom/certs" {
					t.Errorf("SSL_CERT_DIR = %q, want /custom/certs", val)
				}
			}
			if strings.HasPrefix(next, "NODE_EXTRA_CA_CERTS=") {
				val := strings.TrimPrefix(next, "NODE_EXTRA_CA_CERTS=")
				if val != "/custom/ca.pem" {
					t.Errorf("NODE_EXTRA_CA_CERTS = %q, want /custom/ca.pem", val)
				}
			}
		}
	}

	// Verify no default values leaked.
	for i, arg := range capturedArgs {
		if arg == "--env" && i+1 < len(capturedArgs) {
			next := capturedArgs[i+1]
			if strings.HasPrefix(next, "SSL_CERT_DIR=") {
				val := strings.TrimPrefix(next, "SSL_CERT_DIR=")
				if val == trustedCAEnvSSLDirValue {
					t.Error("default SSL_CERT_DIR should not be injected when user provides value")
				}
			}
			if strings.HasPrefix(next, "NODE_EXTRA_CA_CERTS=") {
				val := strings.TrimPrefix(next, "NODE_EXTRA_CA_CERTS=")
				if val == trustedCAEnvNodeExtraValue {
					t.Error("default NODE_EXTRA_CA_CERTS should not be injected when user provides value")
				}
			}
		}
	}

	// Verify no duplicates.
	sslDirCount := 0
	nodeExtraCount := 0
	for i, arg := range capturedArgs {
		if arg == "--env" && i+1 < len(capturedArgs) {
			next := capturedArgs[i+1]
			if strings.HasPrefix(next, "SSL_CERT_DIR=") {
				sslDirCount++
			}
			if strings.HasPrefix(next, "NODE_EXTRA_CA_CERTS=") {
				nodeExtraCount++
			}
		}
	}
	if sslDirCount > 1 {
		t.Errorf("expected at most 1 SSL_CERT_DIR, got %d", sslDirCount)
	}
	if nodeExtraCount > 1 {
		t.Errorf("expected at most 1 NODE_EXTRA_CA_CERTS, got %d", nodeExtraCount)
	}
}

func TestRunCADisabledNoMountOrEnv(t *testing.T) {
	app, token := setupRunTestApp(t)

	// CA injection disabled (default).
	app.Config.TrustedCAInjection = "disabled"
	app.Config.TrustedCAPreparedDir = ""

	var capturedArgs []string
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"echo", "hello"},
	}, token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, w.Code)
	}

	waitRun(t, app, w)

	// Verify no CA mount.
	for i, arg := range capturedArgs {
		if arg == "--mount" && i+1 < len(capturedArgs) {
			if strings.Contains(capturedArgs[i+1], "trusted-ca") {
				t.Errorf("CA mount should not be present when disabled, got: %s", capturedArgs[i+1])
			}
		}
	}

	// Verify no CA env vars.
	for i, arg := range capturedArgs {
		if arg == "--env" && i+1 < len(capturedArgs) {
			next := capturedArgs[i+1]
			if strings.HasPrefix(next, "SSL_CERT_DIR=") {
				t.Errorf("SSL_CERT_DIR should not be injected when disabled, got: %s", next)
			}
			if strings.HasPrefix(next, "NODE_EXTRA_CA_CERTS=") {
				t.Errorf("NODE_EXTRA_CA_CERTS should not be injected when disabled, got: %s", next)
			}
		}
	}
}

func TestRunCAOverlappingMountRejected(t *testing.T) {
	app, token := setupRunTestApp(t)

	preparedDir := filepath.Join(app.Config.RuntimeDir, "trusted-ca", "test-fingerprint")
	if err := os.MkdirAll(preparedDir, 0755); err != nil {
		t.Fatalf("cannot create prepared dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(preparedDir, "ca.pem"), []byte("test-ca"), 0644); err != nil {
		t.Fatalf("cannot write ca.pem: %v", err)
	}
	app.Config.TrustedCAInjection = "auto"
	app.Config.TrustedCAPreparedDir = preparedDir

	dockerCalled := false
	app.ExecCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		dockerCalled = true
		return exec.CommandContext(ctx, "/bin/true")
	}

	req := newRunRequest(map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"echo", "hello"},
		"mounts": []map[string]any{
			{
				"source": "/tmp/data",
				"target": "/run/docker-helper/trusted-ca",
			},
		},
	}, token)
	w := httptest.NewRecorder()
	app.handleRun(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}

	if dockerCalled {
		t.Error("docker should not be called when overlapping mount is rejected")
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if code, ok := resp["code"].(string); !ok || code != "invalid_mount" {
		t.Errorf("expected code=invalid_mount, got %v", resp["code"])
	}
}

func TestCAMountOverlapRejected(t *testing.T) {
	tests := []struct {
		target  string
		overlap bool
	}{
		{"/run/docker-helper/trusted-ca", true},
		{"/run/docker-helper/trusted-ca/ca.pem", true},
		{"/run/docker-helper/trusted-ca/subdir", true},
		{"/run/docker-helper", true},
		{"/run", true},
		{"/workspace", false},
		{"/etc/ssl/certs", false},
		{"/run/docker-helper/other", false},
	}

	for _, tc := range tests {
		got := isTrustedCAMountOverlap(tc.target)
		if got != tc.overlap {
			t.Errorf("isTrustedCAMountOverlap(%q) = %v, want %v", tc.target, got, tc.overlap)
		}
	}
}

func TestIsTrustedCAEnvVar(t *testing.T) {
	if !isTrustedCAEnvVar("SSL_CERT_DIR") {
		t.Error("SSL_CERT_DIR should be a trusted CA env var")
	}
	if !isTrustedCAEnvVar("NODE_EXTRA_CA_CERTS") {
		t.Error("NODE_EXTRA_CA_CERTS should be a trusted CA env var")
	}
	if isTrustedCAEnvVar("SSL_CERT_FILE") {
		t.Error("SSL_CERT_FILE should NOT be a trusted CA env var")
	}
	if isTrustedCAEnvVar("CUSTOM_VAR") {
		t.Error("CUSTOM_VAR should NOT be a trusted CA env var")
	}
}

func TestCAInjectionConstants(t *testing.T) {
	if trustedCAContainerDir != "/run/docker-helper/trusted-ca" {
		t.Errorf("trustedCAContainerDir = %s", trustedCAContainerDir)
	}
	if trustedCAEnvSSLDir != "SSL_CERT_DIR" {
		t.Errorf("trustedCAEnvSSLDir = %s", trustedCAEnvSSLDir)
	}
	if trustedCAEnvNodeExtra != "NODE_EXTRA_CA_CERTS" {
		t.Errorf("trustedCAEnvNodeExtra = %s", trustedCAEnvNodeExtra)
	}
	if !strings.Contains(trustedCAEnvSSLDirValue, "/run/docker-helper/trusted-ca") {
		t.Error("SSL_CERT_DIR value should contain trusted CA dir")
	}
	if !strings.Contains(trustedCAEnvSSLDirValue, "/etc/ssl/certs") {
		t.Error("SSL_CERT_DIR value should contain /etc/ssl/certs")
	}
	if !strings.Contains(trustedCAEnvSSLDirValue, "/etc/pki/tls/certs") {
		t.Error("SSL_CERT_DIR value should contain /etc/pki/tls/certs")
	}
	if trustedCAEnvNodeExtraValue != "/run/docker-helper/trusted-ca/ca.pem" {
		t.Errorf("NODE_EXTRA_CA_CERTS value = %s", trustedCAEnvNodeExtraValue)
	}
}

func TestCAInjectionNoSSL_CERT_FILE(t *testing.T) {
	if isTrustedCAEnvVar("SSL_CERT_FILE") {
		t.Error("SSL_CERT_FILE should NOT be a trusted CA env var")
	}
}
