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

	result, err := app.createSession(testWorkspaceDir(t, app.Config.AllowedRoot))
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

	// Verify exactly one CA mount with the correct value.
	var mountValues []string
	for i, arg := range capturedArgs {
		if arg == "--mount" && i+1 < len(capturedArgs) {
			mountValues = append(mountValues, capturedArgs[i+1])
		}
	}
	expectedMount := "type=bind,source=" + preparedDir + ",target=/run/docker-helper/trusted-ca,readonly"
	if len(mountValues) != 1 || mountValues[0] != expectedMount {
		t.Errorf("expected exactly 1 mount %q, got %v", expectedMount, mountValues)
	}

	// Verify exactly two CA env vars with the correct values and no extras.
	var envValues []string
	for i, arg := range capturedArgs {
		if arg == "--env" && i+1 < len(capturedArgs) {
			envValues = append(envValues, capturedArgs[i+1])
		}
	}
	if len(envValues) != 2 {
		t.Fatalf("expected exactly 2 env vars, got %d: %v", len(envValues), envValues)
	}
	if envValues[0] != "NODE_EXTRA_CA_CERTS=/run/docker-helper/trusted-ca/ca.pem" {
		t.Errorf("env[0] = %q, want NODE_EXTRA_CA_CERTS=/run/docker-helper/trusted-ca/ca.pem", envValues[0])
	}
	if envValues[1] != "SSL_CERT_DIR=/run/docker-helper/trusted-ca:/etc/ssl/certs:/etc/pki/tls/certs" {
		t.Errorf("env[1] = %q, want SSL_CERT_DIR=/run/docker-helper/trusted-ca:/etc/ssl/certs:/etc/pki/tls/certs", envValues[1])
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

	// Verify user values are the only ones present.
	checkEnvArg := func(name, want string) {
		var found []string
		for i, arg := range capturedArgs {
			if arg == "--env" && i+1 < len(capturedArgs) {
				next := capturedArgs[i+1]
				if strings.HasPrefix(next, name+"=") {
					found = append(found, strings.TrimPrefix(next, name+"="))
				}
			}
		}
		if len(found) != 1 {
			t.Errorf("expected exactly 1 %s, got %d: %v", name, len(found), found)
			return
		}
		if found[0] != want {
			t.Errorf("%s = %q, want %q", name, found[0], want)
		}
	}

	checkEnvArg("SSL_CERT_DIR", "/custom/certs")
	checkEnvArg("NODE_EXTRA_CA_CERTS", "/custom/ca.pem")
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
				"source": ".",
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
