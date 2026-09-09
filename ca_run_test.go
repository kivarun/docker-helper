package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func setupRunTestApp(t *testing.T) (*App, string) {
	t.Helper()
	app := newTestAppWithAdminToken(t)
	app.OperationSupervisor = newOperationSupervisor()

	result, err := createDefaultAdminSessionForTest(app, testWorkspaceDir(t, app.Config.AllowedRoots[0]))
	if err != nil {
		t.Fatalf("createSessionAuthorized() error: %v", err)
	}

	return app, result.Token
}

func setupCADir(t *testing.T, app *App) string {
	t.Helper()
	preparedDir := filepath.Join(app.Config.RuntimeDir, "trusted-ca", "test-snapshot")
	if err := os.MkdirAll(preparedDir, 0755); err != nil {
		t.Fatalf("cannot create prepared dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(preparedDir, "ca.pem"), []byte("test-ca"), 0644); err != nil {
		t.Fatalf("cannot write ca.pem: %v", err)
	}
	app.Config.TrustedCAInjection = "auto"
	app.Config.TrustedCAPreparedDir = preparedDir
	return preparedDir
}

func TestRunCAAutoAddsMountAndEnv(t *testing.T) {
	app, token := setupRunTestApp(t)

	preparedDir := setupCADir(t, app)

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, token, map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"echo", "hello"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}

	spec := captured.lastSpec()

	// Verify exactly one CA mount with the correct projection.
	var mounts []engineRunMount
	for _, m := range spec.Mounts {
		if m.Target == trustedCAContainerDir {
			mounts = append(mounts, m)
		}
	}
	if len(mounts) != 1 || mounts[0].Source != preparedDir || !mounts[0].ReadOnly {
		t.Errorf("expected exactly 1 CA mount %s read-only, got %+v", preparedDir, spec.Mounts)
	}

	// Verify exactly two CA env vars with the correct values and no extras.
	if len(spec.Env) != 2 {
		t.Fatalf("expected exactly 2 env vars, got %d: %v", len(spec.Env), spec.Env)
	}
	if got := spec.Env["NODE_EXTRA_CA_CERTS"]; got != trustedCAEnvNodeExtraValue {
		t.Errorf("NODE_EXTRA_CA_CERTS = %q, want %q", got, trustedCAEnvNodeExtraValue)
	}
	if got := spec.Env["SSL_CERT_DIR"]; got != trustedCAEnvSSLDirValue {
		t.Errorf("SSL_CERT_DIR = %q, want %q", got, trustedCAEnvSSLDirValue)
	}
}

func TestRunCAExplicitEnvWins(t *testing.T) {
	app, token := setupRunTestApp(t)

	setupCADir(t, app)

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, token, map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"echo", "hello"},
		"environment": map[string]string{
			"SSL_CERT_DIR":        "/custom/certs",
			"NODE_EXTRA_CA_CERTS": "/custom/ca.pem",
		},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	env := captured.lastSpec().Env

	// User values are the only ones present.
	if got := env["SSL_CERT_DIR"]; got != "/custom/certs" {
		t.Errorf("SSL_CERT_DIR = %q, want /custom/certs", got)
	}
	if got := env["NODE_EXTRA_CA_CERTS"]; got != "/custom/ca.pem" {
		t.Errorf("NODE_EXTRA_CA_CERTS = %q, want /custom/ca.pem", got)
	}
	if len(env) != 2 {
		t.Errorf("unexpected extra env vars: %v", env)
	}
}

func TestRunCADisabledNoMountOrEnv(t *testing.T) {
	app, token := setupRunTestApp(t)

	// CA injection disabled (default).
	app.Config.TrustedCAInjection = "disabled"
	app.Config.TrustedCAPreparedDir = ""

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, token, map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"echo", "hello"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}

	spec := captured.lastSpec()

	for _, m := range spec.Mounts {
		if m.Target == trustedCAContainerDir {
			t.Errorf("CA mount should not be present when disabled, got: %+v", m)
		}
	}

	if _, ok := spec.Env["SSL_CERT_DIR"]; ok {
		t.Errorf("SSL_CERT_DIR should not be injected when disabled: %v", spec.Env)
	}
	if _, ok := spec.Env["NODE_EXTRA_CA_CERTS"]; ok {
		t.Errorf("NODE_EXTRA_CA_CERTS should not be injected when disabled: %v", spec.Env)
	}
}

func TestRunCAOverlappingMountRejected(t *testing.T) {
	app, token := setupRunTestApp(t)

	setupCADir(t, app)

	captured := setupRunSeam(t, app, runSeamOptions{ExitCode: 0})

	w := postRun(t, app, token, map[string]any{
		"image":   "alpine:3.24",
		"command": []string{"echo", "hello"},
		"mounts": []map[string]any{
			{
				"source": ".",
				"target": "/run/docker-helper/trusted-ca",
			},
		},
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, w.Code)
	}

	if captured.reached() {
		t.Error("Engine runner must not be called when an overlapping mount is rejected")
	}

	resp := decodeRunResponse(t, w)
	if resp.Code != "invalid_mount" {
		t.Errorf("expected code=invalid_mount, got %q", resp.Code)
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
