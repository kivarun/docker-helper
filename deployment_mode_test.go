package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUserModePaths(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	mode := resolveDeploymentMode()
	if mode != ModeUser {
		t.Fatalf("expected mode=user, got %s", mode)
	}

	// Config path should use XDG_CONFIG_HOME or ~/.config.
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/home/testuser")
	configPath := getConfigPath()
	expected := "/home/testuser/.config/docker-helper/config.json"
	if configPath != expected {
		t.Errorf("configPath = %q, want %q", configPath, expected)
	}

	// State path should use XDG_STATE_HOME or ~/.local/state.
	t.Setenv("XDG_STATE_HOME", "")
	stateDir := getStateDir()
	expected = "/home/testuser/.local/state/docker-helper"
	if stateDir != expected {
		t.Errorf("stateDir = %q, want %q", stateDir, expected)
	}

	// Runtime path should use XDG_RUNTIME_DIR.
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	runtimeDir, err := getRuntimeDir()
	if err != nil {
		t.Fatalf("getRuntimeDir() error: %v", err)
	}
	expected = "/run/user/1000/docker-helper"
	if runtimeDir != expected {
		t.Errorf("runtimeDir = %q, want %q", runtimeDir, expected)
	}

	// Missing XDG_RUNTIME_DIR should error in user mode.
	t.Setenv("XDG_RUNTIME_DIR", "")
	_, err = getRuntimeDir()
	if err == nil {
		t.Fatal("expected error for missing XDG_RUNTIME_DIR in user mode")
	}
}

func TestUserModeXDGOverride(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	t.Setenv("XDG_CONFIG_HOME", "/custom/config")
	t.Setenv("HOME", "/home/testuser")
	configPath := getConfigPath()
	expected := "/custom/config/docker-helper/config.json"
	if configPath != expected {
		t.Errorf("configPath = %q, want %q", configPath, expected)
	}

	t.Setenv("XDG_STATE_HOME", "/custom/state")
	stateDir := getStateDir()
	expected = "/custom/state/docker-helper"
	if stateDir != expected {
		t.Errorf("stateDir = %q, want %q", stateDir, expected)
	}

	t.Setenv("XDG_RUNTIME_DIR", "/custom/runtime")
	runtimeDir, err := getRuntimeDir()
	if err != nil {
		t.Fatalf("getRuntimeDir() error: %v", err)
	}
	expected = "/custom/runtime/docker-helper"
	if runtimeDir != expected {
		t.Errorf("runtimeDir = %q, want %q", runtimeDir, expected)
	}
}

func TestSystemModePaths(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	mode := resolveDeploymentMode()
	if mode != ModeSystem {
		t.Fatalf("expected mode=system, got %s", mode)
	}

	// System mode should not depend on XDG/HOME.
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("XDG_RUNTIME_DIR", "")

	configPath := getConfigPath()
	if configPath != "/etc/docker-helper/config.json" {
		t.Errorf("configPath = %q, want /etc/docker-helper/config.json", configPath)
	}

	stateDir := getStateDir()
	if stateDir != "/var/lib/docker-helper" {
		t.Errorf("stateDir = %q, want /var/lib/docker-helper", stateDir)
	}

	runtimeDir, err := getRuntimeDir()
	if err != nil {
		t.Fatalf("getRuntimeDir() error: %v", err)
	}
	if runtimeDir != "/run/docker-helper" {
		t.Errorf("runtimeDir = %q, want /run/docker-helper", runtimeDir)
	}

	// XDG values should not affect system mode defaults.
	t.Setenv("XDG_CONFIG_HOME", "/should/not/use")
	t.Setenv("XDG_STATE_HOME", "/should/not/use")
	t.Setenv("XDG_RUNTIME_DIR", "/should/not/use")

	configPath = getConfigPath()
	if configPath != "/etc/docker-helper/config.json" {
		t.Errorf("configPath = %q, want /etc/docker-helper/config.json", configPath)
	}

	stateDir = getStateDir()
	if stateDir != "/var/lib/docker-helper" {
		t.Errorf("stateDir = %q, want /var/lib/docker-helper", stateDir)
	}

	runtimeDir, err = getRuntimeDir()
	if err != nil {
		t.Fatalf("getRuntimeDir() error: %v", err)
	}
	if runtimeDir != "/run/docker-helper" {
		t.Errorf("runtimeDir = %q, want /run/docker-helper", runtimeDir)
	}
}

func TestSystemModeSocketAndDB(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	t.Setenv("XDG_RUNTIME_DIR", "")

	runtimeDir, _ := getRuntimeDir()
	stateDir := getStateDir()

	socketPath := filepath.Join(runtimeDir, "docker-helper.sock")
	if socketPath != "/run/docker-helper/docker-helper.sock" {
		t.Errorf("socketPath = %q, want /run/docker-helper/docker-helper.sock", socketPath)
	}

	dbPath := filepath.Join(stateDir, "docker-helper.db")
	if dbPath != "/var/lib/docker-helper/docker-helper.db" {
		t.Errorf("dbPath = %q, want /var/lib/docker-helper/docker-helper.db", dbPath)
	}

	configDir := filepath.Dir(getConfigPath())
	adminTokenPath := filepath.Join(configDir, "admin.token")
	if adminTokenPath != "/etc/docker-helper/admin.token" {
		t.Errorf("adminTokenPath = %q, want /etc/docker-helper/admin.token", adminTokenPath)
	}
}

func TestDOCKER_HELPER_CONFIGOverride(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	t.Setenv("DOCKER_HELPER_CONFIG", "/custom/path/config.json")
	configPath := getConfigPath()
	if configPath != "/custom/path/config.json" {
		t.Errorf("configPath = %q, want /custom/path/config.json", configPath)
	}

	// Mode should still be system.
	mode := resolveDeploymentMode()
	if mode != ModeSystem {
		t.Errorf("mode = %q, want system", mode)
	}

	// State/runtime should still be system defaults.
	stateDir := getStateDir()
	if stateDir != "/var/lib/docker-helper" {
		t.Errorf("stateDir = %q, want /var/lib/docker-helper", stateDir)
	}

	runtimeDir, _ := getRuntimeDir()
	if runtimeDir != "/run/docker-helper" {
		t.Errorf("runtimeDir = %q, want /run/docker-helper", runtimeDir)
	}

	// Admin token should be beside the custom config.
	configDir := filepath.Dir(configPath)
	adminTokenPath := filepath.Join(configDir, "admin.token")
	if adminTokenPath != "/custom/path/admin.token" {
		t.Errorf("adminTokenPath = %q, want /custom/path/admin.token", adminTokenPath)
	}
}

func TestModeCannotBeConfigured(t *testing.T) {
	// "mode" is read-only and should be rejected in config.json.
	if !isReadOnlyField("mode") {
		t.Error("mode should be read-only")
	}
}

func TestModeCLIUser(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 1000 }

	var stdout, stderr strings.Builder
	code := runCommandWithWriters([]string{"config", "show", "mode"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("config show mode exited %d, stderr: %s", code, stderr.String())
	}
	out := strings.TrimSpace(stdout.String())
	if out != "user" {
		t.Errorf("mode = %q, want user", out)
	}
}

func TestModeCLISystem(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	var stdout, stderr strings.Builder
	code := runCommandWithWriters([]string{"config", "show", "mode"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("config show mode exited %d, stderr: %s", code, stderr.String())
	}
	out := strings.TrimSpace(stdout.String())
	if out != "system" {
		t.Errorf("mode = %q, want system", out)
	}
}

func TestSystemModeRuntimeDirSafe(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	t.Setenv("XDG_RUNTIME_DIR", "")
	runtimeDir := getRuntimeDirSafe()
	if runtimeDir != "/run/docker-helper" {
		t.Errorf("runtimeDir = %q, want /run/docker-helper", runtimeDir)
	}
}

func TestSystemModeDirectoryPermissions(t *testing.T) {
	orig := EffectiveUID
	defer func() { EffectiveUID = orig }()
	EffectiveUID = func() int { return 0 }

	dir := t.TempDir()

	// Simulate system mode directory creation.
	configDir := filepath.Join(dir, "etc", "docker-helper")
	stateDir := filepath.Join(dir, "var", "lib", "docker-helper")
	runtimeDir := filepath.Join(dir, "run", "docker-helper")

	// Config dir: 0755 for system mode.
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("cannot create config dir: %v", err)
	}
	info, err := os.Stat(configDir)
	if err != nil {
		t.Fatalf("cannot stat config dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0755 {
		t.Errorf("config dir perm = %o, want 0755", got)
	}

	// State dir: 0700.
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatalf("cannot create state dir: %v", err)
	}
	info, err = os.Stat(stateDir)
	if err != nil {
		t.Fatalf("cannot stat state dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0700 {
		t.Errorf("state dir perm = %o, want 0700", got)
	}

	// Runtime dir: 0755 for system mode (future multi-user socket).
	if err := os.MkdirAll(runtimeDir, 0755); err != nil {
		t.Fatalf("cannot create runtime dir: %v", err)
	}
	info, err = os.Stat(runtimeDir)
	if err != nil {
		t.Fatalf("cannot stat runtime dir: %v", err)
	}
	if got := info.Mode().Perm(); got != 0755 {
		t.Errorf("runtime dir perm = %o, want 0755", got)
	}
}
