package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Init core tests ---

func TestInitCoreCreatesConfig(t *testing.T) {
	dir := t.TempDir()
	oldConfig := os.Getenv("XDG_CONFIG_HOME")
	t.Setenv("XDG_CONFIG_HOME", dir)

	var stdout, stderr bytes.Buffer
	result, err := initCore("/workspace", &stdout, &stderr)
	if err != nil {
		t.Fatalf("initCore failed: %v", err)
	}
	defer os.Setenv("XDG_CONFIG_HOME", oldConfig)

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.allowedRoot != "/workspace" {
		t.Errorf("expected allowedRoot /workspace, got %s", result.allowedRoot)
	}
	if result.token == "" {
		t.Error("expected non-empty token")
	}

	// Verify config file exists
	configPath := filepath.Join(dir, "docker-helper", "config.json")
	if _, err := os.Stat(configPath); err != nil {
		t.Errorf("config file not created: %v", err)
	}

	// Verify token file exists
	tokenPath := filepath.Join(dir, "docker-helper", "admin.token")
	if _, err := os.Stat(tokenPath); err != nil {
		t.Errorf("token file not created: %v", err)
	}
}

func TestInitCoreExistingTokenFails(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Create existing token
	tokenPath := filepath.Join(dir, "docker-helper", "admin.token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("existing\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	_, err := initCore("/workspace", &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for existing token")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' error, got: %v", err)
	}
}

// --- System mode integration tests ---

func TestInitSystemCallsAddRoot(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	called := false
	addCalledPath := ""
	addRoot := func(path string) (rootResult, error) {
		called = true
		addCalledPath = path
		return rootResult{Path: path, Changed: true}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		return rootResult{Path: path, Changed: true}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor("/workspace", &stdout, &stderr, addRoot, removeRoot)
	if err != nil {
		t.Fatalf("initSystemWithAppArmor failed: %v", err)
	}

	if !called {
		t.Error("addRoot should have been called")
	}
	if addCalledPath != "/workspace" {
		t.Errorf("expected addRoot called with /workspace, got %s", addCalledPath)
	}

	// Verify AppArmor status message
	if !strings.Contains(stdout.String(), "AppArmor workspace root added") {
		t.Errorf("expected AppArmor status message, got: %s", stdout.String())
	}
}

func TestInitSystemAddRootFailure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	addRoot := func(path string) (rootResult, error) {
		return rootResult{}, errors.New("AppArmor add failed")
	}
	removeRoot := func(path string) (rootResult, error) {
		t.Error("removeRoot should not be called on add failure")
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor("/workspace", &stdout, &stderr, addRoot, removeRoot)
	if err == nil {
		t.Fatal("expected error for AppArmor add failure")
	}

	// Verify no config created
	configPath := filepath.Join(dir, "docker-helper", "config.json")
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Error("config should not be created on AppArmor failure")
	}
}

func TestInitSystemCoreFailureRollback(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Create existing token to force initCore failure
	tokenPath := filepath.Join(dir, "docker-helper", "admin.token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("existing\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rollbackCalled := false
	rollbackPath := ""
	addRoot := func(path string) (rootResult, error) {
		return rootResult{Path: path, Changed: true}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		rollbackCalled = true
		rollbackPath = path
		return rootResult{Path: path, Changed: true}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor("/workspace", &stdout, &stderr, addRoot, removeRoot)
	if err == nil {
		t.Fatal("expected error for initCore failure")
	}

	if !rollbackCalled {
		t.Error("removeRoot should have been called for rollback")
	}
	if rollbackPath != "/workspace" {
		t.Errorf("expected rollback path /workspace, got %s", rollbackPath)
	}
}

func TestInitSystemCoreFailureNoRollbackWhenNotChanged(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Create existing token to force initCore failure
	tokenPath := filepath.Join(dir, "docker-helper", "admin.token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("existing\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rollbackCalled := false
	addRoot := func(path string) (rootResult, error) {
		// Simulate idempotent add (already present)
		return rootResult{Path: path, Changed: false}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		rollbackCalled = true
		return rootResult{Path: path, Changed: true}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor("/workspace", &stdout, &stderr, addRoot, removeRoot)
	if err == nil {
		t.Fatal("expected error for initCore failure")
	}

	if rollbackCalled {
		t.Error("removeRoot should not be called when root was already present")
	}
}

func TestInitSystemRollbackFailureReportsBothErrors(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Create existing token to force initCore failure
	tokenPath := filepath.Join(dir, "docker-helper", "admin.token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("existing\n"), 0600); err != nil {
		t.Fatal(err)
	}

	addRoot := func(path string) (rootResult, error) {
		return rootResult{Path: path, Changed: true}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		return rootResult{}, errors.New("rollback failed")
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor("/workspace", &stdout, &stderr, addRoot, removeRoot)
	if err == nil {
		t.Fatal("expected error for initCore failure")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "admin.token already exists") {
		t.Errorf("expected original error in message, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "rollback") {
		t.Errorf("expected rollback error in message, got: %s", errMsg)
	}
}

func TestInitSystemExistingConfigMismatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Create existing config with different allowed_root
	configPath := filepath.Join(dir, "docker-helper", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	// Use a path that exists (dir itself)
	configData := `{"allowed_root": "` + dir + `", "session_ttl": "12h"}`
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	// Create the new path that will be requested
	newPath := filepath.Join(dir, "newpath")
	if err := os.MkdirAll(newPath, 0755); err != nil {
		t.Fatal(err)
	}

	addRoot := func(path string) (rootResult, error) {
		t.Error("addRoot should not be called on config mismatch")
		return rootResult{}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		t.Error("removeRoot should not be called on config mismatch")
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor(newPath, &stdout, &stderr, addRoot, removeRoot)
	if err == nil {
		t.Fatal("expected error for config mismatch")
	}

	if !strings.Contains(err.Error(), "existing configuration allowed_root") {
		t.Errorf("expected config mismatch error, got: %v", err)
	}
}

func TestInitSystemExistingConfigMatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Create existing config with matching allowed_root
	configPath := filepath.Join(dir, "docker-helper", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	configData := `{"allowed_root": "/workspace", "session_ttl": "12h"}`
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	addRootCalled := false
	addRoot := func(path string) (rootResult, error) {
		addRootCalled = true
		return rootResult{Path: path, Changed: false}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		t.Error("removeRoot should not be called")
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor("/workspace", &stdout, &stderr, addRoot, removeRoot)
	if err != nil {
		t.Fatalf("initSystemWithAppArmor failed: %v", err)
	}

	if !addRootCalled {
		t.Error("addRoot should be called even with matching config")
	}

	// Verify AppArmor already present message
	if !strings.Contains(stdout.String(), "AppArmor workspace root already present") {
		t.Errorf("expected 'already present' message, got: %s", stdout.String())
	}
}

// --- User mode tests ---

func TestInitUserModeNoAppArmor(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Save and restore EffectiveUID
	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = origUID }()

	var stdout, stderr bytes.Buffer
	err := runInit("/workspace", &stdout, &stderr)
	if err != nil {
		t.Fatalf("runInit failed: %v", err)
	}

	// Verify no AppArmor status message in stdout
	if strings.Contains(stdout.String(), "workspace root added") ||
		strings.Contains(stdout.String(), "workspace root already present") {
		t.Errorf("user mode should not print AppArmor status, got: %s", stdout.String())
	}
}

// --- Input error exit code tests ---

func TestInitSystemInvalidAppArmorPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Create a valid directory for the path
	validPath := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(validPath, 0755); err != nil {
		t.Fatal(err)
	}

	addRoot := func(path string) (rootResult, error) {
		// Simulate AppArmor rejecting the path
		return rootResult{}, &inputError{msg: "path contains invalid character"}
	}
	removeRoot := func(path string) (rootResult, error) {
		t.Error("removeRoot should not be called on input error from addRoot")
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor(validPath, &stdout, &stderr, addRoot, removeRoot)
	if err == nil {
		t.Fatal("expected error for invalid AppArmor path")
	}

	var ie *inputError
	if !errors.As(err, &ie) {
		t.Error("expected inputError")
	}
}

func TestInitSystemAlreadyPresent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	addRoot := func(path string) (rootResult, error) {
		return rootResult{Path: path, Changed: false}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		t.Error("removeRoot should not be called")
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor("/workspace", &stdout, &stderr, addRoot, removeRoot)
	if err != nil {
		t.Fatalf("initSystemWithAppArmor failed: %v", err)
	}

	if !strings.Contains(stdout.String(), "already present") {
		t.Errorf("expected 'already present' message, got: %s", stdout.String())
	}
}

// --- CLI integration tests ---

func TestInitCLIInputErrorExitCode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Create existing config with mismatch
	configPath := filepath.Join(dir, "docker-helper", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	configData := `{"allowed_root": "/old/path", "session_ttl": "12h"}`
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", "/new/path"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for input error, got %d", code)
	}
}

func TestInitCLIAppArmorFailureExitCode(t *testing.T) {
	// This test would require mocking the AppArmor manager
	// For now, we rely on the unit tests above
	t.Skip("requires AppArmor manager mocking")
}
