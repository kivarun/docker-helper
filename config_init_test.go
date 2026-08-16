package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Init core tests ---

func TestInitCoreCreatesConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Use a real directory for the allowed root
	rootDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	result, err := initCore(rootDir, &stdout, &stderr)
	if err != nil {
		t.Fatalf("initCore failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.allowedRoot != rootDir {
		t.Errorf("expected allowedRoot %s, got %s", rootDir, result.allowedRoot)
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

	rootDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	_, err := initCore(rootDir, &stdout, &stderr)
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

	rootDir := testAllowedRootDir(t)

	var addCalledPath string
	addRoot := func(path string) (rootResult, error) {
		addCalledPath = path
		return rootResult{Path: path, Changed: true}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		return rootResult{Path: path, Changed: true}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor(rootDir, &stdout, &stderr, addRoot, removeRoot,
		func(ar string, so, se io.Writer) error {
			_, err := initCore(ar, so, se)
			return err
		})
	if err != nil {
		t.Fatalf("initSystemWithAppArmor failed: %v", err)
	}

	if addCalledPath != rootDir {
		t.Errorf("expected addRoot called with %s, got %s", rootDir, addCalledPath)
	}

	// Verify AppArmor status message
	if !strings.Contains(stdout.String(), "AppArmor workspace root added") {
		t.Errorf("expected AppArmor status message, got: %s", stdout.String())
	}
}

func TestInitSystemAddRootFailure(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	rootDir := t.TempDir()

	coreCalled := false
	addRoot := func(path string) (rootResult, error) {
		return rootResult{}, errors.New("AppArmor add failed")
	}
	removeRoot := func(path string) (rootResult, error) {
		t.Error("removeRoot should not be called on add failure")
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor(rootDir, &stdout, &stderr, addRoot, removeRoot,
		func(ar string, so, se io.Writer) error {
			coreCalled = true
			return nil
		})
	if err == nil {
		t.Fatal("expected error for AppArmor add failure")
	}

	if coreCalled {
		t.Error("core should not be called on AppArmor add failure")
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

	rootDir := testAllowedRootDir(t)
	// Distinct path that addRoot returns to prove rollback uses result.Path
	distinctPath := filepath.Join(rootDir, "distinct-apparmor-path")

	var rollbackCalled bool
	var rollbackPath string
	addRoot := func(path string) (rootResult, error) {
		// Return a different path than requested to prove rollback uses result.Path
		return rootResult{Path: distinctPath, Changed: true}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		rollbackCalled = true
		rollbackPath = path
		return rootResult{Path: path, Changed: true}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor(rootDir, &stdout, &stderr, addRoot, removeRoot,
		func(ar string, so, se io.Writer) error {
			return errors.New("core init failed")
		})
	if err == nil {
		t.Fatal("expected error for core failure")
	}

	if !rollbackCalled {
		t.Error("removeRoot should have been called for rollback")
	}
	if rollbackPath != distinctPath {
		t.Errorf("expected rollback with addRoot result.Path %s, got %s", distinctPath, rollbackPath)
	}
	// Verify rollback did NOT use the original requested path
	if rollbackPath == rootDir {
		t.Error("rollback should use addRoot result.Path, not original requested path")
	}
}

func TestInitSystemCoreFailureNoRollbackWhenNotChanged(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	rootDir := t.TempDir()

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
	err := initSystemWithAppArmor(rootDir, &stdout, &stderr, addRoot, removeRoot,
		func(ar string, so, se io.Writer) error {
			return errors.New("core init failed")
		})
	if err == nil {
		t.Fatal("expected error for core failure")
	}

	if rollbackCalled {
		t.Error("removeRoot should not be called when root was already present")
	}
}

func TestInitSystemRollbackFailureReportsBothErrors(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	rootDir := testAllowedRootDir(t)

	addRoot := func(path string) (rootResult, error) {
		return rootResult{Path: path, Changed: true}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		return rootResult{}, errors.New("rollback failed")
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor(rootDir, &stdout, &stderr, addRoot, removeRoot,
		func(ar string, so, se io.Writer) error {
			return errors.New("core init failed")
		})
	if err == nil {
		t.Fatal("expected error for core failure")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "core init failed") {
		t.Errorf("expected original error in message, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "rollback") {
		t.Errorf("expected rollback error in message, got: %s", errMsg)
	}
}

func TestInitSystemExistingConfigMismatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Create two real directories for the mismatch
	baseDir := testAllowedRootDir(t)
	oldRoot := filepath.Join(baseDir, "old")
	newRoot := filepath.Join(baseDir, "new")
	for _, d := range []string{oldRoot, newRoot} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Create existing config with old root
	configPath := filepath.Join(dir, "docker-helper", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	configData := fmt.Sprintf(`{"allowed_root": %q, "session_ttl": "12h"}`, oldRoot)
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	addCalled := false
	addRoot := func(path string) (rootResult, error) {
		addCalled = true
		return rootResult{}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		t.Error("removeRoot should not be called on config mismatch")
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor(newRoot, &stdout, &stderr, addRoot, removeRoot,
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called on config mismatch")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for config mismatch")
	}

	if addCalled {
		t.Error("addRoot should not be called on config mismatch")
	}

	// Verify exact error message with canonical paths
	expectedMsg := fmt.Sprintf("existing configuration allowed_root is %s, but init requested %s", oldRoot, newRoot)
	if err.Error() != expectedMsg {
		t.Errorf("exact mismatch error expected\ngot:  %s\nwant: %s", err.Error(), expectedMsg)
	}
}

func TestInitSystemExistingConfigMatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Create real directory for the matching root
	rootDir := testAllowedRootDir(t)

	// Create existing config with matching allowed_root
	configPath := filepath.Join(dir, "docker-helper", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	configData := fmt.Sprintf(`{"allowed_root": %q, "session_ttl": "12h"}`, rootDir)
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
	err := initSystemWithAppArmor(rootDir, &stdout, &stderr, addRoot, removeRoot,
		func(ar string, so, se io.Writer) error {
			_, err := initCore(ar, so, se)
			return err
		})
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

func TestInitSystemExistingTokenNoAppArmor(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	rootDir := t.TempDir()

	// Create existing token
	tokenPath := filepath.Join(dir, "docker-helper", "admin.token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("existing\n"), 0600); err != nil {
		t.Fatal(err)
	}

	addCalled := false
	addRoot := func(path string) (rootResult, error) {
		addCalled = true
		return rootResult{}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		t.Error("removeRoot should not be called")
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor(rootDir, &stdout, &stderr, addRoot, removeRoot,
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called when token exists")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for existing token")
	}

	if addCalled {
		t.Error("addRoot should not be called when token already exists")
	}
}

func TestInitSystemAlreadyPresent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	rootDir := testAllowedRootDir(t)

	addRoot := func(path string) (rootResult, error) {
		return rootResult{Path: path, Changed: false}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		t.Error("removeRoot should not be called")
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor(rootDir, &stdout, &stderr, addRoot, removeRoot,
		func(ar string, so, se io.Writer) error {
			_, err := initCore(ar, so, se)
			return err
		})
	if err != nil {
		t.Fatalf("initSystemWithAppArmor failed: %v", err)
	}

	if !strings.Contains(stdout.String(), "already present") {
		t.Errorf("expected 'already present' message, got: %s", stdout.String())
	}
}

// --- User mode tests ---

func TestInitUserModeNoAppArmor(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	rootDir := t.TempDir()

	// Save and restore EffectiveUID
	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = origUID }()

	var stdout, stderr bytes.Buffer
	err := runInit(rootDir, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runInit failed: %v", err)
	}

	// Verify no AppArmor status message in stdout
	if strings.Contains(stdout.String(), "workspace root added") ||
		strings.Contains(stdout.String(), "workspace root already present") {
		t.Errorf("user mode should not print AppArmor status, got: %s", stdout.String())
	}
}

func TestInitUserModeNoAppArmorRestrictions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Create a directory with a name that AppArmor would reject (glob character)
	rootDir := filepath.Join(dir, "workspace*")
	if err := os.MkdirAll(rootDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Save and restore EffectiveUID
	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = origUID }()

	var stdout, stderr bytes.Buffer
	err := runInit(rootDir, &stdout, &stderr)
	if err != nil {
		t.Fatalf("user mode should not apply AppArmor restrictions, got: %v", err)
	}
}

// --- Input error exit code tests ---

func TestInitSystemInvalidAppArmorPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	rootDir := testAllowedRootDir(t)

	addRoot := func(path string) (rootResult, error) {
		// Simulate AppArmor rejecting the path with input error
		return rootResult{}, &inputError{msg: "path contains invalid character"}
	}
	removeRoot := func(path string) (rootResult, error) {
		t.Error("removeRoot should not be called on input error from addRoot")
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor(rootDir, &stdout, &stderr, addRoot, removeRoot,
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called on input error from addRoot")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for invalid AppArmor path")
	}

	var ie *inputError
	if !errors.As(err, &ie) {
		t.Error("expected inputError")
	}
}

// --- Ordering tests ---

func TestInitSystemOrderingAddRootBeforeCore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	rootDir := testAllowedRootDir(t)

	var order []string
	addRoot := func(path string) (rootResult, error) {
		order = append(order, "addRoot")
		return rootResult{Path: path, Changed: true}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		order = append(order, "removeRoot")
		return rootResult{Path: path, Changed: true}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor(rootDir, &stdout, &stderr, addRoot, removeRoot,
		func(ar string, so, se io.Writer) error {
			order = append(order, "core")
			_, err := initCore(ar, so, se)
			return err
		})
	if err != nil {
		t.Fatalf("initSystemWithAppArmor failed: %v", err)
	}

	// Verify ordering: addRoot before core
	if len(order) < 2 || order[0] != "addRoot" || order[1] != "core" {
		t.Errorf("expected addRoot before core, got order: %v", order)
	}
}

// --- CLI integration tests ---

func TestInitCLIInputErrorExitCode(t *testing.T) {
	dir := t.TempDir()

	// Create two real directories for the mismatch
	oldRoot := t.TempDir()
	newRoot := t.TempDir()

	// Create existing config with mismatch at a controlled path
	configPath := filepath.Join(dir, "config.json")
	configData := fmt.Sprintf(`{"allowed_root": %q, "session_ttl": "12h"}`, oldRoot)
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	// Mock system mode, config path, and inject fake AppArmor operations
	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	origAdd := appArmorAddRoot
	origRemove := appArmorRemoveRoot
	EffectiveUID = func() int { return 0 }
	getConfigPathFunc = func() string { return configPath }
	appArmorAddRoot = func() func(string) (rootResult, error) {
		return func(path string) (rootResult, error) {
			t.Error("addRoot should not be called on mismatch")
			return rootResult{}, nil
		}
	}
	appArmorRemoveRoot = func() func(string) (rootResult, error) {
		return func(path string) (rootResult, error) {
			t.Error("removeRoot should not be called on mismatch")
			return rootResult{}, nil
		}
	}
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
		appArmorAddRoot = origAdd
		appArmorRemoveRoot = origRemove
	}()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", newRoot}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for input error, got %d (stderr: %s)", code, stderr.String())
	}
}

func TestInitCLIAppArmorInputErrorExit2(t *testing.T) {
	dir := t.TempDir()

	rootDir := t.TempDir()

	// Mock system mode, config path, and inject fake AppArmor that returns inputError
	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	origAdd := appArmorAddRoot
	origRemove := appArmorRemoveRoot
	EffectiveUID = func() int { return 0 }
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	appArmorAddRoot = func() func(string) (rootResult, error) {
		return func(path string) (rootResult, error) {
			return rootResult{}, &inputError{msg: "path contains invalid character"}
		}
	}
	appArmorRemoveRoot = func() func(string) (rootResult, error) {
		return func(path string) (rootResult, error) {
			t.Error("removeRoot should not be called on add failure")
			return rootResult{}, nil
		}
	}
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
		appArmorAddRoot = origAdd
		appArmorRemoveRoot = origRemove
	}()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", rootDir}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for typed inputError, got %d (stderr: %s)", code, stderr.String())
	}
}

func TestInitCLIAppArmorOperationalErrorExit1(t *testing.T) {
	dir := t.TempDir()

	rootDir := testAllowedRootDir(t)

	// Mock system mode, config path, and inject fake AppArmor that returns operational error
	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	origAdd := appArmorAddRoot
	origRemove := appArmorRemoveRoot
	EffectiveUID = func() int { return 0 }
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	appArmorAddRoot = func() func(string) (rootResult, error) {
		return func(path string) (rootResult, error) {
			return rootResult{}, errors.New("parser failed")
		}
	}
	appArmorRemoveRoot = func() func(string) (rootResult, error) {
		return func(path string) (rootResult, error) {
			t.Error("removeRoot should not be called on add failure")
			return rootResult{}, nil
		}
	}
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
		appArmorAddRoot = origAdd
		appArmorRemoveRoot = origRemove
	}()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", rootDir}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 for operational error, got %d (stderr: %s)", code, stderr.String())
	}
}

func TestInitHelpContainsAutomationBoundary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 for help, got %d", code)
	}

	helpText := stdout.String()

	// Verify help documents automation boundary
	if !strings.Contains(helpText, "automatically") {
		t.Error("help should mention automatic AppArmor integration")
	}
	if !strings.Contains(helpText, "docker-helper apparmor root add") {
		t.Error("help should mention manual root management command")
	}
	if !strings.Contains(helpText, "System mode") {
		t.Error("help should mention system mode")
	}
	if !strings.Contains(helpText, "User mode") {
		t.Error("help should mention user mode")
	}
}

// --- Rollback Changed=false not an error ---

func TestInitSystemRollbackChangedFalseNotError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	rootDir := testAllowedRootDir(t)

	addRoot := func(path string) (rootResult, error) {
		return rootResult{Path: path, Changed: true}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		// Rollback succeeds but reports Changed=false (desired state already reached)
		return rootResult{Path: path, Changed: false}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor(rootDir, &stdout, &stderr, addRoot, removeRoot,
		func(ar string, so, se io.Writer) error {
			return errors.New("core init failed")
		})
	if err == nil {
		t.Fatal("expected error for core failure")
	}

	// The error should be the core failure, not a rollback error
	if !strings.Contains(err.Error(), "core init failed") {
		t.Errorf("expected core failure in error, got: %v", err)
	}
	// Should NOT contain rollback error
	if strings.Contains(err.Error(), "rollback") {
		t.Errorf("should not report rollback error when Changed=false, got: %v", err)
	}
}

// --- Existing config as directory -> preflight failure ---

func TestInitSystemConfigPathIsDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	rootDir := t.TempDir()

	// Create config.json as a directory
	configPath := filepath.Join(dir, "docker-helper", "config.json")
	if err := os.MkdirAll(configPath, 0755); err != nil {
		t.Fatal(err)
	}

	addCalled := false
	addRoot := func(path string) (rootResult, error) {
		addCalled = true
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor(rootDir, &stdout, &stderr, addRoot,
		func(path string) (rootResult, error) {
			t.Error("removeRoot should not be called")
			return rootResult{}, nil
		},
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for config path as directory")
	}

	if addCalled {
		t.Error("addRoot should not be called when config path is a directory")
	}

	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("expected directory error, got: %v", err)
	}
}

// --- Existing config read error ---

func TestInitSystemExistingConfigReadError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	rootDir := t.TempDir()

	// Create config file without read permissions
	configPath := filepath.Join(dir, "docker-helper", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`{"allowed_root": "`+rootDir+`", "session_ttl": "12h"}`), 0000); err != nil {
		t.Fatal(err)
	}
	defer func() { os.Chmod(configPath, 0600) }() // Cleanup

	addCalled := false
	addRoot := func(path string) (rootResult, error) {
		addCalled = true
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor(rootDir, &stdout, &stderr, addRoot,
		func(path string) (rootResult, error) {
			t.Error("removeRoot should not be called")
			return rootResult{}, nil
		},
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for config read error")
	}

	if addCalled {
		t.Error("addRoot should not be called when config read fails")
	}

	if !strings.Contains(err.Error(), "read") {
		t.Errorf("expected read error, got: %v", err)
	}
}

// --- Validate raw config error ---

func TestInitSystemExistingConfigInvalid(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	rootDir := t.TempDir()

	// Create invalid config
	configPath := filepath.Join(dir, "docker-helper", "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	// Missing required field
	configData := `{"session_ttl": "12h"}`
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	addCalled := false
	addRoot := func(path string) (rootResult, error) {
		addCalled = true
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystemWithAppArmor(rootDir, &stdout, &stderr, addRoot,
		func(path string) (rootResult, error) {
			t.Error("removeRoot should not be called")
			return rootResult{}, nil
		},
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for invalid config")
	}

	if addCalled {
		t.Error("addRoot should not be called when config is invalid")
	}

	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("expected invalid config error, got: %v", err)
	}
}

// --- Validate raw config validation ---

func TestValidateRawConfigRejectsMissingAllowedRoot(t *testing.T) {
	raw := map[string]json.RawMessage{
		"session_ttl": json.RawMessage(`"12h"`),
	}
	err := validateRawConfig(raw)
	if err == nil {
		t.Fatal("expected error for missing allowed_root")
	}
	if !strings.Contains(err.Error(), "allowed_root") {
		t.Errorf("expected allowed_root error, got: %v", err)
	}
}

func TestValidateRawConfigRejectsRelativeAllowedRoot(t *testing.T) {
	raw := map[string]json.RawMessage{
		"allowed_root": json.RawMessage(`"relative"`),
		"session_ttl":  json.RawMessage(`"12h"`),
	}
	err := validateRawConfig(raw)
	if err == nil {
		t.Fatal("expected error for relative allowed_root")
	}
}
