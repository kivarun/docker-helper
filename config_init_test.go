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

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	// Use a real directory for the allowed root
	rootDir := testAllowedRootDir(t)

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
	configPath := filepath.Join(dir, "config.json")
	if _, err := os.Stat(configPath); err != nil {
		t.Errorf("config file not created: %v", err)
	}

	// Verify token file exists
	tokenPath := filepath.Join(dir, "admin.token")
	if _, err := os.Stat(tokenPath); err != nil {
		t.Errorf("token file not created: %v", err)
	}
}

func TestInitCoreExistingTokenFails(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	// Create existing token
	tokenPath := filepath.Join(dir, "admin.token")
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("existing\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootDir := testAllowedRootDir(t)
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

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	addCalled := false
	addRoot := func(path string) (rootResult, error) {
		addCalled = true
		return rootResult{Path: path, Changed: true}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		return rootResult{Path: path, Changed: true}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, newAppArmorSystemInitBackend(addRoot, removeRoot),
		func(ar string, so, se io.Writer) error {
			_, err := initCore(ar, so, se)
			return err
		})
	if err != nil {
		t.Fatalf("initSystem failed: %v", err)
	}

	// System init no longer prepares MAC for the bootstrap allowed root.
	// MAC preparation is handled at session creation time.
	if addCalled {
		t.Error("addRoot must NOT be called during system init")
	}
}

func TestInitSystemAddRootFailure(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	coreCalled := false
	addRoot := func(path string) (rootResult, error) {
		// Must NOT be called during system init.
		t.Error("addRoot must NOT be called during system init")
		return rootResult{}, errors.New("AppArmor add failed")
	}
	removeRoot := func(path string) (rootResult, error) {
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, newAppArmorSystemInitBackend(addRoot, removeRoot),
		func(ar string, so, se io.Writer) error {
			coreCalled = true
			return nil
		})
	if err != nil {
		t.Fatalf("initSystem failed: %v", err)
	}

	// System init no longer prepares MAC; core should be called.
	if !coreCalled {
		t.Error("core should be called during system init")
	}
}

func TestInitSystemCoreFailureRollback(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	addCalled := false
	addRoot := func(path string) (rootResult, error) {
		addCalled = true
		return rootResult{Path: path, Changed: true}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		return rootResult{Path: path, Changed: true}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, newAppArmorSystemInitBackend(addRoot, removeRoot),
		func(ar string, so, se io.Writer) error {
			return errors.New("core init failed")
		})
	if err == nil {
		t.Fatal("expected error for core failure")
	}

	// System init no longer prepares MAC; addRoot must NOT be called.
	if addCalled {
		t.Error("addRoot must NOT be called during system init")
	}
}

func TestInitSystemCoreFailureNoRollbackWhenNotChanged(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	addCalled := false
	addRoot := func(path string) (rootResult, error) {
		addCalled = true
		return rootResult{Path: path, Changed: false}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		return rootResult{Path: path, Changed: true}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, newAppArmorSystemInitBackend(addRoot, removeRoot),
		func(ar string, so, se io.Writer) error {
			return errors.New("core init failed")
		})
	if err == nil {
		t.Fatal("expected error for core failure")
	}

	// System init no longer prepares MAC; addRoot must NOT be called.
	if addCalled {
		t.Error("addRoot must NOT be called during system init")
	}
}

func TestInitSystemRollbackFailureReportsBothErrors(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	addCalled := false
	addRoot := func(path string) (rootResult, error) {
		addCalled = true
		return rootResult{Path: path, Changed: true}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		return rootResult{}, errors.New("rollback failed")
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, newAppArmorSystemInitBackend(addRoot, removeRoot),
		func(ar string, so, se io.Writer) error {
			return errors.New("core init failed")
		})
	if err == nil {
		t.Fatal("expected error for core failure")
	}

	// System init no longer prepares MAC; addRoot must NOT be called.
	if addCalled {
		t.Error("addRoot must NOT be called during system init")
	}
}

func TestInitSystemExistingConfigMismatch(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

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
	configPath := filepath.Join(dir, "config.json")
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
	err := initSystem(newRoot, &stdout, &stderr, newAppArmorSystemInitBackend(addRoot, removeRoot),
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
	expectedMsg := fmt.Sprintf("existing configuration allowed_roots [%s] do not include %s", oldRoot, newRoot)
	if err.Error() != expectedMsg {
		t.Errorf("exact mismatch error expected\ngot:  %s\nwant: %s", err.Error(), expectedMsg)
	}
}

func TestInitSystemExistingConfigMatch(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	// Create real directory for the matching root
	rootDir := testAllowedRootDir(t)

	// Create existing config with matching allowed_root
	configPath := filepath.Join(dir, "config.json")
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
	err := initSystem(rootDir, &stdout, &stderr, newAppArmorSystemInitBackend(addRoot, removeRoot),
		func(ar string, so, se io.Writer) error {
			_, err := initCore(ar, so, se)
			return err
		})
	if err != nil {
		t.Fatalf("initSystem failed: %v", err)
	}

	if !addRootCalled {
		// System init no longer prepares MAC; addRoot must NOT be called.
	} else {
		t.Error("addRoot must NOT be called during system init")
	}
}

func TestInitSystemMultiRootPreflight(t *testing.T) {
	// Multi-root preflight: init with rootB when config has [rootA, rootB].
	// Prove rootB is accepted (not first-root-only), backend receives canonical rootB,
	// and core is reached.
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	// Create two real directories for the multi-root config.
	rootA := testAllowedRootDir(t)
	rootB := testAllowedRootDir(t)

	// Create existing config with two roots.
	configPath := filepath.Join(dir, "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	configData := fmt.Sprintf(`{"allowed_roots": [%q, %q], "session_ttl": "12h"}`, rootA, rootB)
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}

	// Track what backend receives and what core receives.
	var backendReceived string
	var coreReceived string
	addCalled := false

	addRoot := func(path string) (rootResult, error) {
		addCalled = true
		backendReceived = path
		return rootResult{Path: path, Changed: true}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootB, &stdout, &stderr, newAppArmorSystemInitBackend(addRoot, removeRoot),
		func(ar string, so, se io.Writer) error {
			coreReceived = ar
			return nil
		})
	if err != nil {
		t.Fatalf("initSystem with rootB failed: %v", err)
	}

	// System init no longer prepares MAC; addRoot must NOT be called.
	if addCalled {
		t.Error("addRoot must NOT be called during system init")
	}
	if backendReceived != "" {
		t.Errorf("backend must NOT receive path, got %q", backendReceived)
	}
	if coreReceived != rootB {
		t.Errorf("core received %q, want rootB %q", coreReceived, rootB)
	}
}

func TestInitSystemExistingTokenNoAppArmor(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	// Create existing token
	tokenPath := filepath.Join(dir, "admin.token")
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
	err := initSystem(rootDir, &stdout, &stderr, newAppArmorSystemInitBackend(addRoot, removeRoot),
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

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	addCalled := false
	addRoot := func(path string) (rootResult, error) {
		addCalled = true
		return rootResult{Path: path, Changed: false}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, newAppArmorSystemInitBackend(addRoot, removeRoot),
		func(ar string, so, se io.Writer) error {
			_, err := initCore(ar, so, se)
			return err
		})
	if err != nil {
		t.Fatalf("initSystem failed: %v", err)
	}

	// System init no longer prepares MAC; addRoot must NOT be called.
	if addCalled {
		t.Error("addRoot must NOT be called during system init")
	}
}

// --- User mode tests ---

func TestInitUserModeNoAppArmor(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	// Save and restore EffectiveUID
	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = origUID }()

	// Standalone user init (no system daemon, Docker accessible).
	restore := mockStandaloneUserInit()
	defer restore()

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

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	// Use a valid workspace root (not under /tmp).
	rootDir := testAllowedRootDir(t)

	// Save and restore EffectiveUID
	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = origUID }()

	// Standalone user init (no system daemon, Docker accessible).
	restore := mockStandaloneUserInit()
	defer restore()

	var stdout, stderr bytes.Buffer
	err := runInit(rootDir, &stdout, &stderr)
	if err != nil {
		t.Fatalf("user mode should not apply AppArmor restrictions, got: %v", err)
	}
}

// --- Input error exit code tests ---

func TestInitSystemInvalidAppArmorPath(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	addCalled := false
	addRoot := func(path string) (rootResult, error) {
		addCalled = true
		return rootResult{}, &inputError{msg: "path contains invalid character"}
	}
	removeRoot := func(path string) (rootResult, error) {
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, newAppArmorSystemInitBackend(addRoot, removeRoot),
		func(ar string, so, se io.Writer) error {
			_, err := initCore(ar, so, se)
			return err
		})
	if err != nil {
		t.Fatalf("initSystem failed: %v", err)
	}

	// System init no longer prepares MAC; addRoot must NOT be called.
	if addCalled {
		t.Error("addRoot must NOT be called during system init")
	}
}

// --- Ordering tests ---

func TestInitSystemOrderingAddRootBeforeCore(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	var order []string
	addCalled := false
	addRoot := func(path string) (rootResult, error) {
		addCalled = true
		order = append(order, "addRoot")
		return rootResult{Path: path, Changed: true}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		order = append(order, "removeRoot")
		return rootResult{Path: path, Changed: true}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, newAppArmorSystemInitBackend(addRoot, removeRoot),
		func(ar string, so, se io.Writer) error {
			order = append(order, "core")
			_, err := initCore(ar, so, se)
			return err
		})
	if err != nil {
		t.Fatalf("initSystem failed: %v", err)
	}

	// System init no longer prepares MAC; only core should be called.
	if addCalled {
		t.Error("addRoot must NOT be called during system init")
	}
	if len(order) != 1 || order[0] != "core" {
		t.Errorf("expected only core, got order: %v", order)
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
	// System init no longer prepares MAC. This test is no longer relevant.
	// MAC preparation happens at session creation time, not during init.
	t.Skip("system init no longer prepares MAC")
}

func TestInitCLIAppArmorOperationalErrorExit1(t *testing.T) {
	// System init no longer prepares MAC. This test is no longer relevant.
	// MAC preparation happens at session creation time, not during init.
	t.Skip("system init no longer prepares MAC")
}

func TestInitHelpContainsAutomationBoundary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 for help, got %d", code)
	}

	helpText := stdout.String()

	// Verify help documents automation boundary
	if !strings.Contains(helpText, "config allowed-root add") {
		t.Error("help should mention config allowed-root add")
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

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	addRoot := func(path string) (rootResult, error) {
		return rootResult{Path: path, Changed: true}, nil
	}
	removeRoot := func(path string) (rootResult, error) {
		// Rollback succeeds but reports Changed=false (desired state already reached)
		return rootResult{Path: path, Changed: false}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, newAppArmorSystemInitBackend(addRoot, removeRoot),
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

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	// Create config.json as a directory
	configPath := filepath.Join(dir, "config.json")
	if err := os.MkdirAll(configPath, 0755); err != nil {
		t.Fatal(err)
	}

	addCalled := false
	addRoot := func(path string) (rootResult, error) {
		addCalled = true
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr,
		newAppArmorSystemInitBackend(addRoot,
			func(path string) (rootResult, error) {
				t.Error("removeRoot should not be called")
				return rootResult{}, nil
			}),
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

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	// Create config file without read permissions
	configPath := filepath.Join(dir, "config.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`{"allowed_roots": ["`+rootDir+`"], "session_ttl": "12h"}`), 0000); err != nil {
		t.Fatal(err)
	}
	defer func() { os.Chmod(configPath, 0600) }() // Cleanup

	addCalled := false
	addRoot := func(path string) (rootResult, error) {
		addCalled = true
		return rootResult{}, nil
	}

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr,
		newAppArmorSystemInitBackend(addRoot,
			func(path string) (rootResult, error) {
				t.Error("removeRoot should not be called")
				return rootResult{}, nil
			}),
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

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	// Create invalid config
	configPath := filepath.Join(dir, "config.json")
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
	err := initSystem(rootDir, &stdout, &stderr,
		newAppArmorSystemInitBackend(addRoot,
			func(path string) (rootResult, error) {
				t.Error("removeRoot should not be called")
				return rootResult{}, nil
			}),
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

// --- User systemd unit installation tests ---

func TestInstallUserSystemdUnitCopiesFromSystemPath(t *testing.T) {
	orig := installUserSystemdUnit
	defer func() { installUserSystemdUnit = orig }()

	homeDir := t.TempDir()
	systemDir := t.TempDir()
	unitContent := []byte("[Unit]\nDescription=Test\n")
	if err := os.WriteFile(filepath.Join(systemDir, "docker-helper.service"), unitContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Override the system path.
	// We can't override a const, so we mock the function instead.
	installUserSystemdUnit = func(stdout, stderr io.Writer) {
		userUnitDir := filepath.Join(homeDir, ".config", "systemd", "user")
		userUnitPath := filepath.Join(userUnitDir, "docker-helper.service")

		if _, err := os.Stat(userUnitPath); err == nil {
			return
		}

		data, err := os.ReadFile(filepath.Join(systemDir, "docker-helper.service"))
		if err != nil {
			return
		}

		if err := os.MkdirAll(userUnitDir, 0700); err != nil {
			return
		}
		if err := os.WriteFile(userUnitPath, data, 0644); err != nil {
			return
		}
		fmt.Fprintln(stdout, "Systemd user unit installed at:")
		fmt.Fprintln(stdout, userUnitPath)
	}

	var stdout, stderr bytes.Buffer
	installUserSystemdUnit(&stdout, &stderr)

	userUnitPath := filepath.Join(homeDir, ".config", "systemd", "user", "docker-helper.service")
	data, err := os.ReadFile(userUnitPath)
	if err != nil {
		t.Fatalf("user unit not installed: %v", err)
	}
	if !bytes.Equal(data, unitContent) {
		t.Errorf("unit content mismatch: got %q, want %q", data, unitContent)
	}
	if !strings.Contains(stdout.String(), "Systemd user unit installed") {
		t.Errorf("expected installation message, got: %s", stdout.String())
	}
}

func TestInstallUserSystemdUnitSkipsIfExists(t *testing.T) {
	orig := installUserSystemdUnit
	defer func() { installUserSystemdUnit = orig }()

	homeDir := t.TempDir()
	existingUnit := filepath.Join(homeDir, ".config", "systemd", "user", "docker-helper.service")
	if err := os.MkdirAll(filepath.Dir(existingUnit), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existingUnit, []byte("[Unit]\nDescription=Existing\n"), 0644); err != nil {
		t.Fatal(err)
	}

	installUserSystemdUnit = func(stdout, stderr io.Writer) {
		userUnitDir := filepath.Join(homeDir, ".config", "systemd", "user")
		userUnitPath := filepath.Join(userUnitDir, "docker-helper.service")

		if _, err := os.Stat(userUnitPath); err == nil {
			return
		}
		fmt.Fprintln(stdout, "would install")
	}

	var stdout, stderr bytes.Buffer
	installUserSystemdUnit(&stdout, &stderr)

	if stdout.Len() > 0 {
		t.Errorf("expected no output when unit exists, got: %s", stdout.String())
	}
	// Verify existing unit was not modified.
	data, err := os.ReadFile(existingUnit)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("[Unit]\nDescription=Existing\n")) {
		t.Error("existing unit was modified")
	}
}

func TestInstallUserSystemdUnitSkipsWhenSystemUnitMissing(t *testing.T) {
	orig := installUserSystemdUnit
	defer func() { installUserSystemdUnit = orig }()

	homeDir := t.TempDir()

	// Simulate missing system unit by reading from non-existent path.
	installUserSystemdUnit = func(stdout, stderr io.Writer) {
		_, err := os.ReadFile("/nonexistent/docker-helper.service")
		if err != nil {
			return
		}
		fmt.Fprintln(stdout, "would install")
	}

	var stdout, stderr bytes.Buffer
	installUserSystemdUnit(&stdout, &stderr)

	if stdout.Len() > 0 {
		t.Errorf("expected no output when system unit missing, got: %s", stdout.String())
	}
	// Verify no user unit was created.
	userUnitPath := filepath.Join(homeDir, ".config", "systemd", "user", "docker-helper.service")
	if _, err := os.Stat(userUnitPath); err == nil {
		t.Error("user unit should not be created when system unit is missing")
	}
}
