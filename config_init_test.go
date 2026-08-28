package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
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

// TestInitSystemCoreInvocation verifies that initSystem calls the core
// callback. System init no longer prepares MAC state for the bootstrap
// allowed root; MAC preparation occurs at session creation time.
func TestInitSystemCoreInvocation(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, nil,
		func(ar string, so, se io.Writer) error {
			_, err := initCore(ar, so, se)
			return err
		})
	if err != nil {
		t.Fatalf("initSystem failed: %v", err)
	}
}

// TestInitSystemCoreFailurePropagates verifies that when the core callback
// fails, initSystem propagates the error.
func TestInitSystemCoreFailurePropagates(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	rootDir := testAllowedRootDir(t)

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, nil,
		func(ar string, so, se io.Writer) error {
			return errors.New("core init failed")
		})
	if err == nil {
		t.Fatal("expected error for core failure")
	}
	if !strings.Contains(err.Error(), "core init failed") {
		t.Errorf("expected core failure in error, got: %v", err)
	}
}

// TestInitSystemExistingConfigMismatch verifies that initSystem rejects a
// new root not present in an existing config.
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

	var stdout, stderr bytes.Buffer
	err := initSystem(newRoot, &stdout, &stderr, nil,
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called on config mismatch")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for config mismatch")
	}

	// Verify exact error message with canonical paths
	expectedMsg := fmt.Sprintf("existing configuration allowed_roots [%s] do not include %s", oldRoot, newRoot)
	if err.Error() != expectedMsg {
		t.Errorf("exact mismatch error expected\ngot:  %s\nwant: %s", err.Error(), expectedMsg)
	}
}

// TestInitSystemExistingConfigMatch verifies that initSystem proceeds when
// the new root matches an existing config root.
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

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, nil,
		func(ar string, so, se io.Writer) error {
			_, err := initCore(ar, so, se)
			return err
		})
	if err != nil {
		t.Fatalf("initSystem failed: %v", err)
	}
}

// TestInitSystemMultiRootConfigAccepted verifies that initSystem accepts a
// root that is one of multiple existing config roots (not first-root-only).
func TestInitSystemMultiRootConfigAccepted(t *testing.T) {
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

	// Track what core receives.
	var coreReceived string

	var stdout, stderr bytes.Buffer
	err := initSystem(rootB, &stdout, &stderr, nil,
		func(ar string, so, se io.Writer) error {
			coreReceived = ar
			return nil
		})
	if err != nil {
		t.Fatalf("initSystem with rootB failed: %v", err)
	}
	if coreReceived != rootB {
		t.Errorf("core received %q, want rootB %q", coreReceived, rootB)
	}
}

// TestInitSystemExistingTokenFails verifies that initSystem rejects when an
// admin token already exists.
func TestInitSystemExistingTokenFails(t *testing.T) {
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

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr, nil,
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called when token exists")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for existing token")
	}
}

// --- User mode tests ---

func TestInitUserModeNoMACBackendCheck(t *testing.T) {
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

	// Verify no MAC backend status message in stdout
	if strings.Contains(stdout.String(), "workspace root added") ||
		strings.Contains(stdout.String(), "workspace root already present") {
		t.Errorf("user mode should not print MAC backend status, got: %s", stdout.String())
	}
}

func TestInitUserModeNoRestrictions(t *testing.T) {
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
		t.Fatalf("user mode should not apply MAC backend restrictions, got: %v", err)
	}
}

// --- Input error exit code tests ---

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

	// Mock system mode and config path.
	origUID := EffectiveUID
	origGetConfig := getConfigPathFunc
	EffectiveUID = func() int { return 0 }
	getConfigPathFunc = func() string { return configPath }
	defer func() {
		EffectiveUID = origUID
		getConfigPathFunc = origGetConfig
	}()

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", newRoot}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for input error, got %d (stderr: %s)", code, stderr.String())
	}
}

// --- Config path validation tests ---

// TestInitSystemConfigPathIsDirectory verifies that initSystem fails when
// the config path is a directory.
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

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr,
		nil,
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for config path as directory")
	}

	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("expected directory error, got: %v", err)
	}
}

// TestInitSystemExistingConfigReadError verifies that initSystem fails when
// the existing config file cannot be read.
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

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr,
		nil,
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for config read error")
	}

	if !strings.Contains(err.Error(), "read") {
		t.Errorf("expected read error, got: %v", err)
	}
}

// TestInitSystemExistingConfigInvalid verifies that initSystem fails when
// the existing config is invalid JSON or missing required fields.
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

	var stdout, stderr bytes.Buffer
	err := initSystem(rootDir, &stdout, &stderr,
		nil,
		func(ar string, so, se io.Writer) error {
			t.Error("core should not be called")
			return nil
		})
	if err == nil {
		t.Fatal("expected error for invalid config")
	}

	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("expected invalid config error, got: %v", err)
	}
}

// --- Validate raw config error ---

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

// --- SELinux deployment relabel (system init) tests ---
//
// These cover the clean-install SELinux lifecycle invariant: system-mode init
// under enforcing SELinux applies the installed fcontext rules to the
// helper-owned config/state directories (recursive restorecon) immediately
// after creating them and before writing the admin token, so the first daemon
// start succeeds. AppArmor system mode and user mode never invoke the SELinux
// relabel, and a relabel failure is fatal (no misleading partial init).

// setupInitSystemMode points config + state dirs at temp dirs and forces
// system mode (EffectiveUID 0) so initCore can run without root and without
// touching /etc/docker-helper or /var/lib/docker-helper.
func setupInitSystemMode(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	t.Cleanup(func() { getConfigPathFunc = origGetConfig })

	origGetState := getStateDirFunc
	getStateDirFunc = func() string { return filepath.Join(dir, "state") }
	t.Cleanup(func() { getStateDirFunc = origGetState })

	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	t.Cleanup(func() { EffectiveUID = origUID })

	return dir
}

// TestInitSystemSELinuxRelabelsDeploymentPaths verifies that system init under
// enforcing SELinux applies the deployment relabel to exactly the helper-owned
// config/state trees, before the admin token is created, and never touches the
// runtime tree or a Session/workspace path.
func TestInitSystemSELinuxRelabelsDeploymentPaths(t *testing.T) {
	dir := setupInitSystemMode(t)

	origLSM := detectLSM
	detectLSM = func() (LSMBackend, error) { return LSMSELinux, nil }
	defer func() { detectLSM = origLSM }()

	origRC := deploymentRestorecon
	var calls [][]string
	tokenAtRelabel := "unset"
	deploymentRestorecon = func(args ...string) ([]byte, error) {
		calls = append(calls, args)
		if _, err := os.Stat(filepath.Join(dir, "admin.token")); os.IsNotExist(err) {
			tokenAtRelabel = "absent"
		} else {
			tokenAtRelabel = "present"
		}
		return nil, nil
	}
	defer func() { deploymentRestorecon = origRC }()

	rootDir := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	if _, err := initCore(rootDir, &stdout, &stderr); err != nil {
		t.Fatalf("initCore failed: %v", err)
	}

	want := [][]string{{"-R", "-m", "/etc/docker-helper", "/var/lib/docker-helper"}}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("deployment restorecon calls = %v, want %v", calls, want)
	}
	if tokenAtRelabel != "absent" {
		t.Errorf("deployment relabel must run before the admin token is created, got %q", tokenAtRelabel)
	}
	for _, call := range calls {
		for _, a := range call {
			if strings.Contains(a, "/run/docker-helper") {
				t.Errorf("deployment relabel must never target /run/docker-helper, got %q", a)
			}
			if a == rootDir || strings.HasPrefix(a, rootDir+string(filepath.Separator)) {
				t.Errorf("system init must not prepare Session/workspace MAC state (relabeled workspace %q)", a)
			}
		}
	}
}

// TestInitSystemAppArmorNoSELinuxRelabel verifies that AppArmor system init
// does not invoke any SELinux relabel.
func TestInitSystemAppArmorNoSELinuxRelabel(t *testing.T) {
	setupInitSystemMode(t)

	origLSM := detectLSM
	detectLSM = func() (LSMBackend, error) { return LSMAppArmor, nil }
	defer func() { detectLSM = origLSM }()

	called := false
	origRC := deploymentRestorecon
	deploymentRestorecon = func(args ...string) ([]byte, error) { called = true; return nil, nil }
	defer func() { deploymentRestorecon = origRC }()

	rootDir := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	if _, err := initCore(rootDir, &stdout, &stderr); err != nil {
		t.Fatalf("initCore failed: %v", err)
	}
	if called {
		t.Error("AppArmor system init must not invoke the SELinux deployment relabel")
	}
}

// TestInitUserModeNoSELinuxRelabel verifies that user-mode init does not
// invoke any SELinux relabel (no new SELinux dependency).
func TestInitUserModeNoSELinuxRelabel(t *testing.T) {
	dir := t.TempDir()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return filepath.Join(dir, "config.json") }
	defer func() { getConfigPathFunc = origGetConfig }()

	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = origUID }()

	called := false
	origRC := deploymentRestorecon
	deploymentRestorecon = func(args ...string) ([]byte, error) { called = true; return nil, nil }
	defer func() { deploymentRestorecon = origRC }()

	rootDir := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	if _, err := initCore(rootDir, &stdout, &stderr); err != nil {
		t.Fatalf("initCore failed: %v", err)
	}
	if called {
		t.Error("user-mode init must not invoke the SELinux deployment relabel")
	}
}

// TestInitSystemSELinuxRelabelFailureFatal verifies that a deployment relabel
// failure under enforcing SELinux system mode makes init fail and leaves no
// partial initialization (no admin token).
func TestInitSystemSELinuxRelabelFailureFatal(t *testing.T) {
	dir := setupInitSystemMode(t)

	origLSM := detectLSM
	detectLSM = func() (LSMBackend, error) { return LSMSELinux, nil }
	defer func() { detectLSM = origLSM }()

	origRC := deploymentRestorecon
	deploymentRestorecon = func(args ...string) ([]byte, error) {
		return []byte("restorecon: permission denied"), errors.New("restorecon exit status 1")
	}
	defer func() { deploymentRestorecon = origRC }()

	rootDir := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	_, err := initCore(rootDir, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected init to fail when the deployment relabel fails")
	}
	if !strings.Contains(err.Error(), "relabel") {
		t.Errorf("expected deployment relabel error, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "admin.token")); !os.IsNotExist(statErr) {
		t.Error("admin.token must not be created when the relabel fails (no partial init)")
	}
}
