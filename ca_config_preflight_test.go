package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestValidateCAConfigPropagatesHashError(t *testing.T) {
	// Regression: validateCAConfig must propagate the error from
	// computeOpenSSLSubjectHash, not discard it.
	//
	// We inject a hasher that returns a sentinel error to prove the error
	// path is exercised and the error context is preserved.

	_, caPath := setupCAConfigPreflightTest(t)

	// Create a hasher that returns a sentinel error.
	sentinelErr := errors.New("simulated hash failure")
	failingHasher := func(*x509.Certificate) (string, error) {
		return "", sentinelErr
	}

	raw := map[string]json.RawMessage{
		"trusted_ca_injection": json.RawMessage(`"auto"`),
		"trusted_ca_path":      json.RawMessage(fmt.Sprintf(`"%s"`, caPath)),
	}

	err := validateCAConfigWithHasher(raw, failingHasher)
	if err == nil {
		t.Fatal("expected error from failing hasher, got nil")
	}

	// Verify the error contains useful context.
	if !strings.Contains(err.Error(), "subject hash computation failed") {
		t.Errorf("expected 'subject hash computation failed' in error, got: %v", err)
	}

	// Verify the underlying error is preserved.
	if !errors.Is(err, sentinelErr) {
		t.Errorf("expected error to wrap sentinel, got: %v", err)
	}
}

func TestCAPreflightAutoMissingCA(t *testing.T) {
	configPath, caPath := setupCAConfigPreflightTest(t)

	// Remove the CA file so it's missing.
	if err := os.Remove(caPath); err != nil {
		t.Fatalf("cannot remove CA: %v", err)
	}

	// Set trusted_ca_path to the missing file first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
	}

	// Save original config bytes before the failing command.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Now try to enable auto with the missing CA.
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stdout: %q, stderr: %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	// Config file should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestCAPreflightAutoMalformedCA(t *testing.T) {
	configPath, _ := setupCAConfigPreflightTest(t)

	// Create a malformed CA file.
	badCAPath := filepath.Join(filepath.Dir(configPath), "bad-ca.crt")
	if err := os.WriteFile(badCAPath, []byte("not valid PEM data"), 0644); err != nil {
		t.Fatalf("cannot write bad CA: %v", err)
	}

	// First set the path.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", badCAPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
	}

	// Save original config bytes.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Now try to enable auto with the malformed CA.
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stderr: %q", code, stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	// Config should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestCAPreflightAutoLeafCA(t *testing.T) {
	configPath, _ := setupCAConfigPreflightTest(t)

	// Create a leaf certificate.
	leafPath := filepath.Join(filepath.Dir(configPath), "leaf.crt")
	leafPEM := generateTestLeafPEM(t)
	if err := os.WriteFile(leafPath, leafPEM, 0644); err != nil {
		t.Fatalf("cannot write leaf: %v", err)
	}

	// Set the path first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", leafPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
	}

	// Save original config bytes.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Try to enable auto with the leaf CA.
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stderr: %q", code, stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	// Config should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestCAPreflightReplacePathInvalidWhileAuto(t *testing.T) {
	configPath, caPath := setupCAConfigPreflightTest(t)

	// First set path and enable auto (should succeed with valid CA).
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d stdout: %q stderr: %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set auto: expected 0, got %d stdout: %q stderr: %q", code, stdout.String(), stderr.String())
	}

	// Save original config bytes after setup.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Now try to replace path with a non-existent file.
	badPath := filepath.Join(filepath.Dir(configPath), "nonexistent.crt")
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_path", badPath}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stderr: %q", code, stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	// Config should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestCAPreflightValidCASucceeds(t *testing.T) {
	configPath, caPath := setupCAConfigPreflightTest(t)

	// Set path and enable auto (should succeed).
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d, stderr: %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set auto: expected 0, got %d, stderr: %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated") {
		t.Errorf("expected 'updated' in stdout, got: %q", stdout.String())
	}

	// Verify config was written.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("cannot parse config: %v", err)
	}
	if raw["trusted_ca_injection"] != "auto" {
		t.Errorf("expected auto, got %v", raw["trusted_ca_injection"])
	}
}

func TestCAPreflightDisabledNoValidation(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	nonexistentRuntime := filepath.Join(dir, "nonexistent_runtime")
	nonexistentState := filepath.Join(dir, "nonexistent_state")

	// Write admin token.
	if err := os.WriteFile(tokenPath, []byte("test-admin-token\n"), 0600); err != nil {
		t.Fatalf("cannot write token: %v", err)
	}

	// Write initial config with disabled injection.
	allowedRoot := testAllowedRootDir(t)
	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         allowedRoot,
		"session_ttl":          "12h",
		"trusted_ca_injection": "disabled",
	})

	// Set environment: nonexistent runtime/state.
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", nonexistentRuntime)
	t.Setenv("XDG_STATE_HOME", nonexistentState)

	// Prevent reaching a real system daemon.
	origSocket := systemSocketExists
	systemSocketExists = func() bool { return false }
	t.Cleanup(func() { systemSocketExists = origSocket })

	// Point to a non-existent CA path while injection is disabled.
	badPath := filepath.Join(dir, "nonexistent.crt")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", badPath}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0 for disabled mode, got %d, stderr: %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated") {
		t.Errorf("expected 'updated' in stdout, got: %q", stdout.String())
	}

	// Verify runtime directory was NOT created.
	if _, err := os.Stat(nonexistentRuntime); !os.IsNotExist(err) {
		t.Errorf("runtime dir %s should not have been created", nonexistentRuntime)
	}

	// Verify state directory was NOT created.
	if _, err := os.Stat(nonexistentState); !os.IsNotExist(err) {
		t.Errorf("state dir %s should not have been created", nonexistentState)
	}
}

func TestCAPreflightUnchangedWithBrokenCA(t *testing.T) {
	configPath, caPath := setupCAConfigPreflightTest(t)

	// Set up valid config first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d stdout: %q stderr: %q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set auto: expected 0, got %d stdout: %q stderr: %q", code, stdout.String(), stderr.String())
	}

	// Save original config bytes.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Now break the CA file.
	if err := os.Remove(caPath); err != nil {
		t.Fatalf("cannot remove CA: %v", err)
	}

	// Try to set the same values (unchanged path).
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 for unchanged with broken CA, got %d, stdout: %q, stderr: %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	// Config should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}

func TestCAPreflightSetUnchanged(t *testing.T) {
	configPath, caPath, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_roots":        []string{testAllowedRootDir(t)},
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "unchanged") {
		t.Errorf("expected 'unchanged' in output, got: %s", stdout.String())
	}
}

func TestCAPreflightUnsetAbsentWithBrokenCA(t *testing.T) {
	configPath, caPath, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	beforeData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	// Break the CA file so preflight validation fails.
	if err := os.Remove(caPath); err != nil {
		t.Fatal(err)
	}

	// Unset a field that is already absent to hit the "already absent" branch.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "unset", "log_level"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stdout: %q, stderr: %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Error("expected non-empty stderr")
	}

	afterData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeData, afterData) {
		t.Error("config.json should not be modified when preflight fails")
	}
}

func TestSystemModeCAOutsideSourceAccepted(t *testing.T) {
	// UAT regression: in system mode, with trusted_ca_injection=auto and
	// trusted_ca_path pointing to a valid CA file outside /etc/docker-helper,
	// the config must load successfully. There is no source-location restriction.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	allowedRoot := testAllowedRootDir(t)
	// Pre-set the CA path so we only need one command to test the validation.
	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         allowedRoot,
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "disabled",
	})

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	shortRuntime := filepath.Join(os.TempDir(), fmt.Sprintf("dh-ca-sys-%d", os.Getpid()))
	t.Setenv("XDG_RUNTIME_DIR", shortRuntime)
	t.Cleanup(func() { os.RemoveAll(shortRuntime) })

	// Mock system mode.
	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	// Mock config path so the config transaction reads the test config.
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	// The config transaction calls validateCAConfig before writing; the reload
	// itself is out of scope here, so report "daemon not running" like the
	// other config mutation integration tests.
	origAttemptReload := attemptReload
	attemptReload = func() reloadOutcome {
		return reloadOutcome{reloadDaemonNotRunning, nil}
	}
	defer func() { attemptReload = origAttemptReload }()

	// Enable auto with a CA outside /etc/docker-helper. This must succeed.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stdout: %q, stderr: %q", code, stdout.String(), stderr.String())
	}

	// The config must be persisted with trusted_ca_injection=auto.
	raw := readConfigJSON(t, configPath)
	var injection string
	if err := json.Unmarshal(raw["trusted_ca_injection"], &injection); err != nil {
		t.Fatal(err)
	}
	if injection != "auto" {
		t.Errorf("trusted_ca_injection = %q, want %q", injection, "auto")
	}
	var path string
	if err := json.Unmarshal(raw["trusted_ca_path"], &path); err != nil {
		t.Fatal(err)
	}
	if path != caPath {
		t.Errorf("trusted_ca_path = %q, want %q", path, caPath)
	}
}

func TestSystemModeCAOutsideSourceAllowsUnrelatedMutation(t *testing.T) {
	// Regression: an unrelated config mutation must not fail because
	// trusted_ca_path points to a valid CA outside /etc/docker-helper.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	allowedRoot := testAllowedRootDir(t)
	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         allowedRoot,
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	shortRuntime := filepath.Join(os.TempDir(), fmt.Sprintf("dh-ca-sys-%d", os.Getpid()))
	t.Setenv("XDG_RUNTIME_DIR", shortRuntime)
	t.Cleanup(func() { os.RemoveAll(shortRuntime) })

	// Mock system mode.
	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	// The config transaction calls validateCAConfig before writing; the reload
	// itself is out of scope here, so report "daemon not running" like the
	// other config mutation integration tests.
	origAttemptReload := attemptReload
	attemptReload = func() reloadOutcome {
		return reloadOutcome{reloadDaemonNotRunning, nil}
	}
	defer func() { attemptReload = origAttemptReload }()

	// Unrelated mutation: add a new allowed root.
	newRoot := testAllowedRootDir(t)
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "allowed-root", "add", newRoot}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stdout: %q, stderr: %q", code, stdout.String(), stderr.String())
	}

	// The allowed root must be added and the CA settings preserved unchanged.
	raw := readConfigJSON(t, configPath)
	var roots []string
	if err := json.Unmarshal(raw["allowed_roots"], &roots); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(roots, newRoot) {
		t.Errorf("allowed_roots = %v, want it to contain %s", roots, newRoot)
	}
	var injection string
	if err := json.Unmarshal(raw["trusted_ca_injection"], &injection); err != nil {
		t.Fatal(err)
	}
	if injection != "auto" {
		t.Errorf("trusted_ca_injection = %q, want %q", injection, "auto")
	}
	var path string
	if err := json.Unmarshal(raw["trusted_ca_path"], &path); err != nil {
		t.Fatal(err)
	}
	if path != caPath {
		t.Errorf("trusted_ca_path = %q, want %q", path, caPath)
	}
}

func TestUserModeCAArbitraryPath(t *testing.T) {
	// User mode must accept arbitrary absolute CA paths.
	_, caPath := setupCAConfigPreflightTest(t)

	// Ensure user mode.
	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = origUID }()

	// Set path and enable auto (should succeed with valid CA in user mode).
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d, stderr: %q", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set auto: expected 0, got %d, stderr: %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated") {
		t.Errorf("expected 'updated' in stdout, got: %q", stdout.String())
	}
}

// TestLoadAndPrepareRuntimeConfigSystemModeAcceptsOutsideCA is the UAT
// regression for config load: in system mode, with trusted_ca_injection=auto
// and trusted_ca_path pointing to a valid CA file outside /etc/docker-helper,
// loadAndPrepareRuntimeConfig must succeed and prepare the CA snapshot.
func TestLoadAndPrepareRuntimeConfigSystemModeAcceptsOutsideCA(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	// Manually write config bypassing config CLI.
	cfg := map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	// Mock system mode.
	origUID := EffectiveUID
	EffectiveUID = func() int { return 0 }
	defer func() { EffectiveUID = origUID }()

	// Mock config path.
	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	// Mock the runtime dir so system mode does not touch /run/docker-helper.
	runtimeDir := filepath.Join(dir, "runtime")
	origRuntimeDir := getRuntimeDirFunc
	getRuntimeDirFunc = func() (string, error) { return runtimeDir, nil }
	defer func() { getRuntimeDirFunc = origRuntimeDir }()

	loaded, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatalf("loadAndPrepareRuntimeConfig should accept CA outside /etc/docker-helper in system mode: %v", err)
	}
	if loaded.TrustedCAPath != caPath {
		t.Errorf("TrustedCAPath = %q, want %q", loaded.TrustedCAPath, caPath)
	}
	if loaded.TrustedCAPreparedDir == "" {
		t.Error("TrustedCAPreparedDir should be set")
	}
}

func TestLoadAndPrepareRuntimeConfigUserModeAcceptsArbitraryCA(t *testing.T) {
	// loadAndPrepareRuntimeConfig in user mode must accept arbitrary absolute CA paths.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	// Manually write config.
	cfg := map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	// Mock user mode.
	origUID := EffectiveUID
	EffectiveUID = func() int { return 1000 }
	defer func() { EffectiveUID = origUID }()

	origGetConfig := getConfigPathFunc
	getConfigPathFunc = func() string { return configPath }
	defer func() { getConfigPathFunc = origGetConfig }()

	// Use XDG environment variables for user mode paths.
	runtimeDir := filepath.Join(dir, "runtime")
	stateDir := filepath.Join(dir, "state")
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("XDG_STATE_HOME", stateDir)

	loaded, err := loadAndPrepareRuntimeConfig()
	if err != nil {
		t.Fatalf("loadAndPrepareRuntimeConfig should accept arbitrary CA path in user mode: %v", err)
	}
	if loaded.TrustedCAPath != caPath {
		t.Errorf("TrustedCAPath = %q, want %q", loaded.TrustedCAPath, caPath)
	}
	if loaded.TrustedCAPreparedDir == "" {
		t.Error("TrustedCAPreparedDir should be set")
	}
}
