package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCAPreflightAutoMissingCA(t *testing.T) {
	configPath, caPath, _ := setupCAConfigPreflightTest(t)

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
	configPath, _, _ := setupCAConfigPreflightTest(t)

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
	configPath, _, _ := setupCAConfigPreflightTest(t)

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

func TestCAPreflightAutoNoOpenSSL(t *testing.T) {
	configPath, caPath, _ := setupCAConfigPreflightTest(t)

	// Set PATH to empty dir (no openssl).
	emptyBin := filepath.Join(filepath.Dir(configPath), "empty_bin")
	if err := os.MkdirAll(emptyBin, 0755); err != nil {
		t.Fatalf("cannot create empty_bin: %v", err)
	}
	t.Setenv("PATH", emptyBin)

	// Set the path first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
	}

	// Save original config bytes.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Try to enable auto without openssl.
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

func TestCAPreflightAutoOpenSSLFailure(t *testing.T) {
	configPath, caPath, _ := setupCAConfigPreflightTest(t)

	// Replace fake openssl with one that fails.
	fakeBinDir := filepath.Join(filepath.Dir(configPath), "fake_bin")
	if err := os.WriteFile(filepath.Join(fakeBinDir, "openssl"), []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatalf("cannot write fake openssl: %v", err)
	}

	// Set the path first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
	}

	// Save original config bytes.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Try to enable auto with failing openssl.
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

func TestCAPreflightAutoOpenSSLInvalidOutput(t *testing.T) {
	configPath, caPath, _ := setupCAConfigPreflightTest(t)

	// Replace fake openssl with one that returns invalid output.
	fakeBinDir := filepath.Join(filepath.Dir(configPath), "fake_bin")
	if err := os.WriteFile(filepath.Join(fakeBinDir, "openssl"), []byte("#!/bin/sh\necho not-a-hash\n"), 0755); err != nil {
		t.Fatalf("cannot write fake openssl: %v", err)
	}

	// Set the path first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
	}

	// Save original config bytes.
	originalBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}

	// Try to enable auto with invalid openssl output.
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
	configPath, caPath, _ := setupCAConfigPreflightTest(t)

	// First set path and enable auto (should succeed with valid CA).
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
	}
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set auto: expected 0, got %d, stderr: %q", code, stderr.String())
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
	configPath, caPath, _ := setupCAConfigPreflightTest(t)

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
	emptyBin := filepath.Join(dir, "empty_bin")

	// Create empty bin dir (no openssl).
	if err := os.MkdirAll(emptyBin, 0755); err != nil {
		t.Fatalf("cannot create empty_bin: %v", err)
	}

	// Write admin token.
	if err := os.WriteFile(tokenPath, []byte("test-admin-token\n"), 0600); err != nil {
		t.Fatalf("cannot write token: %v", err)
	}

	// Write initial config with disabled injection.
	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         "/tmp/work",
		"session_ttl":          "12h",
		"trusted_ca_injection": "disabled",
	})

	// Set environment: nonexistent runtime/state, PATH with no openssl.
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", nonexistentRuntime)
	t.Setenv("XDG_STATE_HOME", nonexistentState)
	t.Setenv("PATH", emptyBin)

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
	configPath, caPath, _ := setupCAConfigPreflightTest(t)

	// Set up valid config first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
	}
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set auto: expected 0, got %d, stderr: %q", code, stderr.String())
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
	configPath, caPath, _, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         "/tmp/work",
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
	configPath, caPath, _, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         "/tmp/work",
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
