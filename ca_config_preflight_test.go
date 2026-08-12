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
	configPath, caPath, _, cleanup := setupCAConfigPreflightTest(t)
	defer cleanup()

	// Remove the CA file so it's missing.
	os.Remove(caPath)

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
	if !strings.Contains(stderr.String(), "error") {
		t.Errorf("expected error in stderr, got: %q", stderr.String())
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
	configPath, _, _, cleanup := setupCAConfigPreflightTest(t)
	defer cleanup()

	// Create a malformed CA file.
	badCAPath := filepath.Join(filepath.Dir(configPath), "bad-ca.crt")
	os.WriteFile(badCAPath, []byte("not valid PEM data"), 0644)

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
	configPath, _, _, cleanup := setupCAConfigPreflightTest(t)
	defer cleanup()

	// Create a leaf certificate.
	leafPath := filepath.Join(filepath.Dir(configPath), "leaf.crt")
	leafPEM := generateTestLeafPEM(t)
	os.WriteFile(leafPath, leafPEM, 0644)

	// Set the path first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", leafPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
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
}

func TestCAPreflightAutoNoOpenSSL(t *testing.T) {
	configPath, caPath, _, cleanup := setupCAConfigPreflightTest(t)
	defer cleanup()

	// Set PATH to empty dir (no openssl).
	emptyBin := filepath.Join(filepath.Dir(configPath), "empty_bin")
	os.MkdirAll(emptyBin, 0755)
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", emptyBin)
	defer os.Setenv("PATH", oldPath)

	// Set the path first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
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
}

func TestCAPreflightAutoOpenSSLFailure(t *testing.T) {
	configPath, caPath, _, cleanup := setupCAConfigPreflightTest(t)
	defer cleanup()

	// Replace fake openssl with one that fails.
	fakeBinDir := filepath.Join(filepath.Dir(configPath), "fake_bin")
	os.WriteFile(filepath.Join(fakeBinDir, "openssl"), []byte("#!/bin/sh\nexit 1\n"), 0755)

	// Set the path first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
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
}

func TestCAPreflightAutoOpenSSLInvalidOutput(t *testing.T) {
	configPath, caPath, _, cleanup := setupCAConfigPreflightTest(t)
	defer cleanup()

	// Replace fake openssl with one that returns invalid output.
	fakeBinDir := filepath.Join(filepath.Dir(configPath), "fake_bin")
	os.WriteFile(filepath.Join(fakeBinDir, "openssl"), []byte("#!/bin/sh\necho not-a-hash\n"), 0755)

	// Set the path first.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set path: expected 0, got %d", code)
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
}

func TestCAPreflightReplacePathInvalidWhileAuto(t *testing.T) {
	configPath, caPath, _, cleanup := setupCAConfigPreflightTest(t)
	defer cleanup()

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
	configPath, caPath, _, cleanup := setupCAConfigPreflightTest(t)
	defer cleanup()

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
	configPath, _, _, cleanup := setupCAConfigPreflightTest(t)
	defer cleanup()

	// Explicitly unset runtime/state dirs.
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("XDG_STATE_HOME", "")

	// Point to a non-existent CA path while injection is disabled.
	badPath := filepath.Join(filepath.Dir(configPath), "nonexistent.crt")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", badPath}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0 for disabled mode, got %d, stderr: %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated") {
		t.Errorf("expected 'updated' in stdout, got: %q", stdout.String())
	}
}

func TestCAPreflightUnchangedWithBrokenCA(t *testing.T) {
	configPath, caPath, _, cleanup := setupCAConfigPreflightTest(t)
	defer cleanup()

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
	os.Remove(caPath)

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

	// Config should be byte-for-byte unchanged.
	newBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("cannot read config: %v", err)
	}
	if !bytes.Equal(originalBytes, newBytes) {
		t.Error("config.json should be byte-for-byte unchanged")
	}
}
