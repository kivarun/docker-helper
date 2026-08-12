package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCAInjectionDefaultDisabled(t *testing.T) {
	cfg := `{
  "allowed_root": "/tmp/work",
  "session_ttl": "12h"
}`
	_ = setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "trusted_ca_injection"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	if stdout.String() != "disabled\n" {
		t.Errorf("expected 'disabled\\n', got %q", stdout.String())
	}
}

func TestCAConfigShowSetUnset(t *testing.T) {
	configPath, caPath, _, _, cleanup := setupCAConfigTest(t)
	defer cleanup()

	cfg := map[string]any{
		"allowed_root":         "/tmp/work",
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "trusted_ca_path"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("show trusted_ca_path: expected 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), caPath) {
		t.Errorf("expected CA path in output, got: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "show", "trusted_ca_injection"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("show trusted_ca_injection: expected 0, got %d", code)
	}
	if stdout.String() != "auto\n" {
		t.Errorf("expected 'auto\\n', got %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "disabled"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set disabled: expected 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated") {
		t.Errorf("expected 'updated' in output, got: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "unset", "trusted_ca_injection"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("unset: expected 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "unset") {
		t.Errorf("expected 'unset' in output, got: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "show", "trusted_ca_injection"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("show after unset: expected 0, got %d", code)
	}
	if stdout.String() != "disabled\n" {
		t.Errorf("expected 'disabled\\n' after unset, got %q", stdout.String())
	}
}

func TestCAConfigInvalidMode(t *testing.T) {
	cfg := `{
  "allowed_root": "/tmp/work",
  "session_ttl": "12h",
  "trusted_ca_injection": "invalid"
}`
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit code for invalid mode")
	}
	if !strings.Contains(stderr.String(), "trusted_ca_injection") {
		t.Errorf("expected error about trusted_ca_injection, got: %s", stderr.String())
	}
}

func TestCAConfigAutoWithoutPath(t *testing.T) {
	cfg := `{
  "allowed_root": "/tmp/work",
  "session_ttl": "12h",
  "trusted_ca_injection": "auto"
}`
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit code for auto without path")
	}
	if !strings.Contains(stderr.String(), "trusted_ca_path") {
		t.Errorf("expected error about trusted_ca_path, got: %s", stderr.String())
	}
}

func TestCAConfigRelativePath(t *testing.T) {
	cfg := `{
  "allowed_root": "/tmp/work",
  "session_ttl": "12h",
  "trusted_ca_path": "relative/path.crt",
  "trusted_ca_injection": "disabled"
}`
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit code for relative path")
	}
}

func TestCAConfigMissingFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	stateHome := filepath.Join(dir, "xdg_state")
	stateSubDir := filepath.Join(stateHome, "docker-helper")

	if err := os.MkdirAll(runtimeSubDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateSubDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := map[string]any{
		"allowed_root":         "/tmp/work",
		"session_ttl":          "12h",
		"trusted_ca_path":      "/nonexistent/ca.crt",
		"trusted_ca_injection": "auto",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(configPath, data, 0600)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("XDG_STATE_HOME", stateHome)

	_, err := loadConfig()
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestCAConfigNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	stateHome := filepath.Join(dir, "xdg_state")
	stateSubDir := filepath.Join(stateHome, "docker-helper")

	if err := os.MkdirAll(runtimeSubDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateSubDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	caDir := filepath.Join(dir, "ca-dir")
	if err := os.MkdirAll(caDir, 0755); err != nil {
		t.Fatal(err)
	}

	fakeBinDir := filepath.Join(dir, "fake_bin")
	os.MkdirAll(fakeBinDir, 0755)
	os.WriteFile(filepath.Join(fakeBinDir, "openssl"), []byte("#!/bin/sh\necho abcd1234\n"), 0755)

	cfg := map[string]any{
		"allowed_root":         "/tmp/work",
		"session_ttl":          "12h",
		"trusted_ca_path":      caDir,
		"trusted_ca_injection": "auto",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(configPath, data, 0600)

	oldConfig := os.Getenv("DOCKER_HELPER_CONFIG")
	oldRuntime := os.Getenv("XDG_RUNTIME_DIR")
	oldState := os.Getenv("XDG_STATE_HOME")
	oldPath := os.Getenv("PATH")
	os.Setenv("DOCKER_HELPER_CONFIG", configPath)
	os.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	os.Setenv("XDG_STATE_HOME", stateHome)
	os.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+oldPath)
	defer func() {
		os.Setenv("DOCKER_HELPER_CONFIG", oldConfig)
		os.Setenv("XDG_RUNTIME_DIR", oldRuntime)
		os.Setenv("XDG_STATE_HOME", oldState)
		os.Setenv("PATH", oldPath)
	}()

	_, err := loadConfig()
	if err == nil {
		t.Fatal("expected error for non-regular CA file")
	}
}

func TestCAConfigMalformedPEM(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	stateHome := filepath.Join(dir, "xdg_state")
	stateSubDir := filepath.Join(stateHome, "docker-helper")

	if err := os.MkdirAll(runtimeSubDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateSubDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	caPath := filepath.Join(dir, "malformed.crt")
	os.WriteFile(caPath, []byte("not valid PEM data"), 0644)

	fakeBinDir := filepath.Join(dir, "fake_bin")
	os.MkdirAll(fakeBinDir, 0755)
	os.WriteFile(filepath.Join(fakeBinDir, "openssl"), []byte("#!/bin/sh\necho abcd1234\n"), 0755)

	cfg := map[string]any{
		"allowed_root":         "/tmp/work",
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(configPath, data, 0600)

	oldConfig := os.Getenv("DOCKER_HELPER_CONFIG")
	oldRuntime := os.Getenv("XDG_RUNTIME_DIR")
	oldState := os.Getenv("XDG_STATE_HOME")
	oldPath := os.Getenv("PATH")
	os.Setenv("DOCKER_HELPER_CONFIG", configPath)
	os.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	os.Setenv("XDG_STATE_HOME", stateHome)
	os.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+oldPath)
	defer func() {
		os.Setenv("DOCKER_HELPER_CONFIG", oldConfig)
		os.Setenv("XDG_RUNTIME_DIR", oldRuntime)
		os.Setenv("XDG_STATE_HOME", oldState)
		os.Setenv("PATH", oldPath)
	}()

	_, err := loadConfig()
	if err == nil {
		t.Fatal("expected error for malformed PEM")
	}
}

func TestCAConfigMultipleCerts(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	stateHome := filepath.Join(dir, "xdg_state")
	stateSubDir := filepath.Join(stateHome, "docker-helper")

	if err := os.MkdirAll(runtimeSubDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateSubDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Generate two certificates and concatenate them as PEM.
	priv1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	cert1, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv1.PublicKey, priv1)
	template.SerialNumber = big.NewInt(2)
	cert2, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv2.PublicKey, priv2)

	caPath := filepath.Join(dir, "multi-ca.crt")
	var buf bytes.Buffer
	buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert1}))
	buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert2}))
	os.WriteFile(caPath, buf.Bytes(), 0644)

	fakeBinDir := filepath.Join(dir, "fake_bin")
	os.MkdirAll(fakeBinDir, 0755)
	os.WriteFile(filepath.Join(fakeBinDir, "openssl"), []byte("#!/bin/sh\necho abcd1234\n"), 0755)

	cfg := map[string]any{
		"allowed_root":         "/tmp/work",
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(configPath, data, 0600)

	oldConfig := os.Getenv("DOCKER_HELPER_CONFIG")
	oldRuntime := os.Getenv("XDG_RUNTIME_DIR")
	oldState := os.Getenv("XDG_STATE_HOME")
	oldPath := os.Getenv("PATH")
	os.Setenv("DOCKER_HELPER_CONFIG", configPath)
	os.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	os.Setenv("XDG_STATE_HOME", stateHome)
	os.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+oldPath)
	defer func() {
		os.Setenv("DOCKER_HELPER_CONFIG", oldConfig)
		os.Setenv("XDG_RUNTIME_DIR", oldRuntime)
		os.Setenv("XDG_STATE_HOME", oldState)
		os.Setenv("PATH", oldPath)
	}()

	_, err := loadConfig()
	if err == nil {
		t.Fatal("expected error for multiple certificates")
	}
}

func TestCAConfigAutoEmptyPath(t *testing.T) {
	cfg := `{
  "allowed_root": "/tmp/work",
  "session_ttl": "12h",
  "trusted_ca_path": "",
  "trusted_ca_injection": "auto"
}`
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero exit code for auto with empty path")
	}
}

func TestCAConfigSetValidation(t *testing.T) {
	configPath, caPath, _, _, cleanup := setupCAConfigTest(t)
	defer cleanup()

	cfg := map[string]any{
		"allowed_root": "/tmp/work",
		"session_ttl":  "12h",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", "relative/path"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for relative path, got %d", code)
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "invalid"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for invalid mode, got %d", code)
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_path", caPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
}

func TestCAUnsetPathWhenAutoActive(t *testing.T) {
	configPath, caPath, _, _, cleanup := setupCAConfigTest(t)
	defer cleanup()

	cfg := map[string]any{
		"allowed_root":         "/tmp/work",
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "unset", "trusted_ca_path"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 for unset path when auto, got %d, stderr: %s", code, stderr.String())
	}
}

func TestCAInitNoInjectionDefault(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))

	allowedRoot := filepath.Join(dir, "workspaces")
	if err := os.MkdirAll(allowedRoot, 0755); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"init", "--allowed-root", allowedRoot}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("init exited %d, stderr: %s", code, stderr.String())
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(data), "trusted_ca") {
		t.Error("init should not include trusted_ca fields by default")
	}
}

func TestCAConfigShowAllIncludesNewFields(t *testing.T) {
	configPath, caPath, _, _, cleanup := setupCAConfigTest(t)
	defer cleanup()

	cfg := map[string]any{
		"allowed_root":         "/tmp/work",
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}

	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if result["trusted_ca_path"] != caPath {
		t.Errorf("trusted_ca_path = %v, want %s", result["trusted_ca_path"], caPath)
	}
	if result["trusted_ca_injection"] != "auto" {
		t.Errorf("trusted_ca_injection = %v, want auto", result["trusted_ca_injection"])
	}
}

func TestCAConfigShowDefaults(t *testing.T) {
	cfg := `{
  "allowed_root": "/tmp/work",
  "session_ttl": "12h"
}`
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}

	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if result["trusted_ca_injection"] != "disabled" {
		t.Errorf("trusted_ca_injection = %v, want disabled", result["trusted_ca_injection"])
	}
	if result["trusted_ca_path"] != "" {
		t.Errorf("trusted_ca_path = %v, want empty", result["trusted_ca_path"])
	}
}

func TestResolveTrustedCAInjection(t *testing.T) {
	if resolveTrustedCAInjection("") != "disabled" {
		t.Error("empty should resolve to disabled")
	}
	if resolveTrustedCAInjection("auto") != "auto" {
		t.Error("auto should resolve to auto")
	}
	if resolveTrustedCAInjection("disabled") != "disabled" {
		t.Error("disabled should resolve to disabled")
	}
}

func TestCASetUnknownField(t *testing.T) {
	setupConfigTest(t)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "unknown_field", "value"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for unknown field, got %d", code)
	}
}

func TestCAReservedFieldRejection(t *testing.T) {
	setupConfigTest(t)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "socket_path", "/tmp/test"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for reserved field, got %d", code)
	}
}

func TestCAUnsetAbsentFieldPreflightFailsOnBrokenCA(t *testing.T) {
	configPath, caPath, _, _, cleanup := setupCAConfigTest(t)
	defer cleanup()

	cfg := map[string]any{
		"allowed_root":         "/tmp/work",
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

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
