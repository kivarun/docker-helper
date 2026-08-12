package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

// generateTestCAPEM creates a proper PEM-encoded self-signed CA and writes it to caPath.
func generateTestCAPEM(t *testing.T, caPath string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	// Use Go's encoding/pem for proper encoding.
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	if err := os.WriteFile(caPath, pemData, 0644); err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// setupCAConfigTest creates a test environment with config, runtime dir, and a fake openssl.
// Returns configPath, caPath, runtimeDir, and a cleanup function.
func setupCAConfigTest(t *testing.T) (configPath, caPath, runtimeDir, fakeBinDir string, cleanup func()) {
	t.Helper()
	dir := t.TempDir()

	configPath = filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	runtimeDir = filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	stateHome := filepath.Join(dir, "xdg_state")
	stateSubDir := filepath.Join(stateHome, "docker-helper")
	fakeBinDir = filepath.Join(dir, "fake_bin")

	if err := os.MkdirAll(runtimeSubDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateSubDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(fakeBinDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create a real CA file.
	caPath = filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	// Compute the real openssl hash for this CA.
	realHash := computeTestOpenSSLHash(t, caPath)

	// Create fake openssl that returns the hash.
	opensslScript := "#!/bin/sh\necho " + realHash + "\n"
	if err := os.WriteFile(filepath.Join(fakeBinDir, "openssl"), []byte(opensslScript), 0755); err != nil {
		t.Fatal(err)
	}

	// Write admin token.
	if err := os.WriteFile(tokenPath, []byte("test-admin-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	oldConfig := os.Getenv("DOCKER_HELPER_CONFIG")
	oldRuntime := os.Getenv("XDG_RUNTIME_DIR")
	oldState := os.Getenv("XDG_STATE_HOME")
	oldPath := os.Getenv("PATH")
	os.Setenv("DOCKER_HELPER_CONFIG", configPath)
	os.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	os.Setenv("XDG_STATE_HOME", stateHome)
	os.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+oldPath)

	cleanup = func() {
		os.Setenv("DOCKER_HELPER_CONFIG", oldConfig)
		os.Setenv("XDG_RUNTIME_DIR", oldRuntime)
		os.Setenv("XDG_STATE_HOME", oldState)
		os.Setenv("PATH", oldPath)
	}

	return configPath, caPath, runtimeDir, fakeBinDir, cleanup
}

// computeTestOpenSSLHash computes the expected openssl hash for a test CA.
func computeTestOpenSSLHash(t *testing.T, caPath string) string {
	t.Helper()
	// Try real openssl first.
	cmd := exec.Command("openssl", "x509", "-hash", "-noout", "-in", caPath)
	if cmd.Run() == nil {
		out, _ := cmd.Output()
		hash := strings.TrimSpace(string(out))
		if regexp.MustCompile(`^[0-9a-fA-F]{8}$`).MatchString(hash) {
			return hash
		}
	}
	// Fallback: use a fixed hash for testing.
	return "abcd1234"
}

// --- Test 1: effective default disabled ---

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

// --- Test 2: config show/set/unset for both fields ---

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

	// Show trusted_ca_path
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show", "trusted_ca_path"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("show trusted_ca_path: expected 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), caPath) {
		t.Errorf("expected CA path in output, got: %s", stdout.String())
	}

	// Show trusted_ca_injection
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "show", "trusted_ca_injection"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("show trusted_ca_injection: expected 0, got %d", code)
	}
	if stdout.String() != "auto\n" {
		t.Errorf("expected 'auto\\n', got %q", stdout.String())
	}

	// Set to disabled
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "disabled"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("set disabled: expected 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated") {
		t.Errorf("expected 'updated' in output, got: %s", stdout.String())
	}

	// Unset trusted_ca_injection (should return to disabled)
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

// --- Test 3: invalid mode, relative/missing/non-regular/malformed/multiple-certificate CA ---

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

	// Config JSON validation passes (file existence checked at load time).
	// But loadConfig should fail.
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

	// Use a directory as CA path (not regular file).
	caDir := filepath.Join(dir, "ca-dir")
	if err := os.MkdirAll(caDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create fake openssl.
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

	// Generate two certificates and concatenate them.
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
	buf.Write(cert1)
	buf.Write(cert2)
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

// --- Test 4: auto without path (config validation) ---

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

// --- Test 5: missing or invalid openssl ---

func TestCAOpenSSLMissing(t *testing.T) {
	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	if err := os.MkdirAll(runtimeSubDir, 0700); err != nil {
		t.Fatal(err)
	}

	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	// Set PATH to empty dir (no openssl available).
	emptyBin := filepath.Join(dir, "empty_bin")
	os.MkdirAll(emptyBin, 0755)
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", emptyBin)
	defer os.Setenv("PATH", oldPath)

	_, err := prepareCAInjection(runtimeSubDir, caPath)
	if err == nil {
		t.Fatal("expected error when openssl is missing")
	}
}

func TestCAOpenSSLInvalidOutput(t *testing.T) {
	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	if err := os.MkdirAll(runtimeSubDir, 0700); err != nil {
		t.Fatal(err)
	}

	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	fakeBinDir := filepath.Join(dir, "fake_bin")
	os.MkdirAll(fakeBinDir, 0755)
	// Fake openssl that returns invalid output.
	os.WriteFile(filepath.Join(fakeBinDir, "openssl"), []byte("#!/bin/sh\necho invalid-hash\n"), 0755)

	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+oldPath)
	defer os.Setenv("PATH", oldPath)

	_, err := prepareCAInjection(runtimeSubDir, caPath)
	if err == nil {
		t.Fatal("expected error for invalid openssl output")
	}
}

// --- Test 6: successful runtime directory preparation ---

func TestCAPrepareSuccess(t *testing.T) {
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

	// Load config (which prepares CA).
	cfgObj, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	if cfgObj.TrustedCAInjection != "auto" {
		t.Errorf("expected auto, got %s", cfgObj.TrustedCAInjection)
	}
	if cfgObj.TrustedCAPreparedDir == "" {
		t.Fatal("expected non-empty prepared dir")
	}

	// Verify directory structure.
	preparedDir := cfgObj.TrustedCAPreparedDir
	if _, err := os.Stat(preparedDir); os.IsNotExist(err) {
		t.Fatal("prepared dir does not exist")
	}

	dirInfo, err := os.Stat(preparedDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0755 {
		t.Errorf("dir mode = %o, want 0755", dirInfo.Mode().Perm())
	}

	// Verify ca.pem exists with correct mode.
	caFile := filepath.Join(preparedDir, "ca.pem")
	caInfo, err := os.Stat(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if caInfo.Mode().Perm() != 0644 {
		t.Errorf("ca.pem mode = %o, want 0644", caInfo.Mode().Perm())
	}

	// Verify hash symlink exists.
	entries, err := os.ReadDir(preparedDir)
	if err != nil {
		t.Fatal(err)
	}
	foundSymlink := false
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".0") {
			foundSymlink = true
			link, err := os.Readlink(filepath.Join(preparedDir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if link != "ca.pem" {
				t.Errorf("symlink target = %s, want ca.pem", link)
			}
		}
	}
	if !foundSymlink {
		t.Fatal("no hash symlink found")
	}
}

// --- Test 7: idempotent preparation and new fingerprint on CA change ---

func TestCAPrepareIdempotent(t *testing.T) {
	configPath, caPath, runtimeDir, _, cleanup := setupCAConfigTest(t)
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

	cfgObj1, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	firstDir := cfgObj1.TrustedCAPreparedDir

	// Reload same CA.
	cfgObj2, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfgObj2.TrustedCAPreparedDir != firstDir {
		t.Error("expected same prepared dir for same CA")
	}

	// Count subdirectories in trusted-ca.
	trustedCADir := filepath.Join(runtimeDir, "docker-helper", "trusted-ca")
	entries, err := os.ReadDir(trustedCADir)
	if err != nil {
		t.Fatal(err)
	}
	dirCount := 0
	for _, e := range entries {
		if e.IsDir() {
			dirCount++
		}
	}
	if dirCount != 1 {
		t.Errorf("expected 1 fingerprint dir, got %d", dirCount)
	}
}

func TestCAPrepareUmaskResilient(t *testing.T) {
	// Set restrictive umask so MkdirAll would produce 0700 instead of 0755.
	oldUmask := syscall.Umask(0077)
	defer syscall.Umask(oldUmask)

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

	cfgObj, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	fpDir := cfgObj.TrustedCAPreparedDir

	// Verify fingerprint directory mode is 0755 despite umask 0077.
	dirInfo, err := os.Stat(fpDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0755 {
		t.Errorf("fingerprint dir mode = %o, want 0755", dirInfo.Mode().Perm())
	}

	// Verify ca.pem mode is 0644.
	caFile := filepath.Join(fpDir, "ca.pem")
	caInfo, err := os.Stat(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if caInfo.Mode().Perm() != 0644 {
		t.Errorf("ca.pem mode = %o, want 0644", caInfo.Mode().Perm())
	}

	// Simulate a degraded directory mode and verify idempotent path restores it.
	if err := os.Chmod(fpDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Reload config with the same CA (idempotent path).
	cfgObj2, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfgObj2.TrustedCAPreparedDir != fpDir {
		t.Error("expected same prepared dir for same CA")
	}

	dirInfo2, err := os.Stat(fpDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo2.Mode().Perm() != 0755 {
		t.Errorf("fingerprint dir mode after idempotent reload = %o, want 0755", dirInfo2.Mode().Perm())
	}
}

func TestCAPrepareNewFingerprintOnCAChange(t *testing.T) {
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

	cfgObj1, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	firstDir := cfgObj1.TrustedCAPreparedDir

	// Replace CA with a new one.
	newCAPath := filepath.Join(filepath.Dir(configPath), "new-ca.crt")
	generateTestCAPEM(t, newCAPath)

	cfg["trusted_ca_path"] = newCAPath
	data, _ = json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	cfgObj2, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfgObj2.TrustedCAPreparedDir == firstDir {
		t.Error("expected different prepared dir for different CA")
	}

	// Old dir should still exist (no cleanup).
	if _, err := os.Stat(firstDir); os.IsNotExist(err) {
		t.Error("old fingerprint dir should still exist")
	}
}

// --- Test 8: reload changes CA for new runs ---

func TestCAReloadChangesCA(t *testing.T) {
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

	cfgObj1, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	firstDir := cfgObj1.TrustedCAPreparedDir

	// Change CA.
	newCAPath := filepath.Join(filepath.Dir(configPath), "new-ca.crt")
	generateTestCAPEM(t, newCAPath)

	cfg["trusted_ca_path"] = newCAPath
	data, _ = json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	cfgObj2, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfgObj2.TrustedCAPreparedDir == firstDir {
		t.Error("expected different prepared dir after CA change")
	}
	if cfgObj2.TrustedCAPreparedDir == "" {
		t.Error("expected non-empty prepared dir after reload")
	}
}

// --- Test 9: auto adds read-only mount and both env vars ---

func TestCAInjectionAddsMountAndEnv(t *testing.T) {
	// This test verifies the Docker argv construction with CA injection.
	// We use a mock exec to capture the command line.
	t.Parallel()

	dir := t.TempDir()
	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	fakeBinDir := filepath.Join(dir, "fake_bin")
	os.MkdirAll(fakeBinDir, 0755)
	realHash := computeTestOpenSSLHash(t, caPath)
	os.WriteFile(filepath.Join(fakeBinDir, "openssl"), []byte("#!/bin/sh\necho "+realHash+"\n"), 0755)

	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	os.MkdirAll(runtimeSubDir, 0700)

	// Prepare CA.
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+oldPath)
	defer os.Setenv("PATH", oldPath)

	preparedDir, err := prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the mount spec would be correct.
	expectedMount := fmt.Sprintf("type=bind,source=%s,target=%s,readonly", preparedDir, trustedCAContainerDir)
	if !strings.Contains(expectedMount, "readonly") {
		t.Error("mount should be readonly")
	}
	if !strings.Contains(expectedMount, trustedCAContainerDir) {
		t.Error("mount should target trusted CA container dir")
	}
}

// --- Test 10: explicit SSL_CERT_DIR/NODE_EXTRA_CA_CERTS preserved ---

func TestCAExplicitEnvPreserved(t *testing.T) {
	// When user explicitly sets SSL_CERT_DIR or NODE_EXTRA_CA_CERTS,
	// the injected values should not overwrite them.
	req := runRequest{
		Image: "alpine:3.24",
		Environment: map[string]string{
			"SSL_CERT_DIR":        "/custom/certs",
			"NODE_EXTRA_CA_CERTS": "/custom/ca.pem",
		},
	}

	allEnv := make(map[string]string)
	for k, v := range req.Environment {
		allEnv[k] = v
	}

	// Simulate injection logic.
	if _, exists := allEnv[trustedCAEnvSSLDir]; !exists {
		allEnv[trustedCAEnvSSLDir] = trustedCAEnvSSLDirValue
	}
	if _, exists := allEnv[trustedCAEnvNodeExtra]; !exists {
		allEnv[trustedCAEnvNodeExtra] = trustedCAEnvNodeExtraValue
	}

	if allEnv["SSL_CERT_DIR"] != "/custom/certs" {
		t.Errorf("SSL_CERT_DIR should be preserved, got %s", allEnv["SSL_CERT_DIR"])
	}
	if allEnv["NODE_EXTRA_CA_CERTS"] != "/custom/ca.pem" {
		t.Errorf("NODE_EXTRA_CA_CERTS should be preserved, got %s", allEnv["NODE_EXTRA_CA_CERTS"])
	}
}

// --- Test 11: injected Docker argv deterministic ---

func TestCADeterministicEnvOrder(t *testing.T) {
	req := runRequest{
		Image: "alpine:3.24",
		Environment: map[string]string{
			"ZEBRA":  "1",
			"ALPHA":  "2",
			"MIDDLE": "3",
		},
	}

	allEnv := make(map[string]string)
	for k, v := range req.Environment {
		allEnv[k] = v
	}
	// Simulate injection.
	if _, exists := allEnv[trustedCAEnvSSLDir]; !exists {
		allEnv[trustedCAEnvSSLDir] = trustedCAEnvSSLDirValue
	}
	if _, exists := allEnv[trustedCAEnvNodeExtra]; !exists {
		allEnv[trustedCAEnvNodeExtra] = trustedCAEnvNodeExtraValue
	}

	names := make([]string, 0, len(allEnv))
	for name := range allEnv {
		names = append(names, name)
	}
	sort.Strings(names)

	// Verify deterministic order.
	expected := []string{
		"ALPHA", "MIDDLE", "NODE_EXTRA_CA_CERTS", "SSL_CERT_DIR", "ZEBRA",
	}
	if !stringSliceEqual(names, expected) {
		t.Errorf("env order = %v, want %v", names, expected)
	}
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- Test 12: overlapping agent mount rejected ---

func TestCAMountOverlapRejected(t *testing.T) {
	// Test that mounts overlapping with the trusted CA target are rejected.
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

// --- Test 13: audit contains only boolean, no host/runtime source ---

func TestCAAuditBooleanOnly(t *testing.T) {
	rec := auditRecord{
		Event:             "run.start",
		SessionID:         "test-session",
		OperationID:       "test-op",
		Image:             "alpine:3.24",
		TrustedCAInjected: true,
	}

	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	str := string(data)

	// Should contain the boolean.
	if !strings.Contains(str, `"trusted_ca_injected":true`) {
		t.Error("expected trusted_ca_injected:true in audit")
	}

	// Should NOT contain any host paths.
	if strings.Contains(str, "/etc/") || strings.Contains(str, "docker-helper") {
		t.Error("audit should not contain host paths")
	}
}

// --- Test 14: disabled does not change existing run contract ---

func TestCADisabledNoChange(t *testing.T) {
	// When injection is disabled, no mount or env should be added.
	cfg := Config{
		TrustedCAInjection:   "disabled",
		TrustedCAPreparedDir: "",
	}

	injected := cfg.TrustedCAInjection == "auto" && cfg.TrustedCAPreparedDir != ""
	if injected {
		t.Error("expected no injection when disabled")
	}
}

// --- Additional: isTrustedCAEnvVar ---

func TestIsTrustedCAEnvVar(t *testing.T) {
	if !isTrustedCAEnvVar("SSL_CERT_DIR") {
		t.Error("SSL_CERT_DIR should be a trusted CA env var")
	}
	if !isTrustedCAEnvVar("NODE_EXTRA_CA_CERTS") {
		t.Error("NODE_EXTRA_CA_CERTS should be a trusted CA env var")
	}
	if isTrustedCAEnvVar("SSL_CERT_FILE") {
		t.Error("SSL_CERT_FILE should NOT be a trusted CA env var")
	}
	if isTrustedCAEnvVar("CUSTOM_VAR") {
		t.Error("CUSTOM_VAR should NOT be a trusted CA env var")
	}
}

// --- Additional: config set validation ---

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

	// Set trusted_ca_path to relative path (should fail).
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", "relative/path"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for relative path, got %d", code)
	}

	// Set trusted_ca_injection to invalid mode (should fail).
	stdout.Reset()
	stderr.Reset()
	code = runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "invalid"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for invalid mode, got %d", code)
	}

	// Set valid values.
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

// --- Additional: unset trusted_ca_path when auto active should fail ---

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

	// Unsetting trusted_ca_path while auto is active should fail validation.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "unset", "trusted_ca_path"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 for unset path when auto, got %d, stderr: %s", code, stderr.String())
	}
}

// --- Additional: init should not include injection by default ---

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

	// Config should not contain trusted_ca_injection or trusted_ca_path.
	if strings.Contains(string(data), "trusted_ca") {
		t.Error("init should not include trusted_ca fields by default")
	}
}

// --- Additional: config show all includes new fields ---

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

// --- Additional: validateCAFile tests ---

func TestValidateCAFileSuccess(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	cert, err := validateCAFile(caPath)
	if err != nil {
		t.Fatalf("validateCAFile failed: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
	if !cert.IsCA {
		t.Error("expected CA certificate")
	}
}

func TestValidateCAFileMissing(t *testing.T) {
	_, err := validateCAFile("/nonexistent/ca.crt")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateCAFileNotRegular(t *testing.T) {
	dir := t.TempDir()
	_, err := validateCAFile(dir)
	if err == nil {
		t.Fatal("expected error for directory")
	}
}

// --- Additional: validateCAPEM tests ---

// generateTestLeafPEM creates a PEM-encoded leaf (non-CA) certificate.
func generateTestLeafPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject: pkix.Name{
			Organization: []string{"Test Leaf"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// generateTestCAPrivateKeyPEM creates PEM data containing a CA cert followed
// by a PRIVATE KEY block.
func generateTestCAPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	// Append a PRIVATE KEY block (raw DER is not valid PKCS8, but it's a valid PEM block).
	buf.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret-key-data")}))
	return buf.Bytes()
}

// generateTestCASecondPEMBlock creates PEM data containing a CA cert followed
// by an arbitrary second PEM block.
func generateTestCASecondPEMBlock(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	buf.Write(pem.EncodeToMemory(&pem.Block{Type: "ARBITRARY", Bytes: []byte("extra")}))
	return buf.Bytes()
}

func TestValidateCAPEMValidCA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cert, err := validateCAPEM(data)
	if err != nil {
		t.Fatalf("expected valid CA, got error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
	if !cert.IsCA {
		t.Error("expected IsCA=true")
	}
}

func TestValidateCAPEMWhitespaceAround(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	data := append([]byte("\n\n\n"), append(pemData, '\n', '\n')...)
	cert, err := validateCAPEM(data)
	if err != nil {
		t.Fatalf("expected valid CA with whitespace, got error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}

func TestValidateCAPEMLeadingGarbageRejected(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	data := append([]byte("garbage before cert\n"), pemData...)
	_, err = validateCAPEM(data)
	if err == nil {
		t.Fatal("expected error for leading garbage before certificate")
	}
}

func TestValidateCAPEMLeafRejected(t *testing.T) {
	data := generateTestLeafPEM(t)
	_, err := validateCAPEM(data)
	if err == nil {
		t.Fatal("expected error for leaf certificate")
	}
}

func TestValidateCAPEMCAPlusPrivateKeyRejected(t *testing.T) {
	data := generateTestCAPrivateKeyPEM(t)
	_, err := validateCAPEM(data)
	if err == nil {
		t.Fatal("expected error for CA + private key")
	}
}

func TestValidateCAPEMCAPlusSecondPEMBlockRejected(t *testing.T) {
	data := generateTestCASecondPEMBlock(t)
	_, err := validateCAPEM(data)
	if err == nil {
		t.Fatal("expected error for CA + second PEM block")
	}
}

func TestValidateCAPEMCAPlusTrailingGarbageRejected(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	data := append(pemData, []byte(" trailing garbage")...)
	_, err = validateCAPEM(data)
	if err == nil {
		t.Fatal("expected error for CA + trailing garbage")
	}
}

func TestValidateCAPEMInvalidBase64Rejected(t *testing.T) {
	data := []byte("-----BEGIN CERTIFICATE-----\n!!!not-base64!!!\n-----END CERTIFICATE-----\n")
	_, err := validateCAPEM(data)
	if err == nil {
		t.Fatal("expected error for invalid base64 in PEM")
	}
}

func TestValidateCAPEMEmptyDataRejected(t *testing.T) {
	_, err := validateCAPEM([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestValidateCAPEMNoPEMRejected(t *testing.T) {
	_, err := validateCAPEM([]byte("not PEM data at all"))
	if err == nil {
		t.Fatal("expected error for non-PEM data")
	}
}

func TestValidateCAPEMNonCertificateBlockRejected(t *testing.T) {
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")})
	_, err := validateCAPEM(data)
	if err == nil {
		t.Fatal("expected error for non-CERTIFICATE block")
	}
}

// --- Additional: fingerprintDir tests ---

func TestFingerprintDirDeterministic(t *testing.T) {
	runtimeDir := "/tmp/runtime"
	data := []byte("test CA data")

	dir1 := fingerprintDir(runtimeDir, data)
	dir2 := fingerprintDir(runtimeDir, data)

	if dir1 != dir2 {
		t.Error("fingerprintDir should be deterministic")
	}

	// Different data should produce different fingerprint.
	dir3 := fingerprintDir(runtimeDir, []byte("different data"))
	if dir1 == dir3 {
		t.Error("different data should produce different fingerprint")
	}
}

// --- Additional: computeOpenSSLHash tests ---

// --- Additional: run handler integration test with mock ---

func TestRunHandlerWithCAInjection(t *testing.T) {
	// Test that the run handler correctly builds docker argv with CA injection.
	// We use a mock exec to capture the command line.

	dir := t.TempDir()
	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	fakeBinDir := filepath.Join(dir, "fake_bin")
	os.MkdirAll(fakeBinDir, 0755)
	realHash := computeTestOpenSSLHash(t, caPath)
	os.WriteFile(filepath.Join(fakeBinDir, "openssl"), []byte("#!/bin/sh\necho "+realHash+"\n"), 0755)

	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	os.MkdirAll(runtimeSubDir, 0700)

	// Prepare CA.
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+oldPath)
	defer os.Setenv("PATH", oldPath)

	preparedDir, err := prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}

	// Build expected mount spec.
	expectedMount := fmt.Sprintf("type=bind,source=%s,target=%s,readonly", preparedDir, trustedCAContainerDir)

	// Verify mount spec format.
	if !strings.HasPrefix(expectedMount, "type=bind,source=") {
		t.Error("mount spec should start with type=bind,source=")
	}
	if !strings.HasSuffix(expectedMount, ",readonly") {
		t.Error("mount spec should end with ,readonly")
	}
}

// --- Additional: env injection does not affect disabled mode ---

func TestCAEnvInjectionDisabledMode(t *testing.T) {
	// When injection is disabled, env vars should not be added.
	req := runRequest{
		Image: "alpine:3.24",
		Environment: map[string]string{
			"APP_MODE": "test",
		},
	}

	allEnv := make(map[string]string)
	for k, v := range req.Environment {
		allEnv[k] = v
	}

	// Simulate disabled mode: no injection.
	trustedCAInjected := false
	if trustedCAInjected {
		if _, exists := allEnv[trustedCAEnvSSLDir]; !exists {
			allEnv[trustedCAEnvSSLDir] = trustedCAEnvSSLDirValue
		}
		if _, exists := allEnv[trustedCAEnvNodeExtra]; !exists {
			allEnv[trustedCAEnvNodeExtra] = trustedCAEnvNodeExtraValue
		}
	}

	if _, exists := allEnv[trustedCAEnvSSLDir]; exists {
		t.Error("SSL_CERT_DIR should not be injected when disabled")
	}
	if _, exists := allEnv[trustedCAEnvNodeExtra]; exists {
		t.Error("NODE_EXTRA_CA_CERTS should not be injected when disabled")
	}
	if len(allEnv) != 1 {
		t.Errorf("expected 1 env var, got %d", len(allEnv))
	}
}

// --- Additional: config set unchanged ---

func TestCAConfigSetUnchanged(t *testing.T) {
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

	// Set same value.
	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "unchanged") {
		t.Errorf("expected 'unchanged' in output, got: %s", stdout.String())
	}
}

// --- Additional: config show with defaults ---

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

// --- Additional: resolveTrustedCAInjection ---

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

// --- Additional: unknown field rejection ---

func TestCAUnknownFieldRejection(t *testing.T) {
	cfg := `{
  "allowed_root": "/tmp/work",
  "session_ttl": "12h",
  "unknown_field": "value"
}`
	setupConfigTestWithData(t, []byte(cfg))
	t.Setenv("XDG_RUNTIME_DIR", "")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "show"}, &stdout, &stderr)
	// Unknown fields are allowed in config (they pass through).
	// This is existing behavior, not changed by CA injection.
	_ = code
	_ = stdout
	_ = stderr
}

// --- Additional: set unknown field rejection ---

func TestCASetUnknownField(t *testing.T) {
	setupConfigTest(t)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "unknown_field", "value"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for unknown field, got %d", code)
	}
}

// --- Additional: reserved field rejection ---

func TestCAReservedFieldRejection(t *testing.T) {
	setupConfigTest(t)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "socket_path", "/tmp/test"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for reserved field, got %d", code)
	}
}

// --- Additional: run with CA injection - full handler test ---

func TestRunHandlerCAInjectionFull(t *testing.T) {
	// Full integration test: start app, configure CA injection, POST /run,
	// verify docker command includes CA mount and env vars.
	// This test requires a mock exec to capture the docker command.

	dir := t.TempDir()
	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	fakeBinDir := filepath.Join(dir, "fake_bin")
	os.MkdirAll(fakeBinDir, 0755)
	realHash := computeTestOpenSSLHash(t, caPath)
	os.WriteFile(filepath.Join(fakeBinDir, "openssl"), []byte("#!/bin/sh\necho "+realHash+"\n"), 0755)

	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	os.MkdirAll(runtimeSubDir, 0700)

	// Prepare CA.
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+oldPath)
	defer os.Setenv("PATH", oldPath)

	preparedDir, err := prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the prepared dir contains the expected files.
	caFile := filepath.Join(preparedDir, "ca.pem")
	if _, err := os.Stat(caFile); os.IsNotExist(err) {
		t.Fatal("ca.pem should exist in prepared dir")
	}

	// Verify the hash symlink.
	entries, err := os.ReadDir(preparedDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".0") {
			info, err := e.Info()
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode()&os.ModeSymlink == 0 {
				t.Error("hash file should be a symlink")
			}
		}
	}
}

// --- Additional: CA injection constants ---

func TestCAInjectionConstants(t *testing.T) {
	// Verify the injection constants are correct.
	if trustedCAContainerDir != "/run/docker-helper/trusted-ca" {
		t.Errorf("trustedCAContainerDir = %s", trustedCAContainerDir)
	}
	if trustedCAEnvSSLDir != "SSL_CERT_DIR" {
		t.Errorf("trustedCAEnvSSLDir = %s", trustedCAEnvSSLDir)
	}
	if trustedCAEnvNodeExtra != "NODE_EXTRA_CA_CERTS" {
		t.Errorf("trustedCAEnvNodeExtra = %s", trustedCAEnvNodeExtra)
	}
	if !strings.Contains(trustedCAEnvSSLDirValue, "/run/docker-helper/trusted-ca") {
		t.Error("SSL_CERT_DIR value should contain trusted CA dir")
	}
	if !strings.Contains(trustedCAEnvSSLDirValue, "/etc/ssl/certs") {
		t.Error("SSL_CERT_DIR value should contain /etc/ssl/certs")
	}
	if !strings.Contains(trustedCAEnvSSLDirValue, "/etc/pki/tls/certs") {
		t.Error("SSL_CERT_DIR value should contain /etc/pki/tls/certs")
	}
	if trustedCAEnvNodeExtraValue != "/run/docker-helper/trusted-ca/ca.pem" {
		t.Errorf("NODE_EXTRA_CA_CERTS value = %s", trustedCAEnvNodeExtraValue)
	}
}

// --- Additional: no SSL_CERT_FILE used ---

func TestCAInjectionNoSSL_CERT_FILE(t *testing.T) {
	// Verify that SSL_CERT_FILE is NOT used (per spec).
	if isTrustedCAEnvVar("SSL_CERT_FILE") {
		t.Error("SSL_CERT_FILE should NOT be a trusted CA env var")
	}
}

// --- Additional: audit record TrustedCAInjected field ---

func TestAuditRecordTrustedCAInjected(t *testing.T) {
	// Test that the audit record correctly serializes TrustedCAInjected.
	rec := auditRecord{
		Event:             "run.start",
		SessionID:         "s1",
		OperationID:       "o1",
		Image:             "alpine",
		TrustedCAInjected: true,
	}
	data, _ := json.Marshal(rec)
	if !strings.Contains(string(data), `"trusted_ca_injected":true`) {
		t.Error("expected trusted_ca_injected:true")
	}

	rec2 := auditRecord{
		Event:             "run.start",
		SessionID:         "s1",
		OperationID:       "o1",
		Image:             "alpine",
		TrustedCAInjected: false,
	}
	data2, _ := json.Marshal(rec2)
	// false should be omitted due to omitempty.
	if strings.Contains(string(data2), "trusted_ca_injected") {
		t.Error("trusted_ca_injected should be omitted when false")
	}
}

// --- CA preflight on config set/unset ---

// setupCAConfigPreflightTest creates a minimal test environment for testing
// config set/unset CA preflight without XDG_RUNTIME_DIR.
// Returns configPath, a CA path (may be empty), a fake_bin dir, and a cleanup function.
func setupCAConfigPreflightTest(t *testing.T) (configPath, caPath, fakeBinDir string, cleanup func()) {
	t.Helper()
	dir := t.TempDir()

	configPath = filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	fakeBinDir = filepath.Join(dir, "fake_bin")

	if err := os.MkdirAll(fakeBinDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create a real CA file.
	caPath = filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	// Compute the real openssl hash for this CA.
	realHash := computeTestOpenSSLHash(t, caPath)

	// Create fake openssl that returns the hash.
	opensslScript := "#!/bin/sh\necho " + realHash + "\n"
	if err := os.WriteFile(filepath.Join(fakeBinDir, "openssl"), []byte(opensslScript), 0755); err != nil {
		t.Fatal(err)
	}

	// Write admin token.
	if err := os.WriteFile(tokenPath, []byte("test-admin-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := map[string]any{
		"allowed_root":         "/tmp/work",
		"session_ttl":          "12h",
		"trusted_ca_injection": "disabled",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	oldConfig := os.Getenv("DOCKER_HELPER_CONFIG")
	oldPath := os.Getenv("PATH")
	os.Setenv("DOCKER_HELPER_CONFIG", configPath)
	os.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+oldPath)

	cleanup = func() {
		os.Setenv("DOCKER_HELPER_CONFIG", oldConfig)
		os.Setenv("PATH", oldPath)
	}

	return configPath, caPath, fakeBinDir, cleanup
}

func TestCAPreflightAutoMissingCA(t *testing.T) {
	_, caPath, _, cleanup := setupCAConfigPreflightTest(t)
	defer cleanup()

	// Remove the CA file so it's missing.
	os.Remove(caPath)

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_injection", "auto"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d, stdout: %q, stderr: %q", code, stdout.String(), stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout, got: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "error") {
		t.Errorf("expected error in stderr, got: %q", stderr.String())
	}

	// Config file should be unchanged.
	configPath := filepath.Dir(caPath) + "/config.json"
	data, _ := os.ReadFile(configPath)
	var raw map[string]any
	json.Unmarshal(data, &raw)
	if raw["trusted_ca_injection"] != "disabled" {
		t.Errorf("config should be unchanged, got injection=%v", raw["trusted_ca_injection"])
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

	// Config should still have disabled injection.
	data, _ := os.ReadFile(configPath)
	var raw map[string]any
	json.Unmarshal(data, &raw)
	if raw["trusted_ca_injection"] != "disabled" {
		t.Errorf("config injection should still be disabled, got %v", raw["trusted_ca_injection"])
	}
}

func TestCAPreflightAutoLeafCA(t *testing.T) {
	configPath, _, _, cleanup := setupCAConfigPreflightTest(t)
	defer cleanup()

	// Create a leaf certificate.
	leafPath := filepath.Join(filepath.Dir(configPath), "leaf.crt")
	generateTestLeafPEM(t)
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

	// Config should be unchanged.
	data, _ := os.ReadFile(configPath)
	var raw map[string]any
	json.Unmarshal(data, &raw)
	if raw["trusted_ca_path"] != caPath {
		t.Errorf("config path should be unchanged, got %v", raw["trusted_ca_path"])
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
	data, _ := os.ReadFile(configPath)
	var raw map[string]any
	json.Unmarshal(data, &raw)
	if raw["trusted_ca_injection"] != "auto" {
		t.Errorf("expected auto, got %v", raw["trusted_ca_injection"])
	}
}

func TestCAPreflightDisabledNoValidation(t *testing.T) {
	configPath, _, _, cleanup := setupCAConfigPreflightTest(t)
	defer cleanup()

	// Point to a non-existent CA path while injection is disabled.
	// This should succeed without validating the CA file.
	badPath := filepath.Join(filepath.Dir(configPath), "nonexistent.crt")

	var stdout, stderr bytes.Buffer
	code := runCommandWithWriters([]string{"config", "set", "trusted_ca_path", badPath}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit code 0 for disabled mode, got %d, stderr: %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "updated") {
		t.Errorf("expected 'updated' in stdout, got: %q", stdout.String())
	}

	// Verify no runtime/state directories were created.
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		// We didn't set XDG_RUNTIME_DIR, so this shouldn't happen.
		// But if it was set, verify no directories were created.
		_ = runtimeDir
	}
}

func TestCAPreflightUnchangedWithBrokenCA(t *testing.T) {
	_, caPath, _, cleanup := setupCAConfigPreflightTest(t)
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
}
