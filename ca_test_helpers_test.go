package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateTestCAPEMData generates a self-signed CA certificate and returns
// its PEM-encoded bytes. The certificate is valid for 2 hours (1 hour before
// and 1 hour after the current time).
func generateTestCAPEMData(t *testing.T) []byte {
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

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// generateTestCAPEM creates a proper PEM-encoded self-signed CA and writes it to caPath.
func generateTestCAPEM(t *testing.T, caPath string) {
	t.Helper()
	if err := os.WriteFile(caPath, generateTestCAPEMData(t), 0644); err != nil {
		t.Fatal(err)
	}
}

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
	return append(generateTestCAPEMData(t), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret-key-data")})...)
}

// generateTestCASecondPEMBlock creates PEM data containing a CA cert followed
// by an arbitrary second PEM block.
func generateTestCASecondPEMBlock(t *testing.T) []byte {
	t.Helper()
	return append(generateTestCAPEMData(t), pem.EncodeToMemory(&pem.Block{Type: "ARBITRARY", Bytes: []byte("extra")})...)
}

// testOpenSSLHash is the fixed hash returned by fake openssl scripts.
const testOpenSSLHash = "abcd1234"

// createFakeOpenSSL creates a fake openssl script in fakeBinDir that returns the given hash.
func createFakeOpenSSL(t *testing.T, fakeBinDir, hash string) {
	t.Helper()
	if err := os.MkdirAll(fakeBinDir, 0755); err != nil {
		t.Fatal(err)
	}
	opensslScript := "#!/bin/sh\necho " + hash + "\n"
	if err := os.WriteFile(filepath.Join(fakeBinDir, "openssl"), []byte(opensslScript), 0755); err != nil {
		t.Fatal(err)
	}
}

// setupCAConfigTest creates a test environment with config, runtime dir, and a fake openssl.
func setupCAConfigTest(t *testing.T) (configPath, caPath, runtimeDir, fakeBinDir string) {
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

	caPath = filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	hash := testOpenSSLHash
	createFakeOpenSSL(t, fakeBinDir, hash)

	if err := os.WriteFile(tokenPath, []byte("test-admin-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("XDG_STATE_HOME", stateHome)
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	return configPath, caPath, runtimeDir, fakeBinDir
}

// setupCAConfigPreflightTest creates a minimal test environment for testing
// config set/unset CA preflight without XDG_RUNTIME_DIR.
func setupCAConfigPreflightTest(t *testing.T) (configPath, caPath, fakeBinDir string) {
	t.Helper()
	dir := t.TempDir()

	configPath = filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	fakeBinDir = filepath.Join(dir, "fake_bin")

	caPath = filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	hash := testOpenSSLHash
	createFakeOpenSSL(t, fakeBinDir, hash)

	if err := os.WriteFile(tokenPath, []byte("test-admin-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := map[string]any{
		"allowed_root":         "/tmp/work",
		"session_ttl":          "12h",
		"trusted_ca_injection": "disabled",
	}
	writeCAConfig(t, configPath, cfg)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	return configPath, caPath, fakeBinDir
}

// writeCAConfig marshals cfg as indented JSON and writes it to configPath.
func writeCAConfig(t *testing.T, configPath string, cfg map[string]any) {
	t.Helper()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
}
