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
	"math/big"
	"os"
	"path/filepath"
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

	caPath = filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	hash := testOpenSSLHash
	createFakeOpenSSL(t, fakeBinDir, hash)

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

// setupCAConfigPreflightTest creates a minimal test environment for testing
// config set/unset CA preflight without XDG_RUNTIME_DIR.
func setupCAConfigPreflightTest(t *testing.T) (configPath, caPath, fakeBinDir string, cleanup func()) {
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
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
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
