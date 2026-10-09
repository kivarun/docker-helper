package main

import (
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

// setupCAConfigTest creates a test environment with config, runtime dir, and CA.
func setupCAConfigTest(t *testing.T) (configPath, caPath, runtimeDir string) {
	t.Helper()
	dir := t.TempDir()

	configPath = filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	runtimeDir = filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	stateHome := filepath.Join(dir, "xdg_state")
	stateSubDir := filepath.Join(stateHome, "docker-helper")

	if err := os.MkdirAll(runtimeSubDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateSubDir, 0700); err != nil {
		t.Fatal(err)
	}

	caPath = filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	if err := os.WriteFile(tokenPath, []byte("test-admin-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("XDG_STATE_HOME", stateHome)

	// System-only layout: the runtime/state directory seams point at the
	// isolated fixture directories so trusted-CA preparation writes there,
	// and the default client endpoint resolves to the (faked) system socket
	// with the operator credential at the canonical client store.
	origRuntime := getRuntimeDirFunc
	getRuntimeDirFunc = func() (string, error) { return runtimeDir, nil }
	t.Cleanup(func() { getRuntimeDirFunc = origRuntime })
	origState := getStateDirFunc
	getStateDirFunc = func() string { return stateHome }
	t.Cleanup(func() { getStateDirFunc = origState })

	origSocketPath := systemSocketPath
	systemSocketPath = filepath.Join(runtimeSubDir, "docker-helper.sock")
	t.Cleanup(func() { systemSocketPath = origSocketPath })
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "xdg_config"))
	if err := os.MkdirAll(filepath.Join(dir, "xdg_config", "docker-helper"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "xdg_config", "docker-helper", "credential.token"), []byte("test-admin-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	return configPath, caPath, runtimeDir
}

// setupCAConfigPreflightTest creates a minimal test environment for testing
// config set/unset CA preflight without XDG_RUNTIME_DIR.
func setupCAConfigPreflightTest(t *testing.T) (configPath, caPath string) {
	t.Helper()
	dir := t.TempDir()

	configPath = filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")

	caPath = filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	if err := os.WriteFile(tokenPath, []byte("test-admin-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_injection": "disabled",
	}
	writeCAConfig(t, configPath, cfg)

	t.Setenv("DOCKER_HELPER_CONFIG", configPath)

	// System-only client contract: point the system-socket seam at a short,
	// unique nonexistent path below the Unix-domain socket pathname limit
	// (~108 bytes on Linux; a long path causes EINVAL, not ENOENT) and
	// install the operator credential at the canonical client store.
	shortSocket := filepath.Join(os.TempDir(), fmt.Sprintf("dh-ca-%d", os.Getpid()), "docker-helper.sock")
	origSocketPath := systemSocketPath
	systemSocketPath = shortSocket
	t.Cleanup(func() { systemSocketPath = origSocketPath; os.RemoveAll(filepath.Dir(shortSocket)) })
	t.Setenv("XDG_CONFIG_HOME", dir)
	if err := os.MkdirAll(filepath.Join(dir, "docker-helper"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-helper", "credential.token"), []byte("test-admin-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	return configPath, caPath
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
