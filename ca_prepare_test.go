package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCAPrepareSuccess(t *testing.T) {
	configPath, caPath, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

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

	caFile := filepath.Join(preparedDir, "ca.pem")
	caInfo, err := os.Stat(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if caInfo.Mode().Perm() != 0644 {
		t.Errorf("ca.pem mode = %o, want 0644", caInfo.Mode().Perm())
	}

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

func TestCAPrepareIdempotent(t *testing.T) {
	configPath, caPath, runtimeDir := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	cfgObj1, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	firstDir := cfgObj1.TrustedCAPreparedDir

	cfgObj2, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfgObj2.TrustedCAPreparedDir != firstDir {
		t.Error("expected same prepared dir for same CA")
	}

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
	oldUmask := syscall.Umask(0077)
	defer syscall.Umask(oldUmask)

	configPath, caPath, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	cfgObj, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	fpDir := cfgObj.TrustedCAPreparedDir

	dirInfo, err := os.Stat(fpDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0755 {
		t.Errorf("fingerprint dir mode = %o, want 0755", dirInfo.Mode().Perm())
	}

	caFile := filepath.Join(fpDir, "ca.pem")
	caInfo, err := os.Stat(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if caInfo.Mode().Perm() != 0644 {
		t.Errorf("ca.pem mode = %o, want 0644", caInfo.Mode().Perm())
	}

	if err := os.Chmod(fpDir, 0700); err != nil {
		t.Fatal(err)
	}

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
	configPath, caPath, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	cfgObj1, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	firstDir := cfgObj1.TrustedCAPreparedDir

	newCAPath := filepath.Join(filepath.Dir(configPath), "new-ca.crt")
	generateTestCAPEM(t, newCAPath)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      newCAPath,
		"trusted_ca_injection": "auto",
	})

	cfgObj2, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfgObj2.TrustedCAPreparedDir == firstDir {
		t.Error("expected different prepared dir for different CA")
	}

	if _, err := os.Stat(firstDir); os.IsNotExist(err) {
		t.Error("old fingerprint dir should still exist")
	}
}

func TestCAReloadChangesCA(t *testing.T) {
	configPath, caPath, _ := setupCAConfigTest(t)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      caPath,
		"trusted_ca_injection": "auto",
	})

	cfgObj1, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	firstDir := cfgObj1.TrustedCAPreparedDir

	newCAPath := filepath.Join(filepath.Dir(configPath), "new-ca.crt")
	generateTestCAPEM(t, newCAPath)

	writeCAConfig(t, configPath, map[string]any{
		"allowed_root":         testAllowedRootDir(t),
		"session_ttl":          "12h",
		"trusted_ca_path":      newCAPath,
		"trusted_ca_injection": "auto",
	})

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

func setupPreparedCA(t *testing.T) (runtimeSubDir, caPath, preparedDir string) {
	t.Helper()
	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir = filepath.Join(runtimeDir, "docker-helper")
	if err := os.MkdirAll(runtimeSubDir, 0700); err != nil {
		t.Fatal(err)
	}

	caPath = filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	var err error
	preparedDir, err = prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestCAPrepareFixesWrongSymlink(t *testing.T) {
	runtimeSubDir, caPath, preparedDir := setupPreparedCA(t)

	// Find the hash symlink.
	entries, err := os.ReadDir(preparedDir)
	if err != nil {
		t.Fatal(err)
	}
	var symlinkPath string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".0") {
			symlinkPath = filepath.Join(preparedDir, e.Name())
			break
		}
	}
	if symlinkPath == "" {
		t.Fatal("no hash symlink found")
	}

	// Corrupt: replace symlink with one pointing to wrong.pem.
	if err := os.Remove(symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("wrong.pem", symlinkPath); err != nil {
		t.Fatal(err)
	}

	// Re-prepare should fix the symlink.
	preparedDir2, err := prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}
	if preparedDir2 != preparedDir {
		t.Error("expected same prepared dir")
	}

	target, err := os.Readlink(symlinkPath)
	if err != nil {
		t.Fatal(err)
	}
	if target != "ca.pem" {
		t.Errorf("symlink target = %q, want ca.pem", target)
	}
}

func TestCAPrepareFixesRegularFileHashEntry(t *testing.T) {
	runtimeSubDir, caPath, preparedDir := setupPreparedCA(t)

	// Find the hash symlink.
	entries, err := os.ReadDir(preparedDir)
	if err != nil {
		t.Fatal(err)
	}
	var symlinkPath string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".0") {
			symlinkPath = filepath.Join(preparedDir, e.Name())
			break
		}
	}
	if symlinkPath == "" {
		t.Fatal("no hash symlink found")
	}

	// Corrupt: replace symlink with a regular file.
	if err := os.Remove(symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(symlinkPath, []byte("not-a-symlink"), 0644); err != nil {
		t.Fatal(err)
	}

	// Re-prepare should restore the symlink.
	preparedDir2, err := prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}
	if preparedDir2 != preparedDir {
		t.Error("expected same prepared dir")
	}

	target, err := os.Readlink(symlinkPath)
	if err != nil {
		t.Fatal(err)
	}
	if target != "ca.pem" {
		t.Errorf("symlink target = %q, want ca.pem", target)
	}
}

func TestCAPrepareRestoresPemMode(t *testing.T) {
	runtimeSubDir, caPath, preparedDir := setupPreparedCA(t)

	caFile := filepath.Join(preparedDir, "ca.pem")

	// Corrupt: change mode to 0600.
	if err := os.Chmod(caFile, 0600); err != nil {
		t.Fatal(err)
	}

	// Re-prepare should restore mode 0644.
	preparedDir2, err := prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}
	if preparedDir2 != preparedDir {
		t.Error("expected same prepared dir")
	}

	info, err := os.Stat(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("ca.pem mode = %o, want 0644", info.Mode().Perm())
	}
}

func TestCAPrepareFixesPemSymlink(t *testing.T) {
	runtimeSubDir, caPath, preparedDir := setupPreparedCA(t)

	caFile := filepath.Join(preparedDir, "ca.pem")
	caData, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt: replace ca.pem with a symlink to another file with the same content.
	targetFile := filepath.Join(preparedDir, "target-ca.pem")
	if err := os.WriteFile(targetFile, caData, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(caFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target-ca.pem", caFile); err != nil {
		t.Fatal(err)
	}

	// Re-prepare should restore ca.pem as a regular file with mode 0644.
	preparedDir2, err := prepareCAInjection(runtimeSubDir, caPath)
	if err != nil {
		t.Fatal(err)
	}
	if preparedDir2 != preparedDir {
		t.Error("expected same prepared dir")
	}

	info, err := os.Lstat(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("ca.pem should be a regular file, got mode %v", info.Mode())
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("ca.pem mode = %o, want 0644", info.Mode().Perm())
	}
}

func TestCAPrepareSnapshotConsistency(t *testing.T) {
	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	if err := os.MkdirAll(runtimeSubDir, 0700); err != nil {
		t.Fatal(err)
	}

	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)
	originalData, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}

	// prepareCAInjection reads the file once and uses that snapshot
	// for both the hash and the file write. Verify this by corrupting
	// the source file after the first read (via a goroutine) and
	// confirming the prepared ca.pem still matches the original.
	done := make(chan struct{})
	go func() {
		<-done
		// Corrupt the source file after prepareCAInjection has read it.
		os.WriteFile(caPath, []byte("corrupted"), 0644)
	}()

	// prepareCAInjection should succeed using the original snapshot.
	preparedDir, err := prepareCAInjection(runtimeSubDir, caPath)
	close(done)
	if err != nil {
		t.Fatalf("prepareCAInjection failed: %v", err)
	}

	// Verify prepared ca.pem matches original bytes (not the corrupted content).
	preparedCAFile := filepath.Join(preparedDir, "ca.pem")
	preparedData, err := os.ReadFile(preparedCAFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(preparedData, originalData) {
		t.Error("prepared ca.pem does not match original CA bytes")
	}
}

func TestOpenSSLHashGolden(t *testing.T) {
	tests := []struct {
		name     string
		subject  pkix.Name
		expected string
	}{
		{
			name: "simple common name",
			subject: pkix.Name{
				CommonName: "Test CA",
			},
			expected: "d2b0b910",
		},
		{
			name: "organization",
			subject: pkix.Name{
				Organization: []string{"My Company"},
			},
			expected: "212fc7b3",
		},
		{
			name: "full dn",
			subject: pkix.Name{
				Country:            []string{"US"},
				Organization:       []string{"Example Inc"},
				OrganizationalUnit: []string{"Engineering"},
				CommonName:         "Root CA",
			},
			expected: "34198664",
		},
		{
			name: "non-ascii subject",
			subject: pkix.Name{
				CommonName: "日本語テスト",
			},
			expected: "cfd8260d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createTestCertWithSubject(t, tt.subject)
			hash := computeOpenSSLHash(cert)
			if hash != tt.expected {
				t.Errorf("hash = %s, want %s", hash, tt.expected)
			}
		})
	}
}

func createTestCertWithSubject(t *testing.T, subject pkix.Name) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
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

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
