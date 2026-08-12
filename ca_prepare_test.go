package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

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

	if _, err := os.Stat(firstDir); os.IsNotExist(err) {
		t.Error("old fingerprint dir should still exist")
	}
}

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

func TestCAOpenSSLMissing(t *testing.T) {
	dir := t.TempDir()
	runtimeDir := filepath.Join(dir, "xdg_runtime")
	runtimeSubDir := filepath.Join(runtimeDir, "docker-helper")
	if err := os.MkdirAll(runtimeSubDir, 0700); err != nil {
		t.Fatal(err)
	}

	caPath := filepath.Join(dir, "test-ca.crt")
	generateTestCAPEM(t, caPath)

	emptyBin := filepath.Join(dir, "empty_bin")
	if err := os.MkdirAll(emptyBin, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", emptyBin)

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
	if err := os.MkdirAll(fakeBinDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBinDir, "openssl"), []byte("#!/bin/sh\necho invalid-hash\n"), 0755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PATH", fakeBinDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err := prepareCAInjection(runtimeSubDir, caPath)
	if err == nil {
		t.Fatal("expected error for invalid openssl output")
	}
}
